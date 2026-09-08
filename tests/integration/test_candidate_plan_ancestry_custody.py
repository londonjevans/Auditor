"""Local-only CLI custody checks; private test outputs are never adopted."""

from __future__ import annotations

import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import FrameType

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
import mmaudit.models.candidate_plan_ancestry as ancestry_module
import mmaudit.release_io as release_io_module
from mmaudit.constants import ExitCode
from mmaudit.models.candidate_plan_ancestry import VerifiedCandidateSelectionPlanAncestry
from mmaudit.models.candidate_selection import load_candidate_selection_plan

ROOT = Path(__file__).parents[2]
ACTIVE_PLAN = ROOT / "config" / "models.selection-plan.json"


@pytest.fixture(autouse=True)
def local_only(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neither capability validation nor refusal may reach secrets or external execution."""

    before = ACTIVE_PLAN.read_bytes()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("ancestry integration must not use external execution or credentials")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(httpx.Client, "send", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "send", forbidden)
    yield
    assert ACTIVE_PLAN.read_bytes() == before


@pytest.mark.parametrize("case", ("normal", "multi_endpoint", "forged_instance", "mutated_class"))
def test_cli_preserves_exact_ancestry_custody_before_private_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
) -> None:
    if case == "forged_instance":
        forged = object.__new__(VerifiedCandidateSelectionPlanAncestry)
        monkeypatch.setattr(
            cli_module, "resolve_verified_candidate_selection_plan_ancestry", lambda: forged
        )
    elif case == "mutated_class":
        monkeypatch.setattr(
            VerifiedCandidateSelectionPlanAncestry, "__eq__", lambda _self, _other: True
        )
    output = tmp_path / "private" / "non-authorizing-plan.json"
    candidate = (
        "google/gemini-3.7-flash=together"
        if case == "multi_endpoint"
        else "anthropic/claude-opus-5=amazon-bedrock"
    )
    result = CliRunner().invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            candidate,
            "--output",
            str(output),
            "--no-color",
        ],
    )
    if case in {"normal", "multi_endpoint"}:
        assert result.exit_code == ExitCode.SUCCESS, result.output
        plan = load_candidate_selection_plan(output)
        assert plan.schema_version == "1.8"
        assert plan.ancestry_transition_binding is not None
        assert plan.ancestry_transition_binding.production_selection_authorized is False
        assert plan.ancestry_transition_binding.provider_call_authorized is False
        model_id, endpoint = candidate.split("=", 1)
        assert next(
            entry.allowed_provider_endpoints
            for entry in plan.entries
            if entry.exact_model_id == model_id
        ) == (endpoint,)
        assert output.stat().st_mode & 0o777 == 0o600
        assert "plan was not adopted" in " ".join(result.output.split())
    else:
        assert result.exit_code == ExitCode.CONFIGURATION, result.output
        assert not output.exists()
        expected = (
            "absent or fork-inherited" if case == "forged_instance" else "runtime boundary changed"
        )
        assert expected in " ".join(result.output.split())


@pytest.mark.parametrize(
    "failure", ("validation", "parent_rename", "parent_mode", "file_mode", "bytes")
)
def test_cli_rolls_back_private_output_after_late_publication_failure(
    tmp_path: Path, failure: str
) -> None:
    output = tmp_path / "private" / "nonauthorizing-plan.json"
    moved = tmp_path / "moved-private"
    triggered = False
    previous_profile = sys.getprofile()

    def inject_local_failure(frame: FrameType, event: str, _arg: object) -> None:
        nonlocal triggered
        if triggered or not output.exists():
            return
        if failure == "validation":
            if (
                event == "call"
                and frame.f_code.co_name == "validate_impl"
                and frame.f_globals is vars(ancestry_module)
            ):
                triggered = True
                raise ancestry_module.CandidateSelectionPlanAncestryError(
                    "synthetic final ancestry validation failure"
                )
        elif (
            event == "return"
            and frame.f_code is release_io_module._observe_file_twice.__code__
            and frame.f_locals.get("relative_path") == output.name
        ):
            triggered = True
            if failure == "parent_rename":
                output.parent.rename(moved)
                output.parent.mkdir(mode=0o700)
            elif failure == "parent_mode":
                output.parent.chmod(0o777)
            elif failure == "file_mode":
                output.chmod(0o644)
            else:
                output.write_bytes(b"synthetic late byte drift")

    try:
        sys.setprofile(inject_local_failure)
        result = CliRunner().invoke(
            cli_module.app,
            [
                "models",
                "emit-selection-plan-reactivation",
                "--candidate",
                "anthropic/claude-opus-5=amazon-bedrock",
                "--output",
                str(output),
                "--no-color",
            ],
        )
    finally:
        sys.setprofile(previous_profile)
    assert triggered
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert not output.exists()
    assert not (moved / output.name).exists()
    assert "plan was not adopted" not in result.output
