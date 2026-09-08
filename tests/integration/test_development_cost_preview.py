from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.constants import ExitCode
from mmaudit.models.development_costs import DevelopmentCostEstimate
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.development_cost_support import development_case

RUNNER = CliRunner()


def _inputs(tmp_path: Path) -> list[str]:
    snapshot, body = development_case()
    (tmp_path / "endpoint.json").write_text(snapshot.model_dump_json(), encoding="utf-8")
    (tmp_path / "request.json").write_text(json.dumps(body), encoding="utf-8")
    return [
        "development",
        "preview-cost",
        "--endpoint-snapshot",
        str(tmp_path / "endpoint.json"),
        "--request-file",
        str(tmp_path / "request.json"),
        "--budget-usd",
        "20",
        "--per-attempt-usd",
        "5",
    ]


def test_local_cli_preview_has_no_transport_credential_ledger_or_release_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = _inputs(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline development preview must not access external or paid state")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "initialize", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    result = RUNNER.invoke(cli_module.app, [*arguments, "--accept-estimate-risk"])
    assert result.exit_code == ExitCode.SUCCESS, result.output
    estimate = DevelopmentCostEstimate.model_validate_json(result.stdout)
    assert estimate.within_estimated_budget is True
    assert estimate.provider_enforced_ceiling is False
    assert estimate.qualification_eligible is estimate.release_eligible is False
    assert "non-deployable synthetic authorization-invariant fixture" not in result.output
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


def test_cli_refuses_without_acknowledgement_before_reading_inputs(tmp_path: Path) -> None:
    arguments = _inputs(tmp_path)
    (tmp_path / "endpoint.json").unlink()
    result = RUNNER.invoke(cli_module.app, arguments)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "--accept-estimate-risk" in result.output


def test_over_target_preview_remains_visible_but_exits_incomplete(tmp_path: Path) -> None:
    arguments = _inputs(tmp_path)
    arguments[-1] = "0.01"
    result = RUNNER.invoke(cli_module.app, [*arguments, "--accept-estimate-risk"])
    assert result.exit_code == ExitCode.INCOMPLETE
    assert (
        DevelopmentCostEstimate.model_validate_json(result.stdout).within_estimated_budget is False
    )


@pytest.mark.parametrize("malformation", ("link", "duplicate", "invalid", "sensitive", "oversize"))
def test_cli_uses_bounded_safe_json_reads_and_does_not_print_input_canaries(
    tmp_path: Path, malformation: str
) -> None:
    arguments = _inputs(tmp_path)
    request_path = tmp_path / "request.json"
    canary = "synthetic-private-input-canary"
    if malformation == "link":
        request_path.unlink()
        target = tmp_path / "actual.json"
        target.write_text(json.dumps({"canary": canary}), encoding="utf-8")
        request_path.symlink_to(target)
    elif malformation == "duplicate":
        request_path.write_text(
            '{"model": "' + canary + '", "model": "duplicate"}', encoding="utf-8"
        )
    elif malformation == "invalid":
        request_path.write_text(canary, encoding="utf-8")
    elif malformation == "oversize":
        request_path.write_text(
            json.dumps({"canary": canary, "padding": "x" * 4_000_001}), encoding="utf-8"
        )
    else:
        arguments[arguments.index("--request-file") + 1] = str(tmp_path / ".env")
    result = RUNNER.invoke(cli_module.app, [*arguments, "--accept-estimate-risk"])
    assert result.exit_code == ExitCode.CONFIGURATION
    assert canary not in result.output
    assert "invalid policy or local JSON evidence" in result.output


def test_production_run_does_not_accept_development_risk_switch() -> None:
    result = RUNNER.invoke(cli_module.app, ["run", "--accept-estimate-risk"])
    assert result.exit_code != ExitCode.SUCCESS
    assert "No such option" in result.output


@pytest.mark.parametrize("option", ("--endpoint-snapshot", "--request-file"))
def test_preview_rejects_relative_paths_without_ambient_working_directory_resolution(
    tmp_path: Path, option: str
) -> None:
    arguments = _inputs(tmp_path)
    arguments[arguments.index(option) + 1] = "synthetic-relative-input.json"
    result = RUNNER.invoke(cli_module.app, [*arguments, "--accept-estimate-risk"])
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "input paths must be absolute" in result.output
