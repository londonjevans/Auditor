"""Unrepresentable campaign counts remain raw evidence, never invented execution credit."""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

import mmaudit.scanners.foundry as foundry
from mmaudit.models.schemas import RepositoryTestExecutionStatus
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from tests.unit.test_foundry_execution_hardening import SEED, _descriptor, _selection

ZERO_CAMPAIGNS = (
    {"Fuzz": {"runs": 0}},
    {"Invariant": {"runs": 0, "calls": 1}},
    {"Invariant": {"runs": 1, "calls": 0}},
)


def _result(kind: dict[str, dict[str, int]], status: str) -> str:
    descriptor = _descriptor()
    return json.dumps(
        {
            f"{descriptor.path}:{descriptor.suite_name}": {
                "test_results": {
                    f"{descriptor.test_name}()": {
                        "status": status,
                        "reason": "synthetic invariant failure" if status == "Failure" else None,
                        "counterexample": {"Single": {"args": "true"}},
                        "kind": kind,
                    }
                }
            }
        }
    )


@pytest.mark.parametrize("kind", ZERO_CAMPAIGNS)
@pytest.mark.parametrize("status", ["Success", "Failure"])
def test_exact_campaign_refuses_zero_observed_population(
    kind: dict[str, dict[str, int]], status: str
) -> None:
    raw = _result(kind, status)
    with pytest.raises(ValueError, match="requires nonzero observed"):
        foundry._parse_exact_foundry_test(
            raw, descriptor=_descriptor(), return_code=int(status == "Failure")
        )
    # The aggregate parser still records original counts. No configured-run estimate
    # or counterexample is substituted for the observed zero-completion count.
    summary = foundry._foundry_execution_summary(raw)
    assert summary is not None
    assert summary.fuzz_cases == kind.get("Fuzz", {}).get("runs", 0)
    assert summary.invariant_runs == kind.get("Invariant", {}).get("runs", 0)
    assert summary.invariant_calls == kind.get("Invariant", {}).get("calls", 0)


@pytest.mark.parametrize(
    "kind",
    [{"Unit": {"gas": 1}}, {"Fuzz": {"runs": 1}}, {"Invariant": {"runs": 1, "calls": 1}}],
)
@pytest.mark.parametrize("status", ["Success", "Failure"])
def test_exact_nonzero_campaign_and_unit_outcomes_remain_classified(
    kind: dict[str, dict[str, int]], status: str
) -> None:
    observed, detail, summary, digest = foundry._parse_exact_foundry_test(
        _result(kind, status), descriptor=_descriptor(), return_code=int(status == "Failure")
    )
    assert observed is (
        RepositoryTestExecutionStatus.PASSED
        if status == "Success"
        else RepositoryTestExecutionStatus.FAILED
    )
    assert (detail is None) == (status == "Success")
    assert summary.fuzz_cases == kind.get("Fuzz", {}).get("runs", 0)
    assert summary.invariant_calls == kind.get("Invariant", {}).get("calls", 0)
    assert len(digest) == 64


@pytest.mark.parametrize("kind", ZERO_CAMPAIGNS)
@pytest.mark.parametrize("status", ["Success", "Failure"])
def test_zero_campaign_execution_retains_original_bytes_and_no_validated_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: dict[str, dict[str, int]], status: str
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    raw = _result(kind, status).encode()
    events: list[str] = []
    exit_code = int(status == "Failure")

    class Backend:
        name = "synthetic-no-child-execution"

        def wrap(self, command: list[str], **kwargs: Any) -> list[str]:
            events.append("wrap")
            assert kwargs["workspace"] == workspace
            return command

        def cleanup(self, private_dir: Path) -> None:
            assert private_dir == private
            events.append("cleanup")

    class OriginalOutputProcess:
        returncode = exit_code

        def __init__(self, command: list[str], **kwargs: Any) -> None:
            events.append("synthetic-output-only")
            assert command[1] == "test"
            assert kwargs["shell"] is False
            kwargs["stdout"].write(raw)
            kwargs["stdout"].flush()

        def poll(self) -> int:
            return self.returncode

        def wait(self, timeout: float) -> int:
            assert timeout >= 0
            return self.returncode

    monkeypatch.setattr(subprocess, "Popen", OriginalOutputProcess)
    observation, usage = foundry._execute_foundry_test(
        descriptor=_descriptor(),
        selection=_selection(),
        workspace=workspace,
        private_dir=private,
        output_index=0,
        executable_path=Path("/synthetic/not-executed/forge"),
        compiler_path=Path("/synthetic/not-executed/solc"),
        compiler_sha256="a" * 64,
        rpc_url="http://127.0.0.1:8545",
        rpc_port=8545,
        fork=PinnedForkObservation(31337, 0, "0x" + "b" * 64),
        fuzz_seed=SEED,
        fuzz_runs=8,
        invariant_runs=2,
        deadline=time.monotonic() + 30,
        max_output_bytes=1_000_000,
        backend=Backend(),
        base_environment={"PATH": "/usr/bin:/bin"},
    )
    assert events == ["wrap", "synthetic-output-only", "cleanup"]
    assert observation.status is RepositoryTestExecutionStatus.INVALID_OUTPUT
    assert not observation.machine_output_validated
    assert observation.machine_result_sha256 is None
    assert observation.summary is None
    assert observation.process_started and observation.process_exit_code == exit_code
    assert usage.captured("stdout.json") == raw
    assert usage.bytes == observation.output_bytes == len(raw)
    assert observation.output_sha256 == usage.artifact_sha256
    retained = private / "repository-suite/tests/00000/stdout.json"
    assert hashlib.sha256(retained.read_bytes()).digest() == hashlib.sha256(raw).digest()
