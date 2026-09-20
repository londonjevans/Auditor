"""Production debugger lifecycle with original synthetic writers and no child execution."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest

import mmaudit.scanners.foundry as foundry
from mmaudit.models.schemas import RepositorySuiteExecutionPolicy, RepositorySuiteSelection
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.foundry_debugger import parse_forge_debugger_observation
from mmaudit.scanners.foundry_inventory import FoundryInventoryLimits, FoundrySourceInput
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryCompilerInputSnapshot,
    FoundryInventoryInvalidError,
    FoundryInventoryOverflowError,
    FoundryInventoryTimeoutError,
)
from mmaudit.scanners.solc_capture import (
    CapturedSolcInvocation,
    OwnedSolcDebuggerLaunch,
    prepare_owned_debugger_launch,
)
from tests import debugger_trace_support as synthetic
from tests.unit.test_foundry_statement_execution import _v12_manifest_carriers
from tests.unit.test_solc_capture import no_process_execution as no_process_execution
from tests.unit.test_solc_debugger_capture import original_writer


@dataclass
class Harness:
    arguments: dict[str, Any]
    events: list[str] = field(default_factory=list)
    launches: list[OwnedSolcDebuggerLaunch] = field(default_factory=list)
    mode: str = "success"

    def run(
        self, **changes: Any
    ) -> tuple[foundry._FoundryDebuggerProcess, foundry._PrivateArtifactUsage]:
        return foundry._execute_foundry_debugger_trace(**(self.arguments | changes))


class Backend:
    name = "synthetic-isolation"

    def __init__(self, harness: Harness) -> None:
        self.harness = harness

    def wrap(self, command: list[str], **arguments: Any) -> list[str]:
        self.harness.events.append("wrap")
        assert arguments["rpc_port"] == 8545
        if self.harness.mode == "source-drift":
            path = arguments["workspace"] / synthetic.SOURCE
            path.write_bytes(path.read_bytes() + b"\n")
        return command

    def cleanup(self, private_dir: Path) -> None:
        self.harness.events.append("cleanup")
        if self.harness.mode == "cleanup-failure":
            raise RuntimeError("synthetic cleanup failure")
        if self.harness.mode == "output-replacement":
            path = self.harness.launches[0].dump_path
            raw = path.read_bytes()
            path.rename(private_dir / "retired-dump.json")
            path.write_bytes(raw)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    private = tmp_path / "private"
    workspace = private / "workspace"
    shutil.copytree(synthetic.FIXTURE, workspace)
    interpreter = Path(sys.executable).resolve(strict=True)
    pin = hashlib.sha256(interpreter.read_bytes()).hexdigest()
    case = Harness(
        dict(
            descriptor=synthetic.descriptor(),
            workspace=workspace,
            private_dir=private,
            output_index=0,
            executable_path=interpreter,
            executable_sha256=pin,
            compiler_path=interpreter,
            compiler_sha256=pin,
            compiler_inputs=(
                FoundryCompilerInputSnapshot(
                    ".", b"{}", (b"{}",), synthetic.sources(), FoundryInventoryLimits()
                ),
            ),
            rpc_url="http://127.0.0.1:8545",
            rpc_port=8545,
            fork=PinnedForkObservation(31337, 42, "0x" + "a" * 64),
            fuzz_seed="0x" + "0" * 63 + "1",
            fuzz_runs=8,
            invariant_runs=2,
            deadline=time.monotonic() + 120,
            max_output_bytes=8_000_000,
            max_output_entries=200,
            base_environment={"PATH": "/usr/bin:/bin"},
        )
    )
    case.arguments["backend"] = Backend(case)
    prepare = prepare_owned_debugger_launch

    def record_launch(**arguments: Any) -> OwnedSolcDebuggerLaunch:
        launch = prepare(**arguments)
        case.launches.append(launch)
        return launch

    class Process:
        def __init__(self) -> None:
            self.returncode: int | None = (
                None
                if case.mode in {"live-bytes", "live-entries", "timeout"}
                else (2 if case.mode == "exit-two" else 0)
            )

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float) -> int:
            assert 0 < timeout <= 0.1
            assert self.returncode is not None
            return self.returncode

    def spawn(command: list[str], **arguments: Any) -> Process:
        case.events.append("spawn")
        assert arguments["stdin"] == subprocess.DEVNULL
        assert arguments["shell"] is False
        assert arguments["cwd"] == workspace
        assert tuple(command) == case.launches[0].command
        environment = arguments["env"]
        assert environment["FOUNDRY_FFI"] == "false"
        assert environment["FOUNDRY_FS_PERMISSIONS"] == "[]"
        assert environment["FOUNDRY_NO_STORAGE_CACHING"] == "true"
        if case.mode == "launch-failure":
            raise OSError("synthetic spawn refusal")
        with monkeypatch.context() as writer_patch:
            original_writer(case.launches[0], writer_patch)
        execution = case.launches[0].dump_path.parent
        if case.mode == "live-bytes":
            (execution / "spill.bin").write_bytes(b"x" * 8_000_001)
        elif case.mode == "live-entries":
            for index in range(201):
                (execution / f"extra-{index:03d}").write_bytes(b"x")
        return Process()

    def stop(process: Process, *, deadline: float) -> None:
        assert deadline == case.arguments["deadline"]
        case.events.append("stop")
        process.returncode = -9

    remaining = foundry._remaining_deadline_seconds

    def remaining_time(deadline: float, **arguments: Any) -> float:
        if case.mode == "timeout" and "spawn" in case.events:
            raise foundry._FoundrySuiteDeadlineExpired("synthetic shared deadline")
        return remaining(deadline, **arguments)

    monkeypatch.setattr(foundry, "prepare_owned_debugger_launch", record_launch)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(foundry, "_stop_process", stop)
    monkeypatch.setattr(foundry, "_remaining_deadline_seconds", remaining_time)
    return case


def test_original_writer_survives_production_lifecycle_and_bounded_handoff(
    harness: Harness,
) -> None:
    process, usage = harness.run()
    assert harness.events == ["wrap", "spawn", "cleanup"]
    assert usage.bytes == process.private_artifact_bytes
    assert usage.artifact_sha256 == process.private_artifact_sha256
    assert len(process.result.observation.steps) == 7
    payload = process.retained_payload(max_bytes=8_000_000, deadline=harness.arguments["deadline"])
    assert len(payload["artifact_files"]) == 14
    assert payload["runtime_authority"] is payload["coverage_complete"] is False
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    assert (
        process.retained_payload(max_bytes=len(encoded), deadline=harness.arguments["deadline"])
        == payload
    )
    with pytest.raises(FoundryInventoryOverflowError):
        process.retained_payload(max_bytes=len(encoded) - 1, deadline=harness.arguments["deadline"])


@pytest.mark.parametrize("mode", ["live-bytes", "live-entries", "timeout"])
def test_live_limit_refusal_stops_process_and_always_cleans_up(harness: Harness, mode: str) -> None:
    harness.mode = mode
    error = FoundryInventoryTimeoutError if mode == "timeout" else FoundryInventoryOverflowError
    with pytest.raises(error):
        harness.run()
    assert harness.events == ["wrap", "spawn", "stop", "cleanup"]


@pytest.mark.parametrize(
    "mode", ["launch-failure", "cleanup-failure", "exit-two", "output-replacement", "source-drift"]
)
def test_invalid_lifecycle_never_returns_a_collected_observation(
    harness: Harness, mode: str
) -> None:
    harness.mode = mode
    with pytest.raises(FoundryInventoryInvalidError):
        harness.run()
    assert harness.events[-1] == "cleanup"
    assert ("spawn" not in harness.events) is (mode == "source-drift")


@pytest.mark.parametrize(
    "changes",
    [
        {"max_output_bytes": 0},
        {"max_output_entries": 0},
        {"compiler_inputs": ()},
        {"compiler_inputs": []},
        {"deadline": 0.0},
    ],
)
def test_invalid_remaining_budget_or_inputs_refuses_before_dispatch(
    harness: Harness, changes: dict[str, Any]
) -> None:
    with pytest.raises(
        (FoundryInventoryInvalidError, FoundryInventoryOverflowError, FoundryInventoryTimeoutError)
    ):
        harness.run(**changes)
    assert harness.events == ["cleanup"]


@pytest.mark.parametrize(
    "change", ["missing", "duplicate", "bytes", "metadata", "source", "plan", "receipt"]
)
def test_retained_handoff_refuses_incomplete_or_changed_original_evidence(
    harness: Harness, change: str
) -> None:
    process, _usage = harness.run()
    files = process.artifact_files
    if change == "missing":
        process = replace(process, artifact_files=files[:-1])
    elif change == "duplicate":
        process = replace(process, artifact_files=(*files, files[0]))
    elif change in {"bytes", "metadata"}:
        target = (
            "steps.json" if change == "bytes" else "compiler-transcript/calls/0000/process.json"
        )
        process = replace(
            process,
            artifact_files=tuple(
                replace(
                    item,
                    content=item.content + b" ",
                    sha256=hashlib.sha256(item.content + b" ").hexdigest(),
                )
                if item.relative_path == target
                else item
                for item in files
            ),
        )
    elif change == "source":
        process = replace(
            process, sources=(replace(process.sources[0], content=b"changed"), *process.sources[1:])
        )
    elif change == "plan":
        process = replace(process, launch_plan=process.launch_plan + b" ")
    else:
        process = replace(process, launch_receipt=process.launch_receipt + b" ")
    with pytest.raises(FoundryInventoryInvalidError):
        process.retained_payload(max_bytes=8_000_000, deadline=harness.arguments["deadline"])


def test_retained_original_bytes_can_be_reparsed_without_the_original_workspace(
    harness: Harness,
) -> None:
    process, _usage = harness.run()
    payload = json.loads(
        json.dumps(
            process.retained_payload(max_bytes=8_000_000, deadline=harness.arguments["deadline"])
        )
    )
    private = harness.arguments["private_dir"]
    private.rename(private.with_name("retired-original"))
    files = {f["path"]: bytes.fromhex(f["content_hex"]) for f in payload["artifact_files"]}
    sources = tuple(
        FoundrySourceInput(s["path"], bytes.fromhex(s["content_hex"]), s["source_sha256"])
        for s in payload["source_inputs"]
    )
    calls = tuple(
        CapturedSolcInvocation(
            c["sequence"],
            tuple(c["received_argv"]),
            tuple(c["compiler_argv"]),
            c["compiler_exit_code"],
            files[c["artifact_directory"] + "/stdin.bin"],
            files[c["artifact_directory"] + "/stdout.bin"],
            files[c["artifact_directory"] + "/stderr.bin"],
            c["transcript_sha256"],
        )
        for c in payload["compiler_transcripts"]
    )
    observed = parse_forge_debugger_observation(
        files["stdout.txt"],
        files["steps.json"],
        compiler_transcripts=calls,
        source_inputs=sources,
        descriptor=process.descriptor,
        process_exit_code=payload["process_exit_code"],
    )
    assert observed == process.result.observation
    assert observed.evidence_authority == "UNATTESTED_DEBUGGER_OBSERVATION"


@pytest.mark.parametrize("failed", [False, True])
def test_completed_and_failed_stage_trees_are_charged_once(harness: Harness, failed: bool) -> None:
    private = harness.arguments["private_dir"]
    for stage, size in (("tests", 7), ("coverage", 11), ("debugger", 13)):
        path = private / "repository-suite" / stage / "00000"
        path.mkdir(parents=True)
        (path / "output.bin").write_bytes(b"x" * size)
    usage = foundry._PrivateArtifactUsage(3, 31, "a" * 64)
    observation = foundry._unavailable_observation(synthetic.descriptor(), "synthetic")
    outcome = foundry._ScopedFoundryTestOutcome(
        None if failed else (observation, usage),
        None,
        FoundryInventoryInvalidError("synthetic stage failure") if failed else None,
    )
    budget = foundry._SuiteArtifactBudget(100, 200, bytes=17)
    foundry._charge_selected_test_artifacts(
        outcome=outcome,
        budget=budget,
        backend=harness.arguments["backend"],
        private_dir=private,
        output_index=0,
        deadline=harness.arguments["deadline"],
    )
    assert budget.bytes == 48 and budget.entries == 3


@pytest.mark.parametrize("per_test", [True, False])
def test_refused_artifact_overage_remains_charged_and_stops_further_work(per_test: bool) -> None:
    budget = foundry._SuiteArtifactBudget(10, 12)
    usage = foundry._PrivateArtifactUsage(1, 13, "a" * 64)
    with pytest.raises(FoundryInventoryOverflowError):
        budget.charge(usage, label="synthetic", per_test=per_test)
    assert budget.bytes == 13 and budget.remaining_bytes == -1


def manifest_inputs(
    process: foundry._FoundryDebuggerProcess,
) -> tuple[RepositorySuiteSelection, RepositorySuiteExecutionPolicy]:
    old_selection, old_policy, *_ = _v12_manifest_carriers()
    selection = RepositorySuiteSelection.sealed(
        **(
            old_selection.model_dump(exclude={"selection_sha256", "tests", "inventory_sha256"})
            | {
                "tests": (process.descriptor,),
                "inventory_sha256": process.descriptor.inventory_sha256,
            }
        )
    )
    policy = RepositorySuiteExecutionPolicy.sealed(
        **(
            old_policy.model_dump(exclude={"policy_sha256"})
            | {
                "selection_sha256": selection.selection_sha256,
                "max_total_output_bytes": 8_000_000,
            }
        )
    )
    return selection, policy


def test_manifest_retains_original_debugger_without_promoting_it_or_double_charging(
    harness: Harness,
) -> None:
    process, usage = harness.run()
    selection, policy = manifest_inputs(process)
    private = harness.arguments["private_dir"]
    arguments = dict(debugger_processes=(process,), deadline=harness.arguments["deadline"])
    path = foundry._write_repository_suite_manifest(
        private,
        selection,
        None,
        None,
        policy,
        [],
        previously_charged_artifact_bytes=usage.bytes,
        **arguments,
    )
    encoded = path.read_bytes()
    payload = json.loads(encoded)
    assert payload["schema_version"] == "1.3" and payload["safety_claim"] is False
    observations = payload["repository_debugger_observations"]
    assert observations["unproduced_descriptors"] == []
    assert observations["runtime_authority"] is observations["coverage_complete"] is False
    assert observations["observed"][0]["descriptor"] == process.descriptor.model_dump(mode="json")
    assert "repository_statement_coverage_evidence" not in payload
    exact = private / "exact"
    exact.mkdir()
    admitted = policy.max_total_output_bytes - len(encoded)
    repeated = foundry._write_repository_suite_manifest(
        exact,
        selection,
        None,
        None,
        policy,
        [],
        previously_charged_artifact_bytes=admitted,
        **arguments,
    )
    assert repeated.read_bytes() == encoded
    refused = private / "refused"
    refused.mkdir()
    with pytest.raises((ValueError, FoundryInventoryOverflowError)):
        foundry._write_repository_suite_manifest(
            refused,
            selection,
            None,
            None,
            policy,
            [],
            previously_charged_artifact_bytes=admitted + 1,
            **arguments,
        )
    assert not (refused / "repository-suite-execution.json").exists()


@pytest.mark.parametrize(
    "change", ["duplicate", "unselected", "no-policy", "unaccounted", "unbounded"]
)
def test_manifest_refuses_invalid_debugger_selection_and_resource_context(
    harness: Harness, change: str
) -> None:
    process, _usage = harness.run()
    selection, policy = manifest_inputs(process)
    arguments: dict[str, Any] = dict(
        debugger_processes=(process,),
        previously_charged_artifact_bytes=0,
        deadline=harness.arguments["deadline"],
    )
    if change == "duplicate":
        arguments["debugger_processes"] = (process, process)
    elif change == "unselected":
        selection = _v12_manifest_carriers()[0]
    elif change == "unaccounted":
        arguments["previously_charged_artifact_bytes"] = True
    elif change == "unbounded":
        arguments["previously_charged_artifact_bytes"] = policy.max_total_output_bytes
    with pytest.raises((ValueError, FoundryInventoryOverflowError)):
        foundry._write_repository_suite_manifest(
            harness.arguments["private_dir"],
            selection,
            None,
            None,
            None if change == "no-policy" else policy,
            [],
            **arguments,
        )


@pytest.mark.parametrize("problem", ["symlink", "expired", "over-budget"])
def test_failed_stage_accounting_refuses_invalid_or_overflowed_residual_artifacts(
    harness: Harness, problem: str
) -> None:
    private = harness.arguments["private_dir"]
    path = private / "repository-suite/debugger/00000"
    path.mkdir(parents=True)
    if problem == "symlink":
        (path / "output").symlink_to(private / "workspace" / synthetic.SOURCE)
    else:
        (path / "output").write_bytes(b"x" * 201)
    budget = foundry._SuiteArtifactBudget(100, 200)
    with pytest.raises(
        (
            foundry._FoundrySuiteDeadlineExpired,
            FoundryInventoryInvalidError,
            FoundryInventoryOverflowError,
        )
    ):
        foundry._charge_selected_test_artifacts(
            outcome=foundry._ScopedFoundryTestOutcome(None, None, ValueError("synthetic")),
            budget=budget,
            backend=harness.arguments["backend"],
            private_dir=private,
            output_index=0,
            deadline=0 if problem == "expired" else harness.arguments["deadline"],
        )
    if problem == "over-budget":
        assert budget.bytes == 201 and budget.remaining_bytes == -1
