"""Original debugger worker/collector controls using synthetic, nonexecuted wire data."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.scanners.foundry_debugger import FoundryDebuggerLimits
from mmaudit.scanners.solc_capture import (
    OwnedSolcDebuggerLaunch,
    SolcCaptureSession,
    prepare_owned_debugger_launch,
    prepare_solc_capture,
)
from mmaudit.solidity import solc_capture_worker as worker
from tests import debugger_trace_support as synthetic
from tests.unit.test_solc_capture import _capture
from tests.unit.test_solc_capture import no_process_execution as no_process_execution


@pytest.fixture
def captured(tmp_path: Path) -> SolcCaptureSession:
    workspace = tmp_path / "source"
    shutil.copytree(synthetic.FIXTURE, workspace)
    owner = tmp_path / "trusted-inputs/debugger-00000"
    owner.mkdir(parents=True)
    execution = tmp_path / "debugger"
    execution.mkdir()
    interpreter = Path(sys.executable).resolve(strict=True)
    return prepare_solc_capture(
        root=execution / "compiler-transcript",
        helper_root=owner / "compiler",
        owner_launch_receipt_path=execution / "launch-receipt.json",
        workspace=workspace,
        compiler=interpreter,
        compiler_sha256=hashlib.sha256(interpreter.read_bytes()).hexdigest(),
        sources=synthetic.sources(),
        deadline_monotonic=time.monotonic() + 120,
    )


def prepare(captured: SolcCaptureSession, **changes: Any) -> OwnedSolcDebuggerLaunch:
    arguments: dict[str, Any] = dict(
        session=captured,
        trusted_root=captured.helper_root.parent.parent,
        forge=captured.compiler,
        forge_sha256=captured.compiler_sha256,
        descriptor=synthetic.descriptor(),
        fuzz_seed="0x" + "0" * 63 + "1",
        fuzz_runs=8,
    )
    return prepare_owned_debugger_launch(**(arguments | changes))


@pytest.fixture
def launch(captured: SolcCaptureSession) -> OwnedSolcDebuggerLaunch:
    return prepare(captured)


def original_writer(launch: OwnedSolcDebuggerLaunch, monkeypatch: pytest.MonkeyPatch) -> None:
    class Executed(Exception):
        pass

    observed: list[str] = []
    plan_path = launch.session.helper_root.parent / "debugger-launch.json"
    plan = json.loads(plan_path.read_bytes())

    def fake_exec(path: str, args: list[str], environment: dict[str, str]) -> NoReturn:
        assert path == plan["command"][0] and args == plan["command"]
        observed.append(path)
        raise Executed

    redirected: list[int] = []
    monkeypatch.setattr(os, "execve", fake_exec)
    monkeypatch.setattr(os, "dup2", lambda fd, destination: redirected.append(destination))
    monkeypatch.chdir(launch.session.workspace)
    with pytest.raises(Executed):
        worker.debugger_launch_main(str(plan_path), launch.plan_sha256)
    assert observed == [plan["command"][0]] and redirected == [1, 2, 0]
    assert (
        _capture(
            launch.session,
            monkeypatch,
            incoming=synthetic.raw(synthetic.compiler_input()),
            output=synthetic.raw(synthetic.compiler_output()),
        )[0]
        == 0
    )
    machine = synthetic.payload()
    launch.stdout_path.write_bytes(synthetic.raw(machine))
    launch.stderr_path.write_bytes(b"synthetic diagnostic only\n")
    launch.dump_path.write_bytes(synthetic.raw(synthetic.dump(machine)))


def test_distinct_original_launch_and_compiler_output_collection(
    launch: OwnedSolcDebuggerLaunch,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_writer(launch, monkeypatch)
    result = launch.collect(process_exit_code=0)
    assert result.observation.descriptor_sha256 == launch.descriptor.descriptor_sha256
    assert result.launch_plan_sha256 == launch.plan_sha256
    assert (
        result.launch_receipt_sha256 == hashlib.sha256(launch.receipt_path.read_bytes()).hexdigest()
    )
    assert result.stdout == launch.stdout_path.read_bytes()
    assert result.stderr == b"synthetic diagnostic only\n"
    assert result.dump == launch.dump_path.read_bytes()
    assert len(result.compiler_transcripts) == 1 and len(result.observation.steps) == 7
    assert (
        result.observation.execution_scope == "ONE_DEBUGGER_TRACE_NOT_FULL_TEST_OR_FUZZ_POPULATION"
    )
    assert result.observation.evidence_authority == "UNATTESTED_DEBUGGER_OBSERVATION"
    result.observation.require_code_bound_steps()
    assert launch.collect(process_exit_code=0) == result
    plan = json.loads((launch.session.helper_root.parent / "debugger-launch.json").read_bytes())
    assert plan["command"][1] == "test" and "coverage" not in plan["command"]
    assert plan["command"].count("--debug") == plan["command"].count("--use") == 1
    assert plan["command"][plan["command"].index("--match-test") + 1].endswith(r"\(\)$")
    assert not hasattr(result, "coverage_complete")


@pytest.mark.parametrize(
    "change",
    [
        {"fuzz_runs": True},
        {"fuzz_runs": 0},
        {"fuzz_runs": 1_000_001},
        {"fuzz_seed": "1"},
        {"fuzz_seed": None},
        {"limits": object()},
        {"fork_url": "http://127.0.0.1:8545"},
        {"fork_block_number": 1},
        {"fork_url": "https://127.0.0.1:8545", "fork_block_number": 0},
        {"fork_url": "http://example.invalid:8545", "fork_block_number": 0},
        {"fork_url": "http://user:secret@127.0.0.1:8545", "fork_block_number": 0},
        {"fork_url": "http://127.0.0.1:0", "fork_block_number": 0},
        {"fork_url": "http://127.0.0.1:8545", "fork_block_number": True},
        {"fork_url": "http://127.0.0.1:8545", "fork_block_number": -1},
        {"forge_sha256": "0" * 64},
        {"descriptor": object()},
    ],
)
def test_selection_refuses_before_producing_launch(
    captured: SolcCaptureSession, change: dict[str, Any]
) -> None:
    with pytest.raises(ValueError):
        prepare(captured, **change)
    assert not (captured.helper_root.parent / "debugger-launch.json").exists()


def test_loopback_selection_is_recorded_without_contact(captured: SolcCaptureSession) -> None:
    launch = prepare(captured, fork_url="http://127.0.0.1:8545", fork_block_number=7)
    plan = json.loads((captured.helper_root.parent / "debugger-launch.json").read_bytes())
    assert plan["command"][-4:] == [
        "--fork-url",
        "http://127.0.0.1:8545",
        "--fork-block-number",
        "7",
    ]
    assert not launch.receipt_path.exists()


@pytest.mark.parametrize("name", ["launch-receipt.json", "stdout.txt", "stderr.txt", "steps.json"])
def test_existing_output_refuses_before_launch(captured: SolcCaptureSession, name: str) -> None:
    (captured.root.parent / name).write_bytes(b"retained prior attempt")
    with pytest.raises(ValueError, match="fresh separate"):
        prepare(captured)
    assert (captured.root.parent / name).read_bytes() == b"retained prior attempt"


@pytest.mark.parametrize(
    "name",
    [
        "debugger-launch.json",
        "debugger-launch.py",
        "compiler/worker.py",
        "compiler/plan.json",
        "compiler/solc-capture",
        "../debugger-forge",
    ],
)
def test_same_byte_original_input_replacement_refuses(
    launch: OwnedSolcDebuggerLaunch, name: str
) -> None:
    path = (launch.session.helper_root.parent / name).resolve(strict=True)
    raw, mode = path.read_bytes(), path.stat().st_mode & 0o777
    path.rename(path.with_name(path.name + ".retained"))
    path.write_bytes(raw)
    path.chmod(mode)
    with pytest.raises(ValueError, match=r"changed|replaced"):
        launch.require_inputs_unchanged()


@pytest.mark.parametrize("boundary", ["namespace", "plan", "deadline", "flags", "occupied_output"])
def test_worker_refuses_before_exec_and_receipt(
    launch: OwnedSolcDebuggerLaunch,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    path = launch.session.helper_root.parent / "debugger-launch.json"
    monkeypatch.chdir(launch.session.workspace)
    if boundary == "namespace":
        monkeypatch.chdir(launch.session.root)
    elif boundary == "plan":
        path.write_bytes(path.read_bytes() + b" ")
    elif boundary == "deadline":
        monkeypatch.setattr(time, "monotonic", lambda: launch.session.deadline_monotonic)
    elif boundary == "flags":
        monkeypatch.setattr(worker, "isolated_runtime_flags", lambda: {"isolated": 0})
    else:
        launch.stderr_path.write_bytes(b"prior")
    assert worker.debugger_launch_main(str(path), launch.plan_sha256) == 125
    assert not launch.receipt_path.exists()


@pytest.mark.parametrize(
    "boundary",
    [
        "receipt_missing",
        "coverage_receipt",
        "descriptor",
        "plan",
        "authority",
        "extra_call",
        "stdout_missing",
        "dump_missing",
        "dump_wrong",
        "stdout_wrong",
        "hardlink",
        "source",
    ],
)
def test_collector_refuses_missing_changed_or_cross_invocation_evidence(
    launch: OwnedSolcDebuggerLaunch,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    original_writer(launch, monkeypatch)
    if boundary in {"receipt_missing", "stdout_missing", "dump_missing"}:
        path = {
            "receipt_missing": launch.receipt_path,
            "stdout_missing": launch.stdout_path,
            "dump_missing": launch.dump_path,
        }[boundary]
        path.rename(path.with_suffix(".retained"))
    elif boundary in {"coverage_receipt", "descriptor", "plan", "authority"}:
        receipt = json.loads(launch.receipt_path.read_bytes())
        if boundary == "coverage_receipt":
            receipt.pop("launch_kind")
            receipt.pop("descriptor_sha256")
        elif boundary == "authority":
            receipt["runtime"]["transitive_native_dependency_closure_verified"] = True
        else:
            receipt["descriptor_sha256" if boundary == "descriptor" else "launch_plan_sha256"] = (
                "0" * 64
            )
        launch.receipt_path.write_text(json.dumps(receipt))
    elif boundary == "extra_call":
        (launch.session.root / "calls/0001").mkdir()
    elif boundary == "hardlink":
        os.link(launch.dump_path, launch.dump_path.with_suffix(".alias"))
    elif boundary == "source":
        (launch.session.workspace / synthetic.SOURCE).write_bytes(b"// changed synthetic source")
    else:
        path = launch.dump_path if boundary == "dump_wrong" else launch.stdout_path
        path.write_bytes(b"{}")
    with pytest.raises((OSError, ValueError)):
        launch.collect(process_exit_code=0)


@pytest.mark.parametrize("code", [None, True, -1, 2, 125])
def test_unfinished_or_refused_process_never_collects(
    launch: OwnedSolcDebuggerLaunch, code: Any
) -> None:
    with pytest.raises(ValueError, match="terminal"):
        launch.collect(process_exit_code=code)


@pytest.mark.parametrize("boundary", ["artifact", "aggregate", "compiler_plus_outputs"])
def test_output_bounds_include_stderr_and_original_compiler_streams(
    launch: OwnedSolcDebuggerLaunch,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    original_writer(launch, monkeypatch)
    total = sum(
        p.stat().st_size for p in (launch.stdout_path, launch.stderr_path, launch.dump_path)
    )
    limits = FoundryDebuggerLimits(
        max_artifact_bytes=1 if boundary == "artifact" else 16_000_000,
        max_total_bytes=total - 1 if boundary == "aggregate" else total,
    )
    with pytest.raises(ValueError, match=r"ceiling|bound"):
        replace(launch, limits=limits).collect(process_exit_code=0)


def test_change_during_parse_refuses(
    launch: OwnedSolcDebuggerLaunch, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mmaudit.scanners.foundry_debugger as parser

    original_writer(launch, monkeypatch)
    original = parser.parse_forge_debugger_observation

    def changed(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        launch.stderr_path.write_bytes(b"late replacement")
        return result

    monkeypatch.setattr(parser, "parse_forge_debugger_observation", changed)
    with pytest.raises(ValueError, match="changed during collection"):
        launch.collect(process_exit_code=0)


@pytest.mark.parametrize("name", ["stdout_path", "stderr_path", "dump_path"])
def test_original_writer_output_object_cannot_be_replaced_with_same_bytes(
    launch: OwnedSolcDebuggerLaunch,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    original_writer(launch, monkeypatch)
    path = getattr(launch, name)
    raw = path.read_bytes()
    path.rename(path.with_suffix(".retained"))
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(ValueError, match="original writer file objects"):
        launch.collect(process_exit_code=0)
