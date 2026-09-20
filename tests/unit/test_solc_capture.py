"""Synthetic transcript custody controls; mocked compilers confer no execution authority."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

import pytest

from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from mmaudit.scanners.solc_capture import (
    OwnedSolcCoverageLaunch,
    SolcCaptureLimits,
    SolcCaptureSession,
    prepare_owned_coverage_launch,
    prepare_solc_capture,
)
from mmaudit.solidity import solc_capture_worker as worker


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture(autouse=True)
def no_process_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("unit transcript control attempted actual process execution")

    monkeypatch.setattr(subprocess, "Popen", refused)
    monkeypatch.setattr(subprocess, "run", refused)
    monkeypatch.setattr(os, "execve", refused)
    monkeypatch.setattr(
        worker,
        "isolated_runtime_flags",
        lambda: {
            "isolated": 1,
            "ignore_environment": 1,
            "no_site": 1,
            "dont_write_bytecode": 1,
        },
    )


@pytest.fixture
def session(tmp_path: Path) -> SolcCaptureSession:
    workspace = tmp_path / "source"
    workspace.mkdir()
    (workspace / "src").mkdir()
    source = (
        b"// Synthetic non-deployable compiler-input control.\r\nabstract contract Control {}\r\n"
    )
    path = workspace / "src/Control.sol"
    path.write_bytes(source)
    compiler = Path(sys.executable).resolve(strict=True)
    return prepare_solc_capture(
        root=tmp_path / "transcript",
        workspace=workspace,
        compiler=compiler,
        compiler_sha256=_hash(compiler.read_bytes()),
        sources=(FoundrySourceInput("src/Control.sol", source, _hash(source)),),
        deadline_monotonic=time.monotonic() + 120,
    )


@pytest.fixture
def owned_launch(session: SolcCaptureSession) -> OwnedSolcCoverageLaunch:
    trusted = session.root.parent / "trusted-inputs"
    owner = trusted / "coverage-00000"
    owner.mkdir(parents=True)
    captured = prepare_solc_capture(
        root=session.root.parent / "owner-transcript",
        helper_root=owner / "compiler",
        owner_launch_receipt_path=session.root.parent / "launch-receipt.json",
        workspace=session.workspace,
        compiler=session.compiler,
        compiler_sha256=session.compiler_sha256,
        sources=session.sources,
        deadline_monotonic=session.deadline_monotonic,
    )
    return prepare_owned_coverage_launch(
        session=captured,
        trusted_root=trusted,
        forge=session.compiler,
        forge_sha256=session.compiler_sha256,
        command=(
            str(session.compiler),
            "coverage",
            "--report",
            "debug",
            "--exclude-tests",
            "--use",
            str(captured.launcher),
        ),
        receipt_path=session.root.parent / "launch-receipt.json",
    )


def _mock_owned_exec(launch: OwnedSolcCoverageLaunch, monkeypatch: pytest.MonkeyPatch) -> None:
    class Executed(Exception):
        pass

    plan_path = launch.session.helper_root.parent / "launch.json"
    plan = json.loads(plan_path.read_bytes())
    observed = []

    def fake_exec(path: str, args: list[str], environment: dict[str, str]) -> NoReturn:
        assert path == plan["command"][0] and args == plan["command"]
        observed.append(path)
        raise Executed

    monkeypatch.chdir(launch.session.workspace)
    monkeypatch.setattr(os, "execve", fake_exec)
    with pytest.raises(Executed):
        worker.coverage_launch_main(str(plan_path), launch.plan_sha256)
    assert observed == [plan["command"][0]]


def test_original_owned_launch_and_reader_keep_forge_compiler_and_runtime_separate(
    owned_launch: OwnedSolcCoverageLaunch,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = owned_launch.session
    assert owned_launch.command[:2] == (str(session.interpreter), "-IBS")
    assert session.helper_root != session.root
    _mock_owned_exec(owned_launch, monkeypatch)
    assert _capture(session, monkeypatch)[0] == 0
    records = owned_launch.collect()
    assert len(records) == 1 and records[0].stdin == _request(session)
    assert set(p.name for p in session.root.iterdir()) == {"serial.lock", "calls"}
    assert set(p.name for p in session.helper_root.iterdir()) == {
        "worker.py",
        "plan.json",
        "solc-capture",
    }
    assert owned_launch.collect() == records
    receipt = json.loads(owned_launch.receipt_path.read_bytes())
    assert receipt["runtime"]["transitive_native_dependency_closure_verified"] is False


@pytest.mark.parametrize(
    "target",
    [
        "launch.json",
        "launch.py",
        "compiler/worker.py",
        "compiler/plan.json",
        "compiler/solc-capture",
        "coverage-forge",
    ],
)
def test_owned_launch_refuses_same_byte_helper_or_staged_tool_replacement(
    owned_launch: OwnedSolcCoverageLaunch,
    target: str,
) -> None:
    owner = owned_launch.session.helper_root.parent
    path = owner.parent / target if target == "coverage-forge" else owner / target
    raw, mode = path.read_bytes(), path.stat().st_mode & 0o777
    path.rename(path.with_name(path.name + ".original"))
    path.write_bytes(raw)
    path.chmod(mode)
    with pytest.raises(ValueError, match=r"replaced|changed"):
        owned_launch.require_inputs_unchanged()


@pytest.mark.parametrize("boundary", ["namespace", "plan", "deadline", "runtime_pin", "flags"])
def test_original_launch_worker_refuses_changed_boundary_before_exec(
    owned_launch: OwnedSolcCoverageLaunch,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    plan_path = owned_launch.session.helper_root.parent / "launch.json"
    monkeypatch.chdir(owned_launch.session.workspace)
    if boundary == "namespace":
        monkeypatch.chdir(owned_launch.session.root.parent)
    elif boundary == "plan":
        plan_path.write_bytes(plan_path.read_bytes() + b" ")
    elif boundary == "deadline":
        monkeypatch.setattr(time, "monotonic", lambda: owned_launch.session.deadline_monotonic)
    elif boundary == "flags":
        monkeypatch.setattr(worker, "isolated_runtime_flags", lambda: {"isolated": 0})
    else:
        # Challenge the runtime validator without changing any host runtime file.
        actual = worker.runtime_observation

        def changed_runtime(plan: dict[str, Any]) -> bytes:
            plan["runtime_files"] = {p: "0" * 64 for p in plan["runtime_files"]}
            return actual(plan)

        monkeypatch.setattr(worker, "runtime_observation", changed_runtime)
    assert worker.coverage_launch_main(str(plan_path), owned_launch.plan_sha256) == 125
    assert not owned_launch.receipt_path.exists()


@pytest.mark.parametrize(
    "boundary", ["missing_receipt", "extra_call", "runtime", "flags", "authority"]
)
def test_owned_collection_rejects_missing_or_changed_original_population(
    owned_launch: OwnedSolcCoverageLaunch,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    _mock_owned_exec(owned_launch, monkeypatch)
    session = owned_launch.session
    assert _capture(session, monkeypatch)[0] == 0
    if boundary == "missing_receipt":
        owned_launch.receipt_path.rename(owned_launch.receipt_path.with_suffix(".retained"))
    elif boundary == "extra_call":
        (session.root / "calls/0002").mkdir()
    else:
        receipt = json.loads(owned_launch.receipt_path.read_bytes())
        if boundary == "authority":
            receipt["runtime"]["transitive_native_dependency_closure_verified"] = True
        elif boundary == "flags":
            receipt["runtime"]["flags"]["no_site"] = True
        else:
            receipt["runtime"]["files"]["/synthetic/unplanned.py"] = "a" * 64
        owned_launch.receipt_path.write_text(json.dumps(receipt))
    with pytest.raises((ValueError, OSError)):
        owned_launch.collect()


def _request(session: SolcCaptureSession, *, normalized: bool = False) -> bytes:
    return json.dumps(
        {
            "language": "Solidity",
            "sources": {
                source.path: {
                    "content": (
                        source.content.replace(b"\r\n", b"\n") if normalized else source.content
                    ).decode()
                }
                for source in session.sources
            },
            "settings": {},
        }
    ).encode()


def _capture(
    session: SolcCaptureSession,
    monkeypatch: pytest.MonkeyPatch,
    *,
    argv: list[str] | None = None,
    incoming: bytes | None = None,
    output: bytes | None = None,
    code: int = 0,
    forward_error: bool = False,
) -> tuple[int, list[tuple[int, bytes]]]:
    request = incoming if incoming is not None else _request(session)
    outgoing = (
        output
        if output is not None
        else json.dumps(
            {"sources": {source.path: {"id": i} for i, source in enumerate(session.sources)}}
        ).encode()
    )
    forwarded: list[tuple[int, bytes]] = []

    def original_input(path: Path, maximum: int, deadline: float) -> bytes:
        assert len(request) <= maximum
        worker.write_bytes(path, request)
        return request

    def compile_control(
        command: list[str], path: Path, directory: Path, limits: dict[str, int], deadline: float
    ) -> tuple[int, bytes, bytes]:
        assert command[0] == str(session.compiler)
        stdout = b"synthetic version\n" if command[1:] == ["--version"] else outgoing
        assert path.read_bytes() == (b"" if command[1:] == ["--version"] else request)
        worker.write_bytes(directory / "stdout.bin", stdout)
        worker.write_bytes(directory / "stderr.bin", b"synthetic diagnostic\n")
        worker.write_bytes(
            directory / "process.json",
            json.dumps({"process_started": True, "compiler_exit_code": code}).encode(),
        )
        return code, stdout, b"synthetic diagnostic\n"

    def forward(fd: int, raw: bytes, deadline: float) -> None:
        forwarded.append((fd, raw))
        if forward_error:
            raise BrokenPipeError("synthetic closed caller")

    monkeypatch.setattr(worker, "_input", original_input)
    monkeypatch.setattr(worker, "_compile", compile_control)
    monkeypatch.setattr(worker, "_forward", forward)
    status = worker.capture_main(
        str(session.root),
        _hash((session.helper_root / "plan.json").read_bytes()),
        argv if argv is not None else ["--standard-json"],
        helper_root=str(session.helper_root),
    )
    return status, forwarded


@pytest.mark.parametrize("normalized", [False, True])
def test_original_worker_and_reader_retain_exact_mocked_streams(
    session: SolcCaptureSession, monkeypatch: pytest.MonkeyPatch, normalized: bool
) -> None:
    assert session.launcher.read_bytes().splitlines()[0].endswith(b" -IBS")
    assert _capture(session, monkeypatch, argv=["--version"])[0] == 0
    request = _request(session, normalized=normalized)
    status, forwarded = _capture(session, monkeypatch, incoming=request)
    assert status == 0
    records = session.collect()
    assert len(records) == 2
    assert records[1].stdin == request
    assert records[1].compiler_argv == ("--standard-json", "--no-import-callback")
    assert forwarded == [(1, records[1].stdout), (2, records[1].stderr)]
    assert all(record.evidence_authority == "UNATTESTED_COMPILER_TRANSCRIPT" for record in records)
    assert session.collect() == records


@pytest.mark.parametrize(
    "name", ["worker.py", "solc-capture", "plan.json", "serial.lock", "source"]
)
def test_same_bytes_replacement_of_prepared_input_refuses(
    session: SolcCaptureSession, name: str
) -> None:
    path = session.workspace / session.sources[0].path if name == "source" else session.root / name
    raw, mode = path.read_bytes(), path.stat().st_mode & 0o777
    path.rename(path.with_name(path.name + ".original"))
    path.write_bytes(raw)
    path.chmod(mode)
    with pytest.raises(ValueError, match="replaced"):
        session.require_inputs_unchanged()


@pytest.mark.parametrize("replacement", ["directory", "symlink", "hardlink"])
def test_original_source_ancestor_and_alias_changes_refuse(
    session: SolcCaptureSession, replacement: str
) -> None:
    source = session.workspace / session.sources[0].path
    if replacement == "hardlink":
        os.link(source, session.workspace / "second.sol")
    else:
        parent = source.parent
        saved = parent.with_name("original-src")
        parent.rename(saved)
        if replacement == "symlink":
            parent.symlink_to(saved, target_is_directory=True)
        else:
            parent.mkdir()
            (saved / source.name).rename(source)
    with pytest.raises(ValueError):
        session.require_inputs_unchanged()


@pytest.mark.parametrize(
    "change", ["missing", "extra", "reordered", "raw", "request", "process", "exit-type"]
)
def test_partial_or_changed_completed_population_refuses(
    session: SolcCaptureSession, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    assert _capture(session, monkeypatch)[0] == 0
    call = session.root / "calls/0000"
    if change == "missing":
        (call / "complete.json").rename(call / "missing-complete.json")
    elif change == "extra":
        (call / "extra.json").write_text("{}")
    elif change == "reordered":
        call.rename(call.with_name("0001"))
    elif change == "raw":
        (call / "stdout.bin").write_bytes(b"{}")
    elif change == "request":
        (call / "request.json").write_text('{"received_argv":["--version"]}')
    elif change == "process":
        (call / "process.json").write_text('{"compiler_exit_code":0,"process_started":false}')
    else:
        complete = json.loads((call / "complete.json").read_bytes())
        complete["compiler_exit_code"] = False
        (call / "complete.json").write_text(json.dumps(complete))
    with pytest.raises(ValueError):
        session.collect()


def test_collection_refuses_a_live_compiler_lock(
    session: SolcCaptureSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _capture(session, monkeypatch)[0] == 0
    fd = os.open(session.root / "serial.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match="active invocation"):
            session.collect()
    finally:
        os.close(fd)


def test_collection_rechecks_earlier_read_bytes_and_objects(
    session: SolcCaptureSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _capture(session, monkeypatch)[0] == 0
    original = worker.file_snapshot
    changed = False

    def drift(path: Path, maximum: int) -> tuple[bytes, worker.FileIdentity]:
        nonlocal changed
        observed = original(path, maximum)
        if path.name == "stdout.bin" and not changed:
            changed = True
            target = path.parent / "stdin.bin"
            raw = target.read_bytes()
            target.rename(target.with_name("original-stdin.bin"))
            target.write_bytes(raw)
        return observed

    monkeypatch.setattr(worker, "file_snapshot", drift)
    with pytest.raises(ValueError, match="changed during collection"):
        session.collect()


@pytest.mark.parametrize(
    "failure", ["compiler-exit", "json-error", "forward", "source", "arguments"]
)
def test_failed_attempt_retains_original_evidence_and_blocks_further_work(
    session: SolcCaptureSession, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    values: dict[str, Any] = {}
    if failure == "compiler-exit":
        values["code"] = 1
    elif failure == "json-error":
        values["output"] = json.dumps(
            {"sources": {session.sources[0].path: {"id": 0}}, "errors": [{"severity": "error"}]}
        ).encode()
    elif failure == "forward":
        values["forward_error"] = True
    elif failure == "source":
        values["incoming"] = b'{"language":"Solidity","sources":{"foreign.sol":{"content":"x"}}}'
    else:
        values["argv"] = ["--help"]
    status, _ = _capture(session, monkeypatch, **values)
    assert status == (1 if failure == "compiler-exit" else 125)
    call = session.root / "calls/0000"
    assert (call / "request.json").is_file()
    if failure not in {"source", "arguments"}:
        assert (call / "stdout.bin").is_file() and (call / "process.json").is_file()
    with pytest.raises(ValueError):
        session.collect()
    assert _capture(session, monkeypatch)[0] == 125
    assert sorted(path.name for path in (session.root / "calls").iterdir()) == ["0000"]
    assert (session.root / "refused.json").is_file()


@pytest.mark.parametrize("mode", ["inclusive", "overflow", "timeout"])
def test_original_input_pump_retains_bounded_partial_prefix(tmp_path: Path, mode: str) -> None:
    read_fd, write_fd = os.pipe()
    closed = False
    path = tmp_path / "stdin.bin"
    try:
        os.write(write_fd, b"prefix")
        if mode != "timeout":
            os.close(write_fd)
            closed = True
        if mode == "inclusive":
            assert worker._input(path, 6, time.monotonic() + 1, input_fd=read_fd) == b"prefix"
        else:
            with pytest.raises(ValueError if mode == "overflow" else TimeoutError):
                worker._input(
                    path,
                    5 if mode == "overflow" else 100,
                    time.monotonic() + 0.05,
                    input_fd=read_fd,
                )
        assert path.read_bytes() == b"prefix"
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        os.close(read_fd)
        if not closed:
            os.close(write_fd)


@pytest.mark.parametrize(
    "argv", [[], ["--help"], ["--standard-json", "--standard-json"], ["--base-path"]]
)
def test_unsupported_compiler_arguments_refuse(tmp_path: Path, argv: list[str]) -> None:
    with pytest.raises(ValueError):
        worker.compiler_arguments(argv, tmp_path)


def test_allow_paths_permission_is_explicitly_replaced_by_closed_literal_inputs(
    tmp_path: Path,
) -> None:
    argv = ["--allow-paths", str(tmp_path), "--base-path", str(tmp_path), "--standard-json"]
    assert worker.compiler_arguments(argv, tmp_path) == (
        "--base-path",
        str(tmp_path),
        "--standard-json",
        "--no-import-callback",
    )
    assert "--allow-paths" in argv
    with pytest.raises(ValueError):
        worker.compiler_arguments(
            ["--standard-json", "--allow-paths", str(tmp_path.parent)], tmp_path
        )


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b'{"unterminated":'])
def test_transcript_json_decoder_is_strict(raw: bytes) -> None:
    with pytest.raises((ValueError, UnicodeError)):
        worker.decode(raw)


@pytest.mark.parametrize("maximum", [True, -1, 200_000_001])
def test_invalid_reader_ceiling_refuses(tmp_path: Path, maximum: int) -> None:
    with pytest.raises(ValueError, match="ceiling"):
        worker.file_snapshot(tmp_path / "not-read", maximum)


def test_constructed_invalid_limits_refuse_before_output_creation(
    session: SolcCaptureSession,
) -> None:
    root = session.root.parent / "invalid-transcript"
    with pytest.raises(ValueError):
        prepare_solc_capture(
            root=root,
            workspace=session.workspace,
            compiler=session.compiler,
            compiler_sha256=session.compiler_sha256,
            sources=session.sources,
            deadline_monotonic=time.monotonic() + 30,
            limits=SolcCaptureLimits.model_construct(max_invocations=0),
        )
    assert not root.exists()


def test_expired_owner_deadline_cannot_be_replaced_by_collection_time(
    session: SolcCaptureSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _capture(session, monkeypatch)[0] == 0
    expired = replace(session, deadline_monotonic=time.monotonic() - 1)
    with pytest.raises(TimeoutError, match="deadline"):
        expired.collect()


@pytest.mark.parametrize("failure", ["none", "stdout", "stderr", "aggregate", "timeout", "wait"])
def test_original_output_pump_bounds_retains_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    writes: list[int] = []
    killed: list[bool] = []

    class ProcessControl:
        def __init__(self, command: list[str], **kwargs: Any) -> None:
            assert command == ["not-executed"]
            assert kwargs["shell"] is False
            assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
            assert kwargs["stdin"].read() == b"{}"
            self.returncode: int | None = None
            self.stdout = stream(b"abcde")
            self.stderr = stream(b"12345")

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, *, timeout: float) -> int:
            if failure == "wait" and self.returncode is None:
                raise subprocess.TimeoutExpired("not-executed", timeout)
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def kill(self) -> None:
            killed.append(True)
            self.returncode = -9

    def stream(raw: bytes) -> Any:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, raw)
        if failure == "timeout":
            writes.append(write_fd)
        else:
            os.close(write_fd)
        return os.fdopen(read_fd, "rb")

    monkeypatch.setattr(subprocess, "Popen", ProcessControl)
    path = tmp_path / "stdin.bin"
    path.write_bytes(b"{}")
    limits = {
        "max_stdin_bytes": 2,
        "max_stdout_bytes": 4 if failure == "stdout" else 5,
        "max_stderr_bytes": 4 if failure == "stderr" else 5,
        "remaining_output_bytes": 8 if failure == "aggregate" else 10,
    }
    deadline = time.monotonic() + (0.05 if failure == "timeout" else 1)
    try:
        if failure == "none":
            assert worker._compile(["not-executed"], path, tmp_path, limits, deadline) == (
                0,
                b"abcde",
                b"12345",
            )
        else:
            with pytest.raises((ValueError, TimeoutError, subprocess.TimeoutExpired)):
                worker._compile(["not-executed"], path, tmp_path, limits, deadline)
    finally:
        for fd in writes:
            os.close(fd)
    retained = {name: (tmp_path / (name + ".bin")).read_bytes() for name in ("stdout", "stderr")}
    assert b"abcde".startswith(retained["stdout"])
    assert b"12345".startswith(retained["stderr"])
    assert len(retained["stdout"]) <= limits["max_stdout_bytes"] + 1
    assert len(retained["stderr"]) <= limits["max_stderr_bytes"] + 1
    assert sum(map(len, retained.values())) <= limits["remaining_output_bytes"] + 1
    assert killed == ([] if failure == "none" else [True])
    assert json.loads((tmp_path / "process.json").read_bytes()) == {
        "process_started": True,
        "compiler_exit_code": 0 if failure == "none" else -9,
    }
