"""Parent-capture boundaries with no real process, socket, Hardhat or container."""

from __future__ import annotations

import hashlib
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from mmaudit.models.schemas import HardhatTestPhaseRequest
from mmaudit.scanners import hardhat_supervision as supervision
from tests.unit.test_hardhat_protocol import _inventory_request


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: unit supervision controls cannot execute or open sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture
def inputs(tmp_path):
    workspace, output = tmp_path / "workspace", tmp_path / "output"
    workspace.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    return dict(
        request=_inventory_request(),
        command=(str(Path(sys.executable).resolve(strict=True)),),
        workspace=workspace,
        output_root=output,
        environment={},
    )


@pytest.mark.parametrize("mutation", ["wrong_type", "hash", "limit", "credit"])
def test_invalid_request_refuses_before_process_creation(inputs, mutation):
    if mutation == "wrong_type":
        inputs["request"] = object()
    else:
        field, value = {
            "hash": ("request_sha256", "0" * 64),
            "limit": ("timeout_seconds", float("inf")),
            "credit": ("execution_credit", True),
        }[mutation]
        inputs["request"] = inputs["request"].model_copy(update={field: value})
    with pytest.raises(supervision.HardhatSupervisionError):
        supervision.supervise_hardhat_phase_process(**inputs)


@pytest.mark.parametrize("mutation", ["alias", "overlap", "permissions", "existing", "link"])
def test_unsafe_or_occupied_output_cannot_start_a_phase(inputs, tmp_path, mutation):
    output = inputs["output_root"]
    if mutation == "alias":
        alias = tmp_path / "alias"
        alias.symlink_to(output, target_is_directory=True)
        inputs["output_root"] = alias
    elif mutation == "overlap":
        inputs["workspace"] = output
    elif mutation == "permissions":
        output.chmod(0o755)
    elif mutation == "existing":
        (output / supervision.HARDHAT_PHASE_REPORT_NAME).write_bytes(b"{}")
    else:
        (output / supervision.HARDHAT_PHASE_REPORT_NAME).symlink_to("absent")
    with pytest.raises(supervision.HardhatSupervisionError):
        supervision.supervise_hardhat_phase_process(**inputs)


@pytest.mark.parametrize(
    "command", [(), [], ("relative",), ("/missing",), (True,), ("a\x00b",), ("a" * 131073,)]
)
def test_unbounded_or_nonexact_command_refuses(inputs, command):
    inputs["command"] = command
    with pytest.raises(supervision.HardhatSupervisionError):
        supervision.supervise_hardhat_phase_process(**inputs)


@pytest.mark.parametrize(
    "environment", [{"bad-name": "x"}, {"A": "\x00"}, {"A": True}, {"A": "x" * 65537}]
)
def test_environment_is_explicit_and_bounded(inputs, environment):
    inputs["environment"] = environment
    with pytest.raises(supervision.HardhatSupervisionError):
        supervision.supervise_hardhat_phase_process(**inputs)


def test_spawn_failure_returns_no_success_or_execution_credit(inputs, monkeypatch):
    def unavailable(*args, **kwargs):
        assert kwargs["env"] == {} and kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["shell"] is False and kwargs["start_new_session"] is True
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.PIPE
        raise OSError("synthetic unavailable runtime")

    monkeypatch.setattr(subprocess, "Popen", unavailable)
    result = supervision.supervise_hardhat_phase_process(**inputs)
    assert result.outcome is supervision.HardhatCaptureOutcome.SPAWN_FAILED
    assert result.process_exit_code is None and result.report is None
    assert result.stdout == result.stderr == b""
    assert not result.complete and result.execution_credit is result.runtime_authority is False


@pytest.mark.parametrize("failure", ["error", "interrupt", "exit", "cleanup", "request", "root"])
def test_owned_process_cleanup_precedes_errors_or_mutated_capture(inputs, monkeypatch, failure):
    events = []
    sentinel = {
        "interrupt": KeyboardInterrupt(),
        "exit": SystemExit(2),
    }.get(failure, RuntimeError("synthetic parent capture failure"))

    class Pipe:
        def close(self):
            events.append("close-pipe")

    class Process:
        stdout, stderr = Pipe(), Pipe()
        returncode = 0

    process = Process()

    def capture(child, **kwargs):
        assert child is process
        if failure in {"error", "interrupt", "exit"}:
            raise sentinel
        if failure == "request":
            inputs["request"].reporter_version = "changed"
        if failure == "root":
            inputs["output_root"].chmod(0o755)
        return supervision.HardhatCaptureOutcome.EXITED, b"", b""

    def cleanup(child):
        assert child is process
        events.append("cleanup")
        if failure in {"error", "interrupt", "exit"}:
            raise ValueError("synthetic secondary cleanup error")
        return failure != "cleanup"

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(supervision, "_capture_pipes", capture)
    monkeypatch.setattr(supervision, "_cleanup_child", cleanup)
    if failure == "cleanup":
        result = supervision.supervise_hardhat_phase_process(**inputs)
        assert result.outcome is supervision.HardhatCaptureOutcome.CLEANUP_FAILED
        assert not result.complete and result.report is None
    else:
        expected = type(sentinel) if failure in {"error", "interrupt", "exit"} else ValueError
        with pytest.raises(expected) as raised:
            supervision.supervise_hardhat_phase_process(**inputs)
        if failure in {"error", "interrupt", "exit"}:
            assert raised.value is sentinel
    assert events == ["cleanup", "close-pipe", "close-pipe"]


def test_capture_does_not_expose_private_bytes_in_repr_or_grant_authority():
    capture = supervision.HardhatPhaseCapture(
        request_sha256="1" * 64,
        phase="inventory",
        outcome=supervision.HardhatCaptureOutcome.EXITED,
        process_exit_code=0,
        duration_seconds=0.1,
        stdout=b"synthetic-private-stdout",
        stderr=b"synthetic-private-stderr",
        report=b"synthetic-private-report",
    )
    assert capture.complete
    assert "synthetic-private" not in repr(capture)
    assert capture.stdout_sha256 == hashlib.sha256(capture.stdout).hexdigest()
    assert capture.stderr_sha256 == hashlib.sha256(capture.stderr).hexdigest()
    assert capture.report_sha256 == hashlib.sha256(capture.report).hexdigest()
    assert capture.execution_credit is capture.runtime_authority is False


def test_capture_directory_cannot_be_claimed_by_two_phases(inputs, monkeypatch):
    launches = []

    def start(*args, **kwargs):
        launches.append(args)
        if len(launches) == 1:
            with pytest.raises(supervision.HardhatSupervisionError, match="claim"):
                supervision.supervise_hardhat_phase_process(**inputs)
        raise OSError("synthetic no-child control")

    monkeypatch.setattr(subprocess, "Popen", start)
    result = supervision.supervise_hardhat_phase_process(**inputs)
    assert result.outcome is supervision.HardhatCaptureOutcome.SPAWN_FAILED
    assert len(launches) == 1
    with pytest.raises(supervision.HardhatSupervisionError, match="claim"):
        supervision.supervise_hardhat_phase_process(**inputs)


def test_report_read_cannot_extend_the_declared_phase_deadline(inputs, monkeypatch):
    class Pipe:
        def close(self):
            pass

    class Process:
        stdout, stderr = Pipe(), Pipe()
        returncode = 0

    now = [10.0]

    def capture(*args, **kwargs):
        (inputs["output_root"] / supervision.HARDHAT_PHASE_REPORT_NAME).write_bytes(b"{}")
        return supervision.HardhatCaptureOutcome.EXITED, b"", b""

    original = supervision.read_file_evidence

    def delayed_report(**kwargs):
        result = original(**kwargs)
        now[0] = 21.0
        return result

    monkeypatch.setattr(supervision.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(supervision, "_capture_pipes", capture)
    monkeypatch.setattr(supervision, "_cleanup_child", lambda child: True)
    monkeypatch.setattr(supervision, "read_file_evidence", delayed_report)
    result = supervision.supervise_hardhat_phase_process(**inputs)
    assert result.outcome is supervision.HardhatCaptureOutcome.TIMED_OUT
    assert not result.complete and result.report is None


def test_pipe_close_failure_preserves_original_error_and_closes_both_streams(inputs, monkeypatch):
    events = []
    original = RuntimeError("synthetic original read error")

    class Pipe:
        def __init__(self, name):
            self.name = name

        def close(self):
            events.append(self.name)
            if self.name == "stdout":
                raise ValueError("synthetic stream-close failure")

    class Process:
        stdout, stderr = Pipe("stdout"), Pipe("stderr")
        returncode = 0

    def capture(*args, **kwargs):
        raise original

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(supervision, "_capture_pipes", capture)
    monkeypatch.setattr(
        supervision, "_cleanup_child", lambda child: events.append("cleanup") or True
    )
    with pytest.raises(RuntimeError) as raised:
        supervision.supervise_hardhat_phase_process(**inputs)
    assert raised.value is original
    assert events == ["cleanup", "stdout", "stderr"]


@pytest.mark.parametrize("mutation", ["claim", "request"])
def test_post_capture_custody_changes_cannot_return_observations(inputs, monkeypatch, mutation):
    class Pipe:
        def close(self):
            pass

    class Process:
        stdout, stderr = Pipe(), Pipe()
        returncode = 0

    def capture(*args, **kwargs):
        (inputs["output_root"] / supervision.HARDHAT_PHASE_REPORT_NAME).write_bytes(b"{}")
        return supervision.HardhatCaptureOutcome.EXITED, b"", b""

    original = supervision.read_file_evidence

    def changed_report(**kwargs):
        result = original(**kwargs)
        if mutation == "request":
            inputs["request"].reporter_version = "changed"
        else:
            claim = next(inputs["output_root"].parent.glob(".mmaudit-hardhat-*.claim"))
            claim.write_bytes(b"synthetic changed ownership")
        return result

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(supervision, "_capture_pipes", capture)
    monkeypatch.setattr(supervision, "_cleanup_child", lambda child: True)
    monkeypatch.setattr(supervision, "read_file_evidence", changed_report)
    with pytest.raises(ValueError):
        supervision.supervise_hardhat_phase_process(**inputs)


def test_test_phase_request_is_retained_without_execution_credit(inputs, monkeypatch):
    inventory = inputs["request"]
    values = inventory.model_dump(exclude={"request_sha256", "phase", "phase_sequence"})
    values.update(
        inventory_request_sha256=inventory.request_sha256,
        inventory_sha256="a" * 64,
        source_authority_sha256="b" * 64,
        selection_sha256="c" * 64,
        selected_test_count=1,
        per_test_timeout_seconds=5.0,
        maximum_output_bytes_per_test=1024,
    )
    request = HardhatTestPhaseRequest.sealed(**values)
    inputs["request"] = request

    def unavailable(*args, **kwargs):
        raise OSError("synthetic unavailable runtime")

    monkeypatch.setattr(subprocess, "Popen", unavailable)
    result = supervision.supervise_hardhat_phase_process(**inputs)
    assert result.phase == "test" and result.request_sha256 == request.request_sha256
    assert result.outcome is supervision.HardhatCaptureOutcome.SPAWN_FAILED
    assert result.execution_credit is result.runtime_authority is result.complete is False


@pytest.mark.parametrize("primary_failure", [False, True])
def test_claim_close_failure_never_masks_the_primary_error(inputs, monkeypatch, primary_failure):
    original_close = supervision.os.close
    primary = RuntimeError("synthetic original capture failure")
    secondary = OSError("synthetic descriptor-close failure")
    closed = []

    def close(descriptor):
        original_close(descriptor)
        closed.append(descriptor)
        raise secondary

    with monkeypatch.context() as scoped:
        scoped.setattr(supervision.os, "close", close)
        expected = RuntimeError if primary_failure else OSError
        with pytest.raises(expected) as raised, supervision._claim_output(inputs["output_root"]):
            if primary_failure:
                raise primary
        assert raised.value is (primary if primary_failure else secondary)
    assert len(closed) == 1
