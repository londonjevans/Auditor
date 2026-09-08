"""Real parent capture of fixed finite Python controls, never Hardhat or image evidence."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mmaudit.models.schemas import HardhatInventoryPhaseRequest
from mmaudit.scanners.hardhat_supervision import (
    HardhatCaptureOutcome,
    supervise_hardhat_phase_process,
)
from tests.unit.test_hardhat_protocol import _inventory_request

CONTROL = Path(__file__).parents[1] / "fixtures/hardhat_supervision/control.py"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: fixed local capture controls cannot open sockets")

    monkeypatch.setattr(socket, "socket", forbidden)


@pytest.fixture(autouse=True)
def track_fixed_owned_processes(monkeypatch):
    original = subprocess.Popen
    processes = []

    def launch(command, **kwargs):
        assert command[:3] == (
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            str(CONTROL),
        )
        assert kwargs["env"] == {} and kwargs["shell"] is False
        assert kwargs["start_new_session"] is True and kwargs["close_fds"] is True
        process = original(command, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    yield processes
    for process in processes:
        alive = process.poll() is None
        if alive:
            process.kill()
            process.wait(timeout=2)
        assert not alive, "owned supervisor child required test-fixture cleanup"
        assert process.stdout.closed and process.stderr.closed


@pytest.mark.parametrize(
    "mode,outcome,exit_code",
    [
        ("success", HardhatCaptureOutcome.EXITED, 0),
        ("exit", HardhatCaptureOutcome.EXITED, 7),
        ("missing", HardhatCaptureOutcome.REPORT_UNAVAILABLE, 0),
        ("stream_limit", HardhatCaptureOutcome.OUTPUT_LIMIT, None),
        ("report_limit", HardhatCaptureOutcome.OUTPUT_LIMIT, None),
        ("timeout", HardhatCaptureOutcome.TIMED_OUT, None),
        ("symlink", HardhatCaptureOutcome.REPORT_UNAVAILABLE, 0),
        ("hardlink", HardhatCaptureOutcome.REPORT_UNAVAILABLE, 0),
        ("descendant", HardhatCaptureOutcome.CLEANUP_FAILED, 0),
        ("bytes", HardhatCaptureOutcome.EXITED, 0),
    ],
)
def test_actual_owned_capture_preserves_exit_limits_and_noncrediting_results(
    tmp_path, mode, outcome, exit_code
):
    workspace, output = tmp_path / "workspace", tmp_path / "output"
    workspace.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    values = _inventory_request().model_dump(exclude={"request_sha256"})
    values.update(timeout_seconds=0.2 if mode == "timeout" else 5.0, maximum_output_bytes=1024)
    request = HardhatInventoryPhaseRequest.sealed(**values)
    started = time.monotonic()
    result = supervise_hardhat_phase_process(
        request,
        command=(
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            str(CONTROL),
            mode,
            str(output),
        ),
        workspace=workspace,
        output_root=output,
        environment={},
    )
    assert result.outcome is outcome
    assert result.request_sha256 == request.request_sha256
    assert result.execution_credit is result.runtime_authority is False
    assert len(result.stdout) + len(result.stderr) + len(result.report or b"") <= 1024
    assert result.complete is (mode in {"success", "bytes"})
    if exit_code is not None:
        assert result.process_exit_code == exit_code
    if mode == "success":
        assert result.stdout == b"fixed stdout\n" and result.stderr == b"fixed stderr\n"
        assert result.report == b'{"synthetic":true}\n'
        (output / "hardhat-report.json").write_bytes(b"changed after capture")
        assert result.report == b'{"synthetic":true}\n'
    if mode in {"timeout", "report_limit"}:
        assert time.monotonic() - started < 1.5
    if mode == "bytes":
        assert result.stdout == b"\xff\x00" and result.stderr == b"\xfe"
