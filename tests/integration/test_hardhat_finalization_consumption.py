"""Owned bridge plus real fixed Node/Python controls; all runtime launch/replies are MOCK."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from mmaudit.models.schemas import RepositoryTestExecutionStatus
from mmaudit.scanners import hardhat_execution as execution
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SOURCE_PATH
from mmaudit.scanners.hardhat_finalization import finalize_hardhat_phase
from tests.hardhat_capture_support import inputs
from tests.integration.test_hardhat_capture_protocol_consumption import CONTROL
from tests.integration.test_hardhat_capture_protocol_consumption import node as node
from tests.integration.test_hardhat_phase_layout_consumption import (
    short_private_root as short_private_root,
)
from tests.unit import test_hardhat_isolation_backend as bridge_controls
from tests.unit.test_hardhat_isolation_backend import live_private_bridge as live_private_bridge
from tests.unit.test_hardhat_isolation_backend import loopback_origin as loopback_origin

CLEANUP_CONTROL = Path(__file__).parents[1] / "fixtures/container_cleanup/control.py"


@pytest.fixture(autouse=True)
def fixed_external_runtime_file(monkeypatch):
    original = bridge_controls._backend

    def backend(**kwargs):
        return original(executable=str(Path(sys.executable).resolve(strict=True)), **kwargs)

    monkeypatch.setattr(bridge_controls, "_backend", backend)


@pytest.fixture
def live_finalization(live_private_bridge, node, monkeypatch):
    private, _, backend, bridge, binding = live_private_bridge
    root, config, request, _ = inputs(private)
    request = type(request).sealed(
        **{
            **request.model_dump(exclude={"request_sha256"}),
            "image": backend.image,
            "isolation_capability_sha256": backend.hardhat_loopback_capability_sha256,
            "bridge_policy_sha256": bridge.live_unix_listener_observation().policy_sha256,
        }
    )
    original = subprocess.Popen
    processes, calls, registered = [], [], {}
    state = SimpleNamespace(
        mode="pass",
        exit_code=0,
        failed_phase=None,
        missing_phase=None,
        changed_ambient=False,
        close_binding=False,
        slow_cleanup=False,
        calls=calls,
        processes=processes,
        registered=registered,
    )

    class FixedBoundary:
        def image_command(self, phase_request, *, prepared):
            return ("hardhat", "test")  # Constructed but never executed.

        def admitted_launch(self, phase_request, layout, *, prepared, absolute_deadline):
            phase = phase_request.phase
            record = SimpleNamespace(
                request=phase_request,
                layout=layout,
                prepared=prepared,
                cid=("a" if phase == "inventory" else "b") * 64,
                environment=None,
            )
            registered[layout.command] = record
            return finalize_hardhat_phase(
                phase_request,
                layout,
                private_dir=private,
                backend=backend,
                bridge=bridge,
                binding=binding,
                absolute_deadline=(
                    min(absolute_deadline, time.monotonic() + 0.5)
                    if state.slow_cleanup
                    else absolute_deadline
                ),
            )

    def launch(command, **kwargs):
        assert command[0] == backend.executable
        assert kwargs["shell"] is False and kwargs["close_fds"] is True
        assert kwargs["start_new_session"] is True and kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.PIPE
        if command[1] == "run":
            record = registered[command]
            phase = record.request.phase
            record.environment = kwargs["env"].copy()
            assert record.environment["HOME"] == str(
                record.layout.private_dir / "runtime-client/runtime-home"
            )
            assert kwargs["cwd"] == root
            cidfile = record.layout.private_dir / "container-runtime/container.cid"
            assert not cidfile.exists()
            if state.missing_phase != phase:
                cidfile.write_text(record.cid, encoding="ascii")  # Synthetic runtime producer only.
            prepared = record.prepared
            fixed = (
                node,
                str(CONTROL),
                str(HARDHAT_REPORTER_SOURCE_PATH),
                str(record.layout.output_root / "hardhat-report.json"),
                str(root),
                record.request.model_dump_json(),
                prepared.selection.model_dump_json() if prepared is not None else "{}",
                state.mode if prepared is not None else "pass",
                str(state.exit_code if prepared is not None else 0),
            )
            if state.changed_ambient:
                monkeypatch.setenv("DOCKER_HOST", "unix:///synthetic/changed-after-launch.sock")
            if state.close_binding:
                binding.close()
            kind = "reporter"
        else:
            matches = [
                record for record in registered.values() if command[-1] == "id=" + record.cid
            ]
            assert len(matches) == 1
            record = matches[0]
            phase = record.request.phase
            assert command == (
                backend.executable,
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--quiet",
                "--filter",
                "id=" + record.cid,
            )
            assert kwargs["cwd"] == record.layout.private_dir / "container-runtime"
            assert kwargs["env"] == record.environment
            mode = (
                "error"
                if state.failed_phase == phase
                else "timeout"
                if state.slow_cleanup
                else "absent"
            )
            fixed = (backend.executable, "-I", str(CLEANUP_CONTROL), mode)
            kind = "cleanup"
        calls.append((phase, kind, kwargs["env"].copy()))
        # Guarded fixed controls only: no runtime argv, image or target JavaScript is executed.
        process = original(fixed, **kwargs)
        processes.append(process)
        return process

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: finalizer integration cannot execute a container runtime")

    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(subprocess, "run", forbidden)
    state.kwargs = dict(
        request=request,
        root=root,
        private_dir=private,
        smart_contracts=config,
        backend=backend,
        bridge=bridge,
        binding=binding,
        boundary=FixedBoundary(),
    )
    yield state
    for process in processes:
        alive = process.poll() is None
        if alive:
            process.kill()
            process.wait(timeout=2)
        assert not alive, "owned fixed child needed fixture emergency cleanup"
        assert process.stdout.closed and process.stderr.closed


@pytest.mark.parametrize(
    "mode,exit_code,status",
    [
        ("pass", 0, RepositoryTestExecutionStatus.PASSED),
        ("fail", 7, RepositoryTestExecutionStatus.FAILED),
        ("skip", 0, RepositoryTestExecutionStatus.SKIPPED),
    ],
)
def test_both_real_fixed_phases_require_typed_cleanup_before_noncrediting_result(
    live_finalization, mode, exit_code, status
):
    state = live_finalization
    state.mode, state.exit_code = mode, exit_code
    result = execution.capture_hardhat_two_phase_execution(**state.kwargs)
    assert [(phase, kind) for phase, kind, _ in state.calls] == [
        ("inventory", "reporter"),
        ("inventory", "cleanup"),
        ("test", "reporter"),
        ("test", "cleanup"),
    ]
    assert result.report.results[0].status is status
    assert (
        result.execution_credit
        is result.runtime_authority
        is result.report.execution_credit
        is False
    )
    assert result.bridge_snapshot.stopped_cleanly
    for record in state.registered.values():
        assert not (record.layout.private_dir / "container-runtime/container.cid").exists()
        assert (record.layout.private_dir / ".mmaudit-hardhat-finalizer").exists()


@pytest.mark.parametrize("phase", ["inventory", "test"])
def test_actual_failed_cleanup_response_prevents_phase_completion(live_finalization, phase):
    state = live_finalization
    state.failed_phase = phase
    with pytest.raises(RuntimeError):
        execution.capture_hardhat_two_phase_execution(**state.kwargs)
    assert len(state.processes) == (2 if phase == "inventory" else 4)
    record = next(r for r in state.registered.values() if r.request.phase == phase)
    assert (record.layout.private_dir / "container-runtime/container.cid").read_text() == record.cid
    assert state.kwargs["bridge"].snapshot().stopped_cleanly


@pytest.mark.parametrize("phase", ["inventory", "test"])
def test_missing_mock_runtime_identifier_never_becomes_a_cleanup_pass(live_finalization, phase):
    state = live_finalization
    state.missing_phase = phase
    with pytest.raises(ValueError):
        execution.capture_hardhat_two_phase_execution(**state.kwargs)
    assert len(state.processes) == (1 if phase == "inventory" else 3)
    assert state.kwargs["bridge"].snapshot().stopped_cleanly


def test_ambient_route_change_cannot_redirect_cleanup_of_an_entered_phase(
    live_finalization, monkeypatch
):
    state = live_finalization
    monkeypatch.setenv("DOCKER_HOST", "unix:///synthetic/original-launch.sock")
    state.changed_ambient = True
    result = execution.capture_hardhat_two_phase_execution(**state.kwargs)
    assert state.calls[0][2] == state.calls[1][2]
    assert state.calls[0][2]["DOCKER_HOST"] == "unix:///synthetic/original-launch.sock"
    assert state.calls[2][2] == state.calls[3][2]
    assert result.runtime_authority is False


def test_closed_bridge_binding_cannot_skip_original_phase_cleanup(live_finalization):
    state = live_finalization
    state.close_binding = True
    with pytest.raises(ValueError):
        execution.capture_hardhat_two_phase_execution(**state.kwargs)
    assert [(phase, kind) for phase, kind, _ in state.calls] == [
        ("inventory", "reporter"),
        ("inventory", "cleanup"),
    ]
    assert state.kwargs["bridge"].snapshot().stopped_cleanly


def test_late_real_cleanup_finishes_owned_control_but_cannot_return_result(live_finalization):
    state = live_finalization
    state.slow_cleanup = True
    with pytest.raises(ValueError, match="deadline"):
        execution.capture_hardhat_two_phase_execution(**state.kwargs)
    assert len(state.processes) == 2 and state.calls[-1][1] == "cleanup"
    assert state.kwargs["bridge"].snapshot().stopped_cleanly
