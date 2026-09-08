"""Actual two-phase fixed reporter plus owned bridge; never Hardhat/Mocha/container evidence."""

from __future__ import annotations

import json
import subprocess
from contextlib import contextmanager

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, RepositoryTestExecutionStatus
from mmaudit.scanners import hardhat_execution as execution
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SOURCE_PATH
from mmaudit.scanners.hardhat_protocol import HardhatProtocolBindingError
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge
from tests.hardhat_capture_support import inputs
from tests.integration.test_hardhat_capture_protocol_consumption import CONTROL
from tests.integration.test_hardhat_capture_protocol_consumption import node as node
from tests.integration.test_hardhat_phase_layout_consumption import (
    short_private_root as short_private_root,
)
from tests.unit.test_hardhat_isolation_backend import live_private_bridge as live_private_bridge
from tests.unit.test_hardhat_isolation_backend import loopback_origin as loopback_origin


@pytest.fixture(autouse=True)
def owned_fixed_processes(monkeypatch, node):
    original = subprocess.Popen
    processes = []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: two-phase controls cannot invoke a container runtime")

    def launch(command, **kwargs):
        assert command[:3] == (node, str(CONTROL), str(HARDHAT_REPORTER_SOURCE_PATH))
        assert kwargs["env"] == {} and kwargs["shell"] is False
        assert kwargs["start_new_session"] is True and kwargs["close_fds"] is True
        process = original(command, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", launch)
    yield processes
    for process in processes:
        alive = process.poll() is None
        if alive:
            process.kill()
            process.wait(timeout=2)
        assert not alive, "owned reporter child required emergency fixture cleanup"
        assert process.stdout.closed and process.stderr.closed


@pytest.fixture
def live_execution(live_private_bridge, node):
    private, _, backend, bridge, binding = live_private_bridge
    root, config, request, _ = inputs(private)
    values = request.model_dump(exclude={"request_sha256"})
    values.update(
        image=backend.image,
        isolation_capability_sha256=backend.hardhat_loopback_capability_sha256,
        bridge_policy_sha256=bridge.live_unix_listener_observation().policy_sha256,
    )
    request = type(request).sealed(**values)
    events = []

    class FixedReporterBoundary:
        mode = "pass"
        exit_code = 0
        stale_phase = None
        close_after_inventory = False
        fail_cleanup = False

        def image_command(self, phase_request, *, prepared):
            return ("hardhat", "test")  # Constructed only; never an admitted fixture command.

        @contextmanager
        def admitted_launch(self, phase_request, layout, *, prepared, absolute_deadline):
            events.append(f"enter-{phase_request.phase}")
            assert layout.request_sha256 == phase_request.request_sha256
            assert layout.execution_credit is layout.runtime_authority is False
            assert not (layout.private_dir / "container-runtime/container.cid").exists()
            payload = phase_request.model_dump(mode="json")
            if self.stale_phase == phase_request.phase:
                payload["request_sha256"] = "a" * 64
            try:
                yield execution.HardhatPhaseLaunch(
                    command=(
                        node,
                        str(CONTROL),
                        str(HARDHAT_REPORTER_SOURCE_PATH),
                        str(layout.output_root / "hardhat-report.json"),
                        str(root),
                        json.dumps(payload),
                        prepared.selection.model_dump_json() if prepared is not None else "{}",
                        self.mode if prepared is not None else "pass",
                        str(self.exit_code if prepared is not None else 0),
                    ),
                    environment={},
                )
            finally:
                events.append(f"cleanup-{phase_request.phase}")
                # No container was started: this exercises only missing-CID cleanup routing.
                backend.cleanup(layout.private_dir)
                if self.close_after_inventory and phase_request.phase == "inventory":
                    binding.close()
                if self.fail_cleanup:
                    raise ValueError("synthetic fixture finalizer failure")

    boundary = FixedReporterBoundary()
    kwargs = dict(
        request=request,
        root=root,
        private_dir=private,
        smart_contracts=config,
        backend=backend,
        bridge=bridge,
        binding=binding,
        boundary=boundary,
    )
    return kwargs, events


@pytest.mark.parametrize(
    "mode,exit_code,status",
    [
        ("pass", 0, RepositoryTestExecutionStatus.PASSED),
        ("fail", 7, RepositoryTestExecutionStatus.FAILED),
        ("skip", 0, RepositoryTestExecutionStatus.SKIPPED),
    ],
)
def test_owned_two_phase_reporter_returns_only_after_clean_bridge_shutdown(
    live_execution, owned_fixed_processes, mode, exit_code, status
):
    kwargs, events = live_execution
    kwargs["boundary"].mode = mode
    kwargs["boundary"].exit_code = exit_code
    result = execution.capture_hardhat_two_phase_execution(**kwargs)
    assert len(owned_fixed_processes) == 2
    assert events == ["enter-inventory", "cleanup-inventory", "enter-test", "cleanup-test"]
    assert result.report.results[0].status is status
    assert result.test_capture.process_exit_code == exit_code
    assert result.bridge_snapshot == kwargs["bridge"].snapshot()
    assert result.bridge_snapshot.stopped_cleanly and result.bridge_snapshot.status == "enforced"
    assert 0 < result.duration_seconds < kwargs["request"].timeout_seconds
    assert result.duration_seconds >= (
        result.prepared.inventory_capture.duration_seconds + result.test_capture.duration_seconds
    )
    assert (
        result.execution_credit
        is result.runtime_authority
        is result.report.execution_credit
        is False
    )
    assert kwargs["backend"].execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    with pytest.raises(ValueError):
        kwargs["binding"].verify(kwargs["backend"], kwargs["private_dir"])


@pytest.mark.parametrize("phase", ["inventory", "test"])
def test_stale_actual_report_still_finalizes_exact_owned_bridge(
    live_execution, owned_fixed_processes, phase
):
    kwargs, events = live_execution
    kwargs["boundary"].stale_phase = phase
    with pytest.raises(HardhatProtocolBindingError):
        execution.capture_hardhat_two_phase_execution(**kwargs)
    assert len(owned_fixed_processes) == (1 if phase == "inventory" else 2)
    assert events[-1] == f"cleanup-{phase}"
    assert kwargs["bridge"].snapshot().stopped_cleanly


@pytest.mark.parametrize("mode,exit_code", [("pass", 7), ("fail", 0)])
def test_actual_contradictory_terminal_report_never_passes(live_execution, mode, exit_code):
    kwargs, _ = live_execution
    kwargs["boundary"].mode, kwargs["boundary"].exit_code = mode, exit_code
    with pytest.raises(HardhatProtocolBindingError):
        execution.capture_hardhat_two_phase_execution(**kwargs)
    assert kwargs["bridge"].snapshot().stopped_cleanly


@pytest.mark.parametrize("change", ["binding", "finalizer"])
def test_owned_inventory_failure_cannot_launch_test_phase(
    live_execution, owned_fixed_processes, change
):
    kwargs, events = live_execution
    if change == "binding":
        kwargs["boundary"].close_after_inventory = True
    else:
        kwargs["boundary"].fail_cleanup = True
    with pytest.raises(ValueError):
        execution.capture_hardhat_two_phase_execution(**kwargs)
    assert len(owned_fixed_processes) == 1
    assert events == ["enter-inventory", "cleanup-inventory"]
    assert kwargs["bridge"].snapshot().stopped_cleanly


def test_an_unrelated_bridge_cannot_transfer_ownership(live_execution, owned_fixed_processes):
    kwargs, _ = live_execution
    original = kwargs["bridge"]
    kwargs["bridge"] = object.__new__(ReadOnlyRpcBridge)
    with pytest.raises(ValueError, match="retained bridge binding"):
        execution.capture_hardhat_two_phase_execution(**kwargs)
    assert not owned_fixed_processes
    kwargs["binding"].verify(kwargs["backend"], kwargs["private_dir"], bridge=original)


def test_closed_lifecycle_cannot_be_reused(live_execution, owned_fixed_processes):
    kwargs, _ = live_execution
    execution.capture_hardhat_two_phase_execution(**kwargs)
    with pytest.raises(ValueError, match="retained bridge binding"):
        execution.capture_hardhat_two_phase_execution(**kwargs)
    assert len(owned_fixed_processes) == 2
