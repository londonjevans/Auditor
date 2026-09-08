"""Owned lifecycle state-machine controls: no network, container or real process."""

from __future__ import annotations

import socket
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from mmaudit.isolation.container import HardhatPhaseCommand, HardhatReadOnlyRpcBridgeBinding
from mmaudit.scanners import hardhat_execution as execution
from mmaudit.scanners.hardhat_supervision import HardhatCaptureOutcome
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge
from tests.hardhat_capture_support import execution_capture, inputs
from tests.unit.test_hardhat_isolation_backend import _backend


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: lifecycle unit controls cannot execute or open sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture
def lifecycle(tmp_path, monkeypatch):
    private = tmp_path.resolve() / "private"
    private.mkdir(mode=0o700)
    root, config, request, inventory = inputs(private)
    events = []
    clock = [100.0]
    backend = _backend()
    bridge = object.__new__(ReadOnlyRpcBridge)
    binding = object.__new__(HardhatReadOnlyRpcBridgeBinding)
    snapshot = SimpleNamespace(
        status="enforced",
        policy_sha256=request.bridge_policy_sha256,
        expected_chain_id=request.chain_id,
        pinned_block_number=request.block_number,
        pinned_block_hash=request.block_hash,
    )

    def verify(self, selected_backend, private_dir, *, bridge=None):
        assert self is binding and selected_backend is backend and private_dir == private
        assert bridge is state.bridge
        events.append("verify")

    def wrap(self, command, phase_request, *, workspace, private_dir, binding):
        assert self is backend and command == ("hardhat", "test")
        assert workspace == root and private_dir == private and binding is state.binding
        phase = private / f"hardhat-{phase_request.phase}-{phase_request.request_sha256}"
        phase.mkdir(mode=0o700)
        output = phase / "container-output"
        output.mkdir(mode=0o700)
        return HardhatPhaseCommand(
            phase_request.phase,
            phase_request.request_sha256,
            phase,
            output,
            ("synthetic-unexecuted-container",),
        )

    class Boundary:
        def image_command(self, phase_request, *, prepared):
            events.append(f"build-{phase_request.phase}")
            return ("hardhat", "test")

        @contextmanager
        def admitted_launch(self, phase_request, layout, *, prepared, absolute_deadline):
            events.append(f"enter-{phase_request.phase}")
            assert absolute_deadline == 110.0
            state.prepared = prepared
            try:
                yield execution.HardhatPhaseLaunch(
                    (str(Path(sys.executable).resolve(strict=True)),), {}
                )
            finally:
                events.append(f"cleanup-{phase_request.phase}")

    def capture(phase_request, **kwargs):
        events.append(f"capture-{phase_request.phase}")
        assert kwargs["absolute_deadline"] == 110.0
        state.allowances.append(kwargs["maximum_output_bytes"])
        return (
            inventory if phase_request.phase == "inventory" else execution_capture(state.prepared)
        )

    monkeypatch.setattr(execution.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(HardhatReadOnlyRpcBridgeBinding, "verify", verify)
    monkeypatch.setattr(
        HardhatReadOnlyRpcBridgeBinding, "close", lambda self: events.append("close")
    )
    monkeypatch.setattr(ReadOnlyRpcBridge, "stop", lambda self: events.append("stop"))
    monkeypatch.setattr(ReadOnlyRpcBridge, "snapshot", lambda self: snapshot)
    monkeypatch.setattr(type(backend), "wrap_hardhat_phase", wrap)
    monkeypatch.setattr(execution, "supervise_hardhat_phase_process", capture)
    state = SimpleNamespace(
        request=request,
        inventory=inventory,
        root=root,
        config=config,
        backend=backend,
        bridge=bridge,
        binding=binding,
        boundary=Boundary(),
        clock=clock,
        events=events,
        snapshot=snapshot,
        prepared=None,
        allowances=[],
    )
    state.kwargs = dict(
        request=request,
        root=root,
        private_dir=private,
        smart_contracts=config,
        backend=backend,
        bridge=bridge,
        binding=binding,
        boundary=state.boundary,
    )
    return state


def test_complete_lifecycle_consumes_both_phases_then_stops_without_credit(lifecycle):
    result = execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert result.execution_credit is result.runtime_authority is False
    assert result.report.execution_credit is False
    assert result.report.request_sha256 == result.prepared.test_request.request_sha256
    assert result.duration_seconds == 0.0
    assert lifecycle.events[-2:] == ["close", "stop"]
    assert [x for x in lifecycle.events if x != "verify"] == [
        "build-inventory",
        "enter-inventory",
        "capture-inventory",
        "cleanup-inventory",
        "build-test",
        "enter-test",
        "capture-test",
        "cleanup-test",
        "close",
        "stop",
    ]
    assert lifecycle.allowances == [
        lifecycle.request.maximum_output_bytes,
        lifecycle.request.maximum_output_bytes - len(lifecycle.inventory.report),
    ]


@pytest.mark.parametrize(
    "field", ["request", "smart_contracts", "backend", "bridge", "binding", "boundary"]
)
def test_invalid_input_does_not_claim_or_close_unrelated_resources(lifecycle, field):
    lifecycle.kwargs[field] = object()
    with pytest.raises(execution.HardhatExecutionError):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert not lifecycle.events


def test_failed_initial_binding_does_not_close_unrelated_resources(lifecycle, monkeypatch):
    def reject(*args, **kwargs):
        raise ValueError("synthetic mismatched owner")

    monkeypatch.setattr(HardhatReadOnlyRpcBridgeBinding, "verify", reject)
    with pytest.raises(ValueError, match="mismatched owner"):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert not lifecycle.events


@pytest.mark.parametrize(
    "stage",
    [
        "build-inventory",
        "enter-inventory",
        "cleanup-inventory",
        "build-test",
        "enter-test",
        "cleanup-test",
        "stop",
    ],
)
def test_shared_deadline_covers_preparation_phase_gaps_and_shutdown(lifecycle, monkeypatch, stage):
    # Intercept only the relevant trusted operation; cleanup must still run after expiry.
    boundary = lifecycle.boundary
    original_build, original_launch = boundary.image_command, boundary.admitted_launch

    def build(phase_request, **kwargs):
        result = original_build(phase_request, **kwargs)
        if stage == f"build-{phase_request.phase}":
            lifecycle.clock[0] = 110.0
        return result

    @contextmanager
    def launch(phase_request, *args, **kwargs):
        with original_launch(phase_request, *args, **kwargs) as selected:
            if stage == f"enter-{phase_request.phase}":
                lifecycle.clock[0] = 110.0
            try:
                yield selected
            finally:
                if stage == f"cleanup-{phase_request.phase}":
                    lifecycle.clock[0] = 110.0

    def stop(self):
        lifecycle.events.append("stop")
        lifecycle.clock[0] = 110.0

    monkeypatch.setattr(boundary, "image_command", build)
    monkeypatch.setattr(boundary, "admitted_launch", launch)
    if stage == "stop":
        monkeypatch.setattr(ReadOnlyRpcBridge, "stop", stop)
    with pytest.raises(execution.HardhatExecutionError, match="deadline"):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert lifecycle.events[-2:] == ["close", "stop"]
    if stage.endswith("inventory"):
        assert "capture-test" not in lifecycle.events


@pytest.mark.parametrize("problem", ["error", "interrupt", "exit"])
def test_primary_failure_survives_phase_and_bridge_cleanup_errors(lifecycle, monkeypatch, problem):
    sentinel = {
        "error": RuntimeError("synthetic primary"),
        "interrupt": KeyboardInterrupt(),
        "exit": SystemExit(2),
    }[problem]

    def fail(*args, **kwargs):
        raise sentinel

    @contextmanager
    def launch(*args, **kwargs):
        try:
            yield execution.HardhatPhaseLaunch(("synthetic",), {})
        finally:
            lifecycle.events.append("phase-cleanup")
            raise ValueError("synthetic secondary")

    def stop(self):
        lifecycle.events.append("stop")
        raise ValueError("synthetic shutdown error")

    monkeypatch.setattr(execution, "supervise_hardhat_phase_process", fail)
    monkeypatch.setattr(lifecycle.boundary, "admitted_launch", launch)
    monkeypatch.setattr(ReadOnlyRpcBridge, "stop", stop)
    with pytest.raises(type(sentinel)) as raised:
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert raised.value is sentinel
    assert lifecycle.events[-3:] == ["phase-cleanup", "close", "stop"]


@pytest.mark.parametrize("stage", ["close", "stop", "snapshot"])
def test_finalization_failure_never_returns_observations(lifecycle, monkeypatch, stage):
    def fail(self):
        lifecycle.events.append(stage)
        raise ValueError("synthetic finalization failure")

    target = HardhatReadOnlyRpcBridgeBinding if stage == "close" else ReadOnlyRpcBridge
    monkeypatch.setattr(target, stage, fail)
    with pytest.raises(ValueError, match="finalization failure"):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert "close" in lifecycle.events and "stop" in lifecycle.events


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "violation"),
        ("policy_sha256", "b" * 64),
        ("expected_chain_id", 1),
        ("pinned_block_number", 1),
        ("pinned_block_hash", "0x" + "a" * 64),
    ],
)
def test_stopped_bridge_snapshot_must_match_request(lifecycle, field, value):
    setattr(lifecycle.snapshot, field, value)
    with pytest.raises(execution.HardhatExecutionError, match="bridge observations"):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)


@pytest.mark.parametrize("change", ["source", "root", "config", "request", "phase_request"])
def test_changed_custody_during_launch_refuses_and_cleans(lifecycle, monkeypatch, change):
    @contextmanager
    def launch(phase_request, *args, **kwargs):
        try:
            if change == "source":
                (lifecycle.root / "test/audit/Vault.ts").write_bytes(b"changed synthetic source")
            elif change == "root":
                lifecycle.root.rename(lifecycle.root.with_name("retained-source"))
                lifecycle.root.mkdir()
            elif change == "config":
                lifecycle.config.repository_suite.total_timeout_seconds = 9
            elif change == "request":
                lifecycle.request.chain_id = 1
            else:
                phase_request.chain_id = 1
            yield execution.HardhatPhaseLaunch(("synthetic",), {})
        finally:
            lifecycle.events.append("phase-cleanup")

    monkeypatch.setattr(lifecycle.boundary, "admitted_launch", launch)
    with pytest.raises(ValueError):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert "capture-inventory" not in lifecycle.events
    assert lifecycle.events[-3:] == ["phase-cleanup", "close", "stop"]


def test_missing_inventory_cannot_start_second_phase(lifecycle, monkeypatch):
    monkeypatch.setattr(
        execution,
        "supervise_hardhat_phase_process",
        lambda *args, **kwargs: replace(
            lifecycle.inventory, outcome=HardhatCaptureOutcome.TIMED_OUT, report=None
        ),
    )
    with pytest.raises(ValueError):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert "build-test" not in lifecycle.events
    assert lifecycle.events[-2:] == ["close", "stop"]


@pytest.mark.parametrize("stage", ["prepare", "consume", "final-consume"])
def test_protocol_work_is_inside_the_shared_deadline(lifecycle, monkeypatch, stage):
    name = (
        "prepare_hardhat_test_phase_from_capture"
        if stage == "prepare"
        else "consume_hardhat_test_phase_capture"
    )
    original = getattr(execution, name)
    calls = 0

    def consume(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if stage != "final-consume" or calls == 2:
            lifecycle.clock[0] = 110.0
        return result

    monkeypatch.setattr(execution, name, consume)
    with pytest.raises(execution.HardhatExecutionError, match="deadline"):
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert lifecycle.events[-2:] == ["close", "stop"]
    if stage == "prepare":
        assert "build-test" not in lifecycle.events


def test_context_manager_cannot_suppress_a_primary_capture_error(lifecycle, monkeypatch):
    sentinel = RuntimeError("synthetic primary")

    class SuppressingManager:
        def __enter__(self):
            return execution.HardhatPhaseLaunch(("synthetic",), {})

        def __exit__(self, exc_type, exc, traceback):
            assert exc is sentinel
            lifecycle.events.append("phase-cleanup")
            return True

    def fail(*args, **kwargs):
        raise sentinel

    monkeypatch.setattr(lifecycle.boundary, "admitted_launch", lambda *a, **k: SuppressingManager())
    monkeypatch.setattr(execution, "supervise_hardhat_phase_process", fail)
    with pytest.raises(RuntimeError) as raised:
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert raised.value is sentinel
    assert lifecycle.events[-3:] == ["phase-cleanup", "close", "stop"]


@pytest.mark.parametrize("stage", ["build", "manager", "enter"])
def test_preparation_errors_still_close_the_owned_bridge(lifecycle, monkeypatch, stage):
    sentinel = RuntimeError("synthetic preparation failure")

    def fail(*args, **kwargs):
        raise sentinel

    class Manager:
        def __enter__(self):
            raise sentinel

        def __exit__(self, *args):
            pytest.fail("entry failure has not transferred a phase resource")

    if stage == "build":
        monkeypatch.setattr(lifecycle.boundary, "image_command", fail)
    elif stage == "manager":
        monkeypatch.setattr(lifecycle.boundary, "admitted_launch", fail)
    else:
        monkeypatch.setattr(lifecycle.boundary, "admitted_launch", lambda *a, **k: Manager())
    with pytest.raises(RuntimeError) as raised:
        execution.capture_hardhat_two_phase_execution(**lifecycle.kwargs)
    assert raised.value is sentinel
    assert lifecycle.events[-2:] == ["close", "stop"]
    assert "capture-inventory" not in lifecycle.events
