"""Phase finalization state-machine controls: no process, network or image admission."""

from __future__ import annotations

import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from mmaudit.isolation import container_cleanup as cleanup
from mmaudit.isolation.container import HardhatPhaseCommand, HardhatReadOnlyRpcBridgeBinding
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.scanners import hardhat_finalization as finalization
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge
from tests.unit.test_hardhat_isolation_backend import _backend
from tests.unit.test_hardhat_protocol import _inventory_request

CID = "a" * 64


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: finalizer unit controls cannot execute or open sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


@pytest.fixture
def phase(tmp_path, monkeypatch):
    private = tmp_path.resolve() / "private"
    private.mkdir(mode=0o700)
    backend = _backend(executable=str(Path(sys.executable).resolve(strict=True)))
    original = _inventory_request()
    request = type(original).sealed(
        **{
            **original.model_dump(exclude={"request_sha256"}),
            "image": backend.image,
            "isolation_capability_sha256": backend.hardhat_loopback_capability_sha256,
        }
    )
    directory = private / f"hardhat-inventory-{request.request_sha256}"
    directory.mkdir(mode=0o700)
    runtime, output = directory / "container-runtime", directory / "container-output"
    runtime.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    cidfile = runtime / "container.cid"
    layout = HardhatPhaseCommand(
        request.phase,
        request.request_sha256,
        directory,
        output,
        (backend.executable, "run", "--cidfile", str(cidfile), backend.image),
    )
    bridge = object.__new__(ReadOnlyRpcBridge)
    binding = object.__new__(HardhatReadOnlyRpcBridgeBinding)
    observation = SimpleNamespace(
        policy_sha256=request.bridge_policy_sha256,
        preflight_origin_observation_sha256="b" * 64,
        state_sha256=canonical_sha256(
            {
                "version": "MMAUDIT_READ_ONLY_RPC_LIVE_STATE_V1",
                "origin_endpoint": backend.approved_loopback_rpc_endpoint,
                "expected_chain_id": request.chain_id,
                "pinned_block_number": request.block_number,
                "pinned_block_hash": request.block_hash,
                "preflight_origin_observation_sha256": "b" * 64,
            }
        ),
    )
    clock = [100.0]
    calls, controls = [], []
    state = SimpleNamespace(
        request=request,
        layout=layout,
        private=private,
        directory=directory,
        runtime=runtime,
        output=output,
        cidfile=cidfile,
        backend=backend,
        bridge=bridge,
        binding=binding,
        observation=observation,
        clock=clock,
        calls=calls,
        controls=controls,
        live=True,
    )

    def verify(self, selected_backend, private_dir, *, bridge):
        assert self is binding and selected_backend is backend
        assert private_dir == private and bridge is state.bridge
        if not state.live:
            raise ValueError("synthetic live binding ended")

    actual_cleanup = cleanup.cleanup_rootless_container

    def tracked(selected_backend, private_dir, **kwargs):
        calls.append((selected_backend, private_dir, kwargs))
        return actual_cleanup(selected_backend, private_dir, **kwargs)

    def control(command, **kwargs):
        controls.append((command, kwargs))
        return b""  # MOCK exact runtime reports the selected CID absent.

    monkeypatch.setattr(finalization.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(HardhatReadOnlyRpcBridgeBinding, "verify", verify)
    monkeypatch.setattr(
        ReadOnlyRpcBridge, "live_unix_listener_observation", lambda self: observation
    )
    monkeypatch.setattr(finalization, "cleanup_rootless_container", tracked)
    monkeypatch.setattr(cleanup, "_run_control_command", control)
    state.kwargs = dict(
        request=request,
        layout=layout,
        private_dir=private,
        backend=backend,
        bridge=bridge,
        binding=binding,
        absolute_deadline=110.0,
    )
    return state


def test_phase_retains_exact_environment_identity_and_noncrediting_cleanup(phase, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "unix:///synthetic/launch.sock")
    with finalization.finalize_hardhat_phase(**phase.kwargs) as launch:
        assert launch.command == phase.layout.command
        phase.cidfile.write_text(CID)
        monkeypatch.setenv("DOCKER_HOST", "unix:///synthetic/changed.sock")
    assert len(phase.calls) == len(phase.controls) == 1
    backend, private, kwargs = phase.calls[0]
    assert backend is not phase.backend and backend == phase.backend
    assert private == phase.directory and kwargs["expected_container_id"] == CID
    assert kwargs["environment"] == launch.environment
    assert kwargs["environment"]["DOCKER_HOST"] == "unix:///synthetic/launch.sock"
    assert kwargs["expected_runtime_identity"].sha256
    assert phase.controls[0][0][-1] == "id=" + CID
    assert not phase.cidfile.exists()
    assert (phase.directory / finalization._FINALIZER_CLAIM).exists()


@pytest.mark.parametrize("field", ["request", "layout", "backend", "bridge", "binding"])
def test_wrong_input_type_refuses_without_launch_or_cleanup(phase, field):
    phase.kwargs[field] = object()
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs):
        pytest.fail("invalid input yielded")
    assert not phase.calls


@pytest.mark.parametrize(
    "value", [True, False, 0, 99, 100, 110.1, float("inf"), float("nan"), "110"]
)
def test_bad_or_expired_deadline_refuses_before_claim(phase, value):
    phase.kwargs["absolute_deadline"] = value
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs):
        pytest.fail("invalid deadline yielded")
    assert not phase.calls and not (phase.directory / finalization._FINALIZER_CLAIM).exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("phase", "test"),
        ("request_sha256", "b" * 64),
        ("command", ()),
        ("command", ("/usr/bin/false", "--cidfile")),
    ],
)
def test_mismatched_layout_refuses_before_claim(phase, field, value):
    phase.kwargs["layout"] = replace(phase.layout, **{field: value})
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs):
        pytest.fail("invalid layout yielded")
    assert not phase.calls


def test_preexisting_cid_is_never_adopted_or_removed(phase):
    phase.cidfile.write_text(CID)
    with (
        pytest.raises(ValueError, match="preexisting"),
        finalization.finalize_hardhat_phase(**phase.kwargs),
    ):
        pytest.fail("stale phase yielded")
    assert phase.cidfile.read_text() == CID and not phase.calls


def test_missing_cid_after_handoff_is_not_success(phase):
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs):
        pass
    assert not phase.calls and not phase.controls


def test_successful_phase_claim_cannot_be_reused(phase):
    with finalization.finalize_hardhat_phase(**phase.kwargs):
        phase.cidfile.write_text(CID)
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs):
        pytest.fail("used phase yielded")
    assert len(phase.calls) == 1


@pytest.mark.parametrize(
    "drift",
    [
        "request",
        "layout",
        "launch_command",
        "coherent_command",
        "environment",
        "backend",
        "nested_backend",
        "binding",
        "output",
    ],
)
def test_phase_drift_refuses_but_still_cleans_original_safe_selection(phase, drift):
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs) as launch:
        phase.cidfile.write_text(CID)
        if drift == "request":
            object.__setattr__(phase.request, "chain_id", 1)
        elif drift in {"layout", "coherent_command", "launch_command"}:
            command = (*launch.command, "synthetic-changed")
            if drift != "launch_command":
                object.__setattr__(phase.layout, "command", command)
            if drift != "layout":
                object.__setattr__(launch, "command", command)
        elif drift == "environment":
            launch.environment["DOCKER_HOST"] = "unix:///synthetic/changed.sock"
        elif drift == "backend":
            object.__setattr__(phase.backend, "executable", "/synthetic/unrelated")
        elif drift == "nested_backend":
            object.__setattr__(phase.backend.limits, "pids", 2)
        elif drift == "binding":
            phase.live = False
        else:
            phase.output.chmod(0o755)
    assert len(phase.calls) == 1 and not phase.cidfile.exists()
    assert phase.calls[0][0].executable == str(Path(sys.executable).resolve(strict=True))
    assert phase.calls[0][0].limits.pids != 2


@pytest.mark.parametrize(
    "drift", ["runtime", "client", "home", "claim", "claim_identity", "executable"]
)
def test_unsafe_cleanup_selection_never_invokes_changed_runtime(phase, monkeypatch, drift):
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs) as launch:
        phase.cidfile.write_text(CID)
        if drift in {"runtime", "client", "home"}:
            path = {
                "runtime": phase.runtime,
                "client": phase.directory / "runtime-client",
                "home": Path(launch.environment["HOME"]),
            }[drift]
            path.chmod(0o755)
        elif drift.startswith("claim"):
            claim = phase.directory / finalization._FINALIZER_CLAIM
            content = claim.read_bytes()
            claim.rename(claim.with_suffix(".retained"))
            claim.write_bytes(content if drift == "claim_identity" else b"b" * 64 + b"\n")
        else:
            monkeypatch.setattr(finalization, "_runtime_identity", lambda *_: None)
    assert not phase.calls and phase.cidfile.read_text() == CID


@pytest.mark.parametrize(
    "error", [RuntimeError("primary capture"), KeyboardInterrupt(), SystemExit(7)]
)
def test_primary_capture_failure_survives_failed_finalization(phase, monkeypatch, error):
    def failed(*args, **kwargs):
        phase.calls.append("failed cleanup")
        raise RuntimeError("secondary cleanup error")

    monkeypatch.setattr(finalization, "cleanup_rootless_container", failed)
    with pytest.raises(type(error)) as caught, finalization.finalize_hardhat_phase(**phase.kwargs):
        phase.cidfile.write_text(CID)
        raise error
    assert caught.value is error and phase.calls == ["failed cleanup"]
    assert "Hardhat phase finalization was incomplete" in error.__notes__[-1]


def test_shared_expiry_cannot_skip_emergency_cleanup_or_return_success(phase):
    with (
        pytest.raises(ValueError, match="deadline"),
        finalization.finalize_hardhat_phase(**phase.kwargs),
    ):
        phase.cidfile.write_text(CID)
        phase.clock[0] = 111.0
    assert len(phase.calls) == 1 and not phase.cidfile.exists()
    assert phase.controls[0][1]["deadline"] == 121.0


@pytest.mark.parametrize(
    "result",
    [
        None,
        {},
        cleanup.ContainerCleanupObservation(cleanup.ContainerCleanupStatus.NO_IDENTIFIER, None),
        cleanup.ContainerCleanupObservation(
            cleanup.ContainerCleanupStatus.ALREADY_ABSENT, "b" * 64
        ),
    ],
)
def test_incomplete_or_wrong_cleanup_result_cannot_finish_phase(phase, monkeypatch, result):
    monkeypatch.setattr(finalization, "cleanup_rootless_container", lambda *args, **kwargs: result)
    with (
        pytest.raises(ValueError, match="establish absence"),
        finalization.finalize_hardhat_phase(**phase.kwargs),
    ):
        phase.cidfile.write_text(CID)
    assert phase.cidfile.exists()


def test_preexisting_client_alias_cannot_create_files_outside_phase(phase):
    target = phase.private / "synthetic-canary"
    target.mkdir(mode=0o700)
    (phase.directory / "runtime-client").symlink_to(target, target_is_directory=True)
    with pytest.raises(FileExistsError), finalization.finalize_hardhat_phase(**phase.kwargs):
        pytest.fail("client alias yielded")
    assert not list(target.iterdir()) and not phase.calls


@pytest.mark.parametrize("tail", [(None,), ("nul\x00argument",), ("a" * (128 * 1024),), (True,)])
def test_phase_argv_bounds_are_checked_before_the_retained_claim(phase, tail):
    phase.kwargs["layout"] = replace(phase.layout, command=(*phase.layout.command, *tail))
    with pytest.raises(ValueError), finalization.finalize_hardhat_phase(**phase.kwargs):
        pytest.fail("unbounded or malformed argv yielded")
    assert not phase.calls and not (phase.directory / finalization._FINALIZER_CLAIM).exists()


@pytest.mark.parametrize("clock", [90.0, float("nan")])
def test_invalid_posthandoff_clock_cannot_return_success(phase, clock):
    with (
        pytest.raises(ValueError, match="clock"),
        finalization.finalize_hardhat_phase(**phase.kwargs),
    ):
        phase.cidfile.write_text(CID)
        phase.clock[0] = clock
    assert len(phase.calls) == 1 and not phase.cidfile.exists()


def test_slow_preparation_cannot_yield_launch_or_start_cleanup(phase, monkeypatch):
    original = type(phase.backend).host_environment

    def slow(self, private):
        result = original(self, private)
        phase.clock[0] = 111.0
        return result

    monkeypatch.setattr(type(phase.backend), "host_environment", slow)
    with (
        pytest.raises(ValueError, match="deadline"),
        finalization.finalize_hardhat_phase(**phase.kwargs),
    ):
        pytest.fail("late preparation yielded")
    assert not phase.calls and not phase.cidfile.exists()


def test_invalid_exception_notes_cannot_mask_primary_failure(phase, monkeypatch):
    error = RuntimeError("primary")
    error.__notes__ = "synthetic invalid notes"
    monkeypatch.setattr(finalization, "cleanup_rootless_container", lambda *args, **kwargs: None)
    with pytest.raises(RuntimeError) as caught, finalization.finalize_hardhat_phase(**phase.kwargs):
        phase.cidfile.write_text(CID)
        raise error
    assert caught.value is error
