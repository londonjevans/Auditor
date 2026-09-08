"""Single-use phase finalization for a trusted executor, never image or launch admission.

The caller must independently admit the exact returned command/environment before execution.
This context does not start a process or establish a real runtime/daemon/container identity.
"""

from __future__ import annotations

import math
import os
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, replace
from pathlib import Path

from mmaudit.isolation.container import (
    HardhatPhaseCommand,
    HardhatReadOnlyRpcBridgeBinding,
    SingleLoopbackHardhatBackend,
)
from mmaudit.isolation.container_cleanup import (
    ContainerCleanupObservation,
    ContainerCleanupStatus,
    _control_environment,
    _runtime_identity,
    cleanup_rootless_container,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_file_evidence, write_file_evidence
from mmaudit.scanners.hardhat_execution import HardhatPhaseLaunch
from mmaudit.scanners.hardhat_supervision import (
    HardhatPhaseRequest,
    _claim_identity,
    _command_and_environment,
    _detached_request,
    _root_identity,
)
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge

_FINALIZER_CLAIM = ".mmaudit-hardhat-finalizer"


class HardhatFinalizationError(ValueError):
    """An entered phase cannot provide a complete, unchanged finalization observation."""


@contextmanager
def finalize_hardhat_phase(
    request: HardhatPhaseRequest,
    layout: HardhatPhaseCommand,
    *,
    private_dir: Path,
    backend: SingleLoopbackHardhatBackend,
    bridge: ReadOnlyRpcBridge,
    binding: HardhatReadOnlyRpcBridgeBinding,
    absolute_deadline: float,
) -> Iterator[HardhatPhaseLaunch]:
    """Retain one phase's cleanup selection before yielding unverified explicit launch inputs.

    The trusted executor owns launch admission and independent parent capture. Yield arms a launch
    attempt: even a missing CID on a normal exit refuses finalization. Cleanup uses its own finite
    emergency allowance after audit expiry; original errors/interrupts/exits cannot be suppressed.
    No CID, daemon route, image, executable dependency or through-exec authenticity is inferred.
    """

    started = time.monotonic()
    if (
        type(layout) is not HardhatPhaseCommand
        or type(backend) is not SingleLoopbackHardhatBackend
        or type(binding) is not HardhatReadOnlyRpcBridgeBinding
        or type(bridge) is not ReadOnlyRpcBridge
        or type(absolute_deadline) not in {int, float}
        or not math.isfinite(absolute_deadline)
        or not math.isfinite(started)
        or started >= absolute_deadline
    ):
        raise HardhatFinalizationError("Hardhat finalizer inputs or deadline are invalid")
    selected, request_json = _detached_request(request)
    if absolute_deadline > started + selected.timeout_seconds:
        raise HardhatFinalizationError("Hardhat finalizer deadline cannot widen the phase request")
    binding.verify(backend, private_dir, bridge=bridge)
    bridge_observation = bridge.live_unix_listener_observation()
    common_identity = _root_identity(private_dir, private=True)
    phase_dir = private_dir / f"hardhat-{selected.phase}-{selected.request_sha256}"
    output_root = phase_dir / "container-output"
    runtime_dir = phase_dir / "container-runtime"
    cidfile = runtime_dir / "container.cid"
    if (
        layout.phase != selected.phase
        or layout.request_sha256 != selected.request_sha256
        or layout.private_dir != phase_dir
        or layout.output_root != output_root
        or selected.image != backend.image
        or selected.isolation_capability_sha256 != backend.hardhat_loopback_capability_sha256
        or selected.bridge_policy_sha256 != bridge_observation.policy_sha256
        or canonical_sha256(
            {
                "version": "MMAUDIT_READ_ONLY_RPC_LIVE_STATE_V1",
                "origin_endpoint": backend.approved_loopback_rpc_endpoint,
                "expected_chain_id": selected.chain_id,
                "pinned_block_number": selected.block_number,
                "pinned_block_hash": selected.block_hash,
                "preflight_origin_observation_sha256": bridge_observation.preflight_origin_observation_sha256,
            }
        )
        != bridge_observation.state_sha256
        or type(layout.command) is not tuple
        or not layout.command
        or layout.command[0] != backend.executable
        or layout.command.count("--cidfile") != 1
        or layout.command[layout.command.index("--cidfile") + 1 :] == ()
        or layout.command[layout.command.index("--cidfile") + 1] != str(cidfile)
    ):
        raise HardhatFinalizationError("Hardhat finalizer request and phase layout do not join")
    phase_identity = _root_identity(phase_dir, private=True)
    output_identity = _root_identity(output_root, private=True)
    runtime_identity = _root_identity(runtime_dir, private=True)
    try:
        cidfile.lstat()
    except FileNotFoundError:
        pass
    else:
        raise HardhatFinalizationError("Hardhat finalizer refuses a preexisting launch identifier")
    backend_snapshot = asdict(backend)
    cleanup_backend = replace(backend, limits=replace(backend.limits))
    layout_snapshot = replace(layout)
    executable = Path(backend.executable)
    executable_identity = _runtime_identity(executable, phase_dir)
    _command_and_environment(layout.command, {}, private_dir, phase_dir)
    claim = selected.request_sha256.encode("ascii") + b"\n"
    claim_path = phase_dir / _FINALIZER_CLAIM
    # The retained claim is outside the container-writable output and cannot be reused on retry.
    write_file_evidence(
        evidence_root=phase_dir, relative_path=_FINALIZER_CLAIM, content=claim, max_bytes=65
    )
    claim_identity = _claim_identity(claim_path.lstat())
    client_dir = phase_dir / "runtime-client"
    client_dir.mkdir(mode=0o700)
    client_identity = _root_identity(client_dir, private=True)
    environment = backend.host_environment(phase_dir)
    environment["PATH"] = str(executable.parent) + os.pathsep + "/usr/bin:/bin"
    environment = _control_environment(executable, phase_dir, environment)
    client_home = Path(environment["HOME"])
    home_identity = _root_identity(client_home, private=True)
    launch = HardhatPhaseLaunch(layout.command, environment.copy())

    def verify_cleanup_root() -> None:
        if (
            _root_identity(private_dir, private=True) != common_identity
            or _root_identity(phase_dir, private=True) != phase_identity
            or _root_identity(runtime_dir, private=True) != runtime_identity
            or _root_identity(client_dir, private=True) != client_identity
            or _root_identity(client_home, private=True) != home_identity
            or _runtime_identity(executable, phase_dir) != executable_identity
            or _claim_identity(claim_path.lstat()) != claim_identity
            or read_file_evidence(
                evidence_root=phase_dir, relative_path=_FINALIZER_CLAIM, max_bytes=65
            ).content
            != claim
        ):
            raise HardhatFinalizationError("Hardhat retained cleanup selection changed")

    def verify_phase() -> None:
        verify_cleanup_root()
        binding.verify(backend, private_dir, bridge=bridge)
        if (
            request.model_dump_json() != request_json
            or layout != layout_snapshot
            or launch.command != layout_snapshot.command
            or launch.environment != environment
            or asdict(backend) != backend_snapshot
            or _root_identity(output_root, private=True) != output_identity
            or bridge.live_unix_listener_observation() != bridge_observation
        ):
            raise HardhatFinalizationError("Hardhat phase selection changed before finalization")

    last_clock = started

    def require_time() -> None:
        nonlocal last_clock
        now = time.monotonic()
        if not math.isfinite(now) or now < last_clock or now >= absolute_deadline:
            raise HardhatFinalizationError("Hardhat shared deadline expired or clock changed")
        last_clock = now

    primary_error: BaseException | None = None
    # Before yield no caller-owned container/process is inferred; failed private state is retained.
    verify_phase()
    require_time()
    try:
        yield launch
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        failure: BaseException | None = None
        try:
            verify_phase()
        except BaseException as exc:
            failure = exc
        try:
            # Phase/request/bridge drift cannot skip safe cleanup of the original selected runtime.
            # Unsafe cleanup-root/executable drift, however, must not invoke a different runtime.
            verify_cleanup_root()
            cid = read_file_evidence(
                evidence_root=runtime_dir, relative_path="container.cid", max_bytes=65
            ).content
            if re.fullmatch(rb"[0-9a-f]{64}\n?", cid) is None:
                raise HardhatFinalizationError("Hardhat launched phase lacks an exact retained CID")
            container_id = cid[:64].decode("ascii")
            result = cleanup_rootless_container(
                cleanup_backend,
                phase_dir,
                environment=environment.copy(),
                expected_runtime_identity=executable_identity,
                expected_container_id=container_id,
            )
            if (
                type(result) is not ContainerCleanupObservation
                or type(result.status) is not ContainerCleanupStatus
                or not result.absence_verified
                or result.container_id != container_id
                or result.execution_credit is not False
                or result.runtime_authority is not False
            ):
                raise HardhatFinalizationError("Hardhat phase cleanup did not establish absence")
            verify_phase()
            require_time()
        except BaseException as exc:
            if failure is None:
                failure = exc
        if failure is not None and primary_error is None:
            raise failure
        if failure is not None and primary_error is not None:
            # Even a broken exception-notes field must not replace the primary failure.
            with suppress(BaseException):
                BaseException.add_note(
                    primary_error,
                    "Hardhat phase finalization was incomplete; no execution credit is available.",
                )
