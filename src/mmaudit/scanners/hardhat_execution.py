"""Owned two-phase observation lifecycle, not image admission or execution authority.

A trusted programmatic boundary must admit each launch and finalize its container/resources.
Neither serialized input nor an unverified wrapped command can supply that boundary. Production
Hardhat remains unavailable until image identity, real containment and finalization are proved.
"""

from __future__ import annotations

import math
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from mmaudit.config import SmartContractsConfig
from mmaudit.isolation.container import (
    HardhatPhaseCommand,
    HardhatReadOnlyRpcBridgeBinding,
    SingleLoopbackHardhatBackend,
)
from mmaudit.models.schemas import HardhatInventoryPhaseRequest, HardhatReporterExecution
from mmaudit.scanners.hardhat_protocol import (
    HardhatPreparedTestPhase,
    _captured_bytes,
    _verify_inventory_context,
    consume_hardhat_test_phase_capture,
    prepare_hardhat_test_phase_from_capture,
)
from mmaudit.scanners.hardhat_supervision import (
    HardhatPhaseCapture,
    HardhatPhaseRequest,
    _root_identity,
    supervise_hardhat_phase_process,
)
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge, ReadOnlyRpcBridgeSnapshot


class HardhatExecutionError(ValueError):
    """Owned lifecycle custody, shared bounds or finalization could not be verified."""


@dataclass(frozen=True, slots=True)
class HardhatPhaseLaunch:
    """Explicit trusted launch inputs; constructing this value never grants admission."""

    command: tuple[str, ...] = field(repr=False)
    environment: dict[str, str] = field(repr=False)


class HardhatPhaseBoundary(Protocol):
    """Trusted code, never target/model/config input or a serialized readiness flag.

    Admission may refuse an unverified layout. Entry failures must finalize their own resources;
    successful entry transfers process capture to this driver and must finalize on exit. Cleanup
    must be independently bounded even after the shared deadline. No production implementation is
    supplied here: a custom callback is not a way to qualify Hardhat or attest an image.
    """

    def image_command(
        self, request: HardhatPhaseRequest, *, prepared: HardhatPreparedTestPhase | None
    ) -> tuple[str, ...]: ...

    def admitted_launch(
        self,
        request: HardhatPhaseRequest,
        layout: HardhatPhaseCommand,
        *,
        prepared: HardhatPreparedTestPhase | None,
        absolute_deadline: float,
    ) -> AbstractContextManager[HardhatPhaseLaunch]: ...


@dataclass(frozen=True, slots=True)
class HardhatTwoPhaseObservation:
    """Both captured protocol joins and stopped bridge, still wholly noncrediting."""

    prepared: HardhatPreparedTestPhase = field(repr=False)
    test_capture: HardhatPhaseCapture = field(repr=False)
    report: HardhatReporterExecution = field(repr=False)
    bridge_snapshot: ReadOnlyRpcBridgeSnapshot = field(repr=False)
    duration_seconds: float

    @property
    def execution_credit(self) -> Literal[False]:
        return False

    @property
    def runtime_authority(self) -> Literal[False]:
        return False


def capture_hardhat_two_phase_execution(
    request: HardhatInventoryPhaseRequest,
    *,
    root: Path,
    private_dir: Path,
    smart_contracts: SmartContractsConfig,
    backend: SingleLoopbackHardhatBackend,
    bridge: ReadOnlyRpcBridge,
    binding: HardhatReadOnlyRpcBridgeBinding,
    boundary: HardhatPhaseBoundary,
    repository_exclusion_root: Path | None = None,
) -> HardhatTwoPhaseObservation:
    """Consume an exact live bridge/binding and capture both phases before owned shutdown.

    Ownership transfers only after the exact live bridge join is verified; thereafter every exit
    closes both binding and bridge. Their earlier startup belongs to the caller's preparation.
    The shared deadline covers this call's preparation, captures, protocol joins and finalizers.
    Expiry refuses a result but cannot skip emergency cleanup or preempt trusted Python callbacks.
    No launch admission, image authenticity, real-container lifetime or per-test credit is implied.
    """

    started = time.monotonic()
    if (
        type(request) is not HardhatInventoryPhaseRequest
        or type(smart_contracts) is not SmartContractsConfig
        or type(backend) is not SingleLoopbackHardhatBackend
        or type(bridge) is not ReadOnlyRpcBridge
        or type(binding) is not HardhatReadOnlyRpcBridgeBinding
        or not callable(getattr(boundary, "image_command", None))
        or not callable(getattr(boundary, "admitted_launch", None))
    ):
        raise HardhatExecutionError(
            "Hardhat lifecycle requires exact inputs and a trusted boundary"
        )
    # Do not close unrelated resources when the caller supplies a mismatched ownership handle.
    binding.verify(backend, private_dir, bridge=bridge)
    primary_error: BaseException | None = None
    snapshot: ReadOnlyRpcBridgeSnapshot | None = None
    try:
        if not math.isfinite(started):
            raise HardhatExecutionError("Hardhat lifecycle clock is invalid")
        request_json = request.model_dump_json()
        config_json = smart_contracts.model_dump_json()
        selected = HardhatInventoryPhaseRequest.model_validate_json(request_json, strict=True)
        config = SmartContractsConfig.model_validate_json(config_json, strict=True)
        private_identity = _root_identity(private_dir, private=True)
        root_identity = _root_identity(root, private=False)
        deadline = started + selected.timeout_seconds
        last_clock = started

        def remaining_time() -> float:
            nonlocal last_clock
            now = time.monotonic()
            if not math.isfinite(now) or now < last_clock or now >= deadline:
                raise HardhatExecutionError("Hardhat shared elapsed-time deadline is exhausted")
            last_clock = now
            return deadline - now

        def verify_context(*, live: bool = True) -> None:
            remaining_time()
            if live:
                binding.verify(backend, private_dir, bridge=bridge)
            if (
                _root_identity(private_dir, private=True) != private_identity
                or request.model_dump_json() != request_json
                or smart_contracts.model_dump_json() != config_json
            ):
                raise HardhatExecutionError("Hardhat lifecycle selection changed")
            _verify_inventory_context(
                selected, config, root, repository_exclusion_root, root_identity
            )
            remaining_time()

        def capture_phase(
            phase_request: HardhatPhaseRequest,
            prepared: HardhatPreparedTestPhase | None,
            output_allowance: int,
        ) -> HardhatPhaseCapture:
            verify_context()
            if output_allowance <= 0:
                raise HardhatExecutionError("Hardhat shared output allowance is exhausted")
            phase_json = phase_request.model_dump_json()
            command = boundary.image_command(phase_request, prepared=prepared)
            verify_context()
            if phase_request.model_dump_json() != phase_json:
                raise HardhatExecutionError("Hardhat phase request changed during preparation")
            layout = backend.wrap_hardhat_phase(
                command, phase_request, workspace=root, private_dir=private_dir, binding=binding
            )
            layout_identity = _root_identity(layout.private_dir, private=True)
            output_identity = _root_identity(layout.output_root, private=True)
            manager = boundary.admitted_launch(
                phase_request, layout, prepared=prepared, absolute_deadline=deadline
            )
            entered = False
            failure: BaseException | None = None
            try:
                # Manual exit preserves primary failures even if a finalizer suppresses/errors.
                launch = manager.__enter__()
                entered = True
                if type(launch) is not HardhatPhaseLaunch:
                    raise HardhatExecutionError("Hardhat launch boundary returned an invalid input")
                verify_context()
                if (
                    phase_request.model_dump_json() != phase_json
                    or _root_identity(layout.private_dir, private=True) != layout_identity
                    or _root_identity(layout.output_root, private=True) != output_identity
                ):
                    raise HardhatExecutionError("Hardhat phase custody changed before capture")
                capture = supervise_hardhat_phase_process(
                    phase_request,
                    command=launch.command,
                    workspace=root,
                    output_root=layout.output_root,
                    environment=launch.environment,
                    absolute_deadline=deadline,
                    maximum_output_bytes=output_allowance,
                )
            except BaseException as exc:
                failure = exc
                raise
            finally:
                if entered:
                    try:
                        manager.__exit__(
                            type(failure) if failure is not None else None,
                            failure,
                            failure.__traceback__ if failure is not None else None,
                        )
                    except BaseException:
                        if failure is None:
                            raise
            verify_context()
            if (
                phase_request.model_dump_json() != phase_json
                or _root_identity(layout.private_dir, private=True) != layout_identity
                or _root_identity(layout.output_root, private=True) != output_identity
            ):
                raise HardhatExecutionError("Hardhat phase custody changed during finalization")
            return capture

        verify_context()
        inventory_capture = capture_phase(selected, None, selected.maximum_output_bytes)
        prepared = prepare_hardhat_test_phase_from_capture(
            selected,
            inventory_capture,
            root=root,
            smart_contracts=config,
            repository_exclusion_root=repository_exclusion_root,
        )
        verify_context()
        test_capture = capture_phase(
            prepared.test_request,
            prepared,
            selected.maximum_output_bytes - _captured_bytes(inventory_capture),
        )
        report = consume_hardhat_test_phase_capture(
            prepared,
            test_capture,
            root=root,
            smart_contracts=config,
            repository_exclusion_root=repository_exclusion_root,
        )
        verify_context()
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_error: BaseException | None = None
        try:
            binding.close()
        except BaseException as exc:
            cleanup_error = exc
        try:
            bridge.stop()
            snapshot = bridge.snapshot()
        except BaseException as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None and primary_error is None:
            raise cleanup_error
    verify_context(live=False)
    final_report = consume_hardhat_test_phase_capture(
        prepared,
        test_capture,
        root=root,
        smart_contracts=config,
        repository_exclusion_root=repository_exclusion_root,
    )
    if final_report != report:
        raise HardhatExecutionError("Hardhat protocol observations changed during shutdown")
    verify_context(live=False)
    if (
        snapshot is None
        or snapshot.status != "enforced"
        or snapshot.policy_sha256 != selected.bridge_policy_sha256
        or snapshot.expected_chain_id != selected.chain_id
        or snapshot.pinned_block_number != selected.block_number
        or snapshot.pinned_block_hash != selected.block_hash
    ):
        raise HardhatExecutionError("Hardhat final bridge observations differ from the request")
    return HardhatTwoPhaseObservation(
        prepared, test_capture, report, snapshot, last_clock - started
    )
