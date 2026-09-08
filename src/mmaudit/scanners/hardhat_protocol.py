"""Exact observation-only request bindings for the two-phase Hardhat protocol."""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final, Literal

from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import (
    HardhatInventoryPhaseRequest,
    HardhatReporterExecution,
    HardhatReporterInventory,
    HardhatTestPhaseRequest,
    RepositorySuiteInventoryKind,
    RepositorySuiteSelection,
    RepositoryTestExecutionStatus,
)
from mmaudit.scanners.base import scanner_workspace_exclusion_path, scanner_workspace_sha256
from mmaudit.scanners.hardhat import (
    HARDHAT_REPORTER_SHA256,
    HARDHAT_REPORTER_VERSION,
    parse_hardhat_execution_report,
    parse_hardhat_inventory_report,
    select_hardhat_repository_suite,
)
from mmaudit.scanners.hardhat_source import (
    HardhatSourceInventoryAuthority,
    bind_hardhat_inventory_to_source,
    verify_hardhat_source_inventory_authority,
)
from mmaudit.scanners.hardhat_supervision import (
    HardhatCaptureOutcome,
    HardhatPhaseCapture,
    HardhatPhaseRequest,
    _root_identity,
)

HARDHAT_INVENTORY_SCHEMA_SHA256: Final = (
    "c5eb7d2e536b8a34d2b6bfdef31b83a67b28f411468056aa833b873a53423a27"
)
HARDHAT_TEST_SCHEMA_SHA256: Final = (
    "82938fe228ae9f4ba9bf64b284ec9cbbab6af0b0ce1a9e13f4cc8b7c63e77bc8"
)
_FAILED_RESULTS = frozenset(
    {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
)


class HardhatProtocolBindingError(ValueError):
    """The two Hardhat phases or their source authority do not join exactly."""


def seal_hardhat_inventory_phase_request(
    *,
    attempt_sha256: str,
    repository_sha256: str,
    repository_exclusion_path: str,
    configuration_sha256: str,
    image: str,
    container_executable_sha256: str,
    isolation_capability_sha256: str,
    bridge_policy_sha256: str,
    reporter_version: str,
    reporter_sha256: str,
    reporter_schema_sha256: str,
    chain_id: int,
    block_number: int,
    block_hash: str,
    fuzz_seed: str,
    timeout_seconds: float,
    maximum_output_bytes: int,
) -> HardhatInventoryPhaseRequest:
    """Seal one inventory request without implying that any process executed it."""

    return HardhatInventoryPhaseRequest.sealed(
        attempt_sha256=attempt_sha256,
        repository_sha256=repository_sha256,
        repository_exclusion_path=repository_exclusion_path,
        configuration_sha256=configuration_sha256,
        image=image,
        container_executable_sha256=container_executable_sha256,
        isolation_capability_sha256=isolation_capability_sha256,
        bridge_policy_sha256=bridge_policy_sha256,
        reporter_version=reporter_version,
        reporter_sha256=reporter_sha256,
        reporter_schema_sha256=reporter_schema_sha256,
        chain_id=chain_id,
        block_number=block_number,
        block_hash=block_hash,
        fuzz_seed=fuzz_seed,
        timeout_seconds=timeout_seconds,
        maximum_output_bytes=maximum_output_bytes,
        execution_credit=False,
    )


def seal_hardhat_test_phase_request(
    inventory_request: HardhatInventoryPhaseRequest,
    inventory: HardhatReporterInventory,
    source_authority: HardhatSourceInventoryAuthority,
    selection: RepositorySuiteSelection,
    *,
    reporter_schema_sha256: str,
    per_test_timeout_seconds: float,
    maximum_output_bytes_per_test: int,
) -> HardhatTestPhaseRequest:
    """Seal phase two only after exact inventory, source, and selection joins."""

    try:
        validated_inventory_request = HardhatInventoryPhaseRequest.model_validate(
            inventory_request.model_dump(mode="json")
        )
        validated_inventory = HardhatReporterInventory.model_validate(
            inventory.model_dump(mode="json")
        )
        validated_selection = RepositorySuiteSelection.model_validate(
            selection.model_dump(mode="json")
        )
    except (TypeError, ValueError) as exc:
        raise HardhatProtocolBindingError(
            "Hardhat test phase received a structurally invalid mutable binding"
        ) from exc
    if (
        type(inventory_request) is not HardhatInventoryPhaseRequest
        or type(inventory) is not HardhatReporterInventory
        or type(selection) is not RepositorySuiteSelection
        or validated_inventory_request != inventory_request
        or validated_inventory != inventory
        or validated_selection != selection
        or inventory_request.request_sha256 != inventory_request.expected_request_sha256()
        or selection.selection_sha256 != selection.expected_selection_sha256()
        or inventory.request_sha256 != inventory_request.request_sha256
        or inventory.repository_sha256 != inventory_request.repository_sha256
        or inventory.reporter_name != inventory_request.reporter_name
        or inventory.reporter_version != inventory_request.reporter_version
        or inventory.reporter_sha256 != inventory_request.reporter_sha256
        or selection.repository_sha256 != inventory_request.repository_sha256
        or selection.repository_exclusion_path != inventory_request.repository_exclusion_path
        or selection.configuration_sha256 != inventory_request.configuration_sha256
        or selection.profile != source_authority.profile
        or selection.candidate_file_count != source_authority.candidate_file_count
        or selection.candidate_test_count != source_authority.candidate_test_count
        or selection.selected_file_count != source_authority.selected_file_count
        or selection.selected_test_count != source_authority.selected_test_count
        or selection.omitted_file_count != source_authority.omitted_file_count
        or selection.omitted_test_count != source_authority.omitted_test_count
        or selection.limit_reached
        or selection.inventory_kind is not RepositorySuiteInventoryKind.STATIC_SOURCE
        or selection.inventory_sha256 is not None
        or selection.safety_claim
        or source_authority.repository_exclusion_path != inventory_request.repository_exclusion_path
        or source_authority.configuration_sha256 != inventory_request.configuration_sha256
        or source_authority.repository_sha256 != inventory_request.repository_sha256
        or source_authority.inventory_sha256 != inventory.inventory_sha256
        or selection.tests != source_authority.descriptors
        or selection.selected_test_count != source_authority.selected_test_count
        or not verify_hardhat_source_inventory_authority(
            source_authority,
            inventory=inventory,
        )
    ):
        raise HardhatProtocolBindingError(
            "Hardhat test phase does not exactly join inventory, source, and selection"
        )
    return HardhatTestPhaseRequest.sealed(
        attempt_sha256=inventory_request.attempt_sha256,
        repository_sha256=inventory_request.repository_sha256,
        repository_exclusion_path=inventory_request.repository_exclusion_path,
        configuration_sha256=inventory_request.configuration_sha256,
        image=inventory_request.image,
        container_executable_sha256=inventory_request.container_executable_sha256,
        isolation_capability_sha256=inventory_request.isolation_capability_sha256,
        bridge_policy_sha256=inventory_request.bridge_policy_sha256,
        reporter_version=inventory_request.reporter_version,
        reporter_sha256=inventory_request.reporter_sha256,
        reporter_schema_sha256=reporter_schema_sha256,
        chain_id=inventory_request.chain_id,
        block_number=inventory_request.block_number,
        block_hash=inventory_request.block_hash,
        fuzz_seed=inventory_request.fuzz_seed,
        timeout_seconds=inventory_request.timeout_seconds,
        maximum_output_bytes=inventory_request.maximum_output_bytes,
        inventory_request_sha256=inventory_request.request_sha256,
        inventory_sha256=inventory.inventory_sha256,
        source_authority_sha256=source_authority.authority_sha256,
        selection_sha256=selection.selection_sha256,
        selected_test_count=selection.selected_test_count,
        per_test_timeout_seconds=per_test_timeout_seconds,
        maximum_output_bytes_per_test=maximum_output_bytes_per_test,
        execution_credit=False,
    )


def validate_hardhat_two_phase_bindings(
    inventory_request: HardhatInventoryPhaseRequest,
    inventory: HardhatReporterInventory,
    source_authority: HardhatSourceInventoryAuthority,
    selection: RepositorySuiteSelection,
    test_request: HardhatTestPhaseRequest,
) -> None:
    """Revalidate a serialized request pair without granting execution credit."""

    expected = seal_hardhat_test_phase_request(
        inventory_request,
        inventory,
        source_authority,
        selection,
        reporter_schema_sha256=test_request.reporter_schema_sha256,
        per_test_timeout_seconds=test_request.per_test_timeout_seconds,
        maximum_output_bytes_per_test=test_request.maximum_output_bytes_per_test,
    )
    if expected != test_request:
        raise HardhatProtocolBindingError("Hardhat test phase differs from its exact bindings")


@dataclass(frozen=True, slots=True)
class HardhatPreparedTestPhase:
    """Retained protocol observations, not command admission or proof of execution."""

    inventory_request: HardhatInventoryPhaseRequest = field(repr=False)
    inventory_capture: HardhatPhaseCapture = field(repr=False)
    inventory: HardhatReporterInventory = field(repr=False)
    source_authority: HardhatSourceInventoryAuthority = field(repr=False)
    selection: RepositorySuiteSelection = field(repr=False)
    test_request: HardhatTestPhaseRequest = field(repr=False)

    @property
    def execution_credit(self) -> Literal[False]:
        return False

    @property
    def runtime_authority(self) -> Literal[False]:
        return False


def _captured_bytes(capture: HardhatPhaseCapture) -> int:
    return len(capture.stdout) + len(capture.stderr) + len(capture.report or b"")


def _checked_capture(
    request: HardhatPhaseRequest, capture: HardhatPhaseCapture
) -> HardhatPhaseCapture:
    """Check detached bounded observations without treating constructible data as authority."""

    if type(capture) is not HardhatPhaseCapture:
        raise HardhatProtocolBindingError("Hardhat capture requires exact parent observations")
    detached = replace(capture)
    schema_sha256 = (
        HARDHAT_INVENTORY_SCHEMA_SHA256
        if request.phase == "inventory"
        else HARDHAT_TEST_SCHEMA_SHA256
    )
    if (
        request.reporter_version != HARDHAT_REPORTER_VERSION
        or request.reporter_sha256 != HARDHAT_REPORTER_SHA256
        or request.reporter_schema_sha256 != schema_sha256
        or detached.request_sha256 != request.request_sha256
        or detached.phase != request.phase
        or detached.outcome is not HardhatCaptureOutcome.EXITED
        or type(detached.process_exit_code) is not int
        or not 0 <= detached.process_exit_code <= 255
        or (request.phase == "inventory" and detached.process_exit_code != 0)
        or type(detached.duration_seconds) not in {int, float}
        or not math.isfinite(detached.duration_seconds)
        or not 0 <= detached.duration_seconds < request.timeout_seconds
        or type(detached.stdout) is not bytes
        or type(detached.stderr) is not bytes
        or type(detached.report) is not bytes
        or not detached.report
        or _captured_bytes(detached) > request.maximum_output_bytes
    ):
        raise HardhatProtocolBindingError(
            "Hardhat capture is incomplete or differs from its request"
        )
    return detached


def _verify_inventory_context(
    request: HardhatInventoryPhaseRequest,
    config: SmartContractsConfig,
    root: Path,
    repository_exclusion_root: Path | None,
    root_identity: tuple[int, int, int, int, int],
) -> None:
    policy = config.repository_suite
    if (
        _root_identity(root, private=False) != root_identity
        or scanner_workspace_exclusion_path(root, repository_exclusion_root)
        != request.repository_exclusion_path
        or scanner_workspace_sha256(root, repository_exclusion_root) != request.repository_sha256
        or policy.stable_hash() != request.configuration_sha256
        or policy.total_timeout_seconds != request.timeout_seconds
        or policy.max_total_output_bytes != request.maximum_output_bytes
        or policy.fuzz_seed != request.fuzz_seed
    ):
        raise HardhatProtocolBindingError("Hardhat capture source or selection policy changed")


def prepare_hardhat_test_phase_from_capture(
    request: HardhatInventoryPhaseRequest,
    capture: HardhatPhaseCapture,
    *,
    root: Path,
    smart_contracts: SmartContractsConfig,
    repository_exclusion_root: Path | None = None,
) -> HardhatPreparedTestPhase:
    """Join captured inventory to literal source and prepare the exact observation-only phase two.

    This starts no process. The eventual executor still owns launch admission, live backend
    revalidation, aggregate wall-clock supervision, image identity and container teardown.
    """

    try:
        if (
            type(request) is not HardhatInventoryPhaseRequest
            or type(smart_contracts) is not SmartContractsConfig
        ):
            raise HardhatProtocolBindingError("Hardhat preparation requires exact typed inputs")
        request_json = request.model_dump_json()
        config_json = smart_contracts.model_dump_json()
        validated = HardhatInventoryPhaseRequest.model_validate_json(request_json, strict=True)
        config = SmartContractsConfig.model_validate_json(config_json, strict=True)
        observed = _checked_capture(validated, capture)
        root_identity = _root_identity(root, private=False)
        _verify_inventory_context(validated, config, root, repository_exclusion_root, root_identity)
        assert observed.report is not None
        inventory = parse_hardhat_inventory_report(
            observed.report,
            expected_request_sha256=validated.request_sha256,
            expected_repository_sha256=validated.repository_sha256,
            maximum_bytes=validated.maximum_output_bytes,
        )
        authority = bind_hardhat_inventory_to_source(
            root,
            inventory,
            config,
            expected_repository_sha256=validated.repository_sha256,
            repository_exclusion_root=repository_exclusion_root,
        )
        selection = select_hardhat_repository_suite(
            inventory,
            config,
            repository_exclusion_path=validated.repository_exclusion_path,
            authority=authority,
        )
        test_request = seal_hardhat_test_phase_request(
            validated,
            inventory,
            authority,
            selection,
            reporter_schema_sha256=HARDHAT_TEST_SCHEMA_SHA256,
            per_test_timeout_seconds=config.repository_suite.per_test_timeout_seconds,
            maximum_output_bytes_per_test=config.repository_suite.max_output_bytes_per_test,
        )
        _verify_inventory_context(validated, config, root, repository_exclusion_root, root_identity)
        if (
            request.model_dump_json() != request_json
            or smart_contracts.model_dump_json() != config_json
            or capture != observed
        ):
            raise HardhatProtocolBindingError(
                "Hardhat preparation inputs changed during consumption"
            )
        return HardhatPreparedTestPhase(
            validated, observed, inventory, authority, selection, test_request
        )
    except (AttributeError, OSError, TypeError, ValueError):
        raise HardhatProtocolBindingError(
            "Hardhat captured inventory could not be joined safely"
        ) from None


def _verify_prepared_phase(
    prepared: HardhatPreparedTestPhase, fresh: HardhatPreparedTestPhase
) -> None:
    if (
        not verify_hardhat_source_inventory_authority(
            prepared.source_authority, inventory=prepared.inventory
        )
        or prepared.inventory_request != fresh.inventory_request
        or prepared.inventory_capture != fresh.inventory_capture
        or prepared.inventory != fresh.inventory
        or prepared.selection != fresh.selection
        or prepared.test_request != fresh.test_request
        or prepared.source_authority.authority_sha256 != fresh.source_authority.authority_sha256
    ):
        raise HardhatProtocolBindingError(
            "Hardhat prepared phase differs from captured source bindings"
        )
    validate_hardhat_two_phase_bindings(
        prepared.inventory_request,
        prepared.inventory,
        prepared.source_authority,
        prepared.selection,
        prepared.test_request,
    )


def consume_hardhat_test_phase_capture(
    prepared: HardhatPreparedTestPhase,
    capture: HardhatPhaseCapture,
    *,
    root: Path,
    smart_contracts: SmartContractsConfig,
    repository_exclusion_root: Path | None = None,
) -> HardhatReporterExecution:
    """Rebind both captured phases and current source; return only untrusted test observations.

    A nonzero normal exit requires a reported failure; signals and incomplete captures refuse.
    Captured durations/bytes share the configured total ceiling. This does not authenticate
    per-test resource attribution, Mocha behavior, the elapsed inter-phase gap or real execution.
    """

    try:
        if (
            type(prepared) is not HardhatPreparedTestPhase
            or type(smart_contracts) is not SmartContractsConfig
        ):
            raise HardhatProtocolBindingError(
                "Hardhat test consumption requires an exact prepared phase"
            )
        root_identity = _root_identity(root, private=False)
        config_json = smart_contracts.model_dump_json()
        fresh = prepare_hardhat_test_phase_from_capture(
            prepared.inventory_request,
            prepared.inventory_capture,
            root=root,
            smart_contracts=smart_contracts,
            repository_exclusion_root=repository_exclusion_root,
        )
        _verify_prepared_phase(prepared, fresh)
        request = fresh.test_request
        observed = _checked_capture(request, capture)
        if (
            fresh.inventory_capture.duration_seconds + observed.duration_seconds
            >= request.timeout_seconds
            or _captured_bytes(fresh.inventory_capture) + _captured_bytes(observed)
            > request.maximum_output_bytes
        ):
            raise HardhatProtocolBindingError("Hardhat combined capture ceiling was exceeded")
        assert observed.report is not None
        report = parse_hardhat_execution_report(
            observed.report,
            selection=fresh.selection,
            expected_request_sha256=request.request_sha256,
            expected_chain_id=request.chain_id,
            expected_block_number=request.block_number,
            expected_block_hash=request.block_hash,
            expected_fuzz_seed=request.fuzz_seed,
            per_test_timeout_seconds=request.per_test_timeout_seconds,
            maximum_bytes=request.maximum_output_bytes,
        )
        has_failure = any(result.status in _FAILED_RESULTS for result in report.results)
        if (observed.process_exit_code == 0) == has_failure:
            raise HardhatProtocolBindingError(
                "Hardhat process exit contradicts reported test outcomes"
            )
        postflight = prepare_hardhat_test_phase_from_capture(
            fresh.inventory_request,
            fresh.inventory_capture,
            root=root,
            smart_contracts=smart_contracts,
            repository_exclusion_root=repository_exclusion_root,
        )
        _verify_prepared_phase(prepared, postflight)
        if (
            capture != observed
            or _root_identity(root, private=False) != root_identity
            or smart_contracts.model_dump_json() != config_json
        ):
            raise HardhatProtocolBindingError("Hardhat test capture changed during consumption")
        return report
    except (AttributeError, OSError, TypeError, ValueError):
        raise HardhatProtocolBindingError(
            "Hardhat captured test report could not be joined safely"
        ) from None
