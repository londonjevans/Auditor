"""Exact observation-only request bindings for the two-phase Hardhat protocol."""

from __future__ import annotations

from mmaudit.models.schemas import (
    HardhatInventoryPhaseRequest,
    HardhatReporterInventory,
    HardhatTestPhaseRequest,
    RepositorySuiteInventoryKind,
    RepositorySuiteSelection,
)
from mmaudit.scanners.hardhat_source import (
    HardhatSourceInventoryAuthority,
    verify_hardhat_source_inventory_authority,
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
