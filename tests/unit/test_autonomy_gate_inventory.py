from __future__ import annotations

import ast
import inspect
import os
import subprocess
import sys
import textwrap
from collections import Counter
from pathlib import Path
from typing import Literal

import pytest
from pydantic import Field, ValidationError, create_model

import mmaudit.orchestration.autonomy_gate_inventory as inventory_module
from mmaudit.config import AuditConfig, AuditRunOptions
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.autonomy_gate_inventory import (
    AUTONOMY_INVENTORY_PATH,
    AutonomousGateDisposition,
    AutonomyGateInventory,
    AutonomyInventoryError,
    CompletionInputSourceKind,
    GateImplementationState,
    SourceCoverageClassification,
    _audit_gate_for_path,
    _discover_audited_module_sources,
    _discover_completion_entrypoint_sources,
    _discover_direct_environment_sources,
    _discover_external_input_sources,
    build_autonomy_gate_inventory,
    load_autonomy_gate_inventory,
    render_autonomy_gate_inventory,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def inventory() -> AutonomyGateInventory:
    return build_autonomy_gate_inventory(repository_root=ROOT)


def test_inventory_freezes_the_exact_recursive_source_universe(
    inventory: AutonomyGateInventory,
) -> None:
    assert inventory.source_count == 4217
    assert inventory.source_occurrence_count == 4220
    assert inventory.audit_config_leaf_locator_count == 513
    assert inventory.audit_config_leaf_occurrence_count == 516
    assert inventory.audit_config_shared_locator_count == 3
    assert inventory.audit_run_option_leaf_count == 16
    assert inventory.audit_override_path_count == 51
    assert inventory.environment_override_count == 28
    assert inventory.cli_run_parameter_count == 53
    assert inventory.pipeline_init_parameter_count == 29
    assert inventory.pipeline_run_parameter_count == 16
    assert inventory.completion_entrypoint_parameter_count == 355
    assert {kind.value: count for kind, count in inventory.source_kind_counts.items()} == {
        "AUDIT_CONFIG_LEAF": 513,
        "AUDIT_RUN_OPTION_LEAF": 16,
        "AUDIT_OVERRIDE_PATH": 51,
        "ENVIRONMENT_OVERRIDE": 28,
        "CLI_RUN_PARAMETER": 53,
        "PIPELINE_INIT_PARAMETER": 29,
        "PIPELINE_RUN_PARAMETER": 16,
        "COMPLETION_ENTRYPOINT_PARAMETER": 355,
        "DIRECT_ENVIRONMENT_INPUT": 549,
        "ENTROPY_INPUT": 19,
        "AUDITED_MODULE_UNIVERSE": 299,
        "EXPLICIT_NON_FIELD_GATE": 2275,
        "REQUIRED_MISSING_GATE": 14,
    }
    assert Counter(source.classification for source in inventory.source_coverage) == {
        SourceCoverageClassification.GATE: 4165,
        SourceCoverageClassification.NON_GATING_CONTROL: 52,
    }
    assert {item.value for item in SourceCoverageClassification} == {
        "GATE",
        "NON_GATING_CONTROL",
    }
    assert sum(":wall-clock:" in source.source_path for source in inventory.source_coverage) == 106
    assert (
        sum(":working-directory:" in source.source_path for source in inventory.source_coverage)
        == 115
    )
    assert (
        sum(":process-identity" in source.source_path for source in inventory.source_coverage)
        == 108
    )
    assert (
        sum(
            source.source_kind is CompletionInputSourceKind.ENTROPY_INPUT
            for source in inventory.source_coverage
        )
        == 19
    )
    assert (
        sum(":content-read:" in source.source_path for source in inventory.source_coverage) == 312
    )
    assert (
        sum(":directory-enumeration:" in source.source_path for source in inventory.source_coverage)
        == 84
    )
    assert (
        sum(":metadata-observation:" in source.source_path for source in inventory.source_coverage)
        == 1813
    )
    assert all(
        source.classification is SourceCoverageClassification.GATE
        for source in inventory.source_coverage
        if source.source_kind
        in {
            CompletionInputSourceKind.AUDIT_CONFIG_LEAF,
            CompletionInputSourceKind.AUDIT_RUN_OPTION_LEAF,
            CompletionInputSourceKind.AUDIT_OVERRIDE_PATH,
            CompletionInputSourceKind.ENVIRONMENT_OVERRIDE,
            CompletionInputSourceKind.PIPELINE_INIT_PARAMETER,
            CompletionInputSourceKind.PIPELINE_RUN_PARAMETER,
            CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT,
            CompletionInputSourceKind.AUDITED_MODULE_UNIVERSE,
            CompletionInputSourceKind.EXPLICIT_NON_FIELD_GATE,
            CompletionInputSourceKind.REQUIRED_MISSING_GATE,
        }
    )


def test_development_routing_observation_confers_no_transport_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id, gate_id in {
        "explicit:development-routing-observation": "gate-provider-secret-transport",
        "audited-module:models.development_routing": "gate-runtime-package-integrity",
    }.items():
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_measurement_preserves_unverified_benchmark_and_scope_gates(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id, gate_id in {
        "audited-module:benchmark.development": "gate-runtime-package-integrity",
        "explicit:development-benchmark-truth": "gate-benchmark-evidence-authority",
        "explicit:development-benchmark-plan-binding": "gate-client-audit-scope",
        "explicit:development-benchmark-score": "gate-benchmark-evidence-authority",
    }.items():
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_shard_boundaries_are_gated_not_a_qualified_audit(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    expected = {
        "explicit:development-audit-frozen-plan": "gate-client-audit-scope",
        "explicit:development-audit-shard-transport": "gate-provider-secret-transport",
        "explicit:development-audit-sequential-run": "gate-full-quality-analysis",
        "audited-module:models.development_audit": "gate-runtime-package-integrity",
        "audited-module:orchestration.development_audit": "gate-runtime-package-integrity",
    }
    for source_id, gate_id in expected.items():
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29 and inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_executable_observation_inputs_join_the_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:scanners.base:_observe_scanner_executable:"
        )
    ]
    assert len(sources) == 7
    assert sum(":content-read:" in source.source_path for source in sources) == 1
    assert sum(":metadata-observation:" in source.source_path for source in sources) == 6
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_offline_image_metadata_chain_does_not_promote_layer_or_execution_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    anchor = by_id["explicit:managed-image-metadata-chain"]
    module = by_id["audited-module:orchestration.managed_image_metadata"]
    assert anchor.logical_gate_id == "gate-managed-toolchain-bundle"
    assert module.logical_gate_id == "gate-runtime-package-integrity"
    assert anchor.classification is module.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_local_layer_identity_and_stream_custody_do_not_promote_image_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["explicit:managed-image-layer-bytes"].logical_gate_id
        == "gate-managed-toolchain-bundle"
    )
    assert (
        by_id["explicit:bound-read-only-evidence-stream"].logical_gate_id
        == "gate-release-evidence-pipeline"
    )
    assert (
        by_id["audited-module:orchestration.managed_image_layers"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    stream_inputs = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            (
                "filesystem-input:release_io:stream_file_evidence:",
                "filesystem-input:release_io:_require_stream_custody:",
            )
        )
    ]
    assert len(stream_inputs) == 8
    assert sum(":metadata-observation:" in item.source_path for item in stream_inputs) == 7
    assert sum(":content-read:" in item.source_path for item in stream_inputs) == 1
    assert all(item.logical_gate_id == "gate-release-evidence-pipeline" for item in stream_inputs)
    assert all(item.classification is SourceCoverageClassification.GATE for item in stream_inputs)
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_static_image_membership_keeps_lookup_and_parser_gated_without_runtime_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert by_id["explicit:managed-image-file-membership"].logical_gate_id == (
        "gate-managed-toolchain-bundle"
    )
    for module in ("isolation.oci_layer", "orchestration.managed_image_files"):
        assert by_id["audited-module:" + module].logical_gate_id == "gate-runtime-package-integrity"
    # The conservative AST visitor records resolve() even for this in-memory view.
    lookup = by_id[
        "filesystem-input:orchestration.managed_image_files:verify_managed_image_files:1"
    ]
    assert lookup.logical_gate_id == "gate-managed-toolchain-bundle"
    assert lookup.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_pipeline_inputs_are_classified_without_promoting_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert by_id["pipeline-init:host_tools"].logical_gate_id == "gate-managed-toolchain-bundle"
    assert (
        by_id["pipeline-init:managed_backend"].logical_gate_id
        == "gate-reproduction-capability-policy"
    )
    roots = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:orchestration.managed_pipeline:")
    ]
    assert len(roots) == 4
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in roots)
    assert all(":metadata-observation:" in source.source_path for source in roots)
    assert "audited-module:orchestration.managed_pipeline" in by_id
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_matrix_roots_and_module_are_classified_without_promoting_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["audited-module:orchestration.managed_fork_matrix"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    roots = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:orchestration.managed_fork_matrix:")
    ]
    assert len(roots) == 1
    assert roots[0].logical_gate_id == "gate-managed-toolchain-bundle"
    assert ":metadata-observation:" in roots[0].source_path
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_matrix_uses_existing_observations_without_ambient_tool_selection() -> None:
    from mmaudit.orchestration import managed_fork_matrix

    tree = ast.parse(inspect.getsource(managed_fork_matrix))
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_observe_scanner_executable"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"open", "read_bytes", "which", "getenv"}
        for node in ast.walk(tree)
    )


def test_offline_fork_archive_input_is_classified_without_promoting_a_running_fork(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    source = by_id["explicit:offline-fork-read-archive"]
    assert source.logical_gate_id == "gate-fork-environment"
    assert source.classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:scanners.offline_fork_rpc"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_offline_read_lease_remains_a_fork_prerequisite_not_runtime_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    source = by_id["explicit:offline-fork-read-lease"]
    assert source.logical_gate_id == "gate-fork-environment"
    assert source.classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:scanners.offline_fork_service"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_archive_handoff_inputs_are_explicit_without_promoting_fork_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "pipeline-init:offline_forks",
        "explicit:managed-offline-fork-archive-preparation",
        "explicit:managed-offline-fork-archive-consumption",
        "filesystem-input:orchestration.managed_fork_archives:_verify_archive_roots:1",
        "filesystem-input:orchestration.managed_fork_archives:_verify_archive_roots:2",
    ):
        assert by_id[source_id].logical_gate_id == "gate-fork-environment"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:orchestration.managed_fork_archives"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_primary_archive_selection_and_foundry_consumer_are_explicit_nonauthorizing_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:managed-offline-primary-archive-selection",
        "explicit:managed-primary-foundry-consumption",
    ):
        assert by_id[source_id].logical_gate_id == "gate-fork-environment"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_reproduction_archive_selection_and_existing_consumer_remain_nonauthorizing_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:managed-reproduction-archive-selection",
        "explicit:fork-reproduction-runner",
    ):
        assert by_id[source_id].logical_gate_id == "gate-fork-environment"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_invariant_archive_selection_and_existing_consumer_remain_nonauthorizing_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id, gate_id in (
        ("explicit:managed-invariant-archive-selection", "gate-fork-environment"),
        ("explicit:typed-invariant-runner", "gate-invariant-template-library"),
    ):
        assert by_id[source_id].logical_gate_id == gate_id
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_hardhat_parent_capture_inputs_do_not_promote_execution_or_runtime_authority(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["audited-module:scanners.hardhat_supervision"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert (
        by_id["explicit:hardhat-phase-output-supervision"].logical_gate_id
        == "gate-full-quality-analysis"
    )
    filesystem = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:scanners.hardhat_supervision:")
    ]
    assert len(filesystem) == 10
    assert all(":metadata-observation:" in source.source_path for source in filesystem)
    assert all(source.logical_gate_id == "gate-full-quality-analysis" for source in filesystem)
    environment = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("direct-env-ast:scanners.hardhat_supervision:")
    ]
    assert {source.source_id for source in environment} == {
        "direct-env-ast:scanners.hardhat_supervision:_root_identity:host-identity:1",
        "direct-env-ast:scanners.hardhat_supervision:"
        "supervise_hardhat_phase_process:host-platform:1",
    }
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in environment)
    assert all(
        source.classification is SourceCoverageClassification.GATE
        for source in filesystem + environment
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_hardhat_capture_protocol_join_inputs_preserve_unverified_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    for source_id in (
        "explicit:hardhat-captured-inventory-preparation",
        "explicit:hardhat-captured-test-consumption",
    ):
        assert by_id[source_id].logical_gate_id == "gate-full-quality-analysis"
        assert by_id[source_id].classification is SourceCoverageClassification.GATE
    assert (
        by_id["audited-module:scanners.hardhat_protocol"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_hardhat_phase_layout_inputs_preserve_unverified_fork_boundary(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    roots = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:isolation.container:_hardhat_phase_workspace_identity:"
        )
    ]
    assert len(roots) == 2
    for source in [*roots, by_id["explicit:hardhat-phase-container-layout"]]:
        assert source.logical_gate_id == "gate-fork-environment"
        assert source.classification is SourceCoverageClassification.GATE
    relocated = "filesystem-input:isolation.container:singleloopbackhardhatbackend."
    assert relocated + "wrap_hardhat_fork_suite:1" not in by_id
    assert (
        by_id[relocated + "_wrap_hardhat_with_layout:1"].logical_gate_id == "gate-fork-environment"
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_exact_rootless_cleanup_inputs_never_promote_runtime_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["explicit:rootless-exact-container-cleanup"].logical_gate_id
        == "gate-managed-output-provisioning"
    )
    assert (
        by_id["audited-module:isolation.container_cleanup"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    filesystem = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:isolation.container_cleanup:")
    ]
    environment = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("direct-env-ast:isolation.container_cleanup:")
    ]
    assert len(filesystem) == 7 and len(environment) == 6
    for source in filesystem + environment:
        expected = (
            "gate-managed-toolchain-bundle"
            if any(
                token in source.source_id
                for token in (
                    ":_runtime_identity:",
                    ":_control_environment:",
                    ":_run_control_command:",
                    ":host-platform:",
                )
            )
            else "gate-managed-output-provisioning"
        )
        assert source.logical_gate_id == expected
        assert source.classification is SourceCoverageClassification.GATE
    assert not any(
        ":RootlessContainerBackend.cleanup:" in s.source_path for s in inventory.source_coverage
    )
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_owned_hardhat_lifecycle_is_classified_without_promoting_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    anchor = by_id["explicit:hardhat-owned-two-phase-execution"]
    module = by_id["audited-module:scanners.hardhat_execution"]
    assert anchor.logical_gate_id == "gate-full-quality-analysis"
    assert module.logical_gate_id == "gate-runtime-package-integrity"
    assert anchor.classification is module.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_phase_finalizer_and_retained_cleanup_handoff_do_not_supply_admission(
    inventory: AutonomyGateInventory,
) -> None:
    by_id = {source.source_id: source for source in inventory.source_coverage}
    assert (
        by_id["explicit:hardhat-phase-finalization"].logical_gate_id == "gate-full-quality-analysis"
    )
    assert (
        by_id["audited-module:scanners.hardhat_finalization"].logical_gate_id
        == "gate-runtime-package-integrity"
    )
    filesystem = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:scanners.hardhat_finalization:")
    ]
    assert len(filesystem) == 3
    assert all(source.logical_gate_id == "gate-full-quality-analysis" for source in filesystem)
    assert all(source.classification is SourceCoverageClassification.GATE for source in filesystem)
    assert (
        by_id["explicit:rootless-exact-container-cleanup"].logical_gate_id
        == "gate-managed-output-provisioning"
    )
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize("field", ["source_count", "source_occurrence_count", "gate_source_count"])
def test_expanded_inventory_ceiling_remains_bounded(inventory: AutonomyGateInventory, field: str):
    schema = AutonomyGateInventory.model_json_schema()
    assert schema["properties"][field]["maximum"] == 8192
    assert schema["properties"]["source_coverage"]["maxItems"] == 8192
    values = inventory.model_dump(mode="json")
    values[field] = 8193
    with pytest.raises(ValidationError) as error:
        AutonomyGateInventory.model_validate(values)
    assert any(item["loc"] == (field,) for item in error.value.errors())


def test_host_material_inputs_remain_an_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            (
                "filesystem-input:orchestration.managed_host_tools:",
                "direct-env-ast:orchestration.managed_host_tools:",
            )
        )
    ]
    assert len(sources) == 17
    assert sum(":content-read:" in source.source_path for source in sources) == 2
    assert sum(":metadata-observation:" in source.source_path for source in sources) == 12
    assert sum(":directory-enumeration:" in source.source_path for source in sources) == 1
    assert sum(":host-identity:" in source.source_path for source in sources) == 2
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_isolation_admission_reuses_existing_bounded_filesystem_observations(
    inventory: AutonomyGateInventory,
) -> None:
    from mmaudit.isolation import provenance

    tree = ast.parse(textwrap.dedent(inspect.getsource(provenance._admit_isolation_executable)))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert (
        sum(
            isinstance(node.func, ast.Name) and node.func.id == "_observe_scanner_executable"
            for node in calls
        )
        == 1
    )
    assert not any(
        isinstance(node.func, ast.Attribute) and node.func.attr in {"open", "resolve", "is_file"}
        for node in calls
    )
    assert not hasattr(provenance, "_file_sha256")
    removed = {
        "filesystem-input:isolation.provenance:_file_sha256:1",
        "filesystem-input:isolation.provenance:_seal_builtin_isolation_backend:1",
        "filesystem-input:isolation.provenance:_seal_builtin_isolation_backend:2",
        "filesystem-input:isolation.provenance:_attestation_still_valid:1",
    }
    assert removed.isdisjoint(source.source_id for source in inventory.source_coverage)
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_isolation_sealing_lookup_and_each_probe_preserve_launcher_admission() -> None:
    from mmaudit.isolation import provenance

    expected = {
        provenance._seal_builtin_isolation_backend: (1, 4),
        provenance._attestation_still_valid: (1, 1),
        provenance._execute_probe: (0, 3),
        provenance._run_builtin_preflight: (1, 2),
        provenance._network_probe_denied: (1, 1),
    }
    for consumer, (admit_count, recheck_count) in expected.items():
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        named = Counter(node.func.id for node in calls if isinstance(node.func, ast.Name))
        assert named["_admit_isolation_executable"] == admit_count
        assert named["_require_isolation_executable_unchanged"] == recheck_count
        for node in calls:
            if isinstance(node.func, ast.Name) and node.func.id in {
                "_execute_probe",
                "_run_builtin_preflight",
                "_network_probe_denied",
            }:
                assert any(
                    keyword.arg == "admission"
                    and isinstance(keyword.value, ast.Name)
                    and keyword.value.id == "admission"
                    for keyword in node.keywords
                )


def test_absolute_executable_availability_inputs_share_the_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            (
                "filesystem-input:scanners.base:scanner_executable_candidate:",
                "direct-env-ast:scanners.base:scanner_executable_candidate:",
            )
        )
    ]
    assert len(sources) == 3
    assert sum(":metadata-observation:" in source.source_path for source in sources) == 2
    assert sum(":path-resolution:" in source.source_path for source in sources) == 1
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_shared_path_resolver_preserves_all_four_previous_lookup_consumers() -> None:
    from mmaudit.scanners.base import ScannerAdapter
    from mmaudit.scanners.foundry import FoundryForkScanner
    from mmaudit.scanners.runner import preflight_configured_scanner_tools

    for consumer in (
        ScannerAdapter.available,
        ScannerAdapter._run,
        FoundryForkScanner._run_repository_suite,
        preflight_configured_scanner_tools,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        assert (
            sum(
                isinstance(node.func, ast.Name) and node.func.id == "scanner_executable_candidate"
                for node in calls
            )
            == 1
        )
        assert not any(
            isinstance(node.func, ast.Attribute) and node.func.attr == "which" for node in calls
        )


def test_managed_isolation_cpu_and_os_inputs_retain_unverified_toolchain_gate(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        item
        for item in inventory.source_coverage
        if item.source_id.startswith("direct-env-ast:isolation.managed:")
    ]
    assert len(sources) == 2
    assert all(":host-platform:" in item.source_path for item in sources)
    assert all(item.logical_gate_id == "gate-managed-toolchain-bundle" for item in sources)
    assert all(item.classification is SourceCoverageClassification.GATE for item in sources)
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_compiler_path_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.compile:_managed_compilation_selection:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_formal_root_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.formal:_managedformalselection.verify_roots:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_clean_anvil_root_check_is_classified_without_promoting_readiness(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:scanners.clean_chain:_managedcleananviltool.verify:"
        )
    ]
    assert len(sources) == 1
    assert ":metadata-observation:" in sources[0].source_path
    assert sources[0].logical_gate_id == "gate-managed-toolchain-bundle"
    assert sources[0].classification is SourceCoverageClassification.GATE
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_prepared_clean_anvil_reuses_bounded_identity_observation_without_new_path_lookup() -> None:
    from mmaudit.scanners import clean_chain

    parameter = inspect.signature(clean_chain.TrustedCleanAnvilLauncher).parameters["host_tools"]
    assert parameter.default is None
    for consumer in (
        clean_chain._managed_clean_anvil_tool,
        clean_chain._ManagedCleanAnvilTool.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which", "getenv"}
            for node in ast.walk(tree)
        )


def test_managed_reproduction_root_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.reproduction:_managedreproductionselection.verify_roots:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_reproduction_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import reproduction

    for consumer in (
        reproduction._managed_reproduction_selection,
        reproduction._ManagedReproductionSelection.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(
        textwrap.dedent(
            inspect.getsource(reproduction.ForkReproductionRunner._preflight_managed_tools)
        )
    )
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert "expected_host_observation" in {keyword.arg for keyword in probes[0].keywords}


def test_managed_invariant_root_checks_remain_unverified_toolchain_inputs(
    inventory: AutonomyGateInventory,
) -> None:
    sources = [
        source
        for source in inventory.source_coverage
        if source.source_id.startswith(
            "filesystem-input:solidity.invariant_execution:_managedinvariantselection.verify_roots:"
        )
    ]
    assert len(sources) == 2
    assert all(":metadata-observation:" in source.source_path for source in sources)
    assert all(source.logical_gate_id == "gate-managed-toolchain-bundle" for source in sources)
    assert all(source.classification is SourceCoverageClassification.GATE for source in sources)
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_managed_invariant_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import invariant_execution as invariant

    for consumer in (
        invariant._managed_invariant_selection,
        invariant._ManagedInvariantSelection.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(textwrap.dedent(inspect.getsource(invariant._external_executable_version)))
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert "expected_host_observation" in {keyword.arg for keyword in probes[0].keywords}


def test_managed_formal_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import formal

    for consumer in (formal._managed_formal_selection, formal._ManagedFormalSelection.verify):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(textwrap.dedent(inspect.getsource(formal._isolated_tool_version)))
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert "expected_host_observation" in {keyword.arg for keyword in probes[0].keywords}


def test_managed_compilation_retains_shared_bounded_identity_and_probe_admission() -> None:
    from mmaudit.solidity import compile as compiler

    for consumer in (
        compiler._managed_compilation_selection,
        compiler._ManagedCompilationSelection.verify,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer)))
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_observe_scanner_executable"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"open", "read_bytes", "which"}
            for node in ast.walk(tree)
        )
    tree = ast.parse(textwrap.dedent(inspect.getsource(compiler._isolated_tool_versions)))
    probes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "isolated_executable_version_probe"
    ]
    assert len(probes) == 1
    assert any(keyword.arg == "expected_host_observation" for keyword in probes[0].keywords)


@pytest.mark.parametrize(
    "source",
    [
        "import platform as host\ndef selected_cpu():\n    return host.machine()\n",
        "from platform import machine as cpu\nselected = cpu\ndef selected_cpu():\n    return selected()\n",
    ],
)
def test_new_direct_or_aliased_cpu_platform_input_fails_closed(tmp_path: Path, source: str) -> None:
    root = tmp_path / "mmaudit"
    root.mkdir()
    (root / "new_platform.py").write_text(source)
    observed = inventory_module._direct_environment_occurrences(root)
    assert len(observed) == 1
    assert observed[0][:3] == ("new_platform.py", "selected_cpu", "host-platform")
    with pytest.raises(AutonomyInventoryError, match="direct environment"):
        _discover_direct_environment_sources(root)


def test_inventory_has_exact_autonomous_dispositions_and_honest_phase_zero_state(
    inventory: AutonomyGateInventory,
) -> None:
    assert {gate.desired_disposition for gate in inventory.logical_gates} == set(
        AutonomousGateDisposition
    )
    assert {item.value for item in AutonomousGateDisposition} == {
        "AUTONOMOUS_EVIDENCE_SUBSTITUTE",
        "PREPROVISIONED_NONHUMAN_INPUT",
        "PRERUN_CLIENT_DECISION",
        "OBJECTIVE_OUT_OF_SCOPE",
    }
    assert inventory.logical_gate_count == 35
    assert inventory.unsatisfied_gate_count == 29
    assert inventory.current_manual_gate_count == 15
    assert inventory.runtime_authority is False
    assert inventory.managed_run_ready is False
    assert inventory.provider_or_network_accessed is False
    assert inventory.secret_material_read is False
    assert inventory.completion_scope == "SYNTHETIC_PUBLIC_ONLY"
    assert inventory.discovery_scope == (
        "TYPED_BOUNDARIES_REGISTERED_ENTRYPOINTS_RUNTIME_PACKAGE_RESOURCES_"
        "UNSEALED_ENV_HOST_WALL_CLOCK_AUTHORITY_ENTROPY_FILESYSTEM_INTERACTIVE_"
        "OPAQUE_AUTHORITIES_"
        "EXPLICIT_MISSING_OBJECTIVE_BOUNDARIES"
    )
    assert inventory.private_repository_completion_in_scope is False
    managed_toolchain = next(
        gate for gate in inventory.logical_gates if gate.gate_id == "gate-managed-toolchain-bundle"
    )
    assert managed_toolchain.implementation_state is GateImplementationState.PARTIAL
    assert "independent bundle trust" in managed_toolchain.implementation_detail
    assert "operating-system probe helpers remain unmodeled" in (
        managed_toolchain.implementation_detail
    )
    sources = {source.source_id: source for source in inventory.source_coverage}
    retained_writer_inputs = tuple(
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:release_io:_write_file_content:")
        or source.source_id == "direct-env-ast:release_io:_write_file_content:host-identity:1"
    )
    assert len(retained_writer_inputs) == 13
    assert all(
        source.logical_gate_id == "gate-release-evidence-pipeline"
        and source.classification is SourceCoverageClassification.GATE
        for source in retained_writer_inputs
    )
    for source_id in (
        "direct-env-ast:orchestration.budgets:_accounting_portfolio_scope_material:"
        "process-identity:1",
        "direct-env-ast:orchestration.budgets:budgetmanager.portfolio_task_scope:"
        "process-identity:1",
        "direct-env-ast:orchestration.budgets:budgetmanager.reserve:process-identity:1",
        "entropy-ast:orchestration.cost_ledger:atomiccostledger.claim_portfolio_slot:uuid-uuid4:1",
        "entropy-ast:orchestration.cost_ledger:atomiccostledger.reserve_portfolio:uuid-uuid4:1",
    ):
        assert sources[source_id].logical_gate_id == "gate-cost-ledger-provisioning"
    scheduler_filesystem_sources = tuple(
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("filesystem-input:orchestration.scheduler:")
    )
    assert len(scheduler_filesystem_sources) == 59
    assert all(
        source.logical_gate_id == "gate-managed-output-provisioning"
        for source in scheduler_filesystem_sources
    )
    assert {
        "filesystem-input:orchestration.scheduler:_adopt_pending_private_file:1",
        "filesystem-input:orchestration.scheduler:_cleanup_orphan_immutable_writes:1",
        "filesystem-input:orchestration.scheduler:_durable_directory_names:1",
        "filesystem-input:orchestration.scheduler:_inspect_orphan_immutable_writes:1",
        "filesystem-input:orchestration.scheduler:"
        "_build_scheduler_journal_custody_registry.record_validated_snapshot:2",
        "filesystem-input:orchestration.scheduler:_write_exclusive_private_file:1",
        "filesystem-input:orchestration.scheduler:_write_model:1",
    } <= set(sources)
    smoke_run_index = sources[
        "completion-entrypoint:models_authenticated_runner_smoke:smoke_run_index"
    ]
    assert smoke_run_index.source_kind is CompletionInputSourceKind.COMPLETION_ENTRYPOINT_PARAMETER
    assert smoke_run_index.classification is SourceCoverageClassification.GATE
    assert smoke_run_index.logical_gate_id == "gate-authenticated-real-campaign"
    runtime_evidence = sources[
        "completion-entrypoint:models_authenticated_runner:runtime_evidence_smoke_bundle"
    ]
    assert runtime_evidence.source_kind is CompletionInputSourceKind.COMPLETION_ENTRYPOINT_PARAMETER
    assert runtime_evidence.classification is SourceCoverageClassification.GATE
    assert runtime_evidence.logical_gate_id == "gate-autonomous-model-authority"
    for source_id in (
        "completion-entrypoint:models_emit_selection_plan_successor:candidate",
        "completion-entrypoint:models_emit_selection_plan_successor:predecessor_plan",
        "completion-entrypoint:models_emit_selection_plan_successor:refresh_endpoint_inventory",
        "completion-entrypoint:models_emit_selection_plan_successor:upgrade_price_cap_profile_v2",
        "completion-entrypoint:models_list_endpoints:model_id",
    ):
        assert sources[source_id].logical_gate_id == "gate-autonomous-model-authority"
    for source_id in (
        "completion-entrypoint:certify_run_command:configuration_root",
        "completion-entrypoint:replay_command:configuration_root",
        "completion-entrypoint:verify_run_command:configuration_root",
        "filesystem-input:cli:_verification_configuration_root:1",
        "filesystem-input:repository.configuration_custody:observe_configuration_input:1",
    ):
        assert sources[source_id].logical_gate_id == "gate-managed-profile"
    scheduler_process_sources = tuple(
        source
        for source in inventory.source_coverage
        if source.source_id.startswith("direct-env-ast:orchestration.scheduler:")
        and ":process-identity" in source.source_id
    )
    assert len(scheduler_process_sources) == 12
    assert all(
        source.logical_gate_id == "gate-release-evidence-pipeline"
        for source in scheduler_process_sources
        if "privacy_evidence_custody" not in source.source_id
    )
    assert (
        sources[
            "direct-env-ast:orchestration.scheduler:open_scheduler_privacy_evidence_custody:"
            "process-identity:1"
        ].logical_gate_id
        == "gate-client-privacy-consent"
    )
    for source_id in (
        "cli-run:accepted_quote",
        "completion-entrypoint:_execute_audit:accepted_quote",
        "completion-entrypoint:quote_accept:quote_path",
        "completion-entrypoint:quote_create:portfolio_preflight",
        "completion-entrypoint:quote_reconcile:acceptance_path",
        "pipeline-init:accepted_prepurchase_quote",
    ):
        assert sources[source_id].logical_gate_id == "gate-budget-ceiling"
    for source_id in (
        "audit-config:execution.max_schema_validation_retries",
        "audit-override:execution.max_schema_validation_retries",
        "cli-run:schema_validation_retries",
        "completion-entrypoint:_execute_audit:schema_validation_retries",
        "completion-entrypoint:quote_create:schema_validation_retries",
    ):
        assert sources[source_id].logical_gate_id == "gate-full-quality-analysis"
    assert (
        sources["completion-entrypoint:quote_create:campaign_manifest"].logical_gate_id
        == "gate-authenticated-real-campaign"
    )
    assert (
        sources["completion-entrypoint:quote_reconcile:cost_ledger_evidence"].logical_gate_id
        == "gate-cost-ledger-provisioning"
    )
    assert (
        sources["completion-entrypoint:quote_reconcile:model_execution"].logical_gate_id
        == "gate-release-evidence-pipeline"
    )
    assert sources["audited-module:models.route_runtime_evidence"].logical_gate_id == (
        "gate-runtime-package-integrity"
    )
    for source_id in (
        "direct-env-ast:models.route_runtime_evidence:"
        "_build_runtime_capability_authority:process-identity-binding:1",
        "direct-env-ast:models.route_runtime_evidence:"
        "_build_runtime_capability_authority.issue:process-identity:1",
        "direct-env-ast:models.route_runtime_evidence:"
        "_build_runtime_capability_authority.reasons:process-identity:1",
    ):
        assert sources[source_id].logical_gate_id == "gate-authenticated-real-campaign"
    for source_id in (
        "audited-module:orchestration.managed_toolchain",
        "audited-module:resources.managed_toolchain_bundle.json",
    ):
        assert sources[source_id].logical_gate_id == "gate-runtime-package-integrity"
    assert (
        sources[
            "filesystem-input:orchestration.managed_toolchain:_load_managed_toolchain_bundle_path:1"
        ].logical_gate_id
        == "gate-managed-toolchain-bundle"
    )


def test_every_gate_source_has_exactly_one_logical_assignment(
    inventory: AutonomyGateInventory,
) -> None:
    covered = {
        source.source_id
        for source in inventory.source_coverage
        if source.classification is SourceCoverageClassification.GATE
    }
    assigned = [source_id for gate in inventory.logical_gates for source_id in gate.source_ids]
    assert len(assigned) == len(set(assigned))
    assert set(assigned) == covered
    assert all(
        source.logical_gate_id is None
        for source in inventory.source_coverage
        if source.source_id not in covered
    )


def test_unresolved_findings_and_external_authorities_remain_separately_unsatisfied(
    inventory: AutonomyGateInventory,
) -> None:
    gates = {gate.gate_id: gate for gate in inventory.logical_gates}
    unresolved = gates["gate-unresolved-finding-disposition"]
    assert unresolved.implementation_state is GateImplementationState.MISSING
    assert {
        "explicit:post-judge-manual-review-incomplete-branch",
        "explicit:consensus-needs-review-status",
        "required:autonomous-unresolved-finding-terminal-resolution",
    } <= set(unresolved.source_ids)
    assert gates["gate-external-transparency-seal"].implementation_state is (
        GateImplementationState.MISSING
    )
    assert gates["gate-trusted-time-independent-replay"].implementation_state is (
        GateImplementationState.MISSING
    )
    assert set(gates["gate-external-transparency-seal"].source_ids).isdisjoint(
        gates["gate-trusted-time-independent-replay"].source_ids
    )


def test_equivalent_config_and_cli_boundaries_use_consistent_primary_gates() -> None:
    assert _audit_gate_for_path("language_profile") == "gate-client-audit-scope"
    assert _audit_gate_for_path("smart_contracts.project_root") == "gate-client-audit-scope"
    assert _audit_gate_for_path("smart_contracts.allow_network") == "gate-dependency-snapshot"
    assert _audit_gate_for_path("maximum_assurance.benchmark_gate") == (
        "gate-benchmark-evidence-authority"
    )
    assert _audit_gate_for_path("execution.conservative_usd_per_million_tokens") == (
        "gate-budget-ceiling"
    )
    assert inventory_module._command_parameter_classification(
        "models_authenticated_runner_smoke", "smoke_corpus"
    ) == (SourceCoverageClassification.GATE, "gate-authenticated-real-campaign")
    assert inventory_module._command_parameter_classification(
        "managed_provision", "verify_only"
    ) == (SourceCoverageClassification.GATE, "gate-managed-provisioning")


def test_managed_provisioning_mechanism_is_partial_and_nonauthorizing(
    inventory: AutonomyGateInventory,
) -> None:
    gate = next(
        item for item in inventory.logical_gates if item.gate_id == "gate-managed-provisioning"
    )
    assert gate.implementation_state is GateImplementationState.PARTIAL
    assert "portfolio holds" in gate.implementation_detail
    assert "authority stay false" in gate.implementation_detail
    assert inventory.runtime_authority is False
    assert inventory.managed_run_ready is False


def test_development_rejection_projection_is_audited_without_acquiring_authority(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "audited-module:models.development_diagnostics"
    )
    assert source.source_path == "src/mmaudit/models/development_diagnostics.py"
    assert source.logical_gate_id == "gate-runtime-package-integrity"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    ("source_id", "gate_id"),
    [
        ("audited-module:benchmark.development_comparison", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_comparison", "gate-runtime-package-integrity"),
        ("explicit:development-benchmark-comparison", "gate-benchmark-evidence-authority"),
        ("explicit:development-comparison-files", "gate-client-audit-scope"),
    ],
)
def test_development_comparison_inputs_and_outputs_have_explicit_gate_coverage(
    inventory: AutonomyGateInventory, source_id: str, gate_id: str
) -> None:
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_completion_telemetry_has_explicit_non_authorizing_coverage(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "explicit:development-completion-telemetry"
    )
    assert source.logical_gate_id == "gate-provider-secret-transport"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_development_uncertain_carry_has_explicit_non_authorizing_coverage(
    inventory: AutonomyGateInventory,
) -> None:
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "explicit:development-uncertain-estimate-carry"
    )
    assert source.logical_gate_id == "gate-cost-ledger-provisioning"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_judgment", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_judgment", "gate-runtime-package-integrity"),
        ("explicit:development-judgment-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-judgment-shard-transport", "gate-provider-secret-transport"),
        ("explicit:development-judgment-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-judgment-candidate-accounting", "gate-cost-ledger-provisioning"),
        ("explicit:development-judgment-impact", "gate-benchmark-evidence-authority"),
    ],
)
def test_development_judgment_execution_and_impact_are_explicitly_nonauthorizing(
    inventory, source_id, gate_id
):
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_committed_inventory_is_canonical_self_hashed_and_current(
    inventory: AutonomyGateInventory,
) -> None:
    path = ROOT / AUTONOMY_INVENTORY_PATH
    assert path.read_text(encoding="utf-8") == render_autonomy_gate_inventory(repository_root=ROOT)
    assert load_autonomy_gate_inventory(path) == inventory
    assert render_autonomy_gate_inventory(repository_root=ROOT) == (
        render_autonomy_gate_inventory(repository_root=ROOT)
    )


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:benchmark.development_ensemble", "gate-runtime-package-integrity"),
        ("audited-module:models.development_ensemble", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_ensemble", "gate-runtime-package-integrity"),
        ("explicit:development-ensemble-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-ensemble-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-ensemble-accounting", "gate-cost-ledger-provisioning"),
        ("explicit:development-ensemble-impact", "gate-benchmark-evidence-authority"),
    ],
)
def test_executed_development_ensemble_remains_explicitly_nonauthorizing(
    inventory, source_id, gate_id
):
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_corpus", "gate-runtime-package-integrity"),
        ("audited-module:orchestration.development_corpus", "gate-runtime-package-integrity"),
        ("audited-module:repository.development_corpus", "gate-runtime-package-integrity"),
        ("explicit:development-corpus-frozen-manifest", "gate-client-audit-scope"),
        ("explicit:development-corpus-selected-source-loader", "gate-client-audit-scope"),
        ("explicit:development-corpus-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-corpus-shard-transport", "gate-provider-secret-transport"),
        ("explicit:development-corpus-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-corpus-accounting", "gate-cost-ledger-provisioning"),
    ],
)
def test_manifest_development_corpus_remains_explicitly_nonauthorizing(
    inventory, source_id, gate_id
):
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


def test_selected_development_deadline_is_a_nonauthorizing_transport_input(inventory):
    source = next(
        item
        for item in inventory.source_coverage
        if item.source_id == "explicit:development-selected-request-deadline"
    )
    assert source.logical_gate_id == "gate-provider-secret-transport"
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


@pytest.mark.parametrize(
    "source_id,gate_id",
    [
        ("audited-module:models.development_corpus_judgment", "gate-runtime-package-integrity"),
        (
            "audited-module:orchestration.development_corpus_judgment",
            "gate-runtime-package-integrity",
        ),
        ("explicit:development-corpus-judgment-retained-candidate", "gate-client-audit-scope"),
        ("explicit:development-corpus-judgment-frozen-plan", "gate-client-audit-scope"),
        ("explicit:development-corpus-judgment-shard-transport", "gate-provider-secret-transport"),
        ("explicit:development-corpus-judgment-sequential-run", "gate-full-quality-analysis"),
        ("explicit:development-corpus-judgment-accounting", "gate-cost-ledger-provisioning"),
    ],
)
def test_manifest_candidate_review_preserves_all_nonauthorizing_gates(
    inventory, source_id, gate_id
):
    source = next(item for item in inventory.source_coverage if item.source_id == source_id)
    assert source.logical_gate_id == gate_id
    assert source.classification is SourceCoverageClassification.GATE
    assert inventory.logical_gate_count == 35 and inventory.unsatisfied_gate_count == 29
    assert inventory.runtime_authority is inventory.managed_run_ready is False


class _InnocuousNestedConfig(StrictModel):
    harmless_counter: int = 0


class _AuditConfigWithNewLeaf(AuditConfig):
    innocuous: _InnocuousNestedConfig = Field(default_factory=_InnocuousNestedConfig)


class _AuditRunOptionsWithNewLeaf(AuditRunOptions):
    innocuous: bool = False


def test_new_innocuously_named_config_and_run_option_leaves_fail_closed() -> None:
    with pytest.raises(AutonomyInventoryError, match="AuditConfig leaves"):
        build_autonomy_gate_inventory(
            repository_root=ROOT, audit_config_model=_AuditConfigWithNewLeaf
        )
    with pytest.raises(AutonomyInventoryError, match="AuditRunOptions leaves"):
        build_autonomy_gate_inventory(
            repository_root=ROOT,
            audit_run_options_model=_AuditRunOptionsWithNewLeaf,
        )


def test_new_override_and_environment_entries_fail_closed() -> None:
    from mmaudit.config import _AUDIT_OVERRIDE_VALUE_TYPES, _ENVIRONMENT_OVERRIDE_MAPPINGS

    overrides = dict(_AUDIT_OVERRIDE_VALUE_TYPES)
    overrides["innocuous.harmless_counter"] = (int,)
    with pytest.raises(AutonomyInventoryError, match="audit override allowlist"):
        build_autonomy_gate_inventory(repository_root=ROOT, audit_override_value_types=overrides)
    environment = dict(_ENVIRONMENT_OVERRIDE_MAPPINGS)
    environment["MMAUDIT_INNOCUOUS_COUNTER"] = ("innocuous.harmless_counter", int)
    with pytest.raises(AutonomyInventoryError, match="environment override allowlist"):
        build_autonomy_gate_inventory(
            repository_root=ROOT, environment_override_mappings=environment
        )


def test_new_cli_and_pipeline_parameters_fail_closed() -> None:
    def changed_cli(innocuous: bool = False) -> None:
        del innocuous

    def changed_pipeline_init(self: object, innocuous: bool = False) -> None:
        del self, innocuous

    async def changed_pipeline_run(self: object, innocuous: bool = False) -> None:
        del self, innocuous

    with pytest.raises(AutonomyInventoryError, match="run_command parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, cli_run_command=changed_cli)
    with pytest.raises(AutonomyInventoryError, match=r"AuditPipeline\.__init__ parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, pipeline_init=changed_pipeline_init)
    with pytest.raises(AutonomyInventoryError, match=r"AuditPipeline\.run parameters"):
        build_autonomy_gate_inventory(repository_root=ROOT, pipeline_run=changed_pipeline_run)


def test_new_auxiliary_completion_entrypoint_parameter_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = inventory_module._registered_cli_commands()

    def new_completion_command(innocuous: bool = False) -> None:
        del innocuous

    monkeypatch.setattr(
        inventory_module,
        "_registered_cli_commands",
        lambda: (*current, ("new_completion_command", new_completion_command)),
    )
    with pytest.raises(AutonomyInventoryError, match="completion entrypoint parameters"):
        _discover_completion_entrypoint_sources()
    with pytest.raises(AutonomyInventoryError, match="unclassified completion command parameter"):
        inventory_module._command_parameter_classification("new_completion_command", "innocuous")


def test_existing_field_semantics_drift_changes_the_objective_source_universe() -> None:
    changed_model = create_model(
        "AuditConfigWithChangedSemantics",
        __base__=AuditConfig,
        version=(Literal[1], Field(default=1, description="semantics-only mutation")),
    )

    baseline = build_autonomy_gate_inventory(repository_root=ROOT)
    changed = build_autonomy_gate_inventory(
        repository_root=ROOT,
        audit_config_model=changed_model,
    )
    assert changed.source_universe_sha256 != baseline.source_universe_sha256
    assert changed.inventory_sha256 != baseline.inventory_sha256


def test_repository_local_path_defaults_are_worktree_independent(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    relative_path = Path("benchmarks/model_corpus/manifest.json")

    first = inventory_module._canonical_default(
        first_root / relative_path,
        repository_root=first_root,
    )
    second = inventory_module._canonical_default(
        second_root / relative_path,
        repository_root=second_root,
    )

    assert first == second == {"repository_path": relative_path.as_posix()}
    assert inventory_module._canonical_default(
        (first_root / relative_path, frozenset({first_root / "schemas/current.json"})),
        repository_root=first_root,
    ) == [
        {"repository_path": relative_path.as_posix()},
        [{"repository_path": "schemas/current.json"}],
    ]
    assert inventory_module._canonical_default(
        tmp_path / "external.json",
        repository_root=first_root,
    ) == {"path": (tmp_path / "external.json").as_posix()}


def test_new_runtime_resource_and_interactive_input_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_resource.dat").write_text("bounded", encoding="utf-8")
    assert [
        path.relative_to(source_root).as_posix()
        for path in inventory_module._runtime_package_paths(source_root)
    ] == ["new_resource.dat"]
    with pytest.raises(AutonomyInventoryError, match="runtime package paths"):
        _discover_audited_module_sources(source_root)
    monkeypatch.setattr(
        inventory_module,
        "_FROZEN_AUDITED_MODULE_PATHS_SHA256",
        inventory_module._canonical_sha256(["new_resource.dat"]),
    )
    before = _discover_audited_module_sources(source_root)[0].source_semantics_sha256
    (source_root / "new_resource.dat").write_text("changed bytes", encoding="utf-8")
    after = _discover_audited_module_sources(source_root)[0].source_semantics_sha256
    assert after != before
    (source_root / "new_gate.py").write_text(
        "from builtins import input as ask\ndef request_operator():\n    return ask('approve?')\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert filesystem == ()
    assert [(path, scope) for path, scope, _ in interactive] == [
        ("new_gate.py", "request_operator")
    ]
    assert "approve?" in interactive[0][2]
    with pytest.raises(AutonomyInventoryError, match="interactive operator input loci"):
        _discover_external_input_sources(source_root)


def test_new_aliased_filesystem_read_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_reader.py").write_text(
        "from os import F_OK, O_RDONLY, access as permitted, fstat as descriptor_status\n"
        "from os import listdir as members, open as raw_open, stat as status\n"
        "from os.path import lexists as link_exists\n"
        "from pathlib import Path as P\n"
        "from shutil import copy2 as clone\n"
        "read_path = P.read_text\n"
        "list_path = P.iterdir\n"
        "path_exists = P.exists\n"
        "def read_external():\n"
        "    raw_open('opaque', O_RDONLY)\n"
        "    clone('source', 'destination')\n"
        "    members('.')\n"
        "    status('opaque')\n"
        "    permitted('opaque', F_OK)\n"
        "    descriptor_status(0)\n"
        "    tuple(P('.').iterdir())\n"
        "    P('opaque').is_junction()\n"
        "    getattr(P('opaque'), 'is_junction', lambda: False)()\n"
        "    link_exists('opaque')\n"
        "    read_path(P('opaque'))\n"
        "    tuple(list_path(P('.')))\n"
        "    path_exists(P('opaque'))\n"
        "    return P('opaque').read_text()\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert interactive == ()
    assert Counter(kind for _, _, kind, _ in filesystem) == {
        "content-read": 4,
        "directory-enumeration": 3,
        "metadata-observation": 7,
    }
    assert {(path, scope) for path, scope, _, _ in filesystem} == {
        ("new_reader.py", "read_external")
    }
    with pytest.raises(AutonomyInventoryError, match="unclassified filesystem input authority"):
        inventory_module._filesystem_input_gate("new_reader.py", "read_external")
    with pytest.raises(AutonomyInventoryError, match="filesystem input loci"):
        _discover_external_input_sources(source_root)


def test_new_aliased_wall_clock_read_fails_closed(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "new_clock.py").write_text(
        "from elsewhere import clock\n"
        "from datetime import UTC, datetime as D\n"
        "import os\n"
        "from os.path import abspath as absolute_name\n"
        "from pathlib import Path\n"
        "clock = D.now\n"
        "current_uid = getattr(os, 'getuid', lambda: 0)\n"
        "trusted_process = os.getpid\n"
        "def authority_time():\n"
        "    return (clock(UTC), current_uid(), trusted_process(), "
        "absolute_name('x'), Path('x').absolute())\n"
        "def custom_attribute_is_not_os(custom):\n"
        "    trusted = custom.getpid\n"
        "    return trusted()\n",
        encoding="utf-8",
    )
    occurrences = inventory_module._direct_environment_occurrences(source_root)
    assert Counter((path, scope, kind) for path, scope, kind, _ in occurrences) == {
        ("new_clock.py", "authority_time", "host-identity"): 1,
        ("new_clock.py", "authority_time", "process-identity"): 1,
        ("new_clock.py", "authority_time", "wall-clock"): 1,
        ("new_clock.py", "authority_time", "working-directory"): 2,
        ("new_clock.py", "module", "process-identity-binding"): 1,
    }
    assert any("clock" in expression for *_, expression in occurrences)
    assert all("custom" not in expression for *_, expression in occurrences)
    with pytest.raises(AutonomyInventoryError, match="direct environment and PATH-resolution"):
        _discover_direct_environment_sources(source_root)


def test_budget_portfolio_scope_process_identity_is_a_cost_ledger_gate() -> None:
    assert (
        inventory_module._direct_environment_gate(
            "orchestration/budgets.py",
            "BudgetManager.portfolio_task_scope",
            "process-identity",
            "os.getpid()",
        )
        == "gate-cost-ledger-provisioning"
    )


def test_filesystem_privacy_provenance_has_exact_nonfallback_gate() -> None:
    assert (
        inventory_module._filesystem_input_gate(
            "repository/privacy_provenance.py", "classify_repository_source"
        )
        == "gate-synthetic-public-scope"
    )
    assert (
        inventory_module._filesystem_input_gate(
            "solidity/invariant_execution.py", "FoundryInvariantRunner._execute"
        )
        == "gate-full-quality-analysis"
    )


@pytest.mark.parametrize(
    ("relative_path", "scope", "expected_gate"),
    [
        (
            "models/authenticated_runner_durable_bundle.py",
            "load_authenticated_runner_durable_bundle",
            "gate-managed-output-provisioning",
        ),
        (
            "scanners/trusted_inputs.py",
            "_validated_private_directory",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/provenance.py",
            "_run_builtin_preflight",
            "gate-reproduction-capability-policy",
        ),
        (
            "isolation/provenance.py",
            "_trusted_helper",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/container.py",
            "discover_rootless_container_backend",
            "gate-managed-toolchain-bundle",
        ),
        (
            "orchestration/managed_toolchain.py",
            "_load_managed_toolchain_bundle_path",
            "gate-managed-toolchain-bundle",
        ),
        (
            "scanners/base.py",
            "_observe_scanner_executable",
            "gate-managed-toolchain-bundle",
        ),
        (
            "orchestration/managed_host_tools.py",
            "materialize_managed_host_tools",
            "gate-managed-toolchain-bundle",
        ),
        (
            "isolation/container.py",
            "SingleLoopbackHardhatBackend.bridge_socket_path",
            "gate-fork-environment",
        ),
        (
            "scanners/fork_matrix.py",
            "_open_private_root",
            "gate-managed-output-provisioning",
        ),
        (
            "scanners/read_only_rpc.py",
            "ReadOnlyRpcBridge.start",
            "gate-fork-environment",
        ),
        ("solidity/formal.py", "_read_halmos_plan", "gate-formal-analysis"),
        (
            "solidity/formal.py",
            "FormalAdapter.available",
            "gate-managed-toolchain-bundle",
        ),
    ],
)
def test_filesystem_primary_gate_map_is_scope_specific(
    relative_path: str,
    scope: str,
    expected_gate: str,
) -> None:
    assert inventory_module._filesystem_input_gate(relative_path, scope) == expected_gate


def test_write_only_opens_are_not_filesystem_content_inputs(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "writer.py").write_text(
        "from os import O_CREAT, O_EXCL, O_WRONLY, open as descriptor_open\n"
        "from pathlib import Path\n"
        "def write_only():\n"
        "    Path('plain').open('wb')\n"
        "    descriptor_open('plain', O_WRONLY | O_CREAT)\n"
        "    descriptor_open('exclusive', O_WRONLY | O_CREAT | O_EXCL)\n",
        encoding="utf-8",
    )
    filesystem, interactive = inventory_module._external_input_occurrences(source_root)
    assert interactive == ()
    assert [(path, scope, kind) for path, scope, kind, _ in filesystem] == [
        ("writer.py", "write_only", "metadata-observation")
    ]


def test_authority_entropy_alias_is_detected_without_a_default_gate(tmp_path: Path) -> None:
    source_root = tmp_path / "mmaudit"
    source_root.mkdir()
    (source_root / "entropy.py").write_text(
        "from uuid import uuid4 as new_id\ndef authority_id():\n    return new_id().hex\n",
        encoding="utf-8",
    )
    occurrences = inventory_module._entropy_input_occurrences(source_root)
    assert [(path, scope, kind) for path, scope, kind, _ in occurrences] == [
        ("entropy.py", "authority_id", "uuid.uuid4")
    ]
    with pytest.raises(AutonomyInventoryError, match="unclassified entropy input authority"):
        inventory_module._entropy_input_classification("entropy.py", "authority_id")


def test_objective_drift_fails_before_any_runtime_discovery(tmp_path: Path) -> None:
    objective = tmp_path / "docs" / "remediation" / "v3" / "product_completion_goal.txt"
    objective.parent.mkdir(parents=True)
    objective.write_text("drifted objective\n", encoding="utf-8")
    with pytest.raises(AutonomyInventoryError, match="objective bytes drifted"):
        build_autonomy_gate_inventory(repository_root=tmp_path)


def test_missing_duplicate_and_multiple_assignments_are_rejected(
    inventory: AutonomyGateInventory,
) -> None:
    values = inventory.model_dump(mode="json")
    values["source_coverage"] = values["source_coverage"][:-1]
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)

    values = inventory.model_dump(mode="json")
    values["source_coverage"].append(values["source_coverage"][0])
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)

    values = inventory.model_dump(mode="json")
    first_source = values["logical_gates"][0]["source_ids"][0]
    second_sources = set(values["logical_gates"][1]["source_ids"])
    second_sources.add(first_source)
    values["logical_gates"][1]["source_ids"] = sorted(second_sources)
    with pytest.raises(ValidationError):
        AutonomyGateInventory.model_validate(values)


def test_cold_generation_is_provider_network_and_secret_free() -> None:
    assay = textwrap.dedent(
        f"""
        import os
        import socket
        from collections import UserDict
        from pathlib import Path

        class GuardedEnvironment(UserDict):
            def _guard(self, key):
                text = str(key).upper()
                if any(token in text for token in ("SECRET", "TOKEN", "API_KEY", "OPENROUTER")):
                    raise AssertionError(f"sensitive environment key was read: {{key}}")

            def __getitem__(self, key):
                self._guard(key)
                return super().__getitem__(key)

            def __contains__(self, key):
                self._guard(key)
                return super().__contains__(key)

        def forbidden(*args, **kwargs):
            raise AssertionError("network access is forbidden during inventory generation")

        class GuardedSocket(socket.socket):
            def connect(self, *args, **kwargs):
                return forbidden(*args, **kwargs)

            def connect_ex(self, *args, **kwargs):
                return forbidden(*args, **kwargs)

        safe = dict(os.environ)
        safe["OPENROUTER_API_KEY"] = "must-not-be-read"
        os.environ = GuardedEnvironment(safe)
        os.getenv = lambda key, default=None: os.environ.get(key, default)
        socket.socket = GuardedSocket
        socket.create_connection = forbidden
        socket.getaddrinfo = forbidden
        socket.gethostbyname = forbidden
        socket.gethostbyname_ex = forbidden

        from mmaudit.orchestration.autonomy_gate_inventory import build_autonomy_gate_inventory

        generated = build_autonomy_gate_inventory(repository_root=Path({str(ROOT)!r}))
        assert generated.provider_or_network_accessed is False
        assert generated.secret_material_read is False
        """
    )
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(ROOT / "src"),
    }
    completed = subprocess.run(
        [sys.executable, "-c", assay],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
