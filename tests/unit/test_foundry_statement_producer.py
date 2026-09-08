from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TypedDict

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditedSuiteEntityCatalog,
    AuditedSuiteEntityCatalogBinding,
    AuditedSuiteStatementStatus,
    ExecutionEvidenceKind,
    ForkRpcMethodCount,
    FoundryTestExecutionSummary,
    Location,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteInventoryArtifact,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryKind,
    RepositorySuiteInventoryPhase,
    RepositorySuiteInventoryRecord,
    RepositorySuiteProjectInventoryEvidence,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositorySuiteWorkspaceCopyEvidence,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestForkRpcScopeEvidence,
    RepositoryTestForkRpcScopeStatus,
    RepositoryTestKind,
    ScannerRun,
    ScannerStatus,
    SolidityEntityKind,
    SolidityProvenance,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.scanners.foundry_inventory import (
    FoundryCompilerBuildUnit,
    FoundryCompilerEntity,
    FoundryCompilerSource,
    FoundryCompilerStatement,
    FoundryCompilerStatementCatalog,
)
from mmaudit.scanners.foundry_statement_coverage import (
    ForgeDebugStatementCoverage,
    ForgeDebugStatementRecord,
)
from mmaudit.scanners.foundry_statement_producer import (
    FOUNDRY_STATEMENT_COVERAGE_NORMALIZER_POLICY_SHA256,
    FOUNDRY_STATEMENT_COVERAGE_PRODUCER_VERSION,
    FoundryStatementCoverageProcessObservation,
    FoundryStatementCoverageProductionError,
    produce_foundry_statement_coverage,
)

_SOURCE = b"contract Vault {\n    function set() public {\n        value = 1;\n    }\n}\n"
_SOURCE_SHA256 = hashlib.sha256(_SOURCE).hexdigest()
_REPOSITORY_SHA256 = "1" * 64
_CONFIGURATION_SHA256 = "2" * 64
_TOOL_SHA256 = "3" * 64
_COMPILER_SHA256 = "4" * 64
_ISOLATION_SHA256 = "5" * 64
_PRODUCER_SHA256 = "6" * 64
_BLOCK_HASH = "0x" + "7" * 64
_FUZZ_SEED = "0x" + "8" * 64
_BUILD_SHA256 = "a" * 64
_SECOND_BUILD_SHA256 = "b" * 64
_TEST_SOURCE_SHA256 = "c" * 64


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _compiler_unit(build_sha256: str = _BUILD_SHA256) -> FoundryCompilerBuildUnit:
    contract_end = _SOURCE.rindex(b"}") + 1
    function_start = _SOURCE.index(b"function")
    function_end = _SOURCE.index(b"}", function_start) + 1
    statement_start = _SOURCE.index(b"value")
    statement_end = statement_start + len(b"value = 1;")
    source = FoundryCompilerSource(
        source_id=0,
        path="src/Vault.sol",
        content=_SOURCE,
        source_sha256=_SOURCE_SHA256,
    )
    return FoundryCompilerBuildUnit(
        project_root=".",
        normalized_build_info_sha256=build_sha256,
        compiler_version="0.8.24",
        compiler_sha256=_COMPILER_SHA256,
        source_id_to_path=((0, "src/Vault.sol"),),
        sources=(source,),
        entities=(
            FoundryCompilerEntity(
                compiler_ast_id=1,
                node_type="ContractDefinition",
                kind="contract",
                name="Vault",
                enclosing_contract_ast_id=None,
                enclosing_contract_name=None,
                source_id=0,
                path="src/Vault.sol",
                source_sha256=_SOURCE_SHA256,
                start_byte=0,
                end_byte_exclusive=contract_end,
                start_line=1,
                end_line_exclusive=6,
            ),
            FoundryCompilerEntity(
                compiler_ast_id=2,
                node_type="FunctionDefinition",
                kind="function",
                name="set",
                enclosing_contract_ast_id=1,
                enclosing_contract_name="Vault",
                source_id=0,
                path="src/Vault.sol",
                source_sha256=_SOURCE_SHA256,
                start_byte=function_start,
                end_byte_exclusive=function_end,
                start_line=2,
                end_line_exclusive=5,
            ),
        ),
        statements=(
            FoundryCompilerStatement(
                compiler_ast_id=3,
                enclosing_inline_assembly_ast_id=None,
                node_type="ExpressionStatement",
                enclosing_contract_ast_id=1,
                enclosing_function_ast_id=2,
                source_id=0,
                path="src/Vault.sol",
                source_sha256=_SOURCE_SHA256,
                start_byte=statement_start,
                end_byte_exclusive=statement_end,
                start_line=3,
                end_line_exclusive=4,
            ),
        ),
    )


def _compiler_catalog(*, duplicate_unit: bool = False) -> FoundryCompilerStatementCatalog:
    units: tuple[FoundryCompilerBuildUnit, ...] = (_compiler_unit(),)
    if duplicate_unit:
        units += (_compiler_unit(_SECOND_BUILD_SHA256),)
    return FoundryCompilerStatementCatalog(
        project_root=".",
        compiler_version="0.8.24",
        compiler_sha256=_COMPILER_SHA256,
        units=units,
    )


def _inventory_records() -> tuple[RepositorySuiteInventoryRecord, ...]:
    return tuple(
        RepositorySuiteInventoryRecord.sealed(
            project_root=".",
            execution_path="test/Vault.t.sol",
            execution_suite_name="VaultTest",
            test_name=test_name,
            execution_signature=f"{test_name}()",
            execution_source_sha256=_TEST_SOURCE_SHA256,
            execution_start_line=index,
            execution_end_line=index,
            execution_contract_ast_id=10,
            declaration_path="test/Vault.t.sol",
            declaration_suite_name="VaultTest",
            declaration_signature=f"{test_name}()",
            declaration_source_sha256=_TEST_SOURCE_SHA256,
            declaration_start_line=index,
            declaration_end_line=index,
            declaration_contract_ast_id=10,
            declaration_function_ast_id=10 + index,
            build_info_sha256=_BUILD_SHA256,
        )
        for index, test_name in enumerate(("testOne", "testTwo"), start=10)
    )


def _inventory(
    phase: RepositorySuiteInventoryPhase,
    *,
    duplicate_unit: bool = False,
) -> RepositorySuiteInventoryEvidence:
    records = _inventory_records()
    build_hashes = [_BUILD_SHA256]
    if duplicate_unit:
        build_hashes.append(_SECOND_BUILD_SHA256)
    artifacts = tuple(
        RepositorySuiteInventoryArtifact(
            name=f"build-{index}.json",
            sha256=_hash(f"raw-build-{index}"),
            normalized_sha256=build_hash,
            bytes=2,
        )
        for index, build_hash in enumerate(build_hashes)
    )
    project = RepositorySuiteProjectInventoryEvidence.sealed(
        project_root=".",
        command_sha256=_hash(f"inventory-command-{phase.value}"),
        process_exit_code=0,
        machine_output_validated=True,
        stdout_sha256=_hash(f"inventory-stdout-{phase.value}"),
        stdout_bytes=2,
        stderr_sha256=_hash(f"inventory-stderr-{phase.value}"),
        stderr_bytes=0,
        build_info_artifacts=artifacts,
        build_info_bundle_sha256=_canonical_sha256(
            [artifact.model_dump(mode="json") for artifact in artifacts]
        ),
        normalized_build_info_bundle_sha256=_canonical_sha256(sorted(build_hashes)),
        parser_inventory_sha256=_hash("parser-inventory"),
        records=records,
        normalized_inventory_sha256=_canonical_sha256(
            sorted(record.record_sha256 for record in records)
        ),
    )
    return RepositorySuiteInventoryEvidence.sealed(
        phase=phase,
        framework=RepositorySuiteFramework.FOUNDRY,
        repository_sha256=_REPOSITORY_SHA256,
        configuration_sha256=_CONFIGURATION_SHA256,
        tool_version="forge 1.3.2",
        tool_sha256=_TOOL_SHA256,
        compiler_version="0.8.24",
        compiler_sha256=_COMPILER_SHA256,
        isolation_backend="synthetic-local-isolation",
        isolation_attestation_sha256=_ISOLATION_SHA256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        projects=(project,),
        project_bundle_sha256=_canonical_sha256([project.project_inventory_sha256]),
        normalized_inventory_sha256=project.normalized_inventory_sha256,
        inventory_record_count=len(records),
    )


def _entity_catalog() -> AuditedSuiteEntityCatalog:
    unit = _compiler_unit()
    contract, function = unit.entities
    bindings = [
        AuditedSuiteEntityCatalogBinding.sealed(
            entity_id="entity-contract-vault",
            entity_kind=SolidityEntityKind.CONTRACT,
            entity_name="Vault",
            declaring_contract_name=None,
            evidence_contract_name="Vault",
            location=Location(
                path="src/Vault.sol",
                start_line=contract.start_line,
                end_line=contract.end_line_exclusive - 1,
                symbol="Vault",
                content_hash=line_range_hash(
                    _SOURCE.decode(),
                    contract.start_line,
                    contract.end_line_exclusive - 1,
                ),
            ),
            entity_start_byte_offset=contract.start_byte,
            entity_end_byte_offset=contract.end_byte_exclusive,
            source_file_sha256=_SOURCE_SHA256,
            provenance=SolidityProvenance.COMPILER,
        ),
        AuditedSuiteEntityCatalogBinding.sealed(
            entity_id="entity-function-set",
            entity_kind=SolidityEntityKind.FUNCTION,
            entity_name="set",
            declaring_contract_name="Vault",
            evidence_contract_name="Vault",
            location=Location(
                path="src/Vault.sol",
                start_line=function.start_line,
                end_line=function.end_line_exclusive - 1,
                symbol="set()",
                content_hash=line_range_hash(
                    _SOURCE.decode(),
                    function.start_line,
                    function.end_line_exclusive - 1,
                ),
            ),
            entity_start_byte_offset=function.start_byte,
            entity_end_byte_offset=function.end_byte_exclusive,
            source_file_sha256=_SOURCE_SHA256,
            provenance=SolidityProvenance.COMPILER,
        ),
    ]
    return AuditedSuiteEntityCatalog.sealed(
        repository_sha256=_REPOSITORY_SHA256,
        classification_complete=True,
        classification_limitations=[],
        bindings=sorted(bindings, key=lambda item: (item.entity_id, item.binding_sha256)),
    )


def _selection(
    inventory: RepositorySuiteInventoryEvidence,
) -> RepositorySuiteSelection:
    descriptors = tuple(
        RepositorySuiteTestDescriptor.sealed(
            framework=RepositorySuiteFramework.FOUNDRY,
            project_root=".",
            path=record.execution_path,
            suite_name=record.execution_suite_name,
            test_name=record.test_name,
            source_sha256=record.execution_source_sha256,
            start_line=record.execution_start_line,
            end_line=record.execution_end_line,
            inventory_sha256=inventory.normalized_inventory_sha256,
            inventory_record_sha256=record.record_sha256,
            execution_contract_ast_id=record.execution_contract_ast_id,
            declaration_path=record.declaration_path,
            declaration_suite_name=record.declaration_suite_name,
            declaration_signature=record.declaration_signature,
            declaration_source_sha256=record.declaration_source_sha256,
            declaration_start_line=record.declaration_start_line,
            declaration_end_line=record.declaration_end_line,
            declaration_contract_ast_id=record.declaration_contract_ast_id,
            declaration_function_ast_id=record.declaration_function_ast_id,
        )
        for record in _inventory_records()
    )
    return RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256=_REPOSITORY_SHA256,
        repository_exclusion_path=".mmaudit-private",
        configuration_sha256=_CONFIGURATION_SHA256,
        candidate_file_count=1,
        candidate_test_count=2,
        selected_file_count=1,
        selected_test_count=2,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        inventory_kind=RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO,
        inventory_sha256=inventory.normalized_inventory_sha256,
        tests=descriptors,
    )


def _policy(selection: RepositorySuiteSelection) -> RepositorySuiteExecutionPolicy:
    return RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=1,
        block_number=100,
        block_hash=_BLOCK_HASH,
        tool_version="forge 1.3.2",
        tool_sha256=_TOOL_SHA256,
        compiler_version="0.8.24",
        compiler_sha256=_COMPILER_SHA256,
        isolation_backend="synthetic-local-isolation",
        isolation_attestation_sha256=_ISOLATION_SHA256,
        fuzz_seed=_FUZZ_SEED,
        fuzz_runs=256,
        invariant_runs=16,
        per_test_timeout_seconds=60,
        total_timeout_seconds=120,
        max_output_bytes_per_test=100_000,
        max_total_output_bytes=1_000_000,
    )


def _executions(
    selection: RepositorySuiteSelection,
    policy: RepositorySuiteExecutionPolicy,
    pre_inventory: RepositorySuiteInventoryEvidence,
    post_inventory: RepositorySuiteInventoryEvidence,
) -> tuple[RepositoryTestExecution, ...]:
    return tuple(
        RepositoryTestExecution.sealed(
            selection_sha256=selection.selection_sha256,
            descriptor_sha256=descriptor.descriptor_sha256,
            inventory_sha256=pre_inventory.inventory_sha256,
            post_inventory_sha256=post_inventory.inventory_sha256,
            inventory_record_sha256=descriptor.inventory_record_sha256,
            framework=descriptor.framework,
            project_root=descriptor.project_root,
            path=descriptor.path,
            suite_name=descriptor.suite_name,
            test_name=descriptor.test_name,
            chain_id=policy.chain_id,
            block_number=policy.block_number,
            block_hash=policy.block_hash,
            fuzz_seed=policy.fuzz_seed,
            test_kind=RepositoryTestKind.UNIT,
            status=RepositoryTestExecutionStatus.PASSED,
            duration_seconds=0.1,
            command_sha256=_hash(f"test-command-{index}"),
            output_sha256=_hash(f"test-output-{index}"),
            output_bytes=10,
            machine_result_sha256=_hash(f"test-result-{index}"),
            process_exit_code=0,
            machine_output_validated=True,
            execution_evidence=ExecutionEvidenceKind.REAL,
            repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
            isolation_backend=policy.isolation_backend,
            isolation_attestation_sha256=policy.isolation_attestation_sha256,
            compiler_version=policy.compiler_version,
            compiler_sha256=policy.compiler_sha256,
            execution_policy_sha256=policy.policy_sha256,
        )
        for index, descriptor in enumerate(selection.tests, start=1)
    )


def _scope(
    descriptor: RepositorySuiteTestDescriptor,
    selection: RepositorySuiteSelection,
    policy: RepositorySuiteExecutionPolicy,
    sequence_index: int,
) -> RepositoryTestForkRpcScopeEvidence:
    values = {
        "schema_version": "1.0",
        "attempt_binding_sha256": _hash("attempt-binding"),
        "selection_sha256": selection.selection_sha256,
        "descriptor_sha256": descriptor.descriptor_sha256,
        "sequence_index": sequence_index,
        "bridge_policy_sha256": _hash("bridge-policy"),
        "expected_chain_id": policy.chain_id,
        "pinned_block_number": policy.block_number,
        "pinned_block_hash": policy.block_hash,
        "status": RepositoryTestForkRpcScopeStatus.VALIDATED,
        "http_request_count": 1,
        "permitted_rpc_call_count": 1,
        "origin_attempted_rpc_call_count": 1,
        "origin_validated_rpc_call_count": 1,
        "synthetic_rpc_call_count": 0,
        "denied_request_count": 0,
        "malformed_request_count": 0,
        "limit_exceeded_request_count": 0,
        "upstream_error_request_count": 0,
        "allowed_method_counts": (ForkRpcMethodCount(method="eth_call", count=1),),
        "method_log_sha256": _hash(f"method-log-{sequence_index}"),
        "boundary_drained": True,
        "transaction_capable_request_forwarded": False,
        "credentials_forwarded": False,
        "raw_payloads_retained": False,
        "rpc_endpoint_recorded": False,
    }
    return RepositoryTestForkRpcScopeEvidence.sealed(
        **values,
        bridge_scope_snapshot_sha256=(
            RepositoryTestForkRpcScopeEvidence.calculate_bridge_scope_snapshot_sha256(values)
        ),
    )


def _debug_coverage(
    *, hit_count: int, include_statement: bool = True
) -> ForgeDebugStatementCoverage:
    unit = _compiler_unit()
    statement = unit.statements[0]
    records = [
        ForgeDebugStatementRecord(
            source_id=0,
            start_byte=0,
            end_byte=8,
            start_line=1,
            end_line=2,
            hits=99,
            item_ids=(1,),
        )
    ]
    if include_statement:
        records.append(
            ForgeDebugStatementRecord(
                source_id=statement.source_id,
                start_byte=statement.start_byte,
                end_byte=statement.end_byte_exclusive,
                start_line=statement.start_line,
                end_line=statement.end_line_exclusive,
                hits=hit_count,
                item_ids=(2,),
            )
        )
    return ForgeDebugStatementCoverage(
        machine_json_bytes=json.dumps(
            {"hit_count": hit_count},
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        statements=tuple(sorted(records)),
        uncovered_sources=(),
        anchored_item_count=len(records),
        descriptor_record_count=len(records),
    )


def _process(
    descriptor: RepositorySuiteTestDescriptor,
    sequence_index: int,
    debug_coverage: ForgeDebugStatementCoverage,
    machine_result_sha256: str,
) -> FoundryStatementCoverageProcessObservation:
    private_path = f"repository-suite/coverage/{sequence_index - 1:05d}"
    return FoundryStatementCoverageProcessObservation(
        sequence_index=sequence_index,
        descriptor_sha256=descriptor.descriptor_sha256,
        coverage_command_sha256=_hash(f"coverage-command-{sequence_index}"),
        process_exit_code=0,
        machine_output_validated=True,
        machine_result_sha256=machine_result_sha256,
        private_artifact_path=private_path,
        stdout_path=f"{private_path}/stdout.txt",
        stdout_sha256=_hash(f"coverage-stdout-{sequence_index}"),
        stdout_bytes=20,
        stderr_path=f"{private_path}/stderr.txt",
        stderr_sha256=_hash(f"coverage-stderr-{sequence_index}"),
        stderr_bytes=0,
        private_artifact_sha256=_hash(f"coverage-artifact-{sequence_index}"),
        private_artifact_bytes=100,
        duration_seconds=0.1,
        debug_coverage=debug_coverage,
    )


@dataclass(frozen=True)
class _Inputs:
    entity_catalog: AuditedSuiteEntityCatalog
    selection: RepositorySuiteSelection
    execution_policy: RepositorySuiteExecutionPolicy
    pre_inventory: RepositorySuiteInventoryEvidence
    post_inventory: RepositorySuiteInventoryEvidence
    pre_compiler_catalogs: tuple[FoundryCompilerStatementCatalog, ...]
    post_compiler_catalogs: tuple[FoundryCompilerStatementCatalog, ...]
    executions: tuple[RepositoryTestExecution, ...]
    processes: tuple[FoundryStatementCoverageProcessObservation, ...]
    fork_rpc_scopes: tuple[RepositoryTestForkRpcScopeEvidence, ...]
    producer_sha256: str = _PRODUCER_SHA256

    def kwargs(self) -> _ProducerKwargs:
        return {
            "entity_catalog": self.entity_catalog,
            "selection": self.selection,
            "execution_policy": self.execution_policy,
            "pre_inventory": self.pre_inventory,
            "post_inventory": self.post_inventory,
            "pre_compiler_catalogs": self.pre_compiler_catalogs,
            "post_compiler_catalogs": self.post_compiler_catalogs,
            "executions": self.executions,
            "processes": self.processes,
            "fork_rpc_scopes": self.fork_rpc_scopes,
            "producer_sha256": self.producer_sha256,
        }


class _ProducerKwargs(TypedDict):
    entity_catalog: AuditedSuiteEntityCatalog
    selection: RepositorySuiteSelection
    execution_policy: RepositorySuiteExecutionPolicy
    pre_inventory: RepositorySuiteInventoryEvidence
    post_inventory: RepositorySuiteInventoryEvidence
    pre_compiler_catalogs: tuple[FoundryCompilerStatementCatalog, ...]
    post_compiler_catalogs: tuple[FoundryCompilerStatementCatalog, ...]
    executions: tuple[RepositoryTestExecution, ...]
    processes: tuple[FoundryStatementCoverageProcessObservation, ...]
    fork_rpc_scopes: tuple[RepositoryTestForkRpcScopeEvidence, ...]
    producer_sha256: str


def _inputs(*, duplicate_unit: bool = False) -> _Inputs:
    pre_inventory = _inventory(
        RepositorySuiteInventoryPhase.PRE_EXECUTION,
        duplicate_unit=duplicate_unit,
    )
    post_inventory = _inventory(
        RepositorySuiteInventoryPhase.POST_EXECUTION,
        duplicate_unit=duplicate_unit,
    )
    selection = _selection(pre_inventory)
    policy = _policy(selection)
    executions = _executions(selection, policy, pre_inventory, post_inventory)
    processes = tuple(
        _process(
            descriptor,
            index,
            _debug_coverage(hit_count=0 if index == 1 else 5),
            execution.machine_result_sha256 or "",
        )
        for index, (descriptor, execution) in enumerate(
            zip(selection.tests, executions, strict=True),
            start=1,
        )
    )
    scopes = tuple(
        _scope(descriptor, selection, policy, index)
        for index, descriptor in enumerate(selection.tests, start=1)
    )
    catalog = _compiler_catalog(duplicate_unit=duplicate_unit)
    return _Inputs(
        entity_catalog=_entity_catalog(),
        selection=selection,
        execution_policy=policy,
        pre_inventory=pre_inventory,
        post_inventory=post_inventory,
        pre_compiler_catalogs=(catalog,),
        post_compiler_catalogs=(catalog,),
        executions=executions,
        processes=processes,
        fork_rpc_scopes=scopes,
    )


def test_producer_emits_shared_receipt_exact_projections_and_or_coverage() -> None:
    inputs = _inputs()

    produced = produce_foundry_statement_coverage(**inputs.kwargs())

    assert produced.receipt.producer_version == FOUNDRY_STATEMENT_COVERAGE_PRODUCER_VERSION
    assert (
        produced.receipt.normalizer_policy_sha256
        == FOUNDRY_STATEMENT_COVERAGE_NORMALIZER_POLICY_SHA256
    )
    assert produced.receipt.compiler_statement_count == 1
    assert produced.receipt.compiler_statements[0].covered is True
    physical_id = produced.receipt.compiler_statements[0].physical_statement_id
    assert produced.receipt.entity_statement_ids == {
        "entity-contract-vault": [physical_id],
        "entity-function-set": [physical_id],
    }
    assert [item.entity_id for item in produced.evidence] == [
        "entity-contract-vault",
        "entity-function-set",
    ]
    assert all(item.schema_version == "1.2" for item in produced.evidence)
    assert all(
        item.coverage_receipt_sha256 == produced.receipt.receipt_sha256
        and item.statement_status is AuditedSuiteStatementStatus.COVERED
        and item.statement_count == 1
        and item.covered_statement_count == 1
        for item in produced.evidence
    )
    assert all(
        statement.start_byte_offset != 0
        for evidence in produced.evidence
        for statement in evidence.statements
    ), "the covered debug extra must never receive compiler statement credit"
    assert [process.fork_rpc_scope_evidence_sha256 for process in produced.receipt.processes] == [
        scope.evidence_sha256 for scope in inputs.fork_rpc_scopes
    ]


def test_v12_scanner_run_round_trip_and_receipt_hash_tampering() -> None:
    inputs = _inputs()
    produced = produce_foundry_statement_coverage(**inputs.kwargs())
    now = datetime(2026, 9, 2, tzinfo=UTC)
    workspace_copy = RepositorySuiteWorkspaceCopyEvidence.sealed(
        attempt_binding_sha256=_hash("attempt-binding"),
        selection_sha256=inputs.selection.selection_sha256,
        repository_sha256=inputs.selection.repository_sha256,
        source_inventory_sha256_before=inputs.selection.repository_sha256,
        source_inventory_sha256_after=inputs.selection.repository_sha256,
        workspace_inventory_sha256_after_copy=inputs.selection.repository_sha256,
        workspace_inventory_sha256_after_execution=inputs.selection.repository_sha256,
        source_root_device_before=1,
        source_root_inode_before=2,
        source_root_device_after=1,
        source_root_inode_after=2,
        workspace_root_device_before=1,
        workspace_root_inode_before=3,
        workspace_root_device_after=1,
        workspace_root_inode_after=3,
        workspace_parent_device=1,
        workspace_parent_inode=4,
    )
    provisional = ScannerRun(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version=inputs.execution_policy.tool_version,
        executable_sha256=inputs.execution_policy.tool_sha256,
        command=["forge", "test", "--offline"],
        started_at=now,
        finished_at=now,
        duration_seconds=0.2,
        raw_output_path="repository-suite-execution.json",
        raw_output_sha256=_hash("repository-suite-manifest"),
        raw_output_bytes=10,
        process_exit_code=0,
        machine_output_validated=True,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend=inputs.execution_policy.isolation_backend,
        isolation_attestation_sha256=inputs.execution_policy.isolation_attestation_sha256,
        foundry_summary=FoundryTestExecutionSummary(
            unit_tests=2,
            fuzz_tests=0,
            invariant_tests=0,
            passed_tests=2,
            failed_tests=0,
            skipped_tests=0,
            fuzz_cases=0,
            invariant_runs=0,
            invariant_calls=0,
        ),
        repository_suite_selection=inputs.selection,
        repository_suite_inventory=inputs.pre_inventory,
        repository_suite_post_inventory=inputs.post_inventory,
        repository_suite_execution_policy=inputs.execution_policy,
        repository_suite_workspace_copy=workspace_copy,
        repository_test_executions=list(inputs.executions),
        repository_test_fork_rpc_scopes=list(inputs.fork_rpc_scopes),
        repository_statement_entity_catalog=inputs.entity_catalog,
        repository_statement_coverage_receipt=produced.receipt,
        repository_statement_coverage_evidence=list(produced.evidence),
    )
    run = ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": provisional.expected_execution_observation_sha256(),
        }
    )

    restored = ScannerRun.model_validate_json(run.model_dump_json())
    assert restored.repository_statement_entity_catalog == inputs.entity_catalog
    assert restored.repository_statement_coverage_receipt == produced.receipt
    assert restored.repository_statement_coverage_evidence == list(produced.evidence)

    tampered = run.model_dump(mode="json")
    receipt_payload = tampered["repository_statement_coverage_receipt"]
    assert isinstance(receipt_payload, dict)
    receipt_payload["receipt_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="receipt hash does not match"):
        ScannerRun.model_validate(tampered)


def test_producer_rejects_missing_atomic_compiler_statement_in_every_process() -> None:
    inputs = _inputs()
    processes = tuple(
        _process(
            descriptor,
            index,
            _debug_coverage(hit_count=0, include_statement=False),
            execution.machine_result_sha256 or "",
        )
        for index, (descriptor, execution) in enumerate(
            zip(inputs.selection.tests, inputs.executions, strict=True),
            start=1,
        )
    )

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="lacks an exact Forge debug span",
    ):
        produce_foundry_statement_coverage(**replace(inputs, processes=processes).kwargs())


def test_producer_rejects_debug_population_change_within_project() -> None:
    inputs = _inputs()
    second_debug = _debug_coverage(hit_count=5, include_statement=False)
    processes = (
        inputs.processes[0],
        _process(
            inputs.selection.tests[1],
            2,
            second_debug,
            inputs.executions[1].machine_result_sha256 or "",
        ),
    )

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="population changed",
    ):
        produce_foundry_statement_coverage(**replace(inputs, processes=processes).kwargs())


def test_producer_rejects_ambiguous_compiler_build_units() -> None:
    inputs = _inputs(duplicate_unit=True)

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="exactly one compiler AST/build unit",
    ):
        produce_foundry_statement_coverage(**inputs.kwargs())


def test_producer_rejects_changed_post_execution_compiler_catalog() -> None:
    inputs = _inputs()
    changed_unit = replace(
        _compiler_unit(),
        statements=(),
    )
    changed_catalog = replace(_compiler_catalog(), units=(changed_unit,))

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="pre/post compiler statement catalogs are not identical",
    ):
        produce_foundry_statement_coverage(
            **replace(inputs, post_compiler_catalogs=(changed_catalog,)).kwargs()
        )


def test_producer_rejects_scope_that_does_not_match_process_sequence() -> None:
    inputs = _inputs()

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="validated fork RPC scope",
    ):
        produce_foundry_statement_coverage(
            **replace(
                inputs,
                fork_rpc_scopes=tuple(reversed(inputs.fork_rpc_scopes)),
            ).kwargs()
        )


def test_producer_recomputes_entity_line_range_hash_from_compiler_source() -> None:
    inputs = _inputs()
    binding = inputs.entity_catalog.bindings[0]
    binding_payload = binding.model_dump(mode="python", exclude={"binding_sha256"})
    binding_payload["location"] = binding.location.model_copy(
        update={"content_hash": _hash("unrelated-entity-lines")}
    )
    changed_binding = AuditedSuiteEntityCatalogBinding.sealed(**binding_payload)
    changed_catalog = AuditedSuiteEntityCatalog.sealed(
        repository_sha256=inputs.entity_catalog.repository_sha256,
        classification_complete=True,
        classification_limitations=[],
        bindings=sorted(
            [changed_binding, inputs.entity_catalog.bindings[1]],
            key=lambda item: (item.entity_id, item.binding_sha256),
        ),
    )

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="line-range hash differs",
    ):
        produce_foundry_statement_coverage(
            **replace(inputs, entity_catalog=changed_catalog).kwargs()
        )


def test_producer_requires_coverage_semantics_to_match_paired_execution() -> None:
    inputs = _inputs()
    changed_process = _process(
        inputs.selection.tests[0],
        1,
        inputs.processes[0].debug_coverage,
        _hash("different-semantic-result"),
    )

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="differs from selected test execution",
    ):
        produce_foundry_statement_coverage(
            **replace(
                inputs,
                processes=(changed_process, inputs.processes[1]),
            ).kwargs()
        )


def test_producer_preserves_contract_owned_statement_without_function_ast_id() -> None:
    inputs = _inputs()
    unit = _compiler_unit()
    modifier_owned = FoundryCompilerStatement(
        compiler_ast_id=4,
        enclosing_inline_assembly_ast_id=None,
        node_type="ExpressionStatement",
        enclosing_contract_ast_id=1,
        enclosing_function_ast_id=None,
        source_id=0,
        path="src/Vault.sol",
        source_sha256=_SOURCE_SHA256,
        start_byte=0,
        end_byte_exclusive=8,
        start_line=1,
        end_line_exclusive=2,
    )
    changed_unit = replace(unit, statements=(modifier_owned, *unit.statements))
    changed_catalog = replace(_compiler_catalog(), units=(changed_unit,))

    produced = produce_foundry_statement_coverage(
        **replace(
            inputs,
            pre_compiler_catalogs=(changed_catalog,),
            post_compiler_catalogs=(changed_catalog,),
        ).kwargs()
    )

    records = produced.receipt.compiler_statements
    assert len(records) == 2
    modifier_record = next(record for record in records if record.start_byte_offset == 0)
    assert modifier_record.enclosing_function_ast_id is None
    assert len(produced.receipt.entity_statement_ids["entity-contract-vault"]) == 2
    assert len(produced.receipt.entity_statement_ids["entity-function-set"]) == 1


def test_producer_rejects_nonatomic_compiler_statement_node() -> None:
    inputs = _inputs()
    unit = _compiler_unit()
    changed_statement = replace(unit.statements[0], node_type="IfStatement")
    changed_unit = replace(unit, statements=(changed_statement,))
    changed_catalog = replace(_compiler_catalog(), units=(changed_unit,))

    with pytest.raises(
        FoundryStatementCoverageProductionError,
        match="invalid AST/source custody",
    ):
        produce_foundry_statement_coverage(
            **replace(
                inputs,
                pre_compiler_catalogs=(changed_catalog,),
                post_compiler_catalogs=(changed_catalog,),
            ).kwargs()
        )
