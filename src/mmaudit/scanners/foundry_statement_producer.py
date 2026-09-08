"""Compiler-exact audited-suite statement coverage production.

This module is deliberately pure.  Callers supply already validated compiler
inventories, selected-test executions, and parsed Forge debug output.  The
producer only grants statement credit after reconciling those independent
identities without source-line or name-only fallbacks.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from mmaudit.models.schemas import (
    AUDITED_SUITE_STATEMENT_OBSERVATION_LIMIT,
    AuditedSuiteCompilerStatementRecord,
    AuditedSuiteEntityCatalog,
    AuditedSuiteEntityCatalogBinding,
    AuditedSuiteStatementCoverageEvidence,
    AuditedSuiteStatementCoverageProcessReceipt,
    AuditedSuiteStatementCoverageReceipt,
    AuditedSuiteStatementObservation,
    AuditedSuiteStatementStatus,
    ExecutionEvidenceKind,
    Location,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteInventoryEvidence,
    RepositorySuiteInventoryKind,
    RepositorySuiteInventoryPhase,
    RepositorySuiteSelection,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestForkRpcScopeEvidence,
    RepositoryTestForkRpcScopeStatus,
    SolidityEntityKind,
    SolidityProvenance,
    validated_repository_statement_coverage_evidence,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.scanners.foundry_inventory import (
    FoundryCompilerBuildUnit,
    FoundryCompilerEntity,
    FoundryCompilerStatement,
    FoundryCompilerStatementCatalog,
)
from mmaudit.scanners.foundry_statement_coverage import ForgeDebugStatementCoverage

FOUNDRY_STATEMENT_COVERAGE_PRODUCER_VERSION = "1.0.0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTRACT_ENTITY_KINDS = frozenset(
    {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.INTERFACE,
        SolidityEntityKind.LIBRARY,
    }
)
_FUNCTION_ENTITY_KINDS = frozenset(
    {
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
    }
)
_ATOMIC_STATEMENT_NODE_TYPES = frozenset(
    {
        "Break",
        "Continue",
        "EmitStatement",
        "ExpressionStatement",
        "PlaceholderStatement",
        "Return",
        "RevertStatement",
        "Throw",
        "VariableDeclarationStatement",
        "YulAssignment",
        "YulBreak",
        "YulContinue",
        "YulExpressionStatement",
        "YulLeave",
        "YulVariableDeclaration",
    }
)
_NORMALIZER_POLICY = {
    "compiler_denominator": "nonoverlapping_atomic_solidity_and_yul_ast_leaves",
    "coverage_aggregation": "boolean_or_across_exact_selected_tests_in_project",
    "debug_extras": "ignored_without_credit",
    "debug_population": "identical_within_project_across_selected_test_processes",
    "empty_inventory": "vacuously_covered_exact_empty_inventory",
    "entity_binding": "exact_compiler_ast_source_hash_byte_line_kind_name_contract",
    "physical_statement_identity": "repository_path_source_sha256_half_open_byte_span",
    "process_cardinality": "one_successful_debug_process_per_selected_test",
    "process_custody": "exact_private_tree_stream_paths_and_validated_fork_rpc_scope",
    "schema_version": "1.0",
    "uncovered_source_bindings": "identical_within_project_and_compiler_exact_when_present",
}


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


FOUNDRY_STATEMENT_COVERAGE_NORMALIZER_POLICY_SHA256 = _canonical_sha256(_NORMALIZER_POLICY)


class FoundryStatementCoverageProductionError(ValueError):
    """Raised when exact compiler/debug evidence cannot support coverage credit."""


@dataclass(frozen=True, slots=True)
class FoundryStatementCoverageProcessObservation:
    """Bounded host custody and parsed output from one exact coverage process."""

    sequence_index: int
    descriptor_sha256: str
    coverage_command_sha256: str
    process_exit_code: int
    machine_output_validated: bool
    machine_result_sha256: str
    private_artifact_path: str
    stdout_path: str
    stdout_sha256: str
    stdout_bytes: int
    stderr_path: str
    stderr_sha256: str
    stderr_bytes: int
    private_artifact_sha256: str
    private_artifact_bytes: int
    duration_seconds: float
    debug_coverage: ForgeDebugStatementCoverage

    def __post_init__(self) -> None:
        if type(self.sequence_index) is not int or not 1 <= self.sequence_index <= 10_000:
            raise FoundryStatementCoverageProductionError(
                "coverage process sequence index is invalid"
            )
        for value, label in (
            (self.descriptor_sha256, "descriptor"),
            (self.coverage_command_sha256, "coverage command"),
            (self.machine_result_sha256, "machine result"),
            (self.stdout_sha256, "stdout"),
            (self.stderr_sha256, "stderr"),
            (self.private_artifact_sha256, "private artifact"),
        ):
            _require_sha256(value, label)
        if type(self.process_exit_code) is not int or self.process_exit_code != 0:
            raise FoundryStatementCoverageProductionError(
                "coverage process must have an exact zero exit code"
            )
        if self.machine_output_validated is not True:
            raise FoundryStatementCoverageProductionError(
                "coverage process must have validated machine output"
            )
        expected_private_path = f"repository-suite/coverage/{self.sequence_index - 1:05d}"
        if (
            self.private_artifact_path != expected_private_path
            or self.stdout_path != f"{expected_private_path}/stdout.txt"
            or self.stderr_path != f"{expected_private_path}/stderr.txt"
        ):
            raise FoundryStatementCoverageProductionError(
                "coverage process paths differ from its exact private artifact tree"
            )
        for byte_count, byte_label, minimum in (
            (self.stdout_bytes, "stdout bytes", 1),
            (self.stderr_bytes, "stderr bytes", 0),
            (self.private_artifact_bytes, "private artifact bytes", 1),
        ):
            if type(byte_count) is not int or not minimum <= byte_count <= 1_000_000_000:
                raise FoundryStatementCoverageProductionError(
                    f"coverage process {byte_label} are invalid"
                )
        if self.stdout_bytes + self.stderr_bytes > self.private_artifact_bytes:
            raise FoundryStatementCoverageProductionError(
                "coverage process streams exceed private artifact custody"
            )
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or not math.isfinite(float(self.duration_seconds))
            or not 0 < float(self.duration_seconds) <= 86_400
        ):
            raise FoundryStatementCoverageProductionError("coverage process duration is invalid")
        if type(self.debug_coverage) is not ForgeDebugStatementCoverage:
            raise FoundryStatementCoverageProductionError(
                "coverage process lacks an exact parsed debug result"
            )


@dataclass(frozen=True, slots=True)
class FoundryStatementCoverageProduction:
    """One shared statement receipt and its complete entity projections."""

    receipt: AuditedSuiteStatementCoverageReceipt
    evidence: tuple[AuditedSuiteStatementCoverageEvidence, ...]

    def __post_init__(self) -> None:
        if type(self.receipt) is not AuditedSuiteStatementCoverageReceipt:
            raise FoundryStatementCoverageProductionError(
                "statement production receipt is not schema validated"
            )
        if type(self.evidence) is not tuple or any(
            type(item) is not AuditedSuiteStatementCoverageEvidence for item in self.evidence
        ):
            raise FoundryStatementCoverageProductionError(
                "statement production evidence is not an exact immutable population"
            )


@dataclass(frozen=True, slots=True)
class _MappedEntity:
    binding: AuditedSuiteEntityCatalogBinding
    project_root: str
    unit: FoundryCompilerBuildUnit
    compiler_entity: FoundryCompilerEntity
    statements: tuple[FoundryCompilerStatement, ...]


@dataclass(frozen=True, slots=True)
class _PhysicalStatement:
    project_root: str
    repository_path: str
    unit: FoundryCompilerBuildUnit
    statement: FoundryCompilerStatement

    @property
    def source_key(self) -> tuple[str, str, int, int]:
        return (
            self.repository_path,
            self.statement.source_sha256,
            self.statement.start_byte,
            self.statement.end_byte_exclusive,
        )

    @property
    def debug_identity(self) -> tuple[int, int, int, int, int]:
        return (
            self.statement.source_id,
            self.statement.start_byte,
            self.statement.end_byte_exclusive,
            self.statement.start_line,
            self.statement.end_line_exclusive,
        )


def produce_foundry_statement_coverage(
    *,
    entity_catalog: AuditedSuiteEntityCatalog,
    selection: RepositorySuiteSelection,
    execution_policy: RepositorySuiteExecutionPolicy,
    pre_inventory: RepositorySuiteInventoryEvidence,
    post_inventory: RepositorySuiteInventoryEvidence,
    pre_compiler_catalogs: Sequence[FoundryCompilerStatementCatalog],
    post_compiler_catalogs: Sequence[FoundryCompilerStatementCatalog],
    executions: Sequence[RepositoryTestExecution],
    processes: Sequence[FoundryStatementCoverageProcessObservation],
    fork_rpc_scopes: Sequence[RepositoryTestForkRpcScopeEvidence],
    producer_sha256: str,
) -> FoundryStatementCoverageProduction:
    """Produce compiler-exact v1.2 statement evidence or fail without partial credit."""

    _require_sha256(producer_sha256, "producer")
    catalog = _canonical_model(entity_catalog, AuditedSuiteEntityCatalog, "entity catalog")
    selected = _canonical_model(selection, RepositorySuiteSelection, "suite selection")
    policy = _canonical_model(
        execution_policy,
        RepositorySuiteExecutionPolicy,
        "suite execution policy",
    )
    before = _canonical_model(
        pre_inventory,
        RepositorySuiteInventoryEvidence,
        "pre-execution inventory",
    )
    after = _canonical_model(
        post_inventory,
        RepositorySuiteInventoryEvidence,
        "post-execution inventory",
    )
    if not catalog.classification_complete or catalog.classification_limitations:
        raise FoundryStatementCoverageProductionError(
            "statement coverage requires a complete audited entity catalog"
        )
    if not catalog.bindings:
        raise FoundryStatementCoverageProductionError(
            "statement coverage cannot emit an orphan receipt for an empty entity catalog"
        )
    _reconcile_run_authority(catalog, selected, policy, before, after)

    pre_catalog_map = _validated_compiler_catalogs(
        pre_compiler_catalogs,
        inventory=before,
        policy=policy,
        label="pre-execution",
    )
    post_catalog_map = _validated_compiler_catalogs(
        post_compiler_catalogs,
        inventory=after,
        policy=policy,
        label="post-execution",
    )
    if pre_catalog_map != post_catalog_map:
        raise FoundryStatementCoverageProductionError(
            "pre/post compiler statement catalogs are not identical"
        )

    canonical_executions = _validated_executions(
        executions,
        selection=selected,
        policy=policy,
        pre_inventory=before,
        post_inventory=after,
    )
    canonical_processes = _validated_processes(processes, selected, canonical_executions)
    canonical_scopes = _validated_fork_rpc_scopes(
        fork_rpc_scopes,
        selection=selected,
        policy=policy,
    )
    processes_by_project = _processes_by_project(canonical_processes, selected)

    mapped_entities = tuple(_map_entity(binding, pre_catalog_map) for binding in catalog.bindings)
    mapped_compiler_entities = [
        (
            mapped.project_root,
            mapped.unit.normalized_build_info_sha256,
            mapped.compiler_entity.compiler_ast_id,
        )
        for mapped in mapped_entities
    ]
    if len(mapped_compiler_entities) != len(set(mapped_compiler_entities)):
        raise FoundryStatementCoverageProductionError(
            "audited entity bindings do not map one-to-one to compiler AST entities"
        )
    audited_projects = {mapped.project_root for mapped in mapped_entities}
    missing_process_projects = sorted(audited_projects - set(processes_by_project))
    if missing_process_projects:
        raise FoundryStatementCoverageProductionError(
            "audited compiler projects lack selected coverage processes: "
            f"{missing_process_projects!r}"
        )

    physical_by_source: dict[tuple[str, str, int, int], _PhysicalStatement] = {}
    entity_source_keys: dict[str, tuple[tuple[str, str, int, int], ...]] = {}
    for mapped in mapped_entities:
        keys: list[tuple[str, str, int, int]] = []
        for statement in mapped.statements:
            physical = _PhysicalStatement(
                project_root=mapped.project_root,
                repository_path=mapped.binding.location.path,
                unit=mapped.unit,
                statement=statement,
            )
            prior = physical_by_source.get(physical.source_key)
            if prior is not None and prior != physical:
                raise FoundryStatementCoverageProductionError(
                    "one physical statement resolves to conflicting compiler identities"
                )
            physical_by_source[physical.source_key] = physical
            keys.append(physical.source_key)
        entity_source_keys[mapped.binding.entity_id] = tuple(sorted(set(keys)))

    coverage_by_source = _aggregate_coverage(
        physical_by_source,
        catalogs=pre_catalog_map,
        processes_by_project=processes_by_project,
    )
    compiler_records = tuple(
        sorted(
            (
                _compiler_statement_record(physical, covered=coverage_by_source[source_key])
                for source_key, physical in physical_by_source.items()
            ),
            key=lambda item: (
                item.path,
                item.start_byte_offset,
                item.end_byte_offset,
                item.physical_statement_id,
                item.record_sha256,
            ),
        )
    )
    records_by_source = {
        (
            record.path,
            record.source_file_sha256,
            record.start_byte_offset,
            record.end_byte_offset,
        ): record
        for record in compiler_records
    }
    entity_statement_ids = {
        entity_id: sorted(
            records_by_source[source_key].physical_statement_id for source_key in source_keys
        )
        for entity_id, source_keys in sorted(entity_source_keys.items())
    }
    process_receipts = tuple(
        _process_receipt(process, execution, scope)
        for process, execution, scope in zip(
            canonical_processes,
            canonical_executions,
            canonical_scopes,
            strict=True,
        )
    )
    statement_inventory_sha256 = _canonical_sha256(
        [
            record.model_dump(mode="json", exclude={"covered", "record_sha256"})
            for record in compiler_records
        ]
    )
    artifact_payload = [
        {
            "sequence_index": process.sequence_index,
            "private_artifact_path": process.private_artifact_path,
            "stdout_path": process.stdout_path,
            "stdout_sha256": process.stdout_sha256,
            "stdout_bytes": process.stdout_bytes,
            "stderr_path": process.stderr_path,
            "stderr_sha256": process.stderr_sha256,
            "stderr_bytes": process.stderr_bytes,
            "private_artifact_sha256": process.private_artifact_sha256,
            "private_artifact_bytes": process.private_artifact_bytes,
        }
        for process in process_receipts
    ]
    receipt = AuditedSuiteStatementCoverageReceipt.sealed(
        source_repository_sha256=selected.repository_sha256,
        repository_suite_selection_sha256=selected.selection_sha256,
        repository_suite_execution_policy_sha256=policy.policy_sha256,
        pre_inventory_sha256=before.inventory_sha256,
        post_inventory_sha256=after.inventory_sha256,
        entity_catalog_sha256=catalog.catalog_sha256,
        repository_test_execution_sha256s=sorted(
            execution.execution_sha256 for execution in canonical_executions
        ),
        processes=list(process_receipts),
        compiler_statements=list(compiler_records),
        entity_statement_ids=entity_statement_ids,
        compiler_statement_count=len(compiler_records),
        statement_inventory_sha256=statement_inventory_sha256,
        coverage_artifact_sha256=_canonical_sha256(artifact_payload),
        coverage_artifact_bytes=sum(process.private_artifact_bytes for process in process_receipts),
        producer_version=FOUNDRY_STATEMENT_COVERAGE_PRODUCER_VERSION,
        producer_sha256=producer_sha256,
        normalizer_policy_sha256=(FOUNDRY_STATEMENT_COVERAGE_NORMALIZER_POLICY_SHA256),
        tool_version=policy.tool_version,
        tool_sha256=policy.tool_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
    )
    evidence = tuple(
        _entity_evidence(
            mapped,
            receipt=receipt,
            records_by_source=records_by_source,
            source_keys=entity_source_keys[mapped.binding.entity_id],
        )
        for mapped in mapped_entities
    )
    validated = validated_repository_statement_coverage_evidence(
        evidence,
        receipt=receipt,
        selection=selected,
        execution_policy=policy,
        executions=canonical_executions,
        tool_version=policy.tool_version,
        tool_sha256=policy.tool_sha256,
        isolation_attestation_sha256=policy.isolation_attestation_sha256,
        fork_rpc_scopes=canonical_scopes,
        pre_inventory=before,
        post_inventory=after,
        entity_catalog=catalog,
        entity_catalog_sha256=catalog.catalog_sha256,
    )
    return FoundryStatementCoverageProduction(receipt=receipt, evidence=tuple(validated))


def _canonical_model[T: BaseModel](value: object, model_type: type[T], label: str) -> T:
    if type(value) is not model_type:
        raise FoundryStatementCoverageProductionError(f"{label} has the wrong typed schema")
    assert isinstance(value, model_type)
    try:
        canonical = model_type.model_validate(value.model_dump(mode="json"))
    except (TypeError, ValueError) as exc:
        raise FoundryStatementCoverageProductionError(
            f"{label} failed canonical schema validation"
        ) from exc
    if canonical != value:
        raise FoundryStatementCoverageProductionError(
            f"{label} differs after canonical schema validation"
        )
    return canonical


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None or value == "0" * 64:
        raise FoundryStatementCoverageProductionError(f"{label} SHA-256 is invalid")
    return value


def _reconcile_run_authority(
    catalog: AuditedSuiteEntityCatalog,
    selection: RepositorySuiteSelection,
    policy: RepositorySuiteExecutionPolicy,
    pre_inventory: RepositorySuiteInventoryEvidence,
    post_inventory: RepositorySuiteInventoryEvidence,
) -> None:
    if (
        catalog.repository_sha256 != selection.repository_sha256
        or policy.selection_sha256 != selection.selection_sha256
        or policy.selection_configuration_sha256 != selection.configuration_sha256
        or selection.inventory_kind is not RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO
        or selection.inventory_sha256 != pre_inventory.normalized_inventory_sha256
        or pre_inventory.configuration_sha256 != selection.configuration_sha256
        or selection.selected_test_count < 1
    ):
        raise FoundryStatementCoverageProductionError(
            "entity catalog, compiler selection, and execution policy differ"
        )
    if (
        pre_inventory.phase is not RepositorySuiteInventoryPhase.PRE_EXECUTION
        or post_inventory.phase is not RepositorySuiteInventoryPhase.POST_EXECUTION
        or pre_inventory.repository_sha256 != selection.repository_sha256
        or post_inventory.repository_sha256 != selection.repository_sha256
        or pre_inventory.configuration_sha256 != post_inventory.configuration_sha256
        or pre_inventory.normalized_inventory_sha256 != post_inventory.normalized_inventory_sha256
        or pre_inventory.execution_evidence is not ExecutionEvidenceKind.REAL
        or post_inventory.execution_evidence is not ExecutionEvidenceKind.REAL
    ):
        raise FoundryStatementCoverageProductionError(
            "pre/post compiler inventory authority is incomplete or changed"
        )
    for inventory in (pre_inventory, post_inventory):
        if (
            inventory.tool_version != policy.tool_version
            or inventory.tool_sha256 != policy.tool_sha256
            or inventory.compiler_version != policy.compiler_version
            or inventory.compiler_sha256 != policy.compiler_sha256
            or inventory.isolation_backend != policy.isolation_backend
            or inventory.isolation_attestation_sha256 != policy.isolation_attestation_sha256
        ):
            raise FoundryStatementCoverageProductionError(
                "compiler inventory identity differs from execution policy"
            )


def _validated_compiler_catalogs(
    catalogs: Sequence[FoundryCompilerStatementCatalog],
    *,
    inventory: RepositorySuiteInventoryEvidence,
    policy: RepositorySuiteExecutionPolicy,
    label: str,
) -> dict[str, FoundryCompilerStatementCatalog]:
    if isinstance(catalogs, (str, bytes)) or not isinstance(catalogs, Sequence):
        raise FoundryStatementCoverageProductionError(
            f"{label} compiler catalogs are not a bounded sequence"
        )
    if not catalogs or len(catalogs) > 1_000:
        raise FoundryStatementCoverageProductionError(f"{label} compiler catalog count is invalid")
    result: dict[str, FoundryCompilerStatementCatalog] = {}
    inventory_projects = {project.project_root: project for project in inventory.projects}
    for catalog in catalogs:
        if type(catalog) is not FoundryCompilerStatementCatalog:
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler catalog has the wrong type"
            )
        if catalog.project_root in result:
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler catalogs duplicate a project root"
            )
        if (
            catalog.compiler_version != policy.compiler_version
            or catalog.compiler_sha256 != policy.compiler_sha256
        ):
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler catalog differs from pinned compiler"
            )
        project_evidence = inventory_projects.get(catalog.project_root)
        if project_evidence is None:
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler catalog lacks inventory project custody"
            )
        _validate_catalog_structure(catalog, label)
        unit_hashes = {unit.normalized_build_info_sha256 for unit in catalog.units}
        artifact_hashes = {
            artifact.normalized_sha256 for artifact in project_evidence.build_info_artifacts
        }
        if unit_hashes != artifact_hashes:
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler catalog differs from normalized build artifacts"
            )
        result[catalog.project_root] = catalog
    if set(result) != set(inventory_projects):
        raise FoundryStatementCoverageProductionError(
            f"{label} compiler catalogs do not cover the exact inventory projects"
        )
    return dict(sorted(result.items()))


def _validate_catalog_structure(
    catalog: FoundryCompilerStatementCatalog,
    label: str,
) -> None:
    if not catalog.units or tuple(
        unit.normalized_build_info_sha256 for unit in catalog.units
    ) != tuple(sorted({unit.normalized_build_info_sha256 for unit in catalog.units})):
        raise FoundryStatementCoverageProductionError(
            f"{label} compiler build units are empty, duplicated, or noncanonical"
        )
    for unit in catalog.units:
        _require_sha256(unit.normalized_build_info_sha256, "normalized build info")
        if (
            unit.project_root != catalog.project_root
            or unit.compiler_version != catalog.compiler_version
            or unit.compiler_sha256 != catalog.compiler_sha256
        ):
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler build-unit identity differs from its catalog"
            )
        source_ids = tuple(source.source_id for source in unit.sources)
        source_paths = tuple(source.path for source in unit.sources)
        if (
            not unit.sources
            or source_ids != tuple(sorted(set(source_ids)))
            or len(source_paths) != len(set(source_paths))
            or unit.source_id_to_path
            != tuple((source.source_id, source.path) for source in unit.sources)
        ):
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler build-unit source map is noncanonical"
            )
        sources = {source.source_id: source for source in unit.sources}
        sources_by_path = {source.path: source for source in unit.sources}
        for source in unit.sources:
            _require_sha256(source.source_sha256, "compiler source")
            if type(source.content) is not bytes or (
                hashlib.sha256(source.content).hexdigest() != source.source_sha256
            ):
                raise FoundryStatementCoverageProductionError(
                    f"{label} compiler source bytes differ from their digest"
                )
        entity_keys = tuple(
            (
                entity.path,
                entity.start_byte,
                entity.end_byte_exclusive,
                entity.node_type,
                entity.compiler_ast_id,
            )
            for entity in unit.entities
        )
        if entity_keys != tuple(sorted(set(entity_keys))) or len(
            {entity.compiler_ast_id for entity in unit.entities}
        ) != len(unit.entities):
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler entities are duplicated or noncanonical"
            )
        entities_by_id = {entity.compiler_ast_id: entity for entity in unit.entities}
        for entity in unit.entities:
            entity_source = sources.get(entity.source_id)
            if entity.node_type == "ContractDefinition":
                entity_identity_valid = (
                    entity.kind in {"contract", "interface", "library"}
                    and bool(entity.name)
                    and entity.enclosing_contract_ast_id is None
                    and entity.enclosing_contract_name is None
                )
            elif entity.node_type == "FunctionDefinition":
                enclosing_contract = (
                    entities_by_id.get(entity.enclosing_contract_ast_id)
                    if entity.enclosing_contract_ast_id is not None
                    else None
                )
                if entity.kind == "freeFunction":
                    entity_identity_valid = (
                        bool(entity.name)
                        and entity.enclosing_contract_ast_id is None
                        and entity.enclosing_contract_name is None
                    )
                else:
                    entity_identity_valid = (
                        entity.kind in {"constructor", "fallback", "function", "receive"}
                        and enclosing_contract is not None
                        and enclosing_contract.node_type == "ContractDefinition"
                        and entity.enclosing_contract_name == enclosing_contract.name
                        and (
                            (entity.kind == "function" and bool(entity.name))
                            or (entity.kind != "function" and not entity.name)
                        )
                    )
            else:
                entity_identity_valid = False
            if (
                entity_source is None
                or entity_source.path != entity.path
                or entity_source.source_sha256 != entity.source_sha256
                or sources_by_path.get(entity.path) != entity_source
                or not entity_identity_valid
                or entity.end_byte_exclusive <= entity.start_byte
                or entity.end_line_exclusive <= entity.start_line
                or entity.end_byte_exclusive > len(entity_source.content)
            ):
                raise FoundryStatementCoverageProductionError(
                    f"{label} compiler entity has invalid source custody"
                )
        statement_keys = tuple(
            (
                statement.path,
                statement.start_byte,
                statement.end_byte_exclusive,
                statement.node_type,
                -1 if statement.compiler_ast_id is None else statement.compiler_ast_id,
            )
            for statement in unit.statements
        )
        if statement_keys != tuple(sorted(set(statement_keys))):
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler statements are duplicated or noncanonical"
            )
        solidity_statement_ast_ids = [
            statement.compiler_ast_id
            for statement in unit.statements
            if statement.compiler_ast_id is not None
        ]
        if len(solidity_statement_ast_ids) != len(set(solidity_statement_ast_ids)) or set(
            solidity_statement_ast_ids
        ) & set(entities_by_id):
            raise FoundryStatementCoverageProductionError(
                f"{label} compiler Solidity AST identities are duplicated"
            )
        previous_by_path: dict[str, FoundryCompilerStatement] = {}
        for statement in unit.statements:
            statement_source = sources.get(statement.source_id)
            contract = (
                entities_by_id.get(statement.enclosing_contract_ast_id)
                if statement.enclosing_contract_ast_id is not None
                else None
            )
            function = (
                entities_by_id.get(statement.enclosing_function_ast_id)
                if statement.enclosing_function_ast_id is not None
                else None
            )
            yul = statement.node_type.startswith("Yul")
            contract_owned = (
                contract is not None
                and contract.node_type == "ContractDefinition"
                and (
                    function is None
                    or (
                        function.node_type == "FunctionDefinition"
                        and function.enclosing_contract_ast_id
                        == statement.enclosing_contract_ast_id
                    )
                )
            )
            free_function_owned = (
                contract is None
                and function is not None
                and function.node_type == "FunctionDefinition"
                and function.kind == "freeFunction"
                and function.enclosing_contract_ast_id is None
                and statement.enclosing_contract_ast_id is None
            )
            if (
                statement_source is None
                or statement_source.path != statement.path
                or statement_source.source_sha256 != statement.source_sha256
                or statement.node_type not in _ATOMIC_STATEMENT_NODE_TYPES
                or statement.end_byte_exclusive <= statement.start_byte
                or statement.end_line_exclusive <= statement.start_line
                or statement.end_byte_exclusive > len(statement_source.content)
                or not (contract_owned or free_function_owned)
                or yul
                != (
                    statement.compiler_ast_id is None
                    and statement.enclosing_inline_assembly_ast_id is not None
                )
                or (not yul and statement.enclosing_inline_assembly_ast_id is not None)
            ):
                raise FoundryStatementCoverageProductionError(
                    f"{label} compiler statement has invalid AST/source custody"
                )
            previous = previous_by_path.get(statement.path)
            if previous is not None and statement.start_byte < previous.end_byte_exclusive:
                raise FoundryStatementCoverageProductionError(
                    f"{label} compiler atomic statements overlap"
                )
            previous_by_path[statement.path] = statement


def _validated_executions(
    executions: Sequence[RepositoryTestExecution],
    *,
    selection: RepositorySuiteSelection,
    policy: RepositorySuiteExecutionPolicy,
    pre_inventory: RepositorySuiteInventoryEvidence,
    post_inventory: RepositorySuiteInventoryEvidence,
) -> tuple[RepositoryTestExecution, ...]:
    if isinstance(executions, (str, bytes)) or not isinstance(executions, Sequence):
        raise FoundryStatementCoverageProductionError(
            "repository test executions are not a bounded sequence"
        )
    if len(executions) != selection.selected_test_count:
        raise FoundryStatementCoverageProductionError(
            "repository test execution count differs from selection"
        )
    canonical = tuple(
        _canonical_model(item, RepositoryTestExecution, "repository test execution")
        for item in executions
    )
    for descriptor, execution in zip(selection.tests, canonical, strict=True):
        if (
            execution.canonical_key != descriptor.canonical_key
            or execution.descriptor_sha256 != descriptor.descriptor_sha256
            or execution.status is not RepositoryTestExecutionStatus.PASSED
            or execution.execution_evidence is not ExecutionEvidenceKind.REAL
            or execution.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
            or execution.inventory_sha256 != pre_inventory.inventory_sha256
            or execution.post_inventory_sha256 != post_inventory.inventory_sha256
            or execution.inventory_record_sha256 != descriptor.inventory_record_sha256
            or execution.chain_id != policy.chain_id
            or execution.block_number != policy.block_number
            or execution.block_hash != policy.block_hash
            or execution.fuzz_seed != policy.fuzz_seed
            or execution.compiler_version != policy.compiler_version
            or execution.compiler_sha256 != policy.compiler_sha256
            or execution.execution_policy_sha256 != policy.policy_sha256
            or execution.isolation_backend != policy.isolation_backend
            or execution.isolation_attestation_sha256 != policy.isolation_attestation_sha256
        ):
            raise FoundryStatementCoverageProductionError(
                "selected repository test lacks exact passing execution custody"
            )
    if len({execution.execution_sha256 for execution in canonical}) != len(canonical):
        raise FoundryStatementCoverageProductionError(
            "repository test execution hashes are duplicated"
        )
    return canonical


def _validated_processes(
    processes: Sequence[FoundryStatementCoverageProcessObservation],
    selection: RepositorySuiteSelection,
    executions: tuple[RepositoryTestExecution, ...],
) -> tuple[FoundryStatementCoverageProcessObservation, ...]:
    if isinstance(processes, (str, bytes)) or not isinstance(processes, Sequence):
        raise FoundryStatementCoverageProductionError(
            "statement coverage processes are not a bounded sequence"
        )
    if len(processes) != selection.selected_test_count:
        raise FoundryStatementCoverageProductionError(
            "statement coverage requires exactly one process per selected test"
        )
    canonical = tuple(processes)
    if any(type(item) is not FoundryStatementCoverageProcessObservation for item in canonical):
        raise FoundryStatementCoverageProductionError(
            "statement coverage process has the wrong typed observation"
        )
    if tuple(process.sequence_index for process in canonical) != tuple(
        range(1, len(canonical) + 1)
    ):
        raise FoundryStatementCoverageProductionError(
            "statement coverage processes are not contiguous and selection ordered"
        )
    for descriptor, execution, process in zip(
        selection.tests,
        executions,
        canonical,
        strict=True,
    ):
        if (
            process.descriptor_sha256 != descriptor.descriptor_sha256
            or execution.descriptor_sha256 != process.descriptor_sha256
            or process.machine_result_sha256 != execution.machine_result_sha256
        ):
            raise FoundryStatementCoverageProductionError(
                "statement coverage process differs from selected test execution"
            )
    for values, label in (
        ([process.descriptor_sha256 for process in canonical], "descriptors"),
        ([process.coverage_command_sha256 for process in canonical], "commands"),
    ):
        if len(values) != len(set(values)):
            raise FoundryStatementCoverageProductionError(
                f"statement coverage process {label} are duplicated"
            )
    return canonical


def _validated_fork_rpc_scopes(
    scopes: Sequence[RepositoryTestForkRpcScopeEvidence],
    *,
    selection: RepositorySuiteSelection,
    policy: RepositorySuiteExecutionPolicy,
) -> tuple[RepositoryTestForkRpcScopeEvidence, ...]:
    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Sequence):
        raise FoundryStatementCoverageProductionError("fork RPC scopes are not a bounded sequence")
    if len(scopes) != selection.selected_test_count:
        raise FoundryStatementCoverageProductionError(
            "statement coverage requires one fork RPC scope per selected test"
        )
    canonical = tuple(
        _canonical_model(scope, RepositoryTestForkRpcScopeEvidence, "fork RPC scope")
        for scope in scopes
    )
    for index, (descriptor, scope) in enumerate(
        zip(selection.tests, canonical, strict=True),
        start=1,
    ):
        if (
            scope.sequence_index != index
            or scope.selection_sha256 != selection.selection_sha256
            or scope.descriptor_sha256 != descriptor.descriptor_sha256
            or scope.expected_chain_id != policy.chain_id
            or scope.pinned_block_number != policy.block_number
            or scope.pinned_block_hash != policy.block_hash
            or scope.status is not RepositoryTestForkRpcScopeStatus.VALIDATED
        ):
            raise FoundryStatementCoverageProductionError(
                "statement coverage lacks an exact validated fork RPC scope"
            )
    if len({scope.evidence_sha256 for scope in canonical}) != len(canonical):
        raise FoundryStatementCoverageProductionError(
            "statement coverage fork RPC scope hashes are duplicated"
        )
    return canonical


def _processes_by_project(
    processes: tuple[FoundryStatementCoverageProcessObservation, ...],
    selection: RepositorySuiteSelection,
) -> dict[str, tuple[FoundryStatementCoverageProcessObservation, ...]]:
    grouped: dict[str, list[FoundryStatementCoverageProcessObservation]] = {}
    for descriptor, process in zip(selection.tests, processes, strict=True):
        grouped.setdefault(descriptor.project_root, []).append(process)
    result: dict[str, tuple[FoundryStatementCoverageProcessObservation, ...]] = {}
    for project_root, project_processes in sorted(grouped.items()):
        populations = {
            process.debug_coverage.statement_inventory_sha256 for process in project_processes
        }
        uncovered_source_bindings = {
            process.debug_coverage.uncovered_sources for process in project_processes
        }
        if len(populations) != 1 or len(uncovered_source_bindings) != 1:
            raise FoundryStatementCoverageProductionError(
                "Forge debug statement population changed across selected tests in project "
                f"{project_root!r}"
            )
        result[project_root] = tuple(project_processes)
    return result


def _map_entity(
    binding: AuditedSuiteEntityCatalogBinding,
    catalogs: dict[str, FoundryCompilerStatementCatalog],
) -> _MappedEntity:
    if binding.provenance is not SolidityProvenance.COMPILER:
        raise FoundryStatementCoverageProductionError(
            "audited entity lacks one exact compiler source hash"
        )
    candidates: list[tuple[str, FoundryCompilerBuildUnit, FoundryCompilerEntity]] = []
    for project_root, catalog in catalogs.items():
        local_path = _project_relative_path(binding.location.path, project_root)
        if local_path is None:
            continue
        for unit in catalog.units:
            for entity in unit.entities:
                if _compiler_entity_matches(binding, entity, local_path):
                    candidates.append((project_root, unit, entity))
    if len(candidates) != 1:
        raise FoundryStatementCoverageProductionError(
            "audited entity does not map to exactly one compiler AST/build unit: "
            f"{binding.entity_id}"
        )
    project_root, unit, compiler_entity = candidates[0]
    source_matches = [
        source
        for source in unit.sources
        if source.source_id == compiler_entity.source_id
        and source.path == compiler_entity.path
        and source.source_sha256 == binding.source_file_sha256
    ]
    if len(source_matches) != 1:
        raise FoundryStatementCoverageProductionError(
            "audited entity lacks one exact compiler source body"
        )
    try:
        source_text = source_matches[0].content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FoundryStatementCoverageProductionError(
            "audited compiler source is not exact UTF-8"
        ) from exc
    if binding.location.content_hash != line_range_hash(
        source_text,
        binding.location.start_line,
        binding.location.end_line,
    ):
        raise FoundryStatementCoverageProductionError(
            "audited entity line-range hash differs from compiler source bytes"
        )
    if binding.entity_kind in _CONTRACT_ENTITY_KINDS:
        statements = tuple(
            statement
            for statement in unit.statements
            if statement.enclosing_contract_ast_id == compiler_entity.compiler_ast_id
        )
    else:
        statements = tuple(
            statement
            for statement in unit.statements
            if statement.enclosing_function_ast_id == compiler_entity.compiler_ast_id
        )
    if any(
        statement.path != compiler_entity.path
        or statement.source_sha256 != compiler_entity.source_sha256
        or statement.start_byte < compiler_entity.start_byte
        or statement.end_byte_exclusive > compiler_entity.end_byte_exclusive
        or statement.start_line < compiler_entity.start_line
        or statement.end_line_exclusive > compiler_entity.end_line_exclusive
        for statement in statements
    ):
        raise FoundryStatementCoverageProductionError(
            "compiler-owned statement escapes its audited entity span"
        )
    return _MappedEntity(
        binding=binding,
        project_root=project_root,
        unit=unit,
        compiler_entity=compiler_entity,
        statements=statements,
    )


def _compiler_entity_matches(
    binding: AuditedSuiteEntityCatalogBinding,
    entity: FoundryCompilerEntity,
    local_path: str,
) -> bool:
    if (
        entity.path != local_path
        or entity.source_sha256 != binding.source_file_sha256
        or entity.start_byte != binding.entity_start_byte_offset
        or entity.end_byte_exclusive != binding.entity_end_byte_offset
        or entity.start_line != binding.location.start_line
        or entity.end_line_exclusive - 1 != binding.location.end_line
    ):
        return False
    if binding.entity_kind in _CONTRACT_ENTITY_KINDS:
        return (
            entity.node_type == "ContractDefinition"
            and entity.kind == binding.entity_kind.value
            and entity.name == binding.entity_name
            and entity.enclosing_contract_ast_id is None
            and entity.enclosing_contract_name is None
        )
    if binding.entity_kind is SolidityEntityKind.CONSTRUCTOR:
        expected_kind = "constructor"
        expected_name = ""
    elif binding.entity_name in {"fallback", "receive"}:
        expected_kind = binding.entity_name
        expected_name = ""
    else:
        expected_kind = "function"
        expected_name = binding.entity_name
    return (
        binding.entity_kind in _FUNCTION_ENTITY_KINDS
        and entity.node_type == "FunctionDefinition"
        and entity.kind == expected_kind
        and entity.name == expected_name
        and entity.enclosing_contract_ast_id is not None
        and entity.enclosing_contract_name == binding.declaring_contract_name
    )


def _project_relative_path(repository_path: str, project_root: str) -> str | None:
    if project_root == ".":
        return repository_path
    prefix = f"{project_root}/"
    if not repository_path.startswith(prefix):
        return None
    return repository_path[len(prefix) :]


def _aggregate_coverage(
    physical_by_source: dict[tuple[str, str, int, int], _PhysicalStatement],
    *,
    catalogs: dict[str, FoundryCompilerStatementCatalog],
    processes_by_project: dict[
        str,
        tuple[FoundryStatementCoverageProcessObservation, ...],
    ],
) -> dict[tuple[str, str, int, int], bool]:
    targets_by_project: dict[
        str,
        dict[
            tuple[int, int, int, int, int],
            tuple[tuple[str, str, int, int], _PhysicalStatement],
        ],
    ] = {}
    for source_key, physical in physical_by_source.items():
        targets = targets_by_project.setdefault(physical.project_root, {})
        prior = targets.get(physical.debug_identity)
        if prior is not None and prior != (source_key, physical):
            raise FoundryStatementCoverageProductionError(
                "audited physical statements share an ambiguous debug identity"
            )
        targets[physical.debug_identity] = (source_key, physical)

    compiler_matches: dict[
        str,
        dict[tuple[int, int, int, int, int], list[_PhysicalStatement]],
    ] = {
        project_root: {identity: [] for identity in targets}
        for project_root, targets in targets_by_project.items()
    }
    for project_root, catalog in catalogs.items():
        project_matches = compiler_matches.get(project_root)
        if project_matches is None:
            continue
        for unit in catalog.units:
            for statement in unit.statements:
                repository_path = (
                    statement.path if project_root == "." else f"{project_root}/{statement.path}"
                )
                physical = _PhysicalStatement(
                    project_root=project_root,
                    repository_path=repository_path,
                    unit=unit,
                    statement=statement,
                )
                matches = project_matches.get(physical.debug_identity)
                if matches is not None:
                    matches.append(physical)

    result = {source_key: False for source_key in physical_by_source}
    for project_root, targets in targets_by_project.items():
        for identity, (source_key, physical) in targets.items():
            matches = compiler_matches[project_root][identity]
            if len(matches) != 1 or matches[0] != physical:
                raise FoundryStatementCoverageProductionError(
                    "compiler build units make a debug statement identity ambiguous"
                )
            if source_key != physical.source_key:
                raise FoundryStatementCoverageProductionError(
                    "physical statement source identity changed during normalization"
                )
        required = set(targets)
        for process in processes_by_project[project_root]:
            seen: set[tuple[int, int, int, int, int]] = set()
            uncovered_paths = {
                source.source_id: source.path for source in process.debug_coverage.uncovered_sources
            }
            for observed in process.debug_coverage.statements:
                target = targets.get(observed.identity)
                if target is None:
                    continue
                source_key, physical = target
                uncovered_path = uncovered_paths.get(observed.source_id)
                if uncovered_path is not None and uncovered_path != physical.statement.path:
                    raise FoundryStatementCoverageProductionError(
                        "Forge debug source path differs from its compiler source-ID binding"
                    )
                result[source_key] = result[source_key] or observed.covered
                seen.add(observed.identity)
            if seen != required:
                raise FoundryStatementCoverageProductionError(
                    "atomic compiler statement lacks an exact Forge debug span in every "
                    "selected-test process"
                )
    return result


def _compiler_statement_record(
    physical: _PhysicalStatement,
    *,
    covered: bool,
) -> AuditedSuiteCompilerStatementRecord:
    statement = physical.statement
    physical_id = AuditedSuiteCompilerStatementRecord.calculate_physical_statement_id(
        path=physical.repository_path,
        source_file_sha256=statement.source_sha256,
        start_byte_offset=statement.start_byte,
        end_byte_offset=statement.end_byte_exclusive,
    )
    if statement.enclosing_contract_ast_id is None:
        raise FoundryStatementCoverageProductionError(
            "audited compiler statement lacks an enclosing contract identity"
        )
    return AuditedSuiteCompilerStatementRecord.sealed(
        physical_statement_id=physical_id,
        project_root=physical.project_root,
        path=physical.repository_path,
        source_file_sha256=statement.source_sha256,
        normalized_build_info_sha256=physical.unit.normalized_build_info_sha256,
        compiler_source_id=statement.source_id,
        compiler_ast_id=statement.compiler_ast_id,
        enclosing_inline_assembly_ast_id=statement.enclosing_inline_assembly_ast_id,
        enclosing_contract_ast_id=statement.enclosing_contract_ast_id,
        enclosing_function_ast_id=statement.enclosing_function_ast_id,
        compiler_ast_node_type=statement.node_type,
        start_line=statement.start_line,
        end_line=statement.end_line_exclusive,
        start_byte_offset=statement.start_byte,
        end_byte_offset=statement.end_byte_exclusive,
        covered=covered,
    )


def _process_receipt(
    process: FoundryStatementCoverageProcessObservation,
    execution: RepositoryTestExecution,
    scope: RepositoryTestForkRpcScopeEvidence,
) -> AuditedSuiteStatementCoverageProcessReceipt:
    result_payload = [
        {
            "end_byte": statement.end_byte,
            "end_line": statement.end_line,
            "hits": statement.hits,
            "item_ids": list(statement.item_ids),
            "source_id": statement.source_id,
            "start_byte": statement.start_byte,
            "start_line": statement.start_line,
        }
        for statement in process.debug_coverage.statements
    ]
    return AuditedSuiteStatementCoverageProcessReceipt.sealed(
        sequence_index=process.sequence_index,
        descriptor_sha256=process.descriptor_sha256,
        repository_test_execution_sha256=execution.execution_sha256,
        coverage_command_sha256=process.coverage_command_sha256,
        fork_rpc_scope_evidence_sha256=scope.evidence_sha256,
        process_exit_code=process.process_exit_code,
        machine_output_validated=process.machine_output_validated,
        machine_result_sha256=process.machine_result_sha256,
        private_artifact_path=process.private_artifact_path,
        stdout_path=process.stdout_path,
        stdout_sha256=process.stdout_sha256,
        stdout_bytes=process.stdout_bytes,
        stderr_path=process.stderr_path,
        stderr_sha256=process.stderr_sha256,
        stderr_bytes=process.stderr_bytes,
        private_artifact_sha256=process.private_artifact_sha256,
        private_artifact_bytes=process.private_artifact_bytes,
        duration_seconds=float(process.duration_seconds),
        debug_statement_population_sha256=(process.debug_coverage.statement_inventory_sha256),
        debug_statement_result_sha256=_canonical_sha256(result_payload),
    )


def _entity_evidence(
    mapped: _MappedEntity,
    *,
    receipt: AuditedSuiteStatementCoverageReceipt,
    records_by_source: dict[
        tuple[str, str, int, int],
        AuditedSuiteCompilerStatementRecord,
    ],
    source_keys: tuple[tuple[str, str, int, int], ...],
) -> AuditedSuiteStatementCoverageEvidence:
    binding = mapped.binding
    observations: list[AuditedSuiteStatementObservation] = []
    for source_key in source_keys:
        record = records_by_source[source_key]
        location = Location(
            path=record.path,
            start_line=record.start_line,
            end_line=record.end_line - 1,
            symbol=binding.location.symbol,
            content_hash=binding.location.content_hash,
        )
        observations.append(
            AuditedSuiteStatementObservation(
                statement_id=AuditedSuiteStatementObservation.calculate_statement_id(
                    location=location,
                    start_byte_offset=record.start_byte_offset,
                    end_byte_offset=record.end_byte_offset,
                ),
                location=location,
                start_byte_offset=record.start_byte_offset,
                end_byte_offset=record.end_byte_offset,
                covered=record.covered,
            )
        )
    observations.sort(
        key=lambda item: (
            item.location.path,
            item.start_byte_offset,
            item.end_byte_offset,
            item.statement_id,
        )
    )
    if len(observations) > AUDITED_SUITE_STATEMENT_OBSERVATION_LIMIT:
        raise FoundryStatementCoverageProductionError(
            "one audited entity exceeds the statement observation limit"
        )
    covered_count = sum(observation.covered for observation in observations)
    status = (
        AuditedSuiteStatementStatus.COVERED
        if covered_count == len(observations)
        else AuditedSuiteStatementStatus.UNCOVERED
    )
    return AuditedSuiteStatementCoverageEvidence.sealed(
        schema_version="1.2",
        entity_id=binding.entity_id,
        entity_kind=binding.entity_kind,
        contract_name=binding.evidence_contract_name,
        location=binding.location,
        statement_status=status,
        statement_count=len(observations),
        covered_statement_count=covered_count,
        statements=observations,
        repository_test_execution_sha256s=(receipt.repository_test_execution_sha256s),
        source_repository_sha256=receipt.source_repository_sha256,
        repository_suite_selection_sha256=(receipt.repository_suite_selection_sha256),
        repository_suite_execution_policy_sha256=(receipt.repository_suite_execution_policy_sha256),
        coverage_command_sha256s=receipt.coverage_command_sha256s,
        statement_inventory_sha256=receipt.statement_inventory_sha256,
        coverage_artifact_sha256=receipt.coverage_artifact_sha256,
        coverage_artifact_bytes=receipt.coverage_artifact_bytes,
        producer_version=receipt.producer_version,
        producer_sha256=receipt.producer_sha256,
        normalizer_policy_sha256=receipt.normalizer_policy_sha256,
        tool_name=receipt.tool_name,
        tool_version=receipt.tool_version,
        tool_sha256=receipt.tool_sha256,
        compiler_version=receipt.compiler_version,
        compiler_sha256=receipt.compiler_sha256,
        isolation_attestation_sha256=receipt.isolation_attestation_sha256,
        coverage_receipt_sha256=receipt.receipt_sha256,
    )


__all__ = [
    "FOUNDRY_STATEMENT_COVERAGE_NORMALIZER_POLICY_SHA256",
    "FOUNDRY_STATEMENT_COVERAGE_PRODUCER_VERSION",
    "FoundryStatementCoverageProcessObservation",
    "FoundryStatementCoverageProduction",
    "FoundryStatementCoverageProductionError",
    "produce_foundry_statement_coverage",
]
