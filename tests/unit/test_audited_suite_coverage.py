from __future__ import annotations

import hashlib
import json
import shutil
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.scanners.runner as runner_module
import mmaudit.scanners.runtime_evidence as runtime_evidence_module
import mmaudit.solidity.coverage as coverage_module
from mmaudit.benchmark.mutations import (
    MutationApplicabilityBinding,
    MutationApplicabilityPlan,
    MutationCampaignEvidence,
    MutationKind,
    MutationKindAccounting,
    MutationKindInventoryStatus,
    MutationSuiteObservation,
    MutationSuiteTestObservation,
    MutationSuiteTestStatus,
    SourceMutationSpec,
)
from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    AnalysisState,
    AuditedSuiteAssertionStatus,
    AuditedSuiteCoverage,
    AuditedSuiteCoverageGapKind,
    AuditedSuiteMutationEvidence,
    AuditedSuiteMutationOutcome,
    AuditedSuiteMutationSurfaceEvidence,
    AuditedSuiteStatementCoverageEvidence,
    AuditedSuiteStatementObservation,
    AuditedSuiteStatementStatus,
    AuditedSuiteSurfaceCoverage,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    ExecutionEvidenceKind,
    FoundryTestExecutionSummary,
    InvariantCategory,
    InvariantSpec,
    InvariantSuite,
    Location,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewPriority,
    ModelSurfaceReviewRequest,
    RepositoryCodeExecutionState,
    RepositorySuiteExecutionPolicy,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    RepositoryTestKind,
    ScannerRun,
    ScannerStatus,
    SolidityCoverage,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphOmission,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityProvenance,
    solidity_graph_edge_logical_key,
    solidity_graph_occurrence_sha256,
)
from mmaudit.orchestration.model_coverage import build_model_surface_requests
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.scanners.base import ScannerIsolationBackend, scanner_workspace_sha256
from mmaudit.scanners.foundry import FoundryForkScanner, _write_repository_suite_manifest
from mmaudit.scanners.foundry_inventory_runner import FoundryInventoryOverflowError
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.coverage import (
    build_solidity_coverage,
    partition_audited_source_entities,
)
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects

FIXTURE = Path(__file__).parents[1] / "fixtures" / "solidity" / "foundry"


def _replace_graph_edges(
    graphs: SolidityGraphSet,
    edges: list[SolidityGraphEdge],
    **updates: object,
) -> SolidityGraphSet:
    retained_counts = {
        item.subject_sha256: item.occurrence_count
        for item in graphs.retained_occurrences
        if item.subject_kind is SolidityGraphOccurrenceKind.EDGE
    }
    logical_counts = {
        solidity_graph_edge_logical_key(edge): retained_counts[
            solidity_graph_occurrence_sha256(SolidityGraphOccurrenceKind.EDGE, edge)
        ]
        for edge in graphs.edges
    }
    retained_occurrences = [
        item
        for item in graphs.retained_occurrences
        if item.subject_kind is not SolidityGraphOccurrenceKind.EDGE
    ]
    retained_occurrences.extend(
        SolidityGraphRetainedOccurrence(
            subject_kind=SolidityGraphOccurrenceKind.EDGE,
            subject_sha256=solidity_graph_occurrence_sha256(
                SolidityGraphOccurrenceKind.EDGE,
                edge,
            ),
            occurrence_count=logical_counts.get(solidity_graph_edge_logical_key(edge), 1),
        )
        for edge in edges
    )
    coverage_keys = {*graphs.coverage, *(edge.graph.value for edge in edges)}
    return graphs.model_copy(
        update={
            **updates,
            "edges": edges,
            "coverage": {
                key: sum(edge.graph.value == key for edge in edges) for key in sorted(coverage_keys)
            },
            "retained_occurrences": tuple(
                sorted(
                    retained_occurrences,
                    key=lambda item: (item.subject_kind.value, item.subject_sha256),
                )
            ),
        }
    )


class _SyntheticRunnerIsolation:
    """Test-only backend identity used to exercise the exact trusted runner boundary."""

    name = "synthetic-rootless"

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


@dataclass
class _SyntheticRuntimeAuthority:
    """Test-only registry kept separate from production runtime authority."""

    _holder: dict[str, ScannerRun | None]
    invoke: Callable[..., ScannerRun]
    contains: Callable[[ScannerRun], bool]
    validated_copy: Callable[[ScannerRun], ScannerRun]

    @property
    def result(self) -> ScannerRun | None:
        return self._holder["result"]

    @result.setter
    def result(self, value: ScannerRun | None) -> None:
        self._holder["result"] = value


def _install_synthetic_runtime_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> _SyntheticRuntimeAuthority:
    existing = getattr(monkeypatch, "_mmaudit_audited_suite_runtime_authority", None)
    if isinstance(existing, _SyntheticRuntimeAuthority):
        return existing

    holder: dict[str, ScannerRun | None] = {"result": None}

    def synthetic_foundry_repository_suite(
        self: FoundryForkScanner,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
        workspace_custody_guard: list[object],
    ) -> ScannerRun:
        del (
            self,
            root,
            private_dir,
            timeout_seconds,
            backend,
            expected_version,
            expected_sha256,
            workspace_custody_guard,
        )
        result = holder["result"]
        if result is None:
            raise AssertionError("synthetic runtime authority has no configured result")
        return result

    invoke, contains, validated_copy, _annotate, _lease = (
        runtime_evidence_module._build_foundry_runtime_authority(
            adapter_type=FoundryForkScanner,
            producer_body=synthetic_foundry_repository_suite,
            execution_evidence_resolver=lambda _backend: ExecutionEvidenceKind.REAL,
            attestation_resolver=lambda _backend: "3" * 64,
        )
    )
    authority = _SyntheticRuntimeAuthority(
        _holder=holder,
        invoke=invoke,
        contains=contains,
        validated_copy=validated_copy,
    )
    monkeypatch.setattr(
        monkeypatch,
        "_mmaudit_audited_suite_runtime_authority",
        authority,
        raising=False,
    )
    monkeypatch.setattr(runner_module, "_invoke_builtin_foundry_adapter", authority.invoke)
    monkeypatch.setattr(
        coverage_module,
        "has_host_repository_suite_runtime_authority",
        authority.contains,
    )
    monkeypatch.setattr(
        coverage_module,
        "validated_scanner_run_copy_preserving_runtime_authority",
        authority.validated_copy,
    )
    return authority


def _self_authored_repository_suite_run(
    *,
    execution_status: RepositoryTestExecutionStatus = RepositoryTestExecutionStatus.PASSED,
) -> tuple[ScannerRun, str]:
    passed = execution_status is RepositoryTestExecutionStatus.PASSED
    machine_validated = passed
    descriptor = RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.FOUNDRY,
        project_root=".",
        path="test/Suite.t.sol",
        suite_name="Suite",
        test_name="testCoverage",
        source_sha256="a" * 64,
        start_line=10,
        end_line=12,
    )
    selection = RepositorySuiteSelection.sealed(
        profile="explicit",
        repository_sha256="b" * 64,
        repository_exclusion_path=".mmaudit",
        configuration_sha256="c" * 64,
        candidate_file_count=1,
        candidate_test_count=1,
        selected_file_count=1,
        selected_test_count=1,
        omitted_file_count=0,
        omitted_test_count=0,
        limit_reached=False,
        tests=(descriptor,),
        safety_claim=False,
    )
    policy = RepositorySuiteExecutionPolicy.sealed(
        selection_sha256=selection.selection_sha256,
        selection_configuration_sha256=selection.configuration_sha256,
        chain_id=31_337,
        block_number=0,
        block_hash="0x" + ("d" * 64),
        tool_version="forge 1.0",
        tool_sha256="e" * 64,
        compiler_version="solc 0.8.30",
        compiler_sha256="f" * 64,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="3" * 64,
        fuzz_seed="0x" + ("1" * 64),
        fuzz_runs=256,
        invariant_runs=256,
        per_test_timeout_seconds=30,
        total_timeout_seconds=60,
        max_output_bytes_per_test=1_024,
        max_total_output_bytes=1_000_000,
    )
    execution = RepositoryTestExecution.sealed(
        selection_sha256=selection.selection_sha256,
        descriptor_sha256=descriptor.descriptor_sha256,
        framework=descriptor.framework,
        project_root=descriptor.project_root,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        chain_id=policy.chain_id,
        block_number=policy.block_number,
        block_hash=policy.block_hash,
        fuzz_seed=policy.fuzz_seed,
        test_kind=RepositoryTestKind.UNIT if machine_validated else None,
        status=execution_status,
        terminal_detail=(None if passed else "synthetic non-passing test observation"),
        duration_seconds=0.1,
        command_sha256="0" * 64,
        output_sha256="1" * 64,
        output_bytes=10,
        machine_result_sha256="2" * 64 if machine_validated else None,
        process_exit_code=(
            0
            if passed
            else (None if execution_status is RepositoryTestExecutionStatus.TIMED_OUT else 2)
        ),
        machine_output_validated=machine_validated,
        execution_evidence=ExecutionEvidenceKind.REAL,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="3" * 64,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_policy_sha256=policy.policy_sha256,
        safety_claim=False,
    )
    now = datetime.now(UTC)
    run = ScannerRun(
        scanner="foundry_fork",
        status=(
            ScannerStatus.SUCCESS
            if passed
            else (
                ScannerStatus.TIMED_OUT
                if execution_status is RepositoryTestExecutionStatus.TIMED_OUT
                else ScannerStatus.FAILED
            )
        ),
        execution_evidence=ExecutionEvidenceKind.REAL,
        version=policy.tool_version,
        executable_sha256=policy.tool_sha256,
        command=["forge", "test", "--offline"],
        started_at=now,
        finished_at=now,
        duration_seconds=0.1,
        raw_output_path="private/foundry.json",
        raw_output_sha256="4" * 64,
        raw_output_bytes=10,
        process_exit_code=(
            0
            if passed
            else (None if execution_status is RepositoryTestExecutionStatus.TIMED_OUT else 2)
        ),
        machine_output_validated=machine_validated,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="3" * 64,
        foundry_summary=(
            FoundryTestExecutionSummary(
                unit_tests=1,
                fuzz_tests=0,
                invariant_tests=0,
                passed_tests=1,
                failed_tests=0,
                skipped_tests=0,
                fuzz_cases=0,
                invariant_runs=0,
                invariant_calls=0,
            )
            if machine_validated
            else None
        ),
        repository_suite_selection=selection,
        repository_suite_execution_policy=policy,
        repository_test_executions=[execution],
    )
    validated = ScannerRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "execution_observation_sha256": run.expected_execution_observation_sha256(),
        }
    )
    return validated, execution.execution_sha256


async def _runner_authorized_repository_suite_run(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: AuditConfig,
    execution_status: RepositoryTestExecutionStatus = RepositoryTestExecutionStatus.PASSED,
    result_override: ScannerRun | None = None,
) -> tuple[ScannerRun, ScannerRunner, str]:
    """Issue a synthetic receipt only through the exact built-in runner invocation."""

    if result_override is None:
        result, execution_sha256 = _self_authored_repository_suite_run(
            execution_status=execution_status
        )
    else:
        result = result_override
        assert len(result.repository_test_executions) == 1
        execution_sha256 = result.repository_test_executions[0].execution_sha256
    authority = _install_synthetic_runtime_authority(monkeypatch)
    authority.result = result
    configured = config.model_copy(
        update={
            "scanners": config.scanners.model_copy(
                update={
                    "foundry_fork": config.scanners.foundry_fork.model_copy(
                        update={"enabled": True, "required": False}
                    )
                }
            )
        }
    )
    runner = ScannerRunner(
        configured,
        adapters={
            "foundry_fork": FoundryForkScanner(configured.smart_contracts),
        },
        backend=_SyntheticRunnerIsolation(),
    )
    tmp_path.mkdir(parents=True, exist_ok=True)
    runs = await runner.run_all(
        tmp_path,
        tmp_path / ".mmaudit",
        audited_relative_paths=(),
        expected_repository_sha256=scanner_workspace_sha256(tmp_path),
    )
    assert len(runs) == 1
    return runs[0], runner, execution_sha256


def _forged_repository_suite_run() -> tuple[ScannerRun, str]:
    descriptor = RepositorySuiteTestDescriptor.model_construct(descriptor_sha256="d" * 64)
    selection = RepositorySuiteSelection.model_construct(tests=(descriptor,))
    execution = RepositoryTestExecution.model_construct(
        descriptor_sha256=descriptor.descriptor_sha256,
        status=RepositoryTestExecutionStatus.PASSED,
        output_sha256="1" * 64,
        machine_result_sha256="2" * 64,
        machine_output_validated=True,
        execution_evidence=ExecutionEvidenceKind.REAL,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="3" * 64,
        execution_policy_sha256="4" * 64,
        execution_sha256="0" * 64,
    )
    execution = execution.model_copy(
        update={"execution_sha256": execution.expected_execution_sha256()}
    )
    run = ScannerRun.model_construct(
        scanner="foundry_fork",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        machine_output_validated=True,
        repository_code_execution=RepositoryCodeExecutionState.ISOLATED,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="3" * 64,
        repository_suite_selection=selection,
        repository_test_executions=[execution],
        execution_observation_sha256=None,
    )
    run = run.model_copy(
        update={"execution_observation_sha256": run.expected_execution_observation_sha256()}
    )
    return run, execution.execution_sha256


def _covered_statement_evidence(
    entity: SolidityEntity,
    run: ScannerRun,
    *,
    covered: bool = True,
    covered_spans: Mapping[tuple[int, int], bool] | None = None,
) -> AuditedSuiteStatementCoverageEvidence:
    selection = run.repository_suite_selection
    policy = run.repository_suite_execution_policy
    assert selection is not None
    assert policy is not None
    assert run.version is not None
    assert run.executable_sha256 is not None
    assert run.isolation_attestation_sha256 is not None
    location = Location(
        path=entity.path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        symbol=entity.signature or entity.name,
        content_hash=entity.source_hash,
    )
    source = (FIXTURE / entity.path).read_text(encoding="utf-8")
    source_lines = source.splitlines(keepends=True)
    statements: list[AuditedSuiteStatementObservation] = []
    byte_cursor = 0
    for line_number, line in enumerate(source_lines, start=1):
        encoded = line.encode("utf-8")
        if entity.start_line <= line_number <= entity.end_line and line.strip():
            leading = len(line) - len(line.lstrip())
            trailing_text = line.rstrip()
            start_byte_offset = byte_cursor + len(line[:leading].encode("utf-8"))
            end_byte_offset = byte_cursor + len(trailing_text.encode("utf-8"))
            statement_covered = (
                covered_spans.get((start_byte_offset, end_byte_offset), covered)
                if covered_spans is not None
                else covered
            )
            statement_location = Location(
                path=entity.path,
                start_line=line_number,
                end_line=line_number,
                symbol=entity.signature or entity.name,
                content_hash=entity.source_hash,
            )
            statements.append(
                AuditedSuiteStatementObservation(
                    statement_id=AuditedSuiteStatementObservation.calculate_statement_id(
                        location=statement_location,
                        start_byte_offset=start_byte_offset,
                        end_byte_offset=end_byte_offset,
                    ),
                    location=statement_location,
                    start_byte_offset=start_byte_offset,
                    end_byte_offset=end_byte_offset,
                    covered=statement_covered,
                )
            )
        byte_cursor += len(encoded)
    assert statements
    execution_sha256s = sorted(
        execution.execution_sha256 for execution in run.repository_test_executions
    )
    covered_count = sum(statement.covered for statement in statements)
    return AuditedSuiteStatementCoverageEvidence.sealed(
        entity_id=entity.id,
        entity_kind=entity.kind,
        contract_name=entity.contract_name or entity.name,
        location=location,
        statement_status=(
            AuditedSuiteStatementStatus.COVERED
            if covered_count == len(statements)
            else AuditedSuiteStatementStatus.UNCOVERED
        ),
        statement_count=len(statements),
        covered_statement_count=covered_count,
        statements=statements,
        repository_test_execution_sha256s=execution_sha256s,
        source_repository_sha256=selection.repository_sha256,
        repository_suite_selection_sha256=selection.selection_sha256,
        repository_suite_execution_policy_sha256=policy.policy_sha256,
        coverage_command_sha256s=["8" * 64],
        statement_inventory_sha256="9" * 64,
        coverage_artifact_sha256="5" * 64,
        coverage_artifact_bytes=128,
        producer_version="synthetic-normalizer 1.0",
        producer_sha256="7" * 64,
        normalizer_policy_sha256="a" * 64,
        tool_name="forge",
        tool_version=run.version,
        tool_sha256=run.executable_sha256,
        compiler_version=policy.compiler_version,
        compiler_sha256=policy.compiler_sha256,
        execution_evidence=ExecutionEvidenceKind.REAL,
        machine_output_validated=True,
        isolation_attestation_sha256=run.isolation_attestation_sha256,
    )


def _run_with_statement_evidence(
    run: ScannerRun,
    evidence: list[AuditedSuiteStatementCoverageEvidence],
) -> ScannerRun:
    provisional = run.model_copy(
        update={
            "repository_statement_coverage_evidence": sorted(
                evidence,
                key=lambda item: (item.entity_id, item.evidence_sha256),
            ),
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": (provisional.expected_execution_observation_sha256()),
        }
    )


def test_statement_observation_identity_distinguishes_two_statements_on_one_line() -> None:
    source = "contract C { function f() external { uint256 a = 1; uint256 b = 2; } }\n"
    location = Location(
        path="src/C.sol",
        start_line=1,
        end_line=1,
        symbol="f()",
        content_hash=hashlib.sha256(source.encode("utf-8")).hexdigest(),
    )
    spans = [
        (source.index("uint256 a"), source.index("uint256 a") + len("uint256 a = 1;")),
        (source.index("uint256 b"), source.index("uint256 b") + len("uint256 b = 2;")),
    ]
    observations = [
        AuditedSuiteStatementObservation(
            statement_id=AuditedSuiteStatementObservation.calculate_statement_id(
                location=location,
                start_byte_offset=start,
                end_byte_offset=end,
            ),
            location=location,
            start_byte_offset=start,
            end_byte_offset=end,
            covered=index == 0,
        )
        for index, (start, end) in enumerate(spans)
    ]

    assert observations[0].statement_id != observations[1].statement_id
    assert observations[0].location.start_line == observations[1].location.start_line == 1


def test_statement_span_validation_uses_exact_utf8_boundaries_and_multiline_locations() -> None:
    source = (
        "contract Café {\n"
        "    function label() external pure returns (string memory) {\n"
        '        return "café";\n'
        "    }\n"
        "}\n"
    )
    content_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    entity_location = Location(
        path="src/Café.sol",
        start_line=1,
        end_line=5,
        symbol="label()",
        content_hash=content_hash,
    )
    statement_location = Location(
        path=entity_location.path,
        start_line=2,
        end_line=3,
        symbol=entity_location.symbol,
        content_hash=content_hash,
    )
    start = len(source[: source.index("function")].encode("utf-8"))
    end = len(source[: source.index(";\n") + 1].encode("utf-8"))
    source_index = coverage_module._utf8_source_span_index(source)
    entity_end = len(source.encode("utf-8"))

    assert coverage_module._statement_observation_matches_source(
        source_index=source_index,
        entity_location=entity_location,
        entity_start_byte_offset=0,
        entity_end_byte_offset=entity_end,
        statement_location=statement_location,
        start_byte_offset=start,
        end_byte_offset=end,
    )
    multibyte_offset = source.encode("utf-8").index("é".encode())
    assert not coverage_module._statement_observation_matches_source(
        source_index=source_index,
        entity_location=entity_location,
        entity_start_byte_offset=0,
        entity_end_byte_offset=entity_end,
        statement_location=statement_location,
        start_byte_offset=multibyte_offset + 1,
        end_byte_offset=end,
    )


def test_statement_span_cannot_cross_between_two_functions_on_one_line() -> None:
    source = (
        "contract C { function a() external { uint256 x = 1; } "
        "function b() external { uint256 y = 2; } }\n"
    )
    source_bytes = source.encode()
    content_hash = hashlib.sha256(source_bytes).hexdigest()
    entity_location = Location(
        path="src/C.sol",
        start_line=1,
        end_line=1,
        symbol="a()",
        content_hash=content_hash,
    )
    statement_location = entity_location
    function_a_start = source.index("function a")
    function_a_end = source.index("function b")
    function_b_statement_start = source.index("uint256 y")
    function_b_statement_end = function_b_statement_start + len("uint256 y = 2;")
    source_index = coverage_module._utf8_source_span_index(source)

    assert coverage_module._entity_span_matches_source(
        source_index=source_index,
        entity_location=entity_location,
        start_byte_offset=function_a_start,
        end_byte_offset=function_a_end,
    )
    assert not coverage_module._statement_observation_matches_source(
        source_index=source_index,
        entity_location=entity_location,
        entity_start_byte_offset=function_a_start,
        entity_end_byte_offset=function_a_end,
        statement_location=statement_location,
        start_byte_offset=function_b_statement_start,
        end_byte_offset=function_b_statement_end,
    )


def test_audited_suite_denominators_exclude_test_harnesses_and_emit_exact_gaps(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)

    partition = partition_audited_source_entities(
        index=build.index,
        projects=projects,
    )
    indexed_contracts = [
        entity
        for entity in build.index.entities
        if entity.kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    ]
    indexed_functions = [
        entity
        for entity in build.index.entities
        if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
    ]
    assert len(indexed_contracts) == 3
    assert len(indexed_functions) == 5
    assert len(partition.contract_exclusions) == 1
    assert len(partition.function_exclusions) == 2
    assert len(partition.contract_entity_ids) == 2
    assert len(partition.function_entity_ids) == 3

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
    )
    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert audited.schema_version == "1.1"

    contract_metric = audited.contract_statement_coverage
    function_metric = audited.function_statement_coverage
    assertion_metric = audited.critical_function_assertion_coverage
    assert (
        contract_metric.population,
        contract_metric.denominator,
        len(contract_metric.exclusions),
    ) == (3, 2, 1)
    assert (
        function_metric.population,
        function_metric.denominator,
        len(function_metric.exclusions),
    ) == (5, 3, 2)
    assert (
        assertion_metric.numerator,
        assertion_metric.denominator,
        assertion_metric.population,
    ) == (0, 5, 5)
    assert assertion_metric.state is AnalysisState.NOT_ANALYZED

    assert not audited.critical_classification_complete
    critical_source_ids = set(partition.function_entity_ids)
    assert {
        surface.entity_id
        for surface in audited.surfaces
        if surface.critical
        and surface.entity_kind
        in {
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
        }
    } == critical_source_ids
    assert {
        surface.contract_name
        for surface in audited.surfaces
        if surface.critical
        and surface.entity_kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    } == {"Owned", "Vault"}

    critical_contract_ids = set(partition.contract_entity_ids)
    assert {
        gap.entity_id
        for gap in audited.gaps
        if gap.entity_kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    } == critical_contract_ids
    assert all(
        not surface.mutation_evidence
        for surface in audited.surfaces
        if surface.entity_id in critical_contract_ids
    )
    requests = build_model_surface_requests(
        index=build.index,
        graphs=graphs,
        invariants=None,
        economic_simulations=[],
        audited_suite_coverage=audited,
    )
    assert all(
        request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
        and request.coverage_gap_ids
        for request in requests
        if request.subject_id in critical_contract_ids
    )

    withdraw = next(
        entity
        for entity in build.index.entities
        if entity.contract_name == "Vault" and entity.name == "withdraw"
    )
    withdraw_gap = next(gap for gap in audited.gaps if gap.entity_id == withdraw.id)
    assert withdraw_gap.kind is AuditedSuiteCoverageGapKind.ASSERTION_NOT_ANALYZED
    assert withdraw_gap.assertion_status is AuditedSuiteAssertionStatus.NOT_ANALYZED
    assert withdraw_gap.location.path == "src/Vault.sol"
    assert withdraw_gap.location.start_line == 20
    assert withdraw_gap.location.end_line == 22
    assert withdraw_gap.location.symbol == "withdraw(uint256)"
    assert withdraw_gap.location.content_hash == withdraw.source_hash
    assert not withdraw_gap.is_finding
    assert all(not gap.location.path.startswith("test/") for gap in audited.gaps)
    assert AuditedSuiteCoverage.model_validate_json(audited.model_dump_json()) == audited
    legacy_payload = audited.model_dump(mode="json")
    legacy_payload["schema_version"] = "1.0"
    legacy_payload.pop("statement_coverage_authority")
    legacy_bytes = json.dumps(
        legacy_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    restored_legacy = AuditedSuiteCoverage.model_validate_json(legacy_bytes)
    assert restored_legacy.schema_version == "1.0"
    assert restored_legacy.statement_coverage_authority is None
    assert (
        json.dumps(
            restored_legacy.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        == legacy_bytes
    )


def test_auxiliary_graph_nodes_do_not_invalidate_critical_source_classification(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    assert graphs.edges
    auxiliary_edge = graphs.edges[0].model_copy(
        update={
            "graph": SolidityGraphKind.UPGRADE_COMPATIBILITY,
            "source_id": "graph:synthetic-upgrade-layout",
            "target_id": "graph:synthetic-upgrade-target",
        }
    )
    graphs = _replace_graph_edges(
        graphs,
        [*graphs.edges, auxiliary_edge],
        analyzed_graphs=sorted(
            {
                *graphs.analyzed_graphs,
                SolidityGraphKind.PRIVILEGE,
                SolidityGraphKind.ASSET_FLOW,
                SolidityGraphKind.SENSITIVE_REACHABILITY,
                SolidityGraphKind.UPGRADE_COMPATIBILITY,
            },
            key=lambda item: item.value,
        ),
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        invariants=InvariantSuite(),
    )

    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert audited.source_classification_complete
    assert audited.critical_classification_complete
    assert audited.critical_function_assertion_coverage.denominator > 0


def test_graph_omissions_make_critical_classification_incomplete(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    omitted_edges = [edge for edge in graphs.edges if edge.graph is SolidityGraphKind.STATE_WRITE]
    assert omitted_edges
    retained_edges = [
        edge for edge in graphs.edges if edge.graph is not SolidityGraphKind.STATE_WRITE
    ]
    omission = SolidityGraphOmission.build(
        graph=SolidityGraphKind.STATE_WRITE,
        candidate_count=len(omitted_edges),
        retained_count=0,
        omitted_count=len(omitted_edges),
        omitted_canonical_bytes=320,
        omitted_stream_sha256="a" * 64,
        omitted_sample_sha256s=("b" * 64,),
    )
    partial_graphs = SolidityGraphSet.model_validate(
        _replace_graph_edges(
            graphs,
            retained_edges,
            analyzed_graphs=[
                kind for kind in graphs.analyzed_graphs if kind is not SolidityGraphKind.STATE_WRITE
            ],
            generation_complete=False,
            edge_omissions=(omission,),
        ).model_dump(mode="python")
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=partial_graphs,
        scanner_runs=[],
        invariants=InvariantSuite(),
    )

    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert audited.source_classification_complete
    assert not audited.critical_classification_complete
    assert any(
        "semantic graph generation omitted bounded edge or fact evidence" in limitation
        for limitation in audited.limitations
    )
    partition = partition_audited_source_entities(index=build.index, projects=projects)
    assert {
        surface.entity_id
        for surface in audited.surfaces
        if surface.critical
        and surface.entity_kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
    } == set(partition.function_entity_ids)


def test_symbolic_invariant_and_applicable_economic_plan_require_exact_audited_binding(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    unbound = InvariantSpec(
        id="inv:unbound-symbolic",
        title="Unbound symbolic invariant",
        category=InvariantCategory.STATE_MACHINE,
        description="A symbolic name alone cannot identify current audited source.",
        functions=["withdraw(uint256)"],
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        evidence_hash="7" * 64,
    )
    applicable = EconomicSimulationPlan(
        kind=EconomicSimulationKind.SHARE_PRICE,
        applicable=True,
        rationale="Synthetic applicable accounting plan requires an exact audited binding.",
    )

    unbound_coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        invariants=InvariantSuite(invariants=[unbound]),
        economic_simulations=[applicable],
    )
    audited = unbound_coverage.audited_suite_coverage
    assert audited is not None
    assert not audited.critical_classification_complete
    assert any("nonempty invariants lacked an exact" in item for item in audited.limitations)
    assert any("applicable economic plans lacked an exact" in item for item in audited.limitations)

    test_function = next(
        entity
        for entity in build.index.entities
        if entity.kind is SolidityEntityKind.FUNCTION and entity.path.startswith("test/")
    )
    exact_test_only = unbound.model_copy(
        update={
            "id": "inv:exact-test-only",
            "entity_ids": [test_function.id],
            "locations": [
                Location(
                    path=test_function.path,
                    start_line=test_function.start_line,
                    end_line=test_function.end_line,
                    symbol=test_function.signature or test_function.name,
                    content_hash=test_function.source_hash,
                )
            ],
            "functions": [test_function.signature or test_function.name],
            "evidence_hash": "6" * 64,
        }
    )
    non_applicable = applicable.model_copy(
        update={
            "applicable": False,
            "rationale": "This exact synthetic repository has no applicable share-price surface.",
        }
    )
    excluded_coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        invariants=InvariantSuite(invariants=[exact_test_only]),
        economic_simulations=[non_applicable],
    )
    excluded_audited = excluded_coverage.audited_suite_coverage
    assert excluded_audited is not None
    assert excluded_audited.critical_classification_complete


@pytest.mark.parametrize(
    "location_update",
    [
        {"symbol": None},
        {"content_hash": "f" * 64},
    ],
)
def test_invariant_location_binding_rejects_missing_or_stale_current_evidence(
    tmp_path: Path,
    config_factory,
    location_update: dict[str, str | None],
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    function = next(
        entity
        for entity in build.index.entities
        if entity.kind is SolidityEntityKind.FUNCTION
        and entity.path.startswith("src/")
        and entity.name == "withdraw"
    )
    location = Location(
        path=function.path,
        start_line=function.start_line,
        end_line=function.end_line,
        symbol=function.signature or function.name,
        content_hash=function.source_hash,
    ).model_copy(update=location_update)
    invariant = InvariantSpec(
        id="inv:stale-location",
        title="Current exact location required",
        category=InvariantCategory.STATE_MACHINE,
        description="Missing or stale source evidence cannot bind this invariant.",
        locations=[location],
        functions=[function.signature or function.name],
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        evidence_hash="5" * 64,
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        invariants=InvariantSuite(invariants=[invariant]),
    )

    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert not audited.critical_classification_complete
    assert any("nonempty invariants lacked an exact" in item for item in audited.limitations)


def test_critical_graph_edge_requires_current_contained_hash_bound_source_range(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    audited_function_ids = set(
        partition_audited_source_entities(index=build.index, projects=projects).function_entity_ids
    )
    critical_kinds = {
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    }
    edge = next(
        item
        for item in graphs.edges
        if item.graph in critical_kinds and item.source_id in audited_function_ids
    )
    stale_edge = edge.model_copy(update={"source_hash": "f" * 64})
    graphs = _replace_graph_edges(
        graphs,
        [stale_edge if item is edge else item for item in graphs.edges],
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        invariants=InvariantSuite(),
    )

    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert not audited.critical_classification_complete
    assert any(
        "critical graph edges lacked an exact current" in item for item in audited.limitations
    )


def test_contract_state_and_location_invariants_share_exact_critical_contracts(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    critical_graphs = {
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    }
    graphs = _replace_graph_edges(
        graphs,
        [edge for edge in graphs.edges if edge.graph not in critical_graphs],
        analyzed_graphs=sorted(
            {*graphs.analyzed_graphs, *critical_graphs},
            key=lambda item: item.value,
        ),
    )
    vault = next(
        entity
        for entity in build.index.entities
        if entity.kind is SolidityEntityKind.CONTRACT and entity.name == "Vault"
    )
    owner = next(
        entity
        for entity in build.index.entities
        if entity.kind is SolidityEntityKind.STATE_VARIABLE
        and entity.contract_name == "Owned"
        and entity.name == "owner"
    )
    internal_withdraw = next(
        entity
        for entity in build.index.entities
        if entity.kind is SolidityEntityKind.FUNCTION
        and entity.contract_name == "Vault"
        and entity.name == "_withdraw"
    )

    def location(entity: SolidityEntity) -> Location:
        return Location(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            symbol=entity.signature or entity.name,
            content_hash=entity.source_hash,
        )

    def invariant(
        invariant_id: str,
        *,
        entity_ids: list[str],
        bound_location: Location,
    ) -> InvariantSpec:
        return InvariantSpec(
            id=invariant_id,
            title=f"Exact invariant {invariant_id}",
            category=InvariantCategory.STATE_MACHINE,
            description="The exact audited-source binding preserves its contract state.",
            locations=[bound_location],
            entity_ids=entity_ids,
            provenance=SolidityProvenance.COMPILER,
            confidence=1,
            evidence_hash=("a" if entity_ids else "b") * 64,
        )

    invariants = InvariantSuite(
        invariants=[
            invariant(
                "inv:direct-contract",
                entity_ids=[vault.id],
                bound_location=location(vault),
            ),
            invariant(
                "inv:direct-state",
                entity_ids=[owner.id],
                bound_location=location(owner),
            ),
            invariant(
                "inv:location-function",
                entity_ids=[],
                bound_location=location(internal_withdraw),
            ),
        ]
    )
    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        invariants=invariants,
    )
    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert audited.critical_classification_complete
    assert {
        surface.contract_name
        for surface in audited.surfaces
        if surface.critical
        and surface.entity_kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    } == {"Owned", "Vault"}

    requests = build_model_surface_requests(
        index=build.index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited,
    )
    critical_contracts = {
        request.contract
        for request in requests
        if request.kind is ModelReviewSurfaceKind.CONTRACT and request.critical
    }
    assert critical_contracts == {"Owned", "Vault"}
    assert any(
        request.kind is ModelReviewSurfaceKind.STATE
        and request.subject_id == owner.id
        and request.critical
        for request in requests
    )
    assert any(
        request.kind is ModelReviewSurfaceKind.INTERNAL_FUNCTION
        and request.subject_id == internal_withdraw.id
        and request.critical
        for request in requests
    )


def test_mixed_source_and_test_invariant_fails_priority_classification_closed(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    source_function = next(
        entity
        for entity in build.index.entities
        if entity.kind is SolidityEntityKind.FUNCTION and entity.path.startswith("src/")
    )
    test_function = next(
        entity
        for entity in build.index.entities
        if entity.kind is SolidityEntityKind.FUNCTION and entity.path.startswith("test/")
    )
    mixed_invariant = InvariantSpec(
        id="inv:mixed-source-test",
        title="Mixed source and test helper invariant",
        category=InvariantCategory.STATE_MACHINE,
        description="Synthetic mixed binding must not authorize source criticality.",
        locations=[
            Location(
                path=source_function.path,
                start_line=source_function.start_line,
                end_line=source_function.end_line,
                content_hash=source_function.source_hash,
            ),
            Location(
                path=test_function.path,
                start_line=test_function.start_line,
                end_line=test_function.end_line,
                content_hash=test_function.source_hash,
            ),
        ],
        entity_ids=[source_function.id, test_function.id],
        functions=[
            source_function.signature or source_function.name,
            test_function.signature or test_function.name,
        ],
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        template_available=False,
        evidence_hash="8" * 64,
    )
    invariants = InvariantSuite(invariants=[mixed_invariant])
    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        invariants=invariants,
    )

    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert not audited.critical_classification_complete
    requests = build_model_surface_requests(
        index=build.index,
        graphs=graphs,
        invariants=invariants,
        economic_simulations=[],
        audited_suite_coverage=audited,
    )
    assert requests
    source_request_ids = set(
        partition_audited_source_entities(
            index=build.index,
            projects=projects,
        ).contract_entity_ids
    ) | set(
        partition_audited_source_entities(
            index=build.index,
            projects=projects,
        ).function_entity_ids
    )
    assert all(
        request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
        and request.coverage_gap_ids
        for request in requests
        if request.subject_id in source_request_ids
    )
    assert all(request.subject_id != mixed_invariant.id for request in requests)


def test_self_authored_statement_artifacts_never_earn_runtime_credit(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    withdraw = next(
        entity
        for entity in build.index.entities
        if entity.contract_name == "Vault" and entity.name == "withdraw"
    )
    standalone_run, _ = _self_authored_repository_suite_run()
    forged = _covered_statement_evidence(withdraw, standalone_run)
    without_runtime = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
        audited_suite_statement_evidence=[forged],
    )
    audited_without_runtime = without_runtime.audited_suite_coverage
    assert audited_without_runtime is not None
    surface_without_runtime = next(
        item for item in audited_without_runtime.surfaces if item.entity_id == withdraw.id
    )
    assert surface_without_runtime.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
    assert surface_without_runtime.statement_evidence_sha256s == []
    assert surface_without_runtime.repository_test_execution_sha256s == []
    assert any(
        "process-local trusted normalizer receipt" in item
        for item in audited_without_runtime.limitations
    )
    forged_surface_values = surface_without_runtime.model_dump(mode="python")
    forged_surface_values.update(
        {
            "location": surface_without_runtime.location,
            "statement_status": AuditedSuiteStatementStatus.COVERED,
            "statement_evidence_sha256s": ["1" * 64],
            "repository_test_execution_sha256s": ["2" * 64],
        }
    )
    forged_surface = AuditedSuiteSurfaceCoverage.model_validate(forged_surface_values)
    assert forged_surface.statement_status is AuditedSuiteStatementStatus.COVERED
    assert forged_surface.statement_evidence_sha256s == ["1" * 64]

    forged_run, _ = _forged_repository_suite_run()
    forged_from_construct = _covered_statement_evidence(withdraw, standalone_run)
    with pytest.raises(ValidationError):
        build_solidity_coverage(
            discovery=discovery,
            projects=projects,
            compilations=[],
            index=build.index,
            graphs=graphs,
            scanner_runs=[forged_run],
            audited_suite_statement_evidence=[forged_from_construct],
        )

    run, _ = _self_authored_repository_suite_run()
    evidence = _covered_statement_evidence(withdraw, run)
    serialized_run = ScannerRun.model_validate_json(run.model_dump_json())
    serialized_coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[serialized_run],
        audited_suite_statement_evidence=[evidence],
    )
    serialized_audited = serialized_coverage.audited_suite_coverage
    assert serialized_audited is not None
    assert serialized_audited.repository_tests_selected == 0
    assert serialized_audited.repository_tests_executed == 0
    assert serialized_audited.repository_tests_failed == 0

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[run],
        audited_suite_statement_evidence=[evidence],
    )
    audited = coverage.audited_suite_coverage
    assert audited is not None
    surface = next(item for item in audited.surfaces if item.entity_id == withdraw.id)
    assert surface.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
    assert surface.statement_evidence_sha256s == []
    assert surface.repository_test_execution_sha256s == []
    assert surface.assertion_status is AuditedSuiteAssertionStatus.NOT_ANALYZED
    assert audited.repository_tests_selected == 0
    assert audited.repository_tests_executed == 0
    assert audited.repository_tests_failed == 0
    assert coverage.tests_executed == 0
    assert coverage.tests_failed == 0
    assert CoverageProvenance.RUNTIME not in audited.contract_statement_coverage.provenance
    assert CoverageProvenance.RUNTIME not in audited.function_statement_coverage.provenance
    assert CoverageProvenance.RUNTIME not in audited.critical_function_assertion_coverage.provenance
    assert any("process-local trusted normalizer receipt" in item for item in audited.limitations)
    restored = SolidityCoverage.model_validate_json(coverage.model_dump_json())
    assert restored.audited_suite_coverage == audited
    inconsistent_counts = coverage.model_dump(mode="json")
    inconsistent_counts["tests_executed"] = 2
    with pytest.raises(ValidationError, match="must match nested audited-suite evidence"):
        SolidityCoverage.model_validate(inconsistent_counts)
    missing_nested_evidence = coverage.model_dump(mode="json")
    missing_nested_evidence["audited_suite_coverage"] = None
    with pytest.raises(ValidationError, match="must exactly match nested audited-suite evidence"):
        SolidityCoverage.model_validate(missing_nested_evidence)
    missing_quality_metric = coverage.model_dump(mode="json")
    del missing_quality_metric["quality_metrics"]["audited_suite_function_statement_coverage"]
    with pytest.raises(ValidationError, match="quality metrics must exactly match"):
        SolidityCoverage.model_validate(missing_quality_metric)

    tampered = evidence.model_copy(update={"coverage_artifact_sha256": "7" * 64})
    with pytest.raises(ValidationError, match="evidence hash does not match"):
        build_solidity_coverage(
            discovery=discovery,
            projects=projects,
            compilations=[],
            index=build.index,
            graphs=graphs,
            scanner_runs=[run],
            audited_suite_statement_evidence=[tampered],
        )


@pytest.mark.asyncio
async def test_synthetic_process_sealed_complete_statement_population_projects_exact_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    partition = partition_audited_source_entities(index=build.index, projects=projects)
    source_entity_ids = {
        *partition.contract_entity_ids,
        *partition.function_entity_ids,
    }
    base_run, _ = _self_authored_repository_suite_run()
    source_entities = sorted(
        (item for item in build.index.entities if item.id in source_entity_ids),
        key=lambda item: item.id,
    )
    function_evidence = [
        _covered_statement_evidence(
            entity,
            base_run,
            covered=not (entity.contract_name == "Vault" and entity.name == "withdraw"),
        )
        for entity in source_entities
        if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
    ]
    contract_evidence: list[AuditedSuiteStatementCoverageEvidence] = []
    for contract in (
        entity
        for entity in source_entities
        if entity.kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    ):
        covered_spans = {
            (statement.start_byte_offset, statement.end_byte_offset): statement.covered
            for function in function_evidence
            if function.location.path == contract.path and function.contract_name == contract.name
            for statement in function.statements
        }
        contract_evidence.append(
            _covered_statement_evidence(
                contract,
                base_run,
                covered=True,
                covered_spans=covered_spans,
            )
        )
    evidence = sorted(
        [*contract_evidence, *function_evidence],
        key=lambda item: (item.entity_id, item.evidence_sha256),
    )

    def reseal_with_statements(
        item: AuditedSuiteStatementCoverageEvidence,
        statements: list[AuditedSuiteStatementObservation],
    ) -> AuditedSuiteStatementCoverageEvidence:
        values = item.model_dump(
            mode="python",
            exclude={
                "evidence_sha256",
                "statement_status",
                "statement_count",
                "covered_statement_count",
            },
        )
        covered_count = sum(statement.covered for statement in statements)
        values.update(
            {
                "location": item.location,
                "statement_status": (
                    AuditedSuiteStatementStatus.COVERED
                    if covered_count == len(statements)
                    else AuditedSuiteStatementStatus.UNCOVERED
                ),
                "statement_count": len(statements),
                "covered_statement_count": covered_count,
                "statements": statements,
            }
        )
        return AuditedSuiteStatementCoverageEvidence.sealed(**values)

    target_function = next(
        item
        for item in function_evidence
        if item.contract_name == "Vault" and item.location.symbol == "withdraw(uint256)"
    )
    target_contract = next(item for item in contract_evidence if item.contract_name == "Vault")
    target_span = (
        target_function.statements[0].start_byte_offset,
        target_function.statements[0].end_byte_offset,
    )
    target_contract_statement = next(
        statement
        for statement in target_contract.statements
        if (statement.start_byte_offset, statement.end_byte_offset) == target_span
    )
    conflicting_contract = reseal_with_statements(
        target_contract,
        [
            (
                statement.model_copy(update={"covered": not statement.covered})
                if statement is target_contract_statement
                else statement
            )
            for statement in target_contract.statements
        ],
    )
    incomplete_contract = reseal_with_statements(
        target_contract,
        [
            statement
            for statement in target_contract.statements
            if statement is not target_contract_statement
        ],
    )
    partial_overlap_location = target_contract_statement.location
    partial_overlap_statement = AuditedSuiteStatementObservation(
        statement_id=AuditedSuiteStatementObservation.calculate_statement_id(
            location=partial_overlap_location,
            start_byte_offset=target_contract_statement.start_byte_offset - 1,
            end_byte_offset=target_contract_statement.end_byte_offset,
        ),
        location=partial_overlap_location,
        start_byte_offset=target_contract_statement.start_byte_offset - 1,
        end_byte_offset=target_contract_statement.end_byte_offset,
        covered=target_contract_statement.covered,
    )
    partial_overlap_contract = reseal_with_statements(
        target_contract,
        [
            partial_overlap_statement if statement is target_contract_statement else statement
            for statement in target_contract.statements
        ],
    )
    sealed_result = _run_with_statement_evidence(base_run, evidence)
    selection = sealed_result.repository_suite_selection
    policy = sealed_result.repository_suite_execution_policy
    assert selection is not None
    assert policy is not None
    manifest_dir = tmp_path / "manifest"
    manifest_dir.mkdir()
    manifest_path = _write_repository_suite_manifest(
        manifest_dir,
        selection,
        None,
        None,
        policy,
        sealed_result.repository_test_executions,
        statement_coverage_evidence=evidence,
        deadline=time.monotonic() + 5,
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1.1"
    assert manifest["repository_statement_coverage_evidence"] == [
        item.model_dump(mode="json") for item in evidence
    ]
    constrained_policy_values = policy.model_dump(mode="python", exclude={"policy_sha256"})
    constrained_policy_values.update(
        {
            "max_output_bytes_per_test": 1_024,
            "max_total_output_bytes": 1_024,
        }
    )
    constrained_policy = RepositorySuiteExecutionPolicy.sealed(**constrained_policy_values)
    overflow_dir = tmp_path / "manifest-overflow"
    overflow_dir.mkdir()
    with pytest.raises(FoundryInventoryOverflowError, match="complete artifact byte budget"):
        _write_repository_suite_manifest(
            overflow_dir,
            selection,
            None,
            None,
            constrained_policy,
            sealed_result.repository_test_executions,
            statement_coverage_evidence=evidence,
            deadline=time.monotonic() + 5,
        )
    assert not (overflow_dir / "repository-suite-execution.json").exists()
    aggregate_overflow_dir = tmp_path / "manifest-aggregate-overflow"
    aggregate_overflow_dir.mkdir()
    with pytest.raises(FoundryInventoryOverflowError, match="complete artifact byte budget"):
        _write_repository_suite_manifest(
            aggregate_overflow_dir,
            selection,
            None,
            None,
            policy,
            sealed_result.repository_test_executions,
            statement_coverage_evidence=evidence,
            previously_charged_artifact_bytes=policy.max_total_output_bytes,
            deadline=time.monotonic() + 5,
        )
    assert not (aggregate_overflow_dir / "repository-suite-execution.json").exists()
    run, runner, _ = await _runner_authorized_repository_suite_run(
        tmp_path=tmp_path / "runtime",
        monkeypatch=monkeypatch,
        config=config,
        result_override=sealed_result,
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[run],
        expected_repository_sha256="b" * 64,
    )
    audited = coverage.audited_suite_coverage
    assert audited is not None
    assert audited.statement_coverage_authority == "comparison_only"
    assert any("comparison-only durable projection" in item for item in audited.limitations)
    forged_authority = audited.model_dump(mode="json")
    forged_authority["statement_coverage_authority"] = "runtime_authoritative"
    with pytest.raises(ValidationError):
        AuditedSuiteCoverage.model_validate(forged_authority)
    assert audited.repository_tests_selected == 1
    assert audited.repository_tests_executed == 1
    assert audited.repository_tests_failed == 0
    assert audited.contract_statement_coverage.state is AnalysisState.DETERMINISTIC
    assert audited.function_statement_coverage.state is AnalysisState.DETERMINISTIC
    assert (
        audited.contract_statement_coverage.numerator,
        audited.contract_statement_coverage.denominator,
    ) == (1, 2)
    assert (
        audited.function_statement_coverage.numerator,
        audited.function_statement_coverage.denominator,
    ) == (2, 3)
    assert CoverageProvenance.RUNTIME in audited.contract_statement_coverage.provenance
    assert CoverageProvenance.RUNTIME in audited.function_statement_coverage.provenance
    assert all(
        surface.statement_status
        in {
            AuditedSuiteStatementStatus.COVERED,
            AuditedSuiteStatementStatus.UNCOVERED,
        }
        and len(surface.statement_evidence_sha256s) == 1
        and surface.repository_test_execution_sha256s
        for surface in audited.surfaces
    )
    withdraw = next(
        surface
        for surface in audited.surfaces
        if surface.contract_name == "Vault"
        and surface.entity_kind is SolidityEntityKind.FUNCTION
        and surface.location.symbol == "withdraw(uint256)"
    )
    assert withdraw.statement_status is AuditedSuiteStatementStatus.UNCOVERED
    assert SolidityCoverage.model_validate_json(coverage.model_dump_json()) == coverage
    legacy_analyzed = audited.model_dump(mode="json")
    legacy_analyzed["schema_version"] = "1.0"
    legacy_analyzed.pop("statement_coverage_authority")
    with pytest.raises(ValidationError, match=r"1\.0 cannot carry analyzed statement evidence"):
        AuditedSuiteCoverage.model_validate(legacy_analyzed)

    for label, inconsistent_contract in (
        ("conflicting-contract-hit", conflicting_contract),
        ("incomplete-contract-inventory", incomplete_contract),
        ("partial-contract-function-overlap", partial_overlap_contract),
    ):
        inconsistent_evidence = [
            inconsistent_contract if item.entity_id == target_contract.entity_id else item
            for item in evidence
        ]
        inconsistent_result = _run_with_statement_evidence(base_run, inconsistent_evidence)
        inconsistent_run, _inconsistent_runner, _ = await _runner_authorized_repository_suite_run(
            tmp_path=tmp_path / label,
            monkeypatch=monkeypatch,
            config=config,
            result_override=inconsistent_result,
        )
        inconsistent = build_solidity_coverage(
            discovery=discovery,
            projects=projects,
            compilations=[],
            index=build.index,
            graphs=graphs,
            scanner_runs=[inconsistent_run],
            expected_repository_sha256="b" * 64,
        )
        assert inconsistent.audited_suite_coverage is not None
        assert all(
            surface.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
            for surface in inconsistent.audited_suite_coverage.surfaces
        )
        assert any(
            "contract/function population hierarchy" in limitation
            for limitation in inconsistent.audited_suite_coverage.limitations
        )

    compiler_entity_id = next(iter(sorted(source_entity_ids)))
    fallback_index = build.index.model_copy(
        update={
            "entities": [
                (
                    entity.model_copy(
                        update={
                            "provenance": SolidityProvenance.FALLBACK,
                            "confidence": 0.7,
                            "transformation": "synthetic.fallback",
                        }
                    )
                    if entity.id == compiler_entity_id
                    else entity
                )
                for entity in build.index.entities
            ]
        }
    )
    fallback_projection = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=fallback_index,
        graphs=graphs,
        scanner_runs=[run],
        expected_repository_sha256="b" * 64,
    )
    assert fallback_projection.audited_suite_coverage is not None
    assert all(
        surface.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
        for surface in fallback_projection.audited_suite_coverage.surfaces
    )
    assert any(
        "compiler-derived audited-source entity byte ranges" in limitation
        for limitation in fallback_projection.audited_suite_coverage.limitations
    )

    serialized_run = ScannerRun.model_validate_json(run.model_dump_json())
    untrusted = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[serialized_run],
        expected_repository_sha256="b" * 64,
    )
    assert untrusted.audited_suite_coverage is not None
    assert all(
        surface.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
        for surface in untrusted.audited_suite_coverage.surfaces
    )
    authority = _install_synthetic_runtime_authority(monkeypatch)
    preserved = authority.validated_copy(run)
    assert authority.contains(preserved)
    tampered_evidence: list[AuditedSuiteStatementCoverageEvidence] = []
    for item in evidence:
        tampered_values = item.model_dump(mode="python", exclude={"evidence_sha256"})
        tampered_values.update(
            {
                "location": item.location,
                "statements": item.statements,
                "coverage_artifact_sha256": "f" * 64,
            }
        )
        tampered_evidence.append(AuditedSuiteStatementCoverageEvidence.sealed(**tampered_values))
    publicly_resealed = _run_with_statement_evidence(run, tampered_evidence)
    assert not authority.contains(publicly_resealed)
    resealed_coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[publicly_resealed],
        expected_repository_sha256="b" * 64,
    )
    assert resealed_coverage.audited_suite_coverage is not None
    assert all(
        surface.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
        for surface in resealed_coverage.audited_suite_coverage.surfaces
    )
    incomplete_result = _run_with_statement_evidence(base_run, evidence[:-1])
    incomplete_run, incomplete_runner, _ = await _runner_authorized_repository_suite_run(
        tmp_path=tmp_path / "incomplete-runtime",
        monkeypatch=monkeypatch,
        config=config,
        result_override=incomplete_result,
    )
    incomplete = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[incomplete_run],
        expected_repository_sha256="b" * 64,
    )
    assert incomplete.audited_suite_coverage is not None
    assert all(
        surface.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
        for surface in incomplete.audited_suite_coverage.surfaces
    )
    assert any(
        "complete exact audited-source entity population" in limitation
        for limitation in incomplete.audited_suite_coverage.limitations
    )
    mixed_projections: list[dict[str, object]] = []
    for scanner_runs in ([run, incomplete_run], [incomplete_run, run]):
        mixed = build_solidity_coverage(
            discovery=discovery,
            projects=projects,
            compilations=[],
            index=build.index,
            graphs=graphs,
            scanner_runs=scanner_runs,
            expected_repository_sha256="b" * 64,
        )
        assert mixed.audited_suite_coverage is not None
        assert all(
            surface.statement_status is AuditedSuiteStatementStatus.NOT_ANALYZED
            for surface in mixed.audited_suite_coverage.surfaces
        )
        assert any(
            "complete exact audited-source entity population" in limitation
            for limitation in mixed.audited_suite_coverage.limitations
        )
        mixed_projections.append(mixed.audited_suite_coverage.model_dump(mode="json"))
    assert mixed_projections[0] == mixed_projections[1]
    assert incomplete_runner.backend is not None
    assert runner.backend is not None


def test_statement_evidence_rejects_inconsistent_denominators(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    withdraw = next(
        entity
        for entity in build.index.entities
        if entity.contract_name == "Vault" and entity.name == "withdraw"
    )
    run, _ = _self_authored_repository_suite_run()
    evidence = _covered_statement_evidence(withdraw, run)
    common = evidence.model_dump(
        mode="python",
        exclude={"evidence_sha256"},
    )
    common["location"] = evidence.location
    common["statements"] = evidence.statements

    with pytest.raises(ValidationError):
        AuditedSuiteStatementCoverageEvidence.sealed(
            **{
                **common,
                "statement_count": 0,
                "covered_statement_count": 0,
            }
        )
    with pytest.raises(ValidationError, match="counts must be derived"):
        AuditedSuiteStatementCoverageEvidence.sealed(
            **{
                **common,
                "statement_status": AuditedSuiteStatementStatus.COVERED,
                "covered_statement_count": 2,
            }
        )


def test_statement_evidence_explicitly_marks_an_exact_empty_inventory_vacuously_covered(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    entity = next(
        item
        for item in build.index.entities
        if item.contract_name == "Vault" and item.name == "withdraw"
    )
    run, _ = _self_authored_repository_suite_run()
    evidence = _covered_statement_evidence(entity, run)
    values = evidence.model_dump(mode="python", exclude={"evidence_sha256"})
    values.update(
        {
            "location": evidence.location,
            "statement_status": AuditedSuiteStatementStatus.COVERED,
            "statement_count": 0,
            "covered_statement_count": 0,
            "statements": [],
        }
    )

    empty = AuditedSuiteStatementCoverageEvidence.sealed(**values)

    assert empty.statement_status is AuditedSuiteStatementStatus.COVERED
    assert empty.statement_count == empty.covered_statement_count == 0
    assert empty.empty_statement_inventory_policy == ("vacuously_covered_exact_empty_inventory")
    with pytest.raises(ValidationError, match="statement status differs"):
        AuditedSuiteStatementCoverageEvidence.sealed(
            **{
                **values,
                "statement_status": AuditedSuiteStatementStatus.UNCOVERED,
            }
        )


@pytest.mark.parametrize("bad_sha256", ["0" * 63, "0" * 65, "g" * 64])
def test_statement_evidence_rejects_noncanonical_coverage_command_hashes(
    tmp_path: Path,
    config_factory,
    bad_sha256: str,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    entity = next(
        item
        for item in build.index.entities
        if item.contract_name == "Vault" and item.name == "withdraw"
    )
    run, _ = _self_authored_repository_suite_run()
    evidence = _covered_statement_evidence(entity, run)
    values = evidence.model_dump(mode="python", exclude={"evidence_sha256"})
    values["location"] = evidence.location
    values["statements"] = evidence.statements
    values["coverage_command_sha256s"] = [bad_sha256]

    with pytest.raises(ValidationError):
        AuditedSuiteStatementCoverageEvidence.sealed(**values)


@pytest.mark.parametrize(
    "execution_status",
    [
        RepositoryTestExecutionStatus.TIMED_OUT,
        RepositoryTestExecutionStatus.INVALID_OUTPUT,
    ],
)
def test_self_authored_incomplete_repository_test_attempts_earn_no_runtime_credit(
    tmp_path: Path,
    config_factory,
    execution_status: RepositoryTestExecutionStatus,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    run, _ = _self_authored_repository_suite_run(execution_status=execution_status)

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=None,
        scanner_runs=[run],
    )

    assert coverage.tests_executed == 0
    assert coverage.tests_failed == 0
    assert coverage.audited_suite_coverage is not None
    assert coverage.audited_suite_coverage.repository_tests_selected == 0
    assert coverage.audited_suite_coverage.repository_tests_executed == 0
    assert coverage.audited_suite_coverage.repository_tests_failed == 0


@pytest.mark.asyncio
async def test_repeated_runtime_outcomes_use_one_logical_test_identity_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    passed, passed_runner, _ = await _runner_authorized_repository_suite_run(
        tmp_path=tmp_path / "passed",
        monkeypatch=monkeypatch,
        config=config,
    )
    failed, failed_runner, _ = await _runner_authorized_repository_suite_run(
        tmp_path=tmp_path / "failed",
        monkeypatch=monkeypatch,
        config=config,
        execution_status=RepositoryTestExecutionStatus.TIMED_OUT,
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=None,
        scanner_runs=[passed, failed],
        expected_repository_sha256="b" * 64,
    )

    assert coverage.tests_executed == 1
    assert coverage.tests_failed == 1
    assert coverage.audited_suite_coverage is not None
    assert coverage.audited_suite_coverage.repository_tests_selected == 1
    assert coverage.audited_suite_coverage.repository_tests_executed == 1
    assert coverage.audited_suite_coverage.repository_tests_failed == 1
    assert passed_runner.backend is not None
    assert failed_runner.backend is not None

    cross_repository = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=None,
        scanner_runs=[passed],
        expected_repository_sha256="c" * 64,
    )
    assert cross_repository.tests_executed == 0
    assert cross_repository.tests_failed == 0
    assert cross_repository.audited_suite_coverage is not None
    assert cross_repository.audited_suite_coverage.repository_tests_selected == 0
    assert any(
        "selection evidence for the exact current repository was not produced" in limitation
        for limitation in cross_repository.audited_suite_coverage.limitations
    )

    unbound_repository = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=None,
        scanner_runs=[passed],
    )
    assert unbound_repository.tests_executed == 0
    assert unbound_repository.audited_suite_coverage is not None
    assert any(
        "lacks an exact current-repository identity" in limitation
        for limitation in unbound_repository.audited_suite_coverage.limitations
    )


def _mutation_evidence_inputs(
    *,
    entity: SolidityEntity,
    source_file_sha256: str,
    source_repository_sha256: str = "b" * 64,
    mutant_status: MutationSuiteTestStatus = MutationSuiteTestStatus.FAILED,
) -> tuple[
    MutationApplicabilityPlan,
    MutationCampaignEvidence,
    AuditedSuiteMutationSurfaceEvidence,
]:
    property_id = f"prop-{'1' * 24}"
    specification = SourceMutationSpec(
        id="mut-accounting-operator",
        kind=MutationKind.ACCOUNTING_OPERATOR_REPLACEMENT,
        path=entity.path,
        line=25,
        expected_file_sha256=source_file_sha256,
        expected_line="        balances[to] -= amount;",
        original_operator="-",
        replacement_operator="+",
    )
    plan = MutationApplicabilityPlan.sealed(
        property_corpus_hash="8" * 64,
        source_repository_sha256=source_repository_sha256,
        approved_executor_sha256="9" * 64,
        approved_isolation_policy_sha256="a" * 64,
        property_repositories={property_id: "synthetic"},
        specifications=[specification],
        bindings=[
            MutationApplicabilityBinding(
                property_id=property_id,
                mutation_id=specification.id,
                test_ids=["testCoverage"],
            )
        ],
        kind_accounting=[
            MutationKindAccounting(
                kind=kind,
                status=(
                    MutationKindInventoryStatus.CANDIDATES_DECLARED
                    if kind is specification.kind
                    else MutationKindInventoryStatus.NO_CANDIDATE_DECLARED
                ),
                candidate_count=int(kind is specification.kind),
                candidate_ids=[specification.id] if kind is specification.kind else [],
                limitation=(
                    None
                    if kind is specification.kind
                    else "synthetic fixture has no candidate for this implemented class"
                ),
            )
            for kind in sorted(MutationKind, key=lambda item: item.value)
        ],
    )
    observation = MutationSuiteObservation.sealed(
        mutation_id=specification.id,
        baseline_source_sha256=source_repository_sha256,
        mutant_source_sha256="c" * 64,
        suite_selection_sha256=MutationSuiteObservation.calculate_selection_sha256(
            ["testCoverage"]
        ),
        executor_sha256=plan.approved_executor_sha256,
        isolation_policy_sha256=plan.approved_isolation_policy_sha256,
        baseline_execution_evidence=ExecutionEvidenceKind.REAL,
        mutant_execution_evidence=ExecutionEvidenceKind.REAL,
        baseline_isolation_attestation_sha256="d" * 64,
        mutant_isolation_attestation_sha256="e" * 64,
        baseline_compilation_succeeded=True,
        mutant_compilation_succeeded=True,
        baseline_tests=[
            MutationSuiteTestObservation(
                test_id="testCoverage",
                status=MutationSuiteTestStatus.PASSED,
            )
        ],
        mutant_tests=[
            MutationSuiteTestObservation(
                test_id="testCoverage",
                status=mutant_status,
            )
        ],
    )
    campaign = MutationCampaignEvidence.sealed(
        plan_sha256=plan.plan_sha256,
        mutation_id=specification.id,
        mutation_specification_sha256=specification.specification_sha256(),
        source_repository_sha256=source_repository_sha256,
        pristine_workspace_sha256=source_repository_sha256,
        mutated_workspace_sha256="c" * 64,
        restored_workspace_sha256=source_repository_sha256,
        executor_observation=observation,
        restoration_verified=True,
        workspace_disposed=True,
        source_preserved=True,
        disposal_entry_count=1,
        failure_kind=None,
    )
    binding = AuditedSuiteMutationSurfaceEvidence.sealed(
        entity_id=entity.id,
        entity_kind=entity.kind,
        contract_name=entity.contract_name or entity.name,
        location=Location(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            symbol=entity.signature or entity.name,
            content_hash=entity.source_hash,
        ),
        property_id=property_id,
        mutation_id=specification.id,
    )
    return plan, campaign, binding


@pytest.mark.asyncio
async def test_runner_observed_mutation_campaign_is_inconclusive_and_gap_evidence_is_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    withdraw_internal = next(
        entity
        for entity in build.index.entities
        if entity.contract_name == "Vault" and entity.name == "_withdraw"
    )
    source_file_sha256 = next(
        item.sha256 for item in discovery.files if item.relative_path == "src/Vault.sol"
    )
    plan, campaign, binding = _mutation_evidence_inputs(
        entity=withdraw_internal,
        source_file_sha256=source_file_sha256,
    )
    run, runner, _ = await _runner_authorized_repository_suite_run(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config=config,
    )

    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[run],
        audited_suite_mutation_plan=plan,
        audited_suite_mutation_campaigns=[campaign],
        audited_suite_mutation_surface_evidence=[binding],
        expected_repository_sha256="b" * 64,
    )
    audited = coverage.audited_suite_coverage
    assert audited is not None
    surface = next(item for item in audited.surfaces if item.entity_id == withdraw_internal.id)
    assert surface.assertion_status is AuditedSuiteAssertionStatus.INCONCLUSIVE
    assert len(surface.mutation_evidence) == 1
    joined = surface.mutation_evidence[0]
    assert joined.outcome is AuditedSuiteMutationOutcome.INCONCLUSIVE
    assert joined.evidence_origin == "planned_unattested"
    assert joined.plan_sha256 == plan.plan_sha256
    assert joined.source_repository_sha256 == plan.source_repository_sha256
    assert joined.mutation_specification_sha256 == (plan.specifications[0].specification_sha256())
    assert joined.campaign_evidence_sha256 == campaign.evidence_sha256
    assert joined.observation_sha256 == campaign.executor_observation.observation_sha256
    assert joined.surface_binding_sha256 == binding.evidence_sha256
    gap = next(item for item in audited.gaps if item.entity_id == withdraw_internal.id)
    assert gap.kind is AuditedSuiteCoverageGapKind.ASSERTION_INCONCLUSIVE
    assert gap.evidence_sha256s == [joined.evidence_sha256]
    assert not gap.is_finding
    decisive_values = joined.model_dump(mode="python", exclude={"evidence_sha256"})
    decisive_values["outcome"] = AuditedSuiteMutationOutcome.KILLED
    with pytest.raises(ValidationError, match="cannot carry a decisive outcome"):
        AuditedSuiteMutationEvidence.sealed(**decisive_values)
    forged_contract_values = surface.model_dump(mode="python")
    forged_contract_values["entity_kind"] = SolidityEntityKind.CONTRACT
    with pytest.raises(ValidationError, match="contract-level"):
        AuditedSuiteSurfaceCoverage.model_validate(forged_contract_values)
    assert runner.backend is not None

    payload = audited.model_dump(mode="json")
    gap_payload = next(
        item for item in payload["gaps"] if item["entity_id"] == withdraw_internal.id
    )
    gap_payload["evidence_sha256s"] = ["f" * 64]
    with pytest.raises(
        ValidationError,
        match="gap evidence must exactly equal its surface evidence",
    ):
        AuditedSuiteCoverage.model_validate(payload)


@pytest.mark.asyncio
async def test_mutation_binding_revalidates_every_hash_and_source_join(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)
    withdraw_internal = next(
        entity
        for entity in build.index.entities
        if entity.contract_name == "Vault" and entity.name == "_withdraw"
    )
    source_file_sha256 = next(
        item.sha256 for item in discovery.files if item.relative_path == "src/Vault.sol"
    )
    plan, campaign, binding = _mutation_evidence_inputs(
        entity=withdraw_internal,
        source_file_sha256=source_file_sha256,
    )
    run, runner, _ = await _runner_authorized_repository_suite_run(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config=config,
    )
    common = {
        "discovery": discovery,
        "projects": projects,
        "compilations": [],
        "index": build.index,
        "graphs": graphs,
        "scanner_runs": [run],
        "audited_suite_mutation_plan": plan,
        "audited_suite_mutation_campaigns": [campaign],
        "expected_repository_sha256": "b" * 64,
    }

    forged_hash = binding.model_copy(update={"evidence_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="surface evidence hash does not match"):
        build_solidity_coverage(
            **common,
            audited_suite_mutation_surface_evidence=[forged_hash],
        )

    random_declaration = AuditedSuiteMutationSurfaceEvidence.model_construct(
        entity_id=binding.entity_id,
        entity_kind=binding.entity_kind,
        contract_name=binding.contract_name,
        location=binding.location,
        property_id=binding.property_id,
        mutation_id=binding.mutation_id,
        evidence_sha256="0" * 64,
    )
    with pytest.raises(ValidationError, match="surface evidence hash does not match"):
        build_solidity_coverage(
            **common,
            audited_suite_mutation_surface_evidence=[random_declaration],
        )

    other_function = next(
        entity
        for entity in build.index.entities
        if entity.contract_name == "Vault" and entity.name == "withdraw"
    )
    duplicate_pair_binding = AuditedSuiteMutationSurfaceEvidence.sealed(
        entity_id=other_function.id,
        entity_kind=other_function.kind,
        contract_name=other_function.contract_name or other_function.name,
        location=Location(
            path=other_function.path,
            start_line=other_function.start_line,
            end_line=other_function.end_line,
            symbol=other_function.signature or other_function.name,
            content_hash=other_function.source_hash,
        ),
        property_id=binding.property_id,
        mutation_id=binding.mutation_id,
    )
    with pytest.raises(ValueError, match="must bind exactly one source surface"):
        build_solidity_coverage(
            **common,
            audited_suite_mutation_surface_evidence=sorted(
                [binding, duplicate_pair_binding],
                key=lambda item: (item.entity_id, item.property_id, item.mutation_id),
            ),
        )

    wrong_file_plan, wrong_file_campaign, wrong_file_binding = _mutation_evidence_inputs(
        entity=withdraw_internal,
        source_file_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="does not bind the exact discovered file"):
        build_solidity_coverage(
            **{
                **common,
                "audited_suite_mutation_plan": wrong_file_plan,
                "audited_suite_mutation_campaigns": [wrong_file_campaign],
            },
            audited_suite_mutation_surface_evidence=[wrong_file_binding],
        )

    no_observation_values = campaign.model_dump(
        mode="python",
        exclude={"evidence_sha256", "executor_observation"},
    )
    no_observation_values.update(
        {
            "executor_observation": None,
            "failure_kind": "MissingObservation",
        }
    )
    no_observation = MutationCampaignEvidence.sealed(**no_observation_values)
    without_observation = build_solidity_coverage(
        **{
            **common,
            "audited_suite_mutation_campaigns": [no_observation],
        },
        audited_suite_mutation_surface_evidence=[binding],
    )
    audited_without_observation = without_observation.audited_suite_coverage
    assert audited_without_observation is not None
    surface_without_observation = next(
        item
        for item in audited_without_observation.surfaces
        if item.entity_id == withdraw_internal.id
    )
    assert surface_without_observation.mutation_evidence == []
    assert surface_without_observation.assertion_status is (
        AuditedSuiteAssertionStatus.NOT_ANALYZED
    )
    assert any(
        "lacks an exact execution observation" in limitation
        for limitation in audited_without_observation.limitations
    )

    wrong_repository_plan, wrong_repository_campaign, wrong_repository_binding = (
        _mutation_evidence_inputs(
            entity=withdraw_internal,
            source_file_sha256=source_file_sha256,
            source_repository_sha256="d" * 64,
        )
    )
    wrong_repository = build_solidity_coverage(
        **{
            **common,
            "audited_suite_mutation_plan": wrong_repository_plan,
            "audited_suite_mutation_campaigns": [wrong_repository_campaign],
        },
        audited_suite_mutation_surface_evidence=[wrong_repository_binding],
    )
    audited = wrong_repository.audited_suite_coverage
    assert audited is not None
    surface = next(item for item in audited.surfaces if item.entity_id == withdraw_internal.id)
    assert surface.assertion_status is AuditedSuiteAssertionStatus.NOT_ANALYZED
    assert surface.mutation_evidence == []
    assert any(
        "lacks a matching validated real repository-suite execution" in limitation
        for limitation in audited.limitations
    )
    assert runner.backend is not None


def test_missing_source_and_critical_classification_fail_closed(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    graphs = build_solidity_graphs(discovery, build)

    missing_projects = build_solidity_coverage(
        discovery=discovery,
        projects=[],
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
    )
    audited = missing_projects.audited_suite_coverage
    assert audited is not None
    assert not audited.source_classification_complete
    assert not audited.critical_classification_complete
    assert audited.surfaces == []
    assert audited.gaps == []
    assert (
        audited.contract_statement_coverage.population,
        audited.contract_statement_coverage.denominator,
        len(audited.contract_statement_coverage.exclusions),
    ) == (3, 0, 3)
    assert (
        audited.function_statement_coverage.population,
        audited.function_statement_coverage.denominator,
        len(audited.function_statement_coverage.exclusions),
    ) == (5, 0, 5)
    assert audited.contract_statement_coverage.failures
    assert audited.function_statement_coverage.failures
    assert audited.critical_function_assertion_coverage.failures
    assert not audited.contract_statement_coverage.not_applicable_evidence
    assert not audited.function_statement_coverage.not_applicable_evidence
    assert any(item.startswith("source classification incomplete:") for item in audited.limitations)
    assert any(
        item.startswith("critical classification incomplete:") for item in audited.limitations
    )

    partition = partition_audited_source_entities(
        index=build.index,
        projects=projects,
    )
    incomplete_critical = build_solidity_coverage(
        discovery=discovery,
        projects=projects,
        compilations=[],
        index=build.index,
        graphs=graphs,
        scanner_runs=[],
    ).audited_suite_coverage
    assert incomplete_critical is not None
    assert not incomplete_critical.critical_classification_complete
    assert {
        surface.entity_id
        for surface in incomplete_critical.surfaces
        if surface.critical
        and surface.entity_kind
        in {
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
        }
    } == set(partition.function_entity_ids)


def test_audited_suite_schema_requires_explicit_classification_and_bounded_counts(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    coverage = build_solidity_coverage(
        discovery=discovery,
        projects=[],
        compilations=[],
        index=build.index,
        graphs=None,
        scanner_runs=[],
    ).audited_suite_coverage
    assert coverage is not None
    payload = coverage.model_dump(mode="json")

    for field in ("source_classification_complete", "critical_classification_complete"):
        omitted = {key: value for key, value in payload.items() if key != field}
        with pytest.raises(ValidationError, match=field):
            AuditedSuiteCoverage.model_validate(omitted)

    with pytest.raises(
        ValidationError,
        match="executed repository tests cannot exceed selected repository tests",
    ):
        AuditedSuiteCoverage.model_validate(
            {
                **payload,
                "repository_tests_selected": 0,
                "repository_tests_executed": 1,
            }
        )


def test_conventional_test_paths_remain_excluded_when_metadata_is_incomplete(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "foundry"
    shutil.copytree(FIXTURE, root)
    config = config_factory(language_profile="solidity-evm")
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [root / "out"])
    project = projects[0].model_copy(update={"test_directories": []})
    index = build.index.model_copy(update={"projects": [project]})

    partition = partition_audited_source_entities(index=index, projects=[project])

    assert not partition.classification_complete
    assert all(
        not entity_id.startswith("test/")
        for entity_id in (*partition.contract_entity_ids, *partition.function_entity_ids)
    )
    excluded_subjects = {
        exclusion.subject
        for exclusion in (*partition.contract_exclusions, *partition.function_exclusions)
    }
    test_entity_ids = {
        entity.id
        for entity in index.entities
        if entity.path.startswith("test/")
        and entity.kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
        }
    }
    assert test_entity_ids
    assert test_entity_ids <= excluded_subjects
    assert any("conventional test path" in item for item in partition.limitations)

    source_entity = next(
        entity
        for entity in index.entities
        if entity.path == "src/Vault.sol"
        and entity.kind in {SolidityEntityKind.CONTRACT, SolidityEntityKind.FUNCTION}
    )
    unsafe_entity = source_entity.model_copy(update={"path": "../test/Poison.sol"})
    unsafe_index = index.model_copy(
        update={
            "entities": [
                unsafe_entity if entity.id == source_entity.id else entity
                for entity in index.entities
            ]
        }
    )
    unsafe_partition = partition_audited_source_entities(
        index=unsafe_index,
        projects=[project],
    )
    assert not unsafe_partition.classification_complete
    assert source_entity.id not in {
        *unsafe_partition.contract_entity_ids,
        *unsafe_partition.function_entity_ids,
    }
    assert source_entity.id in {
        exclusion.subject
        for exclusion in (
            *unsafe_partition.contract_exclusions,
            *unsafe_partition.function_exclusions,
        )
    }

    no_source_project = project.model_copy(update={"source_directories": []})
    no_source_index = index.model_copy(update={"projects": [no_source_project]})
    no_source_partition = partition_audited_source_entities(
        index=no_source_index,
        projects=[no_source_project],
    )
    assert not no_source_partition.classification_complete
    assert any(
        "declare no audited source directory" in limitation
        for limitation in no_source_partition.limitations
    )

    invalid_project = type(project).model_construct(source_directories=["src"])
    with pytest.raises(ValidationError):
        build_solidity_coverage(
            discovery=discovery,
            projects=[invalid_project],
            compilations=[],
            index=index,
            graphs=None,
            scanner_runs=[],
        )


def test_model_surface_gap_priority_preserves_stable_identity_and_is_non_vacuous() -> None:
    kind = ModelReviewSurfaceKind.ENTRY_POINT
    subject_id = "src/Vault.sol:Vault.withdraw(uint256)"
    surface_id = ModelSurfaceReviewRequest.calculate_surface_id(kind, subject_id)
    standard = ModelSurfaceReviewRequest(
        surface_id=surface_id,
        kind=kind,
        subject_id=subject_id,
        contract="Vault",
        function_or_state_surface="withdraw(uint256)",
        critical=True,
        allowed_symbols=("withdraw(uint256)",),
        invariant_considered="authorized withdrawals preserve accounted balances",
    )
    gap_id = f"audited-suite-gap:{'a' * 64}"
    elevated = standard.model_copy(
        update={
            "priority": ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP,
            "coverage_gap_ids": (gap_id,),
        }
    )
    elevated = ModelSurfaceReviewRequest.model_validate(elevated.model_dump(mode="json"))
    assert standard.priority is ModelSurfaceReviewPriority.STANDARD
    assert standard.coverage_gap_ids == ()
    assert elevated.surface_id == standard.surface_id
    assert elevated.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP
    assert elevated.coverage_gap_ids == (gap_id,)

    with pytest.raises(ValidationError, match="standard priority forbids"):
        ModelSurfaceReviewRequest.model_validate(
            {
                **standard.model_dump(mode="json"),
                "coverage_gap_ids": [gap_id],
            }
        )
    with pytest.raises(ValidationError, match="requires gap IDs"):
        ModelSurfaceReviewRequest.model_validate(
            {
                **standard.model_dump(mode="json"),
                "priority": ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP,
            }
        )

    zero_metric = CoverageMetric(
        numerator=0,
        denominator=0,
        population=0,
        percentage=None,
        exclusions=[],
        not_applicable_evidence=["no model review surfaces"],
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=[],
        state=AnalysisState.NOT_ANALYZED,
        detail="No applicable model review surfaces",
    )
    coverage = ModelReviewCoverage(
        applicable=True,
        critical_classification_complete=True,
        surfaces=[],
        overall=zero_metric,
        by_kind={kind: zero_metric for kind in ModelReviewSurfaceKind},
        critical=zero_metric,
        critical_gate_passed=False,
        limitations=[],
    )
    assert not coverage.critical_gate_passed
    with pytest.raises(ValidationError, match="gate does not match"):
        ModelReviewCoverage.model_validate(
            {
                **coverage.model_dump(mode="json"),
                "critical_gate_passed": True,
            }
        )
