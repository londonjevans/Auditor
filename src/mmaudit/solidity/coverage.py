"""Solidity coverage and audit-quality metadata."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    MutationCampaignEvidence,
    MutationScorecardEvidenceOrigin,
    MutationTestOutcome,
    score_planned_mutation_campaigns,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditedSuiteAssertionStatus,
    AuditedSuiteCoverage,
    AuditedSuiteCoverageGap,
    AuditedSuiteCoverageGapKind,
    AuditedSuiteMutationEvidence,
    AuditedSuiteMutationOutcome,
    AuditedSuiteMutationSurfaceEvidence,
    AuditedSuiteStatementCoverageEvidence,
    AuditedSuiteStatementStatus,
    AuditedSuiteSurfaceCoverage,
    CompilationStatus,
    CoverageExclusion,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    EconomicTemplateExecutionCoverage,
    ExecutionEvidenceKind,
    FormalToolRun,
    FormalToolStatus,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantReviewResult,
    InvariantSpec,
    InvariantSuite,
    Location,
    ModelReviewCoverage,
    RepositoryCodeExecutionState,
    RepositoryTestExecution,
    RepositoryTestExecutionStatus,
    ScannerRun,
    ScannerStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.scanners.runtime_evidence import (
    has_host_repository_suite_runtime_authority,
    validated_scanner_run_copy_preserving_runtime_authority,
)
from mmaudit.solidity.graphs import summarize_asset_flows, summarize_control_dependencies


@dataclass(frozen=True)
class AuditedSourceEntityPartition:
    """Pure source/test partition shared by coverage and model-priority accounting."""

    contract_entity_ids: tuple[str, ...]
    function_entity_ids: tuple[str, ...]
    contract_exclusions: tuple[CoverageExclusion, ...]
    function_exclusions: tuple[CoverageExclusion, ...]
    classification_complete: bool
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class AuditedInvariantEntityBinding:
    """Exact audited-source entities reached by one invariant declaration."""

    entity_ids: tuple[str, ...]
    audited: bool
    invalid: bool


@dataclass(frozen=True)
class AuditedEconomicEntityBinding:
    """Exact audited-source entities reached by one applicable economic plan."""

    entity_ids: tuple[str, ...]
    audited: bool
    invalid: bool


@dataclass(frozen=True)
class _AuditedFunctionPopulation:
    """One source-only function denominator with explicit non-source exclusions."""

    entity_ids: tuple[str, ...]
    exclusions: tuple[CoverageExclusion, ...]
    classification_complete: bool
    limitations: tuple[str, ...]


def partition_audited_source_entities(
    *,
    index: SoliditySymbolIndex,
    projects: list[SolidityProjectMetadata],
) -> AuditedSourceEntityPartition:
    """Partition source entities without treating incomplete project metadata as source."""

    index = SoliditySymbolIndex.model_validate(index.model_dump(mode="json"))
    projects = [
        SolidityProjectMetadata.model_validate(project.model_dump(mode="json"))
        for project in projects
    ]
    index_projects_match = index.projects == projects
    classification_projects = projects if index_projects_match else []

    contract_kinds = {
        SolidityEntityKind.CONTRACT,
        SolidityEntityKind.INTERFACE,
        SolidityEntityKind.LIBRARY,
    }
    function_kinds = {
        SolidityEntityKind.FUNCTION,
        SolidityEntityKind.CONSTRUCTOR,
    }
    contract_ids: list[str] = []
    function_ids: list[str] = []
    contract_exclusions: list[CoverageExclusion] = []
    function_exclusions: list[CoverageExclusion] = []
    limitations: set[str] = set()
    classification_complete = bool(classification_projects)
    if not index_projects_match:
        limitations.add(
            "source classification incomplete: symbol-index projects differ from supplied projects"
        )
    elif not projects:
        limitations.add("source classification incomplete: no Solidity project metadata")
    roots = [project.project_root for project in classification_projects]
    duplicate_roots = {root for root in roots if roots.count(root) > 1}
    if duplicate_roots:
        classification_complete = False
        limitations.add("source classification incomplete: duplicate Solidity project roots")
    if any(not _project_directories_are_safe(project) for project in classification_projects):
        classification_complete = False
        limitations.add(
            "source classification incomplete: one or more project directories are invalid "
            "or escape their project root"
        )
    if any(not project.source_directories for project in classification_projects):
        classification_complete = False
        limitations.add(
            "source classification incomplete: one or more projects declare no audited "
            "source directory"
        )
    for entity in sorted(index.entities, key=lambda item: item.id):
        if entity.kind not in contract_kinds | function_kinds:
            continue
        if not _classification_path_is_safe(entity.path, allow_root=False):
            classification_complete = False
            limitations.add(
                "source classification incomplete: indexed entity path is not a safe "
                "repository-relative path"
            )
            exclusion = CoverageExclusion(
                subject=entity.id,
                reason=f"{entity.path}: indexed entity path is unsafe",
                provenance=CoverageProvenance.SYMBOL_INDEX,
            )
            if entity.kind in contract_kinds:
                contract_exclusions.append(exclusion)
            else:
                function_exclusions.append(exclusion)
            continue
        owning_projects = [
            project
            for project in classification_projects
            if _path_is_within_directory(entity.path, project.project_root)
        ]
        if owning_projects:
            maximum_depth = max(
                _directory_depth(project.project_root) for project in owning_projects
            )
            owning_projects = [
                project
                for project in owning_projects
                if _directory_depth(project.project_root) == maximum_depth
            ]
        project = owning_projects[0] if len(owning_projects) == 1 else None
        project_directories_are_safe = project is not None and _project_directories_are_safe(
            project
        )
        non_source_directory = (
            next(
                (
                    directory
                    for directory in [
                        *project.test_directories,
                        *project.script_directories,
                        *project.deployment_directories,
                    ]
                    if _path_is_within_directory(entity.path, directory)
                ),
                None,
            )
            if project_directories_are_safe and project is not None
            else None
        )
        conventional_test_directory = (
            _conventional_test_directory(entity.path, project.project_root)
            if project is not None
            else None
        )
        in_source = (
            project_directories_are_safe
            and project is not None
            and bool(project.source_directories)
            and any(
                _path_is_within_directory(entity.path, directory)
                for directory in project.source_directories
            )
        )
        if non_source_directory is not None or conventional_test_directory is not None:
            directory = non_source_directory or conventional_test_directory
            assert directory is not None
            if conventional_test_directory is not None and non_source_directory is None:
                classification_complete = False
                limitations.add(
                    "source classification incomplete: conventional test path was absent "
                    "from project metadata"
                )
            exclusion = CoverageExclusion(
                subject=entity.id,
                reason=(
                    f"{entity.path}: indexed entity is declared under non-source "
                    f"project directory {directory}"
                ),
                provenance=CoverageProvenance.DISCOVERY,
            )
        elif not in_source:
            classification_complete = False
            if project is None:
                reason = "no unique owning Solidity project could be established"
            elif not project_directories_are_safe:
                reason = "project directories are invalid or escape the project root"
            elif not project.source_directories:
                reason = "owning project declares no audited source directory"
            else:
                reason = "entity is outside every declared audited source directory"
            limitations.add(f"source classification incomplete: {reason}")
            exclusion = CoverageExclusion(
                subject=entity.id,
                reason=f"{entity.path}: {reason}",
                provenance=CoverageProvenance.DISCOVERY,
            )
        else:
            if entity.kind in contract_kinds:
                contract_ids.append(entity.id)
            else:
                function_ids.append(entity.id)
            continue
        if entity.kind in contract_kinds:
            contract_exclusions.append(exclusion)
        else:
            function_exclusions.append(exclusion)
    return AuditedSourceEntityPartition(
        contract_entity_ids=tuple(sorted(contract_ids)),
        function_entity_ids=tuple(sorted(function_ids)),
        contract_exclusions=tuple(sorted(contract_exclusions, key=lambda item: item.subject)),
        function_exclusions=tuple(sorted(function_exclusions, key=lambda item: item.subject)),
        classification_complete=classification_complete,
        limitations=tuple(sorted(limitations)),
    )


def bind_invariant_to_audited_entities(
    *,
    invariant: InvariantSpec,
    entities: list[SolidityEntity],
    audited_entity_ids: set[str],
    exact_test_entity_ids: set[str],
    source_contents_by_path: dict[str, str] | None = None,
) -> AuditedInvariantEntityBinding:
    """Bind an invariant to exact current entities without admitting symbolic evidence.

    A direct entity ID is an exact index binding. A source location must identify one
    current entity by symbol and either carry a hash validated against current source
    bytes or equal that entity's complete range and hash. Pure test-only bindings are
    intentionally excluded without making source classification incomplete.
    """

    entities_by_id = {entity.id: entity for entity in entities}
    direct_ids = set(invariant.entity_ids)
    if not direct_ids <= set(entities_by_id):
        return AuditedInvariantEntityBinding(entity_ids=(), audited=False, invalid=True)
    bound_location_ids: set[str] = set()
    for location in invariant.locations:
        bound_entity_id = _exact_location_entity_id(
            location,
            entities=entities,
            source_contents_by_path=source_contents_by_path,
        )
        if bound_entity_id is None:
            return AuditedInvariantEntityBinding(entity_ids=(), audited=False, invalid=True)
        bound_location_ids.add(bound_entity_id)
    bound_ids = direct_ids | bound_location_ids
    if not bound_ids:
        return AuditedInvariantEntityBinding(entity_ids=(), audited=False, invalid=True)
    if bound_ids <= exact_test_entity_ids:
        return AuditedInvariantEntityBinding(entity_ids=(), audited=False, invalid=False)
    if not bound_ids <= audited_entity_ids:
        return AuditedInvariantEntityBinding(entity_ids=(), audited=False, invalid=True)
    return AuditedInvariantEntityBinding(
        entity_ids=tuple(sorted(bound_ids)),
        audited=True,
        invalid=False,
    )


def _exact_location_entity_id(
    location: Location,
    *,
    entities: list[SolidityEntity],
    source_contents_by_path: dict[str, str] | None,
) -> str | None:
    """Return one exact current entity binding for a source location."""

    if location.symbol is None or location.content_hash is None:
        return None
    candidates = [
        entity
        for entity in entities
        if entity.path == location.path
        and entity.start_line <= location.start_line
        and location.end_line <= entity.end_line
        and location.symbol in {entity.id, entity.name, entity.signature}
    ]
    if len(candidates) != 1:
        return None
    entity = candidates[0]
    source_content = (
        source_contents_by_path.get(location.path) if source_contents_by_path is not None else None
    )
    if source_content is not None:
        if (
            line_range_hash(source_content, entity.start_line, entity.end_line)
            != entity.source_hash
            or line_range_hash(source_content, location.start_line, location.end_line)
            != location.content_hash
        ):
            return None
    elif (
        location.start_line != entity.start_line
        or location.end_line != entity.end_line
        or location.content_hash != entity.source_hash
    ):
        return None
    return entity.id


def exact_test_entity_ids(
    *,
    index: SoliditySymbolIndex,
    projects: list[SolidityProjectMetadata],
) -> set[str]:
    """Return only entities whose paths are provably inside an audited project's tests."""

    result: set[str] = set()
    for entity in index.entities:
        owning_projects = [
            project
            for project in projects
            if _project_directories_are_safe(project)
            and _path_is_within_directory(entity.path, project.project_root)
        ]
        if owning_projects:
            maximum_depth = max(
                _directory_depth(project.project_root) for project in owning_projects
            )
            owning_projects = [
                project
                for project in owning_projects
                if _directory_depth(project.project_root) == maximum_depth
            ]
        if len(owning_projects) != 1:
            continue
        project = owning_projects[0]
        if (
            any(
                _path_is_within_directory(entity.path, directory)
                for directory in project.test_directories
            )
            or _conventional_test_directory(entity.path, project.project_root) is not None
        ):
            result.add(entity.id)
    return result


def critical_graph_edge_is_exact(
    edge: SolidityGraphEdge,
    *,
    entities_by_id: dict[str, SolidityEntity],
    audited_function_ids: set[str],
    source_contents_by_path: dict[str, str] | None,
) -> bool:
    """Validate one critical graph edge against its exact audited source function."""

    source = entities_by_id.get(edge.source_id)
    if source is None or source.id not in audited_function_ids:
        return False
    if (
        edge.path != source.path
        or edge.start_line < source.start_line
        or edge.end_line > source.end_line
    ):
        return False
    source_content = (
        source_contents_by_path.get(edge.path) if source_contents_by_path is not None else None
    )
    if source_content is not None:
        return (
            line_range_hash(source_content, source.start_line, source.end_line)
            == source.source_hash
            and line_range_hash(source_content, edge.start_line, edge.end_line) == edge.source_hash
        )
    return (
        edge.start_line == source.start_line
        and edge.end_line == source.end_line
        and edge.source_hash == source.source_hash
    )


def bind_economic_plan_to_audited_entities(
    *,
    plan: EconomicSimulationPlan,
    entities: list[SolidityEntity],
    audited_entity_ids: set[str],
    exact_test_entity_ids: set[str],
    invariant_bindings_by_id: dict[str, AuditedInvariantEntityBinding],
    source_contents_by_path: dict[str, str] | None = None,
) -> AuditedEconomicEntityBinding:
    """Require each applicable plan to be exactly source- or invariant-bound."""

    if not plan.applicable:
        return AuditedEconomicEntityBinding(entity_ids=(), audited=False, invalid=False)
    referenced_invariants = [
        invariant_bindings_by_id.get(invariant_id) for invariant_id in plan.invariant_ids
    ]
    if any(binding is None or not binding.audited for binding in referenced_invariants):
        return AuditedEconomicEntityBinding(entity_ids=(), audited=False, invalid=True)
    location_entity_ids: set[str] = set()
    for location in plan.source_locations:
        entity_id = _exact_location_entity_id(
            location,
            entities=entities,
            source_contents_by_path=source_contents_by_path,
        )
        if entity_id is None:
            return AuditedEconomicEntityBinding(entity_ids=(), audited=False, invalid=True)
        location_entity_ids.add(entity_id)
    bound_ids = {
        entity_id
        for binding in referenced_invariants
        if binding is not None
        for entity_id in binding.entity_ids
    } | location_entity_ids
    if not bound_ids:
        return AuditedEconomicEntityBinding(entity_ids=(), audited=False, invalid=True)
    if bound_ids <= exact_test_entity_ids:
        return AuditedEconomicEntityBinding(entity_ids=(), audited=False, invalid=True)
    if not bound_ids <= audited_entity_ids:
        return AuditedEconomicEntityBinding(entity_ids=(), audited=False, invalid=True)
    return AuditedEconomicEntityBinding(
        entity_ids=tuple(sorted(bound_ids)),
        audited=True,
        invalid=False,
    )


def _audited_function_population(
    *,
    index: SoliditySymbolIndex,
    projects: list[SolidityProjectMetadata],
    candidate_ids: set[str],
    external_classification_complete: bool = True,
    external_limitations: tuple[str, ...] = (),
) -> _AuditedFunctionPopulation:
    partition = partition_audited_source_entities(index=index, projects=projects)
    audited_ids = candidate_ids & set(partition.function_entity_ids)
    partition_exclusions = {
        exclusion.subject: exclusion for exclusion in partition.function_exclusions
    }
    exclusions = {
        entity_id: partition_exclusions[entity_id]
        for entity_id in candidate_ids
        if entity_id in partition_exclusions
    }
    unclassified_ids = candidate_ids - audited_ids - set(exclusions)
    exclusions.update(
        {
            entity_id: CoverageExclusion(
                subject=entity_id,
                reason=(
                    "graph or symbol-index source could not be classified as an exact "
                    "audited-source function"
                ),
                provenance=CoverageProvenance.SYMBOL_INDEX,
            )
            for entity_id in unclassified_ids
        }
    )
    classification_complete = (
        partition.classification_complete
        and external_classification_complete
        and not unclassified_ids
    )
    limitations = {
        *partition.limitations,
        *external_limitations,
        *(
            (
                "source classification incomplete: one or more review-metric function "
                "sources were absent from the audited-source partition",
            )
            if unclassified_ids
            else ()
        ),
    }
    return _AuditedFunctionPopulation(
        entity_ids=tuple(sorted(audited_ids)),
        exclusions=tuple(exclusions[key] for key in sorted(exclusions)),
        classification_complete=classification_complete,
        limitations=tuple(sorted(limitations)),
    )


def _initial_model_review_population_evidence(
    population: _AuditedFunctionPopulation | None,
    *,
    denominator: int,
    empty_evidence: str,
    pending_evidence: str,
) -> tuple[int, list[CoverageExclusion], list[str], list[str]]:
    if population is None:
        return 0, [], [], ["Solidity symbol index was not produced"]
    failures = list(population.limitations) if not population.classification_complete else []
    if denominator:
        failures.append(pending_evidence)
        not_applicable_evidence: list[str] = []
    elif population.classification_complete:
        not_applicable_evidence = [empty_evidence]
    else:
        not_applicable_evidence = []
    exclusions = list(population.exclusions)
    return denominator + len(exclusions), exclusions, not_applicable_evidence, sorted(set(failures))


def build_solidity_coverage(
    *,
    discovery: DiscoveryResult,
    projects: list[SolidityProjectMetadata],
    compilations: list[SolidityCompilationResult],
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    scanner_runs: list[ScannerRun],
    invariants: InvariantSuite | None = None,
    invariant_executions: list[InvariantExecutionResult] | None = None,
    economic_simulations: list[EconomicSimulationPlan] | None = None,
    formal_runs: list[FormalToolRun] | None = None,
    audited_suite_statement_evidence: (list[AuditedSuiteStatementCoverageEvidence] | None) = None,
    audited_suite_mutation_plan: MutationApplicabilityPlan | None = None,
    audited_suite_mutation_campaigns: list[MutationCampaignEvidence] | None = None,
    audited_suite_mutation_surface_evidence: (
        list[AuditedSuiteMutationSurfaceEvidence] | None
    ) = None,
    expected_repository_sha256: str | None = None,
) -> SolidityCoverage:
    """Summarize what the deterministic Solidity layer did and did not analyze."""

    projects = [
        SolidityProjectMetadata.model_validate(project.model_dump(mode="json"))
        for project in projects
    ]
    compilations = [
        SolidityCompilationResult.model_validate(result.model_dump(mode="json"))
        for result in compilations
    ]
    index = (
        SoliditySymbolIndex.model_validate(index.model_dump(mode="json"))
        if index is not None
        else None
    )
    graphs = (
        SolidityGraphSet.model_validate(graphs.model_dump(mode="json"))
        if graphs is not None
        else None
    )
    scanner_runs = [
        validated_scanner_run_copy_preserving_runtime_authority(run) for run in scanner_runs
    ]
    invariants = (
        InvariantSuite.model_validate(invariants.model_dump(mode="json"))
        if invariants is not None
        else None
    )
    invariant_executions = [
        InvariantExecutionResult.model_validate(result.model_dump(mode="json"))
        for result in (invariant_executions or [])
    ]
    economic_simulations = [
        EconomicSimulationPlan.model_validate(plan.model_dump(mode="json"))
        for plan in (economic_simulations or [])
    ]
    formal_runs = [
        FormalToolRun.model_validate(run.model_dump(mode="json")) for run in (formal_runs or [])
    ]
    audited_suite_statement_evidence = [
        AuditedSuiteStatementCoverageEvidence.model_validate(evidence.model_dump(mode="json"))
        for evidence in (audited_suite_statement_evidence or [])
    ]
    audited_suite_mutation_plan = (
        MutationApplicabilityPlan.model_validate(
            audited_suite_mutation_plan.model_dump(mode="python")
        )
        if audited_suite_mutation_plan is not None
        else None
    )
    audited_suite_mutation_campaigns = [
        MutationCampaignEvidence.model_validate(campaign.model_dump(mode="python"))
        for campaign in (audited_suite_mutation_campaigns or [])
    ]
    audited_suite_mutation_surface_evidence = [
        AuditedSuiteMutationSurfaceEvidence.model_validate(evidence.model_dump(mode="json"))
        for evidence in (audited_suite_mutation_surface_evidence or [])
    ]
    solidity_files = [item.relative_path for item in discovery.files if item.language == "Solidity"]
    entities = index.entities if index else []
    contracts = [
        entity
        for entity in entities
        if entity.kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    ]
    functions = [
        entity
        for entity in entities
        if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
    ]
    modifiers = [entity for entity in entities if entity.kind is SolidityEntityKind.MODIFIER]
    variables = [
        entity
        for entity in entities
        if entity.kind
        in {
            SolidityEntityKind.STATE_VARIABLE,
            SolidityEntityKind.IMMUTABLE,
            SolidityEntityKind.CONSTANT,
        }
    ]
    compiled_contract_names = {
        name for result in compilations for name in result.contracts_compiled
    }
    indexed_contract_names = {entity.name for entity in contracts}
    compiler_contract_population = compiled_contract_names | indexed_contract_names
    project_roots = {project.project_root for project in projects}
    dependency_project_roots = {
        project.project_root for project in projects if project.dependency_files
    }
    successfully_compiled_project_roots = {
        result.project_root for result in compilations if result.status is CompilationStatus.SUCCESS
    }
    failed_compilation = [
        result.project_root
        for result in compilations
        if result.status in {CompilationStatus.FAILED, CompilationStatus.TIMED_OUT}
    ]
    missing_dependencies = [
        error
        for result in compilations
        for error in result.errors
        if "not installed" in error.lower() or "missing" in error.lower()
    ]
    unresolved_imports = [
        diagnostic
        for result in compilations
        for diagnostic in [*result.errors, *result.warnings]
        if "import" in diagnostic.lower() and "not found" in diagnostic.lower()
    ]
    tools_executed = [
        run.scanner
        for run in scanner_runs
        if run.status is ScannerStatus.SUCCESS and run.scanner == "slither"
    ]
    tools_unavailable = [
        run.scanner
        for run in scanner_runs
        if run.status is ScannerStatus.UNAVAILABLE and run.scanner == "slither"
    ]
    tools_failed = [
        run.scanner
        for run in scanner_runs
        if run.status in {ScannerStatus.FAILED, ScannerStatus.TIMED_OUT}
        and run.scanner == "slither"
    ]
    economic_template_execution = _economic_template_execution_coverage(
        economic_simulations,
        invariant_executions,
    )
    indexed_paths = {entity.path for entity in entities}
    graph_edge_counts = dict(graphs.coverage) if graphs else {}
    graph_node_counts: dict[str, int] = {}
    if graphs:
        for node in graphs.nodes:
            graph_node_counts[node.kind.value] = graph_node_counts.get(node.kind.value, 0) + 1
    graph_state = AnalysisState.NOT_ANALYZED
    if graphs is not None:
        graph_state = (
            AnalysisState.FALLBACK_PARSER
            if index is not None and index.fallback_sources
            else AnalysisState.DETERMINISTIC
        )
    index_state = AnalysisState.NOT_ANALYZED
    if index is not None:
        index_state = (
            AnalysisState.FALLBACK_PARSER if index.fallback_sources else AnalysisState.DETERMINISTIC
        )
    entry_point_candidate_ids = {
        entity.id for entity in functions if entity.visibility in {"public", "external"}
    }
    privilege_candidate_ids = _graph_source_ids(graphs, SolidityGraphKind.PRIVILEGE)
    state_write_candidate_ids = _graph_source_ids(graphs, SolidityGraphKind.STATE_WRITE)
    sensitive_candidate_ids = _graph_source_ids(
        graphs,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    )
    if index is not None:
        entry_point_population = _audited_function_population(
            index=index,
            projects=projects,
            candidate_ids=entry_point_candidate_ids,
        )
        privilege_graph_complete, privilege_graph_limitations = _graph_kind_classification_evidence(
            graphs, SolidityGraphKind.PRIVILEGE
        )
        state_write_graph_complete, state_write_graph_limitations = (
            _graph_kind_classification_evidence(graphs, SolidityGraphKind.STATE_WRITE)
        )
        sensitive_graph_complete, sensitive_graph_limitations = _graph_kind_classification_evidence(
            graphs,
            SolidityGraphKind.SENSITIVE_REACHABILITY,
        )
        privilege_population = _audited_function_population(
            index=index,
            projects=projects,
            candidate_ids=privilege_candidate_ids,
            external_classification_complete=privilege_graph_complete,
            external_limitations=privilege_graph_limitations,
        )
        state_write_population = _audited_function_population(
            index=index,
            projects=projects,
            candidate_ids=state_write_candidate_ids,
            external_classification_complete=state_write_graph_complete,
            external_limitations=state_write_graph_limitations,
        )
        sensitive_population = _audited_function_population(
            index=index,
            projects=projects,
            candidate_ids=sensitive_candidate_ids,
            external_classification_complete=sensitive_graph_complete,
            external_limitations=sensitive_graph_limitations,
        )
    else:
        entry_point_population = None
        privilege_population = None
        state_write_population = None
        sensitive_population = None
    entry_point_ids = set(entry_point_population.entity_ids) if entry_point_population else set()
    privilege_sources = set(privilege_population.entity_ids) if privilege_population else set()
    state_write_sources = (
        set(state_write_population.entity_ids) if state_write_population else set()
    )
    sensitive_sources = set(sensitive_population.entity_ids) if sensitive_population else set()
    entry_points = [entity for entity in functions if entity.id in entry_point_ids]
    external_edges = [
        edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph
        in {
            SolidityGraphKind.EXTERNAL_CALL,
            SolidityGraphKind.LOW_LEVEL_CALL,
            SolidityGraphKind.DELEGATECALL,
        }
    ]
    asset_edges = [
        edge
        for edge in (graphs.edges if graphs else [])
        if edge.graph is SolidityGraphKind.ASSET_FLOW
    ]
    classified_asset_edges = [
        edge
        for edge in asset_edges
        if edge.metadata.get("operation")
        and edge.metadata.get("flow_direction")
        and edge.metadata.get("asset_standard")
        and edge.metadata.get("asset_standard") != "unknown"
    ]
    asset_flow_summary = summarize_asset_flows(graphs)
    control_dependency_summary = summarize_control_dependencies(graphs)
    requested_scanners = [run for run in scanner_runs if run.status is not ScannerStatus.SKIPPED]
    successful_scanners = [run for run in requested_scanners if run.status is ScannerStatus.SUCCESS]
    scanner_exclusions = [
        CoverageExclusion(
            subject=f"{run.scanner}[{position}]",
            reason=run.error or "scanner was explicitly skipped",
            provenance=CoverageProvenance.CONFIGURATION,
        )
        for position, run in enumerate(scanner_runs)
        if run.status is ScannerStatus.SKIPPED
    ]
    dependency_exclusions = [
        CoverageExclusion(
            subject=project_root,
            reason="project declares no dependency manifest or dependency source set",
            provenance=CoverageProvenance.DISCOVERY,
        )
        for project_root in sorted(project_roots - dependency_project_roots)
    ]
    executed_invariant_ids = {
        result.invariant_id
        for result in invariant_executions
        if result.status
        in {
            InvariantExecutionStatus.PASSED,
            InvariantExecutionStatus.COUNTEREXAMPLE,
        }
    }
    invariant_population_ids = {spec.id for spec in invariants.invariants} if invariants else set()
    completed_invariants = len(executed_invariant_ids & invariant_population_ids)
    campaign_coverages = [
        result.campaign_coverage
        for result in invariant_executions
        if result.campaign_coverage is not None
        and result.status
        in {
            InvariantExecutionStatus.PASSED,
            InvariantExecutionStatus.COUNTEREXAMPLE,
        }
    ]
    campaign_functions_declared = sum(
        len(evidence.declared_action_functions) for evidence in campaign_coverages
    )
    campaign_functions_observed = sum(
        len(evidence.observed_action_functions) for evidence in campaign_coverages
    )
    campaign_states_declared = sum(
        len(evidence.declared_state_properties) for evidence in campaign_coverages
    )
    campaign_states_observed = sum(
        len(evidence.observed_state_properties) for evidence in campaign_coverages
    )
    counterexample_executions = [
        result
        for result in invariant_executions
        if result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    ]
    counterexample_sequences_observed = sum(
        result.campaign_coverage is not None
        and bool(result.campaign_coverage.observed_sequence_lengths)
        for result in counterexample_executions
    )
    counterexample_sequences_minimized = sum(
        result.minimization_evidence is not None
        and result.minimization_evidence.proven_minimal
        and result.campaign_coverage is not None
        and bool(result.campaign_coverage.minimized_sequence_action_ids)
        for result in counterexample_executions
    )
    indexed_file_count = len(indexed_paths)
    compiler_indexed_count = len(compiled_contract_names & indexed_contract_names)
    compiler_contract_failures = _compiler_index_failures(
        projects=projects,
        compilations=compilations,
        compiled_names=compiled_contract_names,
        indexed_names=indexed_contract_names,
    )
    model_review_pending = "explicit substantive model review coverage has not been applied"
    (
        entry_point_population_count,
        entry_point_exclusions,
        entry_point_not_applicable,
        entry_point_failures,
    ) = _initial_model_review_population_evidence(
        entry_point_population,
        denominator=len(entry_points),
        empty_evidence="symbol index contains no audited-source public or external entry points",
        pending_evidence=model_review_pending,
    )
    (
        privilege_population_count,
        privilege_exclusions,
        privilege_not_applicable,
        privilege_failures,
    ) = _initial_model_review_population_evidence(
        privilege_population,
        denominator=len(privilege_sources),
        empty_evidence="semantic graph contains no audited-source privileged entry points",
        pending_evidence=model_review_pending,
    )
    (
        state_write_population_count,
        state_write_exclusions,
        state_write_not_applicable,
        state_write_failures,
    ) = _initial_model_review_population_evidence(
        state_write_population,
        denominator=len(state_write_sources),
        empty_evidence="semantic graph contains no audited-source state-writing functions",
        pending_evidence=model_review_pending,
    )
    (
        sensitive_population_count,
        sensitive_exclusions,
        sensitive_not_applicable,
        sensitive_failures,
    ) = _initial_model_review_population_evidence(
        sensitive_population,
        denominator=len(sensitive_sources),
        empty_evidence=(
            "semantic graph contains no audited-source sensitive-reachability functions"
        ),
        pending_evidence=model_review_pending,
    )
    compilation_successes = len(project_roots & successfully_compiled_project_roots)
    compilation_failures = [
        f"{result.project_root}: compilation status {result.status.value}"
        for result in compilations
        if result.status is not CompilationStatus.SUCCESS
    ]
    compilation_failures.extend(
        f"{project_root}: no compilation result was produced"
        for project_root in sorted(project_roots - {result.project_root for result in compilations})
    )
    invariant_failures = [
        f"{result.invariant_id}: execution status {result.status.value}"
        for result in invariant_executions
        if result.invariant_id not in executed_invariant_ids
        if result.status
        not in {
            InvariantExecutionStatus.PASSED,
            InvariantExecutionStatus.COUNTEREXAMPLE,
        }
    ]
    if invariants is not None:
        invariant_failures.extend(
            f"{spec.id}: no completed typed campaign"
            for spec in invariants.invariants
            if spec.id not in executed_invariant_ids
            and not any(result.invariant_id == spec.id for result in invariant_executions)
        )
    quality_metrics = {
        "solidity_files_indexed": _metric(
            indexed_file_count,
            len(solidity_files),
            index_state,
            "Solidity files that contributed at least one indexed entity",
            population=len(solidity_files),
            exclusions=[],
            not_applicable_evidence=(
                ["repository discovery found no Solidity source files"]
                if not solidity_files and index is not None
                else []
            ),
            confidence=min((entity.confidence for entity in entities), default=1),
            provenance=[
                CoverageProvenance.DISCOVERY,
                CoverageProvenance.SYMBOL_INDEX,
            ],
            failures=(
                ["Solidity symbol index was not produced"]
                if solidity_files and index is None
                else _coverage_gap(
                    indexed_file_count,
                    len(solidity_files),
                    "discovered Solidity file(s) did not contribute an indexed entity",
                )
            ),
        ),
        "compiler_contracts_indexed": _metric(
            compiler_indexed_count,
            len(compiler_contract_population),
            (
                AnalysisState.DETERMINISTIC
                if not compiler_contract_failures and compiler_contract_population
                else (
                    AnalysisState.NOT_ANALYZED
                    if not projects and not compiler_contract_population
                    else AnalysisState.ATTEMPTED_FAILED
                )
            ),
            "Compiler-reported contracts represented in the normalized symbol index",
            population=len(compiler_contract_population),
            exclusions=[],
            not_applicable_evidence=(
                ["no Solidity projects or contract declarations were discovered"]
                if not compiler_contract_population and not projects
                else []
            ),
            confidence=1,
            provenance=[
                CoverageProvenance.COMPILER,
                CoverageProvenance.SYMBOL_INDEX,
            ],
            failures=compiler_contract_failures,
        ),
        "public_external_entry_points_reviewed": _metric(
            0,
            len(entry_points),
            AnalysisState.NOT_ANALYZED,
            "Public/external entry points with validated substantive model reviews",
            population=entry_point_population_count,
            exclusions=entry_point_exclusions,
            not_applicable_evidence=entry_point_not_applicable,
            confidence=min((entity.confidence for entity in entry_points), default=1),
            provenance=[
                CoverageProvenance.SYMBOL_INDEX,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=entry_point_failures,
        ),
        "privileged_entry_points_reviewed": _metric(
            0,
            len(privilege_sources),
            AnalysisState.NOT_ANALYZED,
            "Privilege-graph source functions with validated substantive model reviews",
            population=privilege_population_count,
            exclusions=privilege_exclusions,
            not_applicable_evidence=privilege_not_applicable,
            confidence=_graph_source_confidence(graphs, privilege_sources),
            provenance=[
                CoverageProvenance.SEMANTIC_GRAPH,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=privilege_failures,
        ),
        "state_writing_functions_reviewed": _metric(
            0,
            len(state_write_sources),
            AnalysisState.NOT_ANALYZED,
            "State-write graph source functions with validated substantive model reviews",
            population=state_write_population_count,
            exclusions=state_write_exclusions,
            not_applicable_evidence=state_write_not_applicable,
            confidence=_graph_source_confidence(graphs, state_write_sources),
            provenance=[
                CoverageProvenance.SEMANTIC_GRAPH,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=state_write_failures,
        ),
        "high_value_paths_reviewed": _metric(
            0,
            len(sensitive_sources),
            AnalysisState.NOT_ANALYZED,
            "Sensitive-reachability source functions with validated substantive model reviews",
            population=sensitive_population_count,
            exclusions=sensitive_exclusions,
            not_applicable_evidence=sensitive_not_applicable,
            confidence=_graph_source_confidence(graphs, sensitive_sources),
            provenance=[
                CoverageProvenance.SEMANTIC_GRAPH,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=sensitive_failures,
        ),
        "external_calls_classified": _metric(
            len(external_edges),
            len(external_edges),
            graph_state,
            "External/low-level/delegate call edges represented in the semantic graph",
            population=len(external_edges),
            exclusions=[],
            not_applicable_evidence=(
                ["semantic graph contains no external, low-level, or delegate call edges"]
                if not external_edges and graphs is not None
                else []
            ),
            confidence=min((edge.confidence for edge in external_edges), default=1),
            provenance=[CoverageProvenance.SEMANTIC_GRAPH],
            failures=(
                ["Solidity semantic graph was not produced"]
                if not external_edges and graphs is None
                else []
            ),
        ),
        "asset_flows_classified": _metric(
            len(classified_asset_edges),
            len(asset_edges),
            graph_state,
            "Asset-flow graph edges classified by flow direction and token/native-asset family",
            population=len(asset_edges),
            exclusions=[],
            not_applicable_evidence=(
                ["semantic graph contains no asset-flow edges"]
                if not asset_edges and graphs is not None
                else []
            ),
            confidence=min((edge.confidence for edge in asset_edges), default=1),
            provenance=[CoverageProvenance.SEMANTIC_GRAPH],
            failures=(
                ["Solidity semantic graph was not produced"]
                if not asset_edges and graphs is None
                else _coverage_gap(
                    len(classified_asset_edges),
                    len(asset_edges),
                    "asset-flow edge(s) lack complete classification",
                )
            ),
        ),
        "storage_variables_modelled": _metric(
            min(len(graphs.storage_layout) if graphs else 0, len(variables)),
            len(variables),
            graph_state,
            "Indexed state variables represented in compiler/fallback storage layout",
            population=len(variables),
            exclusions=[],
            not_applicable_evidence=(
                ["symbol index contains no state variables"]
                if not variables and index is not None
                else []
            ),
            confidence=min(
                (entry.confidence for entry in (graphs.storage_layout if graphs else [])),
                default=1,
            ),
            provenance=[
                CoverageProvenance.SYMBOL_INDEX,
                CoverageProvenance.SEMANTIC_GRAPH,
            ],
            failures=(
                ["Solidity symbol index was not produced"]
                if not variables and index is None
                else _coverage_gap(
                    min(len(graphs.storage_layout) if graphs else 0, len(variables)),
                    len(variables),
                    "indexed state variable(s) lack storage-layout evidence",
                )
            ),
        ),
        "invariants_executed": _metric(
            completed_invariants,
            len(invariants.invariants) if invariants else 0,
            (AnalysisState.DETERMINISTIC if invariant_executions else AnalysisState.NOT_ANALYZED),
            "Source-linked invariant hypotheses with a completed typed campaign",
            population=len(invariants.invariants) if invariants else 0,
            exclusions=[],
            not_applicable_evidence=(
                ["invariant discovery produced no source-linked invariant hypotheses"]
                if invariants is not None and not invariants.invariants
                else []
            ),
            confidence=1,
            provenance=[CoverageProvenance.INVARIANT_EXECUTION],
            failures=(
                ["invariant suite was not produced"] if invariants is None else invariant_failures
            ),
        ),
        "scanner_completion": _metric(
            len(successful_scanners),
            len(requested_scanners),
            (AnalysisState.SCANNER_SUPPORTED if requested_scanners else AnalysisState.NOT_ANALYZED),
            "Requested deterministic scanners that completed successfully",
            population=len(scanner_runs),
            exclusions=scanner_exclusions,
            not_applicable_evidence=(
                ["all inventoried scanners were explicitly skipped"]
                if scanner_runs and not requested_scanners
                else []
            ),
            confidence=1,
            provenance=[
                CoverageProvenance.CONFIGURATION,
                CoverageProvenance.STATIC_TOOL,
            ],
            failures=(
                [
                    f"{run.scanner}: scanner status {run.status.value}"
                    for run in requested_scanners
                    if run.status is not ScannerStatus.SUCCESS
                ]
                if requested_scanners
                else (["scanner inventory was not produced"] if not scanner_runs else [])
            ),
        ),
        "compilation_completion": _metric(
            compilation_successes,
            len(project_roots),
            (AnalysisState.DETERMINISTIC if compilations else AnalysisState.NOT_ANALYZED),
            "Detected Solidity projects with successful isolated compilation",
            population=len(project_roots),
            exclusions=[],
            not_applicable_evidence=(
                ["no Solidity project was discovered"] if not project_roots else []
            ),
            confidence=1,
            provenance=[
                CoverageProvenance.DISCOVERY,
                CoverageProvenance.COMPILER,
            ],
            failures=compilation_failures,
        ),
        "dependency_resolution": _metric(
            len(dependency_project_roots & successfully_compiled_project_roots),
            len(dependency_project_roots),
            (
                AnalysisState.DETERMINISTIC
                if dependency_project_roots
                else AnalysisState.NOT_ANALYZED
            ),
            "Projects declaring dependencies whose isolated compilation resolved them",
            population=len(project_roots),
            exclusions=dependency_exclusions,
            not_applicable_evidence=(
                ["all discovered Solidity projects declare no external dependencies"]
                if project_roots and not dependency_project_roots
                else (["no Solidity project was discovered"] if not project_roots else [])
            ),
            confidence=1,
            provenance=[
                CoverageProvenance.DISCOVERY,
                CoverageProvenance.COMPILER,
            ],
            failures=[
                f"{project_root}: dependency resolution did not complete"
                for project_root in sorted(
                    dependency_project_roots - successfully_compiled_project_roots
                )
            ],
        ),
    }
    quality_metrics.update(_economic_template_quality_metrics(economic_template_execution))
    quality_metrics.update(
        _invariant_campaign_quality_metrics(
            campaign_functions_declared=campaign_functions_declared,
            campaign_functions_observed=campaign_functions_observed,
            campaign_states_declared=campaign_states_declared,
            campaign_states_observed=campaign_states_observed,
            counterexample_count=len(counterexample_executions),
            counterexample_sequences_observed=counterexample_sequences_observed,
            counterexample_sequences_minimized=counterexample_sequences_minimized,
            campaigns_present=bool(campaign_coverages),
        )
    )
    audited_suite_coverage = (
        _build_audited_suite_coverage(
            index=index,
            projects=projects,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=economic_simulations,
            scanner_runs=scanner_runs,
            supplied_statements=audited_suite_statement_evidence or [],
            mutation_plan=audited_suite_mutation_plan,
            mutation_campaigns=audited_suite_mutation_campaigns or [],
            mutation_surface_bindings=audited_suite_mutation_surface_evidence or [],
            expected_repository_sha256=expected_repository_sha256,
            source_file_sha256s={
                item.relative_path: item.sha256
                for item in discovery.files
                if item.language == "Solidity"
            },
            source_contents_by_path={
                item.relative_path: item.content
                for item in discovery.files
                if item.language == "Solidity"
            },
        )
        if index is not None
        else None
    )
    if audited_suite_coverage is not None:
        quality_metrics.update(
            {
                "audited_suite_contract_statement_coverage": (
                    audited_suite_coverage.contract_statement_coverage
                ),
                "audited_suite_function_statement_coverage": (
                    audited_suite_coverage.function_statement_coverage
                ),
                "audited_suite_critical_function_assertion_coverage": (
                    audited_suite_coverage.critical_function_assertion_coverage
                ),
            }
        )
    return SolidityCoverage(
        projects_discovered=len(projects),
        project_types=sorted({project.project_type.value for project in projects}),
        files_discovered=len(solidity_files),
        solidity_files_analyzed=len({entity.path for entity in entities}),
        contracts_indexed=len(contracts),
        functions_indexed=len(functions),
        modifiers_indexed=len(modifiers),
        state_variables_indexed=len(variables),
        ast_backed_files=len(index.ast_sources) if index else 0,
        fallback_parser_files=len(index.fallback_sources) if index else 0,
        graph_edge_counts=graph_edge_counts,
        graph_node_counts=graph_node_counts,
        asset_flow_operation_counts=asset_flow_summary["operations"],
        asset_flow_direction_counts=asset_flow_summary["directions"],
        control_resolution_counts=control_dependency_summary["controls"],
        governance_stage_counts=control_dependency_summary["governance"],
        dependency_resolution_counts=control_dependency_summary["dependencies"],
        oracle_freshness_counts=control_dependency_summary["oracle_freshness"],
        graph_analysis_state=graph_state,
        invariants_discovered=len(invariants.invariants) if invariants else 0,
        executable_invariants=invariants.executable_count if invariants else 0,
        invariants_executed=completed_invariants,
        invariant_campaign_functions_declared=campaign_functions_declared,
        invariant_campaign_functions_observed=campaign_functions_observed,
        invariant_campaign_state_properties_declared=campaign_states_declared,
        invariant_campaign_state_properties_observed=campaign_states_observed,
        invariant_counterexample_sequences_observed=(counterexample_sequences_observed),
        invariant_counterexample_sequences_minimized=(counterexample_sequences_minimized),
        economic_simulations_planned=len(economic_simulations),
        economic_simulations_executed=len(
            {
                result.economic_template
                for result in invariant_executions
                if result.economic_template is not None
                and result.status
                in {
                    InvariantExecutionStatus.PASSED,
                    InvariantExecutionStatus.COUNTEREXAMPLE,
                }
            }
        ),
        economic_template_execution=economic_template_execution,
        formal_tools_available=[
            run.tool
            for run in formal_runs
            if run.status in {FormalToolStatus.SUCCESS, FormalToolStatus.INCONCLUSIVE}
        ],
        formal_tools_unavailable=[
            run.tool for run in formal_runs if run.status is FormalToolStatus.UNAVAILABLE
        ],
        formal_tools_failed=[
            run.tool
            for run in formal_runs
            if run.status in {FormalToolStatus.FAILED, FormalToolStatus.TIMED_OUT}
        ],
        functions_covered_by_static_tools=_static_tool_function_count(functions, scanner_runs),
        contracts_failed_compilation=failed_compilation,
        unsupported_files=[
            path
            for path in solidity_files
            if index is not None and path not in {entity.path for entity in index.entities}
        ],
        missing_dependencies=missing_dependencies[:100],
        unresolved_imports=unresolved_imports[:100],
        graph_warnings=list(graphs.warnings if graphs else []),
        tools_executed=tools_executed,
        tools_unavailable=tools_unavailable,
        tools_failed=tools_failed,
        tests_executed=(
            audited_suite_coverage.repository_tests_executed
            if audited_suite_coverage is not None
            else 0
        ),
        tests_failed=(
            audited_suite_coverage.repository_tests_failed
            if audited_suite_coverage is not None
            else 0
        ),
        audited_suite_coverage=audited_suite_coverage,
        quality_metrics=quality_metrics,
        context_limitations=list(index.warnings if index else []),
        excluded_paths=sorted(
            {
                path
                for project in projects
                for path in [*project.excluded_paths, *project.artifact_paths]
            }
        ),
        project_configuration_assumptions=[
            warning for project in projects for warning in project.discovery_warnings
        ],
    )


def _build_audited_suite_coverage(
    *,
    index: SoliditySymbolIndex,
    projects: list[SolidityProjectMetadata],
    graphs: SolidityGraphSet | None,
    invariants: InvariantSuite | None,
    economic_simulations: list[EconomicSimulationPlan],
    scanner_runs: list[ScannerRun],
    supplied_statements: list[AuditedSuiteStatementCoverageEvidence],
    mutation_plan: MutationApplicabilityPlan | None,
    mutation_campaigns: list[MutationCampaignEvidence],
    mutation_surface_bindings: list[AuditedSuiteMutationSurfaceEvidence],
    expected_repository_sha256: str | None,
    source_file_sha256s: dict[str, str],
    source_contents_by_path: dict[str, str],
) -> AuditedSuiteCoverage:
    partition = partition_audited_source_entities(index=index, projects=projects)
    entities_by_id = {entity.id: entity for entity in index.entities}
    if len(entities_by_id) != len(index.entities):
        raise ValueError("audited-suite coverage requires unique indexed entity IDs")
    source_entity_ids = {
        *partition.contract_entity_ids,
        *partition.function_entity_ids,
    }
    function_ids = set(partition.function_entity_ids)
    contract_ids = set(partition.contract_entity_ids)
    supplied_by_id = {evidence.entity_id: evidence for evidence in supplied_statements}
    if len(supplied_by_id) != len(supplied_statements):
        raise ValueError("audited-suite statement evidence must have unique entity IDs")
    unexpected_supplied_ids = sorted(set(supplied_by_id) - source_entity_ids)
    if unexpected_supplied_ids:
        raise ValueError(
            "audited-suite statement evidence references non-source entity IDs: "
            + ", ".join(unexpected_supplied_ids[:20])
        )

    critical_graphs = {
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    }
    audited_contract_keys = {
        (entities_by_id[entity_id].path, entities_by_id[entity_id].name)
        for entity_id in contract_ids
    }
    audited_state_ids = {
        entity.id
        for entity in index.entities
        if entity.kind
        in {
            SolidityEntityKind.STATE_VARIABLE,
            SolidityEntityKind.IMMUTABLE,
            SolidityEntityKind.CONSTANT,
        }
        and entity.contract_name is not None
        and (entity.path, entity.contract_name) in audited_contract_keys
    }
    audited_invariant_entity_ids = source_entity_ids | audited_state_ids
    test_entity_ids = exact_test_entity_ids(index=index, projects=projects)
    test_function_ids = {
        entity.id
        for entity in index.entities
        if entity.id in test_entity_ids
        and entity.kind
        in {
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
        }
    }
    supplied_invariants = invariants.invariants if invariants is not None else []
    invariant_bindings = [
        (
            invariant,
            bind_invariant_to_audited_entities(
                invariant=invariant,
                entities=index.entities,
                audited_entity_ids=audited_invariant_entity_ids,
                exact_test_entity_ids=test_entity_ids,
                source_contents_by_path=source_contents_by_path,
            ),
        )
        for invariant in supplied_invariants
    ]
    invariant_binding_incomplete = any(binding.invalid for _, binding in invariant_bindings)
    invariant_entity_ids = {
        entity_id
        for _, binding in invariant_bindings
        if binding.audited
        for entity_id in binding.entity_ids
    }
    invariant_bindings_by_id = {invariant.id: binding for invariant, binding in invariant_bindings}
    economic_bindings = [
        (
            plan,
            bind_economic_plan_to_audited_entities(
                plan=plan,
                entities=index.entities,
                audited_entity_ids=audited_invariant_entity_ids,
                exact_test_entity_ids=test_entity_ids,
                invariant_bindings_by_id=invariant_bindings_by_id,
                source_contents_by_path=source_contents_by_path,
            ),
        )
        for plan in economic_simulations
    ]
    economic_binding_incomplete = any(binding.invalid for _, binding in economic_bindings)
    economic_entity_ids = {
        entity_id
        for _, binding in economic_bindings
        if binding.audited
        for entity_id in binding.entity_ids
    }
    critical_graph_edges = [
        edge
        for edge in (graphs.edges if graphs is not None else [])
        if edge.graph in critical_graphs
    ]
    audited_critical_graph_edges = [
        edge for edge in critical_graph_edges if edge.source_id in function_ids
    ]
    graph_binding_incomplete = any(
        (
            edge.source_id not in function_ids | test_function_ids
            or not critical_graph_edge_is_exact(
                edge,
                entities_by_id=entities_by_id,
                audited_function_ids=(
                    function_ids if edge.source_id in function_ids else test_function_ids
                ),
                source_contents_by_path=source_contents_by_path,
            )
        )
        for edge in critical_graph_edges
    )
    missing_critical_graphs = (
        critical_graphs - set(graphs.analyzed_graphs) if graphs is not None else critical_graphs
    )
    critical_classification_limitations: list[str] = []
    if graphs is None:
        critical_classification_limitations.append("Solidity semantic graph was not produced")
    elif missing_critical_graphs:
        critical_classification_limitations.append(
            "required graph kinds were not analyzed: "
            + ", ".join(sorted(kind.value for kind in missing_critical_graphs))
        )
    if invariants is None:
        critical_classification_limitations.append("invariant inventory was not produced")
    if invariant_binding_incomplete:
        critical_classification_limitations.append(
            "one or more nonempty invariants lacked an exact audited-source or test-only binding"
        )
    if economic_binding_incomplete:
        critical_classification_limitations.append(
            "one or more applicable economic plans lacked an exact audited-source binding"
        )
    if graph_binding_incomplete:
        critical_classification_limitations.append(
            "one or more critical graph edges lacked an exact current audited-function "
            "range binding"
        )
    critical_classification_complete = (
        partition.classification_complete
        and graphs is not None
        and invariants is not None
        and not missing_critical_graphs
        and not graph_binding_incomplete
        and not invariant_binding_incomplete
        and not economic_binding_incomplete
    )
    graph_critical_ids = {
        edge.source_id
        for edge in audited_critical_graph_edges
        if critical_graph_edge_is_exact(
            edge,
            entities_by_id=entities_by_id,
            audited_function_ids=function_ids,
            source_contents_by_path=source_contents_by_path,
        )
    }
    critical_function_ids = (
        graph_critical_ids
        | (invariant_entity_ids & function_ids)
        | (economic_entity_ids & function_ids)
        if critical_classification_complete
        else set(function_ids)
    )
    critical_state_ids = (invariant_entity_ids | economic_entity_ids) & audited_state_ids
    if critical_classification_complete:
        critical_state_ids.update(
            edge.target_id
            for edge in (graphs.edges if graphs is not None else [])
            if edge.graph
            in {
                SolidityGraphKind.STATE_READ,
                SolidityGraphKind.STATE_WRITE,
                SolidityGraphKind.STATE_DEPENDENCY,
            }
            and edge.source_id in critical_function_ids
            and edge.target_id in audited_state_ids
        )
    contract_ids_by_key = {
        (entities_by_id[entity_id].path, entities_by_id[entity_id].name): entity_id
        for entity_id in contract_ids
    }
    critical_contract_ids = (
        (invariant_entity_ids | economic_entity_ids) & contract_ids
        if critical_classification_complete
        else set(contract_ids)
    )
    for entity_id in critical_function_ids | critical_state_ids:
        entity = entities_by_id[entity_id]
        if entity.contract_name is None:
            continue
        contract_id = contract_ids_by_key.get((entity.path, entity.contract_name))
        if contract_id is not None:
            critical_contract_ids.add(contract_id)

    mutation_evidence_by_entity, mutation_limitations = _reconcile_mutation_surface_evidence(
        entities_by_id=entities_by_id,
        source_function_ids=function_ids,
        scanner_runs=scanner_runs,
        plan=mutation_plan,
        campaigns=mutation_campaigns,
        surface_bindings=mutation_surface_bindings,
        expected_repository_sha256=expected_repository_sha256,
        source_file_sha256s=source_file_sha256s,
    )
    surfaces: list[AuditedSuiteSurfaceCoverage] = []
    for entity_id in sorted(source_entity_ids):
        entity = entities_by_id[entity_id]
        critical = (
            entity_id in critical_function_ids
            if entity_id in function_ids
            else entity_id in critical_contract_ids
        )
        expected_location = Location(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            symbol=entity.signature or entity.name,
            content_hash=entity.source_hash,
        )
        expected_contract = entity.contract_name or (
            entity.name
            if entity.kind
            in {
                SolidityEntityKind.CONTRACT,
                SolidityEntityKind.INTERFACE,
                SolidityEntityKind.LIBRARY,
            }
            else "protocol"
        )
        statement_evidence = supplied_by_id.get(entity_id)
        if statement_evidence is not None and (
            statement_evidence.entity_kind is not entity.kind
            or statement_evidence.contract_name != expected_contract
            or statement_evidence.location != expected_location
        ):
            raise ValueError(
                "audited-suite statement evidence identity differs from the source index"
            )
        mutation_evidence = mutation_evidence_by_entity.get(entity_id, [])
        assertion_status = _assertion_status_from_mutation_evidence(mutation_evidence)
        surfaces.append(
            AuditedSuiteSurfaceCoverage(
                entity_id=entity.id,
                entity_kind=entity.kind,
                contract_name=expected_contract,
                location=expected_location,
                critical=critical,
                statement_status=AuditedSuiteStatementStatus.NOT_ANALYZED,
                assertion_status=assertion_status,
                mutation_evidence=mutation_evidence,
            )
        )

    contract_surfaces = [
        surface
        for surface in surfaces
        if surface.entity_kind
        in {
            SolidityEntityKind.CONTRACT,
            SolidityEntityKind.INTERFACE,
            SolidityEntityKind.LIBRARY,
        }
    ]
    function_surfaces = [
        surface
        for surface in surfaces
        if surface.entity_kind
        in {
            SolidityEntityKind.FUNCTION,
            SolidityEntityKind.CONSTRUCTOR,
        }
    ]
    critical_surfaces = [surface for surface in surfaces if surface.critical]
    contract_metric = _audited_suite_statement_metric(
        contract_surfaces,
        population=len(contract_surfaces) + len(partition.contract_exclusions),
        exclusions=list(partition.contract_exclusions),
        detail="Indexed audited-source contracts covered by repository-owned suite statements",
        empty_evidence="symbol index contains no audited-source contract declarations",
        classification_complete=partition.classification_complete,
    )
    function_metric = _audited_suite_statement_metric(
        function_surfaces,
        population=len(function_surfaces) + len(partition.function_exclusions),
        exclusions=list(partition.function_exclusions),
        detail="Indexed audited-source functions covered by repository-owned suite statements",
        empty_evidence="symbol index contains no audited-source function declarations",
        classification_complete=partition.classification_complete,
    )
    assertion_metric = _audited_suite_assertion_metric(
        critical_surfaces,
        classification_complete=critical_classification_complete,
    )
    gaps = [
        _audited_suite_gap(surface)
        for surface in critical_surfaces
        if surface.assertion_status is not AuditedSuiteAssertionStatus.ASSERTION_COVERED
    ]
    selected, executed, failed = _repository_suite_runtime_counts(
        scanner_runs,
        expected_repository_sha256=expected_repository_sha256,
    )
    limitations = [*partition.limitations, *mutation_limitations]
    if not critical_classification_complete:
        limitations.extend(
            f"critical classification incomplete: {limitation}"
            for limitation in critical_classification_limitations
        )
        limitations.append(
            "critical classification incomplete: all classified audited-source contracts "
            "and functions were conservatively retained in the critical denominator"
        )
    if not _is_sha256(expected_repository_sha256):
        limitations.append(
            "repository-suite runtime evidence lacks an exact current-repository identity; "
            "runtime test counts remain not analyzed"
        )
    elif not selected:
        limitations.append(
            "repository-owned suite selection evidence for the exact current repository "
            "was not produced"
        )
    elif not executed:
        limitations.append("repository-owned tests were selected but no test executed")
    if supplied_statements:
        limitations.append(
            "self-declared statement coverage artifacts lack a process-local trusted "
            "normalizer receipt; no statement credit was awarded"
        )
    elif surfaces:
        limitations.append(
            "trusted statement coverage producer evidence was not supplied; statement "
            "coverage remains not analyzed"
        )
    if critical_surfaces and all(
        surface.assertion_status is AuditedSuiteAssertionStatus.NOT_ANALYZED
        for surface in critical_surfaces
    ):
        limitations.append("no fully reconciled mutation campaign earned assertion credit")
    return AuditedSuiteCoverage(
        contract_statement_coverage=contract_metric,
        function_statement_coverage=function_metric,
        critical_function_assertion_coverage=assertion_metric,
        surfaces=surfaces,
        gaps=sorted(gaps, key=lambda gap: (gap.entity_id, gap.kind.value)),
        repository_tests_selected=selected,
        repository_tests_executed=executed,
        repository_tests_failed=failed,
        source_classification_complete=partition.classification_complete,
        critical_classification_complete=critical_classification_complete,
        limitations=sorted(set(limitations)),
    )


def _audited_suite_statement_metric(
    surfaces: list[AuditedSuiteSurfaceCoverage],
    *,
    population: int,
    exclusions: list[CoverageExclusion],
    detail: str,
    empty_evidence: str,
    classification_complete: bool,
) -> CoverageMetric:
    covered = sum(
        surface.statement_status is AuditedSuiteStatementStatus.COVERED for surface in surfaces
    )
    analyzed = [
        surface
        for surface in surfaces
        if surface.statement_status is not AuditedSuiteStatementStatus.NOT_ANALYZED
    ]
    state = (
        AnalysisState.NOT_ANALYZED
        if not analyzed
        else (
            AnalysisState.DETERMINISTIC
            if len(analyzed) == len(surfaces)
            and all(
                surface.statement_status
                in {
                    AuditedSuiteStatementStatus.COVERED,
                    AuditedSuiteStatementStatus.UNCOVERED,
                }
                for surface in analyzed
            )
            else AnalysisState.ATTEMPTED_FAILED
        )
    )
    failures = [
        f"{surface.entity_id}: statement coverage {surface.statement_status.value}"
        for surface in surfaces
        if surface.statement_status is not AuditedSuiteStatementStatus.COVERED
    ][:100]
    if not classification_complete and not surfaces:
        failures = ["audited-source classification is incomplete"]
    return _metric(
        covered,
        len(surfaces),
        state,
        detail,
        population=population,
        exclusions=exclusions,
        not_applicable_evidence=(
            [empty_evidence] if not surfaces and classification_complete else []
        ),
        confidence=1,
        provenance=[
            CoverageProvenance.SYMBOL_INDEX,
            *([CoverageProvenance.RUNTIME] if analyzed else []),
        ],
        failures=failures,
    )


def _audited_suite_assertion_metric(
    surfaces: list[AuditedSuiteSurfaceCoverage],
    *,
    classification_complete: bool,
) -> CoverageMetric:
    covered = sum(
        surface.assertion_status is AuditedSuiteAssertionStatus.ASSERTION_COVERED
        for surface in surfaces
    )
    analyzed = [
        surface
        for surface in surfaces
        if surface.assertion_status is not AuditedSuiteAssertionStatus.NOT_ANALYZED
    ]
    state = (
        AnalysisState.NOT_ANALYZED
        if not analyzed
        else (
            AnalysisState.DETERMINISTIC
            if len(analyzed) == len(surfaces)
            and all(
                surface.assertion_status
                in {
                    AuditedSuiteAssertionStatus.ASSERTION_COVERED,
                    AuditedSuiteAssertionStatus.WEAK_ASSERTION,
                }
                for surface in analyzed
            )
            else AnalysisState.ATTEMPTED_FAILED
        )
    )
    failures = [
        f"{surface.entity_id}: assertion coverage {surface.assertion_status.value}"
        for surface in surfaces
        if surface.assertion_status is not AuditedSuiteAssertionStatus.ASSERTION_COVERED
    ][:100]
    if not classification_complete and not surfaces:
        failures = ["critical-surface classification is incomplete"]
    return _metric(
        covered,
        len(surfaces),
        state,
        "Critical audited-source surfaces with qualifying assertion-strength evidence",
        population=len(surfaces),
        exclusions=[],
        not_applicable_evidence=(
            ["semantic graph and invariant inventory contain no critical source surfaces"]
            if not surfaces and classification_complete
            else []
        ),
        confidence=1,
        provenance=[
            CoverageProvenance.SYMBOL_INDEX,
            CoverageProvenance.SEMANTIC_GRAPH,
        ],
        failures=failures,
    )


def _audited_suite_gap(
    surface: AuditedSuiteSurfaceCoverage,
) -> AuditedSuiteCoverageGap:
    kind = {
        AuditedSuiteAssertionStatus.NOT_ANALYZED: (
            AuditedSuiteCoverageGapKind.ASSERTION_NOT_ANALYZED
        ),
        AuditedSuiteAssertionStatus.INCONCLUSIVE: (
            AuditedSuiteCoverageGapKind.ASSERTION_INCONCLUSIVE
        ),
        AuditedSuiteAssertionStatus.WEAK_ASSERTION: (AuditedSuiteCoverageGapKind.WEAK_ASSERTION),
    }[surface.assertion_status]
    evidence_sha256s = sorted(
        {
            *surface.statement_evidence_sha256s,
            *surface.repository_test_execution_sha256s,
            *(evidence.evidence_sha256 for evidence in surface.mutation_evidence),
        }
    )
    detail = {
        AuditedSuiteCoverageGapKind.ASSERTION_NOT_ANALYZED: (
            "No entity-bound mutation execution evidence was available; assertion strength "
            "remains not analyzed."
        ),
        AuditedSuiteCoverageGapKind.ASSERTION_INCONCLUSIVE: (
            "Entity-bound mutation execution was inconclusive; no assertion-strength credit "
            "was awarded."
        ),
        AuditedSuiteCoverageGapKind.WEAK_ASSERTION: (
            "An applicable entity-bound mutation survived the repository-owned suite."
        ),
    }[kind]
    return AuditedSuiteCoverageGap(
        gap_id=AuditedSuiteCoverageGap.calculate_gap_id(surface.entity_id, kind),
        entity_id=surface.entity_id,
        entity_kind=surface.entity_kind,
        location=surface.location,
        kind=kind,
        assertion_status=surface.assertion_status,
        evidence_sha256s=evidence_sha256s,
        detail=detail,
    )


def _reconcile_mutation_surface_evidence(
    *,
    entities_by_id: dict[str, SolidityEntity],
    source_function_ids: set[str],
    scanner_runs: list[ScannerRun],
    plan: MutationApplicabilityPlan | None,
    campaigns: list[MutationCampaignEvidence],
    surface_bindings: list[AuditedSuiteMutationSurfaceEvidence],
    expected_repository_sha256: str | None,
    source_file_sha256s: dict[str, str],
) -> tuple[dict[str, list[AuditedSuiteMutationEvidence]], list[str]]:
    """Derive surface outcomes only from a complete scorer-authoritative join."""

    limitations: list[str] = []
    if not surface_bindings:
        if plan is not None or campaigns:
            limitations.append(
                "mutation campaigns lack exact source-surface bindings; no assertion "
                "credit was awarded"
            )
        return {}, limitations
    if plan is None:
        return {}, [
            "mutation surface bindings lack a validated applicability plan; no assertion "
            "credit was awarded"
        ]
    if not campaigns:
        return {}, [
            "mutation surface bindings lack campaign evidence; no assertion credit was awarded"
        ]

    binding_keys = [
        (binding.entity_id, binding.property_id, binding.mutation_id)
        for binding in surface_bindings
    ]
    if binding_keys != sorted(set(binding_keys)):
        raise ValueError("mutation surface bindings must be unique and canonically sorted")
    binding_pairs = [(binding.property_id, binding.mutation_id) for binding in surface_bindings]
    if len(binding_pairs) != len(set(binding_pairs)):
        raise ValueError("each planned property/mutation pair must bind exactly one source surface")
    if not _is_sha256(expected_repository_sha256):
        return {}, [
            "mutation plan source identity cannot be joined without an exact "
            "current-repository identity; no assertion credit was awarded"
        ]
    real_repository_sha256s = {
        run.repository_suite_selection.repository_sha256
        for run in _validated_real_repository_suite_runs(
            scanner_runs,
            expected_repository_sha256=expected_repository_sha256,
        )
        if run.repository_suite_selection is not None
    }
    if plan.source_repository_sha256 not in real_repository_sha256s:
        return {}, [
            "mutation plan source identity lacks a matching validated real repository-suite "
            "execution; no assertion credit was awarded"
        ]

    scorecard = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=campaigns,
        minimum_property_kill_score=0,
    )
    if scorecard.evidence_origin is not MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED:
        raise ValueError("mutation surface reconciliation requires an unattested planned scorecard")
    planned_bindings = {
        (binding.property_id, binding.mutation_id): binding for binding in plan.bindings
    }
    specifications = {specification.id: specification for specification in plan.specifications}
    campaigns_by_id = {campaign.mutation_id: campaign for campaign in campaigns}
    outcomes = {
        (outcome.property_id, outcome.mutation_id): outcome for outcome in scorecard.outcomes
    }
    result: dict[str, list[AuditedSuiteMutationEvidence]] = {}
    for surface_binding in surface_bindings:
        if surface_binding.entity_id not in source_function_ids:
            raise ValueError(
                "mutation surface binding references an excluded or non-function entity"
            )
        entity = entities_by_id[surface_binding.entity_id]
        expected_contract = entity.contract_name or "protocol"
        expected_location = Location(
            path=entity.path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            symbol=entity.signature or entity.name,
            content_hash=entity.source_hash,
        )
        if (
            surface_binding.entity_kind is not entity.kind
            or surface_binding.contract_name != expected_contract
            or surface_binding.location != expected_location
        ):
            raise ValueError("mutation surface binding differs from the exact source index")
        pair = (surface_binding.property_id, surface_binding.mutation_id)
        if pair not in planned_bindings:
            raise ValueError("mutation surface binding is absent from the applicability plan")
        specification = specifications[surface_binding.mutation_id]
        if (
            specification.path != entity.path
            or source_file_sha256s.get(specification.path) != specification.expected_file_sha256
            or not entity.start_line <= specification.line <= entity.end_line
        ):
            raise ValueError(
                "mutation source specification does not bind the exact discovered file "
                "and source entity"
            )
        campaign = campaigns_by_id.get(surface_binding.mutation_id)
        if campaign is None:
            limitations.append(
                f"{surface_binding.entity_id}: bound mutation campaign was not executed"
            )
            continue
        outcome = outcomes[pair]
        if outcome.evidence_sha256 != campaign.evidence_sha256:
            raise ValueError("mutation scorer outcome differs from campaign evidence")
        if outcome.outcome is not MutationTestOutcome.INCONCLUSIVE:
            raise ValueError("unattested planned mutation evidence cannot earn decisive credit")
        observation = campaign.executor_observation
        if observation is None:
            limitations.append(
                f"{surface_binding.entity_id}: bound mutation campaign lacks an exact "
                "execution observation"
            )
            continue
        joined = AuditedSuiteMutationEvidence.sealed(
            property_id=surface_binding.property_id,
            mutation_id=surface_binding.mutation_id,
            outcome=AuditedSuiteMutationOutcome.INCONCLUSIVE,
            plan_sha256=plan.plan_sha256,
            source_repository_sha256=plan.source_repository_sha256,
            mutation_specification_sha256=specification.specification_sha256(),
            campaign_evidence_sha256=campaign.evidence_sha256,
            observation_sha256=observation.observation_sha256,
            surface_binding_sha256=surface_binding.evidence_sha256,
        )
        result.setdefault(surface_binding.entity_id, []).append(joined)
    for values in result.values():
        values.sort(
            key=lambda evidence: (
                evidence.property_id,
                evidence.mutation_id,
                evidence.evidence_sha256,
            )
        )
    return result, sorted(set(limitations))


def _assertion_status_from_mutation_evidence(
    mutation_evidence: list[AuditedSuiteMutationEvidence],
) -> AuditedSuiteAssertionStatus:
    outcomes = {evidence.outcome for evidence in mutation_evidence}
    if not outcomes:
        return AuditedSuiteAssertionStatus.NOT_ANALYZED
    if AuditedSuiteMutationOutcome.SURVIVED in outcomes:
        return AuditedSuiteAssertionStatus.WEAK_ASSERTION
    if AuditedSuiteMutationOutcome.INCONCLUSIVE in outcomes:
        return AuditedSuiteAssertionStatus.INCONCLUSIVE
    return AuditedSuiteAssertionStatus.ASSERTION_COVERED


def _repository_suite_runtime_counts(
    scanner_runs: list[ScannerRun],
    *,
    expected_repository_sha256: str | None,
) -> tuple[int, int, int]:
    qualifying_runs = _validated_real_repository_suite_runs(
        scanner_runs,
        expected_repository_sha256=expected_repository_sha256,
    )
    selected_descriptor_ids = {
        descriptor.descriptor_sha256
        for run in qualifying_runs
        if run.repository_suite_selection is not None
        for descriptor in run.repository_suite_selection.tests
    }
    executions_by_descriptor: dict[str, list[RepositoryTestExecution]] = {}
    for execution in (
        execution for run in qualifying_runs for execution in run.repository_test_executions
    ):
        executions_by_descriptor.setdefault(execution.descriptor_sha256, []).append(execution)
    attempted_statuses = {
        RepositoryTestExecutionStatus.PASSED,
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
        RepositoryTestExecutionStatus.TIMED_OUT,
        RepositoryTestExecutionStatus.INVALID_OUTPUT,
    }
    failed_statuses = {
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
        RepositoryTestExecutionStatus.TIMED_OUT,
        RepositoryTestExecutionStatus.INVALID_OUTPUT,
    }
    executed_descriptor_ids: set[str] = set()
    failed_descriptor_ids: set[str] = set()
    for descriptor_sha256 in selected_descriptor_ids:
        attempted = [
            execution
            for execution in executions_by_descriptor.get(descriptor_sha256, [])
            if execution.status in attempted_statuses
        ]
        if not attempted:
            continue
        executed_descriptor_ids.add(descriptor_sha256)
        statuses = {execution.status for execution in attempted}
        if statuses & failed_statuses or len(statuses) != 1:
            failed_descriptor_ids.add(descriptor_sha256)
    return (
        len(selected_descriptor_ids),
        len(executed_descriptor_ids),
        len(failed_descriptor_ids),
    )


def _validated_real_repository_suite_runs(
    scanner_runs: list[ScannerRun],
    *,
    expected_repository_sha256: str | None,
) -> list[ScannerRun]:
    """Revalidate complete scanner schemas before any runtime evidence earns credit."""

    if not _is_sha256(expected_repository_sha256):
        return []
    validated_runs: list[ScannerRun] = []
    for candidate in scanner_runs:
        try:
            run = validated_scanner_run_copy_preserving_runtime_authority(candidate)
        except (TypeError, ValueError):
            continue
        if (
            has_host_repository_suite_runtime_authority(run)
            and run.scanner == "foundry_fork"
            and run.status
            in {
                ScannerStatus.SUCCESS,
                ScannerStatus.FAILED,
                ScannerStatus.TIMED_OUT,
            }
            and run.execution_evidence is ExecutionEvidenceKind.REAL
            and run.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
            and run.repository_suite_selection is not None
            and run.repository_suite_selection.repository_sha256 == expected_repository_sha256
            and run.isolation_backend is not None
            and run.isolation_attestation_sha256 is not None
            and run.execution_observation_sha256_is_valid()
        ):
            validated_runs.append(run)
    return validated_runs


def _is_sha256(value: str | None) -> bool:
    return (
        value is not None
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _path_is_within_directory(path: str, directory: str) -> bool:
    normalized = directory.rstrip("/")
    return normalized in {"", "."} or path == normalized or path.startswith(f"{normalized}/")


def _directory_depth(directory: str) -> int:
    return 0 if directory in {"", "."} else len(PurePosixPath(directory).parts)


def _project_directories_are_safe(project: SolidityProjectMetadata) -> bool:
    if not _classification_path_is_safe(project.project_root, allow_root=True):
        return False
    directories = [
        *project.source_directories,
        *project.test_directories,
        *project.script_directories,
        *project.deployment_directories,
    ]
    return all(
        _classification_path_is_safe(directory, allow_root=True)
        and _path_is_within_directory(directory, project.project_root)
        for directory in directories
    )


def _classification_path_is_safe(path: str, *, allow_root: bool) -> bool:
    if path == ".":
        return allow_root
    pure = PurePosixPath(path)
    return (
        bool(path)
        and not pure.is_absolute()
        and "\\" not in path
        and all(part not in {"", ".", ".."} for part in pure.parts)
    )


def _conventional_test_directory(path: str, project_root: str) -> str | None:
    if project_root in {"", "."}:
        relative = PurePosixPath(path)
    else:
        try:
            relative = PurePosixPath(path).relative_to(PurePosixPath(project_root))
        except ValueError:
            return None
    if not relative.parts or relative.parts[0].casefold() not in {
        "test",
        "tests",
        "spec",
        "specs",
    }:
        return None
    return relative.parts[0] if project_root in {"", "."} else f"{project_root}/{relative.parts[0]}"


def _economic_template_execution_coverage(
    plans: list[EconomicSimulationPlan],
    executions: list[InvariantExecutionResult],
) -> dict[EconomicSimulationKind, EconomicTemplateExecutionCoverage]:
    coverage: dict[EconomicSimulationKind, EconomicTemplateExecutionCoverage] = {}
    completed_statuses = {
        InvariantExecutionStatus.PASSED,
        InvariantExecutionStatus.COUNTEREXAMPLE,
    }
    for plan in sorted(plans, key=lambda item: item.kind.value):
        template_executions = [
            result for result in executions if result.economic_template is plan.kind
        ]
        completed = [
            result for result in template_executions if result.status in completed_statuses
        ]
        counterexamples = [
            result
            for result in completed
            if result.status is InvariantExecutionStatus.COUNTEREXAMPLE
        ]
        statuses: dict[InvariantExecutionStatus, int] = {}
        for result in template_executions:
            statuses[result.status] = statuses.get(result.status, 0) + 1
        coverage[plan.kind] = EconomicTemplateExecutionCoverage(
            kind=plan.kind,
            applicable=plan.applicable,
            execution_required=plan.execution_required,
            typed_harness_available=plan.typed_harness_available,
            harnesses_generated=len(template_executions),
            harnesses_compiled=len(completed),
            harnesses_executed=len(completed),
            harnesses_replayed=sum(result.replay_confirmed for result in completed),
            counterexamples=len(counterexamples),
            counterexamples_minimized=sum(
                result.minimization_evidence is not None
                and result.minimization_evidence.proven_minimal
                for result in counterexamples
            ),
            statuses=statuses,
            source_sha256s=sorted(
                {
                    result.source_sha256
                    for result in template_executions
                    if result.source_sha256 is not None
                }
            ),
            compiler_sha256s=sorted(
                {
                    result.compiler_sha256
                    for result in template_executions
                    if result.compiler_sha256 is not None
                }
            ),
            limitations=sorted(
                {
                    *plan.limitations,
                    *(
                        limitation
                        for result in template_executions
                        for limitation in result.limitations
                    ),
                }
            ),
        )
    return coverage


def _invariant_campaign_quality_metrics(
    *,
    campaign_functions_declared: int,
    campaign_functions_observed: int,
    campaign_states_declared: int,
    campaign_states_observed: int,
    counterexample_count: int,
    counterexample_sequences_observed: int,
    counterexample_sequences_minimized: int,
    campaigns_present: bool,
) -> dict[str, CoverageMetric]:
    """Report function, state-property, and sequence coverage independently."""

    state = AnalysisState.DETERMINISTIC if campaigns_present else AnalysisState.NOT_ANALYZED
    provenance = [CoverageProvenance.INVARIANT_EXECUTION]
    no_campaign_failure = (
        [] if campaigns_present else ["no completed Foundry invariant campaign evidence"]
    )
    return {
        "invariant_campaign_function_coverage": _metric(
            campaign_functions_observed,
            campaign_functions_declared,
            state,
            "Declared stateful action functions observed in bounded Foundry output",
            population=campaign_functions_declared,
            exclusions=[],
            not_applicable_evidence=(
                ["completed campaigns declared no stateful action functions"]
                if campaigns_present and not campaign_functions_declared
                else []
            ),
            confidence=1,
            provenance=provenance,
            failures=(
                no_campaign_failure
                or _coverage_gap(
                    campaign_functions_observed,
                    campaign_functions_declared,
                    "declared action function(s) were absent from campaign output",
                )
            ),
        ),
        "invariant_campaign_state_coverage": _metric(
            campaign_states_observed,
            campaign_states_declared,
            state,
            "Declared invariant state properties observed in bounded Foundry output",
            population=campaign_states_declared,
            exclusions=[],
            not_applicable_evidence=(
                ["completed campaigns declared no invariant state properties"]
                if campaigns_present and not campaign_states_declared
                else []
            ),
            confidence=1,
            provenance=provenance,
            failures=(
                no_campaign_failure
                or _coverage_gap(
                    campaign_states_observed,
                    campaign_states_declared,
                    "declared state property/properties were absent from campaign output",
                )
            ),
        ),
        "invariant_campaign_sequence_coverage": _metric(
            counterexample_sequences_minimized,
            counterexample_count,
            state,
            (
                "Observed counterexample sequences with persisted seeds, clean replay, "
                "and proven bounded minimization"
            ),
            population=counterexample_count,
            exclusions=[],
            not_applicable_evidence=(
                ["completed campaigns produced no counterexample sequences"]
                if campaigns_present and not counterexample_count
                else []
            ),
            confidence=1,
            provenance=provenance,
            failures=(
                no_campaign_failure
                or (
                    [
                        (
                            f"{counterexample_count - counterexample_sequences_observed} "
                            "counterexample(s) lacked normalized sequence evidence"
                        )
                    ]
                    if counterexample_sequences_observed < counterexample_count
                    else _coverage_gap(
                        counterexample_sequences_minimized,
                        counterexample_count,
                        "counterexample sequence(s) were not proven minimal",
                    )
                )
            ),
        ),
    }


def _economic_template_quality_metrics(
    execution_coverage: dict[EconomicSimulationKind, EconomicTemplateExecutionCoverage],
) -> dict[str, CoverageMetric]:
    metrics: dict[str, CoverageMetric] = {}
    provenance = [
        CoverageProvenance.SEMANTIC_GRAPH,
        CoverageProvenance.INVARIANT_EXECUTION,
    ]
    for kind, evidence in execution_coverage.items():
        if not evidence.applicable or not evidence.execution_required:
            continue
        prefix = f"economic_{kind.value}"
        generated = evidence.harnesses_generated
        generated_failures = (
            [] if generated else [f"{kind.value}: no typed invariant harness was generated"]
        )
        metrics[f"{prefix}_generated"] = _metric(
            int(generated > 0),
            1,
            AnalysisState.DETERMINISTIC,
            f"{kind.value} applicable template with at least one generated typed harness",
            population=1,
            exclusions=[],
            not_applicable_evidence=[],
            confidence=1,
            provenance=provenance,
            failures=generated_failures,
        )
        for phase, numerator in (
            ("compiled", evidence.harnesses_compiled),
            ("executed", evidence.harnesses_executed),
            ("replayed", evidence.harnesses_replayed),
        ):
            metrics[f"{prefix}_{phase}"] = _metric(
                numerator,
                generated,
                (AnalysisState.DETERMINISTIC if generated else AnalysisState.NOT_ANALYZED),
                f"Generated {kind.value} harnesses with {phase} evidence",
                population=generated,
                exclusions=[],
                not_applicable_evidence=[],
                confidence=1,
                provenance=provenance,
                failures=(
                    [f"{kind.value}: no generated harness was available for {phase} evidence"]
                    if not generated
                    else _coverage_gap(
                        numerator,
                        generated,
                        f"generated {kind.value} harness(es) lack {phase} evidence",
                    )
                ),
            )
        metrics[f"{prefix}_counterexamples_minimized"] = _metric(
            evidence.counterexamples_minimized,
            evidence.counterexamples,
            (
                AnalysisState.DETERMINISTIC
                if evidence.harnesses_executed
                else AnalysisState.NOT_ANALYZED
            ),
            f"Observed {kind.value} counterexamples with bounded minimization evidence",
            population=evidence.counterexamples,
            exclusions=[],
            not_applicable_evidence=(
                [f"{kind.value}: completed executions produced no counterexample"]
                if evidence.harnesses_executed and not evidence.counterexamples
                else []
            ),
            confidence=1,
            provenance=provenance,
            failures=(
                [f"{kind.value}: no completed execution was available for minimization"]
                if not evidence.harnesses_executed
                else _coverage_gap(
                    evidence.counterexamples_minimized,
                    evidence.counterexamples,
                    f"{kind.value} counterexample(s) lack minimization evidence",
                )
            ),
        )
    return metrics


def with_model_review_coverage(
    coverage: SolidityCoverage,
    index: SoliditySymbolIndex | None,
    review_coverage: ModelReviewCoverage,
    graphs: SolidityGraphSet | None = None,
) -> SolidityCoverage:
    """Project validated substantive review evidence onto Solidity function metrics."""

    if index is None:
        return coverage
    all_function_ids = {
        entity.id
        for entity in index.entities
        if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
    }
    audited_suite = coverage.audited_suite_coverage
    external_classification_complete = (
        audited_suite is None or audited_suite.source_classification_complete
    )
    external_limitations = (
        tuple(
            limitation
            for limitation in audited_suite.limitations
            if limitation.startswith("source classification incomplete:")
        )
        if audited_suite is not None and not audited_suite.source_classification_complete
        else ()
    )
    audited_function_ids = set(
        partition_audited_source_entities(
            index=index,
            projects=index.projects,
        ).function_entity_ids
    )
    entry_point_population = _audited_function_population(
        index=index,
        projects=index.projects,
        candidate_ids={
            entity.id
            for entity in index.entities
            if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
            and entity.visibility in {"public", "external"}
        },
        external_classification_complete=external_classification_complete,
        external_limitations=external_limitations,
    )
    privilege_graph_complete, privilege_graph_limitations = _graph_kind_classification_evidence(
        graphs,
        SolidityGraphKind.PRIVILEGE,
        external_classification_complete=external_classification_complete,
        external_limitations=external_limitations,
    )
    state_write_graph_complete, state_write_graph_limitations = _graph_kind_classification_evidence(
        graphs,
        SolidityGraphKind.STATE_WRITE,
        external_classification_complete=external_classification_complete,
        external_limitations=external_limitations,
    )
    sensitive_graph_complete, sensitive_graph_limitations = _graph_kind_classification_evidence(
        graphs,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
        external_classification_complete=external_classification_complete,
        external_limitations=external_limitations,
    )
    population_by_metric = {
        "public_external_entry_points_reviewed": entry_point_population,
        "privileged_entry_points_reviewed": _audited_function_population(
            index=index,
            projects=index.projects,
            candidate_ids=_graph_source_ids(graphs, SolidityGraphKind.PRIVILEGE),
            external_classification_complete=privilege_graph_complete,
            external_limitations=privilege_graph_limitations,
        ),
        "state_writing_functions_reviewed": _audited_function_population(
            index=index,
            projects=index.projects,
            candidate_ids=_graph_source_ids(graphs, SolidityGraphKind.STATE_WRITE),
            external_classification_complete=state_write_graph_complete,
            external_limitations=state_write_graph_limitations,
        ),
        "high_value_paths_reviewed": _audited_function_population(
            index=index,
            projects=index.projects,
            candidate_ids=_graph_source_ids(graphs, SolidityGraphKind.SENSITIVE_REACHABILITY),
            external_classification_complete=sensitive_graph_complete,
            external_limitations=sensitive_graph_limitations,
        ),
    }
    reviewed_ids = {
        surface.subject_id
        for surface in review_coverage.surfaces
        if surface.reviewed
        and surface.subject_id in all_function_ids
        and surface.subject_id in audited_function_ids
    }
    metrics = dict(coverage.quality_metrics)
    for metric_name, population in population_by_metric.items():
        source_ids = set(population.entity_ids)
        existing = metrics[metric_name]
        reviewed_count = len(reviewed_ids & source_ids)
        classification_complete = population.classification_complete and review_coverage.applicable
        failures = list(population.limitations) if not population.classification_complete else []
        if not review_coverage.applicable:
            failures.extend(
                review_coverage.limitations
                or ["substantive model-review coverage was not applicable"]
            )
        if source_ids:
            failures.extend(
                _coverage_gap(
                    reviewed_count,
                    len(source_ids),
                    "eligible function(s) lack validated substantive model reviews",
                )
            )
            not_applicable_evidence: list[str] = []
        elif classification_complete:
            failures = []
            not_applicable_evidence = list(existing.not_applicable_evidence) or [
                "no audited-source function is applicable to this review metric"
            ]
        else:
            not_applicable_evidence = []
        metrics[metric_name] = _metric(
            reviewed_count,
            len(source_ids),
            (AnalysisState.MODEL_ONLY if classification_complete else AnalysisState.NOT_ANALYZED),
            existing.detail,
            population=len(source_ids) + len(population.exclusions),
            exclusions=list(population.exclusions),
            not_applicable_evidence=not_applicable_evidence,
            confidence=existing.confidence,
            provenance=existing.provenance,
            failures=sorted(set(failures)),
        )
    return coverage.model_copy(
        update={
            "functions_reviewed_by_models": len(reviewed_ids),
            "quality_metrics": metrics,
        }
    )


def with_invariant_review_coverage(
    coverage: SolidityCoverage,
    review: InvariantReviewResult | None,
) -> SolidityCoverage:
    """Record model invariant hypotheses without mixing them into deterministic counts."""

    if review is None:
        return coverage
    total = len(review.accepted_proposals) + len(review.rejected_proposals)
    metrics = dict(coverage.quality_metrics)
    metrics["model_invariant_proposal_validation"] = _metric(
        total,
        total,
        AnalysisState.MODEL_ONLY,
        "Model-proposed invariants that received deterministic source and entity validation",
        population=total,
        exclusions=[],
        not_applicable_evidence=(
            ["invariant review returned no model-proposed hypotheses"] if not total else []
        ),
        confidence=1,
        provenance=[
            CoverageProvenance.MODEL_CONTEXT,
            CoverageProvenance.SYMBOL_INDEX,
        ],
        failures=[],
    )
    return coverage.model_copy(
        update={
            "model_invariants_proposed": total,
            "model_invariants_validated": len(review.accepted_proposals),
            "quality_metrics": metrics,
        }
    )


def with_runtime_coverage(
    coverage: SolidityCoverage,
    *,
    eligible_candidate_ids: set[str],
    attempted_candidate_ids: set[str],
    economic_plans: list[EconomicSimulationPlan],
    invariant_executions: list[InvariantExecutionResult],
    formal_runs: list[FormalToolRun],
    expected_model_roles: int,
    completed_model_roles: int,
) -> SolidityCoverage:
    """Add post-model and post-execution metrics without hiding empty denominators."""

    metrics = dict(coverage.quality_metrics)
    completed_economic = {
        result.economic_template
        for result in invariant_executions
        if result.economic_template is not None
        and result.status
        in {
            InvariantExecutionStatus.PASSED,
            InvariantExecutionStatus.COUNTEREXAMPLE,
        }
    }
    applicable_economic = {
        plan.kind for plan in economic_plans if plan.applicable and plan.execution_required
    }
    typed_economic = {
        plan.kind
        for plan in economic_plans
        if plan.applicable and plan.execution_required and plan.typed_harness_available
    }
    economic_by_kind = {plan.kind: plan for plan in economic_plans}
    economic_exclusions = [
        CoverageExclusion(
            subject=kind.value,
            reason=(
                plan.rationale
                if not plan.applicable
                else "template was assessed as applicable but execution was not required"
            ),
            provenance=CoverageProvenance.SEMANTIC_GRAPH,
        )
        for kind, plan in sorted(economic_by_kind.items(), key=lambda item: item[0].value)
        if kind not in applicable_economic
    ]
    formal_requested = [run for run in formal_runs if run.status is not FormalToolStatus.SKIPPED]
    formal_exclusions = [
        CoverageExclusion(
            subject=f"{run.tool}[{position}]",
            reason=run.failure_reason or "formal engine was explicitly skipped",
            provenance=CoverageProvenance.CONFIGURATION,
        )
        for position, run in enumerate(formal_runs)
        if run.status is FormalToolStatus.SKIPPED
    ]
    reproduced_candidates = eligible_candidate_ids & attempted_candidate_ids
    completed_economic_count = len(completed_economic & applicable_economic)
    formal_successes = sum(run.status is FormalToolStatus.SUCCESS for run in formal_requested)
    metrics.update(
        {
            "candidate_reproduction_tested": _metric(
                len(reproduced_candidates),
                len(eligible_candidate_ids),
                (
                    AnalysisState.REPRODUCED
                    if attempted_candidate_ids
                    else AnalysisState.NOT_ANALYZED
                ),
                "Eligible candidate findings with a bounded executable attempt",
                population=len(eligible_candidate_ids),
                exclusions=[],
                not_applicable_evidence=(
                    ["no candidate finding was eligible for bounded reproduction"]
                    if not eligible_candidate_ids
                    else []
                ),
                confidence=1,
                provenance=[CoverageProvenance.RUNTIME],
                failures=[
                    f"{candidate_id}: no bounded executable attempt was recorded"
                    for candidate_id in sorted(eligible_candidate_ids - reproduced_candidates)
                ],
            ),
            "economic_templates_executed": _metric(
                completed_economic_count,
                len(applicable_economic),
                (AnalysisState.DETERMINISTIC if completed_economic else AnalysisState.NOT_ANALYZED),
                "Applicable protocol economic templates with a completed typed harness",
                population=len(economic_by_kind),
                exclusions=economic_exclusions,
                not_applicable_evidence=(
                    ["no economic template required execution for the analyzed protocol"]
                    if not applicable_economic
                    else []
                ),
                confidence=1,
                provenance=[
                    CoverageProvenance.SEMANTIC_GRAPH,
                    CoverageProvenance.INVARIANT_EXECUTION,
                ],
                failures=[
                    f"{kind.value}: no completed typed economic execution"
                    for kind in sorted(
                        applicable_economic - completed_economic,
                        key=lambda item: item.value,
                    )
                ],
            ),
            "economic_templates_with_typed_harness": _metric(
                len(typed_economic),
                len(applicable_economic),
                (AnalysisState.DETERMINISTIC if typed_economic else AnalysisState.NOT_ANALYZED),
                "Applicable protocol economic templates currently expressible as typed Foundry harnesses",
                population=len(economic_by_kind),
                exclusions=economic_exclusions,
                not_applicable_evidence=(
                    ["no economic template required execution for the analyzed protocol"]
                    if not applicable_economic
                    else []
                ),
                confidence=1,
                provenance=[
                    CoverageProvenance.SEMANTIC_GRAPH,
                    CoverageProvenance.INVARIANT_EXECUTION,
                ],
                failures=[
                    f"{kind.value}: no typed invariant harness is available"
                    for kind in sorted(
                        applicable_economic - typed_economic,
                        key=lambda item: item.value,
                    )
                ],
            ),
            "formal_engine_completion": _metric(
                formal_successes,
                len(formal_requested),
                (AnalysisState.DETERMINISTIC if formal_requested else AnalysisState.NOT_ANALYZED),
                "Inventoried formal/property engines that completed successfully",
                population=len(formal_runs),
                exclusions=formal_exclusions,
                not_applicable_evidence=(
                    ["no formal/property engine was requested"]
                    if not formal_runs
                    else (
                        ["all inventoried formal/property engines were explicitly skipped"]
                        if not formal_requested
                        else []
                    )
                ),
                confidence=1,
                provenance=[
                    CoverageProvenance.CONFIGURATION,
                    CoverageProvenance.FORMAL_ENGINE,
                ],
                failures=[
                    f"{run.tool}: formal engine status {run.status.value}"
                    for run in formal_requested
                    if run.status is not FormalToolStatus.SUCCESS
                ],
            ),
            "model_role_completion": _metric(
                completed_model_roles,
                expected_model_roles,
                (AnalysisState.MODEL_ONLY if completed_model_roles else AnalysisState.NOT_ANALYZED),
                "Configured base and specialist model responsibilities that completed",
                population=expected_model_roles,
                exclusions=[],
                not_applicable_evidence=(
                    ["no model roles were configured"] if not expected_model_roles else []
                ),
                confidence=1,
                provenance=[
                    CoverageProvenance.CONFIGURATION,
                    CoverageProvenance.MODEL_CONTEXT,
                ],
                failures=_coverage_gap(
                    completed_model_roles,
                    expected_model_roles,
                    "configured model role(s) did not complete",
                ),
            ),
        }
    )
    return coverage.model_copy(update={"quality_metrics": metrics})


def _static_tool_function_count(
    functions: list[SolidityEntity],
    scanner_runs: list[ScannerRun],
) -> int:
    if any(
        run.scanner == "slither" and run.status is ScannerStatus.SUCCESS for run in scanner_runs
    ):
        return len(functions)
    covered: set[str] = set()
    for run in scanner_runs:
        if run.scanner != "slither" or run.status is not ScannerStatus.SUCCESS:
            continue
        for finding in run.findings:
            for location in finding.locations:
                for function in functions:
                    if (
                        function.path == location.path
                        and function.start_line <= location.start_line <= function.end_line
                    ):
                        covered.add(function.id)
    return len(covered)


def _graph_source_ids(
    graphs: SolidityGraphSet | None,
    graph_kind: SolidityGraphKind,
) -> set[str]:
    return {edge.source_id for edge in (graphs.edges if graphs else []) if edge.graph is graph_kind}


def _graph_kind_classification_evidence(
    graphs: SolidityGraphSet | None,
    graph_kind: SolidityGraphKind,
    *,
    external_classification_complete: bool = True,
    external_limitations: tuple[str, ...] = (),
) -> tuple[bool, tuple[str, ...]]:
    """Require the producer's exact graph-kind completion declaration."""

    limitations = set(external_limitations)
    if graphs is None:
        limitations.add("Solidity semantic graph was not produced")
    elif graph_kind not in graphs.analyzed_graphs:
        limitations.add(f"{graph_kind.value} graph kind was not analyzed")
    return (
        external_classification_complete
        and graphs is not None
        and graph_kind in graphs.analyzed_graphs,
        tuple(sorted(limitations)),
    )


def _graph_source_confidence(
    graphs: SolidityGraphSet | None,
    source_ids: set[str],
) -> float:
    return min(
        (
            edge.confidence
            for edge in (graphs.edges if graphs else [])
            if edge.source_id in source_ids
        ),
        default=1,
    )


def _coverage_gap(numerator: int, denominator: int, description: str) -> list[str]:
    missing = denominator - numerator
    return [f"{missing} {description}"] if missing > 0 else []


def _compiler_index_failures(
    *,
    projects: list[SolidityProjectMetadata],
    compilations: list[SolidityCompilationResult],
    compiled_names: set[str],
    indexed_names: set[str],
) -> list[str]:
    project_roots = {project.project_root for project in projects}
    compiled_project_roots = {result.project_root for result in compilations}
    failures = [
        f"{result.project_root}: compilation status {result.status.value}"
        for result in compilations
        if result.status is not CompilationStatus.SUCCESS
    ]
    failures.extend(
        f"{project_root}: no compilation result was produced"
        for project_root in sorted(project_roots - compiled_project_roots)
    )
    failures.extend(
        f"{name}: compiler-reported contract is absent from the symbol index"
        for name in sorted(compiled_names - indexed_names)
    )
    failures.extend(
        f"{name}: indexed contract lacks compiler confirmation"
        for name in sorted(indexed_names - compiled_names)
    )
    if projects and not compiled_names and not indexed_names:
        failures.append("compiler and symbol index produced no measurable contract population")
    return failures


def _metric(
    numerator: int,
    denominator: int,
    state: AnalysisState,
    detail: str,
    *,
    population: int,
    exclusions: list[CoverageExclusion],
    not_applicable_evidence: list[str],
    confidence: float,
    provenance: list[CoverageProvenance],
    failures: list[str],
) -> CoverageMetric:
    return CoverageMetric(
        numerator=numerator,
        denominator=denominator,
        population=population,
        percentage=(round((numerator / denominator) * 100, 4) if denominator else None),
        exclusions=exclusions,
        not_applicable_evidence=not_applicable_evidence,
        confidence=confidence,
        provenance=provenance,
        failures=failures,
        state=state,
        detail=detail,
    )
