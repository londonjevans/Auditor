"""Solidity coverage and audit-quality metadata."""

from __future__ import annotations

from mmaudit.models.schemas import (
    AnalysisState,
    CompilationStatus,
    CoverageExclusion,
    CoverageMetric,
    CoverageProvenance,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    EconomicTemplateExecutionCoverage,
    FormalToolRun,
    FormalToolStatus,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantReviewResult,
    InvariantSuite,
    ModelReviewCoverage,
    ScannerRun,
    ScannerStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
)
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.solidity.graphs import summarize_asset_flows, summarize_control_dependencies


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
) -> SolidityCoverage:
    """Summarize what the deterministic Solidity layer did and did not analyze."""

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
    formal_runs = formal_runs or []
    invariant_executions = invariant_executions or []
    economic_simulations = economic_simulations or []
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
    entry_points = [entity for entity in functions if entity.visibility in {"public", "external"}]
    privilege_sources = _graph_source_ids(graphs, SolidityGraphKind.PRIVILEGE)
    state_write_sources = _graph_source_ids(graphs, SolidityGraphKind.STATE_WRITE)
    sensitive_sources = _graph_source_ids(
        graphs,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    )
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
            population=len(entry_points),
            exclusions=[],
            not_applicable_evidence=(
                ["symbol index contains no public or external entry points"]
                if not entry_points and index is not None
                else []
            ),
            confidence=min((entity.confidence for entity in entry_points), default=1),
            provenance=[
                CoverageProvenance.SYMBOL_INDEX,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=(
                [model_review_pending]
                if entry_points
                else (["Solidity symbol index was not produced"] if index is None else [])
            ),
        ),
        "privileged_entry_points_reviewed": _metric(
            0,
            len(privilege_sources),
            AnalysisState.NOT_ANALYZED,
            "Privilege-graph source functions with validated substantive model reviews",
            population=len(privilege_sources),
            exclusions=[],
            not_applicable_evidence=(
                ["semantic graph contains no privileged entry points"]
                if not privilege_sources and graphs is not None
                else []
            ),
            confidence=_graph_source_confidence(graphs, privilege_sources),
            provenance=[
                CoverageProvenance.SEMANTIC_GRAPH,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=(
                [model_review_pending]
                if privilege_sources
                else (["Solidity semantic graph was not produced"] if graphs is None else [])
            ),
        ),
        "state_writing_functions_reviewed": _metric(
            0,
            len(state_write_sources),
            AnalysisState.NOT_ANALYZED,
            "State-write graph source functions with validated substantive model reviews",
            population=len(state_write_sources),
            exclusions=[],
            not_applicable_evidence=(
                ["semantic graph contains no state-writing functions"]
                if not state_write_sources and graphs is not None
                else []
            ),
            confidence=_graph_source_confidence(graphs, state_write_sources),
            provenance=[
                CoverageProvenance.SEMANTIC_GRAPH,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=(
                [model_review_pending]
                if state_write_sources
                else (["Solidity semantic graph was not produced"] if graphs is None else [])
            ),
        ),
        "high_value_paths_reviewed": _metric(
            0,
            len(sensitive_sources),
            AnalysisState.NOT_ANALYZED,
            "Sensitive-reachability source functions with validated substantive model reviews",
            population=len(sensitive_sources),
            exclusions=[],
            not_applicable_evidence=(
                ["semantic graph contains no sensitive-reachability source functions"]
                if not sensitive_sources and graphs is not None
                else []
            ),
            confidence=_graph_source_confidence(graphs, sensitive_sources),
            provenance=[
                CoverageProvenance.SEMANTIC_GRAPH,
                CoverageProvenance.MODEL_REVIEW,
            ],
            failures=(
                [model_review_pending]
                if sensitive_sources
                else (["Solidity semantic graph was not produced"] if graphs is None else [])
            ),
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
    function_ids = {
        entity.id
        for entity in index.entities
        if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
    }
    reviewed_ids = {
        surface.subject_id
        for surface in review_coverage.surfaces
        if surface.reviewed and surface.subject_id in function_ids
    }
    metrics = dict(coverage.quality_metrics)
    for metric_name, source_ids in (
        (
            "public_external_entry_points_reviewed",
            {
                entity.id
                for entity in index.entities
                if entity.kind in {SolidityEntityKind.FUNCTION, SolidityEntityKind.CONSTRUCTOR}
                and entity.visibility in {"public", "external"}
            },
        ),
        (
            "privileged_entry_points_reviewed",
            _graph_source_ids(graphs, SolidityGraphKind.PRIVILEGE),
        ),
        (
            "state_writing_functions_reviewed",
            _graph_source_ids(graphs, SolidityGraphKind.STATE_WRITE),
        ),
        (
            "high_value_paths_reviewed",
            _graph_source_ids(graphs, SolidityGraphKind.SENSITIVE_REACHABILITY),
        ),
    ):
        existing = metrics[metric_name]
        reviewed_count = len(reviewed_ids & source_ids)
        metrics[metric_name] = _metric(
            reviewed_count,
            len(source_ids),
            (
                AnalysisState.MODEL_ONLY
                if review_coverage.applicable
                else AnalysisState.NOT_ANALYZED
            ),
            existing.detail,
            population=existing.population,
            exclusions=existing.exclusions,
            not_applicable_evidence=existing.not_applicable_evidence,
            confidence=existing.confidence,
            provenance=existing.provenance,
            failures=(
                _coverage_gap(
                    reviewed_count,
                    len(source_ids),
                    "eligible function(s) lack validated substantive model reviews",
                )
                if source_ids
                else existing.failures
            ),
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
