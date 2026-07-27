"""Auditable contract for the maximum-assurance profile.

The profile name is never treated as proof that a deep audit occurred.  This
module converts actual engine results into explicit, machine-readable clauses.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationStatus,
)
from mmaudit.config import AuditConfig, model_family
from mmaudit.constants import ALL_SPECIALIST_ROLES, SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditScope,
    AuditScopeAssessment,
    CompilationStatus,
    EconomicSimulationPlan,
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantSuite,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    ModelReviewCoverage,
    ReproductionResult,
    ScannerRun,
    ScannerStatus,
    ScopeEvidenceStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
)
from mmaudit.traceability import (
    ImplementationStatus,
    MaximumAssuranceTraceability,
)

FULL_SEMANTIC_GRAPHS: frozenset[SolidityGraphKind] = frozenset(
    {
        SolidityGraphKind.INHERITANCE,
        SolidityGraphKind.MODIFIER,
        SolidityGraphKind.INTERNAL_CALL,
        SolidityGraphKind.EXTERNAL_CALL,
        SolidityGraphKind.LOW_LEVEL_CALL,
        SolidityGraphKind.DELEGATECALL,
        SolidityGraphKind.CONTRACT_CREATION,
        SolidityGraphKind.STATE_READ,
        SolidityGraphKind.STATE_WRITE,
        SolidityGraphKind.STATE_DEPENDENCY,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.PROXY,
        SolidityGraphKind.STORAGE_LAYOUT,
        SolidityGraphKind.UPGRADE_COMPATIBILITY,
        SolidityGraphKind.INITIALIZER,
        SolidityGraphKind.ORACLE_DEPENDENCY,
        SolidityGraphKind.EVENT_STATE,
        SolidityGraphKind.SIGNATURE_REPLAY,
        SolidityGraphKind.REENTRANCY,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    }
)


@dataclass(frozen=True)
class AssuranceRuntime:
    """Only deterministic execution facts used to evaluate the contract."""

    projects: list[SolidityProjectMetadata] = field(default_factory=list)
    compilations: list[SolidityCompilationResult] = field(default_factory=list)
    index: SoliditySymbolIndex | None = None
    graphs: SolidityGraphSet | None = None
    scanners: list[ScannerRun] = field(default_factory=list)
    invariants: InvariantSuite | None = None
    invariant_executions: list[InvariantExecutionResult] = field(default_factory=list)
    economic_simulations: list[EconomicSimulationPlan] = field(default_factory=list)
    formal_runs: list[FormalToolRun] = field(default_factory=list)
    reproduction_results: list[ReproductionResult] = field(default_factory=list)
    eligible_high_critical_ids: set[str] = field(default_factory=set)
    feasible_high_critical_ids: set[str] = field(default_factory=set)
    documented_infeasible_ids: set[str] = field(default_factory=set)
    model_roles_completed: set[str] = field(default_factory=set)
    specialist_roles_completed: set[str] = field(default_factory=set)
    auxiliary_roles_completed: set[str] = field(default_factory=set)
    verifier_completed: bool = False
    falsifier_completed: bool = False
    candidate_falsifier_lineages: set[str] = field(default_factory=set)
    judge_completed: bool = False
    coverage: SolidityCoverage | None = None
    model_review_coverage: ModelReviewCoverage | None = None
    scope_assessment: AuditScopeAssessment | None = None
    benchmark_verification: BenchmarkCertificateVerification | None = None
    isolation_available: bool = False
    scanner_only: bool = False
    artifacts: set[str] = field(default_factory=set)
    traceability: MaximumAssuranceTraceability | None = None


class MaximumAssuranceContract:
    """Evaluate whether the promised maximum-assurance engines actually ran."""

    version = "1.0"

    def __init__(
        self,
        config: AuditConfig,
        *,
        require: bool | None = None,
        allow_downgrade: bool | None = None,
    ) -> None:
        self.config = config
        self.requested = config.profile is AuditProfile.MAXIMUM_ASSURANCE
        self.required = config.maximum_assurance.require if require is None else require
        self.allow_downgrade = (
            config.maximum_assurance.allow_downgrade if allow_downgrade is None else allow_downgrade
        )

    def configuration_requirements(
        self,
        *,
        isolation_available: bool,
        scanner_only: bool,
    ) -> list[MaximumAssuranceRequirement]:
        """Return requirements that can be checked before model or target execution."""

        if not self.requested and not self.required:
            return []
        configured_roles = self._configured_specialist_roles()
        configured_families = self._configured_families()
        missing_roles = set(ALL_SPECIALIST_ROLES) - configured_roles
        return [
            _requirement(
                "maximum_assurance_profile",
                self.requested,
                (
                    "maximum-assurance profile selected"
                    if self.requested
                    else "--require-maximum-assurance requires --profile maximum-assurance"
                ),
                state=(
                    AnalysisState.DETERMINISTIC if self.requested else AnalysisState.NOT_ANALYZED
                ),
            ),
            _requirement(
                "full_pipeline_mode",
                not scanner_only,
                (
                    "full multi-agent pipeline requested"
                    if not scanner_only
                    else "scanner-only mode cannot satisfy maximum-assurance"
                ),
            ),
            _requirement(
                "model_family_diversity",
                len(configured_families) >= self.config.maximum_assurance.minimum_model_families,
                (
                    f"{len(configured_families)} distinct configured model families; "
                    f"{self.config.maximum_assurance.minimum_model_families} required"
                ),
            ),
            _requirement(
                "specialist_agent_configuration",
                len(configured_roles) >= self.config.maximum_assurance.minimum_specialist_agents,
                (
                    f"{len(configured_roles)} specialist roles configured; "
                    f"{self.config.maximum_assurance.minimum_specialist_agents} required"
                ),
            ),
            _requirement(
                "specialist_role_coverage",
                not missing_roles,
                (
                    "all required specialist responsibilities are configured"
                    if not missing_roles
                    else "missing specialist responsibilities: " + ", ".join(sorted(missing_roles))
                ),
            ),
            _requirement(
                "hardened_dynamic_isolation",
                isolation_available,
                (
                    "hardened disposable-workspace execution backend available"
                    if isolation_available
                    else "no supported hardened dynamic-execution backend is available"
                ),
            ),
        ]

    def evaluate(self, runtime: AssuranceRuntime) -> MaximumAssuranceAssessment:
        """Evaluate every contract clause from actual run evidence."""

        if not self.requested and not self.required:
            return MaximumAssuranceAssessment(
                requested=False,
                required=False,
                downgrade_allowed=self.allow_downgrade,
                downgraded=False,
                status=MaximumAssuranceStatus.NOT_REQUESTED,
            )

        requirements = self.configuration_requirements(
            isolation_available=runtime.isolation_available,
            scanner_only=runtime.scanner_only,
        )
        requirements.extend(self._traceability_requirements(runtime))
        requirements.extend(self._runtime_requirements(runtime))
        failed = [item for item in requirements if item.required and not item.passed]
        if not failed:
            status = MaximumAssuranceStatus.COMPLETE
            downgraded = False
        elif self.allow_downgrade:
            status = MaximumAssuranceStatus.DOWNGRADED
            downgraded = True
        elif any(item.state is AnalysisState.ATTEMPTED_FAILED for item in failed):
            status = MaximumAssuranceStatus.INCONCLUSIVE
            downgraded = False
        else:
            status = MaximumAssuranceStatus.FAILED
            downgraded = False
        return MaximumAssuranceAssessment(
            requested=self.requested,
            required=self.required,
            downgrade_allowed=self.allow_downgrade,
            downgraded=downgraded,
            status=status,
            requirements=requirements,
            downgrade_reasons=[item.detail for item in failed] if downgraded else [],
        )

    def _traceability_requirements(
        self,
        runtime: AssuranceRuntime,
    ) -> list[MaximumAssuranceRequirement]:
        matrix = runtime.traceability
        if matrix is None:
            return [
                _requirement(
                    "requirements_traceability",
                    False,
                    "maximum-assurance traceability matrix was not supplied to the contract",
                    artifacts=_present(
                        runtime.artifacts,
                        "maximum_assurance_traceability.json",
                    ),
                )
            ]
        requirements = [
            _requirement(
                "requirements_traceability",
                True,
                (
                    f"traceability schema {matrix.schema_version} evaluated at "
                    f"{matrix.last_verified_commit}"
                ),
                artifacts=_present(
                    runtime.artifacts,
                    "maximum_assurance_traceability.json",
                ),
            )
        ]
        for item in matrix.requirements:
            if not item.required_for_complete:
                continue
            implemented = item.implementation_status is ImplementationStatus.IMPLEMENTED
            requirements.append(
                _requirement(
                    f"traceability:{item.requirement_id.lower()}",
                    implemented,
                    (
                        f"{item.requirement_id} is implemented"
                        if implemented
                        else (
                            f"{item.requirement_id} is "
                            f"{item.implementation_status.value}: {item.downgrade_reason}"
                        )
                    ),
                    artifacts=[
                        artifact
                        for artifact in item.runtime_artifacts
                        if artifact in runtime.artifacts
                    ],
                )
            )
        return requirements

    def _runtime_requirements(
        self,
        runtime: AssuranceRuntime,
    ) -> list[MaximumAssuranceRequirement]:
        compilation_attempted = bool(runtime.compilations) and all(
            result.status is not CompilationStatus.SKIPPED for result in runtime.compilations
        )
        compilation_succeeded = compilation_attempted and all(
            result.status is CompilationStatus.SUCCESS for result in runtime.compilations
        )
        compilation_state = (
            AnalysisState.DETERMINISTIC
            if compilation_succeeded
            else (
                AnalysisState.ATTEMPTED_FAILED
                if compilation_attempted
                else AnalysisState.NOT_ANALYZED
            )
        )
        ast_backed = runtime.index is not None and bool(runtime.index.ast_sources)
        index_state = (
            AnalysisState.DETERMINISTIC
            if ast_backed
            else (
                AnalysisState.FALLBACK_PARSER
                if runtime.index is not None and runtime.index.fallback_sources
                else AnalysisState.NOT_ANALYZED
            )
        )
        analyzed_graphs = set(runtime.graphs.analyzed_graphs) if runtime.graphs else set()
        missing_graphs = sorted(graph.value for graph in FULL_SEMANTIC_GRAPHS - analyzed_graphs)
        deterministic_scanners = [
            run for run in runtime.scanners if run.status is ScannerStatus.SUCCESS
        ]
        required_scanner_failures = [
            run
            for run in runtime.scanners
            if run.scanner == "slither" and run.status is not ScannerStatus.SUCCESS
        ]
        invariant_count = (
            len(runtime.invariants.invariants) if runtime.invariants is not None else 0
        )
        invariant_attempts = [
            result
            for result in runtime.invariant_executions
            if result.status is not InvariantExecutionStatus.NOT_ATTEMPTED
        ]
        invariant_completed = [
            result
            for result in runtime.invariant_executions
            if result.status
            in {
                InvariantExecutionStatus.PASSED,
                InvariantExecutionStatus.COUNTEREXAMPLE,
            }
        ]
        planned_economic = {
            plan.kind
            for plan in runtime.economic_simulations
            if plan.applicable and plan.execution_required
        }
        typed_economic = {
            plan.kind
            for plan in runtime.economic_simulations
            if plan.applicable and plan.execution_required and plan.typed_harness_available
        }
        executed_economic = {
            result.economic_template
            for result in invariant_completed
            if result.economic_template is not None
        }
        missing_economic = planned_economic - executed_economic
        untyped_economic = planned_economic - typed_economic
        attempted_ids = {
            result.candidate_id for result in runtime.reproduction_results if result.attempts > 0
        }
        missing_reproduction = runtime.feasible_high_critical_ids - attempted_ids
        undocumented_impossible = (
            runtime.eligible_high_critical_ids
            - runtime.feasible_high_critical_ids
            - runtime.documented_infeasible_ids
        )
        formal_success = any(run.status is FormalToolStatus.SUCCESS for run in runtime.formal_runs)
        formal_counterexamples = any(
            evidence.result_kind is FormalResultKind.COUNTEREXAMPLE
            for run in runtime.formal_runs
            for evidence in run.evidence
        )
        benchmark_required = (
            self.config.maximum_assurance.benchmark_gate or self.config.maximum_assurance.ci_mode
        )
        base_roles = {
            "threat_model",
            "source_audit",
            "business_logic",
            "configuration",
        }
        completed_specialists = runtime.specialist_roles_completed
        missing_investigators = set(SPECIALIST_INVESTIGATOR_ROLES) - completed_specialists
        clauses = [
            _requirement(
                "full_protocol_scope",
                runtime.scope_assessment is not None
                and runtime.scope_assessment.requested is AuditScope.FULL_PROTOCOL
                and runtime.scope_assessment.complete,
                (
                    f"requested={runtime.scope_assessment.requested.value}; "
                    f"achieved="
                    f"{runtime.scope_assessment.achieved.value if runtime.scope_assessment.achieved else 'none'}"
                    if runtime.scope_assessment is not None
                    else "audit-scope assessment was not produced"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if runtime.scope_assessment is not None and runtime.scope_assessment.complete
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.scope_assessment is not None
                        and any(
                            item.required and item.status is ScopeEvidenceStatus.OMITTED
                            for item in runtime.scope_assessment.components
                        )
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "scope-assessment.json"),
            ),
            _requirement(
                "solidity_project_detection",
                bool(runtime.projects),
                (
                    f"{len(runtime.projects)} Solidity project(s) detected"
                    if runtime.projects
                    else "no Solidity project was detected"
                ),
                artifacts=_present(runtime.artifacts, "solidity-projects.json"),
            ),
            _requirement(
                "compilation",
                compilation_attempted,
                (
                    "all detected projects compiled successfully"
                    if compilation_succeeded
                    else (
                        "compilation was attempted and failure coverage was recorded"
                        if compilation_attempted
                        else "compilation was not attempted"
                    )
                ),
                state=compilation_state,
                artifacts=_present(runtime.artifacts, "solidity-compilation.json"),
            ),
            _requirement(
                "ast_backed_index",
                ast_backed,
                (
                    f"{len(runtime.index.ast_sources)} source file(s) indexed from compiler AST"
                    if ast_backed and runtime.index
                    else "compiler AST unavailable; fallback parsing is not maximum assurance"
                ),
                state=index_state,
                artifacts=_present(runtime.artifacts, "solidity-index.json"),
            ),
            _requirement(
                "full_semantic_graphs",
                not missing_graphs,
                (
                    "all required semantic graph transformations completed"
                    if not missing_graphs
                    else "missing graph transformations: " + ", ".join(missing_graphs)
                ),
                artifacts=_present(runtime.artifacts, "solidity-graphs.json"),
            ),
            _requirement(
                "deterministic_scanners",
                bool(deterministic_scanners) and not required_scanner_failures,
                (
                    f"{len(deterministic_scanners)} deterministic scanner(s) completed"
                    if deterministic_scanners and not required_scanner_failures
                    else "required deterministic scanner unavailable, failed, or timed out"
                ),
                state=(
                    AnalysisState.SCANNER_SUPPORTED
                    if deterministic_scanners and not required_scanner_failures
                    else AnalysisState.ATTEMPTED_FAILED
                ),
                artifacts=_present(runtime.artifacts, "scanner-results.json"),
            ),
            _requirement(
                "multi_agent_review",
                base_roles <= runtime.model_roles_completed
                and len(runtime.specialist_roles_completed)
                >= self.config.maximum_assurance.minimum_specialist_agents
                and not missing_investigators,
                (
                    f"{len(runtime.specialist_roles_completed)} specialist role(s) completed; "
                    f"{self.config.maximum_assurance.minimum_specialist_agents} required; "
                    f"missing investigators={','.join(sorted(missing_investigators)) or 'none'}"
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if runtime.model_roles_completed
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "specialist-execution.json"),
            ),
            _requirement(
                "critical_model_surface_review",
                runtime.model_review_coverage is not None
                and runtime.model_review_coverage.applicable
                and runtime.model_review_coverage.critical_gate_passed,
                (
                    f"{runtime.model_review_coverage.critical.numerator}/"
                    f"{runtime.model_review_coverage.critical.denominator} critical "
                    "surface(s) received independent registered-lineage review"
                    if runtime.model_review_coverage is not None
                    else "per-surface model review coverage was not produced"
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if runtime.model_review_coverage is not None
                    and runtime.model_review_coverage.applicable
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "model-review-coverage.json"),
            ),
            _requirement(
                "invariant_discovery",
                runtime.invariants is not None and invariant_count > 0,
                f"{invariant_count} source-linked invariant(s) discovered",
                artifacts=_present(runtime.artifacts, "solidity-invariants.json"),
            ),
            _requirement(
                "independent_invariant_review",
                "invariant_review" in runtime.auxiliary_roles_completed,
                (
                    "dedicated non-finding invariant-review role completed"
                    if "invariant_review" in runtime.auxiliary_roles_completed
                    else "dedicated invariant-review role did not complete"
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if "invariant_review" in runtime.auxiliary_roles_completed
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "invariant-review.json"),
            ),
            _requirement(
                "stateful_invariant_execution",
                bool(invariant_completed),
                (
                    f"{len(invariant_completed)}/{len(runtime.invariant_executions)} "
                    "typed stateful invariant harness(es) completed"
                    if runtime.invariant_executions
                    else "no validated typed stateful invariant harness was configured"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if invariant_completed
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if invariant_attempts
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "invariant-execution-results.json"),
            ),
            _requirement(
                "protocol_economic_simulation",
                not missing_economic,
                (
                    f"{len(executed_economic & planned_economic)}/"
                    f"{len(planned_economic)} applicable economic template(s) executed"
                    + (
                        f"; {len(untyped_economic)} selected template(s) lack deterministic "
                        "typed harness support"
                        if untyped_economic
                        else ""
                    )
                    if planned_economic
                    else "no protocol-specific economic simulation was applicable"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if not missing_economic
                    else (
                        AnalysisState.NOT_ANALYZED
                        if untyped_economic
                        else (
                            AnalysisState.ATTEMPTED_FAILED
                            if executed_economic
                            else AnalysisState.NOT_ANALYZED
                        )
                    )
                ),
                artifacts=_present(runtime.artifacts, "economic-simulation-plan.json"),
            ),
            _requirement(
                "critical_high_reproduction",
                not missing_reproduction and not undocumented_impossible,
                (
                    f"{len(attempted_ids & runtime.feasible_high_critical_ids)}/"
                    f"{len(runtime.feasible_high_critical_ids)} feasible high/critical "
                    "candidate(s) received an executable attempt; "
                    f"{len(undocumented_impossible)} impossible candidate(s) lacked a reason"
                ),
                artifacts=_present(runtime.artifacts, "reproduction-results.json"),
            ),
            _requirement(
                "independent_verifier",
                runtime.verifier_completed,
                (
                    "independent verifier completed"
                    if runtime.verifier_completed
                    else "independent verifier did not complete"
                ),
            ),
            _requirement(
                "independent_falsifier",
                (runtime.falsifier_completed and len(runtime.candidate_falsifier_lineages) >= 2)
                or not runtime.eligible_high_critical_ids,
                (
                    "two independent candidate-falsifier lineages completed"
                    if (
                        runtime.falsifier_completed
                        and len(runtime.candidate_falsifier_lineages) >= 2
                    )
                    else (
                        "no eligible high/critical candidate required falsification"
                        if not runtime.eligible_high_critical_ids
                        else (
                            f"{len(runtime.candidate_falsifier_lineages)} independent "
                            "candidate-falsifier lineage(s) completed; 2 required"
                        )
                    )
                ),
                artifacts=_present(runtime.artifacts, "cross-examination.json"),
            ),
            _requirement(
                "independent_test_synthesis",
                (
                    {"test_generation", "exploit_reproduction_planner"}
                    <= runtime.auxiliary_roles_completed
                    or not runtime.eligible_high_critical_ids
                ),
                (
                    "independent test-generation and exploit-planning roles completed"
                    if {
                        "test_generation",
                        "exploit_reproduction_planner",
                    }
                    <= runtime.auxiliary_roles_completed
                    else (
                        "no eligible high/critical candidate required test synthesis"
                        if not runtime.eligible_high_critical_ids
                        else "one or more independent test-synthesis roles did not complete"
                    )
                ),
            ),
            _requirement(
                "evidence_capped_judge",
                runtime.judge_completed,
                (
                    "evidence-capped judge completed"
                    if runtime.judge_completed
                    else "evidence-capped judge did not complete"
                ),
            ),
            _requirement(
                "report_quality_review",
                "report_quality" in runtime.auxiliary_roles_completed,
                (
                    "independent report-quality review completed"
                    if "report_quality" in runtime.auxiliary_roles_completed
                    else "independent report-quality review did not complete"
                ),
            ),
            _requirement(
                "coverage_report",
                runtime.coverage is not None,
                (
                    "coverage artifact generated"
                    if runtime.coverage is not None
                    else "coverage artifact missing"
                ),
                artifacts=_present(runtime.artifacts, "solidity-coverage.json"),
            ),
            _requirement(
                "formal_adapter_inventory",
                bool(runtime.formal_runs),
                (
                    f"{len(runtime.formal_runs)} formal/property adapter result(s) recorded"
                    if runtime.formal_runs
                    else "formal/property adapter layer did not record tool availability"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if runtime.formal_runs
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "formal-results.json"),
            ),
            _requirement(
                "formal_or_symbolic_engine",
                formal_success,
                (
                    f"{sum(run.status is FormalToolStatus.SUCCESS for run in runtime.formal_runs)} "
                    f"formal/property engine(s) completed; counterexample={formal_counterexamples}"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if formal_success
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.formal_runs
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                required=False,
                artifacts=_formal_artifacts(runtime.formal_runs),
            ),
            _requirement(
                "benchmark_regression_gate",
                runtime.benchmark_verification is not None
                and runtime.benchmark_verification.status is CertificateVerificationStatus.CURRENT,
                (
                    "benchmark certificate "
                    f"{runtime.benchmark_verification.certificate_sha256} is current"
                    if runtime.benchmark_verification is not None
                    and runtime.benchmark_verification.status
                    is CertificateVerificationStatus.CURRENT
                    else (
                        "benchmark certificate is stale"
                        if runtime.benchmark_verification is not None
                        else "benchmark gate was not requested"
                    )
                ),
                required=benchmark_required,
                state=(
                    AnalysisState.DETERMINISTIC
                    if runtime.benchmark_verification is not None
                    and runtime.benchmark_verification.status
                    is CertificateVerificationStatus.CURRENT
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.benchmark_verification is not None
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(
                    runtime.artifacts,
                    "benchmark-certificate-verification.json",
                ),
            ),
        ]
        formal_by_name = {run.tool: run for run in runtime.formal_runs}
        for tool in self.config.formal.required_tools:
            run = formal_by_name.get(tool)
            clauses.append(
                _requirement(
                    f"required_formal_tool:{tool}",
                    run is not None and run.status is FormalToolStatus.SUCCESS,
                    (
                        f"{tool} completed successfully"
                        if run is not None and run.status is FormalToolStatus.SUCCESS
                        else (
                            f"{tool} status={run.status.value}"
                            if run is not None
                            else f"{tool} did not produce a run record"
                        )
                    ),
                    state=(
                        AnalysisState.DETERMINISTIC
                        if run is not None and run.status is FormalToolStatus.SUCCESS
                        else (
                            AnalysisState.ATTEMPTED_FAILED
                            if run is not None
                            else AnalysisState.NOT_ANALYZED
                        )
                    ),
                    artifacts=_formal_artifacts([run]) if run is not None else [],
                )
            )
        return clauses

    def _configured_families(self) -> set[str]:
        values: Iterable[str]
        specialists = getattr(self.config.models, "specialists", {})
        values = [
            self.config.models.role(role).primary
            for role in (
                "threat_model",
                "source_audit",
                "business_logic",
                "configuration",
                "verifier",
                "judge",
            )
        ]
        if isinstance(specialists, dict):
            values = [*values, *(slot.primary for slot in specialists.values())]
        return {model_family(identifier) for identifier in values}

    def _configured_specialist_roles(self) -> set[str]:
        specialists = getattr(self.config.models, "specialists", {})
        return set(specialists) if isinstance(specialists, dict) else set()


def _requirement(
    engine: str,
    passed: bool,
    detail: str,
    *,
    required: bool = True,
    state: AnalysisState | None = None,
    artifacts: list[str] | None = None,
) -> MaximumAssuranceRequirement:
    return MaximumAssuranceRequirement(
        engine=engine,
        required=required,
        passed=passed,
        blocking=required and not passed,
        state=state or (AnalysisState.DETERMINISTIC if passed else AnalysisState.NOT_ANALYZED),
        detail=detail,
        artifacts=artifacts or [],
    )


def _present(artifacts: set[str], filename: str) -> list[str]:
    return [filename] if filename in artifacts else []


def _formal_artifacts(runs: list[FormalToolRun]) -> list[str]:
    return sorted(
        {
            artifact
            for run in runs
            for evidence in run.evidence
            for artifact in evidence.artifact_paths
        }
    )
