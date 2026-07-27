"""Auditable contract for the maximum-assurance profile.

The profile name is never treated as proof that a deep audit occurred.  This
module converts actual engine results into explicit, machine-readable clauses.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from mmaudit.agents.specialists import canonical_specialist_role
from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationOrigin,
    CertificateVerificationStatus,
)
from mmaudit.config import AuditConfig, model_family, model_lineage_index
from mmaudit.constants import ALL_SPECIALIST_ROLES, SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditScope,
    AuditScopeAssessment,
    CandidateReproductionResolution,
    CompilationStatus,
    EconomicSimulationPlan,
    ExecutionEvidenceKind,
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
    ReproductionIntegrityStatus,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    ScopeEvidenceStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.replay import (
    OfflineReplay,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
)
from mmaudit.solidity.economics import plan_economic_simulations
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

CERTIFIED_PROPERTY_ENGINES: frozenset[str] = frozenset({"echidna", "medusa", "halmos"})
CERTIFIED_FORMAL_PROOF_ENGINES: frozenset[str] = frozenset(
    {"certora", "kontrol", "solc-smtchecker"}
)
CERTIFIED_ISOLATION_BACKENDS: frozenset[str] = frozenset({"bubblewrap", "sandbox-exec"})


@dataclass(frozen=True)
class AssuranceRuntime:
    """Only deterministic execution facts used to evaluate the contract."""

    projects: list[SolidityProjectMetadata] = field(default_factory=list)
    compilations: list[SolidityCompilationResult] = field(default_factory=list)
    index: SoliditySymbolIndex | None = None
    graphs: SolidityGraphSet | None = None
    scanners: list[ScannerRun] = field(default_factory=list)
    invariants: InvariantSuite | None = None
    expected_invariant_harnesses: set[tuple[str, str, str]] = field(default_factory=set)
    invariant_executions: list[InvariantExecutionResult] = field(default_factory=list)
    economic_simulations: list[EconomicSimulationPlan] = field(default_factory=list)
    formal_runs: list[FormalToolRun] = field(default_factory=list)
    property_corpus_sha256: str | None = None
    property_corpus_property_ids: set[str] = field(default_factory=set)
    property_corpus_property_hashes: dict[str, str] = field(default_factory=dict)
    reproduction_results: list[ReproductionResult] = field(default_factory=list)
    reproduction_resolutions: list[CandidateReproductionResolution] = field(default_factory=list)
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
    model_usage: list[UsageRecord] = field(default_factory=list)
    scope_assessment: AuditScopeAssessment | None = None
    benchmark_verification: BenchmarkCertificateVerification | None = None
    benchmark_repository_git_commit: str | None = None
    offline_replay: OfflineReplay | None = None
    replay_run_id: str | None = None
    replay_manifest_sha256: str | None = None
    replay_verification_sha256: str | None = None
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
        expected_compilations = Counter(
            (project.project_root, project.project_type.value) for project in runtime.projects
        )
        observed_compilations = Counter(
            (result.project_root, result.framework.value) for result in runtime.compilations
        )
        compilation_attempted = any(
            result.status
            not in {
                CompilationStatus.SKIPPED,
                CompilationStatus.UNAVAILABLE,
            }
            for result in runtime.compilations
        )
        compilation_inventory_complete = bool(expected_compilations) and (
            observed_compilations == expected_compilations
        )
        compilation_succeeded = compilation_inventory_complete and all(
            result.status is CompilationStatus.SUCCESS
            and result.ast_available
            and bool(result.contracts_compiled)
            for result in runtime.compilations
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
        missing_compilations = list((expected_compilations - observed_compilations).elements())
        unexpected_compilations = list((observed_compilations - expected_compilations).elements())
        incomplete_compilations = [
            f"{result.project_root} ({result.framework.value}): {result.status.value}"
            + (
                "; compiler AST unavailable"
                if result.status is CompilationStatus.SUCCESS and not result.ast_available
                else ""
            )
            + (
                "; no compiled contracts"
                if result.status is CompilationStatus.SUCCESS and not result.contracts_compiled
                else ""
            )
            for result in runtime.compilations
            if result.status is not CompilationStatus.SUCCESS
            or not result.ast_available
            or not result.contracts_compiled
        ]
        indexed_projects = (
            Counter(
                (project.project_root, project.project_type.value)
                for project in runtime.index.projects
            )
            if runtime.index is not None
            else Counter()
        )
        ast_backed = (
            runtime.index is not None
            and indexed_projects == expected_compilations
            and bool(runtime.index.ast_sources)
            and not runtime.index.fallback_sources
        )
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
        real_scanners = [run for run in runtime.scanners if _is_real_scanner_run(run)]
        slither_records = [run for run in runtime.scanners if run.scanner == "slither"]
        real_slither = (
            slither_records[0]
            if (
                len(slither_records) == 1
                and _is_real_slither_run(slither_records[0])
                and _scanner_matches_trust_pin(
                    slither_records[0],
                    version=self.config.scanners.slither.version,
                    sha256=self.config.scanners.slither.sha256,
                )
            )
            else None
        )
        foundry_records = [run for run in runtime.scanners if run.scanner == "foundry_fork"]
        real_foundry_portfolio = (
            foundry_records[0]
            if (
                len(foundry_records) == 1
                and _is_real_foundry_portfolio(foundry_records[0])
                and _scanner_matches_trust_pin(
                    foundry_records[0],
                    version=self.config.scanners.foundry_fork.version,
                    sha256=self.config.scanners.foundry_fork.sha256,
                )
            )
            else None
        )
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
        real_invariant_executions = [
            result
            for result in runtime.invariant_executions
            if _is_real_invariant_execution(result, self.config)
        ]
        expected_harnesses = {
            (invariant_id, harness_name): harness_sha256
            for invariant_id, harness_name, harness_sha256 in runtime.expected_invariant_harnesses
        }
        observed_harness_counts = Counter(
            (result.invariant_id, result.harness_name) for result in runtime.invariant_executions
        )
        observed_harnesses = {
            (result.invariant_id, result.harness_name): result.harness_spec_sha256
            for result in runtime.invariant_executions
        }
        executable_invariant_ids = {
            invariant.id
            for invariant in (
                runtime.invariants.invariants if runtime.invariants is not None else []
            )
            if invariant.executable
        }
        invariant_inventory_bound = (
            bool(expected_harnesses)
            and all(count == 1 for count in observed_harness_counts.values())
            and set(observed_harnesses) == set(expected_harnesses)
            and observed_harnesses == expected_harnesses
            and executable_invariant_ids == {invariant_id for invariant_id, _ in expected_harnesses}
            and runtime.invariants is not None
            and runtime.invariants.executable_count == len(executable_invariant_ids)
        )
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
        expected_economic_plans = plan_economic_simulations(runtime.invariants, runtime.graphs)

        def economic_plan_identity(plan: EconomicSimulationPlan) -> tuple[object, ...]:
            return (
                plan.kind,
                plan.applicable,
                tuple(plan.invariant_ids),
                plan.typed_harness_available,
                plan.execution_required,
                plan.required_transaction_ordering,
            )

        economic_plan_inventory_bound = sorted(
            (economic_plan_identity(plan) for plan in runtime.economic_simulations),
            key=repr,
        ) == sorted(
            (economic_plan_identity(plan) for plan in expected_economic_plans),
            key=repr,
        )
        attempted_ids = {
            result.candidate_id for result in runtime.reproduction_results if result.attempts > 0
        }
        resolution_counts = Counter(
            resolution.candidate_id for resolution in runtime.reproduction_resolutions
        )
        duplicate_resolutions = {
            candidate_id for candidate_id, count in resolution_counts.items() if count != 1
        }
        bound_reproduction_refs: dict[str, set[str]] = {}
        for result in runtime.reproduction_results:
            if (
                result.state
                in {
                    ReproductionState.REPRODUCED,
                    ReproductionState.REPRODUCED_AND_MINIMIZED,
                }
                and result.attempts > 0
                and result.successful_attempts == result.attempts
                and result.integrity is not None
                and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
            ):
                bound_reproduction_refs.setdefault(result.candidate_id, set()).add(
                    f"reproduction:{result.integrity.integrity_sha256}"
                )
        qualifying_resolution_ids = {
            resolution.candidate_id
            for resolution in runtime.reproduction_resolutions
            if resolution.kind is ReproductionResolutionKind.REPRODUCED
            and bool(resolution.evidence_refs)
            and set(resolution.evidence_refs)
            <= bound_reproduction_refs.get(resolution.candidate_id, set())
            and resolution.candidate_id not in duplicate_resolutions
        }
        unbound_resolution_ids = {
            resolution.candidate_id
            for resolution in runtime.reproduction_resolutions
            if resolution.kind is ReproductionResolutionKind.REPRODUCED
            and resolution.candidate_id not in qualifying_resolution_ids
        }
        inconclusive_resolution_ids = {
            resolution.candidate_id
            for resolution in runtime.reproduction_resolutions
            if resolution.kind is ReproductionResolutionKind.INCONCLUSIVE
        }
        missing_reproduction = (
            (runtime.feasible_high_critical_ids - qualifying_resolution_ids)
            | (runtime.feasible_high_critical_ids & duplicate_resolutions)
            | (runtime.feasible_high_critical_ids & unbound_resolution_ids)
        )
        undocumented_impossible = (
            runtime.eligible_high_critical_ids
            - runtime.feasible_high_critical_ids
            - runtime.documented_infeasible_ids
        )
        formal_records_by_name: dict[str, list[FormalToolRun]] = {}
        for run in runtime.formal_runs:
            formal_records_by_name.setdefault(run.tool, []).append(run)
        real_property_engines = {
            tool: records[0]
            for tool, records in formal_records_by_name.items()
            if (
                len(records) == 1
                and _is_real_property_engine_run(records[0])
                and _formal_run_matches_config_pin(records[0], self.config)
                and _formal_run_matches_expected_corpus(records[0], runtime)
            )
        }
        real_formal_proofs = {
            tool: records[0]
            for tool, records in formal_records_by_name.items()
            if tool in CERTIFIED_FORMAL_PROOF_ENGINES
            and len(records) == 1
            and _is_real_formal_proof_run(records[0])
            and _formal_run_matches_config_pin(records[0], self.config)
            and _formal_run_matches_expected_corpus(records[0], runtime)
        }
        expected_replay_components = _expected_replay_components(runtime, expected_harnesses)
        expected_replay_kinds = {kind for kind, _identifier in expected_replay_components}
        offline_replay_qualified = offline_replay_is_qualifying(
            runtime.offline_replay,
            expected_run_id=runtime.replay_run_id,
            expected_manifest_sha256=runtime.replay_manifest_sha256,
            expected_verification_sha256=runtime.replay_verification_sha256,
            expected_applicable_kinds=expected_replay_kinds,
            expected_components=expected_replay_components,
        )
        real_model_records = [
            record for record in runtime.model_usage if _is_real_model_usage(record, self.config)
        ]
        real_model_roles = {record.role for record in real_model_records}
        model_coverage_backed_by_real_usage = _model_coverage_is_backed_by_real_usage(
            runtime.model_review_coverage,
            real_model_records,
            self.config,
        )
        if runtime.model_review_coverage is None:
            model_coverage_detail = "per-surface model review coverage was not produced"
        elif not model_coverage_backed_by_real_usage:
            model_coverage_detail = (
                "model surface credits are not backed by matching "
                "certification-grade real-provider usage"
            )
        else:
            model_coverage_detail = (
                f"{runtime.model_review_coverage.critical.numerator}/"
                f"{runtime.model_review_coverage.critical.denominator} critical "
                "surface(s) received independent certification-grade "
                "registered-lineage review"
            )
        real_falsifier_lineages = _real_model_usage_lineages(
            [record for record in real_model_records if _is_falsifier_usage_role(record.role)],
            self.config,
        )
        qualified_falsifier_lineages = (
            runtime.candidate_falsifier_lineages & real_falsifier_lineages
        )
        real_specialist_roles = {
            role
            for request_role in real_model_roles
            if (role := canonical_specialist_role(request_role)) is not None
        }
        benchmark_required = (
            self.requested
            or self.config.maximum_assurance.benchmark_gate
            or self.config.maximum_assurance.ci_mode
        )
        benchmark_qualified = (
            runtime.benchmark_verification is not None
            and runtime.benchmark_verification.status is CertificateVerificationStatus.CURRENT
            and runtime.benchmark_repository_git_commit is not None
            and runtime.benchmark_verification.observed_repository_git_commit
            == runtime.benchmark_repository_git_commit
            and runtime.benchmark_verification.origin is CertificateVerificationOrigin.FILE_BACKED
            and runtime.benchmark_verification.file_backed_evidence is not None
            and runtime.benchmark_verification.file_backed_evidence.benchmark_profile
            is AuditProfile.MAXIMUM_ASSURANCE
            and runtime.benchmark_verification.file_backed_evidence.benchmark_reports_loaded > 0
            and "benchmark-certificate-verification.json" in runtime.artifacts
        )
        base_roles = {
            "threat_model",
            "source_audit",
            "business_logic",
            "configuration",
        }
        completed_specialists = runtime.specialist_roles_completed & real_specialist_roles
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
                compilation_succeeded,
                (
                    "all detected projects compiled successfully with compiler AST output"
                    if compilation_succeeded
                    else _compilation_failure_detail(
                        missing=missing_compilations,
                        unexpected=unexpected_compilations,
                        incomplete=incomplete_compilations,
                        attempted=compilation_attempted,
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
                    else (
                        "compiler AST index is incomplete, project-mismatched, or includes "
                        "fallback-parsed sources"
                    )
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
                bool(real_scanners),
                (
                    f"{len(real_scanners)} real isolated deterministic scanner(s) completed"
                    if real_scanners
                    else "no scanner produced qualifying real isolated execution evidence"
                ),
                state=(
                    AnalysisState.SCANNER_SUPPORTED
                    if real_scanners
                    else AnalysisState.ATTEMPTED_FAILED
                ),
                artifacts=_present(runtime.artifacts, "scanner-results.json"),
            ),
            _requirement(
                "slither_execution",
                real_slither is not None,
                (
                    "one exact real isolated Slither execution completed"
                    if real_slither is not None
                    else (
                        f"{len(slither_records)} Slither record(s) exist but exact qualifying "
                        "real execution evidence is absent or ambiguous"
                    )
                ),
                state=(
                    AnalysisState.SCANNER_SUPPORTED
                    if real_slither is not None
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if slither_records
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "scanner-results.json"),
            ),
            _requirement(
                "foundry_unit_property_invariant_execution",
                real_foundry_portfolio is not None,
                (
                    "one exact real isolated Foundry suite observed non-empty conclusive unit, "
                    "property/fuzz, and invariant campaigns"
                    if real_foundry_portfolio is not None
                    else (
                        f"{len(foundry_records)} Foundry suite record(s) exist but exact "
                        "qualifying observed execution evidence is absent or ambiguous"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if real_foundry_portfolio is not None
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if foundry_records
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "scanner-results.json"),
            ),
            _requirement(
                "multi_agent_review",
                base_roles <= real_model_roles
                and len(completed_specialists)
                >= self.config.maximum_assurance.minimum_specialist_agents
                and not missing_investigators,
                (
                    f"{len(completed_specialists)} real-provider specialist role(s) completed; "
                    f"{self.config.maximum_assurance.minimum_specialist_agents} required; "
                    f"missing investigators={','.join(sorted(missing_investigators)) or 'none'}"
                ),
                state=(
                    AnalysisState.MODEL_ONLY if real_model_records else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "specialist-execution.json"),
            ),
            _requirement(
                "critical_model_surface_review",
                bool(real_model_records)
                and runtime.model_review_coverage is not None
                and runtime.model_review_coverage.applicable
                and runtime.model_review_coverage.critical_gate_passed
                and model_coverage_backed_by_real_usage,
                model_coverage_detail,
                state=(
                    AnalysisState.MODEL_ONLY
                    if real_model_records
                    and runtime.model_review_coverage is not None
                    and runtime.model_review_coverage.applicable
                    and model_coverage_backed_by_real_usage
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
                "invariant_review" in (runtime.auxiliary_roles_completed & real_specialist_roles),
                (
                    "dedicated real-provider non-finding invariant-review role completed"
                    if "invariant_review"
                    in (runtime.auxiliary_roles_completed & real_specialist_roles)
                    else "dedicated real-provider invariant-review role did not complete"
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if "invariant_review"
                    in (runtime.auxiliary_roles_completed & real_specialist_roles)
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "invariant-review.json"),
            ),
            _requirement(
                "stateful_invariant_execution",
                invariant_inventory_bound
                and bool(runtime.invariant_executions)
                and len(real_invariant_executions) == len(runtime.invariant_executions),
                (
                    (
                        f"{len(real_invariant_executions)}/{len(expected_harnesses)} "
                        "expected typed stateful invariant harness(es) completed with real "
                        "isolated, replayed campaign evidence"
                    )
                    if invariant_inventory_bound
                    else "stateful invariant results do not exactly match the sealed "
                    "executable harness inventory"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if invariant_inventory_bound
                    and runtime.invariant_executions
                    and len(real_invariant_executions) == len(runtime.invariant_executions)
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
                economic_plan_inventory_bound and not missing_economic,
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
                    else (
                        "no protocol-specific economic simulation was applicable"
                        if economic_plan_inventory_bound
                        else "economic simulation plan does not match deterministic applicability"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if economic_plan_inventory_bound and not missing_economic
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
                    f"{len(qualifying_resolution_ids & runtime.feasible_high_critical_ids)}/"
                    f"{len(runtime.feasible_high_critical_ids)} feasible high/critical "
                    "candidate(s) received qualifying terminal resolutions"
                    + (
                        f"; {len(missing_reproduction)} feasible candidate(s) remain unresolved"
                        if missing_reproduction
                        else ""
                    )
                    + (
                        f"; {len(inconclusive_resolution_ids & runtime.feasible_high_critical_ids)} "
                        "feasible candidate(s) are explicitly inconclusive"
                        if inconclusive_resolution_ids & runtime.feasible_high_critical_ids
                        else ""
                    )
                    + (
                        f"; {len(duplicate_resolutions)} candidate(s) have ambiguous resolutions"
                        if duplicate_resolutions
                        else ""
                    )
                    + (
                        f"; {len(unbound_resolution_ids)} reproduced resolution(s) are not "
                        "bound to qualifying raw runtime evidence"
                        if unbound_resolution_ids
                        else ""
                    )
                    + (
                        f"; {len(undocumented_impossible)} infeasible candidate(s) lacked a reason"
                        if undocumented_impossible
                        else ""
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if not runtime.feasible_high_critical_ids and not undocumented_impossible
                    else (
                        AnalysisState.REPRODUCED
                        if not missing_reproduction and not undocumented_impossible
                        else (
                            AnalysisState.ATTEMPTED_FAILED
                            if attempted_ids or runtime.reproduction_resolutions
                            else AnalysisState.NOT_ANALYZED
                        )
                    )
                ),
                artifacts=_present(runtime.artifacts, "reproduction-results.json"),
            ),
            _requirement(
                "independent_verifier",
                runtime.verifier_completed
                and ("verifier" in real_model_roles or not runtime.eligible_high_critical_ids),
                (
                    "independent real-provider verifier completed"
                    if (
                        runtime.verifier_completed
                        and (
                            "verifier" in real_model_roles or not runtime.eligible_high_critical_ids
                        )
                    )
                    else "independent real-provider verifier did not complete"
                ),
            ),
            _requirement(
                "independent_falsifier",
                (runtime.falsifier_completed and len(qualified_falsifier_lineages) >= 2)
                or not runtime.eligible_high_critical_ids,
                (
                    "two independent candidate-falsifier lineages completed"
                    if (runtime.falsifier_completed and len(qualified_falsifier_lineages) >= 2)
                    else (
                        "no eligible high/critical candidate required falsification"
                        if not runtime.eligible_high_critical_ids
                        else (
                            f"{len(qualified_falsifier_lineages)} independent "
                            "candidate-falsifier lineage(s) are backed by "
                            "certification-grade real-provider usage; 2 required"
                        )
                    )
                ),
                artifacts=_present(runtime.artifacts, "cross-examination.json"),
            ),
            _requirement(
                "independent_test_synthesis",
                (
                    {"test_generation", "exploit_reproduction_planner"}
                    <= (runtime.auxiliary_roles_completed & real_specialist_roles)
                    or not runtime.eligible_high_critical_ids
                ),
                (
                    "independent test-generation and exploit-planning roles completed"
                    if {
                        "test_generation",
                        "exploit_reproduction_planner",
                    }
                    <= (runtime.auxiliary_roles_completed & real_specialist_roles)
                    else (
                        "no eligible high/critical candidate required test synthesis"
                        if not runtime.eligible_high_critical_ids
                        else "one or more independent test-synthesis roles did not complete"
                    )
                ),
            ),
            _requirement(
                "evidence_capped_judge",
                runtime.judge_completed
                and ("judge" in real_model_roles or not runtime.eligible_high_critical_ids),
                (
                    "evidence-capped real-provider judge completed"
                    if (
                        runtime.judge_completed
                        and ("judge" in real_model_roles or not runtime.eligible_high_critical_ids)
                    )
                    else "evidence-capped real-provider judge did not complete"
                ),
            ),
            _requirement(
                "report_quality_review",
                "report_quality" in (runtime.auxiliary_roles_completed & real_specialist_roles),
                (
                    "independent real-provider report-quality review completed"
                    if "report_quality"
                    in (runtime.auxiliary_roles_completed & real_specialist_roles)
                    else "independent real-provider report-quality review did not complete"
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
                bool(real_property_engines or real_formal_proofs),
                (
                    f"{len(real_property_engines) + len(real_formal_proofs)} qualifying real "
                    "formal/property engine result(s) recorded"
                    if real_property_engines or real_formal_proofs
                    else "formal/property adapter layer produced no qualifying real execution"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if real_property_engines or real_formal_proofs
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.formal_runs
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "formal-results.json"),
            ),
            _requirement(
                "formal_proof_engine",
                bool(real_formal_proofs),
                (
                    "real isolated formal proof engine(s) completed: "
                    + ", ".join(sorted(real_formal_proofs))
                    if real_formal_proofs
                    else (
                        "no Certora, Kontrol, or Solidity SMTChecker record contained "
                        "qualifying real isolated execution evidence"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if real_formal_proofs
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.formal_runs
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_formal_artifacts(list(real_formal_proofs.values())),
            ),
            _requirement(
                "isolated_replay_execution",
                offline_replay_qualified,
                (
                    f"{len(runtime.offline_replay.components)} sealed scanner, saved-test, and "
                    "counterexample replay component(s) matched under real isolation"
                    if offline_replay_qualified and runtime.offline_replay is not None
                    else "no qualifying manifest-bound real offline replay was supplied"
                ),
                state=(
                    AnalysisState.REPRODUCED
                    if offline_replay_qualified
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.offline_replay is not None
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "offline-replay.json"),
            ),
            _requirement(
                "real_model_execution",
                bool(real_model_records),
                (
                    f"{len(real_model_records)} validated real-provider model request(s) completed"
                    if real_model_records
                    else "no validated real-provider model request completed"
                ),
                state=(
                    AnalysisState.MODEL_ONLY if real_model_records else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "specialist-execution.json"),
            ),
            _requirement(
                "certified_execution_isolation",
                real_slither is not None
                and real_foundry_portfolio is not None
                and set(real_property_engines) >= CERTIFIED_PROPERTY_ENGINES
                and bool(real_formal_proofs)
                and invariant_inventory_bound
                and len(real_invariant_executions) == len(expected_harnesses)
                and offline_replay_qualified,
                (
                    "every mandatory scanner, property, proof, invariant, and replay "
                    "portfolio member has real hardened-isolation evidence"
                    if (
                        real_slither is not None
                        and real_foundry_portfolio is not None
                        and set(real_property_engines) >= CERTIFIED_PROPERTY_ENGINES
                        and bool(real_formal_proofs)
                        and invariant_inventory_bound
                        and len(real_invariant_executions) == len(expected_harnesses)
                        and offline_replay_qualified
                    )
                    else "one or more mandatory portfolio members lacks real hardened-isolation "
                    "execution evidence"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if (
                        real_slither is not None
                        and real_foundry_portfolio is not None
                        and set(real_property_engines) >= CERTIFIED_PROPERTY_ENGINES
                        and bool(real_formal_proofs)
                        and invariant_inventory_bound
                        and len(real_invariant_executions) == len(expected_harnesses)
                        and offline_replay_qualified
                    )
                    else AnalysisState.ATTEMPTED_FAILED
                ),
            ),
            _requirement(
                "benchmark_regression_gate",
                benchmark_qualified,
                (
                    "file-backed benchmark certificate "
                    f"{runtime.benchmark_verification.certificate_sha256} is current"
                    if benchmark_qualified and runtime.benchmark_verification is not None
                    else (
                        "benchmark certificate is stale"
                        if runtime.benchmark_verification is not None
                        and runtime.benchmark_verification.status
                        is CertificateVerificationStatus.STALE
                        else (
                            "benchmark verification was not loaded from a sealed "
                            "maximum-assurance certificate and complete non-empty "
                            "passed-report files"
                            if runtime.benchmark_verification is not None
                            else "benchmark gate was not requested"
                        )
                    )
                ),
                required=benchmark_required,
                state=(
                    AnalysisState.DETERMINISTIC
                    if benchmark_qualified
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
        for tool in self.config.formal.required_tools:
            records = formal_records_by_name.get(tool, [])
            required_run = records[0] if len(records) == 1 else None
            qualifies = (
                required_run is not None
                and (
                    _is_real_property_engine_run(required_run)
                    if tool in CERTIFIED_PROPERTY_ENGINES
                    else (
                        _is_real_formal_proof_run(required_run)
                        if tool in CERTIFIED_FORMAL_PROOF_ENGINES
                        else _is_real_formal_run(required_run)
                    )
                )
                and _formal_run_matches_config_pin(required_run, self.config)
                and (
                    tool not in (CERTIFIED_PROPERTY_ENGINES | CERTIFIED_FORMAL_PROOF_ENGINES)
                    or _formal_run_matches_expected_corpus(required_run, runtime)
                )
            )
            clauses.append(
                _requirement(
                    f"required_formal_tool:{tool}",
                    qualifies,
                    (
                        f"{tool} completed with qualifying real isolated non-empty evidence"
                        if qualifies
                        else (
                            f"{tool} emitted {len(records)} ambiguous or non-qualifying "
                            "run record(s)"
                            if records
                            else f"{tool} did not produce a run record"
                        )
                    ),
                    state=(
                        AnalysisState.DETERMINISTIC
                        if qualifies
                        else (
                            AnalysisState.ATTEMPTED_FAILED
                            if records
                            else AnalysisState.NOT_ANALYZED
                        )
                    ),
                    artifacts=(
                        _formal_artifacts([required_run]) if required_run is not None else []
                    ),
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


def _is_sha256(value: str | None) -> bool:
    return (
        value is not None
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_integer(value: int | None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _positive_integer_at_least(value: int | None, minimum: int) -> bool:
    return _positive_integer(value) and value is not None and value >= minimum


def _formal_execution_observation_matches(run: FormalToolRun) -> bool:
    return (
        _is_sha256(run.execution_observation_sha256)
        and run.execution_observation_sha256 == run.expected_execution_observation_sha256()
    )


def _is_real_scanner_run(run: ScannerRun) -> bool:
    return (
        run.status is ScannerStatus.SUCCESS
        and run.execution_evidence is ExecutionEvidenceKind.REAL
        and bool(run.version)
        and _is_sha256(run.executable_sha256)
        and bool(run.command)
        and bool(run.raw_output_path)
        and _is_sha256(run.raw_output_sha256)
        and run.raw_output_bytes > 0
        and run.process_exit_code is not None
        and run.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
        and _is_sha256(run.isolation_attestation_sha256)
        and run.finished_at >= run.started_at
    )


def _scanner_execution_observation_matches(run: ScannerRun) -> bool:
    return (
        _is_sha256(run.execution_observation_sha256)
        and run.execution_observation_sha256 == run.expected_execution_observation_sha256()
    )


def _is_real_slither_run(run: ScannerRun) -> bool:
    return (
        run.scanner == "slither"
        and _is_real_scanner_run(run)
        and run.process_exit_code == 0
        and run.machine_output_validated
        and _scanner_execution_observation_matches(run)
    )


def _scanner_matches_trust_pin(
    run: ScannerRun,
    *,
    version: str | None,
    sha256: str | None,
) -> bool:
    return (
        version is not None
        and sha256 is not None
        and run.executable_sha256 == sha256
        and run.version is not None
        and re.search(
            rf"(?<![0-9.]){re.escape(version)}(?![0-9.])",
            run.version,
        )
        is not None
    )


def _formal_run_matches_config_pin(run: FormalToolRun, config: AuditConfig) -> bool:
    formal = config.formal
    pins: dict[str, tuple[str | None, str | None]] = {
        "echidna": (formal.echidna_version, formal.echidna_sha256),
        "medusa": (formal.medusa_version, formal.medusa_sha256),
        "halmos": (formal.halmos_version, formal.halmos_sha256),
        "kontrol": (formal.kontrol_version, formal.kontrol_sha256),
        "certora": (
            formal.certora.cli_version if formal.certora.enabled else None,
            formal.certora.cli_sha256 if formal.certora.enabled else None,
        ),
    }
    expected = pins.get(run.tool)
    if expected is None:
        return False
    version, sha256 = expected
    if (
        version is None
        or sha256 is None
        or run.executable_sha256 != sha256
        or run.version is None
        or re.search(
            rf"(?<![0-9.]){re.escape(version)}(?![0-9.])",
            run.version,
        )
        is None
    ):
        return False
    if run.tool != "halmos":
        return True
    return (
        formal.halmos_solver_version is not None
        and formal.halmos_solver_sha256 is not None
        and len(run.dependencies) == 1
        and run.dependencies[0].name == "z3"
        and run.dependencies[0].executable_sha256 == formal.halmos_solver_sha256
        and run.dependencies[0].version is not None
        and re.search(
            rf"(?<![0-9.]){re.escape(formal.halmos_solver_version)}(?![0-9.])",
            run.dependencies[0].version,
        )
        is not None
    )


def _is_real_foundry_portfolio(run: ScannerRun) -> bool:
    summary = run.foundry_summary
    if run.scanner != "foundry_fork" or not _is_real_scanner_run(run) or summary is None:
        return False
    observed_tests = summary.unit_tests + summary.fuzz_tests + summary.invariant_tests
    return (
        run.process_exit_code in {0, 1}
        and run.machine_output_validated
        and _scanner_execution_observation_matches(run)
        and summary.unit_tests > 0
        and summary.fuzz_tests > 0
        and summary.invariant_tests > 0
        and summary.passed_tests + summary.failed_tests == observed_tests
        and summary.skipped_tests == 0
        and summary.fuzz_cases > 0
        and summary.invariant_runs > 0
        and summary.invariant_calls > 0
    )


def _is_real_formal_run(run: FormalToolRun) -> bool:
    indexed_sources = run.coverage.get("indexed_sources")
    return (
        run.status is FormalToolStatus.SUCCESS
        and run.execution_evidence is ExecutionEvidenceKind.REAL
        and bool(run.version)
        and _is_sha256(run.executable_sha256)
        and bool(run.command)
        and run.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
        and _is_sha256(run.isolation_attestation_sha256)
        and bool(run.stdout_path)
        and bool(run.stderr_path)
        and (
            run.process_exit_code == 0
            or (
                run.tool in (CERTIFIED_PROPERTY_ENGINES | {"kontrol"})
                and run.process_exit_code == 1
            )
        )
        and _is_sha256(run.stdout_sha256)
        and _is_sha256(run.stderr_sha256)
        and (run.result_sha256 is None or _is_sha256(run.result_sha256))
        and run.stdout_bytes + run.stderr_bytes + run.result_bytes > 0
        and run.machine_output_validated
        and _formal_execution_observation_matches(run)
        and isinstance(indexed_sources, int)
        and not isinstance(indexed_sources, bool)
        and indexed_sources > 0
    )


def _is_real_property_engine_run(run: FormalToolRun) -> bool:
    configured_campaign = run.configured_campaign
    observed_campaign = run.observed_campaign
    conclusive_evidence = [
        evidence
        for evidence in run.evidence
        if (
            evidence.tool == run.tool
            and evidence.status is FormalToolStatus.SUCCESS
            and evidence.result_kind
            in {
                FormalResultKind.NONE,
                FormalResultKind.COUNTEREXAMPLE,
            }
        )
    ]
    conclusive_property_ids = {evidence.property_id for evidence in conclusive_evidence}
    return (
        run.tool in CERTIFIED_PROPERTY_ENGINES
        and _is_real_formal_run(run)
        and _is_sha256(run.property_corpus_hash)
        and run.translated_properties > 0
        and len(run.executed_property_ids) == run.translated_properties
        and run.observed_property_ids == run.executed_property_ids
        and conclusive_property_ids == set(run.executed_property_ids)
        and len(conclusive_evidence) == len(run.executed_property_ids)
        and len(run.evidence) == len(conclusive_evidence)
        and configured_campaign is not None
        and observed_campaign is not None
        and (
            (
                run.tool in {"echidna", "medusa"}
                and _positive_integer_at_least(
                    observed_campaign.runs,
                    configured_campaign.runs,
                )
                and _positive_integer_at_least(
                    observed_campaign.calls,
                    configured_campaign.runs,
                )
                and _positive_integer_at_least(
                    observed_campaign.depth,
                    configured_campaign.depth,
                )
            )
            or (
                run.tool == "halmos"
                and _positive_integer(observed_campaign.paths)
                and (
                    observed_campaign.depth is None
                    or _positive_integer_at_least(
                        observed_campaign.depth,
                        configured_campaign.depth,
                    )
                )
            )
        )
        and (
            run.tool != "halmos"
            or (
                len(run.dependencies) == 1
                and run.dependencies[0].name == "z3"
                and bool(run.dependencies[0].version)
                and _is_sha256(run.dependencies[0].executable_sha256)
            )
        )
    )


def _formal_run_matches_expected_corpus(
    run: FormalToolRun,
    runtime: AssuranceRuntime,
) -> bool:
    """Require every mandatory property engine to execute the same sealed corpus."""

    return (
        _is_sha256(runtime.property_corpus_sha256)
        and bool(runtime.property_corpus_property_ids)
        and run.property_corpus_hash == runtime.property_corpus_sha256
        and set(run.property_corpus_property_ids) == runtime.property_corpus_property_ids
        and set(run.executed_property_ids) == runtime.property_corpus_property_ids
        and set(run.observed_property_ids) == runtime.property_corpus_property_ids
        and run.translated_properties == len(runtime.property_corpus_property_ids)
        and {binding.corpus_property_id for binding in run.translated_property_bindings}
        == runtime.property_corpus_property_ids
        and runtime.property_corpus_property_hashes
        == {
            binding.corpus_property_id: binding.property_hash
            for binding in run.translated_property_bindings
        }
    )


def _is_real_formal_proof_run(run: FormalToolRun) -> bool:
    qualifying_results = [
        evidence
        for evidence in run.evidence
        if (
            evidence.tool == run.tool
            and evidence.status is FormalToolStatus.SUCCESS
            and evidence.result_kind in {FormalResultKind.PROOF, FormalResultKind.COUNTEREXAMPLE}
            and bool(evidence.property_id)
            and bool(evidence.artifact_paths)
        )
    ]
    return (
        run.tool in CERTIFIED_FORMAL_PROOF_ENGINES
        and _is_real_formal_run(run)
        and bool(qualifying_results)
        and run.translated_properties > 0
        and run.observed_property_ids == run.executed_property_ids
        and {result.property_id for result in qualifying_results} == set(run.executed_property_ids)
        and len(qualifying_results) == run.translated_properties
        and len(run.evidence) == len(qualifying_results)
        and (
            run.tool != "certora"
            or (bool(run.specification_artifacts) and bool(run.vacuity_artifacts))
        )
    )


def _is_real_invariant_execution(
    result: InvariantExecutionResult,
    config: AuditConfig,
) -> bool:
    completed = {
        InvariantExecutionStatus.PASSED,
        InvariantExecutionStatus.COUNTEREXAMPLE,
    }
    coverage = result.campaign_coverage
    return (
        result.status in completed
        and result.execution_evidence is ExecutionEvidenceKind.REAL
        and _is_sha256(result.executable_sha256)
        and result.executable_sha256 == config.scanners.foundry_fork.sha256
        and _is_sha256(result.source_sha256)
        and config.smart_contracts.solc_version is not None
        and config.smart_contracts.solc_sha256 is not None
        and result.compiler_version is not None
        and re.search(
            rf"(?<![0-9.]){re.escape(config.smart_contracts.solc_version)}(?![0-9.])",
            result.compiler_version,
        )
        is not None
        and _is_sha256(result.compiler_sha256)
        and result.compiler_sha256 == config.smart_contracts.solc_sha256
        and _is_sha256(result.isolation_attestation_sha256)
        and _is_sha256(result.execution_observation_sha256)
        and result.execution_observation_sha256 == result.expected_execution_observation_sha256()
        and bool(result.command)
        and result.runs > 0
        and result.depth > 0
        and result.attempts >= 2
        and result.successful_attempts == result.attempts
        and result.replay_confirmed
        and len(result.attempt_evidence) == result.attempts
        and all(
            attempt.fresh_workspace
            and attempt.status is result.status
            and attempt.source_sha256 == result.source_sha256
            and _is_sha256(attempt.stdout_sha256)
            and _is_sha256(attempt.stderr_sha256)
            and bool(attempt.stdout_path)
            and bool(attempt.stderr_path)
            and attempt.process_exit_code in {0, 1}
            and attempt.machine_output_validated
            and attempt.campaign_runs > 0
            and attempt.campaign_calls > 0
            for attempt in result.attempt_evidence
        )
        and coverage is not None
        and coverage.attempts_consistent
        and coverage.sequence_depth_bound == result.depth
        and coverage.observed_campaign_runs > 0
        and coverage.observed_campaign_calls > 0
        and bool(coverage.declared_action_functions)
        and bool(coverage.observed_action_functions)
        and set(coverage.observed_action_functions) == set(coverage.declared_action_functions)
        and bool(coverage.declared_state_properties)
        and bool(coverage.observed_state_properties)
        and set(coverage.observed_state_properties) == set(coverage.declared_state_properties)
        and (
            result.status is InvariantExecutionStatus.PASSED
            or bool(coverage.observed_sequence_lengths)
        )
        and bool(result.stdout_path)
        and bool(result.stderr_path)
        and result.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
    )


def offline_replay_is_qualifying(
    replay: OfflineReplay | None,
    *,
    expected_run_id: str | None,
    expected_manifest_sha256: str | None,
    expected_verification_sha256: str | None,
    expected_applicable_kinds: set[ReplayComponentKind],
    expected_components: set[tuple[ReplayComponentKind, str]],
) -> bool:
    if (
        replay is None
        or expected_run_id is None
        or expected_manifest_sha256 is None
        or expected_verification_sha256 is None
        or not expected_applicable_kinds
        or not expected_components
    ):
        return False
    observed_component_counts = Counter(
        (component.kind, component.identifier) for component in replay.components
    )
    observed_kinds = {
        component.kind
        for component in replay.components
        if (
            component.status is ReplayComponentStatus.MATCHED
            and component.executed
            and component.execution_evidence is ExecutionEvidenceKind.REAL
            and component.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
            and _is_sha256(component.isolation_attestation_sha256)
        )
    }
    return (
        replay.status is OfflineReplayStatus.REPLAYED
        and replay.run_id == expected_run_id
        and replay.manifest_sha256 == expected_manifest_sha256
        and replay.run_verification_sha256 == expected_verification_sha256
        and set(replay.applicable_kinds) == expected_applicable_kinds
        and set(observed_component_counts) == expected_components
        and all(count == 1 for count in observed_component_counts.values())
        and not replay.missing_kinds
        and bool(replay.components)
        and observed_kinds == set(replay.applicable_kinds)
        and all(
            component.status is ReplayComponentStatus.MATCHED
            and component.executed
            and component.execution_evidence is ExecutionEvidenceKind.REAL
            and component.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
            and _is_sha256(component.isolation_attestation_sha256)
            for component in replay.components
        )
    )


def _expected_replay_components(
    runtime: AssuranceRuntime,
    expected_harnesses: dict[tuple[str, str], str],
) -> set[tuple[ReplayComponentKind, str]]:
    """Derive exact replay member obligations from runtime evidence."""

    expected = {(ReplayComponentKind.SCANNER, run.scanner) for run in runtime.scanners}
    results = {
        (result.invariant_id, result.harness_name): result
        for result in runtime.invariant_executions
    }
    for identity in expected_harnesses:
        result = results.get(identity)
        kind = (
            ReplayComponentKind.COUNTEREXAMPLE
            if result is not None and result.status is InvariantExecutionStatus.COUNTEREXAMPLE
            else ReplayComponentKind.SAVED_TEST
        )
        expected.add((kind, f"{identity[0]}/{identity[1]}"))
    expected.update(
        (
            ReplayComponentKind.SAVED_TEST,
            f"{result.candidate_id}/{result.test_name}",
        )
        for result in runtime.reproduction_results
    )
    return expected


def _is_real_model_usage(record: UsageRecord, config: AuditConfig) -> bool:
    role = canonical_specialist_role(record.role) or (
        "falsifier" if record.role.startswith("candidate_falsifier:") else record.role
    )
    try:
        configured_role = config.models.role(role)
    except (KeyError, TypeError):
        return False
    configured_models = {configured_role.primary, *configured_role.fallbacks}
    if record.role.startswith("specialist:falsifier:cross_exam_"):
        for supporting_role in ("verifier", "judge"):
            role_config = config.models.role(supporting_role)
            configured_models.update({role_config.primary, *role_config.fallbacks})
    return (
        is_creditable_usage_record(
            record,
            require_real=True,
            require_certification=True,
        )
        and record.requested_model in configured_models
    )


def _is_falsifier_usage_role(role: str) -> bool:
    return (
        role == "falsifier"
        or role.startswith("candidate_falsifier:")
        or role == "specialist:falsifier"
        or role.startswith("specialist:falsifier:")
    )


def _real_model_usage_lineages(
    records: Iterable[UsageRecord],
    config: AuditConfig,
) -> set[str]:
    lineage_by_model = model_lineage_index(config)
    return {
        lineage.root_lineage
        for record in records
        if (lineage := lineage_by_model.get(record.requested_model.lower())) is not None
    }


def _model_coverage_is_backed_by_real_usage(
    coverage: ModelReviewCoverage | None,
    records: list[UsageRecord],
    config: AuditConfig,
) -> bool:
    if coverage is None:
        return False
    lineage_by_model = model_lineage_index(config)
    lineages_by_role: dict[str, set[str]] = {}
    for record in records:
        lineage = lineage_by_model.get(record.requested_model.lower())
        if lineage is None:
            continue
        lineages_by_role.setdefault(record.role, set()).add(lineage.root_lineage)
    for surface in coverage.surfaces:
        if not surface.reviewed:
            continue
        if any(role not in lineages_by_role for role in surface.reviewer_roles):
            return False
        available_lineages = {
            lineage for role in surface.reviewer_roles for lineage in lineages_by_role[role]
        }
        if not set(surface.root_lineages) <= available_lineages:
            return False
    return True


def _compilation_failure_detail(
    *,
    missing: list[tuple[str, str]],
    unexpected: list[tuple[str, str]],
    incomplete: list[str],
    attempted: bool,
) -> str:
    issues: list[str] = []
    if missing:
        issues.append(
            "missing project results: "
            + ", ".join(f"{root} ({framework})" for root, framework in sorted(missing))
        )
    if unexpected:
        issues.append(
            "unexpected project results: "
            + ", ".join(f"{root} ({framework})" for root, framework in sorted(unexpected))
        )
    if incomplete:
        issues.append("non-qualifying results: " + ", ".join(sorted(incomplete)))
    if issues:
        return "; ".join(issues)
    return (
        "compilation did not produce qualifying project evidence"
        if attempted
        else ("compilation was not attempted")
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
