"""Same-process orchestration for authenticated cross-lineage runner custody.

This module owns no credential and performs no transport itself.  Callers inject
the four bounded async transport boundaries while this layer retains the opaque
campaign, generation, lineage, ledger, and runner capabilities in one process.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from decimal import Decimal, localcontext
from enum import StrEnum
from itertools import islice
from pathlib import Path
from typing import Literal, Never, Protocol, SupportsIndex

from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationCaseResult,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
    adjudication_generation_verification_requests,
    build_cross_lineage_adjudication_report,
    cross_lineage_adjudication_request_cost_previews,
    prepare_cross_lineage_adjudication,
)
from mmaudit.benchmark.model_portfolio import (
    CandidateBenchmarkCampaignJournal,
    ModelBenchmarkPortfolio,
    TrustedCandidateBenchmarkCampaignVerification,
    create_candidate_benchmark_campaign,
    issue_trusted_candidate_benchmark_campaign_verification,
    seal_model_benchmark_portfolio_from_campaign,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    authenticated_runner_model_benchmark_request_descriptors,
)
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerEvidence,
    ClosedCrossLineageLedgerInterval,
    CrossLineageRunnerRunCustody,
    VerifiedCrossLineageRunnerCustody,
    VerifiedCrossLineageRunnerProjection,
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
    issue_verified_cross_lineage_runner_custody,
    require_verified_cross_lineage_runner_custody,
)
from mmaudit.models.authenticated_runner_cost_plan import (
    AuthenticatedRunnerCostPlanStage,
    AuthenticatedRunnerStagedCostPlan,
    build_authenticated_runner_staged_cost_plan,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkExecutionResult,
    CandidateBenchmarkRunState,
    validate_candidate_benchmark_egress,
    validate_candidate_benchmark_policy_capacity,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.endpoint_snapshots import EndpointSnapshotValidationError
from mmaudit.models.generation_evidence import (
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
)
from mmaudit.models.ground_truth_authority import (
    FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
    FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
    FROZEN_GROUND_TRUTH_SOURCE_REVISION,
    VerifiedFrozenGroundTruth,
    VerifiedFrozenGroundTruthProjection,
)
from mmaudit.models.openrouter import (
    OpenRouterProviderPolicy,
    preview_openrouter_structured_request_cost,
)
from mmaudit.models.public_lineage_authority import (
    VerifiedIndependentPublicModelLineageProjection,
    VerifiedPublicModelLineage,
    require_independent_public_model_lineage,
)
from mmaudit.models.qualification import (
    CandidateModel,
    CandidateRegistry,
    QualificationPolicy,
    validate_candidate_registry_discovery,
)
from mmaudit.models.qualification_workflow import (
    candidate_generation_verification_requests,
)
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.models.usage import UsageLedger, is_creditable_usage_record
from mmaudit.orchestration.budgets import (
    BudgetManager,
    _issue_trusted_budget_recovery_scope,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostLedgerSnapshot,
)
from mmaudit.orchestration.scheduler_runtime import build_scheduler_cost_ledger_baseline
from mmaudit.privacy import PrivacyProfile

_RUN_COUNT = 2
_FROZEN_CASE_COUNT = 24
_LOGICAL_REQUEST_COUNT = _RUN_COUNT * _FROZEN_CASE_COUNT * 2
_LEDGER_CAP_USD = Decimal("250")
_MAX_DISCOVERY_EVIDENCE = 128
_PATH_TYPE = type(Path("/"))


class AuthenticatedRunnerExecutionError(ValueError):
    """The prospective or completed same-process runner execution is invalid."""


class AuthenticatedRunnerGenerationSubject(StrEnum):
    """Closed subject identity for an injected metadata re-fetch."""

    CANDIDATE = "CANDIDATE"
    JUDGE = "JUDGE"


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerRunPlan:
    """One fresh candidate campaign followed by one exact independent judge pass."""

    run_kind: CrossLineageAdjudicationRunKind
    campaign_path: Path
    portfolio_path: Path
    judge_discovery_manifest: OpenRouterModelDiscoveryRunManifest
    judge_discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...]
    judge_registry: CandidateRegistry
    candidate_declared_cost_cap_usd_per_attempt: Decimal
    judge_declared_cost_cap_usd_per_attempt: Decimal

    @property
    def judge(self) -> CandidateModel:
        """Return the sole judge only after plan preflight validates its discovery join."""

        if len(self.judge_registry.candidates) != 1:
            raise AuthenticatedRunnerExecutionError(
                "runner plan lacks one exact discovery-derived judge"
            )
        return self.judge_registry.candidates[0]


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerExecutionInventory:
    """Pre-dispatch inventory; declared costs grant no budget or execution authority."""

    run_count: int
    case_count: int
    candidate_logical_request_count: int
    judge_logical_request_count: int
    logical_request_count: int
    maximum_attempts_per_logical_request: int
    maximum_provider_attempt_count: int
    generation_refetch_count: int
    effective_config_sha256: str
    initial_spent_usd: Decimal
    declared_interval_cost_cap_usd: Decimal
    declared_final_spent_cap_usd: Decimal
    candidate_stage_plan_sha256s: tuple[str, ...] = ()
    candidate_derived_interval_cost_cap_usd: Decimal = Decimal("0")
    candidate_derived_final_spent_cap_usd: Decimal = Decimal("0")
    judge_cost_admission_status: Literal["PENDING_REAL_CANDIDATE_OUTPUTS"] = (
        "PENDING_REAL_CANDIDATE_OUTPUTS"
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerExecutedRun:
    """Retained prepared request and every live/durable input for one runner pass."""

    candidate_cost_plan: AuthenticatedRunnerStagedCostPlan
    judge_cost_plan: AuthenticatedRunnerStagedCostPlan
    prepared_adjudication: CrossLineageAdjudicationPreparedRun
    custody: CrossLineageRunnerRunCustody


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerExecutionResult:
    """Retained PID-local runner authority plus exact reports needed by AUTHSEAL."""

    inventory: AuthenticatedRunnerExecutionInventory
    runs: tuple[AuthenticatedRunnerExecutedRun, ...]
    closed_ledger_interval: ClosedCrossLineageLedgerInterval
    runner_capability: VerifiedCrossLineageRunnerCustody
    runner_evidence: AuthenticatedCrossLineageRunnerEvidence
    runner_projection: VerifiedCrossLineageRunnerProjection

    def __reduce__(self) -> Never:
        raise TypeError("authenticated runner execution result cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("authenticated runner execution result cannot be serialized")


class CandidateCampaignExecutor(Protocol):
    """Credential-owning injected boundary for one already-created campaign journal."""

    async def __call__(
        self,
        *,
        run_kind: CrossLineageAdjudicationRunKind,
        config: AuditConfig,
        discovery_manifest: OpenRouterModelDiscoveryRunManifest,
        discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
        candidate_registry: CandidateRegistry,
        benchmark_suite: ModelBenchmarkSuite,
        budget: BudgetManager,
        usage: UsageLedger,
        evidence_sink: CandidateBenchmarkCampaignJournal,
        qualification_policy: QualificationPolicy,
        request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    ) -> CandidateBenchmarkExecutionResult: ...


class CrossLineageJudgeExecutor(Protocol):
    """Credential-owning injected boundary for one exact prepared judge request set."""

    async def __call__(
        self,
        *,
        config: AuditConfig,
        prepared: CrossLineageAdjudicationPreparedRun,
        judge: CandidateModel,
        budget: BudgetManager,
        usage: UsageLedger,
        request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    ) -> tuple[CrossLineageAdjudicationCaseResult, ...]: ...


class JudgeRoutePreparationExecutor(Protocol):
    """Credential-owning metadata refresh for both judges before either paid POST."""

    async def __call__(
        self,
        *,
        config: AuditConfig,
        prepared_runs: tuple[CrossLineageAdjudicationPreparedRun, ...],
        judges: tuple[CandidateModel, ...],
    ) -> object: ...


class RunnerGenerationVerificationExecutor(Protocol):
    """Injected authenticated metadata re-fetch that must return opaque live custody."""

    async def __call__(
        self,
        *,
        run_kind: CrossLineageAdjudicationRunKind,
        subject: AuthenticatedRunnerGenerationSubject,
        requests: tuple[GenerationVerificationRequest, ...],
    ) -> TrustedGenerationVerification: ...


@dataclass(frozen=True, slots=True)
class _PreparedCandidateRun:
    """One fully verified candidate pass retained until aggregate judge admission."""

    plan: AuthenticatedRunnerRunPlan
    candidate_cost_plan: AuthenticatedRunnerStagedCostPlan
    candidate_report: ModelBenchmarkReport
    candidate_usage: tuple[UsageRecord, ...]
    candidate_campaign_reports: tuple[ModelBenchmarkReport, ...]
    candidate_portfolio: ModelBenchmarkPortfolio
    candidate_campaign_verification: TrustedCandidateBenchmarkCampaignVerification
    candidate_generation_verification: TrustedGenerationVerification
    prepared_adjudication: CrossLineageAdjudicationPreparedRun


def _candidate_staged_cost_plan(
    *,
    config: AuditConfig,
    benchmark_suite: ModelBenchmarkSuite,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: OpenRouterModelDiscoveryEvidence,
    candidate: CandidateModel,
    run_kind: CrossLineageAdjudicationRunKind,
) -> AuthenticatedRunnerStagedCostPlan:
    """Build one exact provider-free candidate plan from frozen launch evidence."""

    run_kind_text: Literal["PRIMARY", "REPLAY"] = (
        "PRIMARY" if run_kind is CrossLineageAdjudicationRunKind.PRIMARY else "REPLAY"
    )
    target = ModelBenchmarkTarget(
        model_id=candidate.exact_model_id,
        root_lineage=candidate.root_lineage,
    )
    descriptors = authenticated_runner_model_benchmark_request_descriptors(
        run_kind=run_kind_text,
        suite=benchmark_suite,
        target=target,
    )
    provider_policy = OpenRouterProviderPolicy(
        certification=True,
        only=(candidate.approved_provider_endpoint,),
        allow_fallbacks=False,
    )
    reasoning_policy = build_reasoning_policy(config)
    previews = tuple(
        preview_openrouter_structured_request_cost(
            execution=config.execution,
            privacy=config.privacy,
            token_budgets=config.token_budgets,
            provider_policy=provider_policy,
            reasoning_policy=reasoning_policy,
            discovery_manifest=discovery_manifest,
            discovery_evidence=discovery_evidence,
            role=descriptor.request_role,
            system_prompt=descriptor.system_prompt,
            user_prompt=descriptor.user_prompt,
            response_model=descriptor.response_model,
            schema_name=descriptor.schema_name,
            logical_request_id=descriptor.logical_request_id,
            context_package=None,
            maximum_attempts=config.execution.max_model_retries + 1,
        )
        for descriptor in descriptors
    )
    return build_authenticated_runner_staged_cost_plan(
        run_kind=run_kind,
        stage=AuthenticatedRunnerCostPlanStage.CANDIDATE,
        case_ids=(descriptor.case_id for descriptor in descriptors),
        request_previews=previews,
    )


def _judge_staged_cost_plan(
    *,
    config: AuditConfig,
    prepared: CrossLineageAdjudicationPreparedRun,
    plan: AuthenticatedRunnerRunPlan,
) -> AuthenticatedRunnerStagedCostPlan:
    """Build one exact provider-free judge plan after candidate evidence exists."""

    previews = cross_lineage_adjudication_request_cost_previews(
        config=config,
        prepared=prepared,
        discovery_manifest=plan.judge_discovery_manifest,
        discovery_evidence=plan.judge_discovery_evidence[0],
        maximum_attempts=config.execution.max_model_retries + 1,
    )
    return build_authenticated_runner_staged_cost_plan(
        run_kind=plan.run_kind,
        stage=AuthenticatedRunnerCostPlanStage.JUDGE,
        case_ids=prepared.case_ids,
        request_previews=previews,
    )


async def execute_authenticated_cross_lineage_runner(
    *,
    config: AuditConfig,
    explicitly_allow_synthetic_egress: bool,
    public_lineage_capability: VerifiedPublicModelLineage,
    ground_truth_capability: VerifiedFrozenGroundTruth,
    benchmark_suite: ModelBenchmarkSuite,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: Iterable[OpenRouterModelDiscoveryEvidence],
    candidate_registry: CandidateRegistry,
    qualification_policy: QualificationPolicy,
    budget: BudgetManager,
    usage: UsageLedger,
    run_plans: Iterable[AuthenticatedRunnerRunPlan],
    candidate_executor: CandidateCampaignExecutor,
    judge_route_preparation_executor: JudgeRoutePreparationExecutor,
    judge_executor: CrossLineageJudgeExecutor,
    generation_executor: RunnerGenerationVerificationExecutor,
) -> AuthenticatedRunnerExecutionResult:
    """Execute exactly two full-corpus passes and issue retained runner custody.

    Every structural, route, public-lineage, request-inventory, path, and declared
    cost-tripwire check runs before the first injected callback.  A nonempty terminal
    ledger is adopted as an exact immutable baseline before the interval opens.  Each
    declared per-attempt ceiling is installed on the shared budget and enforced before
    every atomic reservation and provider dispatch in its callback.
    """

    plans = _bounded_exact_tuple(run_plans, _RUN_COUNT, label="runner plan")
    evidence = _bounded_exact_tuple(
        discovery_evidence,
        _MAX_DISCOVERY_EVIDENCE,
        label="discovery evidence",
    )
    inventory, ledger, initial_snapshot, candidate_cost_plans = _preflight_execution(
        config=config,
        explicitly_allow_synthetic_egress=explicitly_allow_synthetic_egress,
        public_lineage_capability=public_lineage_capability,
        ground_truth_capability=ground_truth_capability,
        benchmark_suite=benchmark_suite,
        discovery_manifest=discovery_manifest,
        discovery_evidence=evidence,
        candidate_registry=candidate_registry,
        qualification_policy=qualification_policy,
        budget=budget,
        usage=usage,
        run_plans=plans,
        candidate_executor=candidate_executor,
        judge_route_preparation_executor=judge_route_preparation_executor,
        judge_executor=judge_executor,
        generation_executor=generation_executor,
    )
    effective_config_sha256 = inventory.effective_config_sha256
    await _adopt_exact_ledger_baseline(
        budget=budget,
        ledger=ledger,
        expected_snapshot=initial_snapshot,
    )
    if ledger.snapshot() != initial_snapshot:
        raise AuthenticatedRunnerExecutionError(
            "runner ledger changed between preflight and interval creation"
        )
    interval = begin_cross_lineage_ledger_interval(ledger)
    executed: list[AuthenticatedRunnerExecutedRun] = []
    all_attempt_ids: list[str] = []
    prepared_candidates: list[_PreparedCandidateRun] = []

    # Complete and verify both candidate campaigns before deriving or dispatching
    # either judge inventory.  This makes the remaining judge admission exact.
    for plan, candidate_cost_plan in zip(plans, candidate_cost_plans, strict=True):
        campaign = create_candidate_benchmark_campaign(
            plan.campaign_path,
            candidate_registry=candidate_registry,
            corpus=benchmark_suite,
            effective_config_sha256=effective_config_sha256,
            qualification_policy_sha256=qualification_policy.policy_sha256,
            cost_ledger=ledger,
        )
        usage_start = len(usage.records)
        candidate_ledger_start = ledger.snapshot()
        async with budget.active_request_cost_ceiling(
            plan.candidate_declared_cost_cap_usd_per_attempt
        ):
            candidate_result = await candidate_executor(
                run_kind=plan.run_kind,
                config=config,
                discovery_manifest=discovery_manifest,
                discovery_evidence=evidence,
                candidate_registry=candidate_registry,
                benchmark_suite=benchmark_suite,
                budget=budget,
                usage=usage,
                evidence_sink=campaign,
                qualification_policy=qualification_policy,
                request_cost_plan=candidate_cost_plan,
            )
        candidate_report, candidate_usage = _require_complete_candidate_execution(
            result=candidate_result,
            campaign=campaign,
            candidate_registry=candidate_registry,
            discovery_manifest=discovery_manifest,
            benchmark_suite=benchmark_suite,
            observed_usage=tuple(usage.records[usage_start:]),
            plan=plan,
            request_cost_plan=candidate_cost_plan,
            maximum_attempts=inventory.maximum_attempts_per_logical_request,
        )
        _require_exact_callback_ledger_delta(
            before=candidate_ledger_start,
            after=ledger.snapshot(),
            records=candidate_usage,
            label=f"{plan.run_kind.value} candidate",
        )

        portfolio = seal_model_benchmark_portfolio_from_campaign(
            plan.portfolio_path,
            campaign=campaign,
        )
        # Issue immediately while the original journal still retains its live report
        # bindings and before the judge can append another ledger entry.
        campaign_verification = issue_trusted_candidate_benchmark_campaign_verification(
            campaign=campaign,
            portfolio=portfolio,
            reports=candidate_result.reports,
        )
        campaign_verification.require_for(
            portfolio_sha256=portfolio.portfolio_sha256,
            reports=candidate_result.reports,
            policy_sha256=qualification_policy.policy_sha256,
            effective_config_sha256=effective_config_sha256,
        )

        candidate_generation_requests = candidate_generation_verification_requests(
            registry=candidate_registry,
            benchmark_reports=(candidate_report,),
        )
        _require_exact_generation_inventory(
            candidate_generation_requests,
            benchmark_suite=benchmark_suite,
            expected_model_id=candidate_registry.candidates[0].exact_model_id,
        )
        candidate_generation_ledger = ledger.snapshot()
        usage_before_candidate_generation = tuple(usage.records)
        candidate_generation = await generation_executor(
            run_kind=plan.run_kind,
            subject=AuthenticatedRunnerGenerationSubject.CANDIDATE,
            requests=candidate_generation_requests,
        )
        if (
            ledger.snapshot() != candidate_generation_ledger
            or tuple(usage.records) != usage_before_candidate_generation
        ):
            raise AuthenticatedRunnerExecutionError(
                f"{plan.run_kind.value} candidate generation re-fetch changed cost custody"
            )
        _require_generation_capability(
            candidate_generation,
            requests=candidate_generation_requests,
            embedded_attestations=tuple(
                case.generation_evidence
                for case in candidate_report.results[0].cases
                if case.generation_evidence is not None
            ),
        )

        prepared = prepare_cross_lineage_adjudication(
            public_lineage_capability=public_lineage_capability,
            suite=benchmark_suite,
            candidate_report=candidate_report,
            judge=plan.judge,
            run_kind=plan.run_kind,
        )
        prepared_candidates.append(
            _PreparedCandidateRun(
                plan=plan,
                candidate_cost_plan=candidate_cost_plan,
                candidate_report=candidate_report,
                candidate_usage=candidate_usage,
                candidate_campaign_reports=candidate_result.reports,
                candidate_portfolio=portfolio,
                candidate_campaign_verification=campaign_verification,
                candidate_generation_verification=candidate_generation,
                prepared_adjudication=prepared,
            )
        )

    if tuple(item.plan.run_kind for item in prepared_candidates) != (
        CrossLineageAdjudicationRunKind.PRIMARY,
        CrossLineageAdjudicationRunKind.REPLAY,
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner candidate preparation did not retain exact PRIMARY then REPLAY custody"
        )
    route_preparation_ledger = ledger.snapshot()
    usage_before_route_preparation = tuple(usage.records)
    route_preparation_result = await judge_route_preparation_executor(
        config=config,
        prepared_runs=tuple(item.prepared_adjudication for item in prepared_candidates),
        judges=tuple(item.plan.judge for item in prepared_candidates),
    )
    if (
        route_preparation_result is not None
        or ledger.snapshot() != route_preparation_ledger
        or tuple(usage.records) != usage_before_route_preparation
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner judge route preparation changed usage or cost custody"
        )
    judge_admission_snapshot = ledger.snapshot()
    usage_before_judge_planning = tuple(usage.records)
    try:
        judge_cost_plans = tuple(
            _judge_staged_cost_plan(
                config=config,
                prepared=item.prepared_adjudication,
                plan=item.plan,
            )
            for item in prepared_candidates
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner judge request costs cannot be derived from both exact prepared runs"
        ) from None
    if (
        ledger.snapshot() != judge_admission_snapshot
        or tuple(usage.records) != usage_before_judge_planning
        or tuple(item.run_kind for item in judge_cost_plans)
        != tuple(item.plan.run_kind for item in prepared_candidates)
        or any(
            item.stage is not AuthenticatedRunnerCostPlanStage.JUDGE for item in judge_cost_plans
        )
        or len({item.plan_sha256 for item in judge_cost_plans}) != _RUN_COUNT
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner judge cost admission changed live custody or returned invalid plans"
        )
    with localcontext() as context:
        context.prec = 160
        judge_maximum_cost = sum(
            (Decimal(item.maximum_cost_usd_exact) for item in judge_cost_plans),
            start=Decimal(0),
        )
        judge_maximum_final_spent = judge_admission_snapshot.spent_usd + judge_maximum_cost
    if judge_maximum_final_spent >= _LEDGER_CAP_USD:
        raise AuthenticatedRunnerExecutionError(
            "runner exact judge request-cost plans do not remain strictly below 250 USD"
        )
    for item, judge_cost_plan in zip(prepared_candidates, judge_cost_plans, strict=True):
        if Decimal(judge_cost_plan.maximum_cost_usd_per_attempt_exact) > (
            item.plan.judge_declared_cost_cap_usd_per_attempt
        ):
            raise AuthenticatedRunnerExecutionError(
                "runner judge exact request cost exceeds its operator tripwire"
            )

    for item, judge_cost_plan in zip(prepared_candidates, judge_cost_plans, strict=True):
        plan = item.plan
        prepared = item.prepared_adjudication
        usage_start = len(usage.records)
        judge_ledger_start = ledger.snapshot()
        async with budget.active_request_cost_ceiling(plan.judge_declared_cost_cap_usd_per_attempt):
            judge_results = await judge_executor(
                config=config,
                prepared=prepared,
                judge=plan.judge,
                budget=budget,
                usage=usage,
                request_cost_plan=judge_cost_plan,
            )
        adjudication, judge_usage = _require_complete_judge_execution(
            results=judge_results,
            prepared=prepared,
            judge=plan.judge,
            benchmark_suite=benchmark_suite,
            observed_usage=tuple(usage.records[usage_start:]),
            plan=plan,
            request_cost_plan=judge_cost_plan,
            maximum_attempts=inventory.maximum_attempts_per_logical_request,
        )
        _require_exact_callback_ledger_delta(
            before=judge_ledger_start,
            after=ledger.snapshot(),
            records=judge_usage,
            label=f"{plan.run_kind.value} judge",
        )
        judge_generation_requests = adjudication_generation_verification_requests(
            report=adjudication,
            judge=plan.judge,
        )
        _require_exact_generation_inventory(
            judge_generation_requests,
            benchmark_suite=benchmark_suite,
            expected_model_id=plan.judge.exact_model_id,
        )
        judge_generation_ledger = ledger.snapshot()
        usage_before_judge_generation = tuple(usage.records)
        judge_generation = await generation_executor(
            run_kind=plan.run_kind,
            subject=AuthenticatedRunnerGenerationSubject.JUDGE,
            requests=judge_generation_requests,
        )
        if (
            ledger.snapshot() != judge_generation_ledger
            or tuple(usage.records) != usage_before_judge_generation
        ):
            raise AuthenticatedRunnerExecutionError(
                f"{plan.run_kind.value} judge generation re-fetch changed cost custody"
            )
        _require_generation_capability(
            judge_generation,
            requests=judge_generation_requests,
            embedded_attestations=tuple(case.generation_evidence for case in adjudication.cases),
        )

        custody = CrossLineageRunnerRunCustody(
            run_kind=plan.run_kind,
            candidate_report=item.candidate_report,
            candidate_campaign_verification=item.candidate_campaign_verification,
            candidate_portfolio=item.candidate_portfolio,
            candidate_campaign_reports=item.candidate_campaign_reports,
            candidate_campaign_policy_sha256=qualification_policy.policy_sha256,
            candidate_campaign_effective_config_sha256=effective_config_sha256,
            candidate_generation_verification=item.candidate_generation_verification,
            judge=plan.judge,
            prepared_adjudication=prepared,
            adjudication_report=adjudication,
            judge_generation_verification=judge_generation,
        )
        executed.append(
            AuthenticatedRunnerExecutedRun(
                candidate_cost_plan=item.candidate_cost_plan,
                judge_cost_plan=judge_cost_plan,
                prepared_adjudication=prepared,
                custody=custody,
            )
        )
        all_attempt_ids.extend(_attempt_request_ids((*item.candidate_usage, *judge_usage)))

    expected_attempt_ids = tuple(all_attempt_ids)
    if (
        len(expected_attempt_ids) < inventory.logical_request_count
        or len(expected_attempt_ids) > inventory.maximum_provider_attempt_count
        or len(set(expected_attempt_ids)) != len(expected_attempt_ids)
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner attempt inventory is missing, excessive, or replayed"
        )
    closed_interval = close_cross_lineage_ledger_interval(
        interval,
        expected_request_ids=expected_attempt_ids,
    )
    run_custody = tuple(item.custody for item in executed)
    runner_capability, runner_evidence = issue_verified_cross_lineage_runner_custody(
        public_lineage_capability=public_lineage_capability,
        ground_truth_capability=ground_truth_capability,
        benchmark_suite=benchmark_suite,
        runs=run_custody,
        closed_ledger_interval=closed_interval,
    )
    runner_projection = require_verified_cross_lineage_runner_custody(
        runner_capability,
        evidence=runner_evidence,
    )
    if (
        runner_projection.ledger_request_ids != tuple(sorted(expected_attempt_ids))
        or tuple(item.custody.run_kind for item in executed)
        != (CrossLineageAdjudicationRunKind.PRIMARY, CrossLineageAdjudicationRunKind.REPLAY)
        or tuple(item.adjudication_report_sha256 for item in runner_projection.runs)
        != tuple(item.custody.adjudication_report.report_sha256 for item in executed)
    ):
        raise AuthenticatedRunnerExecutionError(
            "issued runner projection differs from the exact executed inventory"
        )
    return AuthenticatedRunnerExecutionResult(
        inventory=inventory,
        runs=tuple(executed),
        closed_ledger_interval=closed_interval,
        runner_capability=runner_capability,
        runner_evidence=runner_evidence,
        runner_projection=runner_projection,
    )


def _preflight_execution(
    *,
    config: AuditConfig,
    explicitly_allow_synthetic_egress: bool,
    public_lineage_capability: VerifiedPublicModelLineage,
    ground_truth_capability: VerifiedFrozenGroundTruth,
    benchmark_suite: ModelBenchmarkSuite,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    candidate_registry: CandidateRegistry,
    qualification_policy: QualificationPolicy,
    budget: BudgetManager,
    usage: UsageLedger,
    run_plans: tuple[AuthenticatedRunnerRunPlan, ...],
    candidate_executor: CandidateCampaignExecutor,
    judge_route_preparation_executor: JudgeRoutePreparationExecutor,
    judge_executor: CrossLineageJudgeExecutor,
    generation_executor: RunnerGenerationVerificationExecutor,
) -> tuple[
    AuthenticatedRunnerExecutionInventory,
    AtomicCostLedger,
    CostLedgerSnapshot,
    tuple[AuthenticatedRunnerStagedCostPlan, ...],
]:
    for value, expected_type, label in (
        (config, AuditConfig, "configuration"),
        (public_lineage_capability, VerifiedPublicModelLineage, "public lineage capability"),
        (ground_truth_capability, VerifiedFrozenGroundTruth, "ground-truth capability"),
        (benchmark_suite, ModelBenchmarkSuite, "benchmark suite"),
        (discovery_manifest, OpenRouterModelDiscoveryRunManifest, "discovery manifest"),
        (candidate_registry, CandidateRegistry, "candidate registry"),
        (qualification_policy, QualificationPolicy, "qualification policy"),
        (budget, BudgetManager, "budget manager"),
        (usage, UsageLedger, "usage ledger"),
    ):
        if type(value) is not expected_type:
            raise AuthenticatedRunnerExecutionError(f"runner {label} has the wrong exact type")
    if (
        not callable(candidate_executor)
        or not callable(judge_route_preparation_executor)
        or not callable(judge_executor)
        or not callable(generation_executor)
    ):
        raise AuthenticatedRunnerExecutionError("runner injected executor is not callable")
    if not _matches_exact_ledger_cap(config.execution.budget_usd):
        raise AuthenticatedRunnerExecutionError(
            "runner configured execution budget must equal 250 USD"
        )
    if not _matches_exact_ledger_cap(budget.total_usd):
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget manager total must equal 250 USD"
        )
    if budget.max_output_tokens != config.execution.max_output_tokens_per_request:
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget maximum output tokens differ from configuration"
        )
    if Decimal(str(budget.conservative_rate)) != Decimal(
        str(config.execution.conservative_usd_per_million_tokens)
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget conservative rate differs from configuration"
        )
    if budget.max_requests_per_agent != config.execution.max_requests_per_agent:
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget request cap differs from configuration"
        )
    if budget.require_endpoint_cost_bound is not True:
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget must require endpoint cost binding"
        )
    if budget.global_input_token_budget != config.token_budgets.global_input_token_budget:
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget global input token budget differs from configuration"
        )
    if budget.global_output_token_budget != config.token_budgets.global_output_token_budget:
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget global output token budget differs from configuration"
        )
    configured_model_caps = {
        model: Decimal(str(cap))
        for model, cap in config.token_budgets.per_model_cost_budget_usd.items()
    }
    configured_role_caps = {
        role: Decimal(str(cap))
        for role, cap in config.token_budgets.per_role_cost_budget_usd.items()
    }
    if (
        budget.per_model_usd_caps != configured_model_caps
        or budget.per_role_usd_caps != configured_role_caps
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget scoped cost budgets differ from configuration"
        )
    effective_config_sha256 = config.stable_hash()
    if len(benchmark_suite.cases) != _FROZEN_CASE_COUNT:
        raise AuthenticatedRunnerExecutionError("runner requires the exact frozen 24-case suite")
    if len(candidate_registry.candidates) != 1 or len(discovery_evidence) != 1:
        raise AuthenticatedRunnerExecutionError(
            "runner requires one exact candidate in each fresh campaign"
        )
    try:
        validate_candidate_registry_discovery(
            registry=candidate_registry,
            run_manifest=discovery_manifest,
            evidence=discovery_evidence,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner candidate registry differs from fresh discovery"
        ) from None
    _require_exact_runner_egress_policy(
        config=config,
        benchmark_suite=benchmark_suite,
        explicitly_allow_synthetic_egress=explicitly_allow_synthetic_egress,
    )
    try:
        validate_candidate_benchmark_policy_capacity(
            benchmark_suite=benchmark_suite,
            qualification_policy=qualification_policy,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner qualification policy exceeds frozen-corpus case capacity"
        ) from None
    try:
        ground_truth = ground_truth_capability.require_for(
            objective_sha256=FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
            provenance_sha256=FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
            source_revision=FROZEN_GROUND_TRUTH_SOURCE_REVISION,
            benchmark_corpus_sha256=benchmark_suite.corpus_sha256,
            benchmark_ground_truth_sha256=benchmark_suite.ground_truth_sha256,
        )
    except (AttributeError, TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner frozen ground-truth capability does not bind the exact suite"
        ) from None
    if (
        type(ground_truth) is not VerifiedFrozenGroundTruthProjection
        or ground_truth.case_count != _FROZEN_CASE_COUNT
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner ground-truth preflight returned invalid case custody"
        )
    if usage.records:
        raise AuthenticatedRunnerExecutionError("runner requires a fresh empty usage ledger")
    maximum_attempts = config.execution.max_model_retries + 1
    maximum_provider_attempts = _LOGICAL_REQUEST_COUNT * maximum_attempts
    if (
        config.execution.max_requests_per_agent < maximum_provider_attempts
        or budget.max_requests_per_agent < maximum_provider_attempts
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner request cap is below the preflight maximum-attempt inventory"
        )
    ledger = budget.atomic_ledger
    if type(ledger) is not AtomicCostLedger or ledger.cap_usd != _LEDGER_CAP_USD:
        raise AuthenticatedRunnerExecutionError("runner atomic cost ledger cap must equal 250 USD")
    initial = ledger.snapshot()
    _require_clean_ledger_snapshot(initial, label="initial runner ledger")

    if len(run_plans) != _RUN_COUNT or tuple(item.run_kind for item in run_plans) != (
        CrossLineageAdjudicationRunKind.PRIMARY,
        CrossLineageAdjudicationRunKind.REPLAY,
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner plans require exact PRIMARY then REPLAY order"
        )
    candidate = candidate_registry.candidates[0]
    judges: list[CandidateModel] = []
    judge_manifest_hashes: list[str] = []
    judge_evidence_hashes: list[str] = []
    paths: list[Path] = []
    maximum_interval_cost = Decimal(0)
    judge_reasoning_control = build_reasoning_policy(config).control_for_request("model_benchmark")
    for plan in run_plans:
        if type(plan) is not AuthenticatedRunnerRunPlan or type(plan.run_kind) is not (
            CrossLineageAdjudicationRunKind
        ):
            raise AuthenticatedRunnerExecutionError("runner plan has the wrong exact type")
        if (
            type(plan.judge_discovery_manifest) is not OpenRouterModelDiscoveryRunManifest
            or type(plan.judge_discovery_evidence) is not tuple
            or len(plan.judge_discovery_evidence) != 1
            or type(plan.judge_registry) is not CandidateRegistry
            or len(plan.judge_registry.candidates) != 1
        ):
            raise AuthenticatedRunnerExecutionError(
                "runner plan requires one exact fresh judge discovery registry"
            )
        try:
            validate_candidate_registry_discovery(
                registry=plan.judge_registry,
                run_manifest=plan.judge_discovery_manifest,
                evidence=plan.judge_discovery_evidence,
            )
        except (TypeError, ValueError):
            raise AuthenticatedRunnerExecutionError(
                "runner judge registry differs from its fresh discovery"
            ) from None
        judge = plan.judge
        judge_evidence = plan.judge_discovery_evidence[0]
        judge_manifest_hashes.append(plan.judge_discovery_manifest.manifest_sha256)
        judge_evidence_hashes.append(judge_evidence.discovery_evidence_sha256)
        if (
            judge.exact_model_id != judge_evidence.exact_model_id
            or judge.canonical_model_slug != judge_evidence.canonical_slug
            or judge.approved_provider_endpoint != judge_evidence.approved_provider_endpoint
            or judge.approved_provider_name != judge_evidence.provider_name
            or judge.discovery_evidence_sha256 != judge_evidence.discovery_evidence_sha256
            or judge.endpoint_snapshot_sha256 != judge_evidence.endpoint_snapshot_sha256
            or judge.output_capability_sha256 != judge_evidence.output_capability_sha256
            or judge.pricing_snapshot_sha256 != judge_evidence.pricing_snapshot_sha256
            or judge.model_metadata_snapshot_sha256 != judge_evidence.model_metadata_snapshot_sha256
            or judge.structured_output_mode != judge_evidence.structured_output_mode
        ):
            raise AuthenticatedRunnerExecutionError(
                "runner judge identity, route, output, or pricing differs from fresh discovery"
            )
        if judge.exact_model_id == candidate.exact_model_id:
            raise AuthenticatedRunnerExecutionError("runner candidate cannot judge itself")
        try:
            judge_evidence.require_compatible_reasoning_profile(judge_reasoning_control)
        except EndpointSnapshotValidationError:
            raise AuthenticatedRunnerExecutionError(
                "runner judge reasoning profile is incompatible with frozen launch evidence"
            ) from None
        judges.append(judge)
        for path in (plan.campaign_path, plan.portfolio_path):
            _preflight_private_output_leaf(path)
            paths.append(path)
        candidate_cap = _positive_exact_decimal(
            plan.candidate_declared_cost_cap_usd_per_attempt,
            label="candidate declared per-attempt cost cap",
        )
        judge_cap = _positive_exact_decimal(
            plan.judge_declared_cost_cap_usd_per_attempt,
            label="judge declared per-attempt cost cap",
        )
        with localcontext() as context:
            context.prec = 80
            maximum_interval_cost += Decimal(_FROZEN_CASE_COUNT * maximum_attempts) * (
                candidate_cap + judge_cap
            )
    if len(set(paths)) != len(paths):
        raise AuthenticatedRunnerExecutionError("runner campaign paths are not unique")
    if len({item.exact_model_id for item in judges}) != _RUN_COUNT:
        raise AuthenticatedRunnerExecutionError("runner judges must be exact distinct models")
    if (
        len(set(judge_manifest_hashes)) != _RUN_COUNT
        or len(set(judge_evidence_hashes)) != _RUN_COUNT
        or discovery_manifest.manifest_sha256 in judge_manifest_hashes
        or discovery_evidence[0].discovery_evidence_sha256 in judge_evidence_hashes
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner candidate and judges require distinct fresh discovery evidence"
        )

    try:
        candidate_judge = tuple(
            require_independent_public_model_lineage(
                public_lineage_capability,
                candidate.exact_model_id,
                judge.exact_model_id,
            )
            for judge in judges
        )
        judge_pair = require_independent_public_model_lineage(
            public_lineage_capability,
            judges[0].exact_model_id,
            judges[1].exact_model_id,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner public lineage does not prove three distinct roots"
        ) from None
    if any(
        type(item) is not VerifiedIndependentPublicModelLineageProjection
        or item.independent is not True
        for item in (*candidate_judge, judge_pair)
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner public lineage returned an invalid independence projection"
        )
    if candidate.root_lineage is not None and any(
        item.left_root_lineage != candidate.root_lineage for item in candidate_judge
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner candidate caller lineage conflicts with public lineage"
        )
    for judge, projection in zip(judges, candidate_judge, strict=True):
        if judge.root_lineage is not None and judge.root_lineage != projection.right_root_lineage:
            raise AuthenticatedRunnerExecutionError(
                "runner judge caller lineage conflicts with public lineage"
            )

    with localcontext() as context:
        context.prec = 80
        maximum_final_spent = initial.spent_usd + maximum_interval_cost
    if maximum_final_spent >= _LEDGER_CAP_USD:
        raise AuthenticatedRunnerExecutionError(
            "runner declared cost-tripwire does not remain strictly below 250 USD"
        )
    try:
        candidate_cost_plans = tuple(
            _candidate_staged_cost_plan(
                config=config,
                benchmark_suite=benchmark_suite,
                discovery_manifest=discovery_manifest,
                discovery_evidence=discovery_evidence[0],
                candidate=candidate,
                run_kind=plan.run_kind,
            )
            for plan in run_plans
        )
    except EndpointSnapshotValidationError:
        raise AuthenticatedRunnerExecutionError(
            "runner candidate reasoning profile is incompatible with frozen launch evidence"
        ) from None
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner candidate request costs cannot be derived from frozen launch evidence"
        ) from None
    if (
        tuple(item.run_kind for item in candidate_cost_plans)
        != tuple(item.run_kind for item in run_plans)
        or any(
            item.stage is not AuthenticatedRunnerCostPlanStage.CANDIDATE
            for item in candidate_cost_plans
        )
        or len({item.plan_sha256 for item in candidate_cost_plans}) != _RUN_COUNT
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner candidate staged cost plans are missing, reordered, or replayed"
        )
    with localcontext() as context:
        context.prec = 160
        candidate_derived_interval_cost = sum(
            (Decimal(item.maximum_cost_usd_exact) for item in candidate_cost_plans),
            start=Decimal(0),
        )
        candidate_derived_final_spent = initial.spent_usd + candidate_derived_interval_cost
    if candidate_derived_final_spent >= _LEDGER_CAP_USD:
        raise AuthenticatedRunnerExecutionError(
            "runner candidate exact request-cost plans do not remain strictly below 250 USD"
        )
    for cost_plan, run_plan in zip(candidate_cost_plans, run_plans, strict=True):
        if Decimal(cost_plan.maximum_cost_usd_per_attempt_exact) > (
            run_plan.candidate_declared_cost_cap_usd_per_attempt
        ):
            raise AuthenticatedRunnerExecutionError(
                "runner candidate exact request cost exceeds its operator tripwire"
            )
    return (
        AuthenticatedRunnerExecutionInventory(
            run_count=_RUN_COUNT,
            case_count=_FROZEN_CASE_COUNT,
            candidate_logical_request_count=_RUN_COUNT * _FROZEN_CASE_COUNT,
            judge_logical_request_count=_RUN_COUNT * _FROZEN_CASE_COUNT,
            logical_request_count=_LOGICAL_REQUEST_COUNT,
            maximum_attempts_per_logical_request=maximum_attempts,
            maximum_provider_attempt_count=maximum_provider_attempts,
            generation_refetch_count=_LOGICAL_REQUEST_COUNT,
            effective_config_sha256=effective_config_sha256,
            initial_spent_usd=initial.spent_usd,
            declared_interval_cost_cap_usd=maximum_interval_cost,
            declared_final_spent_cap_usd=maximum_final_spent,
            candidate_stage_plan_sha256s=tuple(item.plan_sha256 for item in candidate_cost_plans),
            candidate_derived_interval_cost_cap_usd=candidate_derived_interval_cost,
            candidate_derived_final_spent_cap_usd=candidate_derived_final_spent,
            judge_cost_admission_status="PENDING_REAL_CANDIDATE_OUTPUTS",
        ),
        ledger,
        initial,
        candidate_cost_plans,
    )


def _require_exact_runner_egress_policy(
    *,
    config: AuditConfig,
    benchmark_suite: ModelBenchmarkSuite,
    explicitly_allow_synthetic_egress: bool,
) -> None:
    """Reject each local egress-policy defect with a stable non-provider diagnostic."""

    if config.privacy.profile is PrivacyProfile.STRICT_ZDR:
        raise AuthenticatedRunnerExecutionError(
            "runner privacy profile is STRICT_ZDR; expected SYNTHETIC_BENCHMARK"
        )
    if config.privacy.profile is not PrivacyProfile.SYNTHETIC_BENCHMARK:
        raise AuthenticatedRunnerExecutionError(
            "runner privacy profile must be SYNTHETIC_BENCHMARK"
        )
    if config.privacy.require_zdr is not True:
        raise AuthenticatedRunnerExecutionError(
            "runner SYNTHETIC_BENCHMARK policy requires require_zdr=true"
        )
    if config.privacy.maximum_model_retention != "zero":
        raise AuthenticatedRunnerExecutionError(
            "runner SYNTHETIC_BENCHMARK policy requires maximum_model_retention=zero"
        )
    if (
        config.privacy.store_raw_prompts is not False
        or config.privacy.store_raw_responses is not False
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner SYNTHETIC_BENCHMARK policy refuses raw prompt or response storage"
        )
    if config.models.provider_policy.allow_fallbacks is not False:
        raise AuthenticatedRunnerExecutionError(
            "runner provider fallback is enabled; no fallback is allowed"
        )
    if (
        type(explicitly_allow_synthetic_egress) is not bool
        or explicitly_allow_synthetic_egress is not True
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner requires explicit synthetic-source egress authorization"
        )
    try:
        validate_candidate_benchmark_egress(
            config=config,
            benchmark_suite=benchmark_suite,
            explicitly_allowed=explicitly_allow_synthetic_egress,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner frozen corpus is outside the synthetic-source egress allowlist"
        ) from None


def _matches_exact_ledger_cap(value: object) -> bool:
    """Return whether a local numeric budget equals the frozen ledger cap exactly."""

    try:
        candidate = Decimal(str(value))
    except (ArithmeticError, TypeError, ValueError):
        return False
    return candidate.is_finite() and candidate == _LEDGER_CAP_USD


async def _adopt_exact_ledger_baseline(
    *,
    budget: BudgetManager,
    ledger: AtomicCostLedger,
    expected_snapshot: CostLedgerSnapshot,
) -> None:
    current = ledger.snapshot()
    if current != expected_snapshot or budget.atomic_ledger is not ledger:
        raise AuthenticatedRunnerExecutionError("runner ledger changed before baseline adoption")
    if not current.entries:
        if budget.recovery_required:
            raise AuthenticatedRunnerExecutionError(
                "empty runner ledger unexpectedly requires budget recovery"
            )
        return
    if not budget.recovery_required:
        raise AuthenticatedRunnerExecutionError(
            "nonempty runner ledger lacks fresh baseline-recovery custody"
        )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    if ledger.snapshot() != expected_snapshot:
        raise AuthenticatedRunnerExecutionError("runner ledger changed while freezing its baseline")
    scope = _issue_trusted_budget_recovery_scope((), cost_ledger_baseline=baseline)
    try:
        await budget.restore_recovered_usage((), recovery_scope=scope)
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "runner budget could not adopt the exact ledger baseline"
        ) from None
    if (
        budget.recovery_required
        or budget.spent_usd_exact != expected_snapshot.spent_usd
        or ledger.snapshot() != expected_snapshot
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner budget changed or failed to adopt the exact ledger baseline"
        )


def _require_complete_candidate_execution(
    *,
    result: CandidateBenchmarkExecutionResult,
    campaign: CandidateBenchmarkCampaignJournal,
    candidate_registry: CandidateRegistry,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    benchmark_suite: ModelBenchmarkSuite,
    observed_usage: tuple[UsageRecord, ...],
    plan: AuthenticatedRunnerRunPlan,
    request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    maximum_attempts: int,
) -> tuple[ModelBenchmarkReport, tuple[UsageRecord, ...]]:
    if type(result) is not CandidateBenchmarkExecutionResult:
        raise AuthenticatedRunnerExecutionError(
            "candidate executor returned the wrong exact result type"
        )
    if (
        result.candidate_registry_sha256 != candidate_registry.registry_sha256
        or result.discovery_manifest_sha256 != discovery_manifest.manifest_sha256
        or result.benchmark_corpus_sha256 != benchmark_suite.corpus_sha256
        or result.benchmark_ground_truth_sha256 != benchmark_suite.ground_truth_sha256
        or len(result.reports) != 1
        or len(result.diagnostics) != 1
        or result.reports != campaign.reports
        or result.diagnostics != campaign.diagnostics
    ):
        raise AuthenticatedRunnerExecutionError(
            "candidate execution differs from its exact singleton campaign"
        )
    campaign.require_complete()
    report = result.reports[0]
    diagnostic = result.diagnostics[0]
    cases = report.results[0].cases if len(report.results) == 1 else ()
    report_usage = tuple(case.usage_record for case in cases if case.usage_record is not None)
    if (
        report.execution_evidence is not ExecutionEvidenceKind.REAL
        or report.corpus_name != benchmark_suite.name
        or report.corpus_sha256 != benchmark_suite.corpus_sha256
        or report.ground_truth_sha256 != benchmark_suite.ground_truth_sha256
        or tuple(report.case_ids) != tuple(case.case_id for case in benchmark_suite.cases)
        or len(cases) != _FROZEN_CASE_COUNT
        or any(case.error_kind is not None for case in cases)
        or len(report_usage) != _FROZEN_CASE_COUNT
        or observed_usage != report_usage
        or diagnostic.state is not CandidateBenchmarkRunState.COMPLETE
        or diagnostic.logical_request_count != _FROZEN_CASE_COUNT
        or diagnostic.requests_observed != _FROZEN_CASE_COUNT
        or diagnostic.failed_cases != 0
    ):
        raise AuthenticatedRunnerExecutionError(
            "candidate execution is not one complete REAL 24-case campaign"
        )
    _require_exact_route_and_costs(
        report_usage,
        expected_model=candidate_registry.candidates[0],
        maximum_cost_per_attempt=plan.candidate_declared_cost_cap_usd_per_attempt,
        maximum_attempts=maximum_attempts,
        request_cost_plan=request_cost_plan,
        expected_stage=AuthenticatedRunnerCostPlanStage.CANDIDATE,
        expected_run_kind=plan.run_kind,
        label="candidate",
    )
    return report, report_usage


def _require_complete_judge_execution(
    *,
    results: tuple[CrossLineageAdjudicationCaseResult, ...],
    prepared: CrossLineageAdjudicationPreparedRun,
    judge: CandidateModel,
    benchmark_suite: ModelBenchmarkSuite,
    observed_usage: tuple[UsageRecord, ...],
    plan: AuthenticatedRunnerRunPlan,
    request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    maximum_attempts: int,
) -> tuple[CrossLineageAdjudicationReport, tuple[UsageRecord, ...]]:
    if (
        type(results) is not tuple
        or len(results) != _FROZEN_CASE_COUNT
        or any(type(item) is not CrossLineageAdjudicationCaseResult for item in results)
    ):
        raise AuthenticatedRunnerExecutionError(
            "judge executor returned the wrong exact case-result inventory"
        )
    try:
        report = build_cross_lineage_adjudication_report(
            prepared=prepared,
            results=results,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "judge execution differs from the prepared request set"
        ) from None
    report_usage = tuple(case.usage_record for case in report.cases)
    if (
        report.run_kind is not plan.run_kind
        or report.target != prepared.target
        or report.prepared_run_sha256 != prepared.prepared_run_sha256
        or report.case_ids != tuple(case.case_id for case in benchmark_suite.cases)
        or len(report.cases) != _FROZEN_CASE_COUNT
        or observed_usage != report_usage
        or any(
            item.routing.get("privacy_source_proof_kind")
            != "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION"
            for item in report_usage
        )
    ):
        raise AuthenticatedRunnerExecutionError(
            "judge execution is not the exact complete prepared 24-case report"
        )
    _require_exact_route_and_costs(
        report_usage,
        expected_model=judge,
        maximum_cost_per_attempt=plan.judge_declared_cost_cap_usd_per_attempt,
        maximum_attempts=maximum_attempts,
        request_cost_plan=request_cost_plan,
        expected_stage=AuthenticatedRunnerCostPlanStage.JUDGE,
        expected_run_kind=plan.run_kind,
        label="judge",
    )
    return report, report_usage


def _require_exact_route_and_costs(
    records: tuple[UsageRecord, ...],
    *,
    expected_model: CandidateModel,
    maximum_cost_per_attempt: Decimal,
    maximum_attempts: int,
    request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    expected_stage: AuthenticatedRunnerCostPlanStage,
    expected_run_kind: CrossLineageAdjudicationRunKind,
    label: str,
) -> None:
    maximum_cost = _positive_exact_decimal(
        maximum_cost_per_attempt,
        label=f"{label} per-attempt cost cap",
    )
    request_ids = tuple(record.request_id for record in records)
    generation_ids = tuple(record.openrouter_generation_id for record in records)
    request_body_hashes = tuple(record.request_body_sha256 for record in records)
    if (
        type(request_cost_plan) is not AuthenticatedRunnerStagedCostPlan
        or request_cost_plan.stage is not expected_stage
        or request_cost_plan.run_kind is not expected_run_kind
        or request_cost_plan.exact_model_id != expected_model.exact_model_id
        or request_cost_plan.provider_endpoint != expected_model.approved_provider_endpoint
        or request_cost_plan.maximum_attempts_per_logical_request != maximum_attempts
        or len(request_cost_plan.request_previews) != len(records)
        or request_cost_plan.case_ids != tuple(sorted(request_cost_plan.case_ids))
        or tuple(record.request_id for record in records)
        != tuple(item.logical_request_id for item in request_cost_plan.request_previews)
    ):
        raise AuthenticatedRunnerExecutionError(
            f"{label} execution differs from its exact staged cost plan"
        )
    if (
        len(set(request_ids)) != len(records)
        or None in generation_ids
        or len(set(generation_ids)) != len(records)
        or None in request_body_hashes
        or len(set(request_body_hashes)) != len(records)
    ):
        raise AuthenticatedRunnerExecutionError(f"{label} execution identities are replayed")
    for record, preview in zip(records, request_cost_plan.request_previews, strict=True):
        accounted = record.accounted_cost_usd_exact
        exact_model_id = expected_model.exact_model_id
        canonical_model_id = expected_model.canonical_model_slug
        endpoint = expected_model.approved_provider_endpoint
        if (
            record.execution_evidence is not ExecutionEvidenceKind.REAL
            or not is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
            or record.status != "success"
            or record.requested_model != exact_model_id
            or record.returned_model not in {exact_model_id, canonical_model_id}
            or record.actual_model not in {exact_model_id, canonical_model_id}
            or record.actual_provider_endpoint != endpoint
            or tuple(record.configured_provider_endpoints) != (endpoint,)
            or record.routing.get("selected_provider_endpoint") != endpoint
            or record.routing.get("selected_provider_name") != expected_model.approved_provider_name
            or record.routing.get("canonical_model") != canonical_model_id
            or record.routing.get("discovery_evidence_sha256")
            != expected_model.discovery_evidence_sha256
            or record.routing.get("endpoint_snapshot_sha256")
            != expected_model.endpoint_snapshot_sha256
            or record.routing.get("output_capability_sha256")
            != expected_model.output_capability_sha256
            or record.routing.get("endpoint_pricing_sha256")
            != expected_model.pricing_snapshot_sha256
            or record.routing.get("model_metadata_snapshot_sha256")
            != expected_model.model_metadata_snapshot_sha256
            or record.routing.get("provider_fallbacks_allowed") is not False
            or record.routing.get("request_cost_preview_sha256") != preview.preview_sha256
            or not 1 <= record.attempts <= maximum_attempts
            or accounted is None
            or Decimal(accounted) > maximum_cost * Decimal(record.attempts)
            or Decimal(accounted)
            > Decimal(preview.maximum_cost_usd_per_attempt_exact) * Decimal(record.attempts)
        ):
            raise AuthenticatedRunnerExecutionError(
                f"{label} execution violates its singleton route or cost cap"
            )


def _require_exact_generation_inventory(
    requests: tuple[GenerationVerificationRequest, ...],
    *,
    benchmark_suite: ModelBenchmarkSuite,
    expected_model_id: str,
) -> None:
    if (
        type(requests) is not tuple
        or len(requests) != _FROZEN_CASE_COUNT
        or tuple(item.case_id for item in requests)
        != tuple(case.case_id for case in benchmark_suite.cases)
        or any(item.exact_model_id != expected_model_id for item in requests)
    ):
        raise AuthenticatedRunnerExecutionError(
            "generation re-fetch inventory differs from the exact 24-case subject"
        )


def _require_generation_capability(
    capability: TrustedGenerationVerification,
    *,
    requests: tuple[GenerationVerificationRequest, ...],
    embedded_attestations: tuple[OpenRouterGenerationEvidence, ...],
) -> None:
    if type(capability) is not TrustedGenerationVerification or len(embedded_attestations) != len(
        requests
    ):
        raise AuthenticatedRunnerExecutionError(
            "generation executor did not return exact live verification custody"
        )
    attestations_by_id = {item.generation_id: item for item in embedded_attestations}
    try:
        resolved = tuple(
            capability.attestation_for(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                usage_record=request.usage_record,
                expected_provider_name=request.expected_provider_name,
            )
            for request in requests
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerExecutionError(
            "generation capability does not bind every exact runner case"
        ) from None
    if any(
        attestations_by_id.get(attestation.generation_id) != attestation for attestation in resolved
    ):
        raise AuthenticatedRunnerExecutionError(
            "generation re-fetch differs from embedded runner evidence"
        )


def _attempt_request_ids(records: tuple[UsageRecord, ...]) -> tuple[str, ...]:
    return tuple(
        record.request_id if attempt == 1 else f"{record.request_id}:attempt:{attempt}"
        for record in records
        for attempt in range(1, record.attempts + 1)
    )


def _require_exact_callback_ledger_delta(
    *,
    before: CostLedgerSnapshot,
    after: CostLedgerSnapshot,
    records: tuple[UsageRecord, ...],
    label: str,
) -> None:
    """Require one callback to append only its exact known-cost provider attempts."""

    expected_ids = _attempt_request_ids(records)
    before_by_id = {entry.request_id: entry for entry in before.entries}
    after_by_id = {entry.request_id: entry for entry in after.entries}
    new_ids = tuple(sorted(set(after_by_id) - set(before_by_id)))
    invalid_snapshot = (
        type(before) is not CostLedgerSnapshot
        or type(after) is not CostLedgerSnapshot
        or type(records) is not tuple
        or type(label) is not str
        or not label
        or after.cap_usd != _LEDGER_CAP_USD
        or after.spent_usd >= _LEDGER_CAP_USD
        or after.active_reserved_usd != 0
        or after.over_cap
        or after.has_reservation_overrun
        or len(expected_ids) < len(records)
        or len(expected_ids) != len(set(expected_ids))
        or new_ids != tuple(sorted(expected_ids))
        or any(after_by_id.get(request_id) != entry for request_id, entry in before_by_id.items())
    )
    if invalid_snapshot:
        raise AuthenticatedRunnerExecutionError(
            f"{label} callback ledger delta is not exact terminal known-cost reconciliation"
        )

    new_entries = {request_id: after_by_id[request_id] for request_id in expected_ids}
    if any(
        entry.status is not CostEntryStatus.RECONCILED
        or entry.actual_cost_usd is None
        or entry.accounted_cost_usd != entry.actual_cost_usd
        or entry.actual_cost_usd > entry.reserved_usd
        for entry in new_entries.values()
    ):
        raise AuthenticatedRunnerExecutionError(
            f"{label} callback ledger delta is not exact terminal known-cost reconciliation"
        )

    with localcontext() as context:
        context.prec = 80
        expected_spend = Decimal(0)
        for record in records:
            accounted = record.accounted_cost_usd_exact
            if accounted is None:
                raise AuthenticatedRunnerExecutionError(
                    f"{label} callback ledger delta is not exact terminal known-cost reconciliation"
                )
            attempt_ids = tuple(
                record.request_id if attempt == 1 else f"{record.request_id}:attempt:{attempt}"
                for attempt in range(1, record.attempts + 1)
            )
            actual = sum(
                (new_entries[request_id].accounted_cost_usd for request_id in attempt_ids),
                start=Decimal(0),
            )
            if actual != Decimal(accounted):
                raise AuthenticatedRunnerExecutionError(
                    f"{label} callback ledger delta is not exact terminal known-cost reconciliation"
                )
            expected_spend += actual
        if after.spent_usd - before.spent_usd != expected_spend:
            raise AuthenticatedRunnerExecutionError(
                f"{label} callback ledger delta is not exact terminal known-cost reconciliation"
            )


def _require_clean_ledger_snapshot(snapshot: CostLedgerSnapshot, *, label: str) -> None:
    if (
        type(snapshot) is not CostLedgerSnapshot
        or snapshot.cap_usd != _LEDGER_CAP_USD
        or snapshot.spent_usd >= _LEDGER_CAP_USD
        or snapshot.active_reserved_usd != 0
        or snapshot.over_cap
        or snapshot.has_reservation_overrun
        or any(
            item.status
            not in {
                CostEntryStatus.RECONCILED,
                CostEntryStatus.UNCERTAIN_ACCOUNTED,
                CostEntryStatus.RELEASED,
            }
            for item in snapshot.entries
        )
    ):
        raise AuthenticatedRunnerExecutionError(
            f"{label} must be a clean reconciled ledger strictly below 250 USD"
        )


def _positive_exact_decimal(value: object, *, label: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value <= 0:
        raise AuthenticatedRunnerExecutionError(f"{label} must be a positive exact Decimal")
    return value


def _preflight_private_output_leaf(path: Path) -> None:
    """Prove one fresh output leaf has a private no-follow writable parent."""

    if type(path) is not _PATH_TYPE or not path.is_absolute():
        raise AuthenticatedRunnerExecutionError(
            "runner campaign and portfolio paths must be exact absolute paths"
        )
    absolute = Path(os.path.abspath(path))
    if absolute != path or not absolute.name or absolute.name in {".", ".."}:
        raise AuthenticatedRunnerExecutionError(
            "runner campaign and portfolio paths must be canonical output leaves"
        )
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if (
        no_follow <= 0
        or directory <= 0
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise AuthenticatedRunnerExecutionError(
            "runner output preflight requires descriptor-relative no-follow support"
        )
    directory_flags = os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    probe_name: str | None = None
    try:
        descriptor = os.open(absolute.anchor, directory_flags)
        for component in absolute.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.geteuid()
        ):
            raise AuthenticatedRunnerExecutionError(
                "runner output parent must be an owned private regular directory"
            )
        try:
            os.stat(absolute.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise AuthenticatedRunnerExecutionError(
                "runner campaign and portfolio output leaf must be fresh"
            )

        probe_name = f".mmaudit-runner-preflight-{secrets.token_hex(16)}"
        probe_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | getattr(os, "O_CLOEXEC", 0)
        probe = os.open(probe_name, probe_flags, 0o600, dir_fd=descriptor)
        try:
            os.fchmod(probe, 0o600)
            metadata = os.fstat(probe)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise AuthenticatedRunnerExecutionError(
                    "runner output parent cannot create private exclusive artifacts"
                )
            os.fsync(probe)
        finally:
            os.close(probe)
        os.unlink(probe_name, dir_fd=descriptor)
        probe_name = None
        current_parent = os.fstat(descriptor)
        if (
            current_parent.st_dev,
            current_parent.st_ino,
            current_parent.st_mode,
            current_parent.st_uid,
        ) != (
            parent.st_dev,
            parent.st_ino,
            parent.st_mode,
            parent.st_uid,
        ):
            raise AuthenticatedRunnerExecutionError(
                "runner output parent changed during private write preflight"
            )
    except AuthenticatedRunnerExecutionError:
        raise
    except OSError as exc:
        raise AuthenticatedRunnerExecutionError(
            "runner output parent is unavailable, linked, or not atomically writable"
        ) from exc
    finally:
        if descriptor >= 0:
            if probe_name is not None:
                with suppress(OSError):
                    os.unlink(probe_name, dir_fd=descriptor)
            os.close(descriptor)


def _bounded_exact_tuple[T](values: Iterable[T], maximum: int, *, label: str) -> tuple[T, ...]:
    try:
        bounded = tuple(islice(iter(values), maximum + 1))
    except TypeError:
        raise AuthenticatedRunnerExecutionError(f"{label} inventory is not iterable") from None
    if not bounded or len(bounded) > maximum:
        raise AuthenticatedRunnerExecutionError(f"{label} inventory is empty or exceeds its bound")
    return bounded


__all__ = [
    "AuthenticatedRunnerExecutedRun",
    "AuthenticatedRunnerExecutionError",
    "AuthenticatedRunnerExecutionInventory",
    "AuthenticatedRunnerExecutionResult",
    "AuthenticatedRunnerGenerationSubject",
    "AuthenticatedRunnerRunPlan",
    "CandidateCampaignExecutor",
    "CrossLineageJudgeExecutor",
    "JudgeRoutePreparationExecutor",
    "RunnerGenerationVerificationExecutor",
    "execute_authenticated_cross_lineage_runner",
]
