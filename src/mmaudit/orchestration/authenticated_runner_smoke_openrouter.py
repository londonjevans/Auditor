"""One-shot OpenRouter execution for the NONCREDITING one-case smoke contract.

The adapter exercises the real candidate, generation, judge, pricing, identity,
and ledger surfaces, but deliberately never calls the full AUTHRUNNER custody or
AUTHSEAL issuers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from typing import Never

from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
    adjudication_generation_verification_requests,
    build_cross_lineage_adjudication_report,
    cross_lineage_adjudication_smoke_request_cost_previews,
    execute_noncrediting_cross_lineage_adjudication_smoke_requests,
    prepare_noncrediting_cross_lineage_adjudication_smoke,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    NoncreditingModelBenchmarkSmokeReport,
    authenticated_runner_smoke_model_benchmark_request_descriptor,
    execute_noncrediting_model_benchmark_smoke,
    validate_authenticated_runner_smoke_model_benchmark_cost_preview,
)
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageLedgerIntervalEvidence,
    _require_closed_cross_lineage_ledger_interval,
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
)
from mmaudit.models.authenticated_runner_smoke import (
    AuthenticatedRunnerSmokeCostPlan,
    AuthenticatedRunnerSmokeEvidenceBundle,
    AuthenticatedRunnerSmokeRunEvidence,
    build_authenticated_runner_smoke_cost_plan,
    seal_authenticated_runner_smoke_evidence_bundle,
    seal_authenticated_runner_smoke_run_evidence,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    AUTHENTICATED_RUNNER_SMOKE_CASE_ID,
    AuthenticatedRunnerSmokeCorpusBundle,
)
from mmaudit.models.candidate_benchmark import validate_candidate_benchmark_egress
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
    OpenRouterModelDiscoveryRunManifest,
    openrouter_catalog_canonical_slug,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.generation_evidence import (
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
)
from mmaudit.models.openrouter import (
    OpenRouterClient,
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
    validate_candidate_registry_discovery,
)
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.budgets import BudgetManager, _issue_trusted_budget_recovery_scope
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus, CostLedgerSnapshot
from mmaudit.orchestration.scheduler_runtime import build_scheduler_cost_ledger_baseline
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.privacy_provenance import (
    PrivacySourceProvenanceObservation,
    prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source,
    prove_pinned_noncrediting_smoke_model_benchmark_source,
)

_LEDGER_CAP_USD = Decimal("250")


class AuthenticatedRunnerSmokeOpenRouterError(ValueError):
    """The one-shot smoke launch or its exact runtime evidence failed closed."""


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerSmokeRunPlan:
    """One candidate probe followed by one exact independent judge probe."""

    run_kind: CrossLineageAdjudicationRunKind
    judge_discovery_manifest: OpenRouterModelDiscoveryRunManifest
    judge_discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...]
    judge_registry: CandidateRegistry
    candidate_cost_tripwire_usd_per_attempt: Decimal
    judge_cost_tripwire_usd_per_attempt: Decimal

    @property
    def judge(self) -> CandidateModel:
        if len(self.judge_registry.candidates) != 1:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke run requires one exact singleton judge"
            )
        return self.judge_registry.candidates[0]


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerSmokeOpenRouterLaunch:
    """Already-loaded provider-free inputs for one non-resumable smoke process."""

    config: AuditConfig
    explicitly_allow_synthetic_egress: bool
    public_lineage_capability: VerifiedPublicModelLineage
    benchmark_suite: ModelBenchmarkSuite
    smoke_corpus: AuthenticatedRunnerSmokeCorpusBundle
    candidate_discovery_manifest: OpenRouterModelDiscoveryRunManifest
    candidate_discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...]
    candidate_registry: CandidateRegistry
    budget: BudgetManager
    usage: UsageLedger
    run_plans: tuple[AuthenticatedRunnerSmokeRunPlan, ...]

    def __reduce__(self) -> Never:
        raise TypeError("authenticated runner smoke launch cannot be serialized")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("authenticated runner smoke launch cannot be serialized")


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerSmokePreflightInventory:
    """Provider-free exact admission; judge costs remain deliberately pending."""

    run_count: int
    case_count: int
    logical_request_count: int
    maximum_attempts_per_logical_request: int
    maximum_provider_attempt_count: int
    generation_refetch_count: int
    effective_config_sha256: str
    initial_spent_usd: Decimal
    operator_interval_tripwire_usd: Decimal
    operator_final_spent_tripwire_usd: Decimal
    candidate_cost_plans: tuple[AuthenticatedRunnerSmokeCostPlan, ...]
    candidate_derived_interval_cost_cap_usd: Decimal
    candidate_derived_final_spent_cap_usd: Decimal
    judge_cost_admission_status: str = "PENDING_REAL_CANDIDATE_OUTPUTS"


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerSmokeOpenRouterResult:
    """Final durable smoke bundle plus its exact provider-free inventory."""

    inventory: AuthenticatedRunnerSmokePreflightInventory
    bundle: AuthenticatedRunnerSmokeEvidenceBundle


@dataclass(frozen=True, slots=True)
class _PreparedSmokeRun:
    plan: AuthenticatedRunnerSmokeRunPlan
    candidate_cost_plan: AuthenticatedRunnerSmokeCostPlan
    candidate_report: NoncreditingModelBenchmarkSmokeReport
    candidate_generation_refetch: OpenRouterGenerationEvidence
    prepared_adjudication: CrossLineageAdjudicationPreparedRun


class _SmokeOpenRouterAdapter:
    __slots__ = ("_closed", "_judge_clients", "_launch", "_secrets")

    def __init__(
        self,
        *,
        launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
        secrets: OperatorSecrets,
    ) -> None:
        self._launch = launch
        self._secrets = secrets
        self._judge_clients: dict[CrossLineageAdjudicationRunKind, OpenRouterClient] = {}
        self._closed = False

    async def candidate(
        self,
        *,
        plan: AuthenticatedRunnerSmokeRunPlan,
        cost_plan: AuthenticatedRunnerSmokeCostPlan,
    ) -> tuple[NoncreditingModelBenchmarkSmokeReport, OpenRouterGenerationEvidence]:
        self._require_open()
        launch = self._launch
        candidate = launch.candidate_registry.candidates[0]
        target = ModelBenchmarkTarget(
            model_id=candidate.exact_model_id,
            root_lineage=candidate.root_lineage,
        )
        client = self._new_candidate_client(candidate)
        try:
            await _refresh_and_register_exact_route(
                client=client,
                config=launch.config,
                model=candidate,
                evidence=launch.candidate_discovery_evidence[0],
                manifest=launch.candidate_discovery_manifest,
            )
            report = await execute_noncrediting_model_benchmark_smoke(
                suite=launch.benchmark_suite,
                selected_case=launch.smoke_corpus.case,
                selected_ground_truth=launch.smoke_corpus.ground_truth_case,
                selection_sha256=launch.smoke_corpus.bundle_sha256,
                target=target,
                client=client,
                run_kind=plan.run_kind.value,
                expected_request_cost_preview=cost_plan.request_preview,
            )
            request = _generation_request(
                report_sha256=report.report_sha256,
                case_id=launch.smoke_corpus.case.case_id,
                model=candidate,
                usage=report.result.usage_record,
            )
            verification = await client.create_trusted_generation_verification((request,))
            refetch = verification.attestation_for(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                usage_record=request.usage_record,
                expected_provider_name=request.expected_provider_name,
            )
            return report, refetch
        finally:
            await client.close()

    async def prepare_judges(self, prepared: tuple[_PreparedSmokeRun, ...]) -> None:
        self._require_open()
        if self._judge_clients or len(prepared) != 2:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke judge routes must be prepared together exactly once"
            )
        clients: dict[CrossLineageAdjudicationRunKind, OpenRouterClient] = {}
        try:
            for item in prepared:
                judge = item.plan.judge
                client = self._new_judge_client(
                    judge=judge,
                    candidate_report=item.candidate_report,
                    prepared=item.prepared_adjudication,
                )
                clients[item.plan.run_kind] = client
                await _refresh_and_register_exact_route(
                    client=client,
                    config=self._launch.config,
                    model=judge,
                    evidence=item.plan.judge_discovery_evidence[0],
                    manifest=item.plan.judge_discovery_manifest,
                )
        except BaseException:
            for client in clients.values():
                await client.close()
            raise
        if len(clients) != 2:
            for client in clients.values():
                await client.close()
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke judge route preparation did not retain both exact routes"
            )
        self._judge_clients.update(clients)

    async def judge(
        self,
        *,
        prepared: _PreparedSmokeRun,
        cost_plan: AuthenticatedRunnerSmokeCostPlan,
    ) -> tuple[CrossLineageAdjudicationReport, OpenRouterGenerationEvidence]:
        self._require_open()
        try:
            client = self._judge_clients.pop(prepared.plan.run_kind)
        except KeyError:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke judge execution lacks its pre-admitted live route"
            ) from None
        try:
            results = await execute_noncrediting_cross_lineage_adjudication_smoke_requests(
                client=client,
                prepared=prepared.prepared_adjudication,
                expected_request_cost_previews=(cost_plan.request_preview,),
            )
            report = build_cross_lineage_adjudication_report(
                prepared=prepared.prepared_adjudication,
                results=results,
            )
            requests = adjudication_generation_verification_requests(
                report=report,
                judge=prepared.plan.judge,
            )
            if len(requests) != 1:
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "smoke judge report produced a different generation inventory"
                )
            request = requests[0]
            verification = await client.create_trusted_generation_verification(requests)
            refetch = verification.attestation_for(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                usage_record=request.usage_record,
                expected_provider_name=request.expected_provider_name,
            )
            return report, refetch
        finally:
            await client.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        clients = tuple(self._judge_clients.values())
        self._judge_clients.clear()
        for client in clients:
            try:
                await client.close()
            except BaseException:
                client.clear_credentials()
        self._secrets.clear()

    def _new_candidate_client(self, model: CandidateModel) -> OpenRouterClient:
        now = datetime.now(UTC).replace(microsecond=0)
        source = prove_pinned_noncrediting_smoke_model_benchmark_source(
            self._launch.smoke_corpus,
            now=now,
        )
        return self._new_client(model=model, source=source, now=now)

    def _new_judge_client(
        self,
        *,
        judge: CandidateModel,
        candidate_report: NoncreditingModelBenchmarkSmokeReport,
        prepared: CrossLineageAdjudicationPreparedRun,
    ) -> OpenRouterClient:
        now = datetime.now(UTC).replace(microsecond=0)
        source = prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source(
            self._launch.smoke_corpus,
            candidate_report.result,
            prepared,
            now=now,
        )
        return self._new_client(model=judge, source=source, now=now)

    def _new_client(
        self,
        *,
        model: CandidateModel,
        source: PrivacySourceProvenanceObservation,
        now: datetime,
    ) -> OpenRouterClient:
        evidence = source.evidence
        policy = resolve_effective_privacy_policy(
            profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
            require_zdr=True,
            consent_observation=None,
            source_sha256=evidence.source_sha256,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
            source_provenance_observation=source,
            configured_model_ids=(model.exact_model_id,),
            configured_provider_endpoints=(model.approved_provider_endpoint,),
            requested_budget_usd=Decimal(str(self._launch.budget.total_usd)),
            now=now,
        )
        return OpenRouterClient(
            api_key=self._required_api_key(),
            execution=self._launch.config.execution,
            privacy=self._launch.config.privacy,
            token_budgets=self._launch.config.token_budgets,
            budget=self._launch.budget,
            usage=self._launch.usage,
            provider_policy=OpenRouterProviderPolicy(
                certification=True,
                only=(model.approved_provider_endpoint,),
                allow_fallbacks=False,
            ),
            reasoning_policy=build_reasoning_policy(self._launch.config),
            effective_privacy_policy=policy,
            source_provenance_observation=source,
        )

    def _required_api_key(self) -> str:
        if self._closed or self._secrets.cleared or not self._secrets.openrouter_api_key_present:
            raise AuthenticatedRunnerSmokeOpenRouterError("smoke OpenRouter credential is absent")
        key: str = self._secrets.openrouter_api_key
        if not key:
            raise AuthenticatedRunnerSmokeOpenRouterError("smoke OpenRouter credential is missing")
        return key

    def _require_open(self) -> None:
        if self._closed:
            raise AuthenticatedRunnerSmokeOpenRouterError("smoke OpenRouter adapter is closed")


def preflight_authenticated_runner_smoke_openrouter_launch(
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
) -> AuthenticatedRunnerSmokePreflightInventory:
    """Validate exact frozen inputs and candidate costs without secrets or provider access."""

    if type(launch) is not AuthenticatedRunnerSmokeOpenRouterLaunch:
        raise AuthenticatedRunnerSmokeOpenRouterError("smoke launch has the wrong exact type")
    config = launch.config
    suite = launch.benchmark_suite
    smoke = launch.smoke_corpus
    if (
        type(config) is not AuditConfig
        or type(suite) is not ModelBenchmarkSuite
        or type(smoke) is not AuthenticatedRunnerSmokeCorpusBundle
        or smoke.case.case_id != AUTHENTICATED_RUNNER_SMOKE_CASE_ID
        or len(suite.cases) != 24
        or {item.case_id: item for item in suite.cases}.get(smoke.case.case_id) != smoke.case
        or {item.case_id: item for item in suite.ground_truth.cases}.get(smoke.case.case_id)
        != smoke.ground_truth_case
        or suite.corpus_sha256 != smoke.manifest.parent.corpus_sha256
        or suite.ground_truth_sha256 != smoke.manifest.parent.ground_truth_sha256
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke corpus differs from one exact case in the frozen 24-case parent"
        )
    if launch.explicitly_allow_synthetic_egress is not True:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke launch requires explicit synthetic egress permission"
        )
    try:
        validate_candidate_benchmark_egress(
            config=config,
            benchmark_suite=suite,
            explicitly_allowed=True,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke launch differs from the exact synthetic benchmark egress policy"
        ) from None
    candidate = _require_singleton_registry(
        registry=launch.candidate_registry,
        manifest=launch.candidate_discovery_manifest,
        evidence=launch.candidate_discovery_evidence,
        label="candidate",
    )
    if (
        type(launch.run_plans) is not tuple
        or len(launch.run_plans) != 2
        or tuple(item.run_kind for item in launch.run_plans)
        != (
            CrossLineageAdjudicationRunKind.PRIMARY,
            CrossLineageAdjudicationRunKind.REPLAY,
        )
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke launch requires exact PRIMARY then REPLAY plans"
        )
    judges: list[CandidateModel] = []
    manifests = [launch.candidate_discovery_manifest.manifest_sha256]
    evidences = [launch.candidate_discovery_evidence[0].discovery_evidence_sha256]
    reasoning_control = build_reasoning_policy(config).control_for_request("model_benchmark")
    try:
        launch.candidate_discovery_evidence[0].require_compatible_reasoning_profile(
            reasoning_control
        )
    except EndpointSnapshotValidationError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke candidate reasoning profile is incompatible with frozen discovery"
        ) from None
    for plan in launch.run_plans:
        if type(plan) is not AuthenticatedRunnerSmokeRunPlan:
            raise AuthenticatedRunnerSmokeOpenRouterError("smoke plan has the wrong exact type")
        judge = _require_singleton_registry(
            registry=plan.judge_registry,
            manifest=plan.judge_discovery_manifest,
            evidence=plan.judge_discovery_evidence,
            label="judge",
        )
        try:
            plan.judge_discovery_evidence[0].require_compatible_reasoning_profile(reasoning_control)
        except EndpointSnapshotValidationError:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke judge reasoning profile is incompatible with frozen discovery"
            ) from None
        _positive_cost(plan.candidate_cost_tripwire_usd_per_attempt, label="candidate tripwire")
        _positive_cost(plan.judge_cost_tripwire_usd_per_attempt, label="judge tripwire")
        judges.append(judge)
        manifests.append(plan.judge_discovery_manifest.manifest_sha256)
        evidences.append(plan.judge_discovery_evidence[0].discovery_evidence_sha256)
    if (
        len({candidate.exact_model_id, *(item.exact_model_id for item in judges)}) != 3
        or len(set(manifests)) != 3
        or len(set(evidences)) != 3
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke roles require three models and three distinct discovery bundles"
        )
    _require_three_distinct_roots(
        launch.public_lineage_capability,
        candidate=candidate,
        judges=(judges[0], judges[1]),
    )
    budget = launch.budget
    usage = launch.usage
    ledger = budget.atomic_ledger
    if (
        type(budget) is not BudgetManager
        or type(usage) is not UsageLedger
        or type(ledger) is not AtomicCostLedger
        or ledger.cap_usd != _LEDGER_CAP_USD
        or Decimal(str(budget.total_usd)) != _LEDGER_CAP_USD
        or budget.require_endpoint_cost_bound is not True
        or usage.records
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke launch requires an empty usage ledger and exact 250 USD atomic ledger"
        )
    initial = ledger.snapshot()
    _require_clean_snapshot(initial, final=False)
    maximum_attempts = config.execution.max_model_retries + 1
    if (
        maximum_attempts != 2
        or 4 * maximum_attempts != smoke.verdict_policy.maximum_provider_attempts
        or config.execution.max_requests_per_agent < 4 * maximum_attempts
        or budget.max_requests_per_agent < 4 * maximum_attempts
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke request cap is below its retry inventory"
        )
    candidate_cost_plans = tuple(
        _candidate_cost_plan(
            config=config,
            smoke=smoke,
            candidate=candidate,
            manifest=launch.candidate_discovery_manifest,
            evidence=launch.candidate_discovery_evidence[0],
            run_kind=plan.run_kind,
        )
        for plan in launch.run_plans
    )
    for cost_plan, run_plan in zip(candidate_cost_plans, launch.run_plans, strict=True):
        if Decimal(cost_plan.maximum_cost_usd_per_attempt_exact) > (
            run_plan.candidate_cost_tripwire_usd_per_attempt
        ):
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke candidate exact request cost exceeds its operator tripwire"
            )
    with localcontext() as context:
        context.prec = 160
        candidate_cap = sum(
            (Decimal(item.maximum_cost_usd_all_attempts_exact) for item in candidate_cost_plans),
            start=Decimal(0),
        )
        candidate_final = initial.spent_usd + candidate_cap
        operator_interval = Decimal(maximum_attempts) * sum(
            (
                plan.candidate_cost_tripwire_usd_per_attempt
                + plan.judge_cost_tripwire_usd_per_attempt
                for plan in launch.run_plans
            ),
            start=Decimal(0),
        )
        operator_final = initial.spent_usd + operator_interval
    if candidate_final >= _LEDGER_CAP_USD or operator_final >= _LEDGER_CAP_USD:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke exact candidate admission or operator tripwire reaches 250 USD"
        )
    return AuthenticatedRunnerSmokePreflightInventory(
        run_count=2,
        case_count=1,
        logical_request_count=4,
        maximum_attempts_per_logical_request=maximum_attempts,
        maximum_provider_attempt_count=4 * maximum_attempts,
        generation_refetch_count=4,
        effective_config_sha256=config.stable_hash(),
        initial_spent_usd=initial.spent_usd,
        operator_interval_tripwire_usd=operator_interval,
        operator_final_spent_tripwire_usd=operator_final,
        candidate_cost_plans=candidate_cost_plans,
        candidate_derived_interval_cost_cap_usd=candidate_cap,
        candidate_derived_final_spent_cap_usd=candidate_final,
    )


async def execute_authenticated_runner_smoke_openrouter(
    *,
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
    operator_secrets: OperatorSecrets,
) -> AuthenticatedRunnerSmokeOpenRouterResult:
    """Execute candidates first, admit both judges, and seal no authority."""

    if type(operator_secrets) is not OperatorSecrets:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke execution requires the existing operator secret holder"
        )
    inventory = preflight_authenticated_runner_smoke_openrouter_launch(launch)
    ledger = launch.budget.atomic_ledger
    if type(ledger) is not AtomicCostLedger:
        raise AuthenticatedRunnerSmokeOpenRouterError("smoke execution lacks its atomic ledger")
    await _adopt_ledger_baseline(
        budget=launch.budget,
        ledger=ledger,
        expected=ledger.snapshot(),
    )
    initial_snapshot = ledger.snapshot()
    interval = begin_cross_lineage_ledger_interval(ledger)
    adapter = _SmokeOpenRouterAdapter(launch=launch, secrets=operator_secrets)
    prepared_runs: list[_PreparedSmokeRun] = []
    final_runs: list[AuthenticatedRunnerSmokeRunEvidence] = []
    try:
        for plan, cost_plan in zip(
            launch.run_plans,
            inventory.candidate_cost_plans,
            strict=True,
        ):
            before_usage = tuple(launch.usage.records)
            before_ledger = ledger.snapshot()
            report, refetch = await adapter.candidate(plan=plan, cost_plan=cost_plan)
            after_usage = tuple(launch.usage.records)
            if after_usage[:-1] != before_usage or after_usage[-1:] != (
                report.result.usage_record,
            ):
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "smoke candidate callback changed usage custody"
                )
            candidate_usage = report.result.usage_record
            if candidate_usage is None:
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "smoke candidate callback lacks its exact usage"
                )
            _require_exact_smoke_callback_ledger_delta(
                before=before_ledger,
                after=ledger.snapshot(),
                records=(candidate_usage,),
                label="candidate",
            )
            prepared = prepare_noncrediting_cross_lineage_adjudication_smoke(
                public_lineage_capability=launch.public_lineage_capability,
                suite=launch.benchmark_suite,
                selected_case=launch.smoke_corpus.case,
                selected_ground_truth=launch.smoke_corpus.ground_truth_case,
                selection_sha256=launch.smoke_corpus.bundle_sha256,
                candidate_report=report,
                judge=plan.judge,
                run_kind=plan.run_kind,
            )
            prepared_runs.append(
                _PreparedSmokeRun(
                    plan=plan,
                    candidate_cost_plan=cost_plan,
                    candidate_report=report,
                    candidate_generation_refetch=refetch,
                    prepared_adjudication=prepared,
                )
            )
        before_prepare_usage = tuple(launch.usage.records)
        before_prepare_ledger = ledger.snapshot()
        await adapter.prepare_judges(tuple(prepared_runs))
        if (
            tuple(launch.usage.records) != before_prepare_usage
            or ledger.snapshot() != before_prepare_ledger
        ):
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke judge route preparation changed cost custody"
            )
        judge_cost_plans = tuple(
            _judge_cost_plan(config=launch.config, prepared=item) for item in prepared_runs
        )
        _require_aggregate_judge_admission(
            ledger=ledger,
            initial_snapshot=initial_snapshot,
            prepared=tuple(prepared_runs),
            cost_plans=judge_cost_plans,
        )
        for prepared_item, judge_cost_plan in zip(prepared_runs, judge_cost_plans, strict=True):
            before_usage = tuple(launch.usage.records)
            before_ledger = ledger.snapshot()
            adjudication_report, refetch = await adapter.judge(
                prepared=prepared_item,
                cost_plan=judge_cost_plan,
            )
            after_usage = tuple(launch.usage.records)
            judge_usage = adjudication_report.cases[0].usage_record
            if after_usage[:-1] != before_usage or after_usage[-1:] != (judge_usage,):
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "smoke judge callback changed usage custody"
                )
            if judge_usage is None:
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "smoke judge callback lacks its exact usage"
                )
            _require_exact_smoke_callback_ledger_delta(
                before=before_ledger,
                after=ledger.snapshot(),
                records=(judge_usage,),
                label="judge",
            )
            final_runs.append(
                seal_authenticated_runner_smoke_run_evidence(
                    run_kind=prepared_item.plan.run_kind,
                    candidate=launch.candidate_registry.candidates[0],
                    judge=prepared_item.plan.judge,
                    candidate_cost_plan=prepared_item.candidate_cost_plan,
                    candidate_report=prepared_item.candidate_report,
                    candidate_generation_refetch=(prepared_item.candidate_generation_refetch),
                    prepared_adjudication=prepared_item.prepared_adjudication,
                    judge_cost_plan=judge_cost_plan,
                    adjudication_report=adjudication_report,
                    judge_generation_refetch=refetch,
                )
            )
        request_ids = tuple(
            request_id
            for run in final_runs
            for usage in (
                run.candidate_report.result.usage_record,
                run.adjudication_report.cases[0].usage_record,
            )
            if usage is not None
            for request_id in _attempt_request_ids(usage)
        )
        closed = close_cross_lineage_ledger_interval(
            interval,
            expected_request_ids=request_ids,
        )
        view = _require_closed_cross_lineage_ledger_interval(closed)
        ledger_evidence = AuthenticatedCrossLineageLedgerIntervalEvidence.model_validate_json(
            view.evidence.model_dump_json(),
            strict=True,
        )
        bundle = seal_authenticated_runner_smoke_evidence_bundle(
            smoke_corpus_bundle_sha256=launch.smoke_corpus.bundle_sha256,
            parent_corpus_sha256=launch.smoke_corpus.manifest.parent.corpus_sha256,
            parent_ground_truth_sha256=launch.smoke_corpus.manifest.parent.ground_truth_sha256,
            effective_config_sha256=launch.config.stable_hash(),
            selected_case_id=launch.smoke_corpus.case.case_id,
            selected_case_count=1,
            parent_case_count=24,
            run_count=2,
            logical_request_count=4,
            maximum_provider_attempt_count=inventory.maximum_provider_attempt_count,
            generation_refetch_count=4,
            execution_sequence_request_ids=tuple(
                run.candidate_report.result.usage_record.request_id
                for run in final_runs
                if run.candidate_report.result.usage_record is not None
            )
            + tuple(run.adjudication_report.cases[0].usage_record.request_id for run in final_runs),
            runs=tuple(final_runs),
            closed_ledger_evidence=ledger_evidence,
        )
        return AuthenticatedRunnerSmokeOpenRouterResult(
            inventory=inventory,
            bundle=bundle,
        )
    finally:
        await adapter.close()


def _candidate_cost_plan(
    *,
    config: AuditConfig,
    smoke: AuthenticatedRunnerSmokeCorpusBundle,
    candidate: CandidateModel,
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: OpenRouterModelDiscoveryEvidence,
    run_kind: CrossLineageAdjudicationRunKind,
) -> AuthenticatedRunnerSmokeCostPlan:
    target = ModelBenchmarkTarget(
        model_id=candidate.exact_model_id,
        root_lineage=candidate.root_lineage,
    )
    descriptor = authenticated_runner_smoke_model_benchmark_request_descriptor(
        run_kind=run_kind.value,
        selection_sha256=smoke.bundle_sha256,
        case=smoke.case,
        target=target,
    )
    preview = preview_openrouter_structured_request_cost(
        execution=config.execution,
        privacy=config.privacy,
        token_budgets=config.token_budgets,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=(candidate.approved_provider_endpoint,),
            allow_fallbacks=False,
        ),
        reasoning_policy=build_reasoning_policy(config),
        discovery_manifest=manifest,
        discovery_evidence=evidence,
        role=descriptor.request_role,
        system_prompt=descriptor.system_prompt,
        user_prompt=descriptor.user_prompt,
        response_model=descriptor.response_model,
        schema_name=descriptor.schema_name,
        logical_request_id=descriptor.logical_request_id,
        context_package=None,
        maximum_attempts=config.execution.max_model_retries + 1,
    )
    validate_authenticated_runner_smoke_model_benchmark_cost_preview(
        descriptor=descriptor,
        expected_request_cost_preview=preview,
    )
    return build_authenticated_runner_smoke_cost_plan(
        run_kind=run_kind,
        stage="CANDIDATE",
        case_id=smoke.case.case_id,
        selection_sha256=smoke.bundle_sha256,
        request_preview=preview,
    )


def _judge_cost_plan(
    *,
    config: AuditConfig,
    prepared: _PreparedSmokeRun,
) -> AuthenticatedRunnerSmokeCostPlan:
    previews = cross_lineage_adjudication_smoke_request_cost_previews(
        config=config,
        prepared=prepared.prepared_adjudication,
        discovery_manifest=prepared.plan.judge_discovery_manifest,
        discovery_evidence=prepared.plan.judge_discovery_evidence[0],
        maximum_attempts=config.execution.max_model_retries + 1,
    )
    if len(previews) != 1:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke judge cost derivation returned a different request inventory"
        )
    return build_authenticated_runner_smoke_cost_plan(
        run_kind=prepared.plan.run_kind,
        stage="JUDGE",
        case_id=prepared.candidate_cost_plan.case_id,
        selection_sha256=prepared.candidate_cost_plan.selection_sha256,
        request_preview=previews[0],
    )


def _require_aggregate_judge_admission(
    *,
    ledger: AtomicCostLedger,
    initial_snapshot: CostLedgerSnapshot,
    prepared: tuple[_PreparedSmokeRun, ...],
    cost_plans: tuple[AuthenticatedRunnerSmokeCostPlan, ...],
) -> None:
    if len(prepared) != 2 or len(cost_plans) != 2:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke judge admission requires both exact prepared runs"
        )
    snapshot = ledger.snapshot()
    _require_clean_snapshot(snapshot, final=False)
    expected_candidate_records = tuple(
        item.candidate_report.result.usage_record for item in prepared
    )
    if any(item is None for item in expected_candidate_records):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke aggregate judge admission lacks exact candidate usages"
        )
    _require_exact_smoke_callback_ledger_delta(
        before=initial_snapshot,
        after=snapshot,
        records=tuple(item for item in expected_candidate_records if item is not None),
        label="candidate aggregate",
    )
    with localcontext() as context:
        context.prec = 160
        maximum = sum(
            (Decimal(item.maximum_cost_usd_all_attempts_exact) for item in cost_plans),
            start=Decimal(0),
        )
        final = snapshot.spent_usd + maximum
    for item, cost_plan in zip(prepared, cost_plans, strict=True):
        if Decimal(cost_plan.maximum_cost_usd_per_attempt_exact) > (
            item.plan.judge_cost_tripwire_usd_per_attempt
        ):
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke judge exact request cost exceeds its operator tripwire"
            )
    if final >= _LEDGER_CAP_USD:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke aggregate exact judge admission does not remain below 250 USD"
        )


def _require_singleton_registry(
    *,
    registry: CandidateRegistry,
    manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    label: str,
) -> CandidateModel:
    if (
        type(registry) is not CandidateRegistry
        or type(manifest) is not OpenRouterModelDiscoveryRunManifest
        or type(evidence) is not tuple
        or len(registry.candidates) != 1
        or len(evidence) != 1
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {label} requires one exact registry and discovery"
        )
    try:
        validate_candidate_registry_discovery(
            registry=registry,
            run_manifest=manifest,
            evidence=evidence,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {label} registry differs from fresh discovery"
        ) from None
    model = registry.candidates[0]
    discovery = evidence[0]
    if (
        model.exact_model_id != discovery.exact_model_id
        or model.canonical_model_slug != discovery.canonical_slug
        or model.approved_provider_endpoint != discovery.approved_provider_endpoint
        or model.approved_provider_name != discovery.provider_name
        or model.discovery_evidence_sha256 != discovery.discovery_evidence_sha256
        or model.endpoint_snapshot_sha256 != discovery.endpoint_snapshot_sha256
        or model.model_metadata_snapshot_sha256 != discovery.model_metadata_snapshot_sha256
        or model.pricing_snapshot_sha256 != discovery.pricing_snapshot_sha256
        or model.output_capability_sha256 != discovery.output_capability_sha256
        or model.structured_output_mode != discovery.structured_output_mode
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {label} identity differs from fresh discovery"
        )
    return model


def _require_three_distinct_roots(
    capability: VerifiedPublicModelLineage,
    *,
    candidate: CandidateModel,
    judges: tuple[CandidateModel, CandidateModel],
) -> None:
    if type(capability) is not VerifiedPublicModelLineage:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke public lineage capability has the wrong exact type"
        )
    pairs = ((candidate, judges[0]), (candidate, judges[1]), (judges[0], judges[1]))
    try:
        projections = tuple(
            require_independent_public_model_lineage(
                capability,
                left.exact_model_id,
                right.exact_model_id,
            )
            for left, right in pairs
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke public lineage does not prove three distinct roots"
        ) from None
    expected = tuple(
        (
            left.exact_model_id,
            left.root_lineage,
            right.exact_model_id,
            right.root_lineage,
        )
        for left, right in pairs
    )
    if any(
        type(item) is not VerifiedIndependentPublicModelLineageProjection
        or item.independent is not True
        or (
            item.left_exact_model_id,
            item.left_root_lineage,
            item.right_exact_model_id,
            item.right_root_lineage,
        )
        != expected[index]
        for index, item in enumerate(projections)
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke public lineage returned a non-independent projection"
        )


async def _refresh_and_register_exact_route(
    *,
    client: OpenRouterClient,
    config: AuditConfig,
    model: CandidateModel,
    evidence: OpenRouterModelDiscoveryEvidence,
    manifest: OpenRouterModelDiscoveryRunManifest,
) -> None:
    expected_policy = OpenRouterProviderPolicy(
        certification=True,
        only=(model.approved_provider_endpoint,),
        allow_fallbacks=False,
    )
    if client.provider_policy != expected_policy:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke client differs from its singleton route policy"
        )
    await client.validate_authentication()
    models_payload = await client.get_certification_model_metadata()
    canonical_slug = openrouter_catalog_canonical_slug(
        exact_model_id=model.exact_model_id,
        models_payload=models_payload,
    )
    single_model_payload = await client.get_model_metadata(model.exact_model_id)
    endpoint_payload = await client.get_model_endpoint_metadata(model.exact_model_id)
    zdr_payload = await client.list_zdr_endpoints()
    try:
        current_endpoint = validate_openrouter_endpoint_snapshot(
            exact_model_id=model.exact_model_id,
            configured_provider_endpoints=(model.approved_provider_endpoint,),
            provider_policy_mode="only",
            endpoint_payload=endpoint_payload,
            require_zdr=config.privacy.require_zdr,
            zdr_payload=zdr_payload,
            reasoning_requested=False,
            structured_output_required=False,
        )
        current_model = validate_openrouter_model_discovery(
            exact_model_id=model.exact_model_id,
            models_payload=models_payload,
            single_model_payload=single_model_payload,
            endpoint_snapshot=current_endpoint,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke current model, route, ZDR, pricing, or output metadata is incompatible"
        ) from None
    frozen_model = OpenRouterModelDiscoveryPayload.model_validate(
        evidence.model_dump(mode="json", exclude={"provenance", "discovery_evidence_sha256"})
    )
    try:
        current_model.require_compatible_reasoning_profile(
            build_reasoning_policy(config).control_for_request("model_benchmark")
        )
    except ValueError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke current reasoning metadata is incompatible with launch policy"
        ) from None
    if (
        canonical_slug != evidence.canonical_slug
        or current_endpoint != evidence.endpoint_snapshot
        or current_model != frozen_model
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke current discovery differs from its frozen exact route"
        )
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)


def _generation_request(
    *,
    report_sha256: str,
    case_id: str,
    model: CandidateModel,
    usage: UsageRecord | None,
) -> GenerationVerificationRequest:
    if usage is None:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke candidate report lacks exact generation usage"
        )
    return GenerationVerificationRequest(
        benchmark_report_sha256=report_sha256,
        case_id=case_id,
        exact_model_id=model.exact_model_id,
        canonical_model_id=model.canonical_model_slug,
        catalog_identity_binding_sha256=_canonical_identity_sha256(model),
        discovery_evidence_sha256=model.discovery_evidence_sha256,
        expected_provider_name=model.approved_provider_name,
        usage_record=usage,
    )


def _canonical_identity_sha256(model: CandidateModel) -> str:
    import hashlib
    import json

    return hashlib.sha256(
        json.dumps(
            {"canonical_slug": model.canonical_model_slug, "id": model.exact_model_id},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _attempt_request_ids(usage: object) -> tuple[str, ...]:
    request_id = getattr(usage, "request_id", None)
    attempts = getattr(usage, "attempts", None)
    if type(request_id) is not str or type(attempts) is not int or attempts < 1:
        raise AuthenticatedRunnerSmokeOpenRouterError("smoke usage retry identity is invalid")
    return tuple(
        request_id if index == 1 else f"{request_id}:attempt:{index}"
        for index in range(1, attempts + 1)
    )


def _require_exact_smoke_callback_ledger_delta(
    *,
    before: CostLedgerSnapshot,
    after: CostLedgerSnapshot,
    records: tuple[UsageRecord, ...],
    label: str,
) -> None:
    """Require one smoke callback to append only exact known-cost attempts."""

    expected_ids = tuple(
        request_id for record in records for request_id in _attempt_request_ids(record)
    )
    before_by_id = {entry.request_id: entry for entry in before.entries}
    after_by_id = {entry.request_id: entry for entry in after.entries}
    new_ids = tuple(sorted(set(after_by_id) - set(before_by_id)))
    if (
        type(before) is not CostLedgerSnapshot
        or type(after) is not CostLedgerSnapshot
        or type(records) is not tuple
        or not records
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
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {label} ledger delta is not exact terminal known-cost reconciliation"
        )
    new_entries = {request_id: after_by_id[request_id] for request_id in expected_ids}
    if any(
        entry.status is not CostEntryStatus.RECONCILED
        or entry.actual_cost_usd is None
        or entry.accounted_cost_usd != entry.actual_cost_usd
        or entry.actual_cost_usd > entry.reserved_usd
        for entry in new_entries.values()
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {label} ledger delta is not exact terminal known-cost reconciliation"
        )
    with localcontext() as context:
        context.prec = 160
        expected_spend = Decimal(0)
        for record in records:
            accounted = record.accounted_cost_usd_exact
            if accounted is None:
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    f"smoke {label} ledger delta is not exact terminal known-cost reconciliation"
                )
            actual = sum(
                (
                    new_entries[request_id].accounted_cost_usd
                    for request_id in _attempt_request_ids(record)
                ),
                start=Decimal(0),
            )
            if actual != Decimal(accounted):
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    f"smoke {label} ledger delta is not exact terminal known-cost reconciliation"
                )
            expected_spend += actual
        if after.spent_usd - before.spent_usd != expected_spend:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                f"smoke {label} ledger delta is not exact terminal known-cost reconciliation"
            )


async def _adopt_ledger_baseline(
    *,
    budget: BudgetManager,
    ledger: AtomicCostLedger,
    expected: CostLedgerSnapshot,
) -> None:
    if ledger.snapshot() != expected or budget.atomic_ledger is not ledger:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke ledger changed before baseline adoption"
        )
    if not expected.entries:
        if budget.recovery_required:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "empty smoke ledger unexpectedly requires recovery"
            )
        return
    if not budget.recovery_required:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "nonempty smoke ledger lacks baseline recovery custody"
        )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    scope = _issue_trusted_budget_recovery_scope((), cost_ledger_baseline=baseline)
    try:
        await budget.restore_recovered_usage((), recovery_scope=scope)
    except (TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke budget could not adopt the exact ledger baseline"
        ) from None
    if budget.recovery_required or ledger.snapshot() != expected:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke ledger changed during baseline adoption"
        )


def _require_clean_snapshot(snapshot: CostLedgerSnapshot, *, final: bool) -> None:
    if (
        type(snapshot) is not CostLedgerSnapshot
        or snapshot.cap_usd != _LEDGER_CAP_USD
        or snapshot.active_reserved_usd != 0
        or snapshot.over_cap
        or snapshot.has_reservation_overrun
        or any(
            item.status in {CostEntryStatus.RESERVED, CostEntryStatus.RESERVATION_OVERRUN}
            for item in snapshot.entries
        )
        or (final and snapshot.spent_usd >= _LEDGER_CAP_USD)
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke requires a terminal non-overrun exact-250-USD ledger"
        )


def _positive_cost(value: Decimal, *, label: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value <= 0:
        raise AuthenticatedRunnerSmokeOpenRouterError(f"smoke {label} must be positive")
    return value


__all__ = [
    "AuthenticatedRunnerSmokeOpenRouterError",
    "AuthenticatedRunnerSmokeOpenRouterLaunch",
    "AuthenticatedRunnerSmokeOpenRouterResult",
    "AuthenticatedRunnerSmokePreflightInventory",
    "AuthenticatedRunnerSmokeRunPlan",
    "execute_authenticated_runner_smoke_openrouter",
    "preflight_authenticated_runner_smoke_openrouter_launch",
]
