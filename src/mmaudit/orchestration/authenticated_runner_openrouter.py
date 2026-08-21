"""Launch-ready OpenRouter wiring for the authenticated cross-lineage runner.

This module is deliberately an in-process adapter, not a resumable campaign
format.  The opaque lineage, ground-truth, generation, runner, and AUTHSEAL
capabilities must remain in one Python process.  The only durable authority-like
output is the explicitly non-authorizing runner evidence returned alongside the
non-authorizing AUTHSEAL comparison inputs.

Operator input contract
-----------------------
The caller must load exactly one :class:`~mmaudit.operator_secrets.OperatorSecrets`
holder with :func:`~mmaudit.operator_secrets.load_operator_secrets`, construct one
``AuthenticatedRunnerOpenRouterLaunch`` from already verified frozen inputs, and
await ``execute_authenticated_openrouter_runner`` in that same process.  The launch
must use a shared endpoint-bound ``BudgetManager``/``UsageLedger`` pair backed by
the exact 250 USD ``AtomicCostLedger``.  No callback, credential, or opaque
capability is accepted from a serialized campaign artifact.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Never, SupportsIndex, cast

import mmaudit.models.authenticated_runner as _runner_authority_module
import mmaudit.models.authenticated_runner_execution as _runner_execution_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationCaseResult,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
    cross_lineage_adjudication_source_sha256,
    execute_cross_lineage_adjudication_requests,
)
from mmaudit.benchmark.model_portfolio import CandidateBenchmarkCampaignJournal
from mmaudit.benchmark.models import ModelBenchmarkReport, ModelBenchmarkSuite
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerError,
    AuthenticatedCrossLineageRunnerEvidence,
    CrossLineageRunnerRunCustody,
    VerifiedCrossLineageRunnerCustody,
    require_verified_cross_lineage_runner_custody,
    revoke_verified_cross_lineage_runner_custody,
)
from mmaudit.models.authenticated_runner_cost_plan import (
    AuthenticatedRunnerCostPlanStage,
    AuthenticatedRunnerStagedCostPlan,
)
from mmaudit.models.authenticated_runner_execution import (
    AuthenticatedRunnerExecutedRun,
    AuthenticatedRunnerExecutionInventory,
    AuthenticatedRunnerExecutionResult,
    AuthenticatedRunnerGenerationSubject,
    AuthenticatedRunnerRunPlan,
    CandidateCampaignExecutor,
    CrossLineageJudgeExecutor,
    JudgeRoutePreparationExecutor,
    RunnerGenerationVerificationExecutor,
    execute_authenticated_cross_lineage_runner,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkExecutionResult,
    CandidateBenchmarkPreDispatchError,
    run_candidate_registry_benchmarks,
)
from mmaudit.models.discovery import (
    ModelDiscoveryValidationError,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    openrouter_catalog_canonical_slug,
    require_openrouter_live_discovery_equivalence,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealCollisionMap,
    EvidenceSealDecisionProjection,
    build_authenticated_evidence_seal_runner_inputs,
)
from mmaudit.models.generation_evidence import (
    GenerationVerificationRequest,
    TrustedGenerationVerification,
)
from mmaudit.models.ground_truth_authority import (
    FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
    FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
    FROZEN_GROUND_TRUTH_SOURCE_REVISION,
    VerifiedFrozenGroundTruth,
    VerifiedFrozenGroundTruthProjection,
)
from mmaudit.models.openrouter import OpenRouterClient, OpenRouterProviderPolicy
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.public_lineage_authority import VerifiedPublicModelLineage
from mmaudit.models.qualification import CandidateModel, CandidateRegistry, QualificationPolicy
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.privacy_provenance import (
    prove_release_pinned_cross_lineage_adjudication_source,
    prove_release_pinned_model_benchmark_source,
)

AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_CONTRACT_VERSION = "2.0"
AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_FIELDS = (
    "config",
    "explicitly_allow_synthetic_egress",
    "public_lineage_capability",
    "ground_truth_capability",
    "benchmark_suite",
    "candidate_discovery_manifest",
    "candidate_discovery_evidence",
    "candidate_registry",
    "qualification_policy",
    "budget",
    "usage",
    "run_plans",
)
_TRUSTED_GROUND_TRUTH_REQUIRE_FOR = VerifiedFrozenGroundTruth.require_for
_TRUSTED_EXECUTION_PREFLIGHT = _runner_execution_module._preflight_execution
_TRUSTED_REQUIRE_RUNNER_CUSTODY = require_verified_cross_lineage_runner_custody
_TRUSTED_REVOKE_RUNNER_CUSTODY = revoke_verified_cross_lineage_runner_custody
_REVOKED_RUNNER_CUSTODY_DETAIL = (
    "verified cross-lineage runner custody is absent, mismatched, or revoked"
)


class AuthenticatedRunnerOpenRouterError(ValueError):
    """The concrete OpenRouter runner adapter failed closed across its authority lifecycle."""


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerOpenRouterLaunch:
    """Exact already-loaded inputs for one non-resumable same-process launch."""

    config: AuditConfig
    explicitly_allow_synthetic_egress: bool
    public_lineage_capability: VerifiedPublicModelLineage
    ground_truth_capability: VerifiedFrozenGroundTruth
    benchmark_suite: ModelBenchmarkSuite
    candidate_discovery_manifest: OpenRouterModelDiscoveryRunManifest
    candidate_discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...]
    candidate_registry: CandidateRegistry
    qualification_policy: QualificationPolicy
    budget: BudgetManager
    usage: UsageLedger
    run_plans: tuple[AuthenticatedRunnerRunPlan, ...]

    def __reduce__(self) -> Never:
        raise TypeError("authenticated OpenRouter runner launch cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("authenticated OpenRouter runner launch cannot be serialized")


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerOpenRouterRunSnapshot:
    """Durable report material copied free of PID-local capability custody."""

    candidate_cost_plan: AuthenticatedRunnerStagedCostPlan
    judge_cost_plan: AuthenticatedRunnerStagedCostPlan
    candidate_report: ModelBenchmarkReport
    prepared_adjudication: CrossLineageAdjudicationPreparedRun
    adjudication_report: CrossLineageAdjudicationReport

    def __reduce__(self) -> Never:
        raise TypeError("authenticated OpenRouter run snapshot cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("authenticated OpenRouter run snapshot cannot be serialized")


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerOpenRouterExecutionSnapshot:
    """Post-revocation execution data with no retained runner authority fields."""

    inventory: AuthenticatedRunnerExecutionInventory
    runs: tuple[AuthenticatedRunnerOpenRouterRunSnapshot, ...]

    def __reduce__(self) -> Never:
        raise TypeError("authenticated OpenRouter execution snapshot cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("authenticated OpenRouter execution snapshot cannot be serialized")


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerOpenRouterResult:
    """Sanitized execution data plus durable, explicitly non-authorizing outputs."""

    execution: AuthenticatedRunnerOpenRouterExecutionSnapshot
    runner_evidence: AuthenticatedCrossLineageRunnerEvidence
    authseal_collision_map: EvidenceSealCollisionMap | None
    authseal_decision_projections: tuple[EvidenceSealDecisionProjection, ...]
    authseal_rejection_kind: str | None

    def __reduce__(self) -> Never:
        raise TypeError("authenticated OpenRouter runner result cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("authenticated OpenRouter runner result cannot be serialized")


_TRUSTED_RUN_SNAPSHOT_TYPE = AuthenticatedRunnerOpenRouterRunSnapshot
_TRUSTED_EXECUTION_SNAPSHOT_TYPE = AuthenticatedRunnerOpenRouterExecutionSnapshot


def _build_detached_durable_run_snapshot() -> Callable[
    [AuthenticatedRunnerExecutedRun], AuthenticatedRunnerOpenRouterRunSnapshot
]:
    """Capture the exact copy surface outside ordinary module-symbol retargeting."""

    trusted_error = AuthenticatedRunnerOpenRouterError
    trusted_executed_run_type = AuthenticatedRunnerExecutedRun
    trusted_custody_type = CrossLineageRunnerRunCustody
    trusted_model_report_type = ModelBenchmarkReport
    trusted_cost_plan_type = AuthenticatedRunnerStagedCostPlan
    trusted_prepared_type = CrossLineageAdjudicationPreparedRun
    trusted_adjudication_report_type = CrossLineageAdjudicationReport
    trusted_snapshot_type = AuthenticatedRunnerOpenRouterRunSnapshot
    trusted_getattribute = object.__getattribute__
    trusted_model_dump = ModelBenchmarkReport.model_dump_json
    trusted_model_validate = ModelBenchmarkReport.model_validate_json
    trusted_cost_plan_dump = AuthenticatedRunnerStagedCostPlan.model_dump_json
    trusted_cost_plan_validate = AuthenticatedRunnerStagedCostPlan.model_validate_json
    trusted_prepared_dump = CrossLineageAdjudicationPreparedRun.model_dump_json
    trusted_prepared_validate = CrossLineageAdjudicationPreparedRun.model_validate_json
    trusted_adjudication_dump = CrossLineageAdjudicationReport.model_dump_json
    trusted_adjudication_validate = CrossLineageAdjudicationReport.model_validate_json

    def detached(
        item: AuthenticatedRunnerExecutedRun,
    ) -> AuthenticatedRunnerOpenRouterRunSnapshot:
        if type(item) is not trusted_executed_run_type:
            raise trusted_error("authenticated runner retained run has the wrong exact type")
        custody = trusted_getattribute(item, "custody")
        if type(custody) is not trusted_custody_type:
            raise trusted_error("authenticated runner retained custody has the wrong exact type")
        candidate = trusted_getattribute(custody, "candidate_report")
        candidate_cost_plan = trusted_getattribute(item, "candidate_cost_plan")
        judge_cost_plan = trusted_getattribute(item, "judge_cost_plan")
        prepared = trusted_getattribute(item, "prepared_adjudication")
        adjudication = trusted_getattribute(custody, "adjudication_report")
        if (
            type(candidate_cost_plan) is not trusted_cost_plan_type
            or type(judge_cost_plan) is not trusted_cost_plan_type
            or type(candidate) is not trusted_model_report_type
            or type(prepared) is not trusted_prepared_type
            or type(adjudication) is not trusted_adjudication_report_type
        ):
            raise trusted_error(
                "authenticated runner retained durable reports have the wrong exact type"
            )
        candidate_cost_raw = trusted_cost_plan_dump(candidate_cost_plan)
        judge_cost_raw = trusted_cost_plan_dump(judge_cost_plan)
        candidate_raw = trusted_model_dump(candidate)
        prepared_raw = trusted_prepared_dump(prepared)
        adjudication_raw = trusted_adjudication_dump(adjudication)
        candidate_cost_copy = trusted_cost_plan_validate(candidate_cost_raw, strict=True)
        judge_cost_copy = trusted_cost_plan_validate(judge_cost_raw, strict=True)
        candidate_copy = trusted_model_validate(candidate_raw)
        prepared_copy = trusted_prepared_validate(prepared_raw)
        adjudication_copy = trusted_adjudication_validate(adjudication_raw)
        if (
            trusted_cost_plan_dump(candidate_cost_copy) != candidate_cost_raw
            or trusted_cost_plan_dump(judge_cost_copy) != judge_cost_raw
            or trusted_model_dump(candidate_copy) != candidate_raw
            or trusted_prepared_dump(prepared_copy) != prepared_raw
            or trusted_adjudication_dump(adjudication_copy) != adjudication_raw
        ):
            raise trusted_error(
                "authenticated runner durable report copy changed retained evidence"
            )
        return trusted_snapshot_type(
            candidate_cost_plan=candidate_cost_copy,
            judge_cost_plan=judge_cost_copy,
            candidate_report=candidate_copy,
            prepared_adjudication=prepared_copy,
            adjudication_report=adjudication_copy,
        )

    return detached


_detached_durable_run_snapshot = _build_detached_durable_run_snapshot()
_TRUSTED_DETACHED_DURABLE_RUN_SNAPSHOT = _detached_durable_run_snapshot
del _build_detached_durable_run_snapshot


class _OpenRouterExecutionAdapter:
    """Credential-owning callbacks retained only for one runner invocation."""

    __slots__ = (
        "_candidate_reports",
        "_closed",
        "_generation_subjects",
        "_judge_clients",
        "_judges_executed",
        "_launch",
        "_plans",
        "_secrets",
    )

    def __init__(
        self,
        *,
        launch: AuthenticatedRunnerOpenRouterLaunch,
        secrets: OperatorSecrets,
    ) -> None:
        self._launch = launch
        self._secrets = secrets
        self._plans = {plan.run_kind: plan for plan in launch.run_plans}
        self._candidate_reports: dict[CrossLineageAdjudicationRunKind, ModelBenchmarkReport] = {}
        self._judge_clients: dict[CrossLineageAdjudicationRunKind, OpenRouterClient] = {}
        self._judges_executed: set[CrossLineageAdjudicationRunKind] = set()
        self._generation_subjects: set[
            tuple[CrossLineageAdjudicationRunKind, AuthenticatedRunnerGenerationSubject]
        ] = set()
        self._closed = False

    async def candidate_executor(
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
    ) -> CandidateBenchmarkExecutionResult:
        """Run one exact singleton candidate campaign through the concrete transport."""

        self._require_open()
        launch = self._launch
        if (
            run_kind not in self._plans
            or run_kind in self._candidate_reports
            or config is not launch.config
            or discovery_manifest is not launch.candidate_discovery_manifest
            or discovery_evidence != launch.candidate_discovery_evidence
            or candidate_registry is not launch.candidate_registry
            or benchmark_suite is not launch.benchmark_suite
            or budget is not launch.budget
            or usage is not launch.usage
            or qualification_policy is not launch.qualification_policy
            or type(request_cost_plan) is not AuthenticatedRunnerStagedCostPlan
            or request_cost_plan.run_kind is not run_kind
            or request_cost_plan.stage is not AuthenticatedRunnerCostPlanStage.CANDIDATE
        ):
            raise AuthenticatedRunnerOpenRouterError(
                "candidate callback differs from the exact same-process launch"
            )
        result = await run_candidate_registry_benchmarks(
            config=config,
            discovery_manifest=discovery_manifest,
            discovery_evidence=discovery_evidence,
            candidate_registry=candidate_registry,
            benchmark_suite=benchmark_suite,
            budget=budget,
            usage=usage,
            operator_api_key=self._required_api_key(),
            explicitly_allow_synthetic_egress=launch.explicitly_allow_synthetic_egress,
            evidence_sink=evidence_sink,
            qualification_policy=qualification_policy,
            pre_dispatch_rejection_observer=_raise_candidate_pre_dispatch_rejection,
            authenticated_runner_run_kind=run_kind.value,
            expected_request_cost_previews=request_cost_plan.request_previews,
        )
        if type(result) is not CandidateBenchmarkExecutionResult or len(result.reports) != 1:
            raise AuthenticatedRunnerOpenRouterError(
                "candidate transport did not return one exact singleton report"
            )
        self._candidate_reports[run_kind] = result.reports[0]
        return result

    async def prepare_judge_routes(
        self,
        *,
        config: AuditConfig,
        prepared_runs: tuple[CrossLineageAdjudicationPreparedRun, ...],
        judges: tuple[CandidateModel, ...],
    ) -> None:
        """Refresh and retain both exact judge routes before either paid judge POST."""

        self._require_open()
        launch = self._launch
        if (
            config is not launch.config
            or type(prepared_runs) is not tuple
            or type(judges) is not tuple
            or len(prepared_runs) != len(launch.run_plans)
            or len(judges) != len(launch.run_plans)
            or self._judge_clients
            or self._judges_executed
            or tuple(item.run_kind for item in prepared_runs)
            != tuple(item.run_kind for item in launch.run_plans)
        ):
            raise AuthenticatedRunnerOpenRouterError(
                "judge route preparation differs from the exact same-process launch"
            )
        clients: dict[CrossLineageAdjudicationRunKind, OpenRouterClient] = {}
        try:
            for plan, prepared, judge in zip(
                launch.run_plans,
                prepared_runs,
                judges,
                strict=True,
            ):
                candidate_report = self._candidate_reports.get(plan.run_kind)
                if (
                    type(prepared) is not CrossLineageAdjudicationPreparedRun
                    or type(judge) is not CandidateModel
                    or judge != plan.judge
                    or candidate_report is None
                    or prepared.run_kind is not plan.run_kind
                    or prepared.candidate_report_sha256 != candidate_report.report_sha256
                    or prepared.run_kind in clients
                ):
                    raise AuthenticatedRunnerOpenRouterError(
                        "judge route preparation differs from both exact prepared runs"
                    )
                client = self._new_client(
                    model=judge,
                    source_kind=AuthenticatedRunnerGenerationSubject.JUDGE,
                    prepared=prepared,
                    candidate_report=candidate_report,
                )
                clients[prepared.run_kind] = client
                await _refresh_and_register_judge_discovery(
                    client=client,
                    config=config,
                    judge=judge,
                    evidence=plan.judge_discovery_evidence[0],
                    manifest=plan.judge_discovery_manifest,
                )
        except BaseException:
            for client in clients.values():
                try:
                    await client.close()
                except BaseException:
                    client.clear_credentials()
            raise
        if len(clients) != len(launch.run_plans):
            for client in clients.values():
                await client.close()
            raise AuthenticatedRunnerOpenRouterError(
                "judge route preparation did not retain both exact judge routes"
            )
        self._judge_clients.update(clients)

    async def judge_executor(
        self,
        *,
        config: AuditConfig,
        prepared: CrossLineageAdjudicationPreparedRun,
        judge: CandidateModel,
        budget: BudgetManager,
        usage: UsageLedger,
        request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    ) -> tuple[CrossLineageAdjudicationCaseResult, ...]:
        """Execute one prepared judge inventory on its registered singleton route."""

        self._require_open()
        launch = self._launch
        plan = self._plans.get(prepared.run_kind)
        candidate_report = self._candidate_reports.get(prepared.run_kind)
        if (
            plan is None
            or candidate_report is None
            or config is not launch.config
            or judge != plan.judge
            or budget is not launch.budget
            or usage is not launch.usage
            or prepared.candidate_report_sha256 != candidate_report.report_sha256
            or type(request_cost_plan) is not AuthenticatedRunnerStagedCostPlan
            or request_cost_plan.run_kind is not prepared.run_kind
            or request_cost_plan.stage is not AuthenticatedRunnerCostPlanStage.JUDGE
            or request_cost_plan.exact_model_id != judge.exact_model_id
            or request_cost_plan.provider_endpoint != judge.approved_provider_endpoint
        ):
            raise AuthenticatedRunnerOpenRouterError(
                "judge callback differs from the exact same-process launch"
            )
        client = self._judge_clients.get(prepared.run_kind)
        if client is None or prepared.run_kind in self._judges_executed:
            raise AuthenticatedRunnerOpenRouterError(
                "judge callback lacks one previously admitted exact live route"
            )
        results = await execute_cross_lineage_adjudication_requests(
            client=client,
            prepared=prepared,
            expected_request_cost_previews=request_cost_plan.request_previews,
        )
        self._judges_executed.add(prepared.run_kind)
        return results

    async def generation_executor(
        self,
        *,
        run_kind: CrossLineageAdjudicationRunKind,
        subject: AuthenticatedRunnerGenerationSubject,
        requests: tuple[GenerationVerificationRequest, ...],
    ) -> TrustedGenerationVerification:
        """Freshly re-fetch one exact generation inventory on an owned REAL client."""

        self._require_open()
        plan = self._plans.get(run_kind)
        generation_subject = (run_kind, subject)
        if plan is None or generation_subject in self._generation_subjects:
            raise AuthenticatedRunnerOpenRouterError(
                "generation callback is replayed or does not belong to this launch"
            )
        self._generation_subjects.add(generation_subject)
        if subject is AuthenticatedRunnerGenerationSubject.CANDIDATE:
            if run_kind not in self._candidate_reports:
                raise AuthenticatedRunnerOpenRouterError(
                    "candidate generation re-fetch preceded candidate execution"
                )
            candidate = self._launch.candidate_registry.candidates[0]
            client = self._new_client(
                model=candidate,
                source_kind=subject,
                prepared=None,
                candidate_report=None,
            )
            evidence = self._launch.candidate_discovery_evidence[0]
            manifest = self._launch.candidate_discovery_manifest
            try:
                await client.validate_authentication()
                client.register_certification_model_discovery(
                    evidence=evidence,
                    manifest=manifest,
                )
                return await client.create_trusted_generation_verification(requests)
            finally:
                await client.close()
        if subject is AuthenticatedRunnerGenerationSubject.JUDGE:
            try:
                client = self._judge_clients.pop(run_kind)
            except KeyError:
                raise AuthenticatedRunnerOpenRouterError(
                    "judge generation re-fetch lacks the exact live judge client"
                ) from None
            try:
                return await client.create_trusted_generation_verification(requests)
            finally:
                await client.close()
        raise AuthenticatedRunnerOpenRouterError("generation subject is not recognized")

    async def close(self) -> None:
        """Clear every retained credential and close every owned transport exactly once."""

        if self._closed:
            return
        self._closed = True
        clients = tuple(self._judge_clients.values())
        self._judge_clients.clear()
        failure: BaseException | None = None
        for client in clients:
            try:
                await client.close()
            except BaseException as exc:
                client.clear_credentials()
                if failure is None:
                    failure = exc
        if failure is not None:
            raise AuthenticatedRunnerOpenRouterError(
                "one or more owned OpenRouter transports failed to close"
            ) from failure

    def _new_client(
        self,
        *,
        model: CandidateModel,
        source_kind: AuthenticatedRunnerGenerationSubject,
        prepared: CrossLineageAdjudicationPreparedRun | None,
        candidate_report: ModelBenchmarkReport | None,
    ) -> OpenRouterClient:
        launch = self._launch
        observed_at = datetime.now(UTC).replace(microsecond=0)
        if source_kind is AuthenticatedRunnerGenerationSubject.CANDIDATE:
            if prepared is not None or candidate_report is not None:
                raise AuthenticatedRunnerOpenRouterError(
                    "candidate privacy proof received adjudication inputs"
                )
            source_observation = prove_release_pinned_model_benchmark_source(
                launch.benchmark_suite,
                now=observed_at,
            )
            source_sha256 = launch.benchmark_suite.corpus_sha256
        else:
            if prepared is None or candidate_report is None:
                raise AuthenticatedRunnerOpenRouterError(
                    "judge privacy proof lacks its exact prepared source"
                )
            source_observation = prove_release_pinned_cross_lineage_adjudication_source(
                prepared,
                launch.benchmark_suite,
                candidate_report,
                now=observed_at,
            )
            source_sha256 = cross_lineage_adjudication_source_sha256(prepared)
        policy = resolve_effective_privacy_policy(
            profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
            require_zdr=True,
            consent_observation=None,
            source_sha256=source_sha256,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
            source_provenance_observation=source_observation,
            configured_model_ids=(model.exact_model_id,),
            configured_provider_endpoints=(model.approved_provider_endpoint,),
            requested_budget_usd=Decimal(str(launch.budget.total_usd)),
            now=observed_at,
        )
        return OpenRouterClient(
            api_key=self._required_api_key(),
            execution=launch.config.execution,
            privacy=launch.config.privacy,
            token_budgets=launch.config.token_budgets,
            budget=launch.budget,
            usage=launch.usage,
            provider_policy=OpenRouterProviderPolicy(
                certification=True,
                only=(model.approved_provider_endpoint,),
                allow_fallbacks=False,
            ),
            reasoning_policy=build_reasoning_policy(launch.config),
            effective_privacy_policy=policy,
            source_provenance_observation=source_observation,
        )

    def _required_api_key(self) -> str:
        if self._closed or self._secrets.cleared or not self._secrets.openrouter_api_key_present:
            raise AuthenticatedRunnerOpenRouterError(
                "OpenRouter credential holder is absent or already cleared"
            )
        key = self._secrets.openrouter_api_key
        if not key:
            raise AuthenticatedRunnerOpenRouterError("OpenRouter credential is missing")
        return key

    def _require_open(self) -> None:
        if self._closed:
            raise AuthenticatedRunnerOpenRouterError("OpenRouter runner adapter is closed")


async def execute_authenticated_openrouter_runner(
    *,
    launch: AuthenticatedRunnerOpenRouterLaunch,
    operator_secrets: OperatorSecrets,
) -> AuthenticatedRunnerOpenRouterResult:
    """Run and consume AUTHRUNNER in one PID, clearing all credentials on every exit."""

    if type(operator_secrets) is not OperatorSecrets:
        raise AuthenticatedRunnerOpenRouterError(
            "OpenRouter runner requires the existing operator secret loader"
        )
    adapter: _OpenRouterExecutionAdapter | None = None
    try:
        expected_inventory = preflight_authenticated_openrouter_launch(launch)
        adapter = _OpenRouterExecutionAdapter(launch=launch, secrets=operator_secrets)
        if not operator_secrets.openrouter_api_key_present:
            raise AuthenticatedRunnerOpenRouterError(
                "OPENROUTER_API_KEY is missing from the operator secret holder"
            )
        execution = await execute_authenticated_cross_lineage_runner(
            config=launch.config,
            explicitly_allow_synthetic_egress=launch.explicitly_allow_synthetic_egress,
            public_lineage_capability=launch.public_lineage_capability,
            ground_truth_capability=launch.ground_truth_capability,
            benchmark_suite=launch.benchmark_suite,
            discovery_manifest=launch.candidate_discovery_manifest,
            discovery_evidence=launch.candidate_discovery_evidence,
            candidate_registry=launch.candidate_registry,
            qualification_policy=launch.qualification_policy,
            budget=launch.budget,
            usage=launch.usage,
            run_plans=launch.run_plans,
            candidate_executor=adapter.candidate_executor,
            judge_route_preparation_executor=adapter.prepare_judge_routes,
            judge_executor=adapter.judge_executor,
            generation_executor=adapter.generation_executor,
        )
        if type(execution) is not AuthenticatedRunnerExecutionResult:
            raise AuthenticatedRunnerOpenRouterError(
                "authenticated runner returned the wrong exact execution type"
            )
        runner_capability = execution.runner_capability
        if type(runner_capability) is not VerifiedCrossLineageRunnerCustody:
            raise AuthenticatedRunnerOpenRouterError(
                "authenticated runner returned an invalid custody capability"
            )
        try:
            if (
                type(execution.inventory) is not AuthenticatedRunnerExecutionInventory
                or type(execution.runs) is not tuple
                or any(type(item) is not AuthenticatedRunnerExecutedRun for item in execution.runs)
                or type(execution.runner_evidence) is not AuthenticatedCrossLineageRunnerEvidence
            ):
                raise AuthenticatedRunnerOpenRouterError(
                    "authenticated runner returned invalid retained execution evidence"
                )
            if execution.inventory != expected_inventory:
                raise AuthenticatedRunnerOpenRouterError(
                    "runner execution differs from its provider-free launch preflight"
                )
            ground_truth_projection = _require_launch_ground_truth(launch)
            rejection_kind: str | None
            try:
                collision_map, decisions = build_authenticated_evidence_seal_runner_inputs(
                    runner_custody=runner_capability,
                    runner_evidence=execution.runner_evidence,
                    benchmark_suite=launch.benchmark_suite,
                    ground_truth_projection=ground_truth_projection,
                    runs=tuple(item.custody for item in execution.runs),
                )
            except (TypeError, ValueError) as exc:
                collision_map = None
                decisions = ()
                rejection_kind = type(exc).__name__
            else:
                rejection_kind = None
            if (
                AuthenticatedRunnerOpenRouterRunSnapshot is not _TRUSTED_RUN_SNAPSHOT_TYPE
                or AuthenticatedRunnerOpenRouterExecutionSnapshot
                is not _TRUSTED_EXECUTION_SNAPSHOT_TYPE
                or _detached_durable_run_snapshot is not _TRUSTED_DETACHED_DURABLE_RUN_SNAPSHOT
            ):
                raise AuthenticatedRunnerOpenRouterError(
                    "authenticated runner durable snapshot binding changed"
                )
            sanitized_execution = _TRUSTED_EXECUTION_SNAPSHOT_TYPE(
                inventory=execution.inventory,
                runs=tuple(_TRUSTED_DETACHED_DURABLE_RUN_SNAPSHOT(item) for item in execution.runs),
            )
            return AuthenticatedRunnerOpenRouterResult(
                execution=sanitized_execution,
                runner_evidence=execution.runner_evidence,
                authseal_collision_map=collision_map,
                authseal_decision_projections=decisions,
                authseal_rejection_kind=rejection_kind,
            )
        finally:
            revoke_bindings = (
                _TRUSTED_REVOKE_RUNNER_CUSTODY,
                revoke_verified_cross_lineage_runner_custody,
                _runner_authority_module.revoke_verified_cross_lineage_runner_custody,
            )
            require_bindings = (
                _TRUSTED_REQUIRE_RUNNER_CUSTODY,
                require_verified_cross_lineage_runner_custody,
                _runner_authority_module.require_verified_cross_lineage_runner_custody,
            )
            lifecycle_binding_changed = not (
                revoke_bindings[0] is revoke_bindings[1] is revoke_bindings[2]
                and require_bindings[0] is require_bindings[1] is require_bindings[2]
            )
            if revoke_bindings[0] is revoke_bindings[1] or revoke_bindings[0] is revoke_bindings[2]:
                revoke_runner = revoke_bindings[0]
            elif revoke_bindings[1] is revoke_bindings[2]:
                revoke_runner = revoke_bindings[1]
            else:
                raise AuthenticatedRunnerOpenRouterError(
                    "authenticated runner lifecycle callable binding changed"
                )
            if (
                require_bindings[0] is require_bindings[1]
                or require_bindings[0] is require_bindings[2]
            ):
                require_runner = require_bindings[0]
            elif require_bindings[1] is require_bindings[2]:
                require_runner = require_bindings[1]
            else:
                raise AuthenticatedRunnerOpenRouterError(
                    "authenticated runner lifecycle callable binding changed"
                )
            revoke_result = cast(
                Callable[[VerifiedCrossLineageRunnerCustody], object],
                revoke_runner,
            )(runner_capability)
            if revoke_result is not None:
                raise AuthenticatedRunnerOpenRouterError(
                    "authenticated runner custody revocation returned unexpected evidence"
                )
            try:
                cast(Callable[..., object], require_runner)(
                    runner_capability,
                    evidence=execution.runner_evidence,
                )
            except AuthenticatedCrossLineageRunnerError as exc:
                if str(exc) != _REVOKED_RUNNER_CUSTODY_DETAIL:
                    raise AuthenticatedRunnerOpenRouterError(
                        "authenticated runner custody revocation could not be confirmed"
                    ) from exc
            else:
                raise AuthenticatedRunnerOpenRouterError(
                    "authenticated runner custody remained live after revocation"
                )
            if lifecycle_binding_changed:
                raise AuthenticatedRunnerOpenRouterError(
                    "authenticated runner lifecycle callable binding changed"
                )
    finally:
        try:
            if adapter is not None:
                await adapter.close()
        finally:
            operator_secrets.clear()


def preflight_authenticated_openrouter_launch(
    launch: AuthenticatedRunnerOpenRouterLaunch,
) -> AuthenticatedRunnerExecutionInventory:
    """Validate every launch join and output path without secrets or provider state."""

    if type(launch) is not AuthenticatedRunnerOpenRouterLaunch:
        raise AuthenticatedRunnerOpenRouterError(
            "OpenRouter runner launch has the wrong exact type"
        )
    if (
        type(launch.candidate_discovery_evidence) is not tuple
        or type(launch.run_plans) is not tuple
    ):
        raise AuthenticatedRunnerOpenRouterError(
            "OpenRouter runner discovery evidence and plans must be exact tuples"
        )
    if (
        vars(_runner_execution_module).get("_preflight_execution")
        is not _TRUSTED_EXECUTION_PREFLIGHT
    ):
        raise AuthenticatedRunnerOpenRouterError(
            "authenticated runner provider-free preflight binding changed"
        )
    _require_launch_ground_truth(launch)
    inventory, ledger, snapshot, candidate_cost_plans = _TRUSTED_EXECUTION_PREFLIGHT(
        config=launch.config,
        explicitly_allow_synthetic_egress=launch.explicitly_allow_synthetic_egress,
        public_lineage_capability=launch.public_lineage_capability,
        ground_truth_capability=launch.ground_truth_capability,
        benchmark_suite=launch.benchmark_suite,
        discovery_manifest=launch.candidate_discovery_manifest,
        discovery_evidence=launch.candidate_discovery_evidence,
        candidate_registry=launch.candidate_registry,
        qualification_policy=launch.qualification_policy,
        budget=launch.budget,
        usage=launch.usage,
        run_plans=launch.run_plans,
        candidate_executor=cast(CandidateCampaignExecutor, _provider_dispatch_forbidden),
        judge_route_preparation_executor=cast(
            JudgeRoutePreparationExecutor,
            _provider_dispatch_forbidden,
        ),
        judge_executor=cast(CrossLineageJudgeExecutor, _provider_dispatch_forbidden),
        generation_executor=cast(
            RunnerGenerationVerificationExecutor,
            _provider_dispatch_forbidden,
        ),
    )
    if ledger is None:
        raise AuthenticatedRunnerOpenRouterError(
            "authenticated runner preflight lacks the shared atomic ledger"
        )
    exact_ledger = cast(AtomicCostLedger, ledger)
    if (
        type(inventory) is not AuthenticatedRunnerExecutionInventory
        or type(candidate_cost_plans) is not tuple
        or len(candidate_cost_plans) != len(launch.run_plans)
        or any(type(item) is not AuthenticatedRunnerStagedCostPlan for item in candidate_cost_plans)
        or tuple(item.plan_sha256 for item in candidate_cost_plans)
        != inventory.candidate_stage_plan_sha256s
        or launch.budget.atomic_ledger is not exact_ledger
        or exact_ledger.snapshot() != snapshot
        or vars(_runner_execution_module).get("_preflight_execution")
        is not _TRUSTED_EXECUTION_PREFLIGHT
        or vars(VerifiedFrozenGroundTruth).get("require_for")
        is not _TRUSTED_GROUND_TRUTH_REQUIRE_FOR
    ):
        raise AuthenticatedRunnerOpenRouterError(
            "authenticated runner launch changed during provider-free preflight"
        )
    return inventory


def _provider_dispatch_forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AuthenticatedRunnerOpenRouterError(
        "provider dispatch is forbidden during authenticated runner preflight"
    )


def _raise_candidate_pre_dispatch_rejection(
    rejection: CandidateBenchmarkPreDispatchError,
) -> Never:
    """Preserve the exact bounded setup rejection for the operator CLI."""

    if type(rejection) is not CandidateBenchmarkPreDispatchError:
        raise AuthenticatedRunnerOpenRouterError(
            "candidate pre-dispatch rejection has the wrong exact type"
        )
    raise rejection


async def _refresh_and_register_judge_discovery(
    *,
    client: OpenRouterClient,
    config: AuditConfig,
    judge: CandidateModel,
    evidence: OpenRouterModelDiscoveryEvidence,
    manifest: OpenRouterModelDiscoveryRunManifest,
) -> None:
    """Re-observe one exact judge route before registering it for paid requests."""

    expected_policy = OpenRouterProviderPolicy(
        certification=True,
        only=(judge.approved_provider_endpoint,),
        allow_fallbacks=False,
    )
    if (
        type(client) is not OpenRouterClient
        or type(config) is not AuditConfig
        or type(judge) is not CandidateModel
        or type(evidence) is not OpenRouterModelDiscoveryEvidence
        or type(manifest) is not OpenRouterModelDiscoveryRunManifest
        or client.provider_policy != expected_policy
        or evidence.exact_model_id != judge.exact_model_id
        or evidence.canonical_slug != judge.canonical_model_slug
        or evidence.approved_provider_endpoint != judge.approved_provider_endpoint
        or evidence.provider_name != judge.approved_provider_name
        or evidence.discovery_evidence_sha256 != judge.discovery_evidence_sha256
        or evidence.endpoint_snapshot_sha256 != judge.endpoint_snapshot_sha256
        or evidence.output_capability_sha256 != judge.output_capability_sha256
        or evidence.pricing_snapshot_sha256 != judge.pricing_snapshot_sha256
        or evidence.model_metadata_snapshot_sha256 != judge.model_metadata_snapshot_sha256
    ):
        raise AuthenticatedRunnerOpenRouterError(
            "judge refresh inputs differ from the exact singleton discovery route"
        )
    await client.validate_authentication()
    models_payload = await client.get_certification_model_metadata()
    try:
        canonical_slug = openrouter_catalog_canonical_slug(
            exact_model_id=judge.exact_model_id,
            models_payload=models_payload,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerOpenRouterError(
            "current judge canonical model metadata differs from discovery"
        ) from None
    single_model_payload = await client.get_model_metadata(judge.exact_model_id)
    endpoint_payload = await client.get_model_endpoint_metadata(judge.exact_model_id)
    zdr_payload = await client.list_zdr_endpoints()
    try:
        current_endpoint = validate_openrouter_endpoint_snapshot(
            exact_model_id=judge.exact_model_id,
            configured_provider_endpoints=(judge.approved_provider_endpoint,),
            provider_policy_mode="only",
            endpoint_payload=endpoint_payload,
            require_zdr=config.privacy.require_zdr,
            zdr_payload=zdr_payload,
            reasoning_requested=False,
            required_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerOpenRouterError(
            "current judge endpoint, pricing, ZDR, or output metadata differs from discovery"
        ) from None
    try:
        current_model = validate_openrouter_model_discovery(
            exact_model_id=judge.exact_model_id,
            models_payload=models_payload,
            single_model_payload=single_model_payload,
            endpoint_snapshot=current_endpoint,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerOpenRouterError(
            "current judge model, reasoning, or output metadata differs from discovery"
        ) from None
    reasoning_control = build_reasoning_policy(config).control_for_request("model_benchmark")
    try:
        current_model.require_compatible_reasoning_profile(reasoning_control)
    except ValueError:
        raise AuthenticatedRunnerOpenRouterError(
            "current judge reasoning metadata is incompatible with the launch policy"
        ) from None
    try:
        require_openrouter_live_discovery_equivalence(
            canonical_slug=canonical_slug,
            current_endpoint=current_endpoint,
            current_model=current_model,
            frozen_evidence=evidence,
        )
    except ModelDiscoveryValidationError as exc:
        raise AuthenticatedRunnerOpenRouterError(str(exc)) from None
    client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
    registered = client.registered_model_identity_snapshot(judge.exact_model_id)
    if (
        registered.requested_slug != judge.exact_model_id
        or registered.canonical_slug != judge.canonical_model_slug
        or registered.approved_provider_endpoint != judge.approved_provider_endpoint
        or registered.provider_name != judge.approved_provider_name
        or registered.discovery_evidence_sha256 != judge.discovery_evidence_sha256
        or registered.endpoint_snapshot_sha256 != judge.endpoint_snapshot_sha256
        or registered.pricing_snapshot_sha256 != judge.pricing_snapshot_sha256
        or registered.model_metadata_snapshot_sha256 != judge.model_metadata_snapshot_sha256
        or registered.endpoint_capabilities.output_capability_sha256
        != judge.output_capability_sha256
        or registered.provider_policy.allow_fallbacks is not False
        or registered.provider_policy.configured_endpoints != (judge.approved_provider_endpoint,)
    ):
        raise AuthenticatedRunnerOpenRouterError(
            "registered judge identity differs from same-session discovery refresh"
        )


def _require_launch_ground_truth(
    launch: AuthenticatedRunnerOpenRouterLaunch,
) -> VerifiedFrozenGroundTruthProjection:
    """Invoke the captured opaque-capability method only while its class is pristine."""

    if (
        type(launch.ground_truth_capability) is not VerifiedFrozenGroundTruth
        or vars(VerifiedFrozenGroundTruth).get("require_for")
        is not _TRUSTED_GROUND_TRUTH_REQUIRE_FOR
    ):
        raise AuthenticatedRunnerOpenRouterError(
            "frozen ground-truth capability method changed before AUTHSEAL consumption"
        )
    projection = _TRUSTED_GROUND_TRUTH_REQUIRE_FOR(
        launch.ground_truth_capability,
        objective_sha256=FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
        provenance_sha256=FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
        source_revision=FROZEN_GROUND_TRUTH_SOURCE_REVISION,
        benchmark_corpus_sha256=launch.benchmark_suite.corpus_sha256,
        benchmark_ground_truth_sha256=launch.benchmark_suite.ground_truth_sha256,
    )
    if type(projection) is not VerifiedFrozenGroundTruthProjection:
        raise AuthenticatedRunnerOpenRouterError(
            "frozen ground-truth capability returned the wrong projection type"
        )
    return projection


__all__ = [
    "AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_CONTRACT_VERSION",
    "AUTHENTICATED_RUNNER_OPENROUTER_LAUNCH_FIELDS",
    "AuthenticatedRunnerOpenRouterError",
    "AuthenticatedRunnerOpenRouterExecutionSnapshot",
    "AuthenticatedRunnerOpenRouterLaunch",
    "AuthenticatedRunnerOpenRouterResult",
    "AuthenticatedRunnerOpenRouterRunSnapshot",
    "execute_authenticated_openrouter_runner",
    "preflight_authenticated_openrouter_launch",
]
