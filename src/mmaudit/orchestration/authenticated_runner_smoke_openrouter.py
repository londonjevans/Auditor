"""One-shot OpenRouter execution for the NONCREDITING one-case smoke contract.

The adapter exercises the real candidate, generation, judge, pricing, identity,
and ledger surfaces, but deliberately never calls the full AUTHRUNNER custody or
AUTHSEAL issuers.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, localcontext
from enum import StrEnum
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
from mmaudit.models.candidate_selection import (
    CandidateSelectionError,
    require_authenticated_runner_metadata_completion_limit,
    require_authenticated_runner_native_structured_output,
)
from mmaudit.models.discovery import (
    ModelDiscoveryValidationError,
    OpenRouterLiveDiscoveryMismatchCategory,
    OpenRouterLiveDiscoveryMismatchError,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    openrouter_catalog_canonical_slug,
    require_openrouter_live_discovery_equivalence,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.generation_evidence import (
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    revoke_trusted_generation_verification,
)
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterError,
    OpenRouterProviderPolicy,
    preview_openrouter_structured_request_cost,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.public_lineage_authority import (
    VerifiedIndependentPublicModelLineageProjection,
    VerifiedPublicModelLineage,
    require_independent_public_model_lineage,
)
from mmaudit.models.qualification import (
    CandidateModel,
    CandidateRegistry,
    LineageReviewStatus,
    validate_candidate_registry_discovery,
)
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import UsageLedger, require_authenticated_runner_smoke_run_index
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.budgets import (
    BudgetManager,
    _issue_trusted_budget_recovery_scope,
    _project_trusted_budget_accounting_state,
)
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
_ROOT_LINEAGE_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_SMOKE_LEDGER_REQUEST_ID_PATTERN = re.compile(
    r"^authrunner\.smoke\.r([1-9][0-9]{0,8})\.(?:candidate|judge)\."
    r"(?:primary|replay):[0-9a-f]{64}(?::attempt:[1-9][0-9]*)?$"
)
_LIVE_ROUTE_METADATA_GETS_PER_ROLE = 5
_LIVE_ROUTE_METADATA_LOGICAL_GET_COUNT = 15
_LIVE_ROUTE_METADATA_MAXIMUM_PROVIDER_ATTEMPTS = 30


class AuthenticatedRunnerSmokeOpenRouterError(ValueError):
    """The one-shot smoke launch or its exact runtime evidence failed closed."""


class AuthenticatedRunnerSmokeLiveRouteRole(StrEnum):
    """Closed display order for the three metadata-only smoke routes."""

    CANDIDATE = "candidate"
    PRIMARY_JUDGE = "PRIMARY judge"
    REPLAY_JUDGE = "REPLAY judge"


_SMOKE_ROUTE_ORDER = (
    AuthenticatedRunnerSmokeLiveRouteRole.CANDIDATE,
    AuthenticatedRunnerSmokeLiveRouteRole.PRIMARY_JUDGE,
    AuthenticatedRunnerSmokeLiveRouteRole.REPLAY_JUDGE,
)
_SMOKE_ROUTE_INDEX = {role: index for index, role in enumerate(_SMOKE_ROUTE_ORDER)}


@dataclass(frozen=True, slots=True)
class AuthenticatedRunnerSmokeLiveRouteMismatch:
    """One bounded role/category mismatch without provider-controlled values."""

    role: AuthenticatedRunnerSmokeLiveRouteRole
    category: OpenRouterLiveDiscoveryMismatchCategory

    def __post_init__(self) -> None:
        if (
            type(self.role) is not AuthenticatedRunnerSmokeLiveRouteRole
            or type(self.category) is not OpenRouterLiveDiscoveryMismatchCategory
        ):
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route mismatch has invalid typed material"
            )


class AuthenticatedRunnerSmokeLiveRouteMismatchError(AuthenticatedRunnerSmokeOpenRouterError):
    """Aggregate canonical retained mismatches after all three safe metadata probes."""

    __slots__ = ("mismatches",)

    def __init__(
        self,
        mismatches: tuple[AuthenticatedRunnerSmokeLiveRouteMismatch, ...],
    ) -> None:
        if (
            type(mismatches) is not tuple
            or not 1 <= len(mismatches) <= 3
            or any(
                type(item) is not AuthenticatedRunnerSmokeLiveRouteMismatch for item in mismatches
            )
        ):
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route mismatch aggregate is invalid"
            )
        roles = tuple(item.role for item in mismatches)
        if (
            len(set(roles)) != len(roles)
            or tuple(sorted(roles, key=_SMOKE_ROUTE_INDEX.__getitem__)) != roles
        ):
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route mismatch aggregate order is invalid"
            )
        self.mismatches = mismatches
        diagnostic = "; ".join(f"{item.role.value}={item.category.value}" for item in mismatches)
        super().__init__(f"smoke live-route retained discovery mismatches: {diagnostic}")


class _SmokeRouteDiscoveryMismatchError(AuthenticatedRunnerSmokeOpenRouterError):
    """Internal typed signal that only the metadata-only adapter may accumulate."""

    __slots__ = ("mismatch",)

    def __init__(
        self,
        *,
        role: AuthenticatedRunnerSmokeLiveRouteRole,
        category: OpenRouterLiveDiscoveryMismatchCategory,
    ) -> None:
        self.mismatch = AuthenticatedRunnerSmokeLiveRouteMismatch(
            role=role,
            category=category,
        )
        super().__init__(
            f"smoke {role.value} current OpenRouter {category.value} differs from frozen discovery"
        )


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

    smoke_run_index: int
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

    smoke_run_index: int
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
class AuthenticatedRunnerSmokeLiveRoutePreflightResult:
    """In-memory result of metadata-only candidate and judge route validation."""

    inventory: AuthenticatedRunnerSmokePreflightInventory
    exact_model_ids: tuple[str, str, str]
    logical_metadata_get_count: int
    maximum_metadata_provider_attempt_count: int

    def __post_init__(self) -> None:
        if (
            type(self.inventory) is not AuthenticatedRunnerSmokePreflightInventory
            or type(self.exact_model_ids) is not tuple
            or len(self.exact_model_ids) != 3
            or any(type(item) is not str or not item for item in self.exact_model_ids)
            or type(self.logical_metadata_get_count) is not int
            or self.logical_metadata_get_count != _LIVE_ROUTE_METADATA_LOGICAL_GET_COUNT
            or type(self.maximum_metadata_provider_attempt_count) is not int
            or self.maximum_metadata_provider_attempt_count
            != _LIVE_ROUTE_METADATA_MAXIMUM_PROVIDER_ATTEMPTS
        ):
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route result metadata request inventory is invalid"
            )

    def __reduce__(self) -> Never:
        raise TypeError("authenticated runner smoke live-route preflight cannot be serialized")

    def __reduce_ex__(self, _protocol: object) -> Never:
        raise TypeError("authenticated runner smoke live-route preflight cannot be serialized")


@dataclass(frozen=True, slots=True)
class _PreparedSmokeRun:
    plan: AuthenticatedRunnerSmokeRunPlan
    candidate_cost_plan: AuthenticatedRunnerSmokeCostPlan
    candidate_report: NoncreditingModelBenchmarkSmokeReport
    candidate_generation_refetch: OpenRouterGenerationEvidence
    prepared_adjudication: CrossLineageAdjudicationPreparedRun


class _SmokeOpenRouterAdapter:
    __slots__ = ("_closed", "_generation_revoke", "_judge_clients", "_launch", "_secrets")

    def __init__(
        self,
        *,
        launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
        secrets: OperatorSecrets,
        _generation_revoke: Callable[
            [TrustedGenerationVerification], None
        ] = revoke_trusted_generation_verification,
    ) -> None:
        self._launch = launch
        self._secrets = secrets
        self._generation_revoke = _generation_revoke
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
                route_role=AuthenticatedRunnerSmokeLiveRouteRole.CANDIDATE,
            )
            report = await execute_noncrediting_model_benchmark_smoke(
                smoke_run_index=launch.smoke_run_index,
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
            verification: TrustedGenerationVerification | None = None
            try:
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
            finally:
                if verification is not None:
                    self._generation_revoke(verification)
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
                    route_role=(
                        AuthenticatedRunnerSmokeLiveRouteRole.PRIMARY_JUDGE
                        if item.plan.run_kind is CrossLineageAdjudicationRunKind.PRIMARY
                        else AuthenticatedRunnerSmokeLiveRouteRole.REPLAY_JUDGE
                    ),
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
                smoke_run_index=self._launch.smoke_run_index,
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
            verification: TrustedGenerationVerification | None = None
            try:
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
            finally:
                if verification is not None:
                    self._generation_revoke(verification)
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


class _SmokeLiveRouteProbeAdapter:
    """Own metadata-only clients that have no request-source proof or completion custody."""

    __slots__ = ("_clients", "_closed", "_launch", "_secrets")

    def __init__(
        self,
        *,
        launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
        secrets: OperatorSecrets,
    ) -> None:
        self._launch = launch
        self._secrets = secrets
        self._clients: list[OpenRouterClient] = []
        self._closed = False

    async def probe_exact_routes(self) -> tuple[str, str, str]:
        """Construct and refresh candidate, PRIMARY, and REPLAY metadata routes once."""

        self._require_open()
        if self._clients:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route probe clients were already constructed"
            )
        launch = self._launch
        route_inputs = (
            (
                AuthenticatedRunnerSmokeLiveRouteRole.CANDIDATE,
                launch.candidate_registry.candidates[0],
                launch.candidate_discovery_evidence[0],
                launch.candidate_discovery_manifest,
            ),
            (
                AuthenticatedRunnerSmokeLiveRouteRole.PRIMARY_JUDGE,
                launch.run_plans[0].judge,
                launch.run_plans[0].judge_discovery_evidence[0],
                launch.run_plans[0].judge_discovery_manifest,
            ),
            (
                AuthenticatedRunnerSmokeLiveRouteRole.REPLAY_JUDGE,
                launch.run_plans[1].judge,
                launch.run_plans[1].judge_discovery_evidence[0],
                launch.run_plans[1].judge_discovery_manifest,
            ),
        )
        for _route_role, model, _evidence, _manifest in route_inputs:
            self._clients.append(self._new_metadata_client(model))
        mismatches: list[AuthenticatedRunnerSmokeLiveRouteMismatch] = []
        for client, (route_role, model, evidence, manifest) in zip(
            self._clients,
            route_inputs,
            strict=True,
        ):
            try:
                await _refresh_and_register_exact_route(
                    client=client,
                    config=launch.config,
                    model=model,
                    evidence=evidence,
                    manifest=manifest,
                    route_role=route_role,
                )
            except _SmokeRouteDiscoveryMismatchError as exc:
                mismatches.append(exc.mismatch)
        if mismatches:
            raise AuthenticatedRunnerSmokeLiveRouteMismatchError(tuple(mismatches))
        return (
            route_inputs[0][1].exact_model_id,
            route_inputs[1][1].exact_model_id,
            route_inputs[2][1].exact_model_id,
        )

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        clients = tuple(self._clients)
        self._clients.clear()
        failed = False
        for client in clients:
            try:
                await client.close()
            except BaseException:
                failed = True
                client.clear_credentials()
        self._secrets.clear()
        if failed:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "one or more smoke live-route metadata transports failed to close"
            )

    def _new_metadata_client(self, model: CandidateModel) -> OpenRouterClient:
        """Build an exact paid-control client without any completion-source proof."""

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
        )

    def _required_api_key(self) -> str:
        if self._closed or self._secrets.cleared or not self._secrets.openrouter_api_key_present:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route OpenRouter credential is absent"
            )
        key: str = self._secrets.openrouter_api_key
        if not key:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route OpenRouter credential is missing"
            )
        return key

    def _require_open(self) -> None:
        if self._closed:
            raise AuthenticatedRunnerSmokeOpenRouterError("smoke live-route adapter is closed")


def preflight_authenticated_runner_smoke_openrouter_launch(
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
) -> AuthenticatedRunnerSmokePreflightInventory:
    """Validate exact frozen inputs and candidate costs without secrets or provider access."""

    return _preflight_authenticated_runner_smoke_launch(
        launch,
        live_route_metadata_only=False,
    )


def preflight_authenticated_runner_smoke_live_route_launch(
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
) -> AuthenticatedRunnerSmokePreflightInventory:
    """Validate the metadata-only route probe without granting benchmark-code egress."""

    return _preflight_authenticated_runner_smoke_launch(
        launch,
        live_route_metadata_only=True,
    )


def _preflight_authenticated_runner_smoke_launch(
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
    *,
    live_route_metadata_only: bool,
) -> AuthenticatedRunnerSmokePreflightInventory:
    """Run the common frozen, cost, lineage, usage, and ledger admission checks."""

    if type(launch) is not AuthenticatedRunnerSmokeOpenRouterLaunch:
        raise AuthenticatedRunnerSmokeOpenRouterError("smoke launch has the wrong exact type")
    try:
        smoke_run_index = require_authenticated_runner_smoke_run_index(launch.smoke_run_index)
    except ValueError:
        raise AuthenticatedRunnerSmokeOpenRouterError("smoke run index is invalid") from None
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
    budget = launch.budget
    if type(budget) is not BudgetManager:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke launch requires the exact shared budget manager"
        )
    if Decimal(str(config.execution.budget_usd)) != _LEDGER_CAP_USD:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke configured execution budget must equal 250 USD"
        )
    if Decimal(str(budget.total_usd)) != Decimal(str(config.execution.budget_usd)):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget manager total differs from configured execution budget"
        )
    if budget.max_output_tokens != config.execution.max_output_tokens_per_request:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget maximum output tokens differ from configuration"
        )
    if Decimal(str(budget.conservative_rate)) != Decimal(
        str(config.execution.conservative_usd_per_million_tokens)
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget conservative rate differs from configuration"
        )
    if budget.max_requests_per_agent != config.execution.max_requests_per_agent:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget request cap differs from configuration"
        )
    if budget.require_endpoint_cost_bound is not True:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget must require endpoint cost binding"
        )
    if budget.global_input_token_budget != config.token_budgets.global_input_token_budget:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget global input token budget differs from configuration"
        )
    if budget.global_output_token_budget != config.token_budgets.global_output_token_budget:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget global output token budget differs from configuration"
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
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke shared budget scoped cost budgets differ from configuration"
        )
    if live_route_metadata_only:
        if launch.explicitly_allow_synthetic_egress is not False:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route launch must not grant benchmark-code egress"
            )
    else:
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
    usage = launch.usage
    ledger = budget.atomic_ledger
    if (
        type(usage) is not UsageLedger
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
    _require_unused_smoke_run_index(initial, smoke_run_index=smoke_run_index)
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
            smoke_run_index=smoke_run_index,
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
        smoke_run_index=smoke_run_index,
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


async def preflight_authenticated_runner_smoke_live_routes(
    *,
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
    operator_secrets: OperatorSecrets,
    explicitly_allow_metadata_egress: bool,
) -> AuthenticatedRunnerSmokeLiveRoutePreflightResult:
    """Authenticate and refresh all three exact routes without any completion request."""

    if type(operator_secrets) is not OperatorSecrets:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke live-route preflight requires the existing operator secret holder"
        )
    try:
        if explicitly_allow_metadata_egress is not True:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route preflight requires explicit metadata egress permission"
            )
        inventory = preflight_authenticated_runner_smoke_live_route_launch(launch)
        ledger = launch.budget.atomic_ledger
        if type(ledger) is not AtomicCostLedger:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                "smoke live-route preflight lacks its atomic ledger"
            )
        initial_usage = tuple(launch.usage.records)
        initial_budget = _budget_runtime_state(launch.budget)
        initial_ledger = ledger.snapshot()
        adapter = _SmokeLiveRouteProbeAdapter(launch=launch, secrets=operator_secrets)
        exact_model_ids: tuple[str, str, str]
        close_error: BaseException | None = None
        try:
            exact_model_ids = await adapter.probe_exact_routes()
        finally:
            try:
                await adapter.close()
            except BaseException as exc:
                close_error = exc
            if (
                tuple(launch.usage.records) != initial_usage
                or _budget_runtime_state(launch.budget) != initial_budget
                or ledger.snapshot() != initial_ledger
            ):
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "smoke live-route preflight changed usage, budget, or atomic cost-ledger state"
                ) from None
            if close_error is not None:
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "smoke live-route preflight did not close every metadata transport"
                ) from close_error
        return AuthenticatedRunnerSmokeLiveRoutePreflightResult(
            inventory=inventory,
            exact_model_ids=exact_model_ids,
            logical_metadata_get_count=(len(exact_model_ids) * _LIVE_ROUTE_METADATA_GETS_PER_ROLE),
            maximum_metadata_provider_attempt_count=(
                len(exact_model_ids)
                * _LIVE_ROUTE_METADATA_GETS_PER_ROLE
                * (launch.config.execution.max_model_retries + 1)
            ),
        )
    finally:
        operator_secrets.clear()


def _budget_runtime_state(
    budget: BudgetManager,
) -> tuple[tuple[int, ...], tuple[object, ...]]:
    """Capture exact process-local accounting material without serializing authority."""

    if type(budget) is not BudgetManager:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke live-route preflight budget has the wrong exact type"
        )
    try:
        projection = _project_trusted_budget_accounting_state(budget)
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke live-route preflight budget state is invalid"
        ) from None
    return tuple(id(item) for item in projection.containers), projection.material


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
                    smoke_run_index=launch.smoke_run_index,
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
            smoke_run_index=launch.smoke_run_index,
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
    smoke_run_index: int,
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
        smoke_run_index=smoke_run_index,
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
        smoke_run_index=smoke_run_index,
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
        smoke_run_index=prepared.candidate_cost_plan.smoke_run_index,
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
        smoke_run_index=prepared.candidate_cost_plan.smoke_run_index,
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
    try:
        require_authenticated_runner_native_structured_output(discovery)
    except CandidateSelectionError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {label} route lacks required native structured_outputs support"
        ) from None
    try:
        require_authenticated_runner_metadata_completion_limit(
            discovery,
            required_source="metadata",
        )
    except CandidateSelectionError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {label} route lacks an explicit metadata completion limit"
        ) from None
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
    models = (candidate, judges[0], judges[1])
    if any(
        model.root_lineage is None
        and model.lineage_review.status is not LineageReviewStatus.PENDING
        for model in models
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke registry lineage review does not permit documentary root projection"
        )
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
    if any(
        type(item) is not VerifiedIndependentPublicModelLineageProjection
        or item.independent is not True
        or item.left_exact_model_id != left.exact_model_id
        or item.right_exact_model_id != right.exact_model_id
        or _ROOT_LINEAGE_PATTERN.fullmatch(item.left_root_lineage) is None
        or _ROOT_LINEAGE_PATTERN.fullmatch(item.right_root_lineage) is None
        or (left.root_lineage is not None and item.left_root_lineage != left.root_lineage)
        or (right.root_lineage is not None and item.right_root_lineage != right.root_lineage)
        for item, (left, right) in zip(projections, pairs, strict=True)
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            "smoke public lineage returned a non-independent projection"
        )
    candidate_primary, candidate_replay, primary_replay = projections
    documentary_roots = (
        candidate_primary.left_root_lineage,
        candidate_primary.right_root_lineage,
        candidate_replay.right_root_lineage,
    )
    if (
        candidate_replay.left_root_lineage != documentary_roots[0]
        or primary_replay.left_root_lineage != documentary_roots[1]
        or primary_replay.right_root_lineage != documentary_roots[2]
        or len(set(documentary_roots)) != 3
        or len({item.bundle_sha256 for item in projections}) != 1
        or len({item.manifest_file_sha256 for item in projections}) != 1
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
    route_role: AuthenticatedRunnerSmokeLiveRouteRole,
) -> None:
    if type(route_role) is not AuthenticatedRunnerSmokeLiveRouteRole:
        raise AuthenticatedRunnerSmokeOpenRouterError("smoke route role is invalid")
    expected_policy = OpenRouterProviderPolicy(
        certification=True,
        only=(model.approved_provider_endpoint,),
        allow_fallbacks=False,
    )
    if client.provider_policy != expected_policy:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} client differs from its singleton route policy"
        )
    try:
        await client.validate_authentication()
    except OpenRouterError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} authentication metadata request failed safely"
        ) from None
    try:
        models_payload = await client.get_certification_model_metadata()
    except OpenRouterError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} catalog metadata request failed safely"
        ) from None
    try:
        canonical_slug = openrouter_catalog_canonical_slug(
            exact_model_id=model.exact_model_id,
            models_payload=models_payload,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} current canonical model metadata is incompatible"
        ) from None
    try:
        single_model_payload = await client.get_model_metadata(model.exact_model_id)
    except OpenRouterError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} exact-model metadata request failed safely"
        ) from None
    try:
        endpoint_payload = await client.get_model_endpoint_metadata(model.exact_model_id)
    except OpenRouterError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} endpoint metadata request failed safely"
        ) from None
    try:
        zdr_payload = await client.list_zdr_endpoints()
    except OpenRouterError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} ZDR metadata request failed safely"
        ) from None
    try:
        current_endpoint = validate_openrouter_endpoint_snapshot(
            exact_model_id=model.exact_model_id,
            configured_provider_endpoints=(model.approved_provider_endpoint,),
            provider_policy_mode="only",
            endpoint_payload=endpoint_payload,
            require_zdr=config.privacy.require_zdr,
            zdr_payload=zdr_payload,
            reasoning_requested=False,
            required_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        )
        current_model = validate_openrouter_model_discovery(
            exact_model_id=model.exact_model_id,
            models_payload=models_payload,
            single_model_payload=single_model_payload,
            endpoint_snapshot=current_endpoint,
        )
    except (TypeError, ValueError):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} current model, route, ZDR, pricing, or output metadata "
            "is incompatible"
        ) from None
    try:
        current_model.require_compatible_reasoning_profile(
            build_reasoning_policy(config).control_for_request("model_benchmark")
        )
    except ValueError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} current reasoning metadata is incompatible "
            "with launch policy"
        ) from None
    try:
        require_openrouter_live_discovery_equivalence(
            canonical_slug=canonical_slug,
            current_endpoint=current_endpoint,
            current_model=current_model,
            frozen_evidence=evidence,
        )
    except OpenRouterLiveDiscoveryMismatchError as exc:
        raise _SmokeRouteDiscoveryMismatchError(
            role=route_role,
            category=exc.category,
        ) from None
    except ModelDiscoveryValidationError as exc:
        raise AuthenticatedRunnerSmokeOpenRouterError(f"smoke {route_role.value} {exc}") from None
    try:
        client.register_certification_model_discovery(evidence=evidence, manifest=manifest)
        registered = client.registered_model_identity_snapshot(model.exact_model_id)
    except OpenRouterError:
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} discovery registration failed safely"
        ) from None
    if (
        registered.requested_slug != model.exact_model_id
        or registered.canonical_slug != model.canonical_model_slug
        or registered.approved_provider_endpoint != model.approved_provider_endpoint
        or registered.provider_name != model.approved_provider_name
        or registered.discovery_evidence_sha256 != model.discovery_evidence_sha256
        or registered.endpoint_snapshot_sha256 != model.endpoint_snapshot_sha256
        or registered.pricing_snapshot_sha256 != model.pricing_snapshot_sha256
        or registered.model_metadata_snapshot_sha256 != model.model_metadata_snapshot_sha256
        or registered.endpoint_capabilities.output_capability_sha256
        != model.output_capability_sha256
        or registered.provider_policy.allow_fallbacks is not False
        or registered.provider_policy.configured_endpoints != (model.approved_provider_endpoint,)
    ):
        raise AuthenticatedRunnerSmokeOpenRouterError(
            f"smoke {route_role.value} registered identity differs from same-session "
            "discovery refresh"
        )


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


def _require_unused_smoke_run_index(
    snapshot: CostLedgerSnapshot,
    *,
    smoke_run_index: int,
) -> None:
    """Reject a run namespace already occupied by any cumulative ledger entry."""

    run_index = require_authenticated_runner_smoke_run_index(smoke_run_index)
    for entry in snapshot.entries:
        match = _SMOKE_LEDGER_REQUEST_ID_PATTERN.fullmatch(entry.request_id)
        if match is not None and int(match.group(1)) == run_index:
            raise AuthenticatedRunnerSmokeOpenRouterError(
                f"smoke run index {run_index} is already present in the cumulative ledger"
            )


def _positive_cost(value: Decimal, *, label: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value <= 0:
        raise AuthenticatedRunnerSmokeOpenRouterError(f"smoke {label} must be positive")
    return value


__all__ = [
    "AuthenticatedRunnerSmokeLiveRouteMismatch",
    "AuthenticatedRunnerSmokeLiveRouteMismatchError",
    "AuthenticatedRunnerSmokeLiveRoutePreflightResult",
    "AuthenticatedRunnerSmokeLiveRouteRole",
    "AuthenticatedRunnerSmokeOpenRouterError",
    "AuthenticatedRunnerSmokeOpenRouterLaunch",
    "AuthenticatedRunnerSmokeOpenRouterResult",
    "AuthenticatedRunnerSmokePreflightInventory",
    "AuthenticatedRunnerSmokeRunPlan",
    "execute_authenticated_runner_smoke_openrouter",
    "preflight_authenticated_runner_smoke_live_route_launch",
    "preflight_authenticated_runner_smoke_live_routes",
    "preflight_authenticated_runner_smoke_openrouter_launch",
]
