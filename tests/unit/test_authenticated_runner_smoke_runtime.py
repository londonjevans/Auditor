from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

import mmaudit.benchmark.cross_lineage_adjudication as adjudication_module
import mmaudit.cli as cli_module
import mmaudit.models.authenticated_runner_smoke as smoke_evidence_module
import mmaudit.models.generation_evidence as generation_evidence_module
import mmaudit.orchestration.authenticated_runner_smoke_openrouter as smoke_runtime_module
import tests.unit.test_authenticated_runner_smoke_benchmark as smoke_benchmark_fixtures
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationRunKind,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_report,
    build_cross_lineage_adjudication_response,
    prepare_noncrediting_cross_lineage_adjudication_smoke,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkCaseResult,
    NoncreditingModelBenchmarkSmokeReport,
    authenticated_runner_smoke_model_benchmark_request_descriptor,
    load_model_benchmark_corpus,
)
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageLedgerEntryEvidence,
    AuthenticatedCrossLineageLedgerIntervalEvidence,
)
from mmaudit.models.authenticated_runner_smoke import (
    MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES,
    AuthenticatedRunnerSmokeCostPlan,
    AuthenticatedRunnerSmokeError,
    AuthenticatedRunnerSmokeEvidenceBundle,
    AuthenticatedRunnerSmokeRunEvidence,
    authenticated_runner_smoke_evidence_bytes,
    build_authenticated_runner_smoke_cost_plan,
    revalidate_authenticated_runner_smoke_evidence_bytes,
    seal_authenticated_runner_smoke_evidence_bundle,
    seal_authenticated_runner_smoke_run_evidence,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.discovery import OpenRouterLiveDiscoveryMismatchCategory
from mmaudit.models.generation_evidence import (
    GenerationEvidenceValidationError,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
)
from mmaudit.models.openrouter import OpenRouterModelError, OpenRouterStructuredRequestCostPreview
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.public_lineage_authority import (
    VerifiedIndependentPublicModelLineageProjection,
    require_independent_public_model_lineage,
    require_verified_public_model_lineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.models.qualification import (
    CandidateModel,
    LineageReviewStatus,
    seal_operator_lineage_review,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.token_planning import RequestTokenPlan
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from mmaudit.orchestration.authenticated_runner_smoke_openrouter import (
    AuthenticatedRunnerSmokeLiveRouteMismatchError,
    AuthenticatedRunnerSmokeLiveRouteRole,
    AuthenticatedRunnerSmokeOpenRouterError,
    AuthenticatedRunnerSmokeOpenRouterLaunch,
    AuthenticatedRunnerSmokePreflightInventory,
    AuthenticatedRunnerSmokeRunPlan,
    _require_exact_smoke_callback_ledger_delta,
    _require_three_distinct_roots,
    execute_authenticated_runner_smoke_openrouter,
    preflight_authenticated_runner_smoke_live_route_launch,
    preflight_authenticated_runner_smoke_live_routes,
    preflight_authenticated_runner_smoke_openrouter_launch,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
    ReleaseReason,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacyProfile
from mmaudit.reporting.json_report import stable_json_bytes
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
    rebind_synthetic_token_plan,
)
from tests.output_evidence_fixtures import synthetic_structured_output_routing
from tests.unit import test_authenticated_runner_execution as execution_fixtures
from tests.unit import test_candidate_benchmark as candidate_fixtures
from tests.unit.test_authenticated_runner_cost_plan import _preview, _replace_preview
from tests.unit.test_authenticated_runner_durable_bundle import (
    _cost_preview_for_usage,
    _usage_with_cost_preview,
    _v2_token_plan_for_usage,
)
from tests.unit.test_authenticated_runner_execution import _config
from tests.unit.test_authenticated_runner_smoke_benchmark import (
    JUDGE_ID,
    SELECTION_SHA256,
    _judge,
    _smoke_report,
)
from tests.unit.test_cross_lineage_adjudication import _judge_usage_and_generation
from tests.unit.test_model_benchmark_portfolio import (
    _as_structural_real,
    _candidate_registry,
    _report,
)
from tests.unit.test_openrouter import _as_v3_unknown_token_smoke_usage

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
SMOKE_CORPUS_PATH = ROOT / "benchmarks" / "model_corpus_smoke"
NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

CANDIDATE_ID = "deepseek/deepseek-v4-pro-0813"
PRIMARY_JUDGE_ID = "minimax/minimax-m3"
REPLAY_JUDGE_ID = "moonshotai/kimi-k3"
_TOKEN_ROUTING_FIELDS = (
    "request_token_plan",
    "request_token_plan_sha256",
    "atomic_token_reservation",
    "atomic_token_reservation_sha256",
    "atomic_token_reservations",
    "atomic_token_reservation_sha256s",
)


class _CanonicalSmokeReportReplayEnvelope(BaseModel):
    """Exercise the smoke bundle's strict outer-model/nested-usage JSON boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    report: NoncreditingModelBenchmarkSmokeReport


def _snapshot(*, entries: tuple[CostEntry, ...], spent: Decimal) -> CostLedgerSnapshot:
    return CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=spent,
        active_reserved_usd=Decimal(0),
        remaining_usd=Decimal("250") - spent,
        over_cap=False,
        has_reservation_overrun=False,
        entries=entries,
    )


def _approved_candidate(model_id: str) -> CandidateModel:
    capability = resolve_verified_public_model_lineage()
    lineage = require_verified_public_model_lineage(capability, model_id)
    base = _candidate_registry((model_id,)).candidates[0]
    review = seal_operator_lineage_review(
        status=LineageReviewStatus.APPROVED,
        reviewed_model_ids=(model_id,),
        rationale="Synthetic unit binding to the compiled public-lineage projection.",
        root_lineage=lineage.root_lineage,
        reviewed_by="synthetic-unit-reviewer",
        reviewed_at=NOW,
        evidence_sha256=lineage.bundle_sha256,
    )
    return CandidateModel.model_validate(
        {
            **base.model_dump(mode="python"),
            "root_lineage": lineage.root_lineage,
            "lineage_review": review,
        },
        strict=True,
    )


def _smoke_config(
    config_factory: Callable[..., AuditConfig],
    *,
    retries: int = 1,
) -> AuditConfig:
    return config_factory(
        execution={
            "budget_usd": 250.0,
            "max_model_retries": retries,
            "max_requests_per_agent": 192,
        },
        privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK},
        models={
            "provider_policy": {"allow_fallbacks": False},
            "reasoning": {"effort": "high", "reserved_tokens": 4_096},
        },
    )


def _candidate_smoke_plan(
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    selection_sha256: str,
    case_id: str,
    index: int,
    prompt_price: str = "0.001",
    smoke_run_index: int = 1,
) -> Any:
    preview = _preview(
        index,
        logical_request_id=(
            f"authrunner.smoke.r{smoke_run_index}.candidate."
            f"{run_kind.value.casefold()}:{selection_sha256}"
        ),
        maximum_attempts=2,
        prompt_price=prompt_price,
    )
    return build_authenticated_runner_smoke_cost_plan(
        smoke_run_index=smoke_run_index,
        run_kind=run_kind,
        stage="CANDIDATE",
        case_id=case_id,
        selection_sha256=selection_sha256,
        request_preview=preview,
    )


def _judge_smoke_plan(
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    selection_sha256: str,
    case_id: str,
    request_sha256: str,
    index: int,
    smoke_run_index: int = 1,
) -> Any:
    preview = _preview(
        index,
        logical_request_id=(
            f"authrunner.smoke.r{smoke_run_index}.judge."
            f"{run_kind.value.casefold()}:{request_sha256}"
        ),
        maximum_attempts=2,
    )
    return build_authenticated_runner_smoke_cost_plan(
        smoke_run_index=smoke_run_index,
        run_kind=run_kind,
        stage="JUDGE",
        case_id=case_id,
        selection_sha256=selection_sha256,
        request_preview=preview,
    )


def _discovery_stub(label: str) -> SimpleNamespace:
    return SimpleNamespace(
        discovery_evidence_sha256=canonical_sha256({"discovery": label}),
        require_compatible_reasoning_profile=lambda _control: None,
    )


def _launch(
    *,
    config: AuditConfig,
    tmp_path: Path,
    candidate_tripwires: tuple[Decimal, Decimal] = (Decimal("1"), Decimal("1")),
    judge_tripwires: tuple[Decimal, Decimal] = (Decimal("1"), Decimal("1")),
    smoke_run_index: int = 1,
) -> AuthenticatedRunnerSmokeOpenRouterLaunch:
    tmp_path.chmod(0o700)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "smoke-runtime-ledger.json",
        cap_usd=Decimal("250"),
    )
    budget = BudgetManager(
        total_usd=250.0,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=192,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        per_model_usd_caps={
            model: str(cap) for model, cap in config.token_budgets.per_model_cost_budget_usd.items()
        },
        per_role_usd_caps={
            role: str(cap) for role, cap in config.token_budgets.per_role_cost_budget_usd.items()
        },
    )
    candidate_manifest = SimpleNamespace(
        manifest_sha256=canonical_sha256({"manifest": "candidate"})
    )
    primary_manifest = SimpleNamespace(manifest_sha256=canonical_sha256({"manifest": "primary"}))
    replay_manifest = SimpleNamespace(manifest_sha256=canonical_sha256({"manifest": "replay"}))
    candidate_evidence = _discovery_stub("candidate")
    primary_evidence = _discovery_stub("primary")
    replay_evidence = _discovery_stub("replay")
    run_plans = (
        AuthenticatedRunnerSmokeRunPlan(
            run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
            judge_discovery_manifest=cast(Any, primary_manifest),
            judge_discovery_evidence=cast(Any, (primary_evidence,)),
            judge_registry=_candidate_registry((PRIMARY_JUDGE_ID,)),
            candidate_cost_tripwire_usd_per_attempt=candidate_tripwires[0],
            judge_cost_tripwire_usd_per_attempt=judge_tripwires[0],
        ),
        AuthenticatedRunnerSmokeRunPlan(
            run_kind=CrossLineageAdjudicationRunKind.REPLAY,
            judge_discovery_manifest=cast(Any, replay_manifest),
            judge_discovery_evidence=cast(Any, (replay_evidence,)),
            judge_registry=_candidate_registry((REPLAY_JUDGE_ID,)),
            candidate_cost_tripwire_usd_per_attempt=candidate_tripwires[1],
            judge_cost_tripwire_usd_per_attempt=judge_tripwires[1],
        ),
    )
    return AuthenticatedRunnerSmokeOpenRouterLaunch(
        smoke_run_index=smoke_run_index,
        config=config,
        explicitly_allow_synthetic_egress=True,
        public_lineage_capability=resolve_verified_public_model_lineage(),
        benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
        smoke_corpus=load_authenticated_runner_smoke_corpus_bundle(SMOKE_CORPUS_PATH),
        candidate_discovery_manifest=cast(Any, candidate_manifest),
        candidate_discovery_evidence=cast(Any, (candidate_evidence,)),
        candidate_registry=_candidate_registry((CANDIDATE_ID,)),
        budget=budget,
        usage=UsageLedger(),
        run_plans=run_plans,
    )


async def _live_route_launch(
    *,
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> AuthenticatedRunnerSmokeOpenRouterLaunch:
    harness = await execution_fixtures._harness(tmp_path / "full-runner", config_factory)
    return AuthenticatedRunnerSmokeOpenRouterLaunch(
        smoke_run_index=1,
        config=harness.config,
        explicitly_allow_synthetic_egress=False,
        public_lineage_capability=harness.public_lineage,
        benchmark_suite=harness.suite,
        smoke_corpus=load_authenticated_runner_smoke_corpus_bundle(SMOKE_CORPUS_PATH),
        candidate_discovery_manifest=type(harness.discovery_manifest).model_validate_json(
            harness.discovery_manifest.model_dump_json()
        ),
        candidate_discovery_evidence=tuple(
            type(item).model_validate_json(item.model_dump_json())
            for item in harness.discovery_evidence
        ),
        candidate_registry=harness.registry,
        budget=harness.budget,
        usage=harness.usage,
        run_plans=tuple(
            AuthenticatedRunnerSmokeRunPlan(
                run_kind=plan.run_kind,
                judge_discovery_manifest=type(plan.judge_discovery_manifest).model_validate_json(
                    plan.judge_discovery_manifest.model_dump_json()
                ),
                judge_discovery_evidence=tuple(
                    type(item).model_validate_json(item.model_dump_json())
                    for item in plan.judge_discovery_evidence
                ),
                judge_registry=plan.judge_registry,
                candidate_cost_tripwire_usd_per_attempt=Decimal("1"),
                judge_cost_tripwire_usd_per_attempt=Decimal("1"),
            )
            for plan in harness.plans
        ),
    )


def _install_live_route_client_factory(
    monkeypatch: pytest.MonkeyPatch,
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
    *,
    authentication_failure_models: set[str] | None = None,
    metadata_network_failure_models: set[str] | None = None,
    pricing_drift_models: set[str] | None = None,
    endpoint_inventory_drift_models: set[str] | None = None,
    canonical_shape_models: set[str] | None = None,
    single_model_failure_modes: dict[str, str] | None = None,
    client_wrapper: Callable[[Any], Any] | None = None,
) -> candidate_fixtures._MockClientFactory:
    factory = candidate_fixtures._MockClientFactory(
        authentication_failure_models=set(authentication_failure_models or ()),
        metadata_network_failure_models=set(metadata_network_failure_models or ()),
        pricing_drift_models=set(pricing_drift_models or ()),
        endpoint_inventory_drift_models=set(endpoint_inventory_drift_models or ()),
        canonical_shape_models=set(canonical_shape_models or ()),
        single_model_failure_modes=dict(single_model_failure_modes or {}),
    )
    models = (
        launch.candidate_registry.candidates[0],
        launch.run_plans[0].judge,
        launch.run_plans[1].judge,
    )
    models_by_endpoint = {item.approved_provider_endpoint: item for item in models}

    def build_client(**kwargs: Any) -> Any:
        provider_policy = kwargs["provider_policy"]
        endpoint = provider_policy.only[0]
        client = factory(
            api_key=kwargs["api_key"],
            config=launch.config,
            budget=kwargs["budget"],
            usage=kwargs["usage"],
            candidate=models_by_endpoint[endpoint],
            provider_policy=provider_policy,
            reasoning_policy=kwargs["reasoning_policy"],
            token_budgets=kwargs["token_budgets"],
        )
        return client if client_wrapper is None else client_wrapper(client)

    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", build_client)
    return factory


def _fake_bundle_validator_subject() -> tuple[
    SimpleNamespace,
    list[SimpleNamespace],
    list[SimpleNamespace],
    list[SimpleNamespace],
]:
    config_fields = {
        "execution_config_sha256": "1" * 64,
        "privacy_config_sha256": "2" * 64,
        "token_budget_config_sha256": "3" * 64,
        "reasoning_policy_sha256": "4" * 64,
        "reasoning_policy_role_binding_sha256": "5" * 64,
        "reasoning_profile_sha256": "6" * 64,
    }
    previews = [
        SimpleNamespace(logical_request_id=f"smoke-request-{index}", **config_fields)
        for index in range(4)
    ]
    plans = [
        SimpleNamespace(
            schema_version="1.1",
            smoke_run_index=1,
            request_preview=previews[index],
            maximum_attempts=2,
            maximum_cost_usd_per_attempt_exact="1",
            case_id="case-df79ea132113b863",
            selection_sha256=("721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"),
        )
        for index in range(4)
    ]
    usages = [
        SimpleNamespace(
            request_id=f"smoke-request-{index}",
            token_detail_accounting_evidence=None,
            openrouter_generation_id=f"generation-{index}",
            request_body_sha256=canonical_sha256({"body": index}),
            attempts=1,
            accounted_cost_usd_exact="0.1",
        )
        for index in range(4)
    ]
    candidate = SimpleNamespace(exact_model_id=CANDIDATE_ID)
    primary_lineage_target = SimpleNamespace(
        candidate_model_id=CANDIDATE_ID,
        candidate_root_lineage=f"sha256:{'1' * 64}",
        judge_model_id=PRIMARY_JUDGE_ID,
        judge_root_lineage=f"sha256:{'2' * 64}",
        public_lineage_bundle_sha256="4" * 64,
        public_lineage_manifest_file_sha256="5" * 64,
    )
    replay_lineage_target = SimpleNamespace(
        candidate_model_id=CANDIDATE_ID,
        candidate_root_lineage=f"sha256:{'1' * 64}",
        judge_model_id=REPLAY_JUDGE_ID,
        judge_root_lineage=f"sha256:{'3' * 64}",
        public_lineage_bundle_sha256="4" * 64,
        public_lineage_manifest_file_sha256="5" * 64,
    )
    primary = SimpleNamespace(
        schema_version="1.1",
        smoke_run_index=1,
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        run_sha256="7" * 64,
        candidate=candidate,
        judge=SimpleNamespace(exact_model_id=PRIMARY_JUDGE_ID),
        candidate_cost_plan=plans[0],
        judge_cost_plan=plans[1],
        candidate_report=SimpleNamespace(
            schema_version="1.1",
            smoke_run_index=1,
            result=SimpleNamespace(usage_record=usages[0]),
        ),
        prepared_adjudication=SimpleNamespace(target=primary_lineage_target),
        adjudication_report=SimpleNamespace(cases=(SimpleNamespace(usage_record=usages[1]),)),
    )
    replay = SimpleNamespace(
        schema_version="1.1",
        smoke_run_index=1,
        run_kind=CrossLineageAdjudicationRunKind.REPLAY,
        run_sha256="8" * 64,
        candidate=candidate,
        judge=SimpleNamespace(exact_model_id=REPLAY_JUDGE_ID),
        candidate_cost_plan=plans[2],
        judge_cost_plan=plans[3],
        candidate_report=SimpleNamespace(
            schema_version="1.1",
            smoke_run_index=1,
            result=SimpleNamespace(usage_record=usages[2]),
        ),
        prepared_adjudication=SimpleNamespace(target=replay_lineage_target),
        adjudication_report=SimpleNamespace(cases=(SimpleNamespace(usage_record=usages[3]),)),
    )
    entries = [
        SimpleNamespace(
            request_id=usage.request_id,
            reserved_usd="1",
            actual_cost_usd="0.1",
        )
        for usage in usages
    ]
    bundle = SimpleNamespace(
        schema_version="1.1",
        smoke_run_index=1,
        runs=(primary, replay),
        selected_case_id="case-df79ea132113b863",
        smoke_corpus_bundle_sha256=(
            "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"
        ),
        maximum_provider_attempt_count=8,
        execution_sequence_request_ids=(
            usages[0].request_id,
            usages[2].request_id,
            usages[1].request_id,
            usages[3].request_id,
        ),
        closed_ledger_evidence=SimpleNamespace(entries=tuple(entries)),
        bundle_sha256="9" * 64,
        model_dump=lambda **_kwargs: {"synthetic": "bundle"},
    )
    return bundle, previews, usages, entries


def _validate_fake_bundle(
    monkeypatch: pytest.MonkeyPatch,
    bundle: SimpleNamespace,
) -> object:
    monkeypatch.setattr(smoke_evidence_module, "_require_usage_preview_join", lambda *_a: None)
    monkeypatch.setattr(
        smoke_evidence_module,
        "_canonical_sha256",
        lambda _value: bundle.bundle_sha256,
    )
    validator = cast(
        Callable[[Any], object],
        AuthenticatedRunnerSmokeEvidenceBundle.protocol_is_exact_and_self_bound,
    )
    return validator(bundle)


def _rebound_smoke_usage(
    usage: UsageRecord,
    *,
    proof_kind: str,
    generation_id: str,
    request_body_sha256: str,
    request_id: str | None = None,
    privacy_source_sha256: str | None = None,
) -> UsageRecord:
    """Rebind one synthetic transport record to unique closed smoke coordinates."""

    payload = usage.model_dump(mode="python")
    payload.update(
        {
            "openrouter_generation_id": generation_id,
            "request_body_sha256": request_body_sha256,
            "request_id": usage.request_id if request_id is None else request_id,
        }
    )
    routing = dict(payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    routing.update(
        {
            "generation_id": generation_id,
            "privacy_source_proof_kind": proof_kind,
        }
    )
    if privacy_source_sha256 is not None:
        routing.update(
            {
                "privacy_profile": "SYNTHETIC_BENCHMARK",
                "privacy_source_classification": "SYNTHETIC_COMMITTED",
                "privacy_source_sha256": privacy_source_sha256,
            }
        )
    endpoint = usage.actual_provider_endpoint
    prompt_sha256 = usage.prompt_sha256
    schema_sha256 = usage.schema_sha256
    response_sha256 = usage.response_sha256
    validated_response_sha256 = usage.validated_response_sha256
    provider_policy_sha256 = routing.get("provider_policy_sha256")
    endpoint_snapshot_sha256 = routing.get("endpoint_snapshot_sha256")
    output_capability_sha256 = routing.get("output_capability_sha256")
    structured_output_mode = routing.get("structured_output_mode")
    request_shape_sha256 = routing.get("structured_output_request_shape_sha256")
    strict_protocol_sha256 = routing.get("structured_output_protocol_sha256")
    assert endpoint is not None
    assert prompt_sha256 is not None
    assert schema_sha256 is not None
    assert response_sha256 is not None
    assert validated_response_sha256 is not None
    assert isinstance(provider_policy_sha256, str)
    assert isinstance(endpoint_snapshot_sha256, str)
    assert isinstance(output_capability_sha256, str)
    assert isinstance(structured_output_mode, str)
    assert isinstance(request_shape_sha256, str)
    assert strict_protocol_sha256 is None or isinstance(strict_protocol_sha256, str)
    routing["structured_output"] = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(usage.configured_provider_endpoints),
        selected_provider_endpoint=endpoint,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        output_capability_sha256=output_capability_sha256,
        prompt_sha256=prompt_sha256,
        request_body_sha256=request_body_sha256,
        provider_policy_sha256=provider_policy_sha256,
        schema_sha256=schema_sha256,
        original_response_sha256=response_sha256,
        validated_response_sha256=validated_response_sha256,
        mode=StructuredOutputMode(structured_output_mode),
        request_shape_sha256=request_shape_sha256,
        strict_protocol_sha256=strict_protocol_sha256,
    )
    payload["routing"] = routing
    return bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
    )


def _rebound_generation(
    generation: OpenRouterGenerationEvidence,
    *,
    usage: UsageRecord,
) -> OpenRouterGenerationEvidence:
    payload = generation.model_dump(mode="json", exclude={"evidence_sha256"})
    payload.update(
        {
            "generation_id": usage.openrouter_generation_id,
            "request_id": usage.request_id,
        }
    )
    return OpenRouterGenerationEvidence.model_validate(
        {**payload, "evidence_sha256": canonical_sha256(payload)}
    )


def _current_smoke_usage_and_preview(
    usage: UsageRecord,
    *,
    index: int,
    user_prompt_sha256: str | None = None,
) -> tuple[UsageRecord, OpenRouterStructuredRequestCostPreview]:
    """Upgrade one synthetic smoke usage and cost preview to current token accounting."""

    if user_prompt_sha256 is not None and usage.user_prompt_sha256 != user_prompt_sha256:
        payload = usage.model_dump(mode="python")
        payload["user_prompt_sha256"] = user_prompt_sha256
        usage = bind_synthetic_usage_identity(
            rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
        )
    legacy_preview = _cost_preview_for_usage(usage, index=index)
    if (
        usage.user_prompt_sha256 != legacy_preview.user_prompt_sha256
        or usage.schema_sha256 != legacy_preview.response_schema_sha256
    ):
        payload = usage.model_dump(mode="python")
        payload.update(
            {
                "user_prompt_sha256": legacy_preview.user_prompt_sha256,
                "schema_sha256": legacy_preview.response_schema_sha256,
            }
        )
        usage = bind_synthetic_usage_identity(
            rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
        )
        legacy_preview = _cost_preview_for_usage(usage, index=index)
    legacy_plan = _v2_token_plan_for_usage(
        usage,
        endpoint_capability_sha256=legacy_preview.reasoning_capability_sha256,
    )
    reasoning_plan = legacy_plan.reasoning_plan
    assert reasoning_plan is not None
    usage = _as_v3_unknown_token_smoke_usage(usage, reasoning_plan=reasoning_plan)
    raw_plan = usage.routing.get("request_token_plan")
    plan = RequestTokenPlan.model_validate_json(
        json.dumps(raw_plan, sort_keys=True, separators=(",", ":"))
    )
    assert plan.schema_version == "3.0"
    assert plan.token_detail_accounting_method is not None
    assert plan.wire_max_tokens is not None
    preview_payload = legacy_preview.model_dump(mode="json", exclude={"preview_sha256"})
    preview_payload.update(
        {
            "schema_version": "1.1",
            "request_token_plan_projection_sha256": plan.plan_sha256,
            "token_detail_accounting_method": plan.token_detail_accounting_method,
            "wire_max_tokens": plan.wire_max_tokens,
        }
    )
    preview = OpenRouterStructuredRequestCostPreview.model_validate_json(
        json.dumps(
            {**preview_payload, "preview_sha256": canonical_sha256(preview_payload)},
            sort_keys=True,
            separators=(",", ":"),
        ),
        strict=True,
    )
    payload = usage.model_dump(mode="python")
    routing = dict(payload["routing"])
    routing.update(
        {
            "request_cost_preview_sha256": preview.preview_sha256,
            "request_cost_preview_maximum_cost_usd_per_attempt_exact": (
                preview.maximum_cost_usd_per_attempt_exact
            ),
            "request_cost_preview_maximum_cost_usd_all_attempts_exact": (
                preview.maximum_cost_usd_all_attempts_exact
            ),
        }
    )
    payload["routing"] = routing
    return reattest_synthetic_real_usage(UsageRecord.model_validate(payload)), preview


def _model_bound_to_smoke_usage(candidate: CandidateModel, usage: UsageRecord) -> CandidateModel:
    routing = usage.routing
    provider_name = routing.get("selected_provider_name")
    discovery_sha256 = routing.get("discovery_evidence_sha256")
    endpoint_sha256 = routing.get("endpoint_snapshot_sha256")
    metadata_sha256 = routing.get("model_metadata_snapshot_sha256")
    pricing_sha256 = routing.get("endpoint_pricing_sha256")
    capability_sha256 = routing.get("output_capability_sha256")
    mode = routing.get("structured_output_mode")
    assert usage.actual_model is not None
    assert usage.actual_provider_endpoint is not None
    assert isinstance(provider_name, str)
    assert isinstance(discovery_sha256, str)
    assert isinstance(endpoint_sha256, str)
    assert isinstance(metadata_sha256, str)
    assert isinstance(pricing_sha256, str)
    assert isinstance(capability_sha256, str)
    assert isinstance(mode, str)
    return CandidateModel.model_validate(
        {
            **candidate.model_dump(mode="python"),
            "canonical_model_slug": usage.actual_model,
            "discovery_evidence_sha256": discovery_sha256,
            "approved_provider_endpoint": usage.actual_provider_endpoint,
            "approved_provider_name": provider_name,
            "endpoint_snapshot_sha256": endpoint_sha256,
            "output_capability_sha256": capability_sha256,
            "model_metadata_snapshot_sha256": metadata_sha256,
            "pricing_snapshot_sha256": pricing_sha256,
            "structured_output_mode": mode,
        }
    )


def _current_candidate_smoke_report(
    suite: Any,
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    index: int,
) -> tuple[
    NoncreditingModelBenchmarkSmokeReport,
    OpenRouterStructuredRequestCostPreview,
]:
    smoke = load_authenticated_runner_smoke_corpus_bundle(SMOKE_CORPUS_PATH)
    full_source = _as_structural_real(_report(suite, CANDIDATE_ID))
    source_model_result = full_source.results[0]
    source_result = next(
        result for result in source_model_result.cases if result.case_id == smoke.case.case_id
    )
    template = _smoke_report(
        suite,
        run_kind=run_kind.value,
        model_id=CANDIDATE_ID,
    )
    source_usage = source_result.usage_record
    source_generation = source_result.generation_evidence
    assert source_usage is not None
    assert source_generation is not None
    descriptor = authenticated_runner_smoke_model_benchmark_request_descriptor(
        smoke_run_index=1,
        run_kind=run_kind.value,
        selection_sha256=smoke.bundle_sha256,
        case=smoke.case,
        target=source_model_result.target,
    )
    usage = _rebound_smoke_usage(
        source_usage,
        proof_kind="PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
        generation_id=f"candidate-smoke-generation-{index}",
        request_body_sha256=canonical_sha256({"candidate-smoke-body": index}),
        request_id=descriptor.logical_request_id,
        privacy_source_sha256=hashlib.sha256(smoke.case.source_excerpt.encode("utf-8")).hexdigest(),
    )
    usage, preview = _current_smoke_usage_and_preview(
        usage,
        index=index,
        user_prompt_sha256=hashlib.sha256(descriptor.user_prompt.encode("utf-8")).hexdigest(),
    )
    generation = _rebound_generation(source_generation, usage=usage)
    result = ModelBenchmarkCaseResult.model_validate(
        {
            **source_result.model_dump(mode="json"),
            "usage_record": usage.model_dump(mode="json"),
            "generation_evidence": generation.model_dump(mode="json"),
        }
    )
    payload = template.model_dump(mode="json", exclude={"report_sha256"})
    payload.update(
        {
            "schema_version": "1.2",
            "selected_case_sha256": canonical_sha256(smoke.case.model_dump(mode="json")),
            "selected_ground_truth_sha256": canonical_sha256(
                smoke.ground_truth_case.model_dump(mode="json")
            ),
            "target": source_model_result.target.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
        }
    )
    return (
        NoncreditingModelBenchmarkSmokeReport.model_validate(
            {**payload, "report_sha256": canonical_sha256(payload)}
        ),
        preview,
    )


def _canonical_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _sealed_current_smoke_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> AuthenticatedRunnerSmokeEvidenceBundle:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    smoke = load_authenticated_runner_smoke_corpus_bundle(SMOKE_CORPUS_PATH)
    monkeypatch.setattr(smoke_benchmark_fixtures, "SELECTION_SHA256", smoke.bundle_sha256)
    runs: list[AuthenticatedRunnerSmokeRunEvidence] = []
    for index, (run_kind, judge_id) in enumerate(
        (
            (CrossLineageAdjudicationRunKind.PRIMARY, PRIMARY_JUDGE_ID),
            (CrossLineageAdjudicationRunKind.REPLAY, REPLAY_JUDGE_ID),
        )
    ):
        candidate_report, candidate_preview = _current_candidate_smoke_report(
            suite,
            run_kind=run_kind,
            index=index,
        )
        candidate_usage = candidate_report.result.usage_record
        assert candidate_usage is not None
        candidate = _model_bound_to_smoke_usage(
            _candidate_registry((CANDIDATE_ID,)).candidates[0],
            candidate_usage,
        )
        judge = _judge(judge_id)
        prepared = prepare_noncrediting_cross_lineage_adjudication_smoke(
            public_lineage_capability=resolve_verified_public_model_lineage(),
            suite=suite,
            selected_case=smoke.case,
            selected_ground_truth=smoke.ground_truth_case,
            selection_sha256=smoke.bundle_sha256,
            candidate_report=candidate_report,
            judge=judge,
            run_kind=run_kind,
        )
        request = prepared.requests[0]
        response = build_cross_lineage_adjudication_response(
            request=request,
            dimension_outcomes=request.expected_dimension_outcomes,
            disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
            rationale="Provider-free sealed smoke replay fixture.",
        )
        judge_usage, judge_generation = _judge_usage_and_generation(
            case_index=index + 10,
            request=request,
            response=response,
            judge=judge,
        )
        judge_usage = _rebound_smoke_usage(
            judge_usage,
            proof_kind="PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
            generation_id=f"judge-smoke-generation-{index}",
            request_body_sha256=canonical_sha256({"judge-smoke-body": index}),
            request_id=adjudication_module._cross_lineage_adjudication_smoke_logical_request_id(
                request, 1
            ),
        )
        judge_usage, judge_preview = _current_smoke_usage_and_preview(
            judge_usage,
            index=index + 2,
        )
        judge_generation = _rebound_generation(judge_generation, usage=judge_usage)
        judge_result = build_cross_lineage_adjudication_case_result(
            request=request,
            response=response,
            usage_record=judge_usage,
            generation_evidence=judge_generation,
        )
        adjudication_report = build_cross_lineage_adjudication_report(
            prepared=prepared,
            results=(judge_result,),
        )
        candidate_plan = build_authenticated_runner_smoke_cost_plan(
            smoke_run_index=1,
            run_kind=run_kind,
            stage="CANDIDATE",
            case_id=smoke.case.case_id,
            selection_sha256=smoke.bundle_sha256,
            request_preview=candidate_preview,
        )
        judge_plan = build_authenticated_runner_smoke_cost_plan(
            smoke_run_index=1,
            run_kind=run_kind,
            stage="JUDGE",
            case_id=smoke.case.case_id,
            selection_sha256=smoke.bundle_sha256,
            request_preview=judge_preview,
        )
        candidate_generation = candidate_report.result.generation_evidence
        assert candidate_generation is not None
        runs.append(
            seal_authenticated_runner_smoke_run_evidence(
                smoke_run_index=1,
                run_kind=run_kind,
                candidate=candidate,
                judge=judge,
                candidate_cost_plan=candidate_plan,
                candidate_report=candidate_report,
                candidate_generation_refetch=candidate_generation,
                prepared_adjudication=prepared,
                judge_cost_plan=judge_plan,
                adjudication_report=adjudication_report,
                judge_generation_refetch=judge_generation,
            )
        )
    usages = tuple(
        usage
        for run in runs
        for usage in (
            run.candidate_report.result.usage_record,
            run.adjudication_report.cases[0].usage_record,
        )
        if usage is not None
    )
    plans = tuple(plan for run in runs for plan in (run.candidate_cost_plan, run.judge_cost_plan))
    entries = tuple(
        AuthenticatedCrossLineageLedgerEntryEvidence(
            request_id=usage.request_id,
            entry_sha256=canonical_sha256(
                {"smoke-ledger-entry": usage.request_id, "actual": usage.accounted_cost_usd_exact}
            ),
            reserved_usd=plan.maximum_cost_usd_per_attempt_exact,
            actual_cost_usd=cast(str, usage.accounted_cost_usd_exact),
        )
        for plan, usage in sorted(
            zip(plans, usages, strict=True),
            key=lambda item: item[1].request_id,
        )
    )
    interval_cost = sum((Decimal(item.actual_cost_usd) for item in entries), start=Decimal(0))
    interval_cost_text = _canonical_decimal(interval_cost)
    ledger = AuthenticatedCrossLineageLedgerIntervalEvidence(
        ledger_identity_sha256=canonical_sha256("smoke-replay-ledger"),
        initial_snapshot_sha256=canonical_sha256("smoke-replay-ledger-before"),
        final_snapshot_sha256=canonical_sha256("smoke-replay-ledger-after"),
        initial_spent_usd="0",
        interval_spent_usd=interval_cost_text,
        final_spent_usd=interval_cost_text,
        entries=entries,
    )
    return seal_authenticated_runner_smoke_evidence_bundle(
        smoke_run_index=1,
        smoke_corpus_bundle_sha256=smoke.bundle_sha256,
        parent_corpus_sha256=smoke.manifest.parent.corpus_sha256,
        parent_ground_truth_sha256=smoke.manifest.parent.ground_truth_sha256,
        effective_config_sha256=canonical_sha256("smoke-replay-effective-config"),
        selected_case_id=smoke.case.case_id,
        selected_case_count=1,
        parent_case_count=24,
        run_count=2,
        logical_request_count=4,
        maximum_provider_attempt_count=8,
        generation_refetch_count=4,
        execution_sequence_request_ids=(
            usages[0].request_id,
            usages[2].request_id,
            usages[1].request_id,
            usages[3].request_id,
        ),
        runs=tuple(runs),
        closed_ledger_evidence=ledger,
    )


def test_smoke_replay_preserves_strict_models_without_call_level_strict_datetime_drift() -> None:
    report = _smoke_report(load_model_benchmark_corpus(CORPUS_PATH))
    envelope = _CanonicalSmokeReportReplayEnvelope(report=report)
    raw = stable_json_bytes(envelope)

    replayed = _CanonicalSmokeReportReplayEnvelope.model_validate_json(raw)

    assert replayed == envelope
    assert stable_json_bytes(replayed) == raw
    with pytest.raises(ValidationError) as raised:
        _CanonicalSmokeReportReplayEnvelope.model_validate_json(raw, strict=True)
    assert {
        (tuple(error["loc"]), error["type"]) for error in raised.value.errors(include_url=False)
    } == {
        (("report", "result", "usage_record", "timestamp"), "datetime_type"),
        (("report", "result", "usage_record", "started_at"), "datetime_type"),
        (("report", "result", "usage_record", "ended_at"), "datetime_type"),
    }


def test_smoke_revalidator_round_trips_genuine_sealed_current_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _sealed_current_smoke_bundle(monkeypatch)
    raw = authenticated_runner_smoke_evidence_bytes(bundle)

    replayed = revalidate_authenticated_runner_smoke_evidence_bytes(raw)

    usages = tuple(
        usage
        for run in replayed.runs
        for usage in (
            run.candidate_report.result.usage_record,
            run.adjudication_report.cases[0].usage_record,
        )
        if usage is not None
    )
    assert type(replayed) is AuthenticatedRunnerSmokeEvidenceBundle
    assert replayed == bundle
    assert replayed.schema_version == "1.2"
    assert tuple(run.schema_version for run in replayed.runs) == ("1.2", "1.2")
    assert len(usages) == 4
    assert all(usage.token_detail_accounting_evidence is not None for usage in usages)
    assert authenticated_runner_smoke_evidence_bytes(replayed) == raw


def test_smoke_revalidator_omits_call_level_strict_and_requires_exact_parser_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b'{"synthetic":"bounded-parser-type-check"}\n'
    calls: list[tuple[bytes, dict[str, object]]] = []

    def wrong_type(
        _cls: type[AuthenticatedRunnerSmokeEvidenceBundle],
        value: bytes,
        **kwargs: object,
    ) -> object:
        calls.append((value, kwargs))
        return object()

    monkeypatch.setattr(
        AuthenticatedRunnerSmokeEvidenceBundle,
        "model_validate_json",
        classmethod(wrong_type),
    )

    with pytest.raises(AuthenticatedRunnerSmokeError, match="wrong exact type"):
        revalidate_authenticated_runner_smoke_evidence_bytes(raw)
    assert calls == [(raw, {})]


def test_smoke_revalidator_rejects_real_coercive_and_noncanonical_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical = authenticated_runner_smoke_evidence_bytes(_sealed_current_smoke_bundle(monkeypatch))
    attempts = b'"attempts": 1'
    assert attempts in canonical
    coercive = canonical.replace(attempts, b'"attempts": "1"', 1)

    with pytest.raises(AuthenticatedRunnerSmokeError, match="not canonical"):
        revalidate_authenticated_runner_smoke_evidence_bytes(coercive)
    with pytest.raises(AuthenticatedRunnerSmokeError, match="not canonical"):
        revalidate_authenticated_runner_smoke_evidence_bytes(b" " + canonical)


def test_smoke_revalidator_rejects_nonexact_byte_types_and_bounds() -> None:
    canonical = b'{"synthetic":"bounded-input-check"}\n'

    class ByteSubclass(bytes):
        pass

    for raw in (
        bytearray(canonical),
        memoryview(canonical),
        canonical.decode("utf-8"),
        ByteSubclass(canonical),
        b"",
        b"x" * (MAX_AUTHENTICATED_RUNNER_SMOKE_BUNDLE_BYTES + 1),
    ):
        with pytest.raises(AuthenticatedRunnerSmokeError):
            revalidate_authenticated_runner_smoke_evidence_bytes(cast(Any, raw))


def _fake_run_validator_subject(
    *,
    pending_registry_roots: bool = False,
) -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    if pending_registry_roots:
        candidate = _candidate_registry((CANDIDATE_ID,)).candidates[0]
        judge = _candidate_registry((PRIMARY_JUDGE_ID,)).candidates[0]
    else:
        candidate = _approved_candidate(CANDIDATE_ID)
        judge = _approved_candidate(PRIMARY_JUDGE_ID)
    documentary = require_independent_public_model_lineage(
        resolve_verified_public_model_lineage(),
        candidate.exact_model_id,
        judge.exact_model_id,
    )
    request_sha256 = "a" * 64
    candidate_usage = SimpleNamespace(
        request_id="candidate-request",
        token_detail_accounting_evidence=None,
        routing={
            "privacy_profile": "SYNTHETIC_BENCHMARK",
            "privacy_source_classification": "SYNTHETIC_COMMITTED",
            "privacy_source_sha256": smoke_evidence_module._SMOKE_SOURCE_SHA256,
            "privacy_source_proof_kind": ("PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK"),
        },
    )
    judge_usage = SimpleNamespace(
        request_id=f"authrunner.smoke.r1.judge.primary:{request_sha256}",
        token_detail_accounting_evidence=None,
    )
    embedded_candidate = SimpleNamespace(retrieved_at=NOW)
    embedded_judge = SimpleNamespace(retrieved_at=NOW)
    candidate_report = SimpleNamespace(
        schema_version="1.1",
        smoke_run_index=1,
        run_kind="PRIMARY",
        selection_sha256="b" * 64,
        report_sha256="c" * 64,
        corpus_sha256=smoke_evidence_module._PARENT_CORPUS_SHA256,
        ground_truth_sha256=smoke_evidence_module._PARENT_GROUND_TRUTH_SHA256,
        selected_case_sha256=smoke_evidence_module._SMOKE_CORPUS_CASE_SHA256,
        selected_ground_truth_sha256=(smoke_evidence_module._SMOKE_GROUND_TRUTH_CASE_SHA256),
        result=SimpleNamespace(
            case_id="case-df79ea132113b863",
            usage_record=candidate_usage,
            generation_evidence=embedded_candidate,
        ),
        target=SimpleNamespace(
            model_id=candidate.exact_model_id,
            root_lineage=candidate.root_lineage,
        ),
    )
    candidate_plan = SimpleNamespace(
        schema_version="1.1",
        smoke_run_index=1,
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        stage="CANDIDATE",
        selection_sha256="b" * 64,
        case_id="case-df79ea132113b863",
        request_preview=SimpleNamespace(
            logical_request_id=candidate_usage.request_id,
            exact_model_id=candidate.exact_model_id,
        ),
    )
    prepared = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        candidate_report_sha256=candidate_report.report_sha256,
        prepared_run_sha256="d" * 64,
        corpus_sha256=smoke_evidence_module._PARENT_CORPUS_SHA256,
        ground_truth_sha256=smoke_evidence_module._PARENT_GROUND_TRUTH_SHA256,
        case_ids=("case-df79ea132113b863",),
        requests=(
            SimpleNamespace(
                request_sha256=request_sha256,
                corpus_case_sha256=smoke_evidence_module._SMOKE_CORPUS_CASE_SHA256,
                ground_truth_case_sha256=(smoke_evidence_module._SMOKE_GROUND_TRUTH_CASE_SHA256),
            ),
        ),
        target=SimpleNamespace(
            candidate_model_id=candidate.exact_model_id,
            candidate_root_lineage=documentary.left_root_lineage,
            judge_model_id=judge.exact_model_id,
            judge_root_lineage=documentary.right_root_lineage,
        ),
    )
    judge_plan = SimpleNamespace(
        schema_version="1.1",
        smoke_run_index=1,
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        stage="JUDGE",
        selection_sha256=candidate_plan.selection_sha256,
        case_id=candidate_plan.case_id,
        request_preview=SimpleNamespace(
            logical_request_id=judge_usage.request_id,
            exact_model_id=judge.exact_model_id,
        ),
    )
    adjudication_report = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        prepared_run_sha256=prepared.prepared_run_sha256,
        candidate_report_sha256=candidate_report.report_sha256,
        cases=(
            SimpleNamespace(
                usage_record=judge_usage,
                generation_evidence=embedded_judge,
            ),
        ),
    )
    run = SimpleNamespace(
        schema_version="1.1",
        smoke_run_index=1,
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        candidate=candidate,
        judge=judge,
        candidate_cost_plan=candidate_plan,
        candidate_report=candidate_report,
        candidate_generation_refetch=SimpleNamespace(retrieved_at=NOW + timedelta(seconds=1)),
        prepared_adjudication=prepared,
        judge_cost_plan=judge_plan,
        adjudication_report=adjudication_report,
        judge_generation_refetch=SimpleNamespace(retrieved_at=NOW + timedelta(seconds=1)),
        run_sha256="e" * 64,
        model_dump=lambda **_kwargs: {"synthetic": "run"},
    )
    return run, prepared, candidate_report


def _validate_fake_run(monkeypatch: pytest.MonkeyPatch, run: SimpleNamespace) -> object:
    monkeypatch.setattr(
        smoke_evidence_module, "_require_generation_refetch", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        smoke_evidence_module,
        "_canonical_sha256",
        lambda _value: run.run_sha256,
    )
    validator = cast(
        Callable[[Any], object],
        AuthenticatedRunnerSmokeRunEvidence.run_is_exact_and_self_bound,
    )
    return validator(run)


def _usage_with_request_id(usage: UsageRecord, request_id: str) -> UsageRecord:
    payload = usage.model_dump(mode="python")
    payload["request_id"] = request_id
    routing = dict(payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    payload["routing"] = routing
    return bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
    )


class _StopAfterJudges(RuntimeError):
    pass


def _install_execution_order_harness(
    monkeypatch: pytest.MonkeyPatch,
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
    *,
    fail_second_candidate_delta: bool,
) -> tuple[list[str], OperatorSecrets]:
    smoke = launch.smoke_corpus
    candidate_plans = tuple(
        _candidate_smoke_plan(
            run_kind=kind,
            selection_sha256=smoke.bundle_sha256,
            case_id=smoke.case.case_id,
            index=index,
        )
        for index, kind in enumerate(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )
        )
    )
    inventory = AuthenticatedRunnerSmokePreflightInventory(
        smoke_run_index=launch.smoke_run_index,
        run_count=2,
        case_count=1,
        logical_request_count=4,
        maximum_attempts_per_logical_request=2,
        maximum_provider_attempt_count=8,
        generation_refetch_count=4,
        effective_config_sha256=launch.config.stable_hash(),
        initial_spent_usd=Decimal(0),
        operator_interval_tripwire_usd=Decimal("8"),
        operator_final_spent_tripwire_usd=Decimal("8"),
        candidate_cost_plans=cast(Any, candidate_plans),
        candidate_derived_interval_cost_cap_usd=Decimal("0.1"),
        candidate_derived_final_spent_cap_usd=Decimal("0.1"),
    )
    source = _as_structural_real(_report(launch.benchmark_suite, CANDIDATE_ID))
    base_usages = tuple(item.usage_record for item in source.results[0].cases[:4])
    assert all(item is not None for item in base_usages)
    request_sha256s = ("a" * 64, "b" * 64)
    candidate_usages = tuple(
        _usage_with_request_id(
            cast(UsageRecord, base_usages[index]), plan.request_preview.logical_request_id
        )
        for index, plan in enumerate(candidate_plans)
    )
    judge_plans = tuple(
        _judge_smoke_plan(
            run_kind=kind,
            selection_sha256=smoke.bundle_sha256,
            case_id=smoke.case.case_id,
            request_sha256=request_sha256s[index],
            index=index + 2,
        )
        for index, kind in enumerate(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )
        )
    )
    judge_usages = tuple(
        _usage_with_request_id(
            cast(UsageRecord, base_usages[index + 2]),
            plan.request_preview.logical_request_id,
        )
        for index, plan in enumerate(judge_plans)
    )
    events: list[str] = []

    class _FakeAdapter:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def candidate(self, *, plan: Any, cost_plan: Any) -> tuple[Any, Any]:
            index = 0 if plan.run_kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
            events.append(f"C:{plan.run_kind.value}")
            assert cost_plan == candidate_plans[index]
            usage = candidate_usages[index]
            launch.usage.add(usage)
            report = SimpleNamespace(
                report_sha256=canonical_sha256({"candidate": index}),
                result=SimpleNamespace(usage_record=usage),
            )
            return report, SimpleNamespace(retrieved_at=NOW)

        async def prepare_judges(self, prepared: tuple[Any, ...]) -> None:
            events.append("PREPARE:PRIMARY,REPLAY")
            assert tuple(item.plan.run_kind for item in prepared) == (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )

        async def judge(self, *, prepared: Any, cost_plan: Any) -> tuple[Any, Any]:
            index = 0 if prepared.plan.run_kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
            events.append(f"J:{prepared.plan.run_kind.value}")
            assert cost_plan == judge_plans[index]
            usage = judge_usages[index]
            launch.usage.add(usage)
            report = SimpleNamespace(cases=(SimpleNamespace(usage_record=usage),))
            return report, SimpleNamespace(retrieved_at=NOW)

        async def close(self) -> None:
            events.append("ADAPTER:CLOSE")

    async def adopt(**_kwargs: object) -> None:
        return None

    def prepare(**kwargs: object) -> SimpleNamespace:
        kind = cast(CrossLineageAdjudicationRunKind, kwargs["run_kind"])
        index = 0 if kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
        return SimpleNamespace(
            run_kind=kind,
            requests=(SimpleNamespace(request_sha256=request_sha256s[index]),),
        )

    def judge_plan(*, prepared: Any, **_kwargs: object) -> Any:
        index = 0 if prepared.plan.run_kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
        events.append(f"PLAN:{prepared.plan.run_kind.value}")
        return judge_plans[index]

    candidate_delta_count = 0

    def exact_delta(*, label: str, **_kwargs: object) -> None:
        nonlocal candidate_delta_count
        if label == "candidate":
            candidate_delta_count += 1
            if fail_second_candidate_delta and candidate_delta_count == 2:
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "synthetic second-candidate ledger anomaly"
                )

    def aggregate(**_kwargs: object) -> None:
        events.append("ADMIT:BOTH")

    def seal_run(**kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            candidate_report=kwargs["candidate_report"],
            adjudication_report=kwargs["adjudication_report"],
        )

    def stop_after_judges(*_args: object, **_kwargs: object) -> None:
        raise _StopAfterJudges

    monkeypatch.setattr(
        smoke_runtime_module,
        "preflight_authenticated_runner_smoke_openrouter_launch",
        lambda _launch: inventory,
    )
    monkeypatch.setattr(smoke_runtime_module, "_adopt_ledger_baseline", adopt)
    monkeypatch.setattr(
        smoke_runtime_module, "begin_cross_lineage_ledger_interval", lambda _l: object()
    )
    monkeypatch.setattr(smoke_runtime_module, "_SmokeOpenRouterAdapter", _FakeAdapter)
    monkeypatch.setattr(
        smoke_runtime_module,
        "prepare_noncrediting_cross_lineage_adjudication_smoke",
        prepare,
    )
    monkeypatch.setattr(smoke_runtime_module, "_judge_cost_plan", judge_plan)
    monkeypatch.setattr(
        smoke_runtime_module,
        "_require_exact_smoke_callback_ledger_delta",
        exact_delta,
    )
    monkeypatch.setattr(smoke_runtime_module, "_require_aggregate_judge_admission", aggregate)
    monkeypatch.setattr(
        smoke_runtime_module, "seal_authenticated_runner_smoke_run_evidence", seal_run
    )
    monkeypatch.setattr(
        smoke_runtime_module,
        "close_cross_lineage_ledger_interval",
        stop_after_judges,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-order-test"})
    return events, secrets


def test_smoke_callback_ledger_delta_requires_usage_cost_equality() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _as_structural_real(_report(suite, "deepseek/deepseek-v4-pro-0813"))
    usage = report.results[0].cases[0].usage_record
    assert usage is not None
    assert usage.accounted_cost_usd_exact is not None
    assert usage.attempts == 1
    actual = Decimal(usage.accounted_cost_usd_exact)
    entry = CostEntry(
        request_id=usage.request_id,
        reservation_id="synthetic-reservation",
        status=CostEntryStatus.RECONCILED,
        reserved_usd=Decimal("1"),
        actual_cost_usd=actual,
        accounted_cost_usd=actual,
        release_reason=None,
        created_at=NOW,
        updated_at=NOW,
    )
    before = _snapshot(entries=(), spent=Decimal(0))
    after = _snapshot(entries=(entry,), spent=actual)

    _require_exact_smoke_callback_ledger_delta(
        before=before,
        after=after,
        records=(usage,),
        label="candidate",
    )

    drift = Decimal("0.000001")
    mismatched_entry = CostEntry(
        **{
            **entry.__dict__,
            "actual_cost_usd": actual + drift,
            "accounted_cost_usd": actual + drift,
        }
    )
    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="ledger delta is not exact",
    ):
        _require_exact_smoke_callback_ledger_delta(
            before=before,
            after=_snapshot(entries=(mismatched_entry,), spent=actual + drift),
            records=(usage,),
            label="candidate",
        )


def test_smoke_preflight_lineage_requires_exact_documentary_roots() -> None:
    capability = resolve_verified_public_model_lineage()
    candidate = _approved_candidate("deepseek/deepseek-v4-pro-0813")
    primary = _approved_candidate("minimax/minimax-m3")
    replay = _approved_candidate("moonshotai/kimi-k3")

    _require_three_distinct_roots(
        capability,
        candidate=candidate,
        judges=(primary, replay),
    )

    wrong_review = seal_operator_lineage_review(
        status=LineageReviewStatus.APPROVED,
        reviewed_model_ids=(primary.exact_model_id,),
        rationale="Synthetic negative with a wrong but internally consistent root.",
        root_lineage=f"sha256:{'f' * 64}",
        reviewed_by="synthetic-unit-reviewer",
        reviewed_at=NOW,
        evidence_sha256="f" * 64,
    )
    wrong_primary = CandidateModel.model_validate(
        {
            **primary.model_dump(mode="python"),
            "root_lineage": wrong_review.root_lineage,
            "lineage_review": wrong_review,
        },
        strict=True,
    )
    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="projection",
    ):
        _require_three_distinct_roots(
            capability,
            candidate=candidate,
            judges=(wrong_primary, replay),
        )


def test_smoke_preflight_lineage_fills_all_three_pending_null_roots_from_public_evidence() -> None:
    capability = resolve_verified_public_model_lineage()
    candidate = _candidate_registry((CANDIDATE_ID,)).candidates[0]
    primary = _candidate_registry((PRIMARY_JUDGE_ID,)).candidates[0]
    replay = _candidate_registry((REPLAY_JUDGE_ID,)).candidates[0]
    assert tuple(model.root_lineage for model in (candidate, primary, replay)) == (None, None, None)
    assert tuple(model.lineage_review.status for model in (candidate, primary, replay)) == (
        LineageReviewStatus.PENDING,
        LineageReviewStatus.PENDING,
        LineageReviewStatus.PENDING,
    )

    _require_three_distinct_roots(
        capability,
        candidate=candidate,
        judges=(primary, replay),
    )


def test_smoke_preflight_lineage_rejects_rejected_null_review() -> None:
    capability = resolve_verified_public_model_lineage()
    candidate = _candidate_registry((CANDIDATE_ID,)).candidates[0]
    primary = _candidate_registry((PRIMARY_JUDGE_ID,)).candidates[0]
    replay = _candidate_registry((REPLAY_JUDGE_ID,)).candidates[0]
    rejected_review = seal_operator_lineage_review(
        status=LineageReviewStatus.REJECTED,
        reviewed_model_ids=(primary.exact_model_id,),
        rationale="Synthetic explicit negative lineage decision.",
        reviewed_by="synthetic-unit-reviewer",
        reviewed_at=NOW,
        evidence_sha256="f" * 64,
    )
    rejected_primary = CandidateModel.model_validate(
        {
            **primary.model_dump(mode="python"),
            "lineage_review": rejected_review,
        },
        strict=True,
    )

    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="review does not permit",
    ):
        _require_three_distinct_roots(
            capability,
            candidate=candidate,
            judges=(rejected_primary, replay),
        )


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "forgery",
    ("model_id", "independent", "repeated_root", "duplicate_root", "bundle_pin"),
)
def test_smoke_preflight_lineage_rejects_forged_three_projection_inventory(
    monkeypatch: pytest.MonkeyPatch,
    forgery: str,
) -> None:
    capability = resolve_verified_public_model_lineage()
    candidate = _candidate_registry((CANDIDATE_ID,)).candidates[0]
    primary = _candidate_registry((PRIMARY_JUDGE_ID,)).candidates[0]
    replay = _candidate_registry((REPLAY_JUDGE_ID,)).candidates[0]
    projections = [
        require_independent_public_model_lineage(
            capability,
            left.exact_model_id,
            right.exact_model_id,
        )
        for left, right in ((candidate, primary), (candidate, replay), (primary, replay))
    ]
    if forgery == "model_id":
        projections[0] = replace(projections[0], left_exact_model_id=REPLAY_JUDGE_ID)
    elif forgery == "independent":
        projections[0] = replace(projections[0], independent=cast(Any, False))
    elif forgery == "repeated_root":
        projections[1] = replace(projections[1], left_root_lineage=f"sha256:{'0' * 64}")
    elif forgery == "duplicate_root":
        duplicate = projections[0].right_root_lineage
        projections[1] = replace(projections[1], right_root_lineage=duplicate)
        projections[2] = replace(projections[2], right_root_lineage=duplicate)
    else:
        projections[2] = replace(projections[2], bundle_sha256="f" * 64)
    projection_iterator = iter(projections)

    def forged_projection(
        *_args: object,
        **_kwargs: object,
    ) -> VerifiedIndependentPublicModelLineageProjection:
        return next(projection_iterator)

    monkeypatch.setattr(
        smoke_runtime_module,
        "require_independent_public_model_lineage",
        forged_projection,
    )
    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="non-independent projection",
    ):
        _require_three_distinct_roots(
            capability,
            candidate=candidate,
            judges=(primary, replay),
        )


def test_smoke_execution_lineage_mismatch_precedes_secrets_provider_and_ledger_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    pending_primary = launch.run_plans[0].judge
    wrong_review = seal_operator_lineage_review(
        status=LineageReviewStatus.APPROVED,
        reviewed_model_ids=(pending_primary.exact_model_id,),
        rationale="Synthetic negative with a wrong documentary root.",
        root_lineage=f"sha256:{'f' * 64}",
        reviewed_by="synthetic-unit-reviewer",
        reviewed_at=NOW,
        evidence_sha256="f" * 64,
    )
    wrong_primary = CandidateModel.model_validate(
        {
            **pending_primary.model_dump(mode="python"),
            "root_lineage": wrong_review.root_lineage,
            "lineage_review": wrong_review,
        },
        strict=True,
    )

    def registry_model(**kwargs: object) -> CandidateModel:
        registry = cast(Any, kwargs["registry"])
        model = registry.candidates[0]
        return wrong_primary if model.exact_model_id == PRIMARY_JUDGE_ID else model

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError(
            "lineage mismatch must reject before cost derivation or provider setup"
        )

    monkeypatch.setattr(smoke_runtime_module, "_require_singleton_registry", registry_model)
    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "_SmokeOpenRouterAdapter", forbidden)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-lineage-test"})
    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="non-independent projection",
        ):
            asyncio.run(
                execute_authenticated_runner_smoke_openrouter(
                    launch=launch,
                    operator_secrets=secrets,
                )
            )
        assert secrets.openrouter_api_key_present is True
        assert secrets.cleared is False
        assert ledger.snapshot() == before
        assert launch.usage.records == []
    finally:
        secrets.clear()


def test_callback_ledger_delta_rejects_equal_aggregate_with_wrong_per_usage_costs() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _as_structural_real(_report(suite, CANDIDATE_ID))
    first = report.results[0].cases[0].usage_record
    second = report.results[0].cases[1].usage_record
    assert first is not None
    assert second is not None
    first = first.model_copy(
        update={
            "accounted_cost_usd": 0.01,
            "accounted_cost_usd_exact": "0.01",
            "attempts": 1,
        }
    )
    second = second.model_copy(
        update={
            "accounted_cost_usd": 0.02,
            "accounted_cost_usd_exact": "0.02",
            "attempts": 1,
        }
    )
    wrong_entries = tuple(
        CostEntry(
            request_id=usage.request_id,
            reservation_id=f"reservation-{index}",
            status=CostEntryStatus.RECONCILED,
            reserved_usd=Decimal("1"),
            actual_cost_usd=Decimal("0.015"),
            accounted_cost_usd=Decimal("0.015"),
            release_reason=None,
            created_at=NOW,
            updated_at=NOW,
        )
        for index, usage in enumerate((first, second))
    )
    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="ledger delta is not exact",
    ):
        _require_exact_smoke_callback_ledger_delta(
            before=_snapshot(entries=(), spent=Decimal(0)),
            after=_snapshot(entries=wrong_entries, spent=Decimal("0.03")),
            records=(first, second),
            label="aggregate",
        )

    exact_entries = tuple(
        CostEntry(
            **{
                **entry.__dict__,
                "actual_cost_usd": Decimal(usage.accounted_cost_usd_exact or "0"),
                "accounted_cost_usd": Decimal(usage.accounted_cost_usd_exact or "0"),
            }
        )
        for entry, usage in zip(wrong_entries, (first, second), strict=True)
    )
    _require_exact_smoke_callback_ledger_delta(
        before=_snapshot(entries=(), spent=Decimal(0)),
        after=_snapshot(entries=exact_entries, spent=Decimal("0.03")),
        records=(first, second),
        label="aggregate",
    )


def test_usage_preview_join_binds_full_token_reasoning_discovery_and_output_projection() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _as_structural_real(_report(suite, CANDIDATE_ID))
    usage = report.results[0].cases[0].usage_record
    assert usage is not None
    preview = _cost_preview_for_usage(usage, index=0)
    bound = _usage_with_cost_preview(usage, preview)

    smoke_evidence_module._require_usage_preview_join(bound, preview)

    drifted = _replace_preview(
        preview,
        output_capability_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="exact cost preview"):
        smoke_evidence_module._require_usage_preview_join(bound, drifted)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    ("field", "expected"),
    (
        (
            "global_input_token_budget",
            "smoke shared budget global input token budget differs from configuration",
        ),
        (
            "global_output_token_budget",
            "smoke shared budget global output token budget differs from configuration",
        ),
    ),
)
def test_smoke_preflight_rejects_aggregate_token_budget_drift_before_cost_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    field: str,
    expected: str,
) -> None:
    launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    configured = getattr(launch.config.token_budgets, field)
    setattr(launch.budget, field, configured + 1)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("token-budget drift must reject before cost or provider setup")

    monkeypatch.setattr(smoke_runtime_module, "_require_singleton_registry", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden)

    with pytest.raises(AuthenticatedRunnerSmokeOpenRouterError) as caught:
        preflight_authenticated_runner_smoke_openrouter_launch(launch)

    assert str(caught.value) == expected
    assert ledger.snapshot() == before
    assert launch.usage.records == []


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    ("field", "expected"),
    (
        (
            "max_output_tokens",
            "smoke shared budget maximum output tokens differ from configuration",
        ),
        (
            "conservative_rate",
            "smoke shared budget conservative rate differs from configuration",
        ),
        (
            "max_requests_per_agent",
            "smoke shared budget request cap differs from configuration",
        ),
        (
            "require_endpoint_cost_bound",
            "smoke shared budget must require endpoint cost binding",
        ),
    ),
)
def test_smoke_preflight_rejects_execution_budget_drift_before_cost_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    field: str,
    expected: str,
) -> None:
    launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    value = getattr(launch.budget, field)
    setattr(launch.budget, field, False if field == "require_endpoint_cost_bound" else value + 1)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("budget drift must reject before cost or provider setup")

    monkeypatch.setattr(smoke_runtime_module, "_require_singleton_registry", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden)

    with pytest.raises(AuthenticatedRunnerSmokeOpenRouterError) as caught:
        preflight_authenticated_runner_smoke_openrouter_launch(launch)

    assert str(caught.value) == expected
    assert ledger.snapshot() == before
    assert launch.usage.records == []


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    ("field", "value"),
    (
        ("per_model_usd_caps", {CANDIDATE_ID: Decimal("1")}),
        ("per_role_usd_caps", {"model_benchmark": Decimal("1")}),
    ),
)
def test_smoke_preflight_rejects_scoped_cost_budget_drift_before_cost_derivation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    field: str,
    value: dict[str, Decimal],
) -> None:
    launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    setattr(launch.budget, field, value)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("scoped budget drift must reject before cost or provider setup")

    monkeypatch.setattr(smoke_runtime_module, "_require_singleton_registry", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden)

    with pytest.raises(AuthenticatedRunnerSmokeOpenRouterError) as caught:
        preflight_authenticated_runner_smoke_openrouter_launch(launch)

    assert str(caught.value) == "smoke shared budget scoped cost budgets differ from configuration"
    assert ledger.snapshot() == before
    assert launch.usage.records == []


@pytest.mark.asyncio
async def test_smoke_cli_budget_constructs_live_client_without_egress_or_budget_mutation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    base_launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    assert base_launch.budget.atomic_ledger is not None
    budget, usage = cli_module._budget_and_usage(
        base_launch.config,
        ledger_path=base_launch.budget.atomic_ledger.path,
        require_endpoint_cost_bound=True,
    )
    launch = replace(base_launch, budget=budget, usage=usage)
    assert budget.atomic_ledger is not None
    before = budget.atomic_ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-unit-key"})
    adapter = smoke_runtime_module._SmokeOpenRouterAdapter(launch=launch, secrets=secrets)
    client = adapter._new_candidate_client(launch.candidate_registry.candidates[0])
    try:
        assert client.token_budgets == launch.config.token_budgets
        assert client.budget is budget
        assert client.usage is usage
        assert usage.records == []
        assert budget.atomic_ledger.snapshot() == before
    finally:
        await client.close()
        await adapter.close()
        secrets.clear()


@pytest.mark.asyncio
async def test_smoke_candidate_revokes_generation_capability_after_detached_refetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    report = await asyncio.to_thread(
        _smoke_report,
        launch.benchmark_suite,
        model_id=CANDIDATE_ID,
    )
    usage = report.result.usage_record
    assert usage is not None
    request = generation_evidence_module.GenerationVerificationRequest(
        benchmark_report_sha256=report.report_sha256,
        case_id=report.result.case_id,
        exact_model_id=usage.requested_model,
        canonical_model_id=cast(str, usage.routing["canonical_model"]),
        catalog_identity_binding_sha256=cast(
            str,
            usage.routing["catalog_identity_binding_sha256"],
        ),
        discovery_evidence_sha256=cast(str, usage.routing["discovery_evidence_sha256"]),
        expected_provider_name=cast(str, usage.routing["selected_provider_name"]),
        usage_record=usage,
    )
    issued: list[tuple[TrustedGenerationVerification, tuple[Any, ...]]] = []

    class _FakeClient:
        closed = False

        async def create_trusted_generation_verification(
            self,
            requests: tuple[Any, ...],
        ) -> TrustedGenerationVerification:
            generation = report.result.generation_evidence
            assert generation is not None
            capability = generation_evidence_module._issue_trusted_generation_verification(
                requests=requests,
                attestations=(generation,),
                verification_started_at=generation.retrieved_at,
            )
            issued.append((capability, requests))
            return capability

        async def close(self) -> None:
            self.closed = True

    client = _FakeClient()

    async def refresh(**_kwargs: object) -> None:
        return None

    async def execute_smoke(**_kwargs: object) -> Any:
        return report

    monkeypatch.setattr(
        smoke_runtime_module._SmokeOpenRouterAdapter,
        "_new_candidate_client",
        lambda *_args, **_kwargs: client,
    )
    monkeypatch.setattr(smoke_runtime_module, "_refresh_and_register_exact_route", refresh)
    monkeypatch.setattr(
        smoke_runtime_module,
        "_generation_request",
        lambda **_kwargs: request,
    )
    monkeypatch.setattr(
        smoke_runtime_module,
        "execute_noncrediting_model_benchmark_smoke",
        execute_smoke,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-smoke-revoke-test"})
    adapter = smoke_runtime_module._SmokeOpenRouterAdapter(launch=launch, secrets=secrets)
    try:
        returned, refetch = await adapter.candidate(
            plan=launch.run_plans[0],
            cost_plan=cast(Any, SimpleNamespace(request_preview=object())),
        )
        assert returned is report
        assert refetch == report.result.generation_evidence
        assert client.closed
        assert len(issued) == 1
        capability, requests = issued[0]
        request = requests[0]
        with pytest.raises(GenerationEvidenceValidationError, match="not trusted"):
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
    finally:
        await adapter.close()
        secrets.clear()


@pytest.mark.asyncio
async def test_smoke_candidate_reconciles_unknown_envelope_before_trusted_refetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    source = await asyncio.to_thread(
        _smoke_report,
        launch.benchmark_suite,
        model_id=CANDIDATE_ID,
    )
    generation = source.result.generation_evidence
    assert generation is not None
    usage = SimpleNamespace(token_detail_accounting_evidence=object())
    report = SimpleNamespace(
        report_sha256=source.report_sha256,
        result=SimpleNamespace(usage_record=usage, generation_evidence=generation),
    )
    request = SimpleNamespace(
        benchmark_report_sha256=source.report_sha256,
        case_id=source.result.case_id,
        exact_model_id=CANDIDATE_ID,
        canonical_model_id=CANDIDATE_ID,
        catalog_identity_binding_sha256="a" * 64,
        discovery_evidence_sha256="b" * 64,
        usage_record=usage,
        expected_provider_name="Fixture Provider",
    )
    events: list[str] = []

    class _Capability:
        def attestation_for(self, **_kwargs: object) -> OpenRouterGenerationEvidence:
            events.append("ATTEST")
            return generation

    class _FakeClient:
        async def create_trusted_generation_verification(
            self,
            _requests: tuple[object, ...],
        ) -> _Capability:
            events.append("ISSUE")
            return _Capability()

        async def close(self) -> None:
            events.append("CLOSE")

    async def refresh(**_kwargs: object) -> None:
        return None

    async def execute_smoke(**_kwargs: object) -> object:
        return report

    def reconcile(
        observed: OpenRouterGenerationEvidence,
        **kwargs: object,
    ) -> OpenRouterGenerationEvidence:
        candidate = launch.candidate_registry.candidates[0]
        assert observed is generation
        assert kwargs["usage_record"] is usage
        assert kwargs["expected_exact_model"] == candidate.exact_model_id
        assert kwargs["expected_canonical_model"] == candidate.canonical_model_slug
        assert kwargs["expected_provider_name"] == candidate.approved_provider_name
        events.append("RECONCILE")
        return observed

    monkeypatch.setattr(
        smoke_runtime_module._SmokeOpenRouterAdapter,
        "_new_candidate_client",
        lambda *_args, **_kwargs: _FakeClient(),
    )
    monkeypatch.setattr(smoke_runtime_module, "_refresh_and_register_exact_route", refresh)
    monkeypatch.setattr(
        smoke_runtime_module,
        "execute_noncrediting_model_benchmark_smoke",
        execute_smoke,
    )
    monkeypatch.setattr(smoke_runtime_module, "_generation_request", lambda **_kwargs: request)
    monkeypatch.setattr(
        smoke_runtime_module,
        "reconcile_noncrediting_smoke_generation_evidence",
        reconcile,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-smoke-envelope-test"})
    adapter = smoke_runtime_module._SmokeOpenRouterAdapter(
        launch=launch,
        secrets=secrets,
        _generation_revoke=lambda _capability: events.append("REVOKE"),
    )
    try:
        returned, refetch = await adapter.candidate(
            plan=launch.run_plans[0],
            cost_plan=cast(Any, SimpleNamespace(request_preview=object())),
        )
        assert returned is report
        assert refetch is generation
        assert events == ["RECONCILE", "ISSUE", "ATTEST", "REVOKE", "CLOSE"]
    finally:
        await adapter.close()
        secrets.clear()


@pytest.mark.asyncio
async def test_smoke_judge_revokes_generation_capability_after_detached_refetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_smoke_config(config_factory), tmp_path=tmp_path)
    candidate_report = await asyncio.to_thread(
        _smoke_report,
        launch.benchmark_suite,
        model_id=CANDIDATE_ID,
    )
    plan = launch.run_plans[0]
    case = launch.benchmark_suite.cases[0]
    truth = launch.benchmark_suite.ground_truth_case(case.case_id)
    prepared_adjudication = prepare_noncrediting_cross_lineage_adjudication_smoke(
        public_lineage_capability=resolve_verified_public_model_lineage(),
        suite=launch.benchmark_suite,
        selected_case=case,
        selected_ground_truth=truth,
        selection_sha256=SELECTION_SHA256,
        candidate_report=candidate_report,
        judge=plan.judge,
        run_kind=plan.run_kind,
    )
    request = prepared_adjudication.requests[0]
    response = build_cross_lineage_adjudication_response(
        request=request,
        dimension_outcomes=request.expected_dimension_outcomes,
        disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
        rationale="Synthetic smoke judge generation-revocation regression.",
    )
    usage, generation = _judge_usage_and_generation(
        case_index=0,
        request=request,
        response=response,
        judge=plan.judge,
    )
    smoke_request_id = adjudication_module._cross_lineage_adjudication_smoke_logical_request_id(
        request, 1
    )
    usage_payload = usage.model_dump(mode="python")
    usage_payload["request_id"] = smoke_request_id
    routing = dict(usage_payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    routing["privacy_source_proof_kind"] = "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION"
    usage_payload["routing"] = routing
    smoke_usage = bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(usage_payload))
    )
    generation_payload = generation.model_dump(mode="json", exclude={"evidence_sha256"})
    generation_payload["request_id"] = smoke_request_id
    smoke_generation = OpenRouterGenerationEvidence.model_validate(
        {
            **generation_payload,
            "evidence_sha256": canonical_sha256(generation_payload),
        }
    )
    result = build_cross_lineage_adjudication_case_result(
        request=request,
        response=response,
        usage_record=smoke_usage,
        generation_evidence=smoke_generation,
    )
    issued: list[tuple[TrustedGenerationVerification, tuple[Any, ...]]] = []

    class _FakeClient:
        closed = False

        async def create_trusted_generation_verification(
            self,
            requests: tuple[Any, ...],
        ) -> TrustedGenerationVerification:
            capability = generation_evidence_module._issue_trusted_generation_verification(
                requests=requests,
                attestations=(smoke_generation,),
                verification_started_at=smoke_generation.retrieved_at,
            )
            issued.append((capability, requests))
            return capability

        async def close(self) -> None:
            self.closed = True

    async def execute_judge(**_kwargs: object) -> tuple[Any, ...]:
        return (result,)

    client = _FakeClient()
    monkeypatch.setattr(
        smoke_runtime_module,
        "execute_noncrediting_cross_lineage_adjudication_smoke_requests",
        execute_judge,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-smoke-revoke-test"})
    adapter = smoke_runtime_module._SmokeOpenRouterAdapter(launch=launch, secrets=secrets)
    cast(Any, adapter)._judge_clients[plan.run_kind] = client
    prepared = smoke_runtime_module._PreparedSmokeRun(
        plan=plan,
        candidate_cost_plan=cast(Any, object()),
        candidate_report=candidate_report,
        candidate_generation_refetch=cast(
            OpenRouterGenerationEvidence,
            candidate_report.result.generation_evidence,
        ),
        prepared_adjudication=prepared_adjudication,
    )
    try:
        report, refetch = await adapter.judge(
            prepared=prepared,
            cost_plan=cast(Any, SimpleNamespace(request_preview=object())),
        )
        assert report.cases == (result,)
        assert refetch == smoke_generation
        assert client.closed
        assert len(issued) == 1
        capability, requests = issued[0]
        verification_request = requests[0]
        with pytest.raises(GenerationEvidenceValidationError, match="not trusted"):
            capability.attestation_for(
                benchmark_report_sha256=verification_request.benchmark_report_sha256,
                case_id=verification_request.case_id,
                exact_model_id=verification_request.exact_model_id,
                canonical_model_id=verification_request.canonical_model_id,
                catalog_identity_binding_sha256=(
                    verification_request.catalog_identity_binding_sha256
                ),
                discovery_evidence_sha256=verification_request.discovery_evidence_sha256,
                usage_record=verification_request.usage_record,
                expected_provider_name=verification_request.expected_provider_name,
            )
    finally:
        await adapter.close()
        secrets.clear()


@pytest.mark.asyncio
async def test_live_route_preflight_refreshes_all_roles_without_completion_or_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    models = (
        launch.candidate_registry.candidates[0],
        launch.run_plans[0].judge,
        launch.run_plans[1].judge,
    )
    factory = _install_live_route_client_factory(
        monkeypatch,
        launch,
        canonical_shape_models={item.exact_model_id for item in models},
    )

    def forbidden_proof(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("metadata-only route probes must not issue request-source proof")

    monkeypatch.setattr(
        smoke_runtime_module,
        "prove_pinned_noncrediting_smoke_model_benchmark_source",
        forbidden_proof,
    )
    monkeypatch.setattr(
        smoke_runtime_module,
        "prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source",
        forbidden_proof,
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    try:
        result = await preflight_authenticated_runner_smoke_live_routes(
            launch=launch,
            operator_secrets=secrets,
            explicitly_allow_metadata_egress=True,
        )
        assert result.exact_model_ids == tuple(item.exact_model_id for item in models)
        assert result.logical_metadata_get_count == 15
        assert result.maximum_metadata_provider_attempt_count == 30
        assert len(factory.clients) == 3
        assert factory.request_bodies == []
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert secrets.cleared
        assert all(client._client.is_closed for client in factory.clients)
        assert all(not client._credential and not client._headers for client in factory.clients)
        assert [
            client.registered_model_identity_snapshot(model.exact_model_id).requested_slug
            for client, model in zip(factory.clients, models, strict=True)
        ] == [item.exact_model_id for item in models]
        assert factory.metadata_requests == [
            path
            for model in models
            for path in (
                "/api/v1/key",
                "/api/v1/models",
                f"/api/v1/model/{model.exact_model_id}",
                f"/api/v1/models/{model.exact_model_id}/endpoints",
                "/api/v1/endpoints/zdr",
            )
        ]
    finally:
        await factory.close()


@pytest.mark.asyncio
async def test_live_route_launch_preflight_retains_pure_synthetic_privacy_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    observed: list[tuple[AuditConfig, object, bool]] = []
    original = cast(Any, smoke_runtime_module).validate_candidate_benchmark_egress

    def observe(**kwargs: Any) -> None:
        observed.append(
            (
                kwargs["config"],
                kwargs["benchmark_suite"],
                kwargs["explicitly_allowed"],
            )
        )
        original(**kwargs)

    monkeypatch.setattr(smoke_runtime_module, "validate_candidate_benchmark_egress", observe)

    inventory = preflight_authenticated_runner_smoke_live_route_launch(launch)

    assert inventory.case_count == 1
    assert launch.explicitly_allow_synthetic_egress is False
    assert observed == [(launch.config, launch.benchmark_suite, True)]


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_status", ("reconciled", "released_attempt"))
async def test_preflight_rejects_an_occupied_smoke_run_namespace_before_live_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    terminal_status: str,
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    request_id = f"authrunner.smoke.r1.candidate.primary:{'a' * 64}"
    if terminal_status == "released_attempt":
        request_id = f"{request_id}:attempt:2"
    reservation = ledger.reserve(request_id, Decimal("0.02"))
    if terminal_status == "reconciled":
        ledger.reconcile(reservation, Decimal("0.01680888"))
    else:
        ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
    before = ledger.snapshot()

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("occupied run index must reject before cost or live-route work")

    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden)

    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="run index 1 is already present",
    ):
        preflight_authenticated_runner_smoke_live_route_launch(launch)

    assert ledger.snapshot() == before
    assert launch.usage.records == []


@pytest.mark.asyncio
async def test_preflight_admits_r2_without_changing_the_reconciled_r1_entry(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    r1_request_id = f"authrunner.smoke.r1.candidate.primary:{'a' * 64}"
    reservation = ledger.reserve(r1_request_id, Decimal("0.02"))
    ledger.reconcile(reservation, Decimal("0.01680888"))
    before = ledger.snapshot()

    inventory = preflight_authenticated_runner_smoke_live_route_launch(
        replace(launch, smoke_run_index=2)
    )

    assert inventory.smoke_run_index == 2
    assert all(plan.schema_version == "1.2" for plan in inventory.candidate_cost_plans)
    assert all(
        plan.request_preview.schema_version == "1.1" for plan in inventory.candidate_cost_plans
    )
    assert all(
        ".r2." in plan.request_preview.logical_request_id for plan in inventory.candidate_cost_plans
    )
    current_as_legacy = inventory.candidate_cost_plans[0].model_dump(mode="python")
    current_as_legacy["schema_version"] = "1.1"
    current_as_legacy["plan_sha256"] = canonical_sha256(
        {key: value for key, value in current_as_legacy.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="schema differs from its token accounting"):
        AuthenticatedRunnerSmokeCostPlan.model_validate(current_as_legacy, strict=True)
    assert ledger.snapshot() == before
    assert ledger.snapshot().entries[0].request_id == r1_request_id
    assert ledger.snapshot().entries[0].status is CostEntryStatus.RECONCILED
    assert ledger.snapshot().entries[0].actual_cost_usd == Decimal("0.01680888")
    assert launch.usage.records == []


def test_r2_cost_plans_bind_both_provider_attempt_ids() -> None:
    selection_sha256 = "b" * 64
    request_sha256 = "c" * 64
    candidate = _candidate_smoke_plan(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        selection_sha256=selection_sha256,
        case_id="case-df79ea132113b863",
        index=0,
        smoke_run_index=2,
    )
    judge = _judge_smoke_plan(
        run_kind=CrossLineageAdjudicationRunKind.REPLAY,
        selection_sha256=selection_sha256,
        case_id="case-df79ea132113b863",
        request_sha256=request_sha256,
        index=1,
        smoke_run_index=2,
    )

    assert candidate.provider_attempt_request_ids == (
        f"authrunner.smoke.r2.candidate.primary:{selection_sha256}",
        f"authrunner.smoke.r2.candidate.primary:{selection_sha256}:attempt:2",
    )
    assert judge.provider_attempt_request_ids == (
        f"authrunner.smoke.r2.judge.replay:{request_sha256}",
        f"authrunner.smoke.r2.judge.replay:{request_sha256}:attempt:2",
    )

    assert candidate.schema_version == judge.schema_version == "1.1"
    legacy_as_current = candidate.model_dump(mode="python")
    legacy_as_current["schema_version"] = "1.2"
    legacy_as_current["plan_sha256"] = canonical_sha256(
        {key: value for key, value in legacy_as_current.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="schema differs from its token accounting"):
        AuthenticatedRunnerSmokeCostPlan.model_validate(legacy_as_current, strict=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", (False, True, 0, -1, 1_000_000_000, 1.0, "2"))
async def test_preflight_rejects_invalid_smoke_run_index_before_ledger_or_route_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    value: object,
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("invalid run index must reject before provider-free admission work")

    monkeypatch.setattr(smoke_runtime_module, "validate_candidate_benchmark_egress", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden)

    with pytest.raises(AuthenticatedRunnerSmokeOpenRouterError, match="run index is invalid"):
        preflight_authenticated_runner_smoke_live_route_launch(
            replace(launch, smoke_run_index=cast(Any, value))
        )

    assert ledger.snapshot() == before
    assert launch.usage.records == []


@pytest.mark.asyncio
@pytest.mark.parametrize("role_index", [-1, 0, 1])
async def test_smoke_preflight_rejects_non_native_structured_output_for_every_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    role_index: int,
) -> None:
    launch = replace(
        await _live_route_launch(tmp_path=tmp_path / "native", config_factory=config_factory),
        explicitly_allow_synthetic_egress=True,
    )
    if role_index == -1:
        model = launch.candidate_registry.candidates[0]
    else:
        model = launch.run_plans[role_index].judge
    manifest, evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path / f"loose-{role_index}",
        config=launch.config,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=model.exact_model_id,
                provider_endpoint=model.approved_provider_endpoint,
                provider_name=model.approved_provider_name,
                canonical_model_id=model.canonical_model_slug,
            ),
        ),
    )
    if role_index == -1:
        launch = replace(
            launch,
            candidate_discovery_manifest=manifest,
            candidate_discovery_evidence=evidence,
            candidate_registry=registry,
        )
        expected = "smoke candidate route lacks required native structured_outputs support"
    else:
        plans = list(launch.run_plans)
        plans[role_index] = replace(
            plans[role_index],
            judge_discovery_manifest=manifest,
            judge_discovery_evidence=evidence,
            judge_registry=registry,
        )
        launch = replace(launch, run_plans=tuple(plans))
        expected = "smoke judge route lacks required native structured_outputs support"
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    def forbidden_cost_plan(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("structured-output admission must reject before cost derivation")

    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden_cost_plan)

    with pytest.raises(AuthenticatedRunnerSmokeOpenRouterError, match=expected):
        preflight_authenticated_runner_smoke_openrouter_launch(launch)

    assert launch.usage.records == []
    assert ledger.snapshot() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("role_index", [-1, 0, 1])
async def test_smoke_preflight_rejects_context_fallback_limit_for_every_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    role_index: int,
) -> None:
    launch = replace(
        await _live_route_launch(
            tmp_path=tmp_path / "completion-capacity",
            config_factory=config_factory,
        ),
        explicitly_allow_synthetic_egress=True,
    )
    if role_index == -1:
        model = launch.candidate_registry.candidates[0]
    else:
        model = launch.run_plans[role_index].judge
    manifest, evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path / f"context-fallback-{role_index}",
        config=launch.config,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=model.exact_model_id,
                provider_endpoint=model.approved_provider_endpoint,
                provider_name=model.approved_provider_name,
                canonical_model_id=model.canonical_model_slug,
                native_structured_output_parameter="structured_outputs",
                endpoint_completion_limit_published=False,
            ),
        ),
    )
    if role_index == -1:
        launch = replace(
            launch,
            candidate_discovery_manifest=manifest,
            candidate_discovery_evidence=evidence,
            candidate_registry=registry,
        )
        expected = "smoke candidate route lacks an explicit metadata completion limit"
    else:
        plans = list(launch.run_plans)
        plans[role_index] = replace(
            plans[role_index],
            judge_discovery_manifest=manifest,
            judge_discovery_evidence=evidence,
            judge_registry=registry,
        )
        launch = replace(launch, run_plans=tuple(plans))
        expected = "smoke judge route lacks an explicit metadata completion limit"
    assert evidence[0].endpoint_snapshot.endpoints[0].max_completion_tokens_source == (
        "context_limit"
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    output = tmp_path / "smoke-capacity-output.json"

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("completion-capacity admission must reject before provider setup")

    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", forbidden)
    monkeypatch.setattr(smoke_runtime_module, "_SmokeOpenRouterAdapter", forbidden)
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-capacity-unit-key"})
    try:
        with pytest.raises(AuthenticatedRunnerSmokeOpenRouterError, match=expected):
            await execute_authenticated_runner_smoke_openrouter(
                launch=launch,
                operator_secrets=secrets,
            )
        with pytest.raises(AuthenticatedRunnerSmokeOpenRouterError, match=expected):
            preflight_authenticated_runner_smoke_live_route_launch(
                replace(launch, explicitly_allow_synthetic_egress=False)
            )

        assert secrets.openrouter_api_key_present is True
        assert secrets.cleared is False
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert not output.exists()
    finally:
        secrets.clear()


@pytest.mark.asyncio
async def test_live_route_preflight_requires_positive_metadata_egress_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    def forbidden_client(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("missing metadata authority must not construct a provider client")

    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden_client)

    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="requires explicit metadata egress permission",
    ):
        await preflight_authenticated_runner_smoke_live_routes(
            launch=launch,
            operator_secrets=secrets,
            explicitly_allow_metadata_egress=False,
        )

    assert secrets.cleared
    assert launch.usage.records == []
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_live_route_preflight_clears_secret_when_static_admission_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    invalid_launch = replace(launch, explicitly_allow_synthetic_egress=True)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    def forbidden_client(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("failed static admission must not construct a provider client")

    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden_client)

    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="must not grant benchmark-code egress",
    ):
        await preflight_authenticated_runner_smoke_live_routes(
            launch=invalid_launch,
            operator_secrets=secrets,
            explicitly_allow_metadata_egress=True,
        )

    assert secrets.cleared
    assert launch.usage.records == []
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_live_route_preflight_clears_secret_when_initial_ledger_snapshot_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    original_snapshot = AtomicCostLedger.snapshot
    snapshot_calls = 0

    def fail_second_snapshot(self: AtomicCostLedger) -> CostLedgerSnapshot:
        nonlocal snapshot_calls
        if self is ledger:
            snapshot_calls += 1
            if snapshot_calls == 2:
                raise RuntimeError("synthetic initial live-route ledger snapshot failure")
        return original_snapshot(self)

    def forbidden_client(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("failed initial snapshot must not construct a provider client")

    monkeypatch.setattr(AtomicCostLedger, "snapshot", fail_second_snapshot)
    monkeypatch.setattr(smoke_runtime_module, "OpenRouterClient", forbidden_client)
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    with pytest.raises(RuntimeError, match="synthetic initial live-route ledger snapshot failure"):
        await preflight_authenticated_runner_smoke_live_routes(
            launch=launch,
            operator_secrets=secrets,
            explicitly_allow_metadata_egress=True,
        )

    assert snapshot_calls == 2
    assert secrets.cleared
    assert launch.usage.records == []
    assert original_snapshot(ledger).entries == ()


@pytest.mark.asyncio
async def test_live_route_preflight_detects_process_local_budget_state_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    factory = _install_live_route_client_factory(monkeypatch, launch)
    original_probe = smoke_runtime_module._SmokeLiveRouteProbeAdapter.probe_exact_routes

    async def probe_then_mutate(adapter: Any) -> tuple[str, str, str]:
        exact_model_ids = await original_probe(adapter)
        launch.budget._request_limit_counts[("logical", "synthetic-mutation")] = 1
        return exact_model_ids

    monkeypatch.setattr(
        smoke_runtime_module._SmokeLiveRouteProbeAdapter,
        "probe_exact_routes",
        probe_then_mutate,
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="changed usage, budget, or atomic cost-ledger state",
        ):
            await preflight_authenticated_runner_smoke_live_routes(
                launch=launch,
                operator_secrets=secrets,
                explicitly_allow_metadata_egress=True,
            )
        assert len(factory.clients) == 3
        assert factory.request_bodies == []
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert secrets.cleared
        assert all(client._client.is_closed for client in factory.clients)
        assert all(not client._credential and not client._headers for client in factory.clients)
    finally:
        await factory.close()


@pytest.mark.asyncio
async def test_live_route_preflight_rejects_registered_identity_drift_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    exact_model_id = launch.run_plans[0].judge.exact_model_id

    class RegisteredIdentityDriftClient:
        def __init__(self, client: Any) -> None:
            self._wrapped = client

        def __getattr__(self, name: str) -> Any:
            return getattr(self._wrapped, name)

        def registered_model_identity_snapshot(self, requested_model_id: str) -> Any:
            snapshot = self._wrapped.registered_model_identity_snapshot(requested_model_id)
            if requested_model_id == exact_model_id:
                return snapshot.model_copy(update={"provider_name": "synthetic-registration-drift"})
            return snapshot

    factory = _install_live_route_client_factory(
        monkeypatch,
        launch,
        client_wrapper=RegisteredIdentityDriftClient,
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="PRIMARY judge registered identity differs",
        ):
            await preflight_authenticated_runner_smoke_live_routes(
                launch=launch,
                operator_secrets=secrets,
                explicitly_allow_metadata_egress=True,
            )
        assert len(factory.clients) == 3
        assert factory.request_bodies == []
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert secrets.cleared
        assert all(client._client.is_closed for client in factory.clients)
        assert all(not client._credential and not client._headers for client in factory.clients)
    finally:
        await factory.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("drift_role_indices", "expected_roles"),
    (
        ((0,), (AuthenticatedRunnerSmokeLiveRouteRole.CANDIDATE,)),
        (
            (0, 1),
            (
                AuthenticatedRunnerSmokeLiveRouteRole.CANDIDATE,
                AuthenticatedRunnerSmokeLiveRouteRole.PRIMARY_JUDGE,
            ),
        ),
        (
            (0, 1, 2),
            (
                AuthenticatedRunnerSmokeLiveRouteRole.CANDIDATE,
                AuthenticatedRunnerSmokeLiveRouteRole.PRIMARY_JUDGE,
                AuthenticatedRunnerSmokeLiveRouteRole.REPLAY_JUDGE,
            ),
        ),
    ),
)
async def test_live_route_preflight_aggregates_one_two_or_three_retained_route_drifts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    drift_role_indices: tuple[int, ...],
    expected_roles: tuple[AuthenticatedRunnerSmokeLiveRouteRole, ...],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    models = (
        launch.candidate_registry.candidates[0],
        launch.run_plans[0].judge,
        launch.run_plans[1].judge,
    )
    factory = _install_live_route_client_factory(
        monkeypatch,
        launch,
        endpoint_inventory_drift_models={
            models[index].exact_model_id for index in drift_role_indices
        },
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeLiveRouteMismatchError,
        ) as caught:
            await preflight_authenticated_runner_smoke_live_routes(
                launch=launch,
                operator_secrets=secrets,
                explicitly_allow_metadata_egress=True,
            )
        assert tuple(item.role for item in caught.value.mismatches) == expected_roles
        assert tuple(item.category for item in caught.value.mismatches) == (
            OpenRouterLiveDiscoveryMismatchCategory.ENDPOINT_EXACT_MODEL_IDENTITY_INVENTORY,
        ) * len(expected_roles)
        assert str(caught.value) == (
            "smoke live-route retained discovery mismatches: "
            + "; ".join(
                f"{role.value}=endpoint exact-model identity inventory" for role in expected_roles
            )
        )
        assert len(factory.clients) == 3
        assert factory.request_bodies == []
        assert factory.metadata_requests == [
            path
            for model in models
            for path in (
                "/api/v1/key",
                "/api/v1/models",
                f"/api/v1/model/{model.exact_model_id}",
                f"/api/v1/models/{model.exact_model_id}/endpoints",
                "/api/v1/endpoints/zdr",
            )
        ]
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert secrets.cleared
        assert all(client._client.is_closed for client in factory.clients)
        assert all(not client._credential and not client._headers for client in factory.clients)
        for index in drift_role_indices:
            with pytest.raises(OpenRouterModelError, match="not registered"):
                factory.clients[index].registered_model_identity_snapshot(
                    models[index].exact_model_id
                )
    finally:
        await factory.close()


@pytest.mark.asyncio
async def test_live_route_preflight_mismatch_then_malformed_metadata_fails_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    models = (
        launch.candidate_registry.candidates[0],
        launch.run_plans[0].judge,
        launch.run_plans[1].judge,
    )
    factory = _install_live_route_client_factory(
        monkeypatch,
        launch,
        pricing_drift_models={models[0].exact_model_id},
        single_model_failure_modes={models[1].exact_model_id: "malformed"},
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="PRIMARY judge exact-model metadata request failed safely",
        ) as caught:
            await preflight_authenticated_runner_smoke_live_routes(
                launch=launch,
                operator_secrets=secrets,
                explicitly_allow_metadata_egress=True,
            )
        assert type(caught.value) is AuthenticatedRunnerSmokeOpenRouterError
        assert "retained discovery mismatches" not in str(caught.value)
        assert len(factory.metadata_requests) == 8
        assert f"/api/v1/model/{models[2].exact_model_id}" not in factory.metadata_requests
        assert (
            f"/api/v1/models/{models[2].exact_model_id}/endpoints" not in factory.metadata_requests
        )
        assert factory.request_bodies == []
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert secrets.cleared
        assert all(client._client.is_closed for client in factory.clients)
        assert all(not client._credential and not client._headers for client in factory.clients)
    finally:
        await factory.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("network_failure", "expected_metadata_request_count"),
    ((False, 6), (True, 7)),
)
async def test_live_route_preflight_mismatch_then_auth_or_network_failure_is_immediate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    network_failure: bool,
    expected_metadata_request_count: int,
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    models = (
        launch.candidate_registry.candidates[0],
        launch.run_plans[0].judge,
        launch.run_plans[1].judge,
    )
    failing_judge = {models[1].exact_model_id}
    factory = _install_live_route_client_factory(
        monkeypatch,
        launch,
        pricing_drift_models={models[0].exact_model_id},
        authentication_failure_models=set() if network_failure else failing_judge,
        metadata_network_failure_models=failing_judge if network_failure else set(),
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="PRIMARY judge authentication metadata request failed safely",
        ) as caught:
            await preflight_authenticated_runner_smoke_live_routes(
                launch=launch,
                operator_secrets=secrets,
                explicitly_allow_metadata_egress=True,
            )
        assert type(caught.value) is AuthenticatedRunnerSmokeOpenRouterError
        assert "retained discovery mismatches" not in str(caught.value)
        assert len(factory.metadata_requests) == expected_metadata_request_count
        assert f"/api/v1/model/{models[2].exact_model_id}" not in factory.metadata_requests
        assert (
            f"/api/v1/models/{models[2].exact_model_id}/endpoints" not in factory.metadata_requests
        )
        assert len(factory.clients) == 3
        assert factory.request_bodies == []
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert secrets.cleared
        assert all(client._client.is_closed for client in factory.clients)
        assert all(not client._credential and not client._headers for client in factory.clients)
    finally:
        await factory.close()


@pytest.mark.asyncio
async def test_live_route_preflight_fails_closed_after_transport_close_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = await _live_route_launch(tmp_path=tmp_path, config_factory=config_factory)
    factory = _install_live_route_client_factory(monkeypatch, launch)
    original_close = smoke_runtime_module._SmokeLiveRouteProbeAdapter.close

    async def close_then_fail(adapter: Any) -> None:
        await original_close(adapter)
        raise RuntimeError("synthetic post-close failure")

    monkeypatch.setattr(
        smoke_runtime_module._SmokeLiveRouteProbeAdapter,
        "close",
        close_then_fail,
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-live-route-unit-key"})

    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="did not close every metadata transport",
        ):
            await preflight_authenticated_runner_smoke_live_routes(
                launch=launch,
                operator_secrets=secrets,
                explicitly_allow_metadata_egress=True,
            )
        assert len(factory.clients) == 3
        assert factory.request_bodies == []
        assert launch.usage.records == []
        assert ledger.snapshot() == before
        assert secrets.cleared
        assert all(client._client.is_closed for client in factory.clients)
        assert all(not client._credential and not client._headers for client in factory.clients)
    finally:
        await factory.close()


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "retries", (0, 2)
)
def test_preflight_rejects_any_retry_policy_other_than_one_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    retries: int,
) -> None:
    launch = _launch(config=_smoke_config(config_factory, retries=retries), tmp_path=tmp_path)
    monkeypatch.setattr(
        smoke_runtime_module,
        "_require_singleton_registry",
        lambda **kwargs: kwargs["registry"].candidates[0],
    )
    monkeypatch.setattr(
        smoke_runtime_module, "_require_three_distinct_roots", lambda *_a, **_k: None
    )

    def must_not_derive_cost(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("retry inventory must reject before cost derivation")

    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", must_not_derive_cost)

    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="retry inventory",
    ):
        preflight_authenticated_runner_smoke_openrouter_launch(launch)


def test_preflight_operator_tripwire_sums_unequal_candidate_and_judge_roles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(
        config=_smoke_config(config_factory),
        tmp_path=tmp_path,
        candidate_tripwires=(Decimal("1"), Decimal("2")),
        judge_tripwires=(Decimal("3"), Decimal("5")),
    )
    smoke = launch.smoke_corpus
    plans = {
        kind: _candidate_smoke_plan(
            run_kind=kind,
            selection_sha256=smoke.bundle_sha256,
            case_id=smoke.case.case_id,
            index=index,
            prompt_price="0.001" if index == 0 else "0.002",
        )
        for index, kind in enumerate(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )
        )
    }
    monkeypatch.setattr(
        smoke_runtime_module,
        "_require_singleton_registry",
        lambda **kwargs: kwargs["registry"].candidates[0],
    )
    monkeypatch.setattr(
        smoke_runtime_module,
        "_candidate_cost_plan",
        lambda **kwargs: plans[kwargs["run_kind"]],
    )
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    inventory = preflight_authenticated_runner_smoke_openrouter_launch(launch)

    assert inventory.operator_interval_tripwire_usd == Decimal("22")
    assert inventory.operator_final_spent_tripwire_usd == Decimal("22")
    assert inventory.candidate_derived_interval_cost_cap_usd == sum(
        (Decimal(plan.maximum_cost_usd_all_attempts_exact) for plan in plans.values()),
        start=Decimal(0),
    )
    assert ledger.snapshot() == before
    assert launch.usage.records == []


def test_execution_orders_both_candidates_then_both_judge_preparations_and_judges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_config(config_factory), tmp_path=tmp_path)
    events, secrets = _install_execution_order_harness(
        monkeypatch,
        launch,
        fail_second_candidate_delta=False,
    )
    try:
        with pytest.raises(_StopAfterJudges):
            asyncio.run(
                execute_authenticated_runner_smoke_openrouter(
                    launch=launch,
                    operator_secrets=secrets,
                )
            )
    finally:
        secrets.clear()

    assert events == [
        "C:PRIMARY",
        "C:REPLAY",
        "PREPARE:PRIMARY,REPLAY",
        "PLAN:PRIMARY",
        "PLAN:REPLAY",
        "ADMIT:BOTH",
        "J:PRIMARY",
        "J:REPLAY",
        "ADAPTER:CLOSE",
    ]


def test_execution_never_prepares_or_dispatches_judge_after_candidate_ledger_anomaly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_config(config_factory), tmp_path=tmp_path)
    events, secrets = _install_execution_order_harness(
        monkeypatch,
        launch,
        fail_second_candidate_delta=True,
    )
    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="ledger anomaly",
        ):
            asyncio.run(
                execute_authenticated_runner_smoke_openrouter(
                    launch=launch,
                    operator_secrets=secrets,
                )
            )
    finally:
        secrets.clear()

    assert events == ["C:PRIMARY", "C:REPLAY", "ADAPTER:CLOSE"]


@pytest.mark.parametrize("smoke_run_index", (1, 2, 10, 999_999_999))
def test_smoke_judge_namespace_requires_its_disjoint_smoke_proof_kind(
    smoke_run_index: int,
) -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _smoke_report(suite)
    judge = _judge(JUDGE_ID)
    case = suite.cases[0]
    truth = suite.ground_truth_case(case.case_id)
    prepared = prepare_noncrediting_cross_lineage_adjudication_smoke(
        public_lineage_capability=resolve_verified_public_model_lineage(),
        suite=suite,
        selected_case=case,
        selected_ground_truth=truth,
        selection_sha256=SELECTION_SHA256,
        candidate_report=report,
        judge=judge,
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
    )
    request = prepared.requests[0]
    response = build_cross_lineage_adjudication_response(
        request=request,
        dimension_outcomes=request.expected_dimension_outcomes,
        disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
        rationale="Synthetic smoke namespace and proof-kind regression.",
    )
    usage, generation = _judge_usage_and_generation(
        case_index=0,
        request=request,
        response=response,
        judge=judge,
    )
    smoke_request_id = adjudication_module._cross_lineage_adjudication_smoke_logical_request_id(
        request, smoke_run_index
    )
    release_request_id = adjudication_module._cross_lineage_adjudication_logical_request_id(request)
    assert smoke_request_id != release_request_id
    payload = usage.model_dump(mode="python")
    payload["request_id"] = smoke_request_id
    routing = dict(payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    routing["privacy_source_proof_kind"] = "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION"
    payload["routing"] = routing
    smoke_usage = bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
    )
    generation_payload = generation.model_dump(mode="json", exclude={"evidence_sha256"})
    generation_payload["request_id"] = smoke_request_id
    smoke_generation = OpenRouterGenerationEvidence.model_validate(
        {
            **generation_payload,
            "evidence_sha256": canonical_sha256(generation_payload),
        }
    )

    result = build_cross_lineage_adjudication_case_result(
        request=request,
        response=response,
        usage_record=smoke_usage,
        generation_evidence=smoke_generation,
    )
    assert result.usage_record.request_id == smoke_request_id

    wrong_payload = smoke_usage.model_dump(mode="python")
    wrong_routing = dict(wrong_payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        wrong_routing.pop(field, None)
    wrong_routing["privacy_source_proof_kind"] = "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION"
    wrong_payload["routing"] = wrong_routing
    wrong_usage = bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(wrong_payload))
    )
    with pytest.raises(ValueError, match="privacy custody"):
        build_cross_lineage_adjudication_case_result(
            request=request,
            response=response,
            usage_record=wrong_usage,
            generation_evidence=smoke_generation,
        )


def test_bundle_rejects_mixed_common_preview_config_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, previews, _usages, _entries = _fake_bundle_validator_subject()
    assert _validate_fake_bundle(monkeypatch, bundle) is bundle

    previews[3].execution_config_sha256 = "f" * 64
    with pytest.raises(ValueError, match="maximum-attempt inventory"):
        _validate_fake_bundle(monkeypatch, bundle)


@pytest.mark.parametrize("drift", ("current_label", "legacy_with_token_detail"))
def test_bundle_rejects_resealed_token_accounting_version_crossover(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    bundle, _previews, usages, _entries = _fake_bundle_validator_subject()
    if drift == "current_label":
        bundle.schema_version = "1.2"
    else:
        usages[0].token_detail_accounting_evidence = SimpleNamespace()

    with pytest.raises(ValueError, match="schema differs from its token accounting"):
        _validate_fake_bundle(monkeypatch, bundle)


@pytest.mark.parametrize(
    "binding",
    ("run", "candidate_report", "candidate_plan", "judge_plan"),
)
def test_bundle_rejects_every_mixed_smoke_run_index_binding(
    monkeypatch: pytest.MonkeyPatch,
    binding: str,
) -> None:
    bundle, _previews, _usages, _entries = _fake_bundle_validator_subject()
    run = bundle.runs[1]
    if binding == "run":
        run.smoke_run_index = 2
    elif binding == "candidate_report":
        run.candidate_report.smoke_run_index = 2
    elif binding == "candidate_plan":
        run.candidate_cost_plan.smoke_run_index = 2
    else:
        run.judge_cost_plan.smoke_run_index = 2

    with pytest.raises(ValueError, match="different protocol inventory"):
        _validate_fake_bundle(monkeypatch, bundle)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "field", ("openrouter_generation_id", "request_body_sha256")
)
def test_bundle_rejects_four_way_generation_or_request_body_reuse(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    bundle, _previews, usages, _entries = _fake_bundle_validator_subject()
    setattr(usages[3], field, getattr(usages[0], field))

    with pytest.raises(ValueError, match="reuses provider request evidence"):
        _validate_fake_bundle(monkeypatch, bundle)


def test_bundle_ledger_cost_must_equal_each_usage_not_only_the_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, _previews, _usages, entries = _fake_bundle_validator_subject()
    entries[0].actual_cost_usd = "0.15"
    entries[1].actual_cost_usd = "0.05"

    with pytest.raises(ValueError, match="cost differs from provider usage"):
        _validate_fake_bundle(monkeypatch, bundle)


def test_run_requires_monotonic_generation_refetch_timestamps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _prepared, _candidate_report = _fake_run_validator_subject()
    assert _validate_fake_run(monkeypatch, run) is run

    run.judge_generation_refetch.retrieved_at = NOW - timedelta(seconds=1)
    with pytest.raises(ValueError, match="refetch is not fresh"):
        _validate_fake_run(monkeypatch, run)


@pytest.mark.parametrize("drift", ("current_label", "legacy_with_token_detail"))
def test_run_rejects_resealed_token_accounting_version_crossover(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    run, _prepared, _candidate_report = _fake_run_validator_subject()
    if drift == "current_label":
        run.schema_version = "1.2"
    else:
        run.candidate_report.result.usage_record.token_detail_accounting_evidence = (
            SimpleNamespace()
        )

    with pytest.raises(ValueError, match="schema differs from its token accounting"):
        _validate_fake_run(monkeypatch, run)


@pytest.mark.parametrize("binding", ("candidate_report", "candidate_plan", "judge_plan"))
def test_run_rejects_every_mixed_smoke_run_index_binding(
    monkeypatch: pytest.MonkeyPatch,
    binding: str,
) -> None:
    run, _prepared, _candidate_report = _fake_run_validator_subject()
    target = {
        "candidate_report": run.candidate_report,
        "candidate_plan": run.candidate_cost_plan,
        "judge_plan": run.judge_cost_plan,
    }[binding]
    target.smoke_run_index = 2

    with pytest.raises(ValueError, match="differs from its exact pair"):
        _validate_fake_run(monkeypatch, run)


def test_run_accepts_pending_null_registry_and_report_roots_bound_to_prepared_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, prepared, candidate_report = _fake_run_validator_subject(pending_registry_roots=True)
    assert run.candidate.root_lineage is None
    assert run.judge.root_lineage is None
    assert candidate_report.target.root_lineage is None
    assert prepared.target.candidate_root_lineage is not None
    assert prepared.target.judge_root_lineage is not None

    assert _validate_fake_run(monkeypatch, run) is run


def test_run_rejects_rejected_null_registry_lineage_on_offline_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _prepared, _candidate_report = _fake_run_validator_subject(pending_registry_roots=True)
    rejected_review = seal_operator_lineage_review(
        status=LineageReviewStatus.REJECTED,
        reviewed_model_ids=(run.judge.exact_model_id,),
        rationale="Synthetic explicit negative lineage decision.",
        reviewed_by="synthetic-unit-reviewer",
        reviewed_at=NOW,
        evidence_sha256="f" * 64,
    )
    run.judge = CandidateModel.model_validate(
        {
            **run.judge.model_dump(mode="python"),
            "lineage_review": rejected_review,
        },
        strict=True,
    )

    with pytest.raises(ValueError, match="differs from its exact pair"):
        _validate_fake_run(monkeypatch, run)


def test_run_requires_exact_judge_request_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _prepared, _candidate_report = _fake_run_validator_subject()
    run.judge_cost_plan.request_preview.logical_request_id = (
        f"authrunner.smoke.r1.judge.primary:{'f' * 64}"
    )

    with pytest.raises(ValueError, match="differs from its exact pair"):
        _validate_fake_run(monkeypatch, run)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "join", ("candidate_report", "prepared_candidate")
)
def test_run_requires_documentary_lineage_root_joins(
    monkeypatch: pytest.MonkeyPatch,
    join: str,
) -> None:
    run, prepared, candidate_report = _fake_run_validator_subject()
    if join == "candidate_report":
        candidate_report.target.root_lineage = f"sha256:{'f' * 64}"
    else:
        prepared.target.candidate_root_lineage = f"sha256:{'f' * 64}"

    with pytest.raises(ValueError, match="differs from its exact pair"):
        _validate_fake_run(monkeypatch, run)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "drift", ("candidate_root", "judge_root", "bundle_pin", "manifest_pin", "target_id")
)
def test_bundle_requires_one_exact_three_root_documentary_inventory(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    bundle, _previews, _usages, _entries = _fake_bundle_validator_subject()
    primary_target = bundle.runs[0].prepared_adjudication.target
    replay_target = bundle.runs[1].prepared_adjudication.target
    if drift == "candidate_root":
        replay_target.candidate_root_lineage = f"sha256:{'f' * 64}"
    elif drift == "judge_root":
        replay_target.judge_root_lineage = primary_target.judge_root_lineage
    elif drift == "bundle_pin":
        replay_target.public_lineage_bundle_sha256 = "f" * 64
    elif drift == "manifest_pin":
        replay_target.public_lineage_manifest_file_sha256 = "f" * 64
    else:
        replay_target.judge_model_id = PRIMARY_JUDGE_ID

    with pytest.raises(ValueError, match="inconsistent documentary lineage"):
        _validate_fake_bundle(monkeypatch, bundle)
