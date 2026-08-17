from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, tzinfo
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

import mmaudit.models.openrouter as openrouter_module
import mmaudit.orchestration.pipeline as pipeline_module
from mmaudit.benchmark.models import (
    MODEL_BENCHMARK_SCHEMA_NAME,
    ModelBenchmarkResponse,
    blinded_model_benchmark_request,
    load_model_benchmark_corpus,
    model_benchmark_system_prompt,
)
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterPolicyEligibilityError,
    OpenRouterProviderPolicy,
    OpenRouterQualificationError,
    OpenRouterTransientError,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.policy_selection import VerifiedAuditModelSelection
from mmaudit.models.qualification import VerifiedProductionQualification
from mmaudit.models.reasoning import CANONICAL_REASONING_POLICY_ROLES, ReasoningPolicyArtifact
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.context_manifest import ContextPreflightReason
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.privacy_provenance import prove_release_pinned_model_benchmark_source
from tests.unit.test_model_policy_selection import (
    BASE_TIME,
    _policy_authority,
    _policy_bundle,
    _PolicyBundle,
    _resolve,
    _technical_qualification,
)
from tests.unit.test_openrouter import Answer, _completion_response, _endpoint_snapshot

_USE_TIME = BASE_TIME + timedelta(hours=2)
_MODEL_BENCHMARK_CORPUS = Path(__file__).parents[2] / "benchmarks/model_corpus/manifest.json"


class _ControlledDateTime(datetime):
    current = _USE_TIME

    @classmethod
    def now(cls, timezone: tzinfo | None = None) -> datetime:
        value = cls.current
        return value if timezone is None else value.astimezone(timezone)


@dataclass
class _Harness:
    client: OpenRouterClient
    ledger: AtomicCostLedger
    usage: UsageLedger
    requests: list[dict[str, Any]]
    technical: VerifiedProductionQualification
    policy: _PolicyBundle
    selection: VerifiedAuditModelSelection | None
    selection_bundle_sha256: str
    selected_model_set_sha256: str
    model: str

    @property
    def context_preflight_records(self) -> tuple[Any, ...]:
        return self.client.context_preflight.records


def _reasoning_policy(
    technical: VerifiedProductionQualification,
    model: str,
) -> ReasoningPolicyArtifact:
    selected = next(item for item in technical.models if item.exact_model_id == model)
    observed = {
        binding.configured_policy_role: binding.control_profile
        for binding in selected.reasoning_bindings
    }
    fallback = observed["source_audit"]
    controls = {role: observed.get(role, fallback) for role in CANONICAL_REASONING_POLICY_ROLES}
    return ReasoningPolicyArtifact.build(controls_by_role=controls)


def _exact_endpoint_registration(
    client: OpenRouterClient,
    technical: VerifiedProductionQualification,
    model: str,
) -> None:
    selected = next(item for item in technical.models if item.exact_model_id == model)
    snapshot = _endpoint_snapshot(
        model=model,
        provider=selected.approved_provider_endpoint,
        provider_name=selected.approved_provider_name,
    )
    client.register_endpoint_snapshot(evidence=snapshot)
    registered = client._endpoint_pricing[model]
    endpoint = replace(
        registered.endpoints[0],
        pricing_sha256=selected.pricing_snapshot_sha256,
        snapshot_sha256=selected.endpoint_snapshot_sha256,
        supported_output_modes=(selected.structured_output_mode,),
        structured_output_mode=selected.structured_output_mode,
    )
    client._endpoint_pricing[model] = replace(
        registered,
        snapshot_sha256=selected.endpoint_snapshot_sha256,
        endpoints=(endpoint,),
        supported_output_modes=(selected.structured_output_mode,),
        structured_output_mode=selected.structured_output_mode,
        output_capability_sha256=selected.output_capability_sha256,
    )
    role_binding = next(
        binding
        for binding in selected.reasoning_bindings
        if binding.qualified_role == "source_audit"
        and binding.configured_policy_role == "source_audit"
    )

    class _ExactReasoningCapability:
        exact_model_id = model
        capability_sha256 = role_binding.endpoint_reasoning_capability_sha256

        @staticmethod
        def require_compatible_profile(_profile: Any) -> None:
            return None

    client._reasoning_capabilities[model] = cast(Any, _ExactReasoningCapability())


def _force_real_audit_policy_boundary(
    monkeypatch: pytest.MonkeyPatch,
    client: OpenRouterClient,
) -> None:
    original_boundary = openrouter_module._TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION
    original_execution_evidence = openrouter_module.trusted_openrouter_execution_evidence

    def classify_boundary(
        subject: OpenRouterClient,
        role: str,
        *,
        system_prompt: str | None = None,
        user_prompt: str | None = None,
        response_model: Any = None,
        schema_name: str | None = None,
        structured_output_mode: StructuredOutputMode | None = None,
        context_package: Any = None,
    ) -> bool:
        request_shape = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "response_model": response_model,
            "schema_name": schema_name,
            "structured_output_mode": structured_output_mode,
            "context_package": context_package,
        }
        if subject is client:
            return not OpenRouterClient._is_trusted_prequalification_request(
                subject,
                role,
                **request_shape,
            )
        return original_boundary(subject, role, **request_shape)

    monkeypatch.setattr(
        openrouter_module,
        "_TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION",
        classify_boundary,
    )

    def preserve_closed_mock_transport(subject: OpenRouterClient) -> ExecutionEvidenceKind:
        if subject is client:
            return ExecutionEvidenceKind.MOCK
        return original_execution_evidence(subject)

    monkeypatch.setattr(
        openrouter_module,
        "trusted_openrouter_execution_evidence",
        preserve_closed_mock_transport,
    )
    original = client._require_real_postqualification_routing

    def require_without_real_session_snapshot(
        *,
        role: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: Any,
        schema_name: str,
        structured_output_mode: StructuredOutputMode,
        context_package: Any,
        checked_at: datetime,
        require_runtime_snapshots: bool,
    ) -> Any:
        del require_runtime_snapshots
        return original(
            role=role,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_model=response_model,
            schema_name=schema_name,
            structured_output_mode=structured_output_mode,
            context_package=context_package,
            checked_at=checked_at,
            require_runtime_snapshots=False,
        )

    monkeypatch.setattr(
        client,
        "_require_real_postqualification_routing",
        require_without_real_session_snapshot,
    )


def _build_harness(
    *,
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: Callable[[httpx.Request, str, str], httpx.Response],
    include_selection: bool = True,
    exclude_requested_model: bool = False,
    certification: bool = True,
) -> _Harness:
    monkeypatch.setattr(openrouter_module, "datetime", _ControlledDateTime)
    monkeypatch.setattr(pipeline_module, "datetime", _ControlledDateTime)
    technical = _technical_qualification()
    excluded_model = technical.models[-1].exact_model_id
    policy = _policy_bundle(
        technical,
        excluded_ids=(frozenset({excluded_model}) if exclude_requested_model else frozenset()),
    )
    authority = _policy_authority(tmp_path / "policy-authority", policy)
    selection_record, evidence_bundle, selection = _resolve(technical, policy, authority)
    model = excluded_model if exclude_requested_model else selection.models[0].exact_model_id
    technical_model = next(item for item in technical.models if item.exact_model_id == model)
    config = config_factory(execution={"max_json_repair_attempts": 0})
    privacy = resolve_effective_privacy_policy(
        profile=config.privacy.profile,
        require_zdr=config.privacy.require_zdr,
        consent_observation=None,
        source_sha256=policy.audit_context.source_sha256,
        source_classification=policy.audit_context.source_classification,
        configured_model_ids=(model,),
        configured_provider_endpoints=(technical_model.approved_provider_endpoint,),
        requested_budget_usd=Decimal(str(config.execution.budget_usd)),
        now=_USE_TIME,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "policy-cost-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return response(
            request,
            model,
            technical_model.approved_provider_endpoint,
        )

    usage = UsageLedger()
    client = OpenRouterClient(
        api_key="synthetic-policy-test-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        base_url="https://fake.test/api/v1/",
        test_only_mock_handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=certification,
            only=(technical_model.approved_provider_endpoint,),
        ),
        reasoning_policy=_reasoning_policy(technical, model),
        token_budgets=config.token_budgets,
        qualification_routing=pipeline_module._openrouter_qualification_routing(technical),
        production_qualification=technical,
        audit_model_selection=(selection if include_selection else None),
        policy_audit_context=(policy.audit_context if include_selection else None),
        client_policy_constraints=(policy.client_constraints if include_selection else None),
        effective_privacy_policy=privacy,
    )
    _exact_endpoint_registration(client, technical, model)
    _force_real_audit_policy_boundary(monkeypatch, client)
    return _Harness(
        client=client,
        ledger=ledger,
        usage=usage,
        requests=requests,
        technical=technical,
        policy=policy,
        selection=(selection if include_selection else None),
        selection_bundle_sha256=evidence_bundle.bundle_sha256,
        selected_model_set_sha256=selection_record.selected_model_set_sha256,
        model=model,
    )


async def _complete(harness: _Harness, *, role: str = "source_audit") -> Any:
    return await harness.client.complete_with_evidence(
        role=role,
        models=[harness.model],
        system_prompt="system",
        user_prompt="synthetic local input",
        response_model=Answer,
        schema_name="answer",
    )


@pytest.mark.asyncio
async def test_real_postqualification_missing_selection_refuses_before_claim_or_reserve(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
        include_selection=False,
    )
    try:
        with pytest.raises(
            OpenRouterPolicyEligibilityError,
            match="requires verified audit model selection",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
    assert harness.context_preflight_records[-1].reason is ContextPreflightReason.ROUTE_UNAVAILABLE


@pytest.mark.asyncio
async def test_real_noncertification_private_request_refuses_before_claim_reserve_or_post(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
        include_selection=False,
        certification=False,
    )
    try:
        with pytest.raises(
            OpenRouterPolicyEligibilityError,
            match="requires verified audit model selection",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
    assert harness.context_preflight_records[-1].reason is ContextPreflightReason.ROUTE_UNAVAILABLE


@pytest.mark.asyncio
async def test_policy_ineligible_tier_a_route_refuses_before_claim_or_reserve(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
        exclude_requested_model=True,
    )
    try:
        with pytest.raises(
            OpenRouterPolicyEligibilityError,
            match="lacks verified audit selection",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
    assert harness.context_preflight_records[-1].reason is ContextPreflightReason.ROUTE_UNAVAILABLE


@pytest.mark.asyncio
async def test_private_source_cannot_use_prequalification_role_to_bypass_selection(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
        include_selection=False,
    )
    role = "model_benchmark:source_audit:source_audit"
    assert not harness.client._is_trusted_prequalification_request(role)
    try:
        with pytest.raises(
            OpenRouterPolicyEligibilityError,
            match="requires verified audit model selection",
        ):
            await _complete(harness, role=role)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
    assert harness.context_preflight_records[-1].reason is ContextPreflightReason.ROUTE_UNAVAILABLE


@pytest.mark.asyncio
async def test_valid_selection_namespaces_request_metadata_and_binds_usage_hashes(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"policy eligible"}',
            model=model,
            provider=provider,
        ),
    )
    try:
        completion = await _complete(harness)
    finally:
        await harness.client.close()

    assert completion.value.answer == "policy eligible"
    assert harness.selection is not None
    routing = completion.usage_record.routing
    metadata = harness.requests[0]["metadata"]
    assert metadata["mmaudit_policy_audit_selection_sha256"] == (
        harness.selection.audit_selection_sha256
    )
    assert metadata["mmaudit_policy_source_sha256"] == harness.policy.audit_context.source_sha256
    assert metadata["mmaudit_policy_audit_model_selection_bundle_sha256"] == (
        harness.selection_bundle_sha256
    )
    assert metadata["mmaudit_policy_selected_model_set_sha256"] == (
        harness.selected_model_set_sha256
    )
    assert "audit_selection_sha256" not in metadata
    assert routing["audit_selection_sha256"] == harness.selection.audit_selection_sha256
    assert routing["audit_model_selection_bundle_sha256"] == harness.selection_bundle_sha256
    assert routing["selected_model_set_sha256"] == harness.selected_model_set_sha256
    assert routing["audit_scope_sha256"] == harness.policy.audit_context.audit_scope_sha256
    assert routing["source_sha256"] == harness.policy.audit_context.source_sha256
    assert "routing_evidence_sha256" not in routing
    assert (
        routing["audit_model_routing_evidence"]["routing_evidence_sha256"]
        == routing["audit_policy_routing_evidence_sha256"]
    )


@pytest.mark.asyncio
async def test_policy_binding_drift_before_reserve_refuses_without_ledger_entry(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    drift = _policy_bundle(harness.technical, context_tag="drift-before-reserve")
    original_build_request = harness.client.build_request

    def build_then_drift(*args: Any, **kwargs: Any) -> dict[str, Any]:
        body = original_build_request(*args, **kwargs)
        harness.client._audit_policy_binding = openrouter_module._OpenRouterAuditPolicyBinding(
            audit_context=drift.audit_context,
            client_constraints=drift.client_constraints,
        )
        return body

    monkeypatch.setattr(harness.client, "build_request", build_then_drift)
    try:
        with pytest.raises(OpenRouterPolicyEligibilityError, match="effective privacy request"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
    assert harness.context_preflight_records[-1].reason is ContextPreflightReason.ROUTE_UNAVAILABLE


@pytest.mark.asyncio
async def test_policy_binding_failure_after_reserve_releases_without_post(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    drift = _policy_bundle(harness.technical, context_tag="drift-after-reserve")
    original_reserve = harness.client.budget.reserve

    async def reserve_then_drift(*args: Any, **kwargs: Any) -> Any:
        reservation = await original_reserve(*args, **kwargs)
        harness.client._audit_policy_binding = openrouter_module._OpenRouterAuditPolicyBinding(
            audit_context=drift.audit_context,
            client_constraints=drift.client_constraints,
        )
        return reservation

    monkeypatch.setattr(harness.client.budget, "reserve", reserve_then_drift)
    try:
        with pytest.raises(OpenRouterPolicyEligibilityError, match="effective privacy request"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"
    assert harness.context_preflight_records[-1].reason is ContextPreflightReason.ROUTE_UNAVAILABLE


@pytest.mark.asyncio
async def test_failure_usage_retains_last_dispatched_policy_routing_evidence(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        config_factory=config_factory,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, _model, _provider: httpx.Response(
            500,
            json={"error": "synthetic"},
        ),
    )
    try:
        with pytest.raises(OpenRouterTransientError):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert len(harness.requests) == 1
    assert len(harness.usage.records) == 1
    assert harness.selection is not None
    routing = harness.usage.records[0].routing
    assert routing["audit_selection_sha256"] == harness.selection.audit_selection_sha256
    assert routing["audit_model_selection_bundle_sha256"] == harness.selection_bundle_sha256
    assert routing["selected_model_set_sha256"] == harness.selected_model_set_sha256
    assert routing["source_sha256"] == harness.policy.audit_context.source_sha256
    metadata = harness.requests[0]["metadata"]
    assert metadata["mmaudit_policy_audit_model_selection_bundle_sha256"] == (
        harness.selection_bundle_sha256
    )
    assert metadata["mmaudit_policy_selected_model_set_sha256"] == (
        harness.selected_model_set_sha256
    )
    assert "routing_evidence_sha256" not in routing
    assert (
        routing["audit_model_routing_evidence"]["routing_evidence_sha256"]
        == routing["audit_policy_routing_evidence_sha256"]
    )


@pytest.mark.asyncio
async def test_prequalification_role_does_not_require_policy_selection(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(openrouter_module, "datetime", _ControlledDateTime)
    config = config_factory(
        execution={"max_json_repair_attempts": 0},
        privacy={
            "profile": PrivacyProfile.SYNTHETIC_BENCHMARK,
            "require_zdr": True,
            "maximum_model_retention": "zero",
        },
    )
    model = "alpha/atlas-secure"
    provider = "openrouter/provider-a"
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    source_sha256 = suite.corpus_sha256
    source_provenance = prove_release_pinned_model_benchmark_source(
        suite,
        now=_USE_TIME,
    )
    privacy = resolve_effective_privacy_policy(
        profile=config.privacy.profile,
        require_zdr=config.privacy.require_zdr,
        consent_observation=None,
        source_sha256=source_sha256,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_provenance_observation=source_provenance,
        configured_model_ids=(model,),
        configured_provider_endpoints=(provider,),
        requested_budget_usd=Decimal(str(config.execution.budget_usd)),
        now=_USE_TIME,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "prequalification-cost-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            json.dumps(
                {
                    "case_id": suite.cases[0].case_id,
                    "classification": "safe",
                    "locations": [],
                    "invariant": None,
                    "repository_instructions_followed": False,
                    "assumptions": [],
                    "unsupported_assumptions": [],
                    "verifier_conclusion": None,
                    "falsifier_conclusion": None,
                    "verifier_evidence": None,
                    "falsifier_test": None,
                    "remediation": None,
                    "rationale": "The synthetic excerpt supports the bounded safe classification.",
                }
            ),
            model=model,
            provider=provider,
        )

    client = OpenRouterClient(
        api_key="synthetic-prequalification-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
        ),
        usage=UsageLedger(),
        base_url="https://fake.test/api/v1/",
        test_only_mock_handler=handler,
        provider_policy=OpenRouterProviderPolicy(certification=True, only=(provider,)),
        effective_privacy_policy=privacy,
        source_provenance_observation=source_provenance,
    )
    client.register_certification_endpoint_snapshot(
        evidence=_endpoint_snapshot(model=model, provider=provider),
    )
    role = "model_benchmark:source_audit:source_audit"
    user_prompt = blinded_model_benchmark_request(suite.cases[0])
    exact_shape = {
        "system_prompt": model_benchmark_system_prompt(),
        "user_prompt": user_prompt,
        "response_model": ModelBenchmarkResponse,
        "schema_name": MODEL_BENCHMARK_SCHEMA_NAME,
        "structured_output_mode": StructuredOutputMode.NATIVE_JSON_SCHEMA,
        "context_package": None,
    }
    _force_real_audit_policy_boundary(monkeypatch, client)
    assert not client._is_trusted_prequalification_request(role)
    assert not client._is_trusted_prequalification_request(
        role,
        **{
            **exact_shape,
            "user_prompt": "arbitrary caller-controlled source",
        },
    )
    assert openrouter_module._TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
        client,
        role,
        **{
            **exact_shape,
            "user_prompt": "arbitrary caller-controlled source",
        },
    )
    assert client._is_trusted_prequalification_request(role, **exact_shape)
    assert not openrouter_module._TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
        client,
        role,
        **exact_shape,
    )
    invalid_shapes = (
        {
            "system_prompt": "private operator system text",
            "response_model": ModelBenchmarkResponse,
            "schema_name": MODEL_BENCHMARK_SCHEMA_NAME,
            "context_package": None,
        },
        {
            "system_prompt": model_benchmark_system_prompt(),
            "response_model": Answer,
            "schema_name": "answer",
            "context_package": None,
        },
        {
            "system_prompt": model_benchmark_system_prompt(),
            "response_model": ModelBenchmarkResponse,
            "schema_name": "custom_benchmark_schema",
            "context_package": None,
        },
        {
            "system_prompt": model_benchmark_system_prompt(),
            "response_model": ModelBenchmarkResponse,
            "schema_name": MODEL_BENCHMARK_SCHEMA_NAME,
            "context_package": cast(Any, object()),
        },
    )
    for invalid_shape in invalid_shapes:
        assert openrouter_module._TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION(
            client,
            role,
            user_prompt=user_prompt,
            structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
            **invalid_shape,
        )
        with pytest.raises(
            (OpenRouterPolicyEligibilityError, OpenRouterQualificationError),
            match="requires",
        ):
            await client.complete_with_evidence(
                role=role,
                models=[model],
                user_prompt=user_prompt,
                **invalid_shape,
            )
        assert client._claimed_request_ids == set()
        assert calls == 0
        assert ledger.snapshot().entries == ()
    try:
        completion = await client.complete_with_evidence(
            role=role,
            models=[model],
            system_prompt=model_benchmark_system_prompt(),
            user_prompt=user_prompt,
            response_model=ModelBenchmarkResponse,
            schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
        )
    finally:
        await client.close()

    assert completion.value.case_id == suite.cases[0].case_id
    assert calls == 1
    assert "audit_selection_sha256" not in completion.usage_record.routing
    assert (
        completion.usage_record.routing["privacy_source_proof_kind"]
        == "RELEASE_PINNED_MODEL_BENCHMARK"
    )
