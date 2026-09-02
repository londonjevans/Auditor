from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime, tzinfo
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any, Literal, cast

import httpx
import pytest

import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.schemas as schemas_module
import mmaudit.orchestration.pipeline as pipeline_module
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterCostControlError,
    OpenRouterModelError,
    OpenRouterModelRefreshError,
    OpenRouterModelRefreshPricingError,
    OpenRouterPrivacyError,
    OpenRouterProviderPolicy,
    OpenRouterSchemaError,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.refresh_runtime import (
    AuditModelRefreshPricingRouteEvidence,
    AuditModelRefreshRouteEvidence,
    VerifiedAuditModelRefreshPricingAuthority,
)
from mmaudit.models.schemas import (
    AuditModelRefreshPricingAttemptEvidence,
    ExecutionEvidenceKind,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager, EndpointRequestCostBound
from mmaudit.orchestration.context_manifest import ContextPreflightReason
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, ReleaseReason
from mmaudit.privacy import resolve_effective_privacy_policy
from tests.refresh_runtime_support import SyntheticRefreshRuntime, synthetic_refresh_runtime
from tests.unit.test_openrouter import Answer, _completion_response
from tests.unit.test_openrouter_policy_eligibility import (
    _reasoning_policy,
)

_PROMPT_DOMINATED_CACHE_READ_PRICING = {
    "completion": "0.000002",
    "input_cache_read": "0.0000001",
    "prompt": "0.000001",
}


class _ControlledDateTime(datetime):
    current: datetime

    @classmethod
    def now(cls, timezone: tzinfo | None = None) -> _ControlledDateTime:
        value = cls.current
        return cast(
            _ControlledDateTime,
            value if timezone is None else value.astimezone(timezone),
        )


@dataclass(slots=True)
class _Harness:
    client: OpenRouterClient
    ledger: AtomicCostLedger
    usage: UsageLedger
    requests: list[dict[str, Any]]
    runtime: SyntheticRefreshRuntime
    model: str


def _registered_endpoint_pricing(
    *,
    pricing: dict[str, str],
    provider_endpoint: str = "provider/fp8",
) -> openrouter_module._RegisteredEndpointPricing:
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=(provider_endpoint,),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [
                    {
                        "slug": provider_endpoint,
                        "provider_name": f"Synthetic {provider_endpoint}",
                        "status": 0,
                        "context_length": 100_000,
                        "max_prompt_tokens": 91_808,
                        "max_completion_tokens": 8_192,
                        "supported_parameters": [
                            "max_tokens",
                            "response_format",
                            "temperature",
                        ],
                        "pricing": pricing,
                    }
                ],
            }
        },
        require_zdr=False,
        zdr_payload=None,
        reasoning_requested=False,
        structured_output_required=True,
    )
    observed = snapshot.endpoints[0]
    return openrouter_module._RegisteredEndpointPricing(
        provider_endpoint=observed.provider_endpoint,
        provider_name=observed.provider_name,
        provider_identities=(observed.provider_endpoint, observed.provider_name),
        endpoint_tag=observed.endpoint_tag,
        endpoint_slug=observed.endpoint_slug,
        operational_status=observed.operational_status,
        zdr_eligible=observed.zdr_eligible,
        pricing=tuple(observed.pricing.items()),
        pricing_sha256=observed.pricing_sha256,
        snapshot_sha256=observed.endpoint_snapshot_sha256,
        context_length=observed.context_length,
        max_prompt_tokens=observed.max_prompt_tokens,
        max_prompt_tokens_source=observed.max_prompt_tokens_source,
        max_completion_tokens=observed.max_completion_tokens,
        max_completion_tokens_source=observed.max_completion_tokens_source,
        supported_parameters=observed.supported_parameters,
        required_request_parameters=observed.required_request_parameters,
        structured_output_parameters=observed.structured_output_parameters,
        supported_output_modes=observed.supported_output_modes,
        structured_output_mode=observed.structured_output_mode,
    )


@dataclass(slots=True)
class _ExpiringLifecycleObserver:
    runtime: SyntheticRefreshRuntime

    def request_ready(self, **_values: Any) -> None:
        return None

    def request_dispatched(self, *, logical_request_id: str) -> None:
        del logical_request_id
        _ControlledDateTime.current = self.runtime.evidence.expires_at


class _ObservedRequestLock(asyncio.Lock):
    def __init__(self) -> None:
        super().__init__()
        self.contended = asyncio.Event()

    async def acquire(self) -> Literal[True]:
        if self.locked():
            self.contended.set()
        return await super().acquire()


def _force_real_refresh_boundary(
    monkeypatch: pytest.MonkeyPatch,
    client: OpenRouterClient,
) -> None:
    original_audit_boundary = openrouter_module._TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION
    original_refresh_boundary = openrouter_module._TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH
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
        return original_audit_boundary(subject, role, **request_shape)

    def classify_refresh_boundary(
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
        return original_refresh_boundary(subject, role, **request_shape)

    monkeypatch.setattr(
        openrouter_module,
        "_TRUSTED_REQUIRES_REAL_AUDIT_POLICY_SELECTION",
        classify_boundary,
    )
    monkeypatch.setattr(
        openrouter_module,
        "_TRUSTED_REQUIRES_REAL_AUDIT_MODEL_REFRESH",
        classify_refresh_boundary,
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
    original_routing = client._require_real_postqualification_routing

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
        allow_refreshed_pricing: bool = False,
    ) -> Any:
        del require_runtime_snapshots
        return original_routing(
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
            allow_refreshed_pricing=allow_refreshed_pricing,
        )

    monkeypatch.setattr(
        client,
        "_require_real_postqualification_routing",
        require_without_real_session_snapshot,
    )


def _build_harness(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: Callable[[httpx.Request, str, str], httpx.Response],
    include_refresh: bool = True,
    include_pricing: bool | None = None,
    qualified_pricing: dict[str, str] | None = None,
    current_pricing: dict[str, str] | None = None,
    store_raw_prompts: bool = False,
    per_role_usd_caps: dict[str, str] | None = None,
) -> _Harness:
    runtime = synthetic_refresh_runtime(
        tmp_path / "refresh-runtime",
        qualified_pricing=qualified_pricing,
        current_pricing=current_pricing,
    )
    _ControlledDateTime.current = runtime.verified_at
    monkeypatch.setattr(openrouter_module, "datetime", _ControlledDateTime)
    technical = runtime.technical_qualification
    selection = runtime.audit_selection_evidence.selection
    model = runtime.audit_selection.models[0].exact_model_id
    technical_model = next(item for item in technical.models if item.exact_model_id == model)
    config = runtime.config
    privacy = resolve_effective_privacy_policy(
        profile=config.privacy.profile,
        require_zdr=config.privacy.require_zdr,
        consent_observation=None,
        source_sha256=selection.source_sha256,
        source_classification=runtime.audit_selection_evidence.audit_context.source_classification,
        configured_model_ids=(model,),
        configured_provider_endpoints=(technical_model.approved_provider_endpoint,),
        requested_budget_usd=Decimal(str(config.execution.budget_usd)),
        now=runtime.verified_at,
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "refresh-cost-ledger.json",
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
        per_role_usd_caps=per_role_usd_caps,
    )
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return response(request, model, technical_model.approved_provider_endpoint)

    usage = UsageLedger()
    request_privacy = config.privacy.model_copy(update={"store_raw_prompts": store_raw_prompts})
    client = OpenRouterClient(
        api_key="synthetic-refresh-transport-key",
        execution=config.execution,
        privacy=request_privacy,
        budget=budget,
        usage=usage,
        base_url="https://fake.test/api/v1/",
        test_only_mock_handler=handler,
        run_dir=(tmp_path / "run" if store_raw_prompts else None),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=(technical_model.approved_provider_endpoint,),
        ),
        reasoning_policy=_reasoning_policy(technical, model),
        token_budgets=config.token_budgets,
        qualification_routing=pipeline_module._openrouter_qualification_routing(technical),
        production_qualification=technical,
        audit_model_selection=runtime.audit_selection,
        policy_audit_context=runtime.audit_selection_evidence.audit_context,
        client_policy_constraints=runtime.audit_selection_evidence.client_constraints,
        audit_model_refresh_evidence=(runtime.evidence if include_refresh else None),
        audit_model_refresh_guard=(runtime.guard if include_refresh else None),
        audit_model_refresh_pricing_evidence=(
            runtime.pricing_evidence if include_refresh and include_pricing is not False else None
        ),
        audit_model_refresh_pricing_authority=(
            runtime.pricing_authority if include_refresh and include_pricing is not False else None
        ),
        effective_privacy_policy=privacy,
    )
    _register_current_refresh_endpoint(client, runtime, model)
    _force_real_refresh_boundary(monkeypatch, client)
    return _Harness(
        client=client,
        ledger=ledger,
        usage=usage,
        requests=requests,
        runtime=runtime,
        model=model,
    )


def _register_current_refresh_endpoint(
    client: OpenRouterClient,
    runtime: SyntheticRefreshRuntime,
    model: str,
) -> None:
    """Register the exact synthetic live route while retaining qualification custody."""

    route = next(
        item
        for item in runtime.evidence.routes
        if item.exact_model_id == model and item.audit_selected
    )
    live = route.refresh_route
    endpoint: dict[str, Any] = {
        "provider_name": live.provider_name,
        "status": int(live.operational_status),
        "context_length": live.context_limit,
        "max_prompt_tokens": live.max_prompt_tokens,
        "max_completion_tokens": live.output_limit,
        "supported_parameters": list(live.supported_parameters),
        "pricing": dict(live.pricing),
    }
    if live.endpoint_tag is not None:
        endpoint["tag"] = live.endpoint_tag
    if live.endpoint_slug is not None:
        endpoint["slug"] = live.endpoint_slug
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(live.provider_endpoint,),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model}]},
        reasoning_requested=False,
        structured_output_required=True,
    )
    client.register_endpoint_snapshot(evidence=snapshot)
    technical_model = next(
        item for item in runtime.technical_qualification.models if item.exact_model_id == model
    )
    registered = client._endpoint_pricing[model]
    client._endpoint_pricing[model] = replace(
        registered,
        output_capability_sha256=technical_model.output_capability_sha256,
    )
    role_binding = next(
        binding
        for binding in technical_model.reasoning_bindings
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


async def _complete(harness: _Harness) -> Any:
    return await harness.client.complete_with_evidence(
        role="source_audit",
        models=[harness.model],
        system_prompt="system",
        user_prompt="synthetic local source",
        response_model=Answer,
        schema_name="answer",
    )


@pytest.mark.asyncio
async def test_missing_refresh_pair_refuses_before_request_id_claim_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
        include_refresh=False,
    )
    try:
        with pytest.raises(OpenRouterModelRefreshError, match="requires current model refresh"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
    assert harness.client.context_preflight.records[-1].reason is (
        ContextPreflightReason.ROUTE_UNAVAILABLE
    )


@pytest.mark.asyncio
async def test_missing_refresh_pricing_pair_refuses_before_claim_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
        include_pricing=False,
    )
    try:
        with pytest.raises(
            OpenRouterModelRefreshPricingError,
            match="requires refresh pricing evidence and opaque authority",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
    assert harness.client.context_preflight.records[-1].reason is (
        ContextPreflightReason.ROUTE_UNAVAILABLE
    )


@pytest.mark.asyncio
async def test_expiry_before_reserve_refuses_without_reservation_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    original_request_token_plan = harness.client._request_token_plan

    def plan_then_expire(*args: Any, **kwargs: Any) -> Any:
        plan = original_request_token_plan(*args, **kwargs)
        _ControlledDateTime.current = harness.runtime.evidence.expires_at
        return plan

    monkeypatch.setattr(harness.client, "_request_token_plan", plan_then_expire)
    try:
        with pytest.raises(OpenRouterModelRefreshError, match="future-dated or expired"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_expiry_after_reserve_releases_atomic_reservation_and_makes_zero_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )

    @dataclass(slots=True)
    class ExpireAfterReserve:
        def request_ready(self, **_values: Any) -> None:
            return None

        def request_dispatched(self, *, logical_request_id: str) -> None:
            del logical_request_id
            _ControlledDateTime.current = harness.runtime.evidence.expires_at

    harness.client.bind_request_lifecycle_observer(ExpireAfterReserve())
    try:
        with pytest.raises(OpenRouterModelRefreshError, match="future-dated or expired"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"


@pytest.mark.asyncio
async def test_pricing_expiry_after_reserve_releases_atomic_reservation_and_makes_zero_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    refresh_route = next(
        route
        for route in harness.runtime.evidence.routes
        if route.exact_model_id == harness.model and route.audit_selected
    )
    original_refresh_check = openrouter_module._TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH

    def retain_refresh_while_pricing_expires(
        subject: OpenRouterClient,
        **kwargs: Any,
    ) -> AuditModelRefreshRouteEvidence:
        if subject is harness.client:
            return refresh_route
        return original_refresh_check(subject, **kwargs)

    monkeypatch.setattr(
        openrouter_module,
        "_TRUSTED_REQUIRE_REAL_AUDIT_MODEL_REFRESH",
        retain_refresh_while_pricing_expires,
    )

    @dataclass(slots=True)
    class ExpirePricingAfterReserve:
        def request_ready(self, **_values: Any) -> None:
            return None

        def request_dispatched(self, *, logical_request_id: str) -> None:
            del logical_request_id
            _ControlledDateTime.current = harness.runtime.pricing_evidence.expires_at

    harness.client.bind_request_lifecycle_observer(ExpirePricingAfterReserve())
    try:
        with pytest.raises(
            OpenRouterModelRefreshPricingError,
            match="future-dated or expired",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"


@pytest.mark.asyncio
async def test_observer_delay_cannot_cross_refresh_expiry_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    observer = _ExpiringLifecycleObserver(harness.runtime)
    harness.client.bind_request_lifecycle_observer(observer)
    try:
        with pytest.raises(OpenRouterModelRefreshError, match="future-dated or expired"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"


@pytest.mark.asyncio
async def test_transport_lock_delay_cannot_cross_refresh_expiry_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    binding = openrouter_module._lookup_trusted_transport_binding(harness.client)
    assert binding is not None
    request_lock = _ObservedRequestLock()
    original_validate_transport = openrouter_module._TRUSTED_VALIDATE_TRANSPORT_PROVENANCE

    def preserve_closed_mock_transport(subject: OpenRouterClient) -> ExecutionEvidenceKind:
        if subject is harness.client:
            return ExecutionEvidenceKind.MOCK
        return original_validate_transport(subject)

    monkeypatch.setattr(
        openrouter_module,
        "_TRUSTED_VALIDATE_TRANSPORT_PROVENANCE",
        preserve_closed_mock_transport,
    )
    original_execution_evidence = binding.execution_evidence
    original_request_lock = binding.request_lock
    object.__setattr__(binding, "execution_evidence", ExecutionEvidenceKind.REAL)
    object.__setattr__(binding, "request_lock", request_lock)
    completion_task = asyncio.create_task(_complete(harness))
    try:
        async with request_lock:
            await asyncio.wait_for(request_lock.contended.wait(), timeout=5)
            _ControlledDateTime.current = harness.runtime.evidence.expires_at
        with pytest.raises(OpenRouterModelRefreshError, match="future-dated or expired"):
            await completion_task
    finally:
        object.__setattr__(binding, "execution_evidence", original_execution_evidence)
        object.__setattr__(binding, "request_lock", original_request_lock)
        if not completion_task.done():
            completion_task.cancel()
        with suppress(asyncio.CancelledError, OpenRouterModelRefreshError):
            await completion_task
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"


@pytest.mark.asyncio
async def test_durable_commit_delay_cannot_cross_refresh_expiry_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )

    class ExpireAfterDurableCommitDateTime(datetime):
        @classmethod
        def now(cls, timezone: tzinfo | None = None) -> datetime:
            committed = any(
                entry.status.value == "uncertain_accounted"
                for entry in harness.ledger.snapshot().entries
            )
            value = (
                harness.runtime.evidence.expires_at if committed else harness.runtime.verified_at
            )
            return value if timezone is None else value.astimezone(timezone)

    monkeypatch.setattr(openrouter_module, "datetime", ExpireAfterDurableCommitDateTime)
    try:
        with pytest.raises(OpenRouterModelRefreshError, match="future-dated or expired"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "uncertain_accounted"
    assert snapshot.spent_usd == snapshot.entries[0].reserved_usd
    assert len(harness.usage.records) == 1
    assert Decimal(harness.usage.records[0].accounted_cost_usd_exact or "-1") == (
        snapshot.spent_usd
    )


def _assert_refresh_usage(harness: _Harness, routing: dict[str, Any]) -> None:
    evidence = harness.runtime.evidence
    route_payload = routing["audit_model_refresh_route_evidence"]
    route = AuditModelRefreshRouteEvidence.model_validate_json(
        json.dumps(route_payload),
        strict=True,
    )
    assert route.runtime_authorized is False
    assert route.exact_model_id == harness.model
    assert routing["audit_model_refresh_evidence_sha256"] == evidence.evidence_sha256
    assert routing["audit_model_refresh_workflow_status_sha256"] == (
        evidence.workflow_status_sha256
    )
    assert routing["audit_model_refresh_snapshot_sha256"] == evidence.snapshot_sha256
    assert routing["audit_model_refresh_route_evidence_sha256"] == route.route_evidence_sha256
    assert routing["audit_model_refresh_guard_capability_sha256"] == (
        harness.runtime.guard.capability_sha256
    )
    assert routing["audit_model_refresh_technical_route_set_sha256"] == (
        evidence.technical_route_set_sha256
    )
    assert routing["audit_model_refresh_audit_route_set_sha256"] == (
        evidence.audit_route_set_sha256
    )


def _assert_refresh_pricing_usage(harness: _Harness, routing: dict[str, Any]) -> None:
    evidence = harness.runtime.pricing_evidence
    route = AuditModelRefreshPricingRouteEvidence.model_validate_json(
        json.dumps(routing["audit_model_refresh_pricing_route_evidence"]),
        strict=True,
    )
    assert route.pricing_use_authorized is False
    assert route.exact_model_id == harness.model
    assert route == next(
        item
        for item in evidence.routes
        if item.exact_model_id == harness.model and item.audit_selected
    )
    assert routing["audit_model_refresh_pricing_evidence_sha256"] == evidence.evidence_sha256
    assert routing["audit_model_refresh_pricing_route_evidence_sha256"] == (
        route.route_evidence_sha256
    )
    assert routing["audit_model_refresh_pricing_authority_capability_sha256"] == (
        harness.runtime.pricing_authority.capability_sha256
    )
    attempts = tuple(
        AuditModelRefreshPricingAttemptEvidence.model_validate_json(json.dumps(item), strict=True)
        for item in routing["audit_model_refresh_pricing_attempts"]
    )
    assert attempts
    assert routing["audit_model_refresh_pricing_attempt_sha256s"] == [
        item.evidence_sha256 for item in attempts
    ]
    assert routing["audit_model_refresh_pricing_attempt"] == attempts[-1].model_dump(mode="json")
    assert routing["audit_model_refresh_pricing_attempt_sha256"] == (attempts[-1].evidence_sha256)
    assert all(item.pricing_use_authorized is False for item in attempts)
    assert all(item.provider_access_authorized is False for item in attempts)


def _reseal_cache_read_pricing_attempt(
    attempt: AuditModelRefreshPricingAttemptEvidence,
    *,
    current_cache_read: str,
    component_cache_read: str,
) -> dict[str, Any]:
    payload = attempt.model_dump(mode="python")
    current_pricing = dict(payload["current_pricing"])
    current_pricing["input_cache_read"] = current_cache_read
    payload["current_pricing"] = current_pricing
    payload["current_pricing_sha256"] = schemas_module._canonical_model_sha256(current_pricing)
    components = [dict(component) for component in payload["components"]]
    for component in components:
        if component["pricing_field"] == "input_cache_read":
            component["unit_price_usd_exact"] = component_cache_read
    payload["components"] = tuple(components)
    temporary_bound = openrouter_module._trusted_endpoint_request_cost_bound_from_pricing(
        exact_model_id=attempt.exact_model_id,
        provider_endpoint=attempt.provider_endpoint,
        request_material="synthetic self-resealed pricing attempt",
        pricing={
            component["pricing_field"]: component["unit_price_usd_exact"]
            for component in components
        },
        maximum_units={
            component["pricing_field"]: component["maximum_units"] for component in components
        },
    )
    rebound = EndpointRequestCostBound(
        exact_model_id=attempt.exact_model_id,
        provider_endpoint=attempt.provider_endpoint,
        request_material_sha256=attempt.request_material_sha256,
        pricing_snapshot_sha256=temporary_bound.pricing_snapshot_sha256,
        components=temporary_bound.components,
    )
    payload["cost_bound_pricing_snapshot_sha256"] = rebound.pricing_snapshot_sha256
    payload["maximum_cost_usd_exact"] = format(
        openrouter_module._trusted_endpoint_request_maximum_cost_usd(rebound),
        "f",
    )
    payload["evidence_sha256"] = schemas_module._pricing_attempt_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )
    return payload


def _reseal_extra_nonrouter_pricing_attempt(
    attempt: AuditModelRefreshPricingAttemptEvidence,
    *,
    field: str,
    price: str,
) -> dict[str, Any]:
    payload = attempt.model_dump(mode="python")
    for map_field, hash_field in (
        ("baseline_pricing", "baseline_pricing_sha256"),
        ("current_pricing", "current_pricing_sha256"),
    ):
        pricing = dict(payload[map_field])
        pricing[field] = price
        pricing = dict(sorted(pricing.items()))
        payload[map_field] = pricing
        payload[hash_field] = schemas_module._canonical_model_sha256(pricing)
    payload["qualified_pricing_snapshot_sha256"] = payload["baseline_pricing_sha256"]
    components = [dict(component) for component in payload["components"]]
    components.append(
        {
            "pricing_field": field,
            "unit_price_usd_exact": price,
            "maximum_units": 0,
        }
    )
    components.sort(key=lambda component: component["pricing_field"])
    payload["components"] = tuple(components)
    temporary_bound = openrouter_module._trusted_endpoint_request_cost_bound_from_pricing(
        exact_model_id=attempt.exact_model_id,
        provider_endpoint=attempt.provider_endpoint,
        request_material="synthetic self-resealed extra pricing attempt",
        pricing={
            component["pricing_field"]: component["unit_price_usd_exact"]
            for component in components
        },
        maximum_units={
            component["pricing_field"]: component["maximum_units"] for component in components
        },
    )
    rebound = EndpointRequestCostBound(
        exact_model_id=attempt.exact_model_id,
        provider_endpoint=attempt.provider_endpoint,
        request_material_sha256=attempt.request_material_sha256,
        pricing_snapshot_sha256=temporary_bound.pricing_snapshot_sha256,
        components=temporary_bound.components,
    )
    payload["cost_bound_pricing_snapshot_sha256"] = rebound.pricing_snapshot_sha256
    payload["maximum_cost_usd_exact"] = format(
        openrouter_module._trusted_endpoint_request_maximum_cost_usd(rebound),
        "f",
    )
    payload["evidence_sha256"] = schemas_module._pricing_attempt_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )
    return payload


@pytest.mark.asyncio
async def test_success_usage_projects_typed_non_authorizing_refresh_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"refresh current"}',
            model=model,
            provider=provider,
        ),
    )
    endpoint_pricing_before = harness.client._endpoint_pricing[harness.model]
    try:
        completion = await _complete(harness)
    finally:
        await harness.client.close()

    assert completion.value.answer == "refresh current"
    assert len(harness.requests) == 1
    _assert_refresh_usage(harness, completion.usage_record.routing)
    _assert_refresh_pricing_usage(harness, completion.usage_record.routing)
    metadata = harness.requests[0]["metadata"]
    route = completion.usage_record.routing["audit_model_refresh_route_evidence"]
    refresh_metadata = {
        key: value
        for key, value in metadata.items()
        if key.startswith("mmaudit_refresh_") and not key.startswith("mmaudit_refresh_pricing_")
    }
    assert refresh_metadata == {
        "mmaudit_refresh_evidence_sha256": harness.runtime.evidence.evidence_sha256,
        "mmaudit_refresh_workflow_status_sha256": (harness.runtime.evidence.workflow_status_sha256),
        "mmaudit_refresh_snapshot_sha256": harness.runtime.evidence.snapshot_sha256,
        "mmaudit_refresh_route_evidence_sha256": route["route_evidence_sha256"],
        "mmaudit_refresh_guard_capability_sha256": (harness.runtime.guard.capability_sha256),
        "mmaudit_refresh_technical_route_set_sha256": (
            harness.runtime.evidence.technical_route_set_sha256
        ),
        "mmaudit_refresh_audit_route_set_sha256": (harness.runtime.evidence.audit_route_set_sha256),
        "mmaudit_refresh_expires_at": harness.runtime.evidence.expires_at.isoformat(),
    }
    assert "refresh_evidence_sha256" not in metadata
    assert "refresh_route_evidence_sha256" not in metadata
    assert harness.client._endpoint_pricing[harness.model] == endpoint_pricing_before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "current_completion",
    [
        "0.00000209",
        "0.00000191",
        "0.000002000000000000000000000000000001",
    ],
    ids=["increase", "decrease", "hostile-nonbinary-rounding"],
)
async def test_current_price_drives_provider_cap_and_exact_conservative_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    current_completion: str,
) -> None:
    current_pricing = {
        "completion": current_completion,
        "prompt": "0.000001",
    }
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        current_pricing=current_pricing,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"bounded current pricing"}',
            model=model,
            provider=provider,
        ),
    )
    try:
        with localcontext() as context:
            if current_completion.endswith("000001"):
                context.prec = 6
            completion = await _complete(harness)
    finally:
        await harness.client.close()

    routing = completion.usage_record.routing
    _assert_refresh_pricing_usage(harness, routing)
    route = AuditModelRefreshPricingRouteEvidence.model_validate_json(
        json.dumps(routing["audit_model_refresh_pricing_route_evidence"]),
        strict=True,
    )
    attempt = AuditModelRefreshPricingAttemptEvidence.model_validate_json(
        json.dumps(routing["audit_model_refresh_pricing_attempt"]),
        strict=True,
    )
    assert route.baseline_pricing == {
        "completion": "0.000002",
        "prompt": "0.000001",
    }
    assert route.current_pricing == current_pricing
    assert routing["qualified_pricing_snapshot_sha256"] == route.baseline_pricing_sha256
    assert routing["endpoint_pricing_sha256"] == route.current_pricing_sha256
    assert routing["endpoint_snapshot_sha256"] == (attempt.current_endpoint_snapshot_sha256)
    body_max_price = harness.requests[0]["provider"]["max_price"]
    assert attempt.provider_max_price == {
        field: format(Decimal(str(value)).normalize(), "f")
        for field, value in sorted(body_max_price.items())
    }
    components = {item.pricing_field: item for item in attempt.components}
    cap_completion_per_token = Decimal(str(body_max_price["completion"])) / Decimal(1_000_000)
    assert Decimal(components["completion"].unit_price_usd_exact) == (cap_completion_per_token)
    assert cap_completion_per_token >= Decimal(current_completion)
    cap_implied_maximum = sum(
        (
            Decimal(component.unit_price_usd_exact) * component.maximum_units
            for component in attempt.components
        ),
        start=Decimal(0),
    )
    assert Decimal(attempt.maximum_cost_usd_exact) >= cap_implied_maximum
    ledger_entry = harness.ledger.snapshot().entries[0]
    assert ledger_entry.reserved_usd == Decimal(attempt.maximum_cost_usd_exact)


@pytest.mark.asyncio
async def test_refresh_cache_read_is_reserved_at_transmitted_prompt_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        qualified_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
        current_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"cache-read bounded"}',
            model=model,
            provider=provider,
        ),
    )
    try:
        completion = await _complete(harness)
    finally:
        await harness.client.close()

    routing = completion.usage_record.routing
    attempt = AuditModelRefreshPricingAttemptEvidence.model_validate_json(
        json.dumps(routing["audit_model_refresh_pricing_attempt"]),
        strict=True,
    )
    body_max_price = harness.requests[0]["provider"]["max_price"]
    prompt_cap = Decimal(str(body_max_price["prompt"])) / Decimal(1_000_000)
    components = {component.pricing_field: component for component in attempt.components}
    assert attempt.current_pricing["input_cache_read"] == "0.0000001"
    assert Decimal(components["prompt"].unit_price_usd_exact) == prompt_cap
    assert Decimal(components["input_cache_read"].unit_price_usd_exact) == prompt_cap
    assert components["prompt"].maximum_units == components["input_cache_read"].maximum_units
    additive_input_worst_case = prompt_cap * (
        components["prompt"].maximum_units + components["input_cache_read"].maximum_units
    )
    assert Decimal(attempt.maximum_cost_usd_exact) >= additive_input_worst_case
    assert harness.ledger.snapshot().entries[0].reserved_usd == Decimal(
        attempt.maximum_cost_usd_exact
    )


@pytest.mark.asyncio
async def test_refresh_attempt_rejects_self_resealed_cache_dominance_and_bound_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        qualified_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
        current_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"cache-read evidence"}',
            model=model,
            provider=provider,
        ),
    )
    try:
        completion = await _complete(harness)
    finally:
        await harness.client.close()
    attempt = AuditModelRefreshPricingAttemptEvidence.model_validate_json(
        json.dumps(completion.usage_record.routing["audit_model_refresh_pricing_attempt"]),
        strict=True,
    )

    nondominated = _reseal_cache_read_pricing_attempt(
        attempt,
        current_cache_read="0.000001000000000001",
        component_cache_read="0.000001000000000001",
    )
    with pytest.raises(ValueError, match="not dominated by its prompt price"):
        AuditModelRefreshPricingAttemptEvidence.model_validate(nondominated, strict=True)

    underbounded = _reseal_cache_read_pricing_attempt(
        attempt,
        current_cache_read="0.0000001",
        component_cache_read="0.0000001",
    )
    with pytest.raises(ValueError, match="bound differs from provider prompt cap"):
        AuditModelRefreshPricingAttemptEvidence.model_validate(underbounded, strict=True)

    for field, price, message in (
        ("input_cache_write", "0", "uncappable variable pricing component"),
        ("internal_reasoning", "0", "uncappable variable pricing component"),
        ("web_search", "0.0000001", "uncappable nonzero pricing component"),
    ):
        resealed = _reseal_extra_nonrouter_pricing_attempt(
            attempt,
            field=field,
            price=price,
        )
        with pytest.raises(ValueError, match=message):
            AuditModelRefreshPricingAttemptEvidence.model_validate(resealed, strict=True)


@pytest.mark.asyncio
async def test_exact_accounted_cost_survives_hostile_ambient_decimal_precision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact_cost = Decimal("0.00987654321012345")
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        current_pricing={
            "completion": "0.000002000000000000000000000000000001",
            "prompt": "0.000001",
        },
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"exact accounted cost"}',
            cost=float(exact_cost),
            model=model,
            provider=provider,
        ),
    )
    try:
        with localcontext() as context:
            context.prec = 6
            completion = await _complete(harness)
    finally:
        await harness.client.close()

    record = completion.usage_record
    snapshot = harness.ledger.snapshot()
    assert record.reported_cost_usd_exact == format(exact_cost, "f")
    assert snapshot.spent_usd == exact_cost
    assert Decimal(record.accounted_cost_usd_exact or "-1") == snapshot.spent_usd
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].actual_cost_usd == exact_cost
    assert snapshot.entries[0].accounted_cost_usd == exact_cost
    assert harness.usage.records == [record]
    assert type(record).model_validate_json(record.model_dump_json()) == record
    _assert_refresh_pricing_usage(harness, record.routing)
    attempt = AuditModelRefreshPricingAttemptEvidence.model_validate_json(
        json.dumps(record.routing["audit_model_refresh_pricing_attempt"]),
        strict=True,
    )
    assert snapshot.entries[0].reserved_usd == Decimal(attempt.maximum_cost_usd_exact)
    assert snapshot.entries[0].accounted_cost_usd <= snapshot.entries[0].reserved_usd


@pytest.mark.asyncio
async def test_failure_usage_retains_last_dispatched_refresh_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, _model, _provider: httpx.Response(
            400,
            json={"error": "synthetic refusal"},
        ),
    )
    try:
        with pytest.raises(OpenRouterModelError):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert len(harness.requests) == 1
    assert len(harness.usage.records) == 1
    _assert_refresh_usage(harness, harness.usage.records[0].routing)
    _assert_refresh_pricing_usage(harness, harness.usage.records[0].routing)
    attempt = AuditModelRefreshPricingAttemptEvidence.model_validate_json(
        json.dumps(harness.usage.records[0].routing["audit_model_refresh_pricing_attempt"]),
        strict=True,
    )
    assert harness.ledger.snapshot().entries[0].reserved_usd == Decimal(
        attempt.maximum_cost_usd_exact
    )


@pytest.mark.asyncio
async def test_retry_retains_one_ordered_self_hashed_price_bound_per_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    exact_second_cost = Decimal("0.00987654321012345")

    def respond(
        _request: httpx.Request,
        model: str,
        provider: str,
    ) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, json={"error": "synthetic retry"})
        return _completion_response(
            '{"answer":"retry bounded"}',
            cost=float(exact_second_cost),
            model=model,
            provider=provider,
        )

    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        qualified_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
        current_pricing={
            "completion": "0.000002000000000000000000000000000001",
            "input_cache_read": "0.0000001",
            "prompt": "0.000001",
        },
        response=respond,
    )
    harness.client.execution = harness.client.execution.model_copy(update={"max_model_retries": 1})

    async def skip_backoff(_attempt: int, _retry_after: str | None) -> None:
        return None

    monkeypatch.setattr(harness.client, "_backoff", skip_backoff)
    try:
        with localcontext() as context:
            context.prec = 6
            completion = await _complete(harness)
    finally:
        await harness.client.close()

    assert len(harness.requests) == 2
    routing = completion.usage_record.routing
    _assert_refresh_pricing_usage(harness, routing)
    attempts = tuple(
        AuditModelRefreshPricingAttemptEvidence.model_validate_json(
            json.dumps(item),
            strict=True,
        )
        for item in routing["audit_model_refresh_pricing_attempts"]
    )
    assert len(attempts) == 2
    assert attempts[0].attempt_request_id == attempts[0].logical_request_id
    assert attempts[1].attempt_request_id == (f"{attempts[0].logical_request_id}:attempt:2")
    assert all(item.transport_attempted for item in attempts)
    assert all(item.transport_checked_at is not None for item in attempts)
    assert attempts[0].request_body_sha256 == attempts[1].request_body_sha256
    assert attempts[0].cost_bound_pricing_snapshot_sha256 == (
        attempts[1].cost_bound_pricing_snapshot_sha256
    )
    snapshot = harness.ledger.snapshot()
    assert len(snapshot.entries) == 2
    assert all("input_cache_read" in attempt.current_pricing for attempt in attempts)
    assert all(
        entry.reserved_usd == Decimal(attempt.maximum_cost_usd_exact)
        for entry, attempt in zip(snapshot.entries, attempts, strict=True)
    )
    with localcontext() as context:
        context.prec = 160
        exact_total = sum(
            (entry.accounted_cost_usd for entry in snapshot.entries),
            start=Decimal(0),
        )
    assert snapshot.entries[0].status.value == "uncertain_accounted"
    assert snapshot.entries[1].actual_cost_usd == exact_second_cost
    assert snapshot.spent_usd == exact_total
    assert Decimal(completion.usage_record.accounted_cost_usd_exact or "-1") == exact_total


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "drift_field",
    ["provider_identities", "required_request_parameters", "structured_output_parameters"],
)
async def test_nonprice_endpoint_drift_refuses_before_claim_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift_field: str,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    registered = harness.client._endpoint_pricing[harness.model]
    endpoint = registered.endpoints[0]
    drifted_endpoint = (
        replace(endpoint, provider_identities=(*endpoint.provider_identities, "forged-alias"))
        if drift_field == "provider_identities"
        else (
            replace(
                endpoint,
                required_request_parameters=(
                    *endpoint.required_request_parameters,
                    "reasoning",
                ),
            )
            if drift_field == "required_request_parameters"
            else replace(endpoint, structured_output_parameters=())
        )
    )
    harness.client._endpoint_pricing[harness.model] = replace(
        registered,
        endpoints=(drifted_endpoint,),
    )
    try:
        with pytest.raises(
            OpenRouterModelRefreshPricingError,
            match="exact current provider route",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_current_endpoint_snapshot_custody_rejects_direct_policy_hash_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    registered = harness.client._endpoint_pricing[harness.model]
    harness.client._endpoint_pricing[harness.model] = replace(
        registered,
        snapshot_sha256="f" * 64,
    )
    try:
        with pytest.raises(
            OpenRouterModelRefreshPricingError,
            match="current endpoint pricing changed",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


def test_current_endpoint_snapshot_registration_is_first_write_immutable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"unused"}',
            model=model,
            provider=provider,
        ),
    )
    original_policy = harness.client._endpoint_pricing[harness.model]
    original_hash = openrouter_module._lookup_trusted_endpoint_snapshot(
        harness.client,
        harness.model,
    )
    same_runtime = synthetic_refresh_runtime(tmp_path / "same-refresh-runtime")
    _register_current_refresh_endpoint(
        harness.client,
        same_runtime,
        harness.model,
    )
    assert harness.client._endpoint_pricing[harness.model] == original_policy
    different_runtime = synthetic_refresh_runtime(
        tmp_path / "different-refresh-runtime",
        current_pricing={
            "completion": "0.00000201",
            "prompt": "0.000001",
        },
    )

    with pytest.raises(OpenRouterCostControlError, match="cannot be replaced"):
        _register_current_refresh_endpoint(
            harness.client,
            different_runtime,
            harness.model,
        )

    assert harness.client._endpoint_pricing[harness.model] == original_policy
    assert (
        openrouter_module._lookup_trusted_endpoint_snapshot(
            harness.client,
            harness.model,
        )
        == original_hash
    )


@pytest.mark.asyncio
async def test_mutated_paid_control_requirement_is_rejected_before_claim_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    harness.client._requires_paid_controls = False
    try:
        with pytest.raises(OpenRouterPrivacyError, match="paid-control requirement changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_mutated_atomic_ledger_configuration_is_rejected_before_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )

    class PathSubclass(type(Path("/"))):
        pass

    class DecimalSubclass(Decimal):
        pass

    mutations: tuple[tuple[str, Any], ...] = (
        ("path", tmp_path / "retargeted-ledger.json"),
        ("path", PathSubclass(str(harness.ledger.path))),
        ("lock_path", tmp_path / ".retargeted-ledger.json.lock"),
        ("cap_usd", Decimal("19")),
        ("cap_usd", DecimalSubclass(str(harness.ledger.cap_usd))),
        ("_thread_lock", threading.RLock()),
    )
    try:
        for attribute, changed in mutations:
            original = getattr(harness.ledger, attribute)
            setattr(harness.ledger, attribute, changed)
            try:
                with pytest.raises(
                    OpenRouterPrivacyError,
                    match=r"changed after validation|configuration is invalid",
                ):
                    await _complete(harness)
            finally:
                setattr(harness.ledger, attribute, original)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_deceptive_budget_config_subclasses_are_rejected_before_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        per_role_usd_caps={"source_audit": "1"},
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )

    class DeceptiveCaps(dict[str, Decimal]):
        def get(self, _key: str, _default: Decimal | None = None) -> Decimal:
            return Decimal("999")

    class DeceptiveFloat(float):
        pass

    mutations: tuple[tuple[str, Any], ...] = (
        (
            "per_role_usd_caps",
            DeceptiveCaps(harness.client.budget.per_role_usd_caps),
        ),
        ("total_usd", DeceptiveFloat(harness.client.budget.total_usd)),
    )
    try:
        for attribute, changed in mutations:
            original = getattr(harness.client.budget, attribute)
            setattr(harness.client.budget, attribute, changed)
            try:
                with pytest.raises(
                    OpenRouterPrivacyError,
                    match="budget configuration is invalid",
                ):
                    await _complete(harness)
            finally:
                setattr(harness.client.budget, attribute, original)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_negative_budget_accounting_state_is_rejected_before_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        per_role_usd_caps={"source_audit": "0.015"},
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    harness.client.budget._spent_role_usd = {"source_audit": Decimal("-100")}
    try:
        with pytest.raises(OpenRouterPrivacyError, match="budget accounting state changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_zero_reset_after_spend_cannot_reopen_role_or_request_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        per_role_usd_caps={"source_audit": "0.015"},
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"first request only"}',
            cost=0.01,
            model=model,
            provider=provider,
        ),
    )
    try:
        first = await _complete(harness)
        assert Decimal(first.usage_record.accounted_cost_usd_exact or "-1") == Decimal("0.01")
        assert harness.client.budget._spent_role_usd == {"source_audit": Decimal("0.01")}
        assert harness.client.budget._request_limit_counts

        harness.client.budget._spent_role_usd.clear()
        harness.client.budget._request_limit_counts.clear()
        with pytest.raises(OpenRouterPrivacyError, match="budget accounting state changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert len(harness.requests) == 1
    assert len(snapshot.entries) == 1
    assert snapshot.spent_usd == Decimal("0.01")
    assert snapshot.entries[0].status.value == "reconciled"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "callable_name",
    [
        "reserve",
        "reconcile",
        "reconciled_cost_usd_exact",
        "release",
        "commit_active_reservation_for_transport",
        "_maximum_request_cost",
        "_validate_request_scope",
        "_require_scoped_capacity",
        "_require_usd_scope_capacity",
        "_reserve_scoped",
        "_close_scoped_reservation",
        "_release_scoped",
    ],
)
async def test_budget_lifecycle_and_cap_helper_override_is_rejected_before_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    callable_name: str,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        per_role_usd_caps={"source_audit": "0.0000001"},
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    original = getattr(harness.client.budget, callable_name)
    monkeypatch.setattr(harness.client.budget, callable_name, lambda *_args, **_kwargs: original)
    try:
        with pytest.raises(OpenRouterPrivacyError, match="budget callables changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_noop_atomic_ledger_write_override_is_rejected_before_reserve_or_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    monkeypatch.setattr(harness.ledger, "_write_state", lambda _state: None)
    try:
        with pytest.raises(OpenRouterPrivacyError, match="cost-ledger callables changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_released_persistent_reservation_cannot_reach_provider_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )

    @dataclass(slots=True)
    class ReleaseAfterReserve:
        def request_ready(self, **_values: Any) -> None:
            return None

        def request_dispatched(self, *, logical_request_id: str) -> None:
            reservation = harness.client.budget._issued[logical_request_id]
            assert reservation.persistent is not None
            harness.ledger.release(
                reservation.persistent,
                reason=ReleaseReason.FAILED_BEFORE_SEND,
            )

    harness.client.bind_request_lifecycle_observer(ReleaseAfterReserve())
    try:
        with pytest.raises(OpenRouterSchemaError, match="transport failed safely"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.spent_usd == 0
    assert snapshot.active_reserved_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "surface",
    ["maximum_cost", "from_pricing", "maximum_units_for"],
)
async def test_cost_bound_class_surface_mutation_cannot_understate_nonprompt_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    pricing = {
        "completion": "0.000002",
        "prompt": "0.000001",
        "request": "0.001",
    }
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        qualified_pricing=pricing,
        current_pricing=pricing,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    if surface == "maximum_cost":
        monkeypatch.setattr(
            EndpointRequestCostBound,
            "maximum_cost_usd",
            property(lambda _bound: Decimal("0.000000000000000001")),
        )
    elif surface == "maximum_units_for":
        monkeypatch.setattr(
            EndpointRequestCostBound,
            "maximum_units_for",
            lambda _bound, _field: 0,
        )
    else:
        original = EndpointRequestCostBound.from_endpoint_pricing.__func__

        def understate_request_units(
            cls: type[EndpointRequestCostBound],
            **kwargs: Any,
        ) -> EndpointRequestCostBound:
            bound = original(cls, **kwargs)
            object.__setattr__(
                bound,
                "components",
                tuple(
                    replace(component, maximum_units=0)
                    if component.pricing_field == "request"
                    else component
                    for component in bound.components
                ),
            )
            return bound

        monkeypatch.setattr(
            EndpointRequestCostBound,
            "from_endpoint_pricing",
            classmethod(understate_request_units),
        )
    try:
        with pytest.raises(OpenRouterPrivacyError, match="endpoint cost-bound callables changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert harness.client._claimed_request_ids == set()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "callable_name",
    [
        "build_request",
        "_endpoint_request_cost_bound",
        "_seal_audit_model_refresh_pricing_control",
        "_ensure_request_size",
        "_store_debug",
        "_ensure_no_credential_in_value",
    ],
)
async def test_pricing_control_callable_override_is_rejected_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    callable_name: str,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    original = getattr(harness.client, callable_name)

    def overridden(*args: Any, **kwargs: Any) -> Any:
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.client, callable_name, overridden)
    try:
        with pytest.raises(OpenRouterPrivacyError, match="callables changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert snapshot.entries == ()


@pytest.mark.asyncio
async def test_raw_prompt_debug_override_cannot_mutate_live_request_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        store_raw_prompts=True,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )

    def mutate_debug_body(_request_id: str, _filename: str, value: Any) -> None:
        value["provider"]["max_price"]["completion"] = 999_999.0

    monkeypatch.setattr(harness.client, "_store_debug", mutate_debug_body)
    try:
        with pytest.raises(OpenRouterPrivacyError, match="callables changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert snapshot.entries == ()


@pytest.mark.asyncio
async def test_final_inside_lock_request_body_recheck_rejects_direct_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    original = openrouter_module._TRUSTED_BOUNDED_REQUEST

    async def mutate_before_transport(
        subject: OpenRouterClient,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        body = kwargs["json_body"]
        body["provider"]["only"] = ["forged-provider"]
        body["provider"]["max_price"]["completion"] = 999_999.0
        return await original(subject, method, path, **kwargs)

    monkeypatch.setattr(
        openrouter_module,
        "_TRUSTED_BOUNDED_REQUEST",
        mutate_before_transport,
    )
    try:
        with pytest.raises(
            OpenRouterModelRefreshPricingError,
            match=r"sealed provider policy|changed after exact pricing",
        ):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status.value == "released"


@pytest.mark.parametrize(
    "callable_name",
    [
        "build_request",
        "_endpoint_request_cost_bound",
        "_seal_audit_model_refresh_pricing_control",
        "_ensure_request_size",
        "_store_debug",
        "_ensure_no_credential_in_value",
    ],
)
def test_pricing_control_class_callable_mutation_breaks_pristine_boundary(
    monkeypatch: pytest.MonkeyPatch,
    callable_name: str,
) -> None:
    original = getattr(OpenRouterClient, callable_name)

    def overridden(*args: Any, **kwargs: Any) -> Any:
        return original(*args, **kwargs)

    monkeypatch.setattr(OpenRouterClient, callable_name, overridden)
    assert openrouter_module._openrouter_client_callables_are_pristine() is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "callable_name",
    ["_ensure_request_size", "_store_debug", "_ensure_no_credential_in_value"],
)
async def test_request_body_class_callable_mutation_is_rejected_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    callable_name: str,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        store_raw_prompts=(callable_name == "_store_debug"),
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"must not execute"}',
            model=model,
            provider=provider,
        ),
    )
    original = getattr(OpenRouterClient, callable_name)

    def overridden(*args: Any, **kwargs: Any) -> Any:
        return original(*args, **kwargs)

    monkeypatch.setattr(OpenRouterClient, callable_name, overridden)
    try:
        with pytest.raises(OpenRouterPrivacyError, match="callables changed"):
            await _complete(harness)
    finally:
        await harness.client.close()

    snapshot = harness.ledger.snapshot()
    assert harness.requests == []
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0
    assert snapshot.entries == ()


@pytest.mark.asyncio
async def test_existing_client_requires_the_exact_same_refresh_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"unused"}',
            model=model,
            provider=provider,
        ),
    )
    other = synthetic_refresh_runtime(tmp_path / "other-refresh")
    try:
        harness.client.require_audit_model_refresh_binding(
            audit_model_refresh_evidence=harness.runtime.evidence,
            audit_model_refresh_guard=harness.runtime.guard,
            checked_at=harness.runtime.verified_at,
        )
        with pytest.raises(OpenRouterModelRefreshError, match="binds different"):
            harness.client.require_audit_model_refresh_binding(
                audit_model_refresh_evidence=other.evidence,
                audit_model_refresh_guard=other.guard,
                checked_at=harness.runtime.verified_at,
            )
        harness.client.require_audit_model_refresh_pricing_binding(
            audit_model_refresh_pricing_evidence=harness.runtime.pricing_evidence,
            audit_model_refresh_pricing_authority=harness.runtime.pricing_authority,
            checked_at=harness.runtime.verified_at,
        )
        with pytest.raises(
            OpenRouterModelRefreshPricingError,
            match=r"binds different|differs from its exact refresh custody",
        ):
            harness.client.require_audit_model_refresh_pricing_binding(
                audit_model_refresh_pricing_evidence=other.pricing_evidence,
                audit_model_refresh_pricing_authority=other.pricing_authority,
                checked_at=harness.runtime.verified_at,
            )
    finally:
        await harness.client.close()


def test_pricing_binding_rejects_incomplete_forged_authority_and_mutated_nested_evidence(
    tmp_path: Path,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path / "refresh-runtime")
    refresh_binding = openrouter_module._canonical_audit_model_refresh_binding(
        evidence=runtime.evidence,
        guard=runtime.guard,
    )
    assert refresh_binding is not None
    forged = object.__new__(VerifiedAuditModelRefreshPricingAuthority)
    with pytest.raises(
        OpenRouterModelRefreshPricingError,
        match="incomplete or forged",
    ):
        openrouter_module._canonical_audit_model_refresh_pricing_binding(
            evidence=runtime.pricing_evidence,
            authority=forged,
            refresh_binding=refresh_binding,
        )

    mutated = runtime.pricing_evidence.model_copy(deep=True)
    mutated.routes[0].current_pricing["completion"] = "0.00000201"
    with pytest.raises(
        OpenRouterModelRefreshPricingError,
        match=r"structurally invalid|changed during canonicalization",
    ):
        openrouter_module._canonical_audit_model_refresh_pricing_binding(
            evidence=mutated,
            authority=runtime.pricing_authority,
            refresh_binding=refresh_binding,
        )


def test_pricing_constructor_rejects_refresh_without_technical_or_audit_policy_pair(
    tmp_path: Path,
) -> None:
    runtime = synthetic_refresh_runtime(tmp_path / "refresh-runtime")
    config = runtime.config
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
    )
    with pytest.raises(
        OpenRouterModelRefreshPricingError,
        match="lacks exact technical and audit authority",
    ):
        OpenRouterClient(
            api_key="synthetic-pricing-constructor-key",
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=UsageLedger(),
            base_url="https://fake.test/api/v1/",
            test_only_mock_handler=lambda _request: httpx.Response(500),
            provider_policy=OpenRouterProviderPolicy(
                certification=True,
                only=(runtime.audit_selection.models[0].approved_provider_endpoint,),
            ),
            audit_model_refresh_evidence=runtime.evidence,
            audit_model_refresh_guard=runtime.guard,
            audit_model_refresh_pricing_evidence=runtime.pricing_evidence,
            audit_model_refresh_pricing_authority=runtime.pricing_authority,
        )


@pytest.mark.parametrize(
    "cache_read_price",
    ["0", "0.0000001", "0.000001"],
)
def test_routing_max_price_accepts_only_prompt_dominated_cache_read(
    cache_read_price: str,
) -> None:
    registered = _registered_endpoint_pricing(
        pricing={
            "completion": "0.000002",
            "input_cache_read": cache_read_price,
            "prompt": "0.000001",
        }
    )

    max_price = openrouter_module._routing_max_price((registered,))

    assert "input_cache_read" not in max_price
    assert Decimal(str(max_price["prompt"])) / Decimal(1_000_000) >= Decimal("0.000001")


def test_prompt_and_cache_bounds_share_hostile_upward_rounded_transmitted_cap() -> None:
    exact_price = "0.000001000000000000000000000000000001"
    registered = _registered_endpoint_pricing(
        pricing={
            "completion": "0.000002",
            "input_cache_read": exact_price,
            "prompt": exact_price,
        }
    )

    routing_max_price = openrouter_module._routing_max_price((registered,))
    bounded_pricing = dict(
        openrouter_module._provider_capped_cost_bound_pricing(
            registered,
            routing_max_price,
        )
    )
    transmitted_prompt_cap = Decimal(str(routing_max_price["prompt"])) / Decimal(1_000_000)

    assert transmitted_prompt_cap > Decimal(exact_price)
    assert Decimal(bounded_pricing["prompt"]) == transmitted_prompt_cap
    assert Decimal(bounded_pricing["input_cache_read"]) == transmitted_prompt_cap


@pytest.mark.parametrize(
    ("provider_endpoint", "prompt_price", "completion_price", "cache_read_price"),
    [
        ("novita/fp8", "0.00000132", "0.00000396", "0.000000132"),
        ("coreweave/fp4", "0.00000023", "0.00000096", "0.00000005"),
        ("together", "0.000003", "0.000015", "0.0000003"),
    ],
    ids=("candidate", "primary-judge", "replay-judge"),
)
def test_selected_operator_route_prices_admit_deterministically(
    provider_endpoint: str,
    prompt_price: str,
    completion_price: str,
    cache_read_price: str,
) -> None:
    registered = _registered_endpoint_pricing(
        provider_endpoint=provider_endpoint,
        pricing={
            "completion": completion_price,
            "input_cache_read": cache_read_price,
            "prompt": prompt_price,
        },
    )

    first = openrouter_module._routing_max_price((registered,))
    second = openrouter_module._routing_max_price((registered,))
    bounded_pricing = dict(
        openrouter_module._provider_capped_cost_bound_pricing(
            registered,
            first,
        )
    )
    transmitted_prompt_cap = Decimal(str(first["prompt"])) / Decimal(1_000_000)

    assert first == second
    assert Decimal(cache_read_price) <= Decimal(prompt_price) <= transmitted_prompt_cap
    assert Decimal(bounded_pricing["prompt"]) == transmitted_prompt_cap
    assert Decimal(bounded_pricing["input_cache_read"]) == transmitted_prompt_cap


def test_routing_max_price_rejects_cache_read_above_same_endpoint_prompt() -> None:
    registered = _registered_endpoint_pricing(
        pricing={
            "completion": "0.000002",
            "input_cache_read": "0.000001000000000001",
            "prompt": "0.000001",
        }
    )

    with pytest.raises(
        OpenRouterCostControlError,
        match="endpoint pricing cannot produce the shared provider price cap",
    ):
        openrouter_module._routing_max_price((registered,))


def test_routing_max_price_checks_cache_dominance_per_endpoint_before_aggregate_maximum() -> None:
    nondominated = _registered_endpoint_pricing(
        provider_endpoint="provider-a/fp8",
        pricing={
            "completion": "0.000002",
            "input_cache_read": "0.0000008",
            "prompt": "0.0000005",
        },
    )
    higher_aggregate_prompt = _registered_endpoint_pricing(
        provider_endpoint="provider-b/fp8",
        pricing={
            "completion": "0.000003",
            "input_cache_read": "0.0000009",
            "prompt": "0.000001",
        },
    )

    with pytest.raises(
        OpenRouterCostControlError,
        match="input-cache-read endpoint price exceeds its provider-capped prompt price",
    ):
        openrouter_module._routing_max_price((nondominated, higher_aggregate_prompt))


@pytest.mark.parametrize("field", ["input_cache_write", "internal_reasoning"])
@pytest.mark.parametrize("price", ["0", "0.0000001"])
def test_routing_max_price_rejects_other_uncappable_variable_components(
    field: str,
    price: str,
) -> None:
    registered = _registered_endpoint_pricing(
        pricing={
            "completion": "0.000002",
            field: price,
            "prompt": "0.000001",
        }
    )

    with pytest.raises(OpenRouterCostControlError, match="cannot be provider-capped"):
        openrouter_module._routing_max_price((registered,))


@pytest.mark.parametrize(
    "pricing",
    [
        (("completion", "0.000002"),),
        (("prompt", "0.000001"),),
        (
            ("completion", "0.000002"),
            ("prompt", "0.000001"),
            ("unknown_fee", "0"),
        ),
        (
            ("completion", "0.000002"),
            ("prompt", "0.000001"),
            ("prompt", "0.000001"),
        ),
    ],
)
def test_routing_max_price_rejects_missing_unknown_or_duplicate_components(
    pricing: tuple[tuple[str, str], ...],
) -> None:
    registered = replace(
        _registered_endpoint_pricing(pricing={"completion": "0.000002", "prompt": "0.000001"}),
        pricing=pricing,
    )

    with pytest.raises(OpenRouterCostControlError):
        openrouter_module._routing_max_price((registered,))


@pytest.mark.parametrize(
    "raw_price",
    ["", " ", "NaN", "sNaN", "Infinity", "-Infinity", "-0", "-0.000001"],
)
def test_routing_max_price_rejects_missing_nonfinite_or_negative_prices(
    raw_price: str,
) -> None:
    registered = replace(
        _registered_endpoint_pricing(pricing={"completion": "0.000002", "prompt": "0.000001"}),
        pricing=(("completion", "0.000002"), ("prompt", raw_price)),
    )

    with pytest.raises(
        OpenRouterCostControlError,
        match="endpoint pricing cannot produce the shared provider price cap",
    ):
        openrouter_module._routing_max_price((registered,))


def test_endpoint_price_canonicalization_and_router_cap_ignore_ambient_decimal_precision() -> None:
    exact_price = "0.000002000000000000000000000000000001"
    with localcontext() as context:
        context.prec = 6
        registered = _registered_endpoint_pricing(
            pricing={
                "completion": exact_price,
                "prompt": "0.000001",
            }
        )
        max_price = openrouter_module._routing_max_price((registered,))

    assert dict(registered.pricing)["completion"] == exact_price
    assert Decimal(str(max_price["completion"])) / Decimal(1_000_000) >= Decimal(exact_price)
