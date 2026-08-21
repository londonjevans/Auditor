from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.models.openrouter as openrouter_module
from mmaudit.models.openrouter import (
    OpenRouterCostControlError,
    OpenRouterProviderPolicy,
    OpenRouterRequestCostPreviewError,
    OpenRouterStructuredRequestCostPreview,
    preview_openrouter_structured_request_cost,
)
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningPolicyArtifact,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit.test_openrouter import (
    Answer,
    _client,
    _completion_response,
    _model_discovery_run,
)

_PROMPT_DOMINATED_CACHE_READ_PRICING = {
    "completion": "0.00001",
    "input_cache_read": "0.0000001",
    "prompt": "0.000001",
    "request": "0",
}


def _disabled_reasoning_policy() -> ReasoningPolicyArtifact:
    return ReasoningPolicyArtifact.build(
        controls_by_role={
            role: ReasoningControlProfile.build(
                mode="disabled",
                reserved_reasoning_tokens=0,
            )
            for role in CANONICAL_REASONING_POLICY_ROLES
        }
    )


def _high_effort_reasoning_policy() -> ReasoningPolicyArtifact:
    return ReasoningPolicyArtifact.build(
        controls_by_role={
            role: ReasoningControlProfile.build(
                mode="effort",
                effort="high",
                reserved_reasoning_tokens=4_096,
            )
            for role in CANONICAL_REASONING_POLICY_ROLES
        }
    )


def _preview(
    *,
    config: Any,
    manifest: Any,
    evidence: Any,
    policy: OpenRouterProviderPolicy,
    reasoning_policy: ReasoningPolicyArtifact,
    user_prompt: str = "synthetic provider-free request",
) -> OpenRouterStructuredRequestCostPreview:
    return preview_openrouter_structured_request_cost(
        execution=config.execution,
        privacy=config.privacy,
        token_budgets=config.token_budgets,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        discovery_manifest=manifest,
        discovery_evidence=evidence,
        role="model_benchmark",
        system_prompt="bounded synthetic system prompt",
        user_prompt=user_prompt,
        response_model=Answer,
        schema_name="answer",
        logical_request_id="authrunner-candidate-case-001",
    )


def test_provider_free_request_cost_preview_is_exact_stable_and_nonauthorizing(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    config = config_factory(execution={"max_model_retries": 2, "max_requests_per_agent": 3})
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _disabled_reasoning_policy()

    first = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    second = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )

    assert first == second
    assert first.preview_sha256 == second.preview_sha256
    assert first.maximum_attempts == 3
    assert first.provider_endpoint == "approved-provider"
    assert first.discovery_manifest_sha256 == manifest.manifest_sha256
    assert first.discovery_evidence_sha256 == evidence.discovery_evidence_sha256
    assert first.requested_completion_tokens == (
        first.reserved_output_tokens + first.reserved_reasoning_tokens
    )
    assert Decimal(first.maximum_cost_usd_per_attempt_exact) > Decimal(0)
    assert Decimal(first.maximum_cost_usd_all_attempts_exact) == (
        Decimal(first.maximum_cost_usd_per_attempt_exact) * 3
    )
    components = {component.pricing_field: component for component in first.cost_components}
    raw_endpoint = evidence.endpoint_snapshot.endpoints[0]
    assert raw_endpoint.pricing["input_cache_read"] == "0.0000001"
    assert first.endpoint_pricing_sha256 == raw_endpoint.pricing_sha256
    assert components["input_cache_read"].unit_price_usd_exact == "0.000001"
    assert components["input_cache_read"].maximum_units == first.maximum_priced_prompt_units
    assert components["prompt"].unit_price_usd_exact == "0.000001"
    assert components["prompt"].maximum_units == first.maximum_priced_prompt_units
    additive_input_worst_case = sum(
        Decimal(components[field].unit_price_usd_exact) * components[field].maximum_units
        for field in ("input_cache_read", "prompt")
    )
    assert Decimal(first.maximum_cost_usd_per_attempt_exact) >= (additive_input_worst_case)
    assert not first.authorizes_dispatch
    assert not first.authorizes_budget_reservation
    assert not first.authorizes_provider_transport
    assert not first.grants_review_credit
    assert not first.grants_completion_credit


@pytest.mark.asyncio
async def test_catalog_effort_fallback_dispatches_the_exact_previewed_reasoning_shape(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=3,
        )

    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        model_supported_parameters=(
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ),
        endpoint_supported_parameters=(
            "max_tokens",
            "reasoning",
            "response_format",
            "temperature",
        ),
        model_reasoning={
            "default_enabled": None,
            "supported_efforts": ["low", "high", "max"],
        },
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )

    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _high_effort_reasoning_policy()
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "catalog-effort-preview-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        qualification_routing=(),
        budget=budget,
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        result = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="bounded synthetic system prompt",
            user_prompt="synthetic provider-free request",
            response_model=Answer,
            schema_name="answer",
            logical_request_id="authrunner-candidate-case-001",
            expected_request_cost_preview=preview,
        )
    finally:
        await http_client.aclose()

    assert evidence.reasoning_capability.supported_reasoning_efforts is None
    assert evidence.model_supported_reasoning_efforts == ("low", "high", "max")
    assert preview.reserved_reasoning_tokens == 4_096
    assert len(observed) == 1
    assert json.loads(observed[0].content)["reasoning"] == {
        "effort": "high",
        "exclude": False,
    }
    assert result.usage_record.routing["request_cost_preview_sha256"] == preview.preview_sha256
    assert usage.records == [result.usage_record]


@pytest.mark.parametrize("cache_bound", ["0.0000001", "0.000001000000000001"])
def test_request_cost_preview_rejects_self_resealed_cache_bound_different_from_prompt(
    config_factory: Any,
    tmp_path: Path,
    cache_bound: str,
) -> None:
    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
            certification=True,
        ),
        reasoning_policy=_disabled_reasoning_policy(),
    )
    payload = preview.model_dump(mode="python")
    components = payload["cost_components"]
    for component in components:
        if component["pricing_field"] == "input_cache_read":
            component["unit_price_usd_exact"] = cache_bound
    pricing = {
        component["pricing_field"]: component["unit_price_usd_exact"] for component in components
    }
    maximum_units = {
        component["pricing_field"]: component["maximum_units"] for component in components
    }
    rebound = openrouter_module._trusted_endpoint_request_cost_bound_from_pricing(
        exact_model_id=preview.exact_model_id,
        provider_endpoint=preview.provider_endpoint,
        request_material="mmaudit-provider-free-cost-preview",
        pricing=pricing,
        maximum_units=maximum_units,
    )
    rebound_maximum = openrouter_module._trusted_endpoint_request_maximum_cost_usd(rebound)
    payload["endpoint_cost_bound_pricing_sha256"] = rebound.pricing_snapshot_sha256
    payload["endpoint_cost_bound_projection_sha256"] = (
        openrouter_module._endpoint_request_cost_bound_projection_sha256(
            rebound,
            request_material_projection_sha256=preview.request_material_projection_sha256,
        )
    )
    payload["maximum_cost_usd_per_attempt_exact"] = openrouter_module._format_cost_decimal(
        rebound_maximum
    )
    payload["maximum_cost_usd_all_attempts_exact"] = openrouter_module._multiply_cost_decimal(
        rebound_maximum,
        preview.maximum_attempts,
    )
    payload["preview_sha256"] = openrouter_module._canonical_sha256(
        {key: value for key, value in payload.items() if key != "preview_sha256"}
    )

    with pytest.raises(
        ValueError,
        match="input-cache-read bound differs from its prompt-price bound",
    ):
        OpenRouterStructuredRequestCostPreview.model_validate(payload, strict=True)


@pytest.mark.asyncio
async def test_dispatch_enforces_exact_request_cost_preview_and_records_join(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
        )

    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing=_PROMPT_DOMINATED_CACHE_READ_PRICING,
    )
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _disabled_reasoning_policy()
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "successful-preview-cost-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        qualification_routing=(),
        budget=budget,
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        result = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="bounded synthetic system prompt",
            user_prompt="synthetic provider-free request",
            response_model=Answer,
            schema_name="answer",
            logical_request_id="authrunner-candidate-case-001",
            expected_request_cost_preview=preview,
        )
    finally:
        await http_client.aclose()

    assert result.value.answer == "ok"
    assert len(observed) == 1
    request_body = json.loads(observed[0].content)
    provider_max_price = request_body["provider"]["max_price"]
    assert request_body["provider"]["only"] == ["approved-provider"]
    assert "input_cache_read" not in provider_max_price
    assert Decimal(str(provider_max_price["prompt"])) / Decimal(1_000_000) >= Decimal(
        _PROMPT_DOMINATED_CACHE_READ_PRICING["prompt"]
    )
    assert usage.records == [result.usage_record]
    assert result.usage_record.routing["request_cost_preview_sha256"] == (preview.preview_sha256)
    assert (
        result.usage_record.routing["request_cost_preview_maximum_cost_usd_per_attempt_exact"]
        == preview.maximum_cost_usd_per_attempt_exact
    )
    assert (
        result.usage_record.routing["request_cost_preview_maximum_cost_usd_all_attempts_exact"]
        == preview.maximum_cost_usd_all_attempts_exact
    )


@pytest.mark.asyncio
async def test_request_cost_preview_drift_rejects_before_reserve_or_transport(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    transport_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        return _completion_response('{"answer":"must-not-run"}')

    config = config_factory()
    manifest, evidence = _model_discovery_run(tmp_path)
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )
    reasoning_policy = _disabled_reasoning_policy()
    preview = _preview(
        config=config,
        manifest=manifest,
        evidence=evidence,
        policy=policy,
        reasoning_policy=reasoning_policy,
    )
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "drift-preview-cost-ledger.json",
            cap_usd=Decimal(str(config.execution.budget_usd)),
        ),
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning_policy=reasoning_policy,
        qualification_routing=(),
        budget=budget,
    )
    client.register_model_discovery(evidence=evidence, manifest=manifest)
    try:
        with pytest.raises(OpenRouterRequestCostPreviewError, match="user_prompt_sha256"):
            await client.complete_with_evidence(
                role="model_benchmark",
                models=["alpha/atlas-secure"],
                system_prompt="bounded synthetic system prompt",
                user_prompt="drifted provider request",
                response_model=Answer,
                schema_name="answer",
                logical_request_id="authrunner-candidate-case-001",
                expected_request_cost_preview=preview,
            )
    finally:
        await http_client.aclose()

    assert transport_calls == 0
    assert usage.records == []
    assert budget.spent_usd_exact == Decimal(0)
    assert budget.reserved_input_tokens == 0
    assert budget.reserved_output_tokens == 0


def test_provider_free_request_cost_preview_rejects_cache_read_above_prompt(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    config = config_factory()
    manifest, evidence = _model_discovery_run(
        tmp_path,
        endpoint_pricing={
            "completion": "0.00001",
            "input_cache_read": "0.000001000000000001",
            "prompt": "0.000001",
        },
    )
    policy = OpenRouterProviderPolicy(
        only=("approved-provider",),
        certification=True,
    )

    with pytest.raises(
        OpenRouterCostControlError,
        match="input-cache-read endpoint price exceeds its provider-capped prompt price",
    ):
        _preview(
            config=config,
            manifest=manifest,
            evidence=evidence,
            policy=policy,
            reasoning_policy=_disabled_reasoning_policy(),
        )
