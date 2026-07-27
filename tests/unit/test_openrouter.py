from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.discovery import (
    _TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    _issue_real_openrouter_discovery_run,
    openrouter_endpoint_query,
    validate_openrouter_model_discovery,
    write_model_discovery_run,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    OpenRouterEndpointSnapshotEvidence,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.openrouter import (
    OpenRouterAuthenticationError,
    OpenRouterClient,
    OpenRouterCostControlError,
    OpenRouterModelError,
    OpenRouterPrivacyError,
    OpenRouterProviderPolicy,
    OpenRouterProviderPolicyError,
    OpenRouterReasoning,
    OpenRouterRequestLimitError,
    OpenRouterSchemaError,
    OpenRouterTransientError,
    OpenRouterTruncatedResponseError,
    is_retryable_status,
    safe_headers,
    strict_json_schema,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetExhaustedError, BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str


class OptionalAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str
    note: str | None = None


def _completion(
    content: str,
    *,
    cost: float | None = 0.01,
    model: str = "alpha/atlas-secure",
    selected_model: str | None = None,
    provider: str = "synthetic-provider",
) -> dict[str, Any]:
    routed_model = selected_model or model
    usage: dict[str, Any] = {
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "total_tokens": 15,
    }
    if cost is not None:
        usage["cost"] = cost
    return {
        "id": "generation-test",
        "model": model,
        "provider": provider,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "native_finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": usage,
        "openrouter_metadata": {
            "requested": model,
            "strategy": "direct",
            "attempt": 1,
            "endpoints": {
                "total": 1,
                "available": [
                    {
                        "provider": provider,
                        "model": routed_model,
                        "selected": True,
                    }
                ],
            },
            "attempts": [
                {
                    "provider": provider,
                    "model": routed_model,
                    "status": 200,
                }
            ],
            "pipeline": [],
        },
    }


def _completion_response(
    content: str,
    *,
    cost: float | None = 0.01,
    model: str = "alpha/atlas-secure",
    selected_model: str | None = None,
    provider: str = "synthetic-provider",
) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"X-Generation-Id": "generation-test"},
        json=_completion(
            content,
            cost=cost,
            model=model,
            selected_model=selected_model,
            provider=provider,
        ),
    )


def _endpoint_snapshot(
    *,
    model: str = "alpha/atlas-secure",
    provider: str = "approved-provider",
    provider_name: str = "Approved Provider",
    pricing: dict[str, str] | None = None,
) -> OpenRouterEndpointSnapshotEvidence:
    endpoint = {
        "tag": provider,
        "provider_name": provider_name,
        "status": 0,
        "context_length": 200_000,
        "max_prompt_tokens": 180_000,
        "max_completion_tokens": 20_000,
        "supported_parameters": ["max_tokens", "response_format", "temperature"],
        "pricing": pricing
        or {
            "prompt": "0.000001",
            "completion": "0.00001",
            "request": "0",
        },
    }
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(provider,),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model}]},
    )


def _model_discovery_run(
    tmp_path: Path,
    *,
    canonical_model: str = "alpha/atlas-secure-20260727",
) -> tuple[OpenRouterModelDiscoveryRunManifest, OpenRouterModelDiscoveryEvidence]:
    exact_model = "alpha/atlas-secure"
    endpoint_snapshot = _endpoint_snapshot()
    catalog = {
        "data": [
            {
                "id": exact_model,
                "canonical_slug": canonical_model,
                "context_length": 200_000,
                "top_provider": {
                    "context_length": 200_000,
                    "max_completion_tokens": 20_000,
                },
                "supported_parameters": [
                    "max_tokens",
                    "response_format",
                    "temperature",
                ],
            }
        ]
    }
    payload = validate_openrouter_model_discovery(
        exact_model_id=exact_model,
        models_payload=catalog,
        endpoint_snapshot=endpoint_snapshot,
    )
    route = DiscoveryCandidateRoute(
        exact_model_id=exact_model,
        approved_provider_endpoint="approved-provider",
    )
    _provenance, evidence = _issue_real_openrouter_discovery_run(
        run_id="1" * 32,
        retrieved_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
        client_fingerprint_sha256="a" * 64,
        provider_fingerprint_sha256="b" * 64,
        catalog_snapshot_sha256=hashlib.sha256(
            json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        zdr_snapshot_sha256="d" * 64,
        candidate_routes=(route,),
        endpoint_metadata_bindings=(
            DiscoveryEndpointMetadataBinding(
                exact_model_id=exact_model,
                api_query=openrouter_endpoint_query(exact_model),
                response_snapshot_sha256="e" * 64,
            ),
        ),
        payloads=(payload,),
        issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    )
    manifest = write_model_discovery_run(tmp_path / canonical_model.rsplit("/", 1)[-1], evidence)
    return manifest, evidence[0]


def _multi_endpoint_snapshot(
    *,
    shared_provider_name: bool = False,
) -> OpenRouterEndpointSnapshotEvidence:
    endpoints = [
        {
            "tag": "provider-economy",
            "provider_name": "Provider Economy",
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000001",
                "completion": "0.00001",
                "request": "0",
            },
        },
        {
            "tag": "provider-premium",
            "provider_name": ("Provider Economy" if shared_provider_name else "Provider Premium"),
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000004",
                "completion": "0.00004",
                "request": "0.002",
            },
        },
    ]
    return validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("provider-economy", "provider-premium"),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": endpoints,
            }
        },
        require_zdr=True,
        zdr_payload={
            "data": [
                {
                    **endpoint,
                    "model_id": "alpha/atlas-secure",
                }
                for endpoint in endpoints
            ]
        },
    )


def _client(
    config,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    api_key: str = "synthetic-key",
    run_dir: Path | None = None,
    provider_policy: OpenRouterProviderPolicy | None = None,
    reasoning: OpenRouterReasoning | None = None,
) -> tuple[OpenRouterClient, httpx.AsyncClient, UsageLedger]:
    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(
        transport=transport,
        base_url="https://fake.test/api/v1/",
    )
    usage = UsageLedger()
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
    )
    client = OpenRouterClient(
        api_key=api_key,
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        http_client=http_client,
        run_dir=run_dir,
        provider_policy=provider_policy,
        reasoning=reasoning,
    )
    return client, http_client, usage


async def _paid_control_client_with_mock_transport(
    config,
    *,
    budget: BudgetManager,
    handler: Callable[[httpx.Request], httpx.Response],
    provider_policy: OpenRouterProviderPolicy,
) -> tuple[OpenRouterClient, UsageLedger, httpx.AsyncClient]:
    usage = UsageLedger()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        http_client=http_client,
        provider_policy=provider_policy,
    )
    assert client.execution_evidence is ExecutionEvidenceKind.MOCK
    return client, usage, http_client


def _owned_client(config, *, base_url: str) -> OpenRouterClient:
    return OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=BudgetManager(
            total_usd=config.execution.budget_usd,
            max_output_tokens=config.execution.max_output_tokens_per_request,
            conservative_usd_per_million_tokens=(
                config.execution.conservative_usd_per_million_tokens
            ),
            max_requests_per_agent=config.execution.max_requests_per_agent,
        ),
        usage=UsageLedger(),
        base_url=base_url,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        OPENROUTER_DEFAULT_BASE_URL,
        f"{OPENROUTER_DEFAULT_BASE_URL}/",
        f"{OPENROUTER_DEFAULT_BASE_URL}///",
    ],
)
async def test_owned_official_transport_is_real_after_trailing_slash_normalization(
    config_factory,
    base_url: str,
) -> None:
    client = _owned_client(config_factory(), base_url=base_url)
    try:
        assert client.execution_evidence is ExecutionEvidenceKind.REAL
        assert str(client._client.base_url) == f"{OPENROUTER_DEFAULT_BASE_URL}/"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_injected_network_transport_is_unverified_and_cannot_send(
    config_factory,
) -> None:
    http_client = httpx.AsyncClient(base_url=f"{OPENROUTER_DEFAULT_BASE_URL}/")
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config_factory().execution,
        privacy=config_factory().privacy,
        budget=BudgetManager(
            total_usd=20,
            max_output_tokens=2_048,
            conservative_usd_per_million_tokens=10,
            max_requests_per_agent=2,
        ),
        usage=UsageLedger(),
        http_client=http_client,
    )
    try:
        assert client.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        with pytest.raises(OpenRouterPrivacyError, match="injected provider clients"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        client.clear_credentials()
        await http_client.aclose()


@pytest.mark.asyncio
async def test_injected_network_transport_cannot_redirect_operator_credentials(
    config_factory,
) -> None:
    http_client = httpx.AsyncClient(base_url="https://unapproved.invalid/api/v1/")
    try:
        with pytest.raises(OpenRouterPrivacyError, match="canonical OpenRouter"):
            OpenRouterClient(
                api_key="synthetic-key",
                execution=config_factory().execution,
                privacy=config_factory().privacy,
                budget=BudgetManager(
                    total_usd=20,
                    max_output_tokens=2_048,
                    conservative_usd_per_million_tokens=10,
                    max_requests_per_agent=2,
                ),
                usage=UsageLedger(),
                http_client=http_client,
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_owned_transport_replacement_cannot_fabricate_real_execution(
    config_factory,
) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)
    replacement = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={"data": {}})),
        base_url=f"{OPENROUTER_DEFAULT_BASE_URL}/",
    )
    client._client = replacement
    try:
        with pytest.raises(OpenRouterPrivacyError, match="transport provenance changed"):
            await client.validate_authentication()
    finally:
        await client.close()
        await replacement.aclose()


@pytest.mark.asyncio
async def test_owned_client_send_mutation_cannot_fabricate_real_execution(
    config_factory,
) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)

    async def fabricated_send(*_args: Any, **_kwargs: Any) -> httpx.Response:
        return httpx.Response(200, json={"data": {}})

    client._client.send = fabricated_send  # type: ignore[method-assign]
    try:
        with pytest.raises(OpenRouterPrivacyError, match="callable provenance"):
            await client.validate_authentication()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_owned_transport_request_mutation_cannot_fabricate_real_execution(
    config_factory,
) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)
    transport = client._client._transport

    async def fabricated_request(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {}})

    transport.handle_async_request = fabricated_request  # type: ignore[method-assign]
    try:
        with pytest.raises(OpenRouterPrivacyError, match="callable provenance"):
            await client.validate_authentication()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_mock_transport_exception_is_secretless(
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-transport-exception-canary"

    def handler(_request: httpx.Request) -> httpx.Response:
        raise RuntimeError(f"untrusted transport detail {canary}")

    client, http_client, _usage = _client(
        config_factory(),
        handler,
        api_key=canary,
    )
    try:
        with pytest.raises(OpenRouterSchemaError, match="transport failed safely") as captured:
            await client.validate_authentication()
    finally:
        await http_client.aclose()

    assert canary not in str(captured.value)
    assert canary not in repr(captured.value.__context__)


@pytest.mark.asyncio
async def test_real_completion_requires_durable_atomic_cost_ledger(config_factory) -> None:
    client = _owned_client(config_factory(), base_url=OPENROUTER_DEFAULT_BASE_URL)
    try:
        with pytest.raises(OpenRouterCostControlError, match="durable atomic cost ledger"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_certification_requires_validated_endpoint_pricing_before_send(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"bounded"}',
            provider="approved-provider",
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "cost-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=UsageLedger(),
        http_client=http_client,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterCostControlError, match="validated endpoint pricing"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
        client.register_certification_endpoint_snapshot(
            evidence=_endpoint_snapshot(),
        )
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "bounded"
    assert calls == 1
    assert ledger.snapshot().active_reserved_usd == 0
    assert ledger.snapshot().spent_usd == Decimal("0.01")


@pytest.mark.asyncio
async def test_certification_endpoint_pricing_registration_is_exact(config_factory) -> None:
    config = config_factory(execution={"max_json_repair_attempts": 0})
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterProviderPolicyError, match="exact configured"):
            client.register_certification_endpoint_snapshot(
                evidence=_endpoint_snapshot(provider="other-provider"),
            )
        with pytest.raises(OpenRouterCostControlError, match="unsupported"):
            client.register_certification_endpoint_snapshot(
                evidence=_endpoint_snapshot(
                    pricing={
                        "prompt": "0.1",
                        "completion": "0.2",
                        "unknown_fee": "1",
                    }
                ),
            )
        with pytest.raises(OpenRouterCostControlError, match="cannot be provider-capped"):
            client.register_certification_endpoint_snapshot(
                evidence=_endpoint_snapshot(
                    pricing={
                        "prompt": "0.1",
                        "completion": "0.2",
                        "internal_reasoning": "0",
                    }
                ),
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_provider_cost_is_parsed_exactly_before_decimal_ledger_reconciliation(
    config_factory,
    tmp_path: Path,
) -> None:
    exact_cost = Decimal("0.100000000000000004")

    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"exact-cost"}',
            cost=0,
            provider="approved-provider",
        )
        serialized = json.dumps(payload, sort_keys=True).replace(
            '"cost": 0',
            f'"cost": {exact_cost}',
            1,
        )
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            content=serialized.encode(),
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    ledger = AtomicCostLedger.initialize(
        tmp_path / "exact-provider-cost-ledger.json",
        cap_usd=Decimal("20"),
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        client.register_certification_endpoint_snapshot(
            evidence=_endpoint_snapshot(
                pricing={
                    "prompt": "0.000001",
                    "completion": "0.001",
                    "request": "0",
                }
            )
        )
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert result.answer == "exact-cost"
    assert ledger.snapshot().spent_usd == exact_cost
    assert usage.records[0].reported_cost_usd == float(exact_cost)


@pytest.mark.asyncio
async def test_endpoint_registration_rejects_ambiguous_provider_display_names(
    config_factory,
) -> None:
    client, http_client, _usage = _client(
        config_factory(),
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            only=("provider-economy", "provider-premium"),
        ),
    )
    try:
        with pytest.raises(EndpointSnapshotValidationError, match="display name is ambiguous"):
            client.register_endpoint_snapshot(
                evidence=_multi_endpoint_snapshot(shared_provider_name=True)
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_provider_price_ceiling_never_rounds_below_validated_snapshot(
    config_factory,
) -> None:
    prompt_price = Decimal("0.000000100000000000000000000000000001")
    completion_price = Decimal("0.000000200000000000000000000000000001")
    config = config_factory(execution={"max_json_repair_attempts": 0})
    client, http_client, _usage = _client(
        config,
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        client.register_certification_endpoint_snapshot(
            evidence=_endpoint_snapshot(
                pricing={
                    "prompt": format(prompt_price, "f"),
                    "completion": format(completion_price, "f"),
                }
            )
        )
        request = client.build_request(
            model="alpha/atlas-secure",
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    max_price = request["provider"]["max_price"]
    assert Decimal(str(max_price["prompt"])) >= prompt_price * 1_000_000
    assert Decimal(str(max_price["completion"])) >= completion_price * 1_000_000


@pytest.mark.asyncio
async def test_real_noncertification_completion_requires_endpoint_bound_budget_before_transport(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"must not execute"}',
            cost=0.000001,
            provider="approved-provider",
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "noncertification-cost-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=False,
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterCostControlError, match="endpoint-bound"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_real_completion_requires_registered_endpoint_snapshot_before_transport(
    config_factory,
    tmp_path: Path,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response(
            '{"answer":"must not execute"}',
            provider="approved-provider",
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "missing-snapshot-cost-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterCostControlError, match="validated endpoint pricing"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0
    assert usage.records == []
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_multi_endpoint_snapshot_reserves_worst_case_advertised_price(
    config_factory,
    tmp_path: Path,
) -> None:
    observed_reservations: list[float] = []
    observed_request_material: list[str] = []
    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "multi-endpoint-cost-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        observed_reservations.append(budget.reserved_usd)
        body = json.loads(request.content)
        observed_request_material.append(
            json.dumps(
                body,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        )
        return _completion_response(
            '{"answer":"bounded"}',
            cost=0.000001,
            provider="provider-economy",
        )

    client, _usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=handler,
        provider_policy=OpenRouterProviderPolicy(
            only=("provider-economy", "provider-premium"),
        ),
    )
    snapshot = _multi_endpoint_snapshot()
    try:
        client.register_endpoint_snapshot(evidence=snapshot)
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    premium = snapshot.endpoint("provider-premium")
    assert result.answer == "bounded"
    assert len(observed_reservations) == len(observed_request_material) == 1
    provider = json.loads(observed_request_material[0])["provider"]
    assert provider["max_price"] == {
        "completion": float(Decimal(premium.pricing["completion"]) * 1_000_000),
        "prompt": float(Decimal(premium.pricing["prompt"]) * 1_000_000),
        "request": float(Decimal(premium.pricing["request"])),
    }
    expected_worst_case = (
        Decimal(premium.pricing["prompt"]) * len(observed_request_material[0].encode("utf-8"))
        + Decimal(premium.pricing["completion"]) * config.execution.max_output_tokens_per_request
        + Decimal(premium.pricing["request"])
    )
    assert observed_reservations[0] == pytest.approx(float(expected_worst_case))


@pytest.mark.asyncio
async def test_multi_endpoint_routing_evidence_binds_actual_endpoint_and_full_snapshot(
    config_factory,
    tmp_path: Path,
) -> None:
    config = config_factory(execution={"max_json_repair_attempts": 0})
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=10,
        max_requests_per_agent=2,
        atomic_ledger=AtomicCostLedger.initialize(
            tmp_path / "multi-endpoint-evidence-ledger.json",
            cap_usd=Decimal("20"),
        ),
        require_endpoint_cost_bound=True,
    )
    client, usage, http_client = await _paid_control_client_with_mock_transport(
        config,
        budget=budget,
        handler=lambda _request: _completion_response(
            '{"answer":"premium"}',
            cost=0.000001,
            provider="provider-premium",
        ),
        provider_policy=OpenRouterProviderPolicy(
            only=("provider-economy", "provider-premium"),
        ),
    )
    snapshot = _multi_endpoint_snapshot()
    try:
        client.register_endpoint_snapshot(evidence=snapshot)
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await client.close()
        await http_client.aclose()

    record = usage.records[0]
    assert result.answer == "premium"
    assert record.actual_provider_endpoint == "provider-premium"
    assert record.configured_provider_endpoints == [
        "provider-economy",
        "provider-premium",
    ]
    assert record.routing["selected_provider_endpoint"] == "provider-premium"
    assert record.routing["configured_provider_only"] == [
        "provider-economy",
        "provider-premium",
    ]
    assert record.routing["endpoint_snapshot_sha256"] == snapshot.snapshot_sha256
    assert (
        record.routing["endpoint_pricing_sha256"]
        == snapshot.endpoint("provider-premium").pricing_sha256
    )


@pytest.mark.asyncio
async def test_frozen_discovery_authorizes_and_records_exact_canonical_route(
    config_factory,
    tmp_path: Path,
) -> None:
    canonical_model = "alpha/atlas-secure-20260727"
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"canonical"}',
            selected_model=canonical_model,
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        client.register_certification_model_discovery(
            evidence=evidence,
            manifest=manifest,
        )
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="synthetic local input",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    record = usage.records[0]
    assert result.answer == "canonical"
    assert record.returned_model == "alpha/atlas-secure"
    assert record.actual_model == canonical_model
    assert record.routing["selected_model"] == canonical_model
    assert (
        record.routing["catalog_identity_binding_sha256"]
        == evidence.catalog_identity_binding_sha256
    )
    assert record.routing["discovery_evidence_sha256"] == evidence.discovery_evidence_sha256


@pytest.mark.parametrize("fault", ["unbound", "wrong_canonical", "attempt_mismatch"])
@pytest.mark.asyncio
async def test_canonical_route_must_match_one_frozen_identity(
    config_factory,
    tmp_path: Path,
    fault: str,
) -> None:
    canonical_model = "alpha/atlas-secure-20260727"
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        selected_model = (
            "alpha/atlas-secure-20260728" if fault == "wrong_canonical" else canonical_model
        )
        payload = _completion(
            '{"answer":"must reject"}',
            selected_model=selected_model,
            provider="Approved Provider",
        )
        if fault == "attempt_mismatch":
            payload["openrouter_metadata"]["attempts"][0]["model"] = "alpha/atlas-secure"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        if fault != "unbound":
            client.register_certification_model_discovery(
                evidence=evidence,
                manifest=manifest,
            )
        with pytest.raises((OpenRouterModelError, OpenRouterSchemaError)):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert usage.records[0].status != "success"


@pytest.mark.asyncio
async def test_top_level_returned_model_cannot_use_the_canonical_alias(
    config_factory,
    tmp_path: Path,
) -> None:
    canonical_model = "alpha/atlas-secure-20260727"
    manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model=canonical_model,
    )
    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response(
            '{"answer":"must reject"}',
            model=canonical_model,
            provider="Approved Provider",
        ),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        client.register_certification_model_discovery(
            evidence=evidence,
            manifest=manifest,
        )
        with pytest.raises(OpenRouterModelError, match="exact configured model"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="synthetic local input",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert usage.records[0].status != "success"


@pytest.mark.asyncio
async def test_model_identity_registration_rejects_a_spliced_manifest(
    config_factory,
    tmp_path: Path,
) -> None:
    _first_manifest, evidence = _model_discovery_run(
        tmp_path,
        canonical_model="alpha/atlas-secure-20260727",
    )
    other_manifest, _other_evidence = _model_discovery_run(
        tmp_path,
        canonical_model="alpha/atlas-secure-20260728",
    )
    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        lambda _request: _completion_response('{"answer":"unused"}'),
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterModelError, match="different run provenance"):
            client.register_certification_model_discovery(
                evidence=evidence,
                manifest=other_manifest,
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_owned_alternate_endpoint_is_rejected_before_transport(config_factory) -> None:
    with pytest.raises(OpenRouterPrivacyError, match="canonical OpenRouter"):
        _owned_client(
            config_factory(),
            base_url="https://operator-proxy.invalid/api/v1",
        )


@pytest.mark.asyncio
async def test_structured_request_and_usage(config_factory) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _completion_response('{"answer":"ok"}')

    config = config_factory()
    client, http_client, usage = _client(config, handler)
    assert client.execution_evidence is ExecutionEvidenceKind.MOCK
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    assert result.answer == "ok"
    body = json.loads(observed[0].content)
    assert "synthetic-key" not in json.dumps(body)
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["provider"] == {
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "zdr": True,
    }
    assert observed[0].headers["Authorization"] == "Bearer synthetic-key"
    assert observed[0].headers["X-OpenRouter-Metadata"] == "enabled"
    assert observed[0].headers["X-OpenRouter-Title"] == "mmaudit"
    assert body["metadata"]["mmaudit_role"] == "source_audit"
    assert len(body["metadata"]["mmaudit_prompt_sha256"]) == 64
    assert len(body["metadata"]["mmaudit_schema_sha256"]) == 64
    assert usage.records[0].reported_cost_usd == 0.01
    assert usage.records[0].returned_model == "alpha/atlas-secure"
    assert usage.records[0].execution_evidence is ExecutionEvidenceKind.MOCK
    assert usage.records[0].openrouter_generation_id == "generation-test"
    assert usage.records[0].actual_provider_endpoint == "synthetic-provider"
    assert usage.records[0].finish_reason == "stop"
    assert usage.records[0].validation_status.value == "valid"
    assert usage.records[0].schema_sha256 == body["metadata"]["mmaudit_schema_sha256"]
    assert (
        usage.records[0].validated_response_sha256 == hashlib.sha256(b'{"answer":"ok"}').hexdigest()
    )


@pytest.mark.asyncio
async def test_router_metadata_supplies_provider_when_success_envelope_omits_extension(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"ok"}')
        payload.pop("provider")
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "ok"
    assert usage.records[0].provider == "synthetic-provider"
    assert usage.records[0].actual_provider_endpoint == "synthetic-provider"


@pytest.mark.asyncio
async def test_body_generation_id_is_sufficient_when_optional_header_is_absent(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_completion('{"answer":"body-bound"}'),
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "body-bound"
    assert usage.records[0].openrouter_generation_id == "generation-test"


def test_safe_headers_redacts_every_authorization_header() -> None:
    assert safe_headers(
        {
            "Authorization": "Bearer synthetic-canary",
            "Proxy-Authorization": "Bearer proxy-canary",
            "X-API-Key": "synthetic-api-key",
            "Content-Type": "application/json",
        }
    ) == {
        "Authorization": "[REDACTED]",
        "Proxy-Authorization": "[REDACTED]",
        "X-API-Key": "[REDACTED]",
        "Content-Type": "application/json",
    }


@pytest.mark.parametrize(
    ("status", "expected"),
    [(408, True), (429, True), (500, True), (503, True), (400, False), (401, False)],
)
def test_retry_decisions(status: int, expected: bool) -> None:
    assert is_retryable_status(status) is expected


def test_strict_schema_marks_every_property_required() -> None:
    schema = strict_json_schema(OptionalAnswer)
    assert schema["required"] == ["answer", "note"]
    assert "default" not in schema["properties"]["note"]
    assert schema["additionalProperties"] is False


@pytest.mark.asyncio
async def test_local_validation_rejects_omitted_defaulted_field(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _completion_response('{"answer":"ok"}')

    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
    )
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid structured"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=OptionalAnswer,
                schema_name="optional_answer",
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_rate_limit_retries_once(config_factory, monkeypatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "0"},
                json={
                    "error": {"code": 429, "message": "synthetic retry"},
                    "usage": {
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                        "cost": 0,
                    },
                },
            )
        return _completion_response('{"answer":"after retry"}')

    config = config_factory(execution={"max_model_retries": 1})
    client, http_client, usage = _client(config, handler)

    async def no_wait(attempt: int, retry_after: str | None) -> None:
        del attempt, retry_after

    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    assert result.answer == "after retry"
    assert calls == 2
    assert usage.records[0].attempts == 2
    assert usage.records[0].accounted_cost_usd > usage.records[0].reported_cost_usd
    assert usage.records[0].accounted_cost_usd == pytest.approx(client.budget.spent_usd)


@pytest.mark.asyncio
async def test_concurrent_usage_records_account_only_their_own_request_cost(
    config_factory,
) -> None:
    arrived = 0
    both_arrived = asyncio.Event()

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal arrived
        arrived += 1
        if arrived == 2:
            both_arrived.set()
        await both_arrived.wait()
        return _completion_response('{"answer":"concurrent"}', cost=0.01)

    config = config_factory()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    usage = UsageLedger()
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
    )
    client = OpenRouterClient(
        api_key="synthetic-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        http_client=http_client,
    )
    try:
        await asyncio.gather(
            client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="first",
                response_model=Answer,
                schema_name="answer",
            ),
            client.complete(
                role="business_logic",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="second",
                response_model=Answer,
                schema_name="answer",
            ),
        )
    finally:
        await http_client.aclose()

    assert arrived == 2
    assert [record.accounted_cost_usd for record in usage.records] == [0.01, 0.01]
    assert usage.accounted_cost_usd == pytest.approx(0.02)
    assert budget.spent_usd == pytest.approx(0.02)


@pytest.mark.asyncio
async def test_authentication_failure_is_not_retried(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"error": {"message": "no"}})

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterAuthenticationError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1


@pytest.mark.asyncio
async def test_malformed_structured_output_is_not_repaired(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response("not json")

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid structured"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1
    assert usage.records[0].status == "failed:OpenRouterSchemaError"
    assert usage.records[0].validation_status.value == "invalid_response"


@pytest.mark.asyncio
async def test_invalid_repair_is_not_repeated(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response("still not json")

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1


@pytest.mark.asyncio
async def test_hard_budget_refuses_before_network(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"unexpected"}')

    config = config_factory(
        execution={
            "budget_usd": 0.000001,
            "conservative_usd_per_million_tokens": 1_000,
        }
    )
    client, http_client, _usage = _client(config, handler)
    try:
        with pytest.raises(BudgetExhaustedError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="large enough",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 0


@pytest.mark.asyncio
async def test_serialized_request_limit_refuses_before_network_or_fallback(
    config_factory,
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"unexpected"}')

    client, http_client, _usage = _client(
        config_factory(execution={"max_request_bytes": 1_024}),
        handler,
    )
    try:
        with pytest.raises(OpenRouterRequestLimitError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure", "bravo/borealis-secure"],
                system_prompt="system",
                user_prompt="x" * 2_000,
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 0


@pytest.mark.asyncio
async def test_models_metadata_shape(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/models")
        return httpx.Response(
            200,
            json={
                "data": [{"id": "alpha/atlas-secure", "supported_parameters": ["response_format"]}]
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        models = await client.list_models()
    finally:
        await http_client.aclose()
    assert models[0]["id"] == "alpha/atlas-secure"


@pytest.mark.asyncio
async def test_certification_catalog_uses_fixed_zdr_structured_output_filters(
    config_factory,
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json={"data": [{"id": "alpha/atlas-secure"}]})

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        assert await client.list_certification_models() == [{"id": "alpha/atlas-secure"}]
    finally:
        await http_client.aclose()

    assert observed[0].url.path == "/api/v1/models"
    assert dict(observed[0].url.params) == {
        "zdr": "true",
        "supported_parameters": "response_format",
    }


@pytest.mark.asyncio
async def test_authentication_validation_uses_key_endpoint(config_factory) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json={"data": {"label": "synthetic"}})

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        await client.validate_authentication()
    finally:
        await http_client.aclose()

    assert observed[0].url.path == "/api/v1/key"


@pytest.mark.asyncio
async def test_decoded_metadata_does_not_retain_compression_headers(config_factory) -> None:
    encoded = gzip.compress(b'{"data":{"label":"synthetic"}}')

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=encoded,
            headers={"Content-Encoding": "gzip"},
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        await client.validate_authentication()
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_authentication_validation_rejects_invalid_key(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid"})

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterAuthenticationError):
            await client.validate_authentication()
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_clear_credentials_does_not_mutate_caller_owned_authorization(
    config_factory,
) -> None:
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
        base_url="https://fake.test",
        headers={"Authorization": "Bearer caller-owned"},
    )
    budget = BudgetManager(
        total_usd=20,
        max_output_tokens=1_000,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
    )
    client = OpenRouterClient(
        api_key="synthetic-mmaudit-key",
        execution=config_factory().execution,
        privacy=config_factory().privacy,
        budget=budget,
        usage=UsageLedger(),
        http_client=http_client,
    )

    client.clear_credentials()

    assert http_client.headers["Authorization"] == "Bearer caller-owned"
    assert client._headers == {}
    assert client._credential == bytearray()
    await http_client.aclose()


@pytest.mark.asyncio
async def test_request_response_and_timeout_diagnostics_do_not_retain_key(
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-timeout-canary"

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    client, http_client, usage = _client(
        config_factory(execution={"max_model_retries": 0}),
        handler,
        api_key=canary,
    )
    try:
        with pytest.raises(OpenRouterTransientError) as captured:
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    rendered = "".join(traceback.format_exception(captured.value))
    chained = captured.value.__context__
    assert canary not in rendered
    assert canary not in repr(chained)
    serialized_usage = json.dumps(
        [record.model_dump(mode="json") for record in usage.records],
        sort_keys=True,
        default=str,
    )
    assert canary not in serialized_usage


@pytest.mark.asyncio
async def test_key_in_prompt_or_response_is_rejected_without_debug_artifacts(
    config_factory,
    tmp_path: Path,
) -> None:
    canary = "sk-or-v1-synthetic-payload-canary"
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={
                "Authorization": canary,
                "X-Generation-Id": "generation-test",
            },
            json=_completion(json.dumps({"answer": canary})),
        )

    config = config_factory(
        execution={"max_model_retries": 0},
        privacy={"store_raw_responses": True},
    )
    client, http_client, _usage = _client(
        config,
        handler,
        api_key=canary,
        run_dir=tmp_path,
    )
    try:
        with pytest.raises(OpenRouterPrivacyError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
        with pytest.raises(OpenRouterPrivacyError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt=f"accidental value: {canary}",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert calls == 1
    assert not (tmp_path / "debug").exists()


@pytest.mark.asyncio
async def test_key_in_provider_mapping_key_is_rejected_before_debug_storage(
    config_factory,
    tmp_path: Path,
) -> None:
    canary = "sk-or-v1-synthetic-mapping-key-canary"

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"safe"}')
        payload[canary] = "provider-controlled-key"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    config = config_factory(
        execution={"max_model_retries": 0},
        privacy={"store_raw_responses": True},
    )
    client, http_client, _usage = _client(
        config,
        handler,
        api_key=canary,
        run_dir=tmp_path,
    )
    try:
        with pytest.raises(OpenRouterPrivacyError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert not (tmp_path / "debug").exists()


@pytest.mark.asyncio
async def test_malformed_echoed_response_has_secretless_exception(
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-malformed-canary"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {canary}"
        return httpx.Response(
            200,
            content=f"not-json:{canary}".encode(),
            headers={"Authorization": canary},
        )

    client, http_client, _usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        api_key=canary,
    )
    try:
        with pytest.raises(OpenRouterSchemaError) as captured:
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    rendered = "".join(traceback.format_exception(captured.value))
    assert canary not in rendered
    assert canary not in repr(captured.value.__context__)


@pytest.mark.asyncio
async def test_models_metadata_respects_rate_limit_retry(config_factory, monkeypatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"data": [{"id": "alpha/atlas-secure"}]})

    client, http_client, _usage = _client(
        config_factory(execution={"max_model_retries": 1}),
        handler,
    )

    async def no_wait(attempt: int, retry_after: str | None) -> None:
        del attempt, retry_after

    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        assert await client.list_models() == [{"id": "alpha/atlas-secure"}]
    finally:
        await http_client.aclose()
    assert calls == 2


@pytest.mark.asyncio
async def test_unrelated_returned_model_is_rejected_and_recorded(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"wrong model"}',
            model="unrelated/vendor-model",
        )
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterModelError, match="unrelated model"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status == "rejected_model_substitution"
    assert usage.records[0].returned_model == "unrelated/vendor-model"


@pytest.mark.asyncio
async def test_only_explicit_fallback_is_used(config_factory) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requested.append(body["model"])
        if body["model"] == "alpha/atlas-secure":
            return httpx.Response(404)
        return _completion_response('{"answer":"fallback"}', model=body["model"])

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure", "bravo/borealis-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    assert result.answer == "fallback"
    assert requested == ["alpha/atlas-secure", "bravo/borealis-secure"]


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/auto",
        "openrouter/random",
        "vendor/model-auto-router",
        "vendor/model:latest",
        "vendor/latest",
        "missing-provider",
    ],
)
@pytest.mark.asyncio
async def test_non_exact_model_identifiers_are_rejected_before_network(
    config_factory,
    model: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response('{"answer":"unexpected"}')

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterModelError, match="exact author/model"):
            await client.complete(
                role="source_audit",
                models=[model],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 0


@pytest.mark.asyncio
async def test_certification_request_pins_provider_reasoning_and_single_model(
    config_factory,
) -> None:
    observed: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        observed.append(body)
        return _completion_response(
            '{"answer":"ok"}',
            provider="approved-provider",
        )

    config = config_factory(execution={"max_json_repair_attempts": 0})
    policy = OpenRouterProviderPolicy(
        certification=True,
        only=("approved-provider",),
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=policy,
        reasoning=OpenRouterReasoning(effort="high"),
    )
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
        with pytest.raises(OpenRouterModelError, match="exactly one"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure", "bravo/borealis-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert result.answer == "ok"
    assert observed[0]["provider"] == {
        "allow_fallbacks": False,
        "require_parameters": True,
        "data_collection": "deny",
        "zdr": True,
        "only": ["approved-provider"],
    }
    assert observed[0]["reasoning"] == {"exclude": False, "effort": "high"}
    assert usage.records[0].configured_provider_endpoints == ["approved-provider"]


def test_certification_requires_provider_pin_zdr_and_no_repair(config_factory) -> None:
    with pytest.raises(ValueError, match="endpoint allowlist"):
        OpenRouterProviderPolicy(certification=True)
    with pytest.raises(ValueError, match="exactly one provider endpoint"):
        OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider", "second-provider"),
        )
    with pytest.raises(OpenRouterPrivacyError, match="zero-data-retention"):
        _client(
            config_factory(
                execution={"max_json_repair_attempts": 0},
                privacy={"require_zdr": False},
            ),
            lambda _request: _completion_response('{"answer":"unexpected"}'),
            provider_policy=OpenRouterProviderPolicy(
                certification=True,
                only=("approved-provider",),
            ),
        )
    with pytest.raises(OpenRouterSchemaError, match="repair is disabled"):
        _client(
            config_factory(execution={"max_json_repair_attempts": 1}),
            lambda _request: _completion_response('{"answer":"unexpected"}'),
            provider_policy=OpenRouterProviderPolicy(
                certification=True,
                only=("approved-provider",),
            ),
        )


@pytest.mark.asyncio
async def test_same_family_model_alias_is_rejected_and_evidence_is_invalid(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response(
            '{"answer":"wrong"}',
            model="alpha/atlas-secure:variant",
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterModelError, match="exact configured model"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status == "rejected_model_substitution"
    assert usage.records[0].substitution_detected
    assert usage.records[0].validation_status.value == "model_mismatch"


@pytest.mark.asyncio
async def test_truncated_response_is_rejected_and_not_repaired(config_factory) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _completion('{"answer":"partial"}')
        payload["choices"][0]["finish_reason"] = "length"
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterTruncatedResponseError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1
    assert usage.records[0].status == "rejected_truncated_response"
    assert usage.records[0].validation_status.value == "truncated"


@pytest.mark.asyncio
async def test_router_selected_provider_must_match_certification_policy(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response(
            '{"answer":"wrong provider"}',
            provider="unapproved-provider",
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("approved-provider",),
        ),
    )
    try:
        with pytest.raises(OpenRouterProviderPolicyError, match="outside"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].validation_status.value == "provider_mismatch"


@pytest.mark.asyncio
async def test_optional_router_attempts_require_snapshot_bound_provider_display_name(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"bound"}',
            provider="Google Vertex",
        )
        payload["openrouter_metadata"].pop("attempts")
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(
        config_factory(execution={"max_json_repair_attempts": 0}),
        handler,
        provider_policy=OpenRouterProviderPolicy(
            certification=True,
            only=("google-vertex",),
        ),
    )
    client.register_certification_endpoint_snapshot(
        evidence=_endpoint_snapshot(
            provider="google-vertex",
            provider_name="Google Vertex",
        )
    )
    try:
        result = await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()

    assert result.answer == "bound"
    record = usage.records[0]
    assert record.provider == "Google Vertex"
    assert record.actual_provider_endpoint == "google-vertex"
    assert record.routing["selected_provider_name"] == "Google Vertex"
    assert record.routing["router_attempt_count"] == 1
    assert record.routing["router_attempts_observed"] is False


@pytest.mark.asyncio
async def test_optional_router_attempts_without_exact_endpoint_binding_fail_closed(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"unbound"}')
        payload["openrouter_metadata"].pop("attempts")
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError, match="exact endpoint binding"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    assert usage.records[0].status != "success"


@pytest.mark.asyncio
async def test_model_endpoint_metadata_uses_exact_documented_path(config_factory) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "alpha/atlas-secure",
                    "endpoints": [{"name": "approved-provider"}],
                }
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        endpoints = await client.list_model_endpoints("alpha/atlas-secure")
    finally:
        await http_client.aclose()
    assert endpoints == [{"name": "approved-provider"}]
    assert observed[0].url.path == "/api/v1/models/alpha/atlas-secure/endpoints"


@pytest.mark.asyncio
async def test_model_endpoint_metadata_rejects_wrong_model_binding(config_factory) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "bravo/borealis-secure",
                    "endpoints": [{"name": "approved-provider"}],
                }
            },
        )

    client, http_client, _usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterModelError, match="exact requested model"):
            await client.list_model_endpoints("alpha/atlas-secure")
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_malformed_initial_response_never_produces_success_usage(config_factory) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _completion_response("not-json")

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert calls == 1
    assert usage.records[0].status == "failed:OpenRouterSchemaError"
    assert usage.records[0].validation_status.value == "invalid_response"


@pytest.mark.asyncio
async def test_missing_actual_cost_never_produces_success_usage(config_factory) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response('{"answer":"unaccounted"}', cost=None)

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterSchemaError, match="cost accounting"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status != "success"
    assert usage.records[0].reported_cost_usd is None
    assert usage.records[0].accounted_cost_usd > 0


@pytest.mark.asyncio
async def test_error_inside_success_http_response_is_typed_and_never_credited(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-provider-error"},
            json={
                "error": {"code": 429, "message": "provider-controlled detail"},
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 0,
                    "total_tokens": 10,
                    "cost": 0.003,
                },
            },
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterTransientError, match="rate limit"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status != "success"
    assert usage.records[0].reported_cost_usd is None
    assert usage.records[0].accounted_cost_usd > 0.003
    assert usage.records[0].provider_error_classification == "rate_limit"


@pytest.mark.asyncio
async def test_unvalidated_zero_cost_cannot_release_a_sent_reservation(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion(
            '{"answer":"mismatched"}',
            cost=0,
            model="unrelated/model",
        )
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(OpenRouterModelError, match="exact configured model"):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()

    record = usage.records[0]
    assert record.reported_cost_usd is None
    assert record.accounted_cost_usd > 0
    assert client.budget.spent_usd == pytest.approx(record.accounted_cost_usd)


@pytest.mark.parametrize(
    ("fault", "expected_error"),
    [
        ("mismatched_generation_header", OpenRouterSchemaError),
        ("wrong_message_role", OpenRouterSchemaError),
        ("multiple_choices", OpenRouterSchemaError),
        ("inconsistent_usage", OpenRouterSchemaError),
        ("missing_router_metadata", OpenRouterSchemaError),
        ("hidden_router_fallback", OpenRouterModelError),
    ],
)
@pytest.mark.asyncio
async def test_incomplete_provider_envelopes_fail_closed(
    config_factory,
    fault: str,
    expected_error: type[Exception],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"unsafe envelope"}')
        headers = {"X-Generation-Id": "generation-test"}
        if fault == "mismatched_generation_header":
            headers = {"X-Generation-Id": "different-generation"}
        elif fault == "wrong_message_role":
            payload["choices"][0]["message"]["role"] = "user"
        elif fault == "multiple_choices":
            payload["choices"].append(dict(payload["choices"][0]))
        elif fault == "inconsistent_usage":
            payload["usage"]["total_tokens"] = 99
        elif fault == "missing_router_metadata":
            payload.pop("openrouter_metadata")
        elif fault == "hidden_router_fallback":
            payload["openrouter_metadata"]["strategy"] = "fallback"
        return httpx.Response(200, headers=headers, json=payload)

    client, http_client, usage = _client(config_factory(), handler)
    try:
        with pytest.raises(expected_error):
            await client.complete(
                role="source_audit",
                models=["alpha/atlas-secure"],
                system_prompt="system",
                user_prompt="user",
                response_model=Answer,
                schema_name="answer",
            )
    finally:
        await http_client.aclose()
    assert usage.records[0].status != "success"
    assert usage.records[0].validation_status.value != "valid"


@pytest.mark.asyncio
async def test_reasoning_cached_cost_and_latency_evidence_are_recorded(
    config_factory,
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"evidenced"}')
        payload["usage"]["completion_tokens_details"] = {"reasoning_tokens": 3}
        payload["usage"]["prompt_tokens_details"] = {"cached_tokens": 4}
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "generation-test"},
            json=payload,
        )

    client, http_client, usage = _client(config_factory(), handler)
    try:
        await client.complete(
            role="source_audit",
            models=["alpha/atlas-secure"],
            system_prompt="system",
            user_prompt="user",
            response_model=Answer,
            schema_name="answer",
        )
    finally:
        await http_client.aclose()
    record = usage.records[0]
    assert record.reasoning_tokens == 3
    assert record.cached_tokens == 4
    assert record.reported_cost_usd == 0.01
    assert record.latency_ms is not None
    assert record.started_at is not None
    assert record.ended_at is not None
