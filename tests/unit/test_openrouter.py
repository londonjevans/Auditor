from __future__ import annotations

import gzip
import json
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.openrouter import (
    OpenRouterAuthenticationError,
    OpenRouterClient,
    OpenRouterModelError,
    OpenRouterPrivacyError,
    OpenRouterRequestLimitError,
    OpenRouterSchemaError,
    OpenRouterTransientError,
    is_retryable_status,
    safe_headers,
    strict_json_schema,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetExhaustedError, BudgetManager


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str


class OptionalAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str
    note: str | None = None


def _completion(content: str, *, cost: float | None = 0.01) -> dict[str, Any]:
    usage: dict[str, Any] = {
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "total_tokens": 15,
    }
    if cost is not None:
        usage["cost"] = cost
    return {
        "id": "generation-test",
        "model": "alpha/atlas-secure",
        "provider": "synthetic-provider",
        "choices": [{"message": {"content": content}}],
        "usage": usage,
    }


def _client(
    config,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    api_key: str = "synthetic-key",
    run_dir: Path | None = None,
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
    )
    return client, http_client, usage


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
async def test_owned_alternate_endpoint_is_unverified(config_factory) -> None:
    client = _owned_client(
        config_factory(),
        base_url="https://operator-proxy.invalid/api/v1",
    )
    try:
        assert client.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_structured_request_and_usage(config_factory) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json=_completion('{"answer":"ok"}'))

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
    assert usage.records[0].reported_cost_usd == 0.01
    assert usage.records[0].returned_model == "alpha/atlas-secure"
    assert usage.records[0].execution_evidence is ExecutionEvidenceKind.MOCK


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
        return httpx.Response(200, json=_completion('{"answer":"ok"}'))

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
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json=_completion('{"answer":"after retry"}'))

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
async def test_one_bounded_json_repair(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        content = "not json" if calls == 1 else '{"answer":"repaired"}'
        return httpx.Response(200, json=_completion(content))

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
    assert result.answer == "repaired"
    assert calls == 2
    assert [record.role for record in usage.records] == [
        "source_audit",
        "source_audit:json_repair",
    ]


@pytest.mark.asyncio
async def test_invalid_repair_is_not_repeated(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_completion("still not json"))

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
    assert calls == 2


@pytest.mark.asyncio
async def test_hard_budget_refuses_before_network(config_factory) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_completion('{"answer":"unexpected"}'))

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
        return httpx.Response(200, json=_completion('{"answer":"unexpected"}'))

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
            headers={"Authorization": canary},
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
        return httpx.Response(200, json=payload)

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
        return httpx.Response(200, json={"data": []})

    client, http_client, _usage = _client(
        config_factory(execution={"max_model_retries": 1}),
        handler,
    )

    async def no_wait(attempt: int, retry_after: str | None) -> None:
        del attempt, retry_after

    monkeypatch.setattr(client, "_backoff", no_wait)
    try:
        assert await client.list_models() == []
    finally:
        await http_client.aclose()
    assert calls == 2


@pytest.mark.asyncio
async def test_unrelated_returned_model_is_rejected_and_recorded(config_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _completion('{"answer":"wrong model"}')
        payload["model"] = "unrelated/vendor-model"
        return httpx.Response(200, json=payload)

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
        payload = _completion('{"answer":"fallback"}')
        payload["model"] = body["model"]
        return httpx.Response(200, json=payload)

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
