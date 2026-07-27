from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.generation_evidence import (
    GenerationEvidenceValidationError,
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    reconcile_generation_evidence,
    validate_openrouter_generation_payload,
)
from mmaudit.models.openrouter import (
    OpenRouterAuthenticationError,
    OpenRouterClient,
    OpenRouterModelError,
    OpenRouterPrivacyError,
    OpenRouterRequestLimitError,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import UsageLedger, is_creditable_usage_record
from mmaudit.orchestration.budgets import BudgetManager

_MODEL = "alpha/atlas-secure"
_PROVIDER_ENDPOINT = "approved-provider"
_PROVIDER_NAME = "Approved Provider"
_GENERATION_ID = "gen-test_123"
_STARTED = datetime(2026, 7, 27, 8, 0, tzinfo=UTC)
_ENDED = datetime(2026, 7, 27, 8, 0, 1, tzinfo=UTC)


def _generation_payload() -> dict[str, Any]:
    return {
        "data": {
            "api_type": "completions",
            "cancelled": False,
            "created_at": "2026-07-27T08:00:00+00:00",
            "finish_reason": "stop",
            "generation_time": 120,
            "id": _GENERATION_ID,
            "latency": 125,
            "model": _MODEL,
            "native_finish_reason": "stop",
            "native_tokens_cached": 3,
            "native_tokens_completion": 7,
            "native_tokens_prompt": 12,
            "native_tokens_reasoning": 2,
            "provider_name": _PROVIDER_NAME,
            "request_id": "req-test_123",
            "tokens_completion": 5,
            "tokens_prompt": 10,
            "total_cost": 0.01,
            "usage": 0.01,
            # Content-like provider fields are deliberately not retained.
            "prompt": "SYNTHETIC_CONTENT_CANARY",
            "completion": "SYNTHETIC_CONTENT_CANARY",
        }
    }


def _usage_record(
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    certification: bool = True,
) -> UsageRecord:
    sha = "a" * 64
    routing = {
        "generation_id": _GENERATION_ID,
        "provider": _PROVIDER_NAME,
        "selected_provider_endpoint": _PROVIDER_ENDPOINT,
        "selected_provider_name": _PROVIDER_NAME,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_attempts_observed": True,
        "router_metadata_sha256": "b" * 64,
        "router_pipeline": [],
        "finish_reason": "stop",
        "native_finish_reason": "stop",
        "reasoning_tokens": 2,
        "cached_tokens": 3,
        "schema_sha256": "c" * 64,
        "provider_policy_sha256": "d" * 64,
        "endpoint_snapshot_sha256": "e" * 64,
        "endpoint_pricing_sha256": "f" * 64,
        "configured_provider_only": [_PROVIDER_ENDPOINT],
        "configured_provider_order": [],
        "provider_fallbacks_allowed": False,
        "certification_request": certification,
        "zdr_requested": True,
        "data_collection": "deny",
        "request_started_at": _STARTED.isoformat(),
        "request_ended_at": _ENDED.isoformat(),
        "latency_ms": 1_000,
        "validation_status": "valid",
        "repair_used": False,
        "repair_request": False,
    }
    return UsageRecord(
        request_id="mmaudit-request-123",
        role="accounting",
        execution_evidence=execution_evidence,
        requested_model=_MODEL,
        returned_model=_MODEL,
        provider=_PROVIDER_NAME,
        model_family="atlas",
        timestamp=_STARTED,
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing=routing,
        prompt_sha256=sha,
        response_sha256=sha,
        validated_response_sha256=sha,
        request_body_sha256=sha,
        schema_sha256="c" * 64,
        openrouter_generation_id=_GENERATION_ID,
        configured_provider_endpoints=[_PROVIDER_ENDPOINT],
        actual_provider_endpoint=_PROVIDER_ENDPOINT,
        started_at=_STARTED,
        ended_at=_ENDED,
        latency_ms=1_000,
        finish_reason="stop",
        reasoning_tokens=2,
        cached_tokens=3,
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        fallback_used=False,
        substitution_detected=False,
        status="success",
        attempts=1,
    )


def _evidence(
    *,
    payload: dict[str, Any] | None = None,
    requested_generation_id: str = _GENERATION_ID,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
) -> OpenRouterGenerationEvidence:
    return validate_openrouter_generation_payload(
        payload or _generation_payload(),
        requested_generation_id=requested_generation_id,
        retrieved_at=datetime(2026, 7, 27, 8, 1, tzinfo=UTC),
        execution_evidence=execution_evidence,
    )


def _client(
    config: Any,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    api_key: str = "synthetic-key",
) -> tuple[OpenRouterClient, httpx.AsyncClient]:
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://fake.test/api/v1/",
    )
    client = OpenRouterClient(
        api_key=api_key,
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
        http_client=http_client,
    )
    return client, http_client


def test_generation_payload_is_allowlisted_self_hashed_and_mock_labeled() -> None:
    evidence = _evidence(execution_evidence=ExecutionEvidenceKind.MOCK)

    serialized = evidence.model_dump_json()
    assert evidence.execution_evidence is ExecutionEvidenceKind.MOCK
    assert evidence.source_api_identity == "openrouter:/api/v1/generation"
    assert evidence.total_cost_usd == "0.01"
    assert "SYNTHETIC_CONTENT_CANARY" not in serialized

    with pytest.raises(ValidationError, match="hash"):
        OpenRouterGenerationEvidence.model_validate(
            {**evidence.model_dump(mode="json"), "evidence_sha256": "0" * 64}
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cancelled", True),
        ("tokens_prompt", -1),
        ("native_tokens_cached", 11),
        ("total_cost", float("inf")),
        ("provider_name", "bad\nprovider"),
        ("model", "openrouter/auto"),
    ],
)
def test_generation_payload_rejects_malformed_values(field: str, value: Any) -> None:
    payload = _generation_payload()
    payload["data"][field] = value

    with pytest.raises((GenerationEvidenceValidationError, ValidationError)):
        _evidence(payload=payload)


def test_generation_payload_rejects_conflicting_cost_representations() -> None:
    payload = _generation_payload()
    payload["data"]["usage"] = 0.02

    with pytest.raises(GenerationEvidenceValidationError, match="inconsistent"):
        _evidence(payload=payload)


@pytest.mark.parametrize("mode", ["missing", "null"])
def test_optional_native_token_metadata_is_not_fabricated(mode: str) -> None:
    payload = _generation_payload()
    native_fields = (
        "native_tokens_prompt",
        "native_tokens_completion",
        "native_tokens_reasoning",
        "native_tokens_cached",
    )
    for field in native_fields:
        if mode == "missing":
            del payload["data"][field]
        else:
            payload["data"][field] = None

    evidence = _evidence(payload=payload)

    assert evidence.native_prompt_tokens is None
    assert evidence.native_completion_tokens is None
    assert evidence.reasoning_tokens is None
    assert evidence.cached_tokens is None
    reconciled = reconcile_generation_evidence(
        evidence,
        usage_record=_usage_record(),
        expected_exact_model=_MODEL,
        expected_provider_name=_PROVIDER_NAME,
    )
    assert reconciled.reasoning_tokens is None
    assert reconciled.cached_tokens is None


@pytest.mark.parametrize(
    "field",
    [
        "native_tokens_prompt",
        "native_tokens_completion",
        "native_tokens_reasoning",
        "native_tokens_cached",
    ],
)
def test_optional_native_token_metadata_rejects_invalid_non_null_values(field: str) -> None:
    payload = _generation_payload()
    payload["data"][field] = "0"

    with pytest.raises(GenerationEvidenceValidationError, match="tokens is invalid"):
        _evidence(payload=payload)


def test_real_generation_evidence_reconciles_creditable_certification_usage() -> None:
    usage = _usage_record()
    assert is_creditable_usage_record(
        usage,
        require_real=True,
        require_certification=True,
    )

    evidence = reconcile_generation_evidence(
        _evidence(),
        usage_record=usage,
        expected_exact_model=_MODEL,
        expected_provider_name=_PROVIDER_NAME,
    )

    assert evidence.generation_id == _GENERATION_ID


def test_reconciliation_revalidates_the_evidence_self_hash() -> None:
    evidence = _evidence().model_copy(update={"provider_name": "Other Provider"})

    with pytest.raises(GenerationEvidenceValidationError, match="schema-valid"):
        reconcile_generation_evidence(
            evidence,
            usage_record=_usage_record(),
            expected_exact_model=_MODEL,
            expected_provider_name=_PROVIDER_NAME,
        )


@pytest.mark.parametrize(
    ("field", "value", "requested_generation_id", "message"),
    [
        ("id", "gen-other", "gen-other", "generation ID"),
        ("model", "beta/other-secure", _GENERATION_ID, "expected exact model"),
        ("provider_name", "Other Provider", _GENERATION_ID, "expected provider"),
        ("finish_reason", "error", _GENERATION_ID, "finish reason"),
        ("native_finish_reason", "other", _GENERATION_ID, "native finish reason"),
        ("tokens_prompt", 9, _GENERATION_ID, "prompt tokens"),
        ("tokens_completion", 4, _GENERATION_ID, "completion tokens"),
        ("native_tokens_reasoning", 1, _GENERATION_ID, "reasoning tokens"),
        ("native_tokens_cached", 2, _GENERATION_ID, "cached tokens"),
        ("total_cost", 0.02, _GENERATION_ID, "reported cost"),
        ("created_at", "2025-01-01T00:00:00Z", _GENERATION_ID, "request timestamp"),
    ],
)
def test_generation_evidence_rejects_usage_mismatches(
    field: str,
    value: Any,
    requested_generation_id: str,
    message: str,
) -> None:
    payload = _generation_payload()
    payload["data"][field] = value
    if field == "total_cost":
        payload["data"]["usage"] = value
    evidence = _evidence(
        payload=payload,
        requested_generation_id=requested_generation_id,
    )

    with pytest.raises(GenerationEvidenceValidationError, match=message):
        reconcile_generation_evidence(
            evidence,
            usage_record=_usage_record(),
            expected_exact_model=_MODEL,
            expected_provider_name=_PROVIDER_NAME,
        )


@pytest.mark.parametrize(
    ("evidence_kind", "usage_kind", "certification"),
    [
        (ExecutionEvidenceKind.MOCK, ExecutionEvidenceKind.REAL, True),
        (ExecutionEvidenceKind.UNVERIFIED, ExecutionEvidenceKind.REAL, True),
        (ExecutionEvidenceKind.REAL, ExecutionEvidenceKind.MOCK, True),
        (ExecutionEvidenceKind.REAL, ExecutionEvidenceKind.REAL, False),
    ],
)
def test_self_hash_cannot_upgrade_nonreal_or_noncertification_evidence(
    evidence_kind: ExecutionEvidenceKind,
    usage_kind: ExecutionEvidenceKind,
    certification: bool,
) -> None:
    evidence = _evidence(execution_evidence=evidence_kind)
    usage = _usage_record(
        execution_evidence=usage_kind,
        certification=certification,
    )

    with pytest.raises(GenerationEvidenceValidationError):
        reconcile_generation_evidence(
            evidence,
            usage_record=usage,
            expected_exact_model=_MODEL,
            expected_provider_name=_PROVIDER_NAME,
        )


@pytest.mark.asyncio
async def test_client_uses_fixed_authenticated_bounded_generation_query(
    config_factory: Callable[..., Any],
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, json=_generation_payload())

    config = config_factory()
    client, http_client = _client(config, handler)
    try:
        evidence = await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert evidence.execution_evidence is ExecutionEvidenceKind.MOCK
    assert len(observed) == 1
    assert observed[0].method == "GET"
    assert observed[0].url.path == "/api/v1/generation"
    assert dict(observed[0].url.params) == {"id": _GENERATION_ID}
    assert observed[0].headers["Authorization"] == "Bearer synthetic-key"


@pytest.mark.asyncio
async def test_invalid_generation_id_is_rejected_before_transport(
    config_factory: Callable[..., Any],
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_generation_payload())

    config = config_factory()
    client, http_client = _client(config, handler)
    try:
        with pytest.raises(OpenRouterRequestLimitError, match="bounded safe"):
            await client.get_generation_evidence("gen-ok&second=query")
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 0


@pytest.mark.asyncio
async def test_generation_authentication_error_never_echoes_credential(
    config_factory: Callable[..., Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "SYNTHETIC_SECRET_CANARY_987"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": {"message": canary, "authorization": canary}},
        )

    config = config_factory()
    client, http_client = _client(config, handler, api_key=canary)
    try:
        with pytest.raises(OpenRouterAuthenticationError) as raised:
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    captured = capsys.readouterr()
    assert canary not in str(raised.value)
    assert canary not in captured.out
    assert canary not in captured.err


@pytest.mark.asyncio
async def test_generation_response_rejects_duplicate_json_keys(
    config_factory: Callable[..., Any],
) -> None:
    body = b'{"data":{"id":"gen-test_123","id":"gen-other","model":"alpha/atlas-secure"}}'
    config = config_factory()
    client, http_client = _client(
        config,
        lambda _request: httpx.Response(200, content=body),
    )
    try:
        with pytest.raises(OpenRouterModelError, match="valid object"):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()


class _InjectedTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.called = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.called = True
        return httpx.Response(200, request=request, json=_generation_payload())


@pytest.mark.asyncio
async def test_injected_network_transport_cannot_claim_real_generation_evidence(
    config_factory: Callable[..., Any],
) -> None:
    config = config_factory()
    transport = _InjectedTransport()
    http_client = httpx.AsyncClient(
        transport=transport,
        base_url=OPENROUTER_DEFAULT_BASE_URL,
    )
    client = OpenRouterClient(
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
        http_client=http_client,
    )
    assert client.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    try:
        with pytest.raises(OpenRouterPrivacyError, match="injected"):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert transport.called is False


def test_generation_evidence_does_not_retain_authorization_or_content() -> None:
    payload = copy.deepcopy(_generation_payload())
    payload["data"]["Authorization"] = "Bearer SYNTHETIC_SECRET_CANARY"
    payload["data"]["messages"] = [{"content": "SYNTHETIC_SECRET_CANARY"}]

    serialized = _evidence(payload=payload).model_dump_json()

    assert "SYNTHETIC_SECRET_CANARY" not in serialized
    assert hashlib.sha256(b"SYNTHETIC_SECRET_CANARY").hexdigest() not in serialized


@pytest.mark.asyncio
async def test_mock_client_cannot_issue_trusted_generation_verification(
    config_factory: Callable[..., Any],
) -> None:
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, request=request, json={"data": {}})

    config = config_factory()
    client, http_client = _client(config, handler)
    request = GenerationVerificationRequest(
        benchmark_report_sha256="1" * 64,
        case_id="case-synthetic",
        exact_model_id=_MODEL,
        expected_provider_name=_PROVIDER_NAME,
        usage_record=_usage_record(),
    )
    try:
        with pytest.raises(OpenRouterPrivacyError, match="owned REAL"):
            await client.create_trusted_generation_verification((request,))
    finally:
        await client.close()
        await http_client.aclose()

    assert observed == []


@pytest.mark.asyncio
async def test_generation_verification_rejects_replayed_generation_before_transport(
    config_factory: Callable[..., Any],
) -> None:
    config = config_factory()
    client, http_client = _client(
        config,
        lambda request: httpx.Response(200, request=request, json={"data": {}}),
    )
    requests = tuple(
        GenerationVerificationRequest(
            benchmark_report_sha256="1" * 64,
            case_id=f"case-{index}",
            exact_model_id=_MODEL,
            expected_provider_name=_PROVIDER_NAME,
            usage_record=_usage_record(),
        )
        for index in range(2)
    )
    try:
        with pytest.raises(OpenRouterRequestLimitError, match="replayed"):
            await client.create_trusted_generation_verification(requests)
    finally:
        await client.close()
        await http_client.aclose()


def test_generation_verification_request_rejects_missing_generation_identity() -> None:
    usage = _usage_record().model_copy(update={"openrouter_generation_id": None})

    with pytest.raises(GenerationEvidenceValidationError, match="usage is invalid"):
        GenerationVerificationRequest(
            benchmark_report_sha256="1" * 64,
            case_id="case-synthetic",
            exact_model_id=_MODEL,
            expected_provider_name=_PROVIDER_NAME,
            usage_record=usage,
        )


def test_trusted_generation_capability_cannot_be_constructed_or_serialized() -> None:
    with pytest.raises(TypeError, match="cannot be constructed"):
        TrustedGenerationVerification((), issuer=object())
    assert not hasattr(TrustedGenerationVerification, "model_validate")
    assert not hasattr(TrustedGenerationVerification, "model_dump")
