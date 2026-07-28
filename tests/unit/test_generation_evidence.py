from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.generation_evidence import (
    GenerationEvidenceValidationError,
    GenerationReconciliationMismatchCode,
    GenerationReconciliationMismatchError,
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    reconcile_generation_evidence,
    validate_openrouter_generation_payload,
)
from mmaudit.models.openrouter import (
    OpenRouterAuthenticationError,
    OpenRouterClient,
    OpenRouterGenerationMetadataNotReadyError,
    OpenRouterGenerationReconciliationError,
    OpenRouterModelError,
    OpenRouterPrivacyError,
    OpenRouterRequestLimitError,
    OpenRouterSchemaError,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import (
    UsageLedger,
    _attest_owned_real_usage_record,
    is_creditable_usage_record,
    is_generation_bindable_usage_record,
)
from mmaudit.orchestration.budgets import BudgetManager

_MODEL = "alpha/atlas-secure"
_CANONICAL_MODEL = "alpha/atlas-secure-20260727"
_PROVIDER_ENDPOINT = "approved-provider"
_PROVIDER_NAME = "Approved Provider"
_GENERATION_ID = "gen-test_123"
_STARTED = datetime(2026, 7, 27, 8, 0, tzinfo=UTC)
_ENDED = datetime(2026, 7, 27, 8, 0, 1, tzinfo=UTC)
_CATALOG_SNAPSHOT_SHA256 = "d" * 64
_DISCOVERY_PROVENANCE_SHA256 = "e" * 64
_DISCOVERY_EVIDENCE_SHA256 = "f" * 64


def _catalog_identity_binding(
    *,
    exact_model: str = _MODEL,
    canonical_model: str = _CANONICAL_MODEL,
) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "canonical_slug": canonical_model,
                "id": exact_model,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _generation_payload(*, model: str = _CANONICAL_MODEL) -> dict[str, Any]:
    return {
        "data": {
            "api_type": "completions",
            "cancelled": False,
            "created_at": "2026-07-27T08:00:00+00:00",
            "finish_reason": "stop",
            "generation_time": 120,
            "id": _GENERATION_ID,
            "latency": 125,
            "model": model,
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
    actual_model: str = _CANONICAL_MODEL,
) -> UsageRecord:
    sha = "a" * 64
    routing = {
        "generation_id": _GENERATION_ID,
        "provider": _PROVIDER_NAME,
        "selected_model": actual_model,
        "canonical_model": _CANONICAL_MODEL,
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
        "catalog_identity_binding_sha256": _catalog_identity_binding(),
        "catalog_snapshot_sha256": _CATALOG_SNAPSHOT_SHA256,
        "discovery_provenance_sha256": _DISCOVERY_PROVENANCE_SHA256,
        "discovery_evidence_sha256": _DISCOVERY_EVIDENCE_SHA256,
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
    usage = UsageRecord(
        request_id="mmaudit-request-123",
        role="accounting",
        execution_evidence=execution_evidence,
        requested_model=_MODEL,
        returned_model=_MODEL,
        actual_model=actual_model,
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
    if execution_evidence is ExecutionEvidenceKind.REAL:
        usage = _attest_owned_real_usage_record(usage)
    return usage


def _reconcile(
    evidence: OpenRouterGenerationEvidence,
    *,
    usage_record: UsageRecord | None = None,
    expected_canonical_model: str = _CANONICAL_MODEL,
    expected_catalog_identity_binding_sha256: str | None = None,
) -> OpenRouterGenerationEvidence:
    return reconcile_generation_evidence(
        evidence,
        usage_record=usage_record or _usage_record(),
        expected_exact_model=_MODEL,
        expected_canonical_model=expected_canonical_model,
        expected_catalog_identity_binding_sha256=(
            expected_catalog_identity_binding_sha256
            or _catalog_identity_binding(canonical_model=expected_canonical_model)
        ),
        expected_discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
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
    reconciled = _reconcile(evidence)
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


def test_real_generation_evidence_reconciles_bindable_uncredited_certification_usage() -> None:
    usage = _usage_record()
    assert is_generation_bindable_usage_record(usage)
    assert not is_creditable_usage_record(usage, require_real=True, require_certification=True)

    evidence = _reconcile(_evidence(), usage_record=usage)

    assert evidence.generation_id == _GENERATION_ID


def test_generation_evidence_accepts_requested_model_as_the_actual_provider_model() -> None:
    usage = _usage_record(actual_model=_MODEL)
    evidence = _evidence(payload=_generation_payload(model=_MODEL))

    assert _reconcile(evidence, usage_record=usage).exact_model_id == _MODEL


@pytest.mark.parametrize(
    ("actual_model", "generation_model"),
    [
        (_MODEL, _CANONICAL_MODEL),
        (_CANONICAL_MODEL, _MODEL),
    ],
)
def test_generation_evidence_accepts_frozen_exact_canonical_alias_pair(
    actual_model: str,
    generation_model: str,
) -> None:
    usage = _usage_record(actual_model=actual_model)
    evidence = _evidence(payload=_generation_payload(model=generation_model))

    assert _reconcile(evidence, usage_record=usage).exact_model_id == generation_model


def test_canonical_generation_requires_frozen_catalog_identity_binding() -> None:
    usage = _usage_record()
    unbound_usage = usage.model_copy(
        update={
            "routing": {
                **usage.routing,
                "catalog_identity_binding_sha256": None,
            }
        }
    )

    assert not is_creditable_usage_record(
        unbound_usage,
        require_real=True,
        require_certification=True,
    )
    with pytest.raises(
        GenerationEvidenceValidationError,
        match="different model identity binding",
    ):
        GenerationVerificationRequest(
            benchmark_report_sha256="1" * 64,
            case_id="case-unbound-canonical",
            exact_model_id=_MODEL,
            canonical_model_id=_CANONICAL_MODEL,
            catalog_identity_binding_sha256=_catalog_identity_binding(),
            discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
            expected_provider_name=_PROVIDER_NAME,
            usage_record=unbound_usage,
        )


def test_generation_verification_rejects_wrong_canonical_identity() -> None:
    wrong_canonical = "alpha/other-canonical-20260727"

    with pytest.raises(
        GenerationEvidenceValidationError,
        match="different model identity binding",
    ):
        GenerationVerificationRequest(
            benchmark_report_sha256="1" * 64,
            case_id="case-wrong-canonical",
            exact_model_id=_MODEL,
            canonical_model_id=wrong_canonical,
            catalog_identity_binding_sha256=_catalog_identity_binding(
                canonical_model=wrong_canonical
            ),
            discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
            expected_provider_name=_PROVIDER_NAME,
            usage_record=_usage_record(),
        )


def test_generation_evidence_rejects_model_outside_frozen_alias_pair() -> None:
    usage = _usage_record(actual_model=_MODEL)
    evidence = _evidence(payload=_generation_payload(model="alpha/unapproved-secure"))

    with pytest.raises(GenerationEvidenceValidationError, match="generation model"):
        _reconcile(evidence, usage_record=usage)


def test_reconciliation_revalidates_the_evidence_self_hash() -> None:
    evidence = _evidence().model_copy(update={"provider_name": "Other Provider"})

    with pytest.raises(GenerationEvidenceValidationError, match="schema-valid"):
        _reconcile(evidence)


@pytest.mark.parametrize(
    ("field", "value", "requested_generation_id", "message"),
    [
        ("id", "gen-other", "gen-other", "generation ID"),
        ("model", "beta/other-secure", _GENERATION_ID, "generation model"),
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
        _reconcile(evidence)


@pytest.mark.parametrize(
    ("field", "value", "expected_field"),
    [
        (
            "tokens_prompt",
            9,
            GenerationReconciliationMismatchCode.PROMPT_TOKENS,
        ),
        (
            "tokens_completion",
            4,
            GenerationReconciliationMismatchCode.COMPLETION_TOKENS,
        ),
        (
            "native_tokens_reasoning",
            1,
            GenerationReconciliationMismatchCode.REASONING_TOKENS,
        ),
        (
            "native_tokens_cached",
            2,
            GenerationReconciliationMismatchCode.CACHED_TOKENS,
        ),
        (
            "total_cost",
            0.02,
            GenerationReconciliationMismatchCode.REPORTED_COST,
        ),
    ],
)
def test_eventual_generation_usage_mismatches_are_typed_for_bounded_polling(
    field: str,
    value: Any,
    expected_field: GenerationReconciliationMismatchCode,
) -> None:
    payload = _generation_payload()
    payload["data"][field] = value
    if field == "total_cost":
        payload["data"]["usage"] = value
    evidence = _evidence(payload=payload)

    with pytest.raises(GenerationReconciliationMismatchError) as raised:
        _reconcile(evidence)

    assert raised.value.code is expected_field
    assert raised.value.is_eventual_usage_field


def test_decisive_generation_identity_mismatch_is_not_retryable() -> None:
    evidence = _evidence(payload=_generation_payload(model="alpha/unapproved-secure"))

    with pytest.raises(GenerationEvidenceValidationError) as raised:
        _reconcile(evidence)

    assert isinstance(raised.value, GenerationReconciliationMismatchError)
    assert not raised.value.is_eventual_usage_field


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
        _reconcile(evidence, usage_record=usage)


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
async def test_generation_metadata_polls_until_same_generation_is_complete(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[httpx.Request] = []
    waits: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        if len(observed) == 1:
            return httpx.Response(404)
        if len(observed) == 2:
            return httpx.Response(200, json={"data": {"id": _GENERATION_ID}})
        return httpx.Response(200, json=_generation_payload())

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    monkeypatch.setattr(
        client,
        "_wait_for_generation_metadata",
        no_wait,
        raising=False,
    )
    try:
        evidence = await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert evidence.generation_id == _GENERATION_ID
    assert evidence.retrieval_attempts == 3
    assert len(observed) == 3
    assert waits == [1.0, 3.0]


@pytest.mark.asyncio
async def test_generation_metadata_poll_is_bounded_for_incomplete_same_generation(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"id": _GENERATION_ID}})

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        with pytest.raises(OpenRouterSchemaError, match="incomplete"):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 4
    assert waits == [1.0, 3.0, 7.0]


@pytest.mark.asyncio
async def test_generation_metadata_does_not_poll_contradictory_generation_id(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": {"id": "gen-other"}})

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid"):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 1
    assert waits == []


@pytest.mark.asyncio
async def test_generation_metadata_not_ready_is_bounded_and_typed(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(404)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        with pytest.raises(OpenRouterGenerationMetadataNotReadyError):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 4
    assert waits == [1.0, 3.0, 7.0]


@pytest.mark.asyncio
async def test_generation_verification_polls_eventual_usage_until_it_matches(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        if calls < 3:
            payload["data"]["tokens_prompt"] = 9
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    request = GenerationVerificationRequest(
        benchmark_report_sha256="1" * 64,
        case_id="case-synthetic",
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        usage_record=_usage_record(),
    )
    try:
        evidence = await client.get_generation_evidence(
            _GENERATION_ID,
            reconciliation_request=request,
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert evidence.retrieval_attempts == 3
    assert calls == 3
    assert waits == [1.0, 3.0]


@pytest.mark.asyncio
async def test_generation_verification_exhaustion_preserves_typed_value_free_mismatch(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        payload["data"]["total_cost"] = 0.02
        payload["data"]["usage"] = 0.02
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    request = GenerationVerificationRequest(
        benchmark_report_sha256="1" * 64,
        case_id="case-synthetic",
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        usage_record=_usage_record(),
    )
    try:
        with pytest.raises(OpenRouterGenerationReconciliationError) as raised:
            await client.get_generation_evidence(
                _GENERATION_ID,
                reconciliation_request=request,
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert raised.value.mismatch_code is GenerationReconciliationMismatchCode.REPORTED_COST
    assert raised.value.attempts == 4
    assert raised.value.exhausted
    assert raised.value.last_evidence is not None
    assert raised.value.last_evidence.retrieval_attempts == 4
    assert calls == 4
    assert waits == [1.0, 3.0, 7.0]
    assert "0.01" not in str(raised.value)
    assert "0.02" not in str(raised.value)


@pytest.mark.asyncio
async def test_generation_verification_fails_decisive_provider_mismatch_immediately(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        payload["data"]["provider_name"] = "Other Provider"
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    request = GenerationVerificationRequest(
        benchmark_report_sha256="1" * 64,
        case_id="case-synthetic",
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        usage_record=_usage_record(),
    )
    try:
        with pytest.raises(OpenRouterGenerationReconciliationError) as raised:
            await client.get_generation_evidence(
                _GENERATION_ID,
                reconciliation_request=request,
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert raised.value.mismatch_code is GenerationReconciliationMismatchCode.PROVIDER
    assert raised.value.attempts == 1
    assert not raised.value.exhausted
    assert raised.value.last_evidence is not None
    assert raised.value.last_evidence.retrieval_attempts == 1
    assert calls == 1
    assert waits == []


@pytest.mark.asyncio
async def test_generation_verification_prioritizes_decisive_timestamp_over_eventual_cost(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        payload["data"]["total_cost"] = 0.02
        payload["data"]["usage"] = 0.02
        payload["data"]["created_at"] = "2025-01-01T00:00:00Z"
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    request = GenerationVerificationRequest(
        benchmark_report_sha256="1" * 64,
        case_id="case-synthetic",
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        usage_record=_usage_record(),
    )
    try:
        with pytest.raises(OpenRouterGenerationReconciliationError) as raised:
            await client.get_generation_evidence(
                _GENERATION_ID,
                reconciliation_request=request,
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert raised.value.mismatch_code is GenerationReconciliationMismatchCode.REQUEST_TIMESTAMP
    assert raised.value.attempts == 1
    assert not raised.value.exhausted
    assert raised.value.last_evidence is not None
    assert raised.value.last_evidence.retrieval_attempts == 1
    assert calls == 1
    assert waits == []


@pytest.mark.asyncio
async def test_generation_metadata_does_not_poll_internally_inconsistent_cost(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        payload["data"]["total_cost"] = 0.02
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(config, handler)
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid"):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 1
    assert waits == []


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
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
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
    assert calls == 1


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
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
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
            canonical_model_id=_CANONICAL_MODEL,
            catalog_identity_binding_sha256=_catalog_identity_binding(),
            discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
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
            canonical_model_id=_CANONICAL_MODEL,
            catalog_identity_binding_sha256=_catalog_identity_binding(),
            discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
            expected_provider_name=_PROVIDER_NAME,
            usage_record=usage,
        )


def test_trusted_generation_capability_cannot_be_constructed_or_serialized() -> None:
    with pytest.raises(TypeError, match="cannot be constructed"):
        TrustedGenerationVerification((), issuer=object())
    forged = object.__new__(TrustedGenerationVerification)
    usage = _usage_record()
    with pytest.raises(
        GenerationEvidenceValidationError,
        match="capability is not trusted",
    ):
        forged.attestation_for(
            benchmark_report_sha256="1" * 64,
            case_id="case-synthetic",
            exact_model_id=_MODEL,
            canonical_model_id=_CANONICAL_MODEL,
            catalog_identity_binding_sha256=_catalog_identity_binding(),
            discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
            usage_record=usage,
            expected_provider_name=_PROVIDER_NAME,
        )
    assert not hasattr(TrustedGenerationVerification, "model_validate")
    assert not hasattr(TrustedGenerationVerification, "model_dump")
