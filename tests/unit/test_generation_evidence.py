from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.generation_evidence import (
    GenerationEvidenceValidationError,
    GenerationReconciliationExpectation,
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
from tests.identity_fixtures import (
    synthetic_strict_zdr_privacy_routing,
    synthetic_token_plan_routing,
)
from tests.output_evidence_fixtures import (
    SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
    synthetic_structured_output_routing,
)

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


def _reconciliation_expectation() -> GenerationReconciliationExpectation:
    return GenerationReconciliationExpectation(
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        require_certification=True,
        usage_record=_usage_record(),
    )


def _verification_request(
    generation_id: str,
    *,
    index: int,
) -> GenerationVerificationRequest:
    return GenerationVerificationRequest(
        benchmark_report_sha256="1" * 64,
        case_id=f"case-{index}",
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        usage_record=_usage_record(
            generation_id=generation_id,
            request_id=f"mmaudit-request-{index}",
        ),
    )


def _usage_record(
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
    certification: bool = True,
    actual_model: str = _CANONICAL_MODEL,
    generation_id: str = _GENERATION_ID,
    request_id: str = "mmaudit-request-123",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> UsageRecord:
    sha = "a" * 64
    routing = {
        "generation_id": generation_id,
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
        "output_capability_sha256": SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
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
        "structured_output": synthetic_structured_output_routing(
            configured_provider_endpoints=(_PROVIDER_ENDPOINT,),
            selected_provider_endpoint=_PROVIDER_ENDPOINT,
            endpoint_snapshot_sha256="e" * 64,
            prompt_sha256=sha,
            request_body_sha256=sha,
            provider_policy_sha256="d" * 64,
            schema_sha256="c" * 64,
            original_response_sha256=sha,
            validated_response_sha256=sha,
        ),
    }
    routing = synthetic_strict_zdr_privacy_routing(
        routing,
        source_label=f"generation-evidence:{request_id}",
    )
    usage = UsageRecord(
        request_id=request_id,
        role="accounting",
        execution_evidence=execution_evidence,
        requested_model=_MODEL,
        returned_model=_MODEL,
        actual_model=actual_model,
        provider=_PROVIDER_NAME,
        model_family="atlas",
        timestamp=_STARTED,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing=routing,
        prompt_sha256=sha,
        response_sha256=sha,
        validated_response_sha256=sha,
        request_body_sha256=sha,
        schema_sha256="c" * 64,
        openrouter_generation_id=generation_id,
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
    usage = usage.model_copy(update={"routing": synthetic_token_plan_routing(usage, usage.routing)})
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
    handler: Callable[[httpx.Request], httpx.Response]
    | Callable[[httpx.Request], Coroutine[None, None, httpx.Response]],
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
        ("native_tokens_cached", 13),
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


def test_generation_reconciliation_accepts_one_complete_native_token_basis() -> None:
    payload = _generation_payload()
    payload["data"].update(
        {
            "tokens_prompt": 211,
            "tokens_completion": 19,
            "native_tokens_prompt": 256,
            "native_tokens_completion": 29,
        }
    )
    evidence = _evidence(payload=payload)
    usage = _usage_record(prompt_tokens=256, completion_tokens=29)

    reconciled = _reconcile(evidence, usage_record=usage)

    assert (reconciled.prompt_tokens, reconciled.completion_tokens) == (211, 19)
    assert (
        reconciled.native_prompt_tokens,
        reconciled.native_completion_tokens,
    ) == (256, 29)


@pytest.mark.parametrize(
    ("native_field", "value"),
    [
        ("native_tokens_reasoning", 6),
        ("native_tokens_cached", 11),
    ],
)
def test_native_token_details_use_their_native_parent_bounds(
    native_field: str,
    value: int,
) -> None:
    payload = _generation_payload()
    payload["data"][native_field] = value

    evidence = _evidence(payload=payload)

    assert (
        getattr(
            evidence,
            "reasoning_tokens" if native_field == "native_tokens_reasoning" else "cached_tokens",
        )
        == value
    )


@pytest.mark.parametrize(
    ("normalized_pair", "native_pair"),
    [
        ((10, 4), (12, 5)),
        ((9, 5), (10, 7)),
    ],
)
def test_generation_reconciliation_rejects_cross_basis_token_pair(
    normalized_pair: tuple[int, int],
    native_pair: tuple[int, int],
) -> None:
    payload = _generation_payload()
    payload["data"].update(
        {
            "tokens_prompt": normalized_pair[0],
            "tokens_completion": normalized_pair[1],
            "native_tokens_prompt": native_pair[0],
            "native_tokens_completion": native_pair[1],
        }
    )

    with pytest.raises(GenerationReconciliationMismatchError) as raised:
        _reconcile(_evidence(payload=payload))

    assert raised.value.code is GenerationReconciliationMismatchCode.COMPLETION_TOKENS
    assert raised.value.is_eventual_usage_field


@pytest.mark.parametrize(
    ("normalized_pair", "native_pair", "mismatch_code"),
    [
        (
            (9, 5),
            (10, None),
            GenerationReconciliationMismatchCode.PROMPT_TOKENS,
        ),
        (
            (10, 4),
            (None, 5),
            GenerationReconciliationMismatchCode.COMPLETION_TOKENS,
        ),
    ],
)
def test_generation_reconciliation_rejects_partial_native_token_pair(
    normalized_pair: tuple[int, int],
    native_pair: tuple[int | None, int | None],
    mismatch_code: GenerationReconciliationMismatchCode,
) -> None:
    payload = _generation_payload()
    payload["data"].update(
        {
            "tokens_prompt": normalized_pair[0],
            "tokens_completion": normalized_pair[1],
            "native_tokens_prompt": native_pair[0],
            "native_tokens_completion": native_pair[1],
        }
    )

    with pytest.raises(GenerationReconciliationMismatchError) as raised:
        _reconcile(_evidence(payload=payload))

    assert raised.value.code is mismatch_code


@pytest.mark.parametrize(
    ("normalized_field", "normalized_value", "native_field", "native_value"),
    [
        ("tokens_completion", 10, "native_tokens_reasoning", 8),
        ("tokens_prompt", 20, "native_tokens_cached", 13),
    ],
)
def test_native_token_details_cannot_exceed_smaller_native_parent(
    normalized_field: str,
    normalized_value: int,
    native_field: str,
    native_value: int,
) -> None:
    payload = _generation_payload()
    payload["data"][normalized_field] = normalized_value
    payload["data"][native_field] = native_value

    with pytest.raises(ValidationError, match="exceed"):
        _evidence(payload=payload)


def test_native_token_detail_without_native_parent_uses_conservative_normalized_bound() -> None:
    payload = _generation_payload()
    payload["data"].update(
        {
            "native_tokens_completion": None,
            "native_tokens_reasoning": 6,
        }
    )

    with pytest.raises(ValidationError, match="reasoning tokens exceed"):
        _evidence(payload=payload)


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


def test_generation_evidence_rejects_retrieval_attempts_above_fixed_maximum() -> None:
    with pytest.raises(
        GenerationEvidenceValidationError,
        match="outside the bounded polling policy",
    ):
        validate_openrouter_generation_payload(
            _generation_payload(),
            requested_generation_id=_GENERATION_ID,
            retrieved_at=datetime.now(UTC),
            retrieval_attempts=8,
            execution_evidence=ExecutionEvidenceKind.MOCK,
        )


def test_generation_reconciliation_expectation_binds_provider_and_route_class() -> None:
    with pytest.raises(
        GenerationEvidenceValidationError,
        match="different model identity binding",
    ):
        GenerationReconciliationExpectation(
            exact_model_id=_MODEL,
            canonical_model_id=_CANONICAL_MODEL,
            catalog_identity_binding_sha256=_catalog_identity_binding(),
            discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
            expected_provider_name="Other Provider",
            require_certification=True,
            usage_record=_usage_record(),
        )
    with pytest.raises(
        GenerationEvidenceValidationError,
        match="certification policy differs",
    ):
        GenerationReconciliationExpectation(
            exact_model_id=_MODEL,
            canonical_model_id=_CANONICAL_MODEL,
            catalog_identity_binding_sha256=_catalog_identity_binding(),
            discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
            expected_provider_name=_PROVIDER_NAME,
            require_certification=False,
            usage_record=_usage_record(),
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

    config = config_factory(
        execution={
            "request_timeout_seconds": 11,
            "max_model_retries": 0,
        }
    )
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

    config = config_factory(
        execution={
            "request_timeout_seconds": 11,
            "max_model_retries": 0,
        }
    )
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

    config = config_factory(
        execution={
            "request_timeout_seconds": 11,
            "max_model_retries": 0,
        }
    )
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

    config = config_factory(
        execution={
            "request_timeout_seconds": 11,
            "max_model_retries": 0,
        }
    )
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
async def test_generation_metadata_uses_late_readiness_window_when_timeout_allows(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 5:
            return httpx.Response(404)
        return httpx.Response(200, json=_generation_payload())

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        evidence = await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert evidence.retrieval_attempts == 5
    assert calls == 5
    assert waits == [1.0, 3.0, 7.0, 15.0]


@pytest.mark.asyncio
async def test_generation_metadata_late_readiness_window_remains_bounded(
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

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        with pytest.raises(OpenRouterGenerationMetadataNotReadyError):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 7
    assert waits == [1.0, 3.0, 7.0, 15.0, 30.0, 60.0]


@pytest.mark.asyncio
async def test_generation_metadata_enforces_one_total_wall_clock_deadline(
    config_factory: Callable[..., Any],
) -> None:
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.2)
        return httpx.Response(200, json=_generation_payload())

    config = config_factory(
        execution={
            "request_timeout_seconds": 0.02,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    started = asyncio.get_running_loop().time()
    try:
        with pytest.raises(OpenRouterGenerationMetadataNotReadyError, match="deadline"):
            await client.get_generation_evidence(_GENERATION_ID)
    finally:
        elapsed = asyncio.get_running_loop().time() - started
        await client.close()
        await http_client.aclose()

    assert calls == 1
    assert elapsed < 0.5


@pytest.mark.asyncio
async def test_generation_request_semaphore_limits_only_active_metadata_gets(
    config_factory: Callable[..., Any],
) -> None:
    active_requests = 0
    maximum_active_requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_requests, maximum_active_requests
        generation_id = request.url.params["id"]
        active_requests += 1
        maximum_active_requests = max(maximum_active_requests, active_requests)
        await asyncio.sleep(0.02)
        payload = _generation_payload()
        payload["data"]["id"] = generation_id
        payload["data"]["request_id"] = f"request-{generation_id}"
        active_requests -= 1
        return httpx.Response(200, json=payload)

    config = config_factory(
        execution={
            "request_timeout_seconds": 1,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    semaphore = asyncio.Semaphore(2)
    generation_ids = ("gen-concurrent-a", "gen-concurrent-b", "gen-concurrent-c")
    try:
        evidence = await asyncio.gather(
            *(
                client.get_generation_evidence(
                    generation_id,
                    _request_semaphore=semaphore,
                )
                for generation_id in generation_ids
            )
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert tuple(item.generation_id for item in evidence) == generation_ids
    assert maximum_active_requests == 2


@pytest.mark.asyncio
async def test_waiting_generation_does_not_monopolize_request_semaphore(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_wait_started = asyncio.Event()
    never_release = asyncio.Event()
    observed_ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        generation_id = request.url.params["id"]
        observed_ids.append(generation_id)
        if generation_id == "gen-waiting":
            return httpx.Response(404)
        payload = _generation_payload()
        payload["data"]["id"] = generation_id
        payload["data"]["request_id"] = f"request-{generation_id}"
        return httpx.Response(200, json=payload)

    async def wait_until_cancelled(_delay_seconds: float) -> None:
        first_wait_started.set()
        await never_release.wait()

    config = config_factory(
        execution={
            "request_timeout_seconds": 1,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    monkeypatch.setattr(client, "_wait_for_generation_metadata", wait_until_cancelled)
    semaphore = asyncio.Semaphore(1)
    waiting = asyncio.create_task(
        client.get_generation_evidence(
            "gen-waiting",
            _request_semaphore=semaphore,
        )
    )
    try:
        await asyncio.wait_for(first_wait_started.wait(), timeout=0.2)
        ready = await asyncio.wait_for(
            client.get_generation_evidence(
                "gen-ready",
                _request_semaphore=semaphore,
            ),
            timeout=0.2,
        )
    finally:
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        await client.close()
        await http_client.aclose()

    assert ready.generation_id == "gen-ready"
    assert observed_ids == ["gen-waiting", "gen-ready"]


@pytest.mark.parametrize(
    ("field", "value", "mismatch_code"),
    (
        (
            "model",
            "other/unapproved-model",
            GenerationReconciliationMismatchCode.GENERATION_MODEL,
        ),
        (
            "provider_name",
            "Other Provider",
            GenerationReconciliationMismatchCode.PROVIDER,
        ),
        (
            "finish_reason",
            "error",
            GenerationReconciliationMismatchCode.FINISH_REASON,
        ),
        (
            "created_at",
            "2025-01-01T00:00:00Z",
            GenerationReconciliationMismatchCode.REQUEST_TIMESTAMP,
        ),
    ),
)
@pytest.mark.parametrize("include_generation_id", (True, False))
@pytest.mark.asyncio
async def test_partial_generation_metadata_rejects_explicit_decisive_contradiction(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    mismatch_code: GenerationReconciliationMismatchCode,
    include_generation_id: bool,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        del payload["data"]["tokens_completion"]
        if not include_generation_id:
            del payload["data"]["id"]
        payload["data"][field] = value
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        with pytest.raises(OpenRouterGenerationReconciliationError) as raised:
            await client.get_generation_evidence(
                _GENERATION_ID,
                reconciliation_request=_reconciliation_expectation(),
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert raised.value.mismatch_code is mismatch_code
    assert raised.value.attempts == 1
    assert not raised.value.exhausted
    assert raised.value.last_evidence is None
    assert calls == 1
    assert waits == []
    assert value not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("include_generation_id", (True, False))
async def test_partial_generation_metadata_rejects_internal_cost_contradiction(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
    include_generation_id: bool,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        del payload["data"]["tokens_completion"]
        if not include_generation_id:
            del payload["data"]["id"]
        payload["data"]["total_cost"] = 0.02
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        with pytest.raises(OpenRouterSchemaError, match="invalid"):
            await client.get_generation_evidence(
                _GENERATION_ID,
                reconciliation_request=_reconciliation_expectation(),
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert calls == 1
    assert waits == []


@pytest.mark.asyncio
async def test_partial_generation_metadata_may_settle_only_eventual_usage_field(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        if calls == 1:
            del payload["data"]["tokens_completion"]
            payload["data"]["tokens_prompt"] = 9
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    try:
        evidence = await client.get_generation_evidence(
            _GENERATION_ID,
            reconciliation_request=_reconciliation_expectation(),
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert evidence.retrieval_attempts == 2
    assert calls == 2
    assert waits == [1.0]


@pytest.mark.asyncio
async def test_noncertification_generation_reconciliation_remains_supported(
    config_factory: Callable[..., Any],
) -> None:
    config = config_factory(execution={"max_model_retries": 0})
    client, http_client = _client(
        config,
        lambda _request: httpx.Response(200, json=_generation_payload()),
    )
    client.execution_evidence = ExecutionEvidenceKind.REAL
    expectation = GenerationReconciliationExpectation(
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        require_certification=False,
        usage_record=_usage_record(certification=False),
    )
    try:
        evidence = await client.get_generation_evidence(
            _GENERATION_ID,
            reconciliation_request=expectation,
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert evidence.generation_id == _GENERATION_ID


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

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
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
async def test_generation_reconciliation_polls_until_complete_native_pair_matches(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        payload["data"].update(
            {
                "tokens_prompt": 211,
                "tokens_completion": 19,
                "native_tokens_prompt": 256,
                "native_tokens_completion": None if calls == 1 else 29,
            }
        )
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    expectation = GenerationReconciliationExpectation(
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        require_certification=True,
        usage_record=_usage_record(prompt_tokens=256, completion_tokens=29),
    )
    try:
        evidence = await client.get_generation_evidence(
            _GENERATION_ID,
            reconciliation_request=expectation,
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert evidence.retrieval_attempts == 2
    assert calls == 2
    assert waits == [1.0]


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

    config = config_factory(
        execution={
            "request_timeout_seconds": 11,
            "max_model_retries": 0,
        }
    )
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
async def test_unmatched_token_pairs_exhaust_with_typed_final_evidence(
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    waits: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = _generation_payload()
        payload["data"].update(
            {
                "tokens_prompt": 211,
                "tokens_completion": 19,
                "native_tokens_prompt": 256,
                "native_tokens_completion": 28,
            }
        )
        return httpx.Response(200, json=payload)

    async def no_wait(delay_seconds: float) -> None:
        waits.append(delay_seconds)

    config = config_factory(
        execution={
            "request_timeout_seconds": 11,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    monkeypatch.setattr(client, "_wait_for_generation_metadata", no_wait)
    expectation = GenerationReconciliationExpectation(
        exact_model_id=_MODEL,
        canonical_model_id=_CANONICAL_MODEL,
        catalog_identity_binding_sha256=_catalog_identity_binding(),
        discovery_evidence_sha256=_DISCOVERY_EVIDENCE_SHA256,
        expected_provider_name=_PROVIDER_NAME,
        require_certification=True,
        usage_record=_usage_record(prompt_tokens=256, completion_tokens=29),
    )
    try:
        with pytest.raises(OpenRouterGenerationReconciliationError) as raised:
            await client.get_generation_evidence(
                _GENERATION_ID,
                reconciliation_request=expectation,
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert raised.value.mismatch_code is GenerationReconciliationMismatchCode.COMPLETION_TOKENS
    assert raised.value.attempts == 4
    assert raised.value.exhausted
    assert raised.value.last_evidence is not None
    assert raised.value.last_evidence.retrieval_attempts == 4
    assert calls == 4
    assert waits == [1.0, 3.0, 7.0]


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

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
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

    config = config_factory(
        execution={
            "request_timeout_seconds": 120,
            "max_model_retries": 0,
        }
    )
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
async def test_generation_attestation_set_is_bounded_concurrent_and_ordered(
    config_factory: Callable[..., Any],
) -> None:
    active_requests = 0
    maximum_active_requests = 0
    delays = {
        "gen-ordered-a": 0.04,
        "gen-ordered-b": 0.01,
        "gen-ordered-c": 0.02,
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_requests, maximum_active_requests
        if request.url.path.endswith("/key"):
            return httpx.Response(200, json={"data": {}})
        generation_id = request.url.params["id"]
        active_requests += 1
        maximum_active_requests = max(maximum_active_requests, active_requests)
        await asyncio.sleep(delays[generation_id])
        payload = _generation_payload()
        payload["data"]["id"] = generation_id
        payload["data"]["request_id"] = f"request-{generation_id}"
        active_requests -= 1
        return httpx.Response(200, json=payload)

    config = config_factory(
        execution={
            "concurrency": 2,
            "request_timeout_seconds": 1,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    generation_ids = tuple(delays)
    requests = tuple(
        _verification_request(generation_id, index=index)
        for index, generation_id in enumerate(generation_ids)
    )
    try:
        evidence = await OpenRouterClient._fetch_generation_attestations_with_deadline(
            client,
            requests,
            generation_ids,
        )
    finally:
        await client.close()
        await http_client.aclose()

    assert tuple(item.generation_id for item in evidence) == generation_ids
    assert maximum_active_requests == 2


@pytest.mark.asyncio
async def test_generation_attestation_set_deadline_includes_authentication(
    config_factory: Callable[..., Any],
) -> None:
    observed_paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        observed_paths.append(request.url.path)
        await asyncio.sleep(0.2)
        return httpx.Response(200, json={"data": {}})

    config = config_factory(
        execution={
            "request_timeout_seconds": 0.02,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    generation_ids = ("gen-auth-deadline",)
    requests = (_verification_request(generation_ids[0], index=0),)
    started = asyncio.get_running_loop().time()
    try:
        with pytest.raises(OpenRouterGenerationMetadataNotReadyError, match="deadline"):
            await OpenRouterClient._fetch_generation_attestations_with_deadline(
                client,
                requests,
                generation_ids,
            )
    finally:
        elapsed = asyncio.get_running_loop().time() - started
        await client.close()
        await http_client.aclose()

    assert observed_paths == ["/api/v1/key"]
    assert elapsed < 0.5


@pytest.mark.asyncio
async def test_generation_attestation_set_selects_failure_by_request_order(
    config_factory: Callable[..., Any],
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/key"):
            return httpx.Response(200, json={"data": {}})
        generation_id = request.url.params["id"]
        payload = _generation_payload()
        payload["data"]["id"] = generation_id
        payload["data"]["request_id"] = f"request-{generation_id}"
        if generation_id == "gen-failure-first":
            await asyncio.sleep(0.03)
            payload["data"]["provider_name"] = "Other Provider"
        else:
            payload["data"]["model"] = "other/unapproved-model"
        return httpx.Response(200, json=payload)

    config = config_factory(
        execution={
            "concurrency": 2,
            "request_timeout_seconds": 1,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    client.execution_evidence = ExecutionEvidenceKind.REAL
    generation_ids = ("gen-failure-first", "gen-failure-second")
    requests = tuple(
        _verification_request(generation_id, index=index)
        for index, generation_id in enumerate(generation_ids)
    )
    try:
        with pytest.raises(OpenRouterGenerationReconciliationError) as raised:
            await OpenRouterClient._fetch_generation_attestations_with_deadline(
                client,
                requests,
                generation_ids,
            )
    finally:
        await client.close()
        await http_client.aclose()

    assert raised.value.mismatch_code is GenerationReconciliationMismatchCode.PROVIDER


@pytest.mark.asyncio
async def test_generation_attestation_set_cancels_all_tasks_at_shared_deadline(
    config_factory: Callable[..., Any],
) -> None:
    active_requests = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_requests
        if request.url.path.endswith("/key"):
            return httpx.Response(200, json={"data": {}})
        active_requests += 1
        try:
            await asyncio.sleep(0.2)
        finally:
            active_requests -= 1
        payload = _generation_payload()
        payload["data"]["id"] = request.url.params["id"]
        return httpx.Response(200, json=payload)

    config = config_factory(
        execution={
            "concurrency": 2,
            "request_timeout_seconds": 0.02,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    generation_ids = ("gen-shared-deadline-a", "gen-shared-deadline-b")
    requests = tuple(
        _verification_request(generation_id, index=index)
        for index, generation_id in enumerate(generation_ids)
    )
    started = asyncio.get_running_loop().time()
    try:
        with pytest.raises(OpenRouterGenerationMetadataNotReadyError, match="deadline"):
            await OpenRouterClient._fetch_generation_attestations_with_deadline(
                client,
                requests,
                generation_ids,
            )
    finally:
        elapsed = asyncio.get_running_loop().time() - started
        await client.close()
        await http_client.aclose()

    assert active_requests == 0
    assert elapsed < 0.5


@pytest.mark.asyncio
async def test_generation_attestation_set_cleans_children_on_caller_cancellation(
    config_factory: Callable[..., Any],
) -> None:
    active_requests = 0
    both_started = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active_requests
        if request.url.path.endswith("/key"):
            return httpx.Response(200, json={"data": {}})
        active_requests += 1
        if active_requests == 2:
            both_started.set()
        try:
            await asyncio.sleep(10)
        finally:
            active_requests -= 1
        return httpx.Response(404)

    config = config_factory(
        execution={
            "concurrency": 2,
            "request_timeout_seconds": 1,
            "max_model_retries": 0,
        }
    )
    client, http_client = _client(config, handler)
    generation_ids = ("gen-cancel-a", "gen-cancel-b")
    requests = tuple(
        _verification_request(generation_id, index=index)
        for index, generation_id in enumerate(generation_ids)
    )
    operation = asyncio.create_task(
        OpenRouterClient._fetch_generation_attestations_with_deadline(
            client,
            requests,
            generation_ids,
        )
    )
    try:
        await asyncio.wait_for(both_started.wait(), timeout=0.2)
        operation.cancel()
        with pytest.raises(asyncio.CancelledError):
            await operation
    finally:
        await client.close()
        await http_client.aclose()

    assert active_requests == 0


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


@pytest.mark.asyncio
async def test_generation_verification_rejects_oversized_set_before_transport(
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
        with pytest.raises(OpenRouterRequestLimitError, match="request-set limit"):
            await client.create_trusted_generation_verification((request,) * 513)
    finally:
        await client.close()
        await http_client.aclose()

    assert observed == []


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
