from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record


def _creditable_record(
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK,
) -> UsageRecord:
    started_at = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
    ended_at = started_at + timedelta(milliseconds=125)
    generation_id = "generation-test"
    endpoint = "anthropic"
    schema_sha256 = "d" * 64
    return UsageRecord(
        request_id="request-test",
        role="source_audit",
        execution_evidence=execution_evidence,
        requested_model="author/exact-model",
        returned_model="author/exact-model",
        provider="Anthropic",
        model_family="author/exact-model",
        timestamp=started_at,
        prompt_tokens=100,
        completion_tokens=25,
        total_tokens=125,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing={
            "generation_id": generation_id,
            "selected_provider_endpoint": endpoint,
            "router_strategy": "direct",
            "router_attempt": 1,
            "router_attempt_count": 1,
            "router_pipeline": [],
            "finish_reason": "stop",
            "schema_sha256": schema_sha256,
            "router_metadata_sha256": "e" * 64,
            "provider_policy_sha256": "f" * 64,
            "provider_fallbacks_allowed": False,
            "certification_request": False,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "repair_used": False,
            "repair_request": False,
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": 125,
        },
        prompt_sha256="a" * 64,
        response_sha256="b" * 64,
        request_body_sha256="c" * 64,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[endpoint],
        actual_provider_endpoint=endpoint,
        started_at=started_at,
        ended_at=ended_at,
        latency_ms=125,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )


def test_creditable_usage_accepts_strict_mock_only_when_real_is_not_required() -> None:
    record = _creditable_record()

    assert is_creditable_usage_record(record)
    assert not is_creditable_usage_record(record, require_real=True)
    assert not is_creditable_usage_record(
        record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.UNVERIFIED})
    )
    assert is_creditable_usage_record(
        record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
        require_real=True,
    )
    assert not is_creditable_usage_record(
        record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
        require_real=True,
        require_certification=True,
    )


@pytest.mark.parametrize(
    ("updates", "routing_updates"),
    [
        ({"status": "failed"}, {}),
        ({"validation_status": ModelRequestValidationStatus.INVALID_RESPONSE}, {}),
        ({"returned_model": "author/substituted-model"}, {}),
        ({"substitution_detected": True}, {}),
        ({"provider_error_classification": "timeout"}, {}),
        ({"finish_reason": "length"}, {}),
        ({"openrouter_generation_id": "other-generation"}, {}),
        ({"response_sha256": None}, {}),
        ({"request_body_sha256": "not-a-hash"}, {}),
        ({"started_at": None}, {}),
        ({"timestamp": datetime(2026, 7, 27, 11, 59, tzinfo=UTC)}, {}),
        ({"prompt_tokens": 0}, {}),
        ({"completion_tokens": 0}, {}),
        ({"total_tokens": 124}, {}),
        ({"cached_tokens": 101}, {}),
        ({"reported_cost_usd": None}, {}),
        ({"accounted_cost_usd": 0.009}, {}),
        ({"actual_provider_endpoint": "unapproved"}, {}),
        ({}, {"generation_id": "other-generation"}),
        ({}, {"validation_status": "rejected"}),
        ({}, {"zdr_requested": False}),
        ({}, {"data_collection": "allow"}),
        ({}, {"repair_used": True}),
        ({}, {"repair_request": True}),
        ({}, {"router_metadata_sha256": None}),
    ],
)
def test_creditable_usage_rejects_incomplete_or_incoherent_evidence(
    updates: dict[str, Any],
    routing_updates: dict[str, Any],
) -> None:
    record = _creditable_record()
    if routing_updates:
        updates = {
            **updates,
            "routing": {
                **record.routing,
                **routing_updates,
            },
        }

    assert not is_creditable_usage_record(record.model_copy(update=updates))


def test_recorded_explicit_fallback_is_not_itself_a_model_substitution() -> None:
    record = _creditable_record().model_copy(update={"fallback_used": True})

    assert is_creditable_usage_record(record)


def test_certification_credit_requires_endpoint_snapshot_cost_and_no_fallback() -> None:
    record = _creditable_record()
    certified_routing = {
        **record.routing,
        "certification_request": True,
        "endpoint_snapshot_sha256": "1" * 64,
        "endpoint_pricing_sha256": "2" * 64,
    }

    certified = record.model_copy(
        update={
            "execution_evidence": ExecutionEvidenceKind.REAL,
            "routing": certified_routing,
        }
    )
    assert is_creditable_usage_record(certified)
    assert is_creditable_usage_record(
        certified,
        require_real=True,
        require_certification=True,
    )
    assert not is_creditable_usage_record(
        record.model_copy(
            update={
                "routing": {
                    **certified_routing,
                    "endpoint_snapshot_sha256": None,
                }
            }
        )
    )
    assert not is_creditable_usage_record(
        certified.model_copy(update={"fallback_used": True}),
        require_real=True,
        require_certification=True,
    )
    assert not is_creditable_usage_record(
        certified.model_copy(update={"configured_provider_endpoints": []}),
        require_real=True,
        require_certification=True,
    )
