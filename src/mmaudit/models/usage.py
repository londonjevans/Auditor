"""Thread-safe request usage collection."""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def candidate_falsifier_role_prefix(candidate_id: str) -> str:
    """Return the host-controlled role prefix binding a review to one candidate."""

    if not isinstance(candidate_id, str) or not candidate_id:
        raise ValueError("candidate falsifier role requires a non-empty candidate ID")
    candidate_sha256 = hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
    return f"candidate_falsifier:{candidate_sha256}"


def candidate_falsifier_role(candidate_id: str, reviewer_index: int) -> str:
    """Return the exact per-candidate role for one of two independent reviewers."""

    if reviewer_index not in {1, 2}:
        raise ValueError("candidate falsifier reviewer index must be one or two")
    return f"{candidate_falsifier_role_prefix(candidate_id)}:reviewer_{reviewer_index}"


def is_creditable_usage_record(
    record: UsageRecord,
    *,
    require_real: bool = False,
    require_certification: bool = False,
) -> bool:
    """Return whether one completed provider request has strict, coherent evidence."""

    if record.execution_evidence not in {
        ExecutionEvidenceKind.REAL,
        ExecutionEvidenceKind.MOCK,
    }:
        return False
    if require_real and record.execution_evidence is not ExecutionEvidenceKind.REAL:
        return False
    if (
        record.status != "success"
        or record.validation_status is not ModelRequestValidationStatus.VALID
        or record.returned_model != record.requested_model
        or record.substitution_detected
        or record.provider_error_classification is not None
        or record.finish_reason != "stop"
    ):
        return False
    required_strings = (
        record.request_id,
        record.role,
        record.requested_model,
        record.returned_model,
        record.actual_model,
        record.provider,
        record.actual_provider_endpoint,
        record.openrouter_generation_id,
    )
    if any(not isinstance(value, str) or not value.strip() for value in required_strings):
        return False
    if (
        record.started_at is None
        or record.ended_at is None
        or record.ended_at < record.started_at
        or record.timestamp != record.started_at
        or record.latency_ms is None
        or record.retry_count is None
        or record.retry_count != record.attempts - 1
    ):
        return False
    if not all(
        isinstance(value, str) and _SHA256.fullmatch(value) is not None
        for value in (
            record.prompt_sha256,
            record.response_sha256,
            record.validated_response_sha256,
            record.request_body_sha256,
            record.schema_sha256,
        )
    ):
        return False
    if (
        record.prompt_tokens <= 0
        or record.completion_tokens <= 0
        or record.total_tokens != record.prompt_tokens + record.completion_tokens
        or record.cached_tokens > record.prompt_tokens
    ):
        return False
    if (
        record.reported_cost_usd is None
        or not math.isfinite(record.reported_cost_usd)
        or not math.isfinite(record.accounted_cost_usd)
        or record.accounted_cost_usd + 1e-12 < record.reported_cost_usd
    ):
        return False
    actual_endpoint = record.actual_provider_endpoint
    if not isinstance(actual_endpoint, str):
        return False
    if record.configured_provider_endpoints and actual_endpoint.casefold() not in {
        endpoint.casefold() for endpoint in record.configured_provider_endpoints
    }:
        return False
    routing = record.routing
    base_valid = (
        routing.get("generation_id") == record.openrouter_generation_id
        and routing.get("selected_model") == record.actual_model
        and routing.get("selected_provider_endpoint") == actual_endpoint
        and routing.get("router_strategy") in {"direct", "fallback"}
        and routing.get("finish_reason") == record.finish_reason
        and routing.get("schema_sha256") == record.schema_sha256
        and _is_sha256(routing.get("router_metadata_sha256"))
        and _is_sha256(routing.get("provider_policy_sha256"))
        and routing.get("validation_status") == "valid"
        and routing.get("zdr_requested") is True
        and routing.get("data_collection") == "deny"
        and routing.get("repair_used") is False
        and routing.get("repair_request") is False
        and routing.get("request_started_at") == record.started_at.isoformat()
        and routing.get("request_ended_at") == record.ended_at.isoformat()
        and routing.get("latency_ms") == record.latency_ms
    )
    if not base_valid:
        return False
    certification_request = routing.get("certification_request") is True
    if require_certification and not certification_request:
        return False
    if not certification_request:
        return True
    canonical_model = routing.get("canonical_model")
    actual_model = record.actual_model
    expected_identity_hash = (
        hashlib.sha256(
            json.dumps(
                {
                    "canonical_slug": canonical_model,
                    "id": record.requested_model,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if isinstance(canonical_model, str)
        else None
    )
    return (
        not record.fallback_used
        and actual_model in {record.requested_model, canonical_model}
        and routing.get("catalog_identity_binding_sha256") == expected_identity_hash
        and len(record.configured_provider_endpoints) == 1
        and routing.get("provider_fallbacks_allowed") is False
        and routing.get("router_strategy") == "direct"
        and routing.get("router_attempt") == 1
        and routing.get("router_attempt_count") == 1
        and routing.get("router_pipeline") == []
        and _is_sha256(routing.get("endpoint_snapshot_sha256"))
        and _is_sha256(routing.get("endpoint_pricing_sha256"))
        and _is_sha256(routing.get("catalog_identity_binding_sha256"))
        and _is_sha256(routing.get("catalog_snapshot_sha256"))
        and _is_sha256(routing.get("discovery_provenance_sha256"))
        and _is_sha256(routing.get("discovery_evidence_sha256"))
    )


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


class UsageLedger:
    """Collect immutable request records without global state."""

    def __init__(self) -> None:
        self._records: list[UsageRecord] = []

    def add(self, record: UsageRecord) -> None:
        self._records.append(record)

    @property
    def records(self) -> list[UsageRecord]:
        return list(self._records)

    @property
    def accounted_cost_usd(self) -> float:
        return sum(record.accounted_cost_usd for record in self._records)

    def role_requests(self, role: str) -> int:
        return sum(1 for record in self._records if record.role == role)
