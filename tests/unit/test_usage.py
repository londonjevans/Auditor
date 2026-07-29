from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mmaudit.models.identity import OpenRouterIdentityBindingResult
from mmaudit.models.output_modes import StructuredOutputMode, supported_output_modes
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.privacy import EndpointPolicyClass, PrivacyProfile, PrivacySourceClassification
from tests.identity_fixtures import bind_synthetic_usage_identity
from tests.output_evidence_fixtures import (
    SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
    synthetic_structured_output_routing,
)

_REQUESTED_MODEL = "author/exact-model"
_CANONICAL_MODEL = "author/exact-model-20260727"
_CATALOG_IDENTITY_BINDING_SHA256 = hashlib.sha256(
    json.dumps(
        {
            "canonical_slug": _CANONICAL_MODEL,
            "id": _REQUESTED_MODEL,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()


def _creditable_record(
    *,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK,
) -> UsageRecord:
    started_at = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
    ended_at = started_at + timedelta(milliseconds=125)
    generation_id = "generation-test"
    endpoint = "anthropic"
    schema_sha256 = "d" * 64
    prompt_sha256 = "a" * 64
    response_sha256 = "b" * 64
    validated_response_sha256 = "d" * 64
    request_body_sha256 = "c" * 64
    provider_policy_sha256 = "f" * 64
    endpoint_snapshot_sha256 = "9" * 64
    return UsageRecord(
        request_id="request-test",
        role="source_audit",
        execution_evidence=execution_evidence,
        requested_model=_REQUESTED_MODEL,
        returned_model=_REQUESTED_MODEL,
        actual_model=_CANONICAL_MODEL,
        provider="Anthropic",
        model_family=_REQUESTED_MODEL,
        timestamp=started_at,
        prompt_tokens=100,
        completion_tokens=25,
        total_tokens=125,
        reported_cost_usd=0.01,
        accounted_cost_usd=0.01,
        routing={
            "generation_id": generation_id,
            "selected_model": _CANONICAL_MODEL,
            "canonical_model": _CANONICAL_MODEL,
            "selected_provider_endpoint": endpoint,
            "router_strategy": "direct",
            "router_attempt": 1,
            "router_attempt_count": 1,
            "router_pipeline": [],
            "finish_reason": "stop",
            "schema_sha256": schema_sha256,
            "router_metadata_sha256": "e" * 64,
            "provider_policy_sha256": provider_policy_sha256,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "output_capability_sha256": SYNTHETIC_OUTPUT_CAPABILITY_SHA256,
            "provider_fallbacks_allowed": False,
            "certification_request": False,
            "validation_status": "valid",
            "zdr_requested": True,
            "data_collection": "deny",
            "privacy_profile": PrivacyProfile.STRICT_ZDR.value,
            "privacy_authorization": "STRICT_ZDR_ENFORCED",
            "effective_privacy_policy_sha256": "1" * 64,
            "privacy_source_sha256": "2" * 64,
            "privacy_source_provenance_sha256": "3" * 64,
            "privacy_source_classification": (
                PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
            ),
            "privacy_consent_file_sha256": None,
            "privacy_consent_sha256": None,
            "privacy_consent_expires_at": None,
            "privacy_endpoint_policy_class": EndpointPolicyClass.ZDR.value,
            "repair_used": False,
            "repair_request": False,
            "structured_output": synthetic_structured_output_routing(
                configured_provider_endpoints=(endpoint,),
                selected_provider_endpoint=endpoint,
                endpoint_snapshot_sha256=endpoint_snapshot_sha256,
                prompt_sha256=prompt_sha256,
                request_body_sha256=request_body_sha256,
                provider_policy_sha256=provider_policy_sha256,
                schema_sha256=schema_sha256,
                original_response_sha256=response_sha256,
                validated_response_sha256=validated_response_sha256,
            ),
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": 125,
        },
        prompt_sha256=prompt_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256=request_body_sha256,
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
    assert not is_creditable_usage_record(
        record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
        require_real=True,
    )
    assert not is_creditable_usage_record(
        record.model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL}),
        require_real=True,
        require_certification=True,
    )


def _consent_bound_non_zdr_record() -> UsageRecord:
    record = _creditable_record()
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "zdr_requested": False,
                "privacy_profile": (PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT.value),
                "privacy_authorization": "CONSENT_BOUND_NON_ZDR",
                "effective_privacy_policy_sha256": "1" * 64,
                "privacy_source_sha256": "2" * 64,
                "privacy_source_provenance_sha256": "5" * 64,
                "privacy_source_classification": (
                    PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
                ),
                "privacy_consent_file_sha256": "3" * 64,
                "privacy_consent_sha256": "4" * 64,
                "privacy_consent_expires_at": "2099-01-01T00:00:00+00:00",
                "privacy_endpoint_policy_class": (
                    EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED.value
                ),
            }
        }
    )


def test_creditable_usage_accepts_complete_consent_bound_non_zdr_evidence() -> None:
    assert is_creditable_usage_record(_consent_bound_non_zdr_record())


def test_consent_bound_usage_rejects_profile_source_classification_mismatch() -> None:
    frontier = _consent_bound_non_zdr_record()
    assert is_creditable_usage_record(frontier)
    for source_classification in (
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
        PrivacySourceClassification.PUBLIC_BENCHMARK,
    ):
        assert not is_creditable_usage_record(
            frontier.model_copy(
                update={
                    "routing": {
                        **frontier.routing,
                        "privacy_source_classification": source_classification.value,
                    }
                }
            )
        )

    synthetic = frontier.model_copy(
        update={
            "routing": {
                **frontier.routing,
                "privacy_profile": PrivacyProfile.SYNTHETIC_BENCHMARK.value,
                "privacy_source_classification": (
                    PrivacySourceClassification.SYNTHETIC_COMMITTED.value
                ),
            }
        }
    )
    assert is_creditable_usage_record(synthetic)
    assert not is_creditable_usage_record(
        synthetic.model_copy(
            update={
                "routing": {
                    **synthetic.routing,
                    "privacy_source_classification": (
                        PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
                    ),
                }
            }
        )
    )


@pytest.mark.parametrize(
    "field",
    [
        "effective_privacy_policy_sha256",
        "privacy_source_sha256",
        "privacy_source_provenance_sha256",
        "privacy_consent_file_sha256",
        "privacy_consent_sha256",
    ],
)
def test_consent_bound_non_zdr_credit_rejects_missing_privacy_hash(field: str) -> None:
    record = _consent_bound_non_zdr_record()
    routing = dict(record.routing)
    routing.pop(field)

    assert not is_creditable_usage_record(record.model_copy(update={"routing": routing}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("effective_privacy_policy_sha256", "g" * 64),
        ("privacy_source_sha256", "2" * 63),
        ("privacy_source_provenance_sha256", "not-a-sha256"),
        ("privacy_consent_file_sha256", "not-a-sha256"),
        ("privacy_consent_sha256", ""),
    ],
)
def test_consent_bound_non_zdr_credit_rejects_malformed_privacy_hash(
    field: str,
    value: str,
) -> None:
    record = _consent_bound_non_zdr_record()

    assert not is_creditable_usage_record(
        record.model_copy(
            update={
                "routing": {
                    **record.routing,
                    field: value,
                }
            }
        )
    )


@pytest.mark.parametrize(
    "expires_at",
    [
        "",
        "not-a-timestamp",
        "2026-07-27T11:59:59+00:00",
        "2026-07-27T12:00:00",
    ],
)
def test_consent_bound_non_zdr_credit_rejects_invalid_or_expired_consent(
    expires_at: str,
) -> None:
    record = _consent_bound_non_zdr_record()

    assert not is_creditable_usage_record(
        record.model_copy(
            update={
                "routing": {
                    **record.routing,
                    "privacy_consent_expires_at": expires_at,
                }
            }
        )
    )


def test_consent_free_synthetic_zdr_usage_is_creditable() -> None:
    record = _creditable_record()
    synthetic = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "privacy_profile": PrivacyProfile.SYNTHETIC_BENCHMARK.value,
                "privacy_authorization": "STRICT_ZDR_ENFORCED",
                "effective_privacy_policy_sha256": "1" * 64,
                "privacy_source_sha256": "2" * 64,
                "privacy_source_provenance_sha256": "3" * 64,
                "privacy_source_classification": (
                    PrivacySourceClassification.SYNTHETIC_COMMITTED.value
                ),
                "privacy_endpoint_policy_class": EndpointPolicyClass.ZDR.value,
                "privacy_consent_file_sha256": None,
                "privacy_consent_sha256": None,
                "privacy_consent_expires_at": None,
            }
        }
    )

    assert is_creditable_usage_record(synthetic)
    assert not is_creditable_usage_record(
        synthetic.model_copy(
            update={
                "routing": {
                    **synthetic.routing,
                    "privacy_source_provenance_sha256": None,
                }
            }
        )
    )


def test_profileless_legacy_usage_is_not_creditable() -> None:
    record = _creditable_record()
    routing = {
        key: value
        for key, value in record.routing.items()
        if key
        not in {
            "privacy_profile",
            "privacy_authorization",
            "effective_privacy_policy_sha256",
            "privacy_source_sha256",
            "privacy_source_provenance_sha256",
            "privacy_source_classification",
            "privacy_consent_file_sha256",
            "privacy_consent_sha256",
            "privacy_consent_expires_at",
            "privacy_endpoint_policy_class",
        }
    }
    legacy = record.model_copy(update={"routing": routing})

    assert "privacy_profile" not in legacy.routing
    assert not is_creditable_usage_record(legacy)
    assert not is_creditable_usage_record(
        legacy.model_copy(
            update={
                "routing": {
                    **legacy.routing,
                    "zdr_requested": False,
                }
            }
        )
    )


def test_real_credit_rejects_self_hashed_unbound_cross_author_alias() -> None:
    provisional = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "routing": {
                    **provisional.routing,
                    "selected_provider_name": provisional.provider,
                }
            }
        )
    )
    assert is_creditable_usage_record(record, require_real=True)

    unrelated_model = "bravo/unrelated-model"
    payload = record.model_dump(mode="json")
    routing = payload["routing"]
    binding = routing["identity_binding"]
    snapshot = binding["snapshot"]
    snapshot["frozen_aliases"] = sorted({*snapshot["frozen_aliases"], unrelated_model})
    snapshot["snapshot_sha256"] = _canonical_json_sha256(
        {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
    )
    binding["request"]["returned_slug"] = unrelated_model
    binding["request"]["selected_model_slug"] = unrelated_model
    binding["generation"]["generation_model_slug"] = unrelated_model
    binding["binding_sha256"] = _canonical_json_sha256(
        {key: value for key, value in binding.items() if key != "binding_sha256"}
    )
    routing.update(
        {
            "accepted_model_aliases": sorted({*routing["accepted_model_aliases"], unrelated_model}),
            "selected_model": unrelated_model,
            "identity_binding": binding,
            "identity_binding_sha256": binding["binding_sha256"],
            "identity_snapshot_sha256": snapshot["snapshot_sha256"],
        }
    )
    forged = UsageRecord.model_validate(
        {
            **payload,
            "returned_model": unrelated_model,
            "actual_model": unrelated_model,
            "routing": routing,
        }
    )

    assert not is_creditable_usage_record(forged, require_real=True)


def test_real_credit_rejects_rewritten_same_author_canonical_identity() -> None:
    provisional = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "routing": {
                    **provisional.routing,
                    "selected_provider_name": provisional.provider,
                }
            }
        )
    )
    assert is_creditable_usage_record(record, require_real=True)

    rewritten_canonical = "author/unrelated-model"
    routing = dict(record.routing)
    binding = dict(routing["identity_binding"])
    snapshot = dict(binding["snapshot"])
    snapshot.update(
        {
            "canonical_slug": rewritten_canonical,
            "frozen_aliases": sorted({record.requested_model, rewritten_canonical}),
            "catalog_identity_binding_sha256": _canonical_json_sha256(
                {
                    "canonical_slug": rewritten_canonical,
                    "id": record.requested_model,
                }
            ),
        }
    )
    snapshot["snapshot_sha256"] = _canonical_json_sha256(
        {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
    )
    binding["snapshot"] = snapshot
    binding["request"] = {
        **binding["request"],
        "returned_slug": rewritten_canonical,
        "selected_model_slug": rewritten_canonical,
    }
    binding["generation"] = {
        **binding["generation"],
        "generation_model_slug": rewritten_canonical,
    }
    binding["binding_sha256"] = _canonical_json_sha256(
        {key: value for key, value in binding.items() if key != "binding_sha256"}
    )
    assert OpenRouterIdentityBindingResult.model_validate(binding)
    routing.update(
        {
            "accepted_model_aliases": sorted({record.requested_model, rewritten_canonical}),
            "canonical_model": rewritten_canonical,
            "selected_model": rewritten_canonical,
            "catalog_identity_binding_sha256": snapshot["catalog_identity_binding_sha256"],
            "identity_snapshot_sha256": snapshot["snapshot_sha256"],
            "identity_binding": binding,
            "identity_binding_sha256": binding["binding_sha256"],
        }
    )
    forged = record.model_copy(
        update={
            "returned_model": rewritten_canonical,
            "actual_model": rewritten_canonical,
            "routing": routing,
        }
    )

    assert not is_creditable_usage_record(forged, require_real=True)


def test_serialized_real_usage_cannot_reconstruct_runtime_provenance() -> None:
    provisional = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "routing": {
                    **provisional.routing,
                    "selected_provider_name": provisional.provider,
                }
            }
        )
    )
    reloaded = UsageRecord.model_validate(record.model_dump(mode="json"))

    assert is_creditable_usage_record(record, require_real=True)
    assert not is_creditable_usage_record(reloaded, require_real=True)
    object.__setattr__(
        reloaded,
        "_runtime_execution_attestation",
        (object(), hashlib.sha256(reloaded.model_dump_json().encode()).hexdigest()),
    )
    assert not is_creditable_usage_record(reloaded, require_real=True)


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
        ({"validated_response_sha256": None}, {}),
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


def test_creditable_usage_requires_self_hashed_structured_output_evidence() -> None:
    record = _creditable_record()
    without_evidence = {
        key: value for key, value in record.routing.items() if key != "structured_output"
    }
    assert not is_creditable_usage_record(record.model_copy(update={"routing": without_evidence}))

    tampered = dict(record.routing["structured_output"])
    tampered["output_capability_sha256"] = "0" * 64
    assert not is_creditable_usage_record(
        record.model_copy(
            update={
                "routing": {
                    **record.routing,
                    "structured_output": tampered,
                }
            }
        )
    )


def test_creditable_usage_rejects_output_evidence_bound_to_other_request() -> None:
    record = _creditable_record()
    mismatched = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(record.configured_provider_endpoints),
        selected_provider_endpoint=record.actual_provider_endpoint or "",
        endpoint_snapshot_sha256=record.routing["endpoint_snapshot_sha256"],
        prompt_sha256=record.prompt_sha256,
        request_body_sha256="0" * 64,
        provider_policy_sha256=record.routing["provider_policy_sha256"],
        schema_sha256=record.schema_sha256 or "",
        original_response_sha256=record.response_sha256 or "",
        validated_response_sha256=record.validated_response_sha256 or "",
    )

    assert not is_creditable_usage_record(
        record.model_copy(
            update={
                "routing": {
                    **record.routing,
                    "structured_output": mismatched,
                }
            }
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("structured_output_mode", StructuredOutputMode.VALIDATED_TEXT_JSON.value),
        ("structured_output_request_shape_sha256", "0" * 64),
        ("structured_output_require_parameters", False),
        ("structured_output_required_provider_parameters", []),
        ("structured_output_response_format", None),
        ("structured_output_protocol_sha256", "0" * 64),
        ("structured_output_supported_modes", ["NATIVE_JSON_SCHEMA"]),
        ("structured_output_capability_sha256", "1" * 64),
        ("structured_output_request_body_sha256", "2" * 64),
        ("structured_output_original_response_sha256", "3" * 64),
        ("structured_output_validated_response_sha256", "4" * 64),
    ],
)
def test_credit_rejects_structured_request_shape_routing_drift(
    field: str,
    value: object,
) -> None:
    record = _creditable_record()
    structured = record.routing["structured_output"]
    coherent_routing = {
        **record.routing,
        "structured_output_mode": structured["requested_mode"],
        "structured_output_request_shape_sha256": structured["request_shape_sha256"],
        "structured_output_require_parameters": structured["provider_require_parameters"],
        "structured_output_required_provider_parameters": structured[
            "required_provider_parameters"
        ],
        "structured_output_reasoning_request_sha256": structured["reasoning_request_sha256"],
        "structured_output_response_format": structured["response_format"],
        "structured_output_protocol_sha256": structured["strict_protocol_sha256"],
        "structured_output_supported_modes": [
            mode.value
            for mode in supported_output_modes(structured["endpoint_structured_output_parameters"])
        ],
        "structured_output_capability_sha256": structured["output_capability_sha256"],
        "structured_output_request_body_sha256": structured["request_body_sha256"],
        "structured_output_original_response_sha256": structured["original_response_sha256"],
        "structured_output_validated_response_sha256": structured["validated_response_sha256"],
    }
    coherent = record.model_copy(update={"routing": coherent_routing})
    assert is_creditable_usage_record(coherent)

    assert not is_creditable_usage_record(
        coherent.model_copy(update={"routing": {**coherent.routing, field: value}})
    )


def test_real_credit_binds_text_reasoning_require_parameters_to_identity() -> None:
    provisional = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    text_reasoning = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(provisional.configured_provider_endpoints),
        selected_provider_endpoint=provisional.actual_provider_endpoint or "",
        endpoint_snapshot_sha256=provisional.routing["endpoint_snapshot_sha256"],
        prompt_sha256=provisional.prompt_sha256,
        request_body_sha256=provisional.request_body_sha256 or "",
        provider_policy_sha256=provisional.routing["provider_policy_sha256"],
        schema_sha256=provisional.schema_sha256 or "",
        original_response_sha256=provisional.response_sha256 or "",
        validated_response_sha256=provisional.validated_response_sha256 or "",
        mode=StructuredOutputMode.VALIDATED_TEXT_JSON,
        reasoning_requested=True,
    )
    with_reasoning = provisional.model_copy(
        update={
            "routing": {
                **provisional.routing,
                "selected_provider_name": provisional.provider,
                "structured_output": text_reasoning,
            }
        }
    )
    bound = bind_synthetic_usage_identity(with_reasoning)
    assert is_creditable_usage_record(bound, require_real=True)

    without_reasoning = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(bound.configured_provider_endpoints),
        selected_provider_endpoint=bound.actual_provider_endpoint or "",
        endpoint_snapshot_sha256=bound.routing["endpoint_snapshot_sha256"],
        prompt_sha256=bound.prompt_sha256,
        request_body_sha256=bound.request_body_sha256 or "",
        provider_policy_sha256=bound.routing["provider_policy_sha256"],
        schema_sha256=bound.schema_sha256 or "",
        original_response_sha256=bound.response_sha256 or "",
        validated_response_sha256=bound.validated_response_sha256 or "",
        mode=StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    assert not is_creditable_usage_record(
        bound.model_copy(
            update={
                "routing": {
                    **bound.routing,
                    "structured_output": without_reasoning,
                }
            }
        ),
        require_real=True,
    )


def test_real_credit_rejects_mode_different_from_bound_endpoint_capability() -> None:
    provisional = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "routing": {
                    **provisional.routing,
                    "selected_provider_name": provisional.provider,
                }
            }
        )
    )
    text_evidence = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(record.configured_provider_endpoints),
        selected_provider_endpoint=record.actual_provider_endpoint or "",
        endpoint_snapshot_sha256=record.routing["endpoint_snapshot_sha256"],
        prompt_sha256=record.prompt_sha256,
        request_body_sha256=record.request_body_sha256 or "",
        provider_policy_sha256=record.routing["provider_policy_sha256"],
        schema_sha256=record.schema_sha256 or "",
        original_response_sha256=record.response_sha256 or "",
        validated_response_sha256=record.validated_response_sha256 or "",
        mode=StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    record = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "structured_output": text_evidence,
            }
        }
    )

    assert not is_creditable_usage_record(record, require_real=True)


def test_native_mode_credit_accepts_full_bound_endpoint_capability_inventory() -> None:
    provisional = _creditable_record()
    native_evidence = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(provisional.configured_provider_endpoints),
        selected_provider_endpoint=provisional.actual_provider_endpoint or "",
        endpoint_snapshot_sha256=provisional.routing["endpoint_snapshot_sha256"],
        prompt_sha256=provisional.prompt_sha256,
        request_body_sha256=provisional.request_body_sha256 or "",
        provider_policy_sha256=provisional.routing["provider_policy_sha256"],
        schema_sha256=provisional.schema_sha256 or "",
        original_response_sha256=provisional.response_sha256 or "",
        validated_response_sha256=provisional.validated_response_sha256 or "",
        mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
    )
    provisional = provisional.model_copy(
        update={
            "routing": {
                **provisional.routing,
                "structured_output": native_evidence,
            }
        }
    )
    record = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "routing": {
                    **provisional.routing,
                    "selected_provider_name": provisional.provider,
                }
            }
        ),
        endpoint_supported_parameters=(
            "json_schema",
            "max_tokens",
            "response_format",
            "structured_outputs",
            "temperature",
        ),
        model_supported_parameters=(
            "json_schema",
            "max_tokens",
            "response_format",
            "structured_outputs",
            "temperature",
        ),
    )

    assert is_creditable_usage_record(record)


def test_json_object_credit_accepts_model_endpoint_common_mode_downgrade() -> None:
    provisional = _creditable_record()
    record = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "routing": {
                    **provisional.routing,
                    "selected_provider_name": provisional.provider,
                }
            }
        ),
        endpoint_supported_parameters=(
            "json_schema",
            "max_tokens",
            "response_format",
            "structured_outputs",
            "temperature",
        ),
        model_supported_parameters=(
            "max_tokens",
            "response_format",
            "temperature",
        ),
    )

    assert is_creditable_usage_record(record)
    binding = OpenRouterIdentityBindingResult.model_validate(record.routing["identity_binding"])
    assert (
        binding.snapshot.endpoint_capabilities.structured_output_mode
        is StructuredOutputMode.JSON_OBJECT
    )
    assert set(
        record.routing["structured_output"]["endpoint_structured_output_parameters"]
    ).issubset(binding.snapshot.endpoint_capabilities.structured_output_parameters)


def test_credit_rejects_capability_hash_different_from_bound_identity() -> None:
    provisional = _creditable_record()
    record = bind_synthetic_usage_identity(
        provisional.model_copy(
            update={
                "routing": {
                    **provisional.routing,
                    "selected_provider_name": provisional.provider,
                }
            }
        )
    )
    mismatched = synthetic_structured_output_routing(
        configured_provider_endpoints=tuple(record.configured_provider_endpoints),
        selected_provider_endpoint=record.actual_provider_endpoint or "",
        endpoint_snapshot_sha256=record.routing["endpoint_snapshot_sha256"],
        output_capability_sha256="0" * 64,
        prompt_sha256=record.prompt_sha256,
        request_body_sha256=record.request_body_sha256 or "",
        provider_policy_sha256=record.routing["provider_policy_sha256"],
        schema_sha256=record.schema_sha256 or "",
        original_response_sha256=record.response_sha256 or "",
        validated_response_sha256=record.validated_response_sha256 or "",
    )
    record = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "output_capability_sha256": "0" * 64,
                "structured_output": mismatched,
            }
        }
    )

    assert not is_creditable_usage_record(record)


def test_recorded_explicit_fallback_is_not_itself_a_model_substitution() -> None:
    record = _creditable_record().model_copy(update={"fallback_used": True})

    assert is_creditable_usage_record(record)


def _canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def test_unbound_certification_never_receives_credit_from_exact_slug_or_endpoint_hashes() -> None:
    record = _creditable_record()
    certified_routing = {
        **record.routing,
        "certification_request": True,
        "endpoint_snapshot_sha256": "1" * 64,
        "endpoint_pricing_sha256": "2" * 64,
        "catalog_identity_binding_sha256": _CATALOG_IDENTITY_BINDING_SHA256,
        "catalog_snapshot_sha256": "3" * 64,
        "discovery_provenance_sha256": "4" * 64,
        "discovery_evidence_sha256": "5" * 64,
    }

    certified = record.model_copy(
        update={
            "execution_evidence": ExecutionEvidenceKind.REAL,
            "routing": certified_routing,
        }
    )
    assert not is_creditable_usage_record(certified)
    assert not is_creditable_usage_record(
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


def test_creditable_usage_rejects_actual_model_or_catalog_identity_mismatch() -> None:
    record = _creditable_record()
    certified = record.model_copy(
        update={
            "execution_evidence": ExecutionEvidenceKind.REAL,
            "routing": {
                **record.routing,
                "certification_request": True,
                "endpoint_snapshot_sha256": "1" * 64,
                "endpoint_pricing_sha256": "2" * 64,
                "catalog_identity_binding_sha256": _CATALOG_IDENTITY_BINDING_SHA256,
                "catalog_snapshot_sha256": "3" * 64,
                "discovery_provenance_sha256": "4" * 64,
                "discovery_evidence_sha256": "5" * 64,
            },
        }
    )

    assert not is_creditable_usage_record(
        certified.model_copy(update={"actual_model": "author/other-model"}),
        require_real=True,
        require_certification=True,
    )
    assert not is_creditable_usage_record(
        certified.model_copy(
            update={
                "actual_model": "author/other-model",
                "routing": {
                    **certified.routing,
                    "selected_model": "author/other-model",
                },
            }
        ),
        require_real=True,
        require_certification=True,
    )
    assert not is_creditable_usage_record(
        certified.model_copy(
            update={
                "routing": {
                    **certified.routing,
                    "selected_model": _REQUESTED_MODEL,
                }
            }
        ),
        require_real=True,
        require_certification=True,
    )
    assert not is_creditable_usage_record(
        certified.model_copy(
            update={
                "routing": {
                    **certified.routing,
                    "catalog_identity_binding_sha256": None,
                }
            }
        ),
        require_real=True,
        require_certification=True,
    )
