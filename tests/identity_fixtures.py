"""Test-only builders for internally coherent synthetic identity evidence.

These helpers never perform provider I/O and must not be treated as REAL integration
evidence. They exist so unit tests can exercise production validators without
weakening the rule that serialized REAL usage requires a complete identity binding.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from mmaudit.models.identity import (
    OpenRouterGenerationIdentityEvidence,
    OpenRouterIdentityEndpointCapabilities,
    OpenRouterIdentityPricingEntry,
    OpenRouterRequestIdentityEvidence,
    seal_bound_openrouter_identity,
    seal_openrouter_identity_provider_policy,
    seal_openrouter_model_endpoint_identity_snapshot,
)
from mmaudit.models.schemas import ModelIdentityStrength, UsageRecord
from mmaudit.models.usage import _attest_owned_real_usage_record


def bind_synthetic_usage_identity(record: UsageRecord) -> UsageRecord:
    """Return a self-consistent test record with explicitly synthetic binding data."""

    if (
        record.returned_model is None
        or record.actual_model is None
        or record.actual_provider_endpoint is None
        or record.openrouter_generation_id is None
        or record.request_body_sha256 is None
        or record.response_sha256 is None
        or record.validated_response_sha256 is None
        or record.started_at is None
        or record.ended_at is None
    ):
        raise ValueError("synthetic identity fixture requires complete usage evidence")
    routing = dict(record.routing)
    provider_fallback_used = routing.get("provider_fallback_used")
    host_model_fallback_used = routing.get("host_model_fallback_used")
    if not isinstance(provider_fallback_used, bool):
        provider_fallback_used = record.fallback_used
    if not isinstance(host_model_fallback_used, bool):
        host_model_fallback_used = False
    if record.fallback_used != (provider_fallback_used or host_model_fallback_used):
        raise ValueError("synthetic identity fixture has incoherent fallback evidence")
    routing.update(
        {
            "host_model_fallback_used": host_model_fallback_used,
            "provider_fallback_used": provider_fallback_used,
        }
    )
    canonical_slug = routing.get("canonical_model")
    provider_name = routing.get("selected_provider_name")
    if not isinstance(canonical_slug, str) or not isinstance(provider_name, str):
        raise ValueError("synthetic identity fixture requires canonical route evidence")
    aliases = tuple(
        sorted(
            {
                record.requested_model,
                record.returned_model,
                record.actual_model,
                canonical_slug,
            }
        )
    )
    started_at = _utc_second(record.started_at)
    completed_at = _utc_second(record.ended_at)
    retrieved_at = started_at - timedelta(seconds=1)
    generation_retrieved_at = completed_at + timedelta(seconds=1)
    evaluated_at = generation_retrieved_at + timedelta(seconds=1)
    endpoint_snapshot_sha256 = _hash_or_default(
        routing.get("endpoint_snapshot_sha256"),
        "synthetic endpoint snapshot",
    )
    pricing_snapshot_sha256 = _hash_or_default(
        routing.get("endpoint_pricing_sha256"),
        "synthetic pricing snapshot",
    )
    catalog_snapshot_sha256 = _hash_or_default(
        routing.get("catalog_snapshot_sha256"),
        "synthetic catalog snapshot",
    )
    model_metadata_snapshot_sha256 = _hash_or_default(
        routing.get("model_metadata_snapshot_sha256"),
        "synthetic model metadata snapshot",
    )
    discovery_provenance_sha256 = _hash_or_default(
        routing.get("discovery_provenance_sha256"),
        "synthetic discovery provenance",
    )
    discovery_evidence_sha256 = _hash_or_default(
        routing.get("discovery_evidence_sha256"),
        "synthetic discovery evidence",
    )
    catalog_identity_binding_sha256 = _catalog_identity_binding(
        requested_slug=record.requested_model,
        canonical_slug=canonical_slug,
    )
    routing.update(
        {
            "catalog_identity_binding_sha256": catalog_identity_binding_sha256,
            "catalog_snapshot_sha256": catalog_snapshot_sha256,
            "model_metadata_snapshot_sha256": model_metadata_snapshot_sha256,
            "discovery_provenance_sha256": discovery_provenance_sha256,
            "discovery_evidence_sha256": discovery_evidence_sha256,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "endpoint_pricing_sha256": pricing_snapshot_sha256,
        }
    )
    policy = seal_openrouter_identity_provider_policy(
        mode="only",
        configured_endpoints=(record.actual_provider_endpoint,),
        allow_fallbacks=False,
        zdr_required=True,
    )
    capabilities = OpenRouterIdentityEndpointCapabilities(
        operational=True,
        context_tokens=200_000,
        output_tokens=20_000,
        supported_parameters=("max_tokens", "response_format", "temperature"),
        required_parameters=("max_tokens", "response_format", "temperature"),
        structured_output_parameters=("response_format",),
        reasoning_parameters=(),
        structured_output_supported=True,
        reasoning_supported=False,
        zdr_eligible=True,
        data_collection_deny_eligible=True,
    )
    snapshot = seal_openrouter_model_endpoint_identity_snapshot(
        requested_slug=record.requested_model,
        canonical_slug=canonical_slug,
        frozen_aliases=aliases,
        model_author=canonical_slug.split("/", 1)[0],
        model_context_tokens=200_000,
        model_output_tokens=20_000,
        model_supported_parameters=("max_tokens", "response_format", "temperature"),
        approved_provider_endpoint=record.actual_provider_endpoint,
        endpoint_tag=record.actual_provider_endpoint,
        endpoint_slug=None,
        provider_name=provider_name,
        provider_policy=policy,
        endpoint_capabilities=capabilities,
        pricing=(
            OpenRouterIdentityPricingEntry(
                unit="completion",
                usd_per_unit="0.00001",
            ),
            OpenRouterIdentityPricingEntry(
                unit="prompt",
                usd_per_unit="0.000001",
            ),
        ),
        canonical_slug_mutable=True,
        immutable_provider_version=None,
        immutable_provider_version_evidence_sha256=None,
        retrieved_at=retrieved_at,
        expires_at=evaluated_at + timedelta(days=30),
        catalog_identity_binding_sha256=catalog_identity_binding_sha256,
        catalog_snapshot_sha256=catalog_snapshot_sha256,
        model_metadata_snapshot_sha256=model_metadata_snapshot_sha256,
        discovery_provenance_sha256=discovery_provenance_sha256,
        discovery_evidence_sha256=discovery_evidence_sha256,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        pricing_snapshot_sha256=pricing_snapshot_sha256,
    )
    request = OpenRouterRequestIdentityEvidence(
        internal_request_id=record.request_id,
        execution_evidence=record.execution_evidence.value,
        requested_slug=record.requested_model,
        returned_slug=record.returned_model,
        selected_model_slug=record.actual_model,
        actual_provider_endpoint=record.actual_provider_endpoint,
        actual_provider_name=provider_name,
        openrouter_generation_id=record.openrouter_generation_id,
        request_body_sha256=record.request_body_sha256,
        response_sha256=record.response_sha256,
        validated_response_sha256=record.validated_response_sha256,
        started_at=started_at,
        completed_at=completed_at,
        fallback_used=provider_fallback_used,
    )
    generation = OpenRouterGenerationIdentityEvidence(
        generation_id=record.openrouter_generation_id,
        execution_evidence=record.execution_evidence.value,
        generation_model_slug=record.actual_model,
        provider_name=provider_name,
        provider_version_id=None,
        provider_request_id=None,
        retrieved_at=generation_retrieved_at,
        generation_evidence_sha256=_stable_sha256(
            {
                "fixture": "synthetic generation identity",
                "generation_id": record.openrouter_generation_id,
                "request_id": record.request_id,
            }
        ),
    )
    binding = seal_bound_openrouter_identity(
        snapshot=snapshot,
        request=request,
        generation=generation,
        evaluated_at=evaluated_at,
    )
    routing.update(
        {
            "accepted_model_aliases": list(aliases),
            "identity_snapshot_sha256": snapshot.snapshot_sha256,
            "provisional_identity_strength": (
                ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND.value
            ),
            "identity_binding": binding.model_dump(mode="json"),
            "identity_binding_sha256": binding.binding_sha256,
            "identity_binding_status": "generation_metadata_bound",
        }
    )
    bound_record = UsageRecord.model_validate(
        {
            **record.model_dump(mode="json"),
            "routing": routing,
            "identity_strength": binding.strength,
        }
    )
    if bound_record.execution_evidence.value == "real":
        # This is an explicit unit-test capability only. Serialized synthetic
        # evidence still loses runtime provenance and cannot earn REAL credit.
        bound_record = _attest_owned_real_usage_record(bound_record)
    return bound_record


def reattest_synthetic_real_usage(record: UsageRecord) -> UsageRecord:
    """Refresh a deliberately mutated unit-test record without provider evidence."""

    if record.execution_evidence.value != "real":
        return record
    return _attest_owned_real_usage_record(record)


def _utc_second(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("synthetic identity timestamp must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _hash_or_default(value: object, label: str) -> str:
    if isinstance(value, str) and len(value) == 64:
        try:
            bytes.fromhex(value)
        except ValueError:
            pass
        else:
            return value
    return _stable_sha256(label)


def _catalog_identity_binding(*, requested_slug: str, canonical_slug: str) -> str:
    return _stable_sha256(
        {
            "canonical_slug": canonical_slug,
            "id": requested_slug,
        }
    )


def _stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
