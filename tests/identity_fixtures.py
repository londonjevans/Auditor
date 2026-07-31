"""Test-only builders for internally coherent synthetic identity evidence.

These helpers never perform provider I/O and must not be treated as REAL integration
evidence. They exist so unit tests can exercise production validators without
weakening the rule that serialized REAL usage requires a complete identity binding.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from mmaudit.models.identity import (
    OpenRouterGenerationIdentityEvidence,
    OpenRouterIdentityEndpointCapabilities,
    OpenRouterIdentityPricingEntry,
    OpenRouterRequestIdentityEvidence,
    seal_bound_openrouter_identity,
    seal_openrouter_identity_provider_policy,
    seal_openrouter_model_endpoint_identity_snapshot,
)
from mmaudit.models.output_modes import (
    StructuredOutputMode,
    structured_output_parameters,
    supported_output_modes,
)
from mmaudit.models.schemas import ModelIdentityStrength, StructuredOutputEvidence, UsageRecord
from mmaudit.models.token_planning import (
    MINIMUM_FINDING_OUTPUT_TOKENS,
    MINIMUM_SUMMARY_OUTPUT_TOKENS,
    PROMPT_ALLOCATION_CATEGORIES,
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    PromptTokenAllocation,
    build_request_token_plan,
)
from mmaudit.models.usage import _attest_owned_real_usage_record
from mmaudit.orchestration.budgets import AtomicTokenReservationEvidence
from mmaudit.privacy import EndpointPolicyClass, PrivacyProfile, PrivacySourceClassification
from tests.output_evidence_fixtures import synthetic_structured_output_routing

_PRIVACY_ROUTING_FIELDS = frozenset(
    {
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
)
_TOKEN_ROUTING_FIELDS = frozenset(
    {
        "request_token_plan",
        "request_token_plan_sha256",
        "atomic_token_reservations",
        "atomic_token_reservation_sha256s",
        "atomic_token_reservation",
        "atomic_token_reservation_sha256",
    }
)


def synthetic_strict_zdr_privacy_routing(
    routing: Mapping[str, object],
    *,
    source_label: str,
) -> dict[str, object]:
    """Complete a legacy synthetic ZDR route without masking partial-evidence tests."""

    completed = dict(routing)
    if _PRIVACY_ROUTING_FIELDS.intersection(completed):
        return completed
    if completed.get("zdr_requested") is not True or completed.get("data_collection") != "deny":
        return completed
    source_sha256 = hashlib.sha256(source_label.encode()).hexdigest()
    provenance_sha256 = hashlib.sha256(
        json.dumps(
            {
                "source_sha256": source_sha256,
                "source_classification": (
                    PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
                ),
                "synthetic_fixture": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    policy_sha256 = hashlib.sha256(
        json.dumps(
            {
                "privacy_profile": PrivacyProfile.STRICT_ZDR.value,
                "require_zdr": True,
                "source_sha256": source_sha256,
                "source_provenance_sha256": provenance_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    completed.update(
        {
            "privacy_profile": PrivacyProfile.STRICT_ZDR.value,
            "privacy_authorization": "STRICT_ZDR_ENFORCED",
            "effective_privacy_policy_sha256": policy_sha256,
            "privacy_source_sha256": source_sha256,
            "privacy_source_provenance_sha256": provenance_sha256,
            "privacy_source_classification": (
                PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
            ),
            "privacy_consent_file_sha256": None,
            "privacy_consent_sha256": None,
            "privacy_consent_expires_at": None,
            "privacy_endpoint_policy_class": EndpointPolicyClass.ZDR.value,
        }
    )
    return completed


def synthetic_token_plan_routing(
    record: UsageRecord,
    routing: Mapping[str, object],
) -> dict[str, object]:
    """Complete wholly absent token evidence without masking partial-evidence tests."""

    completed = dict(routing)
    if _TOKEN_ROUTING_FIELDS.intersection(completed):
        return completed
    endpoint = record.actual_provider_endpoint
    if endpoint is None:
        return completed
    allocation_bytes = max(12, ((max(1, record.prompt_tokens) + 9) // 10) * 3)
    allocations = tuple(
        PromptTokenAllocation.from_text(
            category,
            (
                ""
                if category.value == "prior_audit"
                else f"{category.value}:{'x' * allocation_bytes}"
            ),
        )
        for category in PROMPT_ALLOCATION_CATEGORIES
    )
    prompt_ceiling = sum(item.estimate.byte_upper_bound_tokens for item in allocations)
    completion_ceiling = max(
        1 + MINIMUM_FINDING_OUTPUT_TOKENS + MINIMUM_SUMMARY_OUTPUT_TOKENS,
        record.completion_tokens,
    )
    hard_prompt_capacity = (prompt_ceiling * 4 + 2) // 3
    route = EndpointRouteTokenCapacity.build(
        exact_model_id=record.requested_model,
        provider_endpoint=endpoint,
        endpoint_snapshot_sha256=_hash_or_default(
            completed.get("endpoint_snapshot_sha256"),
            "synthetic endpoint snapshot",
        ),
        context_tokens=hard_prompt_capacity + completion_ceiling,
        max_prompt_tokens=hard_prompt_capacity,
        max_prompt_tokens_source="metadata",
        max_completion_tokens=completion_ceiling,
        max_completion_tokens_source="metadata",
    )
    plan = build_request_token_plan(
        request_id=record.request_id,
        role=record.role,
        route_intersection=EndpointRouteIntersection.build((route,)),
        allocations=allocations,
        required_output_tokens=completion_ceiling,
        reserved_reasoning_tokens=0,
        global_input_token_budget=max(prompt_ceiling, 1_000_000),
        global_output_token_budget=max(completion_ceiling, 100_000),
        context_utilization=Decimal("0.75"),
        prompt_envelope_byte_upper_bound_tokens=prompt_ceiling,
    )
    atomic = AtomicTokenReservationEvidence.build(
        request_id=record.request_id,
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=plan.plan_sha256,
        planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=plan.reserved_output_tokens,
        planned_reasoning_tokens=plan.reserved_reasoning_tokens,
        planned_completion_tokens=plan.requested_completion_tokens,
        global_input_token_limit=plan.global_budget.global_input_token_budget,
        global_output_token_limit=plan.global_budget.global_output_token_budget,
        spent_input_tokens_before=0,
        reserved_input_tokens_before=0,
        spent_output_tokens_before=0,
        reserved_output_tokens_before=0,
    )
    completed.update(
        {
            "request_token_plan": plan.model_dump(mode="json"),
            "request_token_plan_sha256": plan.plan_sha256,
            "atomic_token_reservations": [atomic.model_dump(mode="json")],
            "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
            "atomic_token_reservation": atomic.model_dump(mode="json"),
            "atomic_token_reservation_sha256": atomic.evidence_sha256,
        }
    )
    return completed


def rebind_synthetic_token_plan(record: UsageRecord) -> UsageRecord:
    """Explicitly rebuild test-only token evidence after a synthetic route mutation."""

    routing = dict(record.routing)
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    unbound = record.model_copy(update={"routing": routing})
    return unbound.model_copy(update={"routing": synthetic_token_plan_routing(unbound, routing)})


def bind_synthetic_usage_identity(
    record: UsageRecord,
    *,
    endpoint_supported_parameters: tuple[str, ...] | None = None,
    model_supported_parameters: tuple[str, ...] | None = None,
) -> UsageRecord:
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
    routing = synthetic_strict_zdr_privacy_routing(
        record.routing,
        source_label=f"{record.request_id}:{record.prompt_sha256}",
    )
    routing = synthetic_token_plan_routing(record, routing)
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
    raw_structured_output = routing.get("structured_output")
    if raw_structured_output is None:
        legacy_output_capability_sha256 = _hash_or_default(
            routing.get("output_capability_sha256"),
            "synthetic output capability",
        )
        raw_structured_output = synthetic_structured_output_routing(
            configured_provider_endpoints=tuple(record.configured_provider_endpoints),
            selected_provider_endpoint=record.actual_provider_endpoint,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            output_capability_sha256=legacy_output_capability_sha256,
            prompt_sha256=record.prompt_sha256,
            request_body_sha256=record.request_body_sha256,
            provider_policy_sha256=str(routing.get("provider_policy_sha256")),
            schema_sha256=record.schema_sha256,
            original_response_sha256=record.response_sha256,
            validated_response_sha256=record.validated_response_sha256,
            mode=StructuredOutputMode.JSON_OBJECT,
        )
        routing["structured_output"] = raw_structured_output
    structured_output = StructuredOutputEvidence.model_validate(raw_structured_output)
    output_mode = structured_output.achieved_mode
    output_parameters = structured_output.endpoint_structured_output_parameters
    output_capability_sha256 = structured_output.output_capability_sha256
    routed_capability = routing.get("output_capability_sha256")
    if routed_capability is not None and routed_capability != output_capability_sha256:
        raise ValueError("synthetic output capability hash differs from structured evidence")
    required_provider_parameters = structured_output.required_provider_parameters
    default_supported_parameters = tuple(
        sorted(
            {
                "max_tokens",
                "temperature",
                *output_parameters,
                *required_provider_parameters,
            }
        )
    )
    endpoint_parameters = endpoint_supported_parameters or default_supported_parameters
    model_parameters = model_supported_parameters or default_supported_parameters
    if endpoint_parameters != tuple(sorted(set(endpoint_parameters))):
        raise ValueError("synthetic endpoint parameters must be sorted and unique")
    if model_parameters != tuple(sorted(set(model_parameters))):
        raise ValueError("synthetic model parameters must be sorted and unique")
    if output_mode not in supported_output_modes(endpoint_parameters) or output_mode not in (
        supported_output_modes(model_parameters)
    ):
        raise ValueError("synthetic output mode is not supported by model and endpoint")
    endpoint_output_parameters = structured_output_parameters(endpoint_parameters)
    required_parameters = tuple(
        sorted(
            {
                "max_tokens",
                "temperature",
                *required_provider_parameters,
            }
        )
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
            "output_capability_sha256": output_capability_sha256,
        }
    )
    policy = seal_openrouter_identity_provider_policy(
        mode="only",
        configured_endpoints=(record.actual_provider_endpoint,),
        allow_fallbacks=False,
        zdr_required=True,
        require_parameters=bool(set(required_parameters) - {"max_tokens", "temperature"}),
    )
    capabilities = OpenRouterIdentityEndpointCapabilities(
        operational=True,
        context_tokens=200_000,
        output_tokens=20_000,
        supported_parameters=endpoint_parameters,
        required_parameters=required_parameters,
        structured_output_parameters=endpoint_output_parameters,
        supported_output_modes=supported_output_modes(endpoint_parameters),
        structured_output_mode=output_mode,
        output_capability_sha256=output_capability_sha256,
        reasoning_parameters=(
            ("reasoning",) if "reasoning" in required_provider_parameters else ()
        ),
        structured_output_supported=bool(endpoint_output_parameters),
        reasoning_supported="reasoning" in required_provider_parameters,
        zdr_eligible=True,
        data_collection_deny_eligible=True,
        data_collection_deny_request_policy_enforced=True,
        data_collection_deny_evidence_source="ZDR_ENDPOINT_SNAPSHOT",
        data_collection_deny_evidence_sha256="8" * 64,
        data_collection_deny_evidence_expires_at=None,
    )
    snapshot = seal_openrouter_model_endpoint_identity_snapshot(
        requested_slug=record.requested_model,
        canonical_slug=canonical_slug,
        frozen_aliases=aliases,
        model_author=canonical_slug.split("/", 1)[0],
        model_context_tokens=200_000,
        model_output_tokens=20_000,
        model_supported_parameters=model_parameters,
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
