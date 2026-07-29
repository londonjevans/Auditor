"""Thread-safe request usage collection."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import weakref
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from mmaudit.models.identity import OpenRouterIdentityBindingResult
from mmaudit.models.output_modes import supported_output_modes
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    StructuredOutputEvidence,
    StructuredOutputResponseFormat,
    UsageRecord,
)
from mmaudit.privacy import EndpointPolicyClass, PrivacyProfile, PrivacySourceClassification

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

    return _is_strict_usage_record(
        record,
        require_real=require_real,
        require_certification=require_certification,
        allow_unbound_real=False,
    )


def is_generation_bindable_usage_record(record: UsageRecord) -> bool:
    """Return whether REAL certification transport evidence may fetch generation metadata."""

    return is_generation_reconcilable_usage_record(
        record,
        require_certification=True,
    )


def is_generation_reconcilable_usage_record(
    record: UsageRecord,
    *,
    require_certification: bool,
) -> bool:
    """Return whether owned REAL transport evidence may be reconciled."""

    if not isinstance(require_certification, bool):
        return False
    return _is_strict_usage_record(
        record,
        require_real=True,
        require_certification=require_certification,
        allow_unbound_real=True,
    )


def _is_strict_usage_record(
    record: UsageRecord,
    *,
    require_real: bool,
    require_certification: bool,
    allow_unbound_real: bool,
    require_runtime_attestation: bool = True,
) -> bool:
    if record.execution_evidence not in {
        ExecutionEvidenceKind.REAL,
        ExecutionEvidenceKind.MOCK,
    }:
        return False
    if require_real and record.execution_evidence is not ExecutionEvidenceKind.REAL:
        return False
    if (
        record.execution_evidence is ExecutionEvidenceKind.REAL
        and require_runtime_attestation
        and not _has_owned_real_usage_attestation(record)
    ):
        return False
    if (
        record.status != "success"
        or record.validation_status is not ModelRequestValidationStatus.VALID
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
        and _has_valid_privacy_routing(record)
        and _has_valid_structured_output_routing(record)
        and routing.get("repair_used") is False
        and routing.get("repair_request") is False
        and routing.get("request_started_at") == record.started_at.isoformat()
        and routing.get("request_ended_at") == record.ended_at.isoformat()
        and routing.get("latency_ms") == record.latency_ms
    )
    if not base_valid:
        return False
    aliases = routing.get("accepted_model_aliases")
    if record.returned_model != record.requested_model and (
        not isinstance(aliases, list)
        or aliases != sorted(set(aliases))
        or record.returned_model not in aliases
        or record.actual_model not in aliases
        or routing.get("provisional_identity_strength")
        != ModelIdentityStrength.CANONICAL_MODEL_AND_ENDPOINT_BOUND.value
    ):
        return False
    certification_request = routing.get("certification_request") is True
    if require_certification and not certification_request:
        return False
    if not certification_request:
        return (
            allow_unbound_real
            or record.execution_evidence is not ExecutionEvidenceKind.REAL
            or _has_valid_bound_identity(record)
        )
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
        and (allow_unbound_real or _has_valid_bound_identity(record))
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


def _has_valid_structured_output_routing(record: UsageRecord) -> bool:
    raw_evidence = record.routing.get("structured_output")
    if not isinstance(raw_evidence, dict):
        return False
    try:
        evidence = StructuredOutputEvidence.model_validate(raw_evidence)
    except ValidationError:
        return False
    if evidence.model_dump(mode="json") != raw_evidence:
        return False
    if (
        evidence.repair_used
        or evidence.truncated
        or evidence.requested_mode is not evidence.achieved_mode
        or tuple(record.configured_provider_endpoints) != evidence.configured_provider_endpoints
        or record.actual_provider_endpoint != evidence.selected_provider_endpoint
        or record.prompt_sha256 != evidence.prompt_sha256
        or record.request_body_sha256 != evidence.request_body_sha256
        or record.schema_sha256 != evidence.schema_sha256
        or record.response_sha256 != evidence.original_response_sha256
        or record.validated_response_sha256 != evidence.validated_response_sha256
        or record.routing.get("provider_policy_sha256") != evidence.provider_policy_sha256
        or record.routing.get("endpoint_snapshot_sha256") != evidence.endpoint_snapshot_sha256
        or record.routing.get("output_capability_sha256") != evidence.output_capability_sha256
        or record.routing.get("repair_used") is not evidence.repair_used
    ):
        return False
    request_shape_routing = {
        "structured_output_mode": evidence.requested_mode.value,
        "structured_output_request_shape_sha256": evidence.request_shape_sha256,
        "structured_output_require_parameters": evidence.provider_require_parameters,
        "structured_output_required_provider_parameters": list(
            evidence.required_provider_parameters
        ),
        "structured_output_reasoning_request_sha256": (evidence.reasoning_request_sha256),
        "structured_output_response_format": (
            None
            if evidence.response_format is StructuredOutputResponseFormat.OMITTED
            else evidence.response_format.value
        ),
        "structured_output_protocol_sha256": evidence.strict_protocol_sha256,
    }
    if any(key in record.routing for key in request_shape_routing) and any(
        record.routing.get(key) != value for key, value in request_shape_routing.items()
    ):
        return False

    redundant_routing = {
        "structured_output_supported_modes": [
            mode.value
            for mode in supported_output_modes(evidence.endpoint_structured_output_parameters)
        ],
        "structured_output_capability_sha256": evidence.output_capability_sha256,
        "structured_output_request_body_sha256": evidence.request_body_sha256,
        "structured_output_original_response_sha256": (evidence.original_response_sha256),
        "structured_output_validated_response_sha256": (evidence.validated_response_sha256),
    }
    if any(
        key in record.routing and record.routing.get(key) != value
        for key, value in redundant_routing.items()
    ):
        return False

    binding = _validated_identity_binding(record)
    if binding is None:
        return True
    capabilities = binding.snapshot.endpoint_capabilities
    required_special_parameters = set(capabilities.required_parameters) - {
        "max_tokens",
        "temperature",
    }
    return (
        binding.snapshot.endpoint_snapshot_sha256 == evidence.endpoint_snapshot_sha256
        and capabilities.output_capability_sha256 == evidence.output_capability_sha256
        and capabilities.structured_output_mode is evidence.requested_mode
        and set(evidence.endpoint_structured_output_parameters).issubset(
            capabilities.structured_output_parameters
        )
        and set(evidence.required_provider_parameters) == required_special_parameters
        and binding.snapshot.provider_policy.require_parameters
        is evidence.provider_require_parameters
    )


def _has_valid_privacy_routing(record: UsageRecord) -> bool:
    routing = record.routing
    if routing.get("data_collection") != "deny":
        return False
    profile = routing.get("privacy_profile")
    if profile is None:
        return False
    if (
        not _is_sha256(routing.get("effective_privacy_policy_sha256"))
        or not _is_sha256(routing.get("privacy_source_sha256"))
        or not _is_sha256(routing.get("privacy_source_provenance_sha256"))
    ):
        return False
    if profile == PrivacyProfile.STRICT_ZDR.value:
        return (
            routing.get("zdr_requested") is True
            and routing.get("privacy_authorization") == "STRICT_ZDR_ENFORCED"
            and routing.get("privacy_endpoint_policy_class") == EndpointPolicyClass.ZDR.value
        )
    if profile not in {
        PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT.value,
        PrivacyProfile.SYNTHETIC_BENCHMARK.value,
    }:
        return False
    source_classification = routing.get("privacy_source_classification")
    if (
        profile == PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT.value
        and source_classification != PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
    ):
        return False
    if profile == PrivacyProfile.SYNTHETIC_BENCHMARK.value and source_classification not in {
        PrivacySourceClassification.SYNTHETIC_COMMITTED.value,
        PrivacySourceClassification.PUBLIC_BENCHMARK.value,
    }:
        return False
    if routing.get("zdr_requested") is True:
        return (
            routing.get("privacy_authorization") == "STRICT_ZDR_ENFORCED"
            and routing.get("privacy_endpoint_policy_class") == EndpointPolicyClass.ZDR.value
        )
    if (
        not _is_sha256(routing.get("privacy_consent_file_sha256"))
        or not _is_sha256(routing.get("privacy_consent_sha256"))
        or not _valid_consent_expiry(record)
    ):
        return False
    return (
        routing.get("zdr_requested") is False
        and routing.get("privacy_authorization") == "CONSENT_BOUND_NON_ZDR"
        and routing.get("privacy_endpoint_policy_class")
        == EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED.value
    )


def _valid_consent_expiry(record: UsageRecord) -> bool:
    value = record.routing.get("privacy_consent_expires_at")
    if not isinstance(value, str):
        return False
    try:
        expires_at = datetime.fromisoformat(value)
    except ValueError:
        return False
    if (
        expires_at.tzinfo is None
        or expires_at.utcoffset() != UTC.utcoffset(expires_at)
        or expires_at.microsecond != 0
        or expires_at.isoformat() != value
        or record.ended_at is None
    ):
        return False
    return expires_at > record.ended_at


def _build_owned_real_usage_authority() -> tuple[
    Callable[[UsageRecord], UsageRecord],
    Callable[[UsageRecord], bool],
]:
    """Keep REAL runtime authority outside caller-mutable Pydantic state."""

    registry: dict[int, tuple[weakref.ReferenceType[UsageRecord], str]] = {}
    lock = threading.RLock()

    def attest(record: UsageRecord) -> UsageRecord:
        if type(record) is not UsageRecord:
            raise ValueError("REAL usage attestation requires an exact usage record")
        if record.execution_evidence is not ExecutionEvidenceKind.REAL:
            raise ValueError("REAL usage attestation rejects non-REAL evidence")
        key = id(record)
        digest = _usage_record_sha256(record)

        def discard(reference: weakref.ReferenceType[UsageRecord]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(record, discard)
        with lock:
            registry[key] = (reference, digest)
        return record

    def contains(record: UsageRecord) -> bool:
        key = id(record)
        with lock:
            registered = registry.get(key)
        return (
            registered is not None
            and registered[0]() is record
            and registered[1] == _usage_record_sha256(record)
        )

    return attest, contains


_attest_owned_real_usage_record, _has_owned_real_usage_attestation = (
    _build_owned_real_usage_authority()
)


def _validated_usage_copy_preserving_owned_attestation(
    record: UsageRecord,
) -> UsageRecord:
    """Schema-normalize a trusted in-memory record without dropping its capability."""

    trusted_real = (
        record.execution_evidence is ExecutionEvidenceKind.REAL
        and _has_owned_real_usage_attestation(record)
    )
    normalized = UsageRecord.model_validate(record.model_dump(mode="json"))
    if trusted_real:
        normalized = _attest_owned_real_usage_record(normalized)
    return normalized


def _is_structurally_generation_bindable_usage_record(record: UsageRecord) -> bool:
    """Validate serialized transport shape without granting REAL runtime credit."""

    return _is_structurally_generation_reconcilable_usage_record(
        record,
        require_certification=True,
    )


def _is_structurally_generation_reconcilable_usage_record(
    record: UsageRecord,
    *,
    require_certification: bool,
) -> bool:
    """Validate serialized generation-reconciliation shape without runtime credit."""

    if not isinstance(require_certification, bool):
        return False
    return _is_strict_usage_record(
        record,
        require_real=True,
        require_certification=require_certification,
        allow_unbound_real=True,
        require_runtime_attestation=False,
    )


def _is_structurally_creditable_usage_record(
    record: UsageRecord,
    *,
    require_real: bool = False,
    require_certification: bool = False,
) -> bool:
    """Validate serialized evidence shape without granting runtime execution credit."""

    return _is_strict_usage_record(
        record,
        require_real=require_real,
        require_certification=require_certification,
        allow_unbound_real=False,
        require_runtime_attestation=False,
    )


def _usage_record_sha256(record: UsageRecord) -> str:
    return hashlib.sha256(
        json.dumps(
            record.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _has_valid_bound_identity(record: UsageRecord) -> bool:
    binding = _validated_identity_binding(record)
    return (
        binding is not None
        and binding.strength is not ModelIdentityStrength.UNBOUND
        and binding.generation is not None
        and "unbound_generation_observation" not in record.routing
        and record.routing.get("identity_binding_status") == "generation_metadata_bound"
        and _identity_binding_matches_record(record, binding)
        and binding.generation.generation_id == record.openrouter_generation_id
        and binding.generation.execution_evidence == record.execution_evidence.value
    )


def _has_valid_unbound_identity_conclusion(record: UsageRecord) -> bool:
    binding = _validated_identity_binding(record)
    return (
        binding is not None
        and binding.strength is ModelIdentityStrength.UNBOUND
        and binding.generation is None
        and record.identity_strength is ModelIdentityStrength.UNBOUND
        and record.routing.get("identity_binding_status") == "generation_metadata_unbound"
        and _has_valid_unbound_generation_observation(record)
        and _identity_binding_matches_record(record, binding)
    )


def _has_valid_unbound_generation_observation(record: UsageRecord) -> bool:
    raw_observation = record.routing.get("unbound_generation_observation")
    if raw_observation is None:
        return True
    if not isinstance(raw_observation, dict):
        return False
    # Import lazily because generation evidence depends on usage validation.
    from mmaudit.models.generation_evidence import OpenRouterGenerationEvidence

    try:
        observation = OpenRouterGenerationEvidence.model_validate(raw_observation)
    except ValidationError:
        return False
    return observation.model_dump(mode="json") == raw_observation


def _validated_identity_binding(
    record: UsageRecord,
) -> OpenRouterIdentityBindingResult | None:
    raw_binding = record.routing.get("identity_binding")
    if not isinstance(raw_binding, dict):
        return None
    try:
        return OpenRouterIdentityBindingResult.model_validate(raw_binding)
    except ValidationError:
        return None


def _identity_binding_matches_record(
    record: UsageRecord,
    binding: OpenRouterIdentityBindingResult,
) -> bool:
    request = binding.request
    started_at = record.started_at
    ended_at = record.ended_at
    if started_at is None or ended_at is None:
        return False
    return (
        binding.strength is record.identity_strength
        and record.routing.get("identity_binding_sha256") == binding.binding_sha256
        and request.internal_request_id == record.request_id
        and request.execution_evidence == record.execution_evidence.value
        and request.requested_slug == record.requested_model
        and request.returned_slug == record.returned_model
        and request.selected_model_slug == record.actual_model
        and request.actual_provider_endpoint == record.actual_provider_endpoint
        and request.actual_provider_name == record.routing.get("selected_provider_name")
        and request.openrouter_generation_id == record.openrouter_generation_id
        and request.request_body_sha256 == record.request_body_sha256
        and request.response_sha256 == record.response_sha256
        and request.validated_response_sha256 == record.validated_response_sha256
        and request.started_at == started_at.astimezone(UTC).replace(microsecond=0)
        and request.completed_at == ended_at.astimezone(UTC).replace(microsecond=0)
        and request.fallback_used == record.routing.get("provider_fallback_used")
        and binding.snapshot.snapshot_sha256 == record.routing.get("identity_snapshot_sha256")
        and binding.snapshot.catalog_identity_binding_sha256
        == record.routing.get("catalog_identity_binding_sha256")
        and binding.snapshot.endpoint_snapshot_sha256
        == record.routing.get("endpoint_snapshot_sha256")
    )


class UsageLedger:
    """Collect immutable request records without global state."""

    def __init__(self) -> None:
        self._records: list[UsageRecord] = []

    def add(self, record: UsageRecord) -> None:
        self._records.append(record)

    def replace_with_bound_identity(self, record: UsageRecord) -> None:
        """Replace one owned provisional record only with its sealed identity upgrade."""

        if not _has_valid_bound_identity(record):
            raise ValueError("usage identity replacement requires a valid bound identity")
        self._replace_with_identity_result(record)

    def replace_with_unbound_identity(self, record: UsageRecord) -> None:
        """Retain one owned fail-closed identity conclusion and bounded diagnostics."""

        if not _has_valid_unbound_identity_conclusion(record):
            raise ValueError("usage identity replacement requires a valid unbound conclusion")
        self._replace_with_identity_result(record)

    def _replace_with_identity_result(self, record: UsageRecord) -> None:
        """Replace a provisional record without changing immutable request evidence."""

        matching = [
            (index, existing)
            for index, existing in enumerate(self._records)
            if existing.request_id == record.request_id
        ]
        if len(matching) != 1:
            raise ValueError("usage identity replacement requires one owned request record")
        index, existing = matching[0]
        if existing == record:
            return
        if existing.execution_evidence is ExecutionEvidenceKind.REAL and (
            not _has_owned_real_usage_attestation(existing)
            or not _has_owned_real_usage_attestation(record)
        ):
            raise ValueError("REAL usage identity replacement requires owned runtime provenance")
        if (
            existing.identity_strength is not ModelIdentityStrength.UNBOUND
            or existing.routing.get("identity_binding_status") != "generation_metadata_pending"
        ):
            raise ValueError("usage identity replacement cannot overwrite a concluded record")
        existing_core = existing.model_dump(
            mode="json",
            exclude={"identity_strength", "routing"},
        )
        replacement_core = record.model_dump(
            mode="json",
            exclude={"identity_strength", "routing"},
        )
        expected_routing = {
            **existing.routing,
            "identity_binding": record.routing.get("identity_binding"),
            "identity_binding_sha256": record.routing.get("identity_binding_sha256"),
            "identity_binding_status": record.routing.get("identity_binding_status"),
        }
        if "unbound_generation_observation" in record.routing:
            expected_routing["unbound_generation_observation"] = record.routing[
                "unbound_generation_observation"
            ]
        if replacement_core != existing_core or record.routing != expected_routing:
            raise ValueError("usage identity replacement changed immutable request evidence")
        self._records[index] = record

    @property
    def records(self) -> list[UsageRecord]:
        return list(self._records)

    @property
    def accounted_cost_usd(self) -> float:
        return sum(record.accounted_cost_usd for record in self._records)

    def role_requests(self, role: str) -> int:
        return sum(1 for record in self._records if record.role == role)
