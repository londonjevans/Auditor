from __future__ import annotations

import hashlib
import json
from copy import copy
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest

import mmaudit.models.usage as usage_module
from mmaudit.models.identity import OpenRouterIdentityBindingResult
from mmaudit.models.output_modes import StructuredOutputMode, supported_output_modes
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    ReasoningRequestPlanEvidence,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.token_planning import (
    PROMPT_ALLOCATION_CATEGORIES,
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
    build_request_token_plan,
)
from mmaudit.models.usage import (
    STRICT_USAGE_FAILURE_CODES,
    STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES,
    _authrunner_usage_origin_scope,
    _has_authrunner_owned_real_usage_origin,
    _issue_trusted_usage_recovery_scope,
    _recover_trusted_usage_records,
    atomic_request_limit_reservations_from_usage,
    is_creditable_usage_record,
    is_recovery_creditable_usage_record,
    is_structurally_recovery_creditable_usage_record,
    recovery_atomic_request_limit_reservations_from_usage,
    recovery_request_token_plan_from_usage,
    request_token_plan_from_usage,
    usage_requires_audit_policy_evidence,
)
from mmaudit.orchestration.budgets import (
    AtomicRequestLimitReservationEvidence,
    AtomicTokenReservationEvidence,
)
from mmaudit.orchestration.context_manifest import ContextManifestError, build_context_manifest
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import EndpointPolicyClass, PrivacyProfile, PrivacySourceClassification
from tests.identity_fixtures import bind_synthetic_usage_identity, reattest_synthetic_real_usage
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


def test_strict_usage_failure_vocabulary_is_closed_and_evaluator_retarget_cannot_credit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES == (
        "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_TYPE",
        "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_SCHEMA",
        "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_CANONICAL",
        "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED",
        "STRUCTURED_OUTPUT_ROUTING:TRUNCATED",
        "STRUCTURED_OUTPUT_ROUTING:REQUESTED_MODE_MISMATCH",
        "STRUCTURED_OUTPUT_ROUTING:CONFIGURED_PROVIDER_ENDPOINTS",
        "STRUCTURED_OUTPUT_ROUTING:SELECTED_PROVIDER_ENDPOINT",
        "STRUCTURED_OUTPUT_ROUTING:PROMPT_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_BODY_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:SCHEMA_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:ORIGINAL_RESPONSE_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:VALIDATED_RESPONSE_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:PROVIDER_POLICY_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:ENDPOINT_SNAPSHOT_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:OUTPUT_CAPABILITY_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED_ROUTING",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_MODE",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRE_PARAMETERS",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRED_PROVIDER_PARAMETERS",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REASONING_REQUEST_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_RESPONSE_FORMAT",
        "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_PROTOCOL_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_SUPPORTED_MODES",
        "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_CAPABILITY_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_REQUEST_BODY_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_ORIGINAL_RESPONSE_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_VALIDATED_RESPONSE_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_ENDPOINT_SNAPSHOT_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_OUTPUT_CAPABILITY_SHA256",
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_MODE",
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_PARAMETER_SUBSET",
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS",
        "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRE_PARAMETERS",
    )
    assert (
        "RECOVERY_SCOPE",
        "EXECUTION",
        "RUNTIME_ATTESTATION",
        "STATUS",
        "REQUIRED_FIELDS",
        "TIMING",
        "HASHES",
        "TOKEN_ALGEBRA",
        "COST",
        "ENDPOINT",
        "ROUTER_IDENTITY",
        "PRIVACY_ROUTING",
        *STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES,
        "TOKEN_PLAN_ROUTING",
        "REPAIR_TEMPORAL_ROUTING",
        "ALIAS",
        "CERTIFICATION",
        "BOUND_IDENTITY",
        "CERTIFICATION_ROUTE",
        "SMOKE_SCOPE",
        "UNEXPECTED_GENERAL_CREDITABILITY",
    ) == STRICT_USAGE_FAILURE_CODES
    invalid = _creditable_record().model_copy(update={"status": "failed"})
    assert not is_creditable_usage_record(invalid)

    monkeypatch.setattr(
        usage_module,
        "_strict_usage_record_failure_code",
        lambda *_args, **_kwargs: None,
        raising=False,
    )

    assert not is_creditable_usage_record(invalid)


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
    record = UsageRecord(
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
    plan, atomic = _token_plan_for_record(record)
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
            }
        }
    )


def _legacy_has_valid_structured_output_routing(record: UsageRecord) -> bool:
    """Mirror the frozen pre-diagnostic predicate for truth-table differential tests."""

    raw_evidence = record.routing.get("structured_output")
    if not isinstance(raw_evidence, dict):
        return False
    try:
        evidence = usage_module.StructuredOutputEvidence.model_validate(raw_evidence)
    except usage_module.ValidationError:
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
        "structured_output_reasoning_request_sha256": evidence.reasoning_request_sha256,
        "structured_output_response_format": (
            None
            if evidence.response_format is usage_module.StructuredOutputResponseFormat.OMITTED
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
        "structured_output_original_response_sha256": evidence.original_response_sha256,
        "structured_output_validated_response_sha256": evidence.validated_response_sha256,
    }
    if any(
        key in record.routing and record.routing.get(key) != value
        for key, value in redundant_routing.items()
    ):
        return False

    binding = usage_module._validated_identity_binding(record)
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


def test_strict_usage_nested_helper_retargets_remain_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _creditable_record()
    assert is_creditable_usage_record(record)
    captured_helper_names = (
        "_validate_recovery_request_limit_coordinates",
        "_has_owned_real_usage_attestation",
        "_has_valid_privacy_routing",
        "_has_valid_structured_output_routing",
        "_structured_output_routing_failure_code",
        "_has_valid_token_plan_routing",
        "authrunner_noncrediting_unknown_token_smoke_scope",
        "_validate_noncrediting_smoke_reasoning_identity_join",
        "_is_sha256",
        "_has_valid_bound_identity",
    )
    for helper_name in captured_helper_names:
        with monkeypatch.context() as helper_context:
            helper_context.setattr(usage_module, helper_name, lambda *_args, **_kwargs: True)
            assert not is_creditable_usage_record(record)

    trusted_structured_output_validator = usage_module._has_valid_structured_output_routing

    class RetargetingEndpoint(str):
        def casefold(self) -> str:
            monkeypatch.setattr(
                usage_module,
                "_has_valid_structured_output_routing",
                lambda _record: True,
            )
            return super().casefold()

    invalid_structured_routing = {
        key: value for key, value in record.routing.items() if key != "structured_output"
    }
    callback_endpoint = record.model_copy(
        update={
            "actual_provider_endpoint": RetargetingEndpoint(record.actual_provider_endpoint or ""),
            "routing": invalid_structured_routing,
        }
    )
    assert not is_creditable_usage_record(callback_endpoint)
    assert usage_module._has_valid_structured_output_routing is trusted_structured_output_validator

    class RetargetingRequiredString(str):
        def strip(self, chars: str | None = None) -> str:
            monkeypatch.setattr(
                usage_module,
                "_has_valid_structured_output_routing",
                lambda _record: True,
            )
            return super().strip(chars)

    callback_provider = record.model_copy(
        update={
            "provider": RetargetingRequiredString(record.provider),
            "routing": invalid_structured_routing,
        }
    )
    assert not is_creditable_usage_record(callback_provider)
    assert usage_module._has_valid_structured_output_routing is trusted_structured_output_validator

    class RetargetingRouting(dict[str, Any]):
        def get(self, key: str, default: Any = None) -> Any:
            monkeypatch.setattr(
                usage_module,
                "_has_valid_structured_output_routing",
                lambda _record: True,
            )
            return super().get(key, default)

    callback_routing = record.model_copy(
        update={"routing": RetargetingRouting(invalid_structured_routing)}
    )
    assert not is_creditable_usage_record(callback_routing)
    assert usage_module._has_valid_structured_output_routing is trusted_structured_output_validator

    mutations = (
        (
            "_has_valid_structured_output_routing",
            record.model_copy(
                update={
                    "routing": {
                        key: value
                        for key, value in record.routing.items()
                        if key != "structured_output"
                    }
                }
            ),
        ),
        (
            "_has_valid_privacy_routing",
            record.model_copy(
                update={
                    "routing": {
                        **record.routing,
                        "effective_privacy_policy_sha256": None,
                    }
                }
            ),
        ),
        (
            "_has_valid_token_plan_routing",
            record.model_copy(
                update={
                    "routing": {
                        key: value
                        for key, value in record.routing.items()
                        if key != "request_token_plan"
                    }
                }
            ),
        ),
        (
            "_is_sha256",
            record.model_copy(
                update={
                    "routing": {
                        **record.routing,
                        "router_metadata_sha256": "not-a-sha256",
                    }
                }
            ),
        ),
    )
    for helper_name, invalid in mutations:
        assert not is_creditable_usage_record(invalid)
        with monkeypatch.context() as helper_context:
            helper_context.setattr(usage_module, helper_name, lambda *_args, **_kwargs: True)
            assert not is_creditable_usage_record(invalid)


def test_structured_output_helpers_retargeted_during_evaluation_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _creditable_record()
    trusted_predicate = usage_module._has_valid_structured_output_routing
    trusted_diagnostic = usage_module._structured_output_routing_failure_code
    trusted_scope_classifier = usage_module.authrunner_noncrediting_unknown_token_smoke_scope
    trusted_reasoning_join = usage_module._validate_noncrediting_smoke_reasoning_identity_join

    for helper_name, replacement in (
        ("_has_valid_structured_output_routing", lambda _record: True),
        ("_structured_output_routing_failure_code", lambda _record: None),
        ("authrunner_noncrediting_unknown_token_smoke_scope", lambda _record: None),
        (
            "_validate_noncrediting_smoke_reasoning_identity_join",
            lambda *_args, **_kwargs: "DYNAMIC",
        ),
    ):
        callback_values: list[object] = []
        with monkeypatch.context() as context:

            class RetargetingRouteValue:
                def __init__(
                    self,
                    *,
                    patch_context: pytest.MonkeyPatch,
                    target_name: str,
                    target_replacement: object,
                    observed_values: list[object],
                ) -> None:
                    self.patch_context = patch_context
                    self.target_name = target_name
                    self.target_replacement = target_replacement
                    self.observed_values = observed_values

                def __eq__(self, other: object) -> bool:
                    self.observed_values.append(other)
                    self.patch_context.setattr(
                        usage_module,
                        self.target_name,
                        self.target_replacement,
                    )
                    return True

            invalid = record.model_copy(
                update={
                    "routing": {
                        **record.routing,
                        "generation_id": RetargetingRouteValue(
                            patch_context=context,
                            target_name=helper_name,
                            target_replacement=replacement,
                            observed_values=callback_values,
                        ),
                    }
                }
            )
            assert not is_creditable_usage_record(invalid)
            assert callback_values == [record.openrouter_generation_id]

        assert usage_module._has_valid_structured_output_routing is trusted_predicate
        assert usage_module._structured_output_routing_failure_code is trusted_diagnostic
        assert (
            usage_module.authrunner_noncrediting_unknown_token_smoke_scope
            is trusted_scope_classifier
        )
        assert (
            usage_module._validate_noncrediting_smoke_reasoning_identity_join
            is trusted_reasoning_join
        )


def _token_plan_for_record(
    record: UsageRecord,
    *,
    request_id: str | None = None,
    role: str | None = None,
    exact_model_id: str | None = None,
    reserved_reasoning_tokens: int = 50,
    reasoning_plan: ReasoningRequestPlanEvidence | None = None,
) -> tuple[RequestTokenPlan, AtomicTokenReservationEvidence]:
    planned_request_id = request_id or record.request_id
    planned_role = role or record.role
    planned_model = exact_model_id or record.requested_model
    route = EndpointRouteTokenCapacity.build(
        exact_model_id=planned_model,
        provider_endpoint=record.configured_provider_endpoints[0],
        endpoint_snapshot_sha256="9" * 64,
        context_tokens=10_000,
        max_prompt_tokens=8_000,
        max_prompt_tokens_source="metadata",
        max_completion_tokens=1_000,
        max_completion_tokens_source="metadata",
    )
    allocations = tuple(
        PromptTokenAllocation.from_text(
            category,
            (
                ""
                if category is PromptAllocationCategory.PRIOR_AUDIT
                else f"{category.value}:{'x' * 40}"
            ),
        )
        for category in PROMPT_ALLOCATION_CATEGORIES
    )
    plan = build_request_token_plan(
        request_id=planned_request_id,
        role=planned_role,
        route_intersection=EndpointRouteIntersection.build((route,)),
        allocations=allocations,
        required_output_tokens=512,
        reserved_reasoning_tokens=reserved_reasoning_tokens,
        reasoning_plan=reasoning_plan,
        global_input_token_budget=100_000,
        global_output_token_budget=10_000,
        context_utilization=Decimal("0.70"),
        prompt_envelope_byte_upper_bound_tokens=sum(
            allocation.estimate.byte_upper_bound_tokens for allocation in allocations
        ),
    )
    atomic = AtomicTokenReservationEvidence.build(
        request_id=planned_request_id,
        exact_model_id=planned_model,
        role=planned_role,
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
    return plan, atomic


def _active_reasoning_plan(*, reserved_reasoning_tokens: int = 50) -> ReasoningRequestPlanEvidence:
    disabled = ReasoningControlProfile.build(
        mode="disabled",
        reserved_reasoning_tokens=0,
    )
    controls = {role: disabled for role in CANONICAL_REASONING_POLICY_ROLES}
    controls["source_audit"] = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=reserved_reasoning_tokens,
    )
    return ReasoningRequestPlanEvidence.build(
        request_role="source_audit",
        policy=ReasoningPolicyArtifact.build(controls_by_role=controls),
    )


def _reasoning_token_bound_creditable_record(
    observed_reasoning_tokens: int | None,
) -> UsageRecord:
    record = _creditable_record()
    reasoning_plan = _active_reasoning_plan()
    plan, atomic = _token_plan_for_record(
        record,
        reasoning_plan=reasoning_plan,
    )
    reasoning_evidence = ReasoningExecutionEvidence.build(
        request_plan=reasoning_plan,
        observed_reasoning_tokens=observed_reasoning_tokens,
        provider_completion_tokens=record.completion_tokens,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256=record.request_body_sha256 or "",
    )
    return record.model_copy(
        update={
            "reasoning_tokens": observed_reasoning_tokens or 0,
            "reasoning_evidence": reasoning_evidence,
            "routing": {
                **record.routing,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
            },
        }
    )


def _token_bound_creditable_record() -> UsageRecord:
    record = _creditable_record()
    plan, atomic = _token_plan_for_record(record)
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
            }
        }
    )


def _retry_token_bound_creditable_record() -> UsageRecord:
    record = _creditable_record()
    plan, first = _token_plan_for_record(record)
    second = AtomicTokenReservationEvidence.build(
        request_id=f"{record.request_id}:attempt:2",
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=plan.plan_sha256,
        planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=plan.reserved_output_tokens,
        planned_reasoning_tokens=plan.reserved_reasoning_tokens,
        planned_completion_tokens=plan.requested_completion_tokens,
        global_input_token_limit=plan.global_budget.global_input_token_budget,
        global_output_token_limit=plan.global_budget.global_output_token_budget,
        spent_input_tokens_before=record.prompt_tokens,
        reserved_input_tokens_before=0,
        spent_output_tokens_before=record.completion_tokens,
        reserved_output_tokens_before=0,
    )
    inventory = [first.model_dump(mode="json"), second.model_dump(mode="json")]
    hashes = [first.evidence_sha256, second.evidence_sha256]
    return record.model_copy(
        update={
            "attempts": 2,
            "retry_count": 1,
            "routing": {
                **record.routing,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": inventory,
                "atomic_token_reservation_sha256s": hashes,
                "atomic_token_reservation": inventory[-1],
                "atomic_token_reservation_sha256": hashes[-1],
            },
        }
    )


def _with_request_limit_inventory(
    record: UsageRecord,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
    request_limit_maximum: int = 10,
) -> UsageRecord:
    plan = request_token_plan_from_usage(record)
    assert plan is not None
    inventory = tuple(
        AtomicRequestLimitReservationEvidence.build(
            request_id=(
                record.request_id if attempt == 1 else f"{record.request_id}:attempt:{attempt}"
            ),
            exact_model_id=record.requested_model,
            role=record.role,
            request_token_plan_sha256=plan.plan_sha256,
            request_limit_scope=request_limit_scope,
            request_limit_count_before=request_limit_count_before + attempt - 1,
            request_limit_maximum=request_limit_maximum,
        )
        for attempt in range(1, record.attempts + 1)
    )
    final = inventory[-1]
    return record.model_copy(
        update={
            "routing": {
                **record.routing,
                "atomic_request_limit_reservations": [
                    item.model_dump(mode="json") for item in inventory
                ],
                "atomic_request_limit_reservation_sha256s": [
                    item.evidence_sha256 for item in inventory
                ],
                "atomic_request_limit_reservation": final.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": final.evidence_sha256,
            }
        }
    )


def _owned_request_limit_record(
    request_id: str,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
) -> UsageRecord:
    provisional = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL).model_copy(
        update={"request_id": request_id}
    )
    plan, atomic = _token_plan_for_record(provisional, request_id=request_id)
    planned = provisional.model_copy(
        update={
            "routing": {
                **provisional.routing,
                "selected_provider_name": provisional.provider,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
            }
        }
    )
    bound = bind_synthetic_usage_identity(planned)
    return reattest_synthetic_real_usage(
        _with_request_limit_inventory(
            bound,
            request_limit_scope=request_limit_scope,
            request_limit_count_before=request_limit_count_before,
        )
    )


def test_ordinary_request_limit_inventory_remains_task_local_and_zero_based() -> None:
    record = _with_request_limit_inventory(
        _retry_token_bound_creditable_record(),
        request_limit_scope="request-test",
        request_limit_count_before=0,
    )

    plan = request_token_plan_from_usage(record)
    assert plan is not None
    inventory = atomic_request_limit_reservations_from_usage(record, plan)
    assert tuple(item.request_limit_scope for item in inventory) == (
        record.request_id,
        record.request_id,
    )
    assert tuple(item.request_limit_count_before for item in inventory) == (0, 1)
    assert tuple(item.request_limit_count_after for item in inventory) == (1, 2)


def test_recovery_request_limit_inventory_requires_external_root_and_exact_start() -> None:
    record = _with_request_limit_inventory(
        _retry_token_bound_creditable_record(),
        request_limit_scope="campaign-root-request",
        request_limit_count_before=7,
    )

    with pytest.raises(ValueError, match="scheduled usage request-limit attempts"):
        request_token_plan_from_usage(record)
    assert not is_creditable_usage_record(record)

    plan = recovery_request_token_plan_from_usage(
        record,
        request_limit_scope="campaign-root-request",
        request_limit_count_before=7,
    )
    assert plan is not None
    inventory = recovery_atomic_request_limit_reservations_from_usage(
        record,
        plan,
        request_limit_scope="campaign-root-request",
        request_limit_count_before=7,
    )
    assert tuple(item.request_limit_count_before for item in inventory) == (7, 8)
    assert tuple(item.request_limit_count_after for item in inventory) == (8, 9)

    with pytest.raises(ValueError, match="incomplete or unordered"):
        recovery_atomic_request_limit_reservations_from_usage(
            record,
            plan,
            request_limit_scope="different-root-request",
            request_limit_count_before=7,
        )
    with pytest.raises(ValueError, match="incomplete or unordered"):
        recovery_atomic_request_limit_reservations_from_usage(
            record,
            plan,
            request_limit_scope="campaign-root-request",
            request_limit_count_before=8,
        )


def test_recovery_request_limit_inventory_rejects_per_record_maximum_drift() -> None:
    record = _with_request_limit_inventory(
        _retry_token_bound_creditable_record(),
        request_limit_scope="campaign-root-request",
        request_limit_count_before=3,
    )
    plan = recovery_request_token_plan_from_usage(
        record,
        request_limit_scope="campaign-root-request",
        request_limit_count_before=3,
    )
    assert plan is not None
    first = AtomicRequestLimitReservationEvidence.model_validate(
        record.routing["atomic_request_limit_reservations"][0]
    )
    second = AtomicRequestLimitReservationEvidence.build(
        request_id=f"{record.request_id}:attempt:2",
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=plan.plan_sha256,
        request_limit_scope="campaign-root-request",
        request_limit_count_before=4,
        request_limit_maximum=11,
    )
    drifted = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "atomic_request_limit_reservations": [
                    first.model_dump(mode="json"),
                    second.model_dump(mode="json"),
                ],
                "atomic_request_limit_reservation_sha256s": [
                    first.evidence_sha256,
                    second.evidence_sha256,
                ],
                "atomic_request_limit_reservation": second.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": second.evidence_sha256,
            }
        }
    )

    with pytest.raises(ValueError, match="incomplete or unordered"):
        recovery_atomic_request_limit_reservations_from_usage(
            drifted,
            plan,
            request_limit_scope="campaign-root-request",
            request_limit_count_before=3,
        )


def test_recovery_credit_requires_owned_real_usage_and_exact_coordinates() -> None:
    root_scope = "family-root-request"
    record = _owned_request_limit_record(
        "family-root-request.child-a",
        request_limit_scope=root_scope,
        request_limit_count_before=1,
    )

    assert is_recovery_creditable_usage_record(
        record,
        request_limit_scope=root_scope,
        request_limit_count_before=1,
        require_real=True,
    )
    assert not is_creditable_usage_record(record, require_real=True)
    assert not is_recovery_creditable_usage_record(
        record,
        request_limit_scope="different-root-request",
        request_limit_count_before=1,
        require_real=True,
    )
    assert not is_recovery_creditable_usage_record(
        record,
        request_limit_scope=root_scope,
        request_limit_count_before=2,
        require_real=True,
    )

    serialized = UsageRecord.model_validate(record.model_dump(mode="json"))
    assert not is_recovery_creditable_usage_record(
        serialized,
        request_limit_scope=root_scope,
        request_limit_count_before=1,
        require_real=True,
    )
    assert is_structurally_recovery_creditable_usage_record(
        serialized,
        request_limit_scope=root_scope,
        request_limit_count_before=1,
        require_real=True,
    )


def test_usage_recovery_scope_rebinds_mixed_ordinary_and_recovery_real_usage() -> None:
    root_scope = "family-root-request"
    root = _owned_request_limit_record(
        root_scope,
        request_limit_scope=root_scope,
        request_limit_count_before=0,
    )
    child = _owned_request_limit_record(
        "family-root-request.child-a",
        request_limit_scope=root_scope,
        request_limit_count_before=1,
    )
    serialized = tuple(
        UsageRecord.model_validate(record.model_dump(mode="json")) for record in (root, child)
    )
    assert is_structurally_recovery_creditable_usage_record(
        serialized[1],
        request_limit_scope=root_scope,
        request_limit_count_before=1,
        require_real=True,
    )
    scope = _issue_trusted_usage_recovery_scope(
        serialized,
        recovery_request_limit_coordinates=((child.request_id, root_scope, 1),),
    )

    recovered = _recover_trusted_usage_records(serialized, scope)

    assert is_creditable_usage_record(recovered[0], require_real=True)
    assert not _has_authrunner_owned_real_usage_origin(recovered[0])
    assert is_recovery_creditable_usage_record(
        recovered[1],
        request_limit_scope=root_scope,
        request_limit_count_before=1,
        require_real=True,
    )
    assert not _has_authrunner_owned_real_usage_origin(recovered[1])
    with pytest.raises(ValueError, match="invalid or consumed"):
        _recover_trusted_usage_records(serialized, scope)


def test_usage_recovery_scope_rejects_gap_root_swap_and_coordinate_drift() -> None:
    root_scope = "family-root-request"
    records = (
        _owned_request_limit_record(
            root_scope,
            request_limit_scope=root_scope,
            request_limit_count_before=0,
        ),
        _owned_request_limit_record(
            "family-root-request.child-a",
            request_limit_scope=root_scope,
            request_limit_count_before=1,
        ),
        _owned_request_limit_record(
            "family-root-request.child-b",
            request_limit_scope=root_scope,
            request_limit_count_before=3,
        ),
    )
    serialized = tuple(
        UsageRecord.model_validate(record.model_dump(mode="json")) for record in records
    )

    with pytest.raises(ValueError, match="coordinate chain is inconsistent"):
        _issue_trusted_usage_recovery_scope(
            serialized,
            recovery_request_limit_coordinates=(
                (records[1].request_id, root_scope, 1),
                (records[2].request_id, root_scope, 3),
            ),
        )
    with pytest.raises(ValueError, match="invalid recovery-scoped usage"):
        _issue_trusted_usage_recovery_scope(
            serialized,
            recovery_request_limit_coordinates=(
                (records[1].request_id, "different-root-request", 1),
            ),
        )
    with pytest.raises(ValueError, match="invalid recovery-scoped usage"):
        _issue_trusted_usage_recovery_scope(
            serialized,
            recovery_request_limit_coordinates=(
                (records[1].request_id, root_scope, 3),
                (records[2].request_id, root_scope, 1),
            ),
        )
    with pytest.raises(ValueError, match="not exact and sorted"):
        _issue_trusted_usage_recovery_scope(
            serialized,
            recovery_request_limit_coordinates=(
                (records[2].request_id, root_scope, 3),
                (records[1].request_id, root_scope, 1),
            ),
        )


def test_usage_recovery_scope_interleaves_exact_no_usage_transition() -> None:
    root_scope = "family-root-request"
    root = _owned_request_limit_record(
        root_scope,
        request_limit_scope=root_scope,
        request_limit_count_before=0,
    )
    later = _owned_request_limit_record(
        "family-root-request.child-b",
        request_limit_scope=root_scope,
        request_limit_count_before=2,
    )
    serialized = tuple(
        UsageRecord.model_validate(record.model_dump(mode="json")) for record in (root, later)
    )
    maximum = atomic_request_limit_reservations_from_usage(root)[0].request_limit_maximum
    transition = ("family-root-request.child-release", root_scope, 1, 2, maximum)
    scope = _issue_trusted_usage_recovery_scope(
        serialized,
        recovery_request_limit_coordinates=((later.request_id, root_scope, 2),),
        non_usage_request_limit_transitions=(transition,),
    )

    recovered = _recover_trusted_usage_records(serialized, scope)

    assert is_creditable_usage_record(recovered[0], require_real=True)
    assert is_recovery_creditable_usage_record(
        recovered[1],
        request_limit_scope=root_scope,
        request_limit_count_before=2,
        require_real=True,
    )
    with pytest.raises(ValueError, match="invalid or consumed"):
        _recover_trusted_usage_records(serialized, scope)
    copied = copy(scope)
    with pytest.raises(ValueError, match="invalid or consumed"):
        _recover_trusted_usage_records(serialized, copied)


@pytest.mark.parametrize(
    "variant, error",
    [
        ("unknown-root", "unknown root scope"),
        ("overlap", "chain is inconsistent"),
        ("atomic-id-collision", "not exact and sorted"),
        ("wrong-maximum", "chain is inconsistent"),
    ],
)
def test_usage_recovery_scope_rejects_invalid_no_usage_transition(
    variant: str,
    error: str,
) -> None:
    root_scope = "family-root-request"
    root = _owned_request_limit_record(
        root_scope,
        request_limit_scope=root_scope,
        request_limit_count_before=0,
    )
    later = _owned_request_limit_record(
        "family-root-request.child-b",
        request_limit_scope=root_scope,
        request_limit_count_before=2,
    )
    serialized = tuple(
        UsageRecord.model_validate(record.model_dump(mode="json")) for record in (root, later)
    )
    maximum = atomic_request_limit_reservations_from_usage(root)[0].request_limit_maximum
    transitions = {
        "unknown-root": (
            "family-root-request.child-release",
            "unknown-root-request",
            1,
            2,
            maximum,
        ),
        "overlap": (
            "family-root-request.child-release",
            root_scope,
            2,
            3,
            maximum,
        ),
        "atomic-id-collision": (root.request_id, root_scope, 1, 2, maximum),
        "wrong-maximum": (
            "family-root-request.child-release",
            root_scope,
            1,
            2,
            maximum - 1,
        ),
    }

    with pytest.raises(ValueError, match=error):
        _issue_trusted_usage_recovery_scope(
            serialized,
            recovery_request_limit_coordinates=((later.request_id, root_scope, 2),),
            non_usage_request_limit_transitions=(transitions[variant],),
        )


def test_usage_recovery_scope_rejects_duplicate_no_usage_transition_identity() -> None:
    root_scope = "family-root-request"
    root = _owned_request_limit_record(
        root_scope,
        request_limit_scope=root_scope,
        request_limit_count_before=0,
    )
    later = _owned_request_limit_record(
        "family-root-request.child-c",
        request_limit_scope=root_scope,
        request_limit_count_before=3,
    )
    serialized = tuple(
        UsageRecord.model_validate(record.model_dump(mode="json")) for record in (root, later)
    )
    maximum = atomic_request_limit_reservations_from_usage(root)[0].request_limit_maximum
    duplicate_id = "family-root-request.child-release"

    with pytest.raises(ValueError, match="not exact and sorted"):
        _issue_trusted_usage_recovery_scope(
            serialized,
            recovery_request_limit_coordinates=((later.request_id, root_scope, 3),),
            non_usage_request_limit_transitions=(
                (duplicate_id, root_scope, 1, 2, maximum),
                (duplicate_id, root_scope, 2, 3, maximum),
            ),
        )


def test_recovery_plan_rejects_oversized_attempt_count_before_nested_materialization() -> None:
    record = _with_request_limit_inventory(
        _token_bound_creditable_record(),
        request_limit_scope="family-root-request",
        request_limit_count_before=1,
    ).model_copy(update={"attempts": 34, "retry_count": 33})

    with pytest.raises(ValueError, match="compiled bound"):
        recovery_request_token_plan_from_usage(
            record,
            request_limit_scope="family-root-request",
            request_limit_count_before=1,
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


def test_creditable_usage_accepts_matching_plan_and_atomic_reservation() -> None:
    record = _token_bound_creditable_record()

    plan = request_token_plan_from_usage(record)
    assert plan is not None
    assert plan.request_id == record.request_id
    assert plan.role == record.role
    assert plan.route_intersection.exact_model_ids == (record.requested_model,)
    assert is_creditable_usage_record(record)


@pytest.mark.parametrize(
    ("observed_reasoning_tokens", "creditable"),
    [
        pytest.param(1, True, id="positive-observation"),
        pytest.param(0, False, id="observed-zero"),
        pytest.param(None, False, id="observation-unavailable"),
    ],
)
def test_active_reasoning_credit_requires_a_positive_observation(
    observed_reasoning_tokens: int | None,
    creditable: bool,
) -> None:
    record = _reasoning_token_bound_creditable_record(observed_reasoning_tokens)

    assert is_creditable_usage_record(record) is creditable


def test_legacy_token_plan_raw_shape_is_parseable_but_not_creditable() -> None:
    record = _token_bound_creditable_record()
    current = request_token_plan_from_usage(record)
    assert current is not None
    legacy_payload = current.model_dump(mode="json", exclude={"plan_sha256"})
    legacy_payload["schema_version"] = "1.0"
    legacy_payload.pop("reasoning_plan")
    legacy_raw = {
        **legacy_payload,
        "plan_sha256": canonical_sha256(legacy_payload),
    }
    legacy_plan = RequestTokenPlan.model_validate_json(json.dumps(legacy_raw))
    atomic = AtomicTokenReservationEvidence.build(
        request_id=record.request_id,
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=legacy_plan.plan_sha256,
        planned_prompt_tokens=legacy_plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=legacy_plan.reserved_output_tokens,
        planned_reasoning_tokens=legacy_plan.reserved_reasoning_tokens,
        planned_completion_tokens=legacy_plan.requested_completion_tokens,
        global_input_token_limit=legacy_plan.global_budget.global_input_token_budget,
        global_output_token_limit=legacy_plan.global_budget.global_output_token_budget,
        spent_input_tokens_before=0,
        reserved_input_tokens_before=0,
        spent_output_tokens_before=0,
        reserved_output_tokens_before=0,
    )
    legacy_record = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "request_token_plan": legacy_raw,
                "request_token_plan_sha256": legacy_plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
            }
        }
    )

    restored = request_token_plan_from_usage(legacy_record)
    assert restored is not None
    assert restored.schema_version == "1.0"
    assert restored.reasoning_plan is None
    assert not is_creditable_usage_record(legacy_record)
    assert build_context_manifest(
        run_id="legacy-token-plan",
        usage_records=[legacy_record],
    ).requests

    noncanonical_raw = dict(legacy_raw)
    noncanonical_raw["reasoning_plan"] = None
    noncanonical_record = legacy_record.model_copy(
        update={
            "routing": {
                **legacy_record.routing,
                "request_token_plan": noncanonical_raw,
            }
        }
    )
    with pytest.raises(ValueError, match="differs from its request"):
        request_token_plan_from_usage(noncanonical_record)


def test_usage_and_context_reject_atomic_reservation_split_reallocation() -> None:
    record = _token_bound_creditable_record()
    plan = request_token_plan_from_usage(record)
    assert plan is not None
    shifted = AtomicTokenReservationEvidence.build(
        request_id=record.request_id,
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=plan.plan_sha256,
        planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=plan.reserved_output_tokens - 1,
        planned_reasoning_tokens=plan.reserved_reasoning_tokens + 1,
        planned_completion_tokens=plan.requested_completion_tokens,
        global_input_token_limit=plan.global_budget.global_input_token_budget,
        global_output_token_limit=plan.global_budget.global_output_token_budget,
        spent_input_tokens_before=0,
        reserved_input_tokens_before=0,
        spent_output_tokens_before=0,
        reserved_output_tokens_before=0,
    )
    shifted_record = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "atomic_token_reservations": [shifted.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [shifted.evidence_sha256],
                "atomic_token_reservation": shifted.model_dump(mode="json"),
                "atomic_token_reservation_sha256": shifted.evidence_sha256,
            }
        }
    )

    with pytest.raises(ValueError, match="differs from its token plan"):
        request_token_plan_from_usage(shifted_record)
    assert not is_creditable_usage_record(shifted_record)
    with pytest.raises(ContextManifestError, match="token-reservation"):
        build_context_manifest(
            run_id="shifted-token-reservation",
            usage_records=[shifted_record],
        )


def test_creditable_usage_rejects_reasoning_above_its_reserved_slice() -> None:
    record = _creditable_record()
    plan, atomic = _token_plan_for_record(record, reserved_reasoning_tokens=10)
    overrun = record.model_copy(
        update={
            "reasoning_tokens": 11,
            "routing": {
                **record.routing,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
            },
        }
    )

    assert not is_creditable_usage_record(overrun)


def test_creditable_usage_rejects_visible_output_above_its_reserved_slice() -> None:
    record = _creditable_record()
    plan, atomic = _token_plan_for_record(record, reserved_reasoning_tokens=10)
    overrun = record.model_copy(
        update={
            "completion_tokens": 522,
            "reasoning_tokens": 0,
            "total_tokens": 622,
            "routing": {
                **record.routing,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
            },
        }
    )

    assert not is_creditable_usage_record(overrun)


@pytest.mark.parametrize(
    "routing_field",
    [
        "request_token_plan_sha256",
        "atomic_token_reservation_sha256",
    ],
)
def test_creditable_usage_rejects_tampered_token_evidence_hash(
    routing_field: str,
) -> None:
    record = _token_bound_creditable_record()

    assert not is_creditable_usage_record(
        record.model_copy(
            update={
                "routing": {
                    **record.routing,
                    routing_field: "0" * 64,
                }
            }
        )
    )


def test_creditable_usage_rejects_valid_atomic_reservation_for_different_plan() -> None:
    record = _token_bound_creditable_record()
    _different_plan, different_atomic = _token_plan_for_record(
        record,
        reserved_reasoning_tokens=75,
    )
    swapped = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "atomic_token_reservation": different_atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": different_atomic.evidence_sha256,
            }
        }
    )

    with pytest.raises(ValueError, match="differs from its token plan"):
        request_token_plan_from_usage(swapped)
    assert not is_creditable_usage_record(swapped)


@pytest.mark.parametrize(
    ("request_id", "role", "model"),
    [
        ("other-request", None, None),
        (None, "business_logic", None),
        (None, None, "other/model"),
    ],
)
def test_creditable_usage_rejects_self_consistent_plan_for_other_request_identity(
    request_id: str | None,
    role: str | None,
    model: str | None,
) -> None:
    record = _token_bound_creditable_record()
    foreign_plan, foreign_atomic = _token_plan_for_record(
        record,
        request_id=request_id,
        role=role,
        exact_model_id=model,
    )
    swapped = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "request_token_plan": foreign_plan.model_dump(mode="json"),
                "request_token_plan_sha256": foreign_plan.plan_sha256,
                "atomic_token_reservation": foreign_atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": foreign_atomic.evidence_sha256,
            }
        }
    )

    with pytest.raises(ValueError, match="differs from its request"):
        request_token_plan_from_usage(swapped)
    assert not is_creditable_usage_record(swapped)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "reordered",
        "wrong_attempt",
        "wrong_limit",
    ],
)
def test_retry_inventory_mutations_reject_usage_credit_and_context_manifest(
    mutation: str,
) -> None:
    record = _retry_token_bound_creditable_record()
    assert is_creditable_usage_record(record)
    assert build_context_manifest(run_id="retry-inventory", usage_records=[record])

    routing = dict(record.routing)
    inventory = [dict(item) for item in routing["atomic_token_reservations"]]
    hashes = list(routing["atomic_token_reservation_sha256s"])
    plan = request_token_plan_from_usage(record)
    assert plan is not None
    if mutation == "missing":
        routing.pop("atomic_token_reservations")
        routing.pop("atomic_token_reservation_sha256s")
    elif mutation == "duplicate":
        inventory[1] = dict(inventory[0])
        hashes[1] = hashes[0]
    elif mutation == "reordered":
        inventory.reverse()
        hashes.reverse()
    else:
        replacement = AtomicTokenReservationEvidence.build(
            request_id=(
                f"{record.request_id}:attempt:3"
                if mutation == "wrong_attempt"
                else f"{record.request_id}:attempt:2"
            ),
            exact_model_id=record.requested_model,
            role=record.role,
            request_token_plan_sha256=plan.plan_sha256,
            planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
            planned_visible_output_tokens=plan.reserved_output_tokens,
            planned_reasoning_tokens=plan.reserved_reasoning_tokens,
            planned_completion_tokens=plan.requested_completion_tokens,
            global_input_token_limit=(
                plan.global_budget.global_input_token_budget
                if mutation == "wrong_attempt"
                else plan.global_budget.global_input_token_budget - 1
            ),
            global_output_token_limit=plan.global_budget.global_output_token_budget,
            spent_input_tokens_before=record.prompt_tokens,
            reserved_input_tokens_before=0,
            spent_output_tokens_before=record.completion_tokens,
            reserved_output_tokens_before=0,
        )
        inventory[1] = replacement.model_dump(mode="json")
        hashes[1] = replacement.evidence_sha256
    if mutation != "missing":
        routing["atomic_token_reservations"] = inventory
        routing["atomic_token_reservation_sha256s"] = hashes
        routing["atomic_token_reservation"] = inventory[-1]
        routing["atomic_token_reservation_sha256"] = hashes[-1]
    mutated = record.model_copy(update={"routing": routing})

    assert not is_creditable_usage_record(mutated)
    with pytest.raises(ContextManifestError):
        build_context_manifest(run_id="retry-inventory", usage_records=[mutated])


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


def test_private_real_usage_requires_policy_evidence_when_all_policy_keys_are_stripped() -> None:
    record = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    routing = {
        key: value
        for key, value in record.routing.items()
        if "qualification" not in key
        and "certification" not in key
        and not key.startswith("audit_")
    }
    stripped = record.model_copy(update={"routing": routing})

    assert stripped.routing["privacy_source_classification"] == (
        PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
    )
    assert usage_requires_audit_policy_evidence(stripped)


_AUTHRUNNER_ORIGIN_ROUTES = (
    (
        "authrunner.candidate.primary:case-0123456789abcdef",
        "RELEASE_PINNED_MODEL_BENCHMARK",
        "RELEASE",
    ),
    (
        f"cross-lineage-{'1' * 64}",
        "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION",
        "RELEASE",
    ),
    (
        f"authrunner.smoke.r1.candidate.replay:{'2' * 64}",
        "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
        "NONCREDITING_SMOKE",
    ),
    (
        f"authrunner.smoke.r1.judge.primary:{'3' * 64}",
        "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
        "NONCREDITING_SMOKE",
    ),
    (
        f"authrunner.smoke.r2.candidate.primary:{'4' * 64}",
        "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
        "NONCREDITING_SMOKE",
    ),
    (
        f"authrunner.smoke.r10.judge.replay:{'5' * 64}",
        "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
        "NONCREDITING_SMOKE",
    ),
    (
        f"authrunner.smoke.r999999999.candidate.replay:{'6' * 64}",
        "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
        "NONCREDITING_SMOKE",
    ),
)


@pytest.mark.parametrize(
    ("request_id", "expected_proof_kind", "expected_scope"), _AUTHRUNNER_ORIGIN_ROUTES
)
@pytest.mark.parametrize(
    "actual_proof_kind",
    tuple(item[1] for item in _AUTHRUNNER_ORIGIN_ROUTES),
)
def test_authrunner_origin_scope_is_a_closed_four_way_namespace_map(
    request_id: str,
    expected_proof_kind: str,
    expected_scope: str,
    actual_proof_kind: str,
) -> None:
    source = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = source.model_copy(
        update={
            "request_id": request_id,
            "role": "model_benchmark",
            "routing": {
                **source.routing,
                "privacy_source_proof_kind": actual_proof_kind,
            },
        }
    )

    if actual_proof_kind == expected_proof_kind:
        assert _authrunner_usage_origin_scope(record) == expected_scope
    else:
        with pytest.raises(ValueError, match="does not match its closed request namespace"):
            _authrunner_usage_origin_scope(record)


@pytest.mark.parametrize("run_label", ("r0", "r01", "r1000000000"))
def test_authrunner_smoke_origin_scope_rejects_out_of_range_or_noncanonical_run_index(
    run_label: str,
) -> None:
    source = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = source.model_copy(
        update={
            "request_id": f"authrunner.smoke.{run_label}.candidate.primary:{'7' * 64}",
            "role": "model_benchmark",
            "routing": {
                **source.routing,
                "privacy_source_proof_kind": "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
            },
        }
    )

    with pytest.raises(ValueError, match="does not match its closed request namespace"):
        _authrunner_usage_origin_scope(record)


@pytest.mark.parametrize(
    ("proof_kind", "expected_scope"),
    (
        ("RELEASE_PINNED_MODEL_BENCHMARK", "RELEASE"),
        ("RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION", "RELEASE"),
        ("PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK", "raises"),
        ("PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION", "raises"),
    ),
)
def test_nonclosed_uuid_only_preserves_legacy_release_proof_kinds(
    proof_kind: str,
    expected_scope: str,
) -> None:
    source = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = source.model_copy(
        update={
            "request_id": "123e4567-e89b-42d3-a456-426614174000",
            "role": "model_benchmark",
            "routing": {
                **source.routing,
                "privacy_source_proof_kind": proof_kind,
            },
        }
    )

    if expected_scope == "raises":
        with pytest.raises(ValueError, match="does not match its closed request namespace"):
            _authrunner_usage_origin_scope(record)
    else:
        assert _authrunner_usage_origin_scope(record) == expected_scope


@pytest.mark.parametrize(
    ("request_id", "raises"),
    (
        ("123e4567-e89b-42d3-a456-426614174000", False),
        ("authrunner.candidate.primary:case-0123456789abcdef", True),
    ),
)
def test_authrunner_origin_scope_handles_non_string_proof_kinds(
    request_id: str,
    raises: bool,
) -> None:
    source = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    record = source.model_copy(
        update={
            "request_id": request_id,
            "role": "model_benchmark",
            "routing": {
                **source.routing,
                "privacy_source_proof_kind": {},
            },
        }
    )

    if raises:
        with pytest.raises(ValueError, match="lacks its closed privacy proof kind"):
            _authrunner_usage_origin_scope(record)
    else:
        assert _authrunner_usage_origin_scope(record) is None


@pytest.mark.parametrize(
    "source_classification",
    (
        PrivacySourceClassification.PUBLIC_BENCHMARK,
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
    ),
)
def test_detached_prequalification_claim_cannot_recreate_live_policy_exemption(
    source_classification: PrivacySourceClassification,
) -> None:
    record = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    prequalification = record.model_copy(
        update={
            "role": "model_benchmark",
            "routing": {
                **record.routing,
                "privacy_profile": PrivacyProfile.SYNTHETIC_BENCHMARK.value,
                "privacy_source_classification": source_classification.value,
                "privacy_source_proof_kind": "RELEASE_PINNED_MODEL_BENCHMARK",
            },
        }
    )

    assert usage_requires_audit_policy_evidence(prequalification)
    token_plan, reservation = _token_plan_for_record(prequalification)
    prequalification = prequalification.model_copy(
        update={
            "routing": {
                **prequalification.routing,
                "request_token_plan": token_plan.model_dump(mode="json"),
                "request_token_plan_sha256": token_plan.plan_sha256,
                "atomic_token_reservations": [reservation.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [reservation.evidence_sha256],
                "atomic_token_reservation": reservation.model_dump(mode="json"),
                "atomic_token_reservation_sha256": reservation.evidence_sha256,
            }
        }
    )
    reparsed = UsageRecord.model_validate_json(prequalification.model_dump_json())
    assert usage_requires_audit_policy_evidence(reparsed)


@pytest.mark.parametrize(
    "source_proof_kind",
    (
        "PACKAGE_PINNED_SYNTHETIC",
        "DISTRIBUTION_COMMITTED_SYNTHETIC",
    ),
)
def test_generic_synthetic_prequalification_proof_does_not_grant_policy_exemption(
    source_proof_kind: str,
) -> None:
    record = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    prequalification = record.model_copy(
        update={
            "role": "model_benchmark",
            "routing": {
                **record.routing,
                "privacy_profile": PrivacyProfile.SYNTHETIC_BENCHMARK.value,
                "privacy_source_classification": (
                    PrivacySourceClassification.SYNTHETIC_COMMITTED.value
                ),
                "privacy_source_proof_kind": source_proof_kind,
            },
        }
    )

    assert usage_requires_audit_policy_evidence(prequalification)


def test_prequalification_role_string_does_not_exempt_private_real_usage() -> None:
    record = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    role_only = record.model_copy(update={"role": "model_benchmark"})

    assert usage_requires_audit_policy_evidence(role_only)


def test_usage_subclass_cannot_bypass_detached_policy_custody() -> None:
    class UsageRecordSubclass(UsageRecord):
        pass

    record = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    subclass_record = UsageRecordSubclass.model_validate(record.model_dump(mode="python"))

    assert usage_requires_audit_policy_evidence(subclass_record)


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


def test_structured_output_routing_diagnostics_cover_each_nonidentity_clause() -> None:
    record = _creditable_record()
    structured = dict(record.routing["structured_output"])
    endpoint = record.actual_provider_endpoint or ""

    def evidence(**updates: Any) -> dict[str, object]:
        arguments: dict[str, Any] = {
            "configured_provider_endpoints": tuple(record.configured_provider_endpoints),
            "selected_provider_endpoint": endpoint,
            "endpoint_snapshot_sha256": record.routing["endpoint_snapshot_sha256"],
            "output_capability_sha256": record.routing["output_capability_sha256"],
            "prompt_sha256": record.prompt_sha256,
            "request_body_sha256": record.request_body_sha256 or "",
            "provider_policy_sha256": record.routing["provider_policy_sha256"],
            "schema_sha256": record.schema_sha256 or "",
            "original_response_sha256": record.response_sha256 or "",
            "validated_response_sha256": record.validated_response_sha256 or "",
        }
        arguments.update(updates)
        return synthetic_structured_output_routing(**arguments)

    def routed(
        structured_output: object = structured,
        *,
        routing_updates: dict[str, object] | None = None,
        record_updates: dict[str, object] | None = None,
    ) -> UsageRecord:
        updates = dict(record_updates or {})
        updates["routing"] = {
            **record.routing,
            "structured_output": structured_output,
            **(routing_updates or {}),
        }
        return record.model_copy(update=updates)

    other_endpoint = "other-endpoint"
    configured_elsewhere = evidence(
        configured_provider_endpoints=(endpoint, other_endpoint),
    )
    selected_elsewhere = evidence(
        configured_provider_endpoints=(endpoint, other_endpoint),
        selected_provider_endpoint=other_endpoint,
    )
    shape_routing = {
        "structured_output_mode": structured["requested_mode"],
        "structured_output_request_shape_sha256": structured["request_shape_sha256"],
        "structured_output_require_parameters": structured["provider_require_parameters"],
        "structured_output_required_provider_parameters": structured[
            "required_provider_parameters"
        ],
        "structured_output_reasoning_request_sha256": structured["reasoning_request_sha256"],
        "structured_output_response_format": structured["response_format"],
        "structured_output_protocol_sha256": structured["strict_protocol_sha256"],
    }
    redundant_routing = {
        "structured_output_supported_modes": [
            mode.value
            for mode in supported_output_modes(structured["endpoint_structured_output_parameters"])
        ],
        "structured_output_capability_sha256": structured["output_capability_sha256"],
        "structured_output_request_body_sha256": structured["request_body_sha256"],
        "structured_output_original_response_sha256": structured["original_response_sha256"],
        "structured_output_validated_response_sha256": structured["validated_response_sha256"],
    }
    canary = "must-not-appear-in-structured-routing-diagnostics"
    cases = (
        ("STRUCTURED_OUTPUT_ROUTING:EVIDENCE_TYPE", routed(None)),
        (
            "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_SCHEMA",
            routed({**structured, "schema_version": "2.0"}),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:EVIDENCE_CANONICAL",
            routed(
                {
                    **structured,
                    "configured_provider_endpoints": tuple(
                        structured["configured_provider_endpoints"]
                    ),
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED",
            routed({**structured, "repair_evidence": {"canary": canary}}),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:TRUNCATED",
            routed({**structured, "truncated": True}),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUESTED_MODE_MISMATCH",
            routed(
                {
                    **structured,
                    "achieved_mode": StructuredOutputMode.VALIDATED_TEXT_JSON.value,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:CONFIGURED_PROVIDER_ENDPOINTS",
            routed(configured_elsewhere),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:SELECTED_PROVIDER_ENDPOINT",
            routed(
                selected_elsewhere,
                record_updates={
                    "configured_provider_endpoints": [endpoint, other_endpoint],
                },
            ),
        ),
        ("STRUCTURED_OUTPUT_ROUTING:PROMPT_SHA256", routed(evidence(prompt_sha256="0" * 64))),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_BODY_SHA256",
            routed(evidence(request_body_sha256="0" * 64)),
        ),
        ("STRUCTURED_OUTPUT_ROUTING:SCHEMA_SHA256", routed(evidence(schema_sha256="0" * 64))),
        (
            "STRUCTURED_OUTPUT_ROUTING:ORIGINAL_RESPONSE_SHA256",
            routed(evidence(original_response_sha256="0" * 64)),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:VALIDATED_RESPONSE_SHA256",
            routed(evidence(validated_response_sha256="0" * 64)),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:PROVIDER_POLICY_SHA256",
            routed(evidence(provider_policy_sha256="0" * 64)),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:ENDPOINT_SNAPSHOT_SHA256",
            routed(evidence(endpoint_snapshot_sha256="0" * 64)),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:OUTPUT_CAPABILITY_SHA256",
            routed(evidence(output_capability_sha256="0" * 64)),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED_ROUTING",
            routed(routing_updates={"repair_used": True}),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_MODE",
            routed(routing_updates={**shape_routing, "structured_output_mode": canary}),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_SHA256",
            routed(
                routing_updates={
                    **shape_routing,
                    "structured_output_request_shape_sha256": "0" * 64,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRE_PARAMETERS",
            routed(
                routing_updates={
                    **shape_routing,
                    "structured_output_require_parameters": False,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REQUIRED_PROVIDER_PARAMETERS",
            routed(
                routing_updates={
                    **shape_routing,
                    "structured_output_required_provider_parameters": [],
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_REASONING_REQUEST_SHA256",
            routed(
                routing_updates={
                    **shape_routing,
                    "structured_output_reasoning_request_sha256": "0" * 64,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_RESPONSE_FORMAT",
            routed(
                routing_updates={
                    **shape_routing,
                    "structured_output_response_format": canary,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_PROTOCOL_SHA256",
            routed(
                routing_updates={
                    **shape_routing,
                    "structured_output_protocol_sha256": "0" * 64,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_SUPPORTED_MODES",
            routed(
                routing_updates={
                    **redundant_routing,
                    "structured_output_supported_modes": [],
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_CAPABILITY_SHA256",
            routed(
                routing_updates={
                    **redundant_routing,
                    "structured_output_capability_sha256": "0" * 64,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_REQUEST_BODY_SHA256",
            routed(
                routing_updates={
                    **redundant_routing,
                    "structured_output_request_body_sha256": "0" * 64,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_ORIGINAL_RESPONSE_SHA256",
            routed(
                routing_updates={
                    **redundant_routing,
                    "structured_output_original_response_sha256": "0" * 64,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_VALIDATED_RESPONSE_SHA256",
            routed(
                routing_updates={
                    **redundant_routing,
                    "structured_output_validated_response_sha256": "0" * 64,
                }
            ),
        ),
    )

    assert usage_module._structured_output_routing_failure_code(record) is None
    assert _legacy_has_valid_structured_output_routing(record)
    assert usage_module._has_valid_structured_output_routing(record)
    assert (
        tuple(expected for expected, _invalid in cases)
        == (STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES[:-6])
    )
    for expected, invalid in cases:
        diagnostic = usage_module._structured_output_routing_failure_code(invalid)
        assert diagnostic == expected
        assert diagnostic in STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES
        assert canary not in diagnostic
        assert usage_module._has_valid_structured_output_routing(
            invalid
        ) is _legacy_has_valid_structured_output_routing(invalid)
        assert not _legacy_has_valid_structured_output_routing(invalid)
        assert not is_creditable_usage_record(invalid)
    ordered_multi_clause_cases = (
        (
            "STRUCTURED_OUTPUT_ROUTING:REPAIR_USED",
            routed(
                {
                    **structured,
                    "repair_evidence": {"canary": canary},
                    "truncated": True,
                    "achieved_mode": StructuredOutputMode.VALIDATED_TEXT_JSON.value,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:CONFIGURED_PROVIDER_ENDPOINTS",
            routed(selected_elsewhere),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REQUEST_SHAPE_MODE",
            routed(
                routing_updates={
                    **shape_routing,
                    "structured_output_mode": canary,
                    "structured_output_request_shape_sha256": "0" * 64,
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:REDUNDANT_SUPPORTED_MODES",
            routed(
                routing_updates={
                    **redundant_routing,
                    "structured_output_supported_modes": [],
                    "structured_output_capability_sha256": "0" * 64,
                }
            ),
        ),
    )
    for expected, invalid in ordered_multi_clause_cases:
        assert usage_module._structured_output_routing_failure_code(invalid) == expected
        assert usage_module._has_valid_structured_output_routing(
            invalid
        ) is _legacy_has_valid_structured_output_routing(invalid)


def test_structured_output_routing_preserves_optional_and_unbound_semantics() -> None:
    record = _creditable_record()
    structured = record.routing["structured_output"]
    request_shape_without_optional_none = {
        "structured_output_mode": structured["requested_mode"],
        "structured_output_request_shape_sha256": structured["request_shape_sha256"],
        "structured_output_require_parameters": 1,
        "structured_output_required_provider_parameters": structured[
            "required_provider_parameters"
        ],
        "structured_output_response_format": structured["response_format"],
        "structured_output_protocol_sha256": structured["strict_protocol_sha256"],
    }
    optional_projection = record.model_copy(
        update={
            "routing": {
                **record.routing,
                **request_shape_without_optional_none,
                "structured_output_request_body_sha256": structured["request_body_sha256"],
            }
        }
    )
    malformed_optional_binding = optional_projection.model_copy(
        update={
            "routing": {
                **optional_projection.routing,
                "identity_binding": {"untrusted": "ignored-by-legacy-optional-binding"},
            }
        }
    )

    for accepted in (record, optional_projection, malformed_optional_binding):
        assert usage_module._structured_output_routing_failure_code(accepted) is None
        assert usage_module._has_valid_structured_output_routing(
            accepted
        ) is _legacy_has_valid_structured_output_routing(accepted)
        assert _legacy_has_valid_structured_output_routing(accepted)
        assert is_creditable_usage_record(accepted)


def test_structured_output_routing_diagnostics_cover_each_identity_clause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    binding = OpenRouterIdentityBindingResult.model_validate(record.routing["identity_binding"])
    snapshot = binding.snapshot
    capabilities = snapshot.endpoint_capabilities
    cases = (
        (
            "STRUCTURED_OUTPUT_ROUTING:IDENTITY_ENDPOINT_SNAPSHOT_SHA256",
            binding.model_copy(
                update={
                    "snapshot": snapshot.model_copy(update={"endpoint_snapshot_sha256": "0" * 64})
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:IDENTITY_OUTPUT_CAPABILITY_SHA256",
            binding.model_copy(
                update={
                    "snapshot": snapshot.model_copy(
                        update={
                            "endpoint_capabilities": capabilities.model_copy(
                                update={"output_capability_sha256": "0" * 64}
                            )
                        }
                    )
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:IDENTITY_MODE",
            binding.model_copy(
                update={
                    "snapshot": snapshot.model_copy(
                        update={
                            "endpoint_capabilities": capabilities.model_copy(
                                update={
                                    "structured_output_mode": (
                                        StructuredOutputMode.VALIDATED_TEXT_JSON
                                    )
                                }
                            )
                        }
                    )
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:IDENTITY_PARAMETER_SUBSET",
            binding.model_copy(
                update={
                    "snapshot": snapshot.model_copy(
                        update={
                            "endpoint_capabilities": capabilities.model_copy(
                                update={"structured_output_parameters": ()}
                            )
                        }
                    )
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS",
            binding.model_copy(
                update={
                    "snapshot": snapshot.model_copy(
                        update={
                            "endpoint_capabilities": capabilities.model_copy(
                                update={"required_parameters": ("max_tokens", "temperature")}
                            )
                        }
                    )
                }
            ),
        ),
        (
            "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRE_PARAMETERS",
            binding.model_copy(
                update={
                    "snapshot": snapshot.model_copy(
                        update={
                            "provider_policy": snapshot.provider_policy.model_copy(
                                update={"require_parameters": False}
                            )
                        }
                    )
                }
            ),
        ),
    )

    assert usage_module._structured_output_routing_failure_code(record) is None
    assert (
        tuple(expected for expected, _binding in cases)
        == (STRUCTURED_OUTPUT_ROUTING_FAILURE_CODES[-6:])
    )
    for expected, invalid_binding in cases:
        with monkeypatch.context() as context:
            context.setattr(
                usage_module,
                "_validated_identity_binding",
                lambda _record, result=invalid_binding: result,
            )
            assert usage_module._structured_output_routing_failure_code(record) == expected
            assert usage_module._has_valid_structured_output_routing(
                record
            ) is _legacy_has_valid_structured_output_routing(record)
            assert not _legacy_has_valid_structured_output_routing(record)
            assert not is_creditable_usage_record(record)

    endpoint_and_capability_mismatch = cases[0][1].model_copy(
        update={
            "snapshot": cases[0][1].snapshot.model_copy(
                update={
                    "endpoint_capabilities": capabilities.model_copy(
                        update={"output_capability_sha256": "0" * 64}
                    )
                }
            )
        }
    )
    with monkeypatch.context() as context:
        context.setattr(
            usage_module,
            "_validated_identity_binding",
            lambda _record: endpoint_and_capability_mismatch,
        )
        assert usage_module._structured_output_routing_failure_code(record) == (
            "STRUCTURED_OUTPUT_ROUTING:IDENTITY_ENDPOINT_SNAPSHOT_SHA256"
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
