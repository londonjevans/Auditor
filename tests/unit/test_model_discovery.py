from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from mmaudit.constants import OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.discovery import (
    _TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    OPENROUTER_CATALOG_QUERY,
    OPENROUTER_ZDR_QUERY,
    DataCollectionDenyEvidenceSource,
    DiscoveryCandidateRoute,
    DiscoveryEndpointMetadataBinding,
    DiscoveryModelMetadataBinding,
    ModelDiscoveryValidationError,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
    _issue_real_openrouter_discovery_run,
    load_model_discovery_evidence,
    load_model_discovery_run,
    openrouter_endpoint_query,
    openrouter_model_query,
    require_openrouter_constrained_discovery_publication,
    require_openrouter_live_discovery_equivalence,
    validate_openrouter_constrained_model_discovery,
    validate_openrouter_model_discovery,
    write_model_discovery_run,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    OpenRouterEndpointSnapshotEvidence,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterPrivacyError,
    _detach_exact_discovery_json_object,
    _revalidate_openrouter_discovery_payload,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningPolicyArtifact,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    RoutePredicateProfile,
)
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    EndpointPolicyClass,
    EndpointPrivacyDisclosure,
    PrivacyProfile,
    PrivacySourceClassification,
)


def _endpoint(
    *,
    model: str = "alpha/atlas-secure",
    endpoint_id: str = "approved-provider/fp8",
    context_length: int = 200_000,
    max_prompt_tokens: int | None = None,
    max_completion_tokens: int | None = None,
    supported_reasoning_efforts: tuple[str, ...] | None = (
        "none",
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    ),
) -> dict[str, Any]:
    endpoint: dict[str, Any] = {
        "model_id": model,
        "slug": endpoint_id,
        "provider_name": "Approved Provider",
        "status": 0,
        "context_length": context_length,
        "max_prompt_tokens": max_prompt_tokens,
        "max_completion_tokens": max_completion_tokens,
        "supported_parameters": [
            "max_tokens",
            "reasoning",
            "response_format",
            "structured_outputs",
            "temperature",
        ],
        "pricing": {
            "completion": "0.000002",
            "prompt": "0.000001",
        },
    }
    if supported_reasoning_efforts is not None:
        endpoint["reasoning"] = {
            "supported_efforts": list(supported_reasoning_efforts),
        }
    return endpoint


def _endpoint_snapshot(
    *,
    model: str = "alpha/atlas-secure",
    endpoint_id: str = "approved-provider/fp8",
    context_length: int = 200_000,
    max_completion_tokens: int | None = None,
    supported_reasoning_efforts: tuple[str, ...] | None = (
        "none",
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    ),
) -> OpenRouterEndpointSnapshotEvidence:
    exact_endpoint = _endpoint(
        model=model,
        endpoint_id=endpoint_id,
        context_length=context_length,
        max_completion_tokens=max_completion_tokens,
        supported_reasoning_efforts=supported_reasoning_efforts,
    )
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(endpoint_id,),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": model,
                "endpoints": [
                    {key: value for key, value in exact_endpoint.items() if key != "model_id"}
                ],
            }
        },
        require_zdr=True,
        zdr_payload={"data": [exact_endpoint]},
        reasoning_requested=False,
    )


def _model(
    *,
    model: str = "alpha/atlas-secure",
    canonical_slug: str = "alpha/atlas-secure-20260727",
    context_length: int = 200_000,
    provider_context_length: int | None = None,
    max_completion_tokens: int | None = None,
) -> dict[str, Any]:
    return {
        "id": model,
        "canonical_slug": canonical_slug,
        "context_length": context_length,
        "top_provider": {
            "context_length": provider_context_length,
            "max_completion_tokens": max_completion_tokens,
            "is_moderated": False,
        },
        "supported_parameters": [
            "structured_outputs",
            "temperature",
            "response_format",
            "reasoning",
            "max_tokens",
        ],
        "reasoning": {
            "mandatory": False,
            "default_enabled": True,
            "supported_efforts": [
                "none",
                "minimal",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
            ],
        },
        "description": "provider-controlled prose excluded from evidence",
        "benchmarks": {"untrusted": [1, 2, 3]},
        "links": {"details": "https://invalid.example/provider-controlled"},
    }


def _consent_bound_policy() -> EffectivePrivacyPolicyEvidence:
    disclosure = EndpointPrivacyDisclosure(
        provider_endpoint="approved-provider/fp8",
        policy_class=EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,
        disclosed_retention="Synthetic retention disclosure.",
        privacy_policy_reference="https://privacy.example.test/approved-provider",
        privacy_policy_sha256="a" * 64,
    )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "privacy_profile": PrivacyProfile.FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT,
        "source_classification": PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        "source_sha256": "b" * 64,
        "source_provenance_sha256": "f" * 64,
        "source_proof_kind": "PRIVATE_DEFAULT",
        "source_distribution_commit": None,
        "source_distribution_scope": None,
        "source_synthetic_declaration_sha256": None,
        "source_synthetic_declaration_entry_sha256": None,
        "require_zdr": False,
        "data_collection": "deny",
        "permitted_model_ids": ("alpha/atlas-secure",),
        "permitted_provider_endpoints": ("approved-provider/fp8",),
        "endpoint_policy_classes": (EndpointPolicyClass.NON_ZDR_DATA_COLLECTION_DENIED,),
        "endpoint_disclosures": (disclosure,),
        "consent_file_sha256": "c" * 64,
        "consent_file_size": 1_024,
        "consent_sha256": "d" * 64,
        "consent_issued_at": datetime(2026, 7, 28, tzinfo=UTC),
        "consent_expires_at": datetime(2026, 7, 30, tzinfo=UTC),
        "operator_reference_sha256": "e" * 64,
        "consent_maximum_cost_usd": "20",
        "requested_budget_usd": "20",
        "limitations": (
            "At least one consent-bound provider endpoint does not enforce zero-data-retention.",
        ),
    }
    provisional = EffectivePrivacyPolicyEvidence.model_construct(
        **payload,
        evidence_sha256="0" * 64,
    )
    serialized = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
    payload["evidence_sha256"] = hashlib.sha256(
        json.dumps(serialized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return EffectivePrivacyPolicyEvidence.model_validate(payload)


def _discover(
    *,
    models: list[dict[str, Any]] | None = None,
    endpoint_snapshot: OpenRouterEndpointSnapshotEvidence | None = None,
    exact_model_id: str = "alpha/atlas-secure",
) -> OpenRouterModelDiscoveryPayload:
    selected_models = models or [_model()]
    single_model = next(
        (item for item in selected_models if item.get("id") == exact_model_id),
        selected_models[0],
    )
    return validate_openrouter_model_discovery(
        exact_model_id=exact_model_id,
        models_payload={"data": selected_models},
        single_model_payload={"data": copy.deepcopy(single_model)},
        endpoint_snapshot=endpoint_snapshot or _endpoint_snapshot(),
    )


def _constrained_route_bundle() -> tuple[
    ReasoningPolicyArtifact,
    RoutePredicateProfile,
    ExactRouteConstraint,
]:
    control = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=4_096,
    )
    policy = ReasoningPolicyArtifact.build(
        controls_by_role={role: control for role in CANONICAL_REASONING_POLICY_ROLES}
    )
    role_policy = policy.role_policy_for_request("model_benchmark")
    profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=policy.artifact_sha256,
        reasoning_role_profile_sha256=policy.role_profile.profile_sha256,
        reasoning_role_binding_sha256=role_policy.binding_sha256,
        reasoning_control_profile_sha256=control.profile_sha256,
        reserved_reasoning_tokens=4_096,
        minimum_prompt_tokens=100_000,
        required_output_tokens=4_096,
        minimum_context_tokens=120_000,
    )
    constraint = ExactRouteConstraint.build(
        role=ExactRouteRole.CANDIDATE,
        exact_model_id="alpha/atlas-secure",
        provider_endpoint="approved-provider/fp8",
        profile=profile,
    )
    return policy, profile, constraint


def _constrained_discover(
    *,
    model: dict[str, Any] | None = None,
    endpoint: dict[str, Any] | None = None,
    automatic_fallbacks_allowed: bool = False,
) -> tuple[
    OpenRouterModelDiscoveryPayload,
    RoutePredicateProfile,
    ExactRouteConstraint,
]:
    selected_model = model or _model(max_completion_tokens=20_000)
    selected_endpoint = endpoint or _endpoint(
        max_prompt_tokens=180_000,
        max_completion_tokens=20_000,
    )
    policy, profile, constraint = _constrained_route_bundle()
    payload = validate_openrouter_constrained_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [selected_model]},
        single_model_payload={"data": copy.deepcopy(selected_model)},
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [
                    {key: value for key, value in selected_endpoint.items() if key != "model_id"}
                ],
            }
        },
        require_zdr=True,
        zdr_payload={"data": [selected_endpoint]},
        route_predicate_profile=profile,
        exact_route_constraint=constraint,
        expected_selection_plan_sha256="1" * 64,
        reasoning_policy=policy,
        automatic_fallbacks_allowed=automatic_fallbacks_allowed,
    )
    return payload, profile, constraint


def _real_evidence(
    payloads: tuple[OpenRouterModelDiscoveryPayload, ...] | None = None,
) -> tuple[OpenRouterModelDiscoveryEvidence, ...]:
    selected = payloads or (_discover(),)
    routes = tuple(
        DiscoveryCandidateRoute(
            exact_model_id=payload.exact_model_id,
            approved_provider_endpoint=payload.approved_provider_endpoint,
        )
        for payload in selected
    )
    endpoint_bindings = tuple(
        DiscoveryEndpointMetadataBinding(
            exact_model_id=payload.exact_model_id,
            api_query=openrouter_endpoint_query(payload.exact_model_id),
            response_snapshot_sha256=payload.endpoint_snapshot.endpoint_metadata_sha256,
        )
        for payload in selected
    )
    model_bindings = tuple(
        DiscoveryModelMetadataBinding(
            exact_model_id=payload.exact_model_id,
            canonical_slug=payload.canonical_slug,
            api_query=openrouter_model_query(payload.exact_model_id),
            response_snapshot_sha256="e" * 64,
            model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
        )
        for payload in selected
    )
    provenance, evidence = _issue_real_openrouter_discovery_run(
        run_id="1" * 32,
        retrieved_at=datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
        client_fingerprint_sha256="a" * 64,
        provider_fingerprint_sha256="b" * 64,
        catalog_snapshot_sha256="c" * 64,
        zdr_snapshot_sha256="d" * 64,
        candidate_routes=routes,
        model_metadata_bindings=model_bindings,
        endpoint_metadata_bindings=endpoint_bindings,
        payloads=selected,
        issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    )
    assert provenance.catalog_api_query == OPENROUTER_CATALOG_QUERY
    assert provenance.zdr_api_query == OPENROUTER_ZDR_QUERY
    return evidence


def test_current_like_null_limits_are_derived_and_exact_endpoint_is_bound() -> None:
    payload = _discover()
    evidence = _real_evidence((payload,))[0]

    assert evidence.exact_model_id == "alpha/atlas-secure"
    assert evidence.canonical_slug == "alpha/atlas-secure-20260727"
    assert evidence.catalog_provider_context_size == 200_000
    assert evidence.catalog_provider_context_size_source == "catalog_context"
    assert evidence.catalog_output_limit == 200_000
    assert evidence.catalog_output_limit_source == "provider_context"
    assert evidence.context_size == 200_000
    assert evidence.output_limit == 200_000
    assert evidence.approved_provider_endpoint == "approved-provider/fp8"
    assert evidence.operational is True
    assert evidence.zdr_eligible is True
    assert evidence.data_collection_deny_eligible is True
    assert evidence.data_collection_deny_request_policy_enforced is True
    assert (
        evidence.data_collection_deny_evidence_source
        is DataCollectionDenyEvidenceSource.ZDR_ENDPOINT_SNAPSHOT
    )
    assert evidence.data_collection_deny_evidence_sha256
    assert evidence.data_collection_deny_evidence_expires_at is None
    assert evidence.structured_output_supported is True
    assert evidence.supported_output_modes == (
        StructuredOutputMode.NATIVE_JSON_SCHEMA,
        StructuredOutputMode.JSON_OBJECT,
        StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    assert evidence.structured_output_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
    assert len(evidence.output_capability_sha256) == 64
    assert evidence.reasoning_supported is True
    assert evidence.reasoning_capability.reasoning_parameter_support == "supported"
    assert evidence.reasoning_capability.reasoning_metadata_available is True
    assert evidence.reasoning_capability.reasoning_mandatory is False
    assert evidence.reasoning_capability.reasoning_default_enabled is True
    assert evidence.reasoning_capability.reasoning_supports_max_tokens is None
    assert evidence.reasoning_capability.max_reasoning_tokens is None
    assert (
        evidence.reasoning_capability.model_metadata_snapshot_sha256
        == evidence.model_metadata_snapshot_sha256
    )
    assert (
        evidence.reasoning_capability.endpoint_metadata_snapshot_sha256
        == evidence.endpoint_record_sha256
    )
    assert len(evidence.reasoning_capability.capability_sha256) == 64
    assert len(evidence.catalog_identity_binding_sha256) == 64
    assert len(evidence.model_metadata_snapshot_sha256) == 64
    assert len(evidence.discovery_evidence_sha256) == 64
    assert evidence.provenance.execution_evidence.value == "real"
    assert evidence.provenance.authenticated_metadata is True
    assert evidence.provenance.retrieved_at.microsecond == 0


def test_constrained_discovery_custodies_and_rechecks_complete_route_report() -> None:
    payload, profile, constraint = _constrained_discover()

    report = require_openrouter_constrained_discovery_publication(
        payload,
        route_predicate_profile=profile,
        exact_route_constraint=constraint,
        expected_selection_plan_sha256="1" * 64,
    )

    snapshot = payload.endpoint_snapshot
    assert snapshot.route_predicate_profile == profile
    assert snapshot.exact_route_constraint == constraint
    assert snapshot.normalized_route_facts is not None
    assert snapshot.route_predicate_report == report
    assert report.facts_sha256 == snapshot.normalized_route_facts.facts_sha256
    assert OpenRouterModelDiscoveryPayload.model_validate_json(payload.model_dump_json()) == payload


def test_constrained_discovery_observation_replay_preserves_route_custody() -> None:
    model = _model(max_completion_tokens=20_000)
    endpoint = _endpoint(
        max_prompt_tokens=180_000,
        max_completion_tokens=20_000,
    )
    policy, profile, constraint = _constrained_route_bundle()
    models_payload = {"data": [model]}
    single_model_payload = {"data": copy.deepcopy(model)}
    endpoint_payload = {
        "data": {
            "id": "alpha/atlas-secure",
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }
    zdr_payload = {"data": [endpoint]}
    supplied = validate_openrouter_constrained_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload=models_payload,
        single_model_payload=single_model_payload,
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload=endpoint_payload,
        require_zdr=True,
        zdr_payload=zdr_payload,
        route_predicate_profile=profile,
        exact_route_constraint=constraint,
        expected_selection_plan_sha256="1" * 64,
        reasoning_policy=policy,
        automatic_fallbacks_allowed=False,
    )

    observed = _revalidate_openrouter_discovery_payload(
        supplied_discovery=supplied,
        models_payload=models_payload,
        single_model_payload=single_model_payload,
        endpoint_payload=endpoint_payload,
        zdr_payload=zdr_payload,
        route=DiscoveryCandidateRoute(
            exact_model_id="alpha/atlas-secure",
            approved_provider_endpoint="approved-provider/fp8",
        ),
        reasoning_policy=policy,
        automatic_fallbacks_allowed=False,
        effective_privacy_policy=None,
    )

    assert observed == supplied
    assert observed.endpoint_snapshot.route_predicate_report is not None


def test_generic_discovery_observation_replay_remains_custody_free() -> None:
    model = _model()
    endpoint = _endpoint()
    models_payload = {"data": [model]}
    single_model_payload = {"data": copy.deepcopy(model)}
    endpoint_payload = {
        "data": {
            "id": "alpha/atlas-secure",
            "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
        }
    }
    zdr_payload = {"data": [endpoint]}
    supplied = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(),
    )

    observed = _revalidate_openrouter_discovery_payload(
        supplied_discovery=supplied,
        models_payload=models_payload,
        single_model_payload=single_model_payload,
        endpoint_payload=endpoint_payload,
        zdr_payload=zdr_payload,
        route=DiscoveryCandidateRoute(
            exact_model_id="alpha/atlas-secure",
            approved_provider_endpoint="approved-provider/fp8",
        ),
        reasoning_policy=None,
        automatic_fallbacks_allowed=False,
        effective_privacy_policy=None,
    )

    assert observed == supplied
    assert observed.endpoint_snapshot.route_predicate_report is None


def test_constrained_discovery_live_equivalence_reconstructs_strict_embedded_models() -> None:
    payload, _, _ = _constrained_discover()
    evidence = _real_evidence((payload,))[0]

    require_openrouter_live_discovery_equivalence(
        canonical_slug=payload.canonical_slug,
        current_endpoint=payload.endpoint_snapshot,
        current_model=payload,
        frozen_evidence=evidence,
    )


def test_generic_discovery_cannot_satisfy_selected_plan_publication_post_hoc() -> None:
    payload = _discover()
    _, profile, constraint = _constrained_route_bundle()

    with pytest.raises(
        ModelDiscoveryValidationError,
        match="lacks complete route predicate evidence",
    ):
        require_openrouter_constrained_discovery_publication(
            payload,
            route_predicate_profile=profile,
            exact_route_constraint=constraint,
            expected_selection_plan_sha256="1" * 64,
        )


def test_constrained_discovery_rejects_fallback_and_wrong_plan_custody() -> None:
    with pytest.raises(EndpointSnapshotValidationError, match="AUTOMATIC_FALLBACK_ENABLED"):
        _constrained_discover(automatic_fallbacks_allowed=True)

    payload, profile, constraint = _constrained_discover()
    with pytest.raises(ModelDiscoveryValidationError, match="selected-plan custody"):
        require_openrouter_constrained_discovery_publication(
            payload,
            route_predicate_profile=profile,
            exact_route_constraint=constraint,
            expected_selection_plan_sha256="2" * 64,
        )


def test_constrained_discovery_applies_model_reasoning_facts_before_publication() -> None:
    model = _model(max_completion_tokens=20_000)
    model["reasoning"]["supported_efforts"] = ["high"]
    endpoint = _endpoint(
        max_prompt_tokens=180_000,
        max_completion_tokens=20_000,
        supported_reasoning_efforts=None,
    )
    payload, _, _ = _constrained_discover(model=model, endpoint=endpoint)
    assert payload.endpoint_snapshot.normalized_route_facts is not None
    assert payload.endpoint_snapshot.normalized_route_facts.model_supported_reasoning_efforts == (
        "high",
    )

    endpoint_without_reasoning = copy.deepcopy(endpoint)
    endpoint_without_reasoning["supported_parameters"].remove("reasoning")
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="EMITTED_PARAMETER_SUPPORT_MISMATCH",
    ):
        _constrained_discover(model=model, endpoint=endpoint_without_reasoning)

    model_without_reasoning = copy.deepcopy(model)
    model_without_reasoning["supported_parameters"].remove("reasoning")
    model_without_reasoning.pop("reasoning")
    endpoint_with_reasoning = _endpoint(
        max_prompt_tokens=180_000,
        max_completion_tokens=20_000,
        supported_reasoning_efforts=("high",),
    )
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="EMITTED_PARAMETER_SUPPORT_MISMATCH",
    ):
        _constrained_discover(
            model=model_without_reasoning,
            endpoint=endpoint_with_reasoning,
        )

    endpoint["reasoning"] = {"supported_efforts": ["high", "xhigh"]}
    with pytest.raises(
        EndpointSnapshotValidationError,
        match="REASONING_EFFORT_INVENTORY_CONTRADICTORY",
    ):
        _constrained_discover(model=model, endpoint=endpoint)


def test_constrained_discovery_rejects_partial_route_custody_during_final_validation() -> None:
    payload, _, _ = _constrained_discover()
    serialized = payload.model_dump(mode="json")
    del serialized["endpoint_snapshot"]["route_predicate_report"]

    with pytest.raises(ValidationError, match="all present or absent"):
        OpenRouterModelDiscoveryPayload.model_validate_json(json.dumps(serialized))


def test_catalog_discovery_does_not_pre_filter_privacy_or_output_capability() -> None:
    assert OPENROUTER_CATALOG_QUERY == "/models"


def test_non_zdr_non_native_endpoint_remains_a_capability_candidate() -> None:
    model = _model()
    model["supported_parameters"] = ["max_tokens", "temperature"]
    endpoint = _endpoint()
    endpoint["supported_parameters"] = ["max_tokens", "temperature"]
    endpoint.pop("reasoning")
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        structured_output_required=False,
    )

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [model]},
        single_model_payload={"data": copy.deepcopy(model)},
        endpoint_snapshot=snapshot,
    )

    assert payload.zdr_eligible is None
    assert payload.data_collection_deny_eligible is False
    assert payload.data_collection_deny_request_policy_enforced is False
    assert (
        payload.data_collection_deny_evidence_source is DataCollectionDenyEvidenceSource.UNVERIFIED
    )
    assert payload.data_collection_deny_evidence_sha256 is None
    assert payload.structured_output_supported is False
    assert payload.structured_output_parameters == ()
    assert payload.supported_output_modes == (StructuredOutputMode.VALIDATED_TEXT_JSON,)
    assert payload.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON


def test_reasoning_aliases_do_not_authorize_the_emitted_reasoning_request() -> None:
    model = _model()
    model["supported_parameters"] = [
        "max_tokens",
        "reasoning_effort",
        "response_format",
        "temperature",
    ]
    endpoint = _endpoint()
    endpoint["supported_parameters"] = [
        "max_tokens",
        "reasoning_effort",
        "response_format",
        "temperature",
    ]
    endpoint.pop("reasoning")
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        reasoning_requested=False,
        structured_output_required=False,
    )

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [model]},
        single_model_payload={"data": copy.deepcopy(model)},
        endpoint_snapshot=snapshot,
    )

    assert payload.reasoning_parameters == ("reasoning_effort",)
    assert payload.reasoning_supported is False
    assert payload.reasoning_capability.reasoning_parameter_support == "unsupported"
    assert payload.reasoning_capability.reasoning_metadata_available is True
    assert payload.reasoning_capability.reasoning_default_enabled is True


def test_missing_reasoning_object_preserves_unknown_states_without_inference() -> None:
    model = _model()
    model.pop("reasoning")

    payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(supported_reasoning_efforts=None),
    )
    capability = payload.reasoning_capability

    assert capability.reasoning_parameter_support == "supported"
    assert capability.reasoning_metadata_available is False
    assert capability.reasoning_mandatory is None
    assert capability.reasoning_default_enabled is None
    assert capability.reasoning_supports_max_tokens is None
    assert capability.supported_reasoning_efforts is None
    assert capability.max_reasoning_tokens is None
    serialized = payload.model_dump(mode="json")
    assert serialized["reasoning_capability"]["reasoning_mandatory"] is None
    assert serialized["reasoning_capability"]["reasoning_supports_max_tokens"] is None
    assert serialized["reasoning_capability"]["supported_reasoning_efforts"] is None


def test_explicit_reasoning_max_token_ceiling_is_frozen_when_published() -> None:
    model = _model()
    model["reasoning"] = {
        "mandatory": False,
        "default_enabled": True,
        "supports_max_tokens": True,
        "supported_efforts": ["none", "high"],
        "max_tokens": 4_096,
    }

    payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(
            supported_reasoning_efforts=("none", "high"),
        ),
    )

    assert payload.reasoning_capability.reasoning_supports_max_tokens is True
    assert payload.reasoning_capability.max_reasoning_tokens == 4_096
    assert len(payload.reasoning_capability.capability_sha256) == 64


def test_catalog_accepts_max_default_effort_and_canonicalizes_inventory() -> None:
    model = _model()
    model["reasoning"]["default_effort"] = "max"
    model["reasoning"]["supported_efforts"] = ["max", "xhigh", "none"]

    payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(
            supported_reasoning_efforts=("none", "xhigh", "max"),
        ),
    )

    assert payload.model_supported_reasoning_efforts == ("none", "xhigh", "max")
    assert payload.reasoning_capability.supported_reasoning_efforts == (
        "none",
        "xhigh",
        "max",
    )


def test_discovery_prefers_exact_endpoint_reasoning_effort_inventory() -> None:
    model = _model()

    payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(
            supported_reasoning_efforts=("max", "xhigh", "none", "medium"),
        ),
    )

    assert payload.reasoning_capability.supported_reasoning_efforts == (
        "none",
        "medium",
        "xhigh",
        "max",
    )

    unknown_payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(supported_reasoning_efforts=None),
    )
    assert unknown_payload.reasoning_supported is True
    assert unknown_payload.reasoning_capability.supported_reasoning_efforts is None
    unknown_payload.require_compatible_reasoning_profile(
        ReasoningControlProfile.build(
            mode="effort",
            effort="max",
            reserved_reasoning_tokens=4_096,
        )
    )


@pytest.mark.parametrize(
    ("exact_model_id", "default_enabled"),
    [
        ("deepseek/deepseek-v4-pro-0813", None),
        ("moonshotai/kimi-k3", True),
    ],
)
def test_operator_observed_catalog_efforts_fill_absent_endpoint_inventory(
    exact_model_id: str,
    default_enabled: bool | None,
) -> None:
    model = _model(
        model=exact_model_id,
        canonical_slug=exact_model_id,
    )
    model["reasoning"] = {
        "default_enabled": default_enabled,
        "supported_efforts": ["low", "high", "max"],
    }
    payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(
            model=exact_model_id,
            supported_reasoning_efforts=None,
        ),
        exact_model_id=exact_model_id,
    )
    profile = ReasoningControlProfile.build(
        mode="effort",
        effort="max",
        reserved_reasoning_tokens=4_096,
    )

    assert payload.model_supported_reasoning_efforts == ("low", "high", "max")
    assert payload.reasoning_capability.supported_reasoning_efforts is None
    payload.require_compatible_reasoning_profile(profile)
    with pytest.raises(EndpointSnapshotValidationError, match="supported-effort inventory"):
        payload.reasoning_capability.require_compatible_profile(profile)


def test_explicit_endpoint_inventory_vetoes_broader_catalog_efforts() -> None:
    model = _model()
    model["reasoning"]["supported_efforts"] = ["low", "high", "max"]
    profile = ReasoningControlProfile.build(
        mode="effort",
        effort="max",
        reserved_reasoning_tokens=4_096,
    )

    narrower = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(
            supported_reasoning_efforts=("low", "high"),
        ),
    )
    with pytest.raises(EndpointSnapshotValidationError, match="absent from"):
        narrower.require_compatible_reasoning_profile(profile)

    explicitly_empty = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(supported_reasoning_efforts=()),
    )
    with pytest.raises(EndpointSnapshotValidationError, match="absent from"):
        explicitly_empty.require_compatible_reasoning_profile(profile)


def test_absent_model_and_endpoint_effort_metadata_remains_incompatible() -> None:
    model = _model(
        model="minimax/minimax-m3",
        canonical_slug="minimax/minimax-m3",
    )
    model.pop("reasoning")
    payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(
            model="minimax/minimax-m3",
            supported_reasoning_efforts=None,
        ),
        exact_model_id="minimax/minimax-m3",
    )

    with pytest.raises(EndpointSnapshotValidationError, match="frozen metadata"):
        payload.require_compatible_reasoning_profile(
            ReasoningControlProfile.build(
                mode="effort",
                effort="high",
                reserved_reasoning_tokens=4_096,
            )
        )


def test_empty_catalog_effort_inventory_does_not_claim_effort_support() -> None:
    model = _model()
    model["reasoning"]["supported_efforts"] = []
    payload = _discover(
        models=[model],
        endpoint_snapshot=_endpoint_snapshot(supported_reasoning_efforts=None),
    )

    assert payload.model_supported_reasoning_efforts == ()
    with pytest.raises(EndpointSnapshotValidationError, match="absent from"):
        payload.require_compatible_reasoning_profile(
            ReasoningControlProfile.build(
                mode="effort",
                effort="high",
                reserved_reasoning_tokens=4_096,
            )
        )


def test_catalog_effort_fallback_still_requires_endpoint_reasoning_parameter() -> None:
    model = _model()
    model["reasoning"]["supported_efforts"] = ["high"]
    endpoint = _endpoint(supported_reasoning_efforts=None)
    endpoint["supported_parameters"].remove("reasoning")
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=True,
        zdr_payload={"data": [endpoint]},
        reasoning_requested=False,
    )
    payload = _discover(models=[model], endpoint_snapshot=snapshot)

    with pytest.raises(EndpointSnapshotValidationError, match="explicit endpoint"):
        payload.require_compatible_reasoning_profile(
            ReasoningControlProfile.build(
                mode="effort",
                effort="high",
                reserved_reasoning_tokens=4_096,
            )
        )


def test_resealed_unavailable_metadata_cannot_gain_catalog_effort_fallback() -> None:
    payload = _discover(
        endpoint_snapshot=_endpoint_snapshot(supported_reasoning_efforts=None),
    ).model_dump(mode="json")
    capability = payload["reasoning_capability"]
    capability["reasoning_metadata_available"] = False
    capability["reasoning_mandatory"] = None
    capability["reasoning_default_enabled"] = None
    capability["reasoning_supports_max_tokens"] = None
    capability["max_reasoning_tokens"] = None
    capability["capability_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in capability.items() if key != "capability_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    with pytest.raises(
        ValidationError,
        match="unavailable model reasoning metadata cannot claim",
    ):
        OpenRouterModelDiscoveryPayload.model_validate(payload)


def test_endpoint_reasoning_effort_inventory_cannot_exceed_model_metadata() -> None:
    model = _model()
    model["reasoning"]["supported_efforts"] = ["none", "high"]

    with pytest.raises(ModelDiscoveryValidationError, match="exceeds model metadata"):
        _discover(
            models=[model],
            endpoint_snapshot=_endpoint_snapshot(
                supported_reasoning_efforts=("none", "xhigh"),
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mandatory", True),
        ("default_enabled", False),
        ("max_tokens", 2_048),
    ],
)
def test_catalog_and_single_model_reasoning_metadata_must_agree(
    field: str,
    value: object,
) -> None:
    catalog = _model()
    catalog["reasoning"] = {
        "mandatory": False,
        "default_enabled": True,
        "supports_max_tokens": True,
        "supported_efforts": ["none", "high"],
        "max_tokens": 4_096,
    }
    single = copy.deepcopy(catalog)
    single["reasoning"][field] = value

    with pytest.raises(ModelDiscoveryValidationError, match="frozen catalog projection"):
        validate_openrouter_model_discovery(
            exact_model_id="alpha/atlas-secure",
            models_payload={"data": [catalog]},
            single_model_payload={"data": single},
            endpoint_snapshot=_endpoint_snapshot(),
        )


def test_catalog_and_single_model_max_token_support_state_must_agree() -> None:
    catalog = _model()
    catalog["reasoning"]["supports_max_tokens"] = True
    catalog["reasoning"]["supported_efforts"] = ["none", "high"]
    catalog["reasoning"]["max_tokens"] = 4_096
    single = copy.deepcopy(catalog)
    single["reasoning"]["supports_max_tokens"] = False
    single["reasoning"].pop("max_tokens")

    with pytest.raises(ModelDiscoveryValidationError, match="frozen catalog projection"):
        validate_openrouter_model_discovery(
            exact_model_id="alpha/atlas-secure",
            models_payload={"data": [catalog]},
            single_model_payload={"data": single},
            endpoint_snapshot=_endpoint_snapshot(),
        )


@pytest.mark.parametrize(
    "reasoning",
    [
        "enabled",
        {"mandatory": "false"},
        {"default_enabled": 1},
        {"supports_max_tokens": "yes"},
        {"supports_max_tokens": True, "max_tokens": True},
        {"supports_max_tokens": True, "max_tokens": 65_537},
        {"supports_max_tokens": False, "max_tokens": 1_024},
        {"max_tokens": 1_024},
        {"supported_efforts": "high"},
        {"supported_efforts": ["high", "high"]},
        {"supported_efforts": ["very_high"]},
        {"supported_efforts": [True]},
    ],
)
def test_malformed_reasoning_metadata_fails_closed(reasoning: object) -> None:
    model = _model()
    model["reasoning"] = reasoning

    with pytest.raises(ModelDiscoveryValidationError, match="reasoning metadata"):
        _discover(models=[model])


def test_reasoning_metadata_is_bound_into_model_and_discovery_capability_hashes() -> None:
    baseline = _model()
    changed = copy.deepcopy(baseline)
    changed["reasoning"]["supported_efforts"].remove("xhigh")

    endpoint_snapshot = _endpoint_snapshot(
        supported_reasoning_efforts=("none", "high"),
    )
    first = _discover(models=[baseline], endpoint_snapshot=endpoint_snapshot)
    second = _discover(models=[changed], endpoint_snapshot=endpoint_snapshot)

    assert first.model_metadata_snapshot_sha256 != second.model_metadata_snapshot_sha256
    assert (
        first.reasoning_capability.capability_sha256
        != second.reasoning_capability.capability_sha256
    )
    assert first.output_capability_sha256 != second.output_capability_sha256


def test_catalog_and_single_model_reasoning_effort_inventories_must_agree() -> None:
    catalog = _model()
    single = copy.deepcopy(catalog)
    single["reasoning"]["supported_efforts"].remove("xhigh")

    with pytest.raises(ModelDiscoveryValidationError, match="frozen catalog projection"):
        validate_openrouter_model_discovery(
            exact_model_id="alpha/atlas-secure",
            models_payload={"data": [catalog]},
            single_model_payload={"data": single},
            endpoint_snapshot=_endpoint_snapshot(),
        )


def test_discovery_rejects_a_runtime_specific_reasoning_request_profile() -> None:
    endpoint = _endpoint()
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        reasoning_requested=True,
        structured_output_required=False,
    )

    with pytest.raises(ValidationError, match="capability-oriented"):
        validate_openrouter_model_discovery(
            exact_model_id="alpha/atlas-secure",
            models_payload={"data": [_model()]},
            single_model_payload={"data": _model()},
            endpoint_snapshot=snapshot,
        )


def test_equivalent_native_schema_markers_negotiate_native_mode() -> None:
    model = _model()
    model["supported_parameters"] = [
        "json_schema",
        "max_tokens",
        "response_format",
        "temperature",
    ]
    endpoint = _endpoint()
    endpoint["supported_parameters"] = [
        "max_tokens",
        "response_format",
        "structured_outputs",
        "temperature",
    ]
    endpoint.pop("reasoning")
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        reasoning_requested=False,
        structured_output_required=False,
    )

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [model]},
        single_model_payload={"data": copy.deepcopy(model)},
        endpoint_snapshot=snapshot,
    )

    assert payload.structured_output_parameters == ("response_format",)
    assert payload.structured_output_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
    assert payload.structured_output_supported is True


@pytest.mark.parametrize("marker", ["json_schema", "structured_outputs"])
def test_marker_without_response_format_falls_back_to_validated_text(marker: str) -> None:
    model = _model()
    model["supported_parameters"] = ["max_tokens", marker, "temperature"]
    endpoint = _endpoint()
    endpoint["supported_parameters"] = ["max_tokens", marker, "temperature"]
    endpoint.pop("reasoning")
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        reasoning_requested=False,
        structured_output_required=False,
    )

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [model]},
        single_model_payload={"data": copy.deepcopy(model)},
        endpoint_snapshot=snapshot,
    )

    assert payload.structured_output_parameters == (marker,)
    assert payload.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON
    assert payload.structured_output_supported is False


def test_non_zdr_endpoint_without_policy_remains_unverified() -> None:
    model = _model()
    endpoint = _endpoint()
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        structured_output_required=False,
    )

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [model]},
        single_model_payload={"data": copy.deepcopy(model)},
        endpoint_snapshot=snapshot,
    )

    assert payload.data_collection_deny_eligible is False
    assert payload.data_collection_deny_request_policy_enforced is False
    assert (
        payload.data_collection_deny_evidence_source is DataCollectionDenyEvidenceSource.UNVERIFIED
    )
    assert payload.data_collection_deny_evidence_sha256 is None


def test_model_and_endpoint_capabilities_negotiate_json_object_mode() -> None:
    model = _model()
    model["supported_parameters"].remove("structured_outputs")
    payload = _discover(models=[model])

    assert payload.structured_output_parameters == ("response_format",)
    assert payload.supported_output_modes == (
        StructuredOutputMode.JSON_OBJECT,
        StructuredOutputMode.VALIDATED_TEXT_JSON,
    )
    assert payload.structured_output_mode is StructuredOutputMode.JSON_OBJECT


def test_discovery_preserves_only_model_endpoint_common_native_markers() -> None:
    endpoint = _endpoint()
    endpoint["supported_parameters"].append("json_schema")
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        structured_output_required=False,
    )

    payload = _discover(endpoint_snapshot=snapshot)

    assert payload.endpoint_snapshot.endpoints[0].structured_output_parameters == (
        "json_schema",
        "response_format",
        "structured_outputs",
    )
    assert payload.structured_output_parameters == (
        "response_format",
        "structured_outputs",
    )
    assert payload.structured_output_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA


def test_discovery_rejects_tampered_negotiated_output_mode_and_capability_hash() -> None:
    payload = _discover().model_dump(mode="json")
    payload["structured_output_mode"] = StructuredOutputMode.JSON_OBJECT.value
    with pytest.raises(ValidationError, match="negotiated discovery output mode"):
        OpenRouterModelDiscoveryPayload.model_validate(payload)

    payload = _discover().model_dump(mode="json")
    payload["output_capability_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="output-capability hash"):
        OpenRouterModelDiscoveryPayload.model_validate(payload)

    payload = _discover().model_dump(mode="json")
    payload["reasoning_capability"]["capability_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="capability hash"):
        OpenRouterModelDiscoveryPayload.model_validate(payload)


def test_non_zdr_endpoint_credits_exact_consent_bound_policy_hash() -> None:
    model = _model()
    endpoint = _endpoint()
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        structured_output_required=False,
    )
    policy = _consent_bound_policy()

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [model]},
        single_model_payload={"data": copy.deepcopy(model)},
        endpoint_snapshot=snapshot,
        effective_privacy_policy=policy,
    )

    assert payload.data_collection_deny_eligible is False
    assert payload.data_collection_deny_request_policy_enforced is True
    assert (
        payload.data_collection_deny_evidence_source
        is DataCollectionDenyEvidenceSource.CONSENT_BOUND_ROUTER_REQUEST_POLICY
    )
    assert payload.data_collection_deny_evidence_sha256 == policy.evidence_sha256
    assert payload.data_collection_deny_evidence_expires_at == policy.consent_expires_at


def test_non_zdr_route_does_not_claim_zdr_snapshot_request_policy() -> None:
    model = _model()
    endpoint = _endpoint()
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id="alpha/atlas-secure",
        configured_provider_endpoints=("approved-provider/fp8",),
        provider_policy_mode="only",
        endpoint_payload={
            "data": {
                "id": "alpha/atlas-secure",
                "endpoints": [{key: value for key, value in endpoint.items() if key != "model_id"}],
            }
        },
        require_zdr=False,
        zdr_payload={"data": [endpoint]},
        structured_output_required=False,
    )

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [model]},
        single_model_payload={"data": copy.deepcopy(model)},
        endpoint_snapshot=snapshot,
    )

    assert payload.zdr_eligible is True
    assert payload.data_collection_deny_eligible is False
    assert payload.data_collection_deny_request_policy_enforced is False
    assert (
        payload.data_collection_deny_evidence_source is DataCollectionDenyEvidenceSource.UNVERIFIED
    )


def test_evidence_is_deterministic_and_excludes_freeform_catalog_fields() -> None:
    first = _model()
    second = copy.deepcopy(first)
    second["supported_parameters"] = list(reversed(second["supported_parameters"]))
    second["description"] = "different untrusted prose"
    second["benchmarks"] = {"forged": True}
    second["links"] = {"details": "https://different.invalid"}

    first_evidence = _discover(models=[first])
    second_evidence = _discover(models=[second])

    assert first_evidence == second_evidence
    serialized = json.dumps(first_evidence.model_dump(mode="json"), sort_keys=True)
    assert "provider-controlled prose" not in serialized
    assert "benchmarks" not in serialized
    assert "invalid.example" not in serialized


@pytest.mark.parametrize(
    "models,error",
    [
        ([_model(), _model()], "duplicate exact model"),
        ([_model(), {"canonical_slug": "beta/other"}], "missing or invalid"),
        ([_model(model="beta/other", canonical_slug="beta/other")], "unavailable"),
    ],
)
def test_catalog_rejects_duplicate_missing_and_unavailable_ids(
    models: list[dict[str, Any]],
    error: str,
) -> None:
    with pytest.raises(ModelDiscoveryValidationError, match=error):
        _discover(models=models)


def test_unrelated_catalog_aliases_are_not_eligible_candidates() -> None:
    payload = _discover(
        models=[
            _model(model="openrouter/auto", canonical_slug="openrouter/auto"),
            _model(),
        ]
    )

    assert payload.exact_model_id == "alpha/atlas-secure"


def test_unrelated_catalog_ids_outside_candidate_canonical_form_are_ignored() -> None:
    payload = _discover(
        models=[
            _model(model="Publisher/Model-V1", canonical_slug="Publisher/Model-V1"),
            _model(),
        ]
    )

    assert payload.exact_model_id == "alpha/atlas-secure"


@pytest.mark.parametrize(
    "model",
    [
        "openrouter/auto",
        "openrouter/router",
        "alpha/latest",
        "alpha/atlas:free",
        "alpha/atlas:latest",
        "openrouter/auto:online",
        "alpha/atlas:auto",
        "alpha/atlas-free",
        "alpha/atlas-latest",
        "alpha/atlas-online",
    ],
)
def test_requested_model_aliases_are_rejected(model: str) -> None:
    with pytest.raises(ModelDiscoveryValidationError, match="exact non-routed"):
        validate_openrouter_model_discovery(
            exact_model_id=model,
            models_payload={"data": [_model(model=model, canonical_slug=model)]},
            single_model_payload={"data": _model(model=model, canonical_slug=model)},
            endpoint_snapshot=_endpoint_snapshot(),
        )


def test_canonical_slug_is_explicit_catalog_evidence_not_a_prefix_heuristic() -> None:
    with pytest.raises(ModelDiscoveryValidationError, match="changes the requested model author"):
        _discover(models=[_model(canonical_slug="beta/atlas-secure-20260727")])

    payload = _discover(models=[_model(canonical_slug="alpha/unrelated-model")])
    assert payload.canonical_slug == "alpha/unrelated-model"
    assert payload.catalog_identity_binding_sha256

    with pytest.raises(ValidationError, match="different model"):
        _discover(endpoint_snapshot=_endpoint_snapshot(model="beta/other"))


def test_canonical_lookup_accepts_only_requested_or_canonical_model_identity() -> None:
    catalog_model = _model()
    canonical_model = copy.deepcopy(catalog_model)
    canonical_model["id"] = catalog_model["canonical_slug"]

    payload = validate_openrouter_model_discovery(
        exact_model_id="alpha/atlas-secure",
        models_payload={"data": [catalog_model]},
        single_model_payload={"data": canonical_model},
        endpoint_snapshot=_endpoint_snapshot(),
    )

    assert payload.exact_model_id == "alpha/atlas-secure"
    assert payload.canonical_slug == "alpha/atlas-secure-20260727"

    unrelated = copy.deepcopy(canonical_model)
    unrelated["id"] = "alpha/unrelated-model"
    with pytest.raises(ModelDiscoveryValidationError, match="identity differs"):
        validate_openrouter_model_discovery(
            exact_model_id="alpha/atlas-secure",
            models_payload={"data": [catalog_model]},
            single_model_payload={"data": unrelated},
            endpoint_snapshot=_endpoint_snapshot(),
        )


def test_single_model_metadata_binding_queries_exact_id_not_dated_canonical_slug() -> None:
    payload = _discover()
    binding = DiscoveryModelMetadataBinding(
        exact_model_id=payload.exact_model_id,
        canonical_slug=payload.canonical_slug,
        api_query=openrouter_model_query(payload.exact_model_id),
        response_snapshot_sha256="e" * 64,
        model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
    )

    assert binding.api_query == "/model/alpha/atlas-secure"
    with pytest.raises(ValidationError, match="exact model ID"):
        DiscoveryModelMetadataBinding(
            exact_model_id=payload.exact_model_id,
            canonical_slug=payload.canonical_slug,
            api_query=openrouter_model_query(payload.canonical_slug),
            response_snapshot_sha256="e" * 64,
            model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
        )


def test_catalog_and_exact_endpoint_limits_must_be_compatible() -> None:
    with pytest.raises(ValidationError, match="endpoint context exceeds"):
        _discover(
            models=[
                _model(
                    context_length=100_000,
                    provider_context_length=100_000,
                )
            ]
        )

    # The catalog's "top provider" is not necessarily the approved exact
    # endpoint, so its output limit is retained but is not used as a false cap.
    evidence = _discover(
        models=[
            _model(
                max_completion_tokens=20_000,
                provider_context_length=200_000,
            )
        ]
    )
    assert evidence.catalog_output_limit == 20_000
    assert evidence.output_limit == 200_000


def test_catalog_without_native_output_parameter_downgrades_to_validated_text() -> None:
    model = _model()
    model["supported_parameters"].remove("response_format")
    model["supported_parameters"].remove("structured_outputs")

    evidence = _discover(models=[model])

    assert evidence.supported_output_modes == (StructuredOutputMode.VALIDATED_TEXT_JSON,)
    assert evidence.structured_output_mode is StructuredOutputMode.VALIDATED_TEXT_JSON


def test_self_hashes_reject_metadata_and_artifact_tampering() -> None:
    structural = _discover()
    payload = structural.model_dump(mode="json")
    payload["model_metadata_snapshot_sha256"] = "a" * 64
    with pytest.raises(ValidationError, match="metadata projection hash"):
        OpenRouterModelDiscoveryPayload.model_validate(payload)

    evidence = _real_evidence((structural,))[0]
    payload = evidence.model_dump(mode="json")
    payload["discovery_evidence_sha256"] = "b" * 64
    with pytest.raises(ValidationError, match="evidence hash"):
        OpenRouterModelDiscoveryEvidence.model_validate(payload)


def test_real_provenance_requires_the_trusted_issuer_and_whole_second_utc() -> None:
    payload = _discover()
    route = DiscoveryCandidateRoute(
        exact_model_id=payload.exact_model_id,
        approved_provider_endpoint=payload.approved_provider_endpoint,
    )
    binding = DiscoveryEndpointMetadataBinding(
        exact_model_id=payload.exact_model_id,
        api_query=openrouter_endpoint_query(payload.exact_model_id),
        response_snapshot_sha256=payload.endpoint_snapshot.endpoint_metadata_sha256,
    )
    model_binding = DiscoveryModelMetadataBinding(
        exact_model_id=payload.exact_model_id,
        canonical_slug=payload.canonical_slug,
        api_query=openrouter_model_query(payload.exact_model_id),
        response_snapshot_sha256="e" * 64,
        model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
    )
    arguments = {
        "run_id": "1" * 32,
        "retrieved_at": datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
        "client_fingerprint_sha256": "a" * 64,
        "provider_fingerprint_sha256": "b" * 64,
        "catalog_snapshot_sha256": "c" * 64,
        "zdr_snapshot_sha256": "d" * 64,
        "candidate_routes": (route,),
        "model_metadata_bindings": (model_binding,),
        "endpoint_metadata_bindings": (binding,),
        "payloads": (payload,),
    }

    with pytest.raises(ModelDiscoveryValidationError, match="trusted OpenRouter client"):
        _issue_real_openrouter_discovery_run(**arguments, issuer=object())

    with pytest.raises(ValidationError, match="whole-second UTC"):
        _issue_real_openrouter_discovery_run(
            **{
                **arguments,
                "retrieved_at": datetime(2026, 7, 27, 8, 0, 0, 1, tzinfo=UTC),
            },
            issuer=_TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
        )


def test_real_discovery_replay_rejects_mutating_mapping_subclasses_before_hashing() -> None:
    class Flip(dict[str, Any]):
        items_called = False

        def items(self):  # type: ignore[no-untyped-def]
            self.items_called = True
            original = tuple(super().items())
            self["data"] = {"changed": True}
            return iter(original)

    payload = Flip({"data": {"id": "alpha/atlas-secure"}})
    with pytest.raises(OpenRouterPrivacyError, match="exact decoded JSON object"):
        _detach_exact_discovery_json_object(
            payload,
            label="synthetic discovery payload",
        )
    assert payload.items_called is False
    assert payload == {"data": {"id": "alpha/atlas-secure"}}

    nested = {"data": Flip({"id": "alpha/atlas-secure"})}
    with pytest.raises(OpenRouterPrivacyError, match="exact finite decoded JSON object"):
        _detach_exact_discovery_json_object(
            nested,
            label="synthetic discovery payload",
        )
    assert nested["data"].items_called is False


@pytest.mark.asyncio
async def test_mock_transport_cannot_seal_real_discovery_evidence(
    config_factory: Any,
) -> None:
    config = config_factory()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(500, request=request, json={})
        ),
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
    # A caller-injected HTTPX mock is not the issuer-bound internal test seam and therefore
    # receives no MOCK provenance credit. It must remain UNVERIFIED and unable to seal REAL
    # discovery evidence.
    assert client.execution_evidence.value == "unverified"
    try:
        with pytest.raises(OpenRouterPrivacyError, match="injected provider clients"):
            client.seal_real_model_discovery_run(
                run_id="1" * 32,
                retrieved_at=datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
                models_payload={},
                zdr_payload={},
                single_model_payloads={},
                endpoint_payloads={},
                candidate_routes=(),
                payloads=(),
            )
    finally:
        await client.close()
        await http_client.aclose()


def test_atomic_run_write_load_and_reuse_rejection(tmp_path: Path) -> None:
    evidence = _real_evidence()
    destination = tmp_path / "discovery-run"
    manifest = write_model_discovery_run(destination, evidence)

    loaded_manifest, loaded_evidence = load_model_discovery_run(destination)
    assert loaded_manifest == manifest
    assert loaded_evidence == evidence
    assert destination.stat().st_mode & 0o777 == 0o700
    assert all(
        item.stat().st_mode & 0o777 == 0o600 for item in destination.iterdir() if item.is_file()
    )

    with pytest.raises(ValueError, match="fresh"):
        write_model_discovery_run(destination, evidence)

    stale = destination / "candidate-stale.json"
    stale.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale or unmanifested"):
        load_model_discovery_run(destination)


def test_atomic_run_manifest_binds_the_exact_candidate_set(tmp_path: Path) -> None:
    second = _discover(
        exact_model_id="beta/ledger-safe",
        models=[_model(model="beta/ledger-safe", canonical_slug="beta/ledger-safe-20260727")],
        endpoint_snapshot=_endpoint_snapshot(
            model="beta/ledger-safe",
            endpoint_id="second-provider/exact",
        ),
    )
    evidence = _real_evidence((_discover(), second))
    destination = tmp_path / "two-candidate-run"

    manifest = write_model_discovery_run(destination, evidence)
    loaded_manifest, loaded_evidence = load_model_discovery_run(destination)

    assert loaded_manifest == manifest
    assert tuple(item.exact_model_id for item in loaded_evidence) == (
        "alpha/atlas-secure",
        "beta/ledger-safe",
    )
    assert all(
        item.provenance.run_id == loaded_evidence[0].provenance.run_id for item in loaded_evidence
    )
    assert manifest.candidate_set_sha256 == loaded_evidence[0].provenance.candidate_set_sha256


def test_atomic_run_rolls_back_on_manifest_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "failed-run"

    def fail_manifest_write(_path: Path, _value: bytes) -> None:
        raise OSError("synthetic manifest write failure")

    monkeypatch.setattr("mmaudit.models.discovery._write_private_bytes", fail_manifest_write)
    with pytest.raises(OSError, match="synthetic manifest"):
        write_model_discovery_run(destination, _real_evidence())

    assert not destination.exists()
    assert not list(tmp_path.glob(".failed-run.*.tmp"))


def test_load_and_write_reject_hardlinks_and_oversize_files(tmp_path: Path) -> None:
    evidence = _real_evidence()
    run = tmp_path / "run"
    write_model_discovery_run(run, evidence)
    original = next(run.glob("candidate-*.json"))
    linked = tmp_path / "linked.json"
    os.link(original, linked)

    with pytest.raises(ValueError, match="unshared"):
        load_model_discovery_evidence(linked)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * 2_000_001 + b"}")
    with pytest.raises(ValueError, match="bounded"):
        load_model_discovery_evidence(oversized)


def test_parent_symlink_is_rejected(tmp_path: Path) -> None:
    evidence = _real_evidence()
    real = tmp_path / "real"
    real.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="traverse links"):
        write_model_discovery_run(linked_parent / "discovery-run", evidence)
