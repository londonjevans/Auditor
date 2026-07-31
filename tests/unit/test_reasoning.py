from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.constants import (
    ALL_MODEL_ROLES,
    ALL_SPECIALIST_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
)
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    MAX_REASONING_TOKEN_RESERVE,
    ReasoningControlProfile,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    ReasoningPolicyError,
    ReasoningPolicyRoleProfile,
    ReasoningRequestPlanEvidence,
    ReasoningRequestRoleResolution,
    normalize_reasoning_request_role,
    reasoning_qualification_benchmark_role,
    resolve_reasoning_request_role,
)


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _control_payload(
    *,
    mode: str,
    reserved_reasoning_tokens: int,
    effort: str | None = None,
    max_tokens: int | None = None,
    exclude: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "mode": mode,
        "effort": effort,
        "max_tokens": max_tokens,
        "exclude": exclude,
        "reserved_reasoning_tokens": reserved_reasoning_tokens,
    }
    payload["profile_sha256"] = _sha(payload)
    return payload


def _controls() -> dict[str, ReasoningControlProfile]:
    disabled = ReasoningControlProfile.build(
        mode="disabled",
        reserved_reasoning_tokens=0,
    )
    controls = {role: disabled for role in CANONICAL_REASONING_POLICY_ROLES}
    controls["threat_model"] = ReasoningControlProfile.build(
        mode="default",
        reserved_reasoning_tokens=1_024,
    )
    controls["judge"] = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=4_096,
    )
    controls["falsifier"] = ReasoningControlProfile.build(
        mode="max_tokens",
        max_tokens=2_048,
        reserved_reasoning_tokens=2_048,
    )
    return controls


@pytest.mark.parametrize(
    ("mode", "effort", "max_tokens", "exclude", "reserve"),
    [
        ("disabled", None, None, False, 0),
        ("default", None, None, True, 512),
        ("effort", "none", None, True, 0),
        ("effort", "minimal", None, False, 128),
        ("effort", "xhigh", None, True, 4_096),
        ("max_tokens", None, 2_048, True, 2_048),
    ],
)
def test_effective_reasoning_modes_are_explicit_frozen_and_self_hashed(
    mode: str,
    effort: str | None,
    max_tokens: int | None,
    exclude: bool,
    reserve: int,
) -> None:
    profile = ReasoningControlProfile.build(
        mode=mode,  # type: ignore[arg-type]
        effort=effort,  # type: ignore[arg-type]
        max_tokens=max_tokens,
        exclude=exclude,
        reserved_reasoning_tokens=reserve,
    )

    assert profile.mode == mode
    assert profile.effort == effort
    assert profile.max_tokens == max_tokens
    assert profile.exclude is exclude
    assert profile.reserved_reasoning_tokens == reserve
    assert profile.profile_sha256 == _sha(
        profile.model_dump(mode="json", exclude={"profile_sha256"})
    )
    with pytest.raises(ValidationError, match="frozen"):
        profile.reserved_reasoning_tokens = reserve + 1  # type: ignore[misc]


@pytest.mark.parametrize(
    ("mode", "effort", "max_tokens", "exclude", "reserve"),
    [
        ("disabled", None, None, False, 1),
        ("disabled", "none", None, False, 0),
        ("disabled", None, 1, False, 0),
        ("disabled", None, None, True, 0),
        ("default", None, None, False, 0),
        ("default", "high", None, False, 128),
        ("default", None, 128, False, 128),
        ("effort", None, None, False, 128),
        ("effort", "none", None, False, 1),
        ("effort", "low", None, False, 0),
        ("effort", "high", 128, False, 128),
        ("max_tokens", None, None, False, 128),
        ("max_tokens", "high", 128, False, 128),
        ("max_tokens", None, 128, False, 127),
    ],
)
def test_inconsistent_reasoning_controls_fail_closed(
    mode: str,
    effort: str | None,
    max_tokens: int | None,
    exclude: bool,
    reserve: int,
) -> None:
    with pytest.raises(ReasoningPolicyError):
        ReasoningControlProfile.build(
            mode=mode,  # type: ignore[arg-type]
            effort=effort,  # type: ignore[arg-type]
            max_tokens=max_tokens,
            exclude=exclude,
            reserved_reasoning_tokens=reserve,
        )


def test_reasoning_control_rejects_missing_or_non_strict_reserve_and_hash_tampering() -> None:
    missing_reserve = _control_payload(
        mode="default",
        reserved_reasoning_tokens=128,
    )
    missing_reserve.pop("reserved_reasoning_tokens")
    missing_reserve["profile_sha256"] = _sha(
        {key: value for key, value in missing_reserve.items() if key != "profile_sha256"}
    )
    with pytest.raises(ValidationError):
        ReasoningControlProfile.model_validate(missing_reserve)

    boolean_reserve = _control_payload(
        mode="default",
        reserved_reasoning_tokens=128,
    )
    boolean_reserve["reserved_reasoning_tokens"] = True
    boolean_reserve["profile_sha256"] = _sha(
        {key: value for key, value in boolean_reserve.items() if key != "profile_sha256"}
    )
    with pytest.raises(ValidationError):
        ReasoningControlProfile.model_validate(boolean_reserve)

    tampered = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=1_024,
    ).model_dump(mode="json")
    tampered["reserved_reasoning_tokens"] = 2_048
    with pytest.raises(ValidationError, match="canonical reasoning evidence"):
        ReasoningControlProfile.model_validate(tampered)

    extra = _control_payload(mode="disabled", reserved_reasoning_tokens=0)
    extra["untrusted"] = "ignored"
    with pytest.raises(ValidationError, match="Extra inputs"):
        ReasoningControlProfile.model_validate(extra)


def test_reasoning_token_reserve_has_a_finite_host_bound() -> None:
    with pytest.raises(ReasoningPolicyError):
        ReasoningControlProfile.build(
            mode="max_tokens",
            max_tokens=MAX_REASONING_TOKEN_RESERVE + 1,
            reserved_reasoning_tokens=MAX_REASONING_TOKEN_RESERVE + 1,
        )


def test_canonical_policy_role_profile_is_exact_bounded_and_self_hashed() -> None:
    profile = ReasoningPolicyRoleProfile.canonical()

    assert profile.roles == (*ALL_MODEL_ROLES, *ALL_SPECIALIST_ROLES)
    assert profile.roles == CANONICAL_REASONING_POLICY_ROLES
    assert len(profile.roles) == len(set(profile.roles))
    assert profile.profile_sha256 == _sha(
        profile.model_dump(mode="json", exclude={"profile_sha256"})
    )

    reordered = profile.model_dump(mode="json")
    reordered["roles"] = [*reversed(reordered["roles"])]
    reordered["profile_sha256"] = _sha(
        {key: value for key, value in reordered.items() if key != "profile_sha256"}
    )
    with pytest.raises(ValidationError, match="canonical exact set"):
        ReasoningPolicyRoleProfile.model_validate_json(json.dumps(reordered))


def test_full_reasoning_policy_requires_every_canonical_role_exactly_once() -> None:
    controls = _controls()
    artifact = ReasoningPolicyArtifact.build(controls_by_role=controls)

    assert artifact.role_profile == ReasoningPolicyRoleProfile.canonical()
    assert tuple(policy.role for policy in artifact.policies) == (CANONICAL_REASONING_POLICY_ROLES)
    assert artifact.artifact_sha256 == _sha(
        artifact.model_dump(mode="json", exclude={"artifact_sha256"})
    )
    assert artifact.control_for_request("judge") == controls["judge"]

    missing = dict(controls)
    missing.pop("judge")
    with pytest.raises(ReasoningPolicyError, match="missing=judge"):
        ReasoningPolicyArtifact.build(controls_by_role=missing)

    unexpected = dict(controls)
    unexpected["untrusted_role"] = controls["judge"]
    with pytest.raises(ReasoningPolicyError, match="unexpected=untrusted_role"):
        ReasoningPolicyArtifact.build(controls_by_role=unexpected)


def test_full_policy_rejects_reordered_or_nested_tampered_serialization() -> None:
    artifact = ReasoningPolicyArtifact.build(controls_by_role=_controls())

    reordered = artifact.model_dump(mode="json")
    reordered["policies"][0], reordered["policies"][1] = (
        reordered["policies"][1],
        reordered["policies"][0],
    )
    reordered["artifact_sha256"] = _sha(
        {key: value for key, value in reordered.items() if key != "artifact_sha256"}
    )
    with pytest.raises(ValidationError, match="canonical role profile"):
        ReasoningPolicyArtifact.model_validate_json(json.dumps(reordered))

    nested_tamper = artifact.model_dump(mode="json")
    nested_tamper["policies"][0]["control"]["reserved_reasoning_tokens"] = 1
    nested_tamper["artifact_sha256"] = _sha(
        {key: value for key, value in nested_tamper.items() if key != "artifact_sha256"}
    )
    with pytest.raises(ValidationError):
        ReasoningPolicyArtifact.model_validate_json(json.dumps(nested_tamper))


def test_base_and_exact_specialist_request_roles_resolve_deterministically() -> None:
    for role in ALL_MODEL_ROLES:
        resolution = resolve_reasoning_request_role(role)
        assert resolution.semantic_role == role
        assert resolution.configured_policy_role == role
        assert resolution.qualification_role == role
        assert resolution.mapping_kind == "base_exact"
        assert normalize_reasoning_request_role(role) == role

    for role in SPECIALIST_INVESTIGATOR_ROLES:
        resolution = resolve_reasoning_request_role(f"specialist:{role}")
        assert resolution.semantic_role == role
        assert resolution.configured_policy_role == role
        assert resolution.qualification_role == role
        assert resolution.mapping_kind == "specialist_investigator"
        assert normalize_reasoning_request_role(f"specialist:{role}") == role

    for role in (
        "invariant_review",
        "report_quality",
        "falsifier",
        "test_generation",
        "exploit_reproduction_planner",
    ):
        resolution = resolve_reasoning_request_role(f"specialist:{role}")
        assert resolution.semantic_role == role
        assert resolution.configured_policy_role == role
        assert resolution.qualification_role == role
        assert resolution.mapping_kind == "specialist_auxiliary"


def test_exact_exploit_test_roles_distinguish_semantics_from_configured_policy() -> None:
    for role in ("test_generation", "exploit_reproduction_planner"):
        resolution = resolve_reasoning_request_role(f"specialist:{role}:exploit_test")
        assert resolution.semantic_role == role
        assert resolution.configured_policy_role == role
        assert resolution.qualification_role == role
        assert resolution.mapping_kind == "dedicated_exploit_test"
        assert normalize_reasoning_request_role(resolution.request_role) == role

    for role in (
        "source_audit",
        "business_logic",
        "configuration",
        *SPECIALIST_INVESTIGATOR_ROLES,
    ):
        resolution = resolve_reasoning_request_role(f"specialist:{role}:exploit_test")
        assert resolution.semantic_role == "exploit_reproduction_planner"
        assert resolution.configured_policy_role == role
        assert resolution.qualification_role == role
        assert resolution.mapping_kind == "fallback_exploit_test"
        assert normalize_reasoning_request_role(resolution.request_role) == role


def test_dynamic_and_fallback_roles_seal_semantic_and_configured_policy_mapping() -> None:
    candidate_sha256 = "a" * 64
    artifact = ReasoningPolicyArtifact.build(controls_by_role=_controls())

    fallback = resolve_reasoning_request_role("falsifier")
    assert fallback.semantic_role == "falsifier"
    assert fallback.configured_policy_role == "verifier"
    assert fallback.qualification_role == "falsifier"
    assert fallback.mapping_kind == "falsifier_fallback"
    assert artifact.control_for_request("falsifier").mode == "disabled"

    benchmark = resolve_reasoning_request_role("model_benchmark")
    assert benchmark.semantic_role == "model_benchmark"
    assert benchmark.configured_policy_role == "source_audit"
    assert benchmark.qualification_role == "model_benchmark"
    assert benchmark.mapping_kind == "prequalification_benchmark"

    aggregate_cross_examination = resolve_reasoning_request_role("candidate_cross_examination")
    assert aggregate_cross_examination.semantic_role == "falsifier"
    assert aggregate_cross_examination.configured_policy_role == "falsifier"
    assert aggregate_cross_examination.qualification_role == "falsifier"
    assert aggregate_cross_examination.mapping_kind == "candidate_cross_examination_context"

    for reviewer_index in (1, 2):
        request_role = f"candidate_falsifier:{candidate_sha256}:reviewer_{reviewer_index}"
        resolution = resolve_reasoning_request_role(request_role)
        assert resolution.semantic_role == "falsifier"
        assert resolution.configured_policy_role == "falsifier"
        assert resolution.qualification_role == "falsifier"
        assert resolution.mapping_kind == "candidate_cross_examination"
        assert normalize_reasoning_request_role(request_role) == "falsifier"
        assert artifact.control_for_request(request_role).mode == "max_tokens"
    for review_index in (0, 1, 9_999):
        request_role = f"whole_protocol_review:{review_index}"
        resolution = resolve_reasoning_request_role(request_role)
        assert resolution.semantic_role == "whole_protocol_review"
        assert resolution.configured_policy_role == "threat_model"
        assert resolution.qualification_role == "whole_protocol_review"
        assert resolution.mapping_kind == "whole_protocol_indexed"
        assert normalize_reasoning_request_role(request_role) == "threat_model"
        assert artifact.control_for_request(request_role).mode == "default"


def test_role_qualification_benchmark_resolves_only_exact_production_routes() -> None:
    request_role = reasoning_qualification_benchmark_role(
        qualified_role="falsifier",
        configured_policy_role="verifier",
    )
    resolution = resolve_reasoning_request_role(request_role)

    assert request_role == "model_benchmark:falsifier:verifier"
    assert resolution.semantic_role == "verifier"
    assert resolution.configured_policy_role == "verifier"
    assert resolution.qualification_role == "falsifier"
    assert resolution.mapping_kind == "prequalification_role_benchmark"
    assert normalize_reasoning_request_role(request_role) == "verifier"

    for qualified_role, configured_role in (
        ("falsifier", "judge"),
        ("whole_protocol_review", "source_audit"),
        ("unknown", "source_audit"),
    ):
        with pytest.raises(ReasoningPolicyError):
            reasoning_qualification_benchmark_role(
                qualified_role=qualified_role,
                configured_policy_role=configured_role,
            )


def test_request_role_resolution_is_immutable_self_hashed_and_rejects_semantic_forgery() -> None:
    resolution = resolve_reasoning_request_role("specialist:source_audit:exploit_test")

    assert resolution.resolution_sha256 == _sha(
        resolution.model_dump(mode="json", exclude={"resolution_sha256"})
    )
    with pytest.raises(ValidationError, match="frozen"):
        resolution.semantic_role = "source_audit"  # type: ignore[misc]

    forged = resolution.model_dump(mode="json")
    forged["semantic_role"] = "source_audit"
    forged["resolution_sha256"] = _sha(
        {key: value for key, value in forged.items() if key != "resolution_sha256"}
    )
    with pytest.raises(ValidationError, match="sealed host routing"):
        ReasoningRequestRoleResolution.model_validate(forged)

    tampered = resolution.model_dump(mode="json")
    tampered["resolution_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="canonical reasoning evidence"):
        ReasoningRequestRoleResolution.model_validate(tampered)


@pytest.mark.parametrize(
    "request_role",
    [
        "",
        " threat_model",
        "Threat_Model",
        "access_control",
        "specialist:unknown",
        "specialist:invariant_review:exploit_test",
        "specialist:report_quality:exploit_test",
        "specialist:falsifier:exploit_test",
        "specialist:threat_model:exploit_test",
        "specialist:verifier:exploit_test",
        "specialist:judge:exploit_test",
        "specialist:access_control:arbitrary",
        "specialist:access_control:exploit_test:extra",
        "specialist:source_audit",
        "specialist:source_audit:exploit_test:extra",
        "candidate_falsifier:" + ("A" * 64) + ":reviewer_1",
        "candidate_falsifier:" + ("a" * 63) + ":reviewer_1",
        "candidate_falsifier:" + ("a" * 64) + ":reviewer_0",
        "candidate_falsifier:" + ("a" * 64) + ":reviewer_3",
        "candidate_falsifier:" + ("a" * 64) + ":reviewer_01",
        "whole_protocol_review",
        "whole_protocol_review:00",
        "whole_protocol_review:10000",
        "whole_protocol_review:not-an-index",
        "model_benchmark:falsifier:judge",
        "model_benchmark:whole_protocol_review:source_audit",
        "model_benchmark:unknown:source_audit",
        "model_benchmark:falsifier",
    ],
)
def test_unknown_or_noncanonical_request_roles_fail_closed(request_role: str) -> None:
    with pytest.raises(ReasoningPolicyError):
        normalize_reasoning_request_role(request_role)

    artifact = ReasoningPolicyArtifact.build(controls_by_role=_controls())
    with pytest.raises(ReasoningPolicyError):
        artifact.control_for_request(request_role)


def test_non_string_request_role_fails_closed() -> None:
    with pytest.raises(ReasoningPolicyError, match="must be a string"):
        normalize_reasoning_request_role(7)  # type: ignore[arg-type]
    with pytest.raises(ReasoningPolicyError, match="must be a string"):
        resolve_reasoning_request_role(7)  # type: ignore[arg-type]


def test_request_plan_evidence_binds_policy_capability_and_qualification_exactly() -> None:
    policy = ReasoningPolicyArtifact.build(controls_by_role=_controls())
    policy_only = ReasoningRequestPlanEvidence.build(
        request_role="judge",
        policy=policy,
    )
    capability = ReasoningRequestPlanEvidence.build(
        request_role="judge",
        policy=policy,
        endpoint_capability_sha256="1" * 64,
    )
    qualified = ReasoningRequestPlanEvidence.build(
        request_role="judge",
        policy=policy,
        endpoint_capability_sha256="1" * 64,
        qualification_binding_sha256="2" * 64,
    )

    assert policy_only.binding_state == "policy_only"
    assert capability.binding_state == "capability_bound"
    assert qualified.binding_state == "qualification_bound"
    assert qualified.control_profile == _controls()["judge"]
    assert qualified.resolution.configured_policy_role == "judge"
    with pytest.raises(ReasoningPolicyError, match="requires endpoint capability"):
        ReasoningRequestPlanEvidence.build(
            request_role="judge",
            policy=policy,
            qualification_binding_sha256="2" * 64,
        )


def test_request_plan_evidence_rejects_nested_profile_or_role_binding_tampering() -> None:
    plan = ReasoningRequestPlanEvidence.build(
        request_role="judge",
        policy=ReasoningPolicyArtifact.build(controls_by_role=_controls()),
        endpoint_capability_sha256="1" * 64,
    )
    tampered = plan.model_dump(mode="json")
    tampered["control_profile"] = _controls()["falsifier"].model_dump(mode="json")
    tampered["evidence_sha256"] = _sha(
        {key: value for key, value in tampered.items() if key != "evidence_sha256"}
    )
    with pytest.raises(ValidationError, match="policy-role binding"):
        ReasoningRequestPlanEvidence.model_validate(tampered)


def test_execution_evidence_distinguishes_unavailable_observation_from_zero() -> None:
    policy = ReasoningPolicyArtifact.build(controls_by_role=_controls())
    active_plan = ReasoningRequestPlanEvidence.build(
        request_role="judge",
        policy=policy,
        endpoint_capability_sha256="1" * 64,
    )
    observed_zero = ReasoningExecutionEvidence.build(
        request_plan=active_plan,
        observed_reasoning_tokens=0,
        provider_completion_tokens=20,
        request_token_plan_sha256="3" * 64,
        request_body_sha256="4" * 64,
    )
    unavailable = ReasoningExecutionEvidence.build(
        request_plan=active_plan,
        observed_reasoning_tokens=None,
        provider_completion_tokens=20,
        request_token_plan_sha256="3" * 64,
        request_body_sha256="4" * 64,
    )

    assert observed_zero.state == "active_observed"
    assert observed_zero.observation_available is True
    assert observed_zero.visible_completion_tokens == 20
    assert unavailable.state == "active_unavailable"
    assert unavailable.observation_available is False
    assert unavailable.observed_reasoning_tokens is None
    assert unavailable.visible_completion_tokens is None

    tampered = observed_zero.model_dump(mode="json")
    tampered["observed_reasoning_tokens"] = (
        active_plan.control_profile.reserved_reasoning_tokens + 1
    )
    tampered["visible_completion_tokens"] = 0
    tampered["evidence_sha256"] = _sha(
        {key: value for key, value in tampered.items() if key != "evidence_sha256"}
    )
    with pytest.raises(ValidationError, match="reserved ceiling"):
        ReasoningExecutionEvidence.model_validate(tampered)
