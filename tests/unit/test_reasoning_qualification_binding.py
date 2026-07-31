from __future__ import annotations

import pytest
from pydantic import ValidationError

from mmaudit.models.qualification import (
    ModelQualificationResult,
    QualificationDisposition,
    QualifiedReasoningRoleBinding,
    require_complete_reasoning_qualification_bindings,
    seal_qualified_reasoning_role_binding,
)
from mmaudit.models.reasoning import ReasoningControlProfile, ReasoningEffort
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_role_qualification import _sealed_result

_CAPABILITY_SHA256 = "8" * 64
_QUALIFICATION_VERIFICATION_SHA256 = "9" * 64


def _profile(*, effort: ReasoningEffort = "high") -> ReasoningControlProfile:
    return ReasoningControlProfile.build(
        mode="effort",
        effort=effort,
        reserved_reasoning_tokens=32_768,
    )


def _result() -> ModelQualificationResult:
    return _sealed_result(
        disposition=QualificationDisposition.TIER_A,
        approved_roles=("falsifier", "whole_protocol_review"),
    )


def _binding(
    *,
    qualified_role: str,
    configured_policy_role: str,
    profile: ReasoningControlProfile,
) -> QualifiedReasoningRoleBinding:
    result = _result()
    return seal_qualified_reasoning_role_binding(
        exact_model_id=result.exact_model_id,
        approved_provider_endpoint=result.approved_provider_endpoint,
        approved_provider_name=result.approved_provider_name,
        qualified_role=qualified_role,
        configured_policy_role=configured_policy_role,
        control_profile=profile,
        endpoint_reasoning_capability_sha256=_CAPABILITY_SHA256,
        qualification_report_sha256=result.benchmark_report_sha256,
        qualification_result_sha256=result.result_sha256,
        qualification_verification_sha256=_QUALIFICATION_VERIFICATION_SHA256,
    )


def _bindings(
    profile: ReasoningControlProfile,
) -> tuple[QualifiedReasoningRoleBinding, ...]:
    return (
        _binding(
            qualified_role="falsifier",
            configured_policy_role="falsifier",
            profile=profile,
        ),
        _binding(
            qualified_role="falsifier",
            configured_policy_role="verifier",
            profile=profile,
        ),
        _binding(
            qualified_role="whole_protocol_review",
            configured_policy_role="threat_model",
            profile=profile,
        ),
    )


def _expectations(
    profile: ReasoningControlProfile,
) -> dict[tuple[str, str], ReasoningControlProfile]:
    return {
        ("falsifier", "falsifier"): profile,
        ("falsifier", "verifier"): profile,
        ("whole_protocol_review", "threat_model"): profile,
    }


def test_reasoning_qualification_binding_is_immutable_self_hashed_and_not_authority() -> None:
    binding = _bindings(_profile())[0]

    assert binding.binding_status == "exact_evidence_bound"
    assert binding.selection_authority is False
    assert binding.binding_sha256 == canonical_sha256(
        binding.model_dump(mode="json", exclude={"binding_sha256"})
    )
    field_name = "qualified_role"
    with pytest.raises(ValidationError, match="frozen"):
        setattr(binding, field_name, "judge")

    tampered = binding.model_dump(mode="json")
    tampered["control_profile_sha256"] = "a" * 64
    tampered["binding_sha256"] = canonical_sha256(
        {key: value for key, value in tampered.items() if key != "binding_sha256"}
    )
    with pytest.raises(ValidationError, match="profile binding"):
        QualifiedReasoningRoleBinding.model_validate(tampered)


def test_complete_reasoning_qualification_requires_every_approved_role() -> None:
    profile = _profile()
    bindings = _bindings(profile)

    assert (
        require_complete_reasoning_qualification_bindings(
            result=_result(),
            qualification_verification_sha256=_QUALIFICATION_VERIFICATION_SHA256,
            endpoint_reasoning_capability_sha256=_CAPABILITY_SHA256,
            expected_profiles_by_route=_expectations(profile),
            bindings=bindings,
        )
        == bindings
    )
    with pytest.raises(ValueError, match="every approved role route exactly"):
        require_complete_reasoning_qualification_bindings(
            result=_result(),
            qualification_verification_sha256=_QUALIFICATION_VERIFICATION_SHA256,
            endpoint_reasoning_capability_sha256=_CAPABILITY_SHA256,
            expected_profiles_by_route=_expectations(profile),
            bindings=bindings[:-1],
        )


def test_different_reasoning_effort_cannot_inherit_qualification() -> None:
    qualified_profile = _profile(effort="high")
    changed_profile = _profile(effort="medium")

    with pytest.raises(ValueError, match="exact match failed"):
        require_complete_reasoning_qualification_bindings(
            result=_result(),
            qualification_verification_sha256=_QUALIFICATION_VERIFICATION_SHA256,
            endpoint_reasoning_capability_sha256=_CAPABILITY_SHA256,
            expected_profiles_by_route=_expectations(changed_profile),
            bindings=_bindings(qualified_profile),
        )


def test_different_endpoint_capability_cannot_inherit_qualification() -> None:
    profile = _profile()

    with pytest.raises(ValueError, match="exact match failed"):
        require_complete_reasoning_qualification_bindings(
            result=_result(),
            qualification_verification_sha256=_QUALIFICATION_VERIFICATION_SHA256,
            endpoint_reasoning_capability_sha256="a" * 64,
            expected_profiles_by_route=_expectations(profile),
            bindings=_bindings(profile),
        )
