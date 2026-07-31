"""Provider-free, immutable per-role reasoning policy evidence.

This module defines only deterministic control-plane policy. It does not infer
endpoint support, authorize model selection, contact a provider, or reserve cost.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.constants import (
    ALL_MODEL_ROLES,
    ALL_SPECIALIST_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
)

ReasoningControlMode = Literal["disabled", "default", "effort", "max_tokens"]
ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh"]
ReasoningRequestRoleMappingKind = Literal[
    "base_exact",
    "specialist_investigator",
    "specialist_auxiliary",
    "dedicated_exploit_test",
    "fallback_exploit_test",
    "falsifier_fallback",
    "candidate_cross_examination_context",
    "candidate_cross_examination",
    "whole_protocol_indexed",
    "prequalification_benchmark",
    "prequalification_role_benchmark",
]
ReasoningPlanBindingState = Literal[
    "policy_only",
    "capability_bound",
    "qualification_bound",
]
ReasoningExecutionState = Literal[
    "disabled_observed",
    "disabled_unreported",
    "active_observed",
    "active_unavailable",
    "failed_before_observation",
]

MAX_REASONING_TOKEN_RESERVE = 65_536
CANONICAL_REASONING_POLICY_ROLES = (*ALL_MODEL_ROLES, *ALL_SPECIALIST_ROLES)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_RE = re.compile(_SHA256_PATTERN)
_SPECIALIST_REQUEST_ROLE = re.compile(r"^specialist:([a-z][a-z0-9_]{0,63})$")
_EXPLOIT_TEST_REQUEST_ROLE = re.compile(r"^specialist:([a-z][a-z0-9_]{0,63}):exploit_test$")
_CANDIDATE_FALSIFIER_REQUEST_ROLE = re.compile(r"^candidate_falsifier:[0-9a-f]{64}:reviewer_[12]$")
_WHOLE_PROTOCOL_REQUEST_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")
_ROLE_QUALIFICATION_BENCHMARK_REQUEST = re.compile(
    r"^model_benchmark:([a-z][a-z0-9_]{0,63}):([a-z][a-z0-9_]{0,63})$"
)
_DEDICATED_EXPLOIT_TEST_ROLES = frozenset(
    {
        "test_generation",
        "exploit_reproduction_planner",
    }
)
_FALLBACK_BASE_EXPLOIT_TEST_ROLES = frozenset(
    {
        "source_audit",
        "business_logic",
        "configuration",
    }
)


class ReasoningPolicyError(ValueError):
    """Raised when a reasoning policy or request role fails closed."""


class _FrozenReasoningEvidence(BaseModel):
    """Strict, deeply revalidated base for immutable reasoning evidence."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class ReasoningControlProfile(_FrozenReasoningEvidence):
    """One effective reasoning control with an explicit token reservation."""

    schema_version: Literal["1.0"] = "1.0"
    mode: ReasoningControlMode
    effort: ReasoningEffort | None = None
    max_tokens: int | None = Field(
        default=None,
        ge=1,
        le=MAX_REASONING_TOKEN_RESERVE,
    )
    exclude: bool = False
    reserved_reasoning_tokens: int = Field(
        ge=0,
        le=MAX_REASONING_TOKEN_RESERVE,
    )
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        mode: ReasoningControlMode,
        reserved_reasoning_tokens: int,
        effort: ReasoningEffort | None = None,
        max_tokens: int | None = None,
        exclude: bool = False,
    ) -> Self:
        """Validate and self-hash one effective control profile."""

        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "mode": mode,
            "effort": effort,
            "max_tokens": max_tokens,
            "exclude": exclude,
            "reserved_reasoning_tokens": reserved_reasoning_tokens,
        }
        payload["profile_sha256"] = _canonical_sha256(payload)
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise ReasoningPolicyError("reasoning control profile is invalid") from exc

    @model_validator(mode="after")
    def control_is_explicit_consistent_and_self_hashed(self) -> Self:
        has_effort = self.effort is not None
        has_max_tokens = self.max_tokens is not None

        if self.mode == "disabled":
            if has_effort or has_max_tokens or self.exclude or self.reserved_reasoning_tokens != 0:
                raise ValueError("disabled reasoning requires no control and zero reserve")
        elif self.mode == "default":
            if has_effort or has_max_tokens or self.reserved_reasoning_tokens <= 0:
                raise ValueError("default reasoning requires a positive explicit reserve")
        elif self.mode == "effort":
            if not has_effort or has_max_tokens:
                raise ValueError("effort reasoning requires effort XOR max_tokens")
            expected_zero = self.effort == "none"
            if expected_zero != (self.reserved_reasoning_tokens == 0):
                raise ValueError(
                    "effort=none requires zero reserve; named effort requires a positive reserve"
                )
        elif self.mode == "max_tokens":
            if has_effort or not has_max_tokens:
                raise ValueError("max_tokens reasoning requires max_tokens XOR effort")
            if self.reserved_reasoning_tokens != self.max_tokens:
                raise ValueError("max_tokens reasoning reserve must equal max_tokens")

        _require_self_hash(self, "profile_sha256")
        return self


class ReasoningPolicyRoleProfile(_FrozenReasoningEvidence):
    """The exact bounded canonical role inventory that a full policy must cover."""

    schema_version: Literal["1.0"] = "1.0"
    roles: tuple[str, ...] = Field(
        min_length=len(CANONICAL_REASONING_POLICY_ROLES),
        max_length=len(CANONICAL_REASONING_POLICY_ROLES),
    )
    profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def canonical(cls) -> Self:
        """Build the sole accepted canonical reasoning-policy role profile."""

        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "roles": CANONICAL_REASONING_POLICY_ROLES,
        }
        payload["profile_sha256"] = _canonical_sha256(payload)
        return cls.model_validate(payload)

    @model_validator(mode="after")
    def role_inventory_is_exact_and_self_hashed(self) -> Self:
        if self.roles != CANONICAL_REASONING_POLICY_ROLES:
            raise ValueError("reasoning policy role inventory is not the canonical exact set")
        if len(self.roles) != len(set(self.roles)):
            raise ValueError("reasoning policy role inventory contains duplicates")
        _require_self_hash(self, "profile_sha256")
        return self


class ReasoningRolePolicy(_FrozenReasoningEvidence):
    """One canonical role bound to one exact effective reasoning control."""

    schema_version: Literal["1.0"] = "1.0"
    role: str
    control: ReasoningControlProfile
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        role: str,
        control: ReasoningControlProfile,
    ) -> Self:
        """Bind one canonical role to an already sealed control."""

        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "role": role,
            "control": control.model_dump(mode="json"),
        }
        payload["binding_sha256"] = _canonical_sha256(payload)
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise ReasoningPolicyError("reasoning role policy is invalid") from exc

    @model_validator(mode="after")
    def binding_is_canonical_and_self_hashed(self) -> Self:
        if self.role not in CANONICAL_REASONING_POLICY_ROLES:
            raise ValueError("reasoning role policy names an unknown canonical role")
        _require_self_hash(self.control, "profile_sha256")
        _require_self_hash(self, "binding_sha256")
        return self


class ReasoningPolicyArtifact(_FrozenReasoningEvidence):
    """Full exact per-role policy without endpoint or qualification authority."""

    schema_version: Literal["1.0"] = "1.0"
    role_profile: ReasoningPolicyRoleProfile
    policies: tuple[ReasoningRolePolicy, ...] = Field(
        min_length=len(CANONICAL_REASONING_POLICY_ROLES),
        max_length=len(CANONICAL_REASONING_POLICY_ROLES),
    )
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        controls_by_role: Mapping[str, ReasoningControlProfile],
    ) -> Self:
        """Build a full self-hashed policy from an exact canonical role mapping."""

        supplied_roles = set(controls_by_role)
        canonical_roles = set(CANONICAL_REASONING_POLICY_ROLES)
        if supplied_roles != canonical_roles:
            missing = sorted(canonical_roles - supplied_roles)
            unexpected = sorted(supplied_roles - canonical_roles)
            detail = []
            if missing:
                detail.append("missing=" + ",".join(missing))
            if unexpected:
                detail.append("unexpected=" + ",".join(unexpected))
            raise ReasoningPolicyError(
                "reasoning policy must cover the exact canonical role set"
                + (": " + "; ".join(detail) if detail else "")
            )
        if any(
            not isinstance(controls_by_role[role], ReasoningControlProfile)
            for role in CANONICAL_REASONING_POLICY_ROLES
        ):
            raise ReasoningPolicyError("reasoning policy controls must be sealed profiles")

        role_profile = ReasoningPolicyRoleProfile.canonical()
        policies = tuple(
            ReasoningRolePolicy.build(
                role=role,
                control=controls_by_role[role],
            )
            for role in CANONICAL_REASONING_POLICY_ROLES
        )
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "role_profile": role_profile,
            "policies": policies,
        }
        payload["artifact_sha256"] = _canonical_sha256(payload)
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise ReasoningPolicyError("reasoning policy artifact is invalid") from exc

    @model_validator(mode="after")
    def artifact_is_full_canonical_and_self_hashed(self) -> Self:
        canonical_profile = ReasoningPolicyRoleProfile.canonical()
        if self.role_profile != canonical_profile:
            raise ValueError("reasoning policy artifact role profile is not canonical")
        policy_roles = tuple(policy.role for policy in self.policies)
        if policy_roles != self.role_profile.roles:
            raise ValueError("reasoning policies do not exactly follow the canonical role profile")
        for policy in self.policies:
            _require_self_hash(policy.control, "profile_sha256")
            _require_self_hash(policy, "binding_sha256")
        _require_self_hash(self, "artifact_sha256")
        return self

    def control_for_request(self, request_role: str) -> ReasoningControlProfile:
        """Resolve one host request role to its exact canonical control."""

        return self.role_policy_for_request(request_role).control

    def role_policy_for_request(self, request_role: str) -> ReasoningRolePolicy:
        """Resolve one host request role to its exact sealed policy binding."""

        return self.role_policy(normalize_reasoning_request_role(request_role))

    def role_policy(self, canonical_role: str) -> ReasoningRolePolicy:
        """Return one exact canonical role binding without request-role normalization."""

        if canonical_role not in CANONICAL_REASONING_POLICY_ROLES:
            raise ReasoningPolicyError("reasoning policy role is not canonical")
        for policy in self.policies:
            if policy.role == canonical_role:
                return policy
        raise ReasoningPolicyError("canonical reasoning role is absent from the full policy")


class ReasoningRequestRoleResolution(_FrozenReasoningEvidence):
    """Exact host request-role meaning, policy routing, and qualification role."""

    schema_version: Literal["1.0"] = "1.0"
    request_role: str = Field(min_length=1, max_length=200)
    semantic_role: str = Field(min_length=1, max_length=64)
    configured_policy_role: str = Field(min_length=1, max_length=64)
    qualification_role: str = Field(min_length=1, max_length=64)
    mapping_kind: ReasoningRequestRoleMappingKind
    resolution_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, request_role: str) -> Self:
        """Resolve and seal one exact role form emitted by host orchestration."""

        semantic_role, configured_policy_role, qualification_role, mapping_kind = (
            _resolve_reasoning_request_role_fields(request_role)
        )
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "request_role": request_role,
            "semantic_role": semantic_role,
            "configured_policy_role": configured_policy_role,
            "qualification_role": qualification_role,
            "mapping_kind": mapping_kind,
        }
        payload["resolution_sha256"] = _canonical_sha256(payload)
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise ReasoningPolicyError("reasoning request role resolution is invalid") from exc

    @model_validator(mode="after")
    def resolution_is_exact_and_self_hashed(self) -> Self:
        expected = _resolve_reasoning_request_role_fields(self.request_role)
        observed = (
            self.semantic_role,
            self.configured_policy_role,
            self.qualification_role,
            self.mapping_kind,
        )
        if observed != expected:
            raise ValueError("reasoning request role resolution does not match sealed host routing")
        if self.configured_policy_role not in CANONICAL_REASONING_POLICY_ROLES:
            raise ValueError("reasoning request role resolves outside the canonical policy")
        _require_self_hash(self, "resolution_sha256")
        return self


class ReasoningRequestPlanEvidence(_FrozenReasoningEvidence):
    """Exact role, control, capability, and qualification joins for one request plan."""

    schema_version: Literal["1.0"] = "1.0"
    resolution: ReasoningRequestRoleResolution
    control_profile: ReasoningControlProfile
    policy_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_role_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_capability_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    qualification_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    binding_state: ReasoningPlanBindingState
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        request_role: str,
        policy: ReasoningPolicyArtifact,
        endpoint_capability_sha256: str | None = None,
        qualification_binding_sha256: str | None = None,
    ) -> Self:
        """Seal the exact reasoning authorities available before transport."""

        resolution = resolve_reasoning_request_role(request_role)
        role_policy = policy.role_policy_for_request(request_role)
        if qualification_binding_sha256 is not None and endpoint_capability_sha256 is None:
            raise ReasoningPolicyError(
                "reasoning qualification binding requires endpoint capability evidence"
            )
        state: ReasoningPlanBindingState = (
            "qualification_bound"
            if qualification_binding_sha256 is not None
            else ("capability_bound" if endpoint_capability_sha256 is not None else "policy_only")
        )
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "resolution": resolution,
            "control_profile": role_policy.control,
            "policy_artifact_sha256": policy.artifact_sha256,
            "policy_role_binding_sha256": role_policy.binding_sha256,
            "endpoint_capability_sha256": endpoint_capability_sha256,
            "qualification_binding_sha256": qualification_binding_sha256,
            "binding_state": state,
        }
        payload["evidence_sha256"] = _canonical_sha256(payload)
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise ReasoningPolicyError("reasoning request plan evidence is invalid") from exc

    @model_validator(mode="after")
    def plan_join_is_exact_and_self_hashed(self) -> Self:
        resolution = resolve_reasoning_request_role(self.resolution.request_role)
        if self.resolution != resolution:
            raise ValueError("reasoning plan request-role resolution is inconsistent")
        expected_policy = ReasoningRolePolicy.build(
            role=resolution.configured_policy_role,
            control=self.control_profile,
        )
        if self.policy_role_binding_sha256 != expected_policy.binding_sha256:
            raise ValueError("reasoning plan policy-role binding is inconsistent")
        expected_state: ReasoningPlanBindingState = (
            "qualification_bound"
            if self.qualification_binding_sha256 is not None
            else (
                "capability_bound" if self.endpoint_capability_sha256 is not None else "policy_only"
            )
        )
        if self.binding_state != expected_state or (
            self.qualification_binding_sha256 is not None
            and self.endpoint_capability_sha256 is None
        ):
            raise ValueError("reasoning plan authority state is inconsistent")
        _require_self_hash(self, "evidence_sha256")
        return self


class ReasoningExecutionEvidence(_FrozenReasoningEvidence):
    """Provider accounting joined to the exact pre-transport reasoning plan."""

    schema_version: Literal["1.0"] = "1.0"
    request_plan: ReasoningRequestPlanEvidence
    reserved_reasoning_tokens: int = Field(ge=0, le=MAX_REASONING_TOKEN_RESERVE)
    observation_available: bool
    observed_reasoning_tokens: int | None = Field(
        default=None,
        ge=0,
        le=MAX_REASONING_TOKEN_RESERVE,
    )
    provider_completion_tokens: int | None = Field(default=None, ge=0)
    visible_completion_tokens: int | None = Field(default=None, ge=0)
    state: ReasoningExecutionState
    request_token_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_body_sha256: str = Field(pattern=_SHA256_PATTERN)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        request_plan: ReasoningRequestPlanEvidence,
        observed_reasoning_tokens: int | None,
        provider_completion_tokens: int | None,
        request_token_plan_sha256: str,
        request_body_sha256: str,
    ) -> Self:
        """Seal provider reasoning observation without converting absence to zero."""

        disabled = request_plan.control_profile.mode == "disabled"
        observation_available = observed_reasoning_tokens is not None
        if disabled:
            state: ReasoningExecutionState = (
                "disabled_observed" if observation_available else "disabled_unreported"
            )
        elif observation_available:
            state = "active_observed"
        elif provider_completion_tokens is not None:
            state = "active_unavailable"
        else:
            state = "failed_before_observation"
        visible_completion_tokens = (
            provider_completion_tokens - (observed_reasoning_tokens or 0)
            if provider_completion_tokens is not None and (observation_available or disabled)
            else None
        )
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "request_plan": request_plan,
            "reserved_reasoning_tokens": (request_plan.control_profile.reserved_reasoning_tokens),
            "observation_available": observation_available,
            "observed_reasoning_tokens": observed_reasoning_tokens,
            "provider_completion_tokens": provider_completion_tokens,
            "visible_completion_tokens": visible_completion_tokens,
            "state": state,
            "request_token_plan_sha256": request_token_plan_sha256,
            "request_body_sha256": request_body_sha256,
        }
        payload["evidence_sha256"] = _canonical_sha256(payload)
        try:
            return cls.model_validate(payload)
        except ValueError as exc:
            raise ReasoningPolicyError("reasoning execution evidence is invalid") from exc

    @model_validator(mode="after")
    def execution_conserves_tokens_and_is_self_hashed(self) -> Self:
        control = self.request_plan.control_profile
        if self.reserved_reasoning_tokens != control.reserved_reasoning_tokens:
            raise ValueError("reasoning execution reserve differs from its control profile")
        if self.observation_available != (self.observed_reasoning_tokens is not None):
            raise ValueError("reasoning observation availability is inconsistent")
        disabled = control.mode == "disabled"
        if disabled:
            expected_state: ReasoningExecutionState = (
                "disabled_observed" if self.observation_available else "disabled_unreported"
            )
            if self.observed_reasoning_tokens not in {None, 0}:
                raise ValueError("disabled reasoning cannot report positive reasoning tokens")
        elif self.observation_available:
            expected_state = "active_observed"
        elif self.provider_completion_tokens is not None:
            expected_state = "active_unavailable"
        else:
            expected_state = "failed_before_observation"
        if self.state != expected_state:
            raise ValueError("reasoning execution state is inconsistent")
        if (
            self.observed_reasoning_tokens is not None
            and self.observed_reasoning_tokens > self.reserved_reasoning_tokens
        ):
            raise ValueError("observed reasoning exceeds the reserved ceiling")
        expected_visible = (
            self.provider_completion_tokens - (self.observed_reasoning_tokens or 0)
            if self.provider_completion_tokens is not None
            and (self.observation_available or disabled)
            else None
        )
        if expected_visible is not None and expected_visible < 0:
            raise ValueError("observed reasoning exceeds provider completion tokens")
        if self.visible_completion_tokens != expected_visible:
            raise ValueError("visible completion accounting is inconsistent")
        _require_self_hash(self, "evidence_sha256")
        return self


def resolve_reasoning_request_role(request_role: str) -> ReasoningRequestRoleResolution:
    """Return immutable semantic and configured-policy routing for one request."""

    return ReasoningRequestRoleResolution.build(request_role)


def normalize_reasoning_request_role(request_role: str) -> str:
    """Map one exact host request role to a canonical policy role or fail closed."""

    return resolve_reasoning_request_role(request_role).configured_policy_role


def reasoning_policy_roles_for_qualified_role(qualified_role: str) -> tuple[str, ...]:
    """Return every configured policy route that one approved role may authorize."""

    if qualified_role == "whole_protocol_review":
        return ("threat_model",)
    if qualified_role == "falsifier":
        return ("falsifier", "verifier")
    if qualified_role in CANONICAL_REASONING_POLICY_ROLES:
        return (qualified_role,)
    raise ReasoningPolicyError("qualified role has no exact reasoning policy route")


def reasoning_qualification_benchmark_role(
    *,
    qualified_role: str,
    configured_policy_role: str,
) -> str:
    """Build the closed prequalification role for one exact production route."""

    if configured_policy_role not in reasoning_policy_roles_for_qualified_role(qualified_role):
        raise ReasoningPolicyError(
            "reasoning qualification benchmark role is not an approved production route"
        )
    return f"model_benchmark:{qualified_role}:{configured_policy_role}"


def _resolve_reasoning_request_role_fields(
    request_role: str,
) -> tuple[str, str, str, ReasoningRequestRoleMappingKind]:
    """Resolve the closed request-role grammar without accepting prefix near-misses."""

    if not isinstance(request_role, str):
        raise ReasoningPolicyError("reasoning request role must be a string")
    if request_role in ALL_MODEL_ROLES:
        return request_role, request_role, request_role, "base_exact"
    if request_role == "model_benchmark":
        return (
            "model_benchmark",
            "source_audit",
            "model_benchmark",
            "prequalification_benchmark",
        )
    qualification_benchmark = _ROLE_QUALIFICATION_BENCHMARK_REQUEST.fullmatch(request_role)
    if qualification_benchmark is not None:
        qualified_role, configured_policy_role = qualification_benchmark.groups()
        if configured_policy_role not in reasoning_policy_roles_for_qualified_role(qualified_role):
            raise ReasoningPolicyError(
                "reasoning qualification benchmark names an invalid production route"
            )
        return (
            configured_policy_role,
            configured_policy_role,
            qualified_role,
            "prequalification_role_benchmark",
        )

    specialist_match = _SPECIALIST_REQUEST_ROLE.fullmatch(request_role)
    if specialist_match is not None:
        specialist_role = specialist_match.group(1)
        if specialist_role in SPECIALIST_INVESTIGATOR_ROLES:
            return (
                specialist_role,
                specialist_role,
                specialist_role,
                "specialist_investigator",
            )
        if specialist_role in ALL_SPECIALIST_ROLES:
            return (
                specialist_role,
                specialist_role,
                specialist_role,
                "specialist_auxiliary",
            )
        raise ReasoningPolicyError("reasoning request names an unknown specialist role")

    exploit_test_match = _EXPLOIT_TEST_REQUEST_ROLE.fullmatch(request_role)
    if exploit_test_match is not None:
        configured_role = exploit_test_match.group(1)
        if configured_role in _DEDICATED_EXPLOIT_TEST_ROLES:
            return (
                configured_role,
                configured_role,
                configured_role,
                "dedicated_exploit_test",
            )
        if (
            configured_role in _FALLBACK_BASE_EXPLOIT_TEST_ROLES
            or configured_role in SPECIALIST_INVESTIGATOR_ROLES
        ):
            return (
                "exploit_reproduction_planner",
                configured_role,
                configured_role,
                "fallback_exploit_test",
            )
        raise ReasoningPolicyError("reasoning request names an invalid exploit-test role")

    if request_role == "falsifier":
        return "falsifier", "verifier", "falsifier", "falsifier_fallback"
    if request_role == "candidate_cross_examination":
        return (
            "falsifier",
            "falsifier",
            "falsifier",
            "candidate_cross_examination_context",
        )
    if _CANDIDATE_FALSIFIER_REQUEST_ROLE.fullmatch(request_role) is not None:
        return "falsifier", "falsifier", "falsifier", "candidate_cross_examination"
    if _WHOLE_PROTOCOL_REQUEST_ROLE.fullmatch(request_role) is not None:
        return (
            "whole_protocol_review",
            "threat_model",
            "whole_protocol_review",
            "whole_protocol_indexed",
        )
    raise ReasoningPolicyError("reasoning request role is not a recognized exact form")


def _require_self_hash(model: BaseModel, field: str) -> None:
    observed = getattr(model, field)
    if not isinstance(observed, str) or _SHA256_RE.fullmatch(observed) is None:
        raise ValueError(f"{field} is invalid")
    expected = _canonical_sha256(model.model_dump(mode="json", exclude={field}))
    if observed != expected:
        raise ValueError(f"{field} does not match the canonical reasoning evidence")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_canonical_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


__all__ = [
    "CANONICAL_REASONING_POLICY_ROLES",
    "MAX_REASONING_TOKEN_RESERVE",
    "ReasoningControlMode",
    "ReasoningControlProfile",
    "ReasoningEffort",
    "ReasoningExecutionEvidence",
    "ReasoningExecutionState",
    "ReasoningPlanBindingState",
    "ReasoningPolicyArtifact",
    "ReasoningPolicyError",
    "ReasoningPolicyRoleProfile",
    "ReasoningRequestPlanEvidence",
    "ReasoningRequestRoleMappingKind",
    "ReasoningRequestRoleResolution",
    "ReasoningRolePolicy",
    "normalize_reasoning_request_role",
    "reasoning_policy_roles_for_qualified_role",
    "reasoning_qualification_benchmark_role",
    "resolve_reasoning_request_role",
]
