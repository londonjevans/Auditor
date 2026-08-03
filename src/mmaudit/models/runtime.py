"""Translate validated product configuration into OpenRouter runtime controls."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from mmaudit.config import AuditConfig, ConfigError, ModelReasoningConfig
from mmaudit.constants import ALL_MODEL_ROLES
from mmaudit.models.openrouter import OpenRouterProviderPolicy
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningPolicyArtifact,
)
from mmaudit.models.schemas import AuditProfile, ExecutionEvidenceKind
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    TrustedPrivacyAuthorization,
    validate_trusted_privacy_authorization,
)


@dataclass(frozen=True)
class OpenRouterRuntimeControls:
    """Provider controls applied consistently at every production construction site."""

    provider_policy: OpenRouterProviderPolicy
    reasoning_policy: ReasoningPolicyArtifact


def maximum_assurance_model_certification_required(config: AuditConfig) -> bool:
    """Return whether model calls contribute to a certified assurance claim."""

    return (
        config.profile is AuditProfile.MAXIMUM_ASSURANCE
        or config.maximum_assurance.require
        or config.maximum_assurance.ci_mode
    )


def production_model_qualification_required(
    config: AuditConfig,
    *,
    execution_evidence: ExecutionEvidenceKind,
) -> bool:
    """Require current qualification for every path that could establish production evidence.

    Standard-profile calls may omit production qualification only when a closed mock transport
    makes their evidence explicitly MOCK. Maximum-assurance modes remain qualification-bound
    even under mocks so their fail-closed contract can be exercised deterministically.
    """

    return (
        maximum_assurance_model_certification_required(config)
        or execution_evidence is not ExecutionEvidenceKind.MOCK
    )


def build_openrouter_runtime_controls(
    config: AuditConfig,
    *,
    certification: bool,
    require_single_model_per_role: bool = False,
    effective_privacy_policy: EffectivePrivacyPolicyEvidence | None = None,
    privacy_authorization: TrustedPrivacyAuthorization | None = None,
) -> OpenRouterRuntimeControls:
    """Build fail-closed request controls without accessing operator secrets."""

    policy = config.models.provider_policy
    configured_endpoints = policy.only or policy.order
    if len(configured_endpoints) > 1 or policy.allow_fallbacks:
        raise ConfigError(
            "identity-bound model execution currently requires one exact provider endpoint "
            "and forbids provider fallback routing"
        )
    if certification:
        if not config.privacy.require_zdr:
            if effective_privacy_policy is None or privacy_authorization is None:
                raise ConfigError(
                    "non-ZDR OpenRouter certification requires live operator privacy authorization"
                )
            try:
                validate_trusted_privacy_authorization(
                    privacy_authorization,
                    evidence_sha256=effective_privacy_policy.evidence_sha256,
                    source_sha256=effective_privacy_policy.source_sha256,
                    source_classification=effective_privacy_policy.source_classification,
                    configured_model_ids=effective_privacy_policy.permitted_model_ids,
                    configured_provider_endpoints=effective_privacy_policy.permitted_provider_endpoints,
                    requested_budget_usd=Decimal(str(config.execution.budget_usd)),
                    now=datetime.now(UTC).replace(microsecond=0),
                )
            except ValueError as exc:
                raise ConfigError(
                    f"non-ZDR OpenRouter certification privacy authorization failed: {exc}"
                ) from None
        if not (policy.only or policy.order):
            raise ConfigError(
                "OpenRouter certification requires an explicit provider endpoint allowlist"
            )
        if policy.allow_fallbacks:
            raise ConfigError("OpenRouter certification forbids provider fallback routing")
        if config.execution.max_json_repair_attempts:
            raise ConfigError("OpenRouter certification forbids model-output repair")
        if require_single_model_per_role:
            fallback_roles = [
                role
                for role in (
                    *ALL_MODEL_ROLES,
                    *sorted(config.models.specialists),
                )
                if config.models.role(role).fallbacks
            ]
            if fallback_roles:
                raise ConfigError(
                    "OpenRouter certification requires exactly one model per role; "
                    "configured model fallbacks remain for: " + ", ".join(fallback_roles)
                )

    reasoning_policy = build_reasoning_policy(config)
    if certification:
        _require_consistent_reasoning_parameter_presence(config, reasoning_policy)
    return OpenRouterRuntimeControls(
        provider_policy=OpenRouterProviderPolicy(
            certification=certification,
            only=policy.only,
            order=policy.order,
            allow_fallbacks=policy.allow_fallbacks,
        ),
        reasoning_policy=reasoning_policy,
    )


def build_reasoning_policy(config: AuditConfig) -> ReasoningPolicyArtifact:
    """Build the provider-independent exact per-role reasoning policy."""

    reasoning_controls = {
        role: _reasoning_control_for_configured_role(config, role)
        for role in CANONICAL_REASONING_POLICY_ROLES
    }
    return ReasoningPolicyArtifact.build(controls_by_role=reasoning_controls)


def _reasoning_control_for_configured_role(
    config: AuditConfig,
    role: str,
) -> ReasoningControlProfile:
    role_config = (
        config.models.role(role)
        if role in ALL_MODEL_ROLES or role in config.models.specialists
        else None
    )
    configured = (
        role_config.reasoning
        if role_config is not None and role_config.reasoning is not None
        else config.models.reasoning
    )
    return _reasoning_control_from_config(configured)


def _reasoning_control_from_config(
    configured: ModelReasoningConfig,
) -> ReasoningControlProfile:
    if configured.max_tokens is not None:
        return ReasoningControlProfile.build(
            mode="max_tokens",
            max_tokens=configured.max_tokens,
            exclude=configured.exclude,
            reserved_reasoning_tokens=configured.max_tokens,
        )
    if configured.effort is not None:
        return ReasoningControlProfile.build(
            mode="effort",
            effort=configured.effort,
            exclude=configured.exclude,
            reserved_reasoning_tokens=configured.reserved_tokens or 0,
        )
    if configured.exclude or configured.reserved_tokens is not None:
        assert configured.reserved_tokens is not None
        return ReasoningControlProfile.build(
            mode="default",
            exclude=configured.exclude,
            reserved_reasoning_tokens=configured.reserved_tokens,
        )
    return ReasoningControlProfile.build(
        mode="disabled",
        reserved_reasoning_tokens=0,
    )


def _require_consistent_reasoning_parameter_presence(
    config: AuditConfig,
    policy: ReasoningPolicyArtifact,
) -> None:
    """Keep each exact model on one frozen request-parameter shape."""

    request_shape_by_model: dict[str, bool] = {}
    conflicting: set[str] = set()
    for role in (*ALL_MODEL_ROLES, *sorted(config.models.specialists)):
        role_config = config.models.role(role)
        emits_reasoning = (
            policy.control_for_request(
                role if role in ALL_MODEL_ROLES else f"specialist:{role}"
            ).mode
            != "disabled"
        )
        for model in (role_config.primary, *role_config.fallbacks):
            previous = request_shape_by_model.setdefault(model, emits_reasoning)
            if previous is not emits_reasoning:
                conflicting.add(model)
    if conflicting:
        raise ConfigError(
            "one exact model cannot mix reasoning-enabled and reasoning-disabled "
            "certification request shapes: " + ", ".join(sorted(conflicting))
        )
