"""Translate validated product configuration into OpenRouter runtime controls."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from mmaudit.config import AuditConfig, ConfigError
from mmaudit.constants import ALL_MODEL_ROLES
from mmaudit.models.openrouter import OpenRouterProviderPolicy, OpenRouterReasoning
from mmaudit.models.schemas import AuditProfile
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    TrustedPrivacyAuthorization,
    validate_trusted_privacy_authorization,
)


@dataclass(frozen=True)
class OpenRouterRuntimeControls:
    """Provider controls applied consistently at every production construction site."""

    provider_policy: OpenRouterProviderPolicy
    reasoning: OpenRouterReasoning | None


def maximum_assurance_model_certification_required(config: AuditConfig) -> bool:
    """Return whether model calls contribute to a certified assurance claim."""

    return (
        config.profile is AuditProfile.MAXIMUM_ASSURANCE
        or config.maximum_assurance.require
        or config.maximum_assurance.ci_mode
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

    reasoning_config = config.models.reasoning
    reasoning = (
        None
        if (
            reasoning_config.effort is None
            and reasoning_config.max_tokens is None
            and not reasoning_config.exclude
        )
        else OpenRouterReasoning(
            effort=reasoning_config.effort,
            max_tokens=reasoning_config.max_tokens,
            exclude=reasoning_config.exclude,
        )
    )
    return OpenRouterRuntimeControls(
        provider_policy=OpenRouterProviderPolicy(
            certification=certification,
            only=policy.only,
            order=policy.order,
            allow_fallbacks=policy.allow_fallbacks,
        ),
        reasoning=reasoning,
    )
