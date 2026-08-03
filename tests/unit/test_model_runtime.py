from __future__ import annotations

import pytest

from mmaudit.config import ConfigError
from mmaudit.models.runtime import (
    build_openrouter_runtime_controls,
    maximum_assurance_model_certification_required,
    production_model_qualification_required,
)
from mmaudit.models.schemas import AuditProfile, ExecutionEvidenceKind


@pytest.mark.parametrize(
    ("execution_evidence", "required"),
    [
        (ExecutionEvidenceKind.REAL, True),
        (ExecutionEvidenceKind.UNVERIFIED, True),
        (ExecutionEvidenceKind.MOCK, False),
    ],
)
def test_standard_production_qualification_tracks_execution_evidence(
    config_factory,
    execution_evidence: ExecutionEvidenceKind,
    required: bool,
) -> None:
    assert (
        production_model_qualification_required(
            config_factory(),
            execution_evidence=execution_evidence,
        )
        is required
    )


def test_maximum_assurance_requires_qualification_even_for_mock_execution(config_factory) -> None:
    config = config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE).effective()

    assert production_model_qualification_required(
        config,
        execution_evidence=ExecutionEvidenceKind.MOCK,
    )


def test_standard_runtime_controls_require_one_exact_endpoint_without_provider_fallback(
    config_factory,
) -> None:
    config = config_factory(
        models={
            "provider_policy": {
                "only": ["anthropic", "google-vertex/us-east5"],
                "allow_fallbacks": True,
            },
            "reasoning": {
                "effort": "high",
                "reserved_tokens": 4_096,
                "exclude": True,
            },
        }
    )

    with pytest.raises(ConfigError, match="one exact provider endpoint"):
        build_openrouter_runtime_controls(config, certification=False)

    exact = config_factory(
        models={
            "provider_policy": {
                "only": ["anthropic"],
                "allow_fallbacks": False,
            },
            "reasoning": {
                "effort": "high",
                "reserved_tokens": 4_096,
                "exclude": True,
            },
        }
    )
    controls = build_openrouter_runtime_controls(exact, certification=False)
    assert controls.provider_policy.certification is False
    assert controls.provider_policy.only == ("anthropic",)
    assert controls.provider_policy.allow_fallbacks is False
    profile = controls.reasoning_policy.control_for_request("source_audit")
    assert profile.mode == "effort"
    assert profile.effort == "high"
    assert profile.exclude is True
    assert profile.reserved_reasoning_tokens == 4_096


def test_default_runtime_does_not_emit_an_unrequested_reasoning_parameter(
    config_factory,
) -> None:
    controls = build_openrouter_runtime_controls(
        config_factory(),
        certification=False,
    )

    assert controls.reasoning_policy.control_for_request("source_audit").mode == "disabled"


def test_role_reasoning_override_is_exact_and_specialist_aware(config_factory) -> None:
    base = config_factory()
    config = config_factory(
        models={
            "reasoning": {"effort": "none", "exclude": True},
            "judge": {
                **base.models.judge.model_dump(mode="python"),
                "reasoning": {
                    "effort": "xhigh",
                    "reserved_tokens": 8_192,
                    "exclude": True,
                },
            },
            "specialists": {
                "falsifier": {
                    "primary": "alpha/atlas-secure",
                    "fallbacks": [],
                    "reasoning": {
                        "max_tokens": 2_048,
                        "reserved_tokens": 2_048,
                    },
                }
            },
        }
    )

    policy = build_openrouter_runtime_controls(
        config,
        certification=False,
    ).reasoning_policy

    assert policy.control_for_request("source_audit").effort == "none"
    assert policy.control_for_request("source_audit").reserved_reasoning_tokens == 0
    assert policy.control_for_request("judge").effort == "xhigh"
    assert policy.control_for_request("judge").reserved_reasoning_tokens == 8_192
    assert (
        policy.control_for_request("candidate_falsifier:" + ("a" * 64) + ":reviewer_1").max_tokens
        == 2_048
    )


def test_certification_rejects_mixed_reasoning_parameter_shape_for_one_model(
    config_factory,
) -> None:
    base = config_factory()
    shared = base.models.source_audit.primary
    config = config_factory(
        execution={"max_json_repair_attempts": 0},
        models={
            "provider_policy": {"only": ["synthetic-provider"]},
            "reasoning": {},
            "threat_model": {
                **base.models.threat_model.model_dump(mode="python"),
                "primary": shared,
            },
            "source_audit": {
                **base.models.source_audit.model_dump(mode="python"),
                "reasoning": None,
            },
        },
    )
    payload = config.model_dump(mode="python")
    payload["models"]["source_audit"]["reasoning"] = {
        "effort": "high",
        "reserved_tokens": 4_096,
    }
    config = type(config).model_validate(payload)

    with pytest.raises(ConfigError, match="cannot mix reasoning-enabled"):
        build_openrouter_runtime_controls(config, certification=True)


def test_qualification_controls_require_endpoint_zdr_no_repair_and_no_provider_fallback(
    config_factory,
) -> None:
    valid = config_factory(
        execution={"max_json_repair_attempts": 0},
        models={"provider_policy": {"only": ["anthropic"]}},
    )
    controls = build_openrouter_runtime_controls(valid, certification=True)
    assert controls.provider_policy.certification is True
    assert controls.provider_policy.configured_endpoints == ("anthropic",)

    with pytest.raises(ConfigError, match="endpoint allowlist"):
        build_openrouter_runtime_controls(
            config_factory(
                execution={"max_json_repair_attempts": 0},
                models={"provider_policy": {"only": [], "order": []}},
            ),
            certification=True,
        )
    with pytest.raises(ConfigError, match="live operator privacy authorization"):
        build_openrouter_runtime_controls(
            config_factory(
                privacy={
                    "profile": "FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT",
                    "require_zdr": False,
                    "maximum_model_retention": "temporary",
                },
                execution={"max_json_repair_attempts": 0},
                models={"provider_policy": {"only": ["anthropic"]}},
            ),
            certification=True,
        )
    with pytest.raises(ConfigError, match="provider fallback"):
        build_openrouter_runtime_controls(
            config_factory(
                execution={"max_json_repair_attempts": 0},
                models={
                    "provider_policy": {
                        "only": ["anthropic"],
                        "allow_fallbacks": True,
                    }
                },
            ),
            certification=True,
        )
    with pytest.raises(ConfigError, match="one exact provider endpoint"):
        build_openrouter_runtime_controls(
            config_factory(
                execution={"max_json_repair_attempts": 0},
                models={"provider_policy": {"only": ["anthropic", "google-vertex"]}},
            ),
            certification=True,
        )
    with pytest.raises(ConfigError, match="model-output repair"):
        build_openrouter_runtime_controls(
            config_factory(
                execution={"max_json_repair_attempts": 1},
                models={"provider_policy": {"only": ["anthropic"]}},
            ),
            certification=True,
        )


def test_maximum_assurance_controls_reject_role_model_fallbacks(config_factory) -> None:
    base = config_factory()
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance={"allow_downgrade": True},
        models={
            "provider_policy": {"only": ["anthropic"]},
            "threat_model": {
                "primary": base.models.threat_model.primary,
                "fallbacks": ["golf/glacier-secure"],
            },
        },
    ).effective()

    assert maximum_assurance_model_certification_required(config) is True
    with pytest.raises(ConfigError, match="exactly one model per role"):
        build_openrouter_runtime_controls(
            config,
            certification=True,
            require_single_model_per_role=True,
        )


@pytest.mark.parametrize(
    "maximum_assurance",
    [
        {"require": True},
        {"ci_mode": True},
    ],
)
def test_explicit_certification_modes_require_certified_model_routing(
    config_factory,
    maximum_assurance,
) -> None:
    config = config_factory(maximum_assurance=maximum_assurance)
    assert maximum_assurance_model_certification_required(config) is True
