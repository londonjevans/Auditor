from __future__ import annotations

import pytest

from mmaudit.config import ConfigError
from mmaudit.models.runtime import (
    build_openrouter_runtime_controls,
    maximum_assurance_model_certification_required,
)
from mmaudit.models.schemas import AuditProfile


def test_standard_runtime_controls_preserve_explicit_routing_and_reasoning(
    config_factory,
) -> None:
    config = config_factory(
        models={
            "provider_policy": {
                "only": ["anthropic", "google-vertex/us-east5"],
                "allow_fallbacks": True,
            },
            "reasoning": {"effort": "high", "exclude": True},
        }
    )

    controls = build_openrouter_runtime_controls(config, certification=False)

    assert controls.provider_policy.certification is False
    assert controls.provider_policy.only == ("anthropic", "google-vertex/us-east5")
    assert controls.provider_policy.allow_fallbacks is True
    assert controls.reasoning is not None
    assert controls.reasoning.as_request_payload() == {
        "exclude": True,
        "effort": "high",
    }


def test_default_runtime_does_not_emit_an_unrequested_reasoning_parameter(
    config_factory,
) -> None:
    controls = build_openrouter_runtime_controls(
        config_factory(),
        certification=False,
    )

    assert controls.reasoning is None


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
    with pytest.raises(ConfigError, match="zero-data-retention"):
        build_openrouter_runtime_controls(
            config_factory(
                privacy={"require_zdr": False},
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
    multi_endpoint = build_openrouter_runtime_controls(
        config_factory(
            execution={"max_json_repair_attempts": 0},
            models={"provider_policy": {"only": ["anthropic", "google-vertex"]}},
        ),
        certification=True,
    )
    assert multi_endpoint.provider_policy.configured_endpoints == (
        "anthropic",
        "google-vertex",
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
