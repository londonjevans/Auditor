from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import (
    ConfigError,
    ExecutionConfig,
    ModelReasoningConfig,
    configured_model_ids,
    load_config,
    model_lineage_index,
)
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.runtime import build_openrouter_runtime_controls

ROOT = Path(__file__).parents[2]
QUALIFICATION_CONFIG = ROOT / "config" / "openrouter-qualification.toml"
ROLE_MODEL_ID = "qwen/qwen3.6-35b-a3b"


def test_qualification_runtime_config_loads_without_secrets_or_claims() -> None:
    raw = QUALIFICATION_CONFIG.read_text(encoding="utf-8")
    config = load_config(QUALIFICATION_CONFIG, environ={})

    assert "OPENROUTER_API_KEY" not in raw
    assert "sk-or-" not in raw
    assert config.repository.root == ".."
    assert config.execution.budget_usd == 250.0
    assert config.execution.cost_ledger_path is None
    assert config.execution.max_model_retries == 1
    assert config.execution.max_output_tokens_per_request == 4_096
    assert config.execution.max_requests_per_agent == 512
    assert 12 * 16 * (config.execution.max_model_retries + 1) <= (
        config.execution.max_requests_per_agent
    )
    assert config.privacy.allow_code_egress is False
    assert config.privacy.require_zdr is True
    assert config.privacy.store_raw_prompts is False
    assert config.privacy.store_raw_responses is False
    assert config.privacy.approved_model_lineages == ()
    assert config.models.registry == ()
    assert config.models.allow_non_independent_models is True
    assert set(configured_model_ids(config)) == {ROLE_MODEL_ID}
    assert config.models.provider_policy.only == ()
    assert config.models.provider_policy.order == ()
    assert config.models.provider_policy.allow_fallbacks is False
    assert config.models.reasoning.effort is None
    assert config.models.reasoning.max_tokens == 4_096
    assert config.models.reasoning.exclude is False


def test_unbound_qualification_config_cannot_qualify_an_ordinary_audit() -> None:
    config = load_config(QUALIFICATION_CONFIG, environ={})
    metadata = [
        {
            "id": ROLE_MODEL_ID,
            "supported_parameters": ["response_format", "reasoning"],
        }
    ]

    assert model_lineage_index(config) == {}
    errors = ModelRegistry.validate(
        config,
        metadata,
        zdr_model_ids={ROLE_MODEL_ID},
        source_egress_requested=True,
    )
    assert any("no immutable lineage record" in error for error in errors)
    with pytest.raises(ConfigError, match="endpoint allowlist"):
        build_openrouter_runtime_controls(config, certification=True)


def test_qualification_request_limit_is_explicitly_bounded() -> None:
    assert ExecutionConfig().max_requests_per_agent == 2
    assert ExecutionConfig(max_requests_per_agent=512).max_requests_per_agent == 512
    with pytest.raises(ValidationError, match="less than or equal to 512"):
        ExecutionConfig(max_requests_per_agent=513)


def test_reasoning_effort_and_token_budget_are_mutually_exclusive_at_config_load() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        ModelReasoningConfig(effort="high", max_tokens=4_096)


def test_reasoning_can_be_explicitly_disabled_for_optional_reasoning_models() -> None:
    controls = ModelReasoningConfig(effort="none", exclude=True)

    assert controls.effort == "none"
    assert controls.max_tokens is None
    assert controls.exclude is True
