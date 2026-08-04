from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import (
    ConfigError,
    ExecutionConfig,
    ModelReasoningConfig,
    TokenBudgetConfig,
    configured_model_ids,
    load_config,
    model_lineage_index,
)
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.schemas import LanguageCapabilityProfile
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
    assert config.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM
    assert config.execution.budget_usd == 250.0
    assert config.execution.cost_ledger_path is None
    assert config.execution.max_model_retries == 1
    assert config.execution.max_output_tokens_per_request == 4_096
    assert config.effective_reserved_output_tokens == 4_096
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
    assert config.models.reasoning.reserved_tokens == 4_096
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
        require_verified_qualification=False,
        zdr_model_ids={ROLE_MODEL_ID},
        source_egress_requested=True,
    )
    assert any("no immutable lineage record" in error for error in errors)
    with pytest.raises(ConfigError, match="endpoint allowlist"):
        build_openrouter_runtime_controls(config, certification=True)


def test_qualification_request_limit_is_explicitly_bounded() -> None:
    assert ExecutionConfig().max_output_tokens_per_request == 32_768
    assert ExecutionConfig().max_requests_per_agent == 2
    assert ExecutionConfig(max_requests_per_agent=512).max_requests_per_agent == 512
    with pytest.raises(ValidationError, match="less than or equal to 512"):
        ExecutionConfig(max_requests_per_agent=513)


def test_endpoint_token_budget_defaults_are_high_capacity_and_bounded() -> None:
    budgets = TokenBudgetConfig()

    assert budgets.usable_input_fraction == 0.70
    assert budgets.maximum_source_tokens_per_request == 200_000
    assert budgets.reserved_workflow_tokens == 32_768
    assert budgets.reserved_output_tokens is None
    assert budgets.global_input_token_budget == 8_000_000
    assert budgets.global_output_token_budget == 2_000_000

    with pytest.raises(ValidationError, match=r"greater than or equal to 0\.65"):
        TokenBudgetConfig(usable_input_fraction=0.64)
    with pytest.raises(ValidationError, match=r"less than or equal to 0\.75"):
        TokenBudgetConfig(usable_input_fraction=0.76)
    with pytest.raises(ValidationError, match="exact model IDs"):
        TokenBudgetConfig(per_model_cost_budget_usd={"not-exact": 1})
    with pytest.raises(ValidationError, match="safe role IDs"):
        TokenBudgetConfig(per_role_cost_budget_usd={"role with spaces": 1})
    with pytest.raises(ValidationError, match="less than or equal to 65536"):
        TokenBudgetConfig(reserved_workflow_tokens=65_537)


def test_explicit_output_reserve_cannot_drift_from_request_limit() -> None:
    config = load_config(QUALIFICATION_CONFIG, environ={})
    payload = config.model_dump(mode="python")
    payload["token_budgets"]["reserved_output_tokens"] = 32_768

    with pytest.raises(ValidationError, match="output reserve"):
        type(config).model_validate(payload)


def test_reasoning_effort_and_token_budget_are_mutually_exclusive_at_config_load() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        ModelReasoningConfig(effort="high", max_tokens=4_096)


def test_named_reasoning_effort_requires_an_explicit_positive_reserve() -> None:
    with pytest.raises(ValidationError, match="positive token reserve"):
        ModelReasoningConfig(effort="high")
    with pytest.raises(ValidationError, match="must equal"):
        ModelReasoningConfig(max_tokens=4_096, reserved_tokens=2_048)


def test_reasoning_can_be_explicitly_disabled_for_optional_reasoning_models() -> None:
    controls = ModelReasoningConfig(effort="none", exclude=True)

    assert controls.effort == "none"
    assert controls.max_tokens is None
    assert controls.exclude is True
