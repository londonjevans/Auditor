from __future__ import annotations

from pathlib import Path

import pytest

from mmaudit.config import (
    ConfigError,
    ReproductionConfig,
    load_config,
    model_family,
    validate_model_independence,
)
from mmaudit.models.schemas import AuditProfile, AuditScope
from tests.conftest import base_config_data


def _write_config(path: Path, budget: float = 20.0) -> None:
    data = base_config_data()
    lines = [
        "version = 1",
        "[repository]",
        'root = "."',
        "[privacy]",
        "allow_code_egress = true",
        "require_zdr = true",
        "redact_secrets = true",
        "fail_on_detected_secret = true",
        "store_raw_prompts = false",
        "store_raw_responses = false",
        "[execution]",
        f"budget_usd = {budget}",
        "[models]",
        "minimum_distinct_families = 3",
    ]
    for role, model in data["models"].items():
        if not isinstance(model, dict):
            continue
        lines.extend(
            [
                f"[models.{role}]",
                f'primary = "{model["primary"]}"',
                "fallbacks = []",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def test_load_configuration_and_defaults(tmp_path: Path) -> None:
    path = tmp_path / "mmaudit.toml"
    _write_config(path)
    config = load_config(path, environ={})
    assert config.version == 1
    assert config.execution.budget_usd == 20
    assert config.repository.max_file_bytes == 250_000
    assert config.repository.max_walk_entries == 50_000
    assert config.execution.max_request_bytes == 4_000_000
    assert config.reporting.json_report is True


def test_environment_overrides_are_typed(tmp_path: Path) -> None:
    path = tmp_path / "mmaudit.toml"
    _write_config(path)
    config = load_config(
        path,
        environ={
            "MMAUDIT_BUDGET_USD": "7.5",
            "MMAUDIT_CONCURRENCY": "2",
            "MMAUDIT_MAX_WALK_ENTRIES": "1234",
            "MMAUDIT_MAX_REQUEST_BYTES": "9000",
            "MMAUDIT_ALLOW_CODE_EGRESS": "false",
            "MMAUDIT_SCOPE": "contracts-and-deployment",
            "MMAUDIT_REQUIRE_COMPLETE_SCOPE": "true",
            "MMAUDIT_PRIOR_AUDIT_PATH": "audit/prior.json",
            "MMAUDIT_REQUIRE_PRIOR_AUDIT": "true",
            "MMAUDIT_FAIL_ON_MISSED_PRIOR": "true",
        },
    )
    assert config.execution.budget_usd == 7.5
    assert config.execution.concurrency == 2
    assert config.repository.max_walk_entries == 1234
    assert config.execution.max_request_bytes == 9000
    assert config.privacy.allow_code_egress is False
    assert config.scope.mode is AuditScope.CONTRACTS_AND_DEPLOYMENT
    assert config.scope.require_complete
    assert config.prior_audit.path == "audit/prior.json"
    assert config.prior_audit.required
    assert config.prior_audit.fail_on_missed


def test_environment_profile_override_is_effective(tmp_path: Path) -> None:
    path = tmp_path / "mmaudit.toml"
    _write_config(path)
    config = load_config(path, environ={"MMAUDIT_PROFILE": "maximum-assurance"})
    assert config.profile is AuditProfile.MAXIMUM_ASSURANCE
    assert config.smart_contracts.compile is True
    assert config.scanners.slither.enabled is True
    assert config.scanners.slither.required is True
    assert config.reproduction.required_for_solidity is True
    assert config.quality_gates.require_candidate_reproduction is True
    assert config.quality_gates.min_reviewed_privileged_entry_point_fraction == 1.0
    assert config.quality_gates.min_classified_external_call_fraction == 1.0
    assert config.quality_gates.min_classified_asset_flow_fraction == 1.0
    assert config.quality_gates.min_model_role_completion_fraction == 1.0


def test_invalid_environment_boolean_fails(tmp_path: Path) -> None:
    path = tmp_path / "mmaudit.toml"
    _write_config(path)
    with pytest.raises(ConfigError, match="must be a boolean"):
        load_config(path, environ={"MMAUDIT_REQUIRE_ZDR": "perhaps"})


def test_missing_config_fails(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml", environ={})


def test_configuration_validation_error_does_not_echo_rejected_secret(tmp_path: Path) -> None:
    secret = "sk-or-v1-" + ("x" * 40)
    path = tmp_path / "mmaudit.toml"
    _write_config(path)
    existing = path.read_text(encoding="utf-8")
    path.write_text(f'openrouter_api_key = "{secret}"\n{existing}', encoding="utf-8")
    with pytest.raises(ConfigError) as captured:
        load_config(path, environ={})
    assert secret not in str(captured.value)
    assert "openrouter_api_key" in str(captured.value)


def test_model_family_removes_version_suffix() -> None:
    assert model_family("anthropic/claude-sonnet-4-20250514") == "anthropic/claude-sonnet"
    assert model_family("openai/gpt-5.2") == "openai/gpt"


def test_independent_models_pass(config_factory) -> None:
    assert validate_model_independence(config_factory()) == []


def test_duplicate_models_fail(config_factory) -> None:
    config = config_factory()
    duplicate = config.models.model_copy(
        update={
            "business_logic": config.models.source_audit,
        }
    )
    config = config.model_copy(update={"models": duplicate})
    errors = validate_model_independence(config)
    assert any("duplicate" in error for error in errors)


def test_duplicate_fallback_is_also_rejected(config_factory) -> None:
    config = config_factory()
    source = config.models.source_audit.model_copy(
        update={"fallbacks": [config.models.threat_model.primary]}
    )
    config = config.model_copy(
        update={"models": config.models.model_copy(update={"source_audit": source})}
    )
    assert any("duplicate" in error for error in validate_model_independence(config))


def test_configuration_hash_is_deterministic(config_factory) -> None:
    left = config_factory()
    right = config_factory()
    assert left.stable_hash() == right.stable_hash()
    assert left.model_hash() == right.model_hash()


def test_smart_contract_defaults_are_conservative(config_factory) -> None:
    config = config_factory()
    assert config.smart_contracts.enabled is True
    assert config.smart_contracts.compile is False
    assert config.smart_contracts.allow_network is False
    assert config.smart_contracts.fork_only is True
    assert config.scanners.slither.enabled is False
    assert config.scanners.foundry_fork.enabled is False


def test_reproduction_capability_defaults_are_operator_bounded() -> None:
    config = ReproductionConfig()
    assert config.max_attacker_controlled_actors == 4
    assert config.max_attacker_controlled_contracts == 4
    assert config.allowed_token_approval_targets == []
    assert config.allowed_privileged_roles == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allowed_token_approval_targets", ["../Vault"]),
        ("allowed_privileged_roles", ["Role;rm"]),
        ("allowed_token_approval_targets", ["Vault", "Vault"]),
    ],
)
def test_reproduction_capability_names_are_safe_and_unique(
    field: str,
    value: list[str],
) -> None:
    with pytest.raises(ValueError, match="allowed capability names"):
        ReproductionConfig(**{field: value})


def test_maximum_assurance_profile_keeps_legacy_fork_scanner_opt_in(config_factory) -> None:
    config = config_factory(
        profile=AuditProfile.MAXIMUM_ASSURANCE,
        smart_contracts={"compile": False},
        reproduction={"repetitions": 1, "required_for_solidity": False},
        quality_gates={"require_candidate_reproduction": False},
        scanners={
            "slither": {"enabled": False, "required": False},
            "foundry_fork": {"enabled": False, "required": False},
        },
    ).effective()
    assert config.smart_contracts.compile is True
    assert config.reproduction.repetitions == 3
    assert config.reproduction.required_for_solidity is True
    assert config.quality_gates.require_candidate_reproduction is True
    assert config.quality_gates.min_invariant_execution_fraction >= 0.8
    assert config.quality_gates.min_dependency_resolution_fraction == 1.0
    assert config.scanners.slither.enabled is True
    assert config.scanners.slither.required is True
    assert config.scanners.foundry_fork.enabled is False
    assert config.scanners.foundry_fork.required is False


def test_smart_contract_path_and_env_validation(config_factory) -> None:
    config = config_factory(smart_contracts={"project_root": "packages/contracts"})
    assert config.smart_contracts.project_root == "packages/contracts"
    with pytest.raises(ValueError):
        config_factory(smart_contracts={"project_root": "../outside"})
    with pytest.raises(ValueError):
        config_factory(smart_contracts={"fork_rpc_url_env": "not-safe"})
