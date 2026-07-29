from __future__ import annotations

import pytest
from pydantic import ValidationError

from mmaudit.config import RepositoryForkSuiteConfig, SmartContractsConfig
from mmaudit.models.schemas import AuditProfile


def _explicit_config(**updates: object) -> RepositoryForkSuiteConfig:
    values: dict[str, object] = {
        "profile": "explicit",
        "foundry_include_paths": ("contracts/test/*.t.sol",),
        "foundry_include_tests": ("test*",),
        "hardhat_include_paths": (),
        "hardhat_include_tests": (),
    }
    values.update(updates)
    return RepositoryForkSuiteConfig.model_validate(values)


def test_repository_suite_defaults_preserve_legacy_selection_and_disable_hardhat(
    config_factory,
) -> None:
    suite = RepositoryForkSuiteConfig()
    config = config_factory()

    assert suite.profile == "legacy_audit"
    assert suite.foundry_include_paths == ("test/audit/*.t.sol",)
    assert suite.foundry_include_tests == ("*",)
    assert suite.hardhat_include_paths == ()
    assert suite.fuzz_seed == "0x" + ("0" * 63) + "1"
    assert config.smart_contracts.repository_suite == suite
    assert config.scanners.hardhat_fork.enabled is False
    assert config.scanners.hardhat_fork.required is False
    assert (
        suite.stable_hash()
        == RepositoryForkSuiteConfig.model_validate_json(suite.model_dump_json()).stable_hash()
    )
    maximum = config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE).effective()
    assert maximum.scanners.hardhat_fork.enabled is False
    assert maximum.scanners.hardhat_fork.required is False


def test_explicit_repository_suite_requires_authored_narrow_framework_selections() -> None:
    suite = _explicit_config(
        foundry_exclude_paths=("contracts/test/integration/*.t.sol",),
        foundry_exclude_tests=("testFork*",),
    )

    assert suite.profile == "explicit"
    assert suite.max_selected_files == 100

    with pytest.raises(ValidationError, match="requires explicit Foundry and Hardhat"):
        RepositoryForkSuiteConfig(profile="explicit")
    with pytest.raises(ValidationError, match="selects no tests"):
        RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=(),
            foundry_include_tests=(),
            hardhat_include_paths=(),
            hardhat_include_tests=(),
        )
    with pytest.raises(ValidationError, match="both include-path and include-test"):
        _explicit_config(foundry_include_tests=())


def test_legacy_repository_suite_cannot_silently_broaden() -> None:
    with pytest.raises(ValidationError, match="cannot broaden"):
        RepositoryForkSuiteConfig(
            profile="legacy_audit",
            foundry_include_paths=("test/**/*.t.sol",),
        )
    with pytest.raises(ValidationError, match="cannot broaden"):
        RepositoryForkSuiteConfig(
            profile="legacy_audit",
            hardhat_include_paths=("test/*.ts",),
            hardhat_include_tests=("*",),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("foundry_include_paths", ("/test/*.t.sol",)),
        ("foundry_include_paths", ("../test/*.t.sol",)),
        ("foundry_include_paths", ("test\\*.t.sol",)),
        ("foundry_include_paths", ("test/.env/*.t.sol",)),
        ("foundry_include_paths", ("test/\u202e/*.t.sol",)),
        ("foundry_include_paths", ("test/*.t.sol", "test/*.t.sol")),
        ("foundry_include_paths", ("z/*.t.sol", "a/*.t.sol")),
        ("foundry_include_tests", ("-vvv",)),
        ("foundry_include_tests", ("test\nInjected",)),
        ("foundry_include_tests", ("test\u202eInjected",)),
        ("foundry_include_tests", ("testZ*", "testA*")),
    ],
)
def test_repository_suite_globs_reject_unsafe_duplicate_or_noncanonical_values(
    field: str,
    value: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError, match="safe, unique, and canonically sorted"):
        _explicit_config(**{field: value})


@pytest.mark.parametrize(
    "updates",
    [
        {"max_selected_files": 0},
        {"max_tests_per_file": 0},
        {"max_total_tests": 0},
        {"per_test_timeout_seconds": 0},
        {"total_timeout_seconds": 0},
        {"max_output_bytes_per_test": 0},
        {"max_total_output_bytes": 0},
        {"fuzz_seed": "0x" + ("A" * 64)},
        {"fuzz_seed": "0x01"},
    ],
)
def test_repository_suite_limits_and_seed_fail_closed(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _explicit_config(**updates)


def test_repository_suite_aggregate_ceilings_cover_one_test() -> None:
    with pytest.raises(ValidationError, match="total timeout"):
        _explicit_config(per_test_timeout_seconds=121, total_timeout_seconds=120)
    with pytest.raises(ValidationError, match="total output"):
        _explicit_config(
            max_output_bytes_per_test=2_000_000,
            max_total_output_bytes=1_000_000,
        )


def test_smart_contract_config_round_trip_preserves_explicit_repository_suite() -> None:
    config = SmartContractsConfig(repository_suite=_explicit_config())

    restored = SmartContractsConfig.model_validate_json(config.model_dump_json())

    assert restored == config
    assert restored.repository_suite.profile == "explicit"


def test_repository_suite_fork_matrix_requires_clean_and_pinned_states() -> None:
    suite = _explicit_config(
        fork_matrix_repetitions=2,
        fork_matrix_states=(
            {
                "state_id": "clean-local",
                "kind": "clean_local",
                "rpc_url_env": "MMAUDIT_CLEAN_LOCAL_RPC_URL",
                "expected_chain_id": 31_337,
                "pinned_block_number": 0,
                "state_source_sha256": "a" * 64,
            },
            {
                "state_id": "pinned-state",
                "kind": "pinned_fork",
                "rpc_url_env": "MMAUDIT_PINNED_FORK_RPC_URL",
                "expected_chain_id": 1,
                "pinned_block_number": 20_000_000,
                "state_source_sha256": "b" * 64,
            },
        ),
    )

    assert suite.fork_matrix_repetitions == 2
    assert [state.state_id for state in suite.fork_matrix_states] == [
        "clean-local",
        "pinned-state",
    ]

    with pytest.raises(ValidationError, match="one clean-local state"):
        _explicit_config(
            fork_matrix_states=(
                {
                    "state_id": "pinned-only",
                    "kind": "pinned_fork",
                    "rpc_url_env": "MMAUDIT_PINNED_FORK_RPC_URL",
                    "expected_chain_id": 1,
                    "pinned_block_number": 20_000_000,
                    "state_source_sha256": "b" * 64,
                },
            ),
        )
    with pytest.raises(ValidationError, match="at least two fresh repetitions"):
        _explicit_config(
            fork_matrix_repetitions=1,
            fork_matrix_states=suite.fork_matrix_states,
        )


def test_safe_legacy_foundry_selectors_migrate_to_one_explicit_authority() -> None:
    migrated = SmartContractsConfig(
        foundry_match_path="contracts/test/*.t.sol",
        foundry_match_test="testInvariant",
    )

    assert migrated.repository_suite.profile == "explicit"
    assert migrated.repository_suite.foundry_include_paths == ("contracts/test/*.t.sol",)
    assert migrated.repository_suite.foundry_include_tests == ("testInvariant",)
    assert SmartContractsConfig.model_validate_json(migrated.model_dump_json()) == migrated

    with pytest.raises(ValidationError, match="cannot be migrated safely"):
        SmartContractsConfig(foundry_match_test="test.*")
    with pytest.raises(ValidationError, match="conflict"):
        SmartContractsConfig(
            foundry_match_path="contracts/test/*.t.sol",
            repository_suite=_explicit_config(
                foundry_include_paths=("other/test/*.t.sol",),
            ),
        )
