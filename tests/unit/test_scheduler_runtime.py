from __future__ import annotations

from collections.abc import Callable

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.scheduler import (
    ABSENT_QUALIFICATION_SHA256,
    SchedulerShardKind,
)
from mmaudit.models.schemas import RepositoryFile, RepositoryMap
from mmaudit.orchestration.scheduler_runtime import (
    build_scheduler_shard_inventory,
    scheduler_prompt_template_inventory,
    scheduler_prompt_template_set_sha256,
    scheduler_qualification_sha256,
    scheduler_response_schema_hashes,
    scheduler_response_schema_registry,
    scheduler_response_schema_set_sha256,
    scheduler_tool_policy_sha256,
)


def _repository(*files: RepositoryFile) -> RepositoryMap:
    return RepositoryMap(
        root_name="synthetic",
        languages={item.language: 1 for item in files},
        frameworks=[],
        manifests=[],
        entry_points=[],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=[],
        sensitive_processing=[],
        security_tests=[],
        files=list(files),
    )


def test_static_prompt_and_schema_registries_are_nonempty_stable_and_exact() -> None:
    prompts = scheduler_prompt_template_inventory()
    schemas = scheduler_response_schema_registry()

    assert prompts == scheduler_prompt_template_inventory()
    assert schemas == scheduler_response_schema_registry()
    assert prompts == tuple(sorted(prompts, key=lambda item: item["name"]))
    assert schemas == tuple(sorted(schemas, key=lambda item: item["model_type"]))
    assert len({item["name"] for item in prompts}) == len(prompts) > 0
    assert len({item["model_type"] for item in schemas}) == len(schemas) > 0
    assert scheduler_response_schema_hashes() == frozenset(
        item["schema_sha256"] for item in schemas
    )
    assert len(scheduler_prompt_template_set_sha256()) == 64
    assert len(scheduler_response_schema_set_sha256()) == 64


def test_schema_registry_cache_is_isolated_from_caller_mutation() -> None:
    expected = scheduler_response_schema_registry()
    poisoned = scheduler_response_schema_registry()
    poisoned[0]["model_type"] = "forged.Model"
    poisoned[0]["schema_sha256"] = "f" * 64

    observed = scheduler_response_schema_registry()

    assert observed == expected
    assert observed is not poisoned
    assert observed[0] is not poisoned[0]
    assert scheduler_response_schema_hashes() == frozenset(
        item["schema_sha256"] for item in expected
    )
    assert scheduler_response_schema_set_sha256() == scheduler_response_schema_set_sha256()


def test_tool_policy_hash_tracks_execution_policy_but_not_reporting_format(
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = config_factory()
    changed_tool_policy = config_factory(execution={"scanner_timeout_seconds": 901})
    changed_reporting_only = config_factory(
        reporting={"markdown": False, "json": True, "sarif": True}
    )

    assert scheduler_tool_policy_sha256(base) != scheduler_tool_policy_sha256(changed_tool_policy)
    assert scheduler_tool_policy_sha256(base) == scheduler_tool_policy_sha256(
        changed_reporting_only
    )


def test_missing_qualification_uses_typed_absence_commitment() -> None:
    assert scheduler_qualification_sha256(None) == ABSENT_QUALIFICATION_SHA256
    assert len(ABSENT_QUALIFICATION_SHA256) == 64


def test_non_solidity_source_inventory_is_one_exact_pseudo_shard() -> None:
    repository = _repository(
        RepositoryFile(
            path="app.py",
            size=7,
            lines=1,
            sha256="1" * 64,
            language="Python",
        ),
        RepositoryFile(
            path="config.toml",
            size=9,
            lines=1,
            sha256="2" * 64,
            language="TOML",
        ),
    )

    inventory = build_scheduler_shard_inventory(repository, None)

    assert inventory.source_count == 2
    assert len(inventory.shards) == 1
    assert inventory.shards[0].kind is SchedulerShardKind.REPOSITORY_PSEUDO
    assert [source.path for source in inventory.shards[0].sources] == [
        "app.py",
        "config.toml",
    ]


def test_solidity_source_cannot_fall_into_nonsemantic_pseudo_shard() -> None:
    repository = _repository(
        RepositoryFile(
            path="src/Vault.sol",
            size=11,
            lines=1,
            sha256="3" * 64,
            language="Solidity",
        )
    )

    with pytest.raises(ValueError, match="non-Solidity"):
        build_scheduler_shard_inventory(repository, None)
