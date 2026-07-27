from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.config import (
    AuditConfig,
    configured_model_ids,
    validate_model_independence,
)
from mmaudit.models.registry import ModelRegistry
from tests.conftest import MODEL_IDS, base_config_data, model_registry_entry


def _metadata(config: AuditConfig) -> list[dict[str, Any]]:
    return [
        {
            "id": model_id,
            "supported_parameters": ["response_format"],
        }
        for model_id in configured_model_ids(config, include_fallbacks=True)
    ]


def test_lineage_record_is_immutable(config_factory) -> None:
    lineage = config_factory().models.registry[0]
    with pytest.raises(ValidationError, match="frozen"):
        lineage.root_lineage = "sha256:" + ("f" * 64)


def test_aliases_share_one_independence_slot(config_factory) -> None:
    base = config_factory()
    threat_id = base.models.threat_model.primary
    source_id = base.models.source_audit.primary
    shared = model_registry_entry(
        "synthetic/shared-root",
        aliases=[threat_id, source_id],
    )
    remaining = [
        entry.model_dump(mode="json")
        for entry in base.models.registry
        if entry.canonical_model_id not in {threat_id, source_id}
    ]
    config = config_factory(
        models={
            "minimum_distinct_families": 4,
            "registry": [shared, *remaining],
        }
    )

    errors = validate_model_independence(config)

    assert any("only 3 independent analysis model families" in error for error in errors)


def test_registry_rejects_duplicate_alias_across_lineages() -> None:
    data = base_config_data()
    duplicate = model_registry_entry(
        "synthetic/duplicate-root",
        aliases=[MODEL_IDS["threat_model"]],
    )
    data["models"]["registry"].append(duplicate)

    with pytest.raises(ValidationError, match="globally unique"):
        AuditConfig.model_validate(data)


def test_source_egress_requires_explicit_root_approval(config_factory) -> None:
    config = config_factory(privacy={"approved_model_lineages": []})

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        zdr_model_ids=set(configured_model_ids(config, include_fallbacks=True)),
        source_egress_requested=True,
    )

    assert any("root lineage is not approved" in error for error in errors)


def test_source_egress_rejects_retention_above_policy(config_factory) -> None:
    config = config_factory()
    registry = list(config.models.registry)
    registry[0] = registry[0].model_copy(update={"retention_policy": "temporary"})
    config = config.model_copy(
        update={
            "models": config.models.model_copy(update={"registry": tuple(registry)}),
        }
    )

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        zdr_model_ids=set(configured_model_ids(config, include_fallbacks=True)),
        source_egress_requested=True,
    )

    assert any(
        "retention policy temporary exceeds configured maximum zero" in error for error in errors
    )


def test_measured_quality_tier_must_satisfy_role_requirement(config_factory) -> None:
    config = config_factory()
    source = config.models.source_audit.model_copy(update={"quality_tier": "highest"})
    registry = [
        (
            entry.model_copy(
                update={
                    "measured_quality_score": 0.8,
                    "measured_quality_tier": "high",
                }
            )
            if entry.canonical_model_id == source.primary
            else entry
        )
        for entry in config.models.registry
    ]
    config = config.model_copy(
        update={
            "models": config.models.model_copy(
                update={
                    "source_audit": source,
                    "registry": tuple(registry),
                }
            )
        }
    )

    errors = ModelRegistry.validate(config, _metadata(config))

    assert any("measured quality tier is below source_audit.primary" in error for error in errors)


def test_measured_quality_tier_rejects_unqualified_score() -> None:
    data = base_config_data()
    data["models"]["registry"][0]["measured_quality_score"] = 0.5
    data["models"]["registry"][0]["measured_quality_tier"] = "high"

    with pytest.raises(ValidationError, match=r"requires score >= 0\.75"):
        AuditConfig.model_validate(data)
