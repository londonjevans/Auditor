"""Synthetic full-report configuration must satisfy unchanged qualification checks."""

from datetime import UTC, datetime
from typing import Any

import pytest

from mmaudit.config import AuditConfig, configured_model_ids, model_lineage_index
from mmaudit.constants import ALL_MODEL_ROLES
from mmaudit.models.registry import ModelRegistry
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.truncation_tree_report_support import candidate_report_config
from tests.unit import test_assurance as assurance


@pytest.fixture(scope="module")
def configured_report_authorities() -> tuple[AuditConfig, Any]:
    config = candidate_report_config()
    now = datetime.now(UTC).replace(microsecond=0)
    return config, assurance._assurance_policy_selection(config, now)


def test_original_report_config_declares_every_primary_before_qualification(
    configured_report_authorities: tuple[AuditConfig, Any],
) -> None:
    config, authorities = configured_report_authorities
    primary_ids = set(configured_model_ids(config))
    lineages = model_lineage_index(config)
    assert len(primary_ids) == 14
    assert all(model_id in lineages for model_id in primary_ids)
    assert {lineages[model_id].root_lineage for model_id in primary_ids} <= set(
        config.privacy.approved_model_lineages
    )
    assert all(
        not config.models.role(role).fallbacks
        for role in (*ALL_MODEL_ROLES, *config.models.specialists)
    )
    validation = ModelRegistry.validate_production_qualification(
        config, authorities.qualification, now=authorities.qualification.verified_at
    )
    assert validation.valid, validation.errors


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("lineage", "lacks an immutable lineage"),
        ("approval", "root lineage is not approved"),
        ("endpoint", "endpoint is not configured"),
        ("fallback", "forbids configured model fallbacks"),
    ),
)
def test_original_report_config_cannot_drop_required_routing_evidence(
    configured_report_authorities: tuple[AuditConfig, Any], mutation: str, message: str
) -> None:
    config, authorities = configured_report_authorities
    payload = config.model_dump(mode="json")
    specialist = next(
        entry
        for entry in payload["models"]["registry"]
        if entry["canonical_model_id"] == "specialist-0/model-0"
    )
    if mutation == "lineage":
        payload["models"]["registry"].remove(specialist)
    elif mutation == "approval":
        payload["privacy"]["approved_model_lineages"].remove(specialist["root_lineage"])
    elif mutation == "endpoint":
        payload["models"]["provider_policy"]["only"].pop()
    else:
        payload["models"]["specialists"]["falsifier"]["fallbacks"] = ["specialist-0/model-0"]
    validation = ModelRegistry.validate_production_qualification(
        AuditConfig.model_validate(payload),
        authorities.qualification,
        now=authorities.qualification.verified_at,
    )
    assert not validation.valid
    assert any(message in error for error in validation.errors), validation.errors
