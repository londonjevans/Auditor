"""Original seven-pass specialist recovery reaches real consumers with synthetic authorities."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.scheduler import SchedulerCampaignStatus
from mmaudit.models.schemas import SpecialistExecutionStatus, UsageRecord
from tests.conftest import base_config_data, model_registry_entry
from tests.truncation_tree_assurance_support import (
    CompleteTreeAssuranceFixture,
    build_complete_tree_assurance_fixture,
)
from tests.unit import test_assurance as assurance
from tests.unit.test_truncation_tree_assurance import _requirements


@pytest.fixture(scope="module")
def complete_specialist_tree(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[AuditConfig, CompleteTreeAssuranceFixture]]:
    def config_factory(**sections: Any) -> AuditConfig:
        data = base_config_data()
        data["execution"]["budget_usd"] = 250
        for section, updates in sections.items():
            if isinstance(data.get(section), dict):
                data[section].update(updates)
            else:
                data[section] = updates
        return AuditConfig.model_validate(data)

    config = assurance._maximum_config(config_factory)
    # Declare this synthetic identity before qualification, selection or journal creation.
    # The ordinary fixture only registered base-role models; its specialist file reviews
    # were never eligible to contribute credited rich surfaces.
    raw = config.model_dump(mode="json")
    specialist_model = config.models.specialists["access_control"].primary
    assert all(
        entry["canonical_model_id"] != specialist_model for entry in raw["models"]["registry"]
    )
    entry = model_registry_entry(specialist_model)
    raw["models"]["registry"].append(entry)
    raw["privacy"]["approved_model_lineages"].append(entry["root_lineage"])
    config = AuditConfig.model_validate(raw)
    fixture = build_complete_tree_assurance_fixture(
        config,
        tmp_path_factory.mktemp("specialist-assurance") / "private" / "scheduler-journal",
        recovery_role="specialist:access_control",
    )
    try:
        yield config, fixture
    finally:
        fixture.close()


def test_original_specialist_tree_completes_execution_and_seven_pass_surface_joins(
    complete_specialist_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture],
) -> None:
    config, fixture = complete_specialist_tree
    runtime = fixture.runtime
    assert runtime.scheduler_artifact.summary.status is SchedulerCampaignStatus.COMPLETE
    assert len(runtime.scheduler_artifact.summary.pass_results) == 7
    assert {
        request.schema_version for request in runtime.scheduler_artifact.recovery_model_requests
    } == {"1.4"}
    assert runtime.model_review_coverage.critical_gate_passed
    record = next(
        item for item in runtime.specialist_execution_records if item.role == "access_control"
    )
    assert record.status is SpecialistExecutionStatus.COMPLETED
    assert record.failed_request_ids == ()
    assert set(record.successful_request_ids) == {
        usage.request_id for usage in fixture.projection.leaf_usage_records
    }
    assert len(record.accepted_outcomes) == 4
    failed_ids = {
        fixture.projection.parent_usage_record.request_id,
        *(usage.request_id for usage in fixture.projection.bridge_usage_records),
    }
    assert failed_ids.isdisjoint(outcome.request_id for outcome in record.accepted_outcomes)
    assert failed_ids <= {usage.request_id for usage in runtime.model_usage}
    requirements = _requirements(config, runtime)
    for name in ("critical_model_surface_review", "seven_pass_scheduler"):
        assert requirements[name].passed, requirements[name].detail


def test_missing_original_specialist_outcomes_refuse_assurance(
    complete_specialist_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture],
) -> None:
    config, fixture = complete_specialist_tree
    runtime = replace(
        fixture.runtime,
        specialist_execution_records=[
            record
            for record in fixture.runtime.specialist_execution_records
            if record.role != "access_control"
        ],
    )
    requirement = _requirements(config, runtime)["seven_pass_scheduler"]
    assert not requirement.passed
    assert "host-accepted outcomes" in requirement.detail


@pytest.mark.parametrize("owner", ("parent", "bridge", "leaf"))
def test_specialist_assurance_rejects_detached_original_usage(
    complete_specialist_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture], owner: str
) -> None:
    config, fixture = complete_specialist_tree
    target = {
        "parent": fixture.projection.parent_usage_record,
        "bridge": fixture.projection.bridge_usage_records[0],
        "leaf": fixture.projection.leaf_usage_records[0],
    }[owner]
    copied = UsageRecord.model_validate_json(target.model_dump_json())
    runtime = replace(
        fixture.runtime,
        model_usage=[copied if usage is target else usage for usage in fixture.runtime.model_usage],
    )
    assert not _requirements(config, runtime)["seven_pass_scheduler"].passed
