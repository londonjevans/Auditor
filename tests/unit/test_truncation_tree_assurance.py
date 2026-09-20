"""Original-journal synthetic assurance acceptance, with no real provider or release claim."""

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.scheduler import SchedulerCampaignStatus
from mmaudit.models.schemas import UsageRecord
from mmaudit.orchestration import pipeline
from mmaudit.orchestration.model_coverage import build_model_review_coverage
from tests.conftest import base_config_data
from tests.truncation_tree_assurance_support import (
    CompleteTreeAssuranceFixture,
    build_complete_tree_assurance_fixture,
)
from tests.unit import test_assurance as assurance


@pytest.fixture(scope="module")
def complete_tree(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[AuditConfig, CompleteTreeAssuranceFixture]]:
    """Share only the original live owner; negative cases replace consumer inputs."""

    def config_factory(**sections: Any) -> AuditConfig:
        data = base_config_data()
        # Match the original campaign's fixed synthetic ledger ceiling and report budget.
        data["execution"]["budget_usd"] = 250
        for section, updates in sections.items():
            if isinstance(data.get(section), dict):
                data[section].update(updates)
            else:
                data[section] = updates
        return AuditConfig.model_validate(data)

    config = assurance._maximum_config(config_factory)
    fixture = build_complete_tree_assurance_fixture(
        config,
        tmp_path_factory.mktemp("full-tree-assurance") / "private" / "scheduler-journal",
    )
    try:
        yield config, fixture
    finally:
        fixture.close()


def _requirements(config: AuditConfig, runtime: Any) -> dict[str, Any]:
    return {
        item.engine: item
        for item in assurance.MaximumAssuranceContract(config).evaluate(runtime).requirements
    }


def test_full_tree_recovery_completes_original_seven_pass_critical_surface_joins(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture],
) -> None:
    config, fixture = complete_tree
    runtime = fixture.runtime
    assert runtime.scheduler_artifact.summary.status is SchedulerCampaignStatus.COMPLETE
    assert len(runtime.scheduler_artifact.summary.pass_results) == 7
    assert len(fixture.projection.bridge_usage_records) == 2
    assert len(fixture.projection.leaf_usage_records) == 4
    assert runtime.model_review_coverage.critical_gate_passed, {
        surface.surface_id: [
            (ref.review_role, ref.root_lineage, ref.credited, ref.reason)
            for ref in surface.evidence_references
        ]
        for surface in runtime.model_review_coverage.surfaces
    }
    requirements = _requirements(config, runtime)
    for name in ("critical_model_surface_review", "seven_pass_scheduler"):
        assert requirements[name].passed, requirements[name].detail


@pytest.mark.parametrize(
    "field",
    (
        "production_qualification",
        "verified_audit_model_selection",
        "audit_model_refresh_guard",
        "audit_model_refresh_pricing_authority",
    ),
)
def test_complete_tree_cannot_replace_current_authority_with_declared_coverage(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture], field: str
) -> None:
    config, fixture = complete_tree
    runtime = replace(fixture.runtime, **{field: None})
    assert runtime.model_review_coverage.critical_gate_passed
    requirements = _requirements(config, runtime)
    for name in ("critical_model_surface_review", "seven_pass_scheduler"):
        assert not requirements[name].passed, (field, name, requirements[name].detail)


@pytest.mark.parametrize("missing", ("promotion", "leaf_artifact"))
def test_complete_tree_requires_original_promotion_and_every_leaf_artifact(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture], missing: str
) -> None:
    config, fixture = complete_tree
    if missing == "promotion":
        runtime = replace(fixture.runtime, promoted_recursive_recovery_surface_coverages=[])
    else:
        leaf = fixture.projection.artifact.children[0].surface_artifact
        runtime = replace(
            fixture.runtime,
            model_surface_review_artifacts=[
                artifact
                for artifact in fixture.runtime.model_surface_review_artifacts
                if artifact.artifact_sha256 != leaf.artifact_sha256
            ],
        )
        assert len(runtime.model_surface_review_artifacts) == (
            len(fixture.runtime.model_surface_review_artifacts) - 1
        )
    requirements = _requirements(config, runtime)
    for name in ("critical_model_surface_review", "seven_pass_scheduler"):
        assert not requirements[name].passed, (missing, name, requirements[name].detail)


@pytest.mark.parametrize("bridge_index", (0, 1))
def test_complete_tree_requires_each_original_bridge_usage_owner(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture], bridge_index: int
) -> None:
    config, fixture = complete_tree
    bridge = fixture.projection.bridge_usage_records[bridge_index]
    copied = UsageRecord.model_validate_json(bridge.model_dump_json())
    assert copied == bridge and copied is not bridge
    runtime = replace(
        fixture.runtime,
        model_usage=[copied if usage is bridge else usage for usage in fixture.runtime.model_usage],
    )
    requirements = _requirements(config, runtime)
    for name in ("critical_model_surface_review", "seven_pass_scheduler"):
        assert not requirements[name].passed, (bridge_index, name, requirements[name].detail)


@pytest.mark.parametrize("owner_index", (0, 1, 2))
def test_retained_parent_and_bridge_reviews_require_their_own_source_context(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture], owner_index: int
) -> None:
    config, fixture = complete_tree
    owners = (fixture.projection.artifact.parent, *fixture.projection.artifact.bridges)
    owner = owners[owner_index]
    contexts = dict(fixture.coverage_arguments["review_contexts_by_request"])
    assert contexts.pop(owner.usage_record.request_id)
    coverage = build_model_review_coverage(
        config, **(fixture.coverage_arguments | {"review_contexts_by_request": contexts})
    )
    assert not coverage.critical_gate_passed
    retained = {record.surface_id for record in owner.projection.surface_reviews}
    assert retained
    assert not any(
        ref.credited and ref.request_id == owner.usage_record.request_id
        for surface in coverage.surfaces
        if surface.surface_id in retained
        for ref in surface.evidence_references
    )


def test_original_complete_campaign_credits_only_the_four_promoted_leaves(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture],
) -> None:
    _config, fixture = complete_tree
    authorities = pipeline._require_current_promoted_recovery_leaf_authorities(
        direct_capabilities=(), recursive_capabilities=(fixture.capability,)
    )
    requests = fixture.runtime.scheduler_artifact.recovery_model_requests
    leaves = pipeline._require_promoted_recovery_leaf_requests(
        authorities=authorities, recovery_requests=requests
    )
    expected = {usage.request_id for usage in fixture.projection.leaf_usage_records}
    assert {authority.request_id for authority in authorities} == expected
    assert {request.logical_request_id for request in leaves} == expected
    credited = pipeline._minimum_floor_creditable_usage_records(
        usage_records=fixture.runtime.model_usage,
        # Even if the caller declares every request successful, truncated owners cannot count.
        successful_request_ids={usage.request_id for usage in fixture.runtime.model_usage},
        all_recovery_requests=tuple(requests),
        promoted_recovery_leaf_requests=leaves,
    )
    credited_ids = {usage.request_id for usage in credited}
    assert expected <= credited_ids
    assert fixture.projection.parent_usage_record.request_id not in credited_ids
    assert (
        not {usage.request_id for usage in fixture.projection.bridge_usage_records} & credited_ids
    )


@pytest.mark.parametrize("changed", ("usage_record_sha256", "promotion_entry_sha256", "role"))
def test_original_leaf_authority_refuses_substituted_public_coordinates(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture], changed: str
) -> None:
    _config, fixture = complete_tree
    authorities = pipeline._require_current_promoted_recovery_leaf_authorities(
        direct_capabilities=(), recursive_capabilities=(fixture.capability,)
    )
    leaf_id = authorities[0].request_id
    requests = tuple(
        request.model_copy(update={changed: "substituted-role" if changed == "role" else "f" * 64})
        if request.logical_request_id == leaf_id
        else request
        for request in fixture.runtime.scheduler_artifact.recovery_model_requests
    )
    with pytest.raises(ValueError, match="differs from scheduler comparison evidence"):
        pipeline._require_promoted_recovery_leaf_requests(
            authorities=authorities, recovery_requests=requests
        )
