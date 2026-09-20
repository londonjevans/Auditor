"""Local synthetic live-custody checks; these do not qualify any real provider."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.schemas import UsageRecord
from tests.unit import test_assurance as assurance
from tests.unit import test_model_coverage as coverage_support


@pytest.mark.parametrize("parent_retained_count,bridge_retained_count", [(0, 1), (1, 1), (1, 2)])
def test_journal_promotion_credits_retained_records_to_their_original_requests(
    config_factory: Any,
    tmp_path: Path,
    parent_retained_count: int,
    bridge_retained_count: int,
) -> None:
    model_id = "synthetic/auditor-v1"
    config = coverage_support._config_with_promoted_surface_manifest_lineage(
        config_factory(), model_id
    )
    index, graphs, invariants, audited_suite, requests = coverage_support._promoted_surface_inputs()
    context = coverage_support._promoted_surface_context(
        requests,
        coverage_support._usage("source_audit", model_id, "retained-bridge"),
        index,
        graphs,
    )
    fixture = coverage_support._basic_promoted_recursive_surface_fixture(
        tmp_path / "retained-bridge-journal",
        requests=requests,
        records=tuple(
            coverage_support._record(request, "source_audit", index, graphs) for request in requests
        ),
        context=context,
        parent_retained_count=parent_retained_count,
        bridge_retained_count=bridge_retained_count,
    )
    try:
        coverage = coverage_support._coverage_from_promoted_recursive_surface_fixture(
            config,
            fixture,
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
        )
        artifact = fixture.structural_artifact
        assert artifact.schema_version == "1.1"
        assert coverage.overall.numerator == coverage.overall.denominator == len(requests)
        assert fixture.promotion.recovered_output.recovered_batch.surface_reviews == fixture.records
        assert len(fixture.journal.recovery_model_requests) == 4
        assert fixture.bridge_usage.request_id not in {
            usage.request_id
            for usage in fixture.journal.structurally_successful_review_usage_records
        }
        by_surface = {surface.surface_id: surface for surface in coverage.surfaces}
        for owner in (artifact.parent, artifact.bridge):
            for record in owner.projection.surface_reviews:
                refs = by_surface[record.surface_id].evidence_references
                assert len(refs) == 1
                assert refs[0].credited
                assert refs[0].request_id == owner.usage_record.request_id
                assert refs[0].artifact_sha256 == artifact.artifact_sha256
        coverage_support._validate_promoted_fixture_manifest_replay(
            config=config, coverage=coverage, fixture=fixture, detached=False
        )
        serialized_bridge = UsageRecord.model_validate_json(fixture.bridge_usage.model_dump_json())
        refused = coverage_support._coverage_from_promoted_recursive_surface_fixture(
            config,
            fixture,
            index=index,
            graphs=graphs,
            invariants=invariants,
            audited_suite_coverage=audited_suite,
            usage_records=[fixture.parent_usage, serialized_bridge, *fixture.leaf_usages],
        )
        assert not any(
            reference.credited and reference.artifact_sha256 == artifact.artifact_sha256
            for surface in refused.surfaces
            for reference in surface.evidence_references
        )
    finally:
        fixture.journal.close()


def test_assurance_accepts_exact_retained_bridge_but_refuses_relabelled_origin(
    config_factory: Any, tmp_path: Path
) -> None:
    config = assurance._maximum_config(config_factory)
    authorities = assurance._assurance_policy_selection(
        config, datetime.now(UTC).replace(microsecond=0)
    )
    runtime, fixture = assurance._runtime_with_promoted_recursive_parent_surface(
        config=config,
        runtime=assurance._complete_runtime(config),
        authorities=authorities,
        root=tmp_path / "retained-bridge-assurance",
        parent_retained_count=1,
        bridge_retained_count=1,
    )
    try:
        assert assurance._critical_surface_requirement(runtime, config).passed
        coverage = runtime.model_review_coverage
        assert coverage is not None
        bridge_ids = set(fixture.structural_artifact.bridge.retained_surface_ids)
        altered = coverage.model_copy(
            update={
                "surfaces": [
                    surface.model_copy(
                        update={
                            "evidence_references": [
                                reference.model_copy(
                                    update={"request_id": fixture.parent_usage.request_id}
                                )
                                if reference.request_id == fixture.bridge_usage.request_id
                                else reference
                                for reference in surface.evidence_references
                            ]
                        }
                    )
                    if surface.surface_id in bridge_ids
                    else surface
                    for surface in coverage.surfaces
                ]
            }
        )
        assert not assurance._critical_surface_requirement(
            replace(runtime, model_review_coverage=altered), config
        ).passed
        for mutation in (
            replace(runtime, promoted_recursive_recovery_surface_coverages=[]),
            replace(
                runtime,
                model_usage=[
                    UsageRecord.model_validate_json(usage.model_dump_json())
                    if usage is fixture.bridge_usage
                    else usage
                    for usage in runtime.model_usage
                ],
            ),
        ):
            assert not assurance._critical_surface_requirement(mutation, config).passed
    finally:
        fixture.journal.close()
