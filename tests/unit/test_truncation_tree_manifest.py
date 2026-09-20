"""Source-consistent complete model-review manifest checks, entirely synthetic and local."""

from typing import Any

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import AuditRunStatus, MaximumAssuranceStatus
from mmaudit.orchestration import manifest
from mmaudit.orchestration.assurance import AssuranceRuntime
from mmaudit.orchestration.scheduler_runtime import build_scheduler_analysis_input_inventory
from mmaudit.privacy import PrivacySourceClassification
from tests.truncation_tree_assurance_support import CompleteTreeAssuranceFixture
from tests.truncation_tree_manifest_support import (
    build_review_manifest_report,
    build_review_source_fixture,
)
from tests.unit import test_assurance as assurance
from tests.unit.test_truncation_tree_assurance import complete_tree as complete_tree


def _manifest_arguments(
    config: AuditConfig, fixture: CompleteTreeAssuranceFixture
) -> dict[str, Any]:
    """Exercise the real manifest consumer with a typed, explicitly incomplete report."""

    report = build_review_manifest_report(
        config,
        fixture.source,
        fixture.runtime,
        fixture.journal.manifest.cost_ledger_baseline.cap_usd_exact,
        privacy=fixture.privacy,
    )
    projection = fixture.projection
    promoted = manifest._PromotedModelReviewArtifactInventory(
        schema_version="1.2",
        promotions=(
            manifest._FullTreePromotedModelReviewArtifact(
                promotion_entry_sha256=projection.promotion_entry_sha256,
                recovered_output_artifact_sha256=projection.recovered_output_artifact_sha256,
                recursive_tree=True,
                full_tree=True,
                artifact=projection.artifact,
            ),
        ),
    )
    return dict(
        report=report,
        inventory=manifest.build_model_review_artifact_inventory(
            artifacts=fixture.runtime.model_surface_review_artifacts,
            review_contexts_by_request=fixture.coverage_arguments["review_contexts_by_request"],
        ),
        snapshot=manifest._scheduler_report_authority_snapshot(fixture.journal),
        config=config,
        promoted_inventory=promoted,
        detached=False,
        index=fixture.source.index,
        graphs=fixture.source.graphs,
        runtime_journal=fixture.journal,
    )


@pytest.fixture(scope="module")
def complete_manifest(
    complete_tree: tuple[AuditConfig, CompleteTreeAssuranceFixture],
) -> tuple[CompleteTreeAssuranceFixture, dict[str, Any]]:
    config, fixture = complete_tree
    return fixture, _manifest_arguments(config, fixture)


def test_review_source_inventory_is_derived_from_the_actual_shared_fixture_bytes() -> None:
    source = build_review_source_fixture()
    descriptors = {
        item.path: item for shard in source.scheduler_shards.shards for item in shard.sources
    }
    assert set(descriptors) == set(source.sources)
    for item in source.discovery.files:
        assert descriptors[item.relative_path].sha256 == item.sha256
        assert descriptors[item.relative_path].size == item.size > 1
    assert len(source.rich_requests) == 9
    assert source.analysis_inputs == build_scheduler_analysis_input_inventory(
        **source.analysis_arguments
    )
    for absent in ("compilations", "invariant_executions", "formal_runs", "scanner_runs"):
        assert source.analysis_arguments[absent] == []


def test_current_synthetic_manifest_report_cannot_claim_absent_engine_completion(
    config_factory: Any,
) -> None:
    config = assurance._maximum_config(config_factory)
    source = build_review_source_fixture()
    runtime = AssuranceRuntime(
        index=source.index, graphs=source.graphs, invariants=source.invariants
    )
    report = build_review_manifest_report(config, source, runtime, "250")
    assert not report.completed and report.run_status is AuditRunStatus.INCOMPLETE
    assert report.maximum_assurance is not None
    assert report.maximum_assurance.status is not MaximumAssuranceStatus.COMPLETE
    assert report.minimum_analysis_floor is not None
    assert report.minimum_analysis_floor.qualifying_compilations == 0
    assert report.minimum_analysis_floor.qualifying_real_static_scanners == []


def test_original_campaign_privacy_files_join_every_usage_and_the_report(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]],
) -> None:
    fixture, arguments = complete_manifest
    report = arguments["report"]
    custody = fixture.privacy.custody
    assert fixture.journal.path.parent.stat().st_mode & 0o777 == 0o700
    assert fixture.journal.manifest.privacy_evidence_custody == custody
    assert (
        fixture.journal.manifest.bindings.privacy_evidence_custody_sha256 == custody.custody_sha256
    )
    assert report.usage == fixture.runtime.model_usage and report.usage
    assert report.budget_usd == float(fixture.privacy.policy.requested_budget_usd) == 250
    with fixture.journal.open_privacy_evidence_custody() as original:
        assert original == custody
        manifest._validate_scheduler_privacy_artifacts(
            root=fixture.privacy.run_directory, report=report, custody=original
        )
        manifest.validate_report_privacy_consistency(
            report,
            source_tree_sha256=fixture.source.scheduler_shards.source_tree_sha256,
            expected_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        )
    assert not report.completed


@pytest.mark.parametrize("owner", ("root", "bridge0", "bridge1", "leaf", "business_logic"))
def test_report_privacy_rejects_policy_substitution_for_every_kind_of_original_owner(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]], owner: str
) -> None:
    fixture, arguments = complete_manifest
    report = arguments["report"]
    owners = {
        "root": fixture.projection.parent_usage_record,
        "bridge0": fixture.projection.bridge_usage_records[0],
        "bridge1": fixture.projection.bridge_usage_records[1],
        "leaf": fixture.projection.leaf_usage_records[0],
        "business_logic": next(usage for usage in report.usage if usage.role == "business_logic"),
    }
    request_id = owners[owner].request_id
    assert sum(usage.request_id == request_id for usage in report.usage) == 1
    altered = report.model_copy(
        update={
            "usage": [
                usage.model_copy(
                    update={
                        "routing": usage.routing | {"effective_privacy_policy_sha256": "0" * 64}
                    }
                )
                if usage.request_id == request_id
                else usage
                for usage in report.usage
            ]
        }
    )
    with pytest.raises(ValueError, match="usage privacy routing disagrees"):
        manifest.validate_report_privacy_consistency(
            altered, source_tree_sha256=fixture.source.scheduler_shards.source_tree_sha256
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("data_collection", "allow"),
        ("zdr_requested", False),
        ("privacy_profile", "SYNTHETIC_BENCHMARK"),
        ("privacy_authorization", "CONSENT_BOUND_NON_ZDR"),
        ("privacy_source_classification", "SYNTHETIC_COMMITTED"),
        ("privacy_source_sha256", "0" * 64),
        ("privacy_source_provenance_sha256", "0" * 64),
        ("privacy_consent_file_sha256", "0" * 64),
        ("privacy_consent_sha256", "0" * 64),
        ("privacy_consent_expires_at", "2026-09-12T00:00:00+00:00"),
    ),
)
def test_report_privacy_rejects_each_routing_downgrade_or_source_consent_substitution(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]], field: str, value: Any
) -> None:
    fixture, arguments = complete_manifest
    report = arguments["report"]
    first, *remaining = report.usage
    changed = first.model_copy(update={"routing": first.routing | {field: value}})
    altered = report.model_copy(update={"usage": [changed, *remaining]})
    with pytest.raises(ValueError, match="usage privacy routing disagrees"):
        manifest.validate_report_privacy_consistency(
            altered, source_tree_sha256=fixture.source.scheduler_shards.source_tree_sha256
        )


def test_complete_model_review_manifest_joins_original_source_contexts_and_authorities(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]],
) -> None:
    fixture, arguments = complete_manifest
    inventory = arguments["inventory"]
    contexts = {item.request_id: item.context for item in inventory.context_authorities}
    assert {artifact.request_id for artifact in inventory.artifacts} <= contexts.keys()
    assert set(contexts) == {usage.request_id for usage in fixture.runtime.model_usage}
    for context in contexts.values():
        assert context.repository_map.files == fixture.source.repository_map.files
        for excerpt in context.excerpts:
            assert excerpt.path in fixture.source.sources
            lines = fixture.source.sources[excerpt.path].splitlines(keepends=True)
            assert excerpt.content == "".join(lines[excerpt.start_line - 1 : excerpt.end_line])
    assert arguments["report"].model_review_coverage.critical_gate_passed
    assert not arguments["report"].completed
    assert fixture.runtime.compilations == fixture.runtime.scanners == []
    assert fixture.runtime.formal_runs == fixture.runtime.invariant_executions == []
    try:
        manifest._validate_model_review_artifact_inventory_against_scheduler(**arguments)
    except ValueError as error:
        trace = error.__traceback__
        while trace is not None:
            if trace.tb_frame.f_code.co_name == (
                "_validate_model_review_artifact_inventory_against_scheduler"
            ):
                local = trace.tb_frame.f_locals
                reference = local.get("reference")
                raise AssertionError(
                    {
                        "refusal": str(error),
                        "reference": reference.model_dump() if reference is not None else None,
                        "context": local.get("context_custody_failures"),
                        "semantic": local.get("semantic_custody_failures"),
                        "usage_creditable": local.get("usage_is_creditable"),
                    }
                ) from error
            trace = trace.tb_next
        raise


@pytest.mark.parametrize("missing", ("artifact", "promotion", "runtime_owner"))
def test_complete_model_review_manifest_refuses_missing_original_evidence(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]], missing: str
) -> None:
    _fixture, original_arguments = complete_manifest
    arguments = dict(original_arguments)
    if missing == "artifact":
        inventory = arguments["inventory"]
        arguments["inventory"] = inventory.model_copy(update={"artifacts": inventory.artifacts[1:]})
    elif missing == "promotion":
        arguments["promoted_inventory"] = None
    else:
        arguments["runtime_journal"] = None
    with pytest.raises(ValueError):
        manifest._validate_model_review_artifact_inventory_against_scheduler(**arguments)


@pytest.mark.parametrize("origin", ("root", "bridge_0", "bridge_1", "leaf", "ordinary"))
def test_complete_model_review_manifest_refuses_each_missing_credited_source_context(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]], origin: str
) -> None:
    fixture, original_arguments = complete_manifest
    projection = fixture.projection
    request_id = {
        "root": projection.parent_usage_record.request_id,
        "bridge_0": projection.bridge_usage_records[0].request_id,
        "bridge_1": projection.bridge_usage_records[1].request_id,
        "leaf": projection.leaf_usage_records[0].request_id,
        "ordinary": next(
            usage.request_id
            for usage in fixture.runtime.model_usage
            if usage.role == "business_logic"
        ),
    }[origin]
    arguments = dict(original_arguments)
    inventory = arguments["inventory"]
    arguments["inventory"] = inventory.model_copy(
        update={
            "context_authorities": tuple(
                item for item in inventory.context_authorities if item.request_id != request_id
            )
        }
    )
    assert arguments["report"].model_review_coverage.critical_gate_passed
    with pytest.raises(ValueError):
        manifest._validate_model_review_artifact_inventory_against_scheduler(**arguments)


@pytest.mark.parametrize("changed", ("index", "graphs"))
def test_complete_model_review_manifest_refuses_a_substituted_semantic_inventory(
    complete_manifest: tuple[CompleteTreeAssuranceFixture, dict[str, Any]], changed: str
) -> None:
    _fixture, original_arguments = complete_manifest
    arguments = dict(original_arguments)
    value = arguments[changed]
    arguments[changed] = value.model_copy(
        update={"entities" if changed == "index" else "nodes": []}
    )
    with pytest.raises(ValueError):
        manifest._validate_model_review_artifact_inventory_against_scheduler(**arguments)
