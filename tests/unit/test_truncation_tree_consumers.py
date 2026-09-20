"""Provider-free full-tree public replay; synthetic ownership is not qualification."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from mmaudit.models.scheduler import SchedulerPassKind, SchedulerPassStatus
from mmaudit.orchestration.scheduler import (
    require_verified_promoted_recursive_truncation_recovery_surface_coverage,
)
from mmaudit.orchestration.truncation_tree_promotion import (
    issue_promoted_full_tree_surface_coverage,
    require_promoted_full_tree_surface_coverage,
)
from tests.unit.test_truncation_tree_promotion import promoted_tree as promoted_tree


@pytest.fixture(scope="module")
def public_tree(promoted_tree: tuple[Any, Any, Any]) -> tuple[Any, Any]:
    fixture, private, _details = promoted_tree
    return fixture, issue_promoted_full_tree_surface_coverage(private)


def test_full_tree_public_replay_retains_all_original_requests(
    public_tree: tuple[Any, Any],
) -> None:
    fixture, token = public_tree
    projection = require_verified_promoted_recursive_truncation_recovery_surface_coverage(token)
    requests = fixture.journal.recovery_model_requests
    assert len(requests) == 6
    assert projection.matches_requests(requests)
    assert projection.binding.schema_version == "1.2"
    assert len(projection.bridge_usage_records) == 2
    assert len(projection.leaf_usage_records) == 4
    assert fixture.journal.promoted_recursive_truncation_recovery_surface_coverages == (token,)
    assert (
        fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW).status
        is SchedulerPassStatus.COMPLETE
    )
    assert require_promoted_full_tree_surface_coverage(token).binding == projection.binding


@pytest.mark.parametrize("operation", (copy.copy, copy.deepcopy, pickle.dumps))
def test_full_tree_public_capability_cannot_be_transferred(
    public_tree: tuple[Any, Any], operation: Any
) -> None:
    with pytest.raises(TypeError):
        operation(public_tree[1])


def test_private_or_serialized_public_data_is_not_live_public_custody(
    promoted_tree: tuple[Any, Any, Any], public_tree: tuple[Any, Any]
) -> None:
    private = promoted_tree[1]
    projection = require_promoted_full_tree_surface_coverage(public_tree[1])
    for invalid in (
        private,
        projection,
        projection.binding,
        projection.binding.model_dump(mode="json"),
    ):
        with pytest.raises(ValueError):
            require_verified_promoted_recursive_truncation_recovery_surface_coverage(invalid)


def test_full_tree_public_requests_require_original_ordinals_and_family_coordinates(
    public_tree: tuple[Any, Any],
) -> None:
    fixture, token = public_tree
    projection = require_promoted_full_tree_surface_coverage(token)
    requests = fixture.journal.recovery_model_requests
    assert projection.matches_requests(requests)
    assert not projection.matches_requests(requests[:-1])
    shifted = tuple(
        request.model_copy(update={"global_request_ordinal": request.global_request_ordinal + 7})
        for request in requests
    )
    assert not projection.matches_requests(shifted)
    for field in (
        "family_root_sha256",
        "family_closure_sha256",
        "child_result_entry_sha256",
        "activation_entry_sha256",
        "terminal_evidence_sha256",
        "usage_record_sha256",
        "runtime_completion_evidence_sha256",
        "output_artifact_sha256",
    ):
        altered = (requests[0].model_copy(update={field: "0" * 64}), *requests[1:])
        assert not projection.matches_requests(altered), field


def test_every_full_tree_retained_surface_reaches_coverage_manifest_and_pipeline(
    config_factory: Any, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mmaudit.models.schemas import UsageRecord
    from mmaudit.orchestration import assurance, manifest, pipeline
    from mmaudit.orchestration.model_coverage import build_model_review_coverage
    from mmaudit.orchestration.truncation_tree_evidence import verify_truncation_recovery_full_tree
    from mmaudit.orchestration.truncation_tree_promotion import (
        promote_truncation_recovery_full_tree,
    )
    from tests.unit import test_model_coverage as support
    from tests.unit import test_truncation_tree_evidence as fixture_module

    config = support._config_with_promoted_surface_manifest_lineage(
        config_factory(), "synthetic/auditor-v1"
    )
    index, graphs, invariants, suite, requests = support._promoted_surface_inputs()
    context = support._promoted_surface_context(
        requests,
        support._usage("source_audit", "synthetic/auditor-v1", "full-tree-consumer"),
        index,
        graphs,
    )
    records = {
        request.surface_id: support._record(request, "source_audit", index, graphs)
        for request in requests
    }
    original_parent = fixture_module._typed_parent_truncation
    original_child_context = fixture_module.build_truncation_recovery_child_context
    original_leaf = fixture_module._bind_child_to_parent_invariant
    original_bridge = fixture_module._bind_bridge_to_parent_invariant
    original_orientation_usage = fixture_module.build_scheduler_test_real_usage
    child_contexts: dict[str, Any] = {}
    orientation_usages: list[UsageRecord] = []

    def exact_orientation_usage(*args: Any, **kwargs: Any) -> UsageRecord:
        usage = original_orientation_usage(*args, **kwargs)
        orientation_usages.append(usage)
        return usage

    def exact_record(request: Any, *, review_role: str) -> Any:
        assert review_role == "source_audit"
        return records[request.surface_id]

    def exact_parent(**kwargs: Any) -> Any:
        envelope, usage = original_parent(**kwargs)
        return envelope, support._with_context_request_evidence(
            usage, kwargs["context"], request_role=usage.role
        )

    def exact_child_context(**kwargs: Any) -> Any:
        result = original_child_context(**kwargs)
        child_contexts[kwargs["child"].child_logical_request_id] = result
        return result

    def exact_leaf(usage: Any, **kwargs: Any) -> Any:
        bound = original_leaf(usage, **kwargs)
        return support._with_context_request_evidence(
            bound, child_contexts[usage.request_id], request_role=usage.role
        )

    def exact_bridge(usage: Any, **kwargs: Any) -> Any:
        bound = original_bridge(usage, **kwargs)
        return support._with_context_request_evidence(
            bound, child_contexts[usage.request_id], request_role=usage.role
        )

    # Generate synthetic responses before their original usage-owner helper binds identity.
    with monkeypatch.context() as fixture_patch:
        fixture_patch.setattr(
            fixture_module, "build_scheduler_test_real_usage", exact_orientation_usage
        )
        fixture_patch.setattr(fixture_module, "_typed_parent_truncation", exact_parent)
        fixture_patch.setattr(
            fixture_module, "build_truncation_recovery_child_context", exact_child_context
        )
        fixture_patch.setattr(fixture_module, "_bind_child_to_parent_invariant", exact_leaf)
        fixture_patch.setattr(fixture_module, "_bind_bridge_to_parent_invariant", exact_bridge)
        fixture_patch.setattr(fixture_module, "_requests", lambda _count: requests)
        fixture_patch.setattr(fixture_module, "_record", exact_record)
        fixture_patch.setattr(fixture_module, "_context", lambda *_args, **_kwargs: context)
        fixture = fixture_module.build_live_tree(
            tmp_path / "rich-public",
            source_count=len(requests),
            truncated_paths=frozenset({"0", "1"}),
            retained_count=1,
        )
    try:
        source, _artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        private, _promotion = promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=source
        )
        token = issue_promoted_full_tree_surface_coverage(private)
        projection = require_promoted_full_tree_surface_coverage(token)
        fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
        public = fixture.journal.artifact()
        assert projection.matches_requests(public.recovery_model_requests)
        contexts = {
            usage.request_id: [item]
            for usage, item in zip(
                (fixture.parent_usage, *fixture.usages),
                (fixture.parent_context, *fixture.contexts),
                strict=True,
            )
        }
        arguments = dict(
            usage_records=[fixture.parent_usage, *fixture.usages],
            review_artifacts=[child.surface_artifact for child in projection.artifact.children],
            review_contexts_by_request=contexts,
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            minimum_critical_root_lineages=2,
            audited_suite_coverage=suite,
            source_contents_by_path={support._PATH: support._SOURCE},
            recovery_usage_coordinates=tuple(
                (
                    request.logical_request_id,
                    request.request_limit_scope,
                    request.request_limit_count_before,
                )
                for request in public.recovery_model_requests
                if request.output_artifact_sha256 is not None
            ),
            promoted_recursive_recovery_surface_coverages=(token,),
        )
        coverage = build_model_review_coverage(config, **arguments)
        assert coverage.overall.numerator == coverage.overall.denominator == len(requests), {
            surface.surface_id: [ref.reason for ref in surface.evidence_references]
            for surface in coverage.surfaces
        }
        by_surface = {surface.surface_id: surface for surface in coverage.surfaces}
        for owner in (projection.artifact.parent, *projection.artifact.bridges):
            for record in owner.projection.surface_reviews:
                refs = by_surface[record.surface_id].evidence_references
                assert len(refs) == 1 and refs[0].credited
                assert refs[0].request_id == owner.usage_record.request_id
        authorities = pipeline._require_current_promoted_recovery_leaf_authorities(
            direct_capabilities=(), recursive_capabilities=(token,)
        )
        expected_leaves = {usage.request_id for usage in projection.leaf_usage_records}
        assert {authority.request_id for authority in authorities} == expected_leaves
        assert {
            request.logical_request_id
            for request in pipeline._require_promoted_recovery_leaf_requests(
                authorities=authorities, recovery_requests=public.recovery_model_requests
            )
        } == expected_leaves
        snapshot = manifest._scheduler_report_authority_snapshot(fixture.journal)
        raw_inventory = manifest.build_model_review_artifact_inventory(
            artifacts=arguments["review_artifacts"], review_contexts_by_request=contexts
        )
        promoted_inventory = manifest._PromotedModelReviewArtifactInventory(
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
        promoted_inventory = type(promoted_inventory).model_validate_json(
            promoted_inventory.model_dump_json()
        )
        assert (
            set(manifest._promoted_model_review_leaf_usage_inventory(promoted_inventory))
            == expected_leaves
        )
        manifest._validate_model_review_artifact_inventory_against_scheduler(
            report=SimpleNamespace(model_review_coverage=coverage),
            inventory=raw_inventory,
            snapshot=snapshot,
            config=config,
            promoted_inventory=promoted_inventory,
            detached=False,
            index=index,
            graphs=graphs,
            runtime_journal=fixture.journal,
        )
        runtime = assurance.AssuranceRuntime(
            scheduler_artifact=public,
            model_surface_review_artifacts=arguments["review_artifacts"],
            model_usage=[*orientation_usages, *arguments["usage_records"]],
            promoted_recursive_recovery_surface_coverages=[token],
        )
        errors = assurance._scheduler_assurance_errors(config, runtime, None, None, None)
        # These local synthetic handles establish only the new custody joins, not
        # a qualified model route, seven-pass campaign, or maximum-assurance pass.
        assert "current audit policy-selected model authority was not supplied" in errors
        assert "runtime provider usage differs from the scheduler request inventory" not in errors
        assert not any("recursive recovery promotion" in error for error in errors), errors
        missing_custody = assurance._scheduler_assurance_errors(
            config,
            replace(runtime, promoted_recursive_recovery_surface_coverages=[]),
            None,
            None,
            None,
        )
        assert (
            "public recursive recovery promotions differ from exact live promotion custody"
            in missing_custody
        )
        for bridge_usage in projection.bridge_usage_records:
            altered = {
                **arguments,
                "usage_records": [
                    UsageRecord.model_validate_json(usage.model_dump_json())
                    if usage is bridge_usage
                    else usage
                    for usage in arguments["usage_records"]
                ],
            }
            refused = build_model_review_coverage(config, **altered)
            assert not any(
                ref.credited and ref.artifact_sha256 == projection.artifact.artifact_sha256
                for surface in refused.surfaces
                for ref in surface.evidence_references
            )
            altered_custody = assurance._scheduler_assurance_errors(
                config,
                replace(runtime, model_usage=[*orientation_usages, *altered["usage_records"]]),
                None,
                None,
                None,
            )
            assert (
                "recursive recovery promotion differs from exact live usage custody"
                in altered_custody
            )
    finally:
        fixture.journal.close()


def test_full_tree_reissuance_requires_original_live_source_without_another_append(
    promoted_tree: tuple[Any, Any, Any], public_tree: tuple[Any, Any]
) -> None:
    from mmaudit.orchestration.truncation_tree_promotion import (
        promote_truncation_recovery_full_tree,
    )

    fixture, _private, (source, _artifact, promotion) = promoted_tree
    before = tuple(fixture.journal.truncation_recovery_entries)
    private, retained = promote_truncation_recovery_full_tree(
        journal=fixture.journal, capability=source, existing_only=True
    )
    assert retained == promotion
    assert issue_promoted_full_tree_surface_coverage(private) is public_tree[1]
    assert tuple(fixture.journal.truncation_recovery_entries) == before
