"""Durable, nonauthorizing model tests for recovered-family promotion records."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import CandidateReviewBatch
from mmaudit.models.truncation_recovery_journal import (
    SchedulerRecoveredCandidateOrigin,
    SchedulerRecoveredCandidateOriginKind,
    SchedulerRecoveredCandidateReviewOutput,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryPromotionBinding,
    validate_truncation_recovery_entry_chain,
)
from mmaudit.orchestration import scheduler as scheduler_module
from tests.unit.test_truncation import _candidate
from tests.unit.test_truncation_recovery_journal import (
    _journal_with_truncated_parent,
    _recursive_promotion_for_public_projection,
    _recursive_public_projection_base,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _promotion_fixture(
    root: Path,
) -> tuple[
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerRecoveredCandidateReviewOutput,
]:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(root)
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child_hashes = tuple(sorted((_digest("child-0"), _digest("child-1"))))
    closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=family,
        closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
        child_result_sha256s=child_hashes,
        nested_family_closure_sha256s=(),
        covered_unfinished_surface_ids=plan.parent.unfinished_surface_ids,
        entry_index=1,
        previous_entry_sha256=family.entry_sha256,
    )
    activation = next(
        item for item in journal.activations if item.task_id == plan.parent.parent_task_id
    )
    attempt = next(
        item for item in journal.provider_attempts if item.task_id == plan.parent.parent_task_id
    )
    output = SchedulerRecoveredCandidateReviewOutput.build(
        campaign_id=family.campaign_id,
        pass_plan_id=plan.parent.pass_plan_id,
        parent_task_id=plan.parent.parent_task_id,
        parent_logical_request_id=plan.parent.parent_logical_request_id,
        parent_activation_sha256=plan.parent.parent_activation_sha256,
        original_truncated_result_sha256=family.parent_terminal_result_sha256,
        parent_provider_attempt_sha256=attempt.attempt_evidence_sha256,
        recovery_family_id=family.family_id,
        family_root_sha256=family.entry_sha256,
        family_closure_sha256=closure.entry_sha256,
        structural_surface_artifact_sha256=_digest("structural-surface-artifact"),
        recovered_batch=CandidateReviewBatch(findings=(), surface_reviews=surfaces),
        candidate_origins=(),
        scanner_fingerprints_by_request=(),
        delivered_source_descriptor_sha256s=activation.delivered_source_descriptor_sha256s,
    )
    promotion = SchedulerTruncationRecoveryFamilyPromotion.build(
        family=family,
        closure=closure,
        direct_child_result_sha256s=child_hashes,
        recovered_output=output,
        capability_binding_sha256=_digest("opaque-capability-binding"),
        entry_index=2,
        previous_entry_sha256=closure.entry_sha256,
    )
    journal.close()
    return promotion, output


def _recursive_promotion_fixture(
    root: Path,
) -> tuple[
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryPromotionBinding,
]:
    base = _recursive_public_projection_base(root)
    promotion = _recursive_promotion_for_public_projection(base)
    return promotion, SchedulerTruncationRecoveryPromotionBinding.from_promotion(promotion)


def test_promotion_is_exact_append_only_and_still_nonauthorizing(tmp_path: Path) -> None:
    promotion, output = _promotion_fixture(tmp_path / "promotion")

    assert promotion.promotion_status == "RECOVERED"
    assert promotion.recovered_output == output
    assert not promotion.review_credit_authorized
    assert not promotion.coverage_credit_authorized
    assert not promotion.completion_authorized
    assert not output.review_credit_authorized
    assert not output.completion_authorized
    replayed = SchedulerTruncationRecoveryFamilyPromotion.model_validate_json(
        promotion.model_dump_json(),
        strict=True,
    )
    assert replayed == promotion


def test_public_promotion_binding_omits_private_recovered_review(tmp_path: Path) -> None:
    promotion, output = _promotion_fixture(tmp_path / "promotion-binding")

    binding = SchedulerTruncationRecoveryPromotionBinding.from_promotion(promotion)
    serialized = binding.model_dump_json()

    assert binding.promotion_entry_sha256 == promotion.entry_sha256
    assert binding.recovered_output_artifact_sha256 == output.output_artifact_sha256
    assert len(binding.delivered_source_inventory_sha256) == 64
    assert "recovered_batch" not in serialized
    assert "candidate_origins" not in serialized
    assert "scanner_fingerprints_by_request" not in serialized
    assert "structural_surface_artifact_sha256" not in serialized
    assert "raw_candidate" not in serialized
    assert not binding.review_credit_authorized
    assert not binding.completion_authorized


def test_recovered_output_accepts_full_scheduler_source_inventory_bound(
    tmp_path: Path,
) -> None:
    _promotion, output = _promotion_fixture(tmp_path / "promotion-many-sources")
    source_hashes = tuple(_digest(f"source-{index}") for index in range(10_001))

    rebuilt = SchedulerRecoveredCandidateReviewOutput.build(
        campaign_id=output.campaign_id,
        pass_plan_id=output.pass_plan_id,
        parent_task_id=output.parent_task_id,
        parent_logical_request_id=output.parent_logical_request_id,
        parent_activation_sha256=output.parent_activation_sha256,
        original_truncated_result_sha256=output.original_truncated_result_sha256,
        parent_provider_attempt_sha256=output.parent_provider_attempt_sha256,
        recovery_family_id=output.recovery_family_id,
        family_root_sha256=output.family_root_sha256,
        family_closure_sha256=output.family_closure_sha256,
        structural_surface_artifact_sha256=output.structural_surface_artifact_sha256,
        recovered_batch=output.recovered_batch,
        candidate_origins=output.candidate_origins,
        scanner_fingerprints_by_request=output.scanner_fingerprints_by_request,
        delivered_source_descriptor_sha256s=source_hashes,
    )

    assert len(rebuilt.delivered_source_descriptor_sha256s) == 10_001


def test_promotion_entry_chain_is_contiguous_but_does_not_self_authorize(tmp_path: Path) -> None:
    journal, plan, projection, surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "promotion-chain"
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )
    child_hashes = tuple(sorted((_digest("child-a"), _digest("child-b"))))
    closure = SchedulerTruncationRecoveryFamilyClosure.build(
        family=family,
        closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
        child_result_sha256s=child_hashes,
        nested_family_closure_sha256s=(),
        covered_unfinished_surface_ids=plan.parent.unfinished_surface_ids,
        entry_index=1,
        previous_entry_sha256=family.entry_sha256,
    )
    output = SchedulerRecoveredCandidateReviewOutput.build(
        campaign_id=family.campaign_id,
        pass_plan_id=plan.parent.pass_plan_id,
        parent_task_id=plan.parent.parent_task_id,
        parent_logical_request_id=plan.parent.parent_logical_request_id,
        parent_activation_sha256=plan.parent.parent_activation_sha256,
        original_truncated_result_sha256=family.parent_terminal_result_sha256,
        parent_provider_attempt_sha256=next(
            item for item in journal.provider_attempts if item.task_id == plan.parent.parent_task_id
        ).attempt_evidence_sha256,
        recovery_family_id=family.family_id,
        family_root_sha256=family.entry_sha256,
        family_closure_sha256=closure.entry_sha256,
        structural_surface_artifact_sha256=_digest("surface-artifact"),
        recovered_batch=CandidateReviewBatch(findings=(), surface_reviews=surfaces),
        candidate_origins=(),
        scanner_fingerprints_by_request=(),
        delivered_source_descriptor_sha256s=next(
            item for item in journal.activations if item.task_id == plan.parent.parent_task_id
        ).delivered_source_descriptor_sha256s,
    )
    promotion = SchedulerTruncationRecoveryFamilyPromotion.build(
        family=family,
        closure=closure,
        direct_child_result_sha256s=child_hashes,
        recovered_output=output,
        capability_binding_sha256=_digest("capability"),
        entry_index=2,
        previous_entry_sha256=closure.entry_sha256,
    )

    assert validate_truncation_recovery_entry_chain((family, closure, promotion)) == (
        family,
        closure,
        promotion,
    )
    journal.close()


def test_v11_coverage_closure_requires_two_direct_results_and_no_nested_family(
    tmp_path: Path,
) -> None:
    journal, plan, projection, _surfaces, surface_manifest = _journal_with_truncated_parent(
        tmp_path / "closure-shape"
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=surface_manifest,
    )

    with pytest.raises(ValidationError, match="exact direct typed coverage"):
        SchedulerTruncationRecoveryFamilyClosure.build(
            family=family,
            closure_status=SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED,
            child_result_sha256s=(_digest("only-child"),),
            nested_family_closure_sha256s=(),
            covered_unfinished_surface_ids=plan.parent.unfinished_surface_ids,
            entry_index=1,
            previous_entry_sha256=family.entry_sha256,
        )
    journal.close()


def test_candidate_origin_requires_one_exact_parent_or_child_shape() -> None:
    values = {
        "origin_kind": SchedulerRecoveredCandidateOriginKind.PARENT_FRAME,
        "accepted_candidate_id": "cand-" + "1" * 24,
        "accepted_candidate_sha256": _digest("accepted"),
        "raw_candidate_id": "raw-one",
        "raw_candidate_sha256": _digest("raw"),
        "request_id": "scheduler-request-" + "2" * 64,
        "request_role": "source_audit",
        "usage_record_sha256": _digest("usage"),
        "context_request_evidence_sha256": _digest("context"),
        "parent_projection_sha256": _digest("projection"),
        "accepted_frame_sequence": 1,
        "accepted_frame_sha256": _digest("frame"),
        "child_task_id": "scheduler-recovery-task-" + "3" * 64,
        "child_result_sha256": _digest("result"),
        "normalization_evidence_sha256": _digest("normalization"),
        "surface_artifact_sha256": _digest("surface"),
        "origin_sha256": _digest("irrelevant"),
    }

    with pytest.raises(ValidationError, match="exact one-of"):
        SchedulerRecoveredCandidateOrigin.model_validate(values)


def test_recursive_promotion_and_public_binding_name_exact_tree(tmp_path: Path) -> None:
    promotion, binding = _recursive_promotion_fixture(tmp_path / "recursive-promotion")

    assert promotion.schema_version == "1.1"
    assert binding.schema_version == "1.1"
    assert binding.nested_family_id == promotion.nested_family_id
    assert binding.nested_family_root_sha256 == promotion.nested_family_root_sha256
    assert binding.nested_recovery_plan_sha256 == promotion.nested_recovery_plan_sha256
    assert binding.nested_family_closure_id == promotion.nested_family_closure_id
    assert binding.nested_family_closure_sha256 == promotion.nested_family_closure_sha256
    assert binding.nested_child_result_sha256s == promotion.nested_child_result_sha256s
    assert binding.superseded_bridge_result_sha256 == promotion.superseded_bridge_result_sha256
    assert binding.promoted_leaf_result_sha256s == promotion.promoted_leaf_result_sha256s
    assert len(binding.direct_child_result_sha256s) == 2
    assert len(binding.nested_child_result_sha256s or ()) == 2
    assert len(binding.promoted_leaf_result_sha256s or ()) == 3
    assert (
        SchedulerTruncationRecoveryPromotionBinding.model_validate_json(
            binding.model_dump_json(), strict=True
        )
        == binding
    )


def test_recursive_binding_rejects_missing_and_duplicate_nested_fields(tmp_path: Path) -> None:
    _promotion, binding = _recursive_promotion_fixture(tmp_path / "recursive-binding-negative")

    missing = binding.model_dump(mode="json")
    missing.pop("nested_family_closure_id")
    missing["binding_sha256"] = _canonical_sha256(
        {key: value for key, value in missing.items() if key != "binding_sha256"}
    )
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        SchedulerTruncationRecoveryPromotionBinding.model_validate(missing)

    duplicate = binding.model_dump(mode="json")
    nested_hashes = duplicate["nested_child_result_sha256s"]
    assert isinstance(nested_hashes, tuple | list)
    duplicate["nested_child_result_sha256s"] = (nested_hashes[0], nested_hashes[0])
    duplicate["binding_sha256"] = _canonical_sha256(
        {key: value for key, value in duplicate.items() if key != "binding_sha256"}
    )
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        SchedulerTruncationRecoveryPromotionBinding.model_validate(duplicate)


def test_truncated_child_frame_origin_is_distinct_and_stamps_output_v11(
    tmp_path: Path,
) -> None:
    _promotion, direct_output = _promotion_fixture(tmp_path / "bridge-origin")
    empty_bridge_output = SchedulerRecoveredCandidateReviewOutput.build(
        campaign_id=direct_output.campaign_id,
        pass_plan_id=direct_output.pass_plan_id,
        parent_task_id=direct_output.parent_task_id,
        parent_logical_request_id=direct_output.parent_logical_request_id,
        parent_activation_sha256=direct_output.parent_activation_sha256,
        original_truncated_result_sha256=direct_output.original_truncated_result_sha256,
        parent_provider_attempt_sha256=direct_output.parent_provider_attempt_sha256,
        recovery_family_id=direct_output.recovery_family_id,
        family_root_sha256=direct_output.family_root_sha256,
        family_closure_sha256=direct_output.family_closure_sha256,
        structural_surface_artifact_sha256=direct_output.structural_surface_artifact_sha256,
        recovered_batch=direct_output.recovered_batch,
        candidate_origins=(),
        scanner_fingerprints_by_request=(),
        delivered_source_descriptor_sha256s=(direct_output.delivered_source_descriptor_sha256s),
        recursive_tree=True,
    )
    finding = _candidate("cand-" + "b" * 24)
    finding_sha256 = _canonical_sha256(finding.model_dump(mode="json"))
    request_id = "scheduler-recovery-request-" + "c" * 64
    origin = SchedulerRecoveredCandidateOrigin.build(
        origin_kind=SchedulerRecoveredCandidateOriginKind.TRUNCATED_CHILD_FRAME,
        accepted_candidate_id=finding.candidate_id,
        accepted_candidate_sha256=finding_sha256,
        raw_candidate_id="bridge-raw-finding",
        raw_candidate_sha256=_digest("bridge-raw-finding"),
        request_id=request_id,
        request_role="source_audit",
        usage_record_sha256=_digest("bridge-usage"),
        context_request_evidence_sha256=_digest("bridge-context"),
        truncation_projection_sha256=_digest("bridge-truncation-projection"),
        accepted_frame_sequence=2,
        accepted_frame_sha256=_digest("bridge-accepted-frame"),
        child_task_id="scheduler-recovery-task-" + "d" * 64,
        child_result_sha256=_digest("bridge-result"),
    )

    recursive_output = SchedulerRecoveredCandidateReviewOutput.build(
        campaign_id=direct_output.campaign_id,
        pass_plan_id=direct_output.pass_plan_id,
        parent_task_id=direct_output.parent_task_id,
        parent_logical_request_id=direct_output.parent_logical_request_id,
        parent_activation_sha256=direct_output.parent_activation_sha256,
        original_truncated_result_sha256=direct_output.original_truncated_result_sha256,
        parent_provider_attempt_sha256=direct_output.parent_provider_attempt_sha256,
        recovery_family_id=direct_output.recovery_family_id,
        family_root_sha256=direct_output.family_root_sha256,
        family_closure_sha256=direct_output.family_closure_sha256,
        structural_surface_artifact_sha256=direct_output.structural_surface_artifact_sha256,
        recovered_batch=CandidateReviewBatch(
            findings=(finding,),
            surface_reviews=direct_output.recovered_batch.surface_reviews,
        ),
        candidate_origins=(origin,),
        scanner_fingerprints_by_request=((request_id, ()),),
        delivered_source_descriptor_sha256s=(direct_output.delivered_source_descriptor_sha256s),
    )

    assert origin.origin_kind is SchedulerRecoveredCandidateOriginKind.TRUNCATED_CHILD_FRAME
    assert origin.normalization_evidence_sha256 is None
    assert origin.surface_artifact_sha256 is None
    assert empty_bridge_output.schema_version == "1.1"
    assert empty_bridge_output.candidate_origins == ()
    assert recursive_output.schema_version == "1.1"
    assert recursive_output.candidate_origins == (origin,)


def test_retained_v1_direct_promotion_chain_replays_exact_pre_actor_bytes(
    tmp_path: Path,
) -> None:
    fixture_root = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "scheduler"
        / "retained_v1_direct_promotion_chain"
    )
    fixture_paths = tuple(sorted(fixture_root.glob("entry-*.json")))
    assert tuple(path.name for path in fixture_paths) == (
        "entry-00000000-family-root-"
        "c35e1ec5c2144827de46e7117ba8567b7655689762b3ca83e24e71fb3a80f31a.json",
        "entry-00000001-family-closed-"
        "c29fac1f4750690778c70ba922ce1d480e80a11f957b4c489e60203e2844f2cd.json",
        "entry-00000002-family-promoted-"
        "71f7604f1cf4794bd548c92e52a3bc32a164e53916fd2380316ede33ab65fa91.json",
    )
    fixture_bytes = tuple(path.read_bytes() for path in fixture_paths)
    assert tuple(hashlib.sha256(item).hexdigest() for item in fixture_bytes) == (
        "e248577e185ed42c67e25d41ec565a2a755dbd7feb2bc2effc03ddcf0c44092d",
        "47206d08ba54bc9001e6fa10b85dc19563d5b5683dbf58956fa735f57b313397",
        "e23b31744826276d8f667354882478d35f66e4cd9e7118366df7be522677aa73",
    )
    encoded_entries = tuple(
        json.dumps(
            json.loads(item),
            sort_keys=True,
            separators=(",", ":"),
        )
        for item in fixture_bytes
    )
    assert tuple(hashlib.sha256(item.encode()).hexdigest() for item in encoded_entries) == (
        "f3f16b9501f5faf764953189db5a0f1688c2a6d57700d5f95bb5d381f56c0df4",
        "3e0d48cfa4f9bedffb1d798c2837294a0b211f03f631cb71cf71504a3622a96a",
        "8cd6abe345901b106a204f04ccd5e0fe18f9bde41b55e883af44a87eb67b8f79",
    )
    assert b"actor_model_applicability" not in b"".join(fixture_bytes)
    assert b"actor_context" not in b"".join(fixture_bytes)
    replayed = (
        SchedulerTruncationRecoveryFamilyRoot.model_validate_json(fixture_bytes[0], strict=True),
        SchedulerTruncationRecoveryFamilyClosure.model_validate_json(fixture_bytes[1], strict=True),
        SchedulerTruncationRecoveryFamilyPromotion.model_validate_json(
            fixture_bytes[2], strict=True
        ),
    )
    assert validate_truncation_recovery_entry_chain(replayed) == replayed
    retained_root = tmp_path / "retained-v1-disk-reopen"
    retained_root.mkdir(mode=0o700)
    retained_root.chmod(0o700)
    recovery_directory = retained_root / scheduler_module._TRUNCATION_RECOVERY_DIRECTORY
    recovery_directory.mkdir(mode=0o700)
    recovery_directory.chmod(0o700)
    for entry, raw_fixture in zip(replayed, fixture_bytes, strict=True):
        relative = scheduler_module._truncation_recovery_entry_path(entry)
        path = retained_root / relative
        path.write_bytes(raw_fixture)
        path.chmod(0o600)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    root_descriptor = os.open(retained_root, directory_flags)
    recovery_descriptor = os.open(recovery_directory, directory_flags)
    try:
        loaded = scheduler_module._load_truncation_recovery_entries(
            root_descriptor,
            {scheduler_module._TRUNCATION_RECOVERY_DIRECTORY: recovery_descriptor},
        )
    finally:
        os.close(recovery_descriptor)
        os.close(root_descriptor)
    assert loaded == replayed
    binding = SchedulerTruncationRecoveryPromotionBinding.from_promotion(replayed[2])
    assert binding.recovered_output_artifact_sha256 == (
        replayed[2].recovered_output.output_artifact_sha256
    )
