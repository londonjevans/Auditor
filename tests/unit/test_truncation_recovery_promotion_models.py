"""Durable, nonauthorizing model tests for recovered-family promotion records."""

from __future__ import annotations

import hashlib
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
    SchedulerTruncationRecoveryPromotionBinding,
    validate_truncation_recovery_entry_chain,
)
from tests.unit.test_truncation_recovery_journal import _journal_with_truncated_parent


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


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
