"""Provisional report export must preserve original file ownership, records and charges."""

from __future__ import annotations

from functools import partial
from pathlib import Path

import pytest

import mmaudit.orchestration.provisional_findings as export_module
from mmaudit.models.truncation import CandidateReviewChannelState
from mmaudit.orchestration.provisional_findings import build_provisional_finding_inventory
from tests.channel_retention_support import VALID_FINDING_IDS, channel_projection
from tests.unit import test_truncation_recovery_journal as support
from tests.unit.test_scheduler_journal import (
    _bindings,
    _inventory,
    _journal_private_file_snapshot,
    resume_scheduler_journal,
)


@pytest.mark.parametrize(
    "state", [CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID]
)
def test_original_parent_and_child_export_retains_every_record_and_replays_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: CandidateReviewChannelState
) -> None:
    path = tmp_path / "original-provisional-owner"
    with monkeypatch.context() as patch:
        patch.setattr(support, "_projection", partial(channel_projection, state=state))
        journal, plan, projection, surfaces, manifest = support._journal_with_truncated_parent(
            path, typed_parent_attempt=True, source_count=7, parent_cost_usd_exact="0.02"
        )
    try:
        root = journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        child = plan.children[0]
        activation = support._activate_child(journal, child.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        with monkeypatch.context() as patch:
            patch.setattr(support, "_projection", partial(channel_projection, state=state))
            usage, envelope, child_projection = support._truncated_custody(
                child=child, activation=activation, surfaces=surfaces, retained_count=1
            )
        child_result = journal.record_truncation_recovery_child_truncated(
            child.child_task_id,
            failed_usage_record=usage,
            truncated_envelope_evidence=envelope,
            truncation_projection=child_projection,
        )
        artifact = journal.artifact()
        before = _journal_private_file_snapshot(path)
        inventory = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
        assert inventory is not None
        assert inventory.retained_finding_count == 4
        assert {source.source_kind for source in inventory.sources} == {
            "scheduler_parent",
            "recovery_child",
        }
        assert all(
            tuple(record.candidate.candidate_id for record in source.records) == VALID_FINDING_IDS
            for source in inventory.sources
        )
        assert all(source.findings_state is state for source in inventory.sources)
        assert {source.truncation_projection_sha256 for source in inventory.sources} == {
            projection.evidence_sha256,
            child_projection.evidence_sha256,
        }
        assert child_result.entry_sha256 in {
            source.source_entry_sha256 for source in inventory.sources
        }
        assert not inventory.review_credit_authorized
        assert not inventory.validated_finding_authorized
        assert (
            journal.recovered_candidate_review_output_for_task(plan.parent.parent_task_id) is None
        )
        assert journal.truncation_recovery_families == (root,)
        assert child_result.accounted_cost_usd_exact == "0.05"
        assert plan.resources.parent_accounted_cost_usd_exact == "0.02"
        assert _journal_private_file_snapshot(path) == before
        evidence = journal.journal_evidence
        journal.close()
        resumed = resume_scheduler_journal(
            path,
            expected_bindings=_bindings(),
            expected_shard_inventory=_inventory(),
            expected_journal_evidence=evidence,
        )
        try:
            replayed = build_provisional_finding_inventory(resumed, scheduler_artifact=artifact)
            assert replayed is not None
            assert replayed.model_dump_json() == inventory.model_dump_json()
            assert _journal_private_file_snapshot(path) == before
        finally:
            resumed.close()
        assert _journal_private_file_snapshot(path) == before
    finally:
        journal.close()


@pytest.mark.parametrize(
    "refusal", ["stale_artifact", "closed_owner", "record_limit", "byte_limit"]
)
def test_provisional_export_refuses_stale_custody_and_bounds_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    path = tmp_path / "provisional-refusal-owner"
    with monkeypatch.context() as patch:
        patch.setattr(
            support,
            "_projection",
            partial(channel_projection, state=CandidateReviewChannelState.OPEN),
        )
        journal, plan, projection, _, manifest = support._journal_with_truncated_parent(
            path, typed_parent_attempt=True, source_count=7, parent_cost_usd_exact="0.02"
        )
    try:
        artifact = journal.artifact()
        if refusal == "stale_artifact":
            journal.open_truncation_recovery_family(
                recovery_plan=plan,
                truncation_projection=projection,
                requested_surface_manifest=manifest,
            )
        elif refusal == "closed_owner":
            journal.close()
        elif refusal == "record_limit":
            monkeypatch.setattr(export_module, "MAX_PROVISIONAL_FINDINGS", 1)
        else:
            monkeypatch.setattr(export_module, "MAX_JSON_ARTIFACT_BYTES", 1)
        before = _journal_private_file_snapshot(path)
        with pytest.raises(ValueError):
            build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
        assert _journal_private_file_snapshot(path) == before
    finally:
        journal.close()
