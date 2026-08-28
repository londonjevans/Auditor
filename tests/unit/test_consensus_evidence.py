from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from mmaudit.models.scheduler import (
    SchedulerCandidateWorkset,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    CONSENSUS_REVIEWER_SLOTS,
    ConsensusReviewerSlot,
    VerificationBatch,
)
from mmaudit.orchestration.consensus_evidence import (
    ConsensusEvidenceError,
    ConsensusReviewerEvidenceRecord,
    build_consensus_review_artifact,
)
from tests.scheduler_support import build_complete_scheduler_fixture


@dataclass(frozen=True)
class _EvidenceFixture:
    plan: SchedulerPassPlan
    workset: SchedulerCandidateWorkset
    records: tuple[ConsensusReviewerEvidenceRecord, ...]


_TASK_KEY_BY_SLOT = {
    ConsensusReviewerSlot.VERIFIER: "independent-verifier",
    ConsensusReviewerSlot.FALSIFIER_1: "candidate-falsifier-1",
    ConsensusReviewerSlot.FALSIFIER_2: "candidate-falsifier-2",
}


@pytest.fixture(scope="module")
def evidence_fixture() -> _EvidenceFixture:
    fixture = build_complete_scheduler_fixture(seed="consensus-evidence")
    plan = next(
        plan
        for plan in fixture.plans
        if plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )
    assert plan.candidate_workset is not None
    tasks_by_key = {task.task_key: task for task in plan.tasks}
    results_by_task = {
        result.task_id: result
        for result in fixture.task_results
        if result.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    }
    usage_by_request = {usage.request_id: usage for usage in fixture.usage_records}
    outputs_by_task = {output.task_id: output for output in fixture.outputs}
    records = tuple(
        ConsensusReviewerEvidenceRecord(
            slot=slot,
            task=(task := tasks_by_key[_TASK_KEY_BY_SLOT[slot]]),
            result=results_by_task[task.task_id],
            usage=usage_by_request[task.logical_request_id],
            raw_batch=VerificationBatch.model_validate(outputs_by_task[task.task_id].payload),
        )
        for slot in CONSENSUS_REVIEWER_SLOTS
    )
    return _EvidenceFixture(
        plan=plan,
        workset=plan.candidate_workset,
        records=records,
    )


def test_builder_reconstructs_deterministic_exact_three_review_artifact(
    evidence_fixture: _EvidenceFixture,
) -> None:
    artifact = build_consensus_review_artifact(
        candidate_workset=evidence_fixture.workset,
        reviewers=tuple(reversed(evidence_fixture.records)),
    )
    rebuilt = build_consensus_review_artifact(
        candidate_workset=evidence_fixture.workset,
        reviewers=evidence_fixture.records,
    )

    assert artifact == rebuilt
    assert artifact.artifact_sha256 == artifact.expected_artifact_sha256()
    assert tuple(reviewer.slot for reviewer in artifact.reviewers) == CONSENSUS_REVIEWER_SLOTS
    assert artifact.candidate_ids == evidence_fixture.workset.selected_candidate_ids
    assert all(reviewer.candidate_ids == artifact.candidate_ids for reviewer in artifact.reviewers)
    assert tuple(
        reviewer.model_completion_evidence_sha256 for reviewer in artifact.reviewers
    ) == tuple(
        record.result.model_completion_evidence_sha256 for record in evidence_fixture.records
    )


@pytest.mark.parametrize("record_count", (0, 1, 2))
def test_builder_rejects_missing_reviewer_records(
    evidence_fixture: _EvidenceFixture,
    record_count: int,
) -> None:
    with pytest.raises(ConsensusEvidenceError, match="exactly three reviewer records"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=evidence_fixture.records[:record_count],
        )


def test_builder_rejects_duplicate_reviewer_slot(
    evidence_fixture: _EvidenceFixture,
) -> None:
    records = (
        evidence_fixture.records[0],
        evidence_fixture.records[1],
        replace(
            evidence_fixture.records[2],
            slot=ConsensusReviewerSlot.FALSIFIER_1,
        ),
    )

    with pytest.raises(ConsensusEvidenceError, match="each exact reviewer slot once"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=records,
        )


def test_builder_rejects_task_assigned_to_wrong_reviewer_slot(
    evidence_fixture: _EvidenceFixture,
) -> None:
    verifier, falsifier_one, falsifier_two = evidence_fixture.records
    records = (
        verifier,
        replace(
            falsifier_one,
            task=falsifier_two.task,
            result=falsifier_two.result,
            usage=falsifier_two.usage,
            raw_batch=falsifier_two.raw_batch,
        ),
        replace(
            falsifier_two,
            task=falsifier_one.task,
            result=falsifier_one.result,
            usage=falsifier_one.usage,
            raw_batch=falsifier_one.raw_batch,
        ),
    )

    with pytest.raises(ConsensusEvidenceError, match="exact pass-six reviewer slot"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=records,
        )


def test_builder_rejects_reused_task_result_or_usage(
    evidence_fixture: _EvidenceFixture,
) -> None:
    verifier, falsifier_one, falsifier_two = evidence_fixture.records

    for changed in (
        replace(falsifier_one, result=verifier.result),
        replace(falsifier_one, usage=verifier.usage),
    ):
        with pytest.raises(ConsensusEvidenceError):
            build_consensus_review_artifact(
                candidate_workset=evidence_fixture.workset,
                reviewers=(verifier, changed, falsifier_two),
            )


def test_builder_rejects_reused_provider_generation_identity(
    evidence_fixture: _EvidenceFixture,
) -> None:
    verifier, falsifier_one, falsifier_two = evidence_fixture.records
    changed_usage = falsifier_one.usage.model_copy(
        update={"openrouter_generation_id": verifier.usage.openrouter_generation_id}
    )
    result_payload = falsifier_one.result.model_dump(
        mode="python",
        exclude={"result_sha256"},
    )
    result_payload.update(
        {
            "usage_record_sha256": scheduler_canonical_sha256(
                changed_usage.model_dump(mode="json")
            ),
        }
    )
    changed_result = SchedulerTaskResult(
        **result_payload,
        result_sha256=scheduler_canonical_sha256(result_payload),
    )

    with pytest.raises(ConsensusEvidenceError, match="provider generation identities"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=(
                verifier,
                replace(falsifier_one, result=changed_result, usage=changed_usage),
                falsifier_two,
            ),
        )


def test_builder_recomputes_usage_record_hash(
    evidence_fixture: _EvidenceFixture,
) -> None:
    verifier, falsifier_one, falsifier_two = evidence_fixture.records
    changed = replace(
        falsifier_one,
        usage=falsifier_one.usage.model_copy(update={"model_family": "synthetic/drift"}),
    )

    with pytest.raises(ConsensusEvidenceError, match="exact task completion"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=(verifier, changed, falsifier_two),
        )


def test_builder_rejects_failed_pass_six_result(
    evidence_fixture: _EvidenceFixture,
) -> None:
    verifier, falsifier_one, falsifier_two = evidence_fixture.records
    failed_result = SchedulerTaskResult.build_preflight_failure(
        plan=evidence_fixture.plan,
        task=falsifier_one.task,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256="0" * 64,
    )

    with pytest.raises(ConsensusEvidenceError, match="exact successful task"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=(
                verifier,
                replace(falsifier_one, result=failed_result),
                falsifier_two,
            ),
        )


def test_builder_rejects_normalized_batch_hash_drift(
    evidence_fixture: _EvidenceFixture,
) -> None:
    verifier, falsifier_one, falsifier_two = evidence_fixture.records
    decision = falsifier_one.raw_batch.decisions[0]
    changed_batch = VerificationBatch(
        decisions=[
            decision.model_copy(update={"rationale": "Coherently parsed but unbound drift."})
        ]
    )

    with pytest.raises(ConsensusEvidenceError, match="validated completion hash"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=(
                verifier,
                replace(falsifier_one, raw_batch=changed_batch),
                falsifier_two,
            ),
        )


@pytest.mark.parametrize("decisions", ([], None))
def test_builder_rejects_inexact_normalized_candidate_inventory(
    evidence_fixture: _EvidenceFixture,
    decisions: list[object] | None,
) -> None:
    verifier, falsifier_one, falsifier_two = evidence_fixture.records
    exact_decision = falsifier_one.raw_batch.decisions[0]
    changed_batch = VerificationBatch(
        decisions=[] if decisions == [] else [exact_decision, exact_decision]
    )

    with pytest.raises(ConsensusEvidenceError, match="exact candidate inventory"):
        build_consensus_review_artifact(
            candidate_workset=evidence_fixture.workset,
            reviewers=(
                verifier,
                replace(falsifier_one, raw_batch=changed_batch),
                falsifier_two,
            ),
        )
