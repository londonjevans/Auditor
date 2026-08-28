from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Callable, Mapping, Sequence

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    CONSENSUS_REVIEWER_SLOTS,
    CandidateConsensusDecision,
    ConsensusQuorumOutcome,
    ConsensusReviewArtifact,
    ConsensusReviewerBatch,
    ConsensusReviewerSlot,
    VerificationDecision,
    VerificationTest,
    VerificationVerdict,
)

ReviewerTransform = Callable[
    [tuple[ConsensusReviewerBatch, ...]],
    Sequence[ConsensusReviewerBatch],
]


def _set_model_field(model: object, field_name: str, value: object) -> None:
    setattr(model, field_name, value)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _decision(candidate_id: str, verdict: VerificationVerdict) -> VerificationDecision:
    return VerificationDecision(
        candidate_id=candidate_id,
        verdict=verdict,
        rationale=f"Synthetic local {verdict.value} review.",
        source_to_sink="synthetic source to sink",
        reachability="synthetic local reachability",
        authentication="synthetic caller",
        privilege_requirements="none",
        environmental_assumptions=[],
        guards_and_controls=[],
        false_positive_conditions=["synthetic guard may reject the local input"],
        safe_verification_test=VerificationTest(
            description="Inspect only the synthetic local fixture."
        ),
        confidence=0.8,
    )


def _batch(
    slot: ConsensusReviewerSlot,
    verdicts: Mapping[str, VerificationVerdict],
    *,
    identity_index: int,
    scheduler_task_id: str | None = None,
    logical_request_id: str | None = None,
    completion_sha256: str | None = None,
    root_lineage: str | None = None,
) -> ConsensusReviewerBatch:
    return ConsensusReviewerBatch.build(
        slot=slot,
        scheduler_task_id=(
            scheduler_task_id or f"scheduler-task-{_sha256(f'task:{identity_index}')}"
        ),
        logical_request_id=(
            logical_request_id or f"scheduler-request-{_sha256(f'request:{identity_index}')}"
        ),
        requested_model=f"synthetic/model-{identity_index}",
        returned_model=f"synthetic/model-{identity_index}",
        root_lineage=(root_lineage or f"sha256:{_sha256(f'lineage:{identity_index}')}"),
        model_completion_evidence_sha256=(
            completion_sha256 or _sha256(f"completion:{identity_index}")
        ),
        decisions=[
            _decision(candidate_id, verdict)
            for candidate_id, verdict in reversed(tuple(verdicts.items()))
        ],
    )


def _reviewers(
    verdicts_by_slot: Sequence[Mapping[str, VerificationVerdict]],
) -> tuple[ConsensusReviewerBatch, ...]:
    return tuple(
        _batch(slot, verdicts, identity_index=index)
        for index, (slot, verdicts) in enumerate(
            zip(CONSENSUS_REVIEWER_SLOTS, verdicts_by_slot, strict=True),
            start=1,
        )
    )


def _artifact(
    reviewers: Sequence[ConsensusReviewerBatch],
    *,
    candidate_payload_sha256s: Mapping[str, str] | None = None,
) -> ConsensusReviewArtifact:
    return ConsensusReviewArtifact.build(
        campaign_id=f"scheduler-campaign-{_sha256('campaign')}",
        manifest_sha256=_sha256("manifest"),
        pass_plan_id=f"scheduler-plan-{_sha256('pass-plan-id')}",
        pass_plan_sha256=_sha256("pass-plan"),
        candidate_workset_sha256=_sha256("workset"),
        candidate_payload_sha256s=(
            candidate_payload_sha256s
            or {
                "candidate-a": _sha256("candidate-a"),
                "candidate-b": _sha256("candidate-b"),
            }
        ),
        reviewers=reviewers,
    )


@pytest.mark.parametrize(
    "verdicts",
    tuple(itertools.product(tuple(VerificationVerdict), repeat=3)),
)
def test_candidate_consensus_derives_every_closed_three_vote_outcome(
    verdicts: tuple[VerificationVerdict, VerificationVerdict, VerificationVerdict],
) -> None:
    candidate_id = "candidate-a"
    reviewers = _reviewers(
        tuple({candidate_id: verdict} for verdict in verdicts),
    )

    decision = CandidateConsensusDecision.build(
        candidate_id=candidate_id,
        reviewers=reviewers,
    )

    support_count = sum(
        verdict in {VerificationVerdict.VERIFIED, VerificationVerdict.PLAUSIBLE}
        for verdict in verdicts
    )
    reject_count = verdicts.count(VerificationVerdict.REJECTED)
    expected = (
        ConsensusQuorumOutcome.SUPPORTED
        if support_count >= 2
        else (
            ConsensusQuorumOutcome.REJECTED
            if reject_count >= 2
            else ConsensusQuorumOutcome.INCONCLUSIVE
        )
    )
    assert decision.outcome is expected
    assert tuple(decision.review_decision_sha256s) == CONSENSUS_REVIEWER_SLOTS
    assert decision.quorum_sha256 == decision.expected_quorum_sha256()


def test_review_artifact_canonicalizes_candidates_and_binds_every_input() -> None:
    verdicts = {
        "candidate-b": VerificationVerdict.REJECTED,
        "candidate-a": VerificationVerdict.VERIFIED,
    }
    artifact = _artifact(
        _reviewers((verdicts, verdicts, verdicts)),
        candidate_payload_sha256s={
            "candidate-b": _sha256("candidate-b"),
            "candidate-a": _sha256("candidate-a"),
        },
    )

    assert artifact.candidate_ids == ("candidate-a", "candidate-b")
    assert all(reviewer.candidate_ids == artifact.candidate_ids for reviewer in artifact.reviewers)
    assert artifact.quorum_for("candidate-a").outcome is ConsensusQuorumOutcome.SUPPORTED
    assert artifact.quorum_for("candidate-b").outcome is ConsensusQuorumOutcome.REJECTED
    assert artifact.artifact_sha256 == artifact.expected_artifact_sha256()
    assert all(
        reviewer.batch_sha256 == reviewer.expected_batch_sha256() for reviewer in artifact.reviewers
    )
    sorted_json = json.dumps(artifact.model_dump(mode="json"), sort_keys=True)
    assert ConsensusReviewArtifact.model_validate_json(sorted_json) == artifact


@pytest.mark.parametrize(
    ("identity_field", "duplicate_value"),
    (
        ("scheduler_task_id", f"scheduler-task-{_sha256('task:1')}"),
        ("logical_request_id", f"scheduler-request-{_sha256('request:1')}"),
        ("model_completion_evidence_sha256", _sha256("completion:1")),
        ("root_lineage", f"sha256:{_sha256('lineage:1')}"),
    ),
)
def test_review_artifact_rejects_reused_reviewer_identity(
    identity_field: str,
    duplicate_value: str,
) -> None:
    verdicts = {
        "candidate-a": VerificationVerdict.VERIFIED,
        "candidate-b": VerificationVerdict.PLAUSIBLE,
    }
    reviewers = list(_reviewers((verdicts, verdicts, verdicts)))
    overrides: dict[str, str] = {identity_field: duplicate_value}
    reviewers[1] = _batch(
        ConsensusReviewerSlot.FALSIFIER_1,
        verdicts,
        identity_index=2,
        scheduler_task_id=overrides.get("scheduler_task_id"),
        logical_request_id=overrides.get("logical_request_id"),
        completion_sha256=overrides.get("model_completion_evidence_sha256"),
        root_lineage=overrides.get("root_lineage"),
    )

    with pytest.raises(ValidationError, match="must be pairwise unique"):
        _artifact(reviewers)


@pytest.mark.parametrize(
    "reviewers_transform",
    (
        lambda reviewers: reviewers[:2],
        lambda reviewers: (reviewers[1], reviewers[0], reviewers[2]),
        lambda reviewers: (reviewers[0], reviewers[1], reviewers[1]),
    ),
)
def test_review_artifact_requires_exact_ordered_reviewer_slots(
    reviewers_transform: ReviewerTransform,
) -> None:
    verdicts = {
        "candidate-a": VerificationVerdict.VERIFIED,
        "candidate-b": VerificationVerdict.PLAUSIBLE,
    }
    reviewers = _reviewers((verdicts, verdicts, verdicts))

    with pytest.raises((ValidationError, ValueError), match="exact ordered reviewer slots"):
        _artifact(reviewers_transform(reviewers))


def test_review_artifact_rejects_incomplete_candidate_batch() -> None:
    complete = {
        "candidate-a": VerificationVerdict.VERIFIED,
        "candidate-b": VerificationVerdict.PLAUSIBLE,
    }
    incomplete = {"candidate-a": VerificationVerdict.VERIFIED}
    reviewers = _reviewers((complete, incomplete, complete))

    with pytest.raises(ValueError, match="lacks one exact candidate decision"):
        _artifact(reviewers)


def test_reviewer_batch_rejects_missing_or_substituted_returned_model() -> None:
    batch = _batch(
        ConsensusReviewerSlot.VERIFIER,
        {"candidate-a": VerificationVerdict.VERIFIED},
        identity_index=1,
    )
    for returned_model in (None, "synthetic/substitute"):
        payload = batch.model_dump(mode="json")
        payload["returned_model"] = returned_model
        payload["batch_sha256"] = _canonical_sha256(
            {key: value for key, value in payload.items() if key != "batch_sha256"}
        )
        with pytest.raises(ValidationError, match="exact unsubstituted returned model"):
            ConsensusReviewerBatch.model_validate(payload)


@pytest.mark.parametrize("candidate_id", (" candidate-a", "candidate-a ", "candidate\n-a"))
def test_reviewer_batch_rejects_noncanonical_candidate_ids(candidate_id: str) -> None:
    with pytest.raises(ValidationError, match="candidate IDs"):
        _batch(
            ConsensusReviewerSlot.VERIFIER,
            {candidate_id: VerificationVerdict.VERIFIED},
            identity_index=1,
        )


def test_candidate_consensus_rejects_non_sha256_decision_identity() -> None:
    candidate_id = "candidate-a"
    decision = CandidateConsensusDecision.build(
        candidate_id=candidate_id,
        reviewers=_reviewers(tuple({candidate_id: VerificationVerdict.VERIFIED} for _ in range(3))),
    )
    payload = decision.model_dump(mode="json")
    payload["review_decision_sha256s"][ConsensusReviewerSlot.VERIFIER.value] = "z" * 64
    payload["quorum_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "quorum_sha256"}
    )

    with pytest.raises(ValidationError, match="decision hashes must be sha256"):
        CandidateConsensusDecision.model_validate(payload)


def test_review_artifact_rejects_coherently_resealed_forged_derived_quorum() -> None:
    verdicts = {
        "candidate-a": VerificationVerdict.VERIFIED,
        "candidate-b": VerificationVerdict.VERIFIED,
    }
    payload = _artifact(_reviewers((verdicts, verdicts, verdicts))).model_dump(mode="json")
    quorum = payload["candidate_quorums"][0]
    quorum.update(
        {
            "outcome": ConsensusQuorumOutcome.REJECTED.value,
            "verified_slots": [],
            "plausible_slots": [],
            "rejected_slots": [
                ConsensusReviewerSlot.VERIFIER.value,
                ConsensusReviewerSlot.FALSIFIER_1.value,
            ],
            "insufficient_context_slots": [ConsensusReviewerSlot.FALSIFIER_2.value],
        }
    )
    quorum["quorum_sha256"] = _canonical_sha256(
        {key: value for key, value in quorum.items() if key != "quorum_sha256"}
    )
    payload["artifact_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "artifact_sha256"}
    )

    with pytest.raises(ValidationError, match="differ from exact reviewer decisions"):
        ConsensusReviewArtifact.model_validate(payload)


def test_consensus_evidence_models_are_frozen() -> None:
    verdicts = {
        "candidate-a": VerificationVerdict.VERIFIED,
        "candidate-b": VerificationVerdict.VERIFIED,
    }
    artifact = _artifact(_reviewers((verdicts, verdicts, verdicts)))

    with pytest.raises(ValidationError, match="frozen"):
        _set_model_field(artifact, "campaign_id", f"scheduler-campaign-{_sha256('other')}")
    with pytest.raises(ValidationError, match="frozen"):
        _set_model_field(artifact.reviewers[0], "slot", ConsensusReviewerSlot.FALSIFIER_1)
