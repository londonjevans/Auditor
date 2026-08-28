"""Deterministic, replayable enrichment of candidate evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from mmaudit.models.schemas import (
    CandidateCrossExaminationDecision,
    CandidateFinding,
    CandidateOriginKind,
    ConsensusReviewArtifact,
    ConsensusReviewerSlot,
    Evidence,
    FalsificationBatch,
    FalsificationVerdict,
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    ModelVote,
    ReproductionIntegrityStatus,
    ReproductionResult,
    ReproductionState,
    VerificationDecision,
)


def _deduplicate_evidence(evidence: list[Evidence]) -> list[Evidence]:
    by_key: dict[tuple[str, str, str | None, str | None], Evidence] = {}
    for item in evidence:
        by_key[(item.type, item.source, item.rule_id, item.fingerprint)] = item
    return list(by_key.values())


def attach_formal_counterexamples(
    candidates: list[CandidateFinding],
    formal_runs: list[FormalToolRun],
) -> list[CandidateFinding]:
    """Attach only source-overlapping formal counterexamples to candidates.

    The pure projection is shared by pipeline execution and detached manifest
    verification so a post-run coherent reseal cannot invent candidate changes.
    """

    # Imported lazily because assurance imports benchmark manifest validation,
    # whose detached replay path imports this pure projection.
    from mmaudit.orchestration.assurance import is_structurally_qualifying_real_formal_run

    result: list[CandidateFinding] = []
    for candidate in candidates:
        if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION:
            result.append(candidate)
            continue
        evidence = list(candidate.evidence)
        for run in formal_runs:
            if not is_structurally_qualifying_real_formal_run(run):
                continue
            observed_property_ids = set(run.observed_property_ids)
            for formal in run.evidence:
                if (
                    formal.tool != run.tool
                    or formal.status is not FormalToolStatus.SUCCESS
                    or formal.result_kind is not FormalResultKind.COUNTEREXAMPLE
                    or (observed_property_ids and formal.property_id not in observed_property_ids)
                    or not formal.locations
                    or not any(
                        candidate_location.path == formal_location.path
                        and candidate_location.start_line <= formal_location.end_line
                        and formal_location.start_line <= candidate_location.end_line
                        for candidate_location in candidate.locations
                        for formal_location in formal.locations
                    )
                ):
                    continue
                fingerprint = hashlib.sha256(
                    json.dumps(
                        {
                            "tool": formal.tool,
                            "property": formal.property_id,
                            "counterexample": formal.counterexample,
                            "execution_observation_sha256": run.execution_observation_sha256,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                evidence.append(
                    Evidence(
                        type="formal",
                        source=formal.tool,
                        rule_id="source_overlap_counterexample",
                        description=(
                            f"Source-overlapping formal counterexample for "
                            f"{formal.property_id}: {formal.property_description}"
                        ),
                        fingerprint=fingerprint,
                    )
                )
        result.append(candidate.model_copy(update={"evidence": _deduplicate_evidence(evidence)}))
    return result


def attach_verification_votes(
    candidates: list[CandidateFinding],
    decisions: Mapping[str, VerificationDecision],
    *,
    role: str,
    requested_model: str,
    returned_model: str | None,
    family: str,
) -> list[CandidateFinding]:
    """Attach one exact normalized reviewer vote to every matching candidate."""

    result: list[CandidateFinding] = []
    for candidate in candidates:
        decision = decisions.get(candidate.candidate_id)
        if decision is None:
            result.append(candidate)
            continue
        vote = ModelVote(
            role=role,
            requested_model=requested_model,
            returned_model=returned_model,
            family=family,
            verdict=decision.verdict.value,
            rationale=decision.rationale,
        )
        result.append(candidate.model_copy(update={"model_votes": [*candidate.model_votes, vote]}))
    return result


def attach_cross_examination_votes(
    candidates: list[CandidateFinding],
    cross_examinations: list[CandidateCrossExaminationDecision],
) -> list[CandidateFinding]:
    """Attach every independent pass-five vote in canonical reviewer order."""

    by_candidate: dict[str, list[CandidateCrossExaminationDecision]] = {}
    for decision in cross_examinations:
        by_candidate.setdefault(decision.candidate_id, []).append(decision)
    result: list[CandidateFinding] = []
    for candidate in candidates:
        decisions = sorted(
            by_candidate.get(candidate.candidate_id, []),
            key=lambda item: item.reviewer_index,
        )
        votes = [
            ModelVote(
                role=f"specialist:falsifier:{decision.reviewer_index}",
                requested_model=decision.requested_model,
                returned_model=decision.returned_model,
                family=decision.root_lineage,
                verdict=decision.verdict.value,
                rationale=decision.rationale,
            )
            for decision in decisions
        ]
        result.append(
            candidate.model_copy(update={"model_votes": [*candidate.model_votes, *votes]})
        )
    return result


def attach_consensus_review_votes(
    candidates: list[CandidateFinding],
    consensus_review: ConsensusReviewArtifact | None,
) -> list[CandidateFinding]:
    """Replay the exact ordered pass-six reviewer votes from sealed quorum evidence."""

    if consensus_review is None:
        return candidates
    roles = {
        ConsensusReviewerSlot.VERIFIER: "verifier",
        ConsensusReviewerSlot.FALSIFIER_1: "candidate_falsifier:1",
        ConsensusReviewerSlot.FALSIFIER_2: "candidate_falsifier:2",
    }
    result = candidates
    for reviewer in consensus_review.reviewers:
        result = attach_verification_votes(
            result,
            {
                decision.candidate_id: decision.as_verification_decision()
                for decision in reviewer.decisions
            },
            role=roles[reviewer.slot],
            requested_model=reviewer.requested_model,
            returned_model=reviewer.returned_model,
            family=reviewer.root_lineage,
        )
    return result


def apply_reproduction_results(
    candidates: list[CandidateFinding],
    results: list[ReproductionResult],
    falsifications: FalsificationBatch,
) -> tuple[list[CandidateFinding], frozenset[str]]:
    """Attach verified local reproduction evidence and derive deterministic rejections."""

    falsification_by_test = {
        (decision.candidate_id, decision.test_name): decision
        for decision in falsifications.decisions
    }
    evidence_by_candidate: dict[str, list[Evidence]] = {}
    deterministically_rejected: set[str] = set()
    for result in results:
        falsification = falsification_by_test.get((result.candidate_id, result.test_name))
        if (
            result.state
            in {
                ReproductionState.REPRODUCED,
                ReproductionState.REPRODUCED_AND_MINIMIZED,
            }
            and result.integrity is not None
            and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
            and falsification is not None
            and falsification.verdict is FalsificationVerdict.ACCEPTED
            and falsification.test_matches_claim
            and falsification.assumptions_validated
        ):
            evidence_by_candidate.setdefault(result.candidate_id, []).append(
                Evidence(
                    type="reproduction",
                    source="mmaudit-local-fork-reproduction",
                    rule_id=result.state.value,
                    description=(
                        f"Typed Foundry fork test {result.test_name} passed "
                        f"{result.successful_attempts}/{result.attempts} bounded attempts "
                        "and survived independent falsification"
                    ),
                    fingerprint=result.generated_test_sha256 or result.specification_sha256,
                )
            )
        if (
            result.state is ReproductionState.NOT_REPRODUCED
            and result.integrity is not None
            and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
            and falsification is not None
            and falsification.verdict is FalsificationVerdict.FALSIFIED
            and falsification.test_matches_claim
            and falsification.assumptions_validated
        ):
            deterministically_rejected.add(result.candidate_id)
    return (
        [
            candidate.model_copy(
                update={
                    "evidence": [
                        *candidate.evidence,
                        *evidence_by_candidate.get(candidate.candidate_id, []),
                    ]
                }
            )
            for candidate in candidates
        ],
        frozenset(deterministically_rejected),
    )
