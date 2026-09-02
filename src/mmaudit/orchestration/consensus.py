"""Deterministic grouping, stable IDs, and consensus classification."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

from mmaudit.constants import SEVERITY_ORDER
from mmaudit.models.schemas import (
    CandidateConsensusDecision,
    CandidateCrossExaminationDecision,
    CandidateFinding,
    CandidateOriginKind,
    ConsensusQuorumOutcome,
    ConsensusReviewArtifact,
    Evidence,
    EvidenceStrength,
    Finding,
    FindingOriginKind,
    FindingStatus,
    JudgeDecision,
    Location,
    LocationValidation,
    ReproductionState,
    ScannerFinding,
    VerificationDecision,
    VerificationVerdict,
    execution_origin_location_validation_sha256,
)

_STOPWORDS = {
    "a",
    "an",
    "and",
    "in",
    "of",
    "the",
    "to",
    "via",
    "with",
    "without",
    "unsafe",
    "possible",
}

HOST_EXECUTION_ANALYSIS_LINK_SOURCE = "mmaudit-host-execution-link"

type _CandidateClaimKey = str


@dataclass(frozen=True)
class CandidateGroup:
    group_id: str
    candidates: tuple[CandidateFinding, ...]
    publication_claim_key: str | None = None

    @property
    def execution_candidates(self) -> tuple[CandidateFinding, ...]:
        """Return host-originated execution observations in canonical order."""

        return tuple(
            candidate
            for candidate in self.candidates
            if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
        )


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if token not in _STOPWORDS and len(token) > 1
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def candidate_similarity(left: CandidateFinding, right: CandidateFinding) -> float:
    score = 0.0
    left_cwe = {value.upper() for value in left.cwe}
    right_cwe = {value.upper() for value in right.cwe}
    if left_cwe and left_cwe & right_cwe:
        score += 0.3
    location_score = max(
        (
            0.25
            + (0.2 if abs(left_location.start_line - right_location.start_line) <= 12 else 0)
            + (0.1 if left_location.symbol and left_location.symbol == right_location.symbol else 0)
            for left_location in left.locations
            for right_location in right.locations
            if left_location.path == right_location.path
        ),
        default=0.0,
    )
    score += location_score
    score += 0.1 * _jaccard(_tokens(left.title), _tokens(right.title))
    score += 0.05 * _jaccard(
        _tokens(" ".join(left.attack_path)),
        _tokens(" ".join(right.attack_path)),
    )
    if left.source and right.source and left.source.path == right.source.path:
        score += 0.05
    if left.sink and right.sink and left.sink.path == right.sink.path:
        score += 0.05
    return min(1.0, score)


def _execution_location_compatible(
    execution_candidate: CandidateFinding,
    candidate: CandidateFinding,
) -> bool:
    """Require an exact source relationship before attaching review commentary."""

    for execution_location in execution_candidate.locations:
        for candidate_location in candidate.locations:
            if execution_location.path != candidate_location.path:
                continue
            ranges_overlap = not (
                execution_location.end_line < candidate_location.start_line
                or candidate_location.end_line < execution_location.start_line
            )
            same_symbol = bool(
                execution_location.symbol
                and candidate_location.symbol
                and execution_location.symbol == candidate_location.symbol
            )
            if ranges_overlap or same_symbol:
                return True
    return False


def _execution_semantic_compatible(
    execution_candidate: CandidateFinding,
    candidate: CandidateFinding,
) -> bool:
    """Require an exact host-authored provenance link in addition to co-location."""

    if execution_candidate is candidate:
        return True
    provenance = execution_candidate.execution_provenance
    if provenance is None:
        return False
    if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION:
        return candidate.execution_provenance == provenance
    return any(
        evidence.type == "repository"
        and evidence.source == HOST_EXECUTION_ANALYSIS_LINK_SOURCE
        and evidence.rule_id == provenance.invariant_id
        and evidence.fingerprint == provenance.provenance_sha256
        for evidence in candidate.evidence
    )


def bind_model_analysis_to_execution_origin(
    *,
    execution_candidate: CandidateFinding,
    model_candidate: CandidateFinding,
) -> CandidateFinding:
    """Attach a host-owned exact-provenance relation without changing model content."""

    provenance = execution_candidate.execution_provenance
    if (
        execution_candidate.origin_kind is not CandidateOriginKind.DETERMINISTIC_EXECUTION
        or provenance is None
    ):
        raise ValueError("execution analysis links require a typed execution-origin candidate")
    if model_candidate.origin_kind is not CandidateOriginKind.MODEL_REVIEW:
        raise ValueError("execution analysis links may annotate only model-review candidates")
    if any(
        evidence.source == HOST_EXECUTION_ANALYSIS_LINK_SOURCE
        for evidence in model_candidate.evidence
    ):
        raise ValueError("model candidate already carries a host execution analysis link")
    if not _execution_location_compatible(execution_candidate, model_candidate):
        raise ValueError("execution analysis links require an exact source relationship")
    if candidate_similarity(execution_candidate, model_candidate) < 0.55:
        raise ValueError("execution analysis links retain the candidate similarity threshold")
    linked = model_candidate.model_copy(
        update={
            "evidence": [
                *model_candidate.evidence,
                Evidence(
                    type="repository",
                    source=HOST_EXECUTION_ANALYSIS_LINK_SOURCE,
                    description=(
                        "Host validation linked this model analysis to the exact "
                        "deterministic execution provenance."
                    ),
                    rule_id=provenance.invariant_id,
                    fingerprint=provenance.provenance_sha256,
                ),
            ]
        }
    )
    return CandidateFinding.model_validate(linked.model_dump(mode="python"))


def group_candidates(candidates: list[CandidateFinding]) -> list[CandidateGroup]:
    if not candidates:
        return []
    candidates = sorted(candidates, key=lambda candidate: candidate.candidate_id)
    parent = list(range(len(candidates)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    def component_indices(root: int) -> list[int]:
        return [index for index in range(len(candidates)) if find(index) == root]

    def can_union(left: int, right: int) -> bool:
        """Require complete-link similarity and compatible execution anchors."""

        left_root, right_root = find(left), find(right)
        if left_root == right_root:
            return True
        left_indices = component_indices(left_root)
        right_indices = component_indices(right_root)
        if not all(
            candidate_similarity(candidates[left_index], candidates[right_index]) >= 0.55
            for left_index in left_indices
            for right_index in right_indices
        ):
            return False
        member_indices = [*left_indices, *right_indices]
        members = [candidates[index] for index in sorted(set(member_indices))]
        execution_anchors = [
            candidate
            for candidate in members
            if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
        ]
        return all(
            anchor is member
            or (
                _execution_location_compatible(anchor, member)
                and _execution_semantic_compatible(anchor, member)
            )
            for anchor in execution_anchors
            for member in members
        )

    for left_index, left in enumerate(candidates):
        for right_index in range(left_index + 1, len(candidates)):
            if candidate_similarity(left, candidates[right_index]) >= 0.55 and can_union(
                left_index, right_index
            ):
                union(left_index, right_index)
    grouped: dict[int, list[CandidateFinding]] = {}
    for index, candidate in enumerate(candidates):
        grouped.setdefault(find(index), []).append(candidate)
    result: list[CandidateGroup] = []
    for members in grouped.values():
        ordered = tuple(sorted(members, key=lambda item: item.candidate_id))
        identity_members = (
            tuple(
                candidate
                for candidate in ordered
                if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
            )
            or ordered
        )
        digest = hashlib.sha256(
            "\0".join(item.candidate_id for item in identity_members).encode()
        ).hexdigest()[:16]
        result.append(CandidateGroup(group_id=f"group-{digest}", candidates=ordered))
    return sorted(result, key=lambda group: group.group_id)


def publication_groups(candidates: list[CandidateFinding]) -> list[CandidateGroup]:
    """Partition fuzzy model groups into exact public claims before judgment."""

    result: list[CandidateGroup] = []
    for coarse_group in group_candidates(candidates):
        if coarse_group.execution_candidates:
            result.append(coarse_group)
            continue
        partitions: dict[str, list[CandidateFinding]] = {}
        for candidate in coarse_group.candidates:
            claim_key = _candidate_claim_key(candidate)
            partition_key = claim_key or json.dumps(
                {"candidate_id": candidate.candidate_id},
                sort_keys=True,
                separators=(",", ":"),
            )
            partitions.setdefault(partition_key, []).append(candidate)
        for claim_key, members in partitions.items():
            ordered = tuple(sorted(members, key=lambda candidate: candidate.candidate_id))
            digest = hashlib.sha256(
                f"mmaudit.publication-claim.v1\0{claim_key}".encode()
            ).hexdigest()[:16]
            result.append(
                CandidateGroup(
                    group_id=f"claim-{digest}",
                    candidates=ordered,
                    publication_claim_key=claim_key,
                )
            )
    return sorted(result, key=lambda group: group.group_id)


def stable_finding_id(
    candidate: CandidateFinding,
    *,
    publication_claim_key: str | None = None,
) -> str:
    primary = sorted(
        candidate.locations,
        key=lambda location: (location.path, location.start_line, location.end_line),
    )[0]
    vulnerability_class = sorted(value.upper() for value in candidate.cwe)
    class_value = (
        vulnerability_class[0]
        if vulnerability_class
        else " ".join(sorted(_tokens(candidate.title)))
    )
    stable = "\0".join(
        (
            class_value,
            primary.path,
            str(primary.start_line),
            primary.symbol or "",
            publication_claim_key or "",
        )
    )
    return f"MMA-{hashlib.sha256(stable.encode()).hexdigest()[:12].upper()}"


def _candidate_quorum(
    consensus_review: ConsensusReviewArtifact | None,
    candidate_id: str,
) -> CandidateConsensusDecision | None:
    if consensus_review is None or candidate_id not in consensus_review.candidate_ids:
        return None
    return consensus_review.quorum_for(candidate_id)


def _review_decisions_for_candidate(
    consensus_review: ConsensusReviewArtifact,
    candidate_id: str,
) -> tuple[VerificationDecision, ...]:
    return tuple(
        reviewer.decision_for(candidate_id).as_verification_decision()
        for reviewer in consensus_review.reviewers
    )


def _has_exact_cross_examination(
    candidate_id: str,
    cross_examinations: Iterable[CandidateCrossExaminationDecision],
) -> bool:
    decisions = tuple(
        sorted(
            (decision for decision in cross_examinations if decision.candidate_id == candidate_id),
            key=lambda decision: decision.reviewer_index,
        )
    )
    return (
        len(decisions) == 2
        and tuple(decision.reviewer_index for decision in decisions) == (1, 2)
        and len({decision.request_id for decision in decisions}) == 2
        and len({decision.root_lineage for decision in decisions}) == 2
        and len({decision.requested_model for decision in decisions}) == 2
        and all(decision.returned_model == decision.requested_model for decision in decisions)
    )


def _candidate_status(
    candidate: CandidateFinding,
    *,
    consensus_review: ConsensusReviewArtifact | None,
    validation: LocationValidation | None,
    scanner_findings: list[ScannerFinding],
    cross_examinations: Iterable[CandidateCrossExaminationDecision],
    deterministically_rejected_candidate_ids: frozenset[str],
) -> FindingStatus:
    """Reduce one candidate without borrowing evidence or controls from a peer."""

    if validation is None or not validation.valid:
        return FindingStatus.REJECTED
    if candidate.candidate_id in deterministically_rejected_candidate_ids:
        return FindingStatus.REJECTED
    quorum = _candidate_quorum(consensus_review, candidate.candidate_id)
    if quorum is None or quorum.outcome is ConsensusQuorumOutcome.INCONCLUSIVE:
        return FindingStatus.NEEDS_REVIEW
    if quorum.outcome is ConsensusQuorumOutcome.REJECTED:
        return FindingStatus.REJECTED
    if candidate.severity.value in {"high", "critical"} and not _has_exact_cross_examination(
        candidate.candidate_id,
        cross_examinations,
    ):
        return FindingStatus.NEEDS_REVIEW

    assert consensus_review is not None
    review_decisions = _review_decisions_for_candidate(
        consensus_review,
        candidate.candidate_id,
    )
    verified_support = sum(
        decision.verdict is VerificationVerdict.VERIFIED for decision in review_decisions
    )
    unguarded_support = sum(
        decision.verdict in {VerificationVerdict.VERIFIED, VerificationVerdict.PLAUSIBLE}
        and not decision.guards_and_controls
        for decision in review_decisions
    )
    complete_attack_path = (
        candidate.source is not None
        and candidate.sink is not None
        and not candidate.compensating_controls
        and unguarded_support >= 2
    )
    reproduction = any(
        evidence.type == "reproduction"
        and evidence.source == "mmaudit-local-fork-reproduction"
        and bool(evidence.fingerprint)
        for evidence in candidate.evidence
    )
    del scanner_findings  # Scanner observations lack an exact full-claim binding.

    # A mixed support quorum is deliberately only plausible. Two exact VERIFIED
    # decisions are required before model review can participate in a higher cap.
    quorum_verified = verified_support >= 2
    if quorum_verified and reproduction:
        return FindingStatus.CONFIRMED
    if quorum_verified and complete_attack_path:
        return FindingStatus.HIGH_CONFIDENCE
    return FindingStatus.NEEDS_REVIEW


def _candidate_claim_key(candidate: CandidateFinding) -> _CandidateClaimKey | None:
    """Return the complete canonical public semantics eligible for support credit."""

    cwe = tuple(sorted({value.upper() for value in candidate.cwe}))
    if not cwe or candidate.source is None or candidate.sink is None:
        return None
    payload = {
        "title": candidate.title,
        "cwe": cwe,
        "owasp": tuple(sorted({value.upper() for value in candidate.owasp})),
        "summary": candidate.summary,
        "impact": candidate.impact,
        "preconditions": candidate.preconditions,
        "locations": [
            location.model_dump(mode="json")
            for location in sorted(
                candidate.locations,
                key=lambda item: (
                    item.path,
                    item.start_line,
                    item.end_line,
                    item.symbol or "",
                    item.content_hash or "",
                ),
            )
        ],
        "source": candidate.source.model_dump(mode="json"),
        "sink": candidate.sink.model_dump(mode="json"),
        "attack_path": candidate.attack_path,
        "compensating_controls": candidate.compensating_controls,
        "false_positive_conditions": candidate.false_positive_conditions,
        "recommendation": candidate.recommendation,
        "verification_test": candidate.verification_test.model_dump(mode="json"),
        "actor_model_applicability": candidate.actor_model_applicability.value,
        "actor_context": (
            candidate.actor_context.model_dump(mode="json")
            if candidate.actor_context is not None
            else None
        ),
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _candidate_publication_rank(candidate: CandidateFinding) -> tuple[int, float, str]:
    return (
        SEVERITY_ORDER[candidate.severity.value],
        candidate.confidence,
        candidate.candidate_id,
    )


def _candidate_status_publication_rank(
    candidate: CandidateFinding,
    candidate_statuses: dict[str, FindingStatus],
) -> tuple[int, int, float, str]:
    """Rank exact-claim primaries by severity, then deterministic evidence status."""

    status = candidate_statuses.get(candidate.candidate_id)
    return (
        SEVERITY_ORDER[candidate.severity.value],
        _STATUS_RANK[status] if status is not None else -1,
        candidate.confidence,
        candidate.candidate_id,
    )


def _publication_claim_candidates(
    candidates: Iterable[CandidateFinding],
    *,
    candidate_statuses: dict[str, FindingStatus],
) -> tuple[CandidateFinding, ...]:
    """Select the highest-severity exact semantic claim without cross-claim transfer."""

    ordered = tuple(sorted(candidates, key=lambda candidate: candidate.candidate_id))
    if not ordered:
        return ()
    primary = max(
        ordered,
        key=lambda candidate: _candidate_status_publication_rank(
            candidate,
            candidate_statuses,
        ),
    )
    claim_key = _candidate_claim_key(primary)
    if claim_key is None:
        return (primary,)
    return tuple(candidate for candidate in ordered if _candidate_claim_key(candidate) == claim_key)


def _strongly_supported_model_candidates(
    *,
    candidates: Iterable[CandidateFinding],
    candidate_statuses: dict[str, FindingStatus],
) -> tuple[CandidateFinding, ...]:
    """Select one exact-claim cluster with at least two independent model families."""

    by_claim: dict[_CandidateClaimKey, list[CandidateFinding]] = {}
    for candidate in candidates:
        claim_key = _candidate_claim_key(candidate)
        if (
            candidate_statuses.get(candidate.candidate_id) is FindingStatus.HIGH_CONFIDENCE
            and candidate.model_family is not None
            and claim_key is not None
        ):
            by_claim.setdefault(claim_key, []).append(candidate)
    eligible = [
        tuple(sorted(members, key=lambda candidate: candidate.candidate_id))
        for members in by_claim.values()
        if len({candidate.model_family for candidate in members}) >= 2
    ]
    if not eligible:
        return ()
    return max(
        eligible,
        key=lambda members: max(
            _candidate_status_publication_rank(candidate, candidate_statuses)
            for candidate in members
        ),
    )


def preliminary_status(
    group: CandidateGroup,
    decisions: dict[str, VerificationDecision],
    validations: dict[str, LocationValidation],
    scanner_findings: list[ScannerFinding],
    *,
    consensus_review: ConsensusReviewArtifact | None = None,
    cross_examinations: Iterable[CandidateCrossExaminationDecision] = (),
    deterministically_rejected_candidate_ids: frozenset[str] = frozenset(),
) -> FindingStatus:
    cross_examination_records = tuple(cross_examinations)
    valid_execution = [
        candidate
        for candidate in group.execution_candidates
        if validations.get(candidate.candidate_id) and validations[candidate.candidate_id].valid
    ]
    if group.execution_candidates:
        if len(valid_execution) != len(group.execution_candidates):
            return FindingStatus.REJECTED
        # A qualifying execution candidate is already a repeated, replay-confirmed
        # invariant counterexample. Model roles may analyze its impact, but they do
        # not control whether the deterministic observation exists.
        return FindingStatus.CONFIRMED
    del decisions  # The single-verifier map is retained for API compatibility, never authority.
    candidate_statuses = {
        candidate.candidate_id: _candidate_status(
            candidate,
            consensus_review=consensus_review,
            validation=validations.get(candidate.candidate_id),
            scanner_findings=scanner_findings,
            cross_examinations=cross_examination_records,
            deterministically_rejected_candidate_ids=(deterministically_rejected_candidate_ids),
        )
        for candidate in group.candidates
    }
    retained = [
        candidate
        for candidate in group.candidates
        if candidate_statuses[candidate.candidate_id] is not FindingStatus.REJECTED
    ]
    if not retained:
        return FindingStatus.REJECTED
    publication_claim = _publication_claim_candidates(
        retained,
        candidate_statuses=candidate_statuses,
    )
    publication_primary = max(
        publication_claim,
        key=lambda candidate: _candidate_status_publication_rank(
            candidate,
            candidate_statuses,
        ),
    )
    primary_status = candidate_statuses[publication_primary.candidate_id]
    strongly_supported_candidates = _strongly_supported_model_candidates(
        candidates=publication_claim,
        candidate_statuses=candidate_statuses,
    )
    if (
        primary_status is FindingStatus.HIGH_CONFIDENCE
        and publication_primary in strongly_supported_candidates
    ):
        return FindingStatus.STRONGLY_SUPPORTED
    # The candidate that owns the published severity and claim text must also own
    # its status cap. In particular, executable evidence on a lower-severity peer
    # cannot confirm a higher-severity model-only publication.
    return primary_status


def _select_status_bearing_model_candidates(
    *,
    group: CandidateGroup,
    valid_candidates: list[CandidateFinding],
    candidate_statuses: dict[str, FindingStatus],
    cap: FindingStatus,
) -> tuple[CandidateFinding, ...]:
    accepted_valid_candidates = [
        candidate
        for candidate in valid_candidates
        if candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
        and candidate_statuses.get(candidate.candidate_id) is not FindingStatus.REJECTED
    ]
    publication_claim = _publication_claim_candidates(
        accepted_valid_candidates,
        candidate_statuses=candidate_statuses,
    )
    if cap is FindingStatus.STRONGLY_SUPPORTED:
        winning_candidates = _strongly_supported_model_candidates(
            candidates=publication_claim,
            candidate_statuses=candidate_statuses,
        )
    else:
        winning_candidates = tuple(
            candidate
            for candidate in publication_claim
            if candidate_statuses.get(candidate.candidate_id) is cap
        )
    selection_pool = (
        publication_claim
        or [
            candidate
            for candidate in valid_candidates
            if candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
        ]
        or list(group.candidates)
    )
    publication_primary = max(
        selection_pool,
        key=lambda candidate: _candidate_status_publication_rank(
            candidate,
            candidate_statuses,
        ),
    )
    return tuple(
        sorted(
            {
                candidate.candidate_id: candidate
                for candidate in (*winning_candidates, publication_primary)
            }.values(),
            key=lambda candidate: candidate.candidate_id,
        )
    )


def status_bearing_candidate_ids(
    group: CandidateGroup,
    *,
    decisions: dict[str, VerificationDecision],
    validations: dict[str, LocationValidation],
    scanner_findings: list[ScannerFinding],
    consensus_review: ConsensusReviewArtifact | None = None,
    cross_examinations: Iterable[CandidateCrossExaminationDecision] = (),
    deterministically_rejected_candidate_ids: frozenset[str] = frozenset(),
) -> frozenset[str]:
    """Return exact-claim status support plus the candidate owning published semantics."""

    valid_candidates = [
        candidate
        for candidate in group.candidates
        if (validation := validations.get(candidate.candidate_id)) is not None and validation.valid
    ]
    if group.execution_candidates:
        valid_execution = [
            candidate for candidate in group.execution_candidates if candidate in valid_candidates
        ]
        selected_execution_candidates = valid_execution or list(group.execution_candidates)
        return frozenset(candidate.candidate_id for candidate in selected_execution_candidates)

    cross_examination_records = tuple(cross_examinations)
    candidate_statuses = {
        candidate.candidate_id: _candidate_status(
            candidate,
            consensus_review=consensus_review,
            validation=validations.get(candidate.candidate_id),
            scanner_findings=scanner_findings,
            cross_examinations=cross_examination_records,
            deterministically_rejected_candidate_ids=deterministically_rejected_candidate_ids,
        )
        for candidate in group.candidates
        if candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
    }
    cap = preliminary_status(
        group,
        decisions,
        validations,
        scanner_findings,
        consensus_review=consensus_review,
        cross_examinations=cross_examination_records,
        deterministically_rejected_candidate_ids=deterministically_rejected_candidate_ids,
    )
    selected_model_candidates = _select_status_bearing_model_candidates(
        group=group,
        valid_candidates=valid_candidates,
        candidate_statuses=candidate_statuses,
        cap=cap,
    )
    return frozenset(candidate.candidate_id for candidate in selected_model_candidates)


def _unique_strings(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _unique_locations(values: Iterable[Location]) -> list[Location]:
    by_key: dict[tuple[str, int, int, str | None], Location] = {}
    for location in values:
        by_key[(location.path, location.start_line, location.end_line, location.symbol)] = location
    return sorted(
        by_key.values(),
        key=lambda location: (
            location.path,
            location.start_line,
            location.end_line,
            location.symbol or "",
            location.content_hash or "",
        ),
    )


def _unique_evidence(values: Iterable[Evidence]) -> list[Evidence]:
    by_key: dict[tuple[str, str, str | None, str | None, str], Evidence] = {}
    for evidence in values:
        by_key[
            (
                evidence.type,
                evidence.source,
                evidence.rule_id,
                evidence.fingerprint,
                evidence.description,
            )
        ] = evidence
    return list(by_key.values())


_STATUS_RANK = {
    FindingStatus.REJECTED: 0,
    FindingStatus.UNSUPPORTED: 1,
    FindingStatus.INSUFFICIENT_CONTEXT: 2,
    FindingStatus.INFORMATIONAL: 3,
    FindingStatus.NEEDS_REVIEW: 4,
    FindingStatus.PLAUSIBLE: 5,
    FindingStatus.HIGH_CONFIDENCE: 6,
    FindingStatus.STRONGLY_SUPPORTED: 7,
    FindingStatus.CONFIRMED: 8,
}


def merge_group(
    group: CandidateGroup,
    *,
    decisions: dict[str, VerificationDecision],
    validations: dict[str, LocationValidation],
    scanner_findings: list[ScannerFinding],
    judge: JudgeDecision | None,
    consensus_review: ConsensusReviewArtifact | None = None,
    cross_examinations: Iterable[CandidateCrossExaminationDecision] = (),
    deterministically_rejected_candidate_ids: frozenset[str] = frozenset(),
    apply_judge_classification: bool = True,
) -> Finding:
    """Merge evidence while preventing a judge from exceeding consensus."""

    cross_examination_records = tuple(cross_examinations)
    valid_candidates = [
        candidate
        for candidate in group.candidates
        if (validation := validations.get(candidate.candidate_id)) is not None and validation.valid
    ]
    candidate_statuses = {
        candidate.candidate_id: _candidate_status(
            candidate,
            consensus_review=consensus_review,
            validation=validations.get(candidate.candidate_id),
            scanner_findings=scanner_findings,
            cross_examinations=cross_examination_records,
            deterministically_rejected_candidate_ids=(deterministically_rejected_candidate_ids),
        )
        for candidate in group.candidates
        if candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
    }
    valid_execution_candidates = [
        candidate for candidate in group.execution_candidates if candidate in valid_candidates
    ]
    execution_provenance = tuple(
        sorted(
            {
                candidate.execution_provenance.provenance_sha256: (candidate.execution_provenance)
                for candidate in group.execution_candidates
                if candidate.execution_provenance is not None
            }.values(),
            key=lambda provenance: provenance.provenance_sha256,
        )
    )
    execution_origin_valid = bool(group.execution_candidates) and len(
        valid_execution_candidates
    ) == len(group.execution_candidates)
    cap = preliminary_status(
        group,
        decisions,
        validations,
        scanner_findings,
        consensus_review=consensus_review,
        cross_examinations=cross_examination_records,
        deterministically_rejected_candidate_ids=deterministically_rejected_candidate_ids,
    )
    status_bearing_model_candidates = list(
        _select_status_bearing_model_candidates(
            group=group,
            valid_candidates=valid_candidates,
            candidate_statuses=candidate_statuses,
            cap=cap,
        )
    )
    primary_pool = (
        valid_execution_candidates
        or list(group.execution_candidates)
        or status_bearing_model_candidates
        or valid_candidates
        or list(group.candidates)
    )
    primary = max(
        primary_pool,
        key=lambda candidate: _candidate_status_publication_rank(
            candidate,
            candidate_statuses,
        ),
    )
    status = cap
    if (
        apply_judge_classification
        and not valid_execution_candidates
        and judge is not None
        and _STATUS_RANK[judge.status] < _STATUS_RANK[status]
    ):
        # A fourth model may calibrate within the retained partition, but it cannot
        # unilaterally erase a group retained by the exact three-review quorum.
        status = (
            FindingStatus.NEEDS_REVIEW
            if _STATUS_RANK[judge.status] < _STATUS_RANK[FindingStatus.NEEDS_REVIEW]
            else judge.status
        )
    severity = (
        max(
            (primary.severity, judge.severity),
            key=lambda value: SEVERITY_ORDER[value.value],
        )
        if judge is not None and apply_judge_classification
        else primary.severity
    )
    confidence = (
        max(candidate.confidence for candidate in valid_execution_candidates)
        if valid_execution_candidates
        else min(
            max(candidate.confidence for candidate in primary_pool),
            judge.confidence if judge is not None and apply_judge_classification else 1.0,
        )
    )
    # Execution-origin groups retain linked candidates in contributor IDs and review
    # dissent, while execution anchors alone own the published claim and evidence.
    # Model-origin groups likewise publish only candidates establishing the winning cap.
    evidence_candidates = (
        valid_execution_candidates or list(group.execution_candidates)
        if group.execution_candidates
        else [primary]
    )
    validation_scope = (
        list(group.execution_candidates) if group.execution_candidates else evidence_candidates
    )
    validation_errors = [
        error
        for candidate in validation_scope
        for error in validations.get(
            candidate.candidate_id,
            LocationValidation(valid=False, errors=["not validated"]),
        ).errors
    ]
    valid_hashes = [
        validation.content_hash
        for candidate in validation_scope
        if (validation := validations.get(candidate.candidate_id)) is not None
        and validation.valid
        and validation.content_hash
    ]
    aggregate_hash = (
        execution_origin_location_validation_sha256(execution_provenance)
        if execution_origin_valid
        else (
            hashlib.sha256("".join(sorted(valid_hashes)).encode()).hexdigest()
            if valid_hashes
            else None
        )
    )
    if group.execution_candidates and not execution_origin_valid:
        confidence = 0.0
    elif validation_errors and not valid_candidates:
        confidence = min(confidence, 0.59)
    review_rationales = (
        [
            (
                f"{reviewer.slot.value}:{candidate.candidate_id}:"
                f"{reviewer.decision_for(candidate.candidate_id).rationale}"
            )
            for candidate in group.candidates
            for reviewer in consensus_review.reviewers
            if candidate.candidate_id in consensus_review.candidate_ids
        ]
        if consensus_review is not None
        else [
            decision.rationale
            for candidate in group.candidates
            if (decision := decisions.get(candidate.candidate_id)) is not None
        ]
    )
    disagreement = "; ".join(
        [*review_rationales, *([f"judge:{judge.rationale}"] if judge is not None else [])]
    )
    # The group judge may calibrate impact, but cannot replace a winning claim's
    # classification with taxonomy unsupported by its status-bearing candidates.
    cwe = _unique_strings(value for candidate in evidence_candidates for value in candidate.cwe)
    owasp = _unique_strings(value for candidate in evidence_candidates for value in candidate.owasp)
    location_candidates = (
        (
            valid_execution_candidates
            if status is not FindingStatus.REJECTED and valid_execution_candidates
            else list(group.execution_candidates)
        )
        if group.execution_candidates
        else (
            evidence_candidates
            if status is not FindingStatus.REJECTED and evidence_candidates
            else list(group.candidates)
        )
    )
    evidence = _unique_evidence(
        [
            *(
                evidence
                for candidate in evidence_candidates
                for evidence in candidate.evidence
                if candidate.origin_kind is not CandidateOriginKind.MODEL_REVIEW
                or evidence.type != "scanner"
            ),
        ]
    )
    reproduction_state = _reproduction_state(evidence)
    evidence_strength = _evidence_strength(
        evidence=evidence,
        independent_families={
            candidate.model_family
            for candidate in evidence_candidates
            if candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
            and candidate.model_family is not None
        },
        has_complete_attack_path=any(
            candidate.source is not None and candidate.sink is not None
            for candidate in evidence_candidates
        ),
        has_execution_counterexample=execution_origin_valid,
    )
    return Finding(
        id=stable_finding_id(
            primary,
            publication_claim_key=group.publication_claim_key,
        ),
        group_id=group.group_id,
        origin_kind=(
            FindingOriginKind.DETERMINISTIC_EXECUTION
            if group.execution_candidates
            else FindingOriginKind.MODEL_REVIEW
        ),
        execution_provenance=execution_provenance,
        title=primary.title,
        status=status,
        severity=severity,
        confidence=confidence,
        cwe=cwe,
        owasp=owasp,
        summary=primary.summary,
        impact=primary.impact,
        preconditions=_unique_strings(
            value for candidate in evidence_candidates for value in candidate.preconditions
        ),
        locations=_unique_locations(
            location for candidate in location_candidates for location in candidate.locations
        ),
        source=primary.source,
        sink=primary.sink,
        attack_path=primary.attack_path,
        evidence=evidence,
        compensating_controls=_unique_strings(
            value for candidate in evidence_candidates for value in candidate.compensating_controls
        ),
        false_positive_conditions=_unique_strings(
            value
            for candidate in evidence_candidates
            for value in candidate.false_positive_conditions
        ),
        recommendation=primary.recommendation,
        verification_test=primary.verification_test,
        model_votes=[vote for candidate in evidence_candidates for vote in candidate.model_votes],
        location_validation=LocationValidation(
            valid=(
                execution_origin_valid
                if group.execution_candidates
                else bool(evidence_candidates)
                and all(
                    (validation := validations.get(candidate.candidate_id)) is not None
                    and validation.valid
                    for candidate in evidence_candidates
                )
            ),
            content_hash=aggregate_hash,
            errors=validation_errors,
            # The validation substance is deterministic and already bound to
            # exact source hashes. A wall-clock observation would make an exact
            # scheduler replay serialize different finding evidence.
            validated_at=None,
        ),
        disagreement=disagreement,
        contributing_candidate_ids=[candidate.candidate_id for candidate in group.candidates],
        evidence_strength=evidence_strength,
        reproduction_state=reproduction_state,
        actor_model_applicability=primary.actor_model_applicability,
        actor_context=primary.actor_context,
    )


def _reproduction_state(evidence: list[Evidence]) -> ReproductionState:
    for item in evidence:
        if item.type != "reproduction" or item.source != "mmaudit-local-fork-reproduction":
            continue
        if item.rule_id == ReproductionState.REPRODUCED_AND_MINIMIZED.value:
            return ReproductionState.REPRODUCED_AND_MINIMIZED
        if item.rule_id == ReproductionState.REPRODUCED.value:
            return ReproductionState.REPRODUCED
    return ReproductionState.NOT_ATTEMPTED


def _evidence_strength(
    *,
    evidence: list[Evidence],
    independent_families: set[str],
    has_complete_attack_path: bool,
    has_execution_counterexample: bool = False,
) -> EvidenceStrength:
    reproduction = _reproduction_state(evidence)
    if reproduction is ReproductionState.REPRODUCED_AND_MINIMIZED:
        return EvidenceStrength.MINIMIZED_LOCAL_FORK_REPRODUCTION
    if reproduction is ReproductionState.REPRODUCED:
        return EvidenceStrength.LOCAL_FORK_REPRODUCTION
    if has_execution_counterexample:
        return EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE
    if any(item.type == "scanner" for item in evidence):
        return EvidenceStrength.DETERMINISTIC_ANALYZER
    if has_complete_attack_path:
        return EvidenceStrength.VALIDATED_ATTACK_PATH
    if len(independent_families) >= 2:
        return EvidenceStrength.INDEPENDENT_MODEL_SUPPORT
    if any(item.type == "model" for item in evidence):
        return EvidenceStrength.MODEL_INFERENCE
    return EvidenceStrength.NONE


def enforce_critical_evidence_cap(
    finding: Finding,
    *,
    require_formal_or_reproduction: bool,
) -> Finding:
    """Prevent a critical finding from being confirmed without executable proof.

    Severity remains an impact assessment. This only caps the confidence/status
    dimension, so a potentially critical issue stays prominent without being
    misrepresented as executed or formally demonstrated.
    """

    if (
        not require_formal_or_reproduction
        or finding.severity.value != "critical"
        or finding.status is not FindingStatus.CONFIRMED
        or finding.evidence_strength
        in {
            EvidenceStrength.LOCAL_FORK_REPRODUCTION,
            EvidenceStrength.MINIMIZED_LOCAL_FORK_REPRODUCTION,
            EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE,
        }
    ):
        return finding
    reason = (
        "Critical confirmation was capped at strongly supported because no "
        "accepted local reproduction or typed deterministic execution counterexample was "
        "available."
    )
    return finding.model_copy(
        update={
            "status": FindingStatus.STRONGLY_SUPPORTED,
            "disagreement": (
                f"{finding.disagreement}; {reason}" if finding.disagreement else reason
            ),
        }
    )
