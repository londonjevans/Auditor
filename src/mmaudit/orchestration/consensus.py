"""Deterministic grouping, stable IDs, and consensus classification."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from mmaudit.constants import SEVERITY_ORDER
from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateOriginKind,
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


@dataclass(frozen=True)
class CandidateGroup:
    group_id: str
    candidates: tuple[CandidateFinding, ...]

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
    for left_location in left.locations:
        for right_location in right.locations:
            if left_location.path == right_location.path:
                score += 0.25
                if abs(left_location.start_line - right_location.start_line) <= 12:
                    score += 0.2
                if left_location.symbol and left_location.symbol == right_location.symbol:
                    score += 0.1
                break
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


def group_candidates(candidates: list[CandidateFinding]) -> list[CandidateGroup]:
    if not candidates:
        return []
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
        """Prevent a review-only bridge from absorbing an unrelated execution anchor."""

        member_indices = [
            *component_indices(find(left)),
            *component_indices(find(right)),
        ]
        members = [candidates[index] for index in sorted(set(member_indices))]
        execution_anchors = [
            candidate
            for candidate in members
            if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
        ]
        return all(
            anchor is member or _execution_location_compatible(anchor, member)
            for anchor in execution_anchors
            for member in members
        )

    for left_index, left in enumerate(candidates):
        for right_index in range(left_index + 1, len(candidates)):
            if (
                candidate_similarity(left, candidates[right_index]) >= 0.55
                and can_union(left_index, right_index)
            ):
                union(left_index, right_index)
    grouped: dict[int, list[CandidateFinding]] = {}
    for index, candidate in enumerate(candidates):
        grouped.setdefault(find(index), []).append(candidate)
    result: list[CandidateGroup] = []
    for members in grouped.values():
        ordered = tuple(sorted(members, key=lambda item: item.candidate_id))
        identity_members = tuple(
            candidate
            for candidate in ordered
            if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
        ) or ordered
        digest = hashlib.sha256(
            "\0".join(item.candidate_id for item in identity_members).encode()
        ).hexdigest()[:16]
        result.append(CandidateGroup(group_id=f"group-{digest}", candidates=ordered))
    return sorted(result, key=lambda group: group.group_id)


def stable_finding_id(candidate: CandidateFinding) -> str:
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
        )
    )
    return f"MMA-{hashlib.sha256(stable.encode()).hexdigest()[:12].upper()}"


def _scanner_matches(candidate: CandidateFinding, scanners: Iterable[ScannerFinding]) -> bool:
    candidate_cwe = {value.upper() for value in candidate.cwe}
    for scanner in scanners:
        if any(
            evidence.type == "scanner"
            and evidence.fingerprint
            and evidence.fingerprint == scanner.fingerprint
            for evidence in candidate.evidence
        ):
            return True
        scanner_cwe = {value.upper() for value in scanner.cwe}
        for candidate_location in candidate.locations:
            for scanner_location in scanner.locations:
                if (
                    candidate_location.path == scanner_location.path
                    and abs(candidate_location.start_line - scanner_location.start_line) <= 12
                    and (not candidate_cwe or not scanner_cwe or bool(candidate_cwe & scanner_cwe))
                ):
                    return True
    return False


def preliminary_status(
    group: CandidateGroup,
    decisions: dict[str, VerificationDecision],
    validations: dict[str, LocationValidation],
    scanner_findings: list[ScannerFinding],
) -> FindingStatus:
    valid_execution = [
        candidate
        for candidate in group.execution_candidates
        if validations.get(candidate.candidate_id)
        and validations[candidate.candidate_id].valid
    ]
    if valid_execution:
        # A qualifying execution candidate is already a repeated, replay-confirmed
        # invariant counterexample. Model roles may analyze its impact, but they do
        # not control whether the deterministic observation exists.
        return FindingStatus.CONFIRMED
    accepted = [
        candidate
        for candidate in group.candidates
        if decisions.get(candidate.candidate_id)
        and decisions[candidate.candidate_id].verdict
        in {VerificationVerdict.VERIFIED, VerificationVerdict.PLAUSIBLE}
    ]
    if not accepted:
        return FindingStatus.REJECTED
    valid = [
        candidate
        for candidate in accepted
        if validations.get(candidate.candidate_id) and validations[candidate.candidate_id].valid
    ]
    if not valid:
        return FindingStatus.REJECTED
    verifier_accepts = any(
        decisions[candidate.candidate_id].verdict is VerificationVerdict.VERIFIED
        for candidate in valid
    )
    scanner_support = any(_scanner_matches(candidate, scanner_findings) for candidate in valid)
    independent_families = {
        candidate.model_family
        for candidate in valid
        if candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
        and candidate.model_family is not None
    }
    reproduction = any(
        evidence.type == "reproduction"
        and evidence.source == "mmaudit-local-fork-reproduction"
        and bool(evidence.fingerprint)
        for candidate in valid
        for evidence in candidate.evidence
    )
    formal_counterexample = any(
        evidence.type == "formal"
        and evidence.rule_id == "counterexample"
        and bool(evidence.fingerprint)
        for candidate in valid
        for evidence in candidate.evidence
    )
    complete_attack_path = any(
        candidate.source is not None
        and candidate.sink is not None
        and not candidate.compensating_controls
        and not decisions[candidate.candidate_id].guards_and_controls
        for candidate in valid
    )
    if verifier_accepts and reproduction:
        return FindingStatus.CONFIRMED
    if verifier_accepts and formal_counterexample and complete_attack_path:
        return FindingStatus.CONFIRMED
    if verifier_accepts and scanner_support and complete_attack_path:
        return FindingStatus.CONFIRMED
    if verifier_accepts and len(independent_families) >= 2 and complete_attack_path:
        return FindingStatus.STRONGLY_SUPPORTED
    if verifier_accepts:
        strongest = max(valid, key=lambda candidate: candidate.confidence)
        decision = decisions[strongest.candidate_id]
        if (
            strongest.source is not None
            and strongest.sink is not None
            and not strongest.compensating_controls
            and not decision.guards_and_controls
        ):
            return FindingStatus.HIGH_CONFIDENCE
    return FindingStatus.NEEDS_REVIEW


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
    by_key: dict[tuple[str, str, str | None, str], Evidence] = {}
    for evidence in values:
        by_key[(evidence.type, evidence.source, evidence.rule_id, evidence.description)] = evidence
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
) -> Finding:
    """Merge evidence while preventing a judge from exceeding consensus."""

    valid_candidates = [
        candidate
        for candidate in group.candidates
        if (validation := validations.get(candidate.candidate_id)) is not None and validation.valid
    ]
    accepted_valid_candidates = [
        candidate
        for candidate in valid_candidates
        if (decision := decisions.get(candidate.candidate_id)) is not None
        and decision.verdict in {VerificationVerdict.VERIFIED, VerificationVerdict.PLAUSIBLE}
    ]
    valid_execution_candidates = [
        candidate
        for candidate in group.execution_candidates
        if candidate in valid_candidates
    ]
    primary_pool = (
        valid_execution_candidates
        or list(group.execution_candidates)
        or accepted_valid_candidates
        or valid_candidates
        or list(group.candidates)
    )
    primary = max(
        primary_pool,
        key=lambda candidate: (
            candidate.confidence,
            SEVERITY_ORDER[candidate.severity.value],
            candidate.candidate_id,
        ),
    )
    cap = preliminary_status(group, decisions, validations, scanner_findings)
    status = cap
    if (
        not valid_execution_candidates
        and judge is not None
        and _STATUS_RANK[judge.status] < _STATUS_RANK[status]
    ):
        status = judge.status
    severity = judge.severity if judge is not None else primary.severity
    confidence = (
        max(candidate.confidence for candidate in valid_execution_candidates)
        if valid_execution_candidates
        else min(
            max(candidate.confidence for candidate in group.candidates),
            judge.confidence if judge is not None else 1.0,
        )
    )
    validation_scope = (
        list(group.execution_candidates)
        if group.execution_candidates
        else list(group.candidates)
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
        hashlib.sha256("".join(sorted(valid_hashes)).encode()).hexdigest() if valid_hashes else None
    )
    if validation_errors and not valid_candidates:
        confidence = min(confidence, 0.59)
    disagreement = (
        judge.rationale
        if judge
        else "; ".join(
            decision.rationale
            for candidate in group.candidates
            if (decision := decisions.get(candidate.candidate_id)) is not None
        )
    )
    cwe = (
        judge.cwe
        if judge and judge.cwe
        else _unique_strings(value for candidate in group.candidates for value in candidate.cwe)
    )
    owasp = (
        judge.owasp
        if judge and judge.owasp
        else _unique_strings(value for candidate in group.candidates for value in candidate.owasp)
    )
    location_candidates = (
        (
            valid_execution_candidates
            if status is not FindingStatus.REJECTED and valid_execution_candidates
            else list(group.execution_candidates)
        )
        if group.execution_candidates
        else (
            valid_candidates
            if status is not FindingStatus.REJECTED and valid_candidates
            else list(group.candidates)
        )
    )
    matched_scanners = [
        scanner
        for scanner in scanner_findings
        if any(_scanner_matches(candidate, [scanner]) for candidate in valid_candidates)
    ]
    evidence = _unique_evidence(
        [
            *(evidence for candidate in group.candidates for evidence in candidate.evidence),
            *(
                Evidence(
                    type="scanner",
                    source=scanner.scanner,
                    description=scanner.message,
                    rule_id=scanner.rule_id,
                    fingerprint=scanner.fingerprint,
                )
                for scanner in matched_scanners
            ),
        ]
    )
    reproduction_state = _reproduction_state(evidence)
    evidence_strength = _evidence_strength(
        evidence=evidence,
        independent_families={
            candidate.model_family
            for candidate in valid_candidates
            if candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
            and candidate.model_family is not None
        },
        has_complete_attack_path=any(
            candidate.source is not None and candidate.sink is not None
            for candidate in valid_candidates
        ),
        has_execution_counterexample=bool(valid_execution_candidates),
    )
    execution_provenance = tuple(
        sorted(
            {
                candidate.execution_provenance.provenance_sha256: (
                    candidate.execution_provenance
                )
                for candidate in group.execution_candidates
                if candidate.execution_provenance is not None
            }.values(),
            key=lambda provenance: provenance.provenance_sha256,
        )
    )
    return Finding(
        id=stable_finding_id(primary),
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
            value for candidate in group.candidates for value in candidate.preconditions
        ),
        locations=_unique_locations(
            location for candidate in location_candidates for location in candidate.locations
        ),
        source=primary.source,
        sink=primary.sink,
        attack_path=primary.attack_path,
        evidence=evidence,
        compensating_controls=_unique_strings(
            value for candidate in group.candidates for value in candidate.compensating_controls
        ),
        false_positive_conditions=_unique_strings(
            value for candidate in group.candidates for value in candidate.false_positive_conditions
        ),
        recommendation=primary.recommendation,
        verification_test=primary.verification_test,
        model_votes=[vote for candidate in group.candidates for vote in candidate.model_votes],
        location_validation=LocationValidation(
            valid=bool(valid_candidates),
            content_hash=aggregate_hash,
            errors=validation_errors,
            validated_at=datetime.now(UTC),
        ),
        disagreement=disagreement,
        contributing_candidate_ids=[candidate.candidate_id for candidate in group.candidates],
        evidence_strength=evidence_strength,
        reproduction_state=reproduction_state,
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
    if any(item.type == "formal" and item.rule_id == "counterexample" for item in evidence):
        return EvidenceStrength.FORMAL_COUNTEREXAMPLE
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
            EvidenceStrength.FORMAL_COUNTEREXAMPLE,
            EvidenceStrength.LOCAL_FORK_REPRODUCTION,
            EvidenceStrength.MINIMIZED_LOCAL_FORK_REPRODUCTION,
            EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE,
        }
    ):
        return finding
    reason = (
        "Critical confirmation was capped at strongly supported because no "
        "accepted local reproduction or matching formal counterexample was available."
    )
    return finding.model_copy(
        update={
            "status": FindingStatus.STRONGLY_SUPPORTED,
            "disagreement": (
                f"{finding.disagreement}; {reason}" if finding.disagreement else reason
            ),
        }
    )
