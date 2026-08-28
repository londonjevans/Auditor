from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from itertools import permutations

from mmaudit.models.schemas import (
    CONSENSUS_REVIEWER_SLOTS,
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationVerdict,
    CandidateFinding,
    ConsensusReviewArtifact,
    ConsensusReviewerBatch,
    Evidence,
    EvidenceStrength,
    FalsificationBatch,
    FalsificationDecision,
    FalsificationVerdict,
    FindingStatus,
    JudgeDecision,
    Location,
    LocationValidation,
    ReproductionIntegrityAssessment,
    ReproductionIntegrityCheck,
    ReproductionIntegrityCheckKind,
    ReproductionIntegrityStatus,
    ReproductionMinimizationEvidence,
    ReproductionResult,
    ReproductionSettlementEvidence,
    ReproductionSettlementStatus,
    ReproductionState,
    ScannerFinding,
    Severity,
    VerificationDecision,
    VerificationTest,
    VerificationVerdict,
)
from mmaudit.orchestration.candidate_enrichment import (
    apply_reproduction_results,
    attach_consensus_review_votes,
    attach_cross_examination_votes,
)
from mmaudit.orchestration.consensus import (
    candidate_similarity,
    enforce_critical_evidence_cap,
    group_candidates,
    merge_group,
    preliminary_status,
    publication_groups,
    stable_finding_id,
    status_bearing_candidate_ids,
)

VoteTriple = tuple[VerificationVerdict, VerificationVerdict, VerificationVerdict]
CandidateFactory = Callable[..., CandidateFinding]


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


def _verified_reproduction_integrity() -> ReproductionIntegrityAssessment:
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "status": ReproductionIntegrityStatus.VERIFIED,
        "repository_sha256": "a" * 64,
        "targets": [],
        "reachability": [],
        "settlement": ReproductionSettlementEvidence(
            status=ReproductionSettlementStatus.ASSERTIONS_SATISFIED,
            assertions_sha256="b" * 64,
            assertion_count=1,
            verified_attempts=1,
        ).model_dump(mode="json"),
        "minimization": ReproductionMinimizationEvidence(
            original_step_ids=["SyntheticStep"],
            retained_step_ids=["SyntheticStep"],
            strategy="single_step_trivial",
            proven_minimal=True,
        ).model_dump(mode="json"),
        "checks": [
            ReproductionIntegrityCheck(
                check=check,
                passed=True,
                detail="synthetic local integrity evidence",
                evidence_sha256=_canonical_sha256({"check": check.value}),
            ).model_dump(mode="json")
            for check in ReproductionIntegrityCheckKind
        ],
    }
    payload["integrity_sha256"] = _canonical_sha256(payload)
    return ReproductionIntegrityAssessment.model_validate(payload)


def _decision(
    candidate_id: str,
    verdict: VerificationVerdict,
    *,
    rationale: str | None = None,
) -> VerificationDecision:
    return VerificationDecision(
        candidate_id=candidate_id,
        verdict=verdict,
        rationale=rationale or "Source and sink are reachable in the synthetic fixture.",
        source_to_sink="query to execute",
        reachability="direct",
        authentication="authenticated",
        privilege_requirements="ordinary user",
        environmental_assumptions=[],
        guards_and_controls=[],
        false_positive_conditions=["driver neutralizes interpolation"],
        safe_verification_test=VerificationTest(
            description="Use a fake local connection and synthetic text"
        ),
        confidence=0.9,
    )


def _review_evidence(
    candidates: Sequence[CandidateFinding],
    verdicts_by_candidate: Mapping[str, VoteTriple],
) -> tuple[ConsensusReviewArtifact, tuple[CandidateCrossExaminationDecision, ...]]:
    """Build the exact three-review artifact and its two falsifier projections."""

    ordered_candidates = tuple(sorted(candidates, key=lambda candidate: candidate.candidate_id))
    candidate_ids = tuple(candidate.candidate_id for candidate in ordered_candidates)
    if candidate_ids != tuple(sorted(verdicts_by_candidate)):
        raise ValueError("test review evidence requires one vote triple per exact candidate")
    payload_hashes = {
        candidate.candidate_id: _canonical_sha256(candidate.model_dump(mode="json"))
        for candidate in ordered_candidates
    }
    reviewers: list[ConsensusReviewerBatch] = []
    for slot_index, slot in enumerate(CONSENSUS_REVIEWER_SLOTS):
        reviewers.append(
            ConsensusReviewerBatch.build(
                slot=slot,
                scheduler_task_id=f"scheduler-task-{_sha256(f'task:{slot.value}')}",
                logical_request_id=(f"scheduler-request-{_sha256(f'request:{slot.value}')}"),
                requested_model=f"synthetic/{slot.value}",
                returned_model=f"synthetic/{slot.value}",
                root_lineage=f"sha256:{_sha256(f'lineage:{slot.value}')}",
                model_completion_evidence_sha256=_sha256(f"completion:{slot.value}"),
                decisions=[
                    _decision(
                        candidate_id,
                        verdicts_by_candidate[candidate_id][slot_index],
                        rationale=(
                            f"{slot.value} retained "
                            f"{verdicts_by_candidate[candidate_id][slot_index].value} dissent "
                            f"for {candidate_id}."
                        ),
                    )
                    for candidate_id in candidate_ids
                ],
            )
        )
    artifact = ConsensusReviewArtifact.build(
        campaign_id=f"scheduler-campaign-{_sha256('campaign')}",
        manifest_sha256=_sha256("manifest"),
        pass_plan_id=f"scheduler-plan-{_sha256('pass-plan-id')}",
        pass_plan_sha256=_sha256("pass-plan"),
        candidate_workset_sha256=_canonical_sha256(payload_hashes),
        candidate_payload_sha256s=payload_hashes,
        reviewers=reviewers,
    )
    cross_examinations = tuple(
        CandidateCrossExaminationDecision(
            candidate_id=candidate_id,
            request_id=reviewer.logical_request_id,
            reviewer_index=reviewer_index,
            requested_model=reviewer.requested_model,
            returned_model=reviewer.returned_model,
            root_lineage=reviewer.root_lineage,
            verdict=(
                CandidateCrossExaminationVerdict.DISPUTED
                if reviewer.decision_for(candidate_id).verdict is VerificationVerdict.REJECTED
                else (
                    CandidateCrossExaminationVerdict.INCONCLUSIVE
                    if reviewer.decision_for(candidate_id).verdict
                    is VerificationVerdict.INSUFFICIENT_CONTEXT
                    else CandidateCrossExaminationVerdict.SUPPORTED
                )
            ),
            rationale=reviewer.decision_for(candidate_id).rationale,
        )
        for candidate_id in candidate_ids
        for reviewer_index, reviewer in enumerate(artifact.reviewers[1:], start=1)
    )
    return artifact, cross_examinations


def _uniform_review_evidence(
    candidates: Sequence[CandidateFinding],
    verdicts: VoteTriple = (
        VerificationVerdict.VERIFIED,
        VerificationVerdict.VERIFIED,
        VerificationVerdict.VERIFIED,
    ),
) -> tuple[ConsensusReviewArtifact, tuple[CandidateCrossExaminationDecision, ...]]:
    return _review_evidence(
        candidates,
        {candidate.candidate_id: verdicts for candidate in candidates},
    )


def _scanner() -> ScannerFinding:
    return ScannerFinding(
        scanner="semgrep",
        rule_id="sql-injection",
        title="SQL injection",
        severity=Severity.HIGH,
        message="formatted query",
        locations=[Location(path="app.py", start_line=13, end_line=13)],
        cwe=["CWE-89"],
        fingerprint="scanner-fingerprint",
    )


def _with_scanner_evidence(candidate: CandidateFinding) -> CandidateFinding:
    return candidate.model_copy(
        update={
            "evidence": [
                *candidate.evidence,
                Evidence(
                    type="scanner",
                    source="semgrep",
                    description="The qualifying scanner cited this exact candidate.",
                    rule_id="sql-injection",
                    fingerprint="scanner-fingerprint",
                ),
            ]
        }
    )


def _with_reproduction_evidence(candidate: CandidateFinding) -> CandidateFinding:
    return candidate.model_copy(
        update={
            "evidence": [
                *candidate.evidence,
                Evidence(
                    type="reproduction",
                    source="mmaudit-local-fork-reproduction",
                    description="A synthetic local regression reproduced this exact claim.",
                    rule_id=ReproductionState.REPRODUCED.value,
                    fingerprint="exact-local-reproduction",
                ),
            ]
        }
    )


def test_similarity_and_duplicate_grouping(candidate_factory: CandidateFactory) -> None:
    left = candidate_factory(candidate_id="left")
    right = candidate_factory(
        candidate_id="right",
        role="business_logic",
        family="charlie/cirrus-secure",
    )
    assert candidate_similarity(left, right) >= 0.55
    groups = group_candidates([right, left])
    assert len(groups) == 1
    assert [item.candidate_id for item in groups[0].candidates] == ["left", "right"]


def test_unrelated_candidates_do_not_merge(candidate_factory: CandidateFactory) -> None:
    left = candidate_factory()
    right = candidate_factory(
        candidate_id="path",
        path="config.py",
        start_line=3,
        end_line=3,
        title="Debug setting enabled",
        cwe=["CWE-489"],
    )
    assert candidate_similarity(left, right) < 0.55
    assert len(group_candidates([left, right])) == 2


def test_location_similarity_is_symmetric_bounded_and_id_rename_invariant(
    candidate_factory: CandidateFactory,
) -> None:
    multi = candidate_factory(candidate_id="a-multi", path="config.py").model_copy(
        update={
            "title": "Synthetic query interpolation",
            "cwe": ["CWE-89"],
            "locations": [
                Location(path="config.py", start_line=line, end_line=line) for line in (1, 20, 40)
            ],
            "source": None,
            "sink": None,
            "attack_path": ["Supply query text."],
        }
    )
    single = candidate_factory(candidate_id="z-single", path="config.py").model_copy(
        update={
            "title": "Archive traversal",
            "cwe": ["CWE-22"],
            "locations": [Location(path="config.py", start_line=100, end_line=100)],
            "source": None,
            "sink": None,
            "attack_path": ["Extract an archive member."],
        }
    )

    assert candidate_similarity(multi, single) == candidate_similarity(single, multi) == 0.25
    assert len(group_candidates([multi, single])) == 2
    renamed = [
        multi.model_copy(update={"candidate_id": "z-multi"}),
        single.model_copy(update={"candidate_id": "a-single"}),
    ]
    assert len(group_candidates(renamed)) == 2


def test_rejected_transitive_bridge_cannot_stitch_unrelated_winning_claims(
    candidate_factory: CandidateFactory,
) -> None:
    left = candidate_factory(
        candidate_id="a-left-sql",
        path="config.py",
        start_line=1,
        end_line=4,
        cwe=["CWE-89"],
    )
    bridge = candidate_factory(
        candidate_id="b-rejected-bridge",
        role="business_logic",
        family="charlie/cirrus-secure",
        path="config.py",
        start_line=11,
        end_line=14,
        cwe=["CWE-22", "CWE-89"],
    )
    right = candidate_factory(
        candidate_id="c-right-path",
        role="configuration",
        family="delta/dawn-secure",
        path="config.py",
        start_line=21,
        end_line=24,
        cwe=["CWE-22"],
    )

    assert candidate_similarity(left, bridge) >= 0.55
    assert candidate_similarity(bridge, right) >= 0.55
    assert candidate_similarity(left, right) < 0.55
    expected_partition = {
        frozenset({left.candidate_id, bridge.candidate_id}),
        frozenset({right.candidate_id}),
    }
    for ordering in permutations([left, bridge, right]):
        assert {
            frozenset(candidate.candidate_id for candidate in group.candidates)
            for group in group_candidates(list(ordering))
        } == expected_partition

    findings = []
    for group in group_candidates([left, bridge, right]):
        grouped_candidates = list(group.candidates)
        review, cross_examinations = _review_evidence(
            grouped_candidates,
            {
                candidate.candidate_id: (
                    (
                        VerificationVerdict.REJECTED,
                        VerificationVerdict.REJECTED,
                        VerificationVerdict.VERIFIED,
                    )
                    if candidate.candidate_id == bridge.candidate_id
                    else (
                        VerificationVerdict.VERIFIED,
                        VerificationVerdict.VERIFIED,
                        VerificationVerdict.VERIFIED,
                    )
                )
                for candidate in grouped_candidates
            },
        )
        findings.append(
            merge_group(
                group,
                decisions={},
                validations={
                    candidate.candidate_id: LocationValidation(valid=True)
                    for candidate in grouped_candidates
                },
                scanner_findings=[],
                judge=None,
                consensus_review=review,
                cross_examinations=cross_examinations,
            )
        )

    assert {finding.status for finding in findings} == {FindingStatus.HIGH_CONFIDENCE}
    assert {tuple(finding.cwe) for finding in findings} == {("CWE-89",), ("CWE-22",)}


def test_stable_finding_ids_are_repeatable(candidate_factory: CandidateFactory) -> None:
    candidate = candidate_factory()
    assert stable_finding_id(candidate) == stable_finding_id(candidate)
    changed = candidate.model_copy(update={"title": "Different wording"})
    assert stable_finding_id(candidate) == stable_finding_id(changed)


def test_matching_scanner_remains_nonconfirming_without_exact_claim_binding(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = _with_scanner_evidence(candidate_factory())
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])

    status = preliminary_status(
        group,
        {},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [_scanner()],
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.HIGH_CONFIDENCE


def test_scanner_corroboration_cannot_transfer_to_a_divergent_claim(
    candidate_factory: CandidateFactory,
) -> None:
    scanner_backed = _with_scanner_evidence(candidate_factory(candidate_id="scanner-backed"))
    divergent = candidate_factory(
        candidate_id="divergent",
        role="business_logic",
        family="beta/two",
        title="Different same-location database claim",
    ).model_copy(
        update={
            "summary": "A materially different database behavior is alleged.",
            "impact": "A different impact belongs only to this claim.",
            "preconditions": ["A different precondition applies."],
            "attack_path": ["Reach a different same-location path."],
        }
    )
    groups = publication_groups([scanner_backed, divergent])
    assert len(groups) == 2
    review, cross_examinations = _uniform_review_evidence([scanner_backed, divergent])
    validations = {
        scanner_backed.candidate_id: LocationValidation(valid=True),
        divergent.candidate_id: LocationValidation(valid=True),
    }
    findings = {
        finding.title: finding
        for finding in (
            merge_group(
                group,
                decisions={},
                validations=validations,
                scanner_findings=[_scanner()],
                judge=None,
                consensus_review=review,
                cross_examinations=cross_examinations,
            )
            for group in groups
        )
    }

    scanner_backed_finding = findings[scanner_backed.title]
    assert scanner_backed_finding.status is FindingStatus.HIGH_CONFIDENCE
    assert all(item.type != "scanner" for item in scanner_backed_finding.evidence)
    divergent_finding = findings[divergent.title]
    assert divergent_finding.status is FindingStatus.HIGH_CONFIDENCE
    assert all(item.type != "scanner" for item in divergent_finding.evidence)


def test_same_cwe_at_unrelated_location_is_not_scanner_corroboration(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    unrelated = _scanner().model_copy(
        update={"locations": [Location(path="config.py", start_line=3, end_line=3)]}
    )
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])

    status = preliminary_status(
        group,
        {},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [unrelated],
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.HIGH_CONFIDENCE


def test_scanner_corroboration_requires_nonempty_cwe_on_both_sides(
    candidate_factory: CandidateFactory,
) -> None:
    candidate_without_cwe = candidate_factory(candidate_id="candidate-without-cwe").model_copy(
        update={"cwe": []}
    )
    candidate_for_scanner_without_cwe = candidate_factory(candidate_id="scanner-without-cwe")
    scanner_without_cwe = _scanner().model_copy(update={"cwe": []})

    for candidate, scanner in (
        (candidate_without_cwe, _scanner()),
        (candidate_for_scanner_without_cwe, scanner_without_cwe),
    ):
        group = group_candidates([candidate])[0]
        review, cross_examinations = _uniform_review_evidence([candidate])

        status = preliminary_status(
            group,
            {},
            {candidate.candidate_id: LocationValidation(valid=True)},
            [scanner],
            consensus_review=review,
            cross_examinations=cross_examinations,
        )

        assert status is FindingStatus.HIGH_CONFIDENCE


def test_copied_scanner_fingerprint_at_unrelated_location_is_not_corroboration(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    candidate = candidate.model_copy(
        update={
            "evidence": [
                *candidate.evidence,
                Evidence(
                    type="scanner",
                    source="model-supplied",
                    description="Copied scanner identifier without a location match.",
                    fingerprint="scanner-fingerprint",
                ),
            ]
        }
    )
    unrelated = _scanner().model_copy(
        update={"locations": [Location(path="other.py", start_line=100, end_line=100)]}
    )
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])

    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[unrelated],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.HIGH_CONFIDENCE
    assert all(evidence.type != "scanner" for evidence in finding.evidence)


def test_two_independent_families_are_strong_support_not_confirmation(
    candidate_factory: CandidateFactory,
) -> None:
    left = candidate_factory(candidate_id="left")
    right = candidate_factory(
        candidate_id="right",
        role="business_logic",
        family="charlie/cirrus-secure",
    )
    group = group_candidates([left, right])[0]
    review, cross_examinations = _uniform_review_evidence([left, right])
    validations = {item.candidate_id: LocationValidation(valid=True) for item in (left, right)}

    status = preliminary_status(
        group,
        {},
        validations,
        [],
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.STRONGLY_SUPPORTED


def test_same_taxonomy_and_coordinates_do_not_bridge_divergent_claim_semantics(
    candidate_factory: CandidateFactory,
) -> None:
    left = candidate_factory(candidate_id="left")
    right = candidate_factory(
        candidate_id="right",
        role="business_logic",
        family="charlie/cirrus-secure",
    ).model_copy(
        update={
            "impact": "This candidate describes a materially different consequence.",
            "attack_path": ["Reach an unrelated mechanism at the same source range."],
        }
    )
    group = group_candidates([left, right])[0]
    review, cross_examinations = _uniform_review_evidence([left, right])
    validations = {item.candidate_id: LocationValidation(valid=True) for item in (left, right)}

    assert (
        preliminary_status(
            group,
            {},
            validations,
            [],
            consensus_review=review,
            cross_examinations=cross_examinations,
        )
        is FindingStatus.HIGH_CONFIDENCE
    )
    assert (
        len(
            status_bearing_candidate_ids(
                group,
                decisions={},
                validations=validations,
                scanner_findings=[],
                consensus_review=review,
                cross_examinations=cross_examinations,
            )
        )
        == 1
    )


def test_exact_support_cluster_publishes_highest_severity_candidate(
    candidate_factory: CandidateFactory,
) -> None:
    critical = candidate_factory(candidate_id="critical").model_copy(
        update={"severity": Severity.CRITICAL, "confidence": 0.9}
    )
    low = candidate_factory(
        candidate_id="low",
        role="business_logic",
        family="charlie/cirrus-secure",
    ).model_copy(update={"severity": Severity.LOW, "confidence": 0.99})
    # Independent reviewers may grade the same exact claim differently; the
    # host must retain the higher severity when choosing the public primary.
    group = group_candidates([critical, low])[0]
    review, cross_examinations = _uniform_review_evidence([critical, low])
    validations = {
        candidate.candidate_id: LocationValidation(valid=True) for candidate in (critical, low)
    }

    finding = merge_group(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.STRONGLY_SUPPORTED
    assert finding.severity is Severity.CRITICAL


def test_rejected_verifier_cannot_suppress_two_verified_falsifiers(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence(
        [candidate],
        (
            VerificationVerdict.REJECTED,
            VerificationVerdict.VERIFIED,
            VerificationVerdict.VERIFIED,
        ),
    )

    status = preliminary_status(
        group,
        {},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [],
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.HIGH_CONFIDENCE


def test_two_rejections_reject_one_verified_vote(candidate_factory: CandidateFactory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence(
        [candidate],
        (
            VerificationVerdict.VERIFIED,
            VerificationVerdict.REJECTED,
            VerificationVerdict.REJECTED,
        ),
    )

    status = preliminary_status(
        group,
        {},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [_scanner()],
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.REJECTED


def test_mixed_verified_plausible_rejected_quorum_needs_review(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence(
        [candidate],
        (
            VerificationVerdict.VERIFIED,
            VerificationVerdict.PLAUSIBLE,
            VerificationVerdict.REJECTED,
        ),
    )

    status = preliminary_status(
        group,
        {},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [_scanner()],
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.NEEDS_REVIEW


def test_missing_quorum_needs_review_even_with_legacy_verifier_and_cross_examination(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    _, cross_examinations = _uniform_review_evidence([candidate])

    status = preliminary_status(
        group,
        {candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.VERIFIED)},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [_scanner()],
        consensus_review=None,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.NEEDS_REVIEW


def test_missing_exact_cross_examination_needs_review(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, _ = _uniform_review_evidence([candidate])

    status = preliminary_status(
        group,
        {},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [_scanner()],
        consensus_review=review,
    )

    assert status is FindingStatus.NEEDS_REVIEW


def test_model_only_quorum_never_confirms(candidate_factory: CandidateFactory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])

    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.HIGH_CONFIDENCE


def test_runtime_and_detached_replay_share_exact_reviewer_vote_enrichment(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    review, cross_examinations = _uniform_review_evidence([candidate])

    enriched = attach_cross_examination_votes([candidate], cross_examinations)
    enriched = attach_consensus_review_votes(enriched, review)

    assert [vote.role for vote in enriched[0].model_votes] == [
        "specialist:falsifier:1",
        "specialist:falsifier:2",
        "verifier",
        "candidate_falsifier:1",
        "candidate_falsifier:2",
    ]
    assert [vote.family for vote in enriched[0].model_votes] == [
        cross_examinations[0].root_lineage,
        cross_examinations[1].root_lineage,
        *(reviewer.root_lineage for reviewer in review.reviewers),
    ]


def test_runtime_and_detached_replay_share_verified_reproduction_enrichment(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    result = ReproductionResult(
        candidate_id=candidate.candidate_id,
        test_name="synthetic-local-regression",
        state=ReproductionState.REPRODUCED,
        specification_sha256="c" * 64,
        generated_test_sha256="d" * 64,
        attempts=1,
        successful_attempts=1,
        integrity=_verified_reproduction_integrity(),
    )
    falsification = FalsificationDecision(
        candidate_id=candidate.candidate_id,
        test_name=result.test_name,
        verdict=FalsificationVerdict.ACCEPTED,
        test_matches_claim=True,
        assumptions_validated=True,
        rationale="The bounded synthetic regression matches the exact claim.",
    )

    enriched, rejected = apply_reproduction_results(
        [candidate],
        [result],
        FalsificationBatch(decisions=[falsification]),
    )

    assert rejected == frozenset()
    reproduction = [item for item in enriched[0].evidence if item.type == "reproduction"]
    assert len(reproduction) == 1
    assert reproduction[0].fingerprint == result.generated_test_sha256
    assert reproduction[0].rule_id == ReproductionState.REPRODUCED.value


def test_candidate_evidence_cannot_cross_stitch_between_group_members(
    candidate_factory: CandidateFactory,
) -> None:
    scanner_backed = candidate_factory(candidate_id="scanner-backed")
    model_only = candidate_factory(
        candidate_id="model-only",
        role="business_logic",
        family="charlie/cirrus-secure",
        start_line=20,
        end_line=23,
    )
    group = group_candidates([scanner_backed, model_only])[0]
    review, cross_examinations = _review_evidence(
        [scanner_backed, model_only],
        {
            scanner_backed.candidate_id: (
                VerificationVerdict.VERIFIED,
                VerificationVerdict.PLAUSIBLE,
                VerificationVerdict.REJECTED,
            ),
            model_only.candidate_id: (
                VerificationVerdict.VERIFIED,
                VerificationVerdict.VERIFIED,
                VerificationVerdict.VERIFIED,
            ),
        },
    )

    finding = merge_group(
        group,
        decisions={},
        validations={
            scanner_backed.candidate_id: LocationValidation(valid=True),
            model_only.candidate_id: LocationValidation(valid=True),
        },
        scanner_findings=[_scanner()],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.HIGH_CONFIDENCE


def test_reproduction_cannot_confirm_a_higher_severity_model_only_primary(
    candidate_factory: CandidateFactory,
) -> None:
    reproduced_low = candidate_factory(
        candidate_id="a-reproduced",
        family="alpha/one",
    ).model_copy(
        update={
            "severity": Severity.LOW,
            "evidence": [
                *candidate_factory().evidence,
                Evidence(
                    type="reproduction",
                    source="mmaudit-local-fork-reproduction",
                    description="Synthetic local regression reproduced only this candidate.",
                    rule_id=ReproductionState.REPRODUCED.value,
                    fingerprint="reproduced-low-only",
                ),
            ],
        }
    )
    model_only_high = candidate_factory(
        candidate_id="z-primary",
        role="business_logic",
        family="beta/two",
    )
    assert len(publication_groups([reproduced_low, model_only_high])) == 1
    group = publication_groups([reproduced_low, model_only_high])[0]
    review, cross_examinations = _uniform_review_evidence([reproduced_low, model_only_high])
    validations = {
        reproduced_low.candidate_id: LocationValidation(valid=True),
        model_only_high.candidate_id: LocationValidation(valid=True),
    }

    finding = merge_group(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.HIGH_CONFIDENCE
    assert {item.type for item in finding.evidence} == {"model"}
    assert finding.reproduction_state is ReproductionState.NOT_ATTEMPTED
    assert status_bearing_candidate_ids(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        consensus_review=review,
        cross_examinations=cross_examinations,
    ) == frozenset({model_only_high.candidate_id})


def test_same_severity_reproduction_outranks_higher_confidence_model_only_peer(
    candidate_factory: CandidateFactory,
) -> None:
    reproduced = candidate_factory(
        candidate_id="a-reproduced",
        family="alpha/one",
    )
    reproduced = reproduced.model_copy(
        update={
            "confidence": 0.7,
            "evidence": [
                *reproduced.evidence,
                Evidence(
                    type="reproduction",
                    source="mmaudit-local-fork-reproduction",
                    description="Synthetic local regression reproduced this exact claim.",
                    rule_id=ReproductionState.REPRODUCED.value,
                    fingerprint="same-severity-exact-reproduction",
                ),
            ],
        }
    )
    model_only = candidate_factory(
        candidate_id="z-model-only",
        role="business_logic",
        family="beta/two",
    ).model_copy(update={"confidence": 0.99})
    assert len(publication_groups([reproduced, model_only])) == 1
    group = publication_groups([reproduced, model_only])[0]
    review, cross_examinations = _uniform_review_evidence([reproduced, model_only])
    validations = {
        reproduced.candidate_id: LocationValidation(valid=True),
        model_only.candidate_id: LocationValidation(valid=True),
    }

    finding = merge_group(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.CONFIRMED
    assert {item.type for item in finding.evidence} == {"model", "reproduction"}
    assert finding.reproduction_state is ReproductionState.REPRODUCED
    assert status_bearing_candidate_ids(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        consensus_review=review,
        cross_examinations=cross_examinations,
    ) == frozenset({reproduced.candidate_id})


def test_colocated_distinct_claims_cannot_mint_composite_independent_support(
    candidate_factory: CandidateFactory,
) -> None:
    sql = candidate_factory(candidate_id="a-sql").model_copy(
        update={
            "preconditions": ["SQL-only precondition"],
            "evidence": [
                Evidence(
                    type="model",
                    source="sql-only-evidence",
                    description="Evidence for only the SQL claim.",
                )
            ],
        }
    )
    traversal = candidate_factory(
        candidate_id="z-traversal",
        role="configuration",
        family="charlie/cirrus-secure",
        title="Archive path traversal",
        cwe=["CWE-22"],
    ).model_copy(
        update={
            "owasp": ["A01:2021"],
            "summary": "This summary belongs only to the traversal claim.",
            "preconditions": ["Traversal-only precondition"],
            "attack_path": ["Submit an archive member.", "Reach local extraction."],
            "evidence": [
                Evidence(
                    type="model",
                    source="traversal-only-evidence",
                    description="Evidence for only the traversal claim.",
                )
            ],
        }
    )
    assert candidate_similarity(sql, traversal) >= 0.55
    group = group_candidates([sql, traversal])[0]
    review, cross_examinations = _uniform_review_evidence([sql, traversal])
    validations = {
        sql.candidate_id: LocationValidation(valid=True),
        traversal.candidate_id: LocationValidation(valid=True),
    }

    finding = merge_group(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.HIGH_CONFIDENCE
    assert finding.title == traversal.title
    assert finding.summary == traversal.summary
    assert finding.cwe == traversal.cwe
    assert finding.owasp == traversal.owasp
    assert finding.preconditions == traversal.preconditions
    assert {evidence.source for evidence in finding.evidence} == {"traversal-only-evidence"}
    assert finding.contributing_candidate_ids == [sql.candidate_id, traversal.candidate_id]
    assert status_bearing_candidate_ids(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        consensus_review=review,
        cross_examinations=cross_examinations,
    ) == frozenset({traversal.candidate_id})


def test_divergent_critical_claim_cannot_be_hidden_by_lower_severity_status(
    candidate_factory: CandidateFactory,
) -> None:
    low = candidate_factory(candidate_id="low", family="alpha/one").model_copy(
        update={"severity": Severity.LOW, "confidence": 0.99}
    )
    critical = candidate_factory(
        candidate_id="critical",
        role="business_logic",
        family="beta/two",
        title="Critical alternate colocated claim",
    ).model_copy(
        update={
            "severity": Severity.CRITICAL,
            "summary": "This summary belongs only to the critical claim.",
            "impact": "Critical-only impact.",
            "preconditions": ["Critical-only precondition."],
            "attack_path": ["Reach only the critical path."],
        }
    )
    assert candidate_similarity(low, critical) >= 0.55
    group = group_candidates([low, critical])[0]
    review, cross_examinations = _review_evidence(
        [low, critical],
        {
            low.candidate_id: (
                VerificationVerdict.VERIFIED,
                VerificationVerdict.VERIFIED,
                VerificationVerdict.VERIFIED,
            ),
            critical.candidate_id: (
                VerificationVerdict.VERIFIED,
                VerificationVerdict.PLAUSIBLE,
                VerificationVerdict.REJECTED,
            ),
        },
    )
    validations = {
        low.candidate_id: LocationValidation(valid=True),
        critical.candidate_id: LocationValidation(valid=True),
    }

    finding = merge_group(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.NEEDS_REVIEW
    assert finding.severity is Severity.CRITICAL
    assert finding.title == critical.title
    assert finding.summary == critical.summary
    assert status_bearing_candidate_ids(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        consensus_review=review,
        cross_examinations=cross_examinations,
    ) == frozenset({critical.candidate_id})

    published = [
        merge_group(
            publication_group,
            decisions={},
            validations=validations,
            scanner_findings=[],
            judge=None,
            consensus_review=review,
            cross_examinations=cross_examinations,
        )
        for publication_group in publication_groups([low, critical])
    ]
    assert len(published) == 2
    assert len({item.id for item in published}) == 2
    assert any(
        item.title == critical.title
        and item.severity is Severity.CRITICAL
        and item.status is FindingStatus.NEEDS_REVIEW
        for item in published
    )


def test_confirmed_status_cannot_publish_an_inconclusive_candidates_claim(
    candidate_factory: CandidateFactory,
) -> None:
    confirmed = _with_reproduction_evidence(
        candidate_factory(candidate_id="confirmed", title="Confirmed SQL injection")
    )
    inconclusive = candidate_factory(
        candidate_id="inconclusive",
        role="business_logic",
        title="Inconclusive alternate claim",
    ).model_copy(
        update={
            "confidence": 0.99,
            "summary": "This summary belongs only to the inconclusive candidate.",
            "preconditions": ["Inconclusive-only precondition"],
            "evidence": [
                Evidence(
                    type="model",
                    source="business_logic",
                    description="Inconclusive-only evidence",
                )
            ],
        }
    )
    group = group_candidates([confirmed, inconclusive])[0]
    review, cross_examinations = _review_evidence(
        [confirmed, inconclusive],
        {
            confirmed.candidate_id: (
                VerificationVerdict.VERIFIED,
                VerificationVerdict.VERIFIED,
                VerificationVerdict.VERIFIED,
            ),
            inconclusive.candidate_id: (
                VerificationVerdict.VERIFIED,
                VerificationVerdict.PLAUSIBLE,
                VerificationVerdict.REJECTED,
            ),
        },
    )

    finding = merge_group(
        group,
        decisions={},
        validations={
            confirmed.candidate_id: LocationValidation(valid=True),
            inconclusive.candidate_id: LocationValidation(valid=True),
        },
        scanner_findings=[_scanner()],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.title == confirmed.title
    assert finding.summary == confirmed.summary
    assert finding.confidence == confirmed.confidence
    assert "Inconclusive-only precondition" not in finding.preconditions
    assert all(
        evidence.description != "Inconclusive-only evidence" for evidence in finding.evidence
    )
    assert finding.contributing_candidate_ids == ["confirmed", "inconclusive"]
    assert status_bearing_candidate_ids(
        group,
        decisions={},
        validations={
            confirmed.candidate_id: LocationValidation(valid=True),
            inconclusive.candidate_id: LocationValidation(valid=True),
        },
        scanner_findings=[_scanner()],
        consensus_review=review,
        cross_examinations=cross_examinations,
    ) == frozenset({confirmed.candidate_id})


def test_judge_cannot_replace_status_bearing_candidate_taxonomy(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = _with_reproduction_evidence(candidate_factory())
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])
    judge = JudgeDecision(
        group_id=group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        confidence=0.95,
        cwe=["CWE-22"],
        owasp=["A01:2021"],
        rationale="The judge supplied taxonomy unrelated to the winning claim.",
    )

    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[_scanner()],
        judge=judge,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.cwe == candidate.cwe
    assert finding.owasp == candidate.owasp


def test_judge_cannot_lower_confirmed_candidate_below_reporting_threshold(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = _with_reproduction_evidence(candidate_factory())
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])
    judge = JudgeDecision(
        group_id=group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.INFORMATIONAL,
        confidence=0.95,
        cwe=candidate.cwe,
        owasp=candidate.owasp,
        rationale="The judge attempted to suppress the retained group by lowering impact.",
    )

    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[_scanner()],
        judge=judge,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.severity is Severity.HIGH


def test_invalid_location_rejects_supported_quorum(candidate_factory: CandidateFactory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])

    status = preliminary_status(
        group,
        {},
        {candidate.candidate_id: LocationValidation(valid=False, errors=["outside context"])},
        [_scanner()],
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert status is FindingStatus.REJECTED


def test_judge_cannot_raise_consensus_cap(candidate_factory: CandidateFactory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence(
        [candidate],
        (
            VerificationVerdict.VERIFIED,
            VerificationVerdict.PLAUSIBLE,
            VerificationVerdict.REJECTED,
        ),
    )
    judge = JudgeDecision(
        group_id=group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.CRITICAL,
        confidence=0.99,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        rationale="The judge tried to raise status.",
    )

    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[],
        judge=judge,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.NEEDS_REVIEW
    assert finding.id.startswith("MMA-")


def test_judge_cannot_reject_candidate_retained_by_quorum(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])
    judge = JudgeDecision(
        group_id=group.group_id,
        status=FindingStatus.REJECTED,
        severity=Severity.LOW,
        confidence=0.2,
        rationale="A fourth model tried to erase the retained candidate.",
    )

    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[],
        judge=judge,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.NEEDS_REVIEW
    assert finding.confidence == 0.2


def test_every_dissenting_review_is_retained(candidate_factory: CandidateFactory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence(
        [candidate],
        (
            VerificationVerdict.VERIFIED,
            VerificationVerdict.PLAUSIBLE,
            VerificationVerdict.REJECTED,
        ),
    )

    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.NEEDS_REVIEW
    assert "verifier:candidate-1:verifier retained verified dissent" in finding.disagreement
    assert "falsifier_1:candidate-1:falsifier_1 retained plausible dissent" in finding.disagreement
    assert "falsifier_2:candidate-1:falsifier_2 retained rejected dissent" in finding.disagreement


def test_critical_scanner_evidence_remains_nonconfirming_without_exact_claim_binding(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = _with_scanner_evidence(candidate_factory())
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])
    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[_scanner().model_copy(update={"severity": Severity.CRITICAL})],
        judge=JudgeDecision(
            group_id=group.group_id,
            status=FindingStatus.CONFIRMED,
            severity=Severity.CRITICAL,
            confidence=0.95,
            rationale="The deterministic scanner matches the exact candidate location.",
        ),
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    capped = enforce_critical_evidence_cap(
        finding,
        require_formal_or_reproduction=True,
    )

    assert finding.status is FindingStatus.HIGH_CONFIDENCE
    assert finding.evidence_strength is EvidenceStrength.VALIDATED_ATTACK_PATH
    assert capped.status is FindingStatus.HIGH_CONFIDENCE
    assert capped.severity is Severity.CRITICAL
    assert all(item.type != "scanner" for item in capped.evidence)


def test_unbound_formal_counterexample_cannot_confirm_critical(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    candidate = candidate.model_copy(
        update={
            "severity": Severity.CRITICAL,
            "evidence": [
                *candidate.evidence,
                Evidence(
                    type="formal",
                    source="solc-smtchecker",
                    description="SMTChecker found an assertion counterexample.",
                    rule_id="counterexample",
                    fingerprint="formal-witness-hash",
                ),
            ],
        }
    )
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])
    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.HIGH_CONFIDENCE
    assert finding.evidence_strength is EvidenceStrength.VALIDATED_ATTACK_PATH


def test_accepted_local_reproduction_can_confirm_critical(
    candidate_factory: CandidateFactory,
) -> None:
    candidate = candidate_factory()
    candidate = candidate.model_copy(
        update={
            "severity": Severity.CRITICAL,
            "evidence": [
                *candidate.evidence,
                Evidence(
                    type="reproduction",
                    source="mmaudit-local-fork-reproduction",
                    description="A minimized synthetic local test reproduced the unsafe state.",
                    rule_id="reproduced_and_minimized",
                    fingerprint="generated-test-hash",
                ),
            ],
        }
    )
    group = group_candidates([candidate])[0]
    review, cross_examinations = _uniform_review_evidence([candidate])
    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[],
        judge=None,
        consensus_review=review,
        cross_examinations=cross_examinations,
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.evidence_strength is EvidenceStrength.MINIMIZED_LOCAL_FORK_REPRODUCTION
    assert (
        enforce_critical_evidence_cap(
            finding,
            require_formal_or_reproduction=True,
        ).status
        is FindingStatus.CONFIRMED
    )
