from __future__ import annotations

from mmaudit.models.schemas import (
    Evidence,
    EvidenceStrength,
    FindingStatus,
    JudgeDecision,
    Location,
    LocationValidation,
    ScannerFinding,
    Severity,
    VerificationDecision,
    VerificationTest,
    VerificationVerdict,
)
from mmaudit.orchestration.consensus import (
    candidate_similarity,
    enforce_critical_evidence_cap,
    group_candidates,
    merge_group,
    preliminary_status,
    stable_finding_id,
)


def _decision(candidate_id: str, verdict: VerificationVerdict) -> VerificationDecision:
    return VerificationDecision(
        candidate_id=candidate_id,
        verdict=verdict,
        rationale="Source and sink are reachable in the synthetic fixture.",
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


def test_similarity_and_duplicate_grouping(candidate_factory) -> None:
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


def test_unrelated_candidates_do_not_merge(candidate_factory) -> None:
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


def test_stable_finding_ids_are_repeatable(candidate_factory) -> None:
    candidate = candidate_factory()
    assert stable_finding_id(candidate) == stable_finding_id(candidate)
    changed = candidate.model_copy(update={"title": "Different wording"})
    assert stable_finding_id(candidate) == stable_finding_id(changed)


def test_scanner_plus_verifier_can_confirm(candidate_factory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    status = preliminary_status(
        group,
        {candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.VERIFIED)},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [_scanner()],
    )
    assert status == "confirmed"


def test_same_cwe_at_unrelated_location_is_not_scanner_corroboration(candidate_factory) -> None:
    candidate = candidate_factory()
    unrelated = _scanner().model_copy(
        update={"locations": [Location(path="config.py", start_line=3, end_line=3)]}
    )
    group = group_candidates([candidate])[0]
    status = preliminary_status(
        group,
        {candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.VERIFIED)},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [unrelated],
    )
    assert status == "high_confidence"


def test_two_independent_families_are_strong_support_not_confirmation(
    candidate_factory,
) -> None:
    left = candidate_factory(candidate_id="left")
    right = candidate_factory(
        candidate_id="right",
        role="business_logic",
        family="charlie/cirrus-secure",
    )
    group = group_candidates([left, right])[0]
    decisions = {
        item.candidate_id: _decision(item.candidate_id, VerificationVerdict.VERIFIED)
        for item in (left, right)
    }
    validations = {item.candidate_id: LocationValidation(valid=True) for item in (left, right)}
    assert preliminary_status(group, decisions, validations, []) == "strongly_supported"


def test_accepted_local_fork_reproduction_can_confirm(candidate_factory) -> None:
    candidate = candidate_factory()
    candidate = candidate.model_copy(
        update={
            "evidence": [
                *candidate.evidence,
                Evidence(
                    type="reproduction",
                    source="mmaudit-local-fork-reproduction",
                    description="A minimized local fork test reproduced the attack",
                    rule_id="reproduced_and_minimized",
                    fingerprint="generated-test-hash",
                ),
            ]
        }
    )
    group = group_candidates([candidate])[0]
    assert (
        preliminary_status(
            group,
            {
                candidate.candidate_id: _decision(
                    candidate.candidate_id, VerificationVerdict.VERIFIED
                )
            },
            {candidate.candidate_id: LocationValidation(valid=True)},
            [],
        )
        == "confirmed"
    )


def test_single_strong_model_is_high_confidence(candidate_factory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    status = preliminary_status(
        group,
        {candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.VERIFIED)},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [],
    )
    assert status == "high_confidence"


def test_plausible_or_invalid_evidence_cannot_confirm(candidate_factory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    plausible = preliminary_status(
        group,
        {candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.PLAUSIBLE)},
        {candidate.candidate_id: LocationValidation(valid=True)},
        [],
    )
    invalid = preliminary_status(
        group,
        {candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.VERIFIED)},
        {candidate.candidate_id: LocationValidation(valid=False, errors=["outside context"])},
        [_scanner()],
    )
    assert plausible == "needs_review"
    assert invalid == "rejected"


def test_verifier_rejection_rejects_group(candidate_factory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    assert (
        preliminary_status(
            group,
            {
                candidate.candidate_id: _decision(
                    candidate.candidate_id, VerificationVerdict.REJECTED
                )
            },
            {candidate.candidate_id: LocationValidation(valid=True)},
            [_scanner()],
        )
        == "rejected"
    )


def test_judge_cannot_raise_consensus_cap(candidate_factory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    decisions = {
        candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.PLAUSIBLE)
    }
    validations = {candidate.candidate_id: LocationValidation(valid=True)}
    judge = JudgeDecision(
        group_id=group.group_id,
        status="confirmed",
        severity="critical",
        confidence=0.99,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
        rationale="The model tried to raise status.",
    )
    finding = merge_group(
        group,
        decisions=decisions,
        validations=validations,
        scanner_findings=[],
        judge=judge,
    )
    assert finding.status == "needs_review"
    assert finding.id.startswith("MMA-")


def test_judge_can_lower_or_reject(candidate_factory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    decisions = {
        candidate.candidate_id: _decision(candidate.candidate_id, VerificationVerdict.VERIFIED)
    }
    validations = {candidate.candidate_id: LocationValidation(valid=True)}
    judge = JudgeDecision(
        group_id=group.group_id,
        status="rejected",
        severity="low",
        confidence=0.2,
        rationale="A nearby framework control disproves it.",
    )
    finding = merge_group(
        group,
        decisions=decisions,
        validations=validations,
        scanner_findings=[_scanner()],
        judge=judge,
    )
    assert finding.status == "rejected"
    assert finding.confidence == 0.2


def test_confirmed_critical_requires_formal_or_reproduction(candidate_factory) -> None:
    candidate = candidate_factory()
    group = group_candidates([candidate])[0]
    finding = merge_group(
        group,
        decisions={
            candidate.candidate_id: _decision(
                candidate.candidate_id,
                VerificationVerdict.VERIFIED,
            )
        },
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[_scanner().model_copy(update={"severity": Severity.CRITICAL})],
        judge=JudgeDecision(
            group_id=group.group_id,
            status=FindingStatus.CONFIRMED,
            severity=Severity.CRITICAL,
            confidence=0.95,
            rationale="Scanner and verifier agree.",
        ),
    )
    capped = enforce_critical_evidence_cap(
        finding,
        require_formal_or_reproduction=True,
    )
    assert capped.status is FindingStatus.STRONGLY_SUPPORTED
    assert capped.severity is Severity.CRITICAL
    assert "no accepted local reproduction" in capped.disagreement


def test_matching_formal_counterexample_can_confirm_critical(candidate_factory) -> None:
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
    finding = merge_group(
        group,
        decisions={
            candidate.candidate_id: _decision(
                candidate.candidate_id,
                VerificationVerdict.VERIFIED,
            )
        },
        validations={candidate.candidate_id: LocationValidation(valid=True)},
        scanner_findings=[],
        judge=None,
    )
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.evidence_strength is EvidenceStrength.FORMAL_COUNTEREXAMPLE
    assert (
        enforce_critical_evidence_cap(
            finding,
            require_formal_or_reproduction=True,
        ).status
        is FindingStatus.CONFIRMED
    )
