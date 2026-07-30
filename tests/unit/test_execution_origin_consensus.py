"""Consensus authority boundaries for deterministic execution-origin findings."""

from __future__ import annotations

from itertools import permutations

from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateOriginKind,
    Evidence,
    EvidenceStrength,
    FindingOriginKind,
    FindingStatus,
    InvariantExecutionCandidateProvenance,
    JudgeDecision,
    Location,
    LocationValidation,
    ModelVote,
    ScannerFinding,
    Severity,
    SourceSink,
    VerificationDecision,
    VerificationTest,
    VerificationVerdict,
)
from mmaudit.orchestration.consensus import (
    CandidateGroup,
    candidate_similarity,
    enforce_critical_evidence_cap,
    group_candidates,
    merge_group,
    preliminary_status,
)


def _provenance(
    *,
    marker: str = "a",
    path: str = "src/SyntheticVault.sol",
    start_line: int = 10,
    end_line: int = 12,
    symbol: str = "updateAccounting",
) -> InvariantExecutionCandidateProvenance:
    return InvariantExecutionCandidateProvenance.sealed(
        invariant_id=f"invariant-{marker}",
        invariant_evidence_sha256="1" * 64,
        harness_name=f"SyntheticHarness{marker.upper()}",
        harness_spec_sha256="2" * 64,
        property_corpus_sha256="3" * 64,
        property_ids=(f"property-{marker}",),
        property_hashes=(marker * 64,),
        execution_result_sha256="4" * 64,
        execution_observation_sha256="5" * 64,
        executable_sha256="6" * 64,
        source_sha256="7" * 64,
        compiler_version="forge 1.5.0 / solc 0.8.30",
        compiler_sha256="8" * 64,
        isolation_backend="synthetic-rootless-isolation",
        isolation_attestation_sha256="9" * 64,
        attempts=2,
        successful_attempts=2,
        minimized=True,
        source_locations=(
            Location(
                path=path,
                start_line=start_line,
                end_line=end_line,
                symbol=symbol,
                content_hash=marker * 64,
            ),
        ),
    )


def _vote(*, role: str, verdict: str) -> ModelVote:
    return ModelVote(
        role=role,
        requested_model=f"synthetic/{role}",
        returned_model=f"synthetic/{role}",
        family=f"lineage-{role}",
        verdict=verdict,
        rationale="Non-authoritative model commentary.",
    )


def _execution_candidate(
    provenance: InvariantExecutionCandidateProvenance,
    *,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.82,
    model_votes: list[ModelVote] | None = None,
) -> CandidateFinding:
    return CandidateFinding(
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        origin_kind=CandidateOriginKind.DETERMINISTIC_EXECUTION,
        execution_provenance=provenance,
        title="Accounting invariant counterexample",
        severity=severity,
        confidence=confidence,
        cwe=["CWE-682"],
        summary="Repeated local execution observed an incorrect accounting transition.",
        impact="The declared accounting invariant does not hold.",
        preconditions=["The bounded synthetic harness reaches the affected transition."],
        locations=list(provenance.source_locations),
        attack_path=["Replay the bounded local sequence that violates the invariant."],
        evidence=[
            Evidence(
                type="execution",
                source="mmaudit-foundry-invariant",
                description="Two fresh local executions produced the counterexample.",
                rule_id=provenance.invariant_id,
                fingerprint=provenance.provenance_sha256,
            )
        ],
        false_positive_conditions=["The typed invariant does not express intended behavior."],
        recommendation="Correct the transition and rerun the local invariant campaign.",
        verification_test=VerificationTest(
            description="Replay the typed invariant in a fresh isolated workspace."
        ),
        role=None,
        model_family=None,
        model_votes=model_votes or [],
    )


def _model_candidate(
    *,
    candidate_id: str,
    locations: list[Location],
    family: str = "lineage-model-a",
    confidence: float = 0.95,
    severity: Severity = Severity.CRITICAL,
    model_votes: list[ModelVote] | None = None,
) -> CandidateFinding:
    primary = locations[0]
    return CandidateFinding(
        candidate_id=candidate_id,
        title="Accounting invariant counterexample",
        severity=severity,
        confidence=confidence,
        cwe=["CWE-682"],
        summary="A model supplied impact commentary about the accounting transition.",
        impact="The model assessed the potential effect of the observed transition.",
        preconditions=["The affected transition is reachable."],
        locations=locations,
        source=SourceSink(
            description="Synthetic state transition input.",
            path=primary.path,
            line=primary.start_line,
        ),
        sink=SourceSink(
            description="Synthetic accounting state update.",
            path=primary.path,
            line=primary.end_line,
        ),
        attack_path=["Reach the transition.", "Observe the accounting mismatch."],
        evidence=[
            Evidence(
                type="model",
                source="specialist:business_logic",
                description="Non-authoritative impact and remediation analysis.",
            )
        ],
        false_positive_conditions=["A surrounding guard prevents the transition."],
        recommendation="Review the transition and preserve the declared invariant.",
        verification_test=VerificationTest(
            description="Run the bounded synthetic accounting regression."
        ),
        role="business_logic",
        model_family=family,
        model_votes=model_votes or [],
    )


def _decision(
    candidate_id: str,
    verdict: VerificationVerdict,
) -> VerificationDecision:
    return VerificationDecision(
        candidate_id=candidate_id,
        verdict=verdict,
        rationale="Independent model assessment of the submitted candidate.",
        source_to_sink="Synthetic transition to accounting state.",
        reachability="Locally reachable.",
        authentication="Not relevant to the synthetic fixture.",
        privilege_requirements="Synthetic fixture caller.",
        environmental_assumptions=[],
        guards_and_controls=[],
        false_positive_conditions=["A local guard blocks the transition."],
        safe_verification_test=VerificationTest(description="Replay the bounded local transition."),
        confidence=0.9,
    )


def _judge(
    group_id: str,
    *,
    status: FindingStatus,
    severity: Severity = Severity.CRITICAL,
    confidence: float = 0.99,
) -> JudgeDecision:
    return JudgeDecision(
        group_id=group_id,
        status=status,
        severity=severity,
        confidence=confidence,
        cwe=["CWE-682"],
        rationale="Non-authoritative final model assessment.",
    )


def _validation(
    *,
    valid: bool,
    marker: str,
) -> LocationValidation:
    return LocationValidation(
        valid=valid,
        content_hash=marker * 64 if valid else None,
        errors=[] if valid else ["execution origin no longer matches current source"],
    )


def test_execution_alone_is_confirmed_by_validated_deterministic_evidence() -> None:
    provenance = _provenance()
    candidate = _execution_candidate(provenance)
    group = group_candidates([candidate])[0]
    validations = {candidate.candidate_id: _validation(valid=True, marker="a")}

    assert preliminary_status(group, {}, validations, []) is FindingStatus.CONFIRMED

    finding = merge_group(
        group,
        decisions={},
        validations=validations,
        scanner_findings=[],
        judge=None,
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
    assert finding.execution_provenance == (provenance,)
    assert finding.locations == list(provenance.source_locations)
    assert finding.contributing_candidate_ids == [candidate.candidate_id]
    assert finding.evidence_strength is EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE
    assert finding.model_votes == []


def test_verifier_and_judge_cannot_delete_or_relocate_valid_execution_origin() -> None:
    provenance = _provenance()
    execution = _execution_candidate(provenance, confidence=0.4)
    relocated = Location(
        path=provenance.source_locations[0].path,
        start_line=200,
        end_line=202,
        symbol="unrelatedTransition",
        content_hash="b" * 64,
    )
    commentary = _model_candidate(
        candidate_id="model-relocation-attempt",
        locations=[provenance.source_locations[0], relocated],
        confidence=0.99,
    )
    group = group_candidates([commentary, execution])[0]
    decisions = {
        execution.candidate_id: _decision(
            execution.candidate_id,
            VerificationVerdict.REJECTED,
        ),
        commentary.candidate_id: _decision(
            commentary.candidate_id,
            VerificationVerdict.REJECTED,
        ),
    }
    validations = {
        execution.candidate_id: _validation(valid=True, marker="a"),
        commentary.candidate_id: _validation(valid=True, marker="b"),
    }

    finding = merge_group(
        group,
        decisions=decisions,
        validations=validations,
        scanner_findings=[],
        judge=_judge(
            group.group_id,
            status=FindingStatus.REJECTED,
            severity=Severity.LOW,
            confidence=0.01,
        ),
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.title == execution.title
    assert finding.summary == execution.summary
    assert finding.recommendation == execution.recommendation
    assert finding.confidence == execution.confidence
    assert finding.locations == list(provenance.source_locations)
    assert relocated not in finding.locations


def test_group_identity_and_origin_do_not_change_under_model_commentary() -> None:
    provenance = _provenance()
    bare_execution = _execution_candidate(provenance)
    annotated_execution = _execution_candidate(
        provenance,
        model_votes=[
            _vote(role="verifier", verdict="rejected"),
            _vote(role="judge", verdict="rejected"),
        ],
    )
    commentary = _model_candidate(
        candidate_id="model-impact-commentary",
        locations=list(provenance.source_locations),
        model_votes=[_vote(role="business_logic", verdict="proposed")],
    )
    execution_group_id = group_candidates([bare_execution])[0].group_id
    group = group_candidates([commentary, annotated_execution])[0]

    assert group.group_id == execution_group_id

    finding = merge_group(
        group,
        decisions={
            annotated_execution.candidate_id: _decision(
                annotated_execution.candidate_id,
                VerificationVerdict.REJECTED,
            ),
            commentary.candidate_id: _decision(
                commentary.candidate_id,
                VerificationVerdict.VERIFIED,
            ),
        },
        validations={
            annotated_execution.candidate_id: _validation(valid=True, marker="a"),
            commentary.candidate_id: _validation(valid=True, marker="b"),
        },
        scanner_findings=[],
        judge=_judge(group.group_id, status=FindingStatus.CONFIRMED),
    )

    assert annotated_execution.role is None
    assert annotated_execution.model_family is None
    assert finding.group_id == execution_group_id
    assert finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
    assert finding.execution_provenance == (provenance,)
    assert finding.evidence_strength is EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE
    assert {vote.role for vote in finding.model_votes} == {
        "business_logic",
        "judge",
        "verifier",
    }


def test_transitive_model_bridge_cannot_absorb_unrelated_model_candidate() -> None:
    provenance = _provenance()
    execution = _execution_candidate(provenance)
    remote = Location(
        path=provenance.source_locations[0].path,
        start_line=80,
        end_line=82,
        symbol="withdraw",
        content_hash="b" * 64,
    )
    bridge = _model_candidate(
        candidate_id="model-bridge",
        locations=[provenance.source_locations[0], remote],
    )
    unrelated = _model_candidate(
        candidate_id="model-unrelated",
        locations=[remote],
        family="lineage-model-b",
    )
    expected_execution_group_id = group_candidates([execution])[0].group_id

    assert candidate_similarity(execution, bridge) >= 0.55
    assert candidate_similarity(bridge, unrelated) >= 0.55
    for ordering in permutations([execution, bridge, unrelated]):
        groups = group_candidates(list(ordering))
        execution_group = next(
            group for group in groups if execution.candidate_id in _candidate_ids(group)
        )
        assert execution_group.group_id == expected_execution_group_id
        assert unrelated.candidate_id not in _candidate_ids(execution_group)


def test_transitive_model_bridge_cannot_merge_unrelated_execution_anchors() -> None:
    left = _execution_candidate(
        _provenance(marker="a", start_line=10, end_line=12, symbol="deposit")
    )
    right = _execution_candidate(
        _provenance(marker="b", start_line=80, end_line=82, symbol="withdraw")
    )
    bridge = _model_candidate(
        candidate_id="model-multilocation-bridge",
        locations=[left.locations[0], right.locations[0]],
    )
    expected_group_ids = {
        group_candidates([left])[0].group_id,
        group_candidates([right])[0].group_id,
    }

    for ordering in permutations([left, bridge, right]):
        groups = group_candidates(list(ordering))
        assert {group.group_id for group in groups} == expected_group_ids
        assert all(
            not {left.candidate_id, right.candidate_id} <= _candidate_ids(group) for group in groups
        )


def _candidate_ids(group: CandidateGroup) -> set[str]:
    return {candidate.candidate_id for candidate in group.candidates}


def test_invalid_execution_anchor_cannot_be_rescued_by_model_verification() -> None:
    provenance = _provenance()
    execution = _execution_candidate(provenance)
    commentary = _model_candidate(
        candidate_id="model-valid-current-source",
        locations=list(provenance.source_locations),
    )
    group = group_candidates([execution, commentary])[0]
    validations = {
        execution.candidate_id: _validation(valid=False, marker="a"),
        commentary.candidate_id: _validation(valid=True, marker="b"),
    }
    decisions = {
        execution.candidate_id: _decision(
            execution.candidate_id,
            VerificationVerdict.REJECTED,
        ),
        commentary.candidate_id: _decision(
            commentary.candidate_id,
            VerificationVerdict.VERIFIED,
        ),
    }

    assert preliminary_status(group, decisions, validations, []) is FindingStatus.REJECTED


def test_execution_finding_validation_state_is_bound_to_execution_anchor() -> None:
    provenance = _provenance()
    execution = _execution_candidate(provenance)
    commentary = _model_candidate(
        candidate_id="model-valid-current-source",
        locations=list(provenance.source_locations),
    )
    group = group_candidates([execution, commentary])[0]

    finding = merge_group(
        group,
        decisions={
            execution.candidate_id: _decision(
                execution.candidate_id,
                VerificationVerdict.REJECTED,
            ),
            commentary.candidate_id: _decision(
                commentary.candidate_id,
                VerificationVerdict.VERIFIED,
            ),
        },
        validations={
            execution.candidate_id: _validation(valid=False, marker="a"),
            commentary.candidate_id: _validation(valid=True, marker="b"),
        },
        scanner_findings=[],
        judge=_judge(group.group_id, status=FindingStatus.CONFIRMED),
    )

    assert finding.location_validation.valid is False
    assert finding.status is FindingStatus.REJECTED


def test_model_only_consensus_cap_remains_strong_support() -> None:
    location = Location(
        path="src/SyntheticVault.sol",
        start_line=30,
        end_line=32,
        symbol="settle",
    )
    left = _model_candidate(
        candidate_id="model-left",
        locations=[location],
        family="lineage-model-a",
    )
    right = _model_candidate(
        candidate_id="model-right",
        locations=[location],
        family="lineage-model-b",
    )
    group = group_candidates([left, right])[0]
    decisions = {
        candidate.candidate_id: _decision(
            candidate.candidate_id,
            VerificationVerdict.VERIFIED,
        )
        for candidate in (left, right)
    }
    validations = {
        candidate.candidate_id: _validation(valid=True, marker=marker)
        for candidate, marker in ((left, "a"), (right, "b"))
    }

    assert preliminary_status(group, decisions, validations, []) is FindingStatus.STRONGLY_SUPPORTED

    finding = merge_group(
        group,
        decisions=decisions,
        validations=validations,
        scanner_findings=[],
        judge=_judge(group.group_id, status=FindingStatus.CONFIRMED),
    )

    assert finding.status is FindingStatus.STRONGLY_SUPPORTED
    assert finding.origin_kind is FindingOriginKind.MODEL_REVIEW
    assert finding.execution_provenance == ()
    assert finding.evidence_strength is EvidenceStrength.VALIDATED_ATTACK_PATH
    assert (
        enforce_critical_evidence_cap(
            finding,
            require_formal_or_reproduction=True,
        ).status
        is FindingStatus.STRONGLY_SUPPORTED
    )


def test_model_only_confirmed_critical_still_requires_executable_proof() -> None:
    location = Location(
        path="src/SyntheticVault.sol",
        start_line=40,
        end_line=42,
        symbol="rebalance",
    )
    candidate = _model_candidate(
        candidate_id="model-scanner-supported",
        locations=[location],
        severity=Severity.CRITICAL,
    )
    group = group_candidates([candidate])[0]
    scanner = ScannerFinding(
        scanner="synthetic-static-analyzer",
        rule_id="synthetic-accounting-rule",
        title="Synthetic accounting mismatch",
        severity=Severity.CRITICAL,
        message="A deterministic analyzer reported the same local source range.",
        locations=[location],
        cwe=["CWE-682"],
        fingerprint="synthetic-scanner-fingerprint",
    )
    finding = merge_group(
        group,
        decisions={
            candidate.candidate_id: _decision(
                candidate.candidate_id,
                VerificationVerdict.VERIFIED,
            )
        },
        validations={candidate.candidate_id: _validation(valid=True, marker="a")},
        scanner_findings=[scanner],
        judge=_judge(group.group_id, status=FindingStatus.CONFIRMED),
    )

    assert finding.status is FindingStatus.CONFIRMED
    assert finding.evidence_strength is EvidenceStrength.DETERMINISTIC_ANALYZER
    capped = enforce_critical_evidence_cap(
        finding,
        require_formal_or_reproduction=True,
    )
    assert capped.status is FindingStatus.STRONGLY_SUPPORTED
    assert capped.origin_kind is FindingOriginKind.MODEL_REVIEW
    assert capped.execution_provenance == ()
