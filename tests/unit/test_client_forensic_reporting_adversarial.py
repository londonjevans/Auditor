from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

import pytest

from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.schemas import (
    AuditReport,
    AuditRunStatus,
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationVerdict,
    CandidateFinding,
    Evidence,
    ExecutionEvidenceKind,
    FalsificationDecision,
    FalsificationVerdict,
    Finding,
    FindingOriginKind,
    FindingStatus,
    FormalToolRun,
    FormalToolStatus,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    Location,
    LocationValidation,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    UsageRecord,
    VerificationDecision,
    VerificationTest,
    VerificationVerdict,
)
from mmaudit.reporting.bundle import build_coverage_artifact, build_findings_artifact
from mmaudit.reporting.client import (
    bind_active_finding_source_locations,
    render_client_markdown,
)
from mmaudit.reporting.markdown import render_forensic_markdown
from mmaudit.reporting.run_authority import RunTerminalReportAuthority
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import effective_report_status
from mmaudit.repository.chunking import line_range_hash
from tests.unit.test_assurance import _real_formal_run
from tests.unit.test_client_forensic_reporting import (
    SOURCE,
    SOURCE_PATH,
    _finding,
    _report,
)
from tests.unit.test_run_status import (
    NOW,
    _assessment,
    _coverage,
    _real_scanner,
    _report_payload,
    _typed_report_payload,
    _usage,
)


def _report_with_decisions(
    finding: Finding,
    *,
    verifications: Sequence[VerificationDecision] = (),
    cross_examinations: Sequence[CandidateCrossExaminationDecision] = (),
    falsifications: Sequence[FalsificationDecision] = (),
) -> AuditReport:
    return _report(findings=[finding]).model_copy(
        update={
            "verification_decisions": list(verifications),
            "cross_examination_decisions": list(cross_examinations),
            "falsification_decisions": list(falsifications),
        }
    )


def _verification(verdict: VerificationVerdict) -> VerificationDecision:
    return VerificationDecision(
        candidate_id="candidate-synthetic-001",
        verdict=verdict,
        rationale="The independent verifier cannot support the reported authority.",
        source_to_sink="The cited transition does not establish the stated sink.",
        reachability="Reachability remains contradicted by the synthetic guard.",
        authentication="The caller boundary remains material.",
        privilege_requirements="No impossible privilege may be assumed.",
        environmental_assumptions=["The synthetic runtime state matches the cited source."],
        guards_and_controls=["The amount guard executes before the state transition."],
        false_positive_conditions=["The guard rejects the disputed transition."],
        safe_verification_test=VerificationTest(
            description="Run the safe local verifier negative control."
        ),
        confidence=0.88,
    )


def _cross_examination(
    *,
    candidate_id: str = "candidate-synthetic-001",
    reviewer_index: int = 1,
) -> CandidateCrossExaminationDecision:
    return CandidateCrossExaminationDecision(
        candidate_id=candidate_id,
        request_id=f"cross-{reviewer_index}-{candidate_id}",
        reviewer_index=reviewer_index,
        requested_model=f"synthetic/reviewer-{reviewer_index}",
        returned_model=f"synthetic/reviewer-{reviewer_index}",
        root_lineage="sha256:" + str(reviewer_index) * 64,
        verdict=CandidateCrossExaminationVerdict.INCONCLUSIVE,
        rationale="The independent reviewer could not resolve the contradictory transition.",
        contradictions=["The observed guard conflicts with the claimed reachable path."],
        missing_evidence=["A source-bound post-state observation is missing."],
    )


def _falsification(verdict: FalsificationVerdict) -> FalsificationDecision:
    return FalsificationDecision(
        candidate_id="candidate-synthetic-001",
        test_name=f"negative-control-{verdict.value}",
        verdict=verdict,
        test_matches_claim=False,
        assumptions_validated=False,
        rationale="The negative control did not validate the claimed transition.",
        contradictions=["The observed state remained within the declared accounting bound."],
    )


def _candidate(candidate_id: str, finding: Finding) -> CandidateFinding:
    assert finding.verification_test is not None
    return CandidateFinding(
        candidate_id=candidate_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        cwe=list(finding.cwe),
        owasp=list(finding.owasp),
        summary=finding.summary,
        impact=finding.impact,
        preconditions=list(finding.preconditions),
        locations=list(finding.locations),
        source=finding.source,
        sink=finding.sink,
        attack_path=list(finding.attack_path),
        evidence=list(finding.evidence),
        compensating_controls=list(finding.compensating_controls),
        false_positive_conditions=list(finding.false_positive_conditions),
        recommendation=finding.recommendation,
        verification_test=finding.verification_test,
        role="source_audit",
        model_family=f"synthetic-{candidate_id}",
    )


def _render_client(
    report: AuditReport,
    source_contents: dict[str, str],
    *,
    candidates: Sequence[CandidateFinding] | None = None,
) -> str:
    """Render with an exact, explicit synthetic candidate evidence inventory."""

    resolved_candidates = (
        list(candidates)
        if candidates is not None
        else [
            _candidate(candidate_id, finding)
            for finding in [*report.findings, *report.rejected_findings]
            for candidate_id in finding.contributing_candidate_ids
        ]
    )
    return render_client_markdown(report, source_contents, candidates=resolved_candidates)


def _report_for_source(
    source: str,
    *,
    start_line: int,
    end_line: int,
    symbol: str,
) -> AuditReport:
    range_sha256 = line_range_hash(source, start_line, end_line)
    location = Location(
        path=SOURCE_PATH,
        start_line=start_line,
        end_line=end_line,
        symbol=symbol,
        content_hash=range_sha256,
    )
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED).model_copy(
        update={
            "locations": [location],
            "location_validation": LocationValidation(
                valid=True,
                content_hash=hashlib.sha256(range_sha256.encode()).hexdigest(),
                validated_at=NOW,
            ),
        }
    )
    report = _report(findings=[finding])
    source_file = report.repository.files[0].model_copy(
        update={
            "size": len(source.encode()),
            "lines": len(source.splitlines()),
            "sha256": hashlib.sha256(source.encode()).hexdigest(),
        }
    )
    repository = report.repository.model_copy(update={"files": [source_file]})
    return report.model_copy(update={"repository": repository})


def _scanner_variant(
    scanner: ScannerRun,
    *,
    name: str,
    execution_evidence: ExecutionEvidenceKind,
) -> ScannerRun:
    payload = scanner.model_dump(mode="python")
    payload.update(
        {
            "scanner": name,
            "execution_evidence": execution_evidence,
            "execution_observation_sha256": None,
        }
    )
    draft = ScannerRun.model_validate(payload)
    return ScannerRun.model_validate(
        {
            **draft.model_dump(mode="python"),
            "execution_observation_sha256": draft.expected_execution_observation_sha256(),
        }
    )


def _failed_usage() -> UsageRecord:
    return UsageRecord(
        request_id="request-failed",
        role="source_audit",
        execution_evidence=ExecutionEvidenceKind.REAL,
        requested_model="synthetic/failed",
        model_family="synthetic-failed",
        timestamp=NOW,
        prompt_sha256="f" * 64,
        validation_status=ModelRequestValidationStatus.PROVIDER_ERROR,
        provider_error_classification="provider_unavailable",
        status="failed",
        attempts=1,
    )


def _unverified_usage() -> UsageRecord:
    payload = _usage(
        "configuration",
        execution_evidence=ExecutionEvidenceKind.MOCK,
    ).model_dump(mode="python")
    payload.update(
        {
            "execution_evidence": ExecutionEvidenceKind.UNVERIFIED,
            "identity_strength": ModelIdentityStrength.UNBOUND,
        }
    )
    return UsageRecord.model_validate(payload)


def test_legacy_zero_evidence_report_cannot_render_complete() -> None:
    report = AuditReport.model_validate(_report_payload())

    rendered = _render_client(report, {})

    assert "> **RUN STATUS: INCOMPLETE**" in rendered
    assert "> **RUN STATUS: COMPLETE**" not in rendered
    assert (
        "No reportable findings were identified by the analyses that completed. "
        "This run is incomplete and does not support a conclusion about repository safety."
    ) in rendered


def test_typed_complete_floor_can_render_calibrated_complete_no_findings() -> None:
    scanner = _real_scanner()
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    coverage = _coverage()
    floor = _assessment(
        scanner_runs=[scanner],
        usage=usage,
        coverage=coverage,
        required_model_roles=ANALYSIS_ROLES,
    )
    report = AuditReport.model_validate(
        _typed_report_payload(
            floor=floor,
            scanner_runs=[scanner],
            usage=usage,
            coverage=coverage,
        )
    )

    rendered = _render_client(report, {})
    findings_artifact = build_findings_artifact(report)
    coverage_artifact = build_coverage_artifact(report)
    forensic = render_forensic_markdown(report, findings_artifact=findings_artifact)
    sarif = generate_report_sarif(report, findings_artifact=findings_artifact)
    authority = RunTerminalReportAuthority.build(report)

    assert "> **RUN STATUS: COMPLETE**" in rendered
    assert "No reportable findings were identified within the analyses that completed" in rendered
    assert "This does not prove that the repository is secure" in rendered
    for artifact in (findings_artifact, coverage_artifact):
        assert artifact.run_status is AuditRunStatus.COMPLETE
        assert artifact.completed
        assert artifact.limitations == []
    assert "> **RUN STATUS: COMPLETE**" in forensic
    assert "No surviving findings met the configured scope" in forensic
    assert sarif["runs"][0]["properties"]["runStatus"] == AuditRunStatus.COMPLETE.value
    assert sarif["runs"][0]["properties"]["completed"] is True
    assert authority.run_status == AuditRunStatus.COMPLETE.value
    assert authority.terminal_exit_code == 0
    accounted_cost = authority.accounted_cost_usd_exact

    with pytest.raises(
        ValueError,
        match="runtime terminal exit code conflicts with the effective run status",
    ):
        RunTerminalReportAuthority.build_from_runtime(
            report=report,
            status=effective_report_status(report),
            minimum_analysis_floor=report.minimum_analysis_floor,
            maximum_assurance=report.maximum_assurance,
            accounted_cost_usd_exact=accounted_cost,
            terminal_exit_code=6,
        )


def test_pre_authorized_degraded_report_authority_retains_successful_process_exit() -> None:
    usage = [_usage(role) for role in ANALYSIS_ROLES]
    coverage = _coverage()
    floor = _assessment(
        usage=usage,
        coverage=coverage,
        explicit_downgrade_reason="operator accepted the unavailable static analyzer",
        required_model_roles=ANALYSIS_ROLES,
    )
    assert floor.run_status is AuditRunStatus.DEGRADED
    report = AuditReport.model_validate(
        _typed_report_payload(
            floor=floor,
            scanner_runs=[],
            usage=usage,
            coverage=coverage,
        )
    )

    authority = RunTerminalReportAuthority.build(report)

    assert authority.run_status == AuditRunStatus.DEGRADED.value
    assert not authority.completed
    assert authority.terminal_exit_code == 0


@pytest.mark.parametrize(
    ("finding_status", "verdict", "expected_disposition"),
    [
        (FindingStatus.STRONGLY_SUPPORTED, VerificationVerdict.REJECTED, "DISPUTED"),
        (
            FindingStatus.STRONGLY_SUPPORTED,
            VerificationVerdict.INSUFFICIENT_CONTEXT,
            "INCONCLUSIVE",
        ),
        (FindingStatus.CONFIRMED, VerificationVerdict.REJECTED, "DISPUTED"),
        (
            FindingStatus.CONFIRMED,
            VerificationVerdict.INSUFFICIENT_CONTEXT,
            "INCONCLUSIVE",
        ),
    ],
)
def test_verifier_dissent_limits_strong_or_confirmed_projection(
    finding_status: FindingStatus,
    verdict: VerificationVerdict,
    expected_disposition: str,
) -> None:
    decision = _verification(verdict)
    report = _report_with_decisions(
        _finding(finding_status),
        verifications=[decision],
    )

    rendered = _render_client(report, {SOURCE_PATH: SOURCE})

    assert f"> **{expected_disposition}**" in rendered
    for retained in (
        decision.rationale,
        decision.source_to_sink,
        decision.reachability,
        decision.authentication,
        decision.privilege_requirements,
        *decision.environmental_assumptions,
        *decision.guards_and_controls,
        *decision.false_positive_conditions,
        decision.safe_verification_test.description,
    ):
        assert retained in rendered
    assert rendered.count(f"Confidence: {decision.confidence:.2f}") == 1


@pytest.mark.parametrize(
    "finding_status", [FindingStatus.STRONGLY_SUPPORTED, FindingStatus.CONFIRMED]
)
def test_cross_examination_inconclusive_retains_complete_dissent(
    finding_status: FindingStatus,
) -> None:
    decision = _cross_examination()
    report = _report_with_decisions(
        _finding(finding_status),
        cross_examinations=[decision],
    )

    rendered = _render_client(report, {SOURCE_PATH: SOURCE})

    assert "> **INCONCLUSIVE**" in rendered
    assert decision.rationale in rendered
    assert decision.contradictions[0] in rendered
    assert decision.missing_evidence[0] in rendered


@pytest.mark.parametrize(
    "finding_status", [FindingStatus.STRONGLY_SUPPORTED, FindingStatus.CONFIRMED]
)
@pytest.mark.parametrize(
    ("verdict", "expected_disposition"),
    [
        (FalsificationVerdict.FALSIFIED, "DISPUTED"),
        (FalsificationVerdict.INCONCLUSIVE, "INCONCLUSIVE"),
        (FalsificationVerdict.UNSAFE, "INCONCLUSIVE"),
    ],
)
def test_falsifier_outcome_limits_authority_and_retains_boolean_evidence(
    finding_status: FindingStatus,
    verdict: FalsificationVerdict,
    expected_disposition: str,
) -> None:
    decision = _falsification(verdict)
    report = _report_with_decisions(
        _finding(finding_status),
        falsifications=[decision],
    )

    rendered = _render_client(report, {SOURCE_PATH: SOURCE})

    assert f"> **{expected_disposition}**" in rendered
    assert decision.rationale in rendered
    assert decision.contradictions[0] in rendered
    assert "Test matches claim: false" in rendered
    assert "Assumptions validated: false" in rendered


def test_narrative_summary_is_not_relabelled_as_a_violated_property() -> None:
    narrative = "The review observed a concerning withdrawal implementation."
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED).model_copy(
        update={"summary": narrative, "execution_provenance": ()}
    )

    rendered = _render_client(
        _report(findings=[finding]),
        {SOURCE_PATH: SOURCE},
    )

    property_line = next(
        line for line in rendered.splitlines() if line.startswith("Violated property:")
    )
    assert narrative not in property_line
    assert "Host-derived safety property" in property_line
    assert finding.title in property_line
    assert finding.preconditions[0] in property_line
    assert "not independent deterministic evidence" in rendered
    assert "not separately recorded" not in property_line


def test_bound_formal_property_identity_is_preserved_in_substantive_statement() -> None:
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED)
    formal_property_id = "INV-SYNTHETIC-CONSERVATION"
    finding = finding.model_copy(
        update={
            "evidence": [
                *finding.evidence,
                Evidence(
                    type="formal",
                    source="synthetic-formal-engine",
                    rule_id=formal_property_id,
                    description="The retained formal record identifies the checked property.",
                ),
            ]
        }
    )

    rendered = _render_client(_report(findings=[finding]), {SOURCE_PATH: SOURCE})
    property_line = next(
        line for line in rendered.splitlines() if line.startswith("Violated property:")
    )

    assert formal_property_id in property_line
    assert "Host-derived safety property" in property_line
    assert "bound deterministic/formal evidence identity" in rendered


def test_completed_analysis_credits_only_structurally_qualifying_real_evidence() -> None:
    real_scanner = _real_scanner()
    scanner_runs = [
        real_scanner,
        _scanner_variant(
            real_scanner,
            name="mock-slither",
            execution_evidence=ExecutionEvidenceKind.MOCK,
        ),
        _scanner_variant(
            real_scanner,
            name="unverified-slither",
            execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        ),
        ScannerRun(
            scanner="failed-slither",
            status=ScannerStatus.FAILED,
            execution_evidence=ExecutionEvidenceKind.REAL,
            started_at=NOW,
            finished_at=NOW,
            duration_seconds=0,
            error="Synthetic scanner failure.",
        ),
    ]
    usage = [
        _usage("source_audit"),
        _usage("business_logic", execution_evidence=ExecutionEvidenceKind.MOCK),
        _unverified_usage(),
        _failed_usage(),
    ]
    invariant_executions = [
        InvariantExecutionResult(
            invariant_id="claimed-real-without-attestation",
            harness_name="ClaimedRealHarness",
            status=InvariantExecutionStatus.PASSED,
            execution_evidence=ExecutionEvidenceKind.REAL,
        ),
        InvariantExecutionResult(
            invariant_id="mock-pass",
            harness_name="MockHarness",
            status=InvariantExecutionStatus.PASSED,
            execution_evidence=ExecutionEvidenceKind.MOCK,
        ),
        InvariantExecutionResult(
            invariant_id="failed-real",
            harness_name="FailedHarness",
            status=InvariantExecutionStatus.EXECUTION_FAILED,
            execution_evidence=ExecutionEvidenceKind.REAL,
        ),
    ]
    formal_runs = [
        _real_formal_run("halmos"),
        FormalToolRun(
            tool="claimed-real-without-attestation",
            status=FormalToolStatus.SUCCESS,
            execution_evidence=ExecutionEvidenceKind.REAL,
        ),
        FormalToolRun(
            tool="mock-formal",
            status=FormalToolStatus.SUCCESS,
            execution_evidence=ExecutionEvidenceKind.MOCK,
        ),
        FormalToolRun(
            tool="unverified-formal",
            status=FormalToolStatus.SUCCESS,
            execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        ),
        FormalToolRun(
            tool="failed-formal",
            status=FormalToolStatus.FAILED,
            execution_evidence=ExecutionEvidenceKind.REAL,
            failure_reason="Synthetic formal-engine failure.",
        ),
    ]
    reproductions = [
        ReproductionResult(
            candidate_id="candidate-synthetic-001",
            test_name="testClaimedReal",
            state=ReproductionState.REPRODUCED,
            execution_evidence=ExecutionEvidenceKind.REAL,
            specification_sha256="1" * 64,
        ),
        ReproductionResult(
            candidate_id="candidate-synthetic-001",
            test_name="testMock",
            state=ReproductionState.REPRODUCED,
            execution_evidence=ExecutionEvidenceKind.MOCK,
            specification_sha256="2" * 64,
        ),
        ReproductionResult(
            candidate_id="candidate-synthetic-001",
            test_name="testFailed",
            state=ReproductionState.NOT_REPRODUCED,
            execution_evidence=ExecutionEvidenceKind.REAL,
            specification_sha256="3" * 64,
        ),
    ]
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED)
    report = _report(findings=[finding]).model_copy(
        update={
            "scanner_runs": scanner_runs,
            "usage": usage,
            "invariant_executions": invariant_executions,
            "formal_runs": formal_runs,
            "reproductions": reproductions,
        }
    )

    rendered = _render_client(report, {SOURCE_PATH: SOURCE})

    assert "Qualifying REAL static analyzers: slither" in rendered
    assert "Creditable REAL completed model requests: 1" in rendered
    assert "REAL terminal invariant records: 0 of 3 retained" in rendered
    assert "REAL successful formal-engine records: 1 of 5 retained" in rendered
    assert "REAL terminal reproduction records: 0 of 3 retained" in rendered
    for non_creditable_name in (
        "mock-slither",
        "unverified-slither",
        "failed-slither",
    ):
        assert non_creditable_name not in rendered


def test_near_match_symbol_does_not_validate_against_a_different_identifier() -> None:
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED)
    near_match = finding.locations[0].model_copy(update={"symbol": "draw"})
    finding = finding.model_copy(update={"locations": [near_match]})

    with pytest.raises(ValueError, match="symbol"):
        _render_client(
            _report(findings=[finding]),
            {SOURCE_PATH: SOURCE},
        )


def test_active_finding_requires_an_authoritative_per_range_source_hash() -> None:
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED)
    unhashed = finding.locations[0].model_copy(update={"content_hash": None})
    hashless = finding.model_copy(update={"locations": [unhashed]})
    report = _report(findings=[hashless])

    with pytest.raises(ValueError, match=r"source range.*hash|hash.*source range"):
        _render_client(report, {SOURCE_PATH: SOURCE})

    bound = bind_active_finding_source_locations(report, {SOURCE_PATH: SOURCE})

    assert report.findings[0].locations[0].content_hash is None
    assert bound.findings[0].locations[0].content_hash == line_range_hash(
        SOURCE,
        unhashed.start_line,
        unhashed.end_line,
    )
    _render_client(bound, {SOURCE_PATH: SOURCE})


def test_active_final_binding_rejects_invalid_location_validation() -> None:
    finding = _finding(FindingStatus.NEEDS_REVIEW).model_copy(
        update={
            "location_validation": LocationValidation(
                valid=False,
                errors=["Synthetic source validation failed."],
                validated_at=NOW,
            )
        }
    )

    with pytest.raises(ValueError, match="lacks valid source-location evidence"):
        bind_active_finding_source_locations(
            _report(findings=[finding]),
            {SOURCE_PATH: SOURCE},
        )


def test_static_analyzer_custody_requires_zero_candidate_records() -> None:
    base = _finding(FindingStatus.NEEDS_REVIEW)
    fingerprint = "synthetic-scanner-fingerprint"
    static_finding = base.model_copy(
        update={
            "origin_kind": FindingOriginKind.STATIC_ANALYZER,
            "evidence": [
                Evidence(
                    type="scanner",
                    source="synthetic-scanner",
                    rule_id="synthetic-rule",
                    description="A synthetic local scanner observation.",
                    fingerprint=fingerprint,
                )
            ],
            "contributing_candidate_ids": [fingerprint],
        }
    )
    report = _report(findings=[static_finding])

    artifact = build_findings_artifact(report)

    assert artifact.candidate_findings == []
    assert artifact.records[0].candidate_findings == []
    with pytest.raises(ValueError, match="static-analyzer finding"):
        build_findings_artifact(
            report,
            candidates=[_candidate(fingerprint, base)],
        )


def test_large_cited_range_renders_a_bounded_line_window() -> None:
    body = "\n".join(f"        assets += {index};" for index in range(1, 40))
    source = (
        "pragma solidity ^0.8.30;\n"
        "contract SyntheticVault {\n"
        "    uint256 public assets;\n"
        "    function withdraw(uint256 amount) external {\n"
        f"{body}\n"
        "    }\n"
        "}\n"
    )
    report = _report_for_source(source, start_line=4, end_line=43, symbol="withdraw")

    rendered = _render_client(report, {SOURCE_PATH: source})
    code_lines = [line for line in rendered.splitlines() if re.match(r"^    \d{4} \|", line)]

    assert f"{SOURCE_PATH}:4-43" in rendered
    assert 1 <= len(code_lines) <= 24
    assert "bound source line(s) omitted after" in rendered
    assert "cited range hash covers the full retained range" in rendered


def test_oversized_source_line_renders_a_bounded_inert_excerpt() -> None:
    omitted_tail = "WIDE-LINE-TAIL-MUST-NOT-LEAK"
    source = (
        "pragma solidity ^0.8.30;\n"
        "contract SyntheticVault {\n"
        "    uint256 public assets;\n"
        "    function withdraw(uint256 amount) external { " + "x" * 20_000 + omitted_tail + " }\n"
        "}\n"
    )
    report = _report_for_source(source, start_line=4, end_line=4, symbol="withdraw")

    rendered = _render_client(report, {SOURCE_PATH: source})
    code_lines = [line for line in rendered.splitlines() if re.match(r"^    \d{4} \|", line)]

    assert 1 <= len(code_lines) <= 24
    cited_line = next(line for line in code_lines if "function withdraw" in line)
    assert len(cited_line.encode()) < 16_384
    assert "[line truncated]" in cited_line
    assert omitted_tail not in rendered


def test_permuted_candidate_and_decision_inputs_render_identically() -> None:
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED).model_copy(
        update={"contributing_candidate_ids": ["candidate-a", "candidate-b"]}
    )
    candidates = [
        _candidate(candidate_id, finding) for candidate_id in ("candidate-a", "candidate-b")
    ]
    decisions = [
        _cross_examination(candidate_id="candidate-a", reviewer_index=1),
        _cross_examination(candidate_id="candidate-b", reviewer_index=2),
    ]
    first = _report_with_decisions(finding, cross_examinations=decisions)
    second = _report_with_decisions(finding, cross_examinations=list(reversed(decisions)))

    first_render = _render_client(
        first,
        {SOURCE_PATH: SOURCE},
        candidates=candidates,
    )
    second_render = _render_client(
        second,
        {SOURCE_PATH: SOURCE},
        candidates=list(reversed(candidates)),
    )

    assert first_render == second_render


def test_incomplete_rejected_finding_requires_complete_contributor_closure() -> None:
    evidence_source = _finding(FindingStatus.STRONGLY_SUPPORTED)
    candidates = [
        _candidate("candidate-rejected-a", evidence_source),
        _candidate("candidate-rejected-b", evidence_source),
    ]
    rejected = Finding(
        id="MMA-SYNTHETIC-INCOMPLETE-REJECTED",
        group_id="group-synthetic-incomplete-rejected",
        title="Rejected synthetic proposal",
        status=FindingStatus.REJECTED,
        severity=evidence_source.severity,
        confidence=0.2,
        summary="The final rejected projection intentionally retains only its decision summary.",
        impact="The candidate evidence was not accepted as a reportable finding.",
        location_validation=LocationValidation(
            valid=False,
            errors=["The rejected projection does not claim a validated final location."],
            validated_at=NOW,
        ),
        disagreement="The linked candidate evidence remains available for forensic review.",
        contributing_candidate_ids=[candidate.candidate_id for candidate in candidates],
    )
    report = _report(rejected=[rejected])

    artifact = build_findings_artifact(report, candidates=candidates)

    assert [item.candidate_id for item in artifact.records[0].candidate_findings] == [
        "candidate-rejected-a",
        "candidate-rejected-b",
    ]
    with pytest.raises(ValueError, match=r"complete retained evidence|contributor set"):
        build_findings_artifact(report)
    with pytest.raises(ValueError, match="contributor set"):
        build_findings_artifact(report, candidates=candidates[:1])
