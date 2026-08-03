from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from mmaudit.models.schemas import (
    AnalysisState,
    AuditQualityStatus,
    AuditReport,
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationVerdict,
    CandidateReproductionResolution,
    CoverageMetric,
    CoverageProvenance,
    EvidenceStrength,
    Finding,
    FindingStatus,
    Location,
    LocationValidation,
    ModelReviewCoverage,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    RepositoryFile,
    RepositoryMap,
    ReproductionResolutionKind,
    ReproductionState,
    Severity,
    VerificationTest,
)
from mmaudit.reporting.bundle import (
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
)
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.markdown import render_forensic_markdown
from mmaudit.repository.chunking import line_range_hash

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)
SOURCE_PATH = "src/SyntheticVault.sol"
SOURCE = """pragma solidity ^0.8.30;

contract SyntheticVault {
    uint256 public assets;
    function withdraw(uint256 amount) external {
        require(amount <= assets, "balance");
        assets -= amount; // </code><script>fixture()</script> ``` | control
    }
}
"""
LOCATION_START = 5
LOCATION_END = 7


def _range_hash() -> str:
    return line_range_hash(SOURCE, LOCATION_START, LOCATION_END)


def _aggregate_location_hash() -> str:
    return hashlib.sha256(_range_hash().encode()).hexdigest()


def _finding(
    status: FindingStatus,
    *,
    finding_id: str = "MMA-SYNTHETIC-001",
) -> Finding:
    return Finding(
        id=finding_id,
        group_id="group-synthetic-001",
        title="Observed-versus-assumed accounting can diverge",
        status=status,
        severity=Severity.HIGH,
        confidence=0.91,
        cwe=["CWE-682"],
        summary="Withdrawals must not reduce recorded assets beyond the validated amount.",
        impact="The synthetic vault can record an incorrect asset transition.",
        preconditions=["The caller reaches the local synthetic withdrawal path."],
        locations=[
            Location(
                path=SOURCE_PATH,
                start_line=LOCATION_START,
                end_line=LOCATION_END,
                symbol="withdraw",
                content_hash=_range_hash(),
            )
        ],
        attack_path=[
            "Invoke the synthetic withdrawal entry point.",
            "Observe the accounting transition against the declared property.",
        ],
        evidence=[
            {
                "type": "repository",
                "source": "synthetic regression",
                "description": "The cited transition is bound to the audited source range.",
            }
        ],
        compensating_controls=["The amount guard bounds the immediate transition."],
        false_positive_conditions=["A separately proven invariant restores conservation."],
        recommendation="Bind the state transition to observed asset movement.",
        verification_test=VerificationTest(
            description="Run the safe local accounting invariant regression."
        ),
        location_validation=LocationValidation(
            valid=True,
            content_hash=_aggregate_location_hash(),
            validated_at=NOW,
        ),
        disagreement="Retain material dissent and unresolved assumptions.",
        contributing_candidate_ids=["candidate-synthetic-001"],
        evidence_strength=(
            EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE
            if status is FindingStatus.CONFIRMED
            else EvidenceStrength.INDEPENDENT_MODEL_SUPPORT
        ),
        reproduction_state=(
            ReproductionState.REPRODUCED
            if status is FindingStatus.CONFIRMED
            else ReproductionState.NOT_ATTEMPTED
        ),
    )


def _repository() -> RepositoryMap:
    encoded = SOURCE.encode()
    return RepositoryMap(
        root_name="synthetic-client-report",
        git_commit="a" * 40,
        languages={"Solidity": 1},
        frameworks=["foundry"],
        manifests=["foundry.toml"],
        entry_points=[SOURCE_PATH],
        api_surfaces=[f"{SOURCE_PATH}:withdraw"],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=["foundry.toml"],
        sensitive_processing=[SOURCE_PATH],
        security_tests=[],
        files=[
            RepositoryFile(
                path=SOURCE_PATH,
                size=len(encoded),
                lines=len(SOURCE.splitlines()),
                sha256=hashlib.sha256(encoded).hexdigest(),
                language="Solidity",
            )
        ],
    )


def _report(
    *,
    findings: list[Finding] | None = None,
    rejected: list[Finding] | None = None,
    completed: bool = True,
    cross_examinations: list[CandidateCrossExaminationDecision] | None = None,
) -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        run_id="synthetic-report-run",
        generated_at=NOW,
        completed=completed,
        incomplete_reasons=(
            [] if completed else ["The required model-review phase did not complete."]
        ),
        repository=_repository(),
        configuration_hash="b" * 64,
        model_configuration_hash="c" * 64,
        privacy={
            "profile": "STRICT_ZDR",
            "code_egress_enabled": False,
            "require_zdr": True,
            "redact_secrets": True,
            "store_raw_prompts": False,
            "store_raw_responses": False,
        },
        scanner_runs=[],
        usage=[],
        budget_usd=250,
        accounted_cost_usd=0,
        findings=findings or [],
        rejected_findings=rejected or [],
        quality_status=(
            AuditQualityStatus.COMPLETED if completed else AuditQualityStatus.INCOMPLETE
        ),
        cross_examination_decisions=cross_examinations or [],
        metadata={"configured_models": {}, "configured_fallbacks": {}},
    )


@pytest.mark.parametrize(
    ("status", "expected_label"),
    [
        (FindingStatus.CONFIRMED, "CONFIRMED"),
        (FindingStatus.STRONGLY_SUPPORTED, "STRONGLY SUPPORTED"),
    ],
)
def test_client_report_contains_complete_source_bound_finding_detail(
    status: FindingStatus,
    expected_label: str,
) -> None:
    report = _report(findings=[_finding(status)])

    rendered = render_client_markdown(report, {SOURCE_PATH: SOURCE})

    assert "# Corrovera Security Assurance Report" in rendered
    assert "Prepared by Corrovera Security · corrovera.com" in rendered
    assert "Generated by `mmaudit` · corrovera.ai" in rendered
    assert expected_label in rendered
    assert "Affected component" in rendered and "withdraw" in rendered
    assert "Violated property" in rendered
    assert f"{SOURCE_PATH}:{LOCATION_START}-{LOCATION_END}" in rendered
    assert "0005 |     function withdraw" in rendered
    assert "Impact" in rendered
    assert "Preconditions" in rendered
    assert "Reachable path" in rendered
    assert "Supporting evidence" in rendered
    assert "Dispute and falsifier outcome" in rendered
    assert "Remediation" in rendered
    assert "Safe verification test" in rendered
    assert "Residual uncertainty" in rendered
    assert "<script>fixture()" not in rendered
    assert "&lt;script&gt;fixture()&lt;/script&gt;" in rendered
    assert "Complete surface review table" not in rendered
    assert rendered == render_client_markdown(report, {SOURCE_PATH: SOURCE})


def test_client_report_makes_cross_examination_dispute_prominent() -> None:
    finding = _finding(FindingStatus.NEEDS_REVIEW)
    dispute = CandidateCrossExaminationDecision(
        candidate_id=finding.contributing_candidate_ids[0],
        request_id="cross-examination-1",
        reviewer_index=1,
        requested_model="synthetic/falsifier",
        returned_model="synthetic/falsifier",
        root_lineage="sha256:" + "d" * 64,
        verdict=CandidateCrossExaminationVerdict.DISPUTED,
        rationale="The guard may prevent the claimed incorrect transition.",
        contradictions=["The cited amount check is reachable before mutation."],
    )
    report = _report(findings=[finding], cross_examinations=[dispute])

    rendered = render_client_markdown(report, {SOURCE_PATH: SOURCE})

    assert "DISPUTED" in rendered
    assert "The guard may prevent the claimed incorrect transition" in rendered
    assert "not established as a confirmed vulnerability" in rendered


def test_client_report_retains_inconclusive_candidate_resolution() -> None:
    finding = _finding(FindingStatus.NEEDS_REVIEW)
    resolution = CandidateReproductionResolution(
        candidate_id=finding.contributing_candidate_ids[0],
        kind=ReproductionResolutionKind.INCONCLUSIVE,
        detail="The local reproduction could not establish or falsify the transition.",
    )
    report = _report(findings=[finding])

    rendered = render_client_markdown(
        report,
        {SOURCE_PATH: SOURCE},
        reproduction_resolutions=[resolution],
    )

    assert "INCONCLUSIVE" in rendered
    assert "could not establish or falsify" in rendered
    assert "not established as a confirmed vulnerability" in rendered


def test_forensic_report_retains_complete_rejected_finding_evidence() -> None:
    rejected = _finding(FindingStatus.REJECTED, finding_id="MMA-SYNTHETIC-REJECTED")
    report = _report(rejected=[rejected])

    rendered = render_forensic_markdown(report)

    assert "# Corrovera Forensic Evidence Report" in rendered
    assert "MMA-SYNTHETIC-REJECTED" in rendered
    assert rejected.impact in rendered
    assert rejected.preconditions[0] in rendered
    assert rejected.attack_path[0] in rendered
    assert rejected.evidence[0].description in rendered
    assert rejected.recommendation in rendered
    assert rejected.verification_test is not None
    assert rejected.verification_test.description in rendered
    assert rejected.false_positive_conditions[0] in rendered


def test_complete_no_findings_report_is_calibrated_without_claiming_security() -> None:
    rendered = render_client_markdown(_report(), {SOURCE_PATH: SOURCE})

    assert "No reportable findings were identified within the analyses that completed" in rendered
    assert "does not prove that the repository is secure" in rendered
    assert "This run is incomplete" not in rendered
    assert "Completed — zero findings" not in rendered


def test_incomplete_no_findings_report_uses_required_warning_on_first_screen() -> None:
    rendered = render_client_markdown(_report(completed=False), {SOURCE_PATH: SOURCE})

    required = (
        "No reportable findings were identified by the analyses that completed. "
        "This run is incomplete and does not support a conclusion about repository safety."
    )
    assert required in rendered
    assert rendered.index(required) < rendered.index("## Scope and source identity")
    assert "The required model-review phase did not complete" in rendered
    assert "Completed — zero findings" not in rendered


def test_client_excerpt_fails_closed_when_source_identity_changed() -> None:
    report = _report(findings=[_finding(FindingStatus.CONFIRMED)])

    with pytest.raises(ValueError, match=r"source.*hash|hash.*source"):
        render_client_markdown(report, {SOURCE_PATH: SOURCE + "// changed\n"})


def test_typed_forensic_projections_are_exact_and_secret_free() -> None:
    report = _report(findings=[_finding(FindingStatus.CONFIRMED)])

    findings = build_findings_artifact(report)
    coverage = build_coverage_artifact(report)
    model_execution = build_model_execution_artifact(report)

    assert findings.run_id == report.run_id
    assert findings.findings == report.findings
    assert findings.rejected_findings == report.rejected_findings
    assert coverage.run_id == report.run_id
    assert coverage.quality_gates == report.quality_gates
    assert model_execution.run_id == report.run_id
    assert model_execution.usage == report.usage
    assert model_execution.accounted_cost_usd == report.accounted_cost_usd
    serialized = "\n".join(
        artifact.model_dump_json() for artifact in (findings, coverage, model_execution)
    )
    assert "Authorization" not in serialized
    assert "OPENROUTER_API_KEY" not in serialized


def _coverage_metric(*, denominator: int) -> CoverageMetric:
    return CoverageMetric(
        numerator=0,
        denominator=denominator,
        population=denominator,
        percentage=0.0 if denominator else None,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.MODEL_REVIEW],
        failures=["Synthetic surface records remain unreviewed."],
        state=AnalysisState.NOT_ANALYZED,
        detail="Synthetic forensic-only surface inventory.",
    )


def test_large_surface_table_stays_in_forensic_report_only() -> None:
    surfaces = sorted(
        [
            ModelReviewSurface(
                surface_id=f"model-surface:{hashlib.sha256(str(index).encode()).hexdigest()}",
                kind=ModelReviewSurfaceKind.SOURCE_FILE,
                subject_id=f"source-{index:04d}",
                label=f"FORENSIC-ONLY-SURFACE-{index:04d}",
                critical=False,
            )
            for index in range(1_000)
        ],
        key=lambda item: item.surface_id,
    )
    by_kind = {
        kind: _coverage_metric(
            denominator=1_000 if kind is ModelReviewSurfaceKind.SOURCE_FILE else 0
        )
        for kind in ModelReviewSurfaceKind
    }
    model_coverage = ModelReviewCoverage(
        applicable=True,
        critical_classification_complete=True,
        surfaces=surfaces,
        overall=_coverage_metric(denominator=1_000),
        by_kind=by_kind,
        critical=_coverage_metric(denominator=0),
        critical_gate_passed=False,
        limitations=["Synthetic surface inventory is intentionally unreviewed."],
    )
    report = _report().model_copy(update={"model_review_coverage": model_coverage})

    client = render_client_markdown(report, {SOURCE_PATH: SOURCE})
    forensic = render_forensic_markdown(report)

    assert "FORENSIC-ONLY-SURFACE-0000" not in client
    assert "FORENSIC-ONLY-SURFACE-0999" not in client
    assert "FORENSIC-ONLY-SURFACE-0000" in forensic
    assert "FORENSIC-ONLY-SURFACE-0999" in forensic
