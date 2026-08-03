from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from mmaudit.models.schemas import (
    AnalysisState,
    AuditQualityStatus,
    AuditReport,
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationVerdict,
    CandidateFinding,
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
from mmaudit.reporting.status import effective_report_status
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


def _candidate(finding: Finding, candidate_id: str | None = None) -> CandidateFinding:
    """Build explicit retained candidate evidence for a synthetic final finding."""

    assert finding.verification_test is not None
    resolved_candidate_id = candidate_id or finding.contributing_candidate_ids[0]
    return CandidateFinding(
        candidate_id=resolved_candidate_id,
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
        model_family=f"synthetic-{resolved_candidate_id}",
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


def _render_client(
    report: AuditReport,
    source_contents: dict[str, str],
    *,
    reproduction_resolutions: list[CandidateReproductionResolution] | None = None,
) -> str:
    """Render with the complete explicit candidate inventory retained by the fixture."""

    findings = [*report.findings, *report.rejected_findings]
    candidates = [
        _candidate(finding, candidate_id)
        for finding in findings
        for candidate_id in finding.contributing_candidate_ids
    ]
    return render_client_markdown(
        report,
        source_contents,
        candidates=candidates,
        reproduction_resolutions=reproduction_resolutions or [],
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

    rendered = _render_client(report, {SOURCE_PATH: SOURCE})

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
    assert rendered == _render_client(report, {SOURCE_PATH: SOURCE})


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

    rendered = _render_client(report, {SOURCE_PATH: SOURCE})

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

    rendered = _render_client(
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


def test_legacy_completed_flag_cannot_project_a_complete_no_findings_run() -> None:
    rendered = _render_client(_report(), {SOURCE_PATH: SOURCE})

    assert "No reportable findings were identified by the analyses that completed" in rendered
    assert "This run is incomplete and does not support a conclusion" in rendered
    assert "> **RUN STATUS: INCOMPLETE**" in rendered
    assert "Completed — zero findings" not in rendered


def test_source_tree_identity_is_deterministic_without_a_git_commit() -> None:
    additional_content = "contract AdditionalSyntheticSource {}\n"
    additional = RepositoryFile(
        path="src/AdditionalSyntheticSource.sol",
        size=len(additional_content.encode()),
        lines=1,
        sha256=hashlib.sha256(additional_content.encode()).hexdigest(),
        language="Solidity",
    )
    repository = _repository().model_copy(
        update={"git_commit": None, "files": [additional, *_repository().files]}
    )
    reversed_repository = repository.model_copy(update={"files": list(reversed(repository.files))})
    first = _report().model_copy(update={"repository": repository})
    second = _report().model_copy(update={"repository": reversed_repository})
    projection = [
        {"path": item.path, "sha256": item.sha256, "size": item.size}
        for item in sorted(repository.files, key=lambda candidate: candidate.path)
    ]
    expected = hashlib.sha256(
        json.dumps(
            projection,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()

    first_rendered = _render_client(first, {})
    second_rendered = _render_client(second, {})

    assert first_rendered == second_rendered
    assert "Source commit: `not available`" in first_rendered
    assert f"Source-tree SHA-256: `{expected}`" in first_rendered


def test_incomplete_no_findings_report_uses_required_warning_on_first_screen() -> None:
    rendered = _render_client(_report(completed=False), {SOURCE_PATH: SOURCE})

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
        _render_client(report, {SOURCE_PATH: SOURCE + "// changed\n"})


def test_typed_forensic_projections_are_exact_and_secret_free() -> None:
    report = _report(findings=[_finding(FindingStatus.CONFIRMED)])
    projection = effective_report_status(report)

    findings = build_findings_artifact(report, candidates=[_candidate(report.findings[0])])
    coverage = build_coverage_artifact(report)
    model_execution = build_model_execution_artifact(report)

    assert findings.run_id == report.run_id
    assert findings.findings == report.findings
    assert findings.rejected_findings == report.rejected_findings
    assert coverage.run_id == report.run_id
    assert model_execution.run_id == report.run_id
    assert model_execution.usage == report.usage
    assert model_execution.accounted_cost_usd == report.accounted_cost_usd
    for artifact in (findings, coverage, model_execution):
        assert artifact.run_status is projection.run_status
        assert artifact.quality_status is projection.quality_status
        assert artifact.completed is projection.completed
        assert artifact.quality_gates == projection.quality_gates
        assert artifact.limitations == projection.limitations
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


def _large_model_coverage() -> ModelReviewCoverage:
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
    return ModelReviewCoverage(
        applicable=True,
        critical_classification_complete=True,
        surfaces=surfaces,
        overall=_coverage_metric(denominator=1_000),
        by_kind=by_kind,
        critical=_coverage_metric(denominator=0),
        critical_gate_passed=False,
        limitations=["Synthetic surface inventory is intentionally unreviewed."],
    )


def test_large_surface_table_stays_in_forensic_report_only() -> None:
    report = _report().model_copy(update={"model_review_coverage": _large_model_coverage()})

    client = _render_client(report, {SOURCE_PATH: SOURCE})
    forensic = render_forensic_markdown(report)

    assert "FORENSIC-ONLY-SURFACE-0000" not in client
    assert "FORENSIC-ONLY-SURFACE-0999" not in client
    assert "FORENSIC-ONLY-SURFACE-0000" in forensic
    assert "FORENSIC-ONLY-SURFACE-0999" in forensic


def test_representative_client_report_stays_within_page_equivalent_budget() -> None:
    findings = [
        _finding(
            FindingStatus.STRONGLY_SUPPORTED,
            finding_id=f"MMA-SYNTHETIC-{index:03d}",
        ).model_copy(update={"contributing_candidate_ids": [f"candidate-synthetic-{index:03d}"]})
        for index in range(8)
    ]
    report = _report(findings=findings).model_copy(
        update={"model_review_coverage": _large_model_coverage()}
    )

    client = _render_client(report, {SOURCE_PATH: SOURCE})
    client_lines = client.splitlines()
    required_sections = [
        "# Corrovera Security Assurance Report",
        "## Executive risk narrative",
        "## Scope and source identity",
        "## Methodology summary",
        "## Analysis actually completed",
        "## Finding summary",
        "## Priority remediation roadmap",
        "## Detailed findings",
        "## Residual risk and limitations",
        "## Conclusion",
    ]

    assert [client_lines.index(section) for section in required_sections] == sorted(
        client_lines.index(section) for section in required_sections
    )
    assert 10 * 45 <= len(client_lines) <= 20 * 45
    assert len(client.encode()) <= 64_000
    assert "FORENSIC-ONLY-SURFACE-0000" not in client
    assert "FORENSIC-ONLY-SURFACE-0999" not in client
