from __future__ import annotations

import pytest

from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.schemas import (
    AnalysisState,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    Evidence,
    FalsificationVerdict,
    FindingOriginKind,
    FindingStatus,
    QualityGateResult,
    Severity,
    VerificationVerdict,
)
from mmaudit.reporting.bundle import (
    CandidateTerminalState,
    FindingsArtifact,
    ForensicDisposition,
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
)
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.sarif import generate_report_sarif, generate_sarif
from mmaudit.reporting.status import (
    LEGACY_MINIMUM_FLOOR_LIMITATION,
    ReportStatusProjection,
    effective_report_status,
)
from tests.unit.test_client_forensic_reporting import (
    SOURCE,
    SOURCE_PATH,
    _candidate,
    _finding,
    _render_client,
    _report,
)
from tests.unit.test_client_forensic_reporting_adversarial import (
    _cross_examination,
    _falsification,
    _verification,
)
from tests.unit.test_run_status import (
    _assessment,
    _coverage,
    _typed_report_payload,
)


def test_legacy_no_floor_status_is_identical_across_every_canonical_report_leaf() -> None:
    report = _report()
    projection = effective_report_status(report)

    findings = build_findings_artifact(report)
    coverage = build_coverage_artifact(report)
    model_execution = build_model_execution_artifact(report)
    client = render_client_markdown(report, {})
    forensic = render_forensic_markdown(report)
    sarif = generate_report_sarif(report)
    sarif_properties = sarif["runs"][0]["properties"]

    assert projection.run_status is AuditRunStatus.INCOMPLETE
    assert projection.quality_status is AuditQualityStatus.INCOMPLETE
    assert not projection.completed
    assert projection.limitations == [LEGACY_MINIMUM_FLOOR_LIMITATION]
    for artifact in (findings, coverage, model_execution):
        assert artifact.run_status is projection.run_status
        assert artifact.quality_status is projection.quality_status
        assert artifact.completed is projection.completed
        assert artifact.quality_gates == projection.quality_gates
        assert artifact.limitations == projection.limitations
    for markdown in (client, forensic):
        assert "> **RUN STATUS: INCOMPLETE**" in markdown
        assert "Quality status: **incomplete**" in markdown
        assert LEGACY_MINIMUM_FLOOR_LIMITATION in markdown
    assert sarif_properties["runStatus"] == projection.run_status.value
    assert sarif_properties["qualityStatus"] == projection.quality_status.value
    assert sarif_properties["completed"] is projection.completed
    assert sarif_properties["qualityGates"] == [
        gate.model_dump(mode="json") for gate in projection.quality_gates
    ]
    assert sarif_properties["limitations"] == projection.limitations


def test_degraded_projection_preserves_a_passing_minimum_floor() -> None:
    floor = QualityGateResult(
        gate="minimum_analysis_floor",
        required=True,
        passed=True,
        detail="minimum floor completed before a separately authorized downgrade",
        state=AnalysisState.DETERMINISTIC,
    )

    projection = ReportStatusProjection(
        run_status=AuditRunStatus.DEGRADED,
        quality_status=AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
        completed=False,
        quality_gates=[floor],
        limitations=["a separate required integration remained unavailable"],
    )

    assert projection.quality_gates == [floor]
    assert projection.quality_gates[0].passed


def test_static_analyzer_fingerprint_does_not_require_a_model_candidate_record() -> None:
    fingerprint = "f" * 64
    finding = _finding(FindingStatus.NEEDS_REVIEW).model_copy(
        update={
            "origin_kind": FindingOriginKind.STATIC_ANALYZER,
            "contributing_candidate_ids": [fingerprint],
            "evidence": [
                Evidence(
                    type="scanner",
                    source="synthetic-scanner",
                    rule_id="synthetic-rule",
                    description="Synthetic scanner evidence retained for manifest validation.",
                    fingerprint=fingerprint,
                )
            ],
        }
    )
    report = _report(findings=[finding])

    artifact = build_findings_artifact(report)

    assert artifact.records[0].candidate_findings == []
    assert artifact.records[0].finding.contributing_candidate_ids == [fingerprint]


@pytest.mark.parametrize(
    ("verdict", "expected_disposition", "expected_level"),
    [
        (VerificationVerdict.REJECTED, ForensicDisposition.DISPUTED, "warning"),
        (
            VerificationVerdict.INSUFFICIENT_CONTEXT,
            ForensicDisposition.INCONCLUSIVE,
            "note",
        ),
    ],
)
def test_effective_finding_disposition_is_coherent_across_every_rendered_leaf(
    verdict: VerificationVerdict,
    expected_disposition: ForensicDisposition,
    expected_level: str,
) -> None:
    finding = _finding(FindingStatus.CONFIRMED)
    report = _report(findings=[finding]).model_copy(
        update={"verification_decisions": [_verification(verdict)]}
    )
    artifact = build_findings_artifact(report, candidates=[_candidate(finding)])

    client = _render_client(report, {SOURCE_PATH: SOURCE})
    compatibility = render_markdown(report, findings_artifact=artifact)
    forensic = render_forensic_markdown(report, findings_artifact=artifact)
    sarif = generate_report_sarif(report, findings_artifact=artifact)
    result = sarif["runs"][0]["results"][0]
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

    assert artifact.records[0].disposition is expected_disposition
    assert f"> **{expected_disposition.value}**" in client
    for rendered in (compatibility, forensic):
        assert f"**{expected_disposition.value.title()} finding" in rendered
        assert "**Confirmed finding**" not in rendered
        assert "1 confirmed" not in rendered
    assert result["level"] == expected_level
    assert result["properties"]["status"] == expected_disposition.value.lower()
    assert result["properties"]["effectiveDisposition"] == expected_disposition.value
    assert result["properties"]["rawFindingStatus"] == FindingStatus.CONFIRMED.value
    assert result["message"]["text"].startswith(f"[{expected_disposition.value}]")
    assert rule["properties"]["status"] == expected_disposition.value.lower()
    assert f"disposition/{expected_disposition.value.lower()}" in rule["properties"]["tags"]
    assert "status/confirmed" not in rule["properties"]["tags"]


@pytest.mark.parametrize(
    ("decision_kind", "expected_disposition", "expected_level"),
    [
        ("cross_examination", ForensicDisposition.INCONCLUSIVE, "note"),
        ("falsified", ForensicDisposition.DISPUTED, "warning"),
        ("falsifier_inconclusive", ForensicDisposition.INCONCLUSIVE, "note"),
    ],
)
def test_cross_exam_and_falsifier_dissent_is_coherent_across_every_rendered_leaf(
    decision_kind: str,
    expected_disposition: ForensicDisposition,
    expected_level: str,
) -> None:
    finding = _finding(FindingStatus.CONFIRMED)
    updates: dict[str, object]
    if decision_kind == "cross_examination":
        updates = {"cross_examination_decisions": [_cross_examination()]}
    else:
        verdict = (
            FalsificationVerdict.FALSIFIED
            if decision_kind == "falsified"
            else FalsificationVerdict.INCONCLUSIVE
        )
        updates = {"falsification_decisions": [_falsification(verdict)]}
    report = _report(findings=[finding]).model_copy(update=updates)
    artifact = build_findings_artifact(report, candidates=[_candidate(finding)])

    client = _render_client(report, {SOURCE_PATH: SOURCE})
    compatibility = render_markdown(report, findings_artifact=artifact)
    forensic = render_forensic_markdown(report, findings_artifact=artifact)
    sarif = generate_report_sarif(report, findings_artifact=artifact)
    result = sarif["runs"][0]["results"][0]

    assert artifact.records[0].disposition is expected_disposition
    assert f"> **{expected_disposition.value}**" in client
    for rendered in (compatibility, forensic):
        assert f"**{expected_disposition.value.title()} finding" in rendered
        assert "**Confirmed finding**" not in rendered
    assert result["level"] == expected_level
    assert result["properties"]["effectiveDisposition"] == expected_disposition.value
    assert result["properties"]["rawFindingStatus"] == FindingStatus.CONFIRMED.value


def test_artifact_aware_outputs_preserve_rejected_finding_handling() -> None:
    rejected = _finding(FindingStatus.REJECTED, finding_id="MMA-SYNTHETIC-REJECTED")
    report = _report(rejected=[rejected])
    artifact = build_findings_artifact(report, candidates=[_candidate(rejected)])

    compatibility = render_markdown(report, findings_artifact=artifact)
    forensic = render_forensic_markdown(report, findings_artifact=artifact)
    sarif = generate_report_sarif(report, findings_artifact=artifact)

    assert "**Rejected finding**" in compatibility
    assert "**Rejected finding**" in forensic
    assert sarif["runs"][0]["results"] == []


def test_artifact_aware_outputs_reject_a_mismatched_authority() -> None:
    finding = _finding(FindingStatus.CONFIRMED)
    report = _report(findings=[finding])
    artifact = build_findings_artifact(report, candidates=[_candidate(finding)])
    wrong_run = artifact.model_copy(update={"run_id": "different-run"})

    with pytest.raises(ValueError, match="findings artifact differs from the bound audit report"):
        render_markdown(report, findings_artifact=wrong_run)
    with pytest.raises(ValueError, match="findings artifact differs from the bound audit report"):
        render_forensic_markdown(report, findings_artifact=wrong_run)
    with pytest.raises(ValueError, match="findings artifact differs from the bound audit report"):
        generate_report_sarif(report, findings_artifact=wrong_run)
    with pytest.raises(ValueError, match="differs from the SARIF finding inventory"):
        generate_sarif([], findings_artifact=artifact)


def test_current_filtered_candidate_is_forensic_only_and_has_one_terminal_state() -> None:
    coverage = _coverage()
    floor = _assessment(coverage=coverage, required_model_roles=ANALYSIS_ROLES)
    finding = _finding(FindingStatus.STRONGLY_SUPPORTED).model_copy(
        update={"severity": Severity.HIGH}
    )
    payload = _typed_report_payload(
        floor=floor,
        scanner_runs=[],
        usage=[],
        coverage=coverage,
    )
    metadata = dict(payload["metadata"])
    metadata["severity_threshold"] = Severity.CRITICAL.value
    payload.update(
        {
            "repository": _report().repository,
            "findings": [],
            "filtered_findings": [finding],
            "verification_decisions": [_verification(VerificationVerdict.PLAUSIBLE)],
            "metadata": metadata,
        }
    )
    report = AuditReport.model_validate(payload)
    candidate = _candidate(finding)
    artifact = build_findings_artifact(report, candidates=[candidate])

    assert artifact.findings == []
    assert artifact.filtered_findings == [finding]
    assert artifact.candidate_findings == [candidate]
    assert artifact.verification_decisions == report.verification_decisions
    assert len(artifact.terminal_candidate_dispositions) == 1
    terminal = artifact.terminal_candidate_dispositions[0]
    assert terminal.candidate_id == candidate.candidate_id
    assert terminal.finding_id == finding.id
    assert terminal.group_id == finding.group_id
    assert terminal.state is CandidateTerminalState.FILTERED_BELOW_THRESHOLD
    assert terminal.reporting_severity_threshold is Severity.CRITICAL

    client = render_client_markdown(report, {SOURCE_PATH: SOURCE}, candidates=[candidate])
    forensic = render_forensic_markdown(report, findings_artifact=artifact)
    sarif = generate_report_sarif(report, findings_artifact=artifact)

    assert finding.title not in client
    assert "Findings filtered below the client reporting threshold" in forensic
    assert finding.id in forensic
    assert finding.title in forensic
    assert sarif["runs"][0]["results"] == []

    with pytest.raises(ValueError, match="terminal dispositions"):
        tampered = artifact.model_dump(mode="python")
        tampered["terminal_candidate_dispositions"] = []
        FindingsArtifact.model_validate(tampered)
