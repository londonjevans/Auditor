from __future__ import annotations

from mmaudit.models.schemas import (
    AnalysisState,
    AuditQualityStatus,
    AuditRunStatus,
    Evidence,
    FindingOriginKind,
    FindingStatus,
    QualityGateResult,
)
from mmaudit.reporting.bundle import (
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
)
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.markdown import render_forensic_markdown
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import (
    LEGACY_MINIMUM_FLOOR_LIMITATION,
    ReportStatusProjection,
    effective_report_status,
)
from tests.unit.test_client_forensic_reporting import _finding, _report


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
