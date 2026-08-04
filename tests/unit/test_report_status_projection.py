from __future__ import annotations

import pytest
from pydantic import ValidationError

from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    Evidence,
    FalsificationVerdict,
    FindingOriginKind,
    FindingStatus,
    LanguageCapabilityAssessment,
    LanguageCapabilityFileEvidence,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    QualityGateResult,
    Severity,
    VerificationVerdict,
)
from mmaudit.orchestration.coverage import generic_source_ingestion_coverage_metric
from mmaudit.reporting.bundle import (
    CandidateTerminalState,
    CoverageArtifact,
    FindingsArtifact,
    ForensicDisposition,
    ModelExecutionArtifact,
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
from tests.language_capability_support import (
    empty_language_capability,
    language_capability_for_files,
    matched_solidity_language_capability,
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


def _legacy_report_with_recorded_complete_assurance() -> AuditReport:
    assurance = MaximumAssuranceAssessment(
        requested=True,
        required=True,
        downgrade_allowed=False,
        downgraded=False,
        status=MaximumAssuranceStatus.COMPLETE,
        requirements=[
            MaximumAssuranceRequirement(
                engine="synthetic_legacy_clause",
                required=True,
                passed=True,
                blocking=False,
                state=AnalysisState.DETERMINISTIC,
                detail="The pre-capability record marked this synthetic clause as passing.",
            )
        ],
    )
    return _report().model_copy(
        update={
            "audit_profile": AuditProfile.MAXIMUM_ASSURANCE,
            "maximum_assurance": assurance,
        }
    )


def _reduced_generic_language_capability() -> LanguageCapabilityAssessment:
    return language_capability_for_files(
        LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW,
        (
            LanguageCapabilityFileEvidence(
                path="app.py",
                sha256="a" * 64,
                size=10,
                lines=1,
                language="Python",
            ),
        ),
    ).assessment


def _inconclusive_solidity_language_capability() -> LanguageCapabilityAssessment:
    return LanguageCapabilityAssessment(
        plugin_id="mmaudit.language.solidity-evm",
        requested_profile=LanguageCapabilityProfile.SOLIDITY_EVM,
        status=LanguageCapabilityStatus.INCONCLUSIVE,
        language_counts={},
        discovered_text_file_count=0,
        solidity_file_count=0,
        non_solidity_file_count=0,
        solidity_project_count=0,
        discovery_inventory_sha256="b" * 64,
        blocking_discovery_omissions=("repository: max_files reached",),
        evm_portfolio_applicable=False,
        evm_maximum_assurance_eligible=False,
        reduced_capability=False,
        limitations=("bounded discovery did not establish the requested capability",),
    )


def test_findings_artifact_versions_bind_language_capability_presence() -> None:
    finding = _finding(FindingStatus.CONFIRMED)
    capability = matched_solidity_language_capability(
        path=SOURCE_PATH,
        content=SOURCE.encode("utf-8"),
    ).assessment
    report = _report(findings=[finding]).model_copy(update={"language_capability": capability})

    current = build_findings_artifact(report, candidates=[_candidate(finding)])
    assert current.schema_version == "1.2"
    assert current.language_capability == capability
    missing_current = current.model_dump(mode="json")
    missing_current.pop("language_capability")
    with pytest.raises(ValidationError, match="requires typed language capability"):
        FindingsArtifact.model_validate(missing_current)

    legacy = build_findings_artifact(
        report,
        candidates=[_candidate(finding)],
        schema_version="1.1",
    )
    legacy_payload = legacy.model_dump(mode="json")
    assert "language_capability" not in legacy_payload
    assert FindingsArtifact.model_validate(legacy_payload) == legacy
    legacy_payload["language_capability"] = capability.model_dump(mode="json")
    with pytest.raises(ValidationError, match="legacy artifact cannot carry"):
        FindingsArtifact.model_validate(legacy_payload)


def test_model_execution_artifact_versions_bind_language_capability_presence() -> None:
    capability = matched_solidity_language_capability(
        path=SOURCE_PATH,
        content=SOURCE.encode("utf-8"),
    ).assessment
    report = _report().model_copy(update={"language_capability": capability})

    current = build_model_execution_artifact(report)
    assert current.schema_version == "1.2"
    assert current.language_capability == capability
    missing_current = current.model_dump(mode="json")
    missing_current.pop("language_capability")
    with pytest.raises(ValidationError, match="requires typed language capability"):
        ModelExecutionArtifact.model_validate(missing_current)

    legacy = build_model_execution_artifact(report, schema_version="1.1")
    legacy_payload = legacy.model_dump(mode="json")
    assert "language_capability" not in legacy_payload
    assert ModelExecutionArtifact.model_validate(legacy_payload) == legacy
    legacy_payload["language_capability"] = capability.model_dump(mode="json")
    with pytest.raises(ValidationError, match="legacy artifact cannot carry"):
        ModelExecutionArtifact.model_validate(legacy_payload)


def _detached_coverage_payload(
    capability: LanguageCapabilityAssessment | None,
    *,
    run_status: AuditRunStatus = AuditRunStatus.COMPLETE,
) -> dict[str, object]:
    completed = run_status is AuditRunStatus.COMPLETE
    reduced_generic = bool(
        capability is not None and capability.status is LanguageCapabilityStatus.REDUCED
    )
    return {
        "schema_version": "1.1",
        "run_id": "synthetic-detached-status",
        "scanner_only": False,
        "run_status": run_status,
        "quality_status": (
            AuditQualityStatus.COMPLETED
            if completed
            else AuditQualityStatus.COMPLETED_WITH_LIMITATIONS
        ),
        "completed": completed,
        "quality_gates": [
            QualityGateResult(
                gate="minimum_analysis_floor",
                required=True,
                passed=True,
                detail="synthetic minimum floor passed",
                state=AnalysisState.DETERMINISTIC,
            )
        ],
        "limitations": [] if completed else ["explicit reduced generic capability"],
        "language_capability": capability,
        "scope_assessment": None,
        "solidity_coverage": None,
        "model_review_coverage": None,
        "generic_source_coverage": (
            {
                "generic_source_files_ingested": generic_source_ingestion_coverage_metric(
                    capability.discovered_text_file_count
                )
            }
            if reduced_generic and capability is not None
            else None
        ),
    }


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
    assert projection.language_capability is None
    for artifact in (findings, coverage, model_execution):
        assert artifact.run_status is projection.run_status
        assert artifact.quality_status is projection.quality_status
        assert artifact.completed is projection.completed
        assert artifact.quality_gates == projection.quality_gates
        assert artifact.limitations == projection.limitations
        assert artifact.language_capability is projection.language_capability
    for markdown in (client, forensic):
        assert "> **RUN STATUS: INCOMPLETE**" in markdown
        assert "Quality status: **incomplete**" in markdown
        assert LEGACY_MINIMUM_FLOOR_LIMITATION in markdown
        assert "LANGUAGE CAPABILITY NOT RECORDED" in markdown
        assert "evidence-derived standard Solidity/EVM audit" not in markdown
        assert "For Solidity findings, model agreement" not in markdown
    assert sarif_properties["runStatus"] == projection.run_status.value
    assert sarif_properties["qualityStatus"] == projection.quality_status.value
    assert sarif_properties["completed"] is projection.completed
    assert sarif_properties["qualityGates"] == [
        gate.model_dump(mode="json") for gate in projection.quality_gates
    ]
    assert sarif_properties["limitations"] == projection.limitations
    assert sarif_properties["capabilityStatus"] == "NOT_RECORDED"
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["properties"]["capabilityStatus"] == "NOT_RECORDED"
    assert any(
        "Language capability evidence was not recorded" in notification["message"]["text"]
        for notification in invocation["toolExecutionNotifications"]
    )


def test_legacy_complete_assurance_is_rendered_only_as_unverified_in_markdown() -> None:
    report = _legacy_report_with_recorded_complete_assurance()

    client = render_client_markdown(report, {})
    compatibility = render_markdown(report)
    forensic = render_forensic_markdown(report)

    for rendered in (client, compatibility, forensic):
        assert "Maximum-assurance contract status: **COMPLETE**" not in rendered
        assert "ASSURANCE NOT ACHIEVED" in rendered
        assert "RUN STATUS: INCOMPLETE" in rendered
    for rendered in (compatibility, forensic):
        assert "Maximum-assurance evidence status: **UNVERIFIED LEGACY RECORD**" in rendered
        assert "Recorded legacy contract status (not an achieved claim): **COMPLETE**" in rendered
        assert "Effective report status: **INCOMPLETE**" in rendered
        assert "Unverified legacy maximum-assurance evidence" in rendered


def test_legacy_complete_assurance_is_wrapped_as_unverified_in_sarif() -> None:
    report = _legacy_report_with_recorded_complete_assurance()

    sarif = generate_report_sarif(report)
    run = sarif["runs"][0]
    assurance = run["properties"]["maximumAssurance"]
    invocation = run["invocations"][0]

    assert assurance["evidenceStatus"] == "UNVERIFIED_LEGACY"
    assert assurance["achieved"] is False
    assert assurance["effectiveRunStatus"] == "INCOMPLETE"
    assert assurance["recordedLegacyEvidence"]["status"] == "COMPLETE"
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["maximumAssuranceStatus"] == "UNVERIFIED_LEGACY"
    assert invocation["properties"]["maximumAssuranceAchieved"] is False
    assert invocation["properties"]["recordedLegacyMaximumAssuranceStatus"] == "COMPLETE"
    assert any(
        "legacy maximum-assurance evidence is unverified" in notification["message"]["text"]
        for notification in invocation["toolExecutionNotifications"]
    )
    with pytest.raises(ValueError, match="lacks matched Solidity/EVM capability"):
        generate_sarif([], maximum_assurance=report.maximum_assurance)


def test_sarif_rejects_complete_assurance_with_blocking_source_omission() -> None:
    report = _legacy_report_with_recorded_complete_assurance()
    assert report.maximum_assurance is not None
    capability = matched_solidity_language_capability().assessment.model_copy(
        update={"blocking_discovery_omissions": ("repository: max_files reached",)}
    )

    with pytest.raises(ValueError, match="lacks matched Solidity/EVM capability"):
        generate_sarif(
            [],
            maximum_assurance=report.maximum_assurance,
            language_capability=capability,
        )


@pytest.mark.parametrize(
    ("case", "capability", "expected_error"),
    [
        (
            "absent",
            None,
            "COMPLETE report projection requires coherent achieved language capability",
        ),
        (
            "mismatched",
            empty_language_capability(LanguageCapabilityProfile.SOLIDITY_EVM).assessment,
            "COMPLETE report projection requires coherent achieved language capability",
        ),
        (
            "inconclusive",
            _inconclusive_solidity_language_capability(),
            "COMPLETE report projection requires coherent achieved language capability",
        ),
        (
            "blocking-discovery-omission",
            matched_solidity_language_capability().assessment.model_copy(
                update={"blocking_discovery_omissions": ("repository: max_files reached",)}
            ),
            "COMPLETE report projection requires coherent achieved language capability",
        ),
        (
            "contradictory-achieved-capability",
            _reduced_generic_language_capability().model_copy(
                update={"achieved_profile": LanguageCapabilityProfile.SOLIDITY_EVM}
            ),
            "reduced generic-source-review evidence is inconsistent",
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_detached_complete_artifact_requires_coherent_achieved_language_capability(
    case: str,
    capability: LanguageCapabilityAssessment | None,
    expected_error: str,
) -> None:
    del case

    with pytest.raises(ValidationError, match=expected_error):
        CoverageArtifact.model_validate(_detached_coverage_payload(capability))


def test_detached_complete_artifact_accepts_matched_solidity_evm_capability() -> None:
    capability = matched_solidity_language_capability().assessment

    artifact = CoverageArtifact.model_validate(_detached_coverage_payload(capability))

    assert artifact.run_status is AuditRunStatus.COMPLETE
    assert artifact.completed
    assert artifact.language_capability == capability


def test_detached_complete_artifact_accepts_reduced_generic_capability() -> None:
    capability = _reduced_generic_language_capability()

    artifact = CoverageArtifact.model_validate(_detached_coverage_payload(capability))

    assert artifact.run_status is AuditRunStatus.COMPLETE
    assert artifact.completed
    assert artifact.language_capability == capability
    assert artifact.language_capability.reduced_capability
    assert not artifact.language_capability.evm_portfolio_applicable
    assert not artifact.language_capability.evm_maximum_assurance_eligible


def test_detached_degraded_artifact_preserves_reduced_generic_capability() -> None:
    capability = _reduced_generic_language_capability()

    artifact = CoverageArtifact.model_validate(
        _detached_coverage_payload(capability, run_status=AuditRunStatus.DEGRADED)
    )

    assert artifact.run_status is AuditRunStatus.DEGRADED
    assert not artifact.completed
    assert artifact.language_capability == capability


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
        language_capability=None,
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
