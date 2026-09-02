"""SARIF 2.1.0 generation for surviving security findings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from mmaudit.models.actor_model import ActorRemediationFocus, actor_remediation_guidance
from mmaudit.models.schemas import (
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    Finding,
    FindingStatus,
    KnownIssueDisposition,
    KnownIssueTaxonomyCoverage,
    LanguageCapabilityAssessment,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
    MaximumAssuranceAssessment,
    MaximumAssuranceStatus,
    QualityGateResult,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.reporting.bundle import (
    FindingsArtifact,
    ForensicDisposition,
    ForensicFindingRecord,
)
from mmaudit.reporting.status import effective_report_status, quality_status_for_run_status

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}


def _taxonomy_run_properties(
    coverage: KnownIssueTaxonomyCoverage,
) -> dict[str, Any]:
    """Project bounded taxonomy coverage metadata without creating SARIF findings."""

    reviewed_count = sum(
        item.disposition is KnownIssueDisposition.REVIEWED for item in coverage.dispositions
    )
    not_applicable_count = sum(
        item.disposition is KnownIssueDisposition.NOT_APPLICABLE for item in coverage.dispositions
    )
    gap_count = sum(item.disposition is KnownIssueDisposition.GAP for item in coverage.dispositions)
    return {
        "schemaVersion": coverage.schema_version,
        "taxonomyVersion": coverage.corpus.taxonomy_version,
        "corpusSha256": coverage.corpus.corpus_sha256,
        "corpusRawSha256": coverage.corpus_raw_sha256,
        "coverageSha256": coverage.coverage_sha256,
        "findingAuthority": False,
        "profileClassificationComplete": bool(
            coverage.profile_assessment is not None
            and coverage.profile_assessment.classification_complete
        ),
        "overall": {
            "numerator": coverage.overall.numerator,
            "denominator": coverage.overall.denominator,
            "population": coverage.overall.population,
            "percentage": coverage.overall.percentage,
        },
        "critical": {
            "numerator": coverage.critical.numerator,
            "denominator": coverage.critical.denominator,
            "population": coverage.critical.population,
            "percentage": coverage.critical.percentage,
        },
        "dispositions": {
            "reviewed": reviewed_count,
            "notApplicable": not_applicable_count,
            "gap": gap_count,
        },
        "criticalGapIds": list(coverage.critical_gap_ids),
        "criticalGatePassed": coverage.critical_gate_passed,
        "limitationCount": len(coverage.limitations),
    }


def _taxonomy_notification(
    coverage: KnownIssueTaxonomyCoverage,
) -> dict[str, Any] | None:
    gap_count = sum(item.disposition is KnownIssueDisposition.GAP for item in coverage.dispositions)
    if not gap_count and coverage.critical_gate_passed:
        return None
    critical_ids = coverage.critical_gap_ids[:20]
    critical_detail = (
        " Critical GAPs: "
        + ", ".join(critical_ids)
        + (
            f", +{len(coverage.critical_gap_ids) - len(critical_ids)} retained."
            if len(coverage.critical_gap_ids) > len(critical_ids)
            else "."
        )
        if critical_ids
        else (
            " The critical taxonomy gate is not passed."
            if not coverage.critical_gate_passed
            else ""
        )
    )
    message_text = (
        f"Known-issue taxonomy coverage retains {gap_count} GAP disposition(s)."
        f"{critical_detail} GAPs are absent review evidence, not findings."
        if gap_count
        else (
            "Known-issue taxonomy critical coverage gate is not passed. This is incomplete "
            "review coverage, not a finding."
        )
    )
    return {
        "level": "warning" if not coverage.critical_gate_passed else "note",
        "message": {"text": message_text},
        "properties": {
            "findingAuthority": False,
            "gapCount": gap_count,
            "criticalGapCount": len(coverage.critical_gap_ids),
        },
    }


def _validated_artifact_for_findings(
    findings: list[Finding],
    artifact: FindingsArtifact | None,
) -> FindingsArtifact | None:
    if artifact is None:
        return None
    artifact = FindingsArtifact.model_validate(artifact.model_dump(mode="python"))
    if artifact.findings != findings:
        raise ValueError("findings artifact differs from the SARIF finding inventory")
    return artifact


def _record_map(
    artifact: FindingsArtifact | None,
) -> dict[str, ForensicFindingRecord]:
    if artifact is None:
        return {}
    return {record.finding_id: record for record in artifact.records[: len(artifact.findings)]}


def _effective_status(
    finding: Finding,
    record: ForensicFindingRecord | None,
) -> str:
    if record is None:
        return finding.status.value
    return record.disposition.value.lower()


def _result_level(
    finding: Finding,
    record: ForensicFindingRecord | None,
) -> str:
    if record is not None:
        if record.disposition is ForensicDisposition.INCONCLUSIVE:
            return "note"
        if record.disposition is ForensicDisposition.DISPUTED:
            return "warning"
    if finding.status is FindingStatus.NEEDS_REVIEW:
        return "note"
    return _LEVEL[finding.severity]


def _execution_provenance_sha256s(finding: Finding) -> list[str]:
    return sorted({item.provenance_sha256 for item in finding.execution_provenance})


def _origin_properties(finding: Finding) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "findingOrigin": finding.origin_kind.value,
        "executionProvenanceSha256s": _execution_provenance_sha256s(finding),
    }
    if finding.group_id is not None:
        properties["groupId"] = finding.group_id
    if finding.actor_assessment is not None:
        actor = finding.actor_assessment
        properties["actorModel"] = {
            "inputState": actor.input_state.value,
            "disposition": actor.disposition.value,
            "roleId": actor.role_id,
            "severityBasis": actor.severity_basis,
            "harmedPartyDisposition": (
                actor.harmed_party_disposition.value
                if actor.harmed_party_disposition is not None
                else None
            ),
            "harmedPartyId": actor.harmed_party_id,
            "baselineFindingSha256": actor.baseline_finding_sha256,
            "originalSeverity": actor.original_severity.value,
            "calibratedSeverity": actor.calibrated_severity.value,
            "likelihoodAdjustment": actor.likelihood_adjustment.value,
            "remediationFocus": actor.remediation_focus.value,
            "remediationGuidance": actor_remediation_guidance(actor.remediation_focus),
            "holderFeeRevenueExposure": (
                actor.holder_fee_revenue_exposure.value
                if actor.holder_fee_revenue_exposure is not None
                else None
            ),
            "holderProtocolFailureLoss": (
                actor.holder_protocol_failure_loss.value
                if actor.holder_protocol_failure_loss is not None
                else None
            ),
            "concentratedWithRoleIds": list(actor.concentrated_with_role_ids),
            "requiredConcentratedRoleIds": list(actor.required_concentrated_role_ids),
            "relevantEconomicExposures": [
                value.value for value in actor.relevant_economic_exposures
            ],
            "plausibilityEvidenceReferenceIds": list(actor.plausibility_evidence_reference_ids),
            "assessmentSha256": actor.assessment_sha256,
            "limitation": actor.limitation,
        }
    return properties


def _origin_fingerprint(finding: Finding) -> str:
    payload = {
        "finding_id": finding.id,
        "group_id": finding.group_id,
        "origin_kind": finding.origin_kind.value,
        "execution_provenance_sha256s": _execution_provenance_sha256s(finding),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _ordinary_legitimate_behavior(finding: Finding) -> bool:
    assessment = finding.actor_assessment
    return bool(
        assessment is not None
        and assessment.remediation_focus is ActorRemediationFocus.LEGITIMATE_STATE_TRANSITION
    )


def _sarif_title(finding: Finding) -> str:
    return (
        "Ordinary legitimate behavior finding"
        if _ordinary_legitimate_behavior(finding)
        else finding.title
    )


def _sarif_remediation(finding: Finding) -> str:
    assessment = finding.actor_assessment
    if assessment is None or not _ordinary_legitimate_behavior(finding):
        return finding.recommendation
    return actor_remediation_guidance(assessment.remediation_focus)


def _sarif_summary(finding: Finding) -> str:
    if not _ordinary_legitimate_behavior(finding):
        return finding.summary
    return (
        "The calibrated actor context, citing operator evidence, classifies this as an ordinary "
        "authorized state transition whose safety properties and affected-party protections "
        "require defensive validation."
    )


def _scanner_execution_record(run: ScannerRun) -> dict[str, Any]:
    """Return a content-free SARIF projection of one typed scanner outcome."""

    return {
        "scanner": run.scanner,
        "status": run.status.value,
        "executionEvidence": run.execution_evidence.value,
        "version": run.version,
        "findingCount": len(run.findings),
        "processExitCode": run.process_exit_code,
        "machineOutputValidated": run.machine_output_validated,
        "operatorPreparationStep": run.operator_preparation_step,
        "privateStderrPath": run.private_stderr_path,
        "privateStderrSha256": run.private_stderr_sha256,
        "privateStderrBytes": run.private_stderr_bytes,
    }


def _scanner_execution_notification(run: ScannerRun) -> dict[str, Any] | None:
    if run.status is ScannerStatus.SUCCESS:
        return None
    if run.status is ScannerStatus.NOT_APPLICABLE:
        message = f"{run.scanner}: scanner was not applicable to the audited scope"
        level = "note"
    elif run.status is ScannerStatus.UNMET_PREREQUISITE:
        message = (
            f"{run.scanner}: scanner prerequisite is unmet; operator preparation step: "
            f"{run.operator_preparation_step}"
        )
        level = "warning"
    else:
        message = f"{run.scanner}: scanner ended with status {run.status.value}"
        level = (
            "error"
            if run.status
            in {ScannerStatus.FAILED, ScannerStatus.SILENT_FAILURE, ScannerStatus.TIMED_OUT}
            else "warning"
        )
    return {
        "level": level,
        "message": {"text": message},
        "properties": {
            "scanner": run.scanner,
            "status": run.status.value,
            "operatorPreparationStep": run.operator_preparation_step,
            "privateStderrPath": run.private_stderr_path,
        },
    }


def _is_unverified_legacy_assurance_projection(
    *,
    maximum_assurance: MaximumAssuranceAssessment | None,
    language_capability: LanguageCapabilityAssessment | None,
    run_status: AuditRunStatus | None,
    quality_status: AuditQualityStatus | None,
    completed: bool | None,
) -> bool:
    """Identify an explicitly fail-closed projection of pre-capability evidence."""

    if (
        maximum_assurance is None
        or language_capability is not None
        or run_status not in {AuditRunStatus.INCOMPLETE, AuditRunStatus.FAILED}
    ):
        return False
    return completed is False and quality_status is quality_status_for_run_status(run_status)


def generate_sarif(
    findings: list[Finding],
    *,
    findings_artifact: FindingsArtifact | None = None,
    scanner_runs: Sequence[ScannerRun] = (),
    maximum_assurance: MaximumAssuranceAssessment | None = None,
    language_capability: LanguageCapabilityAssessment | None = None,
    taxonomy_coverage: KnownIssueTaxonomyCoverage | None = None,
    run_status: AuditRunStatus | None = None,
    quality_status: AuditQualityStatus | None = None,
    completed: bool | None = None,
    incomplete_reasons: Sequence[str] = (),
    quality_gates: Sequence[QualityGateResult] = (),
) -> dict[str, Any]:
    findings_artifact = _validated_artifact_for_findings(findings, findings_artifact)
    if taxonomy_coverage is not None:
        taxonomy_coverage = KnownIssueTaxonomyCoverage.model_validate(
            taxonomy_coverage.model_dump(mode="python")
        )
    artifact_records = _record_map(findings_artifact)
    if findings_artifact is not None:
        if run_status is not None and run_status is not findings_artifact.run_status:
            raise ValueError("SARIF run status conflicts with the findings artifact")
        if quality_status is not None and quality_status is not findings_artifact.quality_status:
            raise ValueError("SARIF quality status conflicts with the findings artifact")
        if completed is not None and completed is not findings_artifact.completed:
            raise ValueError("SARIF completion conflicts with the findings artifact")
        if incomplete_reasons and list(incomplete_reasons) != findings_artifact.limitations:
            raise ValueError("SARIF limitations conflict with the findings artifact")
        if quality_gates and list(quality_gates) != findings_artifact.quality_gates:
            raise ValueError("SARIF quality gates conflict with the findings artifact")
        run_status = findings_artifact.run_status
        quality_status = findings_artifact.quality_status
        completed = findings_artifact.completed
        incomplete_reasons = findings_artifact.limitations
        quality_gates = findings_artifact.quality_gates
    if run_status is not None:
        expected_completed = run_status is AuditRunStatus.COMPLETE
        expected_quality = quality_status_for_run_status(run_status)
        if completed is not None and completed != expected_completed:
            raise ValueError("SARIF completion conflicts with the typed run status")
        if quality_status is not None and quality_status is not expected_quality:
            raise ValueError("SARIF quality status conflicts with the typed run status")
        if run_status is not AuditRunStatus.COMPLETE and not incomplete_reasons:
            raise ValueError("non-complete SARIF requires a prominent incomplete reason")
    elif completed is not None and quality_status is not None:
        completed_quality = quality_status is AuditQualityStatus.COMPLETED
        if completed != completed_quality:
            raise ValueError("SARIF completion conflicts with the quality status")
    if (
        language_capability is not None
        and language_capability.status
        in {
            LanguageCapabilityStatus.MISMATCH,
            LanguageCapabilityStatus.INCONCLUSIVE,
        }
        and (
            run_status is AuditRunStatus.COMPLETE
            or completed is True
            or quality_status is AuditQualityStatus.COMPLETED
        )
    ):
        raise ValueError("SARIF completion conflicts with unachieved language capability")
    unverified_legacy_assurance = _is_unverified_legacy_assurance_projection(
        maximum_assurance=maximum_assurance,
        language_capability=language_capability,
        run_status=run_status,
        quality_status=quality_status,
        completed=completed,
    )
    if (
        maximum_assurance is not None
        and maximum_assurance.status is MaximumAssuranceStatus.COMPLETE
        and (
            language_capability is None
            or language_capability.status is not LanguageCapabilityStatus.MATCHED
            or language_capability.achieved_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
            or not language_capability.evm_maximum_assurance_eligible
            or bool(language_capability.blocking_discovery_omissions)
        )
        and not unverified_legacy_assurance
    ):
        raise ValueError("SARIF maximum-assurance completion lacks matched Solidity/EVM capability")

    included = []
    for finding in findings:
        record = artifact_records.get(finding.id)
        retained = (
            record.disposition is not ForensicDisposition.REJECTED
            if record is not None
            else finding.status is not FindingStatus.REJECTED
        )
        if retained and finding.location_validation.valid:
            included.append(finding)
    rules = []
    results = []
    for finding in included:
        record = artifact_records.get(finding.id)
        effective_status = _effective_status(finding, record)
        tags = [
            *finding.cwe,
            *finding.owasp,
            f"status/{effective_status}",
            f"origin/{finding.origin_kind.value}",
        ]
        if record is not None:
            tags.extend(
                (
                    f"disposition/{record.disposition.value.lower()}",
                    f"raw-status/{finding.status.value}",
                )
            )
        origin_properties = _origin_properties(finding)
        ordinary_behavior = _ordinary_legitimate_behavior(finding)
        effective_remediation = _sarif_remediation(finding)
        disposition_properties: dict[str, Any] = (
            {
                "effectiveDisposition": record.disposition.value,
                "rawFindingStatus": finding.status.value,
            }
            if record is not None
            else {}
        )
        rules.append(
            {
                "id": finding.id,
                "name": finding.id.replace("-", "_"),
                "shortDescription": {"text": _sarif_title(finding)},
                "fullDescription": {"text": _sarif_summary(finding)},
                "help": {
                    "text": effective_remediation,
                },
                "properties": {
                    "tags": tags,
                    "security-severity": f"{_security_score(finding):.1f}",
                    "confidence": finding.confidence,
                    "status": effective_status,
                    **disposition_properties,
                    **origin_properties,
                },
            }
        )
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": quote(location.path, safe="/-._~"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": location.start_line,
                        "endLine": location.end_line,
                    },
                },
                **(
                    {"logicalLocations": [{"name": location.symbol, "kind": "function"}]}
                    if location.symbol
                    else {}
                ),
            }
            for location in finding.locations
        ]
        result_properties: dict[str, Any] = {
            "confidence": finding.confidence,
            "status": effective_status,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            **disposition_properties,
            **origin_properties,
            **(
                {
                    "submittedModelTitle": finding.title,
                    "submittedModelSummary": finding.summary,
                    "submittedModelImpact": finding.impact,
                    "submittedModelPath": list(finding.attack_path),
                    "submittedModelRecommendation": finding.recommendation,
                    "submittedModelFramingSuperseded": True,
                }
                if ordinary_behavior
                else {}
            ),
        }
        results.append(
            {
                "ruleId": finding.id,
                "level": _result_level(finding, record),
                "message": {
                    "text": (
                        f"[{record.disposition.value if record is not None else finding.status.value}] "
                        f"[{finding.origin_kind.value}] "
                        f"{_sarif_summary(finding)} "
                        f"Remediation: {effective_remediation}"
                    )
                },
                "locations": locations,
                "partialFingerprints": {
                    "primaryLocationLineHash": finding.id,
                    "mmaudit/v1": finding.location_validation.content_hash or finding.id,
                    "mmaudit/origin/v1": _origin_fingerprint(finding),
                },
                "properties": result_properties,
            }
        )
    maximum_assurance_properties: dict[str, Any] | None
    if maximum_assurance is None:
        maximum_assurance_properties = None
    elif unverified_legacy_assurance:
        assert run_status is not None
        maximum_assurance_properties = {
            "evidenceStatus": "UNVERIFIED_LEGACY",
            "achieved": False,
            "effectiveRunStatus": run_status.value,
            "recordedLegacyEvidence": maximum_assurance.model_dump(mode="json"),
        }
    else:
        maximum_assurance_properties = maximum_assurance.model_dump(mode="json")
    run_properties: dict[str, Any] = {
        "maximumAssurance": maximum_assurance_properties,
        "scannerExecutions": [
            _scanner_execution_record(run)
            for run in sorted(scanner_runs, key=lambda item: item.scanner)
        ],
    }
    if language_capability is not None:
        run_properties.update(
            {
                "languageCapability": language_capability.model_dump(mode="json"),
                "capabilityProfile": language_capability.requested_profile.value,
                "achievedCapabilityProfile": (
                    language_capability.achieved_profile.value
                    if language_capability.achieved_profile is not None
                    else None
                ),
                "capabilityStatus": language_capability.status.value,
                "reducedCapability": language_capability.reduced_capability,
            }
        )
    if taxonomy_coverage is not None:
        run_properties["knownIssueTaxonomyCoverage"] = _taxonomy_run_properties(taxonomy_coverage)
    if run_status is not None:
        run_properties["runStatus"] = run_status.value
    if quality_status is not None:
        run_properties["qualityStatus"] = quality_status.value
    if completed is not None:
        run_properties["completed"] = completed
    if run_status is not None or incomplete_reasons:
        run_properties["limitations"] = list(incomplete_reasons)
    if run_status is not None or quality_gates:
        run_properties["qualityGates"] = [gate.model_dump(mode="json") for gate in quality_gates]

    invocation: dict[str, Any] | None = None
    run_evidence_supplied = any(
        (
            run_status is not None,
            quality_status is not None,
            completed is not None,
            bool(incomplete_reasons),
            bool(quality_gates),
            bool(scanner_runs),
            language_capability is not None,
            taxonomy_coverage is not None,
        )
    )
    if run_evidence_supplied:
        invocation_properties: dict[str, Any] = {}
        if run_status is not None:
            invocation_properties["runStatus"] = run_status.value
        if quality_status is not None:
            invocation_properties["qualityStatus"] = quality_status.value
        if completed is not None:
            invocation_properties["completed"] = completed
        if language_capability is not None:
            invocation_properties.update(
                {
                    "capabilityProfile": language_capability.requested_profile.value,
                    "achievedCapabilityProfile": (
                        language_capability.achieved_profile.value
                        if language_capability.achieved_profile is not None
                        else None
                    ),
                    "capabilityStatus": language_capability.status.value,
                    "reducedCapability": language_capability.reduced_capability,
                }
            )
        if taxonomy_coverage is not None:
            invocation_properties["knownIssueTaxonomyCoverage"] = {
                "overallNumerator": taxonomy_coverage.overall.numerator,
                "overallDenominator": taxonomy_coverage.overall.denominator,
                "criticalNumerator": taxonomy_coverage.critical.numerator,
                "criticalDenominator": taxonomy_coverage.critical.denominator,
                "criticalGapCount": len(taxonomy_coverage.critical_gap_ids),
                "criticalGatePassed": taxonomy_coverage.critical_gate_passed,
                "findingAuthority": False,
            }
        invocation = {
            "executionSuccessful": (
                run_status is AuditRunStatus.COMPLETE
                if run_status is not None
                else (
                    completed
                    if completed is not None
                    else (
                        quality_status is AuditQualityStatus.COMPLETED
                        if quality_status is not None
                        else (
                            any(run.status is ScannerStatus.SUCCESS for run in scanner_runs)
                            and all(not run.status.is_failure for run in scanner_runs)
                        )
                    )
                )
            ),
            "properties": invocation_properties,
            "toolExecutionNotifications": [
                {
                    "level": (
                        "error"
                        if run_status in {AuditRunStatus.INCOMPLETE, AuditRunStatus.FAILED}
                        else "warning"
                    ),
                    "message": {"text": reason},
                }
                for reason in incomplete_reasons
            ],
        }
        invocation["toolExecutionNotifications"].extend(
            notification
            for run in sorted(scanner_runs, key=lambda item: item.scanner)
            if (notification := _scanner_execution_notification(run)) is not None
        )
        if taxonomy_coverage is not None:
            taxonomy_notification = _taxonomy_notification(taxonomy_coverage)
            if taxonomy_notification is not None:
                invocation["toolExecutionNotifications"].append(taxonomy_notification)
        if language_capability is not None and language_capability.status in {
            LanguageCapabilityStatus.MISMATCH,
            LanguageCapabilityStatus.INCONCLUSIVE,
        }:
            invocation["toolExecutionNotifications"].append(
                {
                    "level": "error",
                    "message": {
                        "text": (
                            "Requested language capability was not established; no EVM "
                            "assurance is claimed."
                        )
                    },
                }
            )
        if maximum_assurance is not None:
            if unverified_legacy_assurance:
                assert run_status is not None
                invocation_properties.update(
                    {
                        "maximumAssuranceStatus": "UNVERIFIED_LEGACY",
                        "maximumAssuranceAchieved": False,
                        "recordedLegacyMaximumAssuranceStatus": (maximum_assurance.status.value),
                    }
                )
                invocation["toolExecutionNotifications"].append(
                    {
                        "level": "warning",
                        "message": {
                            "text": (
                                "Recorded legacy maximum-assurance evidence is unverified; "
                                f"effective run status is {run_status.value}, and no "
                                "maximum assurance is achieved."
                            )
                        },
                    }
                )
            else:
                invocation_properties["maximumAssuranceStatus"] = maximum_assurance.status.value
                invocation_properties["downgraded"] = maximum_assurance.downgraded
                invocation["toolExecutionNotifications"].extend(
                    {
                        "level": "warning",
                        "message": {"text": reason},
                    }
                    for reason in maximum_assurance.downgrade_reasons
                )
    elif maximum_assurance is not None:
        invocation = {
            "executionSuccessful": maximum_assurance.status.value == "COMPLETE",
            "properties": {
                "maximumAssuranceStatus": maximum_assurance.status.value,
                "downgraded": maximum_assurance.downgraded,
            },
            "toolExecutionNotifications": [
                {
                    "level": "warning",
                    "message": {"text": reason},
                }
                for reason in maximum_assurance.downgrade_reasons
            ],
        }

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mmaudit",
                        "informationUri": "https://github.com/mmaudit/mmaudit",
                        "semanticVersion": "0.1.0",
                        "rules": rules,
                    }
                },
                "properties": run_properties,
                "invocations": [invocation] if invocation is not None else [],
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
                "results": results,
            }
        ],
    }


def generate_report_sarif(
    report: AuditReport,
    *,
    findings_artifact: FindingsArtifact | None = None,
) -> dict[str, Any]:
    """Generate SARIF from the same effective status projection as every report leaf."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    projection = effective_report_status(report)
    if findings_artifact is not None:
        findings_artifact = FindingsArtifact.model_validate(
            findings_artifact.model_dump(mode="python")
        )
        if (
            findings_artifact.run_id != report.run_id
            or findings_artifact.rejected_findings != report.rejected_findings
            or findings_artifact.filtered_findings != report.filtered_findings
        ):
            raise ValueError("findings artifact differs from the bound audit report")
    sarif = generate_sarif(
        report.findings,
        findings_artifact=findings_artifact,
        scanner_runs=report.scanner_runs,
        maximum_assurance=report.maximum_assurance,
        language_capability=report.language_capability,
        taxonomy_coverage=report.taxonomy_coverage,
        run_status=projection.run_status,
        quality_status=projection.quality_status,
        completed=projection.completed,
        incomplete_reasons=projection.limitations,
        quality_gates=projection.quality_gates,
    )
    if report.actor_model_evaluation is not None:
        run = sarif["runs"][0]
        evaluation = report.actor_model_evaluation
        run["properties"]["actorModel"] = {
            "inputState": evaluation.input_evidence.state.value,
            "evaluationSha256": evaluation.evaluation_sha256,
            "governanceFindingCount": len(evaluation.governance_findings),
            "limitations": list(evaluation.input_evidence.limitations),
        }
        if evaluation.governance_findings:
            run["tool"]["driver"]["rules"].append(
                {
                    "id": "MMAUDIT-ACTOR-GOVERNANCE",
                    "name": "mmaudit_actor_governance",
                    "shortDescription": {
                        "text": "Actor-model and retained code-role governance observation"
                    },
                    "fullDescription": {
                        "text": (
                            "A typed actor-model assumption disagrees with, or is unresolved "
                            "against, retained local role evidence."
                        )
                    },
                    "properties": {"tags": ["governance", "actor-model"]},
                }
            )
        for governance in evaluation.governance_findings:
            locations = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(item.path, safe="/-._~"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": item.start_line,
                            "endLine": item.end_line,
                        },
                    }
                }
                for item in governance.code_evidence
            ]
            run["results"].append(
                {
                    "ruleId": "MMAUDIT-ACTOR-GOVERNANCE",
                    "level": "warning",
                    "message": {
                        "text": (
                            f"{governance.kind.value} for role {governance.role_id}: "
                            f"{governance.detail}"
                        )
                    },
                    "locations": locations,
                    "partialFingerprints": {"actorGovernanceConflictId": governance.conflict_id},
                    "properties": {
                        "conflictId": governance.conflict_id,
                        "kind": governance.kind.value,
                        "roleId": governance.role_id,
                        "actorModelSha256": governance.actor_model_sha256,
                        "findingSha256": governance.finding_sha256,
                    },
                }
            )
    if report.language_capability is None:
        run = sarif["runs"][0]
        run["properties"]["capabilityStatus"] = "NOT_RECORDED"
        if run["invocations"]:
            invocation = run["invocations"][0]
            invocation["properties"]["capabilityStatus"] = "NOT_RECORDED"
            invocation["toolExecutionNotifications"].append(
                {
                    "level": "warning",
                    "message": {
                        "text": (
                            "Language capability evidence was not recorded; this legacy report "
                            "cannot support a Solidity/EVM or maximum-assurance claim."
                        )
                    },
                }
            )
    return sarif


def _security_score(finding: Finding) -> float:
    base = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFORMATIONAL: 0.0,
    }[finding.severity]
    return base * max(0.1, finding.confidence)
