"""SARIF 2.1.0 generation for surviving security findings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from mmaudit.models.schemas import (
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    Finding,
    FindingStatus,
    MaximumAssuranceAssessment,
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


def generate_sarif(
    findings: list[Finding],
    *,
    findings_artifact: FindingsArtifact | None = None,
    scanner_runs: Sequence[ScannerRun] = (),
    maximum_assurance: MaximumAssuranceAssessment | None = None,
    run_status: AuditRunStatus | None = None,
    quality_status: AuditQualityStatus | None = None,
    completed: bool | None = None,
    incomplete_reasons: Sequence[str] = (),
    quality_gates: Sequence[QualityGateResult] = (),
) -> dict[str, Any]:
    findings_artifact = _validated_artifact_for_findings(findings, findings_artifact)
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
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.summary},
                "help": {
                    "text": finding.recommendation,
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
        }
        results.append(
            {
                "ruleId": finding.id,
                "level": _result_level(finding, record),
                "message": {
                    "text": (
                        f"[{record.disposition.value if record is not None else finding.status.value}] "
                        f"[{finding.origin_kind.value}] "
                        f"{finding.summary} "
                        f"Remediation: {finding.recommendation}"
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
    run_properties: dict[str, Any] = {
        "maximumAssurance": (
            maximum_assurance.model_dump(mode="json") if maximum_assurance is not None else None
        ),
        "scannerExecutions": [
            _scanner_execution_record(run)
            for run in sorted(scanner_runs, key=lambda item: item.scanner)
        ],
    }
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
        if maximum_assurance is not None:
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
    return generate_sarif(
        report.findings,
        findings_artifact=findings_artifact,
        scanner_runs=report.scanner_runs,
        maximum_assurance=report.maximum_assurance,
        run_status=projection.run_status,
        quality_status=projection.quality_status,
        completed=projection.completed,
        incomplete_reasons=projection.limitations,
        quality_gates=projection.quality_gates,
    )


def _security_score(finding: Finding) -> float:
    base = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFORMATIONAL: 0.0,
    }[finding.severity]
    return base * max(0.1, finding.confidence)
