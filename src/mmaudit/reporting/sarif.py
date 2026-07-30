"""SARIF 2.1.0 generation for surviving security findings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote

from mmaudit.models.schemas import (
    AuditQualityStatus,
    AuditRunStatus,
    Finding,
    FindingStatus,
    MaximumAssuranceAssessment,
    Severity,
)

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "note",
}


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


def generate_sarif(
    findings: list[Finding],
    *,
    maximum_assurance: MaximumAssuranceAssessment | None = None,
    run_status: AuditRunStatus | None = None,
    quality_status: AuditQualityStatus | None = None,
    completed: bool | None = None,
    incomplete_reasons: Sequence[str] = (),
) -> dict[str, Any]:
    if run_status is not None:
        expected_completed = run_status is AuditRunStatus.COMPLETE
        expected_quality = {
            AuditRunStatus.COMPLETE: AuditQualityStatus.COMPLETED,
            AuditRunStatus.DEGRADED: AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
            AuditRunStatus.INCOMPLETE: AuditQualityStatus.INCOMPLETE,
            AuditRunStatus.FAILED: AuditQualityStatus.FAILED,
        }[run_status]
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

    included = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.REJECTED and finding.location_validation.valid
    ]
    rules = []
    results = []
    for finding in included:
        tags = [
            *finding.cwe,
            *finding.owasp,
            f"status/{finding.status.value}",
            f"origin/{finding.origin_kind.value}",
        ]
        origin_properties = _origin_properties(finding)
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
                    "status": finding.status.value,
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
            "status": finding.status.value,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            **origin_properties,
        }
        results.append(
            {
                "ruleId": finding.id,
                "level": (
                    "note"
                    if finding.status is FindingStatus.NEEDS_REVIEW
                    else _LEVEL[finding.severity]
                ),
                "message": {
                    "text": (
                        f"[{finding.status.value}] [{finding.origin_kind.value}] "
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
        )
    }
    if run_status is not None:
        run_properties["runStatus"] = run_status.value
    if quality_status is not None:
        run_properties["qualityStatus"] = quality_status.value
    if completed is not None:
        run_properties["completed"] = completed

    invocation: dict[str, Any] | None = None
    run_evidence_supplied = any(
        (
            run_status is not None,
            quality_status is not None,
            completed is not None,
            bool(incomplete_reasons),
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
            "executionSuccessful": run_status is AuditRunStatus.COMPLETE,
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


def _security_score(finding: Finding) -> float:
    base = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFORMATIONAL: 0.0,
    }[finding.severity]
    return base * max(0.1, finding.confidence)
