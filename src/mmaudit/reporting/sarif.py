"""SARIF 2.1.0 generation for surviving security findings."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from mmaudit.models.schemas import (
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


def generate_sarif(
    findings: list[Finding],
    *,
    maximum_assurance: MaximumAssuranceAssessment | None = None,
) -> dict[str, Any]:
    included = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.REJECTED and finding.location_validation.valid
    ]
    rules = []
    results = []
    for finding in included:
        tags = [*finding.cwe, *finding.owasp, f"status/{finding.status.value}"]
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
                        f"[{finding.status.value}] {finding.summary} "
                        f"Remediation: {finding.recommendation}"
                    )
                },
                "locations": locations,
                "partialFingerprints": {
                    "primaryLocationLineHash": finding.id,
                    "mmaudit/v1": finding.location_validation.content_hash or finding.id,
                },
                "properties": {
                    "confidence": finding.confidence,
                    "status": finding.status.value,
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                },
            }
        )
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
                "properties": {
                    "maximumAssurance": (
                        maximum_assurance.model_dump(mode="json")
                        if maximum_assurance is not None
                        else None
                    )
                },
                "invocations": (
                    [
                        {
                            "executionSuccessful": (maximum_assurance.status.value == "COMPLETE"),
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
                    ]
                    if maximum_assurance is not None
                    else []
                ),
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
