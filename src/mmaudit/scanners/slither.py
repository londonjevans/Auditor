"""Slither adapter with bounded structured-output normalization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mmaudit.models.schemas import ScannerFinding, Severity
from mmaudit.scanners.base import ScannerAdapter, make_finding, safe_json, severity_from_text


class SlitherScanner(ScannerAdapter):
    name = "slither"
    executable = "slither"
    finding_exit_codes = frozenset({0})
    may_execute_repository_code = True
    strict_machine_output = True

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        return [
            self.executable,
            ".",
            "--json",
            "-",
            "--disable-color",
            "--no-fail",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        payload = safe_json(stdout)
        results, detectors = _validate_slither_envelope(payload)
        findings: list[ScannerFinding] = []
        del results
        for detector in detectors:
            source = _source_mapping(detector)
            if source is None:
                continue
            rule_id = str(detector.get("check") or detector.get("id") or "slither")
            description = str(
                detector.get("description")
                or detector.get("markdown")
                or detector.get("first_markdown_element")
                or rule_id
            )[:2_000]
            finding = make_finding(
                root=root,
                scanner=self.name,
                rule_id=rule_id,
                title=str(detector.get("check") or rule_id),
                severity=_slither_severity(detector.get("impact")),
                message=description,
                path=source["path"],
                start_line=source["start_line"],
                end_line=source["end_line"],
                metadata={
                    "class": "solidity_static_analysis",
                    "tool": "slither",
                    "impact": detector.get("impact"),
                    "confidence": detector.get("confidence"),
                    "elements": _element_summary(detector.get("elements")),
                },
            )
            if finding is not None:
                findings.append(finding)
        return findings


def _validate_slither_envelope(
    payload: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Require Slither's successful machine envelope before accepting its output."""

    if not isinstance(payload, dict):
        raise ValueError("Slither output must be a JSON object")
    if payload.get("success") is not True:
        raise ValueError("Slither machine output did not report success")
    if payload.get("error") not in (None, ""):
        raise ValueError("Slither machine output contains an error")
    results = payload.get("results")
    if not isinstance(results, dict):
        raise ValueError("Slither results must be a JSON object")
    detectors = results.get("detectors")
    if not isinstance(detectors, list) or any(
        not isinstance(detector, dict) for detector in detectors
    ):
        raise ValueError("Slither detectors must be a JSON object array")
    return results, detectors


def _slither_severity(value: Any) -> Severity:
    normalized = str(value or "").lower()
    if normalized == "high":
        return Severity.HIGH
    if normalized == "medium":
        return Severity.MEDIUM
    if normalized == "low":
        return Severity.LOW
    if normalized == "informational":
        return Severity.INFORMATIONAL
    return severity_from_text(normalized)


def _source_mapping(detector: dict[str, Any]) -> dict[str, Any] | None:
    for element in detector.get("elements", []) or []:
        if not isinstance(element, dict):
            continue
        mapping = element.get("source_mapping", {})
        if not isinstance(mapping, dict):
            continue
        filename = (
            mapping.get("filename_relative")
            or mapping.get("filename_short")
            or mapping.get("filename_absolute")
            or mapping.get("filename")
        )
        if not filename:
            continue
        lines = mapping.get("lines", [])
        if isinstance(lines, list) and lines:
            parsed = [max(1, int(line)) for line in lines if str(line).isdigit()]
            if parsed:
                return {
                    "path": str(filename),
                    "start_line": min(parsed),
                    "end_line": max(parsed),
                }
        start = mapping.get("start")
        if isinstance(start, int):
            line = max(1, start)
            return {"path": str(filename), "start_line": line, "end_line": line}
    return None


def _element_summary(value: Any) -> list[dict[str, str]]:
    summary = []
    for element in value if isinstance(value, list) else []:
        if not isinstance(element, dict):
            continue
        summary.append(
            {
                "type": str(element.get("type", ""))[:80],
                "name": str(element.get("name", ""))[:160],
            }
        )
        if len(summary) == 20:
            break
    return summary
