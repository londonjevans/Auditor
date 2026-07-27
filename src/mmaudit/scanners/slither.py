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
        results = payload.get("results", {}) if isinstance(payload, dict) else {}
        detectors = results.get("detectors", []) if isinstance(results, dict) else []
        findings: list[ScannerFinding] = []
        for detector in detectors if isinstance(detectors, list) else []:
            if not isinstance(detector, dict):
                continue
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
