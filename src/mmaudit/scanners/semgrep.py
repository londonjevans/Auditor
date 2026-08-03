"""Semgrep adapter using only bundled local rules."""

from __future__ import annotations

from pathlib import Path

from mmaudit.models.schemas import ScannerFinding
from mmaudit.scanners.base import ScannerAdapter, make_finding, safe_json, severity_from_text
from mmaudit.scanners.trusted_inputs import (
    stage_bundled_scanner_resource,
    validate_staged_bundled_scanner_resource,
)


class SemgrepScanner(ScannerAdapter):
    name = "semgrep"
    executable = "semgrep"
    finding_exit_codes = frozenset({0, 1})
    strict_machine_output = True

    def validate_pre_execution_inputs(self, workspace: Path, private_dir: Path) -> None:
        del workspace
        validate_staged_bundled_scanner_resource(
            private_dir,
            resource_relative_path="rules/security.yml",
            destination_name="semgrep-security.yml",
            scanner_label="Semgrep",
        )

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root
        rules = stage_bundled_scanner_resource(
            private_dir,
            resource_relative_path="rules/security.yml",
            destination_name="semgrep-security.yml",
            scanner_label="Semgrep",
        )
        return [
            self.executable,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--exclude",
            ".mmaudit",
            "--no-rewrite-rule-ids",
            "--config",
            str(rules),
            ".",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        payload = safe_json(stdout)
        if not isinstance(payload, dict):
            raise ValueError("Semgrep machine output must be a JSON object")
        results = payload.get("results")
        if not isinstance(results, list):
            raise ValueError("Semgrep machine output must contain a results array")
        if "errors" in payload and not isinstance(payload["errors"], list):
            raise ValueError("Semgrep machine output errors must be an array")
        findings: list[ScannerFinding] = []
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("Semgrep result records must be JSON objects")
            rule_id = _required_string(result, "check_id")
            path = _required_string(result, "path")
            start = _required_object(result, "start")
            end = _required_object(result, "end")
            start_line = _required_positive_integer(start, "line")
            end_line = _required_positive_integer(end, "line")
            if end_line < start_line:
                raise ValueError("Semgrep result end line precedes its start line")
            extra = _required_object(result, "extra")
            message = _required_string(extra, "message")
            severity = _required_string(extra, "severity")
            metadata_value = extra.get("metadata", {})
            if not isinstance(metadata_value, dict):
                raise ValueError("Semgrep result metadata must be a JSON object")
            metadata = metadata_value
            cwe_raw = metadata.get("cwe", [])
            if isinstance(cwe_raw, str):
                cwe = [cwe_raw]
            elif isinstance(cwe_raw, list) and all(
                isinstance(item, str) and bool(item.strip()) for item in cwe_raw
            ):
                cwe = cwe_raw
            else:
                raise ValueError("Semgrep result CWE metadata must contain strings")
            shortlink = metadata.get("shortlink", rule_id)
            if not isinstance(shortlink, str) or not shortlink.strip():
                raise ValueError("Semgrep result shortlink must be a non-empty string")
            engine_kind = extra.get("engine_kind")
            if engine_kind is not None and not isinstance(engine_kind, str):
                raise ValueError("Semgrep result engine kind must be a string")
            finding = make_finding(
                root=root,
                scanner=self.name,
                rule_id=rule_id,
                title=shortlink,
                severity=severity_from_text(severity),
                message=message,
                path=path,
                start_line=start_line,
                end_line=end_line,
                cwe=cwe,
                metadata={"engine_kind": engine_kind},
            )
            if finding is None or finding.locations[0].path == ".":
                raise ValueError("Semgrep result path is outside the scanned repository")
            findings.append(finding)
        return findings


def _required_object(record: dict[object, object], key: str) -> dict[object, object]:
    value = record.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Semgrep result {key} must be a JSON object")
    return value


def _required_string(record: dict[object, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Semgrep result {key} must be a non-empty string")
    return value


def _required_positive_integer(record: dict[object, object], key: str) -> int:
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"Semgrep result {key} must be a positive integer")
    return value
