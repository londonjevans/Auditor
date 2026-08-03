"""Gitleaks adapter with mandatory redaction."""

from __future__ import annotations

from pathlib import Path

from mmaudit.models.schemas import ScannerFinding, Severity
from mmaudit.scanners.base import ScannerAdapter, make_finding, safe_json
from mmaudit.scanners.trusted_inputs import (
    stage_bundled_scanner_resource,
    validate_staged_bundled_scanner_resource,
)


class GitleaksScanner(ScannerAdapter):
    name = "gitleaks"
    executable = "gitleaks"
    finding_exit_codes = frozenset({0})
    strict_machine_output = True

    def validate_pre_execution_inputs(self, workspace: Path, private_dir: Path) -> None:
        del workspace
        validate_staged_bundled_scanner_resource(
            private_dir,
            resource_relative_path="rules/gitleaks.toml",
            destination_name="gitleaks.toml",
            scanner_label="Gitleaks",
        )

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root
        rules = stage_bundled_scanner_resource(
            private_dir,
            resource_relative_path="rules/gitleaks.toml",
            destination_name="gitleaks.toml",
            scanner_label="Gitleaks",
        )
        return [
            self.executable,
            "detect",
            "--source",
            ".",
            "--no-git",
            "--config",
            str(rules),
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--exit-code",
            "0",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        payload = safe_json(stdout)
        if not isinstance(payload, list):
            raise ValueError("Gitleaks machine output must be a JSON array")
        findings: list[ScannerFinding] = []
        for result in payload:
            if not isinstance(result, dict):
                raise ValueError("Gitleaks finding records must be JSON objects")
            rule_id = _required_string(result, "RuleID")
            description = (
                _required_string(result, "Description") if "Description" in result else rule_id
            )
            path = _required_string(result, "File")
            start_line = _required_positive_integer(result, "StartLine")
            end_line = _required_positive_integer(result, "EndLine")
            if end_line < start_line:
                raise ValueError("Gitleaks finding end line precedes its start line")
            finding = make_finding(
                root=root,
                scanner=self.name,
                rule_id=rule_id,
                title=description,
                severity=Severity.HIGH,
                message="Potential credential detected; scanner output was redacted",
                path=path,
                start_line=start_line,
                end_line=end_line,
                metadata={"redacted": True},
            )
            if finding is None or finding.locations[0].path == ".":
                raise ValueError("Gitleaks finding path is outside the scanned repository")
            findings.append(finding)
        return findings


def _required_string(record: dict[object, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Gitleaks finding {key} must be a non-empty string")
    return value


def _required_positive_integer(record: dict[object, object], key: str) -> int:
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"Gitleaks finding {key} must be a positive integer")
    return value
