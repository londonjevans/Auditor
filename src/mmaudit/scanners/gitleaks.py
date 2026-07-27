"""Gitleaks adapter with mandatory redaction."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from mmaudit.models.schemas import ScannerFinding, Severity
from mmaudit.scanners.base import ScannerAdapter, make_finding, positive_line, safe_json


class GitleaksScanner(ScannerAdapter):
    name = "gitleaks"
    executable = "gitleaks"
    finding_exit_codes = frozenset({0})

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root
        return [
            self.executable,
            "detect",
            "--source",
            ".",
            "--no-git",
            "--config",
            str(files("mmaudit.scanners").joinpath("rules/gitleaks.toml")),
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(private_dir / "gitleaks-report.json"),
            "--exit-code",
            "0",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del stdout
        report_path = private_dir / "gitleaks-report.json"
        if report_path.exists() and report_path.stat().st_size > self.max_stdout_bytes:
            raise ValueError("gitleaks report exceeded output limit")
        payload = safe_json(report_path.read_text(encoding="utf-8")) if report_path.exists() else []
        findings: list[ScannerFinding] = []
        for result in payload if isinstance(payload, list) else []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("RuleID", "secret"))
            finding = make_finding(
                root=root,
                scanner=self.name,
                rule_id=rule_id,
                title=str(result.get("Description", "Potential secret")),
                severity=Severity.HIGH,
                message="Potential credential detected; scanner output was redacted",
                path=str(result.get("File", "")),
                start_line=positive_line(result.get("StartLine")),
                end_line=positive_line(
                    result.get("EndLine"), positive_line(result.get("StartLine"))
                ),
                metadata={"redacted": True},
            )
            if finding:
                findings.append(finding)
        return findings
