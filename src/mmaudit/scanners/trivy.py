"""Offline Trivy filesystem adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mmaudit.models.schemas import ScannerFinding
from mmaudit.scanners.base import (
    ScannerAdapter,
    make_finding,
    positive_line,
    safe_json,
    severity_from_text,
)


class TrivyScanner(ScannerAdapter):
    name = "trivy"
    executable = "trivy"
    finding_exit_codes = frozenset({0})

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root
        private_dir.mkdir(parents=True, exist_ok=True)
        config_path = private_dir / "trivy.yaml"
        config_path.write_text("{}\n", encoding="utf-8")
        return [
            self.executable,
            "fs",
            "--config",
            str(config_path),
            "--format",
            "json",
            "--scanners",
            "vuln,misconfig,secret",
            "--skip-db-update",
            "--offline-scan",
            "--cache-dir",
            str(private_dir / "cache"),
            "--skip-dirs",
            ".mmaudit",
            "--no-progress",
            ".",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        payload = safe_json(stdout)
        findings: list[ScannerFinding] = []
        for result in payload.get("Results", []):
            if not isinstance(result, dict):
                continue
            target = str(result.get("Target", ""))
            for vulnerability in result.get("Vulnerabilities") or []:
                if isinstance(vulnerability, dict):
                    finding = self._vulnerability(root, target, vulnerability)
                    if finding:
                        findings.append(finding)
            for misconfiguration in result.get("Misconfigurations") or []:
                if isinstance(misconfiguration, dict):
                    finding = self._misconfiguration(root, target, misconfiguration)
                    if finding:
                        findings.append(finding)
            for secret in result.get("Secrets") or []:
                if isinstance(secret, dict):
                    finding = make_finding(
                        root=root,
                        scanner=self.name,
                        rule_id=str(secret.get("RuleID", "secret")),
                        title=str(secret.get("Title", "Potential secret")),
                        severity=severity_from_text(str(secret.get("Severity", "HIGH"))),
                        message="Potential credential detected; value omitted",
                        path=target,
                        start_line=positive_line(secret.get("StartLine")),
                        end_line=positive_line(
                            secret.get("EndLine"), positive_line(secret.get("StartLine"))
                        ),
                        metadata={"redacted": True, "class": "secret"},
                    )
                    if finding:
                        findings.append(finding)
        return findings

    def _vulnerability(
        self, root: Path, target: str, item: dict[str, Any]
    ) -> ScannerFinding | None:
        identifier = str(item.get("VulnerabilityID", "dependency-vulnerability"))
        package = str(item.get("PkgName", "dependency"))
        return make_finding(
            root=root,
            scanner=self.name,
            rule_id=identifier,
            title=f"{identifier} in {package}",
            severity=severity_from_text(str(item.get("Severity", ""))),
            message=str(item.get("Title") or item.get("Description") or identifier)[:2_000],
            path=target,
            start_line=1,
            cwe=[str(value) for value in item.get("CweIDs", [])],
            metadata={
                "package": package,
                "installed_version": item.get("InstalledVersion"),
                "fixed_version": item.get("FixedVersion"),
                "class": "vulnerability",
            },
        )

    def _misconfiguration(
        self, root: Path, target: str, item: dict[str, Any]
    ) -> ScannerFinding | None:
        cause = item.get("CauseMetadata", {})
        start = cause.get("StartLine", 1) if isinstance(cause, dict) else 1
        end = cause.get("EndLine", start) if isinstance(cause, dict) else start
        identifier = str(item.get("ID", "misconfiguration"))
        return make_finding(
            root=root,
            scanner=self.name,
            rule_id=identifier,
            title=str(item.get("Title", identifier)),
            severity=severity_from_text(str(item.get("Severity", ""))),
            message=str(item.get("Message") or item.get("Description") or identifier)[:2_000],
            path=target,
            start_line=positive_line(start),
            end_line=positive_line(end, positive_line(start)),
            metadata={"class": "misconfiguration"},
        )
