"""Semgrep adapter using only bundled local rules."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from mmaudit.models.schemas import ScannerFinding
from mmaudit.scanners.base import ScannerAdapter, make_finding, safe_json, severity_from_text


class SemgrepScanner(ScannerAdapter):
    name = "semgrep"
    executable = "semgrep"
    finding_exit_codes = frozenset({0, 1})

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        rules = files("mmaudit.scanners").joinpath("rules/security.yml")
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
        findings: list[ScannerFinding] = []
        for result in payload.get("results", []):
            if not isinstance(result, dict):
                continue
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
            start = result.get("start", {})
            end = result.get("end", {})
            rule_id = str(result.get("check_id", "semgrep"))
            cwe_raw = metadata.get("cwe", []) if isinstance(metadata, dict) else []
            cwe = [str(cwe_raw)] if isinstance(cwe_raw, str) else [str(v) for v in cwe_raw]
            finding = make_finding(
                root=root,
                scanner=self.name,
                rule_id=rule_id,
                title=str(metadata.get("shortlink", rule_id)),
                severity=severity_from_text(str(extra.get("severity", ""))),
                message=str(extra.get("message", rule_id)),
                path=str(result.get("path", "")),
                start_line=int(start.get("line", 1)),
                end_line=int(end.get("line", start.get("line", 1))),
                cwe=cwe,
                metadata={"engine_kind": extra.get("engine_kind")},
            )
            if finding:
                findings.append(finding)
        return findings
