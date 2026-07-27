"""Optional CodeQL adapter for an explicitly prebuilt database."""

from __future__ import annotations

import re
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


class CodeQLScanner(ScannerAdapter):
    name = "codeql"
    executable = "codeql"
    finding_exit_codes = frozenset({0})

    def __init__(self, database_path: str | None, query_suite: str | None) -> None:
        self.database_path = database_path
        self.query_suite = query_suite

    def available(self) -> bool:
        return bool(self.database_path) and bool(self.query_suite) and super().available()

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        assert self.database_path is not None
        assert self.query_suite is not None
        repository_root = root.resolve(strict=True)
        database = (root / self.database_path).resolve()
        try:
            database.relative_to(repository_root)
        except ValueError as exc:
            raise ValueError("CodeQL database must be inside the repository") from exc
        if not database.exists():
            raise ValueError("CodeQL database does not exist")
        if re.fullmatch(r"[A-Za-z0-9_.@-]+", self.query_suite):
            suite = self.query_suite
        else:
            suite_path = (root / self.query_suite).resolve()
            try:
                suite_path.relative_to(repository_root)
            except ValueError as exc:
                raise ValueError("CodeQL query suite path must be inside the repository") from exc
            suite = str(suite_path)
        return [
            self.executable,
            "database",
            "analyze",
            str(database),
            suite,
            "--format=sarifv2.1.0",
            f"--output={private_dir / 'codeql.sarif'}",
            "--threads=2",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del stdout
        sarif_path = private_dir / "codeql.sarif"
        if sarif_path.exists() and sarif_path.stat().st_size > self.max_stdout_bytes:
            raise ValueError("CodeQL SARIF exceeded output limit")
        payload = safe_json(sarif_path.read_text(encoding="utf-8"))
        findings: list[ScannerFinding] = []
        for run in payload.get("runs", []):
            if not isinstance(run, dict):
                continue
            rules = _sarif_rules(run)
            for result in run.get("results", []):
                if not isinstance(result, dict):
                    continue
                identifier = str(result.get("ruleId", "codeql"))
                rule = rules.get(identifier, {})
                for location in result.get("locations", [])[:1]:
                    finding = _sarif_finding(root, identifier, rule, result, location)
                    if finding:
                        findings.append(finding)
        return findings


def _sarif_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = run.get("tool", {}).get("driver", {})
    rules = driver.get("rules", []) if isinstance(driver, dict) else []
    return {
        str(rule.get("id")): rule for rule in rules if isinstance(rule, dict) and rule.get("id")
    }


def _sarif_finding(
    root: Path,
    identifier: str,
    rule: dict[str, Any],
    result: dict[str, Any],
    location: Any,
) -> ScannerFinding | None:
    if not isinstance(location, dict):
        return None
    physical = location.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
    region = physical.get("region", {}) if isinstance(physical, dict) else {}
    message_obj = result.get("message", {})
    message = (
        str(message_obj.get("text", identifier)) if isinstance(message_obj, dict) else identifier
    )
    properties = rule.get("properties", {}) if isinstance(rule, dict) else {}
    cwe = properties.get("tags", []) if isinstance(properties, dict) else []
    normalized_cwe = [
        value for tag in cwe if (value := str(tag).rsplit("/", 1)[-1].upper()).startswith("CWE-")
    ]
    return make_finding(
        root=root,
        scanner="codeql",
        rule_id=identifier,
        title=str(rule.get("name", identifier)),
        severity=severity_from_text(str(result.get("level", "warning"))),
        message=message,
        path=str(artifact.get("uri", "")) if isinstance(artifact, dict) else "",
        start_line=positive_line(region.get("startLine")) if isinstance(region, dict) else 1,
        end_line=positive_line(region.get("endLine"), positive_line(region.get("startLine")))
        if isinstance(region, dict)
        else 1,
        cwe=normalized_cwe,
        metadata={"class": "codeql"},
    )
