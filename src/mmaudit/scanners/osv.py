"""OSV-Scanner v2 offline source adapter."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mmaudit.models.schemas import ScannerFinding, ScannerStatus, Severity
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerExitClassification,
    make_finding,
    safe_json,
    severity_from_text,
)

_NO_PACKAGE_SOURCE_DIAGNOSTICS = frozenset(
    {
        "no package sources found",
        "no package sources found, --help for usage information",
    }
)


class OsvScanner(ScannerAdapter):
    name = "osv"
    executable = "osv-scanner"
    finding_exit_codes = frozenset({0, 1})
    strict_machine_output = True

    def classify_non_success_exit(
        self,
        *,
        return_code: int,
        stdout: bytes,
        stderr: bytes,
    ) -> ScannerExitClassification | None:
        try:
            diagnostic = stderr.decode("utf-8", errors="strict").strip().casefold()
        except UnicodeDecodeError:
            diagnostic = ""
        if (
            return_code == 128
            and not stdout.strip()
            and diagnostic.rstrip(".") in _NO_PACKAGE_SOURCE_DIAGNOSTICS
        ):
            return ScannerExitClassification(
                status=ScannerStatus.NOT_APPLICABLE,
                diagnostic="no supported package sources were present in the audited scope",
            )
        return super().classify_non_success_exit(
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
        )

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root
        private_dir.mkdir(parents=True, exist_ok=True)
        config_path = private_dir / "osv-scanner.toml"
        config_path.write_text("", encoding="utf-8")
        return [
            self.executable,
            "scan",
            "source",
            f"--config={config_path}",
            "--format=json",
            "--verbosity=error",
            "--recursive",
            "--offline",
            "--offline-vulnerabilities",
            "--no-resolve",
            ".",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        payload = safe_json(stdout)
        if not isinstance(payload, dict):
            raise ValueError("OSV machine output must be a JSON object")
        results = payload.get("results")
        if not isinstance(results, list):
            raise ValueError("OSV machine output must contain an explicit results array")
        findings: list[ScannerFinding] = []
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("OSV result records must be JSON objects")
            source = result.get("source")
            if not isinstance(source, dict):
                raise ValueError("OSV result source must be a JSON object")
            source_path = _required_string(source, "path", label="OSV result source")
            packages = result.get("packages")
            if not isinstance(packages, list):
                raise ValueError("OSV result packages must be an explicit JSON array")
            for package_group in packages:
                if not isinstance(package_group, dict):
                    raise ValueError("OSV package records must be JSON objects")
                package = package_group.get("package")
                if not isinstance(package, dict):
                    raise ValueError("OSV package identity must be a JSON object")
                package_name = _required_string(package, "name", label="OSV package")
                vulnerabilities = package_group.get("vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    raise ValueError("OSV package vulnerabilities must be an explicit JSON array")
                for vulnerability in vulnerabilities:
                    if not isinstance(vulnerability, dict):
                        raise ValueError("OSV vulnerability records must be JSON objects")
                    finding = self._finding(root, source_path, package_name, vulnerability)
                    if finding is None or finding.locations[0].path == ".":
                        raise ValueError(
                            "OSV vulnerability source is outside the scanned repository"
                        )
                    findings.append(finding)
        return findings

    def _finding(
        self,
        root: Path,
        source_path: str,
        package: str,
        item: dict[str, Any],
    ) -> ScannerFinding | None:
        identifier = _required_string(item, "id", label="OSV vulnerability")
        summary_value = item.get("summary")
        details_value = item.get("details")
        if summary_value is not None and not isinstance(summary_value, str):
            raise ValueError("OSV vulnerability summary must be a string")
        if details_value is not None and not isinstance(details_value, str):
            raise ValueError("OSV vulnerability details must be a string")
        aliases = _optional_string_array(item, "aliases", label="OSV vulnerability")
        database_specific = item.get("database_specific")
        if database_specific is not None and not isinstance(database_specific, dict):
            raise ValueError("OSV vulnerability database_specific must be a JSON object")
        if isinstance(database_specific, dict):
            database_severity = database_specific.get("severity")
            if database_severity is not None and not isinstance(database_severity, str):
                raise ValueError("OSV vulnerability database severity must be a string")
        severity_entries = item.get("severity")
        if severity_entries is not None and not isinstance(severity_entries, list):
            raise ValueError("OSV vulnerability severity must be a JSON array")
        if isinstance(severity_entries, list) and any(
            not isinstance(entry, dict) for entry in severity_entries
        ):
            raise ValueError("OSV vulnerability severity records must be JSON objects")
        summary = (summary_value or details_value or identifier)[:2_000]
        severity = _osv_severity(item)
        return make_finding(
            root=root,
            scanner=self.name,
            rule_id=identifier,
            title=f"{identifier} in {package}",
            severity=severity,
            message=summary,
            path=source_path,
            start_line=1,
            metadata={
                "package": package,
                "aliases": aliases,
                "class": "dependency",
            },
        )


def _osv_severity(item: dict[str, Any]) -> Severity:
    database_specific = item.get("database_specific", {})
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        return severity_from_text(str(database_specific["severity"]))
    severity_entries = item.get("severity", [])
    score = "medium" if severity_entries else "informational"
    return severity_from_text(score)


def _required_string(record: Mapping[str, Any], key: str, *, label: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} {key} must be a non-empty string")
    return value


def _optional_string_array(
    record: Mapping[str, Any],
    key: str,
    *,
    label: str,
) -> list[str]:
    value = record.get(key, [])
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{label} {key} must be a JSON array of non-empty strings")
    return value
