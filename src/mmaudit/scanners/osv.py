"""OSV-Scanner v2 offline source adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mmaudit.models.schemas import ScannerFinding, ScannerStatus
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
        findings: list[ScannerFinding] = []
        for result in payload.get("results", []):
            if not isinstance(result, dict):
                continue
            source = result.get("source", {})
            source_path = str(source.get("path", "")) if isinstance(source, dict) else ""
            for package_group in result.get("packages", []):
                if not isinstance(package_group, dict):
                    continue
                package = package_group.get("package", {})
                package_name = (
                    str(package.get("name", "dependency"))
                    if isinstance(package, dict)
                    else "dependency"
                )
                for vulnerability in package_group.get("vulnerabilities", []):
                    if not isinstance(vulnerability, dict):
                        continue
                    finding = self._finding(root, source_path, package_name, vulnerability)
                    if finding:
                        findings.append(finding)
        return findings

    def _finding(
        self,
        root: Path,
        source_path: str,
        package: str,
        item: dict[str, Any],
    ) -> ScannerFinding | None:
        identifier = str(item.get("id", "OSV-UNKNOWN"))
        summary = str(item.get("summary") or item.get("details") or identifier)[:2_000]
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
                "aliases": [str(value) for value in item.get("aliases", [])],
                "class": "dependency",
            },
        )


def _osv_severity(item: dict[str, Any]) -> Any:
    database_specific = item.get("database_specific", {})
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        return severity_from_text(str(database_specific["severity"]))
    severity_entries = item.get("severity", [])
    score = "medium" if severity_entries else "informational"
    return severity_from_text(score)
