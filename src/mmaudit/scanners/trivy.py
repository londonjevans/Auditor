"""Offline Trivy filesystem adapter."""

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

_TRIVY_DATABASE_PREPARATION_STEP = "prepare_trivy_offline_vulnerability_database"


class TrivyScanner(ScannerAdapter):
    name = "trivy"
    executable = "trivy"
    finding_exit_codes = frozenset({0})
    strict_machine_output = True

    def classify_non_success_exit(
        self,
        *,
        return_code: int,
        stdout: bytes,
        stderr: bytes,
    ) -> ScannerExitClassification | None:
        try:
            diagnostic = " ".join(stderr.decode("utf-8", errors="strict").casefold().split())
        except UnicodeDecodeError:
            diagnostic = ""
        if (
            return_code != 0
            and not stdout.strip()
            and "[vulndb]" in diagnostic
            and "the first run cannot skip downloading db" in diagnostic
        ):
            return ScannerExitClassification(
                status=ScannerStatus.UNMET_PREREQUISITE,
                diagnostic=(
                    "the approved offline Trivy vulnerability database is unavailable; "
                    "complete the named operator preparation step before retrying"
                ),
                operator_preparation_step=_TRIVY_DATABASE_PREPARATION_STEP,
            )
        return super().classify_non_success_exit(
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
        )

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
        if not isinstance(payload, dict):
            raise ValueError("Trivy machine output must be a JSON object")
        results = payload.get("Results")
        if not isinstance(results, list):
            raise ValueError("Trivy machine output must contain an explicit Results array")
        findings: list[ScannerFinding] = []
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("Trivy result records must be JSON objects")
            target = _required_string(result, "Target", label="Trivy result")
            for vulnerability in _optional_record_array(result, "Vulnerabilities"):
                finding = self._vulnerability(root, target, vulnerability)
                findings.append(_require_contained_finding(finding, kind="vulnerability"))
            for misconfiguration in _optional_record_array(result, "Misconfigurations"):
                finding = self._misconfiguration(root, target, misconfiguration)
                findings.append(_require_contained_finding(finding, kind="misconfiguration"))
            for secret in _optional_record_array(result, "Secrets"):
                rule_id = _required_string(secret, "RuleID", label="Trivy secret")
                title = _optional_string(
                    secret,
                    "Title",
                    default="Potential secret",
                    label="Trivy secret",
                )
                severity = _required_string(secret, "Severity", label="Trivy secret")
                start_line = _required_positive_integer(
                    secret,
                    "StartLine",
                    label="Trivy secret",
                )
                end_line = _required_positive_integer(
                    secret,
                    "EndLine",
                    label="Trivy secret",
                )
                if end_line < start_line:
                    raise ValueError("Trivy secret end line precedes its start line")
                finding = make_finding(
                    root=root,
                    scanner=self.name,
                    rule_id=rule_id,
                    title=title,
                    severity=severity_from_text(severity),
                    message="Potential credential detected; value omitted",
                    path=target,
                    start_line=start_line,
                    end_line=end_line,
                    metadata={"redacted": True, "class": "secret"},
                )
                findings.append(_require_contained_finding(finding, kind="secret"))
        return findings

    def _vulnerability(
        self, root: Path, target: str, item: dict[str, Any]
    ) -> ScannerFinding | None:
        identifier = _required_string(item, "VulnerabilityID", label="Trivy vulnerability")
        package = _required_string(item, "PkgName", label="Trivy vulnerability")
        severity = _required_string(item, "Severity", label="Trivy vulnerability")
        title = _optional_string(item, "Title", default="", label="Trivy vulnerability")
        description = _optional_string(
            item,
            "Description",
            default="",
            label="Trivy vulnerability",
        )
        cwe = _optional_string_array(item, "CweIDs", label="Trivy vulnerability")
        installed_version = _optional_nullable_string(
            item,
            "InstalledVersion",
            label="Trivy vulnerability",
        )
        fixed_version = _optional_nullable_string(
            item,
            "FixedVersion",
            label="Trivy vulnerability",
        )
        return make_finding(
            root=root,
            scanner=self.name,
            rule_id=identifier,
            title=f"{identifier} in {package}",
            severity=severity_from_text(severity),
            message=(title or description or identifier)[:2_000],
            path=target,
            start_line=1,
            cwe=cwe,
            metadata={
                "package": package,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "class": "vulnerability",
            },
        )

    def _misconfiguration(
        self, root: Path, target: str, item: dict[str, Any]
    ) -> ScannerFinding | None:
        cause_value = item.get("CauseMetadata")
        if cause_value is not None and not isinstance(cause_value, dict):
            raise ValueError("Trivy misconfiguration CauseMetadata must be a JSON object")
        cause = cause_value or {}
        start = _optional_positive_integer(
            cause,
            "StartLine",
            default=1,
            label="Trivy misconfiguration cause",
        )
        end = _optional_positive_integer(
            cause,
            "EndLine",
            default=start,
            label="Trivy misconfiguration cause",
        )
        if end < start:
            raise ValueError("Trivy misconfiguration end line precedes its start line")
        identifier = _required_string(item, "ID", label="Trivy misconfiguration")
        title = _optional_string(
            item,
            "Title",
            default=identifier,
            label="Trivy misconfiguration",
        )
        severity = _required_string(item, "Severity", label="Trivy misconfiguration")
        message = _optional_string(
            item,
            "Message",
            default="",
            label="Trivy misconfiguration",
        )
        description = _optional_string(
            item,
            "Description",
            default="",
            label="Trivy misconfiguration",
        )
        return make_finding(
            root=root,
            scanner=self.name,
            rule_id=identifier,
            title=title,
            severity=severity_from_text(severity),
            message=(message or description or identifier)[:2_000],
            path=target,
            start_line=start,
            end_line=end,
            metadata={"class": "misconfiguration"},
        )


def _optional_record_array(
    record: dict[str, Any],
    key: str,
) -> list[dict[str, Any]]:
    value = record.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"Trivy result {key} must be a JSON object array or null")
    return value


def _required_string(record: dict[str, Any], key: str, *, label: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} {key} must be a non-empty string")
    return value


def _optional_string(
    record: dict[str, Any],
    key: str,
    *,
    default: str,
    label: str,
) -> str:
    value = record.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"{label} {key} must be a string")
    return value


def _optional_nullable_string(
    record: dict[str, Any],
    key: str,
    *,
    label: str,
) -> str | None:
    value = record.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{label} {key} must be a string or null")
    return value


def _optional_string_array(
    record: dict[str, Any],
    key: str,
    *,
    label: str,
) -> list[str]:
    value = record.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{label} {key} must be a JSON array of non-empty strings or null")
    return value


def _required_positive_integer(
    record: dict[str, Any],
    key: str,
    *,
    label: str,
) -> int:
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} {key} must be a positive integer")
    return value


def _optional_positive_integer(
    record: dict[str, Any],
    key: str,
    *,
    default: int,
    label: str,
) -> int:
    if key not in record or record[key] is None:
        return default
    return _required_positive_integer(record, key, label=label)


def _require_contained_finding(
    finding: ScannerFinding | None,
    *,
    kind: str,
) -> ScannerFinding:
    if finding is None or finding.locations[0].path == ".":
        raise ValueError(f"Trivy {kind} source is outside the scanned repository")
    return finding
