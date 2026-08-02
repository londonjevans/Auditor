"""Semgrep adapter using only bundled local rules."""

from __future__ import annotations

import hashlib
import os
import stat
from importlib.resources import files
from pathlib import Path

from mmaudit.models.schemas import ScannerFinding
from mmaudit.scanners.base import ScannerAdapter, make_finding, safe_json, severity_from_text

_MAX_BUNDLED_RULE_BYTES = 1_000_000


class SemgrepScanner(ScannerAdapter):
    name = "semgrep"
    executable = "semgrep"
    finding_exit_codes = frozenset({0, 1})

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root
        rules = _stage_bundled_rules(private_dir)
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


def _stage_bundled_rules(private_dir: Path) -> Path:
    """Copy the fixed package rule set into the sandbox-readable private directory."""

    resource = files("mmaudit.scanners").joinpath("rules/security.yml")
    if not resource.is_file():
        raise ValueError("bundled Semgrep rule resource is unavailable")
    with resource.open("rb") as handle:
        rule_bytes = handle.read(_MAX_BUNDLED_RULE_BYTES + 1)
    if not rule_bytes or len(rule_bytes) > _MAX_BUNDLED_RULE_BYTES:
        raise ValueError("bundled Semgrep rule resource is empty or exceeds its fixed bound")
    source_sha256 = hashlib.sha256(rule_bytes).hexdigest()

    private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if private_dir.is_symlink() or private_dir.is_junction():
        raise ValueError("Semgrep private directory may not be a link")
    resolved_private = private_dir.resolve(strict=True)
    private_metadata = resolved_private.stat()
    current_uid = int(getattr(os, "getuid", lambda: private_metadata.st_uid)())
    if (
        not stat.S_ISDIR(private_metadata.st_mode)
        or stat.S_IMODE(private_metadata.st_mode) != 0o700
        or private_metadata.st_uid != current_uid
    ):
        raise ValueError("Semgrep private directory must be operator-owned with mode 0700")
    staged_root = resolved_private / "trusted-inputs"
    staged_root.mkdir(mode=0o700)
    staged_metadata = staged_root.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(staged_metadata.st_mode)
        or stat.S_IMODE(staged_metadata.st_mode) != 0o700
        or staged_metadata.st_uid != current_uid
    ):
        raise ValueError("Semgrep staged-input directory failed private-mode validation")
    destination = staged_root / "semgrep-security.yml"
    with destination.open("xb") as handle:
        handle.write(rule_bytes)
    destination.chmod(0o600)
    destination_metadata = destination.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(destination_metadata.st_mode)
        or stat.S_IMODE(destination_metadata.st_mode) != 0o600
        or destination_metadata.st_uid != current_uid
    ):
        raise ValueError("staged Semgrep rule resource failed private-file validation")
    staged_bytes = destination.read_bytes()
    if staged_bytes != rule_bytes or hashlib.sha256(staged_bytes).hexdigest() != source_sha256:
        raise ValueError("staged Semgrep rule resource failed exact-byte verification")
    return destination
