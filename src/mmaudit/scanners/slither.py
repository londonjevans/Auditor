"""Slither adapter with bounded structured-output normalization."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.config import SmartContractsConfig
from mmaudit.models.schemas import ScannerFinding, Severity
from mmaudit.scanners.base import ScannerAdapter, make_finding, safe_json, severity_from_text

_MAX_SOLIDITY_SOURCES = 10_000
_MAX_SOLIDITY_SOURCE_PATH_CHARACTERS = 500
_MAX_PINNED_COMPILER_BYTES = 500_000_000
_SAFE_SOLIDITY_SOURCE_PATH = re.compile(r"[A-Za-z0-9_./@+~-]+\Z")


class SlitherScanner(ScannerAdapter):
    name = "slither"
    executable = "slither"
    finding_exit_codes = frozenset({0})
    may_execute_repository_code = True
    strict_machine_output = True

    def __init__(self, smart_contracts: SmartContractsConfig | None = None) -> None:
        self.smart_contracts = smart_contracts

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        if self.smart_contracts is None:
            return self._default_command()
        if not self._uses_pinned_compiler():
            raise ValueError("configured Slither requires exact solc_version and solc_sha256 pins")
        _prepare_private_solc_select_state(private_dir)
        compiler = _stage_pinned_compiler(root, private_dir, self.smart_contracts)
        entrypoint = _stage_analysis_entrypoint(root, private_dir)
        return [
            self.executable,
            str(entrypoint),
            "--compile-force-framework",
            "solc",
            "--solc",
            str(compiler),
            "--solc-working-dir",
            str(private_dir.resolve(strict=True)),
            "--solc-args",
            (
                f"--base-path {private_dir.resolve(strict=True)} "
                f"--allow-paths {private_dir.resolve(strict=True)}"
            ),
            "--json",
            "-",
            "--disable-color",
            "--fail-none",
        ]

    def execution_working_directory(self, workspace: Path, private_dir: Path) -> Path:
        if self._uses_pinned_compiler():
            return private_dir / "analysis"
        return workspace

    def validate_pre_execution_inputs(self, workspace: Path, private_dir: Path) -> None:
        """Revalidate the isolated compiler and solc-select state before launch."""

        del workspace
        if not self._uses_pinned_compiler():
            return
        assert self.smart_contracts is not None
        _validate_private_solc_select_state(private_dir)
        _validate_staged_compiler(private_dir, self.smart_contracts)

    def _uses_pinned_compiler(self) -> bool:
        return (
            self.smart_contracts is not None
            and self.smart_contracts.solc_version is not None
            and self.smart_contracts.solc_sha256 is not None
        )

    def _default_command(self) -> list[str]:
        return [
            self.executable,
            ".",
            "--json",
            "-",
            "--disable-color",
            "--fail-none",
        ]

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        payload = safe_json(stdout)
        results, detectors = _validate_slither_envelope(payload)
        findings: list[ScannerFinding] = []
        del results
        for detector in detectors:
            source = _source_mapping(detector)
            if source is None:
                continue
            rule_id = str(detector.get("check") or detector.get("id") or "slither")
            description = str(
                detector.get("description")
                or detector.get("markdown")
                or detector.get("first_markdown_element")
                or rule_id
            )[:2_000]
            finding = make_finding(
                root=root,
                scanner=self.name,
                rule_id=rule_id,
                title=str(detector.get("check") or rule_id),
                severity=_slither_severity(detector.get("impact")),
                message=description,
                path=source["path"],
                start_line=source["start_line"],
                end_line=source["end_line"],
                metadata={
                    "class": "solidity_static_analysis",
                    "tool": "slither",
                    "impact": detector.get("impact"),
                    "confidence": detector.get("confidence"),
                    "elements": _element_summary(detector.get("elements")),
                },
            )
            if finding is not None:
                findings.append(finding)
        return findings


def _validate_slither_envelope(
    payload: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Require Slither's successful machine envelope before accepting its output."""

    if not isinstance(payload, dict):
        raise ValueError("Slither output must be a JSON object")
    if payload.get("success") is not True:
        raise ValueError("Slither machine output did not report success")
    if payload.get("error") not in (None, ""):
        raise ValueError("Slither machine output contains an error")
    results = payload.get("results")
    if not isinstance(results, dict):
        raise ValueError("Slither results must be a JSON object")
    detectors = results.get("detectors")
    if not isinstance(detectors, list) or any(
        not isinstance(detector, dict) for detector in detectors
    ):
        raise ValueError("Slither detectors must be a JSON object array")
    return results, detectors


def _slither_severity(value: Any) -> Severity:
    normalized = str(value or "").lower()
    if normalized == "high":
        return Severity.HIGH
    if normalized == "medium":
        return Severity.MEDIUM
    if normalized == "low":
        return Severity.LOW
    if normalized == "informational":
        return Severity.INFORMATIONAL
    return severity_from_text(normalized)


def _source_mapping(detector: dict[str, Any]) -> dict[str, Any] | None:
    for element in detector.get("elements", []) or []:
        if not isinstance(element, dict):
            continue
        mapping = element.get("source_mapping", {})
        if not isinstance(mapping, dict):
            continue
        filename = (
            mapping.get("filename_relative")
            or mapping.get("filename_short")
            or mapping.get("filename_absolute")
            or mapping.get("filename")
        )
        if not filename:
            continue
        normalized_filename = str(filename)
        if normalized_filename.startswith("workspace/"):
            normalized_filename = normalized_filename.removeprefix("workspace/")
        lines = mapping.get("lines", [])
        if isinstance(lines, list) and lines:
            parsed = [max(1, int(line)) for line in lines if str(line).isdigit()]
            if parsed:
                return {
                    "path": normalized_filename,
                    "start_line": min(parsed),
                    "end_line": max(parsed),
                }
        start = mapping.get("start")
        if isinstance(start, int):
            line = max(1, start)
            return {"path": normalized_filename, "start_line": line, "end_line": line}
    return None


def _element_summary(value: Any) -> list[dict[str, str]]:
    summary = []
    for element in value if isinstance(value, list) else []:
        if not isinstance(element, dict):
            continue
        summary.append(
            {
                "type": str(element.get("type", ""))[:80],
                "name": str(element.get("name", ""))[:160],
            }
        )
        if len(summary) == 20:
            break
    return summary


def _stage_pinned_compiler(
    root: Path,
    private_dir: Path,
    config: SmartContractsConfig,
) -> Path:
    """Copy the exact configured compiler into the private scanner toolchain."""

    if config.solc_sha256 is None:
        raise ValueError("Slither requires configured Solidity compiler SHA-256")
    raw_path = os.environ.get(config.solc_executable_env, "")
    if not raw_path:
        raise ValueError("configured Solidity compiler executable is unavailable")
    source = Path(raw_path)
    try:
        source_metadata = source.lstat()
        resolved_source = source.resolve(strict=True)
        resolved_source.relative_to(root.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise ValueError("configured Solidity compiler could not be inspected") from exc
    else:
        raise ValueError("configured Solidity compiler cannot reside in the audited repository")
    if (
        not source.is_absolute()
        or resolved_source != source
        or source.is_symlink()
        or source.is_junction()
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or not 0 < source_metadata.st_size <= _MAX_PINNED_COMPILER_BYTES
        or not os.access(source, os.X_OK)
    ):
        raise ValueError("configured Solidity compiler is not a safe executable")
    if _sha256_file(source) != config.solc_sha256:
        raise ValueError("configured Solidity compiler does not match its SHA-256 pin")

    toolchain = private_dir / "toolchain"
    toolchain.mkdir(mode=0o700)
    destination = toolchain / "solc"
    with source.open("rb") as source_handle, destination.open("xb") as destination_handle:
        shutil.copyfileobj(source_handle, destination_handle, length=1024 * 1024)
    destination.chmod(0o500)
    if _sha256_file(destination) != config.solc_sha256:
        raise ValueError("staged Solidity compiler differs from its SHA-256 pin")
    return destination.resolve(strict=True)


def _prepare_private_solc_select_state(private_dir: Path) -> Path:
    """Create only the empty private state imported by Slither's solc-select dependency."""

    private_root = private_dir.resolve(strict=True)
    home = private_dir / "home"
    _require_private_state_directory(
        home,
        private_root=private_root,
        label="Slither private HOME",
        exact_mode=None,
    )
    home.chmod(0o700)
    _require_private_state_directory(
        home,
        private_root=private_root,
        label="Slither private HOME",
        exact_mode=0o700,
    )
    solc_select = home / ".solc-select"
    artifacts = solc_select / "artifacts"
    for path, label in (
        (solc_select, "Slither private solc-select directory"),
        (artifacts, "Slither private solc-select artifacts directory"),
    ):
        with contextlib.suppress(FileExistsError):
            path.mkdir(mode=0o700)
        _require_private_state_directory(
            path,
            private_root=private_root,
            label=label,
            exact_mode=None,
        )
        path.chmod(0o700)
        _require_private_state_directory(
            path,
            private_root=private_root,
            label=label,
            exact_mode=0o700,
        )
    return artifacts


def _validate_private_solc_select_state(private_dir: Path) -> None:
    private_root = private_dir.resolve(strict=True)
    home = private_dir / "home"
    for path, label, exact_mode in (
        (home, "Slither private HOME", 0o700),
        (home / ".solc-select", "Slither private solc-select directory", 0o700),
        (
            home / ".solc-select" / "artifacts",
            "Slither private solc-select artifacts directory",
            0o700,
        ),
    ):
        _require_private_state_directory(
            path,
            private_root=private_root,
            label=label,
            exact_mode=exact_mode,
        )
    try:
        (home / ".solc-select" / "global-version").lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("Slither private solc-select state must not select an ambient compiler")
    try:
        next((home / ".solc-select" / "artifacts").iterdir())
    except StopIteration:
        pass
    except OSError as exc:
        raise ValueError("Slither private solc-select artifacts could not be inspected") from exc
    else:
        raise ValueError("Slither private solc-select artifacts must remain empty")


def _require_private_state_directory(
    path: Path,
    *,
    private_root: Path,
    label: str,
    exact_mode: int | None,
) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(private_root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} is unavailable inside the private boundary") from exc
    current_uid = os.geteuid() if hasattr(os, "geteuid") else None
    if (
        path.is_symlink()
        or path.is_junction()
        or not stat.S_ISDIR(metadata.st_mode)
        or (current_uid is not None and metadata.st_uid != current_uid)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode)
    ):
        raise ValueError(f"{label} is not an owner-private non-link directory")


def _validate_staged_compiler(private_dir: Path, config: SmartContractsConfig) -> Path:
    if config.solc_sha256 is None:
        raise ValueError("Slither requires configured Solidity compiler SHA-256")
    private_root = private_dir.resolve(strict=True)
    compiler = private_dir / "toolchain" / "solc"
    try:
        metadata = compiler.lstat()
        resolved = compiler.resolve(strict=True)
        resolved.relative_to(private_root)
    except (OSError, ValueError) as exc:
        raise ValueError("staged Solidity compiler is unavailable") from exc
    if (
        compiler.is_symlink()
        or compiler.is_junction()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= _MAX_PINNED_COMPILER_BYTES
        or stat.S_IMODE(metadata.st_mode) != 0o500
        or not os.access(compiler, os.X_OK)
    ):
        raise ValueError("staged Solidity compiler is not a private executable")
    if _sha256_file(compiler) != config.solc_sha256:
        raise ValueError("staged Solidity compiler differs from its SHA-256 pin")
    return resolved


def _stage_analysis_entrypoint(root: Path, private_dir: Path) -> Path:
    """Create an import-only private entrypoint covering every copied Solidity source."""

    sources: list[str] = []
    for candidate in sorted(root.rglob("*.sol")):
        if candidate.is_symlink() or candidate.is_junction() or not candidate.is_file():
            raise ValueError("Slither source inventory contains an unsupported file")
        relative = PurePosixPath(candidate.relative_to(root).as_posix()).as_posix()
        if (
            not relative
            or len(relative) > _MAX_SOLIDITY_SOURCE_PATH_CHARACTERS
            or _SAFE_SOLIDITY_SOURCE_PATH.fullmatch(relative) is None
        ):
            raise ValueError("Slither source path cannot be represented safely")
        sources.append(relative)
        if len(sources) > _MAX_SOLIDITY_SOURCES:
            raise ValueError("Slither source inventory exceeds the fixed source limit")
    if not sources:
        raise ValueError("Slither requires at least one Solidity source")

    analysis = private_dir / "analysis"
    analysis.mkdir(mode=0o700)
    entrypoint = analysis / "slither-entrypoint.sol"
    lines = ["// SPDX-License-Identifier: UNLICENSED"]
    lines.extend(f'import "workspace/{source}";' for source in sources)
    payload = ("\n".join(lines) + "\n").encode()
    with entrypoint.open("xb") as handle:
        handle.write(payload)
    entrypoint.chmod(0o600)
    if entrypoint.read_bytes() != payload:
        raise ValueError("Slither analysis entrypoint failed exact-byte validation")
    return entrypoint


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
