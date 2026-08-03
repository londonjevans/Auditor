"""Deterministic replay of trusted built-in scanner normalization.

This module never discovers or imports repository-provided adapters.  It reparses
manifest-bound stdout with a closed set of built-in parser classes and compares the
entire normalized finding inventory.  The only tolerated delta is the
``metadata.location_validation`` annotation added later by the trusted host.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal

from pydantic import ValidationError

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    LocationValidation,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.scanners.base import ScannerAdapter
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.scanners.trivy import TrivyScanner

__all__ = [
    "CODEQL_AUXILIARY_SARIF_REPLAY_REQUIREMENT",
    "CodeQLAuxiliarySarifReplayRequirement",
    "ScannerNormalizationReplayError",
    "reparse_trusted_scanner_stdout",
    "trusted_stdout_scanner_names",
    "validate_real_scanner_normalization_replay",
]


class ScannerNormalizationReplayError(ValueError):
    """Retained scanner output cannot recreate its claimed normalized semantics."""


@dataclass(frozen=True, slots=True)
class CodeQLAuxiliarySarifReplayRequirement:
    """Typed remaining requirement before CodeQL can receive replay authority."""

    scanner: Literal["codeql"] = "codeql"
    artifact_name: Literal["codeql.sarif"] = "codeql.sarif"
    required_bindings: tuple[str, ...] = ("normalized path", "SHA-256", "byte length")
    supported: Literal[False] = False
    reason: str = (
        "CodeQL findings are parsed from an auxiliary SARIF file rather than retained stdout; "
        "ScannerRun does not yet bind that auxiliary file's normalized path, SHA-256, and byte "
        "length, so it cannot receive current REAL normalization authority."
    )


CODEQL_AUXILIARY_SARIF_REPLAY_REQUIREMENT = CodeQLAuxiliarySarifReplayRequirement()

_AdapterFactory = Callable[[], ScannerAdapter]
_TRUSTED_STDOUT_ADAPTER_FACTORIES: MappingProxyType[str, _AdapterFactory] = MappingProxyType(
    {
        "gitleaks": GitleaksScanner,
        "osv": OsvScanner,
        "semgrep": SemgrepScanner,
        "slither": SlitherScanner,
        "trivy": TrivyScanner,
    }
)
_MISSING = object()


def trusted_stdout_scanner_names() -> frozenset[str]:
    """Return the closed set of built-in scanners with stdout-only replay."""

    return frozenset(_TRUSTED_STDOUT_ADAPTER_FACTORIES)


def reparse_trusted_scanner_stdout(
    *,
    scanner: str,
    repository_root: Path,
    retained_stdout: bytes,
) -> tuple[ScannerFinding, ...]:
    """Reparse exact retained bytes with one fixed built-in scanner adapter.

    Decoding intentionally matches :class:`ScannerAdapter` execution, which uses UTF-8
    replacement before calling a parser.  Parser diagnostics never include retained output.
    """

    factory = _TRUSTED_STDOUT_ADAPTER_FACTORIES.get(scanner)
    if factory is None:
        raise ScannerNormalizationReplayError(
            f"scanner {scanner!r} has no trusted built-in stdout normalizer"
        )
    root = _canonical_repository_root(repository_root)
    adapter = factory()
    if adapter.name != scanner:
        raise ScannerNormalizationReplayError("trusted scanner normalizer identity is inconsistent")
    if len(retained_stdout) > adapter.max_stdout_bytes:
        raise ScannerNormalizationReplayError("retained scanner stdout exceeds its replay bound")
    try:
        findings = adapter.parse(
            root,
            retained_stdout.decode("utf-8", errors="replace"),
            root,
        )
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ScannerNormalizationReplayError(
            f"retained {scanner} stdout failed trusted normalization: {type(exc).__name__}"
        ) from exc
    normalized = tuple(
        ScannerFinding.model_validate(finding.model_dump(mode="python")) for finding in findings
    )
    if any(finding.scanner != scanner for finding in normalized):
        raise ScannerNormalizationReplayError(
            "trusted scanner normalizer emitted a different scanner identity"
        )
    return normalized


def validate_real_scanner_normalization_replay(
    *,
    run: ScannerRun,
    repository_root: Path,
    retained_stdout: bytes,
) -> tuple[ScannerFinding, ...]:
    """Require a current REAL scanner claim to equal deterministic stdout replay."""

    if run.scanner not in _TRUSTED_STDOUT_ADAPTER_FACTORIES:
        raise ScannerNormalizationReplayError(
            f"REAL scanner {run.scanner!r} has no trusted built-in stdout normalizer"
        )
    if run.execution_evidence is not ExecutionEvidenceKind.REAL:
        raise ScannerNormalizationReplayError(
            "scanner normalization authority requires REAL evidence"
        )
    if run.status is not ScannerStatus.SUCCESS or not run.machine_output_validated:
        raise ScannerNormalizationReplayError(
            "scanner normalization authority requires successful validated machine output"
        )
    if run.process_exit_code is None:
        raise ScannerNormalizationReplayError(
            "scanner normalization authority requires an observed process exit code"
        )
    adapter = _TRUSTED_STDOUT_ADAPTER_FACTORIES[run.scanner]()
    if run.process_exit_code not in adapter.finding_exit_codes:
        raise ScannerNormalizationReplayError(
            "scanner success uses an exit code rejected by its built-in adapter"
        )
    if run.raw_output_path is None or run.raw_output_sha256 is None:
        raise ScannerNormalizationReplayError(
            "scanner normalization authority requires retained stdout byte custody"
        )
    if run.raw_output_bytes != len(retained_stdout):
        raise ScannerNormalizationReplayError("retained scanner stdout byte length differs")
    if hashlib.sha256(retained_stdout).hexdigest() != run.raw_output_sha256:
        raise ScannerNormalizationReplayError("retained scanner stdout SHA-256 differs")

    replayed = reparse_trusted_scanner_stdout(
        scanner=run.scanner,
        repository_root=repository_root,
        retained_stdout=retained_stdout,
    )
    expected = _without_host_location_validation(run.findings)
    if replayed != expected:
        raise ScannerNormalizationReplayError(
            "retained scanner stdout differs from the complete normalized finding inventory"
        )
    return replayed


def _canonical_repository_root(root: Path) -> Path:
    absolute = Path(os.path.abspath(root))
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ScannerNormalizationReplayError("scanner replay repository is unavailable") from exc
    if (
        resolved != absolute
        or not resolved.is_dir()
        or resolved.is_symlink()
        or resolved.is_junction()
    ):
        raise ScannerNormalizationReplayError(
            "scanner replay repository must be a canonical non-linked directory"
        )
    return resolved


def _without_host_location_validation(
    findings: Sequence[ScannerFinding],
) -> tuple[ScannerFinding, ...]:
    normalized: list[ScannerFinding] = []
    for finding in findings:
        payload = finding.model_dump(mode="python")
        metadata = dict(finding.metadata)
        annotation = metadata.pop("location_validation", _MISSING)
        if annotation is not _MISSING:
            _validate_host_location_annotation(finding, annotation)
        payload["metadata"] = metadata
        normalized.append(ScannerFinding.model_validate(payload))
    return tuple(normalized)


def _validate_host_location_annotation(finding: ScannerFinding, annotation: object) -> None:
    if not isinstance(annotation, list) or len(annotation) != len(finding.locations):
        raise ScannerNormalizationReplayError(
            "host scanner location validation does not cover the exact location inventory"
        )
    try:
        for item in annotation:
            LocationValidation.model_validate(item)
    except ValidationError as exc:
        raise ScannerNormalizationReplayError(
            "host scanner location validation is not typed evidence"
        ) from exc
