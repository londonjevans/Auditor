"""Read-only verification of hash-linked run evidence manifests."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.config import AuditConfig
from mmaudit.constants import VERSION
from mmaudit.models.schemas import AuditReport, StrictModel
from mmaudit.orchestration.manifest import (
    ManifestFileBinding,
    ManifestHashBinding,
    RunEvidenceManifest,
    build_run_evidence_manifest,
    canonical_sha256,
    collect_run_artifacts,
    load_run_evidence_manifest,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_REPORT_BYTES = 100_000_000
_MAX_VERIFICATION_BYTES = 100_000_000


class RunVerificationStatus(StrEnum):
    CURRENT = "current"
    STALE = "stale"


class RunVerificationCategory(StrEnum):
    MANIFEST = "manifest"
    SOURCE = "source"
    CONFIGURATION = "configuration"
    PROMPT = "prompt"
    MODEL = "model"
    TOOL = "tool"
    COMPILER = "compiler"
    ISOLATION = "isolation"
    SEED = "seed"
    CORPUS = "corpus"
    HARNESS = "harness"
    REPRODUCTION = "reproduction"
    COVERAGE = "coverage"
    ARTIFACT = "artifact"
    CERTIFICATE = "certificate"


class RunVerificationMismatchKind(StrEnum):
    MISSING = "missing"
    UNEXPECTED = "unexpected"
    CHANGED = "changed"
    UNSAFE = "unsafe"
    UNVERIFIABLE = "unverifiable"


class RunVerificationMismatch(StrictModel):
    category: RunVerificationCategory
    identifier: str = Field(min_length=1, max_length=4_096)
    kind: RunVerificationMismatchKind
    expected_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    observed_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    expected_size: int | None = Field(default=None, ge=0)
    observed_size: int | None = Field(default=None, ge=0)

    @field_validator("identifier")
    @classmethod
    def identifier_is_printable(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("run-verification identifiers must be printable")
        return value

    @model_validator(mode="after")
    def evidence_matches_kind(self) -> RunVerificationMismatch:
        if self.kind is RunVerificationMismatchKind.MISSING and (
            self.expected_sha256 is None or self.observed_sha256 is not None
        ):
            raise ValueError("missing run evidence requires only an expected hash")
        if self.kind is RunVerificationMismatchKind.UNEXPECTED and (
            self.expected_sha256 is not None or self.observed_sha256 is None
        ):
            raise ValueError("unexpected run evidence requires only an observed hash")
        if self.kind is RunVerificationMismatchKind.CHANGED and (
            self.expected_sha256 is None or self.observed_sha256 is None
        ):
            raise ValueError("changed run evidence requires expected and observed hashes")
        return self


class RunVerificationPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    status: RunVerificationStatus
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    mismatches: list[RunVerificationMismatch] = Field(max_length=200_000)

    @model_validator(mode="after")
    def status_and_mismatches_are_consistent(self) -> RunVerificationPayload:
        keys = [(item.category.value, item.identifier, item.kind.value) for item in self.mismatches]
        if keys != sorted(set(keys)):
            raise ValueError("run-verification mismatches must be unique and sorted")
        expected_status = (
            RunVerificationStatus.CURRENT if not self.mismatches else RunVerificationStatus.STALE
        )
        if self.status is not expected_status:
            raise ValueError("run-verification status is inconsistent")
        return self


class RunVerification(RunVerificationPayload):
    verification_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def verification_hash_matches(self) -> RunVerification:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"verification_sha256"}))
        if self.verification_sha256 != expected:
            raise ValueError("run verification hash is inconsistent")
        return self


_BINDING_CATEGORIES = {
    "configuration": RunVerificationCategory.CONFIGURATION,
    "prompts": RunVerificationCategory.PROMPT,
    "models": RunVerificationCategory.MODEL,
    "tools": RunVerificationCategory.TOOL,
    "compilers": RunVerificationCategory.COMPILER,
    "isolation": RunVerificationCategory.ISOLATION,
    "seeds": RunVerificationCategory.SEED,
    "corpora": RunVerificationCategory.CORPUS,
    "harnesses": RunVerificationCategory.HARNESS,
    "reproductions": RunVerificationCategory.REPRODUCTION,
    "coverage": RunVerificationCategory.COVERAGE,
}


def verify_run_evidence(
    *,
    manifest_path: Path,
    run_dir: Path,
    repository_root: Path,
    config: AuditConfig,
) -> RunVerification:
    """Reconcile local files and projections without running repository code."""

    manifest = load_run_evidence_manifest(manifest_path)
    root = _safe_directory(run_dir, "run")
    source_root = _safe_directory(repository_root, "repository")
    mismatches: list[RunVerificationMismatch] = []
    mismatches.extend(_source_mismatches(manifest, source_root))

    observed_artifacts = collect_run_artifacts(root)
    mismatches.extend(
        _file_binding_mismatches(
            manifest.artifacts,
            observed_artifacts,
            default_category=RunVerificationCategory.ARTIFACT,
        )
    )

    report = _load_report(root)
    if report is None:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.MANIFEST,
                identifier="bindings/recalculation",
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
                expected_sha256=manifest.manifest_sha256,
            )
        )
    else:
        try:
            observed_manifest = build_run_evidence_manifest(
                run_dir=root,
                report=report,
                config=config,
            )
        except (OSError, ValueError):
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.MANIFEST,
                    identifier="bindings/recalculation",
                    kind=RunVerificationMismatchKind.UNVERIFIABLE,
                    expected_sha256=manifest.manifest_sha256,
                )
            )
        else:
            mismatches.extend(_identity_mismatches(manifest, observed_manifest))
            mismatches.extend(_binding_mismatches(manifest, observed_manifest))

    ordered = sorted(
        mismatches,
        key=lambda item: (item.category.value, item.identifier, item.kind.value),
    )
    payload = RunVerificationPayload(
        status=(RunVerificationStatus.CURRENT if not ordered else RunVerificationStatus.STALE),
        run_id=manifest.run_id,
        manifest_sha256=manifest.manifest_sha256,
        mismatches=ordered,
    )
    serialized = payload.model_dump(mode="json")
    return RunVerification.model_validate(
        {
            **serialized,
            "verification_sha256": canonical_sha256(serialized),
        }
    )


def write_run_verification(path: Path, verification: RunVerification) -> None:
    """Write bounded, normalized verification evidence without following links."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive run-verification filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("run-verification destination may not be a link")
    if path.exists() and (
        not path.is_file()
        or path.stat().st_nlink != 1
        or path.stat().st_size > _MAX_VERIFICATION_BYTES
    ):
        raise ValueError("run-verification destination must be an unshared file")
    serialized = stable_json(verification)
    if len(serialized.encode("utf-8")) > _MAX_VERIFICATION_BYTES:
        raise ValueError("run verification exceeds the bounded output size")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def _source_mismatches(
    manifest: RunEvidenceManifest,
    repository_root: Path,
) -> list[RunVerificationMismatch]:
    mismatches: list[RunVerificationMismatch] = []
    for expected in manifest.sources:
        candidate = repository_root / normalize_relative_path(expected.path)
        if candidate.is_symlink() or candidate.is_junction():
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=expected.path,
                    kind=RunVerificationMismatchKind.UNSAFE,
                    expected_sha256=expected.sha256,
                    expected_size=expected.size,
                )
            )
            continue
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(repository_root)
        except (OSError, ValueError):
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=expected.path,
                    kind=RunVerificationMismatchKind.MISSING,
                    expected_sha256=expected.sha256,
                    expected_size=expected.size,
                )
            )
            continue
        metadata = resolved.stat()
        if not resolved.is_file() or metadata.st_nlink != 1:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=expected.path,
                    kind=RunVerificationMismatchKind.UNSAFE,
                    expected_sha256=expected.sha256,
                    expected_size=expected.size,
                )
            )
            continue
        observed = ManifestFileBinding(
            path=expected.path,
            sha256=_file_sha256(resolved),
            size=metadata.st_size,
        )
        if observed.sha256 != expected.sha256 or observed.size != expected.size:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=expected.path,
                    kind=RunVerificationMismatchKind.CHANGED,
                    expected_sha256=expected.sha256,
                    observed_sha256=observed.sha256,
                    expected_size=expected.size,
                    observed_size=observed.size,
                )
            )
    return mismatches


def _file_binding_mismatches(
    expected_bindings: list[ManifestFileBinding],
    observed_bindings: list[ManifestFileBinding],
    *,
    default_category: RunVerificationCategory,
) -> list[RunVerificationMismatch]:
    expected = {binding.path: binding for binding in expected_bindings}
    observed = {binding.path: binding for binding in observed_bindings}
    mismatches: list[RunVerificationMismatch] = []
    for path in sorted(set(expected) | set(observed)):
        expected_binding = expected.get(path)
        observed_binding = observed.get(path)
        category = (
            RunVerificationCategory.CERTIFICATE
            if "benchmark-certificate" in path
            else default_category
        )
        if expected_binding is None and observed_binding is not None:
            mismatches.append(
                RunVerificationMismatch(
                    category=category,
                    identifier=path,
                    kind=RunVerificationMismatchKind.UNEXPECTED,
                    observed_sha256=observed_binding.sha256,
                    observed_size=observed_binding.size,
                )
            )
        elif expected_binding is not None and observed_binding is None:
            mismatches.append(
                RunVerificationMismatch(
                    category=category,
                    identifier=path,
                    kind=RunVerificationMismatchKind.MISSING,
                    expected_sha256=expected_binding.sha256,
                    expected_size=expected_binding.size,
                )
            )
        elif (
            expected_binding is not None
            and observed_binding is not None
            and (
                expected_binding.sha256 != observed_binding.sha256
                or expected_binding.size != observed_binding.size
            )
        ):
            mismatches.append(
                RunVerificationMismatch(
                    category=category,
                    identifier=path,
                    kind=RunVerificationMismatchKind.CHANGED,
                    expected_sha256=expected_binding.sha256,
                    observed_sha256=observed_binding.sha256,
                    expected_size=expected_binding.size,
                    observed_size=observed_binding.size,
                )
            )
    return mismatches


def _identity_mismatches(
    expected: RunEvidenceManifest,
    observed: RunEvidenceManifest,
) -> list[RunVerificationMismatch]:
    fields = {
        "tool_version": (expected.tool_version, VERSION),
        "run_id": (expected.run_id, observed.run_id),
        "repository_root_name": (
            expected.repository_root_name,
            observed.repository_root_name,
        ),
        "git_commit": (expected.git_commit, observed.git_commit),
    }
    return [
        RunVerificationMismatch(
            category=RunVerificationCategory.MANIFEST,
            identifier=f"identity/{name}",
            kind=RunVerificationMismatchKind.CHANGED,
            expected_sha256=canonical_sha256(expected_value),
            observed_sha256=canonical_sha256(observed_value),
        )
        for name, (expected_value, observed_value) in sorted(fields.items())
        if expected_value != observed_value
    ]


def _binding_mismatches(
    expected: RunEvidenceManifest,
    observed: RunEvidenceManifest,
) -> list[RunVerificationMismatch]:
    mismatches: list[RunVerificationMismatch] = []
    for field_name, category in _BINDING_CATEGORIES.items():
        expected_bindings: list[ManifestHashBinding] = getattr(
            expected.bindings,
            field_name,
        )
        observed_bindings: list[ManifestHashBinding] = getattr(
            observed.bindings,
            field_name,
        )
        expected_by_id = {binding.identifier: binding for binding in expected_bindings}
        observed_by_id = {binding.identifier: binding for binding in observed_bindings}
        for identifier in sorted(set(expected_by_id) | set(observed_by_id)):
            expected_binding = expected_by_id.get(identifier)
            observed_binding = observed_by_id.get(identifier)
            if expected_binding is None and observed_binding is not None:
                mismatches.append(
                    RunVerificationMismatch(
                        category=category,
                        identifier=identifier,
                        kind=RunVerificationMismatchKind.UNEXPECTED,
                        observed_sha256=observed_binding.sha256,
                    )
                )
            elif expected_binding is not None and observed_binding is None:
                mismatches.append(
                    RunVerificationMismatch(
                        category=category,
                        identifier=identifier,
                        kind=RunVerificationMismatchKind.MISSING,
                        expected_sha256=expected_binding.sha256,
                    )
                )
            elif (
                expected_binding is not None
                and observed_binding is not None
                and expected_binding.sha256 != observed_binding.sha256
            ):
                mismatches.append(
                    RunVerificationMismatch(
                        category=category,
                        identifier=identifier,
                        kind=RunVerificationMismatchKind.CHANGED,
                        expected_sha256=expected_binding.sha256,
                        observed_sha256=observed_binding.sha256,
                    )
                )
    return mismatches


def _load_report(run_dir: Path) -> AuditReport | None:
    path = run_dir / "final-findings.json"
    if path.is_symlink() or path.is_junction() or not path.is_file():
        return None
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_REPORT_BYTES:
        return None
    try:
        return AuditReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _safe_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"run verification {label} root may not be a link")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"run verification {label} root must be a directory")
    return resolved


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
