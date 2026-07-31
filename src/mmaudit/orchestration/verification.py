"""Read-only verification of hash-linked run evidence manifests."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    parse_canonical_audit_config,
)
from mmaudit.constants import VERSION
from mmaudit.models.schemas import AuditReport, StrictModel
from mmaudit.orchestration.manifest import (
    ManifestFileBinding,
    ManifestHashBinding,
    RunEvidenceManifest,
    canonical_sha256,
    collect_run_artifacts,
    load_run_evidence_manifest,
    rebuild_run_evidence_manifest_for_verification,
    resolve_run_evidence_config,
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
    config: AuditConfig | None = None,
    file_config: AuditConfig | None = None,
) -> RunVerification:
    """Reconcile local files and projections without running repository code."""

    manifest = load_run_evidence_manifest(manifest_path)
    resolved_config = config
    if manifest.run_configuration is not None and file_config is not None:
        resolved_config = resolve_run_evidence_config(
            manifest,
            file_config=file_config,
        )
    elif resolved_config is None and manifest.run_configuration is not None:
        resolved_config = resolve_run_evidence_config(manifest)
    elif resolved_config is None and file_config is not None:
        resolved_config = file_config.effective()
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

    report_binding = next(
        (binding for binding in manifest.artifacts if binding.path == "final-findings.json"),
        None,
    )
    try:
        report = load_manifest_bound_report(run_dir=root, manifest=manifest)
    except ValueError:
        report = None
    metadata_binding = next(
        (binding for binding in manifest.artifacts if binding.path == "metadata.json"),
        None,
    )
    emitted_metadata, metadata_present = _load_metadata_artifact(root, metadata_binding)
    if manifest.schema_version == "1.1" and not metadata_present:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.MANIFEST,
                identifier="metadata/missing",
                kind=(
                    RunVerificationMismatchKind.MISSING
                    if metadata_binding is not None
                    else RunVerificationMismatchKind.UNVERIFIABLE
                ),
                expected_sha256=(metadata_binding.sha256 if metadata_binding is not None else None),
            )
        )
    elif manifest.schema_version == "1.1" and metadata_binding is None:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.MANIFEST,
                identifier="metadata/binding",
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
            )
        )
    if metadata_present and emitted_metadata is None:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.MANIFEST,
                identifier="metadata/validation",
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
                expected_sha256=(metadata_binding.sha256 if metadata_binding is not None else None),
            )
        )
    if report is not None and emitted_metadata is not None:
        mismatches.extend(
            _metadata_artifact_mismatches(
                manifest=manifest,
                report=report,
                metadata=emitted_metadata,
            )
        )
    if report is None or resolved_config is None:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.MANIFEST,
                identifier=(
                    "configuration/reconstruction"
                    if resolved_config is None
                    else "bindings/recalculation"
                ),
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
                expected_sha256=manifest.manifest_sha256,
            )
        )
        if report is None and report_binding is not None:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.MANIFEST,
                    identifier="report/validation",
                    kind=RunVerificationMismatchKind.UNVERIFIABLE,
                    expected_sha256=report_binding.sha256,
                )
            )
    else:
        mismatches.extend(
            _report_configuration_mismatches(
                manifest=manifest,
                report=report,
                resolved_config=resolved_config,
            )
        )
        observed_file_config = resolved_config
        observed_environment_overrides = AuditConfigOverrides()
        observed_cli_overrides = AuditConfigOverrides()
        observed_run_options = AuditRunOptions()
        if manifest.run_configuration is not None:
            observed_run_options = manifest.run_configuration.run_options
            if file_config is not None:
                observed_file_config = file_config
                observed_environment_overrides = manifest.run_configuration.environment_overrides
                observed_cli_overrides = manifest.run_configuration.cli_overrides
            elif (
                resolved_config.stable_hash() == manifest.run_configuration.effective_config_sha256
            ):
                observed_file_config = parse_canonical_audit_config(
                    manifest.run_configuration.file_configuration_json
                )
                observed_environment_overrides = manifest.run_configuration.environment_overrides
                observed_cli_overrides = manifest.run_configuration.cli_overrides
        build_arguments: dict[str, Any] = {
            "file_config": observed_file_config,
            "environment_overrides": observed_environment_overrides,
            "cli_overrides": observed_cli_overrides,
            "run_options": observed_run_options,
        }
        try:
            projection_metadata = dict(report.metadata)
            projection_metadata["run_options"] = observed_run_options.model_dump(mode="json")
            projection_metadata["configuration_provenance"] = {
                "file_config_sha256": observed_file_config.stable_hash(),
                "environment_overrides_sha256": (observed_environment_overrides.stable_hash()),
                "cli_overrides_sha256": observed_cli_overrides.stable_hash(),
                "run_options_sha256": observed_run_options.stable_hash(),
            }
            projection_report = report.model_copy(
                update={
                    "configuration_hash": resolved_config.stable_hash(),
                    "model_configuration_hash": resolved_config.model_hash(),
                    "audit_profile": resolved_config.profile,
                    "metadata": projection_metadata,
                }
            )
            observed_manifest = rebuild_run_evidence_manifest_for_verification(
                run_dir=root,
                report=projection_report,
                config=resolved_config,
                sealed_manifest=manifest,
                **build_arguments,
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
            mismatches.extend(_run_configuration_mismatches(manifest, observed_manifest))
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


def _run_configuration_mismatches(
    expected: RunEvidenceManifest,
    observed: RunEvidenceManifest,
) -> list[RunVerificationMismatch]:
    if expected.run_configuration is None:
        return []
    expected_payload = expected.run_configuration.model_dump(mode="json")
    observed_payload = (
        observed.run_configuration.model_dump(mode="json")
        if observed.run_configuration is not None
        else None
    )
    if expected_payload == observed_payload:
        return []
    return [
        RunVerificationMismatch(
            category=RunVerificationCategory.CONFIGURATION,
            identifier="run/configuration-provenance",
            kind=RunVerificationMismatchKind.CHANGED,
            expected_sha256=canonical_sha256(expected_payload),
            observed_sha256=canonical_sha256(observed_payload),
        )
    ]


def _report_configuration_mismatches(
    *,
    manifest: RunEvidenceManifest,
    report: AuditReport,
    resolved_config: AuditConfig,
) -> list[RunVerificationMismatch]:
    """Reject a report whose declared configuration differs from sealed provenance."""

    run_configuration = manifest.run_configuration
    expected_config_sha256 = (
        run_configuration.effective_config_sha256
        if run_configuration is not None
        else resolved_config.stable_hash()
    )
    expected_model_sha256 = (
        run_configuration.model_config_sha256
        if run_configuration is not None
        else resolved_config.model_hash()
    )
    expected_profile = (
        run_configuration.requested_profile.value
        if run_configuration is not None
        else resolved_config.profile.value
    )
    mismatches: list[RunVerificationMismatch] = []
    if report.configuration_hash != expected_config_sha256:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.CONFIGURATION,
                identifier="report/configuration-hash",
                kind=RunVerificationMismatchKind.CHANGED,
                expected_sha256=expected_config_sha256,
                observed_sha256=report.configuration_hash,
            )
        )
    if report.model_configuration_hash != expected_model_sha256:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.CONFIGURATION,
                identifier="report/model-configuration-hash",
                kind=RunVerificationMismatchKind.CHANGED,
                expected_sha256=expected_model_sha256,
                observed_sha256=report.model_configuration_hash,
            )
        )
    if report.audit_profile.value != expected_profile:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.CONFIGURATION,
                identifier="report/audit-profile",
                kind=RunVerificationMismatchKind.CHANGED,
                expected_sha256=canonical_sha256(expected_profile),
                observed_sha256=canonical_sha256(report.audit_profile.value),
            )
        )
    if run_configuration is not None:
        expected_run_options = run_configuration.run_options.model_dump(mode="json")
        observed_run_options = report.metadata.get("run_options")
        if observed_run_options != expected_run_options:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.CONFIGURATION,
                    identifier="report/run-options",
                    kind=RunVerificationMismatchKind.CHANGED,
                    expected_sha256=canonical_sha256(expected_run_options),
                    observed_sha256=canonical_sha256(observed_run_options),
                )
            )
        expected_provenance = {
            "file_config_sha256": run_configuration.file_config_sha256,
            "environment_overrides_sha256": (run_configuration.environment_overrides_sha256),
            "cli_overrides_sha256": run_configuration.cli_overrides_sha256,
            "run_options_sha256": run_configuration.run_options_sha256,
        }
        observed_provenance = report.metadata.get("configuration_provenance")
        if observed_provenance != expected_provenance:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.CONFIGURATION,
                    identifier="report/configuration-provenance",
                    kind=RunVerificationMismatchKind.CHANGED,
                    expected_sha256=canonical_sha256(expected_provenance),
                    observed_sha256=canonical_sha256(observed_provenance),
                )
            )
    return mismatches


def _metadata_artifact_mismatches(
    *,
    manifest: RunEvidenceManifest,
    report: AuditReport,
    metadata: dict[str, Any],
) -> list[RunVerificationMismatch]:
    """Cross-check independently emitted run metadata against report and manifest state."""

    run_configuration = manifest.run_configuration
    expected_config_sha256 = (
        run_configuration.effective_config_sha256
        if run_configuration is not None
        else report.configuration_hash
    )
    expected_model_sha256 = (
        run_configuration.model_config_sha256
        if run_configuration is not None
        else report.model_configuration_hash
    )
    expected_run_options = (
        run_configuration.run_options.model_dump(mode="json")
        if run_configuration is not None
        else report.metadata.get("run_options")
    )
    expected_provenance = (
        {
            "file_config_sha256": run_configuration.file_config_sha256,
            "environment_overrides_sha256": (run_configuration.environment_overrides_sha256),
            "cli_overrides_sha256": run_configuration.cli_overrides_sha256,
            "run_options_sha256": run_configuration.run_options_sha256,
        }
        if run_configuration is not None
        else report.metadata.get("configuration_provenance")
    )
    comparisons: tuple[
        tuple[RunVerificationCategory, str, Any, Any],
        ...,
    ] = (
        (
            RunVerificationCategory.MANIFEST,
            "metadata/run-id",
            manifest.run_id,
            metadata.get("run_id"),
        ),
        (
            RunVerificationCategory.MANIFEST,
            "metadata/completed",
            report.completed,
            metadata.get("completed"),
        ),
        (
            RunVerificationCategory.MANIFEST,
            "metadata/privacy",
            report.privacy,
            metadata.get("privacy"),
        ),
        (
            RunVerificationCategory.CONFIGURATION,
            "metadata/configuration-hash",
            expected_config_sha256,
            metadata.get("configuration_hash"),
        ),
        (
            RunVerificationCategory.CONFIGURATION,
            "metadata/model-configuration-hash",
            expected_model_sha256,
            metadata.get("model_configuration_hash"),
        ),
        (
            RunVerificationCategory.CONFIGURATION,
            "metadata/run-options",
            expected_run_options,
            metadata.get("metadata", {}).get("run_options")
            if isinstance(metadata.get("metadata"), dict)
            else None,
        ),
        (
            RunVerificationCategory.CONFIGURATION,
            "metadata/configuration-provenance",
            expected_provenance,
            metadata.get("metadata", {}).get("configuration_provenance")
            if isinstance(metadata.get("metadata"), dict)
            else None,
        ),
    )
    mismatches: list[RunVerificationMismatch] = []
    for category, identifier, expected, observed in comparisons:
        expected_sha256 = canonical_sha256(expected)
        observed_sha256 = canonical_sha256(observed)
        if observed_sha256 != expected_sha256:
            mismatches.append(
                RunVerificationMismatch(
                    category=category,
                    identifier=identifier,
                    kind=RunVerificationMismatchKind.CHANGED,
                    expected_sha256=expected_sha256,
                    observed_sha256=observed_sha256,
                )
            )
    return mismatches


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


def load_manifest_bound_report(
    *,
    run_dir: Path,
    manifest: RunEvidenceManifest,
) -> AuditReport:
    """Load exactly the report bytes sealed by a manifest artifact binding."""

    binding = next(
        (item for item in manifest.artifacts if item.path == "final-findings.json"),
        None,
    )
    if binding is None:
        raise ValueError("run manifest does not bind final-findings.json")
    data, present = _read_bound_regular_file(
        run_dir / "final-findings.json",
        expected=binding,
        max_bytes=_MAX_REPORT_BYTES,
    )
    if not present or data is None:
        raise ValueError("run report is missing, unsafe, or differs from its manifest binding")
    try:
        return AuditReport.model_validate(_decode_json_object(data, label="run report"))
    except ValueError as exc:
        raise ValueError("run report is not valid bound audit evidence") from exc


def _load_metadata_artifact(
    run_dir: Path,
    expected: ManifestFileBinding | None,
) -> tuple[dict[str, Any] | None, bool]:
    path = run_dir / "metadata.json"
    data, present = _read_bound_regular_file(
        path,
        expected=expected,
        max_bytes=_MAX_REPORT_BYTES,
    )
    if data is None:
        return None, present
    try:
        value = _decode_json_object(data, label="metadata artifact")
    except ValueError:
        return None, True
    return value, True


def _read_bound_regular_file(
    path: Path,
    *,
    expected: ManifestFileBinding | None,
    max_bytes: int,
) -> tuple[bytes | None, bool]:
    """Read one non-link file once and reject path or byte changes around that read."""

    try:
        path_before = path.lstat()
    except FileNotFoundError:
        return None, False
    except OSError:
        return None, True
    if not stat.S_ISREG(path_before.st_mode) or path_before.st_nlink != 1:
        return None, True
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, True
    try:
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            data = handle.read(max_bytes + 1)
            finished = os.fstat(handle.fileno())
    except OSError:
        return None, True
    try:
        path_after = path.lstat()
    except OSError:
        return None, True
    identities = {
        _stat_identity(path_before),
        _stat_identity(opened),
        _stat_identity(finished),
        _stat_identity(path_after),
    }
    if len(identities) != 1 or len(data) > max_bytes:
        return None, True
    observed_sha256 = hashlib.sha256(data).hexdigest()
    if expected is not None and (len(data) != expected.size or observed_sha256 != expected.sha256):
        return None, True
    return data, True


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _decode_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise ValueError(f"{label} contains non-finite value: {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError(f"{label} contains an out-of-range number")
        return parsed

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


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
