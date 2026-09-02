"""Read-only verification of hash-linked run evidence manifests."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    parse_canonical_audit_config,
)
from mmaudit.constants import VERSION
from mmaudit.language_plugins import parse_language_capability_payload
from mmaudit.models.schemas import (
    AuditReport,
    InvariantSuite,
    LanguageCapabilityArtifact,
    StrictModel,
)
from mmaudit.models.sharding import SolidityGraphsArtifact, SolidityIndexArtifact
from mmaudit.orchestration.actor_model import withhold_actor_model_from_discovery
from mmaudit.orchestration.manifest import (
    LANGUAGE_CAPABILITY_ARTIFACT_PATH,
    ManifestFileBinding,
    ManifestHashBinding,
    RunEvidenceManifest,
    canonical_sha256,
    collect_run_artifacts,
    load_run_evidence_manifest,
    open_manifest_bound_json_artifacts,
    rebuild_run_evidence_manifest_for_verification,
    resolve_run_evidence_config,
    validate_solidity_shard_artifacts,
)
from mmaudit.orchestration.prior_audit import withhold_prior_audit_from_discovery
from mmaudit.orchestration.scope import filter_discovery_for_scope
from mmaudit.reporting.json_report import stable_json
from mmaudit.reporting.status import report_status_metadata
from mmaudit.repository.configuration_custody import (
    ConfigurationInputObservation,
    observe_configuration_input,
    require_unchanged_configuration_input,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    require_unchanged_unlinked_directory,
)
from mmaudit.repository.discovery import (
    DiscoveryResult,
    discover_repository,
    source_language_for_path,
)
from mmaudit.repository.ignore import (
    IgnoreMatcher,
    normalize_relative_path,
    safe_ignore_file,
)
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.solidity.invariants import validate_protocol_profile_replay
from mmaudit.solidity.projects import discover_solidity_projects

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_REPORT_BYTES = 100_000_000
_MAX_VERIFICATION_BYTES = 100_000_000
_PROFILE_REPLAY_ARTIFACT_NAMES = (
    "solidity-graphs.json",
    "solidity-index.json",
    "solidity-invariants.json",
)


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
    configuration_root: Path | None = None,
    config: AuditConfig | None = None,
    file_config: AuditConfig | None = None,
) -> RunVerification:
    """Reconcile local files and projections without running repository code."""

    root_observation = _safe_directory(run_dir, "run")
    source_observation = _safe_directory(repository_root, "repository")
    configuration_root_observation = (
        None if configuration_root is None else _safe_directory(configuration_root, "configuration")
    )
    root = root_observation.path
    source_root = source_observation.path
    trusted_configuration_root = (
        None if configuration_root_observation is None else configuration_root_observation.path
    )
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
    configuration_before: ConfigurationInputObservation | None = None
    if trusted_configuration_root is not None and resolved_config is not None:
        configuration_before = observe_configuration_input(
            configuration_root=trusted_configuration_root,
            configured_ignore_path=resolved_config.repository.ignore_file,
        )
        assert configuration_root_observation is not None
        require_unchanged_unlinked_directory(
            configuration_root_observation,
            label="run verification configuration",
        )
    mismatches: list[RunVerificationMismatch] = []
    mismatches.extend(_source_mismatches(manifest, source_root))
    language_mismatches, reconstructed_discovery = _language_capability_source_mismatches(
        manifest=manifest,
        run_dir=root,
        repository_root=source_root,
        configuration_root=trusted_configuration_root,
        config=resolved_config,
    )
    mismatches.extend(language_mismatches)
    if configuration_before is not None and resolved_config is not None:
        require_unchanged_configuration_input(
            configuration_before,
            configured_ignore_path=resolved_config.repository.ignore_file,
        )
        assert configuration_root_observation is not None
        require_unchanged_unlinked_directory(
            configuration_root_observation,
            label="run verification configuration",
        )
    protocol_profile_replay_discovery: DiscoveryResult | None = None
    if reconstructed_discovery is not None and resolved_config is not None:
        try:
            scope_projects = discover_solidity_projects(
                reconstructed_discovery,
                resolved_config.smart_contracts,
            )
            protocol_profile_replay_discovery = filter_discovery_for_scope(
                reconstructed_discovery,
                scope_projects,
                resolved_config.scope.mode,
            )
        except (OSError, ValueError):
            protocol_profile_replay_discovery = None

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
    if report is not None:
        try:
            validate_solidity_shard_artifacts(root, report)
        except (OSError, ValueError):
            shard_binding = next(
                (
                    binding
                    for binding in manifest.artifacts
                    if binding.path == "solidity-shards.json"
                ),
                None,
            )
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.ARTIFACT,
                    identifier="solidity-shards/cross-artifact",
                    kind=RunVerificationMismatchKind.UNVERIFIABLE,
                    expected_sha256=(shard_binding.sha256 if shard_binding is not None else None),
                )
            )
        mismatches.extend(
            _protocol_profile_replay_mismatches(
                manifest=manifest,
                report=report,
                run_dir=root,
                discovery=protocol_profile_replay_discovery,
            )
        )
    metadata_binding = next(
        (binding for binding in manifest.artifacts if binding.path == "metadata.json"),
        None,
    )
    emitted_metadata, metadata_present = _load_metadata_artifact(root, metadata_binding)
    if manifest.schema_version in {"1.1", "1.2", "1.3", "1.4"} and not metadata_present:
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
    elif manifest.schema_version in {"1.1", "1.2", "1.3", "1.4"} and metadata_binding is None:
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
                protocol_profile_replay_discovery=protocol_profile_replay_discovery,
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

    require_unchanged_unlinked_directory(
        source_observation,
        label="run verification repository",
    )
    if configuration_root_observation is not None:
        require_unchanged_unlinked_directory(
            configuration_root_observation,
            label="run verification configuration",
        )
    require_unchanged_unlinked_directory(
        root_observation,
        label="run verification run",
    )

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
    return _source_binding_mismatches(manifest.sources, repository_root)


def _source_binding_mismatches(
    expected_sources: list[ManifestFileBinding],
    repository_root: Path,
    *,
    identifier_prefix: str = "",
) -> list[RunVerificationMismatch]:
    mismatches: list[RunVerificationMismatch] = []
    for expected in expected_sources:
        identifier = f"{identifier_prefix}{expected.path}"
        kind, observed_sha256, observed_size = _observe_source_binding(
            repository_root,
            expected.path,
        )
        if kind is not None:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=identifier,
                    kind=kind,
                    expected_sha256=expected.sha256,
                    observed_sha256=(
                        observed_sha256 if kind is RunVerificationMismatchKind.CHANGED else None
                    ),
                    expected_size=expected.size,
                    observed_size=(
                        observed_size if kind is RunVerificationMismatchKind.CHANGED else None
                    ),
                )
            )
            continue
        assert observed_sha256 is not None
        assert observed_size is not None
        if observed_sha256 != expected.sha256 or observed_size != expected.size:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=identifier,
                    kind=RunVerificationMismatchKind.CHANGED,
                    expected_sha256=expected.sha256,
                    observed_sha256=observed_sha256,
                    expected_size=expected.size,
                    observed_size=observed_size,
                )
            )
    return mismatches


def _observe_source_binding(
    repository_root: Path,
    relative_path: str,
) -> tuple[RunVerificationMismatchKind | None, str | None, int | None]:
    """Read one source through no-follow directory descriptors with stable identity custody."""

    parts = PurePosixPath(normalize_relative_path(relative_path)).parts
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_descriptors: list[int] = []
    file_descriptor: int | None = None
    try:
        current_descriptor = os.open(repository_root, directory_flags)
        directory_descriptors.append(current_descriptor)
        for part in parts[:-1]:
            current_descriptor = os.open(
                part,
                directory_flags,
                dir_fd=current_descriptor,
            )
            directory_descriptors.append(current_descriptor)
            if not stat.S_ISDIR(os.fstat(current_descriptor).st_mode):
                return RunVerificationMismatchKind.UNSAFE, None, None
        before = os.stat(parts[-1], dir_fd=current_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_REPORT_BYTES
        ):
            return RunVerificationMismatchKind.UNSAFE, None, None
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=current_descriptor)
        opened = os.fstat(file_descriptor)
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining > 0:
            chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        finished = os.fstat(file_descriptor)
        after = os.stat(parts[-1], dir_fd=current_descriptor, follow_symlinks=False)
        identities = {
            _stat_identity(before),
            _stat_identity(opened),
            _stat_identity(finished),
            _stat_identity(after),
        }
        data = b"".join(chunks)
        if len(identities) != 1 or len(data) != before.st_size:
            return RunVerificationMismatchKind.UNSAFE, None, None
        return None, hashlib.sha256(data).hexdigest(), len(data)
    except FileNotFoundError:
        return RunVerificationMismatchKind.MISSING, None, None
    except OSError:
        return RunVerificationMismatchKind.UNSAFE, None, None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for descriptor in reversed(directory_descriptors):
            os.close(descriptor)


def _language_capability_source_mismatches(
    *,
    manifest: RunEvidenceManifest,
    run_dir: Path,
    repository_root: Path,
    configuration_root: Path | None,
    config: AuditConfig | None,
) -> tuple[list[RunVerificationMismatch], DiscoveryResult | None]:
    binding = next(
        (item for item in manifest.artifacts if item.path == LANGUAGE_CAPABILITY_ARTIFACT_PATH),
        None,
    )
    if binding is None:
        if manifest.schema_version not in {"1.2", "1.3", "1.4"}:
            return [], None
        return (
            [
                RunVerificationMismatch(
                    category=RunVerificationCategory.ARTIFACT,
                    identifier="language-capability/source-inventory",
                    kind=RunVerificationMismatchKind.UNVERIFIABLE,
                )
            ],
            None,
        )
    try:
        with open_manifest_bound_json_artifacts(
            run_dir,
            (LANGUAGE_CAPABILITY_ARTIFACT_PATH,),
            required_bindings=(binding,),
        ) as payloads:
            artifact = parse_language_capability_payload(
                payloads[LANGUAGE_CAPABILITY_ARTIFACT_PATH]
            )
        source_bindings = [
            ManifestFileBinding(path=item.path, sha256=item.sha256, size=item.size)
            for item in artifact.files
        ]
    except (OSError, TypeError, ValueError):
        return (
            [
                RunVerificationMismatch(
                    category=RunVerificationCategory.ARTIFACT,
                    identifier="language-capability/source-inventory",
                    kind=RunVerificationMismatchKind.UNVERIFIABLE,
                    expected_sha256=binding.sha256,
                    expected_size=binding.size,
                )
            ],
            None,
        )

    mismatches = _source_binding_mismatches(
        source_bindings,
        repository_root,
        identifier_prefix="language-capability/",
    )
    for item in artifact.files:
        if source_language_for_path(item.path) != item.language:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=f"language-capability/{item.path}/language",
                    kind=RunVerificationMismatchKind.UNVERIFIABLE,
                    expected_sha256=item.sha256,
                    expected_size=item.size,
                )
            )
    if config is None:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.SOURCE,
                identifier="language-capability/source-inventory/reconstruction",
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
            )
        )
        return mismatches, None

    if configuration_root is None and manifest.schema_version == "1.4":
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.CONFIGURATION,
                identifier="language-capability/discovery/configuration-root",
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
            )
        )
        return mismatches, None

    try:
        observed_discovery = _reconstruct_current_discovery(
            artifact=artifact,
            run_dir=run_dir,
            repository_root=repository_root,
            configuration_root=configuration_root or repository_root,
            config=config,
            changed_since=(
                manifest.run_configuration.run_options.changed_since
                if manifest.run_configuration is not None
                else None
            ),
        )
    except (OSError, ValueError):
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.SOURCE,
                identifier="language-capability/source-inventory/reconstruction",
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
            )
        )
        return mismatches, None

    expected_by_path = {item.path: item for item in artifact.files}
    observed_by_path = {item.relative_path: item for item in observed_discovery.files}
    existing_mismatch_ids = {item.identifier for item in mismatches}
    for expected_path, expected in expected_by_path.items():
        identifier = f"language-capability/{expected_path}"
        observed = observed_by_path.get(expected_path)
        if observed is None and identifier not in existing_mismatch_ids:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=identifier,
                    kind=RunVerificationMismatchKind.MISSING,
                    expected_sha256=expected.sha256,
                    expected_size=expected.size,
                )
            )
        elif (
            observed is not None
            and identifier not in existing_mismatch_ids
            and (observed.sha256 != expected.sha256 or observed.size != expected.size)
        ):
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=identifier,
                    kind=RunVerificationMismatchKind.CHANGED,
                    expected_sha256=expected.sha256,
                    observed_sha256=observed.sha256,
                    expected_size=expected.size,
                    observed_size=observed.size,
                )
            )
    for observed in observed_discovery.files:
        if observed.relative_path not in expected_by_path:
            mismatches.append(
                RunVerificationMismatch(
                    category=RunVerificationCategory.SOURCE,
                    identifier=f"language-capability/{observed.relative_path}",
                    kind=RunVerificationMismatchKind.UNEXPECTED,
                    observed_sha256=observed.sha256,
                    observed_size=observed.size,
                )
            )
    observed_omitted = tuple(sorted(set(observed_discovery.omitted)))
    if observed_omitted != artifact.omitted:
        mismatches.append(
            RunVerificationMismatch(
                category=RunVerificationCategory.SOURCE,
                identifier="language-capability/omissions",
                kind=RunVerificationMismatchKind.CHANGED,
                expected_sha256=canonical_sha256(list(artifact.omitted)),
                observed_sha256=canonical_sha256(list(observed_omitted)),
                expected_size=len(artifact.omitted),
                observed_size=len(observed_omitted),
            )
        )
    return mismatches, observed_discovery


def _reconstruct_current_discovery(
    *,
    artifact: LanguageCapabilityArtifact,
    run_dir: Path,
    repository_root: Path,
    configuration_root: Path,
    config: AuditConfig,
    changed_since: str | None,
) -> DiscoveryResult:
    """Replay the retained bounded-discovery policy against current repository bytes."""

    expected_rules, output_exclusion = _effective_discovery_policy(
        run_dir=run_dir,
        repository_root=repository_root,
        configuration_root=configuration_root,
        config=config,
    )
    if artifact.effective_ignore_rules != expected_rules:
        raise ValueError("retained discovery ignore rules differ from effective configuration")
    if output_exclusion is not None and artifact.runtime_output_exclusion_root != output_exclusion:
        raise ValueError("retained output exclusion differs from the current run location")
    matcher = IgnoreMatcher.from_effective_rules(expected_rules)
    if output_exclusion is not None:
        matcher.rules.append("/" + output_exclusion + "/")
    discovery = discover_repository(
        repository_root,
        config.repository,
        matcher,
        changed_since=changed_since,
    )
    discovery, _prior_withheld = withhold_prior_audit_from_discovery(
        discovery,
        config.prior_audit.path,
    )
    discovery, _actor_withheld = withhold_actor_model_from_discovery(
        discovery,
        config.actor_model.path,
    )
    return discovery


def _effective_discovery_policy(
    *,
    run_dir: Path,
    repository_root: Path,
    configuration_root: Path,
    config: AuditConfig,
) -> tuple[tuple[str, ...], str | None]:
    """Rebuild trusted discovery policy without accepting artifact-supplied exclusions."""

    ignore_path = safe_ignore_file(
        configuration_root,
        config.repository.ignore_file,
    )
    matcher = IgnoreMatcher.from_file(ignore_path)
    retained_rules = list(matcher.rules)
    if config.prior_audit.path is not None:
        retained_rules.append("/" + normalize_relative_path(config.prior_audit.path))
    if config.actor_model.path is not None:
        retained_rules.append("/" + normalize_relative_path(config.actor_model.path))
    if config.dependency_preparation.offline_snapshot_path is not None:
        snapshot_parent = PurePosixPath(
            normalize_relative_path(config.dependency_preparation.offline_snapshot_path)
        ).parent
        retained_rules.append("/" + snapshot_parent.as_posix().rstrip("/") + "/")

    try:
        resolved_run = run_dir.resolve(strict=True)
        runs_root = resolved_run.parent
        if runs_root.name != "runs":
            raise ValueError("run directory is not in the canonical output layout")
        output_root = runs_root.parent.relative_to(repository_root.resolve(strict=True))
    except (OSError, ValueError):
        output_exclusion = None
    else:
        normalized_output = output_root.as_posix().rstrip("/")
        output_exclusion = normalized_output if normalized_output not in {"", "."} else None
    return tuple(retained_rules), output_exclusion


def _protocol_profile_replay_mismatches(
    *,
    manifest: RunEvidenceManifest,
    report: AuditReport,
    run_dir: Path,
    discovery: DiscoveryResult | None,
) -> list[RunVerificationMismatch]:
    """Fail closed when retained profile classifications do not replay from current source."""

    if manifest.schema_version != "1.4" or report.schema_version != "1.4":
        return []
    capability = report.language_capability
    if capability is None or not capability.evm_portfolio_applicable or report.invariants is None:
        return []

    bindings_by_path = {binding.path: binding for binding in manifest.artifacts}
    invariant_binding = bindings_by_path.get("solidity-invariants.json")

    def unverifiable() -> list[RunVerificationMismatch]:
        return [
            RunVerificationMismatch(
                category=RunVerificationCategory.ARTIFACT,
                identifier="protocol-profile/source-replay",
                kind=RunVerificationMismatchKind.UNVERIFIABLE,
                expected_sha256=(
                    invariant_binding.sha256 if invariant_binding is not None else None
                ),
                expected_size=(invariant_binding.size if invariant_binding is not None else None),
            )
        ]

    required_bindings = tuple(
        binding
        for name in _PROFILE_REPLAY_ARTIFACT_NAMES
        if (binding := bindings_by_path.get(name)) is not None
    )
    if discovery is None or len(required_bindings) != len(_PROFILE_REPLAY_ARTIFACT_NAMES):
        return unverifiable()

    try:
        with open_manifest_bound_json_artifacts(
            run_dir,
            _PROFILE_REPLAY_ARTIFACT_NAMES,
            required_bindings=required_bindings,
            max_bytes=_MAX_VERIFICATION_BYTES,
        ) as payloads:
            index_artifact = SolidityIndexArtifact.model_validate(payloads["solidity-index.json"])
            graphs_artifact = SolidityGraphsArtifact.model_validate(
                payloads["solidity-graphs.json"]
            )
            invariant_payload = payloads["solidity-invariants.json"]
            if set(invariant_payload) != {"schema_version", "invariants"}:
                raise ValueError("Solidity invariant artifact envelope is invalid")
            if invariant_payload["schema_version"] != "1.0":
                raise ValueError("Solidity invariant artifact schema is unsupported")
            retained_suite = InvariantSuite.model_validate(invariant_payload["invariants"])

        if retained_suite != report.invariants:
            raise ValueError("Solidity invariant artifact differs from the final report")
        if index_artifact.index is None:
            raise ValueError("Solidity index artifact is unavailable")
        validate_protocol_profile_replay(
            discovery,
            index_artifact.index,
            graphs_artifact.graphs,
            retained_suite,
        )
    except (OSError, TypeError, ValueError):
        return unverifiable()
    return []


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
    if manifest.schema_version in {"1.2", "1.3", "1.4"}:
        status_metadata = report_status_metadata(report)
        status_comparisons: tuple[
            tuple[RunVerificationCategory, str, Any, Any],
            ...,
        ] = tuple(
            (
                RunVerificationCategory.MANIFEST,
                f"metadata/{field_name.replace('_', '-')}",
                expected_value,
                metadata.get(field_name),
            )
            for field_name, expected_value in status_metadata.items()
        )
        expected_floor = (
            report.minimum_analysis_floor.model_dump(mode="json")
            if report.minimum_analysis_floor is not None
            else None
        )
        status_comparisons = (
            *status_comparisons,
            (
                RunVerificationCategory.MANIFEST,
                "metadata/minimum-analysis-floor",
                expected_floor,
                metadata.get("minimum_analysis_floor"),
            ),
        )
    else:
        status_comparisons = (
            (
                RunVerificationCategory.MANIFEST,
                "metadata/completed",
                report.completed,
                metadata.get("completed"),
            ),
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
        *status_comparisons,
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


def _safe_directory(path: Path, label: str) -> DirectoryCustodyObservation:
    return observe_unlinked_directory(path, label=f"run verification {label}")
