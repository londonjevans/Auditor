"""Descriptor-safe export and verification of complete local forensic run bundles."""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from mmaudit.models.scheduler import SchedulerRetainedJournalReference
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import (
    SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME,
    ManifestFileBinding,
    RunEvidenceManifest,
    canonical_sha256,
    collect_run_artifacts,
    validate_manifest_artifacts,
)
from mmaudit.release_artifacts import _require_unlinked_directory
from mmaudit.release_io import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    copy_file_evidence,
    read_json_evidence,
    write_json_evidence,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name

_DESCRIPTOR_NAME = "forensic-delivery.json"
_RUNS_DIRECTORY_NAME = "runs"
_RUN_MANIFEST_NAME = "run-evidence-manifest.json"
_PUBLIC_SUBSET_MANIFEST_NAME = "public-evidence-subset-manifest.json"
_INCOMPLETE_MARKER_NAME = "INCOMPLETE_FORENSIC_EXPORT"
_INCOMPLETE_MARKER_CONTENT = b"INCOMPLETE_FORENSIC_EXPORT\n"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_RUN_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_ARTIFACTS = 200_001
_MAX_TOTAL_BYTES = 8 * 1024**3 + DEFAULT_MAX_EVIDENCE_BYTES
_MAX_DESCRIPTOR_BYTES = DEFAULT_MAX_EVIDENCE_BYTES
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAG = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC_FLAG = getattr(os, "O_CLOEXEC", 0)

type _DirectoryIdentity = tuple[int, int, int, int]


class RetainedJournalDependency(StrictModel):
    """Exact owner-journal bytes required to verify one resumed scheduler run."""

    schema_version: Literal["1.0"] = "1.0"
    dependency_kind: Literal["SCHEDULER_RETAINED_JOURNAL"] = "SCHEDULER_RETAINED_JOURNAL"
    reference_path: str = Field(min_length=1, max_length=4_096)
    reference_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    journal_directory: str = Field(min_length=1, max_length=4_096)
    reference: SchedulerRetainedJournalReference
    artifact_count: int = Field(ge=1, le=_MAX_ARTIFACTS)
    artifact_total_bytes: int = Field(ge=1, le=_MAX_TOTAL_BYTES)
    artifact_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifacts: list[ManifestFileBinding] = Field(min_length=1, max_length=_MAX_ARTIFACTS)
    directory_count: int = Field(ge=3, le=_MAX_ARTIFACTS)
    directory_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    directories: list[str] = Field(min_length=3, max_length=_MAX_ARTIFACTS)

    @model_validator(mode="after")
    def inventory_is_exact(self) -> RetainedJournalDependency:
        expected_directory = (
            f"{_RUNS_DIRECTORY_NAME}/{self.reference.owner_run_id}/private/scheduler-journal"
        )
        if self.journal_directory != expected_directory:
            raise ValueError("retained-journal delivery directory differs from its owner")
        paths = [binding.path for binding in self.artifacts]
        if paths != sorted(set(paths)) or any(
            not path.startswith(f"{expected_directory}/") for path in paths
        ):
            raise ValueError("retained-journal delivery inventory is not exact")
        if self.artifact_count != len(self.artifacts):
            raise ValueError("retained-journal delivery artifact count is inconsistent")
        if self.artifact_total_bytes != sum(binding.size for binding in self.artifacts):
            raise ValueError("retained-journal delivery byte total is inconsistent")
        expected_hash = canonical_sha256(
            [binding.model_dump(mode="json") for binding in self.artifacts]
        )
        if self.artifact_inventory_sha256 != expected_hash:
            raise ValueError("retained-journal delivery inventory hash is inconsistent")
        required_directories = {
            f"{_RUNS_DIRECTORY_NAME}/{self.reference.owner_run_id}",
            f"{_RUNS_DIRECTORY_NAME}/{self.reference.owner_run_id}/private",
            expected_directory,
        }
        if self.directories != sorted(set(self.directories)) or any(
            directory != expected_directory
            and not directory.startswith(f"{expected_directory}/")
            and directory
            not in {
                f"{_RUNS_DIRECTORY_NAME}/{self.reference.owner_run_id}",
                f"{_RUNS_DIRECTORY_NAME}/{self.reference.owner_run_id}/private",
            }
            for directory in self.directories
        ):
            raise ValueError("retained-journal directory inventory is not exact")
        if not required_directories <= set(self.directories):
            raise ValueError("retained-journal directory inventory lacks required custody roots")
        if self.directory_count != len(self.directories):
            raise ValueError("retained-journal directory count is inconsistent")
        if self.directory_inventory_sha256 != canonical_sha256(self.directories):
            raise ValueError("retained-journal directory inventory hash is inconsistent")
        return self


class ForensicDeliveryDescriptorPayload(StrictModel):
    """Complete, content-free inventory for one exported forensic run and its dependencies."""

    schema_version: Literal["1.0"] = "1.0"
    bundle_kind: Literal["COMPLETE_FORENSIC_BUNDLE"] = "COMPLETE_FORENSIC_BUNDLE"
    runs_directory: Literal["runs"] = "runs"
    source_run_id: str = Field(min_length=1, max_length=160)
    source_run_directory_name: str = Field(min_length=1, max_length=128)
    primary_run_directory: str = Field(min_length=1, max_length=4_096)
    source_manifest_path: str = Field(min_length=1, max_length=4_096)
    source_manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_manifest_self_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_count: int = Field(ge=2, le=_MAX_ARTIFACTS)
    artifact_total_bytes: int = Field(ge=1, le=_MAX_TOTAL_BYTES)
    artifact_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifacts: list[ManifestFileBinding] = Field(min_length=2, max_length=_MAX_ARTIFACTS)
    directory_count: int = Field(ge=2, le=_MAX_ARTIFACTS)
    directory_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    directories: list[str] = Field(min_length=2, max_length=_MAX_ARTIFACTS)
    retained_journal_dependencies: list[RetainedJournalDependency] = Field(
        default_factory=list,
        max_length=1,
    )
    evidence_inclusion_policy: Literal["ALL_MANIFEST_BOUND_AND_REQUIRED_DEPENDENCY_ARTIFACTS"] = (
        "ALL_MANIFEST_BOUND_AND_REQUIRED_DEPENDENCY_ARTIFACTS"
    )
    private_evidence_included: bool
    logs_included: bool
    sensitive_evidence_acknowledged: Literal[True] = True
    private_artifact_count: int = Field(ge=0, le=_MAX_ARTIFACTS)
    log_artifact_count: int = Field(ge=0, le=_MAX_ARTIFACTS)

    @model_validator(mode="after")
    def inventory_is_exact(self) -> ForensicDeliveryDescriptorPayload:
        _require_safe_run_directory_name(self.source_run_directory_name)
        expected_primary = f"{self.runs_directory}/{self.source_run_directory_name}"
        if self.primary_run_directory != expected_primary:
            raise ValueError("forensic delivery primary run directory is inconsistent")
        expected_manifest_path = f"{expected_primary}/{_RUN_MANIFEST_NAME}"
        if self.source_manifest_path != expected_manifest_path:
            raise ValueError("forensic delivery manifest path is inconsistent")

        paths = [binding.path for binding in self.artifacts]
        if paths != sorted(set(paths)):
            raise ValueError("forensic delivery artifact inventory must be unique and sorted")
        if self.directories != sorted(set(self.directories)):
            raise ValueError("forensic delivery directory inventory must be unique and sorted")
        if self.directory_count != len(self.directories):
            raise ValueError("forensic delivery directory count is inconsistent")
        if self.directory_inventory_sha256 != canonical_sha256(self.directories):
            raise ValueError("forensic delivery directory inventory hash is inconsistent")
        if self.runs_directory not in self.directories or expected_primary not in self.directories:
            raise ValueError("forensic delivery directory inventory lacks its primary run")
        _require_portable_paths([_DESCRIPTOR_NAME, *paths], self.directories)
        manifest_bindings = [
            binding for binding in self.artifacts if binding.path == self.source_manifest_path
        ]
        if (
            len(manifest_bindings) != 1
            or manifest_bindings[0].sha256 != self.source_manifest_file_sha256
        ):
            raise ValueError("forensic delivery manifest file binding is inconsistent")
        if self.artifact_count != len(self.artifacts):
            raise ValueError("forensic delivery artifact count is inconsistent")
        if self.artifact_total_bytes != sum(binding.size for binding in self.artifacts):
            raise ValueError("forensic delivery byte total is inconsistent")
        expected_inventory_sha256 = canonical_sha256(
            [binding.model_dump(mode="json") for binding in self.artifacts]
        )
        if self.artifact_inventory_sha256 != expected_inventory_sha256:
            raise ValueError("forensic delivery artifact inventory hash is inconsistent")

        dependency_paths: set[str] = set()
        dependency_directories: set[str] = set()
        owner_names: set[str] = set()
        for dependency in self.retained_journal_dependencies:
            reference = dependency.reference
            if (
                reference.consumer_run_id != self.source_run_directory_name
                or dependency.reference_path
                != (f"{expected_primary}/private/{SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME}")
            ):
                raise ValueError("retained-journal dependency differs from the primary run")
            if reference.owner_run_id in owner_names:
                raise ValueError("retained-journal dependency owners must be unique")
            owner_names.add(reference.owner_run_id)
            reference_bindings = [
                binding for binding in self.artifacts if binding.path == dependency.reference_path
            ]
            if (
                len(reference_bindings) != 1
                or reference_bindings[0].sha256 != dependency.reference_file_sha256
            ):
                raise ValueError("retained-journal reference is not bound by the delivery")
            for binding in dependency.artifacts:
                if binding.path in dependency_paths:
                    raise ValueError("retained-journal dependency inventories overlap")
                dependency_paths.add(binding.path)
            for directory in dependency.directories:
                if directory in dependency_directories:
                    raise ValueError("retained-journal dependency directories overlap")
                dependency_directories.add(directory)
        inventory_paths = set(paths)
        if not dependency_paths <= inventory_paths:
            raise ValueError("retained-journal dependency bytes are absent from the delivery")
        if not dependency_directories <= set(self.directories):
            raise ValueError("retained-journal dependency directories are absent from the delivery")
        primary_paths = inventory_paths - dependency_paths
        if not primary_paths or any(
            not path.startswith(f"{expected_primary}/") for path in primary_paths
        ):
            raise ValueError("forensic delivery contains bytes outside its declared runs")

        private_count = sum(
            _is_run_evidence_class(binding.path, "private") for binding in self.artifacts
        )
        log_count = sum(_is_run_evidence_class(binding.path, "logs") for binding in self.artifacts)
        if self.private_artifact_count != private_count or self.log_artifact_count != log_count:
            raise ValueError("forensic delivery sensitive-artifact counts are inconsistent")
        if self.private_evidence_included != (private_count > 0) or self.logs_included != (
            log_count > 0
        ):
            raise ValueError("forensic delivery sensitive-artifact presence is inconsistent")
        return self


class ForensicDeliveryDescriptor(ForensicDeliveryDescriptorPayload):
    """Self-hashed descriptor for a complete forensic delivery directory."""

    descriptor_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def descriptor_hash_is_exact(self) -> ForensicDeliveryDescriptor:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"descriptor_sha256"}))
        if self.descriptor_sha256 != expected:
            raise ValueError("forensic delivery descriptor self-hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _ObservedDependency:
    descriptor: RetainedJournalDependency
    source_journal_root: Path
    source_artifacts: list[ManifestFileBinding]
    source_directories: list[str]


@dataclass(slots=True)
class _CreatedWrapper:
    root: Path
    parent_descriptor: int
    wrapper_descriptor: int
    device: int
    inode: int

    def close(self) -> None:
        os.close(self.wrapper_descriptor)
        os.close(self.parent_descriptor)


@dataclass(slots=True)
class _DeliveryAnchors:
    wrapper_descriptor: int
    runs_descriptor: int
    wrapper_identity: _DirectoryIdentity
    runs_identity: _DirectoryIdentity
    primary_descriptor: int | None = None
    primary_identity: _DirectoryIdentity | None = None
    dependency_anchors: list[tuple[int, _DirectoryIdentity]] = field(default_factory=list)

    def close(self) -> None:
        for descriptor, _identity in reversed(self.dependency_anchors):
            os.close(descriptor)
        if self.primary_descriptor is not None:
            os.close(self.primary_descriptor)
        os.close(self.runs_descriptor)
        os.close(self.wrapper_descriptor)


def export_complete_forensic_bundle(
    *,
    source_run: Path,
    destination: Path,
    acknowledge_sensitive_evidence: bool,
) -> ForensicDeliveryDescriptor:
    """Copy one exact manifest-bound run into a fresh complete forensic wrapper."""

    _require_sensitive_acknowledgement(acknowledge_sensitive_evidence)
    source_root = _validated_source_root(source_run)
    source_directory_name = _require_safe_run_directory_name(source_root.name)
    manifest, manifest_content, source_inventory = _observe_complete_run(source_root)
    source_directories = _observe_directory_inventory(source_root)
    dependency = _observe_retained_journal_dependency(
        source_root=source_root,
        source_directory_name=source_directory_name,
        manifest=manifest,
        source_inventory=source_inventory,
    )
    descriptor = _seal_descriptor(
        manifest=manifest,
        source_directory_name=source_directory_name,
        source_inventory=source_inventory,
        source_directories=source_directories,
        dependency=dependency,
    )
    _require_descriptor_fits_output_bound(descriptor)
    destination_path = _validated_destination_candidate(destination, source_root=source_root)

    created = _create_fresh_wrapper(destination_path)
    marker_written = False
    try:
        try:
            _write_incomplete_marker(created.wrapper_descriptor)
            marker_written = True
        except BaseException:
            _remove_created_empty_wrapper(created)
            raise

        _create_direct_directory(created.root, _RUNS_DIRECTORY_NAME)
        for directory in descriptor.directories:
            _create_directory_path(created.root, directory)
        primary_prefix = descriptor.primary_run_directory
        _copy_bound_inventory(
            source_root=source_root,
            source_inventory=source_inventory,
            destination_root=created.root,
            destination_prefix=primary_prefix,
        )
        if dependency is not None:
            _copy_bound_inventory(
                source_root=dependency.source_journal_root,
                source_inventory=dependency.source_artifacts,
                destination_root=created.root,
                destination_prefix=dependency.descriptor.journal_directory,
            )

        final_manifest, final_manifest_content, final_source_inventory = _observe_complete_run(
            source_root
        )
        final_source_directories = _observe_directory_inventory(source_root)
        if (
            final_manifest != manifest
            or final_manifest_content != manifest_content
            or final_source_inventory != source_inventory
            or final_source_directories != source_directories
        ):
            raise ValueError("forensic source run changed during export")
        final_dependency = _observe_retained_journal_dependency(
            source_root=source_root,
            source_directory_name=source_directory_name,
            manifest=final_manifest,
            source_inventory=final_source_inventory,
        )
        if not _dependencies_are_equal(dependency, final_dependency):
            raise ValueError("forensic retained-journal dependency changed during export")

        _validate_delivery_contents(created.root, descriptor)
        write_json_evidence(
            evidence_root=created.root,
            relative_path=_DESCRIPTOR_NAME,
            value=descriptor,
            max_bytes=_MAX_DESCRIPTOR_BYTES,
        )
        _remove_incomplete_marker(created.wrapper_descriptor)
        try:
            verified = verify_complete_forensic_bundle(
                delivery_root=created.root,
                acknowledge_sensitive_evidence=True,
            )
            current = os.stat(
                created.root.name,
                dir_fd=created.parent_descriptor,
                follow_symlinks=False,
            )
            held = os.fstat(created.wrapper_descriptor)
            if (
                _directory_identity(current) != _directory_identity(held)
                or (held.st_dev, held.st_ino) != (created.device, created.inode)
                or stat.S_IMODE(held.st_mode) != 0o700
            ):
                raise ValueError("forensic destination changed before publication completed")
        except BaseException:
            try:
                _write_incomplete_marker(created.wrapper_descriptor)
            except (OSError, ValueError) as restore_exc:
                raise ValueError(
                    "forensic export failed after finalization and its marker could not be restored"
                ) from restore_exc
            raise
        marker_written = False
        return verified
    finally:
        if marker_written:
            # The marker remains in the exact created inode on every post-marker failure.
            with suppress(OSError):
                os.fsync(created.wrapper_descriptor)
        created.close()


def verify_complete_forensic_bundle(
    *,
    delivery_root: Path,
    acknowledge_sensitive_evidence: bool,
) -> ForensicDeliveryDescriptor:
    """Verify a complete forensic delivery without its original run or source repository."""

    _require_sensitive_acknowledgement(acknowledge_sensitive_evidence)
    wrapper_root = _require_unlinked_directory(delivery_root, label="forensic delivery")
    anchors = _open_delivery_base_anchors(wrapper_root)
    try:
        descriptor_observation = read_json_evidence(
            evidence_root=wrapper_root,
            relative_path=_DESCRIPTOR_NAME,
        )
        anchored_descriptor_content = _read_anchored_file_twice(
            anchors.wrapper_descriptor,
            _DESCRIPTOR_NAME,
            max_bytes=_MAX_DESCRIPTOR_BYTES,
        )
        if anchored_descriptor_content != descriptor_observation.content:
            raise ValueError("forensic delivery descriptor differs from its held wrapper")
        descriptor = ForensicDeliveryDescriptor.model_validate(descriptor_observation.value)
        _anchor_primary_run(wrapper_root, descriptor, anchors)
        manifest, manifest_content, source_inventory = _observe_complete_run(
            wrapper_root / descriptor.primary_run_directory
        )
        _require_source_descriptor_match(
            descriptor=descriptor,
            manifest=manifest,
            source_inventory=source_inventory,
        )
        first_inventory = _observe_delivery_inventory(
            wrapper_root=wrapper_root,
            descriptor=descriptor,
            source_inventory=source_inventory,
        )
        if first_inventory != descriptor.artifacts:
            raise ValueError("forensic delivery inventory differs from its descriptor")

        descriptor_final = read_json_evidence(
            evidence_root=wrapper_root,
            relative_path=_DESCRIPTOR_NAME,
        )
        if descriptor_final.content != descriptor_observation.content:
            raise ValueError("forensic delivery descriptor changed during verification")
        if (
            _read_anchored_file_twice(
                anchors.wrapper_descriptor,
                _DESCRIPTOR_NAME,
                max_bytes=_MAX_DESCRIPTOR_BYTES,
            )
            != anchored_descriptor_content
        ):
            raise ValueError("forensic delivery descriptor changed in its held wrapper")
        final_manifest, final_manifest_content, final_source_inventory = _observe_complete_run(
            wrapper_root / descriptor.primary_run_directory
        )
        final_inventory = _observe_delivery_inventory(
            wrapper_root=wrapper_root,
            descriptor=descriptor,
            source_inventory=final_source_inventory,
        )
        if (
            final_manifest != manifest
            or final_manifest_content != manifest_content
            or final_source_inventory != source_inventory
            or final_inventory != first_inventory
        ):
            raise ValueError("forensic delivery changed during verification")
        _revalidate_delivery_anchors(wrapper_root, descriptor, anchors)
        return descriptor
    finally:
        anchors.close()


def _require_sensitive_acknowledgement(acknowledged: bool) -> None:
    if acknowledged is not True:
        raise ValueError(
            "complete forensic delivery requires explicit sensitive-evidence acknowledgement"
        )


def _validated_source_root(source_run: Path) -> Path:
    if ".." in PurePath(source_run).parts:
        raise ValueError("forensic source path may not contain parent traversal")
    root = _require_unlinked_directory(source_run, label="forensic source run")
    if _directory_has_entry(root, _PUBLIC_SUBSET_MANIFEST_NAME):
        raise ValueError("a CI public subset is not a complete forensic source run")
    return root


def _validated_destination_candidate(destination: Path, *, source_root: Path) -> Path:
    if ".." in PurePath(destination).parts:
        raise ValueError("forensic destination path may not contain parent traversal")
    absolute = Path(os.path.abspath(destination))
    if absolute == Path(absolute.anchor):
        raise ValueError("forensic destination must be a named child directory")
    name = absolute.name
    if (
        not name
        or normalize_relative_path(name) != name
        or unicodedata.normalize("NFC", name) != name
        or is_sensitive_workspace_name(name)
    ):
        raise ValueError("forensic destination name is unsafe")
    parent = _require_unlinked_directory(absolute.parent, label="forensic destination parent")
    candidate = parent / name
    try:
        candidate.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError("forensic destination could not be observed safely") from exc
    else:
        raise ValueError("forensic destination must not already exist")
    if _directory_is_within(parent, source_root):
        raise ValueError("forensic source and destination may not overlap")
    return candidate


def _observe_complete_run(
    run_root: Path,
) -> tuple[RunEvidenceManifest, bytes, list[ManifestFileBinding]]:
    if _directory_has_entry(run_root, _PUBLIC_SUBSET_MANIFEST_NAME):
        raise ValueError("a CI public subset is not a complete forensic run")
    manifest_observation = read_json_evidence(
        evidence_root=run_root,
        relative_path=_RUN_MANIFEST_NAME,
    )
    manifest = RunEvidenceManifest.model_validate(manifest_observation.value)
    if manifest.schema_version != "1.2":
        raise ValueError("complete forensic delivery requires run-manifest schema 1.2")
    validate_manifest_artifacts(manifest, run_root)
    inventory = sorted(
        [*manifest.artifacts, manifest_observation.binding],
        key=lambda binding: binding.path,
    )
    if len(inventory) > _MAX_ARTIFACTS:
        raise ValueError("forensic artifact inventory exceeds its bound")
    if sum(binding.size for binding in inventory) > _MAX_TOTAL_BYTES:
        raise ValueError("forensic artifact inventory exceeds its byte bound")
    return manifest, manifest_observation.content, inventory


def _observe_retained_journal_dependency(
    *,
    source_root: Path,
    source_directory_name: str,
    manifest: RunEvidenceManifest,
    source_inventory: list[ManifestFileBinding],
) -> _ObservedDependency | None:
    reference_relative = f"private/{SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME}"
    reference_bindings = [
        binding for binding in source_inventory if binding.path == reference_relative
    ]
    if not reference_bindings:
        return None
    if len(reference_bindings) != 1:
        raise ValueError("forensic retained-journal reference binding is ambiguous")
    reference_observation = read_json_evidence(
        evidence_root=source_root,
        relative_path=reference_relative,
    )
    if reference_observation.binding != reference_bindings[0]:
        raise ValueError("forensic retained-journal reference differs from its manifest")
    reference = SchedulerRetainedJournalReference.model_validate(reference_observation.value)
    if reference.consumer_run_id != source_directory_name:
        raise ValueError("forensic source basename differs from retained-journal custody")

    journal_root = _require_unlinked_directory(
        source_root.parent / reference.owner_run_id / "private" / "scheduler-journal",
        label="forensic retained scheduler journal",
    )
    source_artifacts = collect_run_artifacts(journal_root)
    source_directories = _observe_directory_inventory(journal_root)
    journal_directory = f"{_RUNS_DIRECTORY_NAME}/{reference.owner_run_id}/private/scheduler-journal"
    delivery_artifacts = [
        _prefix_binding(binding, journal_directory) for binding in source_artifacts
    ]
    dependency = RetainedJournalDependency(
        reference_path=(
            f"{_RUNS_DIRECTORY_NAME}/{source_directory_name}/private/"
            f"{SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME}"
        ),
        reference_file_sha256=reference_observation.binding.sha256,
        journal_directory=journal_directory,
        reference=reference,
        artifact_count=len(delivery_artifacts),
        artifact_total_bytes=sum(binding.size for binding in delivery_artifacts),
        artifact_inventory_sha256=canonical_sha256(
            [binding.model_dump(mode="json") for binding in delivery_artifacts]
        ),
        artifacts=delivery_artifacts,
        directory_count=3 + len(source_directories),
        directory_inventory_sha256=canonical_sha256(
            [
                f"{_RUNS_DIRECTORY_NAME}/{reference.owner_run_id}",
                f"{_RUNS_DIRECTORY_NAME}/{reference.owner_run_id}/private",
                journal_directory,
                *(f"{journal_directory}/{directory}" for directory in source_directories),
            ]
        ),
        directories=[
            f"{_RUNS_DIRECTORY_NAME}/{reference.owner_run_id}",
            f"{_RUNS_DIRECTORY_NAME}/{reference.owner_run_id}/private",
            journal_directory,
            *(f"{journal_directory}/{directory}" for directory in source_directories),
        ],
    )
    # The full semantic validation above is the authority tying these bytes to this reference.
    validate_manifest_artifacts(manifest, source_root)
    return _ObservedDependency(
        descriptor=dependency,
        source_journal_root=journal_root,
        source_artifacts=source_artifacts,
        source_directories=source_directories,
    )


def _seal_descriptor(
    *,
    manifest: RunEvidenceManifest,
    source_directory_name: str,
    source_inventory: list[ManifestFileBinding],
    source_directories: list[str],
    dependency: _ObservedDependency | None,
) -> ForensicDeliveryDescriptor:
    primary_directory = f"{_RUNS_DIRECTORY_NAME}/{source_directory_name}"
    delivery_inventory = [
        _prefix_binding(binding, primary_directory) for binding in source_inventory
    ]
    delivery_directories = [
        _RUNS_DIRECTORY_NAME,
        primary_directory,
        *(f"{primary_directory}/{directory}" for directory in source_directories),
    ]
    dependencies: list[RetainedJournalDependency] = []
    if dependency is not None:
        dependencies.append(dependency.descriptor)
        delivery_inventory.extend(dependency.descriptor.artifacts)
        delivery_directories.extend(dependency.descriptor.directories)
    delivery_inventory.sort(key=lambda binding: binding.path)
    delivery_directories = sorted(set(delivery_directories))
    _require_portable_paths(
        [_DESCRIPTOR_NAME, *(item.path for item in delivery_inventory)],
        delivery_directories,
    )
    source_manifest_path = f"{primary_directory}/{_RUN_MANIFEST_NAME}"
    payload = ForensicDeliveryDescriptorPayload(
        source_run_id=manifest.run_id,
        source_run_directory_name=source_directory_name,
        primary_run_directory=primary_directory,
        source_manifest_path=source_manifest_path,
        source_manifest_file_sha256=next(
            binding.sha256 for binding in delivery_inventory if binding.path == source_manifest_path
        ),
        source_manifest_self_sha256=manifest.manifest_sha256,
        artifact_count=len(delivery_inventory),
        artifact_total_bytes=sum(binding.size for binding in delivery_inventory),
        artifact_inventory_sha256=canonical_sha256(
            [binding.model_dump(mode="json") for binding in delivery_inventory]
        ),
        artifacts=delivery_inventory,
        directory_count=len(delivery_directories),
        directory_inventory_sha256=canonical_sha256(delivery_directories),
        directories=delivery_directories,
        retained_journal_dependencies=dependencies,
        private_evidence_included=any(
            _is_run_evidence_class(binding.path, "private") for binding in delivery_inventory
        ),
        logs_included=any(
            _is_run_evidence_class(binding.path, "logs") for binding in delivery_inventory
        ),
        private_artifact_count=sum(
            _is_run_evidence_class(binding.path, "private") for binding in delivery_inventory
        ),
        log_artifact_count=sum(
            _is_run_evidence_class(binding.path, "logs") for binding in delivery_inventory
        ),
    )
    return ForensicDeliveryDescriptor(
        **payload.model_dump(mode="python"),
        descriptor_sha256=canonical_sha256(payload.model_dump(mode="json")),
    )


def _copy_bound_inventory(
    *,
    source_root: Path,
    source_inventory: list[ManifestFileBinding],
    destination_root: Path,
    destination_prefix: str,
) -> None:
    for binding in source_inventory:
        destination_path = f"{destination_prefix}/{binding.path}"
        _create_parent_directories(destination_root, destination_path)
        copied = copy_file_evidence(
            source_root=source_root,
            source_relative_path=binding.path,
            destination_root=destination_root,
            destination_relative_path=destination_path,
            expected_binding=binding,
        )
        if copied != _prefix_binding(binding, destination_prefix):
            raise ValueError("forensic destination artifact differs after copying")


def _validate_delivery_contents(
    wrapper_root: Path,
    descriptor: ForensicDeliveryDescriptor,
) -> None:
    manifest, _content, source_inventory = _observe_complete_run(
        wrapper_root / descriptor.primary_run_directory
    )
    _require_source_descriptor_match(
        descriptor=descriptor,
        manifest=manifest,
        source_inventory=source_inventory,
    )
    inventory = _observe_delivery_inventory(
        wrapper_root=wrapper_root,
        descriptor=descriptor,
        source_inventory=source_inventory,
    )
    if inventory != descriptor.artifacts:
        raise ValueError("copied forensic delivery differs from its descriptor")


def _require_source_descriptor_match(
    *,
    descriptor: ForensicDeliveryDescriptor,
    manifest: RunEvidenceManifest,
    source_inventory: list[ManifestFileBinding],
) -> None:
    if manifest.run_id != descriptor.source_run_id:
        raise ValueError("forensic delivery run ID differs from its descriptor")
    if manifest.manifest_sha256 != descriptor.source_manifest_self_sha256:
        raise ValueError("forensic delivery manifest self-hash differs from its descriptor")
    source_manifest = next(
        binding for binding in source_inventory if binding.path == _RUN_MANIFEST_NAME
    )
    if source_manifest.sha256 != descriptor.source_manifest_file_sha256:
        raise ValueError("forensic delivery manifest file differs from its descriptor")


def _observe_delivery_inventory(
    *,
    wrapper_root: Path,
    descriptor: ForensicDeliveryDescriptor,
    source_inventory: list[ManifestFileBinding],
) -> list[ManifestFileBinding]:
    _validate_runs_layout(wrapper_root / _RUNS_DIRECTORY_NAME, descriptor)
    if _observe_directory_inventory(wrapper_root) != descriptor.directories:
        raise ValueError("forensic delivery directory inventory differs from its descriptor")
    observed = [
        _prefix_binding(binding, descriptor.primary_run_directory) for binding in source_inventory
    ]
    for dependency in descriptor.retained_journal_dependencies:
        journal_root = wrapper_root / dependency.journal_directory
        dependency_inventory = collect_run_artifacts(journal_root)
        prefixed = [
            _prefix_binding(binding, dependency.journal_directory)
            for binding in dependency_inventory
        ]
        if prefixed != dependency.artifacts:
            raise ValueError("forensic retained-journal delivery differs from its descriptor")
        dependency_directories = [
            f"{_RUNS_DIRECTORY_NAME}/{dependency.reference.owner_run_id}",
            f"{_RUNS_DIRECTORY_NAME}/{dependency.reference.owner_run_id}/private",
            dependency.journal_directory,
            *(
                f"{dependency.journal_directory}/{directory}"
                for directory in _observe_directory_inventory(journal_root)
            ),
        ]
        if dependency_directories != dependency.directories:
            raise ValueError(
                "forensic retained-journal directory inventory differs from its descriptor"
            )
        observed.extend(prefixed)
    return sorted(observed, key=lambda binding: binding.path)


def _validate_runs_layout(
    runs_root: Path,
    descriptor: ForensicDeliveryDescriptor,
) -> None:
    runs_descriptor = _open_directory_descriptor(runs_root)
    try:
        expected_names = {descriptor.source_run_directory_name}
        expected_names.update(
            dependency.reference.owner_run_id
            for dependency in descriptor.retained_journal_dependencies
        )
        if set(os.listdir(runs_descriptor)) != expected_names:
            raise ValueError("forensic delivery runs inventory is not exact")
        for dependency in descriptor.retained_journal_dependencies:
            owner = _open_direct_child_directory(
                runs_descriptor,
                dependency.reference.owner_run_id,
                label="forensic retained owner run",
            )
            try:
                if set(os.listdir(owner)) != {"private"}:
                    raise ValueError("forensic retained owner run inventory is not exact")
                private = _open_direct_child_directory(
                    owner,
                    "private",
                    label="forensic retained owner private directory",
                )
                try:
                    if set(os.listdir(private)) != {"scheduler-journal"}:
                        raise ValueError("forensic retained owner private inventory is not exact")
                finally:
                    os.close(private)
            finally:
                os.close(owner)
    finally:
        os.close(runs_descriptor)


def _dependencies_are_equal(
    before: _ObservedDependency | None,
    after: _ObservedDependency | None,
) -> bool:
    if before is None or after is None:
        return before is after
    return (
        before.descriptor == after.descriptor
        and before.source_journal_root == after.source_journal_root
        and before.source_artifacts == after.source_artifacts
        and before.source_directories == after.source_directories
    )


def _create_fresh_wrapper(destination: Path) -> _CreatedWrapper:
    parent = _require_unlinked_directory(destination.parent, label="forensic destination parent")
    parent_descriptor = _open_directory_descriptor(parent)
    wrapper_descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        try:
            os.mkdir(destination.name, mode=0o700, dir_fd=parent_descriptor)
            entry = os.stat(destination.name, dir_fd=parent_descriptor, follow_symlinks=False)
            created_identity = (entry.st_dev, entry.st_ino)
            wrapper_descriptor = os.open(
                destination.name,
                os.O_RDONLY | _DIRECTORY_FLAG | _CLOEXEC_FLAG | _NOFOLLOW_FLAG,
                dir_fd=parent_descriptor,
            )
            os.fchmod(wrapper_descriptor, 0o700)
            opened = os.fstat(wrapper_descriptor)
            entry = os.stat(destination.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino) != created_identity
                or (entry.st_dev, entry.st_ino) != created_identity
                or os.listdir(wrapper_descriptor)
            ):
                raise ValueError("forensic destination changed while it was created")
            os.fsync(parent_descriptor)
            return _CreatedWrapper(
                root=destination,
                parent_descriptor=parent_descriptor,
                wrapper_descriptor=wrapper_descriptor,
                device=opened.st_dev,
                inode=opened.st_ino,
            )
        except OSError as exc:
            raise ValueError("forensic destination could not be created safely") from exc
    except BaseException:
        if created_identity is not None:
            _remove_exact_empty_directory_entry(
                parent_descriptor,
                destination.name,
                created_identity,
            )
        if wrapper_descriptor is not None:
            os.close(wrapper_descriptor)
        os.close(parent_descriptor)
        raise


def _remove_created_empty_wrapper(created: _CreatedWrapper) -> None:
    if os.listdir(created.wrapper_descriptor):
        raise ValueError("failed forensic wrapper is not empty and cannot be rolled back")
    _remove_exact_empty_directory_entry(
        created.parent_descriptor,
        created.root.name,
        (created.device, created.inode),
    )


def _remove_exact_empty_directory_entry(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    try:
        entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        child = os.open(
            name,
            os.O_RDONLY | _DIRECTORY_FLAG | _CLOEXEC_FLAG | _NOFOLLOW_FLAG,
            dir_fd=parent_descriptor,
        )
        try:
            opened = os.fstat(child)
            if (
                (entry.st_dev, entry.st_ino) != expected_identity
                or (opened.st_dev, opened.st_ino) != expected_identity
                or os.listdir(child)
            ):
                raise ValueError("failed forensic wrapper changed before rollback")
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise ValueError("failed forensic wrapper could not be rolled back safely") from exc


def _write_incomplete_marker(wrapper_descriptor: int) -> None:
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            _INCOMPLETE_MARKER_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC_FLAG | _NOFOLLOW_FLAG,
            0o600,
            dir_fd=wrapper_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        created_identity = (opened.st_dev, opened.st_ino)
        view = memoryview(_INCOMPLETE_MARKER_CONTENT)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("forensic marker write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        finished = os.fstat(descriptor)
        entry = os.stat(
            _INCOMPLETE_MARKER_NAME,
            dir_fd=wrapper_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(finished.st_mode)
            or finished.st_nlink != 1
            or stat.S_IMODE(finished.st_mode) != 0o600
            or finished.st_size != len(_INCOMPLETE_MARKER_CONTENT)
            or _file_identity(finished) != _file_identity(entry)
        ):
            raise ValueError("forensic incomplete marker changed while it was created")
        os.fsync(wrapper_descriptor)
    except BaseException as exc:
        if created_identity is not None:
            _unlink_exact_entry(
                wrapper_descriptor,
                _INCOMPLETE_MARKER_NAME,
                created_identity,
            )
        if isinstance(exc, OSError):
            raise ValueError("forensic incomplete marker could not be created safely") from exc
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _remove_incomplete_marker(wrapper_descriptor: int) -> None:
    marker_descriptor: int | None = None
    unlinked = False
    try:
        before = os.stat(
            _INCOMPLETE_MARKER_NAME,
            dir_fd=wrapper_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("forensic incomplete marker is unsafe")
        marker_descriptor = os.open(
            _INCOMPLETE_MARKER_NAME,
            os.O_RDONLY | _CLOEXEC_FLAG | _NOFOLLOW_FLAG,
            dir_fd=wrapper_descriptor,
        )
        opened = os.fstat(marker_descriptor)
        content = os.read(marker_descriptor, len(_INCOMPLETE_MARKER_CONTENT) + 1)
        finished = os.fstat(marker_descriptor)
        after = os.stat(
            _INCOMPLETE_MARKER_NAME,
            dir_fd=wrapper_descriptor,
            follow_symlinks=False,
        )
        if (
            len(
                {
                    _file_identity(before),
                    _file_identity(opened),
                    _file_identity(finished),
                    _file_identity(after),
                }
            )
            != 1
            or content != _INCOMPLETE_MARKER_CONTENT
        ):
            raise ValueError("forensic incomplete marker changed before finalization")
        os.unlink(_INCOMPLETE_MARKER_NAME, dir_fd=wrapper_descriptor)
        unlinked = True
        os.fsync(wrapper_descriptor)
    except OSError as exc:
        if unlinked:
            try:
                _write_incomplete_marker(wrapper_descriptor)
            except (OSError, ValueError) as restore_exc:
                raise ValueError(
                    "forensic finalization failed and its incomplete marker could not be restored"
                ) from restore_exc
            raise ValueError("forensic finalization failed; incomplete marker restored") from exc
        raise ValueError("forensic incomplete marker could not be removed safely") from exc
    finally:
        if marker_descriptor is not None:
            os.close(marker_descriptor)


def _unlink_exact_entry(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    with suppress(OSError):
        entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (entry.st_dev, entry.st_ino) == expected_identity:
            os.unlink(name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)


def _create_direct_directory(root: Path, name: str) -> Path:
    _require_safe_component(name)
    root_descriptor = _open_directory_descriptor(root)
    child_descriptor: int | None = None
    try:
        os.mkdir(name, mode=0o700, dir_fd=root_descriptor)
        child_descriptor = _open_direct_child_directory(
            root_descriptor,
            name,
            label="forensic child directory",
        )
        os.fsync(root_descriptor)
    except OSError as exc:
        raise ValueError("forensic child directory could not be created safely") from exc
    finally:
        if child_descriptor is not None:
            os.close(child_descriptor)
        os.close(root_descriptor)
    return _require_unlinked_directory(root / name, label="forensic child directory")


def _create_directory_path(root: Path, relative_path: str) -> None:
    normalized = normalize_relative_path(relative_path)
    if normalized != relative_path or normalized in {"", "."}:
        raise ValueError("forensic directory path must be direct and normalized")
    descriptor = _open_directory_descriptor(root)
    try:
        for part in PurePosixPath(normalized).parts:
            _require_safe_component(part)
            created = False
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                created = True
            except FileExistsError:
                pass
            if created:
                os.fsync(descriptor)
            child = _open_direct_child_directory(
                descriptor,
                part,
                label="forensic delivery directory",
            )
            os.close(descriptor)
            descriptor = child
    except OSError as exc:
        raise ValueError("forensic delivery directory could not be created safely") from exc
    finally:
        os.close(descriptor)


def _create_parent_directories(root: Path, relative_path: str) -> None:
    normalized = normalize_relative_path(relative_path)
    if normalized != relative_path or normalized in {"", "."}:
        raise ValueError("forensic artifact path must be direct and normalized")
    parts = PurePosixPath(normalized).parts[:-1]
    descriptor = _open_directory_descriptor(root)
    try:
        for part in parts:
            _require_safe_component(part)
            created = False
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                created = True
            except FileExistsError:
                pass
            if created:
                os.fsync(descriptor)
            child = _open_direct_child_directory(
                descriptor,
                part,
                label="forensic artifact parent",
            )
            os.close(descriptor)
            descriptor = child
    except OSError as exc:
        raise ValueError("forensic artifact parent could not be created safely") from exc
    finally:
        os.close(descriptor)


def _open_delivery_base_anchors(wrapper_root: Path) -> _DeliveryAnchors:
    wrapper_descriptor = _open_directory_descriptor(wrapper_root)
    runs_descriptor: int | None = None
    try:
        if set(os.listdir(wrapper_descriptor)) != {_DESCRIPTOR_NAME, _RUNS_DIRECTORY_NAME}:
            raise ValueError("forensic delivery wrapper inventory is not exact")
        wrapper_metadata = os.fstat(wrapper_descriptor)
        descriptor_metadata = os.stat(
            _DESCRIPTOR_NAME,
            dir_fd=wrapper_descriptor,
            follow_symlinks=False,
        )
        if (
            stat.S_IMODE(wrapper_metadata.st_mode) != 0o700
            or not stat.S_ISREG(descriptor_metadata.st_mode)
            or descriptor_metadata.st_nlink != 1
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
        ):
            raise ValueError("forensic delivery wrapper contains an unsafe entry")
        runs_descriptor = _open_direct_child_directory(
            wrapper_descriptor,
            _RUNS_DIRECTORY_NAME,
            label="forensic delivery runs directory",
        )
        return _DeliveryAnchors(
            wrapper_descriptor=wrapper_descriptor,
            runs_descriptor=runs_descriptor,
            wrapper_identity=_directory_identity(wrapper_metadata),
            runs_identity=_directory_identity(os.fstat(runs_descriptor)),
        )
    except BaseException:
        if runs_descriptor is not None:
            os.close(runs_descriptor)
        os.close(wrapper_descriptor)
        raise


def _anchor_primary_run(
    wrapper_root: Path,
    descriptor: ForensicDeliveryDescriptor,
    anchors: _DeliveryAnchors,
) -> None:
    if anchors.primary_descriptor is not None or anchors.primary_identity is not None:
        raise ValueError("forensic delivery primary authority was already established")
    _validate_runs_layout(wrapper_root / _RUNS_DIRECTORY_NAME, descriptor)
    primary_descriptor = _open_direct_child_directory(
        anchors.runs_descriptor,
        descriptor.source_run_directory_name,
        label="forensic delivery primary run",
    )
    anchors.primary_descriptor = primary_descriptor
    anchors.primary_identity = _directory_identity(os.fstat(primary_descriptor))
    for dependency in descriptor.retained_journal_dependencies:
        owner_descriptor = _open_direct_child_directory(
            anchors.runs_descriptor,
            dependency.reference.owner_run_id,
            label="forensic retained owner run",
        )
        anchors.dependency_anchors.append(
            (owner_descriptor, _directory_identity(os.fstat(owner_descriptor)))
        )
        private_descriptor = _open_direct_child_directory(
            owner_descriptor,
            "private",
            label="forensic retained owner private directory",
        )
        anchors.dependency_anchors.append(
            (private_descriptor, _directory_identity(os.fstat(private_descriptor)))
        )
        journal_descriptor = _open_direct_child_directory(
            private_descriptor,
            "scheduler-journal",
            label="forensic retained scheduler journal",
        )
        anchors.dependency_anchors.append(
            (journal_descriptor, _directory_identity(os.fstat(journal_descriptor)))
        )


def _open_delivery_anchors(
    wrapper_root: Path,
    descriptor: ForensicDeliveryDescriptor,
) -> _DeliveryAnchors:
    anchors = _open_delivery_base_anchors(wrapper_root)
    try:
        _anchor_primary_run(wrapper_root, descriptor, anchors)
        return anchors
    except BaseException:
        anchors.close()
        raise


def _revalidate_delivery_anchors(
    wrapper_root: Path,
    descriptor: ForensicDeliveryDescriptor,
    anchors: _DeliveryAnchors,
) -> None:
    if anchors.primary_descriptor is None or anchors.primary_identity is None:
        raise ValueError("forensic delivery primary authority is unavailable")
    if (
        _directory_identity(os.fstat(anchors.wrapper_descriptor)) != anchors.wrapper_identity
        or _directory_identity(os.fstat(anchors.runs_descriptor)) != anchors.runs_identity
        or _directory_identity(os.fstat(anchors.primary_descriptor)) != anchors.primary_identity
        or any(
            _directory_identity(os.fstat(dependency_descriptor)) != dependency_identity
            for dependency_descriptor, dependency_identity in anchors.dependency_anchors
        )
    ):
        raise ValueError("forensic delivery directory authority changed during verification")
    current = _open_delivery_anchors(wrapper_root, descriptor)
    try:
        if (
            current.wrapper_identity != anchors.wrapper_identity
            or current.runs_identity != anchors.runs_identity
            or current.primary_identity != anchors.primary_identity
            or [identity for _descriptor, identity in current.dependency_anchors]
            != [identity for _descriptor, identity in anchors.dependency_anchors]
        ):
            raise ValueError("forensic delivery directory identity changed during verification")
    finally:
        current.close()


def _open_direct_child_directory(parent_descriptor: int, name: str, *, label: str) -> int:
    _require_safe_component(name)
    try:
        entry = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor = os.open(
            name,
            os.O_RDONLY | _DIRECTORY_FLAG | _CLOEXEC_FLAG | _NOFOLLOW_FLAG,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(entry.st_mode)
            or stat.S_IMODE(entry.st_mode) != 0o700
            or _directory_identity(entry) != _directory_identity(opened)
        ):
            raise ValueError(f"{label} is unsafe")
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _read_anchored_file_twice(
    parent_descriptor: int,
    name: str,
    *,
    max_bytes: int,
) -> bytes:
    def read_once() -> bytes:
        file_descriptor: int | None = None
        try:
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > max_bytes
            ):
                raise ValueError("forensic anchored file is not a bounded private regular file")
            file_descriptor = os.open(
                name,
                os.O_RDONLY | _CLOEXEC_FLAG | _NOFOLLOW_FLAG,
                dir_fd=parent_descriptor,
            )
            opened = os.fstat(file_descriptor)
            content = bytearray()
            while len(content) <= max_bytes:
                chunk = os.read(file_descriptor, min(1024 * 1024, max_bytes + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            finished = os.fstat(file_descriptor)
            after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                len(
                    {
                        _file_identity(before),
                        _file_identity(opened),
                        _file_identity(finished),
                        _file_identity(after),
                    }
                )
                != 1
                or len(content) > max_bytes
                or len(content) != before.st_size
            ):
                raise ValueError("forensic anchored file changed while it was read")
            return bytes(content)
        except OSError as exc:
            raise ValueError("forensic anchored file could not be read safely") from exc
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)

    first = read_once()
    second = read_once()
    if first != second:
        raise ValueError("forensic anchored file changed between observations")
    return second


def _directory_has_entry(root: Path, name: str) -> bool:
    descriptor = _open_directory_descriptor(root)
    try:
        return name in set(os.listdir(descriptor))
    except OSError as exc:
        raise ValueError("forensic directory could not be observed safely") from exc
    finally:
        os.close(descriptor)


def _observe_directory_inventory(root: Path) -> list[str]:
    directories: list[str] = []
    pending = [PurePosixPath()]
    while pending:
        prefix = pending.pop()
        directory = root if not prefix.parts else root / prefix.as_posix()
        descriptor = _open_directory_descriptor(directory)
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as exc:
            os.close(descriptor)
            raise ValueError("forensic directory inventory could not be listed safely") from exc
        try:
            for name in names:
                _require_safe_component(name)
                relative = (prefix / name).as_posix()
                if len(relative) > 4_096:
                    raise ValueError("forensic directory inventory path exceeds its bound")
                try:
                    entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as exc:
                    raise ValueError("forensic directory inventory entry is unavailable") from exc
                if stat.S_ISDIR(entry.st_mode):
                    directories.append(relative)
                    if len(directories) > _MAX_ARTIFACTS:
                        raise ValueError("forensic directory inventory exceeds its count bound")
                    pending.append(PurePosixPath(relative))
                elif not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
                    raise ValueError("forensic directory inventory contains an unsafe entry")
        finally:
            os.close(descriptor)
    return sorted(directories)


def _open_directory_descriptor(path: Path) -> int:
    flags = os.O_RDONLY | _DIRECTORY_FLAG | _CLOEXEC_FLAG | _NOFOLLOW_FLAG
    absolute = Path(os.path.abspath(path))
    descriptor: int | None = None
    try:
        descriptor = os.open(absolute.anchor, flags)
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child)
                raise ValueError("forensic path is not a directory")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _directory_is_within(candidate: Path, directory: Path) -> bool:
    """Compare ancestor directory identity, including case and Unicode aliases."""

    try:
        directory_metadata = directory.stat()
        current = candidate
        while True:
            if os.path.samestat(current.stat(), directory_metadata):
                return True
            parent = current.parent
            if parent == current:
                return False
            current = parent
    except OSError as exc:
        raise ValueError("forensic source and destination identities are unavailable") from exc


def _prefix_binding(binding: ManifestFileBinding, prefix: str) -> ManifestFileBinding:
    return ManifestFileBinding(
        path=f"{prefix}/{binding.path}",
        sha256=binding.sha256,
        size=binding.size,
    )


def _require_descriptor_fits_output_bound(descriptor: ForensicDeliveryDescriptor) -> None:
    try:
        encoded_size = len(stable_json(descriptor).encode("utf-8"))
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("forensic delivery descriptor cannot be encoded exactly") from exc
    if encoded_size > _MAX_DESCRIPTOR_BYTES:
        raise ValueError("forensic delivery descriptor exceeds its output bound")


def _require_safe_run_directory_name(value: str) -> str:
    if (
        _SAFE_RUN_NAME_PATTERN.fullmatch(value) is None
        or value.casefold() == "latest"
        or unicodedata.normalize("NFC", value) != value
        or is_sensitive_workspace_name(value)
    ):
        raise ValueError("forensic source run directory name must be one safe basename")
    return value


def _require_safe_component(value: str) -> None:
    if (
        not value
        or "/" in value
        or value in {".", ".."}
        or unicodedata.normalize("NFC", value) != value
        or normalize_relative_path(value) != value
        or is_sensitive_workspace_name(value)
    ):
        raise ValueError("forensic directory component is unsafe")


def _require_portable_paths(paths: list[str], directory_paths: list[str] | None = None) -> None:
    seen: dict[str, tuple[str, str]] = {}

    def register(path: str, *, leaf_kind: Literal["file", "directory"]) -> None:
        normalized = normalize_relative_path(path)
        if len(path) > 4_096 or normalized != path or unicodedata.normalize("NFC", path) != path:
            raise ValueError("forensic delivery path is not portable NFC")
        parts = PurePosixPath(path).parts
        for index in range(len(parts)):
            prefix = "/".join(parts[: index + 1])
            kind = leaf_kind if index == len(parts) - 1 else "directory"
            key = unicodedata.normalize("NFC", prefix).casefold()
            previous = seen.get(key)
            if previous is not None and previous != (prefix, kind):
                raise ValueError("forensic delivery paths contain a portable-name collision")
            seen[key] = (prefix, kind)

    for directory in directory_paths or []:
        register(directory, leaf_kind="directory")
    for path in paths:
        register(path, leaf_kind="file")


def _is_run_evidence_class(path: str, directory: Literal["private", "logs"]) -> bool:
    parts = PurePosixPath(path).parts
    return len(parts) >= 4 and parts[0] == _RUNS_DIRECTORY_NAME and parts[2] == directory


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
