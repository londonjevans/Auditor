"""Fresh binding for independently recomputed run-verification evidence."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import (
    ManifestFileBinding,
    RunEvidenceManifest,
    canonical_sha256,
)
from mmaudit.orchestration.verification import (
    RunVerification,
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.release_artifacts import (
    _decode_json_object,
    _read_unique_regular_file,
    _require_unlinked_directory,
)
from mmaudit.release_run import ReleaseRunBinding, observe_release_run_binding
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name

_MANIFEST_NAME = "run-evidence-manifest.json"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_VERIFICATION_BYTES = 100_000_000
_MAX_SOURCE_BYTES = 4 * 1024**3
_READ_CHUNK_BYTES = 1024 * 1024


class ReleaseRunVerificationBindingPayload(StrictModel):
    """Canonical identity of one CURRENT verification and its bound run."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    run_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    target_source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: Literal[RunVerificationStatus.CURRENT]
    mismatches: int = Field(ge=0, le=0)
    verification_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    verification_file_size: int = Field(ge=1, le=_MAX_VERIFICATION_BYTES)
    verification_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("release run-verification time must be whole-second UTC")
        return value


class ReleaseRunVerificationBinding(ReleaseRunVerificationBindingPayload):
    """Self-hashed result of two equal, independent verification passes."""

    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def binding_hash_is_consistent(self) -> ReleaseRunVerificationBinding:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("release run-verification binding hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _BoundSourceObservation:
    binding: ManifestFileBinding
    identity: tuple[int, int, int, int, int, int, int]


def observe_release_run_verification(
    *,
    run_dir: Path,
    target_repository_root: Path,
    release_repository_root: Path,
    artifact_evidence_path: Path,
    verification_path: Path,
    run_binding: ReleaseRunBinding,
) -> ReleaseRunVerificationBinding:
    """Require a supplied CURRENT result to equal two fresh recomputations."""

    run_root = _require_unlinked_directory(run_dir, label="release run")
    target_root = _require_unlinked_directory(
        target_repository_root,
        label="release target repository",
    )
    release_root = _require_unlinked_directory(
        release_repository_root,
        label="mmaudit release repository",
    )
    supplied_run_binding = _strict_release_run_binding(run_binding)
    verification_parent = _require_unlinked_directory(
        verification_path.parent,
        label="run-verification parent",
    )
    if _directory_is_within(verification_parent, run_root):
        raise ValueError("run-verification evidence must be outside the emitted run")
    manifest_path = run_root / _MANIFEST_NAME
    manifest_model_before, manifest_before = _read_manifest_exact(manifest_path)
    _require_manifest_run_binding(
        manifest=manifest_model_before,
        manifest_bytes=manifest_before,
        run_binding=supplied_run_binding,
    )
    sources_before = _observe_bound_sources(
        target_root,
        manifest_model_before.sources,
        expected_tree_sha256=manifest_model_before.source_tree_sha256,
    )
    observed_run_before = _strict_release_run_binding(
        observe_release_run_binding(
            run_root,
            release_root,
            artifact_evidence_path,
        )
    )
    if _run_binding_state(observed_run_before) != _run_binding_state(supplied_run_binding):
        raise ValueError("supplied release run binding differs from fresh run evidence")

    supplied_before, supplied_bytes_before = _read_verification_exact(verification_path)
    computed_before = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_root,
        repository_root=target_root,
    )
    _require_current_equal_verification(
        supplied=supplied_before,
        computed=computed_before,
        run_binding=supplied_run_binding,
    )

    supplied_after, supplied_bytes_after = _read_verification_exact(verification_path)
    computed_after = verify_run_evidence(
        manifest_path=manifest_path,
        run_dir=run_root,
        repository_root=target_root,
    )
    observed_run_after = _strict_release_run_binding(
        observe_release_run_binding(
            run_root,
            release_root,
            artifact_evidence_path,
        )
    )
    manifest_model_after, manifest_after = _read_manifest_exact(manifest_path)
    _require_manifest_run_binding(
        manifest=manifest_model_after,
        manifest_bytes=manifest_after,
        run_binding=supplied_run_binding,
    )
    sources_after = _observe_bound_sources(
        target_root,
        manifest_model_after.sources,
        expected_tree_sha256=manifest_model_after.source_tree_sha256,
    )
    if (
        supplied_after != supplied_before
        or supplied_bytes_after != supplied_bytes_before
        or manifest_after != manifest_before
        or manifest_model_after != manifest_model_before
        or computed_after != computed_before
        or _run_binding_state(observed_run_after) != _run_binding_state(observed_run_before)
        or _run_binding_state(observed_run_after) != _run_binding_state(supplied_run_binding)
        or sources_after != sources_before
    ):
        raise ValueError("run-verification inputs changed while being bound")
    _require_current_equal_verification(
        supplied=supplied_after,
        computed=computed_after,
        run_binding=supplied_run_binding,
    )
    final_source_identities = _snapshot_bound_source_identities(
        target_root,
        manifest_model_after.sources,
    )
    if final_source_identities != tuple(item.identity for item in sources_after):
        raise ValueError("release target sources changed after verification")
    supplied_final, supplied_bytes_final = _read_verification_exact(verification_path)
    manifest_model_final, manifest_final = _read_manifest_exact(manifest_path)
    if (
        supplied_final != supplied_before
        or supplied_bytes_final != supplied_bytes_before
        or manifest_model_final != manifest_model_before
        or manifest_final != manifest_before
    ):
        raise ValueError("run-verification evidence changed after verification")

    payload = ReleaseRunVerificationBindingPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id=supplied_before.run_id,
        run_binding_sha256=supplied_run_binding.binding_sha256,
        manifest_sha256=supplied_before.manifest_sha256,
        manifest_file_sha256=supplied_run_binding.manifest_file_sha256,
        target_source_tree_sha256=supplied_run_binding.target_source_tree_sha256,
        effective_config_sha256=supplied_run_binding.effective_config_sha256,
        status=RunVerificationStatus.CURRENT,
        mismatches=0,
        verification_file_sha256=hashlib.sha256(supplied_bytes_before).hexdigest(),
        verification_file_size=len(supplied_bytes_before),
        verification_sha256=supplied_before.verification_sha256,
        observed_at=datetime.now(UTC).replace(microsecond=0),
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseRunVerificationBinding.model_validate(
        {
            **serialized,
            "binding_sha256": canonical_sha256(serialized),
        }
    )


def _strict_release_run_binding(run_binding: ReleaseRunBinding) -> ReleaseRunBinding:
    if type(run_binding) is not ReleaseRunBinding:
        raise ValueError("release verification requires an exact release run binding")
    try:
        validated = ReleaseRunBinding.model_validate(run_binding.model_dump(mode="json"))
    except (TypeError, ValueError) as exc:
        raise ValueError("release run binding failed integrity validation") from exc
    if validated != run_binding:
        raise ValueError("release run binding changed after validation")
    return validated


def _run_binding_state(run_binding: ReleaseRunBinding) -> dict[str, object]:
    return run_binding.model_dump(
        mode="json",
        exclude={"observed_at", "binding_sha256"},
    )


def _read_manifest_exact(path: Path) -> tuple[RunEvidenceManifest, bytes]:
    data = _read_unique_regular_file(
        path,
        max_bytes=_MAX_VERIFICATION_BYTES,
        label="run evidence manifest",
    )
    return (
        RunEvidenceManifest.model_validate(
            _decode_json_object(data, label="run evidence manifest")
        ),
        data,
    )


def _require_manifest_run_binding(
    *,
    manifest: RunEvidenceManifest,
    manifest_bytes: bytes,
    run_binding: ReleaseRunBinding,
) -> None:
    run_configuration = manifest.run_configuration
    if manifest.schema_version != "1.1" or run_configuration is None:
        raise ValueError("release verification requires reconstructable manifest schema 1.1")
    expected = (
        manifest.run_id,
        manifest.repository_root_name,
        manifest.git_commit,
        manifest.source_tree_sha256,
        hashlib.sha256(manifest_bytes).hexdigest(),
        manifest.manifest_sha256,
        canonical_sha256(run_configuration.model_dump(mode="json")),
        run_configuration.file_config_sha256,
        run_configuration.environment_overrides_sha256,
        run_configuration.cli_overrides_sha256,
        run_configuration.run_options_sha256,
        run_configuration.effective_config_sha256,
        run_configuration.model_config_sha256,
        run_configuration.invocation_sha256,
        run_configuration.requested_profile,
        run_configuration.achieved_profile,
    )
    supplied = (
        run_binding.run_id,
        run_binding.target_repository_name,
        run_binding.target_git_commit,
        run_binding.target_source_tree_sha256,
        run_binding.manifest_file_sha256,
        run_binding.manifest_sha256,
        run_binding.run_configuration_sha256,
        run_binding.file_config_sha256,
        run_binding.environment_overrides_sha256,
        run_binding.cli_overrides_sha256,
        run_binding.run_options_sha256,
        run_binding.effective_config_sha256,
        run_binding.model_config_sha256,
        run_binding.invocation_sha256,
        run_binding.requested_profile,
        run_binding.achieved_profile,
    )
    if supplied != expected:
        raise ValueError("release run binding differs from the exact run manifest")


def _observe_bound_sources(
    root: Path,
    expected_sources: list[ManifestFileBinding],
    *,
    expected_tree_sha256: str,
) -> tuple[_BoundSourceObservation, ...]:
    observations: list[_BoundSourceObservation] = []
    total_bytes = 0
    for expected in expected_sources:
        path, before = _require_unlinked_source_file(root, expected.path)
        if before.st_size != expected.size:
            raise ValueError("release target source size differs from its manifest binding")
        total_bytes += before.st_size
        if total_bytes > _MAX_SOURCE_BYTES:
            raise ValueError("release target sources exceed their byte limit")
        digest, finished = _hash_bound_source_file(path, before=before)
        observed = ManifestFileBinding(
            path=expected.path,
            sha256=digest,
            size=finished.st_size,
        )
        if observed != expected:
            raise ValueError("release target source differs from its manifest binding")
        observations.append(
            _BoundSourceObservation(
                binding=observed,
                identity=_stat_identity(finished),
            )
        )
    observed_bindings = [item.binding.model_dump(mode="json") for item in observations]
    if canonical_sha256(observed_bindings) != expected_tree_sha256:
        raise ValueError("release target source inventory differs from its manifest")
    return tuple(observations)


def _require_unlinked_source_file(
    root: Path,
    relative: str,
) -> tuple[Path, os.stat_result]:
    normalized = normalize_relative_path(relative)
    if normalized != relative:
        raise ValueError("release target source path is not canonical")
    current = root
    parts = tuple(relative.split("/"))
    try:
        for index, part in enumerate(parts):
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError("release target source path may not traverse a link")
            if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("release target source parent is not a directory")
        metadata = current.lstat()
    except OSError as exc:
        raise ValueError("release target source is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > _MAX_SOURCE_BYTES
    ):
        raise ValueError("release target source must be bounded and unshared")
    return current, metadata


def _hash_bound_source_file(
    path: Path,
    *,
    before: os.stat_result,
) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("release target source could not be opened safely") from exc
    digest = hashlib.sha256()
    observed_bytes = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise ValueError("release target source changed before hashing")
        while observed_bytes <= before.st_size:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, before.st_size + 1 - observed_bytes),
            )
            if not chunk:
                break
            observed_bytes += len(chunk)
            digest.update(chunk)
        finished = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError("release target source could not be hashed safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("release target source changed while being hashed") from exc
    if (
        len(
            {
                _stat_identity(before),
                _stat_identity(opened),
                _stat_identity(finished),
                _stat_identity(after),
            }
        )
        != 1
        or observed_bytes != before.st_size
    ):
        raise ValueError("release target source changed while being hashed")
    return digest.hexdigest(), finished


def _snapshot_bound_source_identities(
    root: Path,
    expected_sources: list[ManifestFileBinding],
) -> tuple[tuple[int, int, int, int, int, int, int], ...]:
    return tuple(
        _stat_identity(_require_unlinked_source_file(root, source.path)[1])
        for source in expected_sources
    )


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


def _read_verification_exact(path: Path) -> tuple[RunVerification, bytes]:
    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive run-verification filename")
    parent = _require_unlinked_directory(path.parent, label="run-verification parent")
    data = _read_unique_regular_file(
        parent / path.name,
        max_bytes=_MAX_VERIFICATION_BYTES,
        label="run verification",
    )
    return (
        RunVerification.model_validate(_decode_json_object(data, label="run verification")),
        data,
    )


def _require_current_equal_verification(
    *,
    supplied: RunVerification,
    computed: RunVerification,
    run_binding: ReleaseRunBinding,
) -> None:
    if (
        supplied.status is not RunVerificationStatus.CURRENT
        or supplied.mismatches
        or supplied != computed
    ):
        raise ValueError("release run requires an exact freshly recomputed CURRENT verification")
    if (
        supplied.run_id != run_binding.run_id
        or supplied.manifest_sha256 != run_binding.manifest_sha256
    ):
        raise ValueError("run verification differs from the release run binding")


def _directory_is_within(candidate: Path, directory: Path) -> bool:
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
        raise ValueError("run-verification paths are unavailable") from exc
