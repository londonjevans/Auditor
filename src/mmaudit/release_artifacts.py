"""Observed, hash-bound runtime artifacts for release evidence."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import (
    ManifestFileBinding,
    RunEvidenceManifest,
    canonical_sha256,
    collect_run_artifacts,
    validate_manifest_artifacts,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_name
from mmaudit.traceability import (
    MaximumAssuranceTraceability,
    build_traceability_matrix,
    validate_traceability_evidence,
)

_MANIFEST_NAME = "run-evidence-manifest.json"
_TRACEABILITY_NAME = "maximum_assurance_traceability.json"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_EVIDENCE_BYTES = 100_000_000
_MAX_ARTIFACTS = 100_000


class ReleaseArtifactEvidencePayload(StrictModel):
    """Typed observation of one exact emitted audit-run inventory."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    manifest_path: Literal["run-evidence-manifest.json"]
    manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_count: int = Field(ge=1, le=_MAX_ARTIFACTS)
    artifact_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifacts: list[ManifestFileBinding] = Field(min_length=1, max_length=_MAX_ARTIFACTS)
    traceability_path: Literal["maximum_assurance_traceability.json"]
    traceability_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("artifacts")
    @classmethod
    def artifact_inventory_is_sorted_and_unique(
        cls,
        value: list[ManifestFileBinding],
    ) -> list[ManifestFileBinding]:
        paths = [binding.path for binding in value]
        if paths != sorted(set(paths)):
            raise ValueError("release artifact inventory must be unique and sorted")
        if _MANIFEST_NAME in paths:
            raise ValueError("release artifact inventory cannot contain its run manifest")
        return value

    @model_validator(mode="after")
    def counts_hashes_and_traceability_reconcile(self) -> ReleaseArtifactEvidencePayload:
        if self.artifact_count != len(self.artifacts):
            raise ValueError("release artifact count does not match the observed inventory")
        expected_inventory_sha256 = canonical_sha256(
            [binding.model_dump(mode="json") for binding in self.artifacts]
        )
        if self.artifact_inventory_sha256 != expected_inventory_sha256:
            raise ValueError("release artifact inventory hash is inconsistent")
        traceability = [
            binding for binding in self.artifacts if binding.path == self.traceability_path
        ]
        if len(traceability) != 1 or traceability[0].sha256 != self.traceability_sha256:
            raise ValueError("release traceability hash is not bound by the artifact inventory")
        return self


class ReleaseArtifactEvidence(ReleaseArtifactEvidencePayload):
    """Self-hashed release observation over files that were actually emitted."""

    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_hash_is_consistent(self) -> ReleaseArtifactEvidence:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("release artifact evidence hash is inconsistent")
        return self


def observe_release_artifacts(
    run_dir: Path,
    repository_root: Path,
) -> ReleaseArtifactEvidence:
    """Observe and bind a complete emitted run without trusting declared names."""

    root = _require_unlinked_directory(run_dir, label="release run")
    source_root = _require_unlinked_directory(repository_root, label="release repository")
    manifest_path = root / _MANIFEST_NAME
    manifest_before = _read_unique_regular_file(
        manifest_path,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="run evidence manifest",
    )
    manifest = RunEvidenceManifest.model_validate(
        _decode_json_object(manifest_before, label="run evidence manifest")
    )
    manifest_after = _read_unique_regular_file(
        manifest_path,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="run evidence manifest",
    )
    if manifest_before != manifest_after:
        raise ValueError("run evidence manifest changed while release artifacts were observed")
    if manifest.schema_version != "1.2" or manifest.run_configuration is None:
        raise ValueError(
            "release artifact evidence requires manifest schema 1.2 and its report bundle"
        )

    validate_manifest_artifacts(manifest, root)
    observed_artifacts = collect_run_artifacts(root)
    if observed_artifacts != manifest.artifacts:
        raise ValueError("observed release artifacts differ from the sealed run manifest")

    traceability_binding = next(
        (binding for binding in observed_artifacts if binding.path == _TRACEABILITY_NAME),
        None,
    )
    if traceability_binding is None:
        raise ValueError("emitted release artifacts lack maximum-assurance traceability")
    traceability_path = root / _TRACEABILITY_NAME
    traceability_bytes = _read_unique_regular_file(
        traceability_path,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="maximum-assurance traceability",
    )
    traceability_sha256 = hashlib.sha256(traceability_bytes).hexdigest()
    if (
        traceability_binding.size != len(traceability_bytes)
        or traceability_binding.sha256 != traceability_sha256
    ):
        raise ValueError("emitted traceability differs from its run-manifest binding")
    traceability = MaximumAssuranceTraceability.model_validate(
        _decode_json_object(traceability_bytes, label="maximum-assurance traceability")
    )
    expected_traceability = build_traceability_matrix(manifest.git_commit)
    if traceability != expected_traceability:
        raise ValueError("emitted maximum-assurance traceability is stale")

    runtime_artifacts = {binding.path for binding in observed_artifacts}
    runtime_artifacts.add(_MANIFEST_NAME)
    validate_traceability_evidence(
        traceability,
        repository_root=source_root,
        runtime_artifacts=runtime_artifacts,
    )

    manifest_final = _read_unique_regular_file(
        manifest_path,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="run evidence manifest",
    )
    traceability_final = _read_unique_regular_file(
        traceability_path,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="maximum-assurance traceability",
    )
    artifacts_final = collect_run_artifacts(root)
    if (
        manifest_final != manifest_before
        or traceability_final != traceability_bytes
        or artifacts_final != observed_artifacts
    ):
        raise ValueError("release evidence changed while it was being observed")

    inventory_sha256 = canonical_sha256(
        [binding.model_dump(mode="json") for binding in observed_artifacts]
    )
    payload = ReleaseArtifactEvidencePayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id=manifest.run_id,
        manifest_path=_MANIFEST_NAME,
        manifest_file_sha256=hashlib.sha256(manifest_before).hexdigest(),
        manifest_sha256=manifest.manifest_sha256,
        artifact_count=len(observed_artifacts),
        artifact_inventory_sha256=inventory_sha256,
        artifacts=observed_artifacts,
        traceability_path=_TRACEABILITY_NAME,
        traceability_sha256=traceability_sha256,
    )
    serialized = payload.model_dump(mode="json")
    return ReleaseArtifactEvidence.model_validate(
        {
            **serialized,
            "evidence_sha256": canonical_sha256(serialized),
        }
    )


def load_release_artifact_evidence(path: Path) -> ReleaseArtifactEvidence:
    """Load self-hashed release evidence from a bounded unshared non-link file."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive release-evidence filename")
    parent = _require_unlinked_directory(path.parent, label="release-evidence parent")
    data = _read_unique_regular_file(
        parent / path.name,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="release artifact evidence",
    )
    return ReleaseArtifactEvidence.model_validate(
        _decode_json_object(data, label="release artifact evidence")
    )


def write_release_artifact_evidence(
    path: Path,
    evidence: ReleaseArtifactEvidence,
) -> None:
    """Write self-hashed evidence to a fresh bounded non-link file."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive release-evidence filename")
    parent = _require_unlinked_directory(path.parent, label="release-evidence parent")
    destination = parent / path.name
    serialized = stable_json(evidence).encode("utf-8")
    if len(serialized) > _MAX_EVIDENCE_BYTES:
        raise ValueError("release artifact evidence exceeds its output bound")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(destination, flags, 0o600)
    except OSError as exc:
        raise ValueError("release artifact evidence destination must be a fresh file") from exc
    completed = False
    created_identity: tuple[int, int] | None = None
    verified_metadata: os.stat_result | None = None
    try:
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        created_identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError("release artifact evidence output is not a fresh private file")
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("release artifact evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        written_metadata = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        readback = bytearray()
        while len(readback) <= len(serialized):
            chunk = os.read(
                descriptor,
                min(1024 * 1024, len(serialized) + 1 - len(readback)),
            )
            if not chunk:
                break
            readback.extend(chunk)
        verified_metadata = os.fstat(descriptor)
        if (
            bytes(readback) != serialized
            or _stat_identity(written_metadata) != _stat_identity(verified_metadata)
            or verified_metadata.st_size != len(serialized)
            or verified_metadata.st_nlink != 1
        ):
            raise ValueError("release artifact evidence output changed while being written")
        completed = True
    finally:
        os.close(descriptor)
        if not completed:
            _unlink_matching_file(destination, created_identity)
    try:
        metadata = destination.lstat()
    except OSError as exc:
        raise ValueError("release artifact evidence output changed after writing") from exc
    if verified_metadata is None or _stat_identity(metadata) != _stat_identity(verified_metadata):
        _unlink_matching_file(destination, created_identity)
        raise ValueError("release artifact evidence output is not a unique regular file")


def _unlink_matching_file(path: Path, identity: tuple[int, int] | None) -> None:
    """Remove only the file object created by this writer."""

    if identity is None:
        return
    try:
        metadata = path.lstat()
    except OSError:
        return
    if (metadata.st_dev, metadata.st_ino) == identity:
        path.unlink(missing_ok=True)


def _require_unlinked_directory(path: Path, *, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError(f"{label} path may not traverse a link")
        metadata = absolute.lstat()
    except OSError as exc:
        raise ValueError(f"{label} directory is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a directory")
    return absolute.resolve(strict=True)


def _read_unique_regular_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is missing") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes:
        raise ValueError(f"{label} must be a bounded unshared regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} could not be opened safely") from exc
    try:
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            data = handle.read(max_bytes + 1)
            finished = os.fstat(handle.fileno())
    except OSError as exc:
        raise ValueError(f"{label} could not be read safely") from exc
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} changed while being read") from exc
    identities = {
        _stat_identity(before),
        _stat_identity(opened),
        _stat_identity(finished),
        _stat_identity(after),
    }
    if len(identities) != 1 or len(data) > max_bytes:
        raise ValueError(f"{label} changed or exceeded its bound while being read")
    return data


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
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value
