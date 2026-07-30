"""Strict provider-free validation and staging for model-refresh evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Sequence
from contextlib import suppress
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.qualification import CandidateRegistry
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    ModelRefreshAttemptStatus,
    ModelRefreshFreshnessState,
    ModelRefreshSnapshot,
    RefreshBaselineKind,
    SelectedModelRoute,
    load_model_refresh_attempt,
    load_model_refresh_diff,
    load_model_refresh_freshness,
    load_model_refresh_snapshot,
)
from mmaudit.release_io import read_json_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json

WORKFLOW_STATUS_FILENAME = "workflow-status.json"
_SUCCESS_FILENAMES = frozenset(
    {
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
    }
)
_FAILURE_FILENAMES = frozenset({ATTEMPT_FILENAME})
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_WORKFLOW_NUMBER_PATTERN = r"^[1-9][0-9]{0,19}$"
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_MAX_ARTIFACT_BYTES = 20_000_000


class ModelRefreshStagingError(ValueError):
    """Raised when emitted refresh evidence is unsafe or internally inconsistent."""


class ModelRefreshWorkflowDisposition(StrEnum):
    COMPLETED = "COMPLETED"
    PRODUCTION_BLOCKED = "PRODUCTION_BLOCKED"
    FAILED = "FAILED"
    PREREQUISITE_MISSING = "PREREQUISITE_MISSING"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StagedModelRefreshArtifact(_FrozenModel):
    """Content and internal identity for one validated staged artifact."""

    filename: Literal[
        "model-refresh-snapshot.json",
        "model-refresh-diff.json",
        "model-refresh-attempt.json",
        "model-refresh-freshness.json",
    ]
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    byte_count: int = Field(ge=1, le=_MAX_ARTIFACT_BYTES)


class ModelRefreshWorkflowStatus(_FrozenModel):
    """Commit-bound inventory for one scheduled refresh attempt."""

    schema_version: Literal["1.0"] = "1.0"
    disposition: ModelRefreshWorkflowDisposition
    refresh_exit_status: int = Field(ge=0, le=255)
    source_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    workflow_run_id: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    workflow_run_attempt: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_tolerance_fraction: str
    soft_max_age_hours: int = Field(ge=1, le=24 * 30)
    hard_max_age_hours: int = Field(ge=2, le=24 * 90)
    artifacts: tuple[StagedModelRefreshArtifact, ...]
    workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("pricing_tolerance_fraction")
    @classmethod
    def pricing_tolerance_is_canonical(cls, value: str) -> str:
        parsed = _canonical_fraction(value)
        if parsed > 1:
            raise ValueError("refresh workflow pricing tolerance cannot exceed one")
        return value

    @model_validator(mode="after")
    def status_is_canonical_and_self_bound(self) -> Self:
        if self.hard_max_age_hours <= self.soft_max_age_hours:
            raise ValueError("refresh workflow hard age must exceed its soft age")
        filenames = tuple(artifact.filename for artifact in self.artifacts)
        if filenames != tuple(sorted(set(filenames))):
            raise ValueError("staged refresh artifact inventory must be unique and sorted")
        expected_names: frozenset[str]
        if self.disposition in {
            ModelRefreshWorkflowDisposition.COMPLETED,
            ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
        }:
            expected_names = _SUCCESS_FILENAMES
        elif self.disposition is ModelRefreshWorkflowDisposition.FAILED:
            expected_names = _FAILURE_FILENAMES
        else:
            expected_names = frozenset()
        if set(filenames) != expected_names:
            raise ValueError("staged refresh artifact inventory differs from its disposition")
        expected_exit_disposition = _disposition_for_exit(self.refresh_exit_status)
        if self.disposition is not expected_exit_disposition:
            raise ValueError("staged refresh disposition differs from its exit status")
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"workflow_status_sha256"})
        )
        if self.workflow_status_sha256 != expected:
            raise ValueError("staged refresh workflow status self-hash is inconsistent")
        return self


def stage_model_refresh_evidence(
    *,
    output_dir: Path,
    staging_dir: Path,
    candidate_registry: CandidateRegistry,
    refresh_exit_status: int,
    source_commit: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    pricing_tolerance_fraction: str,
    soft_max_age_hours: int,
    hard_max_age_hours: int,
    previous_snapshot: ModelRefreshSnapshot | None = None,
    expected_selected_routes: Sequence[SelectedModelRoute] = (),
) -> ModelRefreshWorkflowStatus:
    """Validate one exact emitted bundle and reconstruct canonical upload evidence."""

    if isinstance(refresh_exit_status, bool) or not 0 <= refresh_exit_status <= 255:
        raise ModelRefreshStagingError("refresh exit status must be an integer from zero to 255")
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    tolerance = _canonical_fraction(pricing_tolerance_fraction)
    if tolerance > 1:
        raise ModelRefreshStagingError("refresh staging pricing tolerance cannot exceed one")
    if (
        isinstance(soft_max_age_hours, bool)
        or isinstance(hard_max_age_hours, bool)
        or not isinstance(soft_max_age_hours, int)
        or not isinstance(hard_max_age_hours, int)
        or not 1 <= soft_max_age_hours <= 24 * 30
        or not 2 <= hard_max_age_hours <= 24 * 90
        or hard_max_age_hours <= soft_max_age_hours
    ):
        raise ModelRefreshStagingError("refresh staging freshness policy is invalid")
    disposition = _disposition_for_exit(refresh_exit_status)
    expected_names = _expected_output_names(disposition)
    if disposition is ModelRefreshWorkflowDisposition.PREREQUISITE_MISSING:
        if output_dir.exists() or output_dir.is_symlink():
            raise ModelRefreshStagingError(
                "prerequisite-missing refresh must not emit an output directory"
            )
        validated: dict[str, BaseModel] = {}
    else:
        before = _observe_exact_private_directory(output_dir, expected_names=expected_names)
        validated = _load_and_validate_bundle(
            output_dir=output_dir,
            disposition=disposition,
            registry=registry,
            previous_snapshot=previous_snapshot,
            expected_selected_routes=expected_selected_routes,
            pricing_tolerance_fraction=pricing_tolerance_fraction,
            soft_max_age_hours=soft_max_age_hours,
            hard_max_age_hours=hard_max_age_hours,
        )
        after = _observe_exact_private_directory(output_dir, expected_names=expected_names)
        if before != after:
            raise ModelRefreshStagingError("refresh output changed while being validated")

    staging_root = _create_private_staging_directory(staging_dir)
    completed = False
    try:
        bindings: list[StagedModelRefreshArtifact] = []
        for filename in sorted(validated):
            artifact = validated[filename]
            raw = stable_json(artifact).encode("utf-8")
            write_json_evidence(
                evidence_root=staging_root,
                relative_path=filename,
                value=artifact,
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
            bindings.append(
                StagedModelRefreshArtifact(
                    filename=filename,
                    content_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_sha256=_artifact_self_hash(artifact),
                    byte_count=len(raw),
                )
            )

        status_values = {
            "schema_version": "1.0",
            "disposition": disposition.value,
            "refresh_exit_status": refresh_exit_status,
            "source_commit": source_commit,
            "workflow_run_id": workflow_run_id,
            "workflow_run_attempt": workflow_run_attempt,
            "candidate_registry_sha256": registry.registry_sha256,
            "pricing_tolerance_fraction": pricing_tolerance_fraction,
            "soft_max_age_hours": soft_max_age_hours,
            "hard_max_age_hours": hard_max_age_hours,
            "artifacts": [binding.model_dump(mode="json") for binding in bindings],
        }
        status_values["workflow_status_sha256"] = _canonical_sha256(status_values)
        try:
            status = ModelRefreshWorkflowStatus.model_validate(status_values)
        except ValueError as exc:
            raise ModelRefreshStagingError("refresh workflow identity is invalid") from exc
        write_json_evidence(
            evidence_root=staging_root,
            relative_path=WORKFLOW_STATUS_FILENAME,
            value=status,
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        _observe_exact_private_directory(
            staging_root,
            expected_names=expected_names | {WORKFLOW_STATUS_FILENAME},
        )
        completed = True
        return status
    finally:
        if not completed:
            _remove_fresh_staging_directory(staging_root)


def load_model_refresh_workflow_status(path: Path) -> ModelRefreshWorkflowStatus:
    """Load one canonical status through descriptor-safe evidence I/O."""

    if path.name != WORKFLOW_STATUS_FILENAME:
        raise ModelRefreshStagingError("refresh workflow status filename is invalid")
    try:
        observation = read_json_evidence(
            evidence_root=path.parent,
            relative_path=path.name,
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        status = ModelRefreshWorkflowStatus.model_validate(observation.value)
    except ValueError as exc:
        raise ModelRefreshStagingError("refresh workflow status failed strict validation") from exc
    if observation.content != stable_json(status).encode("utf-8"):
        raise ModelRefreshStagingError("refresh workflow status is not canonical")
    return status


def _load_and_validate_bundle(
    *,
    output_dir: Path,
    disposition: ModelRefreshWorkflowDisposition,
    registry: CandidateRegistry,
    previous_snapshot: ModelRefreshSnapshot | None,
    expected_selected_routes: Sequence[SelectedModelRoute],
    pricing_tolerance_fraction: str,
    soft_max_age_hours: int,
    hard_max_age_hours: int,
) -> dict[str, BaseModel]:
    attempt = load_model_refresh_attempt(output_dir / ATTEMPT_FILENAME)
    if attempt.candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshStagingError("refresh attempt binds a different candidate registry")
    if disposition is ModelRefreshWorkflowDisposition.FAILED:
        if attempt.status is not ModelRefreshAttemptStatus.FAILED:
            raise ModelRefreshStagingError("failed refresh exit lacks a failed attempt artifact")
        return {ATTEMPT_FILENAME: attempt}

    snapshot = load_model_refresh_snapshot(output_dir / SNAPSHOT_FILENAME)
    diff = load_model_refresh_diff(output_dir / DIFF_FILENAME)
    freshness = load_model_refresh_freshness(output_dir / FRESHNESS_FILENAME)
    expected_routes = tuple(
        sorted(
            (
                SelectedModelRoute.model_validate(route.model_dump(mode="json"))
                for route in expected_selected_routes
            ),
            key=lambda route: (route.exact_model_id, route.provider_endpoint),
        )
    )
    if len(expected_routes) != len(
        {(route.exact_model_id, route.provider_endpoint) for route in expected_routes}
    ):
        raise ModelRefreshStagingError("expected refresh selected routes contain duplicates")
    if snapshot.authenticated_metadata is not True:
        raise ModelRefreshStagingError("refresh snapshot lacks authenticated metadata evidence")
    if snapshot.candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshStagingError("refresh snapshot binds a different candidate registry")
    if diff.candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshStagingError("refresh diff binds a different candidate registry")
    if (
        attempt.snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.diff_sha256 != diff.diff_sha256
        or diff.current_snapshot_sha256 != snapshot.snapshot_sha256
        or freshness.snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.status is not diff.status
        or diff.selected_routes != expected_routes
        or diff.pricing_tolerance_fraction != pricing_tolerance_fraction
        or freshness.soft_max_age_hours != soft_max_age_hours
        or freshness.hard_max_age_hours != hard_max_age_hours
        or freshness.production_selection_present != bool(expected_routes)
    ):
        raise ModelRefreshStagingError("refresh success bundle has inconsistent hash bindings")
    if freshness.state is not ModelRefreshFreshnessState.CURRENT:
        raise ModelRefreshStagingError("newly emitted refresh evidence is not current")
    if not (
        attempt.attempted_at <= snapshot.retrieved_at == diff.compared_at == freshness.observed_at
    ):
        raise ModelRefreshStagingError("refresh success bundle time ordering is inconsistent")
    if diff.baseline_kind is RefreshBaselineKind.CANDIDATE_REGISTRY_HASH_ONLY:
        if diff.baseline_sha256 != registry.registry_sha256 or previous_snapshot is not None:
            raise ModelRefreshStagingError("refresh bootstrap baseline binding is inconsistent")
    else:
        if previous_snapshot is None:
            raise ModelRefreshStagingError(
                "refresh previous-snapshot baseline is unavailable for validation"
            )
        previous = ModelRefreshSnapshot.model_validate(previous_snapshot.model_dump(mode="json"))
        if (
            previous.snapshot_sha256 != diff.baseline_sha256
            or previous.candidate_registry_sha256 != registry.registry_sha256
            or previous.retrieved_at > snapshot.retrieved_at
        ):
            raise ModelRefreshStagingError("refresh previous-snapshot baseline binding is invalid")
    if disposition is ModelRefreshWorkflowDisposition.COMPLETED:
        if attempt.status not in {
            ModelRefreshAttemptStatus.UNCHANGED,
            ModelRefreshAttemptStatus.CHANGED,
        }:
            raise ModelRefreshStagingError("successful refresh exit has a blocking attempt status")
    elif attempt.status is not ModelRefreshAttemptStatus.PRODUCTION_BLOCKED:
        raise ModelRefreshStagingError(
            "incomplete refresh exit lacks a production-blocked attempt status"
        )
    return {
        SNAPSHOT_FILENAME: snapshot,
        DIFF_FILENAME: diff,
        ATTEMPT_FILENAME: attempt,
        FRESHNESS_FILENAME: freshness,
    }


def _expected_output_names(
    disposition: ModelRefreshWorkflowDisposition,
) -> frozenset[str]:
    if disposition in {
        ModelRefreshWorkflowDisposition.COMPLETED,
        ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
    }:
        return _SUCCESS_FILENAMES
    if disposition is ModelRefreshWorkflowDisposition.FAILED:
        return _FAILURE_FILENAMES
    return frozenset()


def _disposition_for_exit(exit_status: int) -> ModelRefreshWorkflowDisposition:
    if exit_status == 0:
        return ModelRefreshWorkflowDisposition.COMPLETED
    if exit_status == 6:
        return ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED
    if exit_status == 4:
        return ModelRefreshWorkflowDisposition.FAILED
    if exit_status == 78:
        return ModelRefreshWorkflowDisposition.PREREQUISITE_MISSING
    raise ModelRefreshStagingError("refresh exit status is not an accepted workflow result")


def _artifact_self_hash(artifact: BaseModel) -> str:
    for field in (
        "snapshot_sha256",
        "diff_sha256",
        "attempt_sha256",
        "freshness_sha256",
    ):
        value = getattr(artifact, field, None)
        if isinstance(value, str) and re.fullmatch(_SHA256_PATTERN, value):
            return value
    raise ModelRefreshStagingError("refresh artifact lacks a recognized self-hash")


def _canonical_fraction(value: str) -> Decimal:
    if not isinstance(value, str):
        raise ModelRefreshStagingError("refresh staging fraction must be decimal text")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ModelRefreshStagingError("refresh staging fraction is invalid") from exc
    rendered = format(parsed, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    normalized = "0" if rendered in {"", "-0"} else rendered
    if not parsed.is_finite() or parsed < 0 or normalized != value:
        raise ModelRefreshStagingError("refresh staging fraction is not canonical")
    return parsed


def _observe_exact_private_directory(
    path: Path,
    *,
    expected_names: frozenset[str] | set[str],
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise ModelRefreshStagingError("refresh staging requires descriptor-safe directories")
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise ModelRefreshStagingError("refresh artifact directory is unavailable") from exc
    try:
        directory_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
        ):
            raise ModelRefreshStagingError("refresh artifact directory must be private")
        names = tuple(sorted(os.listdir(descriptor)))
        if set(names) != set(expected_names) or len(names) != len(expected_names):
            raise ModelRefreshStagingError("refresh artifact directory inventory is unexpected")
        observed: list[tuple[str, tuple[int, ...]]] = []
        for name in names:
            if "/" in name or name in {"", ".", ".."}:
                raise ModelRefreshStagingError("refresh artifact filename is unsafe")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                or not 0 < metadata.st_size <= _MAX_ARTIFACT_BYTES
            ):
                raise ModelRefreshStagingError(
                    "refresh artifact must be private, bounded, regular, and unshared"
                )
            observed.append((name, _file_identity(metadata)))
        return tuple(observed)
    except OSError as exc:
        raise ModelRefreshStagingError("refresh artifact directory could not be observed") from exc
    finally:
        os.close(descriptor)


def _create_private_staging_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute.parent)
    if not absolute.parent.is_dir():
        raise ModelRefreshStagingError("refresh staging parent must already exist")
    try:
        os.mkdir(absolute, _PRIVATE_DIRECTORY_MODE)
    except OSError as exc:
        raise ModelRefreshStagingError("refresh staging directory must be fresh") from exc
    metadata = os.lstat(absolute)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        _remove_fresh_staging_directory(absolute)
        raise ModelRefreshStagingError("refresh staging directory is not private")
    return absolute


def _reject_linked_components(path: Path) -> None:
    cursor = path
    while True:
        if cursor.is_symlink() or cursor.is_junction():
            raise ModelRefreshStagingError("refresh artifact path may not traverse links")
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _remove_fresh_staging_directory(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    quarantine = path.with_name(f".{path.name}.rejected-{uuid.uuid4().hex}")
    try:
        os.rename(path, quarantine)
        path = quarantine
    except OSError:
        pass
    for name in (*_SUCCESS_FILENAMES, WORKFLOW_STATUS_FILENAME):
        candidate = path / name
        try:
            if candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()
        except OSError:
            pass
    with suppress(OSError):
        path.rmdir()
