"""Fail-closed observation of the exact clean mmaudit release candidate."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

import mmaudit
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_OBJECT_PATTERN = r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$"
_MAX_TRACKED_FILES = 100_000
_MAX_TRACKED_BYTES = 4 * 1024**3
_MAX_GIT_OUTPUT_BYTES = 512 * 1024**2
_READ_CHUNK_BYTES = 1024 * 1024
_EMPTY_STATUS_SHA256 = canonical_sha256([])


class ReleaseCandidateObservation(StrictModel):
    """Self-hashed evidence for one exact, fully tracked clean candidate."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    candidate_commit: str = Field(pattern=_GIT_OBJECT_PATTERN)
    git_object_format: Literal["sha1", "sha256"]
    candidate_tree_object: str = Field(pattern=_GIT_OBJECT_PATTERN)
    tracked_source_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    tracked_file_count: int = Field(ge=1, le=_MAX_TRACKED_FILES)
    tracked_file_bytes: int = Field(ge=0, le=_MAX_TRACKED_BYTES)
    worktree_clean: Literal[True]
    worktree_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime
    observation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("release candidate observation time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def object_and_observation_hashes_are_consistent(self) -> ReleaseCandidateObservation:
        expected_length = 40 if self.git_object_format == "sha1" else 64
        if (
            len(self.candidate_commit) != expected_length
            or len(self.candidate_tree_object) != expected_length
        ):
            raise ValueError("release candidate Git object length is inconsistent")
        if self.worktree_status_sha256 != _EMPTY_STATUS_SHA256:
            raise ValueError("release candidate worktree status is not the canonical empty set")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"observation_sha256"}))
        if self.observation_sha256 != expected:
            raise ValueError("release candidate observation hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class _TrackedEntry:
    path: str
    mode: Literal["100644", "100755"]
    object_id: str


@dataclass(frozen=True, slots=True)
class _TrackedFileObservation:
    record: dict[str, str | int]
    identity: tuple[int, int, int, int, int, int, int]


def observe_release_candidate(root: Path) -> ReleaseCandidateObservation:
    """Observe a stable clean HEAD and every committed regular worktree file."""

    repository_root = _require_executing_repository_root(root)
    git = _trusted_git_executable()
    top_level = _decode_single_line(
        _run_git(git, repository_root, ("rev-parse", "--show-toplevel")),
        label="Git worktree root",
    )
    try:
        observed_top_level = Path(top_level).resolve(strict=True)
    except OSError as exc:
        raise ValueError("release candidate Git worktree root is unavailable") from exc
    if observed_top_level != repository_root:
        raise ValueError("release candidate root is not the exact Git worktree")

    status_arguments = (
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=all",
    )
    status_before = _run_git(git, repository_root, status_arguments)
    if status_before:
        raise ValueError("release candidate worktree is not clean")

    candidate_commit = _observe_git_object(
        git,
        repository_root,
        revision="HEAD^{commit}",
        label="release candidate commit",
    )
    git_object_format = _decode_single_line(
        _run_git(git, repository_root, ("rev-parse", "--show-object-format")),
        label="Git object format",
    )
    if git_object_format not in {"sha1", "sha256"}:
        raise ValueError("release candidate Git object format is unsupported")
    expected_object_length = 40 if git_object_format == "sha1" else 64
    if len(candidate_commit) != expected_object_length:
        raise ValueError("release candidate commit identity is malformed")
    candidate_tree = _observe_git_object(
        git,
        repository_root,
        revision="HEAD^{tree}",
        label="release candidate tree",
    )
    if len(candidate_tree) != expected_object_length:
        raise ValueError("release candidate tree identity is malformed")

    tree_arguments = ("ls-tree", "-r", "-z", "--full-tree", candidate_commit)
    tree_before = _run_git(git, repository_root, tree_arguments)
    entries = _parse_tracked_entries(
        tree_before,
        git_object_format=git_object_format,
    )
    first_files, first_total = _observe_tracked_files(
        repository_root,
        entries,
        git_object_format=git_object_format,
    )
    second_files, second_total = _observe_tracked_files(
        repository_root,
        entries,
        git_object_format=git_object_format,
    )
    if first_files != second_files or first_total != second_total:
        raise ValueError("release candidate tracked files changed during observation")

    tree_after = _run_git(git, repository_root, tree_arguments)
    candidate_commit_after = _observe_git_object(
        git,
        repository_root,
        revision="HEAD^{commit}",
        label="release candidate commit",
    )
    candidate_tree_after = _observe_git_object(
        git,
        repository_root,
        revision="HEAD^{tree}",
        label="release candidate tree",
    )
    status_after = _run_git(git, repository_root, status_arguments)
    if (
        tree_after != tree_before
        or candidate_commit_after != candidate_commit
        or candidate_tree_after != candidate_tree
        or status_after
    ):
        raise ValueError("release candidate changed during observation")

    final_identities = _snapshot_tracked_identities(repository_root, entries)
    if final_identities != tuple(observation.identity for observation in second_files):
        raise ValueError("release candidate tracked files changed after hashing")

    records = [observation.record for observation in second_files]
    observed_at = datetime.now(UTC).replace(microsecond=0)
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "candidate_commit": candidate_commit,
        "git_object_format": git_object_format,
        "candidate_tree_object": candidate_tree,
        "tracked_source_inventory_sha256": canonical_sha256(records),
        "tracked_file_count": len(records),
        "tracked_file_bytes": second_total,
        "worktree_clean": True,
        "worktree_status_sha256": _EMPTY_STATUS_SHA256,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
    }
    return ReleaseCandidateObservation.model_validate(
        {
            **payload,
            "observation_sha256": canonical_sha256(payload),
        }
    )


def _require_executing_repository_root(root: Path) -> Path:
    repository_root = _require_unlinked_directory(root, label="release candidate repository")
    package_file = mmaudit.__file__
    if package_file is None:
        raise ValueError("executing mmaudit package location is unavailable")
    try:
        executing_package = Path(package_file).parent.resolve(strict=True)
        candidate_package = (repository_root / "src" / "mmaudit").resolve(strict=True)
    except OSError as exc:
        raise ValueError("release candidate package is unavailable") from exc
    if candidate_package != executing_package:
        raise ValueError("release candidate root does not contain the executing mmaudit package")
    return repository_root


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
        raise ValueError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a directory")
    return absolute.resolve(strict=True)


def _trusted_git_executable() -> Path:
    for candidate in (Path("/usr/bin/git"), Path("/bin/git")):
        try:
            declared = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            observed = resolved.stat()
        except OSError:
            continue
        if (
            stat.S_ISLNK(declared.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or stat.S_IMODE(observed.st_mode) & 0o022
        ):
            continue
        return resolved
    raise ValueError("fixed trusted Git executable is unavailable")


def _git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": "/tmp",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _run_git(
    git: Path,
    root: Path,
    arguments: tuple[str, ...],
    *,
    timeout: int = 30,
) -> bytes:
    try:
        result = subprocess.run(
            [
                str(git),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "protocol.allow=never",
                "-c",
                "submodule.recurse=false",
                "-C",
                str(root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            timeout=timeout,
            env=_git_environment(),
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("trusted Git release candidate observation failed") from exc
    if result.returncode != 0 or result.stderr:
        raise ValueError("trusted Git release candidate observation was rejected")
    if len(result.stdout) > _MAX_GIT_OUTPUT_BYTES or len(result.stderr) > _MAX_GIT_OUTPUT_BYTES:
        raise ValueError("trusted Git release candidate output exceeds its bound")
    return result.stdout


def _observe_git_object(
    git: Path,
    root: Path,
    *,
    revision: str,
    label: str,
) -> str:
    value = _decode_single_line(
        _run_git(git, root, ("rev-parse", "--verify", revision)),
        label=label,
    )
    if re.fullmatch(_GIT_OBJECT_PATTERN, value) is None:
        raise ValueError(f"{label} identity is malformed")
    return value


def _decode_single_line(value: bytes, *, label: str) -> str:
    try:
        decoded = value.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise ValueError(f"{label} output is malformed") from exc
    if not decoded.endswith("\n") or decoded.count("\n") != 1:
        raise ValueError(f"{label} output is malformed")
    result = decoded[:-1]
    if not result or "\r" in result:
        raise ValueError(f"{label} output is malformed")
    return result


def _parse_tracked_entries(
    output: bytes,
    *,
    git_object_format: str,
) -> tuple[_TrackedEntry, ...]:
    if not output.endswith(b"\0") or b"\0\0" in output:
        raise ValueError("release candidate Git inventory is malformed")
    raw_entries = tuple(output[:-1].split(b"\0"))
    if not raw_entries or len(raw_entries) > _MAX_TRACKED_FILES:
        raise ValueError("release candidate tracked inventory is empty or excessive")
    expected_object_length = 40 if git_object_format == "sha1" else 64
    entries: list[_TrackedEntry] = []
    collision_keys: set[str] = set()
    for raw_entry in raw_entries:
        try:
            header, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii", errors="strict").split(" ")
            relative = raw_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError):
            raise ValueError("release candidate Git inventory is malformed") from None
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("release candidate Git inventory contains an unsafe entry")
        if re.fullmatch(rf"[0-9a-f]{{{expected_object_length}}}", object_id) is None:
            raise ValueError("release candidate Git blob identity is malformed")
        try:
            normalized = normalize_relative_path(relative)
        except ValueError as exc:
            raise ValueError("release candidate Git inventory contains an unsafe path") from exc
        collision_key = unicodedata.normalize("NFC", relative).casefold()
        if (
            not relative
            or relative.startswith("-")
            or normalized != relative
            or unicodedata.normalize("NFC", relative) != relative
            or is_sensitive_workspace_path(relative)
            or collision_key in collision_keys
        ):
            raise ValueError("release candidate Git inventory contains an unsafe path")
        collision_keys.add(collision_key)
        tracked_mode: Literal["100644", "100755"] = "100644" if mode == "100644" else "100755"
        entries.append(
            _TrackedEntry(
                path=relative,
                mode=tracked_mode,
                object_id=object_id,
            )
        )
    paths = tuple(entry.path for entry in entries)
    if paths != tuple(sorted(set(paths))):
        raise ValueError("release candidate Git inventory is not canonical")
    return tuple(entries)


def _observe_tracked_files(
    root: Path,
    entries: tuple[_TrackedEntry, ...],
    *,
    git_object_format: str,
) -> tuple[tuple[_TrackedFileObservation, ...], int]:
    observed: list[_TrackedFileObservation] = []
    total_bytes = 0
    for entry in entries:
        candidate, before = _require_unshared_tracked_file(root, entry.path)
        total_bytes += before.st_size
        if total_bytes > _MAX_TRACKED_BYTES:
            raise ValueError("release candidate tracked files exceed their byte limit")
        content_sha256, object_id, finished = _hash_tracked_file(
            candidate,
            before=before,
            git_object_format=git_object_format,
        )
        observed_mode = "100755" if finished.st_mode & stat.S_IXUSR else "100644"
        if object_id != entry.object_id or observed_mode != entry.mode:
            raise ValueError("release candidate bytes or mode differ from the committed Git blob")
        observed.append(
            _TrackedFileObservation(
                record={
                    "path": entry.path,
                    "mode": entry.mode,
                    "git_blob_object": entry.object_id,
                    "sha256": content_sha256,
                    "size": finished.st_size,
                },
                identity=_stat_identity(finished),
            )
        )
    return tuple(observed), total_bytes


def _require_unshared_tracked_file(root: Path, relative: str) -> tuple[Path, os.stat_result]:
    current = root
    parts = tuple(relative.split("/"))
    try:
        for index, part in enumerate(parts):
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError("release candidate tracked path may not traverse a link")
            if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("release candidate tracked path parent is not a directory")
        metadata = current.lstat()
    except OSError as exc:
        raise ValueError("release candidate tracked file is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > _MAX_TRACKED_BYTES
    ):
        raise ValueError("release candidate tracked file must be bounded and unshared")
    return current, metadata


def _hash_tracked_file(
    path: Path,
    *,
    before: os.stat_result,
    git_object_format: str,
) -> tuple[str, str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("release candidate tracked file could not be opened safely") from exc
    content_digest = hashlib.sha256()
    git_digest = hashlib.new(git_object_format)
    git_digest.update(f"blob {before.st_size}\0".encode("ascii"))
    observed_bytes = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise ValueError("release candidate tracked file changed before hashing")
        while observed_bytes <= before.st_size:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, before.st_size + 1 - observed_bytes),
            )
            if not chunk:
                break
            observed_bytes += len(chunk)
            content_digest.update(chunk)
            git_digest.update(chunk)
        finished = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError("release candidate tracked file could not be hashed safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("release candidate tracked file changed while being hashed") from exc
    identities = {
        _stat_identity(before),
        _stat_identity(opened),
        _stat_identity(finished),
        _stat_identity(after),
    }
    if len(identities) != 1 or observed_bytes != before.st_size or finished.st_nlink != 1:
        raise ValueError("release candidate tracked file changed while being hashed")
    return content_digest.hexdigest(), git_digest.hexdigest(), finished


def _snapshot_tracked_identities(
    root: Path,
    entries: tuple[_TrackedEntry, ...],
) -> tuple[tuple[int, int, int, int, int, int, int], ...]:
    return tuple(
        _stat_identity(_require_unshared_tracked_file(root, entry.path)[1]) for entry in entries
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
