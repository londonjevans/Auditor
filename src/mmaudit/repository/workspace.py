"""Shared validation for bounded copies of untrusted repository trees."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path

DEFAULT_MAX_WORKSPACE_ENTRIES = 100_000
DEFAULT_MAX_WORKSPACE_FILES = 100_000
DEFAULT_MAX_WORKSPACE_FILE_BYTES = 100_000_000
DEFAULT_MAX_WORKSPACE_BYTES = 2 * 1024**3
DEFAULT_MAX_WORKSPACE_DEPTH = 128
AUDITED_WORKSPACE_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mmaudit",
        ".next",
        ".venv",
        "__pycache__",
        "artifacts",
        "broadcast",
        "build",
        "cache",
        "coverage",
        "dist",
        "node_modules",
        "out",
        "target",
        "vendor",
        "venv",
    }
)


@dataclass(frozen=True, slots=True)
class AuditedWorkspaceExclusionDomain:
    """Versioned policy identity shared by scanner and mutation tree hashes."""

    schema_version: str
    excluded_directories: tuple[str, ...]
    sensitive_path_policy: str

    def as_dict(self) -> dict[str, str | list[str]]:
        """Return a canonical JSON-compatible policy binding."""

        return {
            "schema_version": self.schema_version,
            "excluded_directories": list(self.excluded_directories),
            "sensitive_path_policy": self.sensitive_path_policy,
        }


AUDITED_WORKSPACE_EXCLUSION_DOMAIN = AuditedWorkspaceExclusionDomain(
    schema_version="1.0",
    excluded_directories=tuple(sorted(AUDITED_WORKSPACE_EXCLUDED_DIRECTORIES)),
    sensitive_path_policy="mmaudit-sensitive-workspace-path-v1",
)


def audited_workspace_relative_excluded(
    relative: str | Path | PurePosixPath,
    *,
    is_dir: bool,
) -> bool:
    """Apply the shared scanner and mutation audited-tree exclusion policy."""

    normalized = normalize_relative_path(str(relative))
    parts = PurePosixPath(normalized).parts
    return any(
        part.lower() in AUDITED_WORKSPACE_EXCLUDED_DIRECTORIES for part in parts
    ) or is_sensitive_workspace_path(normalized, is_dir=is_dir)


def audited_workspace_exclusion_root(
    relative: str | Path | PurePosixPath,
) -> str | None:
    """Return the first shared exclusion ancestor, never a caller-defined omission."""

    normalized = normalize_relative_path(str(relative))
    parts = PurePosixPath(normalized).parts
    for length in range(1, len(parts) + 1):
        prefix = PurePosixPath(*parts[:length]).as_posix()
        if audited_workspace_relative_excluded(prefix, is_dir=True):
            return prefix
    return None


def audited_workspace_bindings_sha256(
    bindings: Sequence[Mapping[str, str | int]],
) -> str:
    """Hash audited file bindings using one Unicode-preserving canonical encoding."""

    ordered_bindings = sorted(
        (dict(binding) for binding in bindings),
        key=lambda binding: (
            str(binding.get("path", "")),
            json.dumps(
                binding,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
        ),
    )
    encoded = json.dumps(
        {
            "exclusion_domain": AUDITED_WORKSPACE_EXCLUSION_DOMAIN.as_dict(),
            "files": ordered_bindings,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def require_audited_workspace_paths_included(
    relative_paths: Sequence[str | Path | PurePosixPath],
) -> None:
    """Fail when an explicitly audited file would be absent from execution copies."""

    for relative in relative_paths:
        normalized = normalize_relative_path(str(relative))
        if normalized in {"", "."}:
            raise ValueError("explicit audited workspace path must identify a file")
        if audited_workspace_relative_excluded(normalized, is_dir=False):
            raise ValueError(
                f"explicit audited source path is excluded from execution workspaces: {normalized}"
            )


def validate_copyable_workspace(
    source: Path,
    *,
    excluded: Callable[[Path], bool],
    max_entries: int = DEFAULT_MAX_WORKSPACE_ENTRIES,
    max_files: int = DEFAULT_MAX_WORKSPACE_FILES,
    max_file_bytes: int = DEFAULT_MAX_WORKSPACE_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_WORKSPACE_BYTES,
    max_depth: int = DEFAULT_MAX_WORKSPACE_DEPTH,
) -> None:
    """Reject links, crafted paths, special files, hardlinks, and oversized trees."""

    root = source.resolve(strict=True)
    if not root.is_dir() or root.is_symlink() or root.is_junction():
        raise ValueError("workspace source must be a regular directory")
    entries = 0
    files = 0
    total_bytes = 0
    for directory, directory_names, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current = Path(directory)
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current / name
            if excluded(candidate):
                continue
            _validate_workspace_relative(root, candidate)
            if len(candidate.relative_to(root).parts) > max_depth:
                raise ValueError("workspace source directory depth limit exceeded")
            entries += 1
            if entries > max_entries:
                raise ValueError("workspace source entry limit exceeded")
            if candidate.is_symlink() or candidate.is_junction():
                raise ValueError("workspace source may not contain symlinks or junctions")
            retained_directories.append(name)
        directory_names[:] = retained_directories

        for name in sorted(filenames):
            candidate = current / name
            if excluded(candidate):
                continue
            _validate_workspace_relative(root, candidate)
            entries += 1
            files += 1
            if entries > max_entries or files > max_files:
                raise ValueError("workspace source file-count limit exceeded")
            if candidate.is_symlink() or candidate.is_junction():
                raise ValueError("workspace source may not contain symlinks or junctions")
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("workspace source must contain unique regular files only")
            if metadata.st_size > max_file_bytes:
                raise ValueError("workspace source file exceeds the byte limit")
            total_bytes += metadata.st_size
            if total_bytes > max_total_bytes:
                raise ValueError("workspace source total byte limit exceeded")


def _validate_workspace_relative(root: Path, candidate: Path) -> None:
    try:
        normalize_relative_path(candidate.relative_to(root))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("workspace source contains an unsupported repository path") from exc
