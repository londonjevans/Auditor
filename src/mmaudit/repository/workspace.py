"""Shared validation for bounded copies of untrusted repository trees."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path

from mmaudit.repository.ignore import normalize_relative_path

DEFAULT_MAX_WORKSPACE_ENTRIES = 100_000
DEFAULT_MAX_WORKSPACE_FILES = 100_000
DEFAULT_MAX_WORKSPACE_FILE_BYTES = 100_000_000
DEFAULT_MAX_WORKSPACE_BYTES = 2 * 1024**3


def validate_copyable_workspace(
    source: Path,
    *,
    excluded: Callable[[Path], bool],
    max_entries: int = DEFAULT_MAX_WORKSPACE_ENTRIES,
    max_files: int = DEFAULT_MAX_WORKSPACE_FILES,
    max_file_bytes: int = DEFAULT_MAX_WORKSPACE_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_WORKSPACE_BYTES,
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
