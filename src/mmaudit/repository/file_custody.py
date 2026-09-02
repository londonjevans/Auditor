"""Exact lexical custody for immutable release-evidence files."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import DEFAULT_MAX_EVIDENCE_BYTES, read_file_evidence
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    require_unchanged_unlinked_directory,
)

type RegularFileIdentity = tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class RegularFileCustodyObservation:
    """Exact content, inode, and lexical-parent authority for one regular file."""

    root: Path
    binding: ManifestFileBinding
    identity: RegularFileIdentity
    parent: DirectoryCustodyObservation


def observe_regular_file_custody(
    *,
    root: Path,
    relative_path: str | Path,
    label: str,
    expected_binding: ManifestFileBinding | None = None,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> RegularFileCustodyObservation:
    """Observe stable bytes and their exact unlinked path authority."""

    absolute_root = Path(os.path.abspath(root))
    first = read_file_evidence(
        evidence_root=absolute_root,
        relative_path=relative_path,
        max_bytes=max_bytes,
    )
    if expected_binding is not None and first.binding != expected_binding:
        raise ValueError(f"{label} differs from its expected binding")

    relative = PurePosixPath(first.binding.path)
    parent_path = absolute_root.joinpath(*relative.parent.parts)
    parent = observe_unlinked_directory(parent_path, label=f"{label} parent")
    leaf = parent.path / relative.name
    before = _observe_regular_file_identity(leaf, label=label)
    second = read_file_evidence(
        evidence_root=absolute_root,
        relative_path=first.binding.path,
        max_bytes=max_bytes,
    )
    after = _observe_regular_file_identity(leaf, label=label)
    require_unchanged_unlinked_directory(parent, label=f"{label} parent")
    if first != second or before != after:
        raise ValueError(f"{label} changed while its custody was established")
    return RegularFileCustodyObservation(
        root=absolute_root,
        binding=second.binding,
        identity=after,
        parent=parent,
    )


def require_regular_file_custody_unchanged(
    expected: RegularFileCustodyObservation,
    *,
    label: str,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> None:
    """Require the same bytes, inode metadata, parent, and ancestor lineage."""

    try:
        current = observe_regular_file_custody(
            root=expected.root,
            relative_path=expected.binding.path,
            label=label,
            expected_binding=expected.binding,
            max_bytes=max_bytes,
        )
    except ValueError as exc:
        raise ValueError(f"{label} changed during custody") from exc
    if current != expected:
        raise ValueError(f"{label} changed during custody")


def _observe_regular_file_identity(path: Path, *, label: str) -> RegularFileIdentity:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or path.is_junction()
        or metadata.st_nlink != 1
    ):
        raise ValueError(f"{label} must be an unshared regular file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
