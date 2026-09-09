"""Exact lexical custody for immutable release-evidence files."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    FileEvidenceObservation,
    read_composed_file_evidence,
    read_file_evidence,
)
from mmaudit.repository.directory_custody import (
    DirectoryCustodyObservation,
    observe_unlinked_directory,
    require_same_unlinked_directory_objects,
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
    allow_directory_entry_metadata_change: bool = False,
    allow_composed_evidence: bool = False,
) -> RegularFileCustodyObservation:
    """Keep full file metadata and bytes; explicit directory-entry churn keeps all objects/modes."""

    if type(allow_directory_entry_metadata_change) is not bool:
        raise ValueError(f"{label} directory metadata policy must be boolean")
    if type(allow_composed_evidence) is not bool:
        raise ValueError(f"{label} composed evidence policy must be boolean")
    absolute_root = Path(os.path.abspath(root))

    def read(selected_path: str | Path) -> FileEvidenceObservation:
        if allow_composed_evidence:
            if expected_binding is None:
                raise ValueError(f"{label} composed custody requires an exact binding")
            return read_composed_file_evidence(
                evidence_root=absolute_root,
                relative_path=selected_path,
                expected_binding=expected_binding,
                max_bytes=max_bytes,
            )
        return read_file_evidence(
            evidence_root=absolute_root,
            relative_path=selected_path,
            max_bytes=max_bytes,
        )

    first = read(relative_path)
    if expected_binding is not None and first.binding != expected_binding:
        raise ValueError(f"{label} differs from its expected binding")

    relative = PurePosixPath(first.binding.path)
    parent_path = absolute_root.joinpath(*relative.parent.parts)
    parent = observe_unlinked_directory(
        parent_path,
        label=f"{label} parent",
        allow_entry_metadata_change=allow_directory_entry_metadata_change,
    )
    leaf = parent.path / relative.name
    before = _observe_regular_file_identity(leaf, label=label)
    second = read(first.binding.path)
    after = _observe_regular_file_identity(leaf, label=label)
    if allow_directory_entry_metadata_change:
        require_same_unlinked_directory_objects(parent, label=f"{label} parent")
    else:
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
    allow_directory_entry_metadata_change: bool = False,
    allow_composed_evidence: bool = False,
) -> None:
    """Keep strict defaults; explicit entry churn never permits changed files or ancestor objects."""

    if type(allow_directory_entry_metadata_change) is not bool:
        raise ValueError(f"{label} directory metadata policy must be boolean")
    if type(allow_composed_evidence) is not bool:
        raise ValueError(f"{label} composed evidence policy must be boolean")
    try:
        if allow_directory_entry_metadata_change:
            require_same_unlinked_directory_objects(expected.parent, label=f"{label} parent")
        current = observe_regular_file_custody(
            root=expected.root,
            relative_path=expected.binding.path,
            label=label,
            expected_binding=expected.binding,
            max_bytes=max_bytes,
            allow_directory_entry_metadata_change=allow_directory_entry_metadata_change,
            allow_composed_evidence=allow_composed_evidence,
        )
        if allow_directory_entry_metadata_change:
            require_same_unlinked_directory_objects(expected.parent, label=f"{label} parent")
    except ValueError as exc:
        raise ValueError(f"{label} changed during custody") from exc
    same_file = (current.root, current.binding, current.identity) == (
        expected.root,
        expected.binding,
        expected.identity,
    )
    if not same_file or (not allow_directory_entry_metadata_change and current != expected):
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
