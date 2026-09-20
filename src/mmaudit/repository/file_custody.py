"""Exact lexical custody for immutable release-evidence files."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mmaudit import release_io
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

MAX_REGULAR_FILE_CUSTODY_BATCH_FILES = 8192


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


def require_regular_file_custody_batch_unchanged(
    expected: list[RegularFileCustodyObservation],
    *,
    label: str,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> None:
    """Recheck a bounded same-root batch with caller-owned directory-entry churn.

    Every file is reopened and fully read four times. Each read is bracketed by
    live lexical ancestor and held-root checks; file metadata remains exact.
    Only the root, one current parent descriptor and detached expected values are
    shared, never an I/O verdict. Single-file strict defaults are unchanged.
    """

    bound = release_io._validate_max_bytes(max_bytes)
    snapshots = _batch_custody_snapshots(expected, max_bytes=bound, label=label)
    if not snapshots:
        return
    if not release_io._NONBLOCK_FLAG:
        raise ValueError(f"{label} nonblocking descriptor traversal is unavailable")
    root = release_io._open_root(snapshots[0].root)
    parent_descriptor: int | None = None
    parent_path: Path | None = None
    try:
        for selected in snapshots:
            require_same_unlinked_directory_objects(selected.parent, label=f"{label} parent")
            if parent_path != selected.parent.path:
                if parent_descriptor is not None:
                    os.close(parent_descriptor)
                    parent_descriptor = None
                parent_descriptor, _ = release_io._open_parent(root, selected.binding.path)
                parent_path = selected.parent.path
            assert parent_descriptor is not None
            leaf = selected.binding.path.rsplit("/", 1)[-1]
            first: bytes | None = None
            for _ in range(4):
                _require_batch_ancestry(selected, root, parent_descriptor, label=label)
                observed = release_io._read_file_at_parent(
                    parent_descriptor=parent_descriptor, leaf=leaf, max_bytes=bound
                )
                _require_batch_ancestry(selected, root, parent_descriptor, label=label)
                if (
                    observed.identity != selected.identity
                    or len(observed.content) != selected.binding.size
                ):
                    raise ValueError(f"{label} changed during batch custody")
                if first is None:
                    if hashlib.sha256(observed.content).hexdigest() != selected.binding.sha256:
                        raise ValueError(f"{label} bytes changed during batch custody")
                    first = observed.content
                elif observed.content != first:
                    raise ValueError(f"{label} bytes changed between batch reads")
            require_same_unlinked_directory_objects(selected.parent, label=f"{label} parent")
        if _batch_custody_snapshots(expected, max_bytes=bound, label=label) != snapshots:
            raise ValueError(f"{label} expected batch changed during custody")
    except OSError as exc:
        raise ValueError(f"{label} became unavailable during batch custody") from exc
    finally:
        try:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
        finally:
            os.close(root.descriptor)


def _batch_custody_snapshots(
    expected: list[RegularFileCustodyObservation], *, max_bytes: int, label: str
) -> tuple[RegularFileCustodyObservation, ...]:
    """Detach bounded expected values; no serialized object grants directory authority."""

    if type(expected) is not list or len(expected) > MAX_REGULAR_FILE_CUSTODY_BATCH_FILES:
        raise ValueError(f"{label} file batch exceeds its count bound")
    snapshots: list[RegularFileCustodyObservation] = []
    seen: set[str] = set()
    for selected in expected:
        if type(selected) is not RegularFileCustodyObservation:
            raise ValueError(f"{label} requires exact regular-file custody")
        if type(selected.binding) is not ManifestFileBinding:
            raise ValueError(f"{label} requires an exact file binding")
        binding = ManifestFileBinding.model_validate_json(
            selected.binding.model_dump_json(), strict=True
        )
        relative = PurePosixPath(release_io._normalize_evidence_path(binding.path))
        if (
            not isinstance(selected.root, Path)
            or not selected.root.is_absolute()
            or ".." in selected.root.parts
            or (snapshots and selected.root != snapshots[0].root)
            or binding.size > max_bytes
            or binding.path in seen
        ):
            raise ValueError(f"{label} batch requires one exact root and distinct bounded files")
        seen.add(binding.path)
        identity = selected.identity
        if (
            type(identity) is not tuple
            or len(identity) != 7
            or any(type(value) is not int for value in identity)
            or not stat.S_ISREG(identity[2])
            or identity[3] != 1
            or identity[4] != binding.size
        ):
            raise ValueError(f"{label} requires an exact unshared file identity")
        parent_path = selected.root.joinpath(*relative.parent.parts)
        parent = selected.parent
        if (
            type(parent) is not DirectoryCustodyObservation
            or parent.path != parent_path
            or type(parent.component_identities) is not tuple
            or tuple(path for path, _ in parent.component_identities)
            != (*reversed(parent_path.parents), parent_path)
            or any(
                type(component) is not tuple
                or len(component) != 5
                or any(type(value) is not int for value in component)
                or not stat.S_ISDIR(component[2])
                for _, component in parent.component_identities
            )
        ):
            raise ValueError(f"{label} parent ancestry differs from its selected file")
        snapshots.append(
            RegularFileCustodyObservation(
                selected.root,
                binding,
                identity,
                DirectoryCustodyObservation(parent.path, parent.component_identities),
            )
        )
    return tuple(snapshots)


def _require_batch_ancestry(
    selected: RegularFileCustodyObservation,
    root: release_io._RootHandle,
    parent_descriptor: int,
    *,
    label: str,
) -> None:
    """Rejoin each original lexical component and the held descriptor around every read."""

    for path, identity in selected.parent.component_identities:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or release_io._is_link_or_reparse(metadata)
            or path.is_junction()
            or release_io._directory_identity(metadata) != identity[:3]
        ):
            raise ValueError(f"{label} ancestor changed during batch custody")
        if path == selected.root and (
            root.path != path
            or root.identity != identity[:3]
            or release_io._directory_identity(os.fstat(root.descriptor)) != identity[:3]
        ):
            raise ValueError(f"{label} held root changed during batch custody")
    leaf = selected.root / selected.binding.path
    if _observe_regular_file_identity(leaf, label=label) != selected.identity:
        raise ValueError(f"{label} file changed during batch custody")
    if (
        release_io._directory_identity(os.fstat(parent_descriptor))
        != selected.parent.component_identities[-1][1][:3]
    ):
        raise ValueError(f"{label} held parent changed during batch custody")
