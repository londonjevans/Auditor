"""Stable lexical custody for trusted directory roots."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

DirectoryComponentIdentity = tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class DirectoryCustodyObservation:
    """Opaque identity of one lexical directory root and all of its ancestors."""

    path: Path
    component_identities: tuple[tuple[Path, DirectoryComponentIdentity], ...]


def prepare_owned_empty_directory(
    path: Path,
    *,
    label: str,
    precreated: DirectoryCustodyObservation | None = None,
) -> DirectoryCustodyObservation:
    """Create a private output or claim an exact empty directory already owned by its parent."""

    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be absolute and normalized")
    if precreated is not None:
        if (
            type(precreated) is not DirectoryCustodyObservation
            or precreated.path != path
            or tuple(p for p, _identity in precreated.component_identities)
            != (*reversed(path.parents), path)
        ):
            raise ValueError(f"{label} precreated directory selection differs")
        require_same_unlinked_directory_objects(precreated, label=label)
        if stat.S_IMODE(path.stat().st_mode) != 0o700 or any(path.iterdir()):
            raise ValueError(f"{label} precreated directory must be private and empty")
        require_same_unlinked_directory_objects(precreated, label=label)
        return precreated
    parent = observe_unlinked_directory(path.parent, label=label)
    path.mkdir(mode=0o700)
    require_same_unlinked_directory_objects(parent, label=label)
    return observe_unlinked_directory(path, label=label)


def observe_unlinked_directory(
    path: Path,
    *,
    label: str,
    allow_entry_metadata_change: bool = False,
) -> DirectoryCustodyObservation:
    """Observe exact ancestors; opt-in entry churn never permits object or mode changes."""

    if type(allow_entry_metadata_change) is not bool:
        raise ValueError(f"{label} directory metadata policy must be boolean")
    absolute = Path(os.path.abspath(path))
    observed = _observe_components(absolute, label=label)
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} root is unavailable") from exc
    if resolved != absolute:
        raise ValueError(f"{label} root may not traverse a link")
    if allow_entry_metadata_change:
        _require_same_component_objects(observed, label=label)
    else:
        _require_components(observed, label=label, phase="while being resolved")
    return DirectoryCustodyObservation(path=absolute, component_identities=observed)


def require_unchanged_unlinked_directory(
    expected: DirectoryCustodyObservation,
    *,
    label: str,
    allow_root_metadata_change: bool = False,
) -> None:
    """Require exact continuity with an earlier lexical-directory observation."""

    _require_components(
        expected.component_identities,
        label=label,
        phase="during custody",
        allow_root_metadata_change=allow_root_metadata_change,
    )
    try:
        resolved = expected.path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} root changed during custody") from exc
    if resolved != expected.path:
        raise ValueError(f"{label} root changed during custody")
    _require_components(
        expected.component_identities,
        label=label,
        phase="during custody",
        allow_root_metadata_change=allow_root_metadata_change,
    )


def require_same_unlinked_directory_objects(
    expected: DirectoryCustodyObservation,
    *,
    label: str,
) -> None:
    """Require the same path-component objects when caller-owned metadata may change."""

    _require_same_component_objects(expected.component_identities, label=label)
    try:
        resolved = expected.path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} root changed during custody") from exc
    if resolved != expected.path:
        raise ValueError(f"{label} root changed during custody")
    _require_same_component_objects(expected.component_identities, label=label)


def reobserve_same_unlinked_directory(
    expected: DirectoryCustodyObservation,
    *,
    label: str,
    allowed_metadata_change_paths: frozenset[Path] = frozenset(),
) -> DirectoryCustodyObservation:
    """Rebaseline exact metadata without adopting different path-component objects."""

    expected_paths = {path for path, _identity in expected.component_identities}
    if not allowed_metadata_change_paths <= expected_paths:
        raise ValueError(f"{label} metadata-change allowance is outside its custody path")
    observed = observe_unlinked_directory(expected.path, label=label)
    if len(observed.component_identities) != len(expected.component_identities):
        raise ValueError(f"{label} root changed during metadata rebaseline")
    for (expected_path, expected_identity), (observed_path, observed_identity) in zip(
        expected.component_identities,
        observed.component_identities,
        strict=True,
    ):
        metadata_change_allowed = expected_path in allowed_metadata_change_paths
        same_identity = (
            observed_identity[:3] == expected_identity[:3]
            if metadata_change_allowed
            else observed_identity == expected_identity
        )
        if observed_path != expected_path or not same_identity:
            raise ValueError(f"{label} root changed during metadata rebaseline")
    require_unchanged_unlinked_directory(observed, label=label)
    return observed


def _observe_components(
    absolute: Path,
    *,
    label: str,
) -> tuple[tuple[Path, DirectoryComponentIdentity], ...]:
    current = Path(absolute.anchor)
    observed: list[tuple[Path, DirectoryComponentIdentity]] = []
    try:
        anchor_metadata = current.lstat()
        if (
            stat.S_ISLNK(anchor_metadata.st_mode)
            or current.is_junction()
            or not stat.S_ISDIR(anchor_metadata.st_mode)
        ):
            raise ValueError(f"{label} root may not traverse a link")
        observed.append((current, _component_identity(anchor_metadata)))
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or current.is_junction()
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise ValueError(f"{label} root may not traverse a link")
            observed.append((current, _component_identity(metadata)))
    except OSError as exc:
        raise ValueError(f"{label} root is unavailable") from exc
    return tuple(observed)


def _require_components(
    expected: tuple[tuple[Path, DirectoryComponentIdentity], ...],
    *,
    label: str,
    phase: str,
    allow_root_metadata_change: bool = False,
) -> None:
    try:
        for index, (component, expected_identity) in enumerate(expected):
            metadata = component.lstat()
            observed_identity = _component_identity(metadata)
            root_metadata_only_change = (
                allow_root_metadata_change
                and index == len(expected) - 1
                and observed_identity[:3] == expected_identity[:3]
            )
            if (
                stat.S_ISLNK(metadata.st_mode)
                or component.is_junction()
                or not stat.S_ISDIR(metadata.st_mode)
                or (observed_identity != expected_identity and not root_metadata_only_change)
            ):
                raise ValueError(f"{label} root changed {phase}")
    except OSError as exc:
        raise ValueError(f"{label} root changed {phase}") from exc


def _require_same_component_objects(
    expected: tuple[tuple[Path, DirectoryComponentIdentity], ...],
    *,
    label: str,
) -> None:
    try:
        for component, expected_identity in expected:
            metadata = component.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or component.is_junction()
                or not stat.S_ISDIR(metadata.st_mode)
                or _component_identity(metadata)[:3] != expected_identity[:3]
            ):
                raise ValueError(f"{label} root changed during custody")
    except OSError as exc:
        raise ValueError(f"{label} root changed during custody") from exc


def _component_identity(metadata: os.stat_result) -> DirectoryComponentIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_ctime_ns,
    )
