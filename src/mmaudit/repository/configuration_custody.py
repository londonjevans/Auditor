"""Stable custody for trusted repository-configuration inputs."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from mmaudit.repository.directory_custody import (
    DirectoryComponentIdentity,
    observe_unlinked_directory,
    require_unchanged_unlinked_directory,
)
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path

_MAX_CONFIGURATION_INPUT_BYTES = 100_000_000
_READ_CHUNK_BYTES = 1024 * 1024
_StatIdentity = tuple[int, int, int, int, int, int, int]
_RootComponentIdentity = DirectoryComponentIdentity


@dataclass(frozen=True, slots=True)
class ConfigurationInputObservation:
    """Stable identity and bytes for one exact configuration-owned ignore input."""

    root: Path
    root_identity: _StatIdentity
    root_component_identities: tuple[tuple[Path, _RootComponentIdentity], ...]
    configured_ignore_path: str
    ignore_file_kind: Literal["absent", "directory", "regular"]
    directory_identities: tuple[tuple[str, _StatIdentity], ...]
    missing_path: str | None
    ignore_file_identity: _StatIdentity | None
    ignore_file_sha256: str | None
    ignore_file_size: int | None


def observe_configuration_input(
    *,
    configuration_root: Path,
    configured_ignore_path: str,
) -> ConfigurationInputObservation:
    """Observe the trusted root and exact ignore input without following links."""

    root_observation = observe_unlinked_directory(
        configuration_root,
        label="configuration",
    )
    root = root_observation.path
    root_component_identities = root_observation.component_identities
    relative = normalize_relative_path(configured_ignore_path)
    if is_sensitive_workspace_path(relative):
        raise ValueError("configuration ignore file may not use a sensitive path")
    parts = PurePosixPath(relative).parts
    directories: list[tuple[Path, str, _StatIdentity]] = [(root, ".", _stat_identity(root.lstat()))]
    current = root
    missing_path: str | None = None

    for index, part in enumerate(parts[:-1]):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            missing_path = PurePosixPath(*parts[: index + 1]).as_posix()
            break
        except OSError as exc:
            raise ValueError("configuration ignore parent is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
            raise ValueError("configuration ignore path may not traverse a link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("configuration ignore parent must be a directory")
        directories.append(
            (
                current,
                PurePosixPath(*parts[: index + 1]).as_posix(),
                _stat_identity(metadata),
            )
        )

    ignore_file_kind: Literal["absent", "directory", "regular"] = "absent"
    file_identity: _StatIdentity | None = None
    file_sha256: str | None = None
    file_size: int | None = None
    leaf = root if not parts else root.joinpath(*parts)
    if missing_path is None:
        try:
            leaf_before = leaf.lstat()
        except FileNotFoundError:
            missing_path = relative
        except OSError as exc:
            raise ValueError("configuration ignore input is unavailable") from exc
        else:
            if stat.S_ISLNK(leaf_before.st_mode) or leaf.is_junction():
                raise ValueError("configuration ignore path may not traverse a link")
            if stat.S_ISDIR(leaf_before.st_mode):
                ignore_file_kind = "directory"
                if leaf != root:
                    directories.append((leaf, relative, _stat_identity(leaf_before)))
            elif stat.S_ISREG(leaf_before.st_mode):
                if (
                    leaf_before.st_nlink != 1
                    or leaf_before.st_size > _MAX_CONFIGURATION_INPUT_BYTES
                ):
                    raise ValueError("configuration ignore input must be bounded and unshared")
                ignore_file_kind = "regular"
                file_sha256, finished = _hash_configuration_input(
                    leaf,
                    before=leaf_before,
                )
                file_identity = _stat_identity(finished)
                file_size = finished.st_size
            else:
                raise ValueError("configuration ignore input must be a regular file")

    observed_directories = tuple((label, identity) for _path, label, identity in directories)
    for path, _label, expected_identity in directories:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ValueError("configuration path changed while being observed") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or path.is_junction()
            or not stat.S_ISDIR(metadata.st_mode)
            or _stat_identity(metadata) != expected_identity
        ):
            raise ValueError("configuration path changed while being observed")
    require_unchanged_unlinked_directory(root_observation, label="configuration")
    if missing_path is not None:
        missing_candidate = root.joinpath(*PurePosixPath(missing_path).parts)
        try:
            missing_candidate.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ValueError("configuration ignore input is unavailable") from exc
        else:
            raise ValueError("configuration ignore input changed while being observed")

    return ConfigurationInputObservation(
        root=root,
        root_identity=observed_directories[0][1],
        root_component_identities=root_component_identities,
        configured_ignore_path=relative,
        ignore_file_kind=ignore_file_kind,
        directory_identities=observed_directories,
        missing_path=missing_path,
        ignore_file_identity=file_identity,
        ignore_file_sha256=file_sha256,
        ignore_file_size=file_size,
    )


def require_unchanged_configuration_input(
    expected: ConfigurationInputObservation,
    *,
    configured_ignore_path: str,
) -> None:
    """Reject root, path, identity, or byte changes since an earlier observation."""

    observed = observe_configuration_input(
        configuration_root=expected.root,
        configured_ignore_path=configured_ignore_path,
    )
    if observed.root != expected.root or observed.root_identity[:4] != expected.root_identity[:4]:
        raise ValueError("configuration root changed while discovery was running")
    if _ignore_input_state(observed) != _ignore_input_state(expected):
        raise ValueError("configuration ignore input changed while discovery was running")
    if observed.root_component_identities != expected.root_component_identities:
        raise ValueError("configuration root changed while discovery was running")


def _hash_configuration_input(
    path: Path,
    *,
    before: os.stat_result,
) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("configuration ignore input could not be opened safely") from exc
    digest = hashlib.sha256()
    observed_bytes = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise ValueError("configuration ignore input changed before hashing")
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
        raise ValueError("configuration ignore input could not be hashed safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("configuration ignore input changed while being hashed") from exc
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
        raise ValueError("configuration ignore input changed while being hashed")
    return digest.hexdigest(), finished


def _ignore_input_state(observation: ConfigurationInputObservation) -> tuple[object, ...]:
    return (
        observation.root_identity,
        observation.configured_ignore_path,
        observation.ignore_file_kind,
        observation.directory_identities,
        observation.missing_path,
        observation.ignore_file_identity,
        observation.ignore_file_sha256,
        observation.ignore_file_size,
    )


def _stat_identity(metadata: os.stat_result) -> _StatIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
