"""Strict, descriptor-safe JSON evidence I/O for release artifacts."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
import unicodedata
from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from pydantic import BaseModel

from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path

type JsonScalar = bool | int | float | str | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonWritable = BaseModel | dict[str, Any] | list[Any]

DEFAULT_MAX_EVIDENCE_BYTES = 100_000_000
MAX_COMPOSED_EVIDENCE_BYTES = 256_000_000
MAX_STREAMED_EVIDENCE_BYTES = 4 * 1024**3
MAX_STREAMED_EVIDENCE_SECONDS = 600.0
_READ_CHUNK_BYTES = 1024 * 1024
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK_FLAG = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY_FLAG = getattr(os, "O_DIRECTORY", 0)
_DESCRIPTOR_TRAVERSAL_SUPPORTED = (
    _NOFOLLOW_FLAG != 0
    and _DIRECTORY_FLAG != 0
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
)


@dataclass(frozen=True, slots=True)
class JsonEvidenceObservation:
    """Exact safely read JSON bytes, parsed value, and file binding."""

    value: JsonValue
    content: bytes
    binding: ManifestFileBinding


@dataclass(frozen=True, slots=True)
class FileEvidenceObservation:
    """Exact safely read bytes and their immutable file binding."""

    content: bytes
    binding: ManifestFileBinding


@dataclass(frozen=True, slots=True)
class _RootHandle:
    path: Path
    descriptor: int
    identity: tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class _FileObservation:
    content: bytes
    identity: tuple[int, int, int, int, int, int, int]


@contextmanager
def stream_file_evidence(
    *,
    evidence_root: Path,
    expected_binding: ManifestFileBinding,
    absolute_deadline: float,
) -> Iterator[Iterator[bytes]]:
    """Authenticate then stream one bounded file while retaining its descriptors.

    Consumer code is trusted host code, not a serialized command or admission.
    It must exhaust the iterator and wait for successful context exit before
    accepting results. No file is written. Both passes enforce exact bytes and
    a shared deadline; synchronous OS calls cannot be forcibly preempted here.
    The iterator is closed on every exit and cannot read a reused descriptor.
    """

    if type(expected_binding) is not ManifestFileBinding:
        raise ValueError("streamed evidence requires the exact file-binding type")
    expected = ManifestFileBinding.model_validate_json(
        expected_binding.model_dump_json(), strict=True
    )
    relative = _normalize_evidence_path(expected.path)
    if relative != expected.path or expected.size > MAX_STREAMED_EVIDENCE_BYTES:
        raise ValueError("streamed evidence binding is outside its supported bound")
    if (
        type(absolute_deadline) not in {int, float}
        or not math.isfinite(absolute_deadline)
        or not 0 < absolute_deadline - time.monotonic() <= MAX_STREAMED_EVIDENCE_SECONDS
        or not _NONBLOCK_FLAG
    ):
        raise ValueError("streamed evidence requires a finite bounded deadline and safe input")

    root: _RootHandle | None = None
    parent: int | None = None
    descriptor: int | None = None
    chunks: Generator[bytes, None, None] | None = None
    primary: BaseException | None = None
    consumer_active = False
    try:
        root = _open_root(evidence_root)
        parent, leaf = _open_parent(root, relative)
        parent_identity = _directory_identity(os.fstat(parent))
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_link_or_reparse(before)
            or before.st_nlink != 1
            or before.st_size != expected.size
        ):
            raise ValueError("streamed evidence must be the exact unshared regular file")
        descriptor = os.open(
            leaf,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG | _NONBLOCK_FLAG,
            dir_fd=parent,
        )
        identity = _stat_identity(before)
        if _stat_identity(os.fstat(descriptor)) != identity:
            raise ValueError("streamed evidence changed before reading")
        for _ in _bound_evidence_chunks(descriptor, expected, absolute_deadline):
            pass
        _require_stream_custody(root, parent, descriptor, relative, identity, parent_identity)
        os.lseek(descriptor, 0, os.SEEK_SET)
        complete = False

        def consumed_chunks() -> Generator[bytes, None, None]:
            nonlocal complete
            assert descriptor is not None
            yield from _bound_evidence_chunks(descriptor, expected, absolute_deadline)
            complete = True

        chunks = consumed_chunks()
        _require_stream_deadline(absolute_deadline)
        consumer_active = True
        yield chunks
        consumer_active = False
        if not complete:
            raise ValueError("streamed evidence was not completely consumed")
        _require_stream_custody(root, parent, descriptor, relative, identity, parent_identity)
        _require_stream_deadline(absolute_deadline)
    except BaseException as exc:
        primary = exc
        if isinstance(exc, OSError) and not consumer_active:
            raise ValueError("streamed evidence could not be read safely") from exc
        raise
    finally:
        if chunks is not None:
            chunks.close()
        close_failed = False
        for opened in (descriptor, parent, root.descriptor if root is not None else None):
            if opened is not None:
                try:
                    os.close(opened)
                except OSError:
                    close_failed = True
        if close_failed and primary is None:
            raise ValueError("streamed evidence descriptor cleanup was incomplete")
        if primary is None:
            _require_stream_deadline(absolute_deadline)


def _bound_evidence_chunks(
    descriptor: int, expected: ManifestFileBinding, deadline: float
) -> Iterator[bytes]:
    digest = hashlib.sha256()
    size = 0
    while True:
        _require_stream_deadline(deadline)
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, expected.size - size + 1))
        _require_stream_deadline(deadline)
        if not chunk:
            break
        size += len(chunk)
        if size > expected.size:
            raise ValueError("streamed evidence exceeds its exact binding")
        digest.update(chunk)
        yield chunk
    if size != expected.size or digest.hexdigest() != expected.sha256:
        raise ValueError("streamed evidence bytes differ from the selected binding")


def _require_stream_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ValueError("streamed evidence exceeded its shared deadline")


def _require_stream_custody(
    root: _RootHandle,
    parent: int,
    descriptor: int,
    relative: str,
    identity: tuple[int, int, int, int, int, int, int],
    parent_identity: tuple[int, int, int],
) -> None:
    """Rejoin a retained file to its current path without reopening a possible FIFO."""

    _require_same_root(root.path, root.identity)
    current_parent, leaf = _open_parent(root, relative)
    try:
        if (
            _directory_identity(os.fstat(parent)) != parent_identity
            or _directory_identity(os.fstat(current_parent)) != parent_identity
            or _stat_identity(os.fstat(descriptor)) != identity
            or _stat_identity(os.stat(leaf, dir_fd=current_parent, follow_symlinks=False))
            != identity
        ):
            raise ValueError("streamed evidence custody changed during consumption")
    finally:
        os.close(current_parent)
    _require_same_root(root.path, root.identity)


def read_json_evidence(
    *,
    evidence_root: Path,
    relative_path: str | Path,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> JsonEvidenceObservation:
    """Read stable JSON beneath an explicit root without following path links."""

    bound = _validate_max_bytes(max_bytes)
    normalized = _normalize_evidence_path(relative_path)
    observation = _observe_file_twice(
        evidence_root=evidence_root,
        relative_path=normalized,
        max_bytes=bound,
    )
    value = _decode_json(observation.content)
    return JsonEvidenceObservation(
        value=value,
        content=observation.content,
        binding=_binding(normalized, observation.content),
    )


def read_file_evidence(
    *,
    evidence_root: Path,
    relative_path: str | Path,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> FileEvidenceObservation:
    """Read bounded bytes beneath an explicit root without following or sharing links."""

    bound = _validate_max_bytes(max_bytes)
    normalized = _normalize_evidence_path(relative_path)
    observation = _observe_file_twice(
        evidence_root=evidence_root,
        relative_path=normalized,
        max_bytes=bound,
    )
    return FileEvidenceObservation(
        content=observation.content,
        binding=_binding(normalized, observation.content),
    )


def read_composed_file_evidence(
    *,
    evidence_root: Path,
    relative_path: str | Path,
    expected_binding: ManifestFileBinding,
    max_bytes: int,
) -> FileEvidenceObservation:
    """Explicit composed read at an exact prebound size; ordinary reader limits remain unchanged."""

    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_COMPOSED_EVIDENCE_BYTES:
        raise ValueError("composed evidence byte bound is invalid")
    if type(expected_binding) is not ManifestFileBinding:
        raise ValueError("composed evidence requires an exact original binding")
    expected = ManifestFileBinding.model_validate(
        expected_binding.model_dump(mode="json"), strict=True
    )
    normalized = _normalize_evidence_path(relative_path)
    if normalized != expected.path or not 0 < expected.size <= max_bytes:
        raise ValueError("composed evidence differs from its selected path or byte bound")
    observed = _observe_file_twice(
        evidence_root=evidence_root,
        relative_path=normalized,
        max_bytes=expected.size,
    )
    binding = _binding(normalized, observed.content)
    if binding != expected:
        raise ValueError("composed evidence file differs from its original binding")
    return FileEvidenceObservation(content=observed.content, binding=binding)


def write_json_evidence(
    *,
    evidence_root: Path,
    relative_path: str | Path,
    value: JsonWritable,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
    validate_content: Callable[[bytes], None] | None = None,
    require_private_parent: bool = False,
) -> ManifestFileBinding:
    """Validate exact JSON while retaining the created inode for failure cleanup.

    The optional validator is trusted host code, not serialized or model-supplied
    authority. It runs before final filesystem checks and descriptor release.
    """

    bound = _validate_max_bytes(max_bytes)
    if validate_content is not None and not callable(validate_content):
        raise ValueError("release evidence content validator must be callable")
    if type(require_private_parent) is not bool:
        raise ValueError("release evidence private-parent requirement must be boolean")
    normalized = _normalize_evidence_path(relative_path)
    try:
        serialized = stable_json(value).encode("utf-8")
        _decode_json(serialized)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("release evidence value is not finite JSON") from exc
    if not serialized or len(serialized) > bound:
        raise ValueError("release evidence JSON exceeds its output bound")

    return _write_file_content(
        evidence_root=evidence_root,
        relative_path=normalized,
        content=serialized,
        max_bytes=bound,
        validate_content=validate_content,
        require_private_parent=require_private_parent,
    )


def write_file_evidence(
    *,
    evidence_root: Path,
    relative_path: str | Path,
    content: bytes,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> ManifestFileBinding:
    """Write exact bounded bytes to one fresh private file and verify its inode."""

    bound = _validate_max_bytes(max_bytes)
    normalized = _normalize_evidence_path(relative_path)
    if not isinstance(content, bytes) or len(content) > bound:
        raise ValueError("release evidence bytes exceed their output bound")
    return _write_file_content(
        evidence_root=evidence_root,
        relative_path=normalized,
        content=content,
        max_bytes=bound,
    )


def write_composed_json_evidence(
    *,
    evidence_root: Path,
    relative_path: str | Path,
    value: JsonWritable,
    max_bytes: int,
    validate_content: Callable[[bytes], None],
) -> ManifestFileBinding:
    """Opt-in bounded composition using the same descriptor writer; ordinary I/O caps are unchanged."""

    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_COMPOSED_EVIDENCE_BYTES:
        raise ValueError("composed evidence byte bound is invalid")
    if not callable(validate_content):
        raise ValueError("composed evidence requires a trusted content validator")
    normalized = _normalize_evidence_path(relative_path)
    try:
        serialized = stable_json(value).encode("utf-8")
        _decode_json(serialized)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("composed evidence value is not finite JSON") from exc
    if not serialized or len(serialized) > max_bytes:
        raise ValueError("composed evidence JSON exceeds its output bound")
    return _write_file_content(
        evidence_root=evidence_root,
        relative_path=normalized,
        content=serialized,
        max_bytes=max_bytes,
        validate_content=validate_content,
        require_private_parent=True,
    )


def revalidate_composed_evidence_file_binding(
    *, evidence_root: Path, binding: ManifestFileBinding
) -> ManifestFileBinding:
    """Recheck a composed file at its original size; growth is refused before allocating its bytes."""

    expected = ManifestFileBinding.model_validate(binding.model_dump(mode="json"))
    if not 0 < expected.size <= MAX_COMPOSED_EVIDENCE_BYTES:
        raise ValueError("composed evidence binding exceeds its byte bound")
    normalized = _normalize_evidence_path(expected.path)
    observed = _observe_file_twice(
        evidence_root=evidence_root, relative_path=normalized, max_bytes=expected.size
    )
    actual = _binding(normalized, observed.content)
    if actual != expected:
        raise ValueError("composed evidence file differs from its manifest binding")
    return actual


def copy_file_evidence(
    *,
    source_root: Path,
    source_relative_path: str | Path,
    destination_root: Path,
    destination_relative_path: str | Path,
    expected_binding: ManifestFileBinding,
) -> ManifestFileBinding:
    """Stream one exact manifest-bound file between trusted roots without following links."""

    source_path = _normalize_evidence_path(source_relative_path)
    destination_path = _normalize_evidence_path(destination_relative_path)
    expected = ManifestFileBinding.model_validate(expected_binding.model_dump(mode="json"))
    if expected.path != source_path:
        raise ValueError("release evidence source path differs from its expected binding")
    if expected.size > MAX_STREAMED_EVIDENCE_BYTES:
        raise ValueError("release evidence source exceeds its streamed-copy bound")
    if not _NONBLOCK_FLAG:
        raise ValueError("nonblocking streamed evidence input is unavailable")

    source: _RootHandle | None = None
    destination: _RootHandle | None = None
    source_parent: int | None = None
    destination_parent: int | None = None
    destination_leaf: str | None = None
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    source_identity: tuple[int, int, int, int, int, int, int] | None = None
    destination_identity: tuple[int, int, int, int, int, int, int] | None = None
    created_identity: tuple[int, int] | None = None
    failure: BaseException | None = None
    cleanup_through_path = False
    result: ManifestFileBinding | None = None
    try:
        source = _open_root(source_root)
        source_parent, source_leaf = _open_parent(source, source_path)
        try:
            source_before = os.stat(
                source_leaf,
                dir_fd=source_parent,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ValueError("release evidence source is missing") from exc
        if (
            not stat.S_ISREG(source_before.st_mode)
            or _is_link_or_reparse(source_before)
            or source_before.st_nlink != 1
            or source_before.st_size != expected.size
        ):
            raise ValueError("release evidence source must be the expected unshared regular file")
        try:
            source_descriptor = os.open(
                source_leaf,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG | _NONBLOCK_FLAG,
                dir_fd=source_parent,
            )
        except OSError as exc:
            raise ValueError("release evidence source could not be opened safely") from exc
        source_opened = os.fstat(source_descriptor)
        if _stat_identity(source_opened) != _stat_identity(source_before):
            raise ValueError("release evidence source changed before streaming")
        source_identity = _stat_identity(source_opened)

        destination = _open_root(destination_root)
        destination_parent, destination_leaf = _open_parent(destination, destination_path)
        try:
            destination_descriptor = os.open(
                destination_leaf,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG,
                0o600,
                dir_fd=destination_parent,
            )
        except OSError as exc:
            raise ValueError("release evidence destination must be a fresh file") from exc
        os.fchmod(destination_descriptor, 0o600)
        destination_opened = os.fstat(destination_descriptor)
        created_identity = (destination_opened.st_dev, destination_opened.st_ino)
        if (
            not stat.S_ISREG(destination_opened.st_mode)
            or destination_opened.st_nlink != 1
            or destination_opened.st_size != 0
            or stat.S_IMODE(destination_opened.st_mode) != 0o600
        ):
            raise ValueError("release evidence output is not a fresh private file")

        source_digest = hashlib.sha256()
        source_size = 0
        while True:
            remaining = expected.size - source_size
            chunk = os.read(source_descriptor, min(_READ_CHUNK_BYTES, remaining + 1))
            if not chunk:
                break
            source_size += len(chunk)
            if source_size > expected.size:
                raise ValueError("release evidence source exceeds its exact streamed-copy binding")
            source_digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("release evidence streamed write made no progress")
                view = view[written:]
        os.fsync(destination_descriptor)

        source_finished = os.fstat(source_descriptor)
        source_after = os.stat(
            source_leaf,
            dir_fd=source_parent,
            follow_symlinks=False,
        )
        source_identities = {
            _stat_identity(source_before),
            _stat_identity(source_opened),
            _stat_identity(source_finished),
            _stat_identity(source_after),
        }
        if (
            len(source_identities) != 1
            or source_size != expected.size
            or source_digest.hexdigest() != expected.sha256
        ):
            raise ValueError("release evidence source changed or differs from its binding")

        destination_written = os.fstat(destination_descriptor)
        os.lseek(destination_descriptor, 0, os.SEEK_SET)
        destination_sha256, destination_size = _hash_descriptor(
            destination_descriptor,
            max_bytes=MAX_STREAMED_EVIDENCE_BYTES,
        )
        destination_verified = os.fstat(destination_descriptor)
        destination_entry = os.stat(
            destination_leaf,
            dir_fd=destination_parent,
            follow_symlinks=False,
        )
        if (
            created_identity != (destination_written.st_dev, destination_written.st_ino)
            or _stat_identity(destination_written) != _stat_identity(destination_verified)
            or _stat_identity(destination_verified) != _stat_identity(destination_entry)
            or destination_verified.st_nlink != 1
            or stat.S_IMODE(destination_verified.st_mode) != 0o600
            or _is_link_or_reparse(destination_entry)
            or destination_size != expected.size
            or destination_sha256 != expected.sha256
        ):
            raise ValueError("release evidence destination differs after streaming")
        os.fsync(destination_parent)

        source_identity = _stat_identity(source_finished)
        destination_identity = _stat_identity(destination_verified)
        _require_same_root(source_root, source.identity)
        _require_same_root(destination_root, destination.identity)
        _require_same_relative_file(
            root=source,
            relative_path=source_path,
            expected_identity=source_identity,
            label="source",
        )
        _require_same_relative_file(
            root=destination,
            relative_path=destination_path,
            expected_identity=destination_identity,
            label="destination",
        )
        # Recheck root identity after resolving both nested paths so a root swap cannot
        # bridge two otherwise valid relative observations.
        _require_same_root(source_root, source.identity)
        _require_same_root(destination_root, destination.identity)
        result = ManifestFileBinding(
            path=destination_path,
            sha256=expected.sha256,
            size=expected.size,
        )
    except BaseException as exc:
        failure = exc
        cleanup_through_path = not _unlink_created_file_at(
            parent_descriptor=destination_parent,
            leaf=destination_leaf,
            created_identity=created_identity,
        )
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination_parent is not None:
            os.close(destination_parent)
        if source_parent is not None:
            os.close(source_parent)
        if destination is not None:
            os.close(destination.descriptor)
        if source is not None:
            os.close(source.descriptor)

    if failure is not None:
        if cleanup_through_path:
            _unlink_created_file(
                evidence_root=destination_root,
                relative_path=destination_path,
                created_identity=created_identity,
            )
        if isinstance(failure, OSError):
            raise ValueError("release evidence could not be streamed safely") from failure
        raise failure
    if result is None or source_identity is None or destination_identity is None:
        raise ValueError("release evidence streamed copy did not produce a bound result")
    return result


def _write_file_content(
    *,
    evidence_root: Path,
    relative_path: str,
    content: bytes,
    max_bytes: int,
    validate_content: Callable[[bytes], None] | None = None,
    require_private_parent: bool = False,
) -> ManifestFileBinding:
    """Retain root, parent and output descriptors through validation and rollback."""

    created_identity: tuple[int, int] | None = None
    root: _RootHandle | None = None
    parent_descriptor: int | None = None
    descriptor: int | None = None
    leaf: str | None = None
    try:
        root = _open_root(evidence_root)
        parent_descriptor, leaf = _open_parent(root, relative_path)
        parent_metadata = os.fstat(parent_descriptor)
        parent_identity = (*_directory_identity(parent_metadata), parent_metadata.st_uid)
        if require_private_parent and (
            parent_metadata.st_uid != os.geteuid() or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            raise ValueError("release evidence output parent must be private and owned")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG
        try:
            descriptor = os.open(leaf, flags, 0o600, dir_fd=parent_descriptor)
        except OSError as exc:
            raise ValueError("release evidence destination must be a fresh file") from exc
        # Record ownership before the first fallible operation that changes the file.
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError("release evidence output is not a fresh private file")

        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("release evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        written_metadata = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        readback = _read_descriptor(descriptor, max_bytes=max_bytes)
        verified_metadata = os.fstat(descriptor)
        entry_metadata = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        expected_identity = _stat_identity(verified_metadata)
        if (
            readback != content
            or created_identity != (written_metadata.st_dev, written_metadata.st_ino)
            or _stat_identity(written_metadata) != expected_identity
            or expected_identity != _stat_identity(entry_metadata)
            or verified_metadata.st_nlink != 1
            or verified_metadata.st_size != len(content)
            or stat.S_IMODE(verified_metadata.st_mode) != 0o600
            or _is_link_or_reparse(entry_metadata)
        ):
            raise ValueError("release evidence output changed while being written")
        os.fsync(parent_descriptor)

        observed = _observe_file_twice(
            evidence_root=evidence_root,
            relative_path=relative_path,
            max_bytes=max_bytes,
        )
        if observed.content != content or observed.identity != expected_identity:
            raise ValueError("release evidence output changed after writing")
        result = _binding(relative_path, content)
        if validate_content is not None:
            validate_content(observed.content)

        # Host validation can fail or observe drift. Do not surrender the original
        # descriptors until it and the final path/content/permission checks succeed.
        _require_same_root(evidence_root, root.identity)
        _require_same_relative_file(
            root=root,
            relative_path=relative_path,
            expected_identity=expected_identity,
            label="output",
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        final_content = _read_descriptor(descriptor, max_bytes=max_bytes)
        final_metadata = os.fstat(descriptor)
        final_entry = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        final_parent = os.fstat(parent_descriptor)
        if (
            final_content != content
            or _stat_identity(final_metadata) != expected_identity
            or _stat_identity(final_entry) != expected_identity
            or (*_directory_identity(final_parent), final_parent.st_uid) != parent_identity
        ):
            raise ValueError("release evidence output changed during final validation")
        _require_same_root(evidence_root, root.identity)
        return result
    except BaseException as failure:
        if descriptor is not None:
            try:
                if created_identity is None:
                    created = os.fstat(descriptor)
                    created_identity = (created.st_dev, created.st_ino)
                _unlink_created_file_at(
                    parent_descriptor=parent_descriptor,
                    leaf=leaf,
                    created_identity=created_identity,
                )
                # A replacement belongs to somebody else; an unknown surviving
                # alias of our inode cannot be safely located/deleted by this call.
                if os.fstat(descriptor).st_nlink != 0:
                    raise ValueError("release evidence created output cleanup is incomplete")
            except (OSError, ValueError) as cleanup_failure:
                raise ValueError("release evidence created output cleanup is incomplete") from (
                    cleanup_failure
                )
        if isinstance(failure, OSError):
            raise ValueError("release evidence output could not be written safely") from failure
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if root is not None:
            os.close(root.descriptor)


def create_evidence_file_binding(
    *,
    evidence_root: Path,
    relative_path: str | Path,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> ManifestFileBinding:
    """Create a binding from two equal observations of one exact evidence file."""

    bound = _validate_max_bytes(max_bytes)
    normalized = _normalize_evidence_path(relative_path)
    observation = _observe_file_twice(
        evidence_root=evidence_root,
        relative_path=normalized,
        max_bytes=bound,
    )
    return _binding(normalized, observation.content)


def revalidate_evidence_file_binding(
    *,
    evidence_root: Path,
    binding: ManifestFileBinding,
    max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
) -> ManifestFileBinding:
    """Require a declared file binding to equal a fresh exact observation."""

    expected = ManifestFileBinding.model_validate(binding.model_dump(mode="json"))
    observed = create_evidence_file_binding(
        evidence_root=evidence_root,
        relative_path=expected.path,
        max_bytes=max_bytes,
    )
    if observed != expected:
        raise ValueError("release evidence file differs from its manifest binding")
    return observed


def _observe_file_twice(
    *,
    evidence_root: Path,
    relative_path: str,
    max_bytes: int,
) -> _FileObservation:
    first = _read_file_once(
        evidence_root=evidence_root,
        relative_path=relative_path,
        max_bytes=max_bytes,
    )
    second = _read_file_once(
        evidence_root=evidence_root,
        relative_path=relative_path,
        max_bytes=max_bytes,
    )
    if first != second:
        raise ValueError("release evidence file changed while being observed")
    return second


def _read_file_once(
    *,
    evidence_root: Path,
    relative_path: str,
    max_bytes: int,
) -> _FileObservation:
    root = _open_root(evidence_root)
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor, leaf = _open_parent(root, relative_path)
        try:
            before = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("release evidence file is missing") from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_link_or_reparse(before)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            raise ValueError("release evidence file must be a bounded unshared regular file")
        # A regular file can be substituted with a FIFO after stat. Never wait for
        # a writer before the descriptor's exact type and identity are rechecked.
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | _NOFOLLOW_FLAG
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(leaf, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            raise ValueError("release evidence file could not be opened safely") from exc
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            raise ValueError("release evidence file changed before it was read")
        content = _read_descriptor(descriptor, max_bytes=max_bytes)
        finished = os.fstat(descriptor)
        try:
            after = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("release evidence file changed while it was read") from exc
        identities = {
            _stat_identity(before),
            _stat_identity(opened),
            _stat_identity(finished),
            _stat_identity(after),
        }
        if (
            len(identities) != 1
            or len(content) != before.st_size
            or finished.st_nlink != 1
            or _is_link_or_reparse(after)
        ):
            raise ValueError("release evidence file changed while it was read")
    except OSError as exc:
        raise ValueError("release evidence file could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        os.close(root.descriptor)
    _require_same_root(evidence_root, root.identity)
    return _FileObservation(content=content, identity=_stat_identity(after))


def _open_root(path: Path) -> _RootHandle:
    if not _DESCRIPTOR_TRAVERSAL_SUPPORTED:
        raise ValueError("descriptor-safe release evidence traversal is unavailable")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError("release evidence root may not traverse a link")
        before = absolute.lstat()
    except OSError as exc:
        raise ValueError("release evidence root is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode) or _is_link_or_reparse(before):
        raise ValueError("release evidence root must be an unlinked directory")
    flags = os.O_RDONLY | _DIRECTORY_FLAG | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise ValueError("release evidence root could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        after = absolute.lstat()
        expected = _directory_identity(before)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _is_link_or_reparse(after)
            or _directory_identity(opened) != expected
            or _directory_identity(after) != expected
        ):
            raise ValueError("release evidence root changed while being opened")
    except BaseException:
        os.close(descriptor)
        raise
    return _RootHandle(
        path=absolute.resolve(strict=True),
        descriptor=descriptor,
        identity=expected,
    )


def _open_parent(root: _RootHandle, relative_path: str) -> tuple[int, str]:
    parts = PurePosixPath(relative_path).parts
    descriptor = os.dup(root.descriptor)
    try:
        for part in parts[:-1]:
            flags = os.O_RDONLY | _DIRECTORY_FLAG | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ValueError("release evidence parent is unavailable or linked") from exc
            try:
                metadata = os.fstat(child)
                if not stat.S_ISDIR(metadata.st_mode) or _is_link_or_reparse(metadata):
                    raise ValueError("release evidence parent must be an unlinked directory")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _read_descriptor(descriptor: int, *, max_bytes: int) -> bytes:
    content = bytearray()
    while len(content) <= max_bytes:
        chunk = os.read(
            descriptor,
            min(_READ_CHUNK_BYTES, max_bytes + 1 - len(content)),
        )
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > max_bytes:
        raise ValueError("release evidence file exceeds its read bound")
    return bytes(content)


def _hash_descriptor(descriptor: int, *, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while size <= max_bytes:
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, max_bytes + 1 - size))
        if not chunk:
            break
        size += len(chunk)
        if size > max_bytes:
            raise ValueError("release evidence file exceeds its streamed-copy bound")
        digest.update(chunk)
    return digest.hexdigest(), size


def _require_same_root(path: Path, expected: tuple[int, int, int]) -> None:
    root = _open_root(path)
    try:
        if root.identity != expected:
            raise ValueError("release evidence root changed during file observation")
    finally:
        os.close(root.descriptor)


def _require_same_relative_file(
    *,
    root: _RootHandle,
    relative_path: str,
    expected_identity: tuple[int, int, int, int, int, int, int],
    label: str,
) -> None:
    """Reopen one nested path from its held root and require the same exact file."""

    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor, leaf = _open_parent(root, relative_path)
        before = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            _stat_identity(before) != expected_identity
            or not stat.S_ISREG(before.st_mode)
            or _is_link_or_reparse(before)
            or before.st_nlink != 1
        ):
            raise ValueError(f"release evidence {label} path changed during streaming")
        descriptor = os.open(
            leaf,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        finished = os.fstat(descriptor)
        after = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        if {
            _stat_identity(before),
            _stat_identity(opened),
            _stat_identity(finished),
            _stat_identity(after),
        } != {expected_identity}:
            raise ValueError(f"release evidence {label} path changed during streaming")
    except OSError as exc:
        raise ValueError(f"release evidence {label} path changed during streaming") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _unlink_created_file_at(
    *,
    parent_descriptor: int | None,
    leaf: str | None,
    created_identity: tuple[int, int] | None,
) -> bool:
    """Remove only this call's output while its original parent descriptor is held."""

    if created_identity is None:
        return True
    if parent_descriptor is None or leaf is None:
        return False
    try:
        metadata = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (metadata.st_dev, metadata.st_ino) != created_identity:
        return False
    try:
        os.unlink(leaf, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError:
        return False
    return True


def _normalize_evidence_path(path: str | Path) -> str:
    raw = str(path)
    try:
        normalized = normalize_relative_path(raw)
    except ValueError as exc:
        raise ValueError("release evidence path must be a safe relative path") from exc
    if (
        not normalized
        or normalized == "."
        or normalized != raw
        or normalized.startswith("-")
        or unicodedata.normalize("NFC", normalized) != normalized
        or is_sensitive_workspace_path(normalized)
    ):
        raise ValueError("release evidence path must be direct, normalized, and non-sensitive")
    return normalized


def _validate_max_bytes(max_bytes: int) -> int:
    if type(max_bytes) is not int or not 1 <= max_bytes <= DEFAULT_MAX_EVIDENCE_BYTES:
        raise ValueError("release evidence byte bound is invalid")
    return max_bytes


def _binding(relative_path: str, content: bytes) -> ManifestFileBinding:
    return ManifestFileBinding(
        path=relative_path,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


def _decode_json(data: bytes) -> JsonValue:
    def unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("release evidence JSON contains duplicate keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise ValueError("release evidence JSON contains a non-finite value")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("release evidence JSON contains an out-of-range number")
        return parsed

    try:
        value = json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("release evidence file is not valid JSON") from exc
    return cast(JsonValue, value)


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


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


def _unlink_created_file(
    *,
    evidence_root: Path,
    relative_path: str,
    created_identity: tuple[int, int] | None,
) -> None:
    if created_identity is None:
        return
    root: _RootHandle | None = None
    parent_descriptor: int | None = None
    try:
        root = _open_root(evidence_root)
        parent_descriptor, leaf = _open_parent(root, relative_path)
        metadata = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) == created_identity:
            os.unlink(leaf, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
    except (OSError, ValueError):
        return
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if root is not None:
            os.close(root.descriptor)
