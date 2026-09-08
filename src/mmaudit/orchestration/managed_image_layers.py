"""Observe pinned local OCI layer bytes without extracting or executing an image."""

from __future__ import annotations

import hashlib
import time
import zlib
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mmaudit.orchestration.managed_image_metadata import (
    ManagedImageLayerReference,
    ManagedImageMetadataObservation,
    read_managed_image_metadata,
)
from mmaudit.orchestration.managed_toolchain import ManagedToolchainBundle
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import stream_file_evidence

_TAR = "application/vnd.oci.image.layer.v1.tar"
_GZIP = _TAR + "+gzip"
_DECOMPRESS_CHUNK_BYTES = 64 * 1024


class ManagedImageLayerError(ValueError):
    """Layer bytes are unavailable, changed, unsupported or outside the selected limits."""


class ManagedImageLayerLimits(BaseModel):
    """Independent input, expansion and elapsed-time limits; never image authority."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    max_layer_bytes: int = Field(default=4 * 1024**3, ge=1, le=4 * 1024**3)
    max_total_bytes: int = Field(default=8 * 1024**3, ge=1, le=8 * 1024**3)
    max_expanded_layer_bytes: int = Field(default=4 * 1024**3, ge=1, le=8 * 1024**3)
    max_total_expanded_bytes: int = Field(default=8 * 1024**3, ge=1, le=16 * 1024**3)
    max_gzip_members: int = Field(default=128, ge=1, le=1024)
    timeout_seconds: float = Field(default=120.0, gt=0, le=600, allow_inf_nan=False)


@dataclass(frozen=True, slots=True)
class ManagedImageLayerBytes:
    """Stored-byte and expanded-byte identities observed during a completed read."""

    reference: ManagedImageLayerReference
    stored_binding: ManifestFileBinding
    expanded_sha256: str
    expanded_bytes: int
    gzip_members: int


@dataclass(frozen=True, slots=True)
class ManagedImageLayersObservation:
    """Layer byte identity only; even valid bytes may not describe a valid tar or image."""

    metadata: ManagedImageMetadataObservation = field(repr=False)
    layers: tuple[ManagedImageLayerBytes, ...]
    total_stored_bytes: int
    total_expanded_bytes: int
    independently_trusted: Literal[False] = field(default=False, init=False)
    filesystem_verified: Literal[False] = field(default=False, init=False)
    image_side_attestation_verified: Literal[False] = field(default=False, init=False)
    execution_evidence_verified: Literal[False] = field(default=False, init=False)
    runtime_authority: Literal[False] = field(default=False, init=False)
    managed_run_ready: Literal[False] = field(default=False, init=False)


def verify_managed_image_layers(
    bundle: ManagedToolchainBundle,
    *,
    blob_root: Path,
    limits: ManagedImageLayerLimits | None = None,
) -> ManagedImageLayersObservation:
    """Consume current metadata and exact layer streams under one narrowing allowance.

    No layer is extracted, persisted or treated as an executable. The initial
    raw hash precedes decompression; the consumption pass rehashes and retains
    path/inode custody. All results wait for successful context exit and fresh
    metadata/bundle revalidation. This does not retain a filesystem launch lease.
    """

    return _inspect_managed_image_layers(bundle, blob_root=blob_root, limits=limits)


def _inspect_managed_image_layers(
    bundle: ManagedToolchainBundle,
    *,
    blob_root: Path,
    limits: ManagedImageLayerLimits | None = None,
    consume_layer: Callable[[int, float, Iterator[bytes]], None] | None = None,
) -> ManagedImageLayersObservation:
    """Share byte authentication with a compiled, nonauthorizing in-process consumer."""

    start = time.monotonic()
    if limits is None:
        limits = ManagedImageLayerLimits()
    if type(limits) is not ManagedImageLayerLimits:
        raise ManagedImageLayerError("layer verification requires the exact limits type")
    try:
        selected = ManagedImageLayerLimits.model_validate_json(
            limits.model_dump_json(), strict=True
        )
        deadline = start + selected.timeout_seconds
        metadata = read_managed_image_metadata(bundle, blob_root=blob_root)
        _require_deadline(deadline)
        if any(item.media_type not in {_TAR, _GZIP} for item in metadata.layers):
            raise ManagedImageLayerError(
                "selected layer compression has no supported local decoder"
            )
        total_stored = sum(item.size for item in metadata.layers)
        if total_stored > selected.max_total_bytes or any(
            item.size > selected.max_layer_bytes for item in metadata.layers
        ):
            raise ManagedImageLayerError("stored layer bytes exceed the selected allowance")
        observations: list[ManagedImageLayerBytes] = []
        total_expanded = 0
        for index, reference in enumerate(metadata.layers):
            remaining = min(
                selected.max_expanded_layer_bytes,
                selected.max_total_expanded_bytes - total_expanded,
            )
            if remaining < 0:
                raise ManagedImageLayerError("expanded image byte allowance is exhausted")
            observation = _verify_layer(
                reference,
                blob_root,
                remaining,
                selected.max_gzip_members,
                deadline,
                consume_expanded=(
                    None if consume_layer is None else partial(consume_layer, index, deadline)
                ),
            )
            observations.append(observation)
            total_expanded += observation.expanded_bytes
        if read_managed_image_metadata(bundle, blob_root=blob_root) != metadata:
            raise ManagedImageLayerError(
                "image metadata or bundle changed during layer verification"
            )
        _require_deadline(deadline)
        return ManagedImageLayersObservation(
            metadata, tuple(observations), total_stored, total_expanded
        )
    except (OSError, ValueError, zlib.error) as exc:
        if isinstance(exc, ManagedImageLayerError):
            raise
        raise ManagedImageLayerError("image layer verification was refused") from exc


def _verify_layer(
    reference: ManagedImageLayerReference,
    root: Path,
    max_expanded_bytes: int,
    max_gzip_members: int,
    deadline: float,
    *,
    consume_expanded: Callable[[Iterator[bytes]], None] | None = None,
) -> ManagedImageLayerBytes:
    binding = ManifestFileBinding(
        path=reference.sha256, sha256=reference.sha256, size=reference.size
    )
    digest = hashlib.sha256()
    size = 0
    complete = False
    with stream_file_evidence(
        evidence_root=root, expected_binding=binding, absolute_deadline=deadline
    ) as stored:
        decoder = (
            None
            if reference.media_type == _TAR
            else _GzipLayerDecoder(max_expanded_bytes, max_gzip_members, deadline)
        )

        def measured() -> Generator[bytes, None, None]:
            nonlocal size, complete
            expanded = stored if decoder is None else decoder.expand(stored)
            for chunk in expanded:
                size += len(chunk)
                if size > max_expanded_bytes:
                    raise ManagedImageLayerError("uncompressed layer exceeds expanded allowance")
                digest.update(chunk)
                yield chunk
            complete = True

        chunks = measured()
        try:
            if consume_expanded is None:
                for _ in chunks:
                    pass
            else:
                consume_expanded(chunks)
            if not complete:
                raise ManagedImageLayerError("expanded layer consumer did not reach complete EOF")
        finally:
            chunks.close()
        if digest.hexdigest() != reference.diff_id_sha256:
            raise ManagedImageLayerError("uncompressed layer digest differs from selected diff ID")
    _require_deadline(deadline)
    members = 0 if decoder is None else decoder.member_count
    return ManagedImageLayerBytes(reference, binding, digest.hexdigest(), size, members)


class _GzipLayerDecoder:
    """Bound every inflate call; never use the unbounded zlib flush operation."""

    def __init__(self, max_bytes: int, max_members: int, deadline: float) -> None:
        self.max_bytes = max_bytes
        self.max_members = max_members
        self.deadline = deadline
        self.expanded_bytes = 0
        self.member_count = 0

    def expand(self, stored: Iterator[bytes]) -> Iterator[bytes]:
        decoder = None
        for pending in stored:
            while True:
                _require_deadline(self.deadline)
                if decoder is None:
                    if not pending:
                        break
                    self.member_count += 1
                    if self.member_count > self.max_members:
                        raise ManagedImageLayerError("gzip layer exceeds its member allowance")
                    decoder = zlib.decompressobj(wbits=31)
                expanded = decoder.decompress(
                    pending,
                    max_length=min(
                        _DECOMPRESS_CHUNK_BYTES, self.max_bytes - self.expanded_bytes + 1
                    ),
                )
                self.expanded_bytes += len(expanded)
                if self.expanded_bytes > self.max_bytes:
                    raise ManagedImageLayerError("gzip layer exceeds expanded byte allowance")
                _require_deadline(self.deadline)
                if expanded:
                    yield expanded
                if decoder.eof:
                    pending = decoder.unused_data
                    decoder = None
                else:
                    unconsumed = decoder.unconsumed_tail
                    if not expanded and unconsumed == pending and pending:
                        raise ManagedImageLayerError("gzip decoder made no bounded progress")
                    pending = unconsumed
                    if not pending and not expanded:
                        break
        if decoder is not None or self.member_count == 0:
            raise ManagedImageLayerError("gzip layer is incomplete or has trailing bytes")


def _require_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ManagedImageLayerError("image layer verification exceeded its shared deadline")
