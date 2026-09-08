"""Bounded, read-only parsing of a deliberately restricted OCI tar changeset.

No TarFile is opened and no paths are extracted. Local PAX overrides are bounded
before allocation; global/GNU/sparse/device/xattr semantics refuse explicitly.
"""

from __future__ import annotations

import hashlib
import math
import re
import tarfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_BLOCK = 512
_CHUNK = 64 * 1024
_ZERO = bytes(_BLOCK)
_KINDS = {
    tarfile.REGTYPE: "file",
    tarfile.AREGTYPE: "file",
    tarfile.DIRTYPE: "directory",
    tarfile.SYMTYPE: "symlink",
    tarfile.LNKTYPE: "hardlink",
}
type OciEntryKind = Literal["file", "directory", "symlink", "hardlink", "whiteout", "opaque"]


class OciLayerLimits(BaseModel):
    """Memory/iteration ceilings independent of the caller's expanded byte limit."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    max_headers: int = Field(default=100_000, ge=1, le=500_000)
    max_metadata_bytes: int = Field(default=16 * 1024**2, ge=1, le=64 * 1024**2)
    max_pax_bytes: int = Field(default=64 * 1024, ge=1, le=1024**2)
    max_path_bytes: int = Field(default=4096, ge=1, le=16_384)
    max_path_depth: int = Field(default=128, ge=1, le=256)


@dataclass(frozen=True, slots=True)
class OciLayerEntry:
    """Content hash and numeric archive metadata, never an extracted inode."""

    path: str
    kind: OciEntryKind
    size: int
    sha256: str | None
    link_target: str | None
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class OciLayerChangeset:
    entries: tuple[OciLayerEntry, ...]
    headers: int
    metadata_bytes: int


def require_oci_deadline(deadline: float) -> None:
    """Refuse late synchronous work; this is not a hard preemption mechanism."""

    if time.monotonic() >= deadline:
        raise ValueError("OCI file inspection exceeded its shared deadline")


def oci_path(path: str, limits: OciLayerLimits, *, directory: bool = False) -> str:
    """Canonical archive-relative names only; never resolve a host filesystem path."""

    _bounded_text(path, limits.max_path_bytes)
    if path.startswith("/"):
        raise ValueError("absolute archive member path is unsupported")
    if path.startswith("./"):
        path = path[2:]
    if directory and path.endswith("/"):
        path = path[:-1]
    if directory and path in {"", "."}:
        return ""
    parts = path.split("/")
    if len(parts) > limits.max_path_depth or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("archive member path is ambiguous or outside its allowance")
    if any(part.startswith(".wh.") for part in parts[:-1]):
        raise ValueError("reserved whiteout name in an archive parent path")
    return path


def _bounded_text(value: str, maximum: int) -> None:
    if (
        not value
        or len(value.encode("utf-8", errors="strict")) > maximum
        or "\\" in value
        or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value)
    ):
        raise ValueError("archive path or link text is unsupported")


class _ChunkReader:
    def __init__(self, chunks: Iterator[bytes], deadline: float) -> None:
        self.chunks = chunks
        self.deadline = deadline
        self.pending = memoryview(b"")
        self.consumed = 0

    def _next(self) -> bool:
        while not self.pending:
            require_oci_deadline(self.deadline)
            try:
                self.pending = memoryview(next(self.chunks))
            except StopIteration:
                return False
        return True

    def pieces(self, size: int) -> Iterator[memoryview]:
        while size:
            require_oci_deadline(self.deadline)
            if not self._next():
                raise ValueError("truncated OCI tar record")
            count = min(size, len(self.pending), _CHUNK)
            result, self.pending = self.pending[:count], self.pending[count:]
            size -= count
            self.consumed += count
            yield result

    def read(self, size: int) -> bytes:
        return b"".join(self.pieces(size))

    def padding(self, size: int) -> None:
        if any(self.read((-size) % _BLOCK)):
            raise ValueError("nonzero OCI tar record padding is unsupported")

    def finish(self) -> None:
        if self.read(_BLOCK) != _ZERO:
            raise ValueError("OCI tar requires two zero end blocks")
        while self._next():
            count = min(len(self.pending), _CHUNK)
            if any(self.pending[:count]):
                raise ValueError("nonzero bytes follow the OCI tar end marker")
            self.pending = self.pending[count:]
            self.consumed += count
        if self.consumed % _BLOCK:
            raise ValueError("OCI tar trailing padding is not block aligned")


def _header(raw: bytes) -> tarfile.TarInfo:
    if raw[257:265] != tarfile.POSIX_MAGIC:
        raise ValueError("only POSIX ustar headers and bounded local PAX are supported")
    if raw[156:157] not in {*_KINDS, tarfile.XHDTYPE}:
        raise ValueError("unsupported OCI tar entry or extension type")
    for start, end in (
        (100, 108),
        (108, 116),
        (116, 124),
        (124, 136),
        (136, 148),
        (148, 156),
        (329, 337),
        (337, 345),
    ):
        if re.fullmatch(rb"[0-7]*", raw[start:end].strip(b" \0")) is None:
            raise ValueError("non-USTAR numeric encoding is unsupported")
    for start, end in ((0, 100), (157, 257), (265, 297), (297, 329), (345, 500)):
        _, separator, padding = raw[start:end].partition(b"\0")
        if separator and any(padding):
            raise ValueError("nonzero bytes after a tar text terminator are unsupported")
    if any(raw[500:512]):
        raise ValueError("nonzero USTAR header padding is unsupported")
    try:
        info = tarfile.TarInfo.frombuf(raw, encoding="utf-8", errors="strict")
        # Preserve names before TarInfo's directory slash normalization.
        name = raw[:100].split(b"\0", 1)[0].decode("utf-8")
        prefix = raw[345:500].split(b"\0", 1)[0].decode("utf-8")
        info.name = prefix + "/" + name if prefix else name
        info.type = raw[156:157]
    except (tarfile.HeaderError, UnicodeError, OverflowError) as exc:
        raise ValueError("invalid OCI tar header") from exc
    if (
        info.size < 0
        or not 0 <= info.mode <= 0o7777
        or min(info.uid, info.gid) < 0
        or info.devmajor != 0
        or info.devminor != 0
    ):
        raise ValueError("unsupported OCI tar numeric metadata")
    return info


def _pax(raw: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    offset = 0
    while offset < len(raw):
        space = raw.find(b" ", offset, min(len(raw), offset + 12))
        prefix = raw[offset:space] if space != -1 else b""
        if not prefix.isdigit() or prefix.startswith(b"0"):
            raise ValueError("invalid PAX byte-length prefix")
        end = offset + int(prefix)
        if end > len(raw) or end <= space + 2 or raw[end - 1 : end] != b"\n":
            raise ValueError("invalid PAX record boundary")
        key, separator, value = raw[space + 1 : end - 1].partition(b"=")
        if not separator or not value:
            raise ValueError("empty or malformed PAX override is unsupported")
        name, text = key.decode("ascii"), value.decode("utf-8", errors="strict")
        if name in values or name not in {
            "path",
            "linkpath",
            "size",
            "uid",
            "gid",
            "uname",
            "gname",
            "mtime",
            "atime",
            "ctime",
        }:
            raise ValueError("duplicate or unsupported PAX keyword")
        if name in {"size", "uid", "gid"} and re.fullmatch(r"[0-9]{1,20}", text) is None:
            raise ValueError("invalid PAX integer override")
        if (
            name in {"mtime", "atime", "ctime"}
            and re.fullmatch(r"-?[0-9]{1,20}(?:\.[0-9]{1,20})?", text) is None
        ):
            raise ValueError("invalid PAX timestamp")
        if "\0" in text:
            raise ValueError("NUL in PAX value")
        values[name] = text
        offset = end
    return values


def read_oci_layer(
    chunks: Iterator[bytes], *, limits: OciLayerLimits, absolute_deadline: float
) -> OciLayerChangeset:
    """Consume every byte; callers separately authenticate and bound expanded input."""

    if type(limits) is not OciLayerLimits:
        raise ValueError("OCI parser requires the exact limits type")
    selected = OciLayerLimits.model_validate_json(limits.model_dump_json(), strict=True)
    if (
        type(absolute_deadline) not in {int, float}
        or not math.isfinite(absolute_deadline)
        or not 0 < absolute_deadline - time.monotonic() <= 600
    ):
        raise ValueError("OCI parser requires a bounded future deadline")
    reader = _ChunkReader(chunks, absolute_deadline)
    entries: list[OciLayerEntry] = []
    paths: set[str] = set()
    pending: dict[str, str] | None = None
    headers = metadata_bytes = 0
    while True:
        require_oci_deadline(absolute_deadline)
        raw = reader.read(_BLOCK)
        if raw == _ZERO:
            if pending is not None:
                raise ValueError("PAX header has no following member")
            reader.finish()
            require_oci_deadline(absolute_deadline)
            return OciLayerChangeset(tuple(entries), headers, metadata_bytes)
        headers += 1
        if headers > selected.max_headers:
            raise ValueError("OCI tar exceeds its header allowance")
        info = _header(raw)
        if info.type == tarfile.XHDTYPE:
            if pending is not None or not 0 < info.size <= selected.max_pax_bytes:
                raise ValueError("stacked, empty or oversized PAX header")
            metadata_bytes += info.size
            if metadata_bytes > selected.max_metadata_bytes:
                raise ValueError("OCI tar exceeds its metadata allowance")
            pending = _pax(reader.read(info.size))
            reader.padding(info.size)
            continue
        overrides, pending = pending or {}, None
        info.name = overrides.get("path", info.name)
        info.linkname = overrides.get("linkpath", info.linkname)
        info.size = int(overrides.get("size", str(info.size)))
        info.uid = int(overrides.get("uid", str(info.uid)))
        info.gid = int(overrides.get("gid", str(info.gid)))
        kind: OciEntryKind
        if info.type in {tarfile.REGTYPE, tarfile.AREGTYPE}:
            kind = "file"
        elif info.type == tarfile.DIRTYPE:
            kind = "directory"
        elif info.type == tarfile.SYMTYPE:
            kind = "symlink"
        else:
            kind = "hardlink"
        path = oci_path(info.name, selected, directory=kind == "directory")
        if path in paths:
            raise ValueError("duplicate normalized OCI layer member")
        paths.add(path)
        link = info.linkname or None
        if kind in {"symlink", "hardlink"}:
            if link is None:
                raise ValueError("empty OCI link target")
            _bounded_text(link, selected.max_path_bytes)
            if kind == "hardlink":
                link = oci_path(link, selected)
        elif link is not None:
            raise ValueError("link metadata on a non-link member")
        metadata_bytes += len(path.encode("utf-8")) + len((link or "").encode("utf-8"))
        if metadata_bytes > selected.max_metadata_bytes:
            raise ValueError("OCI tar exceeds its metadata allowance")
        basename = path.rsplit("/", 1)[-1]
        if basename.startswith(".wh."):
            if kind != "file" or info.size != 0:
                raise ValueError("OCI whiteout must be an empty regular file")
            if basename == ".wh..wh..opq":
                kind = "opaque"
            elif basename.startswith(".wh..wh.") or basename[4:] in {"", ".", ".."}:
                raise ValueError("reserved or invalid OCI whiteout name")
            else:
                kind = "whiteout"
        if kind != "file" and info.size != 0:
            raise ValueError("non-file OCI member contains unsupported payload")
        digest = None
        if kind == "file":
            hasher = hashlib.sha256()
            for piece in reader.pieces(info.size):
                hasher.update(piece)
            digest = hasher.hexdigest()
            reader.padding(info.size)
        entries.append(
            OciLayerEntry(path, kind, info.size, digest, link, info.mode, info.uid, info.gid)
        )
