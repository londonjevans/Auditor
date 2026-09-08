"""Non-runnable tar changesets and real local blob joins for static membership tests."""

from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

from mmaudit.orchestration.managed_toolchain import (
    MANAGED_HARDHAT_REPORTER_IMAGE_PATH,
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SOURCE_PATH, HARDHAT_REPORTER_VERSION
from tests.oci_image_layer_support import layer_case
from tests.oci_image_metadata_support import sha256

PLACEHOLDER = Path(__file__).parent / "fixtures/oci_image_files/placeholder.txt"
PATHS = {
    ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT: "usr/local/bin/hardhat",
    ManagedToolchainRole.HARDHAT_IMAGE_NODE: "usr/local/bin/node",
    ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK: "usr/local/bin/mmaudit-hardhat-loopback",
    ManagedToolchainRole.HARDHAT_REPORTER: MANAGED_HARDHAT_REPORTER_IMAGE_PATH.removeprefix("/"),
}


@dataclass(frozen=True)
class Entry:
    path: str
    content: bytes = b""
    kind: bytes = tarfile.REGTYPE
    target: str = ""
    mode: int = 0o555
    uid: int = 0
    gid: int = 0
    pax: dict[str, str] | None = None


def archive(entries, *, format=tarfile.USTAR_FORMAT):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=format) as writer:
        for entry in entries:
            info = tarfile.TarInfo(entry.path)
            info.type, info.linkname = entry.kind, entry.target
            info.mode, info.uid, info.gid, info.mtime = entry.mode, entry.uid, entry.gid, 0
            info.size = len(entry.content)
            info.pax_headers = entry.pax or {}
            writer.addfile(info, io.BytesIO(entry.content))
    return stream.getvalue()


def default_entries():
    return tuple(
        Entry(path, HARDHAT_REPORTER_SOURCE_PATH.read_bytes(), mode=0o444)
        if role == ManagedToolchainRole.HARDHAT_REPORTER
        else Entry(path, PLACEHOLDER.read_bytes() + role.value.encode())
        for role, path in PATHS.items()
    )


def file_case(root, *, changesets=None, codecs=None, indexed=True, formats=None):
    entries = default_entries()
    if changesets is None:
        changesets = (entries,)
    codecs = codecs or ("gzip",) * len(changesets)
    formats = formats or (tarfile.USTAR_FORMAT,) * len(changesets)
    case = layer_case(
        root,
        indexed=indexed,
        codecs=codecs,
        expanded=tuple(
            archive(layer, format=format) for layer, format in zip(changesets, formats, strict=True)
        ),
    )
    expected = {role: sha256(entry.content) for role, entry in zip(PATHS, entries, strict=True)}
    members = []
    for member in case.bundle.members:
        changes = {"sha256": expected[member.role]} if member.role in expected else {}
        if member.role == ManagedToolchainRole.HARDHAT_REPORTER:
            changes["version"] = HARDHAT_REPORTER_VERSION
        members.append(member.model_copy(update=changes))
    case.bundle = seal_managed_toolchain_bundle(
        members=tuple(members), target_platform=case.bundle.target_platform
    )
    case.entries = entries
    return case
