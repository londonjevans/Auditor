"""Tiny non-runnable image-layer byte fixtures for offline consumer tests."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path

from tests.oci_image_metadata_support import FIXTURE, TAR, metadata_case, sha256

LAYER_FIXTURE = Path(__file__).parent / "fixtures/oci_image_layers/identity.txt"


def inert_tar(label: bytes = b"base") -> bytes:
    content = LAYER_FIXTURE.read_bytes() + label
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("synthetic/identity.txt")
        member.size, member.mode, member.mtime = len(content), 0o444, 0
        archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def layer_case(root, *, codecs=("tar", "gzip"), expanded=None, stored=None, indexed=True):
    if expanded is None:
        expanded = tuple(inert_tar(str(index).encode()) for index in range(len(codecs)))
    if stored is None:
        stored = tuple(
            raw if codec == "tar" else gzip.compress(raw, mtime=0)
            for codec, raw in zip(codecs, expanded, strict=True)
        )
    config = json.loads(FIXTURE.read_bytes())
    config["rootfs"]["diff_ids"] = ["sha256:" + sha256(raw) for raw in expanded]
    refs = [
        {
            "mediaType": TAR + ("" if codec == "tar" else "+" + codec),
            "digest": "sha256:" + sha256(raw),
            "size": len(raw),
        }
        for codec, raw in zip(codecs, stored, strict=True)
    ]
    case = metadata_case(
        root, indexed=indexed, config=config, edit_manifest=lambda doc: doc.update(layers=refs)
    )
    for content in stored:
        digest = sha256(content)
        (root / digest).write_bytes(content)
        case.contents[digest] = content
    case.expanded, case.stored = expanded, stored
    case.layer_digests = tuple(sha256(raw) for raw in stored)
    return case
