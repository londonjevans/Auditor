"""Build non-runnable local OCI metadata; no image, layer or executable is produced."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainMemberKind,
    seal_managed_toolchain_bundle,
)
from tests.managed_toolchain_support import synthetic_pinned_members

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
TAR = "application/vnd.oci.image.layer.v1.tar"
FIXTURE = Path(__file__).parent / "fixtures/oci_image_metadata/config.json"


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def pinned_bundle(image_digest: str, manifest_digest: str, platform: str = "linux-amd64"):
    members = []
    for member in synthetic_pinned_members():
        changes: dict[str, Any] = {}
        if member.kind is ManagedToolchainMemberKind.OCI_IMAGE:
            changes = {
                "sha256": image_digest,
                "locator": "registry.example/mmaudit-toolchain@sha256:" + image_digest,
                "platform_manifest_sha256": manifest_digest,
                "platform": platform,
            }
        elif member.kind is ManagedToolchainMemberKind.IMAGE_EXECUTABLE:
            changes = {
                "parent_image_sha256": image_digest,
                "parent_platform_manifest_sha256": manifest_digest,
            }
        members.append(member.model_copy(update=changes))
    return seal_managed_toolchain_bundle(members=tuple(members), target_platform=platform)


def metadata_case(
    root: Path,
    *,
    indexed: bool = True,
    platform: str = "linux-amd64",
    config: Any = None,
    config_bytes: bytes | None = None,
    manifest_bytes: bytes | None = None,
    index_bytes: bytes | None = None,
    edit_manifest: Callable[[dict[str, Any]], Any] | None = None,
    edit_index: Callable[[dict[str, Any]], Any] | None = None,
) -> SimpleNamespace:
    root.mkdir(mode=0o700)
    if config is None:
        config = json.loads(FIXTURE.read_bytes())
        config["architecture"] = platform.split("-", 1)[1]
    config_content = json_bytes(config) if config_bytes is None else config_bytes
    config_digest = sha256(config_content)
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": {
            "mediaType": CONFIG,
            "size": len(config_content),
            "digest": "sha256:" + config_digest,
        },
        "layers": [
            {"mediaType": TAR, "digest": "sha256:" + "1" * 64, "size": 10240},
            {"mediaType": TAR + "+gzip", "digest": "sha256:" + "3" * 64, "size": 1234},
        ],
    }
    if edit_manifest is not None:
        edit_manifest(manifest)
    manifest_content = json_bytes(manifest) if manifest_bytes is None else manifest_bytes
    manifest_digest = sha256(manifest_content)
    index = {
        "schemaVersion": 2,
        "mediaType": INDEX,
        "manifests": [
            {
                "mediaType": MANIFEST,
                "size": len(manifest_content),
                "digest": "sha256:" + manifest_digest,
                "platform": {"os": "linux", "architecture": platform.split("-", 1)[1]},
            }
        ],
    }
    if edit_index is not None:
        edit_index(index)
    index_content = json_bytes(index) if index_bytes is None else index_bytes
    image_digest = sha256(index_content) if indexed else manifest_digest
    contents = {config_digest: config_content, manifest_digest: manifest_content}
    if indexed:
        contents[image_digest] = index_content
    for digest, content in contents.items():
        (root / digest).write_bytes(content)
    return SimpleNamespace(
        root=root,
        bundle=pinned_bundle(image_digest, manifest_digest, platform),
        image_digest=image_digest,
        manifest_digest=manifest_digest,
        config_digest=config_digest,
        config=config,
        manifest=manifest,
        index=index,
        contents=contents,
    )
