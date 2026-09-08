"""Bounded offline OCI metadata joins, not image-content or execution attestation.

Consume a supplied SHA-256 blob directory, never tags, URLs, a runtime or host PATH.
This deliberately supports a narrow OCI v1 image subset: a direct manifest or one
flat index, Linux baseline amd64/arm64, and ordinary tar/gzip/zstd layer references.
Nested indexes, artifacts, alternate descriptor locations and platform requirements
not represented in the managed bundle refuse. This is not a general OCI validator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainBundle,
    ManagedToolchainDisposition,
    ManagedToolchainMember,
    ManagedToolchainRole,
)
from mmaudit.release_io import FileEvidenceObservation, JsonValue, _decode_json, read_file_evidence

_INDEX = "application/vnd.oci.image.index.v1+json"
_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_CONFIG = "application/vnd.oci.image.config.v1+json"
_LAYER_TYPES = frozenset(
    "application/vnd.oci.image.layer.v1.tar" + suffix for suffix in ("", "+gzip", "+zstd")
)
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_MAX_METADATA_BYTES = 1024 * 1024
_MAX_INDEX_ENTRIES = 64
_MAX_LAYERS = 128
_MAX_LAYER_BYTES = 4 * 1024**3
_MAX_TOTAL_LAYER_BYTES = 8 * 1024**3


class ManagedImageMetadataError(ValueError):
    """Selected image metadata is absent, inconsistent or outside the supported subset."""


@dataclass(frozen=True, slots=True)
class ManagedImageLayerReference:
    """Ordered declarations only; neither stored nor uncompressed bytes were observed."""

    media_type: str
    sha256: str
    size: int
    diff_id_sha256: str


@dataclass(frozen=True, slots=True)
class ManagedImageMetadataObservation:
    """Exact observed metadata, never a transferable admission or readiness token.

    Retained bytes describe this read only. A later consumer must revalidate its
    current bundle and file/runtime custody; constructing this type grants no trust.
    Config defaults and actual binary architecture have not been validated.
    """

    source_bundle_sha256: str
    image: ManagedToolchainMember
    root: FileEvidenceObservation = field(repr=False)
    manifest: FileEvidenceObservation = field(repr=False)
    config: FileEvidenceObservation = field(repr=False)
    layers: tuple[ManagedImageLayerReference, ...]
    independently_trusted: Literal[False] = field(default=False, init=False)
    layer_content_verified: Literal[False] = field(default=False, init=False)
    image_side_attestation_verified: Literal[False] = field(default=False, init=False)
    execution_evidence_verified: Literal[False] = field(default=False, init=False)
    runtime_authority: Literal[False] = field(default=False, init=False)
    managed_run_ready: Literal[False] = field(default=False, init=False)


def read_managed_image_metadata(
    bundle: ManagedToolchainBundle, *, blob_root: Path
) -> ManagedImageMetadataObservation:
    """Join a pinned image to raw local metadata without loading any layer or runtime.

    ``blob_root`` is an explicit SHA-256 blob directory (for example the
    ``blobs/sha256`` directory of an operator-supplied OCI layout). Only two or
    three selected digest-named files are read, each at most 1 MiB. No directory
    discovery, alternate locations, image import, extraction or execution occurs.
    """

    if type(bundle) is not ManagedToolchainBundle:
        raise ManagedImageMetadataError("image metadata requires the exact managed bundle type")
    if not isinstance(blob_root, Path) or not blob_root.is_absolute() or ".." in blob_root.parts:
        raise ManagedImageMetadataError("image metadata requires an explicit absolute blob root")
    try:
        selected = ManagedToolchainBundle.model_validate_json(bundle.model_dump_json(), strict=True)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ManagedImageMetadataError("image metadata bundle is invalid") from exc
    image = next(
        item
        for item in selected.members
        if item.role is ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE
    )
    if (
        image.disposition is not ManagedToolchainDisposition.PINNED
        or image.sha256 is None
        or image.platform_manifest_sha256 is None
        or image.platform not in {"linux-amd64", "linux-arm64"}
    ):
        raise ManagedImageMetadataError(
            "image metadata requires pinned image and platform identities"
        )

    root, root_value = _read_blob(blob_root, image.sha256)
    if root_value.get("mediaType") == _INDEX:
        descriptor = _select_manifest(root_value, image)
        manifest, manifest_value = _read_blob(
            blob_root, image.platform_manifest_sha256, size=descriptor["size"]
        )
    else:
        if image.sha256 != image.platform_manifest_sha256:
            raise ManagedImageMetadataError("direct image manifest differs from pinned platform")
        manifest, manifest_value = root, root_value
    _require_document(manifest_value, _MANIFEST, {"config", "layers"})
    config_ref = _descriptor(manifest_value.get("config"), {_CONFIG}, _MAX_METADATA_BYTES)
    config, config_value = _read_blob(
        blob_root, _sha256(config_ref.get("digest")), size=config_ref["size"]
    )
    _require_platform(config_value, image.platform)
    layers = _layer_references(manifest_value.get("layers"), config_value.get("rootfs"))
    return ManagedImageMetadataObservation(
        selected.bundle_sha256, image, root, manifest, config, layers
    )


def _read_blob(
    blob_root: Path, sha256: str, *, size: JsonValue = None
) -> tuple[FileEvidenceObservation, dict[str, JsonValue]]:
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise ManagedImageMetadataError("image metadata digest is invalid")
    if size is not None and (type(size) is not int or not 0 < size <= _MAX_METADATA_BYTES):
        raise ManagedImageMetadataError("image metadata descriptor size is outside its bound")
    try:
        observation = read_file_evidence(
            evidence_root=blob_root,
            relative_path=sha256,
            max_bytes=_MAX_METADATA_BYTES if size is None else size,
        )
    except (OSError, ValueError) as exc:
        raise ManagedImageMetadataError(
            "selected image metadata blob is unavailable or unsafe"
        ) from exc
    if observation.binding.sha256 != sha256 or (
        size is not None and observation.binding.size != size
    ):
        raise ManagedImageMetadataError("image metadata raw digest or descriptor size differs")
    try:
        # The shared decoder rejects duplicates/nonfinite values but also accepts
        # UTF-16/32 byte input. This OCI subset explicitly requires UTF-8, no BOM.
        observation.content.decode("utf-8", errors="strict")
        if observation.content.startswith(b"\xef\xbb\xbf") or b"\x00" in observation.content:
            raise ValueError("unsupported JSON byte encoding")
        value = _decode_json(observation.content)
    except (ValueError, RecursionError) as exc:
        raise ManagedImageMetadataError("image metadata is not strict bounded UTF-8 JSON") from exc
    return observation, _object(value)


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ManagedImageMetadataError("image metadata requires a JSON object")
    return value


def _require_document(value: dict[str, JsonValue], media_type: str, fields: set[str]) -> None:
    if (
        type(value.get("schemaVersion")) is not int
        or value["schemaVersion"] != 2
        or value.get("mediaType") != media_type
        or not fields.issubset(value)
        or value.keys() - (fields | {"schemaVersion", "mediaType", "annotations"})
    ):
        raise ManagedImageMetadataError("unsupported image metadata document or media type")
    _annotations(value)


def _annotations(value: dict[str, JsonValue]) -> None:
    if "annotations" in value:
        annotations = _object(value["annotations"])
        if any(not isinstance(item, str) for item in annotations.values()):
            raise ManagedImageMetadataError("image metadata annotations must be strings")


def _sha256(value: JsonValue) -> str:
    match = _DIGEST.fullmatch(value) if isinstance(value, str) else None
    if match is None or match[1] == "0" * 64:
        raise ManagedImageMetadataError("image descriptor requires a nonzero SHA-256 digest")
    return match[1]


def _descriptor(
    value: JsonValue,
    media_types: set[str] | frozenset[str],
    max_bytes: int,
    *,
    platform: bool = False,
) -> dict[str, JsonValue]:
    descriptor = _object(value)
    allowed = {"mediaType", "digest", "size", "annotations"} | ({"platform"} if platform else set())
    media_type, size = descriptor.get("mediaType"), descriptor.get("size")
    if (
        descriptor.keys() - allowed
        or not isinstance(media_type, str)
        or media_type not in media_types
        or type(size) is not int
        or not 0 < size <= max_bytes
    ):
        raise ManagedImageMetadataError("unsupported image descriptor fields, media type or size")
    _sha256(descriptor.get("digest"))
    _annotations(descriptor)
    return descriptor


def _select_manifest(
    value: dict[str, JsonValue], image: ManagedToolchainMember
) -> dict[str, JsonValue]:
    _require_document(value, _INDEX, {"manifests"})
    entries = value["manifests"]
    if not isinstance(entries, list) or not 0 < len(entries) <= _MAX_INDEX_ENTRIES:
        raise ManagedImageMetadataError("image index entry count is outside its bound")
    candidates: list[dict[str, JsonValue]] = []
    seen: set[str] = set()
    for entry in entries:
        descriptor = _descriptor(entry, {_MANIFEST}, _MAX_METADATA_BYTES, platform=True)
        digest = _sha256(descriptor.get("digest"))
        if digest in seen:
            raise ManagedImageMetadataError("image index contains duplicate manifest identities")
        seen.add(digest)
        platform = _object(descriptor.get("platform"))
        if platform.keys() - {
            "os",
            "architecture",
            "variant",
            "os.version",
            "os.features",
            "features",
        }:
            raise ManagedImageMetadataError("image index platform has unsupported fields")
        if any(
            not isinstance(platform.get(key), str) or not platform[key]
            for key in ("os", "architecture")
        ):
            raise ManagedImageMetadataError("image index platform requires OS and architecture")
        if f"{platform['os']}-{platform['architecture']}" == image.platform:
            _require_platform(platform, image.platform)
            candidates.append(descriptor)
    if (
        len(candidates) != 1
        or _sha256(candidates[0].get("digest")) != image.platform_manifest_sha256
    ):
        raise ManagedImageMetadataError("image index does not select one exact pinned platform")
    return candidates[0]


def _require_platform(value: dict[str, JsonValue], platform: str) -> None:
    os_name, architecture = platform.split("-", 1)
    baseline_variant = "v1" if architecture == "amd64" else "v8"
    if (
        value.get("os") != os_name
        or value.get("architecture") != architecture
        or value.get("variant") not in (None, "", baseline_variant)
        or value.get("os.version") not in (None, "")
        or value.get("os.features") not in (None, [])
        or value.get("features") not in (None, [])
    ):
        raise ManagedImageMetadataError("image platform differs or requires unrepresented features")


def _layer_references(
    layers: JsonValue, rootfs: JsonValue
) -> tuple[ManagedImageLayerReference, ...]:
    root = _object(rootfs)
    diff_ids = root.get("diff_ids")
    if (
        root.keys() != {"type", "diff_ids"}
        or root.get("type") != "layers"
        or not isinstance(layers, list)
        or not 0 < len(layers) <= _MAX_LAYERS
        or not isinstance(diff_ids, list)
        or len(diff_ids) != len(layers)
    ):
        raise ManagedImageMetadataError(
            "image layers and config diff IDs are inconsistent or unbounded"
        )
    result: list[ManagedImageLayerReference] = []
    total = 0
    for layer, diff_id in zip(layers, diff_ids, strict=True):
        descriptor = _descriptor(layer, _LAYER_TYPES, _MAX_LAYER_BYTES)
        sha256, diff_sha256 = _sha256(descriptor.get("digest")), _sha256(diff_id)
        media_type, size = descriptor["mediaType"], descriptor["size"]
        assert isinstance(media_type, str) and isinstance(size, int)
        if media_type == "application/vnd.oci.image.layer.v1.tar" and sha256 != diff_sha256:
            raise ManagedImageMetadataError("uncompressed layer digest differs from its diff ID")
        total += size
        if total > _MAX_TOTAL_LAYER_BYTES:
            raise ManagedImageMetadataError("declared image layer bytes exceed the total bound")
        result.append(ManagedImageLayerReference(media_type, sha256, size, diff_sha256))
    return tuple(result)
