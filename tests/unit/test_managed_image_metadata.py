from __future__ import annotations

import copy
import json
import socket
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import mmaudit.orchestration.managed_image_metadata as metadata
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainBundle,
    default_managed_toolchain_bundle,
)
from tests.oci_image_metadata_support import (
    CONFIG,
    FIXTURE,
    INDEX,
    MANIFEST,
    TAR,
    json_bytes,
    metadata_case,
    pinned_bundle,
)


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("offline image metadata must not start a process or use a network")

    monkeypatch.setattr(subprocess, "Popen", refused)
    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)


def read(case):
    return metadata.read_managed_image_metadata(case.bundle, blob_root=case.root)


@pytest.mark.parametrize("indexed", [False, True])
@pytest.mark.parametrize("platform", ["linux-amd64", "linux-arm64"])
def test_exact_raw_chain_keeps_order_without_image_or_runtime_authority(
    tmp_path, indexed, platform
):
    case = metadata_case(tmp_path / "blobs", indexed=indexed, platform=platform)
    observation = read(case)
    assert observation.source_bundle_sha256 == case.bundle.bundle_sha256
    assert observation.image.platform == platform
    assert observation.root.binding.sha256 == case.image_digest
    assert observation.manifest.binding.sha256 == case.manifest_digest
    assert observation.config.binding.sha256 == case.config_digest
    assert observation.config.content == case.contents[case.config_digest]
    assert (
        observation.root is observation.manifest
        if not indexed
        else observation.root is not observation.manifest
    )
    assert [(x.sha256, x.diff_id_sha256, x.size) for x in observation.layers] == [
        ("1" * 64, "1" * 64, 10240),
        ("3" * 64, "2" * 64, 1234),
    ]
    assert observation.image is not next(
        member for member in case.bundle.members if member.role == observation.image.role
    )
    for key in (
        "independently_trusted",
        "layer_content_verified",
        "image_side_attestation_verified",
        "execution_evidence_verified",
        "runtime_authority",
        "managed_run_ready",
    ):
        assert getattr(observation, key) is False
    with pytest.raises(FrozenInstanceError):
        observation.runtime_authority = True
    assert "rootfs" not in repr(observation)


@pytest.mark.parametrize("slot", ["root", "manifest", "config"])
def test_raw_byte_change_is_not_accepted_as_equivalent_json(tmp_path, slot):
    case = metadata_case(tmp_path / "blobs")
    digest = {
        "root": case.image_digest,
        "manifest": case.manifest_digest,
        "config": case.config_digest,
    }[slot]
    # Same byte length, same JSON value, different raw digest.
    original = case.contents[digest]
    changed = json_bytes(dict(reversed(json.loads(original).items())))
    assert changed != original and len(changed) == len(original)
    (case.root / digest).write_bytes(changed)
    with pytest.raises(metadata.ManagedImageMetadataError, match="raw digest"):
        read(case)


@pytest.mark.parametrize("slot", ["root", "manifest", "config"])
def test_missing_selected_blob_never_uses_an_alternate_location(tmp_path, slot):
    case = metadata_case(tmp_path / "blobs")
    digest = {
        "root": case.image_digest,
        "manifest": case.manifest_digest,
        "config": case.config_digest,
    }[slot]
    (case.root / digest).unlink()
    with pytest.raises(metadata.ManagedImageMetadataError, match="unavailable or unsafe"):
        read(case)


@pytest.mark.parametrize("pin", ["config-as-root", "config-as-both", "different-child"])
def test_config_image_id_cannot_stand_in_for_a_manifest(tmp_path, pin):
    case = metadata_case(tmp_path / "blobs", indexed=False)
    root = case.config_digest if pin.startswith("config") else case.manifest_digest
    child = case.config_digest if pin == "config-as-both" else case.manifest_digest
    if pin == "different-child":
        child = "a" * 64
    case.bundle = pinned_bundle(root, child)
    with pytest.raises(metadata.ManagedImageMetadataError, match=r"manifest|document"):
        read(case)


@pytest.mark.parametrize("delta", [-1, 1])
@pytest.mark.parametrize("slot", ["manifest", "config"])
def test_parent_descriptor_size_is_exact(tmp_path, slot, delta):
    def edit(value):
        descriptor = value["manifests"][0] if slot == "manifest" else value["config"]
        descriptor["size"] += delta

    case = metadata_case(
        tmp_path / "blobs", **{"edit_index" if slot == "manifest" else "edit_manifest": edit}
    )
    with pytest.raises(metadata.ManagedImageMetadataError, match=r"size|unsafe"):
        read(case)


@pytest.mark.parametrize(
    "key,value",
    [
        ("schemaVersion", True),
        ("schemaVersion", 2.0),
        ("schemaVersion", 1),
        ("mediaType", CONFIG),
        ("mediaType", "application/vnd.docker.distribution.manifest.v2+json"),
        ("artifactType", "synthetic/artifact"),
        ("subject", {}),
        ("unknown", True),
        ("annotations", {"invalid": False}),
    ],
)
@pytest.mark.parametrize("slot", ["index", "manifest"])
def test_unsupported_documents_refuse(tmp_path, key, value, slot):
    case = metadata_case(
        tmp_path / "blobs", **{"edit_" + slot: lambda doc: doc.update({key: value})}
    )
    with pytest.raises(metadata.ManagedImageMetadataError):
        read(case)


@pytest.mark.parametrize(
    "key,value",
    [
        ("size", True),
        ("size", "1024"),
        ("size", 1.0),
        ("size", 0),
        ("size", -1),
        ("size", 2**63),
        ("digest", "sha256:" + "0" * 64),
        ("digest", "sha256:" + "A" * 64),
        ("digest", "sha512:" + "a" * 128),
        ("digest", "../../unselected"),
        ("mediaType", INDEX),
        ("urls", ["https://registry.example/never-contact"]),
        ("data", "e30="),
        ("artifactType", "synthetic/artifact"),
        ("platform", {"os": "linux"}),
    ],
)
def test_config_descriptor_rejects_ambiguous_or_alternate_inputs(tmp_path, key, value):
    case = metadata_case(
        tmp_path / "blobs", edit_manifest=lambda doc: doc["config"].update({key: value})
    )
    with pytest.raises(metadata.ManagedImageMetadataError):
        read(case)


@pytest.mark.parametrize(
    "key,value",
    [
        ("os", "windows"),
        ("architecture", "arm64"),
        ("variant", "v2"),
        ("os.version", "synthetic-required-version"),
        ("os.features", ["synthetic"]),
        ("features", ["synthetic"]),
        ("architecture", None),
        ("variant", []),
    ],
)
@pytest.mark.parametrize("slot", ["index", "config"])
def test_selected_platform_must_match_without_unrepresented_requirements(
    tmp_path, key, value, slot
):
    if slot == "config":
        config = json.loads(FIXTURE.read_bytes())
        config[key] = value
        case = metadata_case(tmp_path / "blobs", config=config)
    else:
        case = metadata_case(
            tmp_path / "blobs",
            edit_index=lambda doc: doc["manifests"][0]["platform"].update({key: value}),
        )
    with pytest.raises(metadata.ManagedImageMetadataError, match="platform"):
        read(case)


@pytest.mark.parametrize("platform,variant", [("linux-amd64", "v1"), ("linux-arm64", "v8")])
def test_explicit_baseline_variants_are_accepted_but_do_not_prove_binary_architecture(
    tmp_path, platform, variant
):
    config = json.loads(FIXTURE.read_bytes())
    config.update(architecture=platform.split("-", 1)[1], variant=variant)
    case = metadata_case(
        tmp_path / "blobs",
        platform=platform,
        config=config,
        edit_index=lambda doc: doc["manifests"][0]["platform"].update(variant=variant),
    )
    assert read(case).image_side_attestation_verified is False


@pytest.mark.parametrize(
    "mode",
    ["duplicate", "ambiguous", "wrong-pin", "nested", "empty", "too-many", "missing-platform"],
)
def test_index_requires_one_exact_unambiguous_platform(tmp_path, mode):
    def edit(doc):
        entries = doc["manifests"]
        if mode in {"duplicate", "ambiguous"}:
            other = copy.deepcopy(entries[0])
            if mode == "ambiguous":
                other["digest"] = "sha256:" + "a" * 64
            entries.append(other)
        elif mode == "wrong-pin":
            entries[0]["digest"] = "sha256:" + "a" * 64
        elif mode == "nested":
            entries[0]["mediaType"] = INDEX
        elif mode == "empty":
            doc["manifests"] = []
        elif mode == "too-many":
            doc["manifests"] *= 65
        else:
            entries[0].pop("platform")

    with pytest.raises(metadata.ManagedImageMetadataError):
        read(metadata_case(tmp_path / "blobs", edit_index=edit))


def test_unselected_platform_is_not_read_and_cannot_change_exact_selection(tmp_path, monkeypatch):
    def edit(doc):
        doc["manifests"].insert(
            0,
            {
                "mediaType": MANIFEST,
                "size": 10,
                "digest": "sha256:" + "a" * 64,
                "platform": {"os": "linux", "architecture": "arm64"},
            },
        )

    case = metadata_case(tmp_path / "blobs", edit_index=edit)
    original, paths = metadata.read_file_evidence, []

    def tracked(**kwargs):
        paths.append(kwargs["relative_path"])
        return original(**kwargs)

    monkeypatch.setattr(metadata, "read_file_evidence", tracked)
    assert read(case).manifest.binding.sha256 == case.manifest_digest
    assert paths == [case.image_digest, case.manifest_digest, case.config_digest]


@pytest.mark.parametrize(
    "mode",
    [
        "empty",
        "too-many",
        "count",
        "root-type",
        "root-extra",
        "digest",
        "uncompressed-mismatch",
        "per-layer",
        "total",
        "foreign",
        "urls",
    ],
)
def test_layer_references_are_bounded_ordered_declarations(tmp_path, mode):
    config = json.loads(FIXTURE.read_bytes())
    if mode == "count":
        config["rootfs"]["diff_ids"].pop()
    elif mode == "root-type":
        config["rootfs"]["type"] = "unknown"
    elif mode == "root-extra":
        config["rootfs"]["extra"] = True
    elif mode == "digest":
        config["rootfs"]["diff_ids"][0] = "sha256:" + "A" * 64
    elif mode == "too-many":
        config["rootfs"]["diff_ids"] = ["sha256:" + "1" * 64] * 129
    elif mode == "total":
        config["rootfs"]["diff_ids"] = ["sha256:" + "1" * 64] * 3

    def edit(doc):
        if mode == "empty":
            doc["layers"] = []
        elif mode == "too-many":
            doc["layers"] = [doc["layers"][0]] * 129
        elif mode == "uncompressed-mismatch":
            doc["layers"][0]["digest"] = "sha256:" + "f" * 64
        elif mode == "per-layer":
            doc["layers"][0]["size"] = 4 * 1024**3 + 1
        elif mode == "total":
            doc["layers"][0]["size"] = 4 * 1024**3
            doc["layers"] = [doc["layers"][0]] * 3
        elif mode == "foreign":
            doc["layers"][0]["mediaType"] = (
                "application/vnd.oci.image.layer.nondistributable.v1.tar"
            )
        elif mode == "urls":
            doc["layers"][0]["urls"] = ["https://registry.example/unselected"]

    with pytest.raises(metadata.ManagedImageMetadataError):
        read(metadata_case(tmp_path / "blobs", config=config, edit_manifest=edit))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"os":"linux","os":"linux"}',
        b'{"n":NaN}',
        b'{"n":1e999}',
        b"[]",
        b"{} {}",
        b'{"x":"\xff"}',
        b"\xef\xbb\xbf{}",
        "{}".encode("utf-16"),
        b"[" * 2000 + b"]" * 2000,
    ],
)
@pytest.mark.parametrize("slot", ["config", "manifest", "index"])
def test_raw_metadata_is_strict_json_even_when_all_declared_hashes_match(tmp_path, raw, slot):
    case = metadata_case(tmp_path / "blobs", **{slot + "_bytes": raw})
    with pytest.raises(metadata.ManagedImageMetadataError):
        read(case)


def test_metadata_size_bound_applies_before_decoding(tmp_path, monkeypatch):
    case = metadata_case(tmp_path / "blobs", index_bytes=b" " * (metadata._MAX_METADATA_BYTES + 1))
    monkeypatch.setattr(metadata, "_decode_json", lambda _: pytest.fail("oversized blob decoded"))
    with pytest.raises(metadata.ManagedImageMetadataError, match="unavailable or unsafe"):
        read(case)


def test_declared_digest_is_checked_before_json_processing(tmp_path, monkeypatch):
    case = metadata_case(tmp_path / "blobs")
    (case.root / case.image_digest).write_bytes(b"{}")
    monkeypatch.setattr(metadata, "_decode_json", lambda _: pytest.fail("unmatched digest decoded"))
    with pytest.raises(metadata.ManagedImageMetadataError, match="raw digest"):
        read(case)


@pytest.mark.parametrize(
    "mode",
    ["mapping", "subclass", "hash", "authority", "unresolved", "relative-root", "traversal-root"],
)
def test_invalid_or_unresolved_bundle_and_root_refuse_before_any_blob_read(
    tmp_path, monkeypatch, mode
):
    case = metadata_case(tmp_path / "blobs")
    if mode == "mapping":
        case.bundle = case.bundle.model_dump()
    elif mode == "subclass":

        class Derived(ManagedToolchainBundle):
            pass

        case.bundle = Derived.model_validate(case.bundle.model_dump())
    elif mode == "hash":
        object.__setattr__(case.bundle, "bundle_sha256", "a" * 64)
    elif mode == "authority":
        object.__setattr__(case.bundle, "runtime_authority", True)
    elif mode == "unresolved":
        case.bundle = default_managed_toolchain_bundle()
    elif mode == "relative-root":
        case.root = Path("blobs")
    else:
        case.root = case.root / ".." / "blobs"
    monkeypatch.setattr(
        metadata, "read_file_evidence", lambda **_: pytest.fail("invalid selection read files")
    )
    with pytest.raises(metadata.ManagedImageMetadataError):
        read(case)


def test_oci_metadata_does_not_interpret_runtime_defaults_as_safe(tmp_path):
    config = json.loads(FIXTURE.read_bytes())
    config["config"] = {"Entrypoint": ["/synthetic/not-executed"], "Env": ["SYNTHETIC=untrusted"]}
    case = metadata_case(
        tmp_path / "blobs",
        config=config,
        edit_manifest=lambda doc: doc["layers"][1].update(mediaType=TAR + "+zstd"),
    )
    observation = read(case)
    assert observation.config.content == json_bytes(config)
    assert observation.runtime_authority is observation.image_side_attestation_verified is False
