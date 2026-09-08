"""Real safe file reads of synthetic OCI metadata; no image or runtime exists."""

from __future__ import annotations

import os
import socket
import subprocess

import pytest

import mmaudit.orchestration.managed_image_metadata as metadata
from mmaudit.config import ScannerConfig, SmartContractsConfig
from mmaudit.scanners.hardhat import HardhatForkScanner
from tests.oci_image_metadata_support import metadata_case


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: metadata consumption must not execute or contact a network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.mark.parametrize("indexed", [False, True])
def test_real_metadata_read_is_repeatable_read_only_and_cannot_enable_hardhat(tmp_path, indexed):
    case = metadata_case(tmp_path.resolve() / "blobs", indexed=indexed)
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in case.root.iterdir()
    }
    first = metadata.read_managed_image_metadata(case.bundle, blob_root=case.root)
    second = metadata.read_managed_image_metadata(case.bundle, blob_root=case.root)
    assert first == second
    assert first.root.binding.sha256 == case.image_digest
    assert first.manifest.binding.sha256 == case.manifest_digest
    assert first.config.binding.sha256 == case.config_digest
    assert before == {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in case.root.iterdir()
    }
    assert not (case.root / first.layers[0].sha256).exists()
    assert first.layer_content_verified is first.image_side_attestation_verified is False
    assert (
        first.execution_evidence_verified
        is first.runtime_authority
        is first.managed_run_ready
        is False
    )
    assert HardhatForkScanner(SmartContractsConfig(), ScannerConfig()).available() is False


@pytest.mark.parametrize("slot", ["root", "manifest", "config"])
@pytest.mark.parametrize("replacement", ["symlink", "hardlink", "fifo", "directory"])
def test_unsafe_real_blob_types_refuse_without_following_or_waiting(tmp_path, slot, replacement):
    case = metadata_case(tmp_path.resolve() / "blobs")
    digest = {
        "root": case.image_digest,
        "manifest": case.manifest_digest,
        "config": case.config_digest,
    }[slot]
    leaf = case.root / digest
    outside = tmp_path / "synthetic-unselected"
    outside.write_bytes(leaf.read_bytes())
    leaf.unlink()
    if replacement == "symlink":
        leaf.symlink_to(outside)
    elif replacement == "hardlink":
        os.link(outside, leaf)
    elif replacement == "fifo":
        os.mkfifo(leaf)
    else:
        leaf.mkdir()
    with pytest.raises(metadata.ManagedImageMetadataError, match="unsafe"):
        metadata.read_managed_image_metadata(case.bundle, blob_root=case.root)
    assert outside.read_bytes() == case.contents[digest]


def test_blob_root_alias_refuses_even_if_every_digest_matches(tmp_path):
    case = metadata_case(tmp_path.resolve() / "blobs")
    alias = tmp_path / "alias"
    alias.symlink_to(case.root, target_is_directory=True)
    with pytest.raises(metadata.ManagedImageMetadataError, match="unsafe"):
        metadata.read_managed_image_metadata(case.bundle, blob_root=alias)


def test_blob_read_detects_same_length_content_drift_between_descriptor_reads(
    tmp_path, monkeypatch
):
    from mmaudit import release_io

    case = metadata_case(tmp_path.resolve() / "blobs")
    original = release_io._read_file_once
    reads = 0

    def drift(*args, **kwargs):
        nonlocal reads
        result = original(*args, **kwargs)
        reads += 1
        if reads == 1:
            selected = case.root / case.image_digest
            value = selected.read_bytes()
            selected.write_bytes(value.replace(b"amd64", b"arm64"))
        return result

    monkeypatch.setattr(release_io, "_read_file_once", drift)
    with pytest.raises(metadata.ManagedImageMetadataError, match="unsafe"):
        metadata.read_managed_image_metadata(case.bundle, blob_root=case.root)
