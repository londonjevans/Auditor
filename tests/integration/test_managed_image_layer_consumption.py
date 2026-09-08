"""Actual local tar/gzip byte consumption; no runtime, image import or extraction."""

from __future__ import annotations

import os
import socket
import subprocess
import tarfile

import pytest

import mmaudit.orchestration.managed_image_layers as layers
from mmaudit.config import ScannerConfig, SmartContractsConfig
from mmaudit.scanners.hardhat import HardhatForkScanner
from tests.oci_image_layer_support import layer_case
from tests.unit.test_stream_file_evidence import descriptors as _stream_descriptors

descriptors = _stream_descriptors


@pytest.fixture(autouse=True)
def offline_no_execution_or_extraction(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("invariant: layer identity must not execute, extract or access a network")

    monkeypatch.setattr(subprocess, "Popen", refused)
    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)
    monkeypatch.setattr(tarfile.TarFile, "extractall", refused)
    monkeypatch.setattr(tarfile.TarFile, "extract", refused)


def verify(case):
    return layers.verify_managed_image_layers(case.bundle, blob_root=case.root)


@pytest.mark.parametrize("indexed", [False, True])
def test_real_layer_material_joins_current_metadata_without_mutation_or_admission(
    tmp_path, descriptors, indexed
):
    case = layer_case(tmp_path.resolve() / "blobs", indexed=indexed)
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in case.root.iterdir()
    }
    first, second = verify(case), verify(case)
    assert first == second
    assert first.total_expanded_bytes == sum(map(len, case.expanded))
    assert tuple(item.stored_binding.sha256 for item in first.layers) == case.layer_digests
    assert before == {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in case.root.iterdir()
    }
    assert first.filesystem_verified is first.image_side_attestation_verified is False
    assert (
        first.execution_evidence_verified
        is first.runtime_authority
        is first.managed_run_ready
        is False
    )
    assert HardhatForkScanner(SmartContractsConfig(), ScannerConfig()).available() is False
    assert not descriptors[0]


@pytest.mark.parametrize("which", [0, 1])
@pytest.mark.parametrize("replacement", ["missing", "symlink", "hardlink", "fifo", "directory"])
def test_unsafe_real_layer_blobs_refuse_without_following_or_waiting(
    tmp_path, descriptors, which, replacement
):
    case = layer_case(tmp_path.resolve() / "blobs")
    leaf = case.root / case.layer_digests[which]
    control = tmp_path / "synthetic-unselected"
    control.write_bytes(leaf.read_bytes())
    leaf.unlink()
    if replacement == "symlink":
        leaf.symlink_to(control)
    elif replacement == "hardlink":
        os.link(control, leaf)
    elif replacement == "fifo":
        os.mkfifo(leaf)
    elif replacement == "directory":
        leaf.mkdir()
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case)
    assert control.read_bytes() == case.stored[which]
    assert not descriptors[0]


@pytest.mark.parametrize("mutation", ["content", "inode", "root"])
def test_layer_drift_during_real_decompression_refuses_and_closes_the_original_input(
    tmp_path, monkeypatch, descriptors, mutation
):
    case = layer_case(tmp_path.resolve() / "blobs", codecs=("gzip",))
    actual = layers._GzipLayerDecoder.expand

    def changed(self, stored):
        for index, chunk in enumerate(actual(self, stored)):
            if index == 0:
                leaf = case.root / case.layer_digests[0]
                if mutation == "content":
                    leaf.write_bytes(b"x" * len(case.stored[0]))
                elif mutation == "inode":
                    leaf.unlink()
                    leaf.write_bytes(case.stored[0])
                else:
                    case.root.rename(tmp_path / "moved")
            yield chunk

    monkeypatch.setattr(layers._GzipLayerDecoder, "expand", changed)
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case)
    assert not descriptors[0]


@pytest.mark.parametrize("mutation", ["metadata", "bundle"])
def test_metadata_and_bundle_are_revalidated_after_consuming_real_layers(
    tmp_path, monkeypatch, descriptors, mutation
):
    case = layer_case(tmp_path.resolve() / "blobs")
    actual = layers._verify_layer
    calls = []

    def changed(*args, **kwargs):
        result = actual(*args, **kwargs)
        calls.append(result)
        if len(calls) == len(case.stored):
            if mutation == "metadata":
                leaf = case.root / case.config_digest
                leaf.write_bytes(leaf.read_bytes().replace(b"linux", b"win32"))
            else:
                object.__setattr__(case.bundle, "bundle_sha256", "f" * 64)
        return result

    monkeypatch.setattr(layers, "_verify_layer", changed)
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case)
    assert len(calls) == len(case.stored)
    assert not descriptors[0]


@pytest.mark.parametrize("exception", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_interrupted_real_decoder_does_not_leave_a_blob_descriptor_or_partial_result(
    tmp_path, monkeypatch, descriptors, exception
):
    case = layer_case(tmp_path.resolve() / "blobs", codecs=("gzip",))
    actual = layers._GzipLayerDecoder.expand
    primary = exception("synthetic decoder interruption")

    def interrupted(self, stored):
        for _chunk in actual(self, stored):
            raise primary
            yield b""  # pragma: no cover - keep the exact iterator protocol.

    monkeypatch.setattr(layers._GzipLayerDecoder, "expand", interrupted)
    with pytest.raises(exception) as error:
        verify(case)
    assert error.value is primary
    assert not descriptors[0]
