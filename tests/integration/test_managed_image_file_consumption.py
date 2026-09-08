"""Real local blob consumption only; assert no extraction, process, network or admission."""

from __future__ import annotations

import os
import socket
import subprocess
import tarfile
from dataclasses import replace

import pytest

import mmaudit.orchestration.managed_image_files as files
import mmaudit.orchestration.managed_image_layers as layers
from mmaudit.config import ScannerConfig, SmartContractsConfig
from mmaudit.scanners.hardhat import HardhatForkScanner
from tests.oci_image_file_support import Entry, default_entries, file_case
from tests.unit.test_stream_file_evidence import descriptors as _stream_descriptors

descriptors = _stream_descriptors


@pytest.fixture(autouse=True)
def offline_no_execution_or_extraction(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("invariant: static membership must not extract, execute or access a network")

    monkeypatch.setattr(subprocess, "Popen", refused)
    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)
    monkeypatch.setattr(tarfile.TarFile, "extractall", refused)
    monkeypatch.setattr(tarfile.TarFile, "extract", refused)


def verify(case):
    return files.verify_managed_image_files(case.bundle, blob_root=case.root)


@pytest.mark.parametrize("indexed", [False, True])
@pytest.mark.parametrize("codec", ["tar", "gzip"])
def test_real_file_join_is_repeatable_read_only_and_nonauthorizing(
    tmp_path, monkeypatch, descriptors, indexed, codec
):
    entries = default_entries()
    case = file_case(
        tmp_path.resolve() / "blobs",
        indexed=indexed,
        codecs=(codec, codec),
        changesets=(entries, (entries[0], Entry("usr/local/bin/.wh.hardhat"))),
    )
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in case.root.iterdir()
    }
    actual = os.open

    def read_only(path, flags, *args, **kwargs):
        assert flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC) == 0
        return actual(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", read_only)
    first, second = verify(case), verify(case)
    assert first == second
    assert first.files[0].content_layer_index == 1
    assert before == {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in case.root.iterdir()
    }
    assert first.runtime_authority is first.managed_run_ready is False
    assert first.layers.filesystem_verified is False
    assert HardhatForkScanner(SmartContractsConfig(), ScannerConfig()).available() is False
    assert not descriptors[0]


@pytest.mark.parametrize("replacement", ["missing", "symlink", "hardlink", "fifo", "directory"])
def test_unsafe_layer_blob_refuses_before_parser_access(
    tmp_path, monkeypatch, descriptors, replacement
):
    case = file_case(tmp_path.resolve() / "blobs")
    leaf = case.root / case.layer_digests[0]
    control = tmp_path / "inert-control"
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

    def refused(*args, **kwargs):
        pytest.fail("invariant: unsafe raw blob must refuse before tar parser access")

    monkeypatch.setattr(files, "read_oci_layer", refused)
    with pytest.raises(files.ManagedImageFileError):
        verify(case)
    assert not descriptors[0]
    assert control.read_bytes() == case.stored[0]


@pytest.mark.parametrize("mutation", ["content", "inode", "root", "metadata", "bundle"])
def test_drift_after_tar_parse_cannot_return_membership(
    tmp_path, monkeypatch, descriptors, mutation
):
    case = file_case(tmp_path.resolve() / "blobs")
    actual = files.read_oci_layer

    def changed(*args, **kwargs):
        result = actual(*args, **kwargs)
        leaf = case.root / case.layer_digests[0]
        if mutation == "content":
            leaf.write_bytes(b"x" * len(case.stored[0]))
        elif mutation == "inode":
            leaf.unlink()
            leaf.write_bytes(case.stored[0])
        elif mutation == "root":
            case.root.rename(tmp_path / "moved")
        elif mutation == "metadata":
            (case.root / case.config_digest).write_bytes(b"{}")
        else:
            object.__setattr__(case.bundle, "bundle_sha256", "0" * 64)
        return result

    monkeypatch.setattr(files, "read_oci_layer", changed)
    with pytest.raises(files.ManagedImageFileError):
        verify(case)
    assert not descriptors[0]


@pytest.mark.parametrize("exception", [RuntimeError, OSError, KeyboardInterrupt, SystemExit])
def test_consumer_errors_and_interrupts_close_every_owned_descriptor(
    tmp_path, monkeypatch, descriptors, exception
):
    case = file_case(tmp_path.resolve() / "blobs")
    original = exception("synthetic interruption")

    def interrupted(chunks, **kwargs):
        next(chunks)
        raise original

    monkeypatch.setattr(files, "read_oci_layer", interrupted)
    expected = files.ManagedImageFileError if exception is OSError else exception
    with pytest.raises(expected) as caught:
        verify(case)
    if exception is not OSError:
        assert caught.value is original
    assert not descriptors[0]


def test_matching_raw_hash_does_not_replace_the_expanded_diff_id_check(tmp_path, descriptors):
    entries = default_entries()
    case = file_case(tmp_path.resolve() / "blobs", changesets=(entries,))
    actual_reference = layers.read_managed_image_metadata(case.bundle, blob_root=case.root).layers[
        0
    ]
    # Exercise the trusted layer primitive with a deliberately wrong expected diff ID.
    import time

    with pytest.raises(layers.ManagedImageLayerError, match="diff ID"):
        layers._verify_layer(
            replace(actual_reference, diff_id_sha256="0" * 64),
            case.root,
            1024**2,
            1,
            time.monotonic() + 30,
            consume_expanded=lambda chunks: files.read_oci_layer(
                chunks, limits=files.OciLayerLimits(), absolute_deadline=time.monotonic() + 10
            ),
        )
    assert not descriptors[0]
