from __future__ import annotations

import hashlib
import os
import unicodedata
from pathlib import Path

import pytest

import mmaudit.release_io as release_io_module
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    MAX_STREAMED_EVIDENCE_BYTES,
    copy_file_evidence,
    create_evidence_file_binding,
    read_file_evidence,
    read_json_evidence,
    revalidate_evidence_file_binding,
    write_file_evidence,
    write_json_evidence,
)
from mmaudit.reporting.json_report import stable_json


def test_reader_returns_exact_json_and_manifest_binding(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    nested = evidence_root / "gates"
    nested.mkdir(parents=True)
    content = b'{\n  "count": 2,\n  "nested": {"ok": true}\n}\n'
    path = nested / "result.json"
    path.write_bytes(content)

    observed = read_json_evidence(
        evidence_root=evidence_root,
        relative_path="gates/result.json",
    )

    assert observed.value == {"count": 2, "nested": {"ok": True}}
    assert observed.content == content
    assert observed.binding == ManifestFileBinding(
        path="gates/result.json",
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


def test_file_reader_returns_exact_non_json_bytes_and_binding(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    content = b"pragma solidity ^0.8.20;\n"
    (evidence_root / "Fixture.sol").write_bytes(content)

    observed = read_file_evidence(
        evidence_root=evidence_root,
        relative_path="Fixture.sol",
        max_bytes=1_000,
    )

    assert observed.content == content
    assert observed.binding == ManifestFileBinding(
        path="Fixture.sol",
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


@pytest.mark.parametrize("content", [b"", b"\x00forensic\xff\n"])
def test_file_writer_preserves_exact_binary_or_empty_bytes(
    tmp_path: Path,
    content: bytes,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    binding = write_file_evidence(
        evidence_root=evidence_root,
        relative_path="exact.bin",
        content=content,
    )

    assert (evidence_root / "exact.bin").read_bytes() == content
    assert binding.size == len(content)
    assert binding.sha256 == hashlib.sha256(content).hexdigest()
    assert stat_mode(evidence_root / "exact.bin") == 0o600


def test_streamed_copy_preserves_binding_across_different_relative_paths(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "destination"
    source_root.mkdir()
    destination_root.mkdir()
    (source_root / "private").mkdir()
    (destination_root / "runs").mkdir()
    content = b"\x00streamed-forensic-evidence\xff\n"
    (source_root / "private" / "evidence.bin").write_bytes(content)
    expected = ManifestFileBinding(
        path="private/evidence.bin",
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )

    copied = copy_file_evidence(
        source_root=source_root,
        source_relative_path=expected.path,
        destination_root=destination_root,
        destination_relative_path="runs/evidence.bin",
        expected_binding=expected,
    )

    assert MAX_STREAMED_EVIDENCE_BYTES > DEFAULT_MAX_EVIDENCE_BYTES
    assert copied == ManifestFileBinding(
        path="runs/evidence.bin",
        sha256=expected.sha256,
        size=expected.size,
    )
    assert (destination_root / copied.path).read_bytes() == content
    assert stat_mode(destination_root / copied.path) == 0o600


def _streamed_copy_case(
    tmp_path: Path,
    *,
    content: bytes = b"streamed-evidence-mutation-canary\n",
) -> tuple[Path, Path, Path, Path, ManifestFileBinding]:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "destination"
    source_path = source_root / "private" / "evidence.bin"
    destination_path = destination_root / "runs" / "evidence.bin"
    source_path.parent.mkdir(parents=True)
    destination_path.parent.mkdir(parents=True)
    source_path.write_bytes(content)
    return (
        source_root,
        destination_root,
        source_path,
        destination_path,
        ManifestFileBinding(
            path="private/evidence.bin",
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
        ),
    )


def test_streamed_copy_cleans_partial_output_through_renamed_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root, destination_root, _source_path, destination_path, expected = _streamed_copy_case(
        tmp_path
    )
    destination_parent = destination_path.parent
    moved_parent = tmp_path / "moved-destination-parent"
    real_write = release_io_module.os.write
    writes = 0

    def write_then_rename_parent(descriptor: int, data) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            written = real_write(descriptor, data[:3])
            destination_parent.rename(moved_parent)
            destination_parent.mkdir()
            return written
        raise OSError("synthetic streamed write failure")

    monkeypatch.setattr(release_io_module.os, "write", write_then_rename_parent)

    with pytest.raises(ValueError, match="could not be streamed safely"):
        copy_file_evidence(
            source_root=source_root,
            source_relative_path=expected.path,
            destination_root=destination_root,
            destination_relative_path="runs/evidence.bin",
            expected_binding=expected,
        )

    assert not (moved_parent / "evidence.bin").exists()
    assert not destination_path.exists()


@pytest.mark.parametrize("surface", ["leaf", "parent"])
def test_streamed_copy_rejects_nested_source_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    content = b"same bytes do not establish the same source inode\n"
    source_root, destination_root, source_path, destination_path, expected = _streamed_copy_case(
        tmp_path, content=content
    )
    real_require_same_root = release_io_module._require_same_root
    root_checks = 0

    def replace_before_nested_reopen(path: Path, identity) -> None:
        nonlocal root_checks
        root_checks += 1
        if root_checks == 1:
            if surface == "leaf":
                source_path.rename(tmp_path / "detached-source.bin")
                source_path.write_bytes(content)
            else:
                source_path.parent.rename(tmp_path / "detached-source-parent")
                source_path.parent.mkdir()
                source_path.write_bytes(content)
        real_require_same_root(path, identity)

    monkeypatch.setattr(
        release_io_module,
        "_require_same_root",
        replace_before_nested_reopen,
    )

    with pytest.raises(ValueError, match="source path changed"):
        copy_file_evidence(
            source_root=source_root,
            source_relative_path=expected.path,
            destination_root=destination_root,
            destination_relative_path="runs/evidence.bin",
            expected_binding=expected,
        )

    assert not destination_path.exists()


@pytest.mark.parametrize("surface", ["leaf", "parent"])
def test_streamed_copy_rejects_nested_destination_replacement_without_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    content = b"same bytes do not establish the same destination inode\n"
    source_root, destination_root, _source_path, destination_path, expected = _streamed_copy_case(
        tmp_path, content=content
    )
    real_require_same_root = release_io_module._require_same_root
    root_checks = 0
    detached_leaf = tmp_path / "detached-destination.bin"
    detached_parent = tmp_path / "detached-destination-parent"

    def replace_before_nested_reopen(path: Path, identity) -> None:
        nonlocal root_checks
        root_checks += 1
        if root_checks == 2:
            if surface == "leaf":
                destination_path.rename(detached_leaf)
                destination_path.write_bytes(content)
            else:
                destination_path.parent.rename(detached_parent)
                destination_path.parent.mkdir()
                destination_path.write_bytes(content)
        real_require_same_root(path, identity)

    monkeypatch.setattr(
        release_io_module,
        "_require_same_root",
        replace_before_nested_reopen,
    )

    with pytest.raises(ValueError, match="destination path changed"):
        copy_file_evidence(
            source_root=source_root,
            source_relative_path=expected.path,
            destination_root=destination_root,
            destination_relative_path="runs/evidence.bin",
            expected_binding=expected,
        )

    assert destination_path.read_bytes() == content
    if surface == "leaf":
        assert detached_leaf.read_bytes() == content
    else:
        assert not (detached_parent / "evidence.bin").exists()


@pytest.mark.parametrize("replaced_root", ["source", "destination"])
def test_streamed_copy_rejects_root_replacement_and_cleans_held_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replaced_root: str,
) -> None:
    source_root, destination_root, source_path, destination_path, expected = _streamed_copy_case(
        tmp_path
    )
    target = source_root if replaced_root == "source" else destination_root
    moved = tmp_path / f"moved-{replaced_root}-root"
    real_require_same_root = release_io_module._require_same_root
    root_checks = 0

    def replace_before_root_check(path: Path, identity) -> None:
        nonlocal root_checks
        root_checks += 1
        target_check = 1 if replaced_root == "source" else 2
        if root_checks == target_check:
            target.rename(moved)
            target.mkdir()
        real_require_same_root(path, identity)

    monkeypatch.setattr(
        release_io_module,
        "_require_same_root",
        replace_before_root_check,
    )

    with pytest.raises(ValueError, match="root changed"):
        copy_file_evidence(
            source_root=source_root,
            source_relative_path=expected.path,
            destination_root=destination_root,
            destination_relative_path="runs/evidence.bin",
            expected_binding=expected,
        )

    if replaced_root == "source":
        assert (moved / "private" / "evidence.bin").read_bytes() == (
            b"streamed-evidence-mutation-canary\n"
        )
        assert not source_path.exists()
        assert not destination_path.exists()
    else:
        assert not (moved / "runs" / "evidence.bin").exists()
        assert not destination_path.exists()


@pytest.mark.parametrize("mismatch", ["size", "sha256"])
def test_streamed_copy_rejects_binding_mismatch_and_removes_output(
    tmp_path: Path,
    mismatch: str,
) -> None:
    source_root, destination_root, _source_path, destination_path, expected = _streamed_copy_case(
        tmp_path
    )
    invalid = expected.model_copy(
        update={"size": expected.size + 1} if mismatch == "size" else {"sha256": "0" * 64}
    )

    with pytest.raises(ValueError, match=r"expected unshared|differs from its binding"):
        copy_file_evidence(
            source_root=source_root,
            source_relative_path=expected.path,
            destination_root=destination_root,
            destination_relative_path="runs/evidence.bin",
            expected_binding=invalid,
        )

    assert not destination_path.exists()


def test_streamed_copy_preserves_preexisting_destination(tmp_path: Path) -> None:
    source_root, destination_root, _source_path, destination_path, expected = _streamed_copy_case(
        tmp_path
    )
    destination_path.write_bytes(b"preserve unrelated destination\n")

    with pytest.raises(ValueError, match="fresh file"):
        copy_file_evidence(
            source_root=source_root,
            source_relative_path=expected.path,
            destination_root=destination_root,
            destination_relative_path="runs/evidence.bin",
            expected_binding=expected,
        )

    assert destination_path.read_bytes() == b"preserve unrelated destination\n"


def test_streamed_copy_handles_sparse_file_above_in_memory_reader_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "destination"
    source_path = source_root / "large.bin"
    destination_path = destination_root / "large.bin"
    source_root.mkdir()
    destination_root.mkdir()
    size = DEFAULT_MAX_EVIDENCE_BYTES + 4_097
    with source_path.open("wb") as handle:
        handle.write(b"forensic-stream-start")
        handle.seek(size - 1)
        handle.write(b"\x00")
    with source_path.open("rb") as handle:
        source_sha256 = hashlib.file_digest(handle, "sha256").hexdigest()
    expected = ManifestFileBinding(path="large.bin", sha256=source_sha256, size=size)
    real_read = release_io_module.os.read
    requested_read_sizes: list[int] = []

    def bounded_read(descriptor: int, count: int) -> bytes:
        requested_read_sizes.append(count)
        return real_read(descriptor, count)

    monkeypatch.setattr(release_io_module.os, "read", bounded_read)

    copied = copy_file_evidence(
        source_root=source_root,
        source_relative_path=expected.path,
        destination_root=destination_root,
        destination_relative_path="large.bin",
        expected_binding=expected,
    )

    assert copied.size > DEFAULT_MAX_EVIDENCE_BYTES
    assert destination_path.stat().st_size == size
    with destination_path.open("rb") as handle:
        assert hashlib.file_digest(handle, "sha256").hexdigest() == source_sha256
    assert requested_read_sizes
    assert max(requested_read_sizes) <= 1024 * 1024


@pytest.mark.parametrize(
    "content,error",
    [
        (b'{"same":1,"same":2}', "duplicate keys"),
        (b'{"value":NaN}', "non-finite"),
        (b'{"value":Infinity}', "non-finite"),
        (b'{"value":-Infinity}', "non-finite"),
        (b'{"value":1e9999}', "out-of-range"),
        (b'{"truncated":', "not valid JSON"),
        (b"\xff", "not valid JSON"),
    ],
)
def test_reader_rejects_ambiguous_nonfinite_or_malformed_json(
    tmp_path: Path,
    content: bytes,
    error: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "bad.json").write_bytes(content)

    with pytest.raises(ValueError, match=error):
        read_json_evidence(
            evidence_root=evidence_root,
            relative_path="bad.json",
        )


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        ".",
        "./report.json",
        "nested//report.json",
        "nested/../report.json",
        "../report.json",
        "/tmp/report.json",
        "nested\\report.json",
        "-report.json",
        ".env",
        ".env.production",
        "credentials.json",
        ".git/report.json",
    ],
)
def test_evidence_paths_must_be_direct_normalized_relative_and_non_sensitive(
    tmp_path: Path,
    relative_path: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    with pytest.raises(ValueError, match=r"safe relative|direct, normalized"):
        create_evidence_file_binding(
            evidence_root=evidence_root,
            relative_path=relative_path,
        )


def test_evidence_path_must_be_unicode_nfc(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    decomposed = unicodedata.normalize("NFD", "résultat.json")
    assert unicodedata.normalize("NFC", decomposed) != decomposed

    with pytest.raises(ValueError, match="direct, normalized"):
        read_json_evidence(
            evidence_root=evidence_root,
            relative_path=decomposed,
        )


def test_reader_fails_closed_without_descriptor_safe_traversal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "result.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        release_io_module,
        "_DESCRIPTOR_TRAVERSAL_SUPPORTED",
        False,
    )

    with pytest.raises(ValueError, match="descriptor-safe"):
        read_json_evidence(
            evidence_root=evidence_root,
            relative_path="result.json",
        )


@pytest.mark.parametrize("kind", ["root", "parent", "file", "hardlink"])
def test_reader_rejects_links_junction_surfaces_and_shared_files(
    tmp_path: Path,
    kind: str,
) -> None:
    real_root = tmp_path / "real-root"
    parent = real_root / "nested"
    parent.mkdir(parents=True)
    actual = parent / "actual.json"
    actual.write_text("{}\n", encoding="utf-8")

    if kind == "root":
        linked_root = tmp_path / "linked-root"
        linked_root.symlink_to(real_root, target_is_directory=True)
        evidence_root = linked_root
        relative_path = "nested/actual.json"
    elif kind == "parent":
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        (evidence_root / "nested").symlink_to(parent, target_is_directory=True)
        relative_path = "nested/actual.json"
    elif kind == "file":
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        (evidence_root / "linked.json").symlink_to(actual)
        relative_path = "linked.json"
    else:
        evidence_root = tmp_path / "evidence"
        evidence_root.mkdir()
        os.link(actual, evidence_root / "shared.json")
        relative_path = "shared.json"

    with pytest.raises(ValueError, match=r"link|unshared"):
        read_json_evidence(
            evidence_root=evidence_root,
            relative_path=relative_path,
        )


def test_writer_creates_canonical_private_file_and_revalidatable_binding(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    (evidence_root / "nested").mkdir(parents=True)
    value = {"z": [3, 2, 1], "a": {"safe": True}}

    binding = write_json_evidence(
        evidence_root=evidence_root,
        relative_path="nested/report.json",
        value=value,
    )

    destination = evidence_root / binding.path
    assert destination.read_text(encoding="utf-8") == stable_json(value)
    assert stat_mode(destination) == 0o600
    assert binding.sha256 == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert binding.size == destination.stat().st_size
    assert (
        revalidate_evidence_file_binding(
            evidence_root=evidence_root,
            binding=binding,
        )
        == binding
    )
    assert (
        create_evidence_file_binding(
            evidence_root=evidence_root,
            relative_path=binding.path,
        )
        == binding
    )


def test_writer_completes_partial_descriptor_writes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    real_write = os.write

    def partial_write(descriptor: int, data) -> int:
        return real_write(descriptor, data[:3])

    monkeypatch.setattr(release_io_module.os, "write", partial_write)

    binding = write_json_evidence(
        evidence_root=evidence_root,
        relative_path="partial.json",
        value={"payload": "long enough to require several writes"},
    )

    assert binding == create_evidence_file_binding(
        evidence_root=evidence_root,
        relative_path=binding.path,
    )


def test_writer_rejects_preexisting_destination_without_changing_it(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    destination = evidence_root / "existing.json"
    destination.write_bytes(b"preserve me")

    with pytest.raises(ValueError, match="fresh file"):
        write_json_evidence(
            evidence_root=evidence_root,
            relative_path="existing.json",
            value={"replacement": True},
        )

    assert destination.read_bytes() == b"preserve me"


def test_writer_rejects_preexisting_symlink_without_touching_target(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"preserve outside")
    (evidence_root / "linked.json").symlink_to(outside)

    with pytest.raises(ValueError, match="fresh file"):
        write_json_evidence(
            evidence_root=evidence_root,
            relative_path="linked.json",
            value={"replacement": True},
        )

    assert outside.read_bytes() == b"preserve outside"
    assert (evidence_root / "linked.json").is_symlink()


def test_writer_cleans_up_only_the_inode_it_created_on_write_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    destination = evidence_root / "failed.json"
    real_write = os.write
    calls = 0

    def fail_after_partial_write(descriptor: int, data) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(descriptor, data[:2])
        raise OSError("synthetic local write failure")

    monkeypatch.setattr(release_io_module.os, "write", fail_after_partial_write)

    with pytest.raises(ValueError, match="could not be written safely"):
        write_json_evidence(
            evidence_root=evidence_root,
            relative_path="failed.json",
            value={"write": "must fail"},
        )

    assert not destination.exists()


def test_writer_does_not_delete_a_replacement_inode_after_validation_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    destination = evidence_root / "replaced.json"
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b"unrelated replacement")
    real_observer = release_io_module._observe_file_twice

    def replace_before_observation(**kwargs):
        destination.unlink()
        replacement.rename(destination)
        return real_observer(**kwargs)

    monkeypatch.setattr(
        release_io_module,
        "_observe_file_twice",
        replace_before_observation,
    )

    with pytest.raises(ValueError):
        write_json_evidence(
            evidence_root=evidence_root,
            relative_path="replaced.json",
            value={"original": True},
        )

    assert destination.read_bytes() == b"unrelated replacement"


def test_reader_detects_content_change_between_equal_observation_passes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    destination = evidence_root / "racing.json"
    destination.write_text('{"version":1}\n', encoding="utf-8")
    real_reader = release_io_module._read_file_once
    reads = 0

    def read_then_change(**kwargs):
        nonlocal reads
        result = real_reader(**kwargs)
        reads += 1
        if reads == 1:
            destination.write_text('{"version":2}\n', encoding="utf-8")
        return result

    monkeypatch.setattr(release_io_module, "_read_file_once", read_then_change)

    with pytest.raises(ValueError, match="changed while being observed"):
        read_json_evidence(
            evidence_root=evidence_root,
            relative_path="racing.json",
        )


def test_reader_rejects_path_swap_to_symlink_before_descriptor_open(
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    destination = evidence_root / "racing.json"
    destination.write_text('{"version":1}\n', encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text('{"version":2}\n', encoding="utf-8")
    original = tmp_path / "original.json"
    real_open = os.open
    swapped = False

    def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "racing.json" and dir_fd is not None and not swapped:
            swapped = True
            destination.rename(original)
            destination.symlink_to(outside)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(release_io_module.os, "open", swap_then_open)

    with pytest.raises(ValueError, match="opened safely"):
        read_json_evidence(
            evidence_root=evidence_root,
            relative_path="racing.json",
        )


def test_binding_revalidation_rejects_changed_file(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    destination = evidence_root / "bound.json"
    destination.write_text('{"version":1}\n', encoding="utf-8")
    binding = create_evidence_file_binding(
        evidence_root=evidence_root,
        relative_path="bound.json",
    )
    destination.write_text('{"version":2}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="differs from its manifest binding"):
        revalidate_evidence_file_binding(
            evidence_root=evidence_root,
            binding=binding,
        )


@pytest.mark.parametrize("max_bytes", [0, -1, True, 100_000_001])
def test_byte_bounds_are_positive_and_hard_capped(
    tmp_path: Path,
    max_bytes: int,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    with pytest.raises(ValueError, match="byte bound"):
        write_json_evidence(
            evidence_root=evidence_root,
            relative_path="bounded.json",
            value={},
            max_bytes=max_bytes,
        )


def test_writer_rejects_nonfinite_values_and_missing_parent(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    with pytest.raises(ValueError, match="not finite JSON"):
        write_json_evidence(
            evidence_root=evidence_root,
            relative_path="nan.json",
            value={"value": float("nan")},
        )
    assert not (evidence_root / "nan.json").exists()

    with pytest.raises(ValueError, match="parent is unavailable"):
        write_json_evidence(
            evidence_root=evidence_root,
            relative_path="missing/report.json",
            value={},
        )
    assert not (evidence_root / "missing").exists()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
