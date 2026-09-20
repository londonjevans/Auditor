"""Batch traversal retains exact live files and never reuses a prior I/O verdict."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

import mmaudit.release_io as io
from mmaudit.orchestration import development_tree as controller
from mmaudit.repository import file_custody as custody


def observed_files(tmp_path: Path, count: int = 8):
    root = tmp_path / "synthetic-evidence"
    root.mkdir(mode=0o700)
    nested = root / "nested"
    nested.mkdir(mode=0o700)
    files = []
    for index in range(count):
        path = nested / f"record-{index:04d}.json"
        path.write_bytes(b'{"synthetic": true}\n')
        binding = io.read_file_evidence(
            evidence_root=root, relative_path=path.relative_to(root).as_posix()
        ).binding
        files.append(controller._observe_file(root, binding))
    return files


def test_tree_file_batch_holds_one_root_and_keeps_four_fresh_reads_per_file(tmp_path, monkeypatch):
    files = observed_files(tmp_path)
    opened = []
    reads = []
    original_open = io._open_root
    original_read = io._read_descriptor

    def counted_open(path):
        opened.append(path)
        return original_open(path)

    def counted_read(descriptor, *, max_bytes):
        reads.append(descriptor)
        return original_read(descriptor, max_bytes=max_bytes)

    monkeypatch.setattr(io, "_open_root", counted_open)
    monkeypatch.setattr(io, "_read_descriptor", counted_read)
    controller._same_files(files)
    assert len(reads) == 4 * len(files)
    assert len(opened) == 1
    controller._same_files(files)
    assert len(reads) == 8 * len(files)
    assert len(opened) == 2, "a new guard must reopen its root and reread every file"


def test_batch_holds_one_live_parent_for_consecutive_shared_parent_files(tmp_path, monkeypatch):
    files = observed_files(tmp_path)
    opened = []
    original = io._open_parent

    def counted(root, relative_path):
        opened.append(relative_path)
        return original(root, relative_path)

    monkeypatch.setattr(io, "_open_parent", counted)
    controller._same_files(files)
    assert len(opened) == 1


@pytest.mark.parametrize(
    "change", ["bytes", "inode", "mode", "hardlink", "symlink", "fifo", "directory", "missing"]
)
def test_batch_refuses_changed_original_file(tmp_path, change):
    files = observed_files(tmp_path, 1)
    path = files[0].root / files[0].binding.path
    content = path.read_bytes()
    if change == "bytes":
        path.write_bytes(content.replace(b"true", b"null"))
    elif change == "inode":
        path.rename(path.with_suffix(".retained"))
        path.write_bytes(content)
    elif change == "mode":
        path.chmod(0o600 if path.stat().st_mode & 0o077 else 0o644)
    elif change == "hardlink":
        os.link(path, path.with_suffix(".linked"))
    else:
        path.rename(path.with_suffix(".retained"))
        if change == "symlink":
            path.symlink_to(path.with_suffix(".retained"))
        elif change == "fifo":
            os.mkfifo(path)
        elif change == "directory":
            path.mkdir()
    with pytest.raises(ValueError):
        controller._same_files(files)


@pytest.mark.parametrize("read_number", [1, 2, 3, 4])
@pytest.mark.parametrize("phase", ["before", "after"])
@pytest.mark.parametrize("change", ["bytes", "inode", "parent", "root", "ancestor_mode"])
def test_every_live_read_rejoins_exact_file_parent_and_ancestor(
    tmp_path, monkeypatch, read_number, phase, change
):
    files = observed_files(tmp_path, 1)
    path = files[0].root / files[0].binding.path
    original = io._read_file_at_parent
    count = 0

    def mutate():
        if change == "bytes":
            path.write_bytes(path.read_bytes().replace(b"true", b"null"))
        elif change == "inode":
            content = path.read_bytes()
            path.rename(path.with_suffix(".retained"))
            path.write_bytes(content)
        elif change == "ancestor_mode":
            tmp_path.chmod(0o755 if tmp_path.stat().st_mode & 0o077 == 0 else 0o700)
        else:
            target = path.parent if change == "parent" else files[0].root
            target.rename(target.with_name(target.name + "-retained"))
            target.mkdir(mode=0o700)

    def changed_read(**kwargs):
        nonlocal count
        count += 1
        if count == read_number and phase == "before":
            mutate()
        value = original(**kwargs)
        if count == read_number and phase == "after":
            mutate()
        return value

    monkeypatch.setattr(io, "_read_file_at_parent", changed_read)
    with pytest.raises(ValueError):
        controller._same_files(files)
    assert count == read_number


@pytest.mark.parametrize("where", ["root", "parent", "ancestor"])
@pytest.mark.parametrize("change", ["mode", "symlink", "replacement"])
def test_batch_refuses_original_directory_object_changes(tmp_path, where, change):
    files = observed_files(tmp_path, 1)
    target = {"root": files[0].root, "parent": files[0].parent.path, "ancestor": tmp_path}[where]
    if change == "mode":
        target.chmod(0o755 if target.stat().st_mode & 0o077 == 0 else 0o700)
    else:
        retained = target.with_name(target.name + "-retained")
        target.rename(retained)
        if change == "symlink":
            target.symlink_to(retained, target_is_directory=True)
        else:
            target.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        controller._same_files(files)


@pytest.mark.parametrize("mutation", ["append", "binding", "identity", "parent"])
def test_batch_rejects_expected_population_drift_during_final_read(tmp_path, monkeypatch, mutation):
    files = observed_files(tmp_path, 2)
    original = io._read_file_at_parent
    count = 0

    def changed_read(**kwargs):
        nonlocal count
        value = original(**kwargs)
        count += 1
        if count == 8:
            if mutation == "append":
                files.append(files[0])
            elif mutation == "binding":
                object.__setattr__(files[0].binding, "sha256", "f" * 64)
            elif mutation == "identity":
                object.__setattr__(files[0], "identity", (*files[0].identity[:6], 0))
            else:
                object.__setattr__(files[0].parent, "component_identities", ())
        return value

    monkeypatch.setattr(io, "_read_file_at_parent", changed_read)
    with pytest.raises(ValueError):
        controller._same_files(files)
    assert count == 8


@pytest.mark.parametrize(
    "invalid", ["duplicate", "mixed_root", "relative_root", "ancestry", "oversize", "count"]
)
def test_invalid_batch_is_refused_before_open(tmp_path, monkeypatch, invalid):
    files = observed_files(tmp_path, 2)
    if invalid == "duplicate":
        files[1] = files[0]
    elif invalid == "mixed_root":
        files[1] = replace(files[1], root=tmp_path)
    elif invalid == "relative_root":
        files[0] = replace(files[0], root=Path("synthetic-evidence"))
    elif invalid == "ancestry":
        files[0] = replace(files[0], parent=replace(files[0].parent, component_identities=()))
    elif invalid == "count":
        monkeypatch.setattr(custody, "MAX_REGULAR_FILE_CUSTODY_BATCH_FILES", 1)

    def forbidden_open(*args, **kwargs):
        pytest.fail("invalid batch must refuse before descriptor traversal")

    monkeypatch.setattr(io, "_open_root", forbidden_open)
    with pytest.raises(ValueError):
        custody.require_regular_file_custody_batch_unchanged(
            files, label="synthetic batch", max_bytes=1 if invalid == "oversize" else 1024
        )


@pytest.mark.parametrize("bound", [True, 0, -1, 1.5, io.DEFAULT_MAX_EVIDENCE_BYTES + 1])
def test_batch_preserves_ordinary_byte_bound_even_when_empty(bound):
    with pytest.raises(ValueError):
        custody.require_regular_file_custody_batch_unchanged(
            [], label="synthetic batch", max_bytes=bound
        )


def test_batch_keeps_file_checks_when_directory_entries_change(tmp_path):
    files = observed_files(tmp_path, 1)
    (files[0].parent.path / "new-synthetic-sibling").write_bytes(b"inert")
    controller._same_files(files)
    with pytest.raises(ValueError):
        custody.require_regular_file_custody_unchanged(files[0], label="strict single file")


@pytest.mark.parametrize("failure_read", [None, 1, 2, 3, 4, 5, 8, 9, 16])
def test_batch_uses_constant_descriptors_and_closes_them_on_every_exit(
    tmp_path, monkeypatch, failure_read
):
    files = observed_files(tmp_path, 3)
    second_parent = files[0].root / "second-parent"
    second_parent.mkdir(mode=0o700)
    (second_parent / "record.json").write_bytes(b"synthetic second parent")
    binding = io.read_file_evidence(
        evidence_root=files[0].root, relative_path="second-parent/record.json"
    ).binding
    files.insert(1, controller._observe_file(files[0].root, binding))
    descriptors = set()
    high_water = 0
    read_count = 0
    original_open, original_dup, original_close = os.open, os.dup, os.close
    original_read = io._read_descriptor

    def keep(descriptor):
        nonlocal high_water
        assert descriptor not in descriptors
        descriptors.add(descriptor)
        high_water = max(high_water, len(descriptors))
        return descriptor

    def opened(*args, **kwargs):
        return keep(original_open(*args, **kwargs))

    def duplicated(*args, **kwargs):
        return keep(original_dup(*args, **kwargs))

    def closed(descriptor):
        original_close(descriptor)
        descriptors.remove(descriptor)

    def read(descriptor, *, max_bytes):
        nonlocal read_count
        read_count += 1
        if read_count == failure_read:
            raise RuntimeError("synthetic interrupted read")
        return original_read(descriptor, max_bytes=max_bytes)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "dup", duplicated)
    monkeypatch.setattr(os, "close", closed)
    monkeypatch.setattr(io, "_read_descriptor", read)
    if failure_read is None:
        controller._same_files(files)
        assert read_count == 16
    else:
        with pytest.raises(RuntimeError, match="synthetic interrupted read"):
            controller._same_files(files)
    assert not descriptors
    assert high_water <= 4


def test_batch_fifo_substitution_cannot_block_before_identity_check(tmp_path, monkeypatch):
    files = observed_files(tmp_path, 1)
    path = files[0].root / files[0].binding.path
    original = os.open
    substituted = False

    def opened(name, flags, *args, **kwargs):
        nonlocal substituted
        if name == path.name and not substituted:
            assert flags & os.O_NONBLOCK
            path.rename(path.with_suffix(".retained"))
            os.mkfifo(path)
            substituted = True
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", opened)
    with pytest.raises(ValueError, match="changed before it was read"):
        controller._same_files(files)
    assert substituted


def test_batch_admits_its_complete_file_count_boundary(tmp_path):
    files = observed_files(tmp_path, custody.MAX_REGULAR_FILE_CUSTODY_BATCH_FILES)
    assert len(files) == 8192
    controller._same_files(files)
    with pytest.raises(ValueError, match="count bound"):
        controller._same_files([*files, files[0]])


@pytest.mark.parametrize("flag", ["_NONBLOCK_FLAG", "_DESCRIPTOR_TRAVERSAL_SUPPORTED"])
def test_batch_refuses_unavailable_descriptor_safety(tmp_path, monkeypatch, flag):
    files = observed_files(tmp_path, 1)
    monkeypatch.setattr(io, flag, 0)
    with pytest.raises(ValueError, match="unavailable"):
        controller._same_files(files)


def test_batch_never_reuses_previous_positive_custody(tmp_path, monkeypatch):
    files = observed_files(tmp_path, 1)
    controller._same_files(files)
    path = files[0].root / files[0].binding.path
    path.write_bytes(path.read_bytes().replace(b"true", b"null"))

    def forbidden_read(**kwargs):
        pytest.fail("changed file identity must refuse before reading bytes")

    monkeypatch.setattr(io, "_read_file_at_parent", forbidden_read)
    with pytest.raises(ValueError):
        controller._same_files(files)


@pytest.mark.parametrize("read_number", [1, 2, 3, 4])
def test_batch_checks_every_read_bytes_even_with_matching_identity(
    tmp_path, monkeypatch, read_number
):
    files = observed_files(tmp_path, 1)
    original = io._read_file_at_parent
    count = 0

    def altered(**kwargs):
        nonlocal count
        observed = original(**kwargs)
        count += 1
        if count == read_number:
            return replace(observed, content=observed.content.replace(b"true", b"null"))
        return observed

    monkeypatch.setattr(io, "_read_file_at_parent", altered)
    with pytest.raises(ValueError, match="bytes"):
        controller._same_files(files)
    assert count == read_number


@pytest.mark.parametrize("selected_descriptor", ["root", "parent"])
def test_batch_rejoins_held_descriptors_to_live_original_directories(
    tmp_path, monkeypatch, selected_descriptor
):
    files = observed_files(tmp_path, 1)
    other = tmp_path / "other-synthetic-directory"
    other.mkdir(mode=0o700)
    supplied = []
    original_root = io._open_root

    def root(path):
        opened = original_root(other)
        supplied.append(opened.descriptor)
        identity = files[0].root.stat()
        return replace(
            opened,
            path=files[0].root,
            identity=(identity.st_dev, identity.st_ino, identity.st_mode),
        )

    def parent(root, relative_path):
        descriptor = os.open(other, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        supplied.append(descriptor)
        return descriptor, relative_path.rsplit("/", 1)[-1]

    def forbidden_read(**kwargs):
        pytest.fail("a different held directory must refuse before reading any bytes")

    monkeypatch.setattr(
        io,
        "_open_root" if selected_descriptor == "root" else "_open_parent",
        root if selected_descriptor == "root" else parent,
    )
    monkeypatch.setattr(io, "_read_file_at_parent", forbidden_read)
    with pytest.raises(ValueError):
        controller._same_files(files)
    assert supplied
    for descriptor in supplied:
        with pytest.raises(OSError):
            os.fstat(descriptor)
