from __future__ import annotations

import hashlib
import os
import stat
import time

import pytest

import mmaudit.release_io as evidence
from mmaudit.orchestration.manifest import ManifestFileBinding
from tests.oci_image_layer_support import LAYER_FIXTURE


def case_inputs(tmp_path, content=None):
    if content is None:
        content = LAYER_FIXTURE.read_bytes()
    leaf = tmp_path / "blob"
    leaf.write_bytes(content)
    binding = ManifestFileBinding(
        path=leaf.name, sha256=hashlib.sha256(content).hexdigest(), size=len(content)
    )
    return (
        leaf,
        content,
        dict(
            evidence_root=tmp_path,
            expected_binding=binding,
            absolute_deadline=time.monotonic() + 30,
        ),
    )


@pytest.fixture
def descriptors(monkeypatch):
    opened, closed = set(), []
    actual_open, actual_dup, actual_close = os.open, os.dup, os.close

    def track_open(*args, **kwargs):
        descriptor = actual_open(*args, **kwargs)
        opened.add(descriptor)
        return descriptor

    def track_dup(*args, **kwargs):
        descriptor = actual_dup(*args, **kwargs)
        opened.add(descriptor)
        return descriptor

    def track_close(descriptor):
        actual_close(descriptor)
        if descriptor in opened:
            opened.remove(descriptor)
            closed.append(descriptor)

    monkeypatch.setattr(evidence.os, "open", track_open)
    monkeypatch.setattr(evidence.os, "dup", track_dup)
    monkeypatch.setattr(evidence.os, "close", track_close)
    yield opened, closed
    assert not opened, "invariant: every owned evidence descriptor must be closed"


@pytest.mark.parametrize("repeat", [0, 1, 20000])
def test_exact_read_authenticates_before_bounded_complete_consumption(
    tmp_path, monkeypatch, descriptors, repeat
):
    content = LAYER_FIXTURE.read_bytes() * repeat
    leaf, _, kwargs = case_inputs(tmp_path, content)
    original_read, sizes, read_bytes = evidence.os.read, [], []

    def tracked(descriptor, size):
        sizes.append(size)
        chunk = original_read(descriptor, size)
        read_bytes.append(len(chunk))
        return chunk

    monkeypatch.setattr(evidence.os, "read", tracked)
    with evidence.stream_file_evidence(**kwargs) as chunks:
        assert sum(read_bytes) == len(content), "raw authentication must precede consumer access"
        parts = list(chunks)
        assert b"".join(parts) == content
    assert sum(read_bytes) == 2 * len(content)
    assert max(sizes) <= evidence._READ_CHUNK_BYTES
    assert leaf.read_bytes() == content
    assert list(chunks) == []
    assert not descriptors[0]


@pytest.mark.parametrize("change", ["digest", "size", "oversized", "mapping", "path"])
def test_invalid_expected_binding_never_yields(tmp_path, change, descriptors):
    _, _, kwargs = case_inputs(tmp_path)
    expected = kwargs["expected_binding"]
    if change == "mapping":
        kwargs["expected_binding"] = expected.model_dump()
    else:
        fields = {
            "digest": {"sha256": "a" * 64},
            "size": {"size": expected.size + 1},
            "oversized": {"size": evidence.MAX_STREAMED_EVIDENCE_BYTES + 1},
            "path": {"path": "../blob"},
        }
        object.__setattr__(
            expected, next(iter(fields[change])), next(iter(fields[change].values()))
        )
    with pytest.raises(ValueError), evidence.stream_file_evidence(**kwargs):
        pytest.fail("invalid raw binding was yielded")


@pytest.mark.parametrize(
    "deadline", [True, None, "30", float("nan"), float("inf"), -1.0, 0.0, 10**30]
)
def test_invalid_or_unbounded_deadline_refuses_before_open(tmp_path, monkeypatch, deadline):
    _, _, kwargs = case_inputs(tmp_path)
    kwargs["absolute_deadline"] = deadline
    monkeypatch.setattr(
        evidence, "_open_root", lambda _: pytest.fail("invalid deadline opened input")
    )
    with pytest.raises(ValueError), evidence.stream_file_evidence(**kwargs):
        pytest.fail("invalid deadline was yielded")


@pytest.mark.parametrize("replacement", ["symlink", "hardlink", "fifo", "directory", "missing"])
def test_unsafe_input_types_refuse_before_yield(tmp_path, replacement, descriptors):
    leaf, content, kwargs = case_inputs(tmp_path)
    target = tmp_path / "synthetic-control"
    target.write_bytes(content)
    leaf.unlink()
    if replacement == "symlink":
        leaf.symlink_to(target)
    elif replacement == "hardlink":
        os.link(target, leaf)
    elif replacement == "fifo":
        os.mkfifo(leaf)
    elif replacement == "directory":
        leaf.mkdir()
    with pytest.raises(ValueError), evidence.stream_file_evidence(**kwargs):
        pytest.fail("unsafe file was yielded")
    assert target.read_bytes() == content


@pytest.mark.parametrize("phase", ["before-consume", "after-consume"])
@pytest.mark.parametrize(
    "mutation", ["content", "replace", "fifo", "mode", "parent", "parent-mode", "root"]
)
def test_stream_custody_rejects_drift_without_opening_a_replacement_fifo(
    tmp_path, descriptors, phase, mutation
):
    root = tmp_path / "private"
    root.mkdir()
    leaf, content, kwargs = case_inputs(root)
    if mutation in {"parent", "parent-mode"}:
        nested = root / "nested"
        nested.mkdir()
        leaf.rename(nested / "blob")
        leaf = nested / "blob"
        kwargs["expected_binding"] = kwargs["expected_binding"].model_copy(
            update={"path": "nested/blob"}
        )
    with pytest.raises(ValueError), evidence.stream_file_evidence(**kwargs) as chunks:
        if phase == "after-consume":
            assert b"".join(chunks) == content
        if mutation == "content":
            leaf.write_bytes(b"x" * len(content))
        elif mutation == "replace":
            leaf.unlink()
            leaf.write_bytes(content)
        elif mutation == "fifo":
            leaf.unlink()
            os.mkfifo(leaf)
        elif mutation == "mode":
            leaf.chmod(0o400)
        elif mutation == "parent":
            leaf.parent.rename(root / "moved")
            (root / "nested").mkdir()
            (root / "nested/blob").write_bytes(content)
        elif mutation == "parent-mode":
            leaf.parent.chmod(0o700)
        else:
            root.rename(tmp_path / "moved")
        if phase == "before-consume":
            list(chunks)


@pytest.mark.parametrize("consumed", [False, True])
def test_early_exit_closes_iterator_and_rejects_partial_result(tmp_path, descriptors, consumed):
    _, _, kwargs = case_inputs(tmp_path)
    with (
        pytest.raises(ValueError, match="completely consumed"),
        evidence.stream_file_evidence(**kwargs) as chunks,
    ):
        if consumed:
            next(chunks)  # Even the last chunk needs a subsequent EOF/hash check.
    assert list(chunks) == []


@pytest.mark.parametrize("exception", [RuntimeError, OSError, KeyboardInterrupt, SystemExit])
def test_original_consumer_error_or_interrupt_survives_and_closes_every_descriptor(
    tmp_path, exception, descriptors
):
    _, _, kwargs = case_inputs(tmp_path)
    primary = exception("synthetic primary")
    with pytest.raises(exception) as error, evidence.stream_file_evidence(**kwargs) as chunks:
        next(chunks)
        raise primary
    assert error.value is primary
    assert list(chunks) == []


@pytest.mark.parametrize("phase", ["authentication", "consumption", "context-exit"])
def test_shared_deadline_refuses_late_reads_and_results(tmp_path, monkeypatch, descriptors, phase):
    _, _, kwargs = case_inputs(tmp_path)
    now = [100.0]
    kwargs["absolute_deadline"] = 110.0
    monkeypatch.setattr(evidence.time, "monotonic", lambda: now[0])
    if phase == "authentication":
        original = evidence.os.read

        def expired(*args):
            result = original(*args)
            now[0] = 111.0
            return result

        monkeypatch.setattr(evidence.os, "read", expired)
    with (
        pytest.raises(ValueError, match="deadline"),
        evidence.stream_file_evidence(**kwargs) as chunks,
    ):
        if phase == "context-exit":
            list(chunks)
        now[0] = 111.0
        if phase == "consumption":
            list(chunks)


def test_file_open_is_nonblocking_against_stat_to_fifo_substitution(
    tmp_path, monkeypatch, descriptors
):
    leaf, _, kwargs = case_inputs(tmp_path)
    original = evidence.os.open

    def replace(name, flags, *args, **options):
        if name == leaf.name:
            assert flags & os.O_NONBLOCK
            leaf.unlink()
            os.mkfifo(leaf)
        return original(name, flags, *args, **options)

    monkeypatch.setattr(evidence.os, "open", replace)
    with pytest.raises(ValueError, match="changed before"), evidence.stream_file_evidence(**kwargs):
        pytest.fail("replaced FIFO was yielded")


@pytest.mark.parametrize("primary_error", [False, True])
def test_close_failure_does_not_skip_other_descriptors_or_mask_primary(
    tmp_path, monkeypatch, descriptors, primary_error
):
    _, _, kwargs = case_inputs(tmp_path)
    original = evidence.os.close
    armed = [None]

    def fail_after_close(descriptor):
        original(descriptor)
        if armed[0] == descriptor:
            armed[0] = None
            raise OSError("synthetic close report")

    monkeypatch.setattr(evidence.os, "close", fail_after_close)
    primary = RuntimeError("synthetic primary")
    with (
        pytest.raises(RuntimeError if primary_error else ValueError) as error,
        evidence.stream_file_evidence(**kwargs) as chunks,
    ):
        list(chunks)
        armed[0] = next(fd for fd in descriptors[0] if stat.S_ISREG(os.fstat(fd).st_mode))
        if primary_error:
            raise primary
    if primary_error:
        assert error.value is primary


def test_late_final_descriptor_close_cannot_return_success(tmp_path, monkeypatch, descriptors):
    _, _, kwargs = case_inputs(tmp_path)
    now = [100.0]
    kwargs["absolute_deadline"] = 110.0
    monkeypatch.setattr(evidence.time, "monotonic", lambda: now[0])
    actual = evidence.os.close

    def late_close(descriptor):
        actual(descriptor)
        if not descriptors[0]:
            now[0] = 111.0

    monkeypatch.setattr(evidence.os, "close", late_close)
    with (
        pytest.raises(ValueError, match="deadline"),
        evidence.stream_file_evidence(**kwargs) as chunks,
    ):
        list(chunks)
