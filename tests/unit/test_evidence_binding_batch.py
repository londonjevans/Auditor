"""Descriptor reuse preserves every selected source read and refuses local path drift."""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace

import pytest

from mmaudit import release_io as module
from mmaudit.orchestration.manifest import ManifestFileBinding


@pytest.fixture
def inputs(tmp_path):
    root = tmp_path / "owner" / "sources"
    root.mkdir(parents=True)
    bindings = []
    for name in ("A.sol", "nested/B.sol", "nested/C.sol"):
        path = root / name
        path.parent.mkdir(exist_ok=True)
        content = ("// synthetic non-deployable source: " + name).encode()
        path.write_bytes(content)
        bindings.append(
            ManifestFileBinding(
                path=name, sha256=hashlib.sha256(content).hexdigest(), size=len(content)
            )
        )
    return root, tuple(bindings)


def verify(inputs, **kwargs):
    root, bindings = inputs
    return module.revalidate_evidence_file_bindings(
        evidence_root=root, bindings=bindings, max_bytes=1024, **kwargs
    )


def test_batch_reuses_only_root_descriptor_and_reads_every_file_twice(inputs, monkeypatch):
    original_open = module._open_root
    original_read = module._read_file_at_parent
    roots, reads = [], []

    def opened(path):
        result = original_open(path)
        roots.append(result)
        return result

    def read(**kwargs):
        reads.append(kwargs["leaf"])
        return original_read(**kwargs)

    monkeypatch.setattr(module, "_open_root", opened)
    monkeypatch.setattr(module, "_read_file_at_parent", read)
    for invocation in range(1, 3):
        result = verify(inputs)
        assert result == inputs[1]
        assert all(a is not b for a, b in zip(result, inputs[1], strict=True))
        assert len(roots) == invocation
        assert reads == ["A.sol", "A.sol", "B.sol", "B.sol", "C.sol", "C.sol"] * invocation
        with pytest.raises(OSError):
            os.fstat(roots[-1].descriptor)


def test_batch_matches_unchanged_single_binding_api(inputs):
    root, bindings = inputs
    assert verify(inputs) == tuple(
        module.revalidate_evidence_file_binding(evidence_root=root, binding=b, max_bytes=1024)
        for b in bindings
    )


def test_empty_batch_does_not_open_a_root(inputs, monkeypatch):
    monkeypatch.setattr(module, "_open_root", lambda *_: pytest.fail("empty batch opened root"))
    assert verify((inputs[0], ())) == ()


@pytest.mark.parametrize("bindings", [None, [], {}, "source", (None,)])
def test_batch_refuses_nonexact_input_before_io(inputs, monkeypatch, bindings):
    monkeypatch.setattr(module, "_open_root", lambda *_: pytest.fail("invalid batch opened root"))
    with pytest.raises(ValueError):
        verify((inputs[0], bindings))


@pytest.mark.parametrize(
    "kind", ["duplicate", "count", "size", "path", "hash", "bool_size", "normalized_path"]
)
def test_batch_refuses_unbounded_or_invalid_bindings_before_io(inputs, monkeypatch, kind):
    root, bindings = inputs
    first = bindings[0]
    if kind == "duplicate":
        selected = (first, first)
    elif kind == "count":
        selected = (first,) * 8193
    else:
        field, value = {
            "size": ("size", 1025),
            "path": ("path", "../outside.sol"),
            "hash": ("sha256", "invalid"),
            "bool_size": ("size", True),
            "normalized_path": ("path", "nested/./B.sol"),
        }[kind]
        selected = (first.model_copy(update={field: value}),)
    monkeypatch.setattr(module, "_open_root", lambda *_: pytest.fail("invalid batch opened root"))
    with pytest.raises(ValueError):
        verify((root, selected))


@pytest.mark.parametrize("bound", [0, -1, True, 1.5, "1024", None, 100_000_001])
def test_batch_preserves_existing_byte_bound(inputs, bound):
    with pytest.raises(ValueError):
        module.revalidate_evidence_file_bindings(
            evidence_root=inputs[0], bindings=inputs[1], max_bytes=bound
        )


@pytest.mark.parametrize("kind", ["bytes", "missing", "directory", "link", "hardlink", "fifo"])
def test_batch_rejects_changed_or_unsafe_source(inputs, kind):
    root, _ = inputs
    path = root / "nested/B.sol"
    held = root / "retained.sol"
    path.rename(held)
    if kind == "bytes":
        path.write_bytes(b"changed")
    elif kind == "directory":
        path.mkdir()
    elif kind == "link":
        path.symlink_to(held)
    elif kind == "hardlink":
        os.link(held, path)
    elif kind == "fifo":
        os.mkfifo(path)
    with pytest.raises(ValueError):
        verify(inputs)


@pytest.mark.parametrize("kind", ["bytes", "inode", "mode", "link", "hardlink", "missing"])
def test_every_source_is_reopened_and_identity_checked_between_reads(inputs, monkeypatch, kind):
    root, _ = inputs
    path = root / "nested/B.sol"
    original = module._read_file_at_parent
    changed = False

    def read(**kwargs):
        nonlocal changed
        result = original(**kwargs)
        if kwargs["leaf"] == path.name and not changed:
            changed = True
            if kind == "bytes":
                path.write_bytes(b"drift" * 8)
            elif kind == "mode":
                path.chmod(0o600)
            elif kind == "hardlink":
                os.link(path, root / "alias.sol")
            else:
                retained = root / "retained.sol"
                path.rename(retained)
                if kind == "inode":
                    path.write_bytes(result.content)
                elif kind == "link":
                    path.symlink_to(retained)
        return result

    monkeypatch.setattr(module, "_read_file_at_parent", read)
    with pytest.raises(ValueError):
        verify(inputs)
    assert changed


@pytest.mark.parametrize("hit", [1, 2, 3, 6])
@pytest.mark.parametrize("kind", ["root", "ancestor", "root_mode", "ancestor_mode", "root_link"])
def test_held_root_requires_live_unchanged_lexical_ancestry_after_each_read(
    inputs, monkeypatch, hit, kind
):
    root, _ = inputs
    original = module._read_file_at_parent
    reads = 0

    def read(**kwargs):
        nonlocal reads
        result = original(**kwargs)
        reads += 1
        if reads == hit:
            selected = root.parent if kind.startswith("ancestor") else root
            if kind.endswith("mode"):
                selected.chmod(0o700)
            else:
                retained = selected.with_name("retained-" + selected.name)
                selected.rename(retained)
                if kind == "root_link":
                    selected.symlink_to(retained, target_is_directory=True)
                else:
                    selected.mkdir()
        return result

    monkeypatch.setattr(module, "_read_file_at_parent", read)
    with pytest.raises(ValueError):
        verify(inputs)
    assert reads == hit


def test_nested_parent_is_reopened_between_reads(inputs, monkeypatch):
    root, _ = inputs
    original = module._read_file_at_parent
    changed = False

    def read(**kwargs):
        nonlocal changed
        result = original(**kwargs)
        if kwargs["leaf"] == "B.sol" and not changed:
            changed = True
            parent = root / "nested"
            retained = root / "retained-parent"
            parent.rename(retained)
            parent.symlink_to(retained, target_is_directory=True)
        return result

    monkeypatch.setattr(module, "_read_file_at_parent", read)
    with pytest.raises(ValueError):
        verify(inputs)
    assert changed


@pytest.mark.parametrize("field", ["path", "sha256", "size"])
def test_expected_binding_mutation_cannot_change_the_selected_batch(inputs, monkeypatch, field):
    original = module._read_file_at_parent
    reads = 0

    def read(**kwargs):
        nonlocal reads
        result = original(**kwargs)
        reads += 1
        if reads == 6:
            value = {"path": "other.sol", "sha256": "0" * 64, "size": 1}[field]
            object.__setattr__(inputs[1][0], field, value)
        return result

    monkeypatch.setattr(module, "_read_file_at_parent", read)
    with pytest.raises(ValueError):
        verify(inputs)
    assert reads == 6


@pytest.mark.parametrize("failure", [ValueError, OSError, KeyboardInterrupt])
def test_batch_releases_root_on_every_exception(inputs, monkeypatch, failure):
    original = module._open_root
    roots = []

    def opened(path):
        result = original(path)
        roots.append(result)
        return result

    def fail(**_kwargs):
        raise failure("synthetic interrupted read")

    monkeypatch.setattr(module, "_open_root", opened)
    monkeypatch.setattr(module, "_read_file_at_parent", fail)
    expected = ValueError if failure is OSError else failure
    with pytest.raises(expected, match=r"synthetic|safely"):
        verify(inputs)
    assert len(roots) == 1
    with pytest.raises(OSError):
        os.fstat(roots[0].descriptor)


def test_batch_never_reuses_an_earlier_successful_observation(inputs):
    assert verify(inputs) == inputs[1]
    (inputs[0] / "nested/C.sol").write_bytes(b"changed after prior batch")
    with pytest.raises(ValueError):
        verify(inputs)


def test_equal_bytes_with_different_read_identity_are_rejected(inputs, monkeypatch):
    original = module._read_file_at_parent
    reads = 0

    def read(**kwargs):
        nonlocal reads
        result = original(**kwargs)
        reads += 1
        if reads == 2:
            identity = (*result.identity[:1], result.identity[1] + 1, *result.identity[2:])
            return replace(result, identity=identity)
        return result

    monkeypatch.setattr(module, "_read_file_at_parent", read)
    with pytest.raises(ValueError):
        verify(inputs)


def test_unavailable_safe_descriptor_support_refuses_before_reads(inputs, monkeypatch):
    monkeypatch.setattr(module, "_NONBLOCK_FLAG", 0)
    monkeypatch.setattr(module, "_open_root", lambda *_: pytest.fail("unsafe batch opened root"))
    with pytest.raises(ValueError):
        verify(inputs)
