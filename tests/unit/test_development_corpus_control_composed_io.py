"""Explicit prebound composed I/O never widens ordinary evidence or implicit custody profiles."""

from __future__ import annotations

import hashlib

import pytest

import mmaudit.release_io as release_io
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.repository.file_custody import (
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)


def prepared(tmp_path):
    path = tmp_path / "synthetic.json"
    content = b'{"synthetic": true}'
    path.write_bytes(content)
    return path, ManifestFileBinding(
        path=path.name, size=len(content), sha256=hashlib.sha256(content).hexdigest()
    )


def read(path, binding, *, maximum=128_000_000):
    return release_io.read_composed_file_evidence(
        evidence_root=path.parent,
        relative_path=path.name,
        expected_binding=binding,
        max_bytes=maximum,
    )


def test_standard_profiles_refuse_composed_limit_and_explicit_prebound_custody_succeeds(tmp_path):
    path, binding = prepared(tmp_path)
    with pytest.raises(ValueError):
        release_io.read_file_evidence(
            evidence_root=path.parent, relative_path=path.name, max_bytes=128_000_000
        )
    with pytest.raises(ValueError):
        release_io.write_json_evidence(
            evidence_root=tmp_path, relative_path="new.json", value={}, max_bytes=128_000_000
        )
    with pytest.raises(ValueError):
        observe_regular_file_custody(
            root=tmp_path,
            relative_path=path.name,
            label="synthetic",
            max_bytes=128_000_000,
            expected_binding=binding,
        )
    assert read(path, binding).content == path.read_bytes()
    expected = observe_regular_file_custody(
        root=tmp_path,
        relative_path=path.name,
        label="synthetic",
        max_bytes=128_000_000,
        expected_binding=binding,
        allow_composed_evidence=True,
    )
    require_regular_file_custody_unchanged(
        expected, label="synthetic", max_bytes=128_000_000, allow_composed_evidence=True
    )
    assert release_io.DEFAULT_MAX_EVIDENCE_BYTES == 100_000_000
    assert release_io.MAX_COMPOSED_EVIDENCE_BYTES == 256_000_000


@pytest.mark.parametrize(
    "maximum", [None, True, False, 0, -1, 256_000_001, "128000000", 128_000_000.0]
)
def test_composed_read_requires_exact_positive_integer_within_composed_ceiling(tmp_path, maximum):
    path, binding = prepared(tmp_path)
    with pytest.raises(ValueError):
        read(path, binding, maximum=maximum)


@pytest.mark.parametrize(
    "kind", ["missing", "mapping", "hash", "size", "path", "too_small", "growth"]
)
def test_composed_read_never_discovers_or_rebases_a_different_file_binding(tmp_path, kind):
    path, binding = prepared(tmp_path)
    maximum = 128_000_000
    if kind == "missing":
        binding = None
    elif kind == "mapping":
        binding = binding.model_dump()
    elif kind == "too_small":
        maximum = binding.size - 1
    elif kind == "growth":
        path.write_bytes(path.read_bytes() + b" ")
    else:
        key, value = {
            "hash": ("sha256", "0" * 64),
            "size": ("size", binding.size + 1),
            "path": ("path", "unselected.json"),
        }[kind]
        binding = binding.model_copy(update={key: value})
    with pytest.raises(ValueError):
        read(path, binding, maximum=maximum)


@pytest.mark.parametrize("flag", [None, 0, 1, "true", [], {}])
def test_composed_file_custody_profile_requires_an_exact_boolean(tmp_path, flag):
    path, binding = prepared(tmp_path)
    expected = observe_regular_file_custody(
        root=tmp_path, relative_path=path.name, label="synthetic"
    )
    with pytest.raises(ValueError):
        observe_regular_file_custody(
            root=tmp_path,
            relative_path=path.name,
            label="synthetic",
            expected_binding=binding,
            allow_composed_evidence=flag,
        )
    with pytest.raises(ValueError):
        require_regular_file_custody_unchanged(
            expected, label="synthetic", allow_composed_evidence=flag
        )


def test_composed_file_custody_requires_a_binding_even_for_small_content(tmp_path):
    path, _ = prepared(tmp_path)
    with pytest.raises(ValueError):
        observe_regular_file_custody(
            root=tmp_path, relative_path=path.name, label="synthetic", allow_composed_evidence=True
        )


def test_composed_read_rejects_changed_observations_between_descriptor_reads(tmp_path, monkeypatch):
    path, binding = prepared(tmp_path)
    original = release_io._read_file_once
    calls = 0

    def changed(**kwargs):
        nonlocal calls
        result = original(**kwargs)
        calls += 1
        if calls == 1:
            path.write_bytes(b'{"synthetic":false}')
        return result

    monkeypatch.setattr(release_io, "_read_file_once", changed)
    with pytest.raises(ValueError):
        read(path, binding)
