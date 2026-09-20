"""One source-custody guard shares pure replay work, never actual file or root checks."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest

from mmaudit.models import development_corpus as models
from mmaudit.repository import development_corpus as module
from tests.integration.test_development_partition_custody import bundle


def test_one_guard_parses_each_exact_original_manifest_once_with_four_fresh_reads(
    tmp_path, monkeypatch
):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    content = reference.manifest_file.read_bytes()
    original_parse = models.DevelopmentCorpusManifest.model_validate_json
    original_read = module.read_json_evidence
    parses = []
    reads = []

    def parse(value, **kwargs):
        if value == content:
            parses.append(value)
            assert kwargs == {"strict": True}
        return original_parse(value, **kwargs)

    def read(**kwargs):
        if kwargs["evidence_root"] == reference.manifest_file.parent:
            reads.append(kwargs["relative_path"])
        return original_read(**kwargs)

    monkeypatch.setattr(models.DevelopmentCorpusManifest, "model_validate_json", parse)
    monkeypatch.setattr(module, "read_json_evidence", read)
    for _ in range(2):
        parses.clear()
        reads.clear()
        module.revalidate_loaded_development_corpus(loaded)
        assert reads == [reference.manifest_file.name] * 4
        assert parses == [content]


def test_manifest_replay_is_bounded_and_keyed_by_exact_raw_bytes(tmp_path):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    content = reference.manifest_file.read_bytes()
    replayed = {}
    original = module._replay_manifest(content, replayed)
    assert original == reference.material.manifest
    assert original is not reference.material.manifest
    assert module._replay_manifest(bytes(bytearray(content)), replayed) is original
    assert len(replayed) == 1
    derived = loaded.manifest_file.read_bytes()
    assert module._replay_manifest(derived, replayed) == loaded.material.manifest
    assert len(replayed) == 2
    # Even semantically equivalent text is a different input, never a digest-only hit.
    with pytest.raises(ValueError, match="original/derived manifest bound"):
        module._replay_manifest(content + b"\n", replayed)
    assert len(replayed) == 2
    assert module._replay_manifest(content, replayed) is original


@pytest.mark.parametrize("mutation", ["malformed", "strict_boolean", "unknown_field", "digest"])
def test_invalid_manifest_never_populates_or_hits_the_pure_replay_cache(tmp_path, mutation):
    reference, _, _ = bundle(tmp_path, ("src/IReserve.sol",))
    content = reference.manifest_file.read_bytes()
    replayed = {}
    valid = module._replay_manifest(content, replayed)
    value = json.loads(content)
    if mutation == "malformed":
        changed = content.rstrip()[:-1]
    else:
        if mutation == "strict_boolean":
            value["total_source_bytes"] = True
        elif mutation == "unknown_field":
            value["unselected_field"] = "synthetic"
        else:
            value["manifest_sha256"] = "0" * 64
        changed = json.dumps(value).encode()
    with pytest.raises(ValueError):
        module._replay_manifest(changed, replayed)
    assert replayed == {content: valid}


@pytest.mark.parametrize("content", [b"", "{}", bytearray(b"{}"), memoryview(b"{}"), None])
def test_manifest_replay_requires_nonempty_bounded_immutable_bytes(content):
    with pytest.raises(ValueError, match="bounded immutable manifest bytes"):
        module._replay_manifest(content, {})


def test_manifest_replay_refuses_oversized_bytes_before_parsing(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("oversized manifest reached the parser")

    monkeypatch.setattr(models.DevelopmentCorpusManifest, "model_validate_json", forbidden)
    with pytest.raises(ValueError, match="bounded immutable manifest bytes"):
        module._replay_manifest(b" " * (models.MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES + 1), {})


def test_one_derived_guard_recomputes_original_material_once_but_keeps_every_live_read(
    tmp_path, monkeypatch
):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    original_validation = models.validate_development_corpus_sources
    original_read = module.revalidate_evidence_file_bindings
    semantic_replays = []
    live_reads = []

    def validate(manifest, source_files):
        if manifest.source_origin is None:
            semantic_replays.append(manifest.manifest_sha256)
        return original_validation(manifest, source_files)

    def read(**kwargs):
        if kwargs["evidence_root"] == reference.corpus_root:
            live_reads.extend(binding.path for binding in kwargs["bindings"])
        return original_read(**kwargs)

    monkeypatch.setattr(models, "validate_development_corpus_sources", validate)
    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", read)
    expected_reads = tuple(binding.path for binding in reference.source_bindings) * 4
    for _ in range(2):
        semantic_replays.clear()
        live_reads.clear()
        module.revalidate_loaded_development_corpus(loaded)
        assert tuple(live_reads) == expected_reads
        assert semantic_replays == [reference.material.manifest.manifest_sha256]


def test_material_replay_uses_exact_content_and_never_only_a_declared_digest(tmp_path):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    replayed = {}
    original = module._replay_material(reference.material, replayed)
    assert module._replay_material(deepcopy(reference.material), replayed) is original
    assert len(replayed) == 1
    first, *rest = reference.material.sources
    changed = reference.material.model_copy(
        update={"sources": (first.model_copy(update={"content": first.content + "\n"}), *rest)}
    )
    assert changed.manifest.manifest_sha256 == reference.material.manifest.manifest_sha256
    with pytest.raises(ValueError):
        module._replay_material(changed, replayed)
    assert len(replayed) == 1
    assert module._replay_material(loaded.material, replayed) == loaded.material
    assert len(replayed) == 2
    with pytest.raises(ValueError, match="original/derived material bound"):
        module._replay_material(changed, replayed)
    assert len(replayed) == 2
