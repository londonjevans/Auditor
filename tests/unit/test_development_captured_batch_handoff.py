"""Captured-tree delegation keeps original bounds and propagates each failed guard."""

from __future__ import annotations

import hashlib

import pytest

from mmaudit.models.development_corpus import DevelopmentCorpusMaterial, DevelopmentCorpusText
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import FileEvidenceObservation
from mmaudit.repository import development_corpus_tree as module
from mmaudit.repository.directory_custody import DirectoryCustodyObservation
from tests.unit.test_development_corpus_tree_models import tree_manifest
from tests.unit.test_development_dependency_targets import target_sources


@pytest.fixture
def captured(tmp_path, monkeypatch):
    manifest = tree_manifest()
    material = DevelopmentCorpusMaterial(
        manifest=manifest,
        sources=tuple(
            DevelopmentCorpusText(filename=path, content=raw.decode())
            for path, raw in target_sources()
        ),
    )
    root = tmp_path / "uncreated-unit-source"
    observation = module.DevelopmentCorpusTreeObservation(
        root=root,
        sources=tuple(s.filename for s in manifest.sources),
        directories=manifest.source_tree_evidence.directories,
        non_source_file_count=0,
        node_identities=(),
        root_custody=DirectoryCustodyObservation(root, ()),
    )
    raw = manifest.dependency_evidence.remapping_text.encode()
    binding = ManifestFileBinding(
        path="remappings.txt", sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)
    )
    value = module.CapturedDevelopmentCorpusTree(
        material=material,
        observation=observation,
        source_bindings=tuple(
            ManifestFileBinding(path=s.filename, sha256=s.sha256, size=s.size)
            for s in manifest.sources
        ),
        remappings_file=tmp_path / "remappings.txt",
        remappings_binding=binding,
    )
    monkeypatch.setattr(module, "revalidate_development_corpus_tree", lambda *_: None)
    monkeypatch.setattr(
        module, "read_file_evidence", lambda **_: FileEvidenceObservation(raw, binding)
    )
    return value


@pytest.mark.parametrize("bound", [1, 262_144, 8_388_608])
def test_captured_handoff_forwards_current_ceiling_without_raising_it(captured, monkeypatch, bound):
    calls = []
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_CORPUS_FILE_BYTES", bound)

    def batch(**kwargs):
        calls.append(kwargs)
        assert kwargs["bindings"] is captured.source_bindings
        return captured.source_bindings

    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", batch)
    module.revalidate_captured_development_corpus_tree(captured)
    assert calls == [
        dict(
            evidence_root=captured.observation.root,
            bindings=captured.source_bindings,
            max_bytes=bound,
        )
    ]


def test_captured_batch_failure_stops_before_remapping_observation(captured, monkeypatch):
    def refused(**_kwargs):
        raise ValueError("synthetic batch refusal")

    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", refused)
    monkeypatch.setattr(
        module, "read_file_evidence", lambda **_: pytest.fail("failed batch reached remappings")
    )
    with pytest.raises(ValueError, match="synthetic batch refusal"):
        module.revalidate_captured_development_corpus_tree(captured)


def test_captured_namespace_failure_stops_before_source_batch(captured, monkeypatch):
    def refused(*_args):
        raise ValueError("synthetic namespace refusal")

    monkeypatch.setattr(module, "revalidate_development_corpus_tree", refused)
    monkeypatch.setattr(
        module,
        "revalidate_evidence_file_bindings",
        lambda **_: pytest.fail("failed namespace reached source batch"),
    )
    with pytest.raises(ValueError, match="synthetic namespace refusal"):
        module.revalidate_captured_development_corpus_tree(captured)
