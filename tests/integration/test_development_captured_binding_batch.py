"""Captured-tree batching preserves complete fresh source, namespace and remapping checks."""

from __future__ import annotations

import stat
from dataclasses import replace

import pytest

from mmaudit import release_io
from mmaudit.repository import development_corpus_tree as module
from tests.integration.test_development_corpus_tree import capture, tree_case
from tests.integration.test_development_corpus_tree import (
    no_external_execution as no_external_execution,
)

pytestmark = pytest.mark.usefixtures("no_external_execution")


def test_captured_tree_replays_one_complete_batch_between_both_namespace_checks(
    tmp_path, monkeypatch
):
    case = tree_case(tmp_path)
    captured = capture(case)
    original_batch = module.revalidate_evidence_file_bindings
    original_namespace = module.revalidate_development_corpus_tree
    original_read = release_io._read_file_at_root
    original_remappings = module.read_file_evidence
    events, reads = [], []

    def batch(**kwargs):
        assert kwargs == dict(
            evidence_root=captured.observation.root,
            bindings=captured.source_bindings,
            max_bytes=module.MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
        )
        events.append("all-sources")
        return original_batch(**kwargs)

    def namespace(*args):
        events.append("namespace")
        return original_namespace(*args)

    def read(**kwargs):
        if kwargs["root"].path == captured.observation.root:
            reads.append(kwargs["relative_path"])
        return original_read(**kwargs)

    def remappings(**kwargs):
        assert kwargs["relative_path"] == "remappings.txt"
        events.append("remappings")
        return original_remappings(**kwargs)

    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", batch)
    monkeypatch.setattr(module, "revalidate_development_corpus_tree", namespace)
    monkeypatch.setattr(release_io, "_read_file_at_root", read)
    monkeypatch.setattr(module, "read_file_evidence", remappings)
    expected = tuple(binding.path for binding in captured.source_bindings)
    for _ in range(2):
        events.clear()
        reads.clear()
        module.revalidate_captured_development_corpus_tree(captured)
        assert events == ["namespace", "all-sources", "remappings", "namespace"]
        assert reads == [path for path in expected for _ in range(2)]


@pytest.mark.parametrize(
    "kind",
    ["source_bytes", "source_inode", "added_entry", "metadata_bytes", "root_mode", "remappings"],
)
def test_mutation_after_captured_source_batch_cannot_pass_final_guards(tmp_path, monkeypatch, kind):
    case = tree_case(tmp_path)
    captured = capture(case)
    original_batch = module.revalidate_evidence_file_bindings
    calls = 0

    def batch(**kwargs):
        nonlocal calls
        result = original_batch(**kwargs)
        calls += 1
        root = captured.observation.root
        source = root / "src/InheritedReserve.sol"
        if kind == "source_bytes":
            source.write_bytes(source.read_bytes() + b"\n")
        elif kind == "source_inode":
            raw = source.read_bytes()
            source.rename(tmp_path / "retained-original-source.sol")
            source.write_bytes(raw)
        elif kind == "added_entry":
            (root / "added.txt").write_text("Synthetic namespace drift")
        elif kind == "metadata_bytes":
            (root / "README.txt").write_text("Changed synthetic metadata")
        elif kind == "root_mode":
            root.chmod(stat.S_IMODE(root.stat().st_mode) ^ stat.S_IXGRP)
        else:
            captured.remappings_file.write_text("@local/=changed/\n")
        return result

    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", batch)
    with pytest.raises(ValueError):
        module.revalidate_captured_development_corpus_tree(captured)
    assert calls == 1


@pytest.mark.parametrize("kind", ["omitted", "duplicated", "reordered", "changed_hash"])
def test_captured_binding_selection_must_match_material_before_batch_io(
    tmp_path, monkeypatch, kind
):
    captured = capture(tree_case(tmp_path))
    first, *rest = captured.source_bindings
    changed = {
        "omitted": tuple(rest),
        "duplicated": (first, first, *rest),
        "reordered": tuple(reversed(captured.source_bindings)),
        "changed_hash": (first.model_copy(update={"sha256": "0" * 64}), *rest),
    }[kind]

    def forbidden(**_kwargs):
        pytest.fail("changed captured source selection reached batch I/O")

    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", forbidden)
    with pytest.raises(ValueError, match="source bindings differ"):
        module.revalidate_captured_development_corpus_tree(
            replace(captured, source_bindings=changed)
        )
