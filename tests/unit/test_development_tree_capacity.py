"""Evidence capacity expands without changing source, cost, graph-work or legacy defaults."""

from __future__ import annotations

import pytest

from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_BYTES,
    MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    MAX_DEVELOPMENT_CORPUS_FILES,
    MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES,
    freeze_development_corpus,
)
from mmaudit.models.development_corpus_partition import MAX_DEVELOPMENT_PARTITION_BYTES
from mmaudit.solidity import dependency_closure as closure
from mmaudit.solidity.dependency_targets import (
    MAX_TARGET_CONTEXT_BYTES,
    MAX_TARGET_RECORDS,
    MAX_TARGET_WORK,
)
from tests.development_tree_capacity_support import capacity_source


def test_corpus_and_graph_work_limits_are_unchanged_while_evidence_is_bounded_to_match():
    assert (MAX_DEVELOPMENT_CORPUS_FILES, MAX_DEVELOPMENT_CORPUS_FILE_BYTES) == (256, 262_144)
    assert MAX_DEVELOPMENT_CORPUS_BYTES == 8_388_608
    assert (MAX_TARGET_RECORDS, MAX_TARGET_WORK, closure.MAX_DEPENDENCY_TOKENS) == (
        4096,
        1_000_000,
        131_072,
    )
    assert MAX_TARGET_CONTEXT_BYTES == closure.MAX_DEPENDENCY_GRAPH_BYTES == 2_097_152
    assert closure.MAX_DEPENDENCY_WITNESS_BYTES == 4_194_304
    assert MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES == 8_388_608
    assert MAX_DEVELOPMENT_PARTITION_BYTES == MAX_DEVELOPMENT_CORPUS_MANIFEST_BYTES + 4096


def test_unselected_graph_budget_preserves_legacy_default_and_selected_budget_is_recorded():
    files = (("Source.sol", capacity_source(0)),)
    old = closure.compute_development_dependency_closure(source_files=files)
    new = closure.compute_development_dependency_closure(
        source_files=files, graph_artifact_byte_limit=closure.MAX_DEPENDENCY_GRAPH_BYTES
    )
    assert old.graph_artifact_byte_limit == closure.LEGACY_DEPENDENCY_GRAPH_BYTES == 393_216
    assert new.graph_artifact_byte_limit == 2_097_152
    assert old.graph_sha256 != new.graph_sha256 and old.witness_sha256 != new.witness_sha256
    assert old.graph_facts == new.graph_facts
    assert old.graph_generation_complete and new.graph_generation_complete


@pytest.mark.parametrize("limit", [0, 1023, True, 1024.0, 2_097_153])
def test_invalid_graph_budget_refuses_before_graph_work(monkeypatch, limit):
    monkeypatch.setattr(closure, "build_solidity_graphs", lambda *_a, **_k: pytest.fail())
    with pytest.raises(ValueError, match="graph artifact bound"):
        closure.compute_development_dependency_closure(
            source_files=(("Source.sol", capacity_source(0)),), graph_artifact_byte_limit=limit
        )


def test_graph_budget_cannot_be_silently_ignored_without_static_closure():
    with pytest.raises(ValueError, match="requires computed static closure"):
        freeze_development_corpus(
            corpus_id="synthetic-capacity-refusal",
            source_scope="OPERATOR_SUPPLIED_PROTOCOL",
            source_files=(("Source.sol", capacity_source(0)),),
            dependency_graph_byte_limit=2_097_152,
        )
