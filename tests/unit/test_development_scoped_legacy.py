"""Exact synthetic legacy bytes from the SHA-verified pre-scoped implementation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mmaudit.models.development_corpus import (
    freeze_development_corpus,
    render_development_corpus_sources,
)
from tests.unit.test_development_corpus_tree_models import tree_receipt
from tests.unit.test_development_dependency_targets import target_sources


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.2", "1.3"])
def test_pre_scoped_manifest_witness_and_every_primary_prompt_keep_their_exact_bytes(version):
    golden = json.loads(
        (
            Path(__file__).parents[1] / "fixtures/solidity/dependency_scopes/legacy_replay.json"
        ).read_bytes()
    )
    sources = target_sources()
    assert {name: hashlib.sha256(raw).hexdigest() for name, raw in sources} == golden[
        "source_sha256s"
    ]
    options = {}
    if version != "1.0":
        options["dependency_remapping_text"] = golden["remapping_text"]
    if version in {"1.2", "1.3"}:
        options["dependency_target_context"] = True
    if version == "1.3":
        options["source_tree_evidence"] = tree_receipt()
    manifest = freeze_development_corpus(
        corpus_id=golden["corpus_id"],
        source_scope=golden["source_scope"],
        source_files=sources,
        **options,
    )
    expected = golden["artifacts"][version]
    assert manifest.schema_version == version
    assert (
        hashlib.sha256(manifest.model_dump_json().encode()).hexdigest()
        == expected["manifest_sha256"]
    )
    if manifest.dependency_evidence is not None:
        assert manifest.dependency_evidence.scoped_context is None
        assert "scoped_context" not in manifest.dependency_evidence.model_dump(mode="json")
        assert (
            hashlib.sha256(manifest.dependency_evidence.model_dump_json().encode()).hexdigest()
            == expected["witness_sha256"]
        )
    else:
        assert expected["witness_sha256"] is None
    assert {
        name: hashlib.sha256(
            render_development_corpus_sources(manifest, sources, name).encode()
        ).hexdigest()
        for name, _ in sources
    } == expected["prompt_sha256s"]
