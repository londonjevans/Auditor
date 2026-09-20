"""Actual local custody and full mocked ensemble handoff; no external execution."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace

import pytest

from mmaudit.models.development_corpus import DevelopmentCorpusMaterial
from mmaudit.repository.development_corpus import (
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    retained,
)
from tests.unit.test_development_dependency_closure import closed_manifest, fixture_sources


@pytest.fixture(autouse=True)
def prohibit_external_calls(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("dependency context test attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def load_case(tmp_path):
    source_root = tmp_path / "sources"
    source_root.mkdir(mode=0o700)
    sources = fixture_sources()
    for name, content in sources:
        path = source_root / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(content)
    manifest = closed_manifest(sources)
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(manifest.model_dump_json())
    return load_development_corpus(manifest_file=manifest_file, corpus_root=source_root)


@pytest.mark.parametrize("change", ["bytes", "removed", "symlink", "manifest"])
def test_real_local_loader_refuses_source_or_manifest_drift(tmp_path, change):
    loaded = load_case(tmp_path)
    target = loaded.corpus_root / "lib/Math.sol"
    if change == "bytes":
        target.write_bytes(target.read_bytes() + b"\n// Synthetic drift.\n")
    elif change == "removed":
        target.unlink()
    elif change == "symlink":
        original = target.read_bytes()
        target.unlink()
        outside = tmp_path / "other.sol"
        outside.write_bytes(original)
        target.symlink_to(outside)
    else:
        loaded.manifest_file.write_text(loaded.manifest_file.read_text() + "\n")
    with pytest.raises((OSError, ValueError)):
        revalidate_loaded_development_corpus(loaded)
    assert loaded.material.source_files == fixture_sources()


@pytest.mark.asyncio
async def test_exact_witness_and_complete_context_reach_candidate_and_both_reviewers(tmp_path):
    loaded = load_case(tmp_path)
    manifest = loaded.material.manifest
    prepared = manifest_ensemble_case(source_files=loaded.material.source_files, manifest=manifest)
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(role, ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert manifest.dependency_evidence.witness_sha256 in prompt
        assert "IMPORT_CLOSED" in prompt
        assert "COMPLETE_STATIC_TARGET_AND_IMPLEMENTER_RESOLUTION_UNAVAILABLE" in prompt
        assert "CALL_CLOSED" not in prompt
        assert all("Source file: " + p in prompt for p, _ in loaded.material.source_files)
        assert "return 0;" in prompt and "return 1;" in prompt

    result = await execute(case, custom=inspect)
    assert result == retained(case)
    assert case.counts == [5, 5, 5]
    assert result.status == "OBSERVED_ALL_STAGES"
    assert not result.audit_complete and not result.qualification_eligible
    assert result.lineage_independence == "NOT_ESTABLISHED"
    material = DevelopmentCorpusMaterial.model_validate_json(
        (case.root / "candidate/sources.json").read_bytes()
    )
    assert material == loaded.material
    assert len(result.accounting) == 15


@pytest.mark.asyncio
async def test_runtime_refuses_changed_context_before_any_reservation(tmp_path):
    loaded = load_case(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files, manifest=loaded.material.manifest
    )
    shard = prepared.candidate.shards[0]
    changed = shard.request_content.replace(b"IMPORT_CLOSED", b"CALL_CLOSED")
    assert changed != shard.request_content
    candidate = replace(
        prepared.candidate,
        shards=(replace(shard, request_content=changed), *prepared.candidate.shards[1:]),
    )
    case = execution_case(tmp_path, prepared=replace(prepared, candidate=candidate), scored=False)
    with pytest.raises(ValueError):
        await execute(case)
    assert case.counts == [0, 0, 0]
    assert case.ledger.snapshot().spent_usd == 0
    assert not case.root.exists()
