"""Actual local source custody and complete mock ensemble context; no external execution."""

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
from tests.unit.test_development_dependency_targets import target_manifest, target_sources


@pytest.fixture(autouse=True)
def forbid_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("target-context control attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def load_target_case(tmp_path):
    root = tmp_path / "source"
    root.mkdir(mode=0o700)
    for name, raw in target_sources():
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(target_manifest().model_dump_json())
    return load_development_corpus(manifest_file=manifest, corpus_root=root)


@pytest.mark.asyncio
async def test_source_bound_implementations_reach_actual_candidate_and_both_reviewers(tmp_path):
    loaded = load_target_case(tmp_path)
    context = loaded.material.manifest.dependency_evidence.target_context
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files, manifest=loaded.material.manifest
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(role, ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert context.model_dump_json() in prompt
        assert "Static call closure" in prompt and "NOT_ESTABLISHED" in prompt
        assert "NOT_PERFORMED" in prompt
        assert all("Source file: " + p in prompt for p, _ in loaded.material.source_files)
        assert "return 0;" in prompt and "return 1;" in prompt and "return 2;" in prompt

    result = await execute(case, custom=inspect)
    assert case.counts == [8, 8, 8]
    assert result == retained(case)
    assert result.status == "OBSERVED_ALL_STAGES" and len(result.accounting) == 24
    assert not result.audit_complete and not result.qualification_eligible
    assert result.lineage_independence == "NOT_ESTABLISHED"
    material = DevelopmentCorpusMaterial.model_validate_json(
        (case.root / "candidate/sources.json").read_bytes()
    )
    assert material == loaded.material
    assert material.manifest.dependency_evidence.target_context == context


@pytest.mark.asyncio
async def test_changed_prepared_type_context_refuses_before_any_reservation(tmp_path):
    loaded = load_target_case(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files, manifest=loaded.material.manifest
    )
    first = prepared.candidate.shards[0]
    changed = first.request_content.replace(b"NOT_PERFORMED", b"SYNTHETIC_FAKE_PROOF", 1)
    assert changed != first.request_content
    candidate = replace(
        prepared.candidate,
        shards=(replace(first, request_content=changed), *prepared.candidate.shards[1:]),
    )
    case = execution_case(tmp_path, prepared=replace(prepared, candidate=candidate), scored=False)
    with pytest.raises(ValueError):
        await execute(case)
    assert case.counts == [0, 0, 0] and case.ledger.snapshot().spent_usd == 0
    assert not case.root.exists()


@pytest.mark.parametrize("change", ["bytes", "removed", "symlink"])
def test_retained_implementation_drift_refuses_even_when_primary_and_interface_are_unchanged(
    tmp_path, change
):
    loaded = load_target_case(tmp_path)
    path = loaded.corpus_root / "src/InheritedReserve.sol"
    if change == "bytes":
        path.write_bytes(path.read_bytes() + b"\n// Synthetic implementation drift.\n")
    elif change == "removed":
        path.unlink()
    else:
        outside = tmp_path / "other.sol"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
    with pytest.raises((OSError, ValueError)):
        revalidate_loaded_development_corpus(loaded)
    assert loaded.material.source_files == target_sources()
