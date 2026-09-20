"""Real local tree/retained-source handoff of lexical context; every provider is mocked."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from mmaudit import development_cli
from mmaudit.cli import app
from mmaudit.models.development_corpus import DevelopmentCorpusMaterial
from mmaudit.repository.development_corpus import (
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from mmaudit.repository.development_corpus_tree import freeze_development_corpus_tree
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.development_corpus_judgment_support import selected_policy
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    retained,
)
from tests.unit.test_development_dependency_scopes import scoped_sources


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("scoped context attempted provider, credential or child-process access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def tree_inputs(tmp_path):
    root = tmp_path / "source"
    root.mkdir(mode=0o700)
    for name, raw in scoped_sources():
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
    remappings = tmp_path / "remappings.txt"
    remappings.write_text("@local/=lib/\n")
    return dict(
        corpus_root=root,
        remappings_file=remappings,
        corpus_id="synthetic-scoped-tree",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
    )


def frozen_load(tmp_path):
    inputs = tree_inputs(tmp_path)
    output = tmp_path / "frozen"
    manifest = freeze_development_corpus_tree(
        **inputs, output_dir=output, dependency_scoped_context=True
    )
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest == manifest and manifest.schema_version == "1.4"
    assert (
        loaded.tree_observation is not None and manifest.source_tree_evidence.root_replay_required
    )
    return inputs, loaded


def test_scoped_tree_cli_freezes_and_replays_actual_source_without_credentials(tmp_path):
    inputs = tree_inputs(tmp_path)
    output = tmp_path / "frozen"
    args = [
        "development",
        "freeze-tree",
        "--corpus-root",
        str(inputs["corpus_root"]),
        "--remappings-file",
        str(inputs["remappings_file"]),
        "--corpus-id",
        inputs["corpus_id"],
        "--source-scope",
        inputs["source_scope"],
        "--output-dir",
        str(output),
        "--scoped-targets",
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest.schema_version == "1.4"
    assert loaded.material.source_files == scoped_sources()
    assert loaded.material.manifest.dependency_evidence.scoped_context is not None
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_scoped_member_and_implementation_evidence_reaches_every_retained_review_leg(
    tmp_path,
):
    _inputs, loaded = frozen_load(tmp_path)
    context = loaded.material.manifest.dependency_evidence.scoped_context
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="40", per_attempt="3"),
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(_role, _ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert context.model_dump_json() in prompt
        assert loaded.material.manifest.source_tree_evidence.model_dump_json() in prompt
        assert "not runtime dispatch" in prompt and "NOT_ESTABLISHED" in prompt
        assert all("Source file: " + name in prompt for name, _ in scoped_sources())
        assert "function localValue" in prompt and "return Math.zero();" in prompt

    result = await execute(case, custom=inspect)
    assert case.counts == [5, 5, 5] and result == retained(case)
    assert not result.audit_complete and not result.qualification_eligible
    assert result.lineage_independence == "NOT_ESTABLISHED"
    material = DevelopmentCorpusMaterial.model_validate_json(
        (case.root / "candidate/sources.json").read_bytes()
    )
    assert material == loaded.material


@pytest.mark.asyncio
async def test_changed_prepared_scoped_context_refuses_before_reservation(tmp_path):
    _inputs, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="40", per_attempt="3"),
        source_custody=loaded,
    )
    first = prepared.candidate.shards[0]
    changed = first.request_content.replace(b"DECLARATIONS_BOUND", b"UNJUSTIFIED_CLOSURE", 1)
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


def test_scoped_context_keeps_the_original_cost_refusal_for_an_insufficient_test_budget(tmp_path):
    _inputs, loaded = frozen_load(tmp_path)
    # The default mock fixture reserves at most USD1 per attempt. Scoped evidence is
    # real request input and cannot be excluded from the unchanged conservative estimate.
    with pytest.raises(ValueError, match="source, request or selected route"):
        manifest_ensemble_case(
            source_files=loaded.material.source_files,
            manifest=loaded.material.manifest,
            source_custody=loaded,
        )


@pytest.mark.parametrize(
    "change", ["body", "added_implementer", "removed_implementer", "replacement"]
)
def test_tree_replay_refuses_drift_in_member_bodies_or_the_implementation_universe(
    tmp_path, change
):
    inputs, loaded = frozen_load(tmp_path)
    path = inputs["corpus_root"] / "src/Reserve.sol"
    if change == "body":
        path.write_bytes(path.read_bytes().replace(b"return Math.zero();", b"return 1;"))
    elif change == "added_implementer":
        (inputs["corpus_root"] / "src/Late.sol").write_bytes(path.read_bytes())
    elif change == "removed_implementer":
        path.unlink()
    else:
        raw = path.read_bytes()
        path.rename(tmp_path / "previous.sol")
        path.write_bytes(raw)
    with pytest.raises((OSError, ValueError)):
        revalidate_loaded_development_corpus(loaded)


@pytest.mark.parametrize("flag", [0, 1, None, "true"])
def test_invalid_scoped_mode_refuses_before_reading_the_tree(tmp_path, monkeypatch, flag):
    from mmaudit.repository import development_corpus_tree as tree_io

    inputs = tree_inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("non-boolean scoped mode reached source or remapping I/O")

    monkeypatch.setattr(tree_io, "read_file_evidence", forbidden)
    with pytest.raises(ValueError):
        freeze_development_corpus_tree(
            **inputs, output_dir=tmp_path / "frozen", dependency_scoped_context=flag
        )
