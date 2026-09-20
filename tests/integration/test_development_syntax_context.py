"""Independent syntax census through actual local custody and mock three-leg consumers."""

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
from tests.integration.test_development_typed_calls import tree_inputs
from tests.unit.test_development_dependency_calls import call_sources, split_call_sources
from tests.unit.test_development_dependency_syntax import body_sources


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("syntax census attempted external or credential access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def frozen_load(tmp_path, files=None):
    inputs = tree_inputs(tmp_path, files)
    output = tmp_path / "frozen"
    manifest = freeze_development_corpus_tree(
        **inputs,
        output_dir=output,
        dependency_scoped_context=True,
        dependency_call_context=True,
        dependency_syntax_context=True,
    )
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest == manifest and manifest.schema_version == "1.6"
    assert loaded.tree_observation is not None
    return inputs, loaded


def test_actual_offline_cli_freezes_and_replays_versioned_syntax_evidence(tmp_path):
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
        "--syntax-context",
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest.schema_version == "1.6"
    assert loaded.material.source_files == call_sources()
    assert loaded.material.manifest.dependency_evidence.syntax_context.gaps == ()
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["single", "split", "unsupported"])
async def test_exact_syntax_gaps_and_calls_reach_candidate_and_both_reviewers(tmp_path, kind):
    files = (
        split_call_sources()
        if kind == "split"
        else body_sources("assembly {} return check(1);")
        if kind == "unsupported"
        else call_sources()
    )
    _, loaded = frozen_load(tmp_path, files)
    context = loaded.material.manifest.dependency_evidence.syntax_context
    assert bool(context.gaps) == (kind == "unsupported")
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="60" if kind == "split" else "40", per_attempt="3"),
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(_role, _ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert context.model_dump_json() in prompt
        assert "EXACT_SPAN joins source spans only" in prompt
        assert "Full static call closure remains NOT_ESTABLISHED" in prompt
        for name, raw in files:
            rendered = "\n".join(
                f"{i}: {line}" for i, line in enumerate(raw.decode().splitlines(), 1)
            )
            assert name in prompt and rendered in prompt

    result = await execute(case, custom=inspect)
    assert case.counts == [len(files)] * 3 and result == retained(case)
    assert not result.audit_complete and not result.qualification_eligible
    assert result.lineage_independence == "NOT_ESTABLISHED"
    material = DevelopmentCorpusMaterial.model_validate_json(
        (case.root / "candidate/sources.json").read_bytes()
    )
    assert material == loaded.material


@pytest.mark.asyncio
async def test_changed_syntax_request_refuses_before_reservation_and_provider_dispatch(tmp_path):
    _, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="40", per_attempt="3"),
        source_custody=loaded,
    )
    first = prepared.candidate.shards[0]
    changed = first.request_content.replace(
        b"SUPPORTED_GRAMMAR_ACCOUNTED", b"UNJUSTIFIED_CLOSURE", 1
    )
    assert changed != first.request_content
    candidate = replace(prepared.candidate, shards=(replace(first, request_content=changed),))
    case = execution_case(tmp_path, prepared=replace(prepared, candidate=candidate), scored=False)
    with pytest.raises(ValueError):
        await execute(case)
    assert case.counts == [0, 0, 0] and case.ledger.snapshot().spent_usd == 0
    assert not case.root.exists()


@pytest.mark.parametrize("change", ["statement", "call", "added_source", "replacement"])
def test_actual_root_replay_refuses_syntax_and_implementation_universe_drift(tmp_path, change):
    inputs, loaded = frozen_load(tmp_path)
    path = inputs["corpus_root"] / "Calls.sol"
    raw = path.read_bytes()
    if change == "statement":
        path.write_bytes(raw.replace(b"return amount;", b"return amount + ;"))
    elif change == "call":
        path.write_bytes(raw.replace(b"selected.value(amount)", b"selected.value(unknown(amount))"))
    elif change == "added_source":
        (inputs["corpus_root"] / "Added.sol").write_bytes(raw)
    else:
        path.rename(tmp_path / "old.sol")
        path.write_bytes(raw)
    with pytest.raises((OSError, ValueError)):
        revalidate_loaded_development_corpus(loaded)


@pytest.mark.parametrize("flag", [1, 0, None, "true", True])
def test_invalid_syntax_flag_or_missing_typed_selection_refuses_before_input_io(
    tmp_path, monkeypatch, flag
):
    from mmaudit.repository import development_corpus_tree as tree_io

    inputs = tree_inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid syntax selection reached source I/O")

    monkeypatch.setattr(tree_io, "read_file_evidence", forbidden)
    with pytest.raises(ValueError):
        freeze_development_corpus_tree(
            **inputs, output_dir=tmp_path / "frozen", dependency_syntax_context=flag
        )
