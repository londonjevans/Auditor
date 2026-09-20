"""Modifier dependency custody using local synthetic trees and sealed mock transport only."""

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
from tests.unit.test_development_dependency_modifiers import (
    changed_sources,
    modifier_sources,
    modifiers,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("modifier analysis attempted network, subprocess or secret access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def frozen_load(tmp_path, files=None):
    inputs = tree_inputs(tmp_path, modifier_sources() if files is None else files)
    output = tmp_path / "frozen"
    manifest = freeze_development_corpus_tree(
        **inputs,
        output_dir=output,
        dependency_scoped_context=True,
        dependency_call_context=True,
        dependency_syntax_context=True,
        dependency_modifier_context=True,
    )
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest == manifest and manifest.schema_version == "1.7"
    assert loaded.tree_observation is not None
    return inputs, loaded


def test_offline_cli_freezes_and_replays_actual_modifier_source_universe(tmp_path):
    inputs = tree_inputs(tmp_path, modifier_sources())
    output = tmp_path / "frozen"
    result = CliRunner().invoke(
        app,
        [
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
            "--modifier-context",
        ],
    )
    assert result.exit_code == 0, result.output
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest.schema_version == "1.7"
    assert loaded.material.source_files == modifier_sources()
    assert len(modifiers(loaded.material.manifest)) == 2
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["supported", "missing_body", "bad_override"])
async def test_every_modifier_body_argument_and_shortfall_reaches_all_three_roles(tmp_path, kind):
    files = (
        changed_sources("Guards.sol", "modifier open { _; }", "modifier open;")
        if kind == "missing_body"
        else changed_sources("Child.sol", "uint256 bound", "uint128 bound")
        if kind == "bad_override"
        else modifier_sources()
    )
    _, loaded = frozen_load(tmp_path, files)
    manifest = loaded.material.manifest
    context = manifest.dependency_evidence.call_context
    assert any(c.shortfalls for c in modifiers(manifest)) == (kind != "supported")
    prepared = manifest_ensemble_case(
        source_files=files,
        manifest=manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(_role, _ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert context.model_dump_json() in prompt
        assert manifest.dependency_evidence.syntax_context.model_dump_json() in prompt
        assert "IMPLICIT_MODIFIER call_byte_start is the actual first modifier-name byte" in prompt
        assert "Full static call closure remains NOT_ESTABLISHED" in prompt
        for name, raw in files:
            rendered = "\n".join(
                f"{i}: {line}" for i, line in enumerate(raw.decode().splitlines(), 1)
            )
            assert name in prompt and rendered in prompt

    result = await execute(case, custom=inspect)
    assert case.counts == [len(files)] * 3 and result == retained(case)
    material = DevelopmentCorpusMaterial.model_validate_json(
        (case.root / "candidate/sources.json").read_bytes()
    )
    assert material == loaded.material
    assert not result.audit_complete and not result.qualification_eligible
    assert result.lineage_independence == "NOT_ESTABLISHED"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["dropped_body", "implicit_anchor", "forged_closure"])
async def test_drifted_modifier_evidence_is_refused_before_any_reservation(tmp_path, change):
    _, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    # Candidate request reconstruction is the common preflight before any reviewer can run.
    # Distinct edits model a dropped body, changed implicit anchor or forged stronger claim.
    first = prepared.candidate.shards[0]
    before, after = {
        "dropped_body": (b"implementation_member_ids", b"omitted_modifier_bodies"),
        "implicit_anchor": (b"IMPLICIT_MODIFIER", b"FORGED_ANCHOR"),
        "forged_closure": (b"NOT_ESTABLISHED", b"CALL_CLOSED"),
    }[change]
    changed = first.request_content.replace(before, after, 1)
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


@pytest.mark.parametrize("change", ["body", "argument", "added_implementation", "replacement"])
def test_actual_root_replay_refuses_modifier_tree_drift(tmp_path, change):
    inputs, loaded = frozen_load(tmp_path)
    path = inputs["corpus_root"] / "Guards.sol"
    raw = path.read_bytes()
    if change == "body":
        path.write_bytes(raw.replace(b"<= bound", b">= bound"))
    elif change == "argument":
        path = inputs["corpus_root"] / "Controller.sol"
        path.write_bytes(path.read_bytes().replace(b"normalise(bound)", b"normalise(0)"))
    elif change == "added_implementation":
        (inputs["corpus_root"] / "Added.sol").write_bytes(
            raw.replace(b"contract Guards", b"contract Added")
        )
    else:
        path.rename(tmp_path / "old.sol")
        path.write_bytes(raw)
    with pytest.raises((OSError, ValueError)):
        revalidate_loaded_development_corpus(loaded)


@pytest.mark.parametrize("flag", [1, 0, None, "true", True])
def test_modifier_flag_is_checked_before_source_io(tmp_path, monkeypatch, flag):
    from mmaudit.repository import development_corpus_tree as tree_io

    inputs = tree_inputs(tmp_path, modifier_sources())

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid modifier flag reached source I/O")

    monkeypatch.setattr(tree_io, "read_file_evidence", forbidden)
    with pytest.raises(ValueError, match="modifier context"):
        freeze_development_corpus_tree(
            **inputs, output_dir=tmp_path / "frozen", dependency_modifier_context=flag
        )
