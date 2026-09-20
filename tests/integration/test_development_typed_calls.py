"""Actual local source/retained/request handoff; mock providers, no Solidity execution."""

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
from tests.unit.test_development_dependency_calls import call_sources, split_call_sources


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("typed call context attempted external or credential access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def tree_inputs(tmp_path, files=None):
    root = tmp_path / "source"
    root.mkdir(mode=0o700)
    for name, raw in call_sources() if files is None else files:
        (root / name).write_bytes(raw)
    remappings = tmp_path / "remappings.txt"
    remappings.write_text("")
    return dict(
        corpus_root=root,
        remappings_file=remappings,
        corpus_id="synthetic-typed-tree",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
    )


def frozen_load(tmp_path, files=None):
    inputs = tree_inputs(tmp_path, files)
    output = tmp_path / "frozen"
    manifest = freeze_development_corpus_tree(
        **inputs, output_dir=output, dependency_scoped_context=True, dependency_call_context=True
    )
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert manifest == loaded.material.manifest and manifest.schema_version == "1.5"
    assert loaded.tree_observation is not None
    return inputs, loaded


def test_typed_tree_cli_freezes_and_replays_actual_source_without_credentials(tmp_path):
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
        "--typed-calls",
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest.schema_version == "1.5"
    assert loaded.material.source_files == call_sources()
    assert loaded.material.manifest.dependency_evidence.call_context is not None
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("split_sources", [False, True])
async def test_typed_calls_and_all_nominal_bodies_reach_candidate_and_both_reviewers(
    tmp_path, split_sources
):
    files = split_call_sources() if split_sources else call_sources()
    _, loaded = frozen_load(tmp_path, files)
    context = loaded.material.manifest.dependency_evidence.call_context
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="60" if split_sources else "40", per_attempt="3"),
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(_role, _ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert context.model_dump_json() in prompt
        assert loaded.material.manifest.source_tree_evidence.model_dump_json() in prompt
        assert "not compiler validity or deployed dispatch" in prompt
        assert all(
            name in prompt
            for name in (
                "ReserveA",
                "ReserveB",
                "factory.reserve().value(choice)",
                "choose(factory).value(amount)",
            )
        )

    result = await execute(case, custom=inspect)
    assert case.counts == [len(files)] * 3 and result == retained(case)
    assert not result.audit_complete and not result.qualification_eligible
    assert result.lineage_independence == "NOT_ESTABLISHED"
    material = DevelopmentCorpusMaterial.model_validate_json(
        (case.root / "candidate/sources.json").read_bytes()
    )
    assert material == loaded.material


@pytest.mark.asyncio
async def test_altered_typed_request_context_refuses_before_any_reservation(tmp_path):
    _, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="40", per_attempt="3"),
        source_custody=loaded,
    )
    first = prepared.candidate.shards[0]
    changed = first.request_content.replace(b"STATIC_DECLARATIONS_BOUND", b"UNJUSTIFIED_CLOSURE", 1)
    assert changed != first.request_content
    candidate = replace(prepared.candidate, shards=(replace(first, request_content=changed),))
    case = execution_case(tmp_path, prepared=replace(prepared, candidate=candidate), scored=False)
    with pytest.raises(ValueError):
        await execute(case)
    assert case.counts == [0, 0, 0] and case.ledger.snapshot().spent_usd == 0
    assert not case.root.exists()


def test_split_typed_context_retains_the_original_insufficient_headroom_refusal(tmp_path):
    _, loaded = frozen_load(tmp_path, split_call_sources())
    with pytest.raises(ValueError, match="estimated headroom exceeds"):
        manifest_ensemble_case(
            source_files=loaded.material.source_files,
            manifest=loaded.material.manifest,
            source_custody=loaded,
            policy=selected_policy(total="40", per_attempt="3"),
        )


@pytest.mark.parametrize(
    "change", ["argument_type", "return_type", "body", "added_source", "replacement"]
)
def test_actual_tree_replay_refuses_type_body_and_implementation_universe_drift(tmp_path, change):
    inputs, loaded = frozen_load(tmp_path)
    path = inputs["corpus_root"] / "Calls.sol"
    raw = path.read_bytes()
    if change == "argument_type":
        path.write_bytes(raw.replace(b"uint256 amount", b"uint8 amount"))
    elif change == "return_type":
        path.write_bytes(raw.replace(b"returns (IReserve)", b"returns (address)"))
    elif change == "body":
        path.write_bytes(raw.replace(b"return amount;", b"return 0;"))
    elif change == "added_source":
        (inputs["corpus_root"] / "Added.sol").write_bytes(raw)
    else:
        path.rename(tmp_path / "old.sol")
        path.write_bytes(raw)
    with pytest.raises((OSError, ValueError)):
        revalidate_loaded_development_corpus(loaded)


@pytest.mark.parametrize("flag", [1, 0, None, "true"])
def test_invalid_typed_flag_refuses_before_source_or_remapping_io(tmp_path, monkeypatch, flag):
    from mmaudit.repository import development_corpus_tree as tree_io

    inputs = tree_inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid typed flag reached source I/O")

    monkeypatch.setattr(tree_io, "read_file_evidence", forbidden)
    with pytest.raises(ValueError):
        freeze_development_corpus_tree(
            **inputs,
            output_dir=tmp_path / "frozen",
            dependency_scoped_context=True,
            dependency_call_context=flag,
        )
