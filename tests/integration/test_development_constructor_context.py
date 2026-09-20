"""Constructor context remains exact through actual local roots and all three mock roles."""

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
from tests.unit.test_development_dependency_constructors import (
    changed_sources,
    constructions,
    constructor_sources,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("constructor analysis attempted network, subprocess or secret access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def frozen_load(tmp_path, files=None):
    inputs = tree_inputs(tmp_path, constructor_sources() if files is None else files)
    output = tmp_path / "frozen"
    manifest = freeze_development_corpus_tree(
        **inputs,
        output_dir=output,
        dependency_scoped_context=True,
        dependency_call_context=True,
        dependency_syntax_context=True,
        dependency_modifier_context=True,
        dependency_constructor_context=True,
    )
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert manifest.schema_version == "1.8" and loaded.material.manifest == manifest
    assert loaded.tree_observation is not None
    return inputs, loaded


def test_offline_cli_freezes_constructor_context_with_actual_source_root(tmp_path):
    inputs = tree_inputs(tmp_path, constructor_sources())
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
            "--constructor-context",
        ],
    )
    assert result.exit_code == 0, result.output
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.source_files == constructor_sources()
    assert loaded.material.manifest.schema_version == "1.8"
    assert len(constructions(loaded.material.manifest)) == 6
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["supported", "missing_arguments", "duplicate_arguments"])
async def test_constructor_bodies_arguments_and_shortfalls_reach_candidate_and_both_reviewers(
    tmp_path, kind
):
    files = (
        changed_sources("Products.sol", "Base(uint256(initial))", "")
        if kind == "missing_arguments"
        else changed_sources(
            "Products.sol", "contract Product is Base {", "contract Product is Base(uint256(2)) {"
        )
        if kind == "duplicate_arguments"
        else constructor_sources()
    )
    _, loaded = frozen_load(tmp_path, files)
    manifest = loaded.material.manifest
    context = manifest.dependency_evidence.call_context
    assert any(c.shortfalls for c in constructions(manifest)) == (kind != "supported")
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
        assert "Constructors are not inherited overloads" in prompt
        assert "CALL_CLOSED remains unavailable" in prompt
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
@pytest.mark.parametrize("change", ["constructor_body", "base_argument", "closure_claim"])
async def test_changed_constructor_request_refuses_before_reservation(tmp_path, change):
    _, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    first = prepared.candidate.shards[0]
    before, after = {
        "constructor_body": (b"constructor_member_ids", b"omitted_constructor_bodies"),
        "base_argument": (b"base_argument_calls", b"omitted_base_arguments"),
        "closure_claim": (b"NOT_ESTABLISHED", b"CALL_CLOSED"),
    }[change]
    content = first.request_content.replace(before, after, 1)
    assert content != first.request_content
    candidate = replace(
        prepared.candidate,
        shards=(replace(first, request_content=content), *prepared.candidate.shards[1:]),
    )
    case = execution_case(tmp_path, prepared=replace(prepared, candidate=candidate), scored=False)
    with pytest.raises(ValueError):
        await execute(case)
    assert case.counts == [0, 0, 0] and case.ledger.snapshot().spent_usd == 0
    assert not case.root.exists()


@pytest.mark.parametrize("change", ["body", "argument", "added_constructor", "replacement"])
def test_actual_root_refuses_changed_constructor_source(tmp_path, change):
    inputs, loaded = frozen_load(tmp_path)
    path = inputs["corpus_root"] / "Products.sol"
    raw = path.read_bytes()
    if change == "body":
        path = inputs["corpus_root"] / "Bases.sol"
        path.write_bytes(path.read_bytes().replace(b"seed = initial", b"seed = 0"))
    elif change == "argument":
        path.write_bytes(raw.replace(b"uint256(initial)", b"uint256(1)"))
    elif change == "added_constructor":
        path.write_bytes(
            raw.replace(
                b"contract Implicit is Guard { }",
                b"contract Implicit is Guard { constructor() {} }",
            )
        )
    else:
        path.rename(tmp_path / "old.sol")
        path.write_bytes(raw)
    with pytest.raises((ValueError, OSError)):
        revalidate_loaded_development_corpus(loaded)


@pytest.mark.parametrize("flag", [1, 0, None, "true", True])
def test_constructor_flag_is_validated_before_any_source_io(tmp_path, monkeypatch, flag):
    from mmaudit.repository import development_corpus_tree as tree_io

    inputs = tree_inputs(tmp_path, constructor_sources())

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid constructor flag reached source I/O")

    monkeypatch.setattr(tree_io, "read_file_evidence", forbidden)
    with pytest.raises(ValueError, match="constructor context"):
        freeze_development_corpus_tree(
            **inputs, output_dir=tmp_path / "frozen", dependency_constructor_context=flag
        )
