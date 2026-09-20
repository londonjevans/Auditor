"""Actual-root closure custody reaches all three mock roles without runtime authority."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from mmaudit import development_cli
from mmaudit.cli import app
from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
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
from tests.unit.test_development_dependency_closure import FIXTURE, fixture_sources
from tests.unit.test_development_static_call_closure import FLAGS, changed, resign


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("static closure attempted network, subprocess or secret access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def tree_inputs(tmp_path, files=None):
    root = tmp_path / "source"
    root.mkdir(mode=0o700)
    for name, raw in fixture_sources() if files is None else files:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    remappings = tmp_path / "remappings.txt"
    remappings.write_bytes((FIXTURE / "remappings.txt").read_bytes())
    return dict(
        corpus_root=root,
        remappings_file=remappings,
        corpus_id="synthetic-closed-tree",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
    )


def frozen_load(tmp_path, files=None):
    inputs = tree_inputs(tmp_path, files)
    output = tmp_path / "frozen"
    manifest = freeze_development_corpus_tree(
        **inputs,
        output_dir=output,
        **{
            key.replace("include_", "dependency_"): value
            for key, value in FLAGS.items()
            if key != "include_target_context"
        },
    )
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert manifest.schema_version == "1.9" and manifest.dependency_evidence.schema_version == "1.7"
    assert loaded.material.manifest == manifest and loaded.tree_observation is not None
    return inputs, loaded


def test_offline_cli_computes_static_closure_from_actual_complete_root(tmp_path):
    inputs = tree_inputs(tmp_path)
    output = tmp_path / "frozen"
    result = CliRunner().invoke(
        app,
        [
            "development",
            "freeze-tree",
            "--call-closure",
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
        ],
    )
    assert result.exit_code == 0, result.output
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest.dependency_closure == "CALL_CLOSED"
    assert loaded.material.manifest.schema_version == "1.9"
    assert loaded.material.source_files == fixture_sources()
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "manifest.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("closed", [True, False])
async def test_computed_closure_members_and_refusals_reach_all_roles_and_retained_material(
    tmp_path, closed
):
    files = (
        fixture_sources()
        if closed
        else changed("src/SecondReserve.sol", "function value()", "function missing()")
    )
    _, loaded = frozen_load(tmp_path, files)
    manifest = loaded.material.manifest
    witness = manifest.dependency_evidence
    proof = witness.static_call_closure
    assert (proof.call_closure == "CALL_CLOSED") == closed
    prepared = manifest_ensemble_case(
        source_files=files,
        manifest=manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def inspect(_role, _ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert proof.model_dump_json() in prompt
        for component in (
            witness.target_context,
            witness.scoped_context,
            witness.call_context,
            witness.syntax_context,
        ):
            assert component.model_dump_json() in prompt
        assert "CALL_CLOSED remains unavailable" not in prompt
        assert "full static call closure remains NOT_ESTABLISHED" not in prompt
        assert "not an empty dependency set" in prompt
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
@pytest.mark.parametrize("change", ["members", "graph", "policy", "status"])
async def test_changed_proof_request_refuses_before_reservation(tmp_path, change):
    _, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    first = prepared.candidate.shards[0]
    before, after = {
        "members": (b"src/SecondReserve.sol", b"src/OmittedReserve.sol"),
        "graph": (b"original_graph_sha256", b"unbound_graph_sha256"),
        "policy": (b"SOURCE_GRAPH_SYNTAX_TYPED_CALL_CLOSURE_V1", b"DECLARED_CLOSURE"),
        "status": (b"CALL_CLOSED", b"AUDIT_COMPLETE"),
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


@pytest.mark.parametrize("change", ["body", "add", "remove", "replace"])
def test_actual_root_refuses_changed_or_omitted_dependencies(tmp_path, change):
    inputs, loaded = frozen_load(tmp_path)
    path = inputs["corpus_root"] / "src/SecondReserve.sol"
    raw = path.read_bytes()
    if change == "body":
        path.write_bytes(raw.replace(b"return 1", b"return 2"))
    elif change == "add":
        (path.parent / "Another.sol").write_bytes(raw.replace(b"SecondReserve", b"AnotherReserve"))
    elif change == "remove":
        path.rename(tmp_path / "removed.sol")
    else:
        path.rename(tmp_path / "original.sol")
        path.write_bytes(raw)
    with pytest.raises((ValueError, OSError)):
        revalidate_loaded_development_corpus(loaded)


def test_loaded_closure_uses_frozen_remapping_text_not_a_mutable_origin_file(tmp_path):
    inputs, loaded = frozen_load(tmp_path)
    before = loaded.material.manifest.dependency_evidence.remapping_text
    inputs["remappings_file"].write_text("@local/=different/\n")
    revalidate_loaded_development_corpus(loaded)
    assert loaded.material.manifest.dependency_evidence.remapping_text == before
    validate_development_corpus_sources(loaded.material.manifest, loaded.material.source_files)


def test_self_hashed_line_claim_still_requires_actual_source_recomputation(tmp_path):
    _, loaded = frozen_load(tmp_path)
    payload = loaded.material.manifest.model_dump(mode="json")
    witness = payload["dependency_evidence"]
    witness["static_call_closure"]["call_lines"][0]["line_start"] += 1
    witness["static_call_closure"]["call_lines"][0]["line_end"] += 1
    payload["dependency_evidence"] = json.loads(resign(witness))
    payload["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in payload.items() if k != "manifest_sha256"}
    )
    # With no original graph facts these self-hashed lines cannot be disproved from metadata.
    # Acceptance therefore MUST also rederive the proof from actual source, as every consumer does.
    forged = DevelopmentCorpusManifest.model_validate_json(json.dumps(payload))
    with pytest.raises(ValueError, match="recomputation"):
        validate_development_corpus_sources(forged, loaded.material.source_files)


def test_missing_actual_root_custody_refuses_even_with_a_valid_closed_manifest(tmp_path):
    _, loaded = frozen_load(tmp_path)
    with pytest.raises(ValueError, match="custody"):
        manifest_ensemble_case(
            source_files=loaded.material.source_files,
            manifest=loaded.material.manifest,
            policy=selected_policy(total="60", per_attempt="3"),
        )


@pytest.mark.parametrize("flag", [1, 0, None, "true", True])
def test_static_flag_refuses_before_source_io_without_its_predecessors(tmp_path, monkeypatch, flag):
    from mmaudit.repository import development_corpus_tree as tree_io

    inputs = tree_inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid closure flag reached source I/O")

    monkeypatch.setattr(tree_io, "read_file_evidence", forbidden)
    with pytest.raises(ValueError, match="static closure"):
        freeze_development_corpus_tree(
            **inputs, output_dir=tmp_path / "frozen", dependency_static_closure=flag
        )
