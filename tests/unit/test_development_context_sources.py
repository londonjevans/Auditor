"""Explicit source roles never turn retained context into paid primary work."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    DevelopmentCorpusSourcePartition,
    development_corpus_request_id,
    freeze_development_corpus,
    prepare_development_corpus,
    render_development_corpus_sources,
    validate_development_corpus_response,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.development_corpus import load_development_corpus
from mmaudit.repository.development_corpus_tree import freeze_development_corpus_tree
from tests.development_corpus_support import corpus_case
from tests.integration.test_development_call_closure_custody import tree_inputs
from tests.unit.test_development_dependency_closure import fixture_sources
from tests.unit.test_development_static_call_closure import FLAGS


def partitioned_tree(tmp_path, primaries=("src/Controller.sol",), *, files=None):
    tmp_path.mkdir(exist_ok=True)
    inputs = tree_inputs(tmp_path, files)
    output = tmp_path / "frozen"
    manifest = freeze_development_corpus_tree(
        **inputs,
        output_dir=output,
        primary_filenames=primaries,
        **{
            key.replace("include_", "dependency_"): value
            for key, value in FLAGS.items()
            if key != "include_target_context"
        },
    )
    loaded = load_development_corpus(
        manifest_file=output / "manifest.json", corpus_root=inputs["corpus_root"]
    )
    assert loaded.material.manifest == manifest
    return loaded


def prepared_partition(loaded, *, run_id="synthetic-context-run"):
    previous = corpus_case()
    return prepare_development_corpus(
        policy=previous.plan.policy,
        endpoint_snapshot=previous.shards[0].endpoint_snapshot,
        manifest=loaded.material.manifest,
        source_files=loaded.material.source_files,
        source_custody=loaded,
        run_id=run_id,
    )


def test_explicit_partition_binds_union_and_skips_context_primary_work(tmp_path):
    loaded = partitioned_tree(tmp_path)
    manifest = loaded.material.manifest
    assert manifest.schema_version == "1.10"
    assert tuple(s.filename for s in manifest.primary_sources) == ("src/Controller.sol",)
    assert len(manifest.context_sources) == 4
    assert manifest.dependency_closure == "CALL_CLOSED"
    assert manifest.sources == tuple(
        sorted(manifest.primary_sources + manifest.context_sources, key=lambda s: s.filename)
    )
    prepared = prepared_partition(loaded)
    assert len(prepared.shards) == len(prepared.plan.shards) == 1
    index = next(i for i, s in enumerate(manifest.sources, 1) if s.filename == "src/Controller.sol")
    assert prepared.shards[0].shard_id == f"file-{index:04d}"
    body = json.loads(prepared.shards[0].request_content)
    prompt = body["messages"][1]["content"]
    assert "context presence is not primary review" in prompt
    for path, _ in fixture_sources():
        assert f"Source file: {path}" in prompt
    assert (
        DevelopmentCorpusManifest.model_validate_json(manifest.model_dump_json(), strict=True)
        == manifest
    )


@pytest.mark.parametrize(
    "primary,context",
    [
        ((), ("A.sol",)),
        (("A.sol", "A.sol"), ()),
        (("B.sol", "A.sol"), ()),
        (("A.sol",), ("A.sol",)),
        (("../A.sol",), ()),
        (("A.sol",), (".env",)),
        (("A.sol",), ("B.sol", "B.sol")),
    ],
)
def test_source_role_partition_rejects_noncanonical_or_overlapping_paths(primary, context):
    with pytest.raises(ValueError):
        DevelopmentCorpusSourcePartition(primary_filenames=primary, context_filenames=context)


@pytest.mark.parametrize("kind", ["missing", "extra", "legacy", "no_partition"])
def test_manifest_cannot_rehash_away_missing_extra_or_unversioned_roles(tmp_path, kind):
    manifest = partitioned_tree(tmp_path).material.manifest
    value = manifest.model_dump(mode="json")
    if kind == "missing":
        value["source_partition"]["context_filenames"].pop()
    elif kind == "extra":
        value["source_partition"]["context_filenames"].append("z.sol")
    elif kind == "legacy":
        value["schema_version"] = "1.9"
    else:
        value.pop("source_partition")
    value["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in value.items() if k != "manifest_sha256"}
    )
    with pytest.raises(ValueError):
        DevelopmentCorpusManifest.model_validate_json(json.dumps(value), strict=True)


def test_context_cannot_become_request_primary_even_with_empty_response(tmp_path):
    from mmaudit.models.development_corpus import DevelopmentCorpusResponse

    loaded = partitioned_tree(tmp_path)
    manifest = loaded.material.manifest
    context = manifest.context_sources[0].filename
    with pytest.raises(ValueError):
        development_corpus_request_id("context", manifest, context)
    with pytest.raises(ValueError):
        render_development_corpus_sources(manifest, loaded.material.source_files, context)
    with pytest.raises(ValueError):
        validate_development_corpus_response(
            DevelopmentCorpusResponse(
                schema_version="3.0", summary="No synthetic claims.", findings=()
            ),
            manifest,
            context,
        )


def test_context_bytes_remain_in_the_exact_request_cost_estimate(tmp_path):
    original = partitioned_tree(tmp_path / "original")
    context = original.material.manifest.context_sources[0].filename
    changed = tuple(
        (
            name,
            raw + b"// Synthetic extra context bytes for cost accounting.\n"
            if name == context
            else raw,
        )
        for name, raw in original.material.source_files
    )
    updated = partitioned_tree(tmp_path / "updated", files=changed)
    before, after = (prepared_partition(item).shards[0] for item in (original, updated))
    assert before.estimate.request_bytes == len(before.request_content)
    assert after.estimate.request_bytes == len(after.request_content)
    assert after.estimate.request_bytes > before.estimate.request_bytes
    assert (
        after.estimate.estimated_cost_per_attempt_usd
        > before.estimate.estimated_cost_per_attempt_usd
    )
    assert after.estimate.policy == before.estimate.policy


def test_selected_only_legacy_manifest_keeps_all_sources_primary_and_no_role_bytes():
    manifest = freeze_development_corpus(
        corpus_id="synthetic-legacy",
        source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
        source_files=fixture_sources(),
    )
    assert manifest.primary_sources == manifest.sources and manifest.context_sources == ()
    assert "source_partition" not in manifest.model_dump(mode="json")
    with pytest.raises(ValueError):
        freeze_development_corpus(
            corpus_id="synthetic-legacy",
            source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
            source_files=fixture_sources(),
            primary_filenames=("src/Controller.sol",),
        )


def test_manifest_1_9_and_all_requests_match_pre_context_retained_golden(tmp_path):
    from tests.development_corpus_ensemble_support import manifest_ensemble_case
    from tests.development_corpus_judgment_support import selected_policy
    from tests.integration.test_development_call_closure_custody import frozen_load

    golden = json.loads(
        (
            Path(__file__).parents[1]
            / "fixtures/solidity/dependency_call_closure/manifest_1_9_golden.json"
        ).read_text()
    )
    _, loaded = frozen_load(tmp_path)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    assert loaded.material.manifest.manifest_sha256 == golden["manifest_sha256"]
    assert prepared.candidate.plan.plan_sha256 == golden["candidate_plan_sha256"]
    assert prepared.plan.plan_sha256 == golden["ensemble_plan_sha256"]
    assert [
        dict(
            shard_id=s.shard_id,
            request_sha256=s.estimate.request_sha256,
            request_bytes=s.estimate.request_bytes,
        )
        for s in prepared.candidate.shards
    ] == golden["requests"]
