"""A minimal local bundle must preserve the original tree's complete dependency relation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mmaudit.models import development_corpus_partition as module
from mmaudit.models.development_corpus import DevelopmentCorpusMaterial, freeze_development_corpus
from mmaudit.models.development_corpus_partition import (
    DevelopmentCorpusPartition,
    derive_development_corpus_partition,
    read_development_corpus_partition,
    validate_development_corpus_partition,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.unit.test_development_context_sources import partitioned_tree
from tests.unit.test_development_dependency_closure import fixture_sources


@pytest.fixture(scope="module")
def reference(tmp_path_factory):
    return partitioned_tree(tmp_path_factory.mktemp("partition-reference")).material


def resign(value):
    value["manifest"]["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in value["manifest"].items() if k != "manifest_sha256"}
    )
    value["partition_sha256"] = canonical_sha256(
        {k: v for k, v in value.items() if k != "partition_sha256"}
    )
    return DevelopmentCorpusPartition.model_validate_json(json.dumps(value), strict=True)


@pytest.mark.parametrize("primary", ["src/Controller.sol", "src/IReserve.sol", "src/Reserve.sol"])
def test_recipe_uses_original_static_members_and_recomputes_the_selected_union(reference, primary):
    recipe = derive_development_corpus_partition(reference=reference, primary_filenames=(primary,))
    expected = next(
        p.members
        for p in reference.manifest.dependency_evidence.static_call_closure.primaries
        if p.primary == primary
    )
    assert tuple(s.filename for s in recipe.manifest.sources) == expected
    assert tuple(s.filename for s in recipe.manifest.primary_sources) == (primary,)
    assert recipe.manifest.dependency_closure == "CALL_CLOSED"
    assert recipe.reference_manifest_sha256 == reference.manifest.manifest_sha256
    assert recipe.reference_tree_sha256 == reference.manifest.source_tree_evidence.tree_sha256
    assert recipe.reference_static_closure_sha256 == (
        reference.manifest.dependency_evidence.static_call_closure.proof_sha256
    )
    assert read_development_corpus_partition(recipe.model_dump_json().encode()) == recipe
    material = validate_development_corpus_partition(reference=reference, partition=recipe)
    assert material.source_files == tuple(
        (p, b) for p, b in reference.source_files if p in expected
    )
    assert (
        not recipe.audit_complete
        and not recipe.qualification_eligible
        and not recipe.release_eligible
    )


def test_interface_bundle_does_not_copy_unrelated_primaries(reference):
    recipe = derive_development_corpus_partition(
        reference=reference, primary_filenames=("src/IReserve.sol",)
    )
    assert tuple(s.filename for s in recipe.manifest.sources) == ("src/IReserve.sol",)
    assert len(reference.manifest.sources) == 5
    assert recipe.manifest.source_tree_evidence.non_source_file_count == 0
    assert recipe.manifest.source_tree_evidence != reference.manifest.source_tree_evidence


def test_controller_bundle_keeps_both_interface_implementations(reference):
    recipe = derive_development_corpus_partition(
        reference=reference, primary_filenames=("src/Controller.sol",)
    )
    names = {s.filename for s in recipe.manifest.sources}
    assert {
        "src/IReserve.sol",
        "src/Reserve.sol",
        "src/SecondReserve.sol",
        "lib/Math.sol",
    } <= names


def test_multiple_primaries_have_deterministic_minimal_union_and_identity(reference):
    paths = ("src/IReserve.sol", "src/Reserve.sol")
    recipe = derive_development_corpus_partition(reference=reference, primary_filenames=paths)
    singles = [
        derive_development_corpus_partition(reference=reference, primary_filenames=(p,))
        for p in paths
    ]
    expected = set().union(*(set(s.filename for s in p.manifest.sources) for p in singles))
    assert {s.filename for s in recipe.manifest.sources} == expected
    assert (
        derive_development_corpus_partition(reference=reference, primary_filenames=paths) == recipe
    )
    assert len({p.partition_sha256 for p in (*singles, recipe)}) == 3


@pytest.mark.parametrize(
    "paths",
    [
        (),
        ("missing.sol",),
        ("../Outside.sol",),
        ("src/IReserve.sol", "src/IReserve.sol"),
        ("src/Reserve.sol", "src/IReserve.sol"),
        ["src/IReserve.sol"],
        (True,),
    ],
)
def test_noncanonical_missing_or_unsafe_primary_selection_refuses(reference, paths):
    with pytest.raises(ValueError):
        derive_development_corpus_partition(reference=reference, primary_filenames=paths)


@pytest.mark.parametrize(
    "field",
    ["reference_manifest_sha256", "reference_tree_sha256", "reference_static_closure_sha256"],
)
def test_matching_self_hash_cannot_rebind_the_original_closure(reference, field):
    recipe = derive_development_corpus_partition(
        reference=reference, primary_filenames=("src/IReserve.sol",)
    )
    value = recipe.model_dump(mode="json")
    value[field] = "0" * 64
    value["manifest"]["source_origin"][field] = "0" * 64
    forged = resign(value)
    with pytest.raises(ValueError, match="original tree"):
        validate_development_corpus_partition(reference=reference, partition=forged)


def test_rebinding_a_smaller_tree_cannot_omit_an_original_implementer(reference, tmp_path):
    smaller = partitioned_tree(
        tmp_path, files=tuple((p, b) for p, b in fixture_sources() if p != "src/SecondReserve.sol")
    ).material
    recipe = derive_development_corpus_partition(
        reference=smaller, primary_filenames=("src/Controller.sol",)
    )
    value = recipe.model_dump(mode="json")
    full = derive_development_corpus_partition(
        reference=reference, primary_filenames=("src/Controller.sol",)
    )
    for field in (
        "reference_manifest_sha256",
        "reference_tree_sha256",
        "reference_static_closure_sha256",
    ):
        value[field] = getattr(full, field)
        value["manifest"]["source_origin"][field] = getattr(full, field)
    with pytest.raises(ValueError, match="original tree"):
        validate_development_corpus_partition(reference=reference, partition=resign(value))


def test_legacy_selected_bytes_cannot_claim_full_tree_origin(reference):
    values = reference.model_dump(mode="json")
    values["manifest"] = freeze_development_corpus(
        corpus_id="synthetic-legacy-reference",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=reference.source_files,
    ).model_dump(mode="json")
    legacy = DevelopmentCorpusMaterial.model_validate_json(json.dumps(values), strict=True)
    with pytest.raises(ValueError, match="original tree"):
        derive_development_corpus_partition(
            reference=legacy, primary_filenames=("src/IReserve.sol",)
        )


@pytest.mark.parametrize("value", [False, 0, 1, "true", None])
def test_reference_replay_cannot_be_waived_or_coerced(reference, value):
    recipe = derive_development_corpus_partition(
        reference=reference, primary_filenames=("src/IReserve.sol",)
    )
    data = recipe.model_dump(mode="json")
    data["reference_replay_required"] = value
    with pytest.raises(ValueError):
        resign(data)


def test_recipe_byte_bounds_are_enforced_before_parsing(reference, monkeypatch):
    recipe = derive_development_corpus_partition(
        reference=reference, primary_filenames=("src/IReserve.sol",)
    )
    content = recipe.model_dump_json().encode()
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_PARTITION_BYTES", len(content) - 1)
    with pytest.raises(ValueError, match="byte bound"):
        read_development_corpus_partition(content)
    with pytest.raises(ValueError, match="byte bound"):
        derive_development_corpus_partition(
            reference=reference, primary_filenames=("src/IReserve.sol",)
        )


def test_legacy_one_ten_manifest_and_requests_match_retained_golden(tmp_path):
    golden = json.loads(
        (
            Path(__file__).parents[1]
            / "fixtures/solidity/dependency_call_closure/manifest_1_10_golden.json"
        ).read_text()
    )
    loaded = partitioned_tree(tmp_path, tuple(golden["primary_filenames"]))
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        source_custody=loaded,
        run_id=golden["run_id"],
        policy=DevelopmentCostPolicy.model_validate_json(json.dumps(golden["policy"]), strict=True),
    )
    assert loaded.material.manifest.manifest_sha256 == golden["manifest_sha256"]
    assert prepared.plan.plan_sha256 == golden["ensemble_plan_sha256"]
    assert prepared.candidate.plan.plan_sha256 == golden["candidate_plan_sha256"]
    assert "source_origin" not in loaded.material.manifest.model_dump(mode="json")
    assert [
        {
            "shard_id": s.shard_id,
            "request_bytes": s.estimate.request_bytes,
            "request_sha256": s.estimate.request_sha256,
            "request_id": s.estimate.request_id,
        }
        for s in prepared.candidate.shards
    ] == golden["shards"]
