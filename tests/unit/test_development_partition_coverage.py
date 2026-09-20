"""Derived roots need an exact original-tree recipe before any primary response gets credit."""

from __future__ import annotations

import json

import pytest

from mmaudit.models import development_corpus_coverage as module
from mmaudit.models.development_corpus_coverage import (
    DevelopmentCorpusCoverage,
    compute_development_corpus_coverage,
    read_development_corpus_coverage,
)
from mmaudit.models.development_corpus_partition import derive_development_corpus_partition
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.development_corpus_partition import materialize_development_corpus_partition
from tests.integration.test_development_partition_custody import bundle
from tests.unit.test_development_context_sources import partitioned_tree
from tests.unit.test_development_corpus_coverage import candidate


def test_minimal_bundles_cover_every_original_primary_without_relabeling_context(tmp_path):
    reference = partitioned_tree(tmp_path / "original")
    recipes = []
    records = []
    for index, source in enumerate(reference.material.manifest.sources):
        recipe = derive_development_corpus_partition(
            reference=reference.material, primary_filenames=(source.filename,)
        )
        loaded = materialize_development_corpus_partition(
            reference=reference, partition=recipe, output_dir=tmp_path / f"bundle-{index}"
        )
        _, observed = candidate(loaded, run_id=f"synthetic-bundle-{index}")
        recipes.append(recipe)
        records.append(observed)
    covered = compute_development_corpus_coverage(
        reference=reference.material, records=tuple(records), partitions=tuple(recipes)
    )
    assert covered.summary.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
    assert covered.summary.original_first_attempt_complete
    assert covered.summary.unselected_paths == covered.summary.context_only_paths == ()
    assert covered.summary.successful_primary_paths == tuple(
        s.filename for s in reference.material.manifest.sources
    )
    assert len(covered.records) == len(covered.partitions) == 5
    assert not covered.audit_complete and not covered.findings_validated
    assert (
        compute_development_corpus_coverage(
            reference=reference.material,
            records=tuple(reversed(records)),
            partitions=tuple(reversed(recipes)),
        )
        == covered
    )
    assert read_development_corpus_coverage(covered.model_dump_json().encode()) == covered


def test_same_namespace_does_not_excuse_missing_origin_recipe(tmp_path):
    reference, recipe, loaded = bundle(tmp_path, ("src/Controller.sol",))
    assert recipe.manifest.source_tree_evidence == reference.material.manifest.source_tree_evidence
    _, record = candidate(loaded)
    uncovered = compute_development_corpus_coverage(reference=reference.material, records=(record,))
    assert uncovered.summary.successful_primary_paths == ()
    assert uncovered.run_coverage[0].identity_shortfalls == ("SOURCE_ORIGIN_NOT_REPLAYED",)
    covered = compute_development_corpus_coverage(
        reference=reference.material, records=(record,), partitions=(recipe,)
    )
    assert covered.summary.successful_primary_paths == ("src/Controller.sol",)
    assert covered.summary.status == "INCOMPLETE"


@pytest.mark.parametrize("kind", ["duplicate", "unused", "empty", "wrong_type", "too_many"])
def test_partition_population_refuses_duplicates_unrelated_or_unbounded_recipes(tmp_path, kind):
    reference, recipe, loaded = bundle(tmp_path)
    _, record = candidate(loaded)
    selected = (
        (recipe, recipe)
        if kind == "duplicate"
        else ()
        if kind == "empty"
        else [recipe]
        if kind == "wrong_type"
        else (recipe,) * 257
        if kind == "too_many"
        else (
            derive_development_corpus_partition(
                reference=reference.material, primary_filenames=("src/Reserve.sol",)
            ),
        )
    )
    with pytest.raises(ValueError):
        compute_development_corpus_coverage(
            reference=reference.material, records=(record,), partitions=selected
        )


def test_changed_omitted_original_source_cannot_reuse_a_recipe(tmp_path):
    reference, recipe, loaded = bundle(tmp_path / "first")
    _, record = candidate(loaded)
    files = tuple(
        (p, b + b"\n" if p == "src/Controller.sol" else b)
        for p, b in reference.material.source_files
    )
    other = partitioned_tree(tmp_path / "other", files=files)
    assert (
        dict(loaded.material.source_files)["src/IReserve.sol"]
        == dict(other.material.source_files)["src/IReserve.sol"]
    )
    with pytest.raises(ValueError, match="original tree"):
        compute_development_corpus_coverage(
            reference=other.material, records=(record,), partitions=(recipe,)
        )


@pytest.mark.parametrize(
    "kind", ["version", "missing", "null", "stripped_and_downgraded", "summary"]
)
def test_coverage_cannot_drop_origin_evidence_while_retaining_credit(tmp_path, kind):
    reference, recipe, loaded = bundle(tmp_path)
    _, record = candidate(loaded)
    covered = compute_development_corpus_coverage(
        reference=reference.material, records=(record,), partitions=(recipe,)
    )
    data = covered.model_dump(mode="json")
    if kind == "version":
        data["schema_version"] = "1.0"
    elif kind in {"missing", "stripped_and_downgraded"}:
        data.pop("partitions")
        if kind == "stripped_and_downgraded":
            data["schema_version"] = "1.0"
    elif kind == "null":
        data["partitions"] = None
    else:
        data["summary"]["successful_primary_paths"] = []
    data["coverage_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "coverage_sha256"}
    )
    with pytest.raises(ValueError):
        DevelopmentCorpusCoverage.model_validate_json(json.dumps(data), strict=True)


def test_partition_replay_source_bytes_are_part_of_the_whole_work_bound(tmp_path, monkeypatch):
    reference, recipe, loaded = bundle(tmp_path)
    _, record = candidate(loaded)
    limit = reference.material.manifest.total_source_bytes + 2 * recipe.manifest.total_source_bytes
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_COVERAGE_BYTES", limit - 1)
    with pytest.raises(ValueError, match="source replay work"):
        module._project(reference.material, (record,), (recipe,))


def test_derived_bundle_cannot_replace_the_original_coverage_reference(tmp_path):
    _, _, loaded = bundle(tmp_path)
    _, record = candidate(loaded)
    with pytest.raises(ValueError, match="complete-tree reference"):
        compute_development_corpus_coverage(reference=loaded.material, records=(record,))
