"""A context file or repaired run never retroactively becomes a successful first attempt."""

from __future__ import annotations

import hashlib
import json

import pytest

from mmaudit.models.development_corpus import DevelopmentCorpusObservation
from mmaudit.models.development_corpus_coverage import (
    DevelopmentCorpusCoverage,
    compute_development_corpus_coverage,
    read_development_corpus_coverage,
    read_development_coverage_record,
)
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    freeze_development_corpus_resume_history,
    prepare_development_corpus_resume,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_judgment_support import pure_candidate
from tests.unit.test_development_context_sources import partitioned_tree, prepared_partition


def candidate(loaded, *, run_id="synthetic-coverage", observed_count=None):
    prepared = prepared_partition(loaded, run_id=run_id)
    _, observation = pure_candidate(prepared=prepared, claims=0, observed_count=observed_count)
    data = observation.model_dump(mode="json")
    for shard in data["observations"]:
        shard["generation_id"] = f"gen-{run_id}-{shard['shard_id']}"
    for row in data["accounting"]:
        row["reservation_id"] = hashlib.sha256(f"{run_id}-{row['shard_id']}".encode()).hexdigest()[
            :32
        ]
    return prepared, DevelopmentCorpusObservation.model_validate_json(json.dumps(data), strict=True)


def history_with_completed_continuation(loaded):
    prepared, original = candidate(loaded, observed_count=0)
    history = freeze_development_corpus_resume_history(original=original, material=loaded.material)
    resumed = prepare_development_corpus_resume(
        history=history,
        endpoint_snapshot=prepared.shards[0].endpoint_snapshot,
        run_id="synthetic-coverage-continuation",
        source_custody=loaded,
    )
    _, full = pure_candidate(prepared=resumed.candidate, claims=0)
    attempt = DevelopmentCorpusResumeAttempt(
        plan=resumed.plan,
        transport="MOCK_HTTP",
        status="OBSERVED_ALL_SELECTED_SHARDS",
        stop_reason=None,
        observations=full.observations,
        accounting=full.accounting,
        elapsed_seconds=full.elapsed_seconds,
    )
    return freeze_development_corpus_resume_history(
        original=original, material=loaded.material, continuations=(attempt,)
    )


def test_empty_record_set_reports_every_frozen_source_unselected(tmp_path):
    loaded = partitioned_tree(tmp_path)
    coverage = compute_development_corpus_coverage(reference=loaded.material, records=())
    paths = tuple(s.filename for s in loaded.material.manifest.sources)
    assert (
        coverage.summary.unselected_paths
        == coverage.summary.not_successfully_observed_paths
        == paths
    )
    assert coverage.summary.status == "INCOMPLETE"
    assert not coverage.summary.original_first_attempt_complete
    assert read_development_corpus_coverage(coverage.model_dump_json().encode()) == coverage


def test_one_primary_response_keeps_all_context_only_files_unreviewed(tmp_path):
    loaded = partitioned_tree(tmp_path)
    _, observed = candidate(loaded)
    coverage = compute_development_corpus_coverage(reference=loaded.material, records=(observed,))
    context = tuple(s.filename for s in loaded.material.manifest.context_sources)
    assert observed.status == "OBSERVED_ALL_SHARDS"
    assert coverage.summary.status == "INCOMPLETE"
    assert coverage.summary.successful_primary_paths == ("src/Controller.sol",)
    assert coverage.summary.context_only_paths == coverage.summary.unselected_paths == context
    assert coverage.summary.not_successfully_observed_paths == context
    assert coverage.records[0] == observed
    assert not coverage.audit_complete and not coverage.qualification_eligible


def test_manifests_join_all_primaries_without_losing_context_or_duplicate_credit(tmp_path):
    first = partitioned_tree(tmp_path / "first")
    remaining = tuple(s.filename for s in first.material.manifest.context_sources)
    second = partitioned_tree(tmp_path / "second", remaining)
    _, a = candidate(first, run_id="coverage-first")
    _, b = candidate(second, run_id="coverage-second")
    result = compute_development_corpus_coverage(reference=first.material, records=(a, b))
    reverse = compute_development_corpus_coverage(reference=first.material, records=(b, a))
    assert result == reverse
    assert result.summary.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
    assert result.summary.original_first_attempt_complete
    assert result.summary.context_only_paths == result.summary.unselected_paths == ()
    assert result.summary.not_successfully_observed_paths == ()
    assert len(result.summary.successful_primary_paths) == 5
    assert not result.audit_complete and not result.findings_validated


def test_continuation_adds_cumulative_not_original_credit(tmp_path):
    loaded = partitioned_tree(tmp_path)
    history = history_with_completed_continuation(loaded)
    before = history.model_dump_json()
    coverage = compute_development_corpus_coverage(reference=loaded.material, records=(history,))
    assert coverage.summary.original_successful_primary_paths == ()
    assert coverage.summary.successful_primary_paths == ("src/Controller.sol",)
    assert coverage.run_coverage[0].missing_primary_paths == ()
    assert not coverage.summary.original_first_attempt_complete
    assert coverage.records[0].model_dump_json() == before
    assert history.original.completed_shard_count == 0
    assert read_development_coverage_record(history.model_dump_json().encode()) == history


def test_unattempted_primary_stays_missing_and_context_stays_unselected(tmp_path):
    loaded = partitioned_tree(tmp_path)
    _, original = candidate(loaded, observed_count=0)
    coverage = compute_development_corpus_coverage(reference=loaded.material, records=(original,))
    assert (
        coverage.summary.missing_primary_paths
        == coverage.summary.unobserved_primary_paths
        == ("src/Controller.sol",)
    )
    assert len(coverage.summary.unselected_paths) == 4
    assert len(coverage.summary.not_successfully_observed_paths) == 5


def test_later_original_success_cannot_hide_an_incomplete_original_run(tmp_path):
    from tests.unit.test_development_dependency_closure import fixture_sources

    loaded = partitioned_tree(tmp_path, tuple(path for path, _ in fixture_sources()))
    _, failed = candidate(loaded, run_id="synthetic-incomplete-original", observed_count=0)
    _, successful = candidate(loaded, run_id="synthetic-complete-original")
    coverage = compute_development_corpus_coverage(
        reference=loaded.material, records=(failed, successful)
    )
    assert coverage.summary.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
    assert not coverage.summary.original_first_attempt_complete
    assert len(coverage.summary.successful_primary_paths) == 5
    assert any(record == failed for record in coverage.records)


@pytest.mark.parametrize("kind", ["record", "ancestor", "generation", "reservation"])
def test_duplicate_or_overlapping_evidence_is_refused_not_counted_twice(tmp_path, kind):
    loaded = partitioned_tree(tmp_path)
    if kind == "ancestor":
        history = history_with_completed_continuation(loaded)
        records = (history.original, history)
    else:
        _, first = candidate(loaded, run_id="coverage-first")
        _, second = candidate(loaded, run_id="coverage-second")
        if kind == "record":
            records = (first, first)
        else:
            data = second.model_dump(mode="json")
            field, collection = (
                ("generation_id", "observations")
                if kind == "generation"
                else ("reservation_id", "accounting")
            )
            data[collection][0][field] = first.model_dump(mode="json")[collection][0][field]
            second = DevelopmentCorpusObservation.model_validate_json(json.dumps(data), strict=True)
            records = (first, second)
    with pytest.raises(ValueError, match="overlap"):
        compute_development_corpus_coverage(reference=loaded.material, records=records)


def test_changed_context_invalidates_primary_credit_and_records_exact_source_drift(tmp_path):
    old = partitioned_tree(tmp_path / "old")
    _, observation = candidate(old)
    context = old.material.manifest.context_sources[0].filename
    changed = tuple(
        (name, raw + b"// Synthetic changed source snapshot.\n" if name == context else raw)
        for name, raw in old.material.source_files
    )
    current = partitioned_tree(tmp_path / "current", files=changed)
    result = compute_development_corpus_coverage(reference=current.material, records=(observation,))
    assert result.summary.source_drift_paths == (context,)
    assert result.summary.successful_primary_paths == ()
    assert result.summary.invalidated_primary_paths == ("src/Controller.sol",)
    assert result.run_coverage[0].identity_shortfalls == (
        "SOURCE_BYTES_DIFFER",
        "TREE_IDENTITY_DIFFERS",
    )
    assert result.summary.status == "INCOMPLETE"


@pytest.mark.parametrize(
    "field",
    [
        "status",
        "original_first_attempt_complete",
        "successful_primary_paths",
        "context_only_paths",
        "unselected_paths",
        "not_successfully_observed_paths",
        "missing_primary_paths",
        "source_drift_paths",
    ],
)
def test_rehashed_coverage_cannot_hide_a_gap_or_invent_a_primary_response(tmp_path, field):
    loaded = partitioned_tree(tmp_path)
    _, observation = candidate(loaded, observed_count=0)
    coverage = compute_development_corpus_coverage(
        reference=loaded.material, records=(observation,)
    )
    data = coverage.model_dump(mode="json")
    value = data["summary"][field]
    data["summary"][field] = (
        "ALL_PRIMARY_RESPONSES_OBSERVED"
        if field == "status"
        else True
        if field == "original_first_attempt_complete"
        else []
        if value
        else ["src/Controller.sol"]
    )
    data["coverage_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "coverage_sha256"}
    )
    with pytest.raises(ValueError, match="hides or changes"):
        DevelopmentCorpusCoverage.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize("value", [False, 0, 1, "true"])
def test_root_replay_cannot_be_removed_or_coerced(tmp_path, value):
    loaded = partitioned_tree(tmp_path)
    coverage = compute_development_corpus_coverage(reference=loaded.material, records=())
    data = coverage.model_dump(mode="json")
    data["root_replay_required"] = value
    with pytest.raises(ValueError):
        DevelopmentCorpusCoverage.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize(
    "kind",
    [
        "record_limit",
        "bytes_limit",
        "source_replay_limit",
        "selected_only_reference",
        "record_type",
    ],
)
def test_coverage_capacity_or_missing_reference_refuses_instead_of_trimming(
    tmp_path, monkeypatch, kind
):
    import mmaudit.models.development_corpus_coverage as model
    from mmaudit.models.development_corpus import (
        DevelopmentCorpusMaterial,
        freeze_development_corpus,
    )

    loaded = partitioned_tree(tmp_path)
    _, observed = candidate(loaded)
    reference, records = loaded.material, (observed,)
    if kind == "record_limit":
        monkeypatch.setattr(model, "MAX_DEVELOPMENT_COVERAGE_RUNS", 0)
    elif kind == "bytes_limit":
        monkeypatch.setattr(model, "MAX_DEVELOPMENT_COVERAGE_BYTES", 1)
    elif kind == "source_replay_limit":
        monkeypatch.setattr(
            model, "MAX_DEVELOPMENT_COVERAGE_BYTES", reference.manifest.total_source_bytes
        )
        with pytest.raises(ValueError, match="source replay work"):
            model._project(reference, records)
        return
    elif kind == "selected_only_reference":
        manifest = freeze_development_corpus(
            corpus_id="synthetic-selected",
            source_scope=reference.manifest.source_scope,
            source_files=reference.source_files,
        )
        reference = DevelopmentCorpusMaterial(manifest=manifest, sources=reference.sources)
    else:
        records = ({"untrusted": "not an observation"},)
    with pytest.raises(ValueError):
        compute_development_corpus_coverage(reference=reference, records=records)
