"""Same-input synthetic control jitter retains failures, guarded evidence and every denominator."""

from __future__ import annotations

import json
import socket
import subprocess
from decimal import Decimal

import pytest
from jsonschema import Draft202012Validator

import mmaudit.benchmark.development_corpus_stability as stability
from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.benchmark.development_corpus_control_measurement import (
    measure_development_corpus_controls,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_benchmark_support import paired_observation, paired_response
from tests.development_corpus_control_measurement_support import direct_responses
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_stability_support import trial


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("stability evaluation attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def responses(hit=True, *, advisory=False):
    return (
        direct_responses(advisory=advisory)
        if hit
        else [paired_response(i, count=0) for i in range(1, 7)]
    )


def evaluate(pattern, *, advisory=()):
    return stability.measure_development_corpus_stability(
        measurements=tuple(
            trial(f"synthetic-trial-{i}", responses=responses(hit, advisory=i in advisory))
            for i, hit in enumerate(pattern)
        )
    )


@pytest.mark.parametrize(
    "pattern,classification,numerator,mean,variance",
    [
        ((True, True, True), "STABLE", 3, 1.0, 0.0),
        ((True, False, True), "INTERMITTENT", 2, 0.666666666667, 0.222222222222),
        ((False, False, True), "SINGLE_RUN", 1, 0.333333333333, 0.222222222222),
        ((False, False, False), "NEVER", 0, 0.0, 0.0),
    ],
)
def test_same_request_configuration_distinguishes_stable_intermittent_single_and_never(
    pattern, classification, numerator, mean, variance
):
    result = evaluate(pattern)
    group = result.combined
    root = next(c for c in group.controls if c.expected == "PLANTED")
    assert root.location.classification == root.assertion.classification == classification
    assert root.location.frequency.numerator == numerator
    assert root.location.frequency.denominator == 3
    assert group.mean_selected_run_location_coverage == mean
    assert group.population_variance_selected_run_location_coverage == variance
    assert group.mean_selected_run_assertion_coverage == mean
    assert len(result.cohorts) == 1 and len(result.pairs) == 3
    assert group.comparison_scope == "SAME_ORIGINAL_REQUEST_CONFIGURATION"
    assert result.accounted_cost_usd == Decimal("0.18")
    assert result.reported_actual_cost_usd == Decimal("0.18")
    assert result.sum_recorded_run_elapsed_seconds == 3
    assert not result.audit_complete and not result.findings_validated
    assert not result.qualification_eligible and not result.release_eligible
    assert result.trial_independence == result.predictive_stability == "NOT_ESTABLISHED"
    assert stability.read_development_corpus_stability(result.model_dump_json().encode()) == result


def test_advisory_and_guarded_controls_are_not_promoted_or_erased_across_runs():
    result = evaluate((True, True, False), advisory=(0,))
    group = result.combined
    root = next(c for c in group.controls if c.expected == "PLANTED")
    guarded = next(c for c in group.controls if c.expected == "GUARDED")
    assert root.location.positive_trial_indexes == (0, 1)
    assert root.assertion.positive_trial_indexes == (1,)
    assert root.location.classification == "INTERMITTENT"
    assert root.assertion.classification == "SINGLE_RUN"
    assert guarded.assertion.positive_trial_indexes == (1,)
    assert group.total_claim_count == 4
    assert group.guarded_advisory_claim_count == group.guarded_invariant_claim_count == 1
    assert group.pooled_per_trial_location_precision.numerator == 10
    assert group.pooled_per_trial_location_precision.denominator == 20
    assert group.pooled_per_trial_assertion_precision.numerator == 5
    assert group.pooled_per_trial_assertion_precision.denominator == 20
    high = next(s for s in group.severity if s.severity == "high")
    assert high.single_run_asserted_root_ids == (root.control_id,)
    assert high.guarded_assertion_control_ids == (guarded.control_id,)


@pytest.mark.parametrize("observed_count", [0, 1, 2, 3, 4, 5])
def test_unobserved_scope_keeps_all_selected_trials_and_never_becomes_a_known_miss(observed_count):
    binding, observation = paired_observation(
        observed_count=observed_count, responses=responses(False)
    )
    partial = score_development_corpus(binding=binding, observation=observation)
    result = stability.measure_development_corpus_stability(
        measurements=(
            trial("synthetic-complete", responses=responses()),
            trial("synthetic-partial", score=partial),
        )
    )
    root = next(c for c in result.combined.controls if c.expected == "PLANTED")
    assert root.location.frequency.denominator == 2
    assert root.location.frequency.value == (0.5 if observed_count >= 3 else None)
    assert root.location.unobserved_trial_indexes == (() if observed_count >= 3 else (1,))
    assert result.combined.union_location_coverage.value is None
    assert result.combined.mean_selected_run_location_coverage is None
    assert result.combined.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert len(result.trials[1].missing_accounting_request_ids) == 6 - observed_count
    assert len(result.trials[1].missing_runtime_request_ids) == 6 - observed_count


def test_empty_sets_are_not_perfect_jaccard_or_precision():
    result = evaluate((False, False))
    assert result.combined.union_location_coverage.value == 0
    assert result.combined.pooled_per_trial_location_precision.value is None
    assert result.pairs[0].location_jaccard.state == "EMPTY_DENOMINATOR"
    assert result.pairs[0].location_jaccard.value is None


def test_different_configuration_forms_separate_cohorts_without_fixed_config_variance():
    first = trial("synthetic-first", responses=responses())
    binding, observation = paired_observation(policy=selected_policy(timeout=99))
    second = trial(
        "synthetic-second", score=score_development_corpus(binding=binding, observation=observation)
    )
    result = stability.measure_development_corpus_stability(measurements=(first, second))
    assert len(result.cohorts) == 2
    assert result.combined.comparison_scope == "MIXED_CONFIGURATION_SCOPE_OR_TRANSPORT"
    assert result.combined.population_variance_selected_run_location_coverage is None
    assert not result.pairs[0].same_cohort
    assert all(g.mean_selected_run_location_coverage is None for g in result.cohorts)
    assert all(g.controls[0].location.classification == "NO_REPEATS" for g in result.cohorts)


@pytest.mark.parametrize("cumulative", [False, True])
def test_exact_duplicate_is_not_another_trial(cumulative):
    first = trial("synthetic-first", cumulative=cumulative)
    with pytest.raises(ValueError, match="reuses measurement"):
        stability.measure_development_corpus_stability(measurements=(first, first))


@pytest.mark.parametrize("kind", ["generation", "reservation"])
def test_relabelled_run_cannot_reuse_generation_or_accounting_evidence(kind):
    kw = {"keep_generations": kind == "generation", "keep_reservations": kind == "reservation"}
    values = (trial("synthetic-first", **kw), trial("synthetic-second", **kw))
    with pytest.raises(ValueError, match="reuses " + kind):
        stability.measure_development_corpus_stability(measurements=values)


def test_original_and_its_continuation_cannot_count_as_two_trials():
    resumed = trial("synthetic-first", cumulative=True)
    original = measure_development_corpus_controls(
        score=resumed.source_score.history.original_score
    )
    with pytest.raises(ValueError, match="reuses run"):
        stability.measure_development_corpus_stability(measurements=(original, resumed))


@pytest.mark.parametrize("complete", [False, True])
def test_distinct_continuation_chains_keep_every_original_and_unknown_liability(complete):
    values = tuple(
        trial(f"synthetic-chain-{i}", cumulative=True, complete=complete) for i in range(2)
    )
    result = stability.measure_development_corpus_stability(measurements=values)
    assert result.measurements == values
    assert (
        result.combined.comparison_scope
        == "SAME_REQUEST_CONFIGURATION_CONTINUATION_CHAINS_NOT_SINGLE_PASSES"
    )
    assert (
        result.trials[0].source_scope
        == result.trials[1].source_scope
        == "CUMULATIVE_RECORDED_ATTEMPTS"
    )
    assert result.accounted_cost_usd == sum(
        m.source_score.cumulative_summary.total_accounted_cost_usd for m in values
    )
    assert result.uncertain_accounted_cost_usd == sum(
        m.source_score.cumulative_summary.uncertain_accounted_cost_usd for m in values
    )
    assert all(len(t.unknown_actual_cost_request_ids) == int(not complete) for t in result.trials)
    assert all(len(t.run_ids) == 2 for t in result.trials)


def test_replacement_labels_are_not_merged_into_a_new_truth_denominator():
    first = trial("synthetic-first")
    binding, observation = paired_observation(both_planted=True)
    second = trial(
        "synthetic-second", score=score_development_corpus(binding=binding, observation=observation)
    )
    with pytest.raises(ValueError, match="same complete source and label bytes"):
        stability.measure_development_corpus_stability(measurements=(first, second))


@pytest.mark.parametrize("count", [0, 1, 9])
def test_trial_count_is_bounded_before_any_measurement_is_read(count):
    with pytest.raises(ValueError, match="bounded tuple"):
        stability.measure_development_corpus_stability(measurements=(None,) * count)


def test_eight_distinct_trials_and_all_28_pairs_are_retained():
    result = evaluate((True, False, True, False, True, False, True, False))
    assert len(result.measurements) == len(result.trials) == 8
    assert len(result.pairs) == 28
    assert result.combined.controls[0].location.frequency.denominator == 8


@pytest.mark.parametrize(
    "path,value",
    [
        (("combined", "total_claim_count"), 0),
        (("combined", "comparison_scope"), "MIXED_CONFIGURATION_SCOPE_OR_TRANSPORT"),
        (("trials", 0, "selected_request_count"), 1),
        (("reported_actual_cost_usd",), "0"),
        (("audit_complete",), True),
    ],
)
def test_resealing_a_changed_projection_or_authority_cannot_make_it_valid(path, value):
    result = evaluate((True, False))
    data = result.model_dump(mode="json")
    node = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    data["stability_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "stability_sha256"}
    )
    with pytest.raises(ValueError):
        stability.read_development_corpus_stability(json.dumps(data).encode())


@pytest.mark.parametrize("content", [b"", b"[]", b"null", b"{}{}", b'{"x":1,"x":2}', b"\xff"])
def test_reader_rejects_empty_ambiguous_wrong_shape_or_non_utf8_json(content):
    with pytest.raises(ValueError):
        stability.read_development_corpus_stability(content)


@pytest.mark.parametrize("content", ["{}", bytearray(b"{}"), {}, None])
def test_reader_accepts_only_original_immutable_bytes(content):
    with pytest.raises(ValueError):
        stability.read_development_corpus_stability(content)


def test_aggregate_input_bound_is_not_a_per_file_allowance(monkeypatch):
    values = (trial("synthetic-first"), trial("synthetic-second"))
    total = sum(len(v.model_dump_json().encode()) for v in values)
    monkeypatch.setattr(stability, "MAX_DEVELOPMENT_STABILITY_INPUT_BYTES", total)
    assert (
        stability.measure_development_corpus_stability(measurements=values).measurements == values
    )
    monkeypatch.setattr(stability, "MAX_DEVELOPMENT_STABILITY_INPUT_BYTES", total - 1)
    with pytest.raises(ValueError, match="aggregate input bound"):
        stability.measure_development_corpus_stability(measurements=values)


def test_reader_and_model_enforce_the_composed_output_bound(monkeypatch):
    result = evaluate((True, False))
    content = result.model_dump_json().encode()
    monkeypatch.setattr(stability, "MAX_DEVELOPMENT_STABILITY_BYTES", len(content))
    assert stability.read_development_corpus_stability(content) == result
    with pytest.raises(ValueError):
        stability.read_development_corpus_stability(content + b" ")
    monkeypatch.setattr(stability, "MAX_DEVELOPMENT_STABILITY_BYTES", len(content) - 1)
    with pytest.raises(ValueError, match="output bound"):
        stability.DevelopmentCorpusStability.model_validate_json(content, strict=True)


@pytest.mark.parametrize("values", [(1e308, 1e308), (float("inf"),), (float("nan"),)])
def test_elapsed_total_refuses_nonfinite_or_overflow_without_an_unhandled_numeric_error(values):
    with pytest.raises(ValueError, match="finite range"):
        stability._elapsed_total(values)


@pytest.mark.parametrize("size", [0, -1, True, "1", 128_000_001])
def test_selection_runtime_and_schema_refuse_invalid_individual_file_sizes(size):
    value = {
        "measurements": [
            {"path": "first.json", "size": size, "sha256": "0" * 64},
            {"path": "second.json", "size": 1, "sha256": "1" * 64},
        ]
    }
    with pytest.raises(ValueError):
        stability.read_development_stability_selection(json.dumps(value).encode())
    validator = Draft202012Validator(stability.DevelopmentStabilitySelection.model_json_schema())
    assert list(validator.iter_errors(value))


@pytest.mark.parametrize("kind", ["aggregate", "duplicate", "parent", "absolute", "count"])
def test_selection_rejects_unbounded_ambiguous_or_nonrelative_files(kind):
    first = {"path": "first.json", "size": 64_000_000, "sha256": "0" * 64}
    second = {"path": "second.json", "size": 64_000_000, "sha256": "1" * 64}
    if kind == "aggregate":
        second["size"] += 1
    elif kind == "duplicate":
        second["path"] = first["path"]
    elif kind == "parent":
        second["path"] = "../second.json"
    elif kind == "absolute":
        second["path"] = "/second.json"
    files = [first] if kind == "count" else [first, second]
    with pytest.raises(ValueError):
        stability.read_development_stability_selection(json.dumps({"measurements": files}).encode())


def test_eight_by_1024_critical_claim_weight_limit_remains_exact():
    result = stability.DevelopmentStabilityRatio(
        numerator=81_920, denominator=81_920, state="OBSERVED", value=1.0
    )
    assert result.numerator == result.denominator == 8 * 1024 * 10


@pytest.mark.parametrize("field", ["numerator", "denominator"])
def test_weighted_series_ratio_never_silently_clamps_excess_claim_weight(field):
    value = {"numerator": 81_920, "denominator": 81_920, "state": "OBSERVED", "value": 1.0}
    value[field] += 1
    with pytest.raises(ValueError):
        stability.DevelopmentStabilityRatio.model_validate(value)
