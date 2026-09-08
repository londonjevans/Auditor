"""Observed root unions retain costs and missing scope; never an ensemble or lineage verdict."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from mmaudit.benchmark.development import DevelopmentBenchmarkScore
from mmaudit.benchmark.development_comparison import (
    DevelopmentBenchmarkComparison,
    compare_development_scores,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_comparison_support import comparison_score


def reseal(value):
    value["comparison_sha256"] = canonical_sha256(
        {key: item for key, item in value.items() if key != "comparison_sha256"}
    )
    return json.dumps(value)


def test_shared_roots_count_once_and_every_duplicate_remains_in_the_denominator():
    scores = (comparison_score("run-b"), comparison_score("run-a"))
    result = compare_development_scores(scores)
    assert tuple(row.run_id for row in result.rows) == ("run-a", "run-b")
    assert len(result.union.matched_root_ids) == len(result.union.shared_root_ids) == 1
    assert result.union.total_claim_count == 6
    assert result.union.unique_root_recall.value == 1
    assert result.union.all_claim_unique_root_fraction.value == 0.166667
    assert result.union.first_attempt_shard_completion.denominator == 6
    assert (
        result.union.sum_reported_actual_cost_usd
        == result.union.sum_accounted_cost_usd
        == Decimal("0.06")
    )
    assert result.union.sum_run_elapsed_seconds == 0.2
    assert result.union.executed_ensemble_wall_clock_seconds is None
    assert all(row.roots_unique_to_run == () for row in result.rows)
    assert all(
        row.roots_shared_with_other_runs == result.union.shared_root_ids for row in result.rows
    )
    assert [row.summary for row in result.rows] == [score.summary for score in reversed(scores)]
    assert result == compare_development_scores(tuple(reversed(scores)))
    assert result == DevelopmentBenchmarkComparison.model_validate_json(result.model_dump_json())


def test_root_unique_to_one_run_is_explicit_and_does_not_invent_another_root():
    result = compare_development_scores(
        (comparison_score(), comparison_score("run-b", mode="empty"))
    )
    assert result.rows[0].roots_unique_to_run == result.union.matched_root_ids
    assert result.rows[1].roots_unique_to_run == result.union.shared_root_ids == ()
    assert result.union.total_claim_count == 3
    assert result.union.all_claim_unique_root_fraction.value == 0.333333
    assert result.rows[1].summary.unique_root_recall.value == 0


@pytest.mark.parametrize("mode", ["empty", "advisory", "matched"])
def test_guarded_variant_never_turns_an_empty_truth_denominator_into_perfect_recall(mode):
    result = compare_development_scores(
        tuple(comparison_score(f"run-{n}", variant="b", mode=mode) for n in range(2))
    )
    assert result.union.expected_root_ids == result.union.matched_root_ids == ()
    assert result.union.unique_root_recall.value is None
    assert result.union.unique_root_recall.state == "EMPTY_DENOMINATOR"
    assert result.union.guarded_control_claim_count == (6 if mode == "matched" else 0)
    assert result.union.all_claim_unique_root_fraction.value == (None if mode == "empty" else 0)


@pytest.mark.parametrize("failure", ["known", "unknown", "overrun", "reserved"])
def test_partial_run_retains_exact_accounting_and_suppresses_union_quality(failure):
    complete, partial = comparison_score(), comparison_score("run-b", failure=failure)
    result = compare_development_scores((complete, partial))
    assert result.union.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert result.union.incomplete_run_ids == ("run-b",)
    assert result.union.unique_root_recall.value is None
    assert result.union.all_claim_unique_root_fraction.value is None
    assert result.union.first_attempt_shard_completion.numerator == 4
    assert result.union.first_attempt_shard_completion.denominator == 6
    assert result.union.sum_accounted_cost_usd == sum(
        score.summary.accounted_cost_usd for score in (complete, partial)
    )
    assert result.union.sum_reported_actual_cost_usd == sum(
        score.summary.reported_actual_cost_usd for score in (complete, partial)
    )
    assert (
        result.union.sum_uncertain_accounted_cost_usd
        == partial.summary.uncertain_accounted_cost_usd
    )
    assert result.union.sum_active_reserved_usd == partial.summary.active_reserved_usd
    assert result.rows[1].summary == partial.summary


@pytest.mark.parametrize("count", [0, 1, 9])
def test_input_count_is_bounded_before_validation(count):
    with pytest.raises(ValueError, match="two through eight"):
        compare_development_scores(tuple(comparison_score(f"run-{n}") for n in range(count)))


def test_eight_runs_are_bounded_without_duplicate_root_credit():
    result = compare_development_scores(tuple(comparison_score(f"run-{n}") for n in range(8)))
    assert len(result.rows) == 8 and len(result.union.matched_root_ids) == 1
    assert (
        result.union.total_claim_count
        == result.union.first_attempt_shard_completion.denominator
        == 24
    )
    assert result.union.sum_accounted_cost_usd == Decimal("0.24")


@pytest.mark.parametrize("change", ["corpus", "transport", "run", "generation", "reservation"])
def test_incompatible_or_reused_evidence_cannot_form_a_comparison(change):
    first = comparison_score()
    second = comparison_score("run-b", variant="b" if change == "corpus" else "a")
    if change == "run":
        second = first
    elif change in {"transport", "generation", "reservation"}:
        raw = second.model_dump(mode="json")
        observation = raw["observation"]
        if change == "transport":
            observation["transport"] = "HTTP_OBSERVATION"
            for item in observation["observations"]:
                item["transport"] = "HTTP_OBSERVATION"
        elif change == "generation":
            observation["observations"][0]["generation_id"] = first.observation.observations[
                0
            ].generation_id
        else:
            observation["accounting"][0]["reservation_id"] = first.observation.accounting[
                0
            ].reservation_id
        raw["observation_sha256"] = canonical_sha256(observation)
        second = DevelopmentBenchmarkScore.model_validate_json(json.dumps(raw))
    with pytest.raises(ValueError, match="development comparison"):
        compare_development_scores((first, second))


def test_equal_error_body_hashes_do_not_prove_a_shared_request_or_erase_costs():
    scores = []
    for run_id in ("run-a", "run-b"):
        raw = comparison_score(run_id, failure="known").model_dump(mode="json")
        raw["observation"]["observations"][1]["response_sha256"] = "a" * 64
        raw["observation"]["observations"][1]["generation_id"] = None
        raw["observation_sha256"] = canonical_sha256(raw["observation"])
        scores.append(DevelopmentBenchmarkScore.model_validate_json(json.dumps(raw)))
    result = compare_development_scores(tuple(scores))
    assert result.union.sum_accounted_cost_usd == Decimal("0.04")
    assert result.union.quality_scope == "INCOMPLETE_OBSERVATIONS"


def test_failed_duplicate_generation_inside_one_run_remains_failure_evidence():
    raw = comparison_score("run-b", failure="known").model_dump(mode="json")
    observations = raw["observation"]["observations"]
    observations[1]["generation_id"] = observations[0]["generation_id"]
    raw["observation_sha256"] = canonical_sha256(raw["observation"])
    score = DevelopmentBenchmarkScore.model_validate_json(json.dumps(raw))
    result = compare_development_scores((comparison_score(), score))
    assert result.union.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert result.union.sum_accounted_cost_usd == Decimal("0.05")


@pytest.mark.parametrize(
    "change",
    ["rows", "roots", "cost", "runtime", "scope", "denominator", "input_hash", "score", "order"],
)
def test_resealing_derived_or_nested_tampering_does_not_make_it_valid(change):
    raw = compare_development_scores((comparison_score(), comparison_score("run-b"))).model_dump(
        mode="json"
    )
    if change == "rows":
        raw["rows"][0]["roots_unique_to_run"] = raw["union"]["matched_root_ids"]
    elif change == "roots":
        raw["union"]["matched_root_ids"] = []
    elif change == "cost":
        raw["union"]["sum_accounted_cost_usd"] = "0"
    elif change == "runtime":
        raw["union"]["sum_run_elapsed_seconds"] = 0
    elif change == "scope":
        raw["union"]["incomplete_run_ids"] = ["run-a"]
    elif change == "denominator":
        raw["union"]["all_claim_unique_root_fraction"].update(numerator=1, denominator=1, value=1)
    elif change == "input_hash":
        raw["rows"][0]["score_sha256"] = "a" * 64
    elif change == "score":
        raw["scores"][0]["summary"]["matched_root_ids"] = []
    else:
        raw["scores"].reverse()
    with pytest.raises(ValidationError):
        DevelopmentBenchmarkComparison.model_validate_json(reseal(raw))


@pytest.mark.parametrize(
    "field", ["audit_complete", "findings_validated", "qualification_eligible", "release_eligible"]
)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_no_resealed_authority_promotion_or_boolean_coercion(field, value):
    raw = compare_development_scores((comparison_score(), comparison_score("run-b"))).model_dump(
        mode="json"
    )
    raw[field] = value
    with pytest.raises(ValidationError):
        DevelopmentBenchmarkComparison.model_validate_json(reseal(raw))


@pytest.mark.parametrize(
    "field", ["lineage_independence", "request_and_budget_parity", "superiority"]
)
def test_model_names_or_a_union_do_not_supply_missing_experiment_evidence(field):
    raw = compare_development_scores((comparison_score(), comparison_score("run-b"))).model_dump(
        mode="json"
    )
    raw[field] = "ESTABLISHED"
    with pytest.raises(ValidationError):
        DevelopmentBenchmarkComparison.model_validate_json(reseal(raw))


def test_a_hypothetical_union_cannot_acquire_executed_ensemble_wall_clock():
    raw = compare_development_scores((comparison_score(), comparison_score("run-b"))).model_dump(
        mode="json"
    )
    raw["union"]["executed_ensemble_wall_clock_seconds"] = 0.1
    with pytest.raises(ValidationError):
        DevelopmentBenchmarkComparison.model_validate_json(reseal(raw))


def test_direct_forged_score_cannot_skip_existing_validation():
    first = comparison_score()
    forged = first.model_copy(
        update={"summary": first.summary.model_copy(update={"total_claim_count": 0})}
    )
    with pytest.raises(ValidationError):
        compare_development_scores((forged, comparison_score("run-b")))


@pytest.mark.parametrize("kind", ["list", "wrong_type", "oversized"])
def test_public_comparison_boundary_rejects_wrong_types_and_oversized_scores(monkeypatch, kind):
    import mmaudit.benchmark.development_comparison as comparison_module

    scores = (comparison_score(), comparison_score("run-b"))
    if kind == "list":
        scores = list(scores)
    elif kind == "wrong_type":
        scores = (scores[0], scores[1].model_dump(mode="json"))
    else:
        monkeypatch.setattr(comparison_module, "MAX_DEVELOPMENT_COMPARISON_SCORE_BYTES", 16)
    with pytest.raises(ValueError):
        compare_development_scores(scores)


def test_distinct_model_names_do_not_prove_lineage_independence_or_a_controlled_comparison():
    # Coherently changed labels remain unverified input, not an authenticated provider request.
    data = comparison_score("run-b").model_dump(mode="json")
    plan = data["observation"]["plan"]
    for shard, observation in zip(plan["shards"], data["observation"]["observations"], strict=True):
        shard["estimate"]["exact_model_id"] = "synthetic/second-model"
        observation["estimate"]["exact_model_id"] = "synthetic/second-model"
    plan["plan_sha256"] = canonical_sha256(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    )
    data["binding"]["plan_sha256"] = plan["plan_sha256"]
    data["observation_sha256"] = canonical_sha256(data["observation"])
    other = DevelopmentBenchmarkScore.model_validate_json(json.dumps(data))
    result = compare_development_scores((comparison_score(), other))
    assert len({row.exact_model_id for row in result.rows}) == 2
    assert result.lineage_independence == result.request_and_budget_parity == "NOT_ESTABLISHED"
    assert result.superiority == "NOT_EVALUATED"


def test_overflowing_aggregate_duration_refuses_instead_of_serializing_infinity():
    scores = []
    for name in ("run-a", "run-b"):
        data = comparison_score(name).model_dump(mode="json")
        data["observation"]["elapsed_seconds"] = data["summary"]["elapsed_seconds"] = 1e308
        data["observation_sha256"] = canonical_sha256(data["observation"])
        scores.append(DevelopmentBenchmarkScore.model_validate_json(json.dumps(data)))
    with pytest.raises(ValueError, match="durations"):
        compare_development_scores(tuple(scores))


@pytest.mark.parametrize(
    "change", ["extra", "empty", "count", "lineage", "wall_clock", "authority"]
)
def test_public_comparison_schema_is_canonical_closed_and_bounded(change):
    from scripts.generate_release_schemas import MODELS, rendered_schema

    filename = "development_benchmark_comparison.schema.json"
    content = (Path(__file__).parents[2] / "schemas" / filename).read_text()
    assert content == rendered_schema(filename, MODELS[filename])
    schema = json.loads(content)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    value = compare_development_scores((comparison_score(), comparison_score("run-b"))).model_dump(
        mode="json"
    )
    assert validator.is_valid(value)
    if change == "extra":
        value["private_authority"] = True
    elif change == "empty":
        value["scores"] = []
    elif change == "count":
        value["scores"] *= 5
    elif change == "lineage":
        value["lineage_independence"] = "ESTABLISHED"
    elif change == "wall_clock":
        value["union"]["executed_ensemble_wall_clock_seconds"] = 0
    else:
        value["audit_complete"] = True
    assert not validator.is_valid(value)
