"""Source-pinned local measurement controls; no model or external truth claims."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.development import (
    DEVELOPMENT_TRUTH_PINS,
    DevelopmentBenchmarkScore,
    DevelopmentBenchmarkTruth,
    DevelopmentMeasurementRatio,
    bind_development_benchmark,
    read_development_benchmark_truth,
    score_development_audit,
)
from mmaudit.models.development_audit import DevelopmentAuditObservation
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_audit_support import CORPUS_ROOT, audit_case
from tests.development_benchmark_support import (
    benchmark_truth,
    scored_audit_case,
    scored_file_response,
    scored_observation,
)


def measured(*, variant="a", responses=None):
    observation = scored_observation(variant=variant, responses=responses)
    binding = bind_development_benchmark(plan=observation.plan, truth=benchmark_truth(variant))
    return score_development_audit(binding=binding, observation=observation)


@pytest.mark.parametrize("variant", ["a", "b"])
def test_frozen_truth_is_explicitly_nonqualifying_and_pinned_before_response(variant):
    truth = benchmark_truth(variant)
    assert (
        canonical_sha256(truth.model_dump(mode="json"))
        == DEVELOPMENT_TRUTH_PINS[truth.corpus_id][1]
    )
    assert truth.provenance == "AGENT_CONSTRUCTED_PUBLIC_LABELLED_DEVELOPMENT_CONTROL"
    assert "NOT_EXTERNAL_OR_EXHAUSTIVE" in truth.truth_scope
    assert truth.controls[0].expected == ("PLANTED" if variant == "a" else "GUARDED")
    assert truth.qualification_eligible is truth.audit_complete is truth.findings_validated is False


@pytest.mark.parametrize("change", ["whitespace", "label", "origin", "source", "authority"])
def test_changed_truth_is_not_admitted_even_if_it_is_valid_json(change):
    content = (CORPUS_ROOT / "truth-a.json").read_bytes()
    value = json.loads(content)
    if change == "label":
        value["controls"][0]["expected"] = "GUARDED"
    elif change == "origin":
        value["controls"][0]["origin"]["line_start"] = 41
    elif change == "source":
        value["sources"][0]["sha256"] = "a" * 64
    elif change == "authority":
        value["qualification_eligible"] = True
    changed = content + b" " if change == "whitespace" else json.dumps(value).encode()
    with pytest.raises(ValueError, match="not frozen"):
        read_development_benchmark_truth(changed)
    if change != "whitespace":
        with pytest.raises(ValidationError):
            DevelopmentBenchmarkTruth.model_validate_json(changed)


@pytest.mark.parametrize("change", ["v1", "corpus", "forged_truth"])
def test_pre_dispatch_binding_refuses_wrong_version_source_or_constructed_bypass(change):
    plan = scored_audit_case().plan
    truth = benchmark_truth()
    if change == "v1":
        plan = audit_case().plan
    elif change == "corpus":
        truth = benchmark_truth("b")
    else:
        truth = truth.model_copy(update={"controls": ()})
    with pytest.raises(ValueError):
        bind_development_benchmark(plan=plan, truth=truth)


def test_repeated_primary_and_cross_file_consequences_count_one_root():
    score = measured()
    summary = score.summary
    assert len(summary.matched_root_ids) == 1
    assert summary.total_claim_count == summary.invariant_claim_count == 3
    assert summary.duplicate_claim_count == 2
    assert summary.unmatched_invariant_claim_count == 0
    assert summary.unique_root_recall.value == summary.severity_weighted_root_recall.value == 1
    assert summary.all_claim_unique_root_fraction.value == 0.333333
    assert summary.severity_weighted_structural_precision.value == 0.333333
    assert summary.first_attempt_shard_completion.value == 1
    assert summary.accounted_cost_usd == summary.reported_actual_cost_usd == Decimal("0.03")
    assert summary.uncertain_accounted_cost_usd == summary.active_reserved_usd == 0
    assert score.observation_sha256 == canonical_sha256(score.observation.model_dump(mode="json"))
    assert DevelopmentBenchmarkScore.model_validate_json(score.model_dump_json()) == score
    assert (
        score.qualification_eligible is score.release_eligible is score.findings_validated is False
    )


@pytest.mark.parametrize("change", ["class", "origin_file", "origin_anchor", "primary_site"])
def test_origin_label_alone_cannot_match_a_claim(change):
    responses = tuple(scored_file_response(i) for i in range(1, 4))
    for response in responses:
        finding = response["findings"][0]
        if change == "class":
            finding["vulnerability_class"] = "accounting"
        elif change == "origin_file":
            finding["root_cause_ref"]["filename"] = "UnitStore.sol"
        elif change == "origin_anchor":
            finding["root_cause_ref"]["line_start"] = 41
        else:
            finding.update(line_start=1, line_end=2)
    score = measured(responses=responses)
    assert score.summary.unmatched_invariant_claim_count == 3
    assert score.summary.matched_root_ids == ()
    assert len(score.summary.observed_missed_root_ids) == 1
    assert score.summary.unique_root_recall.value == 0
    assert score.summary.all_claim_unique_root_fraction.value == 0


def test_advisory_relabeling_cannot_erase_claims_or_turn_a_missed_root_into_credit():
    responses = tuple(scored_file_response(i, advisory=True) for i in range(1, 4))
    score = measured(responses=responses)
    assert score.summary.total_claim_count == score.summary.advisory_claim_count == 3
    assert score.summary.advisories_at_planted_sites_count == 3
    assert score.summary.invariant_claim_count == score.summary.duplicate_claim_count == 0
    assert (
        len(score.summary.unmatched_expected_root_ids)
        == len(score.summary.observed_missed_root_ids)
        == 1
    )
    assert score.summary.unique_root_recall.value == 0
    assert score.summary.all_claim_unique_root_fraction.denominator == 3
    assert score.summary.severity_weighted_structural_precision.denominator == 15
    assert all(claim.weight == 5 for claim in score.claims)


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "informational"])
def test_root_and_duplicate_weights_are_frozen_not_response_authored(severity):
    responses = tuple(scored_file_response(i) for i in range(1, 4))
    for response in responses:
        response["findings"][0]["severity"] = severity
    score = measured(responses=responses)
    assert score.summary.severity_weighted_root_recall.numerator == 5
    assert score.summary.severity_weighted_structural_precision.denominator == 15
    assert score.summary.all_claim_unique_root_fraction.value == 0.333333


def test_duplicate_spam_never_increases_root_count_or_disappears_from_precision():
    responses = tuple(scored_file_response(i) for i in range(1, 4))
    for response in responses:
        response["findings"] *= 16
    score = measured(responses=responses)
    assert score.summary.total_claim_count == 48
    assert score.summary.duplicate_claim_count == 47
    assert len(score.summary.matched_root_ids) == 1
    assert score.summary.all_claim_unique_root_fraction.value == 0.020833
    assert score.summary.severity_weighted_structural_precision.denominator == 240


def test_guarded_empty_response_has_no_false_perfect_precision_or_recall():
    responses = tuple(scored_file_response(i) for i in range(1, 4))
    for response in responses:
        response["findings"] = []
    score = measured(variant="b", responses=responses)
    assert score.summary.expected_root_ids == score.summary.matched_root_ids == ()
    assert score.summary.total_claim_count == 0
    assert score.summary.unique_root_recall.state == "EMPTY_DENOMINATOR"
    assert score.summary.unique_root_recall.value is None
    assert score.summary.severity_weighted_structural_precision.value is None
    assert score.summary.first_attempt_shard_completion.value == 1


def test_claiming_the_guarded_control_as_a_violation_is_unmatched_not_deduplicated():
    score = measured(variant="b")
    assert (
        score.summary.guarded_control_claim_count
        == score.summary.unmatched_invariant_claim_count
        == 3
    )
    assert score.summary.duplicate_claim_count == 0
    assert score.summary.matched_root_ids == ()
    assert score.summary.severity_weighted_structural_precision.value == 0


def test_unmatched_advisories_and_informationals_always_remain_in_the_denominator():
    responses = tuple(scored_file_response(i, advisory=True) for i in range(1, 4))
    for response in responses:
        response["findings"][0].update(line_start=1, line_end=2)
    score = measured(responses=responses)
    assert score.summary.advisory_claim_count == score.summary.total_claim_count == 3
    assert score.summary.advisories_at_planted_sites_count == 0
    assert score.summary.severity_weighted_structural_precision.denominator == 3
    assert all(claim.weight == 1 for claim in score.claims)


def test_partial_scope_keeps_known_costs_and_missing_denominators_without_quality_value():
    observation = scored_observation()
    data = observation.model_dump(mode="json")
    data.update(
        observations=data["observations"][:1],
        accounting=data["accounting"][:1],
        status="INCOMPLETE",
        stop_reason="LOCAL_FAILURE",
        completed_shard_count=1,
        unobserved_shard_ids=["file-02", "file-03"],
        total_accounted_cost_usd="0.01",
    )
    partial = DevelopmentAuditObservation.model_validate_json(json.dumps(data))
    score = score_development_audit(
        binding=bind_development_benchmark(plan=partial.plan, truth=benchmark_truth()),
        observation=partial,
    )
    assert score.summary.first_attempt_shard_completion.value == 0.333333
    assert score.summary.unique_root_recall.numerator == 1
    assert score.summary.unique_root_recall.state == "INCOMPLETE_SCOPE"
    assert score.summary.unique_root_recall.value is None
    assert score.summary.severity_weighted_structural_precision.value is None
    assert score.summary.missing_accounting_shard_ids == ("file-02", "file-03")
    assert score.summary.missing_shard_runtime_ids == ("file-02", "file-03")
    assert score.summary.reported_actual_cost_usd == Decimal("0.01")


@pytest.mark.parametrize(
    "change", ["claim_drop", "cost", "scope", "ratio", "observation", "plan", "authority", "clock"]
)
def test_serialized_score_recomputes_all_claims_metrics_bindings_and_false_authority(change):
    data = measured().model_dump(mode="json")
    if change == "claim_drop":
        data["claims"].pop()
    elif change == "cost":
        data["summary"]["accounted_cost_usd"] = "0"
    elif change == "scope":
        data["summary"]["unobserved_shard_ids"] = ["file-03"]
    elif change == "ratio":
        data["summary"]["all_claim_unique_root_fraction"].update(numerator=3, value=1.0)
    elif change == "observation":
        data["observation_sha256"] = "0" * 64
    elif change == "plan":
        data["binding"]["plan_sha256"] = "0" * 64
    elif change == "authority":
        data["qualification_eligible"] = True
    else:
        data["observation"]["elapsed_seconds"] = 0.001
        data["observation_sha256"] = canonical_sha256(data["observation"])
    with pytest.raises(ValidationError):
        DevelopmentBenchmarkScore.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("change", ["empty_pass", "partial_value", "excess_numerator"])
def test_ratio_schema_rejects_invented_empty_or_partial_success(change):
    values = {
        "empty_pass": dict(numerator=0, denominator=0, state="OBSERVED", value=1.0),
        "partial_value": dict(numerator=1, denominator=3, state="INCOMPLETE_SCOPE", value=0.333333),
        "excess_numerator": dict(numerator=2, denominator=1, state="OBSERVED", value=1.0),
    }
    with pytest.raises(ValidationError):
        DevelopmentMeasurementRatio.model_validate(values[change])
