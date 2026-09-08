"""Review effects retain original truth, all candidates, missing decisions and liabilities."""

from __future__ import annotations

import json

import pytest

from mmaudit.benchmark.development import (
    DevelopmentJudgmentImpactScore,
    bind_development_benchmark,
    score_development_judgment,
)
from mmaudit.models.development_judgment import DevelopmentJudgmentObservation
from tests.development_benchmark_support import benchmark_truth, scored_file_response
from tests.development_judgment_support import judgment_observation


def score_case(**kwargs):
    result = judgment_observation(**kwargs)
    return score_development_judgment(
        binding=bind_development_benchmark(
            plan=result.plan.candidate.plan, truth=benchmark_truth(kwargs.get("variant", "a"))
        ),
        observation=result,
    )


@pytest.mark.parametrize(
    "verdicts",
    [
        ("SUPPORTED", "SUPPORTED", "SUPPORTED"),
        ("REFUTED", "SUPPORTED", "REFUTED"),
        ("INCONCLUSIVE", "REFUTED", "SUPPORTED"),
        ("REFUTED", "REFUTED", "REFUTED"),
        ("INCONCLUSIVE", "INCONCLUSIVE", "INCONCLUSIVE"),
    ],
)
def test_supported_roots_are_unique_even_when_the_original_primary_match_is_refuted(verdicts):
    score = score_case(verdicts=verdicts)
    summary = score.summary
    supported = verdicts.count("SUPPORTED")
    assert summary.candidate_claim_count == len(score.claims) == 3
    assert summary.supported_claim_count == supported
    assert summary.refuted_claim_count == verdicts.count("REFUTED")
    assert summary.inconclusive_claim_count == verdicts.count("INCONCLUSIVE")
    assert len(summary.supported_planted_root_ids) == (1 if supported else 0)
    assert summary.supported_root_recall.value == (1 if supported else 0)
    assert summary.supported_severity_weighted_structural_precision.value == (
        round(1 / supported, 6) if supported else None
    )
    assert summary.all_candidate_severity_weighted_structural_precision.value == (
        0.333333 if supported else 0
    )
    assert summary.first_attempt_claim_observation_rate.value == 1
    assert [row.judgment for row in score.claims] == list(verdicts)


@pytest.mark.parametrize("cost", [None, "uncertain", "reserved"])
@pytest.mark.parametrize("completed", [0, 1, 2])
def test_partial_reviews_keep_full_denominators_and_suppress_complete_quality_ratios(
    cost, completed
):
    score = score_case(completed=completed, unobserved_cost=cost)
    summary = score.summary
    assert summary.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert summary.candidate_claim_count == 3 and summary.unreviewed_claim_count == 3 - completed
    assert summary.first_attempt_claim_observation_rate.value == round(completed / 3, 6)
    for ratio in (
        summary.supported_root_recall,
        summary.supported_severity_weighted_structural_precision,
        summary.all_candidate_severity_weighted_structural_precision,
    ):
        assert ratio.state == "INCOMPLETE_SCOPE" and ratio.value is None
    assert summary.combined_accounted_cost_usd == score.observation.combined_accounted_cost_usd
    assert bool(summary.active_reserved_usd) is (cost == "reserved")
    assert len(score.candidate_score.claims) == len(score.claims)


@pytest.mark.parametrize("variant", ["a", "b"])
def test_no_candidates_are_not_a_judgment_pass_or_perfect_empty_recall(variant):
    responses = tuple(scored_file_response(i) for i in range(1, 4))
    for response in responses:
        response["findings"] = []
    score = score_case(variant=variant, responses=responses)
    assert score.summary.quality_scope == "NO_CANDIDATES" and not score.claims
    assert score.summary.first_attempt_claim_observation_rate.value is None
    assert score.summary.supported_severity_weighted_structural_precision.value is None
    assert score.summary.supported_root_recall.value == (0 if variant == "a" else None)


def test_supported_advisories_and_unmatched_hypotheses_stay_visible_without_root_credit():
    responses = tuple(scored_file_response(i, advisory=i == 1) for i in range(1, 4))
    responses[1]["findings"][0]["vulnerability_class"] = "other"
    score = score_case(responses=responses)
    assert score.summary.supported_advisory_count == 1
    assert score.summary.supported_unmatched_invariant_count == 1
    assert score.summary.supported_claim_count == 3
    assert score.summary.supported_root_recall.value == 1
    assert len(score.candidate_score.claims) == len(score.claims) == 3


@pytest.mark.parametrize(
    "field,value",
    [
        ("supported_claim_count", 0),
        ("candidate_claim_count", 2),
        ("supported_planted_root_ids", []),
        ("unreviewed_claim_count", 1),
        ("combined_accounted_cost_usd", "0"),
        ("summed_stage_elapsed_seconds", 0.0),
        ("quality_scope", "NO_CANDIDATES"),
    ],
)
def test_score_cannot_drop_costs_candidates_or_change_metrics(field, value):
    data = score_case().model_dump(mode="json")
    data["summary"][field] = value
    with pytest.raises(ValueError):
        DevelopmentJudgmentImpactScore.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "change",
    [
        "wrong_truth",
        "wrong_digest",
        "omitted_row",
        "changed_decision",
        "different_candidate",
        "authority",
    ],
)
def test_nested_candidate_judgment_truth_and_opinion_bindings_cannot_be_relabelled(change):
    data = score_case().model_dump(mode="json")
    if change == "wrong_truth":
        with pytest.raises(ValueError):
            score_development_judgment(
                binding=bind_development_benchmark(
                    plan=judgment_observation(variant="b").plan.candidate.plan,
                    truth=benchmark_truth("b"),
                ),
                observation=judgment_observation(),
            )
        return
    if change == "wrong_digest":
        data["observation_sha256"] = "a" * 64
    elif change == "omitted_row":
        data["claims"].pop()
    elif change == "changed_decision":
        data["claims"][0]["judgment"] = "REFUTED"
    elif change == "different_candidate":
        data["candidate_score"] = score_case(variant="b").candidate_score.model_dump(mode="json")
    else:
        data["lineage_independence"] = "VERIFIED"
    with pytest.raises(ValueError):
        DevelopmentJudgmentImpactScore.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "field,value",
    [
        ("completed_judgment_count", 2),
        ("unreviewed_claim_ids", ["file-01:01"]),
        ("judgment_accounted_cost_usd", "0"),
        ("combined_accounted_cost_usd", "0.03"),
        ("active_reserved_usd", "1"),
        ("summed_stage_elapsed_seconds", 0.1),
        ("status", "NO_CANDIDATES"),
        ("transport", "HTTP_OBSERVATION"),
    ],
)
def test_observation_cannot_launder_coverage_cost_or_transport(field, value):
    data = judgment_observation().model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValueError):
        DevelopmentJudgmentObservation.model_validate_json(json.dumps(data))
