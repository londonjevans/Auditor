"""All declared trials and missing requests remain visible; a hash cannot qualify a series."""

import json
from decimal import Decimal

import pytest

from mmaudit.benchmark.development_corpus_stability import _configuration
from mmaudit.models.development_corpus_repeats import (
    DevelopmentCorpusRepeatsObservation,
    DevelopmentCorpusRepeatsPlan,
    development_corpus_repeat_run_id,
    read_development_corpus_repeats,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.orchestration.development_corpus_repeats import _report
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_repeats_support import repeat_case
from tests.development_review_support import local_controls


@pytest.mark.parametrize("count", [2, 3, 8])
def test_plan_freezes_all_disjoint_trials_and_identical_request_bytes(count):
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("250"),
        per_attempt_budget_usd=Decimal("5"),
    )
    prepared = repeat_case(trial_count=count, policy=policy)
    assert prepared == repeat_case(trial_count=count, policy=policy)
    assert prepared.plan.trial_count == len(prepared.trials) == count
    assert len({t.plan.run_id for t in prepared.trials}) == count
    assert len({s.estimate.request_id for t in prepared.trials for s in t.shards}) == count * 6
    assert {_configuration(t.plan) for t in prepared.trials} == {prepared.plan.configuration_sha256}
    assert all(
        tuple(s.request_content for s in t.shards)
        == tuple(s.request_content for s in prepared.trials[0].shards)
        for t in prepared.trials
    )
    assert (
        prepared.plan.estimated_total_cost_usd
        == prepared.trials[0].plan.estimated_total_cost_usd * count
    )
    assert prepared.plan.selection_scope == "LOCAL_PREDECLARATION_NOT_EXTERNALLY_REGISTERED"
    assert prepared.plan.trial_independence == "NOT_ESTABLISHED"
    assert not prepared.plan.qualification_eligible and not prepared.plan.audit_complete
    assert (
        DevelopmentCorpusRepeatsPlan.model_validate_json(
            prepared.plan.model_dump_json(), strict=True
        )
        == prepared.plan
    )


@pytest.mark.parametrize("count", [0, 1, 9, True, "2", 2.0])
def test_plan_refuses_invalid_or_coerced_repeat_counts(count):
    with pytest.raises(ValueError):
        repeat_case(trial_count=count)


@pytest.mark.parametrize(
    "run_id,index", [("", 0), ("../run", 0), ("a" * 65, 0), ("run", -1), ("run", 8), ("run", True)]
)
def test_run_identity_refuses_ambiguous_or_unbounded_slots(run_id, index):
    with pytest.raises(ValueError):
        development_corpus_repeat_run_id(run_id, index)


@pytest.mark.parametrize("seconds", [0, -1, 1801, float("inf"), float("nan"), True, "600"])
def test_parent_deadline_must_be_an_exact_bounded_number(seconds):
    with pytest.raises(ValueError):
        repeat_case(maximum_run_seconds=seconds)


@pytest.mark.parametrize(
    "mutation",
    ["count", "order", "identity", "configuration", "labels", "estimate", "authority", "hash"],
)
def test_rehashed_plan_cannot_change_the_predeclared_series_structure(mutation):
    value = repeat_case().plan.model_dump(mode="json")
    if mutation == "count":
        value["trial_count"] = 3
    elif mutation == "order":
        value["trials"].reverse()
    elif mutation == "identity":
        value["run_id"] = "different-series"
    elif mutation == "configuration":
        value["configuration_sha256"] = "a" * 64
    elif mutation == "labels":
        value["benchmark"]["plan_sha256"] = value["trials"][1]["plan_sha256"]
    elif mutation == "estimate":
        value["estimated_total_cost_usd"] = "0.000001"
    elif mutation == "authority":
        value["qualification_eligible"] = True
    value["plan_sha256"] = (
        canonical_sha256({k: v for k, v in value.items() if k != "plan_sha256"})
        if mutation != "hash"
        else "0" * 64
    )
    with pytest.raises(ValueError):
        DevelopmentCorpusRepeatsPlan.model_validate_json(json.dumps(value), strict=True)


def test_whole_series_estimate_is_checked_even_when_each_trial_fits():
    first = repeat_case().trials[0].plan
    cap = (first.estimated_total_cost_usd * Decimal("1.5")).quantize(
        Decimal("0.000000000000000001")
    )
    with pytest.raises(ValueError, match="shared estimated budget"):
        repeat_case(
            policy=DevelopmentCostPolicy(
                overspend_risk_accepted=True, total_budget_usd=cap, per_attempt_budget_usd=cap
            )
        )


def test_unstarted_whole_trials_keep_all_missing_accounting_and_runtime(tmp_path):
    prepared = repeat_case(trial_count=3)
    ledger, _ = local_controls(tmp_path)
    result = _report(prepared, ledger, [None] * 3, 0, "MOCK_HTTP", "LOCAL_FAILURE", 0.0)
    assert [t.status for t in result.trials] == ["NOT_STARTED"] * 3
    assert result.plan.trial_count == len(result.trials) == 3
    assert result.started_trial_count == result.completed_trial_count == 0
    assert result.missing_result_trial_indexes == (0, 1, 2)
    assert (
        result.selected_request_count
        == len(result.missing_accounting_request_ids)
        == len(result.missing_runtime_request_ids)
        == 18
    )
    assert result.measurement_scope == "MISSING_PLANNED_TRIAL_RESULTS"
    assert read_development_corpus_repeats(result.model_dump_json().encode()) == result


@pytest.mark.parametrize(
    "mutation", ["drop", "reorder", "started", "cost", "runtime", "measurement", "authority"]
)
def test_rehashed_observation_cannot_hide_missing_trial_scope(tmp_path, mutation):
    prepared = repeat_case()
    ledger, _ = local_controls(tmp_path)
    result = _report(prepared, ledger, [None] * 2, 0, "MOCK_HTTP", "LOCAL_FAILURE", 0.0)
    value = result.model_dump(mode="json")
    if mutation == "drop":
        value["trials"].pop()
    elif mutation == "reorder":
        value["trials"].reverse()
    elif mutation == "started":
        value["started_trial_count"] = 1
    elif mutation == "cost":
        value["reported_actual_cost_usd"] = "1"
    elif mutation == "runtime":
        value["missing_runtime_request_ids"] = []
    elif mutation == "measurement":
        value["measurement_scope"] = "ALL_PREDECLARED_TRIAL_RESULTS_RETAINED"
    elif mutation == "authority":
        value["audit_complete"] = True
    value["observation_sha256"] = canonical_sha256(
        {k: v for k, v in value.items() if k != "observation_sha256"}
    )
    with pytest.raises(ValueError):
        DevelopmentCorpusRepeatsObservation.model_validate_json(json.dumps(value), strict=True)
