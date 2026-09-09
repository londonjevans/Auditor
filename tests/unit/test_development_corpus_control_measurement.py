"""Synthetic structural locations and annotation disagreements are never semantic audit verdicts."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess

import pytest

import mmaudit.benchmark.development_corpus_control_measurement as measurement
from mmaudit.benchmark.development_corpus import (
    bind_development_corpus_benchmark,
    score_development_corpus,
)
from mmaudit.benchmark.development_corpus_resume import score_development_corpus_resume
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_benchmark_support import paired_observation, paired_response
from tests.development_corpus_control_measurement_support import direct_responses, original_score
from tests.development_corpus_resume_score_support import extend_labelled, labelled_history


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("control measurement attempted network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize(
    "category", ["access_control", "accounting", "reservation", "pause", "other"]
)
def test_category_is_recorded_without_zeroing_unambiguous_locations_or_guarded_claims(category):
    responses = [paired_response(i, guarded_empty=False) for i in range(1, 7)]
    for response in responses:
        response["findings"][0]["vulnerability_class"] = category
    old = original_score(responses=responses)
    raw = old.model_dump_json()
    result = measurement.measure_development_corpus_controls(score=old)
    summary = result.summary
    assert result.source_score == old and old.model_dump_json() == raw
    assert result.source_score_sha256 == canonical_sha256(old.model_dump(mode="json"))
    assert old.summary.unique_root_recall.value == (
        1 if category == old.binding.truth.controls[0].vulnerability_class else 0
    )
    assert summary.unique_root_location_coverage.value == 1
    assert summary.invariant_asserted_root_coverage.value == 1
    assert summary.total_claim_count == 6 and summary.guarded_invariant_claim_count == 3
    assert summary.duplicate_location_count == summary.duplicate_assertion_count == 2
    assert summary.severity_weighted_structural_precision.denominator == 30
    assert (
        summary.matched_category_agreement_count + summary.matched_category_disagreement_count == 6
    )
    assert all(claim.reported_category == category for claim in result.claims)
    assert result.source_score.summary.accounted_cost_usd == old.summary.accounted_cost_usd
    assert (
        measurement.read_development_corpus_control_measurement(result.model_dump_json().encode())
        == result
    )
    assert not result.audit_complete and not result.findings_validated
    assert not result.qualification_eligible and not result.release_eligible
    assert result.root_independence == "NOT_ESTABLISHED"


@pytest.mark.parametrize("advisory", [False, True])
@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "informational"])
def test_same_file_advisories_keep_location_coverage_without_asserted_violation_credit(
    advisory, severity
):
    old = original_score(responses=direct_responses(advisory=advisory, severity=severity))
    result = measurement.measure_development_corpus_controls(score=old)
    summary = result.summary
    assert summary.unique_root_location_coverage.value == 1
    assert summary.invariant_asserted_root_coverage.value == int(not advisory)
    assert summary.total_claim_count == 2
    assert summary.severity_weighted_structural_precision.denominator == 10
    assert summary.severity_weighted_asserted_structural_precision.denominator == 10
    assert all(c.weight == 5 for c in result.claims)
    assert summary.guarded_advisory_claim_count == int(advisory)
    assert summary.guarded_invariant_claim_count == int(not advisory)
    assert len(summary.advisory_only_root_ids) == int(advisory)
    assert {c.origin_basis for c in result.claims} == (
        {"PRIMARY_SPAN"} if advisory else {"EXPLICIT_ROOT_REFERENCE"}
    )
    assert old.summary.unique_root_recall.value == int(not advisory)


def test_advisory_first_does_not_erase_later_assertions_or_any_denominator():
    responses = direct_responses()
    advisory = paired_response(1, advisory=True)["findings"][0]
    invariant = responses[0]["findings"][0]
    responses[0]["findings"] = [advisory, invariant, dict(invariant)]
    responses[3]["findings"] = []
    old = original_score(responses=responses)
    result = measurement.measure_development_corpus_controls(score=old)
    assert [c.duplicate_location for c in result.claims] == [False, True, True]
    assert [c.duplicate_assertion for c in result.claims] == [False, False, True]
    assert result.summary.unique_root_location_coverage.value == 1
    assert result.summary.invariant_asserted_root_coverage.value == 1
    assert not result.summary.advisory_only_root_ids
    assert result.summary.total_claim_count == 3
    assert result.summary.severity_weighted_structural_precision.denominator == 15


@pytest.mark.parametrize("count", range(7))
def test_incomplete_scope_keeps_null_quality_and_both_views_misses(count):
    old = original_score(
        observed_count=count, responses=[paired_response(i, count=0) for i in range(1, 7)]
    )
    result = measurement.measure_development_corpus_controls(score=old)
    summary = result.summary
    assert summary.unique_root_location_coverage.value == (0 if count == 6 else None)
    assert summary.invariant_asserted_root_coverage.value == (0 if count == 6 else None)
    assert summary.severity_weighted_structural_precision.value is None
    assert summary.unlocated_root_ids == summary.unasserted_root_ids == summary.expected_root_ids
    assert len(summary.observed_unlocated_root_ids) == int(count >= 3)
    assert summary.observed_unasserted_root_ids == summary.observed_unlocated_root_ids
    assert len(summary.unobserved_unlocated_root_ids) == int(count < 3)
    assert result.source_score == old


@pytest.mark.parametrize("count", range(6))
def test_continuation_measurements_retain_original_and_cumulative_scope_costs_and_provenance(count):
    responses = [paired_response(i, guarded_empty=False) for i in range(1, 7)]
    for response in responses:
        response["findings"][0]["vulnerability_class"] = "other"
    history, metadata = labelled_history(observed_count=count, responses=responses)
    history = extend_labelled(history, metadata, responses=responses)
    old = score_development_corpus_resume(history=history)
    result = measurement.measure_development_corpus_controls(score=old)
    assert result.source_scope == "CUMULATIVE_RECORDED_ATTEMPTS"
    assert result.source_score == old and result.source_score.history == history
    assert result.source_score.first_attempt_summary.unique_root_recall.value is None
    assert result.source_score.cumulative_quality.unique_root_recall.value == 0
    assert result.summary.unique_root_location_coverage.value == 1
    assert result.summary.invariant_asserted_root_coverage.value == 1
    assert result.summary.guarded_invariant_claim_count == 3
    assert [c.stage_index for c in result.claims] == [0] * count + [1] * (6 - count)
    assert [(c.claim_id, c.run_id, c.request_id) for c in result.claims] == [
        (c.claim_id, c.run_id, c.request_id) for c in old.claims
    ]
    assert result.source_score.cumulative_summary == history.summary


@pytest.mark.parametrize("kind", ["origin", "anchor", "primary", "ambiguous", "ambiguous_category"])
def test_annotation_independence_never_bypasses_source_anchor_or_ambiguity_checks(kind):
    responses = direct_responses()
    responses[3]["findings"] = []
    finding = responses[0]["findings"][0]
    if kind == "origin":
        finding["root_cause_ref"]["filename"] = "src/b/RoutePolicy.sol"
    elif kind == "anchor":
        finding["root_cause_ref"]["line_start"] = 41
    elif kind == "primary":
        finding.update(line_start=1, line_end=1)
    binding, observation = paired_observation(responses=responses)
    if kind.startswith("ambiguous"):
        truth = binding.truth.model_dump(mode="json")
        second = dict(truth["controls"][0], control_id="a-overlapping-root", severity="critical")
        if kind == "ambiguous_category":
            second["vulnerability_class"] = "other"
        truth["controls"].append(second)
        truth["controls"].sort(key=lambda c: c["control_id"])
        raw = json.dumps(truth).encode()
        binding = bind_development_corpus_benchmark(
            plan=observation.plan,
            truth_content=raw,
            expected_truth_sha256=hashlib.sha256(raw).hexdigest(),
        )
    old = score_development_corpus(binding=binding, observation=observation)
    result = measurement.measure_development_corpus_controls(score=old)
    assert not result.summary.located_root_ids and not result.summary.invariant_asserted_root_ids
    assert result.summary.unique_root_location_coverage.value == 0
    assert result.claims[0].control_id is None
    if kind.startswith("ambiguous"):
        assert result.claims[0].anchored_candidate_count == 2
        assert result.summary.ambiguous_claim_count == 1 and result.claims[0].weight == 10
    else:
        assert result.claims[0].disposition == "UNMATCHED"
