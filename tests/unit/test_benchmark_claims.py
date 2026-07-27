from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.claims import (
    ComparativeMetricEvidence,
    HumanComparisonEvidence,
    HumanComparisonEvidencePayload,
    ProportionSample,
    SuperiorityClaimAssessment,
    SuperiorityClaimStatus,
    SuperiorityPrecondition,
    evaluate_superiority_claim,
    load_human_comparison_evidence,
    seal_human_comparison_evidence,
)

ROOT = Path(__file__).parents[2]


def _metric(supported: bool) -> ComparativeMetricEvidence:
    return ComparativeMetricEvidence(
        mmaudit=ProportionSample(successes=95 if supported else 80, trials=100),
        human=ProportionSample(successes=70 if supported else 80, trials=100),
    )


def _evidence(
    *,
    blinded: bool,
    comparable: bool,
    adjudicated: bool,
    precision_supported: bool,
    recall_supported: bool,
) -> HumanComparisonEvidence:
    return seal_human_comparison_evidence(
        HumanComparisonEvidencePayload(
            comparison_id="synthetic-comparison",
            corpus_sha256="a" * 64,
            benchmark_report_sha256="b" * 64,
            reports_generated_blind=blinded,
            ground_truth_withheld_from_humans=blinded,
            ground_truth_withheld_from_mmaudit=blinded,
            blinding_protocol_sha256="c" * 64 if blinded else None,
            same_corpus=comparable,
            same_scope=comparable,
            same_time_budget=comparable,
            same_evidence_access=comparable,
            review_protocol_sha256="d" * 64 if comparable else None,
            human_reviewer_count=3 if comparable else 0,
            adjudicators_independent=adjudicated,
            adjudicator_count=2 if adjudicated else 1,
            adjudication_sha256="e" * 64 if adjudicated else None,
            precision=_metric(precision_supported),
            recall=_metric(recall_supported),
        )
    )


def test_superiority_claim_defaults_to_not_evaluated_deterministically() -> None:
    first = evaluate_superiority_claim()
    second = evaluate_superiority_claim()

    assert first == second
    assert first.status is SuperiorityClaimStatus.NOT_EVALUATED
    assert first.comparison_id is None
    assert first.precision is None
    assert first.recall is None
    assert not any(item.passed for item in first.preconditions)


@pytest.mark.parametrize(
    (
        "blinded",
        "comparable",
        "adjudicated",
        "precision_supported",
        "recall_supported",
    ),
    itertools.product([False, True], repeat=5),
)
def test_every_superiority_precondition_combination_is_fail_closed(
    blinded: bool,
    comparable: bool,
    adjudicated: bool,
    precision_supported: bool,
    recall_supported: bool,
) -> None:
    evidence = _evidence(
        blinded=blinded,
        comparable=comparable,
        adjudicated=adjudicated,
        precision_supported=precision_supported,
        recall_supported=recall_supported,
    )

    assessment = evaluate_superiority_claim(evidence)

    expected = {
        SuperiorityPrecondition.BLINDED_REVIEW: blinded,
        SuperiorityPrecondition.COMPARABLE_HUMAN_REVIEW: comparable,
        SuperiorityPrecondition.INDEPENDENT_ADJUDICATION: adjudicated,
        SuperiorityPrecondition.PRECISION_STATISTICALLY_SUPPORTED: precision_supported,
        SuperiorityPrecondition.RECALL_STATISTICALLY_SUPPORTED: recall_supported,
    }
    assert {item.precondition: item.passed for item in assessment.preconditions} == expected
    all_passed = all(expected.values())
    assert assessment.status is (
        SuperiorityClaimStatus.DEMONSTRATED
        if all_passed
        else SuperiorityClaimStatus.NOT_DEMONSTRATED
    )
    assert (assessment.precision.difference_lower_bound > 0) is precision_supported
    assert (assessment.recall.difference_lower_bound > 0) is recall_supported


def test_superiority_evidence_and_assessment_are_tamper_evident(
    tmp_path: Path,
) -> None:
    evidence = _evidence(
        blinded=True,
        comparable=True,
        adjudicated=True,
        precision_supported=True,
        recall_supported=True,
    )
    assessment = evaluate_superiority_claim(evidence)
    assert assessment.status is SuperiorityClaimStatus.DEMONSTRATED

    tampered_evidence = evidence.model_dump(mode="json")
    tampered_evidence["same_scope"] = False
    with pytest.raises(ValidationError, match="evidence hash"):
        HumanComparisonEvidence.model_validate(tampered_evidence)

    tampered_assessment = assessment.model_dump(mode="json")
    tampered_assessment["status"] = SuperiorityClaimStatus.NOT_DEMONSTRATED
    with pytest.raises(ValidationError, match="status is inconsistent"):
        SuperiorityClaimAssessment.model_validate(tampered_assessment)
    tampered_statistic = assessment.model_dump(mode="json")
    tampered_statistic["precision"]["difference_lower_bound"] = -0.5
    with pytest.raises(ValidationError, match="statistic is inconsistent"):
        SuperiorityClaimAssessment.model_validate(tampered_statistic)

    path = tmp_path / "human-comparison.json"
    path.write_text(evidence.model_dump_json(), encoding="utf-8")
    assert load_human_comparison_evidence(path) == evidence
    linked = tmp_path / "linked-comparison.json"
    try:
        linked.symlink_to(path)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="regular non-link"):
        load_human_comparison_evidence(linked)


def test_published_human_comparison_schema_is_strict_and_bounded() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "human_comparison_evidence.schema.json").read_text(encoding="utf-8")
    )

    assert schema["additionalProperties"] is False
    assert schema["$defs"]["sample"]["additionalProperties"] is False
    assert schema["$defs"]["metricEvidence"]["additionalProperties"] is False
    assert schema["$defs"]["sample"]["properties"]["trials"]["maximum"] == 10_000_000
    assert schema["properties"]["evidence_sha256"] == {"$ref": "#/$defs/sha256"}
