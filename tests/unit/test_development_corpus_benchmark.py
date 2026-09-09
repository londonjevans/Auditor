"""Source-bound structural scoring; constructed labels and opinions acquire no qualification."""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal

import pytest

from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkBinding,
    DevelopmentCorpusBenchmarkScore,
    DevelopmentCorpusBenchmarkTruth,
    DevelopmentCorpusMeasurementRatio,
    bind_development_corpus_benchmark,
    read_development_corpus_truth,
    score_development_corpus,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_benchmark_support import (
    labelled_truth,
    paired_case,
    paired_observation,
    paired_response,
)


def measured(**changes):
    binding, observation = paired_observation(**changes)
    return score_development_corpus(binding=binding, observation=observation)


def test_nested_paired_sources_score_without_losing_original_costs_claims_or_negative_controls():
    score = measured()
    assert score.summary.total_claim_count == 3 and score.summary.duplicate_claim_count == 2
    assert len(score.summary.expected_root_ids) == len(score.summary.matched_root_ids) == 1
    assert score.summary.unique_root_recall.value == 1
    assert score.summary.severity_weighted_structural_precision.value == 0.333333
    assert score.summary.first_attempt_shard_completion.denominator == 6
    assert (
        score.summary.accounted_cost_usd
        == score.summary.reported_actual_cost_usd
        == Decimal("0.06")
    )
    assert score.binding.truth.root_independence == score.root_independence == "NOT_ESTABLISHED"
    assert not score.findings_validated and not score.audit_complete
    assert not score.qualification_eligible and not score.release_eligible
    assert "DECLARED_LABELS_NOT_VERIFIED_EXTERNAL" in score.binding.truth.truth_scope
    assert DevelopmentCorpusBenchmarkScore.model_validate_json(score.model_dump_json()) == score


@pytest.mark.parametrize("observed_count", range(7))
def test_partial_scope_distinguishes_observed_misses_from_unobserved_labelled_controls(
    observed_count,
):
    responses = tuple(paired_response(i, count=0) for i in range(1, 7))
    score = measured(observed_count=observed_count, responses=responses)
    s = score.summary
    assert s.first_attempt_shard_completion.numerator == observed_count
    assert len(s.unobserved_shard_ids) == 6 - observed_count
    assert s.unique_root_recall.value == (0 if observed_count == 6 else None)
    assert len(s.observed_missed_root_ids) == (1 if observed_count >= 3 else 0)
    assert len(s.unobserved_root_ids) == (0 if observed_count >= 3 else 1)
    assert s.all_claim_unique_root_fraction.value is None
    assert (
        len(s.missing_accounting_shard_ids)
        == len(s.missing_shard_runtime_ids)
        == 6 - observed_count
    )


@pytest.mark.parametrize("kind", ["class", "origin", "anchor", "primary", "ambiguous", "advisory"])
def test_label_or_opinion_alone_cannot_create_an_unambiguous_root_match(kind):
    responses = tuple(paired_response(i) for i in range(1, 7))
    for response in responses[:3]:
        finding = response["findings"][0]
        if kind == "class":
            finding["vulnerability_class"] = "accounting"
        elif kind == "origin":
            finding["root_cause_ref"]["filename"] = "src/b/RoutePolicy.sol"
        elif kind == "anchor":
            finding["root_cause_ref"].update(line_start=41)
        elif kind == "primary":
            finding.update(line_start=1, line_end=1)
        elif kind == "advisory":
            finding.update(
                kind="advisory",
                vulnerability_class=None,
                violated_invariant=None,
                root_cause_ref=None,
            )
    binding, observation = paired_observation(responses=responses)
    if kind == "ambiguous":
        data = binding.truth.model_dump(mode="json")
        duplicate = dict(data["controls"][0], control_id="a-second-overlapping-control")
        data["controls"].insert(1, duplicate)
        content = json.dumps(data).encode()
        binding = bind_development_corpus_benchmark(
            plan=observation.plan,
            truth_content=content,
            expected_truth_sha256=hashlib.sha256(content).hexdigest(),
        )
    score = score_development_corpus(binding=binding, observation=observation)
    assert not score.summary.matched_root_ids and score.summary.unique_root_recall.value == 0
    assert score.summary.total_claim_count == 3


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "informational"])
@pytest.mark.parametrize("advisory", [False, True])
def test_relabelling_severity_or_kind_cannot_erase_denominators_or_frozen_weights(
    severity, advisory
):
    responses = tuple(paired_response(i, count=16, advisory=advisory) for i in range(1, 7))
    for response in responses:
        for finding in response["findings"]:
            finding["severity"] = severity
    score = measured(responses=responses)
    assert score.summary.total_claim_count == 48
    assert score.summary.severity_weighted_structural_precision.denominator == 240
    assert all(c.weight == 5 for c in score.claims)
    assert len(score.summary.matched_root_ids) == (0 if advisory else 1)


def test_guarded_violation_claims_stay_unmatched_and_unduplicated():
    score = measured(responses=tuple(paired_response(i, guarded_empty=False) for i in range(1, 7)))
    assert score.summary.guarded_control_claim_count == 3
    assert score.summary.unmatched_invariant_claim_count == 3
    assert score.summary.duplicate_claim_count == 2
    assert score.summary.total_claim_count == 6


@pytest.mark.parametrize(
    "kind", ["hash", "bytes", "utf8", "list", "duplicate", "nonfinite", "deep", "empty", "large"]
)
def test_exact_label_reader_rejects_malformed_unpinned_or_unbounded_bytes(kind):
    raw = labelled_truth(paired_case()).model_dump_json().encode()
    digest = hashlib.sha256(raw).hexdigest()
    if kind == "hash":
        digest = "0" * 64
    elif kind == "bytes":
        raw += b" "
    else:
        raw = {
            "utf8": b"\xff",
            "list": b"[]",
            "duplicate": b'{"truth_id":"first","truth_id":"second"}',
            "nonfinite": b'{"value":NaN}',
            "deep": b"[" * 2000 + b"0" + b"]" * 2000,
            "empty": b"",
            "large": b" " * 2_000_001,
        }[kind]
        digest = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        read_development_corpus_truth(raw, expected_sha256=digest)


@pytest.mark.parametrize(
    "kind",
    [
        "duplicate_id",
        "order",
        "origin_file",
        "origin_line",
        "anchor",
        "claim_site",
        "provenance",
        "authority",
        "secret",
    ],
)
def test_source_bound_label_contract_rejects_invalid_coordinates_identity_or_authority(kind):
    data = labelled_truth(paired_case()).model_dump(mode="json")
    control = data["controls"][0]
    if kind == "duplicate_id":
        data["controls"][1]["control_id"] = control["control_id"]
    elif kind == "order":
        data["controls"].reverse()
    elif kind == "origin_file":
        control["origin"]["filename"] = "src/unselected.sol"
    elif kind == "origin_line":
        control["origin"]["line_end"] = 10000
    elif kind == "anchor":
        control["required_origin_line"] = 1
    elif kind == "claim_site":
        control["claim_sites"][0]["line_end"] = 10000
    elif kind == "provenance":
        data["provenance"] = "EXTERNALLY_VERIFIED"
    elif kind == "authority":
        data["findings_validated"] = True
    else:
        control["invariant"] = (
            "api_key=synthetic-corpus-measurement-secret-abcdefghijklmnopqrstuvwxyz"
        )
    with pytest.raises(ValueError):
        DevelopmentCorpusBenchmarkTruth.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize(
    "kind",
    [
        "truth",
        "raw_hash",
        "raw_bytes",
        "plan",
        "source",
        "summary",
        "claims",
        "observation_hash",
        "authority",
    ],
)
def test_retained_score_rejects_tampered_inputs_or_relabelled_results(kind):
    score = measured()
    data = score.model_dump(mode="json")
    if kind == "truth":
        data["binding"]["truth"]["controls"][0]["expected"] = "GUARDED"
    elif kind == "raw_hash":
        data["binding"]["truth_file_sha256"] = "a" * 64
    elif kind == "raw_bytes":
        data["binding"]["truth_file_content"] += " "
    elif kind == "plan":
        data["binding"]["plan_sha256"] = "a" * 64
    elif kind == "source":
        data["binding"]["truth"]["manifest"]["sources"][0]["sha256"] = "a" * 64
    elif kind == "summary":
        data["summary"]["reported_actual_cost_usd"] = "0"
    elif kind == "claims":
        data["claims"] = []
    elif kind == "observation_hash":
        data["observation_sha256"] = "a" * 64
    else:
        data["release_eligible"] = True
    with pytest.raises(ValueError):
        DevelopmentCorpusBenchmarkScore.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize("kind", ["binding", "candidate", "construct"])
def test_score_requires_exact_revalidated_artifact_types(kind):
    binding, candidate = paired_observation()
    if kind == "binding":
        binding = binding.model_dump()
    elif kind == "candidate":
        candidate = candidate.model_dump()
    else:
        binding = binding.model_copy(update={"plan_sha256": "0" * 64})
    with pytest.raises(ValueError):
        score_development_corpus(binding=binding, observation=candidate)


def test_raw_label_formatting_is_preserved_only_when_its_explicit_pin_matches():
    binding, candidate = paired_observation()
    content = binding.truth_file_content.encode() + b"\n"
    other = bind_development_corpus_benchmark(
        plan=candidate.plan,
        truth_content=content,
        expected_truth_sha256=hashlib.sha256(content).hexdigest(),
    )
    assert other.truth == binding.truth and other.truth_file_sha256 != binding.truth_file_sha256
    assert other.truth_file_content.endswith("\n")
    assert DevelopmentCorpusBenchmarkBinding.model_validate_json(other.model_dump_json()) == other


def test_expanded_weight_ratio_covers_the_full_1024_critical_claim_bound():
    ratio = DevelopmentCorpusMeasurementRatio(
        numerator=10240, denominator=10240, state="OBSERVED", value=1.0
    )
    assert ratio.value == 1
    with pytest.raises(ValueError):
        DevelopmentCorpusMeasurementRatio(
            numerator=10241, denominator=10241, state="OBSERVED", value=1.0
        )


def test_whole_candidate_identity_includes_every_original_claim_and_cost():
    score = measured()
    assert score.observation_sha256 == canonical_sha256(score.observation.model_dump(mode="json"))
    assert score.summary.total_claim_count == score.observation.candidate_claim_count
    assert score.summary.accounted_cost_usd == score.observation.total_accounted_cost_usd


def test_exact_two_megabyte_label_file_retains_raw_bytes_through_scoring():
    binding, candidate = paired_observation()
    content = binding.truth_file_content.encode().ljust(2_000_000, b" ")
    rebound = bind_development_corpus_benchmark(
        plan=candidate.plan,
        truth_content=content,
        expected_truth_sha256=hashlib.sha256(content).hexdigest(),
    )
    score = score_development_corpus(binding=rebound, observation=candidate)
    assert score.binding.truth == binding.truth
    assert score.binding.truth_file_content.encode() == content
    assert len(score.model_dump_json().encode()) > 2_000_000
    assert DevelopmentCorpusBenchmarkScore.model_validate_json(score.model_dump_json()) == score
