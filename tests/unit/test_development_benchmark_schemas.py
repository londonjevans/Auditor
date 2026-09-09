"""Canonical v2 finding shapes and explicitly non-qualifying measurement artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from mmaudit.benchmark.development_corpus import score_development_corpus
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.development_benchmark_support import scored_file_response
from tests.development_corpus_benchmark_support import paired_observation
from tests.development_corpus_judgment_support import manifest_judgment_response

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "filename",
    [
        "development_scored_review_response.schema.json",
        "development_scored_shard_observation.schema.json",
        "development_benchmark_truth.schema.json",
        "development_benchmark_binding.schema.json",
        "development_benchmark_score.schema.json",
        "development_ensemble_plan.schema.json",
        "development_ensemble_observation.schema.json",
        "development_ensemble_score.schema.json",
        "development_corpus_manifest.schema.json",
        "development_corpus_material.schema.json",
        "development_corpus_response.schema.json",
        "development_corpus_plan.schema.json",
        "development_corpus_shard_observation.schema.json",
        "development_corpus_observation.schema.json",
        "development_corpus_resume_plan.schema.json",
        "development_corpus_resume_attempt.schema.json",
        "development_corpus_resume_history.schema.json",
        "development_corpus_ensemble_plan.schema.json",
        "development_corpus_ensemble_observation.schema.json",
        "development_corpus_ensemble_score.schema.json",
        "development_corpus_truth.schema.json",
        "development_corpus_benchmark_binding.schema.json",
        "development_corpus_benchmark_score.schema.json",
        "development_corpus_judgment_response.schema.json",
        "development_corpus_judgment_plan.schema.json",
        "development_corpus_judgment_shard_observation.schema.json",
        "development_corpus_judgment_observation.schema.json",
    ],
)
def test_new_development_schemas_are_exact_canonical_artifacts(filename):
    raw = (ROOT / "schemas" / filename).read_text()
    assert raw == rendered_schema(filename, MODELS[filename])
    schema = json.loads(raw)
    Draft202012Validator.check_schema(schema)
    if filename not in {
        "development_scored_review_response.schema.json",
        "development_corpus_response.schema.json",
        "development_corpus_judgment_response.schema.json",
    }:
        for field in (
            "findings_validated",
            "audit_complete",
            "qualification_eligible",
            "release_eligible",
        ):
            assert schema["properties"][field]["const"] is False


@pytest.mark.parametrize("advisory", [False, True])
@pytest.mark.parametrize("field", ["vulnerability_class", "violated_invariant", "root_cause_ref"])
@pytest.mark.parametrize("version", ["2.0", "3.0"])
def test_public_response_schema_enforces_required_kind_nullability(advisory, field, version):
    filename = (
        "development_scored_review_response.schema.json"
        if version == "2.0"
        else "development_corpus_response.schema.json"
    )
    schema = json.loads((ROOT / "schemas" / filename).read_text())
    validator = Draft202012Validator(schema)
    response = scored_file_response(1, advisory=advisory)
    response["schema_version"] = version
    assert validator.is_valid(response)
    response["findings"][0][field] = (
        scored_file_response(1)["findings"][0][field] if advisory else None
    )
    assert not validator.is_valid(response)
    del response["findings"][0][field]
    assert not validator.is_valid(response)


def test_documentation_retains_exact_metric_and_provenance_limits():
    text = (ROOT / "docs/development_benchmark.md").read_text()
    for marker in (
        "agent-constructed",
        "frozen-objective L",
        "truth-manifest",
        "mode 0700",
        "all_claim_unique_root_fraction",
        "severity_weighted_structural_precision",
        "first_attempt_shard_completion",
        "value: null",
        "unknown",
        "not independent authentication",
        "ensemble-corpus",
        "TWO_REVIEW_UNANIMOUS_OPINION_ONLY",
        "not a portfolio reservation",
        "review_opinion_observation_rate",
        "separately selected token allowances",
        "audit-manifest",
        "EXPLICIT_MANIFEST_ONLY",
        "RESPONSE_COMPLETION_NOT_VALIDATED_ANALYSIS_COVERAGE",
        "sources.json",
        "judge-manifest",
        "CANDIDATE_INCOMPLETE",
        "64 MB",
        "--truth-sha256",
        "DECLARED_LABELS_NOT_VERIFIED_EXTERNAL_OR_EXHAUSTIVE_GROUND_TRUTH",
        "10240",
        "32 MB",
        "resume-manifest",
        "CUMULATIVE_RESPONSES_NOT_VALIDATED_ANALYSIS",
        "eight explicit continuation stages",
    ):
        assert marker in text


@pytest.mark.parametrize("verdict", ["SUPPORTED", "REFUTED", "INCONCLUSIVE"])
@pytest.mark.parametrize("references", [False, True])
def test_public_manifest_judgment_schema_retains_bounded_nested_reference_contract(
    verdict, references
):
    schema = json.loads(
        (ROOT / "schemas/development_corpus_judgment_response.schema.json").read_text()
    )
    response = manifest_judgment_response(verdict=verdict)
    decision = response["decisions"][0]
    decision["claim_id"] = "file-0064:16"
    if references:
        decision["source_refs"][0].update(
            filename="src/nested/Maximum.sol", line_start=10000, line_end=10000
        )
    else:
        decision["source_refs"] = []
    validator = Draft202012Validator(schema)
    assert validator.is_valid(response) == (references or verdict == "INCONCLUSIVE")
    decision["claim_id"] = "file-0065:16"
    assert not validator.is_valid(response)


@pytest.mark.parametrize("field", ["source", "claims", "weight", "authority", "provenance", "root"])
def test_manifest_score_schema_retains_scale_and_nonqualification_contract(field):
    schema = json.loads(
        (ROOT / "schemas/development_corpus_benchmark_score.schema.json").read_text()
    )
    binding, observation = paired_observation()
    data = score_development_corpus(binding=binding, observation=observation).model_dump(
        mode="json"
    )
    validator = Draft202012Validator(schema)
    assert validator.is_valid(data)
    if field == "source":
        data["binding"]["truth"]["controls"][0]["origin"]["line_end"] = 10001
    elif field == "claims":
        data["claims"][0]["claim_id"] = "file-0065:01"
    elif field == "weight":
        data["summary"]["severity_weighted_structural_precision"]["denominator"] = 10241
    elif field == "authority":
        data["findings_validated"] = True
    elif field == "provenance":
        data["binding"]["truth"]["provenance"] = "INDEPENDENT_EXTERNAL_TRUTH"
    else:
        data["root_independence"] = "ESTABLISHED"
    assert not validator.is_valid(data)
