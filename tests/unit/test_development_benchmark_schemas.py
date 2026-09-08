"""Canonical v2 finding shapes and explicitly non-qualifying measurement artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.development_benchmark_support import scored_file_response

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
    ):
        assert marker in text
