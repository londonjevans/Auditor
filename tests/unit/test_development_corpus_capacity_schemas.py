"""Every development consumer retains coherent finite source-count projections."""

from __future__ import annotations

from functools import cache
from importlib import import_module
from typing import Any, cast

import pytest
from pydantic import BaseModel


@cache
def properties(module: str, name: str) -> dict[str, Any]:
    model = cast(type[BaseModel], getattr(import_module("mmaudit." + module), name))
    schema = model.model_json_schema()
    if "$ref" in schema:
        schema = schema["$defs"][schema["$ref"].rsplit("/", 1)[1]]
    return cast(dict[str, Any], schema["properties"])


@pytest.mark.parametrize(
    "module,name,field,keyword,limit",
    [
        ("models.development_corpus", "DevelopmentCorpusManifest", "sources", "maxItems", 256),
        ("models.development_corpus", "DevelopmentCorpusMaterial", "sources", "maxItems", 256),
        ("models.development_corpus", "DevelopmentCorpusPlan", "shards", "maxItems", 256),
        (
            "models.development_corpus",
            "DevelopmentCorpusObservation",
            "observations",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus",
            "DevelopmentCorpusObservation",
            "accounting",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus",
            "DevelopmentCorpusObservation",
            "unobserved_shard_ids",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus",
            "DevelopmentCorpusObservation",
            "candidate_claim_count",
            "maximum",
            4096,
        ),
        (
            "models.development_corpus",
            "DevelopmentCorpusObservation",
            "selected_primary_line_count",
            "maximum",
            2560000,
        ),
        (
            "models.development_corpus_judgment",
            "DevelopmentCorpusJudgmentPlan",
            "shards",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus_judgment",
            "DevelopmentCorpusJudgmentObservation",
            "observations",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus_judgment",
            "DevelopmentCorpusJudgmentObservation",
            "unreviewed_claim_ids",
            "maxItems",
            4096,
        ),
        (
            "models.development_corpus_ensemble",
            "DevelopmentCorpusEnsembleObservation",
            "accounting",
            "maxItems",
            768,
        ),
        (
            "models.development_corpus_ensemble",
            "DevelopmentCorpusEnsembleObservation",
            "claims",
            "maxItems",
            4096,
        ),
        (
            "models.development_corpus_ensemble",
            "DevelopmentCorpusEnsembleObservation",
            "completed_judgment_count",
            "maximum",
            8192,
        ),
        (
            "models.development_corpus_resume",
            "DevelopmentCorpusResumePlan",
            "selected_shard_ids",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus_resume",
            "DevelopmentCorpusResumeAttempt",
            "accounting",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus_resume",
            "DevelopmentCorpusResumeSummary",
            "accounted_request_count",
            "maximum",
            264,
        ),
        (
            "models.development_corpus_repeats",
            "DevelopmentCorpusRepeatTrial",
            "accounting",
            "maxItems",
            256,
        ),
        (
            "models.development_corpus_repeats",
            "DevelopmentCorpusRepeatsObservation",
            "selected_request_count",
            "maximum",
            2048,
        ),
        (
            "benchmark.development_corpus",
            "DevelopmentCorpusBenchmarkScore",
            "claims",
            "maxItems",
            4096,
        ),
        (
            "benchmark.development_corpus",
            "DevelopmentCorpusBenchmarkSummary",
            "missing_accounting_shard_ids",
            "maxItems",
            256,
        ),
        (
            "benchmark.development_corpus",
            "DevelopmentCorpusMeasurementRatio",
            "denominator",
            "maximum",
            40960,
        ),
        (
            "benchmark.development_corpus_control_measurement",
            "DevelopmentCorpusControlMeasurement",
            "claims",
            "maxItems",
            4096,
        ),
        (
            "benchmark.development_corpus_resume",
            "DevelopmentCorpusResumeBenchmarkScore",
            "requests",
            "maxItems",
            2304,
        ),
        (
            "benchmark.development_corpus_resume",
            "DevelopmentCorpusResumeBenchmarkScore",
            "unknown_actual_cost_request_ids",
            "maxItems",
            264,
        ),
        (
            "benchmark.development_corpus_ensemble",
            "DevelopmentCorpusEnsembleSummary",
            "observed_opinion_count",
            "maximum",
            8192,
        ),
        (
            "benchmark.development_corpus_stability",
            "DevelopmentStabilityTrial",
            "selected_request_count",
            "maximum",
            2304,
        ),
        (
            "benchmark.development_corpus_stability",
            "DevelopmentStabilityGroup",
            "total_claim_count",
            "maximum",
            32768,
        ),
        (
            "benchmark.development_corpus_stability",
            "DevelopmentStabilityRatio",
            "denominator",
            "maximum",
            327680,
        ),
    ],
)
def test_consumer_capacity_matches_256_files_without_changing_stage_counts(
    module: str, name: str, field: str, keyword: str, limit: int
) -> None:
    assert properties(module, name)[field][keyword] == limit


def test_per_file_findings_and_truth_labels_remain_independently_bounded() -> None:
    assert (
        properties("models.development_corpus", "DevelopmentCorpusResponse")["findings"]["maxItems"]
        == 16
    )
    assert (
        properties("benchmark.development_corpus", "DevelopmentCorpusBenchmarkTruth")["controls"][
            "maxItems"
        ]
        == 1024
    )
    assert (
        properties("models.development_corpus_resume", "DevelopmentCorpusResumeHistory")[
            "continuations"
        ]["maxItems"]
        == 8
    )
