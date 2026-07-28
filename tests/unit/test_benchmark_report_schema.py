from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.engine import BenchmarkReport, evaluate_benchmark, load_manifest
from mmaudit.models.schemas import AuditProfile

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "benchmark_report.schema.json"
SCHEMA_URI = "https://mmaudit.local/schemas/benchmark_report.schema.json"


def _published_schema() -> dict[str, Any]:
    loaded = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _generated_schema() -> dict[str, Any]:
    schema = BenchmarkReport.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_URI
    schema["title"] = "mmaudit benchmark report"
    return schema


def _valid_payload() -> dict[str, Any]:
    manifest = load_manifest(ROOT / "benchmarks" / "corpus" / "manifest.json")
    report = evaluate_benchmark(
        manifest,
        {},
        profile=AuditProfile.STANDARD,
    )
    return report.model_dump(mode="json")


def test_published_benchmark_report_schema_matches_the_typed_contract() -> None:
    schema = _published_schema()

    assert schema == _generated_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {
        name for name, field in BenchmarkReport.model_fields.items() if field.is_required()
    }
    assert schema["properties"]["report_inputs"]["minItems"] == 1
    assert schema["properties"]["repository_metrics"]["minItems"] == 1
    assert schema["properties"]["case_results"]["minItems"] == 1
    assert schema["properties"]["gates"]["minItems"] == 6
    assert schema["$defs"]["BenchmarkMetricState"]["enum"] == [
        "PASS",
        "FAIL",
        "NOT_EVALUABLE",
        "NOT_APPLICABLE",
        "INCONCLUSIVE",
    ]
    assert all(
        definition["additionalProperties"] is False
        for definition in schema["$defs"].values()
        if definition.get("type") == "object"
    )


def test_published_benchmark_report_schema_accepts_a_typed_report() -> None:
    assert _published_schema() == _generated_schema()
    payload = _valid_payload()

    assert BenchmarkReport.model_validate(payload).model_dump(mode="json") == payload


def test_published_benchmark_report_schema_rejects_a_vacuous_pass_metric() -> None:
    assert _published_schema() == _generated_schema()
    payload = deepcopy(_valid_payload())
    metric = payload["metrics"]["reproduction_success_rate"]
    assert metric["denominator"] > 0
    assert metric["evaluated"] == 0
    metric["state"] = "PASS"

    with pytest.raises(ValidationError, match="passing or failing benchmark metrics"):
        BenchmarkReport.model_validate(payload)


def test_published_benchmark_report_schema_rejects_missing_metrics_and_extra_fields() -> None:
    assert _published_schema() == _generated_schema()
    missing_metric = deepcopy(_valid_payload())
    del missing_metric["metrics"]["model_review_coverage"]
    with pytest.raises(ValidationError):
        BenchmarkReport.model_validate(missing_metric)

    extra_field = deepcopy(_valid_payload())
    extra_field["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        BenchmarkReport.model_validate(extra_field)
