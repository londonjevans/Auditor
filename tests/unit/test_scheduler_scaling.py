"""Bounded measurement definitions and honest timing/refusal behavior."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

import tests.scheduler_scaling_support as measurement
from tests.scheduler_scaling_support import (
    CASE_PATH,
    ROOT,
    ScalingCase,
    duration_summary,
    load_scaling_cases,
    measure_phase,
    profile_location,
)


def test_predeclared_shapes_reach_depth_four_without_expanding_request_limit() -> None:
    cases = load_scaling_cases()
    assert [case.surface_count for case in cases] == [3, 5, 9, 17]
    assert [case.depth for case in cases] == [1, 2, 3, 4]
    assert [case.children for case in cases] == [2, 6, 14, 30]
    assert all(case.children + 1 <= 33 for case in cases)


@pytest.mark.parametrize(
    "update",
    [
        {"case_id": "../different"},
        {"depth": True},
        {"depth": 0},
        {"depth": 5},
        {"surface_count": 17},
        {"children": 3},
        {"families": True},
    ],
)
def test_scaling_case_refuses_relabelled_or_expanded_shapes(update: dict[str, object]) -> None:
    payload = asdict(load_scaling_cases()[0]) | update
    with pytest.raises(ValueError):
        ScalingCase(**payload)


@pytest.mark.parametrize("change", ["request_limit", "samples", "order", "extra", "boolean"])
def test_case_file_must_match_predeclared_dimensions(tmp_path: Path, change: str) -> None:
    value = json.loads(CASE_PATH.read_bytes())
    if change == "request_limit":
        value["request_limit"] = 34
    elif change == "samples":
        value["unprofiled_samples"] = 1
    elif change == "order":
        value["cases"].reverse()
    elif change == "extra":
        value["skip_validation"] = True
    else:
        value["cases"][0]["depth"] = True
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError):
        load_scaling_cases(path)


@pytest.mark.parametrize("kind", ["duplicate", "oversized"])
def test_case_file_refuses_ambiguous_or_over_bound_json(tmp_path: Path, kind: str) -> None:
    original = CASE_PATH.read_text()
    changed = (
        original.replace(
            '"schema_version": "1.0",', '"schema_version": "1.0", "schema_version": "1.0",'
        )
        if kind == "duplicate"
        else " " * 4097 + original
    )
    path = tmp_path / "cases.json"
    path.write_text(changed, encoding="utf-8")
    with pytest.raises(ValueError):
        load_scaling_cases(path)


@pytest.mark.parametrize(
    "samples",
    [
        [],
        [{"wall_ns": -1, "cpu_ns": 0}],
        [{"wall_ns": True, "cpu_ns": 1}],
        [{"wall_ns": 1.5, "cpu_ns": 1}],
        [{"wall_ns": 1}],
        [{"wall_ns": 1, "cpu_ns": 1, "passed": True}],
        [{"wall_ns": 1, "cpu_ns": 1}] * 4,
    ],
)
def test_duration_summary_refuses_invalid_observations(samples: list[dict[str, int]]) -> None:
    with pytest.raises(ValueError):
        duration_summary(samples)


def test_timing_verification_is_outside_the_measured_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order = []
    wall = iter([100, 180])
    cpu = iter([10, 60])
    monkeypatch.setattr(measurement.time, "perf_counter_ns", lambda: next(wall))
    monkeypatch.setattr(measurement.time, "process_time_ns", lambda: next(cpu))

    def operation() -> str:
        order.append("operation")
        return "original"

    def verify(value: str) -> None:
        assert value == "original"
        order.append("verify")

    result = measure_phase(operation, verify, samples=1, profile=False)
    assert order == ["operation", "verify"]
    assert result["samples"] == [{"wall_ns": 80, "cpu_ns": 50}]
    assert "separate_profile" not in result


def test_profile_is_separate_from_all_three_baseline_samples() -> None:
    calls = []

    def operation() -> int:
        calls.append("operation")
        return 42

    def verify(value: int) -> None:
        assert value == 42
        calls.append("verify")

    result = measure_phase(operation, verify)
    assert calls == ["operation", "verify"] * 4
    assert len(result["samples"]) == 3
    assert result["separate_profile"]["included_in_unprofiled_samples"] is False
    assert len(result["separate_profile"]["rows"]) <= 24
    assert all(row["function"] != "verify" for row in result["separate_profile"]["rows"])


@pytest.mark.parametrize("failure", ["operation", "verification"])
def test_failed_operation_or_invariant_never_returns_a_measurement(failure: str) -> None:
    calls = []

    def operation() -> int:
        calls.append("operation")
        if failure == "operation":
            raise ValueError("original refusal")
        return 1

    def verify(_value: int) -> None:
        raise ValueError("original invariant failed")

    with pytest.raises(ValueError):
        measure_phase(operation, verify)
    assert calls == ["operation"]


@pytest.mark.parametrize("samples", [True, 0, 2, 4, 1.0])
def test_measurement_refuses_unselected_sample_counts(samples: int) -> None:
    with pytest.raises(ValueError):
        measure_phase(lambda: None, lambda _value: None, samples=samples)


def test_profile_paths_do_not_publish_host_specific_prefixes() -> None:
    assert profile_location(str(ROOT / "src/mmaudit/orchestration/scheduler.py")) == (
        "src/mmaudit/orchestration/scheduler.py"
    )
    assert profile_location("/synthetic-host/lib/site-packages/pydantic/main.py") == (
        "<site-packages>/pydantic/main.py"
    )
    assert profile_location("/synthetic-host/lib/json/encoder.py") == "<external>/encoder.py"
    assert profile_location("~") == "~"
