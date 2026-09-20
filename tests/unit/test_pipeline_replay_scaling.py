"""Local timing instrumentation must not relax original execution or invent accepted samples."""

from __future__ import annotations

import cProfile
import json
import socket
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.operator_secrets as secrets_module
from mmaudit.models.truncation import candidate_review_protocol_implementation_is_pristine
from tests.pipeline_replay_scaling_support import (
    CASE_PATH,
    load_pipeline_replay_cases,
    measure_async_phase,
    measure_original_pipeline_replay,
    no_external_io,
    replay_profile,
)
from tests.unresolved_recovery_tree_support import tree_scenarios


def test_experiment_retains_original_generic_and_depth_four_mixed_specialist_cases() -> None:
    generic, mixed = load_pipeline_replay_cases()
    assert (generic.name, generic.sources, generic.expected_children) == ("generic-open", 9, 14)
    assert (mixed.name, mixed.sources, mixed.expected_children) == ("mixed-specialist", 33, 30)
    assert mixed.expected_depth == 4 and mixed.role == "specialist:false_negative_hunter"
    assert generic in tree_scenarios() and mixed in tree_scenarios()


@pytest.mark.parametrize(
    "change", ["cases", "samples", "bool", "float", "extra", "duplicate", "oversized"]
)
def test_experiment_refuses_changed_or_ambiguous_selection(tmp_path: Path, change: str) -> None:
    raw = CASE_PATH.read_text()
    value = json.loads(raw)
    if change == "cases":
        value["cases"].reverse()
    elif change == "samples":
        value["unprofiled_resume_samples"] = 1
    elif change == "bool":
        value["fresh_pipeline_samples"] = True
    elif change == "float":
        value["additional_profiled_resume_samples"] = 1.0
    elif change == "extra":
        value["skip_verification"] = True
    if change == "duplicate":
        raw = raw.replace('"schema_version": "1.0",', '"schema_version":"1.0",' * 2)
    elif change == "oversized":
        raw = " " * 4097 + raw
    else:
        raw = json.dumps(value)
    path = tmp_path / "cases.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        load_pipeline_replay_cases(path)


@pytest.mark.asyncio
async def test_async_timing_excludes_progress_and_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wall, cpu = iter((100, 190)), iter((10, 60))
    monkeypatch.setattr(
        "tests.pipeline_replay_scaling_support.time.perf_counter_ns", lambda: next(wall)
    )
    monkeypatch.setattr(
        "tests.pipeline_replay_scaling_support.time.process_time_ns", lambda: next(cpu)
    )
    events = []

    async def operation() -> str:
        events.append("operation")
        return "original"

    def verify(value: str) -> None:
        assert value == "original"
        events.append("verification")

    value, result = await measure_async_phase(
        operation, verify, samples=1, profile=False, progress=events.append
    )
    assert value == "original" and events == ["unprofiled_1", "operation", "verification"]
    assert result["samples"] == [{"wall_ns": 90, "cpu_ns": 50}]
    assert "separate_profile" not in result


@pytest.mark.asyncio
async def test_profile_is_a_fourth_verified_awaited_operation_not_a_baseline_sample() -> None:
    events = []

    async def operation() -> int:
        events.append("operation")
        return len(events)

    def verify(value: int) -> None:
        assert value == len(events)
        events.append("verify")

    value, result = await measure_async_phase(operation, verify, progress=events.append)
    assert len(result["samples"]) == 3 and value == 11
    assert events == [
        item
        for phase in ("unprofiled_1", "unprofiled_2", "unprofiled_3", "separate_profile")
        for item in (phase, "operation", "verify")
    ]
    profile = result["separate_profile"]
    assert profile["included_in_unprofiled_samples"] is False
    assert profile["main_thread_only"] and profile["inclusive_times_overlap"]
    assert all(row["function"] != "verify" for row in profile["rows"])
    assert all(not row["file"].startswith("/") for row in profile["rows"])


@pytest.mark.parametrize("failure", ["operation", "verification", "profile"])
@pytest.mark.asyncio
async def test_failed_operation_or_assertion_cannot_return_a_measurement(failure: str) -> None:
    count = 0
    original_profile = sys.getprofile()

    async def operation() -> int:
        nonlocal count
        count += 1
        if failure == "operation" or (failure == "profile" and count == 2):
            raise ValueError("synthetic operation failed")
        return count

    def verify(_value: int) -> None:
        if failure == "verification":
            raise ValueError("synthetic invariant failed")

    with pytest.raises(ValueError):
        await measure_async_phase(operation, verify, samples=1)
    assert count == (2 if failure == "profile" else 1)
    assert sys.getprofile() is original_profile


@pytest.mark.parametrize(
    "samples,profile", [(True, True), (0, True), (2, True), (3, 1), (1.0, False)]
)
@pytest.mark.asyncio
async def test_invalid_measurement_options_refuse_before_any_operation(
    tmp_path: Path, samples: Any, profile: Any
) -> None:
    async def operation() -> None:
        raise AssertionError("must refuse before any operation")

    with pytest.raises(ValueError):
        await measure_async_phase(operation, lambda _value: None, samples=samples, profile=profile)
    with pytest.raises(ValueError):
        await measure_original_pipeline_replay(
            tree_scenarios()[0], tmp_path, samples=samples, profile=profile
        )
    assert list(tmp_path.iterdir()) == []


def test_network_and_secret_refusals_are_restored_after_instrumentation() -> None:
    original = socket.create_connection
    with no_external_io():
        for forbidden in (
            socket.create_connection,
            socket.socket.connect,
            httpx.HTTPTransport.handle_request,
            httpx.AsyncHTTPTransport.handle_async_request,
            secrets_module.load_operator_secrets,
        ):
            with pytest.raises(AssertionError, match="networks or operator secrets"):
                forbidden()  # type: ignore[call-arg]
    assert socket.create_connection is original


def test_profile_attributes_an_actual_fresh_guard_without_replacing_it() -> None:
    profiler = cProfile.Profile()
    assert profiler.runcall(candidate_review_protocol_implementation_is_pristine)
    report = replay_profile(profiler)
    guard = next(
        row
        for row in report["selected_functions"]
        if row["function"] == "implementation_is_pristine"
    )
    inventory = next(
        row
        for row in report["selected_functions"]
        if row["function"] == "_candidate_review_schema_inventory_sha256"
    )
    assert guard["total_calls"] == guard["primitive_calls"] == 1
    assert inventory["total_calls"] == inventory["primitive_calls"] == 1
    assert guard["cumulative_ns"] >= inventory["cumulative_ns"] > 0
    assert sum(row["total_calls"] for row in inventory["direct_callers"]) == 1
    assert all(not row["file"].startswith("/") for row in report["selected_functions"])
