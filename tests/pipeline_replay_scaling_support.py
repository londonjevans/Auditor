"""Developer measurements around the original full-pipeline regression, never its validators."""

from __future__ import annotations

import cProfile
import hashlib
import json
import pstats
import shutil
import socket
import stat
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

import mmaudit.operator_secrets as secrets_module
from mmaudit.config import AuditConfig
from mmaudit.constants import ExitCode
from mmaudit.orchestration.pipeline import PipelineResult
from tests.conftest import FIXTURES, base_config_data
from tests.integration import test_unresolved_recovery_tree_pipeline as original_test
from tests.integration.test_scheduler_truncation_recovery_pipeline import (
    _assert_resume_retains_exact_scheduler_journal,
    _candidate_and_surface_inventory,
    _recovery_entries,
)
from tests.scheduler_scaling_support import (
    ROOT,
    _profile_summary,
    duration_summary,
    profile_location,
)
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot
from tests.unresolved_recovery_tree_support import TreeScenario, tree_scenarios

CASE_PATH = FIXTURES / "pipeline_replay_scaling/cases.json"
SCOPE = "SYNTHETIC_FULL_PIPELINE_ORIGINAL_REPLAY_NO_PROVIDER"
PROFILE_TARGETS = frozenset(
    {
        "implementation_is_pristine",
        "_candidate_review_schema_inventory_sha256",
        "_candidate_review_schema_input_guard",
        "read_recovery_tree_snapshot",
        "_resume_scheduler_journal_impl",
        "_require_durable_snapshot",
        "_require_incremental_durable_snapshot",
        "_build_journal_evidence",
        "_load_exact_resume_privacy_evidence",
        "_write_artifacts",
    }
)


def load_pipeline_replay_cases(path: Path = CASE_PATH) -> tuple[TreeScenario, ...]:
    """Refuse any change to this predeclared experiment, including ambiguous JSON."""

    with path.open("rb") as handle:
        raw = handle.read(4097)
    if len(raw) > 4096:
        raise ValueError("pipeline experiment exceeds its byte bound")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("pipeline experiment has duplicate fields")
            value[key] = item
        return value

    expected: dict[str, Any] = {
        "schema_version": "1.0",
        "scope": SCOPE,
        "cases": ["generic-open", "mixed-specialist"],
        "fresh_pipeline_samples": 1,
        "unprofiled_resume_samples": 3,
        "additional_profiled_resume_samples": 1,
        "serial_execution": True,
        "runtime_optimization_applied": False,
    }
    value = json.loads(raw, object_pairs_hook=unique)
    # Canonical JSON distinguishes bool/int and int/float, unlike Python equality.
    if json.dumps(value, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("pipeline experiment differs from its declared selection")
    by_name = {case.name: case for case in tree_scenarios()}
    return tuple(by_name[name] for name in expected["cases"])


def replay_profile(profiler: cProfile.Profile) -> dict[str, Any]:
    """Retain useful call counts and direct callers without publishing host paths."""

    selected = []
    stats = cast(
        dict[
            tuple[str, int, str],
            tuple[
                int, int, float, float, dict[tuple[str, int, str], tuple[int, int, float, float]]
            ],
        ],
        vars(pstats.Stats(profiler))["stats"],
    )
    for (filename, line, function), (primitive, total, own, cumulative, callers) in stats.items():
        if function not in PROFILE_TARGETS or not filename.startswith(str(ROOT / "src") + "/"):
            continue
        selected.append(
            {
                "file": profile_location(filename),
                "line": line,
                "function": function,
                "primitive_calls": primitive,
                "total_calls": total,
                "self_ns": round(own * 1_000_000_000),
                "cumulative_ns": round(cumulative * 1_000_000_000),
                "direct_callers": [
                    {
                        "file": profile_location(caller[0]),
                        "line": caller[1],
                        "function": caller[2],
                        "primitive_calls": values[0],
                        "total_calls": values[1],
                        "self_ns": round(values[2] * 1_000_000_000),
                        "cumulative_ns": round(values[3] * 1_000_000_000),
                    }
                    for caller, values in sorted(callers.items())
                ],
            }
        )
    return {
        "rows": _profile_summary(profiler),
        "selected_functions": sorted(selected, key=lambda row: (row["file"], row["line"])),
        "main_thread_only": True,
        "inclusive_times_overlap": True,
    }


async def measure_async_phase[T](
    operation: Callable[[], Awaitable[T]],
    verify: Callable[[T], None],
    *,
    samples: int = 3,
    profile: bool = True,
    progress: Callable[[str], None] = lambda _phase: None,
) -> tuple[T, dict[str, Any]]:
    """Time each complete awaited operation; a failed operation or invariant is not a sample."""

    if type(samples) is not int or samples not in {1, 3} or type(profile) is not bool:
        raise ValueError("select one test sample or three experiment samples and an exact bool")
    observations = []
    for index in range(samples):
        progress(f"unprofiled_{index + 1}")
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        value = await operation()
        elapsed = {"cpu_ns": time.process_time_ns() - cpu, "wall_ns": time.perf_counter_ns() - wall}
        verify(value)
        observations.append(elapsed)
    result = duration_summary(observations)
    if profile:
        progress("separate_profile")
        profiler = cProfile.Profile()
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        try:
            profiler.enable()
            value = await operation()
        finally:
            profiler.disable()
        elapsed = {"cpu_ns": time.process_time_ns() - cpu, "wall_ns": time.perf_counter_ns() - wall}
        verify(value)
        result["separate_profile"] = {
            **elapsed,
            **replay_profile(profiler),
            "included_in_unprofiled_samples": False,
        }
    return value, result


@contextmanager
def no_external_io() -> Iterator[None]:
    """Keep the developer experiment on original synthetic inputs and MockTransport only."""

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("pipeline measurements must not access networks or operator secrets")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket.socket, "connect", forbidden)
        patch.setattr(socket, "create_connection", forbidden)
        patch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
        patch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
        patch.setattr(secrets_module, "load_operator_secrets", forbidden)
        yield


def _synthetic_config(**sections: dict[str, Any]) -> AuditConfig:
    values = base_config_data()
    for key, updates in sections.items():
        if isinstance(values.get(key), dict):
            values[key].update(updates)
        else:
            values[key] = updates
    return AuditConfig.model_validate(values)


async def measure_original_pipeline_replay(
    case: TreeScenario,
    workspace: Path,
    *,
    samples: int = 3,
    profile: bool = True,
    progress: Callable[[str], None] = lambda _phase: None,
) -> dict[str, Any]:
    """Measure full original replay; the existing regression remains the final assertion owner."""

    case = TreeScenario.model_validate(case.model_dump(mode="python"), strict=True)
    if case not in tree_scenarios() or not case.pipeline:
        raise ValueError("pipeline case must be an original declared synthetic scenario")
    if type(samples) is not int or samples not in {1, 3} or type(profile) is not bool:
        raise ValueError("invalid pipeline measurement options")
    info = workspace.lstat()
    if not workspace.is_absolute() or not stat.S_ISDIR(info.st_mode) or workspace.is_symlink():
        raise ValueError("pipeline workspace must be an original absolute directory")
    directory = workspace / case.name
    directory.mkdir(mode=0o700)
    repo = directory / "vulnerable_app"
    shutil.copytree(FIXTURES / "vulnerable_app", repo)
    original_run = cast(Callable[..., Awaitable[PipelineResult]], vars(original_test)["_run"])
    observations: dict[str, Any] = {}
    original_result: PipelineResult | None = None
    call_count = 0

    async def measured_run(*args: Any, **kwargs: Any) -> PipelineResult:
        nonlocal original_result, call_count
        call_count += 1
        if call_count == 1:
            assert kwargs.get("resume_run_dir") is None
            first_result, measured = await measure_async_phase(
                lambda: original_run(*args, **kwargs),
                lambda value: None,
                samples=1,
                profile=False,
                progress=lambda name: progress("fresh_pipeline:" + name),
            )
            original_result = first_result
            observations["fresh_pipeline"] = measured
            return first_result
        assert call_count == 2 and original_result is not None
        first = original_result
        assert kwargs["resume_run_dir"] == first.run_dir
        owner = first.run_dir / "private/scheduler-journal"
        original_files = _journal_private_file_snapshot(owner)
        entries = _recovery_entries(first.run_dir)
        inventory = _candidate_and_surface_inventory(first.run_dir)
        role_bytes = (first.run_dir / "specialist-execution.json").read_bytes()
        ledger = kwargs["cost_ledger"]
        ledger_snapshot = ledger.snapshot()
        ledger_bytes = (directory / "synthetic-ledger.json").read_bytes()
        fake = args[3]

        def verify(value: PipelineResult) -> None:
            assert value.exit_code is ExitCode.INCOMPLETE and not value.report.completed
            assert fake.chat_calls == fake.recovery_child_calls == 0
            assert fake.truncated_parent_calls == fake.specialist_truncation_calls == 0
            assert not fake.retained_ids_by_request
            assert _journal_private_file_snapshot(owner) == original_files
            assert _recovery_entries(first.run_dir) == entries
            assert ledger.snapshot() == ledger_snapshot
            assert (directory / "synthetic-ledger.json").read_bytes() == ledger_bytes
            assert _candidate_and_surface_inventory(value.run_dir) == inventory
            assert (value.run_dir / "specialist-execution.json").read_bytes() == role_bytes
            _assert_resume_retains_exact_scheduler_journal(
                owner=first.run_dir, consumer=value.run_dir
            )

        value, measured = await measure_async_phase(
            lambda: original_run(*args, **kwargs),
            verify,
            samples=samples,
            profile=profile,
            progress=lambda name: progress("full_original_resume:" + name),
        )
        observations["full_original_resume"] = measured
        observations["original_file_count"] = len(original_files)
        observations["original_file_bytes"] = sum(len(item[0]) for item in original_files.values())
        observations["original_entry_values_sha256"] = hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        observations["synthetic_ledger_sha256"] = hashlib.sha256(ledger_bytes).hexdigest()
        return value

    with no_external_io(), pytest.MonkeyPatch.context() as patch:
        # Only the test's call site is wrapped. AuditPipeline and every runtime guard remain exact.
        patch.setattr(original_test, "_run", measured_run)
        await original_test.test_automatic_unresolved_tree_preserves_original_scope_costs_roles_and_resume(
            _synthetic_config, patch, repo, directory, case
        )
    assert vars(original_test)["_run"] is original_run and call_count == 2
    return {
        "schema_version": "1.0",
        "scope": SCOPE,
        "case": case.model_dump(mode="json"),
        **observations,
        "original_regression_assertions_passed": True,
        "verification_outside_timing": True,
        "original_files_costs_findings_roles_unchanged": True,
        "new_resume_dispatches": 0,
        "real_provider_calls": 0,
        "promotion_or_completion_credit": False,
        "runtime_optimization_applied": False,
        "throughput_claim": False,
    }
