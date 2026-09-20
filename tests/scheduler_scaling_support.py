"""Developer-only original journal measurements; no provider or audit authority."""

from __future__ import annotations

import cProfile
import hashlib
import json
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from decimal import Decimal
from pathlib import Path
from statistics import median
from types import CodeType
from typing import Any

import pytest

from mmaudit.models.schemas import CandidateFinding, ModelSurfaceReviewRecord
from mmaudit.models.truncation import CandidateReviewTruncationProjection
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyPromotion,
)
from mmaudit.orchestration.provisional_findings import build_provisional_finding_inventory
from mmaudit.orchestration.scheduler import SchedulerJournal, resume_scheduler_journal
from tests.unit import test_truncation_recovery_journal as projection_support
from tests.unit.test_generic_truncation_tree import _build_tree
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot
from tests.unit.test_truncation import _candidate

ROOT = Path(__file__).resolve().parents[1]
CASE_PATH = ROOT / "tests/fixtures/scheduler_scaling/cases.json"
MAX_PROFILE_ROWS = 24


@dataclass(frozen=True)
class ScalingCase:
    case_id: str
    surface_count: int
    depth: int
    families: int
    children: int

    def __post_init__(self) -> None:
        numbers = (self.surface_count, self.depth, self.families, self.children)
        if any(type(value) is not int for value in numbers) or not 1 <= self.depth <= 4:
            raise ValueError("scaling case requires exact bounded integer dimensions")
        if (
            self.case_id != f"depth-{self.depth}"
            or self.surface_count != 2**self.depth + 1
            or self.families != 2**self.depth - 1
            or self.children != 2 * self.families
        ):
            raise ValueError("scaling case differs from its declared complete binary tree")


def load_scaling_cases(path: Path = CASE_PATH) -> tuple[ScalingCase, ...]:
    """Accept only the four predeclared synthetic shapes, never arbitrary work instructions."""

    with path.open("rb") as handle:
        raw = handle.read(4097)
    if len(raw) > 4096:
        raise ValueError("scaling cases exceed their byte bound")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("scaling cases contain a duplicate field")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique_object)
    expected = {
        "schema_version": "1.0",
        "scope": "SYNTHETIC_ORIGINAL_JOURNAL_NO_PROVIDER",
        "request_limit": 33,
        "unprofiled_samples": 3,
        "cases": [
            asdict(
                ScalingCase(
                    f"depth-{depth}", 2**depth + 1, depth, 2**depth - 1, 2 ** (depth + 1) - 2
                )
            )
            for depth in range(1, 5)
        ],
    }
    if value != expected:
        raise ValueError("scaling cases differ from the predeclared experiment")
    return tuple(ScalingCase(**case) for case in value["cases"])


def duration_summary(samples: list[dict[str, int]]) -> dict[str, Any]:
    """Summarize observed nanoseconds without interpreting them as a performance guarantee."""

    if not 1 <= len(samples) <= 3 or any(
        set(sample) != {"wall_ns", "cpu_ns"}
        or any(type(value) is not int or value < 0 for value in sample.values())
        for sample in samples
    ):
        raise ValueError("duration samples must be bounded nonnegative integer observations")
    return {
        "samples": samples,
        **{
            key: {
                "minimum": min(sample[key] for sample in samples),
                "median": median(sample[key] for sample in samples),
                "maximum": max(sample[key] for sample in samples),
            }
            for key in ("wall_ns", "cpu_ns")
        },
    }


def profile_location(filename: str) -> str:
    """Keep repository locations useful without publishing host-specific absolute paths."""

    if filename == "~" or filename.startswith("<"):
        return filename
    path = Path(filename)
    if path.is_absolute() and path.is_relative_to(ROOT):
        return path.relative_to(ROOT).as_posix()
    if "site-packages/" in filename:
        return "<site-packages>/" + filename.split("site-packages/", 1)[1]
    return "<external>/" + path.name


def _profile_summary(profiler: cProfile.Profile) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for entry in profiler.getstats():
        code = entry.code
        if isinstance(code, CodeType):
            filename, line, function = code.co_filename, code.co_firstlineno, code.co_name
        else:
            filename, line, function = "~", 0, str(code)
        rows.append(
            {
                "file": profile_location(filename),
                "line": line,
                "function": function,
                "primitive_calls": entry.callcount - entry.reccallcount,
                "total_calls": entry.callcount,
                "self_ns": round(entry.inlinetime * 1_000_000_000),
                "cumulative_ns": round(entry.totaltime * 1_000_000_000),
            }
        )
    selected: dict[tuple[str, int, str], dict[str, Any]] = {}
    for metric in ("cumulative_ns", "self_ns"):
        for row in sorted(rows, key=lambda item: item[metric], reverse=True)[:12]:
            selected[row["file"], row["line"], row["function"]] = row
    assert len(selected) <= MAX_PROFILE_ROWS
    return sorted(selected.values(), key=lambda row: (-row["cumulative_ns"], row["file"]))


def measure_phase[T](
    operation: Callable[[], T],
    verify: Callable[[T], None],
    *,
    samples: int = 3,
    profile: bool = True,
) -> dict[str, Any]:
    """Measure only the operation; invariants run after timing and outside call profiles."""

    if type(samples) is not int or samples not in {1, 3} or type(profile) is not bool:
        raise ValueError("measurement requires one test sample or three experiment samples")
    observations = []
    for _ in range(samples):
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        value = operation()
        cpu_elapsed, wall_elapsed = time.process_time_ns() - cpu, time.perf_counter_ns() - wall
        verify(value)
        observations.append({"wall_ns": wall_elapsed, "cpu_ns": cpu_elapsed})
    result = duration_summary(observations)
    if profile:
        profiler = cProfile.Profile()
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        try:
            profiler.enable()
            value = operation()
        finally:
            profiler.disable()
        cpu_elapsed, wall_elapsed = time.process_time_ns() - cpu, time.perf_counter_ns() - wall
        verify(value)
        result["separate_profile"] = {
            "wall_ns": wall_elapsed,
            "cpu_ns": cpu_elapsed,
            "rows": _profile_summary(profiler),
            "included_in_unprofiled_samples": False,
        }
    return result


@contextmanager
def _nonempty_original_projection() -> Iterator[None]:
    original = projection_support._projection
    finding = _candidate("synthetic-scaling-provisional")

    def projection(
        surfaces: tuple[ModelSurfaceReviewRecord, ...],
        *,
        retained_count: int,
        findings: tuple[CandidateFinding, ...] = (),
        algorithm_version: str = "mmaudit.seven-pass-scheduler.v2",
    ) -> CandidateReviewTruncationProjection:
        if findings:
            raise ValueError("scaling fixture must supply exactly its declared synthetic finding")
        return original(
            surfaces,
            retained_count=retained_count,
            findings=(finding,),
            algorithm_version=algorithm_version,
        )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(projection_support, "_projection", projection)
        yield
    assert projection_support._projection is original


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def measure_original_tree(
    case: ScalingCase,
    workspace: Path,
    *,
    samples: int = 3,
    profile: bool = True,
    progress: Callable[[str], None] = lambda _phase: None,
) -> dict[str, Any]:
    """Measure an original nonempty tree and exact replay; never change runtime predicates."""

    # Revalidate a caller-supplied dataclass before choosing paths or creating work.
    case = ScalingCase(**asdict(case))
    if type(samples) is not int or samples not in {1, 3} or type(profile) is not bool:
        raise ValueError("invalid scaling measurement options")
    info = workspace.lstat()
    if not workspace.is_absolute() or not stat.S_ISDIR(info.st_mode) or workspace.is_symlink():
        raise ValueError("scaling workspace must be an original absolute directory")
    directory = workspace / case.case_id
    directory.mkdir(mode=0o700)
    path = directory / "scheduler-journal"
    progress("construction")
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    with _nonempty_original_projection():
        journal, refusals = _build_tree(path, source_count=case.surface_count, request_limit=33)
    setup = {"cpu_ns": time.process_time_ns() - cpu, "wall_ns": time.perf_counter_ns() - wall}
    try:
        if refusals:
            raise ValueError("predeclared scaling tree did not complete structurally")
        families = journal.truncation_recovery_families
        entries = journal.truncation_recovery_entries
        results = tuple(
            item for item in entries if isinstance(item, SchedulerTruncationRecoveryChildResult)
        )
        activations = tuple(
            item for item in entries if isinstance(item, SchedulerTruncationRecoveryChildActivation)
        )
        closures = tuple(
            item for item in entries if isinstance(item, SchedulerTruncationRecoveryFamilyClosure)
        )
        assert len(families) == len(closures) == case.families
        assert len(results) == len(activations) == case.children
        assert (
            max(child.depth for family in families for child in family.recovery_plan.children)
            == case.depth
        )
        assert [entry.request_limit_count_before_child for entry in activations] == list(
            range(1, case.children + 1)
        )
        assert not any(
            isinstance(item, SchedulerTruncationRecoveryFamilyPromotion) for item in entries
        )
        assert all(
            not item.review_credit_authorized and not item.coverage_credit_authorized
            for item in results
        )
        assert all(
            not item.coverage_credit_authorized and not item.completion_authorized
            for item in closures
        )
        assert not journal.dispatchable_truncation_recovery_child_ids
        assert (
            sum((Decimal(item.accounted_cost_usd_exact) for item in results), Decimal("0"))
            == Decimal("0.05") * case.children
        )
        evidence = journal.journal_evidence
        artifact = journal.artifact()
        provisional = build_provisional_finding_inventory(journal, scheduler_artifact=artifact)
        assert provisional is not None and provisional.retained_finding_count == case.families
        assert len(provisional.sources) == case.families
        original_bytes = provisional.model_dump_json()
        original_entries = _stable_json([item.model_dump(mode="json") for item in entries])
        before = _journal_private_file_snapshot(path)
        bindings, shards = journal.manifest.bindings, journal.manifest.shard_inventory
        analysis_inputs = journal.analysis_input_inventory
        phases: dict[str, Any] = {}

        def unchanged() -> None:
            assert _journal_private_file_snapshot(path) == before

        def exact_evidence(value: Any) -> None:
            assert value == evidence
            unchanged()

        def exact_artifact(value: Any) -> None:
            assert value == artifact
            unchanged()

        def exact_export(value: Any) -> None:
            assert value is not None and value.model_dump_json() == original_bytes
            unchanged()

        for name, operation, verify in (
            ("journal_evidence", lambda: journal.journal_evidence, exact_evidence),
            ("public_artifact", journal.artifact, exact_artifact),
            (
                "provisional_export",
                lambda: build_provisional_finding_inventory(journal, scheduler_artifact=artifact),
                exact_export,
            ),
        ):
            progress(name)
            phases[name] = measure_phase(operation, verify, samples=samples, profile=profile)
        journal.close()
        unchanged()

        def resume() -> SchedulerJournal:
            return resume_scheduler_journal(
                path,
                expected_bindings=bindings,
                expected_shard_inventory=shards,
                expected_analysis_input_inventory=analysis_inputs,
                expected_journal_evidence=evidence,
            )

        def exact_resume(resumed: SchedulerJournal) -> None:
            try:
                assert resumed.journal_evidence == evidence
                assert (
                    _stable_json(
                        [
                            item.model_dump(mode="json")
                            for item in resumed.truncation_recovery_entries
                        ]
                    )
                    == original_entries
                )
                assert not resumed.dispatchable_truncation_recovery_child_ids
                exact_export(
                    build_provisional_finding_inventory(resumed, scheduler_artifact=artifact)
                )
                unchanged()
            finally:
                resumed.close()
            unchanged()

        progress("original_resume")
        phases["original_resume"] = measure_phase(
            resume, exact_resume, samples=samples, profile=profile
        )
        resumed = resume()
        try:
            progress("resumed_export")
            phases["resumed_export"] = measure_phase(
                lambda: build_provisional_finding_inventory(resumed, scheduler_artifact=artifact),
                exact_export,
                samples=samples,
                profile=profile,
            )
        finally:
            resumed.close()
        unchanged()
        return {
            "schema_version": "1.0",
            "scope": "SYNTHETIC_ORIGINAL_JOURNAL_NO_PROVIDER",
            "case": asdict(case),
            "request_limit": 33,
            "provisional_findings": provisional.retained_finding_count,
            "original_file_count": len(before),
            "original_file_bytes": sum(len(item[0]) for item in before.values()),
            "original_evidence_sha256": evidence.evidence_sha256,
            "original_provisional_sha256": provisional.inventory_sha256,
            "original_entry_values_sha256": hashlib.sha256(original_entries.encode()).hexdigest(),
            "accounted_child_cost_usd": str(Decimal("0.05") * case.children),
            "construction": setup,
            "phases": phases,
            "original_files_unchanged": True,
            "original_costs_and_request_ordinals_unchanged": True,
            "new_resume_dispatches": 0,
            "provider_calls": 0,
            "promotion_or_completion_credit": False,
            "runtime_optimization_applied": False,
            "throughput_claim": False,
        }
    finally:
        journal.close()
