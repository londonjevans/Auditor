"""Bounded local replay-result verification; never runtime, qualification or release authority."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from statistics import median
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.actor_model import ActorModelInputEvidence
from tests.pipeline_replay_scaling_support import PROFILE_TARGETS, load_pipeline_replay_cases
from tests.pipeline_replay_workload import (
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    ReplayDeclaration,
    ReplayInput,
    _FrozenModel,
    _read_regular,
    load_replay_declaration,
    require_same_replay_workload,
)
from tests.unresolved_recovery_tree_support import TreeScenario

MAX_CAPTURE_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
PHASES = (
    "fresh_pipeline:unprofiled_1",
    "full_original_resume:unprofiled_1",
    "full_original_resume:unprofiled_2",
    "full_original_resume:unprofiled_3",
    "full_original_resume:separate_profile",
)
EXPECTED = {"generic-open": (13436, 103, 7), "mixed-specialist": (26507, 174, 15)}
SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
Nanoseconds = Annotated[int, Field(ge=0, le=86_400_000_000_000)]
Count = Annotated[int, Field(ge=0, le=1_000_000_000_000)]


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _json(raw: str | bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate replay JSON field")
            result[key] = value
        return result

    def invalid(_value: str) -> None:
        raise ValueError("nonfinite replay JSON value")

    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    canonical(value)  # Also reject numeric overflow such as 1e999.
    return value


class NativeReplayResult(_FrozenModel):
    chunk_id: str = Field(pattern=r"^[0-9a-f]{6,64}$", max_length=64)
    wall_time_seconds: float = Field(ge=0, le=43200, allow_inf_nan=False)
    output: str = Field(max_length=MAX_OUTPUT_BYTES)
    session_id: int | None = Field(default=None, gt=0)
    exit_code: int | None = Field(default=None, ge=-255, le=255)
    original_token_count: int | None = Field(default=None, ge=0, le=MAX_OUTPUT_BYTES)


class ReplayCapture(_FrozenModel):
    schema_version: Literal["2.0"]
    capture_kind: Literal["NATIVE_EXEC_COMMAND_WRITE_STDIN_RESULTS_NOT_EXECUTION_ATTESTATION"]
    native_session_id: int = Field(gt=0)
    results: tuple[NativeReplayResult, ...] = Field(min_length=1, max_length=8192)

    @model_validator(mode="after")
    def bounded_output(self) -> Self:
        if sum(len(item.output.encode()) for item in self.results) > MAX_OUTPUT_BYTES:
            raise ValueError("replay output exceeds its byte bound")
        return self


class ReplayFileEvidence(_FrozenModel):
    """Fingerprint all five run directories and the synthetic ledger after original assertions."""

    file_count: int = Field(gt=0, le=MAX_FILES)
    total_bytes: int = Field(gt=0, le=MAX_TOTAL_BYTES)
    inventory_sha256: SHA256
    directory_inventory_sha256: SHA256
    owner_run_id: str = Field(min_length=1, max_length=128)
    run_ids: tuple[str, str, str, str, str]


class Sample(_FrozenModel):
    wall_ns: Nanoseconds
    cpu_ns: Nanoseconds


class Summary(_FrozenModel):
    minimum: Nanoseconds
    median: Nanoseconds
    maximum: Nanoseconds


class ProfileRow(_FrozenModel):
    file: str = Field(min_length=1, max_length=512)
    line: int = Field(ge=0, le=10_000_000)
    function: str = Field(min_length=1, max_length=512)
    primitive_calls: Count
    total_calls: Count
    self_ns: Nanoseconds
    cumulative_ns: Nanoseconds

    @model_validator(mode="after")
    def bounded_location_and_counts(self) -> Self:
        ReplayInput(path=self.file, sha256="0" * 64, byte_count=0)
        if self.total_calls < 1 or self.primitive_calls > self.total_calls:
            raise ValueError("invalid replay profile call counts")
        return self


class SelectedProfileRow(ProfileRow):
    direct_callers: tuple[ProfileRow, ...] = Field(min_length=1, max_length=1024)


def _unique_rows(rows: tuple[ProfileRow, ...]) -> None:
    if len({(row.file, row.line, row.function) for row in rows}) != len(rows):
        raise ValueError("duplicate replay profile location")


class SeparateProfile(Sample):
    rows: tuple[ProfileRow, ...] = Field(min_length=1, max_length=24)
    selected_functions: tuple[SelectedProfileRow, ...] = Field(min_length=3, max_length=256)
    main_thread_only: bool
    inclusive_times_overlap: bool
    included_in_unprofiled_samples: bool

    @model_validator(mode="after")
    def keep_profile_separate(self) -> Self:
        if (
            not self.main_thread_only
            or not self.inclusive_times_overlap
            or self.included_in_unprofiled_samples
            or self.wall_ns == 0
        ):
            raise ValueError("invalid separate replay profile")
        _unique_rows(self.rows)
        _unique_rows(self.selected_functions)
        for row in self.selected_functions:
            _unique_rows(row.direct_callers)
            if not row.file.startswith("src/") or row.function not in PROFILE_TARGETS:
                raise ValueError("unexpected selected replay profile function")
        return self


class Timings(_FrozenModel):
    samples: tuple[Sample, ...] = Field(min_length=1, max_length=3)
    wall_ns: Summary
    cpu_ns: Summary

    @model_validator(mode="after")
    def summaries_cover_every_sample(self) -> Self:
        for clock in ("wall_ns", "cpu_ns"):
            values = [getattr(sample, clock) for sample in self.samples]
            if getattr(self, clock).model_dump() != {
                "minimum": min(values),
                "median": median(values),
                "maximum": max(values),
            }:
                raise ValueError("replay summary differs from original samples")
        return self


class ResumeTimings(Timings):
    separate_profile: SeparateProfile


class ReplayIdentity(_FrozenModel):
    declaration_sha256: SHA256
    workload_sha256: SHA256
    implementation_sha256: SHA256
    declaration_is_execution_or_qualification_evidence: bool

    @model_validator(mode="after")
    def declaration_is_not_authority(self) -> Self:
        if self.declaration_is_execution_or_qualification_evidence:
            raise ValueError("replay declarations are not execution authority")
        return self


class ReplayCaseResult(ReplayIdentity):
    schema_version: Literal["1.0"]
    scope: Literal["SYNTHETIC_FULL_PIPELINE_ORIGINAL_REPLAY_NO_PROVIDER"]
    case: TreeScenario
    fresh_pipeline: Timings
    full_original_resume: ResumeTimings
    original_file_count: int = Field(gt=0, le=MAX_FILES)
    original_file_bytes: int = Field(gt=0, le=MAX_TOTAL_BYTES)
    original_entry_values_sha256: SHA256
    synthetic_ledger_sha256: SHA256
    original_regression_assertions_passed: bool
    verification_outside_timing: bool
    original_files_costs_findings_roles_unchanged: bool
    new_resume_dispatches: int = Field(ge=0, le=0)
    real_provider_calls: int = Field(ge=0, le=0)
    promotion_or_completion_credit: bool
    runtime_optimization_applied: bool
    throughput_claim: bool
    original_evidence: ReplayFileEvidence

    @model_validator(mode="after")
    def complete_original_case(self) -> Self:
        if self.case not in load_pipeline_replay_cases():
            raise ValueError("unexpected replay case")
        if len(self.fresh_pipeline.samples) != 1 or len(self.full_original_resume.samples) != 3:
            raise ValueError("replay must retain every original sample")
        if not all(
            (
                self.original_regression_assertions_passed,
                self.verification_outside_timing,
                self.original_files_costs_findings_roles_unchanged,
            )
        ) or any(
            (
                self.promotion_or_completion_credit,
                self.runtime_optimization_applied,
                self.throughput_claim,
            )
        ):
            raise ValueError("replay invariants failed or unsupported credit claimed")
        guards, files, _logs = EXPECTED[self.case.name]
        if self.original_file_count != files:
            raise ValueError("replay original file count changed")
        selected = self.full_original_resume.separate_profile.selected_functions
        for function in (
            "implementation_is_pristine",
            "_candidate_review_schema_inventory_sha256",
            "_candidate_review_schema_input_guard",
        ):
            matches = [
                row
                for row in selected
                if row.file == "src/mmaudit/models/truncation.py" and row.function == function
            ]
            if len(matches) != 1 or matches[0].total_calls != guards:
                raise ValueError("replay must retain every fresh integrity check")
            row = matches[0]
            if (
                row.primitive_calls != guards
                or sum(c.total_calls for c in row.direct_callers) != guards
            ):
                raise ValueError("replay integrity caller attribution changed")
        return self


def _directory(path: Path) -> os.stat_result:
    if not path.is_absolute() or any(part.startswith(".env") for part in path.parts):
        raise ValueError("replay workspace must be an absolute non-secret directory")
    for parent in (path, *path.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("replay directories must not be links or special files")
    return path.lstat()


def _normalized_review(raw: bytes) -> bytes:
    value = _json(raw)
    for authority in value["context_authorities"]:
        context = authority["context"]
        actor = context["actor_model_evidence"]
        if actor is not None:
            typed = ActorModelInputEvidence.model_validate_json(canonical(actor), strict=True)
            context["actor_model_evidence"] = typed.model_dump(
                mode="json", exclude={"evaluated_at", "evidence_sha256"}
            )
    return canonical(value)


def snapshot_replay_evidence(
    workspace: Path, case_name: str, result: dict[str, Any]
) -> ReplayFileEvidence:
    """Read complete bounded original files; never follow links or execute a captured command."""

    if case_name not in EXPECTED:
        raise ValueError("unexpected replay workspace case")
    base = workspace / case_name
    runs = base / "synthetic-output/runs"
    _directory(runs)
    pending = [runs]
    directories = []
    paths = [base / "synthetic-ledger.json"]
    entries = 0
    while pending:
        directory = pending.pop()
        info = _directory(directory)
        directories.append(
            (
                directory.relative_to(base).as_posix(),
                info.st_dev,
                info.st_ino,
                stat.S_IMODE(info.st_mode),
            )
        )
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if entries > MAX_ENTRIES:
                    raise ValueError("replay evidence traversal exceeds its bound")
                if child.is_symlink():
                    raise ValueError("replay evidence must not contain links")
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                else:
                    paths.append(Path(child.path))
                    if len(paths) > MAX_FILES:
                        raise ValueError("replay evidence file count exceeds its bound")
    contents: dict[str, bytes] = {}
    inventory = []
    total = 0
    for path in sorted(paths):
        relative = path.relative_to(base).as_posix()
        ReplayInput(path=relative, sha256="0" * 64, byte_count=0)
        _directory(path.parent)
        before = path.lstat()
        raw = _read_regular(path, MAX_FILE_BYTES)
        after = path.lstat()

        def metadata(info: os.stat_result) -> tuple[int, ...]:
            return (
                info.st_dev,
                info.st_ino,
                info.st_nlink,
                info.st_mode,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )

        if metadata(before) != metadata(after) or before.st_nlink != 1:
            raise ValueError("replay evidence changed identity during read")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("replay evidence bytes exceed their bound")
        contents[relative] = raw
        inventory.append(
            (
                relative,
                hashlib.sha256(raw).hexdigest(),
                len(raw),
                before.st_dev,
                before.st_ino,
                before.st_nlink,
                stat.S_IMODE(before.st_mode),
            )
        )
    prefix = "synthetic-output/runs/"
    run_ids = sorted(
        name[len(prefix) :]
        for name, *_metadata in directories
        if name.startswith(prefix) and "/" not in name[len(prefix) :]
    )
    owners = [
        name
        for name in run_ids
        if any(path.startswith(prefix + name + "/private/scheduler-journal/") for path in contents)
    ]
    if len(run_ids) != 5 or len(owners) != 1:
        raise ValueError("replay requires one owner and four complete original resumes")
    owner = owners[0]
    owner_prefix = prefix + owner + "/"
    journal = owner_prefix + "private/scheduler-journal/"
    journal_files = {name: raw for name, raw in contents.items() if name.startswith(journal)}
    values = [
        _json(raw)
        for name, raw in journal_files.items()
        if name.startswith(journal + "truncation-recovery/")
        and name.endswith(".json")
        and "/" not in name[len(journal + "truncation-recovery/") :]
    ]
    if (
        not values
        or len(journal_files) != result["original_file_count"]
        or sum(len(raw) for raw in journal_files.values()) != result["original_file_bytes"]
        or hashlib.sha256(canonical(values)).hexdigest() != result["original_entry_values_sha256"]
        or hashlib.sha256(contents["synthetic-ledger.json"]).hexdigest()
        != result["synthetic_ledger_sha256"]
    ):
        raise ValueError("replay original journal or ledger differs from captured evidence")
    owner_state = _json(contents[owner_prefix + "scheduler-state.json"])
    owner_review = _normalized_review(
        contents[owner_prefix + "private/model-review-artifacts.json"]
    )
    for run_id in run_ids:
        if run_id == owner:
            continue
        consumer = prefix + run_id + "/"
        reference = _json(contents[consumer + "private/scheduler-journal-reference.json"])
        expected_reference = {
            "owner_run_id": owner,
            "consumer_run_id": run_id,
            "relative_journal_path": owner + "/private/scheduler-journal",
            "scheduler_artifact_sha256": owner_state["artifact_sha256"],
            "scheduler_journal_evidence_sha256": owner_state["journal_evidence"]["evidence_sha256"],
        }
        if any(
            canonical(reference.get(key)) != canonical(value)
            for key, value in expected_reference.items()
        ):
            raise ValueError("replay resume reference differs from original owner")
        for name in (
            "scheduler-state.json",
            "candidate-findings.json",
            "specialist-execution.json",
        ):
            if contents[consumer + name] != contents[owner_prefix + name]:
                raise ValueError("replay resume changed original findings, roles or scheduler")
        if (
            _normalized_review(contents[consumer + "private/model-review-artifacts.json"])
            != owner_review
        ):
            raise ValueError("replay resume changed original coverage inventory")
    return ReplayFileEvidence.model_validate_json(
        canonical(
            {
                "file_count": len(inventory),
                "total_bytes": total,
                "inventory_sha256": hashlib.sha256(canonical(inventory)).hexdigest(),
                "directory_inventory_sha256": hashlib.sha256(
                    canonical(sorted(directories))
                ).hexdigest(),
                "owner_run_id": owner,
                "run_ids": run_ids,
            }
        ),
        strict=True,
    )


def _pinned(path: Path, sha256: str, maximum: int) -> bytes:
    ReplayInput(path="capture.json", sha256=sha256, byte_count=0)
    _directory(path.parent)
    raw = _read_regular(path, maximum)
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("replay artifact differs from caller pin")
    return raw


def load_replay_capture(path: Path, sha256: str) -> ReplayCapture:
    raw = _pinned(path, sha256, MAX_CAPTURE_BYTES)
    _json(raw)
    return ReplayCapture.model_validate_json(raw, strict=True)


def write_replay_capture(path: Path, capture: ReplayCapture) -> str:
    """Retain even failed or incomplete native output once; writing cannot grant acceptance."""

    raw = canonical(capture.model_dump(mode="json"))
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("replay capture exceeds its byte bound")
    _directory(path.parent)
    ReplayCapture.model_validate_json(raw, strict=True)
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb"
    ) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def validate_replay_capture(
    capture: ReplayCapture, declaration: ReplayDeclaration, workspace: Path, expected_session: int
) -> tuple[ReplayCaseResult, ReplayCaseResult]:
    """Require a complete local observation, not merely input equality or a reported zero exit."""

    if (
        type(expected_session) is not int
        or expected_session <= 0
        or capture.native_session_id != expected_session
    ):
        raise ValueError("replay native session differs from caller selection")
    if len({item.chunk_id for item in capture.results}) != len(capture.results):
        raise ValueError("duplicate native replay receipt")
    for index, item in enumerate(capture.results):
        if item.session_id not in (None, expected_session):
            raise ValueError("mixed native replay sessions")
        if index < len(capture.results) - 1:
            if item.exit_code is not None or item.session_id != expected_session:
                raise ValueError("replay receipt continues after termination or missing handle")
        elif item.exit_code != 0:
            raise ValueError("replay native process failed or has no terminal zero")
    output = "".join(item.output for item in capture.results).replace("\r\n", "\n")
    if not output.endswith("\n"):
        raise ValueError("replay output ends in an incomplete record")
    records = []
    log_positions: list[int] = []
    for line in output.splitlines():
        if line.startswith("{"):
            records.append(_json(line))
        elif line == "Structured model request failed":
            log_positions.append(len(records))
        elif line:
            raise ValueError("unexpected or truncated native replay diagnostics")
    if len(records) != 14 or log_positions != [2] * 7 + [8] * 15:
        raise ValueError("replay capture omits or reorders records or diagnostics")
    identity = {
        "declaration_sha256": declaration.sha256,
        "workload_sha256": declaration.workload_sha256,
        "implementation_sha256": declaration.implementation_sha256,
        "declaration_is_execution_or_qualification_evidence": False,
    }
    case_input = next(
        (
            item
            for item in declaration.workload.inputs
            if item.path == "tests/fixtures/pipeline_replay_scaling/cases.json"
        ),
        None,
    )
    if case_input is None:
        raise ValueError("replay declaration omits original case input")
    header = {
        "experiment": "pipeline-replay-scaling-v2",
        **identity,
        "cases_sha256": case_input.sha256,
        "python": declaration.workload.environment.python,
        "platform": declaration.workload.environment.system,
        "cases": [case.name for case in declaration.workload.cases],
        "fresh_pipeline_samples": 1,
        "unprofiled_resume_samples": 3,
        "additional_profiled_resume_samples": 1,
        "serial_execution": True,
        "test_only_model_plan_override": True,
    }
    terminal = {
        "experiment_complete": True,
        "real_provider_calls": 0,
        "optimization_applied": False,
        **identity,
    }
    if canonical(records[0]) != canonical(header) or canonical(records[-1]) != canonical(terminal):
        raise ValueError("replay header or terminal differs from the declared contract")
    verified = []
    for index, scenario in enumerate(declaration.workload.cases):
        offset = 1 + 6 * index
        expected_phases = [{"case": scenario.name, "phase_started": phase} for phase in PHASES]
        if canonical(records[offset : offset + 5]) != canonical(expected_phases):
            raise ValueError("replay phases are incomplete, interleaved or reordered")
        completion = records[offset + 5]
        if not isinstance(completion, dict) or set(completion) != {"completed_case"}:
            raise ValueError("replay case completion is missing or ambiguous")
        case = ReplayCaseResult.model_validate_json(
            canonical(completion["completed_case"]), strict=True
        )
        if case.case != scenario or any(
            getattr(case, key) != value for key, value in identity.items()
        ):
            raise ValueError("replay case differs from its declared identity")
        observed = snapshot_replay_evidence(workspace, scenario.name, case.model_dump(mode="json"))
        if observed != case.original_evidence:
            raise ValueError("replay output bytes, file identities or permissions changed")
        verified.append(case)
    return verified[0], verified[1]


def compare_replay_results(
    before: tuple[ReplayCaseResult, ReplayCaseResult],
    after: tuple[ReplayCaseResult, ReplayCaseResult],
) -> list[dict[str, Any]]:
    """Retain all observations, including regressions and undefined zero-baseline ratios."""

    rows = []
    for left, right in zip(before, after, strict=True):
        if left.case != right.case:
            raise ValueError("replay comparison cases differ")
        ratios = {}
        for phase in ("fresh_pipeline", "full_original_resume", "separate_profile"):
            for clock in ("wall_ns", "cpu_ns"):
                if phase == "separate_profile":
                    a = getattr(left.full_original_resume.separate_profile, clock)
                    b = getattr(right.full_original_resume.separate_profile, clock)
                else:
                    a = getattr(getattr(left, phase), clock).median
                    b = getattr(getattr(right, phase), clock).median
                ratios[phase + ":" + clock] = {
                    "before_ns": a,
                    "after_ns": b,
                    "regressed": b > a,
                    "after_over_before": b / a if a else None,
                    "decrease_percent": 100 * (a - b) / a if a else None,
                }
        rows.append(
            {
                "case": left.case.name,
                "ratios": ratios,
                "before": left.model_dump(mode="json"),
                "after": right.model_dump(mode="json"),
            }
        )
    return rows


def verify_replay_pair(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Verify two caller-selected artifacts; rejection is reportable without losing either input."""

    if (
        before["session"] == after["session"]
        or before["capture_sha256"] == after["capture_sha256"]
        or before["workspace"].resolve() == after["workspace"].resolve()
    ):
        raise ValueError(
            "paired replay results require distinct original executions and workspaces"
        )
    declarations = []
    cases = []
    for selected in (before, after):
        _directory(selected["declaration"].parent)
        declaration = load_replay_declaration(
            selected["declaration"], selected["declaration_sha256"]
        )
        capture = load_replay_capture(selected["capture"], selected["capture_sha256"])
        declarations.append(declaration)
        cases.append(
            validate_replay_capture(
                capture, declaration, selected["workspace"], selected["session"]
            )
        )
    changed = require_same_replay_workload(declarations[0], declarations[1])
    return {
        "schema_version": "2.0",
        "scope": "LOCAL_REPLAY_COMPARISON_NOT_EXECUTION_ATTESTATION",
        "accepted": True,
        "workload_sha256": declarations[0].workload_sha256,
        "changed_implementation_paths": list(changed),
        "before_capture_sha256": before["capture_sha256"],
        "after_capture_sha256": after["capture_sha256"],
        "cases": compare_replay_results(cases[0], cases[1]),
        "real_provider_calls": 0,
        "new_workloads_executed": 0,
        "execution_attested": False,
        "qualification_or_release_authority": False,
        "causal_or_production_throughput_claim": False,
        "all_native_receipts_samples_profiles_and_regressions_retained": True,
    }
