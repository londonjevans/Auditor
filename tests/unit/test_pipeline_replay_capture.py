"""Synthetic parser/file controls cannot establish an executed audit or a performance gain."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from scripts import measure_pipeline_replay_scaling as runner
from tests import pipeline_replay_capture as subject
from tests.pipeline_replay_scaling_support import SCOPE, load_pipeline_replay_cases
from tests.pipeline_replay_workload import (
    build_replay_declaration,
    load_replay_declaration,
    require_current_replay_inputs,
    write_replay_declaration,
)
from tests.scheduler_scaling_support import ROOT, duration_summary
from tests.unit.test_pipeline_replay_workload import synthetic_replay_project


def _write(path: Path, value: Any) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = subject.canonical(value)
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def synthetic_side(root: Path, revision: int) -> dict[str, Any]:
    """Construct explicitly fabricated local parser evidence, never run a pipeline or a provider."""

    project = synthetic_replay_project(root / "project")
    (project / "src/synthetic.py").write_text(f"# Synthetic implementation revision {revision}.\n")
    declaration = build_replay_declaration(project)
    declaration_path = root / "declaration.json"
    declaration_sha256 = write_replay_declaration(declaration_path, declaration)
    samples = json.loads(
        (ROOT / "tests/fixtures/pipeline_replay_scaling/capture_samples.json").read_bytes()
    )
    assert samples["scope"] == "SYNTHETIC_PARSER_CONTROL_NOT_EXECUTED_PIPELINE"
    times = samples["before" if revision == 0 else "after"]
    workspace = root / "workspace"
    identity = {
        "declaration_sha256": declaration.sha256,
        "workload_sha256": declaration.workload_sha256,
        "implementation_sha256": declaration.implementation_sha256,
        "declaration_is_execution_or_qualification_evidence": False,
    }
    case_pin = next(
        item.sha256
        for item in declaration.workload.inputs
        if item.path == "tests/fixtures/pipeline_replay_scaling/cases.json"
    )
    events: list[Any] = [
        {
            "experiment": "pipeline-replay-scaling-v2",
            **identity,
            "cases_sha256": case_pin,
            "python": declaration.workload.environment.python,
            "platform": declaration.workload.environment.system,
            "cases": [case.name for case in declaration.workload.cases],
            "fresh_pipeline_samples": 1,
            "unprofiled_resume_samples": 3,
            "additional_profiled_resume_samples": 1,
            "serial_execution": True,
            "test_only_model_plan_override": True,
        }
    ]
    for scenario in load_pipeline_replay_cases():
        base = workspace / scenario.name
        owner_id = f"synthetic-owner-{revision}"
        owner = base / "synthetic-output/runs" / owner_id
        state = {"artifact_sha256": "a" * 64, "journal_evidence": {"evidence_sha256": "b" * 64}}
        for run_id in (owner_id, *(f"synthetic-resume-{i}-{revision}" for i in range(4))):
            run = owner.parent / run_id
            _write(run / "scheduler-state.json", state)
            _write(run / "candidate-findings.json", {"synthetic": True, "findings": []})
            _write(run / "specialist-execution.json", {"synthetic": True, "roles": []})
            _write(run / "private/model-review-artifacts.json", {"context_authorities": []})
            if run_id != owner_id:
                _write(
                    run / "private/scheduler-journal-reference.json",
                    {
                        "owner_run_id": owner_id,
                        "consumer_run_id": run_id,
                        "relative_journal_path": owner_id + "/private/scheduler-journal",
                        "scheduler_artifact_sha256": "a" * 64,
                        "scheduler_journal_evidence_sha256": "b" * 64,
                    },
                )
        guards, file_count, logs = subject.EXPECTED[scenario.name]
        journal_rows = []
        byte_count = 0
        for index in range(file_count):
            value = {"synthetic": True, "record": index, "observed_latency_ms": 99 + revision}
            byte_count += len(
                _write(
                    owner / f"private/scheduler-journal/truncation-recovery/{index:04}.json", value
                )
            )
            journal_rows.append(value)
        ledger = _write(base / "synthetic-ledger.json", {"synthetic": True, "cost": "0.01"})
        selected = [
            {
                "file": "src/mmaudit/models/truncation.py",
                "line": line,
                "function": function,
                "primitive_calls": guards,
                "total_calls": guards,
                "self_ns": 10,
                "cumulative_ns": 100,
                "direct_callers": [
                    {
                        "file": "src/mmaudit/models/truncation.py",
                        "line": 1,
                        "function": "synthetic_caller",
                        "primitive_calls": guards,
                        "total_calls": guards,
                        "self_ns": 10,
                        "cumulative_ns": 100,
                    }
                ],
            }
            for line, function in enumerate(
                (
                    "implementation_is_pristine",
                    "_candidate_review_schema_inventory_sha256",
                    "_candidate_review_schema_input_guard",
                ),
                1,
            )
        ]
        fresh = duration_summary([{"wall_ns": times["fresh"], "cpu_ns": 0}])
        resumed = duration_summary([{"wall_ns": wall, "cpu_ns": 0} for wall in times["resumes"]])
        resumed["separate_profile"] = {
            "wall_ns": times["profile"],
            "cpu_ns": 0,
            "rows": [{key: value for key, value in selected[0].items() if key != "direct_callers"}],
            "selected_functions": selected,
            "main_thread_only": True,
            "inclusive_times_overlap": True,
            "included_in_unprofiled_samples": False,
        }
        case = {
            "schema_version": "1.0",
            "scope": SCOPE,
            "case": scenario.model_dump(mode="json"),
            "fresh_pipeline": fresh,
            "full_original_resume": resumed,
            "original_file_count": file_count,
            "original_file_bytes": byte_count,
            "original_entry_values_sha256": hashlib.sha256(
                subject.canonical(journal_rows)
            ).hexdigest(),
            "synthetic_ledger_sha256": hashlib.sha256(ledger).hexdigest(),
            "original_regression_assertions_passed": True,
            "verification_outside_timing": True,
            "original_files_costs_findings_roles_unchanged": True,
            "new_resume_dispatches": 0,
            "real_provider_calls": 0,
            "promotion_or_completion_credit": False,
            "runtime_optimization_applied": False,
            "throughput_claim": False,
            **identity,
        }
        case["original_evidence"] = subject.snapshot_replay_evidence(
            workspace, scenario.name, case
        ).model_dump(mode="json")
        for index, phase in enumerate(subject.PHASES):
            events.append({"case": scenario.name, "phase_started": phase})
            if index == 0:
                events.extend(["Structured model request failed"] * logs)
        events.append({"completed_case": case})
    events.append(
        {
            "experiment_complete": True,
            "real_provider_calls": 0,
            "optimization_applied": False,
            **identity,
        }
    )
    output = "".join(
        (event if isinstance(event, str) else subject.canonical(event).decode()) + "\n"
        for event in events
    )
    session = 100 + revision
    capture = subject.ReplayCapture(
        schema_version="2.0",
        capture_kind="NATIVE_EXEC_COMMAND_WRITE_STDIN_RESULTS_NOT_EXECUTION_ATTESTATION",
        native_session_id=session,
        results=(
            subject.NativeReplayResult(
                chunk_id=f"{session:06x}",
                wall_time_seconds=1.0,
                output=output[:101],
                session_id=session,
            ),
            subject.NativeReplayResult(
                chunk_id=f"{session + 1000:06x}",
                wall_time_seconds=1.0,
                output=output[101:],
                exit_code=0,
            ),
        ),
    )
    path = root / "capture.json"
    return {
        "capture": path,
        "capture_sha256": subject.write_replay_capture(path, capture),
        "declaration": declaration_path,
        "declaration_sha256": declaration_sha256,
        "workspace": workspace,
        "session": session,
    }


@pytest.fixture
def pair(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return synthetic_side(tmp_path / "before", 0), synthetic_side(tmp_path / "after", 1)


def _change_capture(selected: dict[str, Any], change: Any) -> None:
    value = json.loads(selected["capture"].read_bytes())
    change(value)
    raw = _write(selected["capture"], value)
    selected["capture_sha256"] = hashlib.sha256(raw).hexdigest()


def _change_records(selected: dict[str, Any], change: Any) -> None:
    def transform(value: dict[str, Any]) -> None:
        lines = "".join(item["output"] for item in value["results"]).splitlines()
        events = [json.loads(line) if line.startswith("{") else line for line in lines]
        change(events)
        output = "".join(
            (event if isinstance(event, str) else subject.canonical(event).decode()) + "\n"
            for event in events
        )
        value["results"][0]["output"] = output[:101]
        value["results"][1]["output"] = output[101:]

    _change_capture(selected, transform)


def _cases(events: list[Any]) -> list[dict[str, Any]]:
    return [
        event["completed_case"]
        for event in events
        if isinstance(event, dict) and "completed_case" in event
    ]


def test_complete_synthetic_pair_retains_all_samples_regressions_and_no_authority(
    pair: Any,
) -> None:
    before, after = pair
    report = subject.verify_replay_pair(before, after)
    assert report["accepted"] and report["changed_implementation_paths"] == ["src/synthetic.py"]
    assert report["execution_attested"] is report["qualification_or_release_authority"] is False
    assert report["new_workloads_executed"] == report["real_provider_calls"] == 0
    for case in report["cases"]:
        assert len(case["before"]["full_original_resume"]["samples"]) == 3
        assert case["before"]["original_file_bytes"] != case["after"]["original_file_bytes"]
        assert case["ratios"]["fresh_pipeline:wall_ns"]["regressed"] is False
        assert case["ratios"]["full_original_resume:wall_ns"]["regressed"] is True
        assert case["ratios"]["separate_profile:wall_ns"]["regressed"] is True
        assert case["ratios"]["full_original_resume:cpu_ns"]["after_over_before"] is None


@pytest.mark.parametrize(
    "change",
    (
        "missing_terminal",
        "failed",
        "wrong_session",
        "mixed_session",
        "duplicate",
        "early_terminal",
        "missing_handle",
        "legacy",
        "unknown",
        "bool_exit",
    ),
)
def test_native_receipts_must_be_one_whole_terminal_zero_process(pair: Any, change: str) -> None:
    before, after = pair

    def mutate(value: dict[str, Any]) -> None:
        first, last = value["results"]
        if change == "missing_terminal":
            last["exit_code"] = None
        elif change == "failed":
            last["exit_code"] = 1
        elif change == "wrong_session":
            value["native_session_id"] += 1
        elif change == "mixed_session":
            last["session_id"] = 9999
        elif change == "duplicate":
            last["chunk_id"] = first["chunk_id"]
        elif change == "early_terminal":
            first["exit_code"] = 0
        elif change == "missing_handle":
            first["session_id"] = None
        elif change == "legacy":
            value["schema_version"] = "1.0"
        elif change == "unknown":
            value["accept_partial"] = True
        else:
            last["exit_code"] = False

    _change_capture(after, mutate)
    with pytest.raises(ValueError):
        subject.verify_replay_pair(before, after)


@pytest.mark.parametrize(
    "change",
    (
        "phase",
        "case",
        "log_missing",
        "log_extra",
        "log_order",
        "header_pin",
        "header_python",
        "header_bool",
        "terminal",
        "completion_pin",
        "case_scope",
        "sample",
        "summary",
        "profile_blended",
        "profile_absent",
        "profile_row",
        "profile_caller",
        "guard",
        "guard_missing",
        "profile_duplicate",
        "credit",
        "assertion",
        "dispatch",
        "file_count",
        "evidence_missing",
        "unknown",
        "bool_sample",
        "float_sample",
        "negative_sample",
        "mixed_case",
    ),
)
def test_partial_or_reordered_results_never_become_complete_comparisons(
    pair: Any, change: str
) -> None:
    before, after = pair

    def mutate(events: list[Any]) -> None:
        case = _cases(events)[0]
        resume = case["full_original_resume"]
        profile = resume["separate_profile"]
        if change == "phase":
            events[1], events[9] = events[9], events[1]
        elif change == "case":
            events.pop(-2)
        elif change == "log_missing":
            events.remove("Structured model request failed")
        elif change == "log_extra":
            events.insert(2, "synthetic unexpected diagnostic")
        elif change == "log_order":
            events.insert(-1, events.pop(2))
        elif change == "header_pin":
            events[0]["declaration_sha256"] = "f" * 64
        elif change == "header_python":
            events[0]["python"] = "0.0"
        elif change == "header_bool":
            events[0]["fresh_pipeline_samples"] = True
        elif change == "terminal":
            events[-1]["experiment_complete"] = False
        elif change == "completion_pin":
            case["workload_sha256"] = "f" * 64
        elif change == "case_scope":
            case["case"]["sources"] -= 1
        elif change == "sample":
            resume["samples"].pop()
        elif change == "summary":
            resume["wall_ns"]["median"] += 1
        elif change == "profile_blended":
            profile["included_in_unprofiled_samples"] = True
        elif change == "profile_absent":
            del resume["separate_profile"]
        elif change == "profile_row":
            profile["rows"][0]["file"] = "/outside.py"
        elif change == "profile_caller":
            profile["selected_functions"][0]["direct_callers"][0]["file"] = "../outside.py"
        elif change == "guard":
            profile["selected_functions"][0]["total_calls"] -= 1
        elif change == "guard_missing":
            profile["selected_functions"].pop()
        elif change == "profile_duplicate":
            profile["selected_functions"].append(profile["selected_functions"][0])
        elif change == "credit":
            case["promotion_or_completion_credit"] = True
        elif change == "assertion":
            case["original_regression_assertions_passed"] = False
        elif change == "dispatch":
            case["new_resume_dispatches"] = 1
        elif change == "file_count":
            case["original_file_count"] -= 1
        elif change == "evidence_missing":
            del case["original_evidence"]
        elif change == "unknown":
            case["skip_original_files"] = True
        elif change == "bool_sample":
            resume["samples"][0]["cpu_ns"] = False
        elif change == "float_sample":
            resume["samples"][0]["wall_ns"] = 150.0
        elif change == "negative_sample":
            resume["samples"][0]["cpu_ns"] = -1
        else:
            _cases(events)[1]["case"] = case["case"]

    _change_records(after, mutate)
    with pytest.raises(ValueError):
        subject.verify_replay_pair(before, after)


@pytest.mark.parametrize("change", ("duplicate", "nonfinite", "overflow", "truncated", "wrong_pin"))
def test_raw_ambiguous_or_unpinned_capture_refuses(pair: Any, change: str) -> None:
    before, after = pair
    raw = after["capture"].read_bytes()
    if change == "duplicate":
        raw = raw.replace(
            b'"schema_version":"2.0"', b'"schema_version":"2.0","schema_version":"2.0"', 1
        )
    elif change == "nonfinite":
        raw = raw.replace(b'"wall_time_seconds":1.0', b'"wall_time_seconds":NaN', 1)
    elif change == "overflow":
        raw = raw.replace(b'"wall_time_seconds":1.0', b'"wall_time_seconds":1e999', 1)
    elif change == "truncated":
        raw = raw[:-1]
    after["capture"].write_bytes(raw)
    after["capture_sha256"] = "f" * 64 if change == "wrong_pin" else hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        subject.verify_replay_pair(before, after)


@pytest.mark.parametrize(
    "change",
    (
        "bytes",
        "identity",
        "permission",
        "extra_file",
        "removed_file",
        "link",
        "fifo",
        "secret",
        "missing_resume",
        "reference",
        "roles",
        "coverage",
        "findings",
        "ledger",
    ),
)
def test_complete_output_requires_original_unchanged_files_and_all_four_resumes(
    pair: Any, change: str
) -> None:
    before, after = pair
    base = after["workspace"] / "generic-open"
    runs = base / "synthetic-output/runs"
    owner = runs / "synthetic-owner-1"
    consumer = runs / "synthetic-resume-0-1"
    target = owner / "scheduler-state.json"
    if change == "bytes":
        target.write_bytes(target.read_bytes().replace(b"aaaa", b"bbbb", 1))
    elif change == "identity":
        replacement = target.with_suffix(".new")
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(target)
    elif change == "permission":
        target.chmod(0o644)
    elif change == "extra_file":
        _write(owner / "extra.json", {"synthetic": True})
    elif change == "removed_file":
        target.unlink()
    elif change == "link":
        (owner / "link.json").symlink_to(target)
    elif change == "fifo":
        os.mkfifo(owner / "synthetic-pipe")
    elif change == "secret":
        (owner / ".env.synthetic").write_text("SYNTHETIC_NOT_A_SECRET=1\n")
    elif change == "missing_resume":
        consumer.rename(base / "removed-synthetic-resume")
    elif change == "reference":
        _write(consumer / "private/scheduler-journal-reference.json", {})
    elif change == "roles":
        _write(consumer / "specialist-execution.json", {"synthetic": "changed"})
    elif change == "coverage":
        _write(
            consumer / "private/model-review-artifacts.json",
            {"context_authorities": [], "changed": True},
        )
    elif change == "findings":
        _write(consumer / "candidate-findings.json", {"synthetic": "changed"})
    else:
        _write(base / "synthetic-ledger.json", {"synthetic": True, "cost": "0.02"})
    with pytest.raises((ValueError, KeyError, OSError)):
        subject.verify_replay_pair(before, after)


@pytest.mark.parametrize(
    "bound",
    (
        "MAX_CAPTURE_BYTES",
        "MAX_OUTPUT_BYTES",
        "MAX_FILE_BYTES",
        "MAX_TOTAL_BYTES",
        "MAX_FILES",
        "MAX_ENTRIES",
    ),
)
def test_capture_and_workspace_bounds_refuse_without_partial_acceptance(
    pair: Any, monkeypatch: pytest.MonkeyPatch, bound: str
) -> None:
    monkeypatch.setattr(subject, bound, 1)
    with pytest.raises(ValueError):
        subject.verify_replay_pair(*pair)


def test_failed_capture_can_be_retained_privately_without_granting_acceptance(
    pair: Any, tmp_path: Path
) -> None:
    before, after = pair
    _change_capture(after, lambda value: value["results"][-1].update(exit_code=1))
    capture = subject.load_replay_capture(after["capture"], after["capture_sha256"])
    path = tmp_path / "retained-failed-capture.json"
    sha256 = subject.write_replay_capture(path, capture)
    assert subject.load_replay_capture(path, sha256) == capture
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        subject.write_replay_capture(path, capture)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == sha256
    with pytest.raises(ValueError):
        subject.verify_replay_pair(before, after)


def test_rechunking_preserves_the_complete_original_native_output(pair: Any) -> None:
    before, after = pair
    original = subject.verify_replay_pair(before, after)["cases"]

    def rechunk(value: dict[str, Any]) -> None:
        output = "".join(item["output"] for item in value["results"]).replace("\n", "\r\n")
        value["results"][0]["output"] = output[:333]
        value["results"][1]["output"] = output[333:]

    _change_capture(after, rechunk)
    assert subject.verify_replay_pair(before, after)["cases"] == original


@pytest.mark.parametrize("reuse", ("session", "capture_sha256", "workspace"))
def test_one_execution_cannot_supply_both_comparison_sides(pair: Any, reuse: str) -> None:
    before, after = pair
    after[reuse] = before[reuse]
    with pytest.raises(ValueError):
        subject.verify_replay_pair(before, after)


@pytest.mark.asyncio
async def test_output_snapshot_failure_prevents_case_completion_and_terminal_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    project = synthetic_replay_project(tmp_path / "project")
    declaration = build_replay_declaration(project)
    monkeypatch.setattr(runner, "require_current_replay_inputs", lambda _value: None)

    async def measured(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"synthetic_callsite_not_pipeline_evidence": True}

    def refuse(*_args: Any) -> Any:
        raise ValueError("synthetic snapshot failure")

    monkeypatch.setattr(runner, "measure_original_pipeline_replay", measured)
    monkeypatch.setattr(runner, "snapshot_replay_evidence", refuse)
    with pytest.raises(ValueError, match="snapshot failure"):
        await runner._main(tmp_path, None, declaration)
    output = capsys.readouterr().out
    assert "completed_case" not in output and "experiment_complete" not in output


def test_complete_individual_captures_still_refuse_a_different_declared_workload(pair: Any) -> None:
    before, after = pair
    value = json.loads(after["declaration"].read_bytes())
    value["workload"]["environment"]["machine"] = "different-synthetic-machine"
    raw = _write(after["declaration"], value)
    after["declaration_sha256"] = hashlib.sha256(raw).hexdigest()
    declaration = load_replay_declaration(after["declaration"], after["declaration_sha256"])

    def rebind(events: list[Any]) -> None:
        for item in (events[0], *_cases(events), events[-1]):
            item["declaration_sha256"] = declaration.sha256
            item["workload_sha256"] = declaration.workload_sha256

    _change_records(after, rebind)
    with pytest.raises(ValueError, match="same workload"):
        subject.verify_replay_pair(before, after)


def test_an_extra_empty_run_directory_is_not_an_original_five_run_graph(pair: Any) -> None:
    before, after = pair
    (after["workspace"] / "generic-open/synthetic-output/runs/extra-empty-run").mkdir()
    with pytest.raises(ValueError, match="four complete original resumes"):
        subject.verify_replay_pair(before, after)


@pytest.mark.parametrize(
    "change", ("hardlink", "parent_link", "inner_duplicate", "inner_nonfinite")
)
def test_file_aliases_and_ambiguous_inner_records_refuse(pair: Any, change: str) -> None:
    before, after = pair
    if change == "hardlink":
        owner = after["workspace"] / "generic-open/synthetic-output/runs/synthetic-owner-1"
        os.link(owner / "scheduler-state.json", owner / "hardlink.json")
    elif change == "parent_link":
        actual = after["workspace"].with_name("actual-synthetic-workspace")
        after["workspace"].rename(actual)
        after["workspace"].symlink_to(actual, target_is_directory=True)
    else:

        def corrupt(value: dict[str, Any]) -> None:
            raw = "".join(item["output"] for item in value["results"])
            if change == "inner_duplicate":
                raw = raw.replace(
                    '"experiment_complete":true',
                    '"experiment_complete":true,"experiment_complete":true',
                )
            else:
                raw = raw.replace('"real_provider_calls":0', '"real_provider_calls":NaN', 1)
            value["results"][0]["output"], value["results"][1]["output"] = raw[:101], raw[101:]

        _change_capture(after, corrupt)
    with pytest.raises((ValueError, OSError)):
        subject.verify_replay_pair(before, after)


@pytest.mark.asyncio
async def test_actual_v2_producer_and_consumer_join_synthetic_files_without_a_pipeline_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    selected = synthetic_side(tmp_path / "synthetic", 0)
    declaration = load_replay_declaration(selected["declaration"], selected["declaration_sha256"])
    capture = subject.load_replay_capture(selected["capture"], selected["capture_sha256"])
    original_cases = [
        json.loads(line)["completed_case"]
        for line in "".join(item.output for item in capture.results).splitlines()
        if line.startswith('{"completed_case"')
    ]
    monkeypatch.setattr(
        runner,
        "require_current_replay_inputs",
        lambda value: require_current_replay_inputs(
            value, selected["declaration"].parent / "project"
        ),
    )

    async def synthetic_measure(case: Any, _workspace: Path, *, progress: Any) -> dict[str, Any]:
        for index, phase in enumerate(subject.PHASES):
            progress(phase)
            if index == 0:
                for _ in range(subject.EXPECTED[case.name][2]):
                    print("Structured model request failed")
        observed = next(row for row in original_cases if row["case"]["name"] == case.name)
        return {
            key: value
            for key, value in observed.items()
            if key
            not in {
                "original_evidence",
                "declaration_sha256",
                "workload_sha256",
                "implementation_sha256",
                "declaration_is_execution_or_qualification_evidence",
            }
        }

    monkeypatch.setattr(runner, "measure_original_pipeline_replay", synthetic_measure)
    await runner._main(selected["workspace"], None, declaration)
    output = capsys.readouterr().out
    emitted = capture.model_copy(
        update={
            "results": (
                subject.NativeReplayResult(
                    chunk_id="abcdef", wall_time_seconds=1.0, output=output, exit_code=0
                ),
            )
        }
    )
    verified = subject.validate_replay_capture(
        emitted, declaration, selected["workspace"], selected["session"]
    )
    assert [row.model_dump(mode="json") for row in verified] == original_cases
    assert all(not row.declaration_is_execution_or_qualification_evidence for row in verified)
