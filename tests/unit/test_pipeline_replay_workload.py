"""Workload identity must distinguish fixed inputs from variable measurement observations."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any

import pytest

from scripts import measure_pipeline_replay_scaling as runner
from tests import pipeline_replay_workload as subject
from tests.pipeline_replay_capture import ReplayFileEvidence
from tests.pipeline_replay_scaling_support import load_pipeline_replay_cases
from tests.scheduler_scaling_support import ROOT


def synthetic_replay_project(path: Path) -> Path:
    """Minimal local source tree for declaration tests, not a measured audit target."""

    for name in ("src", "scripts", "config", "tests/fixtures"):
        (path / name).mkdir(parents=True, exist_ok=True)
    for name in ("src/synthetic.py", "scripts/synthetic.py", "tests/synthetic.py"):
        (path / name).write_text("# Synthetic declaration input; never executed.\n")
    (path / "pyproject.toml").write_text('[project]\nname = "synthetic-workload"\n')
    (path / "config/models.selection-plan.json").write_text('{"synthetic":true}\n')
    for directory in ("vulnerable_app", "pipeline_replay_scaling", "unresolved_recovery_tree"):
        shutil.copytree(ROOT / "tests/fixtures" / directory, path / "tests/fixtures" / directory)
    return path


@pytest.fixture
def source_root(tmp_path: Path) -> Path:
    return synthetic_replay_project(tmp_path)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _load_raw(path: Path, raw: bytes) -> subject.ReplayDeclaration:
    path.write_bytes(raw)
    return subject.load_replay_declaration(path, hashlib.sha256(raw).hexdigest())


def test_declaration_retains_exact_schedule_cases_and_separate_implementation(
    source_root: Path,
) -> None:
    declaration = subject.build_replay_declaration(source_root)
    assert declaration == subject.build_replay_declaration(source_root)
    assert declaration.workload.cases == load_pipeline_replay_cases()
    schedule = declaration.workload.schedule
    assert (schedule.fresh_pipeline_samples, schedule.unprofiled_resume_samples) == (1, 3)
    assert schedule.separate_profile_samples == 1
    assert schedule.serial_execution and schedule.verification_outside_timing
    assert all(item.path.startswith("src/") for item in declaration.implementation_inputs)
    assert not any(item.path.startswith("src/") for item in declaration.workload.inputs)
    assert {"pyproject.toml", "config/models.selection-plan.json"} <= {
        item.path for item in declaration.workload.inputs
    }
    subject.require_current_replay_inputs(declaration, source_root)


def test_latency_widths_owner_ids_and_output_sizes_do_not_replace_workload_identity(
    source_root: Path,
) -> None:
    fixture = json.loads(
        (ROOT / "tests/fixtures/pipeline_replay_scaling/workload_observations.json").read_bytes()
    )
    assert fixture["scope"] == "SYNTHETIC_OBSERVATIONS_NOT_EXECUTED_PIPELINE_RESULTS"
    before = subject.build_replay_declaration(source_root)
    outputs = source_root / "synthetic-results"
    outputs.mkdir()
    raw_observations = [_canonical(value) for value in fixture["observations"]]
    assert len(raw_observations[0]) != len(raw_observations[1])
    for index, raw in enumerate(raw_observations):
        (outputs / f"observation-{index}.json").write_bytes(raw)
        after = subject.build_replay_declaration(source_root)
        assert after == before and after.workload_sha256 == before.workload_sha256
        assert subject.require_same_replay_workload(before, after) == ()
    assert not any("synthetic-results" in item.path for item in before.workload.inputs)


def test_implementation_revision_is_reported_not_hidden_in_workload_identity(
    source_root: Path,
) -> None:
    before = subject.build_replay_declaration(source_root)
    (source_root / "src/synthetic.py").write_text("# Different synthetic implementation.\n")
    after = subject.build_replay_declaration(source_root)
    assert before.sha256 != after.sha256
    assert before.implementation_sha256 != after.implementation_sha256
    assert before.workload_sha256 == after.workload_sha256
    assert subject.require_same_replay_workload(before, after) == ("src/synthetic.py",)
    with pytest.raises(ValueError, match="changed after declaration"):
        subject.require_current_replay_inputs(before, source_root)
    subject.require_current_replay_inputs(after, source_root)


@pytest.mark.parametrize(
    "name",
    (
        "tests/synthetic.py",
        "scripts/synthetic.py",
        "tests/fixtures/vulnerable_app/app.py",
        "tests/fixtures/vulnerable_app/README.md",
        "tests/fixtures/pipeline_replay_scaling/cases.json",
        "tests/fixtures/unresolved_recovery_tree/cases.json",
        "config/models.selection-plan.json",
        "pyproject.toml",
    ),
)
def test_workload_byte_change_refuses_even_when_its_length_is_unchanged(
    source_root: Path, name: str
) -> None:
    before = subject.build_replay_declaration(source_root)
    path = source_root / name
    raw = path.read_bytes()
    path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    after = subject.build_replay_declaration(source_root)
    assert before.workload_sha256 != after.workload_sha256
    with pytest.raises(ValueError, match="same workload"):
        subject.require_same_replay_workload(before, after)
    with pytest.raises(ValueError, match="changed after declaration"):
        subject.require_current_replay_inputs(before, source_root)


@pytest.mark.parametrize("change", ("add_test", "remove_test", "add_source", "remove_source"))
def test_input_inventory_additions_and_removals_refuse_current_declaration(
    source_root: Path, change: str
) -> None:
    before = subject.build_replay_declaration(source_root)
    directory = "tests" if change.endswith("test") else "src"
    if change.startswith("add"):
        (source_root / directory / "added.py").write_text("# Synthetic addition.\n")
    else:
        (source_root / directory / "synthetic.py").unlink()
    with pytest.raises(ValueError):
        subject.require_current_replay_inputs(before, source_root)


@pytest.mark.parametrize("change", ("python", "package"))
def test_environment_change_is_not_the_same_comparison_workload(
    source_root: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    before = subject.build_replay_declaration(source_root)
    if change == "python":
        monkeypatch.setattr(
            "tests.pipeline_replay_workload.platform.python_version", lambda: "0.0.synthetic"
        )
    else:
        monkeypatch.setattr(subject, "_package_versions", lambda: (("synthetic-package", "0.0"),))
    after = subject.build_replay_declaration(source_root)
    with pytest.raises(ValueError, match="same workload"):
        subject.require_same_replay_workload(before, after)
    with pytest.raises(ValueError, match="changed after declaration"):
        subject.require_current_replay_inputs(before, source_root)


@pytest.mark.parametrize(
    "change",
    (
        "version",
        "extra",
        "missing",
        "duplicate_input",
        "reversed_inputs",
        "absolute",
        "parent",
        "secret",
        "empty_path",
        "control_path",
        "hash",
        "negative_size",
        "cases",
        "fresh_bool",
        "fresh_float",
        "resume_count",
        "profile_count",
        "parallel",
        "timed_verification",
        "latency",
        "overlapping_inputs",
        "packages",
    ),
)
def test_incomplete_ambiguous_or_changed_contract_is_not_a_declaration(
    source_root: Path, change: str
) -> None:
    value = subject.build_replay_declaration(source_root).model_dump(mode="json")
    workload = value["workload"]
    if change == "version":
        value["schema_version"] = "1.0"
    elif change == "extra":
        value["accept_old_comparison"] = True
    elif change == "missing":
        del value["implementation_inputs"]
    elif change == "duplicate_input":
        workload["inputs"].append(workload["inputs"][0])
    elif change == "reversed_inputs":
        workload["inputs"].reverse()
    elif change in {"absolute", "parent", "secret", "empty_path", "control_path"}:
        workload["inputs"][0]["path"] = {
            "absolute": "/outside.json",
            "parent": "../outside.json",
            "secret": ".env",
            "empty_path": ".",
            "control_path": "tests/invalid\x00.py",
        }[change]
    elif change == "hash":
        workload["inputs"][0]["sha256"] = "g" * 64
    elif change == "negative_size":
        workload["inputs"][0]["byte_count"] = -1
    elif change == "cases":
        workload["cases"].reverse()
    elif change == "fresh_bool":
        workload["schedule"]["fresh_pipeline_samples"] = True
    elif change == "fresh_float":
        workload["schedule"]["fresh_pipeline_samples"] = 1.0
    elif change == "resume_count":
        workload["schedule"]["unprofiled_resume_samples"] = 1
    elif change == "profile_count":
        workload["schedule"]["separate_profile_samples"] = 0
    elif change == "parallel":
        workload["schedule"]["serial_execution"] = False
    elif change == "timed_verification":
        workload["schedule"]["verification_outside_timing"] = False
    elif change == "latency":
        workload["latency_ms"] = 99
    elif change == "overlapping_inputs":
        value["implementation_inputs"] = workload["inputs"]
    elif change == "packages":
        workload["environment"]["package_versions"].reverse()
    with pytest.raises(ValueError):
        _load_raw(source_root / "invalid-declaration.json", _canonical(value))


@pytest.mark.parametrize("change", ("duplicate", "nonfinite", "whitespace", "truncated"))
def test_noncanonical_or_ambiguous_json_refuses_even_with_its_own_hash(
    source_root: Path, change: str
) -> None:
    raw = _canonical(subject.build_replay_declaration(source_root).model_dump(mode="json"))
    if change == "duplicate":
        raw = raw.replace(
            b'"schema_version":"2.0"', b'"schema_version":"2.0","schema_version":"2.0"', 1
        )
    elif change == "nonfinite":
        raw = raw.replace(b'"fresh_pipeline_samples":1', b'"fresh_pipeline_samples":NaN')
    elif change == "whitespace":
        raw += b"\n"
    else:
        raw = raw[:-1]
    with pytest.raises(ValueError):
        _load_raw(source_root / "invalid-declaration.json", raw)


def test_declaration_roundtrip_is_exact_private_and_never_overwritten(source_root: Path) -> None:
    declaration = subject.build_replay_declaration(source_root)
    path = source_root / "declaration.json"
    sha256 = subject.write_replay_declaration(path, declaration)
    raw = path.read_bytes()
    assert sha256 == declaration.sha256 == hashlib.sha256(raw).hexdigest()
    assert subject.load_replay_declaration(path, sha256) == declaration
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        subject.write_replay_declaration(path, declaration)
    assert path.read_bytes() == raw
    with pytest.raises(ValueError, match="caller pin"):
        subject.load_replay_declaration(path, "f" * 64)
    for invalid in ("", "F" * 64, "a" * 63, "a" * 64 + "\n"):
        with pytest.raises(ValueError, match="exact SHA256"):
            subject.load_replay_declaration(path, invalid)


def test_declaration_byte_bound_applies_to_both_read_and_write(
    source_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = subject.build_replay_declaration(source_root)
    path = source_root / "bounded-declaration.json"
    raw = _canonical(declaration.model_dump(mode="json"))
    monkeypatch.setattr(subject, "MAX_DECLARATION_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="byte bound"):
        subject.write_replay_declaration(path, declaration)
    assert not path.exists()
    with pytest.raises(ValueError, match="bounded regular file"):
        _load_raw(path, raw)


def test_declaration_link_is_neither_read_nor_overwritten(source_root: Path) -> None:
    declaration = subject.build_replay_declaration(source_root)
    target = source_root / "original-declaration.json"
    sha256 = subject.write_replay_declaration(target, declaration)
    raw = target.read_bytes()
    link = source_root / "linked-declaration.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        subject.load_replay_declaration(link, sha256)
    with pytest.raises(FileExistsError):
        subject.write_replay_declaration(link, declaration)
    assert target.read_bytes() == raw


def test_dependency_inventory_is_complete_bounded_and_rejects_duplicate_names(
    source_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = subject.build_replay_declaration(source_root)
    packages = declaration.workload.environment.package_versions
    assert len(packages) > 7 and len({name for name, _ in packages}) == len(packages)
    payload = declaration.model_dump(mode="json")
    payload["workload"]["environment"]["package_versions"].append(list(packages[-1]))
    with pytest.raises(ValueError, match="duplicated"):
        _load_raw(source_root / "duplicate-packages.json", _canonical(payload))
    monkeypatch.setattr(subject, "MAX_PACKAGES", 1)
    with pytest.raises(ValueError, match="dependency inventory exceeds"):
        subject.build_replay_declaration(source_root)


def test_fixed_input_parent_link_is_refused_before_read(source_root: Path) -> None:
    config = source_root / "config"
    moved = source_root / "synthetic-moved-config"
    config.rename(moved)
    config.symlink_to(moved)
    with pytest.raises(ValueError, match="parent must be an original directory"):
        subject.build_replay_declaration(source_root)


@pytest.mark.parametrize("kind", ("file_link", "directory_link", "fifo", "secret"))
def test_special_or_secret_inputs_are_refused_without_following_them(
    source_root: Path, kind: str
) -> None:
    target = source_root / "synthetic-sentinel.txt"
    target.write_text("synthetic sentinel\n")
    if kind == "file_link":
        (source_root / "tests/link.py").symlink_to(target)
    elif kind == "directory_link":
        (source_root / "tests/linked-dir").symlink_to(source_root / "src")
    elif kind == "fifo":
        os.mkfifo(source_root / "tests/nonregular.py")
    else:
        (source_root / "tests/fixtures/vulnerable_app/.env").write_text("SYNTHETIC=NO_SECRET\n")
    with pytest.raises((ValueError, OSError)):
        subject.build_replay_declaration(source_root)
    assert target.read_text() == "synthetic sentinel\n"


@pytest.mark.parametrize("limit", ("MAX_FILE_BYTES", "MAX_TOTAL_BYTES", "MAX_FILES", "MAX_ENTRIES"))
def test_input_bounds_are_checked_without_accepting_a_partial_inventory(
    source_root: Path, monkeypatch: pytest.MonkeyPatch, limit: str
) -> None:
    monkeypatch.setattr(subject, limit, 1)
    with pytest.raises(ValueError):
        subject.build_replay_declaration(source_root)


@pytest.mark.asyncio
async def test_declared_runner_checks_inputs_outside_each_operation_and_emits_v2_identity(
    source_root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    declaration = subject.build_replay_declaration(source_root)
    checks: list[str] = []
    cases: list[str] = []

    def require(value: subject.ReplayDeclaration) -> None:
        subject.require_current_replay_inputs(value, source_root)
        checks.append("checked")

    async def measured(case: Any, _workspace: Path, *, progress: Any) -> dict[str, Any]:
        cases.append(case.name)
        for phase in (
            "fresh_pipeline:unprofiled_1",
            "full_original_resume:unprofiled_1",
            "full_original_resume:unprofiled_2",
            "full_original_resume:unprofiled_3",
            "full_original_resume:separate_profile",
        ):
            before = len(checks)
            progress(phase)
            assert len(checks) == before + 1
        return {"synthetic_call_site_test_not_pipeline_evidence": True}

    monkeypatch.setattr(runner, "require_current_replay_inputs", require)
    monkeypatch.setattr(runner, "measure_original_pipeline_replay", measured)
    synthetic_evidence = ReplayFileEvidence(
        file_count=1,
        total_bytes=1,
        inventory_sha256="a" * 64,
        directory_inventory_sha256="b" * 64,
        owner_run_id="synthetic-owner",
        run_ids=("synthetic-owner", "r1", "r2", "r3", "r4"),
    )
    monkeypatch.setattr(runner, "snapshot_replay_evidence", lambda *_args: synthetic_evidence)
    await runner._main(source_root / "unused-workspace", None, declaration)
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert cases == ["generic-open", "mixed-specialist"] and len(checks) == 13
    assert output[0]["experiment"] == "pipeline-replay-scaling-v2"
    assert all(
        v["completed_case"]["original_evidence"] == synthetic_evidence.model_dump(mode="json")
        for v in output
        if "completed_case" in v
    )
    for value in (
        output[0],
        *(v["completed_case"] for v in output if "completed_case" in v),
        output[-1],
    ):
        assert value["declaration_sha256"] == declaration.sha256
        assert value["workload_sha256"] == declaration.workload_sha256
        assert value["implementation_sha256"] == declaration.implementation_sha256
        assert value["declaration_is_execution_or_qualification_evidence"] is False


@pytest.mark.parametrize("when", ("before", "phase", "after"))
@pytest.mark.asyncio
async def test_input_drift_cannot_emit_a_completed_case_or_terminal_success(
    source_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    when: str,
) -> None:
    declaration = subject.build_replay_declaration(source_root)
    calls = []

    def change() -> None:
        (source_root / "tests/synthetic.py").write_text("# Synthetic changed harness.\n")

    async def measured(case: Any, _workspace: Path, *, progress: Any) -> dict[str, Any]:
        calls.append(case.name)
        change()
        if when == "phase":
            progress("fresh_pipeline:unprofiled_1")
            pytest.fail("changed input must refuse before the measured operation")
        return {"synthetic_call_site_test_not_pipeline_evidence": True}

    monkeypatch.setattr(
        runner,
        "require_current_replay_inputs",
        lambda value: subject.require_current_replay_inputs(value, source_root),
    )
    monkeypatch.setattr(runner, "measure_original_pipeline_replay", measured)
    if when == "before":
        change()
    with pytest.raises(ValueError, match="changed after declaration"):
        await runner._main(source_root / "unused-workspace", None, declaration)
    output = capsys.readouterr().out
    assert "completed_case" not in output and "experiment_complete" not in output
    assert len(calls) == int(when != "before")


@pytest.mark.asyncio
async def test_declared_runner_refuses_a_selected_smaller_case_before_input_checks(
    source_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = subject.build_replay_declaration(source_root)
    monkeypatch.setattr(
        runner,
        "require_current_replay_inputs",
        lambda _value: pytest.fail("no input check or measured work permitted"),
    )
    with pytest.raises(ValueError, match="both original cases"):
        await runner._main(source_root / "unused-workspace", "generic-open", declaration)


@pytest.mark.asyncio
async def test_legacy_runner_output_is_not_relabelled_as_declared_v2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def measured(_case: Any, _workspace: Path, *, progress: Any) -> dict[str, Any]:
        return {"synthetic_call_site_test_not_pipeline_evidence": True}

    monkeypatch.setattr(runner, "measure_original_pipeline_replay", measured)
    await runner._main(tmp_path, "generic-open")
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert output[0]["experiment"] == "pipeline-replay-scaling-v1"
    assert all("declaration_sha256" not in value for value in output)
    with pytest.raises(ValueError):
        _load_raw(tmp_path / "legacy.json", _canonical(output[0]))
