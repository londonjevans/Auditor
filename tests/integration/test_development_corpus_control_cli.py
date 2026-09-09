"""Provider-free original/cumulative score measurement with exact input/output custody."""

from __future__ import annotations

import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as cli
import mmaudit.orchestration.development_corpus_control_measurement as orchestration
from mmaudit.benchmark.development_corpus_control_measurement import (
    read_development_corpus_control_measurement,
)
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from tests.development_corpus_control_measurement_support import retained_score

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("offline control measurement touched credentials, network or subprocesses")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)


def case(tmp_path, *, cumulative=False, complete=True):
    score = retained_score(cumulative=cumulative, complete=complete)
    path = tmp_path / "inputs" / "middle" / "inner" / "synthetic-score.json"
    path.parent.mkdir(parents=True)
    path.write_text(score.model_dump_json(indent=2))
    path.chmod(0o600)
    return score, path, tmp_path / "measurement"


def invoke(path, output, *extra):
    return RUNNER.invoke(
        app,
        [
            "development",
            "measure-controls",
            "--score-file",
            str(path),
            "--output-dir",
            str(output),
            *extra,
        ],
    )


@pytest.mark.parametrize("cumulative", [False, True])
@pytest.mark.parametrize("complete", [False, True])
def test_cli_measures_exact_retained_score_privately_without_rebinding_or_provider(
    cumulative, complete, tmp_path
):
    old, path, output = case(tmp_path, cumulative=cumulative, complete=complete)
    raw = path.read_bytes()
    result = invoke(path, output)
    assert result.exit_code == 0, result.output
    assert path.read_bytes() == raw
    assert {p.name for p in output.iterdir()} == {"control-measurement.json"}
    measured = read_development_corpus_control_measurement(
        (output / "control-measurement.json").read_bytes()
    )
    assert measured.source_score == old
    assert measured.summary.unique_root_location_coverage.value == (1 if complete else None)
    assert measured.measurement_sha256 in result.stdout and str(path) not in result.stdout
    assert "not validated findings" in result.stdout
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / "control-measurement.json").stat().st_mode) == 0o600
    assert not measured.audit_complete and not measured.qualification_eligible


@pytest.mark.parametrize(
    "kind",
    [
        "history",
        "hash",
        "duplicate",
        "nonfinite",
        "utf8",
        "malformed",
        "symlink",
        "hardlink",
        "relative",
        "overlap",
        "existing_output",
        "linked_ancestor",
    ],
)
def test_bad_unbound_linked_or_overlapping_inputs_refuse_without_a_derived_output(tmp_path, kind):
    old, path, output = case(tmp_path, cumulative=True)
    if kind == "history":
        path.write_text(old.history.model_dump_json())
    elif kind == "hash":
        path.write_text(old.model_copy(update={"score_sha256": "0" * 64}).model_dump_json())
    elif kind in {"duplicate", "nonfinite", "utf8", "malformed"}:
        path.write_bytes(
            {
                "duplicate": b'{"x":1,"x":1}',
                "nonfinite": b'{"x":Infinity}',
                "utf8": b"\xff",
                "malformed": b"{",
            }[kind]
        )
    elif kind in {"symlink", "hardlink"}:
        retained = path.with_suffix(".retained")
        path.rename(retained)
        path.symlink_to(retained) if kind == "symlink" else os.link(retained, path)
    elif kind == "linked_ancestor":
        parent = path.parent
        target = parent.with_name("retained-inner")
        parent.rename(target)
        parent.symlink_to(target, target_is_directory=True)
    elif kind == "relative":
        path = Path("synthetic-relative-score.json")
    elif kind == "overlap":
        output = path.parent
    else:
        output.mkdir(mode=0o700)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert "No provider call was selected" in result.output and str(path) not in result.output
    assert not (output / "control-measurement.json").exists()
    if kind not in {"overlap", "existing_output"}:
        assert not output.exists()


@pytest.mark.parametrize("when", ["after_compute", "inside_writer", "after_writer"])
@pytest.mark.parametrize("kind", ["bytes", "file_replace", "ancestor_replace"])
def test_input_bytes_and_all_ancestor_objects_remain_bound_through_finalization(
    tmp_path, monkeypatch, when, kind
):
    _, path, output = case(tmp_path, cumulative=True)
    raw = path.read_bytes()
    compute = orchestration.measure_development_corpus_controls
    writer = orchestration.write_development_corpus_control_measurement

    def mutate():
        if kind == "ancestor_replace":
            ancestor = path.parent.parent
            ancestor.rename(ancestor.with_name("retained-middle"))
            path.parent.mkdir(parents=True)
            path.write_bytes(raw)
            path.chmod(0o600)
        elif kind == "file_replace":
            path.rename(path.with_suffix(".retained"))
            path.write_bytes(raw)
            path.chmod(0o600)
        else:
            path.write_bytes(raw + b" ")

    def computed(**kwargs):
        result = compute(**kwargs)
        if when == "after_compute":
            mutate()
        return result

    def written(*args, **kwargs):
        if when == "inside_writer":
            mutate()
        result = writer(*args, **kwargs)
        if when == "after_writer":
            mutate()
        return result

    monkeypatch.setattr(orchestration, "measure_development_corpus_controls", computed)
    monkeypatch.setattr(orchestration, "write_development_corpus_control_measurement", written)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert str(path) not in result.output
    if when == "after_compute":
        assert not output.exists()
    elif when == "inside_writer":
        assert not (output / "control-measurement.json").exists()


@pytest.mark.parametrize("kind", ["bytes", "file_replace", "directory_replace", "mode"])
def test_new_output_bytes_inode_directory_and_permissions_are_rechecked(
    tmp_path, monkeypatch, kind
):
    _, path, output = case(tmp_path)
    before = path.read_bytes()
    writer = orchestration.write_development_corpus_control_measurement

    def written(*args, **kwargs):
        result = writer(*args, **kwargs)
        target = output / "control-measurement.json"
        raw = target.read_bytes()
        if kind == "directory_replace":
            output.rename(output.with_name("retained-output"))
            output.mkdir(mode=0o700)
            target.write_bytes(raw)
            target.chmod(0o600)
        elif kind == "file_replace":
            target.rename(target.with_suffix(".retained"))
            target.write_bytes(raw)
            target.chmod(0o600)
        elif kind == "mode":
            target.chmod(0o644)
        else:
            target.write_bytes(raw + b" ")
        return result

    monkeypatch.setattr(orchestration, "write_development_corpus_control_measurement", written)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert str(path) not in result.output and path.read_bytes() == before


def test_replaced_output_parent_is_not_rebased_after_measurement(tmp_path, monkeypatch):
    _, path, _ = case(tmp_path)
    parent = tmp_path / "outputs"
    parent.mkdir()
    output = parent / "measurement"
    compute = orchestration.measure_development_corpus_controls

    def computed(**kwargs):
        result = compute(**kwargs)
        parent.rename(parent.with_name("retained-outputs"))
        parent.mkdir()
        return result

    monkeypatch.setattr(orchestration, "measure_development_corpus_controls", computed)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert not output.exists()


@pytest.mark.parametrize(
    "option",
    [
        "--truth-file",
        "--truth-manifest",
        "--cost-ledger",
        "--secrets-env-file",
        "--provider-endpoint",
        "--category-policy",
        "--kind-policy",
        "--history-file",
    ],
)
def test_measurement_cli_has_no_label_policy_credential_or_provider_override(tmp_path, option):
    _, path, output = case(tmp_path)
    result = invoke(path, output, option, "synthetic-unselected-input")
    assert result.exit_code != 0 and not output.exists()
