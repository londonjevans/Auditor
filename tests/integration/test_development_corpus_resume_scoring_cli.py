"""Explicit local history scoring: no labels, credentials, ledger mutation or provider access."""

from __future__ import annotations

import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as cli
import mmaudit.orchestration.development_corpus_resume_score as scoring_io
from mmaudit.benchmark.development_corpus_control_measurement import (
    read_development_corpus_control_measurement,
)
from mmaudit.benchmark.development_corpus_resume import read_development_corpus_resume_score
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus_resume import freeze_development_corpus_resume_history
from tests.development_corpus_resume_score_support import extend_labelled, labelled_history
from tests.integration.test_development_corpus_resume_execution import execute
from tests.integration.test_development_corpus_resume_scoring_execution import (
    accepted_response,
    scored_case,
)

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("offline history scoring accessed credentials, network or subprocesses")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)


def history_case(tmp_path, *, complete=True):
    history, metadata = labelled_history()
    history = extend_labelled(history, metadata) if complete else history
    path = tmp_path / "input" / "middle" / "inner" / "synthetic-history.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(history.model_dump_json(indent=2).encode())
    path.chmod(0o600)
    return history, path, tmp_path / "score"


def invoke(path, output, *extra):
    return RUNNER.invoke(
        app,
        [
            "development",
            "score-history",
            "--history-file",
            str(path),
            "--output-dir",
            str(output),
            *extra,
        ],
    )


@pytest.mark.parametrize("complete", [False, True])
def test_existing_history_cli_scores_offline_with_original_binding_and_private_output(
    tmp_path, complete
):
    history, path, output = history_case(tmp_path, complete=complete)
    raw = path.read_bytes()
    result = invoke(path, output)
    assert result.exit_code == 0, result.output
    score = read_development_corpus_resume_score((output / "cumulative-score.json").read_bytes())
    assert score.history == history and path.read_bytes() == raw
    assert score.first_attempt_summary == history.original_score.summary
    assert score.cumulative_quality.unique_root_recall.value == (1.0 if complete else None)
    assert score.score_sha256 in result.stdout and str(path) not in result.stdout
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / "cumulative-score.json").stat().st_mode) == 0o600
    assert {p.name for p in output.iterdir()} == {
        "cumulative-score.json",
        "control-measurement.json",
    }
    measured = read_development_corpus_control_measurement(
        (output / "control-measurement.json").read_bytes()
    )
    assert measured.source_score == score
    assert stat.S_IMODE((output / "control-measurement.json").stat().st_mode) == 0o600
    assert not score.audit_complete and not score.qualification_eligible


@pytest.mark.asyncio
async def test_offline_cli_reproduces_the_automatic_score_of_an_executed_local_continuation(
    tmp_path,
):
    case = await scored_case(tmp_path)
    await execute(case, custom=lambda *a: accepted_response(case, *a))
    before = case.ledger.path.read_bytes()
    result = invoke(tmp_path / "resume/result.json", tmp_path / "offline")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "resume/cumulative-score.json").read_bytes() == (
        tmp_path / "offline/cumulative-score.json"
    ).read_bytes()
    assert case.ledger.path.read_bytes() == before and len(case.calls) == 5


@pytest.mark.parametrize(
    "kind",
    [
        "no_binding",
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
    ],
)
def test_invalid_or_unbound_history_refuses_without_creating_a_score(tmp_path, kind):
    history, path, output = history_case(tmp_path)
    if kind == "no_binding":
        unbound = freeze_development_corpus_resume_history(
            original=history.original, material=history.material
        )
        path.write_text(unbound.model_dump_json())
    elif kind == "hash":
        path.write_text(history.model_copy(update={"history_sha256": "0" * 64}).model_dump_json())
    elif kind in {"duplicate", "nonfinite", "utf8", "malformed"}:
        path.write_bytes(
            {
                "duplicate": b'{"a":1,"a":2}',
                "nonfinite": b'{"a":Infinity}',
                "utf8": b"\xff",
                "malformed": b"{",
            }[kind]
        )
    elif kind in {"symlink", "hardlink"}:
        retained = path.with_suffix(".retained")
        path.rename(retained)
        path.symlink_to(retained) if kind == "symlink" else os.link(retained, path)
    elif kind == "relative":
        path = Path("synthetic-relative-history.json")
    elif kind == "overlap":
        output = path.parent
    else:
        output.mkdir(mode=0o700)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert "No provider call was selected" in result.output
    assert str(path) not in result.output
    assert not (output / "cumulative-score.json").exists()
    if kind not in {"overlap", "existing_output"}:
        assert not output.exists()


@pytest.mark.parametrize("when", ["after_scoring", "inside_writer", "after_writer"])
@pytest.mark.parametrize("kind", ["byte_change", "file_replace", "ancestor_replace"])
def test_offline_scoring_rejects_exact_input_or_ancestor_drift_through_finalization(
    tmp_path, monkeypatch, when, kind
):
    _, path, output = history_case(tmp_path)
    raw = path.read_bytes()
    compute = scoring_io.score_development_corpus_resume
    writer = scoring_io._write_cumulative_score

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
        if when == "after_scoring":
            mutate()
        return result

    def written(*args, **kwargs):
        if when == "inside_writer":
            mutate()
        result = writer(*args, **kwargs)
        if when == "after_writer":
            mutate()
        return result

    monkeypatch.setattr(scoring_io, "score_development_corpus_resume", computed)
    monkeypatch.setattr(scoring_io, "_write_cumulative_score", written)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert str(path) not in result.output
    if when == "after_scoring":
        assert not output.exists()
    elif when == "inside_writer":
        assert not (output / "cumulative-score.json").exists()


@pytest.mark.parametrize("kind", ["byte_change", "file_replace", "directory_replace", "mode"])
def test_offline_output_is_rechecked_after_private_publication(tmp_path, monkeypatch, kind):
    _, path, output = history_case(tmp_path)
    before = path.read_bytes()
    writer = scoring_io._write_cumulative_score

    def replaced(*args, **kwargs):
        binding = writer(*args, **kwargs)
        score_path = output / "cumulative-score.json"
        raw = score_path.read_bytes()
        if kind == "directory_replace":
            output.rename(output.with_name("retained-score"))
            output.mkdir(mode=0o700)
            score_path.write_bytes(raw)
            score_path.chmod(0o600)
        elif kind == "file_replace":
            score_path.rename(score_path.with_suffix(".retained"))
            score_path.write_bytes(raw)
            score_path.chmod(0o600)
        elif kind == "mode":
            score_path.chmod(0o644)
        else:
            score_path.write_bytes(raw + b" ")
        return binding

    monkeypatch.setattr(scoring_io, "_write_cumulative_score", replaced)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    "option",
    [
        "--truth-file",
        "--original-score-file",
        "--cost-ledger",
        "--secrets-env-file",
        "--endpoint-snapshot",
        "--run-id",
    ],
)
def test_offline_cli_has_no_label_rebinding_provider_or_ledger_controls(tmp_path, option):
    _, path, output = history_case(tmp_path)
    raw = path.read_bytes()
    result = invoke(path, output, option, "synthetic-unselected-option")
    assert result.exit_code == 2 and "No such option" in result.output
    assert path.read_bytes() == raw and not output.exists()


def test_real_oversize_history_file_refuses_at_unchanged_64mb_reader_bound(tmp_path):
    _, path, output = history_case(tmp_path)
    path.write_bytes(b" " * 64_000_001)
    result = invoke(path, output)
    assert result.exit_code == int(ExitCode.CONFIGURATION) and not output.exists()


def test_scoring_api_rejects_nonpath_inputs_before_reading_history(tmp_path):
    with pytest.raises(ValueError, match="absolute and normalized"):
        scoring_io.score_development_corpus_history_file(
            history_file="synthetic-history", output_dir=tmp_path
        )
