"""Explicit pinned development labels through the real CLI; only synthetic local HTTP and files."""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.benchmark.development_corpus import DevelopmentCorpusBenchmarkScore
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus import DevelopmentCorpusObservation
from tests.development_corpus_benchmark_support import (
    labelled_truth,
    paired_case,
    paired_payload,
    paired_sources,
)
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_cli import inputs, mocked

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest score CLI attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def selected_inputs(tmp_path):
    args, ledger, root, manifest, metadata = inputs(tmp_path)
    prepared = paired_case()
    for name, raw in paired_sources():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    manifest.write_text(prepared.plan.manifest.model_dump_json())
    metadata.write_text(prepared.shards[0].endpoint_snapshot.model_dump_json())
    truth_file = tmp_path / "truth.json"
    truth_file.write_text(labelled_truth(prepared).model_dump_json(indent=2))
    pin = hashlib.sha256(truth_file.read_bytes()).hexdigest()
    args += ["--truth-manifest", str(truth_file), "--truth-sha256", pin]
    return args, ledger, truth_file


@pytest.mark.parametrize("failure", [False, True])
def test_cli_automatically_retains_original_result_and_separate_pinned_score(
    tmp_path, monkeypatch, failure
):
    args, ledger, truth_file = selected_inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        assert (tmp_path / "run/benchmark-plan.json").exists()
        assert b"synthetic-paired-nested-labels" not in request.content
        if failure and len(calls) == 3:
            return httpx.Response(429, json={"error": "synthetic refusal"})
        return httpx.Response(200, json=paired_payload(len(calls)))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.INCOMPLETE if failure else ExitCode.SUCCESS), (
        result.output
    )
    observation = DevelopmentCorpusObservation.model_validate_json(result.stdout, strict=True)
    score = DevelopmentCorpusBenchmarkScore.model_validate_json(
        (tmp_path / "run/score.json").read_bytes(), strict=True
    )
    assert score.observation == observation
    assert score.binding.truth_file_content.encode() == truth_file.read_bytes()
    assert len(calls) == len(ledger.snapshot().entries) == (3 if failure else 6)
    assert score.summary.unique_root_recall.value == (None if failure else 1.0)
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("flag", ["--truth-manifest", "--truth-sha256"])
def test_orphan_truth_options_refuse_before_any_input_read(tmp_path, monkeypatch, flag):
    args, ledger, _ = selected_inputs(tmp_path)
    index = args.index(flag)
    del args[index : index + 2]

    def forbidden(*_args, **_kwargs):
        pytest.fail("orphan label option reached input handling")

    monkeypatch.setattr(development_cli, "load_development_corpus", forbidden)
    monkeypatch.setattr(development_cli, "read_json_evidence", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert not ledger.snapshot().entries and not (tmp_path / "run").exists()


@pytest.mark.parametrize(
    "kind",
    [
        "wrong_pin",
        "bad_pin",
        "different_source",
        "duplicate_json",
        "nonfinite",
        "malformed",
        "oversize",
        "utf8",
        "link",
        "hardlink",
        "fifo",
        "relative",
        "duplicate_path",
        "output_overlap",
        "handoff_drift",
    ],
)
def test_invalid_label_file_refuses_before_credentials_or_dispatch(tmp_path, monkeypatch, kind):
    args, ledger, truth_file = selected_inputs(tmp_path)
    if kind == "wrong_pin":
        args[-1] = "a" * 64
    elif kind == "bad_pin":
        args[-1] = "not-a-digest"
    elif kind == "different_source":
        truth_file.write_text(
            truth_file.read_text().replace("synthetic-medium", "different-corpus")
        )
    elif kind == "duplicate_json":
        truth_file.write_text(
            '{"truth_id":"synthetic-paired-nested-labels",' + truth_file.read_text()[1:]
        )
    elif kind == "nonfinite":
        truth_file.write_text('{"truth_id":NaN}')
    elif kind == "malformed":
        truth_file.write_text("{")
    elif kind == "oversize":
        truth_file.write_bytes(b" " * 2_000_001)
    elif kind == "utf8":
        truth_file.write_bytes(b"\xff")
    elif kind == "link":
        retained = tmp_path / "original-truth.json"
        truth_file.rename(retained)
        truth_file.symlink_to(retained)
    elif kind == "hardlink":
        os.link(truth_file, tmp_path / "linked-truth.json")
    elif kind == "fifo":
        truth_file.unlink()
        os.mkfifo(truth_file)
    elif kind == "relative":
        args[args.index("--truth-manifest") + 1] = "relative.json"
    elif kind == "duplicate_path":
        args[args.index("--truth-manifest") + 1] = args[args.index("--source-manifest") + 1]
    elif kind == "output_overlap":
        args[args.index("--output-dir") + 1] = str(tmp_path)
    else:
        original = development_cli.prepare_development_corpus

        def drift(**kwargs):
            prepared = original(**kwargs)
            truth_file.write_text("changed")
            return prepared

        monkeypatch.setattr(development_cli, "prepare_development_corpus", drift)
    if kind in {"different_source", "duplicate_json", "nonfinite", "malformed", "oversize", "utf8"}:
        args[-1] = hashlib.sha256(truth_file.read_bytes()).hexdigest()

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid label file reached credential or dispatch handling")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_corpus", forbidden)
    before = ledger.path.read_bytes()
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert ledger.path.read_bytes() == before and not (tmp_path / "run").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output
