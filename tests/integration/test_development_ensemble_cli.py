"""Explicit one-command ensemble controls on synthetic local files and mock HTTP only."""

from __future__ import annotations

import os
import socket
import subprocess

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_ensemble import DevelopmentEnsembleObservation
from mmaudit.orchestration.development_ensemble import run_development_ensemble
from tests.development_audit_support import CORPUS_ROOT
from tests.development_ensemble_support import ensemble_case, ensemble_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls
from tests.integration.test_development_ensemble_execution import request_role

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("ensemble CLI attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def inputs(tmp_path, *, variant="a", scored=True):
    prepared = ensemble_case(variant=variant)
    ledger, _ = local_controls(tmp_path)
    roles = (prepared.candidate.shards[0].endpoint_snapshot, *prepared.reviewer_metadata)
    metadata_paths = []
    for ordinal, metadata in enumerate(roles):
        path = tmp_path / f"metadata-{ordinal}.json"
        path.write_text(metadata.model_dump_json())
        metadata_paths.append(path)
    corpus = tmp_path / "corpus"
    corpus.mkdir(mode=0o700)
    for name, content in prepared.candidate.shards[0].source_files:
        (corpus / name).write_bytes(content)
    secret = tmp_path / "synthetic-secrets.txt"
    secret.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    secret.chmod(0o600)
    args = [
        "development",
        "ensemble-corpus",
        "--candidate-endpoint-snapshot",
        str(metadata_paths[0]),
        "--first-reviewer-endpoint-snapshot",
        str(metadata_paths[1]),
        "--second-reviewer-endpoint-snapshot",
        str(metadata_paths[2]),
        "--corpus-root",
        str(corpus),
        "--corpus-id",
        prepared.plan.candidate.corpus_id,
        "--cost-ledger",
        str(ledger.path),
        "--secrets-env-file",
        str(secret),
        "--output-dir",
        str(tmp_path / "ensemble"),
        "--run-id",
        "cli-ensemble",
        "--budget-usd",
        "20",
        "--per-attempt-usd",
        "1",
        "--accept-estimate-risk",
        "--allow-code-egress",
        "--candidate-maximum-completion-tokens",
        "4096",
        "--first-reviewer-maximum-completion-tokens",
        "8192",
        "--second-reviewer-maximum-completion-tokens",
        "16384",
    ]
    if scored:
        truth = tmp_path / "truth.json"
        truth.write_bytes((CORPUS_ROOT / f"truth-{variant}.json").read_bytes())
        args += ["--truth-manifest", str(truth)]
    return args, ledger


def mocked(monkeypatch, handler):
    async def execute(**kwargs):
        return await run_development_ensemble(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(development_cli, "run_development_ensemble", execute)


@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize("scored", [True, False])
@pytest.mark.parametrize("empty", [True, False])
def test_cli_runs_all_selected_stages_and_optional_same_truth_score(
    tmp_path, monkeypatch, variant, scored, empty
):
    args, ledger = inputs(tmp_path, variant=variant, scored=scored)
    calls = []

    def handler(request):
        role, shard, body = request_role(request, calls)
        assert body["max_tokens"] == (4096, 8192, 16384)[role]
        return httpx.Response(200, json=ensemble_payload(role, shard, count=0 if empty else 1))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == 0, result.output
    observation = DevelopmentEnsembleObservation.model_validate_json(result.stdout, strict=True)
    assert observation.status == ("NO_CANDIDATES" if empty else "OBSERVED_ALL_STAGES")
    assert len(calls) == len(ledger.snapshot().entries) == (3 if empty else 9)
    assert (tmp_path / "ensemble/score.json").exists() is scored
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("flag", ["--accept-estimate-risk", "--allow-code-egress"])
def test_cli_requires_both_consents_before_any_file_or_private_control(tmp_path, monkeypatch, flag):
    args, ledger = inputs(tmp_path)
    args.remove(flag)
    before = ledger.snapshot()

    def forbidden(*_args, **_kwargs):
        pytest.fail("ensemble CLI read inputs before explicit consent")

    monkeypatch.setattr(development_cli, "read_json_evidence", forbidden)
    monkeypatch.setattr(development_cli, "read_file_evidence", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert ledger.snapshot() == before and not (tmp_path / "ensemble").exists()


@pytest.mark.parametrize(
    "kind",
    [
        "malformed",
        "duplicate_json",
        "nonfinite",
        "oversized",
        "symlink",
        "hardlink",
        "fifo",
        "relative",
        "duplicate_path",
        "same_model",
        "wrong_source",
        "wrong_truth",
        "bad_allowance",
        "metadata_drift",
    ],
)
def test_cli_rejects_bad_or_changed_inputs_before_credentials_and_dispatch(
    tmp_path, monkeypatch, kind
):
    args, ledger = inputs(tmp_path)
    path = tmp_path / "metadata-1.json"
    before = ledger.snapshot()
    if kind == "malformed":
        path.write_text("{")
    elif kind == "duplicate_json":
        path.write_text('{"id":"x","id":"y"}')
    elif kind == "nonfinite":
        path.write_text('{"value":NaN}')
    elif kind == "oversized":
        path.write_bytes(b" " * 2_000_001)
    elif kind in {"symlink", "hardlink", "fifo"}:
        original = tmp_path / "retained-metadata.json"
        path.rename(original)
        if kind == "symlink":
            path.symlink_to(original)
        elif kind == "hardlink":
            path.hardlink_to(original)
        else:
            os.mkfifo(path)
    elif kind == "relative":
        args[args.index("--corpus-root") + 1] = "corpus"
    elif kind == "duplicate_path":
        args[args.index("--first-reviewer-endpoint-snapshot") + 1] = str(
            tmp_path / "metadata-0.json"
        )
    elif kind == "same_model":
        path.write_bytes((tmp_path / "metadata-0.json").read_bytes())
    elif kind == "wrong_source":
        (tmp_path / "corpus/RoutePolicy.sol").write_bytes(b"// Changed synthetic source.\n")
    elif kind == "wrong_truth":
        (tmp_path / "truth.json").write_bytes((CORPUS_ROOT / "truth-b.json").read_bytes())
    elif kind == "bad_allowance":
        args[args.index("--first-reviewer-maximum-completion-tokens") + 1] = "65536"
    else:
        original_prepare = development_cli.prepare_development_ensemble

        def drift(**kwargs):
            prepared = original_prepare(**kwargs)
            path.write_bytes(path.read_bytes() + b"\n")
            return prepared

        monkeypatch.setattr(development_cli, "prepare_development_ensemble", drift)

    def forbidden(*_args, **_kwargs):
        pytest.fail("ensemble CLI accessed credentials or dispatched after invalid input")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_ensemble", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert SYNTHETIC_CREDENTIAL not in result.output
    assert ledger.snapshot() == before and not (tmp_path / "ensemble").exists()


def test_cli_failed_stage_is_incomplete_not_success_or_automatic_retry(tmp_path, monkeypatch):
    args, ledger = inputs(tmp_path)
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        if role == 1:
            return httpx.Response(429, json={"error": {"message": "Synthetic refusal."}})
        return httpx.Response(200, json=ensemble_payload(role, shard))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.INCOMPLETE, result.output
    observation = DevelopmentEnsembleObservation.model_validate_json(result.stdout)
    assert observation.status == "INCOMPLETE" and len(calls) == 4
    assert len(ledger.snapshot().entries) == 4 and observation.uncertain_accounted_cost_usd > 0
