"""Exact retained-material CLI handoff with fake credentials and no live provider/network access."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.orchestration.development_corpus_judgment import run_development_corpus_judgment
from tests.development_corpus_judgment_support import manifest_judgment_payload
from tests.development_judgment_support import judgment_metadata
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_judgment_execution import candidate_inputs

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest review CLI attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def inputs(tmp_path, *, partial=False, empty=False):
    prepared, ledger, _ = asyncio.run(
        candidate_inputs(
            tmp_path, fail_at=3 if partial else None, carry=partial, claims=0 if empty else 1
        )
    )
    metadata = tmp_path / "synthetic-reviewer.json"
    metadata.write_text(judgment_metadata().model_dump_json())
    metadata.chmod(0o600)
    secret = tmp_path / "synthetic-operator-input"
    secret.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    secret.chmod(0o600)
    args = [
        "development",
        "judge-manifest",
        "--candidate-audit-file",
        str(tmp_path / "candidate/result.json"),
        "--source-material-file",
        str(tmp_path / "candidate/sources.json"),
        "--endpoint-snapshot",
        str(metadata),
        "--cost-ledger",
        str(ledger.path),
        "--secrets-env-file",
        str(secret),
        "--output-dir",
        str(tmp_path / "review"),
        "--run-id",
        prepared.plan.run_id,
        "--budget-usd",
        "20",
        "--per-attempt-usd",
        "1",
        "--accept-estimate-risk",
        "--allow-code-egress",
    ]
    if partial:
        args.append("--carry-uncertain-estimates")
    return args, prepared, ledger


@pytest.mark.parametrize("mode", ["complete", "empty", "partial"])
@pytest.mark.parametrize("timeout", [None, 360])
def test_cli_executes_retained_material_and_keeps_original_incomplete_scope(
    tmp_path, monkeypatch, mode, timeout
):
    args, prepared, ledger = inputs(tmp_path, partial=mode == "partial", empty=mode == "empty")
    if timeout is not None:
        args += ["--request-timeout-seconds", str(timeout)]
    calls = []

    def handler(request):
        index = len(calls)
        calls.append(request)
        assert request.extensions["timeout"]["read"] == (180 if timeout is None else timeout)
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        return httpx.Response(
            200, json=manifest_judgment_payload(index + 1, shard_id=prepared.shards[index].shard_id)
        )

    async def execute(**kwargs):
        return await run_development_corpus_judgment(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(cli, "run_development_corpus_judgment", execute)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == (ExitCode.INCOMPLETE if mode == "partial" else 0), result.output
    data = json.loads(result.stdout)
    assert (
        data["status"]
        == {
            "complete": "OBSERVED_ALL_JUDGMENTS",
            "empty": "NO_CANDIDATES",
            "partial": "INCOMPLETE",
        }[mode]
    )
    assert len(calls) == len(prepared.shards)
    assert data["plan"]["policy"].get("request_timeout_seconds") == timeout
    assert data["unobserved_candidate_shard_ids"] == list(
        prepared.plan.unobserved_candidate_shard_ids
    )
    assert not data["qualification_eligible"] and not data["release_eligible"]
    assert SYNTHETIC_CREDENTIAL not in result.output
    assert ledger.snapshot().active_reserved_usd == 0


@pytest.mark.parametrize("missing", ["--accept-estimate-risk", "--allow-code-egress"])
def test_cli_missing_consent_refuses_before_any_input_or_secret_read(
    tmp_path, monkeypatch, missing
):
    args, _, ledger = inputs(tmp_path)
    args.remove(missing)
    before = ledger.path.read_bytes()

    def forbidden(*_args, **_kwargs):
        pytest.fail("missing consent reached input/secret access")

    monkeypatch.setattr(cli, "read_json_evidence", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert ledger.path.read_bytes() == before and not (tmp_path / "review").exists()


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--request-timeout-seconds", "0"),
        ("--request-timeout-seconds", "1801"),
        ("--request-timeout-seconds", "1.5"),
        ("--maximum-run-seconds", "0"),
        ("--maximum-completion-tokens", "65537"),
    ],
)
def test_cli_invalid_scalar_refuses_before_input_or_secret_access(
    tmp_path, monkeypatch, flag, value
):
    args, _, ledger = inputs(tmp_path)
    before = ledger.path.read_bytes()

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid scalar reached input access")

    monkeypatch.setattr(cli, "read_json_evidence", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)
    result = RUNNER.invoke(app, [*args, flag, value])
    assert result.exit_code == 2 and ledger.path.read_bytes() == before


@pytest.mark.parametrize(
    "flag", ["--candidate-audit-file", "--source-material-file", "--endpoint-snapshot"]
)
def test_cli_rechecks_every_loaded_file_before_credentials_or_dispatch(tmp_path, monkeypatch, flag):
    args, _, ledger = inputs(tmp_path)
    before = ledger.path.read_bytes()
    target = args[args.index(flag) + 1]
    original = cli.prepare_development_corpus_judgment

    def changed(**kwargs):
        from pathlib import Path

        prepared = original(**kwargs)
        path = Path(target)
        path.write_bytes(path.read_bytes() + b"\n")
        return prepared

    def forbidden(*_args, **_kwargs):
        pytest.fail("changed input reached secret access")

    monkeypatch.setattr(cli, "prepare_development_corpus_judgment", changed)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION and ledger.path.read_bytes() == before
    assert not (tmp_path / "review").exists() and SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("kind", ["relative", "duplicate", "overlap", "material_digest"])
def test_cli_refuses_ambiguous_paths_or_changed_source_manifest(tmp_path, monkeypatch, kind):
    args, _, ledger = inputs(tmp_path)
    before = ledger.path.read_bytes()
    index = args.index("--source-material-file") + 1
    if kind == "relative":
        args[index] = "sources.json"
    elif kind == "duplicate":
        args[index] = args[args.index("--candidate-audit-file") + 1]
    elif kind == "overlap":
        args[args.index("--output-dir") + 1] = str(tmp_path / "candidate")
    else:
        path = tmp_path / "candidate/sources.json"
        data = json.loads(path.read_bytes())
        data["manifest"]["manifest_sha256"] = "0" * 64
        path.write_text(json.dumps(data))

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid scope reached credential access")

    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION and ledger.path.read_bytes() == before
