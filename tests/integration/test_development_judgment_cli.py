"""CLI preparation and owned-file custody, using only synthetic local credentials and HTTP."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_judgment import DevelopmentJudgmentObservation
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_judgment import run_development_judgment
from tests.development_audit_support import CORPUS_ROOT
from tests.development_judgment_support import judgment_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_judgment_execution import candidate_inputs

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("judgment CLI attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def inputs(tmp_path, *, variant="a", empty=False, scored=True):
    prepared, ledger, _secrets = asyncio.run(
        candidate_inputs(tmp_path, variant=variant, empty=empty)
    )
    metadata = tmp_path / "reviewer.json"
    metadata.write_text(prepared.endpoint_snapshot.model_dump_json())
    secret_file = tmp_path / "synthetic-secrets.txt"
    secret_file.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    secret_file.chmod(0o600)
    corpus = tmp_path / "corpus"
    corpus.mkdir(mode=0o700)
    for name, content in prepared.source_files:
        (corpus / name).write_bytes(content)
    arguments = [
        "development",
        "judge-audit",
        "--candidate-audit-file",
        str(tmp_path / "candidate/result.json"),
        "--endpoint-snapshot",
        str(metadata),
        "--corpus-root",
        str(corpus),
        "--cost-ledger",
        str(ledger.path),
        "--secrets-env-file",
        str(secret_file),
        "--output-dir",
        str(tmp_path / "judgment"),
        "--run-id",
        "cli-judgment",
        "--budget-usd",
        "20",
        "--per-attempt-usd",
        "5",
        "--accept-estimate-risk",
        "--allow-code-egress",
    ]
    if scored:
        truth = tmp_path / "truth.json"
        truth.write_bytes((CORPUS_ROOT / f"truth-{variant}.json").read_bytes())
        arguments += ["--truth-manifest", str(truth)]
    return arguments, ledger


def mock_judgment(monkeypatch, handler):
    async def execute(**kwargs):
        return await run_development_judgment(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(development_cli, "run_development_judgment", execute)


@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize("scored", [False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_cli_executes_explicit_candidate_review_and_optional_local_score(
    tmp_path, monkeypatch, variant, scored, empty
):
    args, ledger = inputs(tmp_path, variant=variant, empty=empty, scored=scored)
    before = (tmp_path / "candidate/result.json").read_bytes()
    calls = []

    def handler(request):
        calls.append(request.content)
        assert not empty
        return httpx.Response(200, json=judgment_payload(len(calls)))

    mock_judgment(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.SUCCESS, result.output
    observed = DevelopmentJudgmentObservation.model_validate_json(result.stdout)
    assert observed.status == ("NO_CANDIDATES" if empty else "OBSERVED_ALL_JUDGMENTS")
    assert len(calls) == (0 if empty else 3)
    assert len(ledger.snapshot().entries) == (3 if empty else 6)
    assert (tmp_path / "judgment/score.json").exists() is scored
    assert (tmp_path / "candidate/result.json").read_bytes() == before
    assert SYNTHETIC_CREDENTIAL not in result.output and "NOT_ESTABLISHED" in result.output


@pytest.mark.parametrize("missing", ["--accept-estimate-risk", "--allow-code-egress"])
def test_cli_consent_is_checked_before_any_input_or_credential_read(tmp_path, monkeypatch, missing):
    args, _ledger = inputs(tmp_path)
    args.remove(missing)

    def forbidden(*_args, **_kwargs):
        pytest.fail("missing consent reached input or credential access")

    monkeypatch.setattr(development_cli, "read_json_evidence", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "open_existing", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION and not (tmp_path / "judgment").exists()


@pytest.mark.parametrize(
    "malformation",
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
        "wrong_source",
        "wrong_truth",
        "metadata_drift",
    ],
)
def test_cli_invalid_or_changed_public_inputs_refuse_before_credentials_and_dispatch(
    tmp_path, monkeypatch, malformation
):
    args, ledger = inputs(tmp_path)
    candidate = tmp_path / "candidate/result.json"
    alternate = tmp_path / "alternate-candidate.json"
    if malformation in {"malformed", "duplicate_json", "nonfinite", "oversized"}:
        contents = {
            "malformed": b"{",
            "duplicate_json": b'{"plan":{},"plan":{}}',
            "nonfinite": b'{"plan":NaN}',
            "oversized": b" " * 2_000_001,
        }
        alternate.write_bytes(contents[malformation])
        args[args.index("--candidate-audit-file") + 1] = str(alternate)
    elif malformation in {"symlink", "hardlink", "fifo"}:
        if malformation == "symlink":
            alternate.symlink_to(candidate)
        elif malformation == "hardlink":
            os.link(candidate, alternate)
        else:
            os.mkfifo(alternate)
        args[args.index("--candidate-audit-file") + 1] = str(alternate)
    elif malformation == "relative":
        args[args.index("--candidate-audit-file") + 1] = "relative.json"
    elif malformation == "duplicate_path":
        args[args.index("--endpoint-snapshot") + 1] = str(candidate)
    elif malformation == "wrong_source":
        with (tmp_path / "corpus/RoutePolicy.sol").open("ab") as stream:
            stream.write(b"\n")
    elif malformation == "wrong_truth":
        (tmp_path / "truth.json").write_bytes((CORPUS_ROOT / "truth-b.json").read_bytes())
    else:
        original = development_cli.prepare_development_judgment

        def prepare_with_changed_input(**kwargs):
            prepared = original(**kwargs)
            (tmp_path / "reviewer.json").write_text("{}")
            return prepared

        monkeypatch.setattr(
            development_cli, "prepare_development_judgment", prepare_with_changed_input
        )
    before = ledger.path.read_bytes()

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid public input reached private controls or dispatch")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "open_existing", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert ledger.path.read_bytes() == before and not (tmp_path / "judgment").exists()
    assert SYNTHETIC_CREDENTIAL not in result.output


def test_cli_failure_is_incomplete_and_explicit_carry_mode_keeps_prior_liabilities(
    tmp_path, monkeypatch
):
    args, ledger = inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request.content)
        if len(calls) == 1:
            return httpx.Response(429, json={"error": "SYNTHETIC_PRIVATE_CANARY"})
        return httpx.Response(200, json=judgment_payload(len(calls) - 1))

    mock_judgment(monkeypatch, handler)
    first = RUNNER.invoke(app, args)
    assert first.exit_code == ExitCode.INCOMPLETE, first.output
    failed_files = {path.name: path.read_bytes() for path in (tmp_path / "judgment").iterdir()}
    prior = ledger.snapshot().entries
    args[args.index("--run-id") + 1] = "later-selected-judgment"
    args[args.index("--output-dir") + 1] = str(tmp_path / "later-judgment")
    refused = RUNNER.invoke(app, args)
    assert refused.exit_code == ExitCode.CONFIGURATION and len(calls) == 1
    assert not (tmp_path / "later-judgment").exists()
    second = RUNNER.invoke(app, [*args, "--carry-uncertain-estimates"])
    assert second.exit_code == ExitCode.SUCCESS, second.output
    result = DevelopmentJudgmentObservation.model_validate_json(second.stdout)
    assert result.plan.policy.uncertain_cost_policy == "CARRY_RESERVED_ESTIMATE"
    assert len(calls) == 4 and len(ledger.snapshot().entries) == 7
    assert all(entry in ledger.snapshot().entries for entry in prior)
    assert ledger.snapshot().spent_usd > result.combined_accounted_cost_usd
    assert {
        path.name: path.read_bytes() for path in (tmp_path / "judgment").iterdir()
    } == failed_files
    assert (
        SYNTHETIC_CREDENTIAL not in first.output and "SYNTHETIC_PRIVATE_CANARY" not in first.output
    )
