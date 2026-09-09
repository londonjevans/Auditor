"""Real repeat CLI and file/ledger adapters; only paired synthetic fixtures and mock HTTP."""

import asyncio
import json
import os
import socket
import subprocess
from contextlib import contextmanager
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as cli
import mmaudit.orchestration.development_corpus_repeats as repeats
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus_repeats import (
    read_development_corpus_repeats,
    read_development_corpus_repeats_plan,
)
from tests.development_corpus_repeats_support import repeat_input_files, repeat_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.unit.test_development_corpus_resume_metadata import metadata_case

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("repeat CLI attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def inputs(tmp_path, **changes):
    arguments, ledger, secrets, output = repeat_input_files(tmp_path, **changes)
    policy = arguments["policy"]
    flags = {k: v for k, v in arguments.items() if k != "policy"}
    flags.update(
        cost_ledger=ledger.path,
        secrets_env_file=secrets,
        output_dir=output,
        budget_usd=policy.total_budget_usd,
        per_attempt_usd=policy.per_attempt_budget_usd,
    )
    args = ["development", "repeat-manifest"]
    for name, value in flags.items():
        args += ["--" + name.replace("_", "-"), str(value)]
    args += ["--accept-estimate-risk", "--allow-code-egress"]
    return args, arguments, ledger, output


def mocked(monkeypatch, handler):
    async def execute(**kwargs):
        return await repeats.run_development_corpus_repeats(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(cli, "run_development_corpus_repeats", execute)


@pytest.mark.parametrize("count", [2, 3, 8])
def test_cli_freezes_whole_series_and_emits_compact_unqualified_summary(
    tmp_path, monkeypatch, count
):
    args, arguments, ledger, output = inputs(tmp_path, count=count, budget="250")
    calls = []

    def handler(request):
        plan = read_development_corpus_repeats_plan((output / "plan.json").read_bytes())
        assert plan.trial_count == count and len(plan.trials) == count
        assert request.extensions["timeout"]["read"] == 180
        assert b"synthetic-paired-nested-labels" not in request.content
        if len(calls) >= 6:
            assert request.content == calls[len(calls) % 6].content
        calls.append(request)
        return httpx.Response(200, json=repeat_payload(len(calls)))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == 0, result.output
    summary = json.loads(result.stdout)
    observation = read_development_corpus_repeats((output / "result.json").read_bytes())
    assert summary["summary_kind"] == "development_corpus_repeats_cli_summary"
    assert summary["result_sha256"] == observation.observation_sha256
    assert summary["trial_count"] == summary["completed_trial_count"] == count
    assert len(calls) == len(ledger.snapshot().entries) == count * 6
    assert summary["status"] == "COMPLETE" and summary["missing_result_trial_indexes"] == []
    assert all(
        summary[k] is False
        for k in (
            "findings_validated",
            "audit_complete",
            "qualification_eligible",
            "release_eligible",
        )
    )
    assert len(result.stdout.encode()) < 2000
    assert "src/a/" not in result.output and SYNTHETIC_CREDENTIAL not in result.output
    assert observation.plan.benchmark.truth_file_content.encode() == (
        arguments["truth_manifest"].read_bytes()
    )
    assert (output / "stability.json").is_file()


@pytest.mark.parametrize("form", ["discovery_payload", "discovery_file"])
def test_cli_accepts_shared_metadata_without_manual_conversion(tmp_path, monkeypatch, form):
    args, _, _, output = inputs(tmp_path, metadata=metadata_case(form))
    calls = []

    def handler(request):
        calls.append(request)
        assert request.extensions["timeout"]["read"] == 360
        return httpx.Response(200, json=repeat_payload(len(calls)))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(
        app,
        [
            *args,
            "--request-timeout-seconds",
            "360",
            "--maximum-trial-seconds",
            "900",
            "--maximum-run-seconds",
            "1200",
        ],
    )
    assert result.exit_code == 0, result.output
    observed = read_development_corpus_repeats((output / "result.json").read_bytes())
    assert observed.plan.maximum_run_seconds == 1200
    assert all(t.maximum_run_seconds == 900 for t in observed.plan.trials)
    assert observed.plan.policy.request_timeout_seconds == 360


@pytest.mark.parametrize("flag", ["--accept-estimate-risk", "--allow-code-egress"])
def test_missing_consent_refuses_before_inputs_or_credentials(tmp_path, monkeypatch, flag):
    args, _, ledger, output = inputs(tmp_path)
    args.remove(flag)

    def forbidden(*_args, **_kwargs):
        pytest.fail("missing consent reached input handling")

    for name in ("read_development_corpus_repeats_inputs", "load_operator_secrets"):
        monkeypatch.setattr(cli, name, forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert not ledger.snapshot().entries and not output.exists()


@pytest.mark.parametrize(
    "flag,values",
    [
        ("--trial-count", ["1", "9", "2.5", "true"]),
        ("--maximum-trial-seconds", ["0", "1801"]),
        ("--maximum-run-seconds", ["0", "1801"]),
        ("--request-timeout-seconds", ["0", "1801"]),
    ],
)
def test_invalid_bounds_refuse_before_input_or_credential_access(
    tmp_path, monkeypatch, flag, values
):
    args, _, ledger, output = inputs(tmp_path)

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid flag reached input handling")

    monkeypatch.setattr(cli, "read_development_corpus_repeats_inputs", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)
    for value in values:
        result = RUNNER.invoke(app, [*args, flag, value])
        assert result.exit_code == 2
    assert not ledger.snapshot().entries and not output.exists()


@pytest.mark.parametrize(
    "kind",
    [
        "wrong_pin",
        "relative",
        "parent_component",
        "duplicate_path",
        "output_overlap",
        "bad_metadata",
        "bad_truth",
        "source_drift",
        "truth_link",
        "truth_hardlink",
        "truth_fifo",
        "budget",
        "trial_allowance",
        "missing_truth",
        "missing_count",
    ],
)
def test_invalid_selection_refuses_before_credentials_or_dispatch(tmp_path, monkeypatch, kind):
    args, selected, ledger, output = inputs(tmp_path)
    truth = selected["truth_manifest"]
    if kind == "wrong_pin":
        args[args.index("--truth-sha256") + 1] = "0" * 64
    elif kind == "relative":
        args[args.index("--corpus-root") + 1] = "relative"
    elif kind == "parent_component":
        args[args.index("--corpus-root") + 1] = str(tmp_path / "unused/../corpus")
    elif kind == "duplicate_path":
        args[args.index("--truth-manifest") + 1] = str(selected["source_manifest"])
    elif kind == "output_overlap":
        args[args.index("--output-dir") + 1] = str(selected["corpus_root"] / "run")
    elif kind in {"bad_metadata", "bad_truth"}:
        selected["endpoint_snapshot" if kind == "bad_metadata" else "truth_manifest"].write_text(
            "{"
        )
    elif kind == "source_drift":
        path = next(selected["corpus_root"].rglob("*.sol"))
        path.write_bytes(path.read_bytes() + b"\n")
    elif kind == "truth_link":
        target = truth.with_name("retained-truth.json")
        truth.rename(target)
        truth.symlink_to(target)
    elif kind == "truth_hardlink":
        os.link(truth, truth.with_name("linked-truth.json"))
    elif kind == "truth_fifo":
        truth.unlink()
        os.mkfifo(truth)
    elif kind == "budget":
        args[args.index("--budget-usd") + 1] = "0.01"
    elif kind == "trial_allowance":
        args += ["--maximum-completion-tokens", "65536"]
    else:
        flag = "--truth-manifest" if kind == "missing_truth" else "--trial-count"
        index = args.index(flag)
        del args[index : index + 2]

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid input reached credential or provider handling")

    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli, "run_development_corpus_repeats", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert not ledger.snapshot().entries and not output.exists()
    assert SYNTHETIC_CREDENTIAL not in result.output


@pytest.mark.parametrize("kind", ["headroom", "active", "unknown", "future_request"])
def test_ledger_refusal_precedes_credential_loading(tmp_path, monkeypatch, kind):
    args, arguments, ledger, output = inputs(tmp_path)
    if kind == "headroom":
        ledger.reconcile(ledger.reserve("synthetic-earlier-work", Decimal("15")), Decimal("15"))
    else:
        selected = cli.read_development_corpus_repeats_inputs(**arguments)
        request = (
            development_ledger_request_id(
                selected.prepared.plan.trials[1].shards[0].estimate.request_id
            )
            if kind == "future_request"
            else "synthetic-earlier-work"
        )
        reservation = ledger.reserve(request, Decimal("1"))
        if kind != "active":
            ledger.reconcile(reservation, None if kind == "unknown" else Decimal("0.01"))
    before = ledger.snapshot()

    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid ledger reached credential handling")

    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert ledger.snapshot() == before and not output.exists()


@pytest.mark.parametrize("stage", ["before_secrets", "during_secrets"])
@pytest.mark.parametrize("mutation", ["bytes", "inode", "mode"])
def test_input_custody_is_retained_through_control_loading(tmp_path, monkeypatch, stage, mutation):
    args, arguments, ledger, output = inputs(tmp_path)
    truth = arguments["truth_manifest"]

    def drift():
        if mutation == "bytes":
            truth.write_bytes(truth.read_bytes() + b"\n")
        elif mutation == "inode":
            raw, mode = truth.read_bytes(), truth.stat().st_mode
            truth.rename(truth.with_name("retained-truth.json"))
            truth.write_bytes(raw)
            truth.chmod(mode)
        else:
            truth.chmod(truth.stat().st_mode ^ 0o020)

    if stage == "before_secrets":
        original = cli.read_development_corpus_repeats_inputs

        def read(**kwargs):
            result = original(**kwargs)
            drift()
            return result

        monkeypatch.setattr(cli, "read_development_corpus_repeats_inputs", read)
        monkeypatch.setattr(
            cli, "load_operator_secrets", lambda *_a, **_k: pytest.fail("drift reached secrets")
        )
    else:
        original = cli.load_operator_secrets

        @contextmanager
        def controls(*args, **kwargs):
            with original(*args, **kwargs) as secrets:
                drift()
                yield secrets

        monkeypatch.setattr(cli, "load_operator_secrets", controls)
    monkeypatch.setattr(
        cli, "run_development_corpus_repeats", lambda **_: pytest.fail("drift dispatched")
    )
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION), result.output
    assert not ledger.snapshot().entries and not output.exists()


@pytest.mark.parametrize("failure", ["unknown", "known", "missing", "cancel", "derivative"])
def test_cli_never_reports_failed_or_missing_trials_as_complete(tmp_path, monkeypatch, failure):
    args, _, ledger, output = inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            if failure == "unknown":
                return httpx.Response(429, json={"error": "synthetic refused output"})
            if failure == "cancel":
                raise asyncio.CancelledError("synthetic local cancellation")
            if failure == "known":
                payload = repeat_payload(1)
                payload["choices"][0]["message"]["content"] = "invalid synthetic result"
                return httpx.Response(200, json=payload)
        return httpx.Response(200, json=repeat_payload(len(calls)))

    mocked(monkeypatch, handler)
    if failure == "missing":

        async def missing(**_kwargs):
            raise ValueError("synthetic missing child")

        monkeypatch.setattr(repeats, "run_development_corpus", missing)
    elif failure == "derivative":
        original = repeats._write

        def refuse(root, name, model, maximum):
            if name == "stability.json":
                raise ValueError("synthetic derivative refusal")
            return original(root, name, model, maximum)

        monkeypatch.setattr(repeats, "_write", refuse)
    result = RUNNER.invoke(app, args, catch_exceptions=True)
    assert result.exit_code != 0
    observed = read_development_corpus_repeats((output / "result.json").read_bytes())
    if failure in {"unknown", "known", "missing"}:
        assert result.exit_code == int(ExitCode.INCOMPLETE)
        summary = json.loads(result.stdout)
        assert summary["status"] == observed.status == "INCOMPLETE"
    else:
        assert "development_corpus_repeats_cli_summary" not in result.stdout
    if failure in {"unknown", "cancel", "missing"}:
        assert observed.missing_result_trial_indexes == ((0, 1) if failure == "missing" else (1,))
        assert observed.trials[1].status == "NOT_STARTED"
    assert len(observed.trials) == 2
    assert observed.total_accounted_cost_usd == ledger.snapshot().spent_usd
    assert SYNTHETIC_CREDENTIAL not in result.output


def test_explicit_carry_retains_unknown_charge_and_does_not_drop_failed_trial(
    tmp_path, monkeypatch
):
    args, _, ledger, output = inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, json={"error": "synthetic unknown charge"})
        return httpx.Response(200, json=repeat_payload(len(calls), len(calls) - 1))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, [*args, "--carry-uncertain-estimates"])
    assert result.exit_code == int(ExitCode.INCOMPLETE), result.output
    summary = json.loads(result.stdout)
    observed = read_development_corpus_repeats((output / "result.json").read_bytes())
    assert len(calls) == len(ledger.snapshot().entries) == 7
    assert observed.plan.policy.uncertain_cost_policy == "CARRY_RESERVED_ESTIMATE"
    assert [t.status for t in observed.trials] == ["INCOMPLETE", "COMPLETE"]
    assert summary["trial_count"] == summary["started_trial_count"] == 2
    assert summary["completed_trial_count"] == 1
    assert summary["unknown_actual_cost_request_count"] == 1
    assert Decimal(summary["uncertain_accounted_cost_usd"]) > 0
    assert Decimal(summary["reported_actual_cost_usd"]) == Decimal("0.06")
    assert (output / "stability.json").is_file()


def test_parent_environment_cannot_replace_explicit_credential_file(tmp_path, monkeypatch):
    args, _, ledger, output = inputs(tmp_path)
    secret = args[args.index("--secrets-env-file") + 1]
    from pathlib import Path

    Path(secret).unlink()
    monkeypatch.setenv("OPENROUTER_API_KEY", SYNTHETIC_CREDENTIAL)
    monkeypatch.setattr(
        cli, "run_development_corpus_repeats", lambda **_: pytest.fail("missing file dispatched")
    )
    result = RUNNER.invoke(app, args)
    assert result.exit_code == int(ExitCode.CONFIGURATION)
    assert not ledger.snapshot().entries and not output.exists()
    assert SYNTHETIC_CREDENTIAL not in result.output


def test_cli_dispatch_uses_owned_snapshot_not_later_changes_to_originals(tmp_path, monkeypatch):
    args, selected, _, output = inputs(tmp_path)
    truth_before = selected["truth_manifest"].read_bytes()
    source = next(selected["corpus_root"].rglob("*.sol"))
    source_before = source.read_bytes()
    calls = []

    def handler(request):
        calls.append(request)
        assert b"changed original synthetic input" not in request.content
        if len(calls) == 1:
            source.write_bytes(b"// changed original synthetic input\n")
            selected["truth_manifest"].write_bytes(b"changed original synthetic input")
        return httpx.Response(200, json=repeat_payload(len(calls)))

    mocked(monkeypatch, handler)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == 0, result.output
    observed = read_development_corpus_repeats((output / "result.json").read_bytes())
    assert observed.plan.benchmark.truth_file_content.encode() == truth_before
    material = json.loads((output / "sources.json").read_bytes())
    retained = {s["filename"]: s["content"].encode() for s in material["sources"]}
    assert retained[source.relative_to(selected["corpus_root"]).as_posix()] == source_before
    assert len(calls) == 12 and observed.completed_trial_count == 2
