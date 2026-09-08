from __future__ import annotations

import socket
import subprocess
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_audit import DevelopmentAuditObservation
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_audit import run_development_audit
from tests.development_audit_support import corpus_sources, shard_payload
from tests.development_cost_support import development_case
from tests.development_review_support import SYNTHETIC_CREDENTIAL, discovery_review_case

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_network_or_subprocess(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("local mock integration must not network or execute model output")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def inputs(tmp_path, *, variant="a", discovery=False):
    metadata = discovery_review_case() if discovery else development_case()[0]
    (tmp_path / "snapshot.json").write_text(metadata.model_dump_json())
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for name, content in corpus_sources(variant):
        (corpus / name).write_bytes(content)
    # A non-allowlisted neighbor must never be inspected or sent.
    (corpus / "unselected.txt").write_text("SYNTHETIC_UNSELECTED_CANARY")
    control = tmp_path / "synthetic-operator-control.txt"
    control.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    control.chmod(0o600)
    AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20"))
    return [
        "development",
        "audit-corpus",
        "--endpoint-snapshot",
        str(tmp_path / "snapshot.json"),
        "--corpus-root",
        str(corpus),
        "--corpus-id",
        "unit-ledger-" + variant + "-v1",
        "--cost-ledger",
        str(tmp_path / "synthetic-ledger.json"),
        "--secrets-env-file",
        str(control),
        "--output-dir",
        str(tmp_path / "run"),
        "--run-id",
        "synthetic-cli-corpus-1",
        "--budget-usd",
        "20",
        "--per-attempt-usd",
        "5",
        "--accept-estimate-risk",
        "--allow-code-egress",
    ]


@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize("discovery", [False, True])
def test_cli_real_file_plan_shard_ledger_and_aggregate_handoff_is_nonqualifying(
    tmp_path, monkeypatch, variant, discovery
):
    args = inputs(tmp_path, variant=variant, discovery=discovery)
    ledger_path = tmp_path / "synthetic-ledger.json"
    loaded = []
    calls = 0
    unchanged = {p: p.read_bytes() for p in (tmp_path / "corpus").iterdir()}
    unchanged[tmp_path / "snapshot.json"] = (tmp_path / "snapshot.json").read_bytes()

    def loader(path, **kwargs):
        assert kwargs == {"environ": {}, "required": True}
        value = load_operator_secrets(path, **kwargs)
        loaded.append(value)
        return value

    def handler(request):
        nonlocal calls
        calls += 1
        state = AtomicCostLedger.open_existing(ledger_path, cap_usd=Decimal("20")).snapshot()
        assert len(state.entries) == calls
        assert sum(e.status is CostEntryStatus.RESERVED for e in state.entries) == 1
        assert (tmp_path / "run/plan.json").is_file()
        assert "Source file: UnitStore.sol" in request.content.decode()
        assert "Source file: RoutePolicy.sol" in request.content.decode()
        for forbidden in (SYNTHETIC_CREDENTIAL, str(tmp_path), "SYNTHETIC_UNSELECTED_CANARY"):
            assert forbidden.encode() not in request.content
        return httpx.Response(200, json=shard_payload(calls, empty=variant == "b"))

    async def local_audit(**kwargs):
        return await run_development_audit(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-ambient-unused")
    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", "/synthetic-ambient-invalid")
    monkeypatch.setattr(development_cli, "load_operator_secrets", loader)
    monkeypatch.setattr(development_cli, "run_development_audit", local_audit)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.SUCCESS, result.output
    report = DevelopmentAuditObservation.model_validate_json(result.stdout)
    assert report == DevelopmentAuditObservation.model_validate_json(
        (tmp_path / "run/result.json").read_bytes()
    )
    assert calls == report.completed_shard_count == 3
    assert report.transport == "MOCK_HTTP" and report.status == "OBSERVED_ALL_SHARDS"
    assert (
        report.audit_complete is report.findings_validated is report.qualification_eligible is False
    )
    assert report.release_eligible is False and report.total_accounted_cost_usd == Decimal("0.03")
    assert len(loaded) == 1 and loaded[0].cleared is True
    assert all(p.read_bytes() == content for p, content in unchanged.items())
    before_ledger = ledger_path.read_bytes()
    before_output = {p: p.read_bytes() for p in (tmp_path / "run").iterdir()}
    # Both an existing output and the same request identities at a different path refuse.
    for output_dir in (tmp_path / "run", tmp_path / "replay"):
        replay_args = args.copy()
        replay_args[replay_args.index("--output-dir") + 1] = str(output_dir)
        replay = RUNNER.invoke(app, replay_args)
        assert replay.exit_code == ExitCode.CONFIGURATION
        assert calls == 3 and ledger_path.read_bytes() == before_ledger
        assert all(p.read_bytes() == content for p, content in before_output.items())
        assert SYNTHETIC_CREDENTIAL not in replay.output
    assert not (tmp_path / "replay").exists()


@pytest.mark.parametrize(
    "failure",
    [
        "no_consent",
        "no_risk",
        "source_bytes",
        "missing_source",
        "linked_source",
        "linked_root",
        "relative_path",
        "same_paths",
        "overlap",
        "wrong_corpus",
        "missing_ledger",
        "bad_cap",
        "over_estimate",
    ],
)
def test_cli_preflight_refuses_before_credentials_or_transport(tmp_path, monkeypatch, failure):
    args = inputs(tmp_path)
    ledger = tmp_path / "synthetic-ledger.json"
    before = ledger.read_bytes()
    if failure in {"no_consent", "no_risk"}:
        args.remove("--allow-code-egress" if failure == "no_consent" else "--accept-estimate-risk")
    elif failure == "source_bytes":
        (tmp_path / "corpus/RoutePolicy.sol").write_text("SYNTHETIC_CHANGED_SOURCE_CANARY")
    elif failure == "missing_source":
        (tmp_path / "corpus/UnitStore.sol").rename(tmp_path / "retained-source.sol")
    elif failure == "linked_source":
        path = tmp_path / "corpus/UnitStore.sol"
        path.rename(tmp_path / "retained-source.sol")
        path.symlink_to(tmp_path / "retained-source.sol")
    elif failure == "linked_root":
        (tmp_path / "alias").symlink_to(tmp_path / "corpus", target_is_directory=True)
        args[args.index("--corpus-root") + 1] = str(tmp_path / "alias")
    else:
        option, value = {
            "relative_path": ("--corpus-root", "corpus"),
            "same_paths": ("--secrets-env-file", str(tmp_path / "snapshot.json")),
            "overlap": ("--output-dir", str(tmp_path / "corpus/run")),
            "wrong_corpus": ("--corpus-id", "arbitrary"),
            "missing_ledger": ("--cost-ledger", str(tmp_path / "missing.json")),
            "bad_cap": ("--budget-usd", "10"),
            "over_estimate": ("--per-attempt-usd", "0.001"),
        }[failure]
        args[args.index(option) + 1] = value

    def forbidden(*_args, **_kwargs):
        raise AssertionError("preflight must not load credentials or enter transport")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(development_cli, "run_development_audit", forbidden)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert ledger.read_bytes() == before
    assert not (tmp_path / "run").exists() and not (tmp_path / "missing.json").exists()
    for canary in (
        SYNTHETIC_CREDENTIAL,
        "SYNTHETIC_CHANGED_SOURCE_CANARY",
        "SYNTHETIC_UNSELECTED_CANARY",
    ):
        assert canary not in result.output


def test_cli_incomplete_keeps_costs_outputs_and_clears_credentials(tmp_path, monkeypatch):
    args = inputs(tmp_path)
    loaded = []
    calls = 0

    def loader(path, **kwargs):
        value = load_operator_secrets(path, **kwargs)
        loaded.append(value)
        return value

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200, json=shard_payload(1))
        raise httpx.ReadTimeout(SYNTHETIC_CREDENTIAL, request=request)

    async def local_audit(**kwargs):
        return await run_development_audit(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(development_cli, "load_operator_secrets", loader)
    monkeypatch.setattr(development_cli, "run_development_audit", local_audit)
    result = RUNNER.invoke(app, args)
    assert result.exit_code == ExitCode.INCOMPLETE, result.output
    report = DevelopmentAuditObservation.model_validate_json(result.stdout)
    assert calls == len(report.observations) == 2
    assert report.completed_shard_count == 1 and report.status == "INCOMPLETE"
    assert report.accounting[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert report == DevelopmentAuditObservation.model_validate_json(
        (tmp_path / "run/result.json").read_bytes()
    )
    assert loaded[0].cleared is True and SYNTHETIC_CREDENTIAL not in result.output


def test_cli_has_no_implicit_resume_source_discovery_or_transport_override():
    result = RUNNER.invoke(app, ["development", "audit-corpus", "--help"])
    assert result.exit_code == ExitCode.SUCCESS
    for option in (
        "--resume",
        "--retry",
        "--maximum-attempts",
        "--request-file",
        "--repo",
        "--base-url",
        "--transport",
        "--run-command",
    ):
        assert option not in result.output
