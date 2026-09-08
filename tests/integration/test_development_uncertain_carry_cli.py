"""Disposable CLI ledgers and trapped mock HTTP only; no real providers or credentials."""

import json
import socket
import subprocess
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
from mmaudit.benchmark.development import DevelopmentBenchmarkScore
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    development_ledger_request_id,
)
from mmaudit.models.development_costs import DevelopmentCostEstimate
from mmaudit.models.development_review import DevelopmentReviewObservation
from mmaudit.models.development_transport import review_development_fixture
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
    PortfolioAttemptSlot,
)
from mmaudit.orchestration.development_audit import run_development_audit
from tests.development_audit_support import CORPUS_ROOT, audit_case, shard_payload
from tests.development_benchmark_support import scored_file_response, scored_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL, response_payload
from tests.integration.test_development_corpus_audit import inputs as corpus_inputs
from tests.integration.test_development_cost_preview import _inputs as preview_inputs
from tests.integration.test_development_fixture_review import _inputs as fixture_inputs

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("carry regression attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def next_run(arguments, tmp_path, name):
    result = list(arguments)
    result[result.index("--run-id") + 1] = name
    result[result.index("--output-dir") + 1] = str(tmp_path / name)
    return result


@pytest.mark.parametrize(
    "blocker", ["pending", "portfolio", "foreign", "budget", "overrun", "duplicate"]
)
def test_carry_audit_preflight_refuses_other_liabilities_without_outputs_or_transport(
    tmp_path, monkeypatch, blocker
):
    args = corpus_inputs(tmp_path)
    ledger = AtomicCostLedger.open_existing(
        tmp_path / "synthetic-ledger.json", cap_usd=Decimal("20")
    )
    identifier = "dev-estimate-" + "a" * 64 + ":1"
    if blocker == "duplicate":
        prepared = audit_case(run_id=args[args.index("--run-id") + 1])
        identifier = development_ledger_request_id(prepared.shards[0].estimate.request_id)
    amount = Decimal("19.99999") if blocker == "budget" else Decimal("1")
    ledger.reconcile(ledger.reserve(identifier, amount), None)
    if blocker == "pending":
        ledger.reserve("pending", Decimal("1"))
    elif blocker == "portfolio":
        ledger.reserve_portfolio("b" * 64, (PortfolioAttemptSlot("held", Decimal("1")),))
    elif blocker == "foreign":
        ledger.reconcile(ledger.reserve("foreign-unknown", Decimal("1")), None)
    elif blocker == "overrun":
        other = ledger.reserve("overrun", Decimal("1"))
        with pytest.raises(CostReservationOverrunError):
            ledger.reconcile(other, Decimal("2"))
    before = ledger.path.read_bytes()
    calls = []

    def handler(request):
        calls.append(request)
        pytest.fail("blocked cumulative accounting reached transport")

    async def local_run(**kwargs):
        return await run_development_audit(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(development_cli, "run_development_audit", local_run)
    result = RUNNER.invoke(app, [*args, "--carry-uncertain-estimates"])
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert not calls and not (tmp_path / "run").exists()
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize("scored", [False, True])
@pytest.mark.parametrize("failure", ["http429", "missing_cost", "invalid_json", "timeout"])
def test_failed_run_then_explicit_new_run_preserves_cumulative_liability_and_old_artifacts(
    tmp_path, monkeypatch, variant, scored, failure
):
    args = corpus_inputs(tmp_path, variant=variant)
    if scored:
        truth = tmp_path / "truth.json"
        truth.write_bytes((CORPUS_ROOT / f"truth-{variant}.json").read_bytes())
        args.extend(["--truth-manifest", str(truth)])
    calls = []

    def handler(request):
        calls.append(request.content)
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        assert str(tmp_path).encode() not in request.content
        if len(calls) == 1:
            if failure == "http429":
                return httpx.Response(429, json={"error": {"message": "SYNTHETIC_PRIVATE_CANARY"}})
            if failure == "timeout":
                raise httpx.ReadTimeout("SYNTHETIC_PRIVATE_CANARY", request=request)
            if failure == "invalid_json":
                return httpx.Response(200, content=b"{SYNTHETIC_PRIVATE_CANARY")
            payload = scored_payload(1) if scored else shard_payload(1)
            del payload["usage"]["cost"]
            return httpx.Response(200, json=payload)
        index = len(calls) - 1
        assert index <= 3, "an incomplete run must never silently retry or resume"
        payload = (
            scored_payload(index, response=scored_file_response(index, advisory=variant == "b"))
            if scored
            else shard_payload(index)
        )
        payload["id"] = f"gen-synthetic-selected-second-run-{index}"
        return httpx.Response(200, json=payload)

    async def local_run(**kwargs):
        return await run_development_audit(**kwargs, mock_transport=httpx.MockTransport(handler))

    monkeypatch.setattr(development_cli, "run_development_audit", local_run)
    first_args = [*args, "--carry-uncertain-estimates"] if variant == "b" else args
    first = RUNNER.invoke(app, first_args)
    assert first.exit_code == ExitCode.INCOMPLETE, first.output
    failed = DevelopmentAuditObservation.model_validate_json(first.stdout)
    assert failed.status == "INCOMPLETE" and failed.completed_shard_count == 0
    assert len(calls) == 1 and "UNKNOWN_COST" in failed.observations[0].diagnostics
    old_files = {path.name: path.read_bytes() for path in (tmp_path / "run").iterdir()}
    ledger_path = tmp_path / "synthetic-ledger.json"
    ledger = AtomicCostLedger.open_existing(ledger_path, cap_usd=Decimal("20"))
    old_entry = ledger.snapshot().entries[0]
    old_ledger = ledger_path.read_bytes()
    assert old_entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert old_entry.actual_cost_usd is None
    assert old_entry.accounted_cost_usd == old_entry.reserved_usd

    blocked = RUNNER.invoke(app, next_run(args, tmp_path, "default-still-stops"))
    assert blocked.exit_code == ExitCode.CONFIGURATION, blocked.output
    assert not (tmp_path / "default-still-stops").exists() and len(calls) == 1
    assert ledger_path.read_bytes() == old_ledger

    selected = next_run(args, tmp_path, "explicit-next-run")
    second = RUNNER.invoke(app, [*selected, "--carry-uncertain-estimates"])
    assert second.exit_code == ExitCode.SUCCESS, second.output
    result = DevelopmentAuditObservation.model_validate_json(second.stdout)
    assert result.status == "OBSERVED_ALL_SHARDS" and result.completed_shard_count == 3
    assert len(calls) == 4
    assert result.total_accounted_cost_usd == Decimal("0.03")  # Run-scoped, not cumulative history.
    assert (
        result.audit_complete is result.qualification_eligible is result.release_eligible is False
    )
    assert all(
        shard.estimate.policy.uncertain_cost_policy == "CARRY_RESERVED_ESTIMATE"
        for shard in result.plan.shards
    )
    retained = DevelopmentAuditObservation.model_validate_json(
        (tmp_path / "explicit-next-run/result.json").read_bytes()
    )
    assert retained == result
    reopened = AtomicCostLedger.open_existing(ledger_path, cap_usd=Decimal("20"))
    state = reopened.snapshot()
    assert old_entry in state.entries and len(state.entries) == 4
    assert state.spent_usd == old_entry.reserved_usd + Decimal("0.03")
    assert state.remaining_usd == Decimal("20") - state.spent_usd
    assert state.active_reserved_usd == 0 and not state.over_cap
    assert (
        json.loads(ledger_path.read_bytes())["entries"][old_entry.request_id]
        == json.loads(old_ledger)["entries"][old_entry.request_id]
    )
    assert {path.name: path.read_bytes() for path in (tmp_path / "run").iterdir()} == old_files
    after_success = ledger_path.read_bytes()
    replay = list(selected)
    replay[replay.index("--output-dir") + 1] = str(tmp_path / "refused-replay")
    repeated = RUNNER.invoke(app, [*replay, "--carry-uncertain-estimates"])
    assert repeated.exit_code == ExitCode.CONFIGURATION and len(calls) == 4
    assert not (tmp_path / "refused-replay").exists()
    assert ledger_path.read_bytes() == after_success
    if scored:
        old_score = DevelopmentBenchmarkScore.model_validate_json(old_files["score.json"])
        new_score = DevelopmentBenchmarkScore.model_validate_json(
            (tmp_path / "explicit-next-run/score.json").read_bytes()
        )
        assert old_score.summary.quality_scope == "INCOMPLETE_OBSERVATIONS"
        assert old_score.summary.uncertain_accounted_cost_usd == old_entry.reserved_usd
        assert new_score.observation == result
        assert new_score.summary.quality_scope == "COMPLETE_OBSERVATIONS"
    for output in (first.output, blocked.output, second.output):
        assert SYNTHETIC_CREDENTIAL not in output and "SYNTHETIC_PRIVATE_CANARY" not in output


@pytest.mark.parametrize("selected", [False, True])
def test_offline_preview_binds_carry_selection_without_reading_ledger_or_credentials(
    tmp_path, monkeypatch, selected
):
    args = preview_inputs(tmp_path)
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    def forbidden(*_args, **_kwargs):
        pytest.fail("preview accessed credentials or a ledger")

    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "open_existing", forbidden)
    flags = ["--carry-uncertain-estimates"] if selected else []
    result = RUNNER.invoke(app, [*args, "--accept-estimate-risk", *flags])
    assert result.exit_code == ExitCode.SUCCESS, result.output
    estimate = DevelopmentCostEstimate.model_validate_json(result.stdout)
    assert estimate.policy.uncertain_cost_policy == (
        "CARRY_RESERVED_ESTIMATE" if selected else "STOP"
    )
    assert (
        estimate.provider_enforced_ceiling
        is estimate.qualification_eligible
        is estimate.release_eligible
        is False
    )
    assert ("uncertain_cost_policy" in result.stdout) is selected
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("missing", ["--accept-estimate-risk", "--allow-code-egress"])
def test_carry_flag_cannot_bypass_existing_consent_before_any_control_read(
    tmp_path, monkeypatch, missing
):
    args = corpus_inputs(tmp_path)
    args.remove(missing)

    def forbidden(*_args, **_kwargs):
        pytest.fail("missing consent reached an input, ledger or credential read")

    monkeypatch.setattr(development_cli, "read_json_evidence", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "open_existing", forbidden)
    result = RUNNER.invoke(app, [*args, "--carry-uncertain-estimates"])
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert missing in result.output and not (tmp_path / "run").exists()


@pytest.mark.parametrize("selected", [False, True])
def test_fixture_review_uses_same_policy_and_ledger_without_auto_retry(
    tmp_path, monkeypatch, selected
):
    args = fixture_inputs(tmp_path)
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        assert calls <= 2
        return (
            httpx.Response(429, json={"error": {}})
            if calls == 1
            else httpx.Response(200, json=response_payload())
        )

    async def local_review(**kwargs):
        return await review_development_fixture(
            **kwargs, mock_transport=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(development_cli, "review_development_fixture", local_review)
    first = RUNNER.invoke(app, args)
    assert first.exit_code == ExitCode.INCOMPLETE, first.output
    assert calls == 1
    args[args.index("--request-id") + 1] = "synthetic-selected-next-fixture"
    flags = ["--carry-uncertain-estimates"] if selected else []
    second = RUNNER.invoke(app, [*args, *flags])
    assert second.exit_code == (ExitCode.SUCCESS if selected else ExitCode.CONFIGURATION), (
        second.output
    )
    assert calls == (2 if selected else 1)
    if selected:
        result = DevelopmentReviewObservation.model_validate_json(second.stdout)
        assert result.estimate.policy.uncertain_cost_policy == "CARRY_RESERVED_ESTIMATE"
        assert result.audit_complete is result.qualification_eligible is False
