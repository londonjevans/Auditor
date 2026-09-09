"""Synthetic repeat execution with real custody/ledger adapters and no live network or credentials."""

import asyncio
import json
import socket
import subprocess
import time
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.development_cli as cli
import mmaudit.orchestration.development_corpus as candidate_runner
import mmaudit.orchestration.development_corpus_repeats as repeats
from mmaudit.benchmark.development_corpus_stability import read_development_corpus_stability
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus_repeats import read_development_corpus_repeats
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.development_corpus_repeats_support import repeat_case, repeat_payload
from tests.development_review_support import local_controls


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("candidate repeats attempted network, subprocess or credential loading")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [2, 3, 8])
async def test_fixed_series_is_retained_before_first_dispatch_and_measured_automatically(
    tmp_path, count
):
    prepared = repeat_case(
        trial_count=count,
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("250"),
            per_attempt_budget_usd=Decimal("5"),
        ),
    )
    ledger, secrets = local_controls(tmp_path)
    ledger = AtomicCostLedger.initialize(tmp_path / "series-ledger.json", cap_usd=Decimal("250"))
    calls = []

    def handler(request):
        frozen = json.loads((tmp_path / "run/plan.json").read_bytes())
        assert frozen["trial_count"] == len(frozen["trials"]) == count
        assert frozen["plan_sha256"] == prepared.plan.plan_sha256
        calls.append(request)
        trial, shard = divmod(len(calls) - 1, 6)
        assert request.content == prepared.trials[trial].shards[shard].request_content
        return httpx.Response(200, json=repeat_payload(len(calls)))

    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == result.selected_request_count == count * 6
    assert result.status == "COMPLETE" and result.stop_reason is None
    assert result.started_trial_count == result.completed_trial_count == count
    assert result.reported_actual_cost_usd == Decimal("0.06") * count
    assert not result.missing_runtime_request_ids and not result.missing_accounting_request_ids
    assert read_development_corpus_repeats((tmp_path / "run/result.json").read_bytes()) == result
    measured = read_development_corpus_stability((tmp_path / "run/stability.json").read_bytes())
    assert len(measured.trials) == count and len(measured.cohorts) == 1
    assert measured.combined.trial_indexes == tuple(range(count))
    assert not measured.audit_complete and not measured.qualification_eligible
    assert (tmp_path / "run").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "run/result.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("known_cost", [True, False])
async def test_failed_first_trial_is_retained_and_unknown_cost_stops_later_trials(
    tmp_path, known_cost
):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                429,
                json={
                    "error": "Synthetic refusal",
                    **({"usage": {"cost": 0.01}} if known_cost else {}),
                },
            )
        return httpx.Response(200, json=repeat_payload(len(calls), len(calls) - 1))

    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "INCOMPLETE" and len(result.trials) == 2
    assert result.trials[0].status == "INCOMPLETE"
    assert result.trials[1].status == ("COMPLETE" if known_cost else "NOT_STARTED")
    assert len(calls) == (7 if known_cost else 1)
    assert result.stop_reason == ("TRIAL_INCOMPLETE" if known_cost else "BUDGET_STOP")
    assert result.selected_request_count == 12
    assert len(result.missing_runtime_request_ids) == (5 if known_cost else 11)
    if known_cost:
        measured = read_development_corpus_stability((tmp_path / "run/stability.json").read_bytes())
        assert len(measured.trials) == 2 and measured.combined.union_location_coverage.value is None
    else:
        assert result.uncertain_accounted_cost_usd > 0
        assert len(result.unknown_actual_cost_request_ids) == 1
        assert result.missing_result_trial_indexes == (1,)
        assert not (tmp_path / "run/stability.json").exists()


@pytest.mark.asyncio
async def test_cancellation_retains_interrupted_child_and_all_unstarted_trials(tmp_path):
    prepared = repeat_case(trial_count=3)
    ledger, secrets = local_controls(tmp_path)
    calls = []

    async def handler(request):
        calls.append(request)
        raise asyncio.CancelledError("synthetic cancellation")

    with pytest.raises(asyncio.CancelledError, match="synthetic cancellation"):
        await repeats.run_development_corpus_repeats(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    result = read_development_corpus_repeats((tmp_path / "run/result.json").read_bytes())
    assert len(calls) == 1 and result.stop_reason == "INTERRUPTED"
    assert [t.status for t in result.trials] == ["INCOMPLETE", "NOT_STARTED", "NOT_STARTED"]
    assert result.missing_result_trial_indexes == (1, 2)
    assert result.uncertain_accounted_cost_usd > 0
    assert len(result.missing_runtime_request_ids) == 18
    assert not (tmp_path / "run/stability.json").exists()


@pytest.mark.asyncio
async def test_missing_entire_child_result_does_not_invent_a_successful_empty_trial(
    tmp_path, monkeypatch
):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)

    async def unavailable(**_kwargs):
        raise ValueError("synthetic local pre-dispatch failure")

    monkeypatch.setattr(repeats, "run_development_corpus", unavailable)
    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(lambda _: pytest.fail("unexpected dispatch")),
    )
    assert [t.status for t in result.trials] == ["MISSING_RESULT", "NOT_STARTED"]
    assert all(t.observation is None for t in result.trials)
    assert result.selected_request_count == len(result.missing_runtime_request_ids) == 12
    assert result.total_accounted_cost_usd == 0 and not ledger.snapshot().entries
    assert not (tmp_path / "run/stability.json").exists()


@pytest.mark.asyncio
async def test_cross_trial_generation_reuse_retains_costs_but_withholds_series_measurement(
    tmp_path,
):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        payload = repeat_payload(len(calls))
        if len(calls) == 7:
            payload["id"] = "gen-synthetic-repeat-1"
        return httpx.Response(200, json=payload)

    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == 12 and result.stop_reason == "IDENTITY_REUSE"
    assert result.generation_identity_reused and result.completed_trial_count == 2
    assert result.status == "INCOMPLETE" and result.reported_actual_cost_usd == Decimal("0.12")
    assert not (tmp_path / "run/stability.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["bytes", "inode", "mode"])
async def test_parent_plan_custody_is_rechecked_before_every_child_request(tmp_path, kind):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        path = tmp_path / "run/plan.json"
        if len(calls) == 1:
            if kind == "bytes":
                path.write_bytes(b"{}")
            elif kind == "mode":
                path.chmod(0o644)
            else:
                replacement = tmp_path / "new-plan.json"
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(0o600)
                replacement.replace(path)
        return httpx.Response(200, json=repeat_payload(len(calls)))

    with pytest.raises((ValueError, OSError)):
        await repeats.run_development_corpus_repeats(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert len(calls) == len(ledger.snapshot().entries) == 1
    assert not (tmp_path / "run/result.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["request", "trial", "consent", "transport", "output"])
async def test_invalid_prepared_series_never_reaches_dispatch(tmp_path, kind):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    if kind == "request":
        first = prepared.trials[0]
        prepared = replace(
            prepared,
            trials=(
                replace(
                    first,
                    shards=(replace(first.shards[0], request_content=b"{}"), *first.shards[1:]),
                ),
                *prepared.trials[1:],
            ),
        )
    elif kind == "trial":
        prepared = replace(prepared, trials=prepared.trials[:1])
    elif kind == "output":
        (tmp_path / "run").mkdir()
    with pytest.raises((ValueError, OSError)):
        await repeats.run_development_corpus_repeats(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=1 if kind == "consent" else True,
            mock_transport=object()
            if kind == "transport"
            else httpx.MockTransport(lambda _: pytest.fail("invalid series dispatched")),
        )
    assert not ledger.snapshot().entries


@pytest.mark.asyncio
async def test_explicit_uncertain_cost_carry_keeps_failed_trial_and_its_full_charge(tmp_path):
    prepared = repeat_case(
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("20"),
            per_attempt_budget_usd=Decimal("5"),
            uncertain_cost_policy="CARRY_RESERVED_ESTIMATE",
        )
    )
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, json={"error": "synthetic uncertain-cost response"})
        return httpx.Response(200, json=repeat_payload(len(calls), len(calls) - 1))

    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == 7 and [t.status for t in result.trials] == ["INCOMPLETE", "COMPLETE"]
    assert (
        result.uncertain_accounted_cost_usd
        == prepared.plan.trials[0].shards[0].estimate.estimated_cost_per_attempt_usd
    )
    assert result.reported_actual_cost_usd == Decimal("0.06")
    assert (
        result.total_accounted_cost_usd
        == result.reported_actual_cost_usd + result.uncertain_accounted_cost_usd
    )
    measured = read_development_corpus_stability((tmp_path / "run/stability.json").read_bytes())
    assert len(measured.trials) == 2 and measured.combined.union_location_coverage.value is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["headroom", "future_request", "active", "unknown"])
async def test_shared_ledger_preflight_refuses_before_any_output_or_request(tmp_path, kind):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    if kind == "headroom":
        ledger.reconcile(ledger.reserve("synthetic-earlier-work", Decimal("15")), Decimal("15"))
        assert prepared.plan.trials[0].estimated_total_cost_usd < ledger.snapshot().remaining_usd
        assert prepared.plan.estimated_total_cost_usd > ledger.snapshot().remaining_usd
    else:
        request = (
            development_ledger_request_id(prepared.plan.trials[1].shards[0].estimate.request_id)
            if kind == "future_request"
            else "synthetic-prior-request"
        )
        held = ledger.reserve(request, Decimal("1"))
        if kind != "active":
            ledger.reconcile(held, None if kind == "unknown" else Decimal("0.01"))
    before = ledger.snapshot()
    with pytest.raises(ValueError, match=r"accounting|headroom"):
        await repeats.run_development_corpus_repeats(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(lambda _: pytest.fail("refused series dispatched")),
        )
    assert ledger.snapshot() == before and not (tmp_path / "run").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("expire", [False, True])
async def test_one_parent_deadline_is_shared_and_later_trials_cannot_reset_it(
    tmp_path, monkeypatch, expire
):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    advance = [0.0]
    clock = SimpleNamespace(monotonic=lambda: time.monotonic() + advance[0])
    monkeypatch.setattr(repeats, "time", clock)
    monkeypatch.setattr(candidate_runner, "time", clock)
    original = repeats.run_development_corpus
    deadlines, calls = [], []

    async def wrapped(**kwargs):
        deadlines.append(kwargs["parent_deadline"])
        assert kwargs["prepared"].plan.maximum_run_seconds == 600
        result = await original(**kwargs)
        if expire:
            advance[0] += 601
        return result

    monkeypatch.setattr(repeats, "run_development_corpus", wrapped)

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=repeat_payload(len(calls)))

    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(set(deadlines)) == 1 and len(calls) == (6 if expire else 12)
    assert result.started_trial_count == (1 if expire else 2)
    assert result.stop_reason == ("LOCAL_FAILURE" if expire else None)
    assert result.trials[1].status == ("NOT_STARTED" if expire else "COMPLETE")
    assert result.total_accounted_cost_usd == ledger.snapshot().spent_usd


@pytest.mark.asyncio
async def test_child_score_failure_keeps_durable_result_and_all_later_missing_slots(
    tmp_path, monkeypatch
):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def refuse(*_args, **_kwargs):
        raise ValueError("synthetic sidecar failure")

    monkeypatch.setattr(candidate_runner, "_write_score", refuse)

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=repeat_payload(len(calls)))

    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == 6 and result.stop_reason == "LOCAL_FAILURE"
    assert [t.status for t in result.trials] == ["COMPLETE", "NOT_STARTED"]
    assert result.total_accounted_cost_usd == Decimal("0.06")
    assert not (tmp_path / "run/trial-01/score.json").exists()
    assert not (tmp_path / "run/stability.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_parent_finalization_failure_never_overrides_original_cancellation(
    tmp_path, monkeypatch, cancel
):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    original = repeats._write
    calls = []

    def refused(root, name, model, maximum):
        if name == ("result.json" if cancel else "stability.json"):
            raise ValueError("synthetic parent finalization refusal")
        return original(root, name, model, maximum)

    monkeypatch.setattr(repeats, "_write", refused)

    async def handler(request):
        calls.append(request)
        if cancel:
            raise asyncio.CancelledError("synthetic original interrupt")
        return httpx.Response(200, json=repeat_payload(len(calls)))

    with pytest.raises(asyncio.CancelledError if cancel else repeats.DevelopmentCorpusRepeatsError):
        await repeats.run_development_corpus_repeats(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert len(calls) == len(ledger.snapshot().entries) == (1 if cancel else 12)
    assert not (tmp_path / "run/stability.json").exists()
    if not cancel:
        result = read_development_corpus_repeats((tmp_path / "run/result.json").read_bytes())
        assert result.completed_trial_count == 2 and result.reported_actual_cost_usd == Decimal(
            "0.12"
        )
    else:
        assert not (tmp_path / "run/result.json").exists()
        assert (tmp_path / "run/trial-01/result.json").exists()


@pytest.mark.asyncio
async def test_actual_reservation_overrun_stops_series_and_retains_full_reported_cost(tmp_path):
    prepared = repeat_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        payload = repeat_payload(len(calls))
        payload["usage"]["cost"] = 2
        return httpx.Response(200, json=payload)

    result = await repeats.run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == 1 and result.trials[1].status == "NOT_STARTED"
    assert result.stop_reason == "BUDGET_STOP" and ledger.snapshot().has_reservation_overrun
    assert result.reported_actual_cost_usd == result.total_accounted_cost_usd == Decimal("2")
    assert not (tmp_path / "run/stability.json").exists()
