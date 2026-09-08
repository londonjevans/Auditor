"""Durable source-manifest execution on synthetic controls; real network and subprocess are trapped."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest

from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
    PortfolioAttemptSlot,
)
from mmaudit.orchestration.development_corpus import run_development_corpus
from tests.development_corpus_support import corpus_case, corpus_payload, supplied_sources
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("development corpus attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [0, 1, 16])
async def test_fourteen_selected_files_execute_with_original_sources_and_no_quality_promotion(
    tmp_path, count
):
    prepared = corpus_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []
    original = supplied_sources()

    def handler(request):
        calls.append(request.content)
        ordinal = len(calls)
        assert request.content == prepared.shards[ordinal - 1].request_content
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        assert (tmp_path / "run/sources.json").is_file()
        return httpx.Response(
            200,
            json=corpus_payload(
                ordinal, count=count, origin="src/SafeVariants.sol" if count else None
            ),
        )

    result = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == len(result.observations) == len(result.accounting) == 14
    assert result.status == "OBSERVED_ALL_SHARDS" and result.stop_reason is None
    assert result.completed_shard_count == 14 and not result.unobserved_shard_ids
    assert result.selected_primary_line_count == result.primary_lines_with_observed_responses == 424
    assert result.candidate_claim_count == 14 * count
    assert result.total_accounted_cost_usd == result.reported_actual_cost_usd == Decimal("0.14")
    assert result.uncertain_accounted_cost_usd == result.active_reserved_usd == 0
    assert (
        result.findings_validated
        is result.audit_complete
        is result.qualification_eligible
        is result.release_eligible
        is False
    )
    assert (
        DevelopmentCorpusObservation.model_validate_json(
            (tmp_path / "run/result.json").read_bytes(), strict=True
        )
        == result
    )
    retained = DevelopmentCorpusMaterial.model_validate_json(
        (tmp_path / "run/sources.json").read_bytes(), strict=True
    )
    assert retained.source_files == original == supplied_sources()
    assert len(list((tmp_path / "run").iterdir())) == 17
    assert (tmp_path / "run").stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (tmp_path / "run").iterdir())
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="accounting"):
        await run_development_corpus(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "replay",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert ledger.snapshot() == before and len(calls) == 14 and not (tmp_path / "replay").exists()


@pytest.mark.asyncio
async def test_sixty_four_distinct_primary_files_keep_the_exact_upper_scope(tmp_path):
    raw = supplied_sources()[0][1]
    sources = tuple((f"packages/control-{i:03d}/Source.sol", raw) for i in range(64))
    prepared = corpus_case(
        source_files=sources,
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("250"),
            per_attempt_budget_usd=Decimal("5"),
        ),
    )
    _, secrets = local_controls(tmp_path)
    ledger = AtomicCostLedger.initialize(tmp_path / "large-ledger.json", cap_usd=Decimal("250"))
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=corpus_payload(len(calls), count=0))

    result = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == result.completed_shard_count == len(result.accounting) == 64
    assert result.status == "OBSERVED_ALL_SHARDS" and result.candidate_claim_count == 0
    assert result.observations[-1].shard_id == "file-0064"
    assert result.total_accounted_cost_usd == Decimal("0.64")


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_shard", [1, 7, 14])
@pytest.mark.parametrize(
    "failure",
    [
        "known_http",
        "unknown_http",
        "malformed",
        "origin",
        "overrun",
        "generation_reuse",
        "wrong_identity",
        "partial_json",
        "length",
        "too_many_claims",
        "secret_output",
    ],
)
async def test_failure_stops_without_losing_any_selected_file_or_cost(
    tmp_path, failed_shard, failure
):
    if failure == "generation_reuse" and failed_shard == 1:
        failed_shard = 2
    prepared = corpus_case()
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        ordinal = len(calls)
        payload = corpus_payload(ordinal)
        if ordinal == failed_shard:
            if failure in {"known_http", "unknown_http"}:
                return httpx.Response(
                    429,
                    json={
                        "error": "Synthetic local refusal",
                        **({"usage": {"cost": 0.01}} if failure == "known_http" else {}),
                    },
                )
            if failure == "malformed":
                payload["choices"][0]["message"]["content"] = "{"
            elif failure == "origin":
                payload = corpus_payload(ordinal, origin="src/NotSupplied.sol")
            elif failure == "overrun":
                payload["usage"]["cost"] = 2
            elif failure == "generation_reuse":
                payload["id"] = "gen-synthetic-corpus-1"
            elif failure == "wrong_identity":
                payload["model"] = "synthetic/wrong-model"
            elif failure == "partial_json":
                payload["choices"][0]["message"]["content"] = '{"schema_version":"3.0"}'
            elif failure == "length":
                payload["choices"][0]["finish_reason"] = "length"
            elif failure == "too_many_claims":
                payload = corpus_payload(ordinal, count=17)
            elif failure == "secret_output":
                response = json.loads(payload["choices"][0]["message"]["content"])
                response["summary"] = SYNTHETIC_CREDENTIAL
                payload["choices"][0]["message"]["content"] = json.dumps(response)
        return httpx.Response(200, json=payload)

    result = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "INCOMPLETE" and result.stop_reason == "SHARD_INCOMPLETE"
    assert len(calls) == len(result.accounting) == len(result.observations) == failed_shard
    assert result.completed_shard_count == failed_shard - 1
    assert len(result.unobserved_shard_ids) == 15 - failed_shard
    assert result.candidate_claim_count == failed_shard - 1
    assert result.selected_primary_line_count == 424
    assert result.primary_lines_with_observed_responses == sum(
        s.line_count for s in prepared.plan.manifest.sources[: failed_shard - 1]
    )
    assert result.total_accounted_cost_usd == sum(
        e.accounted_cost_usd for e in ledger.snapshot().entries
    )
    assert bool(result.uncertain_accounted_cost_usd) is (failure == "unknown_http")
    if failure == "overrun":
        assert result.accounting[-1].status is CostEntryStatus.RESERVATION_OVERRUN
        assert result.reported_actual_cost_usd == Decimal("2") + Decimal("0.01") * (
            failed_shard - 1
        )
    elif failure != "unknown_http":
        assert result.reported_actual_cost_usd == Decimal("0.01") * failed_shard


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "request",
        "source",
        "missing_shard",
        "consent",
        "transport",
        "output_exists",
        "source_snapshot_drift",
    ],
)
async def test_prepared_and_owned_output_custody_cannot_be_bypassed(tmp_path, kind):
    prepared = corpus_case(source_files=supplied_sources()[:4])
    ledger, secrets = local_controls(tmp_path)
    consent = True
    calls = []

    def handler(request):
        calls.append(request)
        if kind == "source_snapshot_drift":
            (tmp_path / "run/sources.json").write_text("{}")
        return httpx.Response(200, json=corpus_payload(len(calls)))

    transport = httpx.MockTransport(handler)
    if kind in {"request", "source"}:
        first = replace(
            prepared.shards[0],
            **({"request_content": b"{}"} if kind == "request" else {"source_content": b"changed"}),
        )
        prepared = replace(prepared, shards=(first, *prepared.shards[1:]))
    elif kind == "missing_shard":
        prepared = replace(prepared, shards=prepared.shards[:-1])
    elif kind == "consent":
        consent = 1
    elif kind == "transport":
        transport = object()
    elif kind == "output_exists":
        (tmp_path / "run").mkdir()
    with pytest.raises((ValueError, OSError)):
        await run_development_corpus(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=consent,
            mock_transport=transport,
        )
    assert (
        len(calls)
        == len(ledger.snapshot().entries)
        == (1 if kind == "source_snapshot_drift" else 0)
    )
    assert not (tmp_path / "run/result.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_whole_run_deadline_or_cancellation_preserves_unreturned_request_liability(
    tmp_path, cancel
):
    ledger, secrets = local_controls(tmp_path)
    entered = asyncio.Event()

    async def handler(_request):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(
        run_development_corpus(
            prepared=corpus_case(maximum_run_seconds=1.0),
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=4)
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await asyncio.wait_for(task, timeout=4)
    result = DevelopmentCorpusObservation.model_validate_json(
        (tmp_path / "run/result.json").read_bytes(), strict=True
    )
    assert result.status == "INCOMPLETE" and result.completed_shard_count == 0
    assert not result.observations and len(result.accounting) == 1
    assert len(result.unobserved_shard_ids) == 14 and result.selected_primary_line_count == 424
    assert result.uncertain_accounted_cost_usd == result.total_accounted_cost_usd > 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "blocker",
    [
        "pending",
        "portfolio",
        "unknown",
        "foreign_unknown_carry",
        "headroom_spent",
        "overrun",
        "cap",
    ],
)
async def test_corpus_preflight_preserves_blocked_cumulative_state_without_dispatch(
    tmp_path, blocker
):
    prepared = corpus_case()
    ledger, secrets = local_controls(tmp_path)
    if blocker == "portfolio":
        ledger.reserve_portfolio("b" * 64, (PortfolioAttemptSlot("synthetic-slot", Decimal("1")),))
    elif blocker == "headroom_spent":
        ledger.reconcile(ledger.reserve("synthetic-other-work", Decimal("19")), Decimal("19"))
    elif blocker == "cap":
        ledger = AtomicCostLedger.initialize(tmp_path / "other-ledger.json", cap_usd=Decimal("21"))
    else:
        hold = ledger.reserve("synthetic-other-request", Decimal("1"))
        if blocker in {"unknown", "foreign_unknown_carry"}:
            ledger.reconcile(hold, None)
        elif blocker == "overrun":
            with pytest.raises(CostReservationOverrunError):
                ledger.reconcile(hold, Decimal("2"))
        if blocker == "foreign_unknown_carry":
            policy = DevelopmentCostPolicy.model_validate(
                {
                    **prepared.plan.policy.model_dump(),
                    "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE",
                }
            )
            prepared = corpus_case(policy=policy)
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("blocked corpus dispatched")

    with pytest.raises(ValueError, match="accounting"):
        await run_development_corpus(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(forbidden),
        )
    assert ledger.path.read_bytes() == before and not (tmp_path / "run").exists()


@pytest.mark.asyncio
async def test_corpus_carry_retains_prior_unknown_liability_without_attributing_it_to_new_run(
    tmp_path,
):
    prepared = corpus_case()
    ledger, secrets = local_controls(tmp_path)
    hold = ledger.reserve(development_ledger_request_id("synthetic-prior-corpus"), Decimal("1"))
    ledger.reconcile(hold, None)
    original = ledger.snapshot().entries[0]
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=corpus_payload(len(calls)))

    with pytest.raises(ValueError, match="accounting"):
        await run_development_corpus(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "default-refused",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    policy = DevelopmentCostPolicy.model_validate(
        {**prepared.plan.policy.model_dump(), "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"}
    )
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20"))
    result = await run_development_corpus(
        prepared=corpus_case(policy=policy),
        ledger=reopened,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "OBSERVED_ALL_SHARDS" and len(calls) == 14
    assert original in reopened.snapshot().entries
    assert sum(e.accounted_cost_usd for e in reopened.snapshot().entries) == Decimal("1.14")
    assert result.total_accounted_cost_usd == Decimal("0.14")
    assert result.uncertain_accounted_cost_usd == 0
    assert not (tmp_path / "default-refused").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "missing_observation",
        "reverse_observations",
        "missing_accounting",
        "reverse_accounting",
        "duplicate_reservation",
        "wrong_request",
        "wrong_reservation",
        "wrong_cost_join",
        "wrong_run",
        "wrong_source",
        "wrong_transport",
        "generation_reuse",
        "hidden_gaps",
        "completed_count",
        "selected_lines",
        "observed_lines",
        "claims",
        "accounted_total",
        "actual_total",
        "uncertain_total",
        "active_total",
        "elapsed",
        "findings_validated",
        "audit_complete",
        "qualification_eligible",
        "release_eligible",
    ],
)
async def test_retained_corpus_cannot_forge_scope_accounting_or_authority(tmp_path, kind):
    prepared = corpus_case(source_files=supplied_sources()[:4])
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=corpus_payload(len(calls)))

    result = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    data = result.model_dump(mode="json")
    if kind == "missing_observation":
        data["observations"].pop()
    elif kind == "reverse_observations":
        data["observations"].reverse()
    elif kind == "missing_accounting":
        data["accounting"].pop()
    elif kind == "reverse_accounting":
        data["accounting"].reverse()
    elif kind == "duplicate_reservation":
        data["accounting"][1]["reservation_id"] = data["accounting"][0]["reservation_id"]
    elif kind == "wrong_request":
        data["accounting"][0]["ledger_request_id"] = data["accounting"][1]["ledger_request_id"]
    elif kind == "wrong_reservation":
        data["accounting"][0]["reserved_usd"] = "2"
    elif kind == "wrong_cost_join":
        data["accounting"][0].update(actual_cost_usd="0.02", accounted_cost_usd="0.02")
    elif kind == "wrong_run":
        data["observations"][0]["run_id"] = "different-run"
    elif kind == "wrong_source":
        data["observations"][0]["source_filename"] = "src/NotSelected.sol"
    elif kind == "wrong_transport":
        data["transport"] = "HTTP_OBSERVATION"
    elif kind == "generation_reuse":
        data["observations"][1]["generation_id"] = data["observations"][0]["generation_id"]
    elif kind == "hidden_gaps":
        data["unobserved_shard_ids"] = ["file-0001"]
    elif kind in {"completed_count", "selected_lines", "observed_lines", "claims"}:
        key = {
            "completed_count": "completed_shard_count",
            "selected_lines": "selected_primary_line_count",
            "observed_lines": "primary_lines_with_observed_responses",
            "claims": "candidate_claim_count",
        }[kind]
        data[key] += 1
    elif kind in {"accounted_total", "actual_total", "uncertain_total", "active_total"}:
        key = {
            "accounted_total": "total_accounted_cost_usd",
            "actual_total": "reported_actual_cost_usd",
            "uncertain_total": "uncertain_accounted_cost_usd",
            "active_total": "active_reserved_usd",
        }[kind]
        data[key] = "1"
    elif kind == "elapsed":
        data["elapsed_seconds"] = 0
    else:
        data[kind] = True
    with pytest.raises(ValueError):
        DevelopmentCorpusObservation.model_validate_json(json.dumps(data), strict=True)
    assert len(calls) == 4 and result.candidate_claim_count == 4
