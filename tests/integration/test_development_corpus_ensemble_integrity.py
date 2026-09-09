"""Fail-closed parent accounting, replay, original-byte custody and interrupted recovery controls."""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest

from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
    PortfolioAttemptSlot,
)
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.development_corpus_judgment_support import selected_policy
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_judgment_support import judgment_metadata
from tests.integration.test_development_corpus_ensemble_boundaries import STAGES, wrap_children
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    response_payload,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("ensemble integrity control attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    ["active", "unknown", "overrun", "headroom", "cap", "foreign_unknown_carry", "portfolio"],
)
async def test_parent_preflight_preserves_blocking_cumulative_state_without_dispatch(
    tmp_path, kind
):
    case = execution_case(
        tmp_path,
        prepared=manifest_ensemble_case(policy=selected_policy(carry=kind.endswith("carry"))),
    )
    if kind == "portfolio":
        case.ledger.reserve_portfolio(
            "b" * 64, (PortfolioAttemptSlot("synthetic-slot", Decimal("1")),)
        )
    elif kind == "cap":
        case.ledger = AtomicCostLedger.initialize(
            tmp_path / "other-synthetic-ledger.json", cap_usd=Decimal("21")
        )
    else:
        reservation = case.ledger.reserve(
            "synthetic-unrelated-work", Decimal("10" if kind == "headroom" else "1")
        )
        if kind in {"unknown", "foreign_unknown_carry"}:
            case.ledger.reconcile(reservation, None)
        elif kind == "overrun":
            with pytest.raises(CostReservationOverrunError):
                case.ledger.reconcile(reservation, Decimal("2"))
        elif kind == "headroom":
            case.ledger.reconcile(reservation, Decimal("10"))
    original = case.ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await execute(case)
    assert not case.calls and not case.root.exists()
    assert case.ledger.path.read_bytes() == original


@pytest.mark.asyncio
@pytest.mark.parametrize("unknown", [False, True])
async def test_permitted_prior_costs_stay_in_ledger_and_are_not_charged_twice_to_parent(
    tmp_path, unknown
):
    case = execution_case(
        tmp_path, prepared=manifest_ensemble_case(policy=selected_policy(carry=unknown))
    )
    reservation = case.ledger.reserve(
        development_ledger_request_id("synthetic-older-run"), Decimal("1")
    )
    case.ledger.reconcile(reservation, None if unknown else Decimal("0.01"))
    prior = case.ledger.snapshot().entries[0]
    result = await execute(case)
    assert result.status == "OBSERVED_ALL_STAGES" and case.counts == [6, 3, 3]
    assert prior in case.ledger.snapshot().entries
    assert result.total_accounted_cost_usd == Decimal("0.12")
    assert (
        case.ledger.snapshot().spent_usd
        == prior.accounted_cost_usd + result.total_accounted_cost_usd
    )
    assert all(row.entry.ledger_request_id != prior.request_id for row in result.accounting)
    assert result.uncertain_accounted_cost_usd == 0


@pytest.mark.asyncio
async def test_parent_replay_cannot_repeat_original_requests_with_a_new_output_directory(tmp_path):
    case = execution_case(tmp_path)
    original = await execute(case)
    ledger_bytes = case.ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await execute(case, output_dir=tmp_path / "replay-output")
    assert case.counts == [6, 3, 3] and original.total_accounted_cost_usd == Decimal("0.12")
    assert (
        not (tmp_path / "replay-output").exists() and case.ledger.path.read_bytes() == ledger_bytes
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["candidate_alias", "reviewer_alias", "request", "source", "plan"])
async def test_rebuilt_role_source_and_request_bindings_refuse_substitution_before_dispatch(
    tmp_path, kind
):
    case = execution_case(tmp_path)
    prepared = case.prepared
    if kind.endswith("alias"):
        index = 0 if kind == "candidate_alias" else 1
        metadata = list(prepared.reviewer_metadata)
        metadata[index] = judgment_metadata(
            model_id=ENSEMBLE_MODELS[index + 1], canonical=ENSEMBLE_MODELS[index]
        )
        prepared = replace(prepared, reviewer_metadata=tuple(metadata))
    elif kind in {"source", "request"}:
        shard = prepared.candidate.shards[0]
        changed = (
            replace(shard, request_content=shard.request_content + b" ")
            if kind == "request"
            else replace(shard, source_content=shard.source_content + b"\n")
        )
        prepared = replace(
            prepared,
            candidate=replace(prepared.candidate, shards=(changed, *prepared.candidate.shards[1:])),
        )
    else:
        prepared = replace(
            prepared, plan=prepared.plan.model_copy(update={"plan_sha256": "0" * 64})
        )
    before = case.ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await execute(case, prepared=prepared)
    assert not case.calls and not case.root.exists() and case.ledger.path.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("stage,prior", [(1, 0), (1, 1), (2, 0), (2, 1), (2, 2)])
async def test_repeated_generation_never_adds_fresh_review_credit_or_drops_its_cost(
    tmp_path, stage, prior
):
    case = execution_case(tmp_path)

    def duplicate(role, ordinal, _request):
        if role == stage and ordinal == 2:
            payload = response_payload(case.prepared, role, ordinal)
            payload["id"] = f"gen-synthetic-manifest-ensemble-{prior}-1"
            return httpx.Response(200, json=payload)

    result = await execute(case, custom=duplicate)
    assert result.status == "INCOMPLETE" and len(result.claims) == 3
    assert case.counts == ([6, 2, 0] if stage == 1 else [6, 3, 2])
    assert result.completed_judgment_count == (1 if stage == 1 else 4)
    assert result.judgments[-1].observations[-1].response is None
    assert result.accounting[-1].entry.status is CostEntryStatus.RECONCILED
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd


@pytest.mark.asyncio
@pytest.mark.parametrize("stage,prior", [(1, 0), (2, 0), (2, 1)])
async def test_prior_stage_ledger_drift_stops_the_real_parent_before_another_request(
    tmp_path, stage, prior
):
    case = execution_case(tmp_path)

    def mutate(role, ordinal, _request):
        if role == stage and ordinal == 1:
            observed = json.loads((case.root / STAGES[prior] / "result.json").read_bytes())
            request_id = observed["accounting"][0]["ledger_request_id"]
            document = json.loads(case.ledger.path.read_bytes())
            del document["entries"][request_id]
            case.ledger.path.write_text(json.dumps(document))

    with pytest.raises(ValueError):
        await execute(case, custom=mutate)
    assert case.counts == ([6, 1, 0] if stage == 1 else [6, 3, 1])
    assert not (case.root / "result.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage,filename",
    [
        (s, name)
        for s in (0, 1, 2)
        for name in ("plan.json", "sources.json", "result.json", "file-0001.json")
    ]
    + [(0, "score.json")],
)
async def test_completed_child_bytes_cannot_change_before_parent_adoption(
    tmp_path, monkeypatch, stage, filename
):
    case = execution_case(tmp_path)

    async def wrapper(original, kwargs):
        child = await original(**kwargs)
        if kwargs["output_dir"].name == STAGES[stage]:
            path = kwargs["output_dir"] / filename
            path.write_bytes(path.read_bytes() + b" ")
        return child

    wrap_children(monkeypatch, wrapper)
    with pytest.raises(ValueError):
        await execute(case)
    assert case.counts == ([6, 0, 0], [6, 3, 0], [6, 3, 3])[stage]
    assert not (case.root / "result.json").exists()
    assert case.ledger.snapshot().spent_usd == Decimal("0.01") * sum(case.counts)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
@pytest.mark.parametrize("target", ["root", "child"])
async def test_cancellation_does_not_adopt_byte_identical_replacement_directories(
    tmp_path, stage, target
):
    case = execution_case(tmp_path)
    entered = asyncio.Event()

    async def stalled(role, ordinal, _request):
        if role == stage and ordinal == 1:
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(execute(case, custom=stalled))
    try:
        await asyncio.wait_for(entered.wait(), timeout=10)
        active = tuple(
            e for e in case.ledger.snapshot().entries if e.status is CostEntryStatus.RESERVED
        )
        assert len(active) == 1
        active_request_id = active[0].request_id
        original = case.root if target == "root" else case.root / STAGES[stage]
        preserved = original.with_name(original.name + "-preserved")
        original.rename(preserved)
        shutil.copytree(preserved, original)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert case.counts == ([1, 0, 0], [6, 1, 0], [6, 3, 1])[stage]
    assert not (case.root / "result.json").exists()
    entries = {e.request_id: e for e in case.ledger.snapshot().entries}
    assert entries[active_request_id].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert entries[active_request_id].accounted_cost_usd == active[0].reserved_usd
    assert all(
        e.status is CostEntryStatus.RECONCILED
        for request_id, e in entries.items()
        if request_id != active_request_id
    )
