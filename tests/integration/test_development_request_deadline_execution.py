"""Actual local deadline/cancellation behavior; no live HTTP, credentials or source execution."""

from __future__ import annotations

import asyncio
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

import mmaudit.models.development_transport as transport_module
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_judgment import prepare_development_judgment
from mmaudit.models.development_review import prepare_development_review
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_audit import run_development_audit
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_ensemble import run_development_ensemble
from mmaudit.orchestration.development_judgment import run_development_judgment
from tests.development_audit_support import audit_case, shard_payload
from tests.development_benchmark_support import scored_file_response, scored_payload
from tests.development_corpus_support import corpus_case, corpus_payload, supplied_sources
from tests.development_ensemble_support import ensemble_case, ensemble_payload
from tests.development_judgment_support import judgment_payload
from tests.development_review_support import (
    SYNTHETIC_CREDENTIAL,
    local_controls,
    response_payload,
    review_case,
)
from tests.integration.test_development_judgment_execution import candidate_inputs
from tests.unit.test_development_request_deadlines import deadline_policy, scored_deadline_case

FAMILIES = ("fixture", "audit_v1", "audit_v2", "manifest", "judgment", "ensemble")


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("development deadline test attempted actual network or subprocess")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


async def execution(tmp_path, family, *, selected=360, run_seconds=600):
    policy = deadline_policy(selected)
    if family == "judgment":
        old, ledger, secrets = await candidate_inputs(tmp_path)
        prepared = prepare_development_judgment(
            candidate=old.plan.candidate,
            policy=policy,
            endpoint_snapshot=old.endpoint_snapshot,
            source_files=old.source_files,
            run_id=old.plan.run_id,
        )
        function, payload, count = run_development_judgment, judgment_payload, 3
    else:
        ledger, secrets = local_controls(tmp_path)
        if family == "fixture":
            old = review_case()
            prepared = prepare_development_review(
                policy=policy,
                endpoint_snapshot=old.endpoint_snapshot,
                source_filename=old.source_filename,
                source_content=old.source_content,
                request_id=old.estimate.request_id,
            )
            function, payload, count = (
                transport_module.review_development_fixture,
                lambda _: response_payload(),
                1,
            )
        elif family in {"audit_v1", "audit_v2"}:
            prepared = (audit_case if family == "audit_v1" else scored_deadline_case)(policy=policy)
            function, payload, count = (
                run_development_audit,
                shard_payload
                if family == "audit_v1"
                else lambda index: scored_payload(index, response=scored_file_response(index)),
                3,
            )
        elif family == "manifest":
            prepared = corpus_case(
                policy=policy, source_files=supplied_sources()[:4], maximum_run_seconds=run_seconds
            )
            function, payload, count = run_development_corpus, corpus_payload, 4
        else:
            assert family == "ensemble"
            prepared = ensemble_case(policy=policy, maximum_run_seconds=run_seconds)
            function, payload, count = (
                run_development_ensemble,
                lambda index: ensemble_payload((index - 1) // 3, (index - 1) % 3 + 1),
                9,
            )
    kwargs = dict(
        prepared=prepared, ledger=ledger, operator_secrets=secrets, allow_code_egress=True
    )
    if family != "fixture":
        kwargs["output_dir"] = tmp_path / "run"
    if family in {"audit_v1", "audit_v2", "judgment"}:
        kwargs["maximum_run_seconds"] = run_seconds

    async def execute(handler):
        return await function(**kwargs, mock_transport=httpx.MockTransport(handler))

    return execute, payload, count, ledger, kwargs


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("selected", [None, 360])
async def test_selected_timeout_reaches_every_request_and_outlasts_scaled_default(
    tmp_path, monkeypatch, family, selected
):
    execute, payload, count, ledger, _ = await execution(tmp_path, family, selected=selected)
    initial_ids = {e.request_id for e in ledger.snapshot().entries}
    monkeypatch.setattr(transport_module, "DEVELOPMENT_ATTEMPT_TIMEOUT_SECONDS", 0.01)
    calls = []

    async def handler(request):
        calls.append(request)
        expected = 0.01 if selected is None else selected
        assert request.extensions["timeout"] == {
            "read": expected,
            "write": expected,
            "connect": min(10, expected),
            "pool": min(10, expected),
        }
        await asyncio.sleep(0.03)
        return httpx.Response(200, json=payload(len(calls)))

    result = await asyncio.wait_for(execute(handler), timeout=8)
    new = [e for e in ledger.snapshot().entries if e.request_id not in initial_ids]
    assert len(calls) == len(new) == (1 if selected is None else count)
    if selected is None:
        assert result.status == "INCOMPLETE"
        assert new[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    else:
        assert result.status in {
            "OBSERVED",
            "OBSERVED_ALL_SHARDS",
            "OBSERVED_ALL_JUDGMENTS",
            "OBSERVED_ALL_STAGES",
        }
        assert all(e.status is CostEntryStatus.RECONCILED for e in new)
        assert '"request_timeout_seconds":360' in result.model_dump_json()
    assert not result.qualification_eligible and not result.release_eligible


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES)
async def test_actual_one_second_request_timeout_preserves_one_unknown_charge_and_does_not_retry(
    tmp_path, family
):
    execute, _, _, ledger, _ = await execution(tmp_path, family, selected=1, run_seconds=5)
    initial = {e.request_id for e in ledger.snapshot().entries}
    calls = []

    async def stalled(request):
        calls.append(request)
        await asyncio.Event().wait()

    result = await asyncio.wait_for(execute(stalled), timeout=4)
    new = [e for e in ledger.snapshot().entries if e.request_id not in initial]
    assert result.status == "INCOMPLETE" and len(calls) == len(new) == 1
    assert new[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert new[0].actual_cost_usd is None and new[0].accounted_cost_usd == new[0].reserved_usd > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES[1:])
async def test_parent_deadline_wins_over_selected_1800_second_attempt_without_reset(
    tmp_path, family
):
    execute, _, _, ledger, _ = await execution(tmp_path, family, selected=1800, run_seconds=1)
    initial = {e.request_id for e in ledger.snapshot().entries}
    calls = []

    async def stalled(request):
        calls.append(request)
        assert request.extensions["timeout"]["read"] == 1800
        await asyncio.Event().wait()

    result = await asyncio.wait_for(execute(stalled), timeout=4)
    new = [e for e in ledger.snapshot().entries if e.request_id not in initial]
    assert result.status == "INCOMPLETE" and len(calls) == len(new) == 1
    assert new[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert '"request_timeout_seconds":1800' in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES)
async def test_explicit_cancellation_still_propagates_and_keeps_selected_attempt_liability(
    tmp_path, family
):
    execute, _, _, ledger, _ = await execution(tmp_path, family, selected=1800)
    initial = {e.request_id for e in ledger.snapshot().entries}
    entered = asyncio.Event()

    async def stalled(_request):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(execute(stalled))
    await asyncio.wait_for(entered.wait(), timeout=4)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    new = [e for e in ledger.snapshot().entries if e.request_id not in initial]
    assert len(new) == 1 and new[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED


@pytest.mark.asyncio
@pytest.mark.parametrize("family", ["audit_v1", "audit_v2", "manifest", "judgment"])
async def test_plan_and_shard_timeout_mismatch_refuses_before_another_dispatch(tmp_path, family):
    execute, _, _, ledger, kwargs = await execution(tmp_path, family)
    original = kwargs["prepared"]
    first = original.shards[0]
    changed = first.estimate.model_copy(update={"policy": deadline_policy(1)})
    kwargs["prepared"] = replace(
        original, shards=(replace(first, estimate=changed), *original.shards[1:])
    )
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("changed frozen timeout reached dispatch")

    with pytest.raises(ValueError):
        await execute(forbidden)
    assert ledger.path.read_bytes() == before and not (tmp_path / "run").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("family", FAMILIES[1:])
async def test_completed_request_does_not_reset_remaining_parent_budget(tmp_path, family):
    execute, payload, _, ledger, _ = await execution(tmp_path, family, selected=360, run_seconds=1)
    initial = {e.request_id for e in ledger.snapshot().entries}
    calls = []

    async def slow(request):
        calls.append(request)
        await asyncio.sleep(0.65)
        return httpx.Response(200, json=payload(len(calls)))

    result = await asyncio.wait_for(execute(slow), timeout=4)
    new = [e for e in ledger.snapshot().entries if e.request_id not in initial]
    assert result.status == "INCOMPLETE" and len(calls) == len(new) == 2
    assert sum(e.status is CostEntryStatus.RECONCILED for e in new) == 1
    assert sum(e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED for e in new) == 1
    assert sum(e.actual_cost_usd is None for e in new) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "family,failure_index",
    [
        ("manifest", 1),
        ("manifest", 2),
        ("manifest", 4),
        ("ensemble", 1),
        ("ensemble", 5),
        ("ensemble", 9),
    ],
)
async def test_first_middle_last_timeout_keeps_prior_charges_without_retry(
    tmp_path, family, failure_index
):
    execute, payload, _, ledger, _ = await execution(tmp_path, family, selected=1, run_seconds=30)
    initial = {e.request_id for e in ledger.snapshot().entries}
    calls = []

    async def handler(request):
        calls.append(request)
        if len(calls) == failure_index:
            await asyncio.Event().wait()
        return httpx.Response(200, json=payload(len(calls)))

    result = await asyncio.wait_for(execute(handler), timeout=5)
    new = [e for e in ledger.snapshot().entries if e.request_id not in initial]
    assert result.status == "INCOMPLETE" and len(calls) == len(new) == failure_index
    assert sum(e.status is CostEntryStatus.RECONCILED for e in new) == failure_index - 1
    unknown = [e for e in new if e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED]
    assert len(unknown) == 1 and unknown[0].actual_cost_usd is None
    assert unknown[0].accounted_cost_usd == unknown[0].reserved_usd > 0


@pytest.mark.asyncio
async def test_attempt_deadline_covers_stream_body_and_closes_after_timeout(tmp_path):
    execute, _, _, ledger, _ = await execution(tmp_path, "fixture", selected=1)
    closed = False
    calls = []

    class StalledBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"{"
            await asyncio.Event().wait()

        async def aclose(self):
            nonlocal closed
            closed = True

    async def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=StalledBody())

    result = await asyncio.wait_for(execute(handler), timeout=4)
    entries = ledger.snapshot().entries
    assert result.status == "INCOMPLETE" and closed and len(calls) == len(entries) == 1
    assert entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert entries[0].actual_cost_usd is None


@pytest.mark.asyncio
async def test_selected_deadline_consumes_existing_19_file_synthetic_source_snapshot(
    tmp_path, monkeypatch
):
    root = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    names = (
        "src/core/Interfaces.sol",
        "src/core/ProtocolRegistry.sol",
        "src/core/SyntheticFixtureOnly.sol",
        "src/core/SyntheticProxies.sol",
        *(f"src/markets/SyntheticMarket{index:03d}.sol" for index in range(15)),
    )
    sources = tuple((name, (root / name).read_bytes()) for name in names)
    assert len(sources) == 19
    assert sum(len(content) for _, content in sources) == 175158
    assert sum(len(content.splitlines()) for _, content in sources) == 4952
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("250"),
        per_attempt_budget_usd=Decimal("5"),
        request_timeout_seconds=360,
    )
    prepared = corpus_case(source_files=sources, policy=policy)
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    monkeypatch.setattr(transport_module, "DEVELOPMENT_ATTEMPT_TIMEOUT_SECONDS", 0.01)
    calls = []

    async def handler(request):
        calls.append(request)
        assert request.extensions["timeout"]["read"] == 360
        await asyncio.sleep(0.03)
        return httpx.Response(200, json=corpus_payload(len(calls), count=0))

    result = await asyncio.wait_for(
        run_development_corpus(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        ),
        timeout=30,
    )
    assert result.status == "OBSERVED_ALL_SHARDS" and len(calls) == 19
    assert (
        result.selected_primary_line_count == result.primary_lines_with_observed_responses == 4952
    )
    assert not result.unobserved_shard_ids
    assert not result.audit_complete and not result.qualification_eligible
    assert not result.release_eligible
    assert len(ledger.snapshot().entries) == 19
    assert all(e.status is CostEntryStatus.RECONCILED for e in ledger.snapshot().entries)
