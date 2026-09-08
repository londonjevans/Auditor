"""Real local artifact/accounting handoffs with synthetic MockTransport; no live network or tools."""

from __future__ import annotations

import asyncio
import socket
import subprocess
from decimal import Decimal

import httpx
import pytest

from mmaudit.models.development_corpus_judgment import (
    DevelopmentCorpusJudgmentObservation,
    prepare_development_corpus_judgment,
)
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_judgment import run_development_corpus_judgment
from tests.development_corpus_judgment_support import (
    manifest_judgment_payload,
    selected_policy,
    selected_sources,
)
from tests.development_corpus_support import corpus_case, corpus_payload
from tests.development_judgment_support import judgment_metadata
from tests.development_review_support import SYNTHETIC_CREDENTIAL


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest review attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


async def candidate_inputs(
    tmp_path,
    *,
    count=4,
    claims=1,
    fail_at=None,
    carry=False,
    run_seconds=600,
    timeout=None,
    policy=None,
):
    sources = selected_sources(count)
    policy = selected_policy(carry=carry, timeout=timeout) if policy is None else policy
    original = corpus_case(source_files=sources, policy=policy)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "synthetic-ledger.json", cap_usd=policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    calls = []
    counts = (claims,) * count if isinstance(claims, int) else claims

    def handler(request):
        calls.append(request)
        if len(calls) == fail_at:
            return httpx.Response(429, json={"error": {"message": "synthetic rate limit"}})
        return httpx.Response(200, json=corpus_payload(len(calls), count=counts[len(calls) - 1]))

    candidate = await run_development_corpus(
        prepared=original,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "candidate",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    prepared = prepare_development_corpus_judgment(
        candidate=candidate,
        policy=policy,
        endpoint_snapshot=judgment_metadata(),
        source_files=sources,
        run_id="executed-manifest-judgment",
        maximum_run_seconds=run_seconds,
    )
    return prepared, ledger, secrets


async def execute(prepared, ledger, secrets, output_dir, handler, **extra):
    return await run_development_corpus_judgment(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=output_dir,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        **extra,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [0, 1, 16])
async def test_full_fourteen_file_candidate_to_review_preserves_sources_opinions_and_accounting(
    tmp_path, claims
):
    prepared, ledger, secrets = await candidate_inputs(
        tmp_path, count=14, claims=claims, timeout=360
    )
    old_files = {p.name: p.read_bytes() for p in (tmp_path / "candidate").iterdir()}
    old_entries = ledger.snapshot().entries
    calls = []

    def handler(request):
        index = len(calls)
        calls.append(request)
        assert request.content == prepared.shards[index].request_content
        assert request.extensions["timeout"]["read"] == 360
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        verdict = ("SUPPORTED", "REFUTED", "INCONCLUSIVE")[index % 3]
        return httpx.Response(
            200,
            json=manifest_judgment_payload(
                index + 1, shard_id=prepared.shards[index].shard_id, count=claims, verdict=verdict
            ),
        )

    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert len(calls) == (14 if claims else 0)
    assert result.status == ("OBSERVED_ALL_JUDGMENTS" if claims else "NO_CANDIDATES")
    assert result.completed_judgment_count == 14 * claims
    assert result.plan.candidate == prepared.plan.candidate
    assert not result.unreviewed_claim_ids and not result.unobserved_candidate_shard_ids
    assert (
        result.combined_accounted_cost_usd
        == ledger.snapshot().spent_usd
        == Decimal("0.28" if claims else "0.14")
    )
    assert all(e in ledger.snapshot().entries for e in old_entries)
    assert old_files == {p.name: p.read_bytes() for p in (tmp_path / "candidate").iterdir()}
    assert (tmp_path / "review/sources.json").read_bytes() == old_files["sources.json"]
    assert (
        DevelopmentCorpusJudgmentObservation.model_validate_json(
            (tmp_path / "review/result.json").read_bytes(), strict=True
        )
        == result
    )
    assert (
        not result.audit_complete
        and not result.findings_validated
        and not result.qualification_eligible
        and not result.release_eligible
    )
    assert (tmp_path / "review").stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (tmp_path / "review").iterdir())
    assert not (tmp_path / "review/score.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("carry", [False, True])
async def test_partial_candidate_keeps_original_429_liability_and_missing_source_scope(
    tmp_path, carry
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, fail_at=3, carry=carry)
    original_entries = ledger.snapshot().entries
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=manifest_judgment_payload(len(calls)))

    if not carry:
        with pytest.raises(ValueError):
            await execute(prepared, ledger, secrets, tmp_path / "review", handler)
        assert not calls and ledger.snapshot().entries == original_entries
        assert not (tmp_path / "review").exists()
        return
    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert len(calls) == 2 and result.completed_judgment_count == 2
    assert result.status == "INCOMPLETE" and result.stop_reason == "CANDIDATE_INCOMPLETE"
    assert result.unobserved_candidate_shard_ids == ("file-0003", "file-0004")
    assert not result.unreviewed_claim_ids
    assert result.plan.candidate.status == "INCOMPLETE"
    assert all(e in ledger.snapshot().entries for e in original_entries)
    assert (
        sum(e.status is CostEntryStatus.UNCERTAIN_ACCOUNTED for e in ledger.snapshot().entries) == 1
    )
    assert (
        result.combined_accounted_cost_usd
        == prepared.plan.candidate.total_accounted_cost_usd + Decimal("0.02")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("position", [1, 2, 4])
@pytest.mark.parametrize("known", [False, True])
async def test_first_middle_last_review_failure_preserves_missing_claims_and_charges(
    tmp_path, position, known
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == position:
            return httpx.Response(500, json={"usage": {"cost": 0.01}} if known else {"error": {}})
        return httpx.Response(200, json=manifest_judgment_payload(len(calls)))

    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert len(calls) == len(result.accounting) == position
    assert result.status == "INCOMPLETE" and result.stop_reason == "JUDGMENT_INCOMPLETE"
    assert len(result.unreviewed_claim_ids) == 5 - position
    assert result.accounting[-1].status is (
        CostEntryStatus.RECONCILED if known else CostEntryStatus.UNCERTAIN_ACCOUNTED
    )
    assert len(ledger.snapshot().entries) == 4 + position


@pytest.mark.asyncio
async def test_parent_deadline_preserves_one_unreturned_uncertain_attempt(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, run_seconds=0.02, timeout=360)
    calls = []

    async def stalled(request):
        calls.append(request)
        await asyncio.Event().wait()

    result = await asyncio.wait_for(
        execute(prepared, ledger, secrets, tmp_path / "review", stalled), timeout=3
    )
    assert result.status == "INCOMPLETE" and len(calls) == 1
    assert (
        len(result.accounting) == 1
        and result.accounting[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    )
    assert len(result.unreviewed_claim_ids) == 4


@pytest.mark.asyncio
async def test_cancellation_propagates_after_durable_original_and_review_accounting(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    entered = asyncio.Event()

    async def stalled(_request):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(execute(prepared, ledger, secrets, tmp_path / "review", stalled))
    await asyncio.wait_for(entered.wait(), timeout=3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(ledger.snapshot().entries) == 5
    result = DevelopmentCorpusJudgmentObservation.model_validate_json(
        (tmp_path / "review/result.json").read_bytes(), strict=True
    )
    assert (
        result.stop_reason == "INTERRUPTED"
        and result.accounting[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    )
