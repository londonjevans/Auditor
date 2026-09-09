"""Actual local candidate-to-continuation execution with synthetic transport and trapped egress."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import shutil
import socket
import subprocess
from dataclasses import dataclass, field, replace
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

from mmaudit.models.development_corpus_resume import DevelopmentCorpusResumeHistory
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    PortfolioAttemptSlot,
)
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_resume import (
    read_development_corpus_resume_inputs,
    run_development_corpus_resume,
)
from tests.development_corpus_judgment_support import selected_policy, selected_sources
from tests.development_corpus_resume_support import selected_resume
from tests.development_corpus_support import corpus_case, corpus_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("continuation attempted actual network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@dataclass
class Case:
    root: Path
    original_prepared: object
    original: object
    ledger: AtomicCostLedger
    secrets: OperatorSecrets
    inputs: object
    prepared: object
    prior_bytes: dict[Path, bytes]
    calls: list[tuple[str, str]] = field(default_factory=list)


async def execution_case(
    tmp_path,
    *,
    count=4,
    claims=1,
    failure="known",
    carry=False,
    maximum_run_seconds=600,
    source_files=None,
    policy=None,
    endpoint_snapshot=None,
):
    policy = policy or selected_policy(
        carry=carry, total="250" if count == 64 else "20", per_attempt="4" if count == 64 else "1"
    )
    prepared = corpus_case(
        source_files=selected_sources(count) if source_files is None else source_files,
        policy=policy,
        maximum_run_seconds=maximum_run_seconds,
        **({"endpoint_snapshot": endpoint_snapshot} if endpoint_snapshot is not None else {}),
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "synthetic-ledger.json", cap_usd=policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    original_calls = []

    def handler(request):
        original_calls.append(request.content)
        ordinal = len(original_calls)
        assert request.content == prepared.shards[ordinal - 1].request_content
        if ordinal == 2 and failure == "unknown":
            return httpx.Response(429, json={"error": {"message": "synthetic unreturned usage"}})
        payload = corpus_payload(ordinal, count=claims)
        if ordinal == 2:
            payload["choices"][0]["message"]["content"] = "{}"
        return httpx.Response(200, json=payload)

    original = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "original",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert original.status == "INCOMPLETE" and original.completed_shard_count == 1
    assert len(original_calls) == 2
    prior_bytes = {p: p.read_bytes() for p in (tmp_path / "original").iterdir()}
    inputs = read_development_corpus_resume_inputs(
        candidate_file=tmp_path / "original/result.json",
        material_file=tmp_path / "original/sources.json",
    )
    first = prepared.shards[0]
    selected = selected_resume(inputs.history, first.discovery or first.endpoint_snapshot)
    return Case(tmp_path, prepared, original, ledger, secrets, inputs, selected, prior_bytes)


async def execute(case, *, prepared=None, inputs=None, custom=None, output_dir=None, **changes):
    selected = case.prepared if prepared is None else prepared
    local_calls = []

    async def handler(request):
        shard = next(s for s in selected.candidate.shards if s.request_content == request.content)
        local_calls.append(shard.shard_id)
        case.calls.append((selected.plan.candidate.run_id, shard.shard_id))
        assert shard.shard_id in selected.plan.selected_shard_ids
        assert shard.source_files == case.original_prepared.shards[0].source_files
        assert (
            request.content
            == case.original_prepared.shards[int(shard.shard_id[-4:]) - 1].request_content
        )
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        if custom is not None:
            response = custom(shard.shard_id, len(local_calls), request)
            if inspect.isawaitable(response):
                response = await response
            if response is not None:
                return response
        payload = corpus_payload(int(shard.shard_id[-4:]))
        payload["id"] = f"gen-{selected.plan.candidate.run_id}-{shard.shard_id}"
        return httpx.Response(200, json=payload)

    args = dict(
        prepared=selected,
        ledger=case.ledger,
        operator_secrets=case.secrets,
        output_dir=case.root / "resume" if output_dir is None else output_dir,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        inputs=case.inputs if inputs is None else inputs,
    )
    args.update(changes)
    return await run_development_corpus_resume(**args)


@pytest.mark.asyncio
async def test_real_incomplete_candidate_continues_only_missing_sources_and_keeps_every_charge(
    tmp_path,
):
    case = await execution_case(tmp_path)
    before = case.ledger.snapshot().entries
    result = await execute(case)
    assert [shard for _run, shard in case.calls] == ["file-0002", "file-0003", "file-0004"]
    assert result.original == case.original
    assert result.summary.cumulative_completed_shard_count == 4
    assert result.summary.original_first_attempt_completed_shard_count == 1
    assert result.summary.candidate_claim_count == 4
    assert result.summary.total_accounted_cost_usd == Decimal("0.05")
    assert result.summary.accounted_request_count == 5
    assert result.summary.status == "OBSERVED_ALL_SOURCES_ACROSS_RECORDED_ATTEMPTS"
    assert all(entry in case.ledger.snapshot().entries for entry in before)
    assert all(p.read_bytes() == raw for p, raw in case.prior_bytes.items())
    assert (
        DevelopmentCorpusResumeHistory.model_validate_json(
            (tmp_path / "resume/result.json").read_bytes(), strict=True
        )
        == result
    )
    assert (tmp_path / "resume").stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (tmp_path / "resume").iterdir())
    assert not result.audit_complete and not result.qualification_eligible


@pytest.mark.asyncio
async def test_headroom_covers_only_unresolved_requests_while_prior_unrelated_spend_is_retained(
    tmp_path,
):
    case = await execution_case(tmp_path)
    selected = case.prepared.plan.estimated_continuation_cost_usd
    full = case.prepared.plan.candidate.estimated_total_cost_usd
    remaining = (selected + (full - selected) / 2).quantize(Decimal("0.000000000000000001"))
    spent = case.ledger.snapshot().remaining_usd - remaining
    reservation = case.ledger.reserve("synthetic-unrelated-earlier-work", spent)
    case.ledger.reconcile(reservation, spent)
    assert selected < case.ledger.snapshot().remaining_usd < full
    result = await execute(case)
    assert result.summary.total_accounted_cost_usd == Decimal("0.05")
    assert case.ledger.snapshot().spent_usd == spent + Decimal("0.05")
    assert result.summary.cumulative_completed_shard_count == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("carry", [False, True])
async def test_unknown_original_cost_is_never_made_free_by_continuation(tmp_path, carry):
    case = await execution_case(tmp_path, failure="unknown", carry=carry)
    original = case.ledger.path.read_bytes()
    if not carry:
        with pytest.raises(ValueError):
            await execute(case)
        assert not case.calls and not (tmp_path / "resume").exists()
        assert case.ledger.path.read_bytes() == original
        return
    result = await execute(case)
    assert (
        result.summary.uncertain_accounted_cost_usd
        == case.original.uncertain_accounted_cost_usd
        > 0
    )
    assert result.summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert result.original == case.original and result.summary.cumulative_completed_shard_count == 4


@pytest.mark.asyncio
async def test_a_second_explicit_stage_keeps_all_earlier_failure_and_first_attempt_evidence(
    tmp_path,
):
    case = await execution_case(tmp_path, carry=True)

    def fail_second(_shard, ordinal, _request):
        if ordinal == 2:
            return httpx.Response(429, json={"error": {"message": "synthetic unknown usage"}})

    partial = await execute(case, custom=fail_second)
    assert partial.summary.status == "INCOMPLETE"
    assert partial.summary.cumulative_completed_shard_count == 2
    inputs = read_development_corpus_resume_inputs(history_file=tmp_path / "resume/result.json")
    first = case.original_prepared.shards[0]
    prepared = selected_resume(inputs.history, first.discovery or first.endpoint_snapshot)
    assert prepared.plan.selected_shard_ids == ("file-0003", "file-0004")
    result = await execute(
        case, prepared=prepared, inputs=inputs, output_dir=tmp_path / "resume-two"
    )
    assert result.continuations[0] == partial.continuations[0]
    assert result.original == case.original
    assert result.summary.cumulative_completed_shard_count == 4
    assert result.summary.continuation_count == 2
    assert result.summary.accounted_request_count == 6
    assert result.summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert (
        result.summary.uncertain_accounted_cost_usd == partial.summary.uncertain_accounted_cost_usd
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "replay",
        "cap",
        "prior_missing",
        "prior_changed",
        "active",
        "portfolio",
        "headroom",
        "consent",
        "transport",
        "prepared",
        "input_history",
    ],
)
async def test_preflight_cannot_reset_or_bypass_history_cost_identity_and_custody(tmp_path, kind):
    case = await execution_case(tmp_path)
    changes = {}
    if kind == "replay":
        await execute(case)
        case.calls.clear()
        changes["output_dir"] = tmp_path / "replay"
    elif kind == "cap":
        changes["ledger"] = AtomicCostLedger.initialize(
            tmp_path / "wrong-ledger.json", cap_usd=Decimal("21")
        )
    elif kind.startswith("prior_"):
        data = json.loads(case.ledger.path.read_bytes())
        key = case.original.accounting[0].ledger_request_id
        if kind == "prior_missing":
            del data["entries"][key]
        else:
            data["entries"][key]["reservation_id"] = "0" * 32
        case.ledger.path.write_text(json.dumps(data))
    elif kind in {"active", "headroom"}:
        amount = (
            (
                case.ledger.snapshot().remaining_usd
                - case.prepared.plan.estimated_continuation_cost_usd / 2
            ).quantize(Decimal("0.000000000000000001"))
            if kind == "headroom"
            else Decimal("1")
        )
        reservation = case.ledger.reserve("synthetic-unrelated", amount)
        if kind == "headroom":
            case.ledger.reconcile(reservation, amount)
    elif kind == "portfolio":
        case.ledger.reserve_portfolio(
            "b" * 64, (PortfolioAttemptSlot("synthetic-held", Decimal("1")),)
        )
    elif kind == "consent":
        changes["allow_code_egress"] = False
    elif kind == "transport":
        changes["mock_transport"] = None
    elif kind == "prepared":
        shard = case.prepared.candidate.shards[0]
        candidate = replace(
            case.prepared.candidate,
            shards=(
                replace(shard, request_content=shard.request_content + b" "),
                *case.prepared.candidate.shards[1:],
            ),
        )
        changes["prepared"] = replace(case.prepared, candidate=candidate)
    elif kind == "input_history":
        changes["inputs"] = replace(
            case.inputs, history=case.inputs.history.model_copy(update={"history_sha256": "0" * 64})
        )
    before = case.ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await execute(case, **changes)
    assert not case.calls and case.ledger.path.read_bytes() == before
    assert not (tmp_path / ("replay" if kind == "replay" else "resume")).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("prior", [0, 1])
async def test_original_success_or_failed_generation_cannot_be_reused_as_fresh_response(
    tmp_path, prior
):
    case = await execution_case(tmp_path)

    def duplicate(shard, _ordinal, _request):
        payload = corpus_payload(int(shard[-4:]))
        payload["id"] = case.original.observations[prior].generation_id
        return httpx.Response(200, json=payload)

    result = await execute(case, custom=duplicate)
    assert len(case.calls) == 1
    assert result.continuations[0].observations[0].response is None
    assert result.summary.cumulative_completed_shard_count == 1
    assert result.summary.total_accounted_cost_usd == Decimal("0.03")
    assert result.summary.status == "INCOMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target", ["input_file", "input_directory", "output_file", "output_directory", "ledger"]
)
async def test_mid_request_drift_cannot_be_adopted_even_when_replacement_bytes_match(
    tmp_path, target
):
    case = await execution_case(tmp_path)

    def replace_original(_shard, _ordinal, _request):
        if target == "ledger":
            data = json.loads(case.ledger.path.read_bytes())
            del data["entries"][case.original.accounting[0].ledger_request_id]
            case.ledger.path.write_text(json.dumps(data))
            return
        path = {
            "input_file": tmp_path / "original/result.json",
            "input_directory": tmp_path / "original",
            "output_file": tmp_path / "resume/prior-history.json",
            "output_directory": tmp_path / "resume",
        }[target]
        preserved = path.with_name(path.name + "-preserved")
        path.rename(preserved)
        if target.endswith("directory"):
            shutil.copytree(preserved, path)
        else:
            path.write_bytes(preserved.read_bytes())
            path.chmod(0o600)

    with pytest.raises(ValueError):
        await execute(case, custom=replace_original)
    assert len(case.calls) == 1
    assert not (tmp_path / "resume/result.json").exists()
    assert case.ledger.snapshot().spent_usd >= Decimal("0.02")


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["cancel", "timeout"])
async def test_interruption_retains_the_unreturned_new_charge_and_original_first_attempt(
    tmp_path, kind
):
    case = await execution_case(tmp_path, maximum_run_seconds=2)
    entered = asyncio.Event()

    async def stalled(_shard, _ordinal, _request):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(execute(case, custom=stalled))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        if kind == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=8)
        else:
            await asyncio.wait_for(task, timeout=8)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    result = DevelopmentCorpusResumeHistory.model_validate_json(
        (tmp_path / "resume/result.json").read_bytes(), strict=True
    )
    assert result.original == case.original and len(case.calls) == 1
    stage = result.continuations[0]
    assert not stage.observations and len(stage.accounting) == 1
    assert stage.accounting[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert result.summary.cumulative_completed_shard_count == 1 and not result.audit_complete


@pytest.mark.asyncio
async def test_maximum_scope_continuation_reuses_one_response_and_retains_all_sixty_four_sources(
    tmp_path,
    monkeypatch,
):
    import mmaudit.orchestration.development_corpus_resume as resume

    refusals = []

    def observed_guard(name):
        guard = getattr(resume, name)

        def checked(*args, **kwargs):
            try:
                return guard(*args, **kwargs)
            except Exception as exc:
                refusals.append((name, type(exc).__name__, str(exc)))
                raise

        return checked

    for name in (
        "_require_file",
        "_write",
        "require_same_unlinked_directory_objects",
        "validate_development_accounting_entries",
    ):
        monkeypatch.setattr(resume, name, observed_guard(name))
    case = await execution_case(tmp_path, count=64, claims=16)

    def maximum(shard, _ordinal, _request):
        payload = corpus_payload(int(shard[-4:]), count=16)
        payload["id"] = f"gen-synthetic-maximum-resume-{shard}"
        return httpx.Response(200, json=payload)

    try:
        result = await execute(case, custom=maximum)
    except Exception:
        assert not refusals, refusals
        raise
    assert len(case.calls) == 63, refusals
    assert result.summary.cumulative_completed_shard_count == 64
    assert result.summary.candidate_claim_count == 1024
    assert result.summary.accounted_request_count == 65
    assert result.summary.original_first_attempt_completed_shard_count == 1
    assert result.summary.total_accounted_cost_usd == Decimal("0.65")
    assert result.material == case.inputs.history.material and not result.audit_complete


@pytest.mark.asyncio
async def test_realistic_nineteen_file_continuation_never_shrinks_original_context(tmp_path):
    root = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    manifest = json.loads((root / "fixture-manifest.json").read_bytes())
    records = tuple(row for row in manifest["files"] if row["path"].endswith(".sol"))
    expected_names = tuple(
        sorted(
            (
                *(
                    "src/core/" + name
                    for name in (
                        "Interfaces.sol",
                        "ProtocolRegistry.sol",
                        "SyntheticFixtureOnly.sol",
                        "SyntheticProxies.sol",
                    )
                ),
                *(f"src/markets/SyntheticMarket{index:03d}.sol" for index in range(15)),
            )
        )
    )
    assert tuple(row["path"] for row in records) == expected_names
    sources = tuple((row["path"], (root / row["path"]).read_bytes()) for row in records)
    assert len(sources) == 19 and sum(len(raw) for _, raw in sources) == 175158
    assert sum(len(raw.decode().splitlines()) for _, raw in sources) == 4952
    assert all(
        hashlib.sha256(raw).hexdigest() == row["sha256"]
        for (_, raw), row in zip(sources, records, strict=True)
    )
    case = await execution_case(
        tmp_path, source_files=sources, policy=selected_policy(total="250", per_attempt="4")
    )
    result = await execute(case)
    assert len(case.calls) == 18
    assert result.summary.cumulative_completed_shard_count == 19
    assert result.summary.original_first_attempt_completed_shard_count == 1
    assert result.summary.primary_lines_with_observed_responses == 4952
    assert result.material.source_files == sources
    assert result.summary.accounted_request_count == 20
    assert result.summary.total_accounted_cost_usd == Decimal("0.20")
    assert result.original_score is None
    assert all(p.read_bytes() == raw for p, raw in case.prior_bytes.items())
    assert not result.audit_complete and not result.qualification_eligible


@pytest.mark.asyncio
@pytest.mark.parametrize("filename", ["attempt.json", "result.json"])
async def test_derivative_writer_failure_cannot_erase_new_costs_or_return_success(
    tmp_path, monkeypatch, filename
):
    import mmaudit.orchestration.development_corpus_resume as resume

    case = await execution_case(tmp_path)
    writer = resume._write

    def refuse(root, name, model):
        if name == filename:
            raise ValueError("synthetic derivative evidence writer refusal")
        return writer(root, name, model)

    monkeypatch.setattr(resume, "_write", refuse)
    with pytest.raises(ValueError, match="could not be finalized"):
        await execute(case)
    assert len(case.calls) == 3 and case.ledger.snapshot().spent_usd == Decimal("0.05")
    assert all(p.read_bytes() == raw for p, raw in case.prior_bytes.items())
    assert not (tmp_path / "resume/result.json").exists()
    assert all((tmp_path / "resume" / f"file-{index:04d}.json").exists() for index in (2, 3, 4))


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["input", "output"])
async def test_permission_drift_during_request_is_not_adopted_after_a_paid_response(tmp_path, role):
    case = await execution_case(tmp_path)

    def mutate(_shard, _ordinal, _request):
        target = tmp_path / ("original/result.json" if role == "input" else "resume/plan.json")
        target.chmod(0o644)

    with pytest.raises(ValueError):
        await execute(case, custom=mutate)
    assert len(case.calls) == 1 and case.ledger.snapshot().spent_usd == Decimal("0.03")
    assert not (tmp_path / "resume/result.json").exists()
