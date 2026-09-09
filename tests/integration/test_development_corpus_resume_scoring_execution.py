"""Real local candidate/continuation/scoring execution using synthetic sources and MockTransport."""

from __future__ import annotations

import asyncio
import json
import socket
import stat
import subprocess

import httpx
import pytest

import mmaudit.orchestration.development_corpus_resume as continuation
from mmaudit.benchmark.development_corpus_resume import read_development_corpus_resume_score
from mmaudit.models.development_corpus_resume import DevelopmentCorpusResumeHistory
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_corpus import run_development_corpus
from tests.development_corpus_benchmark_support import paired_case, paired_payload, truth_binding
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_resume_support import selected_resume
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_resume_execution import Case, execute


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("cumulative scoring execution attempted actual network or subprocess access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


async def scored_case(
    tmp_path,
    *,
    failure="known",
    maximum_run_seconds=600,
    prepared=None,
    binding=None,
    responses=None,
    stop_ordinal=2,
):
    prepared = prepared or paired_case(
        policy=selected_policy(carry=True), maximum_run_seconds=maximum_run_seconds
    )
    binding = binding or truth_binding(prepared)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "synthetic-ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    calls = []

    def handler(request):
        calls.append(request.content)
        ordinal = len(calls)
        assert request.content == prepared.shards[ordinal - 1].request_content
        assert binding.truth_file_content.encode() not in request.content
        if ordinal == stop_ordinal and failure == "unknown":
            return httpx.Response(429, json={"error": {"message": "synthetic missing usage"}})
        payload = paired_payload(ordinal)
        if responses is not None:
            payload["choices"][0]["message"]["content"] = json.dumps(responses[ordinal - 1])
        if ordinal == stop_ordinal:
            payload["choices"][0]["message"]["content"] = "{}"
        return httpx.Response(200, json=payload)

    original = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "original",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_binding=binding,
    )
    assert len(calls) == stop_ordinal and original.completed_shard_count == stop_ordinal - 1
    prior_bytes = {p: p.read_bytes() for p in (tmp_path / "original").iterdir()}
    inputs = continuation.read_development_corpus_resume_inputs(
        candidate_file=tmp_path / "original/result.json",
        material_file=tmp_path / "original/sources.json",
        original_score_file=tmp_path / "original/score.json",
    )
    first = prepared.shards[0]
    selected = selected_resume(inputs.history, first.discovery or first.endpoint_snapshot)
    return Case(tmp_path, prepared, original, ledger, secrets, inputs, selected, prior_bytes)


def accepted_response(case, shard_id, _count, _request):
    payload = paired_payload(int(shard_id[-4:]))
    payload["id"] = "gen-" + case.prepared.plan.candidate.run_id + "-" + shard_id
    return httpx.Response(200, json=payload)


def read_score(case):
    return read_development_corpus_resume_score(
        (case.root / "resume/cumulative-score.json").read_bytes()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["known", "unknown"])
async def test_real_continuation_automatically_scores_without_new_calls_labels_or_costs(
    tmp_path, failure
):
    case = await scored_case(tmp_path, failure=failure)
    old = case.inputs.history.original_score
    before = case.ledger.snapshot().entries
    result = await execute(case, custom=lambda *a: accepted_response(case, *a))
    score = read_score(case)
    assert len(case.calls) == 5 and len(case.ledger.snapshot().entries) == 7
    assert score.history == result and result.original_score == old
    assert all(p.read_bytes() == raw for p, raw in case.prior_bytes.items())
    assert score.first_attempt_summary == old.summary
    assert score.first_attempt_summary.unique_root_recall.value is None
    assert score.cumulative_quality.unique_root_recall.value == 1.0
    assert score.cumulative_quality.total_claim_count == 3
    assert score.cumulative_quality.duplicate_claim_count == 2
    assert score.cumulative_summary.accounted_request_count == 7
    assert score.cumulative_summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert len(score.requests) == 11 and len(score.missing_accounting_request_ids) == 4
    assert len(score.unknown_actual_cost_request_ids) == int(failure == "unknown")
    assert all(e in case.ledger.snapshot().entries for e in before)
    assert stat.S_IMODE((case.root / "resume").stat().st_mode) == 0o700
    assert stat.S_IMODE((case.root / "resume/cumulative-score.json").stat().st_mode) == 0o600
    assert not score.audit_complete and not score.qualification_eligible
    assert SYNTHETIC_CREDENTIAL not in score.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["invalid", "cancel", "timeout"])
async def test_incomplete_and_interrupted_execution_keeps_score_scope_and_all_liabilities(
    tmp_path, stop
):
    case = await scored_case(tmp_path, maximum_run_seconds=2 if stop == "timeout" else 600)

    async def stopped(shard_id, count, request):
        if stop == "cancel":
            raise asyncio.CancelledError("synthetic selected interruption")
        if stop == "timeout":
            await asyncio.sleep(3)
        payload = paired_payload(int(shard_id[-4:]))
        payload["id"] = "gen-synthetic-invalid-resume"
        payload["choices"][0]["message"]["content"] = "{}"
        return httpx.Response(200, json=payload)

    if stop == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await execute(case, custom=stopped)
    else:
        await execute(case, custom=stopped)
    score = read_score(case)
    assert len(case.calls) == 1 and len(case.ledger.snapshot().entries) == 3
    assert score.cumulative_summary.status == "INCOMPLETE"
    assert score.cumulative_quality.unique_root_recall.value is None
    assert score.cumulative_quality.unique_root_recall.denominator == 1
    assert score.cumulative_shard_completion.numerator == 1
    assert score.cumulative_shard_completion.denominator == 6
    assert score.cumulative_summary.accounted_request_count == 3
    assert score.cumulative_summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert len(score.unknown_actual_cost_request_ids) == int(stop != "invalid")
    assert all(p.read_bytes() == raw for p, raw in case.prior_bytes.items())
    assert not score.audit_complete


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["writer", "bound", "score_bytes", "history_bytes"])
async def test_derivative_failure_never_returns_success_or_discards_durable_charges(
    tmp_path, monkeypatch, failure
):
    case = await scored_case(tmp_path)
    writer = continuation._write_cumulative_score

    def altered(*args, **kwargs):
        if failure == "writer":
            raise OSError("synthetic score write refusal")
        if failure == "history_bytes":
            (tmp_path / "resume/result.json").write_text("{}")
        result = writer(*args, **kwargs)
        if failure == "score_bytes":
            (tmp_path / "resume/cumulative-score.json").write_text("{}")
        return result

    monkeypatch.setattr(continuation, "_write_cumulative_score", altered)
    if failure == "bound":
        monkeypatch.setattr(continuation, "MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES", 1)
    with pytest.raises(ValueError, match="could not be finalized"):
        await execute(case, custom=lambda *a: accepted_response(case, *a))
    assert len(case.calls) == 5 and len(case.ledger.snapshot().entries) == 7
    assert (tmp_path / "resume/attempt.json").is_file()
    assert all(p.read_bytes() == raw for p, raw in case.prior_bytes.items())
    if failure != "history_bytes":
        history = DevelopmentCorpusResumeHistory.model_validate_json(
            (tmp_path / "resume/result.json").read_bytes(), strict=True
        )
        assert history.summary.accounted_request_count == 7
        assert history.original_score == case.inputs.history.original_score
        assert not history.audit_complete
    if failure != "score_bytes":
        assert not (tmp_path / "resume/cumulative-score.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "secondary", [ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError]
)
async def test_original_interruption_survives_secondary_scoring_failure(
    tmp_path, monkeypatch, secondary
):
    case = await scored_case(tmp_path)
    primary = asyncio.CancelledError("synthetic original interruption")

    def refuse(*_args, **_kwargs):
        raise secondary("synthetic secondary scoring failure")

    def cancelled(*_args):
        raise primary

    monkeypatch.setattr(continuation, "_write_cumulative_score", refuse)
    with pytest.raises(asyncio.CancelledError) as caught:
        await execute(case, custom=cancelled)
    assert caught.value is primary
    history = DevelopmentCorpusResumeHistory.model_validate_json(
        (tmp_path / "resume/result.json").read_bytes(), strict=True
    )
    assert history.summary.status == "INCOMPLETE" and history.summary.accounted_request_count == 3
    assert history.summary.uncertain_accounted_cost_usd > 0
    assert not (tmp_path / "resume/cumulative-score.json").exists()
