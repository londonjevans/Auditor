"""Maximum bounded synthetic continuation/scoring controls, not independent roots or live audits."""

from __future__ import annotations

import json
import socket
import subprocess
from decimal import Decimal

import httpx
import pytest

from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.benchmark.development_corpus_resume import (
    MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES,
    read_development_corpus_resume_score,
    score_development_corpus_resume,
)
from mmaudit.models.development_corpus import DevelopmentCorpusMaterial, DevelopmentCorpusText
from mmaudit.models.development_corpus_resume import freeze_development_corpus_resume_history
from mmaudit.orchestration.development_corpus_resume import read_development_corpus_resume_inputs
from mmaudit.orchestration.development_corpus_resume_score import (
    score_development_corpus_history_file,
)
from tests.development_corpus_benchmark_support import paired_payload
from tests.development_corpus_judgment_support import pure_candidate
from tests.development_corpus_resume_score_support import maximum_scoring_case
from tests.development_corpus_resume_support import append_attempt, pure_attempt, selected_resume
from tests.integration.test_development_corpus_resume_execution import execute
from tests.integration.test_development_corpus_resume_scoring_execution import scored_case


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("maximum cumulative scoring attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.asyncio
async def test_actual_maximum_history_scores_1024_claims_after_72_requests_and_retains_eight_unknowns(
    tmp_path,
):
    prepared, binding, responses = maximum_scoring_case()
    case = await scored_case(
        tmp_path,
        prepared=prepared,
        binding=binding,
        responses=responses,
        stop_ordinal=64,
        failure="unknown",
    )
    inputs = case.inputs
    metadata = prepared.shards[0].discovery or prepared.shards[0].endpoint_snapshot
    original_score_bytes = case.inputs.history.original_score.model_dump_json()
    for stage in range(1, 9):
        selected = selected_resume(inputs.history, metadata)
        output = tmp_path / f"stage-{stage}"

        def handler(shard_id, _count, _request, *, selected_stage=stage):
            assert shard_id == "file-0064"
            if selected_stage < 8:
                return httpx.Response(429, json={"error": {"message": "synthetic unknown cost"}})
            payload = paired_payload(64)
            payload["id"] = "gen-maximum-final-continuation"
            payload["choices"][0]["message"]["content"] = json.dumps(responses[-1])
            return httpx.Response(200, json=payload)

        history = await execute(
            case, prepared=selected, inputs=inputs, output_dir=output, custom=handler
        )
        score = read_development_corpus_resume_score(
            (output / "cumulative-score.json").read_bytes()
        )
        assert score.history == history
        assert score.history.original_score.model_dump_json() == original_score_bytes
        assert score.cumulative_quality.unique_root_recall.value == (1.0 if stage == 8 else None)
        inputs = read_development_corpus_resume_inputs(history_file=output / "result.json")
    assert len(case.calls) == 8 and len(case.ledger.snapshot().entries) == 72
    assert len(score.requests) == 72 and len(score.claims) == 1024
    assert len(score.unknown_actual_cost_request_ids) == 8
    assert not score.missing_accounting_request_ids and not score.missing_shard_runtime_request_ids
    assert score.cumulative_summary.accounted_request_count == 72
    assert score.cumulative_summary.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert score.cumulative_summary.reported_actual_cost_usd == Decimal("0.64")
    assert score.cumulative_summary.uncertain_accounted_cost_usd > 0
    assert score.cumulative_quality.severity_weighted_root_recall.numerator == 10_240
    assert score.cumulative_quality.severity_weighted_root_recall.denominator == 10_240
    assert score.first_attempt_summary.first_attempt_shard_completion.numerator == 63
    assert score.first_attempt_summary.unique_root_recall.value is None
    assert score.root_independence == "NOT_ESTABLISHED" and not score.audit_complete
    raw = (output / "result.json").read_bytes()
    padded = tmp_path / "synthetic-padded-history.json"
    padded.write_bytes(raw + b" " * (64_000_000 - len(raw)))
    offline = score_development_corpus_history_file(
        history_file=padded, output_dir=tmp_path / "offline"
    )
    assert offline == score and padded.stat().st_size == 64_000_000


def test_all_576_selected_planned_requests_remain_visible_without_observations():
    prepared, binding, _ = maximum_scoring_case()
    sources = prepared.shards[0].source_files
    _, original = pure_candidate(
        source_files=sources, policy=prepared.plan.policy, observed_count=0
    )
    history = freeze_development_corpus_resume_history(
        original=original,
        material=DevelopmentCorpusMaterial(
            manifest=original.plan.manifest,
            sources=tuple(
                DevelopmentCorpusText(filename=n, content=b.decode()) for n, b in sources
            ),
        ),
        original_score=score_development_corpus(binding=binding, observation=original),
    )
    metadata = prepared.shards[0].discovery or prepared.shards[0].endpoint_snapshot
    for _ in range(8):
        history = append_attempt(
            history, pure_attempt(selected_resume(history, metadata), observed_count=0)
        )
    score = score_development_corpus_resume(history=history)
    assert len(score.requests) == len(score.missing_accounting_request_ids) == 576
    assert len(score.missing_shard_runtime_request_ids) == 576
    assert score.cumulative_quality.unique_root_recall.denominator == 1024
    assert score.cumulative_quality.unique_root_recall.value is None
    assert score.cumulative_summary.accounted_request_count == 0
    assert not score.claims and not score.audit_complete


def test_score_parser_keeps_its_separate_actual_96mb_byte_bound():
    from tests.development_corpus_resume_score_support import labelled_history

    history, _ = labelled_history()
    score = score_development_corpus_resume(history=history)
    raw = score.model_dump_json().encode()
    assert MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES == 96_000_000
    padded = raw + b" " * (96_000_000 - len(raw))
    assert read_development_corpus_resume_score(padded) == score
    with pytest.raises(ValueError, match="byte bound"):
        read_development_corpus_resume_score(padded + b" ")
