"""Actual bounded parent execution over synthetic sources; real network and processes are trapped."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

import mmaudit.orchestration.development_corpus_ensemble as orchestration
from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.benchmark.development_corpus_ensemble import DevelopmentCorpusEnsembleScore
from mmaudit.models.development_corpus_ensemble import DevelopmentCorpusEnsembleObservation
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from tests.development_corpus_benchmark_support import paired_sources, truth_binding
from tests.development_corpus_ensemble_support import (
    manifest_ensemble_case,
    manifest_ensemble_payload,
    maximum_manifest_sources,
)
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_support import corpus_payload
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_review_support import SYNTHETIC_CREDENTIAL


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest ensemble parent attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def response_payload(prepared, role, ordinal, *, claims=1, verdict="SUPPORTED"):
    sources = prepared.candidate.shards[0].source_files
    if role == 0 and sources != paired_sources():
        payload = corpus_payload(ordinal, count=claims, origin=sources[ordinal - 1][0])
        payload["id"] = f"gen-synthetic-manifest-ensemble-{role}-{ordinal}"
        payload["model"] = ENSEMBLE_MODELS[role]
        routing = payload["openrouter_metadata"]
        routing["requested"] = payload["model"]
        routing["endpoints"]["available"][0]["model"] = payload["model"]
        routing["attempts"][0]["model"] = payload["model"]
        return payload
    return manifest_ensemble_payload(
        role, ordinal, count=claims, verdict=verdict, filename=sources[ordinal - 1][0]
    )


def execution_case(tmp_path, *, prepared=None, scored=True, claims=1):
    prepared = manifest_ensemble_case() if prepared is None else prepared
    return SimpleNamespace(
        prepared=prepared,
        ledger=AtomicCostLedger.initialize(
            tmp_path / "synthetic-ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
        ),
        secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
        root=tmp_path / "run",
        binding=truth_binding(prepared.candidate) if scored else None,
        claims=claims,
        calls=[],
        counts=[0, 0, 0],
    )


async def execute(case, *, custom=None, **changes):
    async def handler(request):
        role = ENSEMBLE_MODELS.index(json.loads(request.content)["model"])
        case.counts[role] += 1
        ordinal = case.counts[role]
        case.calls.append((role, ordinal, request))
        if case.binding is not None:
            for marker in (case.binding.truth_file_sha256, case.binding.truth.truth_id):
                assert marker.encode() not in request.content
            assert (case.root / "benchmark-plan.json").is_file()
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        if role == 0:
            assert request.content == case.prepared.candidate.shards[ordinal - 1].request_content
        if custom is not None:
            selected = custom(role, ordinal, request)
            selected = await selected if asyncio.iscoroutine(selected) else selected
            if selected is not None:
                return selected
        return httpx.Response(
            200,
            json=response_payload(
                case.prepared,
                role,
                ordinal,
                claims=case.claims,
                verdict="REFUTED" if role == 2 else "SUPPORTED",
            ),
        )

    values = dict(
        prepared=case.prepared,
        ledger=case.ledger,
        operator_secrets=case.secrets,
        output_dir=case.root,
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_binding=case.binding,
    )
    values.update(changes)
    return await orchestration.run_development_corpus_ensemble(**values)


def retained(case):
    return DevelopmentCorpusEnsembleObservation.model_validate_json(
        (case.root / "result.json").read_bytes(), strict=True
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [0, 1, 16])
async def test_parent_executes_all_available_stages_and_preserves_original_score(tmp_path, claims):
    case = execution_case(tmp_path, claims=claims)
    result = await execute(case)
    assert result == retained(case)
    assert case.counts == ([6, 3, 3] if claims else [6, 0, 0])
    assert result.status == ("OBSERVED_ALL_STAGES" if claims else "NO_CANDIDATES")
    assert len(result.claims) == 3 * claims and result.completed_judgment_count == 6 * claims
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert result.total_accounted_cost_usd == Decimal("0.12" if claims else "0.06")
    score = DevelopmentCorpusEnsembleScore.model_validate_json(
        (case.root / "score.json").read_bytes()
    )
    assert score.observation == result
    assert score.candidate_score == score_development_corpus(
        binding=case.binding, observation=result.candidate
    )
    assert json.loads(
        (case.root / "candidate/score.json").read_bytes()
    ) == score.candidate_score.model_dump(mode="json")
    assert score.summary.refuted_by_one_count == 3 * claims
    assert score.summary.disagreement_count == 3 * claims
    assert score.summary.missing_opinion_count == 0
    assert score.summary.available_claim_opinion_observation_fraction.value == (
        1 if claims else None
    )
    assert not result.audit_complete and not score.findings_validated
    assert not score.qualification_eligible and score.lineage_independence == "NOT_ESTABLISHED"
    for path in case.root.rglob("*"):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)


@pytest.mark.asyncio
@pytest.mark.parametrize("known,carry", [(True, False), (False, False), (False, True)])
async def test_partial_candidate_reviews_only_when_accounting_allows_and_never_completes_source(
    tmp_path, known, carry
):
    case = execution_case(
        tmp_path, prepared=manifest_ensemble_case(policy=selected_policy(carry=carry))
    )

    def handler(role, ordinal, _request):
        if role == 0 and ordinal == 3:
            return httpx.Response(429, json={"usage": {"cost": 0.01}} if known else {"error": {}})

    result = await execute(case, custom=handler)
    allowed = known or carry
    assert case.counts == ([3, 2, 2] if allowed else [3, 0, 0])
    assert result.status == "INCOMPLETE" and result.stop_reason == "CANDIDATE_INCOMPLETE"
    assert result.completed_stage_count == 0 and len(result.unobserved_candidate_shard_ids) == 4
    assert len(result.claims) == 2 and result.available_claim_reviews_complete is allowed
    assert bool(result.uncertain_accounted_cost_usd) is (not known)
    score = DevelopmentCorpusEnsembleScore.model_validate_json(
        (case.root / "score.json").read_bytes()
    )
    assert score.candidate_score.summary.unique_root_recall.value is None
    assert score.summary.overall_observation_scope == "INCOMPLETE_OBSERVATIONS"
    assert score.summary.unobserved_candidate_shard_count == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("stage,ordinal", [(0, 1), (0, 6), (1, 1), (1, 2), (1, 3), (2, 1), (2, 3)])
@pytest.mark.parametrize("known", [False, True])
async def test_first_middle_last_failure_keeps_original_costs_and_stops_failed_review(
    tmp_path, stage, ordinal, known
):
    case = execution_case(tmp_path)

    def handler(role, index, _request):
        if (role, index) == (stage, ordinal):
            return httpx.Response(500, json={"usage": {"cost": 0.01}} if known else {"error": {}})

    result = await execute(case, custom=handler)
    assert result.status == "INCOMPLETE"
    assert case.counts[stage] == ordinal
    if stage == 1:
        assert case.counts[2] == 0
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert result.accounting[-1].entry.status is (
        CostEntryStatus.RECONCILED if known else CostEntryStatus.UNCERTAIN_ACCOUNTED
    )
    assert result == retained(case)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", [0, 1, 2])
async def test_cancelled_child_retains_its_durable_observations_and_unknown_charge(tmp_path, stage):
    case = execution_case(tmp_path)
    entered = asyncio.Event()

    async def handler(role, ordinal, _request):
        if role == stage and ordinal == 2:
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(execute(case, custom=handler))
    await asyncio.wait_for(entered.wait(), timeout=10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    result = retained(case)
    assert result.stop_reason == "INTERRUPTED" and result.status == "INCOMPLETE"
    assert case.counts[stage] == 2 and case.counts[stage + 1 :] == [0] * (2 - stage)
    assert result.uncertain_accounted_cost_usd > 0
    child = result.candidate if stage == 0 else result.judgments[stage - 1]
    assert child is not None and len(child.observations) == 1
    assert len(child.accounting) == 2
    assert child.accounting[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert child.observations[0].status == "OBSERVED"
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert (case.root / "score.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["plan.json", "sources.json", "benchmark-plan.json"])
async def test_parent_input_drift_during_candidate_refuses_before_next_shard(tmp_path, target):
    case = execution_case(tmp_path)

    def handler(role, ordinal, _request):
        if role == 0 and ordinal == 1:
            path = case.root / target
            path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(ValueError):
        await execute(case, custom=handler)
    assert case.counts == [1, 0, 0]
    assert len(case.ledger.snapshot().entries) == 1
    assert not (case.root / "result.json").exists()


@pytest.mark.asyncio
async def test_maximum_64_files_1024_claims_2048_opinions_and_192_requests(tmp_path):
    case = execution_case(
        tmp_path,
        prepared=manifest_ensemble_case(
            source_files=maximum_manifest_sources(), policy=selected_policy(total="250")
        ),
        scored=False,
        claims=16,
    )
    result = await execute(case)
    assert result.status == "OBSERVED_ALL_STAGES" and case.counts == [64, 64, 64]
    assert len(result.claims) == 1024 and result.completed_judgment_count == 2048
    assert len(result.accounting) == len(case.ledger.snapshot().entries) == 192
    assert result.total_accounted_cost_usd == Decimal("1.92")
    assert result == retained(case)
    assert not (case.root / "score.json").exists()
