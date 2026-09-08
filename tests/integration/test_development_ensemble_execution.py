"""Executed candidate and dual-review joins on disposable local controls only."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from decimal import Decimal
from itertools import product

import httpx
import pytest

from mmaudit.benchmark.development_ensemble import DevelopmentEnsembleScore
from mmaudit.models.development_ensemble import DevelopmentEnsembleObservation
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.development_ensemble import run_development_ensemble
from tests.development_benchmark_support import benchmark_truth
from tests.development_ensemble_support import ENSEMBLE_MODELS, ensemble_case, ensemble_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("development ensemble attempted real network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def request_role(request, calls):
    body = json.loads(request.content)
    role = ENSEMBLE_MODELS.index(body["model"])
    shard = sum(prior == role for prior, _ in calls) + 1
    calls.append((role, shard))
    assert SYNTHETIC_CREDENTIAL.encode() not in request.content
    return role, shard, body


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize(
    "opinions", list(product(("SUPPORTED", "REFUTED", "INCONCLUSIVE"), repeat=2))
)
async def test_executes_all_stages_with_unchanged_claims_unique_costs_and_exact_score(
    tmp_path, variant, opinions
):
    prepared = ensemble_case(variant=variant)
    ledger, secrets = local_controls(tmp_path)
    calls = []
    candidate_files = {}

    def handler(request):
        role, shard, body = request_role(request, calls)
        assert (tmp_path / "ensemble/plan.json").exists()
        if role:
            messages = json.dumps(body["messages"])
            assert "truth-" not in messages and "MATCHED_ROOT" not in messages
            assert all(model not in messages for model in ENSEMBLE_MODELS)
            assert "Untrusted candidate hypotheses" in messages
            if role == 1 and shard == 1:
                candidate_files.update(
                    {p.name: p.read_bytes() for p in (tmp_path / "ensemble/candidate").iterdir()}
                )
        return httpx.Response(
            200,
            json=ensemble_payload(role, shard, verdict=opinions[role - 1] if role else "SUPPORTED"),
        )

    result = await run_development_ensemble(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert calls == [(role, shard) for role in range(3) for shard in range(1, 4)]
    assert result.status == "OBSERVED_ALL_STAGES" and result.stop_reason is None
    assert result.completed_stage_count == 3 and result.completed_judgment_count == 6
    assert not result.unobserved_stage_ids
    assert len(result.accounting) == len(ledger.snapshot().entries) == 9
    assert result.total_accounted_cost_usd == result.reported_actual_cost_usd == Decimal("0.09")
    assert result.active_reserved_usd == result.uncertain_accounted_cost_usd == 0
    assert len({row.entry.ledger_request_id for row in result.accounting}) == 9
    assert result.candidate.total_accounted_cost_usd == Decimal("0.03")
    assert all(j.plan.candidate == result.candidate for j in result.judgments)
    expected = opinions[0] if opinions[0] == opinions[1] else "INCONCLUSIVE"
    assert all(row.opinions == opinions and row.consensus == expected for row in result.claims)
    assert all(
        (tmp_path / "ensemble/candidate" / name).read_bytes() == raw
        for name, raw in candidate_files.items()
    )
    score = DevelopmentEnsembleScore.model_validate_json(
        (tmp_path / "ensemble/score.json").read_bytes(), strict=True
    )
    assert score.observation == result and score.candidate_score.observation == result.candidate
    assert score.summary.combined_accounted_cost_usd == Decimal("0.09")
    assert score.summary.candidate_claim_count == 3
    assert score.review_opinion_observation_rate.value == score.stage_observation_rate.value == 1
    assert (
        score.executed_ensemble_wall_clock_seconds
        == result.elapsed_seconds
        >= result.observed_stage_elapsed_seconds
    )
    assert score.lineage_independence == "NOT_ESTABLISHED"
    assert (
        score.findings_validated
        is score.audit_complete
        is score.qualification_eligible
        is score.release_eligible
        is False
    )
    for path in (tmp_path / "ensemble").rglob("*"):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="accounting"):
        await run_development_ensemble(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "replay",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert ledger.snapshot() == before and len(calls) == 9 and not (tmp_path / "replay").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
async def test_empty_candidates_require_no_reviews_and_no_manufactured_completion(
    tmp_path, variant
):
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        assert role == 0
        return httpx.Response(200, json=ensemble_payload(role, shard, count=0))

    result = await run_development_ensemble(
        prepared=ensemble_case(variant=variant),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert result.status == "NO_CANDIDATES" and len(calls) == 3
    assert not result.claims and not result.judgments and not result.judgment_plans
    assert result.completed_stage_count == 1 and result.completed_judgment_count == 0
    assert result.unobserved_stage_ids == ("review-01", "review-02")
    assert result.total_accounted_cost_usd == Decimal("0.03")
    score = DevelopmentEnsembleScore.model_validate_json(
        (tmp_path / "ensemble/score.json").read_bytes()
    )
    assert score.summary.quality_scope == "NO_CANDIDATES"
    assert score.review_opinion_observation_rate.value is None
    assert score.stage_observation_rate.value == 0.333333
    assert score.summary.supported_root_recall.value == (0 if variant == "a" else None)
    assert not (tmp_path / "ensemble/review-01").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_role", [0, 1, 2])
@pytest.mark.parametrize("known_cost", [True, False])
async def test_failed_stage_stops_and_retains_all_costs_claims_and_missing_reviews(
    tmp_path, failed_role, known_cost
):
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        if (role, shard) == (failed_role, 2):
            body = {"error": {"message": "Synthetic local refusal."}}
            if known_cost:
                body["usage"] = {"cost": 0.01}
            return httpx.Response(429, json=body)
        return httpx.Response(200, json=ensemble_payload(role, shard))

    result = await run_development_ensemble(
        prepared=ensemble_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert result.status == "INCOMPLETE" and len(calls) == failed_role * 3 + 2
    assert result.stop_reason == (
        "CANDIDATE_INCOMPLETE" if failed_role == 0 else "REVIEW_INCOMPLETE"
    )
    assert len(result.accounting) == len(calls)
    assert result.total_accounted_cost_usd == sum(
        e.accounted_cost_usd for e in ledger.snapshot().entries
    )
    assert result.reported_actual_cost_usd == Decimal("0.01") * (
        len(calls) if known_cost else len(calls) - 1
    )
    assert bool(result.uncertain_accounted_cost_usd) is (not known_cost)
    assert len(result.claims) == (1 if failed_role == 0 else 3)
    assert all(
        row.consensus == "UNREVIEWED" for row in result.claims[(1 if failed_role == 2 else 0) :]
    )
    score = DevelopmentEnsembleScore.model_validate_json(
        (tmp_path / "ensemble/score.json").read_bytes()
    )
    assert score.summary.quality_scope == "INCOMPLETE_OBSERVATIONS"
    assert score.summary.supported_root_recall.value is None
    assert score.summary.all_candidate_severity_weighted_structural_precision.value is None
    assert score.summary.combined_accounted_cost_usd == result.total_accounted_cost_usd


@pytest.mark.asyncio
@pytest.mark.parametrize("original_role", [0, 1])
async def test_second_reviewer_cannot_reuse_any_prior_role_generation(tmp_path, original_role):
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        payload = ensemble_payload(role, shard)
        if (role, shard) == (2, 1):
            payload["id"] = f"gen-synthetic-ensemble-{original_role}-1"
        return httpx.Response(200, json=payload)

    result = await run_development_ensemble(
        prepared=ensemble_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == 7 and result.status == "INCOMPLETE"
    assert result.stop_reason == "REVIEW_INCOMPLETE" and result.completed_judgment_count == 3
    assert result.total_accounted_cost_usd == Decimal("0.07")
    assert all(row.opinions == ("SUPPORTED", None) for row in result.claims)


@pytest.mark.asyncio
async def test_cancellation_retains_unreturned_stage_accounting_then_propagates(tmp_path):
    ledger, secrets = local_controls(tmp_path)
    calls = []

    async def handler(request):
        request_role(request, calls)
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await run_development_ensemble(
            prepared=ensemble_case(),
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "ensemble",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
            benchmark_truth=benchmark_truth(),
        )
    result = DevelopmentEnsembleObservation.model_validate_json(
        (tmp_path / "ensemble/result.json").read_bytes()
    )
    assert result.status == "INCOMPLETE" and result.stop_reason == "INTERRUPTED"
    assert result.candidate is None and len(calls) == len(result.accounting) == 1
    assert result.accounting[0].entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.total_accounted_cost_usd > 0 and result.reported_actual_cost_usd == 0
    assert result.unobserved_stage_ids == ("candidate", "review-01", "review-02")
    score = DevelopmentEnsembleScore.model_validate_json(
        (tmp_path / "ensemble/score.json").read_bytes()
    )
    assert score.candidate_score is score.summary is None
    assert (
        score.stage_observation_rate.value == 0
        and score.review_opinion_observation_rate.value is None
    )
