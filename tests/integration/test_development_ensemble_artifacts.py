"""Reject changed aggregate claims, accounting and scores from safe executed local controls."""

from __future__ import annotations

import json
import socket
import subprocess
from copy import deepcopy
from decimal import Decimal

import httpx
import pytest
import pytest_asyncio

from mmaudit.benchmark.development import bind_development_benchmark
from mmaudit.benchmark.development_ensemble import (
    DevelopmentEnsembleScore,
    score_development_ensemble,
)
from mmaudit.models.development_ensemble import DevelopmentEnsembleObservation
from mmaudit.orchestration.development_ensemble import run_development_ensemble
from tests.development_benchmark_support import benchmark_truth
from tests.development_ensemble_support import ensemble_case, ensemble_payload
from tests.development_review_support import local_controls
from tests.integration.test_development_ensemble_execution import request_role


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("development ensemble artifact test attempted external execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest_asyncio.fixture
async def executed(tmp_path):
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        return httpx.Response(200, json=ensemble_payload(role, shard))

    observation = await run_development_ensemble(
        prepared=ensemble_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert len(calls) == len(ledger.snapshot().entries) == 9
    assert observation.total_accounted_cost_usd == Decimal("0.09")
    score = DevelopmentEnsembleScore.model_validate_json(
        (tmp_path / "ensemble/score.json").read_bytes(), strict=True
    )
    return observation, score


@pytest.mark.parametrize(
    "field,value",
    [
        ("candidate", None),
        ("transport", "HTTP_OBSERVATION"),
        ("status", "NO_CANDIDATES"),
        ("stop_reason", "LOCAL_FAILURE"),
        ("judgment_plans", []),
        ("judgments", []),
        ("accounting", []),
        ("claims", []),
        ("unobserved_stage_ids", ["review-02"]),
        ("completed_stage_count", 2),
        ("completed_judgment_count", 3),
        ("total_accounted_cost_usd", "0.15"),
        ("reported_actual_cost_usd", "0.03"),
        ("uncertain_accounted_cost_usd", "0.01"),
        ("active_reserved_usd", "0.01"),
        ("elapsed_seconds", 0),
        ("observed_stage_elapsed_seconds", 0),
        ("lineage_independence", "VERIFIED"),
        ("findings_validated", True),
        ("audit_complete", True),
        ("qualification_eligible", True),
        ("release_eligible", True),
    ],
)
def test_retained_aggregate_rejects_missing_scope_changed_costs_or_authority(
    executed, field, value
):
    original, _ = executed
    data = original.model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValueError):
        DevelopmentEnsembleObservation.model_validate_json(json.dumps(data), strict=True)
    assert (
        DevelopmentEnsembleObservation.model_validate_json(original.model_dump_json()) == original
    )


@pytest.mark.parametrize("kind", ["reservation", "stage", "order", "claim", "opinions"])
def test_nested_aggregate_cannot_relabel_requests_or_hide_original_candidates(executed, kind):
    original, _ = executed
    data = original.model_dump(mode="json")
    if kind == "reservation":
        data["accounting"][3]["entry"]["reservation_id"] = data["accounting"][0]["entry"][
            "reservation_id"
        ]
    elif kind == "stage":
        data["accounting"][3]["stage_id"] = "candidate"
    elif kind == "order":
        data["accounting"][0], data["accounting"][1] = data["accounting"][1], data["accounting"][0]
    elif kind == "claim":
        data["claims"][0]["candidate_claim"] = deepcopy(data["claims"][1]["candidate_claim"])
    else:
        data["claims"][0]["opinions"] = ["REFUTED", "REFUTED"]
        data["claims"][0]["consensus"] = "REFUTED"
    with pytest.raises(ValueError):
        DevelopmentEnsembleObservation.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("observation_sha256", "0" * 64),
        ("candidate_score", None),
        ("claims", []),
        ("summary", None),
        ("executed_ensemble_wall_clock_seconds", 0),
        ("interpretation", "VALIDATED_FINDINGS"),
        ("lineage_independence", "VERIFIED"),
        ("findings_validated", True),
        ("audit_complete", True),
        ("qualification_eligible", True),
        ("release_eligible", True),
    ],
)
def test_score_recomputes_original_inputs_without_promoting_consensus(executed, field, value):
    _, original = executed
    data = original.model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValueError):
        DevelopmentEnsembleScore.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize("kind", ["cost", "denominator", "view_rate", "stage_rate", "truth"])
def test_score_cannot_filter_denominators_double_count_costs_or_switch_truth(executed, kind):
    observation, original = executed
    data = original.model_dump(mode="json")
    if kind == "cost":
        data["summary"]["combined_accounted_cost_usd"] = "0.15"
    elif kind == "denominator":
        data["summary"]["candidate_claim_count"] = 1
    elif kind == "view_rate":
        data["review_opinion_observation_rate"]["denominator"] = 3
        data["review_opinion_observation_rate"]["numerator"] = 3
    elif kind == "stage_rate":
        data["stage_observation_rate"]["denominator"] = 1
        data["stage_observation_rate"]["numerator"] = 1
    else:
        binding = bind_development_benchmark(
            plan=ensemble_case(variant="b").plan.candidate, truth=benchmark_truth("b")
        )
        data["binding"] = binding.model_dump(mode="json")
        with pytest.raises(ValueError, match="frozen source"):
            score_development_ensemble(binding=binding, observation=observation)
    with pytest.raises(ValueError):
        DevelopmentEnsembleScore.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [0, 1, 2])
@pytest.mark.parametrize("kind", ["malformed_json", "wrong_coverage"])
async def test_malformed_stage_never_gains_completion_or_dispatches_later_stages(
    tmp_path, role, kind
):
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        actual_role, shard, _ = request_role(request, calls)
        payload = ensemble_payload(actual_role, shard)
        if (actual_role, shard) == (role, 1):
            if kind == "malformed_json":
                payload["choices"][0]["message"]["content"] = "{"
            else:
                body = json.loads(payload["choices"][0]["message"]["content"])
                if role == 0:
                    body["findings"][0]["root_cause_ref"]["filename"] = "outside.sol"
                else:
                    body["decisions"] = []
                payload["choices"][0]["message"]["content"] = json.dumps(body)
        return httpx.Response(200, json=payload)

    result = await run_development_ensemble(
        prepared=ensemble_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert result.status == "INCOMPLETE" and result.completed_stage_count == role
    assert len(calls) == len(result.accounting) == role * 3 + 1
    assert result.total_accounted_cost_usd == Decimal("0.01") * len(calls)
    assert result.stop_reason == ("CANDIDATE_INCOMPLETE" if role == 0 else "REVIEW_INCOMPLETE")
    assert (
        not (tmp_path / "ensemble" / ("review-01" if role == 0 else "review-02")).exists()
        or role == 2
    )
