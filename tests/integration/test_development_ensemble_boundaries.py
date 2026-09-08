"""Bounded execution, failure custody and shared-budget controls for the local ensemble."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest

from mmaudit.benchmark.development_ensemble import DevelopmentEnsembleScore
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.orchestration.cost_ledger import (
    CostEntryStatus,
    CostReservationOverrunError,
    PortfolioAttemptSlot,
)
from mmaudit.orchestration.development_ensemble import run_development_ensemble
from mmaudit.orchestration.development_judgment import run_development_judgment
from tests.development_benchmark_support import benchmark_truth
from tests.development_ensemble_support import ensemble_case, ensemble_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls
from tests.integration.test_development_ensemble_execution import request_role
from tests.integration.test_development_judgment_execution import candidate_inputs


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("ensemble boundary test attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
async def test_maximum_48_candidates_receive_96_opinions_without_truth_or_other_review_leakage(
    tmp_path, variant
):
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("20"),
        per_attempt_budget_usd=Decimal("3"),
    )
    prepared = ensemble_case(variant=variant, policy=policy)
    ledger, secrets = local_controls(tmp_path)
    calls = []
    sentinel = "Synthetic first-review-only explanation sentinel."

    def handler(request):
        role, shard, body = request_role(request, calls)
        if role == 2:
            assert sentinel not in json.dumps(body["messages"])
        payload = ensemble_payload(
            role, shard, count=16, verdict="REFUTED" if role == 2 else "SUPPORTED"
        )
        if role == 1:
            response = json.loads(payload["choices"][0]["message"]["content"])
            for decision in response["decisions"]:
                decision["explanation"] = sentinel
            payload["choices"][0]["message"]["content"] = json.dumps(response)
        return httpx.Response(200, json=payload)

    result = await run_development_ensemble(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert result.status == "OBSERVED_ALL_STAGES" and len(calls) == 9
    assert len(result.claims) == 48 and result.completed_judgment_count == 96
    assert all(
        row.opinions == ("SUPPORTED", "REFUTED") and row.consensus == "INCONCLUSIVE"
        for row in result.claims
    )
    score = DevelopmentEnsembleScore.model_validate_json(
        (tmp_path / "ensemble/score.json").read_bytes()
    )
    assert score.summary.candidate_claim_count == score.summary.inconclusive_claim_count == 48
    assert score.summary.all_candidate_severity_weighted_structural_precision.denominator == 240
    assert score.review_opinion_observation_rate.denominator == 96


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "blocker",
    ["pending", "portfolio", "unknown", "foreign_unknown_carry", "headroom_spent", "overrun"],
)
async def test_preflight_refuses_blocked_cumulative_state_before_creating_outputs(
    tmp_path, blocker
):
    prepared = ensemble_case()
    ledger, secrets = local_controls(tmp_path)
    if blocker == "portfolio":
        ledger.reserve_portfolio("b" * 64, (PortfolioAttemptSlot("synthetic-slot", Decimal("1")),))
    elif blocker == "headroom_spent":
        ledger.reconcile(ledger.reserve("synthetic-other-work", Decimal("19")), Decimal("19"))
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
            prepared = ensemble_case(policy=policy)
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("blocked ensemble dispatched")

    with pytest.raises(ValueError, match="accounting"):
        await run_development_ensemble(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "ensemble",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(forbidden),
        )
    assert ledger.path.read_bytes() == before and not (tmp_path / "ensemble").exists()


@pytest.mark.asyncio
async def test_explicit_carry_keeps_historical_unknown_charge_without_double_counting_it_as_this_run(
    tmp_path,
):
    prepared = ensemble_case()
    ledger, secrets = local_controls(tmp_path)
    hold = ledger.reserve(
        development_ledger_request_id("synthetic-earlier-development"), Decimal("1")
    )
    ledger.reconcile(hold, None)
    original = ledger.snapshot().entries[0]
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        return httpx.Response(200, json=ensemble_payload(role, shard))

    with pytest.raises(ValueError, match="accounting"):
        await run_development_ensemble(
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
    result = await run_development_ensemble(
        prepared=ensemble_case(policy=policy),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "OBSERVED_ALL_STAGES" and len(calls) == 9
    assert original in ledger.snapshot().entries
    assert sum(e.accounted_cost_usd for e in ledger.snapshot().entries) == Decimal("1.09")
    assert (
        result.total_accounted_cost_usd == Decimal("0.09")
        and result.uncertain_accounted_cost_usd == 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_role", [0, 1, 2])
async def test_actual_overrun_in_any_stage_is_retained_and_stops_remaining_calls(
    tmp_path, failed_role
):
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        payload = ensemble_payload(role, shard)
        if (role, shard) == (failed_role, 1):
            payload["usage"]["cost"] = 2
        return httpx.Response(200, json=payload)

    result = await run_development_ensemble(
        prepared=ensemble_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "ensemble",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "INCOMPLETE" and len(calls) == 3 * failed_role + 1
    assert result.accounting[-1].entry.status is CostEntryStatus.RESERVATION_OVERRUN
    assert (
        result.total_accounted_cost_usd
        == result.reported_actual_cost_usd
        == Decimal("2") + Decimal("0.01") * (len(calls) - 1)
    )
    assert ledger.snapshot().has_reservation_overrun


@pytest.mark.asyncio
@pytest.mark.parametrize("blocked_role", [0, 1, 2])
async def test_one_whole_run_deadline_retains_unreturned_stage_liability(tmp_path, blocked_role):
    ledger, secrets = local_controls(tmp_path)
    calls = []
    entered = False

    async def handler(request):
        nonlocal entered
        role, shard, _ = request_role(request, calls)
        if role == blocked_role:
            entered = True
            await asyncio.Event().wait()
        return httpx.Response(200, json=ensemble_payload(role, shard))

    result = await asyncio.wait_for(
        run_development_ensemble(
            prepared=ensemble_case(maximum_run_seconds=1.0),
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "ensemble",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        ),
        timeout=4.0,
    )
    assert entered and result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"
    assert len(calls) == 3 * blocked_role + 1
    assert result.accounting[-1].entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.total_accounted_cost_usd > result.reported_actual_cost_usd
    assert result.completed_stage_count == blocked_role and 0.9 <= result.elapsed_seconds < 4


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["existing", "parent_alias", "parent_plan", "prior_child_result"])
async def test_output_custody_refuses_without_overwriting_or_losing_known_charges(tmp_path, kind):
    ledger, secrets = local_controls(tmp_path)
    output = tmp_path / "ensemble"
    if kind == "existing":
        output.mkdir(mode=0o700)
        (output / "retained.txt").write_text("Existing synthetic content.")
    elif kind == "parent_alias":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        output = alias / "ensemble"
    calls = []

    def handler(request):
        role, shard, _ = request_role(request, calls)
        if kind == "parent_plan" and (role, shard) == (0, 1):
            path = output / "plan.json"
            path.write_bytes(path.read_bytes() + b"\n")
        elif kind == "prior_child_result" and (role, shard) == (1, 1):
            path = output / "candidate/result.json"
            path.write_bytes(path.read_bytes() + b"\n")
        return httpx.Response(200, json=ensemble_payload(role, shard))

    with pytest.raises((ValueError, OSError)):
        await run_development_ensemble(
            prepared=ensemble_case(),
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=output,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert (
        len(calls)
        == ({"existing": 0, "parent_alias": 0, "parent_plan": 3, "prior_child_result": 6}[kind])
    )
    assert sum(e.accounted_cost_usd for e in ledger.snapshot().entries) == Decimal("0.01") * len(
        calls
    )
    assert not (output / "result.json").exists()
    if kind == "existing":
        assert (output / "retained.txt").read_text() == "Existing synthetic content."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["request", "missing_shard", "metadata", "source", "consent", "transport"]
)
async def test_forged_prepared_handles_refuse_before_cost_or_output(tmp_path, kind):
    prepared = ensemble_case()
    ledger, secrets = local_controls(tmp_path)
    consent = True
    transport = httpx.MockTransport(lambda _: pytest.fail("forged plan dispatched"))
    if kind in {"request", "source", "missing_shard"}:
        first = prepared.candidate.shards[0]
        if kind == "request":
            shards = (replace(first, request_content=b"{}"), *prepared.candidate.shards[1:])
        elif kind == "source":
            shards = (replace(first, source_content=b"changed"), *prepared.candidate.shards[1:])
        else:
            shards = prepared.candidate.shards[:2]
        prepared = replace(prepared, candidate=replace(prepared.candidate, shards=shards))
    elif kind == "metadata":
        prepared = replace(prepared, reviewer_metadata=prepared.reviewer_metadata[::-1])
    elif kind == "consent":
        consent = 1
    else:
        transport = object()
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await run_development_ensemble(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "ensemble",
            allow_code_egress=consent,
            mock_transport=transport,
        )
    assert ledger.path.read_bytes() == before and not (tmp_path / "ensemble").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "excluded",
    [
        ["gen-id"],
        (True,),
        ("bad/id",),
        ("same", "same"),
        tuple(f"gen-{i}" for i in range(7)),
        (SYNTHETIC_CREDENTIAL,),
    ],
)
async def test_extra_generation_exclusions_are_rejection_only_bounded_and_secret_free(
    tmp_path, excluded
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError, match="exclusion"):
        await run_development_judgment(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "judgment",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(
                lambda _: pytest.fail("invalid exclusions dispatched")
            ),
            excluded_generation_ids=excluded,
        )
    assert ledger.path.read_bytes() == before and not (tmp_path / "judgment").exists()
