"""Executed mock-HTTP candidate-to-review handoffs on disposable local ledgers only."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest

from mmaudit.benchmark.development import DevelopmentJudgmentImpactScore
from mmaudit.models.development_judgment import (
    DevelopmentJudgmentObservation,
    prepare_development_judgment,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
    PortfolioAttemptSlot,
)
from mmaudit.orchestration.development_audit import run_development_audit
from mmaudit.orchestration.development_judgment import run_development_judgment
from tests.development_benchmark_support import (
    benchmark_truth,
    scored_audit_case,
    scored_file_response,
    scored_payload,
)
from tests.development_judgment_support import (
    judgment_metadata,
    judgment_payload,
    judgment_response,
)
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("development judgment attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


async def candidate_inputs(tmp_path, *, variant="a", empty=False, count=1):
    original = scored_audit_case(variant=variant)
    ledger, secrets = local_controls(tmp_path)
    calls = []

    def handler(request):
        calls.append(request.content)
        index = len(calls)
        response = scored_file_response(index)
        response["findings"] = [] if empty else response["findings"] * count
        return httpx.Response(200, json=scored_payload(index, response=response))

    candidate = await run_development_audit(
        prepared=original,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "candidate",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert candidate.status == "OBSERVED_ALL_SHARDS" and len(calls) == 3
    prepared = prepare_development_judgment(
        candidate=candidate,
        policy=original.plan.shards[0].estimate.policy,
        endpoint_snapshot=judgment_metadata(),
        source_files=original.shards[0].source_files,
        run_id="executed-judgment",
    )
    return prepared, ledger, secrets


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
async def test_executes_every_judgment_with_source_custody_costs_and_same_truth_score(
    tmp_path, variant
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, variant=variant)
    old_files = {path.name: path.read_bytes() for path in (tmp_path / "candidate").iterdir()}
    old_entries = ledger.snapshot().entries
    calls = []

    def handler(request):
        calls.append(request.content)
        index = len(calls)
        assert request.content == prepared.shards[index - 1].request_content
        assert (tmp_path / "judgment/plan.json").exists()
        assert (tmp_path / "judgment/benchmark-plan.json").exists()
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        assert (
            prepared.plan.candidate.plan.shards[0].estimate.exact_model_id.encode()
            not in request.content
        )
        verdict = ("SUPPORTED", "REFUTED", "INCONCLUSIVE")[index - 1]
        return httpx.Response(
            200,
            json=judgment_payload(
                index, response=judgment_response(f"file-{index:02d}", verdict=verdict)
            ),
        )

    result = await run_development_judgment(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "judgment",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert len(calls) == 3 and result.status == "OBSERVED_ALL_JUDGMENTS"
    assert result.completed_judgment_count == 3 and not result.unreviewed_claim_ids
    assert result.judgment_accounted_cost_usd == Decimal("0.03")
    assert result.combined_accounted_cost_usd == ledger.snapshot().spent_usd == Decimal("0.06")
    assert (
        result.summed_stage_elapsed_seconds
        == result.plan.candidate.elapsed_seconds + result.elapsed_seconds
    )
    assert result.lineage_independence == "NOT_ESTABLISHED"
    assert (
        result.audit_complete is result.qualification_eligible is result.findings_validated is False
    )
    assert all(entry in ledger.snapshot().entries for entry in old_entries)
    assert {
        path.name: path.read_bytes() for path in (tmp_path / "candidate").iterdir()
    } == old_files
    assert (
        DevelopmentJudgmentObservation.model_validate_json(
            (tmp_path / "judgment/result.json").read_bytes()
        )
        == result
    )
    score = DevelopmentJudgmentImpactScore.model_validate_json(
        (tmp_path / "judgment/score.json").read_bytes()
    )
    assert (
        score.observation == result and score.candidate_score.observation == prepared.plan.candidate
    )
    assert score.summary.candidate_claim_count == 3
    assert (
        score.summary.supported_claim_count
        == score.summary.refuted_claim_count
        == score.summary.inconclusive_claim_count
        == 1
    )
    assert score.summary.first_attempt_claim_observation_rate.value == 1
    assert score.summary.supported_root_recall.value == (1 if variant == "a" else None)
    assert score.summary.supported_guarded_claim_count == (0 if variant == "a" else 1)
    if variant == "a":
        assert score.summary.supported_severity_weighted_structural_precision.value == 1
        assert score.summary.all_candidate_severity_weighted_structural_precision.value == 0.333333
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (tmp_path / "judgment").iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
async def test_empty_candidates_make_no_request_and_earn_no_review_completion_credit(
    tmp_path, variant
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, variant=variant, empty=True)
    before = ledger.path.read_bytes()

    def handler(_request):
        pytest.fail("empty candidate set dispatched a judgment")

    result = await run_development_judgment(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "judgment",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert result.status == "NO_CANDIDATES" and result.completed_judgment_count == 0
    assert (
        result.judgment_accounted_cost_usd == 0
        and result.combined_accounted_cost_usd == Decimal("0.03")
    )
    assert ledger.path.read_bytes() == before
    score = DevelopmentJudgmentImpactScore.model_validate_json(
        (tmp_path / "judgment/score.json").read_bytes()
    )
    assert score.summary.quality_scope == "NO_CANDIDATES"
    assert score.summary.first_attempt_claim_observation_rate.state == "EMPTY_DENOMINATOR"
    assert score.summary.supported_root_recall.value == (0 if variant == "a" else None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "http429",
        "known429",
        "missing_cost",
        "invalid_json",
        "bad_ids",
        "missing_decision",
        "source_bounds",
        "candidate_generation",
        "previous_generation",
        "timeout",
        "routing",
        "truncated",
    ],
)
async def test_failed_review_stops_without_retry_and_preserves_all_candidates_and_costs(
    tmp_path, failure
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    old_candidate = prepared.plan.candidate.model_dump_json()
    calls = []

    def handler(request):
        calls.append(request.content)
        index = len(calls)
        assert index <= 2, "incomplete review must not dispatch another shard or retry"
        payload = judgment_payload(index)
        if index == 1:
            return httpx.Response(200, json=payload)
        if failure == "http429":
            return httpx.Response(429, json={"error": "SYNTHETIC_PRIVATE_CANARY"})
        if failure == "known429":
            return httpx.Response(429, json={"usage": {"cost": 0.01}})
        if failure == "timeout":
            raise httpx.ReadTimeout("SYNTHETIC_PRIVATE_CANARY", request=request)
        if failure == "invalid_json":
            return httpx.Response(200, content=b"{SYNTHETIC_PRIVATE_CANARY")
        if failure == "missing_cost":
            del payload["usage"]["cost"]
        elif failure in {"bad_ids", "missing_decision", "source_bounds"}:
            response = judgment_response("file-02")
            if failure == "bad_ids":
                response["decisions"][0]["claim_id"] = "file-03:01"
            elif failure == "missing_decision":
                response["decisions"] = []
            else:
                response["decisions"][0]["source_refs"][0]["filename"] = "Unknown.sol"
            payload["choices"][0]["message"]["content"] = json.dumps(response)
        elif failure in {"candidate_generation", "previous_generation"}:
            payload["id"] = (
                prepared.plan.candidate.observations[0].generation_id
                if failure == "candidate_generation"
                else "gen-synthetic-judgment-1"
            )
        elif failure == "routing":
            payload["model"] = "synthetic/incorrect-route"
        elif failure == "truncated":
            payload["choices"][0]["finish_reason"] = "length"
        return httpx.Response(200, json=payload)

    result = await run_development_judgment(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "judgment",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert len(calls) == 2 and result.status == "INCOMPLETE"
    assert result.stop_reason == "JUDGMENT_INCOMPLETE" and result.completed_judgment_count == 1
    assert result.unreviewed_claim_ids == ("file-02:01", "file-03:01")
    assert result.observations[1].response is None and result.observations[1].diagnostics
    unknown = failure in {"http429", "missing_cost", "invalid_json", "timeout"}
    entry = result.accounting[1]
    assert (entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED) is unknown
    assert entry.accounted_cost_usd == (entry.reserved_usd if unknown else Decimal("0.01"))
    assert result.combined_accounted_cost_usd == ledger.snapshot().spent_usd
    assert prepared.plan.candidate.model_dump_json() == old_candidate
    assert len(ledger.snapshot().entries) == 5 and not (tmp_path / "judgment/file-03.json").exists()
    score = DevelopmentJudgmentImpactScore.model_validate_json(
        (tmp_path / "judgment/score.json").read_bytes()
    )
    assert score.summary.candidate_claim_count == 3 and score.summary.unreviewed_claim_count == 2
    assert score.summary.supported_root_recall.state == "INCOMPLETE_SCOPE"
    assert score.summary.first_attempt_claim_observation_rate.value == 0.333333
    assert (
        SYNTHETIC_CREDENTIAL not in result.model_dump_json()
        and "SYNTHETIC_PRIVATE_CANARY" not in result.model_dump_json()
    )
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await run_development_judgment(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "refused-replay",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert not (tmp_path / "refused-replay").exists() and ledger.path.read_bytes() == before


@pytest.mark.asyncio
async def test_cancellation_keeps_unobserved_accounting_and_reraises_after_durable_result(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []

    async def handler(request):
        calls.append(request)
        if len(calls) == 2:
            raise asyncio.CancelledError()
        return httpx.Response(200, json=judgment_payload())

    with pytest.raises(asyncio.CancelledError):
        await run_development_judgment(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "judgment",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
            benchmark_truth=benchmark_truth(),
        )
    result = DevelopmentJudgmentObservation.model_validate_json(
        (tmp_path / "judgment/result.json").read_bytes()
    )
    assert result.stop_reason == "INTERRUPTED" and result.status == "INCOMPLETE"
    assert len(result.observations) == 1 and len(result.accounting) == 2
    assert result.accounting[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.unreviewed_claim_ids == ("file-02:01", "file-03:01")
    assert result.combined_accounted_cost_usd == ledger.snapshot().spent_usd


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "fresh_ledger",
        "changed_request",
        "omitted_shard",
        "source_bytes",
        "metadata",
        "consent",
        "deadline",
        "mock_to_http",
    ],
)
async def test_preflight_rejects_changed_or_unauthorized_inputs_before_outputs_or_dispatch(
    tmp_path, change
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    arguments = dict(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "judgment",
        allow_code_egress=True,
    )

    def handler(_request):
        pytest.fail("preflight refusal dispatched a request")

    arguments["mock_transport"] = httpx.MockTransport(handler)
    if change == "fresh_ledger":
        arguments["ledger"] = AtomicCostLedger.initialize(
            tmp_path / "fresh-ledger.json", cap_usd=Decimal("20")
        )
    elif change == "changed_request":
        arguments["prepared"] = replace(
            prepared,
            shards=(replace(prepared.shards[0], request_content=b"{}"), *prepared.shards[1:]),
        )
    elif change == "omitted_shard":
        arguments["prepared"] = replace(prepared, shards=prepared.shards[:-1])
    elif change == "source_bytes":
        arguments["prepared"] = replace(prepared, source_files=prepared.source_files[:-1])
    elif change == "metadata":
        arguments["prepared"] = replace(
            prepared, endpoint_snapshot=judgment_metadata(model_id="synthetic/changed-reviewer")
        )
    elif change == "consent":
        arguments["allow_code_egress"] = False
    elif change == "deadline":
        arguments["maximum_run_seconds"] = True
    else:
        arguments["mock_transport"] = None
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await run_development_judgment(**arguments)
    assert not (tmp_path / "judgment").exists() and ledger.path.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("variant", ["a", "b"])
async def test_all_forty_eight_candidates_are_reviewed_once_without_dropping_duplicates(
    tmp_path, variant
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, variant=variant, count=16)
    calls = []

    def handler(request):
        calls.append(request)
        index = len(calls)
        return httpx.Response(
            200,
            json=judgment_payload(index, response=judgment_response(f"file-{index:02d}", count=16)),
        )

    result = await run_development_judgment(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "judgment",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(variant),
    )
    assert result.status == "OBSERVED_ALL_JUDGMENTS" and result.completed_judgment_count == 48
    assert len(calls) == 3 and all(
        len(item.response.decisions) == 16 for item in result.observations
    )
    score = DevelopmentJudgmentImpactScore.model_validate_json(
        (tmp_path / "judgment/score.json").read_bytes()
    )
    assert score.summary.candidate_claim_count == score.summary.supported_claim_count == 48
    assert len(score.summary.supported_planted_root_ids) == (1 if variant == "a" else 0)
    assert score.summary.supported_guarded_claim_count == (0 if variant == "a" else 48)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "blocker", ["pending", "portfolio", "foreign_uncertain", "exhausted", "overrun"]
)
async def test_cumulative_guards_still_block_judgments_before_output_or_dispatch(tmp_path, blocker):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    if blocker == "portfolio":
        ledger.reserve_portfolio("b" * 64, (PortfolioAttemptSlot("held-slot", Decimal("1")),))
    elif blocker == "exhausted":
        ledger.reconcile(ledger.reserve("spent-elsewhere", Decimal("19.96")), Decimal("19.96"))
    else:
        hold = ledger.reserve("another-request", Decimal("1"))
        if blocker == "foreign_uncertain":
            ledger.reconcile(hold, None)
        elif blocker == "overrun":
            with pytest.raises(CostReservationOverrunError):
                ledger.reconcile(hold, Decimal("2"))
    before = ledger.path.read_bytes()

    def handler(_request):
        pytest.fail("blocked cumulative state dispatched a judgment")

    with pytest.raises(ValueError):
        await run_development_judgment(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "judgment",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert ledger.path.read_bytes() == before and not (tmp_path / "judgment").exists()


@pytest.mark.asyncio
async def test_judgment_overrun_is_durably_counted_and_stops_the_current_run(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        payload = judgment_payload()
        payload["usage"]["cost"] = 2
        return httpx.Response(200, json=payload)

    result = await run_development_judgment(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "judgment",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
        benchmark_truth=benchmark_truth(),
    )
    assert result.status == "INCOMPLETE" and len(calls) == 1
    assert result.accounting[0].status is CostEntryStatus.RESERVATION_OVERRUN
    assert result.judgment_accounted_cost_usd == Decimal("2")
    assert result.combined_accounted_cost_usd == ledger.snapshot().spent_usd == Decimal("2.03")
    assert result.completed_judgment_count == 0 and len(result.unreviewed_claim_ids) == 3


@pytest.mark.asyncio
async def test_overall_deadline_cancels_inflight_review_without_releasing_unknown_cost(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.Event().wait()
        pytest.fail("deadline did not cancel the synthetic pending transport")

    result = await asyncio.wait_for(
        run_development_judgment(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "judgment",
            allow_code_egress=True,
            maximum_run_seconds=0.25,
            mock_transport=httpx.MockTransport(handler),
        ),
        timeout=2,
    )
    assert result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"
    assert len(calls) == len(result.accounting) == 1 and not result.observations
    assert result.accounting[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.combined_accounted_cost_usd == ledger.snapshot().spent_usd


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["existing_output", "parent_alias", "plan_drift"])
async def test_output_custody_refuses_replacement_and_keeps_known_costs(tmp_path, change):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    output = tmp_path / "judgment"
    sentinel = None
    if change == "existing_output":
        output.mkdir(mode=0o700)
        sentinel = output / "unrelated.txt"
        sentinel.write_text("preserve synthetic unrelated content")
    elif change == "parent_alias":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        output = alias / "judgment"
    calls = []

    def handler(request):
        calls.append(request)
        assert change == "plan_drift"
        (output / "plan.json").write_text("{}")
        return httpx.Response(200, json=judgment_payload())

    with pytest.raises((ValueError, OSError)):
        await run_development_judgment(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=output,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    if change == "plan_drift":
        assert len(calls) == 1 and ledger.snapshot().spent_usd == Decimal("0.04")
        assert (output / "plan.json").read_text() == "{}"
        assert not (output / "result.json").exists()
    else:
        assert not calls and ledger.snapshot().spent_usd == Decimal("0.03")
        if sentinel is not None:
            assert sentinel.read_text() == "preserve synthetic unrelated content"
