"""Maximum scope and fail-closed manifest review boundaries on disposable local controls only."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest

from mmaudit.models.development_corpus import DevelopmentCorpusObservation
from mmaudit.models.development_corpus_judgment import (
    DevelopmentCorpusJudgmentObservation,
    DevelopmentCorpusJudgmentShardObservation,
    prepare_development_corpus_judgment,
)
from mmaudit.models.development_transport import review_development_corpus_judgment_shard
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_corpus_judgment import run_development_corpus_judgment
from tests.development_corpus_judgment_support import manifest_judgment_payload, selected_policy
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_judgment_execution import candidate_inputs, execute


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest boundary test attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [0, 16])
async def test_maximum_64_file_candidate_and_1024_claim_review_keeps_all_scope(tmp_path, claims):
    prepared, ledger, secrets = await candidate_inputs(
        tmp_path,
        count=64,
        claims=claims,
        policy=selected_policy(total="250", per_attempt="5", timeout=360),
    )
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=manifest_judgment_payload(len(calls), count=claims))

    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert result.completed_judgment_count == 64 * claims
    assert len(result.plan.candidate.plan.manifest.sources) == 64
    assert len(result.observations) == len(calls) == (64 if claims else 0)
    assert not result.unreviewed_claim_ids and not result.unobserved_candidate_shard_ids
    assert len(ledger.snapshot().entries) == (128 if claims else 64)
    assert result.combined_accounted_cost_usd == Decimal("1.28" if claims else "0.64")
    assert not result.audit_complete and not result.qualification_eligible


@pytest.mark.asyncio
async def test_mixed_empty_sources_do_not_renumber_original_claims(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, claims=(0, 2, 0, 1))
    assert prepared.plan.empty_candidate_shard_ids == ("file-0001", "file-0003")
    calls = []

    def handler(request):
        index = len(calls)
        calls.append(request)
        shard = prepared.shards[index]
        return httpx.Response(
            200,
            json=manifest_judgment_payload(
                index + 1, shard_id=shard.shard_id, count=len(shard.claims)
            ),
        )

    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert len(calls) == 2 and result.completed_judgment_count == 3
    assert tuple(s.shard_id for s in result.observations) == ("file-0002", "file-0004")


@pytest.mark.asyncio
async def test_empty_available_scope_does_not_clear_an_incomplete_original(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, fail_at=1, carry=True)
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("unobserved source acquired a review request")

    result = await execute(prepared, ledger, secrets, tmp_path / "review", forbidden)
    assert result.status == "INCOMPLETE" and result.stop_reason == "CANDIDATE_INCOMPLETE"
    assert result.completed_judgment_count == 0 and len(result.unobserved_candidate_shard_ids) == 4
    assert result.judgment_accounted_cost_usd == 0 and ledger.path.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["candidate", "prior_review", "excluded"])
async def test_generation_reuse_stops_before_a_third_review_and_retains_the_charge(tmp_path, kind):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    excluded = ("gen-synthetic-excluded",) if kind == "excluded" else ()
    calls = []

    def handler(request):
        calls.append(request)
        payload = manifest_judgment_payload(len(calls))
        if len(calls) == 2:
            payload["id"] = {
                "candidate": prepared.plan.candidate.observations[0].generation_id,
                "prior_review": "gen-synthetic-judgment-1",
                "excluded": "gen-synthetic-excluded",
            }[kind]
        return httpx.Response(200, json=payload)

    result = await execute(
        prepared, ledger, secrets, tmp_path / "review", handler, excluded_generation_ids=excluded
    )
    assert len(calls) == 2 and result.status == "INCOMPLETE"
    assert result.completed_judgment_count == 1 and len(result.unreviewed_claim_ids) == 3
    assert result.accounting[-1].status is CostEntryStatus.RECONCILED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        "json",
        "old_schema",
        "omitted",
        "source",
        "line",
        "repeated_ref",
        "secret",
        "truncation",
        "byok",
        "identity",
        "overrun",
    ],
)
async def test_invalid_review_envelopes_never_gain_review_credit_or_trigger_retry(tmp_path, kind):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, claims=2)
    calls = []

    def handler(request):
        calls.append(request)
        payload = manifest_judgment_payload(1, count=2)
        response = json.loads(payload["choices"][0]["message"]["content"])
        if kind == "old_schema":
            response["schema_version"] = "1.0"
        elif kind == "omitted":
            response["decisions"].pop()
        elif kind == "source":
            response["decisions"][0]["source_refs"][0]["filename"] = "src/Unselected.sol"
        elif kind == "line":
            response["decisions"][0]["source_refs"][0]["line_end"] = 10000
        elif kind == "repeated_ref":
            response["decisions"][0]["source_refs"] *= 2
        elif kind == "secret":
            response["summary"] = SYNTHETIC_CREDENTIAL
        elif kind == "truncation":
            payload["choices"][0]["finish_reason"] = "length"
        elif kind == "byok":
            payload["usage"]["is_byok"] = True
        elif kind == "identity":
            payload["model"] = "synthetic/unselected-reviewer"
        elif kind == "overrun":
            payload["usage"]["cost"] = 10
        payload["choices"][0]["message"]["content"] = (
            "{" if kind == "json" else json.dumps(response)
        )
        return httpx.Response(200, json=payload)

    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert (
        len(calls) == 1 and result.status == "INCOMPLETE" and result.completed_judgment_count == 0
    )
    assert len(result.unreviewed_claim_ids) == 8 and len(result.accounting) == 1
    assert result.accounting[0].status is (
        CostEntryStatus.RESERVATION_OVERRUN if kind == "overrun" else CostEntryStatus.RECONCILED
    )
    assert SYNTHETIC_CREDENTIAL not in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["source", "request", "policy", "candidate", "ledger"])
async def test_prepared_or_candidate_ledger_substitution_refuses_before_dispatch(tmp_path, kind):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    before = ledger.path.read_bytes()
    if kind == "source":
        prepared = replace(
            prepared,
            source_files=(
                (prepared.source_files[0][0], prepared.source_files[0][1] + b"\n"),
                *prepared.source_files[1:],
            ),
        )
    elif kind == "request":
        prepared = replace(
            prepared,
            shards=(
                replace(
                    prepared.shards[0], request_content=prepared.shards[0].request_content + b" "
                ),
                *prepared.shards[1:],
            ),
        )
    elif kind == "policy":
        first = prepared.shards[0]
        estimate = first.estimate.model_copy(update={"policy": selected_policy(timeout=1)})
        prepared = replace(
            prepared, shards=(replace(first, estimate=estimate), *prepared.shards[1:])
        )
    elif kind == "candidate":
        prepared = replace(
            prepared, plan=prepared.plan.model_copy(update={"candidate_sha256": "0" * 64})
        )
    else:
        ledger = AtomicCostLedger.initialize(
            tmp_path / "new-synthetic-ledger.json", cap_usd=Decimal("20")
        )

    def forbidden(_request):
        pytest.fail("substitution reached a review dispatch")

    with pytest.raises(ValueError):
        await execute(prepared, ledger, secrets, tmp_path / "review", forbidden)
    assert (tmp_path / "synthetic-ledger.json").read_bytes() == before and not (
        tmp_path / "review"
    ).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("filename", ["plan.json", "sources.json"])
async def test_output_replacement_after_a_response_refuses_further_dispatch(tmp_path, filename):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        path = tmp_path / "review" / filename
        path.write_bytes(path.read_bytes() + b"\n")
        return httpx.Response(200, json=manifest_judgment_payload(1))

    with pytest.raises(ValueError):
        await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert len(calls) == 1 and len(ledger.snapshot().entries) == 5
    assert not (tmp_path / "review/result.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        ("same", "same"),
        ("with space",),
        ("x" * 129,),
        tuple(f"gen-{i}" for i in range(129)),
        ["gen-list"],
        (None,),
    ],
)
async def test_generation_exclusions_are_bounded_rejection_only_inputs(tmp_path, bad):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("invalid exclusion reached review")

    with pytest.raises(ValueError):
        await execute(
            prepared, ledger, secrets, tmp_path / "review", forbidden, excluded_generation_ids=bad
        )
    assert ledger.path.read_bytes() == before and not (tmp_path / "review").exists()


@pytest.mark.asyncio
async def test_actual_request_timeout_does_not_retry_or_clear_uncertainty(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, timeout=1)
    calls = []

    async def stalled(request):
        calls.append(request)
        await asyncio.Event().wait()

    result = await asyncio.wait_for(
        execute(prepared, ledger, secrets, tmp_path / "review", stalled), timeout=4
    )
    assert result.status == "INCOMPLETE" and len(calls) == 1
    assert result.accounting[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "OBSERVED_ALL_JUDGMENTS"),
        ("stop_reason", None),
        ("unobserved_candidate_shard_ids", ()),
        ("completed_judgment_count", 0),
        ("combined_accounted_cost_usd", Decimal("0")),
        ("judgment_accounted_cost_usd", Decimal("0")),
    ],
)
async def test_result_cannot_hide_original_gaps_or_change_review_costs(tmp_path, field, value):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, fail_at=3, carry=True)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=manifest_judgment_payload(len(calls)))

    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    changed = result.model_dump()
    changed[field] = value
    with pytest.raises(ValueError):
        DevelopmentCorpusJudgmentObservation.model_validate(changed)


@pytest.mark.asyncio
async def test_individual_retained_review_rejects_candidate_coordinates_outside_its_manifest(
    tmp_path,
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=manifest_judgment_payload(len(calls)))

    result = await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    data = result.observations[0].model_dump(mode="json")
    data["claims"][0]["finding"]["line_end"] = 10000
    with pytest.raises(ValueError):
        DevelopmentCorpusJudgmentShardObservation.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    ["consent", "truthy_consent", "prepared", "plan", "shards", "ledger", "secrets", "transport"],
)
async def test_exact_runner_types_and_consent_refuse_before_output_or_dispatch(tmp_path, kind):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("invalid runner input dispatched")

    args = dict(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "review",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(forbidden),
    )
    if kind in {"consent", "truthy_consent"}:
        args["allow_code_egress"] = False if kind == "consent" else 1
    elif kind == "prepared":
        args["prepared"] = {}
    elif kind == "plan":
        args["prepared"] = replace(prepared, plan=prepared.plan.model_dump())
    elif kind == "shards":
        args["prepared"] = replace(prepared, shards=list(prepared.shards))
    else:
        args[
            {"ledger": "ledger", "secrets": "operator_secrets", "transport": "mock_transport"}[kind]
        ] = object()
    with pytest.raises(ValueError):
        await run_development_corpus_judgment(**args)
    assert ledger.path.read_bytes() == before and not (tmp_path / "review").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["mapping", "whole_plan", "consent"])
async def test_exact_shard_wrapper_refuses_invalid_prepared_input(tmp_path, kind):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    before = ledger.path.read_bytes()

    def forbidden(_request):
        pytest.fail("invalid shard input dispatched")

    shard = {} if kind == "mapping" else prepared if kind == "whole_plan" else prepared.shards[0]
    with pytest.raises(ValueError):
        await review_development_corpus_judgment_shard(
            prepared=shard,
            ledger=ledger,
            operator_secrets=secrets,
            allow_code_egress=kind != "consent",
            mock_transport=httpx.MockTransport(forbidden),
        )
    assert ledger.path.read_bytes() == before


@pytest.mark.asyncio
async def test_later_review_inherits_only_remaining_parent_time(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, run_seconds=2, timeout=360)
    calls = []

    async def delayed(request):
        calls.append(request)
        await asyncio.sleep(0.8 if len(calls) == 1 else 1.4)
        return httpx.Response(200, json=manifest_judgment_payload(len(calls)))

    result = await asyncio.wait_for(
        execute(prepared, ledger, secrets, tmp_path / "review", delayed), timeout=5
    )
    assert len(calls) == 2 and result.completed_judgment_count == 1
    assert result.status == "INCOMPLETE" and result.stop_reason == "LOCAL_FAILURE"
    assert [a.status for a in result.accounting] == [
        CostEntryStatus.RECONCILED,
        CostEntryStatus.UNCERTAIN_ACCOUNTED,
    ]
    assert result.unreviewed_claim_ids == ("file-0002:01", "file-0003:01", "file-0004:01")


@pytest.mark.asyncio
async def test_original_candidate_ledger_is_rechecked_before_every_dispatch(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []
    removed_id = prepared.plan.candidate.accounting[0].ledger_request_id
    mutations = []

    def handler(request):
        calls.append(request)
        state = json.loads(ledger.path.read_bytes())
        del state["entries"][removed_id]
        ledger.path.write_text(json.dumps(state))
        mutations.append(removed_id)
        return httpx.Response(200, json=manifest_judgment_payload(1))

    with pytest.raises(ValueError):
        await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    assert mutations == [removed_id] and len(calls) == 1
    assert len(ledger.snapshot().entries) == 4
    assert (tmp_path / "review/file-0001.json").is_file()
    assert not (tmp_path / "review/result.json").exists()


@pytest.mark.asyncio
async def test_replay_cannot_reuse_existing_charged_review_request_ids(tmp_path):
    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=manifest_judgment_payload(len(calls)))

    await execute(prepared, ledger, secrets, tmp_path / "review", handler)
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError):
        await execute(prepared, ledger, secrets, tmp_path / "replay", handler)
    assert len(calls) == 4 and ledger.path.read_bytes() == before
    assert not (tmp_path / "replay").exists()


@pytest.mark.asyncio
async def test_composed_artifact_size_refusal_occurs_before_paid_dispatch(tmp_path, monkeypatch):
    import mmaudit.orchestration.development_corpus_judgment as runner

    prepared, ledger, secrets = await candidate_inputs(tmp_path)
    before = ledger.path.read_bytes()
    assert runner.MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES == 64_000_000
    monkeypatch.setattr(runner, "MAX_DEVELOPMENT_CORPUS_JUDGMENT_ARTIFACT_BYTES", 1)

    def forbidden(_request):
        pytest.fail("oversized composed artifact dispatched")

    with pytest.raises(ValueError):
        await execute(prepared, ledger, secrets, tmp_path / "review", forbidden)
    assert ledger.path.read_bytes() == before and not (tmp_path / "review/result.json").exists()


@pytest.mark.asyncio
async def test_retained_candidate_finalization_failure_stays_incomplete_without_source_gaps(
    tmp_path,
):
    prepared, ledger, secrets = await candidate_inputs(tmp_path, claims=0)
    # Explicit synthetic retained-record variant, not an executed candidate failure.
    data = prepared.plan.candidate.model_dump()
    data.update(status="INCOMPLETE", stop_reason="LOCAL_FAILURE")
    original = DevelopmentCorpusObservation.model_validate(data)
    prepared = prepare_development_corpus_judgment(
        candidate=original,
        policy=prepared.plan.policy,
        endpoint_snapshot=prepared.endpoint_snapshot,
        source_files=prepared.source_files,
        run_id="retained-finalization-failure",
    )

    def forbidden(_request):
        pytest.fail("empty observed source acquired a review request")

    before = ledger.path.read_bytes()
    result = await execute(prepared, ledger, secrets, tmp_path / "review", forbidden)
    assert result.status == "INCOMPLETE" and result.stop_reason == "CANDIDATE_INCOMPLETE"
    assert not result.unobserved_candidate_shard_ids and not result.unreviewed_claim_ids
    assert result.plan.candidate == original and ledger.path.read_bytes() == before
