from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal

import httpx
import pytest

import mmaudit.orchestration.development_audit as runner_module
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    DevelopmentAuditPlan,
    DevelopmentAuditShardObservation,
    development_ledger_request_id,
)
from mmaudit.models.development_transport import (
    DEVELOPMENT_COMPLETION_URL,
    review_development_audit_shard,
    review_development_fixture,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
)
from mmaudit.orchestration.development_audit import DevelopmentAuditError, run_development_audit
from tests.development_audit_support import audit_case, shard_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL, local_controls, review_case


@pytest.fixture(autouse=True)
def no_network_or_commands(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("synthetic audit must never network or execute model output")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


@pytest.fixture
def controls(tmp_path):
    ledger, secrets = local_controls(tmp_path)
    return dict(
        prepared=audit_case(),
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "observations",
        allow_code_egress=True,
    )


def read_result(output_dir):
    return DevelopmentAuditObservation.model_validate_json(
        (output_dir / "result.json").read_bytes()
    )


@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize("discovery", [False, True])
async def test_exact_sequential_requests_have_reserved_cost_and_durable_prior_outputs(
    controls, variant, discovery
):
    prepared = audit_case(variant=variant, discovery=discovery)
    controls["prepared"] = prepared
    ledger = controls["ledger"]
    output = controls["output_dir"]
    calls = []
    prior = {}

    def handler(request):
        index = len(calls)
        shard = prepared.shards[index]
        state = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20")).snapshot()
        assert len(state.entries) == index + 1
        entry = next(e for e in state.entries if e.status is CostEntryStatus.RESERVED)
        assert entry.request_id == development_ledger_request_id(shard.estimate.request_id)
        assert state.active_reserved_usd == shard.estimate.estimated_cost_per_attempt_usd
        assert state.spent_usd == Decimal("0.01") * index
        assert request.content == shard.request_content
        assert hashlib.sha256(request.content).hexdigest() == shard.estimate.request_sha256
        assert str(request.url) == DEVELOPMENT_COMPLETION_URL
        assert request.headers["authorization"] == "Bearer " + SYNTHETIC_CREDENTIAL
        assert DevelopmentAuditPlan.model_validate_json((output / "plan.json").read_bytes()) == (
            prepared.plan
        )
        for earlier in prepared.shards[:index]:
            path = output / (earlier.shard_id + ".json")
            content = path.read_bytes()
            assert prior.setdefault(path, content) == content
            assert (
                DevelopmentAuditShardObservation.model_validate_json(content).status == "OBSERVED"
            )
        assert not (output / "result.json").exists()
        calls.append(request)
        return httpx.Response(200, json=shard_payload(index + 1, empty=variant == "b"))

    result = await run_development_audit(**controls, mock_transport=httpx.MockTransport(handler))
    assert read_result(output) == result
    assert len(calls) == result.completed_shard_count == 3
    assert result.status == "OBSERVED_ALL_SHARDS" and result.unobserved_shard_ids == ()
    assert result.total_accounted_cost_usd == ledger.snapshot().spent_usd == Decimal("0.03")
    assert result.active_reserved_usd == 0
    assert (output.stat().st_mode & 0o777) == 0o700
    assert {p.name for p in output.iterdir()} == {
        "plan.json",
        "file-01.json",
        "file-02.json",
        "file-03.json",
        "result.json",
    }
    for path in output.iterdir():
        assert (path.stat().st_mode & 0o077) == 0
        assert SYNTHETIC_CREDENTIAL not in path.read_text()
    assert (
        result.audit_complete is result.qualification_eligible is result.release_eligible is False
    )
    assert result.findings_validated is False


@pytest.mark.parametrize("bad_index", [1, 2, 3])
@pytest.mark.parametrize("failure", ["unknown_cost", "overrun", "routing", "line", "truncated"])
async def test_first_incomplete_shard_stops_dispatch_and_preserves_all_incurred_costs(
    controls, bad_index, failure
):
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        payload = shard_payload(calls)
        if calls == bad_index:
            if failure == "unknown_cost":
                del payload["usage"]["cost"]
            elif failure == "overrun":
                payload["usage"]["cost"] = 1
            elif failure == "routing":
                payload["provider"] = "Wrong Provider"
            elif failure == "truncated":
                payload["choices"][0]["finish_reason"] = "length"
            else:
                body = json.loads(payload["choices"][0]["message"]["content"])
                body["findings"][0]["line_end"] = 999
                payload["choices"][0]["message"]["content"] = json.dumps(body)
        return httpx.Response(200, json=payload)

    result = await run_development_audit(**controls, mock_transport=httpx.MockTransport(handler))
    assert calls == bad_index and result.completed_shard_count == bad_index - 1
    assert result.status == "INCOMPLETE" and result.stop_reason == "SHARD_INCOMPLETE"
    assert result.observations[-1].response is None
    assert result.unobserved_shard_ids == tuple(f"file-0{i}" for i in range(bad_index, 4))
    assert read_result(controls["output_dir"]) == result
    status = {
        "unknown_cost": CostEntryStatus.UNCERTAIN_ACCOUNTED,
        "overrun": CostEntryStatus.RESERVATION_OVERRUN,
    }.get(failure, CostEntryStatus.RECONCILED)
    assert result.accounting[-1].status is status
    expected_last = (
        controls["prepared"].shards[bad_index - 1].estimate.estimated_cost_per_attempt_usd
        if failure == "unknown_cost"
        else Decimal(1)
        if failure == "overrun"
        else Decimal("0.01")
    )
    assert result.total_accounted_cost_usd == expected_last + Decimal("0.01") * (bad_index - 1)
    assert result.total_accounted_cost_usd == controls["ledger"].snapshot().spent_usd
    assert result.active_reserved_usd == 0


async def test_reused_generation_cannot_cover_two_primary_files(controls):
    result = await run_development_audit(
        **controls,
        mock_transport=httpx.MockTransport(lambda _: httpx.Response(200, json=shard_payload(1))),
    )
    assert result.completed_shard_count == 1 and len(result.observations) == 2
    assert result.observations[-1].diagnostics == ("IDENTITY_MISMATCH",)
    assert result.observations[-1].routing_evidence.failure_codes == ("GENERATION_REUSE",)
    assert result.observations[-1].response is None
    assert result.total_accounted_cost_usd == Decimal("0.02")


@pytest.mark.parametrize("failure", ["hold", "uncertain", "overrun", "remaining", "replay"])
async def test_cumulative_preflight_refuses_before_output_creation_or_dispatch(controls, failure):
    ledger = controls["ledger"]
    request_id = (
        development_ledger_request_id(controls["prepared"].shards[0].estimate.request_id)
        if failure == "replay"
        else "synthetic-prior-request"
    )
    reservation = ledger.reserve(
        request_id, Decimal("19.9") if failure == "remaining" else Decimal(1)
    )
    if failure in {"remaining", "replay"}:
        ledger.reconcile(reservation, reservation.reserved_usd)
    elif failure == "uncertain":
        ledger.reconcile(reservation, None)
    elif failure == "overrun":
        with pytest.raises(CostReservationOverrunError):
            ledger.reconcile(reservation, Decimal(2))
    before = ledger.path.read_bytes()
    with pytest.raises(DevelopmentAuditError, match="cumulative accounting"):
        await run_development_audit(
            **controls, mock_transport=httpx.MockTransport(lambda _: pytest.fail("dispatched"))
        )
    assert ledger.path.read_bytes() == before
    assert not controls["output_dir"].exists()


@pytest.mark.parametrize(
    "failure",
    [
        "existing_output",
        "linked_parent",
        "no_consent",
        "deadline",
        "request",
        "plan_type",
        "shard_type",
    ],
)
async def test_unsafe_run_controls_refuse_without_spending(controls, failure, tmp_path):
    output = controls["output_dir"]
    if failure == "existing_output":
        output.mkdir()
        (output / "sentinel.txt").write_text("owned synthetic sentinel")
    elif failure == "linked_parent":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        controls["output_dir"] = alias / "new-output"
    elif failure == "no_consent":
        controls["allow_code_egress"] = False
    elif failure == "deadline":
        controls["maximum_run_seconds"] = float("inf")
    else:
        prepared = controls["prepared"]
        controls["prepared"] = (
            replace(prepared, plan=None)
            if failure == "plan_type"
            else replace(prepared, shards=(None, *prepared.shards[1:]))
            if failure == "shard_type"
            else replace(
                prepared,
                shards=(replace(prepared.shards[0], request_content=b"{}"), *prepared.shards[1:]),
            )
        )
    before = controls["ledger"].path.read_bytes()
    with pytest.raises((ValueError, OSError)):
        await run_development_audit(
            **controls, mock_transport=httpx.MockTransport(lambda _: pytest.fail("dispatched"))
        )
    assert controls["ledger"].path.read_bytes() == before
    if failure == "existing_output":
        assert (output / "sentinel.txt").read_text() == "owned synthetic sentinel"
        assert {p.name for p in output.iterdir()} == {"sentinel.txt"}


@pytest.mark.parametrize("interruption", ["cancel", "deadline"])
async def test_interruption_retains_prior_output_and_blocking_unknown_cost(controls, interruption):
    entered = asyncio.Event()
    never = asyncio.Event()
    calls = 0

    async def handler(_request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(200, json=shard_payload(1))
        entered.set()
        await never.wait()
        raise AssertionError("interrupted synthetic request returned")

    if interruption == "deadline":
        controls["maximum_run_seconds"] = 0.2
    task = asyncio.create_task(
        run_development_audit(**controls, mock_transport=httpx.MockTransport(handler))
    )
    await asyncio.wait_for(entered.wait(), timeout=5)
    if interruption == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await asyncio.wait_for(task, timeout=5)
    result = read_result(controls["output_dir"])
    assert calls == 2 and result.completed_shard_count == 1
    assert result.status == "INCOMPLETE"
    assert result.stop_reason == ("INTERRUPTED" if interruption == "cancel" else "LOCAL_FAILURE")
    assert len(result.observations) == 1 and len(result.accounting) == 2
    assert result.accounting[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert result.total_accounted_cost_usd == Decimal("0.01") + result.accounting[-1].reserved_usd
    assert result.active_reserved_usd == 0


async def test_failed_cost_persistence_leaves_an_active_hold_and_stops_all_dispatch(
    controls, monkeypatch
):
    def fail_reconciliation(*_args, **_kwargs):
        raise OSError("synthetic ledger persistence failure")

    monkeypatch.setattr(AtomicCostLedger, "reconcile", fail_reconciliation)
    result = await run_development_audit(
        **controls,
        mock_transport=httpx.MockTransport(lambda _: httpx.Response(200, json=shard_payload(1))),
    )
    assert read_result(controls["output_dir"]) == result
    assert result.stop_reason == "LOCAL_FAILURE" and result.observations == ()
    assert len(result.accounting) == 1 and result.accounting[0].status is CostEntryStatus.RESERVED
    assert result.total_accounted_cost_usd == 0
    assert result.active_reserved_usd == result.accounting[0].reserved_usd
    assert controls["ledger"].snapshot().active_reserved_usd == result.active_reserved_usd


async def test_shard_publication_failure_stops_next_request_but_retains_known_observation(
    controls, monkeypatch
):
    original = runner_module._write

    def fail_shard(output_dir, filename, model):
        if filename == "file-01.json":
            raise OSError("synthetic output failure")
        return original(output_dir, filename, model)

    monkeypatch.setattr(runner_module, "_write", fail_shard)
    result = await run_development_audit(
        **controls,
        mock_transport=httpx.MockTransport(lambda _: httpx.Response(200, json=shard_payload(1))),
    )
    assert result.stop_reason == "LOCAL_FAILURE" and len(result.observations) == 1
    assert result.total_accounted_cost_usd == Decimal("0.01")
    assert read_result(controls["output_dir"]) == result
    assert not (controls["output_dir"] / "file-01.json").exists()


@pytest.mark.parametrize("drift", ["plan", "root_mode", "root_swap", "prior_shard"])
async def test_output_custody_drift_refuses_publication_and_further_dispatch(controls, drift):
    output = controls["output_dir"]
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        if drift == "plan":
            (output / "plan.json").write_text("{}")
        elif drift == "root_mode":
            output.chmod(0o755)
        elif drift == "root_swap":
            output.rename(output.with_name("retained-original"))
            output.mkdir(mode=0o700)
        elif calls == 2:
            (output / "file-01.json").write_text("{}")
        return httpx.Response(200, json=shard_payload(calls))

    with pytest.raises(DevelopmentAuditError, match="could not be finalized"):
        await run_development_audit(**controls, mock_transport=httpx.MockTransport(handler))
    assert calls == (2 if drift == "prior_shard" else 1)
    assert controls["ledger"].snapshot().spent_usd == Decimal("0.01") * calls
    assert not (output / "result.json").exists()


@pytest.mark.parametrize("wrong_type", ["fixture", "audit", "changed_audit"])
async def test_transport_entrypoints_rebuild_and_refuse_cross_scope_types(controls, wrong_type):
    first = controls["prepared"].shards[0]
    transport = (
        review_development_fixture if wrong_type == "fixture" else review_development_audit_shard
    )
    prepared = first if wrong_type == "fixture" else review_case()
    if wrong_type == "changed_audit":
        prepared = replace(first, request_content=b"{}")
    with pytest.raises(ValueError):
        await transport(
            prepared=prepared,
            ledger=controls["ledger"],
            operator_secrets=controls["operator_secrets"],
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(lambda _: pytest.fail("dispatched")),
        )
    assert controls["ledger"].snapshot().entries == ()
