"""Cancellation preserves durable paid evidence and never clears an uncertain-billing stop."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from mmaudit.orchestration import development_tree as module
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from tests.integration.test_development_tree_execution import execution
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


@pytest.mark.asyncio
async def test_cancel_after_durable_candidate_recovers_it_then_resumes_without_replay(
    tmp_path, monkeypatch
):
    inputs, arguments, calls = execution(tmp_path)
    original = module.run_development_corpus
    interrupted = False

    async def stop_once(**kwargs):
        nonlocal interrupted
        observed = await original(**kwargs)
        if not interrupted:
            interrupted = True
            raise asyncio.CancelledError
        return observed

    monkeypatch.setattr(module, "run_development_corpus", stop_once)
    with pytest.raises(asyncio.CancelledError):
        await module.run_development_tree_plan(**arguments)
    assert len(calls) == 1
    root = arguments["output_dir"] / "cases/case-0001/run"
    retained_candidate = (root / "candidate/result.json").read_bytes()
    end = json.loads((root / "candidate-end.json").read_bytes())
    assert end["result_file"]["path"] == "candidate/result.json"
    before = arguments["ledger"].snapshot().entries
    arguments["loaded"] = reopen(inputs)
    progress = await module.run_development_tree_plan(**arguments, resume=True)
    assert progress.status == "OBSERVED_ALL_AVAILABLE_STAGES" and len(calls) == 15
    assert (root / "candidate/result.json").read_bytes() == retained_candidate
    entries = {e.request_id: e for e in arguments["ledger"].snapshot().entries}
    assert len(entries) == 15 and all(entries[e.request_id] == e for e in before)


@pytest.mark.asyncio
async def test_cancel_inside_transport_keeps_unknown_charge_and_blocks_any_next_call(tmp_path):
    inputs, arguments, _ = execution(tmp_path)
    requests = []

    async def interrupted(request):
        requests.append(request)
        raise asyncio.CancelledError

    arguments["mock_transport"] = httpx.MockTransport(interrupted)
    with pytest.raises(asyncio.CancelledError):
        await module.run_development_tree_plan(**arguments)
    before = arguments["ledger"].snapshot()
    assert len(requests) == len(before.entries) == 1
    assert before.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert before.entries[0].actual_cost_usd is None
    assert before.entries[0].accounted_cost_usd == before.entries[0].reserved_usd
    assert (arguments["output_dir"] / "cases/case-0001/run/candidate/result.json").is_file()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError, match="uncertain billing"):
        await module.run_development_tree_plan(**arguments, resume=True)
    assert len(requests) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.asyncio
async def test_plan_drift_after_paid_candidate_keeps_charge_and_cannot_close_its_interval(
    tmp_path, monkeypatch
):
    _, arguments, calls = execution(tmp_path)
    original = module.run_development_corpus
    plan_file = arguments["loaded"].directory.path / "plan.json"

    async def change_after_result(**kwargs):
        result = await original(**kwargs)
        plan_file.write_bytes(plan_file.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(module, "run_development_corpus", change_after_result)
    with pytest.raises(ValueError):
        await module.run_development_tree_plan(**arguments)
    snapshot = arguments["ledger"].snapshot()
    assert len(calls) == len(snapshot.entries) == 1
    assert snapshot.entries[0].status is CostEntryStatus.RECONCILED
    assert snapshot.entries[0].actual_cost_usd is not None
    root = arguments["output_dir"] / "cases/case-0001/run"
    assert (root / "candidate/result.json").is_file()
    assert (root / "candidate-start.json").is_file()
    assert not (root / "candidate-end.json").exists()


@pytest.mark.asyncio
async def test_receipt_cannot_understate_the_durable_childs_elapsed_interval(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    root = arguments["output_dir"] / "cases/case-0001/run"
    receipt = root / "candidate-end.json"
    value = json.loads(receipt.read_bytes())
    candidate = json.loads((root / "candidate/result.json").read_bytes())
    assert candidate["elapsed_seconds"] > 0
    value["elapsed_seconds"] = 0.0
    receipt.write_text(json.dumps(value))
    before = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError, match="interval"):
        await module.run_development_tree_plan(
            **arguments, resume=True, maximum_stages_per_invocation=1
        )
    assert len(calls) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.asyncio
async def test_closed_pre_dispatch_failure_is_not_counted_as_a_paid_attempt(tmp_path, monkeypatch):
    _, arguments, calls = execution(tmp_path)
    original = module.run_development_corpus

    async def expire_before_dispatch(**kwargs):
        kwargs["parent_deadline"] = module.time.monotonic() - 1.0
        return await original(**kwargs)

    monkeypatch.setattr(module, "run_development_corpus", expire_before_dispatch)
    progress = await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    assert calls == [] and arguments["ledger"].snapshot().entries == ()
    assert progress.completed_attempt_count == 0
    assert progress.primary_statuses[0].completed_attempt_count == 0
    assert progress.primary_statuses[0].status == "CANDIDATE_INCOMPLETE"
    assert progress.status == "INCOMPLETE" and not progress.audit_complete
    assert progress.coverage.not_successfully_observed_paths


@pytest.mark.asyncio
async def test_active_stage_interval_includes_between_stage_input_and_accounting_checks(
    tmp_path, monkeypatch
):
    _, arguments, calls = execution(tmp_path)
    real_clock = module.time.monotonic
    original_guard = module._accounting_guard
    offset = 0.0
    active_clock_started = False
    delay_injected = False

    def active_clock():
        nonlocal active_clock_started
        active_clock_started = True
        return real_clock() + offset

    def accounting_guard(*args):
        nonlocal offset, delay_injected
        # Offline guards may run before bundle preparation; delay the first active check.
        if active_clock_started and not delay_injected:
            offset += 2.0
            delay_injected = True
        return original_guard(*args)

    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=active_clock))
    monkeypatch.setattr(module, "_accounting_guard", accounting_guard)
    progress = await module.run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    assert delay_injected
    assert len(calls) == progress.completed_attempt_count == 1
    assert progress.elapsed_active_seconds >= 2.0
    root = arguments["output_dir"] / "cases/case-0001/run"
    end = json.loads((root / "candidate-end.json").read_bytes())
    assert end["elapsed_seconds"] >= 2.0
