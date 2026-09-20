"""Observe the recovery quiescence/cost boundary through local MockTransport only."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from mmaudit.constants import ExitCode
from mmaudit.models.scheduler import (
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerTaskEvent,
    SchedulerTaskEventKind,
    SchedulerTaskResult,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.fake_openrouter import FakeOpenRouter
from tests.integration.test_pipeline import _run
from tests.integration.test_scheduler_truncation_recovery_pipeline import (
    _assert_resume_retains_exact_scheduler_journal,
    _one_whole_protocol_config,
    _recovery_entries,
)


class _ObserveBlindTerminalBarrier(FakeOpenRouter):
    """Read the fixture's durable results at dispatch, without replacing runtime gates."""

    def __init__(self, output: Path, ledger: AtomicCostLedger) -> None:
        super().__init__(mode="truncation_recovery")
        self._output = output
        self._ledger = ledger
        self.observations: list[tuple[tuple[str, str], ...]] = []
        self.observer_error: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            body = json.loads(request.content)
            request_id = (body.get("metadata") or {}).get("mmaudit_request_id", "")
            if isinstance(request_id, str) and request_id.startswith("scheduler-recovery-request-"):
                try:
                    self._observe_terminal_barrier()
                except Exception as error:
                    self.observer_error = error
                    raise
        return super().handler(request)

    def _observe_terminal_barrier(self) -> None:
        roots = tuple((self._output / "runs").glob("*/private/scheduler-journal"))
        assert len(roots) == 1
        root = roots[0]
        plan = SchedulerPassPlan.model_validate_json(
            (root / "pass-plans" / "pass-02-plan.json").read_bytes()
        )
        assert plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
        assert len(plan.tasks) >= 4
        results = {
            result.task_id: result
            for path in (root / "task-results").glob("*.json")
            for result in (SchedulerTaskResult.model_validate_json(path.read_bytes()),)
        }
        terminal_events = {
            event.task_id: event
            for path in sorted((root / "events").glob("*.json"))
            for event in (SchedulerTaskEvent.model_validate_json(path.read_bytes()),)
            if event.kind
            in {
                SchedulerTaskEventKind.TERMINAL,
                SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            }
        }
        # Named invariant: no recovery dispatch precedes any main blind terminal commit.
        assert {task.task_id for task in plan.tasks} <= results.keys()
        assert {task.task_id for task in plan.tasks} <= terminal_events.keys()
        for task in plan.tasks:
            assert terminal_events[task.task_id].task_result_sha256 == (
                results[task.task_id].result_sha256
            )
        self.observations.append(
            tuple(
                sorted((task.task_id, results[task.task_id].result_sha256) for task in plan.tasks)
            )
        )

        main_charges = tuple(
            entry
            for entry in self._ledger.snapshot().entries
            if not entry.request_id.startswith("scheduler-recovery-request-")
        )
        dispatched_ids = {
            task.logical_request_id
            for task in plan.tasks
            if terminal_events[task.task_id].kind is SchedulerTaskEventKind.TERMINAL
        }
        preflight_ids = {task.logical_request_id for task in plan.tasks} - dispatched_ids
        assert dispatched_ids and preflight_ids
        assert dispatched_ids <= {entry.request_id for entry in main_charges}
        assert preflight_ids.isdisjoint(entry.request_id for entry in main_charges)
        assert all(entry.actual_cost_usd == entry.accounted_cost_usd for entry in main_charges)
        families = [
            entry
            for entry in _recovery_entries(root.parent.parent)
            if entry["entry_kind"] == "FAMILY_ROOT"
        ]
        assert len(families) == 1
        resources = families[0]["recovery_plan"]["resources"]
        # Every ordinary known charge must already be included in the frozen reservation inputs.
        assert sum((entry.accounted_cost_usd for entry in main_charges), Decimal("0")) == (
            Decimal(resources["accounted_usd_before_parent_exact"])
            + Decimal(resources["parent_accounted_cost_usd_exact"])
        )


@pytest.mark.asyncio
async def test_recovery_dispatch_observes_all_blind_terminals_and_exact_main_costs(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _one_whole_protocol_config(config_factory, monkeypatch)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=Decimal(str(config.execution.budget_usd))
    )
    output = tmp_path / "output"
    fake = _ObserveBlindTerminalBarrier(output, ledger)
    try:
        first = await _run(
            config, vulnerable_repo, tmp_path, fake, cost_ledger=ledger, output=output
        )
    except Exception:
        if fake.observer_error is not None:
            raise AssertionError("mock dispatch observer failed") from fake.observer_error
        raise
    assert first.exit_code is ExitCode.INCOMPLETE
    assert not first.report.completed
    assert fake.truncated_parent_calls == 1
    assert fake.recovery_child_calls == len(fake.observations) == 2
    assert fake.observations[0] == fake.observations[1]
    entries = _recovery_entries(first.run_dir)
    assert not any(entry["entry_kind"] == "FAMILY_PROMOTED" for entry in entries)
    snapshot = ledger.snapshot()
    recovery_charges = tuple(
        entry
        for entry in snapshot.entries
        if entry.request_id.startswith("scheduler-recovery-request-")
    )
    assert len(recovery_charges) == 2
    assert all(entry.actual_cost_usd == entry.accounted_cost_usd for entry in recovery_charges)
    assert sum((entry.accounted_cost_usd for entry in recovery_charges), Decimal("0")) == (
        Decimal("0.002")
    )

    resumed_fake = FakeOpenRouter(mode="truncation_recovery")
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
        output=output,
    )
    assert resumed.exit_code is ExitCode.INCOMPLETE
    assert not resumed.report.completed
    assert resumed_fake.chat_calls == resumed_fake.recovery_child_calls == 0
    assert ledger.snapshot() == snapshot
    assert _recovery_entries(first.run_dir) == entries
    _assert_resume_retains_exact_scheduler_journal(owner=first.run_dir, consumer=resumed.run_dir)
