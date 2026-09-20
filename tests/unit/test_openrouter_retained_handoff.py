"""Explicit nonauthorizing adapter protocol doubles, not native runner issuance."""

from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mmaudit.orchestration.authenticated_calibration_accounting as accounting
import mmaudit.orchestration.authenticated_runner_openrouter as adapter
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerError,
    CrossLineageRunnerRunCustody,
    VerifiedCrossLineageRunnerCustody,
)
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit import test_authenticated_runner_openrouter as fixtures


@dataclass
class HandoffState:
    execution: Any
    launch: Any
    secrets: OperatorSecrets
    ledger: AtomicCostLedger
    owner: Any
    successor: Any
    moved_runs: tuple[Any, ...]
    events: list[str]
    live: set[Any]
    fail: str | None = None


@pytest.fixture
def handoff_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    owner = accounting.begin_calibration_ledger_accounting(ledger)
    execution = fixtures._completed_execution()
    state = HandoffState(
        execution,
        replace(fixtures._structural_launch(), budget=SimpleNamespace(atomic_ledger=ledger)),
        OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-key"}),
        ledger,
        owner,
        object.__new__(VerifiedCrossLineageRunnerCustody),
        tuple(object.__new__(CrossLineageRunnerRunCustody) for _ in execution.runs),
        [],
        {execution.runner_capability},
    )
    fixtures._install_completed_runner(monkeypatch, execution)

    def require(cap: Any, *, evidence: Any) -> Any:
        assert evidence is execution.runner_evidence
        if cap not in state.live:
            raise AuthenticatedCrossLineageRunnerError(adapter._REVOKED_RUNNER_CUSTODY_DETAIL)
        if cap is state.successor and state.fail == "verification":
            raise ValueError("synthetic successor verification failure")
        return execution.runner_projection

    def revoke(cap: Any) -> None:
        state.events.append("revoke-successor" if cap is state.successor else "revoke-original")
        state.live.remove(cap)

    def retain(cap: Any, *, evidence: Any, accounting: Any) -> Any:
        assert cap is execution.runner_capability and evidence is execution.runner_evidence
        assert accounting is owner
        state.events.append("retain")
        if state.fail == "transition":
            raise ValueError("synthetic transition failure")
        state.live.remove(cap)
        state.live.add(state.successor)
        return state.successor, state.moved_runs if state.fail != "shape" else ()

    original_close = adapter._OpenRouterExecutionAdapter.close

    async def close(instance: Any) -> None:
        if not instance._closed:
            state.events.append("close")
        await original_close(instance)
        if state.fail == "close":
            raise ValueError("synthetic close failure")

    fixtures._install_lifecycle_doubles(monkeypatch, require=require, revoke=revoke)
    monkeypatch.setattr(adapter, "_TRUSTED_RETAIN_RUNNER_CUSTODY", retain)
    monkeypatch.setattr(adapter, "retain_verified_cross_lineage_runner_custody", retain)
    monkeypatch.setattr(
        adapter._runner_authority_module, "retain_verified_cross_lineage_runner_custody", retain
    )
    monkeypatch.setattr(adapter._OpenRouterExecutionAdapter, "close", close)
    try:
        yield state
    finally:
        accounting.close_calibration_ledger_accounting(owner)


@pytest.mark.asyncio
async def test_successor_is_owned_before_yield_and_original_inputs_are_preserved(
    handoff_state: HandoffState,
) -> None:
    state = handoff_state
    async with adapter._owned_authenticated_openrouter_runner_scope(
        launch=state.launch, operator_secrets=state.secrets, _accounting=state.owner
    ) as execution:
        assert execution.runner_capability is state.successor
        assert state.execution.runner_capability not in state.live
        assert state.secrets.cleared
        assert state.events == ["retain", "close"]
        for field in (
            "inventory",
            "closed_ledger_interval",
            "runner_evidence",
            "runner_projection",
        ):
            assert getattr(execution, field) is getattr(state.execution, field)
        for item, old, custody in zip(
            execution.runs, state.execution.runs, state.moved_runs, strict=True
        ):
            assert item.custody is custody
            for field in ("candidate_cost_plan", "judge_cost_plan", "prepared_adjudication"):
                assert getattr(item, field) is getattr(old, field)
    assert state.live == set()
    assert state.events == ["retain", "close", "revoke-successor"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("transition", "verification", "shape", "close"))
async def test_every_failed_handoff_disposes_the_handle_it_actually_owns(
    handoff_state: HandoffState, failure: str
) -> None:
    state = handoff_state
    state.fail = failure
    with pytest.raises(ValueError):
        async with adapter._owned_authenticated_openrouter_runner_scope(
            launch=state.launch, operator_secrets=state.secrets, _accounting=state.owner
        ):
            pytest.fail("failed handoff yielded")
    expected = "revoke-original" if failure == "transition" else "revoke-successor"
    assert expected in state.events
    assert state.live == set()
    assert state.secrets.cleared


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("unissued-owner", "foreign-ledger", "unknown-bill", "binding"))
async def test_retention_refusal_happens_before_execution(
    handoff_state: HandoffState, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str
) -> None:
    state = handoff_state
    owner, launch = state.owner, state.launch
    if kind == "unissued-owner":
        owner = object.__new__(accounting.CalibrationLedgerAccounting)
    elif kind == "foreign-ledger":
        foreign = AtomicCostLedger.initialize(tmp_path / "other.json", cap_usd=Decimal("250"))
        launch = replace(launch, budget=SimpleNamespace(atomic_ledger=foreign))
    elif kind == "unknown-bill":
        pending = state.ledger.reserve("synthetic-unknown", Decimal("1"))
        state.ledger.commit_for_transport(pending)
        state.ledger.reconcile(pending, None)
    else:
        monkeypatch.setattr(adapter, "retain_verified_cross_lineage_runner_custody", object())
    with pytest.raises(ValueError):
        async with adapter._owned_authenticated_openrouter_runner_scope(
            launch=launch, operator_secrets=state.secrets, _accounting=owner
        ):
            pytest.fail("ineligible retention yielded")
    assert state.events == []
    assert state.secrets.cleared
