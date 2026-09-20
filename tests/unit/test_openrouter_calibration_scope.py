"""Batch ownership protocol stand-ins with a genuine local immutable cost ledger."""

from __future__ import annotations

import asyncio
import pickle
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mmaudit.orchestration.authenticated_calibration_accounting as accounting
import mmaudit.orchestration.authenticated_calibration_openrouter as batch_module
from mmaudit.models.authenticated_runner import (
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
)
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
)
from tests.unit import test_authenticated_runner_openrouter as fixtures


@dataclass
class BatchState:
    ledger: AtomicCostLedger
    launches: tuple[Any, ...]
    secrets: tuple[OperatorSecrets, ...]
    events: list[str] = field(default_factory=list)
    live: dict[Any, Any] = field(default_factory=dict)
    executions: list[Any] = field(default_factory=list)
    owner: Any = None
    fail_preflight: int | None = None
    fail_launch: int | None = None
    fail_cleanup: int | None = None
    wrong_model: bool = False


@pytest.fixture
def batch_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BatchState:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-batch.json", cap_usd=Decimal("250"))
    base = fixtures._structural_launch()
    launches = tuple(
        replace(
            base,
            budget=SimpleNamespace(atomic_ledger=ledger),
            candidate_registry=SimpleNamespace(
                candidates=(SimpleNamespace(exact_model_id=f"synthetic/model-{i}"),)
            ),
        )
        for i in range(3)
    )
    state = BatchState(
        ledger,
        launches,
        tuple(OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-key"}) for _ in launches),
    )

    def preflight(launch: Any) -> Any:
        index = state.launches.index(launch)
        state.events.append(f"preflight-{index}")
        if state.fail_preflight == index:
            raise ValueError("synthetic launch refusal")
        return fixtures._execution_inventory()

    @asynccontextmanager
    async def owned(*, launch: Any, operator_secrets: OperatorSecrets, _accounting: Any) -> Any:
        index = state.launches.index(launch)
        state.owner = _accounting
        state.events.append(f"dispatch-{index}")
        opened = begin_cross_lineage_ledger_interval(ledger)
        reservation = ledger.reserve(f"synthetic-{index}", Decimal("1"))
        if state.fail_launch == index:
            ledger.commit_for_transport(reservation)
            ledger.reconcile(reservation, None)
            operator_secrets.clear()
            raise ValueError("synthetic attempted launch failure")
        ledger.reconcile(reservation, Decimal("0.25"))
        interval = close_cross_lineage_ledger_interval(
            opened, expected_request_ids=(reservation.request_id,)
        )
        prefix = accounting.retain_calibration_ledger_interval(_accounting, interval=interval)
        execution = fixtures._completed_execution()
        evidence = execution.runner_evidence.model_copy(
            update={
                "runs": (
                    SimpleNamespace(
                        candidate_model_id=(
                            "synthetic/wrong"
                            if state.wrong_model
                            else launch.candidate_registry.candidates[0].exact_model_id
                        )
                    ),
                )
            }
        )
        execution = replace(execution, closed_ledger_interval=interval, runner_evidence=evidence)
        state.live[execution.runner_capability] = (execution, prefix)
        state.executions.append(execution)
        operator_secrets.clear()
        try:
            yield execution
        finally:
            # Accounting is still owned even after a failed later request; observing
            # a liability does not waive it or obstruct revocation of earlier proofs.
            state.events.append(f"revoke-{index}")
            state.live.pop(execution.runner_capability)
            accounting.observe_calibration_ledger_accounting(_accounting)
            if state.fail_cleanup == index:
                raise ValueError("synthetic cleanup failure")

    def require(execution: Any) -> None:
        retained, prefix = state.live[execution.runner_capability]
        assert retained is execution
        accounting.require_calibration_ledger_prefix(prefix)
        state.events.append("verify")

    monkeypatch.setattr(batch_module, "preflight_authenticated_openrouter_launch", preflight)
    monkeypatch.setattr(batch_module, "_owned_authenticated_openrouter_runner_scope", owned)
    monkeypatch.setattr(batch_module, "_require_live_runner_consumption", require)
    return state


def assert_closed(state: BatchState) -> None:
    assert state.live == {}
    assert all(secret.cleared for secret in state.secrets)
    if state.owner is not None:
        with pytest.raises(ValueError, match=r"absent|revoked"):
            accounting.observe_calibration_ledger_accounting(state.owner)


@pytest.mark.asyncio
async def test_all_preflights_precede_sequential_execution_and_reverse_disposal(
    batch_state: BatchState,
) -> None:
    state = batch_state
    async with batch_module.authenticated_openrouter_calibration_scope(
        launches=state.launches, operator_secrets=state.secrets
    ) as batch:
        assert batch.selected_model_ids == tuple(f"synthetic/model-{i}" for i in range(3))
        assert state.events[:6] == [f"preflight-{i}" for i in range(3)] + [
            f"dispatch-{i}" for i in range(3)
        ]
        assert all(secret.cleared for secret in state.secrets)
        assert len(state.live) == len(batch.inputs) == 3
        assert batch.ground_truth is state.launches[0].ground_truth_capability
        for item, execution in zip(batch.inputs, state.executions, strict=True):
            assert item.runner_custody is execution.runner_capability
            assert item.runner_evidence is execution.runner_evidence
            assert item.runs == tuple(run.custody for run in execution.runs)
        with pytest.raises(TypeError, match="cannot be serialized"):
            pickle.dumps(batch)
    assert state.events[-3:] == ["revoke-2", "revoke-1", "revoke-0"]
    assert [entry.actual_cost_usd for entry in state.ledger.snapshot().entries] == [
        Decimal("0.25")
    ] * 3
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ("list", "empty", "wrong-type", "mismatch", "too-many", "aliased-secrets")
)
async def test_invalid_exact_batch_shape_never_preflights(
    batch_state: BatchState, kind: str
) -> None:
    state = batch_state
    launches: Any = state.launches
    secrets: Any = state.secrets
    if kind == "list":
        launches = list(launches)
    elif kind == "empty":
        launches = ()
    elif kind == "wrong-type":
        launches = (object(), *launches[1:])
    elif kind == "mismatch":
        launches = launches[:1]
    elif kind == "too-many":
        launches = (launches[0],) * 129
    else:
        secrets = (secrets[0],) * 3
    with pytest.raises(ValueError, match="exact bounded launches"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=launches, operator_secrets=secrets
        ):
            pytest.fail("invalid shape yielded")
    assert state.events == []
    assert all(secret.cleared for secret in secrets)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ("runner_custody", "runner_evidence", "runs"))
async def test_native_input_field_substitution_is_rejected(
    batch_state: BatchState, field: str
) -> None:
    state = batch_state
    with pytest.raises(ValueError, match="replaced native inputs"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ) as batch:
            object.__setattr__(batch.inputs[0], field, object())
    assert_closed(state)


@pytest.mark.asyncio
async def test_synchronous_preflight_deadline_stops_before_first_dispatch(
    batch_state: BatchState, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = batch_state
    original = batch_module.preflight_authenticated_openrouter_launch

    def slow(launch: Any) -> Any:
        time.sleep(0.01)
        return original(launch)

    monkeypatch.setattr(batch_module, "preflight_authenticated_openrouter_launch", slow)
    with pytest.raises(ValueError, match="deadline expired"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets, timeout_seconds=0.001
        ):
            pytest.fail("late preflight yielded")
    assert not any(event.startswith("dispatch") for event in state.events)
    assert_closed(state)


@pytest.mark.asyncio
async def test_full_128_candidate_bound_retains_every_scope_and_cost(
    batch_state: BatchState,
) -> None:
    state = batch_state
    base = state.launches[0]
    state.launches = tuple(
        replace(
            base,
            candidate_registry=SimpleNamespace(
                candidates=(SimpleNamespace(exact_model_id=f"synthetic/model-{i:03}"),)
            ),
        )
        for i in range(128)
    )
    state.secrets = tuple(
        OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-bound-key"}) for _ in range(128)
    )
    async with batch_module.authenticated_openrouter_calibration_scope(
        launches=state.launches, operator_secrets=state.secrets
    ) as batch:
        assert len(batch.inputs) == len(state.live) == 128
        assert len(state.ledger.snapshot().entries) == 128
    assert len([e for e in state.events if e.startswith("dispatch")]) == 128
    assert len([e for e in state.events if e.startswith("revoke")]) == 128
    assert sum(e.actual_cost_usd for e in state.ledger.snapshot().entries) == Decimal("32")
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("index", (0, 1, 2))
async def test_any_failed_preflight_prevents_every_dispatch(
    batch_state: BatchState, index: int
) -> None:
    state = batch_state
    state.fail_preflight = index
    with pytest.raises(ValueError, match="synthetic launch refusal"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ):
            pytest.fail("invalid population yielded")
    assert not any(event.startswith("dispatch") for event in state.events)
    assert state.ledger.snapshot().entries == ()
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("index", (0, 1, 2))
async def test_failed_attempt_keeps_its_bill_and_never_yields_a_shortened_batch(
    batch_state: BatchState, index: int
) -> None:
    state = batch_state
    state.fail_launch = index
    with pytest.raises(ValueError, match="synthetic attempted launch failure"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ):
            pytest.fail("incomplete population yielded")
    assert [e for e in state.events if e.startswith("dispatch")] == [
        f"dispatch-{i}" for i in range(index + 1)
    ]
    assert len(state.ledger.snapshot().entries) == index + 1
    assert state.ledger.snapshot().entries[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("index", (0, 1, 2))
async def test_cleanup_failure_still_disposes_every_other_runner(
    batch_state: BatchState, index: int
) -> None:
    state = batch_state
    state.fail_cleanup = index
    with pytest.raises(ValueError, match="synthetic cleanup failure"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ):
            pass
    assert state.events[-3:] == ["revoke-2", "revoke-1", "revoke-0"]
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", (ValueError, RuntimeError, TimeoutError, asyncio.CancelledError))
async def test_consumer_errors_survive_cleanup(
    batch_state: BatchState, kind: type[BaseException]
) -> None:
    state = batch_state
    error = kind("synthetic consumer error")
    with pytest.raises(kind) as caught:
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ):
            raise error
    assert caught.value is error
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("seconds", (True, "1", None, 0, -1, float("nan"), float("inf"), 86401))
async def test_invalid_deadline_refuses_before_preflight(
    batch_state: BatchState, seconds: Any
) -> None:
    state = batch_state
    with pytest.raises(ValueError, match="deadline"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets, timeout_seconds=seconds
        ):
            pytest.fail("invalid deadline yielded")
    assert state.events == []
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("await", "swallowed", "synchronous"))
async def test_deadline_never_becomes_success(batch_state: BatchState, mode: str) -> None:
    state = batch_state
    with pytest.raises(ValueError, match="deadline expired"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets, timeout_seconds=0.1
        ):
            if mode == "synchronous":
                time.sleep(0.15)
            elif mode == "swallowed":
                with suppress(asyncio.CancelledError):
                    await asyncio.sleep(1)
            else:
                await asyncio.sleep(1)
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ("selected_model_ids", "benchmark_suite", "ground_truth", "inputs")
)
async def test_consumer_cannot_replace_batch_bindings(batch_state: BatchState, field: str) -> None:
    state = batch_state
    with pytest.raises(ValueError, match="replaced original batch inputs"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ) as batch:
            object.__setattr__(batch, field, object())
    assert_closed(state)


@pytest.mark.asyncio
async def test_wrong_completed_candidate_is_not_yielded(batch_state: BatchState) -> None:
    state = batch_state
    state.wrong_model = True
    with pytest.raises(ValueError, match="differs from selected candidate"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ):
            pytest.fail("wrong candidate yielded")
    assert [e for e in state.events if e.startswith("dispatch")] == ["dispatch-0"]
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ("reverse", "duplicate", "ledger", "truth", "lineage", "suite", "policy")
)
async def test_incompatible_batch_refuses_before_dispatch(
    batch_state: BatchState, kind: str
) -> None:
    state = batch_state
    launches = state.launches
    if kind == "reverse":
        launches = tuple(reversed(launches))
    elif kind == "duplicate":
        launches = (launches[0], launches[0], launches[2])
    else:
        field = {
            "ledger": "budget",
            "truth": "ground_truth_capability",
            "lineage": "public_lineage_capability",
            "suite": "benchmark_suite",
            "policy": "qualification_policy",
        }[kind]
        value = SimpleNamespace(atomic_ledger=object()) if kind == "ledger" else object()
        launches = (launches[0], replace(launches[1], **{field: value}), launches[2])
    state.launches = launches
    with pytest.raises(ValueError, match=r"unique and sorted|share original"):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=launches, operator_secrets=state.secrets
        ):
            pytest.fail("incompatible batch yielded")
    assert not any(event.startswith("dispatch") for event in state.events)
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("swallow", (False, True))
async def test_external_cancellation_is_not_success(batch_state: BatchState, swallow: bool) -> None:
    state = batch_state
    entered = asyncio.Event()

    async def consume() -> None:
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ):
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                if not swallow:
                    raise

    task = asyncio.create_task(consume())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ("reserved", "unknown", "known-unassigned", "overrun", "owner-close")
)
async def test_later_unowned_or_unsettled_work_never_passes_consumption(
    batch_state: BatchState, kind: str
) -> None:
    state = batch_state
    retained: list[bytes] = []
    with pytest.raises(ValueError):
        async with batch_module.authenticated_openrouter_calibration_scope(
            launches=state.launches, operator_secrets=state.secrets
        ):
            if kind == "owner-close":
                accounting.close_calibration_ledger_accounting(state.owner)
            else:
                reservation = state.ledger.reserve("synthetic-unassigned", Decimal("1"))
                if kind == "unknown":
                    state.ledger.commit_for_transport(reservation)
                    state.ledger.reconcile(reservation, None)
                elif kind == "known-unassigned":
                    state.ledger.reconcile(reservation, Decimal("0.5"))
                elif kind == "overrun":
                    with pytest.raises(CostReservationOverrunError):
                        state.ledger.reconcile(reservation, Decimal("1.1"))
            retained.append(state.ledger.path.read_bytes())
    assert state.ledger.path.read_bytes() == retained[0]
    assert_closed(state)
