"""Registered batch protocol stand-ins; real journal I/O and original cost accounting."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mmaudit.orchestration.authenticated_calibration_openrouter as batch_module
from mmaudit.models.authenticated_runner import require_verified_cross_lineage_runner_custody
from mmaudit.models.authenticated_runner_execution import CrossLineageAdjudicationRunKind
from mmaudit.orchestration.calibration_population import CalibrationPopulationJournal
from tests.unit.test_calibration_population_journal import population_plan, read_journal
from tests.unit.test_openrouter_calibration_scope import (
    BatchState,
    assert_closed,
)
from tests.unit.test_openrouter_calibration_scope import (
    batch_state as batch_state,
)

_ORIGINAL_PREFLIGHT = batch_module.preflight_authenticated_openrouter_launch


class DeclaredData(SimpleNamespace):
    """Explicit protocol stand-in; not validated provider or model data."""

    def model_dump(self, *, mode: str) -> dict[str, str]:
        assert mode == "json"
        return {"synthetic": str(self.label)}


@pytest.fixture
def registered(batch_state: BatchState, tmp_path: Path) -> tuple[BatchState, Path]:
    state = batch_state
    common = DeclaredData(label="shared-policy-source-config")
    plan = population_plan()
    state.launches = tuple(
        replace(
            launch,
            config=common,
            qualification_policy=common,
            benchmark_suite=common,
            candidate_registry=DeclaredData(
                label=entry.exact_model_id,
                registry_sha256="a" * 64,
                candidates=(SimpleNamespace(exact_model_id=entry.exact_model_id),),
            ),
            candidate_discovery_manifest=common,
            candidate_discovery_evidence=(),
            run_plans=tuple(
                SimpleNamespace(
                    run_kind=kind,
                    judge_registry=common,
                    judge_discovery_manifest=common,
                    judge_discovery_evidence=(),
                    candidate_declared_cost_cap_usd_per_attempt=Decimal("1"),
                    judge_declared_cost_cap_usd_per_attempt=Decimal("1"),
                )
                for kind in (
                    CrossLineageAdjudicationRunKind.PRIMARY,
                    CrossLineageAdjudicationRunKind.REPLAY,
                )
            ),
        )
        for launch, entry in zip(state.launches, plan.entries, strict=True)
    )
    root = tmp_path / "registered"
    root.mkdir(mode=0o700)
    return state, root


def scope(state: BatchState, root: Path, **overrides: Any) -> Any:
    return batch_module.registered_openrouter_calibration_scope(
        **{
            "selection_plan": population_plan(),
            "ledger": state.ledger,
            "evidence_root": root,
            "launches": state.launches,
            "operator_secrets": state.secrets,
            **overrides,
        }
    )


@pytest.mark.asyncio
async def test_registration_and_start_records_precede_each_owned_runner(
    registered: tuple[BatchState, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, root = registered
    original = batch_module._owned_authenticated_openrouter_runner_scope
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def tracked(**kwargs: Any) -> Any:
        current = read_journal(root)[-1]
        assert current.kind == "RUNNER_STARTED"
        assert (
            current.slots[current.slot_index].exact_model_id
            == kwargs["launch"].candidate_registry.candidates[0].exact_model_id
        )
        assert current.ledger_snapshot == state.ledger.snapshot()
        async with original(**kwargs) as value:
            yield value

    monkeypatch.setattr(batch_module, "_owned_authenticated_openrouter_runner_scope", tracked)
    async with scope(state, root) as batch:
        assert len(batch.inputs) == 3
        assert read_journal(root)[-1].disposition == "OPEN"
        with pytest.raises(ValueError):
            require_verified_cross_lineage_runner_custody(
                batch.inputs[0].runner_custody, evidence=batch.inputs[0].runner_evidence
            )
    events = read_journal(root)
    assert len(events) == 11
    assert events[-1].disposition == "CONSUMED"
    assert events[-1].ledger_snapshot == state.ledger.snapshot()
    assert events[-1].ledger_snapshot.spent_usd == Decimal("0.75")
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", (1, 2, 3))
async def test_missing_launches_remain_visible_and_prevent_all_dispatch(
    registered: tuple[BatchState, Path], missing: int
) -> None:
    state, root = registered
    owned = state.secrets[:-missing]
    with pytest.raises(ValueError, match=r"missing|no available"):
        async with scope(state, root, launches=state.launches[:-missing], operator_secrets=owned):
            pytest.fail("incomplete population yielded")
    final = read_journal(root)[-1]
    assert len(final.slots) == 3
    assert sum(slot.state == "MISSING" for slot in final.slots) == missing
    assert final.disposition == "FAILED"
    assert not any(event.startswith("dispatch") for event in state.events)
    assert state.ledger.snapshot().entries == ()
    assert all(secret.cleared for secret in owned)
    assert all(not secret.cleared for secret in state.secrets[-missing:])


@pytest.mark.asyncio
async def test_every_available_preflight_refusal_is_retained_without_error_text(
    registered: tuple[BatchState, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, root = registered
    calls = []

    def refuse(launch: Any) -> Any:
        calls.append(launch)
        assert (root / "000.json").is_file()
        raise ValueError("synthetic-sensitive-error-not-for-evidence")

    monkeypatch.setattr(batch_module, "preflight_authenticated_openrouter_launch", refuse)
    with pytest.raises(ValueError, match="missing or refused"):
        async with scope(state, root):
            pytest.fail("refused preflights yielded")
    assert calls == list(state.launches)
    assert all(slot.state == "REFUSED" for slot in read_journal(root)[-1].slots)
    assert "synthetic-sensitive-error" not in "".join(path.read_text() for path in root.iterdir())
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("index", (0, 1, 2))
async def test_failed_runner_preserves_unknown_cost_and_all_unattempted_slots(
    registered: tuple[BatchState, Path], index: int
) -> None:
    state, root = registered
    state.fail_launch = index
    with pytest.raises(ValueError):
        async with scope(state, root):
            pytest.fail("failed run yielded")
    final = read_journal(root)[-1]
    assert final.disposition == "FAILED"
    assert [slot.state for slot in final.slots] == ["RETAINED"] * index + ["FAILED"] + ["READY"] * (
        2 - index
    )
    assert final.ledger_snapshot == state.ledger.snapshot()
    assert final.ledger_snapshot.entries[-1].actual_cost_usd is None
    assert len([event for event in state.events if event.startswith("dispatch")]) == index + 1
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ("consumer", "cleanup", "cancellation", "deadline", "unknown"))
async def test_unsuccessful_exit_is_not_recorded_as_consumed(
    registered: tuple[BatchState, Path], kind: str
) -> None:
    state, root = registered
    if kind == "cleanup":
        state.fail_cleanup = 1
    expected = asyncio.CancelledError if kind == "cancellation" else ValueError
    with pytest.raises(expected):
        async with scope(state, root, timeout_seconds=0.5 if kind == "deadline" else 30):
            if kind == "consumer":
                raise ValueError("synthetic consumer error")
            if kind == "cancellation":
                raise asyncio.CancelledError
            if kind == "deadline":
                await asyncio.sleep(1)
            if kind == "unknown":
                reservation = state.ledger.reserve("new-unknown", Decimal("1"))
                state.ledger.commit_for_transport(reservation)
                state.ledger.reconcile(reservation, None)
    final = read_journal(root)[-1]
    assert final.disposition == ("CANCELLED" if kind == "cancellation" else "FAILED")
    assert final.ledger_snapshot == state.ledger.snapshot()
    assert_closed(state)


@pytest.mark.asyncio
async def test_changed_launch_configuration_refuses_before_any_dispatch(
    registered: tuple[BatchState, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, root = registered
    original = batch_module.preflight_authenticated_openrouter_launch

    def mutate(launch: Any) -> Any:
        result = original(launch)
        launch.config.label = "changed-after-registration"
        return result

    monkeypatch.setattr(batch_module, "preflight_authenticated_openrouter_launch", mutate)
    with pytest.raises(ValueError, match="bindings changed"):
        async with scope(state, root):
            pytest.fail("changed declared configuration yielded")
    assert not state.ledger.snapshot().entries
    assert read_journal(root)[-1].disposition == "FAILED"
    assert_closed(state)


@pytest.mark.asyncio
async def test_failed_start_record_prevents_runner_entry(
    registered: tuple[BatchState, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, root = registered
    original = CalibrationPopulationJournal.append

    def unavailable(self: Any, kind: str, **kwargs: Any) -> None:
        if kind == "RUNNER_STARTED":
            raise OSError("synthetic storage refusal")
        original(self, kind, **kwargs)

    monkeypatch.setattr(CalibrationPopulationJournal, "append", unavailable)
    with pytest.raises(OSError):
        async with scope(state, root):
            pytest.fail("unrecorded runner yielded")
    assert not state.ledger.snapshot().entries
    assert read_journal(root)[-1].disposition == "FAILED"
    assert_closed(state)


@pytest.mark.asyncio
async def test_native_preflight_still_refuses_protocol_standins(
    registered: tuple[BatchState, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, root = registered
    monkeypatch.setattr(
        batch_module, "preflight_authenticated_openrouter_launch", _ORIGINAL_PREFLIGHT
    )
    with pytest.raises(ValueError, match="missing or refused"):
        async with scope(state, root):
            pytest.fail("native preflight accepted unverified launch inputs")
    assert all(slot.state == "REFUSED" for slot in read_journal(root)[-1].slots)
    assert state.events == []
    assert_closed(state)


@pytest.mark.asyncio
async def test_unknown_history_remains_visible_and_blocks_runner_entry(
    registered: tuple[BatchState, Path],
) -> None:
    state, root = registered
    reservation = state.ledger.reserve("prior-unknown", Decimal("1"))
    state.ledger.commit_for_transport(reservation)
    state.ledger.reconcile(reservation, None)
    before = state.ledger.snapshot()
    with pytest.raises(ValueError):
        async with scope(state, root):
            pytest.fail("unknown prior cost allowed a new runner")
    assert state.ledger.snapshot() == before
    assert read_journal(root)[0].ledger_snapshot == before
    assert read_journal(root)[-1].ledger_snapshot == before
    assert not any(event.startswith("dispatch") for event in state.events)
    assert_closed(state)


@pytest.mark.asyncio
async def test_consumer_cannot_change_the_precommitted_launch_configuration(
    registered: tuple[BatchState, Path],
) -> None:
    state, root = registered
    with pytest.raises(ValueError, match="bindings changed"):
        async with scope(state, root):
            state.launches[0].config.label = "consumer-changed-source"
    assert read_journal(root)[-1].disposition == "FAILED"
    assert_closed(state)


@pytest.mark.asyncio
async def test_terminal_storage_failure_leaves_open_prefix_not_consumption(
    registered: tuple[BatchState, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, root = registered
    original = CalibrationPopulationJournal.append

    def unavailable(self: Any, kind: str, **kwargs: Any) -> None:
        if kind == "FINISHED":
            raise OSError("synthetic terminal storage refusal")
        original(self, kind, **kwargs)

    monkeypatch.setattr(CalibrationPopulationJournal, "append", unavailable)
    with pytest.raises(OSError):
        async with scope(state, root):
            pass
    assert read_journal(root)[-1].disposition == "OPEN"
    assert_closed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ("list", "duplicate", "length", "foreign-ledger", "outside", "run-count")
)
async def test_malformed_registered_inputs_never_publish_or_execute(
    registered: tuple[BatchState, Path], kind: str
) -> None:
    state, root = registered
    overrides: dict[str, Any] = {}
    if kind == "list":
        overrides["launches"] = list(state.launches)
    elif kind == "duplicate":
        overrides["launches"] = (state.launches[0],) * 3
    elif kind == "length":
        overrides["launches"] = state.launches[:1]
    elif kind == "foreign-ledger":
        overrides["ledger"] = object()
    elif kind == "outside":
        state.launches[0].candidate_registry.candidates[0].exact_model_id = "outside/model"
    else:
        overrides["launches"] = (replace(state.launches[0], run_plans=()), *state.launches[1:])
    with pytest.raises(ValueError):
        async with scope(state, root, **overrides):
            pytest.fail("malformed registered inputs yielded")
    assert list(root.iterdir()) == []
    assert state.events == []
    assert_closed(state)
