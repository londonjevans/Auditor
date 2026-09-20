"""Owned scope lifecycle with explicit stand-ins, never REAL-provider authority."""

from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

import pytest

import mmaudit.orchestration.authenticated_runner_openrouter as adapter
from mmaudit.models.authenticated_runner import AuthenticatedCrossLineageRunnerError
from mmaudit.models.authenticated_runner_execution import AuthenticatedRunnerExecutionResult
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from tests.unit import test_authenticated_runner_openrouter as fixtures


@dataclass
class ScopeState:
    execution: AuthenticatedRunnerExecutionResult
    secrets: OperatorSecrets
    revoked: bool = False
    invalidated: bool = False
    wrong_projection: bool = False
    events: list[str] = field(default_factory=list)


@pytest.fixture
def scope_state(monkeypatch: pytest.MonkeyPatch) -> ScopeState:
    execution = fixtures._completed_execution()
    original_capability = execution.runner_capability
    original_evidence = execution.runner_evidence
    original_projection = execution.runner_projection
    state = ScopeState(
        execution, OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-in-process-test-key"})
    )
    fixtures._install_completed_runner(monkeypatch, execution)

    def require(capability: Any, *, evidence: Any) -> Any:
        assert capability is original_capability
        assert evidence is original_evidence
        state.events.append("verify-revoked" if state.revoked else "verify")
        if state.revoked:
            raise AuthenticatedCrossLineageRunnerError(adapter._REVOKED_RUNNER_CUSTODY_DETAIL)
        if state.invalidated:
            raise AuthenticatedCrossLineageRunnerError("synthetic source changed")
        return object() if state.wrong_projection else original_projection

    def revoke(capability: Any) -> None:
        assert capability is original_capability
        state.events.append("revoke")
        state.revoked = True

    fixtures._install_lifecycle_doubles(monkeypatch, require=require, revoke=revoke)
    original_close = adapter._OpenRouterExecutionAdapter.close

    async def close(instance: Any) -> None:
        state.events.append("close")
        await original_close(instance)

    monkeypatch.setattr(adapter._OpenRouterExecutionAdapter, "close", close)
    return state


def _assert_disposed(state: ScopeState) -> None:
    assert state.events.count("revoke") == 1
    assert state.events[-2:] == ["verify-revoked", "close"]
    assert state.revoked
    assert state.secrets.cleared


@pytest.mark.asyncio
@pytest.mark.parametrize("seconds", (1, 30.0, 300.0))
async def test_original_custody_is_live_only_inside_successful_scope(
    scope_state: ScopeState, seconds: float
) -> None:
    state = scope_state
    async with adapter.authenticated_openrouter_runner_scope(
        launch=fixtures._structural_launch(),
        operator_secrets=state.secrets,
        consumption_timeout_seconds=seconds,
    ) as execution:
        assert execution is state.execution
        assert not state.revoked
        assert not state.secrets.cleared
        state.events.append("consume")
    assert state.events == ["verify", "consume", "verify", "revoke", "verify-revoked", "close"]
    _assert_disposed(state)
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="revoked"):
        adapter.require_verified_cross_lineage_runner_custody(
            execution.runner_capability, evidence=execution.runner_evidence
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "seconds",
    (None, True, False, "1", (), {}, 0, -1, float("nan"), float("inf"), -float("inf"), 300.001),
)
async def test_invalid_deadline_clears_secret_before_any_execution(
    scope_state: ScopeState, seconds: Any
) -> None:
    state = scope_state
    with pytest.raises(adapter.AuthenticatedRunnerOpenRouterError, match="deadline must be finite"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(),
            operator_secrets=state.secrets,
            consumption_timeout_seconds=seconds,
        ):
            pytest.fail("invalid deadline yielded execution")
    assert state.events == []
    assert state.secrets.cleared


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", (ValueError, RuntimeError, TimeoutError, asyncio.CancelledError))
async def test_consumer_failure_is_preserved_after_mandatory_disposal(
    scope_state: ScopeState, kind: type[BaseException]
) -> None:
    state = scope_state
    error = kind("synthetic consumer failure")
    with pytest.raises(kind) as caught:
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(), operator_secrets=state.secrets
        ):
            raise error
    assert caught.value is error
    _assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("await", "swallowed-timeout", "synchronous-return"))
async def test_no_success_after_consumption_deadline(scope_state: ScopeState, mode: str) -> None:
    state = scope_state
    with pytest.raises(adapter.AuthenticatedRunnerOpenRouterError, match="deadline expired"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(),
            operator_secrets=state.secrets,
            consumption_timeout_seconds=0.001,
        ):
            if mode == "synchronous-return":
                # Deliberately block this local test task briefly: cooperative
                # cancellation cannot interrupt it, but late return must refuse.
                time.sleep(0.02)
            elif mode == "swallowed-timeout":
                with suppress(asyncio.CancelledError):
                    await asyncio.sleep(1)
            else:
                await asyncio.sleep(1)
    _assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("swallow", (False, True))
async def test_external_cancellation_cannot_become_success(
    scope_state: ScopeState, swallow: bool
) -> None:
    state = scope_state
    entered = asyncio.Event()

    async def consume() -> None:
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(), operator_secrets=state.secrets
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
    _assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("when", ("before", "after"))
async def test_original_proof_is_replayed_before_and_after_consumption(
    scope_state: ScopeState, when: str
) -> None:
    state = scope_state
    state.invalidated = when == "before"
    with pytest.raises(AuthenticatedCrossLineageRunnerError, match="synthetic source changed"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(), operator_secrets=state.secrets
        ):
            assert when == "after"
            state.invalidated = True
    _assert_disposed(state)


@pytest.mark.asyncio
async def test_unmatched_verified_projection_is_not_yielded(scope_state: ScopeState) -> None:
    state = scope_state
    state.wrong_projection = True
    with pytest.raises(adapter.AuthenticatedRunnerOpenRouterError, match="verified projection"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(), operator_secrets=state.secrets
        ):
            pytest.fail("mismatched original proof was yielded")
    _assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    (
        "inventory",
        "runs",
        "closed_ledger_interval",
        "runner_capability",
        "runner_evidence",
        "runner_projection",
    ),
)
async def test_consumer_cannot_replace_original_custody_fields(
    scope_state: ScopeState, name: str
) -> None:
    state = scope_state
    with pytest.raises(adapter.AuthenticatedRunnerOpenRouterError, match="replaced original"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(), operator_secrets=state.secrets
        ) as execution:
            object.__setattr__(execution, name, object())
    _assert_disposed(state)


@pytest.mark.asyncio
async def test_adapter_close_failure_still_revokes_and_clears_credentials(
    scope_state: ScopeState, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = scope_state

    async def fail_close(_instance: Any) -> None:
        state.events.append("close")
        raise adapter.AuthenticatedRunnerOpenRouterError("synthetic transport cleanup failed")

    monkeypatch.setattr(adapter._OpenRouterExecutionAdapter, "close", fail_close)
    with pytest.raises(adapter.AuthenticatedRunnerOpenRouterError, match="cleanup failed"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(), operator_secrets=state.secrets
        ):
            pass
    _assert_disposed(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("when", ("before", "inside"))
@pytest.mark.parametrize(
    "binding",
    (
        "require_verified_cross_lineage_runner_custody",
        "revoke_verified_cross_lineage_runner_custody",
    ),
)
async def test_consumer_retarget_cannot_replace_owned_verification_or_revocation(
    scope_state: ScopeState, monkeypatch: pytest.MonkeyPatch, when: str, binding: str
) -> None:
    state = scope_state

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        pytest.fail("retargeted lifecycle callable was invoked")

    if when == "before":
        monkeypatch.setattr(adapter, binding, forbidden)
    with pytest.raises(
        adapter.AuthenticatedRunnerOpenRouterError, match="callable binding changed"
    ):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(), operator_secrets=state.secrets
        ):
            assert when == "inside"
            monkeypatch.setattr(adapter, binding, forbidden)
    _assert_disposed(state)


@pytest.mark.asyncio
async def test_success_cannot_be_reported_after_a_late_final_proof_replay(
    scope_state: ScopeState, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = scope_state
    require = adapter._TRUSTED_REQUIRE_RUNNER_CUSTODY
    revoke = adapter._TRUSTED_REVOKE_RUNNER_CUSTODY
    calls = 0

    def delayed_require(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        result = require(*args, **kwargs)
        if calls == 2:
            time.sleep(0.03)
        return result

    fixtures._install_lifecycle_doubles(monkeypatch, require=delayed_require, revoke=revoke)
    with pytest.raises(adapter.AuthenticatedRunnerOpenRouterError, match="deadline expired"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=fixtures._structural_launch(),
            operator_secrets=state.secrets,
            consumption_timeout_seconds=0.01,
        ):
            pass
    assert calls == 3
    _assert_disposed(state)
