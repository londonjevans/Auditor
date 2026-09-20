"""Local request/ledger integration; synthetic transport never reaches a provider."""

from __future__ import annotations

import socket
import subprocess
import tempfile
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.operator_secrets as secrets_module
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostReservationOverrunError,
)
from tests.unit.test_openrouter import _completion_response
from tests.unit.test_openrouter_refresh_runtime import _build_harness, _complete


@pytest.fixture(autouse=True)
def forbid_external_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cost integration must remain local, synthetic and credential-free")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    original_popen = subprocess.Popen

    def local_signature_only(argv: list[str], **kwargs: Any) -> Any:
        # The existing harness creates an ephemeral policy signature using the fixed
        # system tool; it never loads a real operator key or connects to a service.
        assert type(argv) is list and argv[0] == "/usr/bin/ssh-keygen"
        assert kwargs.get("shell") is False and "-f" in argv
        target = Path(argv[argv.index("-f") + 1]).resolve()
        if not target.is_relative_to(tmp_path.resolve()):
            assert argv[1:3] == ["-Y", "verify"]
            assert target.name == "allowed_signers"
            assert target.parent.name.startswith("mmaudit-policy-authority-")
            assert target.is_relative_to(Path(tempfile.gettempdir()).resolve())
        return original_popen(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", local_signature_only)
    monkeypatch.setattr(secrets_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)


@pytest.mark.asyncio
@pytest.mark.parametrize("over_ceiling", (False, True))
async def test_request_reserved_before_external_ledger_overrun_never_reaches_mock_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, over_ceiling: bool
) -> None:
    """Invariant: another ledger opener's overrun stops a previously reserved request."""

    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"prohibited synthetic dispatch"}', model=model, provider=provider
        ),
    )
    other = AtomicCostLedger.open_existing(harness.ledger.path, cap_usd=harness.ledger.cap_usd)
    actual = harness.ledger.cap_usd + Decimal("0.01") if over_ceiling else Decimal("1.01")

    @dataclass(slots=True)
    class OverrunAfterReserve:
        request_id: str | None = None

        def request_ready(self, **_values: Any) -> None:
            return None

        def request_dispatched(self, *, logical_request_id: str) -> None:
            assert self.request_id is None
            self.request_id = logical_request_id
            pending = harness.client.budget._issued[logical_request_id]
            assert pending.persistent is not None
            assert other.active_reservation(logical_request_id) == pending.persistent
            first = other.reserve("synthetic-other-attempt", Decimal("1"))
            other.commit_for_transport(first)
            with pytest.raises(CostReservationOverrunError):
                other.reconcile(first, actual)

    observer = OverrunAfterReserve()
    harness.client.bind_request_lifecycle_observer(observer)
    try:
        # Public errors deliberately remove exception causes; the ledger and absence
        # of a transport attempt are the authoritative observable outcome here.
        with pytest.raises(OpenRouterSchemaError, match="transport failed safely"):
            await _complete(harness)
    finally:
        await harness.client.close()

    assert observer.request_id is not None
    assert harness.requests == []
    reopened = AtomicCostLedger.open_existing(harness.ledger.path, cap_usd=harness.ledger.cap_usd)
    snapshot = reopened.snapshot()
    assert len(snapshot.entries) == 2
    pending = next(e for e in snapshot.entries if e.request_id == observer.request_id)
    first = next(e for e in snapshot.entries if e.request_id == "synthetic-other-attempt")
    assert pending.status is CostEntryStatus.RELEASED
    assert pending.actual_cost_usd is None
    assert pending.accounted_cost_usd == 0
    assert first.status is CostEntryStatus.RESERVATION_OVERRUN
    assert first.actual_cost_usd == first.accounted_cost_usd == actual
    assert snapshot.spent_usd == actual
    assert snapshot.active_reserved_usd == 0
    assert snapshot.has_reservation_overrun is True
    assert snapshot.over_cap is over_ceiling
    with pytest.raises(CostBudgetExceededError, match="further calls are blocked"):
        reopened.reserve("prohibited-restart-attempt", Decimal("0.001"))


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ("class", "instance", "ledger_code", "budget_code"))
async def test_provider_boundary_rejects_override_of_new_ledger_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    from mmaudit.models.openrouter import OpenRouterPrivacyError

    harness = _build_harness(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        response=lambda _request, model, provider: _completion_response(
            '{"answer":"prohibited synthetic dispatch"}', model=model, provider=provider
        ),
    )
    if surface == "ledger_code":
        monkeypatch.setattr(
            AtomicCostLedger.commit_for_transport, "__code__", (lambda *_args: None).__code__
        )
    elif surface == "budget_code":

        async def no_commit(*_args: Any) -> None:
            return None

        monkeypatch.setattr(
            BudgetManager.commit_active_reservation_for_transport, "__code__", no_commit.__code__
        )
    else:
        subject = AtomicCostLedger if surface == "class" else harness.ledger
        monkeypatch.setattr(subject, "commit_for_transport", lambda *_args: None)
    try:
        with pytest.raises(OpenRouterPrivacyError, match=r"callable|authority"):
            await _complete(harness)
    finally:
        await harness.client.close()
    assert harness.requests == []
    assert harness.ledger.snapshot().entries == ()
