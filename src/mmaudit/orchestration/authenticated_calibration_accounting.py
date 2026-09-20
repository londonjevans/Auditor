"""Owned, nonauthorizing accounting for a calibration campaign's one real ledger.

Closed runner intervals must be captured while their original exact-snapshot proof
is still valid. Retention proves immutable cost history, not runner custody or
qualification; existing runner verification and revocation are unchanged.
"""

from __future__ import annotations

import os
import threading
import weakref
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, localcontext
from enum import StrEnum
from typing import Literal, Never, Self, SupportsIndex

import mmaudit.models.authenticated_runner_ledger as _runner
from mmaudit.models.authenticated_runner_ledger import (
    ClosedCrossLineageLedgerInterval,
    _require_closed_cross_lineage_ledger_interval,
    _require_pristine_cross_lineage_ledger_runtime,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostLedgerSnapshot,
    cost_ledger_snapshot_sha256,
)

_MAX_PREFIXES = 128
_MAX_REQUESTS = 100_000
_CAP = Decimal("250")


class CalibrationLedgerAccountingError(ValueError):
    """Accounting custody, immutable history or its budget boundary is invalid."""


class CalibrationAccountingBlocker(StrEnum):
    UNASSIGNED_WORK = "UNASSIGNED_WORK"
    ACTIVE_RESERVATIONS = "ACTIVE_RESERVATIONS"
    ACTIVE_PORTFOLIO_HOLDS = "ACTIVE_PORTFOLIO_HOLDS"
    UNKNOWN_BILLING = "UNKNOWN_BILLING"
    RESERVATION_OVERRUN = "RESERVATION_OVERRUN"
    LEDGER_CEILING = "LEDGER_CEILING"


class _OpaqueAccountingCustody:
    """Shared refusal behavior, not a constructible or transferable authority."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Self:
        raise TypeError("calibration ledger accounting cannot be constructed directly")

    def __copy__(self) -> Never:
        raise TypeError("calibration ledger accounting cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("calibration ledger accounting cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("calibration ledger accounting cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("calibration ledger accounting cannot be serialized")


class CalibrationLedgerAccounting(_OpaqueAccountingCustody):
    """Opaque PID-local owner; neither this object nor its projections grant credit."""

    __slots__ = ()


class RetainedCalibrationLedgerPrefix(_OpaqueAccountingCustody):
    """Distinct opaque cost receipt, never an original closed-runner capability."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class CalibrationLedgerAccountingObservation:
    """Complete current liabilities, including work not covered by retained intervals."""

    ledger_identity_sha256: str
    initial_snapshot_sha256: str
    retained_snapshot_sha256: str
    current_snapshot_sha256: str
    retained_interval_count: int
    retained_request_count: int
    current_snapshot: CostLedgerSnapshot
    unassigned_request_ids: tuple[str, ...]
    unassigned_portfolio_ids: tuple[str, ...]
    blockers: tuple[CalibrationAccountingBlocker, ...]
    serialized_authority: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False


@dataclass(frozen=True, slots=True)
class CalibrationLedgerPrefixProjection:
    """Fresh cost-only projection; the owner and every current liability remain required."""

    ordinal: int
    initial_snapshot_sha256: str
    final_snapshot_sha256: str
    interval_request_ids: tuple[str, ...]
    interval_spent_usd: Decimal
    current_accounting: CalibrationLedgerAccountingObservation
    serialized_authority: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False


def _build_accounting() -> tuple[
    Callable[[AtomicCostLedger], CalibrationLedgerAccounting],
    Callable[..., RetainedCalibrationLedgerPrefix],
    Callable[[CalibrationLedgerAccounting], CalibrationLedgerAccountingObservation],
    Callable[[CalibrationLedgerAccounting], CalibrationLedgerAccountingObservation],
    Callable[[RetainedCalibrationLedgerPrefix], CalibrationLedgerPrefixProjection],
    Callable[[CalibrationLedgerAccounting], None],
]:
    @dataclass(frozen=True, slots=True)
    class PrefixState:
        capability: RetainedCalibrationLedgerPrefix
        initial_sha256: str
        final_sha256: str
        request_ids: tuple[str, ...]
        spent_usd: Decimal

    @dataclass(slots=True)
    class OwnerState:
        ledger: AtomicCostLedger
        identity: str
        initial_sha256: str
        head: CostLedgerSnapshot
        head_sha256: str
        prefixes: tuple[PrefixState, ...] = ()

    registry: weakref.WeakKeyDictionary[CalibrationLedgerAccounting, OwnerState] = (
        weakref.WeakKeyDictionary()
    )
    prefixes: weakref.WeakKeyDictionary[
        RetainedCalibrationLedgerPrefix, weakref.ReferenceType[CalibrationLedgerAccounting]
    ] = weakref.WeakKeyDictionary()
    owners: dict[str, weakref.ReferenceType[CalibrationLedgerAccounting]] = {}
    lock = threading.RLock()
    getpid = os.getpid
    pid = getpid()
    owner_type = CalibrationLedgerAccounting
    prefix_type = RetainedCalibrationLedgerPrefix
    limits = (128, 100_000, Decimal("250"))
    snapshot = AtomicCostLedger.snapshot_with_identity_sha256
    snapshot_hash = cost_ledger_snapshot_sha256
    require_closed = _require_closed_cross_lineage_ledger_interval
    require_ledger_runtime = _require_pristine_cross_lineage_ledger_runtime
    protected = {
        name: globals()[name]
        for name in (
            "_runner",
            "AtomicCostLedger",
            "CostLedgerSnapshot",
            "ClosedCrossLineageLedgerInterval",
            "_OpaqueAccountingCustody",
            "CalibrationLedgerAccounting",
            "RetainedCalibrationLedgerPrefix",
            "CalibrationLedgerAccountingObservation",
            "CalibrationLedgerPrefixProjection",
            "CalibrationAccountingBlocker",
            "CalibrationLedgerAccountingError",
            "CostEntryStatus",
            "Decimal",
            "localcontext",
            "cost_ledger_snapshot_sha256",
            "_require_closed_cross_lineage_ledger_interval",
            "_require_pristine_cross_lineage_ledger_runtime",
        )
    }
    public: dict[str, object] = {}

    def pristine() -> None:
        require_ledger_runtime()
        if (
            os.getpid is not getpid
            or getpid() != pid
            or any(globals().get(name) is not value for name, value in protected.items())
            or any(globals().get(name) is not value for name, value in public.items())
            or AtomicCostLedger.snapshot_with_identity_sha256 is not snapshot
            or _runner._require_closed_cross_lineage_ledger_interval is not require_closed
            or _runner._require_pristine_cross_lineage_ledger_runtime is not require_ledger_runtime
            or type(_MAX_PREFIXES) is not int
            or type(_MAX_REQUESTS) is not int
            or type(_CAP) is not Decimal
            or limits != (_MAX_PREFIXES, _MAX_REQUESTS, _CAP)
        ):
            raise CalibrationLedgerAccountingError("calibration ledger runtime is not pristine")

    def bounded(value: CostLedgerSnapshot) -> None:
        if (
            type(value) is not CostLedgerSnapshot
            or value.cap_usd != _CAP
            or len(value.entries) > _MAX_REQUESTS
            or len(value.portfolio_holds) > _MAX_REQUESTS
        ):
            raise CalibrationLedgerAccountingError("calibration ledger exceeds its exact bounds")

    def cost_blockers(value: CostLedgerSnapshot) -> tuple[CalibrationAccountingBlocker, ...]:
        reasons: list[CalibrationAccountingBlocker] = []
        if value.active_reserved_usd or any(
            entry.status is CostEntryStatus.RESERVED for entry in value.entries
        ):
            reasons.append(CalibrationAccountingBlocker.ACTIVE_RESERVATIONS)
        if value.held_portfolio_usd:
            reasons.append(CalibrationAccountingBlocker.ACTIVE_PORTFOLIO_HOLDS)
        if any(entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED for entry in value.entries):
            reasons.append(CalibrationAccountingBlocker.UNKNOWN_BILLING)
        if value.has_reservation_overrun:
            reasons.append(CalibrationAccountingBlocker.RESERVATION_OVERRUN)
        if value.over_cap or value.spent_usd >= _CAP:
            reasons.append(CalibrationAccountingBlocker.LEDGER_CEILING)
        return tuple(reasons)

    def require_cost_ready(value: CostLedgerSnapshot) -> None:
        reasons = cost_blockers(value)
        if reasons:
            raise CalibrationLedgerAccountingError(
                "calibration accounting refuses work: " + ", ".join(reasons)
            )

    def state_for(owner: CalibrationLedgerAccounting) -> OwnerState:
        if type(owner) is not owner_type:
            raise CalibrationLedgerAccountingError("calibration accounting is absent or revoked")
        state = registry.get(owner)
        if state is None:
            raise CalibrationLedgerAccountingError("calibration accounting is absent or revoked")
        return state

    def recheck_owner(owner: CalibrationLedgerAccounting, state: OwnerState) -> None:
        if registry.get(owner) is not state:
            raise CalibrationLedgerAccountingError(
                "calibration accounting was revoked during replay"
            )

    def current(state: OwnerState) -> CostLedgerSnapshot:
        identity, observed = snapshot(state.ledger)
        bounded(observed)
        if identity != state.identity or snapshot_hash(state.head) != state.head_sha256:
            raise CalibrationLedgerAccountingError("calibration ledger identity or custody changed")
        entries = {entry.request_id: entry for entry in observed.entries}
        holds = {hold.plan_sha256: hold for hold in observed.portfolio_holds}
        if (
            any(entries.get(entry.request_id) != entry for entry in state.head.entries)
            or any(holds.get(hold.plan_sha256) != hold for hold in state.head.portfolio_holds)
            or observed.spent_usd < state.head.spent_usd
        ):
            raise CalibrationLedgerAccountingError("calibration ledger immutable history changed")
        return observed

    def project(
        state: OwnerState, observed: CostLedgerSnapshot
    ) -> CalibrationLedgerAccountingObservation:
        assigned = {entry.request_id for entry in state.head.entries}
        assigned_holds = {hold.plan_sha256 for hold in state.head.portfolio_holds}
        unassigned = tuple(
            entry.request_id for entry in observed.entries if entry.request_id not in assigned
        )
        unassigned_holds = tuple(
            hold.plan_sha256
            for hold in observed.portfolio_holds
            if hold.plan_sha256 not in assigned_holds
        )
        reasons = cost_blockers(observed)
        if unassigned or unassigned_holds:
            reasons += (CalibrationAccountingBlocker.UNASSIGNED_WORK,)
        return CalibrationLedgerAccountingObservation(
            ledger_identity_sha256=state.identity,
            initial_snapshot_sha256=state.initial_sha256,
            retained_snapshot_sha256=state.head_sha256,
            current_snapshot_sha256=snapshot_hash(observed),
            retained_interval_count=len(state.prefixes),
            retained_request_count=sum(len(item.request_ids) for item in state.prefixes),
            current_snapshot=observed,
            unassigned_request_ids=unassigned,
            unassigned_portfolio_ids=unassigned_holds,
            blockers=reasons,
        )

    def begin(ledger: AtomicCostLedger) -> CalibrationLedgerAccounting:
        pristine()
        if type(ledger) is not AtomicCostLedger:
            raise CalibrationLedgerAccountingError("calibration requires the exact atomic ledger")
        with lock:
            identity, initial = snapshot(ledger)
            bounded(initial)
            require_cost_ready(initial)
            previous = owners.get(identity)
            if previous is not None and previous() is not None:
                raise CalibrationLedgerAccountingError("calibration ledger already has an owner")
            capability = object.__new__(owner_type)
            digest = snapshot_hash(initial)
            registry[capability] = OwnerState(ledger, identity, digest, initial, digest)

            def discard(reference: weakref.ReferenceType[CalibrationLedgerAccounting]) -> None:
                with lock:
                    if owners.get(identity) is reference:
                        owners.pop(identity, None)

            owners[identity] = weakref.ref(capability, discard)
            try:
                pristine()
            except BaseException:
                del registry[capability]
                owners.pop(identity, None)
                raise
            return capability

    def retain(
        owner: CalibrationLedgerAccounting,
        *,
        interval: ClosedCrossLineageLedgerInterval,
    ) -> RetainedCalibrationLedgerPrefix:
        pristine()
        with lock:
            state = state_for(owner)
            if len(state.prefixes) >= _MAX_PREFIXES:
                raise CalibrationLedgerAccountingError(
                    "calibration retained interval bound reached"
                )
            observed = current(state)
            require_cost_ready(observed)
            # Replay the original proof before recording any historical-prefix custody.
            view = require_closed(interval)
            if (
                view.ledger is not state.ledger
                or view.ledger_identity_sha256 != state.identity
                or view.initial_snapshot != state.head
                or view.final_snapshot != observed
            ):
                raise CalibrationLedgerAccountingError(
                    "calibration interval overlaps or skips ledger history"
                )
            final_identity, final_snapshot = snapshot(state.ledger)
            if final_identity != state.identity or final_snapshot != observed:
                raise CalibrationLedgerAccountingError(
                    "calibration ledger changed during retention"
                )
            pristine()
            capability = object.__new__(prefix_type)
            final_hash = snapshot_hash(observed)
            with localcontext() as context:
                context.prec = 64
                interval_spent = observed.spent_usd - state.head.spent_usd
            record = PrefixState(
                capability,
                state.head_sha256,
                final_hash,
                tuple(entry.request_id for entry in view.new_entries),
                interval_spent,
            )
            recheck_owner(owner, state)
            pristine()
            prefixes[capability] = weakref.ref(owner)
            state.prefixes += (record,)
            state.head = observed
            state.head_sha256 = final_hash
            return capability

    def observe(owner: CalibrationLedgerAccounting) -> CalibrationLedgerAccountingObservation:
        pristine()
        with lock:
            state = state_for(owner)
            observed = current(state)
            result = project(state, observed)
            recheck_owner(owner, state)
            pristine()
            return result

    def ready(owner: CalibrationLedgerAccounting) -> CalibrationLedgerAccountingObservation:
        result = observe(owner)
        if result.blockers:
            raise CalibrationLedgerAccountingError(
                "calibration accounting refuses work: " + ", ".join(result.blockers)
            )
        return result

    def require_prefix(
        capability: RetainedCalibrationLedgerPrefix,
    ) -> CalibrationLedgerPrefixProjection:
        pristine()
        with lock:
            if type(capability) is not prefix_type:
                raise CalibrationLedgerAccountingError(
                    "calibration ledger prefix is absent or revoked"
                )
            reference = prefixes.get(capability)
            owner = None if reference is None else reference()
            if owner is None:
                raise CalibrationLedgerAccountingError(
                    "calibration ledger prefix is absent or revoked"
                )
            state = state_for(owner)
            observed = current(state)
            require_cost_ready(observed)
            for index, prefix in enumerate(state.prefixes):
                if prefix.capability is capability:
                    result = CalibrationLedgerPrefixProjection(
                        index + 1,
                        prefix.initial_sha256,
                        prefix.final_sha256,
                        prefix.request_ids,
                        prefix.spent_usd,
                        project(state, observed),
                    )
                    recheck_owner(owner, state)
                    pristine()
                    return result
            raise CalibrationLedgerAccountingError("calibration ledger prefix is absent or revoked")

    def close(owner: CalibrationLedgerAccounting) -> None:
        # Revoke first, even when changed runtime bindings make cleanup report failure.
        if getpid() != pid:
            raise CalibrationLedgerAccountingError("calibration accounting belongs to another PID")
        with lock:
            state = state_for(owner)
            del registry[owner]
            for prefix in state.prefixes:
                prefixes.pop(prefix.capability, None)
            reference = owners.get(state.identity)
            if reference is not None and reference() is owner:
                owners.pop(state.identity, None)
        pristine()

    public.update(
        begin_calibration_ledger_accounting=begin,
        retain_calibration_ledger_interval=retain,
        observe_calibration_ledger_accounting=observe,
        require_calibration_accounting_ready=ready,
        require_calibration_ledger_prefix=require_prefix,
        close_calibration_ledger_accounting=close,
    )
    return begin, retain, observe, ready, require_prefix, close


(
    begin_calibration_ledger_accounting,
    retain_calibration_ledger_interval,
    observe_calibration_ledger_accounting,
    require_calibration_accounting_ready,
    require_calibration_ledger_prefix,
    close_calibration_ledger_accounting,
) = _build_accounting()
del _build_accounting


def _build_accounting_scope() -> Callable[
    [AtomicCostLedger], Iterator[CalibrationLedgerAccounting]
]:
    begin = begin_calibration_ledger_accounting
    close = close_calibration_ledger_accounting

    def scope(ledger: AtomicCostLedger) -> Iterator[CalibrationLedgerAccounting]:
        owner = begin(ledger)
        try:
            yield owner
        finally:
            close(owner)

    return scope


calibration_ledger_accounting_scope = contextmanager(_build_accounting_scope())
del _build_accounting_scope
