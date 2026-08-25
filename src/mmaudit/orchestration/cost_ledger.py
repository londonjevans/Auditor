"""Process-safe, secret-free cost reservations for paid model requests."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, localcontext
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

_LEGACY_SCHEMA_VERSION: Final = 1
_PORTFOLIO_SCHEMA_VERSION: Final = 2
_REQUEST_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_DECIMAL_PLACES: Final = 18
_MAX_INTEGER_DIGITS: Final = 12
_MAX_STATE_BYTES: Final = 16 * 1024 * 1024
_LEGACY_STATE_KEYS: Final = frozenset({"schema_version", "cap_usd", "entries"})
_PORTFOLIO_STATE_KEYS: Final = frozenset(
    {"schema_version", "cap_usd", "entries", "portfolio_holds"}
)
_ENTRY_KEYS: Final = frozenset(
    {
        "request_id",
        "reservation_id",
        "status",
        "reserved_usd",
        "actual_cost_usd",
        "accounted_cost_usd",
        "release_reason",
        "created_at",
        "updated_at",
    }
)
_PORTFOLIO_HOLD_KEYS: Final = frozenset(
    {
        "plan_sha256",
        "reservation_id",
        "status",
        "slots",
        "created_at",
        "updated_at",
    }
)
_PORTFOLIO_SLOT_KEYS: Final = frozenset({"request_id", "maximum_cost_usd", "status"})
_MAX_PORTFOLIO_HOLDS: Final = 256
_MAX_PORTFOLIO_SLOTS_PER_HOLD: Final = 1024
_MAX_PORTFOLIO_SLOTS_TOTAL: Final = 4096

_PATH_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[Path, threading.RLock] = {}


class CostLedgerError(RuntimeError):
    """Base class for cost-ledger failures."""


class CostBudgetExceededError(CostLedgerError):
    """Raised before a reservation that could exceed the configured cap."""


class CostLedgerConfigurationError(CostLedgerError):
    """Raised when a ledger cannot safely use its configured path or cap."""


class CostLedgerCorruptError(CostLedgerError):
    """Raised when persisted state cannot be validated exactly."""


class CostReservationStateError(CostLedgerError):
    """Raised for duplicate, unknown, or invalid reservation transitions."""


class CostReservationOverrunError(CostLedgerError):
    """Raised after recording an actual cost larger than its reservation."""


class CostEntryStatus(StrEnum):
    """Persisted lifecycle state for one unique provider request."""

    RESERVED = "reserved"
    RECONCILED = "reconciled"
    RELEASED = "released"
    UNCERTAIN_ACCOUNTED = "uncertain_accounted"
    RESERVATION_OVERRUN = "reservation_overrun"


class ReleaseReason(StrEnum):
    """Closed release reasons that cannot carry arbitrary or secret text."""

    CANCELLED_BEFORE_SEND = "cancelled_before_send"
    FAILED_BEFORE_SEND = "failed_before_send"


class PortfolioHoldStatus(StrEnum):
    """Persisted lifecycle state for one bounded all-request hold."""

    ACTIVE = "active"
    RELEASED = "released"


class PortfolioSlotStatus(StrEnum):
    """Persisted lifecycle state for one exact request slot in a portfolio."""

    HELD = "held"
    CLAIMED = "claimed"
    RELEASED = "released"


class _LedgerOpenMode(StrEnum):
    INITIALIZE = "initialize"
    OPEN_EXISTING = "open_existing"


@dataclass(frozen=True)
class CostReservation:
    """Opaque handle for one active maximum-cost reservation."""

    request_id: str
    reservation_id: str
    reserved_usd: Decimal


@dataclass(frozen=True)
class PortfolioAttemptSlot:
    """One exact request identifier and maximum provider-cost ceiling."""

    request_id: str
    maximum_cost_usd: Decimal

    def __post_init__(self) -> None:
        _validate_request_id(self.request_id)
        _validate_money(
            self.maximum_cost_usd,
            field="maximum_cost_usd",
            positive=True,
        )


@dataclass(frozen=True)
class CostPortfolioReservation:
    """Opaque handle for one durable portfolio hold."""

    plan_sha256: str
    reservation_id: str
    slots: tuple[PortfolioAttemptSlot, ...]


@dataclass(frozen=True)
class CostPortfolioSlot:
    """Validated persisted lifecycle for one held request slot."""

    request_id: str
    maximum_cost_usd: Decimal
    status: PortfolioSlotStatus

    def as_attempt_slot(self) -> PortfolioAttemptSlot:
        return PortfolioAttemptSlot(
            request_id=self.request_id,
            maximum_cost_usd=self.maximum_cost_usd,
        )


@dataclass(frozen=True)
class CostPortfolioHold:
    """Validated durable state for one exact all-request portfolio."""

    plan_sha256: str
    reservation_id: str
    status: PortfolioHoldStatus
    slots: tuple[CostPortfolioSlot, ...]
    created_at: datetime
    updated_at: datetime

    @property
    def initial_slots(self) -> tuple[PortfolioAttemptSlot, ...]:
        return tuple(slot.as_attempt_slot() for slot in self.slots)

    @property
    def remaining_slots(self) -> tuple[PortfolioAttemptSlot, ...]:
        return tuple(
            slot.as_attempt_slot() for slot in self.slots if slot.status is PortfolioSlotStatus.HELD
        )

    @property
    def claimed_slots(self) -> tuple[PortfolioAttemptSlot, ...]:
        return tuple(
            slot.as_attempt_slot()
            for slot in self.slots
            if slot.status is PortfolioSlotStatus.CLAIMED
        )

    @property
    def released_slots(self) -> tuple[PortfolioAttemptSlot, ...]:
        return tuple(
            slot.as_attempt_slot()
            for slot in self.slots
            if slot.status is PortfolioSlotStatus.RELEASED
        )

    def as_reservation(self) -> CostPortfolioReservation:
        if self.status is not PortfolioHoldStatus.ACTIVE:
            raise CostReservationStateError(f"portfolio {self.plan_sha256} is not active")
        return CostPortfolioReservation(
            plan_sha256=self.plan_sha256,
            reservation_id=self.reservation_id,
            slots=self.initial_slots,
        )


@dataclass(frozen=True)
class CostEntry:
    """Validated, non-secret persisted state for one request."""

    request_id: str
    reservation_id: str
    status: CostEntryStatus
    reserved_usd: Decimal
    actual_cost_usd: Decimal | None
    accounted_cost_usd: Decimal
    release_reason: ReleaseReason | None
    created_at: datetime
    updated_at: datetime

    def as_reservation(self) -> CostReservation:
        """Return an active handle, rejecting terminal records."""

        if self.status is not CostEntryStatus.RESERVED:
            raise CostReservationStateError(
                f"request {self.request_id} does not have an active reservation"
            )
        return CostReservation(
            request_id=self.request_id,
            reservation_id=self.reservation_id,
            reserved_usd=self.reserved_usd,
        )


@dataclass(frozen=True)
class CostLedgerSnapshot:
    """Immutable totals derived from validated entries."""

    cap_usd: Decimal
    spent_usd: Decimal
    active_reserved_usd: Decimal
    remaining_usd: Decimal
    over_cap: bool
    has_reservation_overrun: bool
    entries: tuple[CostEntry, ...]
    portfolio_holds: tuple[CostPortfolioHold, ...] = ()
    held_portfolio_usd: Decimal = Decimal(0)


class AtomicCostLedger:
    """Durably reserve and reconcile provider costs under an exact USD cap.

    The on-disk schema accepts only request identifiers, lifecycle state, timestamps,
    and decimal cost values. It has no field for prompts, credentials, headers, model
    output, or arbitrary metadata.

    Active reservations deliberately survive process termination. A recovering caller
    must either reconcile known provider cost, conservatively account the full reservation
    with ``actual_cost_usd=None``, or release it only after proving no request was sent.
    """

    def __init__(
        self,
        path: Path,
        *,
        cap_usd: Decimal,
        _open_mode: _LedgerOpenMode = _LedgerOpenMode.OPEN_EXISTING,
    ) -> None:
        """Open an existing ledger without ever creating missing budget state.

        New ledgers must be created deliberately with :meth:`initialize`. Keeping
        plain construction fail-closed prevents a deleted, moved, or mistyped
        ledger path from silently restoring the full spend allowance.
        """

        if not isinstance(_open_mode, _LedgerOpenMode):
            raise CostLedgerConfigurationError("cost ledger open mode is invalid")
        cap = _validate_money(cap_usd, field="cap_usd", positive=True)
        parent = _validate_operator_ledger_parent(path)

        self.path = parent / path.name
        self.lock_path = parent / f".{path.name}.lock"
        self.cap_usd = cap
        self._thread_lock = _thread_lock_for(self.path)
        initializing = _open_mode is _LedgerOpenMode.INITIALIZE
        if initializing and (_path_entry_exists(self.path) or _path_entry_exists(self.lock_path)):
            raise CostLedgerConfigurationError(
                "cost ledger or lock already exists; initialization is one-time"
            )
        with self._locked(create_lock=initializing):
            state = self._read_state()
            if initializing:
                if state is not None:  # Defensive race check under the newly created lock.
                    raise CostLedgerConfigurationError("cost ledger appeared during initialization")
                self._write_state(_new_state(cap))
                return
            if state is None:
                raise CostLedgerConfigurationError(
                    "existing cost ledger is missing; explicit initialization is required"
                )
            persisted_cap, _entries, _portfolio_holds = _validate_state(state)
            if persisted_cap != cap:
                raise CostLedgerConfigurationError(
                    "configured cost cap does not match the existing ledger"
                )

    @classmethod
    def initialize(cls, path: Path, *, cap_usd: Decimal) -> AtomicCostLedger:
        """Create one new operator-controlled ledger exactly once."""

        return cls(path, cap_usd=cap_usd, _open_mode=_LedgerOpenMode.INITIALIZE)

    @classmethod
    def open_existing(cls, path: Path, *, cap_usd: Decimal) -> AtomicCostLedger:
        """Open existing state, refusing missing ledger or lock files."""

        return cls(path, cap_usd=cap_usd, _open_mode=_LedgerOpenMode.OPEN_EXISTING)

    def reserve(self, request_id: str, maximum_cost_usd: Decimal) -> CostReservation:
        """Atomically reserve a request's maximum possible provider cost."""

        _validate_request_id(request_id)
        requested = _validate_money(
            maximum_cost_usd,
            field="maximum_cost_usd",
            positive=True,
        )
        with self._locked():
            state = self._required_state()
            _cap, entries, portfolio_holds = _validate_state(state)
            if request_id in entries or request_id in _portfolio_request_ids(portfolio_holds):
                raise CostReservationStateError(f"request ID already recorded: {request_id}")
            snapshot = _snapshot(self.cap_usd, entries, portfolio_holds)
            if snapshot.has_reservation_overrun:
                raise CostBudgetExceededError(
                    "a prior provider cost exceeded its reservation; further calls are blocked"
                )
            if requested > snapshot.remaining_usd:
                raise CostBudgetExceededError(
                    f"request {request_id} exceeds the remaining model-cost budget"
                )
            now = _timestamp()
            reservation_id = uuid.uuid4().hex
            entries[request_id] = CostEntry(
                request_id=request_id,
                reservation_id=reservation_id,
                status=CostEntryStatus.RESERVED,
                reserved_usd=requested,
                actual_cost_usd=None,
                accounted_cost_usd=Decimal(0),
                release_reason=None,
                created_at=now,
                updated_at=now,
            )
            self._write_state(_serialize_state(self.cap_usd, entries, portfolio_holds))
        return CostReservation(
            request_id=request_id,
            reservation_id=reservation_id,
            reserved_usd=requested,
        )

    def reserve_portfolio(
        self,
        plan_sha256: str,
        slots: tuple[PortfolioAttemptSlot, ...],
    ) -> CostPortfolioReservation:
        """Atomically hold every exact initial request slot in one durable write."""

        _validate_plan_sha256(plan_sha256)
        exact_slots = _validate_portfolio_attempt_slots(slots)
        with self._locked():
            state = self._required_state()
            _cap, entries, portfolio_holds = _validate_state(state)
            holds = {} if portfolio_holds is None else portfolio_holds
            if plan_sha256 in holds:
                raise CostReservationStateError(
                    f"portfolio plan was already recorded: {plan_sha256}"
                )
            if any(hold.status is PortfolioHoldStatus.ACTIVE for hold in holds.values()):
                raise CostReservationStateError("an active portfolio hold already exists")
            if len(holds) >= _MAX_PORTFOLIO_HOLDS:
                raise CostReservationStateError("cost-ledger portfolio history is full")
            if sum(len(hold.slots) for hold in holds.values()) + len(exact_slots) > (
                _MAX_PORTFOLIO_SLOTS_TOTAL
            ):
                raise CostReservationStateError("cost-ledger portfolio slot history is full")
            existing_request_ids = set(entries).union(_portfolio_request_ids(holds))
            collision = next(
                (
                    slot.request_id
                    for slot in exact_slots
                    if slot.request_id in existing_request_ids
                ),
                None,
            )
            if collision is not None:
                raise CostReservationStateError(f"request ID already recorded: {collision}")
            snapshot = _snapshot(self.cap_usd, entries, portfolio_holds)
            if snapshot.has_reservation_overrun:
                raise CostBudgetExceededError(
                    "a prior provider cost exceeded its reservation; further calls are blocked"
                )
            requested = _portfolio_slot_sum(exact_slots)
            if requested > snapshot.remaining_usd:
                raise CostBudgetExceededError("portfolio exceeds the remaining model-cost budget")
            now = _timestamp()
            hold = CostPortfolioHold(
                plan_sha256=plan_sha256,
                reservation_id=uuid.uuid4().hex,
                status=PortfolioHoldStatus.ACTIVE,
                slots=tuple(
                    CostPortfolioSlot(
                        request_id=slot.request_id,
                        maximum_cost_usd=slot.maximum_cost_usd,
                        status=PortfolioSlotStatus.HELD,
                    )
                    for slot in exact_slots
                ),
                created_at=now,
                updated_at=now,
            )
            holds[plan_sha256] = hold
            self._write_state(_serialize_state(self.cap_usd, entries, holds))
            return hold.as_reservation()

    def recover_portfolio(
        self,
        plan_sha256: str,
        slots: tuple[PortfolioAttemptSlot, ...],
    ) -> CostPortfolioReservation:
        """Idempotently adopt one exact active durable portfolio hold."""

        _validate_plan_sha256(plan_sha256)
        exact_slots = _validate_portfolio_attempt_slots(slots)
        with self._locked():
            state = self._required_state()
            _cap, _entries, portfolio_holds = _validate_state(state)
            hold = None if portfolio_holds is None else portfolio_holds.get(plan_sha256)
            if hold is None:
                raise CostReservationStateError(f"unknown portfolio plan: {plan_sha256}")
            if hold.status is not PortfolioHoldStatus.ACTIVE:
                raise CostReservationStateError(f"portfolio {plan_sha256} is already finalized")
            if hold.initial_slots != exact_slots:
                raise CostReservationStateError(
                    f"portfolio {plan_sha256} differs from its durable initial slots"
                )
            return hold.as_reservation()

    def claim_portfolio_slot(
        self,
        portfolio: CostPortfolioReservation,
        request_id: str,
        exact_maximum_cost_usd: Decimal,
    ) -> CostReservation:
        """Atomically shrink one held slot into an exact ordinary reservation."""

        _validate_request_id(request_id)
        exact_maximum = _validate_money(
            exact_maximum_cost_usd,
            field="exact_maximum_cost_usd",
            positive=True,
        )
        with self._locked():
            state = self._required_state()
            _cap, entries, portfolio_holds = _validate_state(state)
            hold = _matching_portfolio_hold(portfolio_holds, portfolio)
            if hold.status is not PortfolioHoldStatus.ACTIVE:
                raise CostReservationStateError(
                    f"portfolio {portfolio.plan_sha256} is already finalized"
                )
            matching = tuple(slot for slot in hold.slots if slot.request_id == request_id)
            if len(matching) != 1:
                raise CostReservationStateError(
                    f"request {request_id} is not in portfolio {portfolio.plan_sha256}"
                )
            slot = matching[0]
            if slot.status is not PortfolioSlotStatus.HELD:
                raise CostReservationStateError(
                    f"portfolio request {request_id} was already {slot.status.value}"
                )
            if exact_maximum > slot.maximum_cost_usd:
                raise CostBudgetExceededError(
                    f"request {request_id} exceeds its held portfolio ceiling"
                )
            if request_id in entries:
                raise CostReservationStateError(f"request ID already recorded: {request_id}")
            if _snapshot(self.cap_usd, entries, portfolio_holds).has_reservation_overrun:
                raise CostBudgetExceededError(
                    "a prior provider cost exceeded its reservation; further calls are blocked"
                )

            now = _timestamp()
            reservation_id = uuid.uuid4().hex
            entries[request_id] = CostEntry(
                request_id=request_id,
                reservation_id=reservation_id,
                status=CostEntryStatus.RESERVED,
                reserved_usd=exact_maximum,
                actual_cost_usd=None,
                accounted_cost_usd=Decimal(0),
                release_reason=None,
                created_at=now,
                updated_at=now,
            )
            updated_hold = CostPortfolioHold(
                plan_sha256=hold.plan_sha256,
                reservation_id=hold.reservation_id,
                status=hold.status,
                slots=tuple(
                    (
                        CostPortfolioSlot(
                            request_id=current.request_id,
                            maximum_cost_usd=current.maximum_cost_usd,
                            status=PortfolioSlotStatus.CLAIMED,
                        )
                        if current.request_id == request_id
                        else current
                    )
                    for current in hold.slots
                ),
                created_at=hold.created_at,
                updated_at=now,
            )
            assert portfolio_holds is not None
            portfolio_holds[hold.plan_sha256] = updated_hold
            self._write_state(_serialize_state(self.cap_usd, entries, portfolio_holds))
            return CostReservation(
                request_id=request_id,
                reservation_id=reservation_id,
                reserved_usd=exact_maximum,
            )

    def release_portfolio(
        self,
        portfolio: CostPortfolioReservation,
        *,
        expected_remaining_slots: tuple[PortfolioAttemptSlot, ...],
    ) -> CostPortfolioHold:
        """Release exactly the caller-proven unclaimed set and retain its history."""

        expected = _validate_portfolio_attempt_slots(
            expected_remaining_slots,
            allow_empty=True,
        )
        with self._locked():
            state = self._required_state()
            _cap, entries, portfolio_holds = _validate_state(state)
            hold = _matching_portfolio_hold(portfolio_holds, portfolio)
            if hold.status is not PortfolioHoldStatus.ACTIVE:
                raise CostReservationStateError(
                    f"portfolio {portfolio.plan_sha256} is already finalized"
                )
            if hold.remaining_slots != expected:
                raise CostReservationStateError(
                    f"portfolio {portfolio.plan_sha256} remaining slots changed"
                )
            now = _timestamp()
            updated = CostPortfolioHold(
                plan_sha256=hold.plan_sha256,
                reservation_id=hold.reservation_id,
                status=PortfolioHoldStatus.RELEASED,
                slots=tuple(
                    (
                        CostPortfolioSlot(
                            request_id=slot.request_id,
                            maximum_cost_usd=slot.maximum_cost_usd,
                            status=PortfolioSlotStatus.RELEASED,
                        )
                        if slot.status is PortfolioSlotStatus.HELD
                        else slot
                    )
                    for slot in hold.slots
                ),
                created_at=hold.created_at,
                updated_at=now,
            )
            assert portfolio_holds is not None
            portfolio_holds[hold.plan_sha256] = updated
            self._write_state(_serialize_state(self.cap_usd, entries, portfolio_holds))
            return updated

    def reconcile(
        self,
        reservation: CostReservation,
        actual_cost_usd: Decimal | None,
    ) -> CostEntry:
        """Replace a reservation with actual cost, or its full estimate if unknown.

        An unknown cost is conservatively accounted at the reserved maximum. If the
        provider reports more than the reserved maximum, the actual cost is persisted
        honestly and ``CostReservationOverrunError`` is raised after the atomic write.
        """

        actual = (
            None
            if actual_cost_usd is None
            else _validate_money(actual_cost_usd, field="actual_cost_usd", positive=False)
        )
        overrun = False
        with self._locked():
            state = self._required_state()
            _cap, entries, portfolio_holds = _validate_state(state)
            current = _matching_entry(entries, reservation)
            expected_status = (
                CostEntryStatus.UNCERTAIN_ACCOUNTED
                if actual is None
                else (
                    CostEntryStatus.RESERVATION_OVERRUN
                    if actual > reservation.reserved_usd
                    else CostEntryStatus.RECONCILED
                )
            )
            uncertain_to_known = bool(
                current.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
                and actual is not None
                and current.actual_cost_usd is None
                and current.accounted_cost_usd == reservation.reserved_usd
            )
            if current.status is not CostEntryStatus.RESERVED and not uncertain_to_known:
                if (
                    current.status is expected_status
                    and current.actual_cost_usd == actual
                    and current.accounted_cost_usd
                    == (reservation.reserved_usd if actual is None else actual)
                ):
                    if current.status is CostEntryStatus.RESERVATION_OVERRUN:
                        raise CostReservationOverrunError(
                            f"actual cost for {reservation.request_id} exceeded its "
                            "maximum reservation"
                        )
                    return current
                raise CostReservationStateError(
                    f"request {reservation.request_id} was already finalized"
                )

            accounted = reservation.reserved_usd if actual is None else actual
            overrun = actual is not None and actual > reservation.reserved_usd
            status = (
                CostEntryStatus.UNCERTAIN_ACCOUNTED
                if actual is None
                else (
                    CostEntryStatus.RESERVATION_OVERRUN if overrun else CostEntryStatus.RECONCILED
                )
            )
            updated = CostEntry(
                request_id=current.request_id,
                reservation_id=current.reservation_id,
                status=status,
                reserved_usd=current.reserved_usd,
                actual_cost_usd=actual,
                accounted_cost_usd=accounted,
                release_reason=None,
                created_at=current.created_at,
                updated_at=_timestamp(),
            )
            entries[current.request_id] = updated
            self._write_state(_serialize_state(self.cap_usd, entries, portfolio_holds))

        if overrun:
            raise CostReservationOverrunError(
                f"actual cost for {reservation.request_id} exceeded its maximum reservation"
            )
        return updated

    def release(
        self,
        reservation: CostReservation,
        *,
        reason: ReleaseReason,
    ) -> CostEntry:
        """Release a reservation proven unused before any provider request."""

        if not isinstance(reason, ReleaseReason):
            raise CostLedgerConfigurationError("release reason must use the closed reason enum")
        with self._locked():
            state = self._required_state()
            _cap, entries, portfolio_holds = _validate_state(state)
            current = _matching_entry(entries, reservation)
            if current.status is CostEntryStatus.RELEASED:
                if current.release_reason is reason:
                    return current
                raise CostReservationStateError(
                    f"request {reservation.request_id} was released for a different reason"
                )
            if current.status is not CostEntryStatus.RESERVED:
                raise CostReservationStateError(
                    f"request {reservation.request_id} was already finalized"
                )
            updated = CostEntry(
                request_id=current.request_id,
                reservation_id=current.reservation_id,
                status=CostEntryStatus.RELEASED,
                reserved_usd=current.reserved_usd,
                actual_cost_usd=None,
                accounted_cost_usd=Decimal(0),
                release_reason=reason,
                created_at=current.created_at,
                updated_at=_timestamp(),
            )
            entries[current.request_id] = updated
            self._write_state(_serialize_state(self.cap_usd, entries, portfolio_holds))
            return updated

    def active_reservation(self, request_id: str) -> CostReservation | None:
        """Recover a durable active reservation after process interruption."""

        _validate_request_id(request_id)
        with self._locked():
            state = self._required_state()
            _cap, entries, _portfolio_holds = _validate_state(state)
            entry = entries.get(request_id)
            if entry is None or entry.status is not CostEntryStatus.RESERVED:
                return None
            return entry.as_reservation()

    def snapshot(self) -> CostLedgerSnapshot:
        """Return exact totals from a locked, fully validated state."""

        with self._locked():
            state = self._required_state()
            _cap, entries, portfolio_holds = _validate_state(state)
            return _snapshot(self.cap_usd, entries, portfolio_holds)

    @property
    def identity_sha256(self) -> str:
        """Commit the operator-selected ledger and its persistent lock identity."""

        with self._locked() as lock_descriptor:
            lock_details = os.fstat(lock_descriptor)
            material = {
                "schema": "mmaudit.atomic-cost-ledger.identity.v1",
                "canonical_path": self.path.as_posix(),
                "lock_device": lock_details.st_dev,
                "lock_inode": lock_details.st_ino,
                "owner_uid": lock_details.st_uid,
            }
            return hashlib.sha256(
                json.dumps(
                    material,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()

    @contextmanager
    def _locked(self, *, create_lock: bool = False) -> Iterator[int]:
        with self._thread_lock:
            fd = _open_lock_file(self.lock_path, create=create_lock)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                _require_exact_lock_path(self.lock_path, fd)
                try:
                    yield fd
                finally:
                    _require_exact_lock_path(self.lock_path, fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _required_state(self) -> dict[str, Any]:
        state = self._read_state()
        if state is None:
            raise CostLedgerCorruptError("cost ledger disappeared after initialization")
        persisted_cap, _entries, _portfolio_holds = _validate_state(state)
        if persisted_cap != self.cap_usd:
            raise CostLedgerConfigurationError(
                "configured cost cap does not match the existing ledger"
            )
        return state

    def _read_state(self) -> dict[str, Any] | None:
        try:
            descriptor = _open_regular_private_file(self.path)
        except FileNotFoundError:
            return None
        try:
            with os.fdopen(descriptor, encoding="utf-8") as stream:
                if os.fstat(stream.fileno()).st_size > _MAX_STATE_BYTES:
                    raise CostLedgerCorruptError("cost ledger exceeds the bounded state size")
                value = json.load(stream, object_pairs_hook=_unique_object)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CostLedgerCorruptError("cost ledger is not valid UTF-8 JSON") from exc
        if not isinstance(value, dict):
            raise CostLedgerCorruptError("cost ledger root must be an object")
        return value

    def _write_state(self, state: Mapping[str, Any]) -> None:
        material = (
            json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        ).encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(material)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_descriptor = os.open(
                self.path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if temporary.exists():
                temporary.unlink()


def _thread_lock_for(path: Path) -> threading.RLock:
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(path)
        if lock is None:
            lock = threading.RLock()
            _PATH_LOCKS[path] = lock
        return lock


def _path_entry_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CostLedgerConfigurationError("cost ledger path cannot be inspected") from exc
    return True


def _validate_operator_ledger_parent(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or path.name in {"", ".", ".."}:
        raise CostLedgerConfigurationError(
            "cost ledger path must be an absolute operator-selected file"
        )
    parent = path.parent
    try:
        parent_details = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise CostLedgerConfigurationError("cost ledger parent directory is unavailable") from exc
    if (
        resolved_parent != parent
        or not stat.S_ISDIR(parent_details.st_mode)
        or stat.S_ISLNK(parent_details.st_mode)
    ):
        raise CostLedgerConfigurationError(
            "cost ledger parent must be a canonical non-symlink directory"
        )
    if parent_details.st_uid != os.geteuid() or stat.S_IMODE(parent_details.st_mode) != 0o700:
        raise CostLedgerConfigurationError(
            "cost ledger parent must be operator-owned with mode 0700"
        )
    return parent


def _open_lock_file(path: Path, *, create: bool) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        message = (
            "cost ledger lock file is unavailable"
            if create
            else "existing cost ledger lock file is missing or unavailable"
        )
        raise CostLedgerConfigurationError(message) from exc
    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise CostLedgerConfigurationError(
            "cost ledger lock must be a single-link operator-owned mode-0600 regular file"
        )
    return descriptor


def _require_exact_lock_path(path: Path, descriptor: int) -> None:
    """Require the flocked descriptor to remain the exact configured lock path."""

    try:
        held = os.fstat(descriptor)
        current = path.lstat()
    except OSError as exc:
        raise CostLedgerConfigurationError(
            "cost ledger lock changed during the locked operation"
        ) from exc
    if (
        not stat.S_ISREG(held.st_mode)
        or held.st_uid != os.geteuid()
        or held.st_nlink != 1
        or stat.S_IMODE(held.st_mode) != 0o600
        or not stat.S_ISREG(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or current.st_uid != os.geteuid()
        or current.st_nlink != 1
        or stat.S_IMODE(current.st_mode) != 0o600
        or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise CostLedgerConfigurationError("cost ledger lock changed during the locked operation")


def _open_regular_private_file(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise
        raise CostLedgerConfigurationError("cost ledger file is unavailable") from exc
    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise CostLedgerConfigurationError(
            "cost ledger must be a single-link operator-owned mode-0600 regular file"
        )
    return descriptor


def _new_state(cap: Decimal) -> dict[str, Any]:
    return {
        "schema_version": _LEGACY_SCHEMA_VERSION,
        "cap_usd": _money_text(cap),
        "entries": {},
    }


def _serialize_entry(entry: CostEntry) -> dict[str, Any]:
    return {
        "request_id": entry.request_id,
        "reservation_id": entry.reservation_id,
        "status": entry.status.value,
        "reserved_usd": _money_text(entry.reserved_usd),
        "actual_cost_usd": (
            None if entry.actual_cost_usd is None else _money_text(entry.actual_cost_usd)
        ),
        "accounted_cost_usd": _money_text(entry.accounted_cost_usd),
        "release_reason": None if entry.release_reason is None else entry.release_reason.value,
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
    }


def cost_entry_sha256(entry: CostEntry) -> str:
    """Hash every persisted field of one validated non-secret ledger entry."""

    return hashlib.sha256(
        json.dumps(
            _serialize_entry(entry),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def cost_ledger_snapshot_sha256(snapshot: CostLedgerSnapshot) -> str:
    """Hash the exact validated ledger head used as a scheduler baseline."""

    payload: dict[str, Any] = {
        "cap_usd": _money_text(snapshot.cap_usd),
        "spent_usd": _money_text(snapshot.spent_usd),
        "active_reserved_usd": _money_text(snapshot.active_reserved_usd),
        "entries": [
            _serialize_entry(entry)
            for entry in sorted(snapshot.entries, key=lambda item: item.request_id)
        ],
    }
    if snapshot.portfolio_holds:
        payload["portfolio_holds"] = [
            _serialize_portfolio_hold(hold)
            for hold in sorted(snapshot.portfolio_holds, key=lambda item: item.plan_sha256)
        ]
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _serialize_portfolio_hold(hold: CostPortfolioHold) -> dict[str, Any]:
    return {
        "plan_sha256": hold.plan_sha256,
        "reservation_id": hold.reservation_id,
        "status": hold.status.value,
        "slots": [
            {
                "request_id": slot.request_id,
                "maximum_cost_usd": _money_text(slot.maximum_cost_usd),
                "status": slot.status.value,
            }
            for slot in hold.slots
        ],
        "created_at": hold.created_at.isoformat(),
        "updated_at": hold.updated_at.isoformat(),
    }


def _serialize_state(
    cap: Decimal,
    entries: Mapping[str, CostEntry],
    portfolio_holds: Mapping[str, CostPortfolioHold] | None,
) -> dict[str, Any]:
    state: dict[str, Any] = {
        "schema_version": (
            _LEGACY_SCHEMA_VERSION if portfolio_holds is None else _PORTFOLIO_SCHEMA_VERSION
        ),
        "cap_usd": _money_text(cap),
        "entries": {
            request_id: _serialize_entry(entry) for request_id, entry in sorted(entries.items())
        },
    }
    if portfolio_holds is not None:
        state["portfolio_holds"] = {
            plan_sha256: _serialize_portfolio_hold(hold)
            for plan_sha256, hold in sorted(portfolio_holds.items())
        }
    return state


def _validate_state(
    value: Mapping[str, Any],
) -> tuple[Decimal, dict[str, CostEntry], dict[str, CostPortfolioHold] | None]:
    schema_version = value.get("schema_version")
    if type(schema_version) is not int:
        raise CostLedgerCorruptError("unsupported cost ledger schema version")
    expected_keys = (
        _LEGACY_STATE_KEYS if schema_version == _LEGACY_SCHEMA_VERSION else _PORTFOLIO_STATE_KEYS
    )
    if set(value) != expected_keys:
        raise CostLedgerCorruptError("cost ledger contains unexpected or missing fields")
    if schema_version not in {_LEGACY_SCHEMA_VERSION, _PORTFOLIO_SCHEMA_VERSION}:
        raise CostLedgerCorruptError("unsupported cost ledger schema version")
    try:
        cap = _validate_money(
            Decimal(_required_string(value, "cap_usd")),
            field="cap_usd",
            positive=True,
        )
    except (InvalidOperation, CostLedgerConfigurationError) as exc:
        raise CostLedgerCorruptError("cost ledger cap is invalid") from exc
    raw_entries = value.get("entries")
    if not isinstance(raw_entries, dict):
        raise CostLedgerCorruptError("cost ledger entries must be an object")
    entries: dict[str, CostEntry] = {}
    for key, raw_entry in raw_entries.items():
        if not isinstance(key, str) or not isinstance(raw_entry, dict):
            raise CostLedgerCorruptError("cost ledger entry is invalid")
        entry = _parse_entry(raw_entry)
        if key != entry.request_id or key in entries:
            raise CostLedgerCorruptError("cost ledger entry key does not match its request ID")
        entries[key] = entry
    portfolio_holds = (
        None
        if schema_version == _LEGACY_SCHEMA_VERSION
        else _parse_portfolio_holds(value.get("portfolio_holds"))
    )
    _validate_lifecycle(entries, portfolio_holds)
    return cap, entries, portfolio_holds


def _parse_portfolio_holds(value: object) -> dict[str, CostPortfolioHold]:
    if not isinstance(value, dict) or not value or len(value) > _MAX_PORTFOLIO_HOLDS:
        raise CostLedgerCorruptError("cost ledger portfolio holds are invalid or over their bound")
    holds: dict[str, CostPortfolioHold] = {}
    total_slots = 0
    for key, raw_hold in value.items():
        if not isinstance(key, str) or not isinstance(raw_hold, dict):
            raise CostLedgerCorruptError("cost ledger portfolio hold is invalid")
        hold = _parse_portfolio_hold(raw_hold)
        total_slots += len(hold.slots)
        if total_slots > _MAX_PORTFOLIO_SLOTS_TOTAL:
            raise CostLedgerCorruptError("cost ledger portfolio slot history exceeds its bound")
        if key != hold.plan_sha256 or key in holds:
            raise CostLedgerCorruptError("cost ledger portfolio key does not match its plan hash")
        holds[key] = hold
    return holds


def _parse_portfolio_hold(value: Mapping[str, Any]) -> CostPortfolioHold:
    if set(value) != _PORTFOLIO_HOLD_KEYS:
        raise CostLedgerCorruptError(
            "cost ledger portfolio hold contains unexpected or missing fields"
        )
    plan_sha256 = _required_string(value, "plan_sha256")
    try:
        _validate_plan_sha256(plan_sha256)
    except CostLedgerConfigurationError as exc:
        raise CostLedgerCorruptError("cost ledger portfolio plan hash is invalid") from exc
    reservation_id = _required_string(value, "reservation_id")
    if re.fullmatch(r"[0-9a-f]{32}", reservation_id) is None:
        raise CostLedgerCorruptError("cost ledger portfolio reservation ID is invalid")
    raw_slots = value.get("slots")
    if (
        not isinstance(raw_slots, list)
        or not raw_slots
        or len(raw_slots) > _MAX_PORTFOLIO_SLOTS_PER_HOLD
    ):
        raise CostLedgerCorruptError("cost ledger portfolio slots are invalid or over their bound")
    slots: list[CostPortfolioSlot] = []
    request_ids: set[str] = set()
    for raw_slot in raw_slots:
        if not isinstance(raw_slot, dict) or set(raw_slot) != _PORTFOLIO_SLOT_KEYS:
            raise CostLedgerCorruptError("cost ledger portfolio slot is invalid")
        request_id = _required_string(raw_slot, "request_id")
        try:
            _validate_request_id(request_id)
            maximum_cost = _validate_money(
                Decimal(_required_string(raw_slot, "maximum_cost_usd")),
                field="maximum_cost_usd",
                positive=True,
            )
            slot_status = PortfolioSlotStatus(_required_string(raw_slot, "status"))
        except (InvalidOperation, ValueError, CostLedgerConfigurationError) as exc:
            raise CostLedgerCorruptError("cost ledger portfolio slot value is invalid") from exc
        if request_id in request_ids:
            raise CostLedgerCorruptError("cost ledger portfolio request IDs must be unique")
        request_ids.add(request_id)
        slots.append(
            CostPortfolioSlot(
                request_id=request_id,
                maximum_cost_usd=maximum_cost,
                status=slot_status,
            )
        )
    try:
        hold_status = PortfolioHoldStatus(_required_string(value, "status"))
        created_at = _parse_timestamp(_required_string(value, "created_at"))
        updated_at = _parse_timestamp(_required_string(value, "updated_at"))
    except (ValueError, CostLedgerCorruptError) as exc:
        raise CostLedgerCorruptError("cost ledger portfolio hold value is invalid") from exc
    if updated_at < created_at:
        raise CostLedgerCorruptError("cost ledger portfolio timestamp order is invalid")
    return CostPortfolioHold(
        plan_sha256=plan_sha256,
        reservation_id=reservation_id,
        status=hold_status,
        slots=tuple(slots),
        created_at=created_at,
        updated_at=updated_at,
    )


def _parse_entry(value: Mapping[str, Any]) -> CostEntry:
    if set(value) != _ENTRY_KEYS:
        raise CostLedgerCorruptError("cost ledger entry contains unexpected or missing fields")
    request_id = _required_string(value, "request_id")
    try:
        _validate_request_id(request_id)
    except CostLedgerConfigurationError as exc:
        raise CostLedgerCorruptError("cost ledger request ID is invalid") from exc
    reservation_id = _required_string(value, "reservation_id")
    if not re.fullmatch(r"[0-9a-f]{32}", reservation_id):
        raise CostLedgerCorruptError("cost ledger reservation ID is invalid")
    try:
        status_value = CostEntryStatus(_required_string(value, "status"))
        reserved = _validate_money(
            Decimal(_required_string(value, "reserved_usd")),
            field="reserved_usd",
            positive=True,
        )
        accounted = _validate_money(
            Decimal(_required_string(value, "accounted_cost_usd")),
            field="accounted_cost_usd",
            positive=False,
        )
        raw_actual = value.get("actual_cost_usd")
        actual = (
            None
            if raw_actual is None
            else _validate_money(
                Decimal(_string_value(raw_actual)),
                field="actual_cost_usd",
                positive=False,
            )
        )
        raw_release_reason = value.get("release_reason")
        release_reason = (
            None if raw_release_reason is None else ReleaseReason(_string_value(raw_release_reason))
        )
        created_at = _parse_timestamp(_required_string(value, "created_at"))
        updated_at = _parse_timestamp(_required_string(value, "updated_at"))
    except (InvalidOperation, ValueError, CostLedgerConfigurationError) as exc:
        raise CostLedgerCorruptError("cost ledger entry value is invalid") from exc
    if updated_at < created_at:
        raise CostLedgerCorruptError("cost ledger entry timestamp order is invalid")
    return CostEntry(
        request_id=request_id,
        reservation_id=reservation_id,
        status=status_value,
        reserved_usd=reserved,
        actual_cost_usd=actual,
        accounted_cost_usd=accounted,
        release_reason=release_reason,
        created_at=created_at,
        updated_at=updated_at,
    )


def _validate_lifecycle(
    entries: Mapping[str, CostEntry],
    portfolio_holds: Mapping[str, CostPortfolioHold] | None,
) -> None:
    for entry in entries.values():
        if entry.status is CostEntryStatus.RESERVED:
            valid = (
                entry.actual_cost_usd is None
                and entry.accounted_cost_usd == 0
                and entry.release_reason is None
            )
        elif entry.status is CostEntryStatus.RELEASED:
            valid = (
                entry.actual_cost_usd is None
                and entry.accounted_cost_usd == 0
                and entry.release_reason is not None
            )
        elif entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED:
            valid = (
                entry.actual_cost_usd is None
                and entry.accounted_cost_usd == entry.reserved_usd
                and entry.release_reason is None
            )
        elif entry.status is CostEntryStatus.RECONCILED:
            valid = (
                entry.actual_cost_usd is not None
                and entry.actual_cost_usd <= entry.reserved_usd
                and entry.accounted_cost_usd == entry.actual_cost_usd
                and entry.release_reason is None
            )
        else:
            valid = (
                entry.actual_cost_usd is not None
                and entry.actual_cost_usd > entry.reserved_usd
                and entry.accounted_cost_usd == entry.actual_cost_usd
                and entry.release_reason is None
            )
        if not valid:
            raise CostLedgerCorruptError(
                f"cost ledger lifecycle state is inconsistent for {entry.request_id}"
            )

    if portfolio_holds is None:
        return
    portfolio_request_ids: set[str] = set()
    active_holds = 0
    for hold in portfolio_holds.values():
        if hold.status is PortfolioHoldStatus.ACTIVE:
            active_holds += 1
            if any(slot.status is PortfolioSlotStatus.RELEASED for slot in hold.slots):
                raise CostLedgerCorruptError(
                    f"active portfolio has released request slots: {hold.plan_sha256}"
                )
        elif any(slot.status is PortfolioSlotStatus.HELD for slot in hold.slots):
            raise CostLedgerCorruptError(
                f"released portfolio retains held request slots: {hold.plan_sha256}"
            )
        for slot in hold.slots:
            if slot.request_id in portfolio_request_ids:
                raise CostLedgerCorruptError(
                    "cost ledger portfolio request IDs must be globally unique"
                )
            portfolio_request_ids.add(slot.request_id)
            matching_entry = entries.get(slot.request_id)
            if slot.status is PortfolioSlotStatus.CLAIMED:
                if matching_entry is None or matching_entry.reserved_usd > slot.maximum_cost_usd:
                    raise CostLedgerCorruptError(
                        f"claimed portfolio slot lacks its exact entry: {slot.request_id}"
                    )
            elif matching_entry is not None:
                raise CostLedgerCorruptError(
                    f"unclaimed portfolio slot has an ordinary entry: {slot.request_id}"
                )
    if active_holds > 1:
        raise CostLedgerCorruptError("cost ledger has multiple active portfolio holds")


def _snapshot(
    cap: Decimal,
    entries: Mapping[str, CostEntry],
    portfolio_holds: Mapping[str, CostPortfolioHold] | None,
) -> CostLedgerSnapshot:
    with localcontext() as context:
        context.prec = 128
        spent = sum(
            (entry.accounted_cost_usd for entry in entries.values()),
            start=Decimal(0),
        )
        reserved = sum(
            (
                entry.reserved_usd
                for entry in entries.values()
                if entry.status is CostEntryStatus.RESERVED
            ),
            start=Decimal(0),
        )
        held = sum(
            (
                slot.maximum_cost_usd
                for hold in (portfolio_holds or {}).values()
                if hold.status is PortfolioHoldStatus.ACTIVE
                for slot in hold.slots
                if slot.status is PortfolioSlotStatus.HELD
            ),
            start=Decimal(0),
        )
        active = reserved + held
        available = cap - spent - active
    return CostLedgerSnapshot(
        cap_usd=cap,
        spent_usd=spent,
        active_reserved_usd=active,
        remaining_usd=max(Decimal(0), available),
        over_cap=available < 0,
        has_reservation_overrun=any(
            entry.status is CostEntryStatus.RESERVATION_OVERRUN for entry in entries.values()
        ),
        entries=tuple(entries[key] for key in sorted(entries)),
        portfolio_holds=tuple(
            (portfolio_holds or {})[key] for key in sorted(portfolio_holds or {})
        ),
        held_portfolio_usd=held,
    )


def _portfolio_request_ids(
    portfolio_holds: Mapping[str, CostPortfolioHold] | None,
) -> set[str]:
    return {slot.request_id for hold in (portfolio_holds or {}).values() for slot in hold.slots}


def _portfolio_slot_sum(slots: tuple[PortfolioAttemptSlot, ...]) -> Decimal:
    with localcontext() as context:
        context.prec = 128
        return sum((slot.maximum_cost_usd for slot in slots), start=Decimal(0))


def _validate_portfolio_attempt_slots(
    slots: tuple[PortfolioAttemptSlot, ...],
    *,
    allow_empty: bool = False,
) -> tuple[PortfolioAttemptSlot, ...]:
    if type(slots) is not tuple or (not slots and not allow_empty):
        raise CostLedgerConfigurationError(
            "portfolio slots must be supplied as a non-empty exact tuple"
        )
    if len(slots) > _MAX_PORTFOLIO_SLOTS_PER_HOLD:
        raise CostLedgerConfigurationError("portfolio slots exceed their compiled bound")
    if any(type(slot) is not PortfolioAttemptSlot for slot in slots):
        raise CostLedgerConfigurationError("portfolio slots must use exact slot records")
    request_ids: set[str] = set()
    for slot in slots:
        _validate_request_id(slot.request_id)
        _validate_money(
            slot.maximum_cost_usd,
            field="maximum_cost_usd",
            positive=True,
        )
        if slot.request_id in request_ids:
            raise CostLedgerConfigurationError("portfolio request IDs must be unique")
        request_ids.add(slot.request_id)
    return slots


def _matching_portfolio_hold(
    portfolio_holds: Mapping[str, CostPortfolioHold] | None,
    reservation: CostPortfolioReservation,
) -> CostPortfolioHold:
    if type(reservation) is not CostPortfolioReservation:
        raise CostReservationStateError("portfolio reservation handle type is invalid")
    _validate_plan_sha256(reservation.plan_sha256)
    if re.fullmatch(r"[0-9a-f]{32}", reservation.reservation_id) is None:
        raise CostReservationStateError("portfolio reservation handle ID is invalid")
    exact_slots = _validate_portfolio_attempt_slots(reservation.slots)
    current = None if portfolio_holds is None else portfolio_holds.get(reservation.plan_sha256)
    if current is None:
        raise CostReservationStateError(f"unknown portfolio plan: {reservation.plan_sha256}")
    if current.reservation_id != reservation.reservation_id or current.initial_slots != exact_slots:
        raise CostReservationStateError(
            f"portfolio handle does not match plan {reservation.plan_sha256}"
        )
    return current


def _matching_entry(
    entries: Mapping[str, CostEntry],
    reservation: CostReservation,
) -> CostEntry:
    _validate_request_id(reservation.request_id)
    expected_cost = _validate_money(
        reservation.reserved_usd,
        field="reserved_usd",
        positive=True,
    )
    current = entries.get(reservation.request_id)
    if current is None:
        raise CostReservationStateError(f"unknown request ID: {reservation.request_id}")
    if (
        current.reservation_id != reservation.reservation_id
        or current.reserved_usd != expected_cost
    ):
        raise CostReservationStateError(
            f"reservation handle does not match request {reservation.request_id}"
        )
    return current


def _validate_request_id(value: str) -> None:
    if type(value) is not str or not _REQUEST_ID_PATTERN.fullmatch(value):
        raise CostLedgerConfigurationError(
            "request ID must be 1-128 restricted non-secret identifier characters"
        )


def _validate_plan_sha256(value: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise CostLedgerConfigurationError("portfolio plan SHA-256 is invalid")


def _validate_money(value: Decimal, *, field: str, positive: bool) -> Decimal:
    if type(value) is not Decimal:
        raise CostLedgerConfigurationError(f"{field} must be provided as Decimal")
    if not value.is_finite() or (value <= 0 if positive else value < 0):
        qualifier = "positive" if positive else "non-negative"
        raise CostLedgerConfigurationError(f"{field} must be a finite {qualifier} Decimal")
    if value == 0:
        value = Decimal(0)
    sign, digits, exponent = value.as_tuple()
    del sign
    if not isinstance(exponent, int):
        raise CostLedgerConfigurationError(f"{field} must be a finite Decimal")
    while len(digits) > 1 and digits[-1] == 0:
        digits = digits[:-1]
        exponent += 1
    decimal_places = max(0, -exponent)
    integer_digits = max(1, len(digits) + exponent)
    if decimal_places > _MAX_DECIMAL_PLACES or integer_digits > _MAX_INTEGER_DIGITS:
        raise CostLedgerConfigurationError(f"{field} exceeds supported exact decimal bounds")
    return value


def _money_text(value: Decimal) -> str:
    material = format(value, "f")
    if "." in material:
        material = material.rstrip("0").rstrip(".")
    return material or "0"


def _required_string(value: Mapping[str, Any], field: str) -> str:
    return _string_value(value.get(field))


def _string_value(value: object) -> str:
    if not isinstance(value, str):
        raise CostLedgerCorruptError("cost ledger string field is invalid")
    return value


def _parse_timestamp(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(timestamp):
        raise CostLedgerCorruptError("cost ledger timestamps must use UTC")
    return timestamp


def _timestamp() -> datetime:
    return datetime.now(UTC)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CostLedgerCorruptError("cost ledger contains a duplicate JSON field")
        result[key] = value
    return result
