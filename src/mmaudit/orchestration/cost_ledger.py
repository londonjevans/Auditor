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

_SCHEMA_VERSION: Final = 1
_REQUEST_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_DECIMAL_PLACES: Final = 18
_MAX_INTEGER_DIGITS: Final = 12
_MAX_STATE_BYTES: Final = 16 * 1024 * 1024
_STATE_KEYS: Final = frozenset({"schema_version", "cap_usd", "entries"})
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
            persisted_cap, _entries = _validate_state(state)
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
            _cap, entries = _validate_state(state)
            if request_id in entries:
                raise CostReservationStateError(f"request ID already recorded: {request_id}")
            snapshot = _snapshot(self.cap_usd, entries)
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
            self._write_state(_serialize_state(self.cap_usd, entries))
        return CostReservation(
            request_id=request_id,
            reservation_id=reservation_id,
            reserved_usd=requested,
        )

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
            _cap, entries = _validate_state(state)
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
            if current.status is not CostEntryStatus.RESERVED:
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
            self._write_state(_serialize_state(self.cap_usd, entries))

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
            _cap, entries = _validate_state(state)
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
            self._write_state(_serialize_state(self.cap_usd, entries))
            return updated

    def active_reservation(self, request_id: str) -> CostReservation | None:
        """Recover a durable active reservation after process interruption."""

        _validate_request_id(request_id)
        with self._locked():
            state = self._required_state()
            _cap, entries = _validate_state(state)
            entry = entries.get(request_id)
            if entry is None or entry.status is not CostEntryStatus.RESERVED:
                return None
            return entry.as_reservation()

    def snapshot(self) -> CostLedgerSnapshot:
        """Return exact totals from a locked, fully validated state."""

        with self._locked():
            state = self._required_state()
            _cap, entries = _validate_state(state)
            return _snapshot(self.cap_usd, entries)

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
        persisted_cap, _entries = _validate_state(state)
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
        "schema_version": _SCHEMA_VERSION,
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

    return hashlib.sha256(
        json.dumps(
            {
                "cap_usd": _money_text(snapshot.cap_usd),
                "spent_usd": _money_text(snapshot.spent_usd),
                "active_reserved_usd": _money_text(snapshot.active_reserved_usd),
                "entries": [
                    _serialize_entry(entry)
                    for entry in sorted(snapshot.entries, key=lambda item: item.request_id)
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _serialize_state(cap: Decimal, entries: Mapping[str, CostEntry]) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "cap_usd": _money_text(cap),
        "entries": {
            request_id: _serialize_entry(entry) for request_id, entry in sorted(entries.items())
        },
    }


def _validate_state(value: Mapping[str, Any]) -> tuple[Decimal, dict[str, CostEntry]]:
    if set(value) != _STATE_KEYS:
        raise CostLedgerCorruptError("cost ledger contains unexpected or missing fields")
    if value.get("schema_version") != _SCHEMA_VERSION:
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
    _validate_lifecycle(entries)
    return cap, entries


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


def _validate_lifecycle(entries: Mapping[str, CostEntry]) -> None:
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


def _snapshot(cap: Decimal, entries: Mapping[str, CostEntry]) -> CostLedgerSnapshot:
    with localcontext() as context:
        context.prec = 64
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
        available = cap - spent - reserved
    return CostLedgerSnapshot(
        cap_usd=cap,
        spent_usd=spent,
        active_reserved_usd=reserved,
        remaining_usd=max(Decimal(0), available),
        over_cap=available < 0,
        has_reservation_overrun=any(
            entry.status is CostEntryStatus.RESERVATION_OVERRUN for entry in entries.values()
        ),
        entries=tuple(entries[key] for key in sorted(entries)),
    )


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
    if not _REQUEST_ID_PATTERN.fullmatch(value):
        raise CostLedgerConfigurationError(
            "request ID must be 1-128 restricted non-secret identifier characters"
        )


def _validate_money(value: Decimal, *, field: str, positive: bool) -> Decimal:
    if not isinstance(value, Decimal):
        raise CostLedgerConfigurationError(f"{field} must be provided as Decimal")
    if not value.is_finite() or (value <= 0 if positive else value < 0):
        qualifier = "positive" if positive else "non-negative"
        raise CostLedgerConfigurationError(f"{field} must be a finite {qualifier} Decimal")
    if value == 0:
        value = Decimal(0)
    normalized = value.normalize()
    sign, digits, exponent = normalized.as_tuple()
    del sign
    if not isinstance(exponent, int):
        raise CostLedgerConfigurationError(f"{field} must be a finite Decimal")
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
