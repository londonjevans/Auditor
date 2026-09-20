"""Exact-snapshot runner ledger custody, independent of runner and calibration ownership."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import weakref
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from decimal import Decimal, localcontext
from itertools import islice
from typing import Literal, Never, SupportsIndex, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

import mmaudit.orchestration.cost_ledger as _cost_ledger_module
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


_DECIMAL_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")


_RUNNER_LEDGER_CAP_USD = Decimal("250")


_MAX_INTERVAL_REQUEST_IDS = 100_000


class AuthenticatedCrossLineageRunnerError(ValueError):
    """Authenticated runner evidence or live custody is invalid."""


class _StrictFrozenEvidence(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class OpenCrossLineageLedgerInterval:
    """Opaque PID-local start marker for one exact atomic-ledger interval."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> OpenCrossLineageLedgerInterval:
        del cls
        raise TypeError("open cross-lineage ledger interval cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be serialized")


class ClosedCrossLineageLedgerInterval:
    """Opaque PID-local proof of one exact reconciled append-only interval."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ClosedCrossLineageLedgerInterval:
        del cls
        raise TypeError("closed cross-lineage ledger interval cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be serialized")


class AuthenticatedCrossLineageLedgerEntryEvidence(_StrictFrozenEvidence):
    """Durable, non-authorizing binding for one known-cost interval entry."""

    request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    reserved_usd: str | None = Field(
        default=None,
        pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$",
    )
    actual_cost_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")

    @field_validator("reserved_usd", "actual_cost_usd")
    @classmethod
    def cost_is_canonical(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _decimal_text(_parse_decimal(value, label="ledger entry cost")) != value:
            raise ValueError("ledger entry cost is not canonical")
        return value


class AuthenticatedCrossLineageLedgerIntervalEvidence(_StrictFrozenEvidence):
    """Durable evidence for a closed interval; it cannot recreate live custody."""

    ledger_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    initial_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    cap_usd: Literal["250"] = "250"
    initial_spent_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    interval_spent_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    final_spent_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    entries: tuple[AuthenticatedCrossLineageLedgerEntryEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_INTERVAL_REQUEST_IDS,
    )

    @model_validator(mode="after")
    def interval_is_exact(self) -> AuthenticatedCrossLineageLedgerIntervalEvidence:
        request_ids = tuple(item.request_id for item in self.entries)
        if request_ids != tuple(sorted(set(request_ids))):
            raise ValueError("cross-lineage ledger entries must be unique and sorted")
        initial = _parse_decimal(self.initial_spent_usd, label="initial ledger spend")
        interval = _parse_decimal(self.interval_spent_usd, label="interval ledger spend")
        final = _parse_decimal(self.final_spent_usd, label="final ledger spend")
        if any(
            _decimal_text(value) != text
            for value, text in (
                (initial, self.initial_spent_usd),
                (interval, self.interval_spent_usd),
                (final, self.final_spent_usd),
            )
        ):
            raise ValueError("cross-lineage ledger spend is not canonical")
        with localcontext() as context:
            context.prec = 64
            entry_total = sum(
                (
                    _parse_decimal(item.actual_cost_usd, label="interval entry cost")
                    for item in self.entries
                ),
                start=Decimal(0),
            )
        if any(
            item.reserved_usd is not None
            and _parse_decimal(item.actual_cost_usd, label="ledger entry actual cost")
            > _parse_decimal(item.reserved_usd, label="ledger entry reserved cost")
            for item in self.entries
        ):
            raise ValueError("cross-lineage ledger actual cost exceeds its reservation")
        if interval != entry_total or final != initial + interval:
            raise ValueError("cross-lineage ledger interval spend is inconsistent")
        if final >= _RUNNER_LEDGER_CAP_USD:
            raise ValueError("cross-lineage ledger final spend must remain below 250 USD")
        return self


@dataclass(frozen=True, slots=True)
class _ClosedLedgerIntervalView:
    capability: ClosedCrossLineageLedgerInterval
    ledger: AtomicCostLedger
    ledger_identity_sha256: str
    initial_snapshot: CostLedgerSnapshot
    final_snapshot: CostLedgerSnapshot
    new_entries: tuple[CostEntry, ...]
    evidence: AuthenticatedCrossLineageLedgerIntervalEvidence


def _parse_decimal(value: str, *, label: str) -> Decimal:
    if type(value) is not str or _DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    parsed = Decimal(value)
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{label} is invalid")
    return parsed


def _decimal_text(value: Decimal) -> str:
    if type(value) is not Decimal or not value.is_finite() or value < 0:
        raise ValueError("money value is invalid")
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _entry_material(entry: CostEntry) -> dict[str, object]:
    return {
        "request_id": entry.request_id,
        "reservation_id": entry.reservation_id,
        "status": entry.status.value,
        "reserved_usd": _decimal_text(entry.reserved_usd),
        "actual_cost_usd": (
            None if entry.actual_cost_usd is None else _decimal_text(entry.actual_cost_usd)
        ),
        "accounted_cost_usd": _decimal_text(entry.accounted_cost_usd),
        "release_reason": None if entry.release_reason is None else entry.release_reason.value,
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
    }


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _entry_sha256(entry: CostEntry) -> str:
    return _canonical_sha256(_entry_material(entry))


def _snapshot_sha256(snapshot: CostLedgerSnapshot) -> str:
    return _canonical_sha256(
        {
            "cap_usd": _decimal_text(snapshot.cap_usd),
            "spent_usd": _decimal_text(snapshot.spent_usd),
            "active_reserved_usd": _decimal_text(snapshot.active_reserved_usd),
            "entries": [_entry_material(item) for item in snapshot.entries],
        }
    )


def _build_cross_lineage_ledger_interval_authority() -> tuple[
    Callable[[AtomicCostLedger], OpenCrossLineageLedgerInterval],
    Callable[..., ClosedCrossLineageLedgerInterval],
    Callable[[ClosedCrossLineageLedgerInterval], _ClosedLedgerIntervalView],
    Callable[[ClosedCrossLineageLedgerInterval], _ClosedLedgerIntervalView],
    Callable[[], None],
]:
    """Build hidden registries for exact process-local ledger interval custody."""

    @dataclass(frozen=True, slots=True)
    class OpenState:
        process_id: int
        ledger: AtomicCostLedger
        ledger_identity_sha256: str
        initial_snapshot: CostLedgerSnapshot

    @dataclass(slots=True)
    class ClosedState:
        process_id: int
        view: _ClosedLedgerIntervalView
        claimed: bool = False

    open_registry: weakref.WeakKeyDictionary[OpenCrossLineageLedgerInterval, OpenState] = (
        weakref.WeakKeyDictionary()
    )
    closed_registry: weakref.WeakKeyDictionary[ClosedCrossLineageLedgerInterval, ClosedState] = (
        weakref.WeakKeyDictionary()
    )
    lock = threading.RLock()
    namespace = globals()
    trusted_self_module = sys.modules[__name__]
    trusted_cost_ledger_module = _cost_ledger_module
    trusted_sys_module = sys
    trusted_os_module = os
    trusted_json_module = json
    trusted_hashlib_module = hashlib
    trusted_getpid = os.getpid
    trusted_os_functions = {
        name: getattr(os, name) for name in ("close", "fdopen", "fstat", "geteuid", "open")
    }
    trusted_json_dumps = json.dumps
    trusted_json_load = json.load
    trusted_sha256 = hashlib.sha256
    trusted_snapshot = AtomicCostLedger.snapshot
    trusted_identity_getter = cast(property, AtomicCostLedger.identity_sha256).fget
    assert trusted_identity_getter is not None
    trusted_cost_ledger_callables = {
        name: getattr(trusted_cost_ledger_module, name)
        for name in (
            "_open_lock_file",
            "_open_regular_private_file",
            "_require_exact_lock_path",
            "_snapshot",
            "_unique_object",
            "_validate_state",
        )
    }

    def ledger_descriptor_surface() -> tuple[tuple[str, object], ...]:
        return tuple(
            sorted(
                (
                    (name, descriptor)
                    for name, descriptor in vars(AtomicCostLedger).items()
                    if callable(descriptor)
                    or isinstance(descriptor, (classmethod, staticmethod, property))
                ),
                key=lambda item: item[0],
            )
        )

    trusted_ledger_descriptor_surface = ledger_descriptor_surface()
    trusted_objects = {
        "AtomicCostLedger": AtomicCostLedger,
        "CostEntry": CostEntry,
        "CostEntryStatus": CostEntryStatus,
        "CostLedgerSnapshot": CostLedgerSnapshot,
        "OpenCrossLineageLedgerInterval": OpenCrossLineageLedgerInterval,
        "ClosedCrossLineageLedgerInterval": ClosedCrossLineageLedgerInterval,
        "AuthenticatedCrossLineageLedgerEntryEvidence": (
            AuthenticatedCrossLineageLedgerEntryEvidence
        ),
        "AuthenticatedCrossLineageLedgerIntervalEvidence": (
            AuthenticatedCrossLineageLedgerIntervalEvidence
        ),
        "_canonical_sha256": _canonical_sha256,
        "_decimal_text": _decimal_text,
        "_entry_material": _entry_material,
        "_entry_sha256": _entry_sha256,
        "_snapshot_sha256": _snapshot_sha256,
    }
    public_bindings: dict[str, object] = {}

    def require_pristine() -> None:
        if (
            namespace.get("sys") is not trusted_sys_module
            or namespace.get("os") is not trusted_os_module
            or namespace.get("json") is not trusted_json_module
            or namespace.get("hashlib") is not trusted_hashlib_module
            or namespace.get("_cost_ledger_module") is not trusted_cost_ledger_module
            or trusted_sys_module.modules.get(__name__) is not trusted_self_module
            or trusted_sys_module.modules.get(trusted_cost_ledger_module.__name__)
            is not trusted_cost_ledger_module
            or any(namespace.get(name) is not value for name, value in trusted_objects.items())
            or any(namespace.get(name) is not value for name, value in public_bindings.items())
            or trusted_cost_ledger_module.AtomicCostLedger is not AtomicCostLedger
            or trusted_cost_ledger_module.CostEntry is not CostEntry
            or trusted_cost_ledger_module.CostEntryStatus is not CostEntryStatus
            or trusted_cost_ledger_module.CostLedgerSnapshot is not CostLedgerSnapshot
            or any(
                getattr(trusted_cost_ledger_module, name) is not value
                for name, value in trusted_cost_ledger_callables.items()
            )
            or ledger_descriptor_surface() != trusted_ledger_descriptor_surface
            or AtomicCostLedger.snapshot is not trusted_snapshot
            or cast(property, AtomicCostLedger.identity_sha256).fget is not trusted_identity_getter
            or os.getpid is not trusted_getpid
            or any(getattr(os, name) is not value for name, value in trusted_os_functions.items())
            or json.dumps is not trusted_json_dumps
            or json.load is not trusted_json_load
            or hashlib.sha256 is not trusted_sha256
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner ledger verifier runtime is not pristine"
            )

    def require_clean_snapshot(snapshot: CostLedgerSnapshot, *, final: bool) -> None:
        if (
            type(snapshot) is not CostLedgerSnapshot
            or snapshot.cap_usd != _RUNNER_LEDGER_CAP_USD
            or snapshot.active_reserved_usd != 0
            or snapshot.over_cap
            or snapshot.has_reservation_overrun
            or any(
                item.status
                in {
                    CostEntryStatus.RESERVED,
                    CostEntryStatus.RESERVATION_OVERRUN,
                }
                for item in snapshot.entries
            )
            or (final and snapshot.spent_usd >= _RUNNER_LEDGER_CAP_USD)
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger is not a terminal non-overrun 250 USD ledger"
            )

    def current_view(state: ClosedState) -> _ClosedLedgerIntervalView:
        if state.process_id != trusted_getpid():
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval belongs to another process"
            )
        view = state.view
        if (
            type(view.ledger) is not AtomicCostLedger
            or trusted_identity_getter(view.ledger) != view.ledger_identity_sha256
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger identity changed"
            )
        current = trusted_snapshot(view.ledger)
        require_clean_snapshot(current, final=True)
        if current != view.final_snapshot:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger changed after closure"
            )
        return view

    def begin(ledger: AtomicCostLedger) -> OpenCrossLineageLedgerInterval:
        require_pristine()
        if type(ledger) is not AtomicCostLedger:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval requires the exact atomic ledger type"
            )
        identity = trusted_identity_getter(ledger)
        initial = trusted_snapshot(ledger)
        require_clean_snapshot(initial, final=False)
        capability = object.__new__(OpenCrossLineageLedgerInterval)
        with lock:
            open_registry[capability] = OpenState(
                process_id=trusted_getpid(),
                ledger=ledger,
                ledger_identity_sha256=identity,
                initial_snapshot=initial,
            )
        require_pristine()
        return capability

    def close(
        interval: OpenCrossLineageLedgerInterval,
        *,
        expected_request_ids: Iterable[str],
    ) -> ClosedCrossLineageLedgerInterval:
        require_pristine()
        if type(interval) is not OpenCrossLineageLedgerInterval:
            raise AuthenticatedCrossLineageRunnerError(
                "open cross-lineage ledger interval authority is absent"
            )
        bounded = tuple(islice(iter(expected_request_ids), _MAX_INTERVAL_REQUEST_IDS + 1))
        require_pristine()
        if not bounded or len(bounded) > _MAX_INTERVAL_REQUEST_IDS:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger expected request set is empty or exceeds its bound"
            )
        if any(
            type(item) is not str or _REQUEST_ID_PATTERN.fullmatch(item) is None for item in bounded
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger expected request ID is invalid"
            )
        expected = tuple(sorted(bounded))
        if len(expected) != len(set(expected)):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger expected request IDs are not unique"
            )
        with lock:
            state = open_registry.get(interval)
        if state is None or state.process_id != trusted_getpid():
            raise AuthenticatedCrossLineageRunnerError(
                "open cross-lineage ledger interval authority is absent"
            )
        ledger = state.ledger
        if trusted_identity_getter(ledger) != state.ledger_identity_sha256:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger identity changed during the interval"
            )
        final = trusted_snapshot(ledger)
        require_clean_snapshot(final, final=True)
        initial_by_id = {item.request_id: item for item in state.initial_snapshot.entries}
        final_by_id = {item.request_id: item for item in final.entries}
        if any(final_by_id.get(request_id) != entry for request_id, entry in initial_by_id.items()):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger changed an entry that preceded the interval"
            )
        new_request_ids = tuple(sorted(set(final_by_id) - set(initial_by_id)))
        if new_request_ids != expected:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval differs from the exact expected request set"
            )
        new_entries = tuple(final_by_id[item] for item in new_request_ids)
        if any(
            item.status is not CostEntryStatus.RECONCILED
            or item.actual_cost_usd is None
            or item.accounted_cost_usd != item.actual_cost_usd
            or item.actual_cost_usd > item.reserved_usd
            for item in new_entries
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval contains non-reconciled or unknown cost"
            )
        with localcontext() as context:
            context.prec = 64
            interval_spent = final.spent_usd - state.initial_snapshot.spent_usd
            entry_spent = sum(
                (cast(Decimal, item.actual_cost_usd) for item in new_entries),
                start=Decimal(0),
            )
        if interval_spent < 0 or interval_spent != entry_spent:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval spend is inconsistent"
            )
        entry_evidence = tuple(
            AuthenticatedCrossLineageLedgerEntryEvidence(
                request_id=item.request_id,
                entry_sha256=_entry_sha256(item),
                reserved_usd=_decimal_text(item.reserved_usd),
                actual_cost_usd=_decimal_text(cast(Decimal, item.actual_cost_usd)),
            )
            for item in new_entries
        )
        evidence = AuthenticatedCrossLineageLedgerIntervalEvidence(
            ledger_identity_sha256=state.ledger_identity_sha256,
            initial_snapshot_sha256=_snapshot_sha256(state.initial_snapshot),
            final_snapshot_sha256=_snapshot_sha256(final),
            cap_usd="250",
            initial_spent_usd=_decimal_text(state.initial_snapshot.spent_usd),
            interval_spent_usd=_decimal_text(interval_spent),
            final_spent_usd=_decimal_text(final.spent_usd),
            entries=entry_evidence,
        )
        capability = object.__new__(ClosedCrossLineageLedgerInterval)
        view = _ClosedLedgerIntervalView(
            capability=capability,
            ledger=ledger,
            ledger_identity_sha256=state.ledger_identity_sha256,
            initial_snapshot=state.initial_snapshot,
            final_snapshot=final,
            new_entries=new_entries,
            evidence=evidence,
        )
        with lock:
            current = open_registry.get(interval)
            if current is not state:
                raise AuthenticatedCrossLineageRunnerError(
                    "open cross-lineage ledger interval changed during closure"
                )
            del open_registry[interval]
            closed_registry[capability] = ClosedState(
                process_id=trusted_getpid(),
                view=view,
            )
        require_pristine()
        return capability

    def require_closed(
        capability: ClosedCrossLineageLedgerInterval,
    ) -> _ClosedLedgerIntervalView:
        require_pristine()
        if type(capability) is not ClosedCrossLineageLedgerInterval:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval authority is absent"
            )
        with lock:
            state = closed_registry.get(capability)
        if state is None:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval authority is absent"
            )
        result = current_view(state)
        require_pristine()
        return result

    def claim_closed(
        capability: ClosedCrossLineageLedgerInterval,
    ) -> _ClosedLedgerIntervalView:
        require_pristine()
        if type(capability) is not ClosedCrossLineageLedgerInterval:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval authority is absent"
            )
        with lock:
            state = closed_registry.get(capability)
            if state is None:
                raise AuthenticatedCrossLineageRunnerError(
                    "closed cross-lineage ledger interval authority is absent"
                )
            if state.claimed:
                raise AuthenticatedCrossLineageRunnerError(
                    "closed cross-lineage ledger interval was already claimed"
                )
            result = current_view(state)
            state.claimed = True
        require_pristine()
        return result

    public_bindings.update(
        {
            "begin_cross_lineage_ledger_interval": begin,
            "close_cross_lineage_ledger_interval": close,
        }
    )
    return begin, close, require_closed, claim_closed, require_pristine


(
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
    _require_closed_cross_lineage_ledger_interval,
    _claim_closed_cross_lineage_ledger_interval,
    _require_pristine_cross_lineage_ledger_runtime,
) = _build_cross_lineage_ledger_interval_authority()


del _build_cross_lineage_ledger_interval_authority
