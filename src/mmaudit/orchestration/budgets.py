"""Hard model-call budget accounting."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import threading
import weakref
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from decimal import ROUND_CEILING, Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Any, Final, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostReservation,
    CostReservationOverrunError,
    ReleaseReason,
    cost_entry_sha256,
)


class BudgetExhaustedError(RuntimeError):
    """Raised before a request that could exceed the hard run budget."""


class BudgetReservationStateError(RuntimeError):
    """Raised when a request reservation is finalized inconsistently."""


class UnprovenCostBoundError(BudgetExhaustedError):
    """Raised before a certification request whose maximum cost is not proven."""


class TokenReservationOverrunError(BudgetReservationStateError):
    """Raised after provider token usage exceeds its reserved request ceiling."""


_MODEL_ID_PATTERN: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z"
)
_ROLE_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REQUEST_LIMIT_SCOPE_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ENDPOINT_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,255}\Z")
_PRICING_FIELD_PATTERN: Final = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
_USD_QUANTUM: Final = Decimal("1e-18")
_MAX_PRICE_DECIMAL_PLACES: Final = 36
_MAX_PRICE_INTEGER_DIGITS: Final = 12
_MAX_METERED_UNITS: Final = 2**63 - 1
_REQUEST_LIMIT_SCOPE_AUTHORITY: Final = object()
_ACTIVE_REQUEST_COST_CEILING_AUTHORITY: Final = object()
_EXACT_MONEY_PRECISION: Final = 160
_MAX_SHARED_RECOVERY_ROOTS: Final = 16
_MAX_SHARED_RECOVERY_RECORDS: Final = 48
_MAX_SHARED_RECOVERY_REQUESTS_PER_ROOT: Final = 33
_TRUSTED_PATH_TYPE: Final = type(Path("/"))
_TRUSTED_ATOMIC_COST_LEDGER_TYPE: Final = AtomicCostLedger
_TRUSTED_ATOMIC_LEDGER_SNAPSHOT: Final = AtomicCostLedger.snapshot
_TRUSTED_ATOMIC_LEDGER_RESERVE: Final = AtomicCostLedger.reserve
_TRUSTED_ATOMIC_LEDGER_RECONCILE: Final = AtomicCostLedger.reconcile
_TRUSTED_ATOMIC_LEDGER_RELEASE: Final = AtomicCostLedger.release
_TRUSTED_ATOMIC_LEDGER_ACTIVE_RESERVATION: Final = AtomicCostLedger.active_reservation
_TRUSTED_ATOMIC_LEDGER_LOCKED: Final = AtomicCostLedger._locked
_TRUSTED_ATOMIC_LEDGER_REQUIRED_STATE: Final = AtomicCostLedger._required_state
_TRUSTED_ATOMIC_LEDGER_READ_STATE: Final = AtomicCostLedger._read_state
_TRUSTED_ATOMIC_LEDGER_WRITE_STATE: Final = AtomicCostLedger._write_state


def _callable_descriptor_surface(subject_type: type[object]) -> tuple[tuple[str, object], ...]:
    return tuple(
        sorted(
            (
                (name, descriptor)
                for name, descriptor in vars(subject_type).items()
                if callable(descriptor)
                or isinstance(descriptor, (classmethod, staticmethod, property))
            ),
            key=lambda item: item[0],
        )
    )


_TRUSTED_ATOMIC_LEDGER_DESCRIPTOR_SURFACE: Final = _callable_descriptor_surface(AtomicCostLedger)


def _exact_decimal_add(left: Decimal, right: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = _EXACT_MONEY_PRECISION
        return left + right


def _exact_decimal_subtract(minuend: Decimal, *subtrahends: Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = _EXACT_MONEY_PRECISION
        result = minuend
        for subtrahend in subtrahends:
            result -= subtrahend
        return result


def _exact_decimal_sum(values: Iterable[Decimal]) -> Decimal:
    with localcontext() as context:
        context.prec = _EXACT_MONEY_PRECISION
        return sum(values, start=Decimal(0))


def _require_pristine_atomic_cost_ledger(ledger: AtomicCostLedger) -> None:
    if (
        type(ledger) is not _TRUSTED_ATOMIC_COST_LEDGER_TYPE
        or type(ledger.path) is not _TRUSTED_PATH_TYPE
        or type(ledger.lock_path) is not _TRUSTED_PATH_TYPE
        or type(ledger.cap_usd) is not Decimal
        or _callable_descriptor_surface(AtomicCostLedger)
        != _TRUSTED_ATOMIC_LEDGER_DESCRIPTOR_SURFACE
        or any(
            name in vars(ledger) for name, _descriptor in _TRUSTED_ATOMIC_LEDGER_DESCRIPTOR_SURFACE
        )
        or any(
            name in vars(ledger)
            for name in (
                "snapshot",
                "reserve",
                "reconcile",
                "release",
                "active_reservation",
                "_locked",
                "_required_state",
                "_read_state",
                "_write_state",
            )
        )
        or AtomicCostLedger.snapshot is not _TRUSTED_ATOMIC_LEDGER_SNAPSHOT
        or AtomicCostLedger.reserve is not _TRUSTED_ATOMIC_LEDGER_RESERVE
        or AtomicCostLedger.reconcile is not _TRUSTED_ATOMIC_LEDGER_RECONCILE
        or AtomicCostLedger.release is not _TRUSTED_ATOMIC_LEDGER_RELEASE
        or (AtomicCostLedger.active_reservation is not _TRUSTED_ATOMIC_LEDGER_ACTIVE_RESERVATION)
        or AtomicCostLedger._locked is not _TRUSTED_ATOMIC_LEDGER_LOCKED
        or AtomicCostLedger._required_state is not _TRUSTED_ATOMIC_LEDGER_REQUIRED_STATE
        or AtomicCostLedger._read_state is not _TRUSTED_ATOMIC_LEDGER_READ_STATE
        or AtomicCostLedger._write_state is not _TRUSTED_ATOMIC_LEDGER_WRITE_STATE
    ):
        raise BudgetReservationStateError("atomic cost-ledger callable provenance is invalid")


@dataclass(frozen=True, slots=True)
class _TrustedRequestLimitScope:
    """Capability proving a scheduler-bound request-count scope was issued locally."""

    identifier: str
    _authority: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _REQUEST_LIMIT_SCOPE_AUTHORITY:
            raise BudgetReservationStateError("request-limit scope authority is invalid")
        if (
            not isinstance(self.identifier, str)
            or _REQUEST_LIMIT_SCOPE_PATTERN.fullmatch(self.identifier) is None
        ):
            raise BudgetReservationStateError(
                "request-limit scope must use restricted non-secret identifier characters"
            )


def _issue_trusted_request_limit_scope(identifier: str) -> _TrustedRequestLimitScope:
    """Issue a count-scope capability for the trusted provider scheduler boundary."""

    return _TrustedRequestLimitScope(
        identifier=identifier,
        _authority=_REQUEST_LIMIT_SCOPE_AUTHORITY,
    )


@dataclass(frozen=True, slots=True)
class _ActiveRequestCostCeilingScope:
    """Inherited task scope for one manager's active callback ceiling."""

    manager: BudgetManager = field(repr=False, compare=False)
    event_loop: asyncio.AbstractEventLoop = field(repr=False, compare=False)
    maximum_cost_usd: Decimal
    _authority: object = field(repr=False, compare=False)


_ACTIVE_REQUEST_COST_CEILING_SCOPE: Final[ContextVar[_ActiveRequestCostCeilingScope | None]] = (
    ContextVar("mmaudit_active_request_cost_ceiling_scope", default=None)
)


class _TrustedBudgetRecoveryScope:
    """Opaque one-shot authority for exact journal-recovered usage."""

    __slots__ = ("__weakref__",)


@dataclass(frozen=True, slots=True)
class RecoveredSchedulerCostAttempt:
    """Exact non-output provider attempt authorized by scheduler journal ordering."""

    request_id: str
    logical_request_id: str
    task_id: str
    requested_model: str
    role: str
    status: Literal[
        "adopted_proven_pre_send",
        "uncertain_accounted_after_dispatch",
    ]
    reserved_cost_usd_exact: Decimal
    accounted_cost_usd_exact: Decimal
    request_limit_scope: str | None
    request_limit_count_before: int | None
    request_limit_count_after: int | None
    request_limit_maximum: int | None


@dataclass(frozen=True, slots=True)
class RecoveredCostLedgerBaseline:
    """Exact pre-campaign ledger head authorized by an immutable scheduler manifest."""

    cap_usd_exact: Decimal
    spent_usd_exact: Decimal
    ledger_snapshot_sha256: str
    baseline_sha256: str
    entry_sha256s: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class _BudgetRecoveryClaims:
    attempts: tuple[RecoveredSchedulerCostAttempt, ...]
    baseline: RecoveredCostLedgerBaseline | None
    shared_request_limit_roots: tuple[tuple[str, int], ...]


def _normalize_recovered_cost_baseline(value: Any | None) -> RecoveredCostLedgerBaseline | None:
    if value is None:
        return None
    try:
        baseline = RecoveredCostLedgerBaseline(
            cap_usd_exact=Decimal(value.cap_usd_exact),
            spent_usd_exact=Decimal(value.spent_usd_exact),
            ledger_snapshot_sha256=value.ledger_snapshot_sha256,
            baseline_sha256=value.baseline_sha256,
            entry_sha256s=tuple(
                (entry.request_id, entry.ledger_entry_sha256) for entry in value.entries
            ),
        )
    except (AttributeError, InvalidOperation, TypeError, ValueError):
        raise BudgetReservationStateError("cost-ledger recovery baseline is invalid") from None
    if (
        baseline.cap_usd_exact <= 0
        or baseline.spent_usd_exact < 0
        or baseline.spent_usd_exact > baseline.cap_usd_exact
        or _SHA256_PATTERN.fullmatch(baseline.ledger_snapshot_sha256) is None
        or _SHA256_PATTERN.fullmatch(baseline.baseline_sha256) is None
        or baseline.entry_sha256s
        != tuple(sorted(set(baseline.entry_sha256s), key=lambda item: item[0]))
        or len({request_id for request_id, _entry_sha256 in baseline.entry_sha256s})
        != len(baseline.entry_sha256s)
        or any(
            _REQUEST_LIMIT_SCOPE_PATTERN.fullmatch(request_id) is None
            or _SHA256_PATTERN.fullmatch(entry_sha256) is None
            for request_id, entry_sha256 in baseline.entry_sha256s
        )
    ):
        raise BudgetReservationStateError("cost-ledger recovery baseline is invalid")
    return baseline


def _normalize_recovered_scheduler_attempt(value: Any) -> RecoveredSchedulerCostAttempt:
    try:
        attempt = RecoveredSchedulerCostAttempt(
            request_id=value.request_id,
            logical_request_id=value.logical_request_id,
            task_id=value.task_id,
            requested_model=value.requested_model,
            role=value.role,
            status=value.status.value,
            reserved_cost_usd_exact=Decimal(value.reserved_cost_usd_exact),
            accounted_cost_usd_exact=Decimal(value.accounted_cost_usd_exact),
            request_limit_scope=value.request_limit_scope,
            request_limit_count_before=value.request_limit_count_before,
            request_limit_count_after=value.request_limit_count_after,
            request_limit_maximum=value.request_limit_maximum,
        )
    except (AttributeError, InvalidOperation, TypeError, ValueError):
        raise BudgetReservationStateError("scheduler cost-recovery attempt is invalid") from None
    if (
        _REQUEST_LIMIT_SCOPE_PATTERN.fullmatch(attempt.request_id) is None
        or _REQUEST_LIMIT_SCOPE_PATTERN.fullmatch(attempt.logical_request_id) is None
        or _REQUEST_LIMIT_SCOPE_PATTERN.fullmatch(attempt.task_id) is None
        or _MODEL_ID_PATTERN.fullmatch(attempt.requested_model) is None
        or _ROLE_ID_PATTERN.fullmatch(attempt.role) is None
        or attempt.reserved_cost_usd_exact <= 0
        or attempt.accounted_cost_usd_exact < 0
    ):
        raise BudgetReservationStateError("scheduler cost-recovery attempt is invalid")
    request_limit_coordinates = (
        attempt.request_limit_scope,
        attempt.request_limit_count_before,
        attempt.request_limit_count_after,
        attempt.request_limit_maximum,
    )
    if any(item is not None for item in request_limit_coordinates) and (
        attempt.request_limit_scope is None
        or _REQUEST_LIMIT_SCOPE_PATTERN.fullmatch(attempt.request_limit_scope) is None
        or type(attempt.request_limit_count_before) is not int
        or type(attempt.request_limit_count_after) is not int
        or type(attempt.request_limit_maximum) is not int
        or not 0 <= attempt.request_limit_count_before < attempt.request_limit_count_after
        or attempt.request_limit_count_after != attempt.request_limit_count_before + 1
        or attempt.request_limit_count_after > attempt.request_limit_maximum
        or attempt.request_limit_maximum > _MAX_METERED_UNITS
    ):
        raise BudgetReservationStateError(
            "scheduler cost-recovery request-limit coordinates are invalid"
        )
    return attempt


def _recovered_attempt_hash(attempt: RecoveredSchedulerCostAttempt) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "request_id": attempt.request_id,
                "logical_request_id": attempt.logical_request_id,
                "task_id": attempt.task_id,
                "requested_model": attempt.requested_model,
                "role": attempt.role,
                "status": attempt.status,
                "reserved_cost_usd_exact": format(
                    attempt.reserved_cost_usd_exact,
                    "f",
                ),
                "accounted_cost_usd_exact": format(
                    attempt.accounted_cost_usd_exact,
                    "f",
                ),
                "request_limit_scope": attempt.request_limit_scope,
                "request_limit_count_before": attempt.request_limit_count_before,
                "request_limit_count_after": attempt.request_limit_count_after,
                "request_limit_maximum": attempt.request_limit_maximum,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _usage_recovery_hash(record: Any) -> str:
    try:
        payload = record.model_dump(mode="json")
    except AttributeError:
        raise BudgetReservationStateError("budget recovery usage is invalid") from None
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _build_budget_recovery_authority() -> tuple[
    Callable[..., _TrustedBudgetRecoveryScope],
    Callable[
        [tuple[Any, ...], _TrustedBudgetRecoveryScope],
        _BudgetRecoveryClaims,
    ],
    Callable[
        [tuple[Any, ...], _TrustedBudgetRecoveryScope],
        _BudgetRecoveryClaims,
    ],
]:
    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[_TrustedBudgetRecoveryScope],
            tuple[str, ...],
            tuple[str, ...],
            tuple[RecoveredSchedulerCostAttempt, ...],
            RecoveredCostLedgerBaseline | None,
            tuple[tuple[str, int], ...],
        ],
    ] = {}
    lock = threading.RLock()

    def issue(
        records: tuple[Any, ...],
        *,
        non_usage_attempts: tuple[Any, ...] = (),
        cost_ledger_baseline: Any | None = None,
        shared_request_limit_roots: tuple[tuple[str, int], ...] = (),
        shared_request_limit_scope: str | None = None,
        shared_request_limit_count_before: int | None = None,
    ) -> _TrustedBudgetRecoveryScope:
        if (shared_request_limit_scope is None) != (shared_request_limit_count_before is None):
            raise BudgetReservationStateError(
                "shared recovery request-limit scope and starting count must be supplied together"
            )
        if shared_request_limit_roots and shared_request_limit_scope is not None:
            raise BudgetReservationStateError(
                "shared recovery request-limit roots cannot mix legacy and grouped coordinates"
            )
        if type(shared_request_limit_roots) is not tuple:
            raise BudgetReservationStateError(
                "shared recovery request-limit roots must be one bounded tuple"
            )
        canonical_roots: tuple[tuple[str, int], ...] = (
            ((shared_request_limit_scope, cast(int, shared_request_limit_count_before)),)
            if shared_request_limit_scope is not None
            else shared_request_limit_roots
        )
        if (
            len(canonical_roots) > _MAX_SHARED_RECOVERY_ROOTS
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or _REQUEST_LIMIT_SCOPE_PATTERN.fullmatch(item[0]) is None
                or type(item[1]) is not int
                or not 0 <= item[1] <= _MAX_METERED_UNITS
                for item in canonical_roots
            )
            or canonical_roots != tuple(sorted(set(canonical_roots)))
        ):
            raise BudgetReservationStateError(
                "shared recovery request-limit root coordinates are invalid or exceed bounds"
            )
        hashes = tuple(_usage_recovery_hash(record) for record in records)
        raw_request_ids = tuple(getattr(record, "request_id", None) for record in records)
        if any(not isinstance(request_id, str) or not request_id for request_id in raw_request_ids):
            raise BudgetReservationStateError(
                "budget recovery usage identities must be unique and sorted"
            )
        request_ids = cast(tuple[str, ...], raw_request_ids)
        if request_ids != tuple(sorted(set(request_ids))):
            raise BudgetReservationStateError(
                "budget recovery usage identities must be unique and sorted"
            )
        recovered_attempts = tuple(
            sorted(
                (_normalize_recovered_scheduler_attempt(item) for item in non_usage_attempts),
                key=lambda item: item.request_id,
            )
        )
        recovered_ids = tuple(item.request_id for item in recovered_attempts)
        if recovered_ids != tuple(sorted(set(recovered_ids))) or set(recovered_ids).intersection(
            request_ids
        ):
            raise BudgetReservationStateError("budget recovery provider-attempt identities repeat")
        recovered_hashes = tuple(_recovered_attempt_hash(item) for item in recovered_attempts)
        recovered_baseline = _normalize_recovered_cost_baseline(cost_ledger_baseline)
        scope = object.__new__(_TrustedBudgetRecoveryScope)
        key = id(scope)

        def discard(reference: weakref.ReferenceType[_TrustedBudgetRecoveryScope]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(scope, discard)
        with lock:
            registry[key] = (
                reference,
                hashes,
                recovered_hashes,
                recovered_attempts,
                recovered_baseline,
                canonical_roots,
            )
        return scope

    def preview(
        records: tuple[Any, ...],
        scope: _TrustedBudgetRecoveryScope,
    ) -> _BudgetRecoveryClaims:
        hashes = tuple(_usage_recovery_hash(record) for record in records)
        with lock:
            registered = registry.get(id(scope))
        if (
            type(scope) is not _TrustedBudgetRecoveryScope
            or registered is None
            or registered[0]() is not scope
            or registered[1] != hashes
        ):
            raise BudgetReservationStateError(
                "budget recovery capability is invalid, mismatched, or consumed"
            )
        return _BudgetRecoveryClaims(
            attempts=registered[3],
            baseline=registered[4],
            shared_request_limit_roots=registered[5],
        )

    def consume(
        records: tuple[Any, ...],
        scope: _TrustedBudgetRecoveryScope,
    ) -> _BudgetRecoveryClaims:
        claims = preview(records, scope)
        with lock:
            registry.pop(id(scope), None)
        return claims

    return issue, preview, consume


(
    _issue_trusted_budget_recovery_scope,
    _preview_trusted_budget_recovery_scope,
    _consume_trusted_budget_recovery_scope,
) = _build_budget_recovery_authority()


class _FrozenBudgetEvidence(BaseModel):
    """Strict immutable base for serialized budget evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class TokenBudgetStateEvidence(_FrozenBudgetEvidence):
    """One atomic snapshot of process-local global token accounting."""

    spent_input_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    reserved_input_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    remaining_input_tokens: int | None = Field(default=None, ge=0, le=_MAX_METERED_UNITS)
    spent_output_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    reserved_output_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    remaining_output_tokens: int | None = Field(default=None, ge=0, le=_MAX_METERED_UNITS)


class AtomicTokenReservationEvidence(_FrozenBudgetEvidence):
    """Self-hashed before/after proof for one lock-protected token reservation."""

    schema_version: Literal["2.0"] = "2.0"
    request_id: str
    exact_model_id: str
    role: str
    request_token_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    planned_prompt_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    planned_visible_output_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    planned_reasoning_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    planned_completion_tokens: int = Field(ge=0, le=_MAX_METERED_UNITS)
    global_input_token_limit: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_METERED_UNITS,
    )
    global_output_token_limit: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_METERED_UNITS,
    )
    before: TokenBudgetStateEvidence
    after: TokenBudgetStateEvidence
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        exact_model_id: str,
        role: str,
        request_token_plan_sha256: str,
        planned_prompt_tokens: int,
        planned_visible_output_tokens: int,
        planned_reasoning_tokens: int,
        planned_completion_tokens: int,
        global_input_token_limit: int | None,
        global_output_token_limit: int | None,
        spent_input_tokens_before: int,
        reserved_input_tokens_before: int,
        spent_output_tokens_before: int,
        reserved_output_tokens_before: int,
    ) -> Self:
        """Build evidence from a state observed while the manager lock is held."""

        before = _token_budget_state(
            global_input_token_limit=global_input_token_limit,
            global_output_token_limit=global_output_token_limit,
            spent_input_tokens=spent_input_tokens_before,
            reserved_input_tokens=reserved_input_tokens_before,
            spent_output_tokens=spent_output_tokens_before,
            reserved_output_tokens=reserved_output_tokens_before,
        )
        after = _token_budget_state(
            global_input_token_limit=global_input_token_limit,
            global_output_token_limit=global_output_token_limit,
            spent_input_tokens=spent_input_tokens_before,
            reserved_input_tokens=reserved_input_tokens_before + planned_prompt_tokens,
            spent_output_tokens=spent_output_tokens_before,
            reserved_output_tokens=reserved_output_tokens_before + planned_completion_tokens,
        )
        payload: dict[str, Any] = {
            "schema_version": "2.0",
            "request_id": request_id,
            "exact_model_id": exact_model_id,
            "role": role,
            "request_token_plan_sha256": request_token_plan_sha256,
            "planned_prompt_tokens": planned_prompt_tokens,
            "planned_visible_output_tokens": planned_visible_output_tokens,
            "planned_reasoning_tokens": planned_reasoning_tokens,
            "planned_completion_tokens": planned_completion_tokens,
            "global_input_token_limit": global_input_token_limit,
            "global_output_token_limit": global_output_token_limit,
            "before": before,
            "after": after,
        }
        return cls(
            **payload,
            evidence_sha256=_canonical_evidence_sha256(payload),
        )

    @model_validator(mode="after")
    def reservation_is_bound_conservative_and_self_hashed(
        self,
    ) -> AtomicTokenReservationEvidence:
        if not isinstance(self.request_id, str) or not self.request_id:
            raise ValueError("token reservation request ID is empty")
        if len(self.request_id) > 256 or any(
            character.isspace() or ord(character) < 32 for character in self.request_id
        ):
            raise ValueError("token reservation request ID is invalid")
        if _MODEL_ID_PATTERN.fullmatch(self.exact_model_id) is None:
            raise ValueError("token reservation requires an exact author/model ID")
        if _ROLE_ID_PATTERN.fullmatch(self.role) is None:
            raise ValueError("token reservation role is invalid")
        _validate_token_state(
            self.before,
            global_input_token_limit=self.global_input_token_limit,
            global_output_token_limit=self.global_output_token_limit,
        )
        _validate_token_state(
            self.after,
            global_input_token_limit=self.global_input_token_limit,
            global_output_token_limit=self.global_output_token_limit,
        )
        if (
            self.before.spent_input_tokens != self.after.spent_input_tokens
            or self.before.spent_output_tokens != self.after.spent_output_tokens
        ):
            raise ValueError("token reservation may not change spent token counters")
        if (
            self.planned_visible_output_tokens + self.planned_reasoning_tokens
            != self.planned_completion_tokens
        ):
            raise ValueError(
                "visible-output and reasoning reservations do not conserve completion tokens"
            )
        if (
            self.before.reserved_input_tokens + self.planned_prompt_tokens
            != self.after.reserved_input_tokens
        ):
            raise ValueError("input token reservation does not conserve tokens")
        if (
            self.before.reserved_output_tokens + self.planned_completion_tokens
            != self.after.reserved_output_tokens
        ):
            raise ValueError("output token reservation does not conserve tokens")
        expected_hash = _canonical_evidence_sha256(
            self.model_dump(mode="json", exclude={"evidence_sha256"})
        )
        if self.evidence_sha256 != expected_hash:
            raise ValueError("token reservation evidence self-hash does not match")
        return self


class AtomicRequestLimitReservationEvidence(_FrozenBudgetEvidence):
    """Self-hashed request-count reservation for one stable scheduled task."""

    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    exact_model_id: str
    role: str
    request_token_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_limit_scope: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    request_limit_count_before: int = Field(ge=0, le=_MAX_METERED_UNITS)
    request_limit_count_after: int = Field(ge=1, le=_MAX_METERED_UNITS)
    request_limit_maximum: int = Field(ge=1, le=_MAX_METERED_UNITS)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        exact_model_id: str,
        role: str,
        request_token_plan_sha256: str,
        request_limit_scope: str,
        request_limit_count_before: int,
        request_limit_maximum: int,
    ) -> Self:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "request_id": request_id,
            "exact_model_id": exact_model_id,
            "role": role,
            "request_token_plan_sha256": request_token_plan_sha256,
            "request_limit_scope": request_limit_scope,
            "request_limit_count_before": request_limit_count_before,
            "request_limit_count_after": request_limit_count_before + 1,
            "request_limit_maximum": request_limit_maximum,
        }
        return cls(
            **payload,
            evidence_sha256=_canonical_evidence_sha256(payload),
        )

    @model_validator(mode="after")
    def count_is_bound_consecutive_and_self_hashed(
        self,
    ) -> AtomicRequestLimitReservationEvidence:
        if _MODEL_ID_PATTERN.fullmatch(self.exact_model_id) is None:
            raise ValueError("request-limit reservation requires an exact author/model ID")
        if _ROLE_ID_PATTERN.fullmatch(self.role) is None:
            raise ValueError("request-limit reservation role is invalid")
        if self.request_limit_count_after != self.request_limit_count_before + 1:
            raise ValueError("request-limit reservation count is not consecutive")
        if self.request_limit_count_after > self.request_limit_maximum:
            raise ValueError("request-limit reservation exceeds its configured maximum")
        expected_hash = _canonical_evidence_sha256(
            self.model_dump(mode="json", exclude={"evidence_sha256"})
        )
        if self.evidence_sha256 != expected_hash:
            raise ValueError("request-limit reservation evidence self-hash does not match")
        return self


@dataclass(frozen=True)
class EndpointPriceComponent:
    """One complete endpoint pricing field and its request-specific unit ceiling."""

    pricing_field: str
    unit_price_usd: Decimal
    maximum_units: int

    def __post_init__(self) -> None:
        if not _PRICING_FIELD_PATTERN.fullmatch(self.pricing_field):
            raise ValueError("endpoint pricing field is invalid")
        object.__setattr__(self, "unit_price_usd", _validate_price(self.unit_price_usd))
        if (
            isinstance(self.maximum_units, bool)
            or not isinstance(self.maximum_units, int)
            or not 0 <= self.maximum_units <= _MAX_METERED_UNITS
        ):
            raise ValueError("endpoint pricing maximum units are invalid")

    @property
    def maximum_cost_usd(self) -> Decimal:
        """Return this component's exact unrounded upper cost."""

        return _trusted_endpoint_component_maximum_cost_usd(self)


def _trusted_endpoint_component_maximum_cost_usd(
    component: EndpointPriceComponent,
) -> Decimal:
    """Recompute a component maximum without dispatching through mutable properties."""

    if type(component) is not EndpointPriceComponent:
        raise BudgetReservationStateError("endpoint price component type is invalid")
    unit_price = _validate_price(component.unit_price_usd)
    if (
        not _PRICING_FIELD_PATTERN.fullmatch(component.pricing_field)
        or isinstance(component.maximum_units, bool)
        or not isinstance(component.maximum_units, int)
        or not 0 <= component.maximum_units <= _MAX_METERED_UNITS
    ):
        raise BudgetReservationStateError("endpoint price component state is invalid")
    with localcontext() as context:
        context.prec = _EXACT_MONEY_PRECISION
        return unit_price * component.maximum_units


@dataclass(frozen=True)
class EndpointRequestCostBound:
    """Endpoint-bound maximum cost proof for exact canonical request material.

    ``components`` must account for every field in the provider endpoint's
    advertised pricing object, including fields whose maximum units are zero for
    this request. The snapshot hash is recomputed from the exact model, endpoint,
    and components so a bound cannot be silently reused with different pricing.
    ``request_material_sha256`` binds the caller's canonical semantic JSON form;
    it is deliberately not a claim about an HTTP library's equivalent wire encoding.
    """

    exact_model_id: str
    provider_endpoint: str
    request_material_sha256: str
    pricing_snapshot_sha256: str
    components: tuple[EndpointPriceComponent, ...]

    def __post_init__(self) -> None:
        if not _MODEL_ID_PATTERN.fullmatch(self.exact_model_id):
            raise ValueError("endpoint cost bound requires an exact author/model ID")
        if not _ENDPOINT_ID_PATTERN.fullmatch(self.provider_endpoint):
            raise ValueError("endpoint cost bound provider endpoint is invalid")
        if not _SHA256_PATTERN.fullmatch(self.request_material_sha256):
            raise ValueError("endpoint cost bound request hash is invalid")
        if not self.components:
            raise ValueError("endpoint cost bound requires non-empty pricing components")
        fields = tuple(component.pricing_field for component in self.components)
        if fields != tuple(sorted(fields)) or len(fields) != len(set(fields)):
            raise ValueError("endpoint pricing components must be unique and sorted")
        if not {"prompt", "completion"}.issubset(fields):
            raise ValueError("endpoint pricing must include prompt and completion fields")
        expected_hash = _pricing_snapshot_hash(
            self.exact_model_id,
            self.provider_endpoint,
            self.components,
        )
        if self.pricing_snapshot_sha256 != expected_hash:
            raise ValueError("endpoint pricing snapshot hash does not match the bound")
        if _trusted_endpoint_request_maximum_cost_usd(self) <= 0:
            raise ValueError("endpoint request maximum cost must be positive")

    @classmethod
    def from_endpoint_pricing(
        cls,
        *,
        exact_model_id: str,
        provider_endpoint: str,
        request_material: str,
        pricing: Mapping[str, str | Decimal],
        maximum_units: Mapping[str, int],
    ) -> EndpointRequestCostBound:
        """Build a proof from a complete endpoint pricing object.

        Floating-point prices are deliberately rejected. Provider decimal strings
        must be parsed exactly, and ``maximum_units`` must cover precisely the same
        pricing fields. This makes newly introduced or unsupported price fields
        fail closed instead of disappearing from the reservation.
        """

        if not isinstance(request_material, str):
            raise ValueError("endpoint cost bound request material must be text")
        if not pricing:
            raise ValueError("endpoint pricing must be non-empty")
        if any(not isinstance(field, str) for field in pricing) or any(
            not isinstance(field, str) for field in maximum_units
        ):
            raise ValueError("endpoint pricing fields must be strings")
        if set(pricing) != set(maximum_units):
            raise ValueError("every endpoint pricing field requires a maximum-unit bound")
        components = tuple(
            EndpointPriceComponent(
                pricing_field=field,
                unit_price_usd=_parse_price(value),
                maximum_units=maximum_units[field],
            )
            for field, value in sorted(pricing.items())
        )
        request_hash = hashlib.sha256(request_material.encode("utf-8")).hexdigest()
        pricing_hash = _pricing_snapshot_hash(exact_model_id, provider_endpoint, components)
        return cls(
            exact_model_id=exact_model_id,
            provider_endpoint=provider_endpoint,
            request_material_sha256=request_hash,
            pricing_snapshot_sha256=pricing_hash,
            components=components,
        )

    @property
    def maximum_cost_usd(self) -> Decimal:
        """Return the exact component total rounded upward to ledger precision."""

        return _trusted_endpoint_request_maximum_cost_usd(self)

    def maximum_units_for(self, pricing_field: str) -> int:
        """Return a pricing field's unit ceiling, rejecting an absent field."""

        for component in self.components:
            if component.pricing_field == pricing_field:
                return component.maximum_units
        raise UnprovenCostBoundError(f"endpoint cost bound omits required {pricing_field} pricing")


def _property_getter(subject_type: type[object], name: str) -> object | None:
    descriptor = vars(subject_type).get(name)
    if not isinstance(descriptor, property) or descriptor.fget is None:
        return None
    return descriptor.fget


def _classmethod_function(subject_type: type[object], name: str) -> object | None:
    descriptor = vars(subject_type).get(name)
    if not isinstance(descriptor, classmethod):
        return None
    return descriptor.__func__


_TRUSTED_ENDPOINT_COMPONENT_MAXIMUM_COST_FGET: Final = cast(
    Callable[..., object],
    _property_getter(EndpointPriceComponent, "maximum_cost_usd"),
)
_TRUSTED_ENDPOINT_REQUEST_MAXIMUM_COST_FGET: Final = cast(
    Callable[..., object],
    _property_getter(EndpointRequestCostBound, "maximum_cost_usd"),
)
_TRUSTED_ENDPOINT_COMPONENT_POST_INIT: Final = EndpointPriceComponent.__post_init__
_TRUSTED_ENDPOINT_REQUEST_POST_INIT: Final = EndpointRequestCostBound.__post_init__
_TRUSTED_ENDPOINT_REQUEST_FROM_PRICING: Final = cast(
    Callable[..., EndpointRequestCostBound],
    _classmethod_function(EndpointRequestCostBound, "from_endpoint_pricing"),
)
_TRUSTED_ENDPOINT_REQUEST_MAXIMUM_UNITS_FOR: Final = EndpointRequestCostBound.maximum_units_for


def _require_pristine_endpoint_cost_bound_types() -> None:
    """Reject mutable class-property substitution at the reservation boundary."""

    if (
        _property_getter(EndpointPriceComponent, "maximum_cost_usd")
        is not _TRUSTED_ENDPOINT_COMPONENT_MAXIMUM_COST_FGET
        or _property_getter(EndpointRequestCostBound, "maximum_cost_usd")
        is not _TRUSTED_ENDPOINT_REQUEST_MAXIMUM_COST_FGET
        or EndpointPriceComponent.__post_init__ is not _TRUSTED_ENDPOINT_COMPONENT_POST_INIT
        or EndpointRequestCostBound.__post_init__ is not _TRUSTED_ENDPOINT_REQUEST_POST_INIT
        or _classmethod_function(EndpointRequestCostBound, "from_endpoint_pricing")
        is not _TRUSTED_ENDPOINT_REQUEST_FROM_PRICING
        or EndpointRequestCostBound.maximum_units_for
        is not _TRUSTED_ENDPOINT_REQUEST_MAXIMUM_UNITS_FOR
    ):
        raise BudgetReservationStateError("endpoint cost-bound callable provenance is invalid")


def _trusted_endpoint_request_maximum_cost_usd(
    bound: EndpointRequestCostBound,
) -> Decimal:
    """Recompute an exact bound from sealed component fields without property dispatch."""

    if type(bound) is not EndpointRequestCostBound or not bound.components:
        raise BudgetReservationStateError("endpoint request cost-bound type is invalid")
    fields = tuple(component.pricing_field for component in bound.components)
    if fields != tuple(sorted(fields)) or len(fields) != len(set(fields)):
        raise BudgetReservationStateError("endpoint request cost-bound components are invalid")
    if not {"prompt", "completion"}.issubset(fields):
        raise BudgetReservationStateError("endpoint request cost-bound pricing is incomplete")
    if bound.pricing_snapshot_sha256 != _pricing_snapshot_hash(
        bound.exact_model_id,
        bound.provider_endpoint,
        bound.components,
    ):
        raise BudgetReservationStateError("endpoint request cost-bound pricing hash changed")
    with localcontext() as context:
        context.prec = _EXACT_MONEY_PRECISION
        total = _exact_decimal_sum(
            _trusted_endpoint_component_maximum_cost_usd(component)
            for component in bound.components
        )
        return total.quantize(_USD_QUANTUM, rounding=ROUND_CEILING)


def _trusted_endpoint_request_maximum_units_for(
    bound: EndpointRequestCostBound,
    pricing_field: str,
) -> int:
    """Read a component ceiling without dispatching through a mutable method."""

    _trusted_endpoint_request_maximum_cost_usd(bound)
    for component in bound.components:
        if component.pricing_field == pricing_field:
            return component.maximum_units
    raise UnprovenCostBoundError(f"endpoint cost bound omits required {pricing_field} pricing")


def _trusted_endpoint_request_cost_bound_from_pricing(
    *,
    exact_model_id: str,
    provider_endpoint: str,
    request_material: str,
    pricing: Mapping[str, str | Decimal],
    maximum_units: Mapping[str, int],
) -> EndpointRequestCostBound:
    """Build and verify a bound without mutable classmethod or property dispatch."""

    _require_pristine_endpoint_cost_bound_types()
    bound = _TRUSTED_ENDPOINT_REQUEST_FROM_PRICING(
        EndpointRequestCostBound,
        exact_model_id=exact_model_id,
        provider_endpoint=provider_endpoint,
        request_material=request_material,
        pricing=pricing,
        maximum_units=maximum_units,
    )
    if (
        type(bound) is not EndpointRequestCostBound
        or tuple(component.pricing_field for component in bound.components)
        != tuple(sorted(pricing))
        or any(
            component.maximum_units != maximum_units[component.pricing_field]
            or component.unit_price_usd != _parse_price(pricing[component.pricing_field])
            for component in bound.components
        )
    ):
        raise BudgetReservationStateError(
            "constructed endpoint request cost bound differs from its exact inputs"
        )
    _trusted_endpoint_request_maximum_cost_usd(bound)
    return bound


@dataclass(frozen=True)
class Reservation:
    identifier: str
    estimated_cost_usd: float
    persistent: CostReservation | None = None
    endpoint_cost_bound: EndpointRequestCostBound | None = None
    exact_model_id: str | None = None
    role: str | None = None
    planned_prompt_tokens: int | None = None
    planned_visible_output_tokens: int | None = None
    planned_reasoning_tokens: int | None = None
    planned_completion_tokens: int | None = None
    request_token_plan_sha256: str | None = None
    token_reservation_evidence: AtomicTokenReservationEvidence | None = None
    request_limit_scope: str | None = None
    request_limit_reservation_evidence: AtomicRequestLimitReservationEvidence | None = None

    def __post_init__(self) -> None:
        evidence = self.token_reservation_evidence
        split = (self.planned_visible_output_tokens, self.planned_reasoning_tokens)
        if (split[0] is None) != (split[1] is None):
            raise ValueError(
                "visible-output and reasoning token reservations must be supplied together"
            )
        if split[0] is not None:
            assert split[1] is not None
            if self.planned_completion_tokens is None:
                raise ValueError(
                    "split output token reservations require a combined completion reservation"
                )
            if split[0] + split[1] != self.planned_completion_tokens:
                raise ValueError(
                    "visible-output and reasoning reservations do not conserve completion tokens"
                )
        if self.request_token_plan_sha256 is None:
            if evidence is not None:
                raise ValueError("legacy reservation cannot carry plan-bound token evidence")
            if (
                self.request_limit_scope is not None
                or self.request_limit_reservation_evidence is not None
            ):
                raise ValueError("request-limit scope requires plan-bound token evidence")
            return
        if _SHA256_PATTERN.fullmatch(self.request_token_plan_sha256) is None:
            raise ValueError("request token plan hash is invalid")
        if (
            self.exact_model_id is None
            or self.role is None
            or self.planned_prompt_tokens is None
            or self.planned_visible_output_tokens is None
            or self.planned_reasoning_tokens is None
            or self.planned_completion_tokens is None
        ):
            raise ValueError("plan-bound reservation requires complete model and token fields")
        if evidence is None:
            raise ValueError("plan-bound reservation requires atomic token evidence")
        if (
            evidence.request_id != self.identifier
            or evidence.exact_model_id != self.exact_model_id
            or evidence.role != self.role
            or evidence.request_token_plan_sha256 != self.request_token_plan_sha256
            or evidence.planned_prompt_tokens != self.planned_prompt_tokens
            or evidence.planned_visible_output_tokens != self.planned_visible_output_tokens
            or evidence.planned_reasoning_tokens != self.planned_reasoning_tokens
            or evidence.planned_completion_tokens != self.planned_completion_tokens
        ):
            raise ValueError("reservation fields differ from its atomic token evidence")
        request_limit_evidence = self.request_limit_reservation_evidence
        if self.request_limit_scope is None:
            if request_limit_evidence is not None:
                raise ValueError("unscheduled reservation cannot carry request-limit evidence")
        elif (
            request_limit_evidence is None
            or request_limit_evidence.request_id != self.identifier
            or request_limit_evidence.exact_model_id != self.exact_model_id
            or request_limit_evidence.role != self.role
            or request_limit_evidence.request_token_plan_sha256 != self.request_token_plan_sha256
            or request_limit_evidence.request_limit_scope != self.request_limit_scope
        ):
            raise ValueError("reservation request-limit scope differs from its atomic evidence")


@dataclass(frozen=True)
class _Reconciliation:
    actual_cost_usd: Decimal | None
    actual_prompt_tokens: int | None
    actual_completion_tokens: int | None
    actual_reasoning_tokens: int | None
    accounted_cost_usd: float
    accounted_cost_usd_exact: Decimal
    accounted_prompt_tokens: int | None
    accounted_completion_tokens: int | None
    accounted_reasoning_tokens: int | None
    cost_overrun: bool
    token_overrun: bool


class BudgetManager:
    """Reserve conservative request costs and reconcile actual usage."""

    def __init__(
        self,
        *,
        total_usd: float,
        max_output_tokens: int,
        conservative_usd_per_million_tokens: float,
        max_requests_per_agent: int,
        atomic_ledger: AtomicCostLedger | None = None,
        require_endpoint_cost_bound: bool = False,
        global_input_token_budget: int | None = None,
        global_output_token_budget: int | None = None,
        per_model_usd_caps: Mapping[str, str | Decimal | int] | None = None,
        per_role_usd_caps: Mapping[str, str | Decimal | int] | None = None,
    ) -> None:
        if type(require_endpoint_cost_bound) is not bool:
            raise ValueError("endpoint cost-bound requirement must be boolean")
        if require_endpoint_cost_bound and atomic_ledger is None:
            raise BudgetReservationStateError(
                "endpoint-bound certification costs require a durable atomic ledger"
            )
        self.global_input_token_budget = _validate_optional_token_budget(
            global_input_token_budget,
            field="global input token budget",
        )
        self.global_output_token_budget = _validate_optional_token_budget(
            global_output_token_budget,
            field="global output token budget",
        )
        self.per_model_usd_caps = _validate_scoped_caps(
            per_model_usd_caps,
            key_pattern=_MODEL_ID_PATTERN,
            scope="model",
        )
        self.per_role_usd_caps = _validate_scoped_caps(
            per_role_usd_caps,
            key_pattern=_ROLE_ID_PATTERN,
            scope="role",
        )
        self.total_usd = _canonical_budget_float(total_usd, field="total USD", positive=True)
        self.max_output_tokens = _validate_token_count(
            max_output_tokens,
            field="maximum output tokens",
        )
        self.conservative_rate = _canonical_budget_float(
            conservative_usd_per_million_tokens,
            field="conservative USD rate",
            positive=False,
        )
        if (
            type(max_requests_per_agent) is not int
            or not 1 <= max_requests_per_agent <= _MAX_METERED_UNITS
        ):
            raise ValueError("maximum requests per agent is invalid")
        self.max_requests_per_agent = max_requests_per_agent
        self.atomic_ledger = atomic_ledger
        self._atomic_ledger_identity = atomic_ledger
        self._atomic_ledger_configuration_identity = (
            (
                atomic_ledger.path,
                atomic_ledger.lock_path,
                atomic_ledger.cap_usd,
                atomic_ledger._thread_lock,
            )
            if atomic_ledger is not None
            else None
        )
        self.require_endpoint_cost_bound = require_endpoint_cost_bound
        if atomic_ledger is not None:
            _require_pristine_atomic_cost_ledger(atomic_ledger)
        snapshot = (
            _TRUSTED_ATOMIC_LEDGER_SNAPSHOT(atomic_ledger) if atomic_ledger is not None else None
        )
        if snapshot is not None and (
            snapshot.over_cap
            or any(
                entry.status is CostEntryStatus.RESERVATION_OVERRUN for entry in snapshot.entries
            )
        ):
            raise BudgetReservationStateError(
                "persistent model-cost ledger requires explicit recovery"
            )
        self._spent = float(snapshot.spent_usd) if snapshot is not None else 0.0
        self._spent_exact = snapshot.spent_usd if snapshot is not None else Decimal(0)
        self._reserved: dict[str, Decimal] = {}
        self._issued: dict[str, Reservation] = {}
        self._reconciled: dict[str, _Reconciliation] = {}
        self._released: set[str] = set()
        self._transport_committed: set[str] = set()
        self._pending_adoptions: dict[str, RecoveredSchedulerCostAttempt] = {}
        self._request_limit_counts: dict[tuple[str, str], int] = {}
        # Scoped counters intentionally describe this process only. The durable
        # ledger remains the aggregate USD authority across process restarts.
        self._reserved_input_tokens = 0
        self._spent_input_tokens = 0
        self._reserved_output_tokens = 0
        self._spent_output_tokens = 0
        self._reserved_model_usd: dict[str, Decimal] = {}
        self._spent_model_usd: dict[str, Decimal] = {}
        self._reserved_role_usd: dict[str, Decimal] = {}
        self._spent_role_usd: dict[str, Decimal] = {}
        self._active_request_cost_ceiling_scope: _ActiveRequestCostCeilingScope | None = None
        self._recovery_required = bool(snapshot is not None and snapshot.entries)
        self._lock = asyncio.Lock()
        _initialize_trusted_budget_accounting_state(self)

    def _current_atomic_ledger(self) -> AtomicCostLedger | None:
        ledger = self.atomic_ledger
        if ledger is not self._atomic_ledger_identity:
            raise BudgetReservationStateError("atomic cost-ledger identity changed")
        if ledger is not None:
            _require_pristine_atomic_cost_ledger(ledger)
            bound_configuration = self._atomic_ledger_configuration_identity
            if (
                bound_configuration is None
                or ledger.path is not bound_configuration[0]
                or ledger.lock_path is not bound_configuration[1]
                or ledger.cap_usd is not bound_configuration[2]
                or ledger._thread_lock is not bound_configuration[3]
            ):
                raise BudgetReservationStateError("atomic cost-ledger configuration changed")
        return ledger

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Conservative character-based estimate that never returns zero."""

        byte_count = len(text.encode("utf-8"))
        return max(1, math.ceil(byte_count / 3))

    def estimate_request_cost(self, prompt: str) -> float:
        tokens = self.estimate_tokens(prompt) + self.max_output_tokens
        return tokens * self.conservative_rate / 1_000_000

    @property
    def spent_usd(self) -> float:
        return self._spent

    @property
    def spent_usd_exact(self) -> Decimal:
        """Return the exact durable/reconciled USD total used for recovery joins."""

        return self._spent_exact

    @property
    def reserved_usd(self) -> float:
        return float(_exact_decimal_sum(self._reserved.values()))

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.total_usd - self._spent - self.reserved_usd)

    @property
    def reserved_input_tokens(self) -> int:
        return self._reserved_input_tokens

    @property
    def spent_input_tokens(self) -> int:
        return self._spent_input_tokens

    @property
    def remaining_input_tokens(self) -> int | None:
        if self.global_input_token_budget is None:
            return None
        return max(
            0,
            self.global_input_token_budget - self._spent_input_tokens - self._reserved_input_tokens,
        )

    @property
    def reserved_output_tokens(self) -> int:
        return self._reserved_output_tokens

    @property
    def spent_output_tokens(self) -> int:
        return self._spent_output_tokens

    @property
    def remaining_output_tokens(self) -> int | None:
        if self.global_output_token_budget is None:
            return None
        return max(
            0,
            self.global_output_token_budget
            - self._spent_output_tokens
            - self._reserved_output_tokens,
        )

    def reserved_model_usd(self, exact_model_id: str) -> Decimal:
        _validate_scope_key(exact_model_id, _MODEL_ID_PATTERN, scope="model")
        return self._reserved_model_usd.get(exact_model_id, Decimal(0))

    def spent_model_usd(self, exact_model_id: str) -> Decimal:
        _validate_scope_key(exact_model_id, _MODEL_ID_PATTERN, scope="model")
        return self._spent_model_usd.get(exact_model_id, Decimal(0))

    def reserved_role_usd(self, role: str) -> Decimal:
        _validate_scope_key(role, _ROLE_ID_PATTERN, scope="role")
        return self._reserved_role_usd.get(role, Decimal(0))

    def spent_role_usd(self, role: str) -> Decimal:
        _validate_scope_key(role, _ROLE_ID_PATTERN, scope="role")
        return self._spent_role_usd.get(role, Decimal(0))

    @property
    def recovery_required(self) -> bool:
        """Return whether durable spend exists without restored scoped counters."""

        return self._recovery_required

    @asynccontextmanager
    async def active_request_cost_ceiling(
        self,
        maximum_cost_usd: Decimal,
    ) -> AsyncIterator[None]:
        """Bound every request reserved during one awaited callback."""

        ceiling = _validate_active_request_cost_ceiling(maximum_cost_usd)
        scope = _ActiveRequestCostCeilingScope(
            manager=self,
            event_loop=asyncio.get_running_loop(),
            maximum_cost_usd=ceiling,
            _authority=_ACTIVE_REQUEST_COST_CEILING_AUTHORITY,
        )
        async with self._lock:
            _require_trusted_budget_accounting_state(self)
            if (
                self._active_request_cost_ceiling_scope is not None
                or _ACTIVE_REQUEST_COST_CEILING_SCOPE.get() is not None
            ):
                raise BudgetReservationStateError(
                    "an active per-request cost ceiling is already installed"
                )
            self._active_request_cost_ceiling_scope = scope
            _refresh_trusted_budget_accounting_state(self)
            context_token = _ACTIVE_REQUEST_COST_CEILING_SCOPE.set(scope)
        try:
            yield
        finally:
            try:
                async with self._lock:
                    _require_trusted_budget_accounting_state(self)
                    if (
                        self._active_request_cost_ceiling_scope is not scope
                        or _ACTIVE_REQUEST_COST_CEILING_SCOPE.get() is not scope
                    ):
                        raise BudgetReservationStateError(
                            "active per-request cost ceiling changed before cleanup"
                        )
                    self._active_request_cost_ceiling_scope = None
                    _refresh_trusted_budget_accounting_state(self)
            finally:
                _ACTIVE_REQUEST_COST_CEILING_SCOPE.reset(context_token)

    async def restore_recovered_usage(
        self,
        records: tuple[Any, ...],
        *,
        recovery_scope: _TrustedBudgetRecoveryScope,
    ) -> None:
        """Restore exact scoped counters once without changing durable USD spend."""

        from mmaudit.models.usage import (
            atomic_request_limit_reservations_from_usage,
            atomic_token_reservations_from_usage,
            is_accountable_usage_record,
            is_creditable_usage_record,
            is_recovery_accountable_usage_record,
            is_recovery_creditable_usage_record,
            recovery_atomic_request_limit_reservations_from_usage,
            recovery_request_token_plan_from_usage,
            request_token_plan_from_usage,
        )

        ledger = self._current_atomic_ledger()
        if ledger is None:
            raise BudgetReservationStateError(
                "budget recovery requires the exact persistent model-cost ledger"
            )
        normalized_records = tuple(records)
        async with self._lock:
            _require_trusted_budget_accounting_state(self)
            if not self._recovery_required:
                raise BudgetReservationStateError("budget recovery is not required or already ran")
            if (
                self._issued
                or self._reserved
                or self._reconciled
                or self._released
                or self._transport_committed
            ):
                raise BudgetReservationStateError(
                    "budget recovery requires a fresh manager before any request"
                )

            if self._current_atomic_ledger() is not ledger:
                raise BudgetReservationStateError("atomic cost-ledger identity changed")
            snapshot = _TRUSTED_ATOMIC_LEDGER_SNAPSHOT(ledger)
            entries_by_id = {entry.request_id: entry for entry in snapshot.entries}
            expected_entry_ids: set[str] = set()
            spent_input_tokens = 0
            spent_output_tokens = 0
            spent_model_usd: dict[str, Decimal] = {}
            spent_role_usd: dict[str, Decimal] = {}
            request_limit_counts: dict[tuple[str, str], int] = {}
            expected_spent_usd = Decimal(0)
            recovery_claims = _preview_trusted_budget_recovery_scope(
                normalized_records,
                recovery_scope,
            )
            recovered_attempts = recovery_claims.attempts
            uncertain_dispatched_attempt = False
            recovered_uncertain_scopes: set[tuple[str, str]] = set()
            pending_adoptions: dict[str, RecoveredSchedulerCostAttempt] = {}
            baseline = recovery_claims.baseline
            if baseline is not None:
                if snapshot.cap_usd != baseline.cap_usd_exact:
                    raise BudgetReservationStateError(
                        "persistent model-cost ledger cap differs from campaign baseline"
                    )
                for request_id, entry_sha256 in baseline.entry_sha256s:
                    entry = entries_by_id.get(request_id)
                    if entry is None or cost_entry_sha256(entry) != entry_sha256:
                        raise BudgetReservationStateError(
                            "persistent model-cost ledger differs from campaign baseline"
                        )
                    expected_entry_ids.add(request_id)
                expected_spent_usd = baseline.spent_usd_exact

            shared_roots = recovery_claims.shared_request_limit_roots
            ordinary_request_evidence_by_id: dict[
                str,
                tuple[AtomicRequestLimitReservationEvidence, ...],
            ] = {}
            recovery_only_records: dict[str, Any] = {}
            for record in normalized_records:
                try:
                    ordinary_plan = request_token_plan_from_usage(record)
                    ordinary_request_evidence = (
                        atomic_request_limit_reservations_from_usage(record, ordinary_plan)
                        if ordinary_plan is not None
                        else ()
                    )
                except (TypeError, ValueError):
                    ordinary_request_evidence = ()
                if ordinary_request_evidence:
                    ordinary_request_evidence_by_id[record.request_id] = ordinary_request_evidence
                else:
                    recovery_only_records[record.request_id] = record

            shared_positions: dict[str, tuple[str, int]] = {}
            shared_final_counts: dict[str, int] = {}
            for shared_scope, shared_count_before in shared_roots:
                ordinary_candidates = {
                    record.request_id: record
                    for record in normalized_records
                    if record.request_id in ordinary_request_evidence_by_id
                    and all(
                        item.request_limit_scope == shared_scope
                        for item in ordinary_request_evidence_by_id[record.request_id]
                    )
                }
                next_count = shared_count_before
                shared_maximum: int | None = None
                shared_attempts = 0
                matched_for_root = 0
                while True:
                    candidates = (*ordinary_candidates.values(), *recovery_only_records.values())
                    matches: list[
                        tuple[Any, tuple[AtomicRequestLimitReservationEvidence, ...]]
                    ] = []
                    for candidate in candidates:
                        try:
                            candidate_plan = recovery_request_token_plan_from_usage(
                                candidate,
                                request_limit_scope=shared_scope,
                                request_limit_count_before=next_count,
                            )
                            if candidate_plan is None:
                                continue
                            candidate_evidence = (
                                recovery_atomic_request_limit_reservations_from_usage(
                                    candidate,
                                    candidate_plan,
                                    request_limit_scope=shared_scope,
                                    request_limit_count_before=next_count,
                                )
                            )
                        except (TypeError, ValueError):
                            continue
                        matches.append((candidate, candidate_evidence))
                    if len(matches) > 1:
                        raise BudgetReservationStateError(
                            "shared recovery request-limit chain is noncontiguous or ambiguous"
                        )
                    if not matches:
                        break
                    matched_record, matched_evidence = matches[0]
                    exact_maximum = matched_evidence[0].request_limit_maximum
                    if exact_maximum != self.max_requests_per_agent or (
                        shared_maximum is not None and exact_maximum != shared_maximum
                    ):
                        raise BudgetReservationStateError(
                            "shared recovery request-limit maximum differs from the manager"
                        )
                    shared_maximum = exact_maximum
                    if matched_record.request_id in shared_positions:
                        raise BudgetReservationStateError(
                            "shared recovery request-limit groups overlap"
                        )
                    shared_positions[matched_record.request_id] = (shared_scope, next_count)
                    next_count = matched_evidence[-1].request_limit_count_after
                    shared_attempts += len(matched_evidence)
                    matched_for_root += 1
                    if (
                        shared_attempts > _MAX_SHARED_RECOVERY_REQUESTS_PER_ROOT
                        or len(shared_positions) > _MAX_SHARED_RECOVERY_RECORDS
                    ):
                        raise BudgetReservationStateError(
                            "shared recovery request-limit inventory exceeds its compiled bound"
                        )
                    ordinary_candidates.pop(matched_record.request_id, None)
                    recovery_only_records.pop(matched_record.request_id, None)
                if not matched_for_root:
                    raise BudgetReservationStateError(
                        "shared recovery request-limit scope has no bound usage"
                    )
                if ordinary_candidates:
                    raise BudgetReservationStateError(
                        "shared recovery request-limit chain is noncontiguous or ambiguous"
                    )
                shared_final_counts[shared_scope] = next_count
            if shared_roots and recovery_only_records:
                raise BudgetReservationStateError(
                    "shared recovery request-limit usage is unbound or noncontiguous"
                )

            for record in normalized_records:
                recovery_coordinate = shared_positions.get(record.request_id)
                record_recovery_scope = (
                    recovery_coordinate[0] if recovery_coordinate is not None else None
                )
                recovery_count_before = (
                    recovery_coordinate[1] if recovery_coordinate is not None else None
                )
                creditable = (
                    is_recovery_creditable_usage_record(
                        record,
                        request_limit_scope=record_recovery_scope,
                        request_limit_count_before=recovery_count_before,
                        require_real=True,
                    )
                    if record_recovery_scope is not None and recovery_count_before is not None
                    else is_creditable_usage_record(record, require_real=True)
                )
                accountable = (
                    is_recovery_accountable_usage_record(
                        record,
                        request_limit_scope=record_recovery_scope,
                        request_limit_count_before=recovery_count_before,
                        require_real=False,
                    )
                    if record_recovery_scope is not None and recovery_count_before is not None
                    else is_accountable_usage_record(record, require_real=False)
                )
                if not accountable:
                    raise BudgetReservationStateError(
                        "budget recovery requires exact runtime-accountable usage"
                    )
                plan = (
                    recovery_request_token_plan_from_usage(
                        record,
                        request_limit_scope=record_recovery_scope,
                        request_limit_count_before=recovery_count_before,
                    )
                    if record_recovery_scope is not None and recovery_count_before is not None
                    else request_token_plan_from_usage(record)
                )
                if plan is None:
                    raise BudgetReservationStateError(
                        "budget recovery usage lacks an exact request token plan"
                    )
                token_evidence = atomic_token_reservations_from_usage(record, plan)
                request_evidence = (
                    recovery_atomic_request_limit_reservations_from_usage(
                        record,
                        plan,
                        request_limit_scope=record_recovery_scope,
                        request_limit_count_before=recovery_count_before,
                    )
                    if record_recovery_scope is not None and recovery_count_before is not None
                    else atomic_request_limit_reservations_from_usage(record, plan)
                )
                if (
                    len(token_evidence) != record.attempts
                    or len(request_evidence) != record.attempts
                    or not request_evidence
                ):
                    raise BudgetReservationStateError(
                        "budget recovery usage lacks complete scheduled attempt evidence"
                    )
                attempt_ids = tuple(item.request_id for item in token_evidence)
                if attempt_ids != tuple(item.request_id for item in request_evidence):
                    raise BudgetReservationStateError(
                        "budget recovery token and request attempts differ"
                    )
                if expected_entry_ids.intersection(attempt_ids):
                    raise BudgetReservationStateError("budget recovery repeats a provider attempt")
                expected_entry_ids.update(attempt_ids)
                attempt_entries = tuple(entries_by_id.get(item) for item in attempt_ids)
                if any(entry is None for entry in attempt_entries):
                    raise BudgetReservationStateError(
                        "persistent model-cost ledger omits a recovered provider attempt"
                    )
                exact_entries = tuple(entry for entry in attempt_entries if entry is not None)
                if any(
                    entry.status
                    not in {
                        CostEntryStatus.RECONCILED,
                        CostEntryStatus.UNCERTAIN_ACCOUNTED,
                    }
                    for entry in exact_entries
                ) or (creditable and exact_entries[-1].status is not CostEntryStatus.RECONCILED):
                    raise BudgetReservationStateError(
                        "persistent model-cost ledger has an invalid attempt state"
                    )
                if record.accounted_cost_usd_exact is None or (
                    creditable and record.reported_cost_usd_exact is None
                ):
                    raise BudgetReservationStateError(
                        "budget recovery usage lacks exact decimal cost evidence"
                    )
                record_cost = Decimal(record.accounted_cost_usd_exact)
                if (
                    _exact_decimal_sum(entry.accounted_cost_usd for entry in exact_entries)
                    != record_cost
                    or (
                        record.reported_cost_usd_exact is None
                        and exact_entries[-1].actual_cost_usd is not None
                    )
                    or (
                        record.reported_cost_usd_exact is not None
                        and exact_entries[-1].actual_cost_usd
                        != Decimal(record.reported_cost_usd_exact)
                    )
                ):
                    raise BudgetReservationStateError(
                        "persistent model-cost ledger differs from recovered usage cost"
                    )
                expected_spent_usd = _exact_decimal_add(expected_spent_usd, record_cost)
                token_detail = record.token_detail_accounting_evidence
                final_accounted_prompt_tokens = (
                    token_detail.accounted_prompt_tokens
                    if token_detail is not None
                    else (
                        record.prompt_tokens
                        if creditable or record.prompt_tokens > 0
                        else token_evidence[-1].planned_prompt_tokens
                    )
                )
                final_accounted_completion_tokens = (
                    token_detail.accounted_completion_tokens
                    if token_detail is not None
                    else (
                        record.completion_tokens
                        if creditable or record.completion_tokens > 0
                        else token_evidence[-1].planned_completion_tokens
                    )
                )
                spent_input_tokens += (
                    sum(item.planned_prompt_tokens for item in token_evidence[:-1])
                    + final_accounted_prompt_tokens
                )
                spent_output_tokens += (
                    sum(item.planned_completion_tokens for item in token_evidence[:-1])
                    + final_accounted_completion_tokens
                )
                _increment_decimal(spent_model_usd, record.requested_model, record_cost)
                _increment_decimal(spent_role_usd, record.role, record_cost)
                scope_values = {item.request_limit_scope for item in request_evidence}
                if len(scope_values) != 1:
                    raise BudgetReservationStateError(
                        "budget recovery request-limit scope is ambiguous"
                    )
                request_scope = next(iter(scope_values))
                request_key = ("scheduled_task", request_scope)
                if recovery_count_before is None:
                    if request_key in request_limit_counts:
                        raise BudgetReservationStateError(
                            "budget recovery repeats a scheduled request-limit scope"
                        )
                    request_limit_counts[request_key] = request_evidence[
                        -1
                    ].request_limit_count_after

            for shared_scope, shared_final_count in shared_final_counts.items():
                shared_request_key = ("scheduled_task", shared_scope)
                if shared_request_key in request_limit_counts:
                    raise BudgetReservationStateError(
                        "budget recovery repeats a scheduled request-limit scope"
                    )
                request_limit_counts[shared_request_key] = shared_final_count

            for attempt in recovered_attempts:
                if attempt.request_id in expected_entry_ids:
                    raise BudgetReservationStateError("budget recovery repeats a provider attempt")
                entry = entries_by_id.get(attempt.request_id)
                if entry is None:
                    raise BudgetReservationStateError(
                        "persistent model-cost ledger omits a recovered provider attempt"
                    )
                expected_entry_ids.add(attempt.request_id)
                recovery_request_key = (
                    ("scheduled_task", attempt.request_limit_scope)
                    if attempt.request_limit_scope is not None
                    else ("scheduled_task", attempt.logical_request_id)
                )
                if attempt.request_limit_scope is not None and (
                    attempt.request_limit_count_before is None
                    or attempt.request_limit_count_after is None
                    or attempt.request_limit_maximum != self.max_requests_per_agent
                    or request_limit_counts.get(recovery_request_key, 0)
                    != attempt.request_limit_count_before
                ):
                    raise BudgetReservationStateError(
                        "recovered scheduler attempt differs from its shared request limit"
                    )
                if attempt.status == "adopted_proven_pre_send":
                    if (
                        entry.status is not CostEntryStatus.RESERVED
                        or entry.release_reason is not None
                        or entry.accounted_cost_usd != 0
                        or entry.reserved_usd != attempt.reserved_cost_usd_exact
                        or attempt.accounted_cost_usd_exact != 0
                    ):
                        raise BudgetReservationStateError(
                            "adopted pre-send recovery differs from the persistent ledger"
                        )
                    pending_adoptions[attempt.request_id] = attempt
                    continue
                if attempt.request_limit_scope is not None:
                    if attempt.request_limit_count_after is None:
                        raise BudgetReservationStateError(
                            "recovered scheduler attempt lacks its request-limit terminal count"
                        )
                    request_limit_counts[recovery_request_key] = attempt.request_limit_count_after
                else:
                    if (
                        recovery_request_key in request_limit_counts
                        and recovery_request_key not in recovered_uncertain_scopes
                    ):
                        raise BudgetReservationStateError(
                            "budget recovery repeats a scheduled request-limit scope"
                        )
                    if recovery_request_key not in recovered_uncertain_scopes:
                        request_limit_counts[recovery_request_key] = 1
                        recovered_uncertain_scopes.add(recovery_request_key)
                if (
                    entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
                    or entry.actual_cost_usd is not None
                    or entry.reserved_usd != attempt.reserved_cost_usd_exact
                    or entry.accounted_cost_usd != attempt.accounted_cost_usd_exact
                ):
                    raise BudgetReservationStateError(
                        "uncertain dispatched recovery differs from the persistent ledger"
                    )
                uncertain_dispatched_attempt = True
                expected_spent_usd = _exact_decimal_add(
                    expected_spent_usd,
                    attempt.accounted_cost_usd_exact,
                )
                _increment_decimal(
                    spent_model_usd,
                    attempt.requested_model,
                    attempt.accounted_cost_usd_exact,
                )
                _increment_decimal(
                    spent_role_usd,
                    attempt.role,
                    attempt.accounted_cost_usd_exact,
                )

            if uncertain_dispatched_attempt:
                if self.global_input_token_budget is not None:
                    spent_input_tokens = self.global_input_token_budget
                if self.global_output_token_budget is not None:
                    spent_output_tokens = self.global_output_token_budget

            if set(entries_by_id) != expected_entry_ids or snapshot.spent_usd != expected_spent_usd:
                raise BudgetReservationStateError(
                    "persistent model-cost ledger contains unbound recovery entries"
                )
            if (
                self.global_input_token_budget is not None
                and spent_input_tokens > self.global_input_token_budget
            ) or (
                self.global_output_token_budget is not None
                and spent_output_tokens > self.global_output_token_budget
            ):
                raise BudgetReservationStateError(
                    "recovered token usage exceeds the configured global budget"
                )

            _consume_trusted_budget_recovery_scope(normalized_records, recovery_scope)
            self._spent_input_tokens = spent_input_tokens
            self._spent_output_tokens = spent_output_tokens
            self._spent_model_usd = spent_model_usd
            self._spent_role_usd = spent_role_usd
            self._request_limit_counts = request_limit_counts
            self._pending_adoptions = pending_adoptions
            self._spent_exact = snapshot.spent_usd
            self._spent = float(snapshot.spent_usd)
            self._recovery_required = False
            _refresh_trusted_budget_accounting_state(self)

    async def reserve(
        self,
        identifier: str,
        role: str,
        prompt: str,
        *,
        endpoint_cost_bound: EndpointRequestCostBound | None = None,
        exact_model_id: str | None = None,
        planned_prompt_tokens: int | None = None,
        planned_visible_output_tokens: int | None = None,
        planned_reasoning_tokens: int | None = None,
        planned_completion_tokens: int | None = None,
        request_token_plan_sha256: str | None = None,
        request_limit_scope: _TrustedRequestLimitScope | None = None,
    ) -> Reservation:
        """Reserve before send, requiring exact endpoint pricing in certification mode."""

        if self._recovery_required:
            raise BudgetReservationStateError(
                "persistent budget counters require exact usage recovery before dispatch"
            )
        maximum_cost = self._maximum_request_cost(prompt, endpoint_cost_bound)
        estimated = float(maximum_cost)
        (
            resolved_model_id,
            resolved_prompt_tokens,
            resolved_visible_output_tokens,
            resolved_reasoning_tokens,
            resolved_completion_tokens,
            resolved_plan_sha256,
        ) = self._validate_request_scope(
            role=role,
            exact_model_id=exact_model_id,
            planned_prompt_tokens=planned_prompt_tokens,
            planned_visible_output_tokens=planned_visible_output_tokens,
            planned_reasoning_tokens=planned_reasoning_tokens,
            planned_completion_tokens=planned_completion_tokens,
            request_token_plan_sha256=request_token_plan_sha256,
            endpoint_cost_bound=endpoint_cost_bound,
        )
        if request_limit_scope is not None and not isinstance(
            request_limit_scope,
            _TrustedRequestLimitScope,
        ):
            raise BudgetReservationStateError("request-limit scope capability is invalid")
        if request_limit_scope is not None and resolved_plan_sha256 is None:
            raise BudgetReservationStateError(
                "request-limit scope requires a plan-bound reservation"
            )
        request_limit_key = (
            ("role", role)
            if request_limit_scope is None
            else ("scheduled_task", request_limit_scope.identifier)
        )
        async with self._lock:
            _require_trusted_budget_accounting_state(self)
            if self._recovery_required:
                raise BudgetReservationStateError(
                    "persistent budget counters require exact usage recovery before dispatch"
                )
            if identifier in self._issued:
                raise BudgetReservationStateError(
                    "request reservation identifier was already issued"
                )
            pending_adoption = self._pending_adoptions.get(identifier)
            if self._pending_adoptions and pending_adoption is None:
                raise BudgetReservationStateError(
                    "a proven pre-send reservation must be adopted before other dispatch"
                )
            if pending_adoption is not None and (
                pending_adoption.role != role
                or pending_adoption.requested_model != resolved_model_id
                or pending_adoption.reserved_cost_usd_exact != maximum_cost
            ):
                raise BudgetReservationStateError(
                    "resumed request differs from its durable pre-send reservation"
                )
            active_cost_scope = self._active_request_cost_ceiling_scope
            inherited_cost_scope = _ACTIVE_REQUEST_COST_CEILING_SCOPE.get()
            if active_cost_scope is None and inherited_cost_scope is not None:
                raise BudgetReservationStateError(
                    "request inherited an inactive per-request cost ceiling"
                )
            if (active_cost_scope is None) is not (inherited_cost_scope is None):
                raise BudgetReservationStateError(
                    "request is outside the active per-request cost-ceiling callback"
                )
            if active_cost_scope is not None and (
                inherited_cost_scope is not active_cost_scope
                or asyncio.get_running_loop() is not active_cost_scope.event_loop
            ):
                raise BudgetReservationStateError(
                    "request is outside the active per-request cost-ceiling callback"
                )
            if active_cost_scope is not None and maximum_cost > active_cost_scope.maximum_cost_usd:
                raise BudgetExhaustedError(
                    f"request for {role} exceeds the active per-request cost ceiling"
                )
            count = self._request_limit_counts.get(request_limit_key, 0)
            if count >= self.max_requests_per_agent:
                scope_label = (
                    f"role {role}"
                    if request_limit_scope is None
                    else f"scheduled task {request_limit_key[1]}"
                )
                raise BudgetExhaustedError(f"request limit reached for {scope_label}")
            remaining_usd = _exact_decimal_subtract(
                Decimal(str(self.total_usd)),
                self._spent_exact,
                _exact_decimal_sum(self._reserved.values()),
            )
            if maximum_cost > remaining_usd:
                raise BudgetExhaustedError(
                    f"request for {role} could cost ${estimated:.4f}, "
                    f"but only ${self.remaining_usd:.4f} remains"
                )
            self._require_scoped_capacity(
                role=role,
                exact_model_id=resolved_model_id,
                maximum_cost=maximum_cost,
                planned_prompt_tokens=resolved_prompt_tokens,
                planned_completion_tokens=resolved_completion_tokens,
            )
            token_evidence = (
                AtomicTokenReservationEvidence.build(
                    request_id=identifier,
                    exact_model_id=resolved_model_id,
                    role=role,
                    request_token_plan_sha256=resolved_plan_sha256,
                    planned_prompt_tokens=resolved_prompt_tokens,
                    planned_visible_output_tokens=resolved_visible_output_tokens,
                    planned_reasoning_tokens=resolved_reasoning_tokens,
                    planned_completion_tokens=resolved_completion_tokens,
                    global_input_token_limit=self.global_input_token_budget,
                    global_output_token_limit=self.global_output_token_budget,
                    spent_input_tokens_before=self._spent_input_tokens,
                    reserved_input_tokens_before=self._reserved_input_tokens,
                    spent_output_tokens_before=self._spent_output_tokens,
                    reserved_output_tokens_before=self._reserved_output_tokens,
                )
                if (
                    resolved_plan_sha256 is not None
                    and resolved_model_id is not None
                    and resolved_prompt_tokens is not None
                    and resolved_visible_output_tokens is not None
                    and resolved_reasoning_tokens is not None
                    and resolved_completion_tokens is not None
                )
                else None
            )
            request_limit_evidence: AtomicRequestLimitReservationEvidence | None = None
            if request_limit_scope is not None:
                assert resolved_model_id is not None
                assert resolved_plan_sha256 is not None
                request_limit_evidence = AtomicRequestLimitReservationEvidence.build(
                    request_id=identifier,
                    exact_model_id=resolved_model_id,
                    role=role,
                    request_token_plan_sha256=resolved_plan_sha256,
                    request_limit_scope=request_limit_scope.identifier,
                    request_limit_count_before=count,
                    request_limit_maximum=self.max_requests_per_agent,
                )
            reservation_without_persistence = Reservation(
                identifier=identifier,
                estimated_cost_usd=estimated,
                endpoint_cost_bound=endpoint_cost_bound,
                exact_model_id=resolved_model_id,
                role=role,
                planned_prompt_tokens=resolved_prompt_tokens,
                planned_visible_output_tokens=resolved_visible_output_tokens,
                planned_reasoning_tokens=resolved_reasoning_tokens,
                planned_completion_tokens=resolved_completion_tokens,
                request_token_plan_sha256=resolved_plan_sha256,
                token_reservation_evidence=token_evidence,
                request_limit_scope=(
                    request_limit_scope.identifier if request_limit_scope is not None else None
                ),
                request_limit_reservation_evidence=request_limit_evidence,
            )
            try:
                if pending_adoption is not None:
                    ledger = self._current_atomic_ledger()
                    if ledger is None:
                        raise BudgetReservationStateError(
                            "pre-send reservation adoption requires its persistent ledger"
                        )
                    persistent = _TRUSTED_ATOMIC_LEDGER_ACTIVE_RESERVATION(
                        ledger,
                        identifier,
                    )
                    if (
                        persistent is None
                        or persistent.reserved_usd != pending_adoption.reserved_cost_usd_exact
                    ):
                        raise BudgetReservationStateError(
                            "durable pre-send reservation is no longer active"
                        )
                else:
                    ledger = self._current_atomic_ledger()
                    persistent = (
                        _TRUSTED_ATOMIC_LEDGER_RESERVE(ledger, identifier, maximum_cost)
                        if ledger is not None
                        else None
                    )
            except CostBudgetExceededError:
                raise BudgetExhaustedError(
                    f"request for {role} exceeds the persistent model-cost budget"
                ) from None
            self._reserved[identifier] = maximum_cost
            self._request_limit_counts[request_limit_key] = count + 1
            reservation = replace(reservation_without_persistence, persistent=persistent)
            self._issued[identifier] = reservation
            self._reserve_scoped(reservation, maximum_cost)
            if pending_adoption is not None:
                self._pending_adoptions.pop(identifier)
            _refresh_trusted_budget_accounting_state(self)
            return reservation

    def _validate_request_scope(
        self,
        *,
        role: str,
        exact_model_id: str | None,
        planned_prompt_tokens: int | None,
        planned_visible_output_tokens: int | None,
        planned_reasoning_tokens: int | None,
        planned_completion_tokens: int | None,
        request_token_plan_sha256: str | None,
        endpoint_cost_bound: EndpointRequestCostBound | None,
    ) -> tuple[
        str | None,
        int | None,
        int | None,
        int | None,
        int | None,
        str | None,
    ]:
        _validate_scope_key(role, _ROLE_ID_PATTERN, scope="role")
        resolved_model_id = exact_model_id
        if resolved_model_id is not None:
            _validate_scope_key(resolved_model_id, _MODEL_ID_PATTERN, scope="model")
        if endpoint_cost_bound is not None:
            if (
                resolved_model_id is not None
                and resolved_model_id != endpoint_cost_bound.exact_model_id
            ):
                raise BudgetReservationStateError(
                    "request model differs from the endpoint cost bound"
                )
            resolved_model_id = endpoint_cost_bound.exact_model_id

        prompt_tokens = _validate_optional_token_count(
            planned_prompt_tokens,
            field="planned prompt tokens",
        )
        completion_tokens = _validate_optional_token_count(
            planned_completion_tokens,
            field="planned completion tokens",
        )
        visible_output_tokens = _validate_optional_token_count(
            planned_visible_output_tokens,
            field="planned visible-output tokens",
        )
        reasoning_tokens = _validate_optional_token_count(
            planned_reasoning_tokens,
            field="planned reasoning tokens",
        )
        if (prompt_tokens is None) != (completion_tokens is None):
            raise BudgetReservationStateError(
                "planned prompt and completion token ceilings must be supplied together"
            )
        if (visible_output_tokens is None) != (reasoning_tokens is None):
            raise BudgetReservationStateError(
                "planned visible-output and reasoning token ceilings must be supplied together"
            )
        if visible_output_tokens is not None:
            if completion_tokens is None:
                raise BudgetReservationStateError(
                    "split output token ceilings require a planned completion ceiling"
                )
            assert reasoning_tokens is not None
            if visible_output_tokens + reasoning_tokens != completion_tokens:
                raise BudgetReservationStateError(
                    "planned visible-output and reasoning tokens do not conserve completion tokens"
                )
        plan_sha256 = request_token_plan_sha256
        if plan_sha256 is not None and (
            not isinstance(plan_sha256, str) or _SHA256_PATTERN.fullmatch(plan_sha256) is None
        ):
            raise BudgetReservationStateError("request token plan hash is invalid")
        if plan_sha256 is not None and (
            resolved_model_id is None or prompt_tokens is None or completion_tokens is None
        ):
            raise BudgetReservationStateError(
                "request token plan hash requires an exact model and complete token ceilings"
            )
        if plan_sha256 is not None and (visible_output_tokens is None or reasoning_tokens is None):
            raise BudgetReservationStateError(
                "request token plan hash requires visible-output and reasoning token ceilings"
            )
        if prompt_tokens is not None and resolved_model_id is None:
            raise BudgetReservationStateError("planned token ceilings require an exact model ID")
        if self.per_model_usd_caps and resolved_model_id is None:
            raise BudgetReservationStateError("per-model USD caps require an exact model ID")
        if self.global_input_token_budget is not None and prompt_tokens is None:
            raise BudgetReservationStateError(
                "global input token budget requires a planned prompt-token ceiling"
            )
        if self.global_output_token_budget is not None and completion_tokens is None:
            raise BudgetReservationStateError(
                "global output token budget requires a planned completion-token ceiling"
            )
        if (
            endpoint_cost_bound is not None
            and prompt_tokens is not None
            and completion_tokens is not None
        ):
            if prompt_tokens > endpoint_cost_bound.maximum_units_for("prompt"):
                raise BudgetReservationStateError(
                    "planned prompt tokens exceed the endpoint cost bound"
                )
            if completion_tokens > endpoint_cost_bound.maximum_units_for("completion"):
                raise BudgetReservationStateError(
                    "planned completion tokens exceed the endpoint cost bound"
                )
        return (
            resolved_model_id,
            prompt_tokens,
            visible_output_tokens,
            reasoning_tokens,
            completion_tokens,
            plan_sha256,
        )

    def _require_scoped_capacity(
        self,
        *,
        role: str,
        exact_model_id: str | None,
        maximum_cost: Decimal,
        planned_prompt_tokens: int | None,
        planned_completion_tokens: int | None,
    ) -> None:
        if (
            planned_prompt_tokens is not None
            and self.global_input_token_budget is not None
            and planned_prompt_tokens
            > self.global_input_token_budget
            - self._spent_input_tokens
            - self._reserved_input_tokens
        ):
            raise BudgetExhaustedError("request exceeds the remaining global input-token budget")
        if (
            planned_completion_tokens is not None
            and self.global_output_token_budget is not None
            and planned_completion_tokens
            > self.global_output_token_budget
            - self._spent_output_tokens
            - self._reserved_output_tokens
        ):
            raise BudgetExhaustedError("request exceeds the remaining global output-token budget")
        if exact_model_id is not None:
            self._require_usd_scope_capacity(
                scope="model",
                key=exact_model_id,
                maximum_cost=maximum_cost,
                caps=self.per_model_usd_caps,
                spent=self._spent_model_usd,
                reserved=self._reserved_model_usd,
            )
        self._require_usd_scope_capacity(
            scope="role",
            key=role,
            maximum_cost=maximum_cost,
            caps=self.per_role_usd_caps,
            spent=self._spent_role_usd,
            reserved=self._reserved_role_usd,
        )

    @staticmethod
    def _require_usd_scope_capacity(
        *,
        scope: str,
        key: str,
        maximum_cost: Decimal,
        caps: Mapping[str, Decimal],
        spent: Mapping[str, Decimal],
        reserved: Mapping[str, Decimal],
    ) -> None:
        cap = caps.get(key)
        if cap is None:
            if caps:
                raise BudgetExhaustedError(
                    f"request has no configured {scope} USD budget for {key}"
                )
            return
        available = _exact_decimal_subtract(
            cap,
            spent.get(key, Decimal(0)),
            reserved.get(key, Decimal(0)),
        )
        if maximum_cost > available:
            raise BudgetExhaustedError(
                f"request exceeds the remaining {scope} USD budget for {key}"
            )

    def _reserve_scoped(self, reservation: Reservation, maximum_cost: Decimal) -> None:
        if reservation.planned_prompt_tokens is not None:
            self._reserved_input_tokens += reservation.planned_prompt_tokens
        if reservation.planned_completion_tokens is not None:
            self._reserved_output_tokens += reservation.planned_completion_tokens
        if reservation.exact_model_id is not None:
            _increment_decimal(
                self._reserved_model_usd,
                reservation.exact_model_id,
                maximum_cost,
            )
        if reservation.role is not None:
            _increment_decimal(self._reserved_role_usd, reservation.role, maximum_cost)

    def _maximum_request_cost(
        self,
        request_material: str,
        endpoint_cost_bound: EndpointRequestCostBound | None,
    ) -> Decimal:
        if endpoint_cost_bound is None:
            if self.require_endpoint_cost_bound:
                raise UnprovenCostBoundError(
                    "certification paid request lacks an endpoint-bound maximum cost"
                )
            return Decimal(str(self.estimate_request_cost(request_material)))

        material_hash = hashlib.sha256(request_material.encode("utf-8")).hexdigest()
        if endpoint_cost_bound.request_material_sha256 != material_hash:
            raise UnprovenCostBoundError(
                "endpoint cost bound does not match the serialized request"
            )
        input_token_upper_bound = max(1, len(request_material.encode("utf-8")))
        if (
            _trusted_endpoint_request_maximum_units_for(endpoint_cost_bound, "prompt")
            < input_token_upper_bound
        ):
            raise UnprovenCostBoundError(
                "endpoint prompt-token ceiling is below the UTF-8 byte upper bound"
            )
        if (
            _trusted_endpoint_request_maximum_units_for(endpoint_cost_bound, "completion")
            < self.max_output_tokens
        ):
            raise UnprovenCostBoundError(
                "endpoint completion-token ceiling is below the configured output maximum"
            )
        _require_pristine_endpoint_cost_bound_types()
        return _trusted_endpoint_request_maximum_cost_usd(endpoint_cost_bound)

    async def reconcile(
        self,
        reservation: Reservation,
        actual_cost_usd: Decimal | float | int | None,
        *,
        actual_prompt_tokens: int | None = None,
        actual_completion_tokens: int | None = None,
        actual_reasoning_tokens: int | None = None,
    ) -> float:
        """Replace a reservation with reported cost, or its conservative estimate."""

        normalized_actual = _normalize_actual_cost(actual_cost_usd)
        normalized_prompt_tokens = _validate_optional_token_count(
            actual_prompt_tokens,
            field="provider actual prompt tokens",
        )
        normalized_completion_tokens = _validate_optional_token_count(
            actual_completion_tokens,
            field="provider actual completion tokens",
        )
        normalized_reasoning_tokens = _validate_optional_token_count(
            actual_reasoning_tokens,
            field="provider actual reasoning tokens",
        )
        if normalized_reasoning_tokens is not None and normalized_completion_tokens is None:
            raise BudgetReservationStateError(
                "provider reasoning-token usage requires completion-token usage"
            )
        async with self._lock:
            _require_trusted_budget_accounting_state(self)
            if self._issued.get(reservation.identifier) != reservation:
                raise BudgetReservationStateError(
                    "request reservation handle is unknown or inconsistent"
                )
            prior = self._reconciled.get(reservation.identifier)
            if prior is not None:
                if prior.actual_cost_usd != normalized_actual:
                    raise BudgetReservationStateError(
                        "request reservation was reconciled with a different cost"
                    )
                if (
                    prior.actual_prompt_tokens != normalized_prompt_tokens
                    or prior.actual_completion_tokens != normalized_completion_tokens
                    or prior.actual_reasoning_tokens != normalized_reasoning_tokens
                ):
                    raise BudgetReservationStateError(
                        "request reservation was reconciled with different token usage"
                    )
                if prior.cost_overrun:
                    raise CostReservationOverrunError(
                        "actual cost exceeded its maximum reservation"
                    )
                if prior.token_overrun:
                    raise TokenReservationOverrunError(
                        "actual token usage exceeded or did not prove its planned reservation"
                    )
                return prior.accounted_cost_usd
            if reservation.identifier in self._released:
                raise BudgetReservationStateError(
                    "released request reservation cannot be reconciled"
                )
            if reservation.planned_prompt_tokens is None:
                if (
                    normalized_prompt_tokens is not None
                    or normalized_completion_tokens is not None
                    or normalized_reasoning_tokens is not None
                ):
                    raise BudgetReservationStateError(
                        "provider token usage cannot be reconciled without a token plan"
                    )
            elif (
                reservation.planned_completion_tokens is None or reservation.exact_model_id is None
            ):
                raise BudgetReservationStateError(
                    "request reservation has an incomplete token plan"
                )
            if (
                normalized_reasoning_tokens is not None
                and reservation.planned_reasoning_tokens is None
            ):
                raise BudgetReservationStateError(
                    "provider reasoning-token usage cannot be reconciled without a split token plan"
                )
            try:
                estimated = self._reserved[reservation.identifier]
            except KeyError:
                raise BudgetReservationStateError(
                    "request reservation has no active budget"
                ) from None
            accounted_decimal = estimated if normalized_actual is None else normalized_actual
            accounted = float(accounted_decimal)
            accounted_prompt_tokens = (
                reservation.planned_prompt_tokens
                if normalized_prompt_tokens is None
                else normalized_prompt_tokens
            )
            accounted_completion_tokens = (
                reservation.planned_completion_tokens
                if normalized_completion_tokens is None
                else normalized_completion_tokens
            )
            reasoning_observation_missing = bool(
                reservation.planned_reasoning_tokens is not None
                and reservation.planned_reasoning_tokens > 0
                and normalized_completion_tokens is not None
                and normalized_reasoning_tokens is None
            )
            accounted_reasoning_tokens = (
                reservation.planned_reasoning_tokens
                if normalized_completion_tokens is None or reasoning_observation_missing
                else (
                    0
                    if normalized_reasoning_tokens is None
                    and reservation.planned_reasoning_tokens == 0
                    else normalized_reasoning_tokens
                )
            )
            accounted_visible_output_tokens = (
                None
                if accounted_completion_tokens is None or accounted_reasoning_tokens is None
                else accounted_completion_tokens - accounted_reasoning_tokens
            )
            token_overrun = bool(
                reasoning_observation_missing
                or (
                    accounted_reasoning_tokens is not None
                    and accounted_completion_tokens is not None
                    and accounted_reasoning_tokens > accounted_completion_tokens
                )
                or (
                    accounted_prompt_tokens is not None
                    and reservation.planned_prompt_tokens is not None
                    and accounted_prompt_tokens > reservation.planned_prompt_tokens
                )
                or (
                    accounted_completion_tokens is not None
                    and reservation.planned_completion_tokens is not None
                    and accounted_completion_tokens > reservation.planned_completion_tokens
                )
                or (
                    accounted_reasoning_tokens is not None
                    and reservation.planned_reasoning_tokens is not None
                    and accounted_reasoning_tokens > reservation.planned_reasoning_tokens
                )
                or (
                    accounted_visible_output_tokens is not None
                    and reservation.planned_visible_output_tokens is not None
                    and accounted_visible_output_tokens > reservation.planned_visible_output_tokens
                )
            )
            cost_overrun = normalized_actual is not None and normalized_actual > estimated
            persistent_overrun: CostReservationOverrunError | None = None
            ledger = self._current_atomic_ledger()
            if (ledger is None) != (reservation.persistent is None):
                raise BudgetReservationStateError(
                    "request reservation persistent cost-ledger custody is inconsistent"
                )
            if ledger is not None and reservation.persistent is not None:
                try:
                    _TRUSTED_ATOMIC_LEDGER_RECONCILE(
                        ledger,
                        reservation.persistent,
                        normalized_actual,
                    )
                except CostReservationOverrunError as exc:
                    persistent_overrun = exc
                    cost_overrun = True
            self._reserved.pop(reservation.identifier)
            self._close_scoped_reservation(
                reservation,
                reserved_cost=estimated,
                accounted_cost=accounted_decimal,
                accounted_prompt_tokens=accounted_prompt_tokens,
                accounted_completion_tokens=accounted_completion_tokens,
            )
            self._spent_exact = _exact_decimal_add(self._spent_exact, accounted_decimal)
            self._spent = float(self._spent_exact)
            self._reconciled[reservation.identifier] = _Reconciliation(
                actual_cost_usd=normalized_actual,
                actual_prompt_tokens=normalized_prompt_tokens,
                actual_completion_tokens=normalized_completion_tokens,
                actual_reasoning_tokens=normalized_reasoning_tokens,
                accounted_cost_usd=accounted,
                accounted_cost_usd_exact=accounted_decimal,
                accounted_prompt_tokens=accounted_prompt_tokens,
                accounted_completion_tokens=accounted_completion_tokens,
                accounted_reasoning_tokens=accounted_reasoning_tokens,
                cost_overrun=cost_overrun,
                token_overrun=token_overrun,
            )
            self._transport_committed.discard(reservation.identifier)
            _refresh_trusted_budget_accounting_state(self)
            if cost_overrun:
                if persistent_overrun is not None:
                    raise persistent_overrun
                raise CostReservationOverrunError("actual cost exceeded its maximum reservation")
            if token_overrun:
                raise TokenReservationOverrunError(
                    "actual token usage exceeded or did not prove its planned reservation"
                )
            return accounted

    async def reconciled_cost_usd_exact(self, reservation: Reservation) -> Decimal:
        """Return the exact cost retained for one already reconciled reservation."""

        async with self._lock:
            _require_trusted_budget_accounting_state(self)
            if self._issued.get(reservation.identifier) != reservation:
                raise BudgetReservationStateError(
                    "request reservation handle is unknown or inconsistent"
                )
            reconciliation = self._reconciled.get(reservation.identifier)
            if reconciliation is None:
                raise BudgetReservationStateError("request reservation is not reconciled")
            self._require_durable_reconciliation(reservation, reconciliation)
            return reconciliation.accounted_cost_usd_exact

    async def commit_active_reservation_for_transport(self, reservation: Reservation) -> None:
        """Atomically account the full bound before provider transport can begin."""

        async with self._lock:
            _require_trusted_budget_accounting_state(self)
            if self._issued.get(reservation.identifier) != reservation:
                raise BudgetReservationStateError(
                    "request reservation handle is unknown or inconsistent"
                )
            if (
                reservation.identifier in self._released
                or reservation.identifier in self._reconciled
            ):
                raise BudgetReservationStateError("request reservation is not active for transport")
            reserved_cost = self._reserved.get(reservation.identifier)
            bound = reservation.endpoint_cost_bound
            if (
                reserved_cost is None
                or bound is None
                or reserved_cost != _trusted_endpoint_request_maximum_cost_usd(bound)
            ):
                raise BudgetReservationStateError(
                    "active transport reservation differs from its exact endpoint cost bound"
                )
            ledger = self._current_atomic_ledger()
            persistent = reservation.persistent
            if (
                ledger is None
                or persistent is None
                or persistent.request_id != reservation.identifier
                or persistent.reserved_usd != reserved_cost
            ):
                raise BudgetReservationStateError(
                    "active transport reservation lacks exact persistent ledger custody"
                )
            entry = _TRUSTED_ATOMIC_LEDGER_RECONCILE(ledger, persistent, None)
            snapshot = _TRUSTED_ATOMIC_LEDGER_SNAPSHOT(ledger)
            durable_matches = tuple(
                current
                for current in snapshot.entries
                if current.request_id == reservation.identifier
                and current.reservation_id == persistent.reservation_id
            )
            if (
                entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
                or entry.reserved_usd != reserved_cost
                or entry.actual_cost_usd is not None
                or entry.accounted_cost_usd != reserved_cost
                or entry.reservation_id != persistent.reservation_id
                or len(durable_matches) != 1
                or durable_matches[0] != entry
            ):
                raise BudgetReservationStateError(
                    "persistent transport reservation did not become conservatively accounted"
                )
            self._transport_committed.add(reservation.identifier)
            _refresh_trusted_budget_accounting_state(self)

    def _require_durable_reconciliation(
        self,
        reservation: Reservation,
        reconciliation: _Reconciliation,
    ) -> None:
        ledger = self._current_atomic_ledger()
        persistent = reservation.persistent
        if ledger is None:
            if persistent is not None:
                raise BudgetReservationStateError(
                    "reconciled reservation has inconsistent persistent custody"
                )
            return
        if persistent is None:
            raise BudgetReservationStateError(
                "reconciled reservation lacks persistent cost-ledger custody"
            )
        snapshot = _TRUSTED_ATOMIC_LEDGER_SNAPSHOT(ledger)
        matches = tuple(
            entry
            for entry in snapshot.entries
            if entry.request_id == reservation.identifier
            and entry.reservation_id == persistent.reservation_id
        )
        expected_status = (
            CostEntryStatus.UNCERTAIN_ACCOUNTED
            if reconciliation.actual_cost_usd is None
            else (
                CostEntryStatus.RESERVATION_OVERRUN
                if reconciliation.cost_overrun
                else CostEntryStatus.RECONCILED
            )
        )
        if (
            len(matches) != 1
            or matches[0].status is not expected_status
            or matches[0].reserved_usd != persistent.reserved_usd
            or matches[0].actual_cost_usd != reconciliation.actual_cost_usd
            or matches[0].accounted_cost_usd != reconciliation.accounted_cost_usd_exact
        ):
            raise BudgetReservationStateError(
                "durable cost-ledger entry differs from reconciled request custody"
            )

    async def release(self, reservation: Reservation) -> None:
        async with self._lock:
            _require_trusted_budget_accounting_state(self)
            if self._issued.get(reservation.identifier) != reservation:
                raise BudgetReservationStateError(
                    "request reservation handle is unknown or inconsistent"
                )
            if reservation.identifier in self._released:
                return
            if reservation.identifier in self._reconciled:
                raise BudgetReservationStateError(
                    "reconciled request reservation cannot be released"
                )
            if reservation.identifier in self._transport_committed:
                raise BudgetReservationStateError(
                    "transport-committed reservation cannot be released"
                )
            ledger = self._current_atomic_ledger()
            if (ledger is None) != (reservation.persistent is None):
                raise BudgetReservationStateError(
                    "request reservation persistent cost-ledger custody is inconsistent"
                )
            if ledger is not None and reservation.persistent is not None:
                _TRUSTED_ATOMIC_LEDGER_RELEASE(
                    ledger,
                    reservation.persistent,
                    reason=ReleaseReason.FAILED_BEFORE_SEND,
                )
            try:
                reserved_cost = self._reserved.pop(reservation.identifier)
            except KeyError:
                raise BudgetReservationStateError(
                    "request reservation has no active budget"
                ) from None
            self._release_scoped(reservation, reserved_cost)
            self._released.add(reservation.identifier)
            _refresh_trusted_budget_accounting_state(self)

    def _close_scoped_reservation(
        self,
        reservation: Reservation,
        *,
        reserved_cost: Decimal,
        accounted_cost: Decimal,
        accounted_prompt_tokens: int | None,
        accounted_completion_tokens: int | None,
    ) -> None:
        self._release_scoped(reservation, reserved_cost)
        if accounted_prompt_tokens is not None:
            self._spent_input_tokens += accounted_prompt_tokens
        if accounted_completion_tokens is not None:
            self._spent_output_tokens += accounted_completion_tokens
        if reservation.exact_model_id is not None:
            _increment_decimal(
                self._spent_model_usd,
                reservation.exact_model_id,
                accounted_cost,
            )
        if reservation.role is not None:
            _increment_decimal(self._spent_role_usd, reservation.role, accounted_cost)

    def _release_scoped(self, reservation: Reservation, reserved_cost: Decimal) -> None:
        if reservation.planned_prompt_tokens is not None:
            self._reserved_input_tokens -= reservation.planned_prompt_tokens
        if reservation.planned_completion_tokens is not None:
            self._reserved_output_tokens -= reservation.planned_completion_tokens
        if reservation.exact_model_id is not None:
            _decrement_decimal(
                self._reserved_model_usd,
                reservation.exact_model_id,
                reserved_cost,
            )
        if reservation.role is not None:
            _decrement_decimal(self._reserved_role_usd, reservation.role, reserved_cost)


@dataclass(frozen=True, slots=True)
class _TrustedBudgetAccountingState:
    """Closure-retained projection of one manager's last trusted lifecycle state."""

    containers: tuple[object, ...]
    material: tuple[object, ...]


_BUDGET_ACCOUNTING_CONTAINER_FIELDS: Final = (
    "_reserved",
    "_issued",
    "_reconciled",
    "_released",
    "_transport_committed",
    "_pending_adoptions",
    "_request_limit_counts",
    "_reserved_model_usd",
    "_spent_model_usd",
    "_reserved_role_usd",
    "_spent_role_usd",
)


def _accounting_string(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise BudgetReservationStateError(f"budget accounting {field} type is invalid")
    return value


def _accounting_optional_string(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    return _accounting_string(value, field=field)


def _accounting_decimal(value: object, *, field: str) -> Decimal:
    if type(value) is not Decimal or not value.is_finite() or value < 0:
        raise BudgetReservationStateError(f"budget accounting {field} is invalid")
    return value


def _accounting_active_request_cost_scope_material(
    value: object,
    *,
    manager: BudgetManager,
) -> tuple[object, ...] | None:
    if value is None:
        return None
    if (
        type(value) is not _ActiveRequestCostCeilingScope
        or value.manager is not manager
        or not isinstance(value.event_loop, asyncio.AbstractEventLoop)
        or value._authority is not _ACTIVE_REQUEST_COST_CEILING_AUTHORITY
    ):
        raise BudgetReservationStateError(
            "budget accounting active per-request cost scope is invalid"
        )
    ceiling = _accounting_decimal(
        value.maximum_cost_usd,
        field="active per-request cost ceiling",
    )
    if ceiling <= 0:
        raise BudgetReservationStateError(
            "budget accounting active per-request cost ceiling is invalid"
        )
    return (id(value), id(value.event_loop), id(value._authority), ceiling)


def _accounting_float(value: object, *, field: str) -> float:
    if type(value) is not float or not math.isfinite(value) or value < 0:
        raise BudgetReservationStateError(f"budget accounting {field} is invalid")
    return value


def _accounting_int(value: object, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_METERED_UNITS:
        raise BudgetReservationStateError(f"budget accounting {field} is invalid")
    return value


def _accounting_optional_int(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    return _accounting_int(value, field=field)


def _accounting_decimal_map(value: object, *, field: str) -> tuple[tuple[str, Decimal], ...]:
    if type(value) is not dict:
        raise BudgetReservationStateError(f"budget accounting {field} container is invalid")
    entries: list[tuple[str, Decimal]] = []
    for key, amount in value.items():
        entries.append(
            (
                _accounting_string(key, field=f"{field} key"),
                _accounting_decimal(amount, field=f"{field} value"),
            )
        )
    return tuple(sorted(entries))


def _accounting_cost_reservation_material(value: object) -> tuple[object, ...] | None:
    if value is None:
        return None
    if type(value) is not CostReservation:
        raise BudgetReservationStateError(
            "budget accounting persistent reservation type is invalid"
        )
    return (
        id(value),
        _accounting_string(value.request_id, field="persistent request ID"),
        _accounting_string(value.reservation_id, field="persistent reservation ID"),
        _accounting_decimal(value.reserved_usd, field="persistent reserved USD"),
    )


def _accounting_cost_bound_material(value: object) -> tuple[object, ...] | None:
    if value is None:
        return None
    if type(value) is not EndpointRequestCostBound:
        raise BudgetReservationStateError("budget accounting endpoint cost-bound type is invalid")
    maximum_cost = _trusted_endpoint_request_maximum_cost_usd(value)
    return (
        id(value),
        _accounting_string(value.exact_model_id, field="cost-bound model"),
        _accounting_string(value.provider_endpoint, field="cost-bound endpoint"),
        _accounting_string(value.request_material_sha256, field="cost-bound request hash"),
        _accounting_string(value.pricing_snapshot_sha256, field="cost-bound pricing hash"),
        tuple(
            (
                _accounting_string(component.pricing_field, field="cost component field"),
                _accounting_decimal(component.unit_price_usd, field="cost component price"),
                _accounting_int(component.maximum_units, field="cost component units"),
            )
            for component in value.components
        ),
        maximum_cost,
    )


def _accounting_reservation_material(value: object) -> tuple[object, ...]:
    if type(value) is not Reservation:
        raise BudgetReservationStateError("budget accounting reservation type is invalid")
    token_evidence = value.token_reservation_evidence
    if token_evidence is not None and type(token_evidence) is not AtomicTokenReservationEvidence:
        raise BudgetReservationStateError(
            "budget accounting token reservation evidence type is invalid"
        )
    request_evidence = value.request_limit_reservation_evidence
    if (
        request_evidence is not None
        and type(request_evidence) is not AtomicRequestLimitReservationEvidence
    ):
        raise BudgetReservationStateError(
            "budget accounting request-limit evidence type is invalid"
        )
    return (
        id(value),
        _accounting_string(value.identifier, field="reservation ID"),
        _accounting_float(value.estimated_cost_usd, field="estimated cost"),
        _accounting_cost_reservation_material(value.persistent),
        _accounting_cost_bound_material(value.endpoint_cost_bound),
        _accounting_optional_string(value.exact_model_id, field="reservation model"),
        _accounting_optional_string(value.role, field="reservation role"),
        _accounting_optional_int(value.planned_prompt_tokens, field="planned prompt tokens"),
        _accounting_optional_int(
            value.planned_visible_output_tokens,
            field="planned visible-output tokens",
        ),
        _accounting_optional_int(
            value.planned_reasoning_tokens,
            field="planned reasoning tokens",
        ),
        _accounting_optional_int(
            value.planned_completion_tokens,
            field="planned completion tokens",
        ),
        _accounting_optional_string(value.request_token_plan_sha256, field="token plan hash"),
        (
            None
            if token_evidence is None
            else (
                id(token_evidence),
                _accounting_string(
                    token_evidence.evidence_sha256,
                    field="token reservation evidence hash",
                ),
            )
        ),
        _accounting_optional_string(value.request_limit_scope, field="request-limit scope"),
        (
            None
            if request_evidence is None
            else (
                id(request_evidence),
                _accounting_string(
                    request_evidence.evidence_sha256,
                    field="request-limit reservation evidence hash",
                ),
            )
        ),
    )


def _accounting_reconciliation_material(value: object) -> tuple[object, ...]:
    if type(value) is not _Reconciliation:
        raise BudgetReservationStateError("budget accounting reconciliation type is invalid")
    if type(value.cost_overrun) is not bool or type(value.token_overrun) is not bool:
        raise BudgetReservationStateError("budget accounting reconciliation flags are invalid")
    return (
        id(value),
        (
            None
            if value.actual_cost_usd is None
            else _accounting_decimal(value.actual_cost_usd, field="actual cost")
        ),
        _accounting_optional_int(value.actual_prompt_tokens, field="actual prompt tokens"),
        _accounting_optional_int(
            value.actual_completion_tokens,
            field="actual completion tokens",
        ),
        _accounting_optional_int(
            value.actual_reasoning_tokens,
            field="actual reasoning tokens",
        ),
        _accounting_float(value.accounted_cost_usd, field="accounted float cost"),
        _accounting_decimal(value.accounted_cost_usd_exact, field="accounted exact cost"),
        _accounting_optional_int(
            value.accounted_prompt_tokens,
            field="accounted prompt tokens",
        ),
        _accounting_optional_int(
            value.accounted_completion_tokens,
            field="accounted completion tokens",
        ),
        _accounting_optional_int(
            value.accounted_reasoning_tokens,
            field="accounted reasoning tokens",
        ),
        value.cost_overrun,
        value.token_overrun,
    )


def _accounting_recovered_attempt_material(value: object) -> tuple[object, ...]:
    if type(value) is not RecoveredSchedulerCostAttempt:
        raise BudgetReservationStateError("budget accounting recovery attempt type is invalid")
    status = _accounting_string(value.status, field="recovery attempt status")
    if status not in {"adopted_proven_pre_send", "uncertain_accounted_after_dispatch"}:
        raise BudgetReservationStateError("budget accounting recovery attempt status is invalid")
    return (
        id(value),
        _accounting_string(value.request_id, field="recovery request ID"),
        _accounting_string(value.logical_request_id, field="recovery logical request ID"),
        _accounting_string(value.task_id, field="recovery task ID"),
        _accounting_string(value.requested_model, field="recovery model"),
        _accounting_string(value.role, field="recovery role"),
        status,
        _accounting_decimal(value.reserved_cost_usd_exact, field="recovery reserved cost"),
        _accounting_decimal(value.accounted_cost_usd_exact, field="recovery accounted cost"),
    )


def _project_trusted_budget_accounting_state(
    manager: BudgetManager,
) -> _TrustedBudgetAccountingState:
    try:
        containers = tuple(
            object.__getattribute__(manager, field) for field in _BUDGET_ACCOUNTING_CONTAINER_FIELDS
        )
        reserved = object.__getattribute__(manager, "_reserved")
        issued = object.__getattribute__(manager, "_issued")
        reconciled = object.__getattribute__(manager, "_reconciled")
        released = object.__getattribute__(manager, "_released")
        transport_committed = object.__getattribute__(manager, "_transport_committed")
        pending_adoptions = object.__getattribute__(manager, "_pending_adoptions")
        request_limit_counts = object.__getattribute__(manager, "_request_limit_counts")
    except (AttributeError, TypeError) as exc:
        raise BudgetReservationStateError("budget accounting state is incomplete") from exc
    if (
        any(type(value) is not dict for value in containers[:3])
        or any(type(value) is not set for value in containers[3:5])
        or any(type(value) is not dict for value in containers[5:])
    ):
        raise BudgetReservationStateError("budget accounting container type is invalid")

    reserved_material = _accounting_decimal_map(reserved, field="reserved USD")
    issued_material = tuple(
        sorted(
            (
                _accounting_string(key, field="issued request ID"),
                _accounting_reservation_material(value),
            )
            for key, value in issued.items()
        )
    )
    reconciled_material = tuple(
        sorted(
            (
                _accounting_string(key, field="reconciled request ID"),
                _accounting_reconciliation_material(value),
            )
            for key, value in reconciled.items()
        )
    )
    released_material = tuple(
        sorted(_accounting_string(value, field="released request ID") for value in released)
    )
    committed_material = tuple(
        sorted(
            _accounting_string(value, field="transport-committed request ID")
            for value in transport_committed
        )
    )
    pending_material = tuple(
        sorted(
            (
                _accounting_string(key, field="pending adoption request ID"),
                _accounting_recovered_attempt_material(value),
            )
            for key, value in pending_adoptions.items()
        )
    )
    request_count_material: list[tuple[tuple[str, str], int]] = []
    for key, value in request_limit_counts.items():
        if type(key) is not tuple or len(key) != 2:
            raise BudgetReservationStateError("budget accounting request-count key is invalid")
        request_count_material.append(
            (
                (
                    _accounting_string(key[0], field="request-count kind"),
                    _accounting_string(key[1], field="request-count scope"),
                ),
                _accounting_int(value, field="request-count value"),
            )
        )

    scalar_spent = _accounting_float(
        object.__getattribute__(manager, "_spent"),
        field="spent float USD",
    )
    exact_spent = _accounting_decimal(
        object.__getattribute__(manager, "_spent_exact"),
        field="spent exact USD",
    )
    if scalar_spent != float(exact_spent):
        raise BudgetReservationStateError("budget accounting spent totals are inconsistent")
    recovery_required = object.__getattribute__(manager, "_recovery_required")
    if type(recovery_required) is not bool:
        raise BudgetReservationStateError("budget accounting recovery flag is invalid")
    material: tuple[object, ...] = (
        scalar_spent,
        exact_spent,
        reserved_material,
        issued_material,
        reconciled_material,
        released_material,
        committed_material,
        pending_material,
        tuple(sorted(request_count_material)),
        _accounting_int(
            object.__getattribute__(manager, "_reserved_input_tokens"),
            field="reserved input tokens",
        ),
        _accounting_int(
            object.__getattribute__(manager, "_spent_input_tokens"),
            field="spent input tokens",
        ),
        _accounting_int(
            object.__getattribute__(manager, "_reserved_output_tokens"),
            field="reserved output tokens",
        ),
        _accounting_int(
            object.__getattribute__(manager, "_spent_output_tokens"),
            field="spent output tokens",
        ),
        _accounting_decimal_map(
            object.__getattribute__(manager, "_reserved_model_usd"),
            field="reserved model USD",
        ),
        _accounting_decimal_map(
            object.__getattribute__(manager, "_spent_model_usd"),
            field="spent model USD",
        ),
        _accounting_decimal_map(
            object.__getattribute__(manager, "_reserved_role_usd"),
            field="reserved role USD",
        ),
        _accounting_decimal_map(
            object.__getattribute__(manager, "_spent_role_usd"),
            field="spent role USD",
        ),
        _accounting_active_request_cost_scope_material(
            object.__getattribute__(manager, "_active_request_cost_ceiling_scope"),
            manager=manager,
        ),
        recovery_required,
    )
    return _TrustedBudgetAccountingState(containers=containers, material=material)


def _trusted_budget_accounting_state_registry() -> tuple[
    Callable[[BudgetManager], None],
    Callable[[BudgetManager], None],
    Callable[[BudgetManager], None],
]:
    states: weakref.WeakKeyDictionary[BudgetManager, _TrustedBudgetAccountingState] = (
        weakref.WeakKeyDictionary()
    )
    registry_lock = threading.RLock()

    def initialize(manager: BudgetManager) -> None:
        projection = _project_trusted_budget_accounting_state(manager)
        with registry_lock:
            if manager in states:
                raise BudgetReservationStateError("budget accounting state was already initialized")
            states[manager] = projection

    def refresh(manager: BudgetManager) -> None:
        projection = _project_trusted_budget_accounting_state(manager)
        with registry_lock:
            if manager not in states:
                raise BudgetReservationStateError("budget accounting state is not initialized")
            states[manager] = projection

    def require(manager: BudgetManager) -> None:
        projection = _project_trusted_budget_accounting_state(manager)
        with registry_lock:
            expected = states.get(manager)
        if expected is None or len(projection.containers) != len(expected.containers):
            raise BudgetReservationStateError(
                "budget accounting state lacks trusted lifecycle custody"
            )
        if (
            any(
                current is not trusted
                for current, trusted in zip(projection.containers, expected.containers, strict=True)
            )
            or projection.material != expected.material
        ):
            raise BudgetReservationStateError(
                "budget accounting state changed outside a trusted lifecycle transition"
            )

    return initialize, refresh, require


(
    _initialize_trusted_budget_accounting_state,
    _refresh_trusted_budget_accounting_state,
    _require_trusted_budget_accounting_state,
) = _trusted_budget_accounting_state_registry()


def _token_budget_state(
    *,
    global_input_token_limit: int | None,
    global_output_token_limit: int | None,
    spent_input_tokens: int,
    reserved_input_tokens: int,
    spent_output_tokens: int,
    reserved_output_tokens: int,
) -> TokenBudgetStateEvidence:
    remaining_input_tokens = _remaining_token_capacity(
        global_input_token_limit,
        spent=spent_input_tokens,
        reserved=reserved_input_tokens,
        field="input",
    )
    remaining_output_tokens = _remaining_token_capacity(
        global_output_token_limit,
        spent=spent_output_tokens,
        reserved=reserved_output_tokens,
        field="output",
    )
    return TokenBudgetStateEvidence(
        spent_input_tokens=spent_input_tokens,
        reserved_input_tokens=reserved_input_tokens,
        remaining_input_tokens=remaining_input_tokens,
        spent_output_tokens=spent_output_tokens,
        reserved_output_tokens=reserved_output_tokens,
        remaining_output_tokens=remaining_output_tokens,
    )


def _validate_token_state(
    state: TokenBudgetStateEvidence,
    *,
    global_input_token_limit: int | None,
    global_output_token_limit: int | None,
) -> None:
    expected_input = _remaining_token_capacity(
        global_input_token_limit,
        spent=state.spent_input_tokens,
        reserved=state.reserved_input_tokens,
        field="input",
    )
    if state.remaining_input_tokens != expected_input:
        raise ValueError("input token remaining capacity is inconsistent")
    expected_output = _remaining_token_capacity(
        global_output_token_limit,
        spent=state.spent_output_tokens,
        reserved=state.reserved_output_tokens,
        field="output",
    )
    if state.remaining_output_tokens != expected_output:
        raise ValueError("output token remaining capacity is inconsistent")


def _remaining_token_capacity(
    limit: int | None,
    *,
    spent: int,
    reserved: int,
    field: str,
) -> int | None:
    if limit is None:
        return None
    remaining = limit - spent - reserved
    if remaining < 0:
        raise ValueError(f"{field} token state exceeds its global limit")
    return remaining


def _canonical_evidence_sha256(payload: Mapping[str, Any]) -> str:
    material = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_budget_evidence_json_default,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _budget_evidence_json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported budget evidence value: {type(value).__name__}")


def _normalize_actual_cost(
    value: Decimal | float | int | None,
) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (Decimal, float, int)):
        raise BudgetReservationStateError("provider actual cost has an invalid type")
    try:
        parsed = value if isinstance(value, Decimal) else Decimal(str(value))
        if not parsed.is_finite() or parsed < 0:
            raise BudgetReservationStateError("provider actual cost is invalid")
        with localcontext() as context:
            context.prec = _EXACT_MONEY_PRECISION
            return parsed.quantize(_USD_QUANTUM, rounding=ROUND_CEILING)
    except (InvalidOperation, ValueError, OverflowError):
        raise BudgetReservationStateError("provider actual cost is invalid") from None


def _validate_optional_token_budget(value: int | None, *, field: str) -> int | None:
    if value is None:
        return None
    return _validate_token_count(value, field=field)


def _validate_optional_token_count(value: int | None, *, field: str) -> int | None:
    if value is None:
        return None
    return _validate_token_count(value, field=field)


def _validate_token_count(value: int, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_METERED_UNITS:
        raise ValueError(f"{field} is invalid")
    return value


def _validate_scope_key(value: str, pattern: re.Pattern[str], *, scope: str) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        raise ValueError(f"{scope} budget key is invalid")
    return value


def _validate_scoped_caps(
    caps: Mapping[str, str | Decimal | int] | None,
    *,
    key_pattern: re.Pattern[str],
    scope: str,
) -> dict[str, Decimal]:
    if caps is None:
        return {}
    if not isinstance(caps, Mapping):
        raise ValueError(f"{scope} USD caps must be a mapping")
    validated: dict[str, Decimal] = {}
    for key, value in caps.items():
        validated_key = _validate_scope_key(key, key_pattern, scope=scope)
        validated[validated_key] = _parse_usd_cap(value, scope=scope)
    return validated


def _parse_usd_cap(value: str | Decimal | int, *, scope: str) -> Decimal:
    if type(value) not in {str, Decimal, int}:
        raise ValueError(f"{scope} USD cap must be a Decimal-safe value")
    if isinstance(value, str):
        if not value or value != value.strip():
            raise ValueError(f"{scope} USD cap is invalid")
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError(f"{scope} USD cap is invalid") from exc
    else:
        parsed = Decimal(value)
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{scope} USD cap must be finite and non-negative")
    try:
        with localcontext() as context:
            context.prec = _EXACT_MONEY_PRECISION
            quantized = parsed.quantize(_USD_QUANTUM)
    except InvalidOperation as exc:
        raise ValueError(f"{scope} USD cap exceeds supported precision") from exc
    if parsed != quantized:
        raise ValueError(f"{scope} USD cap exceeds supported precision")
    integer_digits = max(1, len(parsed.as_tuple().digits) + cast(int, parsed.as_tuple().exponent))
    if integer_digits > _MAX_PRICE_INTEGER_DIGITS:
        raise ValueError(f"{scope} USD cap exceeds supported magnitude")
    return quantized


def _validate_active_request_cost_ceiling(value: Decimal) -> Decimal:
    if type(value) is not Decimal:
        raise ValueError("active per-request cost ceiling must be an exact Decimal")
    ceiling = _parse_usd_cap(value, scope="active per-request")
    if ceiling <= 0:
        raise ValueError("active per-request USD cap must be positive")
    return ceiling


def _canonical_budget_float(value: float, *, field: str, positive: bool) -> float:
    if type(value) not in {int, float}:
        raise ValueError(f"{field} must be an exact int or float")
    canonical = float(value)
    if not math.isfinite(canonical) or (canonical <= 0 if positive else canonical < 0):
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{field} must be finite and {qualifier}")
    return canonical


def _increment_decimal(values: dict[str, Decimal], key: str, amount: Decimal) -> None:
    values[key] = _exact_decimal_add(values.get(key, Decimal(0)), amount)


def _decrement_decimal(values: dict[str, Decimal], key: str, amount: Decimal) -> None:
    current = values.get(key)
    if current is None or current < amount:
        raise BudgetReservationStateError("scoped reservation accounting is inconsistent")
    remaining = _exact_decimal_subtract(current, amount)
    if remaining == 0:
        values.pop(key)
    else:
        values[key] = remaining


def _parse_price(value: str | Decimal) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, Decimal)):
        raise ValueError("endpoint prices must be decimal strings")
    if isinstance(value, str):
        if not value or value != value.strip():
            raise ValueError("endpoint price is invalid")
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError("endpoint price is invalid") from exc
    else:
        parsed = value
    return _validate_price(parsed)


def _validate_price(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        raise ValueError("endpoint price must be a finite non-negative Decimal")
    if value == 0:
        normalized = Decimal(0)
    else:
        raw = value.as_tuple()
        exponent = cast(int, raw.exponent)
        digits = list(raw.digits)
        while digits[-1] == 0:
            digits.pop()
            exponent += 1
        normalized = Decimal((raw.sign, tuple(digits), exponent))
    components = normalized.as_tuple()
    exponent = cast(int, components.exponent)
    decimal_places = max(0, -exponent)
    integer_digits = max(1, len(components.digits) + exponent)
    if decimal_places > _MAX_PRICE_DECIMAL_PLACES:
        raise ValueError("endpoint price exceeds supported decimal precision")
    if integer_digits > _MAX_PRICE_INTEGER_DIGITS:
        raise ValueError("endpoint price exceeds supported magnitude")
    return normalized


def _pricing_snapshot_hash(
    exact_model_id: str,
    provider_endpoint: str,
    components: tuple[EndpointPriceComponent, ...],
) -> str:
    payload = {
        "exact_model_id": exact_model_id,
        "provider_endpoint": provider_endpoint,
        "pricing": {
            component.pricing_field: format(component.unit_price_usd, "f")
            for component in components
        },
    }
    material = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()
