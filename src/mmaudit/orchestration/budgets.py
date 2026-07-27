"""Hard model-call budget accounting."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal, InvalidOperation, localcontext
from typing import Final, cast

from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostReservation,
    CostReservationOverrunError,
    ReleaseReason,
)


class BudgetExhaustedError(RuntimeError):
    """Raised before a request that could exceed the hard run budget."""


class BudgetReservationStateError(RuntimeError):
    """Raised when a request reservation is finalized inconsistently."""


class UnprovenCostBoundError(BudgetExhaustedError):
    """Raised before a certification request whose maximum cost is not proven."""


_MODEL_ID_PATTERN: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z"
)
_ENDPOINT_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,255}\Z")
_PRICING_FIELD_PATTERN: Final = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
_USD_QUANTUM: Final = Decimal("1e-18")
_MAX_PRICE_DECIMAL_PLACES: Final = 36
_MAX_PRICE_INTEGER_DIGITS: Final = 12
_MAX_METERED_UNITS: Final = 2**63 - 1


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

        with localcontext() as context:
            context.prec = 96
            return self.unit_price_usd * self.maximum_units


@dataclass(frozen=True)
class EndpointRequestCostBound:
    """Endpoint-bound maximum cost proof for one exact serialized request.

    ``components`` must account for every field in the provider endpoint's
    advertised pricing object, including fields whose maximum units are zero for
    this request. The snapshot hash is recomputed from the exact model, endpoint,
    and components so a bound cannot be silently reused with different pricing.
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
        if self.maximum_cost_usd <= 0:
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

        with localcontext() as context:
            context.prec = 96
            total = sum(
                (component.maximum_cost_usd for component in self.components),
                start=Decimal(0),
            )
            return total.quantize(_USD_QUANTUM, rounding=ROUND_CEILING)

    def maximum_units_for(self, pricing_field: str) -> int:
        """Return a pricing field's unit ceiling, rejecting an absent field."""

        for component in self.components:
            if component.pricing_field == pricing_field:
                return component.maximum_units
        raise UnprovenCostBoundError(f"endpoint cost bound omits required {pricing_field} pricing")


@dataclass(frozen=True)
class Reservation:
    identifier: str
    estimated_cost_usd: float
    persistent: CostReservation | None = None
    endpoint_cost_bound: EndpointRequestCostBound | None = None


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
    ) -> None:
        if require_endpoint_cost_bound and atomic_ledger is None:
            raise BudgetReservationStateError(
                "endpoint-bound certification costs require a durable atomic ledger"
            )
        self.total_usd = total_usd
        self.max_output_tokens = max_output_tokens
        self.conservative_rate = conservative_usd_per_million_tokens
        self.max_requests_per_agent = max_requests_per_agent
        self.atomic_ledger = atomic_ledger
        self.require_endpoint_cost_bound = require_endpoint_cost_bound
        snapshot = atomic_ledger.snapshot() if atomic_ledger is not None else None
        if snapshot is not None and (
            snapshot.active_reserved_usd > 0
            or snapshot.over_cap
            or any(
                entry.status is CostEntryStatus.RESERVATION_OVERRUN for entry in snapshot.entries
            )
        ):
            raise BudgetReservationStateError(
                "persistent model-cost ledger requires explicit recovery"
            )
        self._spent = float(snapshot.spent_usd) if snapshot is not None else 0.0
        self._reserved: dict[str, float] = {}
        self._issued: dict[str, Reservation] = {}
        self._reconciled: dict[str, tuple[Decimal | None, float, bool]] = {}
        self._released: set[str] = set()
        self._role_requests: dict[str, int] = {}
        self._lock = asyncio.Lock()

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
    def reserved_usd(self) -> float:
        return sum(self._reserved.values())

    @property
    def remaining_usd(self) -> float:
        return max(0.0, self.total_usd - self._spent - self.reserved_usd)

    async def reserve(
        self,
        identifier: str,
        role: str,
        prompt: str,
        *,
        endpoint_cost_bound: EndpointRequestCostBound | None = None,
    ) -> Reservation:
        """Reserve before send, requiring exact endpoint pricing in certification mode."""

        maximum_cost = self._maximum_request_cost(prompt, endpoint_cost_bound)
        estimated = float(maximum_cost)
        async with self._lock:
            if identifier in self._issued:
                raise BudgetReservationStateError(
                    "request reservation identifier was already issued"
                )
            count = self._role_requests.get(role, 0)
            if count >= self.max_requests_per_agent:
                raise BudgetExhaustedError(f"request limit reached for role {role}")
            if estimated > self.total_usd - self._spent - self.reserved_usd + 1e-12:
                raise BudgetExhaustedError(
                    f"request for {role} could cost ${estimated:.4f}, "
                    f"but only ${self.remaining_usd:.4f} remains"
                )
            try:
                persistent = (
                    self.atomic_ledger.reserve(identifier, maximum_cost)
                    if self.atomic_ledger is not None
                    else None
                )
            except CostBudgetExceededError:
                raise BudgetExhaustedError(
                    f"request for {role} exceeds the persistent model-cost budget"
                ) from None
            self._reserved[identifier] = estimated
            self._role_requests[role] = count + 1
            reservation = Reservation(
                identifier=identifier,
                estimated_cost_usd=estimated,
                persistent=persistent,
                endpoint_cost_bound=endpoint_cost_bound,
            )
            self._issued[identifier] = reservation
            return reservation

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
        if endpoint_cost_bound.maximum_units_for("prompt") < input_token_upper_bound:
            raise UnprovenCostBoundError(
                "endpoint prompt-token ceiling is below the UTF-8 byte upper bound"
            )
        if endpoint_cost_bound.maximum_units_for("completion") < self.max_output_tokens:
            raise UnprovenCostBoundError(
                "endpoint completion-token ceiling is below the configured output maximum"
            )
        return endpoint_cost_bound.maximum_cost_usd

    async def reconcile(
        self,
        reservation: Reservation,
        actual_cost_usd: Decimal | float | int | None,
    ) -> float:
        """Replace a reservation with reported cost, or its conservative estimate."""

        async with self._lock:
            if self._issued.get(reservation.identifier) != reservation:
                raise BudgetReservationStateError(
                    "request reservation handle is unknown or inconsistent"
                )
            prior = self._reconciled.get(reservation.identifier)
            normalized_actual = _normalize_actual_cost(actual_cost_usd)
            if prior is not None:
                prior_actual, prior_accounted, prior_overrun = prior
                if prior_actual != normalized_actual:
                    raise BudgetReservationStateError(
                        "request reservation was reconciled with a different cost"
                    )
                if prior_overrun:
                    raise CostReservationOverrunError(
                        "actual cost exceeded its maximum reservation"
                    )
                return prior_accounted
            if reservation.identifier in self._released:
                raise BudgetReservationStateError(
                    "released request reservation cannot be reconciled"
                )
            try:
                estimated = self._reserved.pop(reservation.identifier)
            except KeyError:
                raise BudgetReservationStateError(
                    "request reservation has no active budget"
                ) from None
            accounted = estimated if normalized_actual is None else float(normalized_actual)
            overrun: CostReservationOverrunError | None = None
            if self.atomic_ledger is not None and reservation.persistent is not None:
                try:
                    self.atomic_ledger.reconcile(
                        reservation.persistent,
                        normalized_actual,
                    )
                except CostReservationOverrunError as exc:
                    overrun = exc
            self._spent += accounted
            self._reconciled[reservation.identifier] = (
                normalized_actual,
                accounted,
                overrun is not None,
            )
            if overrun is not None:
                raise overrun
            return accounted

    async def release(self, reservation: Reservation) -> None:
        async with self._lock:
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
            if self.atomic_ledger is not None and reservation.persistent is not None:
                self.atomic_ledger.release(
                    reservation.persistent,
                    reason=ReleaseReason.FAILED_BEFORE_SEND,
                )
            self._reserved.pop(reservation.identifier, None)
            self._released.add(reservation.identifier)


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
            context.prec = 96
            return parsed.quantize(_USD_QUANTUM, rounding=ROUND_CEILING)
    except (InvalidOperation, ValueError, OverflowError):
        raise BudgetReservationStateError("provider actual cost is invalid") from None


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
    normalized = value.normalize()
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
