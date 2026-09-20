"""Exact reservation accounting under the explicit September-9 operator relaxation.

These artifacts describe costs, not provider guarantees or admission authority.
Every advertised component survives projection. Existing provider-cap algorithms
are used only for the subset of components they actually cap and remain unchanged.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from decimal import ROUND_CEILING, Decimal, localcontext
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.models.route_constraints import (
    ExactRoutePrice,
    ExactRoutePricingSchedule,
    ProviderPriceCap,
    RoutePriceComponent,
    normalize_exact_route_pricing,
)
from mmaudit.models.route_constraints import (
    RouteCostReservationPolicy as RouteCostReservationPolicy,
)
from mmaudit.models.route_constraints import (
    project_route_reservation_provider_caps as _project_provider_capped_subset,
)
from mmaudit.models.token_planning import EndpointRouteTokenCapacity, RequestTokenPlan
from mmaudit.orchestration.cost_ledger import CostEntry, CostEntryStatus, cost_entry_sha256

if TYPE_CHECKING:
    from mmaudit.models.schemas import UsageRecord

_HASH = r"^[0-9a-f]{64}$"
_MONEY = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{0,35}[1-9])?$"
_MAX_REQUEST_BYTES = 64_000_000
_USD_QUANTUM = Decimal("1e-18")
_RATE_QUANTUM = Decimal("1e-36")
_REQUEST_FIELDS = frozenset(
    {
        "model",
        "messages",
        "temperature",
        "max_tokens",
        "stream",
        "provider",
        "response_format",
        "reasoning",
        "metadata",
    }
)


class RouteCostReservationError(ValueError):
    """A complete, bounded and exactly bound reservation could not be derived."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always", allow_inf_nan=False
    )


class ReservationRateBasis(StrEnum):
    PROVIDER_CAPPED = "PROVIDER_CAPPED_RATE"
    OPERATOR_RESERVED = "OPERATOR_RESERVED_UNCAPPABLE_RATE"


class RouteCostReservationComponent(_StrictModel):
    component: RoutePriceComponent
    maximum_observed_unit_price_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    reserved_unit_price_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    maximum_units: int = Field(ge=0, le=2**31 - 1)
    rate_basis: ReservationRateBasis


class RouteCostReservationRate(_StrictModel):
    """A reserved rate, not metered units, a request, or a total provider ceiling."""

    component: RoutePriceComponent
    maximum_observed_unit_price_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    reserved_unit_price_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    rate_basis: ReservationRateBasis


class ExactRouteCostReservation(_StrictModel):
    """Hash-only request binding plus complete prices, units and reserved liability.

    Serialized data is nonauthorizing. The request consumer must rederive this
    contract against the actual request and its own exact plan/profile/snapshot.
    The capped subset is not a ProviderPriceCapProof for the complete price vector.
    """

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["NONAUTHORIZING_COST_RESERVATION"] = "NONAUTHORIZING_COST_RESERVATION"
    policy: RouteCostReservationPolicy
    selection_plan_sha256: str = Field(pattern=_HASH)
    route_predicate_profile_sha256: str = Field(pattern=_HASH)
    route_constraint_sha256: str = Field(pattern=_HASH)
    endpoint_snapshot_sha256: str = Field(pattern=_HASH)
    request_material_sha256: str = Field(pattern=_HASH)
    request_material_utf8_bytes: int = Field(gt=0, le=_MAX_REQUEST_BYTES)
    request_token_plan: RequestTokenPlan
    exact_pricing: tuple[ExactRoutePrice, ...] = Field(min_length=2, max_length=8)
    pricing_schedule: ExactRoutePricingSchedule | None = None
    provider_capped_subset: tuple[ProviderPriceCap, ...] = Field(min_length=2, max_length=4)
    components: tuple[RouteCostReservationComponent, ...] = Field(min_length=2, max_length=8)
    reserved_cost_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    reservation_sha256: str = Field(pattern=_HASH)

    @classmethod
    def build(
        cls,
        *,
        policy: RouteCostReservationPolicy,
        selection_plan_sha256: str,
        route_predicate_profile_sha256: str,
        route_constraint_sha256: str,
        endpoint_snapshot_sha256: str,
        request_material: str,
        request_token_plan: RequestTokenPlan,
        pricing: Mapping[str, str],
        pricing_schedule: ExactRoutePricingSchedule | None = None,
    ) -> Self:
        policy = _detach(policy, RouteCostReservationPolicy)
        plan = _detach(request_token_plan, RequestTokenPlan)
        exact = normalize_exact_route_pricing(pricing)
        schedule = (
            None
            if pricing_schedule is None
            else _detach(pricing_schedule, ExactRoutePricingSchedule)
        )
        caps = project_route_reservation_provider_caps(exact, schedule=schedule)
        material = _require_request_shape(request_material, policy=policy, plan=plan, caps=caps)
        components, total = _project_components(
            policy=policy,
            plan=plan,
            pricing=exact,
            schedule=schedule,
            request_bytes=len(material),
            caps=caps,
        )
        values = {
            "schema_version": "1.0",
            "status": "NONAUTHORIZING_COST_RESERVATION",
            "policy": policy,
            "selection_plan_sha256": selection_plan_sha256,
            "route_predicate_profile_sha256": route_predicate_profile_sha256,
            "route_constraint_sha256": route_constraint_sha256,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "request_material_sha256": hashlib.sha256(material).hexdigest(),
            "request_material_utf8_bytes": len(material),
            "request_token_plan": plan,
            "exact_pricing": exact,
            "pricing_schedule": schedule,
            "provider_capped_subset": caps,
            "components": components,
            "reserved_cost_usd_exact": total,
        }
        values["reservation_sha256"] = _hash(values)
        return cls.model_validate(values)

    @model_validator(mode="after")
    def reservation_is_complete_and_self_hashed(self) -> Self:
        plan = _detach(self.request_token_plan, RequestTokenPlan)
        if (
            len(plan.route_intersection.routes) != 1
            or plan.route_intersection.routes[0].endpoint_snapshot_sha256
            != self.endpoint_snapshot_sha256
        ):
            raise ValueError("cost reservation snapshot differs from its token-plan route")
        caps = project_route_reservation_provider_caps(
            self.exact_pricing, schedule=self.pricing_schedule
        )
        components, total = _project_components(
            policy=self.policy,
            plan=plan,
            pricing=self.exact_pricing,
            schedule=self.pricing_schedule,
            request_bytes=self.request_material_utf8_bytes,
            caps=caps,
        )
        if self.provider_capped_subset != caps or self.components != components:
            raise ValueError("cost reservation component or provider-cap inventory is inconsistent")
        if self.reserved_cost_usd_exact != total:
            raise ValueError("cost reservation total is inconsistent")
        _require_hash(self, "reservation_sha256")
        return self


class RouteCostReservationPlanningEnvelope(_StrictModel):
    """Conservative task planning only: no invented request or dispatch authority.

    The exact request must independently fit these capacities and use the same
    complete route-pricing basis before claiming a durable portfolio slot.
    """

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["NONAUTHORIZING_COST_PLANNING"] = "NONAUTHORIZING_COST_PLANNING"
    policy: RouteCostReservationPolicy
    selection_plan_sha256: str = Field(pattern=_HASH)
    route_predicate_profile_sha256: str = Field(pattern=_HASH)
    route_constraint_sha256: str = Field(pattern=_HASH)
    route: EndpointRouteTokenCapacity
    maximum_request_bytes: int = Field(gt=0, le=_MAX_REQUEST_BYTES)
    maximum_prompt_tokens: int = Field(gt=0, le=2**31 - 1)
    maximum_completion_tokens: int = Field(gt=0, le=2**31 - 1)
    exact_pricing: tuple[ExactRoutePrice, ...] = Field(min_length=2, max_length=8)
    pricing_schedule: ExactRoutePricingSchedule | None = None
    provider_capped_subset: tuple[ProviderPriceCap, ...] = Field(min_length=2, max_length=4)
    components: tuple[RouteCostReservationComponent, ...] = Field(min_length=2, max_length=8)
    reserved_cost_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    planning_sha256: str = Field(pattern=_HASH)

    @classmethod
    def build(
        cls,
        *,
        policy: RouteCostReservationPolicy,
        selection_plan_sha256: str,
        route_predicate_profile_sha256: str,
        route_constraint_sha256: str,
        route: EndpointRouteTokenCapacity,
        maximum_request_bytes: int,
        maximum_prompt_tokens: int,
        maximum_completion_tokens: int,
        pricing: Mapping[str, str],
        pricing_schedule: ExactRoutePricingSchedule | None = None,
    ) -> Self:
        policy = _detach(policy, RouteCostReservationPolicy)
        route = _detach(route, EndpointRouteTokenCapacity)
        exact = normalize_exact_route_pricing(pricing)
        schedule = (
            None
            if pricing_schedule is None
            else _detach(pricing_schedule, ExactRoutePricingSchedule)
        )
        caps = project_route_reservation_provider_caps(exact, schedule=schedule)
        components, total = _project_bounded_components(
            policy=policy,
            route=route,
            request_bytes=maximum_request_bytes,
            prompt_tokens=maximum_prompt_tokens,
            completion_tokens=maximum_completion_tokens,
            pricing=exact,
            schedule=schedule,
            caps=caps,
        )
        values = {
            "schema_version": "1.0",
            "status": "NONAUTHORIZING_COST_PLANNING",
            "policy": policy,
            "selection_plan_sha256": selection_plan_sha256,
            "route_predicate_profile_sha256": route_predicate_profile_sha256,
            "route_constraint_sha256": route_constraint_sha256,
            "route": route,
            "maximum_request_bytes": maximum_request_bytes,
            "maximum_prompt_tokens": maximum_prompt_tokens,
            "maximum_completion_tokens": maximum_completion_tokens,
            "exact_pricing": exact,
            "pricing_schedule": schedule,
            "provider_capped_subset": caps,
            "components": components,
            "reserved_cost_usd_exact": total,
        }
        values["planning_sha256"] = _hash(values)
        return cls.model_validate(values)

    @model_validator(mode="after")
    def planning_is_complete_and_self_hashed(self) -> Self:
        if self.maximum_request_bytes > self.maximum_prompt_tokens:
            raise ValueError("planning prompt envelope does not cover maximum request bytes")
        caps = project_route_reservation_provider_caps(
            self.exact_pricing, schedule=self.pricing_schedule
        )
        components, total = _project_bounded_components(
            policy=self.policy,
            route=self.route,
            request_bytes=self.maximum_request_bytes,
            prompt_tokens=self.maximum_prompt_tokens,
            completion_tokens=self.maximum_completion_tokens,
            pricing=self.exact_pricing,
            schedule=self.pricing_schedule,
            caps=caps,
        )
        if (
            self.provider_capped_subset != caps
            or self.components != components
            or self.reserved_cost_usd_exact != total
        ):
            raise ValueError("planning reservation components or total are inconsistent")
        _require_hash(self, "planning_sha256")
        return self


class OperatorRouteCostAttemptEvidence(_StrictModel):
    """Nonauthorizing per-attempt reservation and exact durable billing observation."""

    schema_version: Literal["1.0"] = "1.0"
    reservation: ExactRouteCostReservation
    attempt_index: int = Field(ge=1, le=32)
    attempt_request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    ledger_reservation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    ledger_entry_sha256: str = Field(pattern=_HASH)
    ledger_status: CostEntryStatus
    reserved_cost_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    actual_billed_cost_usd_exact: str | None = Field(default=None, pattern=_MONEY, max_length=49)
    accounted_cost_usd_exact: str = Field(pattern=_MONEY, max_length=49)
    evidence_sha256: str = Field(pattern=_HASH)

    @classmethod
    def from_entry(
        cls, *, reservation: ExactRouteCostReservation, attempt_index: int, entry: CostEntry
    ) -> Self:
        if type(entry) is not CostEntry:
            raise RouteCostReservationError("operator cost attempt requires an exact ledger entry")
        current = _detach(reservation, ExactRouteCostReservation)
        values = {
            "schema_version": "1.0",
            "reservation": current,
            "attempt_index": attempt_index,
            "attempt_request_id": entry.request_id,
            "ledger_reservation_id": entry.reservation_id,
            "ledger_entry_sha256": cost_entry_sha256(entry),
            "ledger_status": entry.status,
            "reserved_cost_usd_exact": _decimal_text(entry.reserved_usd),
            "actual_billed_cost_usd_exact": (
                _decimal_text(entry.actual_cost_usd) if entry.actual_cost_usd is not None else None
            ),
            "accounted_cost_usd_exact": _decimal_text(entry.accounted_cost_usd),
        }
        return cls.model_validate({**values, "evidence_sha256": _hash(values)})

    @model_validator(mode="after")
    def attempt_conserves_exact_ledger_cost(self) -> Self:
        logical_id = self.reservation.request_token_plan.request_id
        expected_id = (
            logical_id if self.attempt_index == 1 else f"{logical_id}:attempt:{self.attempt_index}"
        )
        reserved = Decimal(self.reserved_cost_usd_exact)
        accounted = Decimal(self.accounted_cost_usd_exact)
        actual = (
            Decimal(self.actual_billed_cost_usd_exact)
            if self.actual_billed_cost_usd_exact is not None
            else None
        )
        if (
            self.attempt_request_id != expected_id
            or reserved < Decimal(self.reservation.reserved_cost_usd_exact)
            or reserved > Decimal(self.reservation.policy.ledger_ceiling_usd_exact)
        ):
            raise ValueError("operator cost attempt differs from its request or reservation")
        if self.ledger_status is CostEntryStatus.RELEASED:
            consistent = actual is None and accounted == 0
        elif self.ledger_status is CostEntryStatus.UNCERTAIN_ACCOUNTED:
            consistent = actual is None and accounted == reserved
        elif self.ledger_status is CostEntryStatus.RECONCILED:
            consistent = actual is not None and actual == accounted and actual <= reserved
        elif self.ledger_status is CostEntryStatus.RESERVATION_OVERRUN:
            consistent = actual is not None and actual == accounted and actual > reserved
        else:
            consistent = False
        if not consistent:
            raise ValueError("operator cost attempt cannot erase liability or invent settlement")
        _require_hash(self, "evidence_sha256")
        return self


def operator_cost_attempts_from_usage(
    usage: UsageRecord,
) -> tuple[OperatorRouteCostAttemptEvidence, ...]:
    """Validate ordered cost attempts without promoting serialized data to ledger authority."""

    keys = {"operator_cost_attempts", "operator_cost_attempt_sha256s", "cost_enforcement_basis"}
    present = keys.intersection(usage.routing)
    if not present:
        return ()
    raw = usage.routing.get("operator_cost_attempts")
    hashes = usage.routing.get("operator_cost_attempt_sha256s")
    if (
        present != keys
        or type(raw) is not list
        or not 1 <= len(raw) <= 32
        or len(raw) != usage.attempts
        or type(hashes) is not list
        or usage.routing["cost_enforcement_basis"] != "MMAUDIT_OPERATOR_RESERVE_THEN_RECONCILE_V1"
    ):
        raise ValueError("usage operator cost-attempt inventory is incomplete")
    attempts = tuple(
        OperatorRouteCostAttemptEvidence.model_validate_json(_canonical(value), strict=True)
        for value in raw
    )
    plan = RequestTokenPlan.model_validate_json(
        _canonical(usage.routing.get("request_token_plan")), strict=True
    )
    if hashes != [item.evidence_sha256 for item in attempts] or any(
        item.attempt_index != index
        or item.reservation.request_token_plan != plan
        or item.reservation.request_material_sha256 != usage.request_body_sha256
        or item.reservation.request_token_plan.route_intersection.exact_model_ids
        != (usage.requested_model,)
        or item.reservation.request_token_plan.request_id != usage.request_id
        or item.reservation.request_token_plan.role != usage.role
        or item.reservation.reservation_sha256 != attempts[0].reservation.reservation_sha256
        for index, item in enumerate(attempts, start=1)
    ):
        raise ValueError("usage operator cost attempts differ from exact request custody")
    with localcontext() as context:
        context.prec = 160
        accounted = sum((Decimal(item.accounted_cost_usd_exact) for item in attempts), Decimal(0))
    if (
        usage.accounted_cost_usd_exact is None
        or accounted != Decimal(usage.accounted_cost_usd_exact)
        or attempts[-1].actual_billed_cost_usd_exact
        != (
            _decimal_text(Decimal(usage.reported_cost_usd_exact))
            if usage.reported_cost_usd_exact is not None
            else None
        )
        or (
            usage.status == "success"
            and any(item.ledger_status is not CostEntryStatus.RECONCILED for item in attempts)
        )
    ):
        raise ValueError("usage operator costs differ from the durable per-attempt accounting")
    return attempts


def project_route_reservation_provider_caps(
    pricing: Sequence[ExactRoutePrice], *, schedule: ExactRoutePricingSchedule | None = None
) -> tuple[ProviderPriceCap, ...]:
    """Cap only the explicitly identified capped subset; retain the rest separately."""

    maximum = _maximum_pricing(tuple(pricing), schedule)
    return _project_provider_capped_subset(maximum)


def require_route_cost_reservation_request(
    reservation: ExactRouteCostReservation,
    *,
    request_material: str,
    selection_plan_sha256: str,
    route_predicate_profile_sha256: str,
    route_constraint_sha256: str,
    endpoint_snapshot_sha256: str,
) -> ExactRouteCostReservation:
    """Revalidate the complete contract and caller-owned bindings before reserving."""

    current = _detach(reservation, ExactRouteCostReservation)
    if (
        current.selection_plan_sha256 != selection_plan_sha256
        or current.route_predicate_profile_sha256 != route_predicate_profile_sha256
        or current.route_constraint_sha256 != route_constraint_sha256
        or current.endpoint_snapshot_sha256 != endpoint_snapshot_sha256
    ):
        raise RouteCostReservationError("cost reservation differs from the selected route bindings")
    raw = _require_request_shape(
        request_material,
        policy=current.policy,
        plan=current.request_token_plan,
        caps=current.provider_capped_subset,
    )
    if (
        len(raw) != current.request_material_utf8_bytes
        or hashlib.sha256(raw).hexdigest() != current.request_material_sha256
    ):
        raise RouteCostReservationError("cost reservation differs from the exact request material")
    return current


def route_cost_reservation_pricing_sha256(
    reservation: ExactRouteCostReservation | RouteCostReservationPlanningEnvelope,
) -> str:
    """Bind complete route prices and policy without request IDs, units or budget position.

    This is pricing custody, not a request authorization. The separate reservation
    hash still binds every request byte, token-plan field and metered-unit ceiling.
    """

    current: ExactRouteCostReservation | RouteCostReservationPlanningEnvelope
    if type(reservation) is RouteCostReservationPlanningEnvelope:
        current = _detach(reservation, RouteCostReservationPlanningEnvelope)
        route = current.route
    else:
        exact_request = _detach(reservation, ExactRouteCostReservation)
        current = exact_request
        route = exact_request.request_token_plan.route_intersection.routes[0]
    return _hash(
        {
            "domain": "mmaudit.operator-reservation-route-pricing.v1",
            "policy": current.policy,
            "selection_plan_sha256": current.selection_plan_sha256,
            "route_predicate_profile_sha256": current.route_predicate_profile_sha256,
            "route_constraint_sha256": current.route_constraint_sha256,
            "endpoint_snapshot_sha256": route.endpoint_snapshot_sha256,
            "exact_model_id": route.exact_model_id,
            "provider_endpoint": route.provider_endpoint,
            "exact_pricing": current.exact_pricing,
            "pricing_schedule": current.pricing_schedule,
            "provider_capped_subset": current.provider_capped_subset,
            "components": tuple(
                item.model_dump(mode="json", exclude={"maximum_units"})
                for item in current.components
            ),
        }
    )


def _maximum_pricing(
    pricing: tuple[ExactRoutePrice, ...], schedule: ExactRoutePricingSchedule | None
) -> tuple[ExactRoutePrice, ...]:
    if type(pricing) is not tuple or any(type(item) is not ExactRoutePrice for item in pricing):
        raise RouteCostReservationError("cost reservation pricing requires exact typed components")
    canonical = normalize_exact_route_pricing(
        {item.component.value: item.unit_price for item in pricing}
    )
    if canonical != pricing:
        raise RouteCostReservationError("cost reservation pricing is duplicate or noncanonical")
    if schedule is None:
        return canonical
    schedule = _detach(schedule, ExactRoutePricingSchedule)
    if schedule.base_pricing != pricing:
        raise RouteCostReservationError("cost reservation tier schedule differs from base pricing")
    return schedule.maximum_pricing


def _project_components(
    *,
    policy: RouteCostReservationPolicy,
    plan: RequestTokenPlan,
    pricing: tuple[ExactRoutePrice, ...],
    schedule: ExactRoutePricingSchedule | None,
    request_bytes: int,
    caps: tuple[ProviderPriceCap, ...],
) -> tuple[tuple[RouteCostReservationComponent, ...], str]:
    routes = plan.route_intersection.routes
    if len(routes) != 1:
        raise RouteCostReservationError("cost reservation requires one bounded exact request route")
    return _project_bounded_components(
        policy=policy,
        route=routes[0],
        request_bytes=request_bytes,
        prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        completion_tokens=plan.requested_completion_tokens,
        pricing=pricing,
        schedule=schedule,
        caps=caps,
    )


def project_route_reserved_rates(
    *,
    policy: RouteCostReservationPolicy,
    pricing: Sequence[ExactRoutePrice],
    schedule: ExactRoutePricingSchedule | None = None,
) -> tuple[RouteCostReservationRate, ...]:
    """Project complete base/tier rates without inventing request or unit evidence."""

    policy = _detach(policy, RouteCostReservationPolicy)
    maximum = _maximum_pricing(tuple(pricing), schedule)
    caps = project_route_reservation_provider_caps(maximum)
    with localcontext() as context:
        context.prec = 160
        capped_rates = {
            item.component.value: (
                Decimal(str(item.value))
                / (1_000_000 if item.component.value in {"prompt", "completion"} else 1)
            ).quantize(_RATE_QUANTUM, rounding=ROUND_CEILING)
            for item in caps
        }
        rates = []
        for item in maximum:
            field = item.component.value
            observed = Decimal(item.unit_price)
            if field in capped_rates:
                rate = capped_rates[field]
                basis = ReservationRateBasis.PROVIDER_CAPPED
            else:
                reference = (
                    capped_rates["prompt"]
                    if field in {"input_cache_read", "input_cache_write"}
                    else capped_rates["completion"]
                    if field == "internal_reasoning"
                    else Decimal(0)
                )
                rate = max(observed, reference) * Decimal(policy.uncappable_rate_multiplier)
                basis = ReservationRateBasis.OPERATOR_RESERVED
            rates.append(
                RouteCostReservationRate(
                    component=item.component,
                    maximum_observed_unit_price_usd_exact=item.unit_price,
                    reserved_unit_price_usd_exact=_decimal_text(rate),
                    rate_basis=basis,
                )
            )
    return tuple(rates)


def _project_bounded_components(
    *,
    policy: RouteCostReservationPolicy,
    route: EndpointRouteTokenCapacity,
    request_bytes: int,
    prompt_tokens: int,
    completion_tokens: int,
    pricing: tuple[ExactRoutePrice, ...],
    schedule: ExactRoutePricingSchedule | None,
    caps: tuple[ProviderPriceCap, ...],
) -> tuple[tuple[RouteCostReservationComponent, ...], str]:
    if (
        any(
            type(value) is not int or value <= 0
            for value in (request_bytes, prompt_tokens, completion_tokens)
        )
        or request_bytes > policy.maximum_request_bytes
    ):
        raise RouteCostReservationError("cost reservation requires bounded exact request units")
    rates = project_route_reserved_rates(policy=policy, pricing=pricing, schedule=schedule)
    if caps != project_route_reservation_provider_caps(pricing, schedule=schedule):
        raise RouteCostReservationError("cost reservation capped subset differs from pricing")
    prompt_units = max(request_bytes, prompt_tokens)
    if (
        prompt_units > route.max_prompt_tokens
        or completion_tokens > route.max_completion_tokens
        or prompt_units + completion_tokens > route.context_tokens
    ):
        raise RouteCostReservationError("cost reservation request exceeds endpoint capacity")
    # A separate reasoning price has no request-local hard cap under effort=high.
    # Reserve the full metadata completion capacity, not just the planned reason reserve.
    units = {
        "prompt": prompt_units,
        "input_cache_read": prompt_units,
        "input_cache_write": prompt_units,
        "completion": completion_tokens,
        "internal_reasoning": route.max_completion_tokens,
        "image": 0,
        "web_search": 0,
        "request": 1,
    }
    with localcontext() as context:
        context.prec = 160
        components = []
        total = Decimal(0)
        for item in rates:
            field = item.component.value
            total += Decimal(item.reserved_unit_price_usd_exact) * units[field]
            components.append(
                RouteCostReservationComponent(
                    **item.model_dump(mode="python"),
                    maximum_units=units[field],
                )
            )
        total = total.quantize(_USD_QUANTUM, rounding=ROUND_CEILING)
        if not 0 < total <= Decimal(policy.ledger_ceiling_usd_exact):
            raise RouteCostReservationError(
                "cost reservation is zero or exceeds the operator ceiling"
            )
    return tuple(components), _decimal_text(total)


def _require_request_shape(
    material: str,
    *,
    policy: RouteCostReservationPolicy,
    plan: RequestTokenPlan,
    caps: tuple[ProviderPriceCap, ...],
) -> bytes:
    if type(material) is not str or not 0 < len(material) <= policy.maximum_request_bytes:
        raise RouteCostReservationError(
            "cost reservation request material is unavailable or oversized"
        )
    try:
        raw = material.encode("utf-8")
        body = json.loads(raw)
        canonical = _canonical(body)
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise RouteCostReservationError(
            "cost reservation request is not bounded canonical JSON"
        ) from exc
    if len(raw) > policy.maximum_request_bytes or raw != canonical or type(body) is not dict:
        raise RouteCostReservationError("cost reservation request is not exact canonical JSON")
    routes = plan.route_intersection.routes
    required = _REQUEST_FIELDS - {"metadata"}
    if len(routes) != 1 or not required <= body.keys() <= _REQUEST_FIELDS:
        raise RouteCostReservationError("cost reservation request shape is unsupported")
    route = routes[0]
    messages = body["messages"]
    provider = body["provider"]
    expected_provider = {
        "only": [route.provider_endpoint],
        "allow_fallbacks": False,
        "data_collection": "deny",
        "require_parameters": True,
        "zdr": True,
        "max_price": {item.component.value: item.value for item in caps},
    }
    expected_wire = (
        plan.wire_max_tokens
        if plan.wire_max_tokens is not None
        else plan.requested_completion_tokens
    )
    response = body["response_format"]
    metadata = body.get("metadata", {})
    if (
        body["model"] != route.exact_model_id
        or type(body["max_tokens"]) is not int
        or body["max_tokens"] != expected_wire
        or body["stream"] is not False
        or type(body["temperature"]) is not int
        or body["temperature"] != 0
        or type(messages) is not list
        or len(messages) != 2
        or any(
            type(message) is not dict
            or set(message) != {"role", "content"}
            or type(message["content"]) is not str
            for message in messages
        )
        or [message["role"] for message in messages] != ["system", "user"]
        or type(provider) is not dict
        or _canonical(provider) != _canonical(expected_provider)
        or type(response) is not dict
        or set(response) != {"type", "json_schema"}
        or response["type"] != "json_schema"
        or type(response["json_schema"]) is not dict
        or set(response["json_schema"]) != {"name", "schema", "strict"}
        or response["json_schema"]["strict"] is not True
        or type(response["json_schema"]["name"]) is not str
        or not response["json_schema"]["name"]
        or type(response["json_schema"]["schema"]) is not dict
        or type(metadata) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in metadata.items())
        or type(body["reasoning"]) is not dict
        or _canonical(body["reasoning"]) != _canonical({"effort": "high", "exclude": False})
    ):
        raise RouteCostReservationError(
            "cost reservation request violates its text/native/route envelope"
        )
    return raw


def _detach[T: BaseModel](value: BaseModel, expected: type[T]) -> T:
    if type(value) is not expected:
        raise RouteCostReservationError("cost reservation input has the wrong exact type")
    try:
        with localcontext() as context:
            context.prec = 160
            rebuilt = expected.model_validate_json(value.model_dump_json(), strict=True)
    except (ValueError, TypeError, AttributeError) as exc:
        raise RouteCostReservationError(
            "cost reservation input failed detached validation"
        ) from exc
    if rebuilt != value:
        raise RouteCostReservationError("cost reservation input changed across validation")
    return rebuilt


def _decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError("cost reservation JSON contains an unsupported value")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_hash(model: BaseModel, field: str) -> None:
    if getattr(model, field) != _hash(model.model_dump(mode="json", exclude={field})):
        raise ValueError("cost reservation self-hash is inconsistent")
