"""Non-qualifying development reservations using the existing cumulative ledger."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from mmaudit.models.development_costs import (
    DevelopmentCostError,
    DevelopmentCostEstimate,
    DevelopmentCostPolicy,
    estimate_development_request,
)
from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.orchestration.cost_ledger import (
    MAX_UNCERTAIN_RESERVATION_ALLOWANCES,
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
    CostReservation,
    CostReservationStateError,
    ReleaseReason,
)

_DEVELOPMENT_LEDGER_REQUEST_ID = re.compile(
    r"dev-estimate-[0-9a-f]{64}:(?:[1-9]|[12][0-9]|3[0-2])\Z"
)


def development_uncertain_reservations(
    *, policy: DevelopmentCostPolicy, snapshot: CostLedgerSnapshot
) -> tuple[CostReservation, ...]:
    """Select estimated liabilities only; the ledger must revalidate these under lock."""

    if policy.uncertain_cost_policy != "CARRY_RESERVED_ESTIMATE":
        return ()
    allowances = tuple(
        CostReservation(entry.request_id, entry.reservation_id, entry.reserved_usd)
        for entry in snapshot.entries
        if entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        and _DEVELOPMENT_LEDGER_REQUEST_ID.fullmatch(entry.request_id)
        and entry.actual_cost_usd is None
        and entry.accounted_cost_usd == entry.reserved_usd
    )
    if len(allowances) > MAX_UNCERTAIN_RESERVATION_ALLOWANCES:
        raise DevelopmentCostError("development uncertain history exceeds its bounded allowance")
    return allowances


@dataclass(frozen=True)
class DevelopmentReservation:
    """An estimated reservation, deliberately not an EndpointRequestCostBound."""

    estimate: DevelopmentCostEstimate
    attempt: int
    ledger_reservation: CostReservation


class DevelopmentCostUncertainError(CostReservationStateError):
    """An unknown cost was fully accounted; the current attempt must remain incomplete."""


class DevelopmentBudgetSession:
    """Serialize development attempts and preserve every known or uncertain charge.

    This adapter neither creates a ledger nor sends a request. The ledger's cap is
    an accounting target for these estimates, not a provider-enforced guarantee.
    A future transport adapter must bind dispatch to the estimated request bytes.
    """

    def __init__(self, *, policy: DevelopmentCostPolicy, ledger: AtomicCostLedger) -> None:
        if type(policy) is not DevelopmentCostPolicy or type(ledger) is not AtomicCostLedger:
            raise DevelopmentCostError(
                "development accounting requires exact policy and ledger types"
            )
        self._policy = DevelopmentCostPolicy.model_validate_json(policy.model_dump_json())
        self._ledger = ledger
        if ledger.snapshot().cap_usd != self._policy.total_budget_usd:
            raise DevelopmentCostError(
                "development budget target must match the cumulative ledger cap"
            )
        self._issued: dict[str, DevelopmentReservation] = {}

    def reserve(
        self,
        *,
        endpoint_snapshot: OpenRouterEndpointSnapshotEvidence,
        request_id: str,
        request_body: dict[str, Any],
        attempt: int = 1,
    ) -> DevelopmentReservation:
        """Recompute the estimate before an atomic, sequential, retry-bounded hold."""

        if type(attempt) is not int or not 1 <= attempt <= self._policy.maximum_attempts:
            raise DevelopmentCostError("development attempt exceeds its explicit retry policy")
        estimate = estimate_development_request(
            policy=self._policy,
            endpoint_snapshot=endpoint_snapshot,
            request_id=request_id,
            request_body=request_body,
        )
        if not estimate.within_estimated_budget:
            raise CostBudgetExceededError(
                "development estimate exceeds its requested budget targets"
            )
        prefix = "dev-estimate-" + hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        snapshot = self._ledger.snapshot()
        prior_ids = {entry.request_id for entry in snapshot.entries}
        if any(f"{prefix}:{prior}" not in prior_ids for prior in range(1, attempt)):
            raise DevelopmentCostError("development retry is missing its prior attempt")
        reservation = self._ledger.reserve(
            f"{prefix}:{attempt}",
            estimate.estimated_cost_per_attempt_usd,
            require_settled_prior_costs=True,
            allowed_uncertain_reservations=development_uncertain_reservations(
                policy=self._policy, snapshot=snapshot
            ),
        )
        result = DevelopmentReservation(estimate, attempt, reservation)
        self._issued[reservation.reservation_id] = result
        return result

    def reconcile(
        self, reservation: DevelopmentReservation, *, actual_cost_usd: Decimal | None
    ) -> CostEntry:
        """Persist spend first; unknown costs never become a successful current attempt."""

        if (
            type(reservation) is not DevelopmentReservation
            or self._issued.get(reservation.ledger_reservation.reservation_id) != reservation
        ):
            raise CostReservationStateError("development reservation is unknown or changed")
        if actual_cost_usd is not None and type(actual_cost_usd) is not Decimal:
            raise DevelopmentCostError("actual development cost requires an exact Decimal")
        entry = self._ledger.reconcile(reservation.ledger_reservation, actual_cost_usd)
        if actual_cost_usd is None:
            raise DevelopmentCostUncertainError(
                "unknown development cost accounted at its estimate; current attempt is incomplete"
            )
        return entry

    def release_before_dispatch(self, reservation: DevelopmentReservation) -> CostEntry:
        """Release only a caller-proven unused hold; transport owns the dispatch boundary."""

        if (
            type(reservation) is not DevelopmentReservation
            or self._issued.get(reservation.ledger_reservation.reservation_id) != reservation
        ):
            raise CostReservationStateError("development reservation is unknown or changed")
        return self._ledger.release(
            reservation.ledger_reservation, reason=ReleaseReason.FAILED_BEFORE_SEND
        )
