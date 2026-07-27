"""Hard model-call budget accounting."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass


class BudgetExhaustedError(RuntimeError):
    """Raised before a request that could exceed the hard run budget."""


@dataclass(frozen=True)
class Reservation:
    identifier: str
    estimated_cost_usd: float


class BudgetManager:
    """Reserve conservative request costs and reconcile actual usage."""

    def __init__(
        self,
        *,
        total_usd: float,
        max_output_tokens: int,
        conservative_usd_per_million_tokens: float,
        max_requests_per_agent: int,
    ) -> None:
        self.total_usd = total_usd
        self.max_output_tokens = max_output_tokens
        self.conservative_rate = conservative_usd_per_million_tokens
        self.max_requests_per_agent = max_requests_per_agent
        self._spent = 0.0
        self._reserved: dict[str, float] = {}
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

    async def reserve(self, identifier: str, role: str, prompt: str) -> Reservation:
        estimated = self.estimate_request_cost(prompt)
        async with self._lock:
            count = self._role_requests.get(role, 0)
            if count >= self.max_requests_per_agent:
                raise BudgetExhaustedError(f"request limit reached for role {role}")
            if estimated > self.total_usd - self._spent - self.reserved_usd + 1e-12:
                raise BudgetExhaustedError(
                    f"request for {role} could cost ${estimated:.4f}, "
                    f"but only ${self.remaining_usd:.4f} remains"
                )
            self._reserved[identifier] = estimated
            self._role_requests[role] = count + 1
        return Reservation(identifier=identifier, estimated_cost_usd=estimated)

    async def reconcile(self, reservation: Reservation, actual_cost_usd: float | None) -> float:
        """Replace a reservation with reported cost, or its conservative estimate."""

        async with self._lock:
            estimated = self._reserved.pop(reservation.identifier, reservation.estimated_cost_usd)
            accounted = estimated if actual_cost_usd is None else max(0.0, actual_cost_usd)
            self._spent += accounted
            return accounted

    async def authorize_additional_request(self, role: str) -> None:
        """Count a repair request whose cost was included in an existing reservation."""

        async with self._lock:
            count = self._role_requests.get(role, 0)
            if count >= self.max_requests_per_agent:
                raise BudgetExhaustedError(f"request limit reached for role {role}")
            self._role_requests[role] = count + 1

    async def release(self, reservation: Reservation) -> None:
        async with self._lock:
            self._reserved.pop(reservation.identifier, None)
