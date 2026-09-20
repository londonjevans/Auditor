"""Exact historical billing exceptions; never settlement or a future-entry waiver."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class LegacyUncertainCostEntry(BaseModel):
    """Bind every immutable identity and retained liability field of one approved row."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )

    request_id: str = Field(
        pattern=r"^authrunner\.smoke\.(?:r17\.judge\.replay|r2\.candidate\.primary):[0-9a-f]{64}$"
    )
    reservation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    created_at: str = Field(min_length=25, max_length=32)
    updated_at: str = Field(min_length=25, max_length=32)
    status: Literal["uncertain_accounted"] = "uncertain_accounted"
    reserved_usd_exact: Literal["0.18105", "0.05225616"]
    accounted_cost_usd_exact: Literal["0.18105", "0.05225616"]
    actual_cost_usd: None = None
    release_reason: None = None

    @field_validator("created_at", "updated_at")
    @classmethod
    def timestamp_is_canonical_utc(cls, value: str) -> str:
        observed = datetime.fromisoformat(value)
        if (
            observed.tzinfo is None
            or observed.utcoffset() != timedelta(0)
            or observed.isoformat() != value
        ):
            raise ValueError("legacy allowance timestamps must be canonical timezone-aware UTC")
        return value

    @model_validator(mode="after")
    def only_the_two_pre_policy_liabilities(self) -> Self:
        expected = (
            "0.18105"
            if self.request_id.startswith("authrunner.smoke.r17.judge.replay:")
            else "0.05225616"
        )
        if self.reserved_usd_exact != expected or self.accounted_cost_usd_exact != expected:
            raise ValueError("legacy allowance must retain the exact approved liability")
        created, updated = (
            datetime.fromisoformat(value) for value in (self.created_at, self.updated_at)
        )
        if not created <= updated < datetime(2026, 9, 9, tzinfo=UTC):
            raise ValueError("legacy allowance must identify a pre-policy uncertain entry")
        return self


class LegacyUncertainCostAllowance(BaseModel):
    """Explicit operator relaxation for two exact rows, with no general carry mechanism."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, revalidate_instances="always"
    )

    schema_version: Literal["1.0"] = "1.0"
    operator_decision_id: Literal["OP-COSTLEGACY-2026-09-11"] = "OP-COSTLEGACY-2026-09-11"
    entries: tuple[LegacyUncertainCostEntry, LegacyUncertainCostEntry]
    allowance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(cls, entries: tuple[LegacyUncertainCostEntry, LegacyUncertainCostEntry]) -> Self:
        values = {
            "schema_version": "1.0",
            "operator_decision_id": "OP-COSTLEGACY-2026-09-11",
            "entries": [entry.model_dump(mode="json") for entry in entries],
        }
        digest = hashlib.sha256(
            json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        return cls(entries=entries, allowance_sha256=digest)

    @model_validator(mode="after")
    def exact_ordered_pair_and_hash(self) -> Self:
        if (
            tuple(entry.request_id.partition(":")[0] for entry in self.entries)
            != (
                "authrunner.smoke.r17.judge.replay",
                "authrunner.smoke.r2.candidate.primary",
            )
            or len({entry.reservation_id for entry in self.entries}) != 2
        ):
            raise ValueError("legacy allowance requires exactly the two distinct approved rows")
        values = self.model_dump(mode="json", exclude={"allowance_sha256"})
        expected = hashlib.sha256(
            json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        if self.allowance_sha256 != expected:
            raise ValueError("legacy allowance hash does not bind its exact historical rows")
        return self
