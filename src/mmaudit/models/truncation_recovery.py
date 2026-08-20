"""Pure, non-dispatching plans for bounded recovery from truncated model output.

This module deliberately stops at deterministic planning.  Its artifacts cannot
authorize a provider call, grant review or coverage credit, complete a campaign,
or authorize a release.  Runtime and journal custody must be added separately.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
)
from enum import StrEnum
from itertools import islice
from typing import Any, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.models.schemas import StrictModel

TRUNCATION_RECOVERY_ALGORITHM_VERSION: Final = "mmaudit.truncation-recovery.v1"
TRUNCATION_RECOVERY_MAX_DEPTH: Final = 4
TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS: Final = 32
TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS: Final = 200
TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS: Final = 2_000_000
TRUNCATION_RECOVERY_MAX_USD_EXACT: Final = "250"
TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS: Final = 65_536
TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS: Final = 6

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SURFACE_ID_PATTERN = r"^model-surface:[0-9a-f]{64}$"
_CAMPAIGN_ID_PATTERN = r"^scheduler-campaign-[0-9a-f]{64}$"
_PASS_PLAN_ID_PATTERN = r"^scheduler-plan-[0-9a-f]{64}$"
_TASK_ID_PATTERN = r"^scheduler-task-[0-9a-f]{64}$"
_LOGICAL_REQUEST_ID_PATTERN = r"^scheduler-request-[0-9a-f]{64}$"
_RECOVERY_TASK_ID_PATTERN = r"^scheduler-recovery-task-[0-9a-f]{64}$"
_RECOVERY_REQUEST_ID_PATTERN = r"^scheduler-recovery-request-[0-9a-f]{64}$"
_PARENT_TASK_ID_PATTERN = r"^(?:scheduler-task|scheduler-recovery-task)-[0-9a-f]{64}$"
_PARENT_REQUEST_ID_PATTERN = r"^(?:scheduler-request|scheduler-recovery-request)-[0-9a-f]{64}$"
_USD_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?$"
_TOTAL_USD_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,12})(?:\.[0-9]{1,36})?$"
_MAX_SURFACES = 10_000
_MAX_RETAINED_RECORDS = 100_000
_MAX_COUNTER = 1_000_000_000
_MAX_TOTAL_RECOVERY_REQUESTS = _MAX_COUNTER + TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
_MAX_TOTAL_PROVIDER_ATTEMPTS = (2 * _MAX_COUNTER) + (
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS * TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS
)
_MAX_TOTAL_COMPLETION_TOKENS = (2 * _MAX_COUNTER) + (
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS * TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS
)
_EXACT_DECIMAL_CONTEXT = Context(
    prec=160,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[InvalidOperation, DivisionByZero, Overflow],
)


class TruncationRecoveryChannel(StrEnum):
    """Independently recoverable visible-output channels."""

    COVERAGE = "coverage"
    FINDINGS = "findings"
    SUMMARY = "summary"


TRUNCATION_RECOVERY_CHANNEL_ORDER: tuple[TruncationRecoveryChannel, ...] = tuple(
    TruncationRecoveryChannel
)


class TruncationRecoveryChannelState(StrEnum):
    """Parser-supplied disposition for one independently validated channel."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


class TruncationRecoveryDisposition(StrEnum):
    """Deterministic result of applying the frozen recovery ceilings."""

    PLANNED = "PLANNED"
    NO_REMAINING_WORK = "NO_REMAINING_WORK"
    IRREDUCIBLE_WORK = "IRREDUCIBLE_WORK"
    DEPTH_EXHAUSTED = "DEPTH_EXHAUSTED"
    REQUEST_EXHAUSTED = "REQUEST_EXHAUSTED"
    PROVIDER_ATTEMPT_EXHAUSTED = "PROVIDER_ATTEMPT_EXHAUSTED"
    TOKEN_EXHAUSTED = "TOKEN_EXHAUSTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class _NonAuthorizingRecoveryModel(StrictModel):
    """Literal-false authority surface shared by every durable recovery model."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    evidence_authority: Literal["comparison_required"] = "comparison_required"
    provider_dispatch_authorized: Literal[False] = False
    review_credit_authorized: Literal[False] = False
    coverage_credit_authorized: Literal[False] = False
    completion_authorized: Literal[False] = False
    release_authorized: Literal[False] = False


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported truncation recovery hash value: {type(value).__qualname__}")


def _model_sha256(model: StrictModel, *, exclude: set[str]) -> str:
    return _canonical_sha256(model.model_dump(mode="json", exclude=exclude))


def _bounded_tuple[ItemT](
    values: Iterable[ItemT],
    *,
    limit: int,
    label: str,
) -> tuple[ItemT, ...]:
    """Materialize at most ``limit + 1`` items from an untrusted iterable."""

    items = tuple(islice(iter(values), limit + 1))
    if len(items) > limit:
        raise ValueError(f"truncation recovery {label} exceeds its item limit")
    return items


def _canonical_surface_ids(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    items = _bounded_tuple(values, limit=_MAX_SURFACES, label=label)
    if any(
        not isinstance(item, str) or re.fullmatch(_SURFACE_ID_PATTERN, item) is None
        for item in items
    ):
        raise ValueError(f"truncation recovery {label} contains an invalid surface ID")
    if len(items) != len(set(items)):
        raise ValueError(f"truncation recovery {label} contains a duplicate surface ID")
    return tuple(sorted(items))


def _require_canonical_surface_ids(values: tuple[str, ...], *, label: str) -> None:
    if len(values) > _MAX_SURFACES or values != _canonical_surface_ids(values, label=label):
        raise ValueError(f"truncation recovery {label} must be bounded, unique, and sorted")


def _decimal_and_canonical_text(value: str, *, label: str) -> tuple[Decimal, str]:
    if not isinstance(value, str) or re.fullmatch(_USD_EXACT_PATTERN, value) is None:
        raise ValueError(f"truncation recovery {label} is not exact bounded USD text")
    try:
        amount = Decimal(value)
    except InvalidOperation:
        raise ValueError(f"truncation recovery {label} is invalid") from None
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"truncation recovery {label} is invalid")
    canonical = format(amount, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    if canonical in {"", "-0"}:
        canonical = "0"
    if value != canonical:
        raise ValueError(f"truncation recovery {label} is not canonical")
    return amount, canonical


def _exact_sum(values: Iterable[Decimal]) -> Decimal:
    context = _EXACT_DECIMAL_CONTEXT.copy()
    total = context.create_decimal(0)
    for value in values:
        total = context.add(total, value)
    return total


def _exact_product(value: Decimal, multiplier: int) -> Decimal:
    context = _EXACT_DECIMAL_CONTEXT.copy()
    return context.multiply(value, context.create_decimal(multiplier))


def _canonical_decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"", "-0"} else text


class TruncationRecoveryPolicy(_NonAuthorizingRecoveryModel):
    """Compiled ceilings; callers cannot relax any recovery bound."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-recovery.v1"] = "mmaudit.truncation-recovery.v1"
    partition_algorithm: Literal["SORTED_CONTIGUOUS_BINARY_V1"] = "SORTED_CONTIGUOUS_BINARY_V1"
    max_depth: Literal[4] = TRUNCATION_RECOVERY_MAX_DEPTH
    max_child_requests: Literal[32] = TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
    max_provider_attempts: Literal[200] = TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS
    max_completion_tokens: Literal[2_000_000] = TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS
    max_usd_exact: Literal["250"] = TRUNCATION_RECOVERY_MAX_USD_EXACT
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def frozen(cls) -> TruncationRecoveryPolicy:
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "algorithm_version": TRUNCATION_RECOVERY_ALGORITHM_VERSION,
            "partition_algorithm": "SORTED_CONTIGUOUS_BINARY_V1",
            "max_depth": TRUNCATION_RECOVERY_MAX_DEPTH,
            "max_child_requests": TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
            "max_provider_attempts": TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS,
            "max_completion_tokens": TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS,
            "max_usd_exact": TRUNCATION_RECOVERY_MAX_USD_EXACT,
        }
        return cls(**values, policy_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def policy_is_compiled_and_exact(self) -> Self:
        _decimal_and_canonical_text(self.max_usd_exact, label="maximum USD")
        if self.policy_sha256 != _model_sha256(self, exclude={"policy_sha256"}):
            raise ValueError("truncation recovery policy hash is inconsistent")
        return self


class TruncationRecoveryChannelBinding(_NonAuthorizingRecoveryModel):
    """Hash-only parser custody for one independently validated output channel."""

    schema_version: Literal["1.0"] = "1.0"
    channel: TruncationRecoveryChannel
    state: TruncationRecoveryChannelState
    retained_record_count: int = Field(ge=0, le=_MAX_RETAINED_RECORDS)
    retained_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        channel: TruncationRecoveryChannel,
        state: TruncationRecoveryChannelState,
        retained_record_count: int,
        retained_inventory_sha256: str,
    ) -> TruncationRecoveryChannelBinding:
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "channel": channel,
            "state": state,
            "retained_record_count": retained_record_count,
            "retained_inventory_sha256": retained_inventory_sha256,
        }
        return cls(**values, binding_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def channel_binding_is_bounded_and_exact(self) -> Self:
        if self.channel is TruncationRecoveryChannel.SUMMARY:
            if self.retained_record_count > 1:
                raise ValueError(
                    "truncation recovery summary channel can retain at most one record"
                )
            if self.state is TruncationRecoveryChannelState.COMPLETE and (
                self.retained_record_count != 1
            ):
                raise ValueError("complete truncation recovery summary requires one record")
            if self.state is TruncationRecoveryChannelState.INCOMPLETE and (
                self.retained_record_count != 0
            ):
                raise ValueError("incomplete truncation recovery summary cannot retain a fragment")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("truncation recovery channel binding hash is inconsistent")
        return self


class TruncationRecoveryParentBinding(_NonAuthorizingRecoveryModel):
    """Exact parent, parser projection, and requested-surface recovery root."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-recovery.v1"] = "mmaudit.truncation-recovery.v1"
    truncation_confirmed: Literal[True] = True
    campaign_id: str = Field(pattern=_CAMPAIGN_ID_PATTERN)
    pass_plan_id: str = Field(pattern=_PASS_PLAN_ID_PATTERN)
    parent_task_id: str = Field(pattern=_PARENT_TASK_ID_PATTERN)
    parent_logical_request_id: str = Field(pattern=_PARENT_REQUEST_ID_PATTERN)
    parent_task_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    truncation_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    requested_surface_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_depth: int = Field(ge=0, le=TRUNCATION_RECOVERY_MAX_DEPTH)
    parent_path: str = Field(pattern=r"^[01]{0,4}$")
    requested_surface_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_SURFACES,
    )
    retained_surface_ids: tuple[str, ...] = Field(max_length=_MAX_SURFACES)
    unfinished_surface_ids: tuple[str, ...] = Field(max_length=_MAX_SURFACES)
    channel_bindings: tuple[TruncationRecoveryChannelBinding, ...] = Field(
        min_length=len(TRUNCATION_RECOVERY_CHANNEL_ORDER),
        max_length=len(TRUNCATION_RECOVERY_CHANNEL_ORDER),
    )
    parent_binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        campaign_id: str,
        pass_plan_id: str,
        parent_task_id: str,
        parent_logical_request_id: str,
        parent_task_plan_sha256: str,
        parent_activation_sha256: str,
        provider_attempt_evidence_sha256: str,
        truncation_projection_sha256: str,
        requested_surface_manifest_sha256: str,
        requested_surface_ids: Iterable[str],
        retained_surface_ids: Iterable[str],
        channel_bindings: Iterable[TruncationRecoveryChannelBinding],
        current_depth: int = 0,
        parent_path: str = "",
    ) -> TruncationRecoveryParentBinding:
        requested = _canonical_surface_ids(requested_surface_ids, label="requested surfaces")
        retained = _canonical_surface_ids(retained_surface_ids, label="retained surfaces")
        retained_set = set(retained)
        unfinished = tuple(item for item in requested if item not in retained_set)
        materialized_channels = _bounded_tuple(
            channel_bindings,
            limit=len(TRUNCATION_RECOVERY_CHANNEL_ORDER),
            label="channel bindings",
        )
        if len(materialized_channels) != len(TRUNCATION_RECOVERY_CHANNEL_ORDER):
            raise ValueError("truncation recovery requires exactly three channel bindings")
        if any(
            type(item) is not TruncationRecoveryChannelBinding for item in materialized_channels
        ):
            raise ValueError("truncation recovery channel bindings must be exact models")
        channels = tuple(sorted(materialized_channels, key=lambda item: item.channel.value))
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "algorithm_version": TRUNCATION_RECOVERY_ALGORITHM_VERSION,
            "truncation_confirmed": True,
            "campaign_id": campaign_id,
            "pass_plan_id": pass_plan_id,
            "parent_task_id": parent_task_id,
            "parent_logical_request_id": parent_logical_request_id,
            "parent_task_plan_sha256": parent_task_plan_sha256,
            "parent_activation_sha256": parent_activation_sha256,
            "provider_attempt_evidence_sha256": provider_attempt_evidence_sha256,
            "truncation_projection_sha256": truncation_projection_sha256,
            "requested_surface_manifest_sha256": requested_surface_manifest_sha256,
            "current_depth": current_depth,
            "parent_path": parent_path,
            "requested_surface_ids": requested,
            "retained_surface_ids": retained,
            "unfinished_surface_ids": unfinished,
            "channel_bindings": channels,
        }
        return cls(**values, parent_binding_sha256=_canonical_sha256(values))

    @property
    def unresolved_channels(self) -> tuple[TruncationRecoveryChannel, ...]:
        """Return channels that did not independently validate as complete."""

        return tuple(
            item.channel
            for item in self.channel_bindings
            if item.state is not TruncationRecoveryChannelState.COMPLETE
        )

    @model_validator(mode="after")
    def parent_binding_is_conservative_and_exact(self) -> Self:
        _require_canonical_surface_ids(
            self.requested_surface_ids,
            label="requested surfaces",
        )
        _require_canonical_surface_ids(
            self.retained_surface_ids,
            label="retained surfaces",
        )
        _require_canonical_surface_ids(
            self.unfinished_surface_ids,
            label="unfinished surfaces",
        )
        requested = set(self.requested_surface_ids)
        retained = set(self.retained_surface_ids)
        if not retained <= requested:
            raise ValueError("truncation recovery retained an unrequested surface")
        expected_unfinished = tuple(
            item for item in self.requested_surface_ids if item not in retained
        )
        if self.unfinished_surface_ids != expected_unfinished:
            raise ValueError(
                "truncation recovery unfinished surfaces are not an exact set difference"
            )
        if len(self.parent_path) != self.current_depth:
            raise ValueError("truncation recovery parent path differs from its depth")
        expected_task_pattern = (
            _TASK_ID_PATTERN if self.current_depth == 0 else _RECOVERY_TASK_ID_PATTERN
        )
        expected_request_pattern = (
            _LOGICAL_REQUEST_ID_PATTERN if self.current_depth == 0 else _RECOVERY_REQUEST_ID_PATTERN
        )
        if (
            re.fullmatch(expected_task_pattern, self.parent_task_id) is None
            or re.fullmatch(
                expected_request_pattern,
                self.parent_logical_request_id,
            )
            is None
        ):
            raise ValueError("truncation recovery immediate-parent identity differs from depth")
        observed_channels = tuple(item.channel for item in self.channel_bindings)
        if observed_channels != TRUNCATION_RECOVERY_CHANNEL_ORDER:
            raise ValueError("truncation recovery channel bindings must be complete and ordered")
        coverage = self.channel_bindings[0]
        if coverage.retained_record_count != len(self.retained_surface_ids):
            raise ValueError("truncation recovery coverage count differs from retained surfaces")
        if coverage.state is TruncationRecoveryChannelState.COMPLETE and (
            self.unfinished_surface_ids
        ):
            raise ValueError("complete truncation recovery coverage leaves unfinished surfaces")
        if coverage.state is TruncationRecoveryChannelState.INCOMPLETE and (
            not self.unfinished_surface_ids
        ):
            raise ValueError("incomplete truncation recovery coverage has no unfinished surface")
        if self.parent_binding_sha256 != _model_sha256(
            self,
            exclude={"parent_binding_sha256"},
        ):
            raise ValueError("truncation recovery parent binding hash is inconsistent")
        return self


class TruncationRecoveryResourceBudget(_NonAuthorizingRecoveryModel):
    """Exact consumed parent resources plus one uniform child reservation."""

    schema_version: Literal["1.0"] = "1.0"
    campaign_cap_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    accounted_usd_before_parent_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    parent_accounted_cost_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    child_reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    recovery_requests_consumed: int = Field(ge=0, le=_MAX_COUNTER)
    provider_attempts_before_parent: int = Field(ge=0, le=_MAX_COUNTER)
    parent_provider_attempts: int = Field(ge=1, le=_MAX_COUNTER)
    child_provider_attempts: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    )
    completion_tokens_before_parent: int = Field(ge=0, le=_MAX_COUNTER)
    parent_completion_tokens: int = Field(ge=0, le=_MAX_COUNTER)
    child_completion_tokens: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
    )
    budget_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        campaign_cap_usd_exact: str,
        accounted_usd_before_parent_exact: str,
        parent_accounted_cost_usd_exact: str,
        child_reserved_usd_exact: str,
        recovery_requests_consumed: int,
        provider_attempts_before_parent: int,
        parent_provider_attempts: int,
        child_provider_attempts: int,
        completion_tokens_before_parent: int,
        parent_completion_tokens: int,
        child_completion_tokens: int,
    ) -> TruncationRecoveryResourceBudget:
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "campaign_cap_usd_exact": campaign_cap_usd_exact,
            "accounted_usd_before_parent_exact": accounted_usd_before_parent_exact,
            "parent_accounted_cost_usd_exact": parent_accounted_cost_usd_exact,
            "child_reserved_usd_exact": child_reserved_usd_exact,
            "recovery_requests_consumed": recovery_requests_consumed,
            "provider_attempts_before_parent": provider_attempts_before_parent,
            "parent_provider_attempts": parent_provider_attempts,
            "child_provider_attempts": child_provider_attempts,
            "completion_tokens_before_parent": completion_tokens_before_parent,
            "parent_completion_tokens": parent_completion_tokens,
            "child_completion_tokens": child_completion_tokens,
        }
        return cls(**values, budget_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def resources_are_exact_bounded_and_parent_inclusive(self) -> Self:
        cap, _ = _decimal_and_canonical_text(
            self.campaign_cap_usd_exact,
            label="campaign cap",
        )
        before, _ = _decimal_and_canonical_text(
            self.accounted_usd_before_parent_exact,
            label="accounted USD before parent",
        )
        parent, _ = _decimal_and_canonical_text(
            self.parent_accounted_cost_usd_exact,
            label="parent accounted USD",
        )
        child, _ = _decimal_and_canonical_text(
            self.child_reserved_usd_exact,
            label="child reserved USD",
        )
        hard_max = Decimal(TRUNCATION_RECOVERY_MAX_USD_EXACT)
        if cap <= 0 or cap > hard_max:
            raise ValueError("truncation recovery campaign cap exceeds the frozen ceiling")
        if child > hard_max:
            raise ValueError("truncation recovery child reservation exceeds the frozen ceiling")
        accounted = _canonical_decimal_text(_exact_sum((before, parent)))
        if re.fullmatch(_TOTAL_USD_EXACT_PATTERN, accounted) is None:
            raise ValueError("truncation recovery accounted USD exceeds evidence bounds")
        if self.budget_sha256 != _model_sha256(self, exclude={"budget_sha256"}):
            raise ValueError("truncation recovery resource budget hash is inconsistent")
        return self


class TruncationRecoveryChildPlan(_NonAuthorizingRecoveryModel):
    """One deterministic, non-dispatchable child-shard recipe."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-recovery.v1"] = "mmaudit.truncation-recovery.v1"
    campaign_id: str = Field(pattern=_CAMPAIGN_ID_PATTERN)
    pass_plan_id: str = Field(pattern=_PASS_PLAN_ID_PATTERN)
    parent_task_id: str = Field(pattern=_PARENT_TASK_ID_PATTERN)
    parent_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    truncation_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    requested_surface_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_unfinished_surface_count: int = Field(ge=2, le=_MAX_SURFACES)
    parent_unfinished_surface_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_depth: int = Field(ge=0, lt=TRUNCATION_RECOVERY_MAX_DEPTH)
    parent_path: str = Field(pattern=r"^[01]{0,3}$")
    depth: int = Field(ge=1, le=TRUNCATION_RECOVERY_MAX_DEPTH)
    path: str = Field(pattern=r"^[01]{1,4}$")
    ordinal: int = Field(ge=0, le=1)
    channel: TruncationRecoveryChannel
    surface_ids: tuple[str, ...] = Field(max_length=_MAX_SURFACES)
    reserved_provider_attempts: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    )
    reserved_completion_tokens: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
    )
    reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    child_task_id: str = Field(pattern=_RECOVERY_TASK_ID_PATTERN)
    child_logical_request_id: str = Field(pattern=_RECOVERY_REQUEST_ID_PATTERN)
    child_plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        parent: TruncationRecoveryParentBinding,
        policy: TruncationRecoveryPolicy,
        resources: TruncationRecoveryResourceBudget,
        ordinal: int,
        channel: TruncationRecoveryChannel,
        surface_ids: Iterable[str],
        path: str,
    ) -> TruncationRecoveryChildPlan:
        parent = TruncationRecoveryParentBinding.model_validate(
            parent.model_dump(mode="python"),
            strict=True,
        )
        policy = TruncationRecoveryPolicy.model_validate(
            policy.model_dump(mode="python"),
            strict=True,
        )
        resources = TruncationRecoveryResourceBudget.model_validate(
            resources.model_dump(mode="python"),
            strict=True,
        )
        if policy != TruncationRecoveryPolicy.frozen():
            raise ValueError("truncation recovery child policy is not the compiled policy")
        surfaces = _canonical_surface_ids(surface_ids, label="child surfaces")
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "algorithm_version": TRUNCATION_RECOVERY_ALGORITHM_VERSION,
            "campaign_id": parent.campaign_id,
            "pass_plan_id": parent.pass_plan_id,
            "parent_task_id": parent.parent_task_id,
            "parent_binding_sha256": parent.parent_binding_sha256,
            "truncation_projection_sha256": parent.truncation_projection_sha256,
            "policy_sha256": policy.policy_sha256,
            "requested_surface_manifest_sha256": (parent.requested_surface_manifest_sha256),
            "parent_unfinished_surface_count": len(parent.unfinished_surface_ids),
            "parent_unfinished_surface_inventory_sha256": _canonical_sha256(
                {
                    "domain": ("mmaudit.truncation-recovery.unfinished-surface-inventory.v1"),
                    "surface_ids": parent.unfinished_surface_ids,
                }
            ),
            "parent_depth": parent.current_depth,
            "parent_path": parent.parent_path,
            "depth": parent.current_depth + 1,
            "path": path,
            "ordinal": ordinal,
            "channel": channel,
            "surface_ids": surfaces,
            "reserved_provider_attempts": resources.child_provider_attempts,
            "reserved_completion_tokens": resources.child_completion_tokens,
            "reserved_usd_exact": resources.child_reserved_usd_exact,
        }
        identity = _canonical_sha256(
            {
                "domain": "mmaudit.truncation-recovery.child-task-identity.v1",
                **values,
            }
        )
        body = {
            **values,
            "child_task_id": "scheduler-recovery-task-" + identity,
            "child_logical_request_id": "scheduler-recovery-request-"
            + _canonical_sha256(
                {
                    "domain": "mmaudit.truncation-recovery.child-request-identity.v1",
                    "child_task_identity_sha256": identity,
                }
            ),
        }
        return cls(**body, child_plan_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def child_identity_scope_and_hash_are_exact(self) -> Self:
        _require_canonical_surface_ids(self.surface_ids, label="child surfaces")
        _decimal_and_canonical_text(self.reserved_usd_exact, label="child reserved USD")
        if (
            self.depth != self.parent_depth + 1
            or len(self.parent_path) != self.parent_depth
            or len(self.path) != self.depth
            or not self.path.startswith(self.parent_path)
            or len(self.path) != len(self.parent_path) + 1
            or self.path != self.parent_path + str(self.ordinal)
        ):
            raise ValueError("truncation recovery child path differs from its parent depth")
        if self.channel is not TruncationRecoveryChannel.COVERAGE:
            raise ValueError("truncation recovery child must be a coverage shard")
        if not 0 < len(self.surface_ids) < self.parent_unfinished_surface_count:
            raise ValueError("truncation recovery child must strictly shrink unfinished surfaces")
        identity_values = self.model_dump(
            mode="json",
            exclude={"child_task_id", "child_logical_request_id", "child_plan_sha256"},
        )
        identity = _canonical_sha256(
            {
                "domain": "mmaudit.truncation-recovery.child-task-identity.v1",
                **identity_values,
            }
        )
        if self.child_task_id != "scheduler-recovery-task-" + identity:
            raise ValueError("truncation recovery child task ID is inconsistent")
        expected_request = "scheduler-recovery-request-" + _canonical_sha256(
            {
                "domain": "mmaudit.truncation-recovery.child-request-identity.v1",
                "child_task_identity_sha256": identity,
            }
        )
        if self.child_logical_request_id != expected_request:
            raise ValueError("truncation recovery child request ID is inconsistent")
        if self.child_plan_sha256 != _model_sha256(self, exclude={"child_plan_sha256"}):
            raise ValueError("truncation recovery child plan hash is inconsistent")
        return self


class _ChildSpec(StrictModel):
    """Internal deterministic child projection used for reconstruction."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    channel: TruncationRecoveryChannel
    surface_ids: tuple[str, ...]
    path: str


def _binary_surface_partitions(
    values: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]] | tuple[()]:
    if len(values) < 2:
        return ()
    midpoint = (len(values) + 1) // 2
    return (values[:midpoint], values[midpoint:])


def _channel_states(
    parent: TruncationRecoveryParentBinding,
) -> dict[TruncationRecoveryChannel, TruncationRecoveryChannelState]:
    return {item.channel: item.state for item in parent.channel_bindings}


def _irreducible_channels(
    parent: TruncationRecoveryParentBinding,
) -> tuple[TruncationRecoveryChannel, ...]:
    states = _channel_states(parent)
    channels: list[TruncationRecoveryChannel] = []
    if (
        states[TruncationRecoveryChannel.COVERAGE] is not TruncationRecoveryChannelState.COMPLETE
        and len(parent.unfinished_surface_ids) < 2
    ):
        channels.append(TruncationRecoveryChannel.COVERAGE)
    if states[TruncationRecoveryChannel.FINDINGS] is not TruncationRecoveryChannelState.COMPLETE:
        channels.append(TruncationRecoveryChannel.FINDINGS)
    return tuple(channels)


def _non_authorizing_incomplete_channels(
    parent: TruncationRecoveryParentBinding,
) -> tuple[TruncationRecoveryChannel, ...]:
    states = _channel_states(parent)
    if states[TruncationRecoveryChannel.SUMMARY] is not TruncationRecoveryChannelState.COMPLETE:
        return (TruncationRecoveryChannel.SUMMARY,)
    return ()


def _required_child_specs(
    parent: TruncationRecoveryParentBinding,
) -> tuple[_ChildSpec, ...]:
    states = _channel_states(parent)
    if (
        states[TruncationRecoveryChannel.COVERAGE] is TruncationRecoveryChannelState.COMPLETE
        or len(parent.unfinished_surface_ids) < 2
    ):
        return ()
    next_paths = (parent.parent_path + "0", parent.parent_path + "1")
    partitions = _binary_surface_partitions(parent.unfinished_surface_ids)
    return tuple(
        _ChildSpec(
            channel=TruncationRecoveryChannel.COVERAGE,
            surface_ids=partition,
            path=next_paths[index],
        )
        for index, partition in enumerate(partitions)
    )


def _candidate_totals(
    *,
    resources: TruncationRecoveryResourceBudget,
    child_count: int,
) -> tuple[int, int, int, Decimal, Decimal]:
    before, _ = _decimal_and_canonical_text(
        resources.accounted_usd_before_parent_exact,
        label="accounted USD before parent",
    )
    parent, _ = _decimal_and_canonical_text(
        resources.parent_accounted_cost_usd_exact,
        label="parent accounted USD",
    )
    child, _ = _decimal_and_canonical_text(
        resources.child_reserved_usd_exact,
        label="child reserved USD",
    )
    child_cost = _exact_product(child, child_count)
    return (
        resources.recovery_requests_consumed + child_count,
        resources.provider_attempts_before_parent
        + resources.parent_provider_attempts
        + (resources.child_provider_attempts * child_count),
        resources.completion_tokens_before_parent
        + resources.parent_completion_tokens
        + (resources.child_completion_tokens * child_count),
        child_cost,
        _exact_sum((before, parent, child_cost)),
    )


def _derive_disposition(
    *,
    parent: TruncationRecoveryParentBinding,
    policy: TruncationRecoveryPolicy,
    resources: TruncationRecoveryResourceBudget,
    specs: tuple[_ChildSpec, ...],
) -> TruncationRecoveryDisposition:
    if not specs:
        if _irreducible_channels(parent):
            return TruncationRecoveryDisposition.IRREDUCIBLE_WORK
        return TruncationRecoveryDisposition.NO_REMAINING_WORK
    if parent.current_depth >= policy.max_depth:
        return TruncationRecoveryDisposition.DEPTH_EXHAUSTED
    requests, attempts, tokens, _child_cost, total_cost = _candidate_totals(
        resources=resources,
        child_count=len(specs),
    )
    if requests > policy.max_child_requests:
        return TruncationRecoveryDisposition.REQUEST_EXHAUSTED
    if attempts > policy.max_provider_attempts:
        return TruncationRecoveryDisposition.PROVIDER_ATTEMPT_EXHAUSTED
    if tokens > policy.max_completion_tokens:
        return TruncationRecoveryDisposition.TOKEN_EXHAUSTED
    campaign_cap = Decimal(resources.campaign_cap_usd_exact)
    if total_cost >= campaign_cap or total_cost >= Decimal(policy.max_usd_exact):
        return TruncationRecoveryDisposition.BUDGET_EXHAUSTED
    return TruncationRecoveryDisposition.PLANNED


class TruncationRecoveryPlan(_NonAuthorizingRecoveryModel):
    """Self-validating child inventory and exact boundary disposition."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-recovery.v1"] = "mmaudit.truncation-recovery.v1"
    policy: TruncationRecoveryPolicy
    parent: TruncationRecoveryParentBinding
    resources: TruncationRecoveryResourceBudget
    disposition: TruncationRecoveryDisposition
    planned_channels: tuple[TruncationRecoveryChannel, ...] = Field(max_length=3)
    irreducible_channels: tuple[TruncationRecoveryChannel, ...] = Field(max_length=3)
    blocked_channels: tuple[TruncationRecoveryChannel, ...] = Field(max_length=3)
    non_authorizing_incomplete_channels: tuple[TruncationRecoveryChannel, ...] = Field(max_length=3)
    required_child_request_count: int = Field(
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    required_child_provider_attempts: int = Field(ge=0, le=_MAX_COUNTER)
    required_child_completion_tokens: int = Field(ge=0, le=_MAX_COUNTER)
    required_child_reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    total_recovery_requests_if_planned: int = Field(
        ge=0,
        le=_MAX_TOTAL_RECOVERY_REQUESTS,
    )
    total_provider_attempts_if_planned: int = Field(
        ge=0,
        le=_MAX_TOTAL_PROVIDER_ATTEMPTS,
    )
    total_completion_tokens_if_planned: int = Field(
        ge=0,
        le=_MAX_TOTAL_COMPLETION_TOKENS,
    )
    total_cost_usd_exact_if_planned: str = Field(pattern=_TOTAL_USD_EXACT_PATTERN)
    parent_cost_refunded: Literal[False] = False
    children: tuple[TruncationRecoveryChildPlan, ...] = Field(
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    child_task_ids: tuple[str, ...] = Field(
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    child_logical_request_ids: tuple[str, ...] = Field(
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    child_plan_sha256s: tuple[str, ...] = Field(
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    covered_unfinished_surface_ids: tuple[str, ...] = Field(max_length=_MAX_SURFACES)
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def plan_is_deterministic_conservative_and_exact(self) -> Self:
        expected_policy = TruncationRecoveryPolicy.frozen()
        if self.policy != expected_policy:
            raise ValueError("truncation recovery plan policy is not the compiled policy")
        specs = _required_child_specs(self.parent)
        expected_disposition = _derive_disposition(
            parent=self.parent,
            policy=self.policy,
            resources=self.resources,
            specs=specs,
        )
        expected_irreducible = _irreducible_channels(self.parent)
        expected_non_authorizing = _non_authorizing_incomplete_channels(self.parent)
        expected_planned = (
            (TruncationRecoveryChannel.COVERAGE,)
            if expected_disposition is TruncationRecoveryDisposition.PLANNED
            else ()
        )
        expected_blocked = (
            (TruncationRecoveryChannel.COVERAGE,)
            if specs and expected_disposition is not TruncationRecoveryDisposition.PLANNED
            else ()
        )
        if (
            self.planned_channels != expected_planned
            or self.irreducible_channels != expected_irreducible
            or self.blocked_channels != expected_blocked
            or self.non_authorizing_incomplete_channels != expected_non_authorizing
        ):
            raise ValueError("truncation recovery channel outcomes are inconsistent")
        child_count = len(specs)
        requests, attempts, tokens, child_cost, total_cost = _candidate_totals(
            resources=self.resources,
            child_count=child_count,
        )
        if (
            self.disposition is not expected_disposition
            or self.required_child_request_count != child_count
            or self.required_child_provider_attempts
            != self.resources.child_provider_attempts * child_count
            or self.required_child_completion_tokens
            != self.resources.child_completion_tokens * child_count
            or self.required_child_reserved_usd_exact != _canonical_decimal_text(child_cost)
            or self.total_recovery_requests_if_planned != requests
            or self.total_provider_attempts_if_planned != attempts
            or self.total_completion_tokens_if_planned != tokens
            or self.total_cost_usd_exact_if_planned != _canonical_decimal_text(total_cost)
        ):
            raise ValueError("truncation recovery plan totals or disposition are inconsistent")
        expected_children = (
            tuple(
                TruncationRecoveryChildPlan.build(
                    parent=self.parent,
                    policy=self.policy,
                    resources=self.resources,
                    ordinal=index,
                    channel=spec.channel,
                    surface_ids=spec.surface_ids,
                    path=spec.path,
                )
                for index, spec in enumerate(specs)
            )
            if self.disposition is TruncationRecoveryDisposition.PLANNED
            else ()
        )
        if self.children != expected_children:
            raise ValueError("truncation recovery child inventory is not deterministic")
        expected_task_ids = tuple(item.child_task_id for item in expected_children)
        expected_request_ids = tuple(item.child_logical_request_id for item in expected_children)
        expected_hashes = tuple(item.child_plan_sha256 for item in expected_children)
        if (
            self.child_task_ids != expected_task_ids
            or self.child_logical_request_ids != expected_request_ids
            or self.child_plan_sha256s != expected_hashes
            or len(expected_task_ids) != len(set(expected_task_ids))
            or len(expected_request_ids) != len(set(expected_request_ids))
            or len(expected_hashes) != len(set(expected_hashes))
        ):
            raise ValueError("truncation recovery child identities are incomplete or duplicated")
        covered = tuple(
            surface_id
            for child in expected_children
            if child.channel is TruncationRecoveryChannel.COVERAGE
            for surface_id in child.surface_ids
        )
        if covered != tuple(sorted(covered)) or len(covered) != len(set(covered)):
            raise ValueError("truncation recovery coverage children overlap or are unordered")
        if covered and covered != self.parent.unfinished_surface_ids:
            raise ValueError("truncation recovery coverage children do not conserve surfaces")
        expected_covered = (
            self.parent.unfinished_surface_ids
            if self.disposition is TruncationRecoveryDisposition.PLANNED
            else ()
        )
        if self.covered_unfinished_surface_ids != expected_covered:
            raise ValueError("truncation recovery covered-surface projection is inconsistent")
        if self.plan_sha256 != _model_sha256(self, exclude={"plan_sha256"}):
            raise ValueError("truncation recovery plan hash is inconsistent")
        return self


def plan_truncation_recovery(
    *,
    parent: TruncationRecoveryParentBinding,
    resources: TruncationRecoveryResourceBudget,
) -> TruncationRecoveryPlan:
    """Apply the compiled policy without dispatching or granting any credit."""

    frozen_parent = TruncationRecoveryParentBinding.model_validate(
        parent.model_dump(mode="python"),
        strict=True,
    )
    frozen_resources = TruncationRecoveryResourceBudget.model_validate(
        resources.model_dump(mode="python"),
        strict=True,
    )
    policy = TruncationRecoveryPolicy.frozen()
    specs = _required_child_specs(frozen_parent)
    disposition = _derive_disposition(
        parent=frozen_parent,
        policy=policy,
        resources=frozen_resources,
        specs=specs,
    )
    children = (
        tuple(
            TruncationRecoveryChildPlan.build(
                parent=frozen_parent,
                policy=policy,
                resources=frozen_resources,
                ordinal=index,
                channel=spec.channel,
                surface_ids=spec.surface_ids,
                path=spec.path,
            )
            for index, spec in enumerate(specs)
        )
        if disposition is TruncationRecoveryDisposition.PLANNED
        else ()
    )
    requests, attempts, tokens, child_cost, total_cost = _candidate_totals(
        resources=frozen_resources,
        child_count=len(specs),
    )
    covered = tuple(
        surface_id
        for child in children
        if child.channel is TruncationRecoveryChannel.COVERAGE
        for surface_id in child.surface_ids
    )
    irreducible_channels = _irreducible_channels(frozen_parent)
    non_authorizing_incomplete_channels = _non_authorizing_incomplete_channels(frozen_parent)
    values: dict[str, Any] = {
        "evidence_authority": "comparison_required",
        "provider_dispatch_authorized": False,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "completion_authorized": False,
        "release_authorized": False,
        "schema_version": "1.0",
        "algorithm_version": TRUNCATION_RECOVERY_ALGORITHM_VERSION,
        "policy": policy,
        "parent": frozen_parent,
        "resources": frozen_resources,
        "disposition": disposition,
        "planned_channels": (
            (TruncationRecoveryChannel.COVERAGE,)
            if disposition is TruncationRecoveryDisposition.PLANNED
            else ()
        ),
        "irreducible_channels": irreducible_channels,
        "blocked_channels": (
            (TruncationRecoveryChannel.COVERAGE,)
            if specs and disposition is not TruncationRecoveryDisposition.PLANNED
            else ()
        ),
        "non_authorizing_incomplete_channels": (non_authorizing_incomplete_channels),
        "required_child_request_count": len(specs),
        "required_child_provider_attempts": (frozen_resources.child_provider_attempts * len(specs)),
        "required_child_completion_tokens": (frozen_resources.child_completion_tokens * len(specs)),
        "required_child_reserved_usd_exact": _canonical_decimal_text(child_cost),
        "total_recovery_requests_if_planned": requests,
        "total_provider_attempts_if_planned": attempts,
        "total_completion_tokens_if_planned": tokens,
        "total_cost_usd_exact_if_planned": _canonical_decimal_text(total_cost),
        "parent_cost_refunded": False,
        "children": children,
        "child_task_ids": tuple(item.child_task_id for item in children),
        "child_logical_request_ids": tuple(item.child_logical_request_id for item in children),
        "child_plan_sha256s": tuple(item.child_plan_sha256 for item in children),
        "covered_unfinished_surface_ids": covered,
    }
    return TruncationRecoveryPlan(**values, plan_sha256=_canonical_sha256(values))


__all__ = [
    "TRUNCATION_RECOVERY_ALGORITHM_VERSION",
    "TRUNCATION_RECOVERY_CHANNEL_ORDER",
    "TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS",
    "TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS",
    "TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS",
    "TRUNCATION_RECOVERY_MAX_COMPLETION_TOKENS",
    "TRUNCATION_RECOVERY_MAX_DEPTH",
    "TRUNCATION_RECOVERY_MAX_PROVIDER_ATTEMPTS",
    "TRUNCATION_RECOVERY_MAX_USD_EXACT",
    "TruncationRecoveryChannel",
    "TruncationRecoveryChannelBinding",
    "TruncationRecoveryChannelState",
    "TruncationRecoveryChildPlan",
    "TruncationRecoveryDisposition",
    "TruncationRecoveryParentBinding",
    "TruncationRecoveryPlan",
    "TruncationRecoveryPolicy",
    "TruncationRecoveryResourceBudget",
    "plan_truncation_recovery",
]
