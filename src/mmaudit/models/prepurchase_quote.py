"""Deterministic, provider-free pre-purchase quote and reconciliation evidence.

The artifacts in this module are immutable constraints and comparison evidence.  They
never grant dispatch, review, completion, or release authority.  Quote construction
fails closed unless every paid task class has a finite ceiling and the existing early
portfolio reservation joins the exact scheduler, shard, pricing, and ledger custody.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from decimal import Context, Decimal, InvalidOperation, localcontext
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.config import ModelRetryPolicy
from mmaudit.models.coverage_planning import (
    ModelPortfolioResourcePreflight,
    ModelPortfolioTaskKind,
    ModelPortfolioTaskResourceEnvelope,
)
from mmaudit.models.identifiers import EXACT_MODEL_ID_PATTERN, require_exact_openrouter_model_id
from mmaudit.models.sharding import SolidityShardInventory

if TYPE_CHECKING:
    from mmaudit.models.scheduler import SchedulerCampaignManifest
    from mmaudit.reporting.bundle import RunCostLedgerEvidence

MAX_QUOTE_TASK_CEILINGS = 10_000
MAX_QUOTE_TASK_COUNT = 1_000_000
MAX_QUOTE_ATTEMPTS_PER_TASK = 64

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_PROVIDER_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,255}$"
_CANONICAL_DECIMAL_PATTERN = re.compile(r"^(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,30})?$")


def _decimal_context() -> Context:
    return Context(prec=96)


def _canonical_decimal_text(value: object, *, label: str) -> str:
    if type(value) is not str or not value or len(value) > 64:
        raise ValueError(f"{label} must be canonical decimal text")
    assert isinstance(value, str)
    if _CANONICAL_DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be canonical non-negative decimal text")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ValueError(f"{label} must be canonical decimal text") from None
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    normalized = format(parsed, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    normalized = normalized or "0"
    if normalized != value:
        raise ValueError(f"{label} must not contain redundant notation")
    return value


def _format_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _sum_decimal_text(values: Iterable[str]) -> str:
    with localcontext(_decimal_context()):
        total = sum((Decimal(value) for value in values), start=Decimal(0))
    return _format_decimal(total)


def _multiply_decimal_text(value: str, *multipliers: int) -> str:
    with localcontext(_decimal_context()):
        result = Decimal(value)
        for multiplier in multipliers:
            result *= Decimal(multiplier)
    return _format_decimal(result)


def _subtract_nonnegative_decimal_text(left: str, right: str) -> str:
    with localcontext(_decimal_context()):
        result = Decimal(left) - Decimal(right)
    if result < 0:
        raise ValueError("decimal subtraction would be negative")
    return _format_decimal(result)


def _canonical_json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Decimal):
        return _format_decimal(value)
    if isinstance(value, datetime):
        _require_utc(value, label="canonical artifact timestamp")
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _canonical_json_text(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_canonical_json_default,
    )


def _canonical_sha256(value: Any) -> str:
    payload = _canonical_json_text(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_self_hash(model: BaseModel, field_name: str) -> None:
    expected = _canonical_sha256(model.model_dump(mode="json", exclude={field_name}))
    if getattr(model, field_name) != expected:
        raise ValueError(f"{field_name} does not match the canonical artifact")


def _require_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{label} must be timezone-aware UTC")
    return value


class _FrozenNonAuthorizingArtifact(BaseModel):
    """Strict immutable evidence that cannot grant any execution or result credit."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    authorizes_dispatch: Literal[False] = False
    grants_review_credit: Literal[False] = False
    grants_completion_credit: Literal[False] = False
    grants_release_authority: Literal[False] = False


class PrepurchaseQuoteTaskClass(StrEnum):
    """Closed paid-work classes that a whole-run quote must bound explicitly."""

    ORIENTATION = "orientation"
    COMPACT_COVERAGE = "compact_coverage"
    SOURCE_AUDIT = "source_audit"
    WHOLE_PROTOCOL = "whole_protocol"
    INVARIANT_REVIEW = "invariant_review"
    CROSS_SHARD_INTEGRATION = "cross_shard_integration"
    ADVERSARIAL_CROSS_EXAMINATION = "adversarial_cross_examination"
    MULTI_LINEAGE_VALIDATION_FALSIFICATION = "multi_lineage_validation_falsification"
    EVIDENCE_CAPPED_JUDGMENT = "evidence_capped_judgment"
    REPORT_QUALITY = "report_quality"
    TRUNCATION_RECOVERY = "truncation_recovery"


class PrepurchaseQuoteRuntimeRoleKind(StrEnum):
    """How a quoted semantic role maps to concrete runtime role identities."""

    EXACT = "exact"
    CANDIDATE_FALSIFIER_SHA256_REVIEWER = "candidate_falsifier_sha256_reviewer"


class PrepurchaseQuoteDeltaRelation(StrEnum):
    """Direction of one non-negative absolute reconciliation delta."""

    UNDER = "UNDER"
    EXACT = "EXACT"
    OVER = "OVER"


class PrepurchaseQuoteReconciliationStatus(StrEnum):
    """Whether the terminal ledger proves an actual cost suitable for comparison."""

    CONCLUSIVE = "CONCLUSIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class PrepurchaseQuoteInconclusiveReason(StrEnum):
    """Closed accounting conditions that prevent an actual-cost claim."""

    UNCERTAIN_ACCOUNTING = "UNCERTAIN_ACCOUNTING"
    RESERVATION_OVERRUN = "RESERVATION_OVERRUN"


class PrepurchaseQuoteTargetBinding(_FrozenNonAuthorizingArtifact):
    """Exact deterministic repository, scheduler, index, graph, and shard identity."""

    artifact_kind: Literal["prepurchase_quote_target_binding"] = "prepurchase_quote_target_binding"
    schema_version: Literal["1.0"] = "1.0"
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selected_model_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    scheduler_campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    scheduler_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_bindings_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_shard_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    solidity_shard_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    symbol_index_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    symbol_index_sha256: str = Field(pattern=_SHA256_PATTERN)
    symbol_index_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    graph_set_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    graph_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    graph_set_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    repository_source_count: int = Field(ge=1, le=100_000)
    repository_source_bytes: int = Field(ge=0, le=2**63 - 1)
    solidity_source_count: int = Field(ge=1, le=100_000)
    solidity_source_bytes: int = Field(ge=0, le=2**63 - 1)
    indexed_entity_count: int = Field(ge=0, le=2**63 - 1)
    graph_node_count: int = Field(ge=0, le=2**63 - 1)
    graph_edge_count: int = Field(ge=0, le=2**63 - 1)
    storage_entry_count: int = Field(ge=0, le=2**63 - 1)
    scheduler_shard_count: int = Field(ge=1, le=100_000)
    solidity_shard_count: int = Field(ge=1, le=100_000)
    target_binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def binding_is_self_hashed(self) -> Self:
        _require_self_hash(self, "target_binding_sha256")
        return self


class PrepurchaseQuoteLedgerBaselineBinding(_FrozenNonAuthorizingArtifact):
    """Exact terminal persistent-ledger head frozen before the quoted run."""

    artifact_kind: Literal["prepurchase_quote_ledger_baseline"] = (
        "prepurchase_quote_ledger_baseline"
    )
    schema_version: Literal["1.0"] = "1.0"
    baseline_sha256: str = Field(pattern=_SHA256_PATTERN)
    ledger_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    ledger_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    cap_usd_exact: str
    spent_usd_exact: str
    active_reserved_usd_exact: str
    remaining_usd_exact: str
    baseline_binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "cap_usd_exact",
        "spent_usd_exact",
        "active_reserved_usd_exact",
        "remaining_usd_exact",
    )
    @classmethod
    def amounts_are_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="quote ledger amount")

    @model_validator(mode="after")
    def baseline_is_terminal_exact_and_self_hashed(self) -> Self:
        with localcontext(_decimal_context()):
            expected_remaining = Decimal(self.cap_usd_exact) - Decimal(self.spent_usd_exact)
            expected_remaining -= Decimal(self.active_reserved_usd_exact)
        if (
            Decimal(self.cap_usd_exact) <= 0
            or Decimal(self.spent_usd_exact) < 0
            or self.active_reserved_usd_exact != "0"
            or expected_remaining < 0
            or self.remaining_usd_exact != _format_decimal(expected_remaining)
        ):
            raise ValueError("quote ledger baseline is not a terminal in-cap snapshot")
        _require_self_hash(self, "baseline_binding_sha256")
        return self


class PrepurchaseQuoteTaskCeiling(_FrozenNonAuthorizingArtifact):
    """Finite route, retry, token, price, task-count, and duration ceiling."""

    artifact_kind: Literal["prepurchase_quote_task_ceiling"] = "prepurchase_quote_task_ceiling"
    schema_version: Literal["1.0"] = "1.0"
    task_class: PrepurchaseQuoteTaskClass
    request_role: str | None = Field(default=None, pattern=_SAFE_ROLE_PATTERN)
    runtime_role_kind: PrepurchaseQuoteRuntimeRoleKind | None = None
    maximum_distinct_runtime_roles: int = Field(ge=0, le=MAX_QUOTE_TASK_COUNT)
    requested_model: str | None = Field(default=None, pattern=EXACT_MODEL_ID_PATTERN)
    request_envelope_recipe_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    endpoint_policy_snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    endpoint_policy_pricing_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    provider_endpoint: str | None = Field(default=None, pattern=_PROVIDER_ENDPOINT_PATTERN)
    endpoint_pricing_snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    standard_task_count: int = Field(ge=0, le=MAX_QUOTE_TASK_COUNT)
    maximum_task_count: int = Field(ge=0, le=MAX_QUOTE_TASK_COUNT)
    standard_attempts_per_task: int = Field(ge=1, le=MAX_QUOTE_ATTEMPTS_PER_TASK)
    maximum_attempts_per_task: int = Field(ge=1, le=MAX_QUOTE_ATTEMPTS_PER_TASK)
    maximum_input_tokens_per_attempt: int = Field(ge=0, le=2**63 - 1)
    maximum_output_tokens_per_attempt: int = Field(ge=0, le=2**63 - 1)
    maximum_cost_usd_per_attempt_exact: str
    standard_wall_clock_seconds_per_task: int = Field(ge=0, le=2**31 - 1)
    maximum_wall_clock_seconds_per_task: int = Field(ge=0, le=2**31 - 1)
    standard_request_count: int = Field(ge=0, le=2**63 - 1)
    worst_case_request_count: int = Field(ge=0, le=2**63 - 1)
    standard_cost_usd_exact: str
    worst_case_cost_usd_exact: str
    standard_wall_clock_seconds: int = Field(ge=0, le=2**63 - 1)
    worst_case_wall_clock_seconds: int = Field(ge=0, le=2**63 - 1)
    ceiling_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        task_class: PrepurchaseQuoteTaskClass,
        request_role: str | None,
        requested_model: str | None,
        request_envelope_recipe_sha256: str | None,
        endpoint_policy_snapshot_sha256: str | None,
        endpoint_policy_pricing_sha256: str | None,
        provider_endpoint: str | None,
        endpoint_pricing_snapshot_sha256: str | None,
        standard_task_count: int,
        maximum_task_count: int,
        standard_attempts_per_task: int,
        maximum_attempts_per_task: int,
        maximum_input_tokens_per_attempt: int,
        maximum_output_tokens_per_attempt: int,
        maximum_cost_usd_per_attempt_exact: str,
        standard_wall_clock_seconds_per_task: int,
        maximum_wall_clock_seconds_per_task: int,
    ) -> PrepurchaseQuoteTaskCeiling:
        exact_integer_values = (
            standard_task_count,
            maximum_task_count,
            standard_attempts_per_task,
            maximum_attempts_per_task,
            maximum_input_tokens_per_attempt,
            maximum_output_tokens_per_attempt,
            standard_wall_clock_seconds_per_task,
            maximum_wall_clock_seconds_per_task,
        )
        if any(type(value) is not int for value in exact_integer_values):
            raise ValueError("quote task ceiling counts and durations must be exact integers")
        cost = _canonical_decimal_text(
            maximum_cost_usd_per_attempt_exact,
            label="quote maximum per-attempt cost",
        )
        disabled = maximum_task_count == 0
        runtime_role_kind = (
            None
            if disabled
            else (
                PrepurchaseQuoteRuntimeRoleKind.CANDIDATE_FALSIFIER_SHA256_REVIEWER
                if task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
                and request_role == "candidate_falsifier"
                else PrepurchaseQuoteRuntimeRoleKind.EXACT
            )
        )
        maximum_distinct_runtime_roles = (
            0
            if disabled
            else (
                maximum_task_count
                if runtime_role_kind
                is PrepurchaseQuoteRuntimeRoleKind.CANDIDATE_FALSIFIER_SHA256_REVIEWER
                else 1
            )
        )
        values = {
            "artifact_kind": "prepurchase_quote_task_ceiling",
            "schema_version": "1.0",
            "task_class": task_class,
            "request_role": request_role,
            "runtime_role_kind": runtime_role_kind,
            "maximum_distinct_runtime_roles": maximum_distinct_runtime_roles,
            "requested_model": requested_model,
            "request_envelope_recipe_sha256": request_envelope_recipe_sha256,
            "endpoint_policy_snapshot_sha256": endpoint_policy_snapshot_sha256,
            "endpoint_policy_pricing_sha256": endpoint_policy_pricing_sha256,
            "provider_endpoint": provider_endpoint,
            "endpoint_pricing_snapshot_sha256": endpoint_pricing_snapshot_sha256,
            "standard_task_count": standard_task_count,
            "maximum_task_count": maximum_task_count,
            "standard_attempts_per_task": standard_attempts_per_task,
            "maximum_attempts_per_task": maximum_attempts_per_task,
            "maximum_input_tokens_per_attempt": maximum_input_tokens_per_attempt,
            "maximum_output_tokens_per_attempt": maximum_output_tokens_per_attempt,
            "maximum_cost_usd_per_attempt_exact": cost,
            "standard_wall_clock_seconds_per_task": standard_wall_clock_seconds_per_task,
            "maximum_wall_clock_seconds_per_task": maximum_wall_clock_seconds_per_task,
            "standard_request_count": standard_task_count * standard_attempts_per_task,
            "worst_case_request_count": maximum_task_count * maximum_attempts_per_task,
            "standard_cost_usd_exact": _multiply_decimal_text(
                cost,
                standard_task_count,
                standard_attempts_per_task,
            ),
            "worst_case_cost_usd_exact": _multiply_decimal_text(
                cost,
                maximum_task_count,
                maximum_attempts_per_task,
            ),
            "standard_wall_clock_seconds": (
                standard_task_count * standard_wall_clock_seconds_per_task
            ),
            "worst_case_wall_clock_seconds": (
                maximum_task_count * maximum_wall_clock_seconds_per_task
            ),
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
            "grants_release_authority": False,
        }
        return cls.model_validate({**values, "ceiling_sha256": _canonical_sha256(values)})

    @field_validator("requested_model")
    @classmethod
    def model_is_exact(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_exact_openrouter_model_id(value, label="quote requested model")

    @field_validator(
        "maximum_cost_usd_per_attempt_exact",
        "standard_cost_usd_exact",
        "worst_case_cost_usd_exact",
    )
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="quote task cost")

    @model_validator(mode="after")
    def totals_are_exact_bounded_and_self_hashed(self) -> Self:
        route_fields = (
            self.request_role,
            self.runtime_role_kind,
            self.requested_model,
            self.request_envelope_recipe_sha256,
            self.endpoint_policy_snapshot_sha256,
            self.endpoint_policy_pricing_sha256,
            self.provider_endpoint,
            self.endpoint_pricing_snapshot_sha256,
        )
        disabled = self.maximum_task_count == 0
        dynamic_candidate_roles = (
            self.runtime_role_kind
            is PrepurchaseQuoteRuntimeRoleKind.CANDIDATE_FALSIFIER_SHA256_REVIEWER
        )
        if (
            (disabled and any(value is not None for value in route_fields))
            or (not disabled and any(value is None for value in route_fields))
            or (
                disabled
                and (
                    self.standard_task_count != 0
                    or self.maximum_distinct_runtime_roles != 0
                    or self.maximum_input_tokens_per_attempt != 0
                    or self.maximum_output_tokens_per_attempt != 0
                    or self.maximum_cost_usd_per_attempt_exact != "0"
                    or self.standard_wall_clock_seconds_per_task != 0
                    or self.maximum_wall_clock_seconds_per_task != 0
                )
            )
            or (
                not disabled
                and (
                    (
                        dynamic_candidate_roles
                        and (
                            self.task_class
                            is not PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
                            or self.request_role != "candidate_falsifier"
                            or self.maximum_distinct_runtime_roles != self.maximum_task_count
                        )
                    )
                    or (
                        not dynamic_candidate_roles
                        and (
                            self.runtime_role_kind is not PrepurchaseQuoteRuntimeRoleKind.EXACT
                            or self.maximum_distinct_runtime_roles != 1
                        )
                    )
                )
            )
            or (
                self.standard_task_count > self.maximum_task_count
                or self.standard_attempts_per_task > self.maximum_attempts_per_task
                or self.standard_wall_clock_seconds_per_task
                > self.maximum_wall_clock_seconds_per_task
                or self.standard_request_count
                != self.standard_task_count * self.standard_attempts_per_task
                or self.worst_case_request_count
                != self.maximum_task_count * self.maximum_attempts_per_task
                or self.standard_cost_usd_exact
                != _multiply_decimal_text(
                    self.maximum_cost_usd_per_attempt_exact,
                    self.standard_task_count,
                    self.standard_attempts_per_task,
                )
                or self.worst_case_cost_usd_exact
                != _multiply_decimal_text(
                    self.maximum_cost_usd_per_attempt_exact,
                    self.maximum_task_count,
                    self.maximum_attempts_per_task,
                )
                or self.standard_wall_clock_seconds
                != self.standard_task_count * self.standard_wall_clock_seconds_per_task
                or self.worst_case_wall_clock_seconds
                != self.maximum_task_count * self.maximum_wall_clock_seconds_per_task
            )
        ):
            raise ValueError("quote task ceiling derived totals are inconsistent")
        _require_self_hash(self, "ceiling_sha256")
        return self


class PrepurchaseQuoteLocalAnalysisCeiling(_FrozenNonAuthorizingArtifact):
    """Finite wall-clock ceiling for deterministic analysis and local scanners."""

    artifact_kind: Literal["prepurchase_quote_local_analysis_ceiling"] = (
        "prepurchase_quote_local_analysis_ceiling"
    )
    schema_version: Literal["1.0"] = "1.0"
    analysis_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    execution_limits_sha256: str = Field(pattern=_SHA256_PATTERN)
    standard_wall_clock_seconds: int = Field(ge=0, le=2**63 - 1)
    maximum_wall_clock_seconds: int = Field(ge=1, le=2**63 - 1)
    ceiling_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        analysis_input_sha256: str,
        execution_limits_sha256: str,
        standard_wall_clock_seconds: int,
        maximum_wall_clock_seconds: int,
    ) -> PrepurchaseQuoteLocalAnalysisCeiling:
        if (
            type(standard_wall_clock_seconds) is not int
            or type(maximum_wall_clock_seconds) is not int
        ):
            raise ValueError("local-analysis quote durations must be exact integers")
        values = {
            "artifact_kind": "prepurchase_quote_local_analysis_ceiling",
            "schema_version": "1.0",
            "analysis_input_sha256": analysis_input_sha256,
            "execution_limits_sha256": execution_limits_sha256,
            "standard_wall_clock_seconds": standard_wall_clock_seconds,
            "maximum_wall_clock_seconds": maximum_wall_clock_seconds,
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
            "grants_release_authority": False,
        }
        return cls.model_validate({**values, "ceiling_sha256": _canonical_sha256(values)})

    @model_validator(mode="after")
    def ceiling_is_ordered_and_self_hashed(self) -> Self:
        if self.standard_wall_clock_seconds > self.maximum_wall_clock_seconds:
            raise ValueError("local-analysis standard duration exceeds its maximum")
        _require_self_hash(self, "ceiling_sha256")
        return self


class PrepurchaseQuoteCostRange(_FrozenNonAuthorizingArtifact):
    """Derived spend range clipped to the current durable ledger capacity."""

    artifact_kind: Literal["prepurchase_quote_cost_range"] = "prepurchase_quote_cost_range"
    schema_version: Literal["1.0"] = "1.0"
    lower_bound_usd_exact: Literal["0"] = "0"
    standard_bound_usd_exact: str
    worst_case_usd_exact: str = Field(
        description=(
            "Accepted hard spend ceiling under the current ledger; use "
            "unconstrained_workflow_worst_usd_exact for the complete-work worst case."
        )
    )
    range_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("standard_bound_usd_exact", "worst_case_usd_exact")
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="quote cost range")

    @model_validator(mode="after")
    def range_is_ordered_and_self_hashed(self) -> Self:
        if not (
            Decimal(self.lower_bound_usd_exact)
            <= Decimal(self.standard_bound_usd_exact)
            <= Decimal(self.worst_case_usd_exact)
        ):
            raise ValueError("quote cost range must satisfy zero <= standard <= worst case")
        _require_self_hash(self, "range_sha256")
        return self


class PrepurchaseQuoteWallClockRange(_FrozenNonAuthorizingArtifact):
    """Derived serial wall-clock range in exact integral seconds."""

    artifact_kind: Literal["prepurchase_quote_wall_clock_range"] = (
        "prepurchase_quote_wall_clock_range"
    )
    schema_version: Literal["1.0"] = "1.0"
    lower_bound_seconds: Literal[0] = 0
    standard_local_seconds: int = Field(ge=0, le=2**63 - 1)
    maximum_local_seconds: int = Field(ge=1, le=2**63 - 1)
    standard_paid_task_seconds: int = Field(ge=0, le=2**63 - 1)
    maximum_paid_task_seconds: int = Field(ge=0, le=2**63 - 1)
    standard_bound_seconds: int = Field(ge=0, le=2**63 - 1)
    worst_case_seconds: int = Field(ge=1, le=2**63 - 1)
    range_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def range_is_ordered_and_self_hashed(self) -> Self:
        if (
            self.standard_bound_seconds
            != self.standard_local_seconds + self.standard_paid_task_seconds
            or self.worst_case_seconds
            != self.maximum_local_seconds + self.maximum_paid_task_seconds
            or not self.lower_bound_seconds
            <= self.standard_bound_seconds
            <= self.worst_case_seconds
        ):
            raise ValueError("quote wall-clock range must satisfy zero <= standard <= worst case")
        _require_self_hash(self, "range_sha256")
        return self


class PrepurchaseQuote(_FrozenNonAuthorizingArtifact):
    """Complete deterministic quote for one exact target and bounded paid-work plan."""

    artifact_kind: Literal["prepurchase_quote"] = "prepurchase_quote"
    schema_version: Literal["1.1"] = "1.1"
    target_binding: PrepurchaseQuoteTargetBinding
    ledger_baseline: PrepurchaseQuoteLedgerBaselineBinding
    local_analysis_ceiling: PrepurchaseQuoteLocalAnalysisCeiling
    retry_policy: ModelRetryPolicy
    portfolio_preflight_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_ceilings: tuple[PrepurchaseQuoteTaskCeiling, ...] = Field(
        min_length=len(PrepurchaseQuoteTaskClass),
        max_length=MAX_QUOTE_TASK_CEILINGS,
    )
    covered_task_classes: tuple[PrepurchaseQuoteTaskClass, ...] = Field(
        min_length=len(PrepurchaseQuoteTaskClass),
        max_length=len(PrepurchaseQuoteTaskClass),
    )
    planned_role_count: int = Field(ge=1, le=MAX_QUOTE_TASK_CEILINGS)
    planned_model_count: int = Field(ge=1, le=MAX_QUOTE_TASK_CEILINGS)
    maximum_request_count: int = Field(ge=1, le=2**63 - 1)
    maximum_input_tokens: int = Field(ge=0, le=2**63 - 1)
    maximum_output_tokens: int = Field(ge=0, le=2**63 - 1)
    unconstrained_workflow_worst_usd_exact: str = Field(
        description="Complete-work worst-case cost before applying the durable spend cap."
    )
    hard_budget_limited: bool = Field(
        description="True when the accepted spend ceiling cannot cover the complete workflow."
    )
    completion_within_hard_ceiling_guaranteed: Literal[False] = False
    cost_range: PrepurchaseQuoteCostRange
    wall_clock_range: PrepurchaseQuoteWallClockRange
    quote_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("unconstrained_workflow_worst_usd_exact")
    @classmethod
    def unconstrained_cost_is_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="unconstrained workflow worst cost")

    @model_validator(mode="after")
    def quote_is_complete_derived_and_self_hashed(self) -> Self:
        expected_ceilings = tuple(sorted(self.task_ceilings, key=_task_ceiling_sort_key))
        if self.task_ceilings != expected_ceilings:
            raise ValueError("quote task ceilings must be canonically sorted")
        keys = tuple(_task_ceiling_identity(item) for item in self.task_ceilings)
        if len(keys) != len(set(keys)):
            raise ValueError("quote task ceilings repeat a route identity")
        expected_classes = tuple(PrepurchaseQuoteTaskClass)
        if self.covered_task_classes != expected_classes or {
            item.task_class for item in self.task_ceilings
        } != set(expected_classes):
            raise ValueError("quote must cover every paid task class exactly as a closed set")
        unconstrained_standard = _sum_decimal_text(
            item.standard_cost_usd_exact for item in self.task_ceilings
        )
        unconstrained_worst = _sum_decimal_text(
            item.worst_case_cost_usd_exact for item in self.task_ceilings
        )
        hard_ceiling = min(
            Decimal(unconstrained_worst),
            Decimal(self.ledger_baseline.remaining_usd_exact),
        )
        expected_costs = (
            _format_decimal(min(Decimal(unconstrained_standard), hard_ceiling)),
            _format_decimal(hard_ceiling),
        )
        expected_limited = Decimal(unconstrained_worst) > hard_ceiling
        retryable_ceilings = tuple(
            item
            for item in self.task_ceilings
            if item.maximum_task_count > 0
            and item.task_class is not PrepurchaseQuoteTaskClass.TRUNCATION_RECOVERY
        )
        if (
            self.local_analysis_ceiling.analysis_input_sha256
            != self.target_binding.analysis_input_sha256
            or self.planned_role_count != _maximum_distinct_runtime_role_count(self.task_ceilings)
            or self.planned_model_count
            != len({item.requested_model for item in self.task_ceilings if item.requested_model})
            or not retryable_ceilings
            or any(
                item.maximum_attempts_per_task != self.retry_policy.maximum_attempts
                for item in retryable_ceilings
            )
            or self.maximum_request_count
            != sum(item.worst_case_request_count for item in self.task_ceilings)
            or self.maximum_input_tokens
            != sum(
                item.worst_case_request_count * item.maximum_input_tokens_per_attempt
                for item in self.task_ceilings
            )
            or self.maximum_output_tokens
            != sum(
                item.worst_case_request_count * item.maximum_output_tokens_per_attempt
                for item in self.task_ceilings
            )
            or self.unconstrained_workflow_worst_usd_exact != unconstrained_worst
            or self.hard_budget_limited is not expected_limited
            or self.cost_range.standard_bound_usd_exact != expected_costs[0]
            or self.cost_range.worst_case_usd_exact != expected_costs[1]
            or self.wall_clock_range.standard_bound_seconds
            != self.local_analysis_ceiling.standard_wall_clock_seconds
            + sum(item.standard_wall_clock_seconds for item in self.task_ceilings)
            or self.wall_clock_range.worst_case_seconds
            != self.local_analysis_ceiling.maximum_wall_clock_seconds
            + sum(item.worst_case_wall_clock_seconds for item in self.task_ceilings)
            or self.wall_clock_range.standard_local_seconds
            != self.local_analysis_ceiling.standard_wall_clock_seconds
            or self.wall_clock_range.maximum_local_seconds
            != self.local_analysis_ceiling.maximum_wall_clock_seconds
        ):
            raise ValueError("quote aggregate bounds differ from their exact task ceilings")
        _require_self_hash(self, "quote_sha256")
        return self


class AcceptedPrepurchaseQuote(_FrozenNonAuthorizingArtifact):
    """Explicit buyer acceptance which constrains, but never authorizes, one run."""

    artifact_kind: Literal["accepted_prepurchase_quote"] = "accepted_prepurchase_quote"
    schema_version: Literal["1.1"] = "1.1"
    quote: PrepurchaseQuote
    quote_sha256: str = Field(pattern=_SHA256_PATTERN)
    accepted_at: datetime
    run_hard_ceiling_usd_exact: str
    acceptance_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("accepted_at")
    @classmethod
    def timestamp_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value, label="quote acceptance timestamp")

    @field_validator("run_hard_ceiling_usd_exact")
    @classmethod
    def hard_ceiling_is_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="accepted run hard ceiling")

    @model_validator(mode="after")
    def acceptance_is_exact_nonauthorizing_and_self_hashed(self) -> Self:
        if (
            self.quote_sha256 != self.quote.quote_sha256
            or self.run_hard_ceiling_usd_exact != self.quote.cost_range.worst_case_usd_exact
        ):
            raise ValueError("accepted quote does not bind its exact hard spend ceiling")
        _require_self_hash(self, "acceptance_sha256")
        return self


class PrepurchaseQuoteReconciliation(_FrozenNonAuthorizingArtifact):
    """Terminal actual-versus-quote comparison from exact run ledger evidence."""

    artifact_kind: Literal["prepurchase_quote_reconciliation"] = "prepurchase_quote_reconciliation"
    schema_version: Literal["1.1"] = "1.1"
    acceptance: AcceptedPrepurchaseQuote
    acceptance_sha256: str = Field(pattern=_SHA256_PATTERN)
    quote_sha256: str = Field(pattern=_SHA256_PATTERN)
    ledger_evidence_canonical_json: str = Field(min_length=2, max_length=100_000_000)
    ledger_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    reconciled_at: datetime
    status: PrepurchaseQuoteReconciliationStatus
    inconclusive_reason: PrepurchaseQuoteInconclusiveReason | None = None
    actual_cost_usd_exact: str | None = None
    standard_delta_relation: PrepurchaseQuoteDeltaRelation | None = None
    standard_delta_usd_exact: str | None = None
    worst_case_delta_relation: PrepurchaseQuoteDeltaRelation | None = None
    worst_case_delta_usd_exact: str | None = None
    within_worst_case: bool | None = None
    reconciliation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("reconciled_at")
    @classmethod
    def timestamp_is_utc(cls, value: datetime) -> datetime:
        return _require_utc(value, label="quote reconciliation timestamp")

    @field_validator(
        "actual_cost_usd_exact",
        "standard_delta_usd_exact",
        "worst_case_delta_usd_exact",
    )
    @classmethod
    def optional_amounts_are_canonical(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _canonical_decimal_text(value, label="quote reconciliation amount")

    @model_validator(mode="after")
    def reconciliation_is_exact_and_self_hashed(self) -> Self:
        baseline = self.acceptance.quote.ledger_baseline
        evidence = self.ledger_evidence()
        if (
            self.acceptance_sha256 != self.acceptance.acceptance_sha256
            or self.quote_sha256 != self.acceptance.quote_sha256
            or self.ledger_evidence_sha256 != evidence.evidence_sha256
            or evidence.schema_version != "1.1"
            or evidence.campaign_id != self.acceptance.quote.target_binding.scheduler_campaign_id
            or evidence.campaign_manifest_sha256
            != self.acceptance.quote.target_binding.scheduler_manifest_sha256
            or evidence.baseline_sha256 != baseline.baseline_sha256
            or evidence.baseline_snapshot_sha256 != baseline.ledger_snapshot_sha256
            or evidence.cap_usd_exact != baseline.cap_usd_exact
            or evidence.baseline_spent_usd_exact != baseline.spent_usd_exact
            or evidence.baseline_active_reserved_usd_exact != baseline.active_reserved_usd_exact
            or self.reconciled_at < self.acceptance.accepted_at
        ):
            raise ValueError("quote reconciliation custody differs from acceptance or ledger")
        expected_reason = _ledger_inconclusive_reason(evidence)
        conclusive = expected_reason is None
        optional_values = (
            self.actual_cost_usd_exact,
            self.standard_delta_relation,
            self.standard_delta_usd_exact,
            self.worst_case_delta_relation,
            self.worst_case_delta_usd_exact,
            self.within_worst_case,
        )
        if conclusive:
            actual = evidence.run_accounted_cost_usd_exact
            standard_relation, standard_delta = _cost_delta(
                actual,
                self.acceptance.quote.cost_range.standard_bound_usd_exact,
            )
            worst_relation, worst_delta = _cost_delta(
                actual,
                self.acceptance.run_hard_ceiling_usd_exact,
            )
            expected_values = (
                actual,
                standard_relation,
                standard_delta,
                worst_relation,
                worst_delta,
                Decimal(actual) <= Decimal(self.acceptance.run_hard_ceiling_usd_exact),
            )
            if (
                self.status is not PrepurchaseQuoteReconciliationStatus.CONCLUSIVE
                or self.inconclusive_reason is not None
                or optional_values != expected_values
            ):
                raise ValueError("conclusive quote reconciliation deltas are inconsistent")
        elif (
            self.status is not PrepurchaseQuoteReconciliationStatus.INCONCLUSIVE
            or self.inconclusive_reason is not expected_reason
            or any(value is not None for value in optional_values)
        ):
            raise ValueError("uncertain or overrun accounting cannot claim actual quote deltas")
        _require_self_hash(self, "reconciliation_sha256")
        return self

    def ledger_evidence(self) -> RunCostLedgerEvidence:
        """Return a fresh strict ledger model from the exact embedded JSON."""

        from mmaudit.reporting.bundle import RunCostLedgerEvidence

        evidence = RunCostLedgerEvidence.model_validate_json(
            self.ledger_evidence_canonical_json,
            strict=True,
        )
        if self.ledger_evidence_canonical_json != _canonical_json_text(
            evidence.model_dump(mode="json")
        ):
            raise ValueError("quote reconciliation ledger evidence JSON is not canonical")
        return evidence


_PORTFOLIO_TASK_CLASS = {
    ModelPortfolioTaskKind.ORIENTATION: PrepurchaseQuoteTaskClass.ORIENTATION,
    ModelPortfolioTaskKind.COMPACT_COVERAGE: PrepurchaseQuoteTaskClass.COMPACT_COVERAGE,
    ModelPortfolioTaskKind.SOURCE_AUDIT: PrepurchaseQuoteTaskClass.SOURCE_AUDIT,
    ModelPortfolioTaskKind.WHOLE_PROTOCOL: PrepurchaseQuoteTaskClass.WHOLE_PROTOCOL,
    ModelPortfolioTaskKind.INVARIANT_REVIEW: PrepurchaseQuoteTaskClass.INVARIANT_REVIEW,
    ModelPortfolioTaskKind.REPORT_QUALITY: PrepurchaseQuoteTaskClass.REPORT_QUALITY,
}

if set(_PORTFOLIO_TASK_CLASS) != set(ModelPortfolioTaskKind):
    raise RuntimeError("pre-purchase quote mapping does not cover every portfolio task kind")


def _task_ceiling_identity(ceiling: PrepurchaseQuoteTaskCeiling) -> tuple[str, ...]:
    return (
        ceiling.task_class.value,
        ceiling.request_role or "",
        ceiling.runtime_role_kind.value if ceiling.runtime_role_kind is not None else "",
        str(ceiling.maximum_distinct_runtime_roles),
        ceiling.requested_model or "",
        ceiling.request_envelope_recipe_sha256 or "",
        ceiling.endpoint_policy_snapshot_sha256 or "",
        ceiling.endpoint_policy_pricing_sha256 or "",
        ceiling.provider_endpoint or "",
        ceiling.endpoint_pricing_snapshot_sha256 or "",
    )


def _task_ceiling_sort_key(ceiling: PrepurchaseQuoteTaskCeiling) -> tuple[str, ...]:
    return _task_ceiling_identity(ceiling)


def _maximum_distinct_runtime_role_count(
    ceilings: Iterable[PrepurchaseQuoteTaskCeiling],
) -> int:
    materialized = tuple(ceilings)
    exact_roles = {
        item.request_role
        for item in materialized
        if item.runtime_role_kind is PrepurchaseQuoteRuntimeRoleKind.EXACT
        and item.request_role is not None
    }
    dynamic_roles = sum(
        item.maximum_distinct_runtime_roles
        for item in materialized
        if item.task_class is not PrepurchaseQuoteTaskClass.TRUNCATION_RECOVERY
        and item.runtime_role_kind
        is PrepurchaseQuoteRuntimeRoleKind.CANDIDATE_FALSIFIER_SHA256_REVIEWER
    )
    return len(exact_roles) + dynamic_roles


def _envelope_identity(envelope: ModelPortfolioTaskResourceEnvelope) -> tuple[str, ...]:
    return (
        _PORTFOLIO_TASK_CLASS[envelope.task_kind].value,
        envelope.request_role,
        PrepurchaseQuoteRuntimeRoleKind.EXACT.value,
        "1",
        envelope.requested_model,
        envelope.request_envelope_recipe_sha256,
        envelope.endpoint_policy_snapshot_sha256,
        envelope.endpoint_policy_pricing_sha256,
        envelope.provider_endpoint,
        envelope.endpoint_pricing_snapshot_sha256,
    )


def _validated_ceilings(
    task_ceilings: Iterable[PrepurchaseQuoteTaskCeiling],
) -> tuple[PrepurchaseQuoteTaskCeiling, ...]:
    if isinstance(task_ceilings, str | bytes | bytearray):
        raise ValueError("quote task ceilings must be an iterable of typed records")
    ceilings: list[PrepurchaseQuoteTaskCeiling] = []
    for item in task_ceilings:
        if len(ceilings) >= MAX_QUOTE_TASK_CEILINGS:
            raise ValueError("quote task ceilings exceed their bounded maximum")
        if type(item) is not PrepurchaseQuoteTaskCeiling:
            raise TypeError("quote task ceilings require exact typed records")
        ceilings.append(PrepurchaseQuoteTaskCeiling.model_validate(item.model_dump(mode="python")))
    canonical = tuple(sorted(ceilings, key=_task_ceiling_sort_key))
    identities = tuple(_task_ceiling_identity(item) for item in canonical)
    if len(identities) != len(set(identities)):
        raise ValueError("quote task ceilings repeat a route identity")
    if {item.task_class for item in canonical} != set(PrepurchaseQuoteTaskClass):
        raise ValueError("quote task ceilings must explicitly cover every paid task class")
    return canonical


def _validate_scheduler_shard_join(
    manifest: SchedulerCampaignManifest,
    inventory: SolidityShardInventory,
) -> None:
    if (
        manifest.shard_inventory.semantic_inventory_sha256 != inventory.inventory_sha256
        or manifest.bindings.shard_inventory_sha256 != manifest.shard_inventory.inventory_sha256
    ):
        raise ValueError("quote scheduler manifest differs from the Solidity shard inventory")
    expected_semantic = {shard.shard_id: shard.shard_sha256 for shard in inventory.shards}
    observed_semantic = {
        shard.shard_id: shard.semantic_shard_sha256
        for shard in manifest.shard_inventory.shards
        if shard.semantic_shard_sha256 is not None
    }
    if observed_semantic != expected_semantic:
        raise ValueError("quote scheduler semantic shards differ from their exact inventory")


def _validate_portfolio_join(
    manifest: SchedulerCampaignManifest,
    preflight: ModelPortfolioResourcePreflight,
    ceilings: tuple[PrepurchaseQuoteTaskCeiling, ...],
) -> None:
    if (
        not preflight.feasible
        or preflight.failure_codes
        or preflight.campaign_manifest_sha256 != manifest.manifest_sha256
    ):
        raise ValueError("quote requires a feasible portfolio preflight for the exact campaign")
    ceilings_by_identity = {_task_ceiling_identity(item): item for item in ceilings}
    envelope_counts = Counter(_envelope_identity(item) for item in preflight.task_envelopes)
    for identity, count in envelope_counts.items():
        ceiling = ceilings_by_identity.get(identity)
        if ceiling is None:
            raise ValueError("quote task ceilings omit an exact early portfolio route")
        matching = tuple(
            item for item in preflight.task_envelopes if _envelope_identity(item) == identity
        )
        if (
            ceiling.standard_task_count < count
            or ceiling.maximum_task_count < count
            or any(
                item.maximum_attempts > ceiling.maximum_attempts_per_task
                or item.maximum_prompt_tokens_per_attempt > ceiling.maximum_input_tokens_per_attempt
                or item.maximum_completion_tokens_per_attempt
                > ceiling.maximum_output_tokens_per_attempt
                or Decimal(item.maximum_cost_usd_per_attempt_exact)
                > Decimal(ceiling.maximum_cost_usd_per_attempt_exact)
                for item in matching
            )
        ):
            raise ValueError("quote task ceiling understates an exact early portfolio envelope")


def _build_target_binding(
    manifest: SchedulerCampaignManifest,
    inventory: SolidityShardInventory,
) -> PrepurchaseQuoteTargetBinding:
    repository_sources = tuple(
        source for shard in manifest.shard_inventory.shards for source in shard.sources
    )
    values = {
        "artifact_kind": "prepurchase_quote_target_binding",
        "schema_version": "1.0",
        "source_sha256": manifest.bindings.source_sha256,
        "analysis_input_sha256": manifest.bindings.analysis_input_sha256,
        "effective_config_sha256": manifest.bindings.effective_config_sha256,
        "audit_selected_model_set_sha256": (
            manifest.bindings.audit_model_selection.selected_model_set_sha256
            if manifest.bindings.audit_model_selection is not None
            else None
        ),
        "scheduler_campaign_id": manifest.campaign_id,
        "scheduler_manifest_sha256": manifest.manifest_sha256,
        "scheduler_bindings_sha256": manifest.bindings.bindings_sha256,
        "scheduler_shard_inventory_sha256": manifest.shard_inventory.inventory_sha256,
        "solidity_shard_inventory_sha256": inventory.inventory_sha256,
        "source_inventory_sha256": inventory.source_inventory_sha256,
        "symbol_index_context_sha256": inventory.symbol_index_context_sha256,
        "symbol_index_sha256": inventory.symbol_index_sha256,
        "symbol_index_projection_sha256": inventory.symbol_index_projection_sha256,
        "graph_set_context_sha256": inventory.graph_set_context_sha256,
        "graph_set_sha256": inventory.graph_set_sha256,
        "graph_set_projection_sha256": inventory.graph_set_projection_sha256,
        "repository_source_count": manifest.shard_inventory.source_count,
        "repository_source_bytes": sum(item.size for item in repository_sources),
        "solidity_source_count": len(inventory.source_units),
        "solidity_source_bytes": sum(item.utf8_bytes for item in inventory.source_units),
        "indexed_entity_count": len(inventory.entity_ids),
        "graph_node_count": len(inventory.graph_node_ids),
        "graph_edge_count": len(inventory.graph_edge_ids),
        "storage_entry_count": len(inventory.storage_entry_ids),
        "scheduler_shard_count": len(manifest.shard_inventory.shards),
        "solidity_shard_count": len(inventory.shards),
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "grants_release_authority": False,
    }
    return PrepurchaseQuoteTargetBinding.model_validate(
        {**values, "target_binding_sha256": _canonical_sha256(values)}
    )


def _build_ledger_baseline(
    manifest: SchedulerCampaignManifest,
) -> PrepurchaseQuoteLedgerBaselineBinding:
    baseline = manifest.cost_ledger_baseline
    if baseline is None:
        raise ValueError("quote requires an exact persistent cost-ledger baseline")
    remaining = _subtract_nonnegative_decimal_text(
        baseline.cap_usd_exact,
        _sum_decimal_text((baseline.spent_usd_exact, baseline.active_reserved_usd_exact)),
    )
    values = {
        "artifact_kind": "prepurchase_quote_ledger_baseline",
        "schema_version": "1.0",
        "baseline_sha256": baseline.baseline_sha256,
        "ledger_snapshot_sha256": baseline.ledger_snapshot_sha256,
        "ledger_identity_sha256": baseline.ledger_identity_sha256,
        "cap_usd_exact": _canonical_decimal_text(
            baseline.cap_usd_exact,
            label="quote baseline cap",
        ),
        "spent_usd_exact": _canonical_decimal_text(
            baseline.spent_usd_exact,
            label="quote baseline spent amount",
        ),
        "active_reserved_usd_exact": _canonical_decimal_text(
            baseline.active_reserved_usd_exact,
            label="quote baseline active reservation",
        ),
        "remaining_usd_exact": remaining,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "grants_release_authority": False,
    }
    return PrepurchaseQuoteLedgerBaselineBinding.model_validate(
        {**values, "baseline_binding_sha256": _canonical_sha256(values)}
    )


def _build_cost_range(
    ceilings: tuple[PrepurchaseQuoteTaskCeiling, ...],
    ledger_baseline: PrepurchaseQuoteLedgerBaselineBinding,
) -> PrepurchaseQuoteCostRange:
    unconstrained_standard = _sum_decimal_text(item.standard_cost_usd_exact for item in ceilings)
    unconstrained_worst = _sum_decimal_text(item.worst_case_cost_usd_exact for item in ceilings)
    hard_ceiling = min(
        Decimal(unconstrained_worst),
        Decimal(ledger_baseline.remaining_usd_exact),
    )
    values = {
        "artifact_kind": "prepurchase_quote_cost_range",
        "schema_version": "1.0",
        "lower_bound_usd_exact": "0",
        "standard_bound_usd_exact": _format_decimal(
            min(Decimal(unconstrained_standard), hard_ceiling)
        ),
        "worst_case_usd_exact": _format_decimal(hard_ceiling),
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "grants_release_authority": False,
    }
    return PrepurchaseQuoteCostRange.model_validate(
        {**values, "range_sha256": _canonical_sha256(values)}
    )


def _build_wall_clock_range(
    ceilings: tuple[PrepurchaseQuoteTaskCeiling, ...],
    local_analysis: PrepurchaseQuoteLocalAnalysisCeiling,
) -> PrepurchaseQuoteWallClockRange:
    standard_paid = sum(item.standard_wall_clock_seconds for item in ceilings)
    maximum_paid = sum(item.worst_case_wall_clock_seconds for item in ceilings)
    values = {
        "artifact_kind": "prepurchase_quote_wall_clock_range",
        "schema_version": "1.0",
        "lower_bound_seconds": 0,
        "standard_local_seconds": local_analysis.standard_wall_clock_seconds,
        "maximum_local_seconds": local_analysis.maximum_wall_clock_seconds,
        "standard_paid_task_seconds": standard_paid,
        "maximum_paid_task_seconds": maximum_paid,
        "standard_bound_seconds": local_analysis.standard_wall_clock_seconds + standard_paid,
        "worst_case_seconds": local_analysis.maximum_wall_clock_seconds + maximum_paid,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "grants_release_authority": False,
    }
    return PrepurchaseQuoteWallClockRange.model_validate(
        {**values, "range_sha256": _canonical_sha256(values)}
    )


def build_prepurchase_quote(
    *,
    campaign_manifest: SchedulerCampaignManifest,
    solidity_shard_inventory: SolidityShardInventory,
    portfolio_preflight: ModelPortfolioResourcePreflight,
    local_analysis_ceiling: PrepurchaseQuoteLocalAnalysisCeiling,
    retry_policy: ModelRetryPolicy,
    task_ceilings: Iterable[PrepurchaseQuoteTaskCeiling],
) -> PrepurchaseQuote:
    """Build a complete local quote or refuse any missing/inconsistent bound."""

    from mmaudit.models.scheduler import SchedulerCampaignManifest

    if type(campaign_manifest) is not SchedulerCampaignManifest:
        raise TypeError("quote requires an exact scheduler campaign manifest")
    if type(solidity_shard_inventory) is not SolidityShardInventory:
        raise TypeError("quote requires an exact Solidity shard inventory")
    if type(portfolio_preflight) is not ModelPortfolioResourcePreflight:
        raise TypeError("quote requires an exact model portfolio resource preflight")
    if type(local_analysis_ceiling) is not PrepurchaseQuoteLocalAnalysisCeiling:
        raise TypeError("quote requires an exact local-analysis wall-clock ceiling")
    if type(retry_policy) is not ModelRetryPolicy:
        raise TypeError("quote requires an exact split retry policy")
    manifest = SchedulerCampaignManifest.model_validate(campaign_manifest.model_dump(mode="python"))
    inventory = SolidityShardInventory.model_validate(
        solidity_shard_inventory.model_dump(mode="python")
    )
    preflight = ModelPortfolioResourcePreflight.model_validate(
        portfolio_preflight.model_dump(mode="python")
    )
    local_analysis = PrepurchaseQuoteLocalAnalysisCeiling.model_validate(
        local_analysis_ceiling.model_dump(mode="python")
    )
    exact_retry_policy = ModelRetryPolicy.model_validate(
        retry_policy.model_dump(mode="python"),
        strict=True,
    )
    ceilings = _validated_ceilings(task_ceilings)
    _validate_scheduler_shard_join(manifest, inventory)
    _validate_portfolio_join(manifest, preflight, ceilings)
    if local_analysis.analysis_input_sha256 != manifest.bindings.analysis_input_sha256:
        raise ValueError("local-analysis quote ceiling differs from scheduler analysis input")
    target = _build_target_binding(manifest, inventory)
    ledger_baseline = _build_ledger_baseline(manifest)
    cost_range = _build_cost_range(ceilings, ledger_baseline)
    wall_clock_range = _build_wall_clock_range(ceilings, local_analysis)
    unconstrained_worst = _sum_decimal_text(item.worst_case_cost_usd_exact for item in ceilings)
    hard_budget_limited = Decimal(unconstrained_worst) > Decimal(cost_range.worst_case_usd_exact)
    values = {
        "artifact_kind": "prepurchase_quote",
        "schema_version": "1.1",
        "target_binding": target,
        "ledger_baseline": ledger_baseline,
        "local_analysis_ceiling": local_analysis,
        "retry_policy": exact_retry_policy,
        "portfolio_preflight_sha256": preflight.preflight_sha256,
        "task_ceilings": ceilings,
        "covered_task_classes": tuple(PrepurchaseQuoteTaskClass),
        # Candidate-specific reviewer roles do not exist until candidates do, so
        # their bounded multiplicity is represented separately from exact roles.
        "planned_role_count": _maximum_distinct_runtime_role_count(ceilings),
        "planned_model_count": len(
            {item.requested_model for item in ceilings if item.requested_model is not None}
        ),
        "maximum_request_count": sum(item.worst_case_request_count for item in ceilings),
        "maximum_input_tokens": sum(
            item.worst_case_request_count * item.maximum_input_tokens_per_attempt
            for item in ceilings
        ),
        "maximum_output_tokens": sum(
            item.worst_case_request_count * item.maximum_output_tokens_per_attempt
            for item in ceilings
        ),
        "unconstrained_workflow_worst_usd_exact": unconstrained_worst,
        "hard_budget_limited": hard_budget_limited,
        "completion_within_hard_ceiling_guaranteed": False,
        "cost_range": cost_range,
        "wall_clock_range": wall_clock_range,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "grants_release_authority": False,
    }
    return PrepurchaseQuote.model_validate({**values, "quote_sha256": _canonical_sha256(values)})


def accept_prepurchase_quote(
    quote: PrepurchaseQuote,
    *,
    accepted_at: datetime,
) -> AcceptedPrepurchaseQuote:
    """Record explicit nonauthorizing acceptance of the quote's exact hard ceiling."""

    if type(quote) is not PrepurchaseQuote:
        raise TypeError("quote acceptance requires an exact pre-purchase quote")
    exact_quote = PrepurchaseQuote.model_validate(quote.model_dump(mode="python"))
    timestamp = _require_utc(accepted_at, label="quote acceptance timestamp")
    values = {
        "artifact_kind": "accepted_prepurchase_quote",
        "schema_version": "1.1",
        "quote": exact_quote,
        "quote_sha256": exact_quote.quote_sha256,
        "accepted_at": timestamp,
        "run_hard_ceiling_usd_exact": exact_quote.cost_range.worst_case_usd_exact,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "grants_release_authority": False,
    }
    return AcceptedPrepurchaseQuote.model_validate(
        {**values, "acceptance_sha256": _canonical_sha256(values)}
    )


def _ledger_inconclusive_reason(
    evidence: RunCostLedgerEvidence,
) -> PrepurchaseQuoteInconclusiveReason | None:
    statuses = {item.status.value for item in evidence.attempts}
    if (
        "reservation_overrun" in statuses
        or evidence.baseline_has_reservation_overrun
        or evidence.final_has_reservation_overrun
        or evidence.final_over_cap
    ):
        return PrepurchaseQuoteInconclusiveReason.RESERVATION_OVERRUN
    if "uncertain_accounted" in statuses:
        return PrepurchaseQuoteInconclusiveReason.UNCERTAIN_ACCOUNTING
    if not statuses <= {"reconciled", "released"}:
        raise ValueError("run ledger evidence contains an unsupported terminal status")
    return None


def _cost_delta(
    actual: str,
    bound: str,
) -> tuple[PrepurchaseQuoteDeltaRelation, str]:
    actual_value = Decimal(actual)
    bound_value = Decimal(bound)
    if actual_value < bound_value:
        return (
            PrepurchaseQuoteDeltaRelation.UNDER,
            _format_decimal(bound_value - actual_value),
        )
    if actual_value > bound_value:
        return (
            PrepurchaseQuoteDeltaRelation.OVER,
            _format_decimal(actual_value - bound_value),
        )
    return PrepurchaseQuoteDeltaRelation.EXACT, "0"


def reconcile_prepurchase_quote(
    acceptance: AcceptedPrepurchaseQuote,
    ledger_evidence: RunCostLedgerEvidence,
    *,
    reconciled_at: datetime,
) -> PrepurchaseQuoteReconciliation:
    """Compare a terminal run ledger with its accepted quote, or remain inconclusive."""

    from mmaudit.reporting.bundle import RunCostLedgerEvidence

    if type(acceptance) is not AcceptedPrepurchaseQuote:
        raise TypeError("quote reconciliation requires an exact accepted quote")
    if type(ledger_evidence) is not RunCostLedgerEvidence:
        raise TypeError("quote reconciliation requires exact run cost-ledger evidence")
    exact_acceptance = AcceptedPrepurchaseQuote.model_validate(acceptance.model_dump(mode="python"))
    evidence = RunCostLedgerEvidence.model_validate(ledger_evidence.model_dump(mode="python"))
    timestamp = _require_utc(reconciled_at, label="quote reconciliation timestamp")
    baseline = exact_acceptance.quote.ledger_baseline
    if (
        evidence.schema_version != "1.1"
        or evidence.campaign_id != exact_acceptance.quote.target_binding.scheduler_campaign_id
        or evidence.campaign_manifest_sha256
        != exact_acceptance.quote.target_binding.scheduler_manifest_sha256
        or evidence.baseline_sha256 != baseline.baseline_sha256
        or evidence.baseline_snapshot_sha256 != baseline.ledger_snapshot_sha256
        or evidence.cap_usd_exact != baseline.cap_usd_exact
        or evidence.baseline_spent_usd_exact != baseline.spent_usd_exact
        or evidence.baseline_active_reserved_usd_exact != baseline.active_reserved_usd_exact
    ):
        raise ValueError("run ledger evidence does not begin at the accepted quote baseline")
    if timestamp < exact_acceptance.accepted_at:
        raise ValueError("quote reconciliation timestamp precedes acceptance")
    reason = _ledger_inconclusive_reason(evidence)
    values: dict[str, Any] = {
        "artifact_kind": "prepurchase_quote_reconciliation",
        "schema_version": "1.1",
        "acceptance": exact_acceptance,
        "acceptance_sha256": exact_acceptance.acceptance_sha256,
        "quote_sha256": exact_acceptance.quote_sha256,
        "ledger_evidence_canonical_json": _canonical_json_text(evidence.model_dump(mode="json")),
        "ledger_evidence_sha256": evidence.evidence_sha256,
        "reconciled_at": timestamp,
        "status": (
            PrepurchaseQuoteReconciliationStatus.CONCLUSIVE
            if reason is None
            else PrepurchaseQuoteReconciliationStatus.INCONCLUSIVE
        ),
        "inconclusive_reason": reason,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "grants_release_authority": False,
    }
    if reason is None:
        actual = evidence.run_accounted_cost_usd_exact
        standard_relation, standard_delta = _cost_delta(
            actual,
            exact_acceptance.quote.cost_range.standard_bound_usd_exact,
        )
        worst_relation, worst_delta = _cost_delta(
            actual,
            exact_acceptance.run_hard_ceiling_usd_exact,
        )
        values.update(
            {
                "actual_cost_usd_exact": actual,
                "standard_delta_relation": standard_relation,
                "standard_delta_usd_exact": standard_delta,
                "worst_case_delta_relation": worst_relation,
                "worst_case_delta_usd_exact": worst_delta,
                "within_worst_case": Decimal(actual)
                <= Decimal(exact_acceptance.run_hard_ceiling_usd_exact),
            }
        )
    else:
        values.update(
            {
                "actual_cost_usd_exact": None,
                "standard_delta_relation": None,
                "standard_delta_usd_exact": None,
                "worst_case_delta_relation": None,
                "worst_case_delta_usd_exact": None,
                "within_worst_case": None,
            }
        )
    return PrepurchaseQuoteReconciliation.model_validate(
        {**values, "reconciliation_sha256": _canonical_sha256(values)}
    )


__all__ = [
    "AcceptedPrepurchaseQuote",
    "PrepurchaseQuote",
    "PrepurchaseQuoteCostRange",
    "PrepurchaseQuoteDeltaRelation",
    "PrepurchaseQuoteInconclusiveReason",
    "PrepurchaseQuoteLedgerBaselineBinding",
    "PrepurchaseQuoteLocalAnalysisCeiling",
    "PrepurchaseQuoteReconciliation",
    "PrepurchaseQuoteReconciliationStatus",
    "PrepurchaseQuoteRuntimeRoleKind",
    "PrepurchaseQuoteTargetBinding",
    "PrepurchaseQuoteTaskCeiling",
    "PrepurchaseQuoteTaskClass",
    "PrepurchaseQuoteWallClockRange",
    "accept_prepurchase_quote",
    "build_prepurchase_quote",
    "reconcile_prepurchase_quote",
]
