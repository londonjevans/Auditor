"""Provider-free runtime joins for pinned model-refresh and pricing evidence.

Durable values in this module are comparison evidence only. They cannot select a
model, authorize provider access, or promote a discovered candidate. The freshness
guard remains veto-only; bounded refreshed-price use requires a separate opaque live
capability plus the exact process-local production and audit-selection capabilities.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Context, Decimal, localcontext
from typing import Annotated, Any, Literal, Never, Self, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    OpenRouterPricingOverrideTier,
    canonicalize_openrouter_pricing,
    canonicalize_openrouter_pricing_schedule,
    effective_openrouter_pricing,
    openrouter_pricing_schedule_sha256,
    project_openrouter_pricing_schedule,
)
from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.policy_selection import (
    AuditModelSelectionEvidenceBundle,
    VerifiedAuditModelSelection,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    LineageReviewStatus,
    VerifiedProductionQualification,
    VerifiedTierAModelQualification,
)
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    CANDIDATE_REGISTRY_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    MAX_MODEL_REFRESH_FRACTION_TEXT_LENGTH,
    MODEL_REFRESH_FRACTION_PATTERN,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    LiveProviderRouteState,
    ModelRefreshAttemptStatus,
    ModelRefreshFreshnessState,
    ModelRefreshSnapshot,
    RefreshBaselineKind,
    SelectedModelRoute,
    build_model_refresh_snapshot_from_source,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    parse_model_refresh_fraction,
    validate_model_refresh_controls,
)
from mmaudit.models.refresh_staging import (
    PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
    PREVIOUS_SNAPSHOT_FILENAME,
    PREVIOUS_SOURCE_EVIDENCE_FILENAME,
    PREVIOUS_WORKFLOW_STATUS_FILENAME,
    ModelRefreshWorkflowDisposition,
    ModelRefreshWorkflowStatus,
    ValidatedModelRefreshHistory,
)
from mmaudit.models.route_constraints import ExactRoutePricingSchedule

AUDIT_MODEL_REFRESH_EVIDENCE_FILENAME = "audit-model-refresh-evidence.json"
AUDIT_MODEL_REFRESH_PRICING_EVIDENCE_FILENAME = "audit-model-refresh-pricing-evidence.json"

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_LINEAGE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
_PROVIDER_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/()&+-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_GIT_COMMIT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_WORKFLOW_NUMBER_PATTERN = r"^[1-9][0-9]{0,19}$"
_PRICING_FIELD_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_CANONICAL_PRICE_PATTERN = r"^(?:0|[1-9][0-9]{0,11}|(?:0|[1-9][0-9]{0,11})\.[0-9]{0,35}[1-9])$"
_MAX_MODELS = 128
_MAX_PRICING_FIELDS = 64
_PRICING_COMPARISON_CONTEXT = Context(prec=160)
_STATUS_CLOCK_SKEW = timedelta(minutes=5)
_JSON_ADAPTER = TypeAdapter(Any)
_PricingField = Annotated[str, Field(min_length=1, max_length=64, pattern=_PRICING_FIELD_PATTERN)]
_CanonicalPrice = Annotated[
    str,
    Field(min_length=1, max_length=49, pattern=_CANONICAL_PRICE_PATTERN),
]
_PricingMap = dict[_PricingField, _CanonicalPrice]


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        _JSON_ADAPTER.dump_python(value, mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ValueError(f"{label} must be a whole-second UTC timestamp")
    return value


def _require_sha256(value: str, *, label: str) -> str:
    if type(value) is not str or re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_canonical_pricing(
    value: _PricingMap,
    *,
    label: str,
) -> _PricingMap:
    """Reject any price map that is not the exact shared canonical projection."""

    try:
        canonical = canonicalize_openrouter_pricing(value)
    except EndpointSnapshotValidationError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if tuple(value) != tuple(sorted(value)) or canonical != value:
        raise ValueError(f"{label} is not canonical")
    return value


def _price_exceeds_tolerance(*, old: str, new: str, tolerance: Decimal) -> bool:
    """Compare canonical prices without inheriting the process Decimal context."""

    with localcontext(_PRICING_COMPARISON_CONTEXT):
        return Decimal(new) > Decimal(old) * (Decimal(1) + tolerance)


def _pricing_schedule_payload(
    pricing: _PricingMap,
    overrides: tuple[OpenRouterPricingOverrideTier, ...],
) -> dict[str, Any]:
    """Reconstruct the shared provider schedule shape for canonical replay."""

    payload: dict[str, Any] = dict(pricing)
    if overrides:
        payload["overrides"] = [
            {
                "min_prompt_tokens": tier.min_prompt_tokens,
                **tier.prices,
            }
            for tier in overrides
        ]
    return payload


def _require_canonical_pricing_schedule(
    *,
    pricing: _PricingMap,
    overrides: tuple[OpenRouterPricingOverrideTier, ...],
    schedule: ExactRoutePricingSchedule | None,
    label: str,
) -> None:
    """Require exact ordered tiers and their shared conservative projection."""

    try:
        canonical_pricing, canonical_overrides = canonicalize_openrouter_pricing_schedule(
            _pricing_schedule_payload(pricing, overrides)
        )
    except EndpointSnapshotValidationError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if canonical_pricing != pricing or canonical_overrides != overrides:
        raise ValueError(f"{label} is not canonical")
    expected_schedule = (
        project_openrouter_pricing_schedule(pricing, overrides) if overrides else None
    )
    if expected_schedule == "unavailable":
        raise ValueError(f"{label} cost projection is unavailable")
    if schedule != expected_schedule:
        raise ValueError(f"{label} cost projection is inconsistent")


def _maximum_pricing(
    pricing: _PricingMap,
    schedule: ExactRoutePricingSchedule | None,
) -> _PricingMap:
    if schedule is None:
        return pricing
    return {item.component.value: item.unit_price for item in schedule.maximum_pricing}


def _compare_pricing_schedules(
    *,
    baseline_pricing: _PricingMap,
    baseline_overrides: tuple[OpenRouterPricingOverrideTier, ...],
    baseline_schedule: ExactRoutePricingSchedule | None,
    current_pricing: _PricingMap,
    current_overrides: tuple[OpenRouterPricingOverrideTier, ...],
    current_schedule: ExactRoutePricingSchedule | None,
    tolerance: Decimal,
) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    """Compare every reachable strict-threshold state and each conservative maximum."""

    checkpoints = tuple(
        sorted(
            {
                0,
                *(
                    tier.min_prompt_tokens + 1
                    for tier in (*baseline_overrides, *current_overrides)
                    if tier.min_prompt_tokens < 2**31 - 1
                ),
            }
        )
    )
    comparisons = [
        (
            effective_openrouter_pricing(
                baseline_pricing,
                baseline_overrides,
                prompt_tokens=prompt_tokens,
            ),
            effective_openrouter_pricing(
                current_pricing,
                current_overrides,
                prompt_tokens=prompt_tokens,
            ),
        )
        for prompt_tokens in checkpoints
    ]
    if baseline_schedule is not None or current_schedule is not None:
        comparisons.append(
            (
                _maximum_pricing(baseline_pricing, baseline_schedule),
                _maximum_pricing(current_pricing, current_schedule),
            )
        )

    baseline_fields = tuple(_maximum_pricing(baseline_pricing, baseline_schedule))
    current_fields = tuple(_maximum_pricing(current_pricing, current_schedule))
    if baseline_fields != current_fields:
        raise ValueError(
            "refresh pricing schedule has a new, missing, or unsupported price component"
        )
    fields = baseline_fields
    changed: set[str] = set()
    increased: set[str] = set()
    exceeds_tolerance = False
    for baseline_state, current_state in comparisons:
        for field in fields:
            old = baseline_state.get(field, "0")
            new = current_state.get(field, "0")
            if new != old:
                changed.add(field)
            if Decimal(new) > Decimal(old):
                increased.add(field)
            if _price_exceeds_tolerance(old=old, new=new, tolerance=tolerance):
                exceeds_tolerance = True
    return tuple(sorted(changed)), tuple(sorted(increased)), exceeds_tolerance


class AuditModelRefreshRouteEvidence(_FrozenModel):
    """Exact current route projection; possession grants no routing authority."""

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str
    canonical_model_slug: str
    root_lineage: str = Field(pattern=_LINEAGE_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    approved_provider_name: str = Field(pattern=_PROVIDER_NAME_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualified_pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    structured_output_mode: StructuredOutputMode
    approved_roles: tuple[str, ...] = Field(min_length=1, max_length=128)
    benchmark_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_expires_at: datetime
    audit_selected: bool
    refresh_model_state_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_route: LiveProviderRouteState
    runtime_authorized: Literal[False] = False
    route_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_ids_are_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("approved_roles")
    @classmethod
    def roles_are_exact(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(_ROLE_PATTERN, role) is None for role in value
        ):
            raise ValueError("refresh runtime roles must be exact, unique, and sorted")
        return value

    @field_validator("qualification_expires_at")
    @classmethod
    def expiry_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh runtime route qualification expiry")

    @field_validator("audit_selected", "runtime_authorized", mode="before")
    @classmethod
    def booleans_are_literal(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("refresh runtime route booleans must be literal")
        return value

    @model_validator(mode="after")
    def route_is_exact_and_self_hashed(self) -> Self:
        route = self.refresh_route
        if (
            route.exact_model_id != self.exact_model_id
            or route.provider_endpoint != self.approved_provider_endpoint
            or route.provider_name != self.approved_provider_name
            or route.structured_output_mode is not self.structured_output_mode
            or not route.routing_identity_unambiguous
            or not route.operational
            or not route.zdr_eligible
            or not route.discovery_eligible
        ):
            raise ValueError("refresh runtime route differs from exact selected identity")
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"route_evidence_sha256"})
        )
        if self.route_evidence_sha256 != expected:
            raise ValueError("refresh runtime route evidence self-hash is inconsistent")
        return self


class AuditModelRefreshEvidence(_FrozenModel):
    """Pinned refresh comparison evidence that remains permanently non-authorizing."""

    schema_version: Literal["1.0"] = "1.0"
    authority_mode: Literal["VETO_ONLY_EXTERNAL_WORKFLOW_PIN_REQUIRED"] = (
        "VETO_ONLY_EXTERNAL_WORKFLOW_PIN_REQUIRED"
    )
    expected_workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    workflow_run_id: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    workflow_run_attempt: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    previous_workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    semantic_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff_sha256: str = Field(pattern=_SHA256_PATTERN)
    freshness_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_tolerance_fraction: str = Field(
        min_length=1,
        max_length=MAX_MODEL_REFRESH_FRACTION_TEXT_LENGTH,
        pattern=MODEL_REFRESH_FRACTION_PATTERN,
    )
    soft_max_age_hours: int = Field(ge=1, le=24 * 30)
    hard_max_age_hours: int = Field(ge=2, le=24 * 90)
    snapshot_retrieved_at: datetime
    verified_at: datetime
    refresh_current_through: datetime
    technical_qualification_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_expires_at: datetime
    audit_selection_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_expires_at: datetime
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_model_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_MODELS)
    audit_model_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_MODELS)
    routes: tuple[AuditModelRefreshRouteEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_MODELS,
    )
    technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    expires_at: datetime
    technical_selection_authorized: Literal[False] = False
    audit_selection_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False
    production_promotion_authorized: Literal[False] = False
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "snapshot_retrieved_at",
        "verified_at",
        "refresh_current_through",
        "technical_qualification_expires_at",
        "audit_selection_expires_at",
        "expires_at",
    )
    @classmethod
    def times_are_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh runtime evidence time")

    @field_validator("technical_model_ids", "audit_model_ids")
    @classmethod
    def model_ids_are_exact_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        exact = tuple(require_exact_openrouter_model_id(item) for item in value)
        if exact != tuple(sorted(set(exact))):
            raise ValueError("refresh runtime model IDs must be exact, unique, and sorted")
        return exact

    @field_validator(
        "technical_selection_authorized",
        "audit_selection_authorized",
        "provider_access_authorized",
        "production_promotion_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("refresh runtime authority flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def evidence_is_veto_only_and_self_hashed(self) -> Self:
        validate_model_refresh_controls(
            pricing_tolerance_fraction=self.pricing_tolerance_fraction,
            soft_max_age_hours=self.soft_max_age_hours,
            hard_max_age_hours=self.hard_max_age_hours,
        )
        if self.expected_workflow_status_sha256 != self.workflow_status_sha256:
            raise ValueError("refresh runtime evidence differs from its external workflow pin")
        route_ids = tuple(route.exact_model_id for route in self.routes)
        if route_ids != self.technical_model_ids or route_ids != tuple(sorted(set(route_ids))):
            raise ValueError("refresh runtime routes differ from technical production selection")
        selected_ids = tuple(route.exact_model_id for route in self.routes if route.audit_selected)
        if selected_ids != self.audit_model_ids or not set(selected_ids).issubset(route_ids):
            raise ValueError("refresh runtime audit routes differ from audit selection")
        expected_current_through = self.snapshot_retrieved_at + timedelta(
            hours=self.soft_max_age_hours
        )
        if self.refresh_current_through != expected_current_through:
            raise ValueError("refresh runtime soft-freshness boundary is inconsistent")
        expected_expiry = min(
            self.refresh_current_through + timedelta(seconds=1),
            self.technical_qualification_expires_at,
            self.audit_selection_expires_at,
        )
        if self.expires_at != expected_expiry or not self.verified_at < self.expires_at:
            raise ValueError("refresh runtime evidence expiry is inconsistent")
        expected_technical_routes = _canonical_sha256(
            [route.model_dump(mode="json") for route in self.routes]
        )
        expected_audit_routes = _canonical_sha256(
            [route.model_dump(mode="json") for route in self.routes if route.audit_selected]
        )
        if (
            self.technical_route_set_sha256 != expected_technical_routes
            or self.audit_route_set_sha256 != expected_audit_routes
        ):
            raise ValueError("refresh runtime route-set hash is inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("refresh runtime evidence self-hash is inconsistent")
        return self


class AuditModelRefreshPricingRouteEvidence(_FrozenModel):
    """Exact baseline/current pricing-schedule comparison for one selected technical route.

    This durable record proves only that a resolver observed a bounded comparison. It
    cannot authorize a request, select a model, or replace the qualification price hash.
    """

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    audit_selected: bool
    qualified_pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    baseline_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    baseline_pricing: _PricingMap = Field(
        min_length=2,
        max_length=_MAX_PRICING_FIELDS,
        json_schema_extra={
            "propertyNames": {
                "minLength": 1,
                "maxLength": 64,
                "pattern": _PRICING_FIELD_PATTERN,
            }
        },
    )
    baseline_pricing_overrides: tuple[OpenRouterPricingOverrideTier, ...] = Field(
        default_factory=tuple,
        max_length=64,
        exclude_if=lambda value: not value,
    )
    baseline_pricing_schedule: ExactRoutePricingSchedule | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    baseline_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_pricing: _PricingMap = Field(
        min_length=2,
        max_length=_MAX_PRICING_FIELDS,
        json_schema_extra={
            "propertyNames": {
                "minLength": 1,
                "maxLength": 64,
                "pattern": _PRICING_FIELD_PATTERN,
            }
        },
    )
    current_pricing_overrides: tuple[OpenRouterPricingOverrideTier, ...] = Field(
        default_factory=tuple,
        max_length=64,
        exclude_if=lambda value: not value,
    )
    current_pricing_schedule: ExactRoutePricingSchedule | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    current_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    price_components: tuple[str, ...] = Field(
        min_length=2,
        max_length=_MAX_PRICING_FIELDS,
    )
    changed_components: tuple[str, ...] = Field(max_length=_MAX_PRICING_FIELDS)
    increased_components: tuple[str, ...] = Field(max_length=_MAX_PRICING_FIELDS)
    pricing_tolerance_fraction: str = Field(
        min_length=1,
        max_length=MAX_MODEL_REFRESH_FRACTION_TEXT_LENGTH,
        pattern=MODEL_REFRESH_FRACTION_PATTERN,
    )
    comparison_state: Literal["EXACT", "WITHIN_TOLERANCE"]
    refresh_route_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_use_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False
    model_selection_authorized: Literal[False] = False
    route_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("baseline_pricing", "current_pricing")
    @classmethod
    def pricing_is_canonical(cls, value: _PricingMap) -> _PricingMap:
        return _require_canonical_pricing(value, label="refresh pricing route map")

    @field_validator(
        "price_components",
        "changed_components",
        "increased_components",
    )
    @classmethod
    def components_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("refresh pricing components must be unique and sorted")
        return value

    @field_validator("pricing_tolerance_fraction")
    @classmethod
    def tolerance_is_canonical(cls, value: str) -> str:
        parse_model_refresh_fraction(value)
        return value

    @field_validator(
        "audit_selected",
        "pricing_use_authorized",
        "provider_access_authorized",
        "model_selection_authorized",
        mode="before",
    )
    @classmethod
    def booleans_are_literal(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("refresh pricing route booleans must be literal")
        return value

    @model_validator(mode="after")
    def comparison_is_exact_bounded_and_self_hashed(self) -> Self:
        _require_canonical_pricing_schedule(
            pricing=self.baseline_pricing,
            overrides=self.baseline_pricing_overrides,
            schedule=self.baseline_pricing_schedule,
            label="refresh baseline pricing schedule",
        )
        _require_canonical_pricing_schedule(
            pricing=self.current_pricing,
            overrides=self.current_pricing_overrides,
            schedule=self.current_pricing_schedule,
            label="refresh current pricing schedule",
        )
        baseline_fields = tuple(
            _maximum_pricing(self.baseline_pricing, self.baseline_pricing_schedule)
        )
        current_fields = tuple(
            _maximum_pricing(self.current_pricing, self.current_pricing_schedule)
        )
        if baseline_fields != current_fields or self.price_components != baseline_fields:
            raise ValueError(
                "refresh pricing route has a new, missing, or unsupported price component"
            )
        if (
            self.baseline_pricing_sha256
            != openrouter_pricing_schedule_sha256(
                self.baseline_pricing,
                self.baseline_pricing_overrides,
            )
            or self.current_pricing_sha256
            != openrouter_pricing_schedule_sha256(
                self.current_pricing,
                self.current_pricing_overrides,
            )
            or self.qualified_pricing_snapshot_sha256 != self.baseline_pricing_sha256
        ):
            raise ValueError("refresh pricing route hash or qualified baseline differs")
        tolerance = parse_model_refresh_fraction(self.pricing_tolerance_fraction)
        changed, increased, exceeds_tolerance = _compare_pricing_schedules(
            baseline_pricing=self.baseline_pricing,
            baseline_overrides=self.baseline_pricing_overrides,
            baseline_schedule=self.baseline_pricing_schedule,
            current_pricing=self.current_pricing,
            current_overrides=self.current_pricing_overrides,
            current_schedule=self.current_pricing_schedule,
            tolerance=tolerance,
        )
        if self.changed_components != changed or self.increased_components != increased:
            raise ValueError("refresh pricing route component comparison is inconsistent")
        if exceeds_tolerance:
            raise ValueError("refresh pricing route exceeds its configured tolerance")
        expected_state = (
            "EXACT"
            if self.baseline_pricing_sha256 == self.current_pricing_sha256
            else "WITHIN_TOLERANCE"
        )
        if self.comparison_state != expected_state:
            raise ValueError("refresh pricing route comparison state is inconsistent")
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"route_evidence_sha256"})
        )
        if self.route_evidence_sha256 != expected:
            raise ValueError("refresh pricing route evidence self-hash is inconsistent")
        return self


class AuditModelRefreshPricingEvidence(_FrozenModel):
    """Pinned bounded pricing-schedule comparisons that remain non-authorizing."""

    schema_version: Literal["1.0"] = "1.0"
    authority_mode: Literal["NON_AUTHORIZING_BOUNDED_PRICE_COMPARISON"] = (
        "NON_AUTHORIZING_BOUNDED_PRICE_COMPARISON"
    )
    expected_workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    workflow_run_id: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    workflow_run_attempt: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    previous_workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)
    previous_candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    previous_source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    previous_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    current_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    diff_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_guard_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_technical_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_audit_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_qualification_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_production_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    technical_candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_selection_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_scope_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    client_constraints_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_tolerance_fraction: str = Field(
        min_length=1,
        max_length=MAX_MODEL_REFRESH_FRACTION_TEXT_LENGTH,
        pattern=MODEL_REFRESH_FRACTION_PATTERN,
    )
    verified_at: datetime
    refresh_expires_at: datetime
    expires_at: datetime
    technical_model_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_MODELS)
    audit_model_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_MODELS)
    routes: tuple[AuditModelRefreshPricingRouteEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_MODELS,
    )
    technical_pricing_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    audit_pricing_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_use_authorized: Literal[False] = False
    technical_selection_authorized: Literal[False] = False
    audit_selection_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False
    production_promotion_authorized: Literal[False] = False
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("verified_at", "refresh_expires_at", "expires_at")
    @classmethod
    def times_are_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh pricing evidence time")

    @field_validator("technical_model_ids", "audit_model_ids")
    @classmethod
    def model_ids_are_exact_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        exact = tuple(require_exact_openrouter_model_id(item) for item in value)
        if exact != tuple(sorted(set(exact))):
            raise ValueError("refresh pricing model IDs must be exact, unique, and sorted")
        return exact

    @field_validator("pricing_tolerance_fraction")
    @classmethod
    def tolerance_is_canonical(cls, value: str) -> str:
        parse_model_refresh_fraction(value)
        return value

    @field_validator(
        "pricing_use_authorized",
        "technical_selection_authorized",
        "audit_selection_authorized",
        "provider_access_authorized",
        "production_promotion_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("refresh pricing authority flags must be literal booleans")
        return value

    @model_validator(mode="after")
    def evidence_is_non_authorizing_and_self_hashed(self) -> Self:
        if self.expected_workflow_status_sha256 != self.workflow_status_sha256:
            raise ValueError("refresh pricing evidence differs from its external workflow pin")
        if self.expires_at != self.refresh_expires_at or not self.verified_at < self.expires_at:
            raise ValueError("refresh pricing evidence expiry is inconsistent")
        route_ids = tuple(route.exact_model_id for route in self.routes)
        route_audit_ids = tuple(
            route.exact_model_id for route in self.routes if route.audit_selected
        )
        if route_ids != self.technical_model_ids or route_ids != tuple(sorted(set(route_ids))):
            raise ValueError("refresh pricing routes differ from technical selection")
        if route_audit_ids != self.audit_model_ids:
            raise ValueError("refresh pricing routes differ from audit selection")
        if any(
            route.baseline_snapshot_sha256 != self.previous_snapshot_sha256
            or route.current_snapshot_sha256 != self.current_snapshot_sha256
            or route.pricing_tolerance_fraction != self.pricing_tolerance_fraction
            for route in self.routes
        ):
            raise ValueError("refresh pricing routes differ from global comparison evidence")
        expected_technical = _canonical_sha256(
            [route.model_dump(mode="json") for route in self.routes]
        )
        expected_audit = _canonical_sha256(
            [route.model_dump(mode="json") for route in self.routes if route.audit_selected]
        )
        if (
            self.technical_pricing_route_set_sha256 != expected_technical
            or self.audit_pricing_route_set_sha256 != expected_audit
        ):
            raise ValueError("refresh pricing route-set hash is inconsistent")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("refresh pricing evidence self-hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class VerifiedAuditModelRefreshGuard:
    """Opaque CURRENT-only veto guard; never a model-selection capability."""

    verified_at: datetime
    expires_at: datetime
    refresh_current_through: datetime
    workflow_status_sha256: str
    snapshot_sha256: str
    technical_qualification_capability_sha256: str
    technical_production_selection_sha256: str
    audit_selection_capability_sha256: str
    audit_selection_sha256: str
    evidence_sha256: str
    capability_sha256: str

    def __new__(cls, *_args: object, **_kwargs: object) -> Self:
        del cls, _args, _kwargs
        raise TypeError("verified audit model refresh guard can only be issued by its resolver")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified audit model refresh guard cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified audit model refresh guard cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified audit model refresh guard cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified audit model refresh guard cannot be serialized")

    def require_current(
        self,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> Self:
        _require_current_guard(
            self,
            now=now,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        return self

    def route_for(
        self,
        exact_model_id: str,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> AuditModelRefreshRouteEvidence:
        return _route_for_current_guard(
            self,
            exact_model_id=exact_model_id,
            now=now,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class VerifiedAuditModelRefreshPricingAuthority:
    """Opaque authority for one bounded refreshed-price inventory.

    This capability authorizes only use of the exact retained current price map. It
    cannot qualify or select a model and cannot authorize provider access by itself.
    """

    verified_at: datetime
    expires_at: datetime
    workflow_status_sha256: str
    refresh_evidence_sha256: str
    refresh_guard_capability_sha256: str
    technical_qualification_capability_sha256: str
    technical_production_selection_sha256: str
    audit_selection_capability_sha256: str
    audit_selection_sha256: str
    pricing_evidence_sha256: str
    capability_sha256: str

    def __new__(cls, *_args: object, **_kwargs: object) -> Self:
        del cls, _args, _kwargs
        raise TypeError(
            "verified audit model refresh pricing authority can only be issued by its resolver"
        )

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified audit model refresh pricing authority cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified audit model refresh pricing authority cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified audit model refresh pricing authority cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified audit model refresh pricing authority cannot be serialized")

    def require_current(
        self,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        refresh_evidence: AuditModelRefreshEvidence,
        refresh_guard: VerifiedAuditModelRefreshGuard,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> Self:
        _require_current_refresh_pricing_authority(
            self,
            now=now,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            refresh_evidence=refresh_evidence,
            refresh_guard=refresh_guard,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        return self

    def route_for(
        self,
        exact_model_id: str,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        refresh_evidence: AuditModelRefreshEvidence,
        refresh_guard: VerifiedAuditModelRefreshGuard,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> AuditModelRefreshPricingRouteEvidence:
        return _pricing_route_for_current_authority(
            self,
            exact_model_id=exact_model_id,
            now=now,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            refresh_evidence=refresh_evidence,
            refresh_guard=refresh_guard,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )


def _resolve_refresh_guard_inputs(
    *,
    history: ValidatedModelRefreshHistory,
    expected_workflow_status_sha256: str,
    expected_source_commit: str,
    expected_workflow_run_id: str,
    expected_workflow_run_attempt: str,
    technical_qualification: VerifiedProductionQualification,
    audit_selection_evidence: AuditModelSelectionEvidenceBundle,
    audit_selection: VerifiedAuditModelSelection,
    expected_pricing_tolerance_fraction: str,
    expected_soft_max_age_hours: int,
    expected_hard_max_age_hours: int,
    verified_at: datetime,
) -> tuple[
    AuditModelRefreshEvidence,
    ModelRefreshSnapshot,
    tuple[int, ...],
    tuple[int, ...],
]:
    """Validate all durable and live inputs before closure-held guard issuance.

    ``expected_workflow_status_sha256`` and workflow identity are trusted caller inputs.
    They must never be read from ``history`` or a sibling file by a convenience loader.
    Even a valid guard remains subordinate to the exact live qualification and audit
    selection capabilities supplied here and again at every use.
    """

    if type(history) is not ValidatedModelRefreshHistory:
        raise ValueError("validated model refresh history is absent or has an invalid type")
    if type(technical_qualification) is not VerifiedProductionQualification:
        raise ValueError("verified production qualification is absent or forged")
    if type(audit_selection_evidence) is not AuditModelSelectionEvidenceBundle:
        raise ValueError("audit model selection evidence is absent or malformed")
    if type(audit_selection) is not VerifiedAuditModelSelection:
        raise ValueError("verified audit model selection is absent or forged")
    expected_workflow_status_sha256 = _require_sha256(
        expected_workflow_status_sha256,
        label="expected refresh workflow status",
    )
    if (
        type(expected_source_commit) is not str
        or re.fullmatch(_GIT_COMMIT_PATTERN, expected_source_commit) is None
    ):
        raise ValueError("expected refresh source commit is malformed")
    if (
        type(expected_workflow_run_id) is not str
        or re.fullmatch(_WORKFLOW_NUMBER_PATTERN, expected_workflow_run_id) is None
    ):
        raise ValueError("expected refresh workflow run ID is malformed")
    if (
        type(expected_workflow_run_attempt) is not str
        or re.fullmatch(_WORKFLOW_NUMBER_PATTERN, expected_workflow_run_attempt) is None
    ):
        raise ValueError("expected refresh workflow run attempt is malformed")
    validate_model_refresh_controls(
        pricing_tolerance_fraction=expected_pricing_tolerance_fraction,
        soft_max_age_hours=expected_soft_max_age_hours,
        hard_max_age_hours=expected_hard_max_age_hours,
    )
    verified_at = _whole_second_utc(verified_at, label="refresh runtime verification time")

    validated = ValidatedModelRefreshHistory.model_validate_json(
        history.model_dump_json(), strict=True
    )
    status = validated.workflow_status
    registry = validated.candidate_registry
    source = validated.source_evidence
    snapshot = validated.snapshot
    diff = validated.diff
    attempt = validated.attempt
    freshness = validated.freshness
    if (
        status.workflow_status_sha256 != expected_workflow_status_sha256
        or status.source_commit != expected_source_commit
        or status.workflow_run_id != expected_workflow_run_id
        or status.workflow_run_attempt != expected_workflow_run_attempt
    ):
        raise ValueError("refresh workflow differs from independently expected identity")
    if status.disposition is not ModelRefreshWorkflowDisposition.COMPLETED:
        raise ValueError("paid audit refresh requires a completed non-blocking workflow")
    if (
        status.pricing_tolerance_fraction != expected_pricing_tolerance_fraction
        or status.soft_max_age_hours != expected_soft_max_age_hours
        or status.hard_max_age_hours != expected_hard_max_age_hours
    ):
        raise ValueError("refresh workflow controls differ from runtime configuration")
    if status.validated_at > verified_at:
        raise ValueError("refresh workflow status is future-dated")

    for filename, artifact_sha256 in (
        (CANDIDATE_REGISTRY_FILENAME, registry.registry_sha256),
        (SOURCE_EVIDENCE_FILENAME, source.source_evidence_sha256),
        (SNAPSHOT_FILENAME, snapshot.snapshot_sha256),
        (DIFF_FILENAME, diff.diff_sha256),
        (ATTEMPT_FILENAME, attempt.attempt_sha256),
        (FRESHNESS_FILENAME, freshness.freshness_sha256),
    ):
        _require_status_artifact_binding(
            status=status,
            filename=filename,
            artifact_sha256=artifact_sha256,
        )

    try:
        replayed_snapshot = build_model_refresh_snapshot_from_source(
            source_evidence=source,
            candidate_registry=registry,
        )
        replayed_stored_freshness = evaluate_model_refresh_freshness(
            observed_at=freshness.observed_at,
            snapshot=snapshot,
            soft_max_age_hours=expected_soft_max_age_hours,
            hard_max_age_hours=expected_hard_max_age_hours,
            production_selection_present=freshness.production_selection_present,
        )
    except ValueError as exc:
        raise ValueError("refresh runtime cannot replay its current snapshot or freshness") from exc
    if replayed_snapshot != snapshot or replayed_stored_freshness != freshness:
        raise ValueError("refresh runtime current snapshot or freshness replay differs")
    if (
        registry.registry_sha256 != status.candidate_registry_sha256
        or source.candidate_registry_sha256 != registry.registry_sha256
        or snapshot.candidate_registry_sha256 != registry.registry_sha256
        or diff.current_candidate_registry_sha256 != registry.registry_sha256
        or diff.current_snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.candidate_registry_sha256 != registry.registry_sha256
        or attempt.snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.diff_sha256 != diff.diff_sha256
        or attempt.status is not diff.status
        or attempt.status
        not in {ModelRefreshAttemptStatus.UNCHANGED, ModelRefreshAttemptStatus.CHANGED}
        or diff.production_block_reasons
        or diff.pricing_tolerance_fraction != expected_pricing_tolerance_fraction
        or freshness.snapshot_sha256 != snapshot.snapshot_sha256
        or freshness.soft_max_age_hours != expected_soft_max_age_hours
        or freshness.hard_max_age_hours != expected_hard_max_age_hours
        or freshness.state is not ModelRefreshFreshnessState.CURRENT
        or freshness.production_blocked
        or registry.created_at > source.retrieved_at
        or source.retrieved_at != snapshot.retrieved_at
        or not (
            attempt.attempted_at
            <= snapshot.retrieved_at
            == diff.compared_at
            == freshness.observed_at
        )
        or abs(status.validated_at - snapshot.retrieved_at) > _STATUS_CLOCK_SKEW
    ):
        raise ValueError("refresh runtime workflow bindings are inconsistent or blocking")

    previous_status = validated.previous_workflow_status
    previous_registry = validated.previous_candidate_registry
    previous_source = validated.previous_source_evidence
    previous_snapshot = validated.previous_snapshot
    predecessor = (previous_status, previous_registry, previous_source, previous_snapshot)
    if not all(item is not None for item in predecessor):
        raise ValueError("selected production routes require an exact refresh predecessor")
    assert previous_status is not None
    assert previous_registry is not None
    assert previous_source is not None
    assert previous_snapshot is not None
    if diff.baseline_kind is not RefreshBaselineKind.PREVIOUS_SNAPSHOT:
        raise ValueError("selected production routes require a previous-snapshot diff")
    for filename, artifact_sha256 in (
        (PREVIOUS_WORKFLOW_STATUS_FILENAME, previous_status.workflow_status_sha256),
        (PREVIOUS_CANDIDATE_REGISTRY_FILENAME, previous_registry.registry_sha256),
        (PREVIOUS_SOURCE_EVIDENCE_FILENAME, previous_source.source_evidence_sha256),
        (PREVIOUS_SNAPSHOT_FILENAME, previous_snapshot.snapshot_sha256),
    ):
        _require_status_artifact_binding(
            status=status,
            filename=filename,
            artifact_sha256=artifact_sha256,
        )
    if (
        status.previous_workflow_status_sha256 != previous_status.workflow_status_sha256
        or status.previous_workflow_run_id != previous_status.workflow_run_id
        or status.previous_workflow_run_attempt != previous_status.workflow_run_attempt
        or previous_status.disposition
        not in {
            ModelRefreshWorkflowDisposition.COMPLETED,
            ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
        }
        or previous_status.candidate_registry_sha256 != previous_registry.registry_sha256
        or previous_registry.created_at > registry.created_at
        or previous_registry.created_at > previous_source.retrieved_at
        or previous_source.retrieved_at != previous_snapshot.retrieved_at
        or previous_snapshot.retrieved_at > snapshot.retrieved_at
        or previous_status.validated_at > status.validated_at + _STATUS_CLOCK_SKEW
        or abs(previous_status.validated_at - previous_snapshot.retrieved_at) > _STATUS_CLOCK_SKEW
    ):
        raise ValueError("refresh runtime predecessor identity or chronology differs")
    for filename, artifact_sha256 in (
        (CANDIDATE_REGISTRY_FILENAME, previous_registry.registry_sha256),
        (SOURCE_EVIDENCE_FILENAME, previous_source.source_evidence_sha256),
        (SNAPSHOT_FILENAME, previous_snapshot.snapshot_sha256),
    ):
        _require_status_artifact_binding(
            status=previous_status,
            filename=filename,
            artifact_sha256=artifact_sha256,
        )
    try:
        replayed_previous_snapshot = build_model_refresh_snapshot_from_source(
            source_evidence=previous_source,
            candidate_registry=previous_registry,
        )
    except ValueError as exc:
        raise ValueError("refresh runtime cannot replay its predecessor snapshot") from exc
    if replayed_previous_snapshot != previous_snapshot:
        raise ValueError("refresh runtime predecessor snapshot replay differs")

    evidence_bundle = AuditModelSelectionEvidenceBundle.model_validate_json(
        audit_selection_evidence.model_dump_json(), strict=True
    )
    selection = evidence_bundle.selection
    technical_qualification.require_current(now=verified_at)
    audit_selection.require_current(
        now=verified_at,
        expected_audit_scope_sha256=selection.audit_scope_sha256,
        expected_source_sha256=selection.source_sha256,
        expected_audit_context_sha256=selection.audit_context_sha256,
        expected_client_constraints_sha256=selection.client_constraints_sha256,
    )
    if (
        selection.technical_qualification_capability_sha256
        != technical_qualification.capability_sha256
        or selection.technical_production_selection_sha256
        != technical_qualification.production_selection_sha256
        or selection.technical_candidate_registry_sha256
        != technical_qualification.candidate_registry_sha256
        or audit_selection.audit_selection_sha256 != selection.selection_sha256
        or audit_selection.technical_qualification_capability_sha256
        != technical_qualification.capability_sha256
        or audit_selection.technical_production_selection_sha256
        != technical_qualification.production_selection_sha256
    ):
        raise ValueError("refresh runtime differs from technical or audit selection authority")

    technical_models = technical_qualification.models
    audit_models = audit_selection.models
    technical_by_id = {model.exact_model_id: model for model in technical_models}
    audit_ids = tuple(model.exact_model_id for model in audit_models)
    if (
        tuple(model.exact_model_id for model in technical_models) != tuple(sorted(technical_by_id))
        or audit_ids != selection.selected_model_ids
        or any(technical_by_id.get(model.exact_model_id) is not model for model in audit_models)
    ):
        raise ValueError("refresh runtime audit selection is not an exact technical subset")
    selected_routes = tuple(
        SelectedModelRoute(
            exact_model_id=model.exact_model_id,
            provider_endpoint=model.approved_provider_endpoint,
        )
        for model in technical_models
    )
    if not selected_routes or diff.selected_routes != selected_routes:
        raise ValueError("refresh diff selected routes differ from exact production selection")
    if not freshness.production_selection_present:
        raise ValueError("refresh freshness omits the exact production selection")

    try:
        replayed_diff = diff_model_refresh(
            current=snapshot,
            previous=previous_snapshot,
            previous_source_evidence=previous_source,
            previous_candidate_registry=previous_registry,
            candidate_registry=registry,
            pricing_tolerance_fraction=expected_pricing_tolerance_fraction,
            compared_at=diff.compared_at,
            selected_routes=selected_routes,
        )
    except ValueError as exc:
        raise ValueError("refresh runtime cannot replay its selected-route diff") from exc
    if (
        replayed_diff != diff
        or replayed_diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
    ):
        raise ValueError("refresh runtime selected-route diff is inconsistent or blocking")
    runtime_freshness = evaluate_model_refresh_freshness(
        observed_at=verified_at,
        snapshot=snapshot,
        soft_max_age_hours=expected_soft_max_age_hours,
        hard_max_age_hours=expected_hard_max_age_hours,
        production_selection_present=True,
    )
    if runtime_freshness.state is not ModelRefreshFreshnessState.CURRENT:
        raise ValueError("paid audit refresh is not current at runtime verification")

    candidates = {candidate.exact_model_id: candidate for candidate in registry.candidates}
    live_models = {model.exact_model_id: model for model in snapshot.models}
    route_evidence: list[AuditModelRefreshRouteEvidence] = []
    audit_id_set = frozenset(audit_ids)
    for model in technical_models:
        candidate = candidates.get(model.exact_model_id)
        live_model = live_models.get(model.exact_model_id)
        if candidate is None or live_model is None:
            raise ValueError(
                f"selected model is absent from current refresh: {model.exact_model_id}"
            )
        _require_exact_selected_candidate(candidate=candidate, model=model, now=verified_at)
        live_routes = tuple(
            route
            for route in live_model.routes
            if route.provider_endpoint == model.approved_provider_endpoint
        )
        if (
            live_model.canonical_model_slug != model.canonical_model_slug
            or model.structured_output_mode not in live_model.supported_output_modes
            or len(live_routes) != 1
        ):
            raise ValueError(
                f"selected model identity or output mode differs in current refresh: "
                f"{model.exact_model_id}"
            )
        live_route = live_routes[0]
        values: dict[str, Any] = {
            "schema_version": "1.0",
            "exact_model_id": model.exact_model_id,
            "canonical_model_slug": model.canonical_model_slug,
            "root_lineage": model.root_lineage,
            "approved_provider_endpoint": model.approved_provider_endpoint,
            "approved_provider_name": model.approved_provider_name,
            "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
            "output_capability_sha256": model.output_capability_sha256,
            "model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
            "qualified_pricing_snapshot_sha256": model.pricing_snapshot_sha256,
            "structured_output_mode": model.structured_output_mode,
            "approved_roles": model.approved_roles,
            "benchmark_report_sha256": model.benchmark_report_sha256,
            "qualification_expires_at": model.expires_at,
            "audit_selected": model.exact_model_id in audit_id_set,
            "refresh_model_state_sha256": live_model.state_sha256,
            "refresh_route": live_route,
            "runtime_authorized": False,
        }
        values["route_evidence_sha256"] = _canonical_sha256(values)
        route_evidence.append(AuditModelRefreshRouteEvidence.model_validate(values))

    routes = tuple(route_evidence)
    refresh_current_through = snapshot.retrieved_at + timedelta(hours=expected_soft_max_age_hours)
    expires_at = min(
        refresh_current_through + timedelta(seconds=1),
        technical_qualification.expires_at,
        audit_selection.expires_at,
    )
    evidence_values: dict[str, Any] = {
        "schema_version": "1.0",
        "authority_mode": "VETO_ONLY_EXTERNAL_WORKFLOW_PIN_REQUIRED",
        "expected_workflow_status_sha256": expected_workflow_status_sha256,
        "workflow_status_sha256": status.workflow_status_sha256,
        "source_commit": status.source_commit,
        "workflow_run_id": status.workflow_run_id,
        "workflow_run_attempt": status.workflow_run_attempt,
        "previous_workflow_status_sha256": previous_status.workflow_status_sha256,
        "current_candidate_registry_sha256": registry.registry_sha256,
        "source_evidence_sha256": source.source_evidence_sha256,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "semantic_sha256": snapshot.semantic_sha256,
        "diff_sha256": diff.diff_sha256,
        "freshness_sha256": freshness.freshness_sha256,
        "pricing_tolerance_fraction": expected_pricing_tolerance_fraction,
        "soft_max_age_hours": expected_soft_max_age_hours,
        "hard_max_age_hours": expected_hard_max_age_hours,
        "snapshot_retrieved_at": snapshot.retrieved_at,
        "verified_at": verified_at,
        "refresh_current_through": refresh_current_through,
        "technical_qualification_capability_sha256": technical_qualification.capability_sha256,
        "technical_production_selection_sha256": (
            technical_qualification.production_selection_sha256
        ),
        "technical_candidate_registry_sha256": (technical_qualification.candidate_registry_sha256),
        "technical_qualification_expires_at": technical_qualification.expires_at,
        "audit_selection_capability_sha256": audit_selection.capability_sha256,
        "audit_selection_sha256": audit_selection.audit_selection_sha256,
        "audit_selection_expires_at": audit_selection.expires_at,
        "audit_scope_sha256": selection.audit_scope_sha256,
        "source_sha256": selection.source_sha256,
        "audit_context_sha256": selection.audit_context_sha256,
        "client_constraints_sha256": selection.client_constraints_sha256,
        "technical_model_ids": tuple(model.exact_model_id for model in technical_models),
        "audit_model_ids": audit_ids,
        "routes": routes,
        "technical_route_set_sha256": _canonical_sha256(
            [route.model_dump(mode="json") for route in routes]
        ),
        "audit_route_set_sha256": _canonical_sha256(
            [route.model_dump(mode="json") for route in routes if route.audit_selected]
        ),
        "expires_at": expires_at,
        "technical_selection_authorized": False,
        "audit_selection_authorized": False,
        "provider_access_authorized": False,
        "production_promotion_authorized": False,
    }
    evidence_values["evidence_sha256"] = _canonical_sha256(evidence_values)
    evidence = AuditModelRefreshEvidence.model_validate(evidence_values)

    return (
        evidence,
        ModelRefreshSnapshot.model_validate_json(snapshot.model_dump_json(), strict=True),
        tuple(id(model) for model in technical_models),
        tuple(id(model) for model in audit_models),
    )


def _require_status_artifact_binding(
    *,
    status: ModelRefreshWorkflowStatus,
    filename: str,
    artifact_sha256: str,
) -> None:
    matches = tuple(item for item in status.artifacts if item.filename == filename)
    if len(matches) != 1 or matches[0].artifact_sha256 != artifact_sha256:
        raise ValueError(f"refresh workflow does not bind exact artifact: {filename}")


def _require_exact_selected_candidate(
    *,
    candidate: CandidateModel,
    model: VerifiedTierAModelQualification,
    now: datetime,
) -> None:
    exact_values = (
        (candidate.exact_model_id, model.exact_model_id),
        (candidate.canonical_model_slug, model.canonical_model_slug),
        (candidate.root_lineage, model.root_lineage),
        (candidate.approved_provider_endpoint, model.approved_provider_endpoint),
        (candidate.approved_provider_name, model.approved_provider_name),
        (candidate.endpoint_snapshot_sha256, model.endpoint_snapshot_sha256),
        (candidate.output_capability_sha256, model.output_capability_sha256),
        (candidate.model_metadata_snapshot_sha256, model.model_metadata_snapshot_sha256),
        (candidate.pricing_snapshot_sha256, model.pricing_snapshot_sha256),
        (candidate.structured_output_mode, model.structured_output_mode),
        (candidate.approved_roles, model.approved_roles),
        (candidate.benchmark_artifact_sha256, model.benchmark_report_sha256),
        (candidate.qualification_expires_at, model.expires_at),
    )
    if (
        any(observed != expected for observed, expected in exact_values)
        or candidate.operational_status is not CandidateOperationalStatus.AVAILABLE
        or candidate.benchmark_status is not CandidateBenchmarkStatus.PASSED
        or candidate.lineage_review.status is not LineageReviewStatus.APPROVED
        or candidate.qualification_expires_at is None
        or candidate.qualification_expires_at <= now
    ):
        raise ValueError(
            f"current candidate downgrades exact production qualification: {model.exact_model_id}"
        )


def _guard_payload(capability: VerifiedAuditModelRefreshGuard) -> dict[str, Any]:
    return {
        "verified_at": capability.verified_at,
        "expires_at": capability.expires_at,
        "refresh_current_through": capability.refresh_current_through,
        "workflow_status_sha256": capability.workflow_status_sha256,
        "snapshot_sha256": capability.snapshot_sha256,
        "technical_qualification_capability_sha256": (
            capability.technical_qualification_capability_sha256
        ),
        "technical_production_selection_sha256": (capability.technical_production_selection_sha256),
        "audit_selection_capability_sha256": capability.audit_selection_capability_sha256,
        "audit_selection_sha256": capability.audit_selection_sha256,
        "evidence_sha256": capability.evidence_sha256,
    }


def _build_refresh_guard_authority() -> tuple[
    Callable[..., tuple[AuditModelRefreshEvidence, VerifiedAuditModelRefreshGuard]],
    Callable[..., None],
    Callable[..., AuditModelRefreshRouteEvidence],
]:
    """Keep the only guard registry writer inside the validated resolver closure."""

    validate_inputs = _resolve_refresh_guard_inputs

    @dataclass(frozen=True, slots=True)
    class IssuedState:
        capability_sha256: str
        evidence: AuditModelRefreshEvidence
        snapshot: ModelRefreshSnapshot
        technical_qualification: VerifiedProductionQualification
        audit_selection: VerifiedAuditModelSelection
        technical_model_identities: tuple[int, ...]
        audit_model_identities: tuple[int, ...]

    registry: dict[
        int,
        tuple[weakref.ReferenceType[VerifiedAuditModelRefreshGuard], IssuedState],
    ] = {}
    lock = threading.RLock()

    def state_for(capability: VerifiedAuditModelRefreshGuard) -> IssuedState:
        if type(capability) is not VerifiedAuditModelRefreshGuard:
            raise ValueError("verified audit model refresh guard is absent or forged")
        with lock:
            registered = registry.get(id(capability))
        if registered is None or registered[0]() is not capability:
            raise ValueError("verified audit model refresh guard is absent or forged")
        return registered[1]

    def require(
        capability: VerifiedAuditModelRefreshGuard,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> None:
        now = _whole_second_utc(now, label="refresh guard use time")
        expected_workflow_status_sha256 = _require_sha256(
            expected_workflow_status_sha256,
            label="expected refresh workflow status",
        )
        state = state_for(capability)
        if (
            technical_qualification is not state.technical_qualification
            or audit_selection is not state.audit_selection
        ):
            raise ValueError("refresh guard is paired with different live selection authority")
        if now < capability.verified_at or now >= capability.expires_at:
            raise ValueError("refresh guard is future-dated or expired")
        technical_qualification.require_current(now=now)
        audit_selection.require_current(
            now=now,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        evidence = AuditModelRefreshEvidence.model_validate_json(
            state.evidence.model_dump_json(), strict=True
        )
        snapshot = ModelRefreshSnapshot.model_validate_json(
            state.snapshot.model_dump_json(), strict=True
        )
        current = evaluate_model_refresh_freshness(
            observed_at=now,
            snapshot=snapshot,
            soft_max_age_hours=evidence.soft_max_age_hours,
            hard_max_age_hours=evidence.hard_max_age_hours,
            production_selection_present=True,
        )
        if current.state is not ModelRefreshFreshnessState.CURRENT:
            raise ValueError("refresh guard is not current")
        if (
            expected_workflow_status_sha256 != capability.workflow_status_sha256
            or expected_workflow_status_sha256 != evidence.workflow_status_sha256
            or capability.capability_sha256 != state.capability_sha256
            or capability.evidence_sha256 != evidence.evidence_sha256
            or capability.snapshot_sha256 != evidence.snapshot_sha256
            or snapshot.snapshot_sha256 != evidence.snapshot_sha256
            or snapshot.semantic_sha256 != evidence.semantic_sha256
            or snapshot.candidate_registry_sha256 != evidence.current_candidate_registry_sha256
            or snapshot.retrieved_at != evidence.snapshot_retrieved_at
            or capability.verified_at != evidence.verified_at
            or capability.expires_at != evidence.expires_at
            or capability.refresh_current_through != evidence.refresh_current_through
            or capability.technical_qualification_capability_sha256
            != technical_qualification.capability_sha256
            or capability.technical_production_selection_sha256
            != technical_qualification.production_selection_sha256
            or capability.audit_selection_capability_sha256 != audit_selection.capability_sha256
            or capability.audit_selection_sha256 != audit_selection.audit_selection_sha256
            or evidence.technical_qualification_capability_sha256
            != technical_qualification.capability_sha256
            or evidence.technical_production_selection_sha256
            != technical_qualification.production_selection_sha256
            or evidence.technical_candidate_registry_sha256
            != technical_qualification.candidate_registry_sha256
            or evidence.technical_qualification_expires_at != technical_qualification.expires_at
            or evidence.audit_selection_capability_sha256 != audit_selection.capability_sha256
            or evidence.audit_selection_sha256 != audit_selection.audit_selection_sha256
            or evidence.audit_selection_expires_at != audit_selection.expires_at
            or evidence.audit_scope_sha256 != expected_audit_scope_sha256
            or evidence.source_sha256 != expected_source_sha256
            or evidence.audit_context_sha256 != expected_audit_context_sha256
            or evidence.client_constraints_sha256 != expected_client_constraints_sha256
            or tuple(id(model) for model in technical_qualification.models)
            != state.technical_model_identities
            or tuple(id(model) for model in audit_selection.models) != state.audit_model_identities
            or capability.capability_sha256 != _canonical_sha256(_guard_payload(capability))
        ):
            raise ValueError("refresh guard integrity or exact selection join failed")

    def route_for(
        capability: VerifiedAuditModelRefreshGuard,
        exact_model_id: str,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> AuditModelRefreshRouteEvidence:
        require(
            capability,
            now=now,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        exact_model_id = require_exact_openrouter_model_id(exact_model_id)
        audit_selection.model_for(
            exact_model_id,
            now=now,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        technical_qualification.model_for(exact_model_id, now=now)
        state = state_for(capability)
        matches = tuple(
            route
            for route in state.evidence.routes
            if route.exact_model_id == exact_model_id and route.audit_selected
        )
        if len(matches) != 1:
            raise ValueError(f"exact model lacks a current refresh guard: {exact_model_id}")
        return AuditModelRefreshRouteEvidence.model_validate_json(
            matches[0].model_dump_json(), strict=True
        )

    def resolve(
        *,
        history: ValidatedModelRefreshHistory,
        expected_workflow_status_sha256: str,
        expected_source_commit: str,
        expected_workflow_run_id: str,
        expected_workflow_run_attempt: str,
        technical_qualification: VerifiedProductionQualification,
        audit_selection_evidence: AuditModelSelectionEvidenceBundle,
        audit_selection: VerifiedAuditModelSelection,
        expected_pricing_tolerance_fraction: str,
        expected_soft_max_age_hours: int,
        expected_hard_max_age_hours: int,
        verified_at: datetime,
    ) -> tuple[AuditModelRefreshEvidence, VerifiedAuditModelRefreshGuard]:
        """Issue a CURRENT-only veto guard from an independently pinned workflow."""

        evidence, snapshot, technical_identities, audit_identities = validate_inputs(
            history=history,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            expected_source_commit=expected_source_commit,
            expected_workflow_run_id=expected_workflow_run_id,
            expected_workflow_run_attempt=expected_workflow_run_attempt,
            technical_qualification=technical_qualification,
            audit_selection_evidence=audit_selection_evidence,
            audit_selection=audit_selection,
            expected_pricing_tolerance_fraction=expected_pricing_tolerance_fraction,
            expected_soft_max_age_hours=expected_soft_max_age_hours,
            expected_hard_max_age_hours=expected_hard_max_age_hours,
            verified_at=verified_at,
        )
        capability = object.__new__(VerifiedAuditModelRefreshGuard)
        for name, value in (
            ("verified_at", evidence.verified_at),
            ("expires_at", evidence.expires_at),
            ("refresh_current_through", evidence.refresh_current_through),
            ("workflow_status_sha256", evidence.workflow_status_sha256),
            ("snapshot_sha256", evidence.snapshot_sha256),
            (
                "technical_qualification_capability_sha256",
                technical_qualification.capability_sha256,
            ),
            (
                "technical_production_selection_sha256",
                technical_qualification.production_selection_sha256,
            ),
            ("audit_selection_capability_sha256", audit_selection.capability_sha256),
            ("audit_selection_sha256", audit_selection.audit_selection_sha256),
            ("evidence_sha256", evidence.evidence_sha256),
        ):
            object.__setattr__(capability, name, value)
        object.__setattr__(
            capability,
            "capability_sha256",
            _canonical_sha256(_guard_payload(capability)),
        )
        state = IssuedState(
            capability_sha256=capability.capability_sha256,
            evidence=evidence,
            snapshot=snapshot,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            technical_model_identities=technical_identities,
            audit_model_identities=audit_identities,
        )
        key = id(capability)

        def discard(reference: weakref.ReferenceType[VerifiedAuditModelRefreshGuard]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        require(
            capability,
            now=evidence.verified_at,
            expected_workflow_status_sha256=evidence.expected_workflow_status_sha256,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=evidence.audit_scope_sha256,
            expected_source_sha256=evidence.source_sha256,
            expected_audit_context_sha256=evidence.audit_context_sha256,
            expected_client_constraints_sha256=evidence.client_constraints_sha256,
        )
        return evidence, capability

    return resolve, require, route_for


(
    resolve_verified_audit_model_refresh_guard,
    _require_current_guard,
    _route_for_current_guard,
) = _build_refresh_guard_authority()
del _build_refresh_guard_authority


def _resolve_refresh_pricing_inputs(
    *,
    history: ValidatedModelRefreshHistory,
    refresh_evidence: AuditModelRefreshEvidence,
    refresh_guard: VerifiedAuditModelRefreshGuard,
    expected_workflow_status_sha256: str,
    expected_source_commit: str,
    expected_workflow_run_id: str,
    expected_workflow_run_attempt: str,
    technical_qualification: VerifiedProductionQualification,
    audit_selection_evidence: AuditModelSelectionEvidenceBundle,
    audit_selection: VerifiedAuditModelSelection,
    expected_pricing_tolerance_fraction: str,
    expected_soft_max_age_hours: int,
    expected_hard_max_age_hours: int,
    verified_at: datetime,
) -> tuple[
    AuditModelRefreshPricingEvidence,
    AuditModelRefreshEvidence,
    tuple[int, ...],
    tuple[int, ...],
]:
    """Replay exact refresh custody before issuing bounded live pricing authority."""

    if type(refresh_evidence) is not AuditModelRefreshEvidence:
        raise ValueError("audit model refresh evidence is absent or has an invalid type")
    if type(refresh_guard) is not VerifiedAuditModelRefreshGuard:
        raise ValueError("verified audit model refresh guard is absent or forged")
    replayed_refresh, replayed_current, technical_ids, audit_ids = _resolve_refresh_guard_inputs(
        history=history,
        expected_workflow_status_sha256=expected_workflow_status_sha256,
        expected_source_commit=expected_source_commit,
        expected_workflow_run_id=expected_workflow_run_id,
        expected_workflow_run_attempt=expected_workflow_run_attempt,
        technical_qualification=technical_qualification,
        audit_selection_evidence=audit_selection_evidence,
        audit_selection=audit_selection,
        expected_pricing_tolerance_fraction=expected_pricing_tolerance_fraction,
        expected_soft_max_age_hours=expected_soft_max_age_hours,
        expected_hard_max_age_hours=expected_hard_max_age_hours,
        verified_at=verified_at,
    )
    canonical_refresh = AuditModelRefreshEvidence.model_validate_json(
        refresh_evidence.model_dump_json(),
        strict=True,
    )
    if canonical_refresh != replayed_refresh:
        raise ValueError("refresh pricing authority received different refresh evidence")

    evidence_bundle = AuditModelSelectionEvidenceBundle.model_validate_json(
        audit_selection_evidence.model_dump_json(),
        strict=True,
    )
    selection = evidence_bundle.selection
    refresh_guard.require_current(
        now=verified_at,
        expected_workflow_status_sha256=expected_workflow_status_sha256,
        technical_qualification=technical_qualification,
        audit_selection=audit_selection,
        expected_audit_scope_sha256=selection.audit_scope_sha256,
        expected_source_sha256=selection.source_sha256,
        expected_audit_context_sha256=selection.audit_context_sha256,
        expected_client_constraints_sha256=selection.client_constraints_sha256,
    )
    if (
        refresh_guard.evidence_sha256 != canonical_refresh.evidence_sha256
        or refresh_guard.snapshot_sha256 != canonical_refresh.snapshot_sha256
        or refresh_guard.workflow_status_sha256 != canonical_refresh.workflow_status_sha256
        or refresh_guard.technical_qualification_capability_sha256
        != technical_qualification.capability_sha256
        or refresh_guard.audit_selection_capability_sha256 != audit_selection.capability_sha256
    ):
        raise ValueError("refresh pricing authority has a different live refresh guard")

    validated = ValidatedModelRefreshHistory.model_validate_json(
        history.model_dump_json(),
        strict=True,
    )
    previous_status = validated.previous_workflow_status
    previous_registry = validated.previous_candidate_registry
    previous_source = validated.previous_source_evidence
    previous_snapshot = validated.previous_snapshot
    if (
        previous_status is None
        or previous_registry is None
        or previous_source is None
        or previous_snapshot is None
    ):
        raise ValueError("refresh pricing authority requires an exact predecessor")
    try:
        replayed_previous = build_model_refresh_snapshot_from_source(
            source_evidence=previous_source,
            candidate_registry=previous_registry,
        )
        independently_replayed_current = build_model_refresh_snapshot_from_source(
            source_evidence=validated.source_evidence,
            candidate_registry=validated.candidate_registry,
        )
        selected_routes = tuple(
            SelectedModelRoute(
                exact_model_id=model.exact_model_id,
                provider_endpoint=model.approved_provider_endpoint,
            )
            for model in technical_qualification.models
        )
        replayed_diff = diff_model_refresh(
            current=independently_replayed_current,
            previous=replayed_previous,
            previous_source_evidence=previous_source,
            previous_candidate_registry=previous_registry,
            candidate_registry=validated.candidate_registry,
            pricing_tolerance_fraction=expected_pricing_tolerance_fraction,
            compared_at=validated.diff.compared_at,
            selected_routes=selected_routes,
        )
    except ValueError as exc:
        raise ValueError("refresh pricing authority cannot replay chained price evidence") from exc
    if (
        replayed_previous != previous_snapshot
        or independently_replayed_current != validated.snapshot
        or independently_replayed_current != replayed_current
        or replayed_diff != validated.diff
        or validated.diff.status is ModelRefreshAttemptStatus.PRODUCTION_BLOCKED
        or validated.diff.production_block_reasons
    ):
        raise ValueError("refresh pricing authority chained snapshot or diff replay differs")

    previous_models = {model.exact_model_id: model for model in previous_snapshot.models}
    current_models = {model.exact_model_id: model for model in validated.snapshot.models}
    refresh_routes = {route.exact_model_id: route for route in canonical_refresh.routes}
    audit_id_set = frozenset(canonical_refresh.audit_model_ids)
    pricing_routes: list[AuditModelRefreshPricingRouteEvidence] = []
    for model in technical_qualification.models:
        previous_model = previous_models.get(model.exact_model_id)
        current_model = current_models.get(model.exact_model_id)
        refresh_route = refresh_routes.get(model.exact_model_id)
        if previous_model is None or current_model is None or refresh_route is None:
            raise ValueError(
                f"refresh pricing route is absent from chained evidence: {model.exact_model_id}"
            )
        previous_matches = tuple(
            route
            for route in previous_model.routes
            if route.provider_endpoint == model.approved_provider_endpoint
        )
        current_matches = tuple(
            route
            for route in current_model.routes
            if route.provider_endpoint == model.approved_provider_endpoint
        )
        if len(previous_matches) != 1 or len(current_matches) != 1:
            raise ValueError(
                f"refresh pricing route identity is missing or ambiguous: {model.exact_model_id}"
            )
        baseline_route = previous_matches[0]
        current_route = current_matches[0]
        if (
            previous_model.canonical_model_slug != model.canonical_model_slug
            or current_model.canonical_model_slug != model.canonical_model_slug
            or baseline_route.provider_name != model.approved_provider_name
            or current_route.provider_name != model.approved_provider_name
            or not baseline_route.discovery_eligible
            or not current_route.discovery_eligible
            or refresh_route.refresh_route != current_route
            or refresh_route.qualified_pricing_snapshot_sha256 != model.pricing_snapshot_sha256
            or refresh_route.audit_selected is not (model.exact_model_id in audit_id_set)
        ):
            raise ValueError(
                f"refresh pricing route differs from exact live selection: {model.exact_model_id}"
            )
        baseline_pricing = _require_canonical_pricing(
            dict(baseline_route.pricing),
            label="refresh baseline pricing",
        )
        current_pricing = _require_canonical_pricing(
            dict(current_route.pricing),
            label="refresh current pricing",
        )
        if (
            baseline_route.pricing_schedule == "unavailable"
            or current_route.pricing_schedule == "unavailable"
        ):
            raise ValueError(
                f"refresh pricing route schedule is unavailable: {model.exact_model_id}"
            )
        baseline_overrides = baseline_route.pricing_overrides
        current_overrides = current_route.pricing_overrides
        baseline_schedule = baseline_route.pricing_schedule
        current_schedule = current_route.pricing_schedule
        _require_canonical_pricing_schedule(
            pricing=baseline_pricing,
            overrides=baseline_overrides,
            schedule=baseline_schedule,
            label="refresh baseline pricing schedule",
        )
        _require_canonical_pricing_schedule(
            pricing=current_pricing,
            overrides=current_overrides,
            schedule=current_schedule,
            label="refresh current pricing schedule",
        )
        if (
            baseline_route.pricing_sha256 != model.pricing_snapshot_sha256
            or baseline_route.pricing_sha256
            != openrouter_pricing_schedule_sha256(
                baseline_pricing,
                baseline_overrides,
            )
            or current_route.pricing_sha256
            != openrouter_pricing_schedule_sha256(
                current_pricing,
                current_overrides,
            )
        ):
            raise ValueError(
                f"refresh pricing baseline differs from qualification: {model.exact_model_id}"
            )
        baseline_fields = tuple(_maximum_pricing(baseline_pricing, baseline_schedule))
        current_fields = tuple(_maximum_pricing(current_pricing, current_schedule))
        if baseline_fields != current_fields:
            raise ValueError(
                "refresh pricing route has a new, missing, or unsupported price component: "
                f"{model.exact_model_id}"
            )
        tolerance = parse_model_refresh_fraction(expected_pricing_tolerance_fraction)
        changed, increased, exceeds_tolerance = _compare_pricing_schedules(
            baseline_pricing=baseline_pricing,
            baseline_overrides=baseline_overrides,
            baseline_schedule=baseline_schedule,
            current_pricing=current_pricing,
            current_overrides=current_overrides,
            current_schedule=current_schedule,
            tolerance=tolerance,
        )
        if exceeds_tolerance:
            raise ValueError(f"refresh pricing route exceeds tolerance: {model.exact_model_id}")
        route_values: dict[str, Any] = {
            "schema_version": "1.0",
            "exact_model_id": model.exact_model_id,
            "approved_provider_endpoint": model.approved_provider_endpoint,
            "audit_selected": refresh_route.audit_selected,
            "qualified_pricing_snapshot_sha256": model.pricing_snapshot_sha256,
            "baseline_snapshot_sha256": previous_snapshot.snapshot_sha256,
            "baseline_pricing": baseline_pricing,
            "baseline_pricing_sha256": baseline_route.pricing_sha256,
            "current_snapshot_sha256": validated.snapshot.snapshot_sha256,
            "current_pricing": current_pricing,
            "current_pricing_sha256": current_route.pricing_sha256,
            "price_components": baseline_fields,
            "changed_components": changed,
            "increased_components": increased,
            "pricing_tolerance_fraction": expected_pricing_tolerance_fraction,
            "comparison_state": (
                "EXACT"
                if baseline_route.pricing_sha256 == current_route.pricing_sha256
                else "WITHIN_TOLERANCE"
            ),
            "refresh_route_evidence_sha256": refresh_route.route_evidence_sha256,
            "pricing_use_authorized": False,
            "provider_access_authorized": False,
            "model_selection_authorized": False,
        }
        if baseline_overrides:
            route_values["baseline_pricing_overrides"] = baseline_overrides
        if baseline_schedule is not None:
            route_values["baseline_pricing_schedule"] = baseline_schedule
        if current_overrides:
            route_values["current_pricing_overrides"] = current_overrides
        if current_schedule is not None:
            route_values["current_pricing_schedule"] = current_schedule
        route_values["route_evidence_sha256"] = _canonical_sha256(route_values)
        pricing_routes.append(AuditModelRefreshPricingRouteEvidence.model_validate(route_values))

    routes = tuple(pricing_routes)
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "authority_mode": "NON_AUTHORIZING_BOUNDED_PRICE_COMPARISON",
        "expected_workflow_status_sha256": expected_workflow_status_sha256,
        "workflow_status_sha256": validated.workflow_status.workflow_status_sha256,
        "source_commit": validated.workflow_status.source_commit,
        "workflow_run_id": validated.workflow_status.workflow_run_id,
        "workflow_run_attempt": validated.workflow_status.workflow_run_attempt,
        "previous_workflow_status_sha256": previous_status.workflow_status_sha256,
        "previous_candidate_registry_sha256": previous_registry.registry_sha256,
        "previous_source_evidence_sha256": previous_source.source_evidence_sha256,
        "previous_snapshot_sha256": previous_snapshot.snapshot_sha256,
        "current_candidate_registry_sha256": validated.candidate_registry.registry_sha256,
        "current_source_evidence_sha256": validated.source_evidence.source_evidence_sha256,
        "current_snapshot_sha256": validated.snapshot.snapshot_sha256,
        "diff_sha256": validated.diff.diff_sha256,
        "refresh_evidence_sha256": canonical_refresh.evidence_sha256,
        "refresh_guard_capability_sha256": refresh_guard.capability_sha256,
        "refresh_technical_route_set_sha256": canonical_refresh.technical_route_set_sha256,
        "refresh_audit_route_set_sha256": canonical_refresh.audit_route_set_sha256,
        "technical_qualification_capability_sha256": (technical_qualification.capability_sha256),
        "technical_production_selection_sha256": (
            technical_qualification.production_selection_sha256
        ),
        "technical_candidate_registry_sha256": (technical_qualification.candidate_registry_sha256),
        "audit_selection_capability_sha256": audit_selection.capability_sha256,
        "audit_selection_sha256": audit_selection.audit_selection_sha256,
        "audit_scope_sha256": selection.audit_scope_sha256,
        "source_sha256": selection.source_sha256,
        "audit_context_sha256": selection.audit_context_sha256,
        "client_constraints_sha256": selection.client_constraints_sha256,
        "pricing_tolerance_fraction": expected_pricing_tolerance_fraction,
        "verified_at": verified_at,
        "refresh_expires_at": canonical_refresh.expires_at,
        "expires_at": canonical_refresh.expires_at,
        "technical_model_ids": canonical_refresh.technical_model_ids,
        "audit_model_ids": canonical_refresh.audit_model_ids,
        "routes": routes,
        "technical_pricing_route_set_sha256": _canonical_sha256(
            [route.model_dump(mode="json") for route in routes]
        ),
        "audit_pricing_route_set_sha256": _canonical_sha256(
            [route.model_dump(mode="json") for route in routes if route.audit_selected]
        ),
        "pricing_use_authorized": False,
        "technical_selection_authorized": False,
        "audit_selection_authorized": False,
        "provider_access_authorized": False,
        "production_promotion_authorized": False,
    }
    values["evidence_sha256"] = _canonical_sha256(values)
    return (
        AuditModelRefreshPricingEvidence.model_validate(values),
        canonical_refresh,
        technical_ids,
        audit_ids,
    )


def _pricing_authority_payload(
    capability: VerifiedAuditModelRefreshPricingAuthority,
) -> dict[str, Any]:
    return {
        "verified_at": capability.verified_at,
        "expires_at": capability.expires_at,
        "workflow_status_sha256": capability.workflow_status_sha256,
        "refresh_evidence_sha256": capability.refresh_evidence_sha256,
        "refresh_guard_capability_sha256": capability.refresh_guard_capability_sha256,
        "technical_qualification_capability_sha256": (
            capability.technical_qualification_capability_sha256
        ),
        "technical_production_selection_sha256": (capability.technical_production_selection_sha256),
        "audit_selection_capability_sha256": capability.audit_selection_capability_sha256,
        "audit_selection_sha256": capability.audit_selection_sha256,
        "pricing_evidence_sha256": capability.pricing_evidence_sha256,
    }


def _build_refresh_pricing_authority() -> tuple[
    Callable[
        ...,
        tuple[
            AuditModelRefreshPricingEvidence,
            VerifiedAuditModelRefreshPricingAuthority,
        ],
    ],
    Callable[..., None],
    Callable[..., AuditModelRefreshPricingRouteEvidence],
]:
    """Keep pricing authority issuance and state inside one private closure."""

    validate_inputs = _resolve_refresh_pricing_inputs

    @dataclass(frozen=True, slots=True)
    class IssuedState:
        capability_sha256: str
        pricing_evidence: AuditModelRefreshPricingEvidence
        refresh_evidence: AuditModelRefreshEvidence
        refresh_guard: VerifiedAuditModelRefreshGuard
        technical_qualification: VerifiedProductionQualification
        audit_selection: VerifiedAuditModelSelection
        technical_model_identities: tuple[int, ...]
        audit_model_identities: tuple[int, ...]

    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[VerifiedAuditModelRefreshPricingAuthority],
            IssuedState,
        ],
    ] = {}
    lock = threading.RLock()

    def state_for(capability: VerifiedAuditModelRefreshPricingAuthority) -> IssuedState:
        if type(capability) is not VerifiedAuditModelRefreshPricingAuthority:
            raise ValueError("verified refresh pricing authority is absent or forged")
        with lock:
            registered = registry.get(id(capability))
        if registered is None or registered[0]() is not capability:
            raise ValueError("verified refresh pricing authority is absent or forged")
        return registered[1]

    def require(
        capability: VerifiedAuditModelRefreshPricingAuthority,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        refresh_evidence: AuditModelRefreshEvidence,
        refresh_guard: VerifiedAuditModelRefreshGuard,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> None:
        now = _whole_second_utc(now, label="refresh pricing authority use time")
        expected_workflow_status_sha256 = _require_sha256(
            expected_workflow_status_sha256,
            label="expected refresh workflow status",
        )
        state = state_for(capability)
        if (
            refresh_guard is not state.refresh_guard
            or technical_qualification is not state.technical_qualification
            or audit_selection is not state.audit_selection
        ):
            raise ValueError("refresh pricing authority is paired with different live authority")
        if type(refresh_evidence) is not AuditModelRefreshEvidence:
            raise ValueError("refresh pricing authority requires exact refresh evidence")
        canonical_refresh = AuditModelRefreshEvidence.model_validate_json(
            refresh_evidence.model_dump_json(),
            strict=True,
        )
        canonical_pricing = AuditModelRefreshPricingEvidence.model_validate_json(
            state.pricing_evidence.model_dump_json(),
            strict=True,
        )
        if now < capability.verified_at or now >= capability.expires_at:
            raise ValueError("refresh pricing authority is future-dated or expired")
        refresh_guard.require_current(
            now=now,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        if (
            canonical_refresh != state.refresh_evidence
            or expected_workflow_status_sha256 != capability.workflow_status_sha256
            or expected_workflow_status_sha256 != canonical_pricing.workflow_status_sha256
            or capability.capability_sha256 != state.capability_sha256
            or capability.verified_at != canonical_pricing.verified_at
            or capability.expires_at != canonical_pricing.expires_at
            or capability.refresh_evidence_sha256 != canonical_refresh.evidence_sha256
            or capability.refresh_evidence_sha256 != canonical_pricing.refresh_evidence_sha256
            or capability.refresh_guard_capability_sha256 != refresh_guard.capability_sha256
            or capability.refresh_guard_capability_sha256
            != canonical_pricing.refresh_guard_capability_sha256
            or capability.technical_qualification_capability_sha256
            != technical_qualification.capability_sha256
            or capability.technical_production_selection_sha256
            != technical_qualification.production_selection_sha256
            or capability.audit_selection_capability_sha256 != audit_selection.capability_sha256
            or capability.audit_selection_sha256 != audit_selection.audit_selection_sha256
            or capability.pricing_evidence_sha256 != canonical_pricing.evidence_sha256
            or tuple(id(model) for model in technical_qualification.models)
            != state.technical_model_identities
            or tuple(id(model) for model in audit_selection.models) != state.audit_model_identities
            or capability.capability_sha256
            != _canonical_sha256(_pricing_authority_payload(capability))
        ):
            raise ValueError("refresh pricing authority integrity or exact joins failed")

    def route_for(
        capability: VerifiedAuditModelRefreshPricingAuthority,
        exact_model_id: str,
        *,
        now: datetime,
        expected_workflow_status_sha256: str,
        refresh_evidence: AuditModelRefreshEvidence,
        refresh_guard: VerifiedAuditModelRefreshGuard,
        technical_qualification: VerifiedProductionQualification,
        audit_selection: VerifiedAuditModelSelection,
        expected_audit_scope_sha256: str,
        expected_source_sha256: str,
        expected_audit_context_sha256: str,
        expected_client_constraints_sha256: str,
    ) -> AuditModelRefreshPricingRouteEvidence:
        require(
            capability,
            now=now,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            refresh_evidence=refresh_evidence,
            refresh_guard=refresh_guard,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        exact_model_id = require_exact_openrouter_model_id(exact_model_id)
        audit_selection.model_for(
            exact_model_id,
            now=now,
            expected_audit_scope_sha256=expected_audit_scope_sha256,
            expected_source_sha256=expected_source_sha256,
            expected_audit_context_sha256=expected_audit_context_sha256,
            expected_client_constraints_sha256=expected_client_constraints_sha256,
        )
        technical_qualification.model_for(exact_model_id, now=now)
        state = state_for(capability)
        matches = tuple(
            route
            for route in state.pricing_evidence.routes
            if route.exact_model_id == exact_model_id and route.audit_selected
        )
        if len(matches) != 1:
            raise ValueError(f"exact model lacks refresh pricing authority: {exact_model_id}")
        return AuditModelRefreshPricingRouteEvidence.model_validate_json(
            matches[0].model_dump_json(),
            strict=True,
        )

    def resolve(
        *,
        history: ValidatedModelRefreshHistory,
        refresh_evidence: AuditModelRefreshEvidence,
        refresh_guard: VerifiedAuditModelRefreshGuard,
        expected_workflow_status_sha256: str,
        expected_source_commit: str,
        expected_workflow_run_id: str,
        expected_workflow_run_attempt: str,
        technical_qualification: VerifiedProductionQualification,
        audit_selection_evidence: AuditModelSelectionEvidenceBundle,
        audit_selection: VerifiedAuditModelSelection,
        expected_pricing_tolerance_fraction: str,
        expected_soft_max_age_hours: int,
        expected_hard_max_age_hours: int,
        verified_at: datetime,
    ) -> tuple[
        AuditModelRefreshPricingEvidence,
        VerifiedAuditModelRefreshPricingAuthority,
    ]:
        pricing_evidence, canonical_refresh, technical_ids, audit_ids = validate_inputs(
            history=history,
            refresh_evidence=refresh_evidence,
            refresh_guard=refresh_guard,
            expected_workflow_status_sha256=expected_workflow_status_sha256,
            expected_source_commit=expected_source_commit,
            expected_workflow_run_id=expected_workflow_run_id,
            expected_workflow_run_attempt=expected_workflow_run_attempt,
            technical_qualification=technical_qualification,
            audit_selection_evidence=audit_selection_evidence,
            audit_selection=audit_selection,
            expected_pricing_tolerance_fraction=expected_pricing_tolerance_fraction,
            expected_soft_max_age_hours=expected_soft_max_age_hours,
            expected_hard_max_age_hours=expected_hard_max_age_hours,
            verified_at=verified_at,
        )
        private_pricing_evidence = AuditModelRefreshPricingEvidence.model_validate_json(
            pricing_evidence.model_dump_json(),
            strict=True,
        )
        capability = object.__new__(VerifiedAuditModelRefreshPricingAuthority)
        for name, value in (
            ("verified_at", pricing_evidence.verified_at),
            ("expires_at", pricing_evidence.expires_at),
            ("workflow_status_sha256", pricing_evidence.workflow_status_sha256),
            ("refresh_evidence_sha256", pricing_evidence.refresh_evidence_sha256),
            (
                "refresh_guard_capability_sha256",
                pricing_evidence.refresh_guard_capability_sha256,
            ),
            (
                "technical_qualification_capability_sha256",
                technical_qualification.capability_sha256,
            ),
            (
                "technical_production_selection_sha256",
                technical_qualification.production_selection_sha256,
            ),
            ("audit_selection_capability_sha256", audit_selection.capability_sha256),
            ("audit_selection_sha256", audit_selection.audit_selection_sha256),
            ("pricing_evidence_sha256", pricing_evidence.evidence_sha256),
        ):
            object.__setattr__(capability, name, value)
        object.__setattr__(
            capability,
            "capability_sha256",
            _canonical_sha256(_pricing_authority_payload(capability)),
        )
        state = IssuedState(
            capability_sha256=capability.capability_sha256,
            pricing_evidence=private_pricing_evidence,
            refresh_evidence=canonical_refresh,
            refresh_guard=refresh_guard,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            technical_model_identities=technical_ids,
            audit_model_identities=audit_ids,
        )
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[VerifiedAuditModelRefreshPricingAuthority],
        ) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        require(
            capability,
            now=pricing_evidence.verified_at,
            expected_workflow_status_sha256=pricing_evidence.expected_workflow_status_sha256,
            refresh_evidence=canonical_refresh,
            refresh_guard=refresh_guard,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection,
            expected_audit_scope_sha256=pricing_evidence.audit_scope_sha256,
            expected_source_sha256=pricing_evidence.source_sha256,
            expected_audit_context_sha256=pricing_evidence.audit_context_sha256,
            expected_client_constraints_sha256=pricing_evidence.client_constraints_sha256,
        )
        return pricing_evidence, capability

    return resolve, require, route_for


(
    resolve_verified_audit_model_refresh_pricing_authority,
    _require_current_refresh_pricing_authority,
    _pricing_route_for_current_authority,
) = _build_refresh_pricing_authority()
del _build_refresh_pricing_authority
