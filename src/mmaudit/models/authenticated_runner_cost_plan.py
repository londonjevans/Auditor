"""Provider-free staged AUTHRUNNER request-cost plan evidence.

The models in this module aggregate already-proven singleton OpenRouter request
previews.  They are durable planning evidence only: they cannot reserve budget,
dispatch a provider request, issue runner custody, or grant benchmark credit.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation, localcontext
from enum import StrEnum
from itertools import islice
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mmaudit.benchmark.cross_lineage_adjudication import CrossLineageAdjudicationRunKind
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.reporting.json_report import stable_json_bytes

AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT = 24
MAX_AUTHENTICATED_RUNNER_COST_PLAN_BYTES = 4_000_000

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CASE_ID_PATTERN = r"^case-[0-9a-f]{16}$"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CANONICAL_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]{0,49})(?:\.[0-9]{1,48})?$")


class AuthenticatedRunnerCostPlanError(ValueError):
    """A staged request-cost plan is absent, non-exact, or contradictory."""


class AuthenticatedRunnerCostPlanStage(StrEnum):
    """The one request class covered by a staged AUTHRUNNER plan."""

    CANDIDATE = "CANDIDATE"
    JUDGE = "JUDGE"


class AuthenticatedRunnerStagedCostPlan(BaseModel):
    """Exact retry-inclusive cost aggregate for one 24-request run/stage."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    artifact_kind: Literal["authenticated_runner_staged_cost_plan"] = (
        "authenticated_runner_staged_cost_plan"
    )
    schema_version: Literal["1.0"] = "1.0"
    run_kind: CrossLineageAdjudicationRunKind
    stage: AuthenticatedRunnerCostPlanStage

    role: str = Field(min_length=1, max_length=128)
    exact_model_id: str = Field(min_length=3, max_length=384)
    provider_endpoint: str = Field(min_length=1, max_length=256)
    maximum_attempts_per_logical_request: int = Field(ge=1, le=32)

    execution_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    privacy_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    token_budget_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    catalog_identity_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_metadata_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_identity_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_policy_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_record_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_policy_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_capability_sha256: str = Field(pattern=_SHA256_PATTERN)

    structured_output_mode: StructuredOutputMode
    system_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_request_shape_sha256: str = Field(pattern=_SHA256_PATTERN)
    required_provider_parameters_sha256: str = Field(pattern=_SHA256_PATTERN)
    strict_output_protocol_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    reasoning_request_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    reasoning_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_policy_role_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    reasoning_profile_sha256: str = Field(pattern=_SHA256_PATTERN)

    case_ids: tuple[str, ...] = Field(
        min_length=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
        max_length=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
    )
    request_previews: tuple[OpenRouterStructuredRequestCostPreview, ...] = Field(
        min_length=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
        max_length=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
    )
    ordered_request_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_attempt_request_ids: tuple[str, ...] = Field(
        min_length=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
        max_length=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT * 32,
    )
    logical_request_count: Literal[24] = 24
    maximum_provider_attempt_count: int = Field(
        ge=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
        le=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT * 32,
    )
    maximum_cost_usd_per_attempt_exact: str
    maximum_cost_usd_per_logical_request_exact: str
    maximum_cost_usd_exact: str

    authorizes_dispatch: Literal[False] = False
    authorizes_budget_reservation: Literal[False] = False
    authorizes_provider_transport: Literal[False] = False
    grants_review_credit: Literal[False] = False
    grants_completion_credit: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "maximum_cost_usd_per_attempt_exact",
        "maximum_cost_usd_per_logical_request_exact",
        "maximum_cost_usd_exact",
    )
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal(value, label="authenticated runner staged cost")

    @field_validator(
        "authorizes_dispatch",
        "authorizes_budget_reservation",
        "authorizes_provider_transport",
        "grants_review_credit",
        "grants_completion_credit",
        "runner_custody_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("authenticated runner staged cost plans grant no authority")
        return value

    @model_validator(mode="after")
    def requests_bind_one_exact_stage_and_self_hash(self) -> Self:
        if self.case_ids != tuple(sorted(set(self.case_ids))):
            raise ValueError("staged cost-plan case IDs must be unique and sorted")
        if any(re.fullmatch(_CASE_ID_PATTERN, case_id) is None for case_id in self.case_ids):
            raise ValueError("staged cost-plan case ID is invalid")
        if len(self.request_previews) != AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT or any(
            type(preview) is not OpenRouterStructuredRequestCostPreview
            for preview in self.request_previews
        ):
            raise ValueError("staged cost plan requires 24 exact request previews")

        singleton_fields = (
            "role",
            "exact_model_id",
            "provider_endpoint",
            "execution_config_sha256",
            "privacy_config_sha256",
            "token_budget_config_sha256",
            "provider_policy_sha256",
            "discovery_manifest_sha256",
            "discovery_evidence_sha256",
            "discovery_provenance_sha256",
            "catalog_snapshot_sha256",
            "catalog_identity_binding_sha256",
            "model_metadata_snapshot_sha256",
            "model_identity_snapshot_sha256",
            "endpoint_policy_snapshot_sha256",
            "endpoint_record_snapshot_sha256",
            "endpoint_policy_pricing_sha256",
            "endpoint_pricing_sha256",
            "output_capability_sha256",
            "reasoning_capability_sha256",
            "structured_output_mode",
            "system_prompt_sha256",
            "response_schema_sha256",
            "output_request_shape_sha256",
            "required_provider_parameters_sha256",
            "strict_output_protocol_sha256",
            "reasoning_request_sha256",
            "reasoning_plan_sha256",
            "reasoning_policy_sha256",
            "reasoning_policy_role_binding_sha256",
            "reasoning_profile_sha256",
        )
        if any(
            getattr(preview, field) != getattr(self, field)
            for preview in self.request_previews
            for field in singleton_fields
        ) or any(
            preview.maximum_attempts != self.maximum_attempts_per_logical_request
            for preview in self.request_previews
        ):
            raise ValueError(
                "staged cost-plan previews differ from the singleton route, discovery, or config"
            )
        first = self.request_previews[0]
        pricing_schedule = tuple(
            (component.pricing_field, component.unit_price_usd_exact)
            for component in first.cost_components
        )
        if any(
            tuple(
                (component.pricing_field, component.unit_price_usd_exact)
                for component in preview.cost_components
            )
            != pricing_schedule
            or preview.requested_completion_tokens != first.requested_completion_tokens
            or preview.reserved_output_tokens != first.reserved_output_tokens
            or preview.reserved_reasoning_tokens != first.reserved_reasoning_tokens
            for preview in self.request_previews
        ):
            raise ValueError(
                "staged cost-plan previews differ from the singleton pricing or output budget"
            )
        if any(
            preview.context_request_evidence_sha256 is not None
            or preview.rendered_context_sha256 is not None
            or preview.reasoning_qualification_sha256 is not None
            for preview in self.request_previews
        ):
            raise ValueError(
                "provider-free AUTHRUNNER cost previews cannot carry context or qualification authority"
            )

        logical_request_ids = tuple(preview.logical_request_id for preview in self.request_previews)
        preview_hashes = tuple(preview.preview_sha256 for preview in self.request_previews)
        if len(set(logical_request_ids)) != len(logical_request_ids) or len(
            set(preview_hashes)
        ) != len(preview_hashes):
            raise ValueError("staged cost-plan logical request IDs and previews must be unique")
        expected_attempt_ids = _provider_attempt_request_ids(self.request_previews)
        if self.provider_attempt_request_ids != expected_attempt_ids or len(
            expected_attempt_ids
        ) != len(set(expected_attempt_ids)):
            raise ValueError("staged cost-plan provider attempt IDs are inconsistent or replayed")

        expected_request_set_hash = _ordered_request_set_sha256(
            self.case_ids,
            self.request_previews,
        )
        if self.ordered_request_set_sha256 != expected_request_set_hash:
            raise ValueError("staged cost-plan ordered request-set hash is inconsistent")

        per_attempt_maximum, per_request_maximum, stage_maximum = _cost_totals(
            self.request_previews
        )
        if (
            self.logical_request_count != AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT
            or self.maximum_provider_attempt_count != len(expected_attempt_ids)
            or self.maximum_provider_attempt_count
            != self.logical_request_count * self.maximum_attempts_per_logical_request
            or self.maximum_cost_usd_per_attempt_exact != per_attempt_maximum
            or self.maximum_cost_usd_per_logical_request_exact != per_request_maximum
            or self.maximum_cost_usd_exact != stage_maximum
        ):
            raise ValueError("staged cost-plan retry-inclusive aggregate is inconsistent")

        expected_hash = _canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"}))
        if self.plan_sha256 != expected_hash:
            raise ValueError("staged cost-plan hash does not match its exact evidence")
        return self


def build_authenticated_runner_staged_cost_plan(
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    stage: AuthenticatedRunnerCostPlanStage,
    case_ids: Iterable[str],
    request_previews: Iterable[OpenRouterStructuredRequestCostPreview],
) -> AuthenticatedRunnerStagedCostPlan:
    """Build one exact ordered 24-request nonauthorizing staged cost plan."""

    if type(run_kind) is not CrossLineageAdjudicationRunKind:
        raise AuthenticatedRunnerCostPlanError("staged cost-plan run kind has the wrong exact type")
    if type(stage) is not AuthenticatedRunnerCostPlanStage:
        raise AuthenticatedRunnerCostPlanError("staged cost-plan stage has the wrong exact type")
    cases = _bounded_exact_tuple(
        case_ids,
        expected=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
        label="case ID",
    )
    raw_previews = _bounded_exact_tuple(
        request_previews,
        expected=AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
        label="request preview",
    )
    if any(type(preview) is not OpenRouterStructuredRequestCostPreview for preview in raw_previews):
        raise AuthenticatedRunnerCostPlanError(
            "staged cost plan requires exact OpenRouter request previews"
        )
    try:
        previews = tuple(
            OpenRouterStructuredRequestCostPreview.model_validate_json(
                preview.model_dump_json(),
                strict=True,
            )
            for preview in raw_previews
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerCostPlanError(
            "staged cost-plan request preview failed detached validation"
        ) from None
    if previews != raw_previews:
        raise AuthenticatedRunnerCostPlanError(
            "staged cost-plan request preview changed across its boundary"
        )

    first = previews[0]
    try:
        attempt_ids = _provider_attempt_request_ids(previews)
        per_attempt_maximum, per_request_maximum, stage_maximum = _cost_totals(previews)
    except (TypeError, ValueError):
        raise AuthenticatedRunnerCostPlanError(
            "staged cost-plan retry inventory or cost aggregate is invalid"
        ) from None
    values: dict[str, Any] = {
        "artifact_kind": "authenticated_runner_staged_cost_plan",
        "schema_version": "1.0",
        "run_kind": run_kind,
        "stage": stage,
        "role": first.role,
        "exact_model_id": first.exact_model_id,
        "provider_endpoint": first.provider_endpoint,
        "maximum_attempts_per_logical_request": first.maximum_attempts,
        "execution_config_sha256": first.execution_config_sha256,
        "privacy_config_sha256": first.privacy_config_sha256,
        "token_budget_config_sha256": first.token_budget_config_sha256,
        "provider_policy_sha256": first.provider_policy_sha256,
        "discovery_manifest_sha256": first.discovery_manifest_sha256,
        "discovery_evidence_sha256": first.discovery_evidence_sha256,
        "discovery_provenance_sha256": first.discovery_provenance_sha256,
        "catalog_snapshot_sha256": first.catalog_snapshot_sha256,
        "catalog_identity_binding_sha256": first.catalog_identity_binding_sha256,
        "model_metadata_snapshot_sha256": first.model_metadata_snapshot_sha256,
        "model_identity_snapshot_sha256": first.model_identity_snapshot_sha256,
        "endpoint_policy_snapshot_sha256": first.endpoint_policy_snapshot_sha256,
        "endpoint_record_snapshot_sha256": first.endpoint_record_snapshot_sha256,
        "endpoint_policy_pricing_sha256": first.endpoint_policy_pricing_sha256,
        "endpoint_pricing_sha256": first.endpoint_pricing_sha256,
        "output_capability_sha256": first.output_capability_sha256,
        "reasoning_capability_sha256": first.reasoning_capability_sha256,
        "structured_output_mode": first.structured_output_mode,
        "system_prompt_sha256": first.system_prompt_sha256,
        "response_schema_sha256": first.response_schema_sha256,
        "output_request_shape_sha256": first.output_request_shape_sha256,
        "required_provider_parameters_sha256": first.required_provider_parameters_sha256,
        "strict_output_protocol_sha256": first.strict_output_protocol_sha256,
        "reasoning_request_sha256": first.reasoning_request_sha256,
        "reasoning_plan_sha256": first.reasoning_plan_sha256,
        "reasoning_policy_sha256": first.reasoning_policy_sha256,
        "reasoning_policy_role_binding_sha256": (first.reasoning_policy_role_binding_sha256),
        "reasoning_profile_sha256": first.reasoning_profile_sha256,
        "case_ids": cases,
        "request_previews": previews,
        "ordered_request_set_sha256": _ordered_request_set_sha256(cases, previews),
        "provider_attempt_request_ids": attempt_ids,
        "logical_request_count": AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
        "maximum_provider_attempt_count": len(attempt_ids),
        "maximum_cost_usd_per_attempt_exact": per_attempt_maximum,
        "maximum_cost_usd_per_logical_request_exact": per_request_maximum,
        "maximum_cost_usd_exact": stage_maximum,
        "authorizes_dispatch": False,
        "authorizes_budget_reservation": False,
        "authorizes_provider_transport": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
        "runner_custody_authorized": False,
        "release_authorized": False,
    }
    try:
        return AuthenticatedRunnerStagedCostPlan.model_validate(
            {**values, "plan_sha256": _canonical_sha256(values)},
            strict=True,
        )
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerCostPlanError("staged AUTHRUNNER cost plan is invalid") from None


def authenticated_runner_staged_cost_plan_bytes(
    plan: AuthenticatedRunnerStagedCostPlan,
) -> bytes:
    """Return the sole canonical bounded UTF-8 representation of a staged plan."""

    if type(plan) is not AuthenticatedRunnerStagedCostPlan:
        raise AuthenticatedRunnerCostPlanError("staged cost-plan serialization type is invalid")
    try:
        validated = AuthenticatedRunnerStagedCostPlan.model_validate(
            plan.model_dump(mode="python"),
            strict=True,
        )
        raw = stable_json_bytes(validated)
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerCostPlanError(
            "staged cost plan failed deterministic serialization"
        ) from None
    if not raw or len(raw) > MAX_AUTHENTICATED_RUNNER_COST_PLAN_BYTES:
        raise AuthenticatedRunnerCostPlanError("staged cost plan exceeds its byte ceiling")
    return raw


def revalidate_authenticated_runner_staged_cost_plan(
    raw: bytes,
) -> AuthenticatedRunnerStagedCostPlan:
    """Strictly replay canonical staged cost-plan bytes without creating authority."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_AUTHENTICATED_RUNNER_COST_PLAN_BYTES:
        raise AuthenticatedRunnerCostPlanError(
            "staged cost-plan bytes are absent, non-exact, or over the byte ceiling"
        )
    try:
        plan = AuthenticatedRunnerStagedCostPlan.model_validate_json(raw, strict=True)
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerCostPlanError("staged cost-plan bytes do not validate") from None
    if type(plan) is not AuthenticatedRunnerStagedCostPlan:
        raise AuthenticatedRunnerCostPlanError("staged cost-plan parser returned the wrong type")
    if authenticated_runner_staged_cost_plan_bytes(plan) != raw:
        raise AuthenticatedRunnerCostPlanError(
            "staged cost-plan bytes are not canonically serialized"
        )
    return plan


def _bounded_exact_tuple(
    values: Iterable[Any],
    *,
    expected: int,
    label: str,
) -> tuple[Any, ...]:
    try:
        bounded = tuple(islice(iter(values), expected + 1))
    except TypeError:
        raise AuthenticatedRunnerCostPlanError(
            f"staged cost-plan {label} inventory is not iterable"
        ) from None
    if len(bounded) != expected:
        raise AuthenticatedRunnerCostPlanError(
            f"staged cost plan requires exactly {expected} {label}s"
        )
    return bounded


def _provider_attempt_request_ids(
    previews: tuple[OpenRouterStructuredRequestCostPreview, ...],
) -> tuple[str, ...]:
    attempt_ids: list[str] = []
    for preview in previews:
        for attempt in range(1, preview.maximum_attempts + 1):
            request_id = (
                preview.logical_request_id
                if attempt == 1
                else f"{preview.logical_request_id}:attempt:{attempt}"
            )
            if _REQUEST_ID_RE.fullmatch(request_id) is None:
                raise ValueError("staged cost-plan logical ID cannot produce bounded retry IDs")
            attempt_ids.append(request_id)
    return tuple(attempt_ids)


def _ordered_request_set_sha256(
    case_ids: tuple[str, ...],
    previews: tuple[OpenRouterStructuredRequestCostPreview, ...],
) -> str:
    return _canonical_sha256(
        [
            {
                "case_id": case_id,
                "logical_request_id": preview.logical_request_id,
                "preview_sha256": preview.preview_sha256,
            }
            for case_id, preview in zip(case_ids, previews, strict=True)
        ]
    )


def _cost_totals(
    previews: tuple[OpenRouterStructuredRequestCostPreview, ...],
) -> tuple[str, str, str]:
    try:
        per_attempt = tuple(
            _decimal_value(
                preview.maximum_cost_usd_per_attempt_exact,
                label="request preview per-attempt cost",
            )
            for preview in previews
        )
        per_request = tuple(
            _decimal_value(
                preview.maximum_cost_usd_all_attempts_exact,
                label="request preview retry-inclusive cost",
            )
            for preview in previews
        )
        with localcontext() as context:
            context.prec = 200
            stage_total = sum(per_request, start=Decimal(0))
    except (InvalidOperation, ValueError):
        raise ValueError("staged cost-plan request costs are invalid") from None
    return (
        _format_decimal(max(per_attempt)),
        _format_decimal(max(per_request)),
        _format_decimal(stage_total),
    )


def _decimal_value(value: str, *, label: str) -> Decimal:
    canonical = _canonical_decimal(value, label=label)
    try:
        parsed = Decimal(canonical)
    except InvalidOperation:
        raise ValueError(f"{label} is invalid") from None
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{label} is invalid")
    return parsed


def _canonical_decimal(value: object, *, label: str) -> str:
    if type(value) is not str or _CANONICAL_DECIMAL_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be canonical non-negative decimal text")
    parsed = Decimal(value)
    if not parsed.is_finite() or parsed < 0 or _format_decimal(parsed) != value:
        raise ValueError(f"{label} must be canonical non-negative decimal text")
    return value


def _format_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_canonical_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported staged cost-plan value: {type(value).__name__}")


__all__ = [
    "AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT",
    "MAX_AUTHENTICATED_RUNNER_COST_PLAN_BYTES",
    "AuthenticatedRunnerCostPlanError",
    "AuthenticatedRunnerCostPlanStage",
    "AuthenticatedRunnerStagedCostPlan",
    "authenticated_runner_staged_cost_plan_bytes",
    "build_authenticated_runner_staged_cost_plan",
    "revalidate_authenticated_runner_staged_cost_plan",
]
