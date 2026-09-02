"""Provider-free planning evidence for bounded model-surface coverage.

This module deliberately does not dispatch requests or grant review/completion
credit.  It turns an already authoritative surface inventory and already approved
reviewer bindings into a deterministic, bounded gap-fill plan.  Provider-specific
request construction can then attach exact resource previews before any planned
task is dispatched.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from decimal import Context, Decimal, Inexact, InvalidOperation, Overflow, Rounded, localcontext
from enum import StrEnum
from typing import Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.constants import CANDIDATE_INDEPENDENT_SPECIALIST_ROLES
from mmaudit.models.identifiers import EXACT_MODEL_ID_PATTERN, require_exact_openrouter_model_id
from mmaudit.models.schemas import (
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewPriority,
    ModelSurfaceReviewRequest,
)

MAX_COVERAGE_SURFACES = 10_000
MAX_COVERAGE_REVIEWERS = 256
MAX_COVERAGE_ASSIGNMENTS = 200_000
MAX_COVERAGE_TASKS = 200_000
MAX_SURFACES_PER_GAP_TASK = 32
MAX_ROOT_LINEAGES_PER_SURFACE = 16
MAX_RESOURCE_ATTEMPTS = 64

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ROOT_LINEAGE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SURFACE_ID_PATTERN = r"^model-surface:[0-9a-f]{64}$"
_SAFE_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_SAFE_SCOPE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SCHEDULER_TASK_ID_PATTERN = r"^scheduler-task-[0-9a-f]{64}$"
_SCHEDULER_REQUEST_ID_PATTERN = r"^scheduler-request-[0-9a-f]{64}$"
_ATTEMPT_REQUEST_ID_PATTERN = r"^scheduler-request-[0-9a-f]{64}(?::attempt:[1-9][0-9]{0,2})?$"
_COVERAGE_TASK_ID_PATTERN = r"^model-surface-gap-task-[0-9a-f]{64}$"
_PROVIDER_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,255}$"
_CANONICAL_DECIMAL_PATTERN = re.compile(r"^(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,30})?$")
_FALSE_NEGATIVE_HUNTER_ROLES = frozenset(
    {"false_negative_hunter", "specialist:false_negative_hunter"}
)


def _decimal_context() -> Context:
    """Return a fresh context so caller-global Decimal state cannot change evidence."""

    return Context(
        prec=96,
        traps=[InvalidOperation, Overflow, Inexact, Rounded],
    )


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
    if value != normalized:
        raise ValueError(f"{label} must use canonical decimal text without redundant notation")
    return value


def _multiply_decimal_text(value: str, multiplier: int) -> str:
    with localcontext(_decimal_context()):
        result = Decimal(value) * Decimal(multiplier)
    return _format_decimal(result)


def _sum_decimal_text(values: Iterable[str]) -> str:
    with localcontext(_decimal_context()):
        total = Decimal(0)
        for value in values:
            total += Decimal(value)
    return _format_decimal(total)


def _format_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


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
    return hashlib.sha256(_canonical_json_text(value).encode("utf-8")).hexdigest()


def _canonical_json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Decimal):
        return _format_decimal(value)
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _bounded_tuple[T](
    values: Iterable[T],
    *,
    maximum: int,
    label: str,
) -> tuple[T, ...]:
    """Consume at most ``maximum + 1`` items without trusting length hints."""

    if isinstance(values, str | bytes | bytearray):
        raise ValueError(f"{label} must be an iterable of records")
    try:
        iterator = iter(values)
    except TypeError:
        raise ValueError(f"{label} must be iterable") from None
    collected: list[T] = []
    for item in iterator:
        if len(collected) >= maximum:
            raise ValueError(f"{label} exceeds the bounded maximum of {maximum}")
        collected.append(item)
    return tuple(collected)


def _bounded_mapping_items[T](
    values: Mapping[str, T],
    *,
    maximum: int,
    label: str,
) -> tuple[tuple[str, T], ...]:
    if not isinstance(values, Mapping):
        raise ValueError(f"{label} must be a mapping")
    raw_items = _bounded_tuple(values.items(), maximum=maximum, label=f"{label} entries")
    normalized: list[tuple[str, T]] = []
    seen: set[str] = set()
    for raw_item in raw_items:
        if not isinstance(raw_item, tuple) or len(raw_item) != 2:
            raise ValueError(f"{label} entries must be key/value pairs")
        key, value = raw_item
        if type(key) is not str:
            raise ValueError(f"{label} keys must be strings")
        if key in seen:
            raise ValueError(f"{label} contains an ambiguous duplicate key")
        seen.add(key)
        normalized.append((key, value))
    return tuple(normalized)


def _require_sorted_unique_strings(
    values: tuple[str, ...],
    *,
    pattern: str,
    label: str,
) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))) or any(
        type(value) is not str or re.fullmatch(pattern, value) is None for value in values
    ):
        raise ValueError(f"{label} must be valid, unique, and sorted")
    return values


def _require_self_hash(model: BaseModel, field: str) -> None:
    expected = _canonical_sha256(model.model_dump(mode="json", exclude={field}))
    if getattr(model, field) != expected:
        raise ValueError(f"{field} does not match the canonical evidence")


class _FrozenNonAuthorizingModel(BaseModel):
    """Immutable evidence which can never itself authorize execution or credit."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    authorizes_dispatch: Literal[False] = False
    grants_review_credit: Literal[False] = False
    grants_completion_credit: Literal[False] = False


class ModelSurfaceRiskTier(StrEnum):
    """Closed deterministic risk tiers for model-review surfaces."""

    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


class ModelSurfaceAssignmentPurpose(StrEnum):
    """Why one reviewer/surface assignment exists in a gap-fill plan."""

    LINEAGE_GAP = "lineage_gap"
    RESPONSIBILITY_SEED = "responsibility_seed"


class ModelSurfaceResourceFailureCode(StrEnum):
    """Bounded reasons why a complete resource portfolio is not feasible."""

    COVERAGE_PLAN_INFEASIBLE = "COVERAGE_PLAN_INFEASIBLE"
    REQUEST_CAP_EXCEEDED = "REQUEST_CAP_EXCEEDED"
    INPUT_TOKEN_CAP_EXCEEDED = "INPUT_TOKEN_CAP_EXCEEDED"
    OUTPUT_TOKEN_CAP_EXCEEDED = "OUTPUT_TOKEN_CAP_EXCEEDED"
    USD_CAP_EXCEEDED = "USD_CAP_EXCEEDED"
    ROLE_USD_CAP_MISSING = "ROLE_USD_CAP_MISSING"
    ROLE_USD_CAP_EXCEEDED = "ROLE_USD_CAP_EXCEEDED"
    MODEL_USD_CAP_MISSING = "MODEL_USD_CAP_MISSING"
    MODEL_USD_CAP_EXCEEDED = "MODEL_USD_CAP_EXCEEDED"


class ModelSurfaceResourceScopeKind(StrEnum):
    """Closed cost-accounting dimensions used by scoped USD preflight."""

    ROLE = "role"
    MODEL = "model"


class ModelPortfolioTaskKind(StrEnum):
    """Closed task classes covered by the pre-orientation spend reservation."""

    ORIENTATION = "orientation"
    RETRIEVAL_PLANNING = "retrieval_planning"
    COMPACT_COVERAGE = "compact_coverage"
    SOURCE_AUDIT = "source_audit"
    WHOLE_PROTOCOL = "whole_protocol"
    INVARIANT_REVIEW = "invariant_review"
    REPORT_QUALITY = "report_quality"


def classify_model_surface_risk(
    request: ModelSurfaceReviewRequest,
) -> ModelSurfaceRiskTier:
    """Classify one revalidated request using the frozen V3 tier contract."""

    validated = ModelSurfaceReviewRequest.model_validate(request.model_dump(mode="python"))
    if validated.critical:
        return ModelSurfaceRiskTier.T0
    if validated.kind in {ModelReviewSurfaceKind.ENTRY_POINT, ModelReviewSurfaceKind.CALL}:
        return ModelSurfaceRiskTier.T1
    if validated.kind in {
        ModelReviewSurfaceKind.INTERNAL_FUNCTION,
        ModelReviewSurfaceKind.STATE,
    }:
        return ModelSurfaceRiskTier.T2
    if validated.kind in {ModelReviewSurfaceKind.CONTRACT, ModelReviewSurfaceKind.SOURCE_FILE}:
        return ModelSurfaceRiskTier.T3
    raise ValueError(
        f"noncritical {validated.kind.value} surfaces cannot be silently downgraded to T1-T3"
    )


class ModelSurfaceTierRequirement(_FrozenNonAuthorizingModel):
    """One immutable, self-hashed tier-to-lineage requirement."""

    artifact_kind: Literal["model_surface_tier_requirement"] = "model_surface_tier_requirement"
    schema_version: Literal["1.0"] = "1.0"
    tier: ModelSurfaceRiskTier
    minimum_root_lineages: int = Field(ge=1, le=MAX_ROOT_LINEAGES_PER_SURFACE)
    completion_blocking: Literal[True] = True
    requirement_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        tier: ModelSurfaceRiskTier,
        minimum_root_lineages: int,
    ) -> ModelSurfaceTierRequirement:
        values = {
            "artifact_kind": "model_surface_tier_requirement",
            "schema_version": "1.0",
            "tier": tier,
            "minimum_root_lineages": minimum_root_lineages,
            "completion_blocking": True,
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "requirement_sha256": _canonical_sha256(values)})

    @model_validator(mode="after")
    def requirement_is_self_hashed(self) -> Self:
        _require_self_hash(self, "requirement_sha256")
        return self


class ModelSurfaceCoveragePolicy(_FrozenNonAuthorizingModel):
    """Complete immutable T0-T3 policy derived from one T0 lineage floor."""

    artifact_kind: Literal["model_surface_coverage_policy"] = "model_surface_coverage_policy"
    schema_version: Literal["1.0"] = "1.0"
    minimum_t0_root_lineages: int = Field(ge=1, le=MAX_ROOT_LINEAGES_PER_SURFACE)
    requirements: tuple[ModelSurfaceTierRequirement, ...] = Field(min_length=4, max_length=4)
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, minimum_t0_root_lineages: int) -> ModelSurfaceCoveragePolicy:
        if type(minimum_t0_root_lineages) is not int:
            raise ValueError("minimum T0 root lineages must be an exact integer")
        requirements = _tier_requirements(minimum_t0_root_lineages)
        values = {
            "artifact_kind": "model_surface_coverage_policy",
            "schema_version": "1.0",
            "minimum_t0_root_lineages": minimum_t0_root_lineages,
            "requirements": requirements,
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "policy_sha256": _canonical_sha256(values)})

    def requirement_for(self, tier: ModelSurfaceRiskTier) -> ModelSurfaceTierRequirement:
        return next(requirement for requirement in self.requirements if requirement.tier is tier)

    @model_validator(mode="after")
    def policy_is_complete_and_self_hashed(self) -> Self:
        expected = _tier_requirements(self.minimum_t0_root_lineages)
        if self.requirements != expected:
            raise ValueError("coverage policy must contain the exact derived T0-T3 requirements")
        _require_self_hash(self, "policy_sha256")
        return self


def _tier_requirements(
    minimum_t0_root_lineages: int,
) -> tuple[ModelSurfaceTierRequirement, ...]:
    if (
        type(minimum_t0_root_lineages) is not int
        or minimum_t0_root_lineages < 1
        or minimum_t0_root_lineages > MAX_ROOT_LINEAGES_PER_SURFACE
    ):
        raise ValueError(f"minimum T0 root lineages must be in 1..{MAX_ROOT_LINEAGES_PER_SURFACE}")
    floors = {
        ModelSurfaceRiskTier.T0: minimum_t0_root_lineages,
        ModelSurfaceRiskTier.T1: min(2, minimum_t0_root_lineages),
        ModelSurfaceRiskTier.T2: 1,
        ModelSurfaceRiskTier.T3: 1,
    }
    return tuple(
        ModelSurfaceTierRequirement.build(tier=tier, minimum_root_lineages=floors[tier])
        for tier in ModelSurfaceRiskTier
    )


def build_model_surface_coverage_policy(
    minimum_t0_root_lineages: int,
) -> ModelSurfaceCoveragePolicy:
    """Build the exact provider-free tier policy."""

    return ModelSurfaceCoveragePolicy.build(minimum_t0_root_lineages)


class ModelSurfaceReviewerBinding(_FrozenNonAuthorizingModel):
    """One exact configured reviewer/model/root binding available to the planner."""

    artifact_kind: Literal["model_surface_reviewer_binding"] = "model_surface_reviewer_binding"
    schema_version: Literal["1.0"] = "1.0"
    review_role: str = Field(pattern=_SAFE_ROLE_PATTERN)
    requested_model: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    root_lineage: str = Field(pattern=_ROOT_LINEAGE_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        review_role: str,
        requested_model: str,
        root_lineage: str,
    ) -> ModelSurfaceReviewerBinding:
        values = {
            "artifact_kind": "model_surface_reviewer_binding",
            "schema_version": "1.0",
            "review_role": review_role,
            "requested_model": requested_model,
            "root_lineage": root_lineage,
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "binding_sha256": _canonical_sha256(values)})

    @field_validator("requested_model")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="coverage reviewer model")

    @model_validator(mode="after")
    def binding_is_self_hashed(self) -> Self:
        _require_self_hash(self, "binding_sha256")
        return self


class ModelSurfaceCoverageRequirement(_FrozenNonAuthorizingModel):
    """One exact scoped request and its immutable risk/lineage requirement."""

    artifact_kind: Literal["model_surface_coverage_requirement"] = (
        "model_surface_coverage_requirement"
    )
    schema_version: Literal["1.0"] = "1.0"
    surface_id: str = Field(pattern=_SURFACE_ID_PATTERN)
    scope_id: str = Field(pattern=_SAFE_SCOPE_PATTERN, max_length=200)
    request_canonical_json: str = Field(min_length=2, max_length=1_000_000)
    request_sha256: str = Field(pattern=_SHA256_PATTERN)
    risk_tier: ModelSurfaceRiskTier
    minimum_root_lineages: int = Field(ge=1, le=MAX_ROOT_LINEAGES_PER_SURFACE)
    completion_blocking: Literal[True] = True
    credited_root_lineages: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_ROOT_LINEAGES_PER_SURFACE,
    )
    requirement_sha256: str = Field(pattern=_SHA256_PATTERN)

    _REQUEST_CACHE_LIMIT: ClassVar[int] = 1_000_000

    @classmethod
    def build(
        cls,
        *,
        request: ModelSurfaceReviewRequest,
        scope_id: str,
        tier_requirement: ModelSurfaceTierRequirement,
        credited_root_lineages: tuple[str, ...],
    ) -> ModelSurfaceCoverageRequirement:
        validated = ModelSurfaceReviewRequest.model_validate(request.model_dump(mode="python"))
        request_payload = validated.model_dump(mode="json")
        request_json = _canonical_json_text(request_payload)
        values = {
            "artifact_kind": "model_surface_coverage_requirement",
            "schema_version": "1.0",
            "surface_id": validated.surface_id,
            "scope_id": scope_id,
            "request_canonical_json": request_json,
            "request_sha256": _canonical_sha256(request_payload),
            "risk_tier": classify_model_surface_risk(validated),
            "minimum_root_lineages": tier_requirement.minimum_root_lineages,
            "completion_blocking": True,
            "credited_root_lineages": credited_root_lineages,
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "requirement_sha256": _canonical_sha256(values)})

    def request(self) -> ModelSurfaceReviewRequest:
        """Return a fresh validated request from the immutable canonical payload."""

        return ModelSurfaceReviewRequest.model_validate_json(self.request_canonical_json)

    @field_validator("credited_root_lineages")
    @classmethod
    def credited_roots_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique_strings(
            value,
            pattern=_ROOT_LINEAGE_PATTERN,
            label="credited model-surface root lineages",
        )

    @model_validator(mode="after")
    def requirement_matches_its_immutable_request(self) -> Self:
        request = self.request()
        request_payload = request.model_dump(mode="json")
        if self.request_canonical_json != _canonical_json_text(request_payload):
            raise ValueError("coverage requirement request JSON is not canonical")
        if self.surface_id != request.surface_id:
            raise ValueError("coverage requirement surface differs from its request")
        if self.request_sha256 != _canonical_sha256(request_payload):
            raise ValueError("coverage requirement request hash is inconsistent")
        if self.risk_tier is not classify_model_surface_risk(request):
            raise ValueError("coverage requirement tier differs from its request")
        _require_self_hash(self, "requirement_sha256")
        return self


class ModelSurfaceGapAssignment(_FrozenNonAuthorizingModel):
    """One non-authorizing reviewer assignment for a lineage gap or responsibility seed."""

    artifact_kind: Literal["model_surface_gap_assignment"] = "model_surface_gap_assignment"
    schema_version: Literal["1.0"] = "1.0"
    surface_id: str = Field(pattern=_SURFACE_ID_PATTERN)
    scope_id: str = Field(pattern=_SAFE_SCOPE_PATTERN, max_length=200)
    requirement_sha256: str = Field(pattern=_SHA256_PATTERN)
    risk_tier: ModelSurfaceRiskTier
    review_role: str = Field(pattern=_SAFE_ROLE_PATTERN)
    requested_model: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    root_lineage: str = Field(pattern=_ROOT_LINEAGE_PATTERN)
    purpose: ModelSurfaceAssignmentPurpose
    counts_toward_lineage_requirement: bool
    assignment_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        requirement: ModelSurfaceCoverageRequirement,
        reviewer: ModelSurfaceReviewerBinding,
        purpose: ModelSurfaceAssignmentPurpose,
    ) -> ModelSurfaceGapAssignment:
        values = {
            "artifact_kind": "model_surface_gap_assignment",
            "schema_version": "1.0",
            "surface_id": requirement.surface_id,
            "scope_id": requirement.scope_id,
            "requirement_sha256": requirement.requirement_sha256,
            "risk_tier": requirement.risk_tier,
            "review_role": reviewer.review_role,
            "requested_model": reviewer.requested_model,
            "root_lineage": reviewer.root_lineage,
            "purpose": purpose,
            "counts_toward_lineage_requirement": (
                purpose is ModelSurfaceAssignmentPurpose.LINEAGE_GAP
            ),
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "assignment_sha256": _canonical_sha256(values)})

    @field_validator("requested_model")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="coverage assignment model")

    @model_validator(mode="after")
    def assignment_is_consistent_and_self_hashed(self) -> Self:
        expected_credit = self.purpose is ModelSurfaceAssignmentPurpose.LINEAGE_GAP
        if self.counts_toward_lineage_requirement is not expected_credit:
            raise ValueError("coverage assignment purpose and lineage contribution disagree")
        _require_self_hash(self, "assignment_sha256")
        return self


class ModelSurfaceGapTask(_FrozenNonAuthorizingModel):
    """One exact single-scope request batch, capped at 32 surface records."""

    artifact_kind: Literal["model_surface_gap_task"] = "model_surface_gap_task"
    schema_version: Literal["1.0"] = "1.0"
    scope_id: str = Field(pattern=_SAFE_SCOPE_PATTERN, max_length=200)
    review_role: str = Field(pattern=_SAFE_ROLE_PATTERN)
    requested_model: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    root_lineage: str = Field(pattern=_ROOT_LINEAGE_PATTERN)
    surface_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_SURFACES_PER_GAP_TASK,
    )
    assignment_sha256s: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_SURFACES_PER_GAP_TASK,
    )
    requested_surface_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    lineage_gap_assignment_count: int = Field(ge=0, le=MAX_SURFACES_PER_GAP_TASK)
    responsibility_seed_assignment_count: int = Field(ge=0, le=MAX_SURFACES_PER_GAP_TASK)
    task_id: str = Field(pattern=_COVERAGE_TASK_ID_PATTERN)
    task_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        assignments: tuple[ModelSurfaceGapAssignment, ...],
        requests: tuple[ModelSurfaceReviewRequest, ...],
    ) -> ModelSurfaceGapTask:
        if not assignments or len(assignments) > MAX_SURFACES_PER_GAP_TASK:
            raise ValueError("coverage task must contain 1..32 assignments")
        if len(assignments) != len(requests):
            raise ValueError("coverage task assignments and requests must be one-to-one")
        first = assignments[0]
        surface_ids = tuple(assignment.surface_id for assignment in assignments)
        if tuple(request.surface_id for request in requests) != surface_ids:
            raise ValueError("coverage task requests differ from its assignments")
        values = {
            "artifact_kind": "model_surface_gap_task",
            "schema_version": "1.0",
            "scope_id": first.scope_id,
            "review_role": first.review_role,
            "requested_model": first.requested_model,
            "root_lineage": first.root_lineage,
            "surface_ids": surface_ids,
            "assignment_sha256s": tuple(assignment.assignment_sha256 for assignment in assignments),
            "requested_surface_manifest_sha256": (
                ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests)
            ),
            "lineage_gap_assignment_count": sum(
                assignment.purpose is ModelSurfaceAssignmentPurpose.LINEAGE_GAP
                for assignment in assignments
            ),
            "responsibility_seed_assignment_count": sum(
                assignment.purpose is ModelSurfaceAssignmentPurpose.RESPONSIBILITY_SEED
                for assignment in assignments
            ),
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        identity = _canonical_sha256(values)
        body = {**values, "task_id": f"model-surface-gap-task-{identity}"}
        return cls.model_validate({**body, "task_sha256": _canonical_sha256(body)})

    @field_validator("requested_model")
    @classmethod
    def model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="coverage task model")

    @field_validator("surface_ids")
    @classmethod
    def surfaces_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique_strings(
            value,
            pattern=_SURFACE_ID_PATTERN,
            label="coverage task surface IDs",
        )

    @field_validator("assignment_sha256s")
    @classmethod
    def assignments_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None for item in value
        ):
            raise ValueError("coverage task assignment hashes must be valid and unique")
        return value

    @model_validator(mode="after")
    def task_identity_and_counts_are_consistent(self) -> Self:
        if len(self.surface_ids) != len(self.assignment_sha256s):
            raise ValueError("coverage task surface and assignment counts differ")
        if self.lineage_gap_assignment_count + self.responsibility_seed_assignment_count != len(
            self.surface_ids
        ):
            raise ValueError("coverage task purpose counts differ from its assignments")
        identity_payload = self.model_dump(
            mode="json",
            exclude={"task_id", "task_sha256"},
        )
        expected_identity = _canonical_sha256(identity_payload)
        if self.task_id != f"model-surface-gap-task-{expected_identity}":
            raise ValueError("coverage task ID differs from its immutable work")
        _require_self_hash(self, "task_sha256")
        return self


class ModelSurfaceCoverageDeficit(_FrozenNonAuthorizingModel):
    """Exact remaining independent-root deficit for one mandatory surface."""

    artifact_kind: Literal["model_surface_coverage_deficit"] = "model_surface_coverage_deficit"
    schema_version: Literal["1.0"] = "1.0"
    surface_id: str = Field(pattern=_SURFACE_ID_PATTERN)
    requirement_sha256: str = Field(pattern=_SHA256_PATTERN)
    minimum_root_lineages: int = Field(ge=1, le=MAX_ROOT_LINEAGES_PER_SURFACE)
    credited_root_lineages: tuple[str, ...] = Field(max_length=MAX_ROOT_LINEAGES_PER_SURFACE)
    assigned_root_lineages: tuple[str, ...] = Field(max_length=MAX_ROOT_LINEAGES_PER_SURFACE)
    missing_root_lineages: int = Field(ge=1, le=MAX_ROOT_LINEAGES_PER_SURFACE)
    deficit_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        requirement: ModelSurfaceCoverageRequirement,
        assigned_root_lineages: tuple[str, ...],
    ) -> ModelSurfaceCoverageDeficit:
        covered = set(requirement.credited_root_lineages) | set(assigned_root_lineages)
        missing = requirement.minimum_root_lineages - len(covered)
        if missing <= 0:
            raise ValueError("satisfied surface cannot produce a coverage deficit")
        values = {
            "artifact_kind": "model_surface_coverage_deficit",
            "schema_version": "1.0",
            "surface_id": requirement.surface_id,
            "requirement_sha256": requirement.requirement_sha256,
            "minimum_root_lineages": requirement.minimum_root_lineages,
            "credited_root_lineages": requirement.credited_root_lineages,
            "assigned_root_lineages": assigned_root_lineages,
            "missing_root_lineages": missing,
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "deficit_sha256": _canonical_sha256(values)})

    @field_validator("credited_root_lineages", "assigned_root_lineages")
    @classmethod
    def roots_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique_strings(
            value,
            pattern=_ROOT_LINEAGE_PATTERN,
            label="coverage deficit root lineages",
        )

    @model_validator(mode="after")
    def deficit_is_consistent_and_self_hashed(self) -> Self:
        if set(self.credited_root_lineages) & set(self.assigned_root_lineages):
            raise ValueError("credited and gap-assigned root lineages must be disjoint")
        expected = self.minimum_root_lineages - len(
            set(self.credited_root_lineages) | set(self.assigned_root_lineages)
        )
        if self.missing_root_lineages != expected or expected <= 0:
            raise ValueError("coverage deficit count is inconsistent")
        _require_self_hash(self, "deficit_sha256")
        return self


class ModelSurfaceCoveragePlan(_FrozenNonAuthorizingModel):
    """Complete deterministic gap-fill plan; never dispatch authority."""

    artifact_kind: Literal["model_surface_coverage_plan"] = "model_surface_coverage_plan"
    schema_version: Literal["1.0"] = "1.0"
    policy: ModelSurfaceCoveragePolicy
    surface_request_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    requirements: tuple[ModelSurfaceCoverageRequirement, ...] = Field(
        min_length=1,
        max_length=MAX_COVERAGE_SURFACES,
    )
    reviewer_bindings: tuple[ModelSurfaceReviewerBinding, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    mandatory_reviewer_roles: tuple[str, ...] = Field(max_length=MAX_COVERAGE_REVIEWERS)
    assignments: tuple[ModelSurfaceGapAssignment, ...] = Field(
        max_length=MAX_COVERAGE_ASSIGNMENTS,
    )
    tasks: tuple[ModelSurfaceGapTask, ...] = Field(max_length=MAX_COVERAGE_TASKS)
    deficits: tuple[ModelSurfaceCoverageDeficit, ...] = Field(
        max_length=MAX_COVERAGE_SURFACES,
    )
    surface_count: int = Field(ge=1, le=MAX_COVERAGE_SURFACES)
    lineage_gap_assignment_count: int = Field(ge=0, le=MAX_COVERAGE_ASSIGNMENTS)
    responsibility_seed_assignment_count: int = Field(ge=0, le=MAX_COVERAGE_REVIEWERS)
    task_count: int = Field(ge=0, le=MAX_COVERAGE_TASKS)
    lineage_requirements_satisfied: bool
    mandatory_responsibilities_satisfied: bool
    feasible: bool
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("mandatory_reviewer_roles")
    @classmethod
    def mandatory_roles_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _require_sorted_unique_strings(
            value,
            pattern=_SAFE_ROLE_PATTERN,
            label="mandatory coverage reviewer roles",
        )

    @model_validator(mode="after")
    def plan_is_exact_and_self_hashed(self) -> Self:
        if self.requirements != tuple(sorted(self.requirements, key=lambda item: item.surface_id)):
            raise ValueError("coverage requirements must be sorted by surface ID")
        if len({item.surface_id for item in self.requirements}) != len(self.requirements):
            raise ValueError("coverage plan surface requirements must be unique")
        binding_keys = [
            (item.review_role, item.requested_model, item.root_lineage)
            for item in self.reviewer_bindings
        ]
        if binding_keys != sorted(binding_keys) or len(
            {item.review_role for item in self.reviewer_bindings}
        ) != len(self.reviewer_bindings):
            raise ValueError("coverage reviewer bindings must be role-unique and sorted")
        binding_roles = {item.review_role for item in self.reviewer_bindings}
        if not set(self.mandatory_reviewer_roles) <= binding_roles:
            raise ValueError("mandatory coverage role lacks an exact reviewer binding")

        rebuilt_requirements = tuple(
            ModelSurfaceCoverageRequirement.build(
                request=requirement.request(),
                scope_id=requirement.scope_id,
                tier_requirement=self.policy.requirement_for(requirement.risk_tier),
                credited_root_lineages=requirement.credited_root_lineages,
            )
            for requirement in self.requirements
        )
        if self.requirements != rebuilt_requirements:
            raise ValueError("coverage requirements differ from the sealed tier policy")
        requests = tuple(requirement.request() for requirement in self.requirements)
        expected_manifest = ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
            requests
        )
        if self.surface_request_manifest_sha256 != expected_manifest:
            raise ValueError("coverage plan request manifest is inconsistent")

        expected_assignments = _derive_assignments(
            self.requirements,
            self.reviewer_bindings,
            self.mandatory_reviewer_roles,
        )
        if self.assignments != expected_assignments:
            raise ValueError("coverage assignments are not the deterministic minimal plan")
        expected_deficits = _derive_deficits(self.requirements, self.assignments)
        if self.deficits != expected_deficits:
            raise ValueError("coverage deficits differ from the exact root shortfall")
        expected_tasks = _derive_tasks(self.requirements, self.assignments)
        if self.tasks != expected_tasks:
            raise ValueError("coverage tasks differ from the exact scoped 32-surface chunks")

        gap_count = sum(
            assignment.purpose is ModelSurfaceAssignmentPurpose.LINEAGE_GAP
            for assignment in self.assignments
        )
        seed_count = len(self.assignments) - gap_count
        roles_with_work = {assignment.review_role for assignment in self.assignments}
        lineage_satisfied = not self.deficits
        responsibilities_satisfied = set(self.mandatory_reviewer_roles) <= roles_with_work
        if (
            self.surface_count != len(self.requirements)
            or self.lineage_gap_assignment_count != gap_count
            or self.responsibility_seed_assignment_count != seed_count
            or self.task_count != len(self.tasks)
            or self.lineage_requirements_satisfied is not lineage_satisfied
            or self.mandatory_responsibilities_satisfied is not responsibilities_satisfied
            or self.feasible is not (lineage_satisfied and responsibilities_satisfied)
        ):
            raise ValueError("coverage plan derived counts or feasibility are inconsistent")
        _require_self_hash(self, "plan_sha256")
        return self


def build_model_surface_coverage_plan(
    requests: Iterable[ModelSurfaceReviewRequest],
    reviewer_bindings: Iterable[ModelSurfaceReviewerBinding],
    *,
    surface_scope_by_id: Mapping[str, str],
    mandatory_reviewer_roles: Iterable[str] = (),
    credited_root_lineages_by_surface: Mapping[str, Iterable[str]] | None = None,
    minimum_t0_root_lineages: int = 3,
) -> ModelSurfaceCoveragePlan:
    """Build one exact bounded plan without dispatching or reserving resources."""

    raw_requests = _bounded_tuple(
        requests,
        maximum=MAX_COVERAGE_SURFACES,
        label="model surface requests",
    )
    if not raw_requests:
        raise ValueError("coverage planning requires a non-empty surface inventory")
    validated_requests = tuple(
        ModelSurfaceReviewRequest.model_validate(request.model_dump(mode="python"))
        for request in raw_requests
    )
    if len({request.surface_id for request in validated_requests}) != len(validated_requests):
        raise ValueError("coverage planning surface inventory contains duplicate IDs")
    validated_requests = tuple(sorted(validated_requests, key=lambda item: item.surface_id))
    surface_ids = {request.surface_id for request in validated_requests}

    scope_items = _bounded_mapping_items(
        surface_scope_by_id,
        maximum=MAX_COVERAGE_SURFACES,
        label="surface scope mapping",
    )
    scope_by_id: dict[str, str] = {}
    for surface_id, scope_id in scope_items:
        if re.fullmatch(_SURFACE_ID_PATTERN, surface_id) is None:
            raise ValueError("surface scope mapping contains an invalid surface ID")
        if type(scope_id) is not str or re.fullmatch(_SAFE_SCOPE_PATTERN, scope_id) is None:
            raise ValueError("surface scope mapping contains an invalid scope ID")
        scope_by_id[surface_id] = scope_id
    if set(scope_by_id) != surface_ids:
        raise ValueError("surface scope mapping must exactly cover the authoritative inventory")

    raw_bindings = _bounded_tuple(
        reviewer_bindings,
        maximum=MAX_COVERAGE_REVIEWERS,
        label="coverage reviewer bindings",
    )
    bindings = tuple(
        sorted(
            (
                ModelSurfaceReviewerBinding.model_validate(binding.model_dump(mode="python"))
                for binding in raw_bindings
            ),
            key=lambda item: (item.review_role, item.requested_model, item.root_lineage),
        )
    )
    if len({binding.review_role for binding in bindings}) != len(bindings):
        raise ValueError("coverage reviewer bindings must contain one binding per role")

    mandatory_roles = _bounded_tuple(
        mandatory_reviewer_roles,
        maximum=MAX_COVERAGE_REVIEWERS,
        label="mandatory coverage reviewer roles",
    )
    if any(type(role) is not str for role in mandatory_roles):
        raise ValueError("mandatory coverage reviewer roles must be strings")
    mandatory_roles = _require_sorted_unique_strings(
        mandatory_roles,
        pattern=_SAFE_ROLE_PATTERN,
        label="mandatory coverage reviewer roles",
    )
    if not set(mandatory_roles) <= {binding.review_role for binding in bindings}:
        raise ValueError("mandatory coverage role lacks an exact reviewer binding")

    credited_by_surface = _normalize_credited_roots(
        credited_root_lineages_by_surface,
        surface_ids=surface_ids,
    )
    policy = build_model_surface_coverage_policy(minimum_t0_root_lineages)
    requirements = tuple(
        ModelSurfaceCoverageRequirement.build(
            request=request,
            scope_id=scope_by_id[request.surface_id],
            tier_requirement=policy.requirement_for(classify_model_surface_risk(request)),
            credited_root_lineages=credited_by_surface.get(request.surface_id, ()),
        )
        for request in validated_requests
    )
    assignments = _derive_assignments(requirements, bindings, mandatory_roles)
    deficits = _derive_deficits(requirements, assignments)
    tasks = _derive_tasks(requirements, assignments)
    gap_count = sum(
        assignment.purpose is ModelSurfaceAssignmentPurpose.LINEAGE_GAP
        for assignment in assignments
    )
    seed_count = len(assignments) - gap_count
    roles_with_work = {assignment.review_role for assignment in assignments}
    lineage_satisfied = not deficits
    responsibilities_satisfied = set(mandatory_roles) <= roles_with_work
    values = {
        "artifact_kind": "model_surface_coverage_plan",
        "schema_version": "1.0",
        "policy": policy,
        "surface_request_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                validated_requests
            )
        ),
        "requirements": requirements,
        "reviewer_bindings": bindings,
        "mandatory_reviewer_roles": mandatory_roles,
        "assignments": assignments,
        "tasks": tasks,
        "deficits": deficits,
        "surface_count": len(requirements),
        "lineage_gap_assignment_count": gap_count,
        "responsibility_seed_assignment_count": seed_count,
        "task_count": len(tasks),
        "lineage_requirements_satisfied": lineage_satisfied,
        "mandatory_responsibilities_satisfied": responsibilities_satisfied,
        "feasible": lineage_satisfied and responsibilities_satisfied,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
    }
    return ModelSurfaceCoveragePlan.model_validate(
        {**values, "plan_sha256": _canonical_sha256(values)}
    )


def _normalize_credited_roots(
    values: Mapping[str, Iterable[str]] | None,
    *,
    surface_ids: set[str],
) -> dict[str, tuple[str, ...]]:
    if values is None:
        return {}
    items = _bounded_mapping_items(
        values,
        maximum=MAX_COVERAGE_SURFACES,
        label="credited root-lineage mapping",
    )
    if any(surface_id not in surface_ids for surface_id, _ in items):
        raise ValueError("credited root-lineage mapping contains an unknown surface")
    normalized: dict[str, tuple[str, ...]] = {}
    for surface_id, roots in items:
        raw_roots = _bounded_tuple(
            roots,
            maximum=MAX_ROOT_LINEAGES_PER_SURFACE,
            label="credited surface root lineages",
        )
        if any(
            type(root) is not str or re.fullmatch(_ROOT_LINEAGE_PATTERN, root) is None
            for root in raw_roots
        ):
            raise ValueError("credited surface root lineage is invalid")
        normalized[surface_id] = tuple(sorted(set(raw_roots)))
    return normalized


def _derive_assignments(
    requirements: tuple[ModelSurfaceCoverageRequirement, ...],
    bindings: tuple[ModelSurfaceReviewerBinding, ...],
    mandatory_roles: tuple[str, ...],
) -> tuple[ModelSurfaceGapAssignment, ...]:
    load_by_role = {binding.review_role: 0 for binding in bindings}
    load_by_scope_role: dict[tuple[str, str], int] = defaultdict(int)
    assignments: list[ModelSurfaceGapAssignment] = []

    def scope_affinity_key(
        binding: ModelSurfaceReviewerBinding,
        *,
        scope_id: str,
    ) -> tuple[bool, int, int, str, str, str]:
        scope_load = load_by_scope_role[(scope_id, binding.review_role)]
        return (
            scope_load == 0 or scope_load >= MAX_SURFACES_PER_GAP_TASK,
            scope_load,
            load_by_role[binding.review_role],
            binding.review_role,
            binding.requested_model,
            binding.root_lineage,
        )

    for requirement in requirements:
        selected_roots = set(requirement.credited_root_lineages)
        missing = max(0, requirement.minimum_root_lineages - len(selected_roots))
        if missing == 0:
            continue
        request = requirement.request()
        if request.priority is ModelSurfaceReviewPriority.ELEVATED_COVERAGE_GAP:
            hunters = tuple(
                binding
                for binding in bindings
                if binding.review_role in _FALSE_NEGATIVE_HUNTER_ROLES
                and binding.root_lineage not in selected_roots
            )
            hunter = (
                min(
                    hunters,
                    key=lambda item: scope_affinity_key(
                        item,
                        scope_id=requirement.scope_id,
                    ),
                )
                if hunters
                else None
            )
            if hunter is not None:
                assignments.append(
                    ModelSurfaceGapAssignment.build(
                        requirement=requirement,
                        reviewer=hunter,
                        purpose=ModelSurfaceAssignmentPurpose.LINEAGE_GAP,
                    )
                )
                selected_roots.add(hunter.root_lineage)
                load_by_role[hunter.review_role] += 1
                load_by_scope_role[(requirement.scope_id, hunter.review_role)] += 1
                missing -= 1
        while missing > 0:
            candidates = [
                binding for binding in bindings if binding.root_lineage not in selected_roots
            ]
            if not candidates:
                break
            selected = min(
                candidates,
                key=lambda item: scope_affinity_key(
                    item,
                    scope_id=requirement.scope_id,
                ),
            )
            assignments.append(
                ModelSurfaceGapAssignment.build(
                    requirement=requirement,
                    reviewer=selected,
                    purpose=ModelSurfaceAssignmentPurpose.LINEAGE_GAP,
                )
            )
            selected_roots.add(selected.root_lineage)
            load_by_role[selected.review_role] += 1
            load_by_scope_role[(requirement.scope_id, selected.review_role)] += 1
            missing -= 1

    roles_with_work = {assignment.review_role for assignment in assignments}
    binding_by_role = {binding.review_role: binding for binding in bindings}
    surface_load: dict[str, int] = defaultdict(int)
    for assignment in assignments:
        surface_load[assignment.surface_id] += 1
    for role in mandatory_roles:
        if role in roles_with_work:
            continue
        if not requirements:
            raise ValueError("mandatory coverage responsibility lacks a surface inventory")
        requirement = min(
            requirements,
            key=lambda item: (surface_load[item.surface_id], item.scope_id, item.surface_id),
        )
        assignments.append(
            ModelSurfaceGapAssignment.build(
                requirement=requirement,
                reviewer=binding_by_role[role],
                purpose=ModelSurfaceAssignmentPurpose.RESPONSIBILITY_SEED,
            )
        )
        roles_with_work.add(role)
        surface_load[requirement.surface_id] += 1
        load_by_role[role] += 1

    return tuple(
        sorted(
            assignments,
            key=lambda item: (
                item.surface_id,
                item.purpose.value,
                item.review_role,
                item.requested_model,
                item.root_lineage,
            ),
        )
    )


def _derive_deficits(
    requirements: tuple[ModelSurfaceCoverageRequirement, ...],
    assignments: tuple[ModelSurfaceGapAssignment, ...],
) -> tuple[ModelSurfaceCoverageDeficit, ...]:
    roots_by_surface: dict[str, set[str]] = defaultdict(set)
    for assignment in assignments:
        if assignment.purpose is ModelSurfaceAssignmentPurpose.LINEAGE_GAP:
            roots_by_surface[assignment.surface_id].add(assignment.root_lineage)
    deficits: list[ModelSurfaceCoverageDeficit] = []
    for requirement in requirements:
        assigned_roots = tuple(sorted(roots_by_surface[requirement.surface_id]))
        if len(set(requirement.credited_root_lineages) | set(assigned_roots)) < (
            requirement.minimum_root_lineages
        ):
            deficits.append(
                ModelSurfaceCoverageDeficit.build(
                    requirement=requirement,
                    assigned_root_lineages=assigned_roots,
                )
            )
    return tuple(deficits)


def _derive_tasks(
    requirements: tuple[ModelSurfaceCoverageRequirement, ...],
    assignments: tuple[ModelSurfaceGapAssignment, ...],
) -> tuple[ModelSurfaceGapTask, ...]:
    requirement_by_id = {requirement.surface_id: requirement for requirement in requirements}
    groups: dict[
        tuple[str, str, str, str],
        list[ModelSurfaceGapAssignment],
    ] = defaultdict(list)
    for assignment in assignments:
        groups[
            (
                assignment.scope_id,
                assignment.review_role,
                assignment.requested_model,
                assignment.root_lineage,
            )
        ].append(assignment)
    tasks: list[ModelSurfaceGapTask] = []
    for group_key in sorted(groups):
        group = sorted(groups[group_key], key=lambda item: item.surface_id)
        for offset in range(0, len(group), MAX_SURFACES_PER_GAP_TASK):
            chunk = tuple(group[offset : offset + MAX_SURFACES_PER_GAP_TASK])
            requests = tuple(requirement_by_id[item.surface_id].request() for item in chunk)
            tasks.append(ModelSurfaceGapTask.build(assignments=chunk, requests=requests))
    return tuple(
        sorted(
            tasks,
            key=lambda item: (
                item.scope_id,
                item.review_role,
                item.requested_model,
                item.root_lineage,
                item.surface_ids,
            ),
        )
    )


class ModelSurfaceTaskResourcePreview(_FrozenNonAuthorizingModel):
    """Exact worst-case resource bound for one sealed scheduler request task."""

    artifact_kind: Literal["model_surface_task_resource_preview"] = (
        "model_surface_task_resource_preview"
    )
    schema_version: Literal["1.0"] = "1.0"
    coverage_task_id: str = Field(pattern=_COVERAGE_TASK_ID_PATTERN)
    coverage_task_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_task_id: str = Field(pattern=_SCHEDULER_TASK_ID_PATTERN)
    scheduler_task_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    campaign_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    rendered_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_token_plan_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_material_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_material_projection_utf8_bytes: int = Field(gt=0, le=2**63 - 1)
    endpoint_policy_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_policy_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_endpoint: str = Field(pattern=_PROVIDER_ENDPOINT_PATTERN)
    endpoint_pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_cost_bound_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    maximum_attempts: int = Field(ge=1, le=MAX_RESOURCE_ATTEMPTS)
    maximum_prompt_tokens_per_attempt: int = Field(gt=0, le=2**63 - 1)
    maximum_completion_tokens_per_attempt: int = Field(gt=0, le=2**63 - 1)
    maximum_cost_usd_per_attempt_exact: str
    maximum_request_count: int = Field(ge=1, le=MAX_RESOURCE_ATTEMPTS)
    maximum_input_tokens: int = Field(gt=0, le=2**63 - 1)
    maximum_output_tokens: int = Field(gt=0, le=2**63 - 1)
    maximum_cost_usd_exact: str
    preview_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        task: ModelSurfaceGapTask,
        scheduler_task_id: str,
        scheduler_task_plan_sha256: str,
        campaign_manifest_sha256: str,
        rendered_context_sha256: str,
        context_request_evidence_sha256: str,
        request_token_plan_projection_sha256: str,
        request_material_projection_sha256: str,
        request_material_projection_utf8_bytes: int,
        endpoint_policy_snapshot_sha256: str,
        endpoint_policy_pricing_sha256: str,
        provider_endpoint: str,
        endpoint_pricing_snapshot_sha256: str,
        endpoint_cost_bound_projection_sha256: str,
        maximum_attempts: int,
        maximum_prompt_tokens_per_attempt: int,
        maximum_completion_tokens_per_attempt: int,
        maximum_cost_usd_per_attempt_exact: str,
    ) -> ModelSurfaceTaskResourcePreview:
        if any(
            type(value) is not int
            for value in (
                maximum_attempts,
                request_material_projection_utf8_bytes,
                maximum_prompt_tokens_per_attempt,
                maximum_completion_tokens_per_attempt,
            )
        ):
            raise ValueError("resource preview counts must be exact integers")
        cost = _canonical_decimal_text(
            maximum_cost_usd_per_attempt_exact,
            label="maximum per-attempt cost",
        )
        values = {
            "artifact_kind": "model_surface_task_resource_preview",
            "schema_version": "1.0",
            "coverage_task_id": task.task_id,
            "coverage_task_sha256": task.task_sha256,
            "scheduler_task_id": scheduler_task_id,
            "scheduler_task_plan_sha256": scheduler_task_plan_sha256,
            "campaign_manifest_sha256": campaign_manifest_sha256,
            "rendered_context_sha256": rendered_context_sha256,
            "context_request_evidence_sha256": context_request_evidence_sha256,
            "request_token_plan_projection_sha256": request_token_plan_projection_sha256,
            "request_material_projection_sha256": request_material_projection_sha256,
            "request_material_projection_utf8_bytes": (request_material_projection_utf8_bytes),
            "endpoint_policy_snapshot_sha256": endpoint_policy_snapshot_sha256,
            "endpoint_policy_pricing_sha256": endpoint_policy_pricing_sha256,
            "provider_endpoint": provider_endpoint,
            "endpoint_pricing_snapshot_sha256": endpoint_pricing_snapshot_sha256,
            "endpoint_cost_bound_projection_sha256": (endpoint_cost_bound_projection_sha256),
            "maximum_attempts": maximum_attempts,
            "maximum_prompt_tokens_per_attempt": maximum_prompt_tokens_per_attempt,
            "maximum_completion_tokens_per_attempt": maximum_completion_tokens_per_attempt,
            "maximum_cost_usd_per_attempt_exact": cost,
            "maximum_request_count": maximum_attempts,
            "maximum_input_tokens": maximum_prompt_tokens_per_attempt * maximum_attempts,
            "maximum_output_tokens": maximum_completion_tokens_per_attempt * maximum_attempts,
            "maximum_cost_usd_exact": _multiply_decimal_text(cost, maximum_attempts),
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "preview_sha256": _canonical_sha256(values)})

    @field_validator("maximum_cost_usd_per_attempt_exact", "maximum_cost_usd_exact")
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="resource preview cost")

    @model_validator(mode="after")
    def totals_are_exact_and_self_hashed(self) -> Self:
        if (
            self.maximum_request_count != self.maximum_attempts
            or self.maximum_input_tokens
            != self.maximum_prompt_tokens_per_attempt * self.maximum_attempts
            or self.maximum_output_tokens
            != self.maximum_completion_tokens_per_attempt * self.maximum_attempts
            or self.maximum_cost_usd_exact
            != _multiply_decimal_text(
                self.maximum_cost_usd_per_attempt_exact,
                self.maximum_attempts,
            )
        ):
            raise ValueError("resource preview totals differ from its per-attempt maxima")
        _require_self_hash(self, "preview_sha256")
        return self


class ModelPortfolioTaskResourceEnvelope(_FrozenNonAuthorizingModel):
    """Conservative pre-orientation ceiling for every attempt of one scheduled task.

    Unlike :class:`ModelSurfaceTaskResourcePreview`, this evidence intentionally does
    not predict the later rendered context or request hash.  It binds an immutable
    route/pricing/envelope recipe and a ceiling which the exact request must fit.
    """

    artifact_kind: Literal["model_portfolio_task_resource_envelope"] = (
        "model_portfolio_task_resource_envelope"
    )
    schema_version: Literal["1.0"] = "1.0"
    task_kind: ModelPortfolioTaskKind
    scheduler_task_id: str = Field(pattern=_SCHEDULER_TASK_ID_PATTERN)
    scheduler_task_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_logical_request_id: str = Field(pattern=_SCHEDULER_REQUEST_ID_PATTERN)
    campaign_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_role: str = Field(pattern=_SAFE_ROLE_PATTERN)
    requested_model: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    coverage_task_id: str | None = Field(default=None, pattern=_COVERAGE_TASK_ID_PATTERN)
    coverage_task_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    request_envelope_recipe_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_policy_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    endpoint_policy_pricing_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_endpoint: str = Field(pattern=_PROVIDER_ENDPOINT_PATTERN)
    endpoint_pricing_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    maximum_attempts: int = Field(ge=1, le=MAX_RESOURCE_ATTEMPTS)
    attempt_request_ids: tuple[str, ...] = Field(min_length=1, max_length=MAX_RESOURCE_ATTEMPTS)
    maximum_prompt_tokens_per_attempt: int = Field(gt=0, le=2**63 - 1)
    maximum_visible_output_tokens_per_attempt: int = Field(ge=0, le=2**63 - 1)
    maximum_reasoning_tokens_per_attempt: int = Field(ge=0, le=2**63 - 1)
    maximum_completion_tokens_per_attempt: int = Field(gt=0, le=2**63 - 1)
    maximum_cost_usd_per_attempt_exact: str
    maximum_request_count: int = Field(ge=1, le=MAX_RESOURCE_ATTEMPTS)
    maximum_input_tokens: int = Field(gt=0, le=2**63 - 1)
    maximum_output_tokens: int = Field(gt=0, le=2**63 - 1)
    maximum_cost_usd_exact: str
    envelope_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        task_kind: ModelPortfolioTaskKind,
        scheduler_task_id: str,
        scheduler_task_plan_sha256: str,
        scheduler_logical_request_id: str,
        campaign_manifest_sha256: str,
        request_role: str,
        requested_model: str,
        request_envelope_recipe_sha256: str,
        endpoint_policy_snapshot_sha256: str,
        endpoint_policy_pricing_sha256: str,
        provider_endpoint: str,
        endpoint_pricing_snapshot_sha256: str,
        maximum_attempts: int,
        attempt_request_ids: Iterable[str],
        maximum_prompt_tokens_per_attempt: int,
        maximum_visible_output_tokens_per_attempt: int,
        maximum_reasoning_tokens_per_attempt: int,
        maximum_completion_tokens_per_attempt: int,
        maximum_cost_usd_per_attempt_exact: str,
        coverage_task: ModelSurfaceGapTask | None = None,
    ) -> ModelPortfolioTaskResourceEnvelope:
        if not isinstance(task_kind, ModelPortfolioTaskKind):
            raise ValueError("portfolio task kind is invalid")
        if any(
            type(value) is not int
            for value in (
                maximum_attempts,
                maximum_prompt_tokens_per_attempt,
                maximum_visible_output_tokens_per_attempt,
                maximum_reasoning_tokens_per_attempt,
                maximum_completion_tokens_per_attempt,
            )
        ):
            raise ValueError("portfolio resource envelope counts must be exact integers")
        attempts = _bounded_tuple(
            attempt_request_ids,
            maximum=MAX_RESOURCE_ATTEMPTS,
            label="portfolio attempt request IDs",
        )
        if (
            len(attempts) != maximum_attempts
            or len(set(attempts)) != len(attempts)
            or any(
                type(request_id) is not str
                or re.fullmatch(_ATTEMPT_REQUEST_ID_PATTERN, request_id) is None
                for request_id in attempts
            )
        ):
            raise ValueError("portfolio attempt request IDs are incomplete or invalid")
        expected_attempts = (
            scheduler_logical_request_id,
            *(
                f"{scheduler_logical_request_id}:attempt:{ordinal}"
                for ordinal in range(2, maximum_attempts + 1)
            ),
        )
        if attempts != expected_attempts:
            raise ValueError("portfolio attempt request IDs are not the canonical retry sequence")
        compact = task_kind is ModelPortfolioTaskKind.COMPACT_COVERAGE
        if compact is not (coverage_task is not None):
            raise ValueError("only compact portfolio tasks may bind a coverage task")
        if coverage_task is not None and (
            coverage_task.review_role != request_role
            or coverage_task.requested_model != requested_model
        ):
            raise ValueError("compact portfolio task differs from its coverage assignment")
        cost = _canonical_decimal_text(
            maximum_cost_usd_per_attempt_exact,
            label="portfolio maximum per-attempt cost",
        )
        values = {
            "artifact_kind": "model_portfolio_task_resource_envelope",
            "schema_version": "1.0",
            "task_kind": task_kind,
            "scheduler_task_id": scheduler_task_id,
            "scheduler_task_plan_sha256": scheduler_task_plan_sha256,
            "scheduler_logical_request_id": scheduler_logical_request_id,
            "campaign_manifest_sha256": campaign_manifest_sha256,
            "request_role": request_role,
            "requested_model": requested_model,
            "coverage_task_id": coverage_task.task_id if coverage_task is not None else None,
            "coverage_task_sha256": coverage_task.task_sha256
            if coverage_task is not None
            else None,
            "request_envelope_recipe_sha256": request_envelope_recipe_sha256,
            "endpoint_policy_snapshot_sha256": endpoint_policy_snapshot_sha256,
            "endpoint_policy_pricing_sha256": endpoint_policy_pricing_sha256,
            "provider_endpoint": provider_endpoint,
            "endpoint_pricing_snapshot_sha256": endpoint_pricing_snapshot_sha256,
            "maximum_attempts": maximum_attempts,
            "attempt_request_ids": attempts,
            "maximum_prompt_tokens_per_attempt": maximum_prompt_tokens_per_attempt,
            "maximum_visible_output_tokens_per_attempt": (
                maximum_visible_output_tokens_per_attempt
            ),
            "maximum_reasoning_tokens_per_attempt": maximum_reasoning_tokens_per_attempt,
            "maximum_completion_tokens_per_attempt": maximum_completion_tokens_per_attempt,
            "maximum_cost_usd_per_attempt_exact": cost,
            "maximum_request_count": maximum_attempts,
            "maximum_input_tokens": maximum_prompt_tokens_per_attempt * maximum_attempts,
            "maximum_output_tokens": maximum_completion_tokens_per_attempt * maximum_attempts,
            "maximum_cost_usd_exact": _multiply_decimal_text(cost, maximum_attempts),
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "envelope_sha256": _canonical_sha256(values)})

    @field_validator("requested_model")
    @classmethod
    def requested_model_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="portfolio requested model")

    @field_validator("maximum_cost_usd_per_attempt_exact", "maximum_cost_usd_exact")
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="portfolio resource cost")

    @model_validator(mode="after")
    def envelope_is_exact_and_self_hashed(self) -> Self:
        if (
            self.maximum_request_count != self.maximum_attempts
            or len(self.attempt_request_ids) != self.maximum_attempts
            or self.attempt_request_ids
            != (
                self.scheduler_logical_request_id,
                *(
                    f"{self.scheduler_logical_request_id}:attempt:{ordinal}"
                    for ordinal in range(2, self.maximum_attempts + 1)
                ),
            )
            or self.maximum_visible_output_tokens_per_attempt
            + self.maximum_reasoning_tokens_per_attempt
            != self.maximum_completion_tokens_per_attempt
            or self.maximum_input_tokens
            != self.maximum_prompt_tokens_per_attempt * self.maximum_attempts
            or self.maximum_output_tokens
            != self.maximum_completion_tokens_per_attempt * self.maximum_attempts
            or self.maximum_cost_usd_exact
            != _multiply_decimal_text(
                self.maximum_cost_usd_per_attempt_exact,
                self.maximum_attempts,
            )
        ):
            raise ValueError("portfolio resource envelope totals or attempts are inconsistent")
        compact = self.task_kind is ModelPortfolioTaskKind.COMPACT_COVERAGE
        if compact is not (
            self.coverage_task_id is not None and self.coverage_task_sha256 is not None
        ) or ((self.coverage_task_id is None) is not (self.coverage_task_sha256 is None)):
            raise ValueError("portfolio coverage-task custody differs from its task kind")
        _require_self_hash(self, "envelope_sha256")
        return self


class ModelSurfaceResourceScopeCost(_FrozenNonAuthorizingModel):
    """Derived maximum coverage cost for one exact role or model."""

    artifact_kind: Literal["model_surface_resource_scope_cost"] = (
        "model_surface_resource_scope_cost"
    )
    schema_version: Literal["1.0"] = "1.0"
    scope_kind: ModelSurfaceResourceScopeKind
    scope_key: str = Field(min_length=1, max_length=385)
    maximum_cost_usd_exact: str
    cost_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        scope_kind: ModelSurfaceResourceScopeKind,
        scope_key: str,
        maximum_cost_usd_exact: str,
    ) -> ModelSurfaceResourceScopeCost:
        values = {
            "artifact_kind": "model_surface_resource_scope_cost",
            "schema_version": "1.0",
            "scope_kind": scope_kind,
            "scope_key": scope_key,
            "maximum_cost_usd_exact": _canonical_decimal_text(
                maximum_cost_usd_exact,
                label="scoped maximum cost",
            ),
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "cost_sha256": _canonical_sha256(values)})

    @field_validator("scope_key")
    @classmethod
    def scope_key_is_exact(cls, value: str, info: Any) -> str:
        scope_kind = info.data.get("scope_kind")
        if scope_kind is ModelSurfaceResourceScopeKind.ROLE:
            if re.fullmatch(_SAFE_ROLE_PATTERN, value) is None:
                raise ValueError("resource role scope key is invalid")
        elif scope_kind is ModelSurfaceResourceScopeKind.MODEL:
            require_exact_openrouter_model_id(value, label="resource model scope key")
        return value

    @field_validator("maximum_cost_usd_exact")
    @classmethod
    def cost_is_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="scoped maximum cost")

    @model_validator(mode="after")
    def cost_is_self_hashed(self) -> Self:
        _require_self_hash(self, "cost_sha256")
        return self


class ModelSurfaceResourceScopeCap(_FrozenNonAuthorizingModel):
    """One exact remaining per-role or per-model USD cap supplied to preflight."""

    artifact_kind: Literal["model_surface_resource_scope_cap"] = "model_surface_resource_scope_cap"
    schema_version: Literal["1.0"] = "1.0"
    scope_kind: ModelSurfaceResourceScopeKind
    scope_key: str = Field(min_length=1, max_length=385)
    remaining_cost_usd_exact: str
    cap_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        scope_kind: ModelSurfaceResourceScopeKind,
        scope_key: str,
        remaining_cost_usd_exact: str,
    ) -> ModelSurfaceResourceScopeCap:
        values = {
            "artifact_kind": "model_surface_resource_scope_cap",
            "schema_version": "1.0",
            "scope_kind": scope_kind,
            "scope_key": scope_key,
            "remaining_cost_usd_exact": _canonical_decimal_text(
                remaining_cost_usd_exact,
                label="scoped remaining cost cap",
            ),
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "cap_sha256": _canonical_sha256(values)})

    @field_validator("scope_key")
    @classmethod
    def scope_key_is_exact(cls, value: str, info: Any) -> str:
        scope_kind = info.data.get("scope_kind")
        if scope_kind is ModelSurfaceResourceScopeKind.ROLE:
            if re.fullmatch(_SAFE_ROLE_PATTERN, value) is None:
                raise ValueError("resource role cap key is invalid")
        elif scope_kind is ModelSurfaceResourceScopeKind.MODEL:
            require_exact_openrouter_model_id(value, label="resource model cap key")
        return value

    @field_validator("remaining_cost_usd_exact")
    @classmethod
    def cap_is_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="scoped remaining cost cap")

    @model_validator(mode="after")
    def cap_is_self_hashed(self) -> Self:
        _require_self_hash(self, "cap_sha256")
        return self


class ModelSurfaceResourceScopeFailure(_FrozenNonAuthorizingModel):
    """Exact missing/over-cap evidence for one planned role or model."""

    artifact_kind: Literal["model_surface_resource_scope_failure"] = (
        "model_surface_resource_scope_failure"
    )
    schema_version: Literal["1.0"] = "1.0"
    scope_kind: ModelSurfaceResourceScopeKind
    scope_key: str = Field(min_length=1, max_length=385)
    failure_code: ModelSurfaceResourceFailureCode
    planned_maximum_cost_usd_exact: str
    remaining_cost_cap_usd_exact: str | None = None
    failure_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        total: ModelSurfaceResourceScopeCost,
        cap: ModelSurfaceResourceScopeCap | None,
    ) -> ModelSurfaceResourceScopeFailure:
        if cap is not None and (
            cap.scope_kind is not total.scope_kind or cap.scope_key != total.scope_key
        ):
            raise ValueError("scoped resource total and cap identify different scopes")
        if cap is None:
            failure_code = (
                ModelSurfaceResourceFailureCode.ROLE_USD_CAP_MISSING
                if total.scope_kind is ModelSurfaceResourceScopeKind.ROLE
                else ModelSurfaceResourceFailureCode.MODEL_USD_CAP_MISSING
            )
            remaining: str | None = None
        else:
            with localcontext(_decimal_context()):
                if Decimal(total.maximum_cost_usd_exact) <= Decimal(cap.remaining_cost_usd_exact):
                    raise ValueError("within-cap resource scope cannot produce a failure")
            failure_code = (
                ModelSurfaceResourceFailureCode.ROLE_USD_CAP_EXCEEDED
                if total.scope_kind is ModelSurfaceResourceScopeKind.ROLE
                else ModelSurfaceResourceFailureCode.MODEL_USD_CAP_EXCEEDED
            )
            remaining = cap.remaining_cost_usd_exact
        values = {
            "artifact_kind": "model_surface_resource_scope_failure",
            "schema_version": "1.0",
            "scope_kind": total.scope_kind,
            "scope_key": total.scope_key,
            "failure_code": failure_code,
            "planned_maximum_cost_usd_exact": total.maximum_cost_usd_exact,
            "remaining_cost_cap_usd_exact": remaining,
            "authorizes_dispatch": False,
            "grants_review_credit": False,
            "grants_completion_credit": False,
        }
        return cls.model_validate({**values, "failure_sha256": _canonical_sha256(values)})

    @field_validator("scope_key")
    @classmethod
    def scope_key_is_exact(cls, value: str, info: Any) -> str:
        scope_kind = info.data.get("scope_kind")
        if scope_kind is ModelSurfaceResourceScopeKind.ROLE:
            if re.fullmatch(_SAFE_ROLE_PATTERN, value) is None:
                raise ValueError("resource failure role key is invalid")
        elif scope_kind is ModelSurfaceResourceScopeKind.MODEL:
            require_exact_openrouter_model_id(value, label="resource failure model key")
        return value

    @field_validator("planned_maximum_cost_usd_exact")
    @classmethod
    def planned_cost_is_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="scoped planned maximum cost")

    @field_validator("remaining_cost_cap_usd_exact")
    @classmethod
    def remaining_cap_is_canonical(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _canonical_decimal_text(value, label="scoped remaining cost cap")

    @model_validator(mode="after")
    def failure_is_semantically_exact_and_self_hashed(self) -> Self:
        expected_kind = (
            ModelSurfaceResourceScopeKind.ROLE
            if self.failure_code
            in {
                ModelSurfaceResourceFailureCode.ROLE_USD_CAP_MISSING,
                ModelSurfaceResourceFailureCode.ROLE_USD_CAP_EXCEEDED,
            }
            else ModelSurfaceResourceScopeKind.MODEL
        )
        if self.scope_kind is not expected_kind:
            raise ValueError("resource scope failure code differs from its scope kind")
        missing = self.failure_code in {
            ModelSurfaceResourceFailureCode.ROLE_USD_CAP_MISSING,
            ModelSurfaceResourceFailureCode.MODEL_USD_CAP_MISSING,
        }
        if missing != (self.remaining_cost_cap_usd_exact is None):
            raise ValueError("resource scope failure cap presence is inconsistent")
        if self.remaining_cost_cap_usd_exact is not None:
            with localcontext(_decimal_context()):
                if Decimal(self.planned_maximum_cost_usd_exact) <= Decimal(
                    self.remaining_cost_cap_usd_exact
                ):
                    raise ValueError("resource scope failure does not exceed its cap")
        _require_self_hash(self, "failure_sha256")
        return self


class ModelSurfaceResourcePreflight(_FrozenNonAuthorizingModel):
    """Exact aggregate request/token/USD feasibility for one complete coverage plan."""

    artifact_kind: Literal["model_surface_resource_preflight"] = "model_surface_resource_preflight"
    schema_version: Literal["1.0"] = "1.0"
    plan: ModelSurfaceCoveragePlan
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_previews: tuple[ModelSurfaceTaskResourcePreview, ...] = Field(
        max_length=MAX_COVERAGE_TASKS,
    )
    planned_maximum_request_count: int = Field(ge=0, le=2**63 - 1)
    planned_maximum_input_tokens: int = Field(ge=0, le=2**63 - 1)
    planned_maximum_output_tokens: int = Field(ge=0, le=2**63 - 1)
    planned_maximum_cost_usd_exact: str
    planned_costs_by_role: tuple[ModelSurfaceResourceScopeCost, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    planned_costs_by_model: tuple[ModelSurfaceResourceScopeCost, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    maximum_requests: int = Field(ge=0, le=2**63 - 1)
    maximum_input_tokens: int = Field(ge=0, le=2**63 - 1)
    maximum_output_tokens: int = Field(ge=0, le=2**63 - 1)
    maximum_cost_usd_exact: str
    remaining_cost_caps_by_role: tuple[ModelSurfaceResourceScopeCap, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    remaining_cost_caps_by_model: tuple[ModelSurfaceResourceScopeCap, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    scoped_failures: tuple[ModelSurfaceResourceScopeFailure, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS * 2,
    )
    failure_codes: tuple[ModelSurfaceResourceFailureCode, ...] = Field(max_length=9)
    feasible: bool
    preflight_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("planned_maximum_cost_usd_exact", "maximum_cost_usd_exact")
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="resource preflight cost")

    @model_validator(mode="after")
    def portfolio_is_exact_joined_and_self_hashed(self) -> Self:
        if self.plan_sha256 != self.plan.plan_sha256:
            raise ValueError("resource preflight plan hash differs from its embedded plan")
        expected_previews = tuple(
            sorted(self.task_previews, key=lambda item: item.coverage_task_id)
        )
        if self.task_previews != expected_previews:
            raise ValueError("resource previews must be sorted by coverage task ID")
        if len({item.coverage_task_id for item in self.task_previews}) != len(
            self.task_previews
        ) or len({item.scheduler_task_id for item in self.task_previews}) != len(
            self.task_previews
        ):
            raise ValueError("resource previews must uniquely bind coverage and scheduler tasks")
        task_by_id = {task.task_id: task for task in self.plan.tasks}
        if {item.coverage_task_id for item in self.task_previews} != set(task_by_id):
            raise ValueError("resource previews must join every coverage task exactly once")
        if any(
            preview.coverage_task_sha256 != task_by_id[preview.coverage_task_id].task_sha256
            for preview in self.task_previews
        ):
            raise ValueError("resource preview coverage task hash is inconsistent")
        totals = _resource_totals(self.task_previews)
        if (
            self.planned_maximum_request_count,
            self.planned_maximum_input_tokens,
            self.planned_maximum_output_tokens,
            self.planned_maximum_cost_usd_exact,
        ) != totals:
            raise ValueError("resource preflight totals differ from its exact task previews")
        role_costs, model_costs = _resource_scoped_costs(self.plan, self.task_previews)
        if self.planned_costs_by_role != role_costs or self.planned_costs_by_model != model_costs:
            raise ValueError("resource preflight scoped costs differ from its exact tasks")
        _validate_scope_caps(
            self.remaining_cost_caps_by_role,
            scope_kind=ModelSurfaceResourceScopeKind.ROLE,
        )
        _validate_scope_caps(
            self.remaining_cost_caps_by_model,
            scope_kind=ModelSurfaceResourceScopeKind.MODEL,
        )
        expected_scoped_failures = _resource_scope_failures(
            role_costs=role_costs,
            model_costs=model_costs,
            role_caps=self.remaining_cost_caps_by_role,
            model_caps=self.remaining_cost_caps_by_model,
        )
        if self.scoped_failures != expected_scoped_failures:
            raise ValueError("resource preflight scoped failures are inconsistent")
        expected_failures = _resource_failure_codes(
            plan=self.plan,
            totals=totals,
            maximum_requests=self.maximum_requests,
            maximum_input_tokens=self.maximum_input_tokens,
            maximum_output_tokens=self.maximum_output_tokens,
            maximum_cost_usd_exact=self.maximum_cost_usd_exact,
            scoped_failures=expected_scoped_failures,
        )
        if self.failure_codes != expected_failures or self.feasible is not (not expected_failures):
            raise ValueError("resource preflight feasibility differs from its exact limits")
        _require_self_hash(self, "preflight_sha256")
        return self


def build_model_surface_resource_preflight(
    plan: ModelSurfaceCoveragePlan,
    task_previews: Iterable[ModelSurfaceTaskResourcePreview],
    *,
    maximum_requests: int,
    maximum_input_tokens: int,
    maximum_output_tokens: int,
    maximum_cost_usd_exact: str,
    remaining_cost_usd_by_role: Mapping[str, str] | None = None,
    remaining_cost_usd_by_model: Mapping[str, str] | None = None,
) -> ModelSurfaceResourcePreflight:
    """Join every task preview once and compare exact aggregate maxima to all caps."""

    validated_plan = ModelSurfaceCoveragePlan.model_validate(plan.model_dump(mode="python"))
    if any(
        type(value) is not int
        for value in (maximum_requests, maximum_input_tokens, maximum_output_tokens)
    ):
        raise ValueError("resource preflight limits must be exact integers")
    cost_cap = _canonical_decimal_text(maximum_cost_usd_exact, label="maximum coverage cost")
    raw_previews = _bounded_tuple(
        task_previews,
        maximum=MAX_COVERAGE_TASKS,
        label="coverage task resource previews",
    )
    previews = tuple(
        sorted(
            (
                ModelSurfaceTaskResourcePreview.model_validate(preview.model_dump(mode="python"))
                for preview in raw_previews
            ),
            key=lambda item: item.coverage_task_id,
        )
    )
    if len({preview.coverage_task_id for preview in previews}) != len(previews):
        raise ValueError("resource previews contain a duplicate coverage task")
    if len({preview.scheduler_task_id for preview in previews}) != len(previews):
        raise ValueError("resource previews contain a duplicate scheduler task")
    task_by_id = {task.task_id: task for task in validated_plan.tasks}
    if {preview.coverage_task_id for preview in previews} != set(task_by_id):
        raise ValueError("resource previews must join every coverage task exactly once")
    if any(
        preview.coverage_task_sha256 != task_by_id[preview.coverage_task_id].task_sha256
        for preview in previews
    ):
        raise ValueError("resource preview coverage task hash is inconsistent")
    totals = _resource_totals(previews)
    role_costs, model_costs = _resource_scoped_costs(validated_plan, previews)
    role_caps = _normalize_scope_caps(
        remaining_cost_usd_by_role,
        scope_kind=ModelSurfaceResourceScopeKind.ROLE,
    )
    model_caps = _normalize_scope_caps(
        remaining_cost_usd_by_model,
        scope_kind=ModelSurfaceResourceScopeKind.MODEL,
    )
    scoped_failures = _resource_scope_failures(
        role_costs=role_costs,
        model_costs=model_costs,
        role_caps=role_caps,
        model_caps=model_caps,
    )
    failures = _resource_failure_codes(
        plan=validated_plan,
        totals=totals,
        maximum_requests=maximum_requests,
        maximum_input_tokens=maximum_input_tokens,
        maximum_output_tokens=maximum_output_tokens,
        maximum_cost_usd_exact=cost_cap,
        scoped_failures=scoped_failures,
    )
    values = {
        "artifact_kind": "model_surface_resource_preflight",
        "schema_version": "1.0",
        "plan": validated_plan,
        "plan_sha256": validated_plan.plan_sha256,
        "task_previews": previews,
        "planned_maximum_request_count": totals[0],
        "planned_maximum_input_tokens": totals[1],
        "planned_maximum_output_tokens": totals[2],
        "planned_maximum_cost_usd_exact": totals[3],
        "planned_costs_by_role": role_costs,
        "planned_costs_by_model": model_costs,
        "maximum_requests": maximum_requests,
        "maximum_input_tokens": maximum_input_tokens,
        "maximum_output_tokens": maximum_output_tokens,
        "maximum_cost_usd_exact": cost_cap,
        "remaining_cost_caps_by_role": role_caps,
        "remaining_cost_caps_by_model": model_caps,
        "scoped_failures": scoped_failures,
        "failure_codes": failures,
        "feasible": not failures,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
    }
    return ModelSurfaceResourcePreflight.model_validate(
        {**values, "preflight_sha256": _canonical_sha256(values)}
    )


class ModelPortfolioResourcePreflight(_FrozenNonAuthorizingModel):
    """Complete conservative spend reservation intent frozen before orientation."""

    artifact_kind: Literal["model_portfolio_resource_preflight"] = (
        "model_portfolio_resource_preflight"
    )
    schema_version: Literal["1.0"] = "1.0"
    coverage_plan: ModelSurfaceCoveragePlan
    coverage_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    campaign_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_envelopes: tuple[ModelPortfolioTaskResourceEnvelope, ...] = Field(
        min_length=1,
        max_length=MAX_COVERAGE_TASKS,
    )
    candidate_independent_request_roles: tuple[str, ...] = Field(max_length=24)
    planned_maximum_request_count: int = Field(ge=1, le=2**63 - 1)
    planned_maximum_input_tokens: int = Field(gt=0, le=2**63 - 1)
    planned_maximum_output_tokens: int = Field(gt=0, le=2**63 - 1)
    planned_maximum_cost_usd_exact: str
    planned_costs_by_role: tuple[ModelSurfaceResourceScopeCost, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    planned_costs_by_model: tuple[ModelSurfaceResourceScopeCost, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    maximum_requests_per_task: int = Field(ge=1, le=MAX_RESOURCE_ATTEMPTS)
    maximum_input_tokens: int = Field(ge=0, le=2**63 - 1)
    maximum_output_tokens: int = Field(ge=0, le=2**63 - 1)
    maximum_cost_usd_exact: str
    remaining_cost_caps_by_role: tuple[ModelSurfaceResourceScopeCap, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    remaining_cost_caps_by_model: tuple[ModelSurfaceResourceScopeCap, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS,
    )
    scoped_failures: tuple[ModelSurfaceResourceScopeFailure, ...] = Field(
        max_length=MAX_COVERAGE_REVIEWERS * 2,
    )
    failure_codes: tuple[ModelSurfaceResourceFailureCode, ...] = Field(max_length=9)
    feasible: bool
    preflight_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("planned_maximum_cost_usd_exact", "maximum_cost_usd_exact")
    @classmethod
    def costs_are_canonical(cls, value: str) -> str:
        return _canonical_decimal_text(value, label="portfolio preflight cost")

    @model_validator(mode="after")
    def portfolio_is_exact_joined_and_self_hashed(self) -> Self:
        if self.coverage_plan_sha256 != self.coverage_plan.plan_sha256:
            raise ValueError("portfolio preflight coverage-plan hash is inconsistent")
        expected_envelopes = tuple(
            sorted(self.task_envelopes, key=lambda item: item.scheduler_task_id)
        )
        if self.task_envelopes != expected_envelopes:
            raise ValueError("portfolio task envelopes must be sorted by scheduler task ID")
        if len({item.scheduler_task_id for item in self.task_envelopes}) != len(
            self.task_envelopes
        ) or len({item.scheduler_logical_request_id for item in self.task_envelopes}) != len(
            self.task_envelopes
        ):
            raise ValueError("portfolio task envelopes repeat scheduler custody")
        attempt_ids = tuple(
            request_id
            for envelope in self.task_envelopes
            for request_id in envelope.attempt_request_ids
        )
        if len(attempt_ids) != len(set(attempt_ids)):
            raise ValueError("portfolio task envelopes repeat a provider attempt identity")
        if any(
            item.campaign_manifest_sha256 != self.campaign_manifest_sha256
            for item in self.task_envelopes
        ):
            raise ValueError("portfolio task envelope differs from the campaign manifest")
        compact_by_id = {
            item.coverage_task_id: item
            for item in self.task_envelopes
            if item.task_kind is ModelPortfolioTaskKind.COMPACT_COVERAGE
            and item.coverage_task_id is not None
        }
        plan_by_id = {task.task_id: task for task in self.coverage_plan.tasks}
        if set(compact_by_id) != set(plan_by_id) or any(
            compact_by_id[task_id].coverage_task_sha256 != task.task_sha256
            or compact_by_id[task_id].request_role != task.review_role
            or compact_by_id[task_id].requested_model != task.requested_model
            for task_id, task in plan_by_id.items()
        ):
            raise ValueError("portfolio compact tasks do not exactly cover the coverage plan")
        expected_roles = _portfolio_candidate_independent_roles(self.task_envelopes)
        if self.candidate_independent_request_roles != expected_roles:
            raise ValueError("portfolio candidate-independent role inventory is inconsistent")
        totals = _portfolio_resource_totals(self.task_envelopes)
        if (
            self.planned_maximum_request_count,
            self.planned_maximum_input_tokens,
            self.planned_maximum_output_tokens,
            self.planned_maximum_cost_usd_exact,
        ) != totals:
            raise ValueError("portfolio preflight totals differ from its task envelopes")
        role_costs, model_costs = _portfolio_resource_scoped_costs(self.task_envelopes)
        if self.planned_costs_by_role != role_costs or self.planned_costs_by_model != model_costs:
            raise ValueError("portfolio scoped costs differ from its task envelopes")
        _validate_scope_caps(
            self.remaining_cost_caps_by_role,
            scope_kind=ModelSurfaceResourceScopeKind.ROLE,
        )
        _validate_scope_caps(
            self.remaining_cost_caps_by_model,
            scope_kind=ModelSurfaceResourceScopeKind.MODEL,
        )
        expected_scoped_failures = _resource_scope_failures(
            role_costs=role_costs,
            model_costs=model_costs,
            role_caps=self.remaining_cost_caps_by_role,
            model_caps=self.remaining_cost_caps_by_model,
        )
        if self.scoped_failures != expected_scoped_failures:
            raise ValueError("portfolio scoped resource failures are inconsistent")
        expected_failures = _portfolio_resource_failure_codes(
            coverage_plan=self.coverage_plan,
            envelopes=self.task_envelopes,
            totals=totals,
            maximum_requests_per_task=self.maximum_requests_per_task,
            maximum_input_tokens=self.maximum_input_tokens,
            maximum_output_tokens=self.maximum_output_tokens,
            maximum_cost_usd_exact=self.maximum_cost_usd_exact,
            scoped_failures=expected_scoped_failures,
        )
        if self.failure_codes != expected_failures or self.feasible is not (not expected_failures):
            raise ValueError("portfolio preflight feasibility differs from its exact limits")
        _require_self_hash(self, "preflight_sha256")
        return self


def build_model_portfolio_resource_preflight(
    coverage_plan: ModelSurfaceCoveragePlan,
    task_envelopes: Iterable[ModelPortfolioTaskResourceEnvelope],
    *,
    campaign_manifest_sha256: str,
    maximum_requests_per_task: int,
    maximum_input_tokens: int,
    maximum_output_tokens: int,
    maximum_cost_usd_exact: str,
    remaining_cost_usd_by_role: Mapping[str, str] | None = None,
    remaining_cost_usd_by_model: Mapping[str, str] | None = None,
) -> ModelPortfolioResourcePreflight:
    """Build one exact, nonauthorizing all-task reservation intent."""

    validated_plan = ModelSurfaceCoveragePlan.model_validate(
        coverage_plan.model_dump(mode="python")
    )
    if any(
        type(value) is not int
        for value in (
            maximum_requests_per_task,
            maximum_input_tokens,
            maximum_output_tokens,
        )
    ):
        raise ValueError("portfolio preflight limits must be exact integers")
    envelopes = tuple(
        sorted(
            (
                ModelPortfolioTaskResourceEnvelope.model_validate(
                    envelope.model_dump(mode="python")
                )
                for envelope in _bounded_tuple(
                    task_envelopes,
                    maximum=MAX_COVERAGE_TASKS,
                    label="portfolio task envelopes",
                )
            ),
            key=lambda item: item.scheduler_task_id,
        )
    )
    if not envelopes:
        raise ValueError("portfolio preflight requires at least one task envelope")
    if any(item.campaign_manifest_sha256 != campaign_manifest_sha256 for item in envelopes):
        raise ValueError("portfolio task envelope differs from the campaign manifest")
    totals = _portfolio_resource_totals(envelopes)
    role_costs, model_costs = _portfolio_resource_scoped_costs(envelopes)
    role_caps = _normalize_scope_caps(
        remaining_cost_usd_by_role,
        scope_kind=ModelSurfaceResourceScopeKind.ROLE,
    )
    model_caps = _normalize_scope_caps(
        remaining_cost_usd_by_model,
        scope_kind=ModelSurfaceResourceScopeKind.MODEL,
    )
    scoped_failures = _resource_scope_failures(
        role_costs=role_costs,
        model_costs=model_costs,
        role_caps=role_caps,
        model_caps=model_caps,
    )
    cost_cap = _canonical_decimal_text(
        maximum_cost_usd_exact,
        label="portfolio maximum cost",
    )
    failures = _portfolio_resource_failure_codes(
        coverage_plan=validated_plan,
        envelopes=envelopes,
        totals=totals,
        maximum_requests_per_task=maximum_requests_per_task,
        maximum_input_tokens=maximum_input_tokens,
        maximum_output_tokens=maximum_output_tokens,
        maximum_cost_usd_exact=cost_cap,
        scoped_failures=scoped_failures,
    )
    values = {
        "artifact_kind": "model_portfolio_resource_preflight",
        "schema_version": "1.0",
        "coverage_plan": validated_plan,
        "coverage_plan_sha256": validated_plan.plan_sha256,
        "campaign_manifest_sha256": campaign_manifest_sha256,
        "task_envelopes": envelopes,
        "candidate_independent_request_roles": (_portfolio_candidate_independent_roles(envelopes)),
        "planned_maximum_request_count": totals[0],
        "planned_maximum_input_tokens": totals[1],
        "planned_maximum_output_tokens": totals[2],
        "planned_maximum_cost_usd_exact": totals[3],
        "planned_costs_by_role": role_costs,
        "planned_costs_by_model": model_costs,
        "maximum_requests_per_task": maximum_requests_per_task,
        "maximum_input_tokens": maximum_input_tokens,
        "maximum_output_tokens": maximum_output_tokens,
        "maximum_cost_usd_exact": cost_cap,
        "remaining_cost_caps_by_role": role_caps,
        "remaining_cost_caps_by_model": model_caps,
        "scoped_failures": scoped_failures,
        "failure_codes": failures,
        "feasible": not failures,
        "authorizes_dispatch": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
    }
    return ModelPortfolioResourcePreflight.model_validate(
        {**values, "preflight_sha256": _canonical_sha256(values)}
    )


def _resource_totals(
    previews: tuple[ModelSurfaceTaskResourcePreview, ...],
) -> tuple[int, int, int, str]:
    return (
        sum(preview.maximum_request_count for preview in previews),
        sum(preview.maximum_input_tokens for preview in previews),
        sum(preview.maximum_output_tokens for preview in previews),
        _sum_decimal_text(preview.maximum_cost_usd_exact for preview in previews),
    )


def _portfolio_candidate_independent_roles(
    envelopes: tuple[ModelPortfolioTaskResourceEnvelope, ...],
) -> tuple[str, ...]:
    """Return the canonical candidate-independent specialist roles actually held."""

    planned_roles = {envelope.request_role for envelope in envelopes}
    return tuple(
        request_role
        for role in CANDIDATE_INDEPENDENT_SPECIALIST_ROLES
        if (request_role := f"specialist:{role}") in planned_roles
    )


def _portfolio_resource_totals(
    envelopes: tuple[ModelPortfolioTaskResourceEnvelope, ...],
) -> tuple[int, int, int, str]:
    return (
        sum(envelope.maximum_request_count for envelope in envelopes),
        sum(envelope.maximum_input_tokens for envelope in envelopes),
        sum(envelope.maximum_output_tokens for envelope in envelopes),
        _sum_decimal_text(envelope.maximum_cost_usd_exact for envelope in envelopes),
    )


def _portfolio_resource_scoped_costs(
    envelopes: tuple[ModelPortfolioTaskResourceEnvelope, ...],
) -> tuple[
    tuple[ModelSurfaceResourceScopeCost, ...],
    tuple[ModelSurfaceResourceScopeCost, ...],
]:
    role_cost_parts: dict[str, list[str]] = defaultdict(list)
    model_cost_parts: dict[str, list[str]] = defaultdict(list)
    for envelope in envelopes:
        role_cost_parts[envelope.request_role].append(envelope.maximum_cost_usd_exact)
        model_cost_parts[envelope.requested_model].append(envelope.maximum_cost_usd_exact)
    role_costs = tuple(
        ModelSurfaceResourceScopeCost.build(
            scope_kind=ModelSurfaceResourceScopeKind.ROLE,
            scope_key=role,
            maximum_cost_usd_exact=_sum_decimal_text(role_cost_parts[role]),
        )
        for role in sorted(role_cost_parts)
    )
    model_costs = tuple(
        ModelSurfaceResourceScopeCost.build(
            scope_kind=ModelSurfaceResourceScopeKind.MODEL,
            scope_key=model,
            maximum_cost_usd_exact=_sum_decimal_text(model_cost_parts[model]),
        )
        for model in sorted(model_cost_parts)
    )
    return role_costs, model_costs


def _portfolio_resource_failure_codes(
    *,
    coverage_plan: ModelSurfaceCoveragePlan,
    envelopes: tuple[ModelPortfolioTaskResourceEnvelope, ...],
    totals: tuple[int, int, int, str],
    maximum_requests_per_task: int,
    maximum_input_tokens: int,
    maximum_output_tokens: int,
    maximum_cost_usd_exact: str,
    scoped_failures: tuple[ModelSurfaceResourceScopeFailure, ...],
) -> tuple[ModelSurfaceResourceFailureCode, ...]:
    _, input_tokens, output_tokens, cost_usd_exact = totals
    failures: list[ModelSurfaceResourceFailureCode] = []
    if not coverage_plan.feasible:
        failures.append(ModelSurfaceResourceFailureCode.COVERAGE_PLAN_INFEASIBLE)
    if any(envelope.maximum_attempts > maximum_requests_per_task for envelope in envelopes):
        failures.append(ModelSurfaceResourceFailureCode.REQUEST_CAP_EXCEEDED)
    if input_tokens > maximum_input_tokens:
        failures.append(ModelSurfaceResourceFailureCode.INPUT_TOKEN_CAP_EXCEEDED)
    if output_tokens > maximum_output_tokens:
        failures.append(ModelSurfaceResourceFailureCode.OUTPUT_TOKEN_CAP_EXCEEDED)
    with localcontext(_decimal_context()):
        if Decimal(cost_usd_exact) > Decimal(maximum_cost_usd_exact):
            failures.append(ModelSurfaceResourceFailureCode.USD_CAP_EXCEEDED)
    scoped_codes = {failure.failure_code for failure in scoped_failures}
    failures.extend(code for code in ModelSurfaceResourceFailureCode if code in scoped_codes)
    return tuple(failures)


def _resource_scoped_costs(
    plan: ModelSurfaceCoveragePlan,
    previews: tuple[ModelSurfaceTaskResourcePreview, ...],
) -> tuple[
    tuple[ModelSurfaceResourceScopeCost, ...],
    tuple[ModelSurfaceResourceScopeCost, ...],
]:
    task_by_id = {task.task_id: task for task in plan.tasks}
    role_cost_parts: dict[str, list[str]] = defaultdict(list)
    model_cost_parts: dict[str, list[str]] = defaultdict(list)
    for preview in previews:
        task = task_by_id[preview.coverage_task_id]
        role_cost_parts[task.review_role].append(preview.maximum_cost_usd_exact)
        model_cost_parts[task.requested_model].append(preview.maximum_cost_usd_exact)
    role_costs = tuple(
        ModelSurfaceResourceScopeCost.build(
            scope_kind=ModelSurfaceResourceScopeKind.ROLE,
            scope_key=role,
            maximum_cost_usd_exact=_sum_decimal_text(role_cost_parts[role]),
        )
        for role in sorted(role_cost_parts)
    )
    model_costs = tuple(
        ModelSurfaceResourceScopeCost.build(
            scope_kind=ModelSurfaceResourceScopeKind.MODEL,
            scope_key=model,
            maximum_cost_usd_exact=_sum_decimal_text(model_cost_parts[model]),
        )
        for model in sorted(model_cost_parts)
    )
    return role_costs, model_costs


def _normalize_scope_caps(
    values: Mapping[str, str] | None,
    *,
    scope_kind: ModelSurfaceResourceScopeKind,
) -> tuple[ModelSurfaceResourceScopeCap, ...]:
    if values is None:
        return ()
    label = f"remaining {scope_kind.value} USD cap mapping"
    items = _bounded_mapping_items(
        values,
        maximum=MAX_COVERAGE_REVIEWERS,
        label=label,
    )
    caps = tuple(
        sorted(
            (
                ModelSurfaceResourceScopeCap.build(
                    scope_kind=scope_kind,
                    scope_key=scope_key,
                    remaining_cost_usd_exact=remaining,
                )
                for scope_key, remaining in items
            ),
            key=lambda item: item.scope_key,
        )
    )
    _validate_scope_caps(caps, scope_kind=scope_kind)
    return caps


def _validate_scope_caps(
    caps: tuple[ModelSurfaceResourceScopeCap, ...],
    *,
    scope_kind: ModelSurfaceResourceScopeKind,
) -> None:
    if caps != tuple(sorted(caps, key=lambda item: item.scope_key)) or len(
        {cap.scope_key for cap in caps}
    ) != len(caps):
        raise ValueError(f"remaining {scope_kind.value} USD caps must be unique and sorted")
    if any(cap.scope_kind is not scope_kind for cap in caps):
        raise ValueError(f"remaining {scope_kind.value} USD cap has the wrong scope kind")


def _resource_scope_failures(
    *,
    role_costs: tuple[ModelSurfaceResourceScopeCost, ...],
    model_costs: tuple[ModelSurfaceResourceScopeCost, ...],
    role_caps: tuple[ModelSurfaceResourceScopeCap, ...],
    model_caps: tuple[ModelSurfaceResourceScopeCap, ...],
) -> tuple[ModelSurfaceResourceScopeFailure, ...]:
    failures: list[ModelSurfaceResourceScopeFailure] = []
    for totals, caps in ((role_costs, role_caps), (model_costs, model_caps)):
        if not caps:
            continue
        cap_by_key = {cap.scope_key: cap for cap in caps}
        for total in totals:
            cap = cap_by_key.get(total.scope_key)
            if cap is None:
                failures.append(ModelSurfaceResourceScopeFailure.build(total=total, cap=None))
                continue
            with localcontext(_decimal_context()):
                exceeds = Decimal(total.maximum_cost_usd_exact) > Decimal(
                    cap.remaining_cost_usd_exact
                )
            if exceeds:
                failures.append(ModelSurfaceResourceScopeFailure.build(total=total, cap=cap))
    return tuple(
        sorted(
            failures,
            key=lambda item: (item.scope_kind.value, item.scope_key, item.failure_code.value),
        )
    )


def _resource_failure_codes(
    *,
    plan: ModelSurfaceCoveragePlan,
    totals: tuple[int, int, int, str],
    maximum_requests: int,
    maximum_input_tokens: int,
    maximum_output_tokens: int,
    maximum_cost_usd_exact: str,
    scoped_failures: tuple[ModelSurfaceResourceScopeFailure, ...],
) -> tuple[ModelSurfaceResourceFailureCode, ...]:
    request_count, input_tokens, output_tokens, cost_usd_exact = totals
    failures: list[ModelSurfaceResourceFailureCode] = []
    if not plan.feasible:
        failures.append(ModelSurfaceResourceFailureCode.COVERAGE_PLAN_INFEASIBLE)
    if request_count > maximum_requests:
        failures.append(ModelSurfaceResourceFailureCode.REQUEST_CAP_EXCEEDED)
    if input_tokens > maximum_input_tokens:
        failures.append(ModelSurfaceResourceFailureCode.INPUT_TOKEN_CAP_EXCEEDED)
    if output_tokens > maximum_output_tokens:
        failures.append(ModelSurfaceResourceFailureCode.OUTPUT_TOKEN_CAP_EXCEEDED)
    with localcontext(_decimal_context()):
        if Decimal(cost_usd_exact) > Decimal(maximum_cost_usd_exact):
            failures.append(ModelSurfaceResourceFailureCode.USD_CAP_EXCEEDED)
    scoped_codes = {failure.failure_code for failure in scoped_failures}
    failures.extend(code for code in ModelSurfaceResourceFailureCode if code in scoped_codes)
    return tuple(failures)


__all__ = [
    "MAX_COVERAGE_ASSIGNMENTS",
    "MAX_COVERAGE_REVIEWERS",
    "MAX_COVERAGE_SURFACES",
    "MAX_COVERAGE_TASKS",
    "MAX_RESOURCE_ATTEMPTS",
    "MAX_ROOT_LINEAGES_PER_SURFACE",
    "MAX_SURFACES_PER_GAP_TASK",
    "ModelPortfolioResourcePreflight",
    "ModelPortfolioTaskKind",
    "ModelPortfolioTaskResourceEnvelope",
    "ModelSurfaceAssignmentPurpose",
    "ModelSurfaceCoverageDeficit",
    "ModelSurfaceCoveragePlan",
    "ModelSurfaceCoveragePolicy",
    "ModelSurfaceCoverageRequirement",
    "ModelSurfaceGapAssignment",
    "ModelSurfaceGapTask",
    "ModelSurfaceResourceFailureCode",
    "ModelSurfaceResourcePreflight",
    "ModelSurfaceResourceScopeCap",
    "ModelSurfaceResourceScopeCost",
    "ModelSurfaceResourceScopeFailure",
    "ModelSurfaceResourceScopeKind",
    "ModelSurfaceReviewerBinding",
    "ModelSurfaceRiskTier",
    "ModelSurfaceTaskResourcePreview",
    "ModelSurfaceTierRequirement",
    "build_model_portfolio_resource_preflight",
    "build_model_surface_coverage_plan",
    "build_model_surface_coverage_policy",
    "build_model_surface_resource_preflight",
    "classify_model_surface_risk",
]
