"""Pure, endpoint-bound token planning for model requests.

The models in this module retain only hashes, counts, endpoint facts, and bounded
allocations. Raw prompts and source text are accepted only by the local estimator
factory and are never stored in evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from decimal import ROUND_FLOOR, Decimal
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_ENDPOINT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_RE = re.compile(_SHA256_PATTERN)
_MAX_TOKENS = 2**31 - 1

MINIMUM_CONTEXT_UTILIZATION = Decimal("0.65")
MAXIMUM_CONTEXT_UTILIZATION = Decimal("0.75")
DEFAULT_CONTEXT_UTILIZATION = Decimal("0.70")
UTF8_TOKEN_ESTIMATOR: Literal["MMAUDIT_UTF8_BYTES_DIV3_V1"] = "MMAUDIT_UTF8_BYTES_DIV3_V1"
PROMPT_UPPER_BOUND_METHOD: Literal["MMAUDIT_UTF8_BYTES_PLUS_FRAMING_V1"] = (
    "MMAUDIT_UTF8_BYTES_PLUS_FRAMING_V1"
)

TokenLimitSource = Literal["metadata", "context_limit"]


class TokenPlanningError(ValueError):
    """Raised when endpoint evidence cannot support a requested token plan."""


class EndpointTokenCapacityError(TokenPlanningError):
    """Raised when a request cannot fit its frozen endpoint token capacities."""


class ContextTokenPlanError(TokenPlanningError):
    """Raised when provider-visible context or configured reserves are inconsistent."""


class GlobalTokenBudgetPlanningError(TokenPlanningError):
    """Raised when one request cannot fit the configured aggregate token ceiling."""


class PromptAllocationCategory(StrEnum):
    """Complete prompt allocation inventory retained by every request plan."""

    FRAMEWORK = "framework"
    GRAPH = "graph"
    INVARIANT = "invariant"
    METADATA = "metadata"
    PRIOR_AUDIT = "prior_audit"
    PROTOCOL = "protocol"
    SCANNER = "scanner"
    SCHEMA = "schema"
    SOURCE = "source"
    SYSTEM = "system"
    WORKFLOW = "workflow"


class ContextOmissionCategory(StrEnum):
    """Typed omitted-content category without raw source or path material."""

    CONTEXT_PACKAGE = "context_package"
    FRAMEWORK = PromptAllocationCategory.FRAMEWORK.value
    GRAPH = PromptAllocationCategory.GRAPH.value
    INVARIANT = PromptAllocationCategory.INVARIANT.value
    METADATA = PromptAllocationCategory.METADATA.value
    PRIOR_AUDIT = PromptAllocationCategory.PRIOR_AUDIT.value
    PROTOCOL = PromptAllocationCategory.PROTOCOL.value
    SCANNER = PromptAllocationCategory.SCANNER.value
    SCHEMA = PromptAllocationCategory.SCHEMA.value
    SOURCE = PromptAllocationCategory.SOURCE.value
    SYSTEM = PromptAllocationCategory.SYSTEM.value
    WORKFLOW = PromptAllocationCategory.WORKFLOW.value


class ContextOmissionReason(StrEnum):
    """Host-defined reason one category or item was not included."""

    BLIND_DISCOVERY_WITHHELD = "BLIND_DISCOVERY_WITHHELD"
    CONTEXT_BUDGET_EXCLUDED = "CONTEXT_BUDGET_EXCLUDED"
    LOGICAL_BLOCK_EXCEEDS_LIMIT = "LOGICAL_BLOCK_EXCEEDS_LIMIT"
    METADATA_BUDGET_EXCLUDED = "METADATA_BUDGET_EXCLUDED"
    REVIEW_CONTRACT_WITHHELD = "REVIEW_CONTRACT_WITHHELD"
    SERIALIZED_BUDGET_EXCLUDED = "SERIALIZED_BUDGET_EXCLUDED"
    SOURCE_BUDGET_EXCLUDED = "SOURCE_BUDGET_EXCLUDED"


class OutputAllocationCategory(StrEnum):
    """Visible-output partitions required for a substantive review response."""

    COVERAGE = "coverage"
    FINDINGS = "findings"
    SUMMARY = "summary"


PROMPT_ALLOCATION_CATEGORIES = tuple(
    sorted(PromptAllocationCategory, key=lambda category: category.value)
)
OUTPUT_ALLOCATION_CATEGORIES = tuple(
    sorted(OutputAllocationCategory, key=lambda category: category.value)
)
MINIMUM_COVERAGE_TOKENS_PER_SURFACE = 64
MINIMUM_FINDING_OUTPUT_TOKENS = 256
MINIMUM_SUMMARY_OUTPUT_TOKENS = 128


class FrozenTokenEvidence(BaseModel):
    """Strict immutable base for public token-planning evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ContextOmissionItem(FrozenTokenEvidence):
    """One category- and reason-bound omitted item represented only by hashes."""

    schema_version: Literal["1.0"] = "1.0"
    category: ContextOmissionCategory
    reason: ContextOmissionReason
    omitted_item_sha256: str = Field(pattern=_SHA256_PATTERN)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        category: ContextOmissionCategory,
        reason: ContextOmissionReason,
        omitted_item_sha256: str,
    ) -> Self:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "category": category,
            "reason": reason,
            "omitted_item_sha256": omitted_item_sha256,
        }
        return cls(
            schema_version="1.0",
            category=category,
            reason=reason,
            omitted_item_sha256=omitted_item_sha256,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def omission_is_typed_and_self_hashed(self) -> ContextOmissionItem:
        permitted_categories = {
            ContextOmissionReason.BLIND_DISCOVERY_WITHHELD: {ContextOmissionCategory.PRIOR_AUDIT},
            ContextOmissionReason.CONTEXT_BUDGET_EXCLUDED: {
                ContextOmissionCategory.CONTEXT_PACKAGE
            },
            ContextOmissionReason.LOGICAL_BLOCK_EXCEEDS_LIMIT: {ContextOmissionCategory.SOURCE},
            ContextOmissionReason.METADATA_BUDGET_EXCLUDED: {
                ContextOmissionCategory.FRAMEWORK,
                ContextOmissionCategory.GRAPH,
                ContextOmissionCategory.INVARIANT,
                ContextOmissionCategory.METADATA,
                ContextOmissionCategory.SCANNER,
            },
            ContextOmissionReason.REVIEW_CONTRACT_WITHHELD: {ContextOmissionCategory.METADATA},
            ContextOmissionReason.SERIALIZED_BUDGET_EXCLUDED: {ContextOmissionCategory.SOURCE},
            ContextOmissionReason.SOURCE_BUDGET_EXCLUDED: {ContextOmissionCategory.SOURCE},
        }
        if self.category not in permitted_categories[self.reason]:
            raise ValueError("context omission category differs from its reason")
        _require_self_hash(self, "evidence_sha256")
        return self


class Utf8TokenEstimate(FrozenTokenEvidence):
    """Deterministic local estimate with a separate conservative byte upper bound."""

    schema_version: Literal["1.0"] = "1.0"
    estimator: Literal["MMAUDIT_UTF8_BYTES_DIV3_V1"] = UTF8_TOKEN_ESTIMATOR
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    utf8_bytes: int = Field(ge=0, le=_MAX_TOKENS)
    estimated_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    byte_upper_bound_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_text(cls, text: str) -> Self:
        """Estimate text locally while retaining no raw content."""

        if not isinstance(text, str):
            raise TypeError("token estimation requires text")
        encoded = text.encode("utf-8")
        return cls.from_measurement(
            content_sha256=hashlib.sha256(encoded).hexdigest(),
            utf8_bytes=len(encoded),
        )

    @classmethod
    def from_measurement(cls, *, content_sha256: str, utf8_bytes: int) -> Self:
        """Build from a locally measured hash/count pair without retaining content."""

        if not isinstance(content_sha256, str) or _SHA256_RE.fullmatch(content_sha256) is None:
            raise TokenPlanningError("token measurement content hash is invalid")
        if (
            isinstance(utf8_bytes, bool)
            or not isinstance(utf8_bytes, int)
            or not 0 <= utf8_bytes <= _MAX_TOKENS
        ):
            raise TokenPlanningError("UTF-8 input exceeds the supported evidence range")
        byte_count = utf8_bytes
        estimated_tokens = (byte_count + 2) // 3
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "estimator": UTF8_TOKEN_ESTIMATOR,
            "content_sha256": content_sha256,
            "utf8_bytes": byte_count,
            "estimated_tokens": estimated_tokens,
            "byte_upper_bound_tokens": byte_count,
        }
        return cls(
            schema_version="1.0",
            estimator=UTF8_TOKEN_ESTIMATOR,
            content_sha256=content_sha256,
            utf8_bytes=byte_count,
            estimated_tokens=estimated_tokens,
            byte_upper_bound_tokens=byte_count,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def estimate_is_deterministic_and_self_bound(self) -> Utf8TokenEstimate:
        if self.estimated_tokens != (self.utf8_bytes + 2) // 3:
            raise ValueError("estimated tokens do not match the UTF-8 byte/3 estimator")
        if self.byte_upper_bound_tokens != self.utf8_bytes:
            raise ValueError("token byte upper bound does not match the UTF-8 byte count")
        _require_self_hash(self, "evidence_sha256")
        return self


class PromptTokenAllocation(FrozenTokenEvidence):
    """One explicit prompt category without raw text."""

    schema_version: Literal["1.0"] = "1.0"
    category: PromptAllocationCategory
    estimate: Utf8TokenEstimate
    allocation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def from_text(cls, category: PromptAllocationCategory, text: str) -> Self:
        return cls.from_estimate(category, Utf8TokenEstimate.from_text(text))

    @classmethod
    def from_measurement(
        cls,
        category: PromptAllocationCategory,
        *,
        content_sha256: str,
        utf8_bytes: int,
    ) -> Self:
        """Build from a locally measured category projection."""

        return cls.from_estimate(
            category,
            Utf8TokenEstimate.from_measurement(
                content_sha256=content_sha256,
                utf8_bytes=utf8_bytes,
            ),
        )

    @classmethod
    def from_estimate(
        cls,
        category: PromptAllocationCategory,
        estimate: Utf8TokenEstimate,
    ) -> Self:
        """Bind one validated local estimate to its prompt category."""

        if not isinstance(estimate, Utf8TokenEstimate):
            raise TypeError("prompt allocation requires validated token evidence")
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "category": category,
            "estimate": estimate,
        }
        return cls(
            schema_version="1.0",
            category=category,
            estimate=estimate,
            allocation_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def allocation_is_self_bound(self) -> PromptTokenAllocation:
        _require_self_hash(self, "allocation_sha256")
        return self


class OutputTokenAllocation(FrozenTokenEvidence):
    """One self-hashed visible-output reservation without response content."""

    schema_version: Literal["1.0"] = "1.0"
    category: OutputAllocationCategory
    reserved_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    minimum_reserved_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    requested_surface_count: int = Field(ge=0, le=10_000)
    minimum_tokens_per_surface: int = Field(ge=0, le=_MAX_TOKENS)
    allocation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        category: OutputAllocationCategory,
        reserved_tokens: int,
        minimum_reserved_tokens: int,
        requested_surface_count: int = 0,
        minimum_tokens_per_surface: int = 0,
    ) -> Self:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "category": category,
            "reserved_tokens": reserved_tokens,
            "minimum_reserved_tokens": minimum_reserved_tokens,
            "requested_surface_count": requested_surface_count,
            "minimum_tokens_per_surface": minimum_tokens_per_surface,
        }
        return cls(
            schema_version="1.0",
            category=category,
            reserved_tokens=reserved_tokens,
            minimum_reserved_tokens=minimum_reserved_tokens,
            requested_surface_count=requested_surface_count,
            minimum_tokens_per_surface=minimum_tokens_per_surface,
            allocation_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def allocation_is_feasible_and_self_bound(self) -> OutputTokenAllocation:
        if self.reserved_tokens < self.minimum_reserved_tokens:
            raise ValueError("output reservation is below its typed minimum")
        if self.category is OutputAllocationCategory.COVERAGE:
            if self.requested_surface_count and not self.minimum_tokens_per_surface:
                raise ValueError("surface coverage output requires a per-surface minimum")
            if (
                self.reserved_tokens
                < self.requested_surface_count * self.minimum_tokens_per_surface
            ):
                raise ValueError("surface coverage output reservation is infeasible")
            expected_minimum = max(
                1,
                self.requested_surface_count * self.minimum_tokens_per_surface,
            )
            if self.minimum_reserved_tokens != expected_minimum:
                raise ValueError("surface coverage typed minimum is inconsistent")
        elif self.requested_surface_count or self.minimum_tokens_per_surface:
            raise ValueError("only coverage output may carry surface feasibility evidence")
        elif (
            self.category is OutputAllocationCategory.FINDINGS
            and self.minimum_reserved_tokens < MINIMUM_FINDING_OUTPUT_TOKENS
        ):
            raise ValueError("finding output minimum is below the defensive floor")
        elif (
            self.category is OutputAllocationCategory.SUMMARY
            and self.minimum_reserved_tokens < MINIMUM_SUMMARY_OUTPUT_TOKENS
        ):
            raise ValueError("summary output minimum is below the defensive floor")
        _require_self_hash(self, "allocation_sha256")
        return self


class EndpointRouteTokenCapacity(FrozenTokenEvidence):
    """Frozen token capacities for one exact model and provider endpoint route."""

    schema_version: Literal["1.0"] = "1.0"
    exact_model_id: str = Field(pattern=_MODEL_ID_PATTERN)
    provider_endpoint: str = Field(pattern=_ENDPOINT_ID_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    max_prompt_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    max_prompt_tokens_source: TokenLimitSource
    max_completion_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    max_completion_tokens_source: TokenLimitSource
    route_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        exact_model_id: str,
        provider_endpoint: str,
        endpoint_snapshot_sha256: str,
        context_tokens: int,
        max_prompt_tokens: int,
        max_prompt_tokens_source: TokenLimitSource,
        max_completion_tokens: int,
        max_completion_tokens_source: TokenLimitSource,
    ) -> Self:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "exact_model_id": exact_model_id,
            "provider_endpoint": provider_endpoint,
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "context_tokens": context_tokens,
            "max_prompt_tokens": max_prompt_tokens,
            "max_prompt_tokens_source": max_prompt_tokens_source,
            "max_completion_tokens": max_completion_tokens,
            "max_completion_tokens_source": max_completion_tokens_source,
        }
        return cls(
            schema_version="1.0",
            exact_model_id=exact_model_id,
            provider_endpoint=provider_endpoint,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            context_tokens=context_tokens,
            max_prompt_tokens=max_prompt_tokens,
            max_prompt_tokens_source=max_prompt_tokens_source,
            max_completion_tokens=max_completion_tokens,
            max_completion_tokens_source=max_completion_tokens_source,
            route_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def route_capacity_is_safe_and_self_bound(self) -> EndpointRouteTokenCapacity:
        if self.max_prompt_tokens > self.context_tokens:
            raise ValueError("endpoint prompt limit exceeds its context capacity")
        if self.max_completion_tokens > self.context_tokens:
            raise ValueError("endpoint completion limit exceeds its context capacity")
        if (
            self.max_prompt_tokens_source == "context_limit"
            and self.max_prompt_tokens != self.context_tokens
        ):
            raise ValueError("context-derived prompt limit differs from context capacity")
        if (
            self.max_completion_tokens_source == "context_limit"
            and self.max_completion_tokens != self.context_tokens
        ):
            raise ValueError("context-derived completion limit differs from context capacity")
        _require_self_hash(self, "route_sha256")
        return self


class EndpointRouteIntersection(FrozenTokenEvidence):
    """Conservative capacity intersection across every possible request route."""

    schema_version: Literal["1.0"] = "1.0"
    routes: tuple[EndpointRouteTokenCapacity, ...] = Field(min_length=1, max_length=256)
    exact_model_ids: tuple[str, ...] = Field(min_length=1, max_length=256)
    provider_endpoints: tuple[str, ...] = Field(min_length=1, max_length=256)
    context_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    max_prompt_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    max_completion_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    intersection_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, routes: Sequence[EndpointRouteTokenCapacity]) -> Self:
        if not routes:
            raise TokenPlanningError("endpoint route intersection requires at least one route")
        if any(not isinstance(route, EndpointRouteTokenCapacity) for route in routes):
            raise TypeError("endpoint route intersection received invalid route evidence")
        ordered = tuple(sorted(routes, key=_route_sort_key))
        route_keys = tuple(_route_identity(route) for route in ordered)
        if len(route_keys) != len(set(route_keys)):
            raise TokenPlanningError("endpoint route intersection contains duplicate routes")
        exact_model_ids = tuple(
            sorted({route.exact_model_id for route in ordered}, key=str.casefold)
        )
        if len(exact_model_ids) != 1:
            raise TokenPlanningError(
                "one request route intersection must bind exactly one model ID"
            )
        provider_endpoints = tuple(
            sorted({route.provider_endpoint for route in ordered}, key=str.casefold)
        )
        context_tokens = min(route.context_tokens for route in ordered)
        max_prompt_tokens = min(route.max_prompt_tokens for route in ordered)
        max_completion_tokens = min(route.max_completion_tokens for route in ordered)
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "routes": ordered,
            "exact_model_ids": exact_model_ids,
            "provider_endpoints": provider_endpoints,
            "context_tokens": context_tokens,
            "max_prompt_tokens": max_prompt_tokens,
            "max_completion_tokens": max_completion_tokens,
        }
        return cls(
            schema_version="1.0",
            routes=ordered,
            exact_model_ids=exact_model_ids,
            provider_endpoints=provider_endpoints,
            context_tokens=context_tokens,
            max_prompt_tokens=max_prompt_tokens,
            max_completion_tokens=max_completion_tokens,
            intersection_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def intersection_is_conservative_and_self_bound(self) -> EndpointRouteIntersection:
        if self.routes != tuple(sorted(self.routes, key=_route_sort_key)):
            raise ValueError("endpoint routes must be canonically sorted")
        route_keys = tuple(_route_identity(route) for route in self.routes)
        if len(route_keys) != len(set(route_keys)):
            raise ValueError("endpoint routes must be unique")
        expected_models = tuple(
            sorted({route.exact_model_id for route in self.routes}, key=str.casefold)
        )
        if len(expected_models) != 1:
            raise ValueError("one request route intersection must bind exactly one model ID")
        expected_endpoints = tuple(
            sorted({route.provider_endpoint for route in self.routes}, key=str.casefold)
        )
        if self.exact_model_ids != expected_models:
            raise ValueError("intersection model IDs are not derived from its routes")
        if self.provider_endpoints != expected_endpoints:
            raise ValueError("intersection endpoints are not derived from its routes")
        if self.context_tokens != min(route.context_tokens for route in self.routes):
            raise ValueError("intersection context capacity is not conservative")
        if self.max_prompt_tokens != min(route.max_prompt_tokens for route in self.routes):
            raise ValueError("intersection prompt capacity is not conservative")
        if self.max_completion_tokens != min(route.max_completion_tokens for route in self.routes):
            raise ValueError("intersection completion capacity is not conservative")
        _require_self_hash(self, "intersection_sha256")
        return self


class SourceTokenBudgetEvidence(FrozenTokenEvidence):
    """Conservation proof for the maximum source allocation in one request."""

    schema_version: Literal["1.0"] = "1.0"
    usable_prompt_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    non_source_prompt_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    reserved_non_source_prompt_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    configured_maximum_source_tokens_per_request: int = Field(gt=0, le=_MAX_TOKENS)
    maximum_source_tokens_per_request: int = Field(ge=0, le=_MAX_TOKENS)
    maximum_source_byte_upper_bound_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    planned_source_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    planned_source_byte_upper_bound_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    remaining_source_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    remaining_source_byte_upper_bound_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    unallocated_prompt_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        usable_prompt_tokens: int,
        non_source_prompt_tokens: int,
        reserved_non_source_prompt_tokens: int,
        configured_maximum_source_tokens_per_request: int,
        planned_source_tokens: int,
        planned_source_byte_upper_bound_tokens: int,
    ) -> Self:
        if reserved_non_source_prompt_tokens < non_source_prompt_tokens:
            raise ContextTokenPlanError(
                "reserved non-source capacity is below actual non-source allocations"
            )
        available_source = usable_prompt_tokens - reserved_non_source_prompt_tokens
        if available_source < 0:
            raise ContextTokenPlanError("non-source reserves exceed usable prompt capacity")
        if (
            isinstance(configured_maximum_source_tokens_per_request, bool)
            or configured_maximum_source_tokens_per_request <= 0
        ):
            raise ContextTokenPlanError("configured maximum source tokens must be positive")
        configured_source_byte_upper = min(
            _MAX_TOKENS,
            configured_maximum_source_tokens_per_request * 3,
        )
        maximum_source_byte_upper = min(available_source, configured_source_byte_upper)
        maximum_source = min(
            configured_maximum_source_tokens_per_request,
            (maximum_source_byte_upper + 2) // 3,
        )
        if (
            planned_source_tokens > maximum_source
            or planned_source_byte_upper_bound_tokens > maximum_source_byte_upper
        ):
            raise ContextTokenPlanError("source allocation exceeds its per-request maximum")
        remaining_source = maximum_source - planned_source_tokens
        remaining_source_byte_upper = (
            maximum_source_byte_upper - planned_source_byte_upper_bound_tokens
        )
        unallocated_prompt = available_source - maximum_source_byte_upper
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "usable_prompt_tokens": usable_prompt_tokens,
            "non_source_prompt_tokens": non_source_prompt_tokens,
            "reserved_non_source_prompt_tokens": reserved_non_source_prompt_tokens,
            "configured_maximum_source_tokens_per_request": (
                configured_maximum_source_tokens_per_request
            ),
            "maximum_source_tokens_per_request": maximum_source,
            "maximum_source_byte_upper_bound_tokens": maximum_source_byte_upper,
            "planned_source_tokens": planned_source_tokens,
            "planned_source_byte_upper_bound_tokens": planned_source_byte_upper_bound_tokens,
            "remaining_source_tokens": remaining_source,
            "remaining_source_byte_upper_bound_tokens": remaining_source_byte_upper,
            "unallocated_prompt_tokens": unallocated_prompt,
        }
        return cls(
            schema_version="1.0",
            usable_prompt_tokens=usable_prompt_tokens,
            non_source_prompt_tokens=non_source_prompt_tokens,
            reserved_non_source_prompt_tokens=reserved_non_source_prompt_tokens,
            configured_maximum_source_tokens_per_request=(
                configured_maximum_source_tokens_per_request
            ),
            maximum_source_tokens_per_request=maximum_source,
            maximum_source_byte_upper_bound_tokens=maximum_source_byte_upper,
            planned_source_tokens=planned_source_tokens,
            planned_source_byte_upper_bound_tokens=planned_source_byte_upper_bound_tokens,
            remaining_source_tokens=remaining_source,
            remaining_source_byte_upper_bound_tokens=remaining_source_byte_upper,
            unallocated_prompt_tokens=unallocated_prompt,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def source_budget_conserves_tokens(self) -> SourceTokenBudgetEvidence:
        if (
            self.reserved_non_source_prompt_tokens
            + self.maximum_source_byte_upper_bound_tokens
            + self.unallocated_prompt_tokens
            != self.usable_prompt_tokens
        ):
            raise ValueError("maximum source budget does not conserve usable prompt tokens")
        if self.reserved_non_source_prompt_tokens < self.non_source_prompt_tokens:
            raise ValueError("non-source reserve is below actual non-source allocations")
        if (
            self.maximum_source_tokens_per_request
            > self.configured_maximum_source_tokens_per_request
        ):
            raise ValueError("effective source budget exceeds its configured maximum")
        if (
            self.planned_source_tokens + self.remaining_source_tokens
            != self.maximum_source_tokens_per_request
        ):
            raise ValueError("planned source budget does not conserve its maximum")
        if (
            self.planned_source_byte_upper_bound_tokens
            + self.remaining_source_byte_upper_bound_tokens
            != self.maximum_source_byte_upper_bound_tokens
        ):
            raise ValueError("planned source byte upper bound does not conserve its maximum")
        _require_self_hash(self, "evidence_sha256")
        return self


class GlobalTokenBudgetEvidence(FrozenTokenEvidence):
    """Immutable input/output reservation proof against global token limits."""

    schema_version: Literal["1.0"] = "1.0"
    global_input_token_budget: int = Field(gt=0, le=_MAX_TOKENS)
    global_output_token_budget: int = Field(gt=0, le=_MAX_TOKENS)
    input_tokens_reserved_before: int = Field(ge=0, le=_MAX_TOKENS)
    output_tokens_reserved_before: int = Field(ge=0, le=_MAX_TOKENS)
    request_input_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    request_output_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    input_tokens_reserved_after: int = Field(ge=0, le=_MAX_TOKENS)
    output_tokens_reserved_after: int = Field(gt=0, le=_MAX_TOKENS)
    input_tokens_remaining_after: int = Field(ge=0, le=_MAX_TOKENS)
    output_tokens_remaining_after: int = Field(ge=0, le=_MAX_TOKENS)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        global_input_token_budget: int,
        global_output_token_budget: int,
        input_tokens_reserved_before: int,
        output_tokens_reserved_before: int,
        request_input_tokens: int,
        request_output_tokens: int,
    ) -> Self:
        input_after = input_tokens_reserved_before + request_input_tokens
        output_after = output_tokens_reserved_before + request_output_tokens
        if input_after > global_input_token_budget:
            raise GlobalTokenBudgetPlanningError("request exceeds the global input token budget")
        if output_after > global_output_token_budget:
            raise GlobalTokenBudgetPlanningError("request exceeds the global output token budget")
        input_remaining = global_input_token_budget - input_after
        output_remaining = global_output_token_budget - output_after
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "global_input_token_budget": global_input_token_budget,
            "global_output_token_budget": global_output_token_budget,
            "input_tokens_reserved_before": input_tokens_reserved_before,
            "output_tokens_reserved_before": output_tokens_reserved_before,
            "request_input_tokens": request_input_tokens,
            "request_output_tokens": request_output_tokens,
            "input_tokens_reserved_after": input_after,
            "output_tokens_reserved_after": output_after,
            "input_tokens_remaining_after": input_remaining,
            "output_tokens_remaining_after": output_remaining,
        }
        return cls(
            schema_version="1.0",
            global_input_token_budget=global_input_token_budget,
            global_output_token_budget=global_output_token_budget,
            input_tokens_reserved_before=input_tokens_reserved_before,
            output_tokens_reserved_before=output_tokens_reserved_before,
            request_input_tokens=request_input_tokens,
            request_output_tokens=request_output_tokens,
            input_tokens_reserved_after=input_after,
            output_tokens_reserved_after=output_after,
            input_tokens_remaining_after=input_remaining,
            output_tokens_remaining_after=output_remaining,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def global_budget_conserves_tokens(self) -> GlobalTokenBudgetEvidence:
        if (
            self.input_tokens_reserved_before + self.request_input_tokens
            != self.input_tokens_reserved_after
        ):
            raise ValueError("global input token reservation does not conserve tokens")
        if (
            self.output_tokens_reserved_before + self.request_output_tokens
            != self.output_tokens_reserved_after
        ):
            raise ValueError("global output token reservation does not conserve tokens")
        if (
            self.input_tokens_reserved_after + self.input_tokens_remaining_after
            != self.global_input_token_budget
        ):
            raise ValueError("global input token remainder is inconsistent")
        if (
            self.output_tokens_reserved_after + self.output_tokens_remaining_after
            != self.global_output_token_budget
        ):
            raise ValueError("global output token remainder is inconsistent")
        _require_self_hash(self, "evidence_sha256")
        return self


class RequestTokenPlan(FrozenTokenEvidence):
    """Self-hashed endpoint-bound input, reasoning, and output request plan."""

    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    role: str = Field(pattern=_ROLE_PATTERN)
    route_intersection: EndpointRouteIntersection
    context_utilization: Decimal = Field(
        ge=MINIMUM_CONTEXT_UTILIZATION,
        le=MAXIMUM_CONTEXT_UTILIZATION,
    )
    allocations: tuple[PromptTokenAllocation, ...] = Field(
        min_length=len(PROMPT_ALLOCATION_CATEGORIES),
        max_length=len(PROMPT_ALLOCATION_CATEGORIES),
    )
    requested_surface_count: int = Field(ge=0, le=10_000)
    output_allocations: tuple[OutputTokenAllocation, ...] = Field(
        min_length=len(OUTPUT_ALLOCATION_CATEGORIES),
        max_length=len(OUTPUT_ALLOCATION_CATEGORIES),
    )
    required_output_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    reserved_output_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    reserved_reasoning_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    requested_completion_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    hard_prompt_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    usable_prompt_tokens: int = Field(gt=0, le=_MAX_TOKENS)
    estimated_prompt_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    prompt_upper_bound_method: Literal["MMAUDIT_UTF8_BYTES_PLUS_FRAMING_V1"] = (
        PROMPT_UPPER_BOUND_METHOD
    )
    prompt_content_byte_upper_bound_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    prompt_framing_reserve_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    prompt_byte_upper_bound_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    reserved_system_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    reserved_schema_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    reserved_protocol_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    reserved_workflow_tokens: int = Field(ge=0, le=_MAX_TOKENS)
    context_omissions: tuple[ContextOmissionItem, ...] = Field(
        default=(),
        max_length=4_096,
    )
    context_omission_sha256s: tuple[str, ...] = Field(default=(), max_length=4_096)
    source_budget: SourceTokenBudgetEvidence
    global_budget: GlobalTokenBudgetEvidence
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def plan_is_endpoint_bound_conservative_and_self_hashed(self) -> RequestTokenPlan:
        if any(
            route.max_completion_tokens_source != "metadata"
            for route in self.route_intersection.routes
        ):
            raise ValueError("request token plan requires an explicit metadata completion limit")
        categories = tuple(allocation.category for allocation in self.allocations)
        if categories != PROMPT_ALLOCATION_CATEGORIES:
            raise ValueError("prompt allocation categories must be complete, unique, and sorted")
        output_categories = tuple(allocation.category for allocation in self.output_allocations)
        if output_categories != OUTPUT_ALLOCATION_CATEGORIES:
            raise ValueError("output allocation categories must be complete, unique, and sorted")
        if (
            sum(allocation.reserved_tokens for allocation in self.output_allocations)
            != self.required_output_tokens
        ):
            raise ValueError("output allocations do not conserve required output tokens")
        coverage_output = next(
            allocation
            for allocation in self.output_allocations
            if allocation.category is OutputAllocationCategory.COVERAGE
        )
        if coverage_output.requested_surface_count != self.requested_surface_count:
            raise ValueError("surface output allocation differs from the request plan")
        if self.required_output_tokens != self.reserved_output_tokens:
            raise ValueError("required output tokens may not be clamped")
        expected_completion = self.reserved_output_tokens + self.reserved_reasoning_tokens
        if self.requested_completion_tokens != expected_completion:
            raise ValueError("completion reserve does not conserve output and reasoning tokens")
        limits = self.route_intersection
        if self.reserved_output_tokens > limits.max_completion_tokens:
            raise ValueError("required output exceeds the endpoint completion limit")
        if self.requested_completion_tokens > limits.max_completion_tokens:
            raise ValueError("output and reasoning reserves exceed the endpoint completion limit")
        remaining_context = limits.context_tokens - self.requested_completion_tokens
        expected_hard_prompt = min(limits.max_prompt_tokens, remaining_context)
        if expected_hard_prompt <= 0 or self.hard_prompt_tokens != expected_hard_prompt:
            raise ValueError("hard prompt capacity is inconsistent with endpoint limits")
        expected_usable = _utilized_tokens(expected_hard_prompt, self.context_utilization)
        if self.usable_prompt_tokens != expected_usable:
            raise ValueError("usable prompt capacity is inconsistent with utilization")
        expected_prompt = sum(
            allocation.estimate.estimated_tokens for allocation in self.allocations
        )
        expected_content_byte_upper = sum(
            allocation.estimate.byte_upper_bound_tokens for allocation in self.allocations
        )
        if self.estimated_prompt_tokens != expected_prompt:
            raise ValueError("prompt allocation estimate does not conserve tokens")
        if self.prompt_content_byte_upper_bound_tokens != expected_content_byte_upper:
            raise ValueError("prompt content byte upper bound does not conserve allocations")
        if (
            self.prompt_content_byte_upper_bound_tokens + self.prompt_framing_reserve_tokens
            != self.prompt_byte_upper_bound_tokens
        ):
            raise ValueError("prompt upper bound does not conserve content and framing")
        if self.prompt_byte_upper_bound_tokens > self.usable_prompt_tokens:
            raise ValueError("conservative prompt bound exceeds the usable endpoint capacity")
        if self.prompt_byte_upper_bound_tokens > limits.max_prompt_tokens:
            raise ValueError("conservative prompt bound exceeds the endpoint prompt limit")
        if (
            self.prompt_byte_upper_bound_tokens + self.requested_completion_tokens
            > limits.context_tokens
        ):
            raise ValueError("conservative prompt and completion bounds exceed endpoint context")
        allocation_map = {allocation.category: allocation for allocation in self.allocations}
        system_tokens = allocation_map[
            PromptAllocationCategory.SYSTEM
        ].estimate.byte_upper_bound_tokens
        schema_tokens = allocation_map[
            PromptAllocationCategory.SCHEMA
        ].estimate.byte_upper_bound_tokens
        protocol_tokens = allocation_map[
            PromptAllocationCategory.PROTOCOL
        ].estimate.byte_upper_bound_tokens
        workflow_tokens = allocation_map[
            PromptAllocationCategory.WORKFLOW
        ].estimate.byte_upper_bound_tokens
        if self.reserved_system_tokens < system_tokens:
            raise ValueError("system token reserve is below its allocation")
        if self.reserved_schema_tokens < schema_tokens:
            raise ValueError("schema token reserve is below its allocation")
        if self.reserved_protocol_tokens < protocol_tokens:
            raise ValueError("protocol token reserve is below its allocation")
        if self.reserved_workflow_tokens < workflow_tokens:
            raise ValueError("workflow token reserve is below its allocation")
        non_source_tokens = (
            sum(
                allocation.estimate.byte_upper_bound_tokens
                for allocation in self.allocations
                if allocation.category is not PromptAllocationCategory.SOURCE
            )
            + self.prompt_framing_reserve_tokens
        )
        reserved_non_source_tokens = (
            non_source_tokens
            - system_tokens
            - schema_tokens
            - protocol_tokens
            - workflow_tokens
            + self.reserved_system_tokens
            + self.reserved_schema_tokens
            + self.reserved_protocol_tokens
            + self.reserved_workflow_tokens
        )
        source_estimate = allocation_map[PromptAllocationCategory.SOURCE].estimate
        if (
            self.source_budget.usable_prompt_tokens != self.usable_prompt_tokens
            or self.source_budget.non_source_prompt_tokens != non_source_tokens
            or self.source_budget.reserved_non_source_prompt_tokens != reserved_non_source_tokens
            or self.source_budget.planned_source_tokens != source_estimate.estimated_tokens
            or self.source_budget.planned_source_byte_upper_bound_tokens
            != source_estimate.byte_upper_bound_tokens
        ):
            raise ValueError("source token budget differs from prompt allocations")
        canonical_omissions = tuple(
            sorted(
                self.context_omissions,
                key=lambda item: (
                    item.category.value,
                    item.reason.value,
                    item.omitted_item_sha256,
                ),
            )
        )
        if self.context_omissions != canonical_omissions:
            raise ValueError("context omissions must be canonically sorted")
        omission_hashes = tuple(sorted(item.omitted_item_sha256 for item in self.context_omissions))
        if (
            len(omission_hashes) != len(set(omission_hashes))
            or self.context_omission_sha256s != omission_hashes
        ):
            raise ValueError("context omission inventory differs from its hash index")
        if self.context_omission_sha256s != tuple(sorted(self.context_omission_sha256s)):
            raise ValueError("context omission hashes must be canonically sorted")
        if len(self.context_omission_sha256s) != len(set(self.context_omission_sha256s)) or any(
            _SHA256_RE.fullmatch(item) is None for item in self.context_omission_sha256s
        ):
            raise ValueError("context omission hashes must be unique SHA-256 values")
        if (
            self.global_budget.request_input_tokens != self.prompt_byte_upper_bound_tokens
            or self.global_budget.request_output_tokens != self.requested_completion_tokens
        ):
            raise ValueError("global token budget differs from the request plan")
        _require_self_hash(self, "plan_sha256")
        return self


def build_request_token_plan(
    *,
    request_id: str,
    role: str,
    route_intersection: EndpointRouteIntersection,
    allocations: Sequence[PromptTokenAllocation],
    requested_surface_count: int = 0,
    required_output_tokens: int,
    reserved_reasoning_tokens: int,
    global_input_token_budget: int,
    global_output_token_budget: int,
    input_tokens_reserved_before: int = 0,
    output_tokens_reserved_before: int = 0,
    context_utilization: Decimal = DEFAULT_CONTEXT_UTILIZATION,
    configured_reserved_system_tokens: int = 0,
    configured_reserved_schema_tokens: int = 0,
    configured_reserved_protocol_tokens: int = 0,
    configured_reserved_workflow_tokens: int = 0,
    maximum_source_tokens_per_request: int = 200_000,
    context_omissions: Sequence[ContextOmissionItem] = (),
    prompt_envelope_byte_upper_bound_tokens: int,
) -> RequestTokenPlan:
    """Build one fail-closed request plan without peer-role allocation coupling."""

    if not isinstance(route_intersection, EndpointRouteIntersection):
        raise TypeError("request token plan requires a route intersection")
    if not isinstance(context_utilization, Decimal):
        raise ContextTokenPlanError("context utilization must be an exact Decimal")
    if not MINIMUM_CONTEXT_UTILIZATION <= context_utilization <= MAXIMUM_CONTEXT_UTILIZATION:
        raise ContextTokenPlanError("context utilization must be between 0.65 and 0.75")
    if isinstance(required_output_tokens, bool) or required_output_tokens <= 0:
        raise ContextTokenPlanError("required output token reserve must be positive")
    if (
        isinstance(requested_surface_count, bool)
        or not isinstance(requested_surface_count, int)
        or not 0 <= requested_surface_count <= 10_000
    ):
        raise ContextTokenPlanError("requested surface count is invalid")
    if isinstance(reserved_reasoning_tokens, bool) or reserved_reasoning_tokens < 0:
        raise ContextTokenPlanError("reasoning token reserve cannot be negative")
    if any(route.max_completion_tokens_source != "metadata" for route in route_intersection.routes):
        raise EndpointTokenCapacityError(
            "endpoint completion capacity requires an explicit metadata limit"
        )
    if required_output_tokens > route_intersection.max_completion_tokens:
        raise EndpointTokenCapacityError("required output exceeds the endpoint completion limit")
    requested_completion_tokens = required_output_tokens + reserved_reasoning_tokens
    if requested_completion_tokens > route_intersection.max_completion_tokens:
        raise EndpointTokenCapacityError(
            "required output and reasoning exceed the endpoint completion limit"
        )
    if requested_completion_tokens >= route_intersection.context_tokens:
        raise EndpointTokenCapacityError("completion reserves leave no endpoint prompt capacity")

    canonical_allocations = _canonical_allocations(allocations)
    output_allocations = build_output_token_allocations(
        required_output_tokens=required_output_tokens,
        requested_surface_count=requested_surface_count,
    )
    estimated_prompt_tokens = sum(
        allocation.estimate.estimated_tokens for allocation in canonical_allocations
    )
    content_byte_upper_bound = sum(
        allocation.estimate.byte_upper_bound_tokens for allocation in canonical_allocations
    )
    if (
        isinstance(prompt_envelope_byte_upper_bound_tokens, bool)
        or not isinstance(prompt_envelope_byte_upper_bound_tokens, int)
        or prompt_envelope_byte_upper_bound_tokens < content_byte_upper_bound
    ):
        raise ContextTokenPlanError(
            "prompt envelope bound must cover every provider-visible content byte"
        )
    byte_upper_bound = prompt_envelope_byte_upper_bound_tokens
    framing_reserve_tokens = byte_upper_bound - content_byte_upper_bound
    hard_prompt_tokens = min(
        route_intersection.max_prompt_tokens,
        route_intersection.context_tokens - requested_completion_tokens,
    )
    usable_prompt_tokens = _utilized_tokens(hard_prompt_tokens, context_utilization)
    if usable_prompt_tokens <= 0:
        raise EndpointTokenCapacityError("endpoint utilization leaves no usable prompt capacity")
    if byte_upper_bound > usable_prompt_tokens:
        raise EndpointTokenCapacityError(
            "conservative prompt bound exceeds the usable endpoint capacity"
        )
    if byte_upper_bound > route_intersection.max_prompt_tokens:
        raise EndpointTokenCapacityError(
            "conservative prompt bound exceeds the endpoint prompt limit"
        )
    if byte_upper_bound + requested_completion_tokens > route_intersection.context_tokens:
        raise EndpointTokenCapacityError(
            "conservative prompt and completion bounds exceed endpoint context"
        )

    allocation_map = {allocation.category: allocation for allocation in canonical_allocations}
    source_estimate = allocation_map[PromptAllocationCategory.SOURCE].estimate
    non_source_tokens = (
        content_byte_upper_bound - source_estimate.byte_upper_bound_tokens + framing_reserve_tokens
    )
    system_tokens = allocation_map[PromptAllocationCategory.SYSTEM].estimate.byte_upper_bound_tokens
    schema_tokens = allocation_map[PromptAllocationCategory.SCHEMA].estimate.byte_upper_bound_tokens
    protocol_tokens = allocation_map[
        PromptAllocationCategory.PROTOCOL
    ].estimate.byte_upper_bound_tokens
    system_reserve = _effective_reserve(
        configured_reserved_system_tokens,
        system_tokens,
        field="system",
    )
    schema_reserve = _effective_reserve(
        configured_reserved_schema_tokens,
        schema_tokens,
        field="schema",
    )
    protocol_reserve = _effective_reserve(
        configured_reserved_protocol_tokens,
        protocol_tokens,
        field="protocol",
    )
    workflow_tokens = allocation_map[
        PromptAllocationCategory.WORKFLOW
    ].estimate.byte_upper_bound_tokens
    workflow_reserve = _effective_reserve(
        configured_reserved_workflow_tokens,
        workflow_tokens,
        field="workflow",
    )
    reserved_non_source_tokens = (
        non_source_tokens
        - system_tokens
        - schema_tokens
        - protocol_tokens
        - workflow_tokens
        + system_reserve
        + schema_reserve
        + protocol_reserve
        + workflow_reserve
    )
    source_budget = SourceTokenBudgetEvidence.build(
        usable_prompt_tokens=usable_prompt_tokens,
        non_source_prompt_tokens=non_source_tokens,
        reserved_non_source_prompt_tokens=reserved_non_source_tokens,
        configured_maximum_source_tokens_per_request=maximum_source_tokens_per_request,
        planned_source_tokens=source_estimate.estimated_tokens,
        planned_source_byte_upper_bound_tokens=source_estimate.byte_upper_bound_tokens,
    )
    global_budget = GlobalTokenBudgetEvidence.build(
        global_input_token_budget=global_input_token_budget,
        global_output_token_budget=global_output_token_budget,
        input_tokens_reserved_before=input_tokens_reserved_before,
        output_tokens_reserved_before=output_tokens_reserved_before,
        request_input_tokens=byte_upper_bound,
        request_output_tokens=requested_completion_tokens,
    )
    canonical_omissions = _canonical_context_omissions(context_omissions)
    omission_hashes = tuple(sorted(item.omitted_item_sha256 for item in canonical_omissions))
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "request_id": request_id,
        "role": role,
        "route_intersection": route_intersection,
        "context_utilization": context_utilization,
        "allocations": canonical_allocations,
        "requested_surface_count": requested_surface_count,
        "output_allocations": output_allocations,
        "required_output_tokens": required_output_tokens,
        "reserved_output_tokens": required_output_tokens,
        "reserved_reasoning_tokens": reserved_reasoning_tokens,
        "requested_completion_tokens": requested_completion_tokens,
        "hard_prompt_tokens": hard_prompt_tokens,
        "usable_prompt_tokens": usable_prompt_tokens,
        "estimated_prompt_tokens": estimated_prompt_tokens,
        "prompt_upper_bound_method": PROMPT_UPPER_BOUND_METHOD,
        "prompt_content_byte_upper_bound_tokens": content_byte_upper_bound,
        "prompt_framing_reserve_tokens": framing_reserve_tokens,
        "prompt_byte_upper_bound_tokens": byte_upper_bound,
        "reserved_system_tokens": system_reserve,
        "reserved_schema_tokens": schema_reserve,
        "reserved_protocol_tokens": protocol_reserve,
        "reserved_workflow_tokens": workflow_reserve,
        "context_omissions": canonical_omissions,
        "context_omission_sha256s": omission_hashes,
        "source_budget": source_budget,
        "global_budget": global_budget,
    }
    return RequestTokenPlan(
        schema_version="1.0",
        request_id=request_id,
        role=role,
        route_intersection=route_intersection,
        context_utilization=context_utilization,
        allocations=canonical_allocations,
        requested_surface_count=requested_surface_count,
        output_allocations=output_allocations,
        required_output_tokens=required_output_tokens,
        reserved_output_tokens=required_output_tokens,
        reserved_reasoning_tokens=reserved_reasoning_tokens,
        requested_completion_tokens=requested_completion_tokens,
        hard_prompt_tokens=hard_prompt_tokens,
        usable_prompt_tokens=usable_prompt_tokens,
        estimated_prompt_tokens=estimated_prompt_tokens,
        prompt_upper_bound_method=PROMPT_UPPER_BOUND_METHOD,
        prompt_content_byte_upper_bound_tokens=content_byte_upper_bound,
        prompt_framing_reserve_tokens=framing_reserve_tokens,
        prompt_byte_upper_bound_tokens=byte_upper_bound,
        reserved_system_tokens=system_reserve,
        reserved_schema_tokens=schema_reserve,
        reserved_protocol_tokens=protocol_reserve,
        reserved_workflow_tokens=workflow_reserve,
        context_omissions=canonical_omissions,
        context_omission_sha256s=omission_hashes,
        source_budget=source_budget,
        global_budget=global_budget,
        plan_sha256=_canonical_sha256(payload),
    )


def _canonical_allocations(
    allocations: Sequence[PromptTokenAllocation],
) -> tuple[PromptTokenAllocation, ...]:
    if any(not isinstance(allocation, PromptTokenAllocation) for allocation in allocations):
        raise ContextTokenPlanError("prompt allocation inventory contains invalid evidence")
    ordered = tuple(sorted(allocations, key=lambda allocation: allocation.category.value))
    categories = tuple(allocation.category for allocation in ordered)
    if categories != PROMPT_ALLOCATION_CATEGORIES:
        raise ContextTokenPlanError(
            "prompt allocation categories must be complete, unique, and sorted"
        )
    return ordered


def build_output_token_allocations(
    *,
    required_output_tokens: int,
    requested_surface_count: int,
) -> tuple[OutputTokenAllocation, ...]:
    """Reserve explicit finding, coverage, and summary capacity.

    The per-surface floor is intentionally compact: it proves that the requested
    coverage inventory is mathematically possible without pretending that this
    estimate is the provider's tokenizer. The remaining visible output is
    preferentially retained for findings and a bounded synthesis.
    """

    if required_output_tokens < len(OUTPUT_ALLOCATION_CATEGORIES):
        raise ContextTokenPlanError(
            "required output cannot fund finding, coverage, and summary allocations"
        )
    coverage_minimum = max(
        1,
        requested_surface_count * MINIMUM_COVERAGE_TOKENS_PER_SURFACE,
    )
    findings_minimum = max(
        MINIMUM_FINDING_OUTPUT_TOKENS,
        min(1_024, required_output_tokens // 4),
    )
    summary_minimum = max(
        MINIMUM_SUMMARY_OUTPUT_TOKENS,
        min(512, required_output_tokens // 8),
    )
    minimum_total = coverage_minimum + findings_minimum + summary_minimum
    if minimum_total > required_output_tokens:
        raise ContextTokenPlanError(
            "requested surface output is infeasible within the visible output reserve"
        )
    remaining = required_output_tokens - minimum_total
    findings_tokens = findings_minimum + ((remaining * 2) // 3)
    coverage_tokens = coverage_minimum + (remaining // 6)
    summary_tokens = required_output_tokens - findings_tokens - coverage_tokens
    allocations = (
        OutputTokenAllocation.build(
            category=OutputAllocationCategory.COVERAGE,
            reserved_tokens=coverage_tokens,
            minimum_reserved_tokens=coverage_minimum,
            requested_surface_count=requested_surface_count,
            minimum_tokens_per_surface=(
                MINIMUM_COVERAGE_TOKENS_PER_SURFACE if requested_surface_count else 0
            ),
        ),
        OutputTokenAllocation.build(
            category=OutputAllocationCategory.FINDINGS,
            reserved_tokens=findings_tokens,
            minimum_reserved_tokens=findings_minimum,
        ),
        OutputTokenAllocation.build(
            category=OutputAllocationCategory.SUMMARY,
            reserved_tokens=summary_tokens,
            minimum_reserved_tokens=summary_minimum,
        ),
    )
    return tuple(sorted(allocations, key=lambda allocation: allocation.category.value))


def _utilized_tokens(capacity: int, utilization: Decimal) -> int:
    return int((Decimal(capacity) * utilization).to_integral_value(rounding=ROUND_FLOOR))


def _effective_reserve(configured: int, actual: int, *, field: str) -> int:
    if isinstance(configured, bool) or not isinstance(configured, int) or configured < 0:
        raise ContextTokenPlanError(f"configured {field} token reserve is invalid")
    return max(configured, actual)


def _canonical_context_omissions(
    values: Sequence[ContextOmissionItem],
) -> tuple[ContextOmissionItem, ...]:
    if any(not isinstance(value, ContextOmissionItem) for value in values):
        raise ContextTokenPlanError("context omission inventory contains invalid evidence")
    canonical = tuple(
        sorted(
            values,
            key=lambda item: (
                item.category.value,
                item.reason.value,
                item.omitted_item_sha256,
            ),
        )
    )
    hashes = tuple(item.omitted_item_sha256 for item in canonical)
    if len(hashes) != len(set(hashes)):
        raise ContextTokenPlanError("context omission inventory contains duplicate items")
    return canonical


def _route_sort_key(route: EndpointRouteTokenCapacity) -> tuple[str, str, str]:
    return (
        route.exact_model_id.casefold(),
        route.provider_endpoint.casefold(),
        route.endpoint_snapshot_sha256,
    )


def _route_identity(route: EndpointRouteTokenCapacity) -> tuple[str, str]:
    return route.exact_model_id.casefold(), route.provider_endpoint.casefold()


def _require_self_hash(model: BaseModel, field: str) -> None:
    observed = getattr(model, field)
    if not isinstance(observed, str) or _SHA256_RE.fullmatch(observed) is None:
        raise ValueError(f"{field} is invalid")
    expected = _canonical_sha256(model.model_dump(mode="json", exclude={field}))
    if observed != expected:
        raise ValueError(f"{field} does not match the canonical evidence")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=_canonical_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Decimal):
        return format(value, "f")
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


__all__ = [
    "DEFAULT_CONTEXT_UTILIZATION",
    "MAXIMUM_CONTEXT_UTILIZATION",
    "MINIMUM_CONTEXT_UTILIZATION",
    "MINIMUM_COVERAGE_TOKENS_PER_SURFACE",
    "MINIMUM_FINDING_OUTPUT_TOKENS",
    "MINIMUM_SUMMARY_OUTPUT_TOKENS",
    "OUTPUT_ALLOCATION_CATEGORIES",
    "PROMPT_ALLOCATION_CATEGORIES",
    "PROMPT_UPPER_BOUND_METHOD",
    "UTF8_TOKEN_ESTIMATOR",
    "ContextOmissionCategory",
    "ContextOmissionItem",
    "ContextOmissionReason",
    "ContextTokenPlanError",
    "EndpointRouteIntersection",
    "EndpointRouteTokenCapacity",
    "EndpointTokenCapacityError",
    "GlobalTokenBudgetEvidence",
    "GlobalTokenBudgetPlanningError",
    "OutputAllocationCategory",
    "OutputTokenAllocation",
    "PromptAllocationCategory",
    "PromptTokenAllocation",
    "RequestTokenPlan",
    "SourceTokenBudgetEvidence",
    "TokenPlanningError",
    "Utf8TokenEstimate",
    "build_request_token_plan",
]
