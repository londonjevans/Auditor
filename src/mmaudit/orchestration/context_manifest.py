"""Hash-only context-planning and provider-usage evidence for one audit run."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Sequence
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.token_planning import (
    CONTEXT_OMISSION_GROUP_CAP,
    CONTEXT_OMISSION_SAMPLE_CAP,
    OUTPUT_ALLOCATION_CATEGORIES,
    PROMPT_ALLOCATION_CATEGORIES,
    ContextOmissionCategory,
    ContextOmissionCommitmentMethod,
    ContextOmissionItem,
    ContextOmissionReason,
    EndpointRouteIntersection,
    OutputTokenAllocation,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
)
from mmaudit.orchestration.budgets import AtomicTokenReservationEvidence
from mmaudit.reporting.json_report import stable_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_RE = re.compile(_SHA256_PATTERN)
_REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_MAX_CONTEXT_MANIFEST_BYTES = 100_000_000
_MAX_CONTEXT_REQUESTS = 100_000
_MAX_REQUEST_OMISSION_EVIDENCE = CONTEXT_OMISSION_GROUP_CAP + 1


class ContextManifestError(ValueError):
    """Raised when request context evidence cannot be proven conservatively."""


class FrozenContextEvidence(BaseModel):
    """Strict immutable base for public context evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ContextRequestState(StrEnum):
    """Terminal provider or host-side preflight state for one planned request."""

    COMPLETED = "COMPLETED"
    TRUNCATED = "TRUNCATED"
    SENT_FAILED = "SENT_FAILED"
    PRE_FLIGHT_REJECTED = "PRE_FLIGHT_REJECTED"
    NOT_SENT = "NOT_SENT"


class ActualTokenUsageSource(StrEnum):
    """Provenance class for actual token totals retained by the provider adapter."""

    PROVIDER_RESPONSE = "PROVIDER_RESPONSE"
    MOCK_RESPONSE = "MOCK_RESPONSE"
    UNAVAILABLE = "UNAVAILABLE"


class ContextOmissionProvenance(StrEnum):
    """Origin of one omission inventory."""

    BLIND_DISCOVERY_POLICY = "BLIND_DISCOVERY_POLICY"
    HASHED_CONTEXT_PACKAGE = "HASHED_CONTEXT_PACKAGE"


class OmissionTokenEstimationState(StrEnum):
    """Whether omitted content has a defensible token estimate."""

    NOT_ESTIMATED = "NOT_ESTIMATED"


class ContextPreflightReason(StrEnum):
    """Typed host-side reason a request did not reach provider transport."""

    ENDPOINT_CAPACITY = "ENDPOINT_CAPACITY"
    GLOBAL_TOKEN_BUDGET = "GLOBAL_TOKEN_BUDGET"
    COST_BUDGET = "COST_BUDGET"
    ROUTE_UNAVAILABLE = "ROUTE_UNAVAILABLE"
    CONTEXT_PLAN_INVALID = "CONTEXT_PLAN_INVALID"
    ORCHESTRATOR_NOT_SCHEDULED = "ORCHESTRATOR_NOT_SCHEDULED"


class ContextPreflightSource(StrEnum):
    """Trusted component that made a preflight decision."""

    TOKEN_PLANNER = "TOKEN_PLANNER"
    BUDGET_MANAGER = "BUDGET_MANAGER"
    ORCHESTRATOR = "ORCHESTRATOR"


class ContextPlanningComponentState(StrEnum):
    """Whether one diagnostic planning component was measured before rejection."""

    MEASURED = "MEASURED"
    UNAVAILABLE = "UNAVAILABLE"


class ContextPlanningSnapshot(FrozenContextEvidence):
    """Self-hashed diagnostic facts retained when no valid request plan exists."""

    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    role: str = Field(pattern=_ROLE_PATTERN)
    requested_model: str = Field(pattern=_MODEL_ID_PATTERN)
    reason: ContextPreflightReason
    route_state: ContextPlanningComponentState
    route_intersection: EndpointRouteIntersection | None = None
    prompt_state: ContextPlanningComponentState
    allocations: tuple[PromptTokenAllocation, ...] | None = None
    output_state: ContextPlanningComponentState
    output_allocations: tuple[OutputTokenAllocation, ...] | None = None
    requested_surface_count: int = Field(ge=0, le=10_000)
    required_output_tokens: int = Field(gt=0)
    reserved_reasoning_tokens: int = Field(ge=0)
    requested_completion_tokens: int = Field(gt=0)
    estimated_prompt_tokens: int | None = Field(default=None, ge=0)
    prompt_content_byte_upper_bound_tokens: int | None = Field(default=None, ge=0)
    prompt_envelope_byte_upper_bound_tokens: int | None = Field(default=None, ge=0)
    context_omissions: tuple[ContextOmissionItem, ...] = Field(
        default=(),
        max_length=CONTEXT_OMISSION_GROUP_CAP,
    )
    context_omission_sha256s: tuple[str, ...] = Field(
        default=(),
        max_length=CONTEXT_OMISSION_GROUP_CAP,
    )
    review_credit: Literal[False] = False
    atomic_reservation_created: Literal[False] = False
    provider_request_sent: Literal[False] = False
    snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        role: str,
        requested_model: str,
        reason: ContextPreflightReason,
        route_intersection: EndpointRouteIntersection | None,
        allocations: Sequence[PromptTokenAllocation] | None,
        output_allocations: Sequence[OutputTokenAllocation] | None,
        requested_surface_count: int,
        required_output_tokens: int,
        reserved_reasoning_tokens: int,
        prompt_envelope_byte_upper_bound_tokens: int | None,
        context_omissions: Sequence[ContextOmissionItem] = (),
    ) -> Self:
        canonical_allocations = (
            tuple(sorted(allocations, key=lambda item: item.category.value))
            if allocations is not None
            else None
        )
        canonical_output_allocations = (
            tuple(sorted(output_allocations, key=lambda item: item.category.value))
            if output_allocations is not None
            else None
        )
        estimated_prompt_tokens = (
            sum(item.estimate.estimated_tokens for item in canonical_allocations)
            if canonical_allocations is not None
            else None
        )
        prompt_content_byte_upper_bound_tokens = (
            sum(item.estimate.byte_upper_bound_tokens for item in canonical_allocations)
            if canonical_allocations is not None
            else None
        )
        canonical_omissions = tuple(
            sorted(
                context_omissions,
                key=lambda item: (
                    item.category.value,
                    item.reason.value,
                    item.omitted_item_sha256,
                ),
            )
        )
        omission_hashes = tuple(sorted(item.omitted_item_sha256 for item in canonical_omissions))
        requested_completion_tokens = required_output_tokens + reserved_reasoning_tokens
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "request_id": request_id,
            "role": role,
            "requested_model": requested_model,
            "reason": reason,
            "route_state": (
                ContextPlanningComponentState.MEASURED
                if route_intersection is not None
                else ContextPlanningComponentState.UNAVAILABLE
            ),
            "route_intersection": route_intersection,
            "prompt_state": (
                ContextPlanningComponentState.MEASURED
                if canonical_allocations is not None
                else ContextPlanningComponentState.UNAVAILABLE
            ),
            "allocations": canonical_allocations,
            "output_state": (
                ContextPlanningComponentState.MEASURED
                if canonical_output_allocations is not None
                else ContextPlanningComponentState.UNAVAILABLE
            ),
            "output_allocations": canonical_output_allocations,
            "requested_surface_count": requested_surface_count,
            "required_output_tokens": required_output_tokens,
            "reserved_reasoning_tokens": reserved_reasoning_tokens,
            "requested_completion_tokens": requested_completion_tokens,
            "estimated_prompt_tokens": estimated_prompt_tokens,
            "prompt_content_byte_upper_bound_tokens": (prompt_content_byte_upper_bound_tokens),
            "prompt_envelope_byte_upper_bound_tokens": (prompt_envelope_byte_upper_bound_tokens),
            "context_omissions": canonical_omissions,
            "context_omission_sha256s": omission_hashes,
            "review_credit": False,
            "atomic_reservation_created": False,
            "provider_request_sent": False,
        }
        return cls(
            **payload,
            snapshot_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def diagnostic_components_are_honest_and_self_hashed(
        self,
    ) -> ContextPlanningSnapshot:
        if (self.route_state is ContextPlanningComponentState.MEASURED) != (
            self.route_intersection is not None
        ):
            raise ValueError("planning route state differs from its evidence")
        if self.route_intersection is not None and (
            self.requested_model not in self.route_intersection.exact_model_ids
        ):
            raise ValueError("planning route evidence differs from the requested model")
        if (self.prompt_state is ContextPlanningComponentState.MEASURED) != (
            self.allocations is not None
        ):
            raise ValueError("planning prompt state differs from its evidence")
        if self.allocations is None:
            if (
                self.estimated_prompt_tokens is not None
                or self.prompt_content_byte_upper_bound_tokens is not None
            ):
                raise ValueError("unavailable prompt planning cannot retain derived totals")
        else:
            if tuple(item.category for item in self.allocations) != (PROMPT_ALLOCATION_CATEGORIES):
                raise ValueError("planning prompt allocation inventory is incomplete")
            if self.estimated_prompt_tokens != sum(
                item.estimate.estimated_tokens for item in self.allocations
            ) or self.prompt_content_byte_upper_bound_tokens != sum(
                item.estimate.byte_upper_bound_tokens for item in self.allocations
            ):
                raise ValueError("planning prompt totals do not conserve allocations")
            if (
                self.prompt_envelope_byte_upper_bound_tokens is not None
                and self.prompt_envelope_byte_upper_bound_tokens
                < self.prompt_content_byte_upper_bound_tokens
            ):
                raise ValueError("planning prompt envelope omits measured content")
        if (self.output_state is ContextPlanningComponentState.MEASURED) != (
            self.output_allocations is not None
        ):
            raise ValueError("planning output state differs from its evidence")
        if self.output_allocations is not None:
            if tuple(item.category for item in self.output_allocations) != (
                OUTPUT_ALLOCATION_CATEGORIES
            ):
                raise ValueError("planning output allocation inventory is incomplete")
            if (
                sum(item.reserved_tokens for item in self.output_allocations)
                != self.required_output_tokens
            ):
                raise ValueError("planning output allocations do not conserve tokens")
            coverage = next(
                item for item in self.output_allocations if item.category.value == "coverage"
            )
            if coverage.requested_surface_count != self.requested_surface_count:
                raise ValueError("planning output surface demand is inconsistent")
        if self.requested_completion_tokens != (
            self.required_output_tokens + self.reserved_reasoning_tokens
        ):
            raise ValueError("planning completion demand is inconsistent")
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
        omission_hashes = tuple(sorted(item.omitted_item_sha256 for item in self.context_omissions))
        omission_groups = tuple((item.category, item.reason) for item in self.context_omissions)
        if self.context_omissions != canonical_omissions:
            raise ValueError("planning omissions must be canonically sorted")
        if (
            len(omission_groups) != len(set(omission_groups))
            or len(omission_hashes) != len(set(omission_hashes))
            or self.context_omission_sha256s != omission_hashes
            or any(_SHA256_RE.fullmatch(value) is None for value in omission_hashes)
        ):
            raise ValueError("planning omission groups and hashes must be unique and sorted")
        _require_self_hash(self, "snapshot_sha256")
        return self


class ContextOmissionEvidence(FrozenContextEvidence):
    """Bounded aggregate inventory for one typed omission class."""

    schema_version: Literal["1.1"] = "1.1"
    category: ContextOmissionCategory
    reason: ContextOmissionReason
    provenance: ContextOmissionProvenance
    inventory_commitment_method: ContextOmissionCommitmentMethod | None = None
    inventory_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    # The compatibility-named field is a bounded representative sample, not the
    # complete inventory. The exact count and inventory commitment are separate.
    omitted_item_sha256s: tuple[str, ...] = Field(
        max_length=CONTEXT_OMISSION_SAMPLE_CAP,
    )
    omitted_item_count: int = Field(ge=0)
    samples_truncated: bool
    context_omission_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    token_estimation_state: Literal[OmissionTokenEstimationState.NOT_ESTIMATED] = (
        OmissionTokenEstimationState.NOT_ESTIMATED
    )
    estimated_tokens: None = None
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        category: ContextOmissionCategory,
        reason: ContextOmissionReason,
        provenance: ContextOmissionProvenance,
        context_omission: ContextOmissionItem | None = None,
    ) -> Self:
        if provenance is ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE:
            if not isinstance(context_omission, ContextOmissionItem):
                raise ContextManifestError(
                    "hashed context omission evidence requires one typed aggregate"
                )
            if context_omission.category is not category or context_omission.reason is not reason:
                raise ContextManifestError(
                    "hashed context omission aggregate differs from its evidence class"
                )
            inventory_sha256 = context_omission.omitted_item_sha256
            inventory_commitment_method = context_omission.inventory_commitment_method
            samples = context_omission.sampled_item_sha256s
            omitted_item_count = context_omission.omitted_item_count
            samples_truncated = context_omission.samples_truncated
            context_omission_evidence_sha256 = context_omission.evidence_sha256
        else:
            if context_omission is not None:
                raise ContextManifestError(
                    "blind-discovery omission evidence cannot retain a context aggregate"
                )
            inventory_sha256 = None
            inventory_commitment_method = None
            samples = ()
            omitted_item_count = 0
            samples_truncated = False
            context_omission_evidence_sha256 = None
        payload: dict[str, Any] = {
            "schema_version": "1.1",
            "category": category,
            "reason": reason,
            "provenance": provenance,
            "inventory_commitment_method": inventory_commitment_method,
            "inventory_sha256": inventory_sha256,
            "omitted_item_sha256s": samples,
            "omitted_item_count": omitted_item_count,
            "samples_truncated": samples_truncated,
            "context_omission_evidence_sha256": context_omission_evidence_sha256,
            "token_estimation_state": OmissionTokenEstimationState.NOT_ESTIMATED,
            "estimated_tokens": None,
        }
        return cls(
            schema_version="1.1",
            category=category,
            reason=reason,
            provenance=provenance,
            inventory_commitment_method=inventory_commitment_method,
            inventory_sha256=inventory_sha256,
            omitted_item_sha256s=samples,
            omitted_item_count=omitted_item_count,
            samples_truncated=samples_truncated,
            context_omission_evidence_sha256=context_omission_evidence_sha256,
            token_estimation_state=OmissionTokenEstimationState.NOT_ESTIMATED,
            estimated_tokens=None,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def omission_is_canonical_and_self_hashed(self) -> ContextOmissionEvidence:
        if any(_SHA256_RE.fullmatch(value) is None for value in self.omitted_item_sha256s):
            raise ValueError("context omission inventory contains a non-SHA-256 value")
        if len(self.omitted_item_sha256s) != len(set(self.omitted_item_sha256s)):
            raise ValueError("context omission samples must be unique")
        if self.omitted_item_count < len(self.omitted_item_sha256s):
            raise ValueError("context omission count is below its retained samples")
        if self.samples_truncated != (self.omitted_item_count > len(self.omitted_item_sha256s)):
            raise ValueError("context omission truncation state differs from its sample count")
        if self.reason is ContextOmissionReason.BLIND_DISCOVERY_WITHHELD:
            if (
                self.category is not ContextOmissionCategory.PRIOR_AUDIT
                or self.provenance is not ContextOmissionProvenance.BLIND_DISCOVERY_POLICY
                or self.inventory_commitment_method is not None
                or self.inventory_sha256 is not None
                or self.omitted_item_sha256s
                or self.omitted_item_count != 0
                or self.samples_truncated
                or self.context_omission_evidence_sha256 is not None
            ):
                raise ValueError("blind-discovery omission evidence is inconsistent")
        else:
            if (
                self.provenance is not ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE
                or self.inventory_commitment_method is None
                or self.inventory_sha256 is None
                or not self.omitted_item_sha256s
                or self.omitted_item_count <= 0
                or self.context_omission_evidence_sha256 is None
            ):
                raise ValueError("context-package omission evidence is inconsistent")
            ContextOmissionItem(
                schema_version="1.1",
                category=self.category,
                reason=self.reason,
                inventory_commitment_method=self.inventory_commitment_method,
                omitted_item_sha256=self.inventory_sha256,
                omitted_item_count=self.omitted_item_count,
                sampled_item_sha256s=self.omitted_item_sha256s,
                samples_truncated=self.samples_truncated,
                evidence_sha256=self.context_omission_evidence_sha256,
            )
        _require_self_hash(self, "evidence_sha256")
        return self


class ActualTokenUsageEvidence(FrozenContextEvidence):
    """Typed actual token totals, with no raw provider response."""

    schema_version: Literal["1.0"] = "1.0"
    source: ActualTokenUsageSource
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    openrouter_generation_id_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, usage: UsageRecord) -> Self:
        source = _actual_usage_source(usage)
        available = source is not ActualTokenUsageSource.UNAVAILABLE
        generation_id_sha256 = (
            hashlib.sha256(usage.openrouter_generation_id.encode("utf-8")).hexdigest()
            if available and usage.openrouter_generation_id is not None
            else None
        )
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "source": source,
            "prompt_tokens": usage.prompt_tokens if available else None,
            "completion_tokens": usage.completion_tokens if available else None,
            "total_tokens": usage.total_tokens if available else None,
            "openrouter_generation_id_sha256": generation_id_sha256,
        }
        return cls(
            schema_version="1.0",
            source=source,
            prompt_tokens=payload["prompt_tokens"],
            completion_tokens=payload["completion_tokens"],
            total_tokens=payload["total_tokens"],
            openrouter_generation_id_sha256=generation_id_sha256,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def actual_usage_conserves_tokens_and_is_self_hashed(self) -> ActualTokenUsageEvidence:
        values = (self.prompt_tokens, self.completion_tokens, self.total_tokens)
        if self.source is ActualTokenUsageSource.UNAVAILABLE:
            if any(value is not None for value in values):
                raise ValueError("unavailable token usage may not retain fabricated totals")
            if self.openrouter_generation_id_sha256 is not None:
                raise ValueError("unavailable token usage may not claim generation provenance")
        else:
            if any(value is None for value in values):
                raise ValueError("reported token usage requires complete totals")
            assert self.prompt_tokens is not None
            assert self.completion_tokens is not None
            assert self.total_tokens is not None
            if self.total_tokens != self.prompt_tokens + self.completion_tokens:
                raise ValueError("actual token usage does not conserve prompt and completion")
            if self.prompt_tokens <= 0:
                raise ValueError("reported token usage requires non-zero prompt tokens")
        _require_self_hash(self, "evidence_sha256")
        return self


class ContextRequestEvidence(FrozenContextEvidence):
    """Semantic join between one usage record and its exact request token plan."""

    schema_version: Literal["1.0"] = "1.0"
    evidence_kind: Literal["provider_usage"] = "provider_usage"
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    role: str = Field(pattern=_ROLE_PATTERN)
    requested_model: str = Field(pattern=_MODEL_ID_PATTERN)
    execution_evidence: ExecutionEvidenceKind
    request_state: Literal[
        ContextRequestState.COMPLETED,
        ContextRequestState.TRUNCATED,
        ContextRequestState.SENT_FAILED,
    ]
    provider_attempts: int = Field(ge=1)
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    user_prompt_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    request_body_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    response_schema_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    request_plan: RequestTokenPlan
    request_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    atomic_token_reservations: tuple[AtomicTokenReservationEvidence, ...] = Field(
        min_length=1,
        max_length=32,
    )
    atomic_token_reservation_sha256s: tuple[str, ...] = Field(
        min_length=1,
        max_length=32,
    )
    atomic_token_reservation: AtomicTokenReservationEvidence
    atomic_token_reservation_sha256: str = Field(pattern=_SHA256_PATTERN)
    omissions: tuple[ContextOmissionEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_REQUEST_OMISSION_EVIDENCE,
    )
    actual_usage: ActualTokenUsageEvidence
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, usage: UsageRecord) -> Self:
        plan = _request_token_plan_from_usage(usage)
        token_reservations = _atomic_token_reservations_from_usage(usage, plan)
        token_reservation = token_reservations[-1]
        token_reservation_sha256s = tuple(
            evidence.evidence_sha256 for evidence in token_reservations
        )
        omissions = [
            ContextOmissionEvidence.build(
                category=ContextOmissionCategory.PRIOR_AUDIT,
                reason=ContextOmissionReason.BLIND_DISCOVERY_WITHHELD,
                provenance=ContextOmissionProvenance.BLIND_DISCOVERY_POLICY,
            )
        ]
        for item in plan.context_omissions:
            omissions.append(
                ContextOmissionEvidence.build(
                    category=item.category,
                    reason=item.reason,
                    provenance=ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE,
                    context_omission=item,
                )
            )
        ordered_omissions = tuple(sorted(omissions, key=_omission_sort_key))
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_kind": "provider_usage",
            "request_id": usage.request_id,
            "role": usage.role,
            "requested_model": usage.requested_model,
            "execution_evidence": usage.execution_evidence,
            "request_state": _request_state(usage),
            "provider_attempts": usage.attempts,
            "usage_record_sha256": _canonical_sha256(usage.model_dump(mode="json")),
            "prompt_sha256": usage.prompt_sha256,
            "user_prompt_sha256": usage.user_prompt_sha256,
            "request_body_sha256": usage.request_body_sha256,
            "response_schema_sha256": usage.schema_sha256,
            "request_plan": plan,
            "request_plan_sha256": plan.plan_sha256,
            "atomic_token_reservations": token_reservations,
            "atomic_token_reservation_sha256s": token_reservation_sha256s,
            "atomic_token_reservation": token_reservation,
            "atomic_token_reservation_sha256": token_reservation.evidence_sha256,
            "omissions": ordered_omissions,
            "actual_usage": ActualTokenUsageEvidence.build(usage),
        }
        return cls(
            schema_version="1.0",
            evidence_kind="provider_usage",
            request_id=usage.request_id,
            role=usage.role,
            requested_model=usage.requested_model,
            execution_evidence=usage.execution_evidence,
            request_state=payload["request_state"],
            provider_attempts=usage.attempts,
            usage_record_sha256=payload["usage_record_sha256"],
            prompt_sha256=usage.prompt_sha256,
            user_prompt_sha256=usage.user_prompt_sha256,
            request_body_sha256=usage.request_body_sha256,
            response_schema_sha256=usage.schema_sha256,
            request_plan=plan,
            request_plan_sha256=plan.plan_sha256,
            atomic_token_reservations=token_reservations,
            atomic_token_reservation_sha256s=token_reservation_sha256s,
            atomic_token_reservation=token_reservation,
            atomic_token_reservation_sha256=token_reservation.evidence_sha256,
            omissions=ordered_omissions,
            actual_usage=payload["actual_usage"],
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def request_join_is_consistent_and_self_hashed(self) -> ContextRequestEvidence:
        expected_attempt_ids = tuple(
            self.request_id if attempt == 1 else f"{self.request_id}:attempt:{attempt}"
            for attempt in range(1, self.provider_attempts + 1)
        )
        if (
            self.request_plan.request_id != self.request_id
            or self.request_plan.role != self.role
            or self.request_plan_sha256 != self.request_plan.plan_sha256
            or self.requested_model not in self.request_plan.route_intersection.exact_model_ids
            or len(self.atomic_token_reservations) != self.provider_attempts
            or len(self.atomic_token_reservation_sha256s) != self.provider_attempts
            or tuple(item.request_id for item in self.atomic_token_reservations)
            != expected_attempt_ids
            or self.atomic_token_reservation_sha256s
            != tuple(item.evidence_sha256 for item in self.atomic_token_reservations)
            or len(set(self.atomic_token_reservation_sha256s))
            != len(self.atomic_token_reservation_sha256s)
            or self.atomic_token_reservation != self.atomic_token_reservations[-1]
            or self.atomic_token_reservation.exact_model_id != self.requested_model
            or self.atomic_token_reservation.role != self.role
            or self.atomic_token_reservation.request_token_plan_sha256
            != self.request_plan.plan_sha256
            or self.atomic_token_reservation.planned_prompt_tokens
            != self.request_plan.prompt_byte_upper_bound_tokens
            or self.atomic_token_reservation.planned_completion_tokens
            != self.request_plan.requested_completion_tokens
            or self.atomic_token_reservation.global_input_token_limit
            != self.request_plan.global_budget.global_input_token_budget
            or self.atomic_token_reservation.global_output_token_limit
            != self.request_plan.global_budget.global_output_token_budget
            or self.atomic_token_reservation_sha256 != self.atomic_token_reservation.evidence_sha256
        ):
            raise ValueError("context request differs from its endpoint-bound token plan")
        for reservation in self.atomic_token_reservations:
            if (
                reservation.exact_model_id != self.requested_model
                or reservation.role != self.role
                or reservation.request_token_plan_sha256 != self.request_plan.plan_sha256
                or reservation.planned_prompt_tokens
                != self.request_plan.prompt_byte_upper_bound_tokens
                or reservation.planned_completion_tokens
                != self.request_plan.requested_completion_tokens
                or reservation.global_input_token_limit
                != self.request_plan.global_budget.global_input_token_budget
                or reservation.global_output_token_limit
                != self.request_plan.global_budget.global_output_token_budget
            ):
                raise ValueError("context request reservation inventory differs from its plan")
        omission_keys = tuple(_omission_sort_key(item) for item in self.omissions)
        if omission_keys != tuple(sorted(set(omission_keys))):
            raise ValueError("context request omissions must be unique and sorted")
        prior_audit = [
            allocation
            for allocation in self.request_plan.allocations
            if allocation.category is PromptAllocationCategory.PRIOR_AUDIT
        ]
        if len(prior_audit) != 1 or prior_audit[0].estimate.estimated_tokens != 0:
            raise ValueError("blind request token plan must withhold prior-audit content")
        if not any(
            omission.reason is ContextOmissionReason.BLIND_DISCOVERY_WITHHELD
            for omission in self.omissions
        ):
            raise ValueError("context request lacks explicit blind prior-audit evidence")
        observed_context_omissions = tuple(
            _context_omission_item_from_evidence(omission)
            for omission in self.omissions
            if omission.provenance is ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE
        )
        expected_context_omissions = self.request_plan.context_omissions
        if observed_context_omissions != expected_context_omissions:
            raise ValueError("context omission evidence differs from its request plan")
        if self.request_state is ContextRequestState.COMPLETED and (
            self.actual_usage.source is ActualTokenUsageSource.UNAVAILABLE
            or self.actual_usage.prompt_tokens is None
            or self.actual_usage.prompt_tokens <= 0
            or self.actual_usage.completion_tokens is None
            or self.actual_usage.completion_tokens <= 0
        ):
            raise ValueError("completed request lacks complete actual token usage")
        if self.actual_usage.source is not ActualTokenUsageSource.UNAVAILABLE:
            assert self.actual_usage.prompt_tokens is not None
            assert self.actual_usage.completion_tokens is not None
            assert self.actual_usage.total_tokens is not None
            limits = self.request_plan.route_intersection
            if (
                self.actual_usage.prompt_tokens > self.request_plan.prompt_byte_upper_bound_tokens
                or self.actual_usage.prompt_tokens > limits.max_prompt_tokens
                or self.actual_usage.completion_tokens
                > self.request_plan.requested_completion_tokens
                or self.actual_usage.completion_tokens > limits.max_completion_tokens
                or self.actual_usage.total_tokens > limits.context_tokens
            ):
                raise ValueError("actual token usage exceeds the endpoint-bound request plan")
        _require_self_hash(self, "evidence_sha256")
        return self


class ContextPreflightRequestEvidence(FrozenContextEvidence):
    """Hash-only proof that one planned request did not enter transport."""

    schema_version: Literal["1.0"] = "1.0"
    evidence_kind: Literal["preflight"] = "preflight"
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    logical_request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    role: str = Field(pattern=_ROLE_PATTERN)
    requested_model: str = Field(pattern=_MODEL_ID_PATTERN)
    request_state: Literal[
        ContextRequestState.PRE_FLIGHT_REJECTED,
        ContextRequestState.NOT_SENT,
    ]
    decision_source: ContextPreflightSource
    reason: ContextPreflightReason
    decision_evidence_sha256s: tuple[str, ...] = Field(min_length=1, max_length=100)
    request_plan: RequestTokenPlan | None = None
    request_plan_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    planning_snapshot: ContextPlanningSnapshot | None = None
    planning_snapshot_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    estimated_prompt_tokens: int | None = Field(default=None, ge=0)
    requested_completion_tokens: int = Field(gt=0)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        logical_request_id: str | None = None,
        role: str,
        requested_model: str,
        request_state: Literal[
            ContextRequestState.PRE_FLIGHT_REJECTED,
            ContextRequestState.NOT_SENT,
        ],
        decision_source: ContextPreflightSource,
        reason: ContextPreflightReason,
        decision_evidence_sha256s: Sequence[str],
        estimated_prompt_tokens: int | None,
        requested_completion_tokens: int,
        request_plan: RequestTokenPlan | None = None,
        planning_snapshot: ContextPlanningSnapshot | None = None,
    ) -> Self:
        evidence_hashes = tuple(sorted(decision_evidence_sha256s))
        resolved_logical_request_id = logical_request_id or request_id
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "evidence_kind": "preflight",
            "request_id": request_id,
            "logical_request_id": resolved_logical_request_id,
            "role": role,
            "requested_model": requested_model,
            "request_state": request_state,
            "decision_source": decision_source,
            "reason": reason,
            "decision_evidence_sha256s": evidence_hashes,
            "request_plan": request_plan,
            "request_plan_sha256": (request_plan.plan_sha256 if request_plan is not None else None),
            "planning_snapshot": planning_snapshot,
            "planning_snapshot_sha256": (
                planning_snapshot.snapshot_sha256 if planning_snapshot is not None else None
            ),
            "estimated_prompt_tokens": estimated_prompt_tokens,
            "requested_completion_tokens": requested_completion_tokens,
        }
        return cls(
            schema_version="1.0",
            evidence_kind="preflight",
            request_id=request_id,
            logical_request_id=resolved_logical_request_id,
            role=role,
            requested_model=requested_model,
            request_state=request_state,
            decision_source=decision_source,
            reason=reason,
            decision_evidence_sha256s=evidence_hashes,
            request_plan=request_plan,
            request_plan_sha256=payload["request_plan_sha256"],
            planning_snapshot=planning_snapshot,
            planning_snapshot_sha256=payload["planning_snapshot_sha256"],
            estimated_prompt_tokens=estimated_prompt_tokens,
            requested_completion_tokens=requested_completion_tokens,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def preflight_evidence_is_canonical_and_self_hashed(
        self,
    ) -> ContextPreflightRequestEvidence:
        if self.decision_evidence_sha256s != tuple(
            sorted(set(self.decision_evidence_sha256s))
        ) or any(_SHA256_RE.fullmatch(value) is None for value in self.decision_evidence_sha256s):
            raise ValueError("preflight decision evidence hashes must be unique and sorted")
        if (self.request_plan is None) != (self.request_plan_sha256 is None):
            raise ValueError("preflight request plan and plan hash must appear together")
        if (self.planning_snapshot is None) != (self.planning_snapshot_sha256 is None):
            raise ValueError("preflight planning snapshot and snapshot hash must appear together")
        if self.request_plan is not None and self.planning_snapshot is not None:
            raise ValueError("preflight evidence cannot carry both a plan and diagnostic snapshot")
        if self.request_plan is not None and (
            self.request_plan.request_id != self.logical_request_id
            or self.request_plan.role != self.role
            or self.requested_model not in self.request_plan.route_intersection.exact_model_ids
            or self.request_plan.plan_sha256 != self.request_plan_sha256
            or self.request_plan.estimated_prompt_tokens != self.estimated_prompt_tokens
            or self.request_plan.requested_completion_tokens != self.requested_completion_tokens
        ):
            raise ValueError("preflight evidence differs from its request token plan")
        if self.planning_snapshot is not None and (
            self.planning_snapshot.request_id != self.logical_request_id
            or self.planning_snapshot.role != self.role
            or self.planning_snapshot.requested_model != self.requested_model
            or self.planning_snapshot.reason is not self.reason
            or self.planning_snapshot.snapshot_sha256 != self.planning_snapshot_sha256
            or self.planning_snapshot.estimated_prompt_tokens != self.estimated_prompt_tokens
            or self.planning_snapshot.requested_completion_tokens
            != self.requested_completion_tokens
            or self.planning_snapshot.snapshot_sha256 not in self.decision_evidence_sha256s
        ):
            raise ValueError("preflight evidence differs from its planning snapshot")
        if self.request_state is ContextRequestState.NOT_SENT:
            if (
                self.decision_source is not ContextPreflightSource.ORCHESTRATOR
                or self.reason is not ContextPreflightReason.ORCHESTRATOR_NOT_SCHEDULED
                or self.logical_request_id != self.request_id
            ):
                raise ValueError("not-sent context evidence must be an orchestrator decision")
        else:
            permitted_rejections = {
                ContextPreflightSource.TOKEN_PLANNER: {
                    ContextPreflightReason.ENDPOINT_CAPACITY,
                    ContextPreflightReason.GLOBAL_TOKEN_BUDGET,
                    ContextPreflightReason.ROUTE_UNAVAILABLE,
                    ContextPreflightReason.CONTEXT_PLAN_INVALID,
                    ContextPreflightReason.COST_BUDGET,
                },
                ContextPreflightSource.BUDGET_MANAGER: {
                    ContextPreflightReason.GLOBAL_TOKEN_BUDGET,
                    ContextPreflightReason.COST_BUDGET,
                    ContextPreflightReason.CONTEXT_PLAN_INVALID,
                },
            }
            if self.reason not in permitted_rejections.get(self.decision_source, set()):
                raise ValueError("preflight rejection source and reason are inconsistent")
            if (
                self.decision_source is ContextPreflightSource.TOKEN_PLANNER
                and self.request_plan is None
                and self.planning_snapshot is None
            ):
                raise ValueError(
                    "planless token-planner rejection requires diagnostic planning evidence"
                )
            if (
                self.decision_source is ContextPreflightSource.BUDGET_MANAGER
                and self.request_plan is None
            ):
                raise ValueError("budget-manager rejection requires a valid request plan")
        _require_self_hash(self, "evidence_sha256")
        return self


class ContextPreflightLedger:
    """Thread-safe run-scoped inventory of host decisions made before transport."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[str, ContextPreflightRequestEvidence] = {}

    @property
    def records(self) -> tuple[ContextPreflightRequestEvidence, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))

    def add(self, record: ContextPreflightRequestEvidence) -> None:
        if not isinstance(record, ContextPreflightRequestEvidence):
            raise TypeError("context preflight ledger accepts only typed evidence")
        with self._lock:
            if record.request_id in self._records:
                raise ContextManifestError("context preflight request identity is duplicated")
            self._records[record.request_id] = record

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


ContextManifestRequestEvidence = Annotated[
    ContextRequestEvidence | ContextPreflightRequestEvidence,
    Field(discriminator="evidence_kind"),
]


class ContextCategoryTotals(FrozenContextEvidence):
    """Aggregate one prompt category across all request plans."""

    category: PromptAllocationCategory
    request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    utf8_bytes: int = Field(ge=0)
    estimated_tokens: int = Field(ge=0)
    byte_upper_bound_tokens: int = Field(ge=0)


class ContextManifestTotals(FrozenContextEvidence):
    """Conserved aggregate counts for a complete context manifest."""

    request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    planned_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    completed_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    truncated_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    failed_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    preflight_rejected_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    not_sent_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    planned_prompt_tokens: int = Field(ge=0)
    planned_source_tokens: int = Field(ge=0)
    reserved_output_tokens: int = Field(ge=0)
    reserved_reasoning_tokens: int = Field(ge=0)
    requested_completion_tokens: int = Field(ge=0)
    provider_attempt_count: int = Field(ge=0)
    atomic_reservation_count: int = Field(ge=0)
    attempt_reserved_prompt_tokens: int = Field(ge=0)
    attempt_reserved_completion_tokens: int = Field(ge=0)
    provider_reported_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    provider_reported_prompt_tokens: int = Field(ge=0)
    provider_reported_completion_tokens: int = Field(ge=0)
    mock_reported_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    mock_reported_prompt_tokens: int = Field(ge=0)
    mock_reported_completion_tokens: int = Field(ge=0)
    unavailable_actual_usage_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    omission_record_count: int = Field(ge=0)
    omission_evidence_occurrence_count: int = Field(ge=0)
    omitted_item_count: int = Field(ge=0)
    sampled_omitted_item_count: int = Field(ge=0)
    truncated_omission_record_count: int = Field(ge=0)
    categories: tuple[ContextCategoryTotals, ...] = Field(
        min_length=len(PROMPT_ALLOCATION_CATEGORIES),
        max_length=len(PROMPT_ALLOCATION_CATEGORIES),
    )
    totals_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, requests: Sequence[ContextManifestRequestEvidence]) -> Self:
        totals = _context_totals_payload(requests)
        totals["totals_sha256"] = _canonical_sha256(totals)
        return cls.model_validate(totals)

    @model_validator(mode="after")
    def totals_are_conserved_and_self_hashed(self) -> ContextManifestTotals:
        if tuple(item.category for item in self.categories) != PROMPT_ALLOCATION_CATEGORIES:
            raise ValueError("context category totals must be complete, unique, and sorted")
        if any(item.request_count != self.planned_request_count for item in self.categories):
            raise ValueError("context category request counts differ from planned requests")
        if (
            self.completed_request_count
            + self.truncated_request_count
            + self.failed_request_count
            + self.preflight_rejected_request_count
            + self.not_sent_request_count
            != self.request_count
        ):
            raise ValueError("context request states do not conserve the request count")
        if (
            self.provider_reported_request_count
            + self.mock_reported_request_count
            + self.unavailable_actual_usage_count
            != self.request_count
        ):
            raise ValueError("actual token provenance does not conserve the request count")
        if self.planned_prompt_tokens != sum(item.estimated_tokens for item in self.categories):
            raise ValueError("planned prompt total differs from category totals")
        source = next(
            item for item in self.categories if item.category is PromptAllocationCategory.SOURCE
        )
        if self.planned_source_tokens != source.estimated_tokens:
            raise ValueError("planned source total differs from the source category")
        if self.requested_completion_tokens != (
            self.reserved_output_tokens + self.reserved_reasoning_tokens
        ):
            raise ValueError("completion totals do not conserve output and reasoning reserves")
        if self.provider_attempt_count != self.atomic_reservation_count:
            raise ValueError("provider attempts differ from the atomic reservation inventory")
        if (
            self.omission_evidence_occurrence_count < self.omission_record_count
            or self.sampled_omitted_item_count > self.omitted_item_count
            or self.truncated_omission_record_count > self.omission_record_count
            or (
                self.truncated_omission_record_count == 0
                and self.sampled_omitted_item_count != self.omitted_item_count
            )
        ):
            raise ValueError("context omission totals do not conserve samples and exact counts")
        _require_self_hash(self, "totals_sha256")
        return self


class ContextManifest(FrozenContextEvidence):
    """Self-hashed deterministic context evidence for one complete run."""

    schema_version: Literal["1.1"] = "1.1"
    generated_by: Literal["mmaudit"] = "mmaudit"
    run_id: str = Field(pattern=_RUN_ID_PATTERN)
    requests: tuple[ContextManifestRequestEvidence, ...] = Field(max_length=_MAX_CONTEXT_REQUESTS)
    totals: ContextManifestTotals
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def requests_totals_and_self_hash_are_consistent(self) -> ContextManifest:
        request_ids = tuple(request.request_id for request in self.requests)
        if request_ids != tuple(sorted(set(request_ids))):
            raise ValueError("context requests must have unique sorted request IDs")
        _validate_logical_request_joins(self.requests)
        if self.totals != ContextManifestTotals.build(self.requests):
            raise ValueError("context manifest totals differ from its request evidence")
        _require_self_hash(self, "manifest_sha256")
        return self


class ContextManifestReportBinding(FrozenContextEvidence):
    """Small report projection binding client evidence to the forensic artifact."""

    schema_version: Literal["1.1"] = "1.1"
    artifact: Literal["context-manifest.json"] = "context-manifest.json"
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    preflight_rejected_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    not_sent_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    planned_prompt_tokens: int = Field(ge=0)
    planned_source_tokens: int = Field(ge=0)
    reserved_output_tokens: int = Field(ge=0)
    provider_attempt_count: int = Field(ge=0)
    atomic_reservation_count: int = Field(ge=0)
    attempt_reserved_prompt_tokens: int = Field(ge=0)
    attempt_reserved_completion_tokens: int = Field(ge=0)
    provider_reported_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    provider_reported_prompt_tokens: int = Field(ge=0)
    provider_reported_completion_tokens: int = Field(ge=0)
    mock_reported_request_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    unavailable_actual_usage_count: int = Field(ge=0, le=_MAX_CONTEXT_REQUESTS)
    omission_record_count: int = Field(ge=0)
    omission_evidence_occurrence_count: int = Field(ge=0)
    omitted_item_count: int = Field(ge=0)
    sampled_omitted_item_count: int = Field(ge=0)
    truncated_omission_record_count: int = Field(ge=0)
    preflight_evidence_sha256s: tuple[str, ...] = Field(max_length=_MAX_CONTEXT_REQUESTS)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, manifest: ContextManifest) -> Self:
        totals = manifest.totals
        payload: dict[str, Any] = {
            "schema_version": "1.1",
            "artifact": "context-manifest.json",
            "manifest_sha256": manifest.manifest_sha256,
            "request_count": totals.request_count,
            "preflight_rejected_request_count": totals.preflight_rejected_request_count,
            "not_sent_request_count": totals.not_sent_request_count,
            "planned_prompt_tokens": totals.planned_prompt_tokens,
            "planned_source_tokens": totals.planned_source_tokens,
            "reserved_output_tokens": totals.reserved_output_tokens,
            "provider_attempt_count": totals.provider_attempt_count,
            "atomic_reservation_count": totals.atomic_reservation_count,
            "attempt_reserved_prompt_tokens": totals.attempt_reserved_prompt_tokens,
            "attempt_reserved_completion_tokens": totals.attempt_reserved_completion_tokens,
            "provider_reported_request_count": totals.provider_reported_request_count,
            "provider_reported_prompt_tokens": totals.provider_reported_prompt_tokens,
            "provider_reported_completion_tokens": totals.provider_reported_completion_tokens,
            "mock_reported_request_count": totals.mock_reported_request_count,
            "unavailable_actual_usage_count": totals.unavailable_actual_usage_count,
            "omission_record_count": totals.omission_record_count,
            "omission_evidence_occurrence_count": (totals.omission_evidence_occurrence_count),
            "omitted_item_count": totals.omitted_item_count,
            "sampled_omitted_item_count": totals.sampled_omitted_item_count,
            "truncated_omission_record_count": totals.truncated_omission_record_count,
            "preflight_evidence_sha256s": tuple(
                sorted(
                    {
                        request.evidence_sha256
                        for request in manifest.requests
                        if isinstance(request, ContextPreflightRequestEvidence)
                    }
                )
            ),
        }
        return cls(**payload, binding_sha256=_canonical_sha256(payload))

    @model_validator(mode="after")
    def binding_is_self_hashed(self) -> ContextManifestReportBinding:
        if self.preflight_evidence_sha256s != tuple(sorted(set(self.preflight_evidence_sha256s))):
            raise ValueError("context preflight report hashes must be unique and sorted")
        _require_self_hash(self, "binding_sha256")
        return self


def build_context_manifest(
    *,
    run_id: str,
    usage_records: Sequence[UsageRecord],
    preflight_records: Sequence[ContextPreflightRequestEvidence] = (),
) -> ContextManifest:
    """Build deterministic request context evidence, rejecting missing plans."""

    provider_requests = tuple(ContextRequestEvidence.build(record) for record in usage_records)
    if any(not isinstance(record, ContextPreflightRequestEvidence) for record in preflight_records):
        raise TypeError("context preflight inventory contains invalid evidence")
    requests: tuple[ContextManifestRequestEvidence, ...] = tuple(
        sorted(
            (*provider_requests, *preflight_records),
            key=lambda request: request.request_id,
        )
    )
    request_ids = tuple(request.request_id for request in requests)
    if len(request_ids) != len(set(request_ids)):
        raise ContextManifestError("context manifest requires unique provider request IDs")
    _validate_logical_request_joins(requests)
    totals = ContextManifestTotals.build(requests)
    payload: dict[str, Any] = {
        "schema_version": "1.1",
        "generated_by": "mmaudit",
        "run_id": run_id,
        "requests": requests,
        "totals": totals,
    }
    return ContextManifest(
        schema_version="1.1",
        generated_by="mmaudit",
        run_id=run_id,
        requests=requests,
        totals=totals,
        manifest_sha256=_canonical_sha256(payload),
    )


def context_manifest_report_binding(
    manifest: ContextManifest,
) -> ContextManifestReportBinding:
    """Return the bounded report metadata projection for a context manifest."""

    return ContextManifestReportBinding.build(manifest)


def validate_context_manifest_against_usage(
    manifest: ContextManifest,
    *,
    run_id: str,
    usage_records: Sequence[UsageRecord],
    preflight_records: Sequence[ContextPreflightRequestEvidence] = (),
) -> None:
    """Rebuild semantic evidence so an independently resealed artifact still fails."""

    expected = build_context_manifest(
        run_id=run_id,
        usage_records=usage_records,
        preflight_records=preflight_records,
    )
    if manifest != expected:
        raise ContextManifestError("context manifest differs from final provider usage evidence")


def write_context_manifest(path: Path, manifest: ContextManifest) -> None:
    """Atomically write one bounded artifact through descriptor-bound directories."""

    serialized = stable_json(manifest).encode("utf-8")
    if len(serialized) > _MAX_CONTEXT_MANIFEST_BYTES:
        raise ContextManifestError("context manifest exceeds its serialized byte limit")
    parent_descriptor = -1
    temporary_descriptor = -1
    temporary_name: str | None = None
    try:
        parent_descriptor, leaf_name = _open_manifest_parent(path, create=True)
        original_metadata = _manifest_leaf_metadata(
            parent_descriptor,
            leaf_name,
            missing_ok=True,
            byte_limit=None,
        )
        temporary_descriptor, temporary_name = _create_manifest_temporary(
            parent_descriptor,
            leaf_name,
        )
        _write_descriptor(temporary_descriptor, serialized)
        os.fsync(temporary_descriptor)
        temporary_metadata = os.fstat(temporary_descriptor)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or temporary_metadata.st_nlink != 1
            or temporary_metadata.st_size != len(serialized)
        ):
            raise ContextManifestError("context manifest temporary file is not unique and regular")
        os.close(temporary_descriptor)
        temporary_descriptor = -1

        current_metadata = _manifest_leaf_metadata(
            parent_descriptor,
            leaf_name,
            missing_ok=True,
            byte_limit=None,
        )
        if _manifest_metadata_signature(current_metadata) != _manifest_metadata_signature(
            original_metadata
        ):
            raise ContextManifestError("context manifest destination changed during atomic write")
        os.replace(
            temporary_name,
            leaf_name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        os.fsync(parent_descriptor)
    except (OSError, ContextManifestError) as exc:
        if isinstance(exc, ContextManifestError):
            raise
        raise ContextManifestError("context manifest could not be written safely") from exc
    finally:
        if temporary_descriptor >= 0:
            with suppress(OSError):
                os.close(temporary_descriptor)
        if temporary_name is not None and parent_descriptor >= 0:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
        if parent_descriptor >= 0:
            with suppress(OSError):
                os.close(parent_descriptor)


def load_context_manifest(path: Path) -> ContextManifest:
    """Load bounded JSON through a stable unique descriptor and non-link parents."""

    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor, leaf_name = _open_manifest_parent(path, create=False)
        descriptor = os.open(
            leaf_name,
            _manifest_leaf_open_flags(write=False),
            dir_fd=parent_descriptor,
        )
        os.close(parent_descriptor)
        parent_descriptor = -1
        before = os.fstat(descriptor)
        _validate_manifest_metadata(before, byte_limit=_MAX_CONTEXT_MANIFEST_BYTES)
        serialized = _read_bounded_descriptor(descriptor, expected_size=before.st_size)
        after = os.fstat(descriptor)
        if (
            _manifest_metadata_signature(before) != _manifest_metadata_signature(after)
            or len(serialized) != before.st_size
        ):
            raise ContextManifestError("context manifest changed while being read")
        os.close(descriptor)
        descriptor = -1
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContextManifestError("context manifest could not be read safely") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if parent_descriptor >= 0:
            with suppress(OSError):
                os.close(parent_descriptor)
    try:
        payload = json.loads(
            serialized.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContextManifestError("context manifest is not valid bounded JSON") from exc
    if not isinstance(payload, dict):
        raise ContextManifestError("context manifest root must be an object")
    return ContextManifest.model_validate_json(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    )


def _open_manifest_parent(path: Path, *, create: bool) -> tuple[int, str]:
    """Resolve each parent relative to a non-link directory descriptor."""

    directory_flags = _manifest_directory_open_flags()
    absolute_path = Path(os.path.abspath(os.fspath(path)))
    leaf_name = absolute_path.name
    if not leaf_name:
        raise ContextManifestError("context manifest path must name a file")
    descriptor = -1
    try:
        descriptor = os.open(os.path.sep, directory_flags)
        for component in absolute_path.parent.parts:
            if component == os.path.sep:
                continue
            try:
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, leaf_name
    except ContextManifestError:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise ContextManifestError(
            "context manifest parent path is unavailable or contains a link"
        ) from exc


def _manifest_directory_open_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if (
        not isinstance(no_follow, int)
        or no_follow <= 0
        or not isinstance(directory, int)
        or directory <= 0
    ):
        raise ContextManifestError("descriptor-safe context manifest I/O is unavailable")
    return os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)


def _manifest_leaf_open_flags(*, write: bool) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int) or no_follow <= 0:
        raise ContextManifestError("descriptor-safe context manifest I/O is unavailable")
    access = os.O_WRONLY if write else os.O_RDONLY
    flags = access | no_follow | getattr(os, "O_CLOEXEC", 0)
    if not write:
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOCTTY", 0)
    return flags


def _manifest_leaf_metadata(
    parent_descriptor: int,
    leaf_name: str,
    *,
    missing_ok: bool,
    byte_limit: int | None,
) -> os.stat_result | None:
    try:
        metadata = os.stat(
            leaf_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    _validate_manifest_metadata(metadata, byte_limit=byte_limit)
    return metadata


def _validate_manifest_metadata(
    metadata: os.stat_result,
    *,
    byte_limit: int | None,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (byte_limit is not None and metadata.st_size > byte_limit)
    ):
        raise ContextManifestError(
            "context manifest must be a bounded unique non-link regular file"
        )


def _manifest_metadata_signature(
    metadata: os.stat_result | None,
) -> tuple[int, int, int, int, int, int, int] | None:
    if metadata is None:
        return None
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _create_manifest_temporary(parent_descriptor: int, leaf_name: str) -> tuple[int, str]:
    flags = _manifest_leaf_open_flags(write=True) | os.O_CREAT | os.O_EXCL
    for _attempt in range(128):
        temporary_name = f".{leaf_name}.{secrets.token_hex(16)}.tmp"
        try:
            return (
                os.open(
                    temporary_name,
                    flags,
                    0o600,
                    dir_fd=parent_descriptor,
                ),
                temporary_name,
            )
        except FileExistsError:
            continue
    raise ContextManifestError("context manifest temporary file is unavailable")


def _write_descriptor(descriptor: int, serialized: bytes) -> None:
    offset = 0
    while offset < len(serialized):
        written = os.write(descriptor, serialized[offset:])
        if written <= 0:
            raise ContextManifestError("context manifest temporary write did not progress")
        offset += written


def _read_bounded_descriptor(descriptor: int, *, expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            raise ContextManifestError("context manifest changed while being read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ContextManifestError("context manifest changed while being read")
    return b"".join(chunks)


def _request_token_plan_from_usage(usage: UsageRecord) -> RequestTokenPlan:
    # The parser lives beside usage validation to keep one authoritative routing
    # projection. getattr keeps this module importable while an older serialized
    # run is inspected, but manifest creation itself fails closed.
    from mmaudit.models import usage as usage_module

    parser = getattr(usage_module, "request_token_plan_from_usage", None)
    if not callable(parser):
        raise ContextManifestError("usage parser cannot validate request token-plan evidence")
    try:
        plan = parser(usage)
    except (TypeError, ValueError) as exc:
        raise ContextManifestError(
            "usage lacks valid request token-plan or atomic token-reservation evidence"
        ) from exc
    if not isinstance(plan, RequestTokenPlan):
        raise ContextManifestError("usage token-plan parser returned invalid evidence")
    return plan


def _atomic_token_reservations_from_usage(
    usage: UsageRecord,
    plan: RequestTokenPlan,
) -> tuple[AtomicTokenReservationEvidence, ...]:
    from mmaudit.models import usage as usage_module

    parser = getattr(usage_module, "atomic_token_reservations_from_usage", None)
    if not callable(parser):
        raise ContextManifestError("usage parser cannot validate reservation inventory")
    try:
        evidence = parser(usage, plan)
    except (TypeError, ValueError) as exc:
        raise ContextManifestError("usage reservation inventory is invalid") from exc
    if (
        not isinstance(evidence, tuple)
        or not evidence
        or any(not isinstance(item, AtomicTokenReservationEvidence) for item in evidence)
    ):
        raise ContextManifestError("usage parser returned an invalid reservation inventory")
    return evidence


def _request_state(usage: UsageRecord) -> ContextRequestState:
    if usage.status == "success" and usage.validation_status is ModelRequestValidationStatus.VALID:
        return ContextRequestState.COMPLETED
    if usage.validation_status is ModelRequestValidationStatus.TRUNCATED:
        return ContextRequestState.TRUNCATED
    return ContextRequestState.SENT_FAILED


def _actual_usage_source(usage: UsageRecord) -> ActualTokenUsageSource:
    if usage.prompt_tokens <= 0 and usage.completion_tokens <= 0:
        return ActualTokenUsageSource.UNAVAILABLE
    if usage.execution_evidence is ExecutionEvidenceKind.REAL:
        return ActualTokenUsageSource.PROVIDER_RESPONSE
    if usage.execution_evidence is ExecutionEvidenceKind.MOCK:
        return ActualTokenUsageSource.MOCK_RESPONSE
    return ActualTokenUsageSource.UNAVAILABLE


def _context_totals_payload(
    requests: Sequence[ContextManifestRequestEvidence],
) -> dict[str, Any]:
    _validate_logical_request_joins(requests)
    request_plans = [
        request.request_plan for request in requests if request.request_plan is not None
    ]
    category_totals: list[ContextCategoryTotals] = []
    for category in PROMPT_ALLOCATION_CATEGORIES:
        allocations = [
            allocation
            for request_plan in request_plans
            for allocation in request_plan.allocations
            if allocation.category is category
        ]
        category_totals.append(
            ContextCategoryTotals(
                category=category,
                request_count=len(allocations),
                utf8_bytes=sum(allocation.estimate.utf8_bytes for allocation in allocations),
                estimated_tokens=sum(
                    allocation.estimate.estimated_tokens for allocation in allocations
                ),
                byte_upper_bound_tokens=sum(
                    allocation.estimate.byte_upper_bound_tokens for allocation in allocations
                ),
            )
        )
    provider_usage = [
        request.actual_usage
        for request in requests
        if isinstance(request, ContextRequestEvidence)
        and request.actual_usage.source is ActualTokenUsageSource.PROVIDER_RESPONSE
    ]
    mock_usage = [
        request.actual_usage
        for request in requests
        if isinstance(request, ContextRequestEvidence)
        and request.actual_usage.source is ActualTokenUsageSource.MOCK_RESPONSE
    ]
    unavailable = [
        request.actual_usage
        for request in requests
        if isinstance(request, ContextRequestEvidence)
        and request.actual_usage.source is ActualTokenUsageSource.UNAVAILABLE
    ]
    unavailable_count = len(unavailable) + sum(
        isinstance(request, ContextPreflightRequestEvidence) for request in requests
    )
    states = [request.request_state for request in requests]
    (
        unique_omission_record_count,
        omission_evidence_occurrence_count,
        unique_context_omissions,
    ) = _context_omission_inventory(requests)
    provider_requests = [
        request for request in requests if isinstance(request, ContextRequestEvidence)
    ]
    reservation_inventory = [
        reservation
        for request in provider_requests
        for reservation in request.atomic_token_reservations
    ]
    return {
        "request_count": len(requests),
        "planned_request_count": len(request_plans),
        "completed_request_count": states.count(ContextRequestState.COMPLETED),
        "truncated_request_count": states.count(ContextRequestState.TRUNCATED),
        "failed_request_count": states.count(ContextRequestState.SENT_FAILED),
        "preflight_rejected_request_count": states.count(ContextRequestState.PRE_FLIGHT_REJECTED),
        "not_sent_request_count": states.count(ContextRequestState.NOT_SENT),
        "planned_prompt_tokens": sum(
            request_plan.estimated_prompt_tokens for request_plan in request_plans
        ),
        "planned_source_tokens": sum(
            allocation.estimate.estimated_tokens
            for request_plan in request_plans
            for allocation in request_plan.allocations
            if allocation.category is PromptAllocationCategory.SOURCE
        ),
        "reserved_output_tokens": sum(
            request_plan.reserved_output_tokens for request_plan in request_plans
        ),
        "reserved_reasoning_tokens": sum(
            request_plan.reserved_reasoning_tokens for request_plan in request_plans
        ),
        "requested_completion_tokens": sum(
            request_plan.requested_completion_tokens for request_plan in request_plans
        ),
        "provider_attempt_count": sum(request.provider_attempts for request in provider_requests),
        "atomic_reservation_count": len(reservation_inventory),
        "attempt_reserved_prompt_tokens": sum(
            reservation.planned_prompt_tokens for reservation in reservation_inventory
        ),
        "attempt_reserved_completion_tokens": sum(
            reservation.planned_completion_tokens for reservation in reservation_inventory
        ),
        "provider_reported_request_count": len(provider_usage),
        "provider_reported_prompt_tokens": _sum_actual_tokens(provider_usage, "prompt_tokens"),
        "provider_reported_completion_tokens": _sum_actual_tokens(
            provider_usage,
            "completion_tokens",
        ),
        "mock_reported_request_count": len(mock_usage),
        "mock_reported_prompt_tokens": _sum_actual_tokens(mock_usage, "prompt_tokens"),
        "mock_reported_completion_tokens": _sum_actual_tokens(
            mock_usage,
            "completion_tokens",
        ),
        "unavailable_actual_usage_count": unavailable_count,
        "omission_record_count": unique_omission_record_count,
        "omission_evidence_occurrence_count": omission_evidence_occurrence_count,
        "omitted_item_count": sum(
            omission.omitted_item_count for omission in unique_context_omissions
        ),
        "sampled_omitted_item_count": sum(
            len(omission.sampled_item_sha256s) for omission in unique_context_omissions
        ),
        "truncated_omission_record_count": sum(
            omission.samples_truncated for omission in unique_context_omissions
        ),
        "categories": tuple(category_totals),
    }


def _validate_logical_request_joins(
    requests: Sequence[ContextManifestRequestEvidence],
) -> None:
    logical_requests: dict[str, list[ContextManifestRequestEvidence]] = {}
    for request in requests:
        logical_request_id = (
            request.request_id
            if isinstance(request, ContextRequestEvidence)
            else request.logical_request_id
        )
        logical_requests.setdefault(logical_request_id, []).append(request)

    for joined_requests in logical_requests.values():
        if len(joined_requests) < 2:
            continue
        expected = joined_requests[0]
        expected_plan = expected.request_plan
        if expected_plan is None or any(
            request.request_plan is None
            or request.role != expected.role
            or request.requested_model != expected.requested_model
            or request.request_plan != expected_plan
            for request in joined_requests[1:]
        ):
            raise ContextManifestError("context records differ from their logical request plan")


def _context_omission_inventory(
    requests: Sequence[ContextManifestRequestEvidence],
) -> tuple[int, int, tuple[ContextOmissionItem, ...]]:
    """Return unique logical inventories plus the raw evidence occurrence count."""

    unique_records: set[tuple[str, str, str]] = set()
    unique_context_omissions: dict[tuple[str, str], ContextOmissionItem] = {}
    occurrence_count = 0
    for request in requests:
        if isinstance(request, ContextRequestEvidence):
            logical_request_id = request.request_id
            for omission in request.omissions:
                occurrence_count += 1
                if omission.provenance is ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE:
                    item = _context_omission_item_from_evidence(omission)
                    key = (logical_request_id, item.evidence_sha256)
                    unique_records.add((logical_request_id, "HASHED_CONTEXT_PACKAGE", key[1]))
                    existing = unique_context_omissions.setdefault(key, item)
                    if existing != item:
                        raise ContextManifestError(
                            "context omission commitment collision is inconsistent"
                        )
                else:
                    unique_records.add(
                        (
                            logical_request_id,
                            omission.provenance.value,
                            omission.evidence_sha256,
                        )
                    )
            continue
        for item in _preflight_context_omissions(request):
            occurrence_count += 1
            key = (request.logical_request_id, item.evidence_sha256)
            unique_records.add((request.logical_request_id, "HASHED_CONTEXT_PACKAGE", key[1]))
            existing = unique_context_omissions.setdefault(key, item)
            if existing != item:
                raise ContextManifestError("context omission commitment collision is inconsistent")
    return (
        len(unique_records),
        occurrence_count,
        tuple(unique_context_omissions.values()),
    )


def _sum_actual_tokens(
    evidence: Sequence[ActualTokenUsageEvidence],
    field: Literal["prompt_tokens", "completion_tokens"],
) -> int:
    return sum(getattr(item, field) or 0 for item in evidence)


def _omission_sort_key(
    omission: ContextOmissionEvidence,
) -> tuple[str, str]:
    return omission.category.value, omission.reason.value


def _context_omission_item_from_evidence(
    omission: ContextOmissionEvidence,
) -> ContextOmissionItem:
    if (
        omission.provenance is not ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE
        or omission.inventory_commitment_method is None
        or omission.inventory_sha256 is None
        or omission.context_omission_evidence_sha256 is None
    ):
        raise ValueError("context omission evidence is not a hashed context aggregate")
    return ContextOmissionItem(
        schema_version="1.1",
        category=omission.category,
        reason=omission.reason,
        inventory_commitment_method=omission.inventory_commitment_method,
        omitted_item_sha256=omission.inventory_sha256,
        omitted_item_count=omission.omitted_item_count,
        sampled_item_sha256s=omission.omitted_item_sha256s,
        samples_truncated=omission.samples_truncated,
        evidence_sha256=omission.context_omission_evidence_sha256,
    )


def _preflight_context_omissions(
    request: ContextPreflightRequestEvidence,
) -> tuple[ContextOmissionItem, ...]:
    if request.request_plan is not None:
        return request.request_plan.context_omissions
    if request.planning_snapshot is not None:
        return request.planning_snapshot.context_omissions
    return ()


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
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContextManifestError("context manifest contains duplicate JSON keys")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ContextManifestError(f"context manifest contains non-finite value: {value}")


__all__ = [
    "ActualTokenUsageEvidence",
    "ActualTokenUsageSource",
    "ContextCategoryTotals",
    "ContextManifest",
    "ContextManifestError",
    "ContextManifestReportBinding",
    "ContextManifestRequestEvidence",
    "ContextManifestTotals",
    "ContextOmissionCategory",
    "ContextOmissionEvidence",
    "ContextOmissionProvenance",
    "ContextOmissionReason",
    "ContextPreflightLedger",
    "ContextPreflightReason",
    "ContextPreflightRequestEvidence",
    "ContextPreflightSource",
    "ContextRequestEvidence",
    "ContextRequestState",
    "OmissionTokenEstimationState",
    "build_context_manifest",
    "context_manifest_report_binding",
    "load_context_manifest",
    "validate_context_manifest_against_usage",
    "write_context_manifest",
]
