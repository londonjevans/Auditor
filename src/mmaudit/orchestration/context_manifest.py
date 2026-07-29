"""Hash-only context-planning and provider-usage evidence for one audit run."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Sequence
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
    PROMPT_ALLOCATION_CATEGORIES,
    PromptAllocationCategory,
    RequestTokenPlan,
)
from mmaudit.orchestration.budgets import AtomicTokenReservationEvidence
from mmaudit.reporting.json_report import write_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_RE = re.compile(_SHA256_PATTERN)
_REQUEST_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_ROLE_PATTERN = r"^[a-z][a-z0-9_:.-]{0,127}$"
_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_MAX_CONTEXT_MANIFEST_BYTES = 100_000_000
_MAX_CONTEXT_REQUESTS = 100_000
_MAX_OMISSIONS_PER_REQUEST = 100_000


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


class ContextOmissionCategory(StrEnum):
    """Typed omission scope without retaining source names or text."""

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
    """Host-defined non-operational reason for withholding context."""

    BLIND_DISCOVERY_WITHHELD = "BLIND_DISCOVERY_WITHHELD"
    CONTEXT_BUDGET_EXCLUDED = "CONTEXT_BUDGET_EXCLUDED"


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


class ContextOmissionEvidence(FrozenContextEvidence):
    """Hash-only inventory for one typed omission class."""

    schema_version: Literal["1.0"] = "1.0"
    category: ContextOmissionCategory
    reason: ContextOmissionReason
    provenance: ContextOmissionProvenance
    omitted_item_sha256s: tuple[str, ...] = Field(max_length=_MAX_OMISSIONS_PER_REQUEST)
    omitted_item_count: int = Field(ge=0, le=_MAX_OMISSIONS_PER_REQUEST)
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
        omitted_item_sha256s: Sequence[str] = (),
    ) -> Self:
        ordered = tuple(sorted(omitted_item_sha256s))
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "category": category,
            "reason": reason,
            "provenance": provenance,
            "omitted_item_sha256s": ordered,
            "omitted_item_count": len(ordered),
            "token_estimation_state": OmissionTokenEstimationState.NOT_ESTIMATED,
            "estimated_tokens": None,
        }
        return cls(
            schema_version="1.0",
            category=category,
            reason=reason,
            provenance=provenance,
            omitted_item_sha256s=ordered,
            omitted_item_count=len(ordered),
            token_estimation_state=OmissionTokenEstimationState.NOT_ESTIMATED,
            estimated_tokens=None,
            evidence_sha256=_canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def omission_is_canonical_and_self_hashed(self) -> ContextOmissionEvidence:
        if self.omitted_item_sha256s != tuple(sorted(set(self.omitted_item_sha256s))):
            raise ValueError("context omission hashes must be unique and sorted")
        if any(_SHA256_RE.fullmatch(value) is None for value in self.omitted_item_sha256s):
            raise ValueError("context omission inventory contains a non-SHA-256 value")
        if self.omitted_item_count != len(self.omitted_item_sha256s):
            raise ValueError("context omission count differs from its hash inventory")
        if self.reason is ContextOmissionReason.BLIND_DISCOVERY_WITHHELD:
            if (
                self.category is not ContextOmissionCategory.PRIOR_AUDIT
                or self.provenance is not ContextOmissionProvenance.BLIND_DISCOVERY_POLICY
                or self.omitted_item_sha256s
            ):
                raise ValueError("blind-discovery omission evidence is inconsistent")
        elif (
            self.category is not ContextOmissionCategory.CONTEXT_PACKAGE
            or self.provenance is not ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE
            or not self.omitted_item_sha256s
        ):
            raise ValueError("context-package omission evidence is inconsistent")
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
        max_length=2,
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
        omission_hashes = plan.context_omission_sha256s
        omissions = [
            ContextOmissionEvidence.build(
                category=ContextOmissionCategory.PRIOR_AUDIT,
                reason=ContextOmissionReason.BLIND_DISCOVERY_WITHHELD,
                provenance=ContextOmissionProvenance.BLIND_DISCOVERY_POLICY,
            )
        ]
        if omission_hashes:
            omissions.append(
                ContextOmissionEvidence.build(
                    category=ContextOmissionCategory.CONTEXT_PACKAGE,
                    reason=ContextOmissionReason.CONTEXT_BUDGET_EXCLUDED,
                    provenance=ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE,
                    omitted_item_sha256s=omission_hashes,
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
        if self.request_plan is not None and (
            self.request_plan.request_id != self.logical_request_id
            or self.request_plan.role != self.role
            or self.requested_model not in self.request_plan.route_intersection.exact_model_ids
            or self.request_plan.plan_sha256 != self.request_plan_sha256
            or self.request_plan.estimated_prompt_tokens != self.estimated_prompt_tokens
            or self.request_plan.requested_completion_tokens != self.requested_completion_tokens
        ):
            raise ValueError("preflight evidence differs from its request token plan")
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
    omitted_item_count: int = Field(ge=0)
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
        _require_self_hash(self, "totals_sha256")
        return self


class ContextManifest(FrozenContextEvidence):
    """Self-hashed deterministic context evidence for one complete run."""

    schema_version: Literal["1.0"] = "1.0"
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
        if self.totals != ContextManifestTotals.build(self.requests):
            raise ValueError("context manifest totals differ from its request evidence")
        _require_self_hash(self, "manifest_sha256")
        return self


class ContextManifestReportBinding(FrozenContextEvidence):
    """Small report projection binding client evidence to the forensic artifact."""

    schema_version: Literal["1.0"] = "1.0"
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
    omitted_item_count: int = Field(ge=0)
    preflight_evidence_sha256s: tuple[str, ...] = Field(max_length=_MAX_CONTEXT_REQUESTS)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(cls, manifest: ContextManifest) -> Self:
        totals = manifest.totals
        payload: dict[str, Any] = {
            "schema_version": "1.0",
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
            "omitted_item_count": totals.omitted_item_count,
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
    totals = ContextManifestTotals.build(requests)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "run_id": run_id,
        "requests": requests,
        "totals": totals,
    }
    return ContextManifest(
        schema_version="1.0",
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
    """Write one typed artifact without following a destination link."""

    if path.is_symlink() or path.is_junction():
        raise ContextManifestError("context manifest destination may not be a link")
    write_json(path, manifest)


def load_context_manifest(path: Path) -> ContextManifest:
    """Load one bounded unique non-link manifest with duplicate-key rejection."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ContextManifestError("context manifest is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or path.is_junction()
        or metadata.st_nlink != 1
        or metadata.st_size > _MAX_CONTEXT_MANIFEST_BYTES
    ):
        raise ContextManifestError("context manifest must be a bounded unique regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContextManifestError("context manifest could not be opened safely") from exc
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            payload = json.load(
                handle,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_nonfinite,
            )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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
    omissions = [
        omission
        for request in requests
        if isinstance(request, ContextRequestEvidence)
        for omission in request.omissions
    ]
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
        "omission_record_count": len(omissions),
        "omitted_item_count": sum(omission.omitted_item_count for omission in omissions),
        "categories": tuple(category_totals),
    }


def _sum_actual_tokens(
    evidence: Sequence[ActualTokenUsageEvidence],
    field: Literal["prompt_tokens", "completion_tokens"],
) -> int:
    return sum(getattr(item, field) or 0 for item in evidence)


def _omission_sort_key(
    omission: ContextOmissionEvidence,
) -> tuple[str, str, str]:
    return omission.category.value, omission.reason.value, omission.evidence_sha256


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
