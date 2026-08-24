"""Fail-closed evidence for closing one truncated candidate-review surface set.

The models in this module are durable comparison evidence.  They do not dispatch a
provider request, turn a truncated request into a successful ``UsageRecord``, or
authorize scheduler/release state.  A future scheduler boundary may grant the narrow
ability to record surface closure only after exact runtime/journal custody exists.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from enum import StrEnum
from itertools import islice
from typing import Annotated, Any, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReviewBatch,
    ContextRequestEvidence,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    StrictModel,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewFramePhase,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_batch_schema_sha256,
    candidate_review_frame_wire_schema_sha256,
)
from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TRUNCATION_RECOVERY_MAX_USD_EXACT,
    TruncationRecoveryChannel,
    TruncationRecoveryChildPlan,
    TruncationRecoveryDisposition,
    TruncationRecoveryPlan,
)
from mmaudit.models.truncation_recovery_journal import (
    rebuild_truncation_recovery_parent_from_projection,
)
from mmaudit.models.usage import (
    atomic_request_limit_reservations_from_usage,
    is_structurally_accountable_usage_record,
    is_structurally_recovery_accountable_usage_record,
    is_structurally_recovery_creditable_usage_record,
)

TRUNCATION_CLOSURE_ALGORITHM_VERSION: Final = "mmaudit.truncation-closure.v1"
TRUNCATION_RECURSIVE_CLOSURE_ALGORITHM_VERSION: Final = "mmaudit.truncation-recursive-closure.v1"
MAX_TRUNCATION_CLOSURE_SURFACES: Final = 10_000
MAX_TRUNCATION_CLOSURE_ATTEMPTS: Final = 200

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SURFACE_ID_PATTERN = r"^model-surface:[0-9a-f]{64}$"
_TASK_ID_PATTERN = r"^(?:scheduler-task|scheduler-recovery-task)-[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = r"^(?:scheduler-request|scheduler-recovery-request)-[0-9a-f]{64}$"
_ROOT_REQUEST_ID_PATTERN = r"^scheduler-request-[0-9a-f]{64}$"
_USD_PATTERN = r"^(?:0|[1-9][0-9]{0,12})(?:\.[0-9]{1,36})?$"
_EXACT_DECIMAL_CONTEXT = Context(
    prec=200,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[InvalidOperation, DivisionByZero, Overflow],
)
_INVARIANT_ROUTING_KEYS: tuple[str, ...] = (
    "privacy_profile",
    "privacy_authorization",
    "privacy_source_sha256",
    "effective_privacy_policy_sha256",
    "privacy_source_provenance_sha256",
    "privacy_source_classification",
    "privacy_source_proof_kind",
    "privacy_consent_file_sha256",
    "privacy_consent_sha256",
    "privacy_consent_expires_at",
    "privacy_endpoint_policy_class",
    "zdr_requested",
    "data_collection",
    "provider_policy_sha256",
    "audit_model_selection_bundle_sha256",
    "audit_selection_sha256",
    "audit_selected_model_set_sha256",
    "audit_scope_sha256",
    "audit_source_sha256",
    "audit_policy_routing_evidence_sha256",
    "audit_model_refresh_evidence_sha256",
    "audit_model_refresh_guard_capability_sha256",
    "audit_model_refresh_route_evidence_sha256",
    "audit_model_refresh_audit_route_set_sha256",
    "audit_model_refresh_technical_route_set_sha256",
    "audit_model_refresh_pricing_evidence_sha256",
    "audit_model_refresh_pricing_authority_capability_sha256",
    "audit_model_refresh_pricing_route_evidence_sha256",
    "audit_model_refresh_pricing_qualified_pricing_snapshot_sha256",
    "audit_model_refresh_pricing_current_pricing_snapshot_sha256",
)


class TruncationClosureError(ValueError):
    """Raised when comparison evidence cannot close an exact surface set."""


class TruncationSurfaceOriginKind(StrEnum):
    """The only two admissible origins for an aggregated surface record."""

    PARENT_PROVISIONAL = "PARENT_PROVISIONAL"
    CHILD_COMPLETE = "CHILD_COMPLETE"


class TruncationNoncompletionState(StrEnum):
    """Terminal family states that can never grant review or completion credit."""

    INCOMPLETE = "INCOMPLETE"
    UNCERTAIN = "UNCERTAIN"
    INVALID = "INVALID"
    EXHAUSTED = "EXHAUSTED"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class _NonAuthorizingModel(_FrozenStrictModel):
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    provider_dispatch_authorized: Literal[False] = False
    review_credit_authorized: Literal[False] = False
    coverage_credit_authorized: Literal[False] = False
    completion_authorized: Literal[False] = False
    release_authorized: Literal[False] = False


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Decimal):
        return format(value, "f")
    raise TypeError(f"unsupported truncation-closure hash value: {type(value).__qualname__}")


def _model_sha256(model: BaseModel, *, exclude: set[str]) -> str:
    return _canonical_sha256(model.model_dump(mode="json", exclude=exclude))


def _exact_model[ModelT: BaseModel](value: ModelT, expected: type[ModelT]) -> ModelT:
    if type(value) is not expected:
        raise TruncationClosureError(
            f"truncation closure requires exact {expected.__qualname__} evidence"
        )
    try:
        with localcontext(_EXACT_DECIMAL_CONTEXT):
            return expected.model_validate(value.model_dump(mode="python"), strict=True)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TruncationClosureError(
            "truncation closure evidence failed strict reconstruction"
        ) from exc


def _bounded_tuple[ItemT](
    values: Iterable[ItemT],
    *,
    limit: int,
    label: str,
) -> tuple[ItemT, ...]:
    try:
        result = tuple(islice(iter(values), limit + 1))
    except (TypeError, ValueError) as exc:
        raise TruncationClosureError(f"truncation closure {label} is not iterable") from exc
    if len(result) > limit:
        raise TruncationClosureError(f"truncation closure {label} exceeds its item limit")
    return result


def _decimal(value: str, *, label: str) -> Decimal:
    if type(value) is not str or re.fullmatch(_USD_PATTERN, value) is None:
        raise TruncationClosureError(f"truncation closure {label} is not canonical USD text")
    try:
        amount = _EXACT_DECIMAL_CONTEXT.create_decimal(value)
    except InvalidOperation:
        raise TruncationClosureError(f"truncation closure {label} is invalid") from None
    if not amount.is_finite() or amount < 0 or _decimal_text(amount) != value:
        raise TruncationClosureError(f"truncation closure {label} is not canonical USD text")
    return amount


def _usage_decimal(value: str, *, label: str) -> Decimal:
    """Parse bounded provider cost text without rewriting its attested representation."""
    if type(value) is not str or re.fullmatch(_USD_PATTERN, value) is None:
        raise TruncationClosureError(f"truncation closure {label} is not bounded USD text")
    try:
        amount = _EXACT_DECIMAL_CONTEXT.create_decimal(value)
    except InvalidOperation:
        raise TruncationClosureError(f"truncation closure {label} is invalid") from None
    if not amount.is_finite() or amount < 0:
        raise TruncationClosureError(f"truncation closure {label} is not bounded USD text")
    return amount


def _decimal_text(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return "0" if rendered in {"", "-0"} else rendered


def _exact_sum(values: Iterable[Decimal]) -> Decimal:
    context = _EXACT_DECIMAL_CONTEXT.copy()
    total = context.create_decimal(0)
    for value in values:
        total = context.add(total, value)
    return total


def _usage_context(usage: UsageRecord) -> ContextRequestEvidence:
    raw = usage.routing.get("context_request_evidence")
    if not isinstance(raw, dict):
        raise TruncationClosureError("truncation closure usage lacks typed context evidence")
    try:
        context = ContextRequestEvidence.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError) as exc:
        raise TruncationClosureError("truncation closure context evidence is invalid") from exc
    if (
        context.request_id != usage.request_id
        or context.request_role != usage.role
        or usage.routing.get("context_request_evidence_sha256") != context.evidence_sha256
        or usage.user_prompt_sha256 != context.rendered_sha256
    ):
        raise TruncationClosureError("truncation closure context evidence differs from usage")
    return context


def _routing_invariant_sha256(usage: UsageRecord) -> str:
    return _canonical_sha256(
        {
            "domain": "mmaudit.truncation-closure.routing-invariant.v1",
            "values": {key: usage.routing.get(key) for key in _INVARIANT_ROUTING_KEYS},
        }
    )


def _record_sha256(record: ModelSurfaceReviewRecord) -> str:
    return _canonical_sha256(record.model_dump(mode="json"))


def _truncated_envelope_routing(
    envelope: CandidateReviewTruncatedEnvelopeEvidence,
) -> dict[str, Any]:
    """Rebuild the complete raw-free envelope inventory retained by OpenRouter."""

    return {
        "candidate_review_truncated_envelope_evidence": envelope.model_dump(mode="json"),
        "candidate_review_truncated_envelope_sha256": envelope.evidence_sha256,
    }


def _truncation_projection_routing(
    projection: CandidateReviewTruncationProjection,
) -> dict[str, Any]:
    """Rebuild the bounded, non-record projection retained by failed usage."""

    return {
        "candidate_review_truncation_projection_sha256": projection.evidence_sha256,
        "candidate_review_truncation_termination": projection.termination.value,
        "candidate_review_truncation_findings_state": projection.findings_state.value,
        "candidate_review_truncation_surface_reviews_state": (
            projection.surface_reviews_state.value
        ),
        "candidate_review_truncation_summary_state": projection.summary_state.value,
        "candidate_review_truncation_stream_integrity_valid": (projection.stream_integrity_valid),
        "candidate_review_truncation_document_complete": projection.document_complete,
        "candidate_review_truncation_declared_finding_count": (projection.declared_finding_count),
        "candidate_review_truncation_declared_surface_review_count": (
            projection.declared_surface_review_count
        ),
        "candidate_review_truncation_observed_frame_count": projection.observed_frame_count,
        "candidate_review_truncation_observed_finding_frame_count": (
            projection.observed_finding_frame_count
        ),
        "candidate_review_truncation_observed_surface_review_frame_count": (
            projection.observed_surface_review_frame_count
        ),
        "candidate_review_truncation_accepted_frame_count": len(projection.accepted_frames),
        "candidate_review_truncation_accepted_finding_count": (projection.accepted_finding_count),
        "candidate_review_truncation_accepted_surface_review_count": (
            projection.accepted_surface_review_count
        ),
        "candidate_review_truncation_invalid_frame_count": projection.invalid_frame_count,
        "candidate_review_truncation_credit_eligible": False,
        "candidate_review_truncation_authority_eligible": False,
    }


def _finding_inventory(findings: Sequence[CandidateFinding]) -> tuple[tuple[str, str], ...]:
    pairs = tuple(
        sorted(
            (
                finding.candidate_id,
                _canonical_sha256(finding.model_dump(mode="json")),
            )
            for finding in findings
        )
    )
    if len(pairs) != len({identifier for identifier, _digest in pairs}):
        raise TruncationClosureError("truncation closure provisional finding IDs are ambiguous")
    return pairs


class TruncationRecoveryInvariantBinding(_NonAuthorizingModel):
    """Fields that must not drift while the requested surface set is resharded."""

    schema_version: Literal["1.0"] = "1.0"
    review_role: str = Field(min_length=1, max_length=200)
    context_role: str = Field(min_length=1, max_length=200)
    requested_model: str = Field(min_length=1, max_length=500)
    selected_model: str = Field(min_length=1, max_length=500)
    response_provider: str = Field(min_length=1, max_length=500)
    selected_provider_endpoint: str = Field(min_length=1, max_length=500)
    selected_provider_identity: str = Field(min_length=1, max_length=500)
    model_family: str = Field(min_length=1, max_length=500)
    wire_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalized_batch_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    routing_invariant_sha256: str = Field(pattern=_SHA256_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def schemas_and_hash_are_exact(self) -> Self:
        if (
            self.wire_schema_sha256 != candidate_review_frame_wire_schema_sha256()
            or self.normalized_batch_schema_sha256 != candidate_review_batch_schema_sha256()
        ):
            raise ValueError("truncation closure invariant schema hashes are inconsistent")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("truncation closure invariant binding hash is inconsistent")
        return self


class TruncationRecoveryParentAttemptEvidence(_NonAuthorizingModel):
    """Exact non-creditable parent usage plus its retained parser projection."""

    schema_version: Literal["1.0"] = "1.0"
    parent_task_id: str = Field(pattern=_TASK_ID_PATTERN)
    parent_logical_request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    parent_activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    usage_record: UsageRecord
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    envelope: CandidateReviewTruncatedEnvelopeEvidence
    projection: CandidateReviewTruncationProjection
    retained_surface_ids: tuple[str, ...] = Field(max_length=MAX_TRUNCATION_CLOSURE_SURFACES)
    retained_surface_record_sha256s: tuple[str, ...] = Field(
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES
    )
    provisional_finding_ids: tuple[str, ...] = Field(max_length=1_000)
    provisional_finding_sha256s: tuple[str, ...] = Field(max_length=1_000)
    provisional_findings_credit_eligible: Literal[False] = False
    summary_credit_eligible: Literal[False] = False
    parent_attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        parent_task_id: str,
        parent_activation_sha256: str,
        provider_attempt_evidence_sha256: str,
        usage_record: UsageRecord,
        envelope: CandidateReviewTruncatedEnvelopeEvidence,
        projection: CandidateReviewTruncationProjection,
    ) -> TruncationRecoveryParentAttemptEvidence:
        usage = _exact_model(usage_record, UsageRecord)
        exact_envelope = _exact_model(envelope, CandidateReviewTruncatedEnvelopeEvidence)
        exact_projection = _exact_model(projection, CandidateReviewTruncationProjection)
        surfaces = tuple(review.surface_id for review in exact_projection.surface_reviews)
        surface_hashes = tuple(
            _record_sha256(review) for review in exact_projection.surface_reviews
        )
        findings = _finding_inventory(exact_projection.findings)
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "parent_task_id": parent_task_id,
            "parent_logical_request_id": usage.request_id,
            "parent_activation_sha256": parent_activation_sha256,
            "provider_attempt_evidence_sha256": provider_attempt_evidence_sha256,
            "usage_record": usage,
            "usage_record_sha256": _canonical_sha256(usage.model_dump(mode="json")),
            "envelope": exact_envelope,
            "projection": exact_projection,
            "retained_surface_ids": surfaces,
            "retained_surface_record_sha256s": surface_hashes,
            "provisional_finding_ids": tuple(item[0] for item in findings),
            "provisional_finding_sha256s": tuple(item[1] for item in findings),
            "provisional_findings_credit_eligible": False,
            "summary_credit_eligible": False,
        }
        return cls(**values, parent_attempt_evidence_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def parent_is_exact_noncreditable_truncation(self) -> Self:
        usage = self.usage_record
        context = _usage_context(usage)
        envelope_routing = _truncated_envelope_routing(self.envelope)
        projection_routing = _truncation_projection_routing(self.projection)
        actual_envelope_keys = {
            key for key in usage.routing if key.startswith("candidate_review_truncated_")
        }
        actual_projection_keys = {
            key for key in usage.routing if key.startswith("candidate_review_truncation_")
        }
        if not is_structurally_accountable_usage_record(usage):
            raise ValueError("truncation parent usage is not structurally accountable")
        if (
            usage.request_id != self.parent_logical_request_id
            or usage.request_id != self.envelope.logical_request_id
            or usage.validation_status is not ModelRequestValidationStatus.TRUNCATED
            or usage.identity_strength is not ModelIdentityStrength.UNBOUND
            or usage.status != "rejected_truncated_response"
            or usage.validated_response_sha256 is not None
            or usage.response_sha256 != self.projection.original_response_sha256
            or usage.response_sha256 != self.envelope.response_sha256
            or usage.schema_sha256 != candidate_review_frame_wire_schema_sha256()
            or usage.schema_sha256 != self.projection.wire_schema_sha256
            or usage.finish_reason != self.projection.finish_reason
            or usage.finish_reason != self.envelope.finish_reason
            or self.projection.native_finish_reason != self.envelope.native_finish_reason
            or usage.requested_model != self.envelope.requested_model
            or usage.returned_model != self.envelope.returned_model
            or usage.actual_model != self.envelope.selected_model
            or usage.provider != self.envelope.selected_provider_name
            or usage.openrouter_generation_id != self.envelope.generation_id
            or usage.actual_provider_endpoint != self.envelope.selected_provider_endpoint
            or usage.routing.get("generation_id") != self.envelope.generation_id
            or usage.routing.get("generation_header_id") != self.envelope.generation_header_id
            or usage.routing.get("provider") != self.envelope.response_provider_identity
            or usage.routing.get("finish_reason") != self.envelope.finish_reason
            or usage.routing.get("native_finish_reason") != self.envelope.native_finish_reason
            or usage.routing.get("schema_sha256") != self.envelope.wire_schema_sha256
            or usage.routing.get("router_metadata_sha256") != self.envelope.router_metadata_sha256
            or actual_envelope_keys != set(envelope_routing)
            or any(usage.routing.get(key) != value for key, value in envelope_routing.items())
            or actual_projection_keys != set(projection_routing)
            or any(usage.routing.get(key) != value for key, value in projection_routing.items())
            or context.request_id != self.parent_logical_request_id
        ):
            raise ValueError("truncation parent usage differs from its envelope or projection")
        surface_ids = tuple(review.surface_id for review in self.projection.surface_reviews)
        surface_hashes = tuple(_record_sha256(review) for review in self.projection.surface_reviews)
        findings = _finding_inventory(self.projection.findings)
        if (
            self.retained_surface_ids != surface_ids
            or self.retained_surface_ids != tuple(sorted(set(self.retained_surface_ids)))
            or self.retained_surface_record_sha256s != surface_hashes
            or self.provisional_finding_ids != tuple(item[0] for item in findings)
            or self.provisional_finding_sha256s != tuple(item[1] for item in findings)
            or self.usage_record_sha256
            != _canonical_sha256(self.usage_record.model_dump(mode="json"))
            or self.parent_attempt_evidence_sha256
            != _model_sha256(self, exclude={"parent_attempt_evidence_sha256"})
        ):
            raise ValueError("truncation parent retained inventory is inconsistent")
        return self


class TruncationRecoveryBridgeAttemptEvidence(_NonAuthorizingModel):
    """Exact zero-retained truncated recovery child that parents one nested family."""

    schema_version: Literal["1.0"] = "1.0"
    child_plan: TruncationRecoveryChildPlan
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    analysis_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_limit_scope: str = Field(pattern=_ROOT_REQUEST_ID_PATTERN)
    request_limit_count_before: int = Field(ge=1, le=1_000_000)
    usage_record: UsageRecord
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    envelope: CandidateReviewTruncatedEnvelopeEvidence
    projection: CandidateReviewTruncationProjection
    retained_surface_ids: tuple[()] = ()
    retained_surface_record_sha256s: tuple[()] = ()
    provisional_finding_ids: tuple[str, ...] = Field(max_length=1_000)
    provisional_finding_sha256s: tuple[str, ...] = Field(max_length=1_000)
    provisional_findings_credit_eligible: Literal[False] = False
    summary_credit_eligible: Literal[False] = False
    bridge_attempt_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        child_plan: TruncationRecoveryChildPlan,
        activation_sha256: str,
        provider_attempt_evidence_sha256: str,
        analysis_context_sha256: str,
        request_limit_scope: str,
        request_limit_count_before: int,
        usage_record: UsageRecord,
        envelope: CandidateReviewTruncatedEnvelopeEvidence,
        projection: CandidateReviewTruncationProjection,
    ) -> TruncationRecoveryBridgeAttemptEvidence:
        plan = _exact_model(child_plan, TruncationRecoveryChildPlan)
        usage = _exact_model(usage_record, UsageRecord)
        exact_envelope = _exact_model(envelope, CandidateReviewTruncatedEnvelopeEvidence)
        exact_projection = _exact_model(projection, CandidateReviewTruncationProjection)
        findings = _finding_inventory(exact_projection.findings)
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "child_plan": plan,
            "activation_sha256": activation_sha256,
            "provider_attempt_evidence_sha256": provider_attempt_evidence_sha256,
            "analysis_context_sha256": analysis_context_sha256,
            "request_limit_scope": request_limit_scope,
            "request_limit_count_before": request_limit_count_before,
            "usage_record": usage,
            "usage_record_sha256": _canonical_sha256(usage.model_dump(mode="json")),
            "envelope": exact_envelope,
            "projection": exact_projection,
            "retained_surface_ids": (),
            "retained_surface_record_sha256s": (),
            "provisional_finding_ids": tuple(item[0] for item in findings),
            "provisional_finding_sha256s": tuple(item[1] for item in findings),
            "provisional_findings_credit_eligible": False,
            "summary_credit_eligible": False,
        }
        return cls(**values, bridge_attempt_evidence_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def bridge_is_exact_zero_retained_recovery_truncation(self) -> Self:
        usage = self.usage_record
        context = _usage_context(usage)
        envelope_routing = _truncated_envelope_routing(self.envelope)
        projection_routing = _truncation_projection_routing(self.projection)
        actual_envelope_keys = {
            key for key in usage.routing if key.startswith("candidate_review_truncated_")
        }
        actual_projection_keys = {
            key for key in usage.routing if key.startswith("candidate_review_truncation_")
        }
        if not is_structurally_recovery_accountable_usage_record(
            usage,
            request_limit_scope=self.request_limit_scope,
            request_limit_count_before=self.request_limit_count_before,
        ):
            raise ValueError("truncation bridge usage is not structurally accountable")
        if (
            usage.request_id != self.child_plan.child_logical_request_id
            or usage.request_id != self.envelope.logical_request_id
            or usage.validation_status is not ModelRequestValidationStatus.TRUNCATED
            or usage.identity_strength is not ModelIdentityStrength.UNBOUND
            or usage.status != "rejected_truncated_response"
            or usage.validated_response_sha256 is not None
            or usage.response_sha256 != self.projection.original_response_sha256
            or usage.response_sha256 != self.envelope.response_sha256
            or usage.schema_sha256 != candidate_review_frame_wire_schema_sha256()
            or usage.schema_sha256 != self.projection.wire_schema_sha256
            or usage.finish_reason != self.projection.finish_reason
            or usage.finish_reason != self.envelope.finish_reason
            or self.projection.native_finish_reason != self.envelope.native_finish_reason
            or usage.requested_model != self.envelope.requested_model
            or usage.returned_model != self.envelope.returned_model
            or usage.actual_model != self.envelope.selected_model
            or usage.provider != self.envelope.selected_provider_name
            or usage.openrouter_generation_id != self.envelope.generation_id
            or usage.actual_provider_endpoint != self.envelope.selected_provider_endpoint
            or usage.routing.get("generation_id") != self.envelope.generation_id
            or usage.routing.get("generation_header_id") != self.envelope.generation_header_id
            or usage.routing.get("provider") != self.envelope.selected_provider_name
            or usage.routing.get("finish_reason") != self.envelope.finish_reason
            or usage.routing.get("native_finish_reason") != self.envelope.native_finish_reason
            or usage.routing.get("schema_sha256") != self.envelope.wire_schema_sha256
            or usage.routing.get("router_metadata_sha256") != self.envelope.router_metadata_sha256
            or actual_envelope_keys != set(envelope_routing)
            or any(usage.routing.get(key) != value for key, value in envelope_routing.items())
            or actual_projection_keys != set(projection_routing)
            or any(usage.routing.get(key) != value for key, value in projection_routing.items())
            or context.request_id != self.child_plan.child_logical_request_id
            or self.child_plan.channel is not TruncationRecoveryChannel.COVERAGE
            or self.child_plan.depth != 1
            or self.projection.surface_reviews
            or self.projection.findings_state is not CandidateReviewChannelState.COMPLETE
            or self.retained_surface_ids
            or self.retained_surface_record_sha256s
        ):
            raise ValueError("truncation bridge differs from its envelope or zero-retained plan")
        findings = _finding_inventory(self.projection.findings)
        child_cost = _usage_decimal(
            usage.accounted_cost_usd_exact or "",
            label="bridge accounted cost",
        )
        if (
            child_cost > _decimal(self.child_plan.reserved_usd_exact, label="bridge reservation")
            or usage.attempts > self.child_plan.reserved_provider_attempts
            or usage.completion_tokens > self.child_plan.reserved_completion_tokens
            or self.provisional_finding_ids != tuple(item[0] for item in findings)
            or self.provisional_finding_sha256s != tuple(item[1] for item in findings)
            or self.usage_record_sha256
            != _canonical_sha256(self.usage_record.model_dump(mode="json"))
            or self.bridge_attempt_evidence_sha256
            != _model_sha256(self, exclude={"bridge_attempt_evidence_sha256"})
        ):
            raise ValueError("truncation bridge inventory, resources, or hash is inconsistent")
        return self


class TruncationRecoveryChildCompletionEvidence(_NonAuthorizingModel):
    """One normally complete child, still nonauthorizing outside closure replay."""

    schema_version: Literal["1.0"] = "1.0"
    child_plan: TruncationRecoveryChildPlan
    analysis_context_sha256: str = Field(pattern=_SHA256_PATTERN)
    requests: tuple[ModelSurfaceReviewRequest, ...] = Field(
        min_length=1,
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES,
    )
    request_limit_scope: str = Field(pattern=_ROOT_REQUEST_ID_PATTERN)
    request_limit_count_before: int = Field(ge=1, le=1_000_000)
    usage_record: UsageRecord
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalization: CandidateReviewNormalizationEvidence
    normalized_batch: CandidateReviewBatch
    surface_artifact: ModelSurfaceReviewArtifact
    findings_credit_eligible: Literal[False] = False
    child_completion_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        child_plan: TruncationRecoveryChildPlan,
        analysis_context_sha256: str,
        requests: Iterable[ModelSurfaceReviewRequest],
        request_limit_scope: str,
        request_limit_count_before: int,
        usage_record: UsageRecord,
        normalization: CandidateReviewNormalizationEvidence,
        normalized_batch: CandidateReviewBatch,
        surface_artifact: ModelSurfaceReviewArtifact,
    ) -> TruncationRecoveryChildCompletionEvidence:
        plan = _exact_model(child_plan, TruncationRecoveryChildPlan)
        materialized_requests = tuple(
            _exact_model(item, ModelSurfaceReviewRequest)
            for item in _bounded_tuple(
                requests,
                limit=MAX_TRUNCATION_CLOSURE_SURFACES,
                label="child surface requests",
            )
        )
        usage = _exact_model(usage_record, UsageRecord)
        normalized = _exact_model(normalization, CandidateReviewNormalizationEvidence)
        batch = _exact_model(normalized_batch, CandidateReviewBatch)
        artifact = _exact_model(surface_artifact, ModelSurfaceReviewArtifact)
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "child_plan": plan,
            "analysis_context_sha256": analysis_context_sha256,
            "requests": materialized_requests,
            "request_limit_scope": request_limit_scope,
            "request_limit_count_before": request_limit_count_before,
            "usage_record": usage,
            "usage_record_sha256": _canonical_sha256(usage.model_dump(mode="json")),
            "normalization": normalized,
            "normalized_batch": batch,
            "surface_artifact": artifact,
            "findings_credit_eligible": False,
        }
        return cls(**values, child_completion_evidence_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def child_is_complete_bounded_and_exact(self) -> Self:
        usage = self.usage_record
        context = _usage_context(usage)
        request_ids = tuple(request.surface_id for request in self.requests)
        if (
            request_ids != tuple(sorted(set(request_ids)))
            or request_ids != self.child_plan.surface_ids
        ):
            raise ValueError("truncation child requests differ from its planned shard")
        try:
            self.normalized_batch.require_exact_surface_set(request_ids)
            self.normalization.require_exact_batch(
                self.normalized_batch,
                request_id=self.child_plan.child_logical_request_id,
            )
            self.surface_artifact.require_exact_requested_surface_manifest(self.requests)
        except ValueError as exc:
            raise ValueError("truncation child normalized custody is inconsistent") from exc
        if not is_structurally_recovery_creditable_usage_record(
            usage,
            request_limit_scope=self.request_limit_scope,
            request_limit_count_before=self.request_limit_count_before,
        ):
            raise ValueError("truncation child usage is not structurally creditable")
        child_cost = _usage_decimal(
            usage.accounted_cost_usd_exact or "",
            label="child accounted cost",
        )
        reservation = _decimal(self.child_plan.reserved_usd_exact, label="child reservation")
        if (
            usage.request_id != self.child_plan.child_logical_request_id
            or usage.schema_sha256 != candidate_review_frame_wire_schema_sha256()
            or usage.validated_response_sha256 != self.normalization.wire_validated_response_sha256
            or usage.validation_status is not ModelRequestValidationStatus.VALID
            or usage.status != "success"
            or usage.finish_reason != "stop"
            or usage.openrouter_generation_id is None
            or context.request_id != self.child_plan.child_logical_request_id
            or self.surface_artifact.request_id != usage.request_id
            or self.surface_artifact.review_role != usage.role
            or self.surface_artifact.rendered_context_sha256 != context.rendered_sha256
            or self.surface_artifact.prompt_sha256 != usage.prompt_sha256
            or self.surface_artifact.response_sha256 != usage.response_sha256
            or self.surface_artifact.validated_response_sha256 != usage.validated_response_sha256
            or self.surface_artifact.response_schema_sha256 != usage.schema_sha256
            or self.surface_artifact.schema_version != "1.1"
            or self.surface_artifact.normalization_evidence != self.normalization
            or self.surface_artifact.normalized_response != self.normalized_batch
            or self.surface_artifact.normalized_response_sha256
            != self.normalization.normalized_batch_sha256
            or self.surface_artifact.records != self.normalized_batch.surface_reviews
            or usage.attempts > self.child_plan.reserved_provider_attempts
            or usage.completion_tokens > self.child_plan.reserved_completion_tokens
            or child_cost > reservation
        ):
            raise ValueError("truncation child completion differs from its exact custody")
        if self.usage_record_sha256 != _canonical_sha256(
            self.usage_record.model_dump(mode="json")
        ) or self.child_completion_evidence_sha256 != _model_sha256(
            self, exclude={"child_completion_evidence_sha256"}
        ):
            raise ValueError("truncation child completion hash is inconsistent")
        return self


class TruncationRecoveryParentSurfaceOrigin(_FrozenStrictModel):
    origin_kind: Literal[TruncationSurfaceOriginKind.PARENT_PROVISIONAL]
    surface_id: str = Field(pattern=_SURFACE_ID_PATTERN)
    record_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    generation_id: str = Field(min_length=1, max_length=500)
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    accepted_frame_sequence: int = Field(ge=0)
    accepted_frame_sha256: str = Field(pattern=_SHA256_PATTERN)
    provisional: Literal[True]


class TruncationRecoveryChildSurfaceOrigin(_FrozenStrictModel):
    origin_kind: Literal[TruncationSurfaceOriginKind.CHILD_COMPLETE]
    surface_id: str = Field(pattern=_SURFACE_ID_PATTERN)
    record_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    generation_id: str = Field(min_length=1, max_length=500)
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalization_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    surface_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_completion_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provisional: Literal[False]


TruncationRecoverySurfaceOrigin = Annotated[
    TruncationRecoveryParentSurfaceOrigin | TruncationRecoveryChildSurfaceOrigin,
    Field(discriminator="origin_kind"),
]


class TruncationRecoveryAttemptAccounting(_NonAuthorizingModel):
    """Exact actual and reserved resource totals for the closed family."""

    schema_version: Literal["1.0"] = "1.0"
    parent_usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_usage_record_sha256s: tuple[str, ...] = Field(
        min_length=1,
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    provider_request_count: int = Field(ge=2, le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS + 1)
    provider_attempt_count: int = Field(ge=2, le=MAX_TRUNCATION_CLOSURE_ATTEMPTS)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    accounted_usd_before_parent_exact: str = Field(pattern=_USD_PATTERN)
    parent_accounted_cost_usd_exact: str = Field(pattern=_USD_PATTERN)
    child_accounted_cost_usd_exact: str = Field(pattern=_USD_PATTERN)
    family_accounted_cost_usd_exact: str = Field(pattern=_USD_PATTERN)
    campaign_accounted_cost_usd_exact: str = Field(pattern=_USD_PATTERN)
    child_reserved_usd_exact: str = Field(pattern=_USD_PATTERN)
    campaign_cap_usd_exact: str = Field(pattern=_USD_PATTERN)
    parent_cost_refunded: Literal[False] = False
    accounting_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def arithmetic_and_hash_are_exact(self) -> Self:
        before = _decimal(self.accounted_usd_before_parent_exact, label="pre-parent cost")
        parent = _decimal(self.parent_accounted_cost_usd_exact, label="parent cost")
        children = _decimal(self.child_accounted_cost_usd_exact, label="child cost")
        family = _decimal(self.family_accounted_cost_usd_exact, label="family cost")
        campaign = _decimal(self.campaign_accounted_cost_usd_exact, label="campaign cost")
        cap = _decimal(self.campaign_cap_usd_exact, label="campaign cap")
        if (
            family != _exact_sum((parent, children))
            or campaign != _exact_sum((before, family))
            or campaign >= cap
            or campaign >= _EXACT_DECIMAL_CONTEXT.create_decimal(TRUNCATION_RECOVERY_MAX_USD_EXACT)
            or self.total_tokens != self.prompt_tokens + self.completion_tokens
            or self.provider_request_count != len(self.child_usage_record_sha256s) + 1
            or len(self.child_usage_record_sha256s) != len(set(self.child_usage_record_sha256s))
            or self.accounting_sha256 != _model_sha256(self, exclude={"accounting_sha256"})
        ):
            raise ValueError("truncation closure accounting is inconsistent")
        return self


class TruncationRecoveredSurfaceReviewArtifact(_NonAuthorizingModel):
    """Structurally complete, origin-preserving surface review comparison evidence."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-closure.v1"] = (
        TRUNCATION_CLOSURE_ALGORITHM_VERSION
    )
    structural_outcome: Literal["EXACT_SURFACE_PARTITION_VALIDATED"] = (
        "EXACT_SURFACE_PARTITION_VALIDATED"
    )
    surface_set_structurally_closed: Literal[True] = True
    scheduler_custody_verified: Literal[False] = False
    scheduler_surface_closure_eligible: Literal[False] = False
    surface_review_credit_eligible: Literal[False] = False
    candidate_credit_eligible: Literal[False] = False
    summary_credit_eligible: Literal[False] = False
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    parent_task_id: str = Field(pattern=_TASK_ID_PATTERN)
    parent_logical_request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    recovery_plan: TruncationRecoveryPlan
    invariant_binding: TruncationRecoveryInvariantBinding
    requests: tuple[ModelSurfaceReviewRequest, ...] = Field(
        min_length=1,
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES,
    )
    requested_surface_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent: TruncationRecoveryParentAttemptEvidence
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...] = Field(
        min_length=1,
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    records: tuple[ModelSurfaceReviewRecord, ...] = Field(
        min_length=1,
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES,
    )
    origins: tuple[TruncationRecoverySurfaceOrigin, ...] = Field(
        min_length=1,
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES,
    )
    accounting: TruncationRecoveryAttemptAccounting
    accepted_candidates: tuple[CandidateFinding, ...] = Field(default=(), max_length=0)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def complete_partition_origins_and_hash_are_exact(self) -> Self:
        plan = self.recovery_plan
        if plan.disposition is not TruncationRecoveryDisposition.PLANNED:
            raise ValueError("truncation closure requires one planned recovery family")
        rebuilt_plan_parent = rebuild_truncation_recovery_parent_from_projection(
            claimed_parent=plan.parent,
            projection=self.parent.projection,
        )
        if (
            rebuilt_plan_parent != plan.parent
            or self.campaign_id != plan.parent.campaign_id
            or self.pass_plan_id != plan.parent.pass_plan_id
            or self.parent_task_id != plan.parent.parent_task_id
            or self.parent_logical_request_id != plan.parent.parent_logical_request_id
            or self.parent.parent_task_id != self.parent_task_id
            or self.parent.parent_logical_request_id != self.parent_logical_request_id
            or self.parent.parent_activation_sha256 != plan.parent.parent_activation_sha256
            or self.parent.provider_attempt_evidence_sha256
            != plan.parent.provider_attempt_evidence_sha256
            or self.parent.projection.evidence_sha256 != plan.parent.truncation_projection_sha256
            or self.parent.retained_surface_ids != plan.parent.retained_surface_ids
        ):
            raise ValueError("truncation closure parent differs from recovery plan")
        request_ids = tuple(request.surface_id for request in self.requests)
        if (
            request_ids != tuple(sorted(set(request_ids)))
            or request_ids != plan.parent.requested_surface_ids
            or self.requested_surface_manifest_sha256
            != ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(self.requests)
            or self.requested_surface_manifest_sha256
            != plan.parent.requested_surface_manifest_sha256
        ):
            raise ValueError("truncation closure requested surface manifest is inconsistent")
        if tuple(child.child_plan for child in self.children) != plan.children:
            raise ValueError("truncation closure child completion inventory differs from plan")
        record_ids = tuple(record.surface_id for record in self.records)
        origin_ids = tuple(origin.surface_id for origin in self.origins)
        if (
            record_ids != request_ids
            or origin_ids != request_ids
            or len(origin_ids) != len(set(origin_ids))
            or any(
                record.status
                not in {
                    ModelSurfaceReviewStatus.CANDIDATE,
                    ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                }
                for record in self.records
            )
        ):
            raise ValueError(
                "truncation closure records and origins are not exact creditable surface reviews"
            )
        records_by_id = {record.surface_id: record for record in self.records}
        expected_records = {
            review.surface_id: review for review in self.parent.projection.surface_reviews
        }
        for child in self.children:
            for review in child.surface_artifact.records:
                if review.surface_id in expected_records:
                    raise ValueError("truncation closure child overlaps another record origin")
                expected_records[review.surface_id] = review
        if set(expected_records) != set(request_ids) or any(
            records_by_id[surface_id] != expected_records[surface_id] for surface_id in request_ids
        ):
            raise ValueError("truncation closure record partition has a gap or mutation")
        expected_origins = _surface_origins(parent=self.parent, children=self.children)
        if self.origins != expected_origins:
            raise ValueError("truncation closure per-record origins are inconsistent")
        _require_family_identity_uniqueness(self.parent, self.children)
        _require_request_limit_chain(self.parent, self.children)
        _require_invariant_binding(self.invariant_binding, self.parent, self.children)
        expected_accounting = _attempt_accounting(plan, self.parent, self.children)
        if self.accounting != expected_accounting:
            raise ValueError("truncation closure attempt accounting is inconsistent")
        if self.artifact_sha256 != _model_sha256(self, exclude={"artifact_sha256"}):
            raise ValueError("truncation closure artifact hash is inconsistent")
        return self


class TruncationRecoveredRecursiveSurfaceReviewArtifact(_NonAuthorizingModel):
    """Exact comparison evidence for the one admitted zero-retained recursive tree."""

    schema_version: Literal["1.0"] = "1.0"
    algorithm_version: Literal["mmaudit.truncation-recursive-closure.v1"] = (
        TRUNCATION_RECURSIVE_CLOSURE_ALGORITHM_VERSION
    )
    structural_outcome: Literal["EXACT_ONE_LEVEL_RECURSIVE_SURFACE_PARTITION_VALIDATED"] = (
        "EXACT_ONE_LEVEL_RECURSIVE_SURFACE_PARTITION_VALIDATED"
    )
    surface_set_structurally_closed: Literal[True] = True
    scheduler_custody_verified: Literal[False] = False
    scheduler_surface_closure_eligible: Literal[False] = False
    surface_review_credit_eligible: Literal[False] = False
    candidate_credit_eligible: Literal[False] = False
    summary_credit_eligible: Literal[False] = False
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    parent_task_id: str = Field(pattern=_TASK_ID_PATTERN)
    parent_logical_request_id: str = Field(pattern=_REQUEST_ID_PATTERN)
    recovery_plan: TruncationRecoveryPlan
    nested_recovery_plan: TruncationRecoveryPlan
    invariant_binding: TruncationRecoveryInvariantBinding
    requests: tuple[ModelSurfaceReviewRequest, ...] = Field(
        min_length=1,
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES,
    )
    requested_surface_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent: TruncationRecoveryParentAttemptEvidence
    bridge: TruncationRecoveryBridgeAttemptEvidence
    children: tuple[
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
    ]
    records: tuple[ModelSurfaceReviewRecord, ...] = Field(
        min_length=1,
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES,
    )
    origins: tuple[TruncationRecoverySurfaceOrigin, ...] = Field(
        min_length=1,
        max_length=MAX_TRUNCATION_CLOSURE_SURFACES,
    )
    accounting: TruncationRecoveryAttemptAccounting
    accepted_candidates: tuple[CandidateFinding, ...] = Field(default=(), max_length=0)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def exact_recursive_partition_and_hash(self) -> Self:
        root_plan = self.recovery_plan
        nested_plan = self.nested_recovery_plan
        if (
            root_plan.disposition is not TruncationRecoveryDisposition.PLANNED
            or nested_plan.disposition is not TruncationRecoveryDisposition.PLANNED
            or root_plan.parent.current_depth != 0
            or nested_plan.parent.current_depth != 1
            or len(root_plan.children) != 2
            or len(nested_plan.children) != 2
            or any(child.depth != 2 for child in nested_plan.children)
        ):
            raise ValueError("recursive truncation closure is outside the one-level binary tree")

        rebuilt_root_parent = rebuild_truncation_recovery_parent_from_projection(
            claimed_parent=root_plan.parent,
            projection=self.parent.projection,
        )
        rebuilt_bridge_parent = rebuild_truncation_recovery_parent_from_projection(
            claimed_parent=nested_plan.parent,
            projection=self.bridge.projection,
        )
        bridge_matches = tuple(
            child
            for child in root_plan.children
            if child.child_task_id == nested_plan.parent.parent_task_id
            and child.child_logical_request_id == nested_plan.parent.parent_logical_request_id
            and child.child_plan_sha256 == nested_plan.parent.parent_task_plan_sha256
            and child.surface_ids == nested_plan.parent.requested_surface_ids
            and child.depth == nested_plan.parent.current_depth
            and child.path == nested_plan.parent.parent_path
        )
        if len(bridge_matches) != 1:
            raise ValueError("recursive truncation closure lacks one exact bridge child")
        bridge_child = bridge_matches[0]
        direct_children = tuple(child for child in root_plan.children if child != bridge_child)
        if len(direct_children) != 1:
            raise ValueError("recursive truncation closure direct leaf is ambiguous")
        direct_child = direct_children[0]
        if (
            rebuilt_root_parent != root_plan.parent
            or rebuilt_bridge_parent != nested_plan.parent
            or self.campaign_id != root_plan.parent.campaign_id
            or self.campaign_id != nested_plan.parent.campaign_id
            or self.pass_plan_id != root_plan.parent.pass_plan_id
            or self.pass_plan_id != nested_plan.parent.pass_plan_id
            or self.parent_task_id != root_plan.parent.parent_task_id
            or self.parent_logical_request_id != root_plan.parent.parent_logical_request_id
            or self.parent.parent_task_id != self.parent_task_id
            or self.parent.parent_logical_request_id != self.parent_logical_request_id
            or self.parent.parent_activation_sha256 != root_plan.parent.parent_activation_sha256
            or self.parent.provider_attempt_evidence_sha256
            != root_plan.parent.provider_attempt_evidence_sha256
            or self.parent.projection.evidence_sha256
            != root_plan.parent.truncation_projection_sha256
            or self.parent.retained_surface_ids != root_plan.parent.retained_surface_ids
            or self.bridge.child_plan != bridge_child
            or self.bridge.child_plan.child_task_id != nested_plan.parent.parent_task_id
            or self.bridge.child_plan.child_logical_request_id
            != nested_plan.parent.parent_logical_request_id
            or self.bridge.activation_sha256 != nested_plan.parent.parent_activation_sha256
            or self.bridge.provider_attempt_evidence_sha256
            != nested_plan.parent.provider_attempt_evidence_sha256
            or self.bridge.projection.evidence_sha256
            != nested_plan.parent.truncation_projection_sha256
            or self.bridge.retained_surface_ids
            or self.bridge.projection.surface_reviews
            or self.bridge.projection.findings_state is not CandidateReviewChannelState.COMPLETE
            or nested_plan.parent.requested_surface_manifest_sha256
            != root_plan.parent.requested_surface_manifest_sha256
            or nested_plan.parent.requested_surface_ids != bridge_child.surface_ids
            or nested_plan.parent.unfinished_surface_ids != bridge_child.surface_ids
            or nested_plan.parent.retained_surface_ids
            or tuple(child.child_plan for child in self.children)
            != (direct_child, *nested_plan.children)
        ):
            raise ValueError("recursive truncation closure differs from its exact tree custody")

        request_ids = tuple(request.surface_id for request in self.requests)
        if (
            request_ids != tuple(sorted(set(request_ids)))
            or request_ids != root_plan.parent.requested_surface_ids
            or self.requested_surface_manifest_sha256
            != ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(self.requests)
            or self.requested_surface_manifest_sha256
            != root_plan.parent.requested_surface_manifest_sha256
        ):
            raise ValueError("recursive truncation closure surface manifest is inconsistent")

        record_ids = tuple(record.surface_id for record in self.records)
        origin_ids = tuple(origin.surface_id for origin in self.origins)
        records_by_id = {record.surface_id: record for record in self.records}
        expected_records = {
            review.surface_id: review for review in self.parent.projection.surface_reviews
        }
        for child in self.children:
            for review in child.surface_artifact.records:
                if review.surface_id in expected_records:
                    raise ValueError("recursive truncation closure leaf records overlap")
                expected_records[review.surface_id] = review
        if (
            record_ids != request_ids
            or origin_ids != request_ids
            or len(origin_ids) != len(set(origin_ids))
            or set(expected_records) != set(request_ids)
            or any(
                records_by_id[surface_id] != expected_records[surface_id]
                for surface_id in request_ids
            )
            or any(
                record.status
                not in {
                    ModelSurfaceReviewStatus.CANDIDATE,
                    ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                }
                for record in self.records
            )
        ):
            raise ValueError("recursive truncation closure record partition has a gap or mutation")
        if self.origins != _surface_origins(parent=self.parent, children=self.children):
            raise ValueError("recursive truncation closure per-record origins are inconsistent")

        _require_recursive_family_identity_uniqueness(
            parent=self.parent,
            bridge=self.bridge,
            children=self.children,
        )
        _require_recursive_request_limit_chain(
            parent=self.parent,
            bridge=self.bridge,
            root_plan=root_plan,
            nested_plan=nested_plan,
            children=self.children,
        )
        _require_recursive_invariant_binding(
            self.invariant_binding,
            parent=self.parent,
            bridge=self.bridge,
            children=self.children,
        )
        expected_accounting = _recursive_attempt_accounting(
            root_plan=root_plan,
            nested_plan=nested_plan,
            parent=self.parent,
            bridge=self.bridge,
            children=self.children,
        )
        if self.accounting != expected_accounting:
            raise ValueError("recursive truncation closure accounting is inconsistent")
        if self.artifact_sha256 != _model_sha256(self, exclude={"artifact_sha256"}):
            raise ValueError("recursive truncation closure artifact hash is inconsistent")
        return self


class TruncationRecoveryNoncompletionEvidence(_NonAuthorizingModel):
    """Hash-only family outcome for states that cannot produce a closure capability."""

    schema_version: Literal["1.0"] = "1.0"
    state: TruncationNoncompletionState
    recovery_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_child_task_ids: tuple[str, ...] = Field(
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
    )
    observed_evidence_sha256s: tuple[str, ...] = Field(
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
    )
    surface_review_credit_eligible: Literal[False] = False
    candidate_credit_eligible: Literal[False] = False
    summary_credit_eligible: Literal[False] = False
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        state: TruncationNoncompletionState,
        recovery_plan_sha256: str,
        observed_child_task_ids: Iterable[str],
        observed_evidence_sha256s: Iterable[str],
    ) -> TruncationRecoveryNoncompletionEvidence:
        task_ids = _bounded_tuple(
            observed_child_task_ids,
            limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
            label="noncompletion child task IDs",
        )
        evidence_hashes = _bounded_tuple(
            observed_evidence_sha256s,
            limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
            label="noncompletion evidence hashes",
        )
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "state": state,
            "recovery_plan_sha256": recovery_plan_sha256,
            "observed_child_task_ids": task_ids,
            "observed_evidence_sha256s": evidence_hashes,
            "surface_review_credit_eligible": False,
            "candidate_credit_eligible": False,
            "summary_credit_eligible": False,
        }
        return cls(**values, evidence_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def inventory_and_hash_are_exact(self) -> Self:
        if (
            len(self.observed_child_task_ids) != len(self.observed_evidence_sha256s)
            or self.observed_child_task_ids != tuple(sorted(set(self.observed_child_task_ids)))
            or any(
                re.fullmatch(_TASK_ID_PATTERN, item) is None
                for item in self.observed_child_task_ids
            )
            or any(
                re.fullmatch(_SHA256_PATTERN, item) is None
                for item in self.observed_evidence_sha256s
            )
            or self.evidence_sha256 != _model_sha256(self, exclude={"evidence_sha256"})
        ):
            raise ValueError("truncation noncompletion evidence is inconsistent")
        return self


def build_truncation_recovered_surface_artifact(
    *,
    recovery_plan: TruncationRecoveryPlan,
    analysis_context_sha256: str,
    requests: Iterable[ModelSurfaceReviewRequest],
    parent: TruncationRecoveryParentAttemptEvidence,
    children: Iterable[TruncationRecoveryChildCompletionEvidence],
) -> TruncationRecoveredSurfaceReviewArtifact:
    """Build deterministic comparison evidence for one exactly closed surface set."""

    plan = _exact_model(recovery_plan, TruncationRecoveryPlan)
    exact_parent = _exact_model(parent, TruncationRecoveryParentAttemptEvidence)
    exact_requests = tuple(
        _exact_model(item, ModelSurfaceReviewRequest)
        for item in _bounded_tuple(
            requests,
            limit=MAX_TRUNCATION_CLOSURE_SURFACES,
            label="requested surfaces",
        )
    )
    exact_children = tuple(
        _exact_model(item, TruncationRecoveryChildCompletionEvidence)
        for item in _bounded_tuple(
            children,
            limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
            label="child completions",
        )
    )
    try:
        return _build_exact_surface_artifact(
            plan=plan,
            analysis_context_sha256=analysis_context_sha256,
            requests=exact_requests,
            parent=exact_parent,
            children=exact_children,
        )
    except (TypeError, ValueError) as exc:
        raise TruncationClosureError("truncation recovery surface set did not close") from exc


def build_truncation_recovered_recursive_surface_artifact(
    *,
    recovery_plan: TruncationRecoveryPlan,
    nested_recovery_plan: TruncationRecoveryPlan,
    analysis_context_sha256: str,
    requests: Iterable[ModelSurfaceReviewRequest],
    parent: TruncationRecoveryParentAttemptEvidence,
    bridge: TruncationRecoveryBridgeAttemptEvidence,
    children: Iterable[TruncationRecoveryChildCompletionEvidence],
) -> TruncationRecoveredRecursiveSurfaceReviewArtifact:
    """Build comparison evidence for the exact admitted one-level recursive tree."""

    root_plan = _exact_model(recovery_plan, TruncationRecoveryPlan)
    nested_plan = _exact_model(nested_recovery_plan, TruncationRecoveryPlan)
    exact_parent = _exact_model(parent, TruncationRecoveryParentAttemptEvidence)
    exact_bridge = _exact_model(bridge, TruncationRecoveryBridgeAttemptEvidence)
    exact_requests = tuple(
        _exact_model(item, ModelSurfaceReviewRequest)
        for item in _bounded_tuple(
            requests,
            limit=MAX_TRUNCATION_CLOSURE_SURFACES,
            label="recursive requested surfaces",
        )
    )
    child_items = _bounded_tuple(
        children,
        limit=3,
        label="recursive leaf completions",
    )
    if len(child_items) != 3:
        raise TruncationClosureError(
            "recursive truncation closure requires exactly three successful leaves"
        )
    materialized_children = tuple(
        _exact_model(item, TruncationRecoveryChildCompletionEvidence) for item in child_items
    )
    exact_children = (
        materialized_children[0],
        materialized_children[1],
        materialized_children[2],
    )
    try:
        invariant = _invariant_binding(
            analysis_context_sha256=analysis_context_sha256,
            parent=exact_parent,
            children=exact_children,
        )
        _require_recursive_invariant_binding(
            invariant,
            parent=exact_parent,
            bridge=exact_bridge,
            children=exact_children,
        )
        records = tuple(
            sorted(
                (
                    *exact_parent.projection.surface_reviews,
                    *(
                        review
                        for child in exact_children
                        for review in child.surface_artifact.records
                    ),
                ),
                key=lambda item: item.surface_id,
            )
        )
        origins = _surface_origins(parent=exact_parent, children=exact_children)
        accounting = _recursive_attempt_accounting(
            root_plan=root_plan,
            nested_plan=nested_plan,
            parent=exact_parent,
            bridge=exact_bridge,
            children=exact_children,
        )
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "algorithm_version": TRUNCATION_RECURSIVE_CLOSURE_ALGORITHM_VERSION,
            "structural_outcome": ("EXACT_ONE_LEVEL_RECURSIVE_SURFACE_PARTITION_VALIDATED"),
            "surface_set_structurally_closed": True,
            "scheduler_custody_verified": False,
            "scheduler_surface_closure_eligible": False,
            "surface_review_credit_eligible": False,
            "candidate_credit_eligible": False,
            "summary_credit_eligible": False,
            "campaign_id": root_plan.parent.campaign_id,
            "pass_plan_id": root_plan.parent.pass_plan_id,
            "parent_task_id": root_plan.parent.parent_task_id,
            "parent_logical_request_id": root_plan.parent.parent_logical_request_id,
            "recovery_plan": root_plan,
            "nested_recovery_plan": nested_plan,
            "invariant_binding": invariant,
            "requests": exact_requests,
            "requested_surface_manifest_sha256": (
                ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
                    exact_requests
                )
            ),
            "parent": exact_parent,
            "bridge": exact_bridge,
            "children": exact_children,
            "records": records,
            "origins": origins,
            "accounting": accounting,
            "accepted_candidates": (),
        }
        with localcontext(_EXACT_DECIMAL_CONTEXT):
            return TruncationRecoveredRecursiveSurfaceReviewArtifact(
                **values,
                artifact_sha256=_canonical_sha256(values),
            )
    except (TypeError, ValueError) as exc:
        raise TruncationClosureError(
            "recursive truncation recovery surface set did not close"
        ) from exc


def _build_exact_surface_artifact(
    *,
    plan: TruncationRecoveryPlan,
    analysis_context_sha256: str,
    requests: tuple[ModelSurfaceReviewRequest, ...],
    parent: TruncationRecoveryParentAttemptEvidence,
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> TruncationRecoveredSurfaceReviewArtifact:
    invariant = _invariant_binding(
        analysis_context_sha256=analysis_context_sha256,
        parent=parent,
        children=children,
    )
    records = tuple(
        sorted(
            (
                *parent.projection.surface_reviews,
                *(review for child in children for review in child.surface_artifact.records),
            ),
            key=lambda item: item.surface_id,
        )
    )
    origins = _surface_origins(parent=parent, children=children)
    accounting = _attempt_accounting(plan, parent, children)
    values: dict[str, Any] = {
        "evidence_authority": "comparison_required",
        "provider_dispatch_authorized": False,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "completion_authorized": False,
        "release_authorized": False,
        "schema_version": "1.0",
        "algorithm_version": TRUNCATION_CLOSURE_ALGORITHM_VERSION,
        "structural_outcome": "EXACT_SURFACE_PARTITION_VALIDATED",
        "surface_set_structurally_closed": True,
        "scheduler_custody_verified": False,
        "scheduler_surface_closure_eligible": False,
        "surface_review_credit_eligible": False,
        "candidate_credit_eligible": False,
        "summary_credit_eligible": False,
        "campaign_id": plan.parent.campaign_id,
        "pass_plan_id": plan.parent.pass_plan_id,
        "parent_task_id": plan.parent.parent_task_id,
        "parent_logical_request_id": plan.parent.parent_logical_request_id,
        "recovery_plan": plan,
        "invariant_binding": invariant,
        "requests": requests,
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests)
        ),
        "parent": parent,
        "children": children,
        "records": records,
        "origins": origins,
        "accounting": accounting,
        "accepted_candidates": (),
    }
    with localcontext(_EXACT_DECIMAL_CONTEXT):
        return TruncationRecoveredSurfaceReviewArtifact(
            **values,
            artifact_sha256=_canonical_sha256(values),
        )


def _invariant_binding(
    *,
    analysis_context_sha256: str,
    parent: TruncationRecoveryParentAttemptEvidence,
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> TruncationRecoveryInvariantBinding:
    context = _usage_context(parent.usage_record)
    values: dict[str, Any] = {
        "evidence_authority": "comparison_required",
        "provider_dispatch_authorized": False,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "completion_authorized": False,
        "release_authorized": False,
        "schema_version": "1.0",
        "review_role": parent.usage_record.role,
        "context_role": context.context_role,
        "requested_model": parent.usage_record.requested_model,
        "selected_model": parent.envelope.selected_model,
        "response_provider": parent.envelope.selected_provider_name,
        "selected_provider_endpoint": parent.envelope.selected_provider_endpoint,
        "selected_provider_identity": parent.envelope.selected_provider_identity,
        "model_family": parent.usage_record.model_family,
        "wire_schema_sha256": candidate_review_frame_wire_schema_sha256(),
        "normalized_batch_schema_sha256": candidate_review_batch_schema_sha256(),
        "analysis_context_sha256": analysis_context_sha256,
        "routing_invariant_sha256": _routing_invariant_sha256(parent.usage_record),
    }
    binding = TruncationRecoveryInvariantBinding(
        **values,
        binding_sha256=_canonical_sha256(values),
    )
    _require_invariant_binding(binding, parent, children)
    return binding


def _require_invariant_binding(
    binding: TruncationRecoveryInvariantBinding,
    parent: TruncationRecoveryParentAttemptEvidence,
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> None:
    parent_context = _usage_context(parent.usage_record)
    if (
        binding.review_role != parent.usage_record.role
        or binding.context_role != parent_context.context_role
        or binding.requested_model != parent.usage_record.requested_model
        or binding.selected_model != parent.envelope.selected_model
        or binding.response_provider != parent.envelope.selected_provider_name
        or binding.selected_provider_endpoint != parent.envelope.selected_provider_endpoint
        or binding.selected_provider_identity != parent.envelope.selected_provider_identity
        or binding.model_family != parent.usage_record.model_family
        or binding.routing_invariant_sha256 != _routing_invariant_sha256(parent.usage_record)
    ):
        raise ValueError("truncation closure invariant differs from parent")
    for child in children:
        usage = child.usage_record
        context = _usage_context(usage)
        if (
            usage.role != binding.review_role
            or context.context_role != binding.context_role
            or usage.requested_model != binding.requested_model
            or usage.actual_model != binding.selected_model
            or usage.provider != binding.response_provider
            or usage.actual_provider_endpoint != binding.selected_provider_endpoint
            or usage.routing.get("selected_provider_identity") != binding.selected_provider_identity
            or usage.model_family != binding.model_family
            or usage.schema_sha256 != binding.wire_schema_sha256
            or child.normalization.normalized_batch_schema_sha256
            != binding.normalized_batch_schema_sha256
            or child.analysis_context_sha256 != binding.analysis_context_sha256
            or _routing_invariant_sha256(usage) != binding.routing_invariant_sha256
        ):
            raise ValueError("truncation child drifted from invariant request custody")


def _require_recursive_invariant_binding(
    binding: TruncationRecoveryInvariantBinding,
    *,
    parent: TruncationRecoveryParentAttemptEvidence,
    bridge: TruncationRecoveryBridgeAttemptEvidence,
    children: tuple[
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
    ],
) -> None:
    _require_invariant_binding(binding, parent, children)
    usage = bridge.usage_record
    context = _usage_context(usage)
    if (
        usage.role != binding.review_role
        or context.context_role != binding.context_role
        or usage.requested_model != binding.requested_model
        or usage.actual_model != binding.selected_model
        or usage.provider != binding.response_provider
        or usage.actual_provider_endpoint != binding.selected_provider_endpoint
        or usage.routing.get("selected_provider_identity") != binding.selected_provider_identity
        or usage.model_family != binding.model_family
        or usage.schema_sha256 != binding.wire_schema_sha256
        or bridge.analysis_context_sha256 != binding.analysis_context_sha256
        or _routing_invariant_sha256(usage) != binding.routing_invariant_sha256
    ):
        raise ValueError("truncation bridge drifted from invariant request custody")


def _surface_origins(
    *,
    parent: TruncationRecoveryParentAttemptEvidence,
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> tuple[TruncationRecoverySurfaceOrigin, ...]:
    parent_frames = {
        frame.record_id: frame
        for frame in parent.projection.accepted_frames
        if frame.phase is CandidateReviewFramePhase.SURFACE_REVIEW
    }
    origins: list[TruncationRecoverySurfaceOrigin] = []
    for record in parent.projection.surface_reviews:
        frame = parent_frames.get(record.surface_id)
        if frame is None:
            raise TruncationClosureError("parent surface lacks its accepted truncation frame")
        origins.append(
            TruncationRecoveryParentSurfaceOrigin(
                origin_kind=TruncationSurfaceOriginKind.PARENT_PROVISIONAL,
                surface_id=record.surface_id,
                record_sha256=_record_sha256(record),
                request_id=parent.parent_logical_request_id,
                generation_id=parent.envelope.generation_id,
                usage_record_sha256=parent.usage_record_sha256,
                projection_sha256=parent.projection.evidence_sha256,
                accepted_frame_sequence=frame.sequence,
                accepted_frame_sha256=frame.frame_sha256,
                provisional=True,
            )
        )
    for child in children:
        generation_id = child.usage_record.openrouter_generation_id
        if generation_id is None:
            raise TruncationClosureError("child completion lacks a generation identity")
        for record in child.surface_artifact.records:
            origins.append(
                TruncationRecoveryChildSurfaceOrigin(
                    origin_kind=TruncationSurfaceOriginKind.CHILD_COMPLETE,
                    surface_id=record.surface_id,
                    record_sha256=_record_sha256(record),
                    request_id=child.usage_record.request_id,
                    generation_id=generation_id,
                    usage_record_sha256=child.usage_record_sha256,
                    child_plan_sha256=child.child_plan.child_plan_sha256,
                    normalization_evidence_sha256=child.normalization.evidence_sha256,
                    surface_artifact_sha256=child.surface_artifact.artifact_sha256,
                    child_completion_evidence_sha256=(child.child_completion_evidence_sha256),
                    provisional=False,
                )
            )
    return tuple(sorted(origins, key=lambda item: item.surface_id))


def _require_family_identity_uniqueness(
    parent: TruncationRecoveryParentAttemptEvidence,
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> None:
    usages = (parent.usage_record, *(child.usage_record for child in children))
    request_ids = tuple(usage.request_id for usage in usages)
    generation_ids = tuple(usage.openrouter_generation_id for usage in usages)
    request_body_sha256s = tuple(usage.request_body_sha256 for usage in usages)
    task_ids = (parent.parent_task_id, *(child.child_plan.child_task_id for child in children))
    if (
        len(request_ids) != len(set(request_ids))
        or None in generation_ids
        or len(generation_ids) != len(set(generation_ids))
        or None in request_body_sha256s
        or len(request_body_sha256s) != len(set(request_body_sha256s))
        or len(task_ids) != len(set(task_ids))
    ):
        raise ValueError("truncation closure request, generation, body, or task identity collides")


def _require_recursive_family_identity_uniqueness(
    *,
    parent: TruncationRecoveryParentAttemptEvidence,
    bridge: TruncationRecoveryBridgeAttemptEvidence,
    children: tuple[
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
    ],
) -> None:
    usages = (
        parent.usage_record,
        bridge.usage_record,
        *(child.usage_record for child in children),
    )
    request_ids = tuple(usage.request_id for usage in usages)
    generation_ids = tuple(usage.openrouter_generation_id for usage in usages)
    request_body_sha256s = tuple(usage.request_body_sha256 for usage in usages)
    task_ids = (
        parent.parent_task_id,
        bridge.child_plan.child_task_id,
        *(child.child_plan.child_task_id for child in children),
    )
    if (
        len(request_ids) != 5
        or len(request_ids) != len(set(request_ids))
        or None in generation_ids
        or len(generation_ids) != len(set(generation_ids))
        or None in request_body_sha256s
        or len(request_body_sha256s) != len(set(request_body_sha256s))
        or len(task_ids) != len(set(task_ids))
    ):
        raise ValueError(
            "recursive truncation closure request, generation, body, or task identity collides"
        )


def _require_request_limit_chain(
    parent: TruncationRecoveryParentAttemptEvidence,
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> None:
    try:
        parent_reservations = atomic_request_limit_reservations_from_usage(parent.usage_record)
    except ValueError as exc:
        raise ValueError("truncation closure parent request-limit evidence is invalid") from exc
    if not parent_reservations:
        raise ValueError("truncation closure parent request-limit evidence is absent")
    final_parent = parent_reservations[-1]
    expected_count = final_parent.request_limit_count_after
    for child in children:
        if (
            child.request_limit_scope != final_parent.request_limit_scope
            or child.request_limit_count_before != expected_count
        ):
            raise ValueError("truncation closure child request-limit chain is inconsistent")
        expected_count += child.usage_record.attempts


def _require_recursive_request_limit_chain(
    *,
    parent: TruncationRecoveryParentAttemptEvidence,
    bridge: TruncationRecoveryBridgeAttemptEvidence,
    root_plan: TruncationRecoveryPlan,
    nested_plan: TruncationRecoveryPlan,
    children: tuple[
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
    ],
) -> None:
    try:
        parent_reservations = atomic_request_limit_reservations_from_usage(parent.usage_record)
    except ValueError as exc:
        raise ValueError(
            "recursive truncation closure parent request-limit evidence is invalid"
        ) from exc
    if not parent_reservations:
        raise ValueError("recursive truncation closure parent request-limit evidence is absent")
    final_parent = parent_reservations[-1]
    expected_count = final_parent.request_limit_count_after
    direct_leaf = children[0]
    root_evidence_by_plan_sha256: dict[
        str,
        TruncationRecoveryBridgeAttemptEvidence | TruncationRecoveryChildCompletionEvidence,
    ] = {
        bridge.child_plan.child_plan_sha256: bridge,
        direct_leaf.child_plan.child_plan_sha256: direct_leaf,
    }
    if len(root_evidence_by_plan_sha256) != 2:
        raise ValueError("recursive truncation closure root request-limit mapping is ambiguous")
    for child_plan in root_plan.children:
        evidence = root_evidence_by_plan_sha256.get(child_plan.child_plan_sha256)
        if evidence is None or evidence.child_plan != child_plan:
            raise ValueError("recursive truncation closure root request-limit mapping is detached")
        if (
            evidence.request_limit_scope != final_parent.request_limit_scope
            or evidence.request_limit_count_before != expected_count
        ):
            raise ValueError(
                "recursive truncation closure root request-limit chain is inconsistent"
            )
        expected_count += evidence.usage_record.attempts
    for child_plan, completion in zip(nested_plan.children, children[1:], strict=True):
        if (
            completion.child_plan != child_plan
            or completion.request_limit_scope != final_parent.request_limit_scope
            or completion.request_limit_count_before != expected_count
        ):
            raise ValueError(
                "recursive truncation closure nested request-limit chain is inconsistent"
            )
        expected_count += completion.usage_record.attempts


def _attempt_accounting(
    plan: TruncationRecoveryPlan,
    parent: TruncationRecoveryParentAttemptEvidence,
    children: tuple[TruncationRecoveryChildCompletionEvidence, ...],
) -> TruncationRecoveryAttemptAccounting:
    parent_usage = parent.usage_record
    child_usages = tuple(child.usage_record for child in children)
    parent_cost = _usage_decimal(
        parent_usage.accounted_cost_usd_exact or "",
        label="parent accounted cost",
    )
    expected_parent_cost = _decimal(
        plan.resources.parent_accounted_cost_usd_exact,
        label="planned parent cost",
    )
    if (
        parent_cost != expected_parent_cost
        or parent_usage.attempts != plan.resources.parent_provider_attempts
        or parent_usage.completion_tokens != plan.resources.parent_completion_tokens
    ):
        raise TruncationClosureError("truncation parent resources differ from recovery plan")
    child_costs = tuple(
        _usage_decimal(usage.accounted_cost_usd_exact or "", label="child accounted cost")
        for usage in child_usages
    )
    child_cost = _exact_sum(child_costs)
    family_cost = _exact_sum((parent_cost, child_cost))
    before = _decimal(
        plan.resources.accounted_usd_before_parent_exact,
        label="pre-parent accounted cost",
    )
    campaign_cost = _exact_sum((before, family_cost))
    child_reserved = _exact_sum(
        _decimal(child.child_plan.reserved_usd_exact, label="child reservation")
        for child in children
    )
    values: dict[str, Any] = {
        "evidence_authority": "comparison_required",
        "provider_dispatch_authorized": False,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "completion_authorized": False,
        "release_authorized": False,
        "schema_version": "1.0",
        "parent_usage_record_sha256": parent.usage_record_sha256,
        "child_usage_record_sha256s": tuple(child.usage_record_sha256 for child in children),
        "provider_request_count": len(child_usages) + 1,
        "provider_attempt_count": sum(usage.attempts for usage in (parent_usage, *child_usages)),
        "prompt_tokens": sum(usage.prompt_tokens for usage in (parent_usage, *child_usages)),
        "completion_tokens": sum(
            usage.completion_tokens for usage in (parent_usage, *child_usages)
        ),
        "total_tokens": sum(usage.total_tokens for usage in (parent_usage, *child_usages)),
        "accounted_usd_before_parent_exact": _decimal_text(before),
        "parent_accounted_cost_usd_exact": _decimal_text(parent_cost),
        "child_accounted_cost_usd_exact": _decimal_text(child_cost),
        "family_accounted_cost_usd_exact": _decimal_text(family_cost),
        "campaign_accounted_cost_usd_exact": _decimal_text(campaign_cost),
        "child_reserved_usd_exact": _decimal_text(child_reserved),
        "campaign_cap_usd_exact": plan.resources.campaign_cap_usd_exact,
        "parent_cost_refunded": False,
    }
    try:
        return TruncationRecoveryAttemptAccounting(
            **values,
            accounting_sha256=_canonical_sha256(values),
        )
    except ValueError as exc:
        raise TruncationClosureError("truncation recovery accounting did not close") from exc


def _recursive_attempt_accounting(
    *,
    root_plan: TruncationRecoveryPlan,
    nested_plan: TruncationRecoveryPlan,
    parent: TruncationRecoveryParentAttemptEvidence,
    bridge: TruncationRecoveryBridgeAttemptEvidence,
    children: tuple[
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
        TruncationRecoveryChildCompletionEvidence,
    ],
) -> TruncationRecoveryAttemptAccounting:
    parent_usage = parent.usage_record
    direct_leaf = children[0]
    nested_leaves = children[1:]
    root_usages_by_plan_sha256 = {
        bridge.child_plan.child_plan_sha256: bridge.usage_record,
        direct_leaf.child_plan.child_plan_sha256: direct_leaf.usage_record,
    }
    ordered_child_usages = tuple(
        root_usages_by_plan_sha256[child.child_plan_sha256] for child in root_plan.children
    ) + tuple(child.usage_record for child in nested_leaves)
    ordered_child_sha256s = tuple(
        bridge.usage_record_sha256
        if child.child_plan_sha256 == bridge.child_plan.child_plan_sha256
        else direct_leaf.usage_record_sha256
        for child in root_plan.children
    ) + tuple(child.usage_record_sha256 for child in nested_leaves)

    parent_cost = _usage_decimal(
        parent_usage.accounted_cost_usd_exact or "",
        label="recursive parent accounted cost",
    )
    bridge_cost = _usage_decimal(
        bridge.usage_record.accounted_cost_usd_exact or "",
        label="recursive bridge accounted cost",
    )
    direct_cost = _usage_decimal(
        direct_leaf.usage_record.accounted_cost_usd_exact or "",
        label="recursive direct-leaf accounted cost",
    )
    root_before = _decimal(
        root_plan.resources.accounted_usd_before_parent_exact,
        label="recursive pre-parent accounted cost",
    )
    expected_nested_before = _exact_sum((root_before, parent_cost, direct_cost))
    if (
        parent_cost
        != _decimal(
            root_plan.resources.parent_accounted_cost_usd_exact,
            label="recursive planned parent cost",
        )
        or parent_usage.attempts != root_plan.resources.parent_provider_attempts
        or parent_usage.completion_tokens != root_plan.resources.parent_completion_tokens
        or bridge_cost
        != _decimal(
            nested_plan.resources.parent_accounted_cost_usd_exact,
            label="recursive planned bridge cost",
        )
        or bridge.usage_record.attempts != nested_plan.resources.parent_provider_attempts
        or bridge.usage_record.completion_tokens != nested_plan.resources.parent_completion_tokens
        or _decimal(
            nested_plan.resources.accounted_usd_before_parent_exact,
            label="nested pre-bridge accounted cost",
        )
        != expected_nested_before
        or nested_plan.resources.provider_attempts_before_parent
        != root_plan.resources.provider_attempts_before_parent
        + parent_usage.attempts
        + direct_leaf.usage_record.attempts
        or nested_plan.resources.completion_tokens_before_parent
        != root_plan.resources.completion_tokens_before_parent
        + parent_usage.completion_tokens
        + direct_leaf.usage_record.completion_tokens
        or nested_plan.resources.recovery_requests_consumed
        != root_plan.resources.recovery_requests_consumed + len(root_plan.children)
        or nested_plan.resources.campaign_cap_usd_exact
        != root_plan.resources.campaign_cap_usd_exact
    ):
        raise TruncationClosureError(
            "recursive truncation resources differ from the root and nested plans"
        )

    child_cost = _exact_sum(
        _usage_decimal(
            usage.accounted_cost_usd_exact or "",
            label="recursive child accounted cost",
        )
        for usage in ordered_child_usages
    )
    family_cost = _exact_sum((parent_cost, child_cost))
    campaign_cost = _exact_sum((root_before, family_cost))
    child_reserved = _exact_sum(
        (
            *(
                _decimal(child.reserved_usd_exact, label="root child reservation")
                for child in root_plan.children
            ),
            *(
                _decimal(child.reserved_usd_exact, label="nested child reservation")
                for child in nested_plan.children
            ),
        )
    )
    all_usages = (parent_usage, *ordered_child_usages)
    values: dict[str, Any] = {
        "evidence_authority": "comparison_required",
        "provider_dispatch_authorized": False,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "completion_authorized": False,
        "release_authorized": False,
        "schema_version": "1.0",
        "parent_usage_record_sha256": parent.usage_record_sha256,
        "child_usage_record_sha256s": ordered_child_sha256s,
        "provider_request_count": len(all_usages),
        "provider_attempt_count": sum(usage.attempts for usage in all_usages),
        "prompt_tokens": sum(usage.prompt_tokens for usage in all_usages),
        "completion_tokens": sum(usage.completion_tokens for usage in all_usages),
        "total_tokens": sum(usage.total_tokens for usage in all_usages),
        "accounted_usd_before_parent_exact": _decimal_text(root_before),
        "parent_accounted_cost_usd_exact": _decimal_text(parent_cost),
        "child_accounted_cost_usd_exact": _decimal_text(child_cost),
        "family_accounted_cost_usd_exact": _decimal_text(family_cost),
        "campaign_accounted_cost_usd_exact": _decimal_text(campaign_cost),
        "child_reserved_usd_exact": _decimal_text(child_reserved),
        "campaign_cap_usd_exact": root_plan.resources.campaign_cap_usd_exact,
        "parent_cost_refunded": False,
    }
    try:
        return TruncationRecoveryAttemptAccounting(
            **values,
            accounting_sha256=_canonical_sha256(values),
        )
    except ValueError as exc:
        raise TruncationClosureError(
            "recursive truncation recovery accounting did not close"
        ) from exc
