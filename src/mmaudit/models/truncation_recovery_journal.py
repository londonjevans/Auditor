"""Typed, nonauthorizing journal entries for scheduler truncation recovery families.

The artifacts in this module are private custody records.  They describe a frozen
recovery plan and its nested child lifecycle, but cannot dispatch a provider call,
grant review or coverage credit, complete a campaign, or authorize a release.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from itertools import islice
from typing import Any, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextRequestEvidence,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRequest,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    StrictModel,
    UsageRecord,
)
from mmaudit.models.truncation import (
    MAX_CANDIDATE_REVIEW_FINDINGS,
    CandidateReviewChannelState,
    CandidateReviewFramePhase,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_batch_schema_sha256,
    candidate_review_frame_wire_schema_sha256,
)
from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
    TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TruncationRecoveryChannel,
    TruncationRecoveryChannelBinding,
    TruncationRecoveryChannelState,
    TruncationRecoveryChildPlan,
    TruncationRecoveryDisposition,
    TruncationRecoveryParentBinding,
    TruncationRecoveryPlan,
    TruncationRecoveryPolicy,
)
from mmaudit.models.usage import (
    is_recovery_accountable_usage_record,
    is_recovery_creditable_usage_record,
    is_structurally_recovery_accountable_usage_record,
    is_structurally_recovery_creditable_usage_record,
    recovery_atomic_request_limit_reservations_from_usage,
)
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence

SCHEDULER_TRUNCATION_RECOVERY_JOURNAL_VERSION: Final = (
    "mmaudit.scheduler.truncation-recovery-journal.v1"
)
SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES: Final = TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS // 2
SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES: Final = (
    SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES * 3 + TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS * 3
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CAMPAIGN_ID_PATTERN = r"^scheduler-campaign-[0-9a-f]{64}$"
_ROOT_REQUEST_ID_PATTERN = r"^scheduler-request-[0-9a-f]{64}$"
_ROOT_TASK_ID_PATTERN = r"^scheduler-task-[0-9a-f]{64}$"
_RECOVERY_TASK_ID_PATTERN = r"^scheduler-recovery-task-[0-9a-f]{64}$"
_RECOVERY_REQUEST_ID_PATTERN = r"^scheduler-recovery-request-[0-9a-f]{64}$"
_MODEL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
_ROLE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_RECOVERY_FAMILY_ID_PATTERN = r"^scheduler-recovery-family-[0-9a-f]{64}$"
_RECOVERY_ACTIVATION_ID_PATTERN = r"^scheduler-recovery-activation-[0-9a-f]{64}$"
_RECOVERY_DISPATCH_ID_PATTERN = r"^scheduler-recovery-dispatch-[0-9a-f]{64}$"
_RECOVERY_RESULT_ID_PATTERN = r"^scheduler-recovery-result-[0-9a-f]{64}$"
_RECOVERY_CLOSURE_ID_PATTERN = r"^scheduler-recovery-closure-[0-9a-f]{64}$"
_RECOVERY_PROMOTION_ID_PATTERN = r"^scheduler-recovery-promotion-[0-9a-f]{64}$"
_SURFACE_ID_PATTERN = r"^model-surface:[0-9a-f]{64}$"
_USD_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,12})(?:\.[0-9]{1,36})?$"
_MAX_SURFACES = 10_000
_MAX_SOURCE_DESCRIPTORS = 100_000
_MAX_PROMOTED_CANDIDATES = MAX_CANDIDATE_REVIEW_FINDINGS * 3
_SPECIALIST_INVESTIGATOR_REQUEST_ROLES = frozenset(
    f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES
)


class SchedulerTruncationRecoveryEntryKind(StrEnum):
    """Closed durable entry kinds for one private recovery journal chain."""

    FAMILY_ROOT = "FAMILY_ROOT"
    CHILD_ACTIVATED = "CHILD_ACTIVATED"
    CHILD_PREFLIGHT_TERMINAL = "CHILD_PREFLIGHT_TERMINAL"
    CHILD_DISPATCHED = "CHILD_DISPATCHED"
    CHILD_TERMINAL = "CHILD_TERMINAL"
    FAMILY_CLOSED = "FAMILY_CLOSED"
    FAMILY_PROMOTED = "FAMILY_PROMOTED"


class SchedulerTruncationRecoveryParentKind(StrEnum):
    """Whether a recovery plan follows a frozen pass task or a recovery child."""

    SCHEDULER_TASK = "SCHEDULER_TASK"
    RECOVERY_CHILD = "RECOVERY_CHILD"


class SchedulerTruncationRecoveryResultOrigin(StrEnum):
    """Whether terminal evidence came from runtime or conservative crash recovery."""

    RUNTIME = "RUNTIME"
    PREFLIGHT = "PREFLIGHT"
    CRASH_RECOVERY = "CRASH_RECOVERY"


class SchedulerTruncationRecoveryTerminalStatus(StrEnum):
    """Exact terminal states for one recovery child."""

    SUCCEEDED = "SUCCEEDED"
    TRUNCATED = "TRUNCATED"
    FAILED = "FAILED"
    INVALID = "INVALID"
    UNBOUND = "UNBOUND"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNCERTAIN = "UNCERTAIN"


class SchedulerTruncationRecoveryCostDisposition(StrEnum):
    """How one child result conservatively accounts provider resources."""

    ACTUAL_ACCOUNTED = "ACTUAL_ACCOUNTED"
    RESERVED_MAX_ACCOUNTED = "RESERVED_MAX_ACCOUNTED"


class SchedulerTruncationRecoveryClosureStatus(StrEnum):
    """Structural family closure; none of these states grants credit."""

    COVERAGE_CLOSED = "COVERAGE_CLOSED"
    INCOMPLETE = "INCOMPLETE"
    UNCERTAIN = "UNCERTAIN"


class SchedulerRecoveredCandidateOriginKind(StrEnum):
    """The exact normally hidden response that supplied one promoted candidate."""

    PARENT_FRAME = "PARENT_FRAME"
    CHILD_BATCH = "CHILD_BATCH"


class _NonAuthorizingRecoveryJournalModel(StrictModel):
    """Literal-false authority surface shared by every recovery journal artifact."""

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
    raise TypeError(f"unsupported recovery journal hash value: {type(value).__qualname__}")


def _model_sha256(model: StrictModel, *, exclude: set[str]) -> str:
    return _canonical_sha256(model.model_dump(mode="json", exclude=exclude))


def _bounded_tuple[ItemT](
    values: Iterable[ItemT],
    *,
    limit: int,
    label: str,
) -> tuple[ItemT, ...]:
    items = tuple(islice(iter(values), limit + 1))
    if len(items) > limit:
        raise ValueError(f"scheduler truncation recovery {label} exceeds its item limit")
    return items


def _canonical_surface_ids(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    items = _bounded_tuple(values, limit=_MAX_SURFACES, label=label)
    if any(
        not isinstance(item, str) or re.fullmatch(_SURFACE_ID_PATTERN, item) is None
        for item in items
    ):
        raise ValueError(f"scheduler truncation recovery {label} contains an invalid surface ID")
    if len(items) != len(set(items)):
        raise ValueError(f"scheduler truncation recovery {label} contains duplicate surfaces")
    return tuple(sorted(items))


def _require_canonical_surface_ids(values: tuple[str, ...], *, label: str) -> None:
    if values != _canonical_surface_ids(values, label=label):
        raise ValueError(f"scheduler truncation recovery {label} is not canonical")


def _canonical_usd(value: str, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(_USD_EXACT_PATTERN, value) is None:
        raise ValueError(f"scheduler truncation recovery {label} is not bounded exact USD")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ValueError(f"scheduler truncation recovery {label} is invalid") from None
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"scheduler truncation recovery {label} is invalid")
    canonical = format(parsed, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    if canonical in {"", "-0"}:
        canonical = "0"
    if canonical != value:
        raise ValueError(f"scheduler truncation recovery {label} is not canonical")
    return canonical


def _canonical_usage_usd(value: str, *, label: str) -> str:
    """Canonicalize a bounded fixed-scale UsageRecord amount for durable scalar custody."""

    if (
        not isinstance(value, str)
        or re.fullmatch(r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?$", value) is None
    ):
        raise ValueError(f"scheduler truncation recovery {label} is not bounded exact USD")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise ValueError(f"scheduler truncation recovery {label} is invalid") from None
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"scheduler truncation recovery {label} is invalid")
    canonical = format(parsed, "f")
    if "." in canonical:
        canonical = canonical.rstrip("0").rstrip(".")
    if canonical in {"", "-0"}:
        canonical = "0"
    return _canonical_usd(canonical, label=label)


def _entry_values(
    *,
    campaign_id: str,
    request_limit_id: str,
    request_limit_binding_sha256: str,
    entry_kind: SchedulerTruncationRecoveryEntryKind,
    entry_index: int,
    previous_entry_sha256: str | None,
) -> dict[str, Any]:
    return {
        "evidence_authority": "comparison_required",
        "provider_dispatch_authorized": False,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "completion_authorized": False,
        "release_authorized": False,
        "schema_version": "1.0",
        "journal_version": SCHEDULER_TRUNCATION_RECOVERY_JOURNAL_VERSION,
        "campaign_id": campaign_id,
        "request_limit_id": request_limit_id,
        "request_limit_binding_sha256": request_limit_binding_sha256,
        "entry_kind": entry_kind,
        "entry_index": entry_index,
        "previous_entry_sha256": previous_entry_sha256,
    }


def _parser_channel_state(
    state: CandidateReviewChannelState,
) -> TruncationRecoveryChannelState:
    if state is CandidateReviewChannelState.COMPLETE:
        return TruncationRecoveryChannelState.COMPLETE
    if state is CandidateReviewChannelState.INVALID:
        return TruncationRecoveryChannelState.INVALID
    return TruncationRecoveryChannelState.INCOMPLETE


def _projection_channel_bindings(
    projection: CandidateReviewTruncationProjection,
) -> tuple[TruncationRecoveryChannelBinding, ...]:
    findings_inventory = tuple(item.model_dump(mode="json") for item in projection.findings)
    surface_inventory = tuple(item.model_dump(mode="json") for item in projection.surface_reviews)
    summary_frames = tuple(
        frame.model_dump(mode="json")
        for frame in projection.accepted_frames
        if frame.phase is CandidateReviewFramePhase.SUMMARY
    )
    summary_inventory = {
        "frames": summary_frames,
        "declared_finding_count": projection.summary_declared_finding_count,
        "declared_surface_review_count": (projection.summary_declared_surface_review_count),
        "state": projection.summary_state,
    }
    return (
        TruncationRecoveryChannelBinding.build(
            channel=TruncationRecoveryChannel.COVERAGE,
            state=_parser_channel_state(projection.surface_reviews_state),
            retained_record_count=len(projection.surface_reviews),
            retained_inventory_sha256=_canonical_sha256(surface_inventory),
        ),
        TruncationRecoveryChannelBinding.build(
            channel=TruncationRecoveryChannel.FINDINGS,
            state=_parser_channel_state(projection.findings_state),
            retained_record_count=len(projection.findings),
            retained_inventory_sha256=_canonical_sha256(findings_inventory),
        ),
        TruncationRecoveryChannelBinding.build(
            channel=TruncationRecoveryChannel.SUMMARY,
            state=_parser_channel_state(projection.summary_state),
            retained_record_count=(
                1 if projection.summary_state is CandidateReviewChannelState.COMPLETE else 0
            ),
            retained_inventory_sha256=_canonical_sha256(summary_inventory),
        ),
    )


def rebuild_truncation_recovery_parent_from_projection(
    *,
    claimed_parent: TruncationRecoveryParentBinding,
    projection: CandidateReviewTruncationProjection,
) -> TruncationRecoveryParentBinding:
    """Rebuild exact channel and retained-surface custody from typed parser evidence."""

    frozen_projection = CandidateReviewTruncationProjection.model_validate_json(
        projection.model_dump_json(),
        strict=True,
    )
    return TruncationRecoveryParentBinding.build(
        campaign_id=claimed_parent.campaign_id,
        pass_plan_id=claimed_parent.pass_plan_id,
        parent_task_id=claimed_parent.parent_task_id,
        parent_logical_request_id=claimed_parent.parent_logical_request_id,
        parent_task_plan_sha256=claimed_parent.parent_task_plan_sha256,
        parent_activation_sha256=claimed_parent.parent_activation_sha256,
        provider_attempt_evidence_sha256=(claimed_parent.provider_attempt_evidence_sha256),
        truncation_projection_sha256=frozen_projection.evidence_sha256,
        requested_surface_manifest_sha256=(claimed_parent.requested_surface_manifest_sha256),
        requested_surface_ids=claimed_parent.requested_surface_ids,
        retained_surface_ids=tuple(item.surface_id for item in frozen_projection.surface_reviews),
        channel_bindings=_projection_channel_bindings(frozen_projection),
        current_depth=claimed_parent.current_depth,
        parent_path=claimed_parent.parent_path,
    )


class SchedulerTruncationRecoveryRequestedSurfaceManifest(_NonAuthorizingRecoveryJournalModel):
    """Exact deterministic request descriptors from the original parent prompt."""

    schema_version: Literal["1.0"] = "1.0"
    requests: tuple[ModelSurfaceReviewRequest, ...] = Field(
        min_length=1,
        max_length=_MAX_SURFACES,
    )
    requested_surface_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_SURFACES,
    )
    requested_surface_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        requests: Iterable[ModelSurfaceReviewRequest],
    ) -> SchedulerTruncationRecoveryRequestedSurfaceManifest:
        materialized = _bounded_tuple(
            requests,
            limit=_MAX_SURFACES,
            label="requested surface manifest",
        )
        frozen = tuple(
            ModelSurfaceReviewRequest.model_validate_json(item.model_dump_json(), strict=True)
            for item in materialized
        )
        ids = tuple(item.surface_id for item in frozen)
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "requests": frozen,
            "requested_surface_ids": ids,
            "requested_surface_manifest_sha256": (
                ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(frozen)
            ),
        }
        return cls(**values, manifest_evidence_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def manifest_is_exact_canonical_and_self_hashed(self) -> Self:
        ids = tuple(item.surface_id for item in self.requests)
        if (
            ids != tuple(sorted(set(ids)))
            or self.requested_surface_ids != ids
            or self.requested_surface_manifest_sha256
            != ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(self.requests)
            or self.manifest_evidence_sha256
            != _model_sha256(self, exclude={"manifest_evidence_sha256"})
        ):
            raise ValueError("scheduler recovery requested-surface manifest is inconsistent")
        return self


class SchedulerTruncationRecoveryRequestLimitBinding(_NonAuthorizingRecoveryJournalModel):
    """Original-request identity for the recursive 32-child recovery ceiling."""

    schema_version: Literal["1.0"] = "1.0"
    journal_version: Literal["mmaudit.scheduler.truncation-recovery-journal.v1"] = (
        SCHEDULER_TRUNCATION_RECOVERY_JOURNAL_VERSION
    )
    campaign_id: str = Field(pattern=_CAMPAIGN_ID_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_limit_id: str = Field(pattern=_ROOT_REQUEST_ID_PATTERN)
    policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_request_limit_reservation: AtomicRequestLimitReservationEvidence
    parent_request_limit_count_after: int = Field(ge=1, le=2**63 - 1)
    request_limit_maximum: int = Field(ge=1, le=2**63 - 1)
    maximum_recovery_requests: Literal[32] = TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
    maximum_recovery_requests_under_request_limit: int = Field(
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    budget_manager_limit_unchanged: Literal[True] = True
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        campaign_id: str,
        manifest_sha256: str,
        request_limit_id: str,
        policy: TruncationRecoveryPolicy,
        parent_request_limit_reservation: AtomicRequestLimitReservationEvidence,
    ) -> SchedulerTruncationRecoveryRequestLimitBinding:
        frozen_policy = TruncationRecoveryPolicy.model_validate(
            policy.model_dump(mode="python"),
            strict=True,
        )
        if frozen_policy != TruncationRecoveryPolicy.frozen():
            raise ValueError("scheduler truncation recovery request policy is not frozen")
        reservation = AtomicRequestLimitReservationEvidence.model_validate(
            parent_request_limit_reservation.model_dump(mode="python"),
            strict=True,
        )
        remaining = reservation.request_limit_maximum - reservation.request_limit_count_after
        if remaining < 0:
            raise ValueError("scheduler truncation recovery parent exceeds its request limit")
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "journal_version": SCHEDULER_TRUNCATION_RECOVERY_JOURNAL_VERSION,
            "campaign_id": campaign_id,
            "manifest_sha256": manifest_sha256,
            "request_limit_id": request_limit_id,
            "policy_sha256": frozen_policy.policy_sha256,
            "parent_request_limit_reservation": reservation,
            "parent_request_limit_count_after": reservation.request_limit_count_after,
            "request_limit_maximum": reservation.request_limit_maximum,
            "maximum_recovery_requests": TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
            "maximum_recovery_requests_under_request_limit": min(
                TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
                remaining,
            ),
            "budget_manager_limit_unchanged": True,
        }
        return cls(**values, binding_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def request_limit_is_exact_and_non_relaxing(self) -> Self:
        reservation = self.parent_request_limit_reservation
        remaining = reservation.request_limit_maximum - reservation.request_limit_count_after
        if (
            self.request_limit_id != reservation.request_limit_scope
            or self.parent_request_limit_count_after != reservation.request_limit_count_after
            or self.request_limit_maximum != reservation.request_limit_maximum
            or self.maximum_recovery_requests_under_request_limit
            != min(TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS, remaining)
        ):
            raise ValueError("scheduler truncation recovery request-limit scope is inconsistent")
        if self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"}):
            raise ValueError("scheduler truncation recovery request-limit hash is inconsistent")
        return self


class _SchedulerTruncationRecoveryEntry(_NonAuthorizingRecoveryJournalModel):
    """Shared exact chain custody for each typed private recovery entry."""

    schema_version: Literal["1.0", "1.1", "1.2"] = "1.0"
    journal_version: Literal["mmaudit.scheduler.truncation-recovery-journal.v1"] = (
        SCHEDULER_TRUNCATION_RECOVERY_JOURNAL_VERSION
    )
    campaign_id: str = Field(pattern=_CAMPAIGN_ID_PATTERN)
    request_limit_id: str = Field(pattern=_ROOT_REQUEST_ID_PATTERN)
    request_limit_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    entry_kind: SchedulerTruncationRecoveryEntryKind
    entry_index: int = Field(
        ge=0,
        lt=SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
    )
    previous_entry_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    entry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def entry_chain_shape_and_hash_are_exact(self) -> Self:
        if (self.entry_index == 0) != (self.previous_entry_sha256 is None):
            raise ValueError("scheduler truncation recovery predecessor shape is inconsistent")
        if self.entry_sha256 != _model_sha256(self, exclude={"entry_sha256"}):
            raise ValueError("scheduler truncation recovery entry hash is inconsistent")
        return self


class SchedulerTruncationRecoveryFamilyRoot(_SchedulerTruncationRecoveryEntry):
    """One frozen root or nested recovery plan kept outside pass task inventory."""

    schema_version: Literal["1.0"] = "1.0"
    entry_kind: Literal[SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT] = (
        SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT
    )
    request_limit_binding: SchedulerTruncationRecoveryRequestLimitBinding
    family_index: int = Field(
        ge=0,
        lt=SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES,
    )
    family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    parent_kind: SchedulerTruncationRecoveryParentKind
    parent_family_id: str | None = Field(
        default=None,
        pattern=_RECOVERY_FAMILY_ID_PATTERN,
    )
    parent_terminal_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    requested_surface_manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest
    truncation_projection: CandidateReviewTruncationProjection
    recovery_plan: TruncationRecoveryPlan
    request_count_before_family: int = Field(
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    request_count_after_family: int = Field(
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    request_limit_count_before_family: int = Field(ge=1, le=2**63 - 1)
    request_limit_count_after_family: int = Field(ge=1, le=2**63 - 1)
    request_limit_attempts_reserved_for_family: int = Field(
        ge=2,
        le=2 * TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    )

    @classmethod
    def build(
        cls,
        *,
        request_limit_binding: SchedulerTruncationRecoveryRequestLimitBinding,
        family_index: int,
        parent_kind: SchedulerTruncationRecoveryParentKind,
        parent_family_id: str | None,
        parent_terminal_result_sha256: str,
        requested_surface_manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest,
        truncation_projection: CandidateReviewTruncationProjection,
        recovery_plan: TruncationRecoveryPlan,
        request_count_before_family: int,
        request_limit_count_before_family: int,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryFamilyRoot:
        binding = SchedulerTruncationRecoveryRequestLimitBinding.model_validate(
            request_limit_binding.model_dump(mode="python"),
            strict=True,
        )
        projection = CandidateReviewTruncationProjection.model_validate_json(
            truncation_projection.model_dump_json(),
            strict=True,
        )
        surface_manifest = SchedulerTruncationRecoveryRequestedSurfaceManifest.model_validate_json(
            requested_surface_manifest.model_dump_json(),
            strict=True,
        )
        plan = TruncationRecoveryPlan.model_validate(
            recovery_plan.model_dump(mode="python"),
            strict=True,
        )
        after = request_count_before_family + len(plan.children)
        family_reserved_attempts = sum(child.reserved_provider_attempts for child in plan.children)
        request_limit_count_after_family = (
            request_limit_count_before_family + family_reserved_attempts
        )
        values: dict[str, Any] = {
            **_entry_values(
                campaign_id=plan.parent.campaign_id,
                request_limit_id=binding.request_limit_id,
                request_limit_binding_sha256=binding.binding_sha256,
                entry_kind=SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            ),
            "request_limit_binding": binding,
            "family_index": family_index,
            "parent_kind": parent_kind,
            "parent_family_id": parent_family_id,
            "parent_terminal_result_sha256": parent_terminal_result_sha256,
            "requested_surface_manifest": surface_manifest,
            "truncation_projection": projection,
            "recovery_plan": plan,
            "request_count_before_family": request_count_before_family,
            "request_count_after_family": after,
            "request_limit_count_before_family": request_limit_count_before_family,
            "request_limit_count_after_family": request_limit_count_after_family,
            "request_limit_attempts_reserved_for_family": family_reserved_attempts,
        }
        family_id = "scheduler-recovery-family-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-family.v1",
                "campaign_id": plan.parent.campaign_id,
                "request_limit_binding_sha256": binding.binding_sha256,
                "parent_task_id": plan.parent.parent_task_id,
                "parent_terminal_result_sha256": parent_terminal_result_sha256,
                "requested_surface_manifest_evidence_sha256": (
                    surface_manifest.manifest_evidence_sha256
                ),
                "recovery_plan_sha256": plan.plan_sha256,
            }
        )
        body = {**values, "family_id": family_id}
        return cls(**body, entry_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def family_root_is_projection_bound_and_exact(self) -> Self:
        rebuilt_parent = rebuild_truncation_recovery_parent_from_projection(
            claimed_parent=self.recovery_plan.parent,
            projection=self.truncation_projection,
        )
        expected_family_id = "scheduler-recovery-family-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-family.v1",
                "campaign_id": self.recovery_plan.parent.campaign_id,
                "request_limit_binding_sha256": (self.request_limit_binding.binding_sha256),
                "parent_task_id": self.recovery_plan.parent.parent_task_id,
                "parent_terminal_result_sha256": self.parent_terminal_result_sha256,
                "requested_surface_manifest_evidence_sha256": (
                    self.requested_surface_manifest.manifest_evidence_sha256
                ),
                "recovery_plan_sha256": self.recovery_plan.plan_sha256,
            }
        )
        if (
            self.campaign_id != self.recovery_plan.parent.campaign_id
            or self.request_limit_binding.campaign_id != self.campaign_id
            or self.request_limit_binding_sha256 != self.request_limit_binding.binding_sha256
            or self.request_limit_binding.policy_sha256 != self.recovery_plan.policy.policy_sha256
            or self.requested_surface_manifest.requested_surface_manifest_sha256
            != self.recovery_plan.parent.requested_surface_manifest_sha256
            or not set(self.recovery_plan.parent.requested_surface_ids)
            <= set(self.requested_surface_manifest.requested_surface_ids)
            or rebuilt_parent != self.recovery_plan.parent
            or self.family_id != expected_family_id
            or self.request_count_before_family
            != self.recovery_plan.resources.recovery_requests_consumed
            or self.request_count_after_family
            != self.request_count_before_family + len(self.recovery_plan.children)
            or self.request_limit_attempts_reserved_for_family
            != sum(child.reserved_provider_attempts for child in self.recovery_plan.children)
            or self.request_limit_count_after_family
            != self.request_limit_count_before_family
            + self.request_limit_attempts_reserved_for_family
            or self.request_limit_count_after_family
            > self.request_limit_binding.request_limit_maximum
        ):
            raise ValueError("scheduler truncation recovery family root is inconsistent")
        parent = self.recovery_plan.parent
        if self.parent_kind is SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK:
            if (
                self.parent_family_id is not None
                or re.fullmatch(_ROOT_TASK_ID_PATTERN, parent.parent_task_id) is None
                or parent.parent_logical_request_id != self.request_limit_id
                or parent.current_depth != 0
                or parent.requested_surface_ids
                != self.requested_surface_manifest.requested_surface_ids
            ):
                raise ValueError("root recovery family lacks its original scheduler request")
        elif (
            self.parent_family_id is None
            or re.fullmatch(_RECOVERY_TASK_ID_PATTERN, parent.parent_task_id) is None
            or re.fullmatch(_RECOVERY_REQUEST_ID_PATTERN, parent.parent_logical_request_id) is None
            or parent.current_depth == 0
        ):
            raise ValueError("nested recovery family lacks its exact recovery parent")
        if (
            self.recovery_plan.disposition is not TruncationRecoveryDisposition.PLANNED
            or len(self.recovery_plan.children) != 2
        ):
            raise ValueError("scheduler recovery family requires one strict binary child split")
        return self


class SchedulerTruncationRecoveryChildActivation(_SchedulerTruncationRecoveryEntry):
    """Exact child request material persisted before a dispatch marker may exist."""

    schema_version: Literal["1.0"] = "1.0"
    entry_kind: Literal[SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED] = (
        SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED
    )
    family_index: int = Field(
        ge=0,
        lt=SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES,
    )
    family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    family_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_ordinal: int = Field(ge=0, le=1)
    child_task_id: str = Field(pattern=_RECOVERY_TASK_ID_PATTERN)
    child_logical_request_id: str = Field(pattern=_RECOVERY_REQUEST_ID_PATTERN)
    child_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_surface_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_SURFACES)
    global_request_ordinal: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    request_limit_count_before_child: int = Field(ge=1, le=2**63 - 1)
    request_limit_count_after_child: int = Field(ge=1, le=2**63 - 1)
    request_limit_maximum: int = Field(ge=1, le=2**63 - 1)
    request_role: str | None = Field(
        default=None,
        pattern=_ROLE_ID_PATTERN,
        exclude_if=lambda value: value is None,
    )
    requested_model: str | None = Field(
        default=None,
        pattern=_MODEL_ID_PATTERN,
        exclude_if=lambda value: value is None,
    )
    actual_input_sha256: str = Field(pattern=_SHA256_PATTERN)
    system_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    user_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    activation_id: str = Field(pattern=_RECOVERY_ACTIVATION_ID_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        family: SchedulerTruncationRecoveryFamilyRoot,
        child: TruncationRecoveryChildPlan,
        actual_input_sha256: str,
        system_prompt_sha256: str,
        user_prompt_sha256: str,
        provider_prompt_sha256: str,
        response_schema_sha256: str,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildActivation:
        if child not in family.recovery_plan.children:
            raise ValueError("scheduler truncation recovery activation child is not planned")
        preceding_reserved_attempts = sum(
            item.reserved_provider_attempts
            for item in family.recovery_plan.children
            if item.ordinal < child.ordinal
        )
        request_limit_count_before_child = (
            family.request_limit_count_before_family + preceding_reserved_attempts
        )
        parent_request = family.request_limit_binding.parent_request_limit_reservation
        values: dict[str, Any] = {
            **_entry_values(
                campaign_id=family.campaign_id,
                request_limit_id=family.request_limit_id,
                request_limit_binding_sha256=family.request_limit_binding_sha256,
                entry_kind=SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            ),
            "family_index": family.family_index,
            "family_id": family.family_id,
            "family_root_sha256": family.entry_sha256,
            "child_ordinal": child.ordinal,
            "child_task_id": child.child_task_id,
            "child_logical_request_id": child.child_logical_request_id,
            "child_plan_sha256": child.child_plan_sha256,
            "child_surface_ids": child.surface_ids,
            "global_request_ordinal": (family.request_count_before_family + child.ordinal + 1),
            "request_limit_count_before_child": request_limit_count_before_child,
            "request_limit_count_after_child": (
                request_limit_count_before_child + child.reserved_provider_attempts
            ),
            "request_limit_maximum": family.request_limit_binding.request_limit_maximum,
            "request_role": parent_request.role,
            "requested_model": parent_request.exact_model_id,
            "actual_input_sha256": actual_input_sha256,
            "system_prompt_sha256": system_prompt_sha256,
            "user_prompt_sha256": user_prompt_sha256,
            "provider_prompt_sha256": provider_prompt_sha256,
            "response_schema_sha256": response_schema_sha256,
        }
        activation_id = "scheduler-recovery-activation-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-activation.v1",
                "family_id": family.family_id,
                "child_task_id": child.child_task_id,
                "actual_input_sha256": actual_input_sha256,
                "provider_prompt_sha256": provider_prompt_sha256,
                "response_schema_sha256": response_schema_sha256,
            }
        )
        body = {**values, "activation_id": activation_id}
        return cls(**body, entry_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def activation_identity_and_hashes_are_exact(self) -> Self:
        _require_canonical_surface_ids(self.child_surface_ids, label="activation surfaces")
        expected_id = "scheduler-recovery-activation-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-activation.v1",
                "family_id": self.family_id,
                "child_task_id": self.child_task_id,
                "actual_input_sha256": self.actual_input_sha256,
                "provider_prompt_sha256": self.provider_prompt_sha256,
                "response_schema_sha256": self.response_schema_sha256,
            }
        )
        if (
            self.request_limit_count_after_child <= self.request_limit_count_before_child
            or self.request_limit_count_after_child > self.request_limit_maximum
            or self.activation_id != expected_id
        ):
            raise ValueError("scheduler truncation recovery activation ID is inconsistent")
        return self


class SchedulerTruncationRecoveryChildPreflightResult(_SchedulerTruncationRecoveryEntry):
    """Activation-bound local terminal with provably zero provider consumption."""

    schema_version: Literal["1.0"] = "1.0"
    entry_kind: Literal[SchedulerTruncationRecoveryEntryKind.CHILD_PREFLIGHT_TERMINAL] = (
        SchedulerTruncationRecoveryEntryKind.CHILD_PREFLIGHT_TERMINAL
    )
    family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    family_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_task_id: str = Field(pattern=_RECOVERY_TASK_ID_PATTERN)
    child_logical_request_id: str = Field(pattern=_RECOVERY_REQUEST_ID_PATTERN)
    child_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_surface_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_SURFACES)
    global_request_ordinal: int = Field(ge=1, le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS)
    activation_id: str = Field(pattern=_RECOVERY_ACTIVATION_ID_PATTERN)
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    result_origin: Literal[SchedulerTruncationRecoveryResultOrigin.PREFLIGHT] = (
        SchedulerTruncationRecoveryResultOrigin.PREFLIGHT
    )
    terminal_status: SchedulerTruncationRecoveryTerminalStatus
    terminal_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    reserved_provider_attempts: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    )
    reserved_completion_tokens: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
    )
    reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    accounted_provider_attempts: Literal[0] = 0
    accounted_completion_tokens: Literal[0] = 0
    accounted_cost_usd_exact: Literal["0"] = "0"
    provider_attempt_evidence_sha256: Literal[None] = None
    cost_disposition: Literal[SchedulerTruncationRecoveryCostDisposition.ACTUAL_ACCOUNTED] = (
        SchedulerTruncationRecoveryCostDisposition.ACTUAL_ACCOUNTED
    )
    result_id: str = Field(pattern=_RECOVERY_RESULT_ID_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        child: TruncationRecoveryChildPlan,
        activation: SchedulerTruncationRecoveryChildActivation,
        terminal_status: SchedulerTruncationRecoveryTerminalStatus,
        terminal_evidence_sha256: str,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildPreflightResult:
        values: dict[str, Any] = {
            **_entry_values(
                campaign_id=activation.campaign_id,
                request_limit_id=activation.request_limit_id,
                request_limit_binding_sha256=activation.request_limit_binding_sha256,
                entry_kind=SchedulerTruncationRecoveryEntryKind.CHILD_PREFLIGHT_TERMINAL,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            ),
            "family_id": activation.family_id,
            "family_root_sha256": activation.family_root_sha256,
            "child_task_id": activation.child_task_id,
            "child_logical_request_id": activation.child_logical_request_id,
            "child_plan_sha256": activation.child_plan_sha256,
            "child_surface_ids": child.surface_ids,
            "global_request_ordinal": activation.global_request_ordinal,
            "activation_id": activation.activation_id,
            "activation_sha256": activation.entry_sha256,
            "result_origin": SchedulerTruncationRecoveryResultOrigin.PREFLIGHT,
            "terminal_status": terminal_status,
            "terminal_evidence_sha256": terminal_evidence_sha256,
            "reserved_provider_attempts": child.reserved_provider_attempts,
            "reserved_completion_tokens": child.reserved_completion_tokens,
            "reserved_usd_exact": child.reserved_usd_exact,
            "accounted_provider_attempts": 0,
            "accounted_completion_tokens": 0,
            "accounted_cost_usd_exact": "0",
            "provider_attempt_evidence_sha256": None,
            "cost_disposition": SchedulerTruncationRecoveryCostDisposition.ACTUAL_ACCOUNTED,
        }
        result_id = "scheduler-recovery-result-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-preflight-result.v1",
                "activation_id": activation.activation_id,
                "terminal_status": terminal_status,
                "terminal_evidence_sha256": terminal_evidence_sha256,
            }
        )
        body = {**values, "result_id": result_id}
        return cls(**body, entry_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def preflight_terminal_is_zero_cost_and_activation_bound(self) -> Self:
        allowed = {
            SchedulerTruncationRecoveryTerminalStatus.FAILED,
            SchedulerTruncationRecoveryTerminalStatus.INVALID,
            SchedulerTruncationRecoveryTerminalStatus.UNBOUND,
            SchedulerTruncationRecoveryTerminalStatus.INCONCLUSIVE,
        }
        expected_id = "scheduler-recovery-result-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-preflight-result.v1",
                "activation_id": self.activation_id,
                "terminal_status": self.terminal_status,
                "terminal_evidence_sha256": self.terminal_evidence_sha256,
            }
        )
        _require_canonical_surface_ids(self.child_surface_ids, label="preflight result surfaces")
        _canonical_usd(self.reserved_usd_exact, label="preflight reserved cost")
        if self.terminal_status not in allowed or self.result_id != expected_id:
            raise ValueError("scheduler recovery preflight terminal is invalid")
        return self


class SchedulerTruncationRecoveryChildDispatch(_SchedulerTruncationRecoveryEntry):
    """Durable pre-transport marker; the marker is not a dispatch capability."""

    schema_version: Literal["1.0"] = "1.0"
    entry_kind: Literal[SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED] = (
        SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED
    )
    family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    family_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_task_id: str = Field(pattern=_RECOVERY_TASK_ID_PATTERN)
    child_logical_request_id: str = Field(pattern=_RECOVERY_REQUEST_ID_PATTERN)
    child_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    global_request_ordinal: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    request_limit_count_before_child: int = Field(ge=1, le=2**63 - 1)
    request_limit_count_after_child: int = Field(ge=1, le=2**63 - 1)
    request_limit_maximum: int = Field(ge=1, le=2**63 - 1)
    activation_id: str = Field(pattern=_RECOVERY_ACTIVATION_ID_PATTERN)
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    dispatch_id: str = Field(pattern=_RECOVERY_DISPATCH_ID_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        activation: SchedulerTruncationRecoveryChildActivation,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildDispatch:
        values: dict[str, Any] = {
            **_entry_values(
                campaign_id=activation.campaign_id,
                request_limit_id=activation.request_limit_id,
                request_limit_binding_sha256=(activation.request_limit_binding_sha256),
                entry_kind=SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            ),
            "family_id": activation.family_id,
            "family_root_sha256": activation.family_root_sha256,
            "child_task_id": activation.child_task_id,
            "child_logical_request_id": activation.child_logical_request_id,
            "child_plan_sha256": activation.child_plan_sha256,
            "global_request_ordinal": activation.global_request_ordinal,
            "request_limit_count_before_child": activation.request_limit_count_before_child,
            "request_limit_count_after_child": activation.request_limit_count_after_child,
            "request_limit_maximum": activation.request_limit_maximum,
            "activation_id": activation.activation_id,
            "activation_sha256": activation.entry_sha256,
        }
        dispatch_id = "scheduler-recovery-dispatch-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-dispatch.v1",
                "activation_id": activation.activation_id,
                "activation_sha256": activation.entry_sha256,
            }
        )
        body = {**values, "dispatch_id": dispatch_id}
        return cls(**body, entry_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def dispatch_identity_is_exact(self) -> Self:
        expected_id = "scheduler-recovery-dispatch-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-dispatch.v1",
                "activation_id": self.activation_id,
                "activation_sha256": self.activation_sha256,
            }
        )
        if self.dispatch_id != expected_id:
            raise ValueError("scheduler truncation recovery dispatch ID is inconsistent")
        return self


def _require_every_field_supplied(model: BaseModel, *, label: str) -> None:
    if set(type(model).model_fields) - model.model_fields_set:
        raise ValueError(f"scheduler recovery {label} relies on omitted defaults")


def _freeze_exact_model[ModelT: BaseModel](
    expected_type: type[ModelT],
    value: ModelT,
    *,
    label: str,
) -> ModelT:
    if type(value) is not expected_type:
        raise TypeError(f"scheduler recovery {label} has an invalid exact type")
    try:
        frozen = expected_type.model_validate(value.model_dump(mode="python"), strict=True)
    except (AttributeError, TypeError, ValueError):
        raise ValueError(f"scheduler recovery {label} is invalid") from None
    _require_every_field_supplied(frozen, label=label)
    return frozen


def _usage_record_sha256(usage: UsageRecord) -> str:
    return _canonical_sha256(usage.model_dump(mode="json"))


def _typed_provider_attempt_sha256(
    *,
    activation_sha256: str,
    usage_record_sha256: str,
) -> str:
    return _canonical_sha256(
        {
            "domain": "mmaudit.scheduler.truncation-recovery-typed-provider-attempt.v1",
            "activation_sha256": activation_sha256,
            "usage_record_sha256": usage_record_sha256,
        }
    )


def _typed_completion_sha256(
    *,
    activation_sha256: str,
    usage_record_sha256: str,
    normalization_evidence_sha256: str,
    normalized_batch_sha256: str,
    requested_surface_manifest_sha256: str,
    output_artifact_sha256: str,
    specialist_accepted_outcome_sha256: str | None = None,
) -> str:
    values = {
        "domain": (
            "mmaudit.scheduler.truncation-recovery-typed-completion.v1.2"
            if specialist_accepted_outcome_sha256 is not None
            else "mmaudit.scheduler.truncation-recovery-typed-completion.v1"
        ),
        "activation_sha256": activation_sha256,
        "usage_record_sha256": usage_record_sha256,
        "normalization_evidence_sha256": normalization_evidence_sha256,
        "normalized_batch_sha256": normalized_batch_sha256,
        "requested_surface_manifest_sha256": requested_surface_manifest_sha256,
        "output_artifact_sha256": output_artifact_sha256,
    }
    if specialist_accepted_outcome_sha256 is not None:
        values["specialist_accepted_outcome_sha256"] = specialist_accepted_outcome_sha256
    return _canonical_sha256(values)


def _freeze_exact_specialist_success_outcome(
    *,
    specialist_accepted_outcome: SpecialistAcceptedOutcome | None,
    activation: SchedulerTruncationRecoveryChildActivation,
    usage: UsageRecord,
    requested_surface_count: int,
    output_artifact_sha256: str,
) -> SpecialistAcceptedOutcome | None:
    """Bind accepted investigator credit to one exact successful recovery request."""

    requires_outcome = activation.request_role in _SPECIALIST_INVESTIGATOR_REQUEST_ROLES
    if not requires_outcome:
        if specialist_accepted_outcome is not None:
            raise ValueError("non-investigator recovery child cannot carry a specialist outcome")
        return None
    if specialist_accepted_outcome is None:
        raise ValueError("specialist investigator recovery child lacks an accepted outcome")
    exact_outcome = _freeze_exact_model(
        SpecialistAcceptedOutcome,
        specialist_accepted_outcome,
        label="specialist accepted outcome",
    )
    raw_context = usage.routing.get("context_request_evidence")
    if not isinstance(raw_context, Mapping):
        raise ValueError("specialist recovery child lacks typed context-request custody")
    try:
        context = ContextRequestEvidence.model_validate(raw_context)
    except (TypeError, ValueError):
        raise ValueError("specialist recovery child context-request custody is invalid") from None
    _require_every_field_supplied(context, label="specialist context-request evidence")
    assert activation.request_role is not None
    specialist_role = activation.request_role.removeprefix("specialist:")
    if (
        exact_outcome.outcome_kind is not SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
        or exact_outcome.request_id != activation.child_logical_request_id
        or exact_outcome.request_id != usage.request_id
        or exact_outcome.request_role != activation.request_role
        or exact_outcome.request_role != usage.role
        or exact_outcome.specialist_role != specialist_role
        or exact_outcome.validated_response_sha256 != usage.validated_response_sha256
        or exact_outcome.context_request_evidence_sha256 != context.evidence_sha256
        or usage.routing.get("context_request_evidence_sha256") != context.evidence_sha256
        or context.request_id != activation.child_logical_request_id
        or context.request_role != activation.request_role
        or context.rendered_sha256 != activation.user_prompt_sha256
        or exact_outcome.requested_surface_count != requested_surface_count
        or exact_outcome.surface_review_artifact_sha256 != output_artifact_sha256
    ):
        raise ValueError("specialist recovery accepted outcome custody is inconsistent")
    return exact_outcome


def _require_exact_request_limit_reservation(
    *,
    usage: UsageRecord,
    activation: SchedulerTruncationRecoveryChildActivation,
    reservation: AtomicRequestLimitReservationEvidence,
) -> None:
    try:
        inventory = recovery_atomic_request_limit_reservations_from_usage(
            usage,
            request_limit_scope=activation.request_limit_id,
            request_limit_count_before=activation.request_limit_count_before_child,
        )
    except ValueError:
        raise ValueError("typed recovery usage request-limit inventory is invalid") from None
    if (
        inventory != (reservation,)
        or reservation.request_limit_count_after != activation.request_limit_count_after_child
        or reservation.request_limit_maximum != activation.request_limit_maximum
    ):
        raise ValueError("typed recovery request-limit root or count is inconsistent")


def _require_exact_typed_usage(
    *,
    usage: UsageRecord,
    activation: SchedulerTruncationRecoveryChildActivation,
    reservation: AtomicRequestLimitReservationEvidence,
    child: TruncationRecoveryChildPlan | None,
    truncated_envelope_selected_model: str | None = None,
) -> tuple[str, str]:
    routed_selected_model = usage.routing.get("selected_model")
    selected_model_is_bound = (
        routed_selected_model == usage.actual_model
        if truncated_envelope_selected_model is None
        else usage.actual_model == truncated_envelope_selected_model
        and routed_selected_model in {None, usage.actual_model}
    )
    if (
        usage.request_id != activation.child_logical_request_id
        or activation.request_role is None
        or activation.requested_model is None
        or usage.role != activation.request_role
        or usage.requested_model != activation.requested_model
        or usage.prompt_sha256 != activation.provider_prompt_sha256
        or usage.user_prompt_sha256 != activation.user_prompt_sha256
        or usage.schema_sha256 != activation.response_schema_sha256
        or usage.attempts != 1
        or usage.retry_count != 0
        or usage.total_tokens != usage.prompt_tokens + usage.completion_tokens
        or usage.accounted_cost_usd_exact is None
        or usage.actual_model is None
        or usage.returned_model is None
        or not selected_model_is_bound
        or usage.routing.get("schema_sha256") != usage.schema_sha256
        or usage.routing.get("finish_reason") != usage.finish_reason
    ):
        raise ValueError("typed recovery usage differs from its activation or request")
    _require_exact_request_limit_reservation(
        usage=usage,
        activation=activation,
        reservation=reservation,
    )
    accounted_cost = _canonical_usage_usd(
        usage.accounted_cost_usd_exact,
        label="typed usage accounted cost",
    )
    if child is not None and (
        usage.completion_tokens > child.reserved_completion_tokens
        or Decimal(accounted_cost) > Decimal(child.reserved_usd_exact)
        or child.reserved_provider_attempts != 1
    ):
        raise ValueError("typed recovery usage exceeds its child reservation")
    usage_sha256 = _usage_record_sha256(usage)
    return accounted_cost, usage_sha256


def _expected_truncated_envelope_routing(
    envelope: CandidateReviewTruncatedEnvelopeEvidence,
) -> dict[str, Any]:
    return {
        "candidate_review_truncated_envelope_evidence": envelope.model_dump(mode="json"),
        "candidate_review_truncated_envelope_sha256": envelope.evidence_sha256,
    }


def _expected_truncation_projection_routing(
    projection: CandidateReviewTruncationProjection,
) -> dict[str, Any]:
    return {
        "candidate_review_truncation_projection_sha256": projection.evidence_sha256,
        "candidate_review_truncation_termination": projection.termination.value,
        "candidate_review_truncation_findings_state": projection.findings_state.value,
        "candidate_review_truncation_surface_reviews_state": (
            projection.surface_reviews_state.value
        ),
        "candidate_review_truncation_summary_state": projection.summary_state.value,
        "candidate_review_truncation_stream_integrity_valid": projection.stream_integrity_valid,
        "candidate_review_truncation_document_complete": projection.document_complete,
        "candidate_review_truncation_declared_finding_count": projection.declared_finding_count,
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


class SchedulerTruncationRecoveryChildResult(_SchedulerTruncationRecoveryEntry):
    """Structural terminal custody; neither legacy nor typed results grant credit."""

    schema_version: Literal["1.0", "1.1", "1.2"] = "1.0"
    entry_kind: Literal[SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL] = (
        SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL
    )
    family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    family_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_task_id: str = Field(pattern=_RECOVERY_TASK_ID_PATTERN)
    child_logical_request_id: str = Field(pattern=_RECOVERY_REQUEST_ID_PATTERN)
    child_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    child_surface_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_SURFACES)
    global_request_ordinal: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    )
    activation_id: str = Field(pattern=_RECOVERY_ACTIVATION_ID_PATTERN)
    activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    dispatch_id: str = Field(pattern=_RECOVERY_DISPATCH_ID_PATTERN)
    dispatch_sha256: str = Field(pattern=_SHA256_PATTERN)
    result_origin: SchedulerTruncationRecoveryResultOrigin
    terminal_status: SchedulerTruncationRecoveryTerminalStatus
    terminal_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    provider_attempt_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    runtime_completion_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    runtime_usage_record_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    runtime_output_artifact_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    runtime_specialist_accepted_outcome_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    runtime_activation: SchedulerTruncationRecoveryChildActivation | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_request_limit_reservation: AtomicRequestLimitReservationEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_usage_record: UsageRecord | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_normalization_evidence: CandidateReviewNormalizationEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_normalized_batch: CandidateReviewBatch | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_requested_surface_requests: tuple[ModelSurfaceReviewRequest, ...] | None = Field(
        default=None,
        min_length=1,
        max_length=_MAX_SURFACES,
        exclude_if=lambda value: value is None,
    )
    runtime_output_artifact: ModelSurfaceReviewArtifact | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_specialist_accepted_outcome: SpecialistAcceptedOutcome | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runtime_truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    truncation_projection: CandidateReviewTruncationProjection | None = None
    completed_surface_ids: tuple[str, ...] = Field(max_length=_MAX_SURFACES)
    retained_surface_ids: tuple[str, ...] = Field(max_length=_MAX_SURFACES)
    reserved_provider_attempts: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    )
    reserved_completion_tokens: int = Field(
        ge=1,
        le=TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
    )
    reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    accounted_provider_attempts: int = Field(
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_PROVIDER_ATTEMPTS,
    )
    accounted_completion_tokens: int = Field(
        ge=0,
        le=TRUNCATION_RECOVERY_MAX_CHILD_COMPLETION_TOKENS,
    )
    accounted_cost_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    cost_disposition: SchedulerTruncationRecoveryCostDisposition
    result_id: str = Field(pattern=_RECOVERY_RESULT_ID_PATTERN)

    @field_validator("runtime_usage_record", mode="before")
    @classmethod
    def recover_json_usage_timestamps(cls, value: object) -> object:
        """Preserve strict JSON datetime semantics across UsageRecord's before validator."""

        if not isinstance(value, Mapping):
            return value
        recovered = dict(value)
        datetime_adapter = TypeAdapter(datetime)
        for field_name in ("timestamp", "started_at", "ended_at"):
            raw = recovered.get(field_name)
            if isinstance(raw, str):
                recovered[field_name] = datetime_adapter.validate_json(
                    json.dumps(raw),
                    strict=True,
                )
        return recovered

    @classmethod
    def build_typed_success(
        cls,
        *,
        child: TruncationRecoveryChildPlan,
        activation: SchedulerTruncationRecoveryChildActivation,
        dispatch: SchedulerTruncationRecoveryChildDispatch,
        usage_record: UsageRecord,
        normalization_evidence: CandidateReviewNormalizationEvidence,
        normalized_batch: CandidateReviewBatch,
        requested_surface_requests: Iterable[ModelSurfaceReviewRequest],
        output_artifact: ModelSurfaceReviewArtifact,
        specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildResult:
        """Build exact successful runtime custody without authorizing its output."""

        frozen_activation = _freeze_exact_model(
            SchedulerTruncationRecoveryChildActivation,
            activation,
            label="typed activation",
        )
        if type(usage_record) is not UsageRecord or not is_recovery_creditable_usage_record(
            usage_record,
            request_limit_scope=frozen_activation.request_limit_id,
            request_limit_count_before=(frozen_activation.request_limit_count_before_child),
        ):
            raise ValueError("successful recovery child lacks owned creditable usage")
        frozen_usage = usage_record
        frozen_normalization = _freeze_exact_model(
            CandidateReviewNormalizationEvidence,
            normalization_evidence,
            label="typed normalization evidence",
        )
        frozen_batch = _freeze_exact_model(
            CandidateReviewBatch,
            normalized_batch,
            label="typed normalized batch",
        )
        request_items = _bounded_tuple(
            requested_surface_requests,
            limit=_MAX_SURFACES,
            label="typed requested surfaces",
        )
        frozen_requests = tuple(
            _freeze_exact_model(
                ModelSurfaceReviewRequest,
                request,
                label="typed surface request",
            )
            for request in request_items
        )
        frozen_artifact = _freeze_exact_model(
            ModelSurfaceReviewArtifact,
            output_artifact,
            label="typed output artifact",
        )
        reservation = cls._request_limit_reservation_from_usage(
            frozen_usage,
            activation=frozen_activation,
        )
        accounted_cost, usage_sha256 = _require_exact_typed_usage(
            usage=frozen_usage,
            activation=frozen_activation,
            reservation=reservation,
            child=child,
        )
        frozen_specialist_outcome = _freeze_exact_specialist_success_outcome(
            specialist_accepted_outcome=specialist_accepted_outcome,
            activation=frozen_activation,
            usage=frozen_usage,
            requested_surface_count=len(frozen_requests),
            output_artifact_sha256=frozen_artifact.artifact_sha256,
        )
        specialist_outcome_sha256 = (
            frozen_specialist_outcome.evidence_sha256
            if frozen_specialist_outcome is not None
            else None
        )
        completion_sha256 = _typed_completion_sha256(
            activation_sha256=frozen_activation.entry_sha256,
            usage_record_sha256=usage_sha256,
            normalization_evidence_sha256=frozen_normalization.evidence_sha256,
            normalized_batch_sha256=frozen_normalization.normalized_batch_sha256,
            requested_surface_manifest_sha256=(frozen_artifact.requested_surface_manifest_sha256),
            output_artifact_sha256=frozen_artifact.artifact_sha256,
            specialist_accepted_outcome_sha256=specialist_outcome_sha256,
        )
        return cls._build(
            schema_version="1.2" if frozen_specialist_outcome is not None else "1.1",
            child=child,
            activation=frozen_activation,
            dispatch=dispatch,
            result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
            terminal_status=SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=completion_sha256,
            provider_attempt_evidence_sha256=_typed_provider_attempt_sha256(
                activation_sha256=frozen_activation.entry_sha256,
                usage_record_sha256=usage_sha256,
            ),
            accounted_provider_attempts=1,
            accounted_completion_tokens=frozen_usage.completion_tokens,
            accounted_cost_usd_exact=accounted_cost,
            runtime_completion_evidence_sha256=completion_sha256,
            runtime_usage_record_sha256=usage_sha256,
            runtime_output_artifact_sha256=frozen_artifact.artifact_sha256,
            runtime_specialist_accepted_outcome_sha256=specialist_outcome_sha256,
            runtime_request_limit_reservation=reservation,
            runtime_usage_record=frozen_usage,
            runtime_normalization_evidence=frozen_normalization,
            runtime_normalized_batch=frozen_batch,
            runtime_requested_surface_requests=frozen_requests,
            runtime_output_artifact=frozen_artifact,
            runtime_specialist_accepted_outcome=frozen_specialist_outcome,
            runtime_truncated_envelope_evidence=None,
            truncation_projection=None,
            cost_disposition=SchedulerTruncationRecoveryCostDisposition.ACTUAL_ACCOUNTED,
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )

    @classmethod
    def build_typed_truncated(
        cls,
        *,
        child: TruncationRecoveryChildPlan,
        activation: SchedulerTruncationRecoveryChildActivation,
        dispatch: SchedulerTruncationRecoveryChildDispatch,
        failed_usage_record: UsageRecord,
        truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence,
        truncation_projection: CandidateReviewTruncationProjection,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildResult:
        """Build exact v1.1 truncated runtime custody with no provisional credit."""

        frozen_activation = _freeze_exact_model(
            SchedulerTruncationRecoveryChildActivation,
            activation,
            label="typed activation",
        )
        if type(failed_usage_record) is not UsageRecord or not is_recovery_accountable_usage_record(
            failed_usage_record,
            request_limit_scope=frozen_activation.request_limit_id,
            request_limit_count_before=(frozen_activation.request_limit_count_before_child),
        ):
            raise ValueError("truncated recovery child lacks owned accountable usage")
        frozen_usage = failed_usage_record
        frozen_envelope = _freeze_exact_model(
            CandidateReviewTruncatedEnvelopeEvidence,
            truncated_envelope_evidence,
            label="typed truncated envelope",
        )
        frozen_projection = _freeze_exact_model(
            CandidateReviewTruncationProjection,
            truncation_projection,
            label="typed truncation projection",
        )
        reservation = cls._request_limit_reservation_from_usage(
            frozen_usage,
            activation=frozen_activation,
        )
        accounted_cost, usage_sha256 = _require_exact_typed_usage(
            usage=frozen_usage,
            activation=frozen_activation,
            reservation=reservation,
            child=child,
            truncated_envelope_selected_model=frozen_envelope.selected_model,
        )
        return cls._build(
            schema_version="1.1",
            child=child,
            activation=frozen_activation,
            dispatch=dispatch,
            result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
            terminal_status=SchedulerTruncationRecoveryTerminalStatus.TRUNCATED,
            terminal_evidence_sha256=frozen_projection.evidence_sha256,
            provider_attempt_evidence_sha256=_typed_provider_attempt_sha256(
                activation_sha256=frozen_activation.entry_sha256,
                usage_record_sha256=usage_sha256,
            ),
            accounted_provider_attempts=1,
            accounted_completion_tokens=frozen_usage.completion_tokens,
            accounted_cost_usd_exact=accounted_cost,
            runtime_completion_evidence_sha256=None,
            runtime_usage_record_sha256=usage_sha256,
            runtime_output_artifact_sha256=None,
            runtime_request_limit_reservation=reservation,
            runtime_usage_record=frozen_usage,
            runtime_normalization_evidence=None,
            runtime_normalized_batch=None,
            runtime_requested_surface_requests=None,
            runtime_output_artifact=None,
            runtime_truncated_envelope_evidence=frozen_envelope,
            truncation_projection=frozen_projection,
            cost_disposition=SchedulerTruncationRecoveryCostDisposition.ACTUAL_ACCOUNTED,
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )

    @staticmethod
    def _request_limit_reservation_from_usage(
        usage: UsageRecord,
        *,
        activation: SchedulerTruncationRecoveryChildActivation,
    ) -> AtomicRequestLimitReservationEvidence:
        try:
            inventory = recovery_atomic_request_limit_reservations_from_usage(
                usage,
                request_limit_scope=activation.request_limit_id,
                request_limit_count_before=activation.request_limit_count_before_child,
            )
        except ValueError:
            raise ValueError("typed recovery request-limit reservation is invalid") from None
        if len(inventory) != 1:
            raise ValueError("typed recovery requires one exact request-limit reservation")
        reservation = inventory[0]
        if (
            reservation.request_limit_count_after != activation.request_limit_count_after_child
            or reservation.request_limit_maximum != activation.request_limit_maximum
        ):
            raise ValueError("typed recovery request-limit root or count is inconsistent")
        _require_every_field_supplied(reservation, label="typed request-limit reservation")
        return reservation

    @classmethod
    def build_runtime(
        cls,
        *,
        child: TruncationRecoveryChildPlan,
        dispatch: SchedulerTruncationRecoveryChildDispatch,
        terminal_status: SchedulerTruncationRecoveryTerminalStatus,
        terminal_evidence_sha256: str,
        provider_attempt_evidence_sha256: str | None,
        accounted_provider_attempts: int,
        accounted_completion_tokens: int,
        accounted_cost_usd_exact: str,
        runtime_completion_evidence_sha256: str | None = None,
        runtime_usage_record_sha256: str | None = None,
        runtime_output_artifact_sha256: str | None = None,
        truncation_projection: CandidateReviewTruncationProjection | None = None,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildResult:
        return cls._build(
            schema_version="1.0",
            child=child,
            activation=None,
            dispatch=dispatch,
            result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
            terminal_status=terminal_status,
            terminal_evidence_sha256=terminal_evidence_sha256,
            provider_attempt_evidence_sha256=provider_attempt_evidence_sha256,
            accounted_provider_attempts=accounted_provider_attempts,
            accounted_completion_tokens=accounted_completion_tokens,
            accounted_cost_usd_exact=accounted_cost_usd_exact,
            runtime_completion_evidence_sha256=runtime_completion_evidence_sha256,
            runtime_usage_record_sha256=runtime_usage_record_sha256,
            runtime_output_artifact_sha256=runtime_output_artifact_sha256,
            runtime_request_limit_reservation=None,
            runtime_usage_record=None,
            runtime_normalization_evidence=None,
            runtime_normalized_batch=None,
            runtime_requested_surface_requests=None,
            runtime_output_artifact=None,
            runtime_truncated_envelope_evidence=None,
            truncation_projection=truncation_projection,
            # V1 retains only runtime hashes, not a typed UsageRecord plus durable
            # ledger join.  It must therefore account the full reservation even
            # when the caller supplies an apparent actual cost.
            cost_disposition=(SchedulerTruncationRecoveryCostDisposition.RESERVED_MAX_ACCOUNTED),
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )

    @classmethod
    def build_uncertain(
        cls,
        *,
        child: TruncationRecoveryChildPlan,
        dispatch: SchedulerTruncationRecoveryChildDispatch,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildResult:
        terminal_evidence_sha256 = _canonical_sha256(
            {
                "classification": "recovery_dispatch_without_terminal",
                "dispatch_sha256": dispatch.entry_sha256,
            }
        )
        return cls._build(
            schema_version="1.0",
            child=child,
            activation=None,
            dispatch=dispatch,
            result_origin=SchedulerTruncationRecoveryResultOrigin.CRASH_RECOVERY,
            terminal_status=SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN,
            terminal_evidence_sha256=terminal_evidence_sha256,
            provider_attempt_evidence_sha256=None,
            accounted_provider_attempts=child.reserved_provider_attempts,
            accounted_completion_tokens=child.reserved_completion_tokens,
            accounted_cost_usd_exact=child.reserved_usd_exact,
            runtime_completion_evidence_sha256=None,
            runtime_usage_record_sha256=None,
            runtime_output_artifact_sha256=None,
            runtime_request_limit_reservation=None,
            runtime_usage_record=None,
            runtime_normalization_evidence=None,
            runtime_normalized_batch=None,
            runtime_requested_surface_requests=None,
            runtime_output_artifact=None,
            runtime_truncated_envelope_evidence=None,
            truncation_projection=None,
            cost_disposition=(SchedulerTruncationRecoveryCostDisposition.RESERVED_MAX_ACCOUNTED),
            entry_index=entry_index,
            previous_entry_sha256=previous_entry_sha256,
        )

    @classmethod
    def _build(
        cls,
        *,
        schema_version: Literal["1.0", "1.1", "1.2"],
        child: TruncationRecoveryChildPlan,
        activation: SchedulerTruncationRecoveryChildActivation | None,
        dispatch: SchedulerTruncationRecoveryChildDispatch,
        result_origin: SchedulerTruncationRecoveryResultOrigin,
        terminal_status: SchedulerTruncationRecoveryTerminalStatus,
        terminal_evidence_sha256: str,
        provider_attempt_evidence_sha256: str | None,
        accounted_provider_attempts: int,
        accounted_completion_tokens: int,
        accounted_cost_usd_exact: str,
        runtime_completion_evidence_sha256: str | None,
        runtime_usage_record_sha256: str | None,
        runtime_output_artifact_sha256: str | None,
        runtime_request_limit_reservation: AtomicRequestLimitReservationEvidence | None,
        runtime_usage_record: UsageRecord | None,
        runtime_normalization_evidence: CandidateReviewNormalizationEvidence | None,
        runtime_normalized_batch: CandidateReviewBatch | None,
        runtime_requested_surface_requests: tuple[ModelSurfaceReviewRequest, ...] | None,
        runtime_output_artifact: ModelSurfaceReviewArtifact | None,
        runtime_specialist_accepted_outcome_sha256: str | None = None,
        runtime_specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
        runtime_truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence | None,
        truncation_projection: CandidateReviewTruncationProjection | None,
        cost_disposition: SchedulerTruncationRecoveryCostDisposition,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryChildResult:
        projection = (
            CandidateReviewTruncationProjection.model_validate_json(
                truncation_projection.model_dump_json(),
                strict=True,
            )
            if truncation_projection is not None
            else None
        )
        completed = (
            child.surface_ids
            if terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
            else ()
        )
        retained = (
            tuple(item.surface_id for item in projection.surface_reviews)
            if projection is not None
            else ()
        )
        values: dict[str, Any] = {
            **_entry_values(
                campaign_id=dispatch.campaign_id,
                request_limit_id=dispatch.request_limit_id,
                request_limit_binding_sha256=dispatch.request_limit_binding_sha256,
                entry_kind=SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            ),
            "schema_version": schema_version,
            "family_id": dispatch.family_id,
            "family_root_sha256": dispatch.family_root_sha256,
            "child_task_id": dispatch.child_task_id,
            "child_logical_request_id": dispatch.child_logical_request_id,
            "child_plan_sha256": dispatch.child_plan_sha256,
            "child_surface_ids": child.surface_ids,
            "global_request_ordinal": dispatch.global_request_ordinal,
            "activation_id": dispatch.activation_id,
            "activation_sha256": dispatch.activation_sha256,
            "dispatch_id": dispatch.dispatch_id,
            "dispatch_sha256": dispatch.entry_sha256,
            "result_origin": result_origin,
            "terminal_status": terminal_status,
            "terminal_evidence_sha256": terminal_evidence_sha256,
            "provider_attempt_evidence_sha256": provider_attempt_evidence_sha256,
            "runtime_completion_evidence_sha256": (runtime_completion_evidence_sha256),
            "runtime_usage_record_sha256": runtime_usage_record_sha256,
            "runtime_output_artifact_sha256": runtime_output_artifact_sha256,
            "runtime_specialist_accepted_outcome_sha256": (
                runtime_specialist_accepted_outcome_sha256
            ),
            "runtime_activation": activation,
            "runtime_request_limit_reservation": runtime_request_limit_reservation,
            "runtime_usage_record": runtime_usage_record,
            "runtime_normalization_evidence": runtime_normalization_evidence,
            "runtime_normalized_batch": runtime_normalized_batch,
            "runtime_requested_surface_requests": runtime_requested_surface_requests,
            "runtime_output_artifact": runtime_output_artifact,
            "runtime_specialist_accepted_outcome": runtime_specialist_accepted_outcome,
            "runtime_truncated_envelope_evidence": runtime_truncated_envelope_evidence,
            "truncation_projection": projection,
            "completed_surface_ids": completed,
            "retained_surface_ids": retained,
            "reserved_provider_attempts": child.reserved_provider_attempts,
            "reserved_completion_tokens": child.reserved_completion_tokens,
            "reserved_usd_exact": child.reserved_usd_exact,
            "accounted_provider_attempts": accounted_provider_attempts,
            "accounted_completion_tokens": accounted_completion_tokens,
            "accounted_cost_usd_exact": accounted_cost_usd_exact,
            "cost_disposition": cost_disposition,
        }
        for optional_typed_field in (
            "runtime_activation",
            "runtime_request_limit_reservation",
            "runtime_usage_record",
            "runtime_normalization_evidence",
            "runtime_normalized_batch",
            "runtime_requested_surface_requests",
            "runtime_output_artifact",
            "runtime_specialist_accepted_outcome_sha256",
            "runtime_specialist_accepted_outcome",
            "runtime_truncated_envelope_evidence",
        ):
            if values[optional_typed_field] is None:
                del values[optional_typed_field]
        result_id = "scheduler-recovery-result-" + _canonical_sha256(
            {
                "domain": (
                    "mmaudit.scheduler.truncation-recovery-result.v1.2"
                    if schema_version == "1.2"
                    else "mmaudit.scheduler.truncation-recovery-result.v1.1"
                    if schema_version == "1.1"
                    else "mmaudit.scheduler.truncation-recovery-result.v1"
                ),
                "dispatch_id": dispatch.dispatch_id,
                "terminal_status": terminal_status,
                "terminal_evidence_sha256": terminal_evidence_sha256,
            }
        )
        body = {**values, "result_id": result_id}
        return cls(**body, entry_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def result_shape_resources_and_identity_are_exact(self) -> Self:
        _require_canonical_surface_ids(self.child_surface_ids, label="result child surfaces")
        _require_canonical_surface_ids(self.completed_surface_ids, label="completed surfaces")
        _require_canonical_surface_ids(self.retained_surface_ids, label="retained surfaces")
        reserved_usd = Decimal(_canonical_usd(self.reserved_usd_exact, label="reserved cost"))
        accounted_usd = Decimal(
            _canonical_usd(self.accounted_cost_usd_exact, label="accounted cost")
        )
        if (
            self.accounted_provider_attempts > self.reserved_provider_attempts
            or self.accounted_completion_tokens > self.reserved_completion_tokens
            or accounted_usd > reserved_usd
        ):
            raise ValueError("scheduler truncation recovery result exceeds reserved resources")
        if self.schema_version in {"1.1", "1.2"}:
            self._require_exact_typed_runtime_custody()
        else:
            self._require_exact_legacy_runtime_custody()
        expected_id = "scheduler-recovery-result-" + _canonical_sha256(
            {
                "domain": (
                    "mmaudit.scheduler.truncation-recovery-result.v1.2"
                    if self.schema_version == "1.2"
                    else "mmaudit.scheduler.truncation-recovery-result.v1.1"
                    if self.schema_version == "1.1"
                    else "mmaudit.scheduler.truncation-recovery-result.v1"
                ),
                "dispatch_id": self.dispatch_id,
                "terminal_status": self.terminal_status,
                "terminal_evidence_sha256": self.terminal_evidence_sha256,
            }
        )
        if self.result_id != expected_id:
            raise ValueError("scheduler truncation recovery result ID is inconsistent")
        return self

    def _require_exact_legacy_runtime_custody(self) -> None:
        typed_fields = (
            self.runtime_activation,
            self.runtime_request_limit_reservation,
            self.runtime_usage_record,
            self.runtime_normalization_evidence,
            self.runtime_normalized_batch,
            self.runtime_requested_surface_requests,
            self.runtime_output_artifact,
            self.runtime_specialist_accepted_outcome,
            self.runtime_truncated_envelope_evidence,
        )
        if any(item is not None for item in typed_fields) or (
            self.runtime_specialist_accepted_outcome_sha256 is not None
        ):
            raise ValueError("legacy recovery child cannot carry typed v1.1 runtime custody")
        completion_fields = (
            self.runtime_completion_evidence_sha256,
            self.runtime_usage_record_sha256,
            self.runtime_output_artifact_sha256,
        )
        if self.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED:
            if (
                any(item is None for item in completion_fields)
                or self.truncation_projection is not None
                or self.completed_surface_ids != self.child_surface_ids
                or self.retained_surface_ids
                or self.provider_attempt_evidence_sha256 is None
                or self.accounted_provider_attempts == 0
            ):
                raise ValueError("successful recovery child lacks exact runtime completion")
        elif self.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
            projection = self.truncation_projection
            if (
                any(item is not None for item in completion_fields)
                or projection is None
                or projection.evidence_sha256 != self.terminal_evidence_sha256
                or self.completed_surface_ids
                or self.retained_surface_ids
                != tuple(item.surface_id for item in projection.surface_reviews)
                or not set(self.retained_surface_ids) <= set(self.child_surface_ids)
                or self.provider_attempt_evidence_sha256 is None
                or self.accounted_provider_attempts == 0
            ):
                raise ValueError("truncated recovery child lacks exact projection custody")
        elif (
            any(item is not None for item in completion_fields)
            or self.truncation_projection is not None
            or self.completed_surface_ids
            or self.retained_surface_ids
        ):
            raise ValueError("non-success recovery child claims provisional completion")
        if self.result_origin is SchedulerTruncationRecoveryResultOrigin.CRASH_RECOVERY:
            if (
                self.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN
                or self.provider_attempt_evidence_sha256 is not None
                or self.cost_disposition
                is not SchedulerTruncationRecoveryCostDisposition.RESERVED_MAX_ACCOUNTED
                or self.accounted_provider_attempts != self.reserved_provider_attempts
                or self.accounted_completion_tokens != self.reserved_completion_tokens
                or self.accounted_cost_usd_exact != self.reserved_usd_exact
            ):
                raise ValueError("crash-recovered child is not conservatively accounted")
        elif (
            self.cost_disposition
            is not SchedulerTruncationRecoveryCostDisposition.RESERVED_MAX_ACCOUNTED
            or self.provider_attempt_evidence_sha256 is None
            or self.accounted_provider_attempts != self.reserved_provider_attempts
            or self.accounted_completion_tokens != self.reserved_completion_tokens
            or self.accounted_cost_usd_exact != self.reserved_usd_exact
        ):
            raise ValueError(
                "hash-only runtime recovery child is not conservatively fully accounted"
            )

    def _require_exact_typed_runtime_custody(self) -> None:
        activation = self.runtime_activation
        reservation = self.runtime_request_limit_reservation
        usage = self.runtime_usage_record
        if activation is None or reservation is None or usage is None:
            raise ValueError(
                "typed recovery child omits activation, request-limit, or usage custody"
            )
        exact_activation = _freeze_exact_model(
            SchedulerTruncationRecoveryChildActivation,
            activation,
            label="typed activation",
        )
        exact_reservation = _freeze_exact_model(
            AtomicRequestLimitReservationEvidence,
            reservation,
            label="typed request-limit reservation",
        )
        if type(usage) is not UsageRecord:
            raise TypeError("scheduler recovery typed usage has an invalid exact type")
        exact_usage = usage
        accounted_cost, usage_sha256 = _require_exact_typed_usage(
            usage=exact_usage,
            activation=exact_activation,
            reservation=exact_reservation,
            child=None,
            truncated_envelope_selected_model=(
                self.runtime_truncated_envelope_evidence.selected_model
                if self.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
                and self.runtime_truncated_envelope_evidence is not None
                else None
            ),
        )
        expected_attempt_sha256 = _typed_provider_attempt_sha256(
            activation_sha256=exact_activation.entry_sha256,
            usage_record_sha256=usage_sha256,
        )
        structurally_admissible = (
            is_structurally_recovery_creditable_usage_record(
                exact_usage,
                request_limit_scope=exact_activation.request_limit_id,
                request_limit_count_before=(exact_activation.request_limit_count_before_child),
            )
            if self.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
            else is_structurally_recovery_accountable_usage_record(
                exact_usage,
                request_limit_scope=exact_activation.request_limit_id,
                request_limit_count_before=(exact_activation.request_limit_count_before_child),
            )
        )
        if (
            self.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            or self.terminal_status
            not in {
                SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED,
                SchedulerTruncationRecoveryTerminalStatus.TRUNCATED,
            }
            or self.cost_disposition
            is not SchedulerTruncationRecoveryCostDisposition.ACTUAL_ACCOUNTED
            or not structurally_admissible
            or self.reserved_provider_attempts != 1
            or exact_activation.request_limit_count_after_child
            - exact_activation.request_limit_count_before_child
            != self.reserved_provider_attempts
            or exact_activation.campaign_id != self.campaign_id
            or exact_activation.request_limit_id != self.request_limit_id
            or exact_activation.request_limit_binding_sha256 != self.request_limit_binding_sha256
            or exact_activation.family_id != self.family_id
            or exact_activation.family_root_sha256 != self.family_root_sha256
            or exact_activation.child_task_id != self.child_task_id
            or exact_activation.child_logical_request_id != self.child_logical_request_id
            or exact_activation.child_plan_sha256 != self.child_plan_sha256
            or exact_activation.child_surface_ids != self.child_surface_ids
            or exact_activation.global_request_ordinal != self.global_request_ordinal
            or exact_activation.activation_id != self.activation_id
            or exact_activation.entry_sha256 != self.activation_sha256
            or self.provider_attempt_evidence_sha256 != expected_attempt_sha256
            or self.runtime_usage_record_sha256 != usage_sha256
            or self.accounted_provider_attempts != 1
            or self.accounted_completion_tokens != exact_usage.completion_tokens
            or self.accounted_cost_usd_exact != accounted_cost
            or self.accounted_completion_tokens > self.reserved_completion_tokens
            or Decimal(accounted_cost) > Decimal(self.reserved_usd_exact)
        ):
            raise ValueError("typed recovery child runtime custody is inconsistent")
        if self.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED:
            self._require_exact_typed_success(
                activation=exact_activation,
                usage=exact_usage,
                usage_sha256=usage_sha256,
            )
        else:
            self._require_exact_typed_truncation(
                usage=exact_usage,
                usage_sha256=usage_sha256,
            )

    def _require_exact_typed_success(
        self,
        *,
        activation: SchedulerTruncationRecoveryChildActivation,
        usage: UsageRecord,
        usage_sha256: str,
    ) -> None:
        normalization = self.runtime_normalization_evidence
        batch = self.runtime_normalized_batch
        requests = self.runtime_requested_surface_requests
        artifact = self.runtime_output_artifact
        if normalization is None or batch is None or requests is None or artifact is None:
            raise ValueError("successful typed recovery child omits exact completion custody")
        if (
            self.runtime_truncated_envelope_evidence is not None
            or self.truncation_projection is not None
        ):
            raise ValueError("successful typed recovery child carries truncation custody")
        exact_normalization = _freeze_exact_model(
            CandidateReviewNormalizationEvidence,
            normalization,
            label="typed normalization evidence",
        )
        exact_batch = _freeze_exact_model(
            CandidateReviewBatch,
            batch,
            label="typed normalized batch",
        )
        exact_requests = tuple(
            _freeze_exact_model(
                ModelSurfaceReviewRequest,
                request,
                label="typed surface request",
            )
            for request in requests
        )
        exact_artifact = _freeze_exact_model(
            ModelSurfaceReviewArtifact,
            artifact,
            label="typed output artifact",
        )
        exact_specialist_outcome = _freeze_exact_specialist_success_outcome(
            specialist_accepted_outcome=self.runtime_specialist_accepted_outcome,
            activation=activation,
            usage=usage,
            requested_surface_count=len(exact_requests),
            output_artifact_sha256=exact_artifact.artifact_sha256,
        )
        specialist_outcome_sha256 = (
            exact_specialist_outcome.evidence_sha256
            if exact_specialist_outcome is not None
            else None
        )
        requested_ids = tuple(request.surface_id for request in exact_requests)
        try:
            exact_batch.require_exact_surface_set(requested_ids)
            exact_normalization.require_exact_batch(
                exact_batch,
                request_id=self.child_logical_request_id,
            )
            exact_artifact.require_exact_requested_surface_manifest(exact_requests)
        except ValueError:
            raise ValueError("typed recovery wire-to-artifact custody is inconsistent") from None
        records_by_id = {record.surface_id: record for record in exact_batch.surface_reviews}
        requests_match_records = all(
            records_by_id[request.surface_id].contract == request.contract
            and records_by_id[request.surface_id].function_or_state_surface
            == request.function_or_state_surface
            and records_by_id[request.surface_id].invariant_considered
            == request.invariant_considered
            for request in exact_requests
        )
        expected_completion_sha256 = _typed_completion_sha256(
            activation_sha256=activation.entry_sha256,
            usage_record_sha256=usage_sha256,
            normalization_evidence_sha256=exact_normalization.evidence_sha256,
            normalized_batch_sha256=exact_normalization.normalized_batch_sha256,
            requested_surface_manifest_sha256=(exact_artifact.requested_surface_manifest_sha256),
            output_artifact_sha256=exact_artifact.artifact_sha256,
            specialist_accepted_outcome_sha256=specialist_outcome_sha256,
        )
        if (
            self.schema_version != ("1.2" if exact_specialist_outcome is not None else "1.1")
            or self.runtime_specialist_accepted_outcome_sha256 != specialist_outcome_sha256
            or requested_ids != self.child_surface_ids
            or not requests_match_records
            or usage.validation_status is not ModelRequestValidationStatus.VALID
            or usage.status != "success"
            or usage.finish_reason != "stop"
            or usage.validated_response_sha256 != exact_normalization.wire_validated_response_sha256
            or usage.schema_sha256 != candidate_review_frame_wire_schema_sha256()
            or exact_normalization.wire_schema_sha256 != usage.schema_sha256
            or exact_normalization.normalized_batch_schema_sha256
            != candidate_review_batch_schema_sha256()
            or exact_artifact.schema_version != "1.1"
            or exact_artifact.request_id != self.child_logical_request_id
            or exact_artifact.review_role != usage.role
            or exact_artifact.prompt_sha256 != usage.prompt_sha256
            or exact_artifact.rendered_context_sha256 != usage.user_prompt_sha256
            or exact_artifact.response_sha256 != usage.response_sha256
            or exact_artifact.validated_response_sha256 != usage.validated_response_sha256
            or exact_artifact.response_schema_sha256 != usage.schema_sha256
            or exact_artifact.normalization_evidence != exact_normalization
            or exact_artifact.normalized_response != exact_batch
            or exact_artifact.records != tuple(exact_batch.surface_reviews)
            or self.runtime_completion_evidence_sha256 != expected_completion_sha256
            or self.terminal_evidence_sha256 != expected_completion_sha256
            or self.runtime_output_artifact_sha256 != exact_artifact.artifact_sha256
            or self.completed_surface_ids != self.child_surface_ids
            or self.retained_surface_ids
        ):
            raise ValueError("successful typed recovery child custody is inconsistent")

    def _require_exact_typed_truncation(
        self,
        *,
        usage: UsageRecord,
        usage_sha256: str,
    ) -> None:
        envelope = self.runtime_truncated_envelope_evidence
        projection = self.truncation_projection
        if envelope is None or projection is None:
            raise ValueError("truncated typed recovery child omits exact failure custody")
        if any(
            item is not None
            for item in (
                self.runtime_completion_evidence_sha256,
                self.runtime_output_artifact_sha256,
                self.runtime_normalization_evidence,
                self.runtime_normalized_batch,
                self.runtime_requested_surface_requests,
                self.runtime_output_artifact,
                self.runtime_specialist_accepted_outcome_sha256,
                self.runtime_specialist_accepted_outcome,
            )
        ):
            raise ValueError("truncated typed recovery child claims completion custody")
        if self.schema_version != "1.1":
            raise ValueError("truncated typed recovery child has an invalid schema generation")
        exact_envelope = _freeze_exact_model(
            CandidateReviewTruncatedEnvelopeEvidence,
            envelope,
            label="typed truncated envelope",
        )
        exact_projection = _freeze_exact_model(
            CandidateReviewTruncationProjection,
            projection,
            label="typed truncation projection",
        )
        expected_envelope_routing = _expected_truncated_envelope_routing(exact_envelope)
        expected_projection_routing = _expected_truncation_projection_routing(exact_projection)
        actual_envelope_keys = {
            key for key in usage.routing if key.startswith("candidate_review_truncated_")
        }
        actual_projection_keys = {
            key for key in usage.routing if key.startswith("candidate_review_truncation_")
        }
        retained_ids = tuple(record.surface_id for record in exact_projection.surface_reviews)
        if (
            usage_sha256 != self.runtime_usage_record_sha256
            or usage.validation_status is not ModelRequestValidationStatus.TRUNCATED
            or usage.identity_strength is not ModelIdentityStrength.UNBOUND
            or usage.status != "rejected_truncated_response"
            or usage.validated_response_sha256 is not None
            or usage.request_id != exact_envelope.logical_request_id
            or usage.requested_model != exact_envelope.requested_model
            or usage.returned_model != exact_envelope.returned_model
            or usage.actual_model != exact_envelope.selected_model
            or usage.provider != exact_envelope.selected_provider_name
            or usage.openrouter_generation_id != exact_envelope.generation_id
            or usage.actual_provider_endpoint != exact_envelope.selected_provider_endpoint
            or usage.response_sha256 != exact_envelope.response_sha256
            or usage.schema_sha256 != exact_envelope.wire_schema_sha256
            or usage.finish_reason != exact_envelope.finish_reason
            or exact_projection.original_response_sha256 != exact_envelope.response_sha256
            or exact_projection.wire_schema_sha256 != exact_envelope.wire_schema_sha256
            or exact_projection.finish_reason != exact_envelope.finish_reason
            or exact_projection.native_finish_reason != exact_envelope.native_finish_reason
            or usage.routing.get("generation_id") != exact_envelope.generation_id
            or usage.routing.get("generation_header_id") != exact_envelope.generation_header_id
            or usage.routing.get("provider") != exact_envelope.selected_provider_name
            or usage.routing.get("router_metadata_sha256") != exact_envelope.router_metadata_sha256
            or usage.routing.get("native_finish_reason") != exact_envelope.native_finish_reason
            or actual_envelope_keys != set(expected_envelope_routing)
            or any(
                usage.routing.get(key) != value for key, value in expected_envelope_routing.items()
            )
            or actual_projection_keys != set(expected_projection_routing)
            or any(
                usage.routing.get(key) != value
                for key, value in expected_projection_routing.items()
            )
            or exact_projection.evidence_sha256 != self.terminal_evidence_sha256
            or self.completed_surface_ids
            or self.retained_surface_ids != retained_ids
            or not set(retained_ids) <= set(self.child_surface_ids)
        ):
            raise ValueError("truncated typed recovery child custody is inconsistent")


class SchedulerTruncationRecoveryFamilyClosure(_SchedulerTruncationRecoveryEntry):
    """Recursive structural closure that deliberately grants no completion authority."""

    schema_version: Literal["1.0", "1.1"] = "1.0"
    entry_kind: Literal[SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED] = (
        SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED
    )
    family_index: int = Field(
        ge=0,
        lt=SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES,
    )
    family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    family_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    recovery_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    closure_status: SchedulerTruncationRecoveryClosureStatus
    child_result_sha256s: tuple[str, ...] = Field(max_length=2)
    nested_family_closure_sha256s: tuple[str, ...] = Field(max_length=2)
    covered_unfinished_surface_ids: tuple[str, ...] = Field(max_length=_MAX_SURFACES)
    closure_id: str = Field(pattern=_RECOVERY_CLOSURE_ID_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        family: SchedulerTruncationRecoveryFamilyRoot,
        closure_status: SchedulerTruncationRecoveryClosureStatus,
        child_result_sha256s: Iterable[str],
        nested_family_closure_sha256s: Iterable[str],
        covered_unfinished_surface_ids: Iterable[str],
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryFamilyClosure:
        result_hashes = _bounded_tuple(
            child_result_sha256s,
            limit=2,
            label="closure child results",
        )
        nested_hashes = _bounded_tuple(
            nested_family_closure_sha256s,
            limit=2,
            label="closure nested families",
        )
        covered = _canonical_surface_ids(
            covered_unfinished_surface_ids,
            label="closure surfaces",
        )
        values: dict[str, Any] = {
            **_entry_values(
                campaign_id=family.campaign_id,
                request_limit_id=family.request_limit_id,
                request_limit_binding_sha256=family.request_limit_binding_sha256,
                entry_kind=SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            ),
            "schema_version": (
                "1.1"
                if closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                else "1.0"
            ),
            "family_index": family.family_index,
            "family_id": family.family_id,
            "family_root_sha256": family.entry_sha256,
            "recovery_plan_sha256": family.recovery_plan.plan_sha256,
            "closure_status": closure_status,
            "child_result_sha256s": result_hashes,
            "nested_family_closure_sha256s": nested_hashes,
            "covered_unfinished_surface_ids": covered,
        }
        closure_id = "scheduler-recovery-closure-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-closure.v1",
                "family_id": family.family_id,
                "family_root_sha256": family.entry_sha256,
                "child_result_sha256s": result_hashes,
                "nested_family_closure_sha256s": nested_hashes,
                "covered_unfinished_surface_ids": covered,
                "closure_status": closure_status,
            }
        )
        body = {**values, "closure_id": closure_id}
        return cls(**body, entry_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def closure_inventory_identity_and_hash_are_exact(self) -> Self:
        if (
            self.schema_version == "1.0"
            and self.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        ):
            raise ValueError("v1 structural recovery closure cannot grant coverage closure")
        if self.schema_version == "1.1" and (
            self.closure_status is not SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
            or len(self.child_result_sha256s) != 2
            or self.nested_family_closure_sha256s
            or not self.covered_unfinished_surface_ids
        ):
            raise ValueError("v1.1 recovery closure requires exact direct typed coverage")
        if len(self.child_result_sha256s) != len(set(self.child_result_sha256s)) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None for item in self.child_result_sha256s
        ):
            raise ValueError("scheduler truncation recovery closure results are ambiguous")
        if len(self.nested_family_closure_sha256s) != len(
            set(self.nested_family_closure_sha256s)
        ) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None
            for item in self.nested_family_closure_sha256s
        ):
            raise ValueError("scheduler truncation recovery nested closures are ambiguous")
        _require_canonical_surface_ids(
            self.covered_unfinished_surface_ids,
            label="closure surfaces",
        )
        expected_id = "scheduler-recovery-closure-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-closure.v1",
                "family_id": self.family_id,
                "family_root_sha256": self.family_root_sha256,
                "child_result_sha256s": self.child_result_sha256s,
                "nested_family_closure_sha256s": (self.nested_family_closure_sha256s),
                "covered_unfinished_surface_ids": (self.covered_unfinished_surface_ids),
                "closure_status": self.closure_status,
            }
        )
        if self.closure_id != expected_id:
            raise ValueError("scheduler truncation recovery closure ID is inconsistent")
        return self


class SchedulerRecoveredCandidateOrigin(StrictModel):
    """Exact parent frame or child batch that supplied one promoted candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    origin_kind: SchedulerRecoveredCandidateOriginKind
    accepted_candidate_id: str = Field(pattern=r"^cand-[0-9a-f]{24}$")
    accepted_candidate_sha256: str = Field(pattern=_SHA256_PATTERN)
    raw_candidate_id: str = Field(min_length=1, max_length=500)
    raw_candidate_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_id: str = Field(
        pattern=r"^(?:scheduler-request|scheduler-recovery-request)-[0-9a-f]{64}$"
    )
    request_role: str = Field(pattern=_ROLE_ID_PATTERN)
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    context_request_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_projection_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    accepted_frame_sequence: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    accepted_frame_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    child_task_id: str | None = Field(
        default=None,
        pattern=_RECOVERY_TASK_ID_PATTERN,
        exclude_if=lambda value: value is None,
    )
    child_result_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    normalization_evidence_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    surface_artifact_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    origin_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        origin_kind: SchedulerRecoveredCandidateOriginKind,
        accepted_candidate_id: str,
        accepted_candidate_sha256: str,
        raw_candidate_id: str,
        raw_candidate_sha256: str,
        request_id: str,
        request_role: str,
        usage_record_sha256: str,
        context_request_evidence_sha256: str,
        parent_projection_sha256: str | None = None,
        accepted_frame_sequence: int | None = None,
        accepted_frame_sha256: str | None = None,
        child_task_id: str | None = None,
        child_result_sha256: str | None = None,
        normalization_evidence_sha256: str | None = None,
        surface_artifact_sha256: str | None = None,
    ) -> SchedulerRecoveredCandidateOrigin:
        values: dict[str, Any] = {
            "origin_kind": origin_kind,
            "accepted_candidate_id": accepted_candidate_id,
            "accepted_candidate_sha256": accepted_candidate_sha256,
            "raw_candidate_id": raw_candidate_id,
            "raw_candidate_sha256": raw_candidate_sha256,
            "request_id": request_id,
            "request_role": request_role,
            "usage_record_sha256": usage_record_sha256,
            "context_request_evidence_sha256": context_request_evidence_sha256,
            "parent_projection_sha256": parent_projection_sha256,
            "accepted_frame_sequence": accepted_frame_sequence,
            "accepted_frame_sha256": accepted_frame_sha256,
            "child_task_id": child_task_id,
            "child_result_sha256": child_result_sha256,
            "normalization_evidence_sha256": normalization_evidence_sha256,
            "surface_artifact_sha256": surface_artifact_sha256,
        }
        return cls(**values, origin_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def exact_origin_shape_and_hash(self) -> Self:
        if self.raw_candidate_id != self.raw_candidate_id.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in self.raw_candidate_id
        ):
            raise ValueError("recovered raw candidate identity is not bounded plain text")
        parent_fields = (
            self.parent_projection_sha256,
            self.accepted_frame_sequence,
            self.accepted_frame_sha256,
        )
        child_fields = (
            self.child_task_id,
            self.child_result_sha256,
            self.normalization_evidence_sha256,
            self.surface_artifact_sha256,
        )
        if self.origin_kind is SchedulerRecoveredCandidateOriginKind.PARENT_FRAME:
            valid_shape = all(item is not None for item in parent_fields) and all(
                item is None for item in child_fields
            )
        else:
            valid_shape = all(item is None for item in parent_fields) and all(
                item is not None for item in child_fields
            )
        if not valid_shape:
            raise ValueError("recovered candidate origin fields are not an exact one-of")
        if self.origin_sha256 != _model_sha256(self, exclude={"origin_sha256"}):
            raise ValueError("recovered candidate origin hash is inconsistent")
        return self


class SchedulerRecoveredCandidateReviewOutput(_NonAuthorizingRecoveryJournalModel):
    """Durable recovered batch; credit still requires the live promotion capability."""

    schema_version: Literal["1.0"] = "1.0"
    campaign_id: str = Field(pattern=_CAMPAIGN_ID_PATTERN)
    pass_plan_id: str = Field(pattern=r"^scheduler-plan-[0-9a-f]{64}$")
    parent_task_id: str = Field(pattern=_ROOT_TASK_ID_PATTERN)
    parent_logical_request_id: str = Field(pattern=_ROOT_REQUEST_ID_PATTERN)
    parent_activation_sha256: str = Field(pattern=_SHA256_PATTERN)
    original_truncated_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_provider_attempt_sha256: str = Field(pattern=_SHA256_PATTERN)
    recovery_family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    family_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    family_closure_sha256: str = Field(pattern=_SHA256_PATTERN)
    structural_surface_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    recovered_batch: CandidateReviewBatch
    candidate_origins: tuple[SchedulerRecoveredCandidateOrigin, ...] = Field(
        max_length=_MAX_PROMOTED_CANDIDATES
    )
    accepted_candidate_payload_sha256s: dict[str, str] = Field(max_length=_MAX_PROMOTED_CANDIDATES)
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...] = Field(
        max_length=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS + 1
    )
    delivered_source_descriptor_sha256s: tuple[str, ...] = Field(max_length=100_000)
    output_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_id: str = Field(pattern=r"^scheduler-recovered-output-[0-9a-f]{64}$")
    output_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        campaign_id: str,
        pass_plan_id: str,
        parent_task_id: str,
        parent_logical_request_id: str,
        parent_activation_sha256: str,
        original_truncated_result_sha256: str,
        parent_provider_attempt_sha256: str,
        recovery_family_id: str,
        family_root_sha256: str,
        family_closure_sha256: str,
        structural_surface_artifact_sha256: str,
        recovered_batch: CandidateReviewBatch,
        candidate_origins: Iterable[SchedulerRecoveredCandidateOrigin],
        scanner_fingerprints_by_request: Iterable[tuple[str, tuple[str, ...]]],
        delivered_source_descriptor_sha256s: Iterable[str],
    ) -> SchedulerRecoveredCandidateReviewOutput:
        batch = CandidateReviewBatch.model_validate_json(recovered_batch.model_dump_json())
        origins = tuple(
            sorted(
                _bounded_tuple(
                    candidate_origins,
                    limit=_MAX_PROMOTED_CANDIDATES,
                    label="candidate origins",
                ),
                key=lambda item: item.accepted_candidate_id,
            )
        )
        accepted_hashes = {
            candidate.candidate_id: _canonical_sha256(candidate.model_dump(mode="json"))
            for candidate in batch.findings
        }
        scanner_projection = tuple(
            sorted(
                _bounded_tuple(
                    scanner_fingerprints_by_request,
                    limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS + 1,
                    label="request scanner fingerprint projections",
                )
            )
        )
        raw_delivered_sources = _bounded_tuple(
            delivered_source_descriptor_sha256s,
            limit=_MAX_SOURCE_DESCRIPTORS,
            label="reviewed source descriptors",
        )
        if len(raw_delivered_sources) != len(set(raw_delivered_sources)) or any(
            not isinstance(item, str) or re.fullmatch(_SHA256_PATTERN, item) is None
            for item in raw_delivered_sources
        ):
            raise ValueError("recovered source descriptor inventory is invalid or duplicated")
        delivered_sources = tuple(sorted(raw_delivered_sources))
        output_sha256 = _canonical_sha256(batch.model_dump(mode="json"))
        output_id = "scheduler-recovered-output-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.recovered-candidate-output.v1",
                "family_id": recovery_family_id,
                "parent_task_id": parent_task_id,
                "output_sha256": output_sha256,
            }
        )
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "campaign_id": campaign_id,
            "pass_plan_id": pass_plan_id,
            "parent_task_id": parent_task_id,
            "parent_logical_request_id": parent_logical_request_id,
            "parent_activation_sha256": parent_activation_sha256,
            "original_truncated_result_sha256": original_truncated_result_sha256,
            "parent_provider_attempt_sha256": parent_provider_attempt_sha256,
            "recovery_family_id": recovery_family_id,
            "family_root_sha256": family_root_sha256,
            "family_closure_sha256": family_closure_sha256,
            "structural_surface_artifact_sha256": structural_surface_artifact_sha256,
            "recovered_batch": batch,
            "candidate_origins": origins,
            "accepted_candidate_payload_sha256s": accepted_hashes,
            "scanner_fingerprints_by_request": scanner_projection,
            "delivered_source_descriptor_sha256s": delivered_sources,
            "output_sha256": output_sha256,
            "output_id": output_id,
        }
        return cls(**values, output_artifact_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def recovered_inventory_identity_and_hash_are_exact(self) -> Self:
        candidates = tuple(self.recovered_batch.findings)
        candidate_ids = tuple(item.candidate_id for item in candidates)
        origin_ids = tuple(item.accepted_candidate_id for item in self.candidate_origins)
        if (
            candidate_ids != tuple(sorted(set(candidate_ids)))
            or origin_ids != candidate_ids
            or tuple(self.accepted_candidate_payload_sha256s) != candidate_ids
            or any(
                self.accepted_candidate_payload_sha256s[item.candidate_id]
                != _canonical_sha256(item.model_dump(mode="json"))
                for item in candidates
            )
            or any(
                origin.accepted_candidate_sha256
                != self.accepted_candidate_payload_sha256s[origin.accepted_candidate_id]
                for origin in self.candidate_origins
            )
        ):
            raise ValueError("recovered candidate and origin inventories are inconsistent")
        surfaces = tuple(item.surface_id for item in self.recovered_batch.surface_reviews)
        scanner_request_ids = tuple(
            request_id for request_id, _fingerprints in self.scanner_fingerprints_by_request
        )
        scanner_fingerprint_count = sum(
            len(fingerprints) for _request_id, fingerprints in self.scanner_fingerprints_by_request
        )
        if surfaces != tuple(sorted(set(surfaces))):
            raise ValueError("recovered surface inventory is not canonical")
        if (
            scanner_request_ids != tuple(sorted(set(scanner_request_ids)))
            or not {origin.request_id for origin in self.candidate_origins}.issubset(
                scanner_request_ids
            )
            or scanner_fingerprint_count > 100_000
            or any(
                request_id != request_id.strip()
                or re.fullmatch(
                    r"^(?:scheduler-request|scheduler-recovery-request)-[0-9a-f]{64}$",
                    request_id,
                )
                is None
                or fingerprints != tuple(sorted(set(fingerprints)))
                or any(re.fullmatch(_SHA256_PATTERN, item) is None for item in fingerprints)
                for request_id, fingerprints in self.scanner_fingerprints_by_request
            )
        ):
            raise ValueError("recovered scanner fingerprint projection is not canonical")
        if self.delivered_source_descriptor_sha256s != tuple(
            sorted(set(self.delivered_source_descriptor_sha256s))
        ) or any(
            re.fullmatch(_SHA256_PATTERN, item) is None
            for item in self.delivered_source_descriptor_sha256s
        ):
            raise ValueError("recovered source descriptor inventory is not canonical")
        expected_output_sha256 = _canonical_sha256(self.recovered_batch.model_dump(mode="json"))
        expected_output_id = "scheduler-recovered-output-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.recovered-candidate-output.v1",
                "family_id": self.recovery_family_id,
                "parent_task_id": self.parent_task_id,
                "output_sha256": expected_output_sha256,
            }
        )
        if (
            self.output_sha256 != expected_output_sha256
            or self.output_id != expected_output_id
            or self.output_artifact_sha256
            != _model_sha256(self, exclude={"output_artifact_sha256"})
        ):
            raise ValueError("recovered candidate output identity or hash is inconsistent")
        return self


class SchedulerTruncationRecoveryFamilyPromotion(_SchedulerTruncationRecoveryEntry):
    """Append-only effective recovery; self-hashed bytes never authorize appending it."""

    schema_version: Literal["1.0"] = "1.0"
    entry_kind: Literal[SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED] = (
        SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED
    )
    family_index: int = Field(ge=0, lt=SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES)
    family_id: str = Field(pattern=_RECOVERY_FAMILY_ID_PATTERN)
    family_root_sha256: str = Field(pattern=_SHA256_PATTERN)
    recovery_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    family_closure_id: str = Field(pattern=_RECOVERY_CLOSURE_ID_PATTERN)
    family_closure_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_task_id: str = Field(pattern=_ROOT_TASK_ID_PATTERN)
    original_truncated_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    direct_child_result_sha256s: tuple[str, str]
    recovered_output: SchedulerRecoveredCandidateReviewOutput
    capability_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
    promotion_status: Literal["RECOVERED"] = "RECOVERED"
    promotion_id: str = Field(pattern=_RECOVERY_PROMOTION_ID_PATTERN)

    @classmethod
    def build(
        cls,
        *,
        family: SchedulerTruncationRecoveryFamilyRoot,
        closure: SchedulerTruncationRecoveryFamilyClosure,
        direct_child_result_sha256s: tuple[str, str],
        recovered_output: SchedulerRecoveredCandidateReviewOutput,
        capability_binding_sha256: str,
        entry_index: int,
        previous_entry_sha256: str | None,
    ) -> SchedulerTruncationRecoveryFamilyPromotion:
        values: dict[str, Any] = {
            **_entry_values(
                campaign_id=family.campaign_id,
                request_limit_id=family.request_limit_id,
                request_limit_binding_sha256=family.request_limit_binding_sha256,
                entry_kind=SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED,
                entry_index=entry_index,
                previous_entry_sha256=previous_entry_sha256,
            ),
            "family_index": family.family_index,
            "family_id": family.family_id,
            "family_root_sha256": family.entry_sha256,
            "recovery_plan_sha256": family.recovery_plan.plan_sha256,
            "family_closure_id": closure.closure_id,
            "family_closure_sha256": closure.entry_sha256,
            "parent_task_id": family.recovery_plan.parent.parent_task_id,
            "original_truncated_result_sha256": (family.parent_terminal_result_sha256),
            "direct_child_result_sha256s": direct_child_result_sha256s,
            "recovered_output": recovered_output,
            "capability_binding_sha256": capability_binding_sha256,
            "promotion_status": "RECOVERED",
        }
        promotion_id = "scheduler-recovery-promotion-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-promotion.v1",
                "family_id": family.family_id,
                "closure_sha256": closure.entry_sha256,
                "recovered_output_sha256": recovered_output.output_artifact_sha256,
            }
        )
        body = {**values, "promotion_id": promotion_id}
        return cls(**body, entry_sha256=_canonical_sha256(body))

    @model_validator(mode="after")
    def promotion_identity_output_and_hash_are_exact(self) -> Self:
        expected_id = "scheduler-recovery-promotion-" + _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.truncation-recovery-promotion.v1",
                "family_id": self.family_id,
                "closure_sha256": self.family_closure_sha256,
                "recovered_output_sha256": self.recovered_output.output_artifact_sha256,
            }
        )
        if (
            len(set(self.direct_child_result_sha256s)) != len(self.direct_child_result_sha256s)
            or any(
                re.fullmatch(_SHA256_PATTERN, item) is None
                for item in self.direct_child_result_sha256s
            )
            or self.recovered_output.campaign_id != self.campaign_id
            or self.recovered_output.parent_task_id != self.parent_task_id
            or self.recovered_output.recovery_family_id != self.family_id
            or self.recovered_output.family_root_sha256 != self.family_root_sha256
            or self.recovered_output.family_closure_sha256 != self.family_closure_sha256
            or self.recovered_output.original_truncated_result_sha256
            != self.original_truncated_result_sha256
            or self.promotion_id != expected_id
        ):
            raise ValueError("scheduler recovery promotion is detached from its exact output")
        return self


class SchedulerTruncationRecoveryPromotionBinding(_NonAuthorizingRecoveryJournalModel):
    """Hash-only public binding to one private recovery promotion."""

    schema_version: Literal["1.0"] = "1.0"
    parent_task_id: str = Field(pattern=_ROOT_TASK_ID_PATTERN)
    original_truncated_result_sha256: str = Field(pattern=_SHA256_PATTERN)
    promotion_entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    direct_child_result_sha256s: tuple[str, str]
    recovered_output_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    delivered_source_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("direct_child_result_sha256s", mode="before")
    @classmethod
    def recover_json_child_result_tuple(cls, value: object) -> object:
        """Recover the fixed tuple emitted as a JSON array by the durable journal."""

        return tuple(value) if isinstance(value, list) else value

    @classmethod
    def from_promotion(
        cls,
        promotion: SchedulerTruncationRecoveryFamilyPromotion,
    ) -> SchedulerTruncationRecoveryPromotionBinding:
        """Project only identities and source hashes safe for the public scheduler artifact."""

        exact = SchedulerTruncationRecoveryFamilyPromotion.model_validate_json(
            promotion.model_dump_json(),
            strict=True,
        )
        output = exact.recovered_output
        source_inventory_sha256 = _canonical_sha256(
            {
                "domain": "mmaudit.scheduler.recovery-delivered-source-inventory.v1",
                "source_descriptor_sha256s": output.delivered_source_descriptor_sha256s,
            }
        )
        values: dict[str, Any] = {
            "evidence_authority": "comparison_required",
            "provider_dispatch_authorized": False,
            "review_credit_authorized": False,
            "coverage_credit_authorized": False,
            "completion_authorized": False,
            "release_authorized": False,
            "schema_version": "1.0",
            "parent_task_id": exact.parent_task_id,
            "original_truncated_result_sha256": exact.original_truncated_result_sha256,
            "promotion_entry_sha256": exact.entry_sha256,
            "direct_child_result_sha256s": exact.direct_child_result_sha256s,
            "recovered_output_artifact_sha256": output.output_artifact_sha256,
            "delivered_source_inventory_sha256": source_inventory_sha256,
        }
        return cls(**values, binding_sha256=_canonical_sha256(values))

    @model_validator(mode="after")
    def public_binding_is_self_hashed(self) -> Self:
        if (
            len(set(self.direct_child_result_sha256s)) != 2
            or any(
                re.fullmatch(_SHA256_PATTERN, item) is None
                for item in self.direct_child_result_sha256s
            )
            or self.binding_sha256 != _model_sha256(self, exclude={"binding_sha256"})
        ):
            raise ValueError("scheduler recovery promotion public binding hash is inconsistent")
        return self


type SchedulerTruncationRecoveryEntry = (
    SchedulerTruncationRecoveryFamilyRoot
    | SchedulerTruncationRecoveryChildActivation
    | SchedulerTruncationRecoveryChildPreflightResult
    | SchedulerTruncationRecoveryChildDispatch
    | SchedulerTruncationRecoveryChildResult
    | SchedulerTruncationRecoveryFamilyClosure
    | SchedulerTruncationRecoveryFamilyPromotion
)


SCHEDULER_TRUNCATION_RECOVERY_ENTRY_TYPES: dict[
    SchedulerTruncationRecoveryEntryKind,
    type[_SchedulerTruncationRecoveryEntry],
] = {
    SchedulerTruncationRecoveryEntryKind.FAMILY_ROOT: (SchedulerTruncationRecoveryFamilyRoot),
    SchedulerTruncationRecoveryEntryKind.CHILD_ACTIVATED: (
        SchedulerTruncationRecoveryChildActivation
    ),
    SchedulerTruncationRecoveryEntryKind.CHILD_PREFLIGHT_TERMINAL: (
        SchedulerTruncationRecoveryChildPreflightResult
    ),
    SchedulerTruncationRecoveryEntryKind.CHILD_DISPATCHED: (
        SchedulerTruncationRecoveryChildDispatch
    ),
    SchedulerTruncationRecoveryEntryKind.CHILD_TERMINAL: (SchedulerTruncationRecoveryChildResult),
    SchedulerTruncationRecoveryEntryKind.FAMILY_CLOSED: (SchedulerTruncationRecoveryFamilyClosure),
    SchedulerTruncationRecoveryEntryKind.FAMILY_PROMOTED: (
        SchedulerTruncationRecoveryFamilyPromotion
    ),
}


def validate_truncation_recovery_entry_chain(
    entries: Iterable[SchedulerTruncationRecoveryEntry],
) -> tuple[SchedulerTruncationRecoveryEntry, ...]:
    """Revalidate a bounded contiguous hash chain without inferring lifecycle joins."""

    materialized = _bounded_tuple(
        entries,
        limit=SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
        label="journal entries",
    )
    validated: list[SchedulerTruncationRecoveryEntry] = []
    previous: SchedulerTruncationRecoveryEntry | None = None
    for index, entry in enumerate(materialized):
        expected_type = SCHEDULER_TRUNCATION_RECOVERY_ENTRY_TYPES.get(entry.entry_kind)
        if expected_type is None or type(entry) is not expected_type:
            raise ValueError("scheduler truncation recovery entry kind/type is inconsistent")
        frozen = expected_type.model_validate(entry.model_dump(mode="python"), strict=True)
        if (
            isinstance(entry, SchedulerTruncationRecoveryChildResult)
            and isinstance(frozen, SchedulerTruncationRecoveryChildResult)
            and entry.runtime_usage_record is not None
        ):
            # Validation above proves byte equality. Keep the exact live UsageRecord
            # object so its process-local REAL attestation is not laundered away.
            frozen = frozen.model_copy(update={"runtime_usage_record": entry.runtime_usage_record})
        if (
            frozen.entry_index != index
            or frozen.previous_entry_sha256
            != (previous.entry_sha256 if previous is not None else None)
            or (previous is not None and frozen.campaign_id != previous.campaign_id)
        ):
            raise ValueError("scheduler truncation recovery entries are not one exact chain")
        validated.append(frozen)
        previous = frozen
    return tuple(validated)


__all__ = [
    "SCHEDULER_TRUNCATION_RECOVERY_ENTRY_TYPES",
    "SCHEDULER_TRUNCATION_RECOVERY_JOURNAL_VERSION",
    "SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES",
    "SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES",
    "SchedulerRecoveredCandidateOrigin",
    "SchedulerRecoveredCandidateOriginKind",
    "SchedulerRecoveredCandidateReviewOutput",
    "SchedulerTruncationRecoveryChildActivation",
    "SchedulerTruncationRecoveryChildDispatch",
    "SchedulerTruncationRecoveryChildPreflightResult",
    "SchedulerTruncationRecoveryChildResult",
    "SchedulerTruncationRecoveryClosureStatus",
    "SchedulerTruncationRecoveryCostDisposition",
    "SchedulerTruncationRecoveryEntry",
    "SchedulerTruncationRecoveryEntryKind",
    "SchedulerTruncationRecoveryFamilyClosure",
    "SchedulerTruncationRecoveryFamilyPromotion",
    "SchedulerTruncationRecoveryFamilyRoot",
    "SchedulerTruncationRecoveryParentKind",
    "SchedulerTruncationRecoveryPromotionBinding",
    "SchedulerTruncationRecoveryRequestLimitBinding",
    "SchedulerTruncationRecoveryRequestedSurfaceManifest",
    "SchedulerTruncationRecoveryResultOrigin",
    "SchedulerTruncationRecoveryTerminalStatus",
    "rebuild_truncation_recovery_parent_from_projection",
    "validate_truncation_recovery_entry_chain",
]
