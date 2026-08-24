"""Live boundary for narrowly scoped candidate-review truncation surface closure.

Durable closure artifacts remain comparison-only.  Opaque process-local custody is
issued only by replaying one exact root family, its direct typed successful children,
and the original live usage records.  This module exposes no conversion to usage,
model-selection, lineage, release, or other trusted authority types.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import weakref
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice
from typing import Any, Never, Protocol, SupportsIndex

from pydantic import BaseModel

from mmaudit.models.scheduler import scheduler_canonical_sha256
from mmaudit.models.schemas import (
    ContextPackage,
    ContextRequestEvidence,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewTruncatedEnvelopeEvidence,
)
from mmaudit.models.truncation_closure import (
    MAX_TRUNCATION_CLOSURE_SURFACES,
    TruncationClosureError,
    TruncationRecoveredSurfaceReviewArtifact,
    TruncationRecoveryChildCompletionEvidence,
    TruncationRecoveryParentAttemptEvidence,
    build_truncation_recovered_surface_artifact,
)
from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TruncationRecoveryChannel,
    TruncationRecoveryChannelState,
    TruncationRecoveryChildPlan,
    TruncationRecoveryPlan,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryParentKind,
    SchedulerTruncationRecoveryResultOrigin,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.models.usage import (
    atomic_request_limit_reservations_from_usage,
    is_accountable_usage_record,
    is_recovery_creditable_usage_record,
)
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence
from mmaudit.orchestration.context import (
    ContextBoundaryError,
    render_context,
    revalidate_model_surface_context_package,
)
from mmaudit.orchestration.model_review_evidence import (
    ModelReviewEvidenceError,
    model_surface_review_excerpt_validation_failures,
    validate_model_surface_review_record,
)

_WHOLE_PROTOCOL_REQUEST_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")


class TruncationRecoveryEvidenceError(ValueError):
    """Raised when live recovery-family evidence cannot close a surface set."""


@dataclass(frozen=True, slots=True)
class TruncationRecoveryChildInput:
    """One child completion and the exact context rendered for that child."""

    completion: TruncationRecoveryChildCompletionEvidence
    context: ContextPackage

    def __post_init__(self) -> None:
        if type(self.completion) is not TruncationRecoveryChildCompletionEvidence:
            raise TypeError("truncation recovery child completion has an invalid exact type")
        if type(self.context) is not ContextPackage:
            raise TypeError("truncation recovery child context has an invalid exact type")


class VerifiedTruncationRecoveryClosure:
    """Opaque PID-local proof of one exact direct-success recovery family."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Never:
        del cls, _args, _kwargs
        raise TypeError("verified truncation recovery closure cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("truncation recovery closure capabilities cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> Never:
        del memo
        raise TypeError("truncation recovery closure capabilities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("truncation recovery closure capabilities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("truncation recovery closure capabilities cannot be serialized")


class VerifiedPromotedTruncationRecoverySurfaceCoverage:
    """Opaque PID-local proof that one live closure was durably promoted."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> Never:
        del cls, _args, _kwargs
        raise TypeError("promoted truncation surface coverage cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("promoted truncation surface coverage capabilities cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> Never:
        del memo
        raise TypeError("promoted truncation surface coverage capabilities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("promoted truncation surface coverage capabilities cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        del protocol
        raise TypeError("promoted truncation surface coverage capabilities cannot be serialized")


@dataclass(frozen=True, slots=True)
class VerifiedTruncationRecoveryClosureProjection:
    """Fresh closure output plus exact request-scoped scanner fingerprints."""

    family_id: str
    family_root_sha256: str
    family_closure_id: str
    family_closure_sha256: str
    child_result_entry_sha256s: tuple[str, ...]
    artifact: TruncationRecoveredSurfaceReviewArtifact
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...]
    parent_usage_record: UsageRecord
    child_usage_records: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    child_contexts: tuple[ContextPackage, ...]


@dataclass(frozen=True, slots=True)
class VerifiedPromotedTruncationRecoverySurfaceCoverageProjection:
    """Fresh promoted surface union and its exact durable promotion identities."""

    promotion_entry_sha256: str
    recovered_output_artifact_sha256: str
    family_id: str
    family_root_sha256: str
    family_closure_id: str
    family_closure_sha256: str
    child_result_entry_sha256s: tuple[str, ...]
    artifact: TruncationRecoveredSurfaceReviewArtifact
    parent_usage_record: UsageRecord
    child_usage_records: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    child_contexts: tuple[ContextPackage, ...]


@dataclass(frozen=True, slots=True)
class _VerifiedTruncationRecoveryMaterial:
    family: SchedulerTruncationRecoveryFamilyRoot
    closure: SchedulerTruncationRecoveryFamilyClosure
    child_results: tuple[SchedulerTruncationRecoveryChildResult, ...]
    parent_usage_record: UsageRecord
    child_usage_records: tuple[UsageRecord, ...]
    parent_context: ContextPackage
    child_contexts: tuple[ContextPackage, ...]
    requests: tuple[ModelSurfaceReviewRequest, ...]
    artifact: TruncationRecoveredSurfaceReviewArtifact
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class _VerifiedTruncationRecoveryState:
    process_id: int
    family_json: str
    closure_json: str
    child_result_jsons: tuple[str, ...]
    parent_usage_record: UsageRecord
    child_usage_records: tuple[UsageRecord, ...]
    parent_context_json: str
    child_context_jsons: tuple[str, ...]
    request_jsons: tuple[str, ...]
    artifact_json: str
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class _VerifiedPromotedTruncationRecoverySurfaceCoverageState:
    process_id: int
    journal_reference: weakref.ReferenceType[object]
    family_id: str
    closure_capability: VerifiedTruncationRecoveryClosure
    promotion_json: str


class _VerifyTruncationRecoveryClosure(Protocol):
    def __call__(
        self,
        *,
        family: SchedulerTruncationRecoveryFamilyRoot,
        closure: SchedulerTruncationRecoveryFamilyClosure,
        child_results: Iterable[SchedulerTruncationRecoveryChildResult],
        parent_usage_record: UsageRecord,
        child_usage_records: Iterable[UsageRecord],
        parent_context: ContextPackage,
        child_contexts: Iterable[ContextPackage],
        requests: Iterable[ModelSurfaceReviewRequest],
    ) -> tuple[
        VerifiedTruncationRecoveryClosure,
        TruncationRecoveredSurfaceReviewArtifact,
    ]: ...


class _RequireTruncationRecoveryClosure(Protocol):
    def __call__(
        self,
        capability: VerifiedTruncationRecoveryClosure,
    ) -> VerifiedTruncationRecoveryClosureProjection: ...


class _IssuePromotedTruncationRecoverySurfaceCoverage(Protocol):
    def __call__(
        self,
        *,
        journal: object,
        family_id: str,
        closure_capability: VerifiedTruncationRecoveryClosure,
    ) -> VerifiedPromotedTruncationRecoverySurfaceCoverage: ...


class _RequirePromotedTruncationRecoverySurfaceCoverage(Protocol):
    def __call__(
        self,
        capability: VerifiedPromotedTruncationRecoverySurfaceCoverage,
    ) -> VerifiedPromotedTruncationRecoverySurfaceCoverageProjection: ...


class _AccountableUsagePredicate(Protocol):
    def __call__(
        self,
        record: UsageRecord,
        *,
        require_real: bool = False,
    ) -> bool: ...


class _RecoveryCreditableUsagePredicate(Protocol):
    def __call__(
        self,
        record: UsageRecord,
        *,
        request_limit_scope: str,
        request_limit_count_before: int,
        require_real: bool = False,
        require_certification: bool = False,
    ) -> bool: ...


class _AtomicRequestLimitParser(Protocol):
    def __call__(
        self,
        record: UsageRecord,
    ) -> tuple[AtomicRequestLimitReservationEvidence, ...]: ...


def seal_truncation_recovery_surface_evidence(
    *,
    recovery_plan: TruncationRecoveryPlan,
    requests: Iterable[ModelSurfaceReviewRequest],
    parent: TruncationRecoveryParentAttemptEvidence,
    parent_context: ContextPackage,
    children: Iterable[TruncationRecoveryChildInput],
) -> TruncationRecoveredSurfaceReviewArtifact:
    """Revalidate inputs into non-creditable exact surface-partition evidence."""

    exact_requests = _bounded_tuple(
        requests,
        limit=MAX_TRUNCATION_CLOSURE_SURFACES,
        label="requested surfaces",
    )
    child_inputs = _bounded_tuple(
        children,
        limit=TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
        label="child inputs",
    )
    if not exact_requests or not child_inputs:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery closure requires requested surfaces and child completions"
        )
    if type(recovery_plan) is not TruncationRecoveryPlan:
        raise TruncationRecoveryEvidenceError("truncation recovery plan has an invalid exact type")
    if type(parent) is not TruncationRecoveryParentAttemptEvidence:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent has an invalid exact type"
        )
    if type(parent_context) is not ContextPackage:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent context has an invalid exact type"
        )
    if any(type(item) is not ModelSurfaceReviewRequest for item in exact_requests):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery requested surface has an invalid exact type"
        )
    if any(type(item) is not TruncationRecoveryChildInput for item in child_inputs):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child input has an invalid exact type"
        )
    try:
        sealed_parent_context = revalidate_model_surface_context_package(parent_context)
    except ContextBoundaryError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent context failed exact boundary validation"
        ) from exc
    if tuple(sealed_parent_context.requested_model_surfaces) != exact_requests:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent context differs from requested surfaces"
        )
    analysis_context_sha256 = model_surface_analysis_context_sha256(sealed_parent_context)
    _require_usage_context(
        usage=parent.usage_record,
        context=sealed_parent_context,
    )
    if not is_accountable_usage_record(parent.usage_record):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent lacks live accountable usage custody"
        )
    request_by_id = {request.surface_id: request for request in exact_requests}
    for record in parent.projection.surface_reviews:
        request = request_by_id.get(record.surface_id)
        if request is None:
            raise TruncationRecoveryEvidenceError(
                "truncation recovery parent retained an unrequested surface"
            )
        _validate_surface_record(
            context=sealed_parent_context,
            request=request,
            record=record,
            expected_role=parent.usage_record.role,
        )

    completions: list[TruncationRecoveryChildCompletionEvidence] = []
    for child_input in child_inputs:
        completion = child_input.completion
        try:
            child_context = revalidate_model_surface_context_package(child_input.context)
        except ContextBoundaryError as exc:
            raise TruncationRecoveryEvidenceError(
                "truncation recovery child context failed exact boundary validation"
            ) from exc
        expected_child_context = build_truncation_recovery_child_context(
            parent_context=sealed_parent_context,
            child=completion.child_plan,
        )
        if (
            child_context != expected_child_context
            or tuple(child_context.requested_model_surfaces) != completion.requests
            or model_surface_analysis_context_sha256(child_context) != analysis_context_sha256
            or completion.analysis_context_sha256 != analysis_context_sha256
        ):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery child context drifted from its planned analysis"
            )
        _require_usage_context(usage=completion.usage_record, context=child_context)
        if not is_recovery_creditable_usage_record(
            completion.usage_record,
            request_limit_scope=completion.request_limit_scope,
            request_limit_count_before=completion.request_limit_count_before,
        ):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery child lacks live creditable usage custody"
            )
        child_requests = {request.surface_id: request for request in completion.requests}
        for record in completion.surface_artifact.records:
            request = child_requests.get(record.surface_id)
            if request is None:
                raise TruncationRecoveryEvidenceError(
                    "truncation recovery child retained an unrequested surface"
                )
            _validate_surface_record(
                context=child_context,
                request=request,
                record=record,
                expected_role=completion.usage_record.role,
            )
        completions.append(completion)
    try:
        artifact = build_truncation_recovered_surface_artifact(
            recovery_plan=recovery_plan,
            analysis_context_sha256=analysis_context_sha256,
            requests=exact_requests,
            parent=parent,
            children=completions,
        )
    except TruncationClosureError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery family failed exact surface closure"
        ) from exc
    return artifact


def _verify_live_truncation_recovery_material(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    closure: SchedulerTruncationRecoveryFamilyClosure,
    child_results: Iterable[SchedulerTruncationRecoveryChildResult],
    parent_usage_record: UsageRecord,
    child_usage_records: Iterable[UsageRecord],
    parent_context: ContextPackage,
    child_contexts: Iterable[ContextPackage],
    requests: Iterable[ModelSurfaceReviewRequest],
    _accountable_usage_predicate: _AccountableUsagePredicate = is_accountable_usage_record,
    _recovery_creditable_usage_predicate: _RecoveryCreditableUsagePredicate = (
        is_recovery_creditable_usage_record
    ),
    _parent_request_limit_parser: _AtomicRequestLimitParser = (
        atomic_request_limit_reservations_from_usage
    ),
) -> _VerifiedTruncationRecoveryMaterial:
    """Rebuild one direct-success family from durable structure and live custody."""

    if type(family) is not SchedulerTruncationRecoveryFamilyRoot:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery family root has an invalid exact type"
        )
    if type(closure) is not SchedulerTruncationRecoveryFamilyClosure:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery family closure has an invalid exact type"
        )
    if type(parent_usage_record) is not UsageRecord:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent usage has an invalid exact type"
        )
    if type(parent_context) is not ContextPackage:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent context has an invalid exact type"
        )
    exact_result_inputs = _bounded_tuple(
        child_results,
        limit=2,
        label="direct child results",
    )
    live_child_usages = _bounded_tuple(
        child_usage_records,
        limit=2,
        label="live child usage records",
    )
    child_context_inputs = _bounded_tuple(
        child_contexts,
        limit=2,
        label="direct child contexts",
    )
    request_inputs = _bounded_tuple(
        requests,
        limit=MAX_TRUNCATION_CLOSURE_SURFACES,
        label="requested surfaces",
    )
    if (
        len(exact_result_inputs) != 2
        or len(live_child_usages) != 2
        or len(child_context_inputs) != 2
        or not request_inputs
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery closure requires exactly two direct successful children"
        )
    if any(
        type(result) is not SchedulerTruncationRecoveryChildResult for result in exact_result_inputs
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child result has an invalid exact type"
        )
    if any(type(usage) is not UsageRecord for usage in live_child_usages):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child usage has an invalid exact type"
        )
    if any(type(context) is not ContextPackage for context in child_context_inputs):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child context has an invalid exact type"
        )
    if any(type(request) is not ModelSurfaceReviewRequest for request in request_inputs):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery requested surface has an invalid exact type"
        )

    try:
        exact_family = SchedulerTruncationRecoveryFamilyRoot.model_validate_json(
            _canonical_model_json(family),
            strict=True,
        )
        exact_closure = SchedulerTruncationRecoveryFamilyClosure.model_validate_json(
            _canonical_model_json(closure),
            strict=True,
        )
        exact_results = tuple(
            SchedulerTruncationRecoveryChildResult.model_validate_json(
                _canonical_model_json(result),
                strict=True,
            )
            for result in exact_result_inputs
        )
        exact_requests = tuple(
            ModelSurfaceReviewRequest.model_validate_json(
                _canonical_model_json(request),
                strict=True,
            )
            for request in request_inputs
        )
        sealed_parent_context = revalidate_model_surface_context_package(parent_context)
    except (AttributeError, TypeError, ValueError) as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery scheduler evidence failed exact reconstruction"
        ) from exc

    plan = exact_family.recovery_plan
    if (
        exact_family.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
        or exact_family.parent_family_id is not None
        or plan.parent.current_depth != 0
        or exact_family.truncation_projection.findings_state
        is not CandidateReviewChannelState.COMPLETE
        or any(child.channel is not TruncationRecoveryChannel.COVERAGE for child in plan.children)
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery closure requires a direct root with complete parent findings"
        )
    findings_bindings = tuple(
        binding
        for binding in plan.parent.channel_bindings
        if binding.channel is TruncationRecoveryChannel.FINDINGS
    )
    if (
        len(findings_bindings) != 1
        or findings_bindings[0].state is not TruncationRecoveryChannelState.COMPLETE
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent findings binding is not complete"
        )
    if (
        exact_closure.schema_version != "1.1"
        or exact_closure.closure_status
        is not SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        or exact_closure.campaign_id != exact_family.campaign_id
        or exact_closure.request_limit_id != exact_family.request_limit_id
        or exact_closure.request_limit_binding_sha256 != exact_family.request_limit_binding_sha256
        or exact_closure.family_index != exact_family.family_index
        or exact_closure.family_id != exact_family.family_id
        or exact_closure.family_root_sha256 != exact_family.entry_sha256
        or exact_closure.recovery_plan_sha256 != plan.plan_sha256
        or exact_closure.nested_family_closure_sha256s
        or exact_closure.covered_unfinished_surface_ids != plan.parent.unfinished_surface_ids
        or exact_closure.child_result_sha256s
        != tuple(result.entry_sha256 for result in exact_results)
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery family closure differs from its exact direct root"
        )
    if tuple(result.child_plan_sha256 for result in exact_results) != tuple(
        child.child_plan_sha256 for child in plan.children
    ) or tuple(result.child_task_id for result in exact_results) != tuple(
        child.child_task_id for child in plan.children
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery direct child result order differs from the frozen plan"
        )
    for child, result in zip(plan.children, exact_results, strict=True):
        if (
            result.schema_version not in {"1.1", "1.2"}
            or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            or result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
            or result.family_id != exact_family.family_id
            or result.family_root_sha256 != exact_family.entry_sha256
            or result.child_logical_request_id != child.child_logical_request_id
            or result.child_surface_ids != child.surface_ids
            or result.runtime_activation is None
            or result.runtime_request_limit_reservation is None
            or result.runtime_usage_record is None
            or result.runtime_normalization_evidence is None
            or result.runtime_normalized_batch is None
            or result.runtime_requested_surface_requests is None
            or result.runtime_output_artifact is None
            or result.runtime_truncated_envelope_evidence is not None
            or result.truncation_projection is not None
        ):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery closure contains mixed or non-success child custody"
            )

    if (
        tuple(sealed_parent_context.requested_model_surfaces) != exact_requests
        or exact_family.requested_surface_manifest.requests != exact_requests
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent context differs from the frozen surface manifest"
        )
    _require_usage_context(usage=parent_usage_record, context=sealed_parent_context)
    if not _accountable_usage_predicate(parent_usage_record, require_real=True):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent lacks live re-attested accountable usage custody"
        )
    try:
        parent_reservations = _parent_request_limit_parser(parent_usage_record)
    except ValueError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent request-limit custody is invalid"
        ) from exc
    if parent_reservations != (
        exact_family.request_limit_binding.parent_request_limit_reservation,
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent request-limit custody differs from the family root"
        )
    envelope = _truncated_envelope_from_usage(parent_usage_record)
    try:
        parent = TruncationRecoveryParentAttemptEvidence.build(
            parent_task_id=plan.parent.parent_task_id,
            parent_activation_sha256=plan.parent.parent_activation_sha256,
            provider_attempt_evidence_sha256=plan.parent.provider_attempt_evidence_sha256,
            usage_record=parent_usage_record,
            envelope=envelope,
            projection=exact_family.truncation_projection,
        )
    except (TypeError, ValueError) as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent differs from its typed root custody"
        ) from exc
    if not _models_are_byte_equal(parent_usage_record, parent.usage_record):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery live parent usage differs from structural custody"
        )
    request_by_id = {request.surface_id: request for request in exact_requests}
    for record in parent.projection.surface_reviews:
        request = request_by_id.get(record.surface_id)
        if request is None:
            raise TruncationRecoveryEvidenceError(
                "truncation recovery parent retained an unrequested surface"
            )
        _validate_surface_record(
            context=sealed_parent_context,
            request=request,
            record=record,
            expected_role=parent_usage_record.role,
        )

    analysis_context_sha256 = model_surface_analysis_context_sha256(sealed_parent_context)
    completions: list[TruncationRecoveryChildCompletionEvidence] = []
    sealed_child_contexts: list[ContextPackage] = []
    for child, result, live_usage, context_input in zip(
        plan.children,
        exact_results,
        live_child_usages,
        child_context_inputs,
        strict=True,
    ):
        activation = result.runtime_activation
        structural_usage = result.runtime_usage_record
        normalization = result.runtime_normalization_evidence
        normalized_batch = result.runtime_normalized_batch
        child_requests = result.runtime_requested_surface_requests
        output_artifact = result.runtime_output_artifact
        if (
            activation is None
            or structural_usage is None
            or normalization is None
            or normalized_batch is None
            or child_requests is None
            or output_artifact is None
        ):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery successful child omitted typed custody"
            )
        if not _models_are_byte_equal(live_usage, structural_usage):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery live child usage differs from structural custody"
            )
        if not _recovery_creditable_usage_predicate(
            live_usage,
            request_limit_scope=activation.request_limit_id,
            request_limit_count_before=activation.request_limit_count_before_child,
            require_real=True,
        ):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery child lacks live re-attested creditable usage custody"
            )
        try:
            sealed_child_context = revalidate_model_surface_context_package(context_input)
        except ContextBoundaryError as exc:
            raise TruncationRecoveryEvidenceError(
                "truncation recovery child context failed exact boundary validation"
            ) from exc
        expected_child_context = build_truncation_recovery_child_context(
            parent_context=sealed_parent_context,
            child=child,
        )
        if (
            sealed_child_context != expected_child_context
            or tuple(sealed_child_context.requested_model_surfaces) != child_requests
            or model_surface_analysis_context_sha256(sealed_child_context)
            != analysis_context_sha256
        ):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery child context drifted from its direct planned shard"
            )
        _require_usage_context(usage=live_usage, context=sealed_child_context)
        try:
            completion = TruncationRecoveryChildCompletionEvidence.build(
                child_plan=child,
                analysis_context_sha256=analysis_context_sha256,
                requests=child_requests,
                request_limit_scope=activation.request_limit_id,
                request_limit_count_before=activation.request_limit_count_before_child,
                usage_record=structural_usage,
                normalization=normalization,
                normalized_batch=normalized_batch,
                surface_artifact=output_artifact,
            )
        except (TypeError, ValueError) as exc:
            raise TruncationRecoveryEvidenceError(
                "truncation recovery child typed completion custody is inconsistent"
            ) from exc
        child_request_by_id = {request.surface_id: request for request in child_requests}
        for record in output_artifact.records:
            request = child_request_by_id.get(record.surface_id)
            if request is None:
                raise TruncationRecoveryEvidenceError(
                    "truncation recovery child retained an unrequested surface"
                )
            _validate_surface_record(
                context=sealed_child_context,
                request=request,
                record=record,
                expected_role=live_usage.role,
            )
        completions.append(completion)
        sealed_child_contexts.append(sealed_child_context)

    try:
        artifact = build_truncation_recovered_surface_artifact(
            recovery_plan=plan,
            analysis_context_sha256=analysis_context_sha256,
            requests=exact_requests,
            parent=parent,
            children=completions,
        )
    except TruncationClosureError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery typed family failed exact surface closure"
        ) from exc
    scanner_fingerprints_by_request = _scanner_fingerprint_projection(
        parent_request_id=parent_usage_record.request_id,
        parent_context=sealed_parent_context,
        child_request_ids=tuple(usage.request_id for usage in live_child_usages),
        child_contexts=tuple(sealed_child_contexts),
    )
    return _VerifiedTruncationRecoveryMaterial(
        family=exact_family,
        closure=exact_closure,
        child_results=exact_results,
        parent_usage_record=parent_usage_record,
        child_usage_records=live_child_usages,
        parent_context=sealed_parent_context,
        child_contexts=tuple(sealed_child_contexts),
        requests=exact_requests,
        artifact=artifact,
        scanner_fingerprints_by_request=scanner_fingerprints_by_request,
    )


def build_truncation_recovery_child_context(
    *,
    parent_context: ContextPackage,
    child: TruncationRecoveryChildPlan,
) -> ContextPackage:
    """Derive one strict coverage shard without changing its analysis facts."""

    if type(parent_context) is not ContextPackage:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent context has an invalid exact type"
        )
    if type(child) is not TruncationRecoveryChildPlan:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child plan has an invalid exact type"
        )
    try:
        child = TruncationRecoveryChildPlan.model_validate(
            child.model_dump(mode="python"),
            strict=True,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child plan failed exact boundary validation"
        ) from exc
    if child.channel is not TruncationRecoveryChannel.COVERAGE:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child context requires a coverage shard"
        )
    try:
        sealed_parent = revalidate_model_surface_context_package(parent_context)
    except ContextBoundaryError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent context failed exact boundary validation"
        ) from exc
    requests_by_id = {
        request.surface_id: request for request in sealed_parent.requested_model_surfaces
    }
    if len(requests_by_id) != len(sealed_parent.requested_model_surfaces):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent surface inventory is ambiguous"
        )
    if any(surface_id not in requests_by_id for surface_id in child.surface_ids):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child requested an unknown parent surface"
        )
    child_requests = tuple(requests_by_id[surface_id] for surface_id in child.surface_ids)
    if tuple(request.surface_id for request in child_requests) != child.surface_ids:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child surface inventory is not exact"
        )
    original_analysis_sha256 = model_surface_analysis_context_sha256(sealed_parent)
    provisional = sealed_parent.model_copy(
        update={"requested_model_surfaces": child_requests},
        deep=True,
    )
    rendered_bytes = len(render_context(provisional).encode("utf-8"))
    try:
        sealed_child = revalidate_model_surface_context_package(
            provisional.model_copy(update={"bytes_used": rendered_bytes}, deep=True)
        )
    except ContextBoundaryError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child context failed exact boundary validation"
        ) from exc
    if (
        tuple(sealed_child.requested_model_surfaces) != child_requests
        or model_surface_analysis_context_sha256(sealed_child) != original_analysis_sha256
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery child context drifted from parent analysis facts"
        )
    return sealed_child


def model_surface_analysis_context_sha256(context: ContextPackage) -> str:
    """Hash analysis facts that must remain invariant across smaller context shards."""

    try:
        sealed = revalidate_model_surface_context_package(context)
    except ContextBoundaryError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery analysis context failed exact validation"
        ) from exc
    payload = {
        "domain": "mmaudit.truncation-recovery.analysis-context.v1",
        "repository_map": sealed.repository_map.model_dump(mode="json"),
        "scanner_findings": [item.model_dump(mode="json") for item in sealed.scanner_findings],
        "threat_model": (
            sealed.threat_model.model_dump(mode="json") if sealed.threat_model is not None else None
        ),
        "solidity_projects": [item.model_dump(mode="json") for item in sealed.solidity_projects],
        "solidity_compilations": [
            item.model_dump(mode="json") for item in sealed.solidity_compilations
        ],
        "solidity_index": (
            sealed.solidity_index.model_dump(mode="json")
            if sealed.solidity_index is not None
            else None
        ),
        "solidity_graphs": (
            sealed.solidity_graphs.model_dump(mode="json")
            if sealed.solidity_graphs is not None
            else None
        ),
        "solidity_invariants": (
            sealed.solidity_invariants.model_dump(mode="json")
            if sealed.solidity_invariants is not None
            else None
        ),
        "invariant_executions": [
            item.model_dump(mode="json") for item in sealed.invariant_executions
        ],
        "economic_simulations": [
            item.model_dump(mode="json") for item in sealed.economic_simulations
        ],
        "formal_runs": [item.model_dump(mode="json") for item in sealed.formal_runs],
        "solidity_coverage": (
            sealed.solidity_coverage.model_dump(mode="json")
            if sealed.solidity_coverage is not None
            else None
        ),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _require_usage_context(*, usage: UsageRecord, context: ContextPackage) -> None:
    raw = usage.routing.get("context_request_evidence")
    if not isinstance(raw, dict):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery usage lacks typed context evidence"
        )
    try:
        evidence = ContextRequestEvidence.model_validate_json(
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
        raise TruncationRecoveryEvidenceError(
            "truncation recovery usage context evidence is invalid"
        ) from exc
    rendered_sha256 = hashlib.sha256(render_context(context).encode("utf-8")).hexdigest()
    role_matches = usage.role == context.role or (
        context.role == "whole_protocol_review"
        and _WHOLE_PROTOCOL_REQUEST_ROLE.fullmatch(usage.role) is not None
    )
    if (
        not role_matches
        or evidence.request_id != usage.request_id
        or evidence.request_role != usage.role
        or evidence.context_role != context.role
        or evidence.rendered_sha256 != rendered_sha256
        or usage.user_prompt_sha256 != rendered_sha256
        or usage.routing.get("context_request_evidence_sha256") != evidence.evidence_sha256
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery usage differs from exact rendered context"
        )


def _validate_surface_record(
    *,
    context: ContextPackage,
    request: ModelSurfaceReviewRequest,
    record: ModelSurfaceReviewRecord,
    expected_role: str,
) -> None:
    try:
        validate_model_surface_review_record(
            request,
            record,
            expected_role=expected_role,
            index=context.solidity_index,
            graphs=context.solidity_graphs,
        )
        failures = model_surface_review_excerpt_validation_failures(
            context=context,
            request=request,
            record=record,
        )
    except ModelReviewEvidenceError as exc:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery surface record failed substantive validation"
        ) from exc
    if failures:
        raise TruncationRecoveryEvidenceError(failures[0])


def _bounded_tuple[ItemT](
    values: Iterable[ItemT],
    *,
    limit: int,
    label: str,
) -> tuple[ItemT, ...]:
    try:
        items = tuple(islice(iter(values), limit + 1))
    except (TypeError, ValueError) as exc:
        raise TruncationRecoveryEvidenceError(
            f"truncation recovery {label} is not iterable"
        ) from exc
    if len(items) > limit:
        raise TruncationRecoveryEvidenceError(f"truncation recovery {label} exceeds its item limit")
    return items


def _canonical_model_json(model: BaseModel) -> str:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _models_are_byte_equal(left: BaseModel, right: BaseModel) -> bool:
    return type(left) is type(right) and _canonical_model_json(left) == _canonical_model_json(right)


def _scanner_fingerprint_projection(
    *,
    parent_request_id: str,
    parent_context: ContextPackage,
    child_request_ids: tuple[str, ...],
    child_contexts: tuple[ContextPackage, ...],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if len(child_request_ids) != len(child_contexts):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery scanner projection lacks an exact request/context join"
        )
    request_contexts = (
        (parent_request_id, parent_context),
        *zip(child_request_ids, child_contexts, strict=True),
    )
    if len({request_id for request_id, _context in request_contexts}) != len(request_contexts):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery scanner projection contains duplicate request identities"
        )
    projection: list[tuple[str, tuple[str, ...]]] = []
    for request_id, context in request_contexts:
        fingerprints = tuple(sorted({finding.fingerprint for finding in context.scanner_findings}))
        if any(
            re.fullmatch(r"^[0-9a-f]{64}$", fingerprint) is None for fingerprint in fingerprints
        ):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery scanner projection contains an invalid fingerprint"
            )
        projection.append((request_id, fingerprints))
    return tuple(sorted(projection))


def _truncated_envelope_from_usage(
    usage: UsageRecord,
) -> CandidateReviewTruncatedEnvelopeEvidence:
    raw = usage.routing.get("candidate_review_truncated_envelope_evidence")
    if not isinstance(raw, dict):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent lacks typed truncated-envelope custody"
        )
    try:
        envelope = CandidateReviewTruncatedEnvelopeEvidence.model_validate_json(
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
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent truncated-envelope custody is invalid"
        ) from exc
    if usage.routing.get("candidate_review_truncated_envelope_sha256") != envelope.evidence_sha256:
        raise TruncationRecoveryEvidenceError(
            "truncation recovery parent truncated-envelope hash is inconsistent"
        )
    return envelope


def _build_truncation_recovery_runtime_authority() -> tuple[
    _VerifyTruncationRecoveryClosure,
    _RequireTruncationRecoveryClosure,
]:
    """Capture exact replay helpers and reject inherited authority after a fork."""

    capability_type = VerifiedTruncationRecoveryClosure
    projection_type = VerifiedTruncationRecoveryClosureProjection
    state_type = _VerifiedTruncationRecoveryState
    verify_material = _verify_live_truncation_recovery_material
    canonical_model_json = _canonical_model_json
    current_process_id = os.getpid
    owner_process_id = current_process_id()
    make_weakref = weakref.ref
    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[VerifiedTruncationRecoveryClosure],
            _VerifiedTruncationRecoveryState,
        ],
    ] = {}
    lock = threading.RLock()

    def replay(
        state: _VerifiedTruncationRecoveryState,
    ) -> VerifiedTruncationRecoveryClosureProjection:
        try:
            family = SchedulerTruncationRecoveryFamilyRoot.model_validate_json(
                state.family_json,
                strict=True,
            )
            closure = SchedulerTruncationRecoveryFamilyClosure.model_validate_json(
                state.closure_json,
                strict=True,
            )
            child_results = tuple(
                SchedulerTruncationRecoveryChildResult.model_validate_json(
                    payload,
                    strict=True,
                )
                for payload in state.child_result_jsons
            )
            parent_context = ContextPackage.model_validate_json(
                state.parent_context_json,
                strict=True,
            )
            child_contexts = tuple(
                ContextPackage.model_validate_json(payload, strict=True)
                for payload in state.child_context_jsons
            )
            requests = tuple(
                ModelSurfaceReviewRequest.model_validate_json(payload, strict=True)
                for payload in state.request_jsons
            )
        except (TypeError, ValueError) as exc:
            raise TruncationRecoveryEvidenceError(
                "verified truncation recovery closure state failed exact replay"
            ) from exc
        material = verify_material(
            family=family,
            closure=closure,
            child_results=child_results,
            parent_usage_record=state.parent_usage_record,
            child_usage_records=state.child_usage_records,
            parent_context=parent_context,
            child_contexts=child_contexts,
            requests=requests,
        )
        if (
            canonical_model_json(material.artifact) != state.artifact_json
            or material.scanner_fingerprints_by_request != state.scanner_fingerprints_by_request
        ):
            raise TruncationRecoveryEvidenceError(
                "verified truncation recovery closure artifact changed during replay"
            )
        return projection_type(
            family_id=material.family.family_id,
            family_root_sha256=material.family.entry_sha256,
            family_closure_id=material.closure.closure_id,
            family_closure_sha256=material.closure.entry_sha256,
            child_result_entry_sha256s=tuple(
                result.entry_sha256 for result in material.child_results
            ),
            artifact=material.artifact,
            scanner_fingerprints_by_request=material.scanner_fingerprints_by_request,
            parent_usage_record=material.parent_usage_record,
            child_usage_records=material.child_usage_records,
            parent_context=material.parent_context,
            child_contexts=material.child_contexts,
        )

    def verify(
        *,
        family: SchedulerTruncationRecoveryFamilyRoot,
        closure: SchedulerTruncationRecoveryFamilyClosure,
        child_results: Iterable[SchedulerTruncationRecoveryChildResult],
        parent_usage_record: UsageRecord,
        child_usage_records: Iterable[UsageRecord],
        parent_context: ContextPackage,
        child_contexts: Iterable[ContextPackage],
        requests: Iterable[ModelSurfaceReviewRequest],
    ) -> tuple[
        VerifiedTruncationRecoveryClosure,
        TruncationRecoveredSurfaceReviewArtifact,
    ]:
        if current_process_id() != owner_process_id:
            raise TruncationRecoveryEvidenceError(
                "truncation recovery closure verifier cannot cross a process fork"
            )
        material = verify_material(
            family=family,
            closure=closure,
            child_results=child_results,
            parent_usage_record=parent_usage_record,
            child_usage_records=child_usage_records,
            parent_context=parent_context,
            child_contexts=child_contexts,
            requests=requests,
        )
        capability = object.__new__(capability_type)
        state = state_type(
            process_id=current_process_id(),
            family_json=canonical_model_json(material.family),
            closure_json=canonical_model_json(material.closure),
            child_result_jsons=tuple(
                canonical_model_json(result) for result in material.child_results
            ),
            parent_usage_record=material.parent_usage_record,
            child_usage_records=material.child_usage_records,
            parent_context_json=canonical_model_json(material.parent_context),
            child_context_jsons=tuple(
                canonical_model_json(context) for context in material.child_contexts
            ),
            request_jsons=tuple(canonical_model_json(request) for request in material.requests),
            artifact_json=canonical_model_json(material.artifact),
            scanner_fingerprints_by_request=material.scanner_fingerprints_by_request,
        )
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[VerifiedTruncationRecoveryClosure],
        ) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = make_weakref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        return capability, material.artifact

    def require(
        capability: VerifiedTruncationRecoveryClosure,
    ) -> VerifiedTruncationRecoveryClosureProjection:
        process_id = current_process_id()
        if process_id != owner_process_id:
            raise TruncationRecoveryEvidenceError(
                "verified truncation recovery closure cannot cross a process fork"
            )
        with lock:
            registered = registry.get(id(capability))
        state = (
            registered[1]
            if type(capability) is capability_type
            and registered is not None
            and registered[0]() is capability
            else None
        )
        if state is None:
            raise TruncationRecoveryEvidenceError(
                "verified truncation recovery closure is absent or forged"
            )
        if state.process_id != process_id:
            raise TruncationRecoveryEvidenceError(
                "verified truncation recovery closure cannot cross a process fork"
            )
        return replay(state)

    return verify, require


_verify_truncation_recovery_closure, _require_truncation_recovery_closure = (
    _build_truncation_recovery_runtime_authority()
)


def _validated_promoted_surface_projection(
    *,
    closure: VerifiedTruncationRecoveryClosureProjection,
    promotion: SchedulerTruncationRecoveryFamilyPromotion,
) -> VerifiedPromotedTruncationRecoverySurfaceCoverageProjection:
    output = promotion.recovered_output
    artifact = closure.artifact
    expected_capability_binding_sha256 = scheduler_canonical_sha256(
        {
            "domain": "mmaudit.scheduler.truncation-recovery-promotion-capability.v1",
            "family_id": closure.family_id,
            "family_root_sha256": closure.family_root_sha256,
            "family_closure_id": closure.family_closure_id,
            "family_closure_sha256": closure.family_closure_sha256,
            "structural_surface_artifact_sha256": artifact.artifact_sha256,
            "scanner_fingerprints_by_request": closure.scanner_fingerprints_by_request,
            "recovered_output_sha256": output.output_artifact_sha256,
        }
    )
    if (
        promotion.family_id != closure.family_id
        or promotion.family_root_sha256 != closure.family_root_sha256
        or promotion.family_closure_sha256 != closure.family_closure_sha256
        or promotion.direct_child_result_sha256s != closure.child_result_entry_sha256s
        or output.recovery_family_id != closure.family_id
        or output.family_root_sha256 != closure.family_root_sha256
        or output.family_closure_sha256 != closure.family_closure_sha256
        or output.structural_surface_artifact_sha256 != artifact.artifact_sha256
        or output.parent_task_id != artifact.parent_task_id
        or output.parent_logical_request_id != artifact.parent_logical_request_id
        or output.recovered_batch.surface_reviews != artifact.records
        or promotion.capability_binding_sha256 != expected_capability_binding_sha256
    ):
        raise TruncationRecoveryEvidenceError(
            "truncation recovery promotion differs from its live surface closure"
        )
    return VerifiedPromotedTruncationRecoverySurfaceCoverageProjection(
        promotion_entry_sha256=promotion.entry_sha256,
        recovered_output_artifact_sha256=output.output_artifact_sha256,
        family_id=closure.family_id,
        family_root_sha256=closure.family_root_sha256,
        family_closure_id=closure.family_closure_id,
        family_closure_sha256=closure.family_closure_sha256,
        child_result_entry_sha256s=closure.child_result_entry_sha256s,
        artifact=artifact,
        parent_usage_record=closure.parent_usage_record,
        child_usage_records=closure.child_usage_records,
        parent_context=closure.parent_context,
        child_contexts=closure.child_contexts,
    )


def _build_promoted_truncation_recovery_surface_coverage_authority() -> tuple[
    _IssuePromotedTruncationRecoverySurfaceCoverage,
    _RequirePromotedTruncationRecoverySurfaceCoverage,
]:
    """Bind one live closure to a promotion retained by its exact journal."""

    capability_type = VerifiedPromotedTruncationRecoverySurfaceCoverage
    state_type = _VerifiedPromotedTruncationRecoverySurfaceCoverageState
    canonical_model_json = _canonical_model_json
    require_closure = _require_truncation_recovery_closure
    validate_projection = _validated_promoted_surface_projection
    current_process_id = os.getpid
    owner_process_id = current_process_id()
    make_weakref = weakref.ref
    registry: dict[
        int,
        tuple[
            weakref.ReferenceType[VerifiedPromotedTruncationRecoverySurfaceCoverage],
            _VerifiedPromotedTruncationRecoverySurfaceCoverageState,
        ],
    ] = {}
    lock = threading.RLock()

    def current_promotion(
        journal: object, family_id: str
    ) -> SchedulerTruncationRecoveryFamilyPromotion:
        # Imported lazily because the scheduler owns this module's closure verifier.
        from mmaudit.orchestration.scheduler import SchedulerJournal

        if type(journal) is not SchedulerJournal:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage lacks exact scheduler custody"
            )
        try:
            return journal._require_current_promoted_truncation_recovery_family(family_id)
        except ValueError as exc:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage lacks a retained journal promotion"
            ) from exc

    def issue(
        *,
        journal: object,
        family_id: str,
        closure_capability: VerifiedTruncationRecoveryClosure,
    ) -> VerifiedPromotedTruncationRecoverySurfaceCoverage:
        if current_process_id() != owner_process_id:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage cannot cross a process fork"
            )
        promotion = current_promotion(journal, family_id)
        closure = require_closure(closure_capability)
        validate_projection(closure=closure, promotion=promotion)
        capability = object.__new__(capability_type)
        try:
            journal_reference = make_weakref(journal)
        except TypeError as exc:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage journal cannot be retained"
            ) from exc
        state = state_type(
            process_id=current_process_id(),
            journal_reference=journal_reference,
            family_id=family_id,
            closure_capability=closure_capability,
            promotion_json=canonical_model_json(promotion),
        )
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[VerifiedPromotedTruncationRecoverySurfaceCoverage],
        ) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = make_weakref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        return capability

    def require(
        capability: VerifiedPromotedTruncationRecoverySurfaceCoverage,
    ) -> VerifiedPromotedTruncationRecoverySurfaceCoverageProjection:
        process_id = current_process_id()
        if process_id != owner_process_id:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage cannot cross a process fork"
            )
        with lock:
            registered = registry.get(id(capability))
        state = (
            registered[1]
            if type(capability) is capability_type
            and registered is not None
            and registered[0]() is capability
            else None
        )
        if state is None:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage is absent or forged"
            )
        journal = state.journal_reference()
        if state.process_id != process_id or journal is None:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage lost live journal custody"
            )
        promotion = current_promotion(journal, state.family_id)
        if canonical_model_json(promotion) != state.promotion_json:
            raise TruncationRecoveryEvidenceError(
                "promoted truncation surface coverage journal state changed"
            )
        closure = require_closure(state.closure_capability)
        return validate_projection(closure=closure, promotion=promotion)

    return issue, require


(
    _issue_verified_promoted_truncation_recovery_surface_coverage,
    _require_verified_promoted_truncation_recovery_surface_coverage,
) = _build_promoted_truncation_recovery_surface_coverage_authority()


def verify_truncation_recovery_closure(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    closure: SchedulerTruncationRecoveryFamilyClosure,
    child_results: Iterable[SchedulerTruncationRecoveryChildResult],
    parent_usage_record: UsageRecord,
    child_usage_records: Iterable[UsageRecord],
    parent_context: ContextPackage,
    child_contexts: Iterable[ContextPackage],
    requests: Iterable[ModelSurfaceReviewRequest],
) -> tuple[
    VerifiedTruncationRecoveryClosure,
    TruncationRecoveredSurfaceReviewArtifact,
]:
    """Issue narrow live authority for one exact direct-success scheduler family."""

    return _verify_truncation_recovery_closure(
        family=family,
        closure=closure,
        child_results=child_results,
        parent_usage_record=parent_usage_record,
        child_usage_records=child_usage_records,
        parent_context=parent_context,
        child_contexts=child_contexts,
        requests=requests,
    )


def require_verified_truncation_recovery_closure(
    capability: VerifiedTruncationRecoveryClosure,
    artifact: TruncationRecoveredSurfaceReviewArtifact | None = None,
) -> TruncationRecoveredSurfaceReviewArtifact:
    """Replay live custody and return a fresh exact nonauthorizing artifact."""

    return require_verified_truncation_recovery_closure_projection(
        capability,
        artifact,
    ).artifact


def require_verified_truncation_recovery_closure_projection(
    capability: VerifiedTruncationRecoveryClosure,
    artifact: TruncationRecoveredSurfaceReviewArtifact | None = None,
) -> VerifiedTruncationRecoveryClosureProjection:
    """Return fresh artifact and context-derived scanner fingerprints for promotion."""

    fresh = _require_truncation_recovery_closure(capability)
    if artifact is not None:
        if type(artifact) is not TruncationRecoveredSurfaceReviewArtifact:
            raise TruncationRecoveryEvidenceError(
                "truncation recovery surface artifact has an invalid exact type"
            )
        if not _models_are_byte_equal(fresh.artifact, artifact):
            raise TruncationRecoveryEvidenceError(
                "truncation recovery surface artifact differs from verified closure state"
            )
    return fresh


def require_verified_promoted_truncation_recovery_surface_coverage(
    capability: VerifiedPromotedTruncationRecoverySurfaceCoverage,
) -> VerifiedPromotedTruncationRecoverySurfaceCoverageProjection:
    """Replay one journal-owned promoted surface union without serialized authority."""

    return _require_verified_promoted_truncation_recovery_surface_coverage(capability)
