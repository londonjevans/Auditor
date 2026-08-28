"""Descriptor-safe durable journal for the seven-pass audit scheduler.

The pure identities and state derivations live in :mod:`mmaudit.models.scheduler`.
This module owns only private filesystem custody and append-only transitions.  A
logical task is resumable only while it has never been dispatched.  Recovery
concludes a dispatch with no durable result as ``UNCERTAIN`` and never retries or
credits that work automatically.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
)
from enum import StrEnum
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, cast

from pydantic import BaseModel

from mmaudit.models.candidate_review_stamping import (
    CandidateReviewStampingError,
    stamp_candidate_review_findings,
)
from mmaudit.models.scheduler import (
    ABSENT_COST_LEDGER_BASELINE_SHA256,
    SCHEDULER_PASS_ORDER,
    SchedulerAnalysisInputInventory,
    SchedulerArtifact,
    SchedulerAuditModelRefreshBinding,
    SchedulerAuditModelRefreshPricingBinding,
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerCampaignStatus,
    SchedulerCampaignSummary,
    SchedulerCostLedgerBaseline,
    SchedulerJournalEvidence,
    SchedulerModelRequestEvidence,
    SchedulerPassDependency,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerPrivacyEvidenceCustody,
    SchedulerProviderAttemptEvidence,
    SchedulerResultOrigin,
    SchedulerShardInventory,
    SchedulerTaskActivation,
    SchedulerTaskEvent,
    SchedulerTaskEventKind,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalReportAuthority,
    SchedulerTerminalStatus,
    SchedulerTruncationRecoveryModelRequestEvidence,
    build_scheduler_model_request_evidence,
    build_scheduler_truncation_recovery_model_request_evidence,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    CandidateCrossExaminationDecision,
    CandidateFinding,
    CandidateReproductionResolution,
    CandidateReviewBatch,
    ConsensusReviewArtifact,
    ContextRequestEvidence,
    FalsificationDecision,
    Finding,
    ModelRequestValidationStatus,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ReportQualityReview,
    ReproductionResult,
    Severity,
    SpecialistAcceptedOutcome,
    StrictModel,
    UsageRecord,
    VerificationDecision,
)
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewFramePhase,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
)
from mmaudit.models.truncation_recovery import (
    TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS,
    TRUNCATION_RECOVERY_MAX_USD_EXACT,
    TruncationRecoveryChildPlan,
    TruncationRecoveryPlan,
    TruncationRecoveryResourceBudget,
)
from mmaudit.models.truncation_recovery_journal import (
    SCHEDULER_TRUNCATION_RECOVERY_ENTRY_TYPES,
    SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
    SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES,
    SchedulerRecoveredCandidateOrigin,
    SchedulerRecoveredCandidateOriginKind,
    SchedulerRecoveredCandidateReviewOutput,
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildDispatch,
    SchedulerTruncationRecoveryChildPreflightResult,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryCostDisposition,
    SchedulerTruncationRecoveryEntry,
    SchedulerTruncationRecoveryEntryKind,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryParentKind,
    SchedulerTruncationRecoveryPromotionBinding,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    SchedulerTruncationRecoveryRequestLimitBinding,
    SchedulerTruncationRecoveryResultOrigin,
    SchedulerTruncationRecoveryTerminalStatus,
    validate_truncation_recovery_entry_chain,
)
from mmaudit.models.usage import (
    _issue_trusted_usage_recovery_scope,
    _recover_trusted_usage_records,
    _TrustedUsageRecoveryScope,
    _validated_usage_copy_preserving_owned_attestation,
    atomic_request_limit_reservations_from_usage,
    atomic_token_reservations_from_usage,
    is_accountable_usage_record,
    is_creditable_usage_record,
    is_recovery_creditable_usage_record,
    is_structurally_accountable_usage_record,
    is_structurally_creditable_usage_record,
    is_structurally_recovery_creditable_usage_record,
    recovery_atomic_request_limit_reservations_from_usage,
)
from mmaudit.orchestration.budgets import (
    _issue_trusted_budget_recovery_scope,
    _TrustedBudgetRecoveryScope,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    ReleaseReason,
    cost_entry_sha256,
)
from mmaudit.orchestration.truncation_recovery_evidence import (
    TruncationRecoveryEvidenceError,
    VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage,
    VerifiedPromotedTruncationRecoverySurfaceCoverage,
    VerifiedRecursiveTruncationRecoveryTree,
    VerifiedTruncationRecoveryClosure,
    _issue_verified_promoted_recursive_truncation_recovery_surface_coverage,
    _issue_verified_promoted_truncation_recovery_surface_coverage,
    require_verified_recursive_truncation_recovery_tree_projection,
    require_verified_truncation_recovery_closure_projection,
)
from mmaudit.reporting.json_report import stable_json

if TYPE_CHECKING:
    from mmaudit.models.policy_selection import VerifiedAuditModelSelection
    from mmaudit.models.qualification import VerifiedProductionQualification
    from mmaudit.models.refresh_runtime import (
        AuditModelRefreshEvidence,
        AuditModelRefreshPricingEvidence,
        VerifiedAuditModelRefreshGuard,
        VerifiedAuditModelRefreshPricingAuthority,
    )

_LOCK_FILENAME = ".scheduler.lock"
_MANIFEST_FILENAME = "manifest.json"
_ANALYSIS_INPUT_INVENTORY_FILENAME = "analysis-input-inventory.json"
_JOURNAL_HEAD_CHECKPOINT_FILENAME = "journal-head-checkpoint.json"
_JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME = ".journal-head-checkpoint.pending"
_JOURNAL_TRANSITION_PREDECESSOR_FILENAME = ".journal-transition-predecessor.pending"
_IMMUTABLE_WRITE_TEMP_PREFIX = ".scheduler-write-"
_IMMUTABLE_WRITE_TEMP_SUFFIX = ".pending"
_TERMINAL_REPORT_AUTHORITY_FILENAME = "terminal-report-authority.json"
_ACTIVATIONS_DIRECTORY = "activations"
_EVENTS_DIRECTORY = "events"
_PASS_PLANS_DIRECTORY = "pass-plans"
_PASS_RESULTS_DIRECTORY = "pass-results"
_TASK_OUTPUTS_DIRECTORY = "task-outputs"
_TASK_RESULTS_DIRECTORY = "task-results"
_PROVIDER_ATTEMPTS_DIRECTORY = "provider-attempts"
_TRUNCATION_RECOVERY_DIRECTORY = "truncation-recovery"
_TRUNCATION_RECOVERY_ACCOUNTING_CONTEXT = Context(
    prec=160,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[InvalidOperation, DivisionByZero, Overflow],
)
_TRUNCATION_RECOVERY_COST_COMPONENT_LIMIT = 700_000 + TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS + 1
_MAX_EVIDENCE_BYTES = 100_000_000
_READ_CHUNK_BYTES = 1024 * 1024
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY_FLAG = getattr(os, "O_DIRECTORY", 0)
_CONTROL_DIRECTORIES = (
    _ACTIVATIONS_DIRECTORY,
    _EVENTS_DIRECTORY,
    _PASS_PLANS_DIRECTORY,
    _PASS_RESULTS_DIRECTORY,
    _TASK_OUTPUTS_DIRECTORY,
    _TASK_RESULTS_DIRECTORY,
    _PROVIDER_ATTEMPTS_DIRECTORY,
    _TRUNCATION_RECOVERY_DIRECTORY,
)
_LIVE_CUSTODY_LOCK = threading.Lock()
_LIVE_CUSTODY: set[tuple[int, int]] = set()
type _EvidenceFileIdentity = tuple[int, int, int, int, int, int, int]
type _DurableArtifactObservation = tuple[str, _EvidenceFileIdentity, str]


@dataclass(frozen=True)
class _OrphanImmutableWrite:
    """One bounded uncommitted temp left by an interrupted immutable write."""

    parent: str | None
    temporary_leaf: str
    target_leaf: str
    identity: _EvidenceFileIdentity
    published_target: bool = False

    @property
    def relative_path(self) -> str:
        return (
            self.temporary_leaf if self.parent is None else f"{self.parent}/{self.temporary_leaf}"
        )

    @property
    def relative_target_path(self) -> str:
        return self.target_leaf if self.parent is None else f"{self.parent}/{self.target_leaf}"


def _detach_canonical_model[ModelT: StrictModel](model: ModelT) -> ModelT:
    """Return a deep copy while preserving any owned live usage capability."""

    detached = type(model).model_validate_json(stable_json(model))
    if isinstance(model, SchedulerTaskOutput) and model.model_completion_evidence is not None:
        assert isinstance(detached, SchedulerTaskOutput)
        completion = detached.model_completion_evidence
        assert completion is not None
        detached = detached.model_copy(
            update={
                "model_completion_evidence": completion.model_copy(
                    update={
                        "usage_record": _validated_usage_copy_preserving_owned_attestation(
                            model.model_completion_evidence.usage_record
                        )
                    }
                )
            }
        )
    elif isinstance(model, SchedulerProviderAttemptEvidence):
        assert isinstance(detached, SchedulerProviderAttemptEvidence)
        detached = detached.model_copy(
            update={
                "usage_record": _validated_usage_copy_preserving_owned_attestation(
                    model.usage_record
                )
            }
        )
    elif (
        isinstance(model, SchedulerTruncationRecoveryChildResult)
        and model.runtime_usage_record is not None
    ):
        assert isinstance(detached, SchedulerTruncationRecoveryChildResult)
        detached = detached.model_copy(
            update={
                "runtime_usage_record": _validated_usage_copy_preserving_owned_attestation(
                    model.runtime_usage_record
                )
            }
        )
    return detached


_TERMINAL_EVENT_KINDS = frozenset(
    {
        SchedulerTaskEventKind.TERMINAL,
        SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
        SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
    }
)
_VALID_TASK_LIFECYCLE_PREFIXES = frozenset(
    {
        (SchedulerTaskEventKind.PLANNED,),
        (SchedulerTaskEventKind.PLANNED, SchedulerTaskEventKind.ACTIVATED),
        (
            SchedulerTaskEventKind.PLANNED,
            SchedulerTaskEventKind.ACTIVATED,
            SchedulerTaskEventKind.DISPATCHED,
        ),
        (
            SchedulerTaskEventKind.PLANNED,
            SchedulerTaskEventKind.ACTIVATED,
            SchedulerTaskEventKind.DISPATCHED,
            SchedulerTaskEventKind.TERMINAL,
        ),
        (SchedulerTaskEventKind.PLANNED, SchedulerTaskEventKind.PREFLIGHT_TERMINAL),
        (
            SchedulerTaskEventKind.PLANNED,
            SchedulerTaskEventKind.ACTIVATED,
            SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
        ),
    }
)


class SchedulerCostRecoveryStatus(StrEnum):
    """Closed cost-ledger outcomes for an interrupted scheduled provider attempt."""

    ADOPTED_PROVEN_PRE_SEND = "adopted_proven_pre_send"
    RELEASED_PROVEN_PRE_SEND = "released_proven_pre_send"
    UNCERTAIN_ACCOUNTED_AFTER_DISPATCH = "uncertain_accounted_after_dispatch"


@dataclass(frozen=True)
class SchedulerCostRecoveryRecord:
    """Process-local exact join from one scheduler task to one recovered ledger entry."""

    request_id: str
    logical_request_id: str
    task_id: str
    requested_model: str
    role: str
    status: SchedulerCostRecoveryStatus
    reserved_cost_usd_exact: Decimal
    accounted_cost_usd_exact: Decimal
    request_limit_scope: str | None = None
    request_limit_count_before: int | None = None
    request_limit_count_after: int | None = None
    request_limit_maximum: int | None = None


@dataclass
class _SchedulerJournalIndexes:
    """Exact in-memory joins for one already validated append-only journal."""

    tasks: dict[str, tuple[SchedulerTaskPlan, SchedulerPassPlan]]
    activations: dict[str, SchedulerTaskActivation]
    outputs: dict[str, SchedulerTaskOutput]
    provider_attempts: dict[str, SchedulerProviderAttemptEvidence]
    results_by_hash: dict[str, SchedulerTaskResult]
    result_observations_by_task: dict[str, list[SchedulerTaskResult]]
    event_histories: dict[str, list[SchedulerTaskEvent]]
    credited_results: dict[str, SchedulerTaskResult]
    event_ids: set[str]


@dataclass
class _SchedulerTruncationRecoveryIndexes:
    """Exact joins for the private nested recovery-family journal."""

    families: dict[str, SchedulerTruncationRecoveryFamilyRoot]
    family_order: list[str]
    children: dict[str, tuple[TruncationRecoveryChildPlan, str]]
    activations: dict[str, SchedulerTruncationRecoveryChildActivation]
    dispatches: dict[str, SchedulerTruncationRecoveryChildDispatch]
    results: dict[
        str,
        SchedulerTruncationRecoveryChildResult | SchedulerTruncationRecoveryChildPreflightResult,
    ]
    closures: dict[str, SchedulerTruncationRecoveryFamilyClosure]
    promotions: dict[str, SchedulerTruncationRecoveryFamilyPromotion]
    family_by_parent_task: dict[str, str]
    nested_family_by_parent_child: dict[str, str]
    promotion_by_parent_task: dict[str, str]
    recovery_requests_consumed: int
    request_limit_attempts_reserved: dict[str, int]


@dataclass(frozen=True)
class _RecoveryChildCostGroup:
    """Fully validated ledger disposition for one recovery-child request."""

    child: TruncationRecoveryChildPlan
    family: SchedulerTruncationRecoveryFamilyRoot
    activation: SchedulerTruncationRecoveryChildActivation
    entries: tuple[tuple[int, CostEntry], ...]
    status: SchedulerCostRecoveryStatus
    retained_usage: bool = False


def _canonical_recovery_usd_sum(values: Iterable[str]) -> str:
    """Sum bounded exact costs without inheriting ambient Decimal state."""

    context = _TRUNCATION_RECOVERY_ACCOUNTING_CONTEXT.copy()
    total = context.create_decimal(0)
    try:
        for index, value in enumerate(values):
            if index >= _TRUNCATION_RECOVERY_COST_COMPONENT_LIMIT:
                raise ValueError("scheduler recovery cost evidence exceeds its item limit")
            if type(value) is not str:
                raise ValueError("scheduler recovery cost evidence is not exact text")
            amount = context.create_decimal(value)
            if not amount.is_finite() or amount < 0:
                raise ValueError("scheduler recovery cost evidence is invalid")
            total = context.add(total, amount)
    except InvalidOperation:
        raise ValueError("scheduler recovery cost evidence is invalid") from None
    rendered = format(total, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return "0" if rendered in {"", "-0"} else rendered


def _main_scheduler_usage_records(
    scheduler: _SchedulerJournalIndexes,
    *,
    maximum_pass_ordinal: int,
) -> tuple[UsageRecord, ...]:
    records = tuple(
        output.model_completion_evidence.usage_record
        for task_id, output in scheduler.outputs.items()
        if output.model_completion_evidence is not None
        and SCHEDULER_PASS_ORDER.index(scheduler.tasks[task_id][1].pass_kind)
        <= maximum_pass_ordinal
    ) + tuple(
        attempt.usage_record
        for task_id, attempt in scheduler.provider_attempts.items()
        if SCHEDULER_PASS_ORDER.index(scheduler.tasks[task_id][1].pass_kind) <= maximum_pass_ordinal
    )
    request_ids = tuple(record.request_id for record in records)
    if len(request_ids) != len(set(request_ids)):
        raise ValueError("scheduler recovery accounting repeats a main request")
    return records


def _require_quiescent_scheduler_for_recovery(
    scheduler: _SchedulerJournalIndexes,
    *,
    maximum_pass_ordinal: int,
) -> None:
    for task_id, (task, plan) in scheduler.tasks.items():
        if (
            task.task_kind is SchedulerTaskKind.MODEL_REQUEST
            and SCHEDULER_PASS_ORDER.index(plan.pass_kind) <= maximum_pass_ordinal
            and task_id in scheduler.activations
            and task_id not in scheduler.credited_results
        ):
            raise ValueError(
                "scheduler recovery planning requires quiescent main provider accounting"
            )


def _recovery_commitments_except_parent(
    *,
    indexes: _SchedulerTruncationRecoveryIndexes,
    excluded_child_task_id: str | None,
) -> tuple[tuple[str, ...], int, int]:
    costs: list[str] = []
    attempts = 0
    completion_tokens = 0
    for child_task_id, (child, _family_id) in sorted(indexes.children.items()):
        if child_task_id == excluded_child_task_id:
            continue
        result = indexes.results.get(child_task_id)
        if result is None:
            costs.append(child.reserved_usd_exact)
            attempts += child.reserved_provider_attempts
            completion_tokens += child.reserved_completion_tokens
            continue
        costs.append(result.accounted_cost_usd_exact)
        attempts += result.accounted_provider_attempts
        completion_tokens += result.accounted_completion_tokens
    return tuple(costs), attempts, completion_tokens


def _require_exact_recovery_resources(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    scheduler: _SchedulerJournalIndexes,
    indexes: _SchedulerTruncationRecoveryIndexes,
    parent_usage: UsageRecord | None,
    parent_result: SchedulerTruncationRecoveryChildResult | None,
) -> None:
    """Join every pre-parent/parent scalar to durable local accounting evidence."""

    if (parent_usage is None) == (parent_result is None):
        raise ValueError("scheduler recovery parent accounting is absent or ambiguous")
    matching_parent_passes = {
        SCHEDULER_PASS_ORDER.index(plan.pass_kind)
        for _task, plan in scheduler.tasks.values()
        if plan.pass_plan_id == family.recovery_plan.parent.pass_plan_id
    }
    if len(matching_parent_passes) != 1:
        raise ValueError("scheduler recovery parent pass is absent or ambiguous")
    maximum_pass_ordinal = matching_parent_passes.pop()
    _require_quiescent_scheduler_for_recovery(
        scheduler,
        maximum_pass_ordinal=maximum_pass_ordinal,
    )
    main_records = _main_scheduler_usage_records(
        scheduler,
        maximum_pass_ordinal=maximum_pass_ordinal,
    )
    excluded_request_id = parent_usage.request_id if parent_usage is not None else None
    prior_main = tuple(
        record for record in main_records if record.request_id != excluded_request_id
    )
    if parent_usage is not None and len(prior_main) + 1 != len(main_records):
        raise ValueError("scheduler recovery parent usage is absent from durable accounting")

    recovery_costs, recovery_attempts, recovery_tokens = _recovery_commitments_except_parent(
        indexes=indexes,
        excluded_child_task_id=(parent_result.child_task_id if parent_result is not None else None),
    )
    # A provider campaign baseline is the durable cap/spend authority. Provider-free
    # structural fixtures without one remain bounded by the compiled $250 ceiling.
    campaign_baseline = scheduler.tasks[next(iter(scheduler.tasks))][
        1
    ].manifest.cost_ledger_baseline
    cap = (
        _canonical_recovery_usd_sum((campaign_baseline.cap_usd_exact,))
        if campaign_baseline is not None
        else TRUNCATION_RECOVERY_MAX_USD_EXACT
    )
    baseline_spent = campaign_baseline.spent_usd_exact if campaign_baseline is not None else "0"
    prior_costs = (
        baseline_spent,
        *(record.accounted_cost_usd_exact or "" for record in prior_main),
        *recovery_costs,
    )
    parent_cost = (
        parent_usage.accounted_cost_usd_exact
        if parent_usage is not None
        else parent_result.accounted_cost_usd_exact
        if parent_result is not None
        else None
    )
    if parent_cost is None or any(value == "" for value in prior_costs):
        raise ValueError("scheduler recovery lacks exact parent or prior cost evidence")
    expected = TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact=cap,
        accounted_usd_before_parent_exact=_canonical_recovery_usd_sum(prior_costs),
        parent_accounted_cost_usd_exact=_canonical_recovery_usd_sum((parent_cost,)),
        child_reserved_usd_exact=family.recovery_plan.resources.child_reserved_usd_exact,
        recovery_requests_consumed=indexes.recovery_requests_consumed,
        provider_attempts_before_parent=(
            sum(record.attempts for record in prior_main) + recovery_attempts
        ),
        parent_provider_attempts=(
            parent_usage.attempts
            if parent_usage is not None
            else parent_result.accounted_provider_attempts
            if parent_result is not None
            else 0
        ),
        child_provider_attempts=family.recovery_plan.resources.child_provider_attempts,
        completion_tokens_before_parent=(
            sum(record.completion_tokens for record in prior_main) + recovery_tokens
        ),
        parent_completion_tokens=(
            parent_usage.completion_tokens
            if parent_usage is not None
            else parent_result.accounted_completion_tokens
            if parent_result is not None
            else 0
        ),
        child_completion_tokens=family.recovery_plan.resources.child_completion_tokens,
    )
    if family.recovery_plan.resources != expected:
        raise ValueError("scheduler recovery plan resources differ from durable accounting")


def _validate_root_scheduler_parent(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    scheduler: _SchedulerJournalIndexes,
    indexes: _SchedulerTruncationRecoveryIndexes,
) -> None:
    parent = family.recovery_plan.parent
    task_and_plan = scheduler.tasks.get(parent.parent_task_id)
    activation = scheduler.activations.get(parent.parent_task_id)
    attempt = scheduler.provider_attempts.get(parent.parent_task_id)
    result = scheduler.credited_results.get(parent.parent_task_id)
    if task_and_plan is None or activation is None or attempt is None or result is None:
        raise ValueError("scheduler recovery root lacks exact durable parent evidence")
    task, pass_plan = task_and_plan
    usage = attempt.usage_record
    try:
        request_limit_reservations = atomic_request_limit_reservations_from_usage(usage)
    except ValueError:
        raise ValueError(
            "scheduler recovery root lacks exact parent request-limit evidence"
        ) from None
    parent_request_limit_reservation = family.request_limit_binding.parent_request_limit_reservation
    expected_parent_request_limit_request_id = (
        usage.request_id if usage.attempts == 1 else f"{usage.request_id}:attempt:{usage.attempts}"
    )
    if (
        not request_limit_reservations
        or request_limit_reservations[-1] != parent_request_limit_reservation
        or parent_request_limit_reservation.request_limit_scope != task.logical_request_id
        or parent_request_limit_reservation.request_id != expected_parent_request_limit_request_id
        or parent_request_limit_reservation.exact_model_id != usage.requested_model
        or parent_request_limit_reservation.role != usage.role
        or task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
        or pass_plan.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
        or result.terminal_status is not SchedulerTerminalStatus.TRUNCATED
        or result.result_origin is not SchedulerResultOrigin.ACTIVATED
        or family.parent_terminal_result_sha256 != result.result_sha256
        or result.terminal_evidence_sha256 != family.truncation_projection.evidence_sha256
        or parent.campaign_id != task.campaign_id
        or parent.pass_plan_id != pass_plan.pass_plan_id
        or parent.parent_logical_request_id != task.logical_request_id
        or parent.parent_task_plan_sha256 != task.task_plan_sha256
        or parent.parent_activation_sha256 != activation.activation_sha256
        or parent.provider_attempt_evidence_sha256 != attempt.attempt_evidence_sha256
        or family.request_limit_id != task.logical_request_id
        or usage.validation_status is not ModelRequestValidationStatus.TRUNCATED
        or usage.status != "rejected_truncated_response"
        or usage.validated_response_sha256 is not None
        or attempt.validated_response_sha256 is not None
        or usage.response_sha256 != family.truncation_projection.original_response_sha256
        or attempt.provider_response_sha256 != family.truncation_projection.original_response_sha256
        or usage.schema_sha256 != family.truncation_projection.wire_schema_sha256
        or attempt.response_schema_sha256 != family.truncation_projection.wire_schema_sha256
    ):
        raise ValueError("scheduler recovery root differs from its truncated parent task")
    _require_exact_recovery_resources(
        family=family,
        scheduler=scheduler,
        indexes=indexes,
        parent_usage=usage,
        parent_result=None,
    )


def _validate_nested_recovery_parent(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    indexes: _SchedulerTruncationRecoveryIndexes,
    scheduler: _SchedulerJournalIndexes,
) -> None:
    parent = family.recovery_plan.parent
    child_match = indexes.children.get(parent.parent_task_id)
    activation = indexes.activations.get(parent.parent_task_id)
    result = indexes.results.get(parent.parent_task_id)
    if child_match is None or activation is None or result is None:
        raise ValueError("nested scheduler recovery root lacks exact durable parent evidence")
    child, parent_family_id = child_match
    parent_family = indexes.families[parent_family_id]
    sibling_children = tuple(
        candidate
        for candidate in parent_family.recovery_plan.children
        if candidate.child_task_id != child.child_task_id
    )
    sibling_result = (
        indexes.results.get(sibling_children[0].child_task_id)
        if len(sibling_children) == 1
        else None
    )
    sibling_activation = (
        indexes.activations.get(sibling_children[0].child_task_id)
        if len(sibling_children) == 1
        else None
    )
    if (
        not isinstance(result, SchedulerTruncationRecoveryChildResult)
        or result.schema_version != "1.1"
        or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
        or result.runtime_usage_record is None
        or result.runtime_activation != activation
        or result.runtime_specialist_accepted_outcome is not None
        or result.runtime_specialist_accepted_outcome_sha256 is not None
        or family.parent_family_id != parent_family_id
        or parent_family.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
        or parent_family.parent_family_id is not None
        or parent_family.recovery_plan.parent.current_depth != 0
        or parent_family_id in indexes.closures
        or not isinstance(sibling_result, SchedulerTruncationRecoveryChildResult)
        or sibling_result.schema_version != "1.1"
        or sibling_result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
        or sibling_result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        or sibling_result.runtime_usage_record is None
        or sibling_result.runtime_activation != sibling_activation
        or sibling_result.runtime_specialist_accepted_outcome is not None
        or sibling_result.runtime_specialist_accepted_outcome_sha256 is not None
        or sibling_result.completed_surface_ids != sibling_children[0].surface_ids
        or sibling_activation is None
        or sibling_activation.request_role != activation.request_role
        or child.parent_depth != 0
        or child.depth != 1
        or parent.parent_logical_request_id != child.child_logical_request_id
        or parent.parent_task_plan_sha256 != child.child_plan_sha256
        or parent.parent_activation_sha256 != activation.entry_sha256
        or parent.provider_attempt_evidence_sha256 != result.provider_attempt_evidence_sha256
        or parent.pass_plan_id != child.pass_plan_id
        or parent.requested_surface_manifest_sha256 != child.requested_surface_manifest_sha256
        or parent.requested_surface_ids != child.surface_ids
        or parent.current_depth != child.depth
        or parent.current_depth != 1
        or parent.parent_path != child.path
        or any(
            grandchild.parent_depth != 1 or grandchild.depth != 2
            for grandchild in (family.recovery_plan.children)
        )
        or result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
        or result.truncation_projection != family.truncation_projection
        or family.truncation_projection.findings_state is not CandidateReviewChannelState.COMPLETE
        or family.truncation_projection.surface_reviews
        or result.retained_surface_ids
        or family.parent_terminal_result_sha256 != result.entry_sha256
        or family.request_limit_binding != parent_family.request_limit_binding
        or family.requested_surface_manifest != parent_family.requested_surface_manifest
        or activation.request_role is None
        or activation.request_role.startswith("specialist:")
        or parent.parent_task_id in indexes.nested_family_by_parent_child
        or any(
            candidate.parent_family_id == parent_family_id
            for candidate in indexes.families.values()
        )
    ):
        raise ValueError("nested scheduler recovery root differs from its truncated child")
    assert isinstance(result, SchedulerTruncationRecoveryChildResult)
    _require_exact_recovery_resources(
        family=family,
        scheduler=scheduler,
        indexes=indexes,
        parent_usage=None,
        parent_result=result,
    )


def _typed_recovery_usage_coordinate(
    *,
    result: SchedulerTruncationRecoveryChildResult,
    child: TruncationRecoveryChildPlan,
    activation: SchedulerTruncationRecoveryChildActivation,
    family: SchedulerTruncationRecoveryFamilyRoot,
) -> tuple[str, str, int]:
    """Derive one recovery usage position only from exact durable scheduler custody."""

    usage = result.runtime_usage_record
    parent_request = family.request_limit_binding.parent_request_limit_reservation
    preceding_reserved_attempts = sum(
        item.reserved_provider_attempts
        for item in family.recovery_plan.children
        if item.ordinal < child.ordinal
    )
    expected_count_before = family.request_limit_count_before_family + preceding_reserved_attempts
    if (
        result.schema_version not in {"1.1", "1.2", "1.3"}
        or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
        or usage is None
        or result.runtime_activation != activation
        or activation.child_task_id != child.child_task_id
        or activation.child_logical_request_id != child.child_logical_request_id
        or activation.request_limit_id != family.request_limit_id
        or activation.request_limit_binding_sha256 != family.request_limit_binding_sha256
        or activation.request_limit_id != parent_request.request_limit_scope
        or activation.request_limit_count_before_child != expected_count_before
        or activation.request_limit_count_after_child
        != expected_count_before + child.reserved_provider_attempts
        or activation.request_limit_maximum != parent_request.request_limit_maximum
        or activation.request_role != parent_request.role
        or activation.requested_model != parent_request.exact_model_id
        or usage.request_id != child.child_logical_request_id
    ):
        raise ValueError("typed scheduler recovery usage lacks exact durable coordinates")
    return usage.request_id, parent_request.request_limit_scope, expected_count_before


def _expected_recovery_family_closure(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    indexes: _SchedulerTruncationRecoveryIndexes,
) -> tuple[
    SchedulerTruncationRecoveryClosureStatus,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    result_hashes: list[str] = []
    nested_hashes: list[str] = []
    covered: set[str] = set()
    uncertain = False
    all_branches_have_typed_coverage = True
    direct_typed_successes: list[SchedulerTruncationRecoveryChildResult] = []
    nested_typed_coverage_count = 0
    for child in family.recovery_plan.children:
        result = indexes.results.get(child.child_task_id)
        if result is None:
            raise ValueError("scheduler recovery family has an unfinished child")
        result_hashes.append(result.entry_sha256)
        if (
            isinstance(result, SchedulerTruncationRecoveryChildResult)
            and result.schema_version in {"1.1", "1.2"}
            and result.result_origin is SchedulerTruncationRecoveryResultOrigin.RUNTIME
            and result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        ):
            activation = indexes.activations.get(child.child_task_id)
            if activation is None:
                raise ValueError("typed recovery success lacks its durable activation")
            _typed_recovery_usage_coordinate(
                result=result,
                child=child,
                activation=activation,
                family=family,
            )
            direct_typed_successes.append(result)
            covered.update(result.completed_surface_ids)
            continue
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED:
            raise ValueError(
                "v1 recovery closure lacks exact typed runtime child completion custody"
            )
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
            if (
                not isinstance(result, SchedulerTruncationRecoveryChildResult)
                or result.schema_version != "1.1"
                or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            ):
                raise ValueError(
                    "v1 recovery closure lacks exact typed runtime child completion custody"
                )
            if family.parent_kind is SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD:
                all_branches_have_typed_coverage = False
                continue
            nested_family_id = indexes.nested_family_by_parent_child.get(child.child_task_id)
            if nested_family_id is None:
                all_branches_have_typed_coverage = False
                continue
            nested_family = indexes.families[nested_family_id]
            nested_closure = indexes.closures.get(nested_family_id)
            if nested_closure is None:
                raise ValueError("scheduler recovery family has an unfinished nested family")
            if (
                nested_family.parent_kind
                is not SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD
                or nested_family.parent_family_id != family.family_id
                or nested_family.recovery_plan.parent.parent_task_id != child.child_task_id
                or nested_family.recovery_plan.parent.current_depth != 1
                or nested_family.recovery_plan.parent.parent_path != child.path
                or nested_closure.family_id != nested_family.family_id
            ):
                raise ValueError("scheduler recovery nested closure differs from its ancestor")
            nested_hashes.append(nested_closure.entry_sha256)
            if (
                nested_closure.schema_version == "1.1"
                and nested_closure.closure_status
                is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                and nested_closure.covered_unfinished_surface_ids == child.surface_ids
            ):
                covered.update(nested_closure.covered_unfinished_surface_ids)
                nested_typed_coverage_count += 1
                continue
            all_branches_have_typed_coverage = False
            if nested_closure.closure_status is SchedulerTruncationRecoveryClosureStatus.UNCERTAIN:
                uncertain = True
            continue
        all_branches_have_typed_coverage = False
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN:
            uncertain = True
            continue

    expected_surfaces = set(family.recovery_plan.parent.unfinished_surface_ids)
    if not covered <= expected_surfaces:
        raise ValueError("scheduler recovery closure covers surfaces outside its frozen parent")
    if nested_hashes and (
        family.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
        or len(nested_hashes) != 1
        or nested_typed_coverage_count != 1
        or len(direct_typed_successes) != 1
        or direct_typed_successes[0].schema_version != "1.1"
    ):
        all_branches_have_typed_coverage = False
    exact_typed_coverage = all_branches_have_typed_coverage and covered == expected_surfaces
    status = (
        SchedulerTruncationRecoveryClosureStatus.UNCERTAIN
        if uncertain
        else (
            SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
            if nested_hashes
            else SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        )
        if exact_typed_coverage
        else SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
    )
    return (
        status,
        tuple(result_hashes),
        tuple(nested_hashes),
        tuple(sorted(covered)),
    )


@dataclass(frozen=True, slots=True)
class _RecoveredCandidateReviewContent:
    findings: tuple[CandidateFinding, ...]
    surface_reviews: tuple[ModelSurfaceReviewRecord, ...]
    origins: tuple[SchedulerRecoveredCandidateOrigin, ...]
    child_results: tuple[SchedulerTruncationRecoveryChildResult, ...]


@dataclass(frozen=True, slots=True)
class _RecursiveRecoveryTreeInventory:
    """Exact durable shape of the single supported recursive recovery tree."""

    bridge_child: TruncationRecoveryChildPlan
    bridge_result: SchedulerTruncationRecoveryChildResult
    direct_leaf_child: TruncationRecoveryChildPlan
    direct_leaf_result: SchedulerTruncationRecoveryChildResult
    root_results: tuple[
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
    ]
    nested_family: SchedulerTruncationRecoveryFamilyRoot
    nested_closure: SchedulerTruncationRecoveryFamilyClosure
    nested_leaf_results: tuple[
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
    ]

    @property
    def root_result_sha256s(self) -> tuple[str, str]:
        return (self.root_results[0].entry_sha256, self.root_results[1].entry_sha256)

    @property
    def direct_child_result_sha256s(self) -> tuple[str, str]:
        return self.root_result_sha256s

    @property
    def nested_result_sha256s(self) -> tuple[str, str]:
        return (
            self.nested_leaf_results[0].entry_sha256,
            self.nested_leaf_results[1].entry_sha256,
        )

    @property
    def nested_child_result_sha256s(self) -> tuple[str, str]:
        return self.nested_result_sha256s

    @property
    def promoted_leaf_results(
        self,
    ) -> tuple[
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
    ]:
        return (self.direct_leaf_result, *self.nested_leaf_results)

    @property
    def promoted_leaf_result_sha256s(self) -> tuple[str, str, str]:
        return (
            self.promoted_leaf_results[0].entry_sha256,
            self.promoted_leaf_results[1].entry_sha256,
            self.promoted_leaf_results[2].entry_sha256,
        )

    @property
    def tree_results(
        self,
    ) -> tuple[
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
        SchedulerTruncationRecoveryChildResult,
    ]:
        return (*self.root_results, *self.nested_leaf_results)


def _recursive_recovery_tree_inventory(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    closure: SchedulerTruncationRecoveryFamilyClosure,
    indexes: _SchedulerTruncationRecoveryIndexes,
) -> _RecursiveRecoveryTreeInventory:
    """Reconstruct the one-level zero-retained tree from durable journal indexes."""

    if (
        family.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
        or family.parent_family_id is not None
        or closure.schema_version != "1.2"
        or closure.closure_status
        is not SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
        or len(family.recovery_plan.children) != 2
        or len(closure.child_result_sha256s) != 2
        or len(closure.nested_family_closure_sha256s) != 1
    ):
        raise ValueError("scheduler recursive promotion lacks one exact root closure")
    root_results: list[
        tuple[TruncationRecoveryChildPlan, SchedulerTruncationRecoveryChildResult]
    ] = []
    for child in family.recovery_plan.children:
        result = indexes.results.get(child.child_task_id)
        if (
            not isinstance(result, SchedulerTruncationRecoveryChildResult)
            or result.schema_version != "1.1"
            or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            or result.family_id != family.family_id
            or result.family_root_sha256 != family.entry_sha256
            or result.child_task_id != child.child_task_id
            or result.child_logical_request_id != child.child_logical_request_id
            or result.child_plan_sha256 != child.child_plan_sha256
            or result.child_surface_ids != child.surface_ids
            or result.runtime_specialist_accepted_outcome is not None
            or result.runtime_specialist_accepted_outcome_sha256 is not None
        ):
            raise ValueError("scheduler recursive promotion root child custody is not exact")
        root_results.append((child, result))
    if closure.child_result_sha256s != tuple(
        result.entry_sha256 for _child, result in root_results
    ):
        raise ValueError("scheduler recursive promotion root result order is inconsistent")
    bridges = tuple(
        (child, result)
        for child, result in root_results
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
        and result.truncation_projection is not None
        and result.truncation_projection.findings_state is CandidateReviewChannelState.COMPLETE
        and not result.retained_surface_ids
        and not result.truncation_projection.surface_reviews
    )
    direct_leaves = tuple(
        (child, result)
        for child, result in root_results
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
        and result.completed_surface_ids == child.surface_ids
        and result.runtime_usage_record is not None
        and result.runtime_normalized_batch is not None
        and result.runtime_output_artifact is not None
    )
    if len(bridges) != 1 or len(direct_leaves) != 1:
        raise ValueError("scheduler recursive promotion requires one bridge and one direct leaf")
    bridge_child, bridge_result = bridges[0]
    direct_leaf_child, direct_leaf_result = direct_leaves[0]
    nested_family_id = indexes.nested_family_by_parent_child.get(bridge_child.child_task_id)
    nested_family = indexes.families.get(nested_family_id) if nested_family_id is not None else None
    nested_closure = (
        indexes.closures.get(nested_family_id) if nested_family_id is not None else None
    )
    if (
        nested_family is None
        or nested_closure is None
        or nested_family.parent_kind is not SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD
        or nested_family.parent_family_id != family.family_id
        or nested_family.recovery_plan.parent.parent_task_id != bridge_child.child_task_id
        or nested_family.parent_terminal_result_sha256 != bridge_result.entry_sha256
        or nested_family.recovery_plan.parent.current_depth != 1
        or nested_family.recovery_plan.parent.parent_path != bridge_child.path
        or nested_closure.schema_version != "1.1"
        or nested_closure.closure_status
        is not SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        or nested_closure.entry_sha256 not in closure.nested_family_closure_sha256s
        or len(nested_family.recovery_plan.children) != 2
    ):
        raise ValueError("scheduler recursive promotion lacks one exact nested closure")
    nested_results_list: list[SchedulerTruncationRecoveryChildResult] = []
    for child in nested_family.recovery_plan.children:
        result = indexes.results.get(child.child_task_id)
        if (
            not isinstance(result, SchedulerTruncationRecoveryChildResult)
            or result.schema_version != "1.1"
            or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            or result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
            or result.family_id != nested_family.family_id
            or result.family_root_sha256 != nested_family.entry_sha256
            or result.child_task_id != child.child_task_id
            or result.child_logical_request_id != child.child_logical_request_id
            or result.child_plan_sha256 != child.child_plan_sha256
            or result.child_surface_ids != child.surface_ids
            or result.completed_surface_ids != child.surface_ids
            or result.runtime_usage_record is None
            or result.runtime_normalized_batch is None
            or result.runtime_output_artifact is None
            or result.runtime_specialist_accepted_outcome is not None
            or result.runtime_specialist_accepted_outcome_sha256 is not None
        ):
            raise ValueError("scheduler recursive promotion nested leaf custody is not exact")
        nested_results_list.append(result)
    nested_results = tuple(nested_results_list)
    if len(nested_results) != 2 or nested_closure.child_result_sha256s != tuple(
        result.entry_sha256 for result in nested_results
    ):
        raise ValueError("scheduler recursive promotion nested result order is inconsistent")
    inventory = _RecursiveRecoveryTreeInventory(
        bridge_child=bridge_child,
        bridge_result=bridge_result,
        direct_leaf_child=direct_leaf_child,
        direct_leaf_result=direct_leaf_result,
        root_results=cast(
            tuple[
                SchedulerTruncationRecoveryChildResult,
                SchedulerTruncationRecoveryChildResult,
            ],
            tuple(result for _child, result in root_results),
        ),
        nested_family=nested_family,
        nested_closure=nested_closure,
        nested_leaf_results=nested_results,
    )
    activations = tuple(
        indexes.activations[result.child_task_id] for result in inventory.tree_results
    )
    expected_ordinals = tuple(
        range(family.request_count_before_family + 1, nested_family.request_count_after_family + 1)
    )
    if tuple(item.global_request_ordinal for item in activations) != expected_ordinals:
        raise ValueError("scheduler recursive promotion leaf order is not globally canonical")
    if (
        len(
            {
                result.runtime_usage_record.request_id
                for result in inventory.tree_results
                if result.runtime_usage_record is not None
            }
        )
        != 4
    ):
        raise ValueError("scheduler recursive promotion repeats a live request identity")
    return inventory


def _rebuild_recovered_candidate_review_content(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    indexes: _SchedulerTruncationRecoveryIndexes,
    scheduler: _SchedulerJournalIndexes,
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...],
) -> _RecoveredCandidateReviewContent:
    """Replay raw parent/child records into exact host-stamped review content."""

    parent_task_id = family.recovery_plan.parent.parent_task_id
    parent_attempt = scheduler.provider_attempts.get(parent_task_id)
    if (
        parent_attempt is None
        or parent_attempt.schema_version != "1.1"
        or parent_attempt.truncation_projection != family.truncation_projection
    ):
        raise ValueError("scheduler recovery promotion lacks a typed parent attempt")

    expected_surface_records = list(family.truncation_projection.surface_reviews)
    raw_candidates: dict[tuple[str, str], tuple[CandidateFinding, dict[str, Any]]] = {}
    usage_by_request: dict[str, UsageRecord] = {}
    parent_usage = parent_attempt.usage_record
    usage_by_request[parent_usage.request_id] = parent_usage
    for finding in family.truncation_projection.findings:
        finding_sha256 = scheduler_canonical_sha256(finding.model_dump(mode="json"))
        frames = tuple(
            frame
            for frame in family.truncation_projection.accepted_frames
            if frame.phase is CandidateReviewFramePhase.FINDING
            and frame.record_id == finding.candidate_id
            and frame.normalized_value_sha256 == finding_sha256
        )
        if len(frames) != 1:
            raise ValueError("scheduler recovery parent finding lacks one accepted frame")
        frame = frames[0]
        raw_candidates[(parent_usage.request_id, finding.candidate_id)] = (
            finding,
            {
                "origin_kind": SchedulerRecoveredCandidateOriginKind.PARENT_FRAME,
                "usage_record_sha256": parent_attempt.usage_record_sha256,
                "context_request_evidence_sha256": (parent_attempt.context_request_evidence_sha256),
                "parent_projection_sha256": family.truncation_projection.evidence_sha256,
                "accepted_frame_sequence": frame.sequence,
                "accepted_frame_sha256": frame.frame_sha256,
            },
        )

    child_results: list[SchedulerTruncationRecoveryChildResult] = []
    for child in family.recovery_plan.children:
        result = indexes.results.get(child.child_task_id)
        if (
            not isinstance(result, SchedulerTruncationRecoveryChildResult)
            or result.schema_version not in {"1.1", "1.2"}
            or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            or result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
            or result.runtime_usage_record is None
            or result.runtime_normalization_evidence is None
            or result.runtime_normalized_batch is None
            or result.runtime_output_artifact is None
        ):
            raise ValueError("scheduler recovery promotion has a non-creditable direct child")
        child_results.append(result)
        if result.runtime_usage_record.request_id in usage_by_request:
            raise ValueError("scheduler recovery promotion reused a request identity")
        usage_by_request[result.runtime_usage_record.request_id] = result.runtime_usage_record
        expected_surface_records.extend(result.runtime_output_artifact.records)
        context_sha256 = result.runtime_usage_record.routing.get("context_request_evidence_sha256")
        if not isinstance(context_sha256, str):
            raise ValueError("scheduler recovery child lacks context-request custody")
        for finding in result.runtime_normalized_batch.findings:
            key = (result.runtime_usage_record.request_id, finding.candidate_id)
            if key in raw_candidates:
                raise ValueError("scheduler recovery raw candidate origin is duplicated")
            raw_candidates[key] = (
                finding,
                {
                    "origin_kind": SchedulerRecoveredCandidateOriginKind.CHILD_BATCH,
                    "usage_record_sha256": result.runtime_usage_record_sha256,
                    "context_request_evidence_sha256": context_sha256,
                    "child_task_id": child.child_task_id,
                    "child_result_sha256": result.entry_sha256,
                    "normalization_evidence_sha256": (
                        result.runtime_normalization_evidence.evidence_sha256
                    ),
                    "surface_artifact_sha256": result.runtime_output_artifact.artifact_sha256,
                },
            )

    scanner_projection = dict(scanner_fingerprints_by_request)
    if len(scanner_projection) != len(scanner_fingerprints_by_request) or set(
        scanner_projection
    ) != set(usage_by_request):
        raise ValueError("scheduler recovery promotion lacks exact request scanner custody")
    raw_by_request: dict[str, list[tuple[CandidateFinding, dict[str, Any]]]] = {
        request_id: [] for request_id in usage_by_request
    }
    for (request_id, _raw_candidate_id), raw in raw_candidates.items():
        raw_by_request[request_id].append(raw)

    expected_findings: list[CandidateFinding] = []
    expected_origins: list[SchedulerRecoveredCandidateOrigin] = []
    for request_id in sorted(usage_by_request):
        usage = usage_by_request[request_id]
        entries = tuple(sorted(raw_by_request[request_id], key=lambda item: item[0].candidate_id))
        raw_findings = tuple(item[0] for item in entries)
        try:
            stamped = stamp_candidate_review_findings(
                request_role=usage.role,
                usage_record=usage,
                trusted_scanner_fingerprints=scanner_projection[request_id],
                raw_findings=raw_findings,
            )
        except CandidateReviewStampingError as exc:
            raise ValueError("scheduler recovery candidate stamping failed exact replay") from exc
        for (raw_finding, expected), accepted in zip(entries, stamped, strict=True):
            origin_kind = cast(SchedulerRecoveredCandidateOriginKind, expected["origin_kind"])
            common: dict[str, Any] = {
                "origin_kind": origin_kind,
                "accepted_candidate_id": accepted.candidate_id,
                "accepted_candidate_sha256": scheduler_canonical_sha256(
                    accepted.model_dump(mode="json")
                ),
                "raw_candidate_id": raw_finding.candidate_id,
                "raw_candidate_sha256": scheduler_canonical_sha256(
                    raw_finding.model_dump(mode="json")
                ),
                "request_id": request_id,
                "request_role": usage.role,
                "usage_record_sha256": cast(str, expected["usage_record_sha256"]),
                "context_request_evidence_sha256": cast(
                    str, expected["context_request_evidence_sha256"]
                ),
            }
            if origin_kind is SchedulerRecoveredCandidateOriginKind.PARENT_FRAME:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    parent_projection_sha256=cast(str, expected["parent_projection_sha256"]),
                    accepted_frame_sequence=cast(int, expected["accepted_frame_sequence"]),
                    accepted_frame_sha256=cast(str, expected["accepted_frame_sha256"]),
                )
            else:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    child_task_id=cast(str, expected["child_task_id"]),
                    child_result_sha256=cast(str, expected["child_result_sha256"]),
                    normalization_evidence_sha256=cast(
                        str, expected["normalization_evidence_sha256"]
                    ),
                    surface_artifact_sha256=cast(str, expected["surface_artifact_sha256"]),
                )
            expected_findings.append(accepted)
            expected_origins.append(origin)

    return _RecoveredCandidateReviewContent(
        findings=tuple(sorted(expected_findings, key=lambda item: item.candidate_id)),
        surface_reviews=tuple(sorted(expected_surface_records, key=lambda item: item.surface_id)),
        origins=tuple(sorted(expected_origins, key=lambda item: item.accepted_candidate_id)),
        child_results=tuple(child_results),
    )


def _rebuild_recursive_recovered_candidate_review_content(
    *,
    family: SchedulerTruncationRecoveryFamilyRoot,
    closure: SchedulerTruncationRecoveryFamilyClosure,
    indexes: _SchedulerTruncationRecoveryIndexes,
    scheduler: _SchedulerJournalIndexes,
    scanner_fingerprints_by_request: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[_RecoveredCandidateReviewContent, _RecursiveRecoveryTreeInventory]:
    """Replay all five request sources in the supported one-level recovery tree."""

    tree = _recursive_recovery_tree_inventory(
        family=family,
        closure=closure,
        indexes=indexes,
    )
    parent_task_id = family.recovery_plan.parent.parent_task_id
    parent_attempt = scheduler.provider_attempts.get(parent_task_id)
    if (
        parent_attempt is None
        or parent_attempt.schema_version != "1.1"
        or parent_attempt.truncation_projection != family.truncation_projection
    ):
        raise ValueError("scheduler recursive promotion lacks a typed root parent attempt")

    expected_surface_records = list(family.truncation_projection.surface_reviews)
    raw_candidates: dict[tuple[str, str], tuple[CandidateFinding, dict[str, Any]]] = {}
    usage_by_request: dict[str, UsageRecord] = {}
    parent_usage = parent_attempt.usage_record
    usage_by_request[parent_usage.request_id] = parent_usage
    for finding in family.truncation_projection.findings:
        finding_sha256 = scheduler_canonical_sha256(finding.model_dump(mode="json"))
        frames = tuple(
            frame
            for frame in family.truncation_projection.accepted_frames
            if frame.phase is CandidateReviewFramePhase.FINDING
            and frame.record_id == finding.candidate_id
            and frame.normalized_value_sha256 == finding_sha256
        )
        if len(frames) != 1:
            raise ValueError("scheduler recursive root finding lacks one accepted frame")
        frame = frames[0]
        raw_candidates[(parent_usage.request_id, finding.candidate_id)] = (
            finding,
            {
                "origin_kind": SchedulerRecoveredCandidateOriginKind.PARENT_FRAME,
                "usage_record_sha256": parent_attempt.usage_record_sha256,
                "context_request_evidence_sha256": (parent_attempt.context_request_evidence_sha256),
                "parent_projection_sha256": family.truncation_projection.evidence_sha256,
                "accepted_frame_sequence": frame.sequence,
                "accepted_frame_sha256": frame.frame_sha256,
            },
        )

    bridge = tree.bridge_result
    bridge_usage = bridge.runtime_usage_record
    bridge_projection = bridge.truncation_projection
    if bridge_usage is None or bridge_projection is None:
        raise ValueError("scheduler recursive promotion bridge lacks typed runtime custody")
    bridge_context_sha256 = bridge_usage.routing.get("context_request_evidence_sha256")
    if not isinstance(bridge_context_sha256, str):
        raise ValueError("scheduler recursive promotion bridge lacks context-request custody")
    usage_by_request[bridge_usage.request_id] = bridge_usage
    for finding in bridge_projection.findings:
        finding_sha256 = scheduler_canonical_sha256(finding.model_dump(mode="json"))
        frames = tuple(
            frame
            for frame in bridge_projection.accepted_frames
            if frame.phase is CandidateReviewFramePhase.FINDING
            and frame.record_id == finding.candidate_id
            and frame.normalized_value_sha256 == finding_sha256
        )
        if len(frames) != 1:
            raise ValueError("scheduler recursive bridge finding lacks one accepted frame")
        frame = frames[0]
        key = (bridge_usage.request_id, finding.candidate_id)
        if key in raw_candidates:
            raise ValueError("scheduler recursive raw bridge candidate is duplicated")
        raw_candidates[key] = (
            finding,
            {
                "origin_kind": SchedulerRecoveredCandidateOriginKind.TRUNCATED_CHILD_FRAME,
                "usage_record_sha256": bridge.runtime_usage_record_sha256,
                "context_request_evidence_sha256": bridge_context_sha256,
                "child_task_id": bridge.child_task_id,
                "child_result_sha256": bridge.entry_sha256,
                "truncation_projection_sha256": bridge_projection.evidence_sha256,
                "accepted_frame_sequence": frame.sequence,
                "accepted_frame_sha256": frame.frame_sha256,
            },
        )

    for result in tree.promoted_leaf_results:
        usage = result.runtime_usage_record
        normalized_batch = result.runtime_normalized_batch
        output_artifact = result.runtime_output_artifact
        normalization = result.runtime_normalization_evidence
        child_match = indexes.children.get(result.child_task_id)
        if (
            usage is None
            or normalized_batch is None
            or output_artifact is None
            or normalization is None
            or child_match is None
        ):
            raise ValueError("scheduler recursive promotion leaf lacks typed runtime custody")
        child, _family_id = child_match
        if usage.request_id in usage_by_request:
            raise ValueError("scheduler recursive promotion reused a request identity")
        usage_by_request[usage.request_id] = usage
        expected_surface_records.extend(output_artifact.records)
        context_sha256 = usage.routing.get("context_request_evidence_sha256")
        if not isinstance(context_sha256, str):
            raise ValueError("scheduler recursive promotion leaf lacks context-request custody")
        for finding in normalized_batch.findings:
            key = (usage.request_id, finding.candidate_id)
            if key in raw_candidates:
                raise ValueError("scheduler recursive raw leaf candidate is duplicated")
            raw_candidates[key] = (
                finding,
                {
                    "origin_kind": SchedulerRecoveredCandidateOriginKind.CHILD_BATCH,
                    "usage_record_sha256": result.runtime_usage_record_sha256,
                    "context_request_evidence_sha256": context_sha256,
                    "child_task_id": child.child_task_id,
                    "child_result_sha256": result.entry_sha256,
                    "normalization_evidence_sha256": normalization.evidence_sha256,
                    "surface_artifact_sha256": output_artifact.artifact_sha256,
                },
            )

    scanner_projection = dict(scanner_fingerprints_by_request)
    if (
        len(usage_by_request) != 5
        or len(scanner_projection) != len(scanner_fingerprints_by_request)
        or set(scanner_projection) != set(usage_by_request)
    ):
        raise ValueError("scheduler recursive promotion lacks exact five-request scanner custody")
    raw_by_request: dict[str, list[tuple[CandidateFinding, dict[str, Any]]]] = {
        request_id: [] for request_id in usage_by_request
    }
    for (request_id, _raw_candidate_id), raw in raw_candidates.items():
        raw_by_request[request_id].append(raw)

    expected_findings: list[CandidateFinding] = []
    expected_origins: list[SchedulerRecoveredCandidateOrigin] = []
    for request_id in sorted(usage_by_request):
        usage = usage_by_request[request_id]
        entries = tuple(sorted(raw_by_request[request_id], key=lambda item: item[0].candidate_id))
        raw_findings = tuple(item[0] for item in entries)
        try:
            stamped = stamp_candidate_review_findings(
                request_role=usage.role,
                usage_record=usage,
                trusted_scanner_fingerprints=scanner_projection[request_id],
                raw_findings=raw_findings,
            )
        except CandidateReviewStampingError as exc:
            raise ValueError("scheduler recursive candidate stamping failed exact replay") from exc
        for (raw_finding, expected), accepted in zip(entries, stamped, strict=True):
            origin_kind = cast(SchedulerRecoveredCandidateOriginKind, expected["origin_kind"])
            common: dict[str, Any] = {
                "origin_kind": origin_kind,
                "accepted_candidate_id": accepted.candidate_id,
                "accepted_candidate_sha256": scheduler_canonical_sha256(
                    accepted.model_dump(mode="json")
                ),
                "raw_candidate_id": raw_finding.candidate_id,
                "raw_candidate_sha256": scheduler_canonical_sha256(
                    raw_finding.model_dump(mode="json")
                ),
                "request_id": request_id,
                "request_role": usage.role,
                "usage_record_sha256": cast(str, expected["usage_record_sha256"]),
                "context_request_evidence_sha256": cast(
                    str,
                    expected["context_request_evidence_sha256"],
                ),
            }
            if origin_kind is SchedulerRecoveredCandidateOriginKind.PARENT_FRAME:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    parent_projection_sha256=cast(str, expected["parent_projection_sha256"]),
                    accepted_frame_sequence=cast(int, expected["accepted_frame_sequence"]),
                    accepted_frame_sha256=cast(str, expected["accepted_frame_sha256"]),
                )
            elif origin_kind is SchedulerRecoveredCandidateOriginKind.TRUNCATED_CHILD_FRAME:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    child_task_id=cast(str, expected["child_task_id"]),
                    child_result_sha256=cast(str, expected["child_result_sha256"]),
                    truncation_projection_sha256=cast(
                        str,
                        expected["truncation_projection_sha256"],
                    ),
                    accepted_frame_sequence=cast(int, expected["accepted_frame_sequence"]),
                    accepted_frame_sha256=cast(str, expected["accepted_frame_sha256"]),
                )
            else:
                origin = SchedulerRecoveredCandidateOrigin.build(
                    **common,
                    child_task_id=cast(str, expected["child_task_id"]),
                    child_result_sha256=cast(str, expected["child_result_sha256"]),
                    normalization_evidence_sha256=cast(
                        str,
                        expected["normalization_evidence_sha256"],
                    ),
                    surface_artifact_sha256=cast(str, expected["surface_artifact_sha256"]),
                )
            expected_findings.append(accepted)
            expected_origins.append(origin)

    return (
        _RecoveredCandidateReviewContent(
            findings=tuple(sorted(expected_findings, key=lambda item: item.candidate_id)),
            surface_reviews=tuple(
                sorted(expected_surface_records, key=lambda item: item.surface_id)
            ),
            origins=tuple(sorted(expected_origins, key=lambda item: item.accepted_candidate_id)),
            child_results=tree.tree_results,
        ),
        tree,
    )


def _validate_durable_recovery_promotion(
    *,
    promotion: SchedulerTruncationRecoveryFamilyPromotion,
    family: SchedulerTruncationRecoveryFamilyRoot,
    closure: SchedulerTruncationRecoveryFamilyClosure,
    indexes: _SchedulerTruncationRecoveryIndexes,
    scheduler: _SchedulerJournalIndexes,
) -> None:
    """Join one already-authorized promotion back to every durable raw input."""

    parent_task_id = family.recovery_plan.parent.parent_task_id
    parent_attempt = scheduler.provider_attempts.get(parent_task_id)
    parent_activation = scheduler.activations.get(parent_task_id)
    task_and_plan = scheduler.tasks.get(parent_task_id)
    parent_result = scheduler.credited_results.get(parent_task_id)
    if (
        family.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
        or family.parent_family_id is not None
        or parent_attempt is None
        or parent_attempt.schema_version != "1.1"
        or parent_attempt.truncation_projection != family.truncation_projection
        or parent_attempt.truncated_envelope_evidence is None
        or parent_activation is None
        or task_and_plan is None
        or parent_result is None
        or parent_result.terminal_status is not SchedulerTerminalStatus.TRUNCATED
        or family.truncation_projection.findings_state is not CandidateReviewChannelState.COMPLETE
        or promotion.family_id != family.family_id
        or promotion.family_index != family.family_index
        or promotion.family_root_sha256 != family.entry_sha256
        or promotion.recovery_plan_sha256 != family.recovery_plan.plan_sha256
        or promotion.family_closure_id != closure.closure_id
        or promotion.family_closure_sha256 != closure.entry_sha256
        or promotion.previous_entry_sha256 != closure.entry_sha256
        or promotion.parent_task_id != parent_task_id
        or promotion.original_truncated_result_sha256 != parent_result.result_sha256
    ):
        raise ValueError("scheduler recovery promotion lacks exact typed parent closure")

    recursive = promotion.schema_version == "1.1"
    tree: _RecursiveRecoveryTreeInventory | None = None
    if recursive:
        tree = _recursive_recovery_tree_inventory(
            family=family,
            closure=closure,
            indexes=indexes,
        )
        if (
            promotion.direct_child_result_sha256s != tree.direct_child_result_sha256s
            or promotion.nested_family_id != tree.nested_family.family_id
            or promotion.nested_family_root_sha256 != tree.nested_family.entry_sha256
            or promotion.nested_recovery_plan_sha256 != tree.nested_family.recovery_plan.plan_sha256
            or promotion.nested_family_closure_id != tree.nested_closure.closure_id
            or promotion.nested_family_closure_sha256 != tree.nested_closure.entry_sha256
            or promotion.nested_child_result_sha256s != tree.nested_child_result_sha256s
            or promotion.superseded_bridge_result_sha256 != tree.bridge_result.entry_sha256
            or promotion.promoted_leaf_result_sha256s != tree.promoted_leaf_result_sha256s
        ):
            raise ValueError("scheduler recursive promotion differs from its exact tree")
    elif (
        closure.schema_version != "1.1"
        or closure.closure_status is not SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        or closure.nested_family_closure_sha256s
        or promotion.direct_child_result_sha256s != closure.child_result_sha256s
    ):
        raise ValueError("scheduler direct promotion differs from its exact closure")

    task, pass_plan = task_and_plan
    output = promotion.recovered_output
    if (
        pass_plan.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
        or task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
        or task.response_schema_sha256 != family.truncation_projection.wire_schema_sha256
        or output.campaign_id != family.campaign_id
        or output.pass_plan_id != pass_plan.pass_plan_id
        or output.parent_task_id != task.task_id
        or output.parent_logical_request_id != task.logical_request_id
        or output.parent_activation_sha256 != parent_activation.activation_sha256
        or output.parent_provider_attempt_sha256 != parent_attempt.attempt_evidence_sha256
        or output.delivered_source_descriptor_sha256s
        != parent_activation.delivered_source_descriptor_sha256s
        or output.schema_version != promotion.schema_version
    ):
        raise ValueError("scheduler recovery promotion output differs from its parent task")

    if recursive:
        content, rebuilt_tree = _rebuild_recursive_recovered_candidate_review_content(
            family=family,
            closure=closure,
            indexes=indexes,
            scheduler=scheduler,
            scanner_fingerprints_by_request=output.scanner_fingerprints_by_request,
        )
        assert tree is not None
        if rebuilt_tree != tree:
            raise ValueError("scheduler recursive promotion tree changed during replay")
    else:
        content = _rebuild_recovered_candidate_review_content(
            family=family,
            indexes=indexes,
            scheduler=scheduler,
            scanner_fingerprints_by_request=output.scanner_fingerprints_by_request,
        )
        if (
            tuple(item.entry_sha256 for item in content.child_results)
            != closure.child_result_sha256s
        ):
            raise ValueError("scheduler recovery promotion child order differs from its closure")
    if tuple(output.recovered_batch.surface_reviews) != content.surface_reviews:
        raise ValueError("scheduler recovery promotion changed its exact surface partition")
    if (
        tuple(output.recovered_batch.findings) != content.findings
        or output.candidate_origins != content.origins
    ):
        raise ValueError("scheduler recovery promotion changed a host-stamped finding")
    capability_payload: dict[str, Any] = {
        "domain": (
            "mmaudit.scheduler.recursive-truncation-recovery-promotion-capability.v1"
            if recursive
            else "mmaudit.scheduler.truncation-recovery-promotion-capability.v1"
        ),
        "family_id": family.family_id,
        "family_root_sha256": family.entry_sha256,
        "family_closure_id": closure.closure_id,
        "family_closure_sha256": closure.entry_sha256,
        "structural_surface_artifact_sha256": output.structural_surface_artifact_sha256,
        "scanner_fingerprints_by_request": output.scanner_fingerprints_by_request,
        "recovered_output_sha256": output.output_artifact_sha256,
    }
    if recursive:
        assert tree is not None
        capability_payload.update(
            {
                "nested_family_id": tree.nested_family.family_id,
                "nested_family_root_sha256": tree.nested_family.entry_sha256,
                "nested_family_closure_id": tree.nested_closure.closure_id,
                "nested_family_closure_sha256": tree.nested_closure.entry_sha256,
                "direct_child_result_sha256s": tree.direct_child_result_sha256s,
                "nested_child_result_sha256s": tree.nested_child_result_sha256s,
                "superseded_bridge_result_sha256": tree.bridge_result.entry_sha256,
                "promoted_leaf_result_sha256s": tree.promoted_leaf_result_sha256s,
            }
        )
    expected_capability_binding_sha256 = scheduler_canonical_sha256(capability_payload)
    if promotion.capability_binding_sha256 != expected_capability_binding_sha256:
        raise ValueError("scheduler recovery promotion capability binding is inconsistent")


def _derive_truncation_recovery_indexes(
    *,
    entries: Iterable[SchedulerTruncationRecoveryEntry],
    scheduler: _SchedulerJournalIndexes,
    manifest: SchedulerCampaignManifest,
) -> _SchedulerTruncationRecoveryIndexes:
    """Rebuild every lifecycle join and the journal-wide recovery request chain."""

    frozen = validate_truncation_recovery_entry_chain(entries)
    indexes = _SchedulerTruncationRecoveryIndexes(
        families={},
        family_order=[],
        children={},
        activations={},
        dispatches={},
        results={},
        closures={},
        promotions={},
        family_by_parent_task={},
        nested_family_by_parent_child={},
        promotion_by_parent_task={},
        recovery_requests_consumed=0,
        request_limit_attempts_reserved={},
    )
    for entry in frozen:
        if entry.campaign_id != manifest.campaign_id or entry.request_limit_binding_sha256 == "":
            raise ValueError("scheduler recovery entry differs from campaign custody")
        if isinstance(entry, SchedulerTruncationRecoveryFamilyRoot):
            parent_task_id = entry.recovery_plan.parent.parent_task_id
            request_limit_attempts_before = indexes.request_limit_attempts_reserved.get(
                entry.request_limit_id,
                0,
            )
            if (
                entry.family_id in indexes.families
                or parent_task_id in indexes.family_by_parent_task
                or entry.family_index != len(indexes.family_order)
                or entry.request_limit_binding.manifest_sha256 != manifest.manifest_sha256
                or entry.request_count_before_family != indexes.recovery_requests_consumed
                or entry.request_count_after_family
                != indexes.recovery_requests_consumed + len(entry.recovery_plan.children)
                or entry.request_count_after_family > TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
                or entry.request_limit_count_before_family
                != entry.request_limit_binding.parent_request_limit_count_after
                + request_limit_attempts_before
                or entry.request_limit_count_after_family
                != entry.request_limit_count_before_family
                + entry.request_limit_attempts_reserved_for_family
                or entry.request_limit_count_after_family
                > entry.request_limit_binding.request_limit_maximum
            ):
                raise ValueError("scheduler recovery family resets or exceeds its global limit")
            if entry.parent_kind is SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK:
                _validate_root_scheduler_parent(
                    family=entry,
                    scheduler=scheduler,
                    indexes=indexes,
                )
            else:
                _validate_nested_recovery_parent(
                    family=entry,
                    indexes=indexes,
                    scheduler=scheduler,
                )
                assert entry.parent_family_id is not None
                indexes.nested_family_by_parent_child[parent_task_id] = entry.family_id
            indexes.families[entry.family_id] = entry
            indexes.family_by_parent_task[parent_task_id] = entry.family_id
            indexes.family_order.append(entry.family_id)
            for child in entry.recovery_plan.children:
                if child.child_task_id in indexes.children:
                    raise ValueError("scheduler recovery child identity is duplicated")
                indexes.children[child.child_task_id] = (child, entry.family_id)
            indexes.recovery_requests_consumed = entry.request_count_after_family
            indexes.request_limit_attempts_reserved[entry.request_limit_id] = (
                request_limit_attempts_before + entry.request_limit_attempts_reserved_for_family
            )
            continue

        if isinstance(entry, SchedulerTruncationRecoveryFamilyClosure):
            family = indexes.families.get(entry.family_id)
            if (
                family is None
                or entry.family_id in indexes.closures
                or entry.family_index != family.family_index
                or entry.family_root_sha256 != family.entry_sha256
                or entry.recovery_plan_sha256 != family.recovery_plan.plan_sha256
            ):
                raise ValueError("scheduler recovery closure is duplicated or misbound")
            expected = _expected_recovery_family_closure(family=family, indexes=indexes)
            observed = (
                entry.closure_status,
                entry.child_result_sha256s,
                entry.nested_family_closure_sha256s,
                entry.covered_unfinished_surface_ids,
            )
            if observed != expected:
                raise ValueError("scheduler recovery closure differs from exact child evidence")
            indexes.closures[entry.family_id] = entry
            continue

        if isinstance(entry, SchedulerTruncationRecoveryFamilyPromotion):
            family = indexes.families.get(entry.family_id)
            closure = indexes.closures.get(entry.family_id)
            parent_task_id = entry.parent_task_id
            if (
                family is None
                or closure is None
                or entry.family_id in indexes.promotions
                or parent_task_id in indexes.promotion_by_parent_task
            ):
                raise ValueError("scheduler recovery promotion is absent, duplicated, or open")
            _validate_durable_recovery_promotion(
                promotion=entry,
                family=family,
                closure=closure,
                indexes=indexes,
                scheduler=scheduler,
            )
            indexes.promotions[entry.family_id] = entry
            indexes.promotion_by_parent_task[parent_task_id] = entry.family_id
            continue

        child_match = indexes.children.get(entry.child_task_id)
        if child_match is None:
            raise ValueError("scheduler recovery child entry is unplanned")
        child, family_id = child_match
        family = indexes.families[family_id]
        if family_id in indexes.closures or entry.family_id != family_id:
            raise ValueError("scheduler recovery child entry follows family closure")
        if (
            entry.child_task_id != child.child_task_id
            or entry.child_logical_request_id != child.child_logical_request_id
            or entry.child_plan_sha256 != child.child_plan_sha256
            or entry.global_request_ordinal
            != family.request_count_before_family + child.ordinal + 1
            or (
                isinstance(
                    entry,
                    (
                        SchedulerTruncationRecoveryChildActivation,
                        SchedulerTruncationRecoveryChildPreflightResult,
                        SchedulerTruncationRecoveryChildResult,
                    ),
                )
                and entry.child_surface_ids != child.surface_ids
            )
        ):
            raise ValueError("scheduler recovery child entry differs from its frozen plan")
        if isinstance(entry, SchedulerTruncationRecoveryChildActivation):
            if (
                entry.family_index != family.family_index
                or entry.family_root_sha256 != family.entry_sha256
                or entry.child_task_id in indexes.activations
            ):
                raise ValueError("scheduler recovery activation is duplicated or misbound")
            indexes.activations[entry.child_task_id] = entry
        elif isinstance(entry, SchedulerTruncationRecoveryChildDispatch):
            activation = indexes.activations.get(entry.child_task_id)
            if (
                activation is None
                or entry.child_task_id in indexes.dispatches
                or entry.child_task_id in indexes.results
                or entry.activation_id != activation.activation_id
                or entry.activation_sha256 != activation.entry_sha256
            ):
                raise ValueError("scheduler recovery dispatch lacks one exact activation")
            indexes.dispatches[entry.child_task_id] = entry
        elif isinstance(entry, SchedulerTruncationRecoveryChildPreflightResult):
            activation = indexes.activations.get(entry.child_task_id)
            if (
                activation is None
                or entry.child_task_id in indexes.dispatches
                or entry.child_task_id in indexes.results
                or entry.activation_id != activation.activation_id
                or entry.activation_sha256 != activation.entry_sha256
                or entry.reserved_provider_attempts != child.reserved_provider_attempts
                or entry.reserved_completion_tokens != child.reserved_completion_tokens
                or entry.reserved_usd_exact != child.reserved_usd_exact
            ):
                raise ValueError(
                    "scheduler recovery preflight result lacks one exact durable activation"
                )
            indexes.results[entry.child_task_id] = entry
        elif isinstance(entry, SchedulerTruncationRecoveryChildResult):
            dispatch = indexes.dispatches.get(entry.child_task_id)
            activation = indexes.activations.get(entry.child_task_id)
            released_v13 = entry.schema_version == "1.3"
            if (
                activation is None
                or entry.child_task_id in indexes.results
                or entry.activation_id != activation.activation_id
                or entry.activation_sha256 != activation.entry_sha256
                or entry.reserved_provider_attempts != child.reserved_provider_attempts
                or entry.reserved_completion_tokens != child.reserved_completion_tokens
                or entry.reserved_usd_exact != child.reserved_usd_exact
                or (
                    not released_v13
                    and (
                        dispatch is None
                        or entry.dispatch_id != dispatch.dispatch_id
                        or entry.dispatch_sha256 != dispatch.entry_sha256
                    )
                )
                or (
                    released_v13
                    and (
                        (
                            dispatch is None
                            and (entry.dispatch_id is not None or entry.dispatch_sha256 is not None)
                        )
                        or (
                            dispatch is not None
                            and (
                                entry.dispatch_id != dispatch.dispatch_id
                                or entry.dispatch_sha256 != dispatch.entry_sha256
                            )
                        )
                    )
                )
            ):
                raise ValueError("scheduler recovery result lacks one exact durable lifecycle")
            assert activation is not None
            if entry.schema_version in {"1.1", "1.2"}:
                _typed_recovery_usage_coordinate(
                    result=entry,
                    child=child,
                    activation=activation,
                    family=family,
                )
            indexes.results[entry.child_task_id] = entry
    return indexes


def _derive_scheduler_journal_indexes(
    *,
    plans: Iterable[SchedulerPassPlan],
    activations: Iterable[SchedulerTaskActivation],
    outputs: Iterable[SchedulerTaskOutput],
    provider_attempts: Iterable[SchedulerProviderAttemptEvidence],
    result_observations: Iterable[SchedulerTaskResult],
    events: Iterable[SchedulerTaskEvent],
) -> _SchedulerJournalIndexes:
    """Derive exact joins without replacing full durable-state validation."""

    tasks: dict[str, tuple[SchedulerTaskPlan, SchedulerPassPlan]] = {}
    for plan in plans:
        for task in plan.tasks:
            if task.task_id in tasks:
                raise ValueError("scheduler task identity is duplicated across pass plans")
            tasks[task.task_id] = (task, plan)

    activations_by_task: dict[str, SchedulerTaskActivation] = {}
    for activation in activations:
        if activation.task_id in activations_by_task or activation.task_id not in tasks:
            raise ValueError("scheduler activation is duplicated or unplanned")
        activations_by_task[activation.task_id] = activation

    outputs_by_task: dict[str, SchedulerTaskOutput] = {}
    for output in outputs:
        if output.task_id in outputs_by_task or output.task_id not in tasks:
            raise ValueError("scheduler output is duplicated or unplanned")
        outputs_by_task[output.task_id] = output

    provider_attempts_by_task: dict[str, SchedulerProviderAttemptEvidence] = {}
    for attempt in provider_attempts:
        if (
            attempt.task_id in provider_attempts_by_task
            or attempt.task_id in outputs_by_task
            or attempt.task_id not in tasks
        ):
            raise ValueError("scheduler provider attempt is duplicated, credited, or unplanned")
        provider_attempts_by_task[attempt.task_id] = attempt

    results_by_hash: dict[str, SchedulerTaskResult] = {}
    observations_by_task: dict[str, list[SchedulerTaskResult]] = {}
    for result in result_observations:
        if result.result_sha256 in results_by_hash or result.task_id not in tasks:
            raise ValueError("scheduler task result is duplicated or unplanned")
        results_by_hash[result.result_sha256] = result
        observations_by_task.setdefault(result.task_id, []).append(result)

    histories: dict[str, list[SchedulerTaskEvent]] = {}
    credited_results: dict[str, SchedulerTaskResult] = {}
    event_ids: set[str] = set()
    for event in events:
        if event.event_id in event_ids or event.task_id not in tasks:
            raise ValueError("scheduler event identity is duplicated or unplanned")
        histories.setdefault(event.task_id, []).append(event)
        if event.kind in _TERMINAL_EVENT_KINDS:
            assert event.task_result_sha256 is not None
            terminal_result = results_by_hash.get(event.task_result_sha256)
            if (
                terminal_result is None
                or terminal_result.task_id != event.task_id
                or event.task_id in credited_results
            ):
                raise ValueError("scheduler terminal event has ambiguous result evidence")
            credited_results[event.task_id] = terminal_result
        event_ids.add(event.event_id)

    return _SchedulerJournalIndexes(
        tasks=tasks,
        activations=activations_by_task,
        outputs=outputs_by_task,
        provider_attempts=provider_attempts_by_task,
        results_by_hash=results_by_hash,
        result_observations_by_task=observations_by_task,
        event_histories=histories,
        credited_results=credited_results,
        event_ids=event_ids,
    )


def _pass_result_binds_plan(
    pass_result: SchedulerPassResult,
    plan: SchedulerPassPlan,
) -> bool:
    """Compare immutable pass authority without a repeated deep model traversal."""

    embedded = pass_result.plan
    return (
        embedded.pass_plan_id == plan.pass_plan_id
        and embedded.pass_plan_sha256 == plan.pass_plan_sha256
        and embedded.pass_kind is plan.pass_kind
        and embedded.manifest.manifest_sha256 == plan.manifest.manifest_sha256
    )


def _campaign_logical_request_id(
    provider_attempt_id: str,
    tasks_by_request: dict[str, SchedulerTaskPlan],
) -> str | None:
    identity = _campaign_provider_attempt_identity(provider_attempt_id, tasks_by_request)
    return identity[0] if identity is not None else None


def _campaign_provider_attempt_identity(
    provider_attempt_id: str,
    tasks_by_request: dict[str, SchedulerTaskPlan],
) -> tuple[str, int] | None:
    """Resolve one canonical provider-attempt ID to its task and one-based ordinal."""

    if provider_attempt_id in tasks_by_request:
        return provider_attempt_id, 1
    marker = ":attempt:"
    logical_request_id, separator, raw_attempt = provider_attempt_id.rpartition(marker)
    if (
        not separator
        or logical_request_id not in tasks_by_request
        or not raw_attempt.isdigit()
        or int(raw_attempt) < 2
        or str(int(raw_attempt)) != raw_attempt
    ):
        return None
    return logical_request_id, int(raw_attempt)


def _require_exact_pre_send_release(entry: CostEntry) -> None:
    """Require a closed zero-cost entry that proves transport was not entered."""

    if (
        entry.status is not CostEntryStatus.RELEASED
        or entry.release_reason
        not in {
            ReleaseReason.CANCELLED_BEFORE_SEND,
            ReleaseReason.FAILED_BEFORE_SEND,
        }
        or entry.actual_cost_usd is not None
        or entry.accounted_cost_usd != 0
    ):
        raise ValueError("provider attempt release lacks exact pre-send custody")


def _require_exact_failed_pre_send_usage(
    record: UsageRecord,
    *,
    require_runtime_attestation: bool,
) -> None:
    """Require response-free, noncrediting custody for a released final attempt."""

    accountable = (
        is_accountable_usage_record(record)
        if require_runtime_attestation
        else is_structurally_accountable_usage_record(record)
    )
    if (
        not accountable
        or is_structurally_creditable_usage_record(record)
        or record.validation_status is ModelRequestValidationStatus.VALID
        or record.status == "success"
        or not record.provider_error_classification
        or record.actual_model is not None
        or record.returned_model is not None
        or record.provider is not None
        or record.openrouter_generation_id is not None
        or record.actual_provider_endpoint is not None
        or record.finish_reason is not None
        or record.response_sha256 is not None
        or record.validated_response_sha256 is not None
        or record.reported_cost_usd_exact is not None
        or record.prompt_tokens != 0
        or record.completion_tokens != 0
        or record.total_tokens != 0
        or record.cached_tokens != 0
        or record.reasoning_tokens not in {None, 0}
        or record.reasoning_evidence is not None
        or record.token_detail_accounting_evidence is not None
    ):
        raise ValueError("released provider usage lacks exact pre-send failure custody")


def _require_exact_activation_released_usage(
    record: UsageRecord,
    *,
    logical_request_id: str,
    require_runtime_attestation: bool,
) -> None:
    """Require the sole zero-cost attempt possible before durable dispatch."""

    _require_exact_failed_pre_send_usage(
        record,
        require_runtime_attestation=require_runtime_attestation,
    )
    try:
        token_attempts = atomic_token_reservations_from_usage(record)
        request_attempts = atomic_request_limit_reservations_from_usage(record)
    except (TypeError, ValueError):
        raise ValueError("activated release lacks exact atomic attempt custody") from None
    if (
        record.request_id != logical_request_id
        or record.attempts != 1
        or record.retry_count != 0
        or record.accounted_cost_usd_exact != "0"
        or tuple(item.request_id for item in token_attempts) != (logical_request_id,)
        or tuple(item.request_id for item in request_attempts) != (logical_request_id,)
    ):
        raise ValueError("activated release differs from its sole zero-cost attempt")


def _campaign_entries_for_task(
    *,
    task: SchedulerTaskPlan,
    tasks_by_request: dict[str, SchedulerTaskPlan],
    ledger_entries: tuple[CostEntry, ...],
) -> tuple[tuple[int, CostEntry], ...]:
    """Return every canonical ledger attempt owned by one current campaign task."""

    matches: list[tuple[int, CostEntry]] = []
    for entry in ledger_entries:
        identity = _campaign_provider_attempt_identity(entry.request_id, tasks_by_request)
        if identity is not None and identity[0] == task.logical_request_id:
            matches.append((identity[1], entry))
    return tuple(sorted(matches, key=lambda item: item[0]))


def _recovery_child_attempt_identity(
    provider_attempt_id: str,
    recovery_children_by_request: dict[
        str,
        tuple[TruncationRecoveryChildPlan, str],
    ],
) -> tuple[str, int] | None:
    """Resolve one canonical recovery-child provider attempt and ordinal."""

    if provider_attempt_id in recovery_children_by_request:
        return provider_attempt_id, 1
    logical_request_id, separator, raw_attempt = provider_attempt_id.rpartition(":attempt:")
    if (
        not separator
        or logical_request_id not in recovery_children_by_request
        or not raw_attempt.isdigit()
        or int(raw_attempt) < 2
        or str(int(raw_attempt)) != raw_attempt
    ):
        return None
    return logical_request_id, int(raw_attempt)


def _recovery_child_entries(
    *,
    child: TruncationRecoveryChildPlan,
    recovery_children_by_request: dict[
        str,
        tuple[TruncationRecoveryChildPlan, str],
    ],
    ledger_entries: tuple[CostEntry, ...],
) -> tuple[tuple[int, CostEntry], ...]:
    """Return all canonical ledger attempts owned by one recovery child."""

    matches: list[tuple[int, CostEntry]] = []
    for entry in ledger_entries:
        identity = _recovery_child_attempt_identity(
            entry.request_id,
            recovery_children_by_request,
        )
        if identity is not None and identity[0] == child.child_logical_request_id:
            matches.append((identity[1], entry))
    return tuple(sorted(matches, key=lambda item: item[0]))


def _released_pre_send_tail_for_recovery_child(
    *,
    child: TruncationRecoveryChildPlan,
    recovery_children_by_request: dict[
        str,
        tuple[TruncationRecoveryChildPlan, str],
    ],
    ledger_entries: tuple[CostEntry, ...],
) -> tuple[tuple[int, CostEntry], ...]:
    """Return one exact child uncertain-prefix/released-tail ledger group."""

    entries = _recovery_child_entries(
        child=child,
        recovery_children_by_request=recovery_children_by_request,
        ledger_entries=ledger_entries,
    )
    released_positions = tuple(
        index
        for index, (_ordinal, entry) in enumerate(entries)
        if entry.status is CostEntryStatus.RELEASED
    )
    if not released_positions:
        return ()
    ordinals = tuple(ordinal for ordinal, _entry in entries)
    if (
        ordinals != tuple(range(1, len(entries) + 1))
        or len(entries) > child.reserved_provider_attempts
    ):
        raise ValueError("released recovery-child attempt inventory is not contiguous")
    if released_positions != (len(entries) - 1,):
        raise ValueError("recovery child has a nonfinal or repeated pre-send release")
    if any(
        entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
        or entry.actual_cost_usd is not None
        or entry.accounted_cost_usd != entry.reserved_usd
        for _ordinal, entry in entries[:-1]
    ):
        raise ValueError("released recovery child lacks an exact uncertain retry prefix")
    _require_exact_pre_send_release(entries[-1][1])
    return entries


def _released_pre_send_tail_for_task(
    *,
    task: SchedulerTaskPlan,
    tasks_by_request: dict[str, SchedulerTaskPlan],
    ledger_entries: tuple[CostEntry, ...],
) -> tuple[tuple[int, CostEntry], ...]:
    """Return one exact uncertain-prefix/released-tail group, or no release group."""

    entries = _campaign_entries_for_task(
        task=task,
        tasks_by_request=tasks_by_request,
        ledger_entries=ledger_entries,
    )
    released_positions = tuple(
        index
        for index, (_ordinal, entry) in enumerate(entries)
        if entry.status is CostEntryStatus.RELEASED
    )
    if not released_positions:
        return ()
    ordinals = tuple(ordinal for ordinal, _entry in entries)
    if ordinals != tuple(range(1, len(entries) + 1)):
        raise ValueError("released provider-attempt ordinals are not contiguous")
    if released_positions != (len(entries) - 1,):
        raise ValueError("provider attempt has a nonfinal or repeated pre-send release")
    if any(
        entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
        or entry.actual_cost_usd is not None
        or entry.accounted_cost_usd != entry.reserved_usd
        for _ordinal, entry in entries[:-1]
    ):
        raise ValueError("released provider attempt lacks an exact uncertain retry prefix")
    _require_exact_pre_send_release(entries[-1][1])
    return entries


def _recovery_child_cost_recovery_plan(
    *,
    indexes: _SchedulerTruncationRecoveryIndexes,
    ledger_entries: tuple[CostEntry, ...],
) -> tuple[_RecoveryChildCostGroup, ...]:
    """Validate every active child ledger group without mutating the ledger."""

    children_by_request = {
        child.child_logical_request_id: (child, family_id)
        for child, family_id in indexes.children.values()
    }
    groups: list[_RecoveryChildCostGroup] = []
    for child_task_id, (child, family_id) in sorted(indexes.children.items()):
        result = indexes.results.get(child_task_id)
        entries = _recovery_child_entries(
            child=child,
            recovery_children_by_request=children_by_request,
            ledger_entries=ledger_entries,
        )
        active_statuses = {
            CostEntryStatus.RESERVED,
            CostEntryStatus.RELEASED,
            CostEntryStatus.UNCERTAIN_ACCOUNTED,
        }
        if not entries or not (
            any(entry.status in active_statuses for _ordinal, entry in entries)
            or (
                isinstance(result, SchedulerTruncationRecoveryChildResult)
                and result.schema_version == "1.3"
            )
        ):
            continue
        family = indexes.families.get(family_id)
        activation = indexes.activations.get(child_task_id)
        dispatch = indexes.dispatches.get(child_task_id)
        ordinals = tuple(ordinal for ordinal, _entry in entries)
        expected_ids = tuple(
            child.child_logical_request_id
            if ordinal == 1
            else f"{child.child_logical_request_id}:attempt:{ordinal}"
            for ordinal in ordinals
        )
        if (
            family is None
            or activation is None
            or activation.request_role is None
            or activation.requested_model is None
            or ordinals != tuple(range(1, len(entries) + 1))
            or len(entries) > child.reserved_provider_attempts
            or tuple(entry.request_id for _ordinal, entry in entries) != expected_ids
            or any(
                entry.reserved_usd <= 0 or entry.reserved_usd > Decimal(child.reserved_usd_exact)
                for _ordinal, entry in entries
            )
        ):
            raise ValueError("active recovery-child cost lacks exact scheduler custody")

        if isinstance(result, SchedulerTruncationRecoveryChildResult) and (
            result.schema_version == "1.3"
        ):
            release_positions = tuple(
                index
                for index, (_ordinal, entry) in enumerate(entries)
                if entry.status is CostEntryStatus.RELEASED
            )
            if release_positions != (len(entries) - 1,):
                raise ValueError("released recovery-child ledger tail is absent or nonfinal")
            released = entries[-1][1]
            _require_exact_pre_send_release(released)
            if (
                result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.FAILED
                or result.cost_disposition
                is not SchedulerTruncationRecoveryCostDisposition.RELEASED_PRE_SEND_TAIL
                or result.accounted_provider_attempts != len(entries)
                or result.released_cost_entry_sha256 != cost_entry_sha256(released)
                or result.terminal_evidence_sha256 != cost_entry_sha256(released)
                or result.pre_send_release_reason
                != cast(ReleaseReason, released.release_reason).value
                or result.runtime_activation != activation
                or ((dispatch is None) != (result.dispatch_id is None))
                or (
                    dispatch is not None
                    and (
                        result.dispatch_id != dispatch.dispatch_id
                        or result.dispatch_sha256 != dispatch.entry_sha256
                    )
                )
            ):
                raise ValueError("released recovery-child result differs from its ledger tail")
            usage = result.runtime_usage_record
            if any(
                entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
                or entry.actual_cost_usd is not None
                or entry.accounted_cost_usd != entry.reserved_usd
                for _ordinal, entry in entries[:-1]
            ):
                raise ValueError("released recovery child lacks an exact uncertain retry prefix")
            if usage is None:
                retained_usage = False
            else:
                try:
                    token_inventory = atomic_token_reservations_from_usage(usage)
                    request_inventory = recovery_atomic_request_limit_reservations_from_usage(
                        usage,
                        request_limit_scope=family.request_limit_id,
                        request_limit_count_before=(activation.request_limit_count_before_child),
                    )
                except (TypeError, ValueError):
                    raise ValueError("released recovery-child usage inventory is invalid") from None
                attempt_ids = tuple(item.request_id for item in token_inventory)
                if (
                    result.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
                    or attempt_ids != tuple(item.request_id for item in request_inventory)
                    or attempt_ids != tuple(entry.request_id for _ordinal, entry in entries)
                ):
                    raise ValueError(
                        "released recovery-child usage differs from its complete ledger inventory"
                    )
                retained_usage = True
            prefix_total = _canonical_recovery_usd_sum(
                tuple(format(entry.accounted_cost_usd, "f") for _ordinal, entry in entries[:-1])
            )
            if result.accounted_cost_usd_exact != prefix_total:
                raise ValueError("released recovery-child prefix cost differs from its ledger")
            groups.append(
                _RecoveryChildCostGroup(
                    child=child,
                    family=family,
                    activation=activation,
                    entries=entries,
                    status=SchedulerCostRecoveryStatus.RELEASED_PROVEN_PRE_SEND,
                    retained_usage=retained_usage,
                )
            )
            continue

        if dispatch is None:
            if (
                result is not None
                or len(entries) != 1
                or entries[0][1].status is not CostEntryStatus.RESERVED
                or entries[0][1].accounted_cost_usd != 0
            ):
                raise ValueError("pre-send recovery-child cost differs from its activation")
            groups.append(
                _RecoveryChildCostGroup(
                    child=child,
                    family=family,
                    activation=activation,
                    entries=entries,
                    status=SchedulerCostRecoveryStatus.ADOPTED_PROVEN_PRE_SEND,
                )
            )
            continue
        if (
            not isinstance(result, SchedulerTruncationRecoveryChildResult)
            or result.schema_version != "1.0"
            or result.result_origin is not SchedulerTruncationRecoveryResultOrigin.CRASH_RECOVERY
            or result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN
            or result.accounted_provider_attempts != len(entries)
            or any(
                entry.status
                not in {
                    CostEntryStatus.RESERVED,
                    CostEntryStatus.UNCERTAIN_ACCOUNTED,
                }
                for _ordinal, entry in entries
            )
        ):
            raise ValueError("dispatched recovery-child cost lacks exact crash terminal evidence")
        groups.append(
            _RecoveryChildCostGroup(
                child=child,
                family=family,
                activation=activation,
                entries=entries,
                status=SchedulerCostRecoveryStatus.UNCERTAIN_ACCOUNTED_AFTER_DISPATCH,
            )
        )
    return tuple(groups)


def _recovery_child_usage_bridge_transitions(
    *,
    indexes: _SchedulerTruncationRecoveryIndexes,
    ledger_entries: tuple[CostEntry, ...],
) -> tuple[tuple[str, str, int, int, int], ...]:
    """Project exact no-usage child attempts into the shared request-limit chain."""

    transitions: list[tuple[str, str, int, int, int]] = []
    for group in _recovery_child_cost_recovery_plan(
        indexes=indexes,
        ledger_entries=ledger_entries,
    ):
        if (
            group.retained_usage
            or group.status is SchedulerCostRecoveryStatus.ADOPTED_PROVEN_PRE_SEND
        ):
            continue
        for attempt_ordinal, entry in group.entries:
            count_before = group.activation.request_limit_count_before_child + attempt_ordinal - 1
            transitions.append(
                (
                    entry.request_id,
                    group.family.request_limit_id,
                    count_before,
                    count_before + 1,
                    group.activation.request_limit_maximum,
                )
            )
    return tuple(sorted(transitions, key=lambda item: (item[1], item[2], item[0])))


def _retained_main_usage_cost_recovery_plan(
    *,
    records: tuple[UsageRecord, ...],
    tasks_by_request: dict[str, SchedulerTaskPlan],
    ledger_entries: tuple[CostEntry, ...],
) -> tuple[frozenset[str], tuple[tuple[CostEntry, Decimal | None], ...]]:
    """Bind retained usage to its ledger attempts before interrupted-cost recovery.

    A retained output or provider-attempt record proves that its transport accounting
    completed far enough to serialize the exact atomic attempt inventory.  Such entries
    must be restored through usage recovery, not reclassified as evidence-less crash
    reservations.  A still-RESERVED entry is the narrow crash window between retaining
    the usage and reconciling its cost; this plan validates the complete post-reconcile
    cost algebra before authorizing any mutation.
    """

    entries_by_id = {entry.request_id: entry for entry in ledger_entries}
    if len(entries_by_id) != len(ledger_entries):
        raise ValueError("persistent model-cost ledger repeats a request identity")

    retained_attempt_ids: set[str] = set()
    pending_reconciliations: list[tuple[CostEntry, Decimal | None]] = []
    for record in sorted(records, key=lambda item: item.request_id):
        if record.request_id not in tasks_by_request:
            raise ValueError("retained scheduler usage lacks exact task custody")
        try:
            attempts = atomic_token_reservations_from_usage(record)
            request_attempts = atomic_request_limit_reservations_from_usage(record)
            accounted_cost = Decimal(record.accounted_cost_usd_exact or "")
            reported_cost = (
                Decimal(record.reported_cost_usd_exact)
                if record.reported_cost_usd_exact is not None
                else None
            )
        except (InvalidOperation, TypeError, ValueError):
            raise ValueError("retained scheduler usage attempts are invalid") from None
        attempt_ids = tuple(item.request_id for item in attempts)
        request_attempt_ids = tuple(item.request_id for item in request_attempts)
        if (
            len(attempt_ids) != record.attempts
            or request_attempt_ids != attempt_ids
            or any(
                _campaign_provider_attempt_identity(request_id, tasks_by_request)
                != (record.request_id, ordinal)
                for ordinal, request_id in enumerate(attempt_ids, start=1)
            )
            or retained_attempt_ids.intersection(attempt_ids)
        ):
            raise ValueError("retained scheduler usage repeats or mismatches a provider attempt")
        task_ledger_attempt_ids = tuple(
            entry.request_id
            for _ordinal, entry in _campaign_entries_for_task(
                task=tasks_by_request[record.request_id],
                tasks_by_request=tasks_by_request,
                ledger_entries=ledger_entries,
            )
        )
        if not set(attempt_ids).issubset(task_ledger_attempt_ids):
            raise ValueError("persistent model-cost ledger omits a retained provider attempt")
        if task_ledger_attempt_ids != attempt_ids:
            raise ValueError(
                "retained scheduler usage differs from its complete ledger attempt inventory"
            )
        retained_attempt_ids.update(attempt_ids)

        exact_entries = tuple(entries_by_id.get(request_id) for request_id in attempt_ids)
        if any(entry is None for entry in exact_entries):
            raise ValueError("persistent model-cost ledger omits a retained provider attempt")
        typed_entries = tuple(entry for entry in exact_entries if entry is not None)
        released_positions = tuple(
            index
            for index, entry in enumerate(typed_entries)
            if entry.status is CostEntryStatus.RELEASED
        )
        if released_positions and (
            released_positions != (len(typed_entries) - 1,)
            or any(
                entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
                or entry.actual_cost_usd is not None
                or entry.accounted_cost_usd != entry.reserved_usd
                for entry in typed_entries[:-1]
            )
        ):
            raise ValueError("released provider attempt lacks an exact uncertain retry prefix")
        post_reconcile_costs: list[Decimal] = []
        final_actual_cost: Decimal | None = None
        for ordinal, entry in enumerate(typed_entries, start=1):
            is_final = ordinal == len(typed_entries)
            if entry.status is CostEntryStatus.RESERVED:
                actual_cost = reported_cost if is_final and reported_cost is not None else None
                if actual_cost is not None and actual_cost > entry.reserved_usd:
                    raise ValueError(
                        "retained provider attempt reported cost exceeds its reservation"
                    )
                post_reconcile_cost = entry.reserved_usd if actual_cost is None else actual_cost
                pending_reconciliations.append((entry, actual_cost))
            elif entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED:
                if (
                    entry.actual_cost_usd is not None
                    or entry.accounted_cost_usd != entry.reserved_usd
                ):
                    raise ValueError(
                        "retained provider attempt uncertainty differs from its reservation"
                    )
                actual_cost = None
                post_reconcile_cost = entry.accounted_cost_usd
            elif entry.status is CostEntryStatus.RECONCILED:
                if (
                    entry.actual_cost_usd is None
                    or entry.accounted_cost_usd != entry.actual_cost_usd
                ):
                    raise ValueError("retained provider attempt reconciliation is inconsistent")
                actual_cost = entry.actual_cost_usd
                post_reconcile_cost = entry.accounted_cost_usd
            elif entry.status is CostEntryStatus.RELEASED:
                if not is_final:
                    raise ValueError("retained provider attempt has a nonfinal pre-send release")
                _require_exact_pre_send_release(entry)
                _require_exact_failed_pre_send_usage(
                    record,
                    require_runtime_attestation=False,
                )
                actual_cost = None
                post_reconcile_cost = Decimal(0)
            else:
                raise ValueError("retained provider attempt has an invalid ledger state")
            post_reconcile_costs.append(post_reconcile_cost)
            if is_final:
                final_actual_cost = actual_cost

        if (reported_cost is None and final_actual_cost is not None) or (
            reported_cost is not None and final_actual_cost != reported_cost
        ):
            raise ValueError("retained provider attempt reported cost differs from its ledger")
        recovered_total = Decimal(
            _canonical_recovery_usd_sum(tuple(format(cost, "f") for cost in post_reconcile_costs))
        )
        if recovered_total != accounted_cost:
            raise ValueError("retained provider attempt accounting differs from its ledger")

    return frozenset(retained_attempt_ids), tuple(pending_reconciliations)


def _bindings_without_cost_baseline(bindings: SchedulerBindings) -> dict[str, object]:
    return bindings.model_dump(
        mode="json",
        exclude={"bindings_sha256", "cost_ledger_baseline_sha256"},
    )


def _require_model_task_privacy_custody(
    manifest: SchedulerCampaignManifest,
    task: SchedulerTaskPlan,
) -> None:
    if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
        return
    custody = manifest.privacy_evidence_custody
    if (
        custody is None
        or manifest.bindings.privacy_evidence_custody_sha256 != custody.custody_sha256
    ):
        raise ValueError("scheduler model task lacks exact pre-dispatch privacy custody")


def _analysis_input_inventory_drift_labels(
    expected: SchedulerAnalysisInputInventory,
    observed: SchedulerAnalysisInputInventory,
) -> tuple[str, ...]:
    expected_by_label = {item.label: item for item in expected.descriptors}
    observed_by_label = {item.label: item for item in observed.descriptors}
    return tuple(
        label
        for label in sorted(set(expected_by_label) | set(observed_by_label))
        if expected_by_label.get(label) != observed_by_label.get(label)
    )


def _validate_cost_ledger_baseline_prefix(
    baseline: SchedulerCostLedgerBaseline,
    atomic_ledger: AtomicCostLedger,
) -> None:
    snapshot = atomic_ledger.snapshot()
    if atomic_ledger.identity_sha256 != baseline.ledger_identity_sha256:
        raise ValueError("current cost ledger identity differs from scheduler baseline")
    if snapshot.cap_usd != Decimal(baseline.cap_usd_exact):
        raise ValueError("current cost ledger cap differs from scheduler baseline")
    current = {entry.request_id: entry for entry in snapshot.entries}
    for expected in baseline.entries:
        observed = current.get(expected.request_id)
        if observed is None or cost_entry_sha256(observed) != expected.ledger_entry_sha256:
            raise ValueError("current cost ledger differs from scheduler baseline prefix")
    if snapshot.spent_usd < Decimal(baseline.spent_usd_exact):
        raise ValueError("current cost ledger spend precedes scheduler baseline")


class SchedulerJournal:
    """Exclusive live custody over one exact append-only scheduler campaign."""

    def __init__(
        self,
        *,
        path: Path,
        root_descriptor: int,
        root_identity: tuple[int, int, int],
        directory_descriptors: dict[str, int],
        directory_identities: dict[str, tuple[int, int, int]],
        lock_descriptor: int,
        manifest: SchedulerCampaignManifest,
        analysis_input_inventory: SchedulerAnalysisInputInventory,
        plans: tuple[SchedulerPassPlan, ...],
        activations: tuple[SchedulerTaskActivation, ...],
        events: tuple[SchedulerTaskEvent, ...],
        outputs: tuple[SchedulerTaskOutput, ...],
        provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...],
        result_observations: tuple[SchedulerTaskResult, ...],
        pass_results: tuple[SchedulerPassResult, ...],
        truncation_recovery_entries: tuple[SchedulerTruncationRecoveryEntry, ...] = (),
        terminal_report_authority: SchedulerTerminalReportAuthority | None = None,
        journal_head_checkpoint: SchedulerJournalEvidence | None = None,
        read_only: bool = False,
        pending_checkpoint_recovery: bool = False,
        allowed_immutable_write_temps: frozenset[str] = frozenset(),
        allowed_published_immutable_targets: dict[
            str,
            _EvidenceFileIdentity,
        ]
        | None = None,
    ) -> None:
        self.path = path
        self._root_descriptor = root_descriptor
        self._root_identity = root_identity
        self._directory_descriptors = directory_descriptors
        self._directory_identities = directory_identities
        self._lock_descriptor = lock_descriptor
        self._closed = False
        self._read_only = read_only
        self._pending_checkpoint_recovery = pending_checkpoint_recovery
        self._allowed_immutable_write_temps = allowed_immutable_write_temps
        self._allowed_published_immutable_targets = dict(allowed_published_immutable_targets or {})
        self._usage_recovery_scope: _TrustedUsageRecoveryScope | None = None
        self._usage_recovery_expires_at: datetime | None = None
        self.manifest = manifest
        self.analysis_input_inventory = analysis_input_inventory
        self._plans = list(plans)
        self._activations = list(activations)
        self._events = list(events)
        self._outputs = [_detach_canonical_model(item) for item in outputs]
        self._provider_attempts = [_detach_canonical_model(item) for item in provider_attempts]
        self._result_observations = list(result_observations)
        self._pass_results = [_detach_canonical_model(item) for item in pass_results]
        self._truncation_recovery_entries = [
            _detach_canonical_model(item) for item in truncation_recovery_entries
        ]
        self._terminal_report_authority = (
            _detach_canonical_model(terminal_report_authority)
            if terminal_report_authority is not None
            else None
        )
        self._journal_head_checkpoint = journal_head_checkpoint
        self._journal_head_checkpoint_bytes = (
            stable_json(journal_head_checkpoint).encode("utf-8")
            if journal_head_checkpoint is not None
            else None
        )
        self._durable_artifact_observations: (
            dict[
                str,
                tuple[_EvidenceFileIdentity, str],
            ]
            | None
        ) = None
        self._indexes = _derive_scheduler_journal_indexes(
            plans=self._plans,
            activations=self._activations,
            outputs=self._outputs,
            provider_attempts=self._provider_attempts,
            result_observations=self._result_observations,
            events=self._events,
        )
        self._truncation_recovery_indexes = _derive_truncation_recovery_indexes(
            entries=self._truncation_recovery_entries,
            scheduler=self._indexes,
            manifest=self.manifest,
        )

    def __enter__(self) -> SchedulerJournal:
        self._assert_live_custody()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    @property
    def plans(self) -> tuple[SchedulerPassPlan, ...]:
        return tuple(self._plans)

    @property
    def events(self) -> tuple[SchedulerTaskEvent, ...]:
        return tuple(self._events)

    @property
    def activations(self) -> tuple[SchedulerTaskActivation, ...]:
        return tuple(sorted(self._activations, key=lambda item: item.task_id))

    @property
    def outputs(self) -> tuple[SchedulerTaskOutput, ...]:
        return tuple(_detach_canonical_model(item) for item in self._retained_outputs())

    @property
    def provider_attempts(self) -> tuple[SchedulerProviderAttemptEvidence, ...]:
        return tuple(_detach_canonical_model(item) for item in self._retained_provider_attempts())

    @property
    def task_results(self) -> tuple[SchedulerTaskResult, ...]:
        """Return only results selected by a durable TERMINAL event."""

        return tuple(sorted(self._credited_results().values(), key=lambda item: item.task_id))

    @property
    def result_observations(self) -> tuple[SchedulerTaskResult, ...]:
        """Return all retained results, including uncredited interrupted output."""

        return tuple(
            sorted(
                self._result_observations,
                key=lambda item: (item.task_id, item.result_sha256),
            )
        )

    @property
    def pass_results(self) -> tuple[SchedulerPassResult, ...]:
        return tuple(_detach_canonical_model(item) for item in self._retained_pass_results())

    @property
    def truncation_recovery_entries(self) -> tuple[SchedulerTruncationRecoveryEntry, ...]:
        """Return the exact private recovery chain in append order."""

        return tuple(
            _detach_canonical_model(item) for item in self._retained_truncation_recovery_entries()
        )

    def _retained_outputs(self) -> tuple[SchedulerTaskOutput, ...]:
        """Return process-private outputs for trusted internal projection only."""

        return tuple(sorted(self._outputs, key=lambda item: item.task_id))

    def _retained_provider_attempts(self) -> tuple[SchedulerProviderAttemptEvidence, ...]:
        """Return process-private attempts for trusted internal projection only."""

        return tuple(sorted(self._provider_attempts, key=lambda item: item.task_id))

    def _retained_truncation_recovery_entries(
        self,
    ) -> tuple[SchedulerTruncationRecoveryEntry, ...]:
        """Return the process-private recovery chain for internal projection only."""

        return tuple(self._truncation_recovery_entries)

    def _retained_pass_results(self) -> tuple[SchedulerPassResult, ...]:
        """Return process-private pass results for trusted internal projection only."""

        return tuple(self._pass_results)

    @property
    def truncation_recovery_families(self) -> tuple[SchedulerTruncationRecoveryFamilyRoot, ...]:
        """Return frozen recovery roots without adding them to pass task inventory."""

        return tuple(
            _detach_canonical_model(self._truncation_recovery_indexes.families[family_id])
            for family_id in self._truncation_recovery_indexes.family_order
        )

    def recovered_candidate_review_output_for_task(
        self,
        task_id: str,
    ) -> SchedulerRecoveredCandidateReviewOutput | None:
        """Return one private promoted review without exposing it in public scheduler state."""

        self._assert_live_custody()
        family_id = self._truncation_recovery_indexes.promotion_by_parent_task.get(task_id)
        if family_id is None:
            return None
        promotion = self._truncation_recovery_indexes.promotions.get(family_id)
        if promotion is None or promotion.parent_task_id != task_id:
            raise ValueError("scheduler recovery promotion index is inconsistent")
        return SchedulerRecoveredCandidateReviewOutput.model_validate_json(
            promotion.recovered_output.model_dump_json(),
            strict=True,
        )

    @property
    def activatable_truncation_recovery_child_ids(self) -> tuple[str, ...]:
        """Return planned recovery children that have never been activated."""

        self._assert_live_custody()
        return tuple(
            sorted(
                child_task_id
                for child_task_id, (_child, family_id) in (
                    self._truncation_recovery_indexes.children.items()
                )
                if child_task_id not in self._truncation_recovery_indexes.activations
                and family_id not in self._truncation_recovery_indexes.closures
            )
        )

    @property
    def dispatchable_truncation_recovery_child_ids(self) -> tuple[str, ...]:
        """Return activated children with no durable dispatch marker."""

        self._assert_live_custody()
        return tuple(
            sorted(
                child_task_id
                for child_task_id in self._truncation_recovery_indexes.activations
                if child_task_id not in self._truncation_recovery_indexes.dispatches
                and child_task_id not in self._truncation_recovery_indexes.results
                and self._truncation_recovery_indexes.children[child_task_id][1]
                not in self._truncation_recovery_indexes.closures
            )
        )

    @property
    def uncertain_truncation_recovery_child_ids(self) -> tuple[str, ...]:
        """Return crash-recovered children that are permanently non-retryable."""

        self._assert_live_custody()
        return tuple(
            sorted(
                child_task_id
                for child_task_id, result in self._truncation_recovery_indexes.results.items()
                if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN
            )
        )

    def open_truncation_recovery_family(
        self,
        *,
        recovery_plan: TruncationRecoveryPlan,
        truncation_projection: CandidateReviewTruncationProjection,
        requested_surface_manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest,
    ) -> SchedulerTruncationRecoveryFamilyRoot:
        """Persist one typed root after its truncated parent is already durable."""

        self._assert_writable_custody()
        plan = TruncationRecoveryPlan.model_validate(
            recovery_plan.model_dump(mode="python"),
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
        parent_task_id = plan.parent.parent_task_id
        if parent_task_id in self._truncation_recovery_indexes.family_by_parent_task:
            raise ValueError("scheduler truncated parent already has a recovery family")
        if plan.parent.current_depth == 0:
            parent_task_and_plan = self._indexes.tasks.get(parent_task_id)
            if parent_task_and_plan is None:
                raise ValueError("scheduler recovery root lacks a planned parent task")
            parent_task, parent_pass_plan = parent_task_and_plan
            if (
                parent_pass_plan.pass_kind is not SchedulerPassKind.BLIND_SHARD_REVIEW
                or parent_task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
                or parent_task.response_schema_sha256 != projection.wire_schema_sha256
            ):
                raise ValueError(
                    "scheduler recovery root requires one framed blind-review model task"
                )
            parent_pass_ordinals = tuple(
                index
                for index, sealed_plan in enumerate(self._plans)
                if sealed_plan.pass_plan_id == parent_pass_plan.pass_plan_id
            )
            if len(parent_pass_ordinals) != 1:
                raise ValueError("scheduler recovery root parent pass is not uniquely sealed")
            if parent_pass_ordinals[0] < len(self._pass_results):
                raise ValueError("scheduler cannot open recovery after its parent pass is sealed")
            scheduler_parent_result = self._indexes.credited_results.get(parent_task_id)
            scheduler_parent_attempt = self._indexes.provider_attempts.get(parent_task_id)
            if scheduler_parent_result is None or scheduler_parent_attempt is None:
                raise ValueError("scheduler recovery root lacks a durable parent result")
            try:
                parent_request_limit_reservations = atomic_request_limit_reservations_from_usage(
                    scheduler_parent_attempt.usage_record
                )
            except ValueError:
                raise ValueError(
                    "scheduler recovery root lacks exact parent request-limit evidence"
                ) from None
            if not parent_request_limit_reservations:
                raise ValueError(
                    "scheduler recovery root lacks exact parent request-limit evidence"
                )
            binding = SchedulerTruncationRecoveryRequestLimitBinding.build(
                campaign_id=self.manifest.campaign_id,
                manifest_sha256=self.manifest.manifest_sha256,
                request_limit_id=plan.parent.parent_logical_request_id,
                policy=plan.policy,
                parent_request_limit_reservation=parent_request_limit_reservations[-1],
            )
            parent_kind = SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
            parent_family_id = None
            parent_terminal_result_sha256 = scheduler_parent_result.result_sha256
        else:
            child_match = self._truncation_recovery_indexes.children.get(parent_task_id)
            nested_parent_result = self._truncation_recovery_indexes.results.get(parent_task_id)
            if child_match is None or not isinstance(
                nested_parent_result,
                SchedulerTruncationRecoveryChildResult,
            ):
                raise ValueError("nested scheduler recovery lacks its typed parent child")
            _parent_child, parent_family_id = child_match
            parent_family = self._truncation_recovery_indexes.families[parent_family_id]
            binding = parent_family.request_limit_binding
            parent_kind = SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD
            parent_terminal_result_sha256 = nested_parent_result.entry_sha256
        request_limit_attempts_before = (
            self._truncation_recovery_indexes.request_limit_attempts_reserved.get(
                binding.request_limit_id,
                0,
            )
        )
        family_reserved_attempts = sum(child.reserved_provider_attempts for child in plan.children)
        if (
            binding.parent_request_limit_count_after
            + request_limit_attempts_before
            + family_reserved_attempts
            > binding.request_limit_maximum
        ):
            raise ValueError("scheduler recovery plan exceeds its parent request limit")
        entry = SchedulerTruncationRecoveryFamilyRoot.build(
            request_limit_binding=binding,
            family_index=len(self._truncation_recovery_indexes.family_order),
            parent_kind=parent_kind,
            parent_family_id=parent_family_id,
            parent_terminal_result_sha256=parent_terminal_result_sha256,
            requested_surface_manifest=surface_manifest,
            truncation_projection=projection,
            recovery_plan=plan,
            request_count_before_family=(
                self._truncation_recovery_indexes.recovery_requests_consumed
            ),
            request_limit_count_before_family=(
                binding.parent_request_limit_count_after + request_limit_attempts_before
            ),
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def activate_truncation_recovery_child(
        self,
        child_task_id: str,
        *,
        actual_input_sha256: str,
        system_prompt_sha256: str,
        user_prompt_sha256: str,
        provider_prompt_sha256: str,
        response_schema_sha256: str,
    ) -> SchedulerTruncationRecoveryChildActivation:
        """Persist exact child request bytes before it can receive a dispatch marker."""

        self._assert_writable_custody()
        child_match = self._truncation_recovery_indexes.children.get(child_task_id)
        if child_match is None:
            raise ValueError("scheduler recovery child is not planned")
        child, family_id = child_match
        if child_task_id in self._truncation_recovery_indexes.activations:
            raise ValueError("scheduler recovery child is already activated")
        if family_id in self._truncation_recovery_indexes.closures:
            raise ValueError("scheduler recovery family is already closed")
        family = self._truncation_recovery_indexes.families[family_id]
        entry = SchedulerTruncationRecoveryChildActivation.build(
            family=family,
            child=child,
            actual_input_sha256=actual_input_sha256,
            system_prompt_sha256=system_prompt_sha256,
            user_prompt_sha256=user_prompt_sha256,
            provider_prompt_sha256=provider_prompt_sha256,
            response_schema_sha256=response_schema_sha256,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def mark_truncation_recovery_child_dispatched(
        self,
        child_task_id: str,
    ) -> SchedulerTruncationRecoveryChildDispatch:
        """Durably mark dispatch; this method performs no provider transport."""

        self._assert_writable_custody()
        activation = self._truncation_recovery_indexes.activations.get(child_task_id)
        if (
            activation is None
            or child_task_id in self._truncation_recovery_indexes.dispatches
            or child_task_id in self._truncation_recovery_indexes.results
        ):
            raise ValueError("only one activated recovery child may be marked dispatched")
        child_match = self._truncation_recovery_indexes.children[child_task_id]
        if child_match[1] in self._truncation_recovery_indexes.closures:
            raise ValueError("scheduler recovery family is already closed")
        entry = SchedulerTruncationRecoveryChildDispatch.build(
            activation=activation,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def record_truncation_recovery_child_preflight_result(
        self,
        child_task_id: str,
        *,
        terminal_status: SchedulerTruncationRecoveryTerminalStatus,
        terminal_evidence_sha256: str,
    ) -> SchedulerTruncationRecoveryChildPreflightResult:
        """Persist an activation-bound local failure with zero provider consumption."""

        self._assert_writable_custody()
        child_match = self._truncation_recovery_indexes.children.get(child_task_id)
        activation = self._truncation_recovery_indexes.activations.get(child_task_id)
        if (
            child_match is None
            or activation is None
            or child_task_id in self._truncation_recovery_indexes.dispatches
            or child_task_id in self._truncation_recovery_indexes.results
        ):
            raise ValueError("scheduler recovery preflight terminal lacks one live activation")
        child, family_id = child_match
        if family_id in self._truncation_recovery_indexes.closures:
            raise ValueError("scheduler recovery family is already closed")
        entry = SchedulerTruncationRecoveryChildPreflightResult.build(
            child=child,
            activation=activation,
            terminal_status=terminal_status,
            terminal_evidence_sha256=terminal_evidence_sha256,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def record_truncation_recovery_child_released_failure(
        self,
        child_task_id: str,
        *,
        failed_usage_record: UsageRecord,
        atomic_ledger: AtomicCostLedger,
    ) -> SchedulerTruncationRecoveryChildResult:
        """Persist one live failed UsageRecord bound to an exact pre-send release."""

        self._assert_writable_custody()
        baseline = self.manifest.cost_ledger_baseline
        child_match = self._truncation_recovery_indexes.children.get(child_task_id)
        activation = self._truncation_recovery_indexes.activations.get(child_task_id)
        dispatch = self._truncation_recovery_indexes.dispatches.get(child_task_id)
        if (
            baseline is None
            or atomic_ledger.identity_sha256 != baseline.ledger_identity_sha256
            or child_match is None
            or activation is None
            or child_task_id in self._truncation_recovery_indexes.results
            or child_match[1] in self._truncation_recovery_indexes.closures
        ):
            raise ValueError("released recovery child lacks exact live ledger custody")
        _validate_cost_ledger_baseline_prefix(baseline, atomic_ledger)
        child, _family_id = child_match
        snapshot = atomic_ledger.snapshot()
        children_by_request = {
            candidate.child_logical_request_id: (candidate, family_id)
            for candidate, family_id in self._truncation_recovery_indexes.children.values()
        }
        released_entries = _released_pre_send_tail_for_recovery_child(
            child=child,
            recovery_children_by_request=children_by_request,
            ledger_entries=snapshot.entries,
        )
        if not released_entries:
            raise ValueError("released recovery child lacks an exact ledger tail")
        released_entry = released_entries[-1][1]
        release_reason = released_entry.release_reason
        assert release_reason is not None
        entry = SchedulerTruncationRecoveryChildResult.build_released_pre_send(
            child=child,
            activation=activation,
            dispatch=dispatch,
            terminal_evidence_sha256=cost_entry_sha256(released_entry),
            release_reason=release_reason.value,
            accounted_prefix_attempts=len(released_entries) - 1,
            accounted_prefix_cost_usd_exact=_canonical_recovery_usd_sum(
                tuple(
                    format(candidate.accounted_cost_usd, "f")
                    for _ordinal, candidate in released_entries[:-1]
                )
            ),
            failed_usage_record=failed_usage_record,
            result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        prospective_indexes = replace(
            self._truncation_recovery_indexes,
            results={**self._truncation_recovery_indexes.results, child_task_id: entry},
        )
        planned = _recovery_child_cost_recovery_plan(
            indexes=prospective_indexes,
            ledger_entries=snapshot.entries,
        )
        matching = tuple(group for group in planned if group.child.child_task_id == child_task_id)
        if len(matching) != 1 or not matching[0].retained_usage:
            raise ValueError("released recovery child lacks exact retained usage custody")
        self._append_truncation_recovery_entry(entry)
        return entry

    def _live_dispatched_truncation_recovery_child(
        self,
        child_task_id: str,
    ) -> tuple[
        TruncationRecoveryChildPlan,
        SchedulerTruncationRecoveryChildActivation,
        SchedulerTruncationRecoveryChildDispatch,
    ]:
        child_match = self._truncation_recovery_indexes.children.get(child_task_id)
        activation = self._truncation_recovery_indexes.activations.get(child_task_id)
        dispatch = self._truncation_recovery_indexes.dispatches.get(child_task_id)
        if (
            child_match is None
            or activation is None
            or dispatch is None
            or child_task_id in self._truncation_recovery_indexes.results
            or child_match[1] in self._truncation_recovery_indexes.closures
        ):
            raise ValueError("typed scheduler recovery result lacks one live dispatched child")
        return child_match[0], activation, dispatch

    def record_truncation_recovery_child_success(
        self,
        child_task_id: str,
        *,
        usage_record: UsageRecord,
        normalization_evidence: CandidateReviewNormalizationEvidence,
        normalized_batch: CandidateReviewBatch,
        requested_surface_requests: Iterable[ModelSurfaceReviewRequest],
        output_artifact: ModelSurfaceReviewArtifact,
        specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
    ) -> SchedulerTruncationRecoveryChildResult:
        """Construct and persist one owned, exact successful child terminal."""

        self._assert_writable_custody()
        child, activation, dispatch = self._live_dispatched_truncation_recovery_child(child_task_id)
        entry = SchedulerTruncationRecoveryChildResult.build_typed_success(
            child=child,
            activation=activation,
            dispatch=dispatch,
            usage_record=usage_record,
            normalization_evidence=normalization_evidence,
            normalized_batch=normalized_batch,
            requested_surface_requests=requested_surface_requests,
            output_artifact=output_artifact,
            specialist_accepted_outcome=specialist_accepted_outcome,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def record_truncation_recovery_child_truncated(
        self,
        child_task_id: str,
        *,
        failed_usage_record: UsageRecord,
        truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence,
        truncation_projection: CandidateReviewTruncationProjection,
    ) -> SchedulerTruncationRecoveryChildResult:
        """Construct and persist one owned, exact v1.1 truncated child terminal."""

        self._assert_writable_custody()
        child, activation, dispatch = self._live_dispatched_truncation_recovery_child(child_task_id)
        entry = SchedulerTruncationRecoveryChildResult.build_typed_truncated(
            child=child,
            activation=activation,
            dispatch=dispatch,
            failed_usage_record=failed_usage_record,
            truncated_envelope_evidence=truncated_envelope_evidence,
            truncation_projection=truncation_projection,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def record_truncation_recovery_child_result(
        self,
        result: SchedulerTruncationRecoveryChildResult,
    ) -> SchedulerTruncationRecoveryChildResult:
        """Persist one detached legacy v1 structural terminal without runtime authority."""

        self._assert_writable_custody()
        if (
            type(result) is not SchedulerTruncationRecoveryChildResult
            or result.schema_version != "1.0"
        ):
            raise ValueError("detached typed recovery results require a live construction API")
        frozen = SchedulerTruncationRecoveryChildResult.model_validate(
            result.model_dump(mode="python"),
            strict=True,
        )
        if (
            frozen.entry_index != len(self._truncation_recovery_entries)
            or frozen.previous_entry_sha256 != self._truncation_recovery_chain_head
        ):
            raise ValueError("scheduler recovery result is detached from the live chain")
        self._append_truncation_recovery_entry(frozen)
        return frozen

    def seal_truncation_recovery_family(
        self,
        family_id: str,
    ) -> SchedulerTruncationRecoveryFamilyClosure:
        """Derive a nonauthorizing recursive closure from exact child terminals."""

        self._assert_writable_custody()
        family = self._truncation_recovery_indexes.families.get(family_id)
        if family is None or family_id in self._truncation_recovery_indexes.closures:
            raise ValueError("scheduler recovery family is absent or already closed")
        status, result_hashes, nested_hashes, covered = _expected_recovery_family_closure(
            family=family,
            indexes=self._truncation_recovery_indexes,
        )
        entry = SchedulerTruncationRecoveryFamilyClosure.build(
            family=family,
            closure_status=status,
            child_result_sha256s=result_hashes,
            nested_family_closure_sha256s=nested_hashes,
            covered_unfinished_surface_ids=covered,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def promote_truncation_recovery_family(
        self,
        family_id: str,
        capability: VerifiedTruncationRecoveryClosure | VerifiedRecursiveTruncationRecoveryTree,
    ) -> SchedulerTruncationRecoveryFamilyPromotion:
        """Append one effective recovery derived solely from a live closure capability."""

        self._assert_writable_custody()
        family = self._truncation_recovery_indexes.families.get(family_id)
        closure = self._truncation_recovery_indexes.closures.get(family_id)
        if (
            family is None
            or closure is None
            or family_id in self._truncation_recovery_indexes.promotions
            or self._truncation_recovery_chain_head != closure.entry_sha256
        ):
            raise ValueError(
                "scheduler recovery promotion requires one unpromoted terminal family closure"
            )
        recursive = (
            closure.schema_version == "1.2"
            and closure.closure_status
            is SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
        )
        if (
            family.parent_kind is not SchedulerTruncationRecoveryParentKind.SCHEDULER_TASK
            or family.parent_family_id is not None
            or (
                not recursive
                and (
                    closure.schema_version != "1.1"
                    or closure.closure_status
                    is not SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                    or closure.nested_family_closure_sha256s
                )
            )
        ):
            raise ValueError("scheduler recovery promotion requires one supported root closure")
        parent_task_id = family.recovery_plan.parent.parent_task_id
        task_and_plan = self._indexes.tasks.get(parent_task_id)
        if task_and_plan is None:
            raise ValueError("scheduler recovery promotion lacks its durable parent task")
        _parent_task, parent_pass_plan = task_and_plan
        parent_pass_ordinals = tuple(
            index
            for index, plan in enumerate(self._plans)
            if plan.pass_plan_id == parent_pass_plan.pass_plan_id
        )
        if len(parent_pass_ordinals) != 1:
            raise ValueError("scheduler recovery promotion parent pass is not uniquely sealed")
        if parent_pass_ordinals[0] < len(self._pass_results):
            raise ValueError("scheduler cannot promote a recovery family after its pass is sealed")
        try:
            if recursive:
                recursive_verified = require_verified_recursive_truncation_recovery_tree_projection(
                    cast(VerifiedRecursiveTruncationRecoveryTree, capability)
                )
                direct_verified = None
            else:
                direct_verified = require_verified_truncation_recovery_closure_projection(
                    cast(VerifiedTruncationRecoveryClosure, capability)
                )
                recursive_verified = None
        except (TruncationRecoveryEvidenceError, TypeError) as exc:
            raise ValueError("scheduler recovery promotion lacks live closure custody") from exc
        verified_family_id = (
            recursive_verified.family_id
            if recursive_verified is not None
            else direct_verified.family_id
            if direct_verified is not None
            else ""
        )
        verified_family_root_sha256 = (
            recursive_verified.family_root_sha256
            if recursive_verified is not None
            else direct_verified.family_root_sha256
            if direct_verified is not None
            else ""
        )
        verified_closure_id = (
            recursive_verified.family_closure_id
            if recursive_verified is not None
            else direct_verified.family_closure_id
            if direct_verified is not None
            else ""
        )
        verified_closure_sha256 = (
            recursive_verified.family_closure_sha256
            if recursive_verified is not None
            else direct_verified.family_closure_sha256
            if direct_verified is not None
            else ""
        )
        verified_artifact = (
            recursive_verified.artifact
            if recursive_verified is not None
            else direct_verified.artifact
            if direct_verified is not None
            else None
        )
        if (
            verified_artifact is None
            or verified_family_id != family.family_id
            or verified_family_root_sha256 != family.entry_sha256
            or verified_closure_id != closure.closure_id
            or verified_closure_sha256 != closure.entry_sha256
            or verified_artifact.recovery_plan != family.recovery_plan
        ):
            raise ValueError("scheduler recovery promotion capability is bound to another family")

        parent_attempt = self._indexes.provider_attempts.get(parent_task_id)
        parent_activation = self._indexes.activations.get(parent_task_id)
        parent_result = self._indexes.credited_results.get(parent_task_id)
        if parent_attempt is None or parent_activation is None or parent_result is None:
            raise ValueError("scheduler recovery promotion lacks its durable parent inventory")
        task, pass_plan = task_and_plan
        if recursive:
            assert recursive_verified is not None
            content, tree = _rebuild_recursive_recovered_candidate_review_content(
                family=family,
                closure=closure,
                indexes=self._truncation_recovery_indexes,
                scheduler=self._indexes,
                scanner_fingerprints_by_request=(
                    recursive_verified.scanner_fingerprints_by_request
                ),
            )
            if (
                recursive_verified.direct_child_result_sha256s != tree.direct_child_result_sha256s
                or recursive_verified.nested_family_id != tree.nested_family.family_id
                or recursive_verified.nested_family_root_sha256 != tree.nested_family.entry_sha256
                or recursive_verified.nested_recovery_plan_sha256
                != tree.nested_family.recovery_plan.plan_sha256
                or recursive_verified.nested_family_closure_id != tree.nested_closure.closure_id
                or recursive_verified.nested_family_closure_sha256
                != tree.nested_closure.entry_sha256
                or recursive_verified.nested_child_result_sha256s
                != tree.nested_child_result_sha256s
                or recursive_verified.superseded_bridge_result_sha256
                != tree.bridge_result.entry_sha256
                or recursive_verified.promoted_leaf_result_sha256s
                != tree.promoted_leaf_result_sha256s
                or recursive_verified.artifact.nested_recovery_plan
                != tree.nested_family.recovery_plan
            ):
                raise ValueError("scheduler recursive promotion capability changed its tree")
            scanner_fingerprints = recursive_verified.scanner_fingerprints_by_request
        else:
            assert direct_verified is not None
            content = _rebuild_recovered_candidate_review_content(
                family=family,
                indexes=self._truncation_recovery_indexes,
                scheduler=self._indexes,
                scanner_fingerprints_by_request=(direct_verified.scanner_fingerprints_by_request),
            )
            tree = None
            scanner_fingerprints = direct_verified.scanner_fingerprints_by_request
        recovered_batch = CandidateReviewBatch(
            findings=content.findings,
            surface_reviews=content.surface_reviews,
        )
        output = SchedulerRecoveredCandidateReviewOutput.build(
            campaign_id=family.campaign_id,
            pass_plan_id=pass_plan.pass_plan_id,
            parent_task_id=task.task_id,
            parent_logical_request_id=task.logical_request_id,
            parent_activation_sha256=parent_activation.activation_sha256,
            original_truncated_result_sha256=parent_result.result_sha256,
            parent_provider_attempt_sha256=parent_attempt.attempt_evidence_sha256,
            recovery_family_id=family.family_id,
            family_root_sha256=family.entry_sha256,
            family_closure_sha256=closure.entry_sha256,
            structural_surface_artifact_sha256=verified_artifact.artifact_sha256,
            recovered_batch=recovered_batch,
            candidate_origins=content.origins,
            scanner_fingerprints_by_request=scanner_fingerprints,
            delivered_source_descriptor_sha256s=(
                parent_activation.delivered_source_descriptor_sha256s
            ),
            recursive_tree=recursive,
        )
        capability_payload: dict[str, Any] = {
            "domain": (
                "mmaudit.scheduler.recursive-truncation-recovery-promotion-capability.v1"
                if recursive
                else "mmaudit.scheduler.truncation-recovery-promotion-capability.v1"
            ),
            "family_id": verified_family_id,
            "family_root_sha256": verified_family_root_sha256,
            "family_closure_id": verified_closure_id,
            "family_closure_sha256": verified_closure_sha256,
            "structural_surface_artifact_sha256": verified_artifact.artifact_sha256,
            "scanner_fingerprints_by_request": scanner_fingerprints,
            "recovered_output_sha256": output.output_artifact_sha256,
        }
        if recursive:
            assert tree is not None
            capability_payload.update(
                {
                    "nested_family_id": tree.nested_family.family_id,
                    "nested_family_root_sha256": tree.nested_family.entry_sha256,
                    "nested_family_closure_id": tree.nested_closure.closure_id,
                    "nested_family_closure_sha256": tree.nested_closure.entry_sha256,
                    "direct_child_result_sha256s": tree.direct_child_result_sha256s,
                    "nested_child_result_sha256s": tree.nested_child_result_sha256s,
                    "superseded_bridge_result_sha256": tree.bridge_result.entry_sha256,
                    "promoted_leaf_result_sha256s": tree.promoted_leaf_result_sha256s,
                }
            )
            direct_child_result_sha256s = tree.direct_child_result_sha256s
        else:
            child_result_hashes = tuple(result.entry_sha256 for result in content.child_results)
            if len(child_result_hashes) != 2:
                raise ValueError(
                    "scheduler recovery promotion requires exactly two direct children"
                )
            direct_child_result_sha256s = (child_result_hashes[0], child_result_hashes[1])
        capability_binding_sha256 = scheduler_canonical_sha256(capability_payload)
        entry = SchedulerTruncationRecoveryFamilyPromotion.build(
            family=family,
            closure=closure,
            direct_child_result_sha256s=direct_child_result_sha256s,
            recovered_output=output,
            capability_binding_sha256=capability_binding_sha256,
            entry_index=len(self._truncation_recovery_entries),
            previous_entry_sha256=self._truncation_recovery_chain_head,
            nested_family=tree.nested_family if tree is not None else None,
            nested_closure=tree.nested_closure if tree is not None else None,
            nested_child_result_sha256s=(
                tree.nested_child_result_sha256s if tree is not None else None
            ),
            superseded_bridge_result_sha256=(
                tree.bridge_result.entry_sha256 if tree is not None else None
            ),
            promoted_leaf_result_sha256s=(
                tree.promoted_leaf_result_sha256s if tree is not None else None
            ),
        )
        self._append_truncation_recovery_entry(entry)
        return entry

    def _require_current_promoted_truncation_recovery_family(
        self,
        family_id: str,
    ) -> SchedulerTruncationRecoveryFamilyPromotion:
        """Return a fresh promotion only while this exact journal retains live custody."""

        self._assert_live_custody()
        promotion = self._truncation_recovery_indexes.promotions.get(family_id)
        family = self._truncation_recovery_indexes.families.get(family_id)
        closure = self._truncation_recovery_indexes.closures.get(family_id)
        matching_entries = tuple(
            entry
            for entry in self._truncation_recovery_entries
            if isinstance(entry, SchedulerTruncationRecoveryFamilyPromotion)
            and entry.family_id == family_id
        )
        if (
            promotion is None
            or family is None
            or closure is None
            or matching_entries != (promotion,)
            or promotion.family_root_sha256 != family.entry_sha256
            or promotion.family_closure_sha256 != closure.entry_sha256
        ):
            raise ValueError("scheduler lacks one exact retained recovery promotion")
        return SchedulerTruncationRecoveryFamilyPromotion.model_validate_json(
            promotion.model_dump_json(),
            strict=True,
        )

    def issue_promoted_truncation_recovery_surface_coverage(
        self,
        family_id: str,
        closure_capability: VerifiedTruncationRecoveryClosure,
    ) -> VerifiedPromotedTruncationRecoverySurfaceCoverage:
        """Issue live coverage custody only after the matching promotion was appended."""

        self._require_current_promoted_truncation_recovery_family(family_id)
        return _issue_verified_promoted_truncation_recovery_surface_coverage(
            journal=self,
            family_id=family_id,
            closure_capability=closure_capability,
        )

    def issue_promoted_recursive_truncation_recovery_surface_coverage(
        self,
        family_id: str,
        tree_capability: VerifiedRecursiveTruncationRecoveryTree,
    ) -> VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage:
        """Issue live recursive coverage custody after the exact root promotion append."""

        promotion = self._require_current_promoted_truncation_recovery_family(family_id)
        if promotion.schema_version != "1.1":
            raise ValueError("scheduler recursive surface coverage requires a recursive promotion")
        return _issue_verified_promoted_recursive_truncation_recovery_surface_coverage(
            journal=self,
            family_id=family_id,
            tree_capability=tree_capability,
        )

    @property
    def _truncation_recovery_chain_head(self) -> str | None:
        return (
            self._truncation_recovery_entries[-1].entry_sha256
            if self._truncation_recovery_entries
            else None
        )

    def _append_truncation_recovery_entry(
        self,
        entry: SchedulerTruncationRecoveryEntry,
    ) -> None:
        retained = _detach_canonical_model(entry)
        prospective = (*self._truncation_recovery_entries, retained)
        indexes = _derive_truncation_recovery_indexes(
            entries=prospective,
            scheduler=self._indexes,
            manifest=self.manifest,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _truncation_recovery_entry_path(retained),
            retained,
        )
        self._truncation_recovery_entries.append(retained)
        self._truncation_recovery_indexes = indexes
        durable_snapshot = self._validate_state()
        self._adopt_validated_durable_snapshot(durable_snapshot)
        self._refresh_journal_head_checkpoint()

    @property
    def terminal_report_authority(self) -> SchedulerTerminalReportAuthority | None:
        """Return the validated private terminal report projection, when sealed."""

        self._assert_live_custody()
        return (
            _detach_canonical_model(self._terminal_report_authority)
            if self._terminal_report_authority is not None
            else None
        )

    @property
    def next_dependencies(self) -> tuple[SchedulerPassDependency, ...]:
        """Return all exact prior results required by the next pass plan."""

        return tuple(SchedulerPassDependency.from_result(item) for item in self._pass_results)

    @property
    def summary(self) -> SchedulerCampaignSummary:
        self._assert_live_custody()
        return SchedulerCampaignSummary.build(
            manifest=self.manifest,
            pass_results=self._pass_results,
        )

    @property
    def journal_evidence(self) -> SchedulerJournalEvidence:
        """Derive the public hash-and-count projection from exact live journal state."""

        durable_snapshot = self._validate_state()
        summary = self.summary
        model_requests = self.model_requests
        evidence = self._build_journal_evidence(
            summary=summary,
            model_requests=model_requests,
        )
        self._require_durable_snapshot(durable_snapshot)
        return evidence

    @property
    def local_journal_head_checkpoint(self) -> SchedulerJournalEvidence:
        """Return the retained local rollback checkpoint; it grants no authority.

        The sibling file detects partial rollback inside this journal directory. A
        coordinated rollback of both journal and checkpoint remains possible until a
        later external append-only transparency anchor exists.
        """

        self._assert_live_custody()
        if self._journal_head_checkpoint is None:
            raise ValueError("scheduler journal lacks its local head checkpoint")
        return SchedulerJournalEvidence.model_validate(
            self._journal_head_checkpoint.model_dump(mode="python")
        )

    def _initialize_journal_head_checkpoint(self) -> None:
        """Create the first independently stored local expected journal head."""

        if self._journal_head_checkpoint is not None:
            raise ValueError("scheduler journal head checkpoint is already initialized")
        evidence = self._build_journal_evidence(
            summary=SchedulerCampaignSummary.build(
                manifest=self.manifest,
                pass_results=self._pass_results,
            ),
            model_requests=self.model_requests,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
            evidence,
        )
        self._journal_head_checkpoint = evidence
        self._journal_head_checkpoint_bytes = stable_json(evidence).encode("utf-8")

    def _require_journal_head_checkpoint_matches_state(self) -> SchedulerJournalEvidence:
        """Compare the independent local checkpoint before any crash recovery mutation."""

        self._assert_live_custody()
        expected = self._journal_head_checkpoint
        if expected is None:
            raise ValueError("scheduler journal lacks its local head checkpoint")
        observed = self.journal_evidence
        if expected != observed:
            raise ValueError(
                "scheduler local journal-head checkpoint does not match durable journal evidence"
            )
        return observed

    def _is_exact_checkpoint_inventory_predecessor(
        self,
        expected: SchedulerJournalEvidence,
    ) -> bool:
        """Rebuild an older checkpoint from exact retained append-only inventories."""

        try:
            plans = self.plans[: expected.pass_plan_count]
            if tuple(item.pass_plan_sha256 for item in plans) != expected.pass_plan_sha256s:
                return False

            pass_results = self.pass_results[: expected.pass_result_count]
            if (
                tuple(item.pass_result_sha256 for item in pass_results)
                != expected.pass_result_sha256s
            ):
                return False

            events = self.events[: expected.event_count]
            if tuple(item.event_sha256 for item in events) != expected.event_sha256s:
                return False

            recovery_entries = self.truncation_recovery_entries[
                : expected.truncation_recovery_entry_count
            ]
            if (
                tuple(item.entry_sha256 for item in recovery_entries)
                != expected.truncation_recovery_entry_sha256s
            ):
                return False

            activation_hashes = frozenset(expected.task_activation_sha256s)
            activations = tuple(
                item for item in self.activations if item.activation_sha256 in activation_hashes
            )
            if (
                tuple(item.activation_sha256 for item in activations)
                != expected.task_activation_sha256s
            ):
                return False

            output_hashes = frozenset(expected.task_output_artifact_sha256s)
            outputs = tuple(
                item
                for item in self._retained_outputs()
                if item.output_artifact_sha256 in output_hashes
            )
            if (
                tuple(item.output_artifact_sha256 for item in outputs)
                != expected.task_output_artifact_sha256s
            ):
                return False

            attempt_hashes = frozenset(expected.provider_attempt_evidence_sha256s)
            provider_attempts = tuple(
                item
                for item in self._retained_provider_attempts()
                if item.attempt_evidence_sha256 in attempt_hashes
            )
            if (
                tuple(item.attempt_evidence_sha256 for item in provider_attempts)
                != expected.provider_attempt_evidence_sha256s
            ):
                return False

            task_result_hashes = frozenset(expected.task_result_sha256s)
            task_results = tuple(
                item for item in self.task_results if item.result_sha256 in task_result_hashes
            )
            if tuple(item.result_sha256 for item in task_results) != expected.task_result_sha256s:
                return False

            observation_hashes = frozenset(expected.result_observation_sha256s)
            result_observations = tuple(
                item
                for item in self.result_observations
                if item.result_sha256 in observation_hashes
            )
            if (
                tuple(item.result_sha256 for item in result_observations)
                != expected.result_observation_sha256s
            ):
                return False

            terminal_report_authority = None
            if expected.terminal_report_authority_sha256 is not None:
                terminal_report_authority = self._terminal_report_authority
                if (
                    terminal_report_authority is None
                    or terminal_report_authority.authority_sha256
                    != expected.terminal_report_authority_sha256
                ):
                    return False

            summary = SchedulerCampaignSummary.build(
                manifest=self.manifest,
                pass_results=pass_results,
            )
            model_requests = build_scheduler_model_request_evidence(
                plans=plans,
                activations=activations,
                task_results=task_results,
            )
            candidate = SchedulerJournalEvidence.build(
                manifest=self.manifest,
                analysis_input_inventory=self.analysis_input_inventory,
                summary=summary,
                plans=plans,
                model_requests=model_requests,
                activations=activations,
                outputs=outputs,
                provider_attempts=provider_attempts,
                task_results=task_results,
                result_observations=result_observations,
                events=events,
                truncation_recovery_entries=recovery_entries,
                terminal_report_authority=terminal_report_authority,
            )
        except (TypeError, ValueError):
            return False
        return candidate == expected

    def _is_exact_append_only_checkpoint_predecessor(
        self,
        expected: SchedulerJournalEvidence,
    ) -> bool:
        """Require one exact public mutator or in-progress mutator prefix."""

        return self._is_exact_checkpoint_inventory_predecessor(
            expected
        ) and self._checkpoint_delta_is_one_legal_transition(expected)

    def _checkpoint_delta_is_one_legal_transition(
        self,
        expected: SchedulerJournalEvidence,
    ) -> bool:
        """Bound recovery to one public mutator or one in-progress mutator prefix."""

        expected_activation_hashes = frozenset(expected.task_activation_sha256s)
        expected_output_hashes = frozenset(expected.task_output_artifact_sha256s)
        expected_attempt_hashes = frozenset(expected.provider_attempt_evidence_sha256s)
        expected_result_hashes = frozenset(expected.task_result_sha256s)
        expected_observation_hashes = frozenset(expected.result_observation_sha256s)
        new_plans = self.plans[expected.pass_plan_count :]
        new_activations = tuple(
            item
            for item in self.activations
            if item.activation_sha256 not in expected_activation_hashes
        )
        new_events = self.events[expected.event_count :]
        new_outputs = tuple(
            item
            for item in self._retained_outputs()
            if item.output_artifact_sha256 not in expected_output_hashes
        )
        new_attempts = tuple(
            item
            for item in self._retained_provider_attempts()
            if item.attempt_evidence_sha256 not in expected_attempt_hashes
        )
        new_task_results = tuple(
            item for item in self.task_results if item.result_sha256 not in expected_result_hashes
        )
        new_observations = tuple(
            item
            for item in self.result_observations
            if item.result_sha256 not in expected_observation_hashes
        )
        new_pass_results = self.pass_results[expected.pass_result_count :]
        new_recovery_entries = self.truncation_recovery_entries[
            expected.truncation_recovery_entry_count :
        ]
        authority_added = (
            expected.terminal_report_authority_sha256 is None
            and self._terminal_report_authority is not None
        )

        signature = (
            len(new_plans),
            len(new_activations),
            len(new_events),
            len(new_outputs),
            len(new_attempts),
            len(new_task_results),
            len(new_observations),
            len(new_pass_results),
            len(new_recovery_entries),
            int(authority_added),
        )

        def predecessor_event_kind(task_id: str) -> SchedulerTaskEventKind | None:
            history = tuple(
                item for item in self.events[: expected.event_count] if item.task_id == task_id
            )
            return history[-1].kind if history else None

        if len(new_plans) == 1:
            plan = new_plans[0]
            return (
                signature
                == (
                    1,
                    0,
                    len(new_events),
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                and tuple(item.task_id for item in new_events)
                == tuple(item.task_id for item in plan.tasks[: len(new_events)])
                and all(item.kind is SchedulerTaskEventKind.PLANNED for item in new_events)
            )

        if len(new_activations) == 1:
            activation = new_activations[0]
            return (
                signature
                in {
                    (0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
                    (0, 1, 1, 0, 0, 0, 0, 0, 0, 0),
                }
                and predecessor_event_kind(activation.task_id) is SchedulerTaskEventKind.PLANNED
                and all(
                    item.kind is SchedulerTaskEventKind.ACTIVATED
                    and item.task_id == activation.task_id
                    and item.activation_sha256 == activation.activation_sha256
                    for item in new_events
                )
            )

        terminal_delta = (
            len(new_observations) == 1
            and len(new_task_results) in {0, 1}
            and len(new_events) in {0, 1}
            and len(new_task_results) == len(new_events)
            and (
                not new_task_results
                or (
                    new_task_results[0] == new_observations[0]
                    and new_events[0].kind in _TERMINAL_EVENT_KINDS
                    and new_events[0].task_id == new_observations[0].task_id
                    and new_events[0].task_result_sha256 == new_observations[0].result_sha256
                )
            )
        )
        if terminal_delta:
            observation = new_observations[0]
            predecessor_kind = predecessor_event_kind(observation.task_id)
            if predecessor_kind is None:
                return False
            try:
                task, plan = self._task_and_plan(observation.task_id)
                if observation.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT:
                    if (
                        predecessor_kind is not SchedulerTaskEventKind.PLANNED
                        or observation.task_id in self._indexes.activations
                    ):
                        return False
                    exact_public_result = SchedulerTaskResult.build_preflight_failure(
                        plan=plan,
                        task=task,
                        terminal_status=observation.terminal_status,
                        terminal_evidence_sha256=observation.terminal_evidence_sha256,
                    )
                    expected_event_kind = SchedulerTaskEventKind.PREFLIGHT_TERMINAL
                else:
                    activation = self._activation_for_task(observation.task_id)
                    if predecessor_kind is SchedulerTaskEventKind.ACTIVATED:
                        if observation.terminal_status not in {
                            SchedulerTerminalStatus.FAILED,
                            SchedulerTerminalStatus.TRUNCATED,
                            SchedulerTerminalStatus.INVALID,
                            SchedulerTerminalStatus.UNBOUND,
                            SchedulerTerminalStatus.INCONCLUSIVE,
                        }:
                            return False
                        output = None
                        expected_event_kind = SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
                    elif predecessor_kind is SchedulerTaskEventKind.DISPATCHED:
                        output = (
                            self._indexes.outputs.get(observation.task_id)
                            if observation.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                            else None
                        )
                        if output is None and observation.task_id in self._indexes.outputs:
                            return False
                        expected_event_kind = SchedulerTaskEventKind.TERMINAL
                    else:
                        return False
                    exact_public_result = SchedulerTaskResult.build(
                        plan=plan,
                        task=task,
                        activation=activation,
                        terminal_status=observation.terminal_status,
                        terminal_evidence_sha256=observation.terminal_evidence_sha256,
                        output=output,
                    )
            except (TypeError, ValueError):
                return False
            if observation != exact_public_result or (
                new_events and new_events[0].kind is not expected_event_kind
            ):
                return False
            same_output_task = not new_outputs or (
                len(new_outputs) == 1 and new_outputs[0].task_id == observation.task_id
            )
            same_attempt_task = not new_attempts or (
                len(new_attempts) == 1 and new_attempts[0].task_id == observation.task_id
            )
            if new_outputs:
                try:
                    task, plan = self._task_and_plan(new_outputs[0].task_id)
                    exact_recovered_result = SchedulerTaskResult.build(
                        plan=plan,
                        task=task,
                        activation=self._activation_for_task(task.task_id),
                        terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                        terminal_evidence_sha256=(
                            _successful_output_terminal_evidence_sha256(
                                task=task,
                                output=new_outputs[0],
                            )
                        ),
                        output=new_outputs[0],
                    )
                except (TypeError, ValueError):
                    return False
                if observation != exact_recovered_result:
                    return False
            if new_attempts:
                attempt = new_attempts[0]
                try:
                    _require_exact_failed_pre_send_usage(
                        attempt.usage_record,
                        require_runtime_attestation=False,
                    )
                except (TypeError, ValueError):
                    try:
                        task, plan = self._task_and_plan(attempt.task_id)
                        activation = self._activation_for_task(task.task_id)
                        dispatched = tuple(
                            item
                            for item in self._history_for_task(task.task_id)
                            if item.kind is SchedulerTaskEventKind.DISPATCHED
                        )
                        if len(dispatched) != 1:
                            return False
                        if attempt.schema_version == "1.1":
                            projection = attempt.truncation_projection
                            envelope = attempt.truncated_envelope_evidence
                            if projection is None or envelope is None:
                                return False
                            exact_recovered_result = SchedulerTaskResult.build(
                                plan=plan,
                                task=task,
                                activation=activation,
                                terminal_status=SchedulerTerminalStatus.TRUNCATED,
                                terminal_evidence_sha256=projection.evidence_sha256,
                            )
                        else:
                            exact_recovered_result = SchedulerTaskResult.build(
                                plan=plan,
                                task=task,
                                activation=activation,
                                terminal_status=SchedulerTerminalStatus.UNCERTAIN,
                                terminal_evidence_sha256=scheduler_canonical_sha256(
                                    {
                                        "classification": "dispatch_without_terminal",
                                        "dispatch_event_sha256": dispatched[0].event_sha256,
                                    }
                                ),
                            )
                    except (TypeError, ValueError):
                        return False
                    if observation != exact_recovered_result:
                        return False
            return (
                not new_plans
                and not new_activations
                and not new_pass_results
                and not new_recovery_entries
                and not authority_added
                and len(new_outputs) <= 1
                and len(new_attempts) <= 1
                and not (new_outputs and new_attempts)
                and same_output_task
                and same_attempt_task
            )

        if signature == (0, 0, 1, 0, 0, 0, 0, 0, 0, 0):
            event = new_events[0]
            return (
                event.kind is SchedulerTaskEventKind.DISPATCHED
                and predecessor_event_kind(event.task_id) is SchedulerTaskEventKind.ACTIVATED
            )
        if signature == (0, 0, 0, 1, 0, 0, 0, 0, 0, 0):
            return (
                predecessor_event_kind(new_outputs[0].task_id) is SchedulerTaskEventKind.DISPATCHED
            )
        if signature == (0, 0, 0, 0, 1, 0, 0, 0, 0, 0):
            attempt = new_attempts[0]
            predecessor_kind = predecessor_event_kind(attempt.task_id)
            if predecessor_kind is SchedulerTaskEventKind.DISPATCHED:
                return True
            if predecessor_kind is not SchedulerTaskEventKind.ACTIVATED:
                return False
            try:
                task, _plan = self._task_and_plan(attempt.task_id)
                _require_exact_failed_pre_send_usage(
                    attempt.usage_record,
                    require_runtime_attestation=False,
                )
                _require_exact_activation_released_usage(
                    attempt.usage_record,
                    logical_request_id=task.logical_request_id,
                    require_runtime_attestation=False,
                )
            except (TypeError, ValueError):
                return False
            return True
        return signature in {
            (0, 0, 0, 0, 0, 0, 0, 1, 0, 0),
            (0, 0, 0, 0, 0, 0, 0, 0, 1, 0),
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
        }

    def _checkpoint_extension_requires_released_cost_join(
        self,
        expected: SchedulerJournalEvidence,
    ) -> bool:
        """Keep released pre-send suffixes behind their exact external-ledger join."""

        expected_attempts = frozenset(expected.provider_attempt_evidence_sha256s)
        expected_observations = frozenset(expected.result_observation_sha256s)
        expected_events = frozenset(expected.event_sha256s)
        released_attempt_task_ids: set[str] = set()
        for attempt in self._retained_provider_attempts():
            try:
                _require_exact_failed_pre_send_usage(
                    attempt.usage_record,
                    require_runtime_attestation=False,
                )
            except (TypeError, ValueError):
                continue
            released_attempt_task_ids.add(attempt.task_id)
            if attempt.attempt_evidence_sha256 not in expected_attempts:
                return True
        if any(
            item.result_sha256 not in expected_observations
            and item.task_id in released_attempt_task_ids
            for item in self.result_observations
        ):
            return True
        if any(
            item.event_sha256 not in expected_events and item.task_id in released_attempt_task_ids
            for item in self.events
        ):
            return True
        expected_recovery_entries = frozenset(expected.truncation_recovery_entry_sha256s)
        return any(
            isinstance(item, SchedulerTruncationRecoveryChildResult)
            and item.entry_sha256 not in expected_recovery_entries
            and item.schema_version == "1.3"
            and item.cost_disposition
            is SchedulerTruncationRecoveryCostDisposition.RELEASED_PRE_SEND_TAIL
            for item in self._retained_truncation_recovery_entries()
        )

    def _released_main_checkpoint_delta_has_exact_ledger_join(
        self,
        *,
        expected: SchedulerJournalEvidence,
        tasks_by_request: dict[str, SchedulerTaskPlan],
        ledger_entries: tuple[CostEntry, ...],
    ) -> bool:
        """Validate one released attempt and its deterministic terminal prefix."""

        expected_attempts = frozenset(expected.provider_attempt_evidence_sha256s)
        expected_observations = frozenset(expected.result_observation_sha256s)
        expected_results = frozenset(expected.task_result_sha256s)
        new_attempts = tuple(
            item
            for item in self._retained_provider_attempts()
            if item.attempt_evidence_sha256 not in expected_attempts
        )
        new_observations = tuple(
            item
            for item in self.result_observations
            if item.result_sha256 not in expected_observations
        )
        new_results = tuple(
            item for item in self.task_results if item.result_sha256 not in expected_results
        )
        new_events = self.events[expected.event_count :]
        candidate_task_ids = {
            *(item.task_id for item in new_attempts),
            *(item.task_id for item in new_observations),
            *(item.task_id for item in new_events),
        }
        if len(candidate_task_ids) != 1:
            return False
        task_id = candidate_task_ids.pop()
        task = next(
            (item for item in tasks_by_request.values() if item.task_id == task_id),
            None,
        )
        attempts = tuple(
            item for item in self._retained_provider_attempts() if item.task_id == task_id
        )
        predecessor_history = tuple(
            item for item in self.events[: expected.event_count] if item.task_id == task_id
        )
        if task is None or len(attempts) != 1 or not predecessor_history:
            return False
        attempt = attempts[0]
        predecessor_kind = predecessor_history[-1].kind
        if predecessor_kind not in {
            SchedulerTaskEventKind.ACTIVATED,
            SchedulerTaskEventKind.DISPATCHED,
        }:
            return False
        try:
            _require_exact_failed_pre_send_usage(
                attempt.usage_record,
                require_runtime_attestation=False,
            )
            if predecessor_kind is SchedulerTaskEventKind.ACTIVATED:
                _require_exact_activation_released_usage(
                    attempt.usage_record,
                    logical_request_id=task.logical_request_id,
                    require_runtime_attestation=False,
                )
            retained_ids, _pending = _retained_main_usage_cost_recovery_plan(
                records=(attempt.usage_record,),
                tasks_by_request=tasks_by_request,
                ledger_entries=ledger_entries,
            )
            task_entries = _campaign_entries_for_task(
                task=task,
                tasks_by_request=tasks_by_request,
                ledger_entries=ledger_entries,
            )
            if not task_entries:
                return False
            released_entry = task_entries[-1][1]
            _require_exact_pre_send_release(released_entry)
            if retained_ids != frozenset(entry.request_id for _ordinal, entry in task_entries):
                return False
            plan = next(item for item in self.plans if task in item.tasks)
            recovered_result = SchedulerTaskResult.build(
                plan=plan,
                task=task,
                activation=self._activation_for_task(task_id),
                terminal_status=SchedulerTerminalStatus.FAILED,
                terminal_evidence_sha256=cost_entry_sha256(released_entry),
            )
        except (StopIteration, TypeError, ValueError):
            return False
        if new_observations and new_observations != (recovered_result,):
            return False
        if new_results and new_results != (recovered_result,):
            return False
        if new_events:
            expected_kind = (
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
                if predecessor_kind is SchedulerTaskEventKind.ACTIVATED
                else SchedulerTaskEventKind.TERMINAL
            )
            if (
                len(new_events) != 1
                or new_events[0].kind is not expected_kind
                or new_events[0].task_result_sha256 != recovered_result.result_sha256
            ):
                return False
        return bool(new_attempts or new_observations or new_results or new_events)

    def _require_checkpoint_or_staged_released_attempt(
        self,
        *,
        atomic_ledger: AtomicCostLedger | None,
        expected_checkpoint: SchedulerJournalEvidence | None = None,
    ) -> SchedulerJournalEvidence:
        """Admit one exact append-only suffix, with strict released-cost custody.

        Ordinary scheduler transitions are replayable only when selecting the hashes
        from the retained checkpoint reconstructs its complete predecessor evidence.
        Released provider-attempt and v1.3 child suffixes additionally require their
        exact trusted-ledger join before checkpoint adoption can mutate the journal.
        """

        self._assert_live_custody()
        expected = expected_checkpoint or self._journal_head_checkpoint
        if expected is None:
            raise ValueError("scheduler journal lacks its local head checkpoint")
        if (
            self._pending_checkpoint_recovery
            and not self._checkpoint_extension_requires_released_cost_join(expected)
            and self._is_exact_append_only_checkpoint_predecessor(expected)
        ):
            return expected
        observed = self.journal_evidence
        if expected == observed:
            return observed
        if atomic_ledger is None:
            raise ValueError(
                "scheduler local journal-head checkpoint does not match durable journal evidence"
            )

        ledger_entries = atomic_ledger.snapshot().entries
        tasks_by_request = {
            task.logical_request_id: task
            for plan in self.plans
            for task in plan.tasks
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
        }
        terminal_task_ids = frozenset(result.task_id for result in self.task_results)
        retained_attempts = self._retained_provider_attempts()
        if (
            self._pending_checkpoint_recovery
            and self._is_exact_append_only_checkpoint_predecessor(expected)
            and self._released_main_checkpoint_delta_has_exact_ledger_join(
                expected=expected,
                tasks_by_request=tasks_by_request,
                ledger_entries=ledger_entries,
            )
        ):
            return expected
        matching_suffixes: list[SchedulerProviderAttemptEvidence] = []
        for attempt in retained_attempts:
            task = next(
                (
                    candidate
                    for candidate in tasks_by_request.values()
                    if candidate.task_id == attempt.task_id
                ),
                None,
            )
            if task is None or task.task_id in terminal_task_ids:
                continue
            history = self._history_for_task(task.task_id)
            if not history or history[-1].kind not in {
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.DISPATCHED,
            }:
                continue
            usage = attempt.usage_record
            try:
                _require_exact_failed_pre_send_usage(
                    usage,
                    require_runtime_attestation=False,
                )
                if history[-1].kind is SchedulerTaskEventKind.ACTIVATED:
                    _require_exact_activation_released_usage(
                        usage,
                        logical_request_id=task.logical_request_id,
                        require_runtime_attestation=False,
                    )
                retained_ids, _pending = _retained_main_usage_cost_recovery_plan(
                    records=(usage,),
                    tasks_by_request=tasks_by_request,
                    ledger_entries=ledger_entries,
                )
                task_entries = _campaign_entries_for_task(
                    task=task,
                    tasks_by_request=tasks_by_request,
                    ledger_entries=ledger_entries,
                )
                if not task_entries:
                    continue
                _require_exact_pre_send_release(task_entries[-1][1])
                if retained_ids != frozenset(entry.request_id for _ordinal, entry in task_entries):
                    continue
                predecessor_attempts = tuple(
                    candidate
                    for candidate in retained_attempts
                    if candidate.attempt_evidence_sha256 != attempt.attempt_evidence_sha256
                )
                predecessor = SchedulerJournalEvidence.build(
                    manifest=self.manifest,
                    analysis_input_inventory=self.analysis_input_inventory,
                    summary=self.summary,
                    plans=self.plans,
                    model_requests=self.model_requests,
                    activations=self.activations,
                    outputs=self._retained_outputs(),
                    provider_attempts=predecessor_attempts,
                    task_results=self.task_results,
                    result_observations=self.result_observations,
                    events=self.events,
                    truncation_recovery_entries=(self._retained_truncation_recovery_entries()),
                    terminal_report_authority=self._terminal_report_authority,
                )
            except (TypeError, ValueError):
                continue
            if predecessor == expected:
                matching_suffixes.append(attempt)
        matching_terminal_suffixes: list[SchedulerTaskResult] = []
        for result in self.task_results:
            if (
                result.terminal_status is not SchedulerTerminalStatus.FAILED
                or not self.events
                or self.events[-1].task_id != result.task_id
                or self.events[-1].kind
                not in {
                    SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
                    SchedulerTaskEventKind.TERMINAL,
                }
                or self.events[-1].task_result_sha256 != result.result_sha256
            ):
                continue
            task = next(
                (
                    candidate
                    for candidate in tasks_by_request.values()
                    if candidate.task_id == result.task_id
                ),
                None,
            )
            matching_attempt = next(
                (
                    candidate
                    for candidate in retained_attempts
                    if candidate.task_id == result.task_id
                ),
                None,
            )
            if task is None or matching_attempt is None:
                continue
            try:
                _require_exact_failed_pre_send_usage(
                    matching_attempt.usage_record,
                    require_runtime_attestation=False,
                )
                task_entries = _campaign_entries_for_task(
                    task=task,
                    tasks_by_request=tasks_by_request,
                    ledger_entries=ledger_entries,
                )
                if not task_entries:
                    continue
                released_entry = task_entries[-1][1]
                _require_exact_pre_send_release(released_entry)
                retained_ids, _pending = _retained_main_usage_cost_recovery_plan(
                    records=(matching_attempt.usage_record,),
                    tasks_by_request=tasks_by_request,
                    ledger_entries=ledger_entries,
                )
                if result.terminal_evidence_sha256 != cost_entry_sha256(
                    released_entry
                ) or retained_ids != frozenset(
                    entry.request_id for _ordinal, entry in task_entries
                ):
                    continue
                predecessor_results = tuple(
                    candidate
                    for candidate in self.task_results
                    if candidate.task_id != result.task_id
                )
                predecessor_observations = tuple(
                    candidate
                    for candidate in self.result_observations
                    if candidate.task_id != result.task_id
                )
                predecessor_events = self.events[:-1]
                predecessor = SchedulerJournalEvidence.build(
                    manifest=self.manifest,
                    analysis_input_inventory=self.analysis_input_inventory,
                    summary=self.summary,
                    plans=self.plans,
                    model_requests=build_scheduler_model_request_evidence(
                        plans=self.plans,
                        activations=self.activations,
                        task_results=predecessor_results,
                    ),
                    activations=self.activations,
                    outputs=self._retained_outputs(),
                    provider_attempts=retained_attempts,
                    task_results=predecessor_results,
                    result_observations=predecessor_observations,
                    events=predecessor_events,
                    truncation_recovery_entries=(self._retained_truncation_recovery_entries()),
                    terminal_report_authority=self._terminal_report_authority,
                )
            except (TypeError, ValueError):
                continue
            if predecessor == expected:
                matching_terminal_suffixes.append(result)
        credited_result_hashes = frozenset(result.result_sha256 for result in self.task_results)
        matching_result_suffixes: list[SchedulerTaskResult] = []
        for result in self.result_observations:
            if (
                result.result_sha256 in credited_result_hashes
                or result.terminal_status is not SchedulerTerminalStatus.FAILED
            ):
                continue
            task = next(
                (
                    candidate
                    for candidate in tasks_by_request.values()
                    if candidate.task_id == result.task_id
                ),
                None,
            )
            matching_attempt = next(
                (
                    candidate
                    for candidate in retained_attempts
                    if candidate.task_id == result.task_id
                ),
                None,
            )
            history = self._history_for_task(result.task_id)
            if (
                task is None
                or matching_attempt is None
                or not history
                or history[-1].kind
                not in {
                    SchedulerTaskEventKind.ACTIVATED,
                    SchedulerTaskEventKind.DISPATCHED,
                }
            ):
                continue
            try:
                _require_exact_failed_pre_send_usage(
                    matching_attempt.usage_record,
                    require_runtime_attestation=False,
                )
                task_entries = _campaign_entries_for_task(
                    task=task,
                    tasks_by_request=tasks_by_request,
                    ledger_entries=ledger_entries,
                )
                if not task_entries:
                    continue
                released_entry = task_entries[-1][1]
                _require_exact_pre_send_release(released_entry)
                retained_ids, _pending = _retained_main_usage_cost_recovery_plan(
                    records=(matching_attempt.usage_record,),
                    tasks_by_request=tasks_by_request,
                    ledger_entries=ledger_entries,
                )
                if result.terminal_evidence_sha256 != cost_entry_sha256(
                    released_entry
                ) or retained_ids != frozenset(
                    entry.request_id for _ordinal, entry in task_entries
                ):
                    continue
                predecessor_observations = tuple(
                    candidate
                    for candidate in self.result_observations
                    if candidate.result_sha256 != result.result_sha256
                )
                predecessor = SchedulerJournalEvidence.build(
                    manifest=self.manifest,
                    analysis_input_inventory=self.analysis_input_inventory,
                    summary=self.summary,
                    plans=self.plans,
                    model_requests=self.model_requests,
                    activations=self.activations,
                    outputs=self._retained_outputs(),
                    provider_attempts=retained_attempts,
                    task_results=self.task_results,
                    result_observations=predecessor_observations,
                    events=self.events,
                    truncation_recovery_entries=(self._retained_truncation_recovery_entries()),
                    terminal_report_authority=self._terminal_report_authority,
                )
            except (TypeError, ValueError):
                continue
            if predecessor == expected:
                matching_result_suffixes.append(result)
        matching_recovery_suffixes: list[SchedulerTruncationRecoveryChildResult] = []
        recovery_entries = self._retained_truncation_recovery_entries()
        if recovery_entries and isinstance(
            recovery_entries[-1],
            SchedulerTruncationRecoveryChildResult,
        ):
            recovery_result = recovery_entries[-1]
            if (
                recovery_result.schema_version == "1.3"
                and recovery_result.cost_disposition
                is SchedulerTruncationRecoveryCostDisposition.RELEASED_PRE_SEND_TAIL
            ):
                try:
                    groups = _recovery_child_cost_recovery_plan(
                        indexes=self._truncation_recovery_indexes,
                        ledger_entries=ledger_entries,
                    )
                    matching_groups = tuple(
                        group
                        for group in groups
                        if group.child.child_task_id == recovery_result.child_task_id
                        and group.status is SchedulerCostRecoveryStatus.RELEASED_PROVEN_PRE_SEND
                    )
                    if len(matching_groups) != 1:
                        raise ValueError("released recovery suffix lacks exact ledger custody")
                    predecessor = SchedulerJournalEvidence.build(
                        manifest=self.manifest,
                        analysis_input_inventory=self.analysis_input_inventory,
                        summary=self.summary,
                        plans=self.plans,
                        model_requests=self.model_requests,
                        activations=self.activations,
                        outputs=self._retained_outputs(),
                        provider_attempts=retained_attempts,
                        task_results=self.task_results,
                        result_observations=self.result_observations,
                        events=self.events,
                        truncation_recovery_entries=recovery_entries[:-1],
                        terminal_report_authority=self._terminal_report_authority,
                    )
                except (TypeError, ValueError):
                    pass
                else:
                    if predecessor == expected:
                        matching_recovery_suffixes.append(recovery_result)
        if (
            len(matching_suffixes)
            + len(matching_terminal_suffixes)
            + len(matching_result_suffixes)
            + len(matching_recovery_suffixes)
            != 1
        ):
            raise ValueError(
                "scheduler local journal-head checkpoint does not match durable journal evidence"
            )
        return expected

    def _refresh_journal_head_checkpoint(self) -> SchedulerJournalEvidence:
        """Atomically retain the exact stable head after one durable transition."""

        self._assert_live_custody()
        if self._read_only:
            raise ValueError("scheduler verification journal is read-only")
        previous = self._journal_head_checkpoint
        if previous is None:
            raise ValueError("scheduler journal lacks its local head checkpoint")
        prospective_snapshot = self._observe_incremental_durable_artifacts()
        current = self._build_retained_journal_evidence()
        self._require_incremental_durable_snapshot(prospective_snapshot)
        previous_bytes = stable_json(previous).encode("utf-8")
        root_names = set(os.listdir(self._root_descriptor))
        if _JOURNAL_TRANSITION_PREDECESSOR_FILENAME not in root_names:
            _write_fresh_private_file(
                self._root_descriptor,
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
                previous_bytes,
            )
        elif (
            _read_private_file(
                self._root_descriptor,
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            )
            != previous_bytes
        ):
            raise ValueError("scheduler transition predecessor differs from retained checkpoint")
        if current == previous:
            _unlink_exact_private_file(
                self._root_descriptor,
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
                previous_bytes,
            )
            return current
        current_bytes = stable_json(current).encode("utf-8")
        _replace_private_file(
            self._root_descriptor,
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
            current_bytes,
        )
        self._pending_checkpoint_recovery = False
        self._journal_head_checkpoint = current
        self._journal_head_checkpoint_bytes = current_bytes
        self._adopt_validated_durable_snapshot(prospective_snapshot)
        _unlink_exact_private_file(
            self._root_descriptor,
            _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            previous_bytes,
        )
        self._assert_live_custody()
        return current

    def _adopt_staged_journal_head_checkpoint(
        self,
        checkpoint: SchedulerJournalEvidence,
    ) -> None:
        """Finish one exact released-transition checkpoint replacement after a crash."""

        self._assert_live_custody()
        canonical = stable_json(checkpoint).encode("utf-8")
        _adopt_pending_private_file(
            self._root_descriptor,
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
            canonical,
        )
        self._journal_head_checkpoint = checkpoint
        self._journal_head_checkpoint_bytes = canonical
        staged_predecessor_present = bool(
            {_JOURNAL_TRANSITION_PREDECESSOR_FILENAME} & set(os.listdir(self._root_descriptor))
        )
        self._pending_checkpoint_recovery = staged_predecessor_present
        _validate_control_layout(
            self._root_descriptor,
            self._directory_descriptors,
            self._directory_identities,
            allow_pending_checkpoint=staged_predecessor_present,
        )
        self._assert_live_custody()

    def _build_retained_journal_evidence(self) -> SchedulerJournalEvidence:
        """Project frozen live state after transition-local validation and byte custody."""

        summary = SchedulerCampaignSummary.build(
            manifest=self.manifest,
            pass_results=self._pass_results,
        )
        model_requests = build_scheduler_model_request_evidence(
            plans=self._plans,
            activations=self._activations,
            task_results=self.task_results,
        )
        return SchedulerJournalEvidence._build_from_validated_retained_state(
            manifest=self.manifest,
            analysis_input_inventory=self.analysis_input_inventory,
            summary=summary,
            plans=self._plans,
            model_requests=model_requests,
            activations=self._activations,
            outputs=self._outputs,
            provider_attempts=self._provider_attempts,
            task_results=self.task_results,
            result_observations=self._result_observations,
            events=self._events,
            truncation_recovery_entries=self._truncation_recovery_entries,
            terminal_report_authority=self._terminal_report_authority,
        )

    def _retained_durable_models(self) -> dict[str, BaseModel]:
        """Return every immutable model represented by the private artifact inventory."""

        pairs: tuple[tuple[str, BaseModel], ...] = (
            (_MANIFEST_FILENAME, self.manifest),
            (_ANALYSIS_INPUT_INVENTORY_FILENAME, self.analysis_input_inventory),
            *((_pass_plan_path(index), item) for index, item in enumerate(self._plans)),
            *((_activation_path(item), item) for item in self._activations),
            *((_event_path(item.event_index), item) for item in self._events),
            *((_task_output_path(item), item) for item in self._outputs),
            *((_provider_attempt_path(item), item) for item in self._provider_attempts),
            *((_task_result_path(item), item) for item in self._result_observations),
            *((_pass_result_path(index), item) for index, item in enumerate(self._pass_results)),
            *(
                (_truncation_recovery_entry_path(item), item)
                for item in self._truncation_recovery_entries
            ),
            *(
                ((_TERMINAL_REPORT_AUTHORITY_FILENAME, self._terminal_report_authority),)
                if self._terminal_report_authority is not None
                else ()
            ),
        )
        retained = dict(pairs)
        if len(retained) != len(pairs):
            raise ValueError("scheduler retained state repeats a durable artifact path")
        return retained

    def _require_exact_retained_artifact_layout(
        self,
        relative_paths: Iterable[str],
    ) -> None:
        """Reject missing or unmanifested child artifacts without reopening their bytes."""

        staged_checkpoint_present = bool(
            {
                _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            }
            & set(os.listdir(self._root_descriptor))
        )
        _assert_descriptor_custody(
            path=self.path,
            root_descriptor=self._root_descriptor,
            root_identity=self._root_identity,
            directory_descriptors=self._directory_descriptors,
            directory_identities=self._directory_identities,
            allow_pending_checkpoint=(
                self._pending_checkpoint_recovery or staged_checkpoint_present
            ),
            allowed_immutable_write_temps=self._allowed_immutable_write_temps,
            allowed_published_immutable_targets=(self._allowed_published_immutable_targets),
        )
        expected_by_directory = {name: set[str]() for name in _CONTROL_DIRECTORIES}
        for relative in relative_paths:
            path = PurePosixPath(relative)
            if len(path.parts) == 2:
                directory, leaf = path.parts
                if directory not in expected_by_directory:
                    raise ValueError("scheduler retained artifact has an uncontrolled parent")
                expected_by_directory[directory].add(leaf)
        for directory, expected in expected_by_directory.items():
            expected.update(
                PurePosixPath(item).name
                for item in self._allowed_immutable_write_temps
                if PurePosixPath(item).parent == PurePosixPath(directory)
            )
            try:
                observed = set(os.listdir(self._directory_descriptors[directory]))
            except OSError as exc:
                raise ValueError("scheduler retained artifact layout is unavailable") from exc
            if observed != expected:
                raise ValueError("scheduler journal contains an unmanifested retained artifact")

    def _observe_incremental_durable_artifacts(
        self,
    ) -> tuple[_DurableArtifactObservation, ...]:
        """Stat immutable artifacts and read only additions to the validated cache."""

        retained_models = self._retained_durable_models()
        retained_paths = tuple(sorted(retained_models))
        self._require_exact_retained_artifact_layout(retained_paths)
        cached = self._durable_artifact_observations
        if cached is None or not set(cached) <= set(retained_paths):
            raise ValueError("scheduler journal lacks its validated durable-artifact cache")
        prospective = dict(cached)
        for relative in retained_paths:
            parent_descriptor, leaf = _relative_parent(
                self._root_descriptor,
                self._directory_descriptors,
                relative,
            )
            previous = cached.get(relative)
            if previous is not None:
                observed_identity = _evidence_file_identity(_stat_entry(parent_descriptor, leaf))
                if observed_identity != previous[0]:
                    raise ValueError("scheduler retained artifact changed after validation")
                continue
            content, observed_identity = _read_private_file_observation(
                parent_descriptor,
                leaf,
                allowed_published_identity=(
                    self._allowed_published_immutable_targets.get(relative)
                ),
            )
            expected_content = stable_json(retained_models[relative]).encode("utf-8")
            if content != expected_content:
                raise ValueError("scheduler new retained artifact differs from live state")
            prospective[relative] = (
                observed_identity,
                hashlib.sha256(content).hexdigest(),
            )
        return tuple(
            (relative, identity, content_sha256)
            for relative, (identity, content_sha256) in sorted(prospective.items())
        )

    def _require_incremental_durable_snapshot(
        self,
        expected: tuple[_DurableArtifactObservation, ...],
    ) -> None:
        """Re-stat the complete immutable inventory after fast evidence projection."""

        expected_by_path = {
            relative: (identity, content_sha256) for relative, identity, content_sha256 in expected
        }
        if len(expected_by_path) != len(expected):
            raise ValueError("scheduler durable snapshot repeats an artifact path")
        self._require_exact_retained_artifact_layout(tuple(expected_by_path))
        for relative, (expected_identity, _content_sha256) in expected_by_path.items():
            parent_descriptor, leaf = _relative_parent(
                self._root_descriptor,
                self._directory_descriptors,
                relative,
            )
            if _evidence_file_identity(_stat_entry(parent_descriptor, leaf)) != expected_identity:
                raise ValueError("scheduler retained artifact changed during checkpoint projection")

    def _adopt_validated_durable_snapshot(
        self,
        snapshot: tuple[_DurableArtifactObservation, ...],
    ) -> None:
        """Cache one full or incrementally verified immutable artifact snapshot."""

        expected_paths = set(self._retained_durable_models())
        observed = {
            relative: (identity, content_sha256) for relative, identity, content_sha256 in snapshot
        }
        if len(observed) != len(snapshot) or set(observed) != expected_paths:
            raise ValueError("scheduler validated snapshot differs from retained artifact paths")
        self._durable_artifact_observations = observed

    def _build_journal_evidence(
        self,
        *,
        summary: SchedulerCampaignSummary,
        model_requests: tuple[SchedulerModelRequestEvidence, ...],
    ) -> SchedulerJournalEvidence:
        return SchedulerJournalEvidence.build(
            manifest=self.manifest,
            analysis_input_inventory=self.analysis_input_inventory,
            summary=summary,
            plans=self.plans,
            model_requests=model_requests,
            activations=self.activations,
            outputs=self._retained_outputs(),
            provider_attempts=self._retained_provider_attempts(),
            task_results=self.task_results,
            result_observations=self.result_observations,
            events=self.events,
            truncation_recovery_entries=self._retained_truncation_recovery_entries(),
            terminal_report_authority=self._terminal_report_authority,
        )

    @property
    def model_requests(self) -> tuple[SchedulerModelRequestEvidence, ...]:
        """Derive public hash-only evidence for every planned model request."""

        return build_scheduler_model_request_evidence(
            plans=self.plans,
            activations=self.activations,
            task_results=self.task_results,
        )

    @property
    def recovery_model_requests(
        self,
    ) -> tuple[SchedulerTruncationRecoveryModelRequestEvidence, ...]:
        """Derive public hash-only evidence for every typed v1.1 recovery usage."""

        return build_scheduler_truncation_recovery_model_request_evidence(
            manifest=self.manifest,
            model_requests=self.model_requests,
            truncation_recovery_entries=self._retained_truncation_recovery_entries(),
            provider_attempts=self.provider_attempts,
        )

    @property
    def retained_provider_usage_records(self) -> tuple[UsageRecord, ...]:
        """Return every retained provider completion for accounting, without REAL credit."""

        records = (
            self._retained_main_provider_usage_records() + self._retained_typed_recovery_usage()[0]
        )
        request_ids = tuple(record.request_id for record in records)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("scheduler retained usage repeats a logical request identity")
        return tuple(sorted(records, key=lambda item: item.request_id))

    def _retained_main_provider_usage_records(self) -> tuple[UsageRecord, ...]:
        return tuple(
            UsageRecord.model_validate(output.model_completion_evidence.usage_record.model_dump())
            for output in self._retained_outputs()
            if output.model_completion_evidence is not None
        ) + tuple(
            UsageRecord.model_validate(attempt.usage_record.model_dump())
            for attempt in self._retained_provider_attempts()
        )

    def _retained_typed_recovery_usage(
        self,
    ) -> tuple[
        tuple[UsageRecord, ...],
        tuple[tuple[str, str, int], ...],
        tuple[str, ...],
    ]:
        retained: list[tuple[UsageRecord, tuple[str, str, int], str]] = []
        for child_task_id, result in self._truncation_recovery_indexes.results.items():
            if not isinstance(
                result, SchedulerTruncationRecoveryChildResult
            ) or result.schema_version not in {"1.1", "1.2", "1.3"}:
                continue
            if result.runtime_usage_record is None:
                continue
            child, family_id = self._truncation_recovery_indexes.children[child_task_id]
            activation = self._truncation_recovery_indexes.activations[child_task_id]
            family = self._truncation_recovery_indexes.families[family_id]
            coordinate = _typed_recovery_usage_coordinate(
                result=result,
                child=child,
                activation=activation,
                family=family,
            )
            usage = result.runtime_usage_record
            assert usage is not None
            detached = UsageRecord.model_validate(usage.model_dump(mode="python"), strict=True)
            retained.append(
                (
                    detached,
                    coordinate,
                    family.request_limit_binding.request_limit_id,
                )
            )
        ordered = tuple(sorted(retained, key=lambda item: item[0].request_id))
        return (
            tuple(item[0] for item in ordered),
            tuple(item[1] for item in ordered),
            tuple(item[2] for item in ordered),
        )

    def _promoted_typed_recovery_usage(
        self,
    ) -> tuple[tuple[UsageRecord, tuple[str, str, int]], ...]:
        promoted_result_sha256s = tuple(
            result_sha256
            for promotion in self._truncation_recovery_indexes.promotions.values()
            for result_sha256 in (
                promotion.promoted_leaf_result_sha256s
                if promotion.schema_version == "1.1"
                and promotion.promoted_leaf_result_sha256s is not None
                else promotion.direct_child_result_sha256s
            )
        )
        if len(promoted_result_sha256s) != len(set(promoted_result_sha256s)):
            raise ValueError("scheduler recovery promotions repeat a child result")
        promoted_hashes = set(promoted_result_sha256s)
        records: list[tuple[UsageRecord, tuple[str, str, int]]] = []
        observed_hashes: set[str] = set()
        for child_task_id, result in self._truncation_recovery_indexes.results.items():
            if result.entry_sha256 not in promoted_hashes:
                continue
            if (
                not isinstance(result, SchedulerTruncationRecoveryChildResult)
                or result.schema_version not in {"1.1", "1.2"}
                or result.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
                or result.runtime_usage_record is None
            ):
                raise ValueError("scheduler recovery promotion lacks typed successful usage")
            child, family_id = self._truncation_recovery_indexes.children[child_task_id]
            activation = self._truncation_recovery_indexes.activations[child_task_id]
            family = self._truncation_recovery_indexes.families[family_id]
            coordinate = _typed_recovery_usage_coordinate(
                result=result,
                child=child,
                activation=activation,
                family=family,
            )
            records.append((result.runtime_usage_record, coordinate))
            observed_hashes.add(result.entry_sha256)
        if observed_hashes != promoted_hashes:
            raise ValueError("scheduler recovery promotion lacks exact child usage custody")
        return tuple(sorted(records, key=lambda item: item[0].request_id))

    def _recovery_budget_request_limit_roots(self) -> tuple[tuple[str, int], ...]:
        _records, _coordinates, roots = self._retained_typed_recovery_usage()
        family_roots = tuple(
            family.request_limit_id
            for family in self._truncation_recovery_indexes.families.values()
        )
        distinct = tuple(sorted(set((*roots, *family_roots))))
        if not distinct:
            return ()
        if len(distinct) > SCHEDULER_TRUNCATION_RECOVERY_MAX_FAMILIES:
            raise ValueError("budget recovery exceeds its shared request-limit root bound")
        main_records = self._retained_main_provider_usage_records()
        coordinates: list[tuple[str, int]] = []
        for root_scope in distinct:
            root_records = tuple(
                record for record in main_records if record.request_id == root_scope
            )
            if len(root_records) != 1:
                raise ValueError("budget recovery lacks one exact retained root request")
            try:
                inventory = atomic_request_limit_reservations_from_usage(root_records[0])
            except ValueError:
                raise ValueError(
                    "budget recovery root request-limit inventory is invalid"
                ) from None
            root_families = tuple(
                family
                for family in self._truncation_recovery_indexes.families.values()
                if family.request_limit_id == root_scope
            )
            if (
                not inventory
                or not root_families
                or any(
                    family.request_limit_binding.parent_request_limit_reservation != inventory[-1]
                    for family in root_families
                )
            ):
                raise ValueError("budget recovery root differs from its frozen family reservation")
            coordinates.append((root_scope, inventory[0].request_limit_count_before))
        return tuple(coordinates)

    @property
    def restorable_usage_records(self) -> tuple[UsageRecord, ...]:
        """Compatibility alias for the complete retained provider-accounting inventory."""

        return self.retained_provider_usage_records

    @property
    def structurally_successful_review_usage_records(self) -> tuple[UsageRecord, ...]:
        """Return durable successful review usage without promoting MOCK to REAL credit."""

        successful = {
            result.task_id
            for result in self.task_results
            if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
        }
        main_records = tuple(
            UsageRecord.model_validate(output.model_completion_evidence.usage_record.model_dump())
            for output in self._retained_outputs()
            if (output.task_id in successful and output.model_completion_evidence is not None)
        )
        recovery_records = tuple(
            UsageRecord.model_validate(record.model_dump(mode="python"), strict=True)
            for record, (_request_id, request_limit_scope, request_limit_count_before) in (
                self._promoted_typed_recovery_usage()
            )
            if is_structurally_recovery_creditable_usage_record(
                record,
                request_limit_scope=request_limit_scope,
                request_limit_count_before=request_limit_count_before,
            )
        )
        records = main_records + recovery_records
        if len({record.request_id for record in records}) != len(records):
            raise ValueError("scheduler successful review usage repeats a request identity")
        return tuple(sorted(records, key=lambda item: item.request_id))

    @property
    def restorable_review_usage_records(self) -> tuple[UsageRecord, ...]:
        """Return only usage attached to a durably credited successful review result."""

        successful = {
            result.task_id
            for result in self.task_results
            if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
        }
        main_records = tuple(
            UsageRecord.model_validate(output.model_completion_evidence.usage_record.model_dump())
            for output in self._retained_outputs()
            if (
                output.task_id in successful
                and output.model_completion_evidence is not None
                and is_creditable_usage_record(
                    output.model_completion_evidence.usage_record,
                    require_real=True,
                )
            )
        )
        recovery_records = tuple(
            UsageRecord.model_validate(record.model_dump(mode="python"), strict=True)
            for record, (_request_id, request_limit_scope, request_limit_count_before) in (
                self._promoted_typed_recovery_usage()
            )
            if is_recovery_creditable_usage_record(
                record,
                request_limit_scope=request_limit_scope,
                request_limit_count_before=request_limit_count_before,
                require_real=True,
            )
        )
        records = main_records + recovery_records
        if len({record.request_id for record in records}) != len(records):
            raise ValueError("scheduler restorable review usage repeats a request identity")
        return tuple(sorted(records, key=lambda item: item.request_id))

    def claim_restorable_usage_records(self) -> tuple[UsageRecord, ...]:
        """Re-attest exact retained REAL usage once under validated resume custody."""

        self._assert_recovery_custody()
        if self._usage_recovery_scope is None:
            raise ValueError("scheduler journal lacks usage recovery authority")
        recovered = _recover_trusted_usage_records(
            self.restorable_usage_records,
            self._usage_recovery_scope,
        )
        self._usage_recovery_scope = None
        self._usage_recovery_expires_at = None
        return recovered

    def claim_restorable_usage_for_budget_recovery(
        self,
        *,
        atomic_ledger: AtomicCostLedger | None = None,
    ) -> tuple[tuple[UsageRecord, ...], _TrustedBudgetRecoveryScope]:
        """Return exact restored usage plus one-shot scoped-budget recovery authority."""

        recovered_attempts = (
            self.recover_active_cost_reservations(atomic_ledger)
            if atomic_ledger is not None
            else ()
        )
        records = self.claim_restorable_usage_records()
        recovery_roots = self._recovery_budget_request_limit_roots()
        return records, _issue_trusted_budget_recovery_scope(
            records,
            non_usage_attempts=recovered_attempts,
            cost_ledger_baseline=self.manifest.cost_ledger_baseline,
            shared_request_limit_roots=recovery_roots,
        )

    def recover_active_cost_reservations(
        self,
        atomic_ledger: AtomicCostLedger,
    ) -> tuple[SchedulerCostRecoveryRecord, ...]:
        """Conclude campaign-owned durable reservations from exact journal ordering.

        A task whose last durable event is ACTIVATED proves transport was never
        entered, so its exact reservation is adopted for one resumed dispatch.
        A task durably marked DISPATCHED without retained usage is never retried;
        an unknown provider charge is conservatively accounted at the full
        reservation. Retained usage owns its exact attempts and is restored by
        :meth:`claim_restorable_usage_for_budget_recovery` instead.
        """

        self._assert_recovery_custody()
        tasks_by_request = {
            task.logical_request_id: task
            for plan in self.plans
            for task in plan.tasks
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
        }
        activations_by_task = {item.task_id: item for item in self.activations}
        histories = self._events_by_task()
        credited = self._credited_results()
        recovered: list[SchedulerCostRecoveryRecord] = []
        ledger_snapshot = atomic_ledger.snapshot()
        retained_main_records = self._retained_main_provider_usage_records()
        retained_attempt_ids, retained_reconciliations = _retained_main_usage_cost_recovery_plan(
            records=retained_main_records,
            tasks_by_request=tasks_by_request,
            ledger_entries=ledger_snapshot.entries,
        )
        ledger_entries_by_id = {entry.request_id: entry for entry in ledger_snapshot.entries}
        for record in retained_main_records:
            attempt_inventory = atomic_token_reservations_from_usage(record)
            final_entry = ledger_entries_by_id[attempt_inventory[-1].request_id]
            if final_entry.status is not CostEntryStatus.RELEASED:
                continue
            task = tasks_by_request[record.request_id]
            history = histories.get(task.task_id, [])
            terminal_result = credited.get(task.task_id)
            if (
                not history
                or history[-1].kind
                not in {
                    SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
                    SchedulerTaskEventKind.TERMINAL,
                }
                or terminal_result is None
                or terminal_result.terminal_status is not SchedulerTerminalStatus.FAILED
                or terminal_result.terminal_evidence_sha256 != cost_entry_sha256(final_entry)
            ):
                raise ValueError(
                    "retained released provider attempt differs from its exact terminal"
                )
            if history[-1].kind is SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL:
                _require_exact_activation_released_usage(
                    record,
                    logical_request_id=task.logical_request_id,
                    require_runtime_attestation=False,
                )
        grouped_entries: dict[str, list[tuple[int, CostEntry]]] = {}
        for entry in ledger_snapshot.entries:
            if (
                entry.status
                not in {
                    CostEntryStatus.RESERVED,
                    CostEntryStatus.RELEASED,
                    CostEntryStatus.UNCERTAIN_ACCOUNTED,
                }
                or entry.request_id in retained_attempt_ids
            ):
                continue
            identity = _campaign_provider_attempt_identity(
                entry.request_id,
                tasks_by_request,
            )
            if identity is None:
                continue
            logical_request_id, attempt_ordinal = identity
            grouped_entries.setdefault(logical_request_id, []).append((attempt_ordinal, entry))

        validated_groups: list[
            tuple[
                str,
                SchedulerTaskPlan,
                list[tuple[int, CostEntry]],
                SchedulerCostRecoveryStatus,
            ]
        ] = []
        for logical_request_id, raw_entries in sorted(grouped_entries.items()):
            task = tasks_by_request[logical_request_id]
            activation = activations_by_task.get(task.task_id)
            history = histories.get(task.task_id, [])
            if activation is None or not history:
                raise ValueError("active model-cost reservation lacks exact scheduler activation")
            entries = sorted(raw_entries, key=lambda item: item[0])
            ordinals = tuple(ordinal for ordinal, _entry in entries)
            if history[-1].kind is SchedulerTaskEventKind.ACTIVATED and (
                ordinals != (1,) or entries[0][1].request_id != logical_request_id
            ):
                raise ValueError("pre-send retry reservation lacks exact dispatch evidence")
            if ordinals != tuple(range(1, len(ordinals) + 1)):
                raise ValueError("scheduler provider-attempt ordinals are not contiguous")
            terminal_result = credited.get(task.task_id)
            was_dispatched = any(
                event.kind is SchedulerTaskEventKind.DISPATCHED for event in history
            )
            if history[-1].kind is SchedulerTaskEventKind.ACTIVATED:
                if entries[0][1].status is not CostEntryStatus.RESERVED:
                    raise ValueError(
                        "accounted model-cost uncertainty lacks scheduler dispatch evidence"
                    )
                validated_groups.append(
                    (
                        logical_request_id,
                        task,
                        entries,
                        SchedulerCostRecoveryStatus.ADOPTED_PROVEN_PRE_SEND,
                    )
                )
                continue
            if history[-1].kind is SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL:
                if (
                    len(entries) != 1
                    or entries[0][0] != 1
                    or terminal_result is None
                    or terminal_result.terminal_status is not SchedulerTerminalStatus.FAILED
                    or terminal_result.terminal_evidence_sha256 != cost_entry_sha256(entries[0][1])
                ):
                    raise ValueError(
                        "released activated attempt differs from its scheduler terminal"
                    )
                _require_exact_pre_send_release(entries[0][1])
                validated_groups.append(
                    (
                        logical_request_id,
                        task,
                        entries,
                        SchedulerCostRecoveryStatus.RELEASED_PROVEN_PRE_SEND,
                    )
                )
                continue
            if not was_dispatched or terminal_result is None:
                raise ValueError(
                    "active model-cost reservation differs from scheduler dispatch state"
                )
            if terminal_result.terminal_status is SchedulerTerminalStatus.FAILED:
                if (
                    entries[-1][1].status is not CostEntryStatus.RELEASED
                    or terminal_result.terminal_evidence_sha256 != cost_entry_sha256(entries[-1][1])
                    or any(
                        entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
                        for _ordinal, entry in entries[:-1]
                    )
                ):
                    raise ValueError(
                        "released dispatched attempt differs from its scheduler terminal"
                    )
                _require_exact_pre_send_release(entries[-1][1])
                validated_groups.append(
                    (
                        logical_request_id,
                        task,
                        entries,
                        SchedulerCostRecoveryStatus.RELEASED_PROVEN_PRE_SEND,
                    )
                )
                continue
            if terminal_result.terminal_status is not SchedulerTerminalStatus.UNCERTAIN or any(
                entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
                for _ordinal, entry in entries[:-1]
            ):
                raise ValueError("prior retry attempt lacks accounted uncertainty")
            validated_groups.append(
                (
                    logical_request_id,
                    task,
                    entries,
                    SchedulerCostRecoveryStatus.UNCERTAIN_ACCOUNTED_AFTER_DISPATCH,
                )
            )

        recovery_child_groups = _recovery_child_cost_recovery_plan(
            indexes=self._truncation_recovery_indexes,
            ledger_entries=ledger_snapshot.entries,
        )

        for entry, actual_cost in retained_reconciliations:
            self._assert_recovery_custody()
            atomic_ledger.reconcile(entry.as_reservation(), actual_cost)

        for logical_request_id, task, entries, recovery_status in validated_groups:
            for attempt_ordinal, entry in entries:
                if recovery_status is SchedulerCostRecoveryStatus.ADOPTED_PROVEN_PRE_SEND:
                    recovered.append(
                        SchedulerCostRecoveryRecord(
                            request_id=entry.request_id,
                            logical_request_id=logical_request_id,
                            task_id=task.task_id,
                            requested_model=task.requested_model or "",
                            role=task.role,
                            status=(SchedulerCostRecoveryStatus.ADOPTED_PROVEN_PRE_SEND),
                            reserved_cost_usd_exact=entry.reserved_usd,
                            accounted_cost_usd_exact=entry.accounted_cost_usd,
                        )
                    )
                    continue
                if (
                    recovery_status is SchedulerCostRecoveryStatus.RELEASED_PROVEN_PRE_SEND
                    and attempt_ordinal == len(entries)
                ):
                    _require_exact_pre_send_release(entry)
                    recovered.append(
                        SchedulerCostRecoveryRecord(
                            request_id=entry.request_id,
                            logical_request_id=logical_request_id,
                            task_id=task.task_id,
                            requested_model=task.requested_model or "",
                            role=task.role,
                            status=(SchedulerCostRecoveryStatus.RELEASED_PROVEN_PRE_SEND),
                            reserved_cost_usd_exact=entry.reserved_usd,
                            accounted_cost_usd_exact=entry.accounted_cost_usd,
                        )
                    )
                    continue
                if entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED:
                    if (
                        entry.actual_cost_usd is not None
                        or entry.accounted_cost_usd != entry.reserved_usd
                    ):
                        raise ValueError(
                            "accounted model-cost uncertainty differs from scheduler dispatch state"
                        )
                    recovered.append(
                        SchedulerCostRecoveryRecord(
                            request_id=entry.request_id,
                            logical_request_id=logical_request_id,
                            task_id=task.task_id,
                            requested_model=task.requested_model or "",
                            role=task.role,
                            status=(SchedulerCostRecoveryStatus.UNCERTAIN_ACCOUNTED_AFTER_DISPATCH),
                            reserved_cost_usd_exact=entry.reserved_usd,
                            accounted_cost_usd_exact=entry.accounted_cost_usd,
                        )
                    )
                    continue
                self._assert_recovery_custody()
                closed = atomic_ledger.reconcile(entry.as_reservation(), None)
                recovered.append(
                    SchedulerCostRecoveryRecord(
                        request_id=entry.request_id,
                        logical_request_id=logical_request_id,
                        task_id=task.task_id,
                        requested_model=task.requested_model or "",
                        role=task.role,
                        status=(SchedulerCostRecoveryStatus.UNCERTAIN_ACCOUNTED_AFTER_DISPATCH),
                        reserved_cost_usd_exact=closed.reserved_usd,
                        accounted_cost_usd_exact=closed.accounted_cost_usd,
                    )
                )

        for group in recovery_child_groups:
            if group.retained_usage:
                continue
            requested_model = group.activation.requested_model
            request_role = group.activation.request_role
            if requested_model is None or request_role is None:
                raise ValueError("recovery-child activation lacks exact provider identity")
            for attempt_ordinal, entry in group.entries:
                status = group.status
                reserved_cost = entry.reserved_usd
                accounted_cost = entry.accounted_cost_usd
                if status is SchedulerCostRecoveryStatus.RELEASED_PROVEN_PRE_SEND:
                    if attempt_ordinal == len(group.entries):
                        _require_exact_pre_send_release(entry)
                    else:
                        status = SchedulerCostRecoveryStatus.UNCERTAIN_ACCOUNTED_AFTER_DISPATCH
                if status is SchedulerCostRecoveryStatus.UNCERTAIN_ACCOUNTED_AFTER_DISPATCH:
                    if entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED:
                        if (
                            entry.actual_cost_usd is not None
                            or entry.accounted_cost_usd != entry.reserved_usd
                        ):
                            raise ValueError(
                                "accounted recovery-child uncertainty differs from its reservation"
                            )
                    elif entry.status is CostEntryStatus.RESERVED:
                        self._assert_recovery_custody()
                        closed = atomic_ledger.reconcile(entry.as_reservation(), None)
                        reserved_cost = closed.reserved_usd
                        accounted_cost = closed.accounted_cost_usd
                    else:
                        raise ValueError("recovery-child uncertainty differs from its ledger state")
                count_before = (
                    group.activation.request_limit_count_before_child + attempt_ordinal - 1
                )
                recovered.append(
                    SchedulerCostRecoveryRecord(
                        request_id=entry.request_id,
                        logical_request_id=group.child.child_logical_request_id,
                        task_id=group.child.child_task_id,
                        requested_model=requested_model,
                        role=request_role,
                        status=status,
                        reserved_cost_usd_exact=reserved_cost,
                        accounted_cost_usd_exact=accounted_cost,
                        request_limit_scope=group.family.request_limit_id,
                        request_limit_count_before=count_before,
                        request_limit_count_after=count_before + 1,
                        request_limit_maximum=group.activation.request_limit_maximum,
                    )
                )
        self._validate_state()
        return tuple(sorted(recovered, key=lambda item: item.request_id))

    @property
    def restorable_context_request_evidence(self) -> tuple[ContextRequestEvidence, ...]:
        """Return context evidence paired with every retained provider completion."""

        evidence = tuple(
            ContextRequestEvidence.model_validate(
                output.model_completion_evidence.context_request_evidence.model_dump()
            )
            for output in self._retained_outputs()
            if output.model_completion_evidence is not None
        ) + tuple(
            ContextRequestEvidence.model_validate(attempt.context_request_evidence.model_dump())
            for attempt in self._retained_provider_attempts()
        )
        request_ids = tuple(item.request_id for item in evidence)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("scheduler retained context repeats a logical request identity")
        return tuple(sorted(evidence, key=lambda item: item.request_id))

    def seal_terminal_report_authority(
        self,
        *,
        severity_threshold: Severity,
        candidates: Iterable[CandidateFinding],
        final_findings: Iterable[Finding],
        rejected_findings: Iterable[Finding],
        filtered_findings: Iterable[Finding],
        report_quality_review: ReportQualityReview | None,
        verification_decisions: Iterable[VerificationDecision],
        cross_examination_decisions: Iterable[CandidateCrossExaminationDecision],
        falsification_decisions: Iterable[FalsificationDecision],
        reproduction_results: Iterable[ReproductionResult],
        reproduction_resolutions: Iterable[CandidateReproductionResolution],
        consensus_review: ConsensusReviewArtifact | None = None,
    ) -> SchedulerTerminalReportAuthority:
        """Persist the exact terminal report projection once, or verify an exact resume.

        This is intentionally the last writable scheduler transition.  A matching call
        after resume is idempotent; any changed candidate, finding, disposition, quality
        review, or campaign prefix fails before public artifact construction.
        """

        self._assert_live_custody()
        threshold = Severity(severity_threshold)
        authority = SchedulerTerminalReportAuthority.build(
            manifest=self.manifest,
            summary=self.summary,
            severity_threshold=threshold,
            candidates=candidates,
            final_findings=final_findings,
            rejected_findings=rejected_findings,
            filtered_findings=filtered_findings,
            report_quality_review=report_quality_review,
            verification_decisions=verification_decisions,
            cross_examination_decisions=cross_examination_decisions,
            falsification_decisions=falsification_decisions,
            reproduction_results=reproduction_results,
            reproduction_resolutions=reproduction_resolutions,
            consensus_review=consensus_review,
        )
        if self._terminal_report_authority is not None:
            if authority != self._terminal_report_authority:
                raise ValueError(
                    "resumed scheduler terminal report authority differs from durable evidence"
                )
            return _detach_canonical_model(self._terminal_report_authority)
        if self._read_only:
            raise ValueError("scheduler verification journal is read-only")
        if not self.manifest.terminal_report_authority_required:
            raise ValueError("legacy scheduler campaign cannot seal current report authority")
        if not self.manifest.terminal_evidence_authority_required:
            raise ValueError("legacy scheduler campaign cannot seal current evidence authority")

        # Build the complete projected evidence before the fresh-file commit.  This
        # checks pass-seven judgment/report-quality custody and requires every planned
        # task in the (possibly incomplete) pass prefix to have a terminal result.
        SchedulerJournalEvidence.build(
            manifest=self.manifest,
            analysis_input_inventory=self.analysis_input_inventory,
            summary=self.summary,
            plans=self.plans,
            model_requests=self.model_requests,
            activations=self.activations,
            outputs=self._retained_outputs(),
            provider_attempts=self._retained_provider_attempts(),
            task_results=self.task_results,
            result_observations=self.result_observations,
            events=self.events,
            truncation_recovery_entries=self._retained_truncation_recovery_entries(),
            terminal_report_authority=authority,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _TERMINAL_REPORT_AUTHORITY_FILENAME,
            authority,
        )
        self._terminal_report_authority = _detach_canonical_model(authority)
        durable_snapshot = self._validate_state()
        self._adopt_validated_durable_snapshot(durable_snapshot)
        self._refresh_journal_head_checkpoint()
        return authority

    def artifact(self) -> SchedulerArtifact:
        """Build the public scheduler artifact from complete journal evidence."""

        durable_snapshot = self._validate_state()
        summary = self.summary
        model_requests = self.model_requests
        recovery_model_requests = self.recovery_model_requests
        artifact = SchedulerArtifact.build(
            summary=summary,
            journal_evidence=self._build_journal_evidence(
                summary=summary,
                model_requests=model_requests,
            ),
            model_requests=model_requests,
            recovery_model_requests=recovery_model_requests,
        )
        self._require_durable_snapshot(durable_snapshot)
        return artifact

    @property
    def resumable_task_ids(self) -> tuple[str, ...]:
        """Return only tasks persisted as planned and never dispatched."""

        histories = self._events_by_task()
        return tuple(
            sorted(
                task_id
                for task_id, history in histories.items()
                if history[-1].kind
                in {SchedulerTaskEventKind.PLANNED, SchedulerTaskEventKind.ACTIVATED}
            )
        )

    @property
    def activatable_task_ids(self) -> tuple[str, ...]:
        histories = self._events_by_task()
        return tuple(
            sorted(
                task_id
                for task_id, history in histories.items()
                if history[-1].kind is SchedulerTaskEventKind.PLANNED
            )
        )

    @property
    def dispatchable_task_ids(self) -> tuple[str, ...]:
        histories = self._events_by_task()
        return tuple(
            sorted(
                task_id
                for task_id, history in histories.items()
                if history[-1].kind is SchedulerTaskEventKind.ACTIVATED
            )
        )

    @property
    def uncertain_task_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                item.task_id
                for item in self.task_results
                if item.terminal_status is SchedulerTerminalStatus.UNCERTAIN
            )
        )

    def seal_pass_plan(self, plan: SchedulerPassPlan) -> SchedulerPassPlan:
        """Persist the exact next plan before exposing any task for dispatch."""

        self._assert_writable_custody()
        frozen = SchedulerPassPlan.model_validate(plan.model_dump(mode="python"))
        ordinal = len(self._plans)
        if ordinal >= len(SCHEDULER_PASS_ORDER):
            raise ValueError("scheduler already contains all seven pass plans")
        if (
            frozen.manifest != self.manifest
            or frozen.pass_kind is not SCHEDULER_PASS_ORDER[ordinal]
        ):
            raise ValueError("scheduler pass plan differs from its exact campaign order")
        if len(self._pass_results) != ordinal:
            raise ValueError("scheduler cannot plan work before every prior pass terminates")
        if any(item.status is not SchedulerPassStatus.COMPLETE for item in self._pass_results):
            raise ValueError("scheduler cannot advance after a non-complete mandatory pass")
        if frozen.dependencies != self.next_dependencies:
            raise ValueError("scheduler pass plan omits exact prior result dependencies")
        for task in frozen.tasks:
            _require_model_task_privacy_custody(self.manifest, task)

        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _pass_plan_path(ordinal),
            frozen,
        )
        self._retain_plan(frozen)
        # Every PLANNED event is appended only after the complete pass plan is
        # durable.  In particular, no blind shard result can append to its plan.
        for task in frozen.tasks:
            self._append_event(
                plan=frozen,
                task=task,
                kind=SchedulerTaskEventKind.PLANNED,
            )
        self._validate_incremental_state()
        self._refresh_journal_head_checkpoint()
        return frozen

    def mark_dispatched(self, task_id: str) -> SchedulerTaskEvent:
        """Persist dispatch before executing a provider or external side effect."""

        self._assert_writable_custody()
        task, plan = self._task_and_plan(task_id)
        _require_model_task_privacy_custody(self.manifest, task)
        history = self._history_for_task(task_id)
        activation = self._activation_for_task(task_id)
        if len(history) != 2 or history[-1].kind is not SchedulerTaskEventKind.ACTIVATED:
            raise ValueError("only an activated scheduler task may be dispatched")
        event = self._append_event(
            plan=plan,
            task=task,
            kind=SchedulerTaskEventKind.DISPATCHED,
            request_id=task.logical_request_id,
            activation=activation,
        )
        self._refresh_journal_head_checkpoint()
        return event

    def activate_task(
        self,
        task_id: str,
        *,
        actual_input_sha256: str,
        system_prompt_sha256: str | None = None,
        user_prompt_sha256: str | None = None,
        provider_prompt_sha256: str | None = None,
        response_schema_sha256: str | None = None,
        delivered_source_descriptor_sha256s: tuple[str, ...] = (),
        upstream_task_result_sha256s: tuple[str, ...] = (),
    ) -> SchedulerTaskActivation:
        """Persist exact dynamic request material before dispatch can occur."""

        self._assert_writable_custody()
        task, plan = self._task_and_plan(task_id)
        _require_model_task_privacy_custody(self.manifest, task)
        history = self._history_for_task(task_id)
        if len(history) != 1 or history[-1].kind is not SchedulerTaskEventKind.PLANNED:
            raise ValueError("only one never-activated planned task may be activated")
        if task_id in self._indexes.activations:
            raise ValueError("scheduler task already has durable activation evidence")
        activation = SchedulerTaskActivation.build(
            plan=plan,
            task=task,
            actual_input_sha256=actual_input_sha256,
            system_prompt_sha256=system_prompt_sha256,
            user_prompt_sha256=user_prompt_sha256,
            provider_prompt_sha256=provider_prompt_sha256,
            response_schema_sha256=response_schema_sha256,
            delivered_source_descriptor_sha256s=(delivered_source_descriptor_sha256s),
            upstream_task_result_sha256s=upstream_task_result_sha256s,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _activation_path(activation),
            activation,
        )
        self._retain_activation(activation)
        self._append_event(
            plan=plan,
            task=task,
            kind=SchedulerTaskEventKind.ACTIVATED,
            activation=activation,
        )
        self._refresh_journal_head_checkpoint()
        return activation

    def persist_output(
        self,
        task_id: str,
        payload: object,
        *,
        usage_record: UsageRecord | None = None,
        specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
        model_surface_review_requests: Iterable[ModelSurfaceReviewRequest] = (),
        model_surface_review_artifact: ModelSurfaceReviewArtifact | None = None,
        accepted_candidates: Iterable[CandidateFinding] = (),
        normalization_evidence: CandidateReviewNormalizationEvidence | None = None,
    ) -> SchedulerTaskOutput:
        """Persist one private normalized task output before success may be recorded."""

        self._assert_writable_custody()
        task, plan = self._task_and_plan(task_id)
        history = self._history_for_task(task_id)
        if len(history) != 3 or history[-1].kind is not SchedulerTaskEventKind.DISPATCHED:
            raise ValueError("scheduler output requires exact durable dispatch evidence")
        activation = self._activation_for_task(task_id)
        if task_id in self._indexes.outputs:
            raise ValueError("scheduler task already has durable output evidence")
        if task_id in self._indexes.provider_attempts:
            raise ValueError("scheduler task already has non-creditable provider evidence")
        output = SchedulerTaskOutput.build(
            plan=plan,
            task=task,
            activation=activation,
            payload=payload,
            usage_record=usage_record,
            specialist_accepted_outcome=specialist_accepted_outcome,
            model_surface_review_requests=model_surface_review_requests,
            model_surface_review_artifact=model_surface_review_artifact,
            accepted_candidates=accepted_candidates,
            normalization_evidence=normalization_evidence,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _task_output_path(output),
            output,
        )
        self._retain_output(output)
        self._validate_incremental_state(task_id=task_id)
        self._refresh_journal_head_checkpoint()
        return output

    def persist_provider_attempt(
        self,
        task_id: str,
        usage_record: UsageRecord,
    ) -> SchedulerProviderAttemptEvidence:
        """Persist exact failed/invalid paid-attempt evidence without review credit."""

        self._assert_writable_custody()
        task, _plan = self._task_and_plan(task_id)
        history = self._history_for_task(task_id)
        if len(history) != 3 or history[-1].kind is not SchedulerTaskEventKind.DISPATCHED:
            raise ValueError("scheduler provider attempt requires exact durable dispatch")
        if task_id in self._indexes.outputs or task_id in self._indexes.provider_attempts:
            raise ValueError("scheduler task already has retained provider evidence")
        attempt = SchedulerProviderAttemptEvidence.build(
            task=task,
            activation=self._activation_for_task(task_id),
            usage_record=usage_record,
            audit_model_selection=self.manifest.bindings.audit_model_selection,
            audit_model_refresh=self.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=(self.manifest.bindings.audit_model_refresh_pricing),
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _provider_attempt_path(attempt),
            attempt,
        )
        self._retain_provider_attempt(attempt)
        self._validate_incremental_state(task_id=task_id)
        self._refresh_journal_head_checkpoint()
        return attempt

    def record_released_provider_failure(
        self,
        task_id: str,
        *,
        usage_records: Iterable[UsageRecord],
        atomic_ledger: AtomicCostLedger,
    ) -> SchedulerTaskResult | None:
        """Close and retain one live provider failure with an exact released tail.

        A non-RELEASED ledger tail is not this lifecycle shape and returns ``None``.
        Once a RELEASED tail is present, every join is validated before mutation.
        The provider attempt is checkpointed first; interrupted-state recovery can
        then derive the exact cost-hash terminal after a crash between the two writes.
        """

        self._assert_writable_custody()
        baseline = self.manifest.cost_ledger_baseline
        if baseline is None or atomic_ledger.identity_sha256 != baseline.ledger_identity_sha256:
            raise ValueError("released scheduler attempt lacks its trusted cost ledger")
        _validate_cost_ledger_baseline_prefix(baseline, atomic_ledger)
        task, plan = self._task_and_plan(task_id)
        if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("released provider failure requires a model task")
        history = self._history_for_task(task_id)
        if not history or history[-1].kind not in {
            SchedulerTaskEventKind.ACTIVATED,
            SchedulerTaskEventKind.DISPATCHED,
        }:
            raise ValueError("released provider failure lacks a live task lifecycle")
        if (
            task_id in self._indexes.outputs
            or task_id in self._indexes.provider_attempts
            or task_id in self._indexes.result_observations_by_task
        ):
            raise ValueError("released provider failure repeats durable task evidence")

        snapshot = atomic_ledger.snapshot()
        tasks_by_request = {
            candidate.logical_request_id: candidate
            for candidate_plan in self.plans
            for candidate in candidate_plan.tasks
            if candidate.task_kind is SchedulerTaskKind.MODEL_REQUEST
        }
        task_entries = _campaign_entries_for_task(
            task=task,
            tasks_by_request=tasks_by_request,
            ledger_entries=snapshot.entries,
        )
        if not task_entries or task_entries[-1][1].status is not CostEntryStatus.RELEASED:
            return None
        ordinals = tuple(ordinal for ordinal, _entry in task_entries)
        if ordinals != tuple(range(1, len(task_entries) + 1)):
            raise ValueError("released provider failure has a noncontiguous attempt inventory")
        released_entry = task_entries[-1][1]
        _require_exact_pre_send_release(released_entry)

        exact_usage = tuple(
            record for record in usage_records if record.request_id == task.logical_request_id
        )
        if len(exact_usage) != 1:
            raise ValueError("released provider failure lacks one exact UsageRecord")
        usage = exact_usage[0]
        _require_exact_failed_pre_send_usage(usage, require_runtime_attestation=True)
        if history[-1].kind is SchedulerTaskEventKind.ACTIVATED:
            _require_exact_activation_released_usage(
                usage,
                logical_request_id=task.logical_request_id,
                require_runtime_attestation=True,
            )
        retained_ids, _pending = _retained_main_usage_cost_recovery_plan(
            records=(usage,),
            tasks_by_request=tasks_by_request,
            ledger_entries=snapshot.entries,
        )
        expected_ids = frozenset(entry.request_id for _ordinal, entry in task_entries)
        if retained_ids != expected_ids or (
            history[-1].kind is SchedulerTaskEventKind.ACTIVATED
            and (ordinals != (1,) or usage.attempts != 1)
        ):
            raise ValueError("released provider failure differs from its complete task inventory")

        activation = self._activation_for_task(task_id)
        attempt = SchedulerProviderAttemptEvidence.build(
            task=task,
            activation=activation,
            usage_record=usage,
            audit_model_selection=self.manifest.bindings.audit_model_selection,
            audit_model_refresh=self.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=self.manifest.bindings.audit_model_refresh_pricing,
        )
        result = SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=SchedulerTerminalStatus.FAILED,
            terminal_evidence_sha256=cost_entry_sha256(released_entry),
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _provider_attempt_path(attempt),
            attempt,
        )
        self._retain_provider_attempt(attempt)
        self._validate_incremental_state(task_id=task_id)
        self._refresh_journal_head_checkpoint()
        if history[-1].kind is SchedulerTaskEventKind.ACTIVATED:
            self.record_activated_preflight_failure(result)
        else:
            self.record_terminal(result)
        return result

    def persist_truncated_provider_attempt(
        self,
        task_id: str,
        usage_record: UsageRecord,
        *,
        truncated_envelope_evidence: CandidateReviewTruncatedEnvelopeEvidence,
        truncation_projection: CandidateReviewTruncationProjection,
    ) -> SchedulerProviderAttemptEvidence:
        """Persist full raw-free truncation custody before its terminal transition."""

        self._assert_writable_custody()
        task, _plan = self._task_and_plan(task_id)
        history = self._history_for_task(task_id)
        if len(history) != 3 or history[-1].kind is not SchedulerTaskEventKind.DISPATCHED:
            raise ValueError("scheduler truncated attempt requires exact durable dispatch")
        if task_id in self._indexes.outputs or task_id in self._indexes.provider_attempts:
            raise ValueError("scheduler task already has retained provider evidence")
        attempt = SchedulerProviderAttemptEvidence.build_truncated(
            task=task,
            activation=self._activation_for_task(task_id),
            usage_record=usage_record,
            audit_model_selection=self.manifest.bindings.audit_model_selection,
            audit_model_refresh=self.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=self.manifest.bindings.audit_model_refresh_pricing,
            truncated_envelope_evidence=truncated_envelope_evidence,
            truncation_projection=truncation_projection,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _provider_attempt_path(attempt),
            attempt,
        )
        self._retain_provider_attempt(attempt)
        self._validate_incremental_state(task_id=task_id)
        self._refresh_journal_head_checkpoint()
        return attempt

    def load_output(self, task_id: str) -> object:
        """Return a detached normalized JSON reconstruction of one retained output."""

        self._assert_live_custody()
        output = self._output_for_task(task_id)
        return json.loads(
            json.dumps(
                output.payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )

    def reconstruct_output[OutputT: BaseModel](
        self,
        task_id: str,
        output_type: type[OutputT],
    ) -> OutputT:
        """Strictly reconstruct one typed output from retained private JSON."""

        return output_type.model_validate(self.load_output(task_id))

    def record_terminal(self, result: SchedulerTaskResult) -> SchedulerTaskEvent:
        """Persist one exact task result and its terminal lifecycle transition."""

        self._assert_writable_custody()
        frozen = SchedulerTaskResult.model_validate(result.model_dump(mode="python"))
        task, plan = self._task_and_plan(frozen.task_id)
        if frozen.result_origin is not SchedulerResultOrigin.ACTIVATED:
            raise ValueError("activated terminal recording requires an activated result")
        activation = self._activation_for_task(task.task_id)
        output = (
            self._output_for_task(task.task_id)
            if frozen.terminal_status is SchedulerTerminalStatus.SUCCEEDED
            else None
        )
        if output is None and task.task_id in self._indexes.outputs:
            raise ValueError("non-success terminal result contradicts retained task output")
        expected = SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=frozen.terminal_status,
            terminal_evidence_sha256=frozen.terminal_evidence_sha256,
            output=output,
        )
        if frozen != expected:
            raise ValueError("scheduler task result differs from its exact planned identity")
        history = self._history_for_task(task.task_id)
        if len(history) != 3 or history[-1].kind is not SchedulerTaskEventKind.DISPATCHED:
            raise ValueError("scheduler terminal result lacks its exact durable dispatch")
        if task.task_id in self._indexes.result_observations_by_task:
            raise ValueError("scheduler task already has a durable terminal result")

        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _task_result_path(frozen),
            frozen,
        )
        self._retain_result_observation(frozen)
        event = self._append_event(
            plan=plan,
            task=task,
            kind=SchedulerTaskEventKind.TERMINAL,
            request_id=task.logical_request_id,
            activation=activation,
            result=frozen,
        )
        self._refresh_journal_head_checkpoint()
        return event

    def record_preflight_failure(self, result: SchedulerTaskResult) -> SchedulerTaskEvent:
        """Persist a typed fail-closed terminal outcome before activation occurred."""

        self._assert_writable_custody()
        frozen = SchedulerTaskResult.model_validate(result.model_dump(mode="python"))
        task, plan = self._task_and_plan(frozen.task_id)
        if frozen.result_origin is not SchedulerResultOrigin.LOCAL_PREFLIGHT:
            raise ValueError("preflight terminal recording requires a local preflight result")
        expected = SchedulerTaskResult.build_preflight_failure(
            plan=plan,
            task=task,
            terminal_status=frozen.terminal_status,
            terminal_evidence_sha256=frozen.terminal_evidence_sha256,
        )
        if frozen != expected:
            raise ValueError("scheduler preflight result differs from its exact planned identity")
        history = self._history_for_task(task.task_id)
        if len(history) != 1 or history[-1].kind is not SchedulerTaskEventKind.PLANNED:
            raise ValueError("scheduler preflight result must precede activation and dispatch")
        if (
            task.task_id in self._indexes.activations
            or task.task_id in self._indexes.outputs
            or task.task_id in self._indexes.result_observations_by_task
        ):
            raise ValueError("scheduler preflight task already has durable runtime evidence")
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _task_result_path(frozen),
            frozen,
        )
        self._retain_result_observation(frozen)
        event = self._append_event(
            plan=plan,
            task=task,
            kind=SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
            result=frozen,
        )
        self._refresh_journal_head_checkpoint()
        return event

    def record_activated_preflight_failure(
        self,
        result: SchedulerTaskResult,
    ) -> SchedulerTaskEvent:
        """Persist a fail-closed outcome after activation but before dispatch."""

        self._assert_writable_custody()
        frozen = SchedulerTaskResult.model_validate(result.model_dump(mode="python"))
        task, plan = self._task_and_plan(frozen.task_id)
        activation = self._activation_for_task(task.task_id)
        if (
            frozen.result_origin is not SchedulerResultOrigin.ACTIVATED
            or frozen.terminal_status
            not in {
                SchedulerTerminalStatus.FAILED,
                SchedulerTerminalStatus.TRUNCATED,
                SchedulerTerminalStatus.INVALID,
                SchedulerTerminalStatus.UNBOUND,
                SchedulerTerminalStatus.INCONCLUSIVE,
            }
        ):
            raise ValueError("activated preflight terminal recording requires a failure")
        expected = SchedulerTaskResult.build(
            plan=plan,
            task=task,
            activation=activation,
            terminal_status=frozen.terminal_status,
            terminal_evidence_sha256=frozen.terminal_evidence_sha256,
        )
        if frozen != expected:
            raise ValueError(
                "scheduler activated preflight result differs from its exact planned identity"
            )
        history = self._history_for_task(task.task_id)
        if len(history) != 2 or history[-1].kind is not SchedulerTaskEventKind.ACTIVATED:
            raise ValueError("scheduler activated preflight result must precede durable dispatch")
        if (
            task.task_id in self._indexes.outputs
            or task.task_id in self._indexes.result_observations_by_task
        ):
            raise ValueError("scheduler activated preflight task already has terminal evidence")
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _task_result_path(frozen),
            frozen,
        )
        self._retain_result_observation(frozen)
        event = self._append_event(
            plan=plan,
            task=task,
            kind=SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            activation=activation,
            result=frozen,
        )
        self._refresh_journal_head_checkpoint()
        return event

    def seal_pass_result(self, pass_kind: SchedulerPassKind) -> SchedulerPassResult:
        """Derive the exact next pass result from all planned terminal tasks."""

        self._assert_writable_custody()
        ordinal = len(self._pass_results)
        if ordinal >= len(self._plans):
            raise ValueError("scheduler pass result lacks an exact sealed plan")
        plan = self._plans[ordinal]
        if plan.pass_kind is not pass_kind:
            raise ValueError("scheduler pass results must follow exact plan order")
        for task in plan.tasks:
            family_id = self._truncation_recovery_indexes.family_by_parent_task.get(task.task_id)
            if family_id is None:
                continue
            family = self._truncation_recovery_indexes.families[family_id]
            closure = self._truncation_recovery_indexes.closures.get(family_id)
            promotion = self._truncation_recovery_indexes.promotions.get(family_id)
            if closure is None or (
                closure.closure_status is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
                and plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
                and family.truncation_projection.findings_state
                is CandidateReviewChannelState.COMPLETE
                and promotion is None
            ):
                raise ValueError(
                    "scheduler cannot seal a pass with live or promotable recovery work"
                )
        by_task = self._indexes.credited_results
        histories = self._indexes.event_histories
        exact_results: list[SchedulerTaskResult] = []
        for task in plan.tasks:
            result = by_task.get(task.task_id)
            history = histories.get(task.task_id, [])
            lifecycle_is_terminal = result is not None and (
                (
                    result.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT
                    and len(history) == 2
                    and history[-1].kind is SchedulerTaskEventKind.PREFLIGHT_TERMINAL
                )
                or (
                    result.result_origin is SchedulerResultOrigin.ACTIVATED
                    and (
                        (
                            len(history) == 3
                            and history[-1].kind
                            is SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
                        )
                        or (
                            len(history) == 4
                            and history[-1].kind is SchedulerTaskEventKind.TERMINAL
                        )
                    )
                )
            )
            if (
                not lifecycle_is_terminal
                or result is None
                or history[-1].task_result_sha256 != result.result_sha256
            ):
                raise ValueError("scheduler cannot seal a pass with unfinished task evidence")
            exact_results.append(result)
        promotions = tuple(
            SchedulerTruncationRecoveryPromotionBinding.from_promotion(
                self._truncation_recovery_indexes.promotions[family_id]
            )
            for task in plan.tasks
            if (
                family_id := self._truncation_recovery_indexes.promotion_by_parent_task.get(
                    task.task_id
                )
            )
        )
        pass_result = SchedulerPassResult.build(
            plan=plan,
            task_results=exact_results,
            recovery_promotion_bindings=promotions,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _pass_result_path(ordinal),
            pass_result,
        )
        self._retain_pass_result(pass_result)
        self._validate_incremental_state()
        durable_snapshot = self._validate_state()
        self._adopt_validated_durable_snapshot(durable_snapshot)
        self._refresh_journal_head_checkpoint()
        return pass_result

    def require_complete(self) -> SchedulerCampaignSummary:
        durable_snapshot = self._validate_state()
        summary = self.summary
        self._require_durable_snapshot(durable_snapshot)
        if summary.status is not SchedulerCampaignStatus.COMPLETE:
            raise ValueError("scheduler campaign is not complete")
        return summary

    @contextmanager
    def open_privacy_evidence_custody(self) -> Iterator[SchedulerPrivacyEvidenceCustody]:
        """Hold the exact persisted privacy-custody root during downstream validation."""

        self._assert_live_custody()
        with _open_model_observation(
            self._root_descriptor,
            self._directory_descriptors,
            _MANIFEST_FILENAME,
            SchedulerCampaignManifest,
        ) as persisted_manifest:
            if persisted_manifest != self.manifest:
                raise ValueError("scheduler persisted manifest differs from live authority")
            custody = persisted_manifest.privacy_evidence_custody
            if custody is None:
                raise ValueError("scheduler campaign lacks pre-dispatch privacy custody")
            try:
                yield custody
            finally:
                self._assert_live_custody()

    def close(self) -> None:
        """Release live custody without changing durable task state."""

        if self._closed:
            return
        self._usage_recovery_scope = None
        self._usage_recovery_expires_at = None
        self._closed = True
        identity = self._root_identity[:2]
        try:
            fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_descriptor)
            for descriptor in self._directory_descriptors.values():
                os.close(descriptor)
            os.close(self._root_descriptor)
            with _LIVE_CUSTODY_LOCK:
                _LIVE_CUSTODY.discard(identity)

    def _append_event(
        self,
        *,
        plan: SchedulerPassPlan,
        task: SchedulerTaskPlan,
        kind: SchedulerTaskEventKind,
        request_id: str | None = None,
        activation: SchedulerTaskActivation | None = None,
        result: SchedulerTaskResult | None = None,
    ) -> SchedulerTaskEvent:
        self._assert_writable_custody()
        history = self._history_for_task(task.task_id)
        event = SchedulerTaskEvent.build(
            plan=plan,
            task=task,
            kind=kind,
            event_index=len(self._events),
            previous_event=self._events[-1] if self._events else None,
            prior_task_event=history[-1] if history else None,
            request_id=request_id,
            activation=activation,
            result=result,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _event_path(event.event_index),
            event,
        )
        self._retain_event(event)
        self._validate_incremental_state(task_id=task.task_id)
        return event

    def _events_by_task(self) -> dict[str, list[SchedulerTaskEvent]]:
        return {
            task_id: list(history) for task_id, history in self._indexes.event_histories.items()
        }

    def _history_for_task(self, task_id: str) -> list[SchedulerTaskEvent]:
        return self._indexes.event_histories.get(task_id, [])

    def _credited_results(self) -> dict[str, SchedulerTaskResult]:
        return dict(self._indexes.credited_results)

    def _task_and_plan(self, task_id: str) -> tuple[SchedulerTaskPlan, SchedulerPassPlan]:
        match = self._indexes.tasks.get(task_id)
        if match is None:
            raise ValueError("scheduler task identity is absent or ambiguous")
        return match

    def _activation_for_task(self, task_id: str) -> SchedulerTaskActivation:
        activation = self._indexes.activations.get(task_id)
        if activation is None:
            raise ValueError("scheduler task lacks one exact durable activation")
        return activation

    def _output_for_task(self, task_id: str) -> SchedulerTaskOutput:
        output = self._indexes.outputs.get(task_id)
        if output is None:
            raise ValueError("scheduler task lacks one exact durable output")
        return output

    def _retain_plan(self, plan: SchedulerPassPlan) -> None:
        task_ids = tuple(task.task_id for task in plan.tasks)
        if len(task_ids) != len(set(task_ids)) or any(
            task_id in self._indexes.tasks for task_id in task_ids
        ):
            raise ValueError("scheduler task identity is duplicated across pass plans")
        self._plans.append(plan)
        self._indexes.tasks.update((task.task_id, (task, plan)) for task in plan.tasks)

    def _retain_activation(self, activation: SchedulerTaskActivation) -> None:
        task_and_plan = self._indexes.tasks.get(activation.task_id)
        if task_and_plan is None or activation.task_id in self._indexes.activations:
            raise ValueError("scheduler activation is duplicated or unplanned")
        task, plan = task_and_plan
        activation.require_exact_task(plan=plan, task=task)
        self._activations.append(activation)
        self._indexes.activations[activation.task_id] = activation

    def _retain_output(self, output: SchedulerTaskOutput) -> None:
        activation = self._indexes.activations.get(output.task_id)
        if (
            activation is None
            or output.task_id in self._indexes.outputs
            or output.task_id in self._indexes.provider_attempts
        ):
            raise ValueError("scheduler output is duplicated, unactivated, or non-creditable")
        retained = _detach_canonical_model(output)
        retained.require_exact_activation(activation)
        self._outputs.append(retained)
        self._indexes.outputs[retained.task_id] = retained

    def _retain_provider_attempt(self, attempt: SchedulerProviderAttemptEvidence) -> None:
        if (
            attempt.task_id not in self._indexes.tasks
            or attempt.task_id not in self._indexes.activations
            or attempt.task_id in self._indexes.outputs
            or attempt.task_id in self._indexes.provider_attempts
        ):
            raise ValueError(
                "scheduler provider attempt is duplicated, credited, unplanned, or unactivated"
            )
        retained = _detach_canonical_model(attempt)
        self._provider_attempts.append(retained)
        self._indexes.provider_attempts[retained.task_id] = retained

    def _retain_result_observation(self, result: SchedulerTaskResult) -> None:
        observations = self._indexes.result_observations_by_task.get(result.task_id, [])
        prospective = [*observations, result]
        if (
            result.task_id not in self._indexes.tasks
            or result.result_sha256 in self._indexes.results_by_hash
            or len(prospective) > 2
            or (
                len(prospective) == 2
                and (
                    sum(
                        item.terminal_status is SchedulerTerminalStatus.UNCERTAIN
                        for item in prospective
                    )
                    != 1
                    or any(
                        item.result_origin is not SchedulerResultOrigin.ACTIVATED
                        for item in prospective
                    )
                )
            )
        ):
            raise ValueError("scheduler task result is duplicated or ambiguous")
        self._result_observations.append(result)
        self._indexes.results_by_hash[result.result_sha256] = result
        self._indexes.result_observations_by_task.setdefault(result.task_id, []).append(result)

    def _retain_event(self, event: SchedulerTaskEvent) -> None:
        task_and_plan = self._indexes.tasks.get(event.task_id)
        if (
            task_and_plan is None
            or event.event_id in self._indexes.event_ids
            or event.event_index != len(self._events)
        ):
            raise ValueError("scheduler event identity is duplicated, unplanned, or unordered")
        task, plan = task_and_plan
        if (
            event.pass_plan_id != plan.pass_plan_id
            or event.pass_plan_sha256 != plan.pass_plan_sha256
            or event.logical_request_id != task.logical_request_id
        ):
            raise ValueError("scheduler event differs from its exact planned task")
        result: SchedulerTaskResult | None = None
        if event.kind in _TERMINAL_EVENT_KINDS:
            assert event.task_result_sha256 is not None
            result = self._indexes.results_by_hash.get(event.task_result_sha256)
            if (
                result is None
                or result.task_id != event.task_id
                or event.task_id in self._indexes.credited_results
            ):
                raise ValueError("scheduler terminal event has ambiguous result evidence")
        self._events.append(event)
        self._indexes.event_histories.setdefault(event.task_id, []).append(event)
        self._indexes.event_ids.add(event.event_id)
        if result is not None:
            self._indexes.credited_results[event.task_id] = result

    def _retain_pass_result(self, pass_result: SchedulerPassResult) -> None:
        ordinal = len(self._pass_results)
        if ordinal >= len(self._plans) or not _pass_result_binds_plan(
            pass_result,
            self._plans[ordinal],
        ):
            raise ValueError("scheduler pass result differs from its exact plan order")
        self._pass_results.append(_detach_canonical_model(pass_result))

    def _assert_live_custody(self) -> None:
        if self._closed:
            raise ValueError("scheduler journal custody is closed")
        staged_checkpoint_present = bool(
            {
                _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            }
            & set(os.listdir(self._root_descriptor))
        )
        _assert_descriptor_custody(
            path=self.path,
            root_descriptor=self._root_descriptor,
            root_identity=self._root_identity,
            directory_descriptors=self._directory_descriptors,
            directory_identities=self._directory_identities,
            allow_pending_checkpoint=(
                self._pending_checkpoint_recovery or staged_checkpoint_present
            ),
            allowed_immutable_write_temps=self._allowed_immutable_write_temps,
            allowed_published_immutable_targets=(self._allowed_published_immutable_targets),
        )
        if self._journal_head_checkpoint is not None:
            expected_checkpoint = self._journal_head_checkpoint_bytes
            if expected_checkpoint is None:
                raise ValueError("scheduler journal lacks canonical checkpoint bytes")
            persisted_checkpoint = _read_private_file(
                self._root_descriptor,
                _JOURNAL_HEAD_CHECKPOINT_FILENAME,
                allowed_published_identity=(
                    self._allowed_published_immutable_targets.get(_JOURNAL_HEAD_CHECKPOINT_FILENAME)
                ),
            )
            if persisted_checkpoint != expected_checkpoint:
                raise ValueError(
                    "scheduler local journal-head checkpoint differs from retained custody"
                )

    def _assert_writable_custody(self) -> None:
        self._assert_live_custody()
        if self._read_only:
            raise ValueError("scheduler verification journal is read-only")
        if self._terminal_report_authority is not None:
            raise ValueError("scheduler journal is frozen by its terminal report authority")

    def _assert_recovery_custody(self) -> None:
        """Allow one-shot process/accounting recovery without changing sealed journal bytes."""

        self._assert_live_custody()
        if self._read_only:
            raise ValueError("scheduler verification journal is read-only")
        if self.manifest.bindings.audit_model_refresh is not None:
            if self._usage_recovery_scope is None or self._usage_recovery_expires_at is None:
                raise ValueError("scheduler journal lacks live model-refresh recovery authority")
            if _scheduler_wall_clock() >= self._usage_recovery_expires_at:
                raise ValueError("scheduler model-refresh recovery authority is expired")

    def _validate_incremental_state(self, *, task_id: str | None = None) -> None:
        """Validate exact append-local joins; open/final validation still reconstructs all state."""

        self._assert_live_custody()
        if (
            self.analysis_input_inventory.analysis_input_sha256
            != self.manifest.bindings.analysis_input_sha256
            or len(self._indexes.tasks) != sum(len(plan.tasks) for plan in self._plans)
            or len(self._indexes.activations) != len(self._activations)
            or len(self._indexes.outputs) != len(self._outputs)
            or len(self._indexes.provider_attempts) != len(self._provider_attempts)
            or len(self._indexes.results_by_hash) != len(self._result_observations)
            or len(self._indexes.event_ids) != len(self._events)
            or len(self._pass_results) > len(self._plans)
            or len(self._pass_results) < max(0, len(self._plans) - 1)
        ):
            raise ValueError("scheduler incremental indexes differ from retained state")
        if self._events:
            tail = self._events[-1]
            predecessor = self._events[-2] if len(self._events) > 1 else None
            if tail.event_index != len(self._events) - 1 or tail.previous_event_sha256 != (
                predecessor.event_sha256 if predecessor is not None else None
            ):
                raise ValueError("scheduler global event tail is not an exact hash chain")
        if self._pass_results:
            ordinal = len(self._pass_results) - 1
            if not _pass_result_binds_plan(
                self._pass_results[-1],
                self._plans[ordinal],
            ):
                raise ValueError("scheduler pass-result prefix differs from exact plan order")
        if task_id is not None:
            self._validate_incremental_task_state(task_id)
        self._assert_live_custody()

    def _validate_incremental_task_state(self, task_id: str) -> None:
        task_and_plan = self._indexes.tasks.get(task_id)
        history = self._indexes.event_histories.get(task_id, [])
        if task_and_plan is None or not history:
            raise ValueError("scheduler incremental task lacks planned lifecycle evidence")
        task, plan = task_and_plan
        kinds = tuple(event.kind for event in history)
        if kinds not in _VALID_TASK_LIFECYCLE_PREFIXES:
            raise ValueError("scheduler task lifecycle is not a strict transition prefix")
        prior: SchedulerTaskEvent | None = None
        for task_event_index, event in enumerate(history):
            if (
                event.task_id != task_id
                or event.task_event_index != task_event_index
                or event.prior_task_event_sha256
                != (prior.event_sha256 if prior is not None else None)
                or event.pass_plan_id != plan.pass_plan_id
                or event.pass_plan_sha256 != plan.pass_plan_sha256
                or event.logical_request_id != task.logical_request_id
                or event.event_index >= len(self._events)
                or self._events[event.event_index] != event
            ):
                raise ValueError("scheduler task event differs from its exact indexed chain")
            prior = event

        activation = self._indexes.activations.get(task_id)
        output = self._indexes.outputs.get(task_id)
        provider_attempt = self._indexes.provider_attempts.get(task_id)
        observations = self._indexes.result_observations_by_task.get(task_id, [])
        credited = self._indexes.credited_results.get(task_id)
        if activation is not None:
            activation.require_exact_task(plan=plan, task=task)
        if output is not None and activation is not None:
            output.require_exact_activation(activation)
        if output is not None and provider_attempt is not None:
            raise ValueError("scheduler task has contradictory provider evidence")
        if len(observations) > 2 or (
            len(observations) == 2
            and (
                sum(
                    item.terminal_status is SchedulerTerminalStatus.UNCERTAIN
                    for item in observations
                )
                != 1
                or any(
                    item.result_origin is not SchedulerResultOrigin.ACTIVATED
                    for item in observations
                )
            )
        ):
            raise ValueError("scheduler task has ambiguous retained result observations")

        terminal = kinds[-1] in _TERMINAL_EVENT_KINDS
        if terminal and (
            credited is None or history[-1].task_result_sha256 != credited.result_sha256
        ):
            raise ValueError("scheduler terminal event lacks its exact indexed result")
        if not terminal and credited is not None:
            raise ValueError("scheduler non-terminal lifecycle has a credited result")
        if kinds[-1] is SchedulerTaskEventKind.PLANNED:
            if activation is not None or output is not None or provider_attempt is not None:
                raise ValueError("scheduler planned task has contradictory runtime evidence")
        elif kinds[-1] is not SchedulerTaskEventKind.PREFLIGHT_TERMINAL and activation is None:
            raise ValueError("scheduler activated lifecycle lacks exact activation evidence")
        if output is not None and kinds[-1] not in {
            SchedulerTaskEventKind.DISPATCHED,
            SchedulerTaskEventKind.TERMINAL,
        }:
            raise ValueError("scheduler output lacks a dispatched lifecycle")
        if provider_attempt is not None and SchedulerTaskEventKind.DISPATCHED not in kinds:
            credited_result = self._indexes.credited_results.get(task_id)
            if (
                kinds[-1]
                not in {
                    SchedulerTaskEventKind.ACTIVATED,
                    SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
                }
                or (kinds[-1] is SchedulerTaskEventKind.ACTIVATED and credited_result is not None)
                or (
                    kinds[-1] is SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
                    and (
                        credited_result is None
                        or credited_result.terminal_status is not SchedulerTerminalStatus.FAILED
                    )
                )
            ):
                raise ValueError("scheduler provider attempt lacks a dispatched lifecycle")
            _require_exact_activation_released_usage(
                provider_attempt.usage_record,
                logical_request_id=task.logical_request_id,
                require_runtime_attestation=False,
            )

    def _observe_retained_durable_artifacts(
        self,
    ) -> tuple[_DurableArtifactObservation, ...]:
        retained_child_paths = _retained_child_artifact_paths(
            plans=self.plans,
            activations=self.activations,
            events=self.events,
            outputs=self._retained_outputs(),
            provider_attempts=self._retained_provider_attempts(),
            result_observations=self.result_observations,
            pass_results=self._retained_pass_results(),
            truncation_recovery_entries=self._retained_truncation_recovery_entries(),
        )
        return _observe_durable_artifacts(
            root_descriptor=self._root_descriptor,
            directory_descriptors=self._directory_descriptors,
            relative_paths=(
                _MANIFEST_FILENAME,
                _ANALYSIS_INPUT_INVENTORY_FILENAME,
                *(
                    (_TERMINAL_REPORT_AUTHORITY_FILENAME,)
                    if self._terminal_report_authority is not None
                    else ()
                ),
                *retained_child_paths,
            ),
            allowed_published_immutable_targets=(self._allowed_published_immutable_targets),
        )

    def _require_durable_snapshot(
        self,
        expected: tuple[_DurableArtifactObservation, ...],
    ) -> None:
        if self._observe_retained_durable_artifacts() != expected:
            raise ValueError("scheduler durable evidence changed during validated projection")
        self._assert_live_custody()

    def _validate_state(self) -> tuple[_DurableArtifactObservation, ...]:
        self._assert_live_custody()
        before_reconstruction = self._observe_retained_durable_artifacts()
        persisted_manifest = _read_model(
            self._root_descriptor,
            self._directory_descriptors,
            _MANIFEST_FILENAME,
            SchedulerCampaignManifest,
            allowed_published_immutable_targets=(self._allowed_published_immutable_targets),
        )
        persisted_analysis_inputs = _read_model(
            self._root_descriptor,
            self._directory_descriptors,
            _ANALYSIS_INPUT_INVENTORY_FILENAME,
            SchedulerAnalysisInputInventory,
            allowed_published_immutable_targets=(self._allowed_published_immutable_targets),
        )
        if persisted_manifest != self.manifest:
            raise ValueError("scheduler persisted manifest differs from retained authority")
        if persisted_analysis_inputs != self.analysis_input_inventory:
            raise ValueError("scheduler persisted analysis inputs differ from retained authority")
        if (
            persisted_analysis_inputs.analysis_input_sha256
            != persisted_manifest.bindings.analysis_input_sha256
        ):
            raise ValueError("scheduler analysis-input inventory differs from campaign bindings")

        staged_checkpoint_present = bool(
            {
                _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            }
            & set(os.listdir(self._root_descriptor))
        )
        durable_state = _load_state(
            self._root_descriptor,
            self._directory_descriptors,
            persisted_manifest,
            allow_pending_checkpoint=(
                self._pending_checkpoint_recovery or staged_checkpoint_present
            ),
            allowed_immutable_write_temps=self._allowed_immutable_write_temps,
            allowed_published_immutable_targets=(self._allowed_published_immutable_targets),
        )
        retained_state = (
            self.plans,
            self.activations,
            self.events,
            self._retained_outputs(),
            self._retained_provider_attempts(),
            self.result_observations,
            self._retained_pass_results(),
            self._retained_truncation_recovery_entries(),
            self._terminal_report_authority,
        )
        if durable_state != retained_state:
            raise ValueError("scheduler retained state differs from durable journal evidence")
        after_reconstruction = self._observe_retained_durable_artifacts()
        if before_reconstruction != after_reconstruction:
            raise ValueError("scheduler durable evidence changed during full reconstruction")
        expected_indexes = _derive_scheduler_journal_indexes(
            plans=durable_state[0],
            activations=durable_state[1],
            outputs=durable_state[3],
            provider_attempts=durable_state[4],
            result_observations=durable_state[5],
            events=durable_state[2],
        )
        if self._indexes != expected_indexes:
            raise ValueError("scheduler in-memory indexes differ from full reconstruction")
        expected_recovery_indexes = _derive_truncation_recovery_indexes(
            entries=durable_state[7],
            scheduler=expected_indexes,
            manifest=persisted_manifest,
        )
        if self._truncation_recovery_indexes != expected_recovery_indexes:
            raise ValueError("scheduler recovery indexes differ from full reconstruction")
        if self._terminal_report_authority is not None:
            self._build_journal_evidence(
                summary=self.summary,
                model_requests=self.model_requests,
            )
        self._assert_live_custody()
        return after_reconstruction


def _scheduler_wall_clock() -> datetime:
    """Return the production wall clock used immediately before journal mutation."""

    return datetime.now(UTC).replace(microsecond=0)


def _scheduler_recovery_expires_at(bindings: SchedulerBindings) -> datetime | None:
    """Return the earliest durable deadline already proven by live resume authority."""

    refresh = bindings.audit_model_refresh
    if refresh is None:
        return None
    pricing = bindings.audit_model_refresh_pricing
    return min(
        refresh.expires_at,
        pricing.expires_at if pricing is not None else refresh.expires_at,
    )


def _validate_live_scheduler_model_refresh(
    *,
    bindings: SchedulerBindings,
    audit_model_refresh_evidence: AuditModelRefreshEvidence | None,
    audit_model_refresh_guard: VerifiedAuditModelRefreshGuard | None,
    audit_model_refresh_pricing_evidence: AuditModelRefreshPricingEvidence | None,
    audit_model_refresh_pricing_authority: VerifiedAuditModelRefreshPricingAuthority | None,
    production_qualification: VerifiedProductionQualification | None,
    audit_model_selection: VerifiedAuditModelSelection | None,
) -> tuple[bool, bool]:
    """Validate atomic live refresh and pricing authority at the mutation boundary."""

    from mmaudit.models.policy_selection import VerifiedAuditModelSelection
    from mmaudit.models.qualification import VerifiedProductionQualification
    from mmaudit.models.refresh_runtime import (
        AuditModelRefreshEvidence,
        AuditModelRefreshPricingEvidence,
        VerifiedAuditModelRefreshGuard,
        VerifiedAuditModelRefreshPricingAuthority,
    )

    pair_present = (
        audit_model_refresh_evidence is not None and audit_model_refresh_guard is not None
    )
    if (audit_model_refresh_evidence is None) != (audit_model_refresh_guard is None):
        raise ValueError("scheduler model-refresh live authority must be one exact atomic pair")
    if bindings.audit_model_refresh is None:
        if pair_present:
            raise ValueError("scheduler live model-refresh authority lacks a campaign binding")
        if (
            audit_model_refresh_pricing_evidence is not None
            or audit_model_refresh_pricing_authority is not None
            or bindings.audit_model_refresh_pricing is not None
        ):
            raise ValueError("scheduler refresh pricing lacks exact refresh campaign custody")
        return False, False
    if not pair_present:
        if (
            audit_model_refresh_pricing_evidence is not None
            or audit_model_refresh_pricing_authority is not None
        ):
            raise ValueError("scheduler refresh pricing requires the exact live refresh pair")
        return False, False
    if (
        type(audit_model_refresh_evidence) is not AuditModelRefreshEvidence
        or type(audit_model_refresh_guard) is not VerifiedAuditModelRefreshGuard
        or type(production_qualification) is not VerifiedProductionQualification
        or type(audit_model_selection) is not VerifiedAuditModelSelection
    ):
        raise ValueError("scheduler model-refresh live authority is absent or forged")
    assert audit_model_refresh_evidence is not None
    assert audit_model_refresh_guard is not None
    assert production_qualification is not None
    assert audit_model_selection is not None
    canonical = AuditModelRefreshEvidence.model_validate_json(
        audit_model_refresh_evidence.model_dump_json(),
        strict=True,
    )
    projected = SchedulerAuditModelRefreshBinding.from_evidence(canonical)
    if bindings.audit_model_refresh != projected:
        raise ValueError("scheduler model-refresh evidence differs from campaign bindings")
    now = _scheduler_wall_clock()
    audit_model_refresh_guard.require_current(
        now=now,
        expected_workflow_status_sha256=canonical.expected_workflow_status_sha256,
        technical_qualification=production_qualification,
        audit_selection=audit_model_selection,
        expected_audit_scope_sha256=canonical.audit_scope_sha256,
        expected_source_sha256=canonical.source_sha256,
        expected_audit_context_sha256=canonical.audit_context_sha256,
        expected_client_constraints_sha256=canonical.client_constraints_sha256,
    )
    if (
        projected.guard_capability_sha256 != audit_model_refresh_guard.capability_sha256
        or audit_model_refresh_guard.evidence_sha256 != canonical.evidence_sha256
        or audit_model_refresh_guard.workflow_status_sha256 != canonical.workflow_status_sha256
        or audit_model_refresh_guard.snapshot_sha256 != canonical.snapshot_sha256
        or audit_model_refresh_guard.technical_qualification_capability_sha256
        != canonical.technical_qualification_capability_sha256
        or audit_model_refresh_guard.technical_production_selection_sha256
        != canonical.technical_production_selection_sha256
        or audit_model_refresh_guard.audit_selection_capability_sha256
        != canonical.audit_selection_capability_sha256
        or audit_model_refresh_guard.audit_selection_sha256 != canonical.audit_selection_sha256
        or audit_model_refresh_guard.refresh_current_through != canonical.refresh_current_through
        or audit_model_refresh_guard.expires_at != canonical.expires_at
    ):
        raise ValueError("scheduler live model-refresh guard differs from canonical evidence")
    pricing_pair_present = (
        audit_model_refresh_pricing_evidence is not None
        and audit_model_refresh_pricing_authority is not None
    )
    if (audit_model_refresh_pricing_evidence is None) != (
        audit_model_refresh_pricing_authority is None
    ):
        raise ValueError("scheduler refresh pricing authority must be one exact atomic pair")
    if bindings.audit_model_refresh_pricing is None:
        if pricing_pair_present:
            raise ValueError("scheduler live refresh pricing lacks a campaign binding")
        return True, False
    if not pricing_pair_present:
        return True, False
    if (
        type(audit_model_refresh_pricing_evidence) is not AuditModelRefreshPricingEvidence
        or type(audit_model_refresh_pricing_authority)
        is not VerifiedAuditModelRefreshPricingAuthority
    ):
        raise ValueError("scheduler refresh pricing authority is absent or forged")
    assert audit_model_refresh_pricing_evidence is not None
    assert audit_model_refresh_pricing_authority is not None
    canonical_pricing = AuditModelRefreshPricingEvidence.model_validate_json(
        audit_model_refresh_pricing_evidence.model_dump_json(),
        strict=True,
    )
    projected_pricing = SchedulerAuditModelRefreshPricingBinding.from_evidence(canonical_pricing)
    if bindings.audit_model_refresh_pricing != projected_pricing:
        raise ValueError("scheduler refresh pricing differs from campaign bindings")
    audit_model_refresh_pricing_authority.require_current(
        now=now,
        expected_workflow_status_sha256=canonical_pricing.expected_workflow_status_sha256,
        refresh_evidence=canonical,
        refresh_guard=audit_model_refresh_guard,
        technical_qualification=production_qualification,
        audit_selection=audit_model_selection,
        expected_audit_scope_sha256=canonical_pricing.audit_scope_sha256,
        expected_source_sha256=canonical_pricing.source_sha256,
        expected_audit_context_sha256=canonical_pricing.audit_context_sha256,
        expected_client_constraints_sha256=canonical_pricing.client_constraints_sha256,
    )
    if (
        projected_pricing.pricing_authority_capability_sha256
        != audit_model_refresh_pricing_authority.capability_sha256
        or audit_model_refresh_pricing_authority.pricing_evidence_sha256
        != canonical_pricing.evidence_sha256
        or audit_model_refresh_pricing_authority.refresh_evidence_sha256
        != canonical.evidence_sha256
        or audit_model_refresh_pricing_authority.refresh_guard_capability_sha256
        != audit_model_refresh_guard.capability_sha256
        or audit_model_refresh_pricing_authority.expires_at != canonical_pricing.expires_at
    ):
        raise ValueError("scheduler live refresh pricing differs from canonical evidence")
    return True, True


def create_scheduler_journal(
    path: Path,
    *,
    bindings: SchedulerBindings,
    analysis_input_inventory: SchedulerAnalysisInputInventory,
    shard_inventory: SchedulerShardInventory,
    cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
    privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None,
    require_terminal_report_authority: bool = False,
    audit_model_refresh_evidence: AuditModelRefreshEvidence | None = None,
    audit_model_refresh_guard: VerifiedAuditModelRefreshGuard | None = None,
    audit_model_refresh_pricing_evidence: AuditModelRefreshPricingEvidence | None = None,
    audit_model_refresh_pricing_authority: VerifiedAuditModelRefreshPricingAuthority | None = None,
    production_qualification: VerifiedProductionQualification | None = None,
    audit_model_selection: VerifiedAuditModelSelection | None = None,
) -> SchedulerJournal:
    """Create one fresh private journal and persist its manifest before work."""

    refresh_authorized, pricing_authorized = _validate_live_scheduler_model_refresh(
        bindings=bindings,
        audit_model_refresh_evidence=audit_model_refresh_evidence,
        audit_model_refresh_guard=audit_model_refresh_guard,
        audit_model_refresh_pricing_evidence=audit_model_refresh_pricing_evidence,
        audit_model_refresh_pricing_authority=audit_model_refresh_pricing_authority,
        production_qualification=production_qualification,
        audit_model_selection=audit_model_selection,
    )
    if (
        bindings.audit_model_refresh is not None
        and require_terminal_report_authority
        and not refresh_authorized
    ):
        raise ValueError("refresh-bound production journal requires live model-refresh authority")
    if bindings.audit_model_refresh_pricing is not None and not pricing_authorized:
        raise ValueError("pricing-bound production journal requires live pricing authority")

    validated_analysis_inputs = SchedulerAnalysisInputInventory.model_validate(
        analysis_input_inventory.model_dump(mode="python")
    )
    if validated_analysis_inputs.analysis_input_sha256 != bindings.analysis_input_sha256:
        raise ValueError("scheduler analysis-input inventory differs from campaign bindings")
    manifest = SchedulerCampaignManifest.build(
        bindings=bindings,
        shard_inventory=shard_inventory,
        cost_ledger_baseline=cost_ledger_baseline,
        privacy_evidence_custody=privacy_evidence_custody,
        require_terminal_report_authority=require_terminal_report_authority,
    )
    absolute = Path(os.path.abspath(path))
    _create_private_root(absolute)
    root_descriptor = -1
    lock_descriptor = -1
    directory_descriptors: dict[str, int] = {}
    directory_identities: dict[str, tuple[int, int, int]] = {}
    registered = False
    root_identity: tuple[int, int, int] | None = None
    try:
        root_descriptor, root_identity = _open_private_root(absolute)
        _register_live_custody(root_identity[:2])
        registered = True
        lock_descriptor = _acquire_custody_lock(root_descriptor, create=True)
        _assert_root_path_identity(absolute, root_descriptor, root_identity)
        directory_descriptors, directory_identities = _open_control_directories(
            root_descriptor,
            create=True,
        )
        _write_model(
            root_descriptor,
            directory_descriptors,
            _MANIFEST_FILENAME,
            manifest,
        )
        _write_model(
            root_descriptor,
            directory_descriptors,
            _ANALYSIS_INPUT_INVENTORY_FILENAME,
            validated_analysis_inputs,
        )
        journal = SchedulerJournal(
            path=absolute,
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            directory_descriptors=directory_descriptors,
            directory_identities=directory_identities,
            lock_descriptor=lock_descriptor,
            manifest=manifest,
            analysis_input_inventory=validated_analysis_inputs,
            plans=(),
            activations=(),
            events=(),
            outputs=(),
            provider_attempts=(),
            result_observations=(),
            pass_results=(),
            terminal_report_authority=None,
        )
        journal._initialize_journal_head_checkpoint()
        durable_snapshot = journal._validate_state()
        journal._adopt_validated_durable_snapshot(durable_snapshot)
        if (
            manifest.cost_ledger_baseline is not None
            and (manifest.bindings.audit_model_refresh is None or refresh_authorized)
            and (
                manifest.bindings.audit_model_refresh is None
                or (
                    manifest.bindings.audit_model_refresh_pricing is not None and pricing_authorized
                )
            )
        ):
            journal._usage_recovery_scope = _issue_trusted_usage_recovery_scope(())
            journal._usage_recovery_expires_at = _scheduler_recovery_expires_at(manifest.bindings)
        return journal
    except BaseException:
        _release_failed_open(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            lock_descriptor=lock_descriptor,
            directory_descriptors=directory_descriptors,
            registered=registered,
        )
        raise


def resume_scheduler_journal(
    path: Path,
    *,
    expected_bindings: SchedulerBindings,
    expected_analysis_input_inventory: SchedulerAnalysisInputInventory,
    expected_shard_inventory: SchedulerShardInventory,
    expected_cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
    atomic_ledger: AtomicCostLedger | None = None,
    expected_terminal_report_authority_required: bool = False,
    audit_model_refresh_evidence: AuditModelRefreshEvidence | None = None,
    audit_model_refresh_guard: VerifiedAuditModelRefreshGuard | None = None,
    audit_model_refresh_pricing_evidence: AuditModelRefreshPricingEvidence | None = None,
    audit_model_refresh_pricing_authority: VerifiedAuditModelRefreshPricingAuthority | None = None,
    production_qualification: VerifiedProductionQualification | None = None,
    audit_model_selection: VerifiedAuditModelSelection | None = None,
    expected_journal_evidence: SchedulerJournalEvidence | None = None,
) -> SchedulerJournal:
    """Resume only an exact-bound campaign, classifying interrupted dispatches."""

    refresh_authorized, pricing_authorized = _validate_live_scheduler_model_refresh(
        bindings=expected_bindings,
        audit_model_refresh_evidence=audit_model_refresh_evidence,
        audit_model_refresh_guard=audit_model_refresh_guard,
        audit_model_refresh_pricing_evidence=audit_model_refresh_pricing_evidence,
        audit_model_refresh_pricing_authority=audit_model_refresh_pricing_authority,
        production_qualification=production_qualification,
        audit_model_selection=audit_model_selection,
    )
    if expected_bindings.audit_model_refresh is not None and not refresh_authorized:
        raise ValueError("refresh-bound journal resume requires live model-refresh authority")
    if expected_bindings.audit_model_refresh_pricing is not None and not pricing_authorized:
        raise ValueError("pricing-bound journal resume requires live pricing authority")
    try:
        validated_expected_bindings = SchedulerBindings.model_validate(
            expected_bindings.model_dump(mode="python")
        )
        validated_expected_inventory = SchedulerShardInventory.model_validate(
            expected_shard_inventory.model_dump(mode="python")
        )
        validated_expected_analysis_inputs = SchedulerAnalysisInputInventory.model_validate(
            expected_analysis_input_inventory.model_dump(mode="python")
        )
    except ValueError:
        raise ValueError("scheduler resume bindings or shard inventory do not match") from None
    absolute = Path(os.path.abspath(path))
    root_descriptor, root_identity = _open_private_root(absolute)
    lock_descriptor = -1
    directory_descriptors: dict[str, int] = {}
    directory_identities: dict[str, tuple[int, int, int]] = {}
    registered = False
    try:
        _register_live_custody(root_identity[:2])
        registered = True
        lock_descriptor = _acquire_custody_lock(root_descriptor, create=False)
        _assert_root_path_identity(absolute, root_descriptor, root_identity)
        directory_descriptors, directory_identities = _open_control_directories(
            root_descriptor,
            create=False,
        )
        orphan_immutable_writes = _inspect_orphan_immutable_writes(
            root_descriptor,
            directory_descriptors,
        )
        allowed_immutable_write_temps = frozenset(
            item.relative_path for item in orphan_immutable_writes
        )
        allowed_published_immutable_targets = {
            item.relative_target_path: item.identity
            for item in orphan_immutable_writes
            if item.published_target
        }
        pending_checkpoint_present = _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME in set(
            os.listdir(root_descriptor)
        )
        transition_predecessor_present = _JOURNAL_TRANSITION_PREDECESSOR_FILENAME in set(
            os.listdir(root_descriptor)
        )
        checkpoint_recovery_present = (
            pending_checkpoint_present
            or transition_predecessor_present
            or any(
                item.parent is None
                and item.target_leaf
                in {
                    _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
                    _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
                }
                for item in orphan_immutable_writes
            )
        )
        _validate_control_layout(
            root_descriptor,
            directory_descriptors,
            directory_identities,
            allow_pending_checkpoint=checkpoint_recovery_present,
            allowed_immutable_write_temps=allowed_immutable_write_temps,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        manifest = _read_model(
            root_descriptor,
            directory_descriptors,
            _MANIFEST_FILENAME,
            SchedulerCampaignManifest,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        analysis_input_inventory = _read_model(
            root_descriptor,
            directory_descriptors,
            _ANALYSIS_INPUT_INVENTORY_FILENAME,
            SchedulerAnalysisInputInventory,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        drift_labels = _analysis_input_inventory_drift_labels(
            validated_expected_analysis_inputs,
            analysis_input_inventory,
        )
        if drift_labels:
            raise ValueError(
                "scheduler analysis-input inventory differs at labels: " + ", ".join(drift_labels)
            )
        if (
            manifest.shard_inventory != validated_expected_inventory
            or analysis_input_inventory.analysis_input_sha256
            != manifest.bindings.analysis_input_sha256
            or _bindings_without_cost_baseline(manifest.bindings)
            != _bindings_without_cost_baseline(validated_expected_bindings)
            or manifest.terminal_report_authority_required
            is not expected_terminal_report_authority_required
            or (
                expected_terminal_report_authority_required
                and not manifest.terminal_evidence_authority_required
            )
            or (
                validated_expected_bindings.cost_ledger_baseline_sha256
                not in {
                    ABSENT_COST_LEDGER_BASELINE_SHA256,
                    manifest.bindings.cost_ledger_baseline_sha256,
                }
            )
        ):
            raise ValueError("scheduler resume bindings or shard inventory do not match")
        if expected_cost_ledger_baseline is not None:
            expected_manifest = SchedulerCampaignManifest.build(
                bindings=manifest.bindings,
                shard_inventory=validated_expected_inventory,
                cost_ledger_baseline=expected_cost_ledger_baseline,
                privacy_evidence_custody=manifest.privacy_evidence_custody,
                require_terminal_report_authority=(expected_terminal_report_authority_required),
            )
            if manifest != expected_manifest:
                raise ValueError("scheduler resume cost-ledger baseline does not match")
        if manifest.cost_ledger_baseline is not None:
            if atomic_ledger is None:
                raise ValueError("scheduler resume requires its exact persistent cost ledger")
            _validate_cost_ledger_baseline_prefix(
                manifest.cost_ledger_baseline,
                atomic_ledger,
            )
        (
            plans,
            activations,
            events,
            outputs,
            provider_attempts,
            result_observations,
            pass_results,
            truncation_recovery_entries,
            terminal_report_authority,
        ) = _load_state(
            root_descriptor,
            directory_descriptors,
            manifest,
            allow_pending_checkpoint=checkpoint_recovery_present,
            allowed_immutable_write_temps=allowed_immutable_write_temps,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        journal_head_checkpoint = _read_model(
            root_descriptor,
            directory_descriptors,
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
            SchedulerJournalEvidence,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        pending_journal_head_checkpoint = (
            _read_model(
                root_descriptor,
                directory_descriptors,
                _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
                SchedulerJournalEvidence,
                allowed_published_immutable_targets=allowed_published_immutable_targets,
            )
            if pending_checkpoint_present
            else None
        )
        transition_predecessor_checkpoint = (
            _read_model(
                root_descriptor,
                directory_descriptors,
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
                SchedulerJournalEvidence,
                allowed_published_immutable_targets=allowed_published_immutable_targets,
            )
            if transition_predecessor_present
            else None
        )
        journal = SchedulerJournal(
            path=absolute,
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            directory_descriptors=directory_descriptors,
            directory_identities=directory_identities,
            lock_descriptor=lock_descriptor,
            manifest=manifest,
            analysis_input_inventory=analysis_input_inventory,
            plans=plans,
            activations=activations,
            events=events,
            outputs=outputs,
            provider_attempts=provider_attempts,
            result_observations=result_observations,
            pass_results=pass_results,
            truncation_recovery_entries=truncation_recovery_entries,
            terminal_report_authority=terminal_report_authority,
            journal_head_checkpoint=journal_head_checkpoint,
            pending_checkpoint_recovery=checkpoint_recovery_present,
            allowed_immutable_write_temps=allowed_immutable_write_temps,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        durable_snapshot = journal._validate_state()
        journal._adopt_validated_durable_snapshot(durable_snapshot)
        comparison_checkpoint = transition_predecessor_checkpoint or journal_head_checkpoint
        if pending_journal_head_checkpoint is not None:
            observed_journal_evidence = journal._require_checkpoint_or_staged_released_attempt(
                atomic_ledger=atomic_ledger,
                expected_checkpoint=comparison_checkpoint,
            )
            if pending_journal_head_checkpoint != journal.journal_evidence:
                raise ValueError("scheduler pending journal checkpoint differs from durable state")
        else:
            observed_journal_evidence = journal._require_checkpoint_or_staged_released_attempt(
                atomic_ledger=atomic_ledger,
                expected_checkpoint=comparison_checkpoint,
            )
        if (
            transition_predecessor_checkpoint is not None
            and transition_predecessor_checkpoint != journal_head_checkpoint
            and journal_head_checkpoint != journal.journal_evidence
        ):
            raise ValueError("scheduler checkpoint and transition predecessor do not join")
        if (
            expected_journal_evidence is not None
            and SchedulerJournalEvidence.model_validate(
                expected_journal_evidence.model_dump(mode="python")
            )
            != observed_journal_evidence
        ):
            raise ValueError("scheduler resume journal evidence does not match")
        _finalize_published_immutable_writes(
            root_descriptor,
            directory_descriptors,
            orphan_immutable_writes,
        )
        _cleanup_orphan_immutable_writes(
            root_descriptor,
            directory_descriptors,
            tuple(item for item in orphan_immutable_writes if not item.published_target),
        )
        journal._allowed_immutable_write_temps = frozenset()
        journal._allowed_published_immutable_targets = {}
        _validate_control_layout(
            root_descriptor,
            directory_descriptors,
            directory_identities,
            allow_pending_checkpoint=checkpoint_recovery_present,
        )
        durable_snapshot = journal._validate_state()
        journal._adopt_validated_durable_snapshot(durable_snapshot)
        if pending_journal_head_checkpoint is not None:
            journal._adopt_staged_journal_head_checkpoint(
                pending_journal_head_checkpoint,
            )
        if transition_predecessor_checkpoint is not None:
            try:
                complete_evidence = journal.journal_evidence
            except (TypeError, ValueError):
                # One multi-file mutator may still need its deterministic recovery
                # suffix (for example the PLANNED events following a sealed plan).
                complete_evidence = None
            if journal.local_journal_head_checkpoint == complete_evidence:
                _unlink_exact_private_file(
                    root_descriptor,
                    _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
                    stable_json(transition_predecessor_checkpoint).encode("utf-8"),
                )
                journal._pending_checkpoint_recovery = False
        _recover_interrupted_state(journal, atomic_ledger=atomic_ledger)
        durable_snapshot = journal._validate_state()
        journal._adopt_validated_durable_snapshot(durable_snapshot)
        journal._refresh_journal_head_checkpoint()
        if (manifest.bindings.audit_model_refresh is None or refresh_authorized) and (
            manifest.bindings.audit_model_refresh is None
            or (manifest.bindings.audit_model_refresh_pricing is not None and pricing_authorized)
        ):
            restorable_records = journal.restorable_usage_records
            _recovery_records, recovery_coordinates, _recovery_roots = (
                journal._retained_typed_recovery_usage()
            )
            recovery_bridge_transitions = (
                _recovery_child_usage_bridge_transitions(
                    indexes=journal._truncation_recovery_indexes,
                    ledger_entries=atomic_ledger.snapshot().entries,
                )
                if atomic_ledger is not None
                else ()
            )
            journal._usage_recovery_scope = _issue_trusted_usage_recovery_scope(
                restorable_records,
                recovery_request_limit_coordinates=recovery_coordinates,
                non_usage_request_limit_transitions=recovery_bridge_transitions,
            )
            journal._usage_recovery_expires_at = _scheduler_recovery_expires_at(manifest.bindings)
        return journal
    except BaseException:
        _release_failed_open(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            lock_descriptor=lock_descriptor,
            directory_descriptors=directory_descriptors,
            registered=registered,
        )
        raise


@contextmanager
def open_scheduler_privacy_evidence_custody(
    path: Path,
) -> Iterator[SchedulerPrivacyEvidenceCustody]:
    """Hold the exact pre-dispatch privacy custody under scheduler authority."""

    absolute = Path(os.path.abspath(path))
    root_descriptor = -1
    root_identity: tuple[int, int, int] | None = None
    lock_descriptor = -1
    directory_descriptors: dict[str, int] = {}
    directory_identities: dict[str, tuple[int, int, int]] = {}
    registered = False
    try:
        root_descriptor, root_identity = _open_private_root(absolute)
        _register_live_custody(root_identity[:2])
        registered = True
        lock_descriptor = _acquire_custody_lock(root_descriptor, create=False)
        _assert_root_path_identity(absolute, root_descriptor, root_identity)
        directory_descriptors, directory_identities = _open_control_directories(
            root_descriptor,
            create=False,
        )
        _validate_control_layout(
            root_descriptor,
            directory_descriptors,
            directory_identities,
        )
        with _open_model_observation(
            root_descriptor,
            directory_descriptors,
            _MANIFEST_FILENAME,
            SchedulerCampaignManifest,
        ) as manifest:
            custody = manifest.privacy_evidence_custody
            if custody is None:
                raise ValueError("scheduler campaign lacks pre-dispatch privacy custody")
            if manifest.bindings.privacy_evidence_custody_sha256 != custody.custody_sha256:
                raise ValueError("scheduler campaign privacy custody differs from its bindings")
            _assert_descriptor_custody(
                path=absolute,
                root_descriptor=root_descriptor,
                root_identity=root_identity,
                directory_descriptors=directory_descriptors,
                directory_identities=directory_identities,
            )
            try:
                yield custody
            finally:
                _assert_descriptor_custody(
                    path=absolute,
                    root_descriptor=root_descriptor,
                    root_identity=root_identity,
                    directory_descriptors=directory_descriptors,
                    directory_identities=directory_identities,
                )
    finally:
        _release_failed_open(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            lock_descriptor=lock_descriptor,
            directory_descriptors=directory_descriptors,
            registered=registered,
        )


def open_scheduler_journal_for_verification(
    path: Path,
    *,
    expected_bindings: SchedulerBindings,
    expected_shard_inventory: SchedulerShardInventory,
    expected_analysis_input_inventory: SchedulerAnalysisInputInventory | None = None,
    expected_cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
    expected_privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None,
    expected_terminal_report_authority_required: bool = False,
    expected_terminal_evidence_authority_required: bool | None = None,
    expected_journal_evidence: SchedulerJournalEvidence | None = None,
) -> SchedulerJournal:
    """Open and validate exact journal bytes without performing crash recovery."""

    try:
        validated_expected_analysis_inputs = (
            SchedulerAnalysisInputInventory.model_validate(
                expected_analysis_input_inventory.model_dump(mode="python")
            )
            if expected_analysis_input_inventory is not None
            else None
        )
        validated_expected_bindings = SchedulerBindings.model_validate(
            expected_bindings.model_dump(mode="python")
        )
        validated_expected_inventory = SchedulerShardInventory.model_validate(
            expected_shard_inventory.model_dump(mode="python")
        )
        validated_expected_baseline = (
            SchedulerCostLedgerBaseline.model_validate(
                expected_cost_ledger_baseline.model_dump(mode="python")
            )
            if expected_cost_ledger_baseline is not None
            else None
        )
        validated_expected_privacy = (
            SchedulerPrivacyEvidenceCustody.model_validate(
                expected_privacy_evidence_custody.model_dump(mode="python")
            )
            if expected_privacy_evidence_custody is not None
            else None
        )
    except ValueError:
        raise ValueError(
            "scheduler verification bindings or shard inventory do not match"
        ) from None
    absolute = Path(os.path.abspath(path))
    root_descriptor, root_identity = _open_private_root(absolute)
    lock_descriptor = -1
    directory_descriptors: dict[str, int] = {}
    directory_identities: dict[str, tuple[int, int, int]] = {}
    registered = False
    try:
        _register_live_custody(root_identity[:2])
        registered = True
        lock_descriptor = _acquire_custody_lock(root_descriptor, create=False)
        _assert_root_path_identity(absolute, root_descriptor, root_identity)
        directory_descriptors, directory_identities = _open_control_directories(
            root_descriptor,
            create=False,
        )
        _validate_control_layout(
            root_descriptor,
            directory_descriptors,
            directory_identities,
        )
        manifest = _read_model(
            root_descriptor,
            directory_descriptors,
            _MANIFEST_FILENAME,
            SchedulerCampaignManifest,
        )
        analysis_input_inventory = _read_model(
            root_descriptor,
            directory_descriptors,
            _ANALYSIS_INPUT_INVENTORY_FILENAME,
            SchedulerAnalysisInputInventory,
        )
        if (
            manifest.bindings != validated_expected_bindings
            or manifest.shard_inventory != validated_expected_inventory
            or manifest.cost_ledger_baseline != validated_expected_baseline
            or manifest.privacy_evidence_custody != validated_expected_privacy
            or manifest.terminal_report_authority_required
            is not expected_terminal_report_authority_required
            or (
                expected_terminal_evidence_authority_required is not None
                and manifest.terminal_evidence_authority_required
                is not expected_terminal_evidence_authority_required
            )
            or (
                validated_expected_analysis_inputs is not None
                and analysis_input_inventory != validated_expected_analysis_inputs
            )
            or analysis_input_inventory.analysis_input_sha256
            != manifest.bindings.analysis_input_sha256
        ):
            raise ValueError("scheduler verification bindings or shard inventory do not match")
        (
            plans,
            activations,
            events,
            outputs,
            provider_attempts,
            result_observations,
            pass_results,
            truncation_recovery_entries,
            terminal_report_authority,
        ) = _load_state(
            root_descriptor,
            directory_descriptors,
            manifest,
        )
        journal_head_checkpoint = _read_model(
            root_descriptor,
            directory_descriptors,
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
            SchedulerJournalEvidence,
        )
        journal = SchedulerJournal(
            path=absolute,
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            directory_descriptors=directory_descriptors,
            directory_identities=directory_identities,
            lock_descriptor=lock_descriptor,
            manifest=manifest,
            analysis_input_inventory=analysis_input_inventory,
            plans=plans,
            activations=activations,
            events=events,
            outputs=outputs,
            provider_attempts=provider_attempts,
            result_observations=result_observations,
            pass_results=pass_results,
            truncation_recovery_entries=truncation_recovery_entries,
            terminal_report_authority=terminal_report_authority,
            journal_head_checkpoint=journal_head_checkpoint,
            read_only=True,
        )
        durable_snapshot = journal._validate_state()
        journal._adopt_validated_durable_snapshot(durable_snapshot)
        observed_journal_evidence = journal._require_journal_head_checkpoint_matches_state()
        if (
            expected_journal_evidence is not None
            and SchedulerJournalEvidence.model_validate(
                expected_journal_evidence.model_dump(mode="python")
            )
            != observed_journal_evidence
        ):
            raise ValueError("scheduler verification journal evidence does not match")
        return journal
    except BaseException:
        _release_failed_open(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            lock_descriptor=lock_descriptor,
            directory_descriptors=directory_descriptors,
            registered=registered,
        )
        raise


def _recover_interrupted_state(
    journal: SchedulerJournal,
    *,
    atomic_ledger: AtomicCostLedger | None,
) -> None:
    """Finish safe fresh-file commits and conclude ambiguous dispatches."""

    tasks_by_request = {
        task.logical_request_id: task
        for plan in journal.plans
        for task in plan.tasks
        if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
    }
    ledger_entries = atomic_ledger.snapshot().entries if atomic_ledger is not None else ()
    if atomic_ledger is not None:
        _retained_main_usage_cost_recovery_plan(
            records=journal._retained_main_provider_usage_records(),
            tasks_by_request=tasks_by_request,
            ledger_entries=ledger_entries,
        )
    released_tails_by_task = {
        task.task_id: tail
        for task in tasks_by_request.values()
        if task.task_id not in journal._indexes.outputs
        and (
            tail := _released_pre_send_tail_for_task(
                task=task,
                tasks_by_request=tasks_by_request,
                ledger_entries=ledger_entries,
            )
        )
    }
    recovery_children_by_request = {
        child.child_logical_request_id: (child, family_id)
        for child, family_id in journal._truncation_recovery_indexes.children.values()
    }
    released_recovery_child_tails = {
        child.child_task_id: tail
        for child, _family_id in recovery_children_by_request.values()
        if (
            tail := _released_pre_send_tail_for_recovery_child(
                child=child,
                recovery_children_by_request=recovery_children_by_request,
                ledger_entries=ledger_entries,
            )
        )
    }
    histories = journal._events_by_task()
    for task_id in journal._indexes.provider_attempts:
        history = histories.get(task_id, [])
        if (
            history
            and history[-1].kind is SchedulerTaskEventKind.ACTIVATED
            and task_id not in released_tails_by_task
        ):
            raise ValueError(
                "activated retained provider attempt lacks an exact released ledger tail"
            )
    # A sealed plan may have survived while its PLANNED-event suffix did not.
    for plan in journal.plans:
        for task in plan.tasks:
            if task.task_id not in histories:
                journal._append_event(
                    plan=plan,
                    task=task,
                    kind=SchedulerTaskEventKind.PLANNED,
                )
    histories = journal._events_by_task()
    activations_by_task = {item.task_id: item for item in journal.activations}
    for plan in journal.plans:
        for task in plan.tasks:
            history = histories.get(task.task_id, [])
            activation = activations_by_task.get(task.task_id)
            if (
                activation is not None
                and history
                and history[-1].kind is SchedulerTaskEventKind.PLANNED
            ):
                journal._append_event(
                    plan=plan,
                    task=task,
                    kind=SchedulerTaskEventKind.ACTIVATED,
                    activation=activation,
                )
                journal._refresh_journal_head_checkpoint()
    histories = journal._events_by_task()
    observations_by_task: dict[str, list[SchedulerTaskResult]] = {}
    for observation in journal.result_observations:
        observations_by_task.setdefault(observation.task_id, []).append(observation)
    for plan in journal.plans:
        for task in plan.tasks:
            history = histories.get(task.task_id, [])
            preflight = [
                item
                for item in observations_by_task.get(task.task_id, [])
                if item.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT
            ]
            if (
                len(preflight) == 1
                and history
                and history[-1].kind is SchedulerTaskEventKind.PLANNED
            ):
                journal._append_event(
                    plan=plan,
                    task=task,
                    kind=SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
                    result=preflight[0],
                )
                journal._refresh_journal_head_checkpoint()
                continue
            activated_preflight = [
                item
                for item in observations_by_task.get(task.task_id, [])
                if item.result_origin is SchedulerResultOrigin.ACTIVATED
                and item.terminal_status
                in {
                    SchedulerTerminalStatus.FAILED,
                    SchedulerTerminalStatus.TRUNCATED,
                    SchedulerTerminalStatus.INVALID,
                    SchedulerTerminalStatus.UNBOUND,
                    SchedulerTerminalStatus.INCONCLUSIVE,
                }
            ]
            released_tail = released_tails_by_task.get(task.task_id)
            if (
                released_tail is not None
                and history
                and history[-1].kind is SchedulerTaskEventKind.ACTIVATED
            ):
                if len(released_tail) != 1 or released_tail[0][0] != 1:
                    raise ValueError(
                        "activated scheduler task has a noninitial released provider attempt"
                    )
                released_failure = SchedulerTaskResult.build(
                    plan=plan,
                    task=task,
                    activation=activations_by_task[task.task_id],
                    terminal_status=SchedulerTerminalStatus.FAILED,
                    terminal_evidence_sha256=cost_entry_sha256(released_tail[0][1]),
                )
                observed = observations_by_task.get(task.task_id, [])
                if observed and observed != [released_failure]:
                    raise ValueError("released activated task has contradictory terminal evidence")
                if observed:
                    journal._append_event(
                        plan=plan,
                        task=task,
                        kind=SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
                        activation=activations_by_task[task.task_id],
                        result=observed[0],
                    )
                    journal._refresh_journal_head_checkpoint()
                else:
                    journal._refresh_journal_head_checkpoint()
                    journal.record_activated_preflight_failure(released_failure)
                continue
            if (
                len(activated_preflight) == 1
                and history
                and history[-1].kind is SchedulerTaskEventKind.ACTIVATED
            ):
                activation = activations_by_task[task.task_id]
                journal._append_event(
                    plan=plan,
                    task=task,
                    kind=SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
                    activation=activation,
                    result=activated_preflight[0],
                )
                journal._refresh_journal_head_checkpoint()
                continue
            if not history or history[-1].kind is not SchedulerTaskEventKind.DISPATCHED:
                continue
            dispatch = history[-1]
            activation = activations_by_task[task.task_id]
            output = journal._indexes.outputs.get(task.task_id)
            provider_attempt = journal._indexes.provider_attempts.get(task.task_id)
            if output is not None:
                terminal_evidence_sha256 = _successful_output_terminal_evidence_sha256(
                    task=task,
                    output=output,
                )
                succeeded = SchedulerTaskResult.build(
                    plan=plan,
                    task=task,
                    activation=activation,
                    terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                    terminal_evidence_sha256=terminal_evidence_sha256,
                    output=output,
                )
                observed = observations_by_task.get(task.task_id, [])
                if observed and observed != [succeeded]:
                    raise ValueError(
                        "interrupted scheduler output has contradictory terminal evidence"
                    )
                if observed:
                    journal._append_event(
                        plan=plan,
                        task=task,
                        kind=SchedulerTaskEventKind.TERMINAL,
                        request_id=task.logical_request_id,
                        activation=activation,
                        result=observed[0],
                    )
                    journal._refresh_journal_head_checkpoint()
                else:
                    journal._refresh_journal_head_checkpoint()
                    journal.record_terminal(succeeded)
                continue
            if released_tail is not None:
                released_failure = SchedulerTaskResult.build(
                    plan=plan,
                    task=task,
                    activation=activation,
                    terminal_status=SchedulerTerminalStatus.FAILED,
                    terminal_evidence_sha256=cost_entry_sha256(released_tail[-1][1]),
                )
                observed = observations_by_task.get(task.task_id, [])
                if observed and observed != [released_failure]:
                    raise ValueError("released dispatched task has contradictory terminal evidence")
                if observed:
                    journal._append_event(
                        plan=plan,
                        task=task,
                        kind=SchedulerTaskEventKind.TERMINAL,
                        request_id=task.logical_request_id,
                        activation=activation,
                        result=observed[0],
                    )
                    journal._refresh_journal_head_checkpoint()
                else:
                    journal._refresh_journal_head_checkpoint()
                    journal.record_terminal(released_failure)
                continue
            if provider_attempt is not None and provider_attempt.schema_version == "1.1":
                projection = provider_attempt.truncation_projection
                envelope = provider_attempt.truncated_envelope_evidence
                if projection is None or envelope is None:
                    raise ValueError(
                        "typed scheduler truncation attempt lacks exact recoverable evidence"
                    )
                truncated = SchedulerTaskResult.build(
                    plan=plan,
                    task=task,
                    activation=activation,
                    terminal_status=SchedulerTerminalStatus.TRUNCATED,
                    terminal_evidence_sha256=projection.evidence_sha256,
                )
                observed = observations_by_task.get(task.task_id, [])
                matching_truncation = [item for item in observed if item == truncated]
                if len(matching_truncation) > 1 or (
                    observed and len(matching_truncation) != len(observed)
                ):
                    raise ValueError(
                        "typed scheduler truncation has contradictory result observations"
                    )
                if matching_truncation:
                    truncated = matching_truncation[0]
                else:
                    journal._refresh_journal_head_checkpoint()
                    _write_model(
                        journal._root_descriptor,
                        journal._directory_descriptors,
                        _task_result_path(truncated),
                        truncated,
                    )
                    journal._retain_result_observation(truncated)
                journal._append_event(
                    plan=plan,
                    task=task,
                    kind=SchedulerTaskEventKind.TERMINAL,
                    request_id=task.logical_request_id,
                    activation=activation,
                    result=truncated,
                )
                journal._refresh_journal_head_checkpoint()
                continue
            observed = observations_by_task.get(task.task_id, [])
            if observed:
                if len(observed) != 1:
                    raise ValueError(
                        "interrupted scheduler task has ambiguous terminal observations"
                    )
                retained_result = observed[0]
                try:
                    exact_retained_result = SchedulerTaskResult.build(
                        plan=plan,
                        task=task,
                        activation=activation,
                        terminal_status=retained_result.terminal_status,
                        terminal_evidence_sha256=(retained_result.terminal_evidence_sha256),
                    )
                except (TypeError, ValueError):
                    raise ValueError(
                        "interrupted scheduler terminal observation is not resumable"
                    ) from None
                if retained_result != exact_retained_result:
                    raise ValueError(
                        "interrupted scheduler terminal observation differs from its task"
                    )
                journal._append_event(
                    plan=plan,
                    task=task,
                    kind=SchedulerTaskEventKind.TERMINAL,
                    request_id=task.logical_request_id,
                    activation=activation,
                    result=retained_result,
                )
                journal._refresh_journal_head_checkpoint()
                continue
            uncertain = SchedulerTaskResult.build(
                plan=plan,
                task=task,
                activation=activation,
                terminal_status=SchedulerTerminalStatus.UNCERTAIN,
                terminal_evidence_sha256=scheduler_canonical_sha256(
                    {
                        "classification": "dispatch_without_terminal",
                        "dispatch_event_sha256": dispatch.event_sha256,
                    }
                ),
            )
            matching = [
                item for item in observations_by_task.get(task.task_id, []) if item == uncertain
            ]
            if len(matching) > 1:
                raise ValueError("scheduler has duplicate uncertain result observations")
            if matching:
                uncertain = matching[0]
            else:
                journal._refresh_journal_head_checkpoint()
                _write_model(
                    journal._root_descriptor,
                    journal._directory_descriptors,
                    _task_result_path(uncertain),
                    uncertain,
                )
                journal._retain_result_observation(uncertain)
            journal._append_event(
                plan=plan,
                task=task,
                kind=SchedulerTaskEventKind.TERMINAL,
                request_id=task.logical_request_id,
                activation=activation,
                result=uncertain,
            )
            journal._refresh_journal_head_checkpoint()

    activated_released_recovery_children = tuple(
        sorted(
            set(released_recovery_child_tails)
            .intersection(journal._truncation_recovery_indexes.activations)
            .difference(journal._truncation_recovery_indexes.dispatches)
            .difference(journal._truncation_recovery_indexes.results)
        )
    )
    for child_task_id in activated_released_recovery_children:
        journal._refresh_journal_head_checkpoint()
        child, _family_id = journal._truncation_recovery_indexes.children[child_task_id]
        recovery_activation = journal._truncation_recovery_indexes.activations[child_task_id]
        released_tail = released_recovery_child_tails[child_task_id]
        if len(released_tail) != 1 or released_tail[0][0] != 1:
            raise ValueError("activated recovery child has a noninitial released provider attempt")
        release_reason = released_tail[0][1].release_reason
        assert release_reason is not None
        released_result = SchedulerTruncationRecoveryChildResult.build_released_pre_send(
            child=child,
            activation=recovery_activation,
            dispatch=None,
            terminal_evidence_sha256=cost_entry_sha256(released_tail[0][1]),
            release_reason=release_reason.value,
            accounted_prefix_attempts=0,
            accounted_prefix_cost_usd_exact="0",
            entry_index=len(journal._truncation_recovery_entries),
            previous_entry_sha256=journal._truncation_recovery_chain_head,
        )
        journal._append_truncation_recovery_entry(released_result)

    interrupted_recovery_children = tuple(
        sorted(
            set(journal._truncation_recovery_indexes.dispatches)
            - set(journal._truncation_recovery_indexes.results)
        )
    )
    for child_task_id in interrupted_recovery_children:
        journal._refresh_journal_head_checkpoint()
        child, _family_id = journal._truncation_recovery_indexes.children[child_task_id]
        recovery_dispatch = journal._truncation_recovery_indexes.dispatches[child_task_id]
        released_tail = released_recovery_child_tails.get(child_task_id)
        release_reason = released_tail[-1][1].release_reason if released_tail is not None else None
        recovered_result = (
            SchedulerTruncationRecoveryChildResult.build_released_pre_send(
                child=child,
                activation=journal._truncation_recovery_indexes.activations[child_task_id],
                dispatch=recovery_dispatch,
                terminal_evidence_sha256=cost_entry_sha256(released_tail[-1][1]),
                release_reason=cast(ReleaseReason, release_reason).value,
                accounted_prefix_attempts=len(released_tail) - 1,
                accounted_prefix_cost_usd_exact=_canonical_recovery_usd_sum(
                    tuple(
                        format(entry.accounted_cost_usd, "f")
                        for _ordinal, entry in released_tail[:-1]
                    )
                ),
                entry_index=len(journal._truncation_recovery_entries),
                previous_entry_sha256=journal._truncation_recovery_chain_head,
            )
            if released_tail is not None
            else SchedulerTruncationRecoveryChildResult.build_uncertain(
                child=child,
                dispatch=recovery_dispatch,
                entry_index=len(journal._truncation_recovery_entries),
                previous_entry_sha256=journal._truncation_recovery_chain_head,
            )
        )
        journal._append_truncation_recovery_entry(recovered_result)


def _successful_output_terminal_evidence_sha256(
    *,
    task: SchedulerTaskPlan,
    output: SchedulerTaskOutput,
) -> str:
    """Derive the only resumable success evidence from a retained exact output."""

    completion = output.model_completion_evidence
    if completion is not None:
        return completion.validated_response_sha256
    if task.task_kind is SchedulerTaskKind.HOST_COMPUTATION:
        return scheduler_canonical_sha256(
            {
                "classification": "host_computation_completed",
                "output_sha256": output.output_sha256,
            }
        )
    raise ValueError("interrupted scheduler output lacks deterministic completion evidence")


def _load_state(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    manifest: SchedulerCampaignManifest,
    *,
    allow_pending_checkpoint: bool = False,
    allowed_immutable_write_temps: frozenset[str] = frozenset(),
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> tuple[
    tuple[SchedulerPassPlan, ...],
    tuple[SchedulerTaskActivation, ...],
    tuple[SchedulerTaskEvent, ...],
    tuple[SchedulerTaskOutput, ...],
    tuple[SchedulerProviderAttemptEvidence, ...],
    tuple[SchedulerTaskResult, ...],
    tuple[SchedulerPassResult, ...],
    tuple[SchedulerTruncationRecoveryEntry, ...],
    SchedulerTerminalReportAuthority | None,
]:
    terminal_report_authority = (
        _read_model(
            root_descriptor,
            directory_descriptors,
            _TERMINAL_REPORT_AUTHORITY_FILENAME,
            SchedulerTerminalReportAuthority,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        if _TERMINAL_REPORT_AUTHORITY_FILENAME in set(os.listdir(root_descriptor))
        else None
    )
    plans = _load_contiguous_pass_artifacts(
        root_descriptor,
        directory_descriptors,
        SchedulerPassPlan,
        result=False,
        allowed_immutable_write_temps=allowed_immutable_write_temps,
        allowed_published_immutable_targets=allowed_published_immutable_targets,
    )
    pass_results = _load_contiguous_pass_artifacts(
        root_descriptor,
        directory_descriptors,
        SchedulerPassResult,
        result=True,
        allowed_immutable_write_temps=allowed_immutable_write_temps,
        allowed_published_immutable_targets=allowed_published_immutable_targets,
    )
    events = _load_indexed_events(
        root_descriptor,
        directory_descriptors,
        allowed_immutable_write_temps=allowed_immutable_write_temps,
        allowed_published_immutable_targets=allowed_published_immutable_targets,
    )
    activations: list[SchedulerTaskActivation] = []
    for candidate_name in _durable_directory_names(
        directory_descriptors[_ACTIVATIONS_DIRECTORY],
        _ACTIVATIONS_DIRECTORY,
        allowed_immutable_write_temps,
    ):
        activation = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_ACTIVATIONS_DIRECTORY}/{candidate_name}",
            SchedulerTaskActivation,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        if candidate_name != PurePosixPath(_activation_path(activation)).name:
            raise ValueError("scheduler activation filename differs from its stable hash")
        activations.append(activation)
    outputs: list[SchedulerTaskOutput] = []
    for candidate_name in _durable_directory_names(
        directory_descriptors[_TASK_OUTPUTS_DIRECTORY],
        _TASK_OUTPUTS_DIRECTORY,
        allowed_immutable_write_temps,
    ):
        output = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_TASK_OUTPUTS_DIRECTORY}/{candidate_name}",
            SchedulerTaskOutput,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        if candidate_name != PurePosixPath(_task_output_path(output)).name:
            raise ValueError("scheduler output filename differs from its stable hash")
        outputs.append(output)
    provider_attempts: list[SchedulerProviderAttemptEvidence] = []
    for candidate_name in _durable_directory_names(
        directory_descriptors[_PROVIDER_ATTEMPTS_DIRECTORY],
        _PROVIDER_ATTEMPTS_DIRECTORY,
        allowed_immutable_write_temps,
    ):
        attempt = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_PROVIDER_ATTEMPTS_DIRECTORY}/{candidate_name}",
            SchedulerProviderAttemptEvidence,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        if candidate_name != PurePosixPath(_provider_attempt_path(attempt)).name:
            raise ValueError("scheduler provider-attempt filename differs from its stable hash")
        provider_attempts.append(attempt)
    result_observations: list[SchedulerTaskResult] = []
    for candidate_name in _durable_directory_names(
        directory_descriptors[_TASK_RESULTS_DIRECTORY],
        _TASK_RESULTS_DIRECTORY,
        allowed_immutable_write_temps,
    ):
        result = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_TASK_RESULTS_DIRECTORY}/{candidate_name}",
            SchedulerTaskResult,
            allowed_published_immutable_targets=allowed_published_immutable_targets,
        )
        if candidate_name != PurePosixPath(_task_result_path(result)).name:
            raise ValueError("scheduler task-result filename differs from its stable result hash")
        result_observations.append(result)
    truncation_recovery_entries = _load_truncation_recovery_entries(
        root_descriptor,
        directory_descriptors,
        allowed_immutable_write_temps=allowed_immutable_write_temps,
        allowed_published_immutable_targets=allowed_published_immutable_targets,
    )
    loaded = (
        tuple(plans),
        tuple(sorted(activations, key=lambda item: item.task_id)),
        tuple(events),
        tuple(sorted(outputs, key=lambda item: item.task_id)),
        tuple(sorted(provider_attempts, key=lambda item: item.task_id)),
        tuple(
            sorted(
                result_observations,
                key=lambda item: (item.task_id, item.result_sha256),
            )
        ),
        tuple(pass_results),
        truncation_recovery_entries,
        terminal_report_authority,
    )
    _validate_loaded_state(
        manifest=manifest,
        plans=loaded[0],
        activations=loaded[1],
        events=loaded[2],
        outputs=loaded[3],
        provider_attempts=loaded[4],
        result_observations=loaded[5],
        pass_results=loaded[6],
        truncation_recovery_entries=loaded[7],
        terminal_report_authority=loaded[8],
    )
    _validate_artifact_inventory(
        root_descriptor=root_descriptor,
        directory_descriptors=directory_descriptors,
        directory_identities={
            name: _directory_identity(os.fstat(descriptor))
            for name, descriptor in directory_descriptors.items()
        },
        plans=loaded[0],
        activations=loaded[1],
        events=loaded[2],
        outputs=loaded[3],
        provider_attempts=loaded[4],
        result_observations=loaded[5],
        pass_results=loaded[6],
        truncation_recovery_entries=loaded[7],
        terminal_report_authority=loaded[8],
        allow_pending_checkpoint=allow_pending_checkpoint,
        allowed_immutable_write_temps=allowed_immutable_write_temps,
        allowed_published_immutable_targets=allowed_published_immutable_targets,
    )
    return loaded


def _load_truncation_recovery_entries(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    *,
    allowed_immutable_write_temps: frozenset[str] = frozenset(),
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> tuple[SchedulerTruncationRecoveryEntry, ...]:
    observed = _bounded_directory_names(
        directory_descriptors[_TRUNCATION_RECOVERY_DIRECTORY],
        limit=SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES,
        label="truncation recovery",
        ignored_names=frozenset(
            PurePosixPath(item).name
            for item in allowed_immutable_write_temps
            if PurePosixPath(item).parent == PurePosixPath(_TRUNCATION_RECOVERY_DIRECTORY)
        ),
    )
    loaded: list[SchedulerTruncationRecoveryEntry] = []
    for index, candidate_name in enumerate(observed):
        relative = f"{_TRUNCATION_RECOVERY_DIRECTORY}/{candidate_name}"
        parent_descriptor, leaf = _relative_parent(
            root_descriptor,
            directory_descriptors,
            relative,
        )
        content = _read_private_file(
            parent_descriptor,
            leaf,
            allowed_published_identity=((allowed_published_immutable_targets or {}).get(relative)),
        )
        try:
            raw = json.loads(content)
            kind = SchedulerTruncationRecoveryEntryKind(raw["entry_kind"])
            model_type = SCHEDULER_TRUNCATION_RECOVERY_ENTRY_TYPES[kind]
            entry = cast(
                SchedulerTruncationRecoveryEntry,
                model_type.model_validate_json(content, strict=True),
            )
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("scheduler truncation recovery entry is invalid") from exc
        if content != stable_json(entry).encode("utf-8"):
            raise ValueError("scheduler truncation recovery entry is not canonical")
        if (
            entry.entry_index != index
            or candidate_name != PurePosixPath(_truncation_recovery_entry_path(entry)).name
        ):
            raise ValueError("scheduler truncation recovery filenames are not contiguous")
        loaded.append(entry)
    return validate_truncation_recovery_entry_chain(loaded)


def _bounded_directory_names(
    directory_descriptor: int,
    *,
    limit: int,
    label: str,
    ignored_names: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    try:
        with os.scandir(directory_descriptor) as iterator:
            entries = tuple(islice(iterator, limit + len(ignored_names) + 1))
    except OSError as exc:
        raise ValueError(f"scheduler {label} directory could not be enumerated") from exc
    if len(entries) > limit + len(ignored_names):
        raise ValueError(f"scheduler {label} directory exceeds its exact entry bound")
    names = tuple(entry.name for entry in entries)
    if len(names) != len(set(names)):
        raise ValueError(f"scheduler {label} directory repeats an entry name")
    if not ignored_names <= set(names):
        raise ValueError(f"scheduler {label} ignored artifact inventory is absent")
    durable_names = tuple(name for name in names if name not in ignored_names)
    if len(durable_names) > limit:
        raise ValueError(f"scheduler {label} directory exceeds its exact entry bound")
    return tuple(sorted(durable_names))


def _durable_directory_names(
    directory_descriptor: int,
    directory: str,
    allowed_immutable_write_temps: frozenset[str],
) -> tuple[str, ...]:
    ignored = {
        PurePosixPath(item).name
        for item in allowed_immutable_write_temps
        if PurePosixPath(item).parent == PurePosixPath(directory)
    }
    observed = set(os.listdir(directory_descriptor))
    if not ignored <= observed:
        raise ValueError("scheduler immutable output temp inventory changed during load")
    return tuple(sorted(observed - ignored))


def _load_contiguous_pass_artifacts[ModelT: StrictModel](
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    model_type: type[ModelT],
    *,
    result: bool,
    allowed_immutable_write_temps: frozenset[str] = frozenset(),
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> list[ModelT]:
    directory = _PASS_RESULTS_DIRECTORY if result else _PASS_PLANS_DIRECTORY
    suffix = "result" if result else "plan"
    observed = _durable_directory_names(
        directory_descriptors[directory],
        directory,
        allowed_immutable_write_temps,
    )
    loaded: list[ModelT] = []
    for ordinal, candidate_name in enumerate(observed):
        expected = f"pass-{ordinal + 1:02d}-{suffix}.json"
        if candidate_name != expected or ordinal >= len(SCHEDULER_PASS_ORDER):
            raise ValueError("scheduler pass artifacts are not a contiguous exact prefix")
        loaded.append(
            _read_model(
                root_descriptor,
                directory_descriptors,
                f"{directory}/{expected}",
                model_type,
                allowed_published_immutable_targets=allowed_published_immutable_targets,
            )
        )
    return loaded


def _load_indexed_events(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    *,
    allowed_immutable_write_temps: frozenset[str] = frozenset(),
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> list[SchedulerTaskEvent]:
    observed = _durable_directory_names(
        directory_descriptors[_EVENTS_DIRECTORY],
        _EVENTS_DIRECTORY,
        allowed_immutable_write_temps,
    )
    events: list[SchedulerTaskEvent] = []
    for index, candidate_name in enumerate(observed):
        if candidate_name != PurePosixPath(_event_path(index)).name:
            raise ValueError("scheduler events are not one contiguous exact journal")
        events.append(
            _read_model(
                root_descriptor,
                directory_descriptors,
                _event_path(index),
                SchedulerTaskEvent,
                allowed_published_immutable_targets=allowed_published_immutable_targets,
            )
        )
    return events


def _validate_loaded_state(
    *,
    manifest: SchedulerCampaignManifest,
    plans: tuple[SchedulerPassPlan, ...],
    activations: tuple[SchedulerTaskActivation, ...],
    events: tuple[SchedulerTaskEvent, ...],
    outputs: tuple[SchedulerTaskOutput, ...],
    provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...],
    result_observations: tuple[SchedulerTaskResult, ...],
    pass_results: tuple[SchedulerPassResult, ...],
    truncation_recovery_entries: tuple[SchedulerTruncationRecoveryEntry, ...],
    terminal_report_authority: SchedulerTerminalReportAuthority | None,
) -> None:
    if len(pass_results) > len(plans) or len(pass_results) < max(0, len(plans) - 1):
        raise ValueError("scheduler pass plan/result prefixes are inconsistent")
    task_lookup: dict[str, tuple[SchedulerTaskPlan, SchedulerPassPlan]] = {}
    for ordinal, plan in enumerate(plans):
        expected_dependencies = tuple(
            SchedulerPassDependency.from_result(item) for item in pass_results[:ordinal]
        )
        if (
            plan.manifest != manifest
            or plan.pass_kind is not SCHEDULER_PASS_ORDER[ordinal]
            or plan.dependencies != expected_dependencies
            or any(
                item.status is not SchedulerPassStatus.COMPLETE for item in pass_results[:ordinal]
            )
        ):
            raise ValueError("scheduler pass plan differs from campaign dependency state")
        for task in plan.tasks:
            _require_model_task_privacy_custody(manifest, task)
            if task.task_id in task_lookup:
                raise ValueError("scheduler task identity is duplicated across pass plans")
            task_lookup[task.task_id] = (task, plan)

    activations_by_task: dict[str, SchedulerTaskActivation] = {}
    for activation in activations:
        if activation.task_id in activations_by_task or activation.task_id not in task_lookup:
            raise ValueError("scheduler activation is duplicated or unplanned")
        task, plan = task_lookup[activation.task_id]
        activation.require_exact_task(plan=plan, task=task)
        activations_by_task[activation.task_id] = activation

    outputs_by_task: dict[str, SchedulerTaskOutput] = {}
    for output in outputs:
        output_activation = activations_by_task.get(output.task_id)
        if (
            output.task_id in outputs_by_task
            or output.task_id not in task_lookup
            or output_activation is None
        ):
            raise ValueError("scheduler output is duplicated, unplanned, or unactivated")
        task, plan = task_lookup[output.task_id]
        output.require_exact_activation(output_activation)
        completion = output.model_completion_evidence
        expected_output = SchedulerTaskOutput.build(
            plan=plan,
            task=task,
            activation=output_activation,
            payload=output.payload,
            usage_record=completion.usage_record if completion is not None else None,
            specialist_accepted_outcome=output.specialist_accepted_outcome,
            model_surface_review_requests=output.model_surface_review_requests,
            model_surface_review_artifact=output.model_surface_review_artifact,
            accepted_candidates=output.accepted_candidates,
            normalizer_sha256=completion.normalizer_sha256 if completion is not None else None,
            normalization_evidence=(
                completion.normalization_evidence if completion is not None else None
            ),
            schema_version=output.schema_version,
        )
        if output != expected_output:
            raise ValueError("scheduler output differs from its exact normalized task evidence")
        outputs_by_task[output.task_id] = output

    provider_attempts_by_task: dict[str, SchedulerProviderAttemptEvidence] = {}
    for attempt in provider_attempts:
        attempt_activation = activations_by_task.get(attempt.task_id)
        if (
            attempt.task_id in provider_attempts_by_task
            or attempt.task_id in outputs_by_task
            or attempt.task_id not in task_lookup
            or attempt_activation is None
        ):
            raise ValueError(
                "scheduler provider attempt is duplicated, credited, unplanned, or unactivated"
            )
        task, plan = task_lookup[attempt.task_id]
        expected_attempt = SchedulerProviderAttemptEvidence.build(
            task=task,
            activation=attempt_activation,
            usage_record=attempt.usage_record,
            audit_model_selection=plan.manifest.bindings.audit_model_selection,
            audit_model_refresh=plan.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=(plan.manifest.bindings.audit_model_refresh_pricing),
            truncated_envelope_evidence=attempt.truncated_envelope_evidence,
            truncation_projection=attempt.truncation_projection,
        )
        if attempt != expected_attempt:
            raise ValueError("scheduler provider attempt differs from exact task evidence")
        provider_attempts_by_task[attempt.task_id] = attempt

    observations_by_hash: dict[str, SchedulerTaskResult] = {}
    observations_by_task: dict[str, list[SchedulerTaskResult]] = {}
    for result in result_observations:
        if result.result_sha256 in observations_by_hash or result.task_id not in task_lookup:
            raise ValueError("scheduler task result is duplicated or unplanned")
        task, plan = task_lookup[result.task_id]
        if result.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT:
            if result.task_id in activations_by_task or result.task_id in outputs_by_task:
                raise ValueError("scheduler preflight result has runtime evidence")
            expected_task_result = SchedulerTaskResult.build_preflight_failure(
                plan=plan,
                task=task,
                terminal_status=result.terminal_status,
                terminal_evidence_sha256=result.terminal_evidence_sha256,
            )
        else:
            result_activation = activations_by_task.get(result.task_id)
            if result_activation is None:
                raise ValueError("scheduler activated result lacks exact activation")
            result_output = (
                outputs_by_task.get(result.task_id)
                if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                else None
            )
            expected_task_result = SchedulerTaskResult.build(
                plan=plan,
                task=task,
                activation=result_activation,
                terminal_status=result.terminal_status,
                terminal_evidence_sha256=result.terminal_evidence_sha256,
                output=result_output,
            )
        if result != expected_task_result:
            raise ValueError("scheduler task result differs from its sealed task plan")
        observations_by_hash[result.result_sha256] = result
        observations_by_task.setdefault(result.task_id, []).append(result)
    if any(len(items) > 2 for items in observations_by_task.values()):
        raise ValueError("scheduler task has too many retained result observations")
    if any(
        len(items) == 2
        and (
            sum(item.terminal_status is SchedulerTerminalStatus.UNCERTAIN for item in items) != 1
            or any(item.result_origin is not SchedulerResultOrigin.ACTIVATED for item in items)
        )
        for items in observations_by_task.values()
    ):
        raise ValueError("scheduler duplicate observations are not exact uncertain recovery")

    for plan in plans:
        workset = plan.candidate_workset
        if workset is None:
            continue
        source_passes = tuple(
            result
            for result in pass_results
            if result.plan.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
            and result.pass_result_sha256 == workset.source_pass_result_sha256
        )
        source_results = tuple(
            result
            for source_pass in source_passes
            for result in source_pass.task_results
            if result.task_id == workset.source_task_id
            and result.result_sha256 == workset.source_result_sha256
        )
        source_outputs = tuple(
            output
            for output in outputs
            if output.task_id == workset.source_task_id
            and output.output_artifact_sha256 == workset.source_output_artifact_sha256
        )
        if len(source_passes) != 1 or len(source_results) != 1 or len(source_outputs) != 1:
            raise ValueError("scheduler candidate workset lacks exact retained pass-four evidence")
        expected_workset = type(workset).build(
            pass_kind=plan.pass_kind,
            source_pass_result=source_passes[0],
            source_result=source_results[0],
            source_output=source_outputs[0],
        )
        if workset != expected_workset:
            raise ValueError("scheduler candidate workset differs from pass-four output")

    histories: dict[str, list[SchedulerTaskEvent]] = {}
    credited_results: dict[str, SchedulerTaskResult] = {}
    previous_global: SchedulerTaskEvent | None = None
    event_ids: set[str] = set()
    for index, event in enumerate(events):
        if event.event_id in event_ids or event.task_id not in task_lookup:
            raise ValueError("scheduler event identity is duplicated or unplanned")
        task, plan = task_lookup[event.task_id]
        history = histories.setdefault(task.task_id, [])
        event_result: SchedulerTaskResult | None = None
        if event.kind in {
            SchedulerTaskEventKind.TERMINAL,
            SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
            SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
        }:
            assert event.task_result_sha256 is not None
            event_result = observations_by_hash.get(event.task_result_sha256)
            if event_result is None or event_result.task_id != task.task_id:
                raise ValueError("scheduler terminal event lacks its exact task result")
            if task.task_id in credited_results:
                raise ValueError("scheduler task has more than one credited terminal result")
        event_activation = (
            activations_by_task.get(task.task_id)
            if event.kind
            in {
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.DISPATCHED,
                SchedulerTaskEventKind.TERMINAL,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            }
            else None
        )
        expected_event = SchedulerTaskEvent.build(
            plan=plan,
            task=task,
            kind=event.kind,
            event_index=index,
            previous_event=previous_global,
            prior_task_event=history[-1] if history else None,
            request_id=(
                task.logical_request_id
                if event.kind
                in {SchedulerTaskEventKind.DISPATCHED, SchedulerTaskEventKind.TERMINAL}
                else None
            ),
            activation=event_activation,
            result=event_result,
        )
        if event != expected_event:
            raise ValueError("scheduler event differs from its exact global or task chain")
        history.append(event)
        if event_result is not None:
            credited_results[task.task_id] = event_result
        if event.kind is SchedulerTaskEventKind.ACTIVATED:
            assert event_activation is not None
            available_result_hashes = {item.result_sha256 for item in credited_results.values()}
            if not set(event_activation.upstream_task_result_sha256s) <= available_result_hashes:
                raise ValueError("scheduler activation references unavailable upstream results")
            task_plan = task_lookup[task.task_id][1]
            if task.task_kind is SchedulerTaskKind.EMPTY_COMPLETION:
                workset = task_plan.candidate_workset
                if workset is None or event_activation.upstream_task_result_sha256s != (
                    workset.source_result_sha256,
                ):
                    raise ValueError(
                        "scheduler explicit-empty activation lacks exact pass-four source result"
                    )
        event_ids.add(event.event_id)
        previous_global = event

    for task_id, history in histories.items():
        kinds = tuple(item.kind for item in history)
        allowed = (
            (SchedulerTaskEventKind.PLANNED,),
            (SchedulerTaskEventKind.PLANNED, SchedulerTaskEventKind.ACTIVATED),
            (
                SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.DISPATCHED,
            ),
            (
                SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.DISPATCHED,
                SchedulerTaskEventKind.TERMINAL,
            ),
            (SchedulerTaskEventKind.PLANNED, SchedulerTaskEventKind.PREFLIGHT_TERMINAL),
            (
                SchedulerTaskEventKind.PLANNED,
                SchedulerTaskEventKind.ACTIVATED,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            ),
        )
        if kinds not in allowed:
            raise ValueError("scheduler task lifecycle is not a strict transition prefix")
        observations = observations_by_task.get(task_id, [])
        task_activation = activations_by_task.get(task_id)
        task_output = outputs_by_task.get(task_id)
        task_provider_attempt = provider_attempts_by_task.get(task_id)
        terminal = kinds[-1] in {
            SchedulerTaskEventKind.TERMINAL,
            SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
            SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
        }
        if kinds[-1] is SchedulerTaskEventKind.PLANNED:
            preflight = [
                item
                for item in observations
                if item.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT
            ]
            if (
                (task_activation is not None and observations)
                or task_output is not None
                or len(preflight) > 1
            ):
                raise ValueError("scheduler planned task has contradictory interrupted evidence")
        elif kinds[-1] is SchedulerTaskEventKind.ACTIVATED:
            activated_preflight = [
                item
                for item in observations
                if item.result_origin is SchedulerResultOrigin.ACTIVATED
                and item.terminal_status
                in {
                    SchedulerTerminalStatus.FAILED,
                    SchedulerTerminalStatus.TRUNCATED,
                    SchedulerTerminalStatus.INVALID,
                    SchedulerTerminalStatus.UNBOUND,
                    SchedulerTerminalStatus.INCONCLUSIVE,
                }
            ]
            if task_output or len(observations) > 1 or observations != activated_preflight:
                raise ValueError("scheduler task has invalid result evidence before dispatch")
        if terminal and task_id not in credited_results:
            raise ValueError("scheduler terminal event lacks its exact task result")
        if terminal and len(observations) > 1:
            credited = credited_results[task_id]
            if credited.terminal_status is not SchedulerTerminalStatus.UNCERTAIN or any(
                item.terminal_status is SchedulerTerminalStatus.UNCERTAIN
                for item in observations
                if item != credited
            ):
                raise ValueError("scheduler has an uncredited result outside uncertain recovery")
        if task_output is not None:
            credited_result = credited_results.get(task_id)
            retained_success = [
                item
                for item in observations
                if item.terminal_status is SchedulerTerminalStatus.SUCCEEDED
            ]
            provisional_statuses = {
                item.terminal_status for item in observations if item != credited_result
            }
            if (
                kinds[-1]
                not in {SchedulerTaskEventKind.DISPATCHED, SchedulerTaskEventKind.TERMINAL}
                or len(retained_success) > 1
                or provisional_statuses - {SchedulerTerminalStatus.SUCCEEDED}
                or (
                    terminal
                    and (
                        credited_result is None
                        or credited_result.terminal_status
                        not in {
                            SchedulerTerminalStatus.SUCCEEDED,
                            SchedulerTerminalStatus.UNCERTAIN,
                        }
                    )
                )
            ):
                raise ValueError("scheduler output lacks a dispatched success observation")
        if task_provider_attempt is not None:
            credited_result = credited_results.get(task_id)
            activation_bound_release = (
                SchedulerTaskEventKind.DISPATCHED not in kinds
                and kinds[-1]
                in {
                    SchedulerTaskEventKind.ACTIVATED,
                    SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
                }
                and (
                    (kinds[-1] is SchedulerTaskEventKind.ACTIVATED and credited_result is None)
                    or (
                        kinds[-1] is SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL
                        and credited_result is not None
                        and credited_result.terminal_status is SchedulerTerminalStatus.FAILED
                    )
                )
            )
            if activation_bound_release:
                _require_exact_activation_released_usage(
                    task_provider_attempt.usage_record,
                    logical_request_id=task_lookup[task_id][0].logical_request_id,
                    require_runtime_attestation=False,
                )
            if (
                (SchedulerTaskEventKind.DISPATCHED not in kinds and not activation_bound_release)
                or task_output is not None
                or (
                    credited_result is not None
                    and credited_result.terminal_status
                    in {
                        SchedulerTerminalStatus.SUCCEEDED,
                        SchedulerTerminalStatus.EXPLICIT_EMPTY,
                    }
                )
            ):
                raise ValueError(
                    "scheduler provider attempt lacks a non-creditable dispatched lifecycle"
                )

    if any(
        task_id not in histories
        for task_id in {
            *activations_by_task,
            *outputs_by_task,
            *provider_attempts_by_task,
            *observations_by_task,
        }
    ):
        raise ValueError("scheduler runtime evidence exists before its planned lifecycle")

    # Missing planned events can only be the suffix of the most recently written
    # pass plan.  This is the one safe interrupted append that recovery completes.
    for plan_index, plan in enumerate(plans):
        planned_task_ids = tuple(task.task_id for task in plan.tasks if task.task_id in histories)
        expected_prefix = tuple(task.task_id for task in plan.tasks[: len(planned_task_ids)])
        if planned_task_ids != expected_prefix:
            raise ValueError("scheduler planned-event inventory is not an exact task prefix")
        if len(planned_task_ids) != len(plan.tasks) and plan_index != len(plans) - 1:
            raise ValueError("scheduler prior pass plan is missing planned task events")

    scheduler_indexes = _derive_scheduler_journal_indexes(
        plans=plans,
        activations=activations,
        outputs=outputs,
        provider_attempts=provider_attempts,
        result_observations=result_observations,
        events=events,
    )
    recovery_indexes = _derive_truncation_recovery_indexes(
        entries=truncation_recovery_entries,
        scheduler=scheduler_indexes,
        manifest=manifest,
    )

    for ordinal, pass_result in enumerate(pass_results):
        plan = plans[ordinal]
        exact_results = [credited_results.get(task.task_id) for task in plan.tasks]
        if any(item is None for item in exact_results):
            raise ValueError("scheduler pass result omits an exact task result")
        typed_results = [item for item in exact_results if item is not None]
        if any(
            histories[item.task_id][-1].kind
            not in {
                SchedulerTaskEventKind.TERMINAL,
                SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
                SchedulerTaskEventKind.ACTIVATED_PREFLIGHT_TERMINAL,
            }
            for item in typed_results
        ):
            raise ValueError("scheduler pass result contains non-terminal task evidence")
        expected_pass_result = SchedulerPassResult.build(
            plan=plan,
            task_results=typed_results,
            recovery_promotion_bindings=tuple(
                SchedulerTruncationRecoveryPromotionBinding.from_promotion(
                    recovery_indexes.promotions[family_id]
                )
                for task in plan.tasks
                if (family_id := recovery_indexes.promotion_by_parent_task.get(task.task_id))
            ),
        )
        if pass_result != expected_pass_result:
            raise ValueError("scheduler pass result is not derived from its exact task results")

    SchedulerCampaignSummary.build(manifest=manifest, pass_results=pass_results)


def _validate_artifact_inventory(
    *,
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    directory_identities: dict[str, tuple[int, int, int]],
    plans: tuple[SchedulerPassPlan, ...],
    activations: tuple[SchedulerTaskActivation, ...],
    events: tuple[SchedulerTaskEvent, ...],
    outputs: tuple[SchedulerTaskOutput, ...],
    provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...],
    result_observations: tuple[SchedulerTaskResult, ...],
    pass_results: tuple[SchedulerPassResult, ...],
    truncation_recovery_entries: tuple[SchedulerTruncationRecoveryEntry, ...],
    terminal_report_authority: SchedulerTerminalReportAuthority | None,
    allow_pending_checkpoint: bool = False,
    allowed_immutable_write_temps: frozenset[str] = frozenset(),
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> None:
    _validate_control_layout(
        root_descriptor,
        directory_descriptors,
        directory_identities,
        allow_pending_checkpoint=allow_pending_checkpoint,
        allowed_immutable_write_temps=allowed_immutable_write_temps,
        allowed_published_immutable_targets=allowed_published_immutable_targets,
    )
    expected_children = {
        _ACTIVATIONS_DIRECTORY: {
            PurePosixPath(_activation_path(item)).name for item in activations
        },
        _EVENTS_DIRECTORY: {PurePosixPath(_event_path(index)).name for index in range(len(events))},
        _PASS_PLANS_DIRECTORY: {
            PurePosixPath(_pass_plan_path(index)).name for index in range(len(plans))
        },
        _PASS_RESULTS_DIRECTORY: {
            PurePosixPath(_pass_result_path(index)).name for index in range(len(pass_results))
        },
        _TASK_OUTPUTS_DIRECTORY: {PurePosixPath(_task_output_path(item)).name for item in outputs},
        _PROVIDER_ATTEMPTS_DIRECTORY: {
            PurePosixPath(_provider_attempt_path(item)).name for item in provider_attempts
        },
        _TASK_RESULTS_DIRECTORY: {
            PurePosixPath(_task_result_path(item)).name for item in result_observations
        },
        _TRUNCATION_RECOVERY_DIRECTORY: {
            PurePosixPath(_truncation_recovery_entry_path(item)).name
            for item in truncation_recovery_entries
        },
    }
    for directory_name, expected in expected_children.items():
        expected_with_temp = expected | {
            PurePosixPath(item).name
            for item in allowed_immutable_write_temps
            if PurePosixPath(item).parent == PurePosixPath(directory_name)
        }
        observed = (
            set(
                _bounded_directory_names(
                    directory_descriptors[directory_name],
                    limit=(
                        SCHEDULER_TRUNCATION_RECOVERY_MAX_ENTRIES
                        + len(expected_with_temp - expected)
                    ),
                    label="truncation recovery",
                )
            )
            if directory_name == _TRUNCATION_RECOVERY_DIRECTORY
            else set(os.listdir(directory_descriptors[directory_name]))
        )
        if observed != expected_with_temp:
            raise ValueError("scheduler journal contains an unmanifested child artifact")
    relative_files = _retained_child_artifact_paths(
        plans=plans,
        activations=activations,
        events=events,
        outputs=outputs,
        provider_attempts=provider_attempts,
        result_observations=result_observations,
        pass_results=pass_results,
        truncation_recovery_entries=truncation_recovery_entries,
    )
    for relative in relative_files:
        parent_descriptor, leaf = _relative_parent(
            root_descriptor,
            directory_descriptors,
            relative,
        )
        _require_private_file(
            parent_descriptor,
            leaf,
            allowed_published_identity=((allowed_published_immutable_targets or {}).get(relative)),
        )
    if terminal_report_authority is not None:
        _require_private_file(
            root_descriptor,
            _TERMINAL_REPORT_AUTHORITY_FILENAME,
            allowed_published_identity=(
                (allowed_published_immutable_targets or {}).get(_TERMINAL_REPORT_AUTHORITY_FILENAME)
            ),
        )


def _retained_child_artifact_paths(
    *,
    plans: tuple[SchedulerPassPlan, ...],
    activations: tuple[SchedulerTaskActivation, ...],
    events: tuple[SchedulerTaskEvent, ...],
    outputs: tuple[SchedulerTaskOutput, ...],
    provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...],
    result_observations: tuple[SchedulerTaskResult, ...],
    pass_results: tuple[SchedulerPassResult, ...],
    truncation_recovery_entries: tuple[SchedulerTruncationRecoveryEntry, ...],
) -> tuple[str, ...]:
    """Return every exact child path represented by retained scheduler state."""

    paths = (
        *(_activation_path(item) for item in activations),
        *(_event_path(index) for index in range(len(events))),
        *(_pass_plan_path(index) for index in range(len(plans))),
        *(_pass_result_path(index) for index in range(len(pass_results))),
        *(_task_output_path(item) for item in outputs),
        *(_provider_attempt_path(item) for item in provider_attempts),
        *(_task_result_path(item) for item in result_observations),
        *(_truncation_recovery_entry_path(item) for item in truncation_recovery_entries),
    )
    if len(paths) != len(set(paths)):
        raise ValueError("scheduler retained state repeats a durable artifact path")
    return tuple(sorted(paths))


def _observe_durable_artifacts(
    *,
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    relative_paths: tuple[str, ...],
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> tuple[_DurableArtifactObservation, ...]:
    """Read exact content and identity for a stable full-validation snapshot."""

    if len(relative_paths) != len(set(relative_paths)):
        raise ValueError("scheduler durable snapshot repeats an artifact path")
    observations: list[_DurableArtifactObservation] = []
    for relative in sorted(relative_paths):
        parent_descriptor, leaf = _relative_parent(
            root_descriptor,
            directory_descriptors,
            relative,
        )
        content, identity = _read_private_file_observation(
            parent_descriptor,
            leaf,
            allowed_published_identity=((allowed_published_immutable_targets or {}).get(relative)),
        )
        observations.append((relative, identity, hashlib.sha256(content).hexdigest()))
    return tuple(observations)


def _validate_control_layout(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    directory_identities: dict[str, tuple[int, int, int]],
    *,
    allow_pending_checkpoint: bool = False,
    allowed_immutable_write_temps: frozenset[str] = frozenset(),
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> None:
    """Reject linked or unexpected structure before enumerating child evidence."""

    expected_root = {
        _LOCK_FILENAME,
        _MANIFEST_FILENAME,
        _ANALYSIS_INPUT_INVENTORY_FILENAME,
        _JOURNAL_HEAD_CHECKPOINT_FILENAME,
        *_CONTROL_DIRECTORIES,
    }
    observed_root = set(os.listdir(root_descriptor))
    expected_root.update(
        PurePosixPath(item).name
        for item in allowed_immutable_write_temps
        if len(PurePosixPath(item).parts) == 1
    )
    if allow_pending_checkpoint and _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME in observed_root:
        expected_root.add(_JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME)
    if allow_pending_checkpoint and _JOURNAL_TRANSITION_PREDECESSOR_FILENAME in observed_root:
        expected_root.add(_JOURNAL_TRANSITION_PREDECESSOR_FILENAME)
    if _TERMINAL_REPORT_AUTHORITY_FILENAME in observed_root:
        expected_root.add(_TERMINAL_REPORT_AUTHORITY_FILENAME)
    if observed_root != expected_root:
        raise ValueError("scheduler journal contains an unmanifested root artifact")
    root_metadata = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise ValueError("scheduler journal root must remain a private directory")
    if set(directory_descriptors) != set(_CONTROL_DIRECTORIES) or set(directory_identities) != set(
        _CONTROL_DIRECTORIES
    ):
        raise ValueError("scheduler journal directory custody is incomplete")
    for name in _CONTROL_DIRECTORIES:
        descriptor_metadata = os.fstat(directory_descriptors[name])
        entry_metadata = _stat_entry(root_descriptor, name)
        if (
            not stat.S_ISDIR(descriptor_metadata.st_mode)
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o700
            or _directory_identity(descriptor_metadata) != directory_identities[name]
            or _directory_identity(entry_metadata) != directory_identities[name]
            or stat.S_ISLNK(entry_metadata.st_mode)
        ):
            raise ValueError("scheduler journal directories must remain private and unlinked")
    allowed_targets = allowed_published_immutable_targets or {}
    _require_private_file(root_descriptor, _LOCK_FILENAME)
    _require_private_file(
        root_descriptor,
        _MANIFEST_FILENAME,
        allowed_published_identity=allowed_targets.get(_MANIFEST_FILENAME),
    )
    _require_private_file(
        root_descriptor,
        _ANALYSIS_INPUT_INVENTORY_FILENAME,
        allowed_published_identity=allowed_targets.get(_ANALYSIS_INPUT_INVENTORY_FILENAME),
    )
    _require_private_file(
        root_descriptor,
        _JOURNAL_HEAD_CHECKPOINT_FILENAME,
        allowed_published_identity=allowed_targets.get(_JOURNAL_HEAD_CHECKPOINT_FILENAME),
    )
    if _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME in observed_root:
        _require_private_file(
            root_descriptor,
            _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
            allowed_published_identity=allowed_targets.get(
                _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME
            ),
        )
    if _JOURNAL_TRANSITION_PREDECESSOR_FILENAME in observed_root:
        _require_private_file(
            root_descriptor,
            _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            allowed_published_identity=allowed_targets.get(
                _JOURNAL_TRANSITION_PREDECESSOR_FILENAME
            ),
        )
    if _TERMINAL_REPORT_AUTHORITY_FILENAME in observed_root:
        _require_private_file(
            root_descriptor,
            _TERMINAL_REPORT_AUTHORITY_FILENAME,
            allowed_published_identity=allowed_targets.get(_TERMINAL_REPORT_AUTHORITY_FILENAME),
        )


def _require_private_file(
    parent_descriptor: int,
    leaf: str,
    *,
    allowed_published_identity: _EvidenceFileIdentity | None = None,
) -> None:
    metadata = _stat_entry(parent_descriptor, leaf)
    identity = _evidence_file_identity(metadata)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (
            identity != allowed_published_identity
            if allowed_published_identity is not None
            else metadata.st_nlink != 1
        )
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or stat.S_ISLNK(metadata.st_mode)
    ):
        raise ValueError("scheduler journal files must remain private unshared regular files")


def _write_model(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    relative: str,
    model: StrictModel,
) -> None:
    content = stable_json(model).encode("utf-8")
    if not content or len(content) > _MAX_EVIDENCE_BYTES:
        raise ValueError("scheduler journal artifact exceeds its output bound")
    parent_descriptor, leaf = _relative_parent(
        root_descriptor,
        directory_descriptors,
        relative,
    )
    root_names = set(os.listdir(root_descriptor))
    if (
        _JOURNAL_HEAD_CHECKPOINT_FILENAME in root_names
        and relative
        not in {
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
            _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
            _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
        }
        and _JOURNAL_TRANSITION_PREDECESSOR_FILENAME not in root_names
    ):
        predecessor = _read_private_file(
            root_descriptor,
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
        )
        _write_fresh_private_file(
            root_descriptor,
            _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            predecessor,
        )
    _write_fresh_private_file(parent_descriptor, leaf, content)


def _read_model[ModelT: StrictModel](
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    relative: str,
    model_type: type[ModelT],
    *,
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> ModelT:
    parent_descriptor, leaf = _relative_parent(
        root_descriptor,
        directory_descriptors,
        relative,
    )
    allowed_targets = allowed_published_immutable_targets or {}
    content = _read_private_file(
        parent_descriptor,
        leaf,
        allowed_published_identity=allowed_targets.get(relative),
    )
    try:
        model = model_type.model_validate(json.loads(content))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("scheduler journal artifact is invalid") from exc
    if content != stable_json(model).encode("utf-8"):
        raise ValueError("scheduler journal artifact is not canonical")
    return model


@contextmanager
def _open_model_observation[ModelT: StrictModel](
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    relative: str,
    model_type: type[ModelT],
) -> Iterator[ModelT]:
    """Hold one exact canonical journal model descriptor through caller validation."""

    parent_descriptor, leaf = _relative_parent(
        root_descriptor,
        directory_descriptors,
        relative,
    )
    before = _stat_entry(parent_descriptor, leaf)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > _MAX_EVIDENCE_BYTES
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise ValueError("scheduler journal artifact must be a bounded private regular file")
    descriptor = -1
    try:
        descriptor = os.open(
            leaf,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if _evidence_file_identity(opened) != _evidence_file_identity(before):
            raise ValueError("scheduler journal artifact changed before observation")
        content = _read_descriptor(descriptor)
        finished = os.fstat(descriptor)
        after_read = _stat_entry(parent_descriptor, leaf)
        identities = {
            _evidence_file_identity(before),
            _evidence_file_identity(opened),
            _evidence_file_identity(finished),
            _evidence_file_identity(after_read),
        }
        if len(identities) != 1 or len(content) != after_read.st_size:
            raise ValueError("scheduler journal artifact changed while being observed")
        try:
            model = model_type.model_validate(json.loads(content))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("scheduler journal artifact is invalid") from exc
        if content != stable_json(model).encode("utf-8"):
            raise ValueError("scheduler journal artifact is not canonical")
        try:
            yield model
        finally:
            descriptor_after = os.fstat(descriptor)
            path_after = _stat_entry(parent_descriptor, leaf)
            if (
                _evidence_file_identity(descriptor_after) != _evidence_file_identity(before)
                or _evidence_file_identity(path_after) != _evidence_file_identity(before)
                or path_after.st_nlink != 1
            ):
                raise ValueError("scheduler journal artifact changed during validation")
    except OSError as exc:
        raise ValueError("scheduler journal artifact could not be observed safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _relative_parent(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    relative: str,
) -> tuple[int, str]:
    path = PurePosixPath(relative)
    if (
        str(path) != relative
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(path.parts) not in {1, 2}
    ):
        raise ValueError("scheduler journal path is not one normalized controlled artifact")
    if len(path.parts) == 1:
        return root_descriptor, path.parts[0]
    directory, leaf = path.parts
    if directory not in directory_descriptors:
        raise ValueError("scheduler journal artifact parent is not under held custody")
    return directory_descriptors[directory], leaf


def _immutable_write_temp_leaf(leaf: str) -> str:
    if (
        PurePosixPath(leaf).name != leaf
        or leaf in {"", ".", ".."}
        or leaf.startswith(_IMMUTABLE_WRITE_TEMP_PREFIX)
    ):
        raise ValueError("scheduler immutable output leaf is invalid")
    temporary_leaf = f"{_IMMUTABLE_WRITE_TEMP_PREFIX}{leaf}{_IMMUTABLE_WRITE_TEMP_SUFFIX}"
    if len(os.fsencode(temporary_leaf)) > 255:
        raise ValueError("scheduler immutable output temp name exceeds its bound")
    return temporary_leaf


def _write_fresh_private_file(parent_descriptor: int, leaf: str, content: bytes) -> None:
    """Publish one immutable file through a fully fsynced hidden temp and rename."""

    if not content or len(content) > _MAX_EVIDENCE_BYTES:
        raise ValueError("scheduler journal artifact exceeds its output bound")
    temporary_leaf = _immutable_write_temp_leaf(leaf)
    observed_names = set(os.listdir(parent_descriptor))
    if leaf in observed_names or temporary_leaf in observed_names:
        raise ValueError("scheduler immutable output destination is not fresh")
    _write_exclusive_private_file(parent_descriptor, temporary_leaf, content)
    temporary = _stat_entry(parent_descriptor, temporary_leaf)
    temporary_identity = (temporary.st_dev, temporary.st_ino)
    temporary_removed = False
    try:
        os.link(
            temporary_leaf,
            leaf,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.fsync(parent_descriptor)
        temporary_after_link = _stat_entry(parent_descriptor, temporary_leaf)
        target_after_link = _stat_entry(parent_descriptor, leaf)
        if (
            (temporary_after_link.st_dev, temporary_after_link.st_ino) != temporary_identity
            or _evidence_file_identity(temporary_after_link)
            != _evidence_file_identity(target_after_link)
            or temporary_after_link.st_nlink != 2
            or stat.S_IMODE(temporary_after_link.st_mode) != 0o600
        ):
            raise ValueError("scheduler immutable output link publication is inconsistent")
        os.unlink(temporary_leaf, dir_fd=parent_descriptor)
        temporary_removed = True
        os.fsync(parent_descriptor)
        observed_content, observed_identity = _read_private_file_observation(
            parent_descriptor,
            leaf,
        )
        if (
            observed_content != content
            or observed_identity[:2] != temporary_identity
            or stat.S_IMODE(observed_identity[2]) != 0o600
            or observed_identity[3] != 1
            or temporary_leaf in set(os.listdir(parent_descriptor))
        ):
            raise ValueError("scheduler immutable output changed while being published")
    except OSError as exc:
        raise ValueError("scheduler immutable output could not be published safely") from exc
    finally:
        if not temporary_removed:
            _unlink_created_file(parent_descriptor, temporary_leaf, temporary_identity)


def _write_exclusive_private_file(parent_descriptor: int, leaf: str, content: bytes) -> None:
    """Write and fsync one exact private leaf without publishing journal state."""

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG
    descriptor = -1
    created_identity: tuple[int, int] | None = None
    completed = False
    try:
        descriptor = os.open(leaf, flags, 0o600, dir_fd=parent_descriptor)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        created_identity = opened.st_dev, opened.st_ino
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError("scheduler journal output is not a fresh private file")
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("scheduler journal write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        written_metadata = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        readback = _read_descriptor(descriptor)
        verified_metadata = os.fstat(descriptor)
        entry_metadata = _stat_entry(parent_descriptor, leaf)
        if (
            readback != content
            or created_identity != (entry_metadata.st_dev, entry_metadata.st_ino)
            or _evidence_file_identity(written_metadata)
            != _evidence_file_identity(verified_metadata)
            or _evidence_file_identity(verified_metadata) != _evidence_file_identity(entry_metadata)
            or verified_metadata.st_nlink != 1
            or stat.S_IMODE(verified_metadata.st_mode) != 0o600
        ):
            raise ValueError("scheduler journal output changed while being written")
        os.fsync(parent_descriptor)
        completed = True
    except OSError as exc:
        raise ValueError("scheduler journal output could not be written safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not completed and created_identity is not None:
            _unlink_created_file(parent_descriptor, leaf, created_identity)


def _is_allowed_immutable_write_target(parent: str | None, leaf: str) -> bool:
    if parent is None:
        return leaf in {
            _MANIFEST_FILENAME,
            _ANALYSIS_INPUT_INVENTORY_FILENAME,
            _JOURNAL_HEAD_CHECKPOINT_FILENAME,
            _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
            _JOURNAL_TRANSITION_PREDECESSOR_FILENAME,
            _TERMINAL_REPORT_AUTHORITY_FILENAME,
        }
    content_addressed = (
        re.fullmatch(
            r"scheduler-task-[0-9a-f]{64}-[0-9a-f]{64}\.json",
            leaf,
        )
        is not None
    )
    if parent in {
        _ACTIVATIONS_DIRECTORY,
        _TASK_OUTPUTS_DIRECTORY,
        _TASK_RESULTS_DIRECTORY,
        _PROVIDER_ATTEMPTS_DIRECTORY,
    }:
        return content_addressed
    if parent == _EVENTS_DIRECTORY:
        return re.fullmatch(r"event-[0-9]{8}\.json", leaf) is not None
    if parent == _PASS_PLANS_DIRECTORY:
        return re.fullmatch(r"pass-0[1-7]-plan\.json", leaf) is not None
    if parent == _PASS_RESULTS_DIRECTORY:
        return re.fullmatch(r"pass-0[1-7]-result\.json", leaf) is not None
    if parent == _TRUNCATION_RECOVERY_DIRECTORY:
        kinds = "|".join(
            re.escape(item.value.lower().replace("_", "-"))
            for item in SchedulerTruncationRecoveryEntryKind
        )
        return (
            re.fullmatch(
                rf"entry-[0-9]{{8}}-(?:{kinds})-[0-9a-f]{{64}}\.json",
                leaf,
            )
            is not None
        )
    return False


def _inspect_orphan_immutable_writes(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
) -> tuple[_OrphanImmutableWrite, ...]:
    """Validate at most one private hidden temp without trusting its partial bytes."""

    parents = (
        (None, root_descriptor),
        *((name, directory_descriptors[name]) for name in _CONTROL_DIRECTORIES),
    )
    orphans: list[_OrphanImmutableWrite] = []
    for parent, descriptor in parents:
        names = set(os.listdir(descriptor))
        for temporary_leaf in sorted(names):
            if not temporary_leaf.startswith(_IMMUTABLE_WRITE_TEMP_PREFIX):
                continue
            if not temporary_leaf.endswith(_IMMUTABLE_WRITE_TEMP_SUFFIX):
                raise ValueError("scheduler immutable output temp name is malformed")
            target_leaf = temporary_leaf[
                len(_IMMUTABLE_WRITE_TEMP_PREFIX) : -len(_IMMUTABLE_WRITE_TEMP_SUFFIX)
            ]
            if (
                not _is_allowed_immutable_write_target(parent, target_leaf)
                or _immutable_write_temp_leaf(target_leaf) != temporary_leaf
            ):
                raise ValueError("scheduler immutable output temp target is invalid")
            metadata = _stat_entry(descriptor, temporary_leaf)
            target_present = target_leaf in names
            target_metadata = _stat_entry(descriptor, target_leaf) if target_present else None
            published_target = target_metadata is not None
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != (2 if published_target else 1)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > _MAX_EVIDENCE_BYTES
                or stat.S_ISLNK(metadata.st_mode)
                or (
                    target_metadata is not None
                    and _evidence_file_identity(target_metadata)
                    != _evidence_file_identity(metadata)
                )
            ):
                raise ValueError("scheduler immutable output temp is not bounded and private")
            orphans.append(
                _OrphanImmutableWrite(
                    parent=parent,
                    temporary_leaf=temporary_leaf,
                    target_leaf=target_leaf,
                    identity=_evidence_file_identity(metadata),
                    published_target=published_target,
                )
            )
            if len(orphans) > 1:
                raise ValueError("scheduler journal has more than one interrupted immutable write")
    return tuple(orphans)


def _cleanup_orphan_immutable_writes(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    orphans: tuple[_OrphanImmutableWrite, ...],
) -> None:
    """Discard only the exact uncommitted temp observations admitted during resume."""

    for orphan in orphans:
        if orphan.published_target:
            raise ValueError("scheduler published immutable temp requires finalization")
        descriptor = (
            root_descriptor if orphan.parent is None else directory_descriptors[orphan.parent]
        )
        names = set(os.listdir(descriptor))
        metadata = _stat_entry(descriptor, orphan.temporary_leaf)
        if _evidence_file_identity(metadata) != orphan.identity or orphan.target_leaf in names:
            raise ValueError("scheduler immutable output temp changed before cleanup")
        try:
            os.unlink(orphan.temporary_leaf, dir_fd=descriptor)
            os.fsync(descriptor)
        except OSError as exc:
            raise ValueError("scheduler immutable output temp could not be cleaned safely") from exc


def _finalize_published_immutable_writes(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    orphans: tuple[_OrphanImmutableWrite, ...],
) -> None:
    """Drop only the temp link of an exact already-published no-replace artifact."""

    for orphan in orphans:
        if not orphan.published_target:
            continue
        descriptor = (
            root_descriptor if orphan.parent is None else directory_descriptors[orphan.parent]
        )
        temporary = _stat_entry(descriptor, orphan.temporary_leaf)
        target = _stat_entry(descriptor, orphan.target_leaf)
        if (
            _evidence_file_identity(temporary) != orphan.identity
            or _evidence_file_identity(target) != orphan.identity
            or temporary.st_nlink != 2
        ):
            raise ValueError("scheduler published immutable temp changed before finalization")
        try:
            os.unlink(orphan.temporary_leaf, dir_fd=descriptor)
            os.fsync(descriptor)
        except OSError as exc:
            raise ValueError(
                "scheduler published immutable temp could not be finalized safely"
            ) from exc
        finalized = _stat_entry(descriptor, orphan.target_leaf)
        if (
            (finalized.st_dev, finalized.st_ino) != orphan.identity[:2]
            or finalized.st_nlink != 1
            or stat.S_IMODE(finalized.st_mode) != 0o600
        ):
            raise ValueError("scheduler published immutable target changed after finalization")


def _replace_private_file(parent_descriptor: int, leaf: str, content: bytes) -> None:
    """Atomically replace one descriptor-held private file or leave a fail-closed marker."""

    if not content or len(content) > _MAX_EVIDENCE_BYTES:
        raise ValueError("scheduler journal checkpoint exceeds its output bound")
    _require_private_file(parent_descriptor, leaf)
    _write_fresh_private_file(
        parent_descriptor,
        _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
        content,
    )
    pending = _stat_entry(parent_descriptor, _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME)
    pending_identity = (pending.st_dev, pending.st_ino)
    replaced = False
    try:
        os.replace(
            _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
            leaf,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        replaced = True
        os.fsync(parent_descriptor)
        observed_content, observed_identity = _read_private_file_observation(
            parent_descriptor,
            leaf,
        )
        if (
            observed_content != content
            or observed_identity[:2] != pending_identity
            or stat.S_IMODE(observed_identity[2]) != 0o600
            or observed_identity[3] != 1
        ):
            raise ValueError("scheduler journal checkpoint changed while being replaced")
    except OSError as exc:
        raise ValueError("scheduler journal checkpoint could not be replaced safely") from exc
    finally:
        if not replaced:
            _unlink_created_file(
                parent_descriptor,
                _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
                pending_identity,
            )


def _adopt_pending_private_file(
    parent_descriptor: int,
    leaf: str,
    content: bytes,
) -> None:
    """Finish an already-fsynced exact checkpoint replacement after process death."""

    _require_private_file(parent_descriptor, leaf)
    _require_private_file(parent_descriptor, _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME)
    pending_content, pending_observation = _read_private_file_observation(
        parent_descriptor,
        _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
    )
    if pending_content != content:
        raise ValueError("scheduler pending journal checkpoint differs from durable state")
    pending_identity = pending_observation[:2]
    try:
        os.replace(
            _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME,
            leaf,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
        observed_content, observed_identity = _read_private_file_observation(
            parent_descriptor,
            leaf,
        )
    except OSError as exc:
        raise ValueError(
            "scheduler pending journal checkpoint could not be adopted safely"
        ) from exc
    if (
        observed_content != content
        or observed_identity[:2] != pending_identity
        or stat.S_IMODE(observed_identity[2]) != 0o600
        or observed_identity[3] != 1
        or _JOURNAL_HEAD_CHECKPOINT_PENDING_FILENAME in set(os.listdir(parent_descriptor))
    ):
        raise ValueError("scheduler pending journal checkpoint changed while being adopted")


def _read_private_file(
    parent_descriptor: int,
    leaf: str,
    *,
    allowed_published_identity: _EvidenceFileIdentity | None = None,
) -> bytes:
    return _read_private_file_observation(
        parent_descriptor,
        leaf,
        allowed_published_identity=allowed_published_identity,
    )[0]


def _read_private_file_observation(
    parent_descriptor: int,
    leaf: str,
    *,
    allowed_published_identity: _EvidenceFileIdentity | None = None,
) -> tuple[bytes, _EvidenceFileIdentity]:
    first = _read_private_file_once(
        parent_descriptor,
        leaf,
        allowed_published_identity=allowed_published_identity,
    )
    second = _read_private_file_once(
        parent_descriptor,
        leaf,
        allowed_published_identity=allowed_published_identity,
    )
    if first != second:
        raise ValueError("scheduler journal artifact changed while being observed")
    return second


def _read_private_file_once(
    parent_descriptor: int,
    leaf: str,
    *,
    allowed_published_identity: _EvidenceFileIdentity | None = None,
) -> tuple[bytes, _EvidenceFileIdentity]:
    before = _stat_entry(parent_descriptor, leaf)
    before_identity = _evidence_file_identity(before)
    if (
        not stat.S_ISREG(before.st_mode)
        or (
            before_identity != allowed_published_identity
            if allowed_published_identity is not None
            else before.st_nlink != 1
        )
        or before.st_size > _MAX_EVIDENCE_BYTES
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise ValueError("scheduler journal artifact must be a bounded private regular file")
    descriptor = -1
    try:
        descriptor = os.open(
            leaf,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        if _evidence_file_identity(opened) != _evidence_file_identity(before):
            raise ValueError("scheduler journal artifact changed before it was read")
        content = _read_descriptor(descriptor)
        finished = os.fstat(descriptor)
        after = _stat_entry(parent_descriptor, leaf)
    except OSError as exc:
        raise ValueError("scheduler journal artifact could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identities = {
        _evidence_file_identity(before),
        _evidence_file_identity(opened),
        _evidence_file_identity(finished),
        _evidence_file_identity(after),
    }
    expected_nlink = 2 if allowed_published_identity is not None else 1
    if len(identities) != 1 or len(content) != after.st_size or after.st_nlink != expected_nlink:
        raise ValueError("scheduler journal artifact changed while it was read")
    return content, _evidence_file_identity(after)


def _read_descriptor(descriptor: int) -> bytes:
    content = bytearray()
    while len(content) <= _MAX_EVIDENCE_BYTES:
        chunk = os.read(
            descriptor,
            min(_READ_CHUNK_BYTES, _MAX_EVIDENCE_BYTES + 1 - len(content)),
        )
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > _MAX_EVIDENCE_BYTES:
        raise ValueError("scheduler journal artifact exceeds its read bound")
    return bytes(content)


def _unlink_created_file(
    parent_descriptor: int,
    leaf: str,
    created_identity: tuple[int, int],
) -> None:
    try:
        metadata = _stat_entry(parent_descriptor, leaf)
        if (metadata.st_dev, metadata.st_ino) == created_identity:
            os.unlink(leaf, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
    except (OSError, ValueError):
        return


def _unlink_exact_private_file(
    parent_descriptor: int,
    leaf: str,
    expected_content: bytes,
) -> None:
    content, identity = _read_private_file_observation(parent_descriptor, leaf)
    if content != expected_content:
        raise ValueError("scheduler staged private file differs before cleanup")
    try:
        current = _stat_entry(parent_descriptor, leaf)
        if _evidence_file_identity(current) != identity:
            raise ValueError("scheduler staged private file changed before cleanup")
        os.unlink(leaf, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise ValueError("scheduler staged private file could not be cleaned safely") from exc


def _event_path(index: int) -> str:
    return f"{_EVENTS_DIRECTORY}/event-{index:08d}.json"


def _activation_path(activation: SchedulerTaskActivation) -> str:
    return f"{_ACTIVATIONS_DIRECTORY}/{activation.task_id}-{activation.activation_sha256}.json"


def _pass_plan_path(ordinal: int) -> str:
    return f"{_PASS_PLANS_DIRECTORY}/pass-{ordinal + 1:02d}-plan.json"


def _pass_result_path(ordinal: int) -> str:
    return f"{_PASS_RESULTS_DIRECTORY}/pass-{ordinal + 1:02d}-result.json"


def _task_result_path(result: SchedulerTaskResult) -> str:
    return f"{_TASK_RESULTS_DIRECTORY}/{result.task_id}-{result.result_sha256}.json"


def _task_output_path(output: SchedulerTaskOutput) -> str:
    return f"{_TASK_OUTPUTS_DIRECTORY}/{output.task_id}-{output.output_artifact_sha256}.json"


def _provider_attempt_path(attempt: SchedulerProviderAttemptEvidence) -> str:
    return (
        f"{_PROVIDER_ATTEMPTS_DIRECTORY}/{attempt.task_id}-{attempt.attempt_evidence_sha256}.json"
    )


def _truncation_recovery_entry_path(entry: SchedulerTruncationRecoveryEntry) -> str:
    kind = entry.entry_kind.value.lower().replace("_", "-")
    return (
        f"{_TRUNCATION_RECOVERY_DIRECTORY}/entry-{entry.entry_index:08d}-"
        f"{kind}-{entry.entry_sha256}.json"
    )


def _create_private_root(path: Path) -> None:
    _reject_linked_components(path.parent)
    if path.exists() or path.is_symlink() or path.is_junction():
        raise ValueError("scheduler journal destination must be fresh")
    try:
        path.mkdir(mode=0o700)
    except OSError as exc:
        raise ValueError("scheduler journal root could not be created privately") from exc


def _open_private_root(path: Path) -> tuple[int, tuple[int, int, int]]:
    _reject_linked_components(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError("scheduler journal root is unavailable") from exc
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o700
        or path.is_symlink()
        or path.is_junction()
    ):
        raise ValueError("scheduler journal root must be a private unlinked directory")
    if not _NOFOLLOW_FLAG or not _DIRECTORY_FLAG or os.open not in os.supports_dir_fd:
        raise ValueError("scheduler journal descriptor-safe custody is unavailable")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | _DIRECTORY_FLAG | _NOFOLLOW_FLAG | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise ValueError("scheduler journal root could not be opened safely") from exc
    opened = os.fstat(descriptor)
    identity = _directory_identity(before)
    if _directory_identity(opened) != identity:
        os.close(descriptor)
        raise ValueError("scheduler journal root changed while opening custody")
    return descriptor, identity


def _open_control_directories(
    root_descriptor: int,
    *,
    create: bool,
) -> tuple[dict[str, int], dict[str, tuple[int, int, int]]]:
    descriptors: dict[str, int] = {}
    identities: dict[str, tuple[int, int, int]] = {}
    try:
        for name in _CONTROL_DIRECTORIES:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=root_descriptor)
                except OSError as exc:
                    raise ValueError(
                        "scheduler journal control directory could not be created privately"
                    ) from exc
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | _DIRECTORY_FLAG | _NOFOLLOW_FLAG | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=root_descriptor,
                )
            except OSError as exc:
                raise ValueError("scheduler journal control directory is unavailable") from exc
            try:
                opened = os.fstat(descriptor)
                entry = _stat_entry(root_descriptor, name)
                identity = _directory_identity(opened)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or stat.S_IMODE(opened.st_mode) != 0o700
                    or _directory_identity(entry) != identity
                    or stat.S_ISLNK(entry.st_mode)
                ):
                    raise ValueError(
                        "scheduler journal control directory must be private and unlinked"
                    )
            except BaseException:
                os.close(descriptor)
                raise
            descriptors[name] = descriptor
            identities[name] = identity
        return descriptors, identities
    except BaseException:
        for descriptor in descriptors.values():
            os.close(descriptor)
        raise


def _acquire_custody_lock(root_descriptor: int, *, create: bool) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | _NOFOLLOW_FLAG
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(_LOCK_FILENAME, flags, 0o600, dir_fd=root_descriptor)
    except OSError as exc:
        raise ValueError("scheduler custody lock is unavailable") from exc
    try:
        if create:
            os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        observed = _stat_entry(root_descriptor, _LOCK_FILENAME)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or _file_identity(metadata) != _file_identity(observed)
            or stat.S_ISLNK(observed.st_mode)
        ):
            raise ValueError("scheduler custody lock must be a private unshared regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise ValueError("scheduler journal already has live custody") from exc
            raise
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _register_live_custody(identity: tuple[int, int]) -> None:
    with _LIVE_CUSTODY_LOCK:
        if identity in _LIVE_CUSTODY:
            raise ValueError("scheduler journal already has live in-process custody")
        _LIVE_CUSTODY.add(identity)


def _release_failed_open(
    *,
    root_descriptor: int,
    root_identity: tuple[int, int, int] | None,
    lock_descriptor: int,
    directory_descriptors: dict[str, int],
    registered: bool,
) -> None:
    if registered and root_identity is not None:
        with _LIVE_CUSTODY_LOCK:
            _LIVE_CUSTODY.discard(root_identity[:2])
    if lock_descriptor >= 0:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)
    for descriptor in directory_descriptors.values():
        os.close(descriptor)
    if root_descriptor >= 0:
        os.close(root_descriptor)


def _assert_root_path_identity(
    path: Path,
    root_descriptor: int,
    expected: tuple[int, int, int],
) -> None:
    try:
        opened = os.fstat(root_descriptor)
        current = path.lstat()
    except OSError as exc:
        raise ValueError("scheduler journal root changed during live custody") from exc
    if (
        _directory_identity(opened) != expected
        or _directory_identity(current) != expected
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_IMODE(current.st_mode) != 0o700
        or stat.S_ISLNK(current.st_mode)
        or path.is_junction()
    ):
        raise ValueError("scheduler journal root changed during live custody")


def _assert_descriptor_custody(
    *,
    path: Path,
    root_descriptor: int,
    root_identity: tuple[int, int, int],
    directory_descriptors: dict[str, int],
    directory_identities: dict[str, tuple[int, int, int]],
    allow_pending_checkpoint: bool = False,
    allowed_immutable_write_temps: frozenset[str] = frozenset(),
    allowed_published_immutable_targets: dict[
        str,
        _EvidenceFileIdentity,
    ]
    | None = None,
) -> None:
    _assert_root_path_identity(path, root_descriptor, root_identity)
    _validate_control_layout(
        root_descriptor,
        directory_descriptors,
        directory_identities,
        allow_pending_checkpoint=allow_pending_checkpoint,
        allowed_immutable_write_temps=allowed_immutable_write_temps,
        allowed_published_immutable_targets=allowed_published_immutable_targets,
    )


def _reject_linked_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError("scheduler journal path may not traverse a link")
    except OSError as exc:
        raise ValueError("scheduler journal path is unavailable") from exc


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink


def _evidence_file_identity(
    metadata: os.stat_result,
) -> _EvidenceFileIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stat_entry(parent_descriptor: int, leaf: str) -> os.stat_result:
    try:
        return os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("scheduler journal entry is unavailable") from exc
