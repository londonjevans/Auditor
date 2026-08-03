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
import stat
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import BaseModel

from mmaudit.models.scheduler import (
    ABSENT_COST_LEDGER_BASELINE_SHA256,
    SCHEDULER_PASS_ORDER,
    SchedulerAnalysisInputInventory,
    SchedulerArtifact,
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
    build_scheduler_model_request_evidence,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    CandidateFinding,
    ContextRequestEvidence,
    Finding,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRequest,
    ReportQualityReview,
    Severity,
    SpecialistAcceptedOutcome,
    StrictModel,
    UsageRecord,
)
from mmaudit.models.usage import (
    _issue_trusted_usage_recovery_scope,
    _recover_trusted_usage_records,
    _TrustedUsageRecoveryScope,
    is_creditable_usage_record,
)
from mmaudit.orchestration.budgets import (
    _issue_trusted_budget_recovery_scope,
    _TrustedBudgetRecoveryScope,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    cost_entry_sha256,
)
from mmaudit.reporting.json_report import stable_json

_LOCK_FILENAME = ".scheduler.lock"
_MANIFEST_FILENAME = "manifest.json"
_ANALYSIS_INPUT_INVENTORY_FILENAME = "analysis-input-inventory.json"
_TERMINAL_REPORT_AUTHORITY_FILENAME = "terminal-report-authority.json"
_ACTIVATIONS_DIRECTORY = "activations"
_EVENTS_DIRECTORY = "events"
_PASS_PLANS_DIRECTORY = "pass-plans"
_PASS_RESULTS_DIRECTORY = "pass-results"
_TASK_OUTPUTS_DIRECTORY = "task-outputs"
_TASK_RESULTS_DIRECTORY = "task-results"
_PROVIDER_ATTEMPTS_DIRECTORY = "provider-attempts"
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
)
_LIVE_CUSTODY_LOCK = threading.Lock()
_LIVE_CUSTODY: set[tuple[int, int]] = set()
type _EvidenceFileIdentity = tuple[int, int, int, int, int, int, int]
type _DurableArtifactObservation = tuple[str, _EvidenceFileIdentity, str]
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
        terminal_report_authority: SchedulerTerminalReportAuthority | None = None,
        read_only: bool = False,
    ) -> None:
        self.path = path
        self._root_descriptor = root_descriptor
        self._root_identity = root_identity
        self._directory_descriptors = directory_descriptors
        self._directory_identities = directory_identities
        self._lock_descriptor = lock_descriptor
        self._closed = False
        self._read_only = read_only
        self._usage_recovery_scope: _TrustedUsageRecoveryScope | None = None
        self.manifest = manifest
        self.analysis_input_inventory = analysis_input_inventory
        self._plans = list(plans)
        self._activations = list(activations)
        self._events = list(events)
        self._outputs = list(outputs)
        self._provider_attempts = list(provider_attempts)
        self._result_observations = list(result_observations)
        self._pass_results = list(pass_results)
        self._terminal_report_authority = terminal_report_authority
        self._indexes = _derive_scheduler_journal_indexes(
            plans=self._plans,
            activations=self._activations,
            outputs=self._outputs,
            provider_attempts=self._provider_attempts,
            result_observations=self._result_observations,
            events=self._events,
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
        return tuple(sorted(self._outputs, key=lambda item: item.task_id))

    @property
    def provider_attempts(self) -> tuple[SchedulerProviderAttemptEvidence, ...]:
        return tuple(sorted(self._provider_attempts, key=lambda item: item.task_id))

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
        return tuple(self._pass_results)

    @property
    def terminal_report_authority(self) -> SchedulerTerminalReportAuthority | None:
        """Return the validated private terminal report projection, when sealed."""

        self._assert_live_custody()
        return self._terminal_report_authority

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
            outputs=self.outputs,
            provider_attempts=self.provider_attempts,
            task_results=self.task_results,
            result_observations=self.result_observations,
            events=self.events,
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
    def retained_provider_usage_records(self) -> tuple[UsageRecord, ...]:
        """Return every retained provider completion for accounting, without REAL credit."""

        records = tuple(
            UsageRecord.model_validate(output.model_completion_evidence.usage_record.model_dump())
            for output in self.outputs
            if output.model_completion_evidence is not None
        ) + tuple(
            UsageRecord.model_validate(attempt.usage_record.model_dump())
            for attempt in self.provider_attempts
        )
        request_ids = tuple(record.request_id for record in records)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("scheduler retained usage repeats a logical request identity")
        return tuple(sorted(records, key=lambda item: item.request_id))

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
        records = tuple(
            UsageRecord.model_validate(output.model_completion_evidence.usage_record.model_dump())
            for output in self.outputs
            if (output.task_id in successful and output.model_completion_evidence is not None)
        )
        return tuple(sorted(records, key=lambda item: item.request_id))

    @property
    def restorable_review_usage_records(self) -> tuple[UsageRecord, ...]:
        """Return only usage attached to a durably credited successful review result."""

        successful = {
            result.task_id
            for result in self.task_results
            if result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
        }
        records = tuple(
            UsageRecord.model_validate(output.model_completion_evidence.usage_record.model_dump())
            for output in self.outputs
            if (
                output.task_id in successful
                and output.model_completion_evidence is not None
                and is_creditable_usage_record(
                    output.model_completion_evidence.usage_record,
                    require_real=True,
                )
            )
        )
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
        return records, _issue_trusted_budget_recovery_scope(
            records,
            non_usage_attempts=recovered_attempts,
            cost_ledger_baseline=self.manifest.cost_ledger_baseline,
        )

    def recover_active_cost_reservations(
        self,
        atomic_ledger: AtomicCostLedger,
    ) -> tuple[SchedulerCostRecoveryRecord, ...]:
        """Conclude campaign-owned durable reservations from exact journal ordering.

        A task whose last durable event is ACTIVATED proves transport was never
        entered, so its exact reservation is adopted for one resumed dispatch.
        A task durably marked DISPATCHED is never retried; an unknown provider
        charge is conservatively accounted at the full reservation.
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
        grouped_entries: dict[str, list[tuple[int, CostEntry]]] = {}
        for entry in atomic_ledger.snapshot().entries:
            if entry.status not in {
                CostEntryStatus.RESERVED,
                CostEntryStatus.UNCERTAIN_ACCOUNTED,
            }:
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
            tuple[str, SchedulerTaskPlan, list[tuple[int, CostEntry]], bool]
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
                validated_groups.append((logical_request_id, task, entries, False))
                continue
            if (
                not was_dispatched
                or terminal_result is None
                or terminal_result.terminal_status is not SchedulerTerminalStatus.UNCERTAIN
            ):
                raise ValueError(
                    "active model-cost reservation differs from scheduler dispatch state"
                )
            if any(
                entry.status is not CostEntryStatus.UNCERTAIN_ACCOUNTED
                for _ordinal, entry in entries[:-1]
            ):
                raise ValueError("prior retry attempt lacks accounted uncertainty")
            validated_groups.append((logical_request_id, task, entries, True))

        for logical_request_id, task, entries, was_dispatched in validated_groups:
            for _attempt_ordinal, entry in entries:
                if not was_dispatched:
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
        self._validate_state()
        return tuple(sorted(recovered, key=lambda item: item.request_id))

    @property
    def restorable_context_request_evidence(self) -> tuple[ContextRequestEvidence, ...]:
        """Return context evidence paired with every retained provider completion."""

        evidence = tuple(
            ContextRequestEvidence.model_validate(
                output.model_completion_evidence.context_request_evidence.model_dump()
            )
            for output in self.outputs
            if output.model_completion_evidence is not None
        ) + tuple(
            ContextRequestEvidence.model_validate(attempt.context_request_evidence.model_dump())
            for attempt in self.provider_attempts
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
        )
        if self._terminal_report_authority is not None:
            if authority != self._terminal_report_authority:
                raise ValueError(
                    "resumed scheduler terminal report authority differs from durable evidence"
                )
            return self._terminal_report_authority
        if self._read_only:
            raise ValueError("scheduler verification journal is read-only")
        if not self.manifest.terminal_report_authority_required:
            raise ValueError("legacy scheduler campaign cannot seal current report authority")

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
            outputs=self.outputs,
            provider_attempts=self.provider_attempts,
            task_results=self.task_results,
            result_observations=self.result_observations,
            events=self.events,
            terminal_report_authority=authority,
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _TERMINAL_REPORT_AUTHORITY_FILENAME,
            authority,
        )
        self._terminal_report_authority = authority
        self._validate_state()
        return authority

    def artifact(self) -> SchedulerArtifact:
        """Build the public scheduler artifact from complete journal evidence."""

        durable_snapshot = self._validate_state()
        summary = self.summary
        model_requests = self.model_requests
        artifact = SchedulerArtifact.build(
            summary=summary,
            journal_evidence=self._build_journal_evidence(
                summary=summary,
                model_requests=model_requests,
            ),
            model_requests=model_requests,
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
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _task_output_path(output),
            output,
        )
        self._retain_output(output)
        self._validate_incremental_state(task_id=task_id)
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
        )
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _provider_attempt_path(attempt),
            attempt,
        )
        self._retain_provider_attempt(attempt)
        self._validate_incremental_state(task_id=task_id)
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
        pass_result = SchedulerPassResult.build(plan=plan, task_results=exact_results)
        _write_model(
            self._root_descriptor,
            self._directory_descriptors,
            _pass_result_path(ordinal),
            pass_result,
        )
        self._retain_pass_result(pass_result)
        self._validate_incremental_state()
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
        output.require_exact_activation(activation)
        self._outputs.append(output)
        self._indexes.outputs[output.task_id] = output

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
        self._provider_attempts.append(attempt)
        self._indexes.provider_attempts[attempt.task_id] = attempt

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
        self._pass_results.append(pass_result)

    def _assert_live_custody(self) -> None:
        if self._closed:
            raise ValueError("scheduler journal custody is closed")
        _assert_descriptor_custody(
            path=self.path,
            root_descriptor=self._root_descriptor,
            root_identity=self._root_identity,
            directory_descriptors=self._directory_descriptors,
            directory_identities=self._directory_identities,
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
            raise ValueError("scheduler provider attempt lacks a dispatched lifecycle")

    def _observe_retained_durable_artifacts(
        self,
    ) -> tuple[_DurableArtifactObservation, ...]:
        retained_child_paths = _retained_child_artifact_paths(
            plans=self.plans,
            activations=self.activations,
            events=self.events,
            outputs=self.outputs,
            provider_attempts=self.provider_attempts,
            result_observations=self.result_observations,
            pass_results=self.pass_results,
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
        )
        persisted_analysis_inputs = _read_model(
            self._root_descriptor,
            self._directory_descriptors,
            _ANALYSIS_INPUT_INVENTORY_FILENAME,
            SchedulerAnalysisInputInventory,
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

        durable_state = _load_state(
            self._root_descriptor,
            self._directory_descriptors,
            persisted_manifest,
        )
        retained_state = (
            self.plans,
            self.activations,
            self.events,
            self.outputs,
            self.provider_attempts,
            self.result_observations,
            self.pass_results,
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
        if self._terminal_report_authority is not None:
            self._build_journal_evidence(
                summary=self.summary,
                model_requests=self.model_requests,
            )
        self._assert_live_custody()
        return after_reconstruction


def create_scheduler_journal(
    path: Path,
    *,
    bindings: SchedulerBindings,
    analysis_input_inventory: SchedulerAnalysisInputInventory,
    shard_inventory: SchedulerShardInventory,
    cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
    privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None,
    require_terminal_report_authority: bool = False,
) -> SchedulerJournal:
    """Create one fresh private journal and persist its manifest before work."""

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
        journal._validate_state()
        if manifest.cost_ledger_baseline is not None:
            journal._usage_recovery_scope = _issue_trusted_usage_recovery_scope(())
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
) -> SchedulerJournal:
    """Resume only an exact-bound campaign, classifying interrupted dispatches."""

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
            terminal_report_authority,
        ) = _load_state(
            root_descriptor,
            directory_descriptors,
            manifest,
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
            terminal_report_authority=terminal_report_authority,
        )
        journal._validate_state()
        _recover_interrupted_state(journal)
        journal._validate_state()
        journal._usage_recovery_scope = _issue_trusted_usage_recovery_scope(
            journal.restorable_usage_records
        )
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
        expected_manifest = SchedulerCampaignManifest.build(
            bindings=expected_bindings,
            shard_inventory=expected_shard_inventory,
            cost_ledger_baseline=expected_cost_ledger_baseline,
            privacy_evidence_custody=expected_privacy_evidence_custody,
            require_terminal_report_authority=(expected_terminal_report_authority_required),
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
            manifest != expected_manifest
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
            terminal_report_authority,
        ) = _load_state(
            root_descriptor,
            directory_descriptors,
            manifest,
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
            terminal_report_authority=terminal_report_authority,
            read_only=True,
        )
        journal._validate_state()
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


def _recover_interrupted_state(journal: SchedulerJournal) -> None:
    """Finish safe fresh-file commits and conclude ambiguous dispatches."""

    histories = journal._events_by_task()
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
                continue
            if not history or history[-1].kind is not SchedulerTaskEventKind.DISPATCHED:
                continue
            dispatch = history[-1]
            activation = activations_by_task[task.task_id]
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


def _load_state(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    manifest: SchedulerCampaignManifest,
) -> tuple[
    tuple[SchedulerPassPlan, ...],
    tuple[SchedulerTaskActivation, ...],
    tuple[SchedulerTaskEvent, ...],
    tuple[SchedulerTaskOutput, ...],
    tuple[SchedulerProviderAttemptEvidence, ...],
    tuple[SchedulerTaskResult, ...],
    tuple[SchedulerPassResult, ...],
    SchedulerTerminalReportAuthority | None,
]:
    terminal_report_authority = (
        _read_model(
            root_descriptor,
            directory_descriptors,
            _TERMINAL_REPORT_AUTHORITY_FILENAME,
            SchedulerTerminalReportAuthority,
        )
        if _TERMINAL_REPORT_AUTHORITY_FILENAME in set(os.listdir(root_descriptor))
        else None
    )
    plans = _load_contiguous_pass_artifacts(
        root_descriptor,
        directory_descriptors,
        SchedulerPassPlan,
        result=False,
    )
    pass_results = _load_contiguous_pass_artifacts(
        root_descriptor,
        directory_descriptors,
        SchedulerPassResult,
        result=True,
    )
    events = _load_indexed_events(root_descriptor, directory_descriptors)
    activations: list[SchedulerTaskActivation] = []
    for candidate_name in sorted(os.listdir(directory_descriptors[_ACTIVATIONS_DIRECTORY])):
        activation = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_ACTIVATIONS_DIRECTORY}/{candidate_name}",
            SchedulerTaskActivation,
        )
        if candidate_name != PurePosixPath(_activation_path(activation)).name:
            raise ValueError("scheduler activation filename differs from its stable hash")
        activations.append(activation)
    outputs: list[SchedulerTaskOutput] = []
    for candidate_name in sorted(os.listdir(directory_descriptors[_TASK_OUTPUTS_DIRECTORY])):
        output = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_TASK_OUTPUTS_DIRECTORY}/{candidate_name}",
            SchedulerTaskOutput,
        )
        if candidate_name != PurePosixPath(_task_output_path(output)).name:
            raise ValueError("scheduler output filename differs from its stable hash")
        outputs.append(output)
    provider_attempts: list[SchedulerProviderAttemptEvidence] = []
    for candidate_name in sorted(os.listdir(directory_descriptors[_PROVIDER_ATTEMPTS_DIRECTORY])):
        attempt = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_PROVIDER_ATTEMPTS_DIRECTORY}/{candidate_name}",
            SchedulerProviderAttemptEvidence,
        )
        if candidate_name != PurePosixPath(_provider_attempt_path(attempt)).name:
            raise ValueError("scheduler provider-attempt filename differs from its stable hash")
        provider_attempts.append(attempt)
    result_observations: list[SchedulerTaskResult] = []
    for candidate_name in sorted(os.listdir(directory_descriptors[_TASK_RESULTS_DIRECTORY])):
        result = _read_model(
            root_descriptor,
            directory_descriptors,
            f"{_TASK_RESULTS_DIRECTORY}/{candidate_name}",
            SchedulerTaskResult,
        )
        if candidate_name != PurePosixPath(_task_result_path(result)).name:
            raise ValueError("scheduler task-result filename differs from its stable result hash")
        result_observations.append(result)
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
        terminal_report_authority=loaded[7],
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
        terminal_report_authority=loaded[7],
    )
    return loaded


def _load_contiguous_pass_artifacts[ModelT: StrictModel](
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    model_type: type[ModelT],
    *,
    result: bool,
) -> list[ModelT]:
    directory = _PASS_RESULTS_DIRECTORY if result else _PASS_PLANS_DIRECTORY
    suffix = "result" if result else "plan"
    observed = sorted(os.listdir(directory_descriptors[directory]))
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
            )
        )
    return loaded


def _load_indexed_events(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
) -> list[SchedulerTaskEvent]:
    observed = sorted(os.listdir(directory_descriptors[_EVENTS_DIRECTORY]))
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
        task, _plan = task_lookup[attempt.task_id]
        expected_attempt = SchedulerProviderAttemptEvidence.build(
            task=task,
            activation=attempt_activation,
            usage_record=attempt.usage_record,
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
            if (
                SchedulerTaskEventKind.DISPATCHED not in kinds
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
    terminal_report_authority: SchedulerTerminalReportAuthority | None,
) -> None:
    _validate_control_layout(
        root_descriptor,
        directory_descriptors,
        directory_identities,
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
    }
    for directory_name, expected in expected_children.items():
        if set(os.listdir(directory_descriptors[directory_name])) != expected:
            raise ValueError("scheduler journal contains an unmanifested child artifact")
    relative_files = _retained_child_artifact_paths(
        plans=plans,
        activations=activations,
        events=events,
        outputs=outputs,
        provider_attempts=provider_attempts,
        result_observations=result_observations,
        pass_results=pass_results,
    )
    for relative in relative_files:
        parent_descriptor, leaf = _relative_parent(
            root_descriptor,
            directory_descriptors,
            relative,
        )
        _require_private_file(parent_descriptor, leaf)
    if terminal_report_authority is not None:
        _require_private_file(root_descriptor, _TERMINAL_REPORT_AUTHORITY_FILENAME)


def _retained_child_artifact_paths(
    *,
    plans: tuple[SchedulerPassPlan, ...],
    activations: tuple[SchedulerTaskActivation, ...],
    events: tuple[SchedulerTaskEvent, ...],
    outputs: tuple[SchedulerTaskOutput, ...],
    provider_attempts: tuple[SchedulerProviderAttemptEvidence, ...],
    result_observations: tuple[SchedulerTaskResult, ...],
    pass_results: tuple[SchedulerPassResult, ...],
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
    )
    if len(paths) != len(set(paths)):
        raise ValueError("scheduler retained state repeats a durable artifact path")
    return tuple(sorted(paths))


def _observe_durable_artifacts(
    *,
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    relative_paths: tuple[str, ...],
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
        content, identity = _read_private_file_observation(parent_descriptor, leaf)
        observations.append((relative, identity, hashlib.sha256(content).hexdigest()))
    return tuple(observations)


def _validate_control_layout(
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    directory_identities: dict[str, tuple[int, int, int]],
) -> None:
    """Reject linked or unexpected structure before enumerating child evidence."""

    expected_root = {
        _LOCK_FILENAME,
        _MANIFEST_FILENAME,
        _ANALYSIS_INPUT_INVENTORY_FILENAME,
        *_CONTROL_DIRECTORIES,
    }
    observed_root = set(os.listdir(root_descriptor))
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
    _require_private_file(root_descriptor, _LOCK_FILENAME)
    _require_private_file(root_descriptor, _MANIFEST_FILENAME)
    _require_private_file(root_descriptor, _ANALYSIS_INPUT_INVENTORY_FILENAME)
    if _TERMINAL_REPORT_AUTHORITY_FILENAME in observed_root:
        _require_private_file(root_descriptor, _TERMINAL_REPORT_AUTHORITY_FILENAME)


def _require_private_file(parent_descriptor: int, leaf: str) -> None:
    metadata = _stat_entry(parent_descriptor, leaf)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
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
    _write_fresh_private_file(parent_descriptor, leaf, content)


def _read_model[ModelT: StrictModel](
    root_descriptor: int,
    directory_descriptors: dict[str, int],
    relative: str,
    model_type: type[ModelT],
) -> ModelT:
    parent_descriptor, leaf = _relative_parent(
        root_descriptor,
        directory_descriptors,
        relative,
    )
    content = _read_private_file(parent_descriptor, leaf)
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


def _write_fresh_private_file(parent_descriptor: int, leaf: str, content: bytes) -> None:
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


def _read_private_file(parent_descriptor: int, leaf: str) -> bytes:
    return _read_private_file_observation(parent_descriptor, leaf)[0]


def _read_private_file_observation(
    parent_descriptor: int,
    leaf: str,
) -> tuple[bytes, _EvidenceFileIdentity]:
    first = _read_private_file_once(parent_descriptor, leaf)
    second = _read_private_file_once(parent_descriptor, leaf)
    if first != second:
        raise ValueError("scheduler journal artifact changed while being observed")
    return second


def _read_private_file_once(
    parent_descriptor: int,
    leaf: str,
) -> tuple[bytes, _EvidenceFileIdentity]:
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
    if len(identities) != 1 or len(content) != after.st_size or after.st_nlink != 1:
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
) -> None:
    _assert_root_path_identity(path, root_descriptor, root_identity)
    _validate_control_layout(
        root_descriptor,
        directory_descriptors,
        directory_identities,
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
