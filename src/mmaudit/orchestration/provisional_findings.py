"""Project original scheduler truncation custody into explicitly unvalidated report data."""

from __future__ import annotations

import json
from typing import Any

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES
from mmaudit.models.provisional_findings import (
    MAX_PROVISIONAL_FINDINGS,
    ProvisionalFindingInventory,
    ProvisionalFindingRecord,
    ProvisionalFindingSource,
)
from mmaudit.models.scheduler import SchedulerArtifact
from mmaudit.models.truncation import (
    CandidateReviewFramePhase,
    CandidateReviewTruncationProjection,
    _canonical_sha256,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryResultOrigin,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.orchestration.scheduler import SchedulerJournal


def build_provisional_finding_inventory(
    journal: SchedulerJournal,
    *,
    scheduler_artifact: SchedulerArtifact,
) -> ProvisionalFindingInventory | None:
    """Retain every complete finding from original parent/child records; never promote it."""

    if type(journal) is not SchedulerJournal:
        raise ValueError("provisional finding export requires the original scheduler journal")
    artifact = SchedulerArtifact.model_validate_json(
        scheduler_artifact.model_dump_json(), strict=True
    )
    before = journal.journal_evidence
    if before != artifact.journal_evidence:
        raise ValueError("provisional finding export differs from original scheduler evidence")
    sources: list[ProvisionalFindingSource] = []
    retained_count = 0
    source_bytes = 0

    def append_source(source: ProvisionalFindingSource) -> None:
        nonlocal source_bytes
        source_bytes += len(
            json.dumps(
                source.model_dump(mode="json"), separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        )
        if source_bytes > MAX_JSON_ARTIFACT_BYTES:
            raise ValueError("provisional finding export exceeds its byte bound")
        sources.append(source)

    def records(
        projection: CandidateReviewTruncationProjection,
    ) -> tuple[ProvisionalFindingRecord, ...]:
        nonlocal retained_count
        validated = CandidateReviewTruncationProjection.model_validate_json(
            projection.model_dump_json(), strict=True
        )
        retained_count += len(validated.findings)
        if retained_count > MAX_PROVISIONAL_FINDINGS:
            raise ValueError("provisional finding export exceeds its record bound")
        frames = {
            frame.record_id: frame
            for frame in validated.accepted_frames
            if frame.phase is CandidateReviewFramePhase.FINDING
        }
        return tuple(
            ProvisionalFindingRecord(candidate=finding, retained_frame=frames[finding.candidate_id])
            for finding in validated.findings
        )

    for attempt in journal.provider_attempts:
        projection = attempt.truncation_projection
        if projection is None or not projection.findings:
            continue
        if projection.declared_finding_count is None:
            raise ValueError("provisional parent findings lack their original declared count")
        append_source(
            ProvisionalFindingSource(
                source_kind="scheduler_parent",
                source_entry_sha256=attempt.attempt_evidence_sha256,
                task_id=attempt.task_id,
                request_id=attempt.logical_request_id,
                request_role=attempt.usage_record.role,
                usage_record_sha256=attempt.usage_record_sha256,
                original_response_sha256=projection.original_response_sha256,
                truncation_projection_sha256=projection.evidence_sha256,
                algorithm_version=journal.manifest.algorithm_version,
                findings_state=projection.findings_state,
                surface_reviews_state=projection.surface_reviews_state,
                summary_state=projection.summary_state,
                declared_finding_count=projection.declared_finding_count,
                records=records(projection),
            )
        )
    for entry in journal.truncation_recovery_entries:
        if not isinstance(entry, SchedulerTruncationRecoveryChildResult):
            continue
        projection = entry.truncation_projection
        if projection is None or not projection.findings:
            continue
        if (
            entry.result_origin is not SchedulerTruncationRecoveryResultOrigin.RUNTIME
            or entry.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
            or entry.runtime_usage_record is None
            or entry.runtime_usage_record_sha256 is None
            or projection.declared_finding_count is None
        ):
            raise ValueError("provisional child findings lack original typed usage custody")
        append_source(
            ProvisionalFindingSource(
                source_kind="recovery_child",
                source_entry_sha256=entry.entry_sha256,
                task_id=entry.child_task_id,
                request_id=entry.child_logical_request_id,
                request_role=entry.runtime_usage_record.role,
                usage_record_sha256=entry.runtime_usage_record_sha256,
                original_response_sha256=projection.original_response_sha256,
                truncation_projection_sha256=projection.evidence_sha256,
                algorithm_version=journal.manifest.algorithm_version,
                findings_state=projection.findings_state,
                surface_reviews_state=projection.surface_reviews_state,
                summary_state=projection.summary_state,
                declared_finding_count=projection.declared_finding_count,
                records=records(projection),
            )
        )
    if journal.journal_evidence != before:
        raise ValueError("original scheduler evidence changed during provisional finding export")
    if not sources:
        return None
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "evidence_authority": "comparison_required",
        "campaign_id": before.campaign_id,
        "manifest_sha256": before.manifest_sha256,
        "journal_evidence_sha256": before.evidence_sha256,
        "scheduler_artifact_sha256": artifact.artifact_sha256,
        "sources": [
            source.model_dump(mode="json")
            for source in sorted(sources, key=lambda item: item.request_id)
        ],
        "retained_finding_count": retained_count,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "validated_finding_authorized": False,
        "completion_authorized": False,
    }
    serialized = json.dumps(
        {**payload, "inventory_sha256": _canonical_sha256(payload)},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(serialized.encode("utf-8")) > MAX_JSON_ARTIFACT_BYTES:
        raise ValueError("provisional finding export exceeds its byte bound")
    return ProvisionalFindingInventory.model_validate_json(serialized, strict=True)
