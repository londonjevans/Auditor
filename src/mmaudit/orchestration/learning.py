"""Terminal orchestration projection for private, tenant-scoped learning capture."""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from mmaudit.models.learning import (
    MAX_LEARNING_LONG_TEXT_CHARS,
    MAX_LEARNING_RECORD_JSON_BYTES,
    MAX_LEARNING_SHORT_TEXT_CHARS,
    LearningAcceptedFindingStatus,
    LearningActorKind,
    LearningAttributionOutcome,
    LearningAttributionTargetKind,
    LearningFindingSeverity,
    LearningSourceKind,
    LearningSurfaceKind,
    LearningSurfaceOutcome,
    TerminalAuditLearningRecord,
    TerminalConfirmedFinding,
    TerminalRejectedCandidate,
    TerminalReviewedSurface,
    TerminalReviewerAttribution,
    TerminalRoleResourceUsage,
    build_terminal_audit_learning_record,
    learning_actor_id,
    learning_canonical_sha256,
    learning_specialist_role,
)
from mmaudit.models.scheduler import SchedulerArtifact
from mmaudit.models.schemas import (
    AuditReport,
    AuditRunStatus,
    CandidateFinding,
    CandidateOriginKind,
    ExecutionEvidenceKind,
    FalsificationDecision,
    FalsificationVerdict,
    Finding,
    FindingStatus,
    Location,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewStatus,
    ModelVote,
    UsageRecord,
)
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.privacy import PrivacySourceClassification
from mmaudit.reporting.json_report import stable_json_bytes, write_json_bounded
from mmaudit.reporting.run_authority import RunTerminalReportAuthority

TERMINAL_AUDIT_LEARNING_ARTIFACT_PATH = "private/terminal-audit-learning.json"

_LEARNING_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_VERIFIED_VERDICTS = frozenset({"verified"})
_FALSIFIED_VERDICTS = frozenset({"falsified"})
_PROPOSED_VERDICTS = frozenset({"proposed"})


def persist_terminal_learning_capture(
    *,
    run_dir: Path,
    record: TerminalAuditLearningRecord,
) -> Path:
    """Write one private manifest-bound record without following directory links."""

    if type(record) is not TerminalAuditLearningRecord:
        raise ValueError("terminal learning persistence requires an exact record")
    validated = TerminalAuditLearningRecord.model_validate(
        record.model_dump(mode="python"),
        strict=True,
    )
    if validated != record:
        raise ValueError("terminal learning record changed during exact validation")
    if run_dir.is_symlink() or run_dir.is_junction() or not run_dir.is_dir():
        raise ValueError("terminal learning run directory is unsafe")
    private_dir = run_dir / "private"
    if private_dir.is_symlink() or private_dir.is_junction() or not private_dir.is_dir():
        raise ValueError("terminal learning private directory is unsafe")
    try:
        run_root = run_dir.resolve(strict=True)
        resolved_private = private_dir.resolve(strict=True)
    except OSError as exc:
        raise ValueError("terminal learning private directory is unavailable") from exc
    if resolved_private != run_root / "private" or resolved_private.parent != run_root:
        raise ValueError("terminal learning private directory escaped its run")

    destination = run_dir / TERMINAL_AUDIT_LEARNING_ARTIFACT_PATH
    if destination.exists() or destination.is_symlink() or destination.is_junction():
        raise ValueError("terminal learning record destination already exists")
    write_json_bounded(
        destination,
        validated,
        max_bytes=MAX_LEARNING_RECORD_JSON_BYTES,
    )
    destination.chmod(0o600, follow_symlinks=False)
    metadata = destination.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_LEARNING_RECORD_JSON_BYTES
    ):
        raise ValueError("terminal learning record destination is unsafe")
    return destination


def persist_terminal_learning_successor(
    *,
    corpus_root: Path,
    parent_record: TerminalAuditLearningRecord,
    successor_record: TerminalAuditLearningRecord,
) -> Path:
    """Persist one append-only, parent-linked feedback snapshot per tenant."""

    if (
        type(parent_record) is not TerminalAuditLearningRecord
        or type(successor_record) is not TerminalAuditLearningRecord
    ):
        raise ValueError("terminal learning successor requires exact records")
    parent = TerminalAuditLearningRecord.model_validate(
        parent_record.model_dump(mode="python"),
        strict=True,
    )
    successor = TerminalAuditLearningRecord.model_validate(
        successor_record.model_dump(mode="python"),
        strict=True,
    )
    if successor.parent_record_sha256 != parent.record_sha256:
        raise ValueError("terminal learning successor lacks its exact parent hash")
    if (
        successor.tenant_id != parent.tenant_id
        or successor.audit_id != parent.audit_id
        or successor.terminal_report_authority_sha256 != parent.terminal_report_authority_sha256
        or successor.report_payload_sha256 != parent.report_payload_sha256
        or successor.completed_at != parent.completed_at
        or successor.confirmed_findings != parent.confirmed_findings
        or successor.rejected_candidates != parent.rejected_candidates
        or successor.reviewed_surfaces != parent.reviewed_surfaces
        or successor.role_usage != parent.role_usage
    ):
        raise ValueError("terminal learning successor changed immutable terminal facts")
    if successor.captured_at < parent.captured_at:
        raise ValueError("terminal learning successor moved capture time backwards")
    parent_misses = {item.external_miss_id: item for item in parent.external_misses}
    successor_misses = {item.external_miss_id: item for item in successor.external_misses}
    if len(successor_misses) != len(parent_misses) + 1 or any(
        successor_misses.get(identifier) != item for identifier, item in parent_misses.items()
    ):
        raise ValueError("terminal learning successor must append exactly one immutable miss")
    new_miss_ids = set(successor_misses) - set(parent_misses)
    assert len(new_miss_ids) == 1
    new_miss = successor_misses[new_miss_ids.pop()]
    parent_attributions = {item.attribution_id: item for item in parent.reviewer_attributions}
    successor_attributions = {item.attribution_id: item for item in successor.reviewer_attributions}
    if any(
        successor_attributions.get(identifier) != item
        for identifier, item in parent_attributions.items()
    ):
        raise ValueError("terminal learning successor changed prior attribution")
    new_attributions = tuple(
        item
        for identifier, item in successor_attributions.items()
        if identifier not in parent_attributions
    )
    if any(
        item.source_kind is not LearningSourceKind.LATER_EXTERNAL_ESTABLISHMENT
        or item.outcome is not LearningAttributionOutcome.MISSED
        or item.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
        or item.target_id != new_miss.external_miss_id
        or item.target_sha256 != new_miss.finding_sha256
        for item in new_attributions
    ):
        raise ValueError("terminal learning successor has unrelated new attribution")

    if corpus_root.is_symlink() or corpus_root.is_junction() or not corpus_root.is_dir():
        raise ValueError("terminal learning corpus root is unsafe")
    root = corpus_root.resolve(strict=True)
    tenant_dir = _private_corpus_child(root, successor.tenant_id)
    records_dir = _private_corpus_child(tenant_dir, "records")
    destination = records_dir / f"{successor.record_sha256}.json"
    expected = stable_json_bytes(successor)
    if destination.exists() or destination.is_symlink() or destination.is_junction():
        if destination.is_symlink() or destination.is_junction() or not destination.is_file():
            raise ValueError("terminal learning successor destination is unsafe")
        metadata = destination.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_LEARNING_RECORD_JSON_BYTES
            or metadata.st_size != len(expected)
            or _read_private_file_bounded(
                destination,
                max_bytes=MAX_LEARNING_RECORD_JSON_BYTES,
            )
            != expected
        ):
            raise ValueError("terminal learning successor destination conflicts")
        return destination
    write_json_bounded(
        destination,
        successor,
        max_bytes=MAX_LEARNING_RECORD_JSON_BYTES,
    )
    destination.chmod(0o600, follow_symlinks=False)
    metadata = destination.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != len(expected)
    ):
        raise ValueError("terminal learning successor destination is unsafe")
    return destination


def _private_corpus_child(parent: Path, name: str) -> Path:
    child = parent / name
    if child.exists() or child.is_symlink() or child.is_junction():
        if child.is_symlink() or child.is_junction() or not child.is_dir():
            raise ValueError("terminal learning corpus directory is unsafe")
    else:
        child.mkdir(mode=0o700, parents=False)
    child.chmod(0o700, follow_symlinks=False)
    resolved = child.resolve(strict=True)
    if resolved.parent != parent.resolve(strict=True):
        raise ValueError("terminal learning corpus directory escaped its parent")
    return resolved


def _read_private_file_bounded(path: Path, *, max_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > max_bytes
        ):
            raise ValueError("terminal learning private file is unsafe")
        remaining = metadata.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1_048_576))
            if not chunk:
                raise ValueError("terminal learning private file ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("terminal learning private file exceeds its observed size")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def terminal_learning_capture_is_eligible(
    *,
    report: AuditReport,
    scanner_only: bool,
    privacy_source_classification: PrivacySourceClassification,
    tenant_scope_id: str | None,
) -> bool:
    """Admit only completed private production-audit results to Phase-1 capture."""

    return (
        not scanner_only
        and tenant_scope_id is not None
        and privacy_source_classification is PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
        and report.schema_version in {"1.2", "1.3", "1.4"}
        and report.completed
        and report.run_status is AuditRunStatus.COMPLETE
        and bool(report.usage)
        and all(record.execution_evidence is ExecutionEvidenceKind.REAL for record in report.usage)
    )


def build_terminal_learning_capture(
    *,
    tenant_id: str,
    report: AuditReport,
    candidate_projection: Iterable[CandidateFinding],
    terminal_report_authority: RunTerminalReportAuthority,
    scheduler_artifact: SchedulerArtifact | None,
    captured_at: datetime | None = None,
) -> TerminalAuditLearningRecord:
    """Project exact terminal evidence into one nonauthorizing private record."""

    validated_report = AuditReport.model_validate(report.model_dump(mode="python"))
    if validated_report.schema_version not in {"1.2", "1.3", "1.4"}:
        raise ValueError("terminal learning capture requires report schema 1.2, 1.3, or 1.4")
    if not validated_report.completed or validated_report.run_status is not AuditRunStatus.COMPLETE:
        raise ValueError("terminal learning capture requires a completed audit")
    if not validated_report.usage or any(
        record.execution_evidence is not ExecutionEvidenceKind.REAL
        for record in validated_report.usage
    ):
        raise ValueError("terminal learning capture requires only real provider usage")
    if (
        validated_report.model_review_coverage is None
        or not validated_report.model_review_coverage.surfaces
    ):
        raise ValueError("terminal learning capture requires a non-empty surface inventory")
    terminal_report_authority.require_exact_report(
        validated_report,
        scheduler_artifact=scheduler_artifact,
    )
    candidates = tuple(
        CandidateFinding.model_validate(candidate.model_dump(mode="python"))
        for candidate in candidate_projection
    )
    candidate_ids = tuple(candidate.candidate_id for candidate in candidates)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("terminal learning capture requires unique candidate IDs")

    confirmed, confirmed_by_candidate = _confirmed_findings(
        tenant_id=tenant_id,
        findings=validated_report.findings,
    )
    rejected, rejected_by_candidate = _rejected_candidates(
        tenant_id=tenant_id,
        candidates=candidates,
        rejected_findings=validated_report.rejected_findings,
    )
    captured_candidate_ids = set(confirmed_by_candidate) | set(rejected_by_candidate)
    missing_candidates = captured_candidate_ids - set(candidate_ids)
    if missing_candidates:
        raise ValueError("terminal learning outcome references an absent candidate payload")
    for candidate in candidates:
        if (
            candidate.candidate_id in captured_candidate_ids
            and candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
            and not any(vote.verdict.lower() == "proposed" for vote in candidate.model_votes)
        ):
            raise ValueError("captured model candidate lacks exact proposer attribution")
    attributions = _reviewer_attributions(
        tenant_id=tenant_id,
        candidates=candidates,
        confirmed_by_candidate=confirmed_by_candidate,
        rejected_by_candidate=rejected_by_candidate,
    )
    attributions.extend(
        _falsification_attributions(
            tenant_id=tenant_id,
            decisions=validated_report.falsification_decisions,
            usage=validated_report.usage,
            confirmed_by_candidate=confirmed_by_candidate,
            rejected_by_candidate=rejected_by_candidate,
        )
    )
    uncaptured_findings = tuple(
        finding
        for finding in (*validated_report.findings, *validated_report.filtered_findings)
        if finding.status is not FindingStatus.CONFIRMED
    )
    surfaces, missed_attributions = _reviewed_surfaces(
        tenant_id=tenant_id,
        surfaces=(
            validated_report.model_review_coverage.surfaces
            if validated_report.model_review_coverage is not None
            else []
        ),
        confirmed=confirmed,
        confirmed_findings=validated_report.findings,
        rejected=rejected,
        rejected_candidates=candidates,
        uncaptured_findings=uncaptured_findings,
    )
    attributions.extend(missed_attributions)
    usage = _role_usage(tenant_id=tenant_id, records=validated_report.usage)
    observed_cost = sum((Decimal(item.cost_usd_exact) for item in usage), start=Decimal(0))
    expected_cost = Decimal(
        validated_report.accounted_cost_usd_exact or str(validated_report.accounted_cost_usd)
    )
    if observed_cost != expected_cost:
        raise ValueError("terminal learning role costs differ from the exact report total")
    completed_at = validated_report.generated_at.astimezone(UTC)
    observed_at = captured_at
    if observed_at is None:
        observed_at = max(datetime.now(UTC), completed_at)
        if observed_at.microsecond:
            observed_at = observed_at.replace(microsecond=0) + timedelta(seconds=1)
    if observed_at.microsecond:
        raise ValueError("terminal learning capture timestamp must be whole-second UTC")
    return build_terminal_audit_learning_record(
        tenant_id=tenant_id,
        audit_id=validated_report.run_id,
        terminal_report_authority_sha256=terminal_report_authority.authority_sha256,
        report_payload_sha256=terminal_report_authority.report_payload_sha256,
        completed_at=completed_at,
        captured_at=observed_at,
        confirmed_findings=confirmed,
        rejected_candidates=rejected,
        reviewer_attributions=attributions,
        reviewed_surfaces=surfaces,
        role_usage=usage,
    )


def _confirmed_findings(
    *,
    tenant_id: str,
    findings: Iterable[Finding],
) -> tuple[list[TerminalConfirmedFinding], dict[str, TerminalConfirmedFinding]]:
    records: list[TerminalConfirmedFinding] = []
    by_candidate: dict[str, TerminalConfirmedFinding] = {}
    for finding in findings:
        if finding.status is not FindingStatus.CONFIRMED:
            continue
        record = TerminalConfirmedFinding(
            tenant_id=tenant_id,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            finding_id=finding.id,
            finding_sha256=learning_canonical_sha256(finding.model_dump(mode="json")),
            title_excerpt=_learning_excerpt(
                finding.title,
                max_chars=MAX_LEARNING_SHORT_TEXT_CHARS,
            ),
            category=_finding_category(finding),
            severity=LearningFindingSeverity(finding.severity.value.upper()),
            status=LearningAcceptedFindingStatus.CONFIRMED,
            summary_excerpt=_learning_excerpt(
                finding.summary,
                max_chars=MAX_LEARNING_LONG_TEXT_CHARS,
            ),
        )
        records.append(record)
        for candidate_id in finding.contributing_candidate_ids:
            if candidate_id in by_candidate:
                raise ValueError("one candidate contributes to multiple terminal findings")
            by_candidate[candidate_id] = record
    return records, by_candidate


def _rejected_candidates(
    *,
    tenant_id: str,
    candidates: tuple[CandidateFinding, ...],
    rejected_findings: Iterable[Finding],
) -> tuple[list[TerminalRejectedCandidate], dict[str, TerminalRejectedCandidate]]:
    candidate_index = {candidate.candidate_id: candidate for candidate in candidates}
    records: list[TerminalRejectedCandidate] = []
    by_candidate: dict[str, TerminalRejectedCandidate] = {}
    for finding in rejected_findings:
        if finding.status is not FindingStatus.REJECTED:
            raise ValueError("rejected terminal inventory contains a non-rejected finding")
        reason_code, reason = _terminal_rejection_reason(finding)
        for candidate_id in finding.contributing_candidate_ids:
            candidate = candidate_index.get(candidate_id)
            if candidate is None:
                raise ValueError("rejected terminal finding references an absent candidate")
            if candidate_id in by_candidate:
                raise ValueError("rejected candidate occurs in multiple terminal findings")
            record = TerminalRejectedCandidate(
                tenant_id=tenant_id,
                source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
                candidate_id=candidate_id,
                candidate_sha256=learning_canonical_sha256(candidate.model_dump(mode="json")),
                title_excerpt=_learning_excerpt(
                    candidate.title,
                    max_chars=MAX_LEARNING_SHORT_TEXT_CHARS,
                ),
                category=_candidate_category(candidate),
                reason_code=reason_code,
                reason_excerpt=_learning_excerpt(
                    reason,
                    max_chars=MAX_LEARNING_LONG_TEXT_CHARS,
                ),
            )
            records.append(record)
            by_candidate[candidate_id] = record
    return records, by_candidate


def _reviewer_attributions(
    *,
    tenant_id: str,
    candidates: tuple[CandidateFinding, ...],
    confirmed_by_candidate: dict[str, TerminalConfirmedFinding],
    rejected_by_candidate: dict[str, TerminalRejectedCandidate],
) -> list[TerminalReviewerAttribution]:
    records: dict[str, TerminalReviewerAttribution] = {}
    for candidate in candidates:
        confirmed_target = confirmed_by_candidate.get(candidate.candidate_id)
        rejected_target = rejected_by_candidate.get(candidate.candidate_id)
        if confirmed_target is not None and rejected_target is not None:
            raise ValueError("one candidate cannot be both confirmed and rejected")
        if confirmed_target is not None:
            _add_vote_attributions(
                records,
                tenant_id=tenant_id,
                votes=candidate.model_votes,
                target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
                target_id=confirmed_target.finding_id,
                target_sha256=confirmed_target.finding_sha256,
            )
        elif rejected_target is not None:
            _add_vote_attributions(
                records,
                tenant_id=tenant_id,
                votes=candidate.model_votes,
                target_kind=LearningAttributionTargetKind.REJECTED_CANDIDATE,
                target_id=rejected_target.candidate_id,
                target_sha256=rejected_target.candidate_sha256,
            )
    return list(records.values())


def _add_vote_attributions(
    records: dict[str, TerminalReviewerAttribution],
    *,
    tenant_id: str,
    votes: Iterable[ModelVote],
    target_kind: LearningAttributionTargetKind,
    target_id: str,
    target_sha256: str,
) -> None:
    for vote in votes:
        verdict = vote.verdict.lower()
        if verdict in _PROPOSED_VERDICTS:
            outcome = LearningAttributionOutcome.PROPOSED
        elif verdict in _VERIFIED_VERDICTS:
            outcome = LearningAttributionOutcome.VERIFIED
        elif verdict in _FALSIFIED_VERDICTS:
            outcome = LearningAttributionOutcome.FALSIFIED
        else:
            continue
        _add_attribution(
            records,
            tenant_id=tenant_id,
            role=vote.role,
            model_id=vote.returned_model or vote.requested_model or vote.family,
            outcome=outcome,
            target_kind=target_kind,
            target_id=target_id,
            target_sha256=target_sha256,
        )


def _add_attribution(
    records: dict[str, TerminalReviewerAttribution],
    *,
    tenant_id: str,
    role: str,
    model_id: str,
    outcome: LearningAttributionOutcome,
    target_kind: LearningAttributionTargetKind,
    target_id: str,
    target_sha256: str,
    surface_ids: tuple[str, ...] = (),
) -> None:
    actor_kind = (
        LearningActorKind.SPECIALIST
        if learning_specialist_role(role) is not None
        else LearningActorKind.MODEL
    )
    identity = {
        "tenant_id": tenant_id,
        "role": role,
        "model_id": model_id,
        "outcome": outcome.value,
        "target_kind": target_kind.value,
        "target_id": target_id,
        "target_sha256": target_sha256,
        "surface_ids": surface_ids,
    }
    attribution_id = f"attribution:{learning_canonical_sha256(identity)}"
    records.setdefault(
        attribution_id,
        TerminalReviewerAttribution(
            tenant_id=tenant_id,
            source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
            attribution_id=attribution_id,
            actor_kind=actor_kind,
            actor_id=learning_actor_id(audit_role=role, model_id=model_id),
            model_id=model_id,
            audit_role=role,
            specialist_role=(
                learning_specialist_role(role)
                if actor_kind is LearningActorKind.SPECIALIST
                else None
            ),
            outcome=outcome,
            target_kind=target_kind,
            target_id=target_id,
            target_sha256=target_sha256,
            surface_ids=surface_ids,
        ),
    )


def _falsification_attributions(
    *,
    tenant_id: str,
    decisions: Iterable[FalsificationDecision],
    usage: Iterable[UsageRecord],
    confirmed_by_candidate: dict[str, TerminalConfirmedFinding],
    rejected_by_candidate: dict[str, TerminalRejectedCandidate],
) -> list[TerminalReviewerAttribution]:
    falsified_ids = {
        decision.candidate_id
        for decision in decisions
        if decision.verdict is FalsificationVerdict.FALSIFIED
        and decision.test_matches_claim
        and decision.assumptions_validated
    }
    if not falsified_ids:
        return []
    falsifier_usage = tuple(
        record
        for record in usage
        if record.role in {"falsifier", "specialist:falsifier"}
        and (
            is_creditable_usage_record(record, require_real=True)
            or (
                record.execution_evidence is ExecutionEvidenceKind.REAL
                and record.status == "success"
                and record.validation_status.value == "valid"
                and not record.substitution_detected
                and record.validated_response_sha256 is not None
            )
        )
    )
    if len(falsifier_usage) != 1:
        raise ValueError("typed falsification lacks one exact creditable falsifier request")
    usage_record = falsifier_usage[0]
    model_id = (
        usage_record.actual_model or usage_record.returned_model or usage_record.requested_model
    )
    records: dict[str, TerminalReviewerAttribution] = {}
    for candidate_id in sorted(falsified_ids):
        confirmed_target = confirmed_by_candidate.get(candidate_id)
        rejected_target = rejected_by_candidate.get(candidate_id)
        if confirmed_target is not None and rejected_target is not None:
            raise ValueError("one falsified candidate cannot be both confirmed and rejected")
        if confirmed_target is not None:
            target_kind = LearningAttributionTargetKind.CONFIRMED_FINDING
            target_id = confirmed_target.finding_id
            target_sha256 = confirmed_target.finding_sha256
        elif rejected_target is not None:
            target_kind = LearningAttributionTargetKind.REJECTED_CANDIDATE
            target_id = rejected_target.candidate_id
            target_sha256 = rejected_target.candidate_sha256
        else:
            continue
        _add_attribution(
            records,
            tenant_id=tenant_id,
            role=usage_record.role,
            model_id=model_id,
            outcome=LearningAttributionOutcome.FALSIFIED,
            target_kind=target_kind,
            target_id=target_id,
            target_sha256=target_sha256,
        )
    return list(records.values())


def _reviewed_surfaces(
    *,
    tenant_id: str,
    surfaces: Iterable[ModelReviewSurface],
    confirmed: list[TerminalConfirmedFinding],
    confirmed_findings: Iterable[Finding],
    rejected: list[TerminalRejectedCandidate],
    rejected_candidates: tuple[CandidateFinding, ...],
    uncaptured_findings: tuple[Finding, ...],
) -> tuple[list[TerminalReviewedSurface], list[TerminalReviewerAttribution]]:
    confirmed_models = {item.id: item for item in confirmed_findings}
    rejected_models = {item.candidate_id: item for item in rejected_candidates}
    confirmed_hashes = {item.finding_id: item.finding_sha256 for item in confirmed}
    rejected_hashes = {item.candidate_id: item.candidate_sha256 for item in rejected}
    records: list[TerminalReviewedSurface] = []
    missed: dict[str, TerminalReviewerAttribution] = {}
    for surface in surfaces:
        if surface.reviewed:
            confirmed_ids = tuple(
                sorted(
                    finding_id
                    for finding_id, finding in confirmed_models.items()
                    if finding_id in confirmed_hashes
                    and _locations_overlap(surface.locations, finding.locations)
                )
            )
            rejected_ids = tuple(
                sorted(
                    candidate_id
                    for candidate_id, candidate in rejected_models.items()
                    if candidate_id in rejected_hashes
                    and _locations_overlap(surface.locations, candidate.locations)
                )
            )
        else:
            confirmed_ids = ()
            rejected_ids = ()
        unresolved_overlap = surface.reviewed and any(
            _locations_overlap(surface.locations, finding.locations)
            for finding in uncaptured_findings
        )
        unresolved_candidate_reference = any(
            reference.credited and reference.status is ModelSurfaceReviewStatus.CANDIDATE
            for reference in surface.evidence_references
        ) and not (confirmed_ids or rejected_ids)
        outcome = _surface_outcome(
            reviewed=surface.reviewed,
            confirmed_ids=confirmed_ids,
            rejected_ids=rejected_ids,
            unresolved=unresolved_overlap or unresolved_candidate_reference,
        )
        credited_actors: set[str] = set()
        for reference in surface.evidence_references:
            model_id = reference.model or reference.requested_model
            if reference.credited and model_id is not None:
                credited_actors.add(
                    learning_actor_id(
                        audit_role=reference.review_role,
                        model_id=model_id,
                    )
                )
        credited_actor_ids = tuple(sorted(credited_actors))
        records.append(
            TerminalReviewedSurface(
                tenant_id=tenant_id,
                source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
                surface_id=surface.surface_id,
                surface_sha256=learning_canonical_sha256(surface.model_dump(mode="json")),
                surface_kind=_surface_kind(surface.kind),
                descriptor_excerpt=_learning_excerpt(
                    surface.label,
                    max_chars=MAX_LEARNING_SHORT_TEXT_CHARS,
                ),
                outcome=outcome,
                credited_reviewer_actor_ids=credited_actor_ids,
                confirmed_finding_ids=confirmed_ids,
                rejected_candidate_ids=rejected_ids,
            )
        )
        for reference in surface.evidence_references:
            if (
                not reference.credited
                or reference.status is not ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE
            ):
                continue
            for finding_id in confirmed_ids:
                _add_missed_surface_attribution(
                    missed,
                    tenant_id=tenant_id,
                    reference=reference,
                    surface_id=surface.surface_id,
                    finding_id=finding_id,
                    finding_sha256=confirmed_hashes[finding_id],
                )
    return records, list(missed.values())


def _add_missed_surface_attribution(
    records: dict[str, TerminalReviewerAttribution],
    *,
    tenant_id: str,
    reference: ModelReviewEvidenceReference,
    surface_id: str,
    finding_id: str,
    finding_sha256: str,
) -> None:
    model_id = reference.model or reference.requested_model
    if model_id is None:
        return
    _add_attribution(
        records,
        tenant_id=tenant_id,
        role=reference.review_role,
        model_id=model_id,
        outcome=LearningAttributionOutcome.MISSED,
        target_kind=LearningAttributionTargetKind.CONFIRMED_FINDING,
        target_id=finding_id,
        target_sha256=finding_sha256,
        surface_ids=(surface_id,),
    )


def _role_usage(
    *,
    tenant_id: str,
    records: Iterable[UsageRecord],
) -> list[TerminalRoleResourceUsage]:
    grouped: dict[str, list[UsageRecord]] = defaultdict(list)
    request_ids: set[str] = set()
    for record in records:
        if record.request_id in request_ids:
            raise ValueError("terminal learning capture requires unique usage request IDs")
        request_ids.add(record.request_id)
        grouped[record.role].append(record)
    result: list[TerminalRoleResourceUsage] = []
    for role, role_records in grouped.items():
        exact_cost = Decimal(0)
        runtime_seconds = Decimal(0)
        model_ids: set[str] = set()
        for record in role_records:
            if record.accounted_cost_usd_exact is None:
                raise ValueError("terminal learning capture requires exact role costs")
            exact_cost += Decimal(record.accounted_cost_usd_exact)
            runtime_seconds += _usage_runtime_seconds(record)
            model_ids.add(
                record.actual_model
                or record.returned_model
                or record.requested_model
                or record.model_family
            )
        result.append(
            TerminalRoleResourceUsage(
                tenant_id=tenant_id,
                source_kind=LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
                role_id=role,
                model_ids=tuple(sorted(model_ids)),
                request_count=len(role_records),
                cost_usd_exact=_canonical_decimal(exact_cost),
                runtime_seconds_exact=_canonical_decimal(runtime_seconds),
            )
        )
    return result


def _usage_runtime_seconds(record: UsageRecord) -> Decimal:
    if record.latency_ms is not None:
        return Decimal(record.latency_ms) / Decimal(1_000)
    if record.started_at is not None and record.ended_at is not None:
        return Decimal(str((record.ended_at - record.started_at).total_seconds()))
    raise ValueError("terminal learning capture requires exact role runtime")


def _canonical_decimal(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _finding_category(finding: Finding) -> str:
    return _category((*finding.cwe, *finding.owasp), fallback=finding.origin_kind.value.upper())


def _terminal_rejection_reason(finding: Finding) -> tuple[str, str]:
    validation_errors = tuple(
        error.strip() for error in finding.location_validation.errors if error.strip()
    )
    if validation_errors:
        return "LOCATION_VALIDATION_FAILED", "; ".join(validation_errors)
    rejected_rationales = tuple(
        vote.rationale.strip()
        for vote in finding.model_votes
        if vote.verdict.lower() in {"disputed", "falsified", "rejected"} and vote.rationale.strip()
    )
    if rejected_rationales:
        return "NEGATIVE_REVIEW_RATIONALE", "; ".join(rejected_rationales)
    disagreement = finding.disagreement.strip()
    if disagreement:
        return "TERMINAL_ADJUDICATION_TRANSCRIPT", disagreement
    raise ValueError("terminally rejected candidates require an explicit rejection reason")


def _candidate_category(candidate: CandidateFinding) -> str:
    return _category(
        (*candidate.cwe, *candidate.owasp),
        fallback=candidate.origin_kind.value.upper(),
    )


def _category(values: Iterable[str], *, fallback: str) -> str:
    return next((value for value in values if _LEARNING_CODE.fullmatch(value)), fallback)


def _surface_kind(kind: ModelReviewSurfaceKind) -> LearningSurfaceKind:
    return {
        ModelReviewSurfaceKind.SOURCE_FILE: LearningSurfaceKind.SOURCE_FILE,
        ModelReviewSurfaceKind.CONTRACT: LearningSurfaceKind.CONTRACT,
        ModelReviewSurfaceKind.ENTRY_POINT: LearningSurfaceKind.FUNCTION,
        ModelReviewSurfaceKind.INTERNAL_FUNCTION: LearningSurfaceKind.FUNCTION,
        ModelReviewSurfaceKind.PRIVILEGE_FUNCTION: LearningSurfaceKind.FUNCTION,
        ModelReviewSurfaceKind.ASSET_FUNCTION: LearningSurfaceKind.FUNCTION,
        ModelReviewSurfaceKind.CALL: LearningSurfaceKind.CALL_PATH,
        ModelReviewSurfaceKind.STATE: LearningSurfaceKind.STATE,
        ModelReviewSurfaceKind.INVARIANT: LearningSurfaceKind.INVARIANT,
        ModelReviewSurfaceKind.TEMPLATE: LearningSurfaceKind.OTHER,
        ModelReviewSurfaceKind.KNOWN_ISSUE_CLASS: LearningSurfaceKind.OTHER,
    }[kind]


def _surface_outcome(
    *,
    reviewed: bool,
    confirmed_ids: tuple[str, ...],
    rejected_ids: tuple[str, ...],
    unresolved: bool,
) -> LearningSurfaceOutcome:
    if not reviewed:
        return LearningSurfaceOutcome.INCONCLUSIVE
    if confirmed_ids and rejected_ids:
        return LearningSurfaceOutcome.MIXED
    if confirmed_ids:
        return LearningSurfaceOutcome.CONFIRMED_FINDINGS
    if rejected_ids:
        return LearningSurfaceOutcome.REJECTED_CANDIDATES
    if unresolved:
        return LearningSurfaceOutcome.INCONCLUSIVE
    return LearningSurfaceOutcome.REVIEWED_NO_ISSUE


def _learning_excerpt(value: str, *, max_chars: int) -> str:
    normalized = unicodedata.normalize("NFC", value).strip()
    if not normalized:
        normalized = "[empty]"
    escaped = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else f"\\u{ord(character):04x}"
        for character in normalized
    )
    if len(escaped) <= max_chars:
        return escaped
    suffix = "…[truncated]"
    return escaped[: max_chars - len(suffix)] + suffix


def _locations_overlap(left: Iterable[Location], right: Iterable[Location]) -> bool:
    return any(
        first.path == second.path
        and first.start_line <= second.end_line
        and second.start_line <= first.end_line
        for first in left
        for second in right
    )
