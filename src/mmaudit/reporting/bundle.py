"""Typed client/forensic report projections derived from one final audit report."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from mmaudit.models.scheduler import (
    SchedulerCostLedgerBaseline,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    AuditReport,
    AuditRunStatus,
    AuditScopeAssessment,
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationVerdict,
    CandidateFinding,
    CandidateReproductionResolution,
    FalsificationDecision,
    FalsificationVerdict,
    Finding,
    FindingOriginKind,
    FindingStatus,
    ModelReviewCoverage,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    SolidityCoverage,
    StrictModel,
    UsageRecord,
    VerificationDecision,
    VerificationVerdict,
)
from mmaudit.orchestration.cost_ledger import (
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
    ReleaseReason,
    cost_entry_sha256,
    cost_ledger_snapshot_sha256,
)
from mmaudit.reporting.status import ReportStatusProjection, effective_report_status
from mmaudit.repository.chunking import line_range_hash

_MAX_SOURCE_EXCERPT_EVIDENCE_BYTES = 1_000_000
_USD_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,18})?$"
_SCHEDULER_REQUEST_PATTERN = r"^scheduler-request-[0-9a-f]{64}$"

MANIFEST_BOUND_REPORT_DELIVERABLES = frozenset(
    {
        "client-report.md",
        "forensic-report.md",
        "findings.json",
        "audit-results.sarif",
        "coverage.json",
        "model-execution.json",
    }
)
REQUIRED_REPORT_DELIVERABLES = frozenset(
    {*MANIFEST_BOUND_REPORT_DELIVERABLES, "run-evidence-manifest.json"}
)


def _money_text(value: Decimal) -> str:
    """Return the ledger's canonical finite non-negative decimal spelling."""

    material = format(value, "f")
    if "." in material:
        material = material.rstrip("0").rstrip(".")
    return material or "0"


def _attempt_request_id(logical_request_id: str, attempt_index: int) -> str:
    """Reproduce the provider's exact first-attempt/retry ledger identity."""

    return (
        logical_request_id
        if attempt_index == 1
        else f"{logical_request_id}:attempt:{attempt_index}"
    )


def _cost_ledger_absence_values(*, persistent_ledger_configured: bool) -> dict[str, object]:
    if persistent_ledger_configured:
        return {
            "schema_version": "1.0",
            "state": "UNESTABLISHED_ZERO",
            "status": "INCONCLUSIVE",
            "reason": "NO_MODEL_USAGE_AND_NO_CAMPAIGN_LEDGER_EVIDENCE",
            "persistent_ledger_configured": True,
            "usage_record_count": 0,
            "run_entry_count": 0,
        }
    return {
        "schema_version": "1.0",
        "state": "ABSENT_ZERO",
        "status": "NOT_APPLICABLE",
        "reason": "NO_MODEL_USAGE_AND_NO_PERSISTENT_LEDGER",
        "persistent_ledger_configured": False,
        "usage_record_count": 0,
        "run_entry_count": 0,
    }


class ForensicDisposition(StrEnum):
    """Client-facing projection that cannot increase deterministic finding authority."""

    CONFIRMED = "CONFIRMED"
    SUPPORTED = "SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


class SourceExcerptEvidence(StrictModel):
    """A small source excerpt bound to the discovered file and cited range."""

    path: str = Field(min_length=1, max_length=4_096)
    symbol: str | None = Field(default=None, max_length=1_000)
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cited_start_line: int = Field(ge=1)
    cited_end_line: int = Field(ge=1)
    cited_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    excerpt_start_line: int = Field(ge=1)
    excerpt_end_line: int = Field(ge=1)
    content: str = Field(max_length=_MAX_SOURCE_EXCERPT_EVIDENCE_BYTES)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    omitted_before: bool
    omitted_after: bool

    @model_validator(mode="after")
    def excerpt_is_self_consistent(self) -> SourceExcerptEvidence:
        if (
            self.cited_end_line < self.cited_start_line
            or self.excerpt_end_line < self.excerpt_start_line
            or self.excerpt_start_line > self.cited_start_line
            or self.excerpt_end_line < self.cited_end_line
        ):
            raise ValueError("source excerpt line bounds are inconsistent")
        if hashlib.sha256(self.content.encode()).hexdigest() != self.content_sha256:
            raise ValueError("source excerpt content hash is inconsistent")
        if len(self.content.splitlines()) != self.excerpt_end_line - self.excerpt_start_line + 1:
            raise ValueError("source excerpt line count is inconsistent")
        relative_start = self.cited_start_line - self.excerpt_start_line + 1
        relative_end = self.cited_end_line - self.excerpt_start_line + 1
        if line_range_hash(self.content, relative_start, relative_end) != self.cited_content_sha256:
            raise ValueError("source excerpt cited range hash is inconsistent")
        if self.symbol is not None and not source_symbol_is_present(
            self.symbol,
            "".join(self.content.splitlines(keepends=True)[relative_start - 1 : relative_end]),
        ):
            raise ValueError("source excerpt symbol is absent from the cited range")
        return self


def source_symbol_is_present(symbol: str, content: str) -> bool:
    """Match a source symbol as an identifier, never as a substring of another symbol."""

    base = symbol.split("(", maxsplit=1)[0].rsplit(".", maxsplit=1)[-1]
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", base) is None:
        return False
    return re.search(rf"(?<![A-Za-z0-9_$]){re.escape(base)}(?![A-Za-z0-9_$])", content) is not None


class ForensicFindingRecord(StrictModel):
    """One final finding with all candidate-linked review evidence kept together."""

    finding_id: str = Field(min_length=1)
    disposition: ForensicDisposition
    finding: Finding
    source_excerpt: SourceExcerptEvidence | None = None
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)
    verification_decisions: list[VerificationDecision] = Field(default_factory=list)
    cross_examination_decisions: list[CandidateCrossExaminationDecision] = Field(
        default_factory=list
    )
    falsification_decisions: list[FalsificationDecision] = Field(default_factory=list)
    reproductions: list[ReproductionResult] = Field(default_factory=list)
    reproduction_resolutions: list[CandidateReproductionResolution] = Field(default_factory=list)

    @model_validator(mode="after")
    def evidence_is_linked_to_the_finding(self) -> ForensicFindingRecord:
        if self.finding_id != self.finding.id:
            raise ValueError("forensic finding ID differs from the embedded finding")
        contributor_ids = set(self.finding.contributing_candidate_ids)
        linked_ids = {
            *(candidate.candidate_id for candidate in self.candidate_findings),
            *(decision.candidate_id for decision in self.verification_decisions),
            *(decision.candidate_id for decision in self.cross_examination_decisions),
            *(decision.candidate_id for decision in self.falsification_decisions),
            *(result.candidate_id for result in self.reproductions),
            *(resolution.candidate_id for resolution in self.reproduction_resolutions),
        }
        if not linked_ids <= contributor_ids:
            raise ValueError("forensic evidence references a non-contributing candidate")
        candidate_ids = [candidate.candidate_id for candidate in self.candidate_findings]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("forensic candidate evidence must be unique")
        if self.finding.origin_kind is FindingOriginKind.STATIC_ANALYZER:
            if candidate_ids:
                raise ValueError("static-analyzer finding cannot claim model candidate evidence")
        elif set(candidate_ids) != contributor_ids:
            raise ValueError("forensic candidate evidence does not close the contributor set")
        unique_keys: tuple[tuple[str, list[object]], ...] = (
            (
                "verification decisions",
                [decision.candidate_id for decision in self.verification_decisions],
            ),
            (
                "cross-examination decisions",
                [
                    (
                        decision.candidate_id,
                        decision.request_id,
                        decision.reviewer_index,
                        decision.root_lineage,
                    )
                    for decision in self.cross_examination_decisions
                ],
            ),
            (
                "falsification decisions",
                [
                    (decision.candidate_id, decision.test_name)
                    for decision in self.falsification_decisions
                ],
            ),
            (
                "reproductions",
                [(result.candidate_id, result.test_name) for result in self.reproductions],
            ),
            (
                "reproduction resolutions",
                [resolution.candidate_id for resolution in self.reproduction_resolutions],
            ),
        )
        for label, keys in unique_keys:
            if len(keys) != len(set(keys)):
                raise ValueError(f"forensic {label} must be unique")
        if self.source_excerpt is not None:
            excerpt = self.source_excerpt
            matching_locations = [
                location
                for location in self.finding.locations
                if location.path == excerpt.path
                and location.start_line == excerpt.cited_start_line
                and location.end_line == excerpt.cited_end_line
                and location.symbol == excerpt.symbol
            ]
            if (
                len(matching_locations) != 1
                or matching_locations[0].content_hash is None
                or matching_locations[0].content_hash != excerpt.cited_content_sha256
            ):
                raise ValueError(
                    "forensic source excerpt differs from its authoritative finding location"
                )
        if self.finding.status is FindingStatus.REJECTED:
            if self.disposition is not ForensicDisposition.REJECTED:
                raise ValueError("rejected finding requires rejected forensic disposition")
            retained_rejection_evidence = bool(
                self.candidate_findings
                or self.finding.evidence
                or self.finding.location_validation.errors
                or self.verification_decisions
                or self.cross_examination_decisions
                or self.falsification_decisions
                or self.reproductions
                or self.reproduction_resolutions
                or self.finding.execution_provenance
            )
            retained_rejection_rationale = bool(
                self.finding.disagreement
                or self.finding.location_validation.errors
                or any(decision.rationale for decision in self.verification_decisions)
                or any(decision.rationale for decision in self.cross_examination_decisions)
                or any(decision.rationale for decision in self.falsification_decisions)
                or any(resolution.detail for resolution in self.reproduction_resolutions)
                or any(result.limitations for result in self.reproductions)
            )
            if not retained_rejection_rationale or not retained_rejection_evidence:
                raise ValueError(
                    "forensic rejected finding requires complete retained evidence "
                    f"(contributors={len(contributor_ids)}, "
                    f"candidates={len(self.candidate_findings)}, "
                    f"evidence={len(self.finding.evidence)}, "
                    f"location_errors={len(self.finding.location_validation.errors)}, "
                    f"decisions={len(self.verification_decisions) + len(self.cross_examination_decisions) + len(self.falsification_decisions)}, "
                    "including an evidence-backed rejection rationale"
                )
        elif self.disposition is ForensicDisposition.REJECTED:
            raise ValueError("active finding cannot receive rejected forensic disposition")
        return self


class FindingsArtifact(ReportStatusProjection):
    """Complete final/candidate finding history for the forensic bundle."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1, max_length=160)
    findings: list[Finding]
    rejected_findings: list[Finding]
    records: list[ForensicFindingRecord]
    candidate_findings: list[CandidateFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def inventory_is_exact_and_unique(self) -> FindingsArtifact:
        expected_findings = [*self.findings, *self.rejected_findings]
        if [record.finding for record in self.records] != expected_findings:
            raise ValueError("forensic records differ from the final finding inventories")
        identifiers = [finding.id for finding in expected_findings]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("forensic finding IDs must be unique")
        candidate_ids = [candidate.candidate_id for candidate in self.candidate_findings]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("forensic candidate IDs must be unique")
        candidate_id_set = set(candidate_ids)
        referenced_candidate_ids = {
            candidate_id
            for record in self.records
            for candidate_id in record.finding.contributing_candidate_ids
        }
        if not candidate_id_set <= referenced_candidate_ids:
            raise ValueError("forensic candidate inventory contains an orphan record")
        for record in self.records:
            expected_candidate_ids = (
                set(record.finding.contributing_candidate_ids) & candidate_id_set
            )
            observed = {candidate.candidate_id for candidate in record.candidate_findings}
            if observed != expected_candidate_ids:
                raise ValueError("forensic record omits candidate inventory evidence")
        return self


class CoverageArtifact(ReportStatusProjection):
    """Compact typed coverage projection with full typed coverage bodies retained."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1, max_length=160)
    scope_assessment: AuditScopeAssessment | None
    solidity_coverage: SolidityCoverage | None
    model_review_coverage: ModelReviewCoverage | None


class CostLedgerAbsenceEvidence(StrictModel):
    """Typed zero-usage state that never invents a ledger snapshot."""

    schema_version: Literal["1.0"] = "1.0"
    state: Literal["ABSENT_ZERO", "UNESTABLISHED_ZERO"]
    status: Literal["NOT_APPLICABLE", "INCONCLUSIVE"]
    reason: Literal[
        "NO_MODEL_USAGE_AND_NO_PERSISTENT_LEDGER",
        "NO_MODEL_USAGE_AND_NO_CAMPAIGN_LEDGER_EVIDENCE",
    ]
    persistent_ledger_configured: bool
    usage_record_count: Literal[0] = 0
    run_entry_count: Literal[0] = 0
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(cls, *, persistent_ledger_configured: bool) -> CostLedgerAbsenceEvidence:
        values = _cost_ledger_absence_values(
            persistent_ledger_configured=persistent_ledger_configured
        )
        return cls(**values, evidence_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def absence_is_exact_and_hash_bound(self) -> CostLedgerAbsenceEvidence:
        expected = _cost_ledger_absence_values(
            persistent_ledger_configured=self.persistent_ledger_configured
        )
        if self.model_dump(
            mode="json", exclude={"evidence_sha256"}
        ) != expected or self.evidence_sha256 != scheduler_canonical_sha256(expected):
            raise ValueError("cost-ledger absence evidence is inconsistent")
        return self


class CostLedgerAttemptEvidence(StrictModel):
    """One terminal campaign reservation with an optional exact usage join."""

    schema_version: Literal["1.0"] = "1.0"
    logical_request_id: str = Field(pattern=_SCHEDULER_REQUEST_PATTERN)
    attempt_index: int = Field(ge=1, le=6)
    request_id: str = Field(min_length=1, max_length=128)
    reservation_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    status: CostEntryStatus
    release_reason: ReleaseReason | None
    reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    reconciled_cost_usd_exact: str | None = Field(default=None, pattern=_USD_EXACT_PATTERN)
    accounted_cost_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    released_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    created_at: datetime
    updated_at: datetime
    usage_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    ledger_entry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_entry(
        cls,
        *,
        logical_request_id: str,
        attempt_index: int,
        entry: CostEntry,
        usage_record_sha256: str | None,
    ) -> CostLedgerAttemptEvidence:
        released = (
            entry.reserved_usd
            if entry.status is CostEntryStatus.RELEASED
            else (
                entry.reserved_usd - entry.accounted_cost_usd
                if entry.status is CostEntryStatus.RECONCILED
                else Decimal(0)
            )
        )
        return cls(
            logical_request_id=logical_request_id,
            attempt_index=attempt_index,
            request_id=entry.request_id,
            reservation_id=entry.reservation_id,
            status=entry.status,
            release_reason=entry.release_reason,
            reserved_usd_exact=_money_text(entry.reserved_usd),
            reconciled_cost_usd_exact=(
                None if entry.actual_cost_usd is None else _money_text(entry.actual_cost_usd)
            ),
            accounted_cost_usd_exact=_money_text(entry.accounted_cost_usd),
            released_usd_exact=_money_text(released),
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            usage_record_sha256=usage_record_sha256,
            ledger_entry_sha256=cost_entry_sha256(entry),
        )

    @model_validator(mode="after")
    def terminal_lifecycle_and_hash_are_exact(self) -> CostLedgerAttemptEvidence:
        expected_request_id = _attempt_request_id(self.logical_request_id, self.attempt_index)
        if self.request_id != expected_request_id:
            raise ValueError("cost-ledger attempt identity differs from its logical request")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() != UTC.utcoffset(
            self.created_at
        ):
            raise ValueError("cost-ledger attempt creation timestamp must use UTC")
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() != UTC.utcoffset(
            self.updated_at
        ):
            raise ValueError("cost-ledger attempt update timestamp must use UTC")
        if self.updated_at < self.created_at:
            raise ValueError("cost-ledger attempt update precedes its reservation")
        reserved = Decimal(self.reserved_usd_exact)
        reconciled = (
            None
            if self.reconciled_cost_usd_exact is None
            else Decimal(self.reconciled_cost_usd_exact)
        )
        accounted = Decimal(self.accounted_cost_usd_exact)
        released = Decimal(self.released_usd_exact)
        if reserved <= 0:
            raise ValueError("cost-ledger attempt reservation must be positive")
        if self.status is CostEntryStatus.RESERVED:
            raise ValueError("forensic cost-ledger attempt must be terminal")
        expected_released = Decimal(0)
        if self.status is CostEntryStatus.RELEASED:
            valid = reconciled is None and accounted == 0 and self.release_reason is not None
            expected_released = reserved
        elif self.status is CostEntryStatus.RECONCILED:
            valid = (
                reconciled is not None
                and reconciled <= reserved
                and accounted == reconciled
                and self.release_reason is None
            )
            expected_released = reserved - accounted
        elif self.status is CostEntryStatus.UNCERTAIN_ACCOUNTED:
            valid = reconciled is None and accounted == reserved and self.release_reason is None
        else:
            valid = (
                self.status is CostEntryStatus.RESERVATION_OVERRUN
                and reconciled is not None
                and reconciled > reserved
                and accounted == reconciled
                and self.release_reason is None
            )
        if not valid or released != expected_released:
            raise ValueError("forensic cost-ledger attempt lifecycle is inconsistent")
        entry = CostEntry(
            request_id=self.request_id,
            reservation_id=self.reservation_id,
            status=self.status,
            reserved_usd=reserved,
            actual_cost_usd=reconciled,
            accounted_cost_usd=accounted,
            release_reason=self.release_reason,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )
        if cost_entry_sha256(entry) != self.ledger_entry_sha256:
            raise ValueError("forensic cost-ledger attempt differs from its persisted entry hash")
        return self


class RunCostLedgerEvidence(StrictModel):
    """Exact campaign-only delta between immutable atomic ledger snapshots."""

    schema_version: Literal["1.0"] = "1.0"
    state: Literal["RUN_SCOPED_CLOSED"] = "RUN_SCOPED_CLOSED"
    status: Literal["VALIDATED"] = "VALIDATED"
    baseline_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    final_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cap_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    baseline_spent_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    baseline_active_reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    final_spent_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    final_active_reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    final_remaining_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    run_reserved_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    run_accounted_cost_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    run_released_usd_exact: str = Field(pattern=_USD_EXACT_PATTERN)
    baseline_entry_count: int = Field(ge=0, le=1_000_000)
    final_entry_count: int = Field(ge=0, le=1_000_000)
    run_entry_count: int = Field(ge=0, le=1_000_000)
    final_over_cap: bool
    baseline_has_reservation_overrun: bool
    final_has_reservation_overrun: bool
    attempts: list[CostLedgerAttemptEvidence] = Field(max_length=1_000_000)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        baseline: SchedulerCostLedgerBaseline,
        final_snapshot: CostLedgerSnapshot,
        attempts: Sequence[CostLedgerAttemptEvidence],
        baseline_has_reservation_overrun: bool,
    ) -> RunCostLedgerEvidence:
        canonical_attempts = sorted(
            attempts,
            key=lambda item: (item.logical_request_id, item.attempt_index),
        )
        values = {
            "schema_version": "1.0",
            "state": "RUN_SCOPED_CLOSED",
            "status": "VALIDATED",
            "baseline_sha256": baseline.baseline_sha256,
            "baseline_snapshot_sha256": baseline.ledger_snapshot_sha256,
            "final_snapshot_sha256": cost_ledger_snapshot_sha256(final_snapshot),
            "cap_usd_exact": _money_text(final_snapshot.cap_usd),
            "baseline_spent_usd_exact": _money_text(Decimal(baseline.spent_usd_exact)),
            "baseline_active_reserved_usd_exact": _money_text(
                Decimal(baseline.active_reserved_usd_exact)
            ),
            "final_spent_usd_exact": _money_text(final_snapshot.spent_usd),
            "final_active_reserved_usd_exact": _money_text(final_snapshot.active_reserved_usd),
            "final_remaining_usd_exact": _money_text(final_snapshot.remaining_usd),
            "run_reserved_usd_exact": _money_text(
                sum(
                    (Decimal(item.reserved_usd_exact) for item in canonical_attempts),
                    start=Decimal(0),
                )
            ),
            "run_accounted_cost_usd_exact": _money_text(
                sum(
                    (Decimal(item.accounted_cost_usd_exact) for item in canonical_attempts),
                    start=Decimal(0),
                )
            ),
            "run_released_usd_exact": _money_text(
                sum(
                    (Decimal(item.released_usd_exact) for item in canonical_attempts),
                    start=Decimal(0),
                )
            ),
            "baseline_entry_count": len(baseline.entries),
            "final_entry_count": len(final_snapshot.entries),
            "run_entry_count": len(canonical_attempts),
            "final_over_cap": final_snapshot.over_cap,
            "baseline_has_reservation_overrun": baseline_has_reservation_overrun,
            "final_has_reservation_overrun": final_snapshot.has_reservation_overrun,
            "attempts": canonical_attempts,
        }
        return cls(**values, evidence_sha256=scheduler_canonical_sha256(values))

    @model_validator(mode="after")
    def delta_totals_closure_and_hash_are_exact(self) -> RunCostLedgerEvidence:
        if self.attempts != sorted(
            self.attempts,
            key=lambda item: (item.logical_request_id, item.attempt_index),
        ):
            raise ValueError("run cost-ledger attempts must be canonically ordered")
        identities = [(item.logical_request_id, item.attempt_index) for item in self.attempts]
        if len(identities) != len(set(identities)):
            raise ValueError("run cost-ledger attempts repeat an identity")
        request_ids = [item.request_id for item in self.attempts]
        reservation_ids = [item.reservation_id for item in self.attempts]
        if len(request_ids) != len(set(request_ids)) or len(reservation_ids) != len(
            set(reservation_ids)
        ):
            raise ValueError("run cost-ledger attempts repeat a reservation")
        by_logical: dict[str, list[CostLedgerAttemptEvidence]] = {}
        for attempt in self.attempts:
            by_logical.setdefault(attempt.logical_request_id, []).append(attempt)
        for attempts in by_logical.values():
            if [item.attempt_index for item in attempts] != list(range(1, len(attempts) + 1)):
                raise ValueError("run cost-ledger attempt indices are not contiguous")
            if sum(item.status is CostEntryStatus.RELEASED for item in attempts) > 1:
                raise ValueError("run cost-ledger request contains repeated pre-send releases")
            if any(
                item.status is CostEntryStatus.RELEASED and item is not attempts[-1]
                for item in attempts
            ):
                raise ValueError("pre-send release must be the terminal logical attempt")
        baseline_spent = Decimal(self.baseline_spent_usd_exact)
        baseline_active = Decimal(self.baseline_active_reserved_usd_exact)
        final_spent = Decimal(self.final_spent_usd_exact)
        final_active = Decimal(self.final_active_reserved_usd_exact)
        cap = Decimal(self.cap_usd_exact)
        run_reserved = sum(
            (Decimal(item.reserved_usd_exact) for item in self.attempts),
            start=Decimal(0),
        )
        run_accounted = sum(
            (Decimal(item.accounted_cost_usd_exact) for item in self.attempts),
            start=Decimal(0),
        )
        run_released = sum(
            (Decimal(item.released_usd_exact) for item in self.attempts),
            start=Decimal(0),
        )
        if (
            baseline_active != 0
            or final_active != 0
            or final_spent != baseline_spent + run_accounted
            or Decimal(self.final_remaining_usd_exact) != max(Decimal(0), cap - final_spent)
            or Decimal(self.run_reserved_usd_exact) != run_reserved
            or Decimal(self.run_accounted_cost_usd_exact) != run_accounted
            or Decimal(self.run_released_usd_exact) != run_released
            or self.final_entry_count != self.baseline_entry_count + len(self.attempts)
            or self.run_entry_count != len(self.attempts)
            or self.final_over_cap != (final_spent > cap)
            or self.final_has_reservation_overrun
            != (
                self.baseline_has_reservation_overrun
                or any(item.status is CostEntryStatus.RESERVATION_OVERRUN for item in self.attempts)
            )
        ):
            raise ValueError("run cost-ledger snapshot delta does not close exactly")
        expected_hash = scheduler_canonical_sha256(
            self.model_dump(mode="json", exclude={"evidence_sha256"})
        )
        if self.evidence_sha256 != expected_hash:
            raise ValueError("run cost-ledger evidence hash is inconsistent")
        return self


CostLedgerForensicEvidence = CostLedgerAbsenceEvidence | RunCostLedgerEvidence


def _validate_usage_cost_joins(
    usage: Sequence[UsageRecord],
    attempts: Sequence[CostLedgerAttemptEvidence],
) -> None:
    """Require every charged campaign entry to close against exact emitted usage."""

    usage_by_id = {record.request_id: record for record in usage}
    if len(usage_by_id) != len(usage):
        raise ValueError("model execution usage contains duplicate request identities")
    attempts_by_logical: dict[str, list[CostLedgerAttemptEvidence]] = {}
    for attempt in attempts:
        attempts_by_logical.setdefault(attempt.logical_request_id, []).append(attempt)
        record = usage_by_id.get(attempt.logical_request_id)
        expected_usage_sha256 = (
            None if record is None else scheduler_canonical_sha256(record.model_dump(mode="json"))
        )
        if attempt.usage_record_sha256 != expected_usage_sha256:
            raise ValueError("cost-ledger attempt differs from its emitted usage record")
    if not set(usage_by_id) <= set(attempts_by_logical):
        raise ValueError("model usage lacks run-scoped cost-ledger attempts")
    for logical_request_id, logical_attempts in attempts_by_logical.items():
        record = usage_by_id.get(logical_request_id)
        if record is None:
            if any(
                item.status not in {CostEntryStatus.RELEASED, CostEntryStatus.UNCERTAIN_ACCOUNTED}
                for item in logical_attempts
            ):
                raise ValueError("charged cost-ledger attempt lacks emitted usage evidence")
            continue
        if (
            len(logical_attempts) != record.attempts
            or [item.attempt_index for item in logical_attempts]
            != list(range(1, record.attempts + 1))
            or sum(
                (Decimal(item.accounted_cost_usd_exact) for item in logical_attempts),
                start=Decimal(0),
            )
            != Decimal(record.accounted_cost_usd_exact or "0")
        ):
            raise ValueError("emitted usage does not exactly close its cost-ledger attempts")


def build_run_cost_ledger_evidence(
    *,
    baseline: SchedulerCostLedgerBaseline,
    final_snapshot: CostLedgerSnapshot,
    campaign_logical_request_ids: Sequence[str],
    usage_records: Sequence[UsageRecord],
) -> RunCostLedgerEvidence:
    """Project only one scheduler campaign's exact terminal atomic-ledger delta."""

    baseline = SchedulerCostLedgerBaseline.model_validate(baseline.model_dump(mode="python"))
    campaign_ids = tuple(campaign_logical_request_ids)
    if len(campaign_ids) != len(set(campaign_ids)) or any(
        re.fullmatch(_SCHEDULER_REQUEST_PATTERN, item) is None for item in campaign_ids
    ):
        raise ValueError("campaign cost custody requires unique scheduler request identities")
    usage = tuple(
        UsageRecord.model_validate(record.model_dump(mode="python")) for record in usage_records
    )
    usage_ids = tuple(record.request_id for record in usage)
    if len(usage_ids) != len(set(usage_ids)) or not set(usage_ids) <= set(campaign_ids):
        raise ValueError("model usage is outside the scheduler campaign inventory")
    if final_snapshot.cap_usd != Decimal(baseline.cap_usd_exact):
        raise ValueError("final cost-ledger cap differs from its scheduler baseline")

    final_entries = {entry.request_id: entry for entry in final_snapshot.entries}
    if len(final_entries) != len(final_snapshot.entries):
        raise ValueError("final cost-ledger snapshot repeats a request identity")
    if final_snapshot.entries != tuple(
        sorted(final_snapshot.entries, key=lambda item: item.request_id)
    ):
        raise ValueError("final cost-ledger snapshot entries are not canonically ordered")
    final_reservation_ids = [entry.reservation_id for entry in final_snapshot.entries]
    if len(final_reservation_ids) != len(set(final_reservation_ids)):
        raise ValueError("final cost-ledger snapshot repeats a reservation identity")
    baseline_by_id = {entry.request_id: entry for entry in baseline.entries}
    final_baseline_ids = tuple(
        entry.request_id for entry in final_snapshot.entries if entry.request_id in baseline_by_id
    )
    if final_baseline_ids != tuple(entry.request_id for entry in baseline.entries):
        raise ValueError("cost-ledger baseline ordered prefix changed during the campaign")
    prefix_entries: list[CostEntry] = []
    for request_id, baseline_entry in baseline_by_id.items():
        final_entry = final_entries.get(request_id)
        if (
            final_entry is None
            or cost_entry_sha256(final_entry) != baseline_entry.ledger_entry_sha256
        ):
            raise ValueError("cost-ledger baseline entry changed during the campaign")
        prefix_entries.append(final_entry)
    baseline_spent = sum(
        (entry.accounted_cost_usd for entry in prefix_entries),
        start=Decimal(0),
    )
    baseline_active = sum(
        (
            entry.reserved_usd
            for entry in prefix_entries
            if entry.status is CostEntryStatus.RESERVED
        ),
        start=Decimal(0),
    )
    if baseline_spent != Decimal(baseline.spent_usd_exact) or baseline_active != Decimal(
        baseline.active_reserved_usd_exact
    ):
        raise ValueError("cost-ledger baseline totals differ from its exact entry prefix")
    reconstructed_baseline = CostLedgerSnapshot(
        cap_usd=final_snapshot.cap_usd,
        spent_usd=baseline_spent,
        active_reserved_usd=baseline_active,
        remaining_usd=max(Decimal(0), final_snapshot.cap_usd - baseline_spent - baseline_active),
        over_cap=baseline_spent + baseline_active > final_snapshot.cap_usd,
        has_reservation_overrun=any(
            entry.status is CostEntryStatus.RESERVATION_OVERRUN for entry in prefix_entries
        ),
        entries=tuple(prefix_entries),
    )
    if cost_ledger_snapshot_sha256(reconstructed_baseline) != baseline.ledger_snapshot_sha256:
        raise ValueError("cost-ledger baseline snapshot hash does not match its final prefix")

    usage_hashes = {
        record.request_id: scheduler_canonical_sha256(record.model_dump(mode="json"))
        for record in usage
    }
    attempts: list[CostLedgerAttemptEvidence] = []
    campaign_set = set(campaign_ids)
    for entry in final_snapshot.entries:
        if entry.request_id in baseline_by_id:
            continue
        match = re.fullmatch(
            rf"({_SCHEDULER_REQUEST_PATTERN[1:-1]})(?::attempt:([0-9]+))?",
            entry.request_id,
        )
        if match is None or match.group(1) not in campaign_set:
            raise ValueError("final cost-ledger delta contains a non-campaign reservation")
        logical_request_id = match.group(1)
        attempt_index = 1 if match.group(2) is None else int(match.group(2))
        if (
            attempt_index > 6
            or _attempt_request_id(logical_request_id, attempt_index) != entry.request_id
        ):
            raise ValueError("campaign cost-ledger attempt identity is non-canonical")
        attempts.append(
            CostLedgerAttemptEvidence.from_entry(
                logical_request_id=logical_request_id,
                attempt_index=attempt_index,
                entry=entry,
                usage_record_sha256=usage_hashes.get(logical_request_id),
            )
        )
    evidence = RunCostLedgerEvidence.build(
        baseline=baseline,
        final_snapshot=final_snapshot,
        attempts=attempts,
        baseline_has_reservation_overrun=reconstructed_baseline.has_reservation_overrun,
    )
    _validate_usage_cost_joins(usage, evidence.attempts)
    return evidence


class ModelExecutionArtifact(ReportStatusProjection):
    """Non-secret model execution and cost evidence for the forensic bundle."""

    schema_version: Literal["1.0", "1.1"] = "1.1"
    run_id: str = Field(min_length=1, max_length=160)
    configured_models: dict[str, str]
    configured_fallbacks: dict[str, list[str]]
    requested_models: list[str]
    actual_models: list[str]
    provider_endpoints: list[str]
    usage: list[UsageRecord]
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    cached_tokens: int = Field(ge=0)
    accounted_cost_usd: float = Field(ge=0)
    accounted_cost_usd_exact: str = Field(pattern=r"^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,36})?$")
    budget_usd: float = Field(ge=0)
    privacy_profile: str
    source_code_egress_enabled: bool
    raw_prompts_retained: bool
    raw_responses_retained: bool
    cost_ledger: CostLedgerForensicEvidence | None = None

    @model_validator(mode="after")
    def totals_are_exact(self) -> ModelExecutionArtifact:
        if self.prompt_tokens != sum(record.prompt_tokens for record in self.usage):
            raise ValueError("model execution prompt-token total is inconsistent")
        if self.completion_tokens != sum(record.completion_tokens for record in self.usage):
            raise ValueError("model execution completion-token total is inconsistent")
        if self.reasoning_tokens != sum(record.reasoning_tokens for record in self.usage):
            raise ValueError("model execution reasoning-token total is inconsistent")
        if self.cached_tokens != sum(record.cached_tokens for record in self.usage):
            raise ValueError("model execution cached-token total is inconsistent")
        if Decimal(self.accounted_cost_usd_exact) != Decimal(str(self.accounted_cost_usd)):
            raise ValueError("model execution exact cost differs from presentation cost")
        if self.schema_version == "1.0":
            if self.cost_ledger is not None:
                raise ValueError("legacy model-execution evidence cannot carry cost custody")
            return self
        if self.cost_ledger is None:
            raise ValueError("current model-execution evidence requires typed cost custody")
        if isinstance(self.cost_ledger, CostLedgerAbsenceEvidence):
            if self.usage or Decimal(self.accounted_cost_usd_exact) != 0:
                raise ValueError("cost-ledger absence requires zero model usage and cost")
            return self
        lifecycle = self.cost_ledger
        _validate_usage_cost_joins(self.usage, lifecycle.attempts)
        if Decimal(self.accounted_cost_usd_exact) != Decimal(
            lifecycle.run_accounted_cost_usd_exact
        ):
            raise ValueError("model execution total differs from run-scoped ledger custody")
        if Decimal(str(self.budget_usd)) != Decimal(lifecycle.cap_usd_exact):
            raise ValueError("model execution budget differs from run-scoped ledger custody")
        return self


def effective_run_status(report: AuditReport) -> AuditRunStatus:
    """Return the typed status, or a calibrated projection for legacy reports."""

    return effective_report_status(report).run_status


def _disposition(
    finding: Finding,
    verifications: Sequence[VerificationDecision],
    cross_examinations: Sequence[CandidateCrossExaminationDecision],
    falsifications: Sequence[FalsificationDecision],
    reproductions: Sequence[ReproductionResult],
    resolutions: Sequence[CandidateReproductionResolution],
) -> ForensicDisposition:
    if finding.status is FindingStatus.REJECTED:
        return ForensicDisposition.REJECTED
    contributor_ids = set(finding.contributing_candidate_ids)
    if (
        any(
            decision.candidate_id in contributor_ids
            and decision.verdict is CandidateCrossExaminationVerdict.DISPUTED
            for decision in cross_examinations
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is VerificationVerdict.REJECTED
            for decision in verifications
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is FalsificationVerdict.FALSIFIED
            for decision in falsifications
        )
        or any(
            result.candidate_id in contributor_ids and result.state is ReproductionState.DISPROVEN
            for result in reproductions
        )
    ):
        return ForensicDisposition.DISPUTED
    if (
        any(
            resolution.candidate_id in contributor_ids
            and resolution.kind is ReproductionResolutionKind.INCONCLUSIVE
            for resolution in resolutions
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is VerificationVerdict.INSUFFICIENT_CONTEXT
            for decision in verifications
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict is CandidateCrossExaminationVerdict.INCONCLUSIVE
            for decision in cross_examinations
        )
        or any(
            decision.candidate_id in contributor_ids
            and decision.verdict in {FalsificationVerdict.INCONCLUSIVE, FalsificationVerdict.UNSAFE}
            for decision in falsifications
        )
        or any(
            result.candidate_id in contributor_ids
            and result.state
            in {
                ReproductionState.GENERATION_FAILED,
                ReproductionState.COMPILE_FAILED,
                ReproductionState.ENVIRONMENT_BLOCKED,
                ReproductionState.NOT_REPRODUCED,
                ReproductionState.PARTIALLY_REPRODUCED,
            }
            for result in reproductions
        )
        or finding.status
        in {
            FindingStatus.NEEDS_REVIEW,
            FindingStatus.INSUFFICIENT_CONTEXT,
            FindingStatus.UNSUPPORTED,
        }
    ):
        return ForensicDisposition.INCONCLUSIVE
    if finding.status is FindingStatus.CONFIRMED:
        return ForensicDisposition.CONFIRMED
    return ForensicDisposition.SUPPORTED


def build_findings_artifact(
    report: AuditReport,
    *,
    candidates: Sequence[CandidateFinding] = (),
    reproduction_resolutions: Sequence[CandidateReproductionResolution] = (),
    source_excerpts: Mapping[str, SourceExcerptEvidence] | None = None,
) -> FindingsArtifact:
    """Build an exact candidate-linked forensic finding inventory."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    excerpts = source_excerpts or {}
    records: list[ForensicFindingRecord] = []
    for finding in [*report.findings, *report.rejected_findings]:
        contributor_ids = set(finding.contributing_candidate_ids)
        linked_candidates = sorted(
            [
                candidate_by_id[candidate_id]
                for candidate_id in finding.contributing_candidate_ids
                if candidate_id in candidate_by_id
            ],
            key=lambda item: item.candidate_id,
        )
        linked_verifications = sorted(
            (
                item
                for item in report.verification_decisions
                if item.candidate_id in contributor_ids
            ),
            key=lambda item: item.candidate_id,
        )
        linked_cross_examinations = sorted(
            (
                item
                for item in report.cross_examination_decisions
                if item.candidate_id in contributor_ids
            ),
            key=lambda item: (
                item.candidate_id,
                item.reviewer_index,
                item.root_lineage,
                item.request_id,
            ),
        )
        linked_falsifications = sorted(
            (
                item
                for item in report.falsification_decisions
                if item.candidate_id in contributor_ids
            ),
            key=lambda item: (item.candidate_id, item.test_name),
        )
        linked_reproductions = sorted(
            (item for item in report.reproductions if item.candidate_id in contributor_ids),
            key=lambda item: (item.candidate_id, item.test_name, item.specification_sha256),
        )
        linked_resolutions = sorted(
            (item for item in reproduction_resolutions if item.candidate_id in contributor_ids),
            key=lambda item: (item.candidate_id, item.kind.value, item.detail),
        )
        records.append(
            ForensicFindingRecord(
                finding_id=finding.id,
                disposition=_disposition(
                    finding,
                    linked_verifications,
                    linked_cross_examinations,
                    linked_falsifications,
                    linked_reproductions,
                    linked_resolutions,
                ),
                finding=finding,
                source_excerpt=excerpts.get(finding.id),
                candidate_findings=linked_candidates,
                verification_decisions=linked_verifications,
                cross_examination_decisions=linked_cross_examinations,
                falsification_decisions=linked_falsifications,
                reproductions=linked_reproductions,
                reproduction_resolutions=linked_resolutions,
            )
        )
    projection = effective_report_status(report)
    return FindingsArtifact(
        **projection.model_dump(mode="python"),
        run_id=report.run_id,
        findings=list(report.findings),
        rejected_findings=list(report.rejected_findings),
        records=records,
        candidate_findings=sorted(candidates, key=lambda item: item.candidate_id),
    )


def build_coverage_artifact(report: AuditReport) -> CoverageArtifact:
    """Build the canonical forensic coverage projection."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    projection = effective_report_status(report)
    return CoverageArtifact(
        **projection.model_dump(mode="python"),
        run_id=report.run_id,
        scope_assessment=report.scope_assessment,
        solidity_coverage=report.effective_solidity_coverage(),
        model_review_coverage=report.model_review_coverage,
    )


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {
        str(key): item
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        if isinstance(item, str)
    }


def _fallback_mapping(value: object) -> dict[str, list[str]]:
    if not isinstance(value, Mapping):
        return {}
    normalized: dict[str, list[str]] = {}
    for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
        if isinstance(item, (list, tuple)) and all(isinstance(entry, str) for entry in item):
            normalized[str(key)] = list(item)
    return normalized


def build_model_execution_artifact(
    report: AuditReport,
    *,
    cost_ledger_evidence: RunCostLedgerEvidence | None = None,
    persistent_ledger_configured: bool = False,
    legacy_schema_1_0: bool = False,
) -> ModelExecutionArtifact:
    """Build non-secret model evidence, requiring custody for every current usage record."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    usage = list(report.usage)
    if legacy_schema_1_0:
        if cost_ledger_evidence is not None or persistent_ledger_configured:
            raise ValueError("legacy model-execution projection cannot claim cost custody")
        cost_evidence: CostLedgerForensicEvidence | None = None
    elif cost_ledger_evidence is not None:
        cost_evidence = RunCostLedgerEvidence.model_validate(
            cost_ledger_evidence.model_dump(mode="python")
        )
    elif usage:
        raise ValueError("model usage requires exact run-scoped cost-ledger closure")
    else:
        cost_evidence = CostLedgerAbsenceEvidence.build(
            persistent_ledger_configured=persistent_ledger_configured
        )
    exact_cost = sum(
        (
            Decimal(record.accounted_cost_usd_exact)
            if record.accounted_cost_usd_exact is not None
            else Decimal(str(record.accounted_cost_usd))
            for record in usage
        ),
        start=Decimal("0"),
    )
    if cost_ledger_evidence is not None:
        exact_cost = Decimal(cost_ledger_evidence.run_accounted_cost_usd_exact)
        if Decimal(str(report.accounted_cost_usd)) != exact_cost:
            raise ValueError("final report cost differs from run-scoped ledger custody")
    elif not usage:
        exact_cost = Decimal(str(report.accounted_cost_usd))
    projection = effective_report_status(report)
    return ModelExecutionArtifact(
        **projection.model_dump(mode="python"),
        schema_version="1.0" if legacy_schema_1_0 else "1.1",
        run_id=report.run_id,
        configured_models=_string_mapping(report.metadata.get("configured_models")),
        configured_fallbacks=_fallback_mapping(report.metadata.get("configured_fallbacks")),
        requested_models=sorted({record.requested_model for record in usage}),
        actual_models=sorted(
            {
                model
                for record in usage
                for model in (record.actual_model or record.returned_model,)
                if model is not None
            }
        ),
        provider_endpoints=sorted(
            {
                endpoint
                for record in usage
                for endpoint in (
                    [record.actual_provider_endpoint]
                    if record.actual_provider_endpoint is not None
                    else record.configured_provider_endpoints
                )
            }
        ),
        usage=usage,
        prompt_tokens=sum(record.prompt_tokens for record in usage),
        completion_tokens=sum(record.completion_tokens for record in usage),
        reasoning_tokens=sum(record.reasoning_tokens for record in usage),
        cached_tokens=sum(record.cached_tokens for record in usage),
        accounted_cost_usd=float(exact_cost),
        accounted_cost_usd_exact=_money_text(exact_cost),
        budget_usd=report.budget_usd,
        privacy_profile=str(report.privacy.get("profile", "UNKNOWN")),
        source_code_egress_enabled=bool(report.privacy.get("code_egress_enabled", False)),
        raw_prompts_retained=bool(report.privacy.get("store_raw_prompts", False)),
        raw_responses_retained=bool(report.privacy.get("store_raw_responses", False)),
        cost_ledger=cost_evidence,
    )
