"""Bounded local stage receipts and progress; none establishes a validated audit."""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus_coverage import (
    CoveragePath,
    DevelopmentCorpusCoverageSummary,
)
from mmaudit.models.development_ensemble import DevelopmentEnsembleStageId
from mmaudit.models.development_judgment import _money_sum
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.orchestration.manifest import ManifestFileBinding


class DevelopmentTreeStageStart(_DevelopmentModel):
    """Written exclusively before dispatch; an unclosed start is never inferred unsent."""

    schema_version: Literal["1.0"] = "1.0"
    tree_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    primary_index: int = Field(ge=1, le=256)
    stage: DevelopmentEnsembleStageId
    child_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_id: str = Field(min_length=1, max_length=256)
    allotted_seconds: float = Field(gt=0, le=1800)


class DevelopmentTreeStageEnd(_DevelopmentModel):
    """A verified durable child and elapsed active work; failed attempts are not retryable here."""

    start: DevelopmentTreeStageStart
    result_file: ManifestFileBinding
    elapsed_seconds: float = Field(ge=0)


class DevelopmentTreePrimaryProgress(_DevelopmentModel):
    filename: CoveragePath
    status: Literal[
        "PENDING",
        "CANDIDATE_INCOMPLETE",
        "NO_CANDIDATES",
        "REVIEW_INCOMPLETE",
        "OBSERVED_ALL_STAGES",
    ]
    completed_attempt_count: int = Field(ge=0, le=3)
    elapsed_seconds: float = Field(ge=0)

    @model_validator(mode="after")
    def status_preserves_actual_attempts(self) -> Self:
        counts = {
            "PENDING": (0,),
            "CANDIDATE_INCOMPLETE": (0, 1),
            "NO_CANDIDATES": (1,),
            "REVIEW_INCOMPLETE": (1, 2, 3),
            "OBSERVED_ALL_STAGES": (3,),
        }
        if self.completed_attempt_count not in counts[self.status] or (
            self.status == "PENDING" and self.elapsed_seconds != 0
        ):
            raise ValueError("automatic tree primary status contradicts its retained attempts")
        return self


class DevelopmentTreeExecutionProgress(_AuditArtifact):
    """Derived from the original durable children; response coverage is not security assurance."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_tree_execution_progress"] = (
        "development_tree_execution_progress"
    )
    tree_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["OBSERVED_ALL_AVAILABLE_STAGES", "INCOMPLETE"]
    primary_statuses: tuple[DevelopmentTreePrimaryProgress, ...] = Field(
        min_length=1, max_length=256
    )
    coverage: DevelopmentCorpusCoverageSummary
    completed_attempt_count: int = Field(ge=0, le=768)
    total_accounted_cost_usd: Decimal = Field(ge=0)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    elapsed_active_seconds: float = Field(ge=0)
    elapsed_scope: Literal[
        "SUM_OF_RETAINED_ACTIVE_STAGE_INTERVALS_EXCLUDES_OFFLINE_PREPARATION"
    ] = "SUM_OF_RETAINED_ACTIVE_STAGE_INTERVALS_EXCLUDES_OFFLINE_PREPARATION"

    @model_validator(mode="after")
    def progress_preserves_slots_accounting_and_coverage(self) -> Self:
        """Internal consistency only; actual children and source custody must still be replayed."""
        rows = self.primary_statuses
        paths = tuple(row.filename for row in rows)
        complete = all(row.status in {"NO_CANDIDATES", "OBSERVED_ALL_STAGES"} for row in rows)
        if paths != tuple(sorted(set(paths))) or (
            (self.status == "OBSERVED_ALL_AVAILABLE_STAGES") != complete
            or self.completed_attempt_count != sum(row.completed_attempt_count for row in rows)
            # The producer sums child intervals; grouped row sums can differ by float rounding.
            or not math.isclose(
                self.elapsed_active_seconds,
                sum(row.elapsed_seconds for row in rows),
                rel_tol=1e-12,
                abs_tol=1e-9,
            )
        ):
            raise ValueError("automatic tree aggregate progress contradicts its primary slots")
        if self.total_accounted_cost_usd != _money_sum(
            (
                self.reported_actual_cost_usd,
                self.uncertain_accounted_cost_usd,
                self.active_reserved_usd,
            )
        ) or (self.completed_attempt_count == 0 and self.total_accounted_cost_usd != 0):
            raise ValueError("automatic tree progress changes its accounted cost components")

        coverage = self.coverage
        source_set = set(paths)
        selected = {row.filename for row in rows if row.status != "PENDING"}
        known_success = {
            row.filename for row in rows if row.status not in {"PENDING", "CANDIDATE_INCOMPLETE"}
        }
        attempted = {row.filename for row in rows if row.completed_attempt_count}
        successful = set(coverage.successful_primary_paths)
        context = set(coverage.context_paths)
        failed = set(coverage.failed_primary_paths)
        missing = set(coverage.missing_primary_paths)
        for name in type(coverage).model_fields:
            value = getattr(coverage, name)
            if isinstance(value, tuple) and (
                value != tuple(sorted(set(value))) or not set(value) <= source_set
            ):
                raise ValueError("automatic tree coverage has repeated, unordered or foreign paths")
        # A retained response followed by interruption may cover a primary without completing
        # its candidate stage. Do not discard that response or promote the interrupted stage.
        if (
            not known_success <= successful <= selected & attempted
            or coverage.selected_primary_paths != tuple(sorted(selected))
            or coverage.original_successful_primary_paths != coverage.successful_primary_paths
            or coverage.context_only_paths != tuple(sorted(context - selected))
            or coverage.unobserved_primary_paths != tuple(sorted(selected - successful))
            or coverage.unselected_paths != tuple(sorted(source_set - selected))
            or coverage.not_successfully_observed_paths != tuple(sorted(source_set - successful))
            or failed & missing
            or failed | missing != selected - successful
            or not failed <= attempted
            or coverage.invalidated_primary_paths
            or coverage.source_drift_paths
            or (coverage.status == "ALL_PRIMARY_RESPONSES_OBSERVED") != (successful == source_set)
            or coverage.original_first_attempt_complete
            != (
                successful == source_set
                and all(row.status != "CANDIDATE_INCOMPLETE" for row in rows)
            )
        ):
            raise ValueError("automatic tree coverage contradicts its exact primary progress")
        pending_seen = False
        for row in rows:
            if pending_seen and row.status != "PENDING":
                raise ValueError("automatic tree progress skips a pending original primary")
            pending_seen = pending_seen or row.status == "PENDING"
        return self
