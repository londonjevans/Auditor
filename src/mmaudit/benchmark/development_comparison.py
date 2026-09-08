"""Descriptive comparisons of retained development runs, never ensemble qualification."""

from __future__ import annotations

import math
from decimal import Decimal, localcontext
from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development import (
    DevelopmentBenchmarkScore,
    DevelopmentBenchmarkSummary,
    DevelopmentMeasurementRatio,
    _ratio,
)
from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_COMPARISON_RUNS = 8
MAX_DEVELOPMENT_COMPARISON_SCORE_BYTES = 2_000_000
MAX_DEVELOPMENT_COMPARISON_BYTES = 18_000_000
_SHA = r"^[0-9a-f]{64}$"


class DevelopmentComparisonRow(_DevelopmentModel):
    run_id: str
    exact_model_id: str
    provider_endpoint: str
    maximum_completion_tokens: int = Field(gt=0, le=65_536)
    score_sha256: str = Field(pattern=_SHA)
    summary: DevelopmentBenchmarkSummary
    roots_unique_to_run: tuple[str, ...] = Field(max_length=16)
    roots_shared_with_other_runs: tuple[str, ...] = Field(max_length=16)


class DevelopmentComparisonUnion(_DevelopmentModel):
    interpretation: Literal["OBSERVED_ROOT_UNION_NOT_AN_EXECUTED_ENSEMBLE"] = (
        "OBSERVED_ROOT_UNION_NOT_AN_EXECUTED_ENSEMBLE"
    )
    quality_scope: Literal["COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS"]
    incomplete_run_ids: tuple[str, ...] = Field(max_length=MAX_DEVELOPMENT_COMPARISON_RUNS)
    expected_root_ids: tuple[str, ...] = Field(max_length=16)
    matched_root_ids: tuple[str, ...] = Field(max_length=16)
    shared_root_ids: tuple[str, ...] = Field(max_length=16)
    total_claim_count: int = Field(ge=0, le=384)
    guarded_control_claim_count: int = Field(ge=0, le=384)
    unique_root_recall: DevelopmentMeasurementRatio
    all_claim_unique_root_fraction: DevelopmentMeasurementRatio
    first_attempt_shard_completion: DevelopmentMeasurementRatio
    sum_estimated_total_cost_usd: Decimal = Field(ge=0)
    sum_reported_actual_cost_usd: Decimal = Field(ge=0)
    sum_accounted_cost_usd: Decimal = Field(ge=0)
    sum_uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    sum_active_reserved_usd: Decimal = Field(ge=0)
    sum_run_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    executed_ensemble_wall_clock_seconds: None = None


def _comparison_parts(
    scores: tuple[DevelopmentBenchmarkScore, ...],
) -> tuple[tuple[DevelopmentComparisonRow, ...], DevelopmentComparisonUnion]:
    """Count observed roots once while retaining all claims, attempts and missing scope."""

    if not 2 <= len(scores) <= MAX_DEVELOPMENT_COMPARISON_RUNS:
        raise ValueError("development comparison requires two through eight scores")
    first = scores[0]
    run_ids = tuple(score.observation.plan.run_id for score in scores)
    if run_ids != tuple(sorted(set(run_ids))):
        raise ValueError("development comparison run identities must be distinct and sorted")
    generations: set[str] = set()
    requests: set[str] = set()
    reservations: set[str] = set()
    for score in scores:
        if (
            score.binding.truth != first.binding.truth
            or score.binding.scorer_version != first.binding.scorer_version
            or score.observation.transport != first.observation.transport
        ):
            raise ValueError("development comparison source, truth, scorer or transport differs")
        for shard in score.observation.plan.shards:
            if shard.estimate.request_id in requests:
                raise ValueError("development comparison reuses a request identity")
            requests.add(shard.estimate.request_id)
        # A single already-validated run can retain a failed duplicate-generation attempt.
        # Reject reuse across claimed runs, not the failure evidence inside one run.
        run_generations = {
            item.generation_id
            for item in score.observation.observations
            if item.generation_id is not None
        }
        if run_generations & generations:
            raise ValueError("development comparison reuses an observed generation")
        generations.update(run_generations)
        for entry in score.observation.accounting:
            if entry.reservation_id in reservations:
                raise ValueError("development comparison reuses an accounting reservation")
            reservations.add(entry.reservation_id)
    matched = [set(score.summary.matched_root_ids) for score in scores]
    roots = set().union(*matched)
    shared = {root for root in roots if sum(root in items for items in matched) > 1}
    rows = tuple(
        DevelopmentComparisonRow(
            run_id=score.observation.plan.run_id,
            exact_model_id=score.observation.plan.shards[0].estimate.exact_model_id,
            provider_endpoint=score.observation.plan.shards[0].estimate.provider_endpoint,
            maximum_completion_tokens=score.observation.plan.shards[
                0
            ].estimate.maximum_completion_tokens,
            score_sha256=canonical_sha256(score.model_dump(mode="json")),
            summary=score.summary,
            roots_unique_to_run=tuple(sorted(matched[index] - shared)),
            roots_shared_with_other_runs=tuple(sorted(matched[index] & shared)),
        )
        for index, score in enumerate(scores)
    )
    incomplete = tuple(
        row.run_id for row in rows if row.summary.quality_scope != "COMPLETE_OBSERVATIONS"
    )
    total_claims = sum(row.summary.total_claim_count for row in rows)
    try:
        elapsed = math.fsum(row.summary.elapsed_seconds for row in rows)
    except OverflowError:
        raise ValueError("development comparison durations exceed their finite range") from None
    # Keep exact decimal totals even when individual bounded provider charges are large.
    with localcontext() as context:
        context.prec = 80
        union = DevelopmentComparisonUnion(
            quality_scope="INCOMPLETE_OBSERVATIONS" if incomplete else "COMPLETE_OBSERVATIONS",
            incomplete_run_ids=incomplete,
            expected_root_ids=first.summary.expected_root_ids,
            matched_root_ids=tuple(sorted(roots)),
            shared_root_ids=tuple(sorted(shared)),
            total_claim_count=total_claims,
            guarded_control_claim_count=sum(
                row.summary.guarded_control_claim_count for row in rows
            ),
            unique_root_recall=_ratio(
                len(roots), len(first.summary.expected_root_ids), complete=not incomplete
            ),
            all_claim_unique_root_fraction=_ratio(
                len(roots), total_claims, complete=not incomplete
            ),
            first_attempt_shard_completion=_ratio(
                sum(score.observation.completed_shard_count for score in scores),
                sum(len(score.observation.plan.shards) for score in scores),
                complete=True,
            ),
            sum_estimated_total_cost_usd=sum(
                (score.observation.plan.estimated_total_cost_usd for score in scores), Decimal(0)
            ),
            sum_reported_actual_cost_usd=sum(
                (row.summary.reported_actual_cost_usd for row in rows), Decimal(0)
            ),
            sum_accounted_cost_usd=sum(
                (row.summary.accounted_cost_usd for row in rows), Decimal(0)
            ),
            sum_uncertain_accounted_cost_usd=sum(
                (row.summary.uncertain_accounted_cost_usd for row in rows), Decimal(0)
            ),
            sum_active_reserved_usd=sum(
                (row.summary.active_reserved_usd for row in rows), Decimal(0)
            ),
            sum_run_elapsed_seconds=elapsed,
        )
    return rows, union


class DevelopmentBenchmarkComparison(_AuditArtifact):
    """Self-recomputing descriptive artifact; hashes do not authenticate private execution."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_benchmark_comparison"] = "development_benchmark_comparison"
    interpretation: Literal["DESCRIPTIVE_RECORDED_RUNS_NOT_A_CONTROLLED_EXPERIMENT"] = (
        "DESCRIPTIVE_RECORDED_RUNS_NOT_A_CONTROLLED_EXPERIMENT"
    )
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    request_and_budget_parity: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    superiority: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    scores: tuple[DevelopmentBenchmarkScore, ...] = Field(
        min_length=2, max_length=MAX_DEVELOPMENT_COMPARISON_RUNS
    )
    rows: tuple[DevelopmentComparisonRow, ...] = Field(
        min_length=2, max_length=MAX_DEVELOPMENT_COMPARISON_RUNS
    )
    union: DevelopmentComparisonUnion
    comparison_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def comparison_recomputes(self) -> Self:
        rows, union = _comparison_parts(self.scores)
        if self.rows != rows or self.union != union:
            raise ValueError("development comparison does not reproduce from its exact scores")
        if canonical_sha256(self.model_dump(mode="json", exclude={"comparison_sha256"})) != (
            self.comparison_sha256
        ):
            raise ValueError("development comparison digest differs from its exact inputs")
        return self


def compare_development_scores(
    scores: tuple[DevelopmentBenchmarkScore, ...],
) -> DevelopmentBenchmarkComparison:
    """Compare exact retained scores without inferring lineage, quality passes or executions."""

    if type(scores) is not tuple or not 2 <= len(scores) <= MAX_DEVELOPMENT_COMPARISON_RUNS:
        raise ValueError("development comparison requires two through eight exact scores")
    validated = []
    for score in scores:
        if type(score) is not DevelopmentBenchmarkScore:
            raise ValueError("development comparison requires exact typed scores")
        content = score.model_dump_json()
        if len(content.encode("utf-8")) > MAX_DEVELOPMENT_COMPARISON_SCORE_BYTES:
            raise ValueError("development comparison score exceeds its byte bound")
        validated.append(DevelopmentBenchmarkScore.model_validate_json(content, strict=True))
    ordered = tuple(sorted(validated, key=lambda score: score.observation.plan.run_id))
    rows, union = _comparison_parts(ordered)
    values = {
        **{
            name: field.default
            for name, field in DevelopmentBenchmarkComparison.model_fields.items()
            if not field.is_required()
        },
        "scores": [score.model_dump(mode="json") for score in ordered],
        "rows": [row.model_dump(mode="json") for row in rows],
        "union": union.model_dump(mode="json"),
    }
    return DevelopmentBenchmarkComparison(
        scores=ordered,
        rows=rows,
        union=union,
        comparison_sha256=canonical_sha256(values),
    )
