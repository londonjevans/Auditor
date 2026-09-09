"""Flat continuation ancestry; original first-attempt observations and liabilities are immutable."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development_corpus import DevelopmentCorpusBenchmarkScore
from mmaudit.models.development_audit import _AuditArtifact, development_ledger_request_id
from mmaudit.models.development_corpus import (
    DevelopmentCorpusAccountingEntry,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusPlan,
    DevelopmentCorpusShardObservation,
    PreparedDevelopmentCorpus,
    prepare_development_corpus,
)
from mmaudit.models.development_judgment import _money_sum
from mmaudit.models.development_review import DevelopmentReviewMetadata, _DevelopmentModel
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256

MAX_DEVELOPMENT_CORPUS_CONTINUATIONS = 8
MAX_DEVELOPMENT_CORPUS_RESUME_BYTES = 64_000_000
_SHA = r"^[0-9a-f]{64}$"
type _StopReason = Literal["SHARD_INCOMPLETE", "LOCAL_FAILURE", "INTERRUPTED"]


class DevelopmentCorpusResumePlan(_AuditArtifact):
    """A new, explicitly selected stage, never a modification of an earlier one-attempt plan."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_resume_plan"] = "development_corpus_resume_plan"
    interpretation: Literal["EXPLICIT_CONTINUATION_ORIGINAL_FIRST_ATTEMPT_UNCHANGED"] = (
        "EXPLICIT_CONTINUATION_ORIGINAL_FIRST_ATTEMPT_UNCHANGED"
    )
    prior_history_sha256: str = Field(pattern=_SHA)
    original_candidate_sha256: str = Field(pattern=_SHA)
    continuation_index: int = Field(ge=1, le=MAX_DEVELOPMENT_CORPUS_CONTINUATIONS)
    candidate: DevelopmentCorpusPlan
    selected_shard_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    reused_observed_shard_ids: tuple[str, ...] = Field(max_length=64)
    estimated_continuation_cost_usd: Decimal = Field(gt=0, le=250)
    plan_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def exact_partition_and_selected_cost(self) -> Self:
        ids = tuple(shard.shard_id for shard in self.candidate.shards)
        selected, reused = set(self.selected_shard_ids), set(self.reused_observed_shard_ids)
        if (
            selected & reused
            or selected | reused != set(ids)
            or self.selected_shard_ids != tuple(s for s in ids if s in selected)
            or self.reused_observed_shard_ids != tuple(s for s in ids if s in reused)
        ):
            raise ValueError("continuation must partition every original source exactly once")
        if self.estimated_continuation_cost_usd != _money_sum(
            s.estimate.estimated_cost_per_attempt_usd
            for s in self.candidate.shards
            if s.shard_id in selected
        ):
            raise ValueError("continuation estimate differs from its exact selected requests")
        if canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"})) != (
            self.plan_sha256
        ):
            raise ValueError("continuation plan digest differs")
        return self


class DevelopmentCorpusResumeAttempt(_AuditArtifact):
    """Only this stage's selected prefix; it cannot impersonate the original candidate run."""

    artifact_kind: Literal["development_corpus_resume_attempt"] = (
        "development_corpus_resume_attempt"
    )
    plan: DevelopmentCorpusResumePlan
    transport: Literal["MOCK_HTTP", "HTTP_OBSERVATION"]
    status: Literal["OBSERVED_ALL_SELECTED_SHARDS", "INCOMPLETE"]
    stop_reason: _StopReason | None
    observations: tuple[DevelopmentCorpusShardObservation, ...] = Field(max_length=64)
    accounting: tuple[DevelopmentCorpusAccountingEntry, ...] = Field(max_length=64)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def selected_prefix_and_accounting_are_exact(self) -> Self:
        selected = self.plan.selected_shard_ids
        plans = {s.shard_id: s for s in self.plan.candidate.shards}
        if (
            tuple(s.shard_id for s in self.observations) != selected[: len(self.observations)]
            or tuple(a.shard_id for a in self.accounting) != selected[: len(self.accounting)]
            or len(self.accounting) > len(self.observations) + 1
            or len({a.reservation_id for a in self.accounting}) != len(self.accounting)
            or any(a.status is not CostEntryStatus.RECONCILED for a in self.accounting[:-1])
        ):
            raise ValueError(
                "continuation loses its selected prefix or continues past unsettled work"
            )
        entries = {a.shard_id: a for a in self.accounting}
        for retained in self.accounting:
            estimate = plans[retained.shard_id].estimate
            if (
                retained.ledger_request_id != development_ledger_request_id(estimate.request_id)
                or retained.reserved_usd != estimate.estimated_cost_per_attempt_usd
            ):
                raise ValueError("continuation accounting differs from its planned request")
        generations: set[str] = set()
        for observation in self.observations:
            account = entries.get(observation.shard_id)
            if (
                observation.manifest != self.plan.candidate.manifest
                or observation.run_id != self.plan.candidate.run_id
                or observation.estimate != plans[observation.shard_id].estimate
                or observation.transport != self.transport
                or account is None
                or account.status != observation.accounting_status
                or account.actual_cost_usd != observation.reported_cost_usd
                or account.accounted_cost_usd != observation.accounted_cost_usd
            ):
                raise ValueError("continuation response is not joined to its own plan and cost")
            if observation.status == "OBSERVED":
                assert observation.generation_id is not None
                if observation.generation_id in generations:
                    raise ValueError("continuation reuses an observed generation")
                generations.add(observation.generation_id)
            elif observation is not self.observations[-1] or len(self.accounting) != len(
                self.observations
            ):
                raise ValueError("continuation dispatch continued after an incomplete response")
        complete = len(self.observations) == len(selected) and all(
            s.status == "OBSERVED" for s in self.observations
        )
        try:
            child_elapsed = math.fsum(s.elapsed_seconds for s in self.observations)
        except OverflowError:
            raise ValueError("continuation child durations exceed their finite range") from None
        if (
            (self.status == "OBSERVED_ALL_SELECTED_SHARDS")
            != (complete and self.stop_reason is None)
            or (self.status == "INCOMPLETE" and self.stop_reason is None)
            or child_elapsed > self.elapsed_seconds + 1e-9
        ):
            raise ValueError("continuation completion or duration differs from its observations")
        return self


class DevelopmentCorpusResumeSummary(_DevelopmentModel):
    interpretation: Literal["CUMULATIVE_RESPONSES_NOT_VALIDATED_ANALYSIS"] = (
        "CUMULATIVE_RESPONSES_NOT_VALIDATED_ANALYSIS"
    )
    status: Literal["OBSERVED_ALL_SOURCES_ACROSS_RECORDED_ATTEMPTS", "INCOMPLETE"]
    original_first_attempt_status: Literal["OBSERVED_ALL_SHARDS", "INCOMPLETE"]
    original_first_attempt_completed_shard_count: int = Field(ge=0, le=64)
    continuation_count: int = Field(ge=0, le=MAX_DEVELOPMENT_CORPUS_CONTINUATIONS)
    cumulative_completed_shard_count: int = Field(ge=0, le=64)
    unobserved_shard_ids: tuple[str, ...] = Field(max_length=64)
    selected_primary_line_count: int = Field(gt=0, le=640_000)
    primary_lines_with_observed_responses: int = Field(ge=0, le=640_000)
    candidate_claim_count: int = Field(ge=0, le=1024)
    accounted_request_count: int = Field(ge=0, le=72)
    total_accounted_cost_usd: Decimal = Field(ge=0)
    reported_actual_cost_usd: Decimal = Field(ge=0)
    uncertain_accounted_cost_usd: Decimal = Field(ge=0)
    active_reserved_usd: Decimal = Field(ge=0)
    sum_run_elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    between_run_wait_seconds: None = None


def _summary(
    original: DevelopmentCorpusObservation,
    continuations: tuple[DevelopmentCorpusResumeAttempt, ...],
) -> DevelopmentCorpusResumeSummary:
    stages: tuple[DevelopmentCorpusObservation | DevelopmentCorpusResumeAttempt, ...] = (
        original,
        *continuations,
    )
    complete = {
        s.shard_id for stage in stages for s in stage.observations if s.status == "OBSERVED"
    }
    gaps = tuple(s.shard_id for s in original.plan.shards if s.shard_id not in complete)
    entries = tuple(a for stage in stages for a in stage.accounting)
    last = stages[-1]
    try:
        elapsed = math.fsum(stage.elapsed_seconds for stage in stages)
    except OverflowError:
        raise ValueError("continuation cumulative duration exceeds its finite range") from None
    return DevelopmentCorpusResumeSummary(
        status="OBSERVED_ALL_SOURCES_ACROSS_RECORDED_ATTEMPTS"
        if not gaps and last.stop_reason is None
        else "INCOMPLETE",
        original_first_attempt_status=original.status,
        original_first_attempt_completed_shard_count=original.completed_shard_count,
        continuation_count=len(continuations),
        cumulative_completed_shard_count=len(complete),
        unobserved_shard_ids=gaps,
        selected_primary_line_count=original.selected_primary_line_count,
        primary_lines_with_observed_responses=sum(
            source.line_count
            for source, shard in zip(
                original.plan.manifest.sources, original.plan.shards, strict=True
            )
            if shard.shard_id in complete
        ),
        candidate_claim_count=sum(
            len(s.response.findings)
            for stage in stages
            for s in stage.observations
            if s.response is not None
        ),
        accounted_request_count=len(entries),
        total_accounted_cost_usd=_money_sum(a.accounted_cost_usd for a in entries),
        reported_actual_cost_usd=_money_sum(a.actual_cost_usd or Decimal(0) for a in entries),
        uncertain_accounted_cost_usd=_money_sum(
            a.accounted_cost_usd for a in entries if a.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        ),
        active_reserved_usd=_money_sum(
            a.reserved_usd for a in entries if a.status is CostEntryStatus.RESERVED
        ),
        sum_run_elapsed_seconds=elapsed,
    )


def _same_configuration(original: DevelopmentCorpusPlan, candidate: DevelopmentCorpusPlan) -> None:
    if (
        candidate.manifest != original.manifest
        or candidate.routing != original.routing
        or candidate.maximum_run_seconds != original.maximum_run_seconds
        or candidate.estimated_total_cost_usd != original.estimated_total_cost_usd
        or any(
            old.estimate.model_dump(mode="json", exclude={"request_id"})
            != new.estimate.model_dump(mode="json", exclude={"request_id"})
            for old, new in zip(original.shards, candidate.shards, strict=True)
        )
    ):
        raise ValueError("continuation changes the original source, request, route or cost policy")


class DevelopmentCorpusResumeHistory(_AuditArtifact):
    """Flat, self-recomputing history; cumulative response coverage never rewrites the first run."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_resume_history"] = (
        "development_corpus_resume_history"
    )
    original: DevelopmentCorpusObservation
    material: DevelopmentCorpusMaterial
    original_score: DevelopmentCorpusBenchmarkScore | None = None
    continuations: tuple[DevelopmentCorpusResumeAttempt, ...] = Field(
        max_length=MAX_DEVELOPMENT_CORPUS_CONTINUATIONS
    )
    summary: DevelopmentCorpusResumeSummary
    history_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def original_ancestry_scope_and_totals_recompute(self) -> Self:
        if self.material.manifest != self.original.plan.manifest or (
            self.original_score is not None and self.original_score.observation != self.original
        ):
            raise ValueError("continuation history changes the original sources or score")
        run_ids = {self.original.plan.run_id}
        request_ids = {s.estimate.request_id for s in self.original.plan.shards}
        reservations = {a.reservation_id for a in self.original.accounting}
        generations = {
            s.generation_id for s in self.original.observations if s.generation_id is not None
        }
        for index, attempt in enumerate(self.continuations):
            prefix = self.continuations[:index]
            previous = _summary(self.original, prefix)
            plan = attempt.plan
            candidate = plan.candidate
            ids = tuple(s.shard_id for s in self.original.plan.shards)
            if (
                plan.continuation_index != index + 1
                or plan.prior_history_sha256
                != _history_digest(
                    self.original, self.material, self.original_score, prefix, previous
                )
                or plan.original_candidate_sha256
                != canonical_sha256(self.original.model_dump(mode="json"))
                or plan.selected_shard_ids != previous.unobserved_shard_ids
                or plan.reused_observed_shard_ids
                != tuple(s for s in ids if s not in previous.unobserved_shard_ids)
                or attempt.transport != self.original.transport
                or candidate.run_id in run_ids
            ):
                raise ValueError(
                    "continuation history loses ancestry or replays original observed work"
                )
            _same_configuration(self.original.plan, candidate)
            current_requests = {s.estimate.request_id for s in candidate.shards}
            current_reservations = {a.reservation_id for a in attempt.accounting}
            if current_requests & request_ids or current_reservations & reservations:
                raise ValueError("continuation history reuses a request or accounting reservation")
            for observation in attempt.observations:
                if observation.status == "OBSERVED" and observation.generation_id in generations:
                    raise ValueError(
                        "continuation history reuses an earlier generation as new evidence"
                    )
            run_ids.add(candidate.run_id)
            request_ids.update(current_requests)
            reservations.update(current_reservations)
            generations.update(
                s.generation_id for s in attempt.observations if s.generation_id is not None
            )
        expected = _summary(self.original, self.continuations)
        if self.summary != expected or self.history_sha256 != _history_digest(
            self.original, self.material, self.original_score, self.continuations, expected
        ):
            raise ValueError(
                "continuation history summary or digest differs from its original evidence"
            )
        return self


def _history_digest(
    original: DevelopmentCorpusObservation,
    material: DevelopmentCorpusMaterial,
    score: DevelopmentCorpusBenchmarkScore | None,
    continuations: tuple[DevelopmentCorpusResumeAttempt, ...],
    summary: DevelopmentCorpusResumeSummary,
) -> str:
    value = DevelopmentCorpusResumeHistory.model_construct(
        original=original,
        material=material,
        original_score=score,
        continuations=continuations,
        summary=summary,
        history_sha256="0" * 64,
    )
    return canonical_sha256(value.model_dump(mode="json", exclude={"history_sha256"}))


def freeze_development_corpus_resume_history(
    *,
    original: DevelopmentCorpusObservation,
    material: DevelopmentCorpusMaterial,
    original_score: DevelopmentCorpusBenchmarkScore | None = None,
    continuations: tuple[DevelopmentCorpusResumeAttempt, ...] = (),
) -> DevelopmentCorpusResumeHistory:
    """Retain all evidence in a flat record; no source is dispatched or first-attempt metric changed."""

    if (
        type(original) is not DevelopmentCorpusObservation
        or type(material) is not DevelopmentCorpusMaterial
        or (
            original_score is not None
            and type(original_score) is not DevelopmentCorpusBenchmarkScore
        )
        or type(continuations) is not tuple
        or len(continuations) > MAX_DEVELOPMENT_CORPUS_CONTINUATIONS
        or any(type(s) is not DevelopmentCorpusResumeAttempt for s in continuations)
    ):
        raise ValueError("continuation history requires exact bounded typed inputs")
    original = DevelopmentCorpusObservation.model_validate_json(
        original.model_dump_json(), strict=True
    )
    material = DevelopmentCorpusMaterial.model_validate_json(
        material.model_dump_json(), strict=True
    )
    if original_score is not None:
        original_score = DevelopmentCorpusBenchmarkScore.model_validate_json(
            original_score.model_dump_json(), strict=True
        )
    continuations = tuple(
        DevelopmentCorpusResumeAttempt.model_validate_json(s.model_dump_json(), strict=True)
        for s in continuations
    )
    summary = _summary(original, continuations)
    return DevelopmentCorpusResumeHistory(
        original=original,
        material=material,
        original_score=original_score,
        continuations=continuations,
        summary=summary,
        history_sha256=_history_digest(original, material, original_score, continuations, summary),
    )


@dataclass(frozen=True)
class PreparedDevelopmentCorpusResume:
    plan: DevelopmentCorpusResumePlan
    history: DevelopmentCorpusResumeHistory = field(repr=False)
    candidate: PreparedDevelopmentCorpus = field(repr=False)


def prepare_development_corpus_resume(
    *,
    history: DevelopmentCorpusResumeHistory,
    endpoint_snapshot: DevelopmentReviewMetadata,
    run_id: str,
) -> PreparedDevelopmentCorpusResume:
    """Select only missing responses under the exact original context and request configuration."""

    if type(history) is not DevelopmentCorpusResumeHistory:
        raise ValueError("continuation requires exact original history")
    content = history.model_dump_json()
    if len(content.encode("utf-8")) > MAX_DEVELOPMENT_CORPUS_RESUME_BYTES:
        raise ValueError("continuation history exceeds its byte bound")
    history = DevelopmentCorpusResumeHistory.model_validate_json(content, strict=True)
    if (
        not history.summary.unobserved_shard_ids
        or len(history.continuations) >= MAX_DEVELOPMENT_CORPUS_CONTINUATIONS
    ):
        raise ValueError("continuation has no unresolved source or exhausted its stage limit")
    run_ids = {
        history.original.plan.run_id,
        *(a.plan.candidate.run_id for a in history.continuations),
    }
    if run_id in run_ids:
        raise ValueError("continuation must use a new run identity")
    original = history.original.plan
    candidate = prepare_development_corpus(
        policy=original.policy,
        endpoint_snapshot=endpoint_snapshot,
        manifest=original.manifest,
        source_files=history.material.source_files,
        run_id=run_id,
        maximum_completion_tokens=original.shards[0].estimate.maximum_completion_tokens,
        maximum_run_seconds=original.maximum_run_seconds,
    )
    _same_configuration(original, candidate.plan)
    selected = history.summary.unobserved_shard_ids
    values: dict[str, Any] = dict(
        prior_history_sha256=history.history_sha256,
        original_candidate_sha256=canonical_sha256(history.original.model_dump(mode="json")),
        continuation_index=len(history.continuations) + 1,
        candidate=candidate.plan,
        selected_shard_ids=selected,
        reused_observed_shard_ids=tuple(
            s.shard_id for s in original.shards if s.shard_id not in selected
        ),
        estimated_continuation_cost_usd=_money_sum(
            s.estimate.estimated_cost_per_attempt_usd
            for s in candidate.plan.shards
            if s.shard_id in selected
        ),
    )
    provisional = DevelopmentCorpusResumePlan.model_construct(**values, plan_sha256="0" * 64)
    values["plan_sha256"] = canonical_sha256(
        provisional.model_dump(mode="json", exclude={"plan_sha256"})
    )
    return PreparedDevelopmentCorpusResume(
        DevelopmentCorpusResumePlan.model_validate(values), history, candidate
    )
