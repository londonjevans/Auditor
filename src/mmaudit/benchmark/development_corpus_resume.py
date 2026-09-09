"""Retained-label cumulative measurements; no new truth, merged first attempt or audit authority."""

from __future__ import annotations

from typing import Any, Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkSummary,
    DevelopmentCorpusClaimMeasurement,
    DevelopmentCorpusClaimSummary,
    DevelopmentCorpusMeasurementRatio,
    _measure_corpus_claims,
    _ratio,
)
from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus import DevelopmentCorpusShardObservation
from mmaudit.models.development_corpus_resume import (
    MAX_DEVELOPMENT_CORPUS_RESUME_BYTES,
    DevelopmentCorpusResumeHistory,
    DevelopmentCorpusResumeSummary,
)
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.orchestration.cost_ledger import CostEntryStatus
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import _decode_json
from mmaudit.repository.redaction import detect_secrets

MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES = 96_000_000
_SHA = r"^[0-9a-f]{64}$"
_REQUEST = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
_SHARD = r"^file-00(?:0[1-9]|[1-5][0-9]|6[0-4])$"


class DevelopmentCorpusResumeClaimMeasurement(DevelopmentCorpusClaimMeasurement):
    """Stable manifest claim identity plus the one recorded attempt that supplied its response."""

    stage_index: int = Field(ge=0, le=8)
    run_id: str = Field(pattern=_REQUEST)
    request_id: str = Field(pattern=_REQUEST)


class DevelopmentCorpusResumeRequestMeasurement(_DevelopmentModel):
    """One selected planned request; absence of a response or charge is never proof of no cost."""

    stage_index: int = Field(ge=0, le=8)
    run_id: str = Field(pattern=_REQUEST)
    shard_id: str = Field(pattern=_SHARD)
    request_id: str = Field(pattern=_REQUEST)
    observation_status: Literal["OBSERVED", "INCOMPLETE", "MISSING"]
    accounting_index: int | None = Field(ge=0, le=63)
    accounting_status: CostEntryStatus | None
    actual_cost_state: Literal["REPORTED", "RELEASED_NO_CHARGE", "UNKNOWN", "MISSING_ACCOUNTING"]
    elapsed_seconds: float | None = Field(ge=0, allow_inf_nan=False)


def _require_history(history: DevelopmentCorpusResumeHistory) -> DevelopmentCorpusResumeHistory:
    if type(history) is not DevelopmentCorpusResumeHistory:
        raise ValueError("cumulative scoring requires an exact continuation history")
    material = history.model_dump_json()
    if len(material.encode()) > MAX_DEVELOPMENT_CORPUS_RESUME_BYTES or detect_secrets(material):
        raise ValueError(
            "cumulative scoring history exceeds its bound or contains secret-like data"
        )
    history = DevelopmentCorpusResumeHistory.model_validate_json(material, strict=True)
    if history.original_score is None:
        raise ValueError(
            "cumulative scoring requires the retained original score and label binding"
        )
    return history


def _projection(history: DevelopmentCorpusResumeHistory) -> dict[str, Any]:
    original_score = history.original_score
    if original_score is None:
        raise ValueError(
            "cumulative scoring requires the retained original score and label binding"
        )
    requests: list[DevelopmentCorpusResumeRequestMeasurement] = []
    observed: dict[str, tuple[int, str, str, DevelopmentCorpusShardObservation]] = {}
    for stage_index in range(len(history.continuations) + 1):
        if stage_index == 0:
            plan = history.original.plan
            selected = tuple(s.shard_id for s in plan.shards)
            observations = history.original.observations
            accounting = history.original.accounting
        else:
            attempt = history.continuations[stage_index - 1]
            plan = attempt.plan.candidate
            selected = attempt.plan.selected_shard_ids
            observations = attempt.observations
            accounting = attempt.accounting
        by_shard = {s.shard_id: s for s in observations}
        accounts = {a.shard_id: (i, a) for i, a in enumerate(accounting)}
        for shard in plan.shards:
            if shard.shard_id not in selected:
                continue
            observation = by_shard.get(shard.shard_id)
            retained = accounts.get(shard.shard_id)
            account = retained[1] if retained is not None else None
            requests.append(
                DevelopmentCorpusResumeRequestMeasurement(
                    stage_index=stage_index,
                    run_id=plan.run_id,
                    shard_id=shard.shard_id,
                    request_id=shard.estimate.request_id,
                    observation_status=observation.status if observation is not None else "MISSING",
                    accounting_index=retained[0] if retained is not None else None,
                    accounting_status=account.status if account is not None else None,
                    actual_cost_state="MISSING_ACCOUNTING"
                    if account is None
                    else "RELEASED_NO_CHARGE"
                    if account.status is CostEntryStatus.RELEASED
                    else "REPORTED"
                    if account.actual_cost_usd is not None
                    else "UNKNOWN",
                    elapsed_seconds=observation.elapsed_seconds
                    if observation is not None
                    else None,
                )
            )
            if observation is not None and observation.status == "OBSERVED":
                if shard.shard_id in observed:
                    raise ValueError(
                        "cumulative scoring cannot select two responses for one source"
                    )
                observed[shard.shard_id] = (
                    stage_index,
                    plan.run_id,
                    shard.estimate.request_id,
                    observation,
                )
    complete = history.summary.status == "OBSERVED_ALL_SOURCES_ACROSS_RECORDED_ATTEMPTS"
    retained_observations = tuple(
        observed[s.shard_id][3] for s in history.original.plan.shards if s.shard_id in observed
    )
    measured, quality = _measure_corpus_claims(
        original_score.binding.truth, retained_observations, complete=complete
    )
    claims = tuple(
        DevelopmentCorpusResumeClaimMeasurement(
            **claim.model_dump(),
            stage_index=observed[claim.claim_id.split(":")[0]][0],
            run_id=observed[claim.claim_id.split(":")[0]][1],
            request_id=observed[claim.claim_id.split(":")[0]][2],
        )
        for claim in measured
    )
    return {
        "history": history,
        "history_sha256": history.history_sha256,
        "original_score_sha256": canonical_sha256(original_score.model_dump(mode="json")),
        "first_attempt_summary": original_score.summary,
        "cumulative_quality": quality,
        "cumulative_summary": history.summary,
        "cumulative_shard_completion": _ratio(
            len(observed), len(history.original.plan.shards), complete=True
        ),
        "claims": claims,
        "requests": tuple(requests),
        "missing_accounting_request_ids": tuple(
            r.request_id for r in requests if r.accounting_index is None
        ),
        "unknown_actual_cost_request_ids": tuple(
            r.request_id for r in requests if r.actual_cost_state == "UNKNOWN"
        ),
        "missing_shard_runtime_request_ids": tuple(
            r.request_id for r in requests if r.elapsed_seconds is None
        ),
    }


class DevelopmentCorpusResumeBenchmarkScore(_AuditArtifact):
    """Separate cumulative score; original evidence and every selected attempt remain embedded."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_resume_benchmark_score"] = (
        "development_corpus_resume_benchmark_score"
    )
    scorer_version: Literal["manifest-structural-controls-v1"] = "manifest-structural-controls-v1"
    interpretation: Literal["CUMULATIVE_STRUCTURAL_LABEL_MATCHES_NOT_VALIDATED_FINDINGS"] = (
        "CUMULATIVE_STRUCTURAL_LABEL_MATCHES_NOT_VALIDATED_FINDINGS"
    )
    root_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    runtime_scope: Literal["SUM_RECORDED_RUN_DURATIONS_NOT_END_TO_END"] = (
        "SUM_RECORDED_RUN_DURATIONS_NOT_END_TO_END"
    )
    actual_cost_scope: Literal["SUM_REPORTED_ACTUAL_NOT_TOTAL_BILL"] = (
        "SUM_REPORTED_ACTUAL_NOT_TOTAL_BILL"
    )
    accounting_reference: Literal["ZERO_BASED_INDEX_IN_RETAINED_STAGE_ACCOUNTING"] = (
        "ZERO_BASED_INDEX_IN_RETAINED_STAGE_ACCOUNTING"
    )
    history: DevelopmentCorpusResumeHistory = Field(
        json_schema_extra={
            "allOf": [
                {
                    "required": ["original_score"],
                    "properties": {"original_score": {"type": "object"}},
                }
            ]
        }
    )
    history_sha256: str = Field(pattern=_SHA)
    original_score_sha256: str = Field(pattern=_SHA)
    first_attempt_summary: DevelopmentCorpusBenchmarkSummary
    cumulative_quality: DevelopmentCorpusClaimSummary
    cumulative_summary: DevelopmentCorpusResumeSummary
    cumulative_shard_completion: DevelopmentCorpusMeasurementRatio
    claims: tuple[DevelopmentCorpusResumeClaimMeasurement, ...] = Field(max_length=1024)
    requests: tuple[DevelopmentCorpusResumeRequestMeasurement, ...] = Field(max_length=576)
    missing_accounting_request_ids: tuple[str, ...] = Field(max_length=576)
    unknown_actual_cost_request_ids: tuple[str, ...] = Field(max_length=72)
    missing_shard_runtime_request_ids: tuple[str, ...] = Field(max_length=576)
    score_sha256: str = Field(pattern=_SHA)

    @model_validator(mode="after")
    def exact_history_reproduces_all_cumulative_and_original_measurements(self) -> Self:
        material = self.history.model_dump_json()
        if (
            type(self.history) is not DevelopmentCorpusResumeHistory
            or len(material.encode()) > MAX_DEVELOPMENT_CORPUS_RESUME_BYTES
            or detect_secrets(material)
            or len(self.model_dump_json().encode()) > MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES
        ):
            raise ValueError(
                "cumulative score exceeds its evidence bounds or contains secret-like data"
            )
        if any(getattr(self, key) != value for key, value in _projection(self.history).items()):
            raise ValueError(
                "cumulative score does not reproduce from its retained original history"
            )
        if self.score_sha256 != canonical_sha256(
            self.model_dump(mode="json", exclude={"score_sha256"})
        ):
            raise ValueError("cumulative score digest differs")
        return self


def score_development_corpus_resume(
    *, history: DevelopmentCorpusResumeHistory
) -> DevelopmentCorpusResumeBenchmarkScore:
    """Use only the retained original labels; do not call a provider, repair evidence or settle costs."""

    history = _require_history(history)
    fields = _projection(history)
    draft = DevelopmentCorpusResumeBenchmarkScore.model_construct(**fields, score_sha256="0" * 64)
    digest = canonical_sha256(draft.model_dump(mode="json", exclude={"score_sha256"}))
    return DevelopmentCorpusResumeBenchmarkScore(**fields, score_sha256=digest)


def read_development_corpus_resume_score(content: bytes) -> DevelopmentCorpusResumeBenchmarkScore:
    """Read bounded unambiguous UTF-8 score JSON and recompute it; a digest alone grants no credit."""

    if (
        type(content) is not bytes
        or not 0 < len(content) <= MAX_DEVELOPMENT_CORPUS_RESUME_SCORE_BYTES
    ):
        raise ValueError("cumulative score JSON exceeds its byte bound")
    content.decode("utf-8")
    try:
        value = _decode_json(content)
    except (RecursionError, OverflowError):
        raise ValueError("cumulative score JSON exceeds its structural bound") from None
    if type(value) is not dict:
        raise ValueError("cumulative score must be an unambiguous JSON object")
    return DevelopmentCorpusResumeBenchmarkScore.model_validate_json(content, strict=True)
