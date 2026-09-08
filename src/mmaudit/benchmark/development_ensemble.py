"""Same-truth development ensemble impact; agreement is not validated vulnerability evidence."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development import (
    DevelopmentBenchmarkBinding,
    DevelopmentBenchmarkScore,
    DevelopmentJudgmentImpactRow,
    DevelopmentJudgmentImpactSummary,
    DevelopmentMeasurementRatio,
    _ratio,
    _review_impact_parts,
    bind_development_benchmark,
    score_development_audit,
)
from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_ensemble import (
    DevelopmentEnsembleObservation,
    DevelopmentEnsembleOpinion,
)
from mmaudit.orchestration.manifest import canonical_sha256


def _parts(
    binding: DevelopmentBenchmarkBinding,
    observation: DevelopmentEnsembleObservation,
) -> tuple[
    DevelopmentBenchmarkScore | None,
    tuple[DevelopmentJudgmentImpactRow, ...],
    DevelopmentJudgmentImpactSummary | None,
]:
    if binding != bind_development_benchmark(plan=observation.plan.candidate, truth=binding.truth):
        raise ValueError("development ensemble truth is not bound to its original candidate plan")
    if observation.candidate is None:
        return None, (), None
    candidate_score = score_development_audit(binding=binding, observation=observation.candidate)
    decisions: dict[str, DevelopmentEnsembleOpinion] = {
        row.candidate_claim.claim_id: row.consensus
        for row in observation.claims
        if row.consensus != "UNREVIEWED"
    }
    rows, impact = _review_impact_parts(
        candidate_score,
        decisions,
        complete=observation.status != "INCOMPLETE",
        no_candidates=observation.status == "NO_CANDIDATES",
        combined_accounted_cost_usd=observation.total_accounted_cost_usd,
        active_reserved_usd=observation.active_reserved_usd,
        summed_stage_elapsed_seconds=observation.observed_stage_elapsed_seconds,
    )
    return candidate_score, rows, impact


class DevelopmentEnsembleScore(_AuditArtifact):
    """Frozen truth, original candidate score and every review opinion in one executed result."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_ensemble_score"] = "development_ensemble_score"
    interpretation: Literal["TWO_REVIEW_OPINIONS_AND_STRUCTURAL_MATCHES_NOT_VALIDATED_FINDINGS"] = (
        "TWO_REVIEW_OPINIONS_AND_STRUCTURAL_MATCHES_NOT_VALIDATED_FINDINGS"
    )
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    binding: DevelopmentBenchmarkBinding
    observation: DevelopmentEnsembleObservation
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_score: DevelopmentBenchmarkScore | None
    claims: tuple[DevelopmentJudgmentImpactRow, ...] = Field(max_length=48)
    summary: DevelopmentJudgmentImpactSummary | None
    review_opinion_observation_rate: DevelopmentMeasurementRatio
    stage_observation_rate: DevelopmentMeasurementRatio
    executed_ensemble_wall_clock_seconds: float = Field(ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def same_truth_impact_and_scope_are_exact(self) -> Self:
        if self.observation_sha256 != canonical_sha256(self.observation.model_dump(mode="json")):
            raise ValueError("development ensemble score observation digest differs")
        candidate, claims, summary = _parts(self.binding, self.observation)
        if (self.candidate_score, self.claims, self.summary) != (candidate, claims, summary):
            raise ValueError(
                "development ensemble score changes its original candidates or consensus"
            )
        if (
            self.review_opinion_observation_rate
            != _ratio(self.observation.completed_judgment_count, 2 * len(claims), complete=True)
            or self.stage_observation_rate
            != _ratio(self.observation.completed_stage_count, 3, complete=True)
            or self.executed_ensemble_wall_clock_seconds != self.observation.elapsed_seconds
        ):
            raise ValueError(
                "development ensemble score loses missing views, stages or measured time"
            )
        return self


def score_development_ensemble(
    *,
    binding: DevelopmentBenchmarkBinding,
    observation: DevelopmentEnsembleObservation,
) -> DevelopmentEnsembleScore:
    """Score actual joined stages, retaining failed scope and the candidate's original costs once."""

    if (
        type(binding) is not DevelopmentBenchmarkBinding
        or type(observation) is not DevelopmentEnsembleObservation
    ):
        raise ValueError("development ensemble scoring requires exact typed inputs")
    binding = DevelopmentBenchmarkBinding.model_validate_json(
        binding.model_dump_json(), strict=True
    )
    observation = DevelopmentEnsembleObservation.model_validate_json(
        observation.model_dump_json(), strict=True
    )
    candidate, claims, summary = _parts(binding, observation)
    return DevelopmentEnsembleScore(
        binding=binding,
        observation=observation,
        observation_sha256=canonical_sha256(observation.model_dump(mode="json")),
        candidate_score=candidate,
        claims=claims,
        summary=summary,
        review_opinion_observation_rate=_ratio(
            observation.completed_judgment_count, 2 * len(claims), complete=True
        ),
        stage_observation_rate=_ratio(observation.completed_stage_count, 3, complete=True),
        executed_ensemble_wall_clock_seconds=observation.elapsed_seconds,
    )
