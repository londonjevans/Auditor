"""Descriptive dual-review measurements beside the unchanged original manifest candidate score."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkBinding,
    DevelopmentCorpusBenchmarkScore,
    DevelopmentCorpusClaimMeasurement,
    DevelopmentCorpusMeasurementRatio,
    _ratio,
    bind_development_corpus_benchmark,
    score_development_corpus,
)
from mmaudit.models.development_audit import _AuditArtifact
from mmaudit.models.development_corpus_ensemble import (
    MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES,
    DevelopmentCorpusEnsembleObservation,
    DevelopmentCorpusRefutationScope,
)
from mmaudit.models.development_ensemble import DevelopmentEnsembleOpinion
from mmaudit.models.development_review import _DevelopmentModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.redaction import detect_secrets


class DevelopmentCorpusEnsembleMeasuredClaim(_DevelopmentModel):
    candidate_measurement: DevelopmentCorpusClaimMeasurement
    opinions: tuple[DevelopmentEnsembleOpinion | None, ...] = Field(min_length=2, max_length=2)
    consensus: Literal["SUPPORTED", "REFUTED", "INCONCLUSIVE", "UNREVIEWED"]
    refutation_scope: DevelopmentCorpusRefutationScope


class DevelopmentCorpusEnsembleSummary(_DevelopmentModel):
    """Available-claim observation counts do not measure unknown source coverage or judge accuracy."""

    overall_observation_scope: Literal[
        "COMPLETE_OBSERVATIONS", "INCOMPLETE_OBSERVATIONS", "NO_CANDIDATES"
    ]
    available_original_claim_count: int = Field(ge=0, le=1024)
    expected_available_claim_opinion_count: int = Field(ge=0, le=2048)
    observed_opinion_count: int = Field(ge=0, le=2048)
    missing_opinion_count: int = Field(ge=0, le=2048)
    claims_reviewed_by_both_count: int = Field(ge=0, le=1024)
    disagreement_count: int = Field(ge=0, le=1024)
    inconclusive_opinion_count: int = Field(ge=0, le=2048)
    unanimous_support_count: int = Field(ge=0, le=1024)
    unanimous_refutation_count: int = Field(ge=0, le=1024)
    refuted_by_one_count: int = Field(ge=0, le=1024)
    refuted_by_both_count: int = Field(ge=0, le=1024)
    matched_root_claims_refuted_by_one_count: int = Field(ge=0, le=1024)
    matched_root_claims_refuted_by_both_count: int = Field(ge=0, le=1024)
    unobserved_candidate_shard_count: int = Field(ge=0, le=64)
    completed_stage_count: int = Field(ge=0, le=3)
    available_claim_opinion_observation_fraction: DevelopmentCorpusMeasurementRatio


def _measure(
    binding: DevelopmentCorpusBenchmarkBinding,
    observation: DevelopmentCorpusEnsembleObservation,
) -> tuple[
    DevelopmentCorpusBenchmarkScore | None,
    tuple[DevelopmentCorpusEnsembleMeasuredClaim, ...],
    DevelopmentCorpusEnsembleSummary,
]:
    if binding != bind_development_corpus_benchmark(
        plan=observation.plan.candidate,
        truth_content=binding.truth_file_content.encode("utf-8"),
        expected_truth_sha256=binding.truth_file_sha256,
    ):
        raise ValueError("manifest ensemble measurement changes pre-dispatch candidate labels")
    candidate_score = (
        score_development_corpus(binding=binding, observation=observation.candidate)
        if observation.candidate is not None
        else None
    )
    originals = () if candidate_score is None else candidate_score.claims
    if len(originals) != len(observation.claims) or any(
        m.claim_id != r.candidate_claim.claim_id
        for m, r in zip(originals, observation.claims, strict=True)
    ):
        raise ValueError("manifest ensemble measurement loses original candidate claims")
    claims = tuple(
        DevelopmentCorpusEnsembleMeasuredClaim(
            candidate_measurement=measured,
            opinions=row.opinions,
            consensus=row.consensus,
            refutation_scope=row.refutation_scope,
        )
        for measured, row in zip(originals, observation.claims, strict=True)
    )
    opinions = sum(op is not None for r in claims for op in r.opinions)
    expected = 2 * len(claims)
    summary = DevelopmentCorpusEnsembleSummary(
        overall_observation_scope="COMPLETE_OBSERVATIONS"
        if observation.status == "OBSERVED_ALL_STAGES"
        else "NO_CANDIDATES"
        if observation.status == "NO_CANDIDATES"
        else "INCOMPLETE_OBSERVATIONS",
        available_original_claim_count=len(claims),
        expected_available_claim_opinion_count=expected,
        observed_opinion_count=opinions,
        missing_opinion_count=expected - opinions,
        claims_reviewed_by_both_count=sum(None not in r.opinions for r in claims),
        disagreement_count=sum(
            None not in r.opinions and r.opinions[0] != r.opinions[1] for r in claims
        ),
        inconclusive_opinion_count=sum(op == "INCONCLUSIVE" for r in claims for op in r.opinions),
        unanimous_support_count=sum(r.consensus == "SUPPORTED" for r in claims),
        unanimous_refutation_count=sum(r.consensus == "REFUTED" for r in claims),
        refuted_by_one_count=sum(r.refutation_scope == "REFUTED_BY_ONE" for r in claims),
        refuted_by_both_count=sum(r.refutation_scope == "REFUTED_BY_BOTH" for r in claims),
        matched_root_claims_refuted_by_one_count=sum(
            r.candidate_measurement.disposition == "MATCHED_ROOT"
            and r.refutation_scope == "REFUTED_BY_ONE"
            for r in claims
        ),
        matched_root_claims_refuted_by_both_count=sum(
            r.candidate_measurement.disposition == "MATCHED_ROOT"
            and r.refutation_scope == "REFUTED_BY_BOTH"
            for r in claims
        ),
        unobserved_candidate_shard_count=len(observation.unobserved_candidate_shard_ids),
        completed_stage_count=observation.completed_stage_count,
        available_claim_opinion_observation_fraction=_ratio(opinions, expected, complete=True),
    )
    return candidate_score, claims, summary


class DevelopmentCorpusEnsembleScore(_AuditArtifact):
    """Keep the original candidate baseline and all opinions; never rescore a filtered candidate."""

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["development_corpus_ensemble_score"] = (
        "development_corpus_ensemble_score"
    )
    interpretation: Literal["ORIGINAL_STRUCTURAL_SCORE_AND_UNVALIDATED_REVIEW_OPINIONS"] = (
        "ORIGINAL_STRUCTURAL_SCORE_AND_UNVALIDATED_REVIEW_OPINIONS"
    )
    lineage_independence: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    binding: DevelopmentCorpusBenchmarkBinding
    observation: DevelopmentCorpusEnsembleObservation
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_score: DevelopmentCorpusBenchmarkScore | None
    claims: tuple[DevelopmentCorpusEnsembleMeasuredClaim, ...] = Field(max_length=1024)
    summary: DevelopmentCorpusEnsembleSummary

    @model_validator(mode="after")
    def recompute_from_every_original_claim_and_opinion(self) -> Self:
        material = self.observation.model_dump_json()
        if len(material.encode()) > MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES or detect_secrets(
            material
        ):
            raise ValueError("manifest ensemble observation exceeds its bounded nonsecret scope")
        if self.observation_sha256 != canonical_sha256(self.observation.model_dump(mode="json")):
            raise ValueError("manifest ensemble measurement observation digest differs")
        if (self.candidate_score, self.claims, self.summary) != _measure(
            self.binding, self.observation
        ):
            raise ValueError(
                "manifest ensemble measurements differ from retained original evidence"
            )
        return self


def score_development_corpus_ensemble(
    *, binding: DevelopmentCorpusBenchmarkBinding, observation: DevelopmentCorpusEnsembleObservation
) -> DevelopmentCorpusEnsembleScore:
    """Preserve strict original scoring and describe two opinions without a new request or pass."""

    if (
        type(binding) is not DevelopmentCorpusBenchmarkBinding
        or type(observation) is not DevelopmentCorpusEnsembleObservation
    ):
        raise ValueError("manifest ensemble measurement requires exact original input types")
    material = observation.model_dump_json()
    if len(material.encode()) > MAX_DEVELOPMENT_CORPUS_ENSEMBLE_BYTES or detect_secrets(material):
        raise ValueError("manifest ensemble measurement exceeds its bounded nonsecret scope")
    observation = DevelopmentCorpusEnsembleObservation.model_validate_json(material, strict=True)
    binding = DevelopmentCorpusBenchmarkBinding.model_validate_json(
        binding.model_dump_json(), strict=True
    )
    candidate_score, claims, summary = _measure(binding, observation)
    return DevelopmentCorpusEnsembleScore(
        binding=binding,
        observation=observation,
        observation_sha256=canonical_sha256(observation.model_dump(mode="json")),
        candidate_score=candidate_score,
        claims=claims,
        summary=summary,
    )
