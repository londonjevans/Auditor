"""Non-dispositive, evidence-bound model benchmark calibration artifacts.

Calibration records observed benchmark distributions. It deliberately has no
qualification disposition and cannot authorize a model or review role.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import threading
import weakref
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Never, SupportsIndex

from pydantic import Field, TypeAdapter, field_validator, model_validator

from mmaudit.benchmark.model_portfolio import (
    ModelBenchmarkPortfolio,
    TrustedCandidateBenchmarkCampaignVerification,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkDimension,
    ModelBenchmarkDimensionScore,
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    verify_model_benchmark_report_structure,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkDiagnostic,
    CandidateBenchmarkRunState,
)
from mmaudit.models.discovery import OpenRouterModelDiscoveryRunManifest
from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.models.qualification import (
    MIN_CALIBRATION_INCLUDED_CANDIDATES,
    MIN_CALIBRATION_INCLUDED_ROOT_LINEAGES,
    CandidateModel,
    CandidateRegistry,
    LineageReviewStatus,
    QualificationDimensionThreshold,
    QualificationPolicy,
    RoleQualificationPolicy,
    seal_qualification_policy,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    StrictModel,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_CANDIDATES = 128
_MAX_ARTIFACT_BYTES = 10_000_000
_PRIVATE_FILE_MODE = 0o600
_JSON_ADAPTER = TypeAdapter(Any)


class TrustedModelCalibrationVerification:
    """Opaque proof that calibration retained one fresh campaign's REAL provenance."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> TrustedModelCalibrationVerification:
        del cls
        raise TypeError("trusted calibration verification cannot be constructed directly")

    def __init__(
        self,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        del self, _args, _kwargs

    def require_for(self, artifact: ModelCalibrationArtifact) -> None:
        """Reject reuse after any calibration evidence changes."""

        _require_trusted_calibration_capability(self, artifact.artifact_sha256)

    def __copy__(self) -> None:
        raise TypeError("trusted calibration verification cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("trusted calibration verification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted calibration verification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted calibration verification cannot be serialized")


def _build_calibration_runtime_authority() -> tuple[
    Callable[..., TrustedModelCalibrationVerification],
    Callable[[TrustedModelCalibrationVerification, str], None],
]:
    registry: dict[
        int,
        tuple[weakref.ReferenceType[TrustedModelCalibrationVerification], str],
    ] = {}
    lock = threading.RLock()

    def issue(
        *,
        artifact: ModelCalibrationArtifact,
        candidate_registry: CandidateRegistry,
        discovery_run_manifest: OpenRouterModelDiscoveryRunManifest,
        benchmark_suite: ModelBenchmarkSuite,
        benchmark_portfolio: ModelBenchmarkPortfolio,
        benchmark_reports: tuple[ModelBenchmarkReport, ...],
        benchmark_policy_sha256: str,
        effective_config_sha256: str,
        trusted_campaign_verification: TrustedCandidateBenchmarkCampaignVerification,
    ) -> TrustedModelCalibrationVerification:
        if type(artifact) is not ModelCalibrationArtifact:
            raise ValueError("trusted calibration issuance requires a typed artifact")
        validated = ModelCalibrationArtifact.model_validate(artifact.model_dump(mode="json"))
        rebuilt = build_model_calibration_artifact(
            created_at=validated.created_at,
            candidate_registry=candidate_registry,
            discovery_run_manifest=discovery_run_manifest,
            benchmark_suite=benchmark_suite,
            benchmark_portfolio=benchmark_portfolio,
            benchmark_reports=benchmark_reports,
            benchmark_policy_sha256=benchmark_policy_sha256,
            effective_config_sha256=effective_config_sha256,
            trusted_campaign_verification=trusted_campaign_verification,
        )
        if rebuilt != validated:
            raise ValueError("calibration artifact differs from live campaign evidence")
        capability = object.__new__(TrustedModelCalibrationVerification)
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[TrustedModelCalibrationVerification],
        ) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, validated.artifact_sha256)
        return capability

    def require(
        capability: TrustedModelCalibrationVerification,
        artifact_sha256: str,
    ) -> None:
        with lock:
            registered = registry.get(id(capability))
            if (
                registered is None
                or registered[0]() is not capability
                or registered[1] != artifact_sha256
            ):
                raise ValueError("trusted calibration verification is absent or mismatched")

    return issue, require


(
    issue_trusted_model_calibration_verification,
    _require_trusted_calibration_capability,
) = _build_calibration_runtime_authority()


class CalibrationExclusionReason(StrEnum):
    """Why one exact candidate contributes no calibration distribution values."""

    CANDIDATE_RUN_NOT_COMPLETE = "candidate_run_not_complete"
    REPORT_CASES_INCOMPLETE = "report_cases_incomplete"
    REPORT_NOT_REAL = "report_not_real"
    ROOT_LINEAGE_NOT_APPROVED = "root_lineage_not_approved"
    ROOT_LINEAGE_REVIEW_POSTDATES_CAMPAIGN = "root_lineage_review_postdates_campaign"


class ModelCalibrationCandidateObservation(StrictModel):
    """One exact candidate retained whether or not its report is creditable."""

    exact_model_id: str = Field(min_length=3, max_length=300)
    root_lineage: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    report_sha256: str = Field(pattern=_SHA256_PATTERN)
    report_execution_evidence: ExecutionEvidenceKind
    diagnostic: CandidateBenchmarkDiagnostic
    included_in_distribution: bool
    exclusion_reasons: tuple[CalibrationExclusionReason, ...] = ()
    dimensions: tuple[ModelBenchmarkDimensionScore, ...] = Field(
        default=(),
        max_length=len(ModelBenchmarkDimension),
    )
    overall_score: float | None = Field(default=None, ge=0, le=1)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("exclusion_reasons")
    @classmethod
    def exclusion_reasons_are_sorted_unique(
        cls,
        value: tuple[CalibrationExclusionReason, ...],
    ) -> tuple[CalibrationExclusionReason, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("calibration exclusion reasons must be unique and sorted")
        return value

    @model_validator(mode="after")
    def evidence_and_distribution_credit_are_consistent(
        self,
    ) -> ModelCalibrationCandidateObservation:
        if (
            self.diagnostic.exact_model_id != self.exact_model_id
            or self.diagnostic.report_sha256 != self.report_sha256
            or self.diagnostic.execution_evidence is not self.report_execution_evidence
        ):
            raise ValueError("calibration candidate diagnostic differs from its report")
        if self.included_in_distribution:
            names = tuple(item.dimension.value for item in self.dimensions)
            if (
                self.report_execution_evidence is not ExecutionEvidenceKind.REAL
                or self.diagnostic.state is not CandidateBenchmarkRunState.COMPLETE
                or self.root_lineage is None
                or self.exclusion_reasons
                or names != tuple(sorted(item.value for item in ModelBenchmarkDimension))
                or self.overall_score is None
            ):
                raise ValueError("credited calibration candidate lacks exact REAL completion")
            expected_overall = round(
                sum(item.score for item in self.dimensions) / len(self.dimensions),
                6,
            )
            if self.overall_score != expected_overall:
                raise ValueError("calibration candidate overall score is inconsistent")
        elif not self.exclusion_reasons or self.dimensions or self.overall_score is not None:
            raise ValueError("excluded calibration candidate must retain only exclusion evidence")
        return self


class ModelCalibrationDimensionObservation(StrictModel):
    """One exact candidate's deterministic score for one dimension."""

    exact_model_id: str = Field(min_length=3, max_length=300)
    root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    passed: int = Field(ge=0)
    evaluated: int = Field(ge=1)
    score: float = Field(ge=0, le=1)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def arithmetic_is_consistent(self) -> ModelCalibrationDimensionObservation:
        if self.passed > self.evaluated or self.score != round(
            self.passed / self.evaluated,
            6,
        ):
            raise ValueError("calibration dimension observation arithmetic is inconsistent")
        return self


class ModelCalibrationScoreFrequency(StrictModel):
    """Exact empirical frequency, without an inferred quality threshold."""

    score: float = Field(ge=0, le=1)
    candidate_count: int = Field(ge=1, le=_MAX_CANDIDATES)


class ModelCalibrationDimensionDistribution(StrictModel):
    """Observed per-model scores for one dimension; no pass threshold is implied."""

    dimension: ModelBenchmarkDimension
    candidate_count: int = Field(ge=1, le=_MAX_CANDIDATES)
    included_candidate_count: int = Field(ge=0, le=_MAX_CANDIDATES)
    excluded_candidate_count: int = Field(ge=0, le=_MAX_CANDIDATES)
    observations: tuple[ModelCalibrationDimensionObservation, ...] = Field(
        default=(),
        max_length=_MAX_CANDIDATES,
    )
    score_frequencies: tuple[ModelCalibrationScoreFrequency, ...] = Field(
        default=(),
        max_length=_MAX_CANDIDATES,
    )
    mean_score: float | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def counts_distribution_and_mean_are_consistent(
        self,
    ) -> ModelCalibrationDimensionDistribution:
        if self.included_candidate_count + self.excluded_candidate_count != self.candidate_count:
            raise ValueError("calibration dimension candidate counts are inconsistent")
        model_ids = tuple(item.exact_model_id for item in self.observations)
        if (
            model_ids != tuple(sorted(set(model_ids)))
            or len(self.observations) != self.included_candidate_count
        ):
            raise ValueError("calibration dimension observations are not an exact model set")
        frequencies: dict[float, int] = {}
        for observation in self.observations:
            frequencies[observation.score] = frequencies.get(observation.score, 0) + 1
        expected_frequencies = tuple(
            ModelCalibrationScoreFrequency(score=score, candidate_count=count)
            for score, count in sorted(frequencies.items())
        )
        if self.score_frequencies != expected_frequencies:
            raise ValueError("calibration dimension score frequencies are inconsistent")
        expected_mean = (
            None
            if not self.observations
            else round(
                sum(item.score for item in self.observations) / len(self.observations),
                6,
            )
        )
        if self.mean_score != expected_mean:
            raise ValueError("calibration dimension mean score is inconsistent")
        return self


class ModelCalibrationArtifact(StrictModel):
    """Self-hashed calibration evidence that intentionally makes no disposition."""

    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_corpus_version: str = Field(min_length=1, max_length=100)
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_version: str = Field(min_length=1, max_length=100)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_portfolio_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    campaign_journal_sha256: str = Field(pattern=_SHA256_PATTERN)
    included_root_lineage_count: int = Field(ge=0, le=_MAX_CANDIDATES)
    candidates: tuple[ModelCalibrationCandidateObservation, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    distributions: tuple[ModelCalibrationDimensionDistribution, ...] = Field(
        min_length=len(ModelBenchmarkDimension),
        max_length=len(ModelBenchmarkDimension),
    )
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("created_at")
    @classmethod
    def created_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
            raise ValueError("calibration creation time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def exact_sets_distributions_and_hash_are_consistent(
        self,
    ) -> ModelCalibrationArtifact:
        candidate_ids = tuple(item.exact_model_id for item in self.candidates)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("calibration candidates must be unique and sorted")
        if self.candidate_set_sha256 != canonical_sha256(list(candidate_ids)):
            raise ValueError("calibration candidate-set hash is inconsistent")
        dimension_names = tuple(item.dimension.value for item in self.distributions)
        if dimension_names != tuple(sorted(item.value for item in ModelBenchmarkDimension)):
            raise ValueError("calibration distributions must cover every dimension exactly once")
        included = tuple(item for item in self.candidates if item.included_in_distribution)
        included_ids = tuple(item.exact_model_id for item in included)
        included_lineages = {item.root_lineage for item in included}
        if None in included_lineages or self.included_root_lineage_count != len(included_lineages):
            raise ValueError("calibration included-lineage count is inconsistent")
        for distribution in self.distributions:
            if (
                distribution.candidate_count != len(self.candidates)
                or distribution.included_candidate_count != len(included)
                or distribution.excluded_candidate_count != len(self.candidates) - len(included)
                or tuple(item.exact_model_id for item in distribution.observations) != included_ids
            ):
                raise ValueError("calibration distribution candidate projection is inconsistent")
            expected = tuple(
                ModelCalibrationDimensionObservation(
                    exact_model_id=candidate.exact_model_id,
                    root_lineage=_required_calibration_root_lineage(candidate),
                    passed=next(
                        item
                        for item in candidate.dimensions
                        if item.dimension is distribution.dimension
                    ).passed,
                    evaluated=next(
                        item
                        for item in candidate.dimensions
                        if item.dimension is distribution.dimension
                    ).evaluated,
                    score=next(
                        item
                        for item in candidate.dimensions
                        if item.dimension is distribution.dimension
                    ).score,
                )
                for candidate in included
            )
            if distribution.observations != expected:
                raise ValueError("calibration distribution differs from candidate evidence")
        expected_hash = canonical_sha256(self.model_dump(mode="json", exclude={"artifact_sha256"}))
        if self.artifact_sha256 != expected_hash:
            raise ValueError("model calibration artifact self-hash is inconsistent")
        return self


def build_model_calibration_artifact(
    *,
    created_at: datetime,
    candidate_registry: CandidateRegistry,
    discovery_run_manifest: OpenRouterModelDiscoveryRunManifest,
    benchmark_suite: ModelBenchmarkSuite,
    benchmark_portfolio: ModelBenchmarkPortfolio,
    benchmark_reports: tuple[ModelBenchmarkReport, ...],
    benchmark_policy_sha256: str,
    effective_config_sha256: str,
    trusted_campaign_verification: TrustedCandidateBenchmarkCampaignVerification,
) -> ModelCalibrationArtifact:
    """Build observed distributions from one live, exact candidate campaign."""

    if re.fullmatch(_SHA256_PATTERN, benchmark_policy_sha256) is None:
        raise ValueError("calibration benchmark-policy hash is malformed")
    if re.fullmatch(_SHA256_PATTERN, effective_config_sha256) is None:
        raise ValueError("calibration effective-config hash is malformed")
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        discovery_run_manifest.model_dump(mode="json")
    )
    suite = ModelBenchmarkSuite.model_validate(benchmark_suite.model_dump(mode="json"))
    portfolio = ModelBenchmarkPortfolio.model_validate(benchmark_portfolio.model_dump(mode="json"))
    reports = tuple(
        ModelBenchmarkReport.model_validate(report.model_dump(mode="json"))
        for report in benchmark_reports
    )
    campaign_anchor = (
        registry.created_at if portfolio.ended_at is None else portfolio.ended_at
    ).replace(microsecond=0)
    if created_at < campaign_anchor:
        raise ValueError("calibration creation time must follow campaign completion")
    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    _validate_discovery_binding(
        registry=registry,
        manifest=manifest,
        candidate_ids=candidate_ids,
    )
    _validate_portfolio_and_report_bindings(
        registry=registry,
        manifest=manifest,
        suite=suite,
        portfolio=portfolio,
        reports=reports,
        benchmark_policy_sha256=benchmark_policy_sha256,
    )
    if type(trusted_campaign_verification) is not TrustedCandidateBenchmarkCampaignVerification:
        raise ValueError("calibration requires live trusted campaign verification")
    try:
        trusted_campaign_verification.require_for(
            portfolio_sha256=portfolio.portfolio_sha256,
            reports=reports,
            policy_sha256=benchmark_policy_sha256,
            effective_config_sha256=effective_config_sha256,
        )
    except ValueError as exc:
        raise ValueError("trusted campaign verification does not bind calibration inputs") from exc

    candidates: list[ModelCalibrationCandidateObservation] = []
    for candidate, report, diagnostic in zip(
        registry.candidates,
        reports,
        portfolio.diagnostics,
        strict=True,
    ):
        result = report.results[0]
        failed_cases = sum(case.error_kind is not None for case in result.cases)
        if (
            result.target.model_id != candidate.exact_model_id
            or result.target.root_lineage != candidate.root_lineage
            or diagnostic.approved_provider_endpoint != candidate.approved_provider_endpoint
            or diagnostic.endpoint_snapshot_sha256 != candidate.endpoint_snapshot_sha256
            or diagnostic.corpus_cases != len(result.cases)
            or diagnostic.failed_cases != failed_cases
            or diagnostic.successful_cases != len(result.cases) - failed_cases
        ):
            raise ValueError("calibration report route differs from its exact candidate")
        complete_cases = _report_cases_are_exact_real_complete(
            report=report,
            candidate=candidate,
        )
        reasons: set[CalibrationExclusionReason] = set()
        if diagnostic.state is not CandidateBenchmarkRunState.COMPLETE:
            reasons.add(CalibrationExclusionReason.CANDIDATE_RUN_NOT_COMPLETE)
        if (
            report.execution_evidence is not ExecutionEvidenceKind.REAL
            or result.execution_evidence is not ExecutionEvidenceKind.REAL
        ):
            reasons.add(CalibrationExclusionReason.REPORT_NOT_REAL)
        if not complete_cases:
            reasons.add(CalibrationExclusionReason.REPORT_CASES_INCOMPLETE)
        if (
            candidate.root_lineage is None
            or candidate.lineage_review.status is not LineageReviewStatus.APPROVED
        ):
            reasons.add(CalibrationExclusionReason.ROOT_LINEAGE_NOT_APPROVED)
        if (
            candidate.lineage_review.reviewed_at is not None
            and benchmark_portfolio.started_at is not None
            and candidate.lineage_review.reviewed_at > benchmark_portfolio.started_at
        ):
            reasons.add(CalibrationExclusionReason.ROOT_LINEAGE_REVIEW_POSTDATES_CAMPAIGN)
        is_included = not reasons
        candidates.append(
            ModelCalibrationCandidateObservation(
                exact_model_id=candidate.exact_model_id,
                root_lineage=candidate.root_lineage,
                report_sha256=report.report_sha256,
                report_execution_evidence=report.execution_evidence,
                diagnostic=diagnostic,
                included_in_distribution=is_included,
                exclusion_reasons=tuple(sorted(reasons, key=lambda item: item.value)),
                dimensions=tuple(result.dimensions) if is_included else (),
                overall_score=result.overall_score if is_included else None,
            )
        )

    ordered_candidates = tuple(candidates)
    included_candidates = tuple(
        item for item in ordered_candidates if item.included_in_distribution
    )
    distributions: list[ModelCalibrationDimensionDistribution] = []
    for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value):
        observations = tuple(
            _calibration_dimension_observation(candidate, dimension)
            for candidate in included_candidates
        )
        frequencies: dict[float, int] = {}
        for observation in observations:
            frequencies[observation.score] = frequencies.get(observation.score, 0) + 1
        distributions.append(
            ModelCalibrationDimensionDistribution(
                dimension=dimension,
                candidate_count=len(ordered_candidates),
                included_candidate_count=len(included_candidates),
                excluded_candidate_count=len(ordered_candidates) - len(included_candidates),
                observations=observations,
                score_frequencies=tuple(
                    ModelCalibrationScoreFrequency(score=score, candidate_count=count)
                    for score, count in sorted(frequencies.items())
                ),
                mean_score=(
                    None
                    if not observations
                    else round(
                        sum(item.score for item in observations) / len(observations),
                        6,
                    )
                ),
            )
        )
    if portfolio.campaign_journal_sha256 is None:
        raise ValueError("calibration requires a journal-bound benchmark portfolio")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "candidate_registry_sha256": registry.registry_sha256,
        "discovery_manifest_sha256": manifest.manifest_sha256,
        "candidate_set_sha256": canonical_sha256(list(candidate_ids)),
        "benchmark_corpus_version": suite.corpus.schema_version,
        "benchmark_corpus_sha256": suite.corpus_sha256,
        "benchmark_ground_truth_version": suite.ground_truth.schema_version,
        "benchmark_ground_truth_sha256": suite.ground_truth_sha256,
        "benchmark_portfolio_sha256": portfolio.portfolio_sha256,
        "benchmark_policy_sha256": benchmark_policy_sha256,
        "effective_config_sha256": effective_config_sha256,
        "campaign_journal_sha256": portfolio.campaign_journal_sha256,
        "included_root_lineage_count": len({item.root_lineage for item in included_candidates}),
        "candidates": [item.model_dump(mode="json") for item in ordered_candidates],
        "distributions": [item.model_dump(mode="json") for item in distributions],
    }
    payload["artifact_sha256"] = _canonical_json_sha256(payload)
    return ModelCalibrationArtifact.model_validate(payload)


def calibration_distribution_sha256(
    distribution: ModelCalibrationDimensionDistribution,
) -> str:
    """Hash one complete observed distribution for threshold-level binding."""

    validated = ModelCalibrationDimensionDistribution.model_validate(
        distribution.model_dump(mode="json")
    )
    return canonical_sha256(validated.model_dump(mode="json"))


def seal_calibrated_qualification_policy(
    *,
    calibration: ModelCalibrationArtifact,
    trusted_calibration_verification: TrustedModelCalibrationVerification,
    created_at: datetime,
    thresholds: tuple[QualificationDimensionThreshold, ...],
    role_policies: tuple[RoleQualificationPolicy, ...],
    tier_a_minimum_overall_score: float,
    tier_a_overall_rationale: str,
    maximum_validity_days: int,
    maximum_benchmark_evidence_age_days: int = 7,
) -> QualificationPolicy:
    """Freeze a v2 policy only from a sufficiently populated live calibration."""

    artifact = ModelCalibrationArtifact.model_validate(calibration.model_dump(mode="json"))
    if type(trusted_calibration_verification) is not TrustedModelCalibrationVerification:
        raise ValueError("calibrated policy sealing requires live calibration verification")
    trusted_calibration_verification.require_for(artifact)
    if created_at < artifact.created_at:
        raise ValueError("calibrated policy cannot predate its calibration artifact")
    included_count = sum(item.included_in_distribution for item in artifact.candidates)
    if included_count < MIN_CALIBRATION_INCLUDED_CANDIDATES:
        raise ValueError("calibrated policy requires at least three complete REAL candidates")
    if artifact.included_root_lineage_count < MIN_CALIBRATION_INCLUDED_ROOT_LINEAGES:
        raise ValueError(
            "calibrated policy requires at least three independently reviewed root lineages"
        )

    _verify_policy_threshold_bindings(
        calibration=artifact,
        thresholds=thresholds,
        role_policies=role_policies,
    )
    policy = seal_qualification_policy(
        created_at=created_at,
        thresholds=thresholds,
        tier_a_minimum_overall_score=tier_a_minimum_overall_score,
        maximum_validity_days=maximum_validity_days,
        maximum_benchmark_evidence_age_days=maximum_benchmark_evidence_age_days,
        role_policies=role_policies,
        calibration_artifact_sha256=artifact.artifact_sha256,
        calibration_included_candidate_count=included_count,
        calibration_included_root_lineage_count=artifact.included_root_lineage_count,
        tier_a_overall_rationale=tier_a_overall_rationale,
    )
    verify_calibrated_qualification_policy(
        calibration=artifact,
        policy=policy,
        trusted_calibration_verification=trusted_calibration_verification,
    )
    return policy


def verify_calibrated_qualification_policy(
    *,
    calibration: ModelCalibrationArtifact,
    policy: QualificationPolicy,
    trusted_calibration_verification: TrustedModelCalibrationVerification,
) -> None:
    """Require exact policy, distribution, and process-local REAL provenance bindings."""

    if type(calibration) is not ModelCalibrationArtifact:
        raise ValueError("calibrated policy verification requires a typed artifact")
    if type(policy) is not QualificationPolicy:
        raise ValueError("calibrated policy verification requires a typed policy")
    artifact = ModelCalibrationArtifact.model_validate(calibration.model_dump(mode="json"))
    validated_policy = QualificationPolicy.model_validate(policy.model_dump(mode="json"))
    if type(trusted_calibration_verification) is not TrustedModelCalibrationVerification:
        raise ValueError("calibrated policy verification requires live calibration verification")
    trusted_calibration_verification.require_for(artifact)
    included_count = sum(item.included_in_distribution for item in artifact.candidates)
    if (
        validated_policy.schema_version != "2.0"
        or validated_policy.calibration_artifact_sha256 != artifact.artifact_sha256
        or validated_policy.calibration_included_candidate_count != included_count
        or validated_policy.calibration_included_root_lineage_count
        != artifact.included_root_lineage_count
        or validated_policy.created_at < artifact.created_at
    ):
        raise ValueError("qualification policy differs from its calibration artifact")
    _verify_policy_threshold_bindings(
        calibration=artifact,
        thresholds=validated_policy.thresholds,
        role_policies=validated_policy.role_policies,
    )


def _verify_policy_threshold_bindings(
    *,
    calibration: ModelCalibrationArtifact,
    thresholds: tuple[QualificationDimensionThreshold, ...],
    role_policies: tuple[RoleQualificationPolicy, ...],
) -> None:
    distributions = {item.dimension: item for item in calibration.distributions}
    global_thresholds = {item.dimension: item for item in thresholds}
    if len(global_thresholds) != len(thresholds):
        raise ValueError("calibrated policy contains duplicate global thresholds")
    for threshold in thresholds:
        _require_threshold_distribution_binding(
            threshold=threshold,
            distribution=distributions[threshold.dimension],
        )
    for role_policy in role_policies:
        for threshold in role_policy.thresholds:
            _require_threshold_distribution_binding(
                threshold=threshold,
                distribution=distributions[threshold.dimension],
            )


def model_calibration_artifact_bytes(artifact: ModelCalibrationArtifact) -> bytes:
    """Return the only accepted canonical byte encoding."""

    validated = ModelCalibrationArtifact.model_validate(artifact.model_dump(mode="json"))
    return stable_json(validated).encode("utf-8")


def write_model_calibration_artifact(
    path: Path,
    artifact: ModelCalibrationArtifact,
) -> None:
    """Atomically create one fresh canonical mode-0600 calibration artifact."""

    serialized = model_calibration_artifact_bytes(artifact)
    if not serialized or len(serialized) > _MAX_ARTIFACT_BYTES:
        raise ValueError("model calibration artifact exceeds its bounded size")
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    _reject_linked_components(parent)
    if not parent.is_dir():
        raise ValueError("model calibration output parent must already exist")
    if os.path.lexists(absolute):
        raise ValueError("model calibration output must be a fresh file")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{absolute.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    published = False
    linked = False
    try:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("model calibration output made no write progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if os.path.lexists(absolute):
            raise ValueError("model calibration output appeared during publication")
        os.link(temporary, absolute, follow_symlinks=False)
        linked = True
        temporary.unlink()
        _fsync_directory(parent)
        if load_model_calibration_artifact(absolute) != artifact:
            raise ValueError("model calibration artifact changed during publication")
        published = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            temporary.unlink(missing_ok=True)
            if linked:
                absolute.unlink(missing_ok=True)


def load_model_calibration_artifact(path: Path) -> ModelCalibrationArtifact:
    """Load one bounded canonical private artifact without following links."""

    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute.parent)
    flags = os.O_RDONLY | os.O_NONBLOCK
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ValueError("model calibration artifact loading requires no-follow support")
    descriptor = -1
    try:
        descriptor = os.open(absolute, flags | no_follow)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != _PRIVATE_FILE_MODE
            or before.st_size <= 0
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise ValueError(
                "model calibration artifact must be a bounded private unshared regular file"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1_048_576))
            if not chunk:
                raise ValueError("model calibration artifact ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("model calibration artifact grew during reading")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise ValueError("model calibration artifact changed during reading")
        try:
            current = os.lstat(absolute)
        except OSError as exc:
            raise ValueError("model calibration artifact path changed during reading") from exc
        identity_current = (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )
        if identity_current != identity_after:
            raise ValueError("model calibration artifact path changed during reading")
        raw = b"".join(chunks)
    except OSError as exc:
        raise ValueError("model calibration artifact is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_json_object)
        if not isinstance(payload, dict):
            raise ValueError("model calibration artifact must contain one JSON object")
        artifact = ModelCalibrationArtifact.model_validate(payload)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("model calibration artifact failed strict validation") from exc
    if raw != model_calibration_artifact_bytes(artifact):
        raise ValueError("model calibration artifact is not canonically serialized")
    return artifact


def _validate_discovery_binding(
    *,
    registry: CandidateRegistry,
    manifest: OpenRouterModelDiscoveryRunManifest,
    candidate_ids: tuple[str, ...],
) -> None:
    routes = manifest.run_provenance.candidate_routes
    route_ids = tuple(item.exact_model_id for item in routes)
    artifact_ids = tuple(item.exact_model_id for item in manifest.artifacts)
    if (
        registry.discovery_run_sha256 != manifest.manifest_sha256
        or route_ids != candidate_ids
        or artifact_ids != candidate_ids
    ):
        raise ValueError("calibration candidate registry differs from discovery manifest")
    for candidate, route, artifact in zip(
        registry.candidates,
        routes,
        manifest.artifacts,
        strict=True,
    ):
        if (
            candidate.approved_provider_endpoint != route.approved_provider_endpoint
            or candidate.approved_provider_endpoint != artifact.approved_provider_endpoint
            or candidate.discovery_evidence_sha256 != artifact.discovery_evidence_sha256
        ):
            raise ValueError("calibration candidate route differs from discovery manifest")


def _validate_portfolio_and_report_bindings(
    *,
    registry: CandidateRegistry,
    manifest: OpenRouterModelDiscoveryRunManifest,
    suite: ModelBenchmarkSuite,
    portfolio: ModelBenchmarkPortfolio,
    reports: tuple[ModelBenchmarkReport, ...],
    benchmark_policy_sha256: str,
) -> None:
    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    if not reports or len(reports) != len(candidate_ids):
        raise ValueError("calibration requires one report per exact candidate")
    for report in reports:
        if len(report.results) != 1:
            raise ValueError("calibration reports must each contain exactly one model")
        verify_model_benchmark_report_structure(report, corpus=suite)
    report_ids = tuple(report.results[0].target.model_id for report in reports)
    if report_ids != candidate_ids:
        raise ValueError("calibration reports do not exactly cover the candidate registry")
    if (
        portfolio.candidate_registry_sha256 != registry.registry_sha256
        or portfolio.discovery_run_manifest_sha256 != manifest.manifest_sha256
        or portfolio.candidate_model_ids != candidate_ids
        or portfolio.corpus_name != suite.name
        or portfolio.corpus_sha256 != suite.corpus_sha256
        or portfolio.ground_truth_sha256 != suite.ground_truth_sha256
        or portfolio.qualification_policy_sha256 != benchmark_policy_sha256
        or len(portfolio.diagnostics) != len(candidate_ids)
    ):
        raise ValueError("calibration portfolio differs from its exact frozen inputs")
    for report, binding, diagnostic in zip(
        reports,
        portfolio.report_artifacts,
        portfolio.diagnostics,
        strict=True,
    ):
        if (
            binding.exact_model_id != report.results[0].target.model_id
            or binding.report_sha256 != report.report_sha256
            or binding.execution_evidence is not report.execution_evidence
            or diagnostic.exact_model_id != binding.exact_model_id
            or diagnostic.report_sha256 != binding.report_sha256
            or diagnostic.execution_evidence is not binding.execution_evidence
        ):
            raise ValueError("calibration report differs from portfolio evidence")


def _report_cases_are_exact_real_complete(
    *,
    report: ModelBenchmarkReport,
    candidate: CandidateModel,
) -> bool:
    result = report.results[0]
    if not result.cases:
        return False
    for case in result.cases:
        record = case.usage_record
        if (
            case.error_kind is not None
            or case.execution_evidence is not ExecutionEvidenceKind.REAL
            or case.normalized_response is None
            or case.generation_evidence is None
            or record is None
            or record.execution_evidence is not ExecutionEvidenceKind.REAL
            or record.status != "success"
            or record.validation_status is not ModelRequestValidationStatus.VALID
            or record.requested_model != candidate.exact_model_id
            or record.returned_model
            not in {candidate.exact_model_id, candidate.canonical_model_slug}
            or record.actual_model not in {candidate.exact_model_id, candidate.canonical_model_slug}
            or record.actual_provider_endpoint != candidate.approved_provider_endpoint
            or record.configured_provider_endpoints != [candidate.approved_provider_endpoint]
            or record.routing.get("certification_request") is not True
            or record.routing.get("provider_fallbacks_allowed") is not False
            or record.routing.get("selected_model") != record.actual_model
            or record.routing.get("canonical_model") != candidate.canonical_model_slug
            or record.routing.get("selected_provider_name") != candidate.approved_provider_name
            or record.routing.get("endpoint_snapshot_sha256") != candidate.endpoint_snapshot_sha256
            or record.routing.get("output_capability_sha256") != candidate.output_capability_sha256
            or record.routing.get("endpoint_pricing_sha256") != candidate.pricing_snapshot_sha256
            or record.routing.get("catalog_identity_binding_sha256")
            != canonical_sha256(
                {
                    "canonical_slug": candidate.canonical_model_slug,
                    "id": candidate.exact_model_id,
                }
            )
            or record.routing.get("discovery_evidence_sha256")
            != candidate.discovery_evidence_sha256
        ):
            return False
    return True


def _calibration_dimension_observation(
    candidate: ModelCalibrationCandidateObservation,
    dimension: ModelBenchmarkDimension,
) -> ModelCalibrationDimensionObservation:
    score = next(item for item in candidate.dimensions if item.dimension is dimension)
    return ModelCalibrationDimensionObservation(
        exact_model_id=candidate.exact_model_id,
        root_lineage=_required_calibration_root_lineage(candidate),
        passed=score.passed,
        evaluated=score.evaluated,
        score=score.score,
    )


def _required_calibration_root_lineage(
    candidate: ModelCalibrationCandidateObservation,
) -> str:
    if candidate.root_lineage is None:
        raise ValueError("included calibration candidate lacks an approved root lineage")
    return candidate.root_lineage


def _require_threshold_distribution_binding(
    *,
    threshold: QualificationDimensionThreshold,
    distribution: ModelCalibrationDimensionDistribution,
) -> None:
    if (
        distribution.included_candidate_count < MIN_CALIBRATION_INCLUDED_CANDIDATES
        or not distribution.observations
    ):
        raise ValueError("calibrated threshold requires a populated distribution")
    evaluated_counts = {item.evaluated for item in distribution.observations}
    if len(evaluated_counts) != 1:
        raise ValueError("calibrated threshold observations have inconsistent denominators")
    observed_denominator = next(iter(evaluated_counts))
    if threshold.minimum_cases != observed_denominator:
        raise ValueError("calibrated threshold cannot reduce its observed denominator")
    if threshold.calibration_distribution_sha256 != calibration_distribution_sha256(distribution):
        raise ValueError("calibrated threshold distribution hash is inconsistent")
    representable_scores = {
        round(passed / observed_denominator, 6) for passed in range(observed_denominator + 1)
    }
    if threshold.minimum_score not in representable_scores:
        raise ValueError("calibrated threshold score is not representable by its denominator")


def _canonical_json_sha256(value: Any) -> str:
    return canonical_sha256(_JSON_ADAPTER.dump_python(value, mode="json"))


def _reject_linked_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink() or current.is_junction():
            raise ValueError("model calibration artifact paths cannot traverse links")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
