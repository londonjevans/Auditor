"""Non-dispositive, evidence-bound model benchmark calibration artifacts.

Calibration records observed benchmark distributions. It deliberately has no
qualification disposition and cannot authorize a model or review role.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import threading
import weakref
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Never, Protocol, SupportsIndex

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
from mmaudit.models.lineage_authority import TrustedModelLineageReviewVerification
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.qualification import (
    DETERMINISTIC_QUALIFICATION_DIMENSIONS,
    CandidateModel,
    CandidateRegistry,
    LineageReviewStatus,
    QualificationDimensionThreshold,
    QualificationPolicy,
    QualificationRoleClass,
    QualificationThresholdBasis,
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
_PRIVATE_JSON_DIR_FD_SUPPORTED = all(
    function in os.supports_dir_fd for function in (os.open, os.stat, os.unlink, os.link)
)
_PRIVATE_JSON_NOFOLLOW_SUPPORTED = all(
    function in os.supports_follow_symlinks for function in (os.stat, os.link)
)
_CALIBRATED_POLICY_MAXIMUM_VALIDITY_DAYS = 30
_CALIBRATED_POLICY_MAXIMUM_BENCHMARK_EVIDENCE_AGE_DAYS = 7
_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT = 8
_CALIBRATION_GLOBAL_ROOT_SUPPORT = 6
_CALIBRATION_ROLE_ROOT_SUPPORT = {
    QualificationRoleClass.INVESTIGATOR: 4,
    QualificationRoleClass.VERIFIER: 2,
    QualificationRoleClass.FALSIFIER: 2,
    QualificationRoleClass.JUDGE: 2,
}
_CALIBRATION_ROLE_DIMENSIONS = {
    QualificationRoleClass.INVESTIGATOR: (
        ModelBenchmarkDimension.EXACT_SOURCE_LOCATION,
        ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION,
        ModelBenchmarkDimension.SOLIDITY_SECURITY_REASONING,
    ),
    QualificationRoleClass.VERIFIER: (ModelBenchmarkDimension.VERIFIER_QUALITY,),
    QualificationRoleClass.FALSIFIER: (ModelBenchmarkDimension.FALSIFIER_QUALITY,),
    QualificationRoleClass.JUDGE: (
        ModelBenchmarkDimension.FALSIFIER_QUALITY,
        ModelBenchmarkDimension.REPORT_QUALITY,
        ModelBenchmarkDimension.VERIFIER_QUALITY,
    ),
}
_DETERMINISTIC_EMPIRICAL_SUPPORT_RATIONALE = (
    "Non-statistical empirical-support record for the deterministic exact-pass requirement; "
    "the 1.0 gate is a protocol requirement, not a statistical-significance claim."
)
_JUDGMENT_EMPIRICAL_SUPPORT_RATIONALE = (
    "Non-statistical empirical-support threshold: the strongest positive non-perfect observed "
    "score meeting the frozen candidate and root-lineage support floor; this is not a "
    "statistical-significance claim."
)
_AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE = (
    "Non-statistical empirical-support aggregate: the strongest observed supported score capped "
    "below perfection; this is not a statistical-significance claim."
)


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
        lineage_review_artifact: ModelLineageReviewArtifact,
        trusted_lineage_verification: TrustedModelLineageReviewVerification,
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
            lineage_review_artifact=lineage_review_artifact,
            trusted_lineage_verification=trusted_lineage_verification,
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


class ModelCalibrationCandidateObservation(StrictModel):
    """One exact candidate retained whether or not its report is creditable."""

    exact_model_id: str = Field(min_length=3, max_length=300)
    root_lineage: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    lineage_binding_sha256: str = Field(pattern=_SHA256_PATTERN)
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

    schema_version: Literal["2.0"] = "2.0"
    created_at: datetime
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    lineage_review_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    lineage_authority_envelope_sha256: str = Field(pattern=_SHA256_PATTERN)
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
        lineage_bindings = tuple(item.lineage_binding_sha256 for item in self.candidates)
        if len(lineage_bindings) != len(set(lineage_bindings)):
            raise ValueError("calibration lineage bindings must be unique per candidate")
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


class _CalibrationMeasurements(Protocol):
    """Read-only distribution inputs; this interface carries no runtime authority."""

    @property
    def candidates(self) -> tuple[ModelCalibrationCandidateObservation, ...]: ...

    @property
    def distributions(self) -> tuple[ModelCalibrationDimensionDistribution, ...]: ...


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
    lineage_review_artifact: ModelLineageReviewArtifact,
    trusted_lineage_verification: TrustedModelLineageReviewVerification,
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
    if type(lineage_review_artifact) is not ModelLineageReviewArtifact:
        raise ValueError("calibration requires a typed lineage review artifact")
    lineage = ModelLineageReviewArtifact.model_validate(
        lineage_review_artifact.model_dump(mode="json")
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
    lineage_candidate_ids = tuple(binding.exact_model_id for binding in lineage.candidate_bindings)
    if (
        lineage.candidate_registry_sha256 != registry.registry_sha256
        or lineage.discovery_manifest_sha256 != manifest.manifest_sha256
        or lineage.discovery_candidate_set_sha256 != manifest.candidate_set_sha256
        or lineage_candidate_ids != candidate_ids
    ):
        raise ValueError("calibration lineage review differs from the exact candidate evidence")
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
    if type(trusted_lineage_verification) is not TrustedModelLineageReviewVerification:
        raise ValueError("calibration requires trusted operator lineage verification")
    campaign_started_at = portfolio.started_at or registry.created_at
    try:
        lineage_authority = trusted_lineage_verification.require_for(
            candidate_registry=registry,
            discovery_manifest=manifest,
            campaign_started_at=campaign_started_at,
            observed_at=created_at,
        )
    except ValueError as exc:
        raise ValueError("trusted lineage verification does not bind calibration inputs") from exc
    if lineage_authority.review_artifact_sha256 != lineage.artifact_sha256:
        raise ValueError("trusted lineage verification differs from the supplied artifact")
    lineage_by_model = {binding.exact_model_id: binding for binding in lineage.candidate_bindings}
    authority_by_model = {
        candidate.exact_model_id: candidate for candidate in lineage_authority.candidates
    }
    if tuple(authority_by_model) != candidate_ids or any(
        authority_by_model[model_id].lineage_binding_sha256
        != lineage_by_model[model_id].binding_sha256
        for model_id in candidate_ids
    ):
        raise ValueError("trusted lineage candidate projection differs from the artifact")

    candidates: list[ModelCalibrationCandidateObservation] = []
    for candidate, report, diagnostic in zip(
        registry.candidates,
        reports,
        portfolio.diagnostics,
        strict=True,
    ):
        lineage_binding = lineage_by_model[candidate.exact_model_id]
        lineage_decision = authority_by_model[candidate.exact_model_id]
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
            lineage_decision.root_lineage is None
            or lineage_decision.decision is not LineageReviewStatus.APPROVED
        ):
            reasons.add(CalibrationExclusionReason.ROOT_LINEAGE_NOT_APPROVED)
        is_included = not reasons
        candidates.append(
            ModelCalibrationCandidateObservation(
                exact_model_id=candidate.exact_model_id,
                root_lineage=lineage_decision.root_lineage,
                lineage_binding_sha256=lineage_binding.binding_sha256,
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
        "schema_version": "2.0",
        "created_at": created_at,
        "candidate_registry_sha256": registry.registry_sha256,
        "discovery_manifest_sha256": manifest.manifest_sha256,
        "candidate_set_sha256": canonical_sha256(list(candidate_ids)),
        "lineage_review_artifact_sha256": lineage.artifact_sha256,
        "lineage_authority_envelope_sha256": (lineage_authority.authority_envelope_sha256),
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


def derive_calibrated_qualification_policy(
    *,
    calibration: ModelCalibrationArtifact,
    trusted_calibration_verification: TrustedModelCalibrationVerification,
) -> QualificationPolicy:
    """Derive and seal the only supported P2 threshold projection from live calibration.

    The resulting policy is a successor candidate, not production-selection authority.
    Its scores, denominators, distribution hashes, role dimensions, and rationales are
    derived here; callers cannot choose any quality threshold.
    """

    if type(calibration) is not ModelCalibrationArtifact:
        raise ValueError("calibrated policy derivation requires a typed artifact")
    artifact = ModelCalibrationArtifact.model_validate(calibration.model_dump(mode="json"))
    if type(trusted_calibration_verification) is not TrustedModelCalibrationVerification:
        raise ValueError("calibrated policy derivation requires live calibration verification")
    trusted_calibration_verification.require_for(artifact)

    thresholds, role_policies, global_overall_score = _derive_calibration_policy_components(
        artifact
    )
    return seal_calibrated_qualification_policy(
        calibration=artifact,
        trusted_calibration_verification=trusted_calibration_verification,
        created_at=artifact.created_at,
        thresholds=thresholds,
        role_policies=role_policies,
        tier_a_minimum_overall_score=global_overall_score,
        tier_a_overall_rationale=_AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE,
        maximum_validity_days=_CALIBRATED_POLICY_MAXIMUM_VALIDITY_DAYS,
        maximum_benchmark_evidence_age_days=(
            _CALIBRATED_POLICY_MAXIMUM_BENCHMARK_EVIDENCE_AGE_DAYS
        ),
    )


def _derive_calibration_policy_components(
    artifact: _CalibrationMeasurements,
) -> tuple[tuple[QualificationDimensionThreshold, ...], tuple[RoleQualificationPolicy, ...], float]:
    """Project the fixed empirical rule, independently of its evidence-authority path."""

    distributions = {item.dimension: item for item in artifact.distributions}
    thresholds = tuple(
        _derive_dimension_threshold(
            distribution=distributions[dimension],
            required_candidate_count=_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT,
            required_root_count=_CALIBRATION_GLOBAL_ROOT_SUPPORT,
        )
        for dimension in sorted(ModelBenchmarkDimension, key=lambda item: item.value)
    )
    role_policies = tuple(
        RoleQualificationPolicy(
            role_class=role_class,
            thresholds=tuple(
                _derive_dimension_threshold(
                    distribution=distributions[dimension],
                    required_candidate_count=None,
                    required_root_count=_CALIBRATION_ROLE_ROOT_SUPPORT[role_class],
                )
                for dimension in _CALIBRATION_ROLE_DIMENSIONS[role_class]
            ),
            minimum_overall_score=_derived_supported_overall_score(
                calibration=artifact,
                dimensions=_CALIBRATION_ROLE_DIMENSIONS[role_class],
                required_candidate_count=None,
                required_root_count=_CALIBRATION_ROLE_ROOT_SUPPORT[role_class],
                label=role_class.value,
            ),
            minimum_overall_rationale=_AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE,
        )
        for role_class in sorted(QualificationRoleClass, key=lambda item: item.value)
    )
    global_dimensions = tuple(sorted(ModelBenchmarkDimension, key=lambda item: item.value))
    global_overall_score = _derived_supported_overall_score(
        calibration=artifact,
        dimensions=global_dimensions,
        required_candidate_count=_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT,
        required_root_count=_CALIBRATION_GLOBAL_ROOT_SUPPORT,
        label="global",
    )
    return thresholds, role_policies, global_overall_score


def _derive_dimension_threshold(
    *,
    distribution: ModelCalibrationDimensionDistribution,
    required_candidate_count: int | None,
    required_root_count: int,
) -> QualificationDimensionThreshold:
    evaluated_counts = {item.evaluated for item in distribution.observations}
    if not distribution.observations or len(evaluated_counts) != 1:
        raise ValueError(
            f"{distribution.dimension.value} calibration distribution has no exact denominator"
        )
    denominator = next(iter(evaluated_counts))
    deterministic = distribution.dimension in DETERMINISTIC_QUALIFICATION_DIMENSIONS
    minimum_score = (
        1.0
        if deterministic
        else _greatest_supported_nonabsolute_score(
            distribution=distribution,
            denominator=denominator,
            required_candidate_count=required_candidate_count,
            required_root_count=required_root_count,
        )
    )
    return QualificationDimensionThreshold(
        dimension=distribution.dimension,
        minimum_cases=denominator,
        minimum_score=minimum_score,
        basis=(
            QualificationThresholdBasis.DETERMINISTIC_REQUIREMENT
            if deterministic
            else QualificationThresholdBasis.CALIBRATED_DISTRIBUTION
        ),
        rationale=(
            _DETERMINISTIC_EMPIRICAL_SUPPORT_RATIONALE
            if deterministic
            else _JUDGMENT_EMPIRICAL_SUPPORT_RATIONALE
        ),
        calibration_distribution_sha256=calibration_distribution_sha256(distribution),
    )


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
    if created_at != artifact.created_at:
        raise ValueError("calibrated policy creation time must equal its calibration artifact")
    if (
        maximum_validity_days != _CALIBRATED_POLICY_MAXIMUM_VALIDITY_DAYS
        or maximum_benchmark_evidence_age_days
        != _CALIBRATED_POLICY_MAXIMUM_BENCHMARK_EVIDENCE_AGE_DAYS
    ):
        raise ValueError("calibrated policy validity windows differ from the frozen projection")
    if tier_a_overall_rationale != _AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE:
        raise ValueError("calibrated policy aggregate rationale differs from the frozen projection")
    included_count = sum(item.included_in_distribution for item in artifact.candidates)
    if included_count < _CALIBRATION_GLOBAL_CANDIDATE_SUPPORT:
        raise ValueError(
            "calibrated policy requires at least "
            f"{_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT} complete REAL candidates"
        )
    if artifact.included_root_lineage_count < _CALIBRATION_GLOBAL_ROOT_SUPPORT:
        raise ValueError(
            "calibrated policy requires at least "
            f"{_CALIBRATION_GLOBAL_ROOT_SUPPORT} independently reviewed root lineages"
        )

    _verify_policy_threshold_bindings(
        calibration=artifact,
        thresholds=thresholds,
        role_policies=role_policies,
        tier_a_minimum_overall_score=tier_a_minimum_overall_score,
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
    """Require structural calibration bindings plus process-local REAL provenance."""

    if type(calibration) is not ModelCalibrationArtifact:
        raise ValueError("calibrated policy verification requires a typed artifact")
    artifact = ModelCalibrationArtifact.model_validate(calibration.model_dump(mode="json"))
    verify_calibrated_qualification_policy_structure(
        calibration=artifact,
        policy=policy,
    )
    if type(trusted_calibration_verification) is not TrustedModelCalibrationVerification:
        raise ValueError("calibrated policy verification requires live calibration verification")
    trusted_calibration_verification.require_for(artifact)


def verify_calibrated_qualification_policy_structure(
    *,
    calibration: ModelCalibrationArtifact,
    policy: QualificationPolicy,
) -> None:
    """Verify the exact A-to-P2 relation without issuing runtime authority.

    This provider-free check proves only that the policy is the deterministic
    structural projection of the supplied calibration artifact. Self-hashes and
    this relation alone are declarations, not production-selection authority.
    """

    if type(calibration) is not ModelCalibrationArtifact:
        raise ValueError("calibrated policy structural verification requires a typed artifact")
    if type(policy) is not QualificationPolicy:
        raise ValueError("calibrated policy structural verification requires a typed policy")
    artifact = ModelCalibrationArtifact.model_validate(calibration.model_dump(mode="json"))
    validated_policy = QualificationPolicy.model_validate(policy.model_dump(mode="json"))
    included_count = sum(item.included_in_distribution for item in artifact.candidates)
    if (
        validated_policy.schema_version != "2.0"
        or validated_policy.calibration_artifact_sha256 != artifact.artifact_sha256
        or validated_policy.calibration_included_candidate_count != included_count
        or validated_policy.calibration_included_root_lineage_count
        != artifact.included_root_lineage_count
        or validated_policy.created_at != artifact.created_at
        or validated_policy.maximum_validity_days != _CALIBRATED_POLICY_MAXIMUM_VALIDITY_DAYS
        or validated_policy.maximum_benchmark_evidence_age_days
        != _CALIBRATED_POLICY_MAXIMUM_BENCHMARK_EVIDENCE_AGE_DAYS
        or validated_policy.tier_a_overall_rationale != _AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE
    ):
        raise ValueError("qualification policy differs from its calibration artifact")
    _verify_policy_threshold_bindings(
        calibration=artifact,
        thresholds=validated_policy.thresholds,
        role_policies=validated_policy.role_policies,
        tier_a_minimum_overall_score=validated_policy.tier_a_minimum_overall_score,
    )


def _verify_policy_threshold_bindings(
    *,
    calibration: _CalibrationMeasurements,
    thresholds: tuple[QualificationDimensionThreshold, ...],
    role_policies: tuple[RoleQualificationPolicy, ...],
    tier_a_minimum_overall_score: float,
) -> None:
    distributions = {item.dimension: item for item in calibration.distributions}
    global_thresholds = {item.dimension: item for item in thresholds}
    if len(global_thresholds) != len(thresholds) or set(global_thresholds) != set(
        ModelBenchmarkDimension
    ):
        raise ValueError("calibrated policy must bind every global dimension exactly once")
    roles = {item.role_class: item for item in role_policies}
    if len(roles) != len(role_policies) or set(roles) != set(QualificationRoleClass):
        raise ValueError("calibrated policy must bind every role class exactly once")
    for role_class, role_policy in roles.items():
        if (
            tuple(item.dimension for item in role_policy.thresholds)
            != (_CALIBRATION_ROLE_DIMENSIONS[role_class])
        ):
            raise ValueError(
                f"{role_class.value} calibrated policy differs from its canonical dimensions"
            )
        if role_policy.minimum_overall_rationale != _AGGREGATE_EMPIRICAL_SUPPORT_RATIONALE:
            raise ValueError(
                f"{role_class.value} calibrated policy aggregate rationale differs "
                "from the frozen projection"
            )
    for threshold in thresholds:
        _require_threshold_distribution_binding(
            threshold=threshold,
            distribution=distributions[threshold.dimension],
            required_candidate_count=_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT,
            required_root_count=_CALIBRATION_GLOBAL_ROOT_SUPPORT,
        )
    for role_policy in role_policies:
        for threshold in role_policy.thresholds:
            _require_threshold_distribution_binding(
                threshold=threshold,
                distribution=distributions[threshold.dimension],
                required_candidate_count=None,
                required_root_count=_CALIBRATION_ROLE_ROOT_SUPPORT[role_policy.role_class],
            )
    _require_overall_threshold_binding(
        calibration=calibration,
        dimensions=tuple(sorted(ModelBenchmarkDimension, key=lambda item: item.value)),
        supplied_score=tier_a_minimum_overall_score,
        required_candidate_count=_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT,
        required_root_count=_CALIBRATION_GLOBAL_ROOT_SUPPORT,
        label="global",
    )
    for role_policy in role_policies:
        _require_overall_threshold_binding(
            calibration=calibration,
            dimensions=tuple(item.dimension for item in role_policy.thresholds),
            supplied_score=role_policy.minimum_overall_score,
            required_candidate_count=None,
            required_root_count=_CALIBRATION_ROLE_ROOT_SUPPORT[role_policy.role_class],
            label=role_policy.role_class.value,
        )
    _require_joint_policy_support(
        calibration=calibration,
        thresholds=thresholds,
        role_policies=role_policies,
        tier_a_minimum_overall_score=tier_a_minimum_overall_score,
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
    _write_private_json_artifact(
        path,
        serialized,
        label="model calibration artifact",
    )


def load_model_calibration_artifact(path: Path) -> ModelCalibrationArtifact:
    """Load one bounded canonical private artifact without following links."""

    raw = _load_private_json_artifact(path, label="model calibration artifact")
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


def calibrated_qualification_policy_bytes(policy: QualificationPolicy) -> bytes:
    """Return the canonical JSON encoding for one calibrated P2 candidate."""

    if type(policy) is not QualificationPolicy:
        raise ValueError("calibrated qualification policy serialization requires a typed policy")
    validated = QualificationPolicy.model_validate(policy.model_dump(mode="json"))
    if validated.schema_version != "2.0":
        raise ValueError("calibrated qualification policy must use schema version 2.0")
    return stable_json(validated).encode("utf-8")


def write_calibrated_qualification_policy(
    path: Path,
    policy: QualificationPolicy,
) -> None:
    """Atomically create one fresh canonical mode-0600 calibrated P2 candidate."""

    serialized = calibrated_qualification_policy_bytes(policy)
    _write_private_json_artifact(
        path,
        serialized,
        label="calibrated qualification policy",
    )


def load_calibrated_qualification_policy(path: Path) -> QualificationPolicy:
    """Descriptor-read one canonical private P2 candidate without following links."""

    raw = _load_private_json_artifact(path, label="calibrated qualification policy")
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_json_object)
        if not isinstance(payload, dict):
            raise ValueError("calibrated qualification policy must contain one JSON object")
        policy = QualificationPolicy.model_validate(payload)
        if policy.schema_version != "2.0":
            raise ValueError("calibrated qualification policy must use schema version 2.0")
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("calibrated qualification policy failed strict validation") from exc
    if raw != calibrated_qualification_policy_bytes(policy):
        raise ValueError("calibrated qualification policy is not canonically serialized")
    return policy


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
    required_candidate_count: int | None,
    required_root_count: int,
) -> None:
    expected_rationale = (
        _DETERMINISTIC_EMPIRICAL_SUPPORT_RATIONALE
        if threshold.dimension in DETERMINISTIC_QUALIFICATION_DIMENSIONS
        else _JUDGMENT_EMPIRICAL_SUPPORT_RATIONALE
    )
    if threshold.rationale != expected_rationale:
        raise ValueError(
            f"{threshold.dimension.value} threshold rationale differs from its frozen projection"
        )
    if (
        distribution.included_candidate_count < _CALIBRATION_GLOBAL_CANDIDATE_SUPPORT
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
    if threshold.dimension in DETERMINISTIC_QUALIFICATION_DIMENSIONS:
        expected_score = 1.0
        supporters = tuple(
            item for item in distribution.observations if item.passed == observed_denominator
        )
        if not _has_required_empirical_support(
            exact_model_ids={item.exact_model_id for item in supporters},
            root_lineages={item.root_lineage for item in supporters},
            required_candidate_count=required_candidate_count,
            required_root_count=required_root_count,
        ):
            raise ValueError(f"{threshold.dimension.value} lacks required exact empirical support")
    else:
        expected_score = _greatest_supported_nonabsolute_score(
            distribution=distribution,
            denominator=observed_denominator,
            required_candidate_count=required_candidate_count,
            required_root_count=required_root_count,
        )
    if threshold.minimum_score != expected_score:
        raise ValueError(
            f"{threshold.dimension.value} threshold differs from its frozen "
            f"empirical-support value {expected_score}"
        )


def _greatest_supported_nonabsolute_score(
    *,
    distribution: ModelCalibrationDimensionDistribution,
    denominator: int,
    required_candidate_count: int | None,
    required_root_count: int,
) -> float:
    """Select the strongest positive, non-perfect score with exact observed support."""

    for passed in range(denominator - 1, 0, -1):
        supporters = tuple(item for item in distribution.observations if item.passed >= passed)
        if _has_required_empirical_support(
            exact_model_ids={item.exact_model_id for item in supporters},
            root_lineages={item.root_lineage for item in supporters},
            required_candidate_count=required_candidate_count,
            required_root_count=required_root_count,
        ):
            return round(passed / denominator, 6)
    raise ValueError(
        f"{distribution.dimension.value} lacks positive non-absolute empirical support"
    )


def _require_overall_threshold_binding(
    *,
    calibration: _CalibrationMeasurements,
    dimensions: tuple[ModelBenchmarkDimension, ...],
    supplied_score: float,
    required_candidate_count: int | None,
    required_root_count: int,
    label: str,
) -> None:
    expected_score = _derived_supported_overall_score(
        calibration=calibration,
        dimensions=dimensions,
        required_candidate_count=required_candidate_count,
        required_root_count=required_root_count,
        label=label,
    )
    if supplied_score != expected_score:
        raise ValueError(
            f"{label} aggregate threshold differs from its frozen "
            f"empirical-support value {expected_score}"
        )


def _derived_supported_overall_score(
    *,
    calibration: _CalibrationMeasurements,
    dimensions: tuple[ModelBenchmarkDimension, ...],
    required_candidate_count: int | None,
    required_root_count: int,
    label: str,
) -> float:
    """Derive a bounded aggregate gate from exact empirical support."""

    if not dimensions or len(dimensions) != len(set(dimensions)):
        raise ValueError(f"{label} aggregate dimensions are empty or duplicate")
    distributions = {item.dimension: item for item in calibration.distributions}
    judgment_denominators: list[int] = []
    for dimension in dimensions:
        if dimension in DETERMINISTIC_QUALIFICATION_DIMENSIONS:
            continue
        evaluated_counts = {item.evaluated for item in distributions[dimension].observations}
        if len(evaluated_counts) != 1:
            raise ValueError(f"{label} aggregate has inconsistent {dimension.value} denominators")
        judgment_denominators.append(next(iter(evaluated_counts)))
    if not judgment_denominators:
        raise ValueError(f"{label} aggregate lacks a judgment dimension")

    aggregate_scores: dict[str, float] = {}
    included = tuple(item for item in calibration.candidates if item.included_in_distribution)
    for candidate in included:
        scores = {item.dimension: item.score for item in candidate.dimensions}
        aggregate_scores[candidate.exact_model_id] = round(
            sum(scores[dimension] for dimension in dimensions) / len(dimensions),
            6,
        )
    supported_score: float | None = None
    for score in sorted(set(aggregate_scores.values()), reverse=True):
        supporters = tuple(
            candidate
            for candidate in included
            if aggregate_scores[candidate.exact_model_id] >= score
        )
        if _has_required_empirical_support(
            exact_model_ids={item.exact_model_id for item in supporters},
            root_lineages={_required_calibration_root_lineage(item) for item in supporters},
            required_candidate_count=required_candidate_count,
            required_root_count=required_root_count,
        ):
            supported_score = score
            break
    if supported_score is None or supported_score <= 0:
        raise ValueError(f"{label} aggregate lacks positive empirical support")

    nonabsolute_ceiling = round(
        1 - (1 / (max(judgment_denominators) * len(dimensions))),
        6,
    )
    return min(supported_score, nonabsolute_ceiling)


def _require_joint_policy_support(
    *,
    calibration: _CalibrationMeasurements,
    thresholds: tuple[QualificationDimensionThreshold, ...],
    role_policies: tuple[RoleQualificationPolicy, ...],
    tier_a_minimum_overall_score: float,
) -> None:
    included = tuple(item for item in calibration.candidates if item.included_in_distribution)
    global_dimensions = tuple(item.dimension for item in thresholds)
    global_supporters = tuple(
        candidate
        for candidate in included
        if _candidate_passes_thresholds(candidate=candidate, thresholds=thresholds)
        and _candidate_aggregate_score(candidate, global_dimensions) >= tier_a_minimum_overall_score
    )
    if not _has_required_empirical_support(
        exact_model_ids={item.exact_model_id for item in global_supporters},
        root_lineages={_required_calibration_root_lineage(item) for item in global_supporters},
        required_candidate_count=_CALIBRATION_GLOBAL_CANDIDATE_SUPPORT,
        required_root_count=_CALIBRATION_GLOBAL_ROOT_SUPPORT,
    ):
        raise ValueError(
            "global calibrated policy is not jointly supported by the required "
            "exact candidates and root lineages"
        )

    for role_policy in role_policies:
        role_dimensions = tuple(item.dimension for item in role_policy.thresholds)
        role_supporters = tuple(
            candidate
            for candidate in global_supporters
            if _candidate_passes_thresholds(
                candidate=candidate,
                thresholds=role_policy.thresholds,
            )
            and _candidate_aggregate_score(candidate, role_dimensions)
            >= role_policy.minimum_overall_score
        )
        if not _has_required_empirical_support(
            exact_model_ids={item.exact_model_id for item in role_supporters},
            root_lineages={_required_calibration_root_lineage(item) for item in role_supporters},
            required_candidate_count=None,
            required_root_count=_CALIBRATION_ROLE_ROOT_SUPPORT[role_policy.role_class],
        ):
            raise ValueError(
                f"{role_policy.role_class.value} calibrated policy is not jointly "
                "supported by the required root lineages"
            )


def _candidate_passes_thresholds(
    *,
    candidate: ModelCalibrationCandidateObservation,
    thresholds: tuple[QualificationDimensionThreshold, ...],
) -> bool:
    scores = {item.dimension: item for item in candidate.dimensions}
    return all(
        scores[threshold.dimension].evaluated >= threshold.minimum_cases
        and scores[threshold.dimension].score >= threshold.minimum_score
        for threshold in thresholds
    )


def _candidate_aggregate_score(
    candidate: ModelCalibrationCandidateObservation,
    dimensions: tuple[ModelBenchmarkDimension, ...],
) -> float:
    scores = {item.dimension: item.score for item in candidate.dimensions}
    return round(
        sum(scores[dimension] for dimension in dimensions) / len(dimensions),
        6,
    )


def _has_required_empirical_support(
    *,
    exact_model_ids: set[str],
    root_lineages: set[str],
    required_candidate_count: int | None,
    required_root_count: int,
) -> bool:
    return (
        required_candidate_count is None or len(exact_model_ids) >= required_candidate_count
    ) and len(root_lineages) >= required_root_count


def _canonical_json_sha256(value: Any) -> str:
    return canonical_sha256(_JSON_ADAPTER.dump_python(value, mode="json"))


def _required_private_json_flag(name: str, *, label: str) -> int:
    value = getattr(os, name, 0)
    if not value:
        raise ValueError(f"{label} I/O requires {name} support")
    return int(value)


def _open_private_json_parent(path: Path, *, label: str) -> tuple[Path, int, str]:
    """Open every ancestor relative to stable no-follow directory descriptors."""

    if not _PRIVATE_JSON_DIR_FD_SUPPORTED:
        raise ValueError(f"descriptor-safe {label} traversal is unavailable")
    if not _PRIVATE_JSON_NOFOLLOW_SUPPORTED:
        raise ValueError(f"no-follow {label} access is unavailable")
    absolute = Path(os.path.abspath(path))
    if not absolute.name or absolute.name in {".", ".."}:
        raise ValueError(f"{label} path lacks a file name")
    flags = (
        os.O_RDONLY
        | _required_private_json_flag("O_DIRECTORY", label=label)
        | _required_private_json_flag("O_NOFOLLOW", label=label)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(absolute.anchor, flags)
        for component in absolute.parts[1:-1]:
            child = os.open(component, flags, dir_fd=descriptor)
            try:
                if not stat.S_ISDIR(os.fstat(child).st_mode):
                    raise ValueError(f"{label} parent must be an unlinked directory")
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return absolute, descriptor, absolute.name
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ValueError(f"{label} parent is unavailable or linked") from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _private_json_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _private_json_directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _read_exact_private_json_bytes(descriptor: int, size: int, *, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1_048_576))
        if not chunk:
            raise ValueError(f"{label} ended before its declared size")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ValueError(f"{label} grew during reading")
    return b"".join(chunks)


def _require_private_json_path_identity(
    path: Path,
    *,
    label: str,
    parent_metadata: os.stat_result,
    file_metadata: os.stat_result,
) -> None:
    _absolute, current_parent, leaf = _open_private_json_parent(path, label=label)
    try:
        current_file = os.stat(leaf, dir_fd=current_parent, follow_symlinks=False)
        if _private_json_directory_identity(
            os.fstat(current_parent)
        ) != _private_json_directory_identity(parent_metadata) or _private_json_file_identity(
            current_file
        ) != _private_json_file_identity(file_metadata):
            raise ValueError(f"{label} path changed during access")
    except OSError as exc:
        raise ValueError(f"{label} path changed during access") from exc
    finally:
        os.close(current_parent)


def _unlink_private_json_if_identity(
    parent_descriptor: int,
    leaf: str,
    expected_identity: tuple[int, int] | None,
) -> None:
    if expected_identity is None:
        return
    try:
        metadata = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) == expected_identity:
            os.unlink(leaf, dir_fd=parent_descriptor)
    except OSError:
        return


def _write_private_json_artifact(path: Path, serialized: bytes, *, label: str) -> None:
    if not serialized or len(serialized) > _MAX_ARTIFACT_BYTES:
        raise ValueError(f"{label} exceeds its bounded size")
    absolute, parent_descriptor, leaf = _open_private_json_parent(path, label=label)
    descriptor = -1
    temporary_leaf: str | None = None
    created_identity: tuple[int, int] | None = None
    published = False
    linked = False
    try:
        try:
            os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ValueError(f"{label} destination could not be inspected safely") from exc
        else:
            raise ValueError(f"{label} output must be a fresh file")

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | _required_private_json_flag("O_NOFOLLOW", label=label)
        )
        for _attempt in range(32):
            candidate = f".mmaudit-private-json-{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    flags,
                    _PRIVATE_FILE_MODE,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            temporary_leaf = candidate
            break
        if descriptor < 0 or temporary_leaf is None:
            raise ValueError(f"{label} temporary name space is exhausted")

        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        opened = os.fstat(descriptor)
        created_identity = (opened.st_dev, opened.st_ino)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != 0
            or stat.S_IMODE(opened.st_mode) != _PRIVATE_FILE_MODE
        ):
            raise ValueError(f"{label} output is not a fresh private file")
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"{label} output made no write progress")
            view = view[written:]
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if _read_exact_private_json_bytes(descriptor, len(serialized), label=label) != serialized:
            raise ValueError(f"{label} changed before publication")

        try:
            os.link(
                temporary_leaf,
                leaf,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ValueError(f"{label} output appeared during publication") from exc
        linked = True
        os.unlink(temporary_leaf, dir_fd=parent_descriptor)
        temporary_leaf = None
        final_descriptor_metadata = os.fstat(descriptor)
        final_entry_metadata = os.stat(
            leaf,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            created_identity != (final_descriptor_metadata.st_dev, final_descriptor_metadata.st_ino)
            or _private_json_file_identity(final_descriptor_metadata)
            != _private_json_file_identity(final_entry_metadata)
            or not stat.S_ISREG(final_entry_metadata.st_mode)
            or final_entry_metadata.st_nlink != 1
            or final_entry_metadata.st_size != len(serialized)
            or stat.S_IMODE(final_entry_metadata.st_mode) != _PRIVATE_FILE_MODE
        ):
            raise ValueError(f"{label} changed during publication")
        os.fsync(parent_descriptor)
        _require_private_json_path_identity(
            absolute,
            label=label,
            parent_metadata=os.fstat(parent_descriptor),
            file_metadata=final_entry_metadata,
        )
        published = True
    except OSError as exc:
        raise ValueError(f"{label} could not be written safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            if temporary_leaf is not None:
                _unlink_private_json_if_identity(
                    parent_descriptor,
                    temporary_leaf,
                    created_identity,
                )
            if linked:
                _unlink_private_json_if_identity(
                    parent_descriptor,
                    leaf,
                    created_identity,
                )
        os.close(parent_descriptor)


def _load_private_json_artifact(path: Path, *, label: str) -> bytes:
    absolute, parent_descriptor, leaf = _open_private_json_parent(path, label=label)
    flags = (
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_CLOEXEC", 0)
        | _required_private_json_flag("O_NOFOLLOW", label=label)
    )
    descriptor = -1
    try:
        before = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor = os.open(leaf, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if _private_json_file_identity(before) != _private_json_file_identity(opened):
            raise ValueError(f"{label} changed before reading")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != _PRIVATE_FILE_MODE
            or before.st_size <= 0
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise ValueError(f"{label} must be a bounded private unshared regular file")
        raw = _read_exact_private_json_bytes(descriptor, before.st_size, label=label)
        after = os.fstat(descriptor)
        current = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
        identities = {
            _private_json_file_identity(before),
            _private_json_file_identity(opened),
            _private_json_file_identity(after),
            _private_json_file_identity(current),
        }
        if len(identities) != 1:
            raise ValueError(f"{label} changed during reading")
        _require_private_json_path_identity(
            absolute,
            label=label,
            parent_metadata=os.fstat(parent_descriptor),
            file_metadata=current,
        )
        return raw
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
