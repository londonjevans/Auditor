"""Conservative three-state evaluation for comparative audit-quality claims."""

from __future__ import annotations

import math
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.secrets import is_sensitive_workspace_name

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_COMPARISON_EVIDENCE_BYTES = 20_000_000
_Z_95 = 1.959963984540054


class SuperiorityClaimStatus(StrEnum):
    """A claim is absent, evaluated but unsupported, or fully demonstrated."""

    NOT_EVALUATED = "not_evaluated"
    NOT_DEMONSTRATED = "not_demonstrated"
    DEMONSTRATED = "demonstrated"


class SuperiorityPrecondition(StrEnum):
    BLINDED_REVIEW = "blinded_review"
    COMPARABLE_HUMAN_REVIEW = "comparable_human_review"
    INDEPENDENT_ADJUDICATION = "independent_adjudication"
    PRECISION_STATISTICALLY_SUPPORTED = "precision_statistically_supported"
    RECALL_STATISTICALLY_SUPPORTED = "recall_statistically_supported"


class ComparativeMetric(StrEnum):
    PRECISION = "precision"
    RECALL = "recall"


class ProportionSample(StrictModel):
    successes: int = Field(ge=0, le=10_000_000)
    trials: int = Field(ge=1, le=10_000_000)

    @model_validator(mode="after")
    def successes_do_not_exceed_trials(self) -> ProportionSample:
        if self.successes > self.trials:
            raise ValueError("comparison successes cannot exceed trials")
        return self


class ComparativeMetricEvidence(StrictModel):
    mmaudit: ProportionSample
    human: ProportionSample


class HumanComparisonEvidencePayload(StrictModel):
    """Operator-supplied evidence; booleans are evaluated, never treated as proof alone."""

    schema_version: Literal["1.0"] = "1.0"
    comparison_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    reports_generated_blind: bool = False
    ground_truth_withheld_from_humans: bool = False
    ground_truth_withheld_from_mmaudit: bool = False
    blinding_protocol_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    same_corpus: bool = False
    same_scope: bool = False
    same_time_budget: bool = False
    same_evidence_access: bool = False
    review_protocol_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    human_reviewer_count: int = Field(default=0, ge=0, le=100_000)
    adjudicators_independent: bool = False
    adjudicator_count: int = Field(default=0, ge=0, le=100_000)
    adjudication_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    precision: ComparativeMetricEvidence | None = None
    recall: ComparativeMetricEvidence | None = None


class HumanComparisonEvidence(HumanComparisonEvidencePayload):
    """Canonical self-hashed comparison evidence."""

    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_hash_matches(self) -> HumanComparisonEvidence:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("human-comparison evidence hash is inconsistent")
        return self


class StatisticalComparisonResult(StrictModel):
    metric: ComparativeMetric
    confidence_level: float = Field(default=0.95, ge=0.95, le=0.95)
    mmaudit_successes: int = Field(ge=0)
    mmaudit_trials: int = Field(ge=1)
    human_successes: int = Field(ge=0)
    human_trials: int = Field(ge=1)
    mmaudit_rate: float = Field(ge=0, le=1)
    human_rate: float = Field(ge=0, le=1)
    observed_difference: float = Field(ge=-1, le=1)
    difference_lower_bound: float = Field(ge=-1, le=1)
    statistically_supported: bool

    @model_validator(mode="after")
    def statistic_is_reproducible(self) -> StatisticalComparisonResult:
        expected = _statistical_result(
            self.metric,
            ComparativeMetricEvidence(
                mmaudit=ProportionSample(
                    successes=self.mmaudit_successes,
                    trials=self.mmaudit_trials,
                ),
                human=ProportionSample(
                    successes=self.human_successes,
                    trials=self.human_trials,
                ),
            ),
        )
        observed = self.model_dump(mode="json")
        expected_payload = expected.model_dump(mode="json")
        if observed != expected_payload:
            raise ValueError("superiority statistic is inconsistent")
        return self


class SuperiorityPreconditionResult(StrictModel):
    precondition: SuperiorityPrecondition
    passed: bool
    detail: str = Field(min_length=1, max_length=500)


class SuperiorityClaimAssessmentPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    status: SuperiorityClaimStatus
    comparison_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    corpus_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    benchmark_report_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    evidence_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    preconditions: list[SuperiorityPreconditionResult] = Field(
        min_length=5,
        max_length=5,
    )
    precision: StatisticalComparisonResult | None = None
    recall: StatisticalComparisonResult | None = None
    limitations: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def assessment_is_conservative_and_complete(
        self,
    ) -> SuperiorityClaimAssessmentPayload:
        names = [item.precondition.value for item in self.preconditions]
        expected_names = sorted(item.value for item in SuperiorityPrecondition)
        if names != expected_names:
            raise ValueError("superiority preconditions must be complete and sorted")
        if self.limitations != sorted(set(self.limitations)):
            raise ValueError("superiority limitations must be unique and sorted")
        has_evidence = (
            self.comparison_id is not None
            and self.corpus_sha256 is not None
            and self.benchmark_report_sha256 is not None
            and self.evidence_sha256 is not None
        )
        expected_status = (
            SuperiorityClaimStatus.NOT_EVALUATED
            if not has_evidence
            else (
                SuperiorityClaimStatus.DEMONSTRATED
                if all(item.passed for item in self.preconditions)
                else SuperiorityClaimStatus.NOT_DEMONSTRATED
            )
        )
        if self.status is not expected_status:
            raise ValueError("superiority claim status is inconsistent")
        if not has_evidence and (
            self.comparison_id is not None
            or self.corpus_sha256 is not None
            or self.benchmark_report_sha256 is not None
            or self.evidence_sha256 is not None
            or self.precision is not None
            or self.recall is not None
        ):
            raise ValueError("not-evaluated superiority claims cannot contain evidence")
        return self


class SuperiorityClaimAssessment(SuperiorityClaimAssessmentPayload):
    assessment_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def assessment_hash_matches(self) -> SuperiorityClaimAssessment:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"assessment_sha256"}))
        if self.assessment_sha256 != expected:
            raise ValueError("superiority assessment hash is inconsistent")
        return self


def seal_human_comparison_evidence(
    payload: HumanComparisonEvidencePayload,
) -> HumanComparisonEvidence:
    serialized = payload.model_dump(mode="json")
    return HumanComparisonEvidence.model_validate(
        {
            **serialized,
            "evidence_sha256": canonical_sha256(serialized),
        }
    )


def load_human_comparison_evidence(path: Path) -> HumanComparisonEvidence:
    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive human-comparison filename")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("human-comparison evidence must be a regular non-link file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_COMPARISON_EVIDENCE_BYTES:
        raise ValueError("human-comparison evidence must be a bounded unshared file")
    return HumanComparisonEvidence.model_validate_json(path.read_text(encoding="utf-8"))


def evaluate_superiority_claim(
    evidence: HumanComparisonEvidence | None = None,
) -> SuperiorityClaimAssessment:
    """Evaluate every necessary precondition; absence is never a negative result."""

    if evidence is None:
        payload = SuperiorityClaimAssessmentPayload(
            status=SuperiorityClaimStatus.NOT_EVALUATED,
            preconditions=[
                SuperiorityPreconditionResult(
                    precondition=precondition,
                    passed=False,
                    detail="no comparable human-review evidence was supplied",
                )
                for precondition in sorted(
                    SuperiorityPrecondition,
                    key=lambda item: item.value,
                )
            ],
            limitations=["No comparative human-review evidence was evaluated."],
        )
        return _seal_assessment(payload)

    precision = (
        _statistical_result(ComparativeMetric.PRECISION, evidence.precision)
        if evidence.precision is not None
        else None
    )
    recall = (
        _statistical_result(ComparativeMetric.RECALL, evidence.recall)
        if evidence.recall is not None
        else None
    )
    blinded = (
        evidence.reports_generated_blind
        and evidence.ground_truth_withheld_from_humans
        and evidence.ground_truth_withheld_from_mmaudit
        and evidence.blinding_protocol_sha256 is not None
    )
    comparable = (
        evidence.same_corpus
        and evidence.same_scope
        and evidence.same_time_budget
        and evidence.same_evidence_access
        and evidence.review_protocol_sha256 is not None
        and evidence.human_reviewer_count > 0
    )
    independently_adjudicated = (
        evidence.adjudicators_independent
        and evidence.adjudicator_count >= 2
        and evidence.adjudication_sha256 is not None
    )
    preconditions = [
        SuperiorityPreconditionResult(
            precondition=SuperiorityPrecondition.BLINDED_REVIEW,
            passed=blinded,
            detail=(
                "both reviews were ground-truth-blind under a hash-bound protocol"
                if blinded
                else "blinded review evidence is incomplete"
            ),
        ),
        SuperiorityPreconditionResult(
            precondition=SuperiorityPrecondition.COMPARABLE_HUMAN_REVIEW,
            passed=comparable,
            detail=(
                "human and mmaudit reviews used comparable corpus, scope, budget, and evidence"
                if comparable
                else "human-review comparability evidence is incomplete"
            ),
        ),
        SuperiorityPreconditionResult(
            precondition=SuperiorityPrecondition.INDEPENDENT_ADJUDICATION,
            passed=independently_adjudicated,
            detail=(
                "at least two independent adjudicators produced hash-bound evidence"
                if independently_adjudicated
                else "independent adjudication evidence is incomplete"
            ),
        ),
        SuperiorityPreconditionResult(
            precondition=SuperiorityPrecondition.PRECISION_STATISTICALLY_SUPPORTED,
            passed=precision is not None and precision.statistically_supported,
            detail=(
                "the 95% lower bound for precision difference is positive"
                if precision is not None and precision.statistically_supported
                else "precision superiority lacks positive 95% lower-bound support"
            ),
        ),
        SuperiorityPreconditionResult(
            precondition=SuperiorityPrecondition.RECALL_STATISTICALLY_SUPPORTED,
            passed=recall is not None and recall.statistically_supported,
            detail=(
                "the 95% lower bound for recall difference is positive"
                if recall is not None and recall.statistically_supported
                else "recall superiority lacks positive 95% lower-bound support"
            ),
        ),
    ]
    preconditions.sort(key=lambda item: item.precondition.value)
    limitations = sorted(item.detail for item in preconditions if not item.passed)
    status = (
        SuperiorityClaimStatus.DEMONSTRATED
        if all(item.passed for item in preconditions)
        else SuperiorityClaimStatus.NOT_DEMONSTRATED
    )
    return _seal_assessment(
        SuperiorityClaimAssessmentPayload(
            status=status,
            comparison_id=evidence.comparison_id,
            corpus_sha256=evidence.corpus_sha256,
            benchmark_report_sha256=evidence.benchmark_report_sha256,
            evidence_sha256=evidence.evidence_sha256,
            preconditions=preconditions,
            precision=precision,
            recall=recall,
            limitations=limitations,
        )
    )


def _statistical_result(
    metric: ComparativeMetric,
    evidence: ComparativeMetricEvidence,
) -> StatisticalComparisonResult:
    mmaudit_rate = evidence.mmaudit.successes / evidence.mmaudit.trials
    human_rate = evidence.human.successes / evidence.human.trials
    mmaudit_lower, _ = _wilson_interval(
        evidence.mmaudit.successes,
        evidence.mmaudit.trials,
    )
    _, human_upper = _wilson_interval(
        evidence.human.successes,
        evidence.human.trials,
    )
    observed_difference = round(mmaudit_rate - human_rate, 6)
    lower_bound = round(
        max(
            -1.0,
            min(
                1.0,
                observed_difference
                - math.sqrt((mmaudit_rate - mmaudit_lower) ** 2 + (human_upper - human_rate) ** 2),
            ),
        ),
        6,
    )
    return StatisticalComparisonResult.model_construct(
        metric=metric,
        confidence_level=0.95,
        mmaudit_successes=evidence.mmaudit.successes,
        mmaudit_trials=evidence.mmaudit.trials,
        human_successes=evidence.human.successes,
        human_trials=evidence.human.trials,
        mmaudit_rate=round(mmaudit_rate, 6),
        human_rate=round(human_rate, 6),
        observed_difference=observed_difference,
        difference_lower_bound=lower_bound,
        statistically_supported=lower_bound > 0,
    )


def _wilson_interval(successes: int, trials: int) -> tuple[float, float]:
    proportion = successes / trials
    z_squared = _Z_95**2
    denominator = 1 + z_squared / trials
    center = (proportion + z_squared / (2 * trials)) / denominator
    radius = (
        _Z_95
        * math.sqrt(proportion * (1 - proportion) / trials + z_squared / (4 * trials**2))
        / denominator
    )
    return max(0.0, center - radius), min(1.0, center + radius)


def _seal_assessment(
    payload: SuperiorityClaimAssessmentPayload,
) -> SuperiorityClaimAssessment:
    serialized = payload.model_dump(mode="json")
    return SuperiorityClaimAssessment.model_validate(
        {
            **serialized,
            "assessment_sha256": canonical_sha256(serialized),
        }
    )
