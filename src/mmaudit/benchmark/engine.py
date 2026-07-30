"""Evaluate mmaudit reports against an explicit, source-attributed corpus."""

from __future__ import annotations

import hashlib
import json
import math
import re
from enum import StrEnum
from pathlib import Path
from typing import Literal, overload

from pydantic import Field, field_validator, model_validator

from mmaudit.benchmark.claims import (
    HumanComparisonEvidence,
    SuperiorityClaimAssessment,
    SuperiorityClaimStatus,
    evaluate_superiority_claim,
)
from mmaudit.benchmark.mutations import (
    MutationScorecard,
    MutationScorecardEvidenceOrigin,
    MutationTestOutcome,
)
from mmaudit.constants import SEVERITY_ORDER
from mmaudit.models.schemas import (
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    EconomicTemplateExecutionCoverage,
    EvidenceStrength,
    ExecutionEvidenceKind,
    Finding,
    FindingStatus,
    Location,
    MaximumAssuranceStatus,
    ModelReviewEvidenceReference,
    ReproductionState,
    Severity,
    StrictModel,
    UsageRecord,
)
from mmaudit.models.usage import (
    _is_structurally_creditable_usage_record,
    is_creditable_usage_record,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path

_MAXIMUM_ASSURANCE_REQUIRED_COVERAGE_METRICS = (
    "audited_suite_contract_statement_coverage",
    "audited_suite_function_statement_coverage",
    "audited_suite_critical_function_assertion_coverage",
    "public_external_entry_points_reviewed",
    "external_calls_classified",
    "asset_flows_classified",
    "storage_variables_modelled",
    "invariants_executed",
    "economic_templates_executed",
    "economic_templates_with_typed_harness",
)
_BENCHMARK_REQUIRED_COVERAGE_METRICS = tuple(
    sorted(
        {
            *_MAXIMUM_ASSURANCE_REQUIRED_COVERAGE_METRICS,
            "compiler_contracts_indexed",
            "privileged_entry_points_reviewed",
            "high_value_paths_reviewed",
        }
    )
)
_RUNTIME_CREDITING_MUTATION_SCORECARD_ORIGINS: frozenset[MutationScorecardEvidenceOrigin] = (
    frozenset()
)
_BASE_REQUIRED_GATE_NAMES = (
    "known_critical_recall",
    "safe_control_false_confirmations",
    "exact_ground_truth_locations",
    "repository_metrics_unmasked",
    "evidence_caps",
    "coverage_present",
)
_MAXIMUM_ASSURANCE_REQUIRED_GATE_NAMES = (
    *_BASE_REQUIRED_GATE_NAMES,
    "maximum_assurance_complete",
    "maximum_assurance_repository_mutation_score",
    "maximum_assurance_semantic_coverage",
    "maximum_assurance_property_mutation_score",
    "maximum_assurance_real_model_calls",
    "maximum_assurance_substantive_model_review",
)
_BASE_CERTIFICATION_METRIC_NAMES = (
    "overall_recall",
    "critical_recall",
    "confirmed_precision",
    "false_confirmed_critical_rate",
    "false_confirmed_high_rate",
    "safe_near_miss_rejection_rate",
    "exact_location_accuracy",
    "reproduction_success_rate",
)
_MAXIMUM_ASSURANCE_CERTIFICATION_METRIC_NAMES = (
    *_BASE_CERTIFICATION_METRIC_NAMES,
    "high_recall",
    "medium_recall",
    "model_call_success_rate",
    "model_review_coverage",
    "critical_model_review_coverage",
    "contract_coverage",
    "entry_point_coverage",
    "privileged_function_coverage",
    "asset_moving_function_coverage",
    "external_call_coverage",
    "invariant_mutation_score",
    "economic_template_applicability_coverage",
    "economic_template_execution_coverage",
)
MAXIMUM_ASSURANCE_CORE_CLAUSES = (
    "maximum_assurance_profile",
    "full_pipeline_mode",
    "model_family_diversity",
    "specialist_agent_configuration",
    "specialist_role_coverage",
    "hardened_dynamic_isolation",
    "requirements_traceability",
    "full_protocol_scope",
    "solidity_project_detection",
    "compilation",
    "ast_backed_index",
    "full_semantic_graphs",
    "deterministic_scanners",
    "slither_execution",
    "foundry_unit_property_invariant_execution",
    "multi_agent_review",
    "critical_model_surface_review",
    "certified_model_ensemble",
    "invariant_discovery",
    "independent_invariant_review",
    "stateful_invariant_execution",
    "protocol_economic_simulation",
    "critical_high_reproduction",
    "independent_verifier",
    "independent_falsifier",
    "independent_test_synthesis",
    "evidence_capped_judge",
    "report_quality_review",
    "coverage_report",
    "formal_adapter_inventory",
    "formal_proof_engine",
    "isolated_replay_execution",
    "production_model_qualification",
    "real_provider_session_provenance",
    "qualified_model_selection_execution",
    "real_model_execution",
    "certified_execution_isolation",
    "benchmark_regression_gate",
)
MAXIMUM_ASSURANCE_MINIMUM_PROPERTY_KILL_SCORE = 1.0
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_BENCHMARK_CASE_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,79}$"
_BENCHMARK_FINDING_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,199}$"
_ASSURANCE_CLAUSE_PATTERN = r"^[a-z][a-z0-9_:-]{0,127}$"
_MAX_GROUND_TRUTH_SOURCE_BYTES = 10_000_000


class BenchmarkStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class BenchmarkMetricState(StrEnum):
    """Whether a benchmark metric was evaluable and met its declared threshold."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class BenchmarkMetricDirection(StrEnum):
    MINIMUM = "minimum"
    MAXIMUM = "maximum"
    INFORMATIONAL = "informational"


class BenchmarkReportInputStatus(StrEnum):
    """Typed disposition for one expected product report."""

    USABLE = "USABLE"
    MISSING = "MISSING"
    MALFORMED = "MALFORMED"
    STALE = "STALE"
    FAILED = "FAILED"


class BenchmarkBlindingProtocol(StrictModel):
    """Declared separation between audit generation and ground-truth disclosure."""

    reports_generated_before_ground_truth: Literal[True] = True
    ground_truth_disclosure: Literal["post_run_only"] = "post_run_only"


class BenchmarkRepository(StrictModel):
    """One synthetic repository whose source root is bound by the corpus."""

    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    source_root: str = Field(min_length=1, max_length=4_096)

    @field_validator("source_root")
    @classmethod
    def source_root_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized in {"", "."} or is_sensitive_workspace_path(normalized, is_dir=True):
            raise ValueError("benchmark source root must identify a repository directory")
        return normalized


class BenchmarkCase(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,79}$")
    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    variant: Literal["vulnerable", "safe", "ambiguous"]
    category: str = Field(min_length=1, max_length=300)
    path: str = Field(min_length=1, max_length=4_096)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    minimum_severity: Severity
    expected_cwe: list[str] = Field(default_factory=list, max_length=100)
    source_attribution: str = Field(min_length=1, max_length=500)
    training_exposure: Literal["unlikely", "possible", "known", "unknown"]

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized in {"", "."} or is_sensitive_workspace_path(normalized):
            raise ValueError("benchmark case path must identify a source file")
        return normalized

    @field_validator("expected_cwe")
    @classmethod
    def cwes_are_sorted_and_unique(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)) or any(
            not item.startswith("CWE-") or not item[4:].isdigit() for item in value
        ):
            raise ValueError("benchmark CWE identifiers must be unique and sorted")
        return value

    @model_validator(mode="after")
    def validates_location(self) -> BenchmarkCase:
        if self.end_line < self.start_line:
            raise ValueError("benchmark line range is reversed")
        return self


class BenchmarkManifestPayload(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    name: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=2_000)
    blinding: BenchmarkBlindingProtocol
    repositories: list[BenchmarkRepository] = Field(min_length=1, max_length=10_000)
    cases: list[BenchmarkCase] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def ground_truth_is_complete_and_deterministic(self) -> BenchmarkManifestPayload:
        repository_ids = [repository.repository_id for repository in self.repositories]
        if repository_ids != sorted(set(repository_ids)):
            raise ValueError("benchmark repositories must be unique and sorted")
        identifiers = [case.id for case in self.cases]
        if identifiers != sorted(set(identifiers)):
            raise ValueError("benchmark case IDs must be unique and sorted")
        if {case.repository_id for case in self.cases} != set(repository_ids):
            raise ValueError("benchmark cases must cover exactly the declared repositories")
        source_hashes: dict[tuple[str, str], str] = {}
        for case in self.cases:
            key = (case.repository_id, case.path)
            previous = source_hashes.setdefault(key, case.source_sha256)
            if previous != case.source_sha256:
                raise ValueError("one benchmark source file cannot have conflicting hashes")
        vulnerable_categories = {
            case.category for case in self.cases if case.variant == "vulnerable"
        }
        safe_categories = {case.category for case in self.cases if case.variant == "safe"}
        if not vulnerable_categories or not vulnerable_categories <= safe_categories:
            raise ValueError("every must-catch category requires a safe control")
        return self


class BenchmarkManifest(BenchmarkManifestPayload):
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def corpus_hash_matches(self) -> BenchmarkManifest:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"corpus_sha256"}))
        if self.corpus_sha256 != expected:
            raise ValueError("benchmark corpus hash is inconsistent")
        return self


class BenchmarkCaseResult(StrictModel):
    case_id: str = Field(pattern=_BENCHMARK_CASE_ID_PATTERN)
    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    variant: Literal["vulnerable", "safe", "ambiguous"]
    minimum_severity: Severity
    evaluated: bool
    detected: bool
    confirmed: bool
    reproduction_attempted: bool = False
    reproduced: bool = False
    exact_location: bool = False
    matched_finding_ids: list[str] = Field(default_factory=list, max_length=10_000)
    confirmed_finding_ids: list[str] = Field(default_factory=list, max_length=10_000)
    cwe_match: bool = False
    limitation: str | None = Field(default=None, min_length=1, max_length=2_000)

    @field_validator("matched_finding_ids", "confirmed_finding_ids")
    @classmethod
    def finding_ids_are_bounded(cls, value: list[str]) -> list[str]:
        if any(re.fullmatch(_BENCHMARK_FINDING_ID_PATTERN, item) is None for item in value):
            raise ValueError("benchmark matched finding IDs must be bounded identifiers")
        return value

    @model_validator(mode="after")
    def evidence_flags_are_consistent(self) -> BenchmarkCaseResult:
        if self.matched_finding_ids != sorted(set(self.matched_finding_ids)):
            raise ValueError("benchmark matched finding IDs must be unique and sorted")
        if self.confirmed_finding_ids != sorted(set(self.confirmed_finding_ids)):
            raise ValueError("benchmark confirmed finding IDs must be unique and sorted")
        if not self.evaluated and any(
            (
                self.detected,
                self.confirmed,
                self.reproduction_attempted,
                self.reproduced,
                self.exact_location,
                bool(self.matched_finding_ids),
                bool(self.confirmed_finding_ids),
            )
        ):
            raise ValueError("unevaluated benchmark cases cannot claim finding evidence")
        if (self.confirmed or self.reproduction_attempted or self.exact_location) and not (
            self.detected
        ):
            raise ValueError("benchmark evidence flags require an active detection")
        if self.reproduced and not self.reproduction_attempted:
            raise ValueError("benchmark reproduction success requires a real attempt")
        if not set(self.confirmed_finding_ids) <= set(self.matched_finding_ids):
            raise ValueError("confirmed benchmark findings must be a subset of active matches")
        if self.confirmed != bool(self.confirmed_finding_ids):
            raise ValueError("benchmark confirmed flag must match its confirmed finding IDs")
        return self


class BenchmarkGroundTruthBinding(StrictModel):
    """Observed local source evidence for one corpus-bound fixture file."""

    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    path: str = Field(min_length=1, max_length=4_096)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=0, le=_MAX_GROUND_TRUTH_SOURCE_BYTES)
    line_count: int = Field(ge=0)
    case_ids: list[str] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def identity_is_deterministic(self) -> BenchmarkGroundTruthBinding:
        if self.case_ids != sorted(set(self.case_ids)):
            raise ValueError("ground-truth binding case IDs must be unique and sorted")
        return self


class BenchmarkGate(StrictModel):
    name: Literal[
        "known_critical_recall",
        "safe_control_false_confirmations",
        "exact_ground_truth_locations",
        "repository_metrics_unmasked",
        "evidence_caps",
        "coverage_present",
        "maximum_assurance_complete",
        "maximum_assurance_repository_mutation_score",
        "maximum_assurance_semantic_coverage",
        "maximum_assurance_property_mutation_score",
        "maximum_assurance_real_model_calls",
        "maximum_assurance_substantive_model_review",
    ]
    state: BenchmarkMetricState
    passed: bool
    detail: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def pass_flag_matches_state(self) -> BenchmarkGate:
        if self.passed != (self.state is BenchmarkMetricState.PASS):
            raise ValueError("benchmark gate pass flag must match its state")
        return self


class BenchmarkRateMetric(StrictModel):
    """One rate with its complete expected denominator and evaluation state."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    evaluated: int = Field(ge=0)
    value: float | None = Field(default=None, ge=0, le=1)
    state: BenchmarkMetricState
    threshold: float | None = Field(default=None, ge=0, le=1)
    direction: BenchmarkMetricDirection
    detail: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def state_and_ratio_are_consistent(self) -> BenchmarkRateMetric:
        if self.numerator > self.evaluated or self.evaluated > self.denominator:
            raise ValueError("benchmark metric must satisfy numerator <= evaluated <= denominator")
        complete = self.denominator > 0 and self.evaluated == self.denominator
        expected_value = round(self.numerator / self.denominator, 6) if complete else None
        if self.value != expected_value:
            raise ValueError("benchmark metric value must use its complete expected denominator")
        if self.state is BenchmarkMetricState.NOT_EVALUABLE:
            if self.evaluated != 0 or self.value is not None:
                raise ValueError("not-evaluable benchmark metrics cannot claim observations")
            return self
        if self.state is BenchmarkMetricState.INCONCLUSIVE:
            if self.evaluated == 0 or self.evaluated >= self.denominator or self.value is not None:
                raise ValueError("inconclusive benchmark metrics require partial observations")
            return self
        if self.state is BenchmarkMetricState.NOT_APPLICABLE:
            if (
                not complete
                or self.direction is not BenchmarkMetricDirection.INFORMATIONAL
                or self.threshold is not None
            ):
                raise ValueError(
                    "not-applicable benchmark thresholds require a complete informational metric"
                )
            return self
        if not complete or self.threshold is None:
            raise ValueError("passing or failing benchmark metrics require a complete threshold")
        if self.direction is BenchmarkMetricDirection.INFORMATIONAL:
            raise ValueError("informational benchmark metrics cannot pass or fail")
        assert self.value is not None
        assert self.threshold is not None
        expected_pass = (
            self.value >= self.threshold
            if self.direction is BenchmarkMetricDirection.MINIMUM
            else self.value <= self.threshold
        )
        if (self.state is BenchmarkMetricState.PASS) != expected_pass:
            raise ValueError("benchmark metric state does not match its threshold")
        return self


class BenchmarkMetrics(StrictModel):
    """Fixed quality metric inventory; unavailable evidence cannot disappear."""

    overall_recall: BenchmarkRateMetric
    critical_recall: BenchmarkRateMetric
    high_recall: BenchmarkRateMetric
    medium_recall: BenchmarkRateMetric
    confirmed_precision: BenchmarkRateMetric
    all_finding_precision: BenchmarkRateMetric
    false_confirmed_critical_rate: BenchmarkRateMetric
    false_confirmed_high_rate: BenchmarkRateMetric
    safe_near_miss_rejection_rate: BenchmarkRateMetric
    exact_location_accuracy: BenchmarkRateMetric
    attack_path_reachability_accuracy: BenchmarkRateMetric
    reproduction_success_rate: BenchmarkRateMetric
    symbolic_counterexample_success_rate: BenchmarkRateMetric
    formal_property_mutation_score: BenchmarkRateMetric
    invariant_mutation_score: BenchmarkRateMetric
    contract_coverage: BenchmarkRateMetric
    entry_point_coverage: BenchmarkRateMetric
    privileged_function_coverage: BenchmarkRateMetric
    asset_moving_function_coverage: BenchmarkRateMetric
    external_call_coverage: BenchmarkRateMetric
    model_call_success_rate: BenchmarkRateMetric
    model_review_coverage: BenchmarkRateMetric
    critical_model_review_coverage: BenchmarkRateMetric
    economic_template_applicability_coverage: BenchmarkRateMetric
    economic_template_execution_coverage: BenchmarkRateMetric

    @model_validator(mode="after")
    def threshold_policy_is_host_controlled(self) -> BenchmarkMetrics:
        minimum_one = (
            "overall_recall",
            "critical_recall",
            "high_recall",
            "medium_recall",
            "confirmed_precision",
            "safe_near_miss_rejection_rate",
            "exact_location_accuracy",
            "reproduction_success_rate",
            "invariant_mutation_score",
            "contract_coverage",
            "entry_point_coverage",
            "privileged_function_coverage",
            "asset_moving_function_coverage",
            "external_call_coverage",
            "model_call_success_rate",
            "model_review_coverage",
            "critical_model_review_coverage",
            "economic_template_applicability_coverage",
            "economic_template_execution_coverage",
        )
        maximum_zero = (
            "false_confirmed_critical_rate",
            "false_confirmed_high_rate",
        )
        informational = (
            "all_finding_precision",
            "attack_path_reachability_accuracy",
            "symbolic_counterexample_success_rate",
            "formal_property_mutation_score",
        )
        expected: dict[
            str,
            tuple[BenchmarkMetricDirection, float | None],
        ] = {
            **{name: (BenchmarkMetricDirection.MINIMUM, 1.0) for name in minimum_one},
            **{name: (BenchmarkMetricDirection.MAXIMUM, 0.0) for name in maximum_zero},
            **{name: (BenchmarkMetricDirection.INFORMATIONAL, None) for name in informational},
        }
        if set(expected) != set(type(self).model_fields):
            raise ValueError("benchmark metric threshold policy is incomplete")
        for name, policy in expected.items():
            metric = getattr(self, name)
            if (metric.direction, metric.threshold) != policy:
                raise ValueError(f"benchmark metric threshold policy cannot be overridden: {name}")
        return self


class BenchmarkResourceMetric(StrictModel):
    """Observed resource use, intentionally separate from quality gates."""

    observations: int = Field(ge=0)
    total: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    average: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    worst: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    state: BenchmarkMetricState
    detail: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def observations_are_consistent(self) -> BenchmarkResourceMetric:
        values = (self.total, self.average, self.worst)
        if self.observations == 0:
            if any(value is not None for value in values):
                raise ValueError("unobserved resources cannot claim numeric values")
            if self.state is not BenchmarkMetricState.NOT_EVALUABLE:
                raise ValueError("unobserved resources must be not evaluable")
            return self
        if any(value is None for value in values):
            raise ValueError("observed resources require total, average, and worst values")
        assert self.total is not None
        assert self.average is not None
        assert self.worst is not None
        if round(self.total / self.observations, 6) != self.average:
            raise ValueError("resource average does not match its observations")
        if self.worst > self.total:
            raise ValueError("resource worst observation cannot exceed its total")
        if self.state is not BenchmarkMetricState.NOT_APPLICABLE:
            raise ValueError("resource observations are not an implicit quality pass")
        return self


class BenchmarkResourceMetrics(StrictModel):
    cost_usd: BenchmarkResourceMetric
    runtime_seconds: BenchmarkResourceMetric


class BenchmarkReportInput(StrictModel):
    """One expected report load attempt, including failed and stale analyses."""

    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    status: BenchmarkReportInputStatus
    attempted: bool
    parsed: bool
    usable: bool
    maximum_assurance_status: MaximumAssuranceStatus | None = None
    maximum_assurance_required_clauses: list[str] = Field(
        default_factory=list,
        max_length=1_000,
    )
    detail: str = Field(min_length=1, max_length=1_000)

    @field_validator("maximum_assurance_required_clauses")
    @classmethod
    def assurance_clauses_are_canonical(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)) or any(
            re.fullmatch(_ASSURANCE_CLAUSE_PATTERN, item) is None for item in value
        ):
            raise ValueError("maximum-assurance clauses must be bounded, unique, and sorted")
        return value

    @model_validator(mode="after")
    def disposition_flags_are_consistent(self) -> BenchmarkReportInput:
        expected = {
            BenchmarkReportInputStatus.USABLE: (True, True, True),
            BenchmarkReportInputStatus.MISSING: (False, False, False),
            BenchmarkReportInputStatus.MALFORMED: (True, False, False),
            BenchmarkReportInputStatus.STALE: (True, True, False),
            BenchmarkReportInputStatus.FAILED: (True, True, False),
        }[self.status]
        if (self.attempted, self.parsed, self.usable) != expected:
            raise ValueError("benchmark report input flags do not match its disposition")
        return self


class BenchmarkCoverageMetric(StrictModel):
    """Aggregate an existing coverage numerator/denominator across reports."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    evaluated: int = Field(ge=0)
    percentage: float | None = Field(default=None, ge=0, le=100)
    state: BenchmarkMetricState
    detail: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def ratio_is_consistent(self) -> BenchmarkCoverageMetric:
        complete = self.denominator > 0 and self.evaluated == self.denominator
        expected = round((self.numerator / self.denominator) * 100, 4) if complete else None
        if (
            self.numerator > self.evaluated
            or self.evaluated > self.denominator
            or self.percentage != expected
        ):
            raise ValueError("benchmark coverage ratio is inconsistent")
        expected_state = (
            BenchmarkMetricState.NOT_EVALUABLE
            if self.evaluated == 0
            else (
                BenchmarkMetricState.INCONCLUSIVE
                if not complete
                else (
                    BenchmarkMetricState.PASS
                    if self.numerator == self.denominator
                    else BenchmarkMetricState.FAIL
                )
            )
        )
        if self.state is not expected_state:
            raise ValueError("benchmark coverage state is inconsistent")
        return self


class BenchmarkRepositoryMetrics(StrictModel):
    """Explicit metrics for one repository; global averages cannot replace these."""

    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    report_status: BenchmarkReportInputStatus
    report_attempted: bool
    report_parsed: bool
    report_loaded: bool
    cases_evaluated: int = Field(ge=0)
    vulnerable_cases: int = Field(ge=0)
    vulnerable_cases_detected: int = Field(ge=0)
    recall: float | None = Field(default=None, ge=0, le=1)
    critical_cases: int = Field(ge=0)
    critical_cases_detected: int = Field(ge=0)
    critical_recall: float | None = Field(default=None, ge=0, le=1)
    safe_cases: int = Field(ge=0)
    ambiguous_cases: int = Field(ge=0)
    safe_false_confirmations: int = Field(ge=0)
    safe_high_critical_confirmations: int = Field(ge=0)
    safe_false_confirmation_rate: float | None = Field(default=None, ge=0, le=1)
    location_cases: int = Field(ge=0)
    exact_locations: int = Field(ge=0)
    location_accuracy: float | None = Field(default=None, ge=0, le=1)
    vulnerable_cases_reproduced: int = Field(ge=0)
    reproduction_success_rate: float | None = Field(default=None, ge=0, le=1)
    mutation_property_ids: list[str] = Field(default_factory=list, max_length=10_000)
    mutation_kill_score: float | None = Field(default=None, ge=0, le=1)
    mutation_gate_passed: bool | None = None
    evidence_cap_bypasses: int = Field(ge=0)
    model_only_findings_kept_below_confirmed: int = Field(ge=0)
    coverage_metrics: dict[str, BenchmarkCoverageMetric] = Field(
        default_factory=dict,
        max_length=1_000,
    )
    cost_usd: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    total_tokens: int | None = Field(default=None, ge=0)
    runtime_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    time_to_first_valid_finding_seconds: float | None = Field(
        default=None,
        ge=0,
        allow_inf_nan=False,
    )

    @model_validator(mode="after")
    def metrics_are_arithmetically_consistent(self) -> BenchmarkRepositoryMetrics:
        ratios = (
            (
                self.vulnerable_cases_detected,
                self.vulnerable_cases,
                self.recall,
                "recall",
            ),
            (
                self.critical_cases_detected,
                self.critical_cases,
                self.critical_recall,
                "critical recall",
            ),
            (
                self.safe_false_confirmations,
                self.safe_cases,
                self.safe_false_confirmation_rate,
                "safe false-confirmation rate",
            ),
            (
                self.exact_locations,
                self.location_cases,
                self.location_accuracy,
                "location accuracy",
            ),
            (
                self.vulnerable_cases_reproduced,
                self.vulnerable_cases,
                self.reproduction_success_rate,
                "reproduction rate",
            ),
        )
        for numerator, denominator, observed, name in ratios:
            expected = (
                round(numerator / denominator, 6) if denominator and self.report_loaded else None
            )
            if numerator > denominator or observed != expected:
                raise ValueError(f"repository benchmark {name} is inconsistent")
        expected_input_flags = {
            BenchmarkReportInputStatus.USABLE: (True, True, True),
            BenchmarkReportInputStatus.MISSING: (False, False, False),
            BenchmarkReportInputStatus.MALFORMED: (True, False, False),
            BenchmarkReportInputStatus.STALE: (True, True, False),
            BenchmarkReportInputStatus.FAILED: (True, True, False),
        }[self.report_status]
        if (
            self.report_attempted,
            self.report_parsed,
            self.report_loaded,
        ) != expected_input_flags:
            raise ValueError("repository report flags do not match its input status")
        expected_cases_evaluated = (
            self.vulnerable_cases + self.safe_cases + self.ambiguous_cases
            if self.report_loaded
            else 0
        )
        if self.cases_evaluated != expected_cases_evaluated:
            raise ValueError("repository evaluated-case count is inconsistent")
        if not self.report_loaded and any(
            (
                self.vulnerable_cases_detected,
                self.critical_cases_detected,
                self.safe_false_confirmations,
                self.exact_locations,
                self.vulnerable_cases_reproduced,
            )
        ):
            raise ValueError("unusable repository reports cannot receive benchmark credit")
        if self.location_cases != self.vulnerable_cases:
            raise ValueError("repository location denominator must cover every vulnerable case")
        if self.safe_high_critical_confirmations > self.safe_false_confirmations:
            raise ValueError(
                "high/critical safe confirmations cannot exceed all safe confirmations"
            )
        if not self.report_loaded and self.coverage_metrics:
            raise ValueError("unusable repository reports cannot claim typed coverage")
        if self.mutation_property_ids != sorted(set(self.mutation_property_ids)):
            raise ValueError("repository mutation property IDs must be unique and sorted")
        has_mutation_evidence = bool(self.mutation_property_ids)
        if has_mutation_evidence != (self.mutation_gate_passed is not None):
            raise ValueError("repository mutation metrics require complete property evidence")
        if not has_mutation_evidence and self.mutation_kill_score is not None:
            raise ValueError("repository mutation score requires attributed properties")
        if self.report_parsed != (self.cost_usd is not None and self.total_tokens is not None):
            raise ValueError("repository cost and token metrics must match parsed report evidence")
        if not self.report_parsed and (
            self.runtime_seconds is not None or self.time_to_first_valid_finding_seconds is not None
        ):
            raise ValueError("unparsed repository reports cannot claim runtime evidence")
        return self


class BenchmarkReport(StrictModel):
    schema_version: Literal["3.0"]
    corpus_name: str = Field(min_length=1, max_length=500)
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    blinding: BenchmarkBlindingProtocol
    profile: AuditProfile
    status: BenchmarkStatus
    reports_expected: int = Field(ge=1, le=10_000)
    reports_attempted: int = Field(ge=0, le=10_000)
    reports_parsed: int = Field(ge=0, le=10_000)
    reports_loaded: int = Field(ge=0, le=10_000)
    report_inputs: list[BenchmarkReportInput] = Field(min_length=1, max_length=10_000)
    vulnerable_cases: int = Field(ge=0, le=10_000)
    vulnerable_cases_detected: int = Field(ge=0, le=10_000)
    vulnerable_cases_reproduced: int = Field(ge=0, le=10_000)
    critical_cases: int = Field(ge=0, le=10_000)
    critical_cases_detected: int = Field(ge=0, le=10_000)
    safe_cases: int = Field(ge=0, le=10_000)
    ambiguous_cases: int = Field(ge=0, le=10_000)
    safe_high_critical_confirmations: int = Field(ge=0, le=10_000)
    evidence_cap_bypasses: int = Field(ge=0, le=10_000)
    reports_missing_coverage: int = Field(ge=0, le=10_000)
    model_only_findings_kept_below_confirmed: int = Field(ge=0, le=10_000)
    active_findings: int = Field(ge=0, le=1_000_000)
    active_findings_matching_vulnerable_cases: int = Field(ge=0, le=1_000_000)
    confirmed_findings: int = Field(ge=0, le=1_000_000)
    confirmed_findings_matching_vulnerable_cases: int = Field(ge=0, le=1_000_000)
    recall: float | None = Field(default=None, ge=0, le=1)
    recall_by_severity: dict[str, float | None] = Field(max_length=10)
    critical_recall: float | None = Field(default=None, ge=0, le=1)
    precision: float | None = Field(default=None, ge=0, le=1)
    false_positive_rate: float | None = Field(default=None, ge=0, le=1)
    safe_false_confirmation_rate: float | None = Field(default=None, ge=0, le=1)
    reproduction_success_rate: float | None = Field(default=None, ge=0, le=1)
    location_cases: int = Field(ge=0, le=10_000)
    exact_locations: int = Field(ge=0, le=10_000)
    location_accuracy: float | None = Field(default=None, ge=0, le=1)
    total_cost_usd: float = Field(ge=0, allow_inf_nan=False)
    total_tokens: int = Field(ge=0)
    total_runtime_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    time_to_first_valid_finding_seconds: float | None = Field(
        default=None,
        ge=0,
        allow_inf_nan=False,
    )
    resource_metrics: BenchmarkResourceMetrics
    metrics: BenchmarkMetrics
    unique_finding_contribution_by_role: dict[str, int] = Field(
        default_factory=dict,
        max_length=1_000,
    )
    unique_finding_contribution_by_family: dict[str, int] = Field(
        default_factory=dict,
        max_length=1_000,
    )
    mutation_scorecard: MutationScorecard | None = None
    superiority_claim: SuperiorityClaimAssessment = Field(
        default_factory=evaluate_superiority_claim
    )
    coverage_metrics: dict[str, BenchmarkCoverageMetric] = Field(
        default_factory=dict,
        max_length=1_000,
    )
    repository_metrics: list[BenchmarkRepositoryMetrics] = Field(
        min_length=1,
        max_length=10_000,
    )
    case_results: list[BenchmarkCaseResult] = Field(min_length=1, max_length=10_000)
    gates: list[BenchmarkGate] = Field(min_length=6, max_length=12)
    limitations: list[str] = Field(default_factory=list, max_length=10_000)

    @field_validator(
        "unique_finding_contribution_by_role",
        "unique_finding_contribution_by_family",
    )
    @classmethod
    def contribution_counts_are_bounded(cls, value: dict[str, int]) -> dict[str, int]:
        if any(
            re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,199}$", name) is None
            or isinstance(count, bool)
            or count < 0
            or count > 1_000_000
            for name, count in value.items()
        ):
            raise ValueError("benchmark contribution counts must be bounded and non-negative")
        return value

    @field_validator("limitations")
    @classmethod
    def limitations_are_bounded(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)) or any(
            not item or len(item) > 2_000 or any(ord(character) == 0 for character in item)
            for item in value
        ):
            raise ValueError("benchmark limitations must be unique, sorted, and bounded")
        return value

    @model_validator(mode="after")
    def gates_are_unique_and_consistent(self) -> BenchmarkReport:
        gate_names = [gate.name for gate in self.gates]
        expected_gate_names = (
            _MAXIMUM_ASSURANCE_REQUIRED_GATE_NAMES
            if self.profile is AuditProfile.MAXIMUM_ASSURANCE
            else _BASE_REQUIRED_GATE_NAMES
        )
        if tuple(gate_names) != expected_gate_names:
            raise ValueError("benchmark gate portfolio is incomplete or out of canonical order")
        input_ids = [item.repository_id for item in self.report_inputs]
        repository_ids = [item.repository_id for item in self.repository_metrics]
        if (
            input_ids != sorted(set(input_ids))
            or repository_ids != input_ids
            or len(input_ids) != self.reports_expected
        ):
            raise ValueError("benchmark report inputs and repository metrics must reconcile")
        case_ids = [item.case_id for item in self.case_results]
        if case_ids != sorted(set(case_ids)):
            raise ValueError("benchmark case results must be unique and sorted")
        input_counts = {
            "reports_attempted": sum(item.attempted for item in self.report_inputs),
            "reports_parsed": sum(item.parsed for item in self.report_inputs),
            "reports_loaded": sum(item.usable for item in self.report_inputs),
        }
        if any(getattr(self, name) != count for name, count in input_counts.items()):
            raise ValueError("benchmark report input counts are inconsistent")
        core_clauses = set(MAXIMUM_ASSURANCE_CORE_CLAUSES)
        for report_input in self.report_inputs:
            clauses = set(report_input.maximum_assurance_required_clauses)
            if self.profile is not AuditProfile.MAXIMUM_ASSURANCE:
                if report_input.maximum_assurance_status is not None or clauses:
                    raise ValueError(
                        "non-maximum benchmark inputs cannot claim maximum-assurance evidence"
                    )
                continue
            if report_input.usable and (
                report_input.maximum_assurance_status is not MaximumAssuranceStatus.COMPLETE
                or not core_clauses <= clauses
            ):
                raise ValueError(
                    "usable maximum-assurance report inputs require the complete core clause portfolio"
                )
        if any(
            (
                repository.report_status,
                repository.report_attempted,
                repository.report_parsed,
                repository.report_loaded,
            )
            != (
                report_input.status,
                report_input.attempted,
                report_input.parsed,
                report_input.usable,
            )
            for repository, report_input in zip(
                self.repository_metrics,
                self.report_inputs,
                strict=True,
            )
        ):
            raise ValueError("benchmark repository metrics disagree with report inputs")
        case_variant_counts = {
            "vulnerable_cases": sum(item.variant == "vulnerable" for item in self.case_results),
            "safe_cases": sum(item.variant == "safe" for item in self.case_results),
            "ambiguous_cases": sum(item.variant == "ambiguous" for item in self.case_results),
        }
        if any(getattr(self, name) != count for name, count in case_variant_counts.items()):
            raise ValueError("benchmark case inventory does not match aggregate counts")
        for repository in self.repository_metrics:
            repository_results = [
                result
                for result in self.case_results
                if result.repository_id == repository.repository_id
            ]
            repository_vulnerable = [
                result for result in repository_results if result.variant == "vulnerable"
            ]
            repository_safe = [result for result in repository_results if result.variant == "safe"]
            repository_ambiguous = [
                result for result in repository_results if result.variant == "ambiguous"
            ]
            expected_repository_counts = (
                sum(result.evaluated for result in repository_results),
                len(repository_vulnerable),
                sum(result.detected for result in repository_vulnerable),
                sum(
                    result.minimum_severity is Severity.CRITICAL for result in repository_vulnerable
                ),
                sum(
                    result.detected and result.minimum_severity is Severity.CRITICAL
                    for result in repository_vulnerable
                ),
                len(repository_safe),
                len(repository_ambiguous),
                sum(result.confirmed for result in repository_safe),
                sum(
                    result.confirmed
                    for result in repository_safe
                    if result.minimum_severity in {Severity.CRITICAL, Severity.HIGH}
                ),
                sum(result.exact_location for result in repository_vulnerable),
                sum(result.reproduced for result in repository_vulnerable),
            )
            observed_repository_counts = (
                repository.cases_evaluated,
                repository.vulnerable_cases,
                repository.vulnerable_cases_detected,
                repository.critical_cases,
                repository.critical_cases_detected,
                repository.safe_cases,
                repository.ambiguous_cases,
                repository.safe_false_confirmations,
                repository.safe_high_critical_confirmations,
                repository.exact_locations,
                repository.vulnerable_cases_reproduced,
            )
            if observed_repository_counts != expected_repository_counts:
                raise ValueError("benchmark repository metrics do not match their case results")
        count_fields = {
            "vulnerable_cases": sum(item.vulnerable_cases for item in self.repository_metrics),
            "vulnerable_cases_detected": sum(
                item.vulnerable_cases_detected for item in self.repository_metrics
            ),
            "vulnerable_cases_reproduced": sum(
                item.vulnerable_cases_reproduced for item in self.repository_metrics
            ),
            "critical_cases": sum(item.critical_cases for item in self.repository_metrics),
            "critical_cases_detected": sum(
                item.critical_cases_detected for item in self.repository_metrics
            ),
            "safe_cases": sum(item.safe_cases for item in self.repository_metrics),
            "ambiguous_cases": sum(item.ambiguous_cases for item in self.repository_metrics),
            "safe_high_critical_confirmations": sum(
                item.safe_high_critical_confirmations for item in self.repository_metrics
            ),
            "evidence_cap_bypasses": sum(
                item.evidence_cap_bypasses for item in self.repository_metrics
            ),
            "model_only_findings_kept_below_confirmed": sum(
                item.model_only_findings_kept_below_confirmed for item in self.repository_metrics
            ),
            "reports_missing_coverage": sum(
                not item.report_loaded or not item.coverage_metrics
                for item in self.repository_metrics
            ),
            "location_cases": sum(item.location_cases for item in self.repository_metrics),
            "exact_locations": sum(item.exact_locations for item in self.repository_metrics),
        }
        if any(getattr(self, name) != expected for name, expected in count_fields.items()):
            raise ValueError("benchmark aggregate counts do not match repository metrics")
        expected_coverage = _aggregate_repository_coverage(self.repository_metrics)
        if set(self.coverage_metrics) != set(expected_coverage) or any(
            _coverage_projection(self.coverage_metrics[name])
            != _coverage_projection(expected_coverage[name])
            for name in expected_coverage
        ):
            raise ValueError("benchmark aggregate coverage does not match repository evidence")

        active_true_ids = {
            finding_id
            for result in self.case_results
            if result.variant == "vulnerable" and result.detected
            for finding_id in result.matched_finding_ids
        }
        confirmed_true_ids = {
            finding_id
            for result in self.case_results
            if result.variant == "vulnerable" and result.confirmed
            for finding_id in result.confirmed_finding_ids
        }
        finding_counts = (
            self.active_findings,
            self.active_findings_matching_vulnerable_cases,
            self.confirmed_findings,
            self.confirmed_findings_matching_vulnerable_cases,
        )
        expected_finding_counts = (
            self.metrics.all_finding_precision.denominator,
            len(active_true_ids),
            self.metrics.confirmed_precision.denominator,
            len(confirmed_true_ids),
        )
        if finding_counts != expected_finding_counts:
            raise ValueError("benchmark precision inventory does not match case evidence")
        if (
            self.metrics.all_finding_precision.numerator
            != self.active_findings_matching_vulnerable_cases
            or self.metrics.confirmed_precision.numerator
            != self.confirmed_findings_matching_vulnerable_cases
            or self.confirmed_findings > self.active_findings
            or self.confirmed_findings_matching_vulnerable_cases
            > self.active_findings_matching_vulnerable_cases
        ):
            raise ValueError("benchmark precision metrics do not match finding counts")
        ratio_fields: dict[str, float | None] = {
            "recall": self.metrics.overall_recall.value,
            "critical_recall": self.metrics.critical_recall.value,
            "precision": self.metrics.confirmed_precision.value,
            "safe_false_confirmation_rate": (
                _combined_false_confirmation_value(
                    self.metrics.false_confirmed_critical_rate,
                    self.metrics.false_confirmed_high_rate,
                )
            ),
            "reproduction_success_rate": self.metrics.reproduction_success_rate.value,
            "location_accuracy": self.metrics.exact_location_accuracy.value,
        }
        safe_rejection = self.metrics.safe_near_miss_rejection_rate.value
        expected_false_positive_rate = (
            round(1 - safe_rejection, 6) if safe_rejection is not None else None
        )
        ratio_fields["false_positive_rate"] = expected_false_positive_rate
        if any(getattr(self, name) != expected for name, expected in ratio_fields.items()):
            raise ValueError("benchmark aggregate rates do not match typed metrics")
        severity_metrics = {
            Severity.CRITICAL.value: self.metrics.critical_recall.value,
            Severity.HIGH.value: self.metrics.high_recall.value,
            Severity.MEDIUM.value: self.metrics.medium_recall.value,
        }
        if self.recall_by_severity != severity_metrics:
            raise ValueError("benchmark severity recall does not match typed metrics")
        case_metric_projections = {
            "overall_recall": (
                sum(
                    result.detected
                    for result in self.case_results
                    if result.variant == "vulnerable"
                ),
                self.vulnerable_cases,
                sum(
                    result.evaluated
                    for result in self.case_results
                    if result.variant == "vulnerable"
                ),
            ),
            "safe_near_miss_rejection_rate": (
                sum(
                    result.evaluated and not result.detected
                    for result in self.case_results
                    if result.variant == "safe"
                ),
                self.safe_cases,
                sum(result.evaluated for result in self.case_results if result.variant == "safe"),
            ),
            "exact_location_accuracy": (
                self.exact_locations,
                self.vulnerable_cases,
                sum(
                    result.evaluated
                    for result in self.case_results
                    if result.variant == "vulnerable"
                ),
            ),
            "reproduction_success_rate": (
                self.vulnerable_cases_reproduced,
                self.vulnerable_cases,
                sum(
                    result.reproduction_attempted
                    for result in self.case_results
                    if result.variant == "vulnerable"
                ),
            ),
        }
        for severity, metric_name in (
            (Severity.CRITICAL, "critical_recall"),
            (Severity.HIGH, "high_recall"),
            (Severity.MEDIUM, "medium_recall"),
        ):
            severity_results = [
                result
                for result in self.case_results
                if result.variant == "vulnerable" and result.minimum_severity is severity
            ]
            case_metric_projections[metric_name] = (
                sum(result.detected for result in severity_results),
                len(severity_results),
                sum(result.evaluated for result in severity_results),
            )
        for severity, metric_name in (
            (Severity.CRITICAL, "false_confirmed_critical_rate"),
            (Severity.HIGH, "false_confirmed_high_rate"),
        ):
            severity_results = [
                result
                for result in self.case_results
                if result.variant == "safe" and result.minimum_severity is severity
            ]
            case_metric_projections[metric_name] = (
                sum(result.confirmed for result in severity_results),
                len(severity_results),
                sum(result.evaluated for result in severity_results),
            )
        if any(
            (
                getattr(self.metrics, name).numerator,
                getattr(self.metrics, name).denominator,
                getattr(self.metrics, name).evaluated,
            )
            != expected
            for name, expected in case_metric_projections.items()
        ):
            raise ValueError("benchmark case-derived metrics do not match case results")
        repository_cost = sum(item.cost_usd or 0 for item in self.repository_metrics)
        repository_tokens = sum(item.total_tokens or 0 for item in self.repository_metrics)
        repository_runtime = [
            item.runtime_seconds
            for item in self.repository_metrics
            if item.runtime_seconds is not None
        ]
        if self.total_cost_usd != repository_cost or self.total_tokens != repository_tokens:
            raise ValueError("benchmark aggregate cost or tokens do not match repositories")
        expected_cost_resource = _resource_metric(
            [item.cost_usd for item in self.repository_metrics if item.cost_usd is not None],
            "parsed report cost observations",
        )
        if _resource_projection(self.resource_metrics.cost_usd) != _resource_projection(
            expected_cost_resource
        ):
            raise ValueError("benchmark cost resource metric does not match repositories")
        expected_runtime = sum(repository_runtime) if repository_runtime else None
        if self.total_runtime_seconds != expected_runtime:
            raise ValueError("benchmark aggregate runtime does not match repositories")
        expected_runtime_resource = _resource_metric(
            repository_runtime,
            "parsed report runtime observations",
        )
        if _resource_projection(self.resource_metrics.runtime_seconds) != _resource_projection(
            expected_runtime_resource
        ):
            raise ValueError("benchmark runtime resource metric does not match repositories")
        repository_first_findings = [
            item.time_to_first_valid_finding_seconds
            for item in self.repository_metrics
            if item.time_to_first_valid_finding_seconds is not None
        ]
        expected_first_finding = (
            min(repository_first_findings) if repository_first_findings else None
        )
        if self.time_to_first_valid_finding_seconds != expected_first_finding:
            raise ValueError("benchmark aggregate first-finding time does not match repositories")
        for repository in self.repository_metrics:
            (
                expected_property_ids,
                expected_mutation_score,
                expected_mutation_gate,
            ) = _repository_mutation_projection(
                self.mutation_scorecard,
                repository.repository_id,
            )
            if (
                repository.mutation_property_ids != expected_property_ids
                or repository.mutation_kill_score != expected_mutation_score
                or repository.mutation_gate_passed != expected_mutation_gate
            ):
                raise ValueError("repository mutation metrics do not match the scorecard")
        if (
            self.superiority_claim.status is not SuperiorityClaimStatus.NOT_EVALUATED
            and self.superiority_claim.corpus_sha256 != self.corpus_sha256
        ):
            raise ValueError("superiority comparison must use the evaluated benchmark corpus")
        expected_gate_states: dict[str, BenchmarkMetricState] = {
            "known_critical_recall": self.metrics.critical_recall.state,
            "safe_control_false_confirmations": _combine_states(
                self.metrics.false_confirmed_critical_rate.state,
                self.metrics.false_confirmed_high_rate.state,
            ),
            "exact_ground_truth_locations": self.metrics.exact_location_accuracy.state,
            "repository_metrics_unmasked": _repository_gate_state(self.repository_metrics),
            "evidence_caps": _complete_portfolio_state(
                self.report_inputs,
                passed=self.evidence_cap_bypasses == 0,
            ),
            "coverage_present": _complete_portfolio_state(
                self.report_inputs,
                passed=self.reports_missing_coverage == 0,
            ),
        }
        if self.profile is AuditProfile.MAXIMUM_ASSURANCE:
            maximum_complete = all(
                item.maximum_assurance_status is MaximumAssuranceStatus.COMPLETE
                and set(MAXIMUM_ASSURANCE_CORE_CLAUSES)
                <= set(item.maximum_assurance_required_clauses)
                for item in self.report_inputs
                if item.usable
            )
            missing_metrics, incomplete_metrics = _maximum_assurance_repository_coverage_gaps(
                self.repository_metrics
            )
            expected_gate_states.update(
                {
                    "maximum_assurance_complete": _complete_portfolio_state(
                        self.report_inputs,
                        passed=maximum_complete,
                    ),
                    "maximum_assurance_repository_mutation_score": _mutation_gate_state(
                        self.mutation_scorecard,
                        self.report_inputs,
                        all(item.mutation_gate_passed is True for item in self.repository_metrics),
                    ),
                    "maximum_assurance_semantic_coverage": _semantic_coverage_state(
                        self.report_inputs,
                        missing_metrics=missing_metrics,
                        incomplete_metrics=incomplete_metrics,
                    ),
                    "maximum_assurance_property_mutation_score": _mutation_gate_state(
                        self.mutation_scorecard,
                        self.report_inputs,
                        self.mutation_scorecard is not None
                        and not _weak_maximum_assurance_mutation_properties(
                            self.mutation_scorecard
                        ),
                    ),
                    "maximum_assurance_real_model_calls": _combine_states(
                        _report_input_coverage_state(self.report_inputs),
                        self.metrics.model_call_success_rate.state,
                    ),
                    "maximum_assurance_substantive_model_review": _combine_states(
                        _report_input_coverage_state(self.report_inputs),
                        self.metrics.model_review_coverage.state,
                        self.metrics.critical_model_review_coverage.state,
                    ),
                }
            )
        observed_gate_states = {gate.name: gate.state for gate in self.gates}
        if observed_gate_states != expected_gate_states:
            raise ValueError("benchmark gates do not match their typed evidence")
        incomplete_input = any(
            item.status is not BenchmarkReportInputStatus.USABLE for item in self.report_inputs
        )
        incomplete_gate = any(
            gate.state
            in {
                BenchmarkMetricState.NOT_EVALUABLE,
                BenchmarkMetricState.INCONCLUSIVE,
            }
            for gate in self.gates
        )
        expected_status = (
            BenchmarkStatus.INCOMPLETE
            if incomplete_input or incomplete_gate
            else (
                BenchmarkStatus.PASSED
                if all(gate.passed for gate in self.gates)
                else BenchmarkStatus.FAILED
            )
        )
        if self.status is not expected_status:
            raise ValueError("benchmark status does not match its report inputs and gates")
        return self


def benchmark_certification_failures(report: BenchmarkReport) -> list[str]:
    """Return every reason a benchmark report cannot back a release certificate."""

    failures: list[str] = []
    if report.status is not BenchmarkStatus.PASSED:
        failures.append(f"benchmark status is {report.status.value}, not passed")
    if any(not gate.passed or gate.state is not BenchmarkMetricState.PASS for gate in report.gates):
        failures.append("one or more required benchmark gates did not pass")
    if any(
        report_input.status is not BenchmarkReportInputStatus.USABLE
        for report_input in report.report_inputs
    ):
        failures.append("one or more expected reports are missing, malformed, stale, or failed")
    if not (
        report.reports_expected
        == report.reports_attempted
        == report.reports_parsed
        == report.reports_loaded
        > 0
    ):
        failures.append("benchmark report inventory is not non-empty and complete")
    if (
        not report.case_results
        or report.vulnerable_cases == 0
        or report.safe_cases == 0
        or not any(
            result.variant == "vulnerable" and result.minimum_severity is Severity.HIGH
            for result in report.case_results
        )
        or not any(
            result.variant == "vulnerable" and result.minimum_severity is Severity.MEDIUM
            for result in report.case_results
        )
        or any(not result.evaluated for result in report.case_results)
    ):
        failures.append("benchmark case inventory is empty or incompletely evaluated")
    if report.evidence_cap_bypasses or report.reports_missing_coverage:
        failures.append("benchmark evidence-cap or coverage counters are not clean")
    if not report.coverage_metrics:
        failures.append("benchmark typed coverage inventory is empty")
    if (
        report.resource_metrics.cost_usd.observations != report.reports_parsed
        or report.resource_metrics.runtime_seconds.observations != report.reports_parsed
    ):
        failures.append("benchmark cost or runtime observations are incomplete")
    required_metric_names = (
        _MAXIMUM_ASSURANCE_CERTIFICATION_METRIC_NAMES
        if report.profile is AuditProfile.MAXIMUM_ASSURANCE
        else _BASE_CERTIFICATION_METRIC_NAMES
    )
    for name in required_metric_names:
        metric = getattr(report.metrics, name)
        if (
            metric.state is not BenchmarkMetricState.PASS
            or metric.denominator == 0
            or metric.evaluated != metric.denominator
            or metric.value is None
        ):
            failures.append(f"required benchmark metric is not a complete pass: {name}")
    return sorted(set(failures))


def require_certifiable_benchmark_report(report: BenchmarkReport) -> None:
    """Reject a benchmark summary that lacks complete runtime evidence."""

    failures = benchmark_certification_failures(report)
    if failures:
        raise ValueError("benchmark report is not certifiable: " + "; ".join(failures))


def require_benchmark_report_matches_manifest(
    report: BenchmarkReport,
    manifest: BenchmarkManifest,
) -> None:
    """Require the report to cover the exact hash-bound corpus inventory."""

    failures: list[str] = []
    if (
        report.corpus_name != manifest.name
        or report.corpus_sha256 != manifest.corpus_sha256
        or report.blinding != manifest.blinding
    ):
        failures.append("benchmark report corpus identity differs from its bound manifest")
    expected_repositories = [repository.repository_id for repository in manifest.repositories]
    observed_repositories = [item.repository_id for item in report.report_inputs]
    if observed_repositories != expected_repositories:
        failures.append("benchmark report repository inventory differs from its bound manifest")
    expected_cases = {
        case.id: (
            case.repository_id,
            case.variant,
            case.minimum_severity,
        )
        for case in manifest.cases
    }
    observed_cases = {
        result.case_id: (
            result.repository_id,
            result.variant,
            result.minimum_severity,
        )
        for result in report.case_results
    }
    if observed_cases != expected_cases:
        failures.append("benchmark report case inventory differs from its bound manifest")
    if failures:
        raise ValueError("; ".join(failures))


def seal_benchmark_manifest(payload: BenchmarkManifestPayload) -> BenchmarkManifest:
    """Add a canonical self-hash to deterministic benchmark ground truth."""

    serialized = payload.model_dump(mode="json")
    return BenchmarkManifest.model_validate(
        {
            **serialized,
            "corpus_sha256": canonical_sha256(serialized),
        }
    )


def load_manifest(path: Path) -> BenchmarkManifest:
    """Load a bounded benchmark manifest without following path references."""

    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("benchmark manifest must be a regular non-symlink file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > 2_000_000:
        raise ValueError("benchmark manifest must be a bounded unshared file")
    return BenchmarkManifest.model_validate_json(path.read_text(encoding="utf-8"))


def validate_benchmark_ground_truth(
    manifest: BenchmarkManifest,
    *,
    workspace_root: Path,
) -> list[BenchmarkGroundTruthBinding]:
    """Verify every corpus source hash and range without executing fixture code."""

    if workspace_root.is_symlink() or workspace_root.is_junction():
        raise ValueError("benchmark ground-truth root may not be a link")
    resolved_workspace = workspace_root.resolve(strict=True)
    repository_roots = {
        repository.repository_id: _resolve_ground_truth_path(
            resolved_workspace,
            repository.source_root,
            expect_directory=True,
        )
        for repository in manifest.repositories
    }
    cases_by_source: dict[tuple[str, str], list[BenchmarkCase]] = {}
    for case in manifest.cases:
        cases_by_source.setdefault((case.repository_id, case.path), []).append(case)

    bindings: list[BenchmarkGroundTruthBinding] = []
    for (repository_id, path), cases in sorted(cases_by_source.items()):
        source_path = _resolve_ground_truth_path(
            repository_roots[repository_id],
            path,
            expect_directory=False,
        )
        metadata = source_path.stat()
        if metadata.st_nlink != 1 or metadata.st_size > _MAX_GROUND_TRUTH_SOURCE_BYTES:
            raise ValueError("benchmark ground-truth source must be bounded and unshared")
        contents = source_path.read_bytes()
        observed_sha256 = hashlib.sha256(contents).hexdigest()
        expected_sha256 = cases[0].source_sha256
        if observed_sha256 != expected_sha256:
            raise ValueError(
                f"benchmark ground-truth source hash changed for {repository_id}/{path}"
            )
        line_count = len(contents.decode("utf-8").splitlines())
        if any(case.end_line > line_count for case in cases):
            raise ValueError(
                f"benchmark ground-truth source range changed for {repository_id}/{path}"
            )
        bindings.append(
            BenchmarkGroundTruthBinding(
                repository_id=repository_id,
                path=path,
                sha256=observed_sha256,
                size=metadata.st_size,
                line_count=line_count,
                case_ids=sorted(case.id for case in cases),
            )
        )
    return bindings


def load_reports(
    root: Path,
    repository_ids: set[str],
    *,
    profile: AuditProfile,
) -> tuple[dict[str, AuditReport], list[BenchmarkReportInput], list[str]]:
    """Load only expected report paths beneath a caller-selected directory."""

    resolved_root = root.resolve(strict=True)
    reports: dict[str, AuditReport] = {}
    inputs: list[BenchmarkReportInput] = []
    limitations: list[str] = []
    for repository_id in sorted(repository_ids):
        candidates = [
            resolved_root / repository_id / "final-findings.json",
            resolved_root / f"{repository_id}.json",
        ]
        report_path = next((path for path in candidates if path.is_file()), None)
        if report_path is None:
            detail = f"missing report for repository {repository_id}"
            limitations.append(detail)
            inputs.append(
                BenchmarkReportInput(
                    repository_id=repository_id,
                    status=BenchmarkReportInputStatus.MISSING,
                    attempted=False,
                    parsed=False,
                    usable=False,
                    detail=detail,
                )
            )
            continue
        if report_path.is_symlink() or report_path.stat().st_size > 100_000_000:
            detail = f"unsafe or oversized report for repository {repository_id}"
            limitations.append(detail)
            inputs.append(
                BenchmarkReportInput(
                    repository_id=repository_id,
                    status=BenchmarkReportInputStatus.MALFORMED,
                    attempted=True,
                    parsed=False,
                    usable=False,
                    detail=detail,
                )
            )
            continue
        report_path.resolve(strict=True).relative_to(resolved_root)
        try:
            report = AuditReport.model_validate_json(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            detail = f"invalid report for repository {repository_id}: {type(exc).__name__}"
            limitations.append(detail)
            inputs.append(
                BenchmarkReportInput(
                    repository_id=repository_id,
                    status=BenchmarkReportInputStatus.MALFORMED,
                    attempted=True,
                    parsed=False,
                    usable=False,
                    detail=detail,
                )
            )
            continue
        reports[repository_id] = report
        report_input = _classify_report_input(
            repository_id,
            report,
            profile=profile,
        )
        inputs.append(report_input)
        if not report_input.usable:
            limitations.append(report_input.detail)
    return reports, inputs, limitations


def evaluate_benchmark(
    manifest: BenchmarkManifest,
    reports: dict[str, AuditReport],
    *,
    profile: AuditProfile,
    report_inputs: list[BenchmarkReportInput] | None = None,
    initial_limitations: list[str] | None = None,
    mutation_scorecard: MutationScorecard | None = None,
    superiority_evidence: HumanComparisonEvidence | None = None,
) -> BenchmarkReport:
    """Calculate evidence-aware regression metrics from actual audit reports."""

    mutation_scorecard = (
        MutationScorecard.model_validate(mutation_scorecard.model_dump(mode="python"))
        if mutation_scorecard is not None
        else None
    )
    repository_ids = {repository.repository_id for repository in manifest.repositories}
    unexpected_reports = sorted(set(reports) - repository_ids)
    if unexpected_reports:
        raise ValueError(
            "benchmark received unexpected repository reports: " + ", ".join(unexpected_reports)
        )
    if mutation_scorecard is not None:
        unexpected_mutation_repositories = sorted(
            set(mutation_scorecard.property_repositories.values()) - repository_ids
        )
        if unexpected_mutation_repositories:
            raise ValueError(
                "mutation scorecard references unexpected repositories: "
                + ", ".join(unexpected_mutation_repositories)
            )

    normalized_inputs = _normalize_report_inputs(
        manifest=manifest,
        reports=reports,
        profile=profile,
        report_inputs=report_inputs,
    )
    input_by_repository = {item.repository_id: item for item in normalized_inputs}
    usable_reports = {
        repository_id: report
        for repository_id, report in reports.items()
        if input_by_repository[repository_id].usable
    }

    results: list[BenchmarkCaseResult] = []
    for case in sorted(manifest.cases, key=lambda item: item.id):
        report = usable_reports.get(case.repository_id)
        if report is None:
            results.append(
                BenchmarkCaseResult(
                    case_id=case.id,
                    repository_id=case.repository_id,
                    variant=case.variant,
                    minimum_severity=case.minimum_severity,
                    evaluated=False,
                    detected=False,
                    confirmed=False,
                    limitation=input_by_repository[case.repository_id].detail,
                )
            )
            continue
        matches = [
            finding
            for finding in [*report.findings, *report.rejected_findings]
            if _matches_case(finding, case)
        ]
        active = [
            finding
            for finding in matches
            if finding.status
            not in {
                FindingStatus.REJECTED,
                FindingStatus.UNSUPPORTED,
                FindingStatus.INSUFFICIENT_CONTEXT,
            }
            and SEVERITY_ORDER[finding.severity.value]
            >= SEVERITY_ORDER[case.minimum_severity.value]
        ]
        confirmed = [finding for finding in active if finding.status is FindingStatus.CONFIRMED]
        reproduction_attempted = any(
            _finding_has_real_reproduction(report, finding, require_success=False)
            for finding in active
        )
        reproduced = [
            finding
            for finding in active
            if _finding_has_real_reproduction(report, finding, require_success=True)
        ]
        results.append(
            BenchmarkCaseResult(
                case_id=case.id,
                repository_id=case.repository_id,
                variant=case.variant,
                minimum_severity=case.minimum_severity,
                evaluated=True,
                detected=bool(active),
                confirmed=bool(confirmed),
                reproduction_attempted=reproduction_attempted,
                reproduced=bool(reproduced),
                exact_location=any(_matches_case_exactly(finding, case) for finding in active),
                matched_finding_ids=sorted({finding.id for finding in active}),
                confirmed_finding_ids=sorted({finding.id for finding in confirmed}),
                cwe_match=(
                    not case.expected_cwe
                    or any(
                        set(value.upper() for value in finding.cwe)
                        & set(value.upper() for value in case.expected_cwe)
                        for finding in active
                    )
                ),
            )
        )
    vulnerable = [result for result in results if result.variant == "vulnerable"]
    critical_ids = {
        case.id
        for case in manifest.cases
        if case.variant == "vulnerable" and case.minimum_severity is Severity.CRITICAL
    }
    critical = [result for result in results if result.case_id in critical_ids]
    safe = [result for result in results if result.variant == "safe"]
    cap_bypasses = sum(
        1
        for report in reports.values()
        for finding in report.findings
        if finding.status is FindingStatus.CONFIRMED
        and finding.evidence_strength
        in {
            EvidenceStrength.NONE,
            EvidenceStrength.MODEL_INFERENCE,
            EvidenceStrength.INDEPENDENT_MODEL_SUPPORT,
            EvidenceStrength.VALIDATED_ATTACK_PATH,
        }
    )
    model_only_capped = sum(
        1
        for report in reports.values()
        for finding in report.findings
        if finding.evidence_strength
        in {
            EvidenceStrength.MODEL_INFERENCE,
            EvidenceStrength.INDEPENDENT_MODEL_SUPPORT,
        }
        and finding.status is not FindingStatus.CONFIRMED
    )
    missing_coverage = len(repository_ids) - sum(
        report.effective_solidity_coverage() is not None for report in usable_reports.values()
    )
    false_confirmations = sum(
        result.confirmed
        for result in safe
        if result.minimum_severity in {Severity.CRITICAL, Severity.HIGH}
    )
    detected_vulnerable = sum(result.detected for result in vulnerable)
    reproduced_vulnerable = sum(result.reproduced for result in vulnerable)
    attempted_reproductions = sum(result.reproduction_attempted for result in vulnerable)
    exact_locations = sum(result.exact_location for result in vulnerable)
    detected_critical = sum(result.detected for result in critical)
    findings = [finding for report in usable_reports.values() for finding in report.findings]
    unique_by_role: dict[str, int] = {}
    unique_by_family: dict[str, int] = {}
    for finding in findings:
        roles = {vote.role for vote in finding.model_votes}
        families = {vote.family for vote in finding.model_votes}
        if len(roles) == 1:
            role = next(iter(roles))
            unique_by_role[role] = unique_by_role.get(role, 0) + 1
        if len(families) == 1:
            family = next(iter(families))
            unique_by_family[family] = unique_by_family.get(family, 0) + 1

    cases_by_id = {case.id: case for case in manifest.cases}
    evaluated_vulnerable = sum(result.evaluated for result in vulnerable)
    active_finding_records = [
        (repository_id, finding)
        for repository_id, report in usable_reports.items()
        for finding in report.findings
        if _finding_is_active(finding)
    ]
    confirmed_finding_records = [
        (repository_id, finding)
        for repository_id, finding in active_finding_records
        if finding.status is FindingStatus.CONFIRMED
    ]
    true_active_findings = sum(
        _finding_matches_any_vulnerable_case(
            finding,
            manifest.cases,
            repository_id=repository_id,
        )
        for repository_id, finding in active_finding_records
    )
    true_confirmed_findings = sum(
        _finding_matches_any_vulnerable_case(
            finding,
            manifest.cases,
            repository_id=repository_id,
        )
        for repository_id, finding in confirmed_finding_records
    )

    severity_metrics: dict[Severity, BenchmarkRateMetric] = {}
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
        severity_results = [
            result
            for result in vulnerable
            if cases_by_id[result.case_id].minimum_severity is severity
        ]
        severity_metrics[severity] = _rate_metric(
            numerator=sum(result.detected for result in severity_results),
            denominator=len(severity_results),
            evaluated=sum(result.evaluated for result in severity_results),
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail=f"{severity.value} must-catch recall",
        )

    safe_by_severity = {
        severity: [
            result for result in safe if cases_by_id[result.case_id].minimum_severity is severity
        ]
        for severity in (Severity.CRITICAL, Severity.HIGH)
    }
    false_confirmation_metrics = {
        severity: _rate_metric(
            numerator=sum(result.confirmed for result in severity_results),
            denominator=len(severity_results),
            evaluated=sum(result.evaluated for result in severity_results),
            threshold=0,
            direction=BenchmarkMetricDirection.MAXIMUM,
            detail=f"false-confirmed {severity.value} safe-control rate",
        )
        for severity, severity_results in safe_by_severity.items()
    }

    repository_metrics = _repository_metrics(
        manifest=manifest,
        results=results,
        reports=reports,
        report_inputs=normalized_inputs,
        mutation_scorecard=mutation_scorecard,
    )
    coverage_metrics = _aggregate_repository_coverage(repository_metrics)
    model_call_metric, model_review_metric, critical_model_review_metric = _model_review_metrics(
        reports,
        normalized_inputs,
        profile=profile,
    )
    invariant_mutation_metric = _mutation_rate_metric(mutation_scorecard)
    economic_applicability_metric, economic_execution_metric = _economic_metrics(
        reports,
        normalized_inputs,
    )
    metrics = BenchmarkMetrics(
        overall_recall=_rate_metric(
            numerator=detected_vulnerable,
            denominator=len(vulnerable),
            evaluated=evaluated_vulnerable,
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="all mandatory vulnerable benchmark cases detected",
        ),
        critical_recall=severity_metrics[Severity.CRITICAL],
        high_recall=severity_metrics[Severity.HIGH],
        medium_recall=severity_metrics[Severity.MEDIUM],
        confirmed_precision=_rate_metric(
            numerator=true_confirmed_findings,
            denominator=len(confirmed_finding_records),
            evaluated=len(confirmed_finding_records),
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="confirmed findings matching vulnerable ground truth",
        ),
        all_finding_precision=_rate_metric(
            numerator=true_active_findings,
            denominator=len(active_finding_records),
            evaluated=len(active_finding_records),
            threshold=None,
            direction=BenchmarkMetricDirection.INFORMATIONAL,
            detail="all active findings matching vulnerable ground truth; no release threshold",
        ),
        false_confirmed_critical_rate=false_confirmation_metrics[Severity.CRITICAL],
        false_confirmed_high_rate=false_confirmation_metrics[Severity.HIGH],
        safe_near_miss_rejection_rate=_rate_metric(
            numerator=sum(result.evaluated and not result.detected for result in safe),
            denominator=len(safe),
            evaluated=sum(result.evaluated for result in safe),
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="safe controls rejected without an active finding",
        ),
        exact_location_accuracy=_rate_metric(
            numerator=exact_locations,
            denominator=len(vulnerable),
            evaluated=evaluated_vulnerable,
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="vulnerable cases with an exact hash-validated source location",
        ),
        attack_path_reachability_accuracy=_unavailable_metric(
            "benchmark corpus has no independently adjudicated reachability labels"
        ),
        reproduction_success_rate=_rate_metric(
            numerator=reproduced_vulnerable,
            denominator=len(vulnerable),
            evaluated=attempted_reproductions,
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="vulnerable cases with qualifying real reproduction attempts",
        ),
        symbolic_counterexample_success_rate=_unavailable_metric(
            "benchmark corpus does not independently label symbolic-engine applicability"
        ),
        formal_property_mutation_score=_unavailable_metric(
            "mutation corpus does not yet attribute outcomes to a formal proof engine"
        ),
        invariant_mutation_score=invariant_mutation_metric,
        contract_coverage=_coverage_rate_metric(
            coverage_metrics,
            "compiler_contracts_indexed",
            detail="compiled contracts represented in the typed symbol index",
        ),
        entry_point_coverage=_coverage_rate_metric(
            coverage_metrics,
            "public_external_entry_points_reviewed",
            detail="public and external entry points substantively reviewed",
        ),
        privileged_function_coverage=_coverage_rate_metric(
            coverage_metrics,
            "privileged_entry_points_reviewed",
            detail="privileged entry points substantively reviewed",
        ),
        asset_moving_function_coverage=_coverage_rate_metric(
            coverage_metrics,
            "high_value_paths_reviewed",
            detail="asset-sensitive paths substantively reviewed",
        ),
        external_call_coverage=_coverage_rate_metric(
            coverage_metrics,
            "external_calls_classified",
            detail="external call edges deterministically classified",
        ),
        model_call_success_rate=model_call_metric,
        model_review_coverage=model_review_metric,
        critical_model_review_coverage=critical_model_review_metric,
        economic_template_applicability_coverage=economic_applicability_metric,
        economic_template_execution_coverage=economic_execution_metric,
    )

    cost_values = [item.cost_usd for item in repository_metrics if item.cost_usd is not None]
    total_cost = sum(cost_values)
    total_tokens = sum(item.total_tokens or 0 for item in repository_metrics)
    runtime_values = [
        item.runtime_seconds for item in repository_metrics if item.runtime_seconds is not None
    ]
    first_finding_values = [
        item.time_to_first_valid_finding_seconds
        for item in repository_metrics
        if item.time_to_first_valid_finding_seconds is not None
    ]
    resources = BenchmarkResourceMetrics(
        cost_usd=_resource_metric(cost_values, "parsed report cost observations"),
        runtime_seconds=_resource_metric(
            runtime_values,
            "parsed report runtime observations",
        ),
    )
    limitations = sorted(
        set(initial_limitations or [])
        | {
            item.detail
            for item in normalized_inputs
            if item.status is not BenchmarkReportInputStatus.USABLE
        }
        | (
            {
                "mutation scorecard is declarative or planned-unattested component "
                "evidence and received no runtime mutation credit"
            }
            if mutation_scorecard is not None
            and not _mutation_scorecard_has_runtime_credit(mutation_scorecard)
            else set()
        )
    )
    repository_gate_state = _repository_gate_state(repository_metrics)
    safe_gate_state = _combine_states(
        false_confirmation_metrics[Severity.CRITICAL].state,
        false_confirmation_metrics[Severity.HIGH].state,
    )
    coverage_present_state = _coverage_present_state(
        normalized_inputs,
        reports,
    )
    gates = [
        _gate(
            name="known_critical_recall",
            state=metrics.critical_recall.state,
            detail=f"{detected_critical}/{len(critical)} critical cases detected",
        ),
        _gate(
            name="safe_control_false_confirmations",
            state=safe_gate_state,
            detail=f"{false_confirmations} safe high/critical case(s) confirmed",
        ),
        _gate(
            name="exact_ground_truth_locations",
            state=metrics.exact_location_accuracy.state,
            detail=f"{exact_locations}/{len(vulnerable)} vulnerable locations matched exactly",
        ),
        _gate(
            name="repository_metrics_unmasked",
            state=repository_gate_state,
            detail=(
                "every repository passed critical recall, safe confirmation, "
                "exact-location, and reproduction checks"
                if repository_gate_state is BenchmarkMetricState.PASS
                else "one or more repositories failed an unmasked quality metric"
            ),
        ),
        _gate(
            name="evidence_caps",
            state=_complete_portfolio_state(
                normalized_inputs,
                passed=cap_bypasses == 0,
            ),
            detail=f"{cap_bypasses} confirmed finding(s) bypassed evidence caps",
        ),
        _gate(
            name="coverage_present",
            state=coverage_present_state,
            detail=f"{missing_coverage} expected report(s) lack typed Solidity coverage",
        ),
    ]
    if profile is AuditProfile.MAXIMUM_ASSURANCE:
        incomplete_maximum = [
            repository_id
            for repository_id, report in usable_reports.items()
            if report.maximum_assurance is None
            or report.maximum_assurance.status is not MaximumAssuranceStatus.COMPLETE
        ]
        maximum_complete_state = _complete_portfolio_state(
            normalized_inputs,
            passed=not incomplete_maximum,
        )
        gates.append(
            _gate(
                name="maximum_assurance_complete",
                state=maximum_complete_state,
                detail=(
                    "all benchmark reports are COMPLETE"
                    if maximum_complete_state is BenchmarkMetricState.PASS
                    else "non-COMPLETE repositories: "
                    + ", ".join(
                        sorted(
                            incomplete_maximum
                            or {item.repository_id for item in normalized_inputs if not item.usable}
                        )
                    )
                ),
            )
        )
        repository_mutation_state = _mutation_gate_state(
            mutation_scorecard,
            normalized_inputs,
            all(item.mutation_gate_passed is True for item in repository_metrics),
        )
        gates.append(
            _gate(
                name="maximum_assurance_repository_mutation_score",
                state=repository_mutation_state,
                detail=(
                    "every repository passed its attributed property mutation score"
                    if repository_mutation_state is BenchmarkMetricState.PASS
                    else "one or more repositories lack a passing attributed mutation score"
                ),
            )
        )
        missing_metrics, incomplete_metrics = _maximum_assurance_repository_coverage_gaps(
            repository_metrics,
        )
        semantic_state = _semantic_coverage_state(
            normalized_inputs,
            missing_metrics=missing_metrics,
            incomplete_metrics=incomplete_metrics,
        )
        gates.append(
            _gate(
                name="maximum_assurance_semantic_coverage",
                state=semantic_state,
                detail=(
                    "required semantic coverage metrics are complete"
                    if semantic_state is BenchmarkMetricState.PASS
                    else "missing metrics: "
                    + ", ".join(missing_metrics or ["none"])
                    + "; incomplete metrics: "
                    + ", ".join(incomplete_metrics or ["none"])
                ),
            )
        )
        weak_properties = _weak_maximum_assurance_mutation_properties(mutation_scorecard)
        property_mutation_state = _mutation_gate_state(
            mutation_scorecard,
            normalized_inputs,
            mutation_scorecard is not None and not weak_properties,
        )
        gates.append(
            _gate(
                name="maximum_assurance_property_mutation_score",
                state=property_mutation_state,
                detail=(
                    "every expected property killed all applicable mutations"
                    if property_mutation_state is BenchmarkMetricState.PASS
                    else (
                        "mutation scorecard unavailable"
                        if mutation_scorecard is None
                        else "properties below the 1.0 kill-score gate: "
                        + ", ".join(weak_properties)
                    )
                ),
            )
        )
        gates.append(
            _gate(
                name="maximum_assurance_real_model_calls",
                state=_combine_states(
                    _report_input_coverage_state(normalized_inputs),
                    model_call_metric.state,
                ),
                detail=model_call_metric.detail,
            )
        )
        gates.append(
            _gate(
                name="maximum_assurance_substantive_model_review",
                state=_combine_states(
                    _report_input_coverage_state(normalized_inputs),
                    model_review_metric.state,
                    critical_model_review_metric.state,
                ),
                detail=(
                    f"overall={model_review_metric.state.value}; "
                    f"critical={critical_model_review_metric.state.value}"
                ),
            )
        )
    if any(not item.usable for item in normalized_inputs) or any(
        gate.state
        in {
            BenchmarkMetricState.NOT_EVALUABLE,
            BenchmarkMetricState.INCONCLUSIVE,
        }
        for gate in gates
    ):
        status = BenchmarkStatus.INCOMPLETE
    elif all(gate.passed for gate in gates):
        status = BenchmarkStatus.PASSED
    else:
        status = BenchmarkStatus.FAILED
    return BenchmarkReport(
        schema_version="3.0",
        corpus_name=manifest.name,
        corpus_sha256=manifest.corpus_sha256,
        blinding=manifest.blinding,
        profile=profile,
        status=status,
        reports_expected=len(repository_ids),
        reports_attempted=sum(item.attempted for item in normalized_inputs),
        reports_parsed=sum(item.parsed for item in normalized_inputs),
        reports_loaded=sum(item.usable for item in normalized_inputs),
        report_inputs=normalized_inputs,
        vulnerable_cases=len(vulnerable),
        vulnerable_cases_detected=detected_vulnerable,
        vulnerable_cases_reproduced=reproduced_vulnerable,
        critical_cases=len(critical),
        critical_cases_detected=detected_critical,
        safe_cases=len(safe),
        ambiguous_cases=sum(result.variant == "ambiguous" for result in results),
        safe_high_critical_confirmations=false_confirmations,
        evidence_cap_bypasses=cap_bypasses,
        reports_missing_coverage=missing_coverage,
        model_only_findings_kept_below_confirmed=model_only_capped,
        active_findings=len(active_finding_records),
        active_findings_matching_vulnerable_cases=true_active_findings,
        confirmed_findings=len(confirmed_finding_records),
        confirmed_findings_matching_vulnerable_cases=true_confirmed_findings,
        recall=metrics.overall_recall.value,
        recall_by_severity={
            Severity.CRITICAL.value: metrics.critical_recall.value,
            Severity.HIGH.value: metrics.high_recall.value,
            Severity.MEDIUM.value: metrics.medium_recall.value,
        },
        critical_recall=metrics.critical_recall.value,
        precision=metrics.confirmed_precision.value,
        false_positive_rate=(
            round(1 - metrics.safe_near_miss_rejection_rate.value, 6)
            if metrics.safe_near_miss_rejection_rate.value is not None
            else None
        ),
        safe_false_confirmation_rate=_combined_false_confirmation_value(
            metrics.false_confirmed_critical_rate,
            metrics.false_confirmed_high_rate,
        ),
        reproduction_success_rate=metrics.reproduction_success_rate.value,
        location_cases=len(vulnerable),
        exact_locations=exact_locations,
        location_accuracy=metrics.exact_location_accuracy.value,
        total_cost_usd=total_cost,
        total_tokens=total_tokens,
        total_runtime_seconds=sum(runtime_values) if runtime_values else None,
        time_to_first_valid_finding_seconds=(
            min(first_finding_values) if first_finding_values else None
        ),
        resource_metrics=resources,
        metrics=metrics,
        unique_finding_contribution_by_role=unique_by_role,
        unique_finding_contribution_by_family=unique_by_family,
        mutation_scorecard=mutation_scorecard,
        superiority_claim=evaluate_superiority_claim(superiority_evidence),
        coverage_metrics=coverage_metrics,
        repository_metrics=repository_metrics,
        case_results=results,
        gates=gates,
        limitations=limitations,
    )


def write_benchmark_report(path: Path, report: BenchmarkReport) -> None:
    report = BenchmarkReport.model_validate(report.model_dump(mode="python"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def _matches_case(finding: Finding, case: BenchmarkCase) -> bool:
    return any(
        location.start_line <= case.end_line and case.start_line <= location.end_line
        for location in _hash_validated_case_locations(finding, case)
    )


def _matches_case_exactly(finding: Finding, case: BenchmarkCase) -> bool:
    return any(
        location.start_line == case.start_line and location.end_line == case.end_line
        for location in _hash_validated_case_locations(finding, case)
    )


def _repository_metrics(
    *,
    manifest: BenchmarkManifest,
    results: list[BenchmarkCaseResult],
    reports: dict[str, AuditReport],
    report_inputs: list[BenchmarkReportInput],
    mutation_scorecard: MutationScorecard | None,
) -> list[BenchmarkRepositoryMetrics]:
    cases_by_id = {case.id: case for case in manifest.cases}
    inputs_by_repository = {item.repository_id: item for item in report_inputs}
    metrics: list[BenchmarkRepositoryMetrics] = []
    for repository in manifest.repositories:
        repository_results = [
            result for result in results if result.repository_id == repository.repository_id
        ]
        vulnerable = [result for result in repository_results if result.variant == "vulnerable"]
        critical = [
            result
            for result in vulnerable
            if cases_by_id[result.case_id].minimum_severity is Severity.CRITICAL
        ]
        safe = [result for result in repository_results if result.variant == "safe"]
        ambiguous = [result for result in repository_results if result.variant == "ambiguous"]
        report = reports.get(repository.repository_id)
        report_input = inputs_by_repository[repository.repository_id]
        (
            property_ids,
            mutation_kill_score,
            mutation_gate_passed,
        ) = _repository_mutation_projection(
            mutation_scorecard,
            repository.repository_id,
        )
        runtime = (
            _nonnegative_metadata_float(report.metadata.get("duration_seconds"))
            if report is not None
            else None
        )
        first_finding = (
            _nonnegative_metadata_float(report.metadata.get("time_to_first_candidate_seconds"))
            if report is not None
            else None
        )
        coverage = report.effective_solidity_coverage() if report is not None else None
        repository_coverage = (
            {
                name: BenchmarkCoverageMetric(
                    numerator=metric.numerator,
                    denominator=metric.denominator,
                    evaluated=metric.denominator,
                    percentage=metric.percentage,
                    state=(
                        BenchmarkMetricState.PASS
                        if metric.denominator > 0 and metric.numerator == metric.denominator
                        else (
                            BenchmarkMetricState.NOT_EVALUABLE
                            if metric.denominator == 0
                            else BenchmarkMetricState.FAIL
                        )
                    ),
                    detail="typed Solidity coverage for one usable benchmark report",
                )
                for name, metric in coverage.quality_metrics.items()
            }
            if report_input.usable and coverage is not None
            else {}
        )
        report_findings = report.findings if report is not None else []
        evidence_cap_bypasses = sum(
            finding.status is FindingStatus.CONFIRMED
            and finding.evidence_strength
            in {
                EvidenceStrength.NONE,
                EvidenceStrength.MODEL_INFERENCE,
                EvidenceStrength.INDEPENDENT_MODEL_SUPPORT,
                EvidenceStrength.VALIDATED_ATTACK_PATH,
            }
            for finding in report_findings
        )
        model_only_capped = sum(
            finding.evidence_strength
            in {
                EvidenceStrength.MODEL_INFERENCE,
                EvidenceStrength.INDEPENDENT_MODEL_SUPPORT,
            }
            and finding.status is not FindingStatus.CONFIRMED
            for finding in report_findings
        )
        metrics.append(
            BenchmarkRepositoryMetrics(
                repository_id=repository.repository_id,
                report_status=report_input.status,
                report_attempted=report_input.attempted,
                report_parsed=report_input.parsed,
                report_loaded=report_input.usable,
                cases_evaluated=sum(item.evaluated for item in repository_results),
                vulnerable_cases=len(vulnerable),
                vulnerable_cases_detected=sum(item.detected for item in vulnerable),
                recall=_repository_ratio(
                    sum(item.detected for item in vulnerable),
                    len(vulnerable),
                    usable=report_input.usable,
                ),
                critical_cases=len(critical),
                critical_cases_detected=sum(item.detected for item in critical),
                critical_recall=_repository_ratio(
                    sum(item.detected for item in critical),
                    len(critical),
                    usable=report_input.usable,
                ),
                safe_cases=len(safe),
                ambiguous_cases=len(ambiguous),
                safe_false_confirmations=sum(item.confirmed for item in safe),
                safe_high_critical_confirmations=sum(
                    item.confirmed
                    for item in safe
                    if item.minimum_severity in {Severity.CRITICAL, Severity.HIGH}
                ),
                safe_false_confirmation_rate=_repository_ratio(
                    sum(item.confirmed for item in safe),
                    len(safe),
                    usable=report_input.usable,
                ),
                location_cases=len(vulnerable),
                exact_locations=sum(item.exact_location for item in vulnerable),
                location_accuracy=_repository_ratio(
                    sum(item.exact_location for item in vulnerable),
                    len(vulnerable),
                    usable=report_input.usable,
                ),
                vulnerable_cases_reproduced=sum(item.reproduced for item in vulnerable),
                reproduction_success_rate=_repository_ratio(
                    sum(item.reproduced for item in vulnerable),
                    len(vulnerable),
                    usable=report_input.usable,
                ),
                mutation_property_ids=property_ids,
                mutation_kill_score=mutation_kill_score,
                mutation_gate_passed=mutation_gate_passed,
                evidence_cap_bypasses=evidence_cap_bypasses,
                model_only_findings_kept_below_confirmed=model_only_capped,
                coverage_metrics=repository_coverage,
                cost_usd=(
                    report.accounted_cost_usd
                    if report is not None and report_input.parsed
                    else None
                ),
                total_tokens=(
                    sum(record.total_tokens for record in report.usage)
                    if report is not None and report_input.parsed
                    else None
                ),
                runtime_seconds=runtime,
                time_to_first_valid_finding_seconds=first_finding,
            )
        )
    return metrics


def _repository_quality_passed(metrics: BenchmarkRepositoryMetrics) -> bool:
    return (
        metrics.report_loaded
        and metrics.critical_cases > 0
        and metrics.critical_recall == 1
        and metrics.safe_cases > 0
        and metrics.safe_false_confirmations == 0
        and metrics.location_cases > 0
        and metrics.location_accuracy == 1
        and metrics.vulnerable_cases > 0
        and metrics.reproduction_success_rate == 1
    )


def _repository_mutation_projection(
    scorecard: MutationScorecard | None,
    repository_id: str,
) -> tuple[list[str], float | None, bool | None]:
    if scorecard is None:
        return [], None, None
    property_ids = sorted(
        property_id
        for property_id, bound_repository in scorecard.property_repositories.items()
        if bound_repository == repository_id
    )
    if not property_ids:
        return [], None, None
    if not _mutation_scorecard_has_runtime_credit(scorecard):
        return property_ids, None, False
    property_scores = {score.property_id: score for score in scorecard.property_scores}
    outcomes = [outcome for outcome in scorecard.outcomes if outcome.property_id in property_ids]
    kill_score = _bounded_ratio(
        sum(outcome.outcome is MutationTestOutcome.KILLED for outcome in outcomes),
        len(outcomes),
        empty=None,
    )
    gate_passed = all(property_scores[property_id].gate_passed for property_id in property_ids)
    return property_ids, kill_score, gate_passed


@overload
def _bounded_ratio(
    numerator: int,
    denominator: int,
    *,
    empty: float,
) -> float: ...


@overload
def _bounded_ratio(
    numerator: int,
    denominator: int,
    *,
    empty: None,
) -> float | None: ...


def _bounded_ratio(
    numerator: int,
    denominator: int,
    *,
    empty: float | None,
) -> float | None:
    return round(numerator / denominator, 6) if denominator else empty


def _repository_ratio(
    numerator: int,
    denominator: int,
    *,
    usable: bool,
) -> float | None:
    if not usable or denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _rate_metric(
    *,
    numerator: int,
    denominator: int,
    evaluated: int,
    threshold: float | None,
    direction: BenchmarkMetricDirection,
    detail: str,
) -> BenchmarkRateMetric:
    if denominator == 0 or evaluated == 0:
        state = BenchmarkMetricState.NOT_EVALUABLE
        value = None
    elif evaluated < denominator:
        state = BenchmarkMetricState.INCONCLUSIVE
        value = None
    else:
        value = round(numerator / denominator, 6)
        if threshold is None:
            state = BenchmarkMetricState.NOT_APPLICABLE
        else:
            passed = (
                value >= threshold
                if direction is BenchmarkMetricDirection.MINIMUM
                else value <= threshold
            )
            state = BenchmarkMetricState.PASS if passed else BenchmarkMetricState.FAIL
    return BenchmarkRateMetric(
        numerator=numerator,
        denominator=denominator,
        evaluated=evaluated,
        value=value,
        state=state,
        threshold=threshold,
        direction=direction,
        detail=detail,
    )


def _unavailable_metric(
    detail: str,
    *,
    direction: BenchmarkMetricDirection = BenchmarkMetricDirection.INFORMATIONAL,
    threshold: float | None = None,
) -> BenchmarkRateMetric:
    return _rate_metric(
        numerator=0,
        denominator=0,
        evaluated=0,
        threshold=threshold,
        direction=direction,
        detail=detail,
    )


def _coverage_rate_metric(
    metrics: dict[str, BenchmarkCoverageMetric],
    name: str,
    *,
    detail: str,
) -> BenchmarkRateMetric:
    metric = metrics.get(name)
    if metric is None:
        return _unavailable_metric(
            f"{detail}; typed coverage metric is absent",
            direction=BenchmarkMetricDirection.MINIMUM,
            threshold=1,
        )
    return _rate_metric(
        numerator=metric.numerator,
        denominator=metric.denominator,
        evaluated=metric.evaluated,
        threshold=1,
        direction=BenchmarkMetricDirection.MINIMUM,
        detail=detail,
    )


def _resource_metric(values: list[float], detail: str) -> BenchmarkResourceMetric:
    if not values:
        return BenchmarkResourceMetric(
            observations=0,
            total=None,
            average=None,
            worst=None,
            state=BenchmarkMetricState.NOT_EVALUABLE,
            detail=detail,
        )
    total = sum(values)
    return BenchmarkResourceMetric(
        observations=len(values),
        total=total,
        average=round(total / len(values), 6),
        worst=max(values),
        state=BenchmarkMetricState.NOT_APPLICABLE,
        detail=f"{detail}; resource use has no implicit quality threshold",
    )


def _resource_projection(
    metric: BenchmarkResourceMetric,
) -> tuple[int, float | None, float | None, float | None, BenchmarkMetricState]:
    return (
        metric.observations,
        metric.total,
        metric.average,
        metric.worst,
        metric.state,
    )


def _classify_report_input(
    repository_id: str,
    report: AuditReport,
    *,
    profile: AuditProfile,
) -> BenchmarkReportInput:
    assessment = report.maximum_assurance
    required_clause_inventory = (
        [requirement.engine for requirement in assessment.requirements if requirement.required]
        if assessment is not None
        else []
    )
    required_clauses = sorted(
        {
            clause
            for clause in required_clause_inventory
            if re.fullmatch(_ASSURANCE_CLAUSE_PATTERN, clause) is not None
        }
    )
    assurance_status = assessment.status if assessment is not None else None
    assurance_complete = (
        assessment is not None
        and assessment.requested
        and assessment.required
        and not assessment.downgraded
        and assessment.status is MaximumAssuranceStatus.COMPLETE
        and len(required_clause_inventory) == len(required_clauses)
        and set(MAXIMUM_ASSURANCE_CORE_CLAUSES) <= set(required_clauses)
        and all(
            requirement.passed and not requirement.blocking
            for requirement in assessment.requirements
            if requirement.required
        )
    )
    recorded_assurance_status = (
        assurance_status if profile is AuditProfile.MAXIMUM_ASSURANCE else None
    )
    recorded_required_clauses = (
        required_clauses if profile is AuditProfile.MAXIMUM_ASSURANCE else []
    )
    if report.repository.root_name != repository_id:
        return BenchmarkReportInput(
            repository_id=repository_id,
            status=BenchmarkReportInputStatus.STALE,
            attempted=True,
            parsed=True,
            usable=False,
            maximum_assurance_status=recorded_assurance_status,
            maximum_assurance_required_clauses=recorded_required_clauses,
            detail=(
                f"stale report for {repository_id}: repository identity is "
                f"{report.repository.root_name}"
            ),
        )
    if report.audit_profile is not profile:
        return BenchmarkReportInput(
            repository_id=repository_id,
            status=BenchmarkReportInputStatus.STALE,
            attempted=True,
            parsed=True,
            usable=False,
            maximum_assurance_status=recorded_assurance_status,
            maximum_assurance_required_clauses=recorded_required_clauses,
            detail=(
                f"stale report for {repository_id}: profile is "
                f"{report.audit_profile.value}, expected {profile.value}"
            ),
        )
    failed_statuses = {
        AuditQualityStatus.INCOMPLETE,
        AuditQualityStatus.FAILED,
        AuditQualityStatus.ENVIRONMENT_UNSAFE,
        AuditQualityStatus.TARGET_UNSUPPORTED,
    }
    if not report.completed or report.quality_status in failed_statuses:
        return BenchmarkReportInput(
            repository_id=repository_id,
            status=BenchmarkReportInputStatus.FAILED,
            attempted=True,
            parsed=True,
            usable=False,
            maximum_assurance_status=recorded_assurance_status,
            maximum_assurance_required_clauses=recorded_required_clauses,
            detail=(
                f"failed report for {repository_id}: completed={report.completed}, "
                f"quality={report.quality_status.value}"
            ),
        )
    if profile is AuditProfile.MAXIMUM_ASSURANCE and not assurance_complete:
        return BenchmarkReportInput(
            repository_id=repository_id,
            status=BenchmarkReportInputStatus.FAILED,
            attempted=True,
            parsed=True,
            usable=False,
            maximum_assurance_status=recorded_assurance_status,
            maximum_assurance_required_clauses=recorded_required_clauses,
            detail=(
                f"failed report for {repository_id}: maximum-assurance assessment "
                "did not contain the passing canonical core clause portfolio"
            ),
        )
    return BenchmarkReportInput(
        repository_id=repository_id,
        status=BenchmarkReportInputStatus.USABLE,
        attempted=True,
        parsed=True,
        usable=True,
        maximum_assurance_status=recorded_assurance_status,
        maximum_assurance_required_clauses=recorded_required_clauses,
        detail=f"report for {repository_id} is parse-valid and eligible for benchmark scoring",
    )


def _normalize_report_inputs(
    *,
    manifest: BenchmarkManifest,
    reports: dict[str, AuditReport],
    profile: AuditProfile,
    report_inputs: list[BenchmarkReportInput] | None,
) -> list[BenchmarkReportInput]:
    repository_ids = sorted(repository.repository_id for repository in manifest.repositories)
    if report_inputs is None:
        return [
            (
                _classify_report_input(
                    repository_id,
                    reports[repository_id],
                    profile=profile,
                )
                if repository_id in reports
                else BenchmarkReportInput(
                    repository_id=repository_id,
                    status=BenchmarkReportInputStatus.MISSING,
                    attempted=False,
                    parsed=False,
                    usable=False,
                    detail=f"missing report for repository {repository_id}",
                )
            )
            for repository_id in repository_ids
        ]
    supplied_ids = [item.repository_id for item in report_inputs]
    if supplied_ids != repository_ids:
        raise ValueError("benchmark report inputs must cover every repository in canonical order")
    for item in report_inputs:
        report = reports.get(item.repository_id)
        if item.parsed != (report is not None):
            raise ValueError("benchmark report input parse state disagrees with loaded reports")
        if report is not None:
            classified = _classify_report_input(
                item.repository_id,
                report,
                profile=profile,
            )
            if item.status is not classified.status:
                raise ValueError(
                    "benchmark report input disposition disagrees with the parsed report"
                )
    return report_inputs


def _finding_location_is_valid_for_case(finding: Finding, case: BenchmarkCase) -> bool:
    return bool(_hash_validated_case_locations(finding, case))


def _hash_validated_case_locations(finding: Finding, case: BenchmarkCase) -> list[Location]:
    if not finding.location_validation.valid:
        return []
    return [
        location
        for location in finding.locations
        if location.path == case.path
        and (location.content_hash or finding.location_validation.content_hash)
        == case.source_sha256
    ]


def _finding_is_active(finding: Finding) -> bool:
    return finding.status not in {
        FindingStatus.REJECTED,
        FindingStatus.UNSUPPORTED,
        FindingStatus.INSUFFICIENT_CONTEXT,
    }


def _finding_matches_any_vulnerable_case(
    finding: Finding,
    cases: list[BenchmarkCase],
    *,
    repository_id: str | None = None,
) -> bool:
    return any(
        case.variant == "vulnerable"
        and (repository_id is None or case.repository_id == repository_id)
        and SEVERITY_ORDER[finding.severity.value] >= SEVERITY_ORDER[case.minimum_severity.value]
        and _matches_case(finding, case)
        for case in cases
    )


def _finding_has_real_reproduction(
    report: AuditReport,
    finding: Finding,
    *,
    require_success: bool,
) -> bool:
    candidate_ids = set(finding.contributing_candidate_ids)
    if not candidate_ids:
        return False
    positive_states = {
        ReproductionState.REPRODUCED,
        ReproductionState.REPRODUCED_AND_MINIMIZED,
    }
    for reproduction in report.reproductions:
        if (
            reproduction.candidate_id not in candidate_ids
            or reproduction.execution_evidence is not ExecutionEvidenceKind.REAL
            or reproduction.attempts == 0
            or len(reproduction.attempt_evidence) != reproduction.attempts
            or reproduction.executable_sha256 is None
            or reproduction.isolation_attestation_sha256 is None
            or reproduction.repository_sha256 is None
        ):
            continue
        if not require_success:
            return True
        if reproduction.state in positive_states and reproduction.successful_attempts > 0:
            return True
    return False


def _model_review_metrics(
    reports: dict[str, AuditReport],
    report_inputs: list[BenchmarkReportInput],
    *,
    profile: AuditProfile,
) -> tuple[BenchmarkRateMetric, BenchmarkRateMetric, BenchmarkRateMetric]:
    require_certification = profile is AuditProfile.MAXIMUM_ASSURANCE
    usage_denominator = 0
    usage_evaluated = 0
    creditable_usage: dict[str, dict[str, tuple[UsageRecord, str]]] = {}
    authority_pending_usage: dict[str, dict[str, tuple[UsageRecord, str]]] = {}
    for report_input in report_inputs:
        report = reports.get(report_input.repository_id)
        records = report.usage if report is not None and report_input.parsed else []
        if not records:
            usage_denominator += 1
            if _report_input_is_failed_evaluation(report_input):
                usage_evaluated += 1
            continue
        usage_denominator += len(records)
        records_by_request: dict[str, list[UsageRecord]] = {}
        for record in records:
            records_by_request.setdefault(record.request_id, []).append(record)
        repository_usage: dict[str, tuple[UsageRecord, str]] = {}
        repository_pending_usage: dict[str, tuple[UsageRecord, str]] = {}
        for request_id, candidates in records_by_request.items():
            if len(candidates) != 1:
                usage_evaluated += len(candidates)
                continue
            record = candidates[0]
            lineage = _qualified_usage_lineage(
                record,
                require_certification=require_certification,
            )
            if lineage is not None:
                usage_evaluated += 1
                if report_input.usable:
                    repository_usage[request_id] = (record, lineage)
                continue
            pending_lineage = _authority_pending_usage_lineage(
                record,
                require_certification=require_certification,
            )
            if pending_lineage is not None:
                if report_input.usable:
                    repository_pending_usage[request_id] = (record, pending_lineage)
                else:
                    usage_evaluated += 1
                continue
            usage_evaluated += 1
        creditable_usage[report_input.repository_id] = repository_usage
        authority_pending_usage[report_input.repository_id] = repository_pending_usage
    real_request_count = sum(len(values) for values in creditable_usage.values())
    model_call_metric = _rate_metric(
        numerator=real_request_count,
        denominator=usage_denominator,
        evaluated=usage_evaluated,
        threshold=1,
        direction=BenchmarkMetricDirection.MINIMUM,
        detail="strictly validated real provider calls among all recorded model attempts",
    )

    surface_denominator = 0
    surface_evaluated = 0
    reviewed_surfaces = 0
    critical_denominator = 0
    critical_evaluated = 0
    reviewed_critical = 0
    for report_input in report_inputs:
        repository_id = report_input.repository_id
        report = reports.get(repository_id)
        if report is None or report.model_review_coverage is None:
            surface_denominator += 1
            critical_denominator += 1
            if _report_input_is_failed_evaluation(report_input):
                surface_evaluated += 1
                critical_evaluated += 1
            continue
        coverage = report.model_review_coverage
        usage_by_request = creditable_usage.get(repository_id, {})
        pending_usage_by_request = authority_pending_usage.get(repository_id, {})
        surfaces = coverage.surfaces
        if not surfaces:
            surface_denominator += 1
            critical_denominator += 1
            if _report_input_is_failed_evaluation(report_input):
                surface_evaluated += 1
                critical_evaluated += 1
            continue
        surface_denominator += len(surfaces)
        artifact_hashes_by_request: dict[str, set[str]] = {}
        for surface in surfaces:
            for reference in surface.evidence_references:
                if reference.credited:
                    artifact_hashes_by_request.setdefault(reference.request_id, set()).add(
                        reference.artifact_sha256
                    )
        for surface in surfaces:
            credited_lineages: set[str] = set()
            has_evaluated_evidence = not surface.evidence_references
            for reference in surface.evidence_references:
                joined = usage_by_request.get(reference.request_id)
                pending = pending_usage_by_request.get(reference.request_id)
                if not reference.credited:
                    has_evaluated_evidence = True
                    continue
                if len(artifact_hashes_by_request.get(reference.request_id, set())) != 1:
                    has_evaluated_evidence = True
                    continue
                if joined is not None:
                    has_evaluated_evidence = True
                    usage, lineage = joined
                    if _model_reference_matches_usage(reference, usage, lineage=lineage):
                        credited_lineages.add(lineage)
                    continue
                if pending is not None:
                    usage, lineage = pending
                    if _model_reference_matches_usage(reference, usage, lineage=lineage):
                        continue
                has_evaluated_evidence = True
            input_failed = _report_input_is_failed_evaluation(report_input)
            if input_failed or (report_input.usable and has_evaluated_evidence):
                surface_evaluated += 1
            if credited_lineages:
                reviewed_surfaces += 1
            if not surface.critical:
                continue
            critical_denominator += 1
            if input_failed or (report_input.usable and has_evaluated_evidence):
                critical_evaluated += 1
            if len(credited_lineages) >= coverage.minimum_critical_root_lineages:
                reviewed_critical += 1
    return (
        model_call_metric,
        _rate_metric(
            numerator=reviewed_surfaces,
            denominator=surface_denominator,
            evaluated=surface_evaluated,
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="surfaces with explicit validated records from approved real model calls",
        ),
        _rate_metric(
            numerator=reviewed_critical,
            denominator=critical_denominator,
            evaluated=critical_evaluated,
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="critical surfaces reviewed by the required independent real lineages",
        ),
    )


def _qualified_usage_lineage(
    record: UsageRecord,
    *,
    require_certification: bool,
) -> str | None:
    if not is_creditable_usage_record(
        record,
        require_real=True,
        require_certification=require_certification,
    ):
        return None
    return _validated_qualified_usage_lineage(record)


def _report_input_is_failed_evaluation(report_input: BenchmarkReportInput) -> bool:
    return report_input.status in {
        BenchmarkReportInputStatus.MALFORMED,
        BenchmarkReportInputStatus.STALE,
        BenchmarkReportInputStatus.FAILED,
    }


def _authority_pending_usage_lineage(
    record: UsageRecord,
    *,
    require_certification: bool,
) -> str | None:
    """Return lineage only for coherent REAL evidence missing live runtime authority."""

    if is_creditable_usage_record(
        record,
        require_real=True,
        require_certification=require_certification,
    ) or not _is_structurally_creditable_usage_record(
        record,
        require_real=True,
        require_certification=require_certification,
    ):
        return None
    return _validated_qualified_usage_lineage(record)


def _validated_qualified_usage_lineage(record: UsageRecord) -> str | None:
    routing = record.routing
    lineage = routing.get("qualified_root_lineage")
    qualified_roles = routing.get("qualified_roles")
    required_hashes = (
        "qualified_endpoint_snapshot_sha256",
        "qualified_model_metadata_snapshot_sha256",
        "qualified_pricing_snapshot_sha256",
        "qualification_artifact_sha256",
        "qualification_verification_sha256",
        "production_selection_sha256",
        "selection_verification_sha256",
        "qualification_result_sha256",
    )
    if (
        not isinstance(lineage, str)
        or re.fullmatch(r"^sha256:[0-9a-f]{64}$", lineage) is None
        or routing.get("qualified_exact_model_id") != record.requested_model
        or routing.get("qualified_canonical_model_slug") != routing.get("canonical_model")
        or routing.get("qualified_provider_endpoint") != record.actual_provider_endpoint
        or routing.get("qualified_provider_name") != record.provider
        or not isinstance(qualified_roles, list)
        or record.role not in qualified_roles
        or any(
            not isinstance(routing.get(name), str)
            or re.fullmatch(_SHA256_PATTERN, routing[name]) is None
            for name in required_hashes
        )
    ):
        return None
    return lineage


def _model_reference_matches_usage(
    reference: ModelReviewEvidenceReference,
    usage: UsageRecord,
    *,
    lineage: str,
) -> bool:
    return (
        reference.requested_model == usage.requested_model
        and reference.model == usage.actual_model
        and reference.review_role == usage.role
        and reference.root_lineage == lineage
    )


def _mutation_rate_metric(
    scorecard: MutationScorecard | None,
) -> BenchmarkRateMetric:
    if (
        scorecard is None
        or not scorecard.outcomes
        or not _mutation_scorecard_has_runtime_credit(scorecard)
    ):
        return _unavailable_metric(
            "runtime-attested typed invariant mutation scorecard is unavailable",
            direction=BenchmarkMetricDirection.MINIMUM,
            threshold=1,
        )
    evaluated_outcomes = [
        outcome
        for outcome in scorecard.outcomes
        if outcome.outcome
        in {
            MutationTestOutcome.KILLED,
            MutationTestOutcome.SURVIVED,
        }
    ]
    return _rate_metric(
        numerator=sum(
            outcome.outcome is MutationTestOutcome.KILLED for outcome in evaluated_outcomes
        ),
        denominator=len(scorecard.outcomes),
        evaluated=len(evaluated_outcomes),
        threshold=MAXIMUM_ASSURANCE_MINIMUM_PROPERTY_KILL_SCORE,
        direction=BenchmarkMetricDirection.MINIMUM,
        detail="executed typed invariant-property mutation outcomes",
    )


def _economic_metrics(
    reports: dict[str, AuditReport],
    report_inputs: list[BenchmarkReportInput],
) -> tuple[BenchmarkRateMetric, BenchmarkRateMetric]:
    inputs_by_repository = {item.repository_id: item for item in report_inputs}
    records: list[tuple[bool, EconomicTemplateExecutionCoverage]] = []
    missing_assessments = 0
    for report_input in report_inputs:
        report = reports.get(report_input.repository_id)
        coverage = report.effective_solidity_coverage() if report is not None else None
        if coverage is None or not coverage.economic_template_execution:
            missing_assessments += 1
            continue
        records.extend(
            (inputs_by_repository[report_input.repository_id].usable, record)
            for record in coverage.economic_template_execution.values()
        )
    applicability_denominator = len(records) + missing_assessments
    applicability_evaluated = sum(usable for usable, _record in records)
    execution_records = [
        (usable, record)
        for usable, record in records
        if record.applicable and record.execution_required
    ]
    execution_evaluated = sum(usable for usable, _record in execution_records)
    execution_successes = sum(
        usable and record.harnesses_executed > 0 for usable, record in execution_records
    )
    return (
        _rate_metric(
            numerator=applicability_evaluated,
            denominator=applicability_denominator,
            evaluated=applicability_evaluated,
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="economic template kinds with typed applicability assessments",
        ),
        _rate_metric(
            numerator=execution_successes,
            denominator=len(execution_records) + missing_assessments,
            evaluated=execution_evaluated,
            threshold=1,
            direction=BenchmarkMetricDirection.MINIMUM,
            detail="applicable required economic templates with executed typed harnesses",
        ),
    )


def _combine_states(*states: BenchmarkMetricState) -> BenchmarkMetricState:
    for state in (
        BenchmarkMetricState.FAIL,
        BenchmarkMetricState.INCONCLUSIVE,
        BenchmarkMetricState.NOT_EVALUABLE,
        BenchmarkMetricState.NOT_APPLICABLE,
    ):
        if state in states:
            return state
    return BenchmarkMetricState.PASS


def _gate(
    *,
    name: Literal[
        "known_critical_recall",
        "safe_control_false_confirmations",
        "exact_ground_truth_locations",
        "repository_metrics_unmasked",
        "evidence_caps",
        "coverage_present",
        "maximum_assurance_complete",
        "maximum_assurance_repository_mutation_score",
        "maximum_assurance_semantic_coverage",
        "maximum_assurance_property_mutation_score",
        "maximum_assurance_real_model_calls",
        "maximum_assurance_substantive_model_review",
    ],
    state: BenchmarkMetricState,
    detail: str,
) -> BenchmarkGate:
    return BenchmarkGate(
        name=name,
        state=state,
        passed=state is BenchmarkMetricState.PASS,
        detail=detail,
    )


def _repository_gate_state(
    repository_metrics: list[BenchmarkRepositoryMetrics],
) -> BenchmarkMetricState:
    loaded = sum(item.report_loaded for item in repository_metrics)
    if loaded == 0:
        return BenchmarkMetricState.NOT_EVALUABLE
    if loaded < len(repository_metrics):
        return BenchmarkMetricState.INCONCLUSIVE
    return (
        BenchmarkMetricState.PASS
        if all(_repository_quality_passed(item) for item in repository_metrics)
        else BenchmarkMetricState.FAIL
    )


def _coverage_present_state(
    report_inputs: list[BenchmarkReportInput],
    reports: dict[str, AuditReport],
) -> BenchmarkMetricState:
    usable = [item for item in report_inputs if item.usable]
    if not usable:
        return BenchmarkMetricState.NOT_EVALUABLE
    if len(usable) < len(report_inputs):
        return BenchmarkMetricState.INCONCLUSIVE
    return (
        BenchmarkMetricState.PASS
        if all(
            reports[item.repository_id].effective_solidity_coverage() is not None for item in usable
        )
        else BenchmarkMetricState.FAIL
    )


def _complete_portfolio_state(
    report_inputs: list[BenchmarkReportInput],
    *,
    passed: bool,
) -> BenchmarkMetricState:
    usable = sum(item.usable for item in report_inputs)
    if usable == 0:
        return BenchmarkMetricState.NOT_EVALUABLE
    if usable < len(report_inputs):
        return BenchmarkMetricState.INCONCLUSIVE
    return BenchmarkMetricState.PASS if passed else BenchmarkMetricState.FAIL


def _report_input_coverage_state(
    report_inputs: list[BenchmarkReportInput],
) -> BenchmarkMetricState:
    usable = sum(item.usable for item in report_inputs)
    if usable == 0:
        return BenchmarkMetricState.NOT_EVALUABLE
    if usable < len(report_inputs):
        return BenchmarkMetricState.INCONCLUSIVE
    return BenchmarkMetricState.PASS


def _mutation_gate_state(
    scorecard: MutationScorecard | None,
    report_inputs: list[BenchmarkReportInput],
    passed: bool,
) -> BenchmarkMetricState:
    if (
        scorecard is None
        or not scorecard.outcomes
        or not _mutation_scorecard_has_runtime_credit(scorecard)
    ):
        return BenchmarkMetricState.NOT_EVALUABLE
    if any(not item.usable for item in report_inputs):
        return BenchmarkMetricState.INCONCLUSIVE
    return BenchmarkMetricState.PASS if passed else BenchmarkMetricState.FAIL


def _semantic_coverage_state(
    report_inputs: list[BenchmarkReportInput],
    *,
    missing_metrics: list[str],
    incomplete_metrics: list[str],
) -> BenchmarkMetricState:
    usable = sum(item.usable for item in report_inputs)
    if usable == 0:
        return BenchmarkMetricState.NOT_EVALUABLE
    if usable < len(report_inputs):
        return BenchmarkMetricState.INCONCLUSIVE
    return (
        BenchmarkMetricState.PASS
        if not missing_metrics and not incomplete_metrics
        else BenchmarkMetricState.FAIL
    )


def _combined_false_confirmation_value(
    critical: BenchmarkRateMetric,
    high: BenchmarkRateMetric,
) -> float | None:
    if critical.value is None or high.value is None:
        return None
    denominator = critical.denominator + high.denominator
    if denominator == 0:
        return None
    return round((critical.numerator + high.numerator) / denominator, 6)


def _nonnegative_metadata_float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    normalized = float(value)
    return normalized if math.isfinite(normalized) and normalized >= 0 else None


def _resolve_ground_truth_path(
    root: Path,
    relative_path: str,
    *,
    expect_directory: bool,
) -> Path:
    normalized = normalize_relative_path(relative_path)
    candidate = root / normalized
    if candidate.is_symlink() or candidate.is_junction():
        raise ValueError("benchmark ground-truth paths may not be links")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root)
    if expect_directory and not resolved.is_dir():
        raise ValueError("benchmark repository source root must be a directory")
    if not expect_directory and not resolved.is_file():
        raise ValueError("benchmark ground-truth source must be a regular file")
    return resolved


def _aggregate_repository_coverage(
    repositories: list[BenchmarkRepositoryMetrics],
) -> dict[str, BenchmarkCoverageMetric]:
    """Aggregate per-repository typed coverage without hiding missing reports."""

    totals: dict[str, tuple[int, int, int]] = {}
    inventory = sorted(
        set(_BENCHMARK_REQUIRED_COVERAGE_METRICS)
        | {name for repository in repositories for name in repository.coverage_metrics}
    )
    for repository in repositories:
        for name in inventory:
            metric = repository.coverage_metrics.get(name)
            previous_numerator, previous_denominator, previous_evaluated = totals.get(
                name,
                (0, 0, 0),
            )
            if metric is None:
                totals[name] = (
                    previous_numerator,
                    previous_denominator + 1,
                    previous_evaluated,
                )
                continue
            totals[name] = (
                previous_numerator + metric.numerator,
                previous_denominator + metric.denominator,
                previous_evaluated + metric.evaluated,
            )
    return {
        name: BenchmarkCoverageMetric(
            numerator=numerator,
            denominator=denominator,
            evaluated=evaluated,
            percentage=(
                round((numerator / denominator) * 100, 4)
                if denominator and evaluated == denominator
                else None
            ),
            state=(
                BenchmarkMetricState.NOT_EVALUABLE
                if evaluated == 0
                else (
                    BenchmarkMetricState.INCONCLUSIVE
                    if evaluated < denominator
                    else (
                        BenchmarkMetricState.PASS
                        if numerator == denominator
                        else BenchmarkMetricState.FAIL
                    )
                )
            ),
            detail="typed Solidity coverage aggregated across expected reports",
        )
        for name, (numerator, denominator, evaluated) in sorted(totals.items())
    }


def _coverage_projection(
    metric: BenchmarkCoverageMetric,
) -> tuple[int, int, int, float | None, BenchmarkMetricState]:
    return (
        metric.numerator,
        metric.denominator,
        metric.evaluated,
        metric.percentage,
        metric.state,
    )


def _maximum_assurance_repository_coverage_gaps(
    repositories: list[BenchmarkRepositoryMetrics],
) -> tuple[list[str], list[str]]:
    missing: list[str] = []
    incomplete: list[str] = []
    for repository in repositories:
        if not repository.report_loaded or not repository.coverage_metrics:
            missing.extend(
                f"{repository.repository_id}:{name}"
                for name in _MAXIMUM_ASSURANCE_REQUIRED_COVERAGE_METRICS
            )
            continue
        for name in _MAXIMUM_ASSURANCE_REQUIRED_COVERAGE_METRICS:
            metric = repository.coverage_metrics.get(name)
            label = f"{repository.repository_id}:{name}"
            if metric is None:
                missing.append(label)
                continue
            if metric.denominator == 0:
                incomplete.append(label)
                continue
            if metric.numerator < metric.denominator:
                incomplete.append(label)
    return missing, incomplete


def _weak_maximum_assurance_mutation_properties(
    scorecard: MutationScorecard | None,
) -> list[str]:
    if scorecard is None:
        return []
    if not _mutation_scorecard_has_runtime_credit(scorecard):
        return list(scorecard.expected_property_ids)
    return [
        score.property_id
        for score in scorecard.property_scores
        if score.applicable_mutations == 0
        or score.inconclusive > 0
        or score.kill_score is None
        or score.kill_score < MAXIMUM_ASSURANCE_MINIMUM_PROPERTY_KILL_SCORE
    ]


def _mutation_scorecard_has_runtime_credit(scorecard: MutationScorecard) -> bool:
    """Credit only explicitly supported runtime-attested origins.

    No such origin exists until a production runner can bind execution custody
    independently from caller-authored serialized evidence.
    """

    return scorecard.evidence_origin in _RUNTIME_CREDITING_MUTATION_SCORECARD_ORIGINS
