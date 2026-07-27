"""Evaluate mmaudit reports against an explicit, source-attributed corpus."""

from __future__ import annotations

import hashlib
import json
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
from mmaudit.benchmark.mutations import MutationScorecard, MutationTestOutcome
from mmaudit.constants import SEVERITY_ORDER
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    EvidenceStrength,
    Finding,
    FindingStatus,
    MaximumAssuranceStatus,
    ReproductionState,
    Severity,
    StrictModel,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path

_MAXIMUM_ASSURANCE_REQUIRED_COVERAGE_METRICS = (
    "public_external_entry_points_reviewed",
    "external_calls_classified",
    "asset_flows_classified",
    "storage_variables_modelled",
    "invariants_executed",
    "economic_templates_executed",
    "economic_templates_with_typed_harness",
)
MAXIMUM_ASSURANCE_MINIMUM_PROPERTY_KILL_SCORE = 1.0
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_GROUND_TRUTH_SOURCE_BYTES = 10_000_000


class BenchmarkStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


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
    case_id: str
    repository_id: str
    variant: Literal["vulnerable", "safe", "ambiguous"]
    detected: bool
    confirmed: bool
    reproduced: bool = False
    exact_location: bool = False
    matched_finding_ids: list[str] = Field(default_factory=list)
    cwe_match: bool = False
    limitation: str | None = None

    @model_validator(mode="after")
    def evidence_flags_are_consistent(self) -> BenchmarkCaseResult:
        if self.matched_finding_ids != sorted(set(self.matched_finding_ids)):
            raise ValueError("benchmark matched finding IDs must be unique and sorted")
        if (self.confirmed or self.reproduced or self.exact_location) and not self.detected:
            raise ValueError("benchmark evidence flags require an active detection")
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
    name: str
    passed: bool
    detail: str


class BenchmarkCoverageMetric(StrictModel):
    """Aggregate an existing coverage numerator/denominator across reports."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    percentage: float | None = Field(default=None, ge=0, le=100)

    @model_validator(mode="after")
    def ratio_is_consistent(self) -> BenchmarkCoverageMetric:
        expected = round((self.numerator / self.denominator) * 100, 4) if self.denominator else None
        if self.numerator > self.denominator or self.percentage != expected:
            raise ValueError("benchmark coverage ratio is inconsistent")
        return self


class BenchmarkRepositoryMetrics(StrictModel):
    """Explicit metrics for one repository; global averages cannot replace these."""

    repository_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    report_loaded: bool
    vulnerable_cases: int = Field(ge=0)
    vulnerable_cases_detected: int = Field(ge=0)
    recall: float | None = Field(default=None, ge=0, le=1)
    critical_cases: int = Field(ge=0)
    critical_cases_detected: int = Field(ge=0)
    critical_recall: float | None = Field(default=None, ge=0, le=1)
    safe_cases: int = Field(ge=0)
    safe_false_confirmations: int = Field(ge=0)
    safe_false_confirmation_rate: float | None = Field(default=None, ge=0, le=1)
    location_cases: int = Field(ge=0)
    exact_locations: int = Field(ge=0)
    location_accuracy: float | None = Field(default=None, ge=0, le=1)
    vulnerable_cases_reproduced: int = Field(ge=0)
    reproduction_success_rate: float | None = Field(default=None, ge=0, le=1)
    mutation_property_ids: list[str] = Field(default_factory=list, max_length=10_000)
    mutation_kill_score: float | None = Field(default=None, ge=0, le=1)
    mutation_gate_passed: bool | None = None
    cost_usd: float | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    runtime_seconds: float | None = Field(default=None, ge=0)
    time_to_first_valid_finding_seconds: float | None = Field(default=None, ge=0)

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
            expected = round(numerator / denominator, 6) if denominator else None
            if numerator > denominator or observed != expected:
                raise ValueError(f"repository benchmark {name} is inconsistent")
        if self.location_cases != self.vulnerable_cases:
            raise ValueError("repository location denominator must cover every vulnerable case")
        if self.mutation_property_ids != sorted(set(self.mutation_property_ids)):
            raise ValueError("repository mutation property IDs must be unique and sorted")
        has_mutation_evidence = bool(self.mutation_property_ids)
        if has_mutation_evidence != (self.mutation_gate_passed is not None):
            raise ValueError("repository mutation metrics require complete property evidence")
        if not has_mutation_evidence and self.mutation_kill_score is not None:
            raise ValueError("repository mutation score requires attributed properties")
        if self.report_loaded != (self.cost_usd is not None and self.total_tokens is not None):
            raise ValueError("repository cost and token metrics must match report availability")
        if not self.report_loaded and (
            self.runtime_seconds is not None or self.time_to_first_valid_finding_seconds is not None
        ):
            raise ValueError("missing repository reports cannot claim runtime evidence")
        return self


class BenchmarkReport(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    corpus_name: str
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    blinding: BenchmarkBlindingProtocol
    profile: AuditProfile
    status: BenchmarkStatus
    reports_expected: int
    reports_loaded: int
    vulnerable_cases: int
    vulnerable_cases_detected: int
    vulnerable_cases_reproduced: int
    critical_cases: int
    critical_cases_detected: int
    safe_cases: int
    safe_high_critical_confirmations: int
    evidence_cap_bypasses: int
    reports_missing_coverage: int
    model_only_findings_kept_below_confirmed: int
    recall: float
    recall_by_severity: dict[str, float]
    critical_recall: float
    precision: float
    false_positive_rate: float
    safe_false_confirmation_rate: float
    reproduction_success_rate: float
    location_cases: int
    exact_locations: int
    location_accuracy: float
    total_cost_usd: float
    total_tokens: int
    total_runtime_seconds: float | None = None
    time_to_first_valid_finding_seconds: float | None = None
    unique_finding_contribution_by_role: dict[str, int] = Field(default_factory=dict)
    unique_finding_contribution_by_family: dict[str, int] = Field(default_factory=dict)
    mutation_scorecard: MutationScorecard | None = None
    superiority_claim: SuperiorityClaimAssessment = Field(
        default_factory=evaluate_superiority_claim
    )
    coverage_metrics: dict[str, BenchmarkCoverageMetric] = Field(default_factory=dict)
    repository_metrics: list[BenchmarkRepositoryMetrics]
    case_results: list[BenchmarkCaseResult]
    gates: list[BenchmarkGate]
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def gates_are_unique_and_consistent(self) -> BenchmarkReport:
        gate_names = [gate.name for gate in self.gates]
        if len(gate_names) != len(set(gate_names)):
            raise ValueError("benchmark gate names must be unique")
        if self.status is BenchmarkStatus.PASSED and not all(gate.passed for gate in self.gates):
            raise ValueError("passed benchmark reports require every gate to pass")
        repository_ids = [item.repository_id for item in self.repository_metrics]
        if repository_ids != sorted(set(repository_ids)):
            raise ValueError("benchmark repository metrics must be unique and sorted")
        case_ids = [item.case_id for item in self.case_results]
        if case_ids != sorted(set(case_ids)):
            raise ValueError("benchmark case results must be unique and sorted")
        if self.reports_expected != len(self.repository_metrics):
            raise ValueError("benchmark expected-report count must cover every repository")
        if self.reports_loaded != sum(item.report_loaded for item in self.repository_metrics):
            raise ValueError("benchmark loaded-report count is inconsistent")
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
            "safe_high_critical_confirmations": sum(
                item.safe_false_confirmations for item in self.repository_metrics
            ),
            "location_cases": sum(item.location_cases for item in self.repository_metrics),
            "exact_locations": sum(item.exact_locations for item in self.repository_metrics),
        }
        if any(getattr(self, name) != expected for name, expected in count_fields.items()):
            raise ValueError("benchmark aggregate counts do not match repository metrics")
        ratio_fields = {
            "recall": _bounded_ratio(
                self.vulnerable_cases_detected,
                self.vulnerable_cases,
                empty=0.0,
            ),
            "critical_recall": _bounded_ratio(
                self.critical_cases_detected,
                self.critical_cases,
                empty=0.0,
            ),
            "safe_false_confirmation_rate": _bounded_ratio(
                self.safe_high_critical_confirmations,
                self.safe_cases,
                empty=0.0,
            ),
            "reproduction_success_rate": _bounded_ratio(
                self.vulnerable_cases_reproduced,
                self.vulnerable_cases,
                empty=0.0,
            ),
            "location_accuracy": _bounded_ratio(
                self.exact_locations,
                self.location_cases,
                empty=0.0,
            ),
        }
        if any(getattr(self, name) != expected for name, expected in ratio_fields.items()):
            raise ValueError("benchmark aggregate rates do not match repository metrics")
        repository_cost = sum(item.cost_usd or 0 for item in self.repository_metrics)
        repository_tokens = sum(item.total_tokens or 0 for item in self.repository_metrics)
        repository_runtime = [
            item.runtime_seconds
            for item in self.repository_metrics
            if item.runtime_seconds is not None
        ]
        if self.total_cost_usd != repository_cost or self.total_tokens != repository_tokens:
            raise ValueError("benchmark aggregate cost or tokens do not match repositories")
        expected_runtime = sum(repository_runtime) if repository_runtime else None
        if self.total_runtime_seconds != expected_runtime:
            raise ValueError("benchmark aggregate runtime does not match repositories")
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
        if self.profile is AuditProfile.MAXIMUM_ASSURANCE:
            mutation_gates = [
                gate
                for gate in self.gates
                if gate.name == "maximum_assurance_property_mutation_score"
            ]
            expected_passed = (
                self.mutation_scorecard is not None
                and not _weak_maximum_assurance_mutation_properties(self.mutation_scorecard)
            )
            if len(mutation_gates) != 1 or mutation_gates[0].passed != expected_passed:
                raise ValueError("maximum-assurance mutation gate is inconsistent")
            repository_mutation_gates = [
                gate
                for gate in self.gates
                if gate.name == "maximum_assurance_repository_mutation_score"
            ]
            expected_repository_passed = all(
                item.mutation_gate_passed is True for item in self.repository_metrics
            )
            if (
                len(repository_mutation_gates) != 1
                or repository_mutation_gates[0].passed != expected_repository_passed
            ):
                raise ValueError("maximum-assurance repository mutation gate is inconsistent")
        return self


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
) -> tuple[dict[str, AuditReport], list[str]]:
    """Load only expected report paths beneath a caller-selected directory."""

    resolved_root = root.resolve(strict=True)
    reports: dict[str, AuditReport] = {}
    limitations: list[str] = []
    for repository_id in sorted(repository_ids):
        candidates = [
            resolved_root / repository_id / "final-findings.json",
            resolved_root / f"{repository_id}.json",
        ]
        report_path = next((path for path in candidates if path.is_file()), None)
        if report_path is None:
            limitations.append(f"missing report for repository {repository_id}")
            continue
        if report_path.is_symlink() or report_path.stat().st_size > 100_000_000:
            limitations.append(f"unsafe or oversized report for repository {repository_id}")
            continue
        report_path.resolve(strict=True).relative_to(resolved_root)
        try:
            reports[repository_id] = AuditReport.model_validate_json(
                report_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            limitations.append(
                f"invalid report for repository {repository_id}: {type(exc).__name__}"
            )
    return reports, limitations


def evaluate_benchmark(
    manifest: BenchmarkManifest,
    reports: dict[str, AuditReport],
    *,
    profile: AuditProfile,
    initial_limitations: list[str] | None = None,
    mutation_scorecard: MutationScorecard | None = None,
    superiority_evidence: HumanComparisonEvidence | None = None,
) -> BenchmarkReport:
    """Calculate evidence-aware regression metrics from actual audit reports."""

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

    results: list[BenchmarkCaseResult] = []
    for case in sorted(manifest.cases, key=lambda item: item.id):
        report = reports.get(case.repository_id)
        if report is None:
            results.append(
                BenchmarkCaseResult(
                    case_id=case.id,
                    repository_id=case.repository_id,
                    variant=case.variant,
                    detected=False,
                    confirmed=False,
                    limitation="audit report unavailable",
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
        reproduced = [
            finding
            for finding in active
            if finding.reproduction_state
            in {
                ReproductionState.REPRODUCED,
                ReproductionState.REPRODUCED_AND_MINIMIZED,
                ReproductionState.FORMALLY_PROVEN,
            }
            or finding.evidence_strength is EvidenceStrength.FORMAL_COUNTEREXAMPLE
        ]
        results.append(
            BenchmarkCaseResult(
                case_id=case.id,
                repository_id=case.repository_id,
                variant=case.variant,
                detected=bool(active),
                confirmed=bool(confirmed),
                reproduced=bool(reproduced),
                exact_location=any(_matches_case_exactly(finding, case) for finding in active),
                matched_finding_ids=sorted({finding.id for finding in matches}),
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
    missing_coverage = sum(
        1
        for report in reports.values()
        if not isinstance(report.metadata.get("solidity"), dict)
        or not report.metadata["solidity"].get("coverage")
    )
    false_confirmations = sum(result.confirmed for result in safe)
    safe_detections = sum(result.detected for result in safe)
    detected_vulnerable = sum(result.detected for result in vulnerable)
    reproduced_vulnerable = sum(result.reproduced for result in vulnerable)
    exact_locations = sum(result.exact_location for result in vulnerable)
    detected_critical = sum(result.detected for result in critical)
    findings = [finding for report in reports.values() for finding in report.findings]
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
    recall_by_severity = {
        severity.value: (
            sum(result.detected for result in severity_results) / len(severity_results)
            if severity_results
            else 0.0
        )
        for severity in Severity
        if (
            severity_results := [
                result
                for result in vulnerable
                if next(
                    case for case in manifest.cases if case.id == result.case_id
                ).minimum_severity
                is severity
            ]
        )
    }
    coverage_metrics = _aggregate_coverage(reports)
    repository_metrics = _repository_metrics(
        manifest=manifest,
        results=results,
        reports=reports,
        mutation_scorecard=mutation_scorecard,
    )
    total_cost = sum(item.cost_usd or 0 for item in repository_metrics)
    total_tokens = sum(item.total_tokens or 0 for item in repository_metrics)
    runtime_values = [
        item.runtime_seconds for item in repository_metrics if item.runtime_seconds is not None
    ]
    first_finding_values = [
        item.time_to_first_valid_finding_seconds
        for item in repository_metrics
        if item.time_to_first_valid_finding_seconds is not None
    ]
    report_ids = repository_ids
    limitations = list(initial_limitations or [])
    repositories_passed = all(_repository_quality_passed(item) for item in repository_metrics)
    gates = [
        BenchmarkGate(
            name="known_critical_recall",
            passed=bool(critical) and detected_critical == len(critical),
            detail=f"{detected_critical}/{len(critical)} critical cases detected",
        ),
        BenchmarkGate(
            name="safe_control_false_confirmations",
            passed=false_confirmations == 0,
            detail=f"{false_confirmations} safe high/critical case(s) confirmed",
        ),
        BenchmarkGate(
            name="exact_ground_truth_locations",
            passed=bool(vulnerable) and exact_locations == len(vulnerable),
            detail=f"{exact_locations}/{len(vulnerable)} vulnerable locations matched exactly",
        ),
        BenchmarkGate(
            name="repository_metrics_unmasked",
            passed=repositories_passed,
            detail=(
                "every repository passed critical recall, safe confirmation, "
                "exact-location, and reproduction checks"
                if repositories_passed
                else "one or more repositories failed an unmasked quality metric"
            ),
        ),
        BenchmarkGate(
            name="evidence_caps",
            passed=cap_bypasses == 0,
            detail=f"{cap_bypasses} confirmed finding(s) bypassed evidence caps",
        ),
        BenchmarkGate(
            name="coverage_present",
            passed=len(reports) == len(report_ids) and missing_coverage == 0,
            detail=f"{missing_coverage} loaded report(s) omitted Solidity coverage",
        ),
    ]
    if profile is AuditProfile.MAXIMUM_ASSURANCE:
        incomplete_maximum = [
            repository_id
            for repository_id, report in reports.items()
            if report.maximum_assurance is None
            or report.maximum_assurance.status is not MaximumAssuranceStatus.COMPLETE
        ]
        gates.append(
            BenchmarkGate(
                name="maximum_assurance_complete",
                passed=not incomplete_maximum and len(reports) == len(report_ids),
                detail=(
                    "all benchmark reports are COMPLETE"
                    if not incomplete_maximum and len(reports) == len(report_ids)
                    else "non-COMPLETE repositories: "
                    + ", ".join(sorted(incomplete_maximum or (report_ids - set(reports))))
                ),
            )
        )
        gates.append(
            BenchmarkGate(
                name="maximum_assurance_repository_mutation_score",
                passed=all(item.mutation_gate_passed is True for item in repository_metrics),
                detail=(
                    "every repository passed its attributed property mutation score"
                    if all(item.mutation_gate_passed is True for item in repository_metrics)
                    else "one or more repositories lack a passing attributed mutation score"
                ),
            )
        )
        missing_metrics, incomplete_metrics = _maximum_assurance_coverage_gaps(reports)
        gates.append(
            BenchmarkGate(
                name="maximum_assurance_semantic_coverage",
                passed=not missing_metrics and not incomplete_metrics,
                detail=(
                    "required semantic coverage metrics are complete"
                    if not missing_metrics and not incomplete_metrics
                    else "missing metrics: "
                    + ", ".join(missing_metrics or ["none"])
                    + "; incomplete metrics: "
                    + ", ".join(incomplete_metrics or ["none"])
                ),
            )
        )
        weak_properties = _weak_maximum_assurance_mutation_properties(mutation_scorecard)
        gates.append(
            BenchmarkGate(
                name="maximum_assurance_property_mutation_score",
                passed=mutation_scorecard is not None and not weak_properties,
                detail=(
                    "every expected property killed all applicable mutations"
                    if mutation_scorecard is not None and not weak_properties
                    else (
                        "mutation scorecard unavailable"
                        if mutation_scorecard is None
                        else "properties below the 1.0 kill-score gate: "
                        + ", ".join(weak_properties)
                    )
                ),
            )
        )
    if len(reports) < len(report_ids):
        status = BenchmarkStatus.INCOMPLETE
    elif all(gate.passed for gate in gates):
        status = BenchmarkStatus.PASSED
    else:
        status = BenchmarkStatus.FAILED
    return BenchmarkReport(
        corpus_name=manifest.name,
        corpus_sha256=manifest.corpus_sha256,
        blinding=manifest.blinding,
        profile=profile,
        status=status,
        reports_expected=len(report_ids),
        reports_loaded=len(reports),
        vulnerable_cases=len(vulnerable),
        vulnerable_cases_detected=detected_vulnerable,
        vulnerable_cases_reproduced=reproduced_vulnerable,
        critical_cases=len(critical),
        critical_cases_detected=detected_critical,
        safe_cases=len(safe),
        safe_high_critical_confirmations=false_confirmations,
        evidence_cap_bypasses=cap_bypasses,
        reports_missing_coverage=missing_coverage,
        model_only_findings_kept_below_confirmed=model_only_capped,
        recall=_bounded_ratio(detected_vulnerable, len(vulnerable), empty=0.0),
        recall_by_severity=recall_by_severity,
        critical_recall=_bounded_ratio(detected_critical, len(critical), empty=0.0),
        precision=(
            detected_vulnerable / (detected_vulnerable + safe_detections)
            if detected_vulnerable + safe_detections
            else 0
        ),
        false_positive_rate=safe_detections / len(safe) if safe else 0,
        safe_false_confirmation_rate=_bounded_ratio(
            false_confirmations,
            len(safe),
            empty=0.0,
        ),
        reproduction_success_rate=_bounded_ratio(
            reproduced_vulnerable,
            len(vulnerable),
            empty=0.0,
        ),
        location_cases=len(vulnerable),
        exact_locations=exact_locations,
        location_accuracy=_bounded_ratio(exact_locations, len(vulnerable), empty=0.0),
        total_cost_usd=total_cost,
        total_tokens=total_tokens,
        total_runtime_seconds=sum(runtime_values) if runtime_values else None,
        time_to_first_valid_finding_seconds=(
            min(first_finding_values) if first_finding_values else None
        ),
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _matches_case(finding: Finding, case: BenchmarkCase) -> bool:
    return any(
        location.path == case.path
        and location.start_line <= case.end_line
        and case.start_line <= location.end_line
        for location in finding.locations
    )


def _matches_case_exactly(finding: Finding, case: BenchmarkCase) -> bool:
    return any(
        location.path == case.path
        and location.start_line == case.start_line
        and location.end_line == case.end_line
        for location in finding.locations
    )


def _repository_metrics(
    *,
    manifest: BenchmarkManifest,
    results: list[BenchmarkCaseResult],
    reports: dict[str, AuditReport],
    mutation_scorecard: MutationScorecard | None,
) -> list[BenchmarkRepositoryMetrics]:
    cases_by_id = {case.id: case for case in manifest.cases}
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
        report = reports.get(repository.repository_id)
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
        metrics.append(
            BenchmarkRepositoryMetrics(
                repository_id=repository.repository_id,
                report_loaded=report is not None,
                vulnerable_cases=len(vulnerable),
                vulnerable_cases_detected=sum(item.detected for item in vulnerable),
                recall=_bounded_ratio(
                    sum(item.detected for item in vulnerable),
                    len(vulnerable),
                    empty=None,
                ),
                critical_cases=len(critical),
                critical_cases_detected=sum(item.detected for item in critical),
                critical_recall=_bounded_ratio(
                    sum(item.detected for item in critical),
                    len(critical),
                    empty=None,
                ),
                safe_cases=len(safe),
                safe_false_confirmations=sum(item.confirmed for item in safe),
                safe_false_confirmation_rate=_bounded_ratio(
                    sum(item.confirmed for item in safe),
                    len(safe),
                    empty=None,
                ),
                location_cases=len(vulnerable),
                exact_locations=sum(item.exact_location for item in vulnerable),
                location_accuracy=_bounded_ratio(
                    sum(item.exact_location for item in vulnerable),
                    len(vulnerable),
                    empty=None,
                ),
                vulnerable_cases_reproduced=sum(item.reproduced for item in vulnerable),
                reproduction_success_rate=_bounded_ratio(
                    sum(item.reproduced for item in vulnerable),
                    len(vulnerable),
                    empty=None,
                ),
                mutation_property_ids=property_ids,
                mutation_kill_score=mutation_kill_score,
                mutation_gate_passed=mutation_gate_passed,
                cost_usd=report.accounted_cost_usd if report is not None else None,
                total_tokens=(
                    sum(record.total_tokens for record in report.usage)
                    if report is not None
                    else None
                ),
                runtime_seconds=runtime,
                time_to_first_valid_finding_seconds=first_finding,
            )
        )
    return metrics


def _repository_quality_passed(metrics: BenchmarkRepositoryMetrics) -> bool:
    return (
        (metrics.critical_cases == 0 or metrics.critical_recall == 1)
        and metrics.safe_false_confirmations == 0
        and (metrics.location_cases == 0 or metrics.location_accuracy == 1)
        and (metrics.vulnerable_cases == 0 or metrics.reproduction_success_rate == 1)
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


def _nonnegative_metadata_float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    normalized = float(value)
    return normalized if normalized >= 0 else None


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


def _aggregate_coverage(
    reports: dict[str, AuditReport],
) -> dict[str, BenchmarkCoverageMetric]:
    totals: dict[str, tuple[int, int]] = {}
    for report in reports.values():
        solidity = report.metadata.get("solidity")
        coverage = solidity.get("coverage") if isinstance(solidity, dict) else None
        metrics = coverage.get("quality_metrics") if isinstance(coverage, dict) else None
        if not isinstance(metrics, dict):
            continue
        for name, raw in metrics.items():
            if not isinstance(name, str) or not isinstance(raw, dict):
                continue
            numerator = raw.get("numerator")
            denominator = raw.get("denominator")
            if (
                not isinstance(numerator, int)
                or isinstance(numerator, bool)
                or not isinstance(denominator, int)
                or isinstance(denominator, bool)
                or numerator < 0
                or denominator < numerator
            ):
                continue
            previous_numerator, previous_denominator = totals.get(name, (0, 0))
            totals[name] = (
                previous_numerator + numerator,
                previous_denominator + denominator,
            )
    return {
        name: BenchmarkCoverageMetric(
            numerator=numerator,
            denominator=denominator,
            percentage=(round((numerator / denominator) * 100, 4) if denominator else None),
        )
        for name, (numerator, denominator) in sorted(totals.items())
    }


def _maximum_assurance_coverage_gaps(
    reports: dict[str, AuditReport],
) -> tuple[list[str], list[str]]:
    missing: list[str] = []
    incomplete: list[str] = []
    for repository_id, report in sorted(reports.items()):
        solidity = report.metadata.get("solidity")
        coverage = solidity.get("coverage") if isinstance(solidity, dict) else None
        metrics = coverage.get("quality_metrics") if isinstance(coverage, dict) else None
        for name in _MAXIMUM_ASSURANCE_REQUIRED_COVERAGE_METRICS:
            raw = metrics.get(name) if isinstance(metrics, dict) else None
            label = f"{repository_id}:{name}"
            if not isinstance(raw, dict):
                missing.append(label)
                continue
            numerator = raw.get("numerator")
            denominator = raw.get("denominator")
            if (
                not isinstance(numerator, int)
                or isinstance(numerator, bool)
                or not isinstance(denominator, int)
                or isinstance(denominator, bool)
                or numerator < 0
                or denominator < numerator
            ):
                incomplete.append(label)
                continue
            if denominator > 0 and numerator < denominator:
                incomplete.append(label)
    return missing, incomplete


def _weak_maximum_assurance_mutation_properties(
    scorecard: MutationScorecard | None,
) -> list[str]:
    if scorecard is None:
        return []
    return [
        score.property_id
        for score in scorecard.property_scores
        if score.applicable_mutations == 0
        or score.inconclusive > 0
        or score.kill_score is None
        or score.kill_score < MAXIMUM_ASSURANCE_MINIMUM_PROPERTY_KILL_SCORE
    ]
