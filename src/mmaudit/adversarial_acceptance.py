"""Typed acceptance evidence for the synthetic hostile-repository portfolio."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.secrets import is_sensitive_workspace_name

_MAX_MANIFEST_BYTES = 1_000_000
_MAX_FIXTURE_FILE_BYTES = 1_000_000
_MAX_FIXTURE_BYTES = 50_000
_MAX_REPORT_BYTES = 2_000_000


class AdversarialCaseId(StrEnum):
    CRAFTED_NAMES = "crafted_names"
    ENVIRONMENT_READ = "environment_read"
    FAKE_BINARIES = "fake_binaries"
    HOME_READ = "home_read"
    NETWORK_SOCKET = "network_socket"
    OUTPUT_ABUSE = "output_abuse"
    PATH_TRAVERSAL = "path_traversal"
    PROCESS_RESOURCE_ABUSE = "process_resource_abuse"
    PROMPT_INJECTION = "prompt_injection"
    SYMLINK_ESCAPE = "symlink_escape"


class AdversarialBoundary(StrEnum):
    REJECT_OR_ENCODE = "reject_or_encode"
    PRIVATE_ENVIRONMENT = "private_environment"
    REJECT_BEFORE_EXECUTION = "reject_before_execution"
    PRIVATE_HOME = "private_home"
    DENY_IN_ROOTLESS_BOUNDARY = "deny_in_rootless_boundary"
    BOUNDED_OUTPUT = "bounded_output"
    REJECT_OR_READ_ONLY_ROOT = "reject_or_read_only_root"
    BOUNDED_PROCESS = "bounded_process"
    UNTRUSTED_EVIDENCE = "untrusted_evidence"
    REJECT_BEFORE_COPY = "reject_before_copy"


class AdversarialDisposition(StrEnum):
    REJECTED_BEFORE_HOST_EXECUTION = "rejected_before_host_execution"
    DETERMINISTICALLY_CONTAINED = "deterministically_contained"
    REAL_ISOLATION_CONTAINED = "real_isolation_contained"


class AdversarialEvidenceKind(StrEnum):
    PATH_NORMALIZATION = "path_normalization"
    REPOSITORY_CODE_FAIL_CLOSED = "repository_code_fail_closed"
    EXTERNAL_EXECUTABLE_VALIDATION = "external_executable_validation"
    BOUNDED_OUTPUT = "bounded_output"
    BOUNDED_PROCESS = "bounded_process"
    UNTRUSTED_CONTEXT = "untrusted_context"
    WORKSPACE_VALIDATION = "workspace_validation"
    ROOTLESS_RUNTIME = "rootless_runtime"


class AdversarialAcceptanceStatus(StrEnum):
    PASSED = "passed"
    FAIL_CLOSED = "fail_closed"
    FAILED = "failed"


_EXPECTED_BOUNDARIES = {
    AdversarialCaseId.CRAFTED_NAMES: AdversarialBoundary.REJECT_OR_ENCODE,
    AdversarialCaseId.ENVIRONMENT_READ: AdversarialBoundary.PRIVATE_ENVIRONMENT,
    AdversarialCaseId.FAKE_BINARIES: AdversarialBoundary.REJECT_BEFORE_EXECUTION,
    AdversarialCaseId.HOME_READ: AdversarialBoundary.PRIVATE_HOME,
    AdversarialCaseId.NETWORK_SOCKET: AdversarialBoundary.DENY_IN_ROOTLESS_BOUNDARY,
    AdversarialCaseId.OUTPUT_ABUSE: AdversarialBoundary.BOUNDED_OUTPUT,
    AdversarialCaseId.PATH_TRAVERSAL: AdversarialBoundary.REJECT_OR_READ_ONLY_ROOT,
    AdversarialCaseId.PROCESS_RESOURCE_ABUSE: AdversarialBoundary.BOUNDED_PROCESS,
    AdversarialCaseId.PROMPT_INJECTION: AdversarialBoundary.UNTRUSTED_EVIDENCE,
    AdversarialCaseId.SYMLINK_ESCAPE: AdversarialBoundary.REJECT_BEFORE_COPY,
}
_RUNTIME_CASES = frozenset(
    {
        AdversarialCaseId.ENVIRONMENT_READ,
        AdversarialCaseId.HOME_READ,
        AdversarialCaseId.NETWORK_SOCKET,
        AdversarialCaseId.OUTPUT_ABUSE,
        AdversarialCaseId.PATH_TRAVERSAL,
        AdversarialCaseId.PROCESS_RESOURCE_ABUSE,
    }
)
_STATIC_EXPECTATIONS = {
    AdversarialCaseId.CRAFTED_NAMES: (
        AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
        AdversarialEvidenceKind.PATH_NORMALIZATION,
    ),
    AdversarialCaseId.FAKE_BINARIES: (
        AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
        AdversarialEvidenceKind.EXTERNAL_EXECUTABLE_VALIDATION,
    ),
    AdversarialCaseId.PROMPT_INJECTION: (
        AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
        AdversarialEvidenceKind.UNTRUSTED_CONTEXT,
    ),
    AdversarialCaseId.SYMLINK_ESCAPE: (
        AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
        AdversarialEvidenceKind.WORKSPACE_VALIDATION,
    ),
}
_FAIL_CLOSED_EVIDENCE = {
    AdversarialCaseId.ENVIRONMENT_READ: AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
    AdversarialCaseId.HOME_READ: AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
    AdversarialCaseId.NETWORK_SOCKET: AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
    AdversarialCaseId.OUTPUT_ABUSE: AdversarialEvidenceKind.BOUNDED_OUTPUT,
    AdversarialCaseId.PATH_TRAVERSAL: AdversarialEvidenceKind.WORKSPACE_VALIDATION,
    AdversarialCaseId.PROCESS_RESOURCE_ABUSE: AdversarialEvidenceKind.BOUNDED_PROCESS,
}


class AdversarialAcceptanceCase(StrictModel):
    case_id: AdversarialCaseId
    expected_boundary: AdversarialBoundary


class AdversarialAcceptanceManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    cases: list[AdversarialAcceptanceCase] = Field(min_length=10, max_length=10)
    fixture_files: list[ManifestFileBinding] = Field(min_length=7, max_length=7)
    fixture_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def cases_files_and_hashes_are_consistent(self) -> AdversarialAcceptanceManifest:
        observed_cases = {item.case_id: item.expected_boundary for item in self.cases}
        if observed_cases != _EXPECTED_BOUNDARIES:
            raise ValueError("adversarial manifest must cover every expected hostile case")
        if [item.case_id for item in self.cases] != sorted(_EXPECTED_BOUNDARIES):
            raise ValueError("adversarial manifest cases must be sorted")
        paths = [item.path for item in self.fixture_files]
        if paths != sorted(set(paths)):
            raise ValueError("adversarial fixture bindings must be unique and sorted")
        serialized_files = [item.model_dump(mode="json") for item in self.fixture_files]
        if self.fixture_tree_sha256 != canonical_sha256(serialized_files):
            raise ValueError("adversarial fixture-tree hash is inconsistent")
        expected_manifest = canonical_sha256(
            self.model_dump(mode="json", exclude={"manifest_sha256"})
        )
        if self.manifest_sha256 != expected_manifest:
            raise ValueError("adversarial manifest hash is inconsistent")
        return self


class AdversarialAcceptanceObservation(StrictModel):
    case_id: AdversarialCaseId
    disposition: AdversarialDisposition
    evidence_kind: AdversarialEvidenceKind
    hostile_repository_code_executed_on_host: bool = False
    real_isolation_backend: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$",
    )
    limitations: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("limitations")
    @classmethod
    def limitations_are_bounded_sorted_and_unique(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)):
            raise ValueError("adversarial limitations must be unique and sorted")
        if any(not item or len(item) > 500 for item in value):
            raise ValueError("adversarial limitations must be bounded")
        return value

    @model_validator(mode="after")
    def backend_matches_disposition(self) -> AdversarialAcceptanceObservation:
        real = self.disposition is AdversarialDisposition.REAL_ISOLATION_CONTAINED
        if real is (self.real_isolation_backend is None):
            raise ValueError("real isolation disposition and backend must be paired")
        return self


class AdversarialAcceptanceOutcome(StrictModel):
    case_id: AdversarialCaseId
    expected_boundary: AdversarialBoundary
    disposition: AdversarialDisposition
    evidence_kind: AdversarialEvidenceKind
    hostile_repository_code_executed_on_host: bool
    real_isolation_backend: str | None = None
    limitations: list[str] = Field(max_length=10)
    passed: bool


class AdversarialAcceptanceReportPayload(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: AdversarialAcceptanceStatus
    total_cases: int = Field(ge=10, le=10)
    safe_cases: int = Field(ge=0, le=10)
    rejected_before_host_execution: int = Field(ge=0, le=10)
    deterministically_contained: int = Field(ge=0, le=10)
    real_isolation_contained: int = Field(ge=0, le=10)
    hostile_host_executions: int = Field(ge=0, le=10)
    real_isolation_executed: bool
    blocked_integrations: list[Literal["real_rootless_containment"]] = Field(max_length=1)
    outcomes: list[AdversarialAcceptanceOutcome] = Field(
        min_length=10,
        max_length=10,
    )

    @model_validator(mode="after")
    def totals_and_status_are_consistent(self) -> AdversarialAcceptanceReportPayload:
        if [item.case_id for item in self.outcomes] != sorted(_EXPECTED_BOUNDARIES):
            raise ValueError("adversarial outcomes must cover every hostile case")
        expected_totals = {
            "total_cases": len(self.outcomes),
            "safe_cases": sum(item.passed for item in self.outcomes),
            "rejected_before_host_execution": sum(
                item.disposition is AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION
                for item in self.outcomes
            ),
            "deterministically_contained": sum(
                item.disposition is AdversarialDisposition.DETERMINISTICALLY_CONTAINED
                for item in self.outcomes
            ),
            "real_isolation_contained": sum(
                item.disposition is AdversarialDisposition.REAL_ISOLATION_CONTAINED
                for item in self.outcomes
            ),
            "hostile_host_executions": sum(
                item.hostile_repository_code_executed_on_host for item in self.outcomes
            ),
        }
        if any(getattr(self, key) != value for key, value in expected_totals.items()):
            raise ValueError("adversarial acceptance totals are inconsistent")
        expected_real = all(
            item.disposition is AdversarialDisposition.REAL_ISOLATION_CONTAINED
            for item in self.outcomes
            if item.case_id in _RUNTIME_CASES
        )
        if self.real_isolation_executed is not expected_real:
            raise ValueError("adversarial real-isolation status is inconsistent")
        expected_status = (
            AdversarialAcceptanceStatus.FAILED
            if not all(item.passed for item in self.outcomes)
            else (
                AdversarialAcceptanceStatus.PASSED
                if expected_real
                else AdversarialAcceptanceStatus.FAIL_CLOSED
            )
        )
        if self.status is not expected_status:
            raise ValueError("adversarial acceptance status is inconsistent")
        expected_blocked = [] if expected_real else ["real_rootless_containment"]
        if self.blocked_integrations != expected_blocked:
            raise ValueError("adversarial blocked-integration evidence is inconsistent")
        return self


class AdversarialAcceptanceReport(AdversarialAcceptanceReportPayload):
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def report_hash_matches(self) -> AdversarialAcceptanceReport:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("adversarial acceptance report hash is inconsistent")
        return self


def load_adversarial_acceptance_manifest(
    path: Path,
) -> AdversarialAcceptanceManifest:
    """Load and verify the bounded hostile fixture without following links."""

    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("adversarial manifest must be a regular non-link file")
    metadata = path.stat()
    if (
        metadata.st_nlink != 1
        or metadata.st_size > _MAX_MANIFEST_BYTES
        or is_sensitive_workspace_name(path.name)
    ):
        raise ValueError("adversarial manifest must be bounded and unshared")
    manifest = AdversarialAcceptanceManifest.model_validate_json(path.read_text(encoding="utf-8"))
    root = path.parent.resolve(strict=True)
    expected = {item.path: item for item in manifest.fixture_files}
    observed: dict[str, ManifestFileBinding] = {}
    total_bytes = 0
    for candidate in path.parent.rglob("*"):
        if candidate == path:
            continue
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("adversarial fixture may not contain links")
        if candidate.is_dir():
            continue
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        file_metadata = resolved.stat()
        if (
            not resolved.is_file()
            or file_metadata.st_nlink != 1
            or file_metadata.st_size > _MAX_FIXTURE_FILE_BYTES
        ):
            raise ValueError("adversarial fixture must contain unique regular files")
        total_bytes += file_metadata.st_size
        relative = resolved.relative_to(root).as_posix()
        observed[relative] = ManifestFileBinding(
            path=relative,
            sha256=_file_sha256(resolved),
            size=file_metadata.st_size,
        )
    if total_bytes > _MAX_FIXTURE_BYTES:
        raise ValueError("adversarial fixture exceeds its aggregate size bound")
    if observed != expected:
        raise ValueError("adversarial fixture inventory or content hash mismatch")
    return manifest


def build_adversarial_acceptance_report(
    manifest: AdversarialAcceptanceManifest,
    observations: list[AdversarialAcceptanceObservation],
) -> AdversarialAcceptanceReport:
    """Reconcile every hostile case without treating fail-closed as real isolation."""

    by_case = {item.case_id: item for item in observations}
    if len(by_case) != len(observations) or set(by_case) != set(_EXPECTED_BOUNDARIES):
        raise ValueError("adversarial observations must uniquely cover every case")
    outcomes: list[AdversarialAcceptanceOutcome] = []
    for case in manifest.cases:
        observation = by_case[case.case_id]
        passed = (
            not observation.hostile_repository_code_executed_on_host
            and _observation_matches_boundary(observation)
        )
        outcomes.append(
            AdversarialAcceptanceOutcome(
                case_id=case.case_id,
                expected_boundary=case.expected_boundary,
                disposition=observation.disposition,
                evidence_kind=observation.evidence_kind,
                hostile_repository_code_executed_on_host=(
                    observation.hostile_repository_code_executed_on_host
                ),
                real_isolation_backend=observation.real_isolation_backend,
                limitations=observation.limitations,
                passed=passed,
            )
        )
    real_executed = all(
        item.disposition is AdversarialDisposition.REAL_ISOLATION_CONTAINED
        for item in outcomes
        if item.case_id in _RUNTIME_CASES
    )
    all_safe = all(item.passed for item in outcomes)
    payload = AdversarialAcceptanceReportPayload(
        manifest_sha256=manifest.manifest_sha256,
        status=(
            AdversarialAcceptanceStatus.FAILED
            if not all_safe
            else (
                AdversarialAcceptanceStatus.PASSED
                if real_executed
                else AdversarialAcceptanceStatus.FAIL_CLOSED
            )
        ),
        total_cases=len(outcomes),
        safe_cases=sum(item.passed for item in outcomes),
        rejected_before_host_execution=sum(
            item.disposition is AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION
            for item in outcomes
        ),
        deterministically_contained=sum(
            item.disposition is AdversarialDisposition.DETERMINISTICALLY_CONTAINED
            for item in outcomes
        ),
        real_isolation_contained=sum(
            item.disposition is AdversarialDisposition.REAL_ISOLATION_CONTAINED for item in outcomes
        ),
        hostile_host_executions=sum(
            item.hostile_repository_code_executed_on_host for item in outcomes
        ),
        real_isolation_executed=real_executed,
        blocked_integrations=[] if real_executed else ["real_rootless_containment"],
        outcomes=outcomes,
    )
    serialized = payload.model_dump(mode="json")
    return AdversarialAcceptanceReport.model_validate(
        {
            **serialized,
            "report_sha256": canonical_sha256(serialized),
        }
    )


def write_adversarial_acceptance_report(
    path: Path,
    report: AdversarialAcceptanceReport,
) -> None:
    """Write normalized hostile-repository evidence to a bounded non-link file."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive adversarial report filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("adversarial report destination may not be a link")
    if path.exists() and (
        not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > _MAX_REPORT_BYTES
    ):
        raise ValueError("adversarial report destination must be an unshared file")
    serialized = stable_json(report)
    if len(serialized.encode("utf-8")) > _MAX_REPORT_BYTES:
        raise ValueError("adversarial report exceeds its output bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def _observation_matches_boundary(
    observation: AdversarialAcceptanceObservation,
) -> bool:
    if observation.case_id in _STATIC_EXPECTATIONS:
        return (
            observation.disposition,
            observation.evidence_kind,
        ) == _STATIC_EXPECTATIONS[observation.case_id]
    if observation.disposition is AdversarialDisposition.REAL_ISOLATION_CONTAINED:
        return observation.evidence_kind is AdversarialEvidenceKind.ROOTLESS_RUNTIME
    return (
        observation.disposition is AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION
        and observation.evidence_kind == _FAIL_CLOSED_EVIDENCE[observation.case_id]
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
