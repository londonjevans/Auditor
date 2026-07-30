"""Fail-closed, source-bound state for deterministic continuous-integration runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.config import AuditConfig, AuditRunOptions
from mmaudit.models.schemas import (
    CI_DETERMINISTIC_COVERAGE_METRIC_IDS,
    AnalysisState,
    AuditReport,
    AuditRunStatus,
    CoverageMetric,
    CoverageProvenance,
    ExecutionEvidenceKind,
    Location,
    LocationValidation,
    RepositoryCodeExecutionState,
    RepositorySuiteFramework,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    SolidityProjectMetadata,
    SolidityProjectType,
    StrictModel,
)
from mmaudit.orchestration.assurance import (
    CERTIFIED_ISOLATION_BACKENDS,
    is_qualifying_real_scanner_run,
)
from mmaudit.orchestration.manifest import (
    ManifestFileBinding,
    RunEvidenceManifest,
    build_manifest_configuration_bindings,
    build_manifest_tool_bindings,
    canonical_sha256,
    resolve_run_evidence_config,
    validate_manifest_artifacts,
)
from mmaudit.orchestration.verification import load_manifest_bound_report
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.scanners.runtime_evidence import has_host_repository_suite_runtime_authority

CI_STATE_FILENAME = "ci-state.json"
_MAX_CI_STATE_BYTES = 25_000_000
_MAX_CI_MANIFEST_BYTES = 100_000_000
_MAX_CI_REPORT_BYTES = 100_000_000
_MAX_PRODUCER_BYTES = 100_000_000
_CI_BASELINE_BUNDLE_FILES = (
    CI_STATE_FILENAME,
    "final-findings.json",
    "run-evidence-manifest.json",
)
_MAX_CI_COMMAND_ARGUMENTS = 10_000
_MAX_CI_COMMAND_ARGUMENT_CHARACTERS = 8_000
_MAX_CI_COMMAND_CHARACTERS = 1_000_000
_LOOPBACK_URL_RE = re.compile(
    r"(?P<scheme>https?://)"
    r"(?P<host>localhost|127\.0\.0\.1|\[::1\])"
    r"(?::(?P<port>[0-9]{1,5}))?",
    flags=re.IGNORECASE,
)


class CIJobStatus(StrEnum):
    """Evidence-derived CI disposition; findings and coverage are never conflated."""

    NO_BASELINE = "NO_BASELINE"
    CLEAN = "CLEAN"
    UNCHANGED = "UNCHANGED"
    NEW_FINDINGS = "NEW_FINDINGS"
    COVERAGE_REGRESSION = "COVERAGE_REGRESSION"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"


class CIRepositorySuiteStatus(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PASSED = "PASSED"
    FAILED = "FAILED"


class CIToolEvidence(StrictModel):
    """Normalized producer identity and exact observation from one deterministic tool."""

    scanner: str = Field(min_length=1, max_length=200)
    status: ScannerStatus
    execution_evidence: ExecutionEvidenceKind
    version: str | None = Field(default=None, max_length=1_000)
    executable_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    command_present: bool
    invocation_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    raw_output_path_present: bool
    isolation_backend: str | None = Field(default=None, max_length=200)
    isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    certified_isolation: bool
    execution_time_order_valid: bool
    machine_output_validated: bool
    raw_output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    raw_output_bytes: int = Field(ge=0)
    process_exit_code: int | None
    execution_observation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    repository_code_execution: RepositoryCodeExecutionState
    repository_suite_selected_test_count: int = Field(ge=0, le=1_000_000)
    repository_suite_executed_test_count: int = Field(ge=0, le=1_000_000)
    repository_suite_configuration_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    tool_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reuse_eligible: bool

    @model_validator(mode="after")
    def hashes_and_eligibility_are_derived(self) -> CIToolEvidence:
        identity = {
            "scanner": self.scanner,
            "version": self.version,
            "executable_sha256": self.executable_sha256,
            "invocation_policy_sha256": self.invocation_policy_sha256,
            "isolation_backend": self.isolation_backend,
            "isolation_attestation_sha256": self.isolation_attestation_sha256,
            "repository_suite_configuration_sha256": (self.repository_suite_configuration_sha256),
        }
        if self.tool_identity_sha256 != canonical_sha256(identity):
            raise ValueError("CI tool identity hash does not match its normalized fields")
        evidence = {
            **identity,
            "status": self.status.value,
            "execution_evidence": self.execution_evidence.value,
            "command_present": self.command_present,
            "raw_output_path_present": self.raw_output_path_present,
            "certified_isolation": self.certified_isolation,
            "execution_time_order_valid": self.execution_time_order_valid,
            "machine_output_validated": self.machine_output_validated,
            "raw_output_sha256": self.raw_output_sha256,
            "raw_output_bytes": self.raw_output_bytes,
            "process_exit_code": self.process_exit_code,
            "execution_observation_sha256": self.execution_observation_sha256,
            "repository_code_execution": self.repository_code_execution.value,
            "repository_suite_selected_test_count": (self.repository_suite_selected_test_count),
            "repository_suite_executed_test_count": (self.repository_suite_executed_test_count),
        }
        if self.evidence_sha256 != canonical_sha256(evidence):
            raise ValueError("CI tool evidence hash does not match its observation")
        expected_qualifying_real_run = (
            self.status is ScannerStatus.SUCCESS
            and self.execution_evidence is ExecutionEvidenceKind.REAL
            and self.version is not None
            and self.executable_sha256 is not None
            and self.command_present
            and self.raw_output_path_present
            and self.raw_output_sha256 is not None
            and self.raw_output_bytes > 0
            and self.process_exit_code is not None
            and self.certified_isolation
            and self.isolation_backend is not None
            and self.isolation_attestation_sha256 is not None
            and self.execution_time_order_valid
            and self.machine_output_validated
            and self.execution_observation_sha256 is not None
        )
        expected_reusable = expected_qualifying_real_run
        if self.reuse_eligible is not expected_reusable:
            raise ValueError("CI tool reuse eligibility differs from real validated evidence")
        if self.certified_isolation is not (self.isolation_backend in CERTIFIED_ISOLATION_BACKENDS):
            raise ValueError("CI tool certified-isolation claim differs from its backend")
        if self.repository_suite_executed_test_count > self.repository_suite_selected_test_count:
            raise ValueError("CI repository-suite executed count exceeds its selection")
        return self

    @field_validator("scanner", "version", "isolation_backend")
    @classmethod
    def text_fields_are_printable(cls, value: str | None) -> str | None:
        return _validated_printable(value, label="CI tool metadata")


class CIFindingEvidence(StrictModel):
    """One scanner observation bound to every source file containing its locations."""

    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    scanner: str = Field(min_length=1, max_length=200)
    rule_id: str = Field(min_length=1, max_length=500)
    fingerprint: str = Field(min_length=1, max_length=4_096)
    severity: Severity
    locations: tuple[Location, ...] = Field(min_length=1, max_length=1_000)
    location_validations: tuple[LocationValidation, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    source_bindings: tuple[ManifestFileBinding, ...] = Field(min_length=1, max_length=1_000)
    finding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity_and_source_bindings_are_canonical(self) -> CIFindingEvidence:
        location_payload = [location.model_dump(mode="json") for location in self.locations]
        if len(self.location_validations) != len(self.locations):
            raise ValueError("CI finding requires one host validation per location")
        for location, validation in zip(
            self.locations,
            self.location_validations,
            strict=True,
        ):
            if (
                not validation.valid
                or validation.errors
                or validation.validated_at is not None
                or validation.content_hash is None
                or re.fullmatch(r"[0-9a-f]{64}", validation.content_hash) is None
                or location.content_hash != validation.content_hash
            ):
                raise ValueError("CI finding requires normalized valid host location evidence")
        location_keys = [
            (
                item["path"],
                item["start_line"],
                item["end_line"],
                item.get("symbol") or "",
                item.get("content_hash") or "",
            )
            for item in location_payload
        ]
        if len(location_keys) != len(set(location_keys)):
            raise ValueError("CI finding locations must be unique")
        if location_payload != sorted(
            location_payload,
            key=lambda item: (
                item["path"],
                item["start_line"],
                item["end_line"],
                item.get("symbol") or "",
                item.get("content_hash") or "",
            ),
        ):
            raise ValueError("CI finding locations must be canonically sorted")
        paths = tuple(binding.path for binding in self.source_bindings)
        if paths != tuple(sorted(set(paths))):
            raise ValueError("CI finding source bindings must be unique and sorted")
        if set(paths) != {location.path for location in self.locations}:
            raise ValueError("CI finding locations and bound source files differ")
        identity = {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "locations": location_payload,
        }
        if self.finding_id != canonical_sha256(identity):
            raise ValueError("CI finding ID does not match its deterministic identity")
        evidence = {
            **identity,
            "severity": self.severity.value,
            "finding_sha256": self.finding_sha256,
            "location_validations": [
                validation.model_dump(mode="json") for validation in self.location_validations
            ],
            "source_bindings": [
                binding.model_dump(mode="json") for binding in self.source_bindings
            ],
        }
        if self.evidence_sha256 != canonical_sha256(evidence):
            raise ValueError("CI finding evidence hash does not match its source bindings")
        return self

    @field_validator("scanner", "rule_id", "fingerprint")
    @classmethod
    def text_fields_are_printable(cls, value: str) -> str:
        validated = _validated_printable(value, label="CI finding metadata")
        assert validated is not None
        return validated


class CICoverageEvidence(StrictModel):
    metric_id: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    metric: CoverageMetric
    metric_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def metric_hash_is_exact(self) -> CICoverageEvidence:
        expected = canonical_sha256(self.metric.model_dump(mode="json"))
        if self.metric_sha256 != expected:
            raise ValueError("CI coverage metric hash does not match its evidence")
        return self


class CIRepositorySuiteScannerCoverage(StrictModel):
    """Typed selected-versus-executed coverage for one repository-suite scanner."""

    scanner: str = Field(min_length=1, max_length=200)
    selection_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    selected_descriptor_sha256s: tuple[str, ...] = Field(
        default=(),
        max_length=10_000,
    )
    executed_descriptor_sha256s: tuple[str, ...] = Field(
        default=(),
        max_length=10_000,
    )
    selected_test_count: int = Field(ge=0, le=1_000_000)
    executed_test_count: int = Field(ge=0, le=1_000_000)
    coverage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(
        cls,
        *,
        scanner: str,
        selection_sha256: str | None,
        selected_descriptor_sha256s: Sequence[str],
        executed_descriptor_sha256s: Sequence[str],
        selected_test_count: int,
        executed_test_count: int,
    ) -> CIRepositorySuiteScannerCoverage:
        payload = {
            "scanner": scanner,
            "selection_sha256": selection_sha256,
            "selected_descriptor_sha256s": tuple(sorted(selected_descriptor_sha256s)),
            "executed_descriptor_sha256s": tuple(sorted(executed_descriptor_sha256s)),
            "selected_test_count": selected_test_count,
            "executed_test_count": executed_test_count,
        }
        return cls(
            **payload,
            coverage_sha256=canonical_sha256(payload),
        )

    @model_validator(mode="after")
    def count_and_hash_are_exact(self) -> CIRepositorySuiteScannerCoverage:
        for label, values in (
            ("selected descriptor identities", self.selected_descriptor_sha256s),
            ("executed descriptor identities", self.executed_descriptor_sha256s),
        ):
            if values != tuple(sorted(set(values))) or any(
                re.fullmatch(r"[0-9a-f]{64}", value) is None for value in values
            ):
                raise ValueError(
                    f"CI repository-suite {label} must be unique sorted SHA-256 values"
                )
        if self.selected_test_count != len(self.selected_descriptor_sha256s):
            raise ValueError("CI repository-suite selected count differs from its identities")
        if self.executed_test_count != len(self.executed_descriptor_sha256s):
            raise ValueError("CI repository-suite executed count differs from its identities")
        if not set(self.executed_descriptor_sha256s) <= set(self.selected_descriptor_sha256s):
            raise ValueError("CI repository-suite executed identities exceed its selection")
        if (self.selection_sha256 is None) is (self.selected_test_count > 0):
            raise ValueError("CI repository-suite selection identity differs from its test count")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"coverage_sha256"}))
        if self.coverage_sha256 != expected:
            raise ValueError("CI repository-suite coverage hash does not match its evidence")
        return self

    @field_validator("scanner")
    @classmethod
    def scanner_is_printable(cls, value: str) -> str:
        validated = _validated_printable(value, label="CI repository-suite scanner")
        assert validated is not None
        return validated


class CIRepositorySuiteEvidence(StrictModel):
    status: CIRepositorySuiteStatus
    applicable_frameworks: tuple[RepositorySuiteFramework, ...] = ()
    required_scanners: tuple[str, ...] = ()
    successful_scanners: tuple[str, ...] = ()
    scanner_coverage: tuple[CIRepositorySuiteScannerCoverage, ...] = Field(
        default=(),
        max_length=10_000,
    )
    failures: tuple[str, ...] = ()

    @classmethod
    def not_applicable(cls) -> CIRepositorySuiteEvidence:
        return cls(status=CIRepositorySuiteStatus.NOT_APPLICABLE)

    @model_validator(mode="after")
    def disposition_matches_inventory(self) -> CIRepositorySuiteEvidence:
        for label, values in (
            ("applicable frameworks", tuple(item.value for item in self.applicable_frameworks)),
            ("required scanners", self.required_scanners),
            ("successful scanners", self.successful_scanners),
            ("scanner coverage", tuple(item.scanner for item in self.scanner_coverage)),
            ("failures", self.failures),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"CI repository-suite {label} must be unique and sorted")
        if self.status is CIRepositorySuiteStatus.NOT_APPLICABLE:
            if (
                self.applicable_frameworks
                or self.required_scanners
                or self.successful_scanners
                or self.scanner_coverage
                or self.failures
            ):
                raise ValueError("non-applicable CI repository suite cannot carry execution claims")
            return self
        if tuple(item.scanner for item in self.scanner_coverage) != self.required_scanners:
            raise ValueError("CI repository-suite coverage must include every required scanner")
        coverage_by_scanner = {item.scanner: item for item in self.scanner_coverage}
        if self.status is CIRepositorySuiteStatus.PASSED:
            if (
                not self.required_scanners
                or self.successful_scanners != self.required_scanners
                or self.failures
                or any(
                    coverage_by_scanner[scanner].selected_test_count <= 0
                    or coverage_by_scanner[scanner].executed_test_count
                    != coverage_by_scanner[scanner].selected_test_count
                    for scanner in self.required_scanners
                )
            ):
                raise ValueError("passed CI repository suite requires every applicable scanner")
        elif not self.required_scanners or not self.failures:
            raise ValueError("failed CI repository suite requires explicit missing evidence")
        return self

    @field_validator("required_scanners", "successful_scanners", "failures")
    @classmethod
    def inventory_text_is_printable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _validated_printable(item, label="CI repository-suite evidence")
            if len(item) > 1_000:
                raise ValueError("CI repository-suite evidence exceeds the text bound")
        return value


class CIDeterministicEvidence(StrictModel):
    """Self-hashed resumable deterministic baseline without raw source or tool output."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    generated_at: datetime
    changed_since: str | None = Field(default=None, max_length=500)
    audit_run_status: AuditRunStatus | None = None
    scanner_workspace_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    effective_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    producer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sources: tuple[ManifestFileBinding, ...] = Field(max_length=100_000)
    source_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tools: tuple[CIToolEvidence, ...] = Field(max_length=10_000)
    findings: tuple[CIFindingEvidence, ...] = Field(max_length=100_000)
    finding_validation_failures: tuple[str, ...] = Field(
        default=(),
        max_length=100_000,
    )
    coverage: tuple[CICoverageEvidence, ...] = Field(max_length=10_000)
    repository_suite: CIRepositorySuiteEvidence
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def inventories_and_self_hash_are_canonical(self) -> CIDeterministicEvidence:
        for label, values in (
            ("sources", tuple(item.path for item in self.sources)),
            ("tools", tuple(item.scanner for item in self.tools)),
            ("findings", tuple(item.finding_id for item in self.findings)),
            ("finding validation failures", self.finding_validation_failures),
            ("coverage", tuple(item.metric_id for item in self.coverage)),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"CI evidence {label} must be unique and sorted")
        expected_source_tree = canonical_sha256(
            [source.model_dump(mode="json") for source in self.sources]
        )
        if self.source_tree_sha256 != expected_source_tree:
            raise ValueError("CI source-tree hash does not match its complete source bindings")
        expected_required = tuple(
            sorted(
                f"{framework.value}_fork"
                for framework in self.repository_suite.applicable_frameworks
            )
        )
        if self.repository_suite.status is not CIRepositorySuiteStatus.NOT_APPLICABLE:
            if self.repository_suite.required_scanners != expected_required:
                raise ValueError(
                    "CI repository-suite requirements differ from applicable frameworks"
                )
            tools_by_name = {tool.scanner: tool for tool in self.tools}
            coverage_by_scanner = {
                coverage.scanner: coverage for coverage in self.repository_suite.scanner_coverage
            }
            for scanner in self.repository_suite.required_scanners:
                coverage = coverage_by_scanner[scanner]
                tool = tools_by_name.get(scanner)
                if tool is None:
                    if coverage.selected_test_count or coverage.executed_test_count:
                        raise ValueError(
                            "CI repository-suite coverage lacks matching tool evidence"
                        )
                    continue
                if (
                    coverage.selected_test_count != tool.repository_suite_selected_test_count
                    or coverage.executed_test_count != tool.repository_suite_executed_test_count
                ):
                    raise ValueError(
                        "CI repository-suite coverage differs from matching tool evidence"
                    )
            for scanner in self.repository_suite.successful_scanners:
                tool = tools_by_name.get(scanner)
                if (
                    tool is None
                    or not tool.reuse_eligible
                    or tool.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
                    or tool.repository_suite_selected_test_count <= 0
                    or tool.repository_suite_executed_test_count
                    != tool.repository_suite_selected_test_count
                    or tool.repository_suite_configuration_sha256 is None
                ):
                    raise ValueError(
                        "CI repository-suite success lacks matching isolated tool evidence"
                    )
        source_by_path = {source.path: source for source in self.sources}
        tools_by_name = {tool.scanner: tool for tool in self.tools}
        for finding in self.findings:
            tool = tools_by_name.get(finding.scanner)
            if tool is None or not tool.reuse_eligible:
                raise ValueError("CI finding lacks matching reusable tool evidence")
            expected_bindings = tuple(
                source_by_path[path]
                for path in sorted({location.path for location in finding.locations})
                if path in source_by_path
            )
            if (
                len(expected_bindings) != len(finding.source_bindings)
                or expected_bindings != finding.source_bindings
            ):
                raise ValueError("CI finding bindings differ from the enclosing source inventory")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("CI evidence self-hash does not match its canonical contents")
        return self

    @field_validator("finding_validation_failures")
    @classmethod
    def finding_failures_are_printable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _validated_printable(item, label="CI finding validation failure")
            if len(item) > 1_000:
                raise ValueError("CI finding validation failure exceeds the text bound")
        return value

    @field_validator("generated_at")
    @classmethod
    def generated_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("CI evidence generated_at requires a timezone")
        if value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("CI evidence generated_at must use UTC")
        return value

    @field_validator("changed_since")
    @classmethod
    def changed_since_is_printable(cls, value: str | None) -> str | None:
        return _validated_printable(value, label="CI changed-since")


class CICoverageRegression(StrictModel):
    metric_id: str
    reasons: tuple[str, ...] = Field(min_length=1)
    baseline: CICoverageEvidence
    current: CICoverageEvidence | None

    @model_validator(mode="after")
    def reasons_are_canonical(self) -> CICoverageRegression:
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("CI coverage regression reasons must be unique and sorted")
        if self.metric_id != self.baseline.metric_id or (
            self.current is not None and self.current.metric_id != self.metric_id
        ):
            raise ValueError("CI coverage regression metric identity differs")
        return self


class CIBaselineComparison(StrictModel):
    baseline_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    baseline_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    whole_run_reuse_eligible: bool
    reuse_rejections: tuple[str, ...]
    new_finding_ids: tuple[str, ...]
    unchanged_finding_ids: tuple[str, ...]
    resolved_finding_ids: tuple[str, ...]
    coverage_regressions: tuple[CICoverageRegression, ...]

    @model_validator(mode="after")
    def comparison_inventories_are_canonical(self) -> CIBaselineComparison:
        for label, values in (
            ("reuse rejections", self.reuse_rejections),
            ("new findings", self.new_finding_ids),
            ("unchanged findings", self.unchanged_finding_ids),
            ("resolved findings", self.resolved_finding_ids),
            (
                "coverage regressions",
                tuple(item.metric_id for item in self.coverage_regressions),
            ),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"CI comparison {label} must be unique and sorted")
        if set(self.new_finding_ids) & set(self.unchanged_finding_ids):
            raise ValueError("CI findings cannot be both new and unchanged")
        if set(self.resolved_finding_ids) & set(self.new_finding_ids) or set(
            self.resolved_finding_ids
        ) & set(self.unchanged_finding_ids):
            raise ValueError("CI resolved findings cannot also be current findings")
        if self.whole_run_reuse_eligible == bool(self.reuse_rejections):
            raise ValueError("CI whole-run reuse result conflicts with rejection evidence")
        return self

    @field_validator("reuse_rejections")
    @classmethod
    def reuse_rejections_are_printable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _validated_printable(item, label="CI reuse rejection")
        return value


class CIRunState(StrictModel):
    """Manifest-bound CI result and resumable comparison baseline."""

    schema_version: Literal["1.0"] = "1.0"
    evidence: CIDeterministicEvidence
    comparison: CIBaselineComparison | None = None
    job_status: CIJobStatus
    analysis_failures: tuple[str, ...]
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def status_and_self_hash_are_derived(self) -> CIRunState:
        if self.analysis_failures != tuple(sorted(set(self.analysis_failures))):
            raise ValueError("CI analysis failures must be unique and sorted")
        expected_failures = _analysis_failures(self.evidence)
        if self.analysis_failures != expected_failures:
            raise ValueError("CI analysis failures differ from deterministic evidence")
        expected_status = _job_status(
            self.evidence,
            comparison=self.comparison,
            analysis_failures=self.analysis_failures,
        )
        if self.job_status is not expected_status:
            raise ValueError("CI job status differs from deterministic evidence")
        expected_hash = canonical_sha256(self.model_dump(mode="json", exclude={"state_sha256"}))
        if self.state_sha256 != expected_hash:
            raise ValueError("CI state self-hash does not match its canonical contents")
        return self

    @field_validator("analysis_failures")
    @classmethod
    def analysis_failures_are_printable(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            _validated_printable(item, label="CI analysis failure")
            if len(item) > 1_000:
                raise ValueError("CI analysis failure exceeds the text bound")
        return value


@dataclass(frozen=True, slots=True)
class LoadedCIBaseline:
    run_dir: Path
    manifest: RunEvidenceManifest
    report: AuditReport
    state: CIRunState


@dataclass(frozen=True, slots=True)
class _CIBundleMemberObservation:
    data: bytes
    identity: tuple[int, int, int, int, int, int, int]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def ci_invocation_policy_sha256(run: ScannerRun) -> str:
    """Hash stable scanner arguments and typed scope without retaining raw command text."""

    if len(run.command) > _MAX_CI_COMMAND_ARGUMENTS:
        raise ValueError("CI scanner command exceeds the bounded argument inventory")
    total_characters = sum(len(argument) for argument in run.command)
    if (
        any(len(argument) > _MAX_CI_COMMAND_ARGUMENT_CHARACTERS for argument in run.command)
        or total_characters > _MAX_CI_COMMAND_CHARACTERS
    ):
        raise ValueError("CI scanner command exceeds the bounded character inventory")
    selection = run.repository_suite_selection
    execution_policy = run.repository_suite_execution_policy
    return canonical_sha256(
        {
            "scanner": run.scanner,
            "command": [
                _normalized_ci_command_argument(argument, index=index)
                for index, argument in enumerate(run.command)
            ],
            "repository_suite": (
                {
                    "selection_sha256": selection.selection_sha256,
                    "configuration_sha256": selection.configuration_sha256,
                    "descriptor_sha256s": [
                        descriptor.descriptor_sha256 for descriptor in selection.tests
                    ],
                }
                if selection is not None
                else None
            ),
            "repository_execution_policy_sha256": (
                execution_policy.policy_sha256 if execution_policy is not None else None
            ),
            "repository_test_commands": [
                {
                    "descriptor_sha256": execution.descriptor_sha256,
                    "command_sha256": execution.command_sha256,
                }
                for execution in run.repository_test_executions
            ],
            "repository_rpc_scopes": [
                {
                    "descriptor_sha256": scope.descriptor_sha256,
                    "sequence_index": scope.sequence_index,
                    "bridge_policy_sha256": scope.bridge_policy_sha256,
                }
                for scope in run.repository_test_fork_rpc_scopes
            ],
        }
    )


def ci_tool_evidence(run: ScannerRun) -> CIToolEvidence:
    """Normalize only host-recorded scanner evidence; never manufacture runtime credit."""

    observation_valid = run.execution_observation_sha256_is_valid()
    invocation_policy_sha256 = ci_invocation_policy_sha256(run)
    suite_configuration_sha256 = (
        run.repository_suite_selection.configuration_sha256
        if run.repository_suite_selection is not None
        else None
    )
    selected_test_count = (
        run.repository_suite_selection.selected_test_count
        if run.repository_suite_selection is not None
        else 0
    )
    executed_test_count = len(run.repository_test_executions)
    command_present = bool(run.command)
    raw_output_path_present = bool(run.raw_output_path)
    certified_isolation = run.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
    execution_time_order_valid = run.finished_at >= run.started_at
    identity = {
        "scanner": run.scanner,
        "version": run.version,
        "executable_sha256": run.executable_sha256,
        "invocation_policy_sha256": invocation_policy_sha256,
        "isolation_backend": run.isolation_backend,
        "isolation_attestation_sha256": run.isolation_attestation_sha256,
        "repository_suite_configuration_sha256": suite_configuration_sha256,
    }
    evidence = {
        **identity,
        "status": run.status.value,
        "execution_evidence": run.execution_evidence.value,
        "command_present": command_present,
        "raw_output_path_present": raw_output_path_present,
        "certified_isolation": certified_isolation,
        "execution_time_order_valid": execution_time_order_valid,
        "machine_output_validated": run.machine_output_validated,
        "raw_output_sha256": run.raw_output_sha256,
        "raw_output_bytes": run.raw_output_bytes,
        "process_exit_code": run.process_exit_code,
        "execution_observation_sha256": (
            run.execution_observation_sha256 if observation_valid else None
        ),
        "repository_code_execution": run.repository_code_execution.value,
        "repository_suite_selected_test_count": selected_test_count,
        "repository_suite_executed_test_count": executed_test_count,
    }
    reusable = is_qualifying_real_scanner_run(run)
    return CIToolEvidence(
        scanner=run.scanner,
        status=run.status,
        execution_evidence=run.execution_evidence,
        version=run.version,
        executable_sha256=run.executable_sha256,
        command_present=command_present,
        invocation_policy_sha256=invocation_policy_sha256,
        raw_output_path_present=raw_output_path_present,
        isolation_backend=run.isolation_backend,
        isolation_attestation_sha256=run.isolation_attestation_sha256,
        certified_isolation=certified_isolation,
        execution_time_order_valid=execution_time_order_valid,
        machine_output_validated=run.machine_output_validated,
        raw_output_sha256=run.raw_output_sha256,
        raw_output_bytes=run.raw_output_bytes,
        process_exit_code=run.process_exit_code,
        execution_observation_sha256=(
            run.execution_observation_sha256 if observation_valid else None
        ),
        repository_code_execution=run.repository_code_execution,
        repository_suite_selected_test_count=selected_test_count,
        repository_suite_executed_test_count=executed_test_count,
        repository_suite_configuration_sha256=suite_configuration_sha256,
        tool_identity_sha256=canonical_sha256(identity),
        evidence_sha256=canonical_sha256(evidence),
        reuse_eligible=reusable,
    )


def ci_finding_evidence(
    finding: ScannerFinding,
    sources: Sequence[ManifestFileBinding],
) -> CIFindingEvidence:
    """Bind one finding to host-validated ranges and complete-file identities."""

    raw_validations = finding.metadata.get("location_validation")
    if not isinstance(raw_validations, list) or len(raw_validations) != len(finding.locations):
        raise ValueError("CI finding requires one host location validation per location")
    pairs: list[tuple[Location, LocationValidation]] = []
    for location, raw_validation in zip(
        finding.locations,
        raw_validations,
        strict=True,
    ):
        try:
            validation = LocationValidation.model_validate(raw_validation)
        except ValueError as exc:
            raise ValueError("CI finding contains invalid host location validation") from exc
        validated_at = validation.validated_at
        if (
            not validation.valid
            or validation.errors
            or validation.content_hash is None
            or re.fullmatch(r"[0-9a-f]{64}", validation.content_hash) is None
            or validated_at is None
            or validated_at.tzinfo is None
            or validated_at.utcoffset() is None
            or validated_at.utcoffset() != UTC.utcoffset(validated_at)
            or (
                location.content_hash is not None
                and location.content_hash != validation.content_hash
            )
        ):
            raise ValueError("CI finding lacks qualifying valid host location evidence")
        pairs.append(
            (
                location.model_copy(
                    update={"content_hash": validation.content_hash},
                ),
                validation.model_copy(update={"validated_at": None}),
            )
        )
    ordered_pairs = tuple(
        sorted(
            pairs,
            key=lambda item: (
                item[0].path,
                item[0].start_line,
                item[0].end_line,
                item[0].symbol or "",
                item[0].content_hash or "",
            ),
        )
    )
    locations = tuple(location for location, _validation in ordered_pairs)
    validations = tuple(validation for _location, validation in ordered_pairs)
    source_by_path = {source.path: source for source in sources}
    location_paths = sorted({location.path for location in locations})
    missing = [path for path in location_paths if path not in source_by_path]
    if missing:
        raise ValueError(
            "CI finding location is absent from current source bindings: " + ", ".join(missing[:20])
        )
    source_bindings = tuple(source_by_path[path] for path in location_paths)
    location_payload = [location.model_dump(mode="json") for location in locations]
    identity = {
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "fingerprint": finding.fingerprint,
        "locations": location_payload,
    }
    normalized_metadata = {
        **finding.metadata,
        "location_validation": [validation.model_dump(mode="json") for validation in validations],
    }
    normalized_finding = finding.model_copy(
        update={
            "locations": list(locations),
            "metadata": normalized_metadata,
        }
    )
    finding_sha256 = canonical_sha256(normalized_finding.model_dump(mode="json"))
    evidence = {
        **identity,
        "severity": finding.severity.value,
        "finding_sha256": finding_sha256,
        "location_validations": [validation.model_dump(mode="json") for validation in validations],
        "source_bindings": [binding.model_dump(mode="json") for binding in source_bindings],
    }
    return CIFindingEvidence(
        finding_id=canonical_sha256(identity),
        scanner=finding.scanner,
        rule_id=finding.rule_id,
        fingerprint=finding.fingerprint,
        severity=finding.severity,
        locations=locations,
        location_validations=validations,
        source_bindings=source_bindings,
        finding_sha256=finding_sha256,
        evidence_sha256=canonical_sha256(evidence),
    )


def ci_coverage_evidence(metric_id: str, metric: CoverageMetric) -> CICoverageEvidence:
    return CICoverageEvidence(
        metric_id=metric_id,
        metric=metric,
        metric_sha256=canonical_sha256(metric.model_dump(mode="json")),
    )


def deterministic_ci_coverage_metrics(
    metrics: Mapping[str, CoverageMetric],
) -> dict[str, CoverageMetric]:
    """Select deterministic scanner/compile coverage applicable to model-free CI."""

    return {
        metric_id: metric
        for metric_id, metric in sorted(metrics.items())
        if metric_id in CI_DETERMINISTIC_COVERAGE_METRIC_IDS
    }


def project_ci_findings(
    scanner_runs: Sequence[ScannerRun],
    sources: Sequence[ManifestFileBinding],
    *,
    reusable_scanners: set[str],
) -> tuple[tuple[CIFindingEvidence, ...], tuple[str, ...]]:
    """Keep valid findings while making malformed or misattributed evidence fail closed."""

    projected: list[CIFindingEvidence] = []
    failures: set[str] = set()
    finding_ids: set[str] = set()
    for run in scanner_runs:
        if run.scanner not in reusable_scanners:
            continue
        for finding in run.findings:
            diagnostic_id = canonical_sha256(
                {
                    "run_scanner": run.scanner,
                    "finding_scanner": finding.scanner,
                    "rule_id": finding.rule_id,
                    "fingerprint": finding.fingerprint,
                    "locations": [
                        location.model_dump(mode="json") for location in finding.locations
                    ],
                }
            )
            prefix = f"scanner:{run.scanner}:finding:{diagnostic_id}"
            if finding.scanner != run.scanner:
                failures.add(f"{prefix}:scanner_attribution_mismatch")
                continue
            try:
                evidence = ci_finding_evidence(finding, sources)
            except ValueError:
                failures.add(f"{prefix}:location_validation_failed")
                continue
            if evidence.finding_id in finding_ids:
                failures.add(f"{prefix}:duplicate_finding_identity")
                continue
            finding_ids.add(evidence.finding_id)
            projected.append(evidence)
    return (
        tuple(sorted(projected, key=lambda item: item.finding_id)),
        tuple(sorted(failures)),
    )


def seal_ci_evidence(
    *,
    run_id: str,
    generated_at: datetime,
    changed_since: str | None,
    scanner_workspace_sha256: str | None,
    effective_config_sha256: str,
    deterministic_policy_sha256: str,
    producer_sha256: str,
    sources: Sequence[ManifestFileBinding],
    tools: Sequence[CIToolEvidence],
    findings: Sequence[CIFindingEvidence],
    finding_validation_failures: Sequence[str] = (),
    coverage: Sequence[CICoverageEvidence],
    repository_suite: CIRepositorySuiteEvidence,
    audit_run_status: AuditRunStatus | None = None,
) -> CIDeterministicEvidence:
    ordered_sources = tuple(sorted(sources, key=lambda item: item.path))
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": run_id,
        "generated_at": generated_at,
        "changed_since": changed_since,
        "audit_run_status": audit_run_status,
        "scanner_workspace_sha256": scanner_workspace_sha256,
        "effective_config_sha256": effective_config_sha256,
        "deterministic_policy_sha256": deterministic_policy_sha256,
        "producer_sha256": producer_sha256,
        "sources": ordered_sources,
        "source_tree_sha256": canonical_sha256(
            [source.model_dump(mode="json") for source in ordered_sources]
        ),
        "tools": tuple(sorted(tools, key=lambda item: item.scanner)),
        "findings": tuple(sorted(findings, key=lambda item: item.finding_id)),
        "finding_validation_failures": tuple(sorted(set(finding_validation_failures))),
        "coverage": tuple(sorted(coverage, key=lambda item: item.metric_id)),
        "repository_suite": repository_suite,
    }
    draft = CIDeterministicEvidence.model_construct(
        **payload,
        evidence_sha256="0" * 64,
    )
    payload["evidence_sha256"] = canonical_sha256(
        draft.model_dump(mode="json", exclude={"evidence_sha256"})
    )
    return CIDeterministicEvidence.model_validate(payload)


def build_ci_run_state(
    evidence: CIDeterministicEvidence,
    *,
    baseline: CIRunState | None = None,
    baseline_manifest_sha256: str | None = None,
) -> CIRunState:
    if (baseline is None) != (baseline_manifest_sha256 is None):
        raise ValueError("CI baseline state and manifest hash must be supplied together")
    comparison = (
        compare_ci_evidence(
            evidence,
            baseline,
            baseline_manifest_sha256=baseline_manifest_sha256,
        )
        if baseline is not None and baseline_manifest_sha256 is not None
        else None
    )
    failures = _analysis_failures(evidence)
    status = _job_status(evidence, comparison=comparison, analysis_failures=failures)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "evidence": evidence,
        "comparison": comparison,
        "job_status": status,
        "analysis_failures": failures,
    }
    draft = CIRunState.model_construct(
        **payload,
        state_sha256="0" * 64,
    )
    payload["state_sha256"] = canonical_sha256(
        draft.model_dump(mode="json", exclude={"state_sha256"})
    )
    return CIRunState.model_validate(payload)


def compare_ci_evidence(
    current: CIDeterministicEvidence,
    baseline: CIRunState,
    *,
    baseline_manifest_sha256: str,
) -> CIBaselineComparison:
    prior = baseline.evidence
    rejections: set[str] = set()
    if current.sources != prior.sources:
        rejections.add("source_inventory_changed")
    if current.scanner_workspace_sha256 is None or prior.scanner_workspace_sha256 is None:
        rejections.add("scanner_workspace_identity_unavailable")
    elif current.scanner_workspace_sha256 != prior.scanner_workspace_sha256:
        rejections.add("scanner_workspace_changed")
    if current.effective_config_sha256 != prior.effective_config_sha256:
        rejections.add("effective_configuration_changed")
    if current.deterministic_policy_sha256 != prior.deterministic_policy_sha256:
        rejections.add("deterministic_policy_changed")
    if current.producer_sha256 != prior.producer_sha256:
        rejections.add("producer_changed")
    current_tools = {item.scanner: item for item in current.tools}
    prior_tools = {item.scanner: item for item in prior.tools}
    current_tool_identities = {
        key: item.tool_identity_sha256 for key, item in current_tools.items()
    }
    prior_tool_identities = {key: item.tool_identity_sha256 for key, item in prior_tools.items()}
    if current_tool_identities != prior_tool_identities:
        rejections.add("tool_identity_changed")
    current_invocation_policies = {
        key: item.invocation_policy_sha256 for key, item in current_tools.items()
    }
    prior_invocation_policies = {
        key: item.invocation_policy_sha256 for key, item in prior_tools.items()
    }
    if current_invocation_policies != prior_invocation_policies:
        rejections.add("tool_invocation_policy_changed")
    if tuple(_ci_tool_semantic_payload(tool) for tool in current.tools) != tuple(
        _ci_tool_semantic_payload(tool) for tool in prior.tools
    ):
        rejections.add("tool_observation_changed")
    if (
        not current.tools
        or not prior.tools
        or any(not item.reuse_eligible for item in (*current.tools, *prior.tools))
    ):
        rejections.add("non_reusable_tool_evidence")
    if not _ci_audit_status_eligible(current.audit_run_status):
        rejections.add("current_audit_not_eligible")
    if not _ci_audit_status_eligible(prior.audit_run_status):
        rejections.add("baseline_audit_not_eligible")
    if current.repository_suite.status is CIRepositorySuiteStatus.FAILED:
        rejections.add("current_repository_suite_failed")
    if prior.repository_suite.status is CIRepositorySuiteStatus.FAILED:
        rejections.add("baseline_repository_suite_failed")
    if _analysis_failures(current) or _analysis_failures(prior):
        rejections.add("analysis_failures_present")
    if current.findings != prior.findings:
        rejections.add("finding_evidence_changed")
    if current.coverage != prior.coverage:
        rejections.add("coverage_evidence_changed")
    if current.repository_suite != prior.repository_suite:
        rejections.add("repository_suite_evidence_changed")

    prior_findings = {item.finding_id: item for item in prior.findings}
    current_findings = {item.finding_id: item for item in current.findings}
    unchanged: set[str] = set()
    new: set[str] = set()
    compatible_producer = current.producer_sha256 == prior.producer_sha256
    compatible_policy = current.deterministic_policy_sha256 == prior.deterministic_policy_sha256
    compatible_workspace = (
        current.scanner_workspace_sha256 is not None
        and current.scanner_workspace_sha256 == prior.scanner_workspace_sha256
        and current.source_tree_sha256 == prior.source_tree_sha256
    )
    for finding_id, finding in current_findings.items():
        previous = prior_findings.get(finding_id)
        current_tool = current_tools.get(finding.scanner)
        prior_tool = prior_tools.get(finding.scanner)
        if (
            previous is not None
            and finding.evidence_sha256 == previous.evidence_sha256
            and current_tool is not None
            and prior_tool is not None
            and current_tool.reuse_eligible
            and prior_tool.reuse_eligible
            and current_tool.tool_identity_sha256 == prior_tool.tool_identity_sha256
            and compatible_producer
            and compatible_policy
            and compatible_workspace
        ):
            unchanged.add(finding_id)
        else:
            new.add(finding_id)
    resolved = set(prior_findings) - set(current_findings)
    regressions = tuple(
        sorted(
            (
                *_coverage_regressions(current.coverage, prior.coverage),
                *_repository_suite_coverage_regressions(
                    current.repository_suite,
                    prior.repository_suite,
                ),
            ),
            key=lambda item: item.metric_id,
        )
    )
    return CIBaselineComparison(
        baseline_run_id=prior.run_id,
        baseline_state_sha256=baseline.state_sha256,
        baseline_manifest_sha256=baseline_manifest_sha256,
        whole_run_reuse_eligible=not rejections,
        reuse_rejections=tuple(sorted(rejections)),
        new_finding_ids=tuple(sorted(new)),
        unchanged_finding_ids=tuple(sorted(unchanged)),
        resolved_finding_ids=tuple(sorted(resolved)),
        coverage_regressions=regressions,
    )


def deterministic_ci_policy_sha256(
    config: AuditConfig,
    run_options: AuditRunOptions,
) -> str:
    """Bind only deterministic CI controls; changed-since remains prioritization metadata."""

    return canonical_sha256(
        {
            "scope": config.scope.model_dump(mode="json"),
            "repository": config.repository.model_dump(mode="json"),
            "dependency_preparation": config.dependency_preparation.model_dump(mode="json"),
            "smart_contracts": config.smart_contracts.model_dump(mode="json"),
            "reproduction": config.reproduction.model_dump(mode="json"),
            "invariants": config.invariants.model_dump(mode="json"),
            "formal": config.formal.model_dump(mode="json"),
            "scanners": config.scanners.model_dump(mode="json"),
            "quality_gates": config.quality_gates.model_dump(mode="json"),
            "run_options": {
                "scanner_only": run_options.scanner_only,
                "allow_code_egress": run_options.allow_code_egress,
                "skip_codeql": run_options.skip_codeql,
                "allow_fork_probing": run_options.allow_fork_probing,
                "severity_threshold": run_options.severity_threshold.value,
            },
        }
    )


def ci_producer_sha256(package_root: Path | None = None) -> str:
    """Hash the installed mmaudit code/templates used to produce deterministic evidence."""

    selected = package_root if package_root is not None else Path(__file__).parents[1]
    if selected.is_symlink() or selected.is_junction():
        raise ValueError("CI producer package root must be a regular non-link directory")
    root = selected.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("CI producer package root must be a regular non-link directory")
    inventory: list[dict[str, str | int]] = []
    total_bytes = 0
    for candidate in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = candidate.relative_to(root).as_posix()
        if "__pycache__" in candidate.parts:
            continue
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or candidate.is_junction():
            raise ValueError("CI producer package may not contain source links")
        if is_sensitive_workspace_path(relative, is_dir=stat.S_ISDIR(metadata.st_mode)):
            raise ValueError("CI producer package may not contain sensitive paths")
        if not stat.S_ISREG(metadata.st_mode):
            continue
        data = _read_unique_regular_file(
            candidate,
            max_bytes=_MAX_PRODUCER_BYTES - total_bytes,
            label="CI producer source",
        )
        total_bytes += len(data)
        if total_bytes > _MAX_PRODUCER_BYTES:
            raise ValueError("CI producer package exceeds the bounded source inventory")
        inventory.append(
            {
                "path": relative,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    if not inventory:
        raise ValueError("CI producer package contains no auditable source files")
    return canonical_sha256(inventory)


def build_ci_evidence_from_report(
    *,
    report: AuditReport,
    config: AuditConfig,
    run_options: AuditRunOptions,
    scanner_workspace_sha256: str | None,
    projects: Sequence[SolidityProjectMetadata],
    producer_sha256: str | None = None,
) -> CIDeterministicEvidence:
    """Project current-process scanner evidence into one safe resumable CI baseline."""

    sources = tuple(
        ManifestFileBinding(path=item.path, sha256=item.sha256, size=item.size)
        for item in sorted(report.repository.files, key=lambda item: item.path)
    )
    tools = tuple(ci_tool_evidence(run) for run in report.scanner_runs)
    reusable_scanners = {tool.scanner for tool in tools if tool.reuse_eligible}
    findings, finding_validation_failures = project_ci_findings(
        report.scanner_runs,
        sources,
        reusable_scanners=reusable_scanners,
    )
    solidity_coverage = report.effective_solidity_coverage()
    deterministic_coverage = deterministic_ci_coverage_metrics(
        solidity_coverage.quality_metrics if solidity_coverage is not None else {}
    )
    coverage = tuple(
        ci_coverage_evidence(metric_id, metric)
        for metric_id, metric in deterministic_coverage.items()
    )
    suite = build_ci_repository_suite_evidence(
        projects=projects,
        scanner_runs=report.scanner_runs,
    )
    return seal_ci_evidence(
        run_id=report.run_id,
        generated_at=report.generated_at,
        changed_since=run_options.changed_since,
        audit_run_status=report.run_status,
        scanner_workspace_sha256=scanner_workspace_sha256,
        effective_config_sha256=config.stable_hash(),
        deterministic_policy_sha256=deterministic_ci_policy_sha256(
            config,
            run_options,
        ),
        producer_sha256=producer_sha256 or ci_producer_sha256(),
        sources=sources,
        tools=tools,
        findings=findings,
        finding_validation_failures=finding_validation_failures,
        coverage=coverage,
        repository_suite=suite,
    )


def build_ci_repository_suite_evidence(
    *,
    projects: Sequence[SolidityProjectMetadata],
    scanner_runs: Sequence[ScannerRun],
) -> CIRepositorySuiteEvidence:
    frameworks: set[RepositorySuiteFramework] = set()
    for project in projects:
        if project.project_type in {SolidityProjectType.FOUNDRY, SolidityProjectType.MIXED}:
            frameworks.add(RepositorySuiteFramework.FOUNDRY)
        if project.project_type in {SolidityProjectType.HARDHAT, SolidityProjectType.MIXED}:
            frameworks.add(RepositorySuiteFramework.HARDHAT)
    if not frameworks:
        return CIRepositorySuiteEvidence.not_applicable()
    required = {f"{framework.value}_fork" for framework in frameworks}
    runs_by_name = {run.scanner: run for run in scanner_runs}
    successful: set[str] = set()
    failures: set[str] = set()
    scanner_coverage: list[CIRepositorySuiteScannerCoverage] = []
    for scanner in sorted(required):
        run = runs_by_name.get(scanner)
        selection = run.repository_suite_selection if run is not None else None
        selected_descriptor_sha256s = (
            tuple(descriptor.descriptor_sha256 for descriptor in selection.tests)
            if selection is not None
            else ()
        )
        executed_descriptor_sha256s = (
            tuple(execution.descriptor_sha256 for execution in run.repository_test_executions)
            if run is not None
            else ()
        )
        selected_test_count = selection.selected_test_count if selection is not None else 0
        executed_test_count = len(run.repository_test_executions) if run is not None else 0
        scanner_coverage.append(
            CIRepositorySuiteScannerCoverage.sealed(
                scanner=scanner,
                selection_sha256=(selection.selection_sha256 if selection is not None else None),
                selected_descriptor_sha256s=selected_descriptor_sha256s,
                executed_descriptor_sha256s=executed_descriptor_sha256s,
                selected_test_count=selected_test_count,
                executed_test_count=executed_test_count,
            )
        )
        valid = (
            run is not None
            and run.status is ScannerStatus.SUCCESS
            and run.execution_evidence is ExecutionEvidenceKind.REAL
            and run.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
            and run.machine_output_validated
            and run.execution_observation_sha256_is_valid()
            and run.repository_suite_selection is not None
            and run.repository_suite_selection.selected_test_count > 0
            and has_host_repository_suite_runtime_authority(run)
        )
        if valid:
            successful.add(scanner)
        else:
            observed = run.status.value if run is not None else "missing"
            failures.add(f"{scanner}:{observed}:hardened_current_runtime_evidence_required")
    return CIRepositorySuiteEvidence(
        status=(
            CIRepositorySuiteStatus.PASSED
            if successful == required
            else CIRepositorySuiteStatus.FAILED
        ),
        applicable_frameworks=tuple(sorted(frameworks, key=lambda item: item.value)),
        required_scanners=tuple(sorted(required)),
        successful_scanners=tuple(sorted(successful)),
        scanner_coverage=tuple(scanner_coverage),
        failures=tuple(sorted(failures)),
    )


def load_ci_baseline(
    run_dir: Path,
    *,
    expected_repository_git_commit: str | None = None,
) -> LoadedCIBaseline:
    """Load only a complete manifest-bound CI state; never execute prior artifacts."""

    return _load_ci_baseline(
        run_dir,
        expected_repository_git_commit=expected_repository_git_commit,
        require_complete_artifact_set=True,
    )


def load_ci_baseline_bundle(
    run_dir: Path,
    *,
    expected_repository_git_commit: str | None = None,
) -> LoadedCIBaseline:
    """Load the exact public three-file comparison bundle produced after full admission."""

    return _load_ci_baseline(
        run_dir,
        expected_repository_git_commit=expected_repository_git_commit,
        require_complete_artifact_set=False,
    )


def _load_ci_baseline(
    run_dir: Path,
    *,
    expected_repository_git_commit: str | None,
    require_complete_artifact_set: bool,
) -> LoadedCIBaseline:
    if not run_dir.is_absolute():
        raise ValueError("CI baseline run directory must be an absolute path")
    if run_dir.is_symlink() or run_dir.is_junction():
        raise ValueError("CI baseline run directory may not be a link")
    root = run_dir.resolve(strict=True)
    if root != run_dir:
        raise ValueError("CI baseline run directory must use its canonical path")
    if not root.is_dir():
        raise ValueError("CI baseline run path must identify a directory")
    bundle = None if require_complete_artifact_set else _read_ci_baseline_bundle_snapshot(root)
    manifest = (
        _load_ci_manifest(root / "run-evidence-manifest.json")
        if bundle is None
        else _parse_ci_manifest(bundle["run-evidence-manifest.json"].data)
    )
    if require_complete_artifact_set:
        validate_manifest_artifacts(manifest, root)
    state_binding = next(
        (binding for binding in manifest.artifacts if binding.path == CI_STATE_FILENAME),
        None,
    )
    if state_binding is None:
        raise ValueError("CI baseline manifest does not bind ci-state.json")
    raw = (
        _read_unique_regular_file(
            root / CI_STATE_FILENAME,
            max_bytes=_MAX_CI_STATE_BYTES,
            label="CI baseline state",
        )
        if bundle is None
        else bundle[CI_STATE_FILENAME].data
    )
    if len(raw) != state_binding.size or hashlib.sha256(raw).hexdigest() != state_binding.sha256:
        raise ValueError("CI baseline state differs from its manifest binding")
    state = CIRunState.model_validate(_decode_json_object(raw))
    report = (
        load_manifest_bound_report(run_dir=root, manifest=manifest)
        if bundle is None
        else _parse_ci_bundle_report(
            bundle["final-findings.json"].data,
            manifest=manifest,
        )
    )
    if report.repository.git_commit != manifest.git_commit:
        raise ValueError("CI baseline repository commit differs across bound artifacts")
    if expected_repository_git_commit is not None:
        if re.fullmatch(r"[0-9a-f]{40,64}", expected_repository_git_commit) is None:
            raise ValueError("CI baseline requires an exact lowercase changed-since commit")
        if report.repository.git_commit != expected_repository_git_commit:
            raise ValueError("CI baseline repository commit differs from changed-since")
    _validate_loaded_ci_state(
        state=state,
        report=report,
        manifest=manifest,
    )
    return LoadedCIBaseline(
        run_dir=root,
        manifest=manifest,
        report=report,
        state=state,
    )


def _validate_loaded_ci_state(
    *,
    state: CIRunState,
    report: AuditReport,
    manifest: RunEvidenceManifest,
) -> None:
    evidence = state.evidence
    if evidence.run_id != report.run_id or evidence.run_id != manifest.run_id:
        raise ValueError("CI baseline run identity differs across bound artifacts")
    if evidence.sources != tuple(manifest.sources):
        raise ValueError("CI baseline sources differ from the run manifest")
    report_sources = tuple(
        ManifestFileBinding(path=item.path, sha256=item.sha256, size=item.size)
        for item in sorted(report.repository.files, key=lambda item: item.path)
    )
    if evidence.sources != report_sources:
        raise ValueError("CI baseline sources differ from the final report")
    if evidence.source_tree_sha256 != manifest.source_tree_sha256:
        raise ValueError("CI baseline source-tree hash differs from the run manifest")
    if evidence.generated_at != report.generated_at:
        raise ValueError("CI baseline generated-at timestamp differs from the final report")
    if evidence.audit_run_status != report.run_status:
        raise ValueError("CI baseline run status differs from the final report")
    if evidence.effective_config_sha256 != report.configuration_hash:
        raise ValueError("CI baseline configuration differs from the final report")
    if manifest.run_configuration is None:
        raise ValueError("CI baseline requires reconstructable run configuration")
    config = resolve_run_evidence_config(manifest)
    run_configuration = manifest.run_configuration
    run_options = run_configuration.run_options
    if (
        evidence.effective_config_sha256 != run_configuration.effective_config_sha256
        or report.configuration_hash != run_configuration.effective_config_sha256
        or config.stable_hash() != run_configuration.effective_config_sha256
    ):
        raise ValueError("CI baseline effective configuration differs across bound artifacts")
    if report.model_configuration_hash != run_configuration.model_config_sha256:
        raise ValueError("CI baseline model configuration differs from the run manifest")
    if manifest.repository_root_name != report.repository.root_name:
        raise ValueError("CI baseline repository root identity differs across bound artifacts")
    if report.repository.changed_since != run_options.changed_since:
        raise ValueError("CI baseline changed-since metadata differs across bound artifacts")
    if report.audit_profile is not run_configuration.requested_profile:
        raise ValueError("CI baseline audit profile differs from the run manifest")
    if manifest.bindings.configuration != build_manifest_configuration_bindings(config):
        raise ValueError("CI baseline configuration bindings differ from the run manifest")
    if manifest.bindings.tools != build_manifest_tool_bindings(config, report):
        raise ValueError("CI baseline tool bindings differ from the final report")
    if not run_options.scanner_only:
        raise ValueError("CI baseline may contain only scanner-only execution")
    if run_options.allow_code_egress or report.usage:
        raise ValueError("CI baseline cannot contain model/source-egress execution")
    if evidence.changed_since != run_options.changed_since:
        raise ValueError("CI baseline changed-since metadata differs from the run manifest")
    if evidence.scanner_workspace_sha256 is None:
        raise ValueError("CI baseline lacks a complete scanner workspace identity")
    if evidence.deterministic_policy_sha256 != deterministic_ci_policy_sha256(
        config,
        run_options,
    ):
        raise ValueError("CI baseline deterministic policy differs from its manifest")
    metadata_ci = report.metadata.get("ci")
    comparison = state.comparison
    expected_ci_metadata = {
        "schema_version": "1.0",
        "enabled": True,
        "scanner_workspace_sha256": evidence.scanner_workspace_sha256,
        "producer_sha256": evidence.producer_sha256,
        "deterministic_policy_sha256": evidence.deterministic_policy_sha256,
        "baseline_state_sha256": (
            comparison.baseline_state_sha256 if comparison is not None else None
        ),
        "baseline_manifest_sha256": (
            comparison.baseline_manifest_sha256 if comparison is not None else None
        ),
        "job_status": state.job_status.value,
        "analysis_failures": list(state.analysis_failures),
        "new_findings": (
            len(comparison.new_finding_ids) if comparison is not None else len(evidence.findings)
        ),
        "unchanged_findings": (
            len(comparison.unchanged_finding_ids) if comparison is not None else 0
        ),
        "resolved_findings": (
            len(comparison.resolved_finding_ids) if comparison is not None else 0
        ),
        "coverage_regressions": (
            len(comparison.coverage_regressions) if comparison is not None else 0
        ),
        "whole_run_reuse_eligible": (
            comparison.whole_run_reuse_eligible if comparison is not None else False
        ),
        "historical_evidence_use": "comparison_only_after_current_execution",
    }
    if not isinstance(metadata_ci, dict) or metadata_ci != expected_ci_metadata:
        raise ValueError("CI baseline scanner workspace identity is absent from the report")
    expected_tools = tuple(
        sorted(
            (ci_tool_evidence(run) for run in report.scanner_runs),
            key=lambda item: item.scanner,
        )
    )
    if evidence.tools != expected_tools:
        raise ValueError("CI baseline tool evidence differs from the final report")
    source_bindings = tuple(manifest.sources)
    reusable_scanners = {tool.scanner for tool in expected_tools if tool.reuse_eligible}
    expected_findings, expected_finding_failures = project_ci_findings(
        report.scanner_runs,
        source_bindings,
        reusable_scanners=reusable_scanners,
    )
    if evidence.findings != expected_findings:
        raise ValueError("CI baseline findings differ from the final report")
    if evidence.finding_validation_failures != expected_finding_failures:
        raise ValueError("CI baseline finding failures differ from the final report")
    solidity_coverage = report.effective_solidity_coverage()
    deterministic_coverage = deterministic_ci_coverage_metrics(
        solidity_coverage.quality_metrics if solidity_coverage is not None else {}
    )
    expected_coverage = tuple(
        ci_coverage_evidence(metric_id, metric)
        for metric_id, metric in deterministic_coverage.items()
    )
    if evidence.coverage != expected_coverage:
        raise ValueError("CI baseline coverage differs from the final report")
    _validate_persisted_repository_suite(evidence, report=report)
    if state.analysis_failures:
        raise ValueError("CI baseline contains failed deterministic analysis")
    if state.job_status is CIJobStatus.COVERAGE_REGRESSION:
        raise ValueError("CI baseline contains an unresolved coverage regression")
    if not _ci_audit_status_eligible(evidence.audit_run_status):
        raise ValueError("CI baseline audit did not reach an eligible deterministic status")


def _analysis_failures(evidence: CIDeterministicEvidence) -> tuple[str, ...]:
    failures: set[str] = set()
    if evidence.scanner_workspace_sha256 is None:
        failures.add("scanner_workspace_identity_unavailable")
    if evidence.audit_run_status is None:
        failures.add("audit_run_status:UNAVAILABLE")
    elif evidence.audit_run_status in {
        AuditRunStatus.INCOMPLETE,
        AuditRunStatus.FAILED,
    }:
        failures.add(f"audit_run_status:{evidence.audit_run_status.value}")
    if not any(tool.reuse_eligible for tool in evidence.tools):
        failures.add("no_real_machine_validated_deterministic_scanner")
    if evidence.repository_suite.status is CIRepositorySuiteStatus.FAILED:
        failures.update(evidence.repository_suite.failures)
    failures.update(evidence.finding_validation_failures)
    if not evidence.coverage:
        failures.add("deterministic_coverage_evidence_unavailable")
    for metric in evidence.coverage:
        if not (metric.metric.denominator > 0 or metric.metric.not_applicable_evidence):
            failures.add(f"coverage:{metric.metric_id}:denominator_unavailable")
    return tuple(sorted(failures))


def _ci_audit_status_eligible(status: AuditRunStatus | None) -> bool:
    return status in {AuditRunStatus.COMPLETE, AuditRunStatus.DEGRADED}


def _ci_tool_semantic_payload(tool: CIToolEvidence) -> dict[str, Any]:
    return tool.model_dump(
        mode="json",
        exclude={"execution_observation_sha256", "evidence_sha256"},
    )


def _job_status(
    evidence: CIDeterministicEvidence,
    *,
    comparison: CIBaselineComparison | None,
    analysis_failures: tuple[str, ...],
) -> CIJobStatus:
    if analysis_failures:
        return CIJobStatus.ANALYSIS_FAILED
    if comparison is None:
        return CIJobStatus.NEW_FINDINGS if evidence.findings else CIJobStatus.NO_BASELINE
    if comparison.coverage_regressions:
        return CIJobStatus.COVERAGE_REGRESSION
    if comparison.new_finding_ids:
        return CIJobStatus.NEW_FINDINGS
    if comparison.unchanged_finding_ids:
        return CIJobStatus.UNCHANGED
    return CIJobStatus.CLEAN


def _repository_suite_coverage_regressions(
    current: CIRepositorySuiteEvidence,
    baseline: CIRepositorySuiteEvidence,
) -> tuple[CICoverageRegression, ...]:
    current_coverage = tuple(
        _repository_suite_coverage_metric(item) for item in current.scanner_coverage
    )
    baseline_coverage = tuple(
        _repository_suite_coverage_metric(item) for item in baseline.scanner_coverage
    )
    regressions = {
        regression.metric_id: regression
        for regression in _coverage_regressions(current_coverage, baseline_coverage)
    }
    current_by_scanner = {item.scanner: item for item in current.scanner_coverage}
    current_metrics = {item.metric_id: item for item in current_coverage}
    baseline_metrics = {item.metric_id: item for item in baseline_coverage}
    for prior in baseline.scanner_coverage:
        observed = current_by_scanner.get(prior.scanner)
        if observed is None:
            continue
        reasons = set(
            regressions[f"repository_suite.{prior.scanner}.execution_coverage"].reasons
            if f"repository_suite.{prior.scanner}.execution_coverage" in regressions
            else ()
        )
        if set(prior.selected_descriptor_sha256s) - set(observed.selected_descriptor_sha256s):
            reasons.add("repository_suite_selected_test_removed")
        if set(prior.executed_descriptor_sha256s) - set(observed.executed_descriptor_sha256s):
            reasons.add("repository_suite_executed_test_removed")
        if not reasons:
            continue
        metric_id = f"repository_suite.{prior.scanner}.execution_coverage"
        regressions[metric_id] = CICoverageRegression(
            metric_id=metric_id,
            reasons=tuple(sorted(reasons)),
            baseline=baseline_metrics[metric_id],
            current=current_metrics.get(metric_id),
        )
    return tuple(sorted(regressions.values(), key=lambda item: item.metric_id))


def _repository_suite_coverage_metric(
    evidence: CIRepositorySuiteScannerCoverage,
) -> CICoverageEvidence:
    selected = evidence.selected_test_count
    executed = evidence.executed_test_count
    complete = selected > 0 and executed == selected
    metric = CoverageMetric(
        numerator=executed,
        denominator=selected,
        population=selected,
        percentage=round((executed / selected) * 100, 4) if selected else None,
        exclusions=[],
        not_applicable_evidence=[],
        confidence=1,
        provenance=[CoverageProvenance.RUNTIME],
        failures=(
            []
            if complete
            else [
                (
                    "repository-suite execution did not cover every selected test"
                    if selected
                    else "repository-suite selection contained no executable tests"
                )
            ]
        ),
        state=(AnalysisState.DETERMINISTIC if complete else AnalysisState.ATTEMPTED_FAILED),
        detail=(f"{evidence.scanner} executed {executed} of {selected} selected repository tests."),
    )
    return ci_coverage_evidence(
        f"repository_suite.{evidence.scanner}.execution_coverage",
        metric,
    )


def _coverage_regressions(
    current: Sequence[CICoverageEvidence],
    baseline: Sequence[CICoverageEvidence],
) -> tuple[CICoverageRegression, ...]:
    current_by_id = {item.metric_id: item for item in current}
    regressions: list[CICoverageRegression] = []
    for prior in baseline:
        observed = current_by_id.get(prior.metric_id)
        reasons: set[str] = set()
        if observed is None:
            reasons.add("coverage_metric_missing")
        else:
            previous = prior.metric
            now = observed.metric
            if now.population < previous.population:
                reasons.add("coverage_population_decreased")
            if now.denominator < previous.denominator:
                reasons.add("coverage_denominator_decreased")
            if len(now.exclusions) > len(previous.exclusions):
                reasons.add("coverage_exclusions_increased")
            previous_exclusions = {
                exclusion.subject: exclusion.model_dump(mode="json")
                for exclusion in previous.exclusions
            }
            current_exclusions = {
                exclusion.subject: exclusion.model_dump(mode="json") for exclusion in now.exclusions
            }
            if set(current_exclusions) - set(previous_exclusions):
                reasons.add("coverage_new_exclusion_subject")
            if any(
                current_exclusions.get(subject) != payload
                for subject, payload in previous_exclusions.items()
                if subject in current_exclusions
            ):
                reasons.add("coverage_exclusion_evidence_changed")
            if now.numerator < previous.numerator:
                reasons.add("coverage_numerator_decreased")
            if previous.percentage is not None and (
                now.percentage is None or now.percentage < previous.percentage
            ):
                reasons.add("coverage_percentage_decreased")
            if _analysis_state_rank(now.state) < _analysis_state_rank(previous.state):
                reasons.add("coverage_analysis_state_weakened")
            if now.confidence < previous.confidence:
                reasons.add("coverage_confidence_decreased")
            if set(previous.provenance) - set(now.provenance):
                reasons.add("coverage_provenance_removed")
            if set(now.failures) - set(previous.failures):
                reasons.add("coverage_failures_increased")
        if reasons:
            regressions.append(
                CICoverageRegression(
                    metric_id=prior.metric_id,
                    reasons=tuple(sorted(reasons)),
                    baseline=prior,
                    current=observed,
                )
            )
    return tuple(sorted(regressions, key=lambda item: item.metric_id))


def _analysis_state_rank(state: AnalysisState) -> int:
    return {
        AnalysisState.NOT_ANALYZED: 0,
        AnalysisState.ATTEMPTED_FAILED: 1,
        AnalysisState.FALLBACK_PARSER: 2,
        AnalysisState.MODEL_ONLY: 2,
        AnalysisState.SCANNER_SUPPORTED: 3,
        AnalysisState.DETERMINISTIC: 4,
        AnalysisState.REPRODUCED: 5,
        AnalysisState.FORMALLY_PROVEN: 6,
    }[state]


def _validate_persisted_repository_suite(
    evidence: CIDeterministicEvidence,
    *,
    report: AuditReport,
) -> None:
    """Cross-check serialized suite claims without recreating process-local authority."""

    solidity = report.metadata.get("solidity")
    project_payloads = solidity.get("projects") if isinstance(solidity, dict) else None
    if not isinstance(project_payloads, list):
        raise ValueError("CI baseline report omits its Solidity project inventory")
    try:
        projects = tuple(
            SolidityProjectMetadata.model_validate(project) for project in project_payloads
        )
    except ValueError as exc:
        raise ValueError("CI baseline report contains invalid Solidity project metadata") from exc
    expected_frameworks: set[RepositorySuiteFramework] = set()
    for project in projects:
        if project.project_type in {SolidityProjectType.FOUNDRY, SolidityProjectType.MIXED}:
            expected_frameworks.add(RepositorySuiteFramework.FOUNDRY)
        if project.project_type in {SolidityProjectType.HARDHAT, SolidityProjectType.MIXED}:
            expected_frameworks.add(RepositorySuiteFramework.HARDHAT)
    expected = tuple(sorted(expected_frameworks, key=lambda item: item.value))
    suite = evidence.repository_suite
    if suite.applicable_frameworks != expected:
        raise ValueError("CI baseline repository-suite applicability differs from the report")
    if not expected:
        if suite.status is not CIRepositorySuiteStatus.NOT_APPLICABLE:
            raise ValueError("CI baseline claims a repository suite for a non-applicable project")
        return
    if suite.status is CIRepositorySuiteStatus.NOT_APPLICABLE:
        raise ValueError("CI baseline omits an applicable repository suite")
    runs_by_scanner = {run.scanner: run for run in report.scanner_runs}
    for coverage in suite.scanner_coverage:
        run = runs_by_scanner.get(coverage.scanner)
        selection = run.repository_suite_selection if run is not None else None
        selected = selection.selected_test_count if selection is not None else 0
        executed = len(run.repository_test_executions) if run is not None else 0
        selected_descriptor_sha256s = tuple(
            sorted(
                descriptor.descriptor_sha256
                for descriptor in (selection.tests if selection is not None else ())
            )
        )
        executed_descriptor_sha256s = tuple(
            sorted(
                execution.descriptor_sha256
                for execution in (run.repository_test_executions if run is not None else ())
            )
        )
        if (
            coverage.selection_sha256
            != (selection.selection_sha256 if selection is not None else None)
            or coverage.selected_descriptor_sha256s != selected_descriptor_sha256s
            or coverage.executed_descriptor_sha256s != executed_descriptor_sha256s
            or coverage.selected_test_count != selected
            or coverage.executed_test_count != executed
        ):
            raise ValueError("CI baseline repository-suite coverage differs from the report")
    unsuccessful = set(suite.required_scanners) - set(suite.successful_scanners)
    failures_by_scanner = {
        scanner: [failure for failure in suite.failures if failure.startswith(f"{scanner}:")]
        for scanner in suite.required_scanners
    }
    if suite.status is CIRepositorySuiteStatus.FAILED and (
        not unsuccessful
        or any(not failures_by_scanner[scanner] for scanner in unsuccessful)
        or any(failures_by_scanner[scanner] for scanner in suite.successful_scanners)
    ):
        raise ValueError("CI baseline repository-suite failures are not scanner-bound")


def _normalized_ci_command_argument(argument: str, *, index: int) -> str:
    """Normalize only volatile path/loopback coordinates, preserving semantic flags."""

    if unicodedata.normalize("NFC", argument) != argument or any(
        unicodedata.category(character).startswith("C") for character in argument
    ):
        raise ValueError("CI scanner command arguments must be normalized printable text")

    def replace_loopback(match: re.Match[str]) -> str:
        port = match.group("port")
        if port is not None and not 1 <= int(port) <= 65_535:
            return match.group(0)
        port_marker = "[EPHEMERAL_PORT]" if port is not None else "[DEFAULT_PORT]"
        return f"{match.group('scheme').lower()}[LOOPBACK]:{port_marker}"

    normalized = _LOOPBACK_URL_RE.sub(replace_loopback, argument)
    if index == 0 and _is_absolute_command_path(normalized):
        return f"[ABSOLUTE_EXECUTABLE]/{_command_path_name(normalized)}"
    if _is_absolute_command_path(normalized):
        return _normalized_absolute_command_path(normalized)
    if normalized.startswith("-") and "=" in normalized:
        option, value = normalized.split("=", maxsplit=1)
        if _is_absolute_command_path(value):
            return f"{option}={_normalized_absolute_command_path(value)}"
    return normalized


def _is_absolute_command_path(value: str) -> bool:
    return value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value) is not None


def _command_path_name(value: str) -> str:
    normalized = value.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", maxsplit=1)[-1] or "[ROOT]"


def _normalized_absolute_command_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", normalized):
        normalized = normalized[2:]
    parts = tuple(part for part in PurePosixPath(normalized).parts if part not in {"/", ""})
    if not parts:
        return normalized
    anchor = _ci_ephemeral_path_anchor(parts)
    if anchor is not None:
        position, marker = anchor
        suffix = parts[position + 1 :]
        return marker if not suffix else f"{marker}/{'/'.join(suffix)}"
    return value.replace("\\", "/")


def _ci_ephemeral_path_anchor(parts: tuple[str, ...]) -> tuple[int, str] | None:
    """Recognize only producer-owned path anchors whose prefixes are run-volatile."""

    for position, part in enumerate(parts):
        if part == "workspace" and _looks_like_ephemeral_prefix(parts[:position]):
            return position, "[WORKSPACE]"
    for position, part in enumerate(parts):
        if (
            part == "private"
            and position + 1 < len(parts)
            and parts[position + 1] == "scanner-output"
        ):
            return position, "[PRIVATE]"
    for position, part in enumerate(parts):
        if part == "mmaudit" and position > 0 and parts[position - 1] == "site-packages":
            return position, "[MMAUDIT_PACKAGE]"
    return None


def _looks_like_ephemeral_prefix(parts: tuple[str, ...]) -> bool:
    return (
        parts[:1] == ("tmp",)
        or parts[:2] == ("private", "tmp")
        or parts[:3] == ("private", "var", "folders")
        or any(
            parts[index : index + 2] == ("private", "scanner-output")
            for index in range(len(parts) - 1)
        )
    )


def _read_ci_baseline_bundle_snapshot(
    root: Path,
) -> dict[str, _CIBundleMemberObservation]:
    """Capture and revalidate the exact public bundle beneath held directory descriptors."""

    observed_root, root_descriptor, root_identity = _open_ci_bundle_root(root)
    try:
        _validate_ci_bundle_inventory_at(root_descriptor)
        initial = {
            name: _read_ci_bundle_member_at(
                root_descriptor,
                name,
                max_bytes=_ci_bundle_member_limit(name),
            )
            for name in _CI_BASELINE_BUNDLE_FILES
        }
        current_root, current_descriptor, current_identity = _open_ci_bundle_root(root)
        try:
            if observed_root != current_root or root_identity != current_identity:
                raise ValueError("CI baseline bundle root changed during inspection")
            _validate_ci_bundle_inventory_at(root_descriptor)
            _validate_ci_bundle_inventory_at(current_descriptor)
            for name, first in initial.items():
                held_final = _read_ci_bundle_member_at(
                    root_descriptor,
                    name,
                    max_bytes=_ci_bundle_member_limit(name),
                )
                current_final = _read_ci_bundle_member_at(
                    current_descriptor,
                    name,
                    max_bytes=_ci_bundle_member_limit(name),
                )
                if held_final != first or current_final != first:
                    raise ValueError(f"CI baseline bundle member changed during inspection: {name}")
            if (
                _file_identity(os.fstat(root_descriptor)) != root_identity
                or _file_identity(os.fstat(current_descriptor)) != root_identity
            ):
                raise ValueError("CI baseline bundle root changed during inspection")
        finally:
            os.close(current_descriptor)
    finally:
        os.close(root_descriptor)
    return initial


def _open_ci_bundle_root(
    path: Path,
) -> tuple[Path, int, tuple[int, int, int, int, int, int, int]]:
    """Open every absolute root component without following links."""

    absolute = Path(os.path.abspath(path))
    flags = _ci_directory_open_flags()
    descriptor: int | None = None
    try:
        descriptor = os.open(absolute.anchor, flags)
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
    except (OSError, TypeError, NotImplementedError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(
            "CI baseline bundle root cannot be opened through descriptor-safe traversal"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValueError("CI baseline bundle root must be a directory")
    return absolute, descriptor, _file_identity(metadata)


def _validate_ci_bundle_inventory_at(root_descriptor: int) -> None:
    observed: set[str] = set()
    try:
        with os.scandir(root_descriptor) as entries:
            for index, entry in enumerate(entries):
                if (
                    index >= len(_CI_BASELINE_BUNDLE_FILES)
                    or entry.name not in _CI_BASELINE_BUNDLE_FILES
                    or entry.name in observed
                ):
                    raise ValueError(
                        "CI baseline bundle contains an unexpected or unsafe member inventory"
                    )
                observed.add(entry.name)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise ValueError("CI baseline bundle inventory is unavailable") from exc
    if tuple(sorted(observed)) != _CI_BASELINE_BUNDLE_FILES:
        raise ValueError("CI baseline bundle contains an unexpected or unsafe member inventory")


def _read_ci_bundle_member_at(
    root_descriptor: int,
    name: str,
    *,
    max_bytes: int,
) -> _CIBundleMemberObservation:
    """Read one fixed bundle member relative to a held root descriptor."""

    if name not in _CI_BASELINE_BUNDLE_FILES or "/" in name or "\\" in name:
        raise ValueError("CI baseline bundle member is outside the exact inventory")
    try:
        before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise ValueError(f"CI baseline bundle member is unavailable: {name}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > max_bytes
    ):
        raise ValueError("CI baseline bundle contains an unexpected or unsafe member")
    try:
        descriptor = os.open(
            name,
            _ci_file_open_flags(),
            dir_fd=root_descriptor,
        )
    except (OSError, TypeError, NotImplementedError) as exc:
        raise ValueError(f"CI baseline bundle member could not be opened safely: {name}") from exc
    chunks: list[bytes] = []
    observed_bytes = 0
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise ValueError(f"CI baseline bundle member changed while opening: {name}")
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, max_bytes - observed_bytes + 1),
            )
            if not chunk:
                break
            observed_bytes += len(chunk)
            if observed_bytes > max_bytes:
                raise ValueError(f"CI baseline bundle member exceeds its bound: {name}")
            chunks.append(chunk)
        finished = os.fstat(descriptor)
        after = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"CI baseline bundle member could not be read safely: {name}") from exc
    finally:
        os.close(descriptor)
    identities = {
        _file_identity(before),
        _file_identity(opened),
        _file_identity(finished),
        _file_identity(after),
    }
    if len(identities) != 1 or observed_bytes != before.st_size:
        raise ValueError(f"CI baseline bundle member changed during inspection: {name}")
    return _CIBundleMemberObservation(
        data=b"".join(chunks),
        identity=_file_identity(after),
    )


def _ci_bundle_member_limit(name: str) -> int:
    return {
        CI_STATE_FILENAME: _MAX_CI_STATE_BYTES,
        "final-findings.json": _MAX_CI_REPORT_BYTES,
        "run-evidence-manifest.json": _MAX_CI_MANIFEST_BYTES,
    }[name]


def _ci_directory_open_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    close_exec = getattr(os, "O_CLOEXEC", 0)
    if (
        not isinstance(no_follow, int)
        or not isinstance(directory, int)
        or not isinstance(close_exec, int)
    ):
        raise ValueError("descriptor-relative no-follow directory access is unavailable")
    return os.O_RDONLY | no_follow | directory | close_exec


def _ci_file_open_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    close_exec = getattr(os, "O_CLOEXEC", 0)
    if (
        not isinstance(no_follow, int)
        or not isinstance(nonblock, int)
        or not isinstance(close_exec, int)
    ):
        raise ValueError("descriptor-relative no-follow file access is unavailable")
    return os.O_RDONLY | no_follow | nonblock | close_exec


def _load_ci_manifest(path: Path) -> RunEvidenceManifest:
    raw = _read_unique_regular_file(
        path,
        max_bytes=_MAX_CI_MANIFEST_BYTES,
        label="CI baseline manifest",
    )
    return _parse_ci_manifest(raw)


def _parse_ci_manifest(raw: bytes) -> RunEvidenceManifest:
    try:
        return RunEvidenceManifest.model_validate(
            _decode_json_object(raw, label="CI baseline manifest")
        )
    except ValueError as exc:
        raise ValueError("CI baseline manifest is not valid bound evidence") from exc


def _parse_ci_bundle_report(
    raw: bytes,
    *,
    manifest: RunEvidenceManifest,
) -> AuditReport:
    binding = next(
        (item for item in manifest.artifacts if item.path == "final-findings.json"),
        None,
    )
    if (
        binding is None
        or len(raw) != binding.size
        or hashlib.sha256(raw).hexdigest() != binding.sha256
    ):
        raise ValueError("CI baseline report differs from its manifest binding")
    try:
        return AuditReport.model_validate(_decode_json_object(raw, label="CI baseline report"))
    except ValueError as exc:
        raise ValueError("CI baseline report is not valid bound audit evidence") from exc


def _validated_printable(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    if (
        not value
        or value != value.strip()
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise ValueError(f"{label} must be non-empty normalized printable text")
    return value


def _read_unique_regular_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read one file through a stable no-follow descriptor."""

    if max_bytes < 0:
        raise ValueError(f"{label} exceeds the bounded inventory")
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or path.is_junction()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > max_bytes
    ):
        raise ValueError(f"{label} must be a bounded unshared regular file")
    flags = _ci_file_open_flags()
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} could not be opened safely") from exc
    chunks: list[bytes] = []
    observed_bytes = 0
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise ValueError(f"{label} changed before it was opened")
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes - observed_bytes + 1))
            if not chunk:
                break
            observed_bytes += len(chunk)
            if observed_bytes > max_bytes:
                raise ValueError(f"{label} exceeds the bounded inventory")
            chunks.append(chunk)
        finished = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} disappeared during inspection") from exc
    if (
        _file_identity(opened) != _file_identity(finished)
        or _file_identity(opened) != _file_identity(after)
        or observed_bytes != opened.st_size
    ):
        raise ValueError(f"{label} changed during inspection")
    return b"".join(chunks)


def _file_identity(
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


def _decode_json_object(
    raw: bytes,
    *,
    label: str = "CI baseline state",
) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise ValueError(f"{label} contains non-finite JSON: {value}")

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload
