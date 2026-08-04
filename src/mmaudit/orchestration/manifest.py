"""Deterministic hash-linked evidence manifests for completed local runs."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import unicodedata
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.agents.verifier import (
    insufficient_verifications,
    normalize_cross_examination_response,
    normalize_verification_response,
)
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    canonical_audit_config_json,
    model_lineage_index,
    parse_canonical_audit_config,
)
from mmaudit.constants import ALL_MODEL_ROLES, VERSION
from mmaudit.models.scheduler import (
    ABSENT_QUALIFICATION_SHA256,
    SchedulerAbsenceReason,
    SchedulerActivationStatus,
    SchedulerArtifact,
    SchedulerCampaignStatus,
    SchedulerCrossShardIntegrationOutput,
    SchedulerEvidenceCapJudgmentOutput,
    SchedulerEvidencePayloadBinding,
    SchedulerFindingReductionOutput,
    SchedulerModelRequestEvidence,
    SchedulerPassKind,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerPrivacyEvidenceCustody,
    SchedulerReportBinding,
    SchedulerReproductionHostOutput,
    SchedulerRetainedJournalReference,
    SchedulerShardInventory,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTerminalFindingState,
    SchedulerTerminalReportAuthority,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    AuditRunStatus,
    CandidateCrossExaminationResponse,
    CandidateFinding,
    CandidateFindingArtifact,
    CandidateOriginKind,
    CandidateReproductionResolution,
    ExecutionEvidenceKind,
    ExecutionOriginDispositionKind,
    FalsificationBatch,
    FalsificationDecision,
    Finding,
    FindingOriginKind,
    FindingStatus,
    FoundryInvariantHarnessSpec,
    GeneratedFoundryTestSpec,
    InvariantExecutionOriginDispositionArtifact,
    InvariantExecutionResult,
    JudgeDecisionBatch,
    LanguageCapabilityProfile,
    LanguageCapabilityArtifact,
    Location,
    LocationValidation,
    MaximumAssuranceStatus,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    PropertyCorpus,
    ReportQualityReview,
    ReproductionIntegrityStatus,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    StrictModel,
    VerificationBatch,
)
from mmaudit.models.schemas import (
    ContextRequestEvidence as ProviderContextRequestEvidence,
)
from mmaudit.models.sharding import (
    SolidityGraphsArtifact,
    SolidityIndexArtifact,
    SolidityShardPolicy,
    SolidityShardReportBinding,
    SolidityShardsArtifact,
)
from mmaudit.models.token_planning import PromptAllocationCategory, RequestTokenPlan
from mmaudit.orchestration.candidate_enrichment import attach_formal_counterexamples
from mmaudit.orchestration.context_manifest import (
    ContextManifest,
    ContextManifestReportBinding,
    ContextPreflightRequestEvidence,
    ContextRequestEvidence,
    context_manifest_report_binding,
    load_context_manifest,
    validate_context_manifest_against_usage,
)
from mmaudit.orchestration.execution_candidates import (
    validate_invariant_execution_candidate_provenance,
)
from mmaudit.orchestration.reproduction_resolution import (
    build_candidate_reproduction_resolutions,
)
from mmaudit.reporting.bundle import (
    MANIFEST_BOUND_REPORT_DELIVERABLES,
    SCANNER_SOURCE_EVIDENCE_PATH,
    CostLedgerAbsenceEvidence,
    CoverageArtifact,
    FindingsArtifact,
    ModelExecutionArtifact,
    RunCostLedgerEvidence,
    ScannerSourceAuthority,
    ScannerSourceEvidenceArtifact,
    ScannerSourceEvidenceRecord,
    SourceExcerptEvidence,
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
    build_scanner_source_evidence_artifact,
    scanner_source_authority,
)
from mmaudit.reporting.client import (
    build_source_excerpt_evidence,
    render_client_markdown_from_artifact,
)
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.run_authority import (
    RUN_TERMINAL_REPORT_AUTHORITY_PATH,
    RunTerminalReportAuthority,
)
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import effective_report_status, report_status_metadata
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name, is_sensitive_workspace_path
from mmaudit.scanners.base import ScannerWorkspaceTextRecord, observe_scanner_workspace_texts
from mmaudit.scanners.normalization import validate_real_scanner_normalization_replay
from mmaudit.scanners.projection import project_scanner_finding
from mmaudit.solidity.sharding import (
    verify_solidity_shard_projection,
    verify_solidity_shard_repository_projection,
)

if TYPE_CHECKING:
    from mmaudit.models.qualification import (
        QualifiedReasoningRoleBinding,
        VerifiedProductionQualification,
    )
    from mmaudit.models.reasoning import ReasoningPolicyArtifact
    from mmaudit.models.registry import ProductionQualificationValidation
    from mmaudit.models.schemas import UsageRecord
    from mmaudit.orchestration.scheduler import SchedulerJournal

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_SCHEDULER_PRIVACY_EVIDENCE_BYTES = 1_048_576
_MAX_MANIFEST_FILES = 100_000
_MAX_MANIFEST_BYTES = 4 * 1024**3
_MAX_JSON_ARTIFACT_BYTES = 100_000_000
LANGUAGE_CAPABILITY_ARTIFACT_PATH = "language-capability.json"
_CURRENT_SCANNER_REPLAY_AUTHORITY = frozenset({"gitleaks", "osv", "semgrep", "slither", "trivy"})
SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME = "scheduler-journal-reference.json"


class ManifestFileBinding(StrictModel):
    """Hash and size for one normalized source or run-artifact path."""

    path: str = Field(min_length=1, max_length=4_096)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if not normalized or normalized == "." or is_sensitive_workspace_path(normalized):
            raise ValueError("manifest file path must identify a file")
        return normalized


class ManifestHashBinding(StrictModel):
    """Named digest for one normalized security-relevant evidence projection."""

    identifier: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@#-]*$",
    )
    sha256: str = Field(pattern=_SHA256_PATTERN)
    details: dict[str, str] = Field(default_factory=dict, max_length=50)

    @field_validator("details")
    @classmethod
    def details_are_bounded(cls, value: dict[str, str]) -> dict[str, str]:
        if any(
            not key
            or len(key) > 100
            or len(detail) > 2_000
            or any(ord(character) < 32 or ord(character) == 127 for character in key)
            for key, detail in value.items()
        ):
            raise ValueError("manifest binding details are not bounded")
        return value


class ManifestBindingSet(StrictModel):
    """Required binding categories from the MAN-001 acceptance contract."""

    configuration: list[ManifestHashBinding] = Field(min_length=1, max_length=100)
    prompts: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    models: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    tools: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    compilers: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    isolation: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    seeds: list[ManifestHashBinding] = Field(min_length=1, max_length=100_000)
    corpora: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    harnesses: list[ManifestHashBinding] = Field(min_length=1, max_length=100_000)
    reproductions: list[ManifestHashBinding] = Field(min_length=1, max_length=100_000)
    coverage: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def categories_are_sorted_and_unique(self) -> ManifestBindingSet:
        for field_name in self.__class__.model_fields:
            bindings = getattr(self, field_name)
            identifiers = [binding.identifier for binding in bindings]
            if identifiers != sorted(set(identifiers)):
                raise ValueError(f"manifest {field_name} bindings must be unique and sorted")
        return self


class RunConfigurationBinding(StrictModel):
    """Self-contained, secret-free reconstruction record for one audit invocation."""

    file_configuration_json: str = Field(min_length=2, max_length=2_000_000)
    file_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    environment_overrides: AuditConfigOverrides
    environment_overrides_sha256: str = Field(pattern=_SHA256_PATTERN)
    cli_overrides: AuditConfigOverrides
    cli_overrides_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_options: AuditRunOptions
    run_options_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_configuration_json: str = Field(min_length=2, max_length=2_000_000)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    invocation_sha256: str = Field(pattern=_SHA256_PATTERN)
    requested_profile: AuditProfile
    achieved_profile: AuditProfile | None = None
    requested_language_profile: LanguageCapabilityProfile
    achieved_language_profile: LanguageCapabilityProfile | None = None
    reduced_language_capability: bool

    @model_validator(mode="after")
    def configuration_layers_reconcile(self) -> RunConfigurationBinding:
        file_config = parse_canonical_audit_config(self.file_configuration_json)
        if file_config.stable_hash() != self.file_config_sha256:
            raise ValueError("run file-configuration hash is inconsistent")
        if self.environment_overrides.stable_hash() != self.environment_overrides_sha256:
            raise ValueError("run environment-override hash is inconsistent")
        if self.cli_overrides.stable_hash() != self.cli_overrides_sha256:
            raise ValueError("run CLI-override hash is inconsistent")
        if self.run_options.stable_hash() != self.run_options_sha256:
            raise ValueError("run-options hash is inconsistent")
        effective = self.cli_overrides.apply(self.environment_overrides.apply(file_config))
        if canonical_audit_config_json(effective) != self.effective_configuration_json:
            raise ValueError("run effective configuration does not replay from its override layers")
        if effective.stable_hash() != self.effective_config_sha256:
            raise ValueError("run effective-configuration hash is inconsistent")
        if effective.model_hash() != self.model_config_sha256:
            raise ValueError("run model-configuration hash is inconsistent")
        if effective.profile is not self.requested_profile:
            raise ValueError("run requested profile differs from the effective configuration")
        if effective.language_profile is not self.requested_language_profile:
            raise ValueError(
                "run requested language profile differs from the effective configuration"
            )
        if (
            self.achieved_profile is not None
            and self.achieved_profile is not self.requested_profile
        ):
            raise ValueError("run cannot claim an unrequested achieved profile")
        if (
            self.achieved_language_profile is not None
            and self.achieved_language_profile is not self.requested_language_profile
        ):
            raise ValueError("run cannot claim an unrequested achieved language profile")
        expected_reduced = (
            self.achieved_language_profile
            is LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW
        )
        if self.reduced_language_capability != expected_reduced:
            raise ValueError("run reduced language capability is inconsistent")
        if self.achieved_profile is AuditProfile.MAXIMUM_ASSURANCE and (
            self.achieved_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
            or self.reduced_language_capability
        ):
            raise ValueError(
                "achieved maximum assurance requires achieved Solidity/EVM capability"
            )
        expected_invocation = canonical_sha256(
            {
                "environment_overrides_sha256": self.environment_overrides_sha256,
                "cli_overrides_sha256": self.cli_overrides_sha256,
                "run_options_sha256": self.run_options_sha256,
                "effective_config_sha256": self.effective_config_sha256,
                "requested_profile": self.requested_profile.value,
                "achieved_profile": (
                    self.achieved_profile.value if self.achieved_profile is not None else None
                ),
                "requested_language_profile": self.requested_language_profile.value,
                "achieved_language_profile": (
                    self.achieved_language_profile.value
                    if self.achieved_language_profile is not None
                    else None
                ),
                "reduced_language_capability": self.reduced_language_capability,
            }
        )
        if self.invocation_sha256 != expected_invocation:
            raise ValueError("run invocation hash is inconsistent")
        return self

    def reconstruct_effective_config(
        self,
        *,
        file_config: AuditConfig | None = None,
    ) -> AuditConfig:
        """Replay recorded safe layers over recorded or explicitly observed file config."""

        base = (
            parse_canonical_audit_config(self.file_configuration_json)
            if file_config is None
            else file_config
        )
        return self.cli_overrides.apply(self.environment_overrides.apply(base))


class RunEvidenceManifest(StrictModel):
    """Self-hashed manifest over source, run evidence projections, and artifacts."""

    schema_version: Literal["1.0", "1.1", "1.2"] = "1.2"
    generated_by: Literal["mmaudit"] = "mmaudit"
    tool_version: str = Field(min_length=1, max_length=100)
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    repository_root_name: str = Field(min_length=1, max_length=500)
    git_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40,64}$")
    sources: list[ManifestFileBinding] = Field(max_length=_MAX_MANIFEST_FILES)
    source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_configuration: RunConfigurationBinding | None = None
    bindings: ManifestBindingSet
    artifacts: list[ManifestFileBinding] = Field(min_length=1, max_length=_MAX_MANIFEST_FILES)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def hashes_and_paths_are_consistent(self) -> RunEvidenceManifest:
        if (self.schema_version in {"1.1", "1.2"}) != (self.run_configuration is not None):
            raise ValueError(
                f"manifest {self.schema_version} requires run configuration provenance"
            )
        source_paths = [binding.path for binding in self.sources]
        if source_paths != sorted(set(source_paths)):
            raise ValueError("manifest source paths must be unique and sorted")
        artifact_paths = [binding.path for binding in self.artifacts]
        if artifact_paths != sorted(set(artifact_paths)):
            raise ValueError("manifest artifact paths must be unique and sorted")
        if self.schema_version == "1.2":
            missing_report_artifacts = sorted(
                (MANIFEST_BOUND_REPORT_DELIVERABLES | {RUN_TERMINAL_REPORT_AUTHORITY_PATH})
                - set(artifact_paths)
            )
            if missing_report_artifacts:
                raise ValueError(
                    "manifest 1.2 requires report artifact bindings: "
                    + ", ".join(missing_report_artifacts)
                )
        if "run-evidence-manifest.json" in artifact_paths:
            raise ValueError("manifest cannot include itself as an artifact")
        expected_source = canonical_sha256(
            [source.model_dump(mode="json") for source in self.sources]
        )
        if self.source_tree_sha256 != expected_source:
            raise ValueError("manifest source-tree hash does not match source bindings")
        exclusions = {"manifest_sha256"}
        if self.schema_version == "1.0":
            exclusions.add("run_configuration")
        expected_manifest = canonical_sha256(self.model_dump(mode="json", exclude=exclusions))
        if self.manifest_sha256 != expected_manifest:
            raise ValueError("manifest self-hash does not match its canonical contents")
        return self


class _ManifestReproductionArtifact(StrictModel):
    """Typed reproduction evidence needed for cross-artifact manifest validation."""

    schema_version: Literal["1.0"]
    test_specifications: list[GeneratedFoundryTestSpec] = Field(max_length=100_000)
    results: list[ReproductionResult] = Field(max_length=100_000)
    candidate_resolutions: list[CandidateReproductionResolution] = Field(
        default_factory=list,
        max_length=100_000,
    )
    falsification_decisions: list[FalsificationDecision] = Field(
        default_factory=list,
        max_length=100_000,
    )

    @model_validator(mode="after")
    def tests_results_and_resolutions_are_unique(self) -> _ManifestReproductionArtifact:
        specification_keys = [(item.candidate_id, item.name) for item in self.test_specifications]
        result_keys = [(item.candidate_id, item.test_name) for item in self.results]
        if len(specification_keys) != len(set(specification_keys)):
            raise ValueError("reproduction test specifications must be unique")
        if len(result_keys) != len(set(result_keys)):
            raise ValueError("reproduction results must be unique")
        resolution_ids = [item.candidate_id for item in self.candidate_resolutions]
        if resolution_ids != sorted(set(resolution_ids)):
            raise ValueError("candidate reproduction resolutions must be unique and sorted")
        return self


def canonical_sha256(value: Any) -> str:
    """Hash a JSON-compatible value using a single canonical encoding."""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def seal_run_evidence_manifest(
    *,
    run_id: str,
    repository_root_name: str,
    git_commit: str | None,
    sources: list[ManifestFileBinding],
    run_configuration: RunConfigurationBinding,
    bindings: ManifestBindingSet,
    artifacts: list[ManifestFileBinding],
    schema_version: Literal["1.1", "1.2"] = "1.2",
    tool_version: str = VERSION,
) -> RunEvidenceManifest:
    """Issue a new complete report-bundle manifest using the current schema only."""

    if schema_version != "1.2":
        raise ValueError("new manifest issuance requires schema 1.2 and all report leaves")
    return _seal_run_evidence_manifest(
        run_id=run_id,
        repository_root_name=repository_root_name,
        git_commit=git_commit,
        sources=sources,
        run_configuration=run_configuration,
        bindings=bindings,
        artifacts=artifacts,
        schema_version=schema_version,
        tool_version=tool_version,
    )


def _seal_run_evidence_manifest(
    *,
    run_id: str,
    repository_root_name: str,
    git_commit: str | None,
    sources: list[ManifestFileBinding],
    run_configuration: RunConfigurationBinding,
    bindings: ManifestBindingSet,
    artifacts: list[ManifestFileBinding],
    schema_version: Literal["1.1", "1.2"],
    tool_version: str,
) -> RunEvidenceManifest:
    """Reconstruct a current or already-sealed legacy manifest deterministically."""

    ordered_sources = sorted(sources, key=lambda item: item.path)
    ordered_artifacts = sorted(artifacts, key=lambda item: item.path)
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "generated_by": "mmaudit",
        "tool_version": tool_version,
        "run_id": run_id,
        "repository_root_name": repository_root_name,
        "git_commit": git_commit,
        "sources": [item.model_dump(mode="json") for item in ordered_sources],
        "source_tree_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in ordered_sources]
        ),
        "run_configuration": run_configuration.model_dump(mode="json"),
        "bindings": bindings.model_dump(mode="json"),
        "artifacts": [item.model_dump(mode="json") for item in ordered_artifacts],
    }
    payload["manifest_sha256"] = canonical_sha256(payload)
    return RunEvidenceManifest.model_validate(payload)


def build_run_evidence_manifest(
    *,
    run_dir: Path,
    report: AuditReport,
    config: AuditConfig,
    file_config: AuditConfig | None = None,
    environment_overrides: AuditConfigOverrides | None = None,
    cli_overrides: AuditConfigOverrides | None = None,
    run_options: AuditRunOptions | None = None,
    production_qualification: VerifiedProductionQualification | None = None,
    scheduler_runtime_journal: SchedulerJournal | None = None,
) -> RunEvidenceManifest:
    """Build runtime MAN-001 projections, requiring opaque qualification authority."""

    return _build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
        file_config=file_config,
        environment_overrides=environment_overrides,
        cli_overrides=cli_overrides,
        run_options=run_options,
        production_qualification=production_qualification,
        scheduler_runtime_journal=scheduler_runtime_journal,
        sealed_verification_manifest=None,
    )


def rebuild_run_evidence_manifest_for_verification(
    *,
    run_dir: Path,
    report: AuditReport,
    config: AuditConfig,
    sealed_manifest: RunEvidenceManifest,
    file_config: AuditConfig | None = None,
    environment_overrides: AuditConfigOverrides | None = None,
    cli_overrides: AuditConfigOverrides | None = None,
    run_options: AuditRunOptions | None = None,
) -> RunEvidenceManifest:
    """Recalculate a sealed manifest without minting runtime qualification authority.

    This read-only path checks the manifest's issuance-time serialized qualification
    projection against bound artifacts and usage. It cannot emit a production
    manifest or grant fresh reasoning credit.
    """

    absolute = Path(os.path.abspath(run_dir))
    try:
        root = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValueError("sealed run directory is unavailable") from exc
    if root != absolute or not root.is_dir() or root.is_symlink() or root.is_junction():
        raise ValueError("sealed run directory must be canonical and non-linked")
    with _open_json_artifact_observation(
        root,
        "run-evidence-manifest.json",
    ) as on_disk_payload:
        on_disk_manifest = RunEvidenceManifest.model_validate(on_disk_payload)
        if on_disk_manifest != sealed_manifest:
            raise ValueError("verification manifest differs from the exact sealed on-disk manifest")
        return _build_run_evidence_manifest(
            run_dir=root,
            report=report,
            config=config,
            file_config=file_config,
            environment_overrides=environment_overrides,
            cli_overrides=cli_overrides,
            run_options=run_options,
            production_qualification=None,
            scheduler_runtime_journal=None,
            sealed_verification_manifest=on_disk_manifest,
        )


def _build_run_evidence_manifest(
    *,
    run_dir: Path,
    report: AuditReport,
    config: AuditConfig,
    file_config: AuditConfig | None,
    environment_overrides: AuditConfigOverrides | None,
    cli_overrides: AuditConfigOverrides | None,
    run_options: AuditRunOptions | None,
    production_qualification: VerifiedProductionQualification | None,
    scheduler_runtime_journal: SchedulerJournal | None,
    sealed_verification_manifest: RunEvidenceManifest | None,
) -> RunEvidenceManifest:
    """Build either runtime evidence or a read-only verification projection."""

    root = run_dir.resolve(strict=True)
    effective_config = config.effective()
    base_config = file_config or effective_config
    environment_layer = environment_overrides or AuditConfigOverrides()
    cli_layer = cli_overrides or AuditConfigOverrides()
    invocation_options = run_options or AuditRunOptions()
    run_configuration = _run_configuration_binding(
        report=report,
        file_config=base_config,
        environment_overrides=environment_layer,
        cli_overrides=cli_layer,
        run_options=invocation_options,
        effective_config=effective_config,
    )
    sources = sorted(
        (
            ManifestFileBinding(
                path=source.path,
                sha256=source.sha256,
                size=source.size,
            )
            for source in report.repository.files
        ),
        key=lambda item: item.path,
    )
    source_tree_sha256 = canonical_sha256([source.model_dump(mode="json") for source in sources])
    validate_report_privacy_consistency(
        report,
        source_tree_sha256=source_tree_sha256,
        expected_source_classification=run_configuration.run_options.privacy_source_classification,
    )
    report_bundle_required = (
        sealed_verification_manifest is None or sealed_verification_manifest.schema_version == "1.2"
    )
    _validate_report_artifact_consistency(
        root,
        report,
        report_bundle_required=report_bundle_required,
    )
    _validate_repository_differential_configuration(report, effective_config)
    for artifact_name, report_key in (
        ("privacy-policy.json", "effective_policy"),
        ("privacy-source-provenance.json", "source_provenance"),
    ):
        path = root / artifact_name
        reported = report.privacy.get(report_key)
        if path.exists() != (reported is not None):
            raise ValueError(f"{artifact_name} presence differs from the final report")
        if reported is not None and _read_json_artifact(root, artifact_name) != reported:
            raise ValueError(f"{artifact_name} differs from the final report")
    compilation = _read_json_artifact(root, "solidity-compilation.json")
    harness_plan = _read_json_artifact(root, "invariant-harness-plan.json")
    property_corpus = _read_json_artifact(root, "property-corpus.json")
    invariant_results = _read_json_artifact(root, "invariant-execution-results.json")
    formal_results = _read_json_artifact(root, "formal-results.json")
    reproduction_results = _read_json_artifact(root, "reproduction-results.json")
    scanner_results = _read_json_artifact(root, "scanner-results.json")
    solidity_coverage = _read_json_artifact(root, "solidity-coverage.json")
    model_coverage = _read_json_artifact(root, "model-review-coverage.json")
    scope_assessment = _read_json_artifact(root, "scope-assessment.json")
    language_artifact_present = (
        root / LANGUAGE_CAPABILITY_ARTIFACT_PATH
    ).is_file()
    if report_bundle_required:
        _validate_language_capability_artifact(root, report)
    elif language_artifact_present or report.language_capability is not None:
        if not language_artifact_present or report.language_capability is None:
            raise ValueError(
                "legacy language capability evidence is only valid when report and artifact agree"
            )
        _validate_language_capability_artifact(root, report)
    context_manifest = _validated_context_manifest(root, report)
    _validate_context_manifest_configuration(context_manifest, effective_config)
    qualification_path = root / "model-qualification-runtime.json"
    if qualification_path.is_symlink() or qualification_path.is_junction():
        raise ValueError("run model qualification artifact may not be a link")
    qualification_runtime = (
        _read_json_artifact(root, "model-qualification-runtime.json")
        if qualification_path.exists()
        else None
    )
    scheduler_path = root / "scheduler-state.json"
    if (
        sealed_verification_manifest is None
        and (scheduler_path.exists() or scheduler_path.is_symlink() or scheduler_path.is_junction())
        and scheduler_runtime_journal is None
    ):
        raise ValueError("scheduler manifest issuance requires live runtime journal authority")
    scheduler_artifact = validate_scheduler_artifact(
        root,
        report,
        config=effective_config,
        qualification_runtime=qualification_runtime,
        scheduler_runtime_journal=scheduler_runtime_journal,
        require_retained_usage_custody=report_bundle_required,
    )
    if report.schema_version == "1.2" or report_bundle_required:
        _validate_model_execution_cost_ledger_custody(
            root,
            report,
            scheduler_artifact,
            current_model_execution_required=report_bundle_required,
        )
    if report_bundle_required:
        _validate_run_terminal_report_authority(
            root,
            report,
            scheduler_artifact=scheduler_artifact,
            achieved_profile=run_configuration.achieved_profile,
        )

    bindings = ManifestBindingSet(
        configuration=_configuration_bindings(effective_config),
        prompts=_prompt_bindings(report),
        models=_model_bindings(
            effective_config,
            report,
            qualification_runtime=qualification_runtime,
            production_qualification=production_qualification,
            sealed_verification_bindings=(
                sealed_verification_manifest.bindings.models
                if sealed_verification_manifest is not None
                else None
            ),
        ),
        tools=_tool_bindings(effective_config, report),
        compilers=_compiler_bindings(effective_config, compilation),
        isolation=_isolation_bindings(effective_config, report, compilation),
        seeds=_seed_bindings(
            property_corpus,
            harness_plan,
            invariant_results,
            formal_results,
            reproduction_results,
            scanner_results,
        ),
        corpora=_corpus_bindings(property_corpus),
        harnesses=_harness_bindings(harness_plan, invariant_results, reproduction_results),
        reproductions=_reproduction_bindings(reproduction_results),
        coverage=_coverage_bindings(
            report,
            solidity_coverage,
            model_coverage,
            scope_assessment,
            context_manifest,
            scheduler_artifact,
            legacy_schema_1_1=(
                sealed_verification_manifest is not None
                and sealed_verification_manifest.schema_version == "1.1"
            ),
        ),
    )
    artifacts = _collect_artifacts(root)
    manifest_schema: Literal["1.1", "1.2"] = (
        "1.1"
        if sealed_verification_manifest is not None
        and sealed_verification_manifest.schema_version == "1.1"
        else "1.2"
    )
    return _seal_run_evidence_manifest(
        run_id=report.run_id,
        repository_root_name=report.repository.root_name,
        git_commit=report.repository.git_commit,
        sources=sources,
        run_configuration=run_configuration,
        bindings=bindings,
        artifacts=artifacts,
        schema_version=manifest_schema,
        tool_version=VERSION,
    )


def validate_report_privacy_consistency(
    report: AuditReport,
    *,
    source_tree_sha256: str,
    expected_source_classification: object | None = None,
) -> None:
    """Fail closed when serialized privacy claims disagree across run evidence."""

    from mmaudit.privacy import EffectivePrivacyPolicyEvidence
    from mmaudit.repository.privacy_provenance import PrivacySourceProvenanceEvidence

    effective_payload = report.privacy.get("effective_policy")
    provenance_payload = report.privacy.get("source_provenance")
    effective = (
        EffectivePrivacyPolicyEvidence.model_validate(effective_payload)
        if effective_payload is not None
        else None
    )
    provenance = (
        PrivacySourceProvenanceEvidence.model_validate(provenance_payload)
        if provenance_payload is not None
        else None
    )

    if provenance is not None and provenance.source_sha256 != source_tree_sha256:
        raise ValueError("privacy source provenance differs from the manifest source tree")
    expected_classification = (
        getattr(
            expected_source_classification,
            "value",
            expected_source_classification,
        )
        if expected_source_classification is not None
        else None
    )
    if (
        provenance is not None
        and expected_classification is not None
        and provenance.source_classification != expected_classification
    ):
        raise ValueError("run source classification differs from source provenance")
    if effective is not None:
        if provenance is None:
            raise ValueError("effective privacy policy lacks trusted source provenance")
        if effective.source_sha256 != source_tree_sha256:
            raise ValueError("effective privacy policy differs from the manifest source tree")
        if effective.source_sha256 != provenance.source_sha256:
            raise ValueError("effective privacy policy and source provenance disagree")
        if effective.source_classification.value != provenance.source_classification:
            raise ValueError("effective privacy policy and source classification disagree")
        if effective.source_provenance_sha256 != provenance.evidence_sha256:
            raise ValueError("effective privacy policy binds different source provenance")
        configured_profile = report.privacy.get("profile")
        if configured_profile != effective.privacy_profile.value:
            raise ValueError("report privacy profile differs from its effective policy")
        if (
            expected_classification is not None
            and expected_classification != effective.source_classification.value
        ):
            raise ValueError("run source classification differs from its effective policy")

    for usage in report.usage:
        routing = usage.routing
        if effective is None or provenance is None:
            raise ValueError("provider usage lacks effective privacy and provenance evidence")
        consent_expiry = (
            effective.consent_expires_at.isoformat()
            if effective.consent_expires_at is not None
            else None
        )
        expected_routing = {
            "data_collection": effective.data_collection,
            "zdr_requested": effective.require_zdr,
            "privacy_profile": effective.privacy_profile.value,
            "privacy_authorization": (
                "STRICT_ZDR_ENFORCED" if effective.require_zdr else "CONSENT_BOUND_NON_ZDR"
            ),
            "privacy_source_classification": effective.source_classification.value,
            "privacy_source_sha256": effective.source_sha256,
            "effective_privacy_policy_sha256": effective.evidence_sha256,
            "privacy_source_provenance_sha256": provenance.evidence_sha256,
            "privacy_consent_file_sha256": effective.consent_file_sha256,
            "privacy_consent_sha256": effective.consent_sha256,
            "privacy_consent_expires_at": consent_expiry,
        }
        if any(routing.get(key) != value for key, value in expected_routing.items()):
            raise ValueError("provider usage privacy routing disagrees with report evidence")


def _post_judgment_execution_resolution_ids(
    *,
    report: AuditReport,
    execution_candidate_ids: set[str],
    pre_judgment_high_critical_ids: set[str],
) -> set[str]:
    """Derive execution candidates whose high/critical obligation arose at judgment."""

    forced_ids: set[str] = set()
    for finding in [*report.findings, *report.rejected_findings]:
        if (
            finding.origin_kind is not FindingOriginKind.DETERMINISTIC_EXECUTION
            or finding.status is FindingStatus.REJECTED
            or finding.severity not in {Severity.HIGH, Severity.CRITICAL}
        ):
            continue
        forced_ids.update(
            (set(finding.contributing_candidate_ids) & execution_candidate_ids)
            - pre_judgment_high_critical_ids
        )
    return forced_ids


def _validate_reproduction_candidate_obligations(
    *,
    report: AuditReport,
    candidate_artifact: CandidateFindingArtifact,
    execution_candidate_ids: set[str],
    reproduction_artifact: _ManifestReproductionArtifact,
) -> None:
    """Bind terminal candidate obligations to typed reproduction evidence."""

    if reproduction_artifact.results != report.reproductions:
        raise ValueError("reproduction-results.json differs from final report reproductions")
    if reproduction_artifact.falsification_decisions != report.falsification_decisions:
        raise ValueError(
            "reproduction-results.json differs from final report falsification decisions"
        )

    specification_keys = {
        (item.candidate_id, item.name) for item in reproduction_artifact.test_specifications
    }
    result_keys = {(item.candidate_id, item.test_name) for item in reproduction_artifact.results}
    if result_keys != specification_keys:
        raise ValueError("reproduction results do not exactly cover test specifications")

    candidates_by_id = {
        candidate.candidate_id: candidate for candidate in candidate_artifact.findings
    }
    candidate_ids = set(candidates_by_id)
    if not {candidate_id for candidate_id, _name in specification_keys} <= candidate_ids:
        raise ValueError("reproduction test specifications reference missing candidates")

    resolution_ids = {
        resolution.candidate_id for resolution in reproduction_artifact.candidate_resolutions
    }
    if not resolution_ids <= candidate_ids:
        raise ValueError("candidate reproduction resolutions reference missing candidates")
    for resolution in reproduction_artifact.candidate_resolutions:
        candidate = candidates_by_id[resolution.candidate_id]
        if (
            candidate.severity not in {Severity.HIGH, Severity.CRITICAL}
            and candidate.origin_kind is not CandidateOriginKind.DETERMINISTIC_EXECUTION
        ):
            raise ValueError(
                "candidate reproduction resolutions may only adjudicate high/critical "
                "or execution-origin candidates"
            )

    high_critical_candidate_ids = {
        candidate.candidate_id
        for candidate in candidate_artifact.findings
        if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
    }
    high_critical_execution_ids: set[str] = set()
    post_judgment_execution_ids = _post_judgment_execution_resolution_ids(
        report=report,
        execution_candidate_ids=execution_candidate_ids,
        pre_judgment_high_critical_ids=high_critical_candidate_ids,
    )
    accepted_statuses = {
        FindingStatus.CONFIRMED,
        FindingStatus.STRONGLY_SUPPORTED,
        FindingStatus.HIGH_CONFIDENCE,
        FindingStatus.PLAUSIBLE,
    }
    for finding in [*report.findings, *report.rejected_findings]:
        if (
            finding.origin_kind is not FindingOriginKind.DETERMINISTIC_EXECUTION
            or finding.status is FindingStatus.REJECTED
            or finding.severity not in {Severity.HIGH, Severity.CRITICAL}
        ):
            continue
        contributing_execution_ids = (
            set(finding.contributing_candidate_ids) & execution_candidate_ids
        )
        high_critical_execution_ids.update(contributing_execution_ids)
        elevated_ids = contributing_execution_ids & post_judgment_execution_ids
        if not elevated_ids:
            continue
        if finding.status in accepted_statuses:
            raise ValueError(
                "post-judgment execution severity elevation cannot retain an accepted status"
            )

    required_resolution_ids = high_critical_candidate_ids | high_critical_execution_ids
    if not required_resolution_ids <= resolution_ids:
        raise ValueError(
            "high/critical candidate obligations require terminal candidate resolutions"
        )
    if post_judgment_execution_ids and (
        report.completed or report.run_status is AuditRunStatus.COMPLETE
    ):
        raise ValueError(
            "post-judgment execution severity elevation requires a non-complete report"
        )

    qualifying_reproduction_refs: dict[str, set[str]] = {}
    for result in reproduction_artifact.results:
        if (
            result.state
            in {
                ReproductionState.REPRODUCED,
                ReproductionState.REPRODUCED_AND_MINIMIZED,
            }
            and result.attempts > 0
            and result.successful_attempts == result.attempts
            and result.integrity is not None
            and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
        ):
            qualifying_reproduction_refs.setdefault(result.candidate_id, set()).add(
                f"reproduction:{result.integrity.integrity_sha256}"
            )
    for resolution in reproduction_artifact.candidate_resolutions:
        expected_refs = qualifying_reproduction_refs.get(resolution.candidate_id, set())
        if resolution.kind is ReproductionResolutionKind.REPRODUCED:
            if set(resolution.evidence_refs) != expected_refs:
                raise ValueError("reproduced resolution is not exactly bound to qualifying results")
        elif resolution.evidence_refs:
            raise ValueError("inconclusive resolution contains unsupported evidence references")
        elif expected_refs:
            raise ValueError("inconclusive resolution contradicts a qualifying reproduction result")
    expected_resolutions = build_candidate_reproduction_resolutions(
        candidates=candidate_artifact.findings,
        results=reproduction_artifact.results,
        forced_candidate_ids=post_judgment_execution_ids,
    )
    if reproduction_artifact.candidate_resolutions != expected_resolutions:
        raise ValueError("candidate reproduction resolutions differ from deterministic replay")


def _scanner_source_record_key(
    finding_id: str,
    location: Location | SourceExcerptEvidence,
) -> tuple[str, str, int, int, str]:
    start_line = (
        location.cited_start_line
        if isinstance(location, SourceExcerptEvidence)
        else location.start_line
    )
    end_line = (
        location.cited_end_line
        if isinstance(location, SourceExcerptEvidence)
        else location.end_line
    )
    return (
        finding_id,
        location.path,
        start_line,
        end_line,
        location.symbol or "",
    )


def _validate_scanner_source_evidence_artifact(
    root: Path,
    report: AuditReport,
    *,
    replay_authorized_scanner_fingerprints: frozenset[str],
) -> dict[tuple[str, str, int, int, str], ScannerSourceEvidenceRecord]:
    """Rebuild every supplemental scanner excerpt from bound private workspace bytes."""

    repository_paths = {item.path for item in report.repository.files}
    required: list[tuple[Finding, Location, ScannerSourceAuthority]] = []
    for finding in [*report.findings, *report.filtered_findings]:
        for location in finding.locations:
            if location.path in repository_paths:
                continue
            authority = scanner_source_authority(report, finding, location)
            if authority.scanner_finding.fingerprint not in replay_authorized_scanner_fingerprints:
                raise ValueError(
                    "scanner source evidence lacks exact normalization replay authority"
                )
            required.append((finding, location, authority))

    evidence_path = root / SCANNER_SOURCE_EVIDENCE_PATH
    present = evidence_path.exists() or evidence_path.is_symlink() or evidence_path.is_junction()
    if present != bool(required):
        raise ValueError(
            "scanner source evidence presence differs from supplemental final locations"
        )
    if not required:
        return {}

    artifact = ScannerSourceEvidenceArtifact.model_validate(
        _read_json_artifact(root, SCANNER_SOURCE_EVIDENCE_PATH)
    )
    reported_inventory = report.metadata.get("scanner_source_inventory_sha256")
    if (
        not isinstance(reported_inventory, str)
        or artifact.scanner_source_inventory_sha256 != reported_inventory
    ):
        raise ValueError("scanner source evidence differs from the frozen report inventory")

    required_by_scanner: dict[str, set[str]] = {}
    for _finding, location, authority in required:
        required_by_scanner.setdefault(authority.scanner_run.scanner, set()).add(location.path)
    observed_by_scanner: dict[str, dict[str, ScannerWorkspaceTextRecord]] = {}
    for scanner, relative_paths in sorted(required_by_scanner.items()):
        workspace = root / "private" / "scanner-output" / scanner / "workspace"
        observed_texts = observe_scanner_workspace_texts(
            workspace,
            tuple(sorted(relative_paths)),
            expected_inventory_sha256=artifact.scanner_source_inventory_sha256,
        )
        observed_by_scanner[scanner] = {item.relative_path: item for item in observed_texts}

    expected_records: list[ScannerSourceEvidenceRecord] = []
    for finding, location, authority in required:
        scanner = authority.scanner_run.scanner
        observed_record = observed_by_scanner[scanner].get(location.path)
        if observed_record is None:
            raise ValueError("scanner source workspace lacks an exact cited path")
        excerpt = build_source_excerpt_evidence(
            report,
            finding,
            location,
            {location.path: observed_record.content},
        )
        observation_sha256 = authority.scanner_run.execution_observation_sha256
        if observation_sha256 is None:
            raise ValueError("scanner source authority lacks an execution observation")
        expected_records.append(
            ScannerSourceEvidenceRecord(
                finding_id=finding.id,
                scanner=scanner,
                scanner_fingerprint=authority.scanner_finding.fingerprint,
                scanner_execution_observation_sha256=observation_sha256,
                source_size=observed_record.size,
                source_line_count=observed_record.lines,
                location=location,
                source_excerpt=excerpt,
            )
        )
    expected_artifact = build_scanner_source_evidence_artifact(
        scanner_source_inventory_sha256=artifact.scanner_source_inventory_sha256,
        records=expected_records,
    )
    if artifact != expected_artifact:
        raise ValueError("scanner source evidence differs from exact private workspace bytes")
    return {
        _scanner_source_record_key(record.finding_id, record.location): record
        for record in artifact.records
    }


def _validate_report_bundle_artifacts(
    root: Path,
    report: AuditReport,
    *,
    candidates: list[CandidateFinding],
    reproduction_resolutions: list[CandidateReproductionResolution],
    current_model_execution_required: bool,
    replay_authorized_scanner_fingerprints: frozenset[str],
) -> None:
    """Cross-check every canonical client/forensic leaf against the final report."""

    present = {
        name
        for name in MANIFEST_BOUND_REPORT_DELIVERABLES
        if (root / name).exists() or (root / name).is_symlink() or (root / name).is_junction()
    }
    if present != MANIFEST_BOUND_REPORT_DELIVERABLES:
        missing = sorted(MANIFEST_BOUND_REPORT_DELIVERABLES - present)
        raise ValueError("client/forensic report bundle is incomplete: " + ", ".join(missing))

    raw_findings = _read_json_artifact(root, "findings.json")
    if current_model_execution_required and raw_findings.get("schema_version") != "1.1":
        raise ValueError("current manifest requires current typed findings custody")
    findings = FindingsArtifact.model_validate(raw_findings)
    expected_findings = build_findings_artifact(
        report,
        candidates=candidates,
        reproduction_resolutions=reproduction_resolutions,
    )
    findings_without_excerpts = findings.model_copy(
        update={
            "records": [
                record.model_copy(update={"source_excerpt": None}) for record in findings.records
            ]
        }
    )
    if findings_without_excerpts != expected_findings:
        raise ValueError("findings.json differs from the final report")
    scanner_source_records = _validate_scanner_source_evidence_artifact(
        root,
        report,
        replay_authorized_scanner_fingerprints=replay_authorized_scanner_fingerprints,
    )
    repository_sources = {item.path: item.sha256 for item in report.repository.files}
    for observed, expected in zip(findings.records, expected_findings.records, strict=True):
        if observed.model_copy(update={"source_excerpt": None}) != expected:
            raise ValueError("findings.json evidence differs from the final report")
        excerpt = observed.source_excerpt
        if observed.finding.status is not FindingStatus.REJECTED and excerpt is None:
            raise ValueError("active forensic finding lacks a source-bound excerpt")
        if excerpt is None:
            continue
        matching_locations = [
            location
            for location in observed.finding.locations
            if location.path == excerpt.path
            and location.start_line == excerpt.cited_start_line
            and location.end_line == excerpt.cited_end_line
            and location.symbol == excerpt.symbol
        ]
        supplemental_record = scanner_source_records.get(
            _scanner_source_record_key(observed.finding.id, excerpt)
        )
        exact_source_binding = (
            repository_sources.get(excerpt.path) == excerpt.file_sha256
            if excerpt.path in repository_sources
            else supplemental_record is not None and supplemental_record.source_excerpt == excerpt
        )
        if (
            len(matching_locations) != 1
            or not exact_source_binding
            or matching_locations[0].content_hash is None
            or matching_locations[0].content_hash != excerpt.cited_content_sha256
        ):
            raise ValueError("forensic source excerpt differs from final source evidence")

    coverage = CoverageArtifact.model_validate(_read_json_artifact(root, "coverage.json"))
    if coverage != build_coverage_artifact(report):
        raise ValueError("coverage.json differs from the final report")
    model_execution = ModelExecutionArtifact.model_validate(
        _read_json_artifact(root, "model-execution.json")
    )
    if current_model_execution_required and model_execution.schema_version != "1.1":
        raise ValueError("current manifest requires current typed model-execution custody")
    if (
        current_model_execution_required
        and report.schema_version == "1.2"
        and report.accounted_cost_usd_exact is None
    ):
        raise ValueError("current report lacks exact accounted-cost evidence")
    expected_model_execution = build_model_execution_artifact(
        report,
        cost_ledger_evidence=(
            model_execution.cost_ledger
            if isinstance(model_execution.cost_ledger, RunCostLedgerEvidence)
            else None
        ),
        persistent_ledger_configured=(
            model_execution.cost_ledger.persistent_ledger_configured
            if isinstance(model_execution.cost_ledger, CostLedgerAbsenceEvidence)
            else False
        ),
        legacy_schema_1_0=model_execution.schema_version == "1.0",
    )
    if model_execution != expected_model_execution:
        raise ValueError("model-execution.json differs from the final report")
    expected_client = render_client_markdown_from_artifact(report, findings).encode("utf-8")
    client_sha256, client_size = _file_sha256(
        root / "client-report.md",
        max_bytes=_MAX_JSON_ARTIFACT_BYTES,
    )
    if (
        client_size != len(expected_client)
        or client_sha256 != hashlib.sha256(expected_client).hexdigest()
    ):
        raise ValueError("client-report.md differs from the final report")
    expected_forensic = render_forensic_markdown(
        report,
        findings_artifact=findings,
    ).encode("utf-8")
    forensic_sha256, forensic_size = _file_sha256(
        root / "forensic-report.md",
        max_bytes=_MAX_JSON_ARTIFACT_BYTES,
    )
    if (
        forensic_size != len(expected_forensic)
        or forensic_sha256 != hashlib.sha256(expected_forensic).hexdigest()
    ):
        raise ValueError("forensic-report.md differs from the final report")
    expected_compatibility = render_markdown(
        report,
        findings_artifact=findings,
    ).encode("utf-8")
    compatibility_sha256, compatibility_size = _file_sha256(
        root / "audit-report.md",
        max_bytes=_MAX_JSON_ARTIFACT_BYTES,
    )
    if (
        compatibility_size != len(expected_compatibility)
        or compatibility_sha256 != hashlib.sha256(expected_compatibility).hexdigest()
    ):
        raise ValueError("audit-report.md differs from the final report")
    expected_sarif = generate_report_sarif(report, findings_artifact=findings)
    if _read_json_artifact(root, "audit-results.sarif") != expected_sarif:
        raise ValueError("audit-results.sarif differs from the final report")


def _validate_run_terminal_report_authority(
    root: Path,
    report: AuditReport,
    *,
    scheduler_artifact: SchedulerArtifact | None,
    achieved_profile: AuditProfile | None,
    expected_binding: ManifestFileBinding | None = None,
) -> None:
    """Compare public report semantics with the required private terminal authority."""

    authority = RunTerminalReportAuthority.model_validate(
        _read_json_artifact(
            root,
            RUN_TERMINAL_REPORT_AUTHORITY_PATH,
            expected_binding=expected_binding,
        )
    )
    authority.require_exact_report(report, scheduler_artifact=scheduler_artifact)
    if authority.achieved_profile != (
        achieved_profile.value if achieved_profile is not None else None
    ):
        raise ValueError("run achieved profile differs from private terminal report authority")


def _validate_model_execution_cost_ledger_custody(
    root: Path,
    report: AuditReport,
    scheduler_artifact: SchedulerArtifact | None,
    *,
    current_model_execution_required: bool,
) -> None:
    """Bind current forensic cost custody to the exact scheduler campaign baseline."""

    model_execution = ModelExecutionArtifact.model_validate(
        _read_json_artifact(root, "model-execution.json")
    )
    if current_model_execution_required and model_execution.schema_version != "1.1":
        raise ValueError("current manifest requires current typed model-execution custody")
    evidence = model_execution.cost_ledger
    baseline = (
        scheduler_artifact.summary.manifest.cost_ledger_baseline
        if scheduler_artifact is not None
        else None
    )
    if isinstance(evidence, CostLedgerAbsenceEvidence):
        if baseline is not None:
            raise ValueError("scheduler cost baseline lacks terminal run-scoped custody")
        return
    if not isinstance(evidence, RunCostLedgerEvidence):
        if current_model_execution_required:
            raise ValueError("current report lacks typed forensic cost-ledger custody")
        return
    if scheduler_artifact is None or baseline is None:
        raise ValueError("run-scoped cost custody lacks an exact scheduler baseline")
    if (
        evidence.baseline_sha256 != baseline.baseline_sha256
        or evidence.baseline_snapshot_sha256 != baseline.ledger_snapshot_sha256
        or Decimal(evidence.cap_usd_exact) != Decimal(baseline.cap_usd_exact)
        or Decimal(evidence.baseline_spent_usd_exact) != Decimal(baseline.spent_usd_exact)
        or Decimal(evidence.baseline_active_reserved_usd_exact)
        != Decimal(baseline.active_reserved_usd_exact)
        or evidence.baseline_entry_count != len(baseline.entries)
    ):
        raise ValueError("forensic cost custody differs from the scheduler baseline")
    scheduler_requests = {
        request.logical_request_id: request for request in scheduler_artifact.model_requests
    }
    if any(attempt.logical_request_id not in scheduler_requests for attempt in evidence.attempts):
        raise ValueError("forensic cost custody contains a non-scheduler request")
    usage_hashes = {
        record.request_id: scheduler_canonical_sha256(record.model_dump(mode="json"))
        for record in report.usage
    }
    for request_id, usage_sha256 in usage_hashes.items():
        scheduler_request = scheduler_requests.get(request_id)
        if scheduler_request is None:
            raise ValueError("model usage is outside the scheduler campaign")
        if scheduler_request.usage_record_sha256 not in {None, usage_sha256}:
            raise ValueError("scheduler usage hash differs from forensic cost custody")
    for request in scheduler_artifact.model_requests:
        if (
            request.usage_record_sha256 is not None
            and usage_hashes.get(request.logical_request_id) != request.usage_record_sha256
        ):
            raise ValueError("scheduler terminal usage is absent from forensic cost custody")


def _validate_scanner_stream_artifact_custody(
    root: Path,
    scanner_runs: list[ScannerRun],
) -> frozenset[str]:
    """Join scanner streams to bytes and return only replay-authorized fingerprints."""

    claims_by_run: dict[
        int,
        list[tuple[str, str, str, int, tuple[str, ...]]],
    ] = {}
    runs_by_index: dict[int, ScannerRun] = {}
    claimed_paths: set[str] = set()
    portable_prefixes: dict[str, tuple[str, str]] = {}
    for run_index, run in enumerate(scanner_runs):
        real_success = (
            run.execution_evidence is ExecutionEvidenceKind.REAL
            and run.status is ScannerStatus.SUCCESS
        )
        if real_success and run.raw_output_path is None:
            raise ValueError(
                "current REAL successful scanner lacks retained stdout normalization evidence"
            )
        streams = (
            ("stdout", run.raw_output_path, run.raw_output_sha256, run.raw_output_bytes),
            (
                "stderr",
                run.private_stderr_path,
                run.private_stderr_sha256,
                run.private_stderr_bytes,
            ),
        )
        for stream_name, claimed_path, claimed_sha256, claimed_size in streams:
            if claimed_path is None:
                if claimed_sha256 is not None or claimed_size != 0:
                    raise ValueError(
                        f"scanner {stream_name} evidence lacks its exact artifact path"
                    )
                continue
            if claimed_sha256 is None:
                raise ValueError(f"scanner {stream_name} artifact lacks a SHA-256 binding")
            normalized = normalize_relative_path(claimed_path)
            path_parts = PurePosixPath(normalized).parts
            if (
                normalized != claimed_path
                or len(path_parts) < 2
                or path_parts[0] != run.scanner
                or normalized in claimed_paths
                or is_sensitive_workspace_path(normalized)
            ):
                raise ValueError(f"scanner {stream_name} artifact path is unsafe or repeated")
            if (
                unicodedata.normalize("NFC", normalized) != normalized
                or unicodedata.normalize("NFC", run.scanner) != run.scanner
                or normalize_relative_path(run.scanner) != run.scanner
                or PurePosixPath(run.scanner).parts != (run.scanner,)
            ):
                raise ValueError(f"scanner {stream_name} artifact path is not exact portable NFC")
            _register_scanner_stream_portable_prefixes(
                normalized,
                portable_prefixes,
            )
            claimed_paths.add(normalized)
            claims_by_run.setdefault(run_index, []).append(
                (
                    stream_name,
                    normalized,
                    claimed_sha256,
                    claimed_size,
                    path_parts,
                )
            )
            runs_by_index[run_index] = run

    if not claims_by_run:
        return frozenset()

    absolute_root = Path(os.path.abspath(root))
    try:
        resolved_root = absolute_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("scanner artifact root is unavailable") from exc
    if resolved_root != absolute_root or absolute_root.is_symlink() or absolute_root.is_junction():
        raise ValueError("scanner artifact root must be an exact non-link directory")

    owner_identities: dict[tuple[int, int], str] = {}
    stream_identities: dict[tuple[int, int], str] = {}
    replay_authorized_fingerprints: set[str] = set()
    with ExitStack() as observations:
        root_descriptor, _ = observations.enter_context(
            _open_scanner_custody_directory(absolute_root, label="run root")
        )
        private_path = absolute_root / "private"
        _require_exact_scanner_directory_entry(
            root_descriptor,
            absolute_root,
            "private",
            label="private artifact directory",
        )
        private_descriptor, _ = observations.enter_context(
            _open_scanner_custody_directory(
                private_path,
                label="private artifact directory",
                parent_descriptor=root_descriptor,
                component="private",
            )
        )
        scanner_output_root = private_path / "scanner-output"
        _require_exact_scanner_directory_entry(
            private_descriptor,
            private_path,
            "scanner-output",
            label="scanner-output directory",
        )
        scanner_root_descriptor, _ = observations.enter_context(
            _open_scanner_custody_directory(
                scanner_output_root,
                label="scanner-output directory",
                parent_descriptor=private_descriptor,
                component="scanner-output",
            )
        )
        scanner_owner_names = _scanner_directory_entries(
            scanner_root_descriptor,
            scanner_output_root,
            label="scanner-output directory",
        )

        for run_index, claims in claims_by_run.items():
            run = runs_by_index[run_index]
            if run.scanner not in scanner_owner_names:
                raise ValueError("scanner artifact owner spelling differs from its exact directory")
            owner_path = scanner_output_root / run.scanner
            owner_descriptor, owner_metadata = observations.enter_context(
                _open_scanner_custody_directory(
                    owner_path,
                    label=f"scanner {run.scanner} owner directory",
                    parent_descriptor=scanner_root_descriptor,
                    component=run.scanner,
                )
            )
            owner_identity = (owner_metadata.st_dev, owner_metadata.st_ino)
            previous_owner = owner_identities.get(owner_identity)
            if previous_owner is not None:
                raise ValueError(
                    "scanner artifact owner identity is claimed by multiple scanner runs"
                )
            owner_identities[owner_identity] = run.scanner

            for stream_name, _normalized, claimed_sha256, claimed_size, path_parts in claims:
                parent_descriptor = owner_descriptor
                parent_path = owner_path
                for component in path_parts[1:-1]:
                    _require_exact_scanner_directory_entry(
                        parent_descriptor,
                        parent_path,
                        component,
                        label=f"scanner {stream_name} artifact directory",
                    )
                    parent_path /= component
                    parent_descriptor, _ = observations.enter_context(
                        _open_scanner_custody_directory(
                            parent_path,
                            label=f"scanner {stream_name} artifact directory",
                            parent_descriptor=parent_descriptor,
                            component=component,
                        )
                    )
                leaf = path_parts[-1]
                _require_exact_scanner_directory_entry(
                    parent_descriptor,
                    parent_path,
                    leaf,
                    label=f"scanner {stream_name} artifact",
                )
                with _open_scanner_stream_observation(
                    parent_path / leaf,
                    parent_descriptor=parent_descriptor,
                    component=leaf,
                    label=f"scanner {stream_name} artifact",
                ) as (
                    observed_sha256,
                    observed_size,
                    stream_identity,
                    retained_bytes,
                ):
                    previous_stream = stream_identities.get(stream_identity)
                    if previous_stream is not None:
                        raise ValueError("scanner stream identity is claimed by multiple artifacts")
                    stream_identities[stream_identity] = f"{run.scanner}:{stream_name}"
                    if observed_sha256 != claimed_sha256 or observed_size != claimed_size:
                        raise ValueError(
                            f"scanner {stream_name} artifact differs from its exact byte custody"
                        )
                    if (
                        stream_name == "stdout"
                        and run.execution_evidence is ExecutionEvidenceKind.REAL
                        and run.status is ScannerStatus.SUCCESS
                    ):
                        if run.scanner not in _CURRENT_SCANNER_REPLAY_AUTHORITY:
                            if run.findings:
                                raise ValueError(
                                    f"REAL scanner {run.scanner!r} findings have no current "
                                    "trusted stdout normalization authority"
                                )
                            continue
                        workspace_path = owner_path / "workspace"
                        _require_exact_scanner_directory_entry(
                            owner_descriptor,
                            owner_path,
                            "workspace",
                            label="scanner replay workspace",
                        )
                        with _open_scanner_custody_directory(
                            workspace_path,
                            label="scanner replay workspace",
                            parent_descriptor=owner_descriptor,
                            component="workspace",
                        ):
                            replayed = validate_real_scanner_normalization_replay(
                                run=run,
                                repository_root=workspace_path,
                                retained_stdout=retained_bytes,
                            )
                            replay_authorized_fingerprints.update(
                                finding.fingerprint for finding in replayed
                            )
    return frozenset(replay_authorized_fingerprints)


def _register_scanner_stream_portable_prefixes(
    path: str,
    prefixes: dict[str, tuple[str, str]],
) -> None:
    """Reject aliases that collide on common case-insensitive NFC filesystems."""

    parts = PurePosixPath(path).parts
    for index in range(len(parts)):
        prefix = "/".join(parts[: index + 1])
        kind = "file" if index == len(parts) - 1 else "directory"
        portable_key = unicodedata.normalize("NFC", prefix).casefold()
        prior = prefixes.get(portable_key)
        if prior is not None and prior != (prefix, kind):
            raise ValueError("scanner artifact paths contain a portable-name collision")
        prefixes[portable_key] = (prefix, kind)


def _scanner_relative_stat(
    path: Path,
    *,
    parent_descriptor: int | None,
    component: str | None,
) -> os.stat_result:
    if (
        parent_descriptor is not None
        and component is not None
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    ):
        return os.stat(
            component,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    return path.lstat()


@contextmanager
def _open_scanner_custody_directory(
    path: Path,
    *,
    label: str,
    parent_descriptor: int | None = None,
    component: str | None = None,
) -> Iterator[tuple[int, os.stat_result]]:
    """Hold one exact non-link directory while scanner evidence is consumed."""

    try:
        before = _scanner_relative_stat(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
        )
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or path.is_symlink()
        or path.is_junction()
    ):
        raise ValueError(f"{label} must be a non-link directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = (
            os.open(component, flags, dir_fd=parent_descriptor)
            if (
                parent_descriptor is not None
                and component is not None
                and os.open in os.supports_dir_fd
            )
            else os.open(path, flags)
        )
    except OSError as exc:
        raise ValueError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        after_open = _scanner_relative_stat(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
        )
        if len(
            {
                _artifact_stat_identity(before),
                _artifact_stat_identity(opened),
                _artifact_stat_identity(after_open),
            }
        ) != 1 or not stat.S_ISDIR(opened.st_mode):
            raise ValueError(f"{label} identity changed while it was opened")
        yield descriptor, opened
        finished = os.fstat(descriptor)
        after_validation = _scanner_relative_stat(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
        )
        if (
            len(
                {
                    _artifact_stat_identity(opened),
                    _artifact_stat_identity(finished),
                    _artifact_stat_identity(after_validation),
                }
            )
            != 1
        ):
            raise ValueError(f"{label} identity changed during validation")
    except OSError as exc:
        raise ValueError(f"{label} identity could not be retained") from exc
    finally:
        os.close(descriptor)


def _scanner_directory_entries(
    descriptor: int,
    path: Path,
    *,
    label: str,
) -> frozenset[str]:
    try:
        entries = os.listdir(descriptor) if os.listdir in os.supports_fd else os.listdir(path)
    except OSError as exc:
        raise ValueError(f"{label} could not be listed safely") from exc
    if any(not isinstance(entry, str) for entry in entries):
        raise ValueError(f"{label} contains an unsupported entry name")
    return frozenset(entries)


def _require_exact_scanner_directory_entry(
    descriptor: int,
    path: Path,
    component: str,
    *,
    label: str,
) -> None:
    if component not in _scanner_directory_entries(descriptor, path, label=label):
        raise ValueError(f"{label} spelling differs from its exact directory entry")


@contextmanager
def _open_scanner_stream_observation(
    path: Path,
    *,
    parent_descriptor: int,
    component: str,
    label: str,
) -> Iterator[tuple[str, int, tuple[int, int], bytes]]:
    """Hash one bounded stream through a descriptor held until validation completes."""

    try:
        before = _scanner_relative_stat(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
        )
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > _MAX_JSON_ARTIFACT_BYTES
        or path.is_symlink()
        or path.is_junction()
    ):
        raise ValueError(f"{label} must be a bounded unique regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = (
            os.open(component, flags, dir_fd=parent_descriptor)
            if os.open in os.supports_dir_fd
            else os.open(path, flags)
        )
    except OSError as exc:
        raise ValueError(f"{label} could not be opened safely") from exc
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    try:
        opened = os.fstat(descriptor)
        if _artifact_stat_identity(before) != _artifact_stat_identity(opened):
            raise ValueError(f"{label} identity changed while it was opened")
        while True:
            remaining = _MAX_JSON_ARTIFACT_BYTES - size
            chunk = os.read(descriptor, min(1024 * 1024, remaining + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_JSON_ARTIFACT_BYTES:
                raise ValueError(f"{label} exceeds its byte limit")
            chunks.append(chunk)
            digest.update(chunk)
        finished = os.fstat(descriptor)
        after_read = _scanner_relative_stat(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
        )
        if (
            len(
                {
                    _artifact_stat_identity(before),
                    _artifact_stat_identity(opened),
                    _artifact_stat_identity(finished),
                    _artifact_stat_identity(after_read),
                }
            )
            != 1
            or not stat.S_ISREG(finished.st_mode)
            or finished.st_nlink != 1
            or finished.st_size != size
        ):
            raise ValueError(f"{label} changed while it was read")
        yield digest.hexdigest(), size, (opened.st_dev, opened.st_ino), b"".join(chunks)
        descriptor_after = os.fstat(descriptor)
        path_after = _scanner_relative_stat(
            path,
            parent_descriptor=parent_descriptor,
            component=component,
        )
        if (
            len(
                {
                    _artifact_stat_identity(opened),
                    _artifact_stat_identity(descriptor_after),
                    _artifact_stat_identity(path_after),
                }
            )
            != 1
        ):
            raise ValueError(f"{label} changed during semantic validation")
    except OSError as exc:
        raise ValueError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)


def _validate_static_scanner_finding_projection(
    finding: Finding,
    scanner: ScannerFinding,
) -> None:
    """Require a report finding to preserve deterministic scanner semantics exactly."""

    raw_validations = scanner.metadata.get("location_validation")
    if not isinstance(raw_validations, list) or len(raw_validations) != len(scanner.locations):
        raise ValueError("current scanner finding lacks exact host location validation")
    expected = project_scanner_finding(
        scanner,
        [LocationValidation.model_validate(item) for item in raw_validations],
        validated_at=finding.location_validation.validated_at,
    )
    if finding != expected:
        raise ValueError(
            "static-analyzer finding differs from its authoritative scanner projection"
        )


def _validate_report_artifact_consistency(
    root: Path,
    report: AuditReport,
    *,
    report_bundle_required: bool = False,
) -> None:
    """Require emitted report summaries to agree before sealing their byte hashes."""

    metadata = _read_json_artifact(root, "metadata.json")
    if metadata.get("privacy") != report.privacy:
        raise ValueError("metadata.json privacy differs from the final report")
    if report_bundle_required:
        for field_name, expected_value in report_status_metadata(report).items():
            if metadata.get(field_name) != expected_value:
                raise ValueError(
                    f"metadata.json {field_name} differs from the canonical report status"
                )
        expected_floor = (
            report.minimum_analysis_floor.model_dump(mode="json")
            if report.minimum_analysis_floor is not None
            else None
        )
        if metadata.get("minimum_analysis_floor") != expected_floor:
            raise ValueError("metadata.json minimum_analysis_floor differs from the final report")
    embedded_metadata = metadata.get("metadata")
    if not isinstance(embedded_metadata, dict):
        raise ValueError("metadata.json lacks typed report metadata")
    if embedded_metadata.get("context_manifest") != report.metadata.get("context_manifest"):
        raise ValueError("metadata.json context manifest differs from the final report")
    if embedded_metadata.get("context_preflight_records") != report.metadata.get(
        "context_preflight_records"
    ):
        raise ValueError("metadata.json context preflight differs from the final report")
    if embedded_metadata.get("scheduler") != report.metadata.get("scheduler"):
        raise ValueError("metadata.json scheduler binding differs from the final report")
    serialized_differential = (
        report.repository_suite_differential.model_dump(mode="json")
        if report.repository_suite_differential is not None
        else None
    )
    if metadata.get("repository_suite_differential") != serialized_differential:
        raise ValueError("metadata.json repository differential differs from the final report")
    scanner_results = _read_json_artifact(root, "scanner-results.json")
    if scanner_results.get("runs") != [run.model_dump(mode="json") for run in report.scanner_runs]:
        raise ValueError("scanner-results.json differs from the final report")
    replay_authorized_scanner_fingerprints: frozenset[str] = frozenset()
    if report_bundle_required:
        verification_results = _read_json_artifact(root, "verification-results.json")
        if verification_results.get("decisions") != [
            decision.model_dump(mode="json") for decision in report.verification_decisions
        ]:
            raise ValueError("verification-results.json differs from the final report")
        cross_examination_results = _read_json_artifact(root, "cross-examination.json")
        if cross_examination_results.get("decisions") != [
            decision.model_dump(mode="json") for decision in report.cross_examination_decisions
        ]:
            raise ValueError("cross-examination.json differs from the final report")
        replay_authorized_scanner_fingerprints = _validate_scanner_stream_artifact_custody(
            root,
            report.scanner_runs,
        )
    candidate_artifact = CandidateFindingArtifact.model_validate(
        _read_json_artifact(root, "candidate-findings.json")
    )
    raw_reproduction_artifact = _read_json_artifact(root, "reproduction-results.json")
    reproduction_artifact = (
        _ManifestReproductionArtifact.model_validate(raw_reproduction_artifact)
        if report.schema_version == "1.2"
        else None
    )
    if report_bundle_required:
        _validate_report_bundle_artifacts(
            root,
            report,
            candidates=list(candidate_artifact.findings),
            reproduction_resolutions=(
                list(reproduction_artifact.candidate_resolutions)
                if reproduction_artifact is not None
                else []
            ),
            current_model_execution_required=report_bundle_required,
            replay_authorized_scanner_fingerprints=(replay_authorized_scanner_fingerprints),
        )
    disposition_path = root / "execution-origin-dispositions.json"
    disposition_artifact_present = (
        disposition_path.exists() or disposition_path.is_symlink() or disposition_path.is_junction()
    )
    if disposition_artifact_present != (report.schema_version == "1.2"):
        raise ValueError(
            "execution-origin disposition artifact presence differs from report schema"
        )
    disposition_artifact = (
        InvariantExecutionOriginDispositionArtifact.model_validate(
            _read_json_artifact(root, "execution-origin-dispositions.json")
        )
        if disposition_artifact_present
        else InvariantExecutionOriginDispositionArtifact()
    )
    if disposition_artifact.dispositions != report.execution_origin_dispositions:
        raise ValueError("execution-origin-dispositions.json differs from the final report")
    candidates = candidate_artifact.findings
    candidates_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    execution_candidate_ids = {
        candidate.candidate_id
        for candidate in candidates
        if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
    }
    if execution_candidate_ids and candidate_artifact.schema_version != "1.1":
        raise ValueError("execution-origin candidates require candidate artifact schema 1.1")
    originated_candidate_ids: set[str] = set()
    for disposition in disposition_artifact.dispositions:
        if disposition.kind is not ExecutionOriginDispositionKind.ORIGINATED:
            continue
        candidate_id = disposition.candidate_id
        if candidate_id is None:
            raise ValueError("originated execution disposition lacks a candidate ID")
        candidate = candidates_by_id.get(candidate_id)
        if (
            candidate is None
            or candidate.origin_kind is not CandidateOriginKind.DETERMINISTIC_EXECUTION
            or candidate.execution_provenance != disposition.execution_provenance
        ):
            raise ValueError(
                "originated execution disposition differs from candidate-findings.json"
            )
        originated_candidate_ids.add(candidate_id)
    if originated_candidate_ids != execution_candidate_ids:
        raise ValueError(
            "execution candidate inventory differs from originated runtime dispositions"
        )

    execution_runtime_names = (
        "solidity-invariants.json",
        "invariant-harness-plan.json",
        "property-corpus.json",
        "invariant-execution-results.json",
    )
    execution_runtime_presence = {
        name: ((root / name).exists() or (root / name).is_symlink() or (root / name).is_junction())
        for name in execution_runtime_names
    }
    if (
        (report.schema_version == "1.2" or execution_candidate_ids)
        and any(execution_runtime_presence.values())
        and not all(execution_runtime_presence.values())
    ):
        raise ValueError("emitted invariant runtime artifact set is incomplete")
    if execution_candidate_ids and not all(execution_runtime_presence.values()):
        raise ValueError("current execution-origin runtime artifacts are absent")
    if all(execution_runtime_presence.values()):
        invariant_artifact = _read_json_artifact(root, "solidity-invariants.json")
        harness_plan = _read_json_artifact(root, "invariant-harness-plan.json")
        property_artifact = _read_json_artifact(root, "property-corpus.json")
        invariant_results = _read_json_artifact(root, "invariant-execution-results.json")
        raw_invariant_suite = invariant_artifact.get("invariants")
        raw_planned_harnesses = harness_plan.get("harnesses")
        raw_execution_harnesses = invariant_results.get("harnesses")
        raw_results = invariant_results.get("results")
        raw_corpus = property_artifact.get("corpus")
        serialized_report_invariants = (
            report.invariants.model_dump(mode="json") if report.invariants is not None else None
        )
        if (
            raw_invariant_suite != serialized_report_invariants
            or not isinstance(raw_planned_harnesses, list)
            or not isinstance(raw_execution_harnesses, list)
            or not isinstance(raw_results, list)
            or not isinstance(raw_corpus, dict)
        ):
            raise ValueError("emitted invariant runtime artifacts differ or are incomplete")
        planned_harnesses = [
            FoundryInvariantHarnessSpec.model_validate(item) for item in raw_planned_harnesses
        ]
        execution_harnesses = [
            FoundryInvariantHarnessSpec.model_validate(item) for item in raw_execution_harnesses
        ]
        planned_by_key = {
            (harness.invariant_id, harness.name): canonical_sha256(harness.model_dump(mode="json"))
            for harness in planned_harnesses
        }
        execution_by_key = {
            (harness.invariant_id, harness.name): canonical_sha256(harness.model_dump(mode="json"))
            for harness in execution_harnesses
        }
        if (
            planned_by_key != execution_by_key
            or len(planned_by_key) != len(planned_harnesses)
            or len(execution_by_key) != len(execution_harnesses)
        ):
            raise ValueError("execution-origin harness artifacts disagree")
        typed_results = [InvariantExecutionResult.model_validate(item) for item in raw_results]
        if [result.model_dump(mode="json") for result in typed_results] != [
            result.model_dump(mode="json") for result in report.invariant_executions
        ]:
            raise ValueError(
                "invariant-execution-results.json differs from the final report runtime evidence"
            )
        typed_corpus = PropertyCorpus.model_validate(raw_corpus)
        for candidate in candidates:
            if candidate.origin_kind is not CandidateOriginKind.DETERMINISTIC_EXECUTION:
                continue
            if candidate.execution_provenance is None:
                raise ValueError("execution-origin candidate lacks typed provenance")
            try:
                validate_invariant_execution_candidate_provenance(
                    candidate.execution_provenance,
                    invariant_suite=report.invariants,
                    harnesses=planned_harnesses,
                    property_corpus=typed_corpus,
                    executions=typed_results,
                )
            except ValueError as exc:
                raise ValueError(
                    "execution-origin candidate differs from its emitted runtime artifacts"
                ) from exc
    scanner_findings = [finding for run in report.scanner_runs for finding in run.findings]
    scanner_findings_by_fingerprint = {finding.fingerprint: finding for finding in scanner_findings}
    if report_bundle_required and len(scanner_findings_by_fingerprint) != len(scanner_findings):
        raise ValueError("current scanner finding fingerprints must be unique")
    scanner_fingerprints = set(scanner_findings_by_fingerprint)
    reported_execution_ids: set[str] = set()
    for finding in [
        *report.findings,
        *report.rejected_findings,
        *report.filtered_findings,
    ]:
        contributing = set(finding.contributing_candidate_ids)
        if len(contributing) != len(finding.contributing_candidate_ids):
            raise ValueError("final finding contains duplicate contributing evidence IDs")
        if finding.origin_kind is FindingOriginKind.STATIC_ANALYZER:
            scanner_evidence_fingerprints = {
                evidence.fingerprint
                for evidence in finding.evidence
                if evidence.type == "scanner" and evidence.fingerprint is not None
            }
            if (
                not contributing
                or contributing != scanner_evidence_fingerprints
                or not contributing <= scanner_fingerprints
            ):
                raise ValueError("static-analyzer finding lacks exact scanner provenance")
            if report_bundle_required:
                if not contributing <= replay_authorized_scanner_fingerprints:
                    raise ValueError(
                        "current static-analyzer finding lacks replay-authorized scanner evidence"
                    )
                if len(finding.contributing_candidate_ids) != 1:
                    raise ValueError("static-analyzer finding has ambiguous scanner provenance")
                _validate_static_scanner_finding_projection(
                    finding,
                    scanner_findings_by_fingerprint[finding.contributing_candidate_ids[0]],
                )
            continue
        unknown_contributors = contributing - set(candidates_by_id)
        if unknown_contributors:
            raise ValueError("final finding references a candidate absent from its inventory")
        contributing_execution = contributing & execution_candidate_ids
        if finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION:
            if not contributing_execution:
                raise ValueError("execution-origin finding lacks an execution-origin candidate")
            candidate_provenance = {
                provenance.provenance_sha256
                for candidate_id in contributing_execution
                if (provenance := candidates_by_id[candidate_id].execution_provenance) is not None
            }
            finding_provenance = {
                provenance.provenance_sha256 for provenance in finding.execution_provenance
            }
            if candidate_provenance != finding_provenance:
                raise ValueError(
                    "execution-origin finding provenance differs from candidate-findings.json"
                )
            reported_execution_ids.update(contributing_execution)
        elif contributing_execution:
            raise ValueError("non-execution finding contains an execution-origin candidate")
    if reported_execution_ids != execution_candidate_ids:
        raise ValueError("an execution-origin candidate was omitted from final report evidence")
    report._validate_execution_origin_bindings()
    if reproduction_artifact is not None:
        _validate_reproduction_candidate_obligations(
            report=report,
            candidate_artifact=candidate_artifact,
            execution_candidate_ids=execution_candidate_ids,
            reproduction_artifact=reproduction_artifact,
        )
    differential_path = root / "repository-suite-differential.json"
    fork_privacy_path = root / "privacy-fork-rpc-egress.json"
    for path in (differential_path, fork_privacy_path):
        if path.is_symlink() or path.is_junction():
            raise ValueError(f"run differential artifact may not be a link: {path.name}")
    expected_present = report.repository_suite_differential is not None
    if differential_path.exists() != expected_present:
        raise ValueError(
            "repository-suite-differential.json presence differs from the final report"
        )
    if fork_privacy_path.exists() != expected_present:
        raise ValueError("privacy-fork-rpc-egress.json presence differs from the final report")
    if expected_present:
        if (
            _read_json_artifact(root, "repository-suite-differential.json")
            != serialized_differential
        ):
            raise ValueError("repository-suite-differential.json differs from the final report")
        if _read_json_artifact(root, "privacy-fork-rpc-egress.json") != report.privacy.get(
            "fork_rpc_egress"
        ):
            raise ValueError("privacy-fork-rpc-egress.json differs from the final report")


def _validate_repository_differential_configuration(
    report: AuditReport,
    config: AuditConfig,
) -> None:
    """Bind configured state/repetition authority to the serialized matrix result."""

    suite = config.smart_contracts.repository_suite
    differential = report.repository_suite_differential
    configured = bool(suite.fork_matrix_states)
    if configured != (differential is not None):
        raise ValueError(
            "repository differential result presence differs from effective configuration"
        )
    if differential is None:
        return
    expected_state_ids = tuple(state.state_id for state in suite.fork_matrix_states)
    if (
        differential.configuration_sha256 != suite.stable_hash()
        or differential.requested_state_ids != expected_state_ids
        or differential.required_repetitions != suite.fork_matrix_repetitions
    ):
        raise ValueError(
            "repository differential result differs from effective state/repetition configuration"
        )


def _validated_context_manifest(
    root: Path,
    report: AuditReport,
) -> ContextManifest | None:
    """Require typed context evidence whenever final usage or a report binding exists."""

    path = root / "context-manifest.json"
    report_binding_payload = report.metadata.get("context_manifest")
    raw_preflight_records = report.metadata.get("context_preflight_records", [])
    if not isinstance(raw_preflight_records, list) or any(
        not isinstance(item, dict) for item in raw_preflight_records
    ):
        raise ValueError("final report context preflight projection is invalid")
    try:
        preflight_records = tuple(
            ContextPreflightRequestEvidence.model_validate_json(
                json.dumps(
                    item,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ),
                strict=True,
            )
            for item in raw_preflight_records
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("final report context preflight projection is invalid") from exc
    if [item.model_dump(mode="json") for item in preflight_records] != raw_preflight_records:
        raise ValueError("final report context preflight projection is not canonical")
    required = bool(report.usage) or report_binding_payload is not None or bool(preflight_records)
    if not path.exists():
        if required:
            raise ValueError("final provider usage lacks context-manifest.json")
        return None
    if report_binding_payload is None:
        raise ValueError("context-manifest.json lacks a final-report binding")
    manifest = load_context_manifest(path)
    if manifest.run_id != report.run_id:
        raise ValueError("context manifest run ID differs from the final report")
    validate_context_manifest_against_usage(
        manifest,
        run_id=report.run_id,
        usage_records=report.usage,
        preflight_records=preflight_records,
    )
    try:
        reported_binding = ContextManifestReportBinding.model_validate_json(
            json.dumps(
                report_binding_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("final report context-manifest binding is invalid") from exc
    expected_binding = context_manifest_report_binding(manifest)
    if reported_binding != expected_binding:
        raise ValueError("final report context-manifest binding differs from its artifact")
    manifest_preflights = tuple(
        request
        for request in manifest.requests
        if isinstance(request, ContextPreflightRequestEvidence)
    )
    if preflight_records != manifest_preflights:
        raise ValueError("final report context preflight differs from its artifact")
    return manifest


def _validate_context_manifest_configuration(
    manifest: ContextManifest | None,
    config: AuditConfig,
) -> None:
    """Bind every atomic request reservation to the effective global ceilings."""

    if manifest is None:
        return
    expected_input = config.token_budgets.global_input_token_budget
    expected_output = config.token_budgets.global_output_token_budget
    expected_source = config.token_budgets.maximum_source_tokens_per_request
    expected_utilization = Decimal(str(config.token_budgets.usable_input_fraction))
    expected_reserved_output = config.effective_reserved_output_tokens
    configured_reserves = {
        PromptAllocationCategory.SYSTEM: config.token_budgets.reserved_system_tokens,
        PromptAllocationCategory.SCHEMA: config.token_budgets.reserved_schema_tokens,
        PromptAllocationCategory.PROTOCOL: config.token_budgets.reserved_protocol_tokens,
        PromptAllocationCategory.WORKFLOW: config.token_budgets.reserved_workflow_tokens,
    }

    def validate_plan(plan: RequestTokenPlan) -> None:
        allocation_bytes = {
            allocation.category: allocation.estimate.byte_upper_bound_tokens
            for allocation in plan.allocations
        }
        expected_reserves = {
            category: max(configured, allocation_bytes[category])
            for category, configured in configured_reserves.items()
        }
        if (
            plan.global_budget.global_input_token_budget != expected_input
            or plan.global_budget.global_output_token_budget != expected_output
            or (plan.source_budget.configured_maximum_source_tokens_per_request != expected_source)
            or plan.context_utilization != expected_utilization
            or plan.reserved_output_tokens != expected_reserved_output
            or plan.reserved_system_tokens != expected_reserves[PromptAllocationCategory.SYSTEM]
            or plan.reserved_schema_tokens != expected_reserves[PromptAllocationCategory.SCHEMA]
            or plan.reserved_protocol_tokens != expected_reserves[PromptAllocationCategory.PROTOCOL]
            or plan.reserved_workflow_tokens != expected_reserves[PromptAllocationCategory.WORKFLOW]
        ):
            raise ValueError("context request plan differs from effective token configuration")

    for request in manifest.requests:
        if isinstance(request, ContextPreflightRequestEvidence):
            plan = request.request_plan
            if plan is not None:
                validate_plan(plan)
            continue
        if not isinstance(request, ContextRequestEvidence):
            continue
        plan = request.request_plan
        validate_plan(plan)
        for reservation in request.atomic_token_reservations:
            if (
                reservation.global_input_token_limit != expected_input
                or reservation.global_output_token_limit != expected_output
            ):
                raise ValueError(
                    "context manifest token reservation differs from effective configuration"
                )


def _run_configuration_binding(
    *,
    report: AuditReport,
    file_config: AuditConfig,
    environment_overrides: AuditConfigOverrides,
    cli_overrides: AuditConfigOverrides,
    run_options: AuditRunOptions,
    effective_config: AuditConfig,
) -> RunConfigurationBinding:
    replayed = cli_overrides.apply(environment_overrides.apply(file_config))
    if canonical_audit_config_json(replayed) != canonical_audit_config_json(effective_config):
        raise ValueError("run configuration provenance does not reproduce the effective config")
    if report.configuration_hash != effective_config.stable_hash():
        raise ValueError("report configuration hash differs from the effective config")
    if report.model_configuration_hash != effective_config.model_hash():
        raise ValueError("report model-configuration hash differs from the effective config")
    if report.audit_profile is not effective_config.profile:
        raise ValueError("report audit profile differs from the effective config")
    if report.language_capability is None:
        raise ValueError("report lacks source-bound language capability evidence")
    if report.language_capability.requested_profile is not effective_config.language_profile:
        raise ValueError("report language profile differs from the effective config")
    if report.metadata.get("run_options") != run_options.model_dump(mode="json"):
        raise ValueError("report run options differ from the sealed invocation")
    expected_provenance = {
        "file_config_sha256": file_config.stable_hash(),
        "environment_overrides_sha256": environment_overrides.stable_hash(),
        "cli_overrides_sha256": cli_overrides.stable_hash(),
        "run_options_sha256": run_options.stable_hash(),
    }
    if report.metadata.get("configuration_provenance") != expected_provenance:
        raise ValueError("report configuration provenance differs from the sealed invocation")
    achieved_profile: AuditProfile | None = None
    if effective_report_status(report).completed:
        if effective_config.profile is not AuditProfile.MAXIMUM_ASSURANCE:
            achieved_profile = effective_config.profile
        elif (
            report.maximum_assurance is not None
            and report.maximum_assurance.status is MaximumAssuranceStatus.COMPLETE
        ):
            achieved_profile = AuditProfile.MAXIMUM_ASSURANCE

    environment_hash = environment_overrides.stable_hash()
    cli_hash = cli_overrides.stable_hash()
    run_options_hash = run_options.stable_hash()
    effective_hash = effective_config.stable_hash()
    invocation = {
        "environment_overrides_sha256": environment_hash,
        "cli_overrides_sha256": cli_hash,
        "run_options_sha256": run_options_hash,
        "effective_config_sha256": effective_hash,
        "requested_profile": effective_config.profile.value,
        "achieved_profile": achieved_profile.value if achieved_profile is not None else None,
        "requested_language_profile": effective_config.language_profile.value,
        "achieved_language_profile": (
            report.language_capability.achieved_profile.value
            if report.language_capability.achieved_profile is not None
            else None
        ),
        "reduced_language_capability": report.language_capability.reduced_capability,
    }
    return RunConfigurationBinding(
        file_configuration_json=canonical_audit_config_json(file_config),
        file_config_sha256=file_config.stable_hash(),
        environment_overrides=environment_overrides,
        environment_overrides_sha256=environment_hash,
        cli_overrides=cli_overrides,
        cli_overrides_sha256=cli_hash,
        run_options=run_options,
        run_options_sha256=run_options_hash,
        effective_configuration_json=canonical_audit_config_json(effective_config),
        effective_config_sha256=effective_hash,
        model_config_sha256=effective_config.model_hash(),
        invocation_sha256=canonical_sha256(invocation),
        requested_profile=effective_config.profile,
        achieved_profile=achieved_profile,
        requested_language_profile=effective_config.language_profile,
        achieved_language_profile=report.language_capability.achieved_profile,
        reduced_language_capability=report.language_capability.reduced_capability,
    )


def write_run_evidence_manifest(path: Path, manifest: RunEvidenceManifest) -> None:
    """Write the sealed manifest without following an existing link."""

    if path.is_symlink() or path.is_junction():
        raise ValueError("run evidence manifest destination may not be a link")
    write_json(path, manifest)


def load_run_evidence_manifest(path: Path) -> RunEvidenceManifest:
    """Load a bounded, unique, non-link manifest and verify its canonical hash."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive run-manifest filename")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("run evidence manifest must be a regular non-link file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_JSON_ARTIFACT_BYTES:
        raise ValueError("run evidence manifest must be a bounded unshared file")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("run evidence manifest contains duplicate keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise ValueError(f"run evidence manifest contains non-finite value: {value}")

    payload = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_nonfinite,
    )
    return RunEvidenceManifest.model_validate(payload)


@contextmanager
def open_manifest_bound_json_artifacts(
    run_dir: Path,
    names: tuple[str, ...],
    *,
    required_bindings: tuple[ManifestFileBinding, ...] | None = None,
    max_bytes: int = _MAX_JSON_ARTIFACT_BYTES,
) -> Iterator[dict[str, dict[str, Any]]]:
    """Hold exact manifest-bound JSON artifacts through semantic validation.

    The manifest and every requested artifact remain open through stable
    ``O_NOFOLLOW`` descriptors until the caller finishes consuming them.  This
    prevents resume-time evidence from being replaced between its manifest hash
    check and its typed semantic validation.
    """

    absolute = Path(os.path.abspath(run_dir))
    try:
        root = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValueError("manifest-bound run directory is unavailable") from exc
    if root != absolute or not root.is_dir() or root.is_symlink() or root.is_junction():
        raise ValueError("manifest-bound run directory must be canonical and non-linked")
    normalized_names = tuple(normalize_relative_path(name) for name in names)
    if (
        not normalized_names
        or normalized_names != names
        or len(normalized_names) != len(set(normalized_names))
        or "run-evidence-manifest.json" in normalized_names
    ):
        raise ValueError("manifest-bound artifact names must be unique normalized paths")

    with _open_json_artifact_observation(
        root,
        "run-evidence-manifest.json",
    ) as manifest_payload:
        manifest = RunEvidenceManifest.model_validate(manifest_payload)
        if manifest.run_id != root.name:
            raise ValueError("run evidence manifest identifies a different exact run")
        bindings = {binding.path: binding for binding in manifest.artifacts}
        missing = tuple(name for name in normalized_names if name not in bindings)
        if missing:
            raise ValueError("run evidence manifest lacks a required retained artifact")
        if required_bindings is not None:
            required = {binding.path: binding for binding in required_bindings}
            if set(required) != set(normalized_names) or any(
                bindings[name] != required[name] for name in normalized_names
            ):
                raise ValueError("run evidence manifest differs from scheduler privacy custody")
        with ExitStack() as observations:
            payloads = {
                name: observations.enter_context(
                    _open_json_artifact_observation(
                        root,
                        name,
                        expected_binding=bindings[name],
                        max_bytes=max_bytes,
                    )
                )
                for name in normalized_names
            }
            yield payloads


@contextmanager
def open_pre_manifest_json_artifacts(
    run_dir: Path,
    names: tuple[str, ...],
    *,
    expected_bindings: tuple[ManifestFileBinding, ...],
    max_bytes: int = _MAX_JSON_ARTIFACT_BYTES,
) -> Iterator[dict[str, dict[str, Any]]]:
    """Hold exact scheduler-bound JSON while a final run manifest is absent."""

    absolute = Path(os.path.abspath(run_dir))
    try:
        root = absolute.resolve(strict=True)
    except OSError as exc:
        raise ValueError("pre-manifest run directory is unavailable") from exc
    if root != absolute or not root.is_dir() or root.is_symlink() or root.is_junction():
        raise ValueError("pre-manifest run directory must be canonical and non-linked")
    normalized_names = tuple(normalize_relative_path(name) for name in names)
    bindings = {binding.path: binding for binding in expected_bindings}
    if (
        not normalized_names
        or normalized_names != names
        or len(normalized_names) != len(set(normalized_names))
        or set(bindings) != set(normalized_names)
    ):
        raise ValueError("pre-manifest artifact custody is incomplete or non-canonical")
    final_manifest_path = root / "run-evidence-manifest.json"

    def require_final_manifest_absent() -> None:
        try:
            final_manifest_path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ValueError("final run-manifest state cannot be inspected") from exc
        raise ValueError("pre-manifest evidence contradicts an emitted final run manifest")

    require_final_manifest_absent()
    with ExitStack() as observations:
        payloads = {
            name: observations.enter_context(
                _open_json_artifact_observation(
                    root,
                    name,
                    expected_binding=bindings[name],
                    max_bytes=max_bytes,
                )
            )
            for name in normalized_names
        }
        try:
            yield payloads
        finally:
            require_final_manifest_absent()


def resolve_run_evidence_config(
    manifest: RunEvidenceManifest,
    *,
    file_config: AuditConfig | None = None,
) -> AuditConfig:
    """Resolve the exact effective config, replaying recorded layers when available."""

    if manifest.run_configuration is None:
        if file_config is None:
            raise ValueError("legacy run manifest has no reconstructable configuration")
        return file_config.effective()
    return manifest.run_configuration.reconstruct_effective_config(file_config=file_config)


def collect_run_artifacts(run_dir: Path) -> list[ManifestFileBinding]:
    """Observe the bounded run artifact set without executing any artifact."""

    return _collect_artifacts(run_dir.resolve(strict=True))


def validate_solidity_shard_artifacts(
    run_dir: Path,
    report: AuditReport,
) -> None:
    """Cross-check persisted typed shard evidence against its index, graphs, and report."""

    root = run_dir.resolve(strict=True)
    artifact_names = {binding.path for binding in collect_run_artifacts(root)}
    relevant = {"solidity-index.json", "solidity-graphs.json", "solidity-shards.json"}
    solidity_metadata = report.metadata.get("solidity")
    shard_summary = (
        solidity_metadata.get("shard_summary") if isinstance(solidity_metadata, dict) else None
    )
    current_shard_metadata = bool(
        isinstance(solidity_metadata, dict)
        and {"index_summary", "graph_summary", "shard_summary"} <= set(solidity_metadata)
    )
    current_shards_required = report.schema_version == "1.2" and report.completed
    report_has_solidity = False
    for source in report.repository.files:
        suffix_is_solidity = PurePosixPath(source.path).suffix.lower() == ".sol"
        language_is_solidity = source.language == "Solidity"
        if suffix_is_solidity != language_is_solidity:
            raise ValueError("report repository Solidity membership is inconsistent")
        report_has_solidity = report_has_solidity or suffix_is_solidity
    if not artifact_names & relevant:
        if shard_summary is not None:
            raise ValueError("Solidity shard report binding lacks persisted artifacts")
        if report_has_solidity and current_shards_required:
            raise ValueError("completed Solidity report lacks persisted shard evidence")
        return
    if not relevant <= artifact_names:
        raise ValueError("persisted Solidity shard evidence is incomplete")
    index_artifact = SolidityIndexArtifact.model_validate(
        _read_json_artifact(root, "solidity-index.json")
    )
    graphs_artifact = SolidityGraphsArtifact.model_validate(
        _read_json_artifact(root, "solidity-graphs.json")
    )
    shards_artifact = SolidityShardsArtifact.model_validate(
        _read_json_artifact(root, "solidity-shards.json")
    )
    if not isinstance(solidity_metadata, dict):
        raise ValueError("persisted Solidity artifacts lack report metadata")
    expected_index_summary = {
        "entities": len(index_artifact.index.entities) if index_artifact.index is not None else 0,
        "ast_sources": (
            len(index_artifact.index.ast_sources) if index_artifact.index is not None else 0
        ),
        "fallback_sources": (
            len(index_artifact.index.fallback_sources) if index_artifact.index is not None else 0
        ),
    }
    expected_graph_summary = {
        "edges": len(graphs_artifact.graphs.edges) if graphs_artifact.graphs is not None else 0,
        "warnings": (
            len(graphs_artifact.graphs.warnings) if graphs_artifact.graphs is not None else 0
        ),
    }
    if solidity_metadata.get("index_summary") != expected_index_summary:
        raise ValueError("Solidity index report summary differs from its typed artifact")
    if solidity_metadata.get("graph_summary") != expected_graph_summary:
        raise ValueError("Solidity graph report summary differs from its typed artifact")
    inventory = shards_artifact.inventory
    if inventory is None:
        if shard_summary is not None:
            raise ValueError("empty Solidity shard artifact has a report binding")
        if (
            report.completed
            and (current_shards_required or current_shard_metadata)
            and (
                report_has_solidity
                or index_artifact.index is not None
                or graphs_artifact.graphs is not None
            )
        ):
            raise ValueError("completed report has a null Solidity shard inventory")
        return
    if index_artifact.index is None or graphs_artifact.graphs is None:
        raise ValueError("non-empty Solidity shard inventory lacks upstream artifacts")
    if not isinstance(shard_summary, dict):
        raise ValueError("non-empty Solidity shard inventory lacks a typed report binding")
    report_binding = SolidityShardReportBinding.model_validate(shard_summary)
    verify_solidity_shard_repository_projection(
        repository=report.repository,
        inventory=inventory,
    )
    verify_solidity_shard_projection(
        index=index_artifact.index,
        graphs=graphs_artifact.graphs,
        inventory=inventory,
        expected_policy=SolidityShardPolicy.build(),
        report_binding=report_binding,
    )


def validate_scheduler_artifact(
    run_dir: Path,
    report: AuditReport,
    *,
    config: AuditConfig | None = None,
    qualification_runtime: dict[str, Any] | None = None,
    scheduler_runtime_journal: SchedulerJournal | None = None,
    scheduler_reference_binding: ManifestFileBinding | None = None,
    require_retained_usage_custody: bool = False,
) -> SchedulerArtifact | None:
    """Cross-check the durable seven-pass summary against report and provider evidence."""

    # Local import avoids manifest -> qualification -> benchmark -> manifest at module load.
    from mmaudit.orchestration.scheduler_runtime import (
        build_scheduler_shard_inventory,
        scheduler_prompt_template_set_sha256,
        scheduler_response_schema_hashes,
        scheduler_response_schema_set_sha256,
        scheduler_tool_policy_sha256,
    )

    root = run_dir.resolve(strict=True)
    path = root / "scheduler-state.json"
    artifact_present = path.exists() or path.is_symlink() or path.is_junction()
    binding_payload = report.metadata.get("scheduler")
    current_scheduler_required = report.schema_version == "1.2" and (
        report.completed or bool(report.usage)
    )
    if not artifact_present:
        if scheduler_runtime_journal is not None:
            raise ValueError("live scheduler authority lacks its persisted public artifact")
        if binding_payload is not None:
            raise ValueError("scheduler report binding lacks its persisted artifact")
        if current_scheduler_required:
            raise ValueError("current provider or completed report lacks scheduler evidence")
        return None
    if binding_payload is None:
        raise ValueError("scheduler artifact lacks its final-report binding")

    artifact = SchedulerArtifact.model_validate(_read_json_artifact(root, "scheduler-state.json"))
    binding = SchedulerReportBinding.model_validate(binding_payload)
    binding.require_exact(artifact)
    if (
        report.schema_version == "1.2"
        and report.completed
        and artifact.summary.status is not SchedulerCampaignStatus.COMPLETE
    ):
        raise ValueError("completed current report contains an incomplete scheduler campaign")

    summary = artifact.summary
    scheduler_bindings = summary.manifest.bindings
    source_projection = sorted(
        (
            ManifestFileBinding(
                path=source.path,
                sha256=source.sha256,
                size=source.size,
            )
            for source in report.repository.files
        ),
        key=lambda item: item.path,
    )
    expected_source_sha256 = canonical_sha256(
        [item.model_dump(mode="json") for item in source_projection]
    )
    if scheduler_bindings.source_sha256 != expected_source_sha256:
        raise ValueError("scheduler source binding differs from the final report")
    if scheduler_bindings.effective_config_sha256 != report.configuration_hash:
        raise ValueError("scheduler configuration binding differs from the final report")
    if scheduler_bindings.model_selection_sha256 != report.model_configuration_hash:
        raise ValueError("scheduler model-selection binding differs from the final report")
    qualification_validation = _qualification_validation(qualification_runtime)
    expected_qualification_sha256 = (
        qualification_validation.qualification_artifact_sha256
        if qualification_validation is not None
        and qualification_validation.qualification_artifact_sha256 is not None
        else ABSENT_QUALIFICATION_SHA256
    )
    if scheduler_bindings.qualification_sha256 != expected_qualification_sha256:
        raise ValueError("scheduler qualification binding differs from runtime evidence")

    solidity_sources = [
        source
        for source in report.repository.files
        if PurePosixPath(source.path).suffix.lower() == ".sol"
    ]
    semantic_inventory = None
    if solidity_sources:
        validate_solidity_shard_artifacts(root, report)
        shards_artifact = SolidityShardsArtifact.model_validate(
            _read_json_artifact(root, "solidity-shards.json")
        )
        semantic_inventory = shards_artifact.inventory
        if semantic_inventory is None:
            raise ValueError("Solidity scheduler campaign lacks a semantic shard inventory")
    expected_shard_inventory = build_scheduler_shard_inventory(
        report.repository,
        semantic_inventory,
    )
    if summary.manifest.shard_inventory != expected_shard_inventory:
        raise ValueError("scheduler campaign differs from its exact audited shard inventory")
    if (
        scheduler_bindings.shard_inventory_sha256 != expected_shard_inventory.inventory_sha256
        or summary.manifest.shard_ids != expected_shard_inventory.shard_ids
    ):
        raise ValueError("scheduler campaign differs from its exact audited shard inventory")

    if config is not None:
        expected_prompt_set_sha256 = scheduler_prompt_template_set_sha256()
        expected_tool_policy_sha256 = scheduler_tool_policy_sha256(config)
        if scheduler_bindings.prompt_set_sha256 != expected_prompt_set_sha256:
            raise ValueError("scheduler prompt-set binding differs from trusted templates")
        if scheduler_bindings.schema_set_sha256 != scheduler_response_schema_set_sha256():
            raise ValueError("scheduler schema-set binding differs from trusted response schemas")
        if scheduler_bindings.tool_policy_sha256 != expected_tool_policy_sha256:
            raise ValueError("scheduler tool-policy binding differs from run evidence")

    _require_scheduler_journal_authority(
        root=root,
        report=report,
        public_artifact=artifact,
        expected_shard_inventory=expected_shard_inventory,
        runtime_journal=scheduler_runtime_journal,
        reference_binding=scheduler_reference_binding,
        require_retained_usage_custody=require_retained_usage_custody,
    )

    model_task_records = {
        task.logical_request_id: (pass_result.plan, task, result)
        for pass_result in summary.pass_results
        for task in pass_result.plan.tasks
        for result in pass_result.task_results
        if result.task_id == task.task_id
        if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
    }
    model_requests = {request.logical_request_id: request for request in artifact.model_requests}
    terminal_request_ids = set(model_task_records)
    request_ids = set(model_requests)
    if (
        len(model_requests) != len(artifact.model_requests)
        or not terminal_request_ids <= request_ids
        or (
            summary.status is SchedulerCampaignStatus.COMPLETE
            and request_ids != terminal_request_ids
        )
    ):
        raise ValueError("scheduler public model-request inventory differs from durable tasks")
    permitted_schema_hashes = scheduler_response_schema_hashes()
    if any(
        task.response_schema_sha256 not in permitted_schema_hashes
        for _plan, task, _result in model_task_records.values()
    ):
        raise ValueError("scheduler model task uses an unregistered response schema")
    configured_lineages = model_lineage_index(config) if config is not None else {}
    known_source_descriptors = {
        source.source_descriptor_sha256
        for shard in expected_shard_inventory.shards
        for source in shard.sources
    }
    for logical_request_id, request in model_requests.items():
        terminal_record = model_task_records.get(logical_request_id)
        if terminal_record is not None:
            plan, task, result = terminal_record
            _validate_scheduler_model_request(
                request=request,
                plan=plan,
                task=task,
                result=result,
                permitted_schema_hashes=permitted_schema_hashes,
            )
        elif request.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            raise ValueError("successful scheduler request lacks its sealed pass result")
        if (
            request.response_schema_sha256 is not None
            and request.response_schema_sha256 not in permitted_schema_hashes
        ):
            raise ValueError("scheduler model task uses an unregistered response schema")
        if not set(request.delivered_source_descriptor_sha256s) <= known_source_descriptors:
            raise ValueError("scheduler model request claims an unknown delivered source")
        if config is not None:
            lineage = configured_lineages.get(request.requested_model.lower())
            if (
                lineage is None
                or lineage.root_lineage != request.root_lineage
                or request.root_lineage not in config.privacy.approved_model_lineages
            ):
                raise ValueError("scheduler model request lacks an approved configured lineage")

    usages_by_logical_id: dict[str, list[UsageRecord]] = {
        request_id: [] for request_id in model_requests
    }
    observed_usage_ids = [usage.request_id for usage in report.usage]
    if len(observed_usage_ids) != len(set(observed_usage_ids)):
        raise ValueError("provider usage contains duplicate scheduler request evidence")
    for usage in report.usage:
        matched_request_id = usage.request_id if usage.request_id in model_requests else None
        route_suffix = ""
        if matched_request_id is None:
            route_base, route_marker, route_suffix = usage.request_id.rpartition(":route:")
            if route_marker and route_base in model_requests:
                matched_request_id = route_base
        if matched_request_id is None:
            raise ValueError("provider usage is orphaned from scheduler task evidence")
        if usage.request_id != matched_request_id and (
            not route_suffix.isascii()
            or not route_suffix.isdecimal()
            or len(route_suffix) > 6
            or int(route_suffix) < 2
        ):
            raise ValueError("provider usage has an invalid scheduler route identity")
        usages_by_logical_id[matched_request_id].append(usage)

    uncertain_provider_successes = 0
    for logical_request_id, request in model_requests.items():
        terminal_record = model_task_records.get(logical_request_id)
        terminal_status = request.terminal_status
        usages = usages_by_logical_id[logical_request_id]
        for usage in usages:
            _validate_scheduler_usage_join(usage=usage, request=request)
        creditable = [
            usage
            for usage in usages
            if _scheduler_usage_is_creditable(usage=usage, request=request, config=config)
        ]
        if terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            if len(usages) != 1 or len(creditable) != 1:
                raise ValueError(
                    "successful scheduler task lacks one exact creditable provider result"
                )
            if (
                terminal_record is None
                or terminal_record[2].terminal_evidence_sha256
                != creditable[0].validated_response_sha256
            ):
                raise ValueError("scheduler terminal evidence differs from provider usage")
        elif len(creditable) > 1:
            raise ValueError("non-success scheduler result has duplicate provider success evidence")
        elif creditable and terminal_status not in {
            SchedulerTerminalStatus.INVALID,
            SchedulerTerminalStatus.UNCERTAIN,
        }:
            raise ValueError("non-success scheduler result contradicts provider success evidence")
        if terminal_status is SchedulerTerminalStatus.UNCERTAIN and creditable:
            uncertain_provider_successes += 1
    retained_uncredited_outputs = (
        artifact.journal_evidence.task_output_count - artifact.journal_evidence.succeeded_count
    )
    if uncertain_provider_successes > retained_uncredited_outputs:
        raise ValueError("uncertain provider success lacks retained uncredited output evidence")
    return artifact


def _require_scheduler_journal_authority(
    *,
    root: Path,
    report: AuditReport,
    public_artifact: SchedulerArtifact,
    expected_shard_inventory: SchedulerShardInventory,
    runtime_journal: SchedulerJournal | None,
    reference_binding: ManifestFileBinding | None,
    require_retained_usage_custody: bool,
) -> None:
    """Compare public state to owner-held runtime or descriptor-reopened private evidence."""

    with _resolve_scheduler_journal_authority_path(
        root=root,
        public_artifact=public_artifact,
        reference_binding=reference_binding,
        detached=runtime_journal is None,
    ) as journal_path:
        if runtime_journal is not None:
            from mmaudit.orchestration.scheduler import SchedulerJournal

            if not isinstance(runtime_journal, SchedulerJournal):
                raise ValueError("scheduler runtime authority must be an owner-held live journal")
            if runtime_journal.path.resolve(strict=True) != journal_path:
                raise ValueError("scheduler runtime journal path differs from the run custody path")
            if (
                runtime_journal.manifest.bindings != public_artifact.summary.manifest.bindings
                or runtime_journal.manifest.shard_inventory != expected_shard_inventory
            ):
                raise ValueError("scheduler runtime journal bindings differ from public evidence")
            reconstructed = _validate_scheduler_privacy_custody_and_reconstruct(
                root=root,
                report=report,
                public_artifact=public_artifact,
                journal=runtime_journal,
                require_retained_usage_custody=require_retained_usage_custody,
            )
            if reconstructed != public_artifact:
                raise ValueError("scheduler public artifact differs from live runtime authority")
            return

        from mmaudit.orchestration.scheduler import open_scheduler_journal_for_verification

        journal = open_scheduler_journal_for_verification(
            journal_path,
            expected_bindings=public_artifact.summary.manifest.bindings,
            expected_shard_inventory=expected_shard_inventory,
            expected_cost_ledger_baseline=(public_artifact.summary.manifest.cost_ledger_baseline),
            expected_privacy_evidence_custody=(
                public_artifact.summary.manifest.privacy_evidence_custody
            ),
            expected_terminal_report_authority_required=(
                public_artifact.summary.manifest.terminal_report_authority_required
            ),
            expected_terminal_evidence_authority_required=(
                public_artifact.summary.manifest.terminal_evidence_authority_required
            ),
        )
        try:
            reconstructed = _validate_scheduler_privacy_custody_and_reconstruct(
                root=root,
                report=report,
                public_artifact=public_artifact,
                journal=journal,
                require_retained_usage_custody=require_retained_usage_custody,
            )
        finally:
            journal.close()
        if reconstructed != public_artifact:
            raise ValueError("scheduler public artifact differs from its private journal")


def _validate_scheduler_privacy_custody_and_reconstruct(
    *,
    root: Path,
    report: AuditReport,
    public_artifact: SchedulerArtifact,
    journal: SchedulerJournal,
    require_retained_usage_custody: bool,
) -> SchedulerArtifact:
    """Join exact privacy bytes to a descriptor-held scheduler manifest and report."""

    expected_custody = public_artifact.summary.manifest.privacy_evidence_custody
    if expected_custody is None:
        reconstructed = journal.artifact()
        _validate_scheduler_report_authority(root=root, report=report, journal=journal)
        if require_retained_usage_custody:
            _validate_scheduler_retained_usage_custody(
                report=report,
                public_artifact=public_artifact,
                journal=journal,
            )
        return reconstructed
    with journal.open_privacy_evidence_custody() as observed_custody:
        if observed_custody != expected_custody:
            raise ValueError("scheduler privacy custody differs from its private authority")
        _validate_scheduler_privacy_artifacts(
            root=root,
            report=report,
            custody=observed_custody,
        )
        reconstructed = journal.artifact()
        _validate_scheduler_report_authority(root=root, report=report, journal=journal)
        if require_retained_usage_custody:
            _validate_scheduler_retained_usage_custody(
                report=report,
                public_artifact=public_artifact,
                journal=journal,
            )
        return reconstructed


def _validate_scheduler_retained_usage_custody(
    *,
    report: AuditReport,
    public_artifact: SchedulerArtifact,
    journal: SchedulerJournal,
) -> None:
    """Close report usage against one exact private scheduler evidence class."""

    output_records = {
        output.model_completion_evidence.usage_record.request_id: (
            output.model_completion_evidence.usage_record
        )
        for output in journal.outputs
        if output.model_completion_evidence is not None
    }
    provider_attempt_records = {
        attempt.usage_record.request_id: attempt.usage_record
        for attempt in journal.provider_attempts
    }
    if set(output_records).intersection(provider_attempt_records):
        raise ValueError("scheduler usage has contradictory retained evidence classes")
    retained_records = {**output_records, **provider_attempt_records}
    if len(retained_records) != len(output_records) + len(provider_attempt_records):
        raise ValueError("scheduler retained usage inventory repeats a request identity")
    report_records = {record.request_id: record for record in report.usage}
    if len(report_records) != len(report.usage):
        raise ValueError("final report repeats a retained scheduler usage identity")
    if report_records != retained_records:
        raise ValueError("final report usage differs from exact retained scheduler custody")

    public_requests = {
        request.logical_request_id: request for request in public_artifact.model_requests
    }
    if not set(retained_records) <= set(public_requests):
        raise ValueError("retained scheduler usage is absent from the public request inventory")
    for logical_request_id, request in public_requests.items():
        if request.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            retained_output = output_records.get(logical_request_id)
            if retained_output is None or request.usage_record_sha256 != scheduler_canonical_sha256(
                retained_output.model_dump(mode="json")
            ):
                raise ValueError("successful scheduler usage lacks exact retained output custody")


def _scheduler_pass_result(
    journal: SchedulerJournal,
    pass_kind: SchedulerPassKind,
) -> SchedulerPassResult | None:
    """Return one exact sealed pass result, rejecting ambiguous private authority."""

    matches = tuple(result for result in journal.pass_results if result.plan.pass_kind is pass_kind)
    if len(matches) > 1:
        raise ValueError("scheduler private journal repeats a sealed pass result")
    return matches[0] if matches else None


def _successful_scheduler_task_output(
    *,
    journal: SchedulerJournal,
    pass_result: SchedulerPassResult,
    task_id: str,
) -> SchedulerTaskOutput:
    """Return one exact successful private output from a complete or failed pass."""

    results = tuple(result for result in pass_result.task_results if result.task_id == task_id)
    outputs = tuple(output for output in journal.outputs if output.task_id == task_id)
    if (
        len(results) != 1
        or results[0].terminal_status is not SchedulerTerminalStatus.SUCCEEDED
        or len(outputs) != 1
    ):
        raise ValueError("scheduler authority task lacks one successful retained output")
    result = results[0]
    output = outputs[0]
    if (
        result.output_sha256 != output.output_sha256
        or result.output_artifact_sha256 != output.output_artifact_sha256
    ):
        raise ValueError("scheduler authority task result differs from its retained output")
    return output


def _scheduler_accepted_candidate_authority(
    journal: SchedulerJournal,
) -> tuple[
    dict[SchedulerPassKind, dict[str, str]],
    dict[SchedulerPassKind, dict[str, CandidateFinding]],
]:
    """Collect exact host-accepted candidates even when a later task failed."""

    hash_authority: dict[SchedulerPassKind, dict[str, str]] = {
        SchedulerPassKind.BLIND_SHARD_REVIEW: {},
        SchedulerPassKind.CROSS_SHARD_INTEGRATION: {},
    }
    candidate_authority: dict[SchedulerPassKind, dict[str, CandidateFinding]] = {
        SchedulerPassKind.BLIND_SHARD_REVIEW: {},
        SchedulerPassKind.CROSS_SHARD_INTEGRATION: {},
    }
    for pass_kind in tuple(hash_authority):
        pass_result = _scheduler_pass_result(journal, pass_kind)
        if pass_result is None:
            continue
        accepted_hashes = hash_authority[pass_kind]
        accepted_candidates = candidate_authority[pass_kind]
        for result in pass_result.task_results:
            if result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
                continue
            output = _successful_scheduler_task_output(
                journal=journal,
                pass_result=pass_result,
                task_id=result.task_id,
            )
            output_candidates = {
                candidate.candidate_id: candidate for candidate in output.accepted_candidates
            }
            if set(output_candidates) != set(output.accepted_candidate_payload_sha256s):
                raise ValueError("scheduler accepted candidate objects differ from their hashes")
            for candidate_id, payload_sha256 in output.accepted_candidate_payload_sha256s.items():
                if candidate_id in accepted_hashes:
                    raise ValueError("scheduler accepted candidate authority repeats an identity")
                candidate = output_candidates[candidate_id]
                if scheduler_canonical_sha256(candidate.model_dump(mode="json")) != payload_sha256:
                    raise ValueError("scheduler accepted candidate object hash is inconsistent")
                accepted_hashes[candidate_id] = payload_sha256
                accepted_candidates[candidate_id] = candidate
        hash_authority[pass_kind] = dict(sorted(accepted_hashes.items()))
        candidate_authority[pass_kind] = dict(sorted(accepted_candidates.items()))
    return hash_authority, candidate_authority


def _reconstruct_successful_scheduler_output[OutputT: StrictModel](
    *,
    journal: SchedulerJournal,
    pass_result: SchedulerPassResult,
    task_id: str,
    output_type: type[OutputT],
) -> OutputT:
    """Join a typed private payload to its one credited task result and output record."""

    output = _successful_scheduler_task_output(
        journal=journal,
        pass_result=pass_result,
        task_id=task_id,
    )
    reconstructed = journal.reconstruct_output(task_id, output_type)
    serialized = reconstructed.model_dump(mode="json")
    if (
        serialized != output.payload
        or scheduler_canonical_sha256(serialized) != output.output_sha256
    ):
        raise ValueError("scheduler authority payload differs from its retained output hashes")
    return reconstructed


def _successful_scheduler_host_output[OutputT: StrictModel](
    *,
    journal: SchedulerJournal,
    pass_kind: SchedulerPassKind,
    role: str,
    output_type: type[OutputT],
) -> OutputT | None:
    """Return a typed host authority only from a fully completed sealed pass."""

    pass_result = _scheduler_pass_result(journal, pass_kind)
    if pass_result is None or pass_result.status is not SchedulerPassStatus.COMPLETE:
        return None
    tasks = tuple(task for task in pass_result.plan.tasks if task.role == role)
    if len(tasks) != 1 or tasks[0].task_kind is not SchedulerTaskKind.HOST_COMPUTATION:
        raise ValueError("scheduler completed pass lacks one exact host authority task")
    return _reconstruct_successful_scheduler_output(
        journal=journal,
        pass_result=pass_result,
        task_id=tasks[0].task_id,
        output_type=output_type,
    )


def _scheduler_evidence_payload_bindings(
    kind: Literal[
        "judge",
        "verification",
        "cross_examination",
        "falsification",
        "reproduction",
        "reproduction_resolution",
    ],
    records: Iterable[tuple[str, StrictModel]],
) -> tuple[SchedulerEvidencePayloadBinding, ...]:
    """Build a lossless canonical binding for every independently retained record."""

    bindings: list[SchedulerEvidencePayloadBinding] = []
    for subject_id, record in records:
        bindings.append(
            SchedulerEvidencePayloadBinding.build(
                kind=kind,
                subject_id=subject_id,
                payload=record,
            )
        )
    ordered = tuple(sorted(bindings, key=lambda item: (item.subject_id, item.record_id)))
    identities = tuple((item.subject_id, item.record_id) for item in ordered)
    if len(identities) != len(set(identities)):
        raise ValueError(f"scheduler {kind} evidence contains an exact duplicate")
    return ordered


def _scheduler_candidate_payload_sha256s(
    candidates: Iterable[CandidateFinding],
) -> dict[str, str]:
    """Hash complete candidate payloads using the scheduler's canonical encoding."""

    ordered = tuple(sorted(candidates, key=lambda item: item.candidate_id))
    identifiers = tuple(item.candidate_id for item in ordered)
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("scheduler report authority candidate inventory is ambiguous")
    return {
        candidate.candidate_id: scheduler_canonical_sha256(candidate.model_dump(mode="json"))
        for candidate in ordered
    }


def _validate_scheduler_report_quality_authority(
    *,
    report: AuditReport,
    journal: SchedulerJournal,
) -> None:
    """Bind the public report-quality review to its exact retained model output."""

    pass_result = _scheduler_pass_result(
        journal,
        SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
    )
    if pass_result is None:
        if report.report_quality_review is not None:
            raise ValueError("public report quality lacks scheduler authority")
        return
    tasks = tuple(
        task for task in pass_result.plan.tasks if task.role == "specialist:report_quality"
    )
    if len(tasks) > 1:
        raise ValueError("scheduler report-quality authority is ambiguous")
    if not tasks:
        if report.report_quality_review is not None:
            raise ValueError("public report quality lacks a scheduled review")
        return
    task = tasks[0]
    results = tuple(result for result in pass_result.task_results if result.task_id == task.task_id)
    if len(results) != 1:
        raise ValueError("scheduler report-quality task lacks one terminal result")
    if results[0].terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
        if report.report_quality_review is not None:
            raise ValueError("failed scheduler report quality was published")
        return
    retained = _reconstruct_successful_scheduler_output(
        journal=journal,
        pass_result=pass_result,
        task_id=task.task_id,
        output_type=ReportQualityReview,
    )
    if report.report_quality_review != retained:
        raise ValueError("public report quality differs from scheduler authority")


def _scheduler_finding_payload_sha256s(
    findings: Iterable[Finding],
) -> tuple[tuple[str, ...], dict[str, str]]:
    """Return one canonical, non-overlapping public finding projection."""

    ordered = tuple(sorted(findings, key=lambda item: item.id))
    finding_ids = tuple(item.id for item in ordered)
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("public terminal finding partition repeats an identity")
    return finding_ids, {
        finding.id: scheduler_canonical_sha256(finding.model_dump(mode="json"))
        for finding in ordered
    }


def _validate_scheduler_terminal_projection_authority(
    *,
    report: AuditReport,
    reproduction_artifact: _ManifestReproductionArtifact,
    candidate_hashes: dict[str, str],
    authority: SchedulerTerminalReportAuthority,
) -> None:
    """Compare every public terminal projection to the private write-once authority."""

    if (
        tuple(candidate_hashes) != authority.candidate_ids
        or candidate_hashes != authority.candidate_payload_sha256s
    ):
        raise ValueError("candidate artifact differs from scheduler terminal authority")
    if report.metadata.get("severity_threshold") != authority.severity_threshold.value:
        raise ValueError("report severity threshold differs from scheduler terminal authority")

    public_partitions = (
        (
            report.findings,
            authority.final_finding_ids,
            authority.final_finding_payload_sha256s,
        ),
        (
            report.rejected_findings,
            authority.rejected_finding_ids,
            authority.rejected_finding_payload_sha256s,
        ),
        (
            report.filtered_findings,
            authority.filtered_finding_ids,
            authority.filtered_finding_payload_sha256s,
        ),
    )
    public_finding_ids: list[str] = []
    for findings, expected_ids, expected_hashes in public_partitions:
        observed_ids, observed_hashes = _scheduler_finding_payload_sha256s(findings)
        if observed_ids != expected_ids or observed_hashes != expected_hashes:
            raise ValueError("public finding partition differs from scheduler terminal authority")
        public_finding_ids.extend(observed_ids)
    if len(public_finding_ids) != len(set(public_finding_ids)):
        raise ValueError("public terminal finding partitions overlap")

    report_quality_payload_sha256 = (
        scheduler_canonical_sha256(report.report_quality_review.model_dump(mode="json"))
        if report.report_quality_review is not None
        else None
    )
    if report_quality_payload_sha256 != authority.report_quality_payload_sha256:
        raise ValueError("public report quality differs from scheduler terminal authority")

    if authority.schema_version == "1.0":
        return
    public_evidence = (
        (
            "verification",
            _scheduler_evidence_payload_bindings(
                "verification",
                ((item.candidate_id, item) for item in report.verification_decisions),
            ),
            authority.verification_decisions,
        ),
        (
            "cross-examination",
            _scheduler_evidence_payload_bindings(
                "cross_examination",
                ((item.candidate_id, item) for item in report.cross_examination_decisions),
            ),
            authority.cross_examination_decisions,
        ),
        (
            "falsification",
            _scheduler_evidence_payload_bindings(
                "falsification",
                ((item.candidate_id, item) for item in report.falsification_decisions),
            ),
            authority.falsification_decisions,
        ),
        (
            "reproduction",
            _scheduler_evidence_payload_bindings(
                "reproduction",
                ((item.candidate_id, item) for item in report.reproductions),
            ),
            authority.reproduction_results,
        ),
        (
            "reproduction resolution",
            _scheduler_evidence_payload_bindings(
                "reproduction_resolution",
                ((item.candidate_id, item) for item in reproduction_artifact.candidate_resolutions),
            ),
            authority.reproduction_resolutions,
        ),
    )
    for label, observed, expected in public_evidence:
        if observed != expected:
            raise ValueError(f"public {label} evidence differs from scheduler terminal authority")


def _validate_scheduler_terminal_authority_against_judgment(
    *,
    authority: SchedulerTerminalReportAuthority,
    judgment: SchedulerEvidenceCapJudgmentOutput,
    journal: SchedulerJournal,
) -> None:
    """Require a successful pass-seven host result to equal terminal report authority."""

    try:
        authority.require_exact_judgment(judgment)
    except ValueError as exc:
        raise ValueError("scheduler terminal authority differs from pass-seven judgment") from exc
    _validate_scheduler_retained_judge_decisions(
        judgment=judgment,
        journal=journal,
        require_complete_pass=False,
    )


def _validate_scheduler_retained_judge_decisions(
    *,
    judgment: SchedulerEvidenceCapJudgmentOutput,
    journal: SchedulerJournal,
    require_complete_pass: bool,
) -> None:
    """Join judgment bindings to exact retained judge outputs, including partial pass seven."""

    pass_result = _scheduler_pass_result(
        journal,
        SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
    )
    if pass_result is None or (
        require_complete_pass and pass_result.status is not SchedulerPassStatus.COMPLETE
    ):
        raise ValueError("scheduler judgment authority lacks its completed pass")
    retained_judges = []
    for task in (task for task in pass_result.plan.tasks if task.role == "judge"):
        if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("scheduler judge authority is not a model request")
        results = tuple(
            result for result in pass_result.task_results if result.task_id == task.task_id
        )
        if len(results) != 1:
            raise ValueError("scheduler judge task lacks one terminal result")
        if results[0].terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
            continue
        batch = _reconstruct_successful_scheduler_output(
            journal=journal,
            pass_result=pass_result,
            task_id=task.task_id,
            output_type=JudgeDecisionBatch,
        )
        retained_judges.extend(batch.decisions)
    judge_bindings = _scheduler_evidence_payload_bindings(
        "judge",
        ((item.group_id, item) for item in retained_judges),
    )
    if judge_bindings != judgment.judge_decisions:
        raise ValueError("scheduler judgment differs from exact retained judge decisions")


def _validate_scheduler_prejudgment_evidence_authority(
    *,
    authority: SchedulerTerminalReportAuthority,
    report: AuditReport,
    candidates: tuple[CandidateFinding, ...],
    reproduction_artifact: _ManifestReproductionArtifact,
    journal: SchedulerJournal,
) -> None:
    """Join current terminal evidence to exact successful pass-five/six outputs."""

    if authority.schema_version == "1.0":
        return
    assert authority.cross_examination_decisions is not None
    assert authority.verification_decisions is not None
    assert authority.falsification_decisions is not None
    assert authority.reproduction_results is not None
    assert authority.reproduction_resolutions is not None

    retained_cross_examinations = []
    cross_pass = _scheduler_pass_result(
        journal,
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
    )
    if cross_pass is not None:
        for task in cross_pass.plan.tasks:
            if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
                continue
            results = tuple(
                result for result in cross_pass.task_results if result.task_id == task.task_id
            )
            if len(results) != 1:
                raise ValueError("scheduler pass-five task lacks one terminal result")
            if results[0].terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
                continue
            if (
                len(task.candidate_ids) != 1
                or task.requested_model is None
                or task.root_lineage is None
            ):
                raise ValueError("scheduler pass-five task lacks exact candidate/model authority")
            candidate_id = task.candidate_ids[0]
            reviewer_text = task.role.rsplit("_", 1)[-1]
            if reviewer_text not in {"1", "2"}:
                raise ValueError("scheduler pass-five task lacks an exact reviewer index")
            reviewer_index = int(reviewer_text)
            expected_role = (
                "candidate_falsifier:"
                + hashlib.sha256(candidate_id.encode("utf-8")).hexdigest()
                + f":reviewer_{reviewer_index}"
            )
            if task.role != expected_role:
                raise ValueError("scheduler pass-five task role differs from its candidate")
            output = _successful_scheduler_task_output(
                journal=journal,
                pass_result=cross_pass,
                task_id=task.task_id,
            )
            completion = output.model_completion_evidence
            if completion is None:
                raise ValueError("scheduler pass-five output lacks completion evidence")
            response = _reconstruct_successful_scheduler_output(
                journal=journal,
                pass_result=cross_pass,
                task_id=task.task_id,
                output_type=CandidateCrossExaminationResponse,
            )
            usage = completion.usage_record
            retained_cross_examinations.extend(
                normalize_cross_examination_response(
                    response,
                    candidate_ids={"candidate-0001": candidate_id},
                    request_id=usage.request_id,
                    reviewer_index=reviewer_index,
                    requested_model=task.requested_model,
                    returned_model=usage.returned_model,
                    root_lineage=task.root_lineage,
                )
            )
    retained_cross_bindings = _scheduler_evidence_payload_bindings(
        "cross_examination",
        ((item.candidate_id, item) for item in retained_cross_examinations),
    )
    if retained_cross_bindings != authority.cross_examination_decisions:
        raise ValueError("scheduler terminal cross-examination differs from retained pass five")

    validation_pass = _scheduler_pass_result(
        journal,
        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
    )
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    retained_verifications = []
    retained_falsifications = []
    if validation_pass is not None:
        for task in validation_pass.plan.tasks:
            if task.task_kind is not SchedulerTaskKind.MODEL_REQUEST:
                continue
            results = tuple(
                result for result in validation_pass.task_results if result.task_id == task.task_id
            )
            if len(results) != 1:
                raise ValueError("scheduler pass-six task lacks one terminal result")
            if task.role == "verifier":
                try:
                    task_candidates = tuple(
                        candidate_by_id[candidate_id] for candidate_id in task.candidate_ids
                    )
                except KeyError as exc:
                    raise ValueError(
                        "scheduler pass-six verifier references an unknown candidate"
                    ) from exc
                if results[0].terminal_status is SchedulerTerminalStatus.SUCCEEDED:
                    retained_verifications.extend(
                        normalize_verification_response(
                            task_candidates,
                            _reconstruct_successful_scheduler_output(
                                journal=journal,
                                pass_result=validation_pass,
                                task_id=task.task_id,
                                output_type=VerificationBatch,
                            ),
                        ).decisions
                    )
                else:
                    retained_verifications.extend(
                        insufficient_verifications(task_candidates).decisions
                    )
            elif task.role in {"falsifier", "specialist:falsifier"}:
                if results[0].terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
                    continue
                retained_falsifications.extend(
                    _reconstruct_successful_scheduler_output(
                        journal=journal,
                        pass_result=validation_pass,
                        task_id=task.task_id,
                        output_type=FalsificationBatch,
                    ).decisions
                )
    retained_verification_bindings = _scheduler_evidence_payload_bindings(
        "verification",
        ((item.candidate_id, item) for item in retained_verifications),
    )
    if retained_verification_bindings != authority.verification_decisions:
        raise ValueError("scheduler terminal verification differs from retained pass six")
    retained_falsification_bindings = _scheduler_evidence_payload_bindings(
        "falsification",
        ((item.candidate_id, item) for item in retained_falsifications),
    )
    if retained_falsification_bindings != authority.falsification_decisions:
        raise ValueError("scheduler terminal falsification differs from retained pass six")

    reproduction_host = None
    exact_conditional_absence = False
    if validation_pass is not None:
        if validation_pass.plan.conditional_absence is not None:
            conditional_absence = validation_pass.plan.conditional_absence
            absence_tasks = validation_pass.plan.tasks
            absence_results = validation_pass.task_results
            if (
                conditional_absence.reason is not SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES
                or len(absence_tasks) != 1
                or absence_tasks[0].role != "host:conditional_absence"
                or absence_tasks[0].task_kind is not SchedulerTaskKind.EMPTY_COMPLETION
                or len(absence_results) != 1
                or absence_results[0].task_id != absence_tasks[0].task_id
                or absence_results[0].terminal_status is not SchedulerTerminalStatus.EXPLICIT_EMPTY
            ):
                raise ValueError("scheduler pass-six conditional absence is not exact")
            exact_conditional_absence = True
        else:
            host_tasks = tuple(
                task for task in validation_pass.plan.tasks if task.role == "host:reproduction"
            )
            if (
                len(host_tasks) != 1
                or host_tasks[0].task_kind is not SchedulerTaskKind.HOST_COMPUTATION
            ):
                raise ValueError("scheduler pass six lacks one exact reproduction host")
            host_results = tuple(
                result
                for result in validation_pass.task_results
                if result.task_id == host_tasks[0].task_id
            )
            if len(host_results) != 1:
                raise ValueError("scheduler reproduction host lacks one terminal result")
            if host_results[0].terminal_status is SchedulerTerminalStatus.SUCCEEDED:
                host_output = _successful_scheduler_task_output(
                    journal=journal,
                    pass_result=validation_pass,
                    task_id=host_tasks[0].task_id,
                )
                reproduction_host = SchedulerReproductionHostOutput.model_validate(
                    host_output.payload
                )
    public_tests = tuple(
        sorted(
            reproduction_artifact.test_specifications,
            key=lambda item: (item.candidate_id, item.name),
        )
    )
    public_results = tuple(
        sorted(
            reproduction_artifact.results,
            key=lambda item: (item.candidate_id, item.test_name),
        )
    )
    candidate_ids = {candidate.candidate_id for candidate in candidates}
    execution_candidate_ids = {
        candidate.candidate_id
        for candidate in candidates
        if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
    }
    forced_candidate_ids = _post_judgment_execution_resolution_ids(
        report=report,
        execution_candidate_ids=execution_candidate_ids,
        pre_judgment_high_critical_ids={
            candidate.candidate_id
            for candidate in candidates
            if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
        },
    )
    if not forced_candidate_ids <= candidate_ids:
        raise ValueError("post-judgment reproduction resolution references an unknown candidate")
    if reproduction_host is None:
        retained_resolutions = tuple(
            build_candidate_reproduction_resolutions(
                candidates=candidates,
                results=(),
                forced_candidate_ids=forced_candidate_ids,
            )
        )
        retained_resolution_bindings = _scheduler_evidence_payload_bindings(
            "reproduction_resolution",
            ((item.candidate_id, item) for item in retained_resolutions),
        )
        if (
            public_tests
            or public_results
            or authority.reproduction_results
            or tuple(reproduction_artifact.candidate_resolutions) != retained_resolutions
            or authority.reproduction_resolutions != retained_resolution_bindings
        ):
            raise ValueError(
                "scheduler terminal reproduction differs from typed pass-six absence"
                if exact_conditional_absence
                else "scheduler terminal reproduction differs without a successful pass-six host"
            )
        return
    if reproduction_host.generated_tests is None or reproduction_host.reproduction_results is None:
        raise ValueError("current scheduler reproduction host lacks exact payload authority")
    retained_tests = tuple(
        sorted(
            reproduction_host.generated_tests,
            key=lambda item: (item.candidate_id, item.name),
        )
    )
    retained_results = tuple(
        sorted(
            reproduction_host.reproduction_results,
            key=lambda item: (item.candidate_id, item.test_name),
        )
    )
    retained_reproduction_bindings = _scheduler_evidence_payload_bindings(
        "reproduction",
        ((item.candidate_id, item) for item in retained_results),
    )
    retained_resolutions = tuple(
        build_candidate_reproduction_resolutions(
            candidates=candidates,
            results=retained_results,
            forced_candidate_ids=forced_candidate_ids,
        )
    )
    public_resolutions = tuple(reproduction_artifact.candidate_resolutions)
    retained_resolution_bindings = _scheduler_evidence_payload_bindings(
        "reproduction_resolution",
        ((item.candidate_id, item) for item in retained_resolutions),
    )
    if (
        public_tests != retained_tests
        or public_results != retained_results
        or public_resolutions != retained_resolutions
        or retained_reproduction_bindings != authority.reproduction_results
        or retained_resolution_bindings != authority.reproduction_resolutions
        or reproduction_host.falsification_decisions != len(authority.falsification_decisions)
    ):
        raise ValueError("scheduler terminal reproduction differs from retained pass six")


def _successful_scheduler_partial_host_output[OutputT: StrictModel](
    *,
    journal: SchedulerJournal,
    pass_kind: SchedulerPassKind,
    role: str,
    output_type: type[OutputT],
) -> OutputT | None:
    """Return a successful host output even when a later task failed the sealed pass."""

    pass_result = _scheduler_pass_result(journal, pass_kind)
    if pass_result is None:
        return None
    tasks = tuple(task for task in pass_result.plan.tasks if task.role == role)
    if len(tasks) != 1 or tasks[0].task_kind is not SchedulerTaskKind.HOST_COMPUTATION:
        raise ValueError("scheduler pass lacks one exact host authority task")
    task_results = tuple(
        result for result in pass_result.task_results if result.task_id == tasks[0].task_id
    )
    if len(task_results) != 1:
        raise ValueError("scheduler host authority task lacks one terminal result")
    if task_results[0].terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
        return None
    return _reconstruct_successful_scheduler_output(
        journal=journal,
        pass_result=pass_result,
        task_id=tasks[0].task_id,
        output_type=output_type,
    )


def _validate_scheduler_terminal_report_authority(
    *,
    report: AuditReport,
    reproduction_artifact: _ManifestReproductionArtifact,
    judgment: SchedulerEvidenceCapJudgmentOutput,
    journal: SchedulerJournal,
) -> None:
    """Compare every terminal public decision to the exact private pass-seven authority."""

    if report.metadata.get("severity_threshold") != judgment.severity_threshold.value:
        raise ValueError("report severity threshold differs from scheduler judgment authority")

    public_partitions = (
        (
            SchedulerTerminalFindingState.REPORTED_ACTIVE,
            report.findings,
            judgment.final_finding_ids,
            judgment.final_finding_payload_sha256s,
        ),
        (
            SchedulerTerminalFindingState.REPORTED_REJECTED,
            report.rejected_findings,
            judgment.rejected_finding_ids,
            judgment.rejected_finding_payload_sha256s,
        ),
        (
            SchedulerTerminalFindingState.FILTERED_BELOW_THRESHOLD,
            report.filtered_findings,
            judgment.filtered_finding_ids,
            judgment.filtered_finding_payload_sha256s,
        ),
    )
    findings_by_id: dict[str, tuple[SchedulerTerminalFindingState, Finding]] = {}
    for state, findings, expected_ids, expected_hashes in public_partitions:
        observed_ids = tuple(sorted(finding.id for finding in findings))
        observed_hashes = {
            finding.id: scheduler_canonical_sha256(finding.model_dump(mode="json"))
            for finding in sorted(findings, key=lambda item: item.id)
        }
        if observed_ids != expected_ids or observed_hashes != expected_hashes:
            raise ValueError("public finding partition differs from scheduler judgment authority")
        for finding in findings:
            if finding.id in findings_by_id:
                raise ValueError("public terminal finding inventory repeats an identity")
            findings_by_id[finding.id] = (state, finding)

    for binding in judgment.terminal_findings:
        public = findings_by_id.get(binding.finding_id)
        if public is None:
            raise ValueError("scheduler terminal finding is absent from the public report")
        state, finding = public
        if (
            state is not binding.state
            or finding.group_id != binding.group_id
            or tuple(sorted(finding.contributing_candidate_ids)) != binding.candidate_ids
            or finding.status is not binding.finding_status
            or finding.severity is not binding.finding_severity
            or finding.origin_kind is not binding.finding_origin_kind
            or scheduler_canonical_sha256(finding.model_dump(mode="json"))
            != binding.finding_payload_sha256
        ):
            raise ValueError("public terminal finding differs from its scheduler disposition")

    public_evidence = (
        (
            "verification",
            _scheduler_evidence_payload_bindings(
                "verification",
                ((item.candidate_id, item) for item in report.verification_decisions),
            ),
            judgment.verification_decisions,
        ),
        (
            "cross-examination",
            _scheduler_evidence_payload_bindings(
                "cross_examination",
                ((item.candidate_id, item) for item in report.cross_examination_decisions),
            ),
            judgment.cross_examination_decisions,
        ),
        (
            "falsification",
            _scheduler_evidence_payload_bindings(
                "falsification",
                ((item.candidate_id, item) for item in report.falsification_decisions),
            ),
            judgment.falsification_decisions,
        ),
        (
            "reproduction",
            _scheduler_evidence_payload_bindings(
                "reproduction",
                ((item.candidate_id, item) for item in report.reproductions),
            ),
            judgment.reproduction_results,
        ),
        (
            "reproduction resolution",
            _scheduler_evidence_payload_bindings(
                "reproduction_resolution",
                ((item.candidate_id, item) for item in reproduction_artifact.candidate_resolutions),
            ),
            judgment.reproduction_resolutions,
        ),
    )
    for label, observed, expected in public_evidence:
        if observed != expected:
            raise ValueError(f"public {label} evidence differs from scheduler judgment authority")

    _validate_scheduler_retained_judge_decisions(
        judgment=judgment,
        journal=journal,
        require_complete_pass=True,
    )


def _validate_scheduler_report_authority(
    *,
    root: Path,
    report: AuditReport,
    journal: SchedulerJournal,
) -> None:
    """Join public candidate and finding semantics to successful private host outputs."""

    candidate_artifact = CandidateFindingArtifact.model_validate(
        _read_json_artifact(root, "candidate-findings.json")
    )
    reproduction_artifact = _ManifestReproductionArtifact.model_validate(
        _read_json_artifact(root, "reproduction-results.json")
    )
    candidate_hashes = _scheduler_candidate_payload_sha256s(candidate_artifact.findings)
    accepted_hash_authority, accepted_candidate_authority = _scheduler_accepted_candidate_authority(
        journal
    )
    blind_candidates = accepted_candidate_authority[SchedulerPassKind.BLIND_SHARD_REVIEW]
    blind_authority = _scheduler_candidate_payload_sha256s(
        attach_formal_counterexamples(
            [blind_candidates[candidate_id] for candidate_id in sorted(blind_candidates)],
            list(report.formal_runs),
        )
    )
    cross_shard_authority = accepted_hash_authority[SchedulerPassKind.CROSS_SHARD_INTEGRATION]

    reduction = _successful_scheduler_host_output(
        journal=journal,
        pass_kind=SchedulerPassKind.FINDING_REDUCTION,
        role="host:finding_reducer",
        output_type=SchedulerFindingReductionOutput,
    )
    integration = _successful_scheduler_host_output(
        journal=journal,
        pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        role="host:cross_shard_integrator",
        output_type=SchedulerCrossShardIntegrationOutput,
    )
    judgment = _successful_scheduler_host_output(
        journal=journal,
        pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
        role="host:evidence_cap_judgment",
        output_type=SchedulerEvidenceCapJudgmentOutput,
    )
    retained_judgment = _successful_scheduler_partial_host_output(
        journal=journal,
        pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
        role="host:evidence_cap_judgment",
        output_type=SchedulerEvidenceCapJudgmentOutput,
    )

    if reduction is None:
        if cross_shard_authority:
            raise ValueError("scheduler cross-shard candidates lack pass-three authority")
        if not set(blind_authority) <= set(candidate_hashes) or any(
            candidate_hashes[candidate_id] != candidate_sha256
            for candidate_id, candidate_sha256 in blind_authority.items()
        ):
            raise ValueError("candidate artifact differs from partial scheduler authority")
        unauthoritative_candidates = tuple(
            candidate
            for candidate in candidate_artifact.findings
            if candidate.candidate_id not in blind_authority
        )
        if any(
            candidate.origin_kind is not CandidateOriginKind.DETERMINISTIC_EXECUTION
            for candidate in unauthoritative_candidates
        ):
            raise ValueError("incomplete scheduler report contains an unauthorized model candidate")
        latest_candidate_authority = candidate_hashes
    else:
        expected_blind_hashes = {
            candidate_id: reduction.candidate_payload_sha256s[candidate_id]
            for candidate_id in reduction.blind_candidate_ids
        }
        if blind_authority != expected_blind_hashes:
            raise ValueError("scheduler pass-three differs from accepted blind candidates")
        latest_candidate_authority = dict(reduction.candidate_payload_sha256s)
        for candidate_id, candidate_sha256 in cross_shard_authority.items():
            if candidate_id in latest_candidate_authority:
                raise ValueError("scheduler cross-shard candidate repeats pass-three identity")
            latest_candidate_authority[candidate_id] = candidate_sha256
        latest_candidate_authority = dict(sorted(latest_candidate_authority.items()))
        if integration is not None and (
            integration.candidate_payload_sha256s != latest_candidate_authority
            or not set(reduction.candidate_ids) <= set(integration.candidate_ids)
        ):
            raise ValueError("scheduler pass-four changed its accepted candidate authority")
        if integration is not None:
            latest_candidate_authority = integration.candidate_payload_sha256s
        if candidate_hashes != latest_candidate_authority:
            raise ValueError("candidate artifact differs from scheduler host authority")

    terminal_authority = journal.terminal_report_authority
    terminal_authority_required = journal.manifest.terminal_report_authority_required
    if terminal_authority_required and terminal_authority is None:
        raise ValueError("current scheduler journal lacks terminal report authority")
    if not terminal_authority_required and terminal_authority is not None:
        raise ValueError("legacy scheduler journal unexpectedly contains terminal authority")
    if terminal_authority is not None:
        _validate_scheduler_terminal_projection_authority(
            report=report,
            reproduction_artifact=reproduction_artifact,
            candidate_hashes=candidate_hashes,
            authority=terminal_authority,
        )
        _validate_scheduler_prejudgment_evidence_authority(
            authority=terminal_authority,
            report=report,
            candidates=tuple(candidate_artifact.findings),
            reproduction_artifact=reproduction_artifact,
            journal=journal,
        )
        if retained_judgment is not None:
            _validate_scheduler_terminal_authority_against_judgment(
                authority=terminal_authority,
                judgment=retained_judgment,
                journal=journal,
            )

    campaign_complete = journal.summary.status is SchedulerCampaignStatus.COMPLETE
    _validate_scheduler_report_quality_authority(report=report, journal=journal)
    if campaign_complete and judgment is None:
        raise ValueError("complete scheduler report lacks successful pass-seven authority")
    if judgment is None:
        return
    if integration is None or (
        judgment.candidate_ids != tuple(latest_candidate_authority)
        or judgment.candidate_payload_sha256s != latest_candidate_authority
    ):
        raise ValueError("scheduler pass-seven candidates differ from pass-four authority")
    if candidate_hashes != judgment.candidate_payload_sha256s:
        raise ValueError("candidate artifact differs from scheduler judgment authority")

    _validate_scheduler_terminal_report_authority(
        report=report,
        reproduction_artifact=reproduction_artifact,
        judgment=judgment,
        journal=journal,
    )


def _validate_scheduler_privacy_artifacts(
    *,
    root: Path,
    report: AuditReport,
    custody: SchedulerPrivacyEvidenceCustody,
) -> None:
    """Validate exact emitted privacy files while their descriptors remain held."""

    from mmaudit.privacy import EffectivePrivacyPolicyEvidence
    from mmaudit.repository.privacy_provenance import PrivacySourceProvenanceEvidence

    names = (custody.source_provenance_path, custody.effective_policy_path)
    bindings = (
        ManifestFileBinding(
            path=custody.source_provenance_path,
            sha256=custody.source_provenance_artifact_sha256,
            size=custody.source_provenance_size,
        ),
        ManifestFileBinding(
            path=custody.effective_policy_path,
            sha256=custody.effective_policy_artifact_sha256,
            size=custody.effective_policy_size,
        ),
    )
    final_manifest_path = root / "run-evidence-manifest.json"
    try:
        final_manifest_path.lstat()
    except FileNotFoundError:
        artifact_observation = open_pre_manifest_json_artifacts(
            root,
            names,
            expected_bindings=bindings,
            max_bytes=_MAX_SCHEDULER_PRIVACY_EVIDENCE_BYTES,
        )
    except OSError as exc:
        raise ValueError("scheduler privacy run-manifest state cannot be inspected") from exc
    else:
        artifact_observation = open_manifest_bound_json_artifacts(
            root,
            names,
            required_bindings=bindings,
            max_bytes=_MAX_SCHEDULER_PRIVACY_EVIDENCE_BYTES,
        )

    with artifact_observation as payloads:
        try:
            provenance = PrivacySourceProvenanceEvidence.model_validate(
                payloads[custody.source_provenance_path]
            )
            policy = EffectivePrivacyPolicyEvidence.model_validate(
                payloads[custody.effective_policy_path]
            )
            reported_provenance = PrivacySourceProvenanceEvidence.model_validate(
                report.privacy.get("source_provenance")
            )
            reported_policy = EffectivePrivacyPolicyEvidence.model_validate(
                report.privacy.get("effective_policy")
            )
        except (TypeError, ValueError):
            raise ValueError("scheduler privacy custody lacks valid typed evidence") from None
        if provenance != reported_provenance or policy != reported_policy:
            raise ValueError("scheduler privacy evidence differs from the final report")
        if (
            provenance.source_sha256 != custody.source_sha256
            or policy.source_sha256 != custody.source_sha256
            or provenance.evidence_sha256 != custody.source_provenance_evidence_sha256
            or policy.evidence_sha256 != custody.effective_policy_evidence_sha256
            or policy.source_provenance_sha256 != custody.policy_source_provenance_sha256
        ):
            raise ValueError("scheduler privacy evidence differs from its exact custody")


@contextmanager
def _resolve_scheduler_journal_authority_path(
    *,
    root: Path,
    public_artifact: SchedulerArtifact,
    reference_binding: ManifestFileBinding | None,
    detached: bool,
) -> Iterator[Path]:
    """Resolve physical same-run or typed no-copy prior-run journal custody."""

    absolute_root = Path(os.path.abspath(root))
    current_component = Path(absolute_root.anchor)
    for part in absolute_root.parts[1:]:
        current_component /= part
        if current_component.is_symlink() or current_component.is_junction():
            raise ValueError("scheduler run custody refuses linked path components")
    try:
        resolved_root = absolute_root.resolve(strict=True)
        runs_root = resolved_root.parent
        runs_metadata = runs_root.lstat()
        run_metadata = resolved_root.lstat()
        private_dir = resolved_root / "private"
        private_metadata = private_dir.lstat()
    except OSError as exc:
        raise ValueError("scheduler run custody path is unavailable") from exc
    if (
        not stat.S_ISDIR(runs_metadata.st_mode)
        or stat.S_ISLNK(runs_metadata.st_mode)
        or runs_root.is_junction()
        or not stat.S_ISDIR(run_metadata.st_mode)
        or stat.S_ISLNK(run_metadata.st_mode)
        or resolved_root.is_junction()
        or not stat.S_ISDIR(private_metadata.st_mode)
        or stat.S_ISLNK(private_metadata.st_mode)
        or private_dir.is_junction()
    ):
        raise ValueError("scheduler run custody requires unlinked physical directories")

    journal_path = private_dir / "scheduler-journal"
    reference_path = private_dir / SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME
    journal_exists = journal_path.exists() or journal_path.is_symlink()
    reference_exists = reference_path.exists() or reference_path.is_symlink()
    if journal_exists and reference_exists:
        raise ValueError("scheduler run custody cannot contain journal and retained reference")
    if journal_exists:
        if reference_binding is not None:
            raise ValueError("physical scheduler journal contradicts a sealed reference binding")
        try:
            journal_metadata = journal_path.lstat()
        except OSError as exc:
            raise ValueError("scheduler public artifact lacks its private journal") from exc
        if (
            not stat.S_ISDIR(journal_metadata.st_mode)
            or stat.S_ISLNK(journal_metadata.st_mode)
            or journal_path.is_junction()
        ):
            raise ValueError("scheduler private journal must be an unlinked directory")
        resolved_journal = journal_path.resolve(strict=True)
        if resolved_journal.parent != private_dir:
            raise ValueError("scheduler private journal escaped its owning run")
        custody = {
            runs_root: _artifact_stat_identity(runs_metadata),
            resolved_root: _artifact_stat_identity(run_metadata),
            private_dir: _artifact_stat_identity(private_metadata),
            journal_path: _artifact_stat_identity(journal_metadata),
        }
        try:
            yield resolved_journal
        finally:
            _require_exact_path_custody(custody)
        return
    if not reference_exists:
        raise ValueError("scheduler public artifact lacks its private journal custody evidence")
    if detached and reference_binding is None:
        raise ValueError("detached scheduler reference lacks its sealed manifest binding")

    reference_name = f"private/{SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME}"
    with _open_json_artifact_observation(
        resolved_root,
        reference_name,
        expected_binding=reference_binding,
    ) as reference_payload:
        try:
            reference = SchedulerRetainedJournalReference.model_validate(reference_payload)
            reference.require_exact(
                owner_run_id=reference.owner_run_id,
                consumer_run_id=resolved_root.name,
                artifact=public_artifact,
            )
        except ValueError as exc:
            raise ValueError("scheduler retained-journal reference is invalid") from exc

        owner_run = runs_root / reference.owner_run_id
        owner_private = owner_run / "private"
        owner_journal = owner_private / "scheduler-journal"
        try:
            owner_metadata = owner_run.lstat()
            owner_private_metadata = owner_private.lstat()
            owner_journal_metadata = owner_journal.lstat()
        except OSError as exc:
            raise ValueError("scheduler retained journal is unavailable") from exc
        if (
            owner_run.parent != runs_root
            or not stat.S_ISDIR(owner_metadata.st_mode)
            or stat.S_ISLNK(owner_metadata.st_mode)
            or owner_run.is_junction()
            or not stat.S_ISDIR(owner_private_metadata.st_mode)
            or stat.S_ISLNK(owner_private_metadata.st_mode)
            or owner_private.is_junction()
            or not stat.S_ISDIR(owner_journal_metadata.st_mode)
            or stat.S_ISLNK(owner_journal_metadata.st_mode)
            or owner_journal.is_junction()
        ):
            raise ValueError("scheduler retained journal path is unsafe")
        owner_reference = owner_private / SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME
        if owner_reference.exists() or owner_reference.is_symlink():
            raise ValueError("scheduler retained-journal reference chains are forbidden")
        resolved_owner = owner_run.resolve(strict=True)
        resolved_owner_private = owner_private.resolve(strict=True)
        resolved_owner_journal = owner_journal.resolve(strict=True)
        if (
            resolved_owner.parent != runs_root
            or resolved_owner_private != resolved_owner / "private"
            or resolved_owner_journal != resolved_owner_private / "scheduler-journal"
            or reference.relative_journal_path
            != f"{reference.owner_run_id}/private/scheduler-journal"
        ):
            raise ValueError("scheduler retained journal escaped the exact runs root")
        custody = {
            runs_root: _artifact_stat_identity(runs_metadata),
            resolved_root: _artifact_stat_identity(run_metadata),
            private_dir: _artifact_stat_identity(private_metadata),
            owner_run: _artifact_stat_identity(owner_metadata),
            owner_private: _artifact_stat_identity(owner_private_metadata),
            owner_journal: _artifact_stat_identity(owner_journal_metadata),
        }
        try:
            yield resolved_owner_journal
        finally:
            _require_exact_path_custody(custody)
            if owner_reference.exists() or owner_reference.is_symlink():
                raise ValueError("scheduler retained-journal reference chains are forbidden")


def _require_exact_path_custody(
    expected: dict[Path, tuple[int, int, int, int, int, int, int]],
) -> None:
    """Reject link, replacement, or metadata drift across one authority decision."""

    try:
        observed = {path: path.lstat() for path in expected}
    except OSError as exc:
        raise ValueError("scheduler journal custody changed during validation") from exc
    if any(
        _artifact_stat_identity(observed[path]) != identity
        or stat.S_ISLNK(observed[path].st_mode)
        or path.is_junction()
        for path, identity in expected.items()
    ):
        raise ValueError("scheduler journal custody changed during validation")


def _validate_scheduler_model_request(
    *,
    request: SchedulerModelRequestEvidence,
    plan: Any,
    task: Any,
    result: Any,
    permitted_schema_hashes: frozenset[str],
) -> None:
    """Require the public lifecycle projection to equal its terminal task evidence."""

    if (
        request.campaign_id != plan.manifest.campaign_id
        or request.manifest_sha256 != plan.manifest.manifest_sha256
        or request.pass_kind is not plan.pass_kind
        or request.pass_id != plan.pass_id
        or request.pass_plan_id != plan.pass_plan_id
        or request.pass_plan_sha256 != plan.pass_plan_sha256
        or request.task_id != task.task_id
        or request.task_plan_sha256 != task.task_plan_sha256
        or request.scope_sha256 != task.scope.scope_sha256
        or request.role != task.role
        or request.requested_model != task.requested_model
        or request.root_lineage != task.root_lineage
        or request.terminal_status is not result.terminal_status
        or request.result_id != result.result_id
        or request.result_sha256 != result.result_sha256
        or request.terminal_evidence_sha256 != result.terminal_evidence_sha256
        or request.output_sha256 != result.output_sha256
        or request.output_artifact_sha256 != result.output_artifact_sha256
        or request.model_completion_evidence_sha256 != result.model_completion_evidence_sha256
        or request.usage_record_sha256 != result.usage_record_sha256
        or request.context_request_evidence_sha256 != result.context_request_evidence_sha256
        or request.provider_response_sha256 != result.provider_response_sha256
        or request.validated_response_sha256 != result.validated_response_sha256
        or request.normalizer_sha256 != result.normalizer_sha256
        or request.reviewed_source_descriptor_sha256s != result.reviewed_source_descriptor_sha256s
        or request.reviewed_candidate_ids != result.reviewed_candidate_ids
    ):
        raise ValueError("scheduler public model request differs from terminal task evidence")
    if result.activation_id is None:
        if request.activation_status is not SchedulerActivationStatus.PREFLIGHT_FAILED:
            raise ValueError("scheduler preflight result differs from public activation status")
        return
    if (
        request.activation_status is not SchedulerActivationStatus.ACTIVATED
        or request.activation_id != result.activation_id
        or request.activation_sha256 != result.activation_sha256
        or request.actual_input_sha256 is None
        or request.actual_input_sha256 != request.user_prompt_sha256
        or request.system_prompt_sha256 != task.system_prompt_sha256
        or request.provider_prompt_sha256 is None
        or request.response_schema_sha256 not in permitted_schema_hashes
    ):
        raise ValueError("scheduler activated request lacks exact public request hashes")


def _validate_scheduler_usage_join(
    *,
    usage: UsageRecord,
    request: SchedulerModelRequestEvidence,
) -> None:
    """Reject provider records that contradict the scheduler's pre-transport activation."""

    if request.activation_status is not SchedulerActivationStatus.ACTIVATED:
        raise ValueError("provider usage exists for an unactivated scheduler request")
    routed_lineage = usage.routing.get("qualified_root_lineage")
    raw_context_evidence = usage.routing.get("context_request_evidence")
    try:
        context_evidence = ProviderContextRequestEvidence.model_validate(raw_context_evidence)
    except ValueError as exc:
        raise ValueError("provider usage lacks typed scheduler context evidence") from exc
    if (
        usage.role != request.role
        or usage.requested_model != request.requested_model
        or usage.prompt_sha256 != request.provider_prompt_sha256
        or usage.user_prompt_sha256 != request.user_prompt_sha256
        or usage.schema_sha256 != request.response_schema_sha256
        or context_evidence.request_id != request.logical_request_id
        or context_evidence.request_role != request.role
        or usage.routing.get("context_request_evidence_sha256") != context_evidence.evidence_sha256
        or (routed_lineage is not None and routed_lineage != request.root_lineage)
    ):
        raise ValueError("provider usage differs from its scheduler activation identity")
    if request.terminal_status is SchedulerTerminalStatus.SUCCEEDED and (
        request.usage_record_sha256 != scheduler_canonical_sha256(usage.model_dump(mode="json"))
        or request.context_request_evidence_sha256 != context_evidence.evidence_sha256
        or request.provider_response_sha256 != usage.response_sha256
        or request.validated_response_sha256 != usage.validated_response_sha256
    ):
        raise ValueError("provider usage differs from persisted scheduler completion evidence")


def _scheduler_usage_is_creditable(
    *,
    usage: UsageRecord,
    request: SchedulerModelRequestEvidence,
    config: AuditConfig | None,
) -> bool:
    """Credit only one exact, validated, non-fallback completion for its activation."""

    routed_lineage = usage.routing.get("qualified_root_lineage")
    configured_lineage = (
        model_lineage_index(config).get(request.requested_model.lower())
        if config is not None
        else None
    )
    lineage_bound = (
        routed_lineage == request.root_lineage
        if routed_lineage is not None
        else configured_lineage is not None
        and configured_lineage.root_lineage == request.root_lineage
    )
    real_identity_bound = (
        usage.execution_evidence is not ExecutionEvidenceKind.REAL
        or usage.identity_strength is not ModelIdentityStrength.UNBOUND
    )
    return bool(
        usage.request_id == request.logical_request_id
        and usage.execution_evidence in {ExecutionEvidenceKind.REAL, ExecutionEvidenceKind.MOCK}
        and usage.status == "success"
        and usage.validation_status is ModelRequestValidationStatus.VALID
        and real_identity_bound
        and usage.provider_error_classification is None
        and usage.finish_reason == "stop"
        and usage.returned_model == request.requested_model
        and usage.actual_model == request.requested_model
        and usage.response_sha256 is not None
        and usage.validated_response_sha256 is not None
        and usage.request_body_sha256 is not None
        and not usage.fallback_used
        and not usage.substitution_detected
        and lineage_bound
    )


def _validate_language_capability_artifact(
    root: Path,
    report: AuditReport,
    *,
    expected_binding: ManifestFileBinding | None = None,
) -> LanguageCapabilityArtifact:
    """Bind the typed capability artifact to the final report under optional byte custody."""

    try:
        artifact = LanguageCapabilityArtifact.model_validate(
            _read_json_artifact(
                root,
                LANGUAGE_CAPABILITY_ARTIFACT_PATH,
                expected_binding=expected_binding,
            ),
            strict=True,
        )
    except ValueError as exc:
        raise ValueError("language capability artifact is invalid") from exc
    if report.language_capability is None:
        raise ValueError("current report lacks source-bound language capability evidence")
    if artifact.assessment != report.language_capability:
        raise ValueError("language capability artifact differs from the final report")
    return artifact


def validate_manifest_artifacts(
    manifest: RunEvidenceManifest,
    run_dir: Path,
    *,
    scheduler_runtime_journal: SchedulerJournal | None = None,
) -> None:
    """Verify every run file is listed and unchanged without executing target code."""

    absolute_run_dir = Path(os.path.abspath(run_dir))
    current_component = Path(absolute_run_dir.anchor)
    for part in absolute_run_dir.parts[1:]:
        current_component /= part
        if current_component.is_symlink() or current_component.is_junction():
            raise ValueError("run artifact validation refuses linked path components")
    root = absolute_run_dir.resolve(strict=True)
    expected = {binding.path: binding for binding in manifest.artifacts}
    actual = {binding.path: binding for binding in collect_run_artifacts(root)}
    if set(actual) != set(expected):
        raise ValueError("run artifact set does not match the evidence manifest")
    for path, binding in expected.items():
        observed = actual[path]
        if observed.size != binding.size or observed.sha256 != binding.sha256:
            raise ValueError(f"run artifact hash mismatch: {path}")
    if manifest.schema_version in {"1.1", "1.2"}:
        required_artifacts = {"final-findings.json", "metadata.json"}
        if manifest.schema_version == "1.2":
            required_artifacts.update(
                MANIFEST_BOUND_REPORT_DELIVERABLES
                | {
                    RUN_TERMINAL_REPORT_AUTHORITY_PATH,
                    LANGUAGE_CAPABILITY_ARTIFACT_PATH,
                }
            )
        for required_artifact in sorted(required_artifacts):
            if required_artifact not in expected:
                raise ValueError(
                    f"current run manifest requires emitted artifact: {required_artifact}"
                )
    if "final-findings.json" in expected:
        scheduler_reference_binding = expected.get(
            f"private/{SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME}"
        )
        report = AuditReport.model_validate(
            _read_json_artifact(
                root,
                "final-findings.json",
                expected_binding=expected["final-findings.json"],
            )
        )
        _validate_report_artifact_consistency(
            root,
            report,
            report_bundle_required=manifest.schema_version == "1.2",
        )
        language_artifact_bound = LANGUAGE_CAPABILITY_ARTIFACT_PATH in expected
        if (
            manifest.schema_version == "1.2"
            or language_artifact_bound
            or report.language_capability is not None
        ):
            if not language_artifact_bound or report.language_capability is None:
                raise ValueError(
                    "language capability evidence is only valid when report and artifact agree"
                )
            _validate_language_capability_artifact(
                root,
                report,
                expected_binding=expected[LANGUAGE_CAPABILITY_ARTIFACT_PATH],
            )
        validate_solidity_shard_artifacts(root, report)
        context_manifest = _validated_context_manifest(root, report)
        if manifest.run_configuration is not None:
            effective_config = manifest.run_configuration.reconstruct_effective_config()
            qualification_path = root / "model-qualification-runtime.json"
            qualification_runtime = (
                _read_json_artifact(root, "model-qualification-runtime.json")
                if qualification_path.exists()
                else None
            )
            scheduler_artifact = validate_scheduler_artifact(
                root,
                report,
                config=effective_config,
                qualification_runtime=qualification_runtime,
                scheduler_runtime_journal=scheduler_runtime_journal,
                scheduler_reference_binding=scheduler_reference_binding,
                require_retained_usage_custody=manifest.schema_version == "1.2",
            )
            _validate_repository_differential_configuration(report, effective_config)
            _validate_context_manifest_configuration(
                context_manifest,
                effective_config,
            )
        else:
            scheduler_artifact = validate_scheduler_artifact(
                root,
                report,
                scheduler_runtime_journal=scheduler_runtime_journal,
                scheduler_reference_binding=scheduler_reference_binding,
                require_retained_usage_custody=manifest.schema_version == "1.2",
            )
        if report.schema_version == "1.2" or manifest.schema_version == "1.2":
            _validate_model_execution_cost_ledger_custody(
                root,
                report,
                scheduler_artifact,
                current_model_execution_required=manifest.schema_version == "1.2",
            )
        if manifest.schema_version == "1.2":
            assert manifest.run_configuration is not None
            _validate_run_terminal_report_authority(
                root,
                report,
                scheduler_artifact=scheduler_artifact,
                achieved_profile=manifest.run_configuration.achieved_profile,
                expected_binding=expected[RUN_TERMINAL_REPORT_AUTHORITY_PATH],
            )
        expected_classification = (
            manifest.run_configuration.run_options.privacy_source_classification
            if manifest.run_configuration is not None
            else None
        )
        validate_report_privacy_consistency(
            report,
            source_tree_sha256=manifest.source_tree_sha256,
            expected_source_classification=expected_classification,
        )
        for artifact_name, report_key in (
            ("privacy-policy.json", "effective_policy"),
            ("privacy-source-provenance.json", "source_provenance"),
        ):
            reported = report.privacy.get(report_key)
            if (artifact_name in expected) != (reported is not None):
                raise ValueError(f"{artifact_name} presence differs from the final report")
            if (
                artifact_name in expected
                and _read_json_artifact(
                    root,
                    artifact_name,
                )
                != reported
            ):
                raise ValueError(f"{artifact_name} differs from the final report")


def build_manifest_configuration_bindings(
    config: AuditConfig,
) -> list[ManifestHashBinding]:
    """Reconstruct the exact full and model configuration binding inventory."""

    return [
        ManifestHashBinding(
            identifier="config/full",
            sha256=config.stable_hash(),
            details={
                "version": str(config.version),
                "profile": config.profile.value,
                "language_profile": config.language_profile.value,
            },
        ),
        ManifestHashBinding(
            identifier="config/models",
            sha256=config.model_hash(),
            details={"configured_roles": str(6 + len(config.models.specialists))},
        ),
    ]


def _configuration_bindings(config: AuditConfig) -> list[ManifestHashBinding]:
    return build_manifest_configuration_bindings(config)


def _prompt_bindings(report: AuditReport) -> list[ManifestHashBinding]:
    bindings: list[ManifestHashBinding] = []
    prompt_root = files("mmaudit.prompts")
    for prompt in sorted(prompt_root.iterdir(), key=lambda item: item.name):
        if prompt.is_file() and prompt.name.endswith(".md"):
            bindings.append(
                ManifestHashBinding(
                    identifier=f"template/{prompt.name}",
                    sha256=hashlib.sha256(prompt.read_bytes()).hexdigest(),
                    details={"kind": "system_template"},
                )
            )
    for index, usage in enumerate(report.usage):
        bindings.append(
            ManifestHashBinding(
                identifier=f"request/{index:05d}",
                sha256=usage.prompt_sha256,
                details={
                    "role": _detail(usage.role),
                    "requested_model": _detail(usage.requested_model),
                    "status": _detail(usage.status),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _model_bindings(
    config: AuditConfig,
    report: AuditReport,
    *,
    qualification_runtime: dict[str, Any] | None,
    production_qualification: VerifiedProductionQualification | None = None,
    sealed_verification_bindings: list[ManifestHashBinding] | None = None,
) -> list[ManifestHashBinding]:
    # Local import avoids introducing runtime construction into schema imports.
    from mmaudit.models.runtime import build_reasoning_policy

    roles = [*ALL_MODEL_ROLES, *sorted(config.models.specialists)]
    registry = {
        model_id.lower(): entry
        for entry in config.models.registry
        for model_id in entry.model_ids()
    }
    bindings = []
    reasoning_policy = build_reasoning_policy(config)
    qualification_validation = _qualification_validation(qualification_runtime)
    if production_qualification is not None and sealed_verification_bindings is not None:
        raise ValueError("runtime authority cannot be mixed with a verification projection")
    opaque_qualification = _validated_opaque_qualification(
        config=config,
        validation=qualification_validation,
        qualification=production_qualification,
    )
    issuance_authority_sha256 = (
        _serialized_issuance_authority_sha256(
            validation=qualification_validation,
            sealed_bindings=sealed_verification_bindings,
        )
        if sealed_verification_bindings is not None
        else (opaque_qualification.capability_sha256 if opaque_qualification is not None else None)
    )
    bindings.append(
        ManifestHashBinding(
            identifier="reasoning/policy",
            sha256=reasoning_policy.artifact_sha256,
            details={
                "schema_version": reasoning_policy.schema_version,
                "roles": str(len(reasoning_policy.policies)),
            },
        )
    )
    bindings.extend(
        ManifestHashBinding(
            identifier=f"reasoning/configured/{policy.role}",
            sha256=policy.binding_sha256,
            details={
                "mode": policy.control.mode,
                "effort": policy.control.effort or "not_set",
                "max_tokens": str(policy.control.max_tokens or 0),
                "reserved_reasoning_tokens": str(policy.control.reserved_reasoning_tokens),
                "profile_sha256": policy.control.profile_sha256,
            },
        )
        for policy in reasoning_policy.policies
    )
    for role in roles:
        role_config = config.models.role(role)
        lineage = registry.get(role_config.primary.lower())
        projection = {
            "role": role,
            "configuration": role_config.model_dump(mode="json"),
            "lineage": lineage.model_dump(mode="json") if lineage is not None else None,
        }
        bindings.append(
            _binding(
                f"configured/{role}",
                projection,
                {
                    "primary": _detail(role_config.primary),
                    "root_lineage": lineage.root_lineage if lineage is not None else "unresolved",
                },
            )
        )
    for index, usage in enumerate(report.usage):
        execution_payload = usage.model_dump(mode="json")
        if usage.reasoning_evidence is None:
            # Preserve the pre-reasoning execution binding for legacy reports.
            execution_payload.pop("reasoning_evidence")
        bindings.append(
            _binding(
                f"execution/{index:05d}",
                execution_payload,
                {
                    "role": _detail(usage.role),
                    "requested": _detail(usage.requested_model),
                    "returned": _detail(usage.returned_model or "not_reported"),
                    "status": _detail(usage.status),
                },
            )
        )
        reasoning = usage.reasoning_evidence
        if reasoning is not None:
            configured_role_policy = reasoning_policy.role_policy_for_request(usage.role)
            if (
                reasoning.request_plan.policy_artifact_sha256 != reasoning_policy.artifact_sha256
                or reasoning.request_plan.policy_role_binding_sha256
                != configured_role_policy.binding_sha256
                or reasoning.request_plan.control_profile != configured_role_policy.control
            ):
                raise ValueError(
                    "reasoning execution evidence differs from the effective configuration"
                )
            bindings.append(
                ManifestHashBinding(
                    identifier=f"reasoning/execution/{usage.request_id}",
                    sha256=reasoning.evidence_sha256,
                    details={
                        "role": _detail(usage.role),
                        "state": reasoning.state,
                        "profile_sha256": (reasoning.request_plan.control_profile.profile_sha256),
                        "reserved_reasoning_tokens": str(reasoning.reserved_reasoning_tokens),
                        "observed_reasoning_tokens": (
                            str(reasoning.observed_reasoning_tokens)
                            if reasoning.observation_available
                            else "unavailable"
                        ),
                    },
                )
            )
            capability_sha256 = reasoning.request_plan.endpoint_capability_sha256
            if capability_sha256 is not None:
                bindings.append(
                    ManifestHashBinding(
                        identifier=(f"reasoning/capability/{usage.request_id}"),
                        sha256=capability_sha256,
                        details={
                            "model": _detail(usage.requested_model),
                            "role": _detail(usage.role),
                        },
                    )
                )
            qualification_sha256 = reasoning.request_plan.qualification_binding_sha256
            if qualification_sha256 is not None:
                qualified_reasoning = (
                    _require_serialized_reasoning_qualification_for_verification(
                        usage=usage,
                        reasoning_policy=reasoning_policy,
                        validation=qualification_validation,
                    )
                    if sealed_verification_bindings is not None
                    else _require_opaque_reasoning_qualification(
                        usage=usage,
                        reasoning_policy=reasoning_policy,
                        validation=qualification_validation,
                        qualification=opaque_qualification,
                    )
                )
                bindings.append(
                    ManifestHashBinding(
                        identifier=(f"reasoning/qualification/{usage.request_id}"),
                        sha256=qualification_sha256,
                        details={
                            "model": _detail(usage.requested_model),
                            "role": _detail(usage.role),
                            "qualified_role": qualified_reasoning.qualified_role,
                            "configured_policy_role": (qualified_reasoning.configured_policy_role),
                            "authority": "opaque_production_qualification",
                            "qualification_verification_sha256": (
                                qualified_reasoning.qualification_verification_sha256
                            ),
                            "reasoning_benchmark_report_sha256": (
                                qualified_reasoning.reasoning_benchmark_report_sha256
                            ),
                            "reasoning_benchmark_verification_sha256": (
                                qualified_reasoning.reasoning_benchmark_verification_sha256
                            ),
                            "reasoning_benchmark_fresh_evidence_sha256": (
                                qualified_reasoning.reasoning_benchmark_fresh_evidence_sha256
                            ),
                        },
                    )
                )
    bindings.extend(
        _qualification_bindings(
            qualification_validation,
            opaque_authority_sha256=issuance_authority_sha256,
        )
    )
    return sorted(bindings, key=lambda item: item.identifier)


def _qualification_validation(
    payload: dict[str, Any] | None,
) -> ProductionQualificationValidation | None:
    """Parse a serialized projection without converting it into runtime authority."""

    if payload is None:
        return None
    # Local import avoids the registry -> qualification -> manifest import cycle.
    from mmaudit.models.registry import ProductionQualificationValidation

    return ProductionQualificationValidation.from_dict(payload)


def _serialized_issuance_authority_sha256(
    *,
    validation: ProductionQualificationValidation | None,
    sealed_bindings: list[ManifestHashBinding],
) -> str | None:
    """Validate, but never recreate, a sealed issuance-time authority projection."""

    by_identifier = {binding.identifier: binding for binding in sealed_bindings}
    runtime_binding = by_identifier.get("qualification/runtime-validation")
    opaque_binding = by_identifier.get("qualification/opaque-authority")
    if validation is None:
        if runtime_binding is not None or opaque_binding is not None:
            raise ValueError("sealed qualification authority projection lacks its runtime artifact")
        return None
    if runtime_binding is None or runtime_binding.sha256 != validation.validation_sha256:
        raise ValueError(
            "sealed qualification authority projection differs from runtime validation"
        )

    claimed_authority = runtime_binding.details.get("authority")
    route_bindings = [
        binding
        for identifier, binding in by_identifier.items()
        if identifier.startswith("qualification/reasoning-route/")
    ]
    if opaque_binding is None:
        if claimed_authority != "serialized_projection_only" or any(
            binding.details.get("authority") != "serialized_projection_only"
            for binding in route_bindings
        ):
            raise ValueError("sealed serialized qualification projection is inconsistent")
        return None

    capability_sha256 = validation.qualification_capability_sha256
    if (
        not validation.valid
        or capability_sha256 is None
        or opaque_binding.sha256 != capability_sha256
        or opaque_binding.details
        != {
            "kind": "process_local_opaque_capability",
            "serialized_projection_authority": "false",
        }
        or claimed_authority != "opaque_joined"
        or any(binding.details.get("authority") != "opaque_joined" for binding in route_bindings)
    ):
        raise ValueError("sealed opaque qualification issuance projection is inconsistent")
    return capability_sha256


def _validated_opaque_qualification(
    *,
    config: AuditConfig,
    validation: ProductionQualificationValidation | None,
    qualification: VerifiedProductionQualification | None,
) -> VerifiedProductionQualification | None:
    """Join a serialized runtime projection to resolver-issued opaque authority."""

    if qualification is None:
        return None
    if validation is None:
        raise ValueError(
            "opaque production qualification requires its serialized runtime projection"
        )

    # Local imports avoid manifest -> registry -> qualification -> manifest at module import.
    from mmaudit.models.qualification import VerifiedProductionQualification
    from mmaudit.models.registry import ModelRegistry

    if type(qualification) is not VerifiedProductionQualification:
        raise ValueError("production qualification authority has an invalid opaque type")
    opaque = qualification
    expected = ModelRegistry.validate_production_qualification(
        config,
        opaque,
        required=validation.required,
        now=validation.observed_at,
    )
    if not expected.valid:
        raise ValueError("opaque production qualification is not valid for the effective config")
    if expected != validation:
        raise ValueError(
            "serialized production qualification differs from opaque runtime authority"
        )
    return opaque.require_current(now=validation.observed_at)


def _require_serialized_reasoning_qualification_for_verification(
    *,
    usage: UsageRecord,
    reasoning_policy: ReasoningPolicyArtifact,
    validation: ProductionQualificationValidation | None,
) -> QualifiedReasoningRoleBinding:
    """Check sealed request evidence without creating or granting runtime authority."""

    if validation is None or not validation.valid:
        raise ValueError(
            "qualified reasoning verification requires valid serialized qualification evidence"
        )

    from mmaudit.models.reasoning import (
        ReasoningExecutionEvidence,
        ReasoningPolicyError,
        resolve_reasoning_request_role,
    )
    from mmaudit.models.usage import is_structurally_creditable_usage_record

    reasoning = usage.reasoning_evidence
    try:
        resolution = resolve_reasoning_request_role(usage.role)
    except ReasoningPolicyError as exc:
        raise ValueError("qualified reasoning request role cannot be resolved") from exc
    if (
        type(reasoning) is not ReasoningExecutionEvidence
        or reasoning.request_plan.resolution != resolution
        or reasoning.request_plan.binding_state != "qualification_bound"
        or not is_structurally_creditable_usage_record(
            usage,
            require_real=True,
            require_certification=True,
        )
    ):
        raise ValueError("qualified reasoning request is not creditable sealed real evidence")
    plan = reasoning.request_plan

    serialized_models = tuple(
        model
        for model in validation.model_bindings
        if model.exact_model_id == usage.requested_model
    )
    if len(serialized_models) != 1:
        raise ValueError("qualified reasoning request lacks one serialized model binding")
    model = serialized_models[0]
    routes = tuple(
        route
        for route in model.reasoning_bindings
        if route.qualified_role == resolution.qualification_role
        and route.configured_policy_role == resolution.configured_policy_role
    )
    if len(routes) != 1:
        raise ValueError("qualified reasoning request lacks one serialized role route")
    route = routes[0]
    policy_role = reasoning_policy.role_policy(resolution.configured_policy_role)
    endpoint_capability_sha256 = plan.endpoint_capability_sha256
    qualification_verification_sha256 = validation.qualification_verification_sha256
    if endpoint_capability_sha256 is None or qualification_verification_sha256 is None:
        raise ValueError("qualified reasoning request lacks serialized parent evidence")
    route = route.require_exact(
        exact_model_id=usage.requested_model,
        approved_provider_endpoint=model.approved_provider_endpoint,
        approved_provider_name=model.approved_provider_name,
        qualified_role=resolution.qualification_role,
        configured_policy_role=resolution.configured_policy_role,
        control_profile=policy_role.control,
        reasoning_policy_artifact_sha256=reasoning_policy.artifact_sha256,
        reasoning_policy_role_binding_sha256=policy_role.binding_sha256,
        endpoint_reasoning_capability_sha256=endpoint_capability_sha256,
        reasoning_benchmark_report_sha256=route.reasoning_benchmark_report_sha256,
        reasoning_benchmark_verification_sha256=(route.reasoning_benchmark_verification_sha256),
        reasoning_benchmark_fresh_evidence_sha256=(route.reasoning_benchmark_fresh_evidence_sha256),
        qualification_report_sha256=model.benchmark_report_sha256,
        qualification_result_sha256=model.qualification_result_sha256,
        qualification_verification_sha256=qualification_verification_sha256,
    )
    if plan.qualification_binding_sha256 != route.binding_sha256:
        raise ValueError("qualified reasoning request differs from its serialized role route")

    request_time = usage.started_at or usage.timestamp
    if request_time.tzinfo is None or request_time.utcoffset() != timedelta(0):
        raise ValueError("qualified reasoning request time must be UTC")
    request_time = request_time.astimezone(UTC).replace(microsecond=0)
    verified_at_raw = usage.routing.get("qualification_verified_at")
    if not isinstance(verified_at_raw, str):
        raise ValueError("qualified reasoning request lacks its sealed verification time")
    try:
        verified_at = datetime.fromisoformat(verified_at_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("qualified reasoning verification time is invalid") from exc
    if verified_at.tzinfo is None or verified_at.utcoffset() != timedelta(0):
        raise ValueError("qualified reasoning verification time must be UTC")
    verified_at = verified_at.astimezone(UTC).replace(microsecond=0)
    if (
        verified_at < model.evaluated_at
        or verified_at > validation.observed_at
        or request_time < verified_at
        or request_time >= model.expires_at
    ):
        raise ValueError("qualified reasoning request is outside its serialized authority window")

    if (
        usage.returned_model not in {model.exact_model_id, model.canonical_model_slug}
        or usage.actual_model not in {model.exact_model_id, model.canonical_model_slug}
        or usage.actual_provider_endpoint != model.approved_provider_endpoint
        or usage.routing.get("selected_provider_name") != model.approved_provider_name
    ):
        raise ValueError("qualified reasoning execution differs from its serialized provider")
    expected_routing: dict[str, Any] = {
        "qualified_exact_model_id": model.exact_model_id,
        "qualified_canonical_model_slug": model.canonical_model_slug,
        "qualified_root_lineage": model.root_lineage,
        "qualified_provider_endpoint": model.approved_provider_endpoint,
        "qualified_provider_name": model.approved_provider_name,
        "qualified_endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
        "qualified_output_capability_sha256": model.output_capability_sha256,
        "qualified_structured_output_mode": model.structured_output_mode.value,
        "qualified_model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
        "qualified_pricing_snapshot_sha256": model.pricing_snapshot_sha256,
        "qualified_roles": list(model.approved_roles),
        "qualification_verified_at": verified_at.isoformat(),
        "qualification_expires_at": model.expires_at.isoformat(),
        "qualification_artifact_sha256": validation.qualification_artifact_sha256,
        "qualification_verification_sha256": qualification_verification_sha256,
        "production_selection_sha256": validation.production_selection_sha256,
        "selection_verification_sha256": validation.selection_verification_sha256,
        "qualification_result_sha256": model.qualification_result_sha256,
        "benchmark_report_sha256": model.benchmark_report_sha256,
        "qualified_reasoning_binding_sha256": [
            binding.binding_sha256 for binding in model.reasoning_bindings
        ],
    }
    if any(usage.routing.get(key) != value for key, value in expected_routing.items()):
        raise ValueError(
            "qualified reasoning execution differs from its sealed qualification projection"
        )
    return route


def _require_opaque_reasoning_qualification(
    *,
    usage: UsageRecord,
    reasoning_policy: ReasoningPolicyArtifact,
    validation: ProductionQualificationValidation | None,
    qualification: VerifiedProductionQualification | None,
) -> QualifiedReasoningRoleBinding:
    """Require one exact request-to-role-to-parent join before granting manifest credit."""

    if validation is None or not validation.valid:
        raise ValueError(
            "qualified reasoning manifest credit requires valid production qualification evidence"
        )
    if qualification is None:
        raise ValueError(
            "qualified reasoning manifest credit requires opaque production qualification authority"
        )

    from mmaudit.models.qualification import usage_matches_verified_reasoning_qualification

    plan = usage.reasoning_evidence.request_plan if usage.reasoning_evidence is not None else None
    if plan is None or plan.binding_state != "qualification_bound":
        raise ValueError("qualified reasoning manifest credit requires a qualification-bound plan")
    resolution = plan.resolution
    request_time = usage.started_at or usage.timestamp
    if request_time.tzinfo is None or request_time.utcoffset() != timedelta(0):
        raise ValueError("qualified reasoning request time must be UTC")
    normalized_request_time = request_time.astimezone(UTC).replace(microsecond=0)
    qualified_model = qualification.model_for(
        usage.requested_model,
        now=normalized_request_time,
    )
    if request_time < qualification.verified_at or request_time >= qualified_model.expires_at:
        raise ValueError("qualified reasoning request occurred outside its authority window")
    if not usage_matches_verified_reasoning_qualification(
        record=usage,
        production_qualification=qualification,
        now=normalized_request_time,
    ):
        raise ValueError(
            "qualified reasoning execution lacks creditable real opaque-authority evidence"
        )
    serialized_models = tuple(
        model
        for model in validation.model_bindings
        if model.exact_model_id == usage.requested_model
    )
    if len(serialized_models) != 1:
        raise ValueError("qualified reasoning request lacks one serialized model binding")
    serialized_model = serialized_models[0]
    authority_routes = tuple(
        route
        for route in qualified_model.reasoning_bindings
        if route.qualified_role == resolution.qualification_role
        and route.configured_policy_role == resolution.configured_policy_role
    )
    serialized_routes = tuple(
        route
        for route in serialized_model.reasoning_bindings
        if route.qualified_role == resolution.qualification_role
        and route.configured_policy_role == resolution.configured_policy_role
    )
    if len(authority_routes) != 1 or len(serialized_routes) != 1:
        raise ValueError("qualified reasoning request lacks one exact role route")
    authority_route = authority_routes[0]
    serialized_route = serialized_routes[0]
    if serialized_route != authority_route:
        raise ValueError("serialized reasoning route differs from opaque production authority")

    policy_role = reasoning_policy.role_policy(resolution.configured_policy_role)
    endpoint_capability_sha256 = plan.endpoint_capability_sha256
    if endpoint_capability_sha256 is None:
        raise ValueError("qualified reasoning request lacks endpoint capability evidence")
    authority_route = authority_route.require_exact(
        exact_model_id=usage.requested_model,
        approved_provider_endpoint=qualified_model.approved_provider_endpoint,
        approved_provider_name=qualified_model.approved_provider_name,
        qualified_role=resolution.qualification_role,
        configured_policy_role=resolution.configured_policy_role,
        control_profile=policy_role.control,
        reasoning_policy_artifact_sha256=reasoning_policy.artifact_sha256,
        reasoning_policy_role_binding_sha256=policy_role.binding_sha256,
        endpoint_reasoning_capability_sha256=endpoint_capability_sha256,
        reasoning_benchmark_report_sha256=(authority_route.reasoning_benchmark_report_sha256),
        reasoning_benchmark_verification_sha256=(
            authority_route.reasoning_benchmark_verification_sha256
        ),
        reasoning_benchmark_fresh_evidence_sha256=(
            authority_route.reasoning_benchmark_fresh_evidence_sha256
        ),
        qualification_report_sha256=qualified_model.benchmark_report_sha256,
        qualification_result_sha256=qualified_model.qualification_result_sha256,
        qualification_verification_sha256=(qualification.qualification_verification_sha256),
    )
    if plan.qualification_binding_sha256 != authority_route.binding_sha256:
        raise ValueError("reasoning request plan differs from its opaque qualification route")
    if (
        usage.actual_provider_endpoint != qualified_model.approved_provider_endpoint
        or usage.routing.get("selected_provider_name") != qualified_model.approved_provider_name
    ):
        raise ValueError("qualified reasoning execution differs from its approved provider")

    expected_routing: dict[str, Any] = {
        "qualified_exact_model_id": qualified_model.exact_model_id,
        "qualified_canonical_model_slug": qualified_model.canonical_model_slug,
        "qualified_root_lineage": qualified_model.root_lineage,
        "qualified_provider_endpoint": qualified_model.approved_provider_endpoint,
        "qualified_provider_name": qualified_model.approved_provider_name,
        "qualified_endpoint_snapshot_sha256": qualified_model.endpoint_snapshot_sha256,
        "qualified_output_capability_sha256": qualified_model.output_capability_sha256,
        "qualified_structured_output_mode": qualified_model.structured_output_mode.value,
        "qualified_model_metadata_snapshot_sha256": (
            qualified_model.model_metadata_snapshot_sha256
        ),
        "qualified_pricing_snapshot_sha256": qualified_model.pricing_snapshot_sha256,
        "qualified_roles": list(qualified_model.approved_roles),
        "qualification_verified_at": qualification.verified_at.isoformat(),
        "qualification_expires_at": qualified_model.expires_at.isoformat(),
        "qualification_artifact_sha256": qualification.artifact_sha256,
        "qualification_verification_sha256": (qualification.qualification_verification_sha256),
        "production_selection_sha256": qualification.production_selection_sha256,
        "selection_verification_sha256": qualification.selection_verification_sha256,
        "qualification_result_sha256": qualified_model.qualification_result_sha256,
        "benchmark_report_sha256": qualified_model.benchmark_report_sha256,
        "qualified_reasoning_binding_sha256": [
            route.binding_sha256 for route in qualified_model.reasoning_bindings
        ],
    }
    if any(usage.routing.get(key) != value for key, value in expected_routing.items()):
        raise ValueError(
            "qualified reasoning execution routing differs from opaque production authority"
        )
    return authority_route


def _qualification_bindings(
    validation: ProductionQualificationValidation | None,
    *,
    opaque_authority_sha256: str | None,
) -> list[ManifestHashBinding]:
    if validation is None:
        if opaque_authority_sha256 is not None:
            raise ValueError("opaque qualification authority lacks a serialized projection")
        return [
            _binding(
                "qualification/runtime-absent",
                {"present": False},
                {"state": "not_emitted"},
            )
        ]

    bindings = [
        ManifestHashBinding(
            identifier="qualification/runtime-validation",
            sha256=validation.validation_sha256,
            details={
                "valid": str(validation.valid).lower(),
                "required": str(validation.required).lower(),
                "configured_models": str(len(validation.configured_model_ids)),
                "qualified_models": str(len(validation.qualified_model_ids)),
                "authority": (
                    "opaque_joined"
                    if opaque_authority_sha256 is not None
                    else "serialized_projection_only"
                ),
            },
        )
    ]
    if opaque_authority_sha256 is not None:
        if opaque_authority_sha256 != validation.qualification_capability_sha256:
            raise ValueError("opaque qualification capability differs from runtime projection")
        bindings.append(
            ManifestHashBinding(
                identifier="qualification/opaque-authority",
                sha256=opaque_authority_sha256,
                details={
                    "kind": "process_local_opaque_capability",
                    "serialized_projection_authority": "false",
                },
            )
        )
    named_hashes = {
        "artifact": validation.qualification_artifact_sha256,
        "verification": validation.qualification_verification_sha256,
        "candidate-registry": validation.candidate_registry_sha256,
        "policy": validation.qualification_policy_sha256,
        "expected-bindings": validation.expected_bindings_sha256,
        "release-observation": validation.release_observation_sha256,
        "production-effective-config": validation.production_effective_config_sha256,
        "production-selection": validation.production_selection_sha256,
        "selection-verification": validation.selection_verification_sha256,
        "capability": validation.qualification_capability_sha256,
    }
    bindings.extend(
        ManifestHashBinding(
            identifier=f"qualification/{name}",
            sha256=value,
            details={"kind": name},
        )
        for name, value in sorted(named_hashes.items())
        if value is not None
    )
    for index, model in enumerate(validation.model_bindings):
        common_details = {
            "model": _detail(model.exact_model_id),
            "root_lineage": model.root_lineage,
            "provider_endpoint": _detail(model.approved_provider_endpoint),
            "structured_output_mode": model.structured_output_mode.value,
            "benchmark_case_count": str(model.benchmark_case_count),
            "evaluated_at": model.evaluated_at.isoformat(),
            "expires_at": model.expires_at.isoformat(),
        }
        model_hashes = {
            "result": model.qualification_result_sha256,
            "benchmark-report": model.benchmark_report_sha256,
            "benchmark-verification": model.benchmark_verification_sha256,
            "fresh-benchmark-evidence": model.fresh_benchmark_evidence_sha256,
            "endpoint-snapshot": model.endpoint_snapshot_sha256,
            "output-capability": model.output_capability_sha256,
            "model-metadata-snapshot": model.model_metadata_snapshot_sha256,
            "pricing-snapshot": model.pricing_snapshot_sha256,
        }
        bindings.extend(
            ManifestHashBinding(
                identifier=f"qualification/{kind}/{index:05d}",
                sha256=sha256,
                details={**common_details, "kind": kind},
            )
            for kind, sha256 in sorted(model_hashes.items())
        )
        bindings.extend(
            ManifestHashBinding(
                identifier=(f"qualification/reasoning-route/{index:05d}/{route_index:05d}"),
                sha256=route.binding_sha256,
                details={
                    **common_details,
                    "kind": "reasoning_route",
                    "qualified_role": route.qualified_role,
                    "configured_policy_role": route.configured_policy_role,
                    "control_profile_sha256": route.control_profile_sha256,
                    "reasoning_policy_artifact_sha256": (route.reasoning_policy_artifact_sha256),
                    "reasoning_policy_role_binding_sha256": (
                        route.reasoning_policy_role_binding_sha256
                    ),
                    "endpoint_reasoning_capability_sha256": (
                        route.endpoint_reasoning_capability_sha256
                    ),
                    "reasoning_benchmark_report_sha256": (route.reasoning_benchmark_report_sha256),
                    "reasoning_benchmark_verification_sha256": (
                        route.reasoning_benchmark_verification_sha256
                    ),
                    "reasoning_benchmark_fresh_evidence_sha256": (
                        route.reasoning_benchmark_fresh_evidence_sha256
                    ),
                    "qualification_report_sha256": route.qualification_report_sha256,
                    "qualification_result_sha256": route.qualification_result_sha256,
                    "qualification_verification_sha256": (route.qualification_verification_sha256),
                    "authority": (
                        "opaque_joined"
                        if opaque_authority_sha256 is not None
                        else "serialized_projection_only"
                    ),
                },
            )
            for route_index, route in enumerate(model.reasoning_bindings)
        )
    qualification_inputs = validation.qualification_bindings
    if qualification_inputs is not None:
        input_hashes = {
            "source-tree": (
                qualification_inputs.source_tree_sha256,
                {"source_commit": qualification_inputs.source_commit},
            ),
            "effective-config": (
                qualification_inputs.effective_config_sha256,
                {"kind": "effective_config"},
            ),
            "benchmark-prompt": (
                qualification_inputs.prompt_sha256,
                {"kind": "prompt_set"},
            ),
            "response-schema": (
                qualification_inputs.response_schema_sha256,
                {"kind": "structured_output_schema"},
            ),
            "toolchain": (
                qualification_inputs.toolchain_sha256,
                {"kind": "toolchain"},
            ),
            "isolation": (
                qualification_inputs.isolation_sha256,
                {"kind": "isolation"},
            ),
            "benchmark-corpus": (
                qualification_inputs.benchmark_corpus_sha256,
                {"version": qualification_inputs.benchmark_corpus_version},
            ),
            "benchmark-ground-truth": (
                qualification_inputs.benchmark_ground_truth_sha256,
                {"version": qualification_inputs.benchmark_ground_truth_version},
            ),
            "benchmark-portfolio": (
                qualification_inputs.benchmark_portfolio_sha256,
                {"kind": "all_candidates"},
            ),
        }
        bindings.extend(
            ManifestHashBinding(
                identifier=f"qualification/input/{name}",
                sha256=sha256,
                details=details,
            )
            for name, (sha256, details) in sorted(input_hashes.items())
        )
    return sorted(bindings, key=lambda item: item.identifier)


def build_manifest_tool_bindings(
    config: AuditConfig,
    report: AuditReport,
) -> list[ManifestHashBinding]:
    """Reconstruct the exact configured and observed tool binding inventory."""

    bindings = [
        _binding(
            "configured/scanners",
            config.scanners.model_dump(mode="json"),
            {"kind": "scanner_configuration"},
        )
    ]
    for index, scanner in enumerate(report.scanner_runs):
        bindings.append(
            _binding(
                f"scanner/{index:05d}",
                scanner.model_dump(mode="json"),
                {
                    "name": _detail(scanner.scanner),
                    "status": scanner.status.value,
                    "version": _detail(scanner.version or "unavailable"),
                    "executable_sha256": _detail(
                        scanner.executable_sha256
                        or (
                            "bound_by_isolation_image"
                            if scanner.repository_code_execution.value == "isolated"
                            else "not_recorded"
                        )
                    ),
                },
            )
        )
    for index, run in enumerate(report.formal_runs):
        bindings.append(
            _binding(
                f"formal/{index:05d}",
                run.model_dump(mode="json"),
                {
                    "name": _detail(run.tool),
                    "status": run.status.value,
                    "version": _detail(run.version or "unavailable"),
                    "executable_sha256": _detail(run.executable_sha256 or "unavailable"),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _tool_bindings(
    config: AuditConfig,
    report: AuditReport,
) -> list[ManifestHashBinding]:
    """Retain the internal verifier seam while sharing the exact public reconstruction."""

    return build_manifest_tool_bindings(config, report)


def _compiler_bindings(
    config: AuditConfig,
    compilation: dict[str, Any],
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "configured/solidity",
            config.smart_contracts.model_dump(mode="json"),
            {
                "compile": str(config.smart_contracts.compile).lower(),
                "framework": config.smart_contracts.framework,
            },
        )
    ]
    for index, result in enumerate(_object_list(compilation, "results")):
        bindings.append(
            _binding(
                f"result/{index:05d}",
                result,
                {
                    "framework": _detail(result.get("framework")),
                    "project_root": _detail(result.get("project_root")),
                    "status": _detail(result.get("status")),
                    "executable_sha256": _detail(
                        result.get("executable_sha256")
                        or (
                            "bound_by_isolation_image"
                            if result.get("repository_code_execution") == "isolated"
                            else "not_recorded"
                        )
                    ),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _isolation_bindings(
    config: AuditConfig,
    report: AuditReport,
    compilation: dict[str, Any],
) -> list[ManifestHashBinding]:
    configured = {
        "backend": config.reproduction.isolation_backend,
        "runtime": config.reproduction.rootless_container_runtime,
        "image": config.reproduction.rootless_container_image,
        "require_hardened": config.reproduction.require_hardened_isolation,
    }
    observed = [
        {
            "kind": "scanner",
            "name": run.scanner,
            "backend": run.isolation_backend,
            "repository_code_execution": run.repository_code_execution.value,
        }
        for run in report.scanner_runs
    ]
    observed.extend(
        {
            "kind": "compiler",
            "name": str(result.get("framework", "unknown")),
            "backend": result.get("isolation_backend"),
            "repository_code_execution": result.get("repository_code_execution"),
        }
        for result in _object_list(compilation, "results")
    )
    observed.extend(
        {
            "kind": "invariant",
            "name": result.harness_name,
            "backend": result.isolation_backend,
        }
        for result in report.invariant_executions
    )
    observed.extend(
        {
            "kind": "reproduction",
            "name": result.test_name,
            "backend": result.isolation_backend,
        }
        for result in report.reproductions
    )
    observed.extend(
        {
            "kind": "formal",
            "name": result.tool,
            "backend": result.isolation_backend,
        }
        for result in report.formal_runs
    )
    return [
        _binding(
            "configured/boundary",
            configured,
            {
                "backend": config.reproduction.isolation_backend,
                "image": _detail(config.reproduction.rootless_container_image or "not_configured"),
            },
        ),
        _binding(
            "observed/boundaries",
            observed,
            {"records": str(len(observed))},
        ),
    ]


def _seed_bindings(*artifacts: dict[str, Any]) -> list[ManifestHashBinding]:
    extracted: list[tuple[str, int | str]] = []
    for artifact_index, artifact in enumerate(artifacts):
        _extract_seed_values(
            artifact,
            path=f"artifact-{artifact_index}",
            output=extracted,
        )
    bindings = [
        _binding(
            "seed-set",
            extracted,
            {"count": str(len(extracted))},
        )
    ]
    for index, (path, value) in enumerate(extracted):
        bindings.append(
            _binding(
                f"seed/{index:05d}",
                {"path": path, "value": value},
                {"field": _detail(path), "value": _detail(value)},
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _corpus_bindings(property_corpus: dict[str, Any]) -> list[ManifestHashBinding]:
    corpus = property_corpus.get("corpus")
    corpus_object = corpus if isinstance(corpus, dict) else {}
    corpus_hash = corpus_object.get("corpus_hash")
    digest = (
        corpus_hash
        if isinstance(corpus_hash, str)
        and len(corpus_hash) == 64
        and all(character in "0123456789abcdef" for character in corpus_hash)
        else canonical_sha256(corpus_object)
    )
    properties = corpus_object.get("properties", [])
    return sorted(
        [
            ManifestHashBinding(
                identifier="property-corpus/content",
                sha256=digest,
                details={
                    "properties": str(len(properties) if isinstance(properties, list) else 0),
                },
            ),
            _binding(
                "property-corpus/artifact",
                property_corpus,
                {"artifact": "property-corpus.json"},
            ),
        ],
        key=lambda item: item.identifier,
    )


def _harness_bindings(
    harness_plan: dict[str, Any],
    invariant_results: dict[str, Any],
    reproduction_results: dict[str, Any],
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "invariant-plan/artifact",
            harness_plan,
            {"artifact": "invariant-harness-plan.json"},
        ),
        _binding(
            "invariant-results/artifact",
            invariant_results,
            {"artifact": "invariant-execution-results.json"},
        ),
        _binding(
            "reproduction-specifications/artifact",
            reproduction_results.get("test_specifications", []),
            {"artifact": "reproduction-results.json"},
        ),
    ]
    for index, harness in enumerate(_object_list(harness_plan, "harnesses")):
        bindings.append(
            _binding(
                f"invariant/{index:05d}",
                harness,
                {
                    "name": _detail(harness.get("name")),
                    "invariant_id": _detail(harness.get("invariant_id")),
                },
            )
        )
    for index, specification in enumerate(
        _object_list(reproduction_results, "test_specifications")
    ):
        bindings.append(
            _binding(
                f"reproduction/{index:05d}",
                specification,
                {"name": _detail(specification.get("name"))},
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _reproduction_bindings(
    reproduction_results: dict[str, Any],
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "results/artifact",
            reproduction_results,
            {"artifact": "reproduction-results.json"},
        )
    ]
    for index, result in enumerate(_object_list(reproduction_results, "results")):
        bindings.append(
            _binding(
                f"result/{index:05d}",
                result,
                {
                    "candidate_id": _detail(result.get("candidate_id")),
                    "state": _detail(result.get("state")),
                    "specification_sha256": _detail(result.get("specification_sha256")),
                    "generated_test_sha256": _detail(
                        result.get("generated_test_sha256") or "not_generated"
                    ),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _coverage_bindings(
    report: AuditReport,
    solidity_coverage: dict[str, Any],
    model_coverage: dict[str, Any],
    scope_assessment: dict[str, Any],
    context_manifest: ContextManifest | None,
    scheduler_artifact: SchedulerArtifact | None,
    *,
    legacy_schema_1_1: bool = False,
) -> list[ManifestHashBinding]:
    status_projection = effective_report_status(report)
    projected_quality_gates = (
        list(report.quality_gates) if legacy_schema_1_1 else status_projection.quality_gates
    )
    bindings = [
        _binding(
            "model-review/artifact",
            model_coverage,
            {"artifact": "model-review-coverage.json"},
        ),
        _binding(
            "quality-gates/report",
            [gate.model_dump(mode="json") for gate in projected_quality_gates],
            {"gates": str(len(projected_quality_gates))},
        ),
        _binding(
            "scope/artifact",
            scope_assessment,
            {"artifact": "scope-assessment.json"},
        ),
        _binding(
            "solidity/artifact",
            solidity_coverage,
            {"artifact": "solidity-coverage.json"},
        ),
    ]
    if not legacy_schema_1_1:
        bindings.append(
            _binding(
                "report-status/projection",
                status_projection.model_dump(mode="json"),
                {
                    "run_status": status_projection.run_status.value,
                    "quality_status": status_projection.quality_status.value,
                },
            )
        )
    if context_manifest is None:
        bindings.append(
            _binding(
                "context-manifest/absent",
                {"present": False},
                {"state": "legacy_without_model_usage"},
            )
        )
    else:
        bindings.append(
            ManifestHashBinding(
                identifier="context-manifest/artifact",
                sha256=context_manifest.manifest_sha256,
                details={
                    "artifact": "context-manifest.json",
                    "requests": str(context_manifest.totals.request_count),
                    "provider_reported_requests": str(
                        context_manifest.totals.provider_reported_request_count
                    ),
                },
            )
        )
    if scheduler_artifact is None:
        bindings.append(
            _binding(
                "scheduler/absent",
                {"present": False},
                {"state": "legacy_without_scheduler_evidence"},
            )
        )
    else:
        summary = scheduler_artifact.summary
        bindings.append(
            ManifestHashBinding(
                identifier="scheduler/artifact",
                sha256=scheduler_artifact.artifact_sha256,
                details={
                    "artifact": "scheduler-state.json",
                    "status": summary.status.value,
                    "passes": str(len(summary.pass_results)),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _binding(
    identifier: str,
    payload: Any,
    details: dict[str, str],
) -> ManifestHashBinding:
    return ManifestHashBinding(
        identifier=identifier,
        sha256=canonical_sha256(payload),
        details=details,
    )


def _extract_seed_values(
    value: Any,
    *,
    path: str,
    output: list[tuple[str, int | str]],
) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            child = value[key]
            child_path = f"{path}/{key}"
            if key in {"seed", "campaign_seed", "fuzz_seed"} and isinstance(
                child,
                (int, str),
            ):
                output.append((child_path, child))
            _extract_seed_values(child, path=child_path, output=output)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _extract_seed_values(child, path=f"{path}/{index}", output=output)


def _collect_artifacts(run_dir: Path) -> list[ManifestFileBinding]:
    artifacts: list[ManifestFileBinding] = []
    total_bytes = 0
    for candidate in sorted(run_dir.rglob("*"), key=lambda path: path.as_posix()):
        relative = normalize_relative_path(candidate.relative_to(run_dir))
        if relative == "run-evidence-manifest.json":
            continue
        try:
            candidate_metadata = candidate.lstat()
        except OSError as exc:
            raise ValueError("run artifact is unavailable") from exc
        if stat.S_ISLNK(candidate_metadata.st_mode) or candidate.is_junction():
            raise ValueError("run artifacts may not contain links")
        is_directory = stat.S_ISDIR(candidate_metadata.st_mode)
        if is_sensitive_workspace_path(relative, is_dir=is_directory):
            raise ValueError("run artifacts may not include sensitive filenames")
        if is_directory:
            continue
        remaining_bytes = _MAX_MANIFEST_BYTES - total_bytes
        file_sha256, file_size = _file_sha256(candidate, max_bytes=remaining_bytes)
        total_bytes += file_size
        if len(artifacts) + 1 > _MAX_MANIFEST_FILES:
            raise ValueError("run artifact manifest limits were exceeded")
        artifacts.append(
            ManifestFileBinding(
                path=relative,
                sha256=file_sha256,
                size=file_size,
            )
        )
    if not artifacts:
        raise ValueError("run evidence manifest requires at least one artifact")
    return artifacts


def _file_sha256(path: Path, *, max_bytes: int) -> tuple[str, int]:
    """Hash one bounded artifact through a stable non-link file descriptor."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError("run artifact is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes:
        raise ValueError("run artifacts must be bounded unique regular files")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    size = 0
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("run artifact could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        while True:
            remaining = max_bytes - size
            chunk = os.read(descriptor, min(1024 * 1024, remaining + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("run artifact manifest limits were exceeded")
            digest.update(chunk)
        finished = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError("run artifact could not be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("run artifact changed while it was hashed") from exc
    identities = {
        _artifact_stat_identity(before),
        _artifact_stat_identity(opened),
        _artifact_stat_identity(finished),
        _artifact_stat_identity(after),
    }
    if (
        len(identities) != 1
        or not stat.S_ISREG(finished.st_mode)
        or finished.st_nlink != 1
        or finished.st_size != size
    ):
        raise ValueError("run artifact changed while it was hashed")
    return digest.hexdigest(), size


def _artifact_stat_identity(
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


def _read_json_artifact(
    run_dir: Path,
    name: str,
    *,
    expected_binding: ManifestFileBinding | None = None,
) -> dict[str, Any]:
    with _open_json_artifact_observation(
        run_dir,
        name,
        expected_binding=expected_binding,
    ) as payload:
        return payload


@contextmanager
def _open_json_artifact_observation(
    run_dir: Path,
    name: str,
    *,
    expected_binding: ManifestFileBinding | None = None,
    max_bytes: int = _MAX_JSON_ARTIFACT_BYTES,
) -> Iterator[dict[str, Any]]:
    """Hold one stable no-follow artifact descriptor across semantic validation."""

    normalized = normalize_relative_path(name)
    path = run_dir / normalized
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"run JSON artifact may not be a link: {name}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(run_dir)
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"run JSON artifact is unavailable: {name}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > max_bytes:
        raise ValueError(f"run JSON artifact is not a bounded unique regular file: {name}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"run JSON artifact could not be opened safely: {name}") from exc
    chunks: list[bytes] = []
    size = 0
    try:
        try:
            opened = os.fstat(descriptor)
            while True:
                remaining = max_bytes - size
                chunk = os.read(descriptor, min(1024 * 1024, remaining + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError(f"run JSON artifact exceeds its byte limit: {name}")
                chunks.append(chunk)
            finished = os.fstat(descriptor)
            after_read = path.lstat()
            if (
                len(
                    {
                        _artifact_stat_identity(before),
                        _artifact_stat_identity(opened),
                        _artifact_stat_identity(finished),
                        _artifact_stat_identity(after_read),
                    }
                )
                != 1
                or not stat.S_ISREG(finished.st_mode)
                or finished.st_nlink != 1
                or finished.st_size != size
                or path.resolve(strict=True) != resolved
            ):
                raise ValueError(f"run JSON artifact changed while it was read: {name}")
            content = b"".join(chunks)
            if expected_binding is not None and (
                expected_binding.path != normalized
                or expected_binding.size != len(content)
                or expected_binding.sha256 != hashlib.sha256(content).hexdigest()
            ):
                raise ValueError(f"run JSON artifact differs from its sealed binding: {name}")
            payload = _parse_json_artifact_content(content, name=name)
        except OSError as exc:
            raise ValueError(f"run JSON artifact could not be read safely: {name}") from exc

        try:
            yield payload
        finally:
            try:
                after_validation = path.lstat()
                descriptor_after = os.fstat(descriptor)
                current_resolved = path.resolve(strict=True)
            except OSError as exc:
                raise ValueError(
                    f"run JSON artifact changed during semantic validation: {name}"
                ) from exc
            if (
                len(
                    {
                        _artifact_stat_identity(before),
                        _artifact_stat_identity(descriptor_after),
                        _artifact_stat_identity(after_validation),
                    }
                )
                != 1
                or current_resolved != resolved
                or path.is_symlink()
                or path.is_junction()
            ):
                raise ValueError(f"run JSON artifact changed during semantic validation: {name}")
    finally:
        os.close(descriptor)


def _parse_json_artifact_content(content: bytes, *, name: str) -> dict[str, Any]:
    """Decode one unique finite UTF-8 JSON object from already-held bytes."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"run JSON artifact contains duplicate keys: {name}")
            result[key] = value
        return result

    def reject_nonfinite(_value: str) -> None:
        raise ValueError(f"run JSON artifact contains a non-finite value: {name}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError(f"run JSON artifact contains an out-of-range number: {name}")
        return parsed

    try:
        payload = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"run JSON artifact is not valid UTF-8 JSON: {name}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"run JSON artifact must contain an object: {name}")
    return payload


def _object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key, [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _detail(value: object) -> str:
    rendered = "none" if value is None else str(value)
    sanitized = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else "\ufffd"
        for character in rendered
    )
    return sanitized[:2_000]
