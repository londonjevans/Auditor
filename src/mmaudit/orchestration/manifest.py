"""Deterministic hash-linked evidence manifests for completed local runs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from decimal import Decimal
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    canonical_audit_config_json,
    parse_canonical_audit_config,
)
from mmaudit.constants import ALL_MODEL_ROLES, VERSION
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    AuditRunStatus,
    CandidateFindingArtifact,
    CandidateOriginKind,
    CandidateReproductionResolution,
    ExecutionOriginDispositionKind,
    FalsificationDecision,
    FindingOriginKind,
    FindingStatus,
    FoundryInvariantHarnessSpec,
    GeneratedFoundryTestSpec,
    InvariantExecutionOriginDispositionArtifact,
    InvariantExecutionResult,
    MaximumAssuranceStatus,
    PropertyCorpus,
    ReproductionIntegrityStatus,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    Severity,
    StrictModel,
)
from mmaudit.models.token_planning import PromptAllocationCategory, RequestTokenPlan
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
from mmaudit.reporting.json_report import write_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name, is_sensitive_workspace_path

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_MANIFEST_FILES = 100_000
_MAX_MANIFEST_BYTES = 4 * 1024**3
_MAX_JSON_ARTIFACT_BYTES = 100_000_000


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
        if (
            self.achieved_profile is not None
            and self.achieved_profile is not self.requested_profile
        ):
            raise ValueError("run cannot claim an unrequested achieved profile")
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

    schema_version: Literal["1.0", "1.1"] = "1.1"
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
        if (self.schema_version == "1.1") != (self.run_configuration is not None):
            raise ValueError("manifest 1.1 requires run configuration provenance")
        source_paths = [binding.path for binding in self.sources]
        if source_paths != sorted(set(source_paths)):
            raise ValueError("manifest source paths must be unique and sorted")
        artifact_paths = [binding.path for binding in self.artifacts]
        if artifact_paths != sorted(set(artifact_paths)):
            raise ValueError("manifest artifact paths must be unique and sorted")
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
    tool_version: str = VERSION,
) -> RunEvidenceManifest:
    """Sort and self-hash an otherwise complete manifest payload."""

    ordered_sources = sorted(sources, key=lambda item: item.path)
    ordered_artifacts = sorted(artifacts, key=lambda item: item.path)
    payload: dict[str, Any] = {
        "schema_version": "1.1",
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
) -> RunEvidenceManifest:
    """Build all MAN-001 projections from typed runtime state and emitted artifacts."""

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
    _validate_report_artifact_consistency(root, report)
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

    bindings = ManifestBindingSet(
        configuration=_configuration_bindings(effective_config),
        prompts=_prompt_bindings(report),
        models=_model_bindings(
            effective_config,
            report,
            qualification_runtime=qualification_runtime,
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
        ),
    )
    return seal_run_evidence_manifest(
        run_id=report.run_id,
        repository_root_name=report.repository.root_name,
        git_commit=report.repository.git_commit,
        sources=sources,
        run_configuration=run_configuration,
        bindings=bindings,
        artifacts=_collect_artifacts(root),
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
    post_judgment_execution_ids: set[str] = set()
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
        elevated_ids = contributing_execution_ids - high_critical_candidate_ids
        if not elevated_ids:
            continue
        post_judgment_execution_ids.update(elevated_ids)
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


def _validate_report_artifact_consistency(root: Path, report: AuditReport) -> None:
    """Require emitted report summaries to agree before sealing their byte hashes."""

    metadata = _read_json_artifact(root, "metadata.json")
    if metadata.get("privacy") != report.privacy:
        raise ValueError("metadata.json privacy differs from the final report")
    embedded_metadata = metadata.get("metadata")
    if not isinstance(embedded_metadata, dict):
        raise ValueError("metadata.json lacks typed report metadata")
    if embedded_metadata.get("context_manifest") != report.metadata.get("context_manifest"):
        raise ValueError("metadata.json context manifest differs from the final report")
    if embedded_metadata.get("context_preflight_records") != report.metadata.get(
        "context_preflight_records"
    ):
        raise ValueError("metadata.json context preflight differs from the final report")
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
    candidate_artifact = CandidateFindingArtifact.model_validate(
        _read_json_artifact(root, "candidate-findings.json")
    )
    raw_reproduction_artifact = _read_json_artifact(root, "reproduction-results.json")
    reproduction_artifact = (
        _ManifestReproductionArtifact.model_validate(raw_reproduction_artifact)
        if report.schema_version == "1.2"
        else None
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
    scanner_fingerprints = {
        finding.fingerprint for run in report.scanner_runs for finding in run.findings
    }
    reported_execution_ids: set[str] = set()
    for finding in [*report.findings, *report.rejected_findings]:
        contributing = set(finding.contributing_candidate_ids)
        if len(contributing) != len(finding.contributing_candidate_ids):
            raise ValueError("final finding contains duplicate contributing evidence IDs")
        if finding.origin_kind is FindingOriginKind.STATIC_ANALYZER:
            if not contributing or not contributing <= scanner_fingerprints:
                raise ValueError("static-analyzer finding lacks exact scanner provenance")
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
    if report.completed:
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


def validate_manifest_artifacts(
    manifest: RunEvidenceManifest,
    run_dir: Path,
) -> None:
    """Verify every run file is listed and unchanged without executing target code."""

    root = run_dir.resolve(strict=True)
    expected = {binding.path: binding for binding in manifest.artifacts}
    actual = {binding.path: binding for binding in collect_run_artifacts(root)}
    if set(actual) != set(expected):
        raise ValueError("run artifact set does not match the evidence manifest")
    for path, binding in expected.items():
        observed = actual[path]
        if observed.size != binding.size or observed.sha256 != binding.sha256:
            raise ValueError(f"run artifact hash mismatch: {path}")
    if manifest.schema_version == "1.1":
        for required_artifact in ("final-findings.json", "metadata.json"):
            if required_artifact not in expected:
                raise ValueError(
                    f"current run manifest requires emitted artifact: {required_artifact}"
                )
    if "final-findings.json" in expected:
        report = AuditReport.model_validate(_read_json_artifact(root, "final-findings.json"))
        _validate_report_artifact_consistency(root, report)
        context_manifest = _validated_context_manifest(root, report)
        if manifest.run_configuration is not None:
            effective_config = manifest.run_configuration.reconstruct_effective_config()
            _validate_repository_differential_configuration(report, effective_config)
            _validate_context_manifest_configuration(
                context_manifest,
                effective_config,
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


def _configuration_bindings(config: AuditConfig) -> list[ManifestHashBinding]:
    return [
        ManifestHashBinding(
            identifier="config/full",
            sha256=config.stable_hash(),
            details={"version": str(config.version), "profile": config.profile.value},
        ),
        ManifestHashBinding(
            identifier="config/models",
            sha256=config.model_hash(),
            details={"configured_roles": str(6 + len(config.models.specialists))},
        ),
    ]


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
) -> list[ManifestHashBinding]:
    roles = [*ALL_MODEL_ROLES, *sorted(config.models.specialists)]
    registry = {
        model_id.lower(): entry
        for entry in config.models.registry
        for model_id in entry.model_ids()
    }
    bindings = []
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
        bindings.append(
            _binding(
                f"execution/{index:05d}",
                usage.model_dump(mode="json"),
                {
                    "role": _detail(usage.role),
                    "requested": _detail(usage.requested_model),
                    "returned": _detail(usage.returned_model or "not_reported"),
                    "status": _detail(usage.status),
                },
            )
        )
    bindings.extend(_qualification_bindings(qualification_runtime))
    return sorted(bindings, key=lambda item: item.identifier)


def _qualification_bindings(
    payload: dict[str, Any] | None,
) -> list[ManifestHashBinding]:
    if payload is None:
        return [
            _binding(
                "qualification/runtime-absent",
                {"present": False},
                {"state": "not_emitted"},
            )
        ]

    # Local import avoids the registry -> qualification -> manifest import cycle.
    from mmaudit.models.registry import ProductionQualificationValidation

    validation = ProductionQualificationValidation.from_dict(payload)
    bindings = [
        ManifestHashBinding(
            identifier="qualification/runtime-validation",
            sha256=validation.validation_sha256,
            details={
                "valid": str(validation.valid).lower(),
                "required": str(validation.required).lower(),
                "configured_models": str(len(validation.configured_model_ids)),
                "qualified_models": str(len(validation.qualified_model_ids)),
            },
        )
    ]
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


def _tool_bindings(
    config: AuditConfig,
    report: AuditReport,
) -> list[ManifestHashBinding]:
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
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "model-review/artifact",
            model_coverage,
            {"artifact": "model-review-coverage.json"},
        ),
        _binding(
            "quality-gates/report",
            [gate.model_dump(mode="json") for gate in report.quality_gates],
            {"gates": str(len(report.quality_gates))},
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


def _read_json_artifact(run_dir: Path, name: str) -> dict[str, Any]:
    normalized = normalize_relative_path(name)
    path = run_dir / normalized
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"run JSON artifact may not be a link: {name}")
    resolved = path.resolve(strict=True)
    resolved.relative_to(run_dir)
    if not resolved.is_file() or resolved.stat().st_nlink != 1:
        raise ValueError(f"run JSON artifact is not a unique regular file: {name}")
    if resolved.stat().st_size > _MAX_JSON_ARTIFACT_BYTES:
        raise ValueError(f"run JSON artifact exceeds its byte limit: {name}")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
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
