"""Deterministic hash-linked evidence manifests for completed local runs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
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
    MaximumAssuranceStatus,
    StrictModel,
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
    solidity_coverage = _read_json_artifact(root, "solidity-coverage.json")
    model_coverage = _read_json_artifact(root, "model-review-coverage.json")
    scope_assessment = _read_json_artifact(root, "scope-assessment.json")
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
        ),
        corpora=_corpus_bindings(property_corpus),
        harnesses=_harness_bindings(harness_plan, invariant_results, reproduction_results),
        reproductions=_reproduction_bindings(reproduction_results),
        coverage=_coverage_bindings(
            report,
            solidity_coverage,
            model_coverage,
            scope_assessment,
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


def _validate_report_artifact_consistency(root: Path, report: AuditReport) -> None:
    """Require emitted report summaries to agree before sealing their byte hashes."""

    metadata = _read_json_artifact(root, "metadata.json")
    if metadata.get("privacy") != report.privacy:
        raise ValueError("metadata.json privacy differs from the final report")


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
) -> list[ManifestHashBinding]:
    return [
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
            if key in {"seed", "campaign_seed"} and isinstance(child, (int, str)):
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
