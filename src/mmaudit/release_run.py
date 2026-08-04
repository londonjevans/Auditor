"""Fresh, hash-bound observation of one emitted audit run.

The target repository identity in this record comes from the audit-run manifest.
It is deliberately distinct from the mmaudit product-candidate identity that a
release report may bind separately.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.models.schemas import (
    AuditProfile,
    LanguageCapabilityArtifact,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
    StrictModel,
)
from mmaudit.orchestration.manifest import (
    LANGUAGE_CAPABILITY_ARTIFACT_PATH,
    RunEvidenceManifest,
    canonical_sha256,
)
from mmaudit.release_artifacts import (
    ReleaseArtifactEvidence,
    _decode_json_object,
    _read_unique_regular_file,
    _require_unlinked_directory,
    observe_release_artifacts,
)
from mmaudit.repository.secrets import is_sensitive_workspace_name

_MANIFEST_NAME = "run-evidence-manifest.json"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_TARGET_COMMIT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_MAX_EVIDENCE_BYTES = 100_000_000
_MAX_ARTIFACTS = 100_000


class ReleaseRunBindingPayload(StrictModel):
    """Canonical projection of an exact target run and its observed evidence."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    target_repository_name: str = Field(min_length=1, max_length=500)
    target_git_commit: str | None = Field(pattern=_TARGET_COMMIT_PATTERN)
    target_source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_path: Literal["run-evidence-manifest.json"]
    manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_configuration_sha256: str = Field(pattern=_SHA256_PATTERN)
    file_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    environment_overrides_sha256: str = Field(pattern=_SHA256_PATTERN)
    cli_overrides_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_options_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    invocation_sha256: str = Field(pattern=_SHA256_PATTERN)
    requested_profile: AuditProfile
    achieved_profile: AuditProfile | None
    requested_language_profile: LanguageCapabilityProfile
    achieved_language_profile: LanguageCapabilityProfile | None
    capability_status: LanguageCapabilityStatus
    reduced_language_capability: bool
    language_capability_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_evidence_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_evidence_file_size: int = Field(ge=1, le=_MAX_EVIDENCE_BYTES)
    artifact_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_count: int = Field(ge=1, le=_MAX_ARTIFACTS)
    traceability_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("release run observation time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def profiles_are_consistent(self) -> ReleaseRunBindingPayload:
        if (
            self.achieved_profile is not None
            and self.achieved_profile is not self.requested_profile
        ):
            raise ValueError("release run cannot claim an unrequested achieved profile")
        if (
            self.achieved_language_profile is not None
            and self.achieved_language_profile is not self.requested_language_profile
        ):
            raise ValueError("release run cannot claim an unrequested language capability")
        expected_reduced = (
            self.capability_status is LanguageCapabilityStatus.REDUCED
            and self.achieved_language_profile
            is LanguageCapabilityProfile.GENERIC_SOURCE_REVIEW
        )
        if self.reduced_language_capability is not expected_reduced:
            raise ValueError("release run reduced language capability is inconsistent")
        if self.capability_status is LanguageCapabilityStatus.MATCHED and (
            self.achieved_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
            or self.reduced_language_capability
        ):
            raise ValueError("matched release capability must be Solidity/EVM")
        if self.capability_status in {
            LanguageCapabilityStatus.MISMATCH,
            LanguageCapabilityStatus.INCONCLUSIVE,
        } and self.achieved_language_profile is not None:
            raise ValueError("unachieved release capability cannot name an achieved profile")
        if self.achieved_profile is AuditProfile.MAXIMUM_ASSURANCE and (
            self.capability_status is not LanguageCapabilityStatus.MATCHED
            or self.requested_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
            or self.achieved_language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
            or self.reduced_language_capability
        ):
            raise ValueError(
                "maximum-assurance release run requires matched Solidity/EVM capability"
            )
        return self


class ReleaseRunBinding(ReleaseRunBindingPayload):
    """Self-hashed binding derived from two fresh observations of one run."""

    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def binding_hash_is_consistent(self) -> ReleaseRunBinding:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("release run binding hash is inconsistent")
        return self


def observe_release_run_binding(
    run_dir: Path,
    repository_root: Path,
    artifact_evidence_path: Path,
) -> ReleaseRunBinding:
    """Bind one explicit emitted run to one exact pre-existing evidence file."""

    run_root = _require_unlinked_directory(run_dir, label="release run")
    evidence, evidence_bytes = _read_artifact_evidence_exact(artifact_evidence_path)
    evidence_parent = _require_unlinked_directory(
        artifact_evidence_path.parent,
        label="release-evidence parent",
    )
    if _directory_is_within(evidence_parent, run_root):
        raise ValueError("release artifact evidence must be outside the emitted run")

    observed_before = observe_release_artifacts(run_root, repository_root)
    if evidence != observed_before:
        raise ValueError("release artifact evidence differs from the explicit emitted run")

    manifest_path = run_root / _MANIFEST_NAME
    manifest_bytes = _read_unique_regular_file(
        manifest_path,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="run evidence manifest",
    )
    manifest = RunEvidenceManifest.model_validate(
        _decode_json_object(manifest_bytes, label="run evidence manifest")
    )
    if manifest.schema_version != "1.2" or manifest.run_configuration is None:
        raise ValueError("release run binding requires report-bundle manifest schema 1.2")
    _require_manifest_evidence_equality(
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        evidence=evidence,
    )

    run_configuration = manifest.run_configuration
    capability_binding = next(
        (
            item
            for item in manifest.artifacts
            if item.path == LANGUAGE_CAPABILITY_ARTIFACT_PATH
        ),
        None,
    )
    if capability_binding is None:
        raise ValueError("release run lacks language capability artifact evidence")
    capability_bytes = _read_unique_regular_file(
        run_root / LANGUAGE_CAPABILITY_ARTIFACT_PATH,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="language capability artifact",
    )
    if (
        len(capability_bytes) != capability_binding.size
        or hashlib.sha256(capability_bytes).hexdigest() != capability_binding.sha256
    ):
        raise ValueError("language capability artifact differs from the run manifest")
    language_capability = LanguageCapabilityArtifact.model_validate(
        _decode_json_object(capability_bytes, label="language capability artifact")
    ).assessment
    if (
        language_capability.requested_profile
        is not run_configuration.requested_language_profile
        or language_capability.achieved_profile
        is not run_configuration.achieved_language_profile
        or language_capability.reduced_capability
        is not run_configuration.reduced_language_capability
    ):
        raise ValueError("language capability artifact differs from run configuration")
    payload = ReleaseRunBindingPayload(
        schema_version="1.0",
        generated_by="mmaudit",
        run_id=manifest.run_id,
        target_repository_name=manifest.repository_root_name,
        target_git_commit=manifest.git_commit,
        target_source_tree_sha256=manifest.source_tree_sha256,
        manifest_path=_MANIFEST_NAME,
        manifest_file_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        manifest_sha256=manifest.manifest_sha256,
        run_configuration_sha256=canonical_sha256(run_configuration.model_dump(mode="json")),
        file_config_sha256=run_configuration.file_config_sha256,
        environment_overrides_sha256=run_configuration.environment_overrides_sha256,
        cli_overrides_sha256=run_configuration.cli_overrides_sha256,
        run_options_sha256=run_configuration.run_options_sha256,
        effective_config_sha256=run_configuration.effective_config_sha256,
        model_config_sha256=run_configuration.model_config_sha256,
        invocation_sha256=run_configuration.invocation_sha256,
        requested_profile=run_configuration.requested_profile,
        achieved_profile=run_configuration.achieved_profile,
        requested_language_profile=run_configuration.requested_language_profile,
        achieved_language_profile=run_configuration.achieved_language_profile,
        capability_status=language_capability.status,
        reduced_language_capability=language_capability.reduced_capability,
        language_capability_sha256=canonical_sha256(
            language_capability.model_dump(mode="json")
        ),
        artifact_evidence_file_sha256=hashlib.sha256(evidence_bytes).hexdigest(),
        artifact_evidence_file_size=len(evidence_bytes),
        artifact_evidence_sha256=evidence.evidence_sha256,
        artifact_inventory_sha256=evidence.artifact_inventory_sha256,
        artifact_count=evidence.artifact_count,
        traceability_sha256=evidence.traceability_sha256,
        observed_at=datetime.now(UTC).replace(microsecond=0),
    )

    observed_after = observe_release_artifacts(run_root, repository_root)
    evidence_after, evidence_bytes_after = _read_artifact_evidence_exact(artifact_evidence_path)
    manifest_bytes_after = _read_unique_regular_file(
        manifest_path,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="run evidence manifest",
    )
    if (
        observed_after != observed_before
        or evidence_after != evidence
        or evidence_bytes_after != evidence_bytes
        or manifest_bytes_after != manifest_bytes
    ):
        raise ValueError("release run or artifact evidence changed while being bound")
    _require_manifest_evidence_equality(
        manifest=RunEvidenceManifest.model_validate(
            _decode_json_object(manifest_bytes_after, label="run evidence manifest")
        ),
        manifest_bytes=manifest_bytes_after,
        evidence=evidence_after,
    )

    serialized = payload.model_dump(mode="json")
    return ReleaseRunBinding.model_validate(
        {
            **serialized,
            "binding_sha256": canonical_sha256(serialized),
        }
    )


def _read_artifact_evidence_exact(
    path: Path,
) -> tuple[ReleaseArtifactEvidence, bytes]:
    """Parse and return the same safely read evidence bytes that are hash-bound."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive release-evidence filename")
    parent = _require_unlinked_directory(path.parent, label="release-evidence parent")
    data = _read_unique_regular_file(
        parent / path.name,
        max_bytes=_MAX_EVIDENCE_BYTES,
        label="release artifact evidence",
    )
    evidence = ReleaseArtifactEvidence.model_validate(
        _decode_json_object(data, label="release artifact evidence")
    )
    return evidence, data


def _require_manifest_evidence_equality(
    *,
    manifest: RunEvidenceManifest,
    manifest_bytes: bytes,
    evidence: ReleaseArtifactEvidence,
) -> None:
    """Cross-reconcile every manifest identity copied into artifact evidence."""

    if (
        manifest.schema_version != "1.2"
        or manifest.run_configuration is None
        or evidence.run_id != manifest.run_id
        or evidence.manifest_path != _MANIFEST_NAME
        or evidence.manifest_file_sha256 != hashlib.sha256(manifest_bytes).hexdigest()
        or evidence.manifest_sha256 != manifest.manifest_sha256
        or evidence.artifacts != manifest.artifacts
        or evidence.artifact_count != len(manifest.artifacts)
        or evidence.artifact_inventory_sha256
        != canonical_sha256([binding.model_dump(mode="json") for binding in manifest.artifacts])
    ):
        raise ValueError("run manifest differs from the bound release artifact evidence")


def _directory_is_within(candidate: Path, directory: Path) -> bool:
    """Compare directory identity, including case/Unicode aliases."""

    try:
        directory_metadata = directory.stat()
        current = candidate
        while True:
            if os.path.samestat(current.stat(), directory_metadata):
                return True
            parent = current.parent
            if parent == current:
                return False
            current = parent
    except OSError as exc:
        raise ValueError("release run binding paths are unavailable") from exc
