"""Strict provider-free validation and staging for model-refresh evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.policy_eligibility import (
    ModelPolicyEligibilityArtifact,
    PolicyEligibilityRoute,
)
from mmaudit.models.policy_eligibility_authority import PolicyEligibilitySourceObservation
from mmaudit.models.policy_eligibility_refresh import (
    POLICY_ELIGIBILITY_REFRESH_FILENAME,
    ModelPolicyEligibilityRefreshError,
    build_model_policy_eligibility_refresh_artifact,
    load_model_policy_eligibility_refresh_artifact,
    verify_model_policy_eligibility_refresh_artifact,
)
from mmaudit.models.qualification import CandidateRegistry
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    CANDIDATE_REGISTRY_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    MAX_MODEL_REFRESH_FRACTION_TEXT_LENGTH,
    MODEL_REFRESH_FRACTION_PATTERN,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    ModelRefreshAttempt,
    ModelRefreshAttemptStatus,
    ModelRefreshDiff,
    ModelRefreshFreshness,
    ModelRefreshFreshnessState,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
    RefreshBaselineKind,
    SelectedModelRoute,
    build_model_refresh_snapshot_from_source,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    load_model_refresh_attempt,
    load_model_refresh_diff,
    load_model_refresh_freshness,
    load_model_refresh_snapshot,
    load_model_refresh_source_evidence,
    parse_model_refresh_fraction,
)
from mmaudit.release_io import read_json_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json

WORKFLOW_STATUS_FILENAME = "workflow-status.json"
PREVIOUS_WORKFLOW_STATUS_FILENAME = "previous-workflow-status.json"
PREVIOUS_CANDIDATE_REGISTRY_FILENAME = "previous-candidate-registry.json"
PREVIOUS_SOURCE_EVIDENCE_FILENAME = "previous-source-evidence.json"
PREVIOUS_SNAPSHOT_FILENAME = "previous-snapshot.json"
_IMMEDIATE_PREDECESSOR_FILENAMES = frozenset(
    {
        PREVIOUS_WORKFLOW_STATUS_FILENAME,
        PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
        PREVIOUS_SOURCE_EVIDENCE_FILENAME,
        PREVIOUS_SNAPSHOT_FILENAME,
    }
)
_REFRESH_SUCCESS_FILENAMES = frozenset(
    {
        SOURCE_EVIDENCE_FILENAME,
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
    }
)
_SUCCESS_FILENAMES = _REFRESH_SUCCESS_FILENAMES | {CANDIDATE_REGISTRY_FILENAME}
_REFRESH_POLICY_SUCCESS_FILENAMES = _REFRESH_SUCCESS_FILENAMES | {
    POLICY_ELIGIBILITY_REFRESH_FILENAME
}
_POLICY_SUCCESS_FILENAMES = _SUCCESS_FILENAMES | {POLICY_ELIGIBILITY_REFRESH_FILENAME}
_FAILURE_FILENAMES = frozenset({ATTEMPT_FILENAME})
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_WORKFLOW_NUMBER_PATTERN = r"^[1-9][0-9]{0,19}$"
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_MAX_ARTIFACT_BYTES = 20_000_000
_MAX_CLOCK_SKEW = timedelta(minutes=5)


class ModelRefreshStagingError(ValueError):
    """Raised when emitted refresh evidence is unsafe or internally inconsistent."""


class ModelRefreshWorkflowDisposition(StrEnum):
    COMPLETED = "COMPLETED"
    PRODUCTION_BLOCKED = "PRODUCTION_BLOCKED"
    FAILED = "FAILED"
    PREREQUISITE_MISSING = "PREREQUISITE_MISSING"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StagedModelRefreshArtifact(_FrozenModel):
    """Content and internal identity for one validated staged artifact."""

    filename: Literal[
        "model-refresh-candidate-registry.json",
        "model-refresh-source-evidence.json",
        "model-refresh-snapshot.json",
        "model-refresh-diff.json",
        "model-refresh-attempt.json",
        "model-refresh-freshness.json",
        "model-policy-eligibility-refresh.json",
        "previous-workflow-status.json",
        "previous-candidate-registry.json",
        "previous-source-evidence.json",
        "previous-snapshot.json",
    ]
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    byte_count: int = Field(ge=1, le=_MAX_ARTIFACT_BYTES)


class ModelRefreshWorkflowStatus(_FrozenModel):
    """Commit-bound inventory for one scheduled refresh attempt."""

    schema_version: Literal["4.0"] = "4.0"
    validated_at: datetime
    disposition: ModelRefreshWorkflowDisposition
    refresh_exit_status: int = Field(ge=0, le=255)
    source_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    workflow_run_id: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    workflow_run_attempt: str = Field(pattern=_WORKFLOW_NUMBER_PATTERN)
    previous_workflow_run_id: str | None = Field(
        default=None,
        pattern=_WORKFLOW_NUMBER_PATTERN,
    )
    previous_workflow_run_attempt: str | None = Field(
        default=None,
        pattern=_WORKFLOW_NUMBER_PATTERN,
    )
    previous_workflow_status_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    pricing_tolerance_fraction: str = Field(
        min_length=1,
        max_length=MAX_MODEL_REFRESH_FRACTION_TEXT_LENGTH,
        pattern=MODEL_REFRESH_FRACTION_PATTERN,
    )
    soft_max_age_hours: int = Field(ge=1, le=24 * 30)
    hard_max_age_hours: int = Field(ge=2, le=24 * 90)
    policy_projection_expected: bool
    artifacts: tuple[StagedModelRefreshArtifact, ...]
    workflow_status_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("pricing_tolerance_fraction")
    @classmethod
    def pricing_tolerance_is_canonical(cls, value: str) -> str:
        parsed = _canonical_fraction(value)
        if parsed > 1:
            raise ValueError("refresh workflow pricing tolerance cannot exceed one")
        return value

    @field_validator("validated_at")
    @classmethod
    def validation_time_is_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="refresh workflow validation time")

    @field_validator("policy_projection_expected", mode="before")
    @classmethod
    def policy_expectation_is_a_literal_bool(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("policy refresh projection expectation must be a literal boolean")
        return value

    @model_validator(mode="after")
    def status_is_canonical_and_self_bound(self) -> Self:
        if self.hard_max_age_hours <= self.soft_max_age_hours:
            raise ValueError("refresh workflow hard age must exceed its soft age")
        prior_identity = (
            self.previous_workflow_run_id,
            self.previous_workflow_run_attempt,
            self.previous_workflow_status_sha256,
        )
        if any(value is not None for value in prior_identity) and not all(
            value is not None for value in prior_identity
        ):
            raise ValueError("prior refresh workflow identity must be supplied atomically")
        predecessor_present = all(value is not None for value in prior_identity)
        filenames = tuple(artifact.filename for artifact in self.artifacts)
        if filenames != tuple(sorted(set(filenames))):
            raise ValueError("staged refresh artifact inventory must be unique and sorted")
        expected_names: frozenset[str]
        if self.disposition in {
            ModelRefreshWorkflowDisposition.COMPLETED,
            ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
        }:
            expected_names = (
                _POLICY_SUCCESS_FILENAMES if self.policy_projection_expected else _SUCCESS_FILENAMES
            )
            if predecessor_present:
                expected_names |= _IMMEDIATE_PREDECESSOR_FILENAMES
        elif self.disposition is ModelRefreshWorkflowDisposition.FAILED:
            expected_names = _FAILURE_FILENAMES
        else:
            expected_names = frozenset()
        if set(filenames) != expected_names:
            raise ValueError("staged refresh artifact inventory differs from its disposition")
        if self.previous_workflow_run_id is not None:
            assert self.previous_workflow_run_attempt is not None
            previous_run_id = int(self.previous_workflow_run_id)
            current_run_id = int(self.workflow_run_id)
            if previous_run_id > current_run_id or (
                previous_run_id == current_run_id
                and int(self.previous_workflow_run_attempt) >= int(self.workflow_run_attempt)
            ):
                raise ValueError("prior refresh workflow attempt is not earlier than this attempt")
        expected_exit_disposition = _disposition_for_exit(self.refresh_exit_status)
        if self.disposition is not expected_exit_disposition:
            raise ValueError("staged refresh disposition differs from its exit status")
        expected = _canonical_sha256(
            self.model_dump(mode="json", exclude={"workflow_status_sha256"})
        )
        if self.workflow_status_sha256 != expected:
            raise ValueError("staged refresh workflow status self-hash is inconsistent")
        return self


class ValidatedModelRefreshHistory(_FrozenModel):
    """Exact non-authorizing workflow bundle retained for deterministic replay."""

    workflow_status: ModelRefreshWorkflowStatus
    candidate_registry: CandidateRegistry
    source_evidence: ModelRefreshSourceEvidence
    snapshot: ModelRefreshSnapshot
    diff: ModelRefreshDiff
    attempt: ModelRefreshAttempt
    freshness: ModelRefreshFreshness
    previous_workflow_status: ModelRefreshWorkflowStatus | None = None
    previous_candidate_registry: CandidateRegistry | None = None
    previous_source_evidence: ModelRefreshSourceEvidence | None = None
    previous_snapshot: ModelRefreshSnapshot | None = None

    @model_validator(mode="after")
    def predecessor_is_atomic_and_non_authorizing(self) -> Self:
        predecessor = (
            self.previous_workflow_status,
            self.previous_candidate_registry,
            self.previous_source_evidence,
            self.previous_snapshot,
        )
        if any(item is not None for item in predecessor) and not all(
            item is not None for item in predecessor
        ):
            raise ValueError("validated refresh predecessor evidence must be atomic")
        if (self.diff.baseline_kind is RefreshBaselineKind.PREVIOUS_SNAPSHOT) is not all(
            item is not None for item in predecessor
        ):
            raise ValueError("validated refresh predecessor differs from its diff baseline")
        return self


def stage_model_refresh_evidence(
    *,
    output_dir: Path,
    staging_dir: Path,
    candidate_registry: CandidateRegistry,
    refresh_exit_status: int,
    source_commit: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    pricing_tolerance_fraction: str,
    soft_max_age_hours: int,
    hard_max_age_hours: int,
    previous_snapshot: ModelRefreshSnapshot | None = None,
    previous_source_evidence: ModelRefreshSourceEvidence | None = None,
    previous_candidate_registry: CandidateRegistry | None = None,
    previous_workflow_status: ModelRefreshWorkflowStatus | None = None,
    expected_selected_routes: Sequence[SelectedModelRoute] = (),
    policy_eligibility_artifact: ModelPolicyEligibilityArtifact | None = None,
    policy_source_observation: PolicyEligibilitySourceObservation | None = None,
    policy_checked_routes: Sequence[PolicyEligibilityRoute] | None = None,
    _validation_observed_at: datetime | None = None,
) -> ModelRefreshWorkflowStatus:
    """Validate one exact emitted bundle and reconstruct canonical upload evidence."""

    if isinstance(refresh_exit_status, bool) or not 0 <= refresh_exit_status <= 255:
        raise ModelRefreshStagingError("refresh exit status must be an integer from zero to 255")
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    validated_at = (
        datetime.now(UTC).replace(microsecond=0)
        if _validation_observed_at is None
        else _whole_second_utc(
            _validation_observed_at,
            label="refresh workflow validation time",
        )
    )
    previous_inputs = (
        previous_snapshot,
        previous_source_evidence,
        previous_candidate_registry,
    )
    if any(item is not None for item in previous_inputs) and not all(
        item is not None for item in previous_inputs
    ):
        raise ModelRefreshStagingError(
            "refresh previous snapshot, source evidence, and candidate registry "
            "must be supplied together"
        )
    if (
        previous_candidate_registry is not None
        and previous_candidate_registry.created_at > registry.created_at
    ):
        raise ModelRefreshStagingError(
            "refresh previous candidate registry is newer than the current registry"
        )
    validated_previous_status: ModelRefreshWorkflowStatus | None = None
    validated_previous_registry: CandidateRegistry | None = None
    validated_previous_source: ModelRefreshSourceEvidence | None = None
    validated_previous_snapshot: ModelRefreshSnapshot | None = None
    if previous_workflow_status is not None:
        if not all(item is not None for item in previous_inputs):
            raise ModelRefreshStagingError(
                "refresh previous workflow status requires the exact previous evidence triple"
            )
        try:
            validated_previous_status = ModelRefreshWorkflowStatus.model_validate_json(
                previous_workflow_status.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise ModelRefreshStagingError("refresh previous workflow status is invalid") from exc
        assert previous_candidate_registry is not None
        assert previous_source_evidence is not None
        assert previous_snapshot is not None
        try:
            validated_previous_registry = CandidateRegistry.model_validate_json(
                previous_candidate_registry.model_dump_json(),
                strict=True,
            )
            validated_previous_source = ModelRefreshSourceEvidence.model_validate_json(
                previous_source_evidence.model_dump_json(),
                strict=True,
            )
            validated_previous_snapshot = ModelRefreshSnapshot.model_validate_json(
                previous_snapshot.model_dump_json(),
                strict=True,
            )
        except (AttributeError, ValueError) as exc:
            raise ModelRefreshStagingError("refresh previous evidence triple is invalid") from exc
        if (
            validated_previous_status.disposition
            not in {
                ModelRefreshWorkflowDisposition.COMPLETED,
                ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
            }
            or validated_previous_status.candidate_registry_sha256
            != validated_previous_registry.registry_sha256
        ):
            raise ModelRefreshStagingError(
                "refresh previous workflow status does not bind the previous candidate registry"
            )
        _validate_status_artifact_binding(
            status=validated_previous_status,
            filename=CANDIDATE_REGISTRY_FILENAME,
            artifact=validated_previous_registry,
        )
        _validate_status_artifact_binding(
            status=validated_previous_status,
            filename=SOURCE_EVIDENCE_FILENAME,
            artifact=validated_previous_source,
        )
        _validate_status_artifact_binding(
            status=validated_previous_status,
            filename=SNAPSHOT_FILENAME,
            artifact=validated_previous_snapshot,
        )
        if validated_previous_status.validated_at > validated_at + _MAX_CLOCK_SKEW:
            raise ModelRefreshStagingError(
                "refresh previous workflow status is newer than the current workflow"
            )
    policy_inputs = (
        policy_eligibility_artifact,
        policy_source_observation,
        policy_checked_routes,
    )
    if any(item is not None for item in policy_inputs) and not all(
        item is not None for item in policy_inputs
    ):
        raise ModelRefreshStagingError(
            "refresh policy artifact, source observation, and checked routes "
            "must be supplied together"
        )
    policy_projection_expected = all(item is not None for item in policy_inputs)
    validated_policy_artifact = None
    validated_policy_observation = None
    validated_policy_routes: tuple[PolicyEligibilityRoute, ...] | None = None
    if policy_projection_expected:
        assert policy_eligibility_artifact is not None
        assert policy_source_observation is not None
        assert policy_checked_routes is not None
        try:
            validated_policy_artifact = ModelPolicyEligibilityArtifact.model_validate_json(
                policy_eligibility_artifact.model_dump_json(),
                strict=True,
            )
            validated_policy_observation = PolicyEligibilitySourceObservation.model_validate_json(
                policy_source_observation.model_dump_json(),
                strict=True,
            )
            validated_policy_routes = tuple(
                PolicyEligibilityRoute.model_validate_json(route.model_dump_json(), strict=True)
                for route in policy_checked_routes
            )
            if not validated_policy_routes:
                raise ValueError("policy checked routes are empty")
        except (AttributeError, ValueError) as exc:
            raise ModelRefreshStagingError("refresh policy inputs are invalid") from exc
    tolerance = _canonical_fraction(pricing_tolerance_fraction)
    if tolerance > 1:
        raise ModelRefreshStagingError("refresh staging pricing tolerance cannot exceed one")
    if (
        isinstance(soft_max_age_hours, bool)
        or isinstance(hard_max_age_hours, bool)
        or not isinstance(soft_max_age_hours, int)
        or not isinstance(hard_max_age_hours, int)
        or not 1 <= soft_max_age_hours <= 24 * 30
        or not 2 <= hard_max_age_hours <= 24 * 90
        or hard_max_age_hours <= soft_max_age_hours
    ):
        raise ModelRefreshStagingError("refresh staging freshness policy is invalid")
    disposition = _disposition_for_exit(refresh_exit_status)
    if (
        disposition
        in {
            ModelRefreshWorkflowDisposition.COMPLETED,
            ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
        }
        and all(item is not None for item in previous_inputs)
        and validated_previous_status is None
    ):
        raise ModelRefreshStagingError(
            "successful refresh previous evidence requires its workflow status"
        )
    output_names = _expected_output_names(
        disposition,
        policy_projection_expected=policy_projection_expected,
    )
    if disposition is ModelRefreshWorkflowDisposition.PREREQUISITE_MISSING:
        if output_dir.exists() or output_dir.is_symlink():
            raise ModelRefreshStagingError(
                "prerequisite-missing refresh must not emit an output directory"
            )
        validated: dict[str, BaseModel] = {}
    else:
        before = _observe_exact_private_directory(output_dir, expected_names=output_names)
        validated = _load_and_validate_bundle(
            output_dir=output_dir,
            disposition=disposition,
            registry=registry,
            previous_snapshot=previous_snapshot,
            previous_source_evidence=previous_source_evidence,
            previous_candidate_registry=previous_candidate_registry,
            expected_selected_routes=expected_selected_routes,
            pricing_tolerance_fraction=pricing_tolerance_fraction,
            soft_max_age_hours=soft_max_age_hours,
            hard_max_age_hours=hard_max_age_hours,
            validated_at=validated_at,
            policy_eligibility_artifact=validated_policy_artifact,
            policy_source_observation=validated_policy_observation,
            policy_checked_routes=validated_policy_routes,
        )
        if validated_previous_status is not None and disposition in {
            ModelRefreshWorkflowDisposition.COMPLETED,
            ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
        }:
            assert validated_previous_registry is not None
            assert validated_previous_source is not None
            assert validated_previous_snapshot is not None
            validated.update(
                {
                    PREVIOUS_WORKFLOW_STATUS_FILENAME: validated_previous_status,
                    PREVIOUS_CANDIDATE_REGISTRY_FILENAME: validated_previous_registry,
                    PREVIOUS_SOURCE_EVIDENCE_FILENAME: validated_previous_source,
                    PREVIOUS_SNAPSHOT_FILENAME: validated_previous_snapshot,
                }
            )
        after = _observe_exact_private_directory(output_dir, expected_names=output_names)
        if before != after:
            raise ModelRefreshStagingError("refresh output changed while being validated")

    staging_root = _create_private_staging_directory(staging_dir)
    completed = False
    try:
        bindings: list[StagedModelRefreshArtifact] = []
        for filename in sorted(validated):
            artifact = validated[filename]
            raw = stable_json(artifact).encode("utf-8")
            write_json_evidence(
                evidence_root=staging_root,
                relative_path=filename,
                value=artifact,
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
            bindings.append(
                StagedModelRefreshArtifact(
                    filename=filename,
                    content_sha256=hashlib.sha256(raw).hexdigest(),
                    artifact_sha256=_artifact_self_hash(filename, artifact),
                    byte_count=len(raw),
                )
            )

        status_values = {
            "schema_version": "4.0",
            "validated_at": validated_at.isoformat().replace("+00:00", "Z"),
            "disposition": disposition.value,
            "refresh_exit_status": refresh_exit_status,
            "source_commit": source_commit,
            "workflow_run_id": workflow_run_id,
            "workflow_run_attempt": workflow_run_attempt,
            "previous_workflow_run_id": (
                None
                if validated_previous_status is None
                else validated_previous_status.workflow_run_id
            ),
            "previous_workflow_run_attempt": (
                None
                if validated_previous_status is None
                else validated_previous_status.workflow_run_attempt
            ),
            "previous_workflow_status_sha256": (
                None
                if validated_previous_status is None
                else validated_previous_status.workflow_status_sha256
            ),
            "candidate_registry_sha256": registry.registry_sha256,
            "pricing_tolerance_fraction": pricing_tolerance_fraction,
            "soft_max_age_hours": soft_max_age_hours,
            "hard_max_age_hours": hard_max_age_hours,
            "policy_projection_expected": policy_projection_expected,
            "artifacts": [binding.model_dump(mode="json") for binding in bindings],
        }
        status_values["workflow_status_sha256"] = _canonical_sha256(status_values)
        try:
            status = ModelRefreshWorkflowStatus.model_validate(status_values)
        except ValueError as exc:
            raise ModelRefreshStagingError("refresh workflow identity is invalid") from exc
        write_json_evidence(
            evidence_root=staging_root,
            relative_path=WORKFLOW_STATUS_FILENAME,
            value=status,
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        _observe_exact_private_directory(
            staging_root,
            expected_names=_expected_staged_names(
                disposition,
                policy_projection_expected=policy_projection_expected,
                predecessor_present=validated_previous_status is not None,
            )
            | {WORKFLOW_STATUS_FILENAME},
        )
        completed = True
        return status
    finally:
        if not completed:
            _remove_fresh_staging_directory(staging_root)


def load_model_refresh_workflow_status(path: Path) -> ModelRefreshWorkflowStatus:
    """Load one canonical status through descriptor-safe evidence I/O."""

    return _load_staged_workflow_status(path, expected_filename=WORKFLOW_STATUS_FILENAME)


def _load_staged_workflow_status(
    path: Path,
    *,
    expected_filename: str,
) -> ModelRefreshWorkflowStatus:
    if path.name != expected_filename:
        raise ModelRefreshStagingError("refresh workflow status filename is invalid")
    try:
        observation = read_json_evidence(
            evidence_root=path.parent,
            relative_path=path.name,
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        status = ModelRefreshWorkflowStatus.model_validate(observation.value)
    except ValueError as exc:
        raise ModelRefreshStagingError("refresh workflow status failed strict validation") from exc
    if observation.content != stable_json(status).encode("utf-8"):
        raise ModelRefreshStagingError("refresh workflow status is not canonical")
    return status


def load_previous_model_refresh_history(
    history_dir: Path,
    *,
    expected_workflow_run_id: str,
    expected_workflow_run_attempt: str,
    expected_source_commit: str,
) -> ValidatedModelRefreshHistory:
    """Load one exact same-workflow artifact bundle as a non-authorizing baseline.

    The caller remains responsible for selecting an artifact from the trusted repository and
    default branch. This function proves only the downloaded bundle's internal custody chain.
    """

    if (
        re.fullmatch(_WORKFLOW_NUMBER_PATTERN, expected_workflow_run_id) is None
        or re.fullmatch(
            _WORKFLOW_NUMBER_PATTERN,
            expected_workflow_run_attempt,
        )
        is None
        or re.fullmatch(_GIT_COMMIT_PATTERN, expected_source_commit) is None
    ):
        raise ModelRefreshStagingError("expected previous workflow identity is invalid")
    expected_names, before = _observe_previous_history_directory(history_dir)
    status = load_model_refresh_workflow_status(history_dir / WORKFLOW_STATUS_FILENAME)
    if (
        status.workflow_run_id != expected_workflow_run_id
        or status.workflow_run_attempt != expected_workflow_run_attempt
        or status.source_commit != expected_source_commit
    ):
        raise ModelRefreshStagingError(
            "downloaded refresh history belongs to another workflow run or source commit"
        )
    if status.disposition not in {
        ModelRefreshWorkflowDisposition.COMPLETED,
        ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
    }:
        raise ModelRefreshStagingError("downloaded refresh history is not a successful bundle")
    expected_artifacts = expected_names - {WORKFLOW_STATUS_FILENAME}
    if {binding.filename for binding in status.artifacts} != expected_artifacts:
        raise ModelRefreshStagingError(
            "downloaded refresh history differs from its workflow inventory"
        )

    try:
        registry = _load_staged_candidate_registry(history_dir / CANDIDATE_REGISTRY_FILENAME)
        source = load_model_refresh_source_evidence(history_dir / SOURCE_EVIDENCE_FILENAME)
        snapshot = load_model_refresh_snapshot(history_dir / SNAPSHOT_FILENAME)
        diff = load_model_refresh_diff(history_dir / DIFF_FILENAME)
        attempt = load_model_refresh_attempt(history_dir / ATTEMPT_FILENAME)
        freshness = load_model_refresh_freshness(history_dir / FRESHNESS_FILENAME)
    except ValueError as exc:
        raise ModelRefreshStagingError(
            "downloaded refresh history contains an invalid staged artifact"
        ) from exc
    artifacts: dict[str, BaseModel] = {
        CANDIDATE_REGISTRY_FILENAME: registry,
        SOURCE_EVIDENCE_FILENAME: source,
        SNAPSHOT_FILENAME: snapshot,
        DIFF_FILENAME: diff,
        ATTEMPT_FILENAME: attempt,
        FRESHNESS_FILENAME: freshness,
    }
    predecessor_present = status.previous_workflow_run_id is not None
    predecessor_files_present = _IMMEDIATE_PREDECESSOR_FILENAMES.issubset(expected_names)
    if predecessor_files_present is not predecessor_present:
        raise ModelRefreshStagingError(
            "downloaded refresh history predecessor inventory is inconsistent"
        )
    previous_status: ModelRefreshWorkflowStatus | None = None
    previous_registry: CandidateRegistry | None = None
    previous_source: ModelRefreshSourceEvidence | None = None
    previous_snapshot: ModelRefreshSnapshot | None = None
    if predecessor_present:
        try:
            previous_status = _load_staged_workflow_status(
                history_dir / PREVIOUS_WORKFLOW_STATUS_FILENAME,
                expected_filename=PREVIOUS_WORKFLOW_STATUS_FILENAME,
            )
            previous_registry = _load_staged_candidate_registry(
                history_dir / PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
                expected_filename=PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
            )
            previous_source = load_model_refresh_source_evidence(
                history_dir / PREVIOUS_SOURCE_EVIDENCE_FILENAME
            )
            previous_snapshot = load_model_refresh_snapshot(
                history_dir / PREVIOUS_SNAPSHOT_FILENAME
            )
        except ValueError as exc:
            raise ModelRefreshStagingError(
                "downloaded refresh history contains invalid predecessor evidence"
            ) from exc
        artifacts.update(
            {
                PREVIOUS_WORKFLOW_STATUS_FILENAME: previous_status,
                PREVIOUS_CANDIDATE_REGISTRY_FILENAME: previous_registry,
                PREVIOUS_SOURCE_EVIDENCE_FILENAME: previous_source,
                PREVIOUS_SNAPSHOT_FILENAME: previous_snapshot,
            }
        )
    policy_refresh = None
    if status.policy_projection_expected:
        try:
            policy_refresh = load_model_policy_eligibility_refresh_artifact(
                history_dir / POLICY_ELIGIBILITY_REFRESH_FILENAME
            )
        except ValueError as exc:
            raise ModelRefreshStagingError(
                "downloaded refresh history contains an invalid policy artifact"
            ) from exc
        artifacts[POLICY_ELIGIBILITY_REFRESH_FILENAME] = policy_refresh
    for filename, artifact in artifacts.items():
        _validate_status_artifact_binding(
            status=status,
            filename=filename,
            artifact=artifact,
        )
    if registry.created_at > source.retrieved_at or registry.created_at > snapshot.retrieved_at:
        raise ModelRefreshStagingError(
            "downloaded refresh history candidate registry postdates its observation"
        )

    try:
        replayed_snapshot = build_model_refresh_snapshot_from_source(
            source_evidence=source,
            candidate_registry=registry,
        )
        replayed_freshness = evaluate_model_refresh_freshness(
            observed_at=freshness.observed_at,
            snapshot=snapshot,
            soft_max_age_hours=status.soft_max_age_hours,
            hard_max_age_hours=status.hard_max_age_hours,
            production_selection_present=freshness.production_selection_present,
        )
        staged_time_freshness = evaluate_model_refresh_freshness(
            observed_at=max(status.validated_at, snapshot.retrieved_at),
            snapshot=snapshot,
            soft_max_age_hours=status.soft_max_age_hours,
            hard_max_age_hours=status.hard_max_age_hours,
            production_selection_present=freshness.production_selection_present,
        )
    except ValueError as exc:
        raise ModelRefreshStagingError(
            "downloaded refresh history cannot reproduce its current snapshot"
        ) from exc
    if (
        replayed_snapshot != snapshot
        or replayed_freshness != freshness
        or status.candidate_registry_sha256 != registry.registry_sha256
        or source.candidate_registry_sha256 != registry.registry_sha256
        or snapshot.candidate_registry_sha256 != registry.registry_sha256
        or diff.current_candidate_registry_sha256 != registry.registry_sha256
        or diff.current_snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.candidate_registry_sha256 != registry.registry_sha256
        or attempt.snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.diff_sha256 != diff.diff_sha256
        or attempt.status is not diff.status
        or diff.pricing_tolerance_fraction != status.pricing_tolerance_fraction
        or freshness.snapshot_sha256 != snapshot.snapshot_sha256
        or freshness.soft_max_age_hours != status.soft_max_age_hours
        or freshness.hard_max_age_hours != status.hard_max_age_hours
        or freshness.production_selection_present != bool(diff.selected_routes)
        or freshness.state is not ModelRefreshFreshnessState.CURRENT
        or staged_time_freshness.state is not ModelRefreshFreshnessState.CURRENT
        or abs(status.validated_at - snapshot.retrieved_at) > _MAX_CLOCK_SKEW
        or not (
            attempt.attempted_at
            <= snapshot.retrieved_at
            == diff.compared_at
            == freshness.observed_at
            <= status.validated_at + _MAX_CLOCK_SKEW
        )
    ):
        raise ModelRefreshStagingError("downloaded refresh history hash bindings are inconsistent")
    approved_routes = {
        (candidate.exact_model_id, candidate.approved_provider_endpoint)
        for candidate in registry.candidates
    }
    if any(
        (route.exact_model_id, route.provider_endpoint) not in approved_routes
        for route in diff.selected_routes
    ):
        raise ModelRefreshStagingError(
            "downloaded refresh history selected routes differ from its candidate registry"
        )
    if (diff.baseline_kind is RefreshBaselineKind.PREVIOUS_SNAPSHOT) is not predecessor_present:
        raise ModelRefreshStagingError(
            "downloaded refresh history baseline differs from its predecessor identity"
        )
    if diff.baseline_kind is RefreshBaselineKind.CANDIDATE_REGISTRY_HASH_ONLY:
        try:
            replayed_diff = diff_model_refresh(
                current=snapshot,
                candidate_registry=registry,
                pricing_tolerance_fraction=status.pricing_tolerance_fraction,
                compared_at=diff.compared_at,
                selected_routes=diff.selected_routes,
            )
        except ValueError as exc:
            raise ModelRefreshStagingError(
                "downloaded bootstrap history cannot reproduce its semantic diff"
            ) from exc
        if replayed_diff != diff:
            raise ModelRefreshStagingError(
                "downloaded bootstrap history differs from its reproduced semantic diff"
            )
    else:
        assert status.previous_workflow_run_id is not None
        assert status.previous_workflow_run_attempt is not None
        assert status.previous_workflow_status_sha256 is not None
        assert previous_status is not None
        assert previous_registry is not None
        assert previous_source is not None
        assert previous_snapshot is not None
        if (
            previous_status.workflow_run_id != status.previous_workflow_run_id
            or previous_status.workflow_run_attempt != status.previous_workflow_run_attempt
            or previous_status.workflow_status_sha256 != status.previous_workflow_status_sha256
            or previous_status.disposition
            not in {
                ModelRefreshWorkflowDisposition.COMPLETED,
                ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
            }
            or previous_status.candidate_registry_sha256 != previous_registry.registry_sha256
        ):
            raise ModelRefreshStagingError(
                "downloaded refresh history predecessor identity is inconsistent"
            )
        for predecessor_filename, predecessor_artifact in (
            (CANDIDATE_REGISTRY_FILENAME, previous_registry),
            (SOURCE_EVIDENCE_FILENAME, previous_source),
            (SNAPSHOT_FILENAME, previous_snapshot),
        ):
            _validate_status_artifact_binding(
                status=previous_status,
                filename=predecessor_filename,
                artifact=predecessor_artifact,
            )
        try:
            replayed_previous_snapshot = build_model_refresh_snapshot_from_source(
                source_evidence=previous_source,
                candidate_registry=previous_registry,
            )
            replayed_diff = diff_model_refresh(
                current=snapshot,
                previous=previous_snapshot,
                previous_source_evidence=previous_source,
                previous_candidate_registry=previous_registry,
                candidate_registry=registry,
                pricing_tolerance_fraction=status.pricing_tolerance_fraction,
                compared_at=diff.compared_at,
                selected_routes=diff.selected_routes,
            )
        except ValueError as exc:
            raise ModelRefreshStagingError(
                "downloaded chained history cannot reproduce its predecessor or semantic diff"
            ) from exc
        if (
            replayed_previous_snapshot != previous_snapshot
            or replayed_diff != diff
            or previous_registry.created_at > previous_source.retrieved_at
            or previous_registry.created_at > previous_snapshot.retrieved_at
            or previous_registry.created_at > registry.created_at
            or previous_snapshot.retrieved_at > snapshot.retrieved_at
            or previous_status.validated_at > status.validated_at + _MAX_CLOCK_SKEW
            or abs(previous_status.validated_at - previous_snapshot.retrieved_at) > _MAX_CLOCK_SKEW
        ):
            raise ModelRefreshStagingError(
                "downloaded chained history differs from its reproduced semantic diff"
            )
    if status.disposition is ModelRefreshWorkflowDisposition.COMPLETED:
        if attempt.status not in {
            ModelRefreshAttemptStatus.UNCHANGED,
            ModelRefreshAttemptStatus.CHANGED,
        }:
            raise ModelRefreshStagingError(
                "downloaded completed history has a blocking attempt status"
            )
    elif attempt.status is not ModelRefreshAttemptStatus.PRODUCTION_BLOCKED:
        raise ModelRefreshStagingError(
            "downloaded blocked history lacks a production-blocked attempt status"
        )
    if policy_refresh is not None and (
        policy_refresh.refresh_candidate_registry_sha256 != registry.registry_sha256
        or policy_refresh.refresh_source_evidence_sha256 != source.source_evidence_sha256
        or policy_refresh.refresh_snapshot_sha256 != snapshot.snapshot_sha256
        or policy_refresh.refresh_semantic_sha256 != snapshot.semantic_sha256
        or policy_refresh.refresh_catalog_snapshot_sha256 != snapshot.catalog_snapshot_sha256
        or policy_refresh.refresh_zdr_snapshot_sha256 != snapshot.zdr_snapshot_sha256
    ):
        raise ModelRefreshStagingError(
            "downloaded policy projection differs from its refresh history"
        )
    after = _observe_exact_private_directory(history_dir, expected_names=expected_names)
    if before != after:
        raise ModelRefreshStagingError("downloaded refresh history changed during validation")
    return ValidatedModelRefreshHistory(
        workflow_status=status,
        candidate_registry=registry,
        source_evidence=source,
        snapshot=snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
        previous_workflow_status=previous_status,
        previous_candidate_registry=previous_registry,
        previous_source_evidence=previous_source,
        previous_snapshot=previous_snapshot,
    )


def _load_and_validate_bundle(
    *,
    output_dir: Path,
    disposition: ModelRefreshWorkflowDisposition,
    registry: CandidateRegistry,
    previous_snapshot: ModelRefreshSnapshot | None,
    previous_source_evidence: ModelRefreshSourceEvidence | None,
    previous_candidate_registry: CandidateRegistry | None,
    expected_selected_routes: Sequence[SelectedModelRoute],
    pricing_tolerance_fraction: str,
    soft_max_age_hours: int,
    hard_max_age_hours: int,
    validated_at: datetime,
    policy_eligibility_artifact: ModelPolicyEligibilityArtifact | None,
    policy_source_observation: PolicyEligibilitySourceObservation | None,
    policy_checked_routes: tuple[PolicyEligibilityRoute, ...] | None,
) -> dict[str, BaseModel]:
    attempt = load_model_refresh_attempt(output_dir / ATTEMPT_FILENAME)
    if attempt.candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshStagingError("refresh attempt binds a different candidate registry")
    if disposition is ModelRefreshWorkflowDisposition.FAILED:
        if attempt.status is not ModelRefreshAttemptStatus.FAILED:
            raise ModelRefreshStagingError("failed refresh exit lacks a failed attempt artifact")
        return {ATTEMPT_FILENAME: attempt}

    source_evidence = load_model_refresh_source_evidence(output_dir / SOURCE_EVIDENCE_FILENAME)
    snapshot = load_model_refresh_snapshot(output_dir / SNAPSHOT_FILENAME)
    diff = load_model_refresh_diff(output_dir / DIFF_FILENAME)
    freshness = load_model_refresh_freshness(output_dir / FRESHNESS_FILENAME)
    policy_refresh = (
        load_model_policy_eligibility_refresh_artifact(
            output_dir / POLICY_ELIGIBILITY_REFRESH_FILENAME
        )
        if policy_eligibility_artifact is not None
        else None
    )
    if (
        registry.created_at > source_evidence.retrieved_at
        or registry.created_at > snapshot.retrieved_at
    ):
        raise ModelRefreshStagingError(
            "refresh candidate registry was created after its metadata observation"
        )
    try:
        reproduced_snapshot = build_model_refresh_snapshot_from_source(
            source_evidence=source_evidence,
            candidate_registry=registry,
        )
    except ValueError as exc:
        raise ModelRefreshStagingError(
            "refresh success bundle cannot reproduce its semantic snapshot"
        ) from exc
    if snapshot != reproduced_snapshot:
        raise ModelRefreshStagingError(
            "refresh success bundle differs from its reproduced semantic snapshot"
        )
    expected_routes = tuple(
        sorted(
            (
                SelectedModelRoute.model_validate(route.model_dump(mode="json"))
                for route in expected_selected_routes
            ),
            key=lambda route: (route.exact_model_id, route.provider_endpoint),
        )
    )
    if len(expected_routes) != len(
        {(route.exact_model_id, route.provider_endpoint) for route in expected_routes}
    ):
        raise ModelRefreshStagingError("expected refresh selected routes contain duplicates")
    if snapshot.authenticated_metadata is not True:
        raise ModelRefreshStagingError("refresh snapshot lacks authenticated metadata evidence")
    if snapshot.candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshStagingError("refresh snapshot binds a different candidate registry")
    if diff.current_candidate_registry_sha256 != registry.registry_sha256:
        raise ModelRefreshStagingError("refresh diff binds a different candidate registry")
    if (
        attempt.snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.diff_sha256 != diff.diff_sha256
        or diff.current_snapshot_sha256 != snapshot.snapshot_sha256
        or freshness.snapshot_sha256 != snapshot.snapshot_sha256
        or attempt.status is not diff.status
        or diff.selected_routes != expected_routes
        or diff.pricing_tolerance_fraction != pricing_tolerance_fraction
        or freshness.soft_max_age_hours != soft_max_age_hours
        or freshness.hard_max_age_hours != hard_max_age_hours
        or freshness.production_selection_present != bool(expected_routes)
    ):
        raise ModelRefreshStagingError("refresh success bundle has inconsistent hash bindings")
    if freshness.state is not ModelRefreshFreshnessState.CURRENT:
        raise ModelRefreshStagingError("newly emitted refresh evidence is not current")
    if not (
        attempt.attempted_at <= snapshot.retrieved_at == diff.compared_at == freshness.observed_at
    ):
        raise ModelRefreshStagingError("refresh success bundle time ordering is inconsistent")
    if abs(validated_at - snapshot.retrieved_at) > _MAX_CLOCK_SKEW:
        raise ModelRefreshStagingError(
            "refresh success bundle validation time differs from its observation beyond "
            "the clock-skew allowance"
        )
    trusted_observed_at = max(validated_at, snapshot.retrieved_at)
    try:
        trusted_freshness = evaluate_model_refresh_freshness(
            observed_at=trusted_observed_at,
            snapshot=snapshot,
            soft_max_age_hours=soft_max_age_hours,
            hard_max_age_hours=hard_max_age_hours,
            production_selection_present=bool(expected_routes),
        )
    except ValueError as exc:
        raise ModelRefreshStagingError(
            "refresh success bundle freshness cannot be reproduced"
        ) from exc
    if trusted_freshness.state is not ModelRefreshFreshnessState.CURRENT:
        raise ModelRefreshStagingError("refresh success bundle is not current at staging time")
    if policy_refresh is not None:
        assert policy_eligibility_artifact is not None
        assert policy_source_observation is not None
        assert policy_checked_routes is not None
        try:
            rebuilt_policy_refresh = build_model_policy_eligibility_refresh_artifact(
                refresh_snapshot=snapshot,
                policy_artifact=policy_eligibility_artifact,
                source_observation=policy_source_observation,
                checked_routes=policy_checked_routes,
            )
            verify_model_policy_eligibility_refresh_artifact(
                artifact=policy_refresh,
                refresh_snapshot=snapshot,
                policy_artifact=policy_eligibility_artifact,
                source_observation=policy_source_observation,
                checked_routes=policy_checked_routes,
                used_at=trusted_observed_at,
            )
        except ModelPolicyEligibilityRefreshError as exc:
            raise ModelRefreshStagingError(
                "policy refresh projection cannot be reproduced from exact inputs"
            ) from exc
        if policy_refresh != rebuilt_policy_refresh:
            raise ModelRefreshStagingError(
                "policy refresh projection differs from its reproduced evidence"
            )
    if diff.baseline_kind is RefreshBaselineKind.CANDIDATE_REGISTRY_HASH_ONLY:
        if (
            diff.baseline_sha256 != registry.registry_sha256
            or diff.baseline_candidate_registry_sha256 != registry.registry_sha256
            or previous_snapshot is not None
            or previous_source_evidence is not None
            or previous_candidate_registry is not None
        ):
            raise ModelRefreshStagingError("refresh bootstrap baseline binding is inconsistent")
    else:
        if (
            previous_snapshot is None
            or previous_source_evidence is None
            or previous_candidate_registry is None
        ):
            raise ModelRefreshStagingError(
                "refresh previous-snapshot baseline, source, or registry is unavailable "
                "for validation"
            )
        previous = ModelRefreshSnapshot.model_validate(previous_snapshot.model_dump(mode="json"))
        previous_source = ModelRefreshSourceEvidence.model_validate(
            previous_source_evidence.model_dump(mode="json")
        )
        previous_registry = CandidateRegistry.model_validate(
            previous_candidate_registry.model_dump(mode="json")
        )
        try:
            reproduced_previous = build_model_refresh_snapshot_from_source(
                source_evidence=previous_source,
                candidate_registry=previous_registry,
            )
        except ValueError as exc:
            raise ModelRefreshStagingError(
                "refresh previous snapshot cannot be reproduced from its source"
            ) from exc
        if (
            previous != reproduced_previous
            or previous.snapshot_sha256 != diff.baseline_sha256
            or previous.candidate_registry_sha256 != previous_registry.registry_sha256
            or diff.baseline_candidate_registry_sha256 != previous_registry.registry_sha256
            or previous_registry.created_at > previous_source.retrieved_at
            or previous_registry.created_at > previous.retrieved_at
            or previous_registry.created_at > registry.created_at
            or previous.retrieved_at > snapshot.retrieved_at
        ):
            raise ModelRefreshStagingError("refresh previous-snapshot baseline binding is invalid")
    try:
        expected_diff = diff_model_refresh(
            current=snapshot,
            previous=previous_snapshot,
            previous_source_evidence=previous_source_evidence,
            previous_candidate_registry=previous_candidate_registry,
            candidate_registry=registry,
            pricing_tolerance_fraction=pricing_tolerance_fraction,
            compared_at=diff.compared_at,
            selected_routes=expected_routes,
        )
    except ValueError as exc:
        raise ModelRefreshStagingError(
            "refresh success bundle cannot reproduce its semantic diff"
        ) from exc
    if diff != expected_diff:
        raise ModelRefreshStagingError(
            "refresh success bundle differs from its reproduced semantic diff"
        )
    if disposition is ModelRefreshWorkflowDisposition.COMPLETED:
        if attempt.status not in {
            ModelRefreshAttemptStatus.UNCHANGED,
            ModelRefreshAttemptStatus.CHANGED,
        }:
            raise ModelRefreshStagingError("successful refresh exit has a blocking attempt status")
    elif attempt.status is not ModelRefreshAttemptStatus.PRODUCTION_BLOCKED:
        raise ModelRefreshStagingError(
            "incomplete refresh exit lacks a production-blocked attempt status"
        )
    result: dict[str, BaseModel] = {
        CANDIDATE_REGISTRY_FILENAME: registry,
        SOURCE_EVIDENCE_FILENAME: source_evidence,
        SNAPSHOT_FILENAME: snapshot,
        DIFF_FILENAME: diff,
        ATTEMPT_FILENAME: attempt,
        FRESHNESS_FILENAME: freshness,
    }
    if policy_refresh is not None:
        result[POLICY_ELIGIBILITY_REFRESH_FILENAME] = policy_refresh
    return result


def _expected_output_names(
    disposition: ModelRefreshWorkflowDisposition,
    *,
    policy_projection_expected: bool,
) -> frozenset[str]:
    if disposition in {
        ModelRefreshWorkflowDisposition.COMPLETED,
        ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
    }:
        return (
            _REFRESH_POLICY_SUCCESS_FILENAMES
            if policy_projection_expected
            else _REFRESH_SUCCESS_FILENAMES
        )
    if disposition is ModelRefreshWorkflowDisposition.FAILED:
        return _FAILURE_FILENAMES
    return frozenset()


def _expected_staged_names(
    disposition: ModelRefreshWorkflowDisposition,
    *,
    policy_projection_expected: bool,
    predecessor_present: bool,
) -> frozenset[str]:
    if disposition in {
        ModelRefreshWorkflowDisposition.COMPLETED,
        ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED,
    }:
        expected = _POLICY_SUCCESS_FILENAMES if policy_projection_expected else _SUCCESS_FILENAMES
        return expected | _IMMEDIATE_PREDECESSOR_FILENAMES if predecessor_present else expected
    if disposition is ModelRefreshWorkflowDisposition.FAILED:
        return _FAILURE_FILENAMES
    return frozenset()


def _disposition_for_exit(exit_status: int) -> ModelRefreshWorkflowDisposition:
    if exit_status == 0:
        return ModelRefreshWorkflowDisposition.COMPLETED
    if exit_status == 6:
        return ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED
    if exit_status == 4:
        return ModelRefreshWorkflowDisposition.FAILED
    if exit_status == 78:
        return ModelRefreshWorkflowDisposition.PREREQUISITE_MISSING
    raise ModelRefreshStagingError("refresh exit status is not an accepted workflow result")


def _artifact_self_hash(filename: str, artifact: BaseModel) -> str:
    field = {
        CANDIDATE_REGISTRY_FILENAME: "registry_sha256",
        SOURCE_EVIDENCE_FILENAME: "source_evidence_sha256",
        SNAPSHOT_FILENAME: "snapshot_sha256",
        DIFF_FILENAME: "diff_sha256",
        ATTEMPT_FILENAME: "attempt_sha256",
        FRESHNESS_FILENAME: "freshness_sha256",
        POLICY_ELIGIBILITY_REFRESH_FILENAME: "artifact_sha256",
        PREVIOUS_WORKFLOW_STATUS_FILENAME: "workflow_status_sha256",
        PREVIOUS_CANDIDATE_REGISTRY_FILENAME: "registry_sha256",
        PREVIOUS_SOURCE_EVIDENCE_FILENAME: "source_evidence_sha256",
        PREVIOUS_SNAPSHOT_FILENAME: "snapshot_sha256",
    }.get(filename)
    value = getattr(artifact, field, None) if field is not None else None
    if isinstance(value, str) and re.fullmatch(_SHA256_PATTERN, value):
        return value
    raise ModelRefreshStagingError("refresh artifact lacks a recognized self-hash")


def _validate_status_artifact_binding(
    *,
    status: ModelRefreshWorkflowStatus,
    filename: str,
    artifact: BaseModel,
) -> None:
    matching = tuple(binding for binding in status.artifacts if binding.filename == filename)
    if len(matching) != 1:
        raise ModelRefreshStagingError(
            "refresh workflow status does not bind the exact previous artifact set"
        )
    raw = stable_json(artifact).encode("utf-8")
    binding = matching[0]
    if (
        binding.byte_count != len(raw)
        or binding.content_sha256 != hashlib.sha256(raw).hexdigest()
        or binding.artifact_sha256 != _artifact_self_hash(filename, artifact)
    ):
        raise ModelRefreshStagingError(
            "refresh workflow status artifact content binding is inconsistent"
        )


def _load_staged_candidate_registry(
    path: Path,
    *,
    expected_filename: str = CANDIDATE_REGISTRY_FILENAME,
) -> CandidateRegistry:
    if path.name != expected_filename:
        raise ModelRefreshStagingError("staged candidate registry filename is invalid")
    try:
        observation = read_json_evidence(
            evidence_root=path.parent,
            relative_path=path.name,
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        registry = CandidateRegistry.model_validate_json(observation.content, strict=True)
    except ValueError as exc:
        raise ModelRefreshStagingError(
            "staged candidate registry failed strict validation"
        ) from exc
    if observation.content != stable_json(registry).encode("utf-8"):
        raise ModelRefreshStagingError("staged candidate registry is not canonical")
    return registry


def _observe_previous_history_directory(
    path: Path,
) -> tuple[frozenset[str], tuple[tuple[str, tuple[int, ...]], ...]]:
    inventories = (
        _POLICY_SUCCESS_FILENAMES | _IMMEDIATE_PREDECESSOR_FILENAMES | {WORKFLOW_STATUS_FILENAME},
        _SUCCESS_FILENAMES | _IMMEDIATE_PREDECESSOR_FILENAMES | {WORKFLOW_STATUS_FILENAME},
        _POLICY_SUCCESS_FILENAMES | {WORKFLOW_STATUS_FILENAME},
        _SUCCESS_FILENAMES | {WORKFLOW_STATUS_FILENAME},
    )
    for expected_names in inventories:
        try:
            return expected_names, _observe_exact_private_directory(
                path,
                expected_names=expected_names,
            )
        except ModelRefreshStagingError:
            continue
    raise ModelRefreshStagingError(
        "downloaded refresh history must contain one exact successful artifact inventory"
    )


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
        raise ModelRefreshStagingError(f"{label} must use whole-second UTC")
    return value


def _canonical_fraction(value: str) -> Decimal:
    try:
        return parse_model_refresh_fraction(value)
    except ValueError as exc:
        raise ModelRefreshStagingError("refresh staging fraction is not canonical") from exc


def _observe_exact_private_directory(
    path: Path,
    *,
    expected_names: frozenset[str] | set[str],
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        raise ModelRefreshStagingError("refresh staging requires descriptor-safe directories")
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise ModelRefreshStagingError("refresh artifact directory is unavailable") from exc
    try:
        directory_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
        ):
            raise ModelRefreshStagingError("refresh artifact directory must be private")
        names = tuple(sorted(os.listdir(descriptor)))
        if set(names) != set(expected_names) or len(names) != len(expected_names):
            raise ModelRefreshStagingError("refresh artifact directory inventory is unexpected")
        observed: list[tuple[str, tuple[int, ...]]] = []
        for name in names:
            if "/" in name or name in {"", ".", ".."}:
                raise ModelRefreshStagingError("refresh artifact filename is unsafe")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
                or not 0 < metadata.st_size <= _MAX_ARTIFACT_BYTES
            ):
                raise ModelRefreshStagingError(
                    "refresh artifact must be private, bounded, regular, and unshared"
                )
            observed.append((name, _file_identity(metadata)))
        return tuple(observed)
    except OSError as exc:
        raise ModelRefreshStagingError("refresh artifact directory could not be observed") from exc
    finally:
        os.close(descriptor)


def _create_private_staging_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute.parent)
    if not absolute.parent.is_dir():
        raise ModelRefreshStagingError("refresh staging parent must already exist")
    try:
        os.mkdir(absolute, _PRIVATE_DIRECTORY_MODE)
    except OSError as exc:
        raise ModelRefreshStagingError("refresh staging directory must be fresh") from exc
    metadata = os.lstat(absolute)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        _remove_fresh_staging_directory(absolute)
        raise ModelRefreshStagingError("refresh staging directory is not private")
    return absolute


def _reject_linked_components(path: Path) -> None:
    cursor = path
    while True:
        if cursor.is_symlink() or cursor.is_junction():
            raise ModelRefreshStagingError("refresh artifact path may not traverse links")
        if cursor == cursor.parent:
            return
        cursor = cursor.parent


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _remove_fresh_staging_directory(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    quarantine = path.with_name(f".{path.name}.rejected-{uuid.uuid4().hex}")
    try:
        os.rename(path, quarantine)
        path = quarantine
    except OSError:
        pass
    for name in (
        *_POLICY_SUCCESS_FILENAMES,
        *_IMMEDIATE_PREDECESSOR_FILENAMES,
        WORKFLOW_STATUS_FILENAME,
    ):
        candidate = path / name
        try:
            if candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()
        except OSError:
            pass
    with suppress(OSError):
        path.rmdir()
