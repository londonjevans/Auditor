"""Exact non-authorizing transition from discovery to reviewed model identity.

The transition preserves the discovery registry as the immutable R0 evidence input
and emits a new R1 registry containing only the signed lineage decisions already
bound into calibration. Conditional role declarations are immutable discovery
inputs; preserving them grants no quality or production-selection authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from mmaudit.models.calibration import ModelCalibrationArtifact
from mmaudit.models.discovery import OpenRouterModelDiscoveryRunManifest
from mmaudit.models.lineage_authority import (
    ModelLineageAuthorityEnvelope,
    TrustedModelLineageReviewVerification,
    VerifiedModelLineageAuthority,
)
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateRegistry,
    LineageReviewStatus,
    OperatorLineageReview,
    seal_candidate_registry,
)
from mmaudit.orchestration.manifest import canonical_sha256


class ModelLineageRegistryTransitionError(ValueError):
    """Raised when exact R0 lineage evidence cannot produce a safe R1 registry."""


def build_identity_reviewed_candidate_registry(
    *,
    candidate_registry: CandidateRegistry,
    lineage_review_artifact: ModelLineageReviewArtifact,
    lineage_authority_envelope: ModelLineageAuthorityEnvelope,
    calibration_artifact: ModelCalibrationArtifact,
    discovery_run_manifest: OpenRouterModelDiscoveryRunManifest,
    trusted_lineage_verification: TrustedModelLineageReviewVerification,
    campaign_started_at: datetime,
    observed_at: datetime,
) -> CandidateRegistry:
    """Apply exact signed lineage decisions while retaining pending quality state.

    The detached signature is expected to have been verified before calibration was
    built.  This provider-free transition replays the durable structural bindings; it
    deliberately issues no runtime capability or production authority.
    """

    registry = _validated_registry(candidate_registry)
    review = _validated_review(lineage_review_artifact)
    envelope = _validated_envelope(lineage_authority_envelope)
    calibration = _validated_calibration(calibration_artifact)
    manifest = _validated_manifest(discovery_run_manifest)

    _require_rootless_pending_r0(registry)
    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    _require_review_matches_r0(
        registry=registry,
        candidate_ids=candidate_ids,
        review=review,
    )
    _require_envelope_matches_review(
        registry=registry,
        review=review,
        envelope=envelope,
        calibration=calibration,
    )
    _require_calibration_matches_lineage(
        registry=registry,
        candidate_ids=candidate_ids,
        review=review,
        envelope=envelope,
        calibration=calibration,
    )
    if type(trusted_lineage_verification) is not TrustedModelLineageReviewVerification:
        raise ModelLineageRegistryTransitionError(
            "R1 transition requires fresh trusted lineage verification"
        )
    try:
        verified_lineage = trusted_lineage_verification.require_for(
            candidate_registry=registry,
            discovery_manifest=manifest,
            campaign_started_at=campaign_started_at,
            observed_at=observed_at,
        )
    except ValueError as exc:
        raise ModelLineageRegistryTransitionError(
            "trusted lineage verification does not authorize the R1 campaign"
        ) from exc
    _require_verified_lineage_matches(
        review=review,
        envelope=envelope,
        calibration=calibration,
        verified=verified_lineage,
    )

    reviews_by_hash: dict[str, OperatorLineageReview] = {
        item.review_sha256: item for item in review.reviews
    }
    bindings_by_model = {binding.exact_model_id: binding for binding in review.candidate_bindings}
    transitioned: list[CandidateModel] = []
    for candidate in registry.candidates:
        binding = bindings_by_model[candidate.exact_model_id]
        decision = reviews_by_hash[binding.review_sha256]
        payload = candidate.model_dump(mode="json")
        payload["root_lineage"] = binding.root_lineage
        payload["lineage_review"] = decision.model_dump(mode="json")
        try:
            transitioned.append(CandidateModel.model_validate(payload))
        except ValueError as exc:
            raise ModelLineageRegistryTransitionError(
                f"reviewed candidate is inconsistent: {candidate.exact_model_id}"
            ) from exc

    result = seal_candidate_registry(
        created_at=registry.created_at,
        discovery_run_sha256=registry.discovery_run_sha256,
        candidates=tuple(transitioned),
    )
    _require_only_lineage_changed(source=registry, reviewed=result)
    return result


def _validated_registry(value: CandidateRegistry) -> CandidateRegistry:
    if type(value) is not CandidateRegistry:
        raise ModelLineageRegistryTransitionError("R0 candidate registry must be exact and typed")
    try:
        return CandidateRegistry.model_validate_json(value.model_dump_json(), strict=True)
    except ValueError as exc:
        raise ModelLineageRegistryTransitionError("R0 candidate registry is invalid") from exc


def _validated_review(value: ModelLineageReviewArtifact) -> ModelLineageReviewArtifact:
    if type(value) is not ModelLineageReviewArtifact:
        raise ModelLineageRegistryTransitionError("lineage review artifact must be exact and typed")
    try:
        return ModelLineageReviewArtifact.model_validate_json(
            value.model_dump_json(),
            strict=True,
        )
    except ValueError as exc:
        raise ModelLineageRegistryTransitionError("lineage review artifact is invalid") from exc


def _validated_envelope(value: ModelLineageAuthorityEnvelope) -> ModelLineageAuthorityEnvelope:
    if type(value) is not ModelLineageAuthorityEnvelope:
        raise ModelLineageRegistryTransitionError(
            "lineage authority envelope must be exact and typed"
        )
    try:
        return ModelLineageAuthorityEnvelope.model_validate_json(
            value.model_dump_json(),
            strict=True,
        )
    except ValueError as exc:
        raise ModelLineageRegistryTransitionError("lineage authority envelope is invalid") from exc


def _validated_calibration(value: ModelCalibrationArtifact) -> ModelCalibrationArtifact:
    if type(value) is not ModelCalibrationArtifact:
        raise ModelLineageRegistryTransitionError("calibration artifact must be exact and typed")
    try:
        return ModelCalibrationArtifact.model_validate_json(
            value.model_dump_json(),
            strict=True,
        )
    except ValueError as exc:
        raise ModelLineageRegistryTransitionError("calibration artifact is invalid") from exc


def _validated_manifest(
    value: OpenRouterModelDiscoveryRunManifest,
) -> OpenRouterModelDiscoveryRunManifest:
    if type(value) is not OpenRouterModelDiscoveryRunManifest:
        raise ModelLineageRegistryTransitionError("discovery manifest must be exact and typed")
    try:
        return OpenRouterModelDiscoveryRunManifest.model_validate_json(
            value.model_dump_json(),
            strict=True,
        )
    except ValueError as exc:
        raise ModelLineageRegistryTransitionError("discovery manifest is invalid") from exc


def _require_rootless_pending_r0(registry: CandidateRegistry) -> None:
    for candidate in registry.candidates:
        if (
            candidate.root_lineage is not None
            or candidate.lineage_review.status is not LineageReviewStatus.PENDING
            or candidate.benchmark_status is not CandidateBenchmarkStatus.PENDING
            or candidate.benchmark_artifact_sha256 is not None
            or candidate.qualification_expires_at is not None
        ):
            raise ModelLineageRegistryTransitionError(
                "R0 candidate registry must be rootless, review-pending, and quality-pending"
            )


def _require_review_matches_r0(
    *,
    registry: CandidateRegistry,
    candidate_ids: tuple[str, ...],
    review: ModelLineageReviewArtifact,
) -> None:
    binding_ids = tuple(binding.exact_model_id for binding in review.candidate_bindings)
    if (
        review.candidate_registry_sha256 != registry.registry_sha256
        or review.discovery_manifest_sha256 != registry.discovery_run_sha256
        or binding_ids != candidate_ids
    ):
        raise ModelLineageRegistryTransitionError(
            "lineage review artifact differs from the exact R0 registry"
        )
    if any(
        binding.decision is LineageReviewStatus.PENDING for binding in review.candidate_bindings
    ):
        raise ModelLineageRegistryTransitionError("R1 lineage decisions must all be complete")


def _require_envelope_matches_review(
    *,
    registry: CandidateRegistry,
    review: ModelLineageReviewArtifact,
    envelope: ModelLineageAuthorityEnvelope,
    calibration: ModelCalibrationArtifact,
) -> None:
    statement = envelope.statement
    candidate_binding_set_sha256 = canonical_sha256(
        [binding.model_dump(mode="json") for binding in review.candidate_bindings]
    )
    try:
        refresh_deadline = review.refresh_retrieved_at + timedelta(hours=review.soft_max_age_hours)
    except OverflowError as exc:
        raise ModelLineageRegistryTransitionError(
            "lineage review freshness deadline is outside the supported time range"
        ) from exc
    if (
        statement.review_artifact_sha256 != review.artifact_sha256
        or statement.candidate_registry_sha256 != registry.registry_sha256
        or statement.discovery_manifest_sha256 != review.discovery_manifest_sha256
        or statement.discovery_candidate_set_sha256 != review.discovery_candidate_set_sha256
        or statement.refresh_source_evidence_sha256 != review.refresh_source_evidence_sha256
        or statement.refresh_snapshot_sha256 != review.refresh_snapshot_sha256
        or statement.refresh_semantic_sha256 != review.refresh_semantic_sha256
        or statement.candidate_binding_set_sha256 != candidate_binding_set_sha256
        or statement.approved_root_lineages != review.approved_root_lineages
        or statement.signed_at < review.created_at
        or statement.expires_at > review.expires_at
        or statement.expires_at > refresh_deadline
        or not statement.signed_at <= calibration.created_at < statement.expires_at
    ):
        raise ModelLineageRegistryTransitionError(
            "lineage authority envelope differs from the R0 review evidence"
        )


def _require_calibration_matches_lineage(
    *,
    registry: CandidateRegistry,
    candidate_ids: tuple[str, ...],
    review: ModelLineageReviewArtifact,
    envelope: ModelLineageAuthorityEnvelope,
    calibration: ModelCalibrationArtifact,
) -> None:
    calibration_ids = tuple(item.exact_model_id for item in calibration.candidates)
    expected_candidate_set_sha256 = canonical_sha256(list(candidate_ids))
    if (
        calibration.candidate_registry_sha256 != registry.registry_sha256
        or calibration.discovery_manifest_sha256 != registry.discovery_run_sha256
        or calibration.candidate_set_sha256 != expected_candidate_set_sha256
        or calibration.lineage_review_artifact_sha256 != review.artifact_sha256
        or calibration.lineage_authority_envelope_sha256 != envelope.authority_envelope_sha256
        or calibration_ids != candidate_ids
    ):
        raise ModelLineageRegistryTransitionError(
            "calibration artifact differs from the exact R0 lineage evidence"
        )

    binding_by_model = {binding.exact_model_id: binding for binding in review.candidate_bindings}
    for observation in calibration.candidates:
        binding = binding_by_model[observation.exact_model_id]
        if (
            observation.root_lineage != binding.root_lineage
            or observation.lineage_binding_sha256 != binding.binding_sha256
        ):
            raise ModelLineageRegistryTransitionError(
                f"calibration lineage projection differs: {observation.exact_model_id}"
            )


def _require_verified_lineage_matches(
    *,
    review: ModelLineageReviewArtifact,
    envelope: ModelLineageAuthorityEnvelope,
    calibration: ModelCalibrationArtifact,
    verified: VerifiedModelLineageAuthority,
) -> None:
    bindings = {binding.exact_model_id: binding for binding in review.candidate_bindings}
    reviews = {item.review_sha256: item for item in review.reviews}
    expected = tuple(
        (
            binding.exact_model_id,
            binding.decision,
            binding.root_lineage,
            reviews[binding.review_sha256].reviewed_at,
            binding.binding_sha256,
        )
        for binding in review.candidate_bindings
    )
    observed = tuple(
        (
            item.exact_model_id,
            item.decision,
            item.root_lineage,
            item.reviewed_at,
            item.lineage_binding_sha256,
        )
        for item in verified.candidates
    )
    if (
        verified.review_artifact_sha256 != review.artifact_sha256
        or verified.authority_envelope_sha256 != envelope.authority_envelope_sha256
        or calibration.lineage_review_artifact_sha256 != verified.review_artifact_sha256
        or calibration.lineage_authority_envelope_sha256 != verified.authority_envelope_sha256
        or expected != observed
        or tuple(bindings) != tuple(item.exact_model_id for item in verified.candidates)
    ):
        raise ModelLineageRegistryTransitionError(
            "trusted lineage projection differs from review, envelope, or calibration"
        )


def _require_only_lineage_changed(
    *,
    source: CandidateRegistry,
    reviewed: CandidateRegistry,
) -> None:
    if (
        reviewed.created_at != source.created_at
        or reviewed.discovery_run_sha256 != source.discovery_run_sha256
        or len(reviewed.candidates) != len(source.candidates)
    ):
        raise ModelLineageRegistryTransitionError("R1 registry changed immutable R0 inventory")
    for before, after in zip(source.candidates, reviewed.candidates, strict=True):
        before_values = _candidate_without_lineage(before)
        after_values = _candidate_without_lineage(after)
        if before_values != after_values:
            raise ModelLineageRegistryTransitionError(
                f"R1 registry changed non-lineage candidate state: {before.exact_model_id}"
            )
        if (
            after.lineage_review.status is LineageReviewStatus.PENDING
            or after.benchmark_status is not CandidateBenchmarkStatus.PENDING
            or after.benchmark_artifact_sha256 is not None
            or after.qualification_expires_at is not None
        ):
            raise ModelLineageRegistryTransitionError(
                f"R1 registry gained quality or selection state: {after.exact_model_id}"
            )


def _candidate_without_lineage(candidate: CandidateModel) -> dict[str, Any]:
    """Return candidate state excluding the only fields this transition may change."""

    return candidate.model_dump(mode="json", exclude={"root_lineage", "lineage_review"})
