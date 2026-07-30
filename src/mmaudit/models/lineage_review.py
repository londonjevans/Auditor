"""Provider-free binding for operator-reviewed model root lineages.

This artifact records lineage identity decisions only. It cannot grant model quality,
production-selection, or source-egress authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateRegistry,
    LineageReviewStatus,
    OperatorLineageReview,
    validate_candidate_registry_discovery,
)
from mmaudit.models.refresh import (
    ModelRefreshFreshness,
    ModelRefreshFreshnessState,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
    build_model_refresh_snapshot_from_source,
    evaluate_model_refresh_freshness,
    model_variant_family_key,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_json_evidence, write_json_evidence

LINEAGE_REVIEW_FILENAME = "model-lineage-review.json"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_LINEAGE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_MAX_CANDIDATES = 128
_MAX_REVIEW_EVIDENCE_BYTES = 2_000_000
_MAX_TOTAL_REVIEW_EVIDENCE_BYTES = 20_000_000
_MAX_ARTIFACT_BYTES = 5_000_000


class ModelLineageReviewError(ValueError):
    """Raised when lineage evidence cannot satisfy the non-authorizing contract."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ModelLineageDecision(OperatorLineageReview):
    """Deep-immutable operator decision retained inside the self-hashed artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ModelLineageReviewEvidenceBinding(_FrozenModel):
    """Exact bounded evidence bytes used by one operator decision."""

    review_sha256: str = Field(pattern=_SHA256_PATTERN)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    byte_count: int = Field(ge=1, le=_MAX_REVIEW_EVIDENCE_BYTES)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def binding_is_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("lineage review evidence binding self-hash is inconsistent")
        return self


class ModelLineageCandidateBinding(_FrozenModel):
    """One exact candidate joined to discovery, refresh, and operator review evidence."""

    exact_model_id: str
    canonical_model_slug: str
    variant_family_key: str
    approved_provider_endpoint: str = Field(min_length=1, max_length=200)
    approved_provider_name: str = Field(min_length=1, max_length=200)
    endpoint_tag: str | None = Field(default=None, min_length=1, max_length=200)
    endpoint_slug: str | None = Field(default=None, min_length=1, max_length=200)
    discovery_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_model_state_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_route_sha256: str = Field(pattern=_SHA256_PATTERN)
    review_sha256: str = Field(pattern=_SHA256_PATTERN)
    decision: LineageReviewStatus
    root_lineage: str | None = Field(default=None, pattern=_LINEAGE_PATTERN)
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug", "variant_family_key")
    @classmethod
    def model_ids_are_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def binding_is_decided_and_self_hashed(self) -> Self:
        if self.exact_model_id.split("/", 1)[0] != self.canonical_model_slug.split("/", 1)[0]:
            raise ValueError("lineage candidate canonical slug changes model author")
        if self.variant_family_key != model_variant_family_key(self.exact_model_id):
            raise ValueError("lineage candidate variant-family key is inconsistent")
        if self.endpoint_tag is None and self.endpoint_slug is None:
            raise ValueError("lineage candidate binding requires an exact route identity")
        if self.approved_provider_endpoint not in {self.endpoint_tag, self.endpoint_slug}:
            raise ValueError("lineage candidate route differs from its tag and slug")
        if self.approved_provider_name != self.approved_provider_name.strip() or any(
            not character.isprintable() for character in self.approved_provider_name
        ):
            raise ValueError("lineage candidate provider name is invalid")
        if self.decision is LineageReviewStatus.PENDING:
            raise ValueError("lineage candidate binding cannot retain a pending decision")
        if self.decision is LineageReviewStatus.APPROVED:
            if self.root_lineage is None:
                raise ValueError("approved lineage candidate requires a root lineage")
        elif self.root_lineage is not None:
            raise ValueError("rejected lineage candidate cannot claim a root lineage")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("lineage candidate binding self-hash is inconsistent")
        return self


class ModelLineageReviewArtifact(_FrozenModel):
    """Exact review overlay that deliberately carries no runtime authority."""

    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    expires_at: datetime
    source_scope: Literal["PUBLIC_OPEN_SOURCE_ONLY"] = "PUBLIC_OPEN_SOURCE_ONLY"
    purpose: Literal["LINEAGE_IDENTITY_ONLY"] = "LINEAGE_IDENTITY_ONLY"
    quality_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    evidence_class: Literal["PROVIDER_FREE_STRUCTURAL"] = "PROVIDER_FREE_STRUCTURAL"
    provider_observation_authenticity: Literal["NOT_INDEPENDENTLY_PROVEN"] = (
        "NOT_INDEPENDENTLY_PROVEN"
    )
    operator_decision_authenticity: Literal["NOT_INDEPENDENTLY_PROVEN"] = "NOT_INDEPENDENTLY_PROVEN"
    source_egress_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_candidate_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_semantic_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_retrieved_at: datetime
    refresh_freshness_sha256: str = Field(pattern=_SHA256_PATTERN)
    soft_max_age_hours: int = Field(ge=1, le=24 * 30)
    hard_max_age_hours: int = Field(ge=2, le=24 * 90)
    reviews: tuple[ModelLineageDecision, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    evidence_bindings: tuple[ModelLineageReviewEvidenceBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    candidate_bindings: tuple[ModelLineageCandidateBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    approved_root_lineages: tuple[str, ...] = Field(max_length=_MAX_CANDIDATES)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("created_at", "expires_at", "refresh_retrieved_at")
    @classmethod
    def timestamps_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="lineage review artifact time")

    @field_validator("approved_root_lineages")
    @classmethod
    def approved_roots_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            len(root) != 71
            or not root.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in root[7:])
            for root in value
        ):
            raise ValueError("approved root lineages must be canonical, unique, and sorted")
        return value

    @field_validator(
        "source_egress_authorized",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("lineage review authority flags must be literal false")
        return value

    @model_validator(mode="after")
    def artifact_is_exact_non_authorizing_and_self_hashed(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("lineage review artifact must expire after creation")
        if self.refresh_retrieved_at > self.created_at:
            raise ValueError("lineage review refresh cannot postdate artifact creation")
        if self.hard_max_age_hours <= self.soft_max_age_hours:
            raise ValueError("lineage review hard age must exceed its soft age")

        ordered_reviews = tuple(
            sorted(
                self.reviews, key=lambda review: (review.reviewed_model_ids, review.review_sha256)
            )
        )
        if self.reviews != ordered_reviews or len(
            {review.review_sha256 for review in self.reviews}
        ) != len(self.reviews):
            raise ValueError("lineage reviews must be unique and canonically ordered")
        if any(review.status is LineageReviewStatus.PENDING for review in self.reviews):
            raise ValueError("lineage review artifact cannot contain a pending decision")
        if any(
            review.reviewed_at is None
            or not self.refresh_retrieved_at <= review.reviewed_at <= self.created_at
            for review in self.reviews
        ):
            raise ValueError("lineage review time is outside the refreshed evidence window")

        evidence_review_hashes = tuple(binding.review_sha256 for binding in self.evidence_bindings)
        if evidence_review_hashes != tuple(sorted(set(evidence_review_hashes))):
            raise ValueError("lineage evidence bindings must be unique and sorted by review")
        reviews_by_hash = {review.review_sha256: review for review in self.reviews}
        if set(evidence_review_hashes) != set(reviews_by_hash):
            raise ValueError("lineage evidence bindings must exactly cover the reviews")
        if any(
            binding.evidence_sha256 != reviews_by_hash[binding.review_sha256].evidence_sha256
            for binding in self.evidence_bindings
        ):
            raise ValueError("lineage evidence binding differs from its operator review")
        if sum(binding.byte_count for binding in self.evidence_bindings) > (
            _MAX_TOTAL_REVIEW_EVIDENCE_BYTES
        ):
            raise ValueError("lineage review evidence exceeds the total byte limit")

        candidate_ids = tuple(binding.exact_model_id for binding in self.candidate_bindings)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("lineage candidate bindings must be unique and sorted")
        review_owner: dict[str, str] = {}
        for review in self.reviews:
            for model_id in review.reviewed_model_ids:
                previous = review_owner.setdefault(model_id, review.review_sha256)
                if previous != review.review_sha256:
                    raise ValueError("lineage review groups overlap")
        if set(review_owner) != set(candidate_ids):
            raise ValueError("lineage reviews must cover the candidate set exactly once")

        canonical_groups: dict[str, tuple[LineageReviewStatus, str | None, str]] = {}
        variant_groups: dict[str, tuple[LineageReviewStatus, str | None, str]] = {}
        root_reviews: dict[str, str] = {}
        for binding in self.candidate_bindings:
            bound_review = reviews_by_hash.get(binding.review_sha256)
            if (
                bound_review is None
                or binding.exact_model_id not in bound_review.reviewed_model_ids
                or binding.decision is not bound_review.status
                or binding.root_lineage != bound_review.root_lineage
            ):
                raise ValueError("lineage candidate differs from its operator review")
            review_identity = (binding.decision, binding.root_lineage, binding.review_sha256)
            _require_consistent_group(
                canonical_groups,
                binding.canonical_model_slug,
                review_identity,
                label="canonical model slug",
            )
            _require_consistent_group(
                variant_groups,
                binding.variant_family_key,
                review_identity,
                label="model variant family",
            )
            if binding.root_lineage is not None:
                previous_review = root_reviews.setdefault(
                    binding.root_lineage,
                    binding.review_sha256,
                )
                if previous_review != binding.review_sha256:
                    raise ValueError("one root lineage is split across review artifacts")

        expected_roots = tuple(
            sorted(
                {
                    review.root_lineage
                    for review in self.reviews
                    if review.status is LineageReviewStatus.APPROVED
                    and review.root_lineage is not None
                }
            )
        )
        if self.approved_root_lineages != expected_roots:
            raise ValueError("approved root lineage projection is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"artifact_sha256"}))
        if self.artifact_sha256 != expected:
            raise ValueError("lineage review artifact self-hash is inconsistent")
        return self

    def as_dict(self) -> dict[str, Any]:
        """Return a stable, non-secret JSON-compatible representation."""

        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Self:
        """Validate an untrusted serialized lineage review artifact."""

        try:
            encoded = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ModelLineageReviewError("lineage review artifact is not finite JSON") from exc
        if not encoded or len(encoded) > _MAX_ARTIFACT_BYTES:
            raise ModelLineageReviewError("lineage review artifact exceeds the byte limit")
        try:
            return cls.model_validate_json(encoded, strict=True)
        except ValueError as exc:
            raise ModelLineageReviewError("lineage review artifact is invalid") from exc


def build_model_lineage_review_artifact(
    *,
    created_at: datetime,
    expires_at: datetime,
    candidate_registry: CandidateRegistry,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    refresh_source_evidence: ModelRefreshSourceEvidence,
    refresh_snapshot: ModelRefreshSnapshot,
    refresh_freshness: ModelRefreshFreshness,
    expected_soft_max_age_hours: int,
    expected_hard_max_age_hours: int,
    reviews: tuple[OperatorLineageReview, ...],
    review_evidence_by_sha256: Mapping[str, bytes],
) -> ModelLineageReviewArtifact:
    """Build one exact, current, non-authorizing lineage review overlay."""

    created_at = _whole_second_utc(created_at, label="lineage review creation time")
    expires_at = _whole_second_utc(expires_at, label="lineage review expiry time")
    if expires_at <= created_at:
        raise ModelLineageReviewError("lineage review expiry must follow creation")

    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        discovery_manifest.model_dump(mode="json")
    )
    evidence = tuple(
        OpenRouterModelDiscoveryEvidence.model_validate(item.model_dump(mode="json"))
        for item in discovery_evidence
    )
    source = ModelRefreshSourceEvidence.model_validate(
        refresh_source_evidence.model_dump(mode="json")
    )
    snapshot = ModelRefreshSnapshot.model_validate(refresh_snapshot.model_dump(mode="json"))
    freshness = ModelRefreshFreshness.model_validate(refresh_freshness.model_dump(mode="json"))
    validated_reviews = tuple(
        ModelLineageDecision.model_validate(review.model_dump(mode="json")) for review in reviews
    )

    _require_pending_source_registry(registry)
    try:
        validate_candidate_registry_discovery(
            registry=registry,
            run_manifest=manifest,
            evidence=evidence,
        )
    except ValueError as exc:
        raise ModelLineageReviewError(
            "lineage review candidate registry is not backed by exact discovery evidence"
        ) from exc
    if source.retrieved_at < registry.created_at:
        raise ModelLineageReviewError("lineage refresh predates candidate discovery")
    replayed_snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    if replayed_snapshot != snapshot:
        raise ModelLineageReviewError("lineage refresh snapshot does not replay from source")
    _require_current_freshness(
        created_at=created_at,
        snapshot=snapshot,
        supplied=freshness,
        expected_soft_max_age_hours=expected_soft_max_age_hours,
        expected_hard_max_age_hours=expected_hard_max_age_hours,
    )

    review_by_model = _validate_reviews(
        reviews=validated_reviews,
        candidate_ids=tuple(candidate.exact_model_id for candidate in registry.candidates),
        refresh_retrieved_at=snapshot.retrieved_at,
        created_at=created_at,
    )
    evidence_bindings = _bind_review_evidence(
        reviews=validated_reviews,
        supplied=review_evidence_by_sha256,
    )
    candidate_bindings = _bind_candidates(
        registry=registry,
        discovery_evidence=evidence,
        snapshot=snapshot,
        review_by_model=review_by_model,
    )
    ordered_reviews = tuple(
        sorted(
            validated_reviews,
            key=lambda review: (review.reviewed_model_ids, review.review_sha256),
        )
    )
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": _utc_json_time(created_at),
        "expires_at": _utc_json_time(expires_at),
        "source_scope": "PUBLIC_OPEN_SOURCE_ONLY",
        "purpose": "LINEAGE_IDENTITY_ONLY",
        "quality_status": "NOT_EVALUATED",
        "evidence_class": "PROVIDER_FREE_STRUCTURAL",
        "provider_observation_authenticity": "NOT_INDEPENDENTLY_PROVEN",
        "operator_decision_authenticity": "NOT_INDEPENDENTLY_PROVEN",
        "source_egress_authorized": False,
        "production_selection_authorized": False,
        "candidate_registry_sha256": registry.registry_sha256,
        "discovery_manifest_sha256": manifest.manifest_sha256,
        "discovery_candidate_set_sha256": manifest.candidate_set_sha256,
        "refresh_source_evidence_sha256": source.source_evidence_sha256,
        "refresh_snapshot_sha256": snapshot.snapshot_sha256,
        "refresh_semantic_sha256": snapshot.semantic_sha256,
        "refresh_retrieved_at": _utc_json_time(snapshot.retrieved_at),
        "refresh_freshness_sha256": freshness.freshness_sha256,
        "soft_max_age_hours": freshness.soft_max_age_hours,
        "hard_max_age_hours": freshness.hard_max_age_hours,
        "reviews": [review.model_dump(mode="json") for review in ordered_reviews],
        "evidence_bindings": [binding.model_dump(mode="json") for binding in evidence_bindings],
        "candidate_bindings": [binding.model_dump(mode="json") for binding in candidate_bindings],
        "approved_root_lineages": sorted(
            {
                review.root_lineage
                for review in ordered_reviews
                if review.status is LineageReviewStatus.APPROVED and review.root_lineage is not None
            }
        ),
    }
    values["artifact_sha256"] = canonical_sha256(values)
    try:
        return ModelLineageReviewArtifact.model_validate(values)
    except ValueError as exc:
        raise ModelLineageReviewError("lineage review artifact is inconsistent") from exc


def validate_model_lineage_review_artifact(
    *,
    artifact: ModelLineageReviewArtifact,
    observed_at: datetime,
    candidate_registry: CandidateRegistry,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    refresh_source_evidence: ModelRefreshSourceEvidence,
    refresh_snapshot: ModelRefreshSnapshot,
    refresh_freshness: ModelRefreshFreshness,
    expected_soft_max_age_hours: int,
    expected_hard_max_age_hours: int,
    review_evidence_by_sha256: Mapping[str, bytes],
) -> None:
    """Rebuild the overlay and reject expired or stale runtime evidence."""

    observed_at = _whole_second_utc(observed_at, label="lineage review validation time")
    validated = ModelLineageReviewArtifact.model_validate(artifact.model_dump(mode="json"))
    if observed_at < validated.created_at:
        raise ModelLineageReviewError("lineage review artifact is future-dated")
    if observed_at >= validated.expires_at:
        raise ModelLineageReviewError("lineage review artifact is expired")
    expected = build_model_lineage_review_artifact(
        created_at=validated.created_at,
        expires_at=validated.expires_at,
        candidate_registry=candidate_registry,
        discovery_manifest=discovery_manifest,
        discovery_evidence=discovery_evidence,
        refresh_source_evidence=refresh_source_evidence,
        refresh_snapshot=refresh_snapshot,
        refresh_freshness=refresh_freshness,
        expected_soft_max_age_hours=expected_soft_max_age_hours,
        expected_hard_max_age_hours=expected_hard_max_age_hours,
        reviews=validated.reviews,
        review_evidence_by_sha256=review_evidence_by_sha256,
    )
    if expected != validated:
        raise ModelLineageReviewError("lineage review artifact differs from current evidence")
    try:
        current = evaluate_model_refresh_freshness(
            observed_at=observed_at,
            snapshot=refresh_snapshot,
            soft_max_age_hours=expected_soft_max_age_hours,
            hard_max_age_hours=expected_hard_max_age_hours,
            production_selection_present=False,
        )
    except ValueError as exc:
        raise ModelLineageReviewError("trusted lineage refresh age policy is invalid") from exc
    if current.state is not ModelRefreshFreshnessState.CURRENT:
        raise ModelLineageReviewError("lineage review refresh evidence is no longer current")


def write_model_lineage_review_artifact(
    output_dir: Path,
    artifact: ModelLineageReviewArtifact,
) -> None:
    """Write one fresh private canonical lineage review artifact."""

    validated = ModelLineageReviewArtifact.model_validate(artifact.model_dump(mode="json"))
    write_json_evidence(
        evidence_root=output_dir,
        relative_path=LINEAGE_REVIEW_FILENAME,
        value=validated,
        max_bytes=_MAX_ARTIFACT_BYTES,
    )


def load_model_lineage_review_artifact(
    output_dir: Path,
) -> ModelLineageReviewArtifact:
    """Load and structurally validate one private lineage review artifact."""

    observation = read_json_evidence(
        evidence_root=output_dir,
        relative_path=LINEAGE_REVIEW_FILENAME,
        max_bytes=_MAX_ARTIFACT_BYTES,
    )
    if not isinstance(observation.value, dict):
        raise ModelLineageReviewError("lineage review artifact must be a JSON object")
    try:
        return ModelLineageReviewArtifact.model_validate_json(
            observation.content,
            strict=True,
        )
    except ValueError as exc:
        raise ModelLineageReviewError("lineage review artifact is invalid") from exc


def _require_pending_source_registry(registry: CandidateRegistry) -> None:
    for candidate in registry.candidates:
        if (
            candidate.root_lineage is not None
            or candidate.lineage_review.status is not LineageReviewStatus.PENDING
            or candidate.benchmark_status is not CandidateBenchmarkStatus.PENDING
        ):
            raise ModelLineageReviewError(
                "lineage review overlay requires a pending, rootless, unqualified registry"
            )


def _require_current_freshness(
    *,
    created_at: datetime,
    snapshot: ModelRefreshSnapshot,
    supplied: ModelRefreshFreshness,
    expected_soft_max_age_hours: int,
    expected_hard_max_age_hours: int,
) -> None:
    if supplied.observed_at != created_at:
        raise ModelLineageReviewError(
            "lineage refresh freshness must be observed at artifact creation"
        )
    try:
        expected = evaluate_model_refresh_freshness(
            observed_at=created_at,
            snapshot=snapshot,
            soft_max_age_hours=expected_soft_max_age_hours,
            hard_max_age_hours=expected_hard_max_age_hours,
            production_selection_present=supplied.production_selection_present,
        )
    except ValueError as exc:
        raise ModelLineageReviewError("trusted lineage refresh age policy is invalid") from exc
    if expected != supplied:
        raise ModelLineageReviewError(
            "lineage refresh freshness differs from the trusted age policy"
        )
    if supplied.state is not ModelRefreshFreshnessState.CURRENT:
        raise ModelLineageReviewError("lineage review requires current refresh evidence")


def _validate_reviews(
    *,
    reviews: tuple[OperatorLineageReview, ...],
    candidate_ids: tuple[str, ...],
    refresh_retrieved_at: datetime,
    created_at: datetime,
) -> dict[str, OperatorLineageReview]:
    if not reviews or len(reviews) > _MAX_CANDIDATES:
        raise ModelLineageReviewError("lineage reviews must be non-empty and bounded")
    by_model: dict[str, OperatorLineageReview] = {}
    seen_hashes: set[str] = set()
    for review in reviews:
        if review.review_sha256 in seen_hashes:
            raise ModelLineageReviewError("lineage review artifact is duplicated")
        seen_hashes.add(review.review_sha256)
        if review.status is LineageReviewStatus.PENDING:
            raise ModelLineageReviewError("lineage review decision is still pending")
        if review.reviewed_at is None or review.evidence_sha256 is None:
            raise ModelLineageReviewError("lineage review decision lacks dated evidence")
        if not refresh_retrieved_at <= review.reviewed_at <= created_at:
            raise ModelLineageReviewError(
                "lineage review time is outside the refreshed evidence window"
            )
        for model_id in review.reviewed_model_ids:
            if model_id in by_model:
                raise ModelLineageReviewError("lineage review groups overlap")
            by_model[model_id] = review
    if set(by_model) != set(candidate_ids):
        raise ModelLineageReviewError("lineage reviews do not exactly cover the candidate set")
    return by_model


def _bind_review_evidence(
    *,
    reviews: tuple[OperatorLineageReview, ...],
    supplied: Mapping[str, bytes],
) -> tuple[ModelLineageReviewEvidenceBinding, ...]:
    expected_hashes = {
        review.evidence_sha256 for review in reviews if review.evidence_sha256 is not None
    }
    if set(supplied) != expected_hashes:
        raise ModelLineageReviewError(
            "lineage review evidence bytes do not exactly cover the decisions"
        )
    total_bytes = 0
    bindings: list[ModelLineageReviewEvidenceBinding] = []
    for review in sorted(reviews, key=lambda item: item.review_sha256):
        assert review.evidence_sha256 is not None
        content = supplied[review.evidence_sha256]
        if not isinstance(content, bytes) or not content:
            raise ModelLineageReviewError("lineage review evidence must be non-empty bytes")
        byte_count = len(content)
        total_bytes += byte_count
        if byte_count > _MAX_REVIEW_EVIDENCE_BYTES:
            raise ModelLineageReviewError("lineage review evidence exceeds the per-item limit")
        if hashlib.sha256(content).hexdigest() != review.evidence_sha256:
            raise ModelLineageReviewError("lineage review evidence hash is inconsistent")
        values: dict[str, Any] = {
            "review_sha256": review.review_sha256,
            "evidence_sha256": review.evidence_sha256,
            "byte_count": byte_count,
        }
        values["binding_sha256"] = canonical_sha256(values)
        bindings.append(ModelLineageReviewEvidenceBinding.model_validate(values))
    if total_bytes > _MAX_TOTAL_REVIEW_EVIDENCE_BYTES:
        raise ModelLineageReviewError("lineage review evidence exceeds the total byte limit")
    return tuple(bindings)


def _bind_candidates(
    *,
    registry: CandidateRegistry,
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    snapshot: ModelRefreshSnapshot,
    review_by_model: Mapping[str, OperatorLineageReview],
) -> tuple[ModelLineageCandidateBinding, ...]:
    discovery_by_model = {item.exact_model_id: item for item in discovery_evidence}
    refresh_by_model = {item.exact_model_id: item for item in snapshot.models}
    bindings: list[ModelLineageCandidateBinding] = []
    canonical_groups: dict[str, tuple[LineageReviewStatus, str | None, str]] = {}
    variant_groups: dict[str, tuple[LineageReviewStatus, str | None, str]] = {}
    root_reviews: dict[str, str] = {}
    for candidate in registry.candidates:
        discovered = discovery_by_model[candidate.exact_model_id]
        refreshed = refresh_by_model.get(candidate.exact_model_id)
        if refreshed is None:
            raise ModelLineageReviewError(
                f"lineage candidate is missing from current refresh: {candidate.exact_model_id}"
            )
        if (
            refreshed.canonical_model_slug != candidate.canonical_model_slug
            or discovered.canonical_slug != candidate.canonical_model_slug
        ):
            raise ModelLineageReviewError(
                f"lineage candidate canonical identity drifted: {candidate.exact_model_id}"
            )
        routes = tuple(
            route
            for route in refreshed.routes
            if route.provider_endpoint == candidate.approved_provider_endpoint
        )
        if (
            len(routes) != 1
            or not routes[0].discovery_eligible
            or candidate.approved_provider_endpoint not in refreshed.eligible_provider_endpoints
        ):
            raise ModelLineageReviewError(
                f"lineage candidate exact route is not current and eligible: "
                f"{candidate.exact_model_id}"
            )
        route = routes[0]
        discovered_route = discovered.endpoint_snapshot.endpoint(
            candidate.approved_provider_endpoint
        )
        if (
            route.provider_name != discovered_route.provider_name
            or route.provider_name != candidate.approved_provider_name
            or route.endpoint_tag != discovered_route.endpoint_tag
            or route.endpoint_slug != discovered_route.endpoint_slug
        ):
            raise ModelLineageReviewError(
                f"lineage candidate provider route identity drifted: {candidate.exact_model_id}"
            )
        review = review_by_model[candidate.exact_model_id]
        review_identity = (review.status, review.root_lineage, review.review_sha256)
        _require_consistent_group(
            canonical_groups,
            candidate.canonical_model_slug,
            review_identity,
            label="canonical model slug",
        )
        variant_key = model_variant_family_key(candidate.exact_model_id)
        _require_consistent_group(
            variant_groups,
            variant_key,
            review_identity,
            label="model variant family",
        )
        if review.root_lineage is not None:
            previous_review = root_reviews.setdefault(
                review.root_lineage,
                review.review_sha256,
            )
            if previous_review != review.review_sha256:
                raise ModelLineageReviewError("one root lineage is split across review artifacts")
        values: dict[str, Any] = {
            "exact_model_id": candidate.exact_model_id,
            "canonical_model_slug": candidate.canonical_model_slug,
            "variant_family_key": variant_key,
            "approved_provider_endpoint": candidate.approved_provider_endpoint,
            "approved_provider_name": candidate.approved_provider_name,
            "endpoint_tag": route.endpoint_tag,
            "endpoint_slug": route.endpoint_slug,
            "discovery_evidence_sha256": candidate.discovery_evidence_sha256,
            "refresh_model_state_sha256": refreshed.state_sha256,
            "refresh_route_sha256": route.route_sha256,
            "review_sha256": review.review_sha256,
            "decision": review.status.value,
            "root_lineage": review.root_lineage,
        }
        values["binding_sha256"] = canonical_sha256(values)
        bindings.append(ModelLineageCandidateBinding.model_validate(values))
    return tuple(bindings)


def _require_consistent_group(
    groups: dict[str, tuple[LineageReviewStatus, str | None, str]],
    key: str,
    value: tuple[LineageReviewStatus, str | None, str],
    *,
    label: str,
) -> None:
    previous = groups.setdefault(key, value)
    if previous != value:
        raise ModelLineageReviewError(f"one {label} has conflicting lineage decisions")


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
        raise ModelLineageReviewError(f"{label} must be a whole-second UTC timestamp")
    return value


def _utc_json_time(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
