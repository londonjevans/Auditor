"""Exact-byte public documentary model-lineage verification.

Durable objects in this module are comparison evidence only.  Identity/root
authority is represented exclusively by :class:`VerifiedPublicModelLineage`, a
PID-local opaque capability issued after the verifier has replayed the compiled
manifest, non-authorizing capture journal, exact source bytes, claim spans,
corroboration, conflicts, aliases, exclusions, roots, and conservative negative
constraints.  The capability grants no provider, runner, egress, qualification,
selection, sealing, release, or benchmark authority.
"""

from __future__ import annotations

import hashlib
import os
import threading
import weakref
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import islice, pairwise
from pathlib import Path
from types import ModuleType
from typing import Literal, Never, Self, SupportsIndex, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import read_file_evidence, read_json_evidence
from mmaudit.reporting.json_report import stable_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SOURCE_ID_PATTERN = r"^[a-z][a-z0-9-]{0,99}$"
_PUBLISHER_ID_PATTERN = r"^[a-z][a-z0-9-]{0,63}$"
_CLAIM_ID_PATTERN = r"^claim-[a-z][a-z0-9-]{0,95}$"
_ALIAS_ID_PATTERN = r"^alias-[a-z][a-z0-9-]{0,95}$"
_CONSTRAINT_ID_PATTERN = r"^constraint-[a-z][a-z0-9-]{0,91}$"
_ROOT_PATTERN = r"^sha256:[0-9a-f]{64}$"
_DOCUMENTARY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@+ -]{0,299}$"
_ROOT_DOMAIN = b"mmaudit-public-documentary-lineage-root-v1\0"
_MAX_SOURCES = 32
_MAX_MODELS = 128
_MAX_CLAIMS = 256
_MAX_CONSTRAINTS = 32
_MAX_SOURCE_BYTES = 100_000
_MAX_TOTAL_SOURCE_BYTES = 2_000_000
_MAX_MANIFEST_BYTES = 1_000_000
_MAX_CAPTURE_JOURNAL_BYTES = 500_000
_MAX_MARKER_BYTES = 2_000
_MAX_REDIRECTS = 5
_MAX_SOURCE_SPREAD = timedelta(minutes=10)
_MAX_VERIFICATION_DELAY = timedelta(days=2)
_MAX_VALIDITY = timedelta(days=180)
_CONCRETE_PATH_TYPE = type(Path())

PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT = (
    Path(__file__).resolve().parents[3] / "config" / "public_model_lineage"
)
PUBLIC_MODEL_LINEAGE_MANIFEST_FILENAME = "manifest.json"
PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME = "capture-observations.json"

# Updated only after a strict builder has emitted and replayed the committed
# manifest.  An all-zero value is intentionally non-authorizing.
PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256 = (
    "90389d27f553d6f167a21aab364cebdb40ca5afbdbcc977d9127338ace4a3008"
)

PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS = (
    "deepcogito/cogito-v2.1-671b",
    "deepseek/deepseek-v3.2-exp",
    "deepseek/deepseek-v4-pro-0813",
    "google/gemma-4-26b-a4b-it",
    "meta-llama/llama-4-maverick",
    "minimax/minimax-m3",
    "mistralai/mistral-small-2603",
    "moonshotai/kimi-k2-thinking",
    "moonshotai/kimi-k3",
    "nvidia/nemotron-3-super-120b-a12b",
    "openai/gpt-oss-120b",
    "qwen/qwen3.6-35b-a3b",
    "tencent/hunyuan-a13b-instruct",
    "tencent/hy3",
    "z-ai/glm-4.7",
)


class PublicModelLineageAuthorityError(ValueError):
    """Raised when public documentary lineage cannot issue identity authority."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PublicModelLineageSourceKind(StrEnum):
    """Allowed documentary source classes."""

    PRIMARY_PUBLISHER_MODEL_CARD = "PRIMARY_PUBLISHER_MODEL_CARD"
    AUTHORITATIVE_SECONDARY = "AUTHORITATIVE_SECONDARY"


class PublicModelLineageClaimKind(StrEnum):
    """Semantics supported by exact documentary spans."""

    ROOT_ANCHOR = "ROOT_ANCHOR"
    ROOTS_WITH = "ROOTS_WITH"
    VAGUE = "VAGUE"


class PublicModelLineageDecisionStatus(StrEnum):
    """Independently derived candidate confirmation state."""

    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"


class PublicModelLineageUnconfirmedReason(StrEnum):
    """Fail-closed reasons produced by the documentary resolver."""

    MISSING_CLAIM = "MISSING_CLAIM"
    VAGUE_ONLY = "VAGUE_ONLY"
    INSUFFICIENT_CORROBORATION = "INSUFFICIENT_CORROBORATION"
    CONFLICTING_CLAIMS = "CONFLICTING_CLAIMS"
    CYCLE = "CYCLE"
    UPSTREAM_UNCONFIRMED = "UPSTREAM_UNCONFIRMED"
    ALIAS_SOURCE_MISMATCH = "ALIAS_SOURCE_MISMATCH"


class PublicModelLineageConstraintKind(StrEnum):
    """Negative-only non-independence constraints."""

    DOCUMENTED_DIRECT_ANCESTRY = "DOCUMENTED_DIRECT_ANCESTRY"
    CONSERVATIVE_ORGANIZATIONAL = "CONSERVATIVE_ORGANIZATIONAL"
    SOURCE_CONFLICT_CORRECTION = "SOURCE_CONFLICT_CORRECTION"


class PublicModelLineageCaptureObservation(_StrictModel):
    """Strict mirror of one non-authorizing capture observation."""

    source_id: str = Field(pattern=_SOURCE_ID_PATTERN)
    requested_url: str = Field(min_length=9, max_length=8_192)
    final_url: str = Field(min_length=9, max_length=8_192)
    redirect_chain: tuple[str, ...] = Field(min_length=1, max_length=_MAX_REDIRECTS)
    publisher_id: str = Field(pattern=_PUBLISHER_ID_PATTERN)
    independence_key: str = Field(pattern=_PUBLISHER_ID_PATTERN)
    source_kind: Literal["PRIMARY_PUBLISHER_MODEL_CARD"]
    immutable_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    retrieved_at: datetime
    media_type: Literal["text/markdown", "text/plain"]
    file_binding: ManifestFileBinding
    observation_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_is_whole_second_utc(cls, value: datetime) -> datetime:
        _require_whole_second_utc(value, label="public lineage source retrieval")
        return value

    @model_validator(mode="after")
    def exact_redirects_path_and_hash_are_consistent(self) -> Self:
        _require_source_urls(self.requested_url, self.final_url, self.redirect_chain)
        _require_source_path(self.source_id, self.file_binding)
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"observation_sha256"}))
        if self.observation_sha256 != expected:
            raise ValueError("public lineage capture observation hash is inconsistent")
        return self


class PublicModelLineageCaptureJournal(_StrictModel):
    """Complete non-authorizing exact-source capture journal."""

    schema_version: Literal["1.0"] = "1.0"
    sources: tuple[PublicModelLineageCaptureObservation, ...] = Field(
        min_length=1, max_length=_MAX_SOURCES
    )
    lineage_identity_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    observation_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def inventory_and_hashes_are_consistent(self) -> Self:
        ids = tuple(source.source_id for source in self.sources)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("public lineage capture inventory must be unique and sorted")
        expected_set = canonical_sha256([source.observation_sha256 for source in self.sources])
        if self.observation_set_sha256 != expected_set:
            raise ValueError("public lineage capture observation set hash is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"bundle_sha256"}))
        if self.bundle_sha256 != expected:
            raise ValueError("public lineage capture journal hash is inconsistent")
        return self


class PublicModelLineageSourceEvidence(_StrictModel):
    """One exact source projection copied from the capture journal."""

    source_id: str = Field(pattern=_SOURCE_ID_PATTERN)
    requested_url: str = Field(min_length=9, max_length=8_192)
    final_url: str = Field(min_length=9, max_length=8_192)
    redirect_chain: tuple[str, ...] = Field(min_length=1, max_length=_MAX_REDIRECTS)
    publisher_id: str = Field(pattern=_PUBLISHER_ID_PATTERN)
    independence_key: str = Field(pattern=_PUBLISHER_ID_PATTERN)
    source_kind: PublicModelLineageSourceKind
    immutable_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    retrieved_at: datetime
    media_type: Literal["text/markdown", "text/plain"]
    file_binding: ManifestFileBinding
    capture_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_is_whole_second_utc(cls, value: datetime) -> datetime:
        _require_whole_second_utc(value, label="public lineage source retrieval")
        return value

    @model_validator(mode="after")
    def source_projection_and_hash_are_consistent(self) -> Self:
        _require_source_urls(self.requested_url, self.final_url, self.redirect_chain)
        _require_source_path(self.source_id, self.file_binding)
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"source_evidence_sha256"})
        )
        if self.source_evidence_sha256 != expected:
            raise ValueError("public lineage source-evidence hash is inconsistent")
        return self

    @classmethod
    def from_capture(
        cls, observation: PublicModelLineageCaptureObservation
    ) -> PublicModelLineageSourceEvidence:
        """Build a strict, non-authorizing source projection."""

        provisional = cls.model_construct(
            source_id=observation.source_id,
            requested_url=observation.requested_url,
            final_url=observation.final_url,
            redirect_chain=observation.redirect_chain,
            publisher_id=observation.publisher_id,
            independence_key=observation.independence_key,
            source_kind=PublicModelLineageSourceKind.PRIMARY_PUBLISHER_MODEL_CARD,
            immutable_revision=observation.immutable_revision,
            retrieved_at=observation.retrieved_at,
            media_type=observation.media_type,
            file_binding=observation.file_binding,
            capture_observation_sha256=observation.observation_sha256,
            source_evidence_sha256="0" * 64,
        )
        return cls(
            source_id=observation.source_id,
            requested_url=observation.requested_url,
            final_url=observation.final_url,
            redirect_chain=observation.redirect_chain,
            publisher_id=observation.publisher_id,
            independence_key=observation.independence_key,
            source_kind=PublicModelLineageSourceKind.PRIMARY_PUBLISHER_MODEL_CARD,
            immutable_revision=observation.immutable_revision,
            retrieved_at=observation.retrieved_at,
            media_type=observation.media_type,
            file_binding=observation.file_binding,
            capture_observation_sha256=observation.observation_sha256,
            source_evidence_sha256=canonical_sha256(
                provisional.model_dump(mode="json", exclude={"source_evidence_sha256"})
            ),
        )


class PublicModelLineageAliasBinding(_StrictModel):
    """Compiled exact production identity to documentary identity binding."""

    alias_id: str = Field(pattern=_ALIAS_ID_PATTERN)
    exact_model_id: str
    documentary_model_id: str = Field(pattern=_DOCUMENTARY_ID_PATTERN)
    publisher_id: str = Field(pattern=_PUBLISHER_ID_PATTERN)
    source_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_SOURCES)
    alias_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def exact_id_is_provider_identity(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="public lineage exact model ID")

    @field_validator("source_ids")
    @classmethod
    def source_inventory_is_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("public lineage alias sources must be unique and sorted")
        return value

    @model_validator(mode="after")
    def alias_hash_is_consistent(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"alias_sha256"}))
        if self.alias_sha256 != expected:
            raise ValueError("public lineage alias hash is inconsistent")
        return self


class PublicModelLineageClaim(_StrictModel):
    """One exact non-overlapping documentary claim span."""

    claim_id: str = Field(pattern=_CLAIM_ID_PATTERN)
    subject_exact_model_id: str
    claim_kind: PublicModelLineageClaimKind
    target_exact_model_id: str | None = None
    source_id: str = Field(pattern=_SOURCE_ID_PATTERN)
    decisive_primary_publisher: bool
    byte_start: int = Field(ge=0, le=_MAX_SOURCE_BYTES)
    byte_end: int = Field(gt=0, le=_MAX_SOURCE_BYTES)
    exact_marker: str = Field(min_length=1, max_length=_MAX_MARKER_BYTES)
    marker_sha256: str = Field(pattern=_SHA256_PATTERN)
    claim_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("subject_exact_model_id")
    @classmethod
    def subject_is_exact_id(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="public lineage claim subject")

    @field_validator("target_exact_model_id")
    @classmethod
    def target_is_exact_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_exact_openrouter_model_id(value, label="public lineage claim target")

    @model_validator(mode="after")
    def relation_span_and_hash_are_consistent(self) -> Self:
        if self.claim_kind is PublicModelLineageClaimKind.ROOTS_WITH:
            if (
                self.target_exact_model_id is None
                or self.target_exact_model_id == self.subject_exact_model_id
            ):
                raise ValueError("ROOTS_WITH requires another exact target")
        elif self.target_exact_model_id is not None:
            raise ValueError("only ROOTS_WITH accepts a target")
        if self.claim_kind is PublicModelLineageClaimKind.VAGUE and self.decisive_primary_publisher:
            raise ValueError("vague public lineage evidence cannot be decisive")
        marker_bytes = self.exact_marker.encode("utf-8")
        if len(marker_bytes) > _MAX_MARKER_BYTES or self.byte_end - self.byte_start != len(
            marker_bytes
        ):
            raise ValueError("public lineage claim span does not equal its exact marker")
        if hashlib.sha256(marker_bytes).hexdigest() != self.marker_sha256:
            raise ValueError("public lineage claim marker hash is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"claim_sha256"}))
        if self.claim_sha256 != expected:
            raise ValueError("public lineage claim hash is inconsistent")
        return self


class PublicModelLineageDecision(_StrictModel):
    """One comparison-only decision independently rebuilt by the verifier."""

    exact_model_id: str
    documentary_model_id: str = Field(pattern=_DOCUMENTARY_ID_PATTERN)
    status: PublicModelLineageDecisionStatus
    root_lineage: str | None = Field(default=None, pattern=_ROOT_PATTERN)
    supporting_claim_ids: tuple[str, ...] = Field(max_length=_MAX_CLAIMS)
    unconfirmed_reasons: tuple[PublicModelLineageUnconfirmedReason, ...] = Field(
        max_length=len(PublicModelLineageUnconfirmedReason)
    )
    decision_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def exact_id_is_provider_identity(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="public lineage decision model ID")

    @model_validator(mode="after")
    def status_and_hash_are_consistent(self) -> Self:
        if self.supporting_claim_ids != tuple(sorted(set(self.supporting_claim_ids))):
            raise ValueError("public lineage decision claims must be unique and sorted")
        if self.unconfirmed_reasons != tuple(sorted(set(self.unconfirmed_reasons), key=str)):
            raise ValueError("public lineage decision reasons must be unique and sorted")
        if self.status is PublicModelLineageDecisionStatus.CONFIRMED:
            if (
                self.root_lineage is None
                or not self.supporting_claim_ids
                or self.unconfirmed_reasons
            ):
                raise ValueError("confirmed public lineage decision lacks exact support")
        elif self.root_lineage is not None or not self.unconfirmed_reasons:
            raise ValueError("unconfirmed public lineage decision is not fail closed")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"decision_sha256"}))
        if self.decision_sha256 != expected:
            raise ValueError("public lineage decision hash is inconsistent")
        return self


class PublicModelLineageNonIndependenceConstraint(_StrictModel):
    """A conservative negative-only collision constraint."""

    constraint_id: str = Field(pattern=_CONSTRAINT_ID_PATTERN)
    constraint_kind: PublicModelLineageConstraintKind
    member_exact_model_ids: tuple[str, ...] = Field(min_length=2, max_length=16)
    supporting_claim_ids: tuple[str, ...] = Field(max_length=_MAX_CLAIMS)
    negative_only: Literal[True] = True
    positive_root_assignment_authorized: Literal[False] = False
    constraint_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("member_exact_model_ids")
    @classmethod
    def members_are_exact_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        checked = tuple(
            require_exact_openrouter_model_id(item, label="public lineage constraint model ID")
            for item in value
        )
        if checked != tuple(sorted(set(checked))):
            raise ValueError("public lineage constraint members must be unique and sorted")
        return checked

    @field_validator("supporting_claim_ids")
    @classmethod
    def claims_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("public lineage constraint claims must be unique and sorted")
        return value

    @model_validator(mode="after")
    def constraint_hash_is_consistent(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"constraint_sha256"}))
        if self.constraint_sha256 != expected:
            raise ValueError("public lineage constraint hash is inconsistent")
        return self


class PublicModelLineageEvidenceBundle(_StrictModel):
    """Complete durable public-lineage evidence; serialized bytes grant no authority."""

    schema_version: Literal["1.0"] = "1.0"
    evidence_standard: Literal["DOCUMENTARY_EXACT_BYTES_V1"] = "DOCUMENTARY_EXACT_BYTES_V1"
    capture_observations_file_binding: ManifestFileBinding
    verified_at: datetime
    valid_until: datetime
    sources: tuple[PublicModelLineageSourceEvidence, ...] = Field(
        min_length=1, max_length=_MAX_SOURCES
    )
    aliases: tuple[PublicModelLineageAliasBinding, ...] = Field(
        min_length=1, max_length=_MAX_MODELS
    )
    claims: tuple[PublicModelLineageClaim, ...] = Field(min_length=1, max_length=_MAX_CLAIMS)
    decisions: tuple[PublicModelLineageDecision, ...] = Field(min_length=1, max_length=_MAX_MODELS)
    conservative_non_independence_constraints: tuple[
        PublicModelLineageNonIndependenceConstraint, ...
    ] = Field(max_length=_MAX_CONSTRAINTS)
    confirmed_exact_model_ids: tuple[str, ...] = Field(max_length=_MAX_MODELS)
    unconfirmed_exact_model_ids: tuple[str, ...] = Field(max_length=_MAX_MODELS)
    excluded_exact_model_ids: tuple[str, ...] = Field(max_length=_MAX_MODELS)
    approved_root_lineages: tuple[str, ...] = Field(max_length=_MAX_MODELS)
    source_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    alias_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    claim_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    decision_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    constraint_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    operator_review_authoritative: Literal[False] = False
    provider_route_identity_required: Literal[False] = False
    sigstore_lineage_receipt_required: Literal[False] = False
    serialized_authority: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    runner_authority_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    seal_publication_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    benchmark_authorized: Literal[False] = False
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("verified_at", "valid_until")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        _require_whole_second_utc(value, label="public lineage bundle time")
        return value

    @model_validator(mode="after")
    def inventory_derivation_and_hashes_are_exact(self) -> Self:
        if (
            self.capture_observations_file_binding.path
            != PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME
        ):
            raise ValueError("public lineage capture journal path is not exact")
        if not self.verified_at < self.valid_until <= self.verified_at + _MAX_VALIDITY:
            raise ValueError("public lineage validity window is invalid")
        _require_unique_sorted(self.sources, key=lambda item: item.source_id, label="sources")
        _require_unique_sorted(self.aliases, key=lambda item: item.exact_model_id, label="aliases")
        _require_unique_sorted(self.claims, key=lambda item: item.claim_id, label="claims")
        _require_unique_sorted(
            self.decisions, key=lambda item: item.exact_model_id, label="decisions"
        )
        _require_unique_sorted(
            self.conservative_non_independence_constraints,
            key=lambda item: item.constraint_id,
            label="constraints",
        )
        if sum(source.file_binding.size for source in self.sources) > _MAX_TOTAL_SOURCE_BYTES:
            raise ValueError("public lineage source inventory exceeds total byte bound")
        retrievals = tuple(source.retrieved_at for source in self.sources)
        if (
            max(retrievals) > self.verified_at
            or self.verified_at - max(retrievals) > _MAX_VERIFICATION_DELAY
            or max(retrievals) - min(retrievals) > _MAX_SOURCE_SPREAD
        ):
            raise ValueError("public lineage source retrieval window is stale or incoherent")

        expected_decisions = _derive_public_lineage_decisions(
            self.aliases, self.sources, self.claims
        )
        if self.decisions != expected_decisions:
            raise ValueError("public lineage decisions are not independently derived")
        confirmed = tuple(
            item.exact_model_id
            for item in self.decisions
            if item.status is PublicModelLineageDecisionStatus.CONFIRMED
        )
        unconfirmed = tuple(
            item.exact_model_id
            for item in self.decisions
            if item.status is PublicModelLineageDecisionStatus.UNCONFIRMED
        )
        roots = tuple(
            sorted({item.root_lineage for item in self.decisions if item.root_lineage is not None})
        )
        if (
            self.confirmed_exact_model_ids != confirmed
            or self.unconfirmed_exact_model_ids != unconfirmed
            or self.excluded_exact_model_ids != unconfirmed
            or self.approved_root_lineages != roots
        ):
            raise ValueError("public lineage inclusion or exclusion inventory is inconsistent")

        claim_ids = {claim.claim_id for claim in self.claims}
        for constraint in self.conservative_non_independence_constraints:
            if not set(constraint.supporting_claim_ids) <= claim_ids:
                raise ValueError("public lineage constraint cites an unknown claim")

        expected_hashes = (
            canonical_sha256([item.source_evidence_sha256 for item in self.sources]),
            canonical_sha256([item.alias_sha256 for item in self.aliases]),
            canonical_sha256([item.claim_sha256 for item in self.claims]),
            canonical_sha256([item.decision_sha256 for item in self.decisions]),
            canonical_sha256(
                [item.constraint_sha256 for item in self.conservative_non_independence_constraints]
            ),
        )
        observed_hashes = (
            self.source_set_sha256,
            self.alias_set_sha256,
            self.claim_set_sha256,
            self.decision_set_sha256,
            self.constraint_set_sha256,
        )
        if observed_hashes != expected_hashes:
            raise ValueError("public lineage inventory-set hash is inconsistent")
        expected_bundle = canonical_sha256(self.model_dump(mode="json", exclude={"bundle_sha256"}))
        if self.bundle_sha256 != expected_bundle:
            raise ValueError("public lineage bundle hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedPublicModelLineageBindingProjection:
    """Fresh identity-only projection for one confirmed exact model."""

    exact_model_id: str
    documentary_model_id: str
    root_lineage: str
    decision_sha256: str
    bundle_sha256: str
    manifest_file_sha256: str
    lineage_identity_authorized: Literal[True]
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    model_qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    seal_publication_authorized: Literal[False]
    release_authorized: Literal[False]
    benchmark_authorized: Literal[False]


@dataclass(frozen=True, slots=True)
class VerifiedPublicModelLineageInventory:
    """Fresh complete projection from an opaque capability."""

    bundle_sha256: str
    manifest_file_sha256: str
    confirmed_exact_model_ids: tuple[str, ...]
    unconfirmed_exact_model_ids: tuple[str, ...]
    excluded_exact_model_ids: tuple[str, ...]
    approved_root_lineages: tuple[str, ...]
    confirmed_bindings: tuple[VerifiedPublicModelLineageBindingProjection, ...]
    conservative_non_independence_constraints: tuple[
        PublicModelLineageNonIndependenceConstraint, ...
    ]
    lineage_identity_authorized: Literal[True]
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    model_qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    seal_publication_authorized: Literal[False]
    release_authorized: Literal[False]
    benchmark_authorized: Literal[False]


@dataclass(frozen=True, slots=True)
class VerifiedIndependentPublicModelLineageProjection:
    """Fresh proof that two confirmed exact identities may be treated independently."""

    left_exact_model_id: str
    left_root_lineage: str
    right_exact_model_id: str
    right_root_lineage: str
    independent: Literal[True]
    bundle_sha256: str
    manifest_file_sha256: str


class VerifiedPublicModelLineage:
    """PID-local opaque custody for exact replayed documentary identity evidence."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedPublicModelLineage:
        del cls
        raise TypeError("verified public model lineage cannot be constructed directly")

    def __copy__(self) -> Never:
        raise TypeError("verified public model lineage cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified public model lineage cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified public model lineage cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified public model lineage cannot be serialized")


@dataclass(frozen=True, slots=True)
class _VerifiedPublicLineageState:
    process_id: int
    evidence_root: Path
    expected_manifest_file_sha256: str
    clock: Callable[[], datetime]
    require_production_inventory: bool
    bundle_sha256: str


_CAPABILITY_LOCK = threading.RLock()
_CAPABILITY_STATES: weakref.WeakKeyDictionary[
    VerifiedPublicModelLineage, _VerifiedPublicLineageState
] = weakref.WeakKeyDictionary()


def build_public_model_lineage_evidence_bundle(
    *,
    capture_observations_file_binding: ManifestFileBinding,
    verified_at: datetime,
    valid_until: datetime,
    sources: Iterable[PublicModelLineageSourceEvidence],
    aliases: Iterable[PublicModelLineageAliasBinding],
    claims: Iterable[PublicModelLineageClaim],
    conservative_non_independence_constraints: Iterable[
        PublicModelLineageNonIndependenceConstraint
    ] = (),
) -> PublicModelLineageEvidenceBundle:
    """Build comparison-only evidence with every decision and hash independently derived."""

    source_items = _bounded_tuple(sources, _MAX_SOURCES, label="public lineage sources")
    alias_items = _bounded_tuple(aliases, _MAX_MODELS, label="public lineage aliases")
    claim_items = _bounded_tuple(claims, _MAX_CLAIMS, label="public lineage claims")
    constraints = _bounded_tuple(
        conservative_non_independence_constraints,
        _MAX_CONSTRAINTS,
        label="public lineage constraints",
    )
    decisions = _derive_public_lineage_decisions(alias_items, source_items, claim_items)
    confirmed = tuple(
        item.exact_model_id
        for item in decisions
        if item.status is PublicModelLineageDecisionStatus.CONFIRMED
    )
    unconfirmed = tuple(
        item.exact_model_id
        for item in decisions
        if item.status is PublicModelLineageDecisionStatus.UNCONFIRMED
    )
    roots = tuple(
        sorted({item.root_lineage for item in decisions if item.root_lineage is not None})
    )
    provisional = PublicModelLineageEvidenceBundle.model_construct(
        schema_version="1.0",
        evidence_standard="DOCUMENTARY_EXACT_BYTES_V1",
        capture_observations_file_binding=capture_observations_file_binding,
        verified_at=verified_at,
        valid_until=valid_until,
        sources=source_items,
        aliases=alias_items,
        claims=claim_items,
        decisions=decisions,
        conservative_non_independence_constraints=constraints,
        confirmed_exact_model_ids=confirmed,
        unconfirmed_exact_model_ids=unconfirmed,
        excluded_exact_model_ids=unconfirmed,
        approved_root_lineages=roots,
        source_set_sha256=canonical_sha256([item.source_evidence_sha256 for item in source_items]),
        alias_set_sha256=canonical_sha256([item.alias_sha256 for item in alias_items]),
        claim_set_sha256=canonical_sha256([item.claim_sha256 for item in claim_items]),
        decision_set_sha256=canonical_sha256([item.decision_sha256 for item in decisions]),
        constraint_set_sha256=canonical_sha256([item.constraint_sha256 for item in constraints]),
        operator_review_authoritative=False,
        provider_route_identity_required=False,
        sigstore_lineage_receipt_required=False,
        serialized_authority=False,
        provider_call_authorized=False,
        source_egress_authorized=False,
        runner_authority_authorized=False,
        model_qualification_authorized=False,
        production_selection_authorized=False,
        seal_publication_authorized=False,
        release_authorized=False,
        benchmark_authorized=False,
        bundle_sha256="0" * 64,
    )
    return PublicModelLineageEvidenceBundle(
        schema_version="1.0",
        evidence_standard="DOCUMENTARY_EXACT_BYTES_V1",
        capture_observations_file_binding=capture_observations_file_binding,
        verified_at=verified_at,
        valid_until=valid_until,
        sources=source_items,
        aliases=alias_items,
        claims=claim_items,
        decisions=decisions,
        conservative_non_independence_constraints=constraints,
        confirmed_exact_model_ids=confirmed,
        unconfirmed_exact_model_ids=unconfirmed,
        excluded_exact_model_ids=unconfirmed,
        approved_root_lineages=roots,
        source_set_sha256=provisional.source_set_sha256,
        alias_set_sha256=provisional.alias_set_sha256,
        claim_set_sha256=provisional.claim_set_sha256,
        decision_set_sha256=provisional.decision_set_sha256,
        constraint_set_sha256=provisional.constraint_set_sha256,
        operator_review_authoritative=False,
        provider_route_identity_required=False,
        sigstore_lineage_receipt_required=False,
        serialized_authority=False,
        provider_call_authorized=False,
        source_egress_authorized=False,
        runner_authority_authorized=False,
        model_qualification_authorized=False,
        production_selection_authorized=False,
        seal_publication_authorized=False,
        release_authorized=False,
        benchmark_authorized=False,
        bundle_sha256=canonical_sha256(
            provisional.model_dump(mode="json", exclude={"bundle_sha256"})
        ),
    )


def _public_model_lineage_inventory_impl(
    capability: VerifiedPublicModelLineage,
    *,
    clock: Callable[[], datetime],
) -> VerifiedPublicModelLineageInventory:
    """Return a fresh complete identity-only inventory after exact replay."""

    bundle, state = _replay_capability(capability, clock=clock)
    bindings = tuple(
        _binding_projection(bundle, state, item) for item in bundle.decisions if item.root_lineage
    )
    return VerifiedPublicModelLineageInventory(
        bundle_sha256=bundle.bundle_sha256,
        manifest_file_sha256=state.expected_manifest_file_sha256,
        confirmed_exact_model_ids=bundle.confirmed_exact_model_ids,
        unconfirmed_exact_model_ids=bundle.unconfirmed_exact_model_ids,
        excluded_exact_model_ids=bundle.excluded_exact_model_ids,
        approved_root_lineages=bundle.approved_root_lineages,
        confirmed_bindings=bindings,
        conservative_non_independence_constraints=bundle.conservative_non_independence_constraints,
        lineage_identity_authorized=True,
        provider_call_authorized=False,
        source_egress_authorized=False,
        runner_authority_authorized=False,
        model_qualification_authorized=False,
        production_selection_authorized=False,
        seal_publication_authorized=False,
        release_authorized=False,
        benchmark_authorized=False,
    )


def _require_verified_public_model_lineage_impl(
    capability: VerifiedPublicModelLineage,
    exact_model_id: str,
    *,
    clock: Callable[[], datetime],
) -> VerifiedPublicModelLineageBindingProjection:
    """Require one confirmed exact identity and return its fresh derived root."""

    checked = require_exact_openrouter_model_id(exact_model_id, label="public lineage model ID")
    inventory = _public_model_lineage_inventory_impl(capability, clock=clock)
    for binding in inventory.confirmed_bindings:
        if binding.exact_model_id == checked:
            return binding
    raise PublicModelLineageAuthorityError("exact model lacks confirmed public lineage")


def _require_independent_public_model_lineage_impl(
    capability: VerifiedPublicModelLineage,
    left_exact_model_id: str,
    right_exact_model_id: str,
    *,
    clock: Callable[[], datetime],
) -> VerifiedIndependentPublicModelLineageProjection:
    """Require distinct roots and absence of every conservative collision constraint."""

    left = _require_verified_public_model_lineage_impl(capability, left_exact_model_id, clock=clock)
    right = _require_verified_public_model_lineage_impl(
        capability, right_exact_model_id, clock=clock
    )
    if left.exact_model_id == right.exact_model_id or left.root_lineage == right.root_lineage:
        raise PublicModelLineageAuthorityError("public model lineages are not independent")
    inventory = _public_model_lineage_inventory_impl(capability, clock=clock)
    pair = {left.exact_model_id, right.exact_model_id}
    if any(
        pair <= set(item.member_exact_model_ids)
        for item in inventory.conservative_non_independence_constraints
    ):
        raise PublicModelLineageAuthorityError(
            "public model pair is conservatively non-independent"
        )
    return VerifiedIndependentPublicModelLineageProjection(
        left_exact_model_id=left.exact_model_id,
        left_root_lineage=left.root_lineage,
        right_exact_model_id=right.exact_model_id,
        right_root_lineage=right.root_lineage,
        independent=True,
        bundle_sha256=inventory.bundle_sha256,
        manifest_file_sha256=inventory.manifest_file_sha256,
    )


def _approved_public_model_lineages_impl(
    capability: VerifiedPublicModelLineage,
    *,
    clock: Callable[[], datetime],
) -> tuple[str, ...]:
    """Return only roots derived for confirmed exact identities."""

    return _public_model_lineage_inventory_impl(capability, clock=clock).approved_root_lineages


def _resolve_verified_public_model_lineage_for_test(
    *,
    evidence_root: Path,
    expected_manifest_file_sha256: str,
    verification_time: datetime,
    clock: Callable[[], datetime] | None = None,
) -> VerifiedPublicModelLineage:
    """Private deterministic seam for local synthetic verifier tests."""

    return _resolve_verified_public_model_lineage(
        evidence_root=evidence_root,
        expected_manifest_file_sha256=expected_manifest_file_sha256,
        verification_time=verification_time,
        require_production_inventory=False,
        clock=clock or (lambda: verification_time),
    )


def _resolve_verified_public_model_lineage(
    *,
    evidence_root: Path,
    expected_manifest_file_sha256: str,
    verification_time: datetime,
    require_production_inventory: bool,
    clock: Callable[[], datetime],
) -> VerifiedPublicModelLineage:
    if require_production_inventory:
        raise PublicModelLineageAuthorityError(
            "production public-lineage authority is available only through the captured issuer"
        )
    _require_whole_second_utc(verification_time, label="public lineage verification")
    if type(evidence_root) is not _CONCRETE_PATH_TYPE or not evidence_root.is_absolute():
        raise PublicModelLineageAuthorityError(
            "public lineage evidence root must be an absolute concrete path"
        )
    if len(expected_manifest_file_sha256) != 64 or any(
        item not in "0123456789abcdef" for item in expected_manifest_file_sha256
    ):
        raise PublicModelLineageAuthorityError("public lineage manifest pin is invalid")
    first = _load_and_verify_bundle(
        evidence_root,
        expected_manifest_file_sha256,
        verification_time,
        require_production_inventory=require_production_inventory,
    )
    second = _load_and_verify_bundle(
        evidence_root,
        expected_manifest_file_sha256,
        verification_time,
        require_production_inventory=require_production_inventory,
    )
    if first != second:
        raise PublicModelLineageAuthorityError(
            "public lineage evidence changed during verification"
        )
    capability = object.__new__(VerifiedPublicModelLineage)
    state = _VerifiedPublicLineageState(
        process_id=os.getpid(),
        evidence_root=evidence_root,
        expected_manifest_file_sha256=expected_manifest_file_sha256,
        clock=clock,
        require_production_inventory=require_production_inventory,
        bundle_sha256=first.bundle_sha256,
    )
    with _CAPABILITY_LOCK:
        _CAPABILITY_STATES[capability] = state
    return capability


def _replay_capability(
    capability: VerifiedPublicModelLineage,
    *,
    clock: Callable[[], datetime],
) -> tuple[PublicModelLineageEvidenceBundle, _VerifiedPublicLineageState]:
    if type(capability) is not VerifiedPublicModelLineage:
        raise TypeError("verified public model lineage capability has the wrong type")
    with _CAPABILITY_LOCK:
        state = _CAPABILITY_STATES.get(capability)
    if state is None or state.process_id != os.getpid():
        raise PublicModelLineageAuthorityError(
            "verified public model lineage is absent or fork-inherited"
        )
    if (
        not state.require_production_inventory
        or state.evidence_root != PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT
        or state.expected_manifest_file_sha256 != PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256
        or PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256 == "0" * 64
    ):
        raise PublicModelLineageAuthorityError(
            "public lineage capability is not bound to the compiled production evidence"
        )
    verification_time = clock()
    _require_whole_second_utc(verification_time, label="public lineage replay time")
    bundle = _load_and_verify_bundle(
        state.evidence_root,
        state.expected_manifest_file_sha256,
        verification_time,
        require_production_inventory=state.require_production_inventory,
    )
    if bundle.bundle_sha256 != state.bundle_sha256:
        raise PublicModelLineageAuthorityError(
            "public lineage bundle changed after capability issuance"
        )
    return bundle, state


def _replay_public_model_lineage_for_test(
    capability: VerifiedPublicModelLineage,
) -> PublicModelLineageEvidenceBundle:
    """Replay synthetic local evidence without issuing a public authority projection."""

    if type(capability) is not VerifiedPublicModelLineage:
        raise TypeError("replayed public model lineage capability has the wrong type")
    with _CAPABILITY_LOCK:
        state = _CAPABILITY_STATES.get(capability)
    if state is None or state.process_id != os.getpid() or state.require_production_inventory:
        raise PublicModelLineageAuthorityError("synthetic public lineage replay is unavailable")
    verification_time = state.clock()
    _require_whole_second_utc(verification_time, label="public lineage test replay time")
    bundle = _load_and_verify_bundle(
        state.evidence_root,
        state.expected_manifest_file_sha256,
        verification_time,
        require_production_inventory=False,
    )
    if bundle.bundle_sha256 != state.bundle_sha256:
        raise PublicModelLineageAuthorityError(
            "public lineage bundle changed after test replay issuance"
        )
    return bundle


def _load_and_verify_bundle(
    evidence_root: Path,
    expected_manifest_file_sha256: str,
    verification_time: datetime,
    *,
    require_production_inventory: bool,
) -> PublicModelLineageEvidenceBundle:
    try:
        manifest = read_json_evidence(
            evidence_root=evidence_root,
            relative_path=PUBLIC_MODEL_LINEAGE_MANIFEST_FILENAME,
            max_bytes=_MAX_MANIFEST_BYTES,
        )
    except ValueError as exc:
        raise PublicModelLineageAuthorityError(
            "public lineage manifest cannot be read safely"
        ) from exc
    if manifest.binding.sha256 != expected_manifest_file_sha256:
        raise PublicModelLineageAuthorityError(
            "public lineage manifest differs from its compiled pin"
        )
    try:
        bundle = PublicModelLineageEvidenceBundle.model_validate_json(manifest.content)
    except ValueError as exc:
        raise PublicModelLineageAuthorityError("public lineage manifest is invalid") from exc
    if stable_json(bundle).encode("utf-8") != manifest.content:
        raise PublicModelLineageAuthorityError(
            "public lineage manifest is not canonical exact JSON"
        )
    if not bundle.verified_at <= verification_time <= bundle.valid_until:
        raise PublicModelLineageAuthorityError("public lineage manifest is not current")

    try:
        journal_observation = read_json_evidence(
            evidence_root=evidence_root,
            relative_path=PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME,
            max_bytes=_MAX_CAPTURE_JOURNAL_BYTES,
        )
    except ValueError as exc:
        raise PublicModelLineageAuthorityError(
            "public lineage capture journal cannot be read safely"
        ) from exc
    if journal_observation.binding != bundle.capture_observations_file_binding:
        raise PublicModelLineageAuthorityError(
            "public lineage capture journal differs from the manifest"
        )
    try:
        journal = PublicModelLineageCaptureJournal.model_validate_json(journal_observation.content)
    except ValueError as exc:
        raise PublicModelLineageAuthorityError("public lineage capture journal is invalid") from exc
    if stable_json(journal).encode("utf-8") != journal_observation.content:
        raise PublicModelLineageAuthorityError(
            "public lineage capture journal is not canonical JSON"
        )
    expected_sources = tuple(
        PublicModelLineageSourceEvidence.from_capture(item) for item in journal.sources
    )
    if bundle.sources != expected_sources:
        raise PublicModelLineageAuthorityError(
            "public lineage source projections differ from capture"
        )

    source_bytes: dict[str, bytes] = {}
    for source in bundle.sources:
        try:
            observed = read_file_evidence(
                evidence_root=evidence_root,
                relative_path=source.file_binding.path,
                max_bytes=_MAX_SOURCE_BYTES,
            )
        except ValueError as exc:
            raise PublicModelLineageAuthorityError(
                "public lineage source cannot be read safely"
            ) from exc
        if observed.binding != source.file_binding:
            raise PublicModelLineageAuthorityError("public lineage source differs from its binding")
        try:
            observed.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise PublicModelLineageAuthorityError(
                "public lineage source is not exact UTF-8"
            ) from exc
        source_bytes[source.source_id] = observed.content
    _verify_claim_spans(bundle.claims, source_bytes)
    if require_production_inventory:
        _require_compiled_production_inventory(bundle)
    return bundle


def _derive_public_lineage_decisions(
    aliases: Sequence[PublicModelLineageAliasBinding],
    sources: Sequence[PublicModelLineageSourceEvidence],
    claims: Sequence[PublicModelLineageClaim],
) -> tuple[PublicModelLineageDecision, ...]:
    source_by_id = {item.source_id: item for item in sources}
    alias_by_id = {item.exact_model_id: item for item in aliases}
    claims_by_subject: dict[str, list[PublicModelLineageClaim]] = {
        item.exact_model_id: [] for item in aliases
    }
    for claim in claims:
        if claim.subject_exact_model_id not in alias_by_id:
            raise ValueError("public lineage claim subject lacks an exact alias")
        if claim.source_id not in source_by_id:
            raise ValueError("public lineage claim cites an unknown source")
        claims_by_subject[claim.subject_exact_model_id].append(claim)
    for source_claims in claims_by_subject.values():
        source_claims.sort(key=lambda item: item.claim_id)

    selected: dict[str, tuple[PublicModelLineageClaimKind, str | None, tuple[str, ...]]] = {}
    reasons: dict[str, set[PublicModelLineageUnconfirmedReason]] = {}
    for exact_id, alias in alias_by_id.items():
        subject_claims = claims_by_subject[exact_id]
        alias_sources = set(alias.source_ids)
        if not alias_sources or any(
            source_id not in source_by_id
            or source_by_id[source_id].publisher_id != alias.publisher_id
            for source_id in alias_sources
        ):
            reasons.setdefault(exact_id, set()).add(
                PublicModelLineageUnconfirmedReason.ALIAS_SOURCE_MISMATCH
            )
        if any(claim.source_id not in alias_sources for claim in subject_claims):
            reasons.setdefault(exact_id, set()).add(
                PublicModelLineageUnconfirmedReason.ALIAS_SOURCE_MISMATCH
            )
        material = [
            claim
            for claim in subject_claims
            if claim.claim_kind is not PublicModelLineageClaimKind.VAGUE
        ]
        if not subject_claims:
            reasons.setdefault(exact_id, set()).add(
                PublicModelLineageUnconfirmedReason.MISSING_CLAIM
            )
            continue
        if not material:
            reasons.setdefault(exact_id, set()).add(PublicModelLineageUnconfirmedReason.VAGUE_ONLY)
            continue
        semantics = {(claim.claim_kind, claim.target_exact_model_id) for claim in material}
        if len(semantics) != 1:
            reasons.setdefault(exact_id, set()).add(
                PublicModelLineageUnconfirmedReason.CONFLICTING_CLAIMS
            )
            continue
        semantic = next(iter(semantics))
        decisive = [
            claim
            for claim in material
            if claim.decisive_primary_publisher
            and source_by_id[claim.source_id].source_kind
            is PublicModelLineageSourceKind.PRIMARY_PUBLISHER_MODEL_CARD
            and source_by_id[claim.source_id].publisher_id == alias.publisher_id
        ]
        agreeing_keys = {
            source_by_id[claim.source_id].independence_key
            for claim in material
            if (claim.claim_kind, claim.target_exact_model_id) == semantic
        }
        if not decisive and len(agreeing_keys) < 2:
            reasons.setdefault(exact_id, set()).add(
                PublicModelLineageUnconfirmedReason.INSUFFICIENT_CORROBORATION
            )
            continue
        support = tuple(
            sorted(
                claim.claim_id
                for claim in material
                if (claim.claim_kind, claim.target_exact_model_id) == semantic
            )
        )
        selected[exact_id] = (semantic[0], semantic[1], support)

    # Resolve ancestry targets and cycles without allowing one bad candidate to
    # block unrelated confirmed identities.
    terminal: dict[str, str] = {}

    def resolve_terminal(exact_id: str, stack: tuple[str, ...] = ()) -> str | None:
        if exact_id in terminal:
            return terminal[exact_id]
        if exact_id in stack:
            for member in stack[stack.index(exact_id) :]:
                reasons.setdefault(member, set()).add(PublicModelLineageUnconfirmedReason.CYCLE)
            return None
        if exact_id in reasons or exact_id not in selected:
            return None
        kind, target, _support = selected[exact_id]
        if kind is PublicModelLineageClaimKind.ROOT_ANCHOR:
            terminal[exact_id] = exact_id
            return exact_id
        if (
            kind is not PublicModelLineageClaimKind.ROOTS_WITH
            or target is None
            or target not in alias_by_id
        ):
            reasons.setdefault(exact_id, set()).add(
                PublicModelLineageUnconfirmedReason.UPSTREAM_UNCONFIRMED
            )
            return None
        resolved = resolve_terminal(target, (*stack, exact_id))
        if resolved is None:
            reasons.setdefault(exact_id, set()).add(
                PublicModelLineageUnconfirmedReason.UPSTREAM_UNCONFIRMED
            )
            return None
        terminal[exact_id] = resolved
        return resolved

    for exact_id in alias_by_id:
        resolve_terminal(exact_id)

    root_by_terminal: dict[str, str] = {}
    claim_by_id = {item.claim_id: item for item in claims}
    for root_id in sorted(set(terminal.values())):
        anchor_claim_evidence = tuple(
            sorted(
                (
                    claim_by_id[claim_id].claim_sha256,
                    _stable_root_source_evidence_sha256(
                        source_by_id[claim_by_id[claim_id].source_id]
                    ),
                )
                for claim_id in selected[root_id][2]
            )
        )
        root_material = stable_json(
            {
                "anchor_exact_model_id": root_id,
                "anchor_alias_sha256": alias_by_id[root_id].alias_sha256,
                "anchor_claim_evidence": anchor_claim_evidence,
            }
        ).encode("utf-8")
        root_by_terminal[root_id] = (
            "sha256:" + hashlib.sha256(_ROOT_DOMAIN + root_material).hexdigest()
        )

    decisions: list[PublicModelLineageDecision] = []
    for exact_id, alias in sorted(alias_by_id.items()):
        if exact_id in reasons or exact_id not in terminal:
            observed_reasons: set[PublicModelLineageUnconfirmedReason] = reasons.get(
                exact_id,
                {PublicModelLineageUnconfirmedReason.UPSTREAM_UNCONFIRMED},
            )
            status = PublicModelLineageDecisionStatus.UNCONFIRMED
            root_lineage: str | None = None
            supporting_claim_ids: tuple[str, ...] = ()
            unconfirmed_reasons = tuple(sorted(observed_reasons, key=str))
        else:
            # Include the exact ancestry path, not unrelated descendants.
            path_claims: set[str] = set()
            current = exact_id
            while True:
                kind, target, support = selected[current]
                path_claims.update(support)
                if kind is PublicModelLineageClaimKind.ROOT_ANCHOR:
                    break
                if target is None:
                    raise AssertionError("resolved public lineage target is missing")
                current = target
            status = PublicModelLineageDecisionStatus.CONFIRMED
            root_lineage = root_by_terminal[terminal[exact_id]]
            supporting_claim_ids = tuple(sorted(path_claims))
            unconfirmed_reasons = ()
        provisional = PublicModelLineageDecision.model_construct(
            exact_model_id=exact_id,
            documentary_model_id=alias.documentary_model_id,
            status=status,
            root_lineage=root_lineage,
            supporting_claim_ids=supporting_claim_ids,
            unconfirmed_reasons=unconfirmed_reasons,
            decision_sha256="0" * 64,
        )
        decisions.append(
            PublicModelLineageDecision(
                exact_model_id=exact_id,
                documentary_model_id=alias.documentary_model_id,
                status=status,
                root_lineage=root_lineage,
                supporting_claim_ids=supporting_claim_ids,
                unconfirmed_reasons=unconfirmed_reasons,
                decision_sha256=canonical_sha256(
                    provisional.model_dump(mode="json", exclude={"decision_sha256"})
                ),
            )
        )
    return tuple(decisions)


def _stable_root_source_evidence_sha256(
    source: PublicModelLineageSourceEvidence,
) -> str:
    """Hash immutable publisher identity and bytes for lineage-root derivation.

    Capture time, redirect observations, and local custody paths stay bound by
    the bundle and freshness replay. They are excluded here so recapturing the
    same immutable publisher bytes cannot create an artificial second root.
    """

    return canonical_sha256(
        {
            "source_id": source.source_id,
            "requested_url": source.requested_url,
            "publisher_id": source.publisher_id,
            "independence_key": source.independence_key,
            "source_kind": source.source_kind,
            "immutable_revision": source.immutable_revision,
            "exact_source_bytes_sha256": source.file_binding.sha256,
        }
    )


def _verify_claim_spans(
    claims: Sequence[PublicModelLineageClaim], source_bytes: dict[str, bytes]
) -> None:
    spans_by_source: dict[str, list[tuple[int, int]]] = {}
    for claim in claims:
        content = source_bytes.get(claim.source_id)
        if content is None or claim.byte_end > len(content):
            raise PublicModelLineageAuthorityError(
                "public lineage claim span is outside its source"
            )
        marker = claim.exact_marker.encode("utf-8")
        if content[claim.byte_start : claim.byte_end] != marker:
            raise PublicModelLineageAuthorityError(
                "public lineage claim marker differs from exact bytes"
            )
        spans_by_source.setdefault(claim.source_id, []).append((claim.byte_start, claim.byte_end))
    for spans in spans_by_source.values():
        ordered = sorted(spans)
        if any(previous[1] > current[0] for previous, current in pairwise(ordered)):
            raise PublicModelLineageAuthorityError("public lineage claim spans overlap")


def _require_compiled_production_inventory(bundle: PublicModelLineageEvidenceBundle) -> None:
    if (
        tuple(item.exact_model_id for item in bundle.aliases)
        != PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS
    ):
        raise PublicModelLineageAuthorityError(
            "public lineage production candidate inventory drifted"
        )
    source_ids = tuple(item.source_id for item in bundle.sources)
    if source_ids != _COMPILED_SOURCE_IDS:
        raise PublicModelLineageAuthorityError("public lineage production source inventory drifted")
    observed_pins = tuple(
        (
            item.source_id,
            item.requested_url,
            item.publisher_id,
            item.independence_key,
            item.immutable_revision,
            item.file_binding.path,
        )
        for item in bundle.sources
    )
    if observed_pins != _COMPILED_SOURCE_PINS:
        raise PublicModelLineageAuthorityError("public lineage production source pins drifted")
    observed_constraints = tuple(
        (item.constraint_id, item.member_exact_model_ids)
        for item in bundle.conservative_non_independence_constraints
    )
    if observed_constraints != _COMPILED_CONSERVATIVE_CONSTRAINTS:
        raise PublicModelLineageAuthorityError("public lineage conservative constraints drifted")


def _binding_projection(
    bundle: PublicModelLineageEvidenceBundle,
    state: _VerifiedPublicLineageState,
    decision: PublicModelLineageDecision,
) -> VerifiedPublicModelLineageBindingProjection:
    if decision.root_lineage is None:
        raise AssertionError("unconfirmed public lineage cannot produce a binding")
    return VerifiedPublicModelLineageBindingProjection(
        exact_model_id=decision.exact_model_id,
        documentary_model_id=decision.documentary_model_id,
        root_lineage=decision.root_lineage,
        decision_sha256=decision.decision_sha256,
        bundle_sha256=bundle.bundle_sha256,
        manifest_file_sha256=state.expected_manifest_file_sha256,
        lineage_identity_authorized=True,
        provider_call_authorized=False,
        source_egress_authorized=False,
        runner_authority_authorized=False,
        model_qualification_authorized=False,
        production_selection_authorized=False,
        seal_publication_authorized=False,
        release_authorized=False,
        benchmark_authorized=False,
    )


def _require_source_urls(requested: str, final: str, chain: tuple[str, ...]) -> None:
    if chain[0] != requested or chain[-1] != final or len(chain) != len(set(chain)):
        raise ValueError("public lineage redirect chain is inconsistent")
    for index, value in enumerate(chain):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname not in {"huggingface.co", "raw.githubusercontent.com"}
            or parsed.port is not None
            or parsed.fragment
            or len(value.encode("utf-8")) > 8_192
        ):
            raise ValueError("public lineage source URL is outside the exact HTTPS boundary")
        if index == 0 and (
            parsed.query or ("/resolve/" not in parsed.path and parsed.hostname == "huggingface.co")
        ):
            raise ValueError("public lineage requested URL is not immutable")
        if index > 0 and parsed.hostname != "huggingface.co":
            raise ValueError("public lineage redirect changes source origin")


def _require_source_path(source_id: str, binding: ManifestFileBinding) -> None:
    if (
        binding.path != f"sources/{source_id}.md"
        or binding.size <= 0
        or binding.size > _MAX_SOURCE_BYTES
    ):
        raise ValueError("public lineage source file binding is not exact and bounded")


def _require_whole_second_utc(value: datetime, *, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
        raise ValueError(f"{label} must be whole-second UTC")


def _public_lineage_utc_now() -> datetime:
    """Return the verifier-owned whole-second UTC clock value."""

    return datetime.now(UTC).replace(microsecond=0)


def _require_unique_sorted[T, K: str](
    items: Sequence[T], *, key: Callable[[T], K], label: str
) -> None:
    values = tuple(key(item) for item in items)
    if values != tuple(sorted(set(values))):
        raise ValueError(f"public lineage {label} must be unique and sorted")


def _bounded_tuple[T](values: Iterable[T], maximum: int, *, label: str) -> tuple[T, ...]:
    observed = tuple(islice(iter(values), maximum + 1))
    if len(observed) > maximum:
        raise ValueError(f"{label} exceeds its compiled bound")
    return observed


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    return value


_COMPILED_SOURCE_PINS = (
    (
        "deepcogito-cogito-v2-1-671b-card",
        "https://huggingface.co/deepcogito/cogito-671b-v2.1/resolve/f5b0199c2c54a284b00f1a2db3942299d4198484/README.md",
        "deepcogito",
        "deepcogito",
        "f5b0199c2c54a284b00f1a2db3942299d4198484",
        "sources/deepcogito-cogito-v2-1-671b-card.md",
    ),
    (
        "deepseek-deepseek-v3-2-exp-card",
        "https://huggingface.co/deepseek-ai/DeepSeek-V3.2-Exp/resolve/a678d82902a8da587f29fd3f3ad22dd35b522ed5/README.md",
        "deepseek-ai",
        "deepseek-ai",
        "a678d82902a8da587f29fd3f3ad22dd35b522ed5",
        "sources/deepseek-deepseek-v3-2-exp-card.md",
    ),
    (
        "deepseek-deepseek-v4-pro-0813-card",
        "https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro-0813/resolve/72e1d3230f6c080a530b0a1d46f8eb4602340597/README.md",
        "deepseek-ai",
        "deepseek-ai",
        "72e1d3230f6c080a530b0a1d46f8eb4602340597",
        "sources/deepseek-deepseek-v4-pro-0813-card.md",
    ),
    (
        "google-gemma-4-26b-a4b-it-card",
        "https://huggingface.co/google/gemma-4-26B-A4B-it/resolve/b2a81a03d25f927590a91d84ba43f96e8ef7349f/README.md",
        "google-deepmind",
        "google-deepmind",
        "b2a81a03d25f927590a91d84ba43f96e8ef7349f",
        "sources/google-gemma-4-26b-a4b-it-card.md",
    ),
    (
        "meta-llama-4-maverick-card",
        "https://huggingface.co/meta-llama/Llama-4-Maverick-17B-128E-Instruct/resolve/73d14711bcc77c16df3470856949c3764056b617/README.md",
        "meta",
        "meta",
        "73d14711bcc77c16df3470856949c3764056b617",
        "sources/meta-llama-4-maverick-card.md",
    ),
    (
        "minimax-m3-card",
        "https://huggingface.co/MiniMaxAI/MiniMax-M3/resolve/f0e1c1e04d40177e4673a22097036854f536e9c0/README.md",
        "minimax",
        "minimax",
        "f0e1c1e04d40177e4673a22097036854f536e9c0",
        "sources/minimax-m3-card.md",
    ),
    (
        "mistral-small-4-119b-2603-card",
        "https://huggingface.co/mistralai/Mistral-Small-4-119B-2603/resolve/97ee14542b6c053394af45dd2ff89aadecf457a0/README.md",
        "mistral-ai",
        "mistral-ai",
        "97ee14542b6c053394af45dd2ff89aadecf457a0",
        "sources/mistral-small-4-119b-2603-card.md",
    ),
    (
        "moonshot-kimi-k2-thinking-card",
        "https://huggingface.co/moonshotai/Kimi-K2-Thinking/resolve/1b9dbb7b20fe8e92047f956b75f3bc49d69f8f73/README.md",
        "moonshot-ai",
        "moonshot-ai",
        "1b9dbb7b20fe8e92047f956b75f3bc49d69f8f73",
        "sources/moonshot-kimi-k2-thinking-card.md",
    ),
    (
        "moonshot-kimi-k3-card",
        "https://huggingface.co/moonshotai/Kimi-K3/resolve/a590ce090cb049c93a33dfe8c208ec652aa20503/README.md",
        "moonshot-ai",
        "moonshot-ai",
        "a590ce090cb049c93a33dfe8c208ec652aa20503",
        "sources/moonshot-kimi-k3-card.md",
    ),
    (
        "nvidia-nemotron-3-super-120b-a12b-base-card",
        "https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-Base-BF16/resolve/46cc6113d364942e7742b0b2afd35b5db5058b29/README.md",
        "nvidia",
        "nvidia",
        "46cc6113d364942e7742b0b2afd35b5db5058b29",
        "sources/nvidia-nemotron-3-super-120b-a12b-base-card.md",
    ),
    (
        "nvidia-nemotron-3-super-120b-a12b-posttrain-card",
        "https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16/resolve/d51eab0d1f979ebc26b546e634a04f450d99158e/README.md",
        "nvidia",
        "nvidia",
        "d51eab0d1f979ebc26b546e634a04f450d99158e",
        "sources/nvidia-nemotron-3-super-120b-a12b-posttrain-card.md",
    ),
    (
        "openai-gpt-oss-120b-readme",
        "https://raw.githubusercontent.com/openai/gpt-oss/599476783c6f88508dab8577808b5ead5cbee8d2/README.md",
        "openai",
        "openai",
        "599476783c6f88508dab8577808b5ead5cbee8d2",
        "sources/openai-gpt-oss-120b-readme.md",
    ),
    (
        "qwen-qwen3-6-35b-a3b-card",
        "https://huggingface.co/Qwen/Qwen3.6-35B-A3B/resolve/995ad96eacd98c81ed38be0c5b274b04031597b0/README.md",
        "alibaba-qwen",
        "alibaba-qwen",
        "995ad96eacd98c81ed38be0c5b274b04031597b0",
        "sources/qwen-qwen3-6-35b-a3b-card.md",
    ),
    (
        "tencent-hunyuan-a13b-instruct-card",
        "https://huggingface.co/tencent/Hunyuan-A13B-Instruct/resolve/290ddb9a56ed23c2c83a1c8081533e58925df952/README.md",
        "tencent-hunyuan",
        "tencent-hunyuan",
        "290ddb9a56ed23c2c83a1c8081533e58925df952",
        "sources/tencent-hunyuan-a13b-instruct-card.md",
    ),
    (
        "tencent-hy3-card",
        "https://huggingface.co/tencent/Hy3/resolve/a960ebc3da325ba167f069f76c41eb62c9280d22/README.md",
        "tencent",
        "tencent",
        "a960ebc3da325ba167f069f76c41eb62c9280d22",
        "sources/tencent-hy3-card.md",
    ),
    (
        "z-ai-glm-4-7-card",
        "https://huggingface.co/zai-org/GLM-4.7/resolve/2765a661c9061116a4bef693c61f5de3f0687f2c/README.md",
        "z-ai",
        "z-ai",
        "2765a661c9061116a4bef693c61f5de3f0687f2c",
        "sources/z-ai-glm-4-7-card.md",
    ),
)
_COMPILED_SOURCE_IDS = tuple(item[0] for item in _COMPILED_SOURCE_PINS)
_COMPILED_CONSERVATIVE_CONSTRAINTS = (
    (
        "constraint-cogito-deepseek",
        ("deepcogito/cogito-v2.1-671b", "deepseek/deepseek-v3.2-exp"),
    ),
    (
        "constraint-deepseek-family",
        (
            "deepcogito/cogito-v2.1-671b",
            "deepseek/deepseek-v3.2-exp",
            "deepseek/deepseek-v4-pro-0813",
        ),
    ),
    ("constraint-gemma-gemini", ("google/gemini-3.7-flash", "google/gemma-4-26b-a4b-it")),
    ("constraint-gpt-oss-gpt-5-6", ("openai/gpt-5.6-sol", "openai/gpt-oss-120b")),
    ("constraint-kimi-k2-k3", ("moonshotai/kimi-k2-thinking", "moonshotai/kimi-k3")),
    (
        "constraint-nemotron-meta",
        ("meta-llama/llama-4-maverick", "nvidia/nemotron-3-super-120b-a12b"),
    ),
    (
        "constraint-tencent-hy3-hunyuan",
        ("tencent/hunyuan-a13b-instruct", "tencent/hy3"),
    ),
)


def _build_public_lineage_runtime_authority() -> tuple[
    Callable[[], VerifiedPublicModelLineage],
    Callable[[VerifiedPublicModelLineage], VerifiedPublicModelLineageInventory],
    Callable[[VerifiedPublicModelLineage, str], VerifiedPublicModelLineageBindingProjection],
    Callable[
        [VerifiedPublicModelLineage, str, str],
        VerifiedIndependentPublicModelLineageProjection,
    ],
    Callable[[VerifiedPublicModelLineage], tuple[str, ...]],
]:
    """Capture the compiled production contract against ordinary reassignment."""

    namespace = globals()
    trusted_objects = {
        "PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT": PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT,
        "_CAPABILITY_LOCK": _CAPABILITY_LOCK,
        "_CAPABILITY_STATES": _CAPABILITY_STATES,
        "_binding_projection": _binding_projection,
        "_bounded_tuple": _bounded_tuple,
        "_derive_public_lineage_decisions": _derive_public_lineage_decisions,
        "_approved_public_model_lineages_impl": _approved_public_model_lineages_impl,
        "_load_and_verify_bundle": _load_and_verify_bundle,
        "_public_model_lineage_inventory_impl": _public_model_lineage_inventory_impl,
        "_public_lineage_utc_now": _public_lineage_utc_now,
        "_replay_capability": _replay_capability,
        "_require_compiled_production_inventory": _require_compiled_production_inventory,
        "_require_independent_public_model_lineage_impl": (
            _require_independent_public_model_lineage_impl
        ),
        "_require_source_path": _require_source_path,
        "_require_source_urls": _require_source_urls,
        "_require_unique_sorted": _require_unique_sorted,
        "_require_verified_public_model_lineage_impl": (
            _require_verified_public_model_lineage_impl
        ),
        "_require_whole_second_utc": _require_whole_second_utc,
        "_resolve_verified_public_model_lineage": _resolve_verified_public_model_lineage,
        "_stable_root_source_evidence_sha256": _stable_root_source_evidence_sha256,
        "_verify_claim_spans": _verify_claim_spans,
        "canonical_sha256": canonical_sha256,
        "read_file_evidence": read_file_evidence,
        "read_json_evidence": read_json_evidence,
        "require_exact_openrouter_model_id": require_exact_openrouter_model_id,
        "stable_json": stable_json,
        "datetime": datetime,
        "UTC": UTC,
        "timedelta": timedelta,
        "ManifestFileBinding": ManifestFileBinding,
        "PublicModelLineageAliasBinding": PublicModelLineageAliasBinding,
        "PublicModelLineageCaptureObservation": PublicModelLineageCaptureObservation,
        "PublicModelLineageCaptureJournal": PublicModelLineageCaptureJournal,
        "PublicModelLineageClaim": PublicModelLineageClaim,
        "PublicModelLineageClaimKind": PublicModelLineageClaimKind,
        "PublicModelLineageConstraintKind": PublicModelLineageConstraintKind,
        "PublicModelLineageDecision": PublicModelLineageDecision,
        "PublicModelLineageDecisionStatus": PublicModelLineageDecisionStatus,
        "PublicModelLineageEvidenceBundle": PublicModelLineageEvidenceBundle,
        "PublicModelLineageNonIndependenceConstraint": (
            PublicModelLineageNonIndependenceConstraint
        ),
        "PublicModelLineageSourceKind": PublicModelLineageSourceKind,
        "PublicModelLineageSourceEvidence": PublicModelLineageSourceEvidence,
        "PublicModelLineageUnconfirmedReason": PublicModelLineageUnconfirmedReason,
        "VerifiedIndependentPublicModelLineageProjection": (
            VerifiedIndependentPublicModelLineageProjection
        ),
        "VerifiedPublicModelLineage": VerifiedPublicModelLineage,
        "VerifiedPublicModelLineageBindingProjection": (
            VerifiedPublicModelLineageBindingProjection
        ),
        "VerifiedPublicModelLineageInventory": VerifiedPublicModelLineageInventory,
        "_VerifiedPublicLineageState": _VerifiedPublicLineageState,
    }
    trusted_values = {
        "PUBLIC_MODEL_LINEAGE_MANIFEST_FILENAME": PUBLIC_MODEL_LINEAGE_MANIFEST_FILENAME,
        "PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME": (
            PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME
        ),
        "PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256": (PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256),
        "PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS": (PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS),
        "_COMPILED_SOURCE_PINS": _COMPILED_SOURCE_PINS,
        "_COMPILED_SOURCE_IDS": _COMPILED_SOURCE_IDS,
        "_COMPILED_CONSERVATIVE_CONSTRAINTS": _COMPILED_CONSERVATIVE_CONSTRAINTS,
        "_ROOT_DOMAIN": _ROOT_DOMAIN,
        "_MAX_SOURCES": _MAX_SOURCES,
        "_MAX_MODELS": _MAX_MODELS,
        "_MAX_CLAIMS": _MAX_CLAIMS,
        "_MAX_CONSTRAINTS": _MAX_CONSTRAINTS,
        "_MAX_SOURCE_BYTES": _MAX_SOURCE_BYTES,
        "_MAX_TOTAL_SOURCE_BYTES": _MAX_TOTAL_SOURCE_BYTES,
        "_MAX_MANIFEST_BYTES": _MAX_MANIFEST_BYTES,
        "_MAX_CAPTURE_JOURNAL_BYTES": _MAX_CAPTURE_JOURNAL_BYTES,
        "_MAX_MARKER_BYTES": _MAX_MARKER_BYTES,
        "_MAX_REDIRECTS": _MAX_REDIRECTS,
        "_MAX_SOURCE_SPREAD": _MAX_SOURCE_SPREAD,
        "_MAX_VERIFICATION_DELAY": _MAX_VERIFICATION_DELAY,
        "_MAX_VALIDITY": _MAX_VALIDITY,
        "_CONCRETE_PATH_TYPE": _CONCRETE_PATH_TYPE,
    }
    trusted_sha256 = hashlib.sha256
    trusted_getpid = os.getpid
    trusted_urlsplit = urlsplit
    canonical_globals = canonical_sha256.__globals__
    canonical_json = cast(ModuleType, canonical_globals["json"])
    canonical_hashlib = cast(ModuleType, canonical_globals["hashlib"])
    canonical_json_dumps = canonical_json.dumps
    canonical_hashlib_sha256 = canonical_hashlib.sha256
    stable_json_globals = stable_json.__globals__
    stable_json_json = cast(ModuleType, stable_json_globals["json"])
    stable_json_base_model = stable_json_globals["BaseModel"]
    stable_json_dumps = stable_json_json.dumps
    trusted_state_type = _VerifiedPublicLineageState
    trusted_capability_type = VerifiedPublicModelLineage
    trusted_root = PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT
    trusted_manifest_sha256 = PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256
    trusted_datetime_now = datetime.now
    trusted_utc = UTC

    def trusted_clock() -> datetime:
        return trusted_datetime_now(trusted_utc).replace(microsecond=0)

    trusted_load = _load_and_verify_bundle
    trusted_lock = _CAPABILITY_LOCK
    trusted_registry = _CAPABILITY_STATES
    trusted_inventory = _public_model_lineage_inventory_impl
    trusted_require = _require_verified_public_model_lineage_impl
    trusted_require_independent = _require_independent_public_model_lineage_impl
    trusted_approved = _approved_public_model_lineages_impl
    public_bindings: dict[str, object] = {}

    def require_pristine() -> None:
        if (
            any(namespace.get(name) is not value for name, value in trusted_objects.items())
            or any(namespace.get(name) != value for name, value in trusted_values.items())
            or hashlib.sha256 is not trusted_sha256
            or os.getpid is not trusted_getpid
            or urlsplit is not trusted_urlsplit
            or canonical_globals.get("json") is not canonical_json
            or canonical_globals.get("hashlib") is not canonical_hashlib
            or canonical_json.dumps is not canonical_json_dumps
            or canonical_hashlib.sha256 is not canonical_hashlib_sha256
            or stable_json_globals.get("json") is not stable_json_json
            or stable_json_globals.get("BaseModel") is not stable_json_base_model
            or stable_json_json.dumps is not stable_json_dumps
            or any(namespace.get(name) is not value for name, value in public_bindings.items())
        ):
            raise PublicModelLineageAuthorityError(
                "public lineage verifier runtime is not pristine"
            )

    def resolve() -> VerifiedPublicModelLineage:
        require_pristine()
        if trusted_manifest_sha256 == "0" * 64:
            raise PublicModelLineageAuthorityError("public lineage manifest pin is not compiled")
        verification_time = trusted_clock()
        _require_whole_second_utc(verification_time, label="public lineage verification")
        first = trusted_load(
            trusted_root,
            trusted_manifest_sha256,
            verification_time,
            require_production_inventory=True,
        )
        second = trusted_load(
            trusted_root,
            trusted_manifest_sha256,
            verification_time,
            require_production_inventory=True,
        )
        if first != second:
            raise PublicModelLineageAuthorityError(
                "public lineage evidence changed during verification"
            )
        result = object.__new__(trusted_capability_type)
        state = trusted_state_type(
            process_id=trusted_getpid(),
            evidence_root=trusted_root,
            expected_manifest_file_sha256=trusted_manifest_sha256,
            clock=trusted_clock,
            require_production_inventory=True,
            bundle_sha256=first.bundle_sha256,
        )
        with trusted_lock:
            trusted_registry[result] = state
        require_pristine()
        return result

    def inventory(
        capability: VerifiedPublicModelLineage,
    ) -> VerifiedPublicModelLineageInventory:
        require_pristine()
        result = trusted_inventory(capability, clock=trusted_clock)
        require_pristine()
        return result

    def require(
        capability: VerifiedPublicModelLineage,
        exact_model_id: str,
    ) -> VerifiedPublicModelLineageBindingProjection:
        require_pristine()
        result = trusted_require(capability, exact_model_id, clock=trusted_clock)
        require_pristine()
        return result

    def require_independent(
        capability: VerifiedPublicModelLineage,
        left_exact_model_id: str,
        right_exact_model_id: str,
    ) -> VerifiedIndependentPublicModelLineageProjection:
        require_pristine()
        result = trusted_require_independent(
            capability,
            left_exact_model_id,
            right_exact_model_id,
            clock=trusted_clock,
        )
        require_pristine()
        return result

    def approved(capability: VerifiedPublicModelLineage) -> tuple[str, ...]:
        require_pristine()
        result = trusted_approved(capability, clock=trusted_clock)
        require_pristine()
        return result

    public_bindings.update(
        {
            "resolve_verified_public_model_lineage": resolve,
            "public_model_lineage_inventory": inventory,
            "require_verified_public_model_lineage": require,
            "require_independent_public_model_lineage": require_independent,
            "approved_public_model_lineages": approved,
        }
    )
    return resolve, inventory, require, require_independent, approved


(
    resolve_verified_public_model_lineage,
    public_model_lineage_inventory,
    require_verified_public_model_lineage,
    require_independent_public_model_lineage,
    approved_public_model_lineages,
) = _build_public_lineage_runtime_authority()
del _build_public_lineage_runtime_authority
