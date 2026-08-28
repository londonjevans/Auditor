"""Bounded, tenant-scoped capture of nonauthorizing terminal-audit learning.

This module stores only a deterministic terminal outcome projection.  Its records
are leads for offline analysis; they cannot confirm a finding, grant confidence,
coverage, or consensus credit, prime a later audit, dispatch a provider request,
or authorize qualification or release.  In particular, benchmark, private-holdout,
and time-split material have no representable source kind.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable
from datetime import datetime, timedelta
from enum import StrEnum
from itertools import islice
from typing import Annotated, Any, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.constants import ALL_SPECIALIST_ROLES
from mmaudit.models.schemas import StrictModel

TERMINAL_AUDIT_LEARNING_SCHEMA_VERSION: Final = "mmaudit.terminal-audit-learning.v1"

MAX_LEARNING_CONFIRMED_FINDINGS: Final = 4_096
MAX_LEARNING_REJECTED_CANDIDATES: Final = 16_384
MAX_LEARNING_ATTRIBUTIONS: Final = 65_536
MAX_LEARNING_REVIEWED_SURFACES: Final = 20_000
MAX_LEARNING_ROLE_USAGE_RECORDS: Final = 256
MAX_LEARNING_EXTERNAL_MISSES: Final = 4_096
MAX_LEARNING_RELATED_TARGETS_PER_SURFACE: Final = 1_024
MAX_LEARNING_MODELS_PER_ROLE: Final = 64
MAX_LEARNING_REQUESTS_PER_ROLE: Final = 100_000
MAX_LEARNING_RECORD_JSON_BYTES: Final = 32_000_000
MAX_LEARNING_SHORT_TEXT_CHARS: Final = 512
MAX_LEARNING_LONG_TEXT_CHARS: Final = 4_096

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_TENANT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_CODE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_USD_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,12})(?:\.[0-9]{1,36})?$"
_SECONDS_EXACT_PATTERN = r"^(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,9})?$"

TenantId = Annotated[str, Field(min_length=1, max_length=128, pattern=_TENANT_ID_PATTERN)]
LearningId = Annotated[str, Field(min_length=1, max_length=256, pattern=_IDENTIFIER_PATTERN)]
LearningCode = Annotated[str, Field(min_length=1, max_length=128, pattern=_CODE_PATTERN)]
Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]
ShortText = Annotated[str, Field(min_length=1, max_length=MAX_LEARNING_SHORT_TEXT_CHARS)]
LongText = Annotated[str, Field(min_length=1, max_length=MAX_LEARNING_LONG_TEXT_CHARS)]
ExactUsd = Annotated[str, Field(pattern=_USD_EXACT_PATTERN)]
ExactSeconds = Annotated[str, Field(pattern=_SECONDS_EXACT_PATTERN)]


class LearningSourceKind(StrEnum):
    """The complete admissible source inventory for Phase-1 capture.

    Benchmark, private-holdout, and time-split sources are deliberately absent.
    """

    TERMINAL_PRODUCTION_AUDIT = "TERMINAL_PRODUCTION_AUDIT"
    LATER_EXTERNAL_ESTABLISHMENT = "LATER_EXTERNAL_ESTABLISHMENT"


class LearningFindingSeverity(StrEnum):
    """Stable severity retained as a lead attribute, never as confidence credit."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class LearningAcceptedFindingStatus(StrEnum):
    """The only terminal status admitted to the confirmed-finding inventory."""

    CONFIRMED = "confirmed"


class LearningActorKind(StrEnum):
    """Whether an attribution belongs to a general model role or a specialist."""

    MODEL = "MODEL"
    SPECIALIST = "SPECIALIST"


class LearningAttributionOutcome(StrEnum):
    """Closed outcome vocabulary for one model/specialist contribution."""

    PROPOSED = "PROPOSED"
    VERIFIED = "VERIFIED"
    FALSIFIED = "FALSIFIED"
    MISSED = "MISSED"


class LearningAttributionTargetKind(StrEnum):
    """Typed target inventories for attribution joins."""

    CONFIRMED_FINDING = "CONFIRMED_FINDING"
    REJECTED_CANDIDATE = "REJECTED_CANDIDATE"
    EXTERNAL_MISS = "EXTERNAL_MISS"


class LearningSurfaceKind(StrEnum):
    """Bounded surface kinds retained from a terminal audit."""

    SOURCE_FILE = "SOURCE_FILE"
    CONTRACT = "CONTRACT"
    FUNCTION = "FUNCTION"
    STATE = "STATE"
    INVARIANT = "INVARIANT"
    CALL_PATH = "CALL_PATH"
    OTHER = "OTHER"


class LearningSurfaceOutcome(StrEnum):
    """Exact terminal disposition of one reviewed surface."""

    CONFIRMED_FINDINGS = "CONFIRMED_FINDINGS"
    REJECTED_CANDIDATES = "REJECTED_CANDIDATES"
    MIXED = "MIXED"
    REVIEWED_NO_ISSUE = "REVIEWED_NO_ISSUE"
    INCONCLUSIVE = "INCONCLUSIVE"


class ExternalMissEstablishmentKind(StrEnum):
    """Allowed post-audit ways a real miss can be independently established."""

    INDEPENDENT_POST_AUDIT_REVIEW = "INDEPENDENT_POST_AUDIT_REVIEW"
    CLIENT_CONFIRMED_POST_AUDIT = "CLIENT_CONFIRMED_POST_AUDIT"
    PUBLIC_POST_AUDIT_DISCLOSURE = "PUBLIC_POST_AUDIT_DISCLOSURE"


class _LearningStrictModel(StrictModel):
    """Deep-frozen strict base with exact, canonical text handling."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )

    @model_validator(mode="after")
    def strings_are_exact_bounded_unicode(self) -> Self:
        for field_name in type(self).model_fields:
            _require_exact_strings(getattr(self, field_name), label=field_name)
        return self


class TerminalConfirmedFinding(_LearningStrictModel):
    """One finding confirmed by the completed audit, retained only as a lead."""

    tenant_id: TenantId
    source_kind: Literal[LearningSourceKind.TERMINAL_PRODUCTION_AUDIT]
    finding_id: LearningId
    finding_sha256: Sha256
    title_excerpt: ShortText
    category: LearningCode
    status: Literal[LearningAcceptedFindingStatus.CONFIRMED]
    severity: LearningFindingSeverity
    summary_excerpt: LongText


class TerminalRejectedCandidate(_LearningStrictModel):
    """One terminally rejected candidate and its explicit rejection reason."""

    tenant_id: TenantId
    source_kind: Literal[LearningSourceKind.TERMINAL_PRODUCTION_AUDIT]
    candidate_id: LearningId
    candidate_sha256: Sha256
    title_excerpt: ShortText
    category: LearningCode
    reason_code: LearningCode
    reason_excerpt: LongText


class ExternallyEstablishedMiss(_LearningStrictModel):
    """A real audit miss established after completion by an allowed external path."""

    tenant_id: TenantId
    source_kind: Literal[LearningSourceKind.LATER_EXTERNAL_ESTABLISHMENT]
    external_miss_id: LearningId
    finding_sha256: Sha256
    title_excerpt: ShortText
    category: LearningCode
    severity: LearningFindingSeverity
    summary_excerpt: LongText
    established_at: datetime
    establishment_kind: ExternalMissEstablishmentKind
    establishment_reference_sha256: Sha256
    expected_surface_ids: Annotated[
        tuple[LearningId, ...],
        Field(min_length=1, max_length=MAX_LEARNING_RELATED_TARGETS_PER_SURFACE),
    ]

    @field_validator("established_at")
    @classmethod
    def established_at_is_exact_utc(cls, value: datetime) -> datetime:
        return _require_whole_second_utc(value, label="external miss establishment")

    @model_validator(mode="after")
    def expected_surfaces_are_canonical(self) -> Self:
        _require_sorted_unique_strings(
            self.expected_surface_ids,
            label="external-miss expected surface IDs",
        )
        return self


class TerminalReviewerAttribution(_LearningStrictModel):
    """One exact proposed/verified/falsified/missed event for a model or specialist."""

    tenant_id: TenantId
    source_kind: LearningSourceKind
    attribution_id: LearningId
    actor_kind: LearningActorKind
    actor_id: LearningId
    model_id: LearningId
    audit_role: LearningCode
    specialist_role: LearningCode | None
    outcome: LearningAttributionOutcome
    target_kind: LearningAttributionTargetKind
    target_id: LearningId
    target_sha256: Sha256
    surface_ids: Annotated[
        tuple[LearningId, ...],
        Field(max_length=MAX_LEARNING_RELATED_TARGETS_PER_SURFACE),
    ] = ()

    @model_validator(mode="after")
    def actor_target_and_source_are_coherent(self) -> Self:
        expected_specialist = learning_specialist_role(self.audit_role)
        expected_kind = (
            LearningActorKind.SPECIALIST
            if expected_specialist is not None
            else LearningActorKind.MODEL
        )
        if self.actor_kind is not expected_kind or self.specialist_role != expected_specialist:
            raise ValueError("learning actor kind differs from its exact audit role")
        if self.actor_id != learning_actor_id(
            audit_role=self.audit_role,
            model_id=self.model_id,
        ):
            raise ValueError("learning actor ID differs from its exact reviewer identity")

        allowed_targets = {
            LearningAttributionOutcome.PROPOSED: {
                LearningAttributionTargetKind.CONFIRMED_FINDING,
                LearningAttributionTargetKind.REJECTED_CANDIDATE,
            },
            LearningAttributionOutcome.VERIFIED: {
                LearningAttributionTargetKind.CONFIRMED_FINDING,
                LearningAttributionTargetKind.REJECTED_CANDIDATE,
            },
            LearningAttributionOutcome.FALSIFIED: {
                LearningAttributionTargetKind.CONFIRMED_FINDING,
                LearningAttributionTargetKind.REJECTED_CANDIDATE,
            },
            LearningAttributionOutcome.MISSED: {
                LearningAttributionTargetKind.CONFIRMED_FINDING,
                LearningAttributionTargetKind.EXTERNAL_MISS,
            },
        }
        if self.target_kind not in allowed_targets[self.outcome]:
            raise ValueError("learning attribution outcome cannot apply to that target kind")

        external = self.target_kind is LearningAttributionTargetKind.EXTERNAL_MISS
        expected_source = (
            LearningSourceKind.LATER_EXTERNAL_ESTABLISHMENT
            if external
            else LearningSourceKind.TERMINAL_PRODUCTION_AUDIT
        )
        if self.source_kind is not expected_source:
            raise ValueError("learning attribution source does not match its target origin")
        _require_sorted_unique_strings(self.surface_ids, label="attribution surface IDs")
        if (self.outcome is LearningAttributionOutcome.MISSED) != bool(self.surface_ids):
            raise ValueError("only missed attribution requires one or more reviewed surfaces")
        return self


class TerminalReviewedSurface(_LearningStrictModel):
    """One canonical reviewed surface and its exact terminal outcome."""

    tenant_id: TenantId
    source_kind: Literal[LearningSourceKind.TERMINAL_PRODUCTION_AUDIT]
    surface_id: LearningId
    surface_sha256: Sha256
    surface_kind: LearningSurfaceKind
    descriptor_excerpt: ShortText
    outcome: LearningSurfaceOutcome
    credited_reviewer_actor_ids: Annotated[
        tuple[LearningId, ...],
        Field(max_length=MAX_LEARNING_MODELS_PER_ROLE),
    ]
    confirmed_finding_ids: Annotated[
        tuple[LearningId, ...], Field(max_length=MAX_LEARNING_RELATED_TARGETS_PER_SURFACE)
    ]
    rejected_candidate_ids: Annotated[
        tuple[LearningId, ...], Field(max_length=MAX_LEARNING_RELATED_TARGETS_PER_SURFACE)
    ]

    @model_validator(mode="after")
    def outcome_and_targets_are_exact(self) -> Self:
        _require_sorted_unique_strings(
            self.confirmed_finding_ids,
            label="reviewed-surface confirmed finding IDs",
        )
        _require_sorted_unique_strings(
            self.rejected_candidate_ids,
            label="reviewed-surface rejected candidate IDs",
        )
        _require_sorted_unique_strings(
            self.credited_reviewer_actor_ids,
            label="reviewed-surface credited reviewer actor IDs",
        )
        if (
            self.outcome is LearningSurfaceOutcome.INCONCLUSIVE
            and not self.credited_reviewer_actor_ids
        ):
            return self
        if not self.credited_reviewer_actor_ids:
            raise ValueError("reviewed surface outcome requires credited reviewer identities")
        has_confirmed = bool(self.confirmed_finding_ids)
        has_rejected = bool(self.rejected_candidate_ids)
        expected = {
            (True, False): LearningSurfaceOutcome.CONFIRMED_FINDINGS,
            (False, True): LearningSurfaceOutcome.REJECTED_CANDIDATES,
            (True, True): LearningSurfaceOutcome.MIXED,
        }.get((has_confirmed, has_rejected))
        if expected is None:
            if self.outcome not in {
                LearningSurfaceOutcome.REVIEWED_NO_ISSUE,
                LearningSurfaceOutcome.INCONCLUSIVE,
            }:
                raise ValueError("reviewed surface outcome requires related terminal targets")
        elif self.outcome is not expected:
            raise ValueError("reviewed surface outcome differs from its related targets")
        return self


class TerminalRoleResourceUsage(_LearningStrictModel):
    """Exact aggregate cost and runtime for one terminal audit role."""

    tenant_id: TenantId
    source_kind: Literal[LearningSourceKind.TERMINAL_PRODUCTION_AUDIT]
    role_id: LearningCode
    model_ids: Annotated[
        tuple[LearningId, ...], Field(min_length=1, max_length=MAX_LEARNING_MODELS_PER_ROLE)
    ]
    request_count: Annotated[int, Field(ge=1, le=MAX_LEARNING_REQUESTS_PER_ROLE)]
    cost_usd_exact: ExactUsd
    runtime_seconds_exact: ExactSeconds

    @model_validator(mode="after")
    def model_inventory_is_canonical(self) -> Self:
        _require_sorted_unique_strings(self.model_ids, label="role usage model IDs")
        return self


class TerminalAuditLearningRecord(_LearningStrictModel):
    """Self-hashed Phase-1 record for exactly one tenant and one completed audit."""

    schema_version: Literal["mmaudit.terminal-audit-learning.v1"]
    record_kind: Literal["TERMINAL_AUDIT_LEARNING_RECORD"]
    tenant_id: TenantId
    audit_id: LearningId
    terminal_report_authority_sha256: Sha256
    report_payload_sha256: Sha256
    parent_record_sha256: Sha256 | None
    source_kind: Literal[LearningSourceKind.TERMINAL_PRODUCTION_AUDIT]
    terminal_state: Literal["COMPLETED"]
    completed_at: datetime
    captured_at: datetime
    confirmed_findings: Annotated[
        tuple[TerminalConfirmedFinding, ...],
        Field(max_length=MAX_LEARNING_CONFIRMED_FINDINGS),
    ]
    rejected_candidates: Annotated[
        tuple[TerminalRejectedCandidate, ...],
        Field(max_length=MAX_LEARNING_REJECTED_CANDIDATES),
    ]
    reviewer_attributions: Annotated[
        tuple[TerminalReviewerAttribution, ...],
        Field(max_length=MAX_LEARNING_ATTRIBUTIONS),
    ]
    reviewed_surfaces: Annotated[
        tuple[TerminalReviewedSurface, ...],
        Field(min_length=1, max_length=MAX_LEARNING_REVIEWED_SURFACES),
    ]
    role_usage: Annotated[
        tuple[TerminalRoleResourceUsage, ...],
        Field(min_length=1, max_length=MAX_LEARNING_ROLE_USAGE_RECORDS),
    ]
    external_misses: Annotated[
        tuple[ExternallyEstablishedMiss, ...],
        Field(max_length=MAX_LEARNING_EXTERNAL_MISSES),
    ]

    permitted_use: Literal["LEAD_ONLY_NON_PRIMING"]
    authority: Literal["NONAUTHORIZING"]
    evidence_credit_authorized: Literal[False]
    confidence_credit_authorized: Literal[False]
    coverage_credit_authorized: Literal[False]
    consensus_credit_authorized: Literal[False]
    prompt_priming_authorized: Literal[False]
    cross_tenant_aggregation_authorized: Literal[False]
    provider_dispatch_authorized: Literal[False]
    qualification_authorized: Literal[False]
    release_authorized: Literal[False]
    record_sha256: Sha256

    @field_validator("completed_at")
    @classmethod
    def completion_timestamp_is_exact_utc(cls, value: datetime) -> datetime:
        return _require_utc(value, label="terminal learning completion")

    @field_validator("captured_at")
    @classmethod
    def capture_timestamp_is_exact_utc(cls, value: datetime) -> datetime:
        return _require_whole_second_utc(value, label="terminal learning capture")

    @model_validator(mode="after")
    def record_is_tenant_scoped_canonical_joined_and_self_hashed(self) -> Self:
        if self.captured_at < self.completed_at:
            raise ValueError("learning record cannot be captured before audit completion")

        collections: tuple[tuple[BaseModel, ...], ...] = (
            self.confirmed_findings,
            self.rejected_candidates,
            self.reviewer_attributions,
            self.reviewed_surfaces,
            self.role_usage,
            self.external_misses,
        )
        for collection in collections:
            if any(getattr(item, "tenant_id", None) != self.tenant_id for item in collection):
                raise ValueError("learning record cannot aggregate across tenant IDs")

        _require_canonical_models(
            self.confirmed_findings,
            key=lambda item: item.finding_id,
            label="confirmed findings",
        )
        _require_canonical_models(
            self.rejected_candidates,
            key=lambda item: item.candidate_id,
            label="rejected candidates",
        )
        _require_canonical_models(
            self.reviewer_attributions,
            key=lambda item: item.attribution_id,
            label="reviewer attributions",
        )
        _require_canonical_models(
            self.reviewed_surfaces,
            key=lambda item: item.surface_id,
            label="reviewed surfaces",
        )
        _require_canonical_models(
            self.role_usage,
            key=lambda item: item.role_id,
            label="role usage",
        )
        _require_canonical_models(
            self.external_misses,
            key=lambda item: item.external_miss_id,
            label="external misses",
        )

        confirmed = {item.finding_id: item.finding_sha256 for item in self.confirmed_findings}
        rejected = {item.candidate_id: item.candidate_sha256 for item in self.rejected_candidates}
        external = {item.external_miss_id: item.finding_sha256 for item in self.external_misses}
        if bool(external) != (self.parent_record_sha256 is not None):
            raise ValueError("external-miss snapshots require one parent learning record")
        if (
            set(confirmed) & set(rejected)
            or set(confirmed) & set(external)
            or set(rejected) & set(external)
        ):
            raise ValueError("learning target IDs must be globally unambiguous")

        target_indexes = {
            LearningAttributionTargetKind.CONFIRMED_FINDING: confirmed,
            LearningAttributionTargetKind.REJECTED_CANDIDATE: rejected,
            LearningAttributionTargetKind.EXTERNAL_MISS: external,
        }
        attribution_semantics: set[tuple[object, ...]] = set()
        actor_identities: dict[str, tuple[object, ...]] = {}
        for attribution in self.reviewer_attributions:
            semantic_key = (
                attribution.actor_kind,
                attribution.actor_id,
                attribution.model_id,
                attribution.audit_role,
                attribution.specialist_role,
                attribution.outcome,
                attribution.target_kind,
                attribution.target_id,
                attribution.target_sha256,
                attribution.surface_ids,
            )
            if semantic_key in attribution_semantics:
                raise ValueError("learning attribution events must be semantically unique")
            attribution_semantics.add(semantic_key)
            actor_identity = (
                attribution.actor_kind,
                attribution.model_id,
                attribution.audit_role,
                attribution.specialist_role,
            )
            prior_identity = actor_identities.setdefault(attribution.actor_id, actor_identity)
            if prior_identity != actor_identity:
                raise ValueError("learning actor ID cannot alias multiple reviewer identities")
            expected_sha256 = target_indexes[attribution.target_kind].get(attribution.target_id)
            if expected_sha256 is None or attribution.target_sha256 != expected_sha256:
                raise ValueError("learning attribution target is absent or hash-mismatched")

        surface_index = {surface.surface_id: surface for surface in self.reviewed_surfaces}
        external_surface_coverage: dict[str, set[str]] = {
            miss.external_miss_id: set() for miss in self.external_misses
        }
        external_actor_surface_coverage: dict[str, set[tuple[str, str]]] = {
            miss.external_miss_id: set() for miss in self.external_misses
        }
        for attribution in self.reviewer_attributions:
            if attribution.outcome is not LearningAttributionOutcome.MISSED:
                continue
            for surface_id in attribution.surface_ids:
                surface = surface_index.get(surface_id)
                if surface is None:
                    raise ValueError("missed attribution references an absent reviewed surface")
                if attribution.actor_id not in surface.credited_reviewer_actor_ids:
                    raise ValueError("missed attribution actor lacks credited surface review")
            if attribution.target_kind is LearningAttributionTargetKind.EXTERNAL_MISS:
                external_surface_coverage[attribution.target_id].update(attribution.surface_ids)
                external_actor_surface_coverage[attribution.target_id].update(
                    (surface_id, attribution.actor_id) for surface_id in attribution.surface_ids
                )

        for surface in self.reviewed_surfaces:
            if not set(surface.confirmed_finding_ids) <= set(confirmed):
                raise ValueError("reviewed surface references an absent confirmed finding")
            if not set(surface.rejected_candidate_ids) <= set(rejected):
                raise ValueError("reviewed surface references an absent rejected candidate")

        for miss in self.external_misses:
            if miss.established_at <= self.completed_at:
                raise ValueError("external miss must be established after audit completion")
            if miss.established_at > self.captured_at:
                raise ValueError("external miss cannot be established after record capture")
            absent_surface_ids = set(miss.expected_surface_ids) - set(surface_index)
            if absent_surface_ids:
                raise ValueError("external miss references an absent reviewed surface")
            attributable_surface_ids = {
                surface_id
                for surface_id in miss.expected_surface_ids
                if surface_index[surface_id].credited_reviewer_actor_ids
            }
            if attributable_surface_ids != external_surface_coverage[miss.external_miss_id]:
                raise ValueError("external miss lacks exact missed-attribution surface coverage")
            expected_actor_surface_coverage = {
                (surface_id, actor_id)
                for surface_id in miss.expected_surface_ids
                for actor_id in surface_index[surface_id].credited_reviewer_actor_ids
            }
            if (
                expected_actor_surface_coverage
                != external_actor_surface_coverage[miss.external_miss_id]
            ):
                raise ValueError("external miss lacks every credited surface reviewer")

        serialized = _canonical_json_bytes(self.model_dump(mode="json"))
        if len(serialized) > MAX_LEARNING_RECORD_JSON_BYTES:
            raise ValueError("terminal learning record exceeds its JSON byte limit")
        expected_hash = learning_canonical_sha256(
            self.model_dump(mode="json", exclude={"record_sha256"})
        )
        if self.record_sha256 != expected_hash:
            raise ValueError("terminal learning record self-hash is inconsistent")
        return self


def build_terminal_audit_learning_record(
    *,
    tenant_id: str,
    audit_id: str,
    terminal_report_authority_sha256: str,
    report_payload_sha256: str,
    completed_at: datetime,
    captured_at: datetime,
    confirmed_findings: Iterable[TerminalConfirmedFinding],
    rejected_candidates: Iterable[TerminalRejectedCandidate],
    reviewer_attributions: Iterable[TerminalReviewerAttribution],
    reviewed_surfaces: Iterable[TerminalReviewedSurface],
    role_usage: Iterable[TerminalRoleResourceUsage],
    parent_record_sha256: str | None = None,
    external_misses: Iterable[ExternallyEstablishedMiss] = (),
) -> TerminalAuditLearningRecord:
    """Build one canonical, explicit, self-hashed terminal learning record."""

    confirmed = _bounded_exact_models(
        confirmed_findings,
        expected=TerminalConfirmedFinding,
        limit=MAX_LEARNING_CONFIRMED_FINDINGS,
        label="confirmed findings",
    )
    rejected = _bounded_exact_models(
        rejected_candidates,
        expected=TerminalRejectedCandidate,
        limit=MAX_LEARNING_REJECTED_CANDIDATES,
        label="rejected candidates",
    )
    attributions = _bounded_exact_models(
        reviewer_attributions,
        expected=TerminalReviewerAttribution,
        limit=MAX_LEARNING_ATTRIBUTIONS,
        label="reviewer attributions",
    )
    surfaces = _bounded_exact_models(
        reviewed_surfaces,
        expected=TerminalReviewedSurface,
        limit=MAX_LEARNING_REVIEWED_SURFACES,
        label="reviewed surfaces",
    )
    usage = _bounded_exact_models(
        role_usage,
        expected=TerminalRoleResourceUsage,
        limit=MAX_LEARNING_ROLE_USAGE_RECORDS,
        label="role usage",
    )
    misses = _bounded_exact_models(
        external_misses,
        expected=ExternallyEstablishedMiss,
        limit=MAX_LEARNING_EXTERNAL_MISSES,
        label="external misses",
    )

    payload: dict[str, Any] = {
        "schema_version": TERMINAL_AUDIT_LEARNING_SCHEMA_VERSION,
        "record_kind": "TERMINAL_AUDIT_LEARNING_RECORD",
        "tenant_id": tenant_id,
        "audit_id": audit_id,
        "terminal_report_authority_sha256": terminal_report_authority_sha256,
        "report_payload_sha256": report_payload_sha256,
        "parent_record_sha256": parent_record_sha256,
        "source_kind": LearningSourceKind.TERMINAL_PRODUCTION_AUDIT,
        "terminal_state": "COMPLETED",
        "completed_at": completed_at,
        "captured_at": captured_at,
        "confirmed_findings": tuple(sorted(confirmed, key=lambda item: item.finding_id)),
        "rejected_candidates": tuple(sorted(rejected, key=lambda item: item.candidate_id)),
        "reviewer_attributions": tuple(sorted(attributions, key=lambda item: item.attribution_id)),
        "reviewed_surfaces": tuple(sorted(surfaces, key=lambda item: item.surface_id)),
        "role_usage": tuple(sorted(usage, key=lambda item: item.role_id)),
        "external_misses": tuple(sorted(misses, key=lambda item: item.external_miss_id)),
        "permitted_use": "LEAD_ONLY_NON_PRIMING",
        "authority": "NONAUTHORIZING",
        "evidence_credit_authorized": False,
        "confidence_credit_authorized": False,
        "coverage_credit_authorized": False,
        "consensus_credit_authorized": False,
        "prompt_priming_authorized": False,
        "cross_tenant_aggregation_authorized": False,
        "provider_dispatch_authorized": False,
        "qualification_authorized": False,
        "release_authorized": False,
    }
    payload["record_sha256"] = learning_canonical_sha256(payload)
    return TerminalAuditLearningRecord.model_validate(payload, strict=True)


def append_externally_established_miss(
    *,
    record: TerminalAuditLearningRecord,
    miss: ExternallyEstablishedMiss,
    missed_attributions: Iterable[TerminalReviewerAttribution],
    captured_at: datetime,
) -> TerminalAuditLearningRecord:
    """Append one later-established miss without changing terminal audit facts.

    The returned record is a fresh immutable snapshot.  Every pre-existing fact and
    both terminal-report custody hashes are passed through byte-for-byte at the
    model level; only capture time, external misses, missed attributions, and the
    resulting record self-hash can change.
    """

    if type(record) is not TerminalAuditLearningRecord:
        raise ValueError("external miss append requires an exact terminal learning record")
    canonical_record = TerminalAuditLearningRecord.model_validate_json(
        record.model_dump_json(), strict=True
    )
    if type(miss) is not ExternallyEstablishedMiss:
        raise ValueError("external miss append requires an exact external miss record")
    canonical_miss = ExternallyEstablishedMiss.model_validate_json(
        miss.model_dump_json(), strict=True
    )
    appended_attributions = _bounded_exact_models(
        missed_attributions,
        expected=TerminalReviewerAttribution,
        limit=MAX_LEARNING_ATTRIBUTIONS,
        label="appended missed attributions",
    )
    captured = _require_whole_second_utc(captured_at, label="external miss capture")
    if canonical_miss.tenant_id != canonical_record.tenant_id or any(
        item.tenant_id != canonical_record.tenant_id for item in appended_attributions
    ):
        raise ValueError("external miss append cannot cross tenant IDs")
    if canonical_miss.established_at <= canonical_record.completed_at:
        raise ValueError("external miss append must be established after audit completion")
    if captured < canonical_miss.established_at:
        raise ValueError("external miss append cannot precede establishment")
    if captured < canonical_record.captured_at:
        raise ValueError("external miss append cannot move capture time backwards")
    if canonical_miss.external_miss_id in {
        item.external_miss_id for item in canonical_record.external_misses
    }:
        raise ValueError("external miss append cannot duplicate an existing miss ID")

    existing_attribution_ids = {
        item.attribution_id for item in canonical_record.reviewer_attributions
    }
    for attribution in appended_attributions:
        if attribution.attribution_id in existing_attribution_ids:
            raise ValueError("external miss append cannot duplicate an attribution ID")
        if (
            attribution.source_kind is not LearningSourceKind.LATER_EXTERNAL_ESTABLISHMENT
            or attribution.outcome is not LearningAttributionOutcome.MISSED
            or attribution.target_kind is not LearningAttributionTargetKind.EXTERNAL_MISS
            or attribution.target_id != canonical_miss.external_miss_id
            or attribution.target_sha256 != canonical_miss.finding_sha256
        ):
            raise ValueError("external miss append requires exact missed-attribution joins")

    return build_terminal_audit_learning_record(
        tenant_id=canonical_record.tenant_id,
        audit_id=canonical_record.audit_id,
        terminal_report_authority_sha256=canonical_record.terminal_report_authority_sha256,
        report_payload_sha256=canonical_record.report_payload_sha256,
        parent_record_sha256=canonical_record.record_sha256,
        completed_at=canonical_record.completed_at,
        captured_at=captured,
        confirmed_findings=canonical_record.confirmed_findings,
        rejected_candidates=canonical_record.rejected_candidates,
        reviewer_attributions=(*canonical_record.reviewer_attributions, *appended_attributions),
        reviewed_surfaces=canonical_record.reviewed_surfaces,
        role_usage=canonical_record.role_usage,
        external_misses=(*canonical_record.external_misses, canonical_miss),
    )


def learning_canonical_sha256(value: object) -> str:
    """Return the canonical SHA-256 used by terminal learning artifacts."""

    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def learning_actor_id(*, audit_role: str, model_id: str) -> str:
    """Derive the only admissible actor identity from exact role and model."""

    return f"actor:{learning_canonical_sha256({'role': audit_role, 'model_id': model_id})}"


def learning_specialist_role(audit_role: str) -> str | None:
    """Return the canonical specialist responsibility for an exact audit role."""

    parts = audit_role.split(":")
    if parts[0] == "specialist" and len(parts) >= 2 and parts[1] in ALL_SPECIALIST_ROLES:
        return parts[1]
    if audit_role in ALL_SPECIALIST_ROLES:
        return audit_role
    if parts[0] in {"candidate_falsifier", "falsifier"}:
        return "falsifier"
    return None


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"unsupported terminal learning hash value: {type(value).__qualname__}")


def _require_whole_second_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
        raise ValueError(f"{label} timestamp must be whole-second UTC")
    return value


def _require_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} timestamp must be UTC")
    return value


def _require_exact_strings(value: object, *, label: str) -> None:
    if isinstance(value, StrEnum):
        return
    if isinstance(value, str):
        if (
            value != value.strip()
            or unicodedata.normalize("NFC", value) != value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError(f"learning {label} must be exact NFC text without controls")
        return
    if isinstance(value, tuple):
        for item in value:
            if isinstance(item, str):
                _require_exact_strings(item, label=label)


def _require_sorted_unique_strings(values: tuple[str, ...], *, label: str) -> None:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"learning {label} must be sorted and unique")


def _require_canonical_models[ItemT: BaseModel](
    values: tuple[ItemT, ...],
    *,
    key: Any,
    label: str,
) -> None:
    keys = tuple(key(item) for item in values)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        raise ValueError(f"learning {label} must be sorted and unique")


def _bounded_exact_models[ItemT: BaseModel](
    values: Iterable[ItemT],
    *,
    expected: type[ItemT],
    limit: int,
    label: str,
) -> tuple[ItemT, ...]:
    try:
        items = tuple(islice(iter(values), limit + 1))
    except TypeError as exc:
        raise ValueError(f"learning {label} is not iterable") from exc
    if len(items) > limit:
        raise ValueError(f"learning {label} exceeds its item limit")
    if any(type(item) is not expected for item in items):
        raise ValueError(f"learning {label} requires exact typed records")
    return items
