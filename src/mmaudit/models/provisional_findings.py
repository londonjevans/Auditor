"""Bounded comparison data for findings retained from truncated model output."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES
from mmaudit.models.schemas import CandidateFinding, StrictModel
from mmaudit.models.truncation import (
    MAX_CANDIDATE_REVIEW_FINDINGS,
    CandidateReviewAcceptedFrame,
    CandidateReviewChannelState,
    CandidateReviewFramePhase,
    _canonical_sha256,
    candidate_review_typed_payload_projection,
)

PROVISIONAL_FINDINGS_METADATA_KEY = "provisional_truncated_findings"
MAX_PROVISIONAL_FINDINGS = 100_000
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ProvisionalFindingRecord(StrictModel):
    """One complete proposed finding and its original accepted frame coordinate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate: CandidateFinding
    retained_frame: CandidateReviewAcceptedFrame


class ProvisionalFindingSource(StrictModel):
    """A request-scoped inventory, not an accepted candidate batch or review."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_kind: Literal["scheduler_parent", "recovery_child"]
    source_entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    task_id: str = Field(pattern=r"^scheduler-(?:recovery-)?task-[0-9a-f]{64}$")
    request_id: str = Field(pattern=r"^scheduler-(?:recovery-)?request-[0-9a-f]{64}$")
    request_role: str = Field(min_length=1, max_length=500)
    usage_record_sha256: str = Field(pattern=_SHA256_PATTERN)
    original_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    truncation_projection_sha256: str = Field(pattern=_SHA256_PATTERN)
    algorithm_version: Literal["mmaudit.seven-pass-scheduler.v1", "mmaudit.seven-pass-scheduler.v2"]
    findings_state: CandidateReviewChannelState
    surface_reviews_state: CandidateReviewChannelState
    summary_state: CandidateReviewChannelState
    declared_finding_count: int = Field(ge=1, le=MAX_CANDIDATE_REVIEW_FINDINGS, strict=True)
    records: tuple[ProvisionalFindingRecord, ...] = Field(
        min_length=1, max_length=MAX_CANDIDATE_REVIEW_FINDINGS
    )

    @model_validator(mode="after")
    def records_match_original_finding_frames(self) -> Self:
        recovery = self.source_kind == "recovery_child"
        if (
            recovery != self.task_id.startswith("scheduler-recovery-task-")
            or recovery != self.request_id.startswith("scheduler-recovery-request-")
            or self.findings_state is CandidateReviewChannelState.NOT_STARTED
            or len(self.records) > self.declared_finding_count
            or (
                self.findings_state is CandidateReviewChannelState.COMPLETE
                and len(self.records) != self.declared_finding_count
            )
        ):
            raise ValueError("provisional findings have inconsistent source or channel state")
        identities = tuple(record.candidate.candidate_id for record in self.records)
        sequences = tuple(record.retained_frame.sequence for record in self.records)
        if len(identities) != len(set(identities)) or sequences != tuple(sorted(set(sequences))):
            raise ValueError("provisional finding records are duplicate or out of frame order")
        for record in self.records:
            frame = record.retained_frame
            candidate = CandidateFinding.model_validate_json(
                record.candidate.model_dump_json(), strict=True
            )
            if (
                frame.phase is not CandidateReviewFramePhase.FINDING
                or not 1 <= frame.sequence <= self.declared_finding_count
                or frame.record_id != candidate.candidate_id
                or frame.normalized_value_sha256
                != _canonical_sha256(
                    candidate_review_typed_payload_projection(
                        candidate, algorithm_version=self.algorithm_version
                    )
                )
            ):
                raise ValueError("provisional finding differs from its retained frame")
        return self


class ProvisionalFindingInventory(StrictModel):
    """Lossless report inventory; serialized data never authorizes finding or audit credit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    evidence_authority: Literal["comparison_required"] = "comparison_required"
    campaign_id: str = Field(pattern=r"^scheduler-campaign-[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    journal_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    scheduler_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    sources: tuple[ProvisionalFindingSource, ...] = Field(
        min_length=1, max_length=MAX_PROVISIONAL_FINDINGS
    )
    retained_finding_count: int = Field(ge=1, le=MAX_PROVISIONAL_FINDINGS, strict=True)
    review_credit_authorized: Literal[False]
    coverage_credit_authorized: Literal[False]
    validated_finding_authorized: Literal[False]
    completion_authorized: Literal[False]
    inventory_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "review_credit_authorized",
        "coverage_credit_authorized",
        "validated_finding_authorized",
        "completion_authorized",
        mode="before",
    )
    @classmethod
    def credit_is_literal_false(cls, value: object) -> Literal[False]:
        if value is not False:
            raise ValueError("provisional findings cannot authorize credit")
        return False

    @model_validator(mode="after")
    def inventory_is_exact_and_noncrediting(self) -> Self:
        request_ids = tuple(source.request_id for source in self.sources)
        entry_ids = tuple(source.source_entry_sha256 for source in self.sources)
        if (
            request_ids != tuple(sorted(set(request_ids)))
            or len(entry_ids) != len(set(entry_ids))
            or self.retained_finding_count != sum(len(source.records) for source in self.sources)
        ):
            raise ValueError("provisional finding inventory count or source identity differs")
        if self.inventory_sha256 != _canonical_sha256(
            self.model_dump(mode="json", exclude={"inventory_sha256"})
        ):
            raise ValueError("provisional finding inventory hash differs")
        return self


def provisional_findings_from_metadata(
    metadata: Mapping[str, Any],
) -> ProvisionalFindingInventory | None:
    """Read a bounded, typed report projection without granting original-journal authority."""

    if PROVISIONAL_FINDINGS_METADATA_KEY not in metadata:
        return None
    value = metadata[PROVISIONAL_FINDINGS_METADATA_KEY]
    if type(value) is not dict:
        raise ValueError("provisional finding metadata must be an explicit object")
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(serialized.encode("utf-8")) > MAX_JSON_ARTIFACT_BYTES:
        raise ValueError("provisional finding metadata exceeds its byte bound")
    inventory = ProvisionalFindingInventory.model_validate_json(serialized, strict=True)
    scheduler = metadata.get("scheduler")
    if type(scheduler) is not dict or any(
        scheduler.get(name) != getattr(inventory, name)
        for name in (
            "campaign_id",
            "manifest_sha256",
            "journal_evidence_sha256",
            "scheduler_artifact_sha256",
        )
    ):
        raise ValueError("provisional findings differ from the report scheduler binding")
    return inventory
