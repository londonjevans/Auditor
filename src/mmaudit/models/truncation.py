"""Strict, non-crediting recovery for length-truncated candidate-review output.

The wire format remains one JSON document for native structured-output transports.  A complete
document has the shape ``{"frames":[...]}``.  The recovery path accepts the exact ASCII envelope
prefix and retains only individually bounded, strictly validated frame objects.  It never stores
the discarded suffix or grants review, coverage, summary, or authority credit.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from itertools import pairwise
from typing import Annotated, Any, Literal, Never

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReviewBatch,
    ModelSurfaceReviewRecord,
)
from mmaudit.models.structured_output import (
    StructuredOutputDecodeError,
    StructuredOutputFailureCode,
    decode_structured_output,
)

_COPY_DEEPCOPY = copy.deepcopy
_HASHLIB_SHA256 = hashlib.sha256
_JSON_DECODE_ERROR = json.JSONDecodeError
_JSON_DUMPS = json.dumps
_JSON_LOADS = json.loads
_JSON_DECODER = json.JSONDecoder
_JSON_DECODER_DECODE = json.JSONDecoder.decode
_JSON_DECODER_RAW_DECODE = json.JSONDecoder.raw_decode
_JSON_ENCODER = json.JSONEncoder
_JSON_ENCODER_ENCODE = json.JSONEncoder.encode
_JSON_ENCODER_ITERENCODE = json.JSONEncoder.iterencode
_JSON_DECODER_MODULE: Any = json.decoder
_JSON_ENCODER_MODULE: Any = json.encoder
_JSON_SCANNER_MODULE: Any = json.scanner  # type: ignore[attr-defined]
_JSON_ENCODE_BASESTRING_ASCII = _JSON_ENCODER_MODULE.encode_basestring_ascii
_JSON_MAKE_ENCODER: Any = _JSON_ENCODER_MODULE.c_make_encoder
_JSON_MAKE_SCANNER = _JSON_SCANNER_MODULE.make_scanner
_JSON_PARSE_ARRAY = _JSON_DECODER_MODULE.JSONArray
_JSON_PARSE_OBJECT = _JSON_DECODER_MODULE.JSONObject
_JSON_SCANSTRING = _JSON_DECODER_MODULE.scanstring
_MATH_ISFINITE = math.isfinite

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_WIRE_PREFIX = '{"frames":['
_WIRE_SUFFIX = "]}"
_PROTOCOL = "CANDIDATE_REVIEW_FRAMES_V1"
_SCHEDULER_V1 = "mmaudit.seven-pass-scheduler.v1"
_SCHEDULER_V2 = "mmaudit.seven-pass-scheduler.v2"
_V1_CANDIDATE_REVIEW_BATCH_SCHEMA_SHA256 = (
    "29158e2c31350751f683bfa2910db39d2883d3258ef7fc41a1479d4f3133c186"
)
_V1_CANDIDATE_REVIEW_FRAME_WIRE_SCHEMA_SHA256 = (
    "478bc1d7e11e4ae1635c371ef1965025f012b5c9056af08d7a4c729425cb46a1"
)

# These are compiled protocol limits, not caller-controlled recovery knobs.
MAX_CANDIDATE_REVIEW_RESPONSE_BYTES = 4_000_000
MAX_CANDIDATE_REVIEW_FRAME_BYTES = 512_000
MAX_CANDIDATE_REVIEW_JSON_DEPTH = 128
MAX_CANDIDATE_REVIEW_FINDINGS = 1_000
MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS = 10_000
MAX_CANDIDATE_REVIEW_FRAMES = (
    MAX_CANDIDATE_REVIEW_FINDINGS + MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS + 5
)

_LENGTH_TRUNCATION_REASONS = frozenset(
    {
        "length",
        "max_tokens",
        "max_tokens_exceeded",
        "token_limit_exceeded",
    }
)
_PROVIDER_TRUNCATION_REASONS = _LENGTH_TRUNCATION_REASONS | {"content_filter", "error"}


class CandidateReviewFramePhase(StrEnum):
    """Ordered phase names in the candidate-review framed wire document."""

    BEGIN = "BEGIN"
    FINDING = "FINDING"
    FINDINGS_END = "FINDINGS_END"
    SURFACE_REVIEW = "SURFACE_REVIEW"
    SURFACE_REVIEWS_END = "SURFACE_REVIEWS_END"
    SUMMARY = "SUMMARY"
    END = "END"


class CandidateReviewChannelState(StrEnum):
    """Independent validation state for one recovery channel."""

    NOT_STARTED = "NOT_STARTED"
    OPEN = "OPEN"
    COMPLETE = "COMPLETE"
    INVALID = "INVALID"


class CandidateReviewTruncationTermination(StrEnum):
    """Raw-free reason why prefix recovery stopped."""

    COMPLETE_DOCUMENT = "COMPLETE_DOCUMENT"
    INCOMPLETE_TAIL = "INCOMPLETE_TAIL"
    END_OF_INPUT_AFTER_FRAME = "END_OF_INPUT_AFTER_FRAME"
    INVALID_FRAME = "INVALID_FRAME"
    INVALID_SEQUENCE = "INVALID_SEQUENCE"
    INVALID_PHASE_ORDER = "INVALID_PHASE_ORDER"
    INVALID_SEPARATOR = "INVALID_SEPARATOR"
    FRAME_LIMIT_REACHED = "FRAME_LIMIT_REACHED"


class CandidateReviewTruncationFailureCode(StrEnum):
    """Bounded failure classifications that never include provider text."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    TRUNCATION_NOT_CONFIRMED = "TRUNCATION_NOT_CONFIRMED"
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    INVALID_COMPLETE_DOCUMENT = "INVALID_COMPLETE_DOCUMENT"


class CandidateReviewTruncationError(ValueError):
    """Typed, raw-output-free framed recovery rejection."""

    def __init__(
        self,
        code: CandidateReviewTruncationFailureCode,
        *,
        structured_output_failure_code: StructuredOutputFailureCode | None = None,
    ) -> None:
        self.code = code
        self.structured_output_failure_code = structured_output_failure_code
        super().__init__(f"candidate review truncation rejected: {code.value}")


def _strip_v1_candidate_actor_defaults(value: object, projection: object) -> None:
    """Remove only exact neutral actor defaults absent from the v1 wire models."""

    if isinstance(value, CandidateFinding):
        if value.actor_model_applicability.value != "unstated" or value.actor_context is not None:
            raise ValueError("scheduler v1 candidate review cannot carry actor annotations")
        if not isinstance(projection, dict):
            raise TypeError("candidate-review v1 projection has an invalid finding shape")
        projection.pop("actor_model_applicability", None)
        projection.pop("actor_context", None)
    if isinstance(value, BaseModel):
        if not isinstance(projection, dict):
            raise TypeError("candidate-review v1 projection has an invalid model shape")
        for field_name in type(value).model_fields:
            if field_name in projection:
                _strip_v1_candidate_actor_defaults(
                    getattr(value, field_name), projection[field_name]
                )
        return
    if isinstance(value, Mapping):
        if not isinstance(projection, dict):
            raise TypeError("candidate-review v1 projection has an invalid mapping shape")
        for key, item in value.items():
            if key in projection:
                _strip_v1_candidate_actor_defaults(item, projection[key])
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        if not isinstance(projection, list) or len(value) != len(projection):
            raise TypeError("candidate-review v1 projection has an invalid sequence shape")
        for item, projected_item in zip(value, projection, strict=True):
            _strip_v1_candidate_actor_defaults(item, projected_item)


def candidate_review_typed_payload_projection(
    value: BaseModel,
    *,
    algorithm_version: str,
) -> Any:
    """Return the exact candidate-review JSON projection for a scheduler version."""

    if algorithm_version not in {_SCHEDULER_V1, _SCHEDULER_V2}:
        raise ValueError("candidate-review projection uses an unknown scheduler algorithm")
    projection = value.model_dump(mode="json")
    if algorithm_version == _SCHEDULER_V1:
        _strip_v1_candidate_actor_defaults(value, projection)
    return projection


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CandidateReviewBeginFrame(_FrozenStrictModel):
    schema_version: Literal["1.0"]
    sequence: Literal[0]
    phase: Literal[CandidateReviewFramePhase.BEGIN]
    finding_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FINDINGS)
    surface_review_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS)
    summary_count: Literal[1]


class CandidateReviewFindingFrame(_FrozenStrictModel):
    schema_version: Literal["1.0"]
    sequence: int = Field(ge=1, le=MAX_CANDIDATE_REVIEW_FRAMES - 1)
    phase: Literal[CandidateReviewFramePhase.FINDING]
    record: CandidateFinding

    @model_validator(mode="after")
    def projected_identity_is_bounded(self) -> CandidateReviewFindingFrame:
        if not _is_bounded_record_identity(self.record.candidate_id):
            raise ValueError("candidate review finding identity is not safely bounded")
        return self


class CandidateReviewFindingsEndFrame(_FrozenStrictModel):
    schema_version: Literal["1.0"]
    sequence: int = Field(ge=1, le=MAX_CANDIDATE_REVIEW_FRAMES - 1)
    phase: Literal[CandidateReviewFramePhase.FINDINGS_END]
    record_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FINDINGS)


class CandidateReviewSurfaceReviewFrame(_FrozenStrictModel):
    schema_version: Literal["1.0"]
    sequence: int = Field(ge=1, le=MAX_CANDIDATE_REVIEW_FRAMES - 1)
    phase: Literal[CandidateReviewFramePhase.SURFACE_REVIEW]
    record: ModelSurfaceReviewRecord


class CandidateReviewSurfaceReviewsEndFrame(_FrozenStrictModel):
    schema_version: Literal["1.0"]
    sequence: int = Field(ge=1, le=MAX_CANDIDATE_REVIEW_FRAMES - 1)
    phase: Literal[CandidateReviewFramePhase.SURFACE_REVIEWS_END]
    record_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS)


class CandidateReviewSummaryFrame(_FrozenStrictModel):
    schema_version: Literal["1.0"]
    sequence: int = Field(ge=1, le=MAX_CANDIDATE_REVIEW_FRAMES - 1)
    phase: Literal[CandidateReviewFramePhase.SUMMARY]
    finding_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FINDINGS)
    surface_review_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS)


class CandidateReviewEndFrame(_FrozenStrictModel):
    schema_version: Literal["1.0"]
    sequence: int = Field(ge=1, le=MAX_CANDIDATE_REVIEW_FRAMES - 1)
    phase: Literal[CandidateReviewFramePhase.END]
    frame_count: int = Field(ge=5, le=MAX_CANDIDATE_REVIEW_FRAMES)
    finding_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FINDINGS)
    surface_review_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS)
    summary_count: Literal[1]


CandidateReviewFrame = Annotated[
    CandidateReviewBeginFrame
    | CandidateReviewFindingFrame
    | CandidateReviewFindingsEndFrame
    | CandidateReviewSurfaceReviewFrame
    | CandidateReviewSurfaceReviewsEndFrame
    | CandidateReviewSummaryFrame
    | CandidateReviewEndFrame,
    Field(discriminator="phase"),
]


class CandidateReviewFramedDocument(_FrozenStrictModel):
    """The exact provider wire schema; it is deliberately not CandidateReviewBatch."""

    frames: tuple[CandidateReviewFrame, ...] = Field(
        min_length=5,
        max_length=MAX_CANDIDATE_REVIEW_FRAMES,
    )

    @model_validator(mode="after")
    def frame_sequence_is_semantically_complete(self) -> CandidateReviewFramedDocument:
        # Keep semantic ordering/count checks inside the wire type as well as the raw-byte
        # decoder.  A provider-valid JSON schema document is not a successful review until its
        # control frames prove one exact CandidateReviewBatch projection.
        _complete_batch_from_frames(self.frames)
        return self


class CandidateReviewAcceptedFrame(_FrozenStrictModel):
    """Hash-only custody for one exact retained frame byte range."""

    sequence: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FRAMES - 1)
    phase: CandidateReviewFramePhase
    byte_start: int = Field(ge=len(_WIRE_PREFIX.encode("ascii")))
    byte_end: int = Field(gt=0, le=MAX_CANDIDATE_REVIEW_RESPONSE_BYTES)
    frame_bytes: int = Field(ge=2, le=MAX_CANDIDATE_REVIEW_FRAME_BYTES)
    frame_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalized_value_sha256: str = Field(pattern=_SHA256_PATTERN)
    record_id: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def range_is_exact(self) -> CandidateReviewAcceptedFrame:
        if self.byte_end <= self.byte_start or self.byte_end - self.byte_start != self.frame_bytes:
            raise ValueError("accepted frame byte range is inconsistent")
        if self.phase is CandidateReviewFramePhase.FINDING and (
            self.record_id is None or not _is_bounded_record_identity(self.record_id)
        ):
            raise ValueError("finding frame requires its bounded candidate identity")
        if self.phase is CandidateReviewFramePhase.SURFACE_REVIEW and (
            self.record_id is None or not self.record_id.startswith("model-surface:")
        ):
            raise ValueError("surface-review frame requires its stable surface identity")
        if (
            self.phase
            not in {
                CandidateReviewFramePhase.FINDING,
                CandidateReviewFramePhase.SURFACE_REVIEW,
            }
            and self.record_id is not None
        ):
            raise ValueError("control frame cannot carry a record identity")
        return self


class CandidateReviewTruncationProjection(_FrozenStrictModel):
    """Nonauthorizing recovery evidence with no retained incomplete provider suffix."""

    schema_version: Literal["1.0"]
    protocol: Literal["CANDIDATE_REVIEW_FRAMES_V1"]
    wire_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalized_batch_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    finish_reason: str = Field(min_length=1, max_length=100)
    native_finish_reason: str | None = Field(default=None, min_length=1, max_length=100)
    truncation_confirmed: Literal[True]
    original_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    original_response_bytes: int = Field(
        ge=len(_WIRE_PREFIX), le=MAX_CANDIDATE_REVIEW_RESPONSE_BYTES
    )
    accepted_prefix_sha256: str = Field(pattern=_SHA256_PATTERN)
    accepted_prefix_bytes: int = Field(ge=len(_WIRE_PREFIX), le=MAX_CANDIDATE_REVIEW_RESPONSE_BYTES)
    discarded_suffix_sha256: str = Field(pattern=_SHA256_PATTERN)
    discarded_suffix_bytes: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_RESPONSE_BYTES)
    discarded_suffix_retained: Literal[False]
    accepted_frames: tuple[CandidateReviewAcceptedFrame, ...] = Field(
        max_length=MAX_CANDIDATE_REVIEW_FRAMES
    )
    observed_frame_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FRAMES)
    invalid_frame_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FRAMES)
    last_observed_sequence: int | None = Field(
        default=None,
        ge=0,
        le=MAX_CANDIDATE_REVIEW_FRAMES - 1,
    )
    declared_finding_count: int | None = Field(
        default=None,
        ge=0,
        le=MAX_CANDIDATE_REVIEW_FINDINGS,
    )
    observed_finding_frame_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FINDINGS)
    accepted_finding_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FINDINGS)
    declared_surface_review_count: int | None = Field(
        default=None,
        ge=0,
        le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS,
    )
    observed_surface_review_frame_count: int = Field(
        ge=0,
        le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS,
    )
    accepted_surface_review_count: int = Field(
        ge=0,
        le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS,
    )
    summary_declared_finding_count: int | None = Field(
        default=None,
        ge=0,
        le=MAX_CANDIDATE_REVIEW_FINDINGS,
    )
    summary_declared_surface_review_count: int | None = Field(
        default=None,
        ge=0,
        le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS,
    )
    end_declared_frame_count: int | None = Field(
        default=None,
        ge=5,
        le=MAX_CANDIDATE_REVIEW_FRAMES,
    )
    end_declared_finding_count: int | None = Field(
        default=None,
        ge=0,
        le=MAX_CANDIDATE_REVIEW_FINDINGS,
    )
    end_declared_surface_review_count: int | None = Field(
        default=None,
        ge=0,
        le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS,
    )
    end_declared_summary_count: int | None = Field(default=None, ge=0, le=1)
    findings_state: CandidateReviewChannelState
    surface_reviews_state: CandidateReviewChannelState
    summary_state: CandidateReviewChannelState
    stream_integrity_valid: bool
    document_complete: bool
    termination: CandidateReviewTruncationTermination
    findings: tuple[CandidateFinding, ...] = Field(max_length=MAX_CANDIDATE_REVIEW_FINDINGS)
    surface_reviews: tuple[ModelSurfaceReviewRecord, ...] = Field(
        max_length=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS
    )
    review_credit_eligible: Literal[False]
    coverage_credit_eligible: Literal[False]
    summary_credit_eligible: Literal[False]
    authority_eligible: Literal[False]
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_is_coherent_and_self_hashed(self) -> CandidateReviewTruncationProjection:
        guard = globals().get("candidate_review_protocol_implementation_is_pristine")
        if guard is not None and (not callable(guard) or not guard()):
            raise ValueError("candidate-review protocol implementation changed")
        algorithm_version = candidate_review_schema_algorithm_version(
            wire_schema_sha256=self.wire_schema_sha256,
            normalized_batch_schema_sha256=self.normalized_batch_schema_sha256,
        )
        _require_every_model_field_supplied(self, algorithm_version=algorithm_version)
        if not {
            self.finish_reason.casefold(),
            self.native_finish_reason.casefold() if self.native_finish_reason is not None else "",
        }.intersection(_LENGTH_TRUNCATION_REASONS):
            raise ValueError("truncation evidence lacks a confirmed length finish reason")
        if any(
            value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            for value in (self.finish_reason,)
            + ((self.native_finish_reason,) if self.native_finish_reason is not None else ())
        ):
            raise ValueError("truncation finish reason is not bounded plain text")
        if self.original_response_bytes != self.accepted_prefix_bytes + self.discarded_suffix_bytes:
            raise ValueError("truncation response byte partition is inconsistent")
        if self.discarded_suffix_bytes == 0 and self.discarded_suffix_sha256 != _bytes_sha256(b""):
            raise ValueError("empty truncation suffix hash is inconsistent")
        if self.accepted_finding_count != len(self.findings) or (
            self.accepted_surface_review_count != len(self.surface_reviews)
        ):
            raise ValueError("truncation accepted record counts are inconsistent")
        if (
            self.accepted_finding_count > self.observed_finding_frame_count
            or self.accepted_surface_review_count > self.observed_surface_review_frame_count
            or len(self.accepted_frames) > self.observed_frame_count
            or self.invalid_frame_count > self.observed_frame_count + 1
        ):
            raise ValueError("truncation accepted/observed counts are inconsistent")
        if self.last_observed_sequence != (
            self.observed_frame_count - 1 if self.observed_frame_count else None
        ):
            raise ValueError("truncation last observed sequence is inconsistent")
        frame_sequences = tuple(frame.sequence for frame in self.accepted_frames)
        frame_ranges = tuple((frame.byte_start, frame.byte_end) for frame in self.accepted_frames)
        if frame_sequences != tuple(sorted(set(frame_sequences))) or frame_ranges != tuple(
            sorted(set(frame_ranges))
        ):
            raise ValueError("truncation accepted frames must be unique and ordered")
        if any(frame.byte_end > self.accepted_prefix_bytes for frame in self.accepted_frames):
            raise ValueError("truncation accepted frame exceeds the bounded prefix")
        if any(frame.sequence >= self.observed_frame_count for frame in self.accepted_frames):
            raise ValueError("truncation accepted frame exceeds the observed sequence domain")
        if any(left.byte_end > right.byte_start for left, right in pairwise(self.accepted_frames)):
            raise ValueError("truncation accepted frame byte ranges overlap")
        finding_ids = tuple(item.candidate_id for item in self.findings)
        surface_ids = tuple(item.surface_id for item in self.surface_reviews)
        if len(finding_ids) != len(set(finding_ids)) or surface_ids != tuple(
            sorted(set(surface_ids))
        ):
            raise ValueError("truncation retained record identities are ambiguous")
        if any(not _is_bounded_record_identity(identifier) for identifier in finding_ids):
            raise ValueError("truncation retained finding identity is not bounded")
        finding_frames = tuple(
            frame
            for frame in self.accepted_frames
            if frame.phase is CandidateReviewFramePhase.FINDING
        )
        surface_frames = tuple(
            frame
            for frame in self.accepted_frames
            if frame.phase is CandidateReviewFramePhase.SURFACE_REVIEW
        )
        if len(finding_frames) != len(self.findings) or len(surface_frames) != len(
            self.surface_reviews
        ):
            raise ValueError("truncation retained records lack exact accepted frames")
        finding_frames_by_id = {frame.record_id: frame for frame in finding_frames}
        surface_frames_by_id = {frame.record_id: frame for frame in surface_frames}
        if set(finding_frames_by_id) != set(finding_ids) or set(surface_frames_by_id) != set(
            surface_ids
        ):
            raise ValueError("truncation retained record/frame identities differ")
        if any(
            finding_frames_by_id[finding.candidate_id].normalized_value_sha256
            != _canonical_sha256(
                candidate_review_typed_payload_projection(
                    finding,
                    algorithm_version=algorithm_version,
                )
            )
            for finding in self.findings
        ) or any(
            surface_frames_by_id[review.surface_id].normalized_value_sha256
            != _canonical_sha256(review.model_dump(mode="json"))
            for review in self.surface_reviews
        ):
            raise ValueError("truncation retained record/frame hashes differ")
        phases = tuple(frame.phase for frame in self.accepted_frames)
        control_phases = {
            CandidateReviewFramePhase.BEGIN,
            CandidateReviewFramePhase.FINDINGS_END,
            CandidateReviewFramePhase.SURFACE_REVIEWS_END,
            CandidateReviewFramePhase.SUMMARY,
            CandidateReviewFramePhase.END,
        }
        if any(phases.count(phase) > 1 for phase in control_phases):
            raise ValueError("truncation control frames must be unique")
        begin_present = phases.count(CandidateReviewFramePhase.BEGIN) == 1
        begin_counts_present = (
            self.declared_finding_count is not None
            and self.declared_surface_review_count is not None
        )
        if begin_present != begin_counts_present or (
            (self.declared_finding_count is None) != (self.declared_surface_review_count is None)
        ):
            raise ValueError("truncation BEGIN count presence is inconsistent")
        if begin_present and (
            not self.accepted_frames
            or self.accepted_frames[0].phase is not CandidateReviewFramePhase.BEGIN
            or self.accepted_frames[0].sequence != 0
            or self.accepted_frames[0].byte_start != len(_WIRE_PREFIX.encode("ascii"))
        ):
            raise ValueError("truncation declared counts lack the exact BEGIN frame")
        if not begin_present and self.accepted_frames:
            raise ValueError("truncation accepted records cannot precede BEGIN")

        if begin_counts_present:
            assert self.declared_finding_count is not None
            assert self.declared_surface_review_count is not None
            total_frame_count = self.declared_finding_count + self.declared_surface_review_count + 5
            if self.observed_frame_count > total_frame_count:
                raise ValueError("truncation observed frame count exceeds BEGIN")
            expected_observed_findings = min(
                self.declared_finding_count,
                max(0, self.observed_frame_count - 1),
            )
            surface_start_sequence = self.declared_finding_count + 2
            expected_observed_surface_reviews = min(
                self.declared_surface_review_count,
                max(0, self.observed_frame_count - surface_start_sequence),
            )
            if (
                self.observed_finding_frame_count != expected_observed_findings
                or self.observed_surface_review_frame_count != expected_observed_surface_reviews
            ):
                raise ValueError("truncation observed record counts differ from sequence")
            for frame in self.accepted_frames:
                if frame.phase is not _expected_phase_for_sequence(
                    finding_count=self.declared_finding_count,
                    surface_review_count=self.declared_surface_review_count,
                    sequence=frame.sequence,
                ):
                    raise ValueError("truncation accepted frame phase differs from sequence")
                expected_control_hash = _expected_control_frame_sha256(self, frame)
                if (
                    expected_control_hash is not None
                    and frame.normalized_value_sha256 != expected_control_hash
                ):
                    raise ValueError("truncation accepted control-frame hash is inconsistent")
        elif (
            self.observed_frame_count > 1
            or self.observed_finding_frame_count
            or self.observed_surface_review_frame_count
        ):
            raise ValueError("truncation observations without BEGIN are inconsistent")

        summary_fields_present = (
            self.summary_declared_finding_count is not None,
            self.summary_declared_surface_review_count is not None,
        )
        if len(set(summary_fields_present)) != 1 or summary_fields_present[0] != (
            CandidateReviewFramePhase.SUMMARY in phases
        ):
            raise ValueError("truncation SUMMARY count presence is inconsistent")
        end_fields_present = (
            self.end_declared_frame_count is not None,
            self.end_declared_finding_count is not None,
            self.end_declared_surface_review_count is not None,
            self.end_declared_summary_count is not None,
        )
        if len(set(end_fields_present)) != 1 or end_fields_present[0] != (
            CandidateReviewFramePhase.END in phases
        ):
            raise ValueError("truncation END count presence is inconsistent")
        if summary_fields_present[0] and (
            self.summary_declared_finding_count != self.declared_finding_count
            or self.summary_declared_surface_review_count != self.declared_surface_review_count
        ):
            raise ValueError("truncation SUMMARY counts differ from BEGIN")
        if end_fields_present[0] and (
            self.end_declared_frame_count != self.observed_frame_count
            or self.end_declared_frame_count
            != (self.declared_finding_count or 0) + (self.declared_surface_review_count or 0) + 5
            or self.end_declared_finding_count != self.declared_finding_count
            or self.end_declared_surface_review_count != self.declared_surface_review_count
            or self.end_declared_summary_count != 1
        ):
            raise ValueError("truncation END counts differ from the observed stream")

        invalid_unobserved_phase = (
            _expected_phase_for_sequence(
                finding_count=self.declared_finding_count,
                surface_review_count=self.declared_surface_review_count,
                sequence=self.observed_frame_count,
            )
            if begin_counts_present
            and self.termination
            in {
                CandidateReviewTruncationTermination.INVALID_FRAME,
                CandidateReviewTruncationTermination.INVALID_SEQUENCE,
                CandidateReviewTruncationTermination.INVALID_PHASE_ORDER,
                CandidateReviewTruncationTermination.FRAME_LIMIT_REACHED,
            }
            else None
        )
        findings_end_sequence = (self.declared_finding_count or 0) + 1
        findings_end_observed = begin_counts_present and (
            self.observed_frame_count > findings_end_sequence
        )
        findings_end_accepted = CandidateReviewFramePhase.FINDINGS_END in phases
        findings_invalid = bool(
            begin_counts_present
            and (
                self.accepted_finding_count != self.observed_finding_frame_count
                or (findings_end_observed and not findings_end_accepted)
                or invalid_unobserved_phase
                in {
                    CandidateReviewFramePhase.FINDING,
                    CandidateReviewFramePhase.FINDINGS_END,
                }
            )
        )
        expected_findings_state = (
            CandidateReviewChannelState.NOT_STARTED
            if not begin_counts_present
            else (
                CandidateReviewChannelState.INVALID
                if findings_invalid
                else (
                    CandidateReviewChannelState.COMPLETE
                    if findings_end_accepted
                    else CandidateReviewChannelState.OPEN
                )
            )
        )

        surface_end_sequence = (
            (self.declared_finding_count or 0) + (self.declared_surface_review_count or 0) + 2
        )
        surface_started = begin_counts_present and findings_end_observed
        surface_end_observed = begin_counts_present and (
            self.observed_frame_count > surface_end_sequence
        )
        surface_end_accepted = CandidateReviewFramePhase.SURFACE_REVIEWS_END in phases
        surface_invalid = bool(
            surface_started
            and (
                self.accepted_surface_review_count != self.observed_surface_review_frame_count
                or (surface_end_observed and not surface_end_accepted)
                or invalid_unobserved_phase
                in {
                    CandidateReviewFramePhase.SURFACE_REVIEW,
                    CandidateReviewFramePhase.SURFACE_REVIEWS_END,
                }
            )
        )
        expected_surface_state = (
            CandidateReviewChannelState.NOT_STARTED
            if not surface_started
            else (
                CandidateReviewChannelState.INVALID
                if surface_invalid
                else (
                    CandidateReviewChannelState.COMPLETE
                    if surface_end_accepted
                    else CandidateReviewChannelState.OPEN
                )
            )
        )
        summary_sequence = surface_end_sequence + 1
        summary_observed = begin_counts_present and self.observed_frame_count > summary_sequence
        summary_accepted = CandidateReviewFramePhase.SUMMARY in phases
        summary_invalid = bool(
            (summary_observed and not summary_accepted)
            or invalid_unobserved_phase is CandidateReviewFramePhase.SUMMARY
        )
        expected_summary_state = (
            CandidateReviewChannelState.INVALID
            if summary_invalid
            else (
                CandidateReviewChannelState.COMPLETE
                if summary_accepted
                else CandidateReviewChannelState.NOT_STARTED
            )
        )
        if (
            self.findings_state is not expected_findings_state
            or self.surface_reviews_state is not expected_surface_state
            or self.summary_state is not expected_summary_state
        ):
            raise ValueError("truncation channel state differs from accepted frame evidence")
        if (
            CandidateReviewChannelState.INVALID
            in {
                self.findings_state,
                self.surface_reviews_state,
                self.summary_state,
            }
            and not self.invalid_frame_count
        ):
            raise ValueError("invalid truncation channel lacks an invalid frame count")

        invalid_terminations = {
            CandidateReviewTruncationTermination.INVALID_FRAME,
            CandidateReviewTruncationTermination.INVALID_SEQUENCE,
            CandidateReviewTruncationTermination.INVALID_PHASE_ORDER,
            CandidateReviewTruncationTermination.INVALID_SEPARATOR,
            CandidateReviewTruncationTermination.FRAME_LIMIT_REACHED,
        }
        if self.termination in invalid_terminations and self.stream_integrity_valid:
            raise ValueError("invalid truncation termination cannot preserve stream integrity")
        if self.stream_integrity_valid and (
            self.invalid_frame_count
            or CandidateReviewChannelState.INVALID
            in {self.findings_state, self.surface_reviews_state, self.summary_state}
            or len(self.accepted_frames) != self.observed_frame_count
            or frame_sequences != tuple(range(self.observed_frame_count))
        ):
            raise ValueError("truncation valid stream evidence is internally inconsistent")
        if self.document_complete:
            end_frames = tuple(
                frame
                for frame in self.accepted_frames
                if frame.phase is CandidateReviewFramePhase.END
            )
            if (
                len(end_frames) != 1
                or self.accepted_prefix_bytes != end_frames[0].byte_end + len(_WIRE_SUFFIX)
                or self.discarded_suffix_bytes != 0
            ):
                raise ValueError("complete truncation document lacks its exact closing envelope")
        if self.document_complete != (
            self.termination is CandidateReviewTruncationTermination.COMPLETE_DOCUMENT
        ):
            raise ValueError("truncation document completion state is inconsistent")
        expected_payload = candidate_review_typed_payload_projection(
            self,
            algorithm_version=algorithm_version,
        )
        if not isinstance(expected_payload, dict):
            raise TypeError("truncation evidence projection has an invalid object shape")
        expected_payload.pop("evidence_sha256", None)
        expected = _canonical_sha256(expected_payload)
        if self.evidence_sha256 != expected:
            raise ValueError("truncation evidence hash is inconsistent")
        return self


class CandidateReviewNormalizationEvidence(_FrozenStrictModel):
    """Durable custody for the exact wire-document to normalized-batch projection."""

    schema_version: Literal["1.0"]
    protocol: Literal["CANDIDATE_REVIEW_NORMALIZATION_V1"]
    request_id: str = Field(min_length=1, max_length=500)
    wire_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalized_batch_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    wire_validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    normalized_batch_sha256: str = Field(pattern=_SHA256_PATTERN)
    findings_sha256: str = Field(pattern=_SHA256_PATTERN)
    surface_reviews_sha256: str = Field(pattern=_SHA256_PATTERN)
    finding_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_FINDINGS)
    surface_review_count: int = Field(ge=0, le=MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS)
    control_frames_removed: Literal[True]
    semantic_records_unchanged: Literal[True]
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_is_coherent_and_self_hashed(self) -> CandidateReviewNormalizationEvidence:
        guard = globals().get("candidate_review_protocol_implementation_is_pristine")
        if guard is not None and (not callable(guard) or not guard()):
            raise ValueError("candidate-review protocol implementation changed")
        if set(type(self).model_fields) - self.model_fields_set:
            raise ValueError("candidate-review normalization evidence requires every field")
        if not _is_bounded_record_identity(self.request_id):
            raise ValueError("candidate-review normalization request identity is invalid")
        candidate_review_schema_algorithm_version(
            wire_schema_sha256=self.wire_schema_sha256,
            normalized_batch_schema_sha256=self.normalized_batch_schema_sha256,
        )
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("candidate-review normalization evidence hash is inconsistent")
        return self

    def require_exact_batch(
        self,
        batch: CandidateReviewBatch,
        *,
        request_id: str,
    ) -> CandidateReviewNormalizationEvidence:
        """Reframe one retained batch and independently replay every custody join."""

        algorithm_version = candidate_review_schema_algorithm_version(
            wire_schema_sha256=self.wire_schema_sha256,
            normalized_batch_schema_sha256=self.normalized_batch_schema_sha256,
        )
        exact_batch = _strict_candidate_review_batch(batch)
        framed = frame_candidate_review_batch(exact_batch)
        findings = [
            candidate_review_typed_payload_projection(
                finding,
                algorithm_version=algorithm_version,
            )
            for finding in exact_batch.findings
        ]
        surface_reviews = [review.model_dump(mode="json") for review in exact_batch.surface_reviews]
        if (
            self.request_id != request_id
            or self.wire_validated_response_sha256
            != _canonical_sha256(
                candidate_review_typed_payload_projection(
                    framed,
                    algorithm_version=algorithm_version,
                )
            )
            or self.normalized_batch_sha256
            != _canonical_sha256(
                candidate_review_typed_payload_projection(
                    exact_batch,
                    algorithm_version=algorithm_version,
                )
            )
            or self.findings_sha256 != _canonical_sha256(findings)
            or self.surface_reviews_sha256 != _canonical_sha256(surface_reviews)
            or self.finding_count != len(exact_batch.findings)
            or self.surface_review_count != len(exact_batch.surface_reviews)
        ):
            raise ValueError("candidate-review normalization custody does not bind the batch")
        return self


class CandidateReviewTruncatedEnvelopeEvidence(_FrozenStrictModel):
    """Raw-free proof that provider/model identity was validated before truncation."""

    schema_version: Literal["1.0"]
    protocol: Literal["CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_V1"]
    logical_request_id: str = Field(min_length=1, max_length=128)
    generation_id: str = Field(min_length=1, max_length=500)
    generation_header_id: str | None = Field(default=None, min_length=1, max_length=500)
    requested_model: str = Field(min_length=1, max_length=500)
    returned_model: str = Field(min_length=1, max_length=500)
    selected_model: str = Field(min_length=1, max_length=500)
    response_provider_identity: str | None = Field(default=None, min_length=1, max_length=500)
    selected_provider_endpoint: str = Field(min_length=1, max_length=500)
    selected_provider_identity: str = Field(min_length=1, max_length=500)
    selected_provider_name: str = Field(min_length=1, max_length=500)
    router_metadata_sha256: str = Field(pattern=_SHA256_PATTERN)
    finish_reason: str = Field(min_length=1, max_length=100)
    native_finish_reason: str | None = Field(default=None, min_length=1, max_length=100)
    wire_schema_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    truncation_confirmed: Literal[True]
    review_credit_eligible: Literal[False]
    authority_eligible: Literal[False]
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_is_coherent_and_self_hashed(
        self,
    ) -> CandidateReviewTruncatedEnvelopeEvidence:
        guard = globals().get("candidate_review_protocol_implementation_is_pristine")
        if guard is not None and (not callable(guard) or not guard()):
            raise ValueError("candidate-review protocol implementation changed")
        _require_every_model_field_supplied(self)
        for value in (
            self.logical_request_id,
            self.generation_id,
            self.requested_model,
            self.returned_model,
            self.selected_model,
            self.selected_provider_endpoint,
            self.selected_provider_identity,
            self.selected_provider_name,
            self.finish_reason,
            *((self.generation_header_id,) if self.generation_header_id is not None else ()),
            *(
                (self.response_provider_identity,)
                if self.response_provider_identity is not None
                else ()
            ),
            *((self.native_finish_reason,) if self.native_finish_reason is not None else ()),
        ):
            if value != value.strip() or any(
                ord(character) < 32 or ord(character) == 127 for character in value
            ):
                raise ValueError("truncated envelope identity is not bounded plain text")
        if not {
            self.finish_reason.casefold(),
            self.native_finish_reason.casefold() if self.native_finish_reason is not None else "",
        }.intersection(_PROVIDER_TRUNCATION_REASONS):
            raise ValueError("truncated envelope lacks a provider truncation reason")
        if (
            self.generation_header_id is not None
            and self.generation_header_id != self.generation_id
        ):
            raise ValueError("truncated envelope generation identities are inconsistent")
        candidate_review_wire_schema_algorithm_version(self.wire_schema_sha256)
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("truncated envelope evidence hash is inconsistent")
        return self


def seal_candidate_review_truncated_envelope_evidence(
    *,
    logical_request_id: str,
    generation_id: str,
    generation_header_id: str | None,
    requested_model: str,
    returned_model: str,
    selected_model: str,
    response_provider_identity: str | None,
    selected_provider_endpoint: str,
    selected_provider_identity: str,
    selected_provider_name: str,
    router_metadata_sha256: str,
    finish_reason: str,
    native_finish_reason: str | None,
    wire_schema_sha256: str,
    response_sha256: str,
) -> CandidateReviewTruncatedEnvelopeEvidence:
    """Seal already-validated OpenRouter envelope scalars without importing its types."""

    if not candidate_review_protocol_implementation_is_pristine():
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "protocol": "CANDIDATE_REVIEW_TRUNCATED_ENVELOPE_V1",
        "logical_request_id": logical_request_id,
        "generation_id": generation_id,
        "generation_header_id": generation_header_id,
        "requested_model": requested_model,
        "returned_model": returned_model,
        "selected_model": selected_model,
        "response_provider_identity": response_provider_identity,
        "selected_provider_endpoint": selected_provider_endpoint,
        "selected_provider_identity": selected_provider_identity,
        "selected_provider_name": selected_provider_name,
        "router_metadata_sha256": router_metadata_sha256,
        "finish_reason": finish_reason,
        "native_finish_reason": native_finish_reason,
        "wire_schema_sha256": wire_schema_sha256,
        "response_sha256": response_sha256,
        "truncation_confirmed": True,
        "review_credit_eligible": False,
        "authority_eligible": False,
    }
    try:
        evidence = CandidateReviewTruncatedEnvelopeEvidence.model_validate_json(
            _CANONICAL_JSON_DUMPS({**payload, "evidence_sha256": _canonical_sha256(payload)}),
            strict=True,
        )
    except (TypeError, ValidationError, ValueError):
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.INVALID_ARGUMENT
        ) from None
    if not candidate_review_protocol_implementation_is_pristine():
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    return evidence


def _expected_phase_for_sequence(
    *,
    finding_count: int | None,
    surface_review_count: int | None,
    sequence: int,
) -> CandidateReviewFramePhase | None:
    if finding_count is None or surface_review_count is None or sequence < 0:
        return None
    if sequence == 0:
        return CandidateReviewFramePhase.BEGIN
    if sequence <= finding_count:
        return CandidateReviewFramePhase.FINDING
    if sequence == finding_count + 1:
        return CandidateReviewFramePhase.FINDINGS_END
    surface_start = finding_count + 2
    if sequence < surface_start + surface_review_count:
        return CandidateReviewFramePhase.SURFACE_REVIEW
    if sequence == surface_start + surface_review_count:
        return CandidateReviewFramePhase.SURFACE_REVIEWS_END
    if sequence == surface_start + surface_review_count + 1:
        return CandidateReviewFramePhase.SUMMARY
    if sequence == surface_start + surface_review_count + 2:
        return CandidateReviewFramePhase.END
    return None


def _expected_control_frame_sha256(
    projection: CandidateReviewTruncationProjection,
    accepted: CandidateReviewAcceptedFrame,
) -> str | None:
    finding_count = projection.declared_finding_count
    surface_review_count = projection.declared_surface_review_count
    if finding_count is None or surface_review_count is None:
        return None
    frame: BaseModel | None = None
    if accepted.phase is CandidateReviewFramePhase.BEGIN:
        frame = CandidateReviewBeginFrame(
            schema_version="1.0",
            sequence=0,
            phase=CandidateReviewFramePhase.BEGIN,
            finding_count=finding_count,
            surface_review_count=surface_review_count,
            summary_count=1,
        )
    elif accepted.phase is CandidateReviewFramePhase.FINDINGS_END:
        frame = CandidateReviewFindingsEndFrame(
            schema_version="1.0",
            sequence=accepted.sequence,
            phase=CandidateReviewFramePhase.FINDINGS_END,
            record_count=finding_count,
        )
    elif accepted.phase is CandidateReviewFramePhase.SURFACE_REVIEWS_END:
        frame = CandidateReviewSurfaceReviewsEndFrame(
            schema_version="1.0",
            sequence=accepted.sequence,
            phase=CandidateReviewFramePhase.SURFACE_REVIEWS_END,
            record_count=surface_review_count,
        )
    elif accepted.phase is CandidateReviewFramePhase.SUMMARY:
        if (
            projection.summary_declared_finding_count is None
            or projection.summary_declared_surface_review_count is None
        ):
            return None
        frame = CandidateReviewSummaryFrame(
            schema_version="1.0",
            sequence=accepted.sequence,
            phase=CandidateReviewFramePhase.SUMMARY,
            finding_count=projection.summary_declared_finding_count,
            surface_review_count=projection.summary_declared_surface_review_count,
        )
    elif accepted.phase is CandidateReviewFramePhase.END:
        if (
            projection.end_declared_frame_count is None
            or projection.end_declared_finding_count is None
            or projection.end_declared_surface_review_count is None
            or projection.end_declared_summary_count is None
        ):
            return None
        frame = CandidateReviewEndFrame(
            schema_version="1.0",
            sequence=accepted.sequence,
            phase=CandidateReviewFramePhase.END,
            frame_count=projection.end_declared_frame_count,
            finding_count=projection.end_declared_finding_count,
            surface_review_count=projection.end_declared_surface_review_count,
            summary_count=1,
        )
    return _canonical_sha256(frame.model_dump(mode="json")) if frame is not None else None


class _DuplicateObjectKeyError(ValueError):
    pass


class _NonFiniteNumberError(ValueError):
    pass


class _MalformedFrameBoundaryError(ValueError):
    pass


class _CandidateReviewRawBoundError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RetainedFinding:
    value: CandidateFinding
    frame: CandidateReviewAcceptedFrame


@dataclass(frozen=True, slots=True)
class _RetainedSurfaceReview:
    value: ModelSurfaceReviewRecord
    frame: CandidateReviewAcceptedFrame


_FRAME_MODELS: dict[CandidateReviewFramePhase, type[BaseModel]] = {
    CandidateReviewFramePhase.BEGIN: CandidateReviewBeginFrame,
    CandidateReviewFramePhase.FINDING: CandidateReviewFindingFrame,
    CandidateReviewFramePhase.FINDINGS_END: CandidateReviewFindingsEndFrame,
    CandidateReviewFramePhase.SURFACE_REVIEW: CandidateReviewSurfaceReviewFrame,
    CandidateReviewFramePhase.SURFACE_REVIEWS_END: CandidateReviewSurfaceReviewsEndFrame,
    CandidateReviewFramePhase.SUMMARY: CandidateReviewSummaryFrame,
    CandidateReviewFramePhase.END: CandidateReviewEndFrame,
}


@lru_cache(maxsize=2)
def candidate_review_frame_wire_schema_sha256(
    *,
    algorithm_version: str = _SCHEDULER_V2,
) -> str:
    """Return the strict provider wire-schema hash, distinct from normalized semantics."""

    if algorithm_version == _SCHEDULER_V1:
        return _V1_CANDIDATE_REVIEW_FRAME_WIRE_SCHEMA_SHA256
    if algorithm_version != _SCHEDULER_V2:
        raise ValueError("candidate-review wire schema uses an unknown scheduler algorithm")
    return _strict_schema_sha256(CandidateReviewFramedDocument)


@lru_cache(maxsize=2)
def candidate_review_batch_schema_sha256(
    *,
    algorithm_version: str = _SCHEDULER_V2,
) -> str:
    """Return the strict normalized CandidateReviewBatch schema hash."""

    if algorithm_version == _SCHEDULER_V1:
        return _V1_CANDIDATE_REVIEW_BATCH_SCHEMA_SHA256
    if algorithm_version != _SCHEDULER_V2:
        raise ValueError("candidate-review batch schema uses an unknown scheduler algorithm")
    return _strict_schema_sha256(CandidateReviewBatch)


def candidate_review_schema_algorithm_version(
    *,
    wire_schema_sha256: str,
    normalized_batch_schema_sha256: str,
) -> str:
    """Resolve only an exact coherent v1 or v2 candidate-review schema pair."""

    for algorithm_version in (_SCHEDULER_V1, _SCHEDULER_V2):
        if wire_schema_sha256 == candidate_review_frame_wire_schema_sha256(
            algorithm_version=algorithm_version,
        ) and normalized_batch_schema_sha256 == candidate_review_batch_schema_sha256(
            algorithm_version=algorithm_version,
        ):
            return algorithm_version
    raise ValueError("candidate-review schema hashes are not one coherent algorithm pair")


def candidate_review_wire_schema_algorithm_version(wire_schema_sha256: str) -> str:
    """Resolve one exact supported candidate-review framed-wire schema digest."""

    matches = tuple(
        algorithm_version
        for algorithm_version in (_SCHEDULER_V1, _SCHEDULER_V2)
        if wire_schema_sha256
        == candidate_review_frame_wire_schema_sha256(algorithm_version=algorithm_version)
    )
    if len(matches) != 1:
        raise ValueError("candidate-review wire schema hash uses an unknown algorithm")
    return matches[0]


def frame_candidate_review_batch(
    batch: CandidateReviewBatch,
) -> CandidateReviewFramedDocument:
    """Build the unique normalized wire document for one exact candidate-review batch."""

    if not candidate_review_protocol_implementation_is_pristine():
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    exact_batch = _strict_candidate_review_batch(batch)
    findings = tuple(exact_batch.findings)
    surface_reviews = tuple(exact_batch.surface_reviews)
    frames: list[CandidateReviewFrame] = [
        CandidateReviewBeginFrame(
            schema_version="1.0",
            sequence=0,
            phase=CandidateReviewFramePhase.BEGIN,
            finding_count=len(findings),
            surface_review_count=len(surface_reviews),
            summary_count=1,
        )
    ]
    sequence = 1
    for finding in findings:
        frames.append(
            CandidateReviewFindingFrame(
                schema_version="1.0",
                sequence=sequence,
                phase=CandidateReviewFramePhase.FINDING,
                record=finding,
            )
        )
        sequence += 1
    frames.append(
        CandidateReviewFindingsEndFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.FINDINGS_END,
            record_count=len(findings),
        )
    )
    sequence += 1
    for review in surface_reviews:
        frames.append(
            CandidateReviewSurfaceReviewFrame(
                schema_version="1.0",
                sequence=sequence,
                phase=CandidateReviewFramePhase.SURFACE_REVIEW,
                record=review,
            )
        )
        sequence += 1
    frames.append(
        CandidateReviewSurfaceReviewsEndFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.SURFACE_REVIEWS_END,
            record_count=len(surface_reviews),
        )
    )
    sequence += 1
    frames.append(
        CandidateReviewSummaryFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.SUMMARY,
            finding_count=len(findings),
            surface_review_count=len(surface_reviews),
        )
    )
    sequence += 1
    frames.append(
        CandidateReviewEndFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.END,
            frame_count=sequence + 1,
            finding_count=len(findings),
            surface_review_count=len(surface_reviews),
            summary_count=1,
        )
    )
    return CandidateReviewFramedDocument(frames=tuple(frames))


def normalize_candidate_review_document(
    document: CandidateReviewFramedDocument,
    *,
    request_id: str,
    algorithm_version: str = _SCHEDULER_V2,
) -> tuple[CandidateReviewBatch, CandidateReviewNormalizationEvidence]:
    """Normalize one strict wire document and seal a replayable custody projection."""

    if not candidate_review_protocol_implementation_is_pristine():
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    if type(document) is not CandidateReviewFramedDocument:
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    try:
        exact_document = CandidateReviewFramedDocument.model_validate_json(
            _CANONICAL_JSON_DUMPS(
                candidate_review_typed_payload_projection(
                    document,
                    algorithm_version=algorithm_version,
                )
            ),
            strict=True,
        )
        batch = _complete_batch_from_frames(exact_document.frames)
        # The strict frame protocol is a bijection over normalized batches.  Reframing proves
        # there was no alternate control-frame interpretation hidden by normalization.
        reframed = frame_candidate_review_batch(batch)
    except (ValidationError, ValueError, TypeError):
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT
        ) from None
    if exact_document != reframed:
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT
        )
    if not _is_bounded_record_identity(request_id):
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    findings = [
        candidate_review_typed_payload_projection(
            finding,
            algorithm_version=algorithm_version,
        )
        for finding in batch.findings
    ]
    surface_reviews = [review.model_dump(mode="json") for review in batch.surface_reviews]
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "protocol": "CANDIDATE_REVIEW_NORMALIZATION_V1",
        "request_id": request_id,
        "wire_schema_sha256": candidate_review_frame_wire_schema_sha256(
            algorithm_version=algorithm_version,
        ),
        "normalized_batch_schema_sha256": candidate_review_batch_schema_sha256(
            algorithm_version=algorithm_version,
        ),
        "wire_validated_response_sha256": _canonical_sha256(
            candidate_review_typed_payload_projection(
                exact_document,
                algorithm_version=algorithm_version,
            )
        ),
        "normalized_batch_sha256": _canonical_sha256(
            candidate_review_typed_payload_projection(
                batch,
                algorithm_version=algorithm_version,
            )
        ),
        "findings_sha256": _canonical_sha256(findings),
        "surface_reviews_sha256": _canonical_sha256(surface_reviews),
        "finding_count": len(findings),
        "surface_review_count": len(surface_reviews),
        "control_frames_removed": True,
        "semantic_records_unchanged": True,
    }
    evidence = CandidateReviewNormalizationEvidence.model_validate_json(
        _CANONICAL_JSON_DUMPS({**payload, "evidence_sha256": _canonical_sha256(payload)}),
        strict=True,
    )
    evidence.require_exact_batch(batch, request_id=request_id)
    if not candidate_review_protocol_implementation_is_pristine():
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    return batch, evidence


def decode_complete_candidate_review_document(content: str) -> CandidateReviewFramedDocument:
    """Decode a complete wire document under the same raw bounds as prefix recovery."""

    if not candidate_review_protocol_implementation_is_pristine():
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    _validated_response_bytes(content)
    raw_bound_failure = False
    try:
        _validate_complete_document_raw_bounds(content)
    except _CandidateReviewRawBoundError:
        raw_bound_failure = True
    except ValueError:
        pass
    if raw_bound_failure:
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT
        ) from None
    decoded_document: CandidateReviewFramedDocument | None = None
    structured_output_failure_code: StructuredOutputFailureCode | None = None
    try:
        decoded_document = decode_structured_output(
            content,
            CandidateReviewFramedDocument,
        ).value
    except StructuredOutputDecodeError as exc:
        structured_output_failure_code = exc.code
    if structured_output_failure_code is not None:
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT,
            structured_output_failure_code=structured_output_failure_code,
        ) from None
    assert decoded_document is not None
    return decoded_document


def decode_complete_candidate_review_frames(content: str) -> CandidateReviewBatch:
    """Decode one complete framed document into its normalized candidate-review batch."""

    document = decode_complete_candidate_review_document(content)
    try:
        return _complete_batch_from_frames(document.frames)
    except (ValidationError, ValueError):
        pass
    raise CandidateReviewTruncationError(
        CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT
    ) from None


def project_truncated_candidate_review_prefix(
    content: str,
    *,
    finish_reason: str,
    native_finish_reason: str | None,
    algorithm_version: str = _SCHEDULER_V2,
) -> CandidateReviewTruncationProjection:
    """Recover strictly validated provisional frames from a confirmed length truncation.

    ``content`` is transient input.  The result retains exact complete records plus hashes and
    byte ranges, but never the raw incomplete/invalid suffix.  The result is non-creditable even
    when the provider happened to return a syntactically complete framed document alongside a
    truncation finish reason.
    """

    if not candidate_review_protocol_implementation_is_pristine():
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    response_bytes = _validated_response_bytes(content)
    normalized_finish = _validated_finish_reason(finish_reason)
    normalized_native = (
        _validated_finish_reason(native_finish_reason) if native_finish_reason is not None else None
    )
    if not {
        normalized_finish.casefold(),
        normalized_native.casefold() if normalized_native is not None else "",
    }.intersection(_LENGTH_TRUNCATION_REASONS):
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.TRUNCATION_NOT_CONFIRMED
        )
    if not content.startswith(_WIRE_PREFIX):
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ENVELOPE)
    if algorithm_version not in {_SCHEDULER_V1, _SCHEDULER_V2}:
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)

    return _project_prefix(
        content,
        response_bytes=response_bytes,
        finish_reason=normalized_finish,
        native_finish_reason=normalized_native,
        algorithm_version=algorithm_version,
    )


def _complete_batch_from_frames(
    frames: tuple[CandidateReviewFrame, ...],
) -> CandidateReviewBatch:
    if not frames or type(frames[0]) is not CandidateReviewBeginFrame:
        raise ValueError("candidate review frames must begin with BEGIN")
    begin = frames[0]
    assert isinstance(begin, CandidateReviewBeginFrame)
    finding_end_index = 1 + begin.finding_count
    surface_start = finding_end_index + 1
    surface_end_index = surface_start + begin.surface_review_count
    summary_index = surface_end_index + 1
    end_index = summary_index + 1
    if len(frames) != end_index + 1:
        raise ValueError("candidate review frame count differs from BEGIN")
    if tuple(frame.sequence for frame in frames) != tuple(range(len(frames))):
        raise ValueError("candidate review frame sequence is not exact")

    finding_frames = frames[1:finding_end_index]
    findings_end = frames[finding_end_index]
    surface_frames = frames[surface_start:surface_end_index]
    surface_end = frames[surface_end_index]
    summary = frames[summary_index]
    end = frames[end_index]
    if (
        any(type(frame) is not CandidateReviewFindingFrame for frame in finding_frames)
        or type(findings_end) is not CandidateReviewFindingsEndFrame
        or any(type(frame) is not CandidateReviewSurfaceReviewFrame for frame in surface_frames)
        or type(surface_end) is not CandidateReviewSurfaceReviewsEndFrame
        or type(summary) is not CandidateReviewSummaryFrame
        or type(end) is not CandidateReviewEndFrame
    ):
        raise ValueError("candidate review frame phases are out of order")
    assert isinstance(findings_end, CandidateReviewFindingsEndFrame)
    assert isinstance(surface_end, CandidateReviewSurfaceReviewsEndFrame)
    assert isinstance(summary, CandidateReviewSummaryFrame)
    assert isinstance(end, CandidateReviewEndFrame)
    if (
        findings_end.record_count != begin.finding_count
        or surface_end.record_count != begin.surface_review_count
        or summary.finding_count != begin.finding_count
        or summary.surface_review_count != begin.surface_review_count
        or end.frame_count != len(frames)
        or end.finding_count != begin.finding_count
        or end.surface_review_count != begin.surface_review_count
        or end.summary_count != begin.summary_count
    ):
        raise ValueError("candidate review frame end counts are inconsistent")
    findings = [
        frame.record for frame in finding_frames if isinstance(frame, CandidateReviewFindingFrame)
    ]
    candidate_ids = tuple(item.candidate_id for item in findings)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("candidate review finding identities are duplicated")
    surface_reviews = tuple(
        frame.record
        for frame in surface_frames
        if isinstance(frame, CandidateReviewSurfaceReviewFrame)
    )
    return CandidateReviewBatch(findings=findings, surface_reviews=surface_reviews)


def _validated_response_bytes(content: str) -> bytes:
    if type(content) is not str or not content:
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    if len(content) > MAX_CANDIDATE_REVIEW_RESPONSE_BYTES:
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.RESPONSE_TOO_LARGE
        )
    encoded: bytes | None
    try:
        encoded = content.encode("utf-8")
    except UnicodeError:
        encoded = None
    if encoded is None:
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    if len(encoded) > MAX_CANDIDATE_REVIEW_RESPONSE_BYTES:
        raise CandidateReviewTruncationError(
            CandidateReviewTruncationFailureCode.RESPONSE_TOO_LARGE
        )
    return encoded


def _validated_finish_reason(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 100
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CandidateReviewTruncationError(CandidateReviewTruncationFailureCode.INVALID_ARGUMENT)
    return value


def _strict_candidate_review_batch(batch: CandidateReviewBatch) -> CandidateReviewBatch:
    if type(batch) is not CandidateReviewBatch:
        raise TypeError("candidate-review batch has an invalid exact type")
    return CandidateReviewBatch.model_validate_json(batch.model_dump_json(), strict=True)


def _require_every_model_field_supplied(
    value: Any,
    *,
    algorithm_version: str = _SCHEDULER_V2,
) -> None:
    if isinstance(value, BaseModel):
        missing = set(type(value).model_fields) - value.model_fields_set
        if algorithm_version == _SCHEDULER_V1 and isinstance(value, CandidateFinding):
            if (
                value.actor_model_applicability.value != "unstated"
                or value.actor_context is not None
            ):
                raise ValueError("scheduler v1 candidate review cannot carry actor annotations")
            missing -= {"actor_model_applicability", "actor_context"}
        if missing:
            raise ValueError("strict truncation evidence requires every nested field")
        for field_name in type(value).model_fields:
            _require_every_model_field_supplied(
                getattr(value, field_name),
                algorithm_version=algorithm_version,
            )
    elif isinstance(value, dict):
        for child in value.values():
            _require_every_model_field_supplied(child, algorithm_version=algorithm_version)
    elif isinstance(value, list | tuple):
        for child in value:
            _require_every_model_field_supplied(child, algorithm_version=algorithm_version)


def _strict_schema_sha256(model: type[BaseModel]) -> str:
    schema = _COPY_DEEPCOPY(model.model_json_schema())

    def normalize(node: Any) -> None:
        if isinstance(node, dict):
            node.pop("default", None)
            properties = node.get("properties")
            if isinstance(properties, dict):
                node["required"] = list(properties)
                node["additionalProperties"] = False
            for child in node.values():
                normalize(child)
        elif isinstance(node, list):
            for child in node:
                normalize(child)

    normalize(schema)
    return _canonical_sha256(schema)


def _canonical_sha256(value: Any) -> str:
    return _bytes_sha256(_CANONICAL_JSON_DUMPS(value).encode("utf-8"))


def _bytes_sha256(value: bytes) -> str:
    return _HASHLIB_SHA256(value).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateObjectKeyError
        result[key] = value
    return result


def _reject_non_finite(_: str) -> Never:
    raise _NonFiniteNumberError


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not _MATH_ISFINITE(parsed):
        raise _NonFiniteNumberError
    return parsed


def _seal_candidate_review_json_primitives() -> tuple[
    Callable[[str], Any],
    Callable[[Any], str],
]:
    """Capture strict JSON machinery without later module or class dispatch."""

    decoder = _JSON_DECODER(
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_non_finite,
        parse_float=_finite_float,
    )
    decoder_runtime: Any = decoder
    scan_once = decoder_runtime.scan_once
    make_encoder = _JSON_MAKE_ENCODER
    encode_string = _JSON_ENCODE_BASESTRING_ASCII
    if make_encoder is None:
        raise RuntimeError("candidate review requires the CPython canonical JSON encoder")

    def decode_frame(value: str) -> Any:
        try:
            decoded, end = scan_once(value, 0)
        except StopIteration:
            raise ValueError("candidate review frame JSON is incomplete") from None
        if end != len(value):
            raise ValueError("candidate review frame JSON has trailing content")
        return decoded

    def reject_unsupported(value: object) -> Never:
        raise TypeError(
            "candidate review canonical JSON contains an unsupported value of type "
            f"{type(value).__name__}"
        )

    def canonical_dumps(value: Any) -> str:
        encoder = make_encoder(
            {},
            reject_unsupported,
            encode_string,
            None,
            ":",
            ",",
            True,
            False,
            False,
        )
        return "".join(encoder(value, 0))

    return decode_frame, canonical_dumps


_STRICT_FRAME_JSON_DECODE, _CANONICAL_JSON_DUMPS = _seal_candidate_review_json_primitives()
del _seal_candidate_review_json_primitives


def _frame_identity(raw_frame: str) -> tuple[CandidateReviewFramePhase, int]:
    try:
        value = _STRICT_FRAME_JSON_DECODE(raw_frame)
    except (
        _DuplicateObjectKeyError,
        _NonFiniteNumberError,
        _JSON_DECODE_ERROR,
        UnicodeError,
        RecursionError,
    ):
        raise ValueError("frame identity is invalid") from None
    if not isinstance(value, dict):
        raise ValueError("frame identity is not an object")
    raw_phase = value.get("phase")
    sequence = value.get("sequence")
    if (
        not isinstance(raw_phase, str)
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
    ):
        raise ValueError("frame phase or sequence is invalid")
    try:
        phase = CandidateReviewFramePhase(raw_phase)
    except ValueError:
        raise ValueError("frame phase is unknown") from None
    return phase, sequence


def _scan_object_end(content: str, start: int) -> int | None:
    """Return one object end in one pass, or None for a genuinely incomplete object."""

    if start >= len(content) or content[start] != "{":
        raise _MalformedFrameBoundaryError
    stack: list[str] = ["}"]
    in_string = False
    escaped = False
    index = start + 1
    while index < len(content):
        character = content[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            if len(stack) >= MAX_CANDIDATE_REVIEW_JSON_DEPTH:
                raise _CandidateReviewRawBoundError
            stack.append("}")
        elif character == "[":
            if len(stack) >= MAX_CANDIDATE_REVIEW_JSON_DEPTH:
                raise _CandidateReviewRawBoundError
            stack.append("]")
        elif character in "}]":
            if not stack or character != stack.pop():
                raise _MalformedFrameBoundaryError
            if not stack:
                return index + 1
        index += 1
    return None


def _skip_json_whitespace(content: str, index: int) -> int:
    while index < len(content) and content[index] in " \t\r\n":
        index += 1
    return index


def _validate_complete_document_raw_bounds(content: str) -> None:
    """Preflight ordinary JSON whitespace while bounding every complete frame in one pass."""

    index = _skip_json_whitespace(content, 0)
    if index >= len(content) or content[index] != "{":
        raise ValueError("candidate review document is not an object")
    index = _skip_json_whitespace(content, index + 1)
    if not content.startswith('"frames"', index):
        raise ValueError("candidate review document lacks its frame array")
    index = _skip_json_whitespace(content, index + len('"frames"'))
    if index >= len(content) or content[index] != ":":
        raise ValueError("candidate review frame array lacks a separator")
    index = _skip_json_whitespace(content, index + 1)
    if index >= len(content) or content[index] != "[":
        raise ValueError("candidate review frames are not an array")
    index = _skip_json_whitespace(content, index + 1)
    frame_count = 0
    while index < len(content) and content[index] != "]":
        if frame_count >= MAX_CANDIDATE_REVIEW_FRAMES:
            raise _CandidateReviewRawBoundError
        frame_end = _scan_object_end(content, index)
        if frame_end is None:
            raise ValueError("candidate review frame is incomplete")
        if len(content[index:frame_end].encode("utf-8")) > MAX_CANDIDATE_REVIEW_FRAME_BYTES:
            raise _CandidateReviewRawBoundError
        frame_count += 1
        index = _skip_json_whitespace(content, frame_end)
        if index < len(content) and content[index] == ",":
            index = _skip_json_whitespace(content, index + 1)
            continue
        if index >= len(content) or content[index] != "]":
            raise ValueError("candidate review frame separator is invalid")
    if index >= len(content) or content[index] != "]":
        raise ValueError("candidate review frame array is incomplete")
    index = _skip_json_whitespace(content, index + 1)
    if index >= len(content) or content[index] != "}":
        raise ValueError("candidate review document is incomplete")
    index = _skip_json_whitespace(content, index + 1)
    if index != len(content):
        raise ValueError("candidate review document has trailing data")


@dataclass(slots=True)
class _PrefixState:
    begin: CandidateReviewBeginFrame | None = None
    findings_end_seen: bool = False
    surface_reviews_end_seen: bool = False
    summary_seen: bool = False
    end_seen: bool = False
    observed_frames: int = 0
    invalid_frames: int = 0
    finding_frames: int = 0
    surface_review_frames: int = 0
    last_sequence: int | None = None
    findings_invalid: bool = False
    surface_reviews_invalid: bool = False
    summary_invalid: bool = False
    stream_integrity_valid: bool = True
    summary: CandidateReviewSummaryFrame | None = None
    end: CandidateReviewEndFrame | None = None

    def expected_phase(self) -> CandidateReviewFramePhase | None:
        if self.begin is None:
            return CandidateReviewFramePhase.BEGIN
        if self.finding_frames < self.begin.finding_count:
            return CandidateReviewFramePhase.FINDING
        if not self.findings_end_seen:
            return CandidateReviewFramePhase.FINDINGS_END
        if self.surface_review_frames < self.begin.surface_review_count:
            return CandidateReviewFramePhase.SURFACE_REVIEW
        if not self.surface_reviews_end_seen:
            return CandidateReviewFramePhase.SURFACE_REVIEWS_END
        if not self.summary_seen:
            return CandidateReviewFramePhase.SUMMARY
        if not self.end_seen:
            return CandidateReviewFramePhase.END
        return None

    def note_invalid_phase(self, phase: CandidateReviewFramePhase) -> None:
        self.invalid_frames += 1
        self.stream_integrity_valid = False
        if phase in {
            CandidateReviewFramePhase.FINDING,
            CandidateReviewFramePhase.FINDINGS_END,
        }:
            self.findings_invalid = True
        elif phase in {
            CandidateReviewFramePhase.SURFACE_REVIEW,
            CandidateReviewFramePhase.SURFACE_REVIEWS_END,
        }:
            self.surface_reviews_invalid = True
        elif phase is CandidateReviewFramePhase.SUMMARY:
            self.summary_invalid = True
        else:
            self.stream_integrity_valid = False


def _project_prefix(
    content: str,
    *,
    response_bytes: bytes,
    finish_reason: str,
    native_finish_reason: str | None,
    algorithm_version: str,
) -> CandidateReviewTruncationProjection:
    state = _PrefixState()
    retained_findings: list[_RetainedFinding] = []
    retained_surface_reviews: list[_RetainedSurfaceReview] = []
    accepted_controls: list[CandidateReviewAcceptedFrame] = []
    cursor = len(_WIRE_PREFIX)
    cursor_byte = len(_WIRE_PREFIX.encode("ascii"))
    discarded_start = cursor
    termination = CandidateReviewTruncationTermination.INCOMPLETE_TAIL

    while True:
        if state.observed_frames >= MAX_CANDIDATE_REVIEW_FRAMES:
            termination = CandidateReviewTruncationTermination.FRAME_LIMIT_REACHED
            state.stream_integrity_valid = False
            discarded_start = cursor
            break
        if cursor == len(content):
            discarded_start = cursor
            termination = CandidateReviewTruncationTermination.INCOMPLETE_TAIL
            break
        if content.startswith(_WIRE_SUFFIX, cursor):
            if cursor + len(_WIRE_SUFFIX) != len(content):
                termination = CandidateReviewTruncationTermination.INVALID_SEPARATOR
                state.stream_integrity_valid = False
                discarded_start = cursor
            else:
                termination = CandidateReviewTruncationTermination.COMPLETE_DOCUMENT
                discarded_start = len(content)
                if state.expected_phase() is not None:
                    state.stream_integrity_valid = False
            break
        try:
            frame_end = _scan_object_end(content, cursor)
        except (_CandidateReviewRawBoundError, _MalformedFrameBoundaryError):
            termination = CandidateReviewTruncationTermination.INVALID_FRAME
            _note_expected_invalid(state)
            discarded_start = cursor
            break
        if frame_end is None:
            termination = CandidateReviewTruncationTermination.INCOMPLETE_TAIL
            discarded_start = cursor
            break

        raw_frame = content[cursor:frame_end]
        raw_frame_bytes = raw_frame.encode("utf-8")
        if len(raw_frame_bytes) > MAX_CANDIDATE_REVIEW_FRAME_BYTES:
            termination = CandidateReviewTruncationTermination.FRAME_LIMIT_REACHED
            _note_expected_invalid(state)
            discarded_start = cursor
            break
        expected_phase = state.expected_phase()
        try:
            phase, sequence = _frame_identity(raw_frame)
        except ValueError:
            termination = CandidateReviewTruncationTermination.INVALID_FRAME
            _note_expected_invalid(state)
            discarded_start = cursor
            break
        if sequence != state.observed_frames:
            termination = CandidateReviewTruncationTermination.INVALID_SEQUENCE
            _note_expected_invalid(state)
            discarded_start = cursor
            break
        if phase is not expected_phase:
            termination = CandidateReviewTruncationTermination.INVALID_PHASE_ORDER
            _note_expected_invalid(state)
            discarded_start = cursor
            break

        frame_model = _FRAME_MODELS[phase]
        decoded_frame: BaseModel | None = None
        try:
            if algorithm_version == _SCHEDULER_V1:
                decoded_frame = frame_model.model_validate_json(
                    _CANONICAL_JSON_DUMPS(_STRICT_FRAME_JSON_DECODE(raw_frame)),
                    strict=True,
                )
                _require_every_model_field_supplied(
                    decoded_frame,
                    algorithm_version=algorithm_version,
                )
            else:
                decoded_frame = decode_structured_output(raw_frame, frame_model).value
        except (StructuredOutputDecodeError, TypeError, ValidationError, ValueError):
            state.note_invalid_phase(phase)

        accepted_frame: CandidateReviewAcceptedFrame | None = None
        if decoded_frame is not None:
            record_id: str | None = None
            if isinstance(decoded_frame, CandidateReviewFindingFrame):
                record_id = decoded_frame.record.candidate_id
            elif isinstance(decoded_frame, CandidateReviewSurfaceReviewFrame):
                record_id = decoded_frame.record.surface_id
            accepted_frame = CandidateReviewAcceptedFrame(
                sequence=sequence,
                phase=phase,
                byte_start=cursor_byte,
                byte_end=cursor_byte + len(raw_frame_bytes),
                frame_bytes=len(raw_frame_bytes),
                frame_sha256=_bytes_sha256(raw_frame_bytes),
                normalized_value_sha256=_canonical_sha256(
                    candidate_review_typed_payload_projection(
                        decoded_frame.record,
                        algorithm_version=algorithm_version,
                    )
                    if isinstance(decoded_frame, CandidateReviewFindingFrame)
                    else (
                        decoded_frame.record.model_dump(mode="json")
                        if isinstance(decoded_frame, CandidateReviewSurfaceReviewFrame)
                        else decoded_frame.model_dump(mode="json")
                    )
                ),
                record_id=record_id,
            )

        _consume_frame(
            state,
            phase=phase,
            decoded_frame=decoded_frame,
            accepted_frame=accepted_frame,
            retained_findings=retained_findings,
            retained_surface_reviews=retained_surface_reviews,
            accepted_controls=accepted_controls,
        )
        state.observed_frames += 1
        state.last_sequence = sequence

        if frame_end == len(content):
            discarded_start = frame_end
            termination = CandidateReviewTruncationTermination.END_OF_INPUT_AFTER_FRAME
            break
        if content[frame_end] == ",":
            cursor = frame_end + 1
            cursor_byte += len(raw_frame_bytes) + 1
            discarded_start = cursor
            continue
        if content.startswith(_WIRE_SUFFIX, frame_end) and frame_end + len(_WIRE_SUFFIX) == len(
            content
        ):
            discarded_start = len(content)
            termination = CandidateReviewTruncationTermination.COMPLETE_DOCUMENT
            if state.expected_phase() is not None:
                state.stream_integrity_valid = False
            break
        discarded_start = frame_end
        termination = CandidateReviewTruncationTermination.INVALID_SEPARATOR
        state.stream_integrity_valid = False
        break

    if termination is CandidateReviewTruncationTermination.COMPLETE_DOCUMENT and state.end is None:
        termination = CandidateReviewTruncationTermination.INVALID_FRAME
        state.stream_integrity_valid = False

    findings, finding_frames = _remove_duplicate_findings(retained_findings, state)
    surface_reviews, surface_frames = _remove_duplicate_surface_reviews(
        retained_surface_reviews,
        state,
    )
    accepted_frames = tuple(
        sorted(
            (*accepted_controls, *finding_frames, *surface_frames),
            key=lambda frame: frame.sequence,
        )
    )
    accepted_prefix = content[:discarded_start].encode("utf-8")
    discarded_suffix = content[discarded_start:].encode("utf-8")
    findings_state = _findings_state(state)
    surface_reviews_state = _surface_reviews_state(state)
    summary_state = _summary_state(state)
    summary = state.summary
    end = state.end
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "protocol": _PROTOCOL,
        "wire_schema_sha256": candidate_review_frame_wire_schema_sha256(
            algorithm_version=algorithm_version,
        ),
        "normalized_batch_schema_sha256": candidate_review_batch_schema_sha256(
            algorithm_version=algorithm_version,
        ),
        "finish_reason": finish_reason,
        "native_finish_reason": native_finish_reason,
        "truncation_confirmed": True,
        "original_response_sha256": _bytes_sha256(response_bytes),
        "original_response_bytes": len(response_bytes),
        "accepted_prefix_sha256": _bytes_sha256(accepted_prefix),
        "accepted_prefix_bytes": len(accepted_prefix),
        "discarded_suffix_sha256": _bytes_sha256(discarded_suffix),
        "discarded_suffix_bytes": len(discarded_suffix),
        "discarded_suffix_retained": False,
        "accepted_frames": [frame.model_dump(mode="json") for frame in accepted_frames],
        "observed_frame_count": state.observed_frames,
        "invalid_frame_count": state.invalid_frames,
        "last_observed_sequence": state.last_sequence,
        "declared_finding_count": state.begin.finding_count if state.begin is not None else None,
        "observed_finding_frame_count": state.finding_frames,
        "accepted_finding_count": len(findings),
        "declared_surface_review_count": (
            state.begin.surface_review_count if state.begin is not None else None
        ),
        "observed_surface_review_frame_count": state.surface_review_frames,
        "accepted_surface_review_count": len(surface_reviews),
        "summary_declared_finding_count": summary.finding_count if summary is not None else None,
        "summary_declared_surface_review_count": (
            summary.surface_review_count if summary is not None else None
        ),
        "end_declared_frame_count": end.frame_count if end is not None else None,
        "end_declared_finding_count": end.finding_count if end is not None else None,
        "end_declared_surface_review_count": (
            end.surface_review_count if end is not None else None
        ),
        "end_declared_summary_count": end.summary_count if end is not None else None,
        "findings_state": findings_state.value,
        "surface_reviews_state": surface_reviews_state.value,
        "summary_state": summary_state.value,
        "stream_integrity_valid": state.stream_integrity_valid,
        "document_complete": termination is CandidateReviewTruncationTermination.COMPLETE_DOCUMENT,
        "termination": termination.value,
        "findings": [
            candidate_review_typed_payload_projection(
                finding,
                algorithm_version=algorithm_version,
            )
            for finding in findings
        ],
        "surface_reviews": [review.model_dump(mode="json") for review in surface_reviews],
        "review_credit_eligible": False,
        "coverage_credit_eligible": False,
        "summary_credit_eligible": False,
        "authority_eligible": False,
    }
    return CandidateReviewTruncationProjection.model_validate_json(
        _CANONICAL_JSON_DUMPS({**payload, "evidence_sha256": _canonical_sha256(payload)})
    )


def _consume_frame(
    state: _PrefixState,
    *,
    phase: CandidateReviewFramePhase,
    decoded_frame: BaseModel | None,
    accepted_frame: CandidateReviewAcceptedFrame | None,
    retained_findings: list[_RetainedFinding],
    retained_surface_reviews: list[_RetainedSurfaceReview],
    accepted_controls: list[CandidateReviewAcceptedFrame],
) -> None:
    if phase is CandidateReviewFramePhase.BEGIN:
        if isinstance(decoded_frame, CandidateReviewBeginFrame):
            state.begin = decoded_frame
            assert accepted_frame is not None
            accepted_controls.append(accepted_frame)
        else:
            state.stream_integrity_valid = False
        return

    if phase is CandidateReviewFramePhase.FINDING:
        state.finding_frames += 1
        if isinstance(decoded_frame, CandidateReviewFindingFrame):
            assert accepted_frame is not None
            retained_findings.append(_RetainedFinding(decoded_frame.record, accepted_frame))
        return
    if phase is CandidateReviewFramePhase.FINDINGS_END:
        state.findings_end_seen = True
        if not isinstance(decoded_frame, CandidateReviewFindingsEndFrame):
            state.findings_invalid = True
            return
        assert state.begin is not None
        if decoded_frame.record_count != state.begin.finding_count or (
            decoded_frame.record_count != state.finding_frames
        ):
            state.findings_invalid = True
            state.stream_integrity_valid = False
            state.invalid_frames += 1
            return
        assert accepted_frame is not None
        accepted_controls.append(accepted_frame)
        return
    if phase is CandidateReviewFramePhase.SURFACE_REVIEW:
        state.surface_review_frames += 1
        if isinstance(decoded_frame, CandidateReviewSurfaceReviewFrame):
            assert accepted_frame is not None
            retained_surface_reviews.append(
                _RetainedSurfaceReview(decoded_frame.record, accepted_frame)
            )
        return
    if phase is CandidateReviewFramePhase.SURFACE_REVIEWS_END:
        state.surface_reviews_end_seen = True
        if not isinstance(decoded_frame, CandidateReviewSurfaceReviewsEndFrame):
            state.surface_reviews_invalid = True
            return
        assert state.begin is not None
        if decoded_frame.record_count != state.begin.surface_review_count or (
            decoded_frame.record_count != state.surface_review_frames
        ):
            state.surface_reviews_invalid = True
            state.stream_integrity_valid = False
            state.invalid_frames += 1
            return
        assert accepted_frame is not None
        accepted_controls.append(accepted_frame)
        return
    if phase is CandidateReviewFramePhase.SUMMARY:
        state.summary_seen = True
        if not isinstance(decoded_frame, CandidateReviewSummaryFrame):
            state.summary_invalid = True
            return
        assert state.begin is not None
        if (
            decoded_frame.finding_count != state.begin.finding_count
            or decoded_frame.surface_review_count != state.begin.surface_review_count
        ):
            state.summary_invalid = True
            state.stream_integrity_valid = False
            state.invalid_frames += 1
            return
        state.summary = decoded_frame
        assert accepted_frame is not None
        accepted_controls.append(accepted_frame)
        return
    if phase is CandidateReviewFramePhase.END:
        state.end_seen = True
        if not isinstance(decoded_frame, CandidateReviewEndFrame):
            state.stream_integrity_valid = False
            return
        assert state.begin is not None
        if (
            decoded_frame.frame_count != state.observed_frames + 1
            or decoded_frame.finding_count != state.begin.finding_count
            or decoded_frame.surface_review_count != state.begin.surface_review_count
            or decoded_frame.summary_count != state.begin.summary_count
        ):
            state.stream_integrity_valid = False
            state.invalid_frames += 1
            return
        state.end = decoded_frame
        assert accepted_frame is not None
        accepted_controls.append(accepted_frame)


def _remove_duplicate_findings(
    retained: list[_RetainedFinding],
    state: _PrefixState,
) -> tuple[tuple[CandidateFinding, ...], tuple[CandidateReviewAcceptedFrame, ...]]:
    counts: dict[str, int] = {}
    for item in retained:
        counts[item.value.candidate_id] = counts.get(item.value.candidate_id, 0) + 1
    duplicates = {identifier for identifier, count in counts.items() if count > 1}
    if duplicates:
        state.findings_invalid = True
        state.stream_integrity_valid = False
        state.invalid_frames += sum(counts[identifier] for identifier in duplicates)
    unique = tuple(item for item in retained if item.value.candidate_id not in duplicates)
    return tuple(item.value for item in unique), tuple(item.frame for item in unique)


def _remove_duplicate_surface_reviews(
    retained: list[_RetainedSurfaceReview],
    state: _PrefixState,
) -> tuple[tuple[ModelSurfaceReviewRecord, ...], tuple[CandidateReviewAcceptedFrame, ...]]:
    counts: dict[str, int] = {}
    for item in retained:
        counts[item.value.surface_id] = counts.get(item.value.surface_id, 0) + 1
    duplicates = {identifier for identifier, count in counts.items() if count > 1}
    if duplicates:
        state.surface_reviews_invalid = True
        state.stream_integrity_valid = False
        state.invalid_frames += sum(counts[identifier] for identifier in duplicates)
    unique = tuple(item for item in retained if item.value.surface_id not in duplicates)
    surface_ids = tuple(item.value.surface_id for item in unique)
    if surface_ids != tuple(sorted(surface_ids)):
        state.surface_reviews_invalid = True
        state.stream_integrity_valid = False
        state.invalid_frames += len(unique)
    ordered = tuple(sorted(unique, key=lambda item: item.value.surface_id))
    return tuple(item.value for item in ordered), tuple(item.frame for item in ordered)


def _findings_state(state: _PrefixState) -> CandidateReviewChannelState:
    if state.findings_invalid:
        return CandidateReviewChannelState.INVALID
    if state.findings_end_seen:
        return CandidateReviewChannelState.COMPLETE
    if state.begin is not None:
        return CandidateReviewChannelState.OPEN
    return CandidateReviewChannelState.NOT_STARTED


def _surface_reviews_state(state: _PrefixState) -> CandidateReviewChannelState:
    if state.surface_reviews_invalid:
        return CandidateReviewChannelState.INVALID
    if state.surface_reviews_end_seen:
        return CandidateReviewChannelState.COMPLETE
    if state.findings_end_seen or state.surface_review_frames:
        return CandidateReviewChannelState.OPEN
    return CandidateReviewChannelState.NOT_STARTED


def _summary_state(state: _PrefixState) -> CandidateReviewChannelState:
    if state.summary_invalid:
        return CandidateReviewChannelState.INVALID
    if state.summary_seen:
        return CandidateReviewChannelState.COMPLETE
    return CandidateReviewChannelState.NOT_STARTED


def _note_expected_invalid(state: _PrefixState) -> None:
    expected = state.expected_phase()
    if expected is None:
        state.invalid_frames += 1
        state.stream_integrity_valid = False
        return
    state.note_invalid_phase(expected)


def _is_bounded_record_identity(value: str) -> bool:
    return bool(
        isinstance(value, str)
        and 1 <= len(value) <= 500
        and value == value.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _seal_candidate_review_protocol_pristine_guard() -> Callable[[], bool]:
    """Close over every implementation dependency used to create durable review custody."""

    binding_names = (
        "copy",
        "hashlib",
        "json",
        "math",
        "_COPY_DEEPCOPY",
        "_HASHLIB_SHA256",
        "_JSON_DECODE_ERROR",
        "_JSON_DUMPS",
        "_JSON_LOADS",
        "_JSON_DECODER",
        "_JSON_DECODER_DECODE",
        "_JSON_DECODER_RAW_DECODE",
        "_JSON_ENCODER",
        "_JSON_ENCODER_ENCODE",
        "_JSON_ENCODER_ITERENCODE",
        "_JSON_DECODER_MODULE",
        "_JSON_ENCODER_MODULE",
        "_JSON_SCANNER_MODULE",
        "_JSON_ENCODE_BASESTRING_ASCII",
        "_JSON_MAKE_ENCODER",
        "_JSON_MAKE_SCANNER",
        "_JSON_PARSE_ARRAY",
        "_JSON_PARSE_OBJECT",
        "_JSON_SCANSTRING",
        "_MATH_ISFINITE",
        "_STRICT_FRAME_JSON_DECODE",
        "_CANONICAL_JSON_DUMPS",
        "pairwise",
        "Mapping",
        "Sequence",
        "BaseModel",
        "ValidationError",
        "StructuredOutputDecodeError",
        "StructuredOutputFailureCode",
        "CandidateFinding",
        "CandidateReviewBatch",
        "ModelSurfaceReviewRecord",
        "CandidateReviewFramePhase",
        "CandidateReviewChannelState",
        "CandidateReviewTruncationTermination",
        "CandidateReviewTruncationFailureCode",
        "CandidateReviewTruncationError",
        "_FrozenStrictModel",
        "CandidateReviewBeginFrame",
        "CandidateReviewFindingFrame",
        "CandidateReviewFindingsEndFrame",
        "CandidateReviewSurfaceReviewFrame",
        "CandidateReviewSurfaceReviewsEndFrame",
        "CandidateReviewSummaryFrame",
        "CandidateReviewEndFrame",
        "CandidateReviewFramedDocument",
        "CandidateReviewAcceptedFrame",
        "CandidateReviewTruncationProjection",
        "CandidateReviewNormalizationEvidence",
        "CandidateReviewTruncatedEnvelopeEvidence",
        "decode_structured_output",
        "_complete_batch_from_frames",
        "_validated_response_bytes",
        "_validated_finish_reason",
        "_strict_candidate_review_batch",
        "_require_every_model_field_supplied",
        "_strict_schema_sha256",
        "_canonical_sha256",
        "_bytes_sha256",
        "_reject_duplicate_pairs",
        "_reject_non_finite",
        "_finite_float",
        "_frame_identity",
        "_scan_object_end",
        "_skip_json_whitespace",
        "_validate_complete_document_raw_bounds",
        "_DuplicateObjectKeyError",
        "_NonFiniteNumberError",
        "_MalformedFrameBoundaryError",
        "_CandidateReviewRawBoundError",
        "_RetainedFinding",
        "_RetainedSurfaceReview",
        "_PrefixState",
        "_FRAME_MODELS",
        "_project_prefix",
        "_consume_frame",
        "_remove_duplicate_findings",
        "_remove_duplicate_surface_reviews",
        "_findings_state",
        "_surface_reviews_state",
        "_summary_state",
        "_note_expected_invalid",
        "_is_bounded_record_identity",
        "_SCHEDULER_V1",
        "_SCHEDULER_V2",
        "_V1_CANDIDATE_REVIEW_BATCH_SCHEMA_SHA256",
        "_V1_CANDIDATE_REVIEW_FRAME_WIRE_SCHEMA_SHA256",
        "_strip_v1_candidate_actor_defaults",
        "candidate_review_typed_payload_projection",
        "candidate_review_schema_algorithm_version",
        "candidate_review_wire_schema_algorithm_version",
        "_expected_phase_for_sequence",
        "_expected_control_frame_sha256",
        "frame_candidate_review_batch",
        "normalize_candidate_review_document",
        "seal_candidate_review_truncated_envelope_evidence",
        "decode_complete_candidate_review_document",
        "decode_complete_candidate_review_frames",
        "project_truncated_candidate_review_prefix",
        "candidate_review_frame_wire_schema_sha256",
        "candidate_review_batch_schema_sha256",
    )
    trusted_bindings = tuple((name, globals()[name]) for name in binding_names)
    trusted_dependency_attributes = (
        (copy, "deepcopy", _COPY_DEEPCOPY),
        (hashlib, "sha256", _HASHLIB_SHA256),
        (json, "JSONDecodeError", _JSON_DECODE_ERROR),
        (json, "dumps", _JSON_DUMPS),
        (json, "loads", _JSON_LOADS),
        (json, "JSONDecoder", _JSON_DECODER),
        (_JSON_DECODER, "decode", _JSON_DECODER_DECODE),
        (_JSON_DECODER, "raw_decode", _JSON_DECODER_RAW_DECODE),
        (json, "JSONEncoder", _JSON_ENCODER),
        (_JSON_ENCODER, "encode", _JSON_ENCODER_ENCODE),
        (_JSON_ENCODER, "iterencode", _JSON_ENCODER_ITERENCODE),
        (json, "decoder", _JSON_DECODER_MODULE),
        (json, "encoder", _JSON_ENCODER_MODULE),
        (json, "scanner", _JSON_SCANNER_MODULE),
        (_JSON_ENCODER_MODULE, "encode_basestring_ascii", _JSON_ENCODE_BASESTRING_ASCII),
        (_JSON_ENCODER_MODULE, "c_make_encoder", _JSON_MAKE_ENCODER),
        (_JSON_SCANNER_MODULE, "make_scanner", _JSON_MAKE_SCANNER),
        (_JSON_DECODER_MODULE, "JSONArray", _JSON_PARSE_ARRAY),
        (_JSON_DECODER_MODULE, "JSONObject", _JSON_PARSE_OBJECT),
        (_JSON_DECODER_MODULE, "scanstring", _JSON_SCANSTRING),
        (math, "isfinite", _MATH_ISFINITE),
    )
    models = (
        CandidateFinding,
        CandidateReviewBatch,
        ModelSurfaceReviewRecord,
        CandidateReviewBeginFrame,
        CandidateReviewFindingFrame,
        CandidateReviewFindingsEndFrame,
        CandidateReviewSurfaceReviewFrame,
        CandidateReviewSurfaceReviewsEndFrame,
        CandidateReviewSummaryFrame,
        CandidateReviewEndFrame,
        CandidateReviewFramedDocument,
        CandidateReviewAcceptedFrame,
        CandidateReviewTruncationProjection,
        CandidateReviewNormalizationEvidence,
        CandidateReviewTruncatedEnvelopeEvidence,
    )

    def descriptor_surface(model: type[BaseModel]) -> tuple[tuple[str, object], ...]:
        return tuple(
            sorted(
                (
                    (name, descriptor)
                    for name, descriptor in vars(model).items()
                    if callable(descriptor)
                    or isinstance(descriptor, (classmethod, staticmethod, property))
                ),
                key=lambda item: item[0],
            )
        )

    trusted_strict_schema_sha256 = _strict_schema_sha256
    model_states = tuple(
        (
            model,
            model.__pydantic_validator__,
            model.__pydantic_core_schema__,
            descriptor_surface(model),
            trusted_strict_schema_sha256(model),
        )
        for model in models
    )
    trusted_frame_models = tuple(_FRAME_MODELS.items())
    constant_names = (
        "_WIRE_PREFIX",
        "_WIRE_SUFFIX",
        "_PROTOCOL",
        "_LENGTH_TRUNCATION_REASONS",
        "_PROVIDER_TRUNCATION_REASONS",
        "MAX_CANDIDATE_REVIEW_RESPONSE_BYTES",
        "MAX_CANDIDATE_REVIEW_FRAME_BYTES",
        "MAX_CANDIDATE_REVIEW_JSON_DEPTH",
        "MAX_CANDIDATE_REVIEW_FINDINGS",
        "MAX_CANDIDATE_REVIEW_SURFACE_REVIEWS",
        "MAX_CANDIDATE_REVIEW_FRAMES",
    )
    trusted_constants = tuple((name, globals()[name]) for name in constant_names)

    def implementation_is_pristine() -> bool:
        if any(globals().get(name) is not value for name, value in trusted_bindings):
            return False
        if any(
            getattr(module, name, None) is not trusted
            for module, name, trusted in trusted_dependency_attributes
        ):
            return False
        if len(_FRAME_MODELS) != len(trusted_frame_models) or any(
            _FRAME_MODELS.get(phase) is not model for phase, model in trusted_frame_models
        ):
            return False
        if any(globals().get(name) is not value for name, value in trusted_constants):
            return False
        for model, validator, core_schema, descriptors, schema_sha256 in model_states:
            current_descriptors = descriptor_surface(model)
            if (
                model.__pydantic_validator__ is not validator
                or model.__pydantic_core_schema__ is not core_schema
                or len(current_descriptors) != len(descriptors)
                or any(
                    current_name != trusted_name or current is not trusted
                    for (current_name, current), (trusted_name, trusted) in zip(
                        current_descriptors,
                        descriptors,
                        strict=True,
                    )
                )
                or trusted_strict_schema_sha256(model) != schema_sha256
            ):
                return False
        return True

    return implementation_is_pristine


candidate_review_protocol_implementation_is_pristine = (
    _seal_candidate_review_protocol_pristine_guard()
)
del _seal_candidate_review_protocol_pristine_guard
