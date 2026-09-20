"""Synthetic framed channel failures; no provider, engine or live-credit evidence."""

from __future__ import annotations

from mmaudit.models.schemas import CandidateFinding, ModelSurfaceReviewRecord
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewTruncationProjection,
    project_truncated_candidate_review_prefix,
)
from tests.unit.test_truncation import _candidate, _frame_json, _frames

VALID_FINDING_IDS = ("channel-valid-first", "channel-valid-second")


def channel_projection(
    surfaces: tuple[ModelSurfaceReviewRecord, ...],
    *,
    state: CandidateReviewChannelState,
    retained_count: int,
    findings: tuple[CandidateFinding, ...] = (),
    algorithm_version: str = "mmaudit.seven-pass-scheduler.v2",
) -> CandidateReviewTruncationProjection:
    """Retain two exact findings while a later finding is invalid or truncated."""

    assert not findings
    assert algorithm_version == "mmaudit.seven-pass-scheduler.v2"
    assert state in {CandidateReviewChannelState.INVALID, CandidateReviewChannelState.OPEN}
    assert 0 <= retained_count < len(surfaces)
    records = tuple(_candidate(identity) for identity in (*VALID_FINDING_IDS, "channel-bad"))
    frames = _frames(records, surfaces)
    if state is CandidateReviewChannelState.INVALID:
        record = frames[3]["record"]
        assert isinstance(record, dict)
        record["confidence"] = "synthetic-invalid-confidence"
        count = 2 + len(records) + retained_count
        phase = "SURFACE_REVIEW"
        partial = '"surface_id":"synthetic-partial'
    else:
        count = 3
        phase = "FINDING"
        partial = '"candidate_id":"synthetic-partial'
    wire = (
        '{"frames":['
        + ",".join(_frame_json(frame) for frame in frames[:count])
        + ',{"schema_version":"1.0","sequence":'
        + str(count)
        + ',"phase":"'
        + phase
        + '","record":{'
        + partial
    )
    projection = project_truncated_candidate_review_prefix(
        wire,
        finish_reason="stop",
        native_finish_reason="max_tokens",
    )
    assert projection.findings_state is state
    assert tuple(finding.candidate_id for finding in projection.findings) == VALID_FINDING_IDS
    return projection
