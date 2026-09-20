"""An unresolved finding channel must not erase or excuse its valid records."""

from __future__ import annotations

import json

import pytest

from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewTruncationProjection,
    _canonical_sha256,
)
from tests.channel_retention_support import VALID_FINDING_IDS, channel_projection
from tests.unit.test_truncation_recovery_journal import _requested_surfaces


@pytest.mark.parametrize(
    "state", [CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID]
)
def test_unresolved_findings_preserve_each_valid_record_and_independent_channels(
    state: CandidateReviewChannelState,
) -> None:
    _, records = _requested_surfaces(7)
    projection = channel_projection(records, state=state, retained_count=1)

    assert tuple(finding.candidate_id for finding in projection.findings) == VALID_FINDING_IDS
    assert projection.accepted_finding_count == 2
    assert projection.declared_finding_count == 3
    assert projection.surface_reviews == (
        records[:1] if state is CandidateReviewChannelState.INVALID else ()
    )
    assert projection.summary_state is CandidateReviewChannelState.NOT_STARTED
    assert projection.truncation_confirmed
    assert not projection.review_credit_eligible
    assert not projection.coverage_credit_eligible
    assert not projection.summary_credit_eligible
    assert not projection.authority_eligible
    encoded = projection.model_dump_json()
    assert "synthetic-invalid-confidence" not in encoded
    assert "synthetic-partial" not in encoded
    replayed = CandidateReviewTruncationProjection.model_validate_json(encoded, strict=True)
    assert replayed.model_dump_json() == encoded


@pytest.mark.parametrize(
    "state", [CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID]
)
def test_unresolved_channel_cannot_excuse_a_rehashed_valid_finding_substitution(
    state: CandidateReviewChannelState,
) -> None:
    _, records = _requested_surfaces(7)
    projection = channel_projection(records, state=state, retained_count=1)
    payload = projection.model_dump(mode="json")
    payload["findings"][0]["confidence"] = 0.7
    payload["evidence_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )
    with pytest.raises(ValueError, match=r"finding|frame|hash"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(payload), strict=True)
