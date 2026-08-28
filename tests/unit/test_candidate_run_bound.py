from __future__ import annotations

from typing import cast

import pytest

from mmaudit.models.schemas import CandidateFinding
from mmaudit.orchestration.pipeline import _require_candidate_run_bound


def _inventory(size: int) -> list[CandidateFinding]:
    # The pure bound depends only on inventory cardinality; opaque sentinels keep this
    # regression independent of candidate schema evolution.
    return cast(list[CandidateFinding], [object() for _ in range(size)])


def test_candidate_run_bound_accepts_the_exact_configured_ceiling() -> None:
    _require_candidate_run_bound(_inventory(200), max_candidates_per_run=200)


def test_candidate_run_bound_refuses_overflow_without_truncating_inventory() -> None:
    candidates = _inventory(201)

    with pytest.raises(
        ValueError,
        match=r"candidate inventory exceeds configured per-run bound: 201 > 200",
    ):
        _require_candidate_run_bound(candidates, max_candidates_per_run=200)

    assert len(candidates) == 201


@pytest.mark.parametrize("invalid", [True, False, 0, 2_001])
def test_candidate_run_bound_rejects_invalid_or_boolean_limits(invalid: object) -> None:
    with pytest.raises(
        ValueError,
        match="candidate run bound must be an integer from 1 through 2000",
    ):
        _require_candidate_run_bound(
            _inventory(0),
            max_candidates_per_run=cast(int, invalid),
        )
