"""Nonempty synthetic recovery records issued before their original usage is sealed."""

from pathlib import Path
from typing import Any

import pytest

import tests.unit.test_truncation_recovery_journal as recovery_fixture
import tests.unit.test_truncation_tree_evidence as tree_fixture
from mmaudit.models.schemas import CandidateReviewBatch
from tests.unit.test_truncation import _candidate


def build_nonempty_candidate_tree(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> tree_fixture.LiveTreeFixture:
    """Keep one identical raw ID on the original parent, two bridges and four leaves."""

    raw = _candidate("same-synthetic-raw-id")
    project = tree_fixture._projection
    parent = tree_fixture._typed_parent_truncation
    truncate = tree_fixture._truncated_custody
    complete = tree_fixture._success_custody

    def project_nonempty(*args: Any, **kwargs: Any) -> Any:
        return project(*args, **kwargs, findings=(raw,))

    def parent_nonempty(**kwargs: Any) -> Any:
        kwargs["full_batch"] = CandidateReviewBatch(
            findings=(raw,), surface_reviews=kwargs["full_batch"].surface_reviews
        )
        return parent(**kwargs)

    def truncate_nonempty(**kwargs: Any) -> Any:
        return truncate(**kwargs, findings=(raw,))

    def complete_nonempty(**kwargs: Any) -> Any:
        def response(**values: Any) -> CandidateReviewBatch:
            return CandidateReviewBatch(**{**values, "findings": (raw,)})

        with monkeypatch.context() as patch:
            patch.setattr(recovery_fixture, "CandidateReviewBatch", response)
            return complete(**kwargs)

    # Only author test responses; never replace runtime admission, ownership or validation.
    with monkeypatch.context() as patch:
        patch.setattr(tree_fixture, "_projection", project_nonempty)
        patch.setattr(tree_fixture, "_typed_parent_truncation", parent_nonempty)
        patch.setattr(tree_fixture, "_truncated_custody", truncate_nonempty)
        patch.setattr(tree_fixture, "_success_custody", complete_nonempty)
        return tree_fixture.build_live_tree(
            path, source_count=7, truncated_paths=frozenset({"0", "1"}), retained_count=1
        )
