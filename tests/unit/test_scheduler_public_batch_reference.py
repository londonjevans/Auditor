"""Strict-reference projection checks for synthetic promoted and failed recovery paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.scheduler import (
    SchedulerTruncationRecoveryModelRequestEvidence,
    build_scheduler_truncation_recovery_model_request_evidence,
)
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot
from tests.unit.test_scheduler_recovery_release_projection import _released_projection
from tests.unit.test_specialist_truncation_ancestry import build_specialist_ancestry
from tests.unit.test_truncation_tree_promotion import promoted_tree as promoted_tree


def _assert_strict_reference(
    arguments: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> tuple[SchedulerTruncationRecoveryModelRequestEvidence, ...]:
    captured: list[dict[str, Any]] = []
    original = SchedulerTruncationRecoveryModelRequestEvidence._build_with_entry_validator

    def capture(cls: type[Any], **item: Any) -> SchedulerTruncationRecoveryModelRequestEvidence:
        captured.append({key: value for key, value in item.items() if key != "entry_validator"})
        return original(**item)

    with monkeypatch.context() as patch:
        patch.setattr(
            SchedulerTruncationRecoveryModelRequestEvidence,
            "_build_with_entry_validator",
            classmethod(capture),
        )
        actual = build_scheduler_truncation_recovery_model_request_evidence(**arguments)
    assert captured
    assert len(captured) == len(actual)
    strict = tuple(
        sorted(
            (SchedulerTruncationRecoveryModelRequestEvidence.build(**item) for item in captured),
            key=lambda item: item.logical_request_id,
        )
    )
    assert tuple(item.model_dump_json() for item in actual) == tuple(
        item.model_dump_json() for item in strict
    )
    assert all(
        not item.provider_dispatch_authorized
        and not item.review_credit_authorized
        and not item.coverage_credit_authorized
        and not item.completion_authorized
        and not item.release_authorized
        for item in actual
    )
    incomplete = arguments["truncation_recovery_entries"][1:]
    with pytest.raises(ValueError):
        build_scheduler_truncation_recovery_model_request_evidence(
            **{**arguments, "truncation_recovery_entries": incomplete}
        )
    for item in captured:
        with pytest.raises(ValueError):
            SchedulerTruncationRecoveryModelRequestEvidence.build(
                **{**item, "recovery_entries": incomplete}
            )
    return actual


def test_promoted_full_tree_with_retained_records_matches_strict_projection(
    promoted_tree: tuple[Any, Any, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, _token, (_source, _artifact, promotion) = promoted_tree
    journal = fixture.journal
    files = _journal_private_file_snapshot(journal.path)
    actual = _assert_strict_reference(
        {
            "manifest": journal.manifest,
            "model_requests": journal.model_requests,
            "provider_attempts": journal.provider_attempts,
            "truncation_recovery_entries": journal.truncation_recovery_entries,
        },
        monkeypatch,
    )
    assert len(actual) == 6
    assert {item.promotion_entry_sha256 for item in actual} == {promotion.entry_sha256}
    assert _journal_private_file_snapshot(journal.path) == files


@pytest.mark.parametrize("retained_count", (0, 1))
def test_specialist_recursive_inventory_matches_strict_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retained_count: int
) -> None:
    fixture = build_specialist_ancestry(
        tmp_path / "synthetic-specialist-batch-reference", retained_count=retained_count
    )
    journal = fixture.journal
    try:
        files = _journal_private_file_snapshot(journal.path)
        actual = _assert_strict_reference(
            {
                "manifest": journal.manifest,
                "model_requests": journal.model_requests,
                "provider_attempts": journal.provider_attempts,
                "truncation_recovery_entries": journal.truncation_recovery_entries,
            },
            monkeypatch,
        )
        assert len(actual) == 2
        assert {item.role for item in actual} == {"specialist:access_control"}
        assert _journal_private_file_snapshot(journal.path) == files
    finally:
        journal.close()


@pytest.mark.parametrize("with_dispatch", (False, True))
def test_released_runtime_inventory_matches_strict_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_dispatch: bool
) -> None:
    path = tmp_path / "synthetic-release-batch-reference"
    base = _released_projection(path, with_dispatch=with_dispatch)
    files = _journal_private_file_snapshot(path)
    actual = _assert_strict_reference(
        {
            "manifest": base.manifest,
            "model_requests": (base.parent_request,),
            "provider_attempts": (base.parent_attempt,),
            "truncation_recovery_entries": base.entries,
        },
        monkeypatch,
    )
    assert actual == (base.request,)
    assert _journal_private_file_snapshot(path) == files
