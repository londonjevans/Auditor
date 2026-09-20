"""Synthetic progress records cannot contradict their source slots, attempts or liabilities."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from mmaudit.models.development_tree_execution import DevelopmentTreeExecutionProgress


def progress_payload(statuses=("OBSERVED_ALL_STAGES", "REVIEW_INCOMPLETE", "PENDING")):
    counts = {
        "PENDING": 0,
        "CANDIDATE_INCOMPLETE": 1,
        "NO_CANDIDATES": 1,
        "REVIEW_INCOMPLETE": 2,
        "OBSERVED_ALL_STAGES": 3,
    }
    rows = [
        dict(
            filename=f"Source{i:03d}.sol",
            status=status,
            completed_attempt_count=counts[status],
            elapsed_seconds=float(counts[status]),
        )
        for i, status in enumerate(statuses)
    ]
    all_paths = [r["filename"] for r in rows]
    selected = [r["filename"] for r in rows if r["status"] != "PENDING"]
    successful = [
        r["filename"] for r in rows if r["status"] not in {"PENDING", "CANDIDATE_INCOMPLETE"}
    ]
    failed = [r["filename"] for r in rows if r["status"] == "CANDIDATE_INCOMPLETE"]
    all_candidates = successful == all_paths
    attempts = sum(r["completed_attempt_count"] for r in rows)
    return dict(
        tree_plan_sha256="a" * 64,
        status="OBSERVED_ALL_AVAILABLE_STAGES"
        if all(s in {"NO_CANDIDATES", "OBSERVED_ALL_STAGES"} for s in statuses)
        else "INCOMPLETE",
        primary_statuses=rows,
        coverage=dict(
            status="ALL_PRIMARY_RESPONSES_OBSERVED" if all_candidates else "INCOMPLETE",
            original_first_attempt_complete=all_candidates,
            selected_primary_paths=selected,
            original_successful_primary_paths=successful,
            successful_primary_paths=successful,
            context_paths=[],
            context_only_paths=[],
            failed_primary_paths=failed,
            missing_primary_paths=[],
            unobserved_primary_paths=failed,
            unselected_paths=[p for p in all_paths if p not in selected],
            not_successfully_observed_paths=[p for p in all_paths if p not in successful],
            invalidated_primary_paths=[],
            source_drift_paths=[],
        ),
        completed_attempt_count=attempts,
        total_accounted_cost_usd=str(Decimal(attempts) / 100),
        reported_actual_cost_usd=str(Decimal(attempts) / 100),
        uncertain_accounted_cost_usd="0",
        active_reserved_usd="0",
        elapsed_active_seconds=sum(r["elapsed_seconds"] for r in rows),
    )


def read(value):
    return DevelopmentTreeExecutionProgress.model_validate_json(json.dumps(value), strict=True)


@pytest.mark.parametrize(
    "statuses",
    [
        ("PENDING",),
        ("CANDIDATE_INCOMPLETE", "PENDING"),
        ("NO_CANDIDATES", "OBSERVED_ALL_STAGES"),
        ("OBSERVED_ALL_STAGES", "REVIEW_INCOMPLETE", "PENDING"),
        ("REVIEW_INCOMPLETE",),
    ],
)
def test_consistent_response_progress_is_never_a_validated_audit(statuses):
    value = read(progress_payload(statuses))
    assert (
        not value.audit_complete and not value.qualification_eligible and not value.release_eligible
    )
    assert read(value.model_dump(mode="json")) == value


@pytest.mark.parametrize(
    ("status", "count"),
    [
        ("PENDING", 1),
        ("CANDIDATE_INCOMPLETE", 2),
        ("NO_CANDIDATES", 0),
        ("NO_CANDIDATES", 2),
        ("REVIEW_INCOMPLETE", 0),
        ("OBSERVED_ALL_STAGES", 2),
    ],
)
def test_primary_status_cannot_disagree_with_its_number_of_actual_attempts(status, count):
    payload = progress_payload((status,))
    payload["primary_statuses"][0]["completed_attempt_count"] = count
    payload["completed_attempt_count"] = count
    with pytest.raises(ValueError):
        read(payload)


@pytest.mark.parametrize(
    "field",
    [
        "status",
        "completed_attempt_count",
        "elapsed_active_seconds",
        "total_accounted_cost_usd",
        "reported_actual_cost_usd",
        "uncertain_accounted_cost_usd",
        "active_reserved_usd",
    ],
)
def test_aggregate_progress_cannot_contradict_stages_or_accounting(field):
    payload = progress_payload()
    payload[field] = (
        "OBSERVED_ALL_AVAILABLE_STAGES"
        if field == "status"
        else payload[field] + 1
        if field in {"completed_attempt_count", "elapsed_active_seconds"}
        else str(Decimal(payload[field]) + 1)
    )
    with pytest.raises(ValueError):
        read(payload)


@pytest.mark.parametrize(
    "field",
    [
        "status",
        "original_first_attempt_complete",
        "selected_primary_paths",
        "original_successful_primary_paths",
        "successful_primary_paths",
        "context_paths",
        "context_only_paths",
        "failed_primary_paths",
        "missing_primary_paths",
        "unobserved_primary_paths",
        "unselected_paths",
        "not_successfully_observed_paths",
        "invalidated_primary_paths",
        "source_drift_paths",
    ],
)
def test_embedded_coverage_cannot_invent_or_hide_a_primary_or_source_shortfall(field):
    payload = progress_payload()
    payload["coverage"][field] = (
        "ALL_PRIMARY_RESPONSES_OBSERVED"
        if field == "status"
        else True
        if field == "original_first_attempt_complete"
        else ["Foreign.sol"]
    )
    with pytest.raises(ValueError):
        read(payload)


@pytest.mark.parametrize("change", ["duplicate", "order", "path", "pending_time"])
def test_source_slots_remain_canonical_unique_and_pending_means_no_elapsed_stage(change):
    payload = progress_payload()
    rows = payload["primary_statuses"]
    if change == "duplicate":
        rows[1]["filename"] = rows[0]["filename"]
    elif change == "order":
        rows.reverse()
    elif change == "path":
        rows[0]["filename"] = "../Source.sol"
    else:
        rows[-1]["elapsed_seconds"] = 1.0
        payload["elapsed_active_seconds"] += 1.0
    with pytest.raises(ValueError):
        read(payload)


def test_closed_unsent_failure_has_time_but_no_fabricated_attempt_or_cost():
    payload = progress_payload(("CANDIDATE_INCOMPLETE", "PENDING"))
    payload["primary_statuses"][0]["completed_attempt_count"] = 0
    payload["completed_attempt_count"] = 0
    payload["total_accounted_cost_usd"] = payload["reported_actual_cost_usd"] = "0"
    payload["coverage"]["failed_primary_paths"] = []
    payload["coverage"]["missing_primary_paths"] = ["Source000.sol"]
    result = read(payload)
    assert result.completed_attempt_count == 0 and result.elapsed_active_seconds > 0
    payload["total_accounted_cost_usd"] = payload["reported_actual_cost_usd"] = "1"
    with pytest.raises(ValueError):
        read(payload)


def test_uncertain_or_reserved_amounts_remain_separate_liabilities():
    payload = progress_payload(("CANDIDATE_INCOMPLETE",) * 3)
    payload.update(
        total_accounted_cost_usd="1.25",
        reported_actual_cost_usd="0.25",
        uncertain_accounted_cost_usd="0.5",
        active_reserved_usd="0.5",
    )
    value = read(payload)
    assert value.uncertain_accounted_cost_usd == value.active_reserved_usd == Decimal("0.5")
    assert value.status == "INCOMPLETE" and not value.audit_complete


def test_retained_response_before_interruption_is_not_discarded_or_promoted():
    payload = progress_payload(("CANDIDATE_INCOMPLETE",))
    coverage = payload["coverage"]
    coverage.update(
        status="ALL_PRIMARY_RESPONSES_OBSERVED",
        original_successful_primary_paths=["Source000.sol"],
        successful_primary_paths=["Source000.sol"],
        failed_primary_paths=[],
        unobserved_primary_paths=[],
        not_successfully_observed_paths=[],
    )
    value = read(payload)
    assert value.coverage.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
    assert not value.coverage.original_first_attempt_complete
    assert value.status == "INCOMPLETE" and not value.audit_complete


def test_later_completed_source_cannot_skip_an_earlier_pending_primary():
    with pytest.raises(ValueError, match="pending"):
        read(progress_payload(("PENDING", "NO_CANDIDATES")))


@pytest.mark.parametrize(
    ("field", "paths"),
    [
        ("selected_primary_paths", ["Source000.sol"]),
        ("original_successful_primary_paths", ["Source000.sol"]),
        ("successful_primary_paths", ["Source000.sol", "Source001.sol", "Source002.sol"]),
        ("context_only_paths", ["Source000.sol"]),
        ("failed_primary_paths", ["Source000.sol"]),
        ("missing_primary_paths", ["Source000.sol"]),
        ("unobserved_primary_paths", ["Source001.sol"]),
        ("unselected_paths", []),
        ("not_successfully_observed_paths", []),
        ("invalidated_primary_paths", ["Source000.sol"]),
        ("source_drift_paths", ["Source000.sol"]),
    ],
)
def test_in_scope_paths_cannot_be_relabelled_to_invent_credit_or_hide_pending_work(field, paths):
    payload = progress_payload()
    payload["coverage"][field] = paths
    with pytest.raises(ValueError, match="coverage"):
        read(payload)


def test_context_only_member_stays_pending_as_a_primary():
    payload = progress_payload()
    payload["coverage"]["context_paths"] = ["Source000.sol", "Source002.sol"]
    payload["coverage"]["context_only_paths"] = ["Source002.sol"]
    value = read(payload)
    assert value.primary_statuses[2].status == "PENDING"
    assert value.coverage.not_successfully_observed_paths == ("Source002.sol",)
    assert value.status == "INCOMPLETE" and not value.audit_complete


def test_aggregate_elapsed_time_preserves_grouped_floating_point_intervals():
    payload = progress_payload(("OBSERVED_ALL_STAGES", "NO_CANDIDATES"))
    payload["primary_statuses"][0]["elapsed_seconds"] = 0.1 + 0.2
    payload["primary_statuses"][1]["elapsed_seconds"] = 0.3
    payload["elapsed_active_seconds"] = 0.6
    assert read(payload).elapsed_active_seconds == 0.6
