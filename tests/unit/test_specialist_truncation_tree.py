"""Synthetic specialist tree membership retains outcomes without promotion authority."""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models import truncation_tree as tree_models
from mmaudit.models.scheduler import scheduler_canonical_sha256
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.models.truncation_tree import (
    TruncationRecoveredTreeArtifact,
    _generic_truncation_recovery_tree_inventory,
    truncation_recovery_tree_inventory,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from mmaudit.orchestration.truncation_tree_evidence import (
    require_verified_truncation_recovery_full_tree,
)
from mmaudit.orchestration.truncation_tree_promotion import (
    require_journal_promoted_truncation_recovery_tree,
)
from tests.unit.test_generic_truncation_tree import _build_tree
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot


@pytest.mark.parametrize(
    "role", ("access_control", "formal_methods_property", "false_negative_hunter")
)
def test_exact_known_specialist_leaves_enter_only_structural_inventory(
    tmp_path: Path, role: str
) -> None:
    path = tmp_path / "synthetic-specialist-tree"
    journal, refusals = _build_tree(path, source_count=3, parent_role=f"specialist:{role}")
    try:
        assert refusals == ()
        entries = journal.truncation_recovery_entries
        root = journal.truncation_recovery_families[0]
        before = _journal_private_file_snapshot(path)
        tree = truncation_recovery_tree_inventory(entries, root_family_id=root.family_id)
        assert tree.families == (root,)
        assert len(tree.results) == 2
        for result in tree.results:
            outcome = result.runtime_specialist_accepted_outcome
            assert result.schema_version == "1.2"
            assert outcome is not None
            assert outcome.specialist_role == role
            assert outcome.request_role == f"specialist:{role}"
            assert outcome.request_id == result.child_logical_request_id
            assert result.runtime_specialist_accepted_outcome_sha256 == outcome.evidence_sha256
            assert not result.review_credit_authorized
            assert not result.coverage_credit_authorized
        assert not tree.closures[0].completion_authorized
        assert _journal_private_file_snapshot(path) == before
    finally:
        journal.close()


@pytest.fixture(scope="module", params=(0, 1), ids=("unretained", "retained"))
def specialist_tree(
    tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> Iterator[SchedulerJournal]:
    retained_count = int(request.param)
    journal, refusals = _build_tree(
        tmp_path_factory.mktemp("specialist-full-tree") / "journal",
        source_count=13 if retained_count else 9,
        retained_count=retained_count,
        truncated_paths=frozenset({"0", "1", "00"}),
        parent_role="specialist:access_control",
    )
    try:
        assert refusals == ()
        yield journal
    finally:
        journal.close()


def test_multiple_and_deeper_branches_keep_outcome_owners_and_failed_costs(
    specialist_tree: SchedulerJournal,
) -> None:
    journal = specialist_tree
    entries = journal.truncation_recovery_entries
    root = journal.truncation_recovery_families[0]
    before = _journal_private_file_snapshot(journal.path)
    tree = truncation_recovery_tree_inventory(entries, root_family_id=root.family_id)
    assert len(tree.families) == len(tree.closures) == 4
    assert len(tree.results) == 8
    assert max(child.depth for child in tree.children) == 3
    assert [result.global_request_ordinal for result in tree.results] == list(range(1, 9))
    assert sum(Decimal(result.accounted_cost_usd_exact) for result in tree.results) == Decimal(
        "0.4"
    )
    assert sum(result.accounted_provider_attempts for result in tree.results) == 8
    assert sum(result.accounted_completion_tokens for result in tree.results) == 80
    assert tree.closures[0].schema_version == "1.3"
    assert (
        tree.closures[0].covered_unfinished_surface_ids
        == root.recovery_plan.parent.unfinished_surface_ids
    )
    for result in tree.results:
        usage = result.runtime_usage_record
        activation = result.runtime_activation
        assert usage is not None and activation is not None
        assert (
            usage.role
            == activation.request_role
            == root.request_limit_binding.parent_request_limit_reservation.role
        )
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
            assert result.schema_version == "1.1"
            assert result.completed_surface_ids == ()
            assert result.runtime_specialist_accepted_outcome is None
            assert result.runtime_specialist_accepted_outcome_sha256 is None
            descendants = [
                family
                for family in tree.families
                if family.recovery_plan.parent.parent_task_id == result.child_task_id
            ]
            assert len(descendants) == 1
            assert set(result.retained_surface_ids).isdisjoint(
                descendants[0].recovery_plan.parent.unfinished_surface_ids
            )
        else:
            outcome = result.runtime_specialist_accepted_outcome
            assert outcome is not None
            assert result.schema_version == "1.2"
            assert outcome.request_id == usage.request_id == result.child_logical_request_id
            assert outcome.validated_response_sha256 == usage.validated_response_sha256
            assert outcome.surface_review_artifact_sha256 == result.runtime_output_artifact_sha256
            assert outcome.requested_surface_count == len(result.child_surface_ids)
        assert not result.review_credit_authorized
        assert not result.coverage_credit_authorized
    assert not any(
        isinstance(entry, SchedulerTruncationRecoveryFamilyPromotion) for entry in entries
    )
    assert _journal_private_file_snapshot(journal.path) == before


@pytest.mark.parametrize(
    "change",
    (
        "missing_outcome",
        "missing_hash",
        "wrong_hash",
        "generic_success_schema",
        "outcome_on_truncated_bridge",
        "wrong_request",
        "wrong_response",
        "wrong_context",
        "wrong_surface_count",
        "wrong_artifact",
        "missing_usage",
        "missing_activation",
        "substituted_usage_role",
        "substituted_context",
    ),
)
def test_deep_specialist_leaf_substitutions_refuse_without_rewriting_journal(
    specialist_tree: SchedulerJournal, change: str
) -> None:
    journal = specialist_tree
    entries = journal.truncation_recovery_entries
    root = journal.truncation_recovery_families[0]
    results = [
        entry for entry in entries if isinstance(entry, SchedulerTruncationRecoveryChildResult)
    ]
    deep_ids = {
        child.child_task_id
        for family in journal.truncation_recovery_families
        for child in family.recovery_plan.children
        if child.depth == 3
    }
    target = next(
        result
        for result in results
        if result.child_task_id in deep_ids
        and result.runtime_specialist_accepted_outcome is not None
    )
    outcome = target.runtime_specialist_accepted_outcome
    assert outcome is not None
    updates: dict[str, Any] = {}
    if change == "missing_outcome":
        updates["runtime_specialist_accepted_outcome"] = None
    elif change in {"missing_hash", "wrong_hash"}:
        updates["runtime_specialist_accepted_outcome_sha256"] = (
            None if change == "missing_hash" else "a" * 64
        )
    elif change == "generic_success_schema":
        updates["schema_version"] = "1.1"
    elif change == "outcome_on_truncated_bridge":
        target = next(
            result
            for result in results
            if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
        )
        updates.update(
            runtime_specialist_accepted_outcome=outcome,
            runtime_specialist_accepted_outcome_sha256=outcome.evidence_sha256,
        )
    elif change == "missing_usage":
        updates["runtime_usage_record"] = None
    elif change == "missing_activation":
        updates["runtime_activation"] = None
    elif change in {"substituted_usage_role", "substituted_context"}:
        usage = target.runtime_usage_record
        assert usage is not None
        usage_updates = (
            {"role": "specialist:false_negative_hunter"}
            if change == "substituted_usage_role"
            else {"routing": {**usage.routing, "context_request_evidence_sha256": "a" * 64}}
        )
        updates["runtime_usage_record"] = usage.model_copy(update=usage_updates)
    else:
        field, value = {
            "wrong_request": ("request_id", results[0].child_logical_request_id),
            "wrong_response": ("validated_response_sha256", "a" * 64),
            "wrong_context": ("context_request_evidence_sha256", "a" * 64),
            "wrong_surface_count": ("requested_surface_count", outcome.requested_surface_count + 1),
            "wrong_artifact": ("surface_review_artifact_sha256", "a" * 64),
        }[change]
        values = {**outcome.model_dump(mode="python"), field: value}
        values.pop("evidence_sha256")
        substituted = outcome.model_copy(
            update={field: value, "evidence_sha256": scheduler_canonical_sha256(values)}
        )
        updates.update(
            runtime_specialist_accepted_outcome=substituted,
            runtime_specialist_accepted_outcome_sha256=substituted.evidence_sha256,
        )
    changed = tuple(
        target.model_copy(update=updates) if entry is target else entry for entry in entries
    )
    before = _journal_private_file_snapshot(journal.path)
    with pytest.raises(ValueError):
        truncation_recovery_tree_inventory(changed, root_family_id=root.family_id)
    assert _journal_private_file_snapshot(journal.path) == before


@pytest.mark.parametrize("other_role", ("false_negative_hunter", "unknown_role"))
def test_inventory_role_join_remains_independent_of_typed_entry_validation(
    specialist_tree: SchedulerJournal, monkeypatch: pytest.MonkeyPatch, other_role: str
) -> None:
    entries = specialist_tree.truncation_recovery_entries
    root = specialist_tree.truncation_recovery_families[0]
    deep_ids = {
        child.child_task_id
        for family in specialist_tree.truncation_recovery_families
        for child in family.recovery_plan.children
        if child.depth == 3
    }
    target = next(
        entry
        for entry in entries
        if isinstance(entry, SchedulerTruncationRecoveryChildResult)
        and entry.child_task_id in deep_ids
        and entry.runtime_specialist_accepted_outcome is not None
    )
    activation = target.runtime_activation
    assert activation is not None
    different = activation.model_copy(update={"request_role": f"specialist:{other_role}"})
    changed = tuple(
        different
        if entry == activation
        else target.model_copy(update={"runtime_activation": different})
        if entry is target
        else entry
        for entry in entries
    )
    # Isolate the inventory's root-role join; unmocked invalid-entry tests above cover parsing.
    monkeypatch.setattr(
        tree_models, "validate_truncation_recovery_entry_chain", lambda values: tuple(values)
    )
    with pytest.raises(ValueError, match="role-bound typed child custody"):
        truncation_recovery_tree_inventory(changed, root_family_id=root.family_id)


def test_unknown_root_specialist_role_cannot_enter_structural_tree(
    specialist_tree: SchedulerJournal, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = specialist_tree.truncation_recovery_entries
    root = specialist_tree.truncation_recovery_families[0]
    binding = root.request_limit_binding
    unknown = root.model_copy(
        update={
            "request_limit_binding": binding.model_copy(
                update={
                    "parent_request_limit_reservation": binding.parent_request_limit_reservation.model_copy(
                        update={"role": "specialist:unknown_role"}
                    )
                }
            )
        }
    )
    changed = tuple(unknown if entry == root else entry for entry in entries)
    # Independently exercise role admission; the full unmocked parser also rejects this input.
    with pytest.raises(ValueError):
        truncation_recovery_tree_inventory(changed, root_family_id=root.family_id)
    monkeypatch.setattr(
        tree_models, "validate_truncation_recovery_entry_chain", lambda values: tuple(values)
    )
    with pytest.raises(ValueError, match="known specialist investigator role"):
        truncation_recovery_tree_inventory(changed, root_family_id=root.family_id)


def test_specialist_membership_does_not_widen_generic_evidence_or_promotion(
    specialist_tree: SchedulerJournal,
) -> None:
    entries = specialist_tree.truncation_recovery_entries
    root = specialist_tree.truncation_recovery_families[0]
    with pytest.raises(ValueError, match="generic typed child custody"):
        _generic_truncation_recovery_tree_inventory(entries, root_family_id=root.family_id)
    # Role-aware structural evidence still cannot stand in for original live custody.
    artifact = TruncationRecoveredTreeArtifact.model_construct(
        recovery_prefix=entries, root_family_id=root.family_id
    )
    with pytest.raises(ValueError, match="absent or forged"):
        require_verified_truncation_recovery_full_tree(artifact)  # type: ignore[arg-type]
    promotion = SchedulerTruncationRecoveryFamilyPromotion.model_construct(
        family_id=root.family_id, family_closure_sha256=entries[-1].entry_sha256
    )
    with pytest.raises(ValueError, match="absent or forged"):
        require_journal_promoted_truncation_recovery_tree(promotion)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "failure",
    (
        SchedulerTruncationRecoveryTerminalStatus.FAILED,
        SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN,
    ),
)
def test_failed_or_uncertain_specialist_child_blocks_complete_tree(
    tmp_path: Path, failure: SchedulerTruncationRecoveryTerminalStatus
) -> None:
    journal, refusals = _build_tree(
        tmp_path / "synthetic-incomplete-specialist",
        source_count=3,
        parent_role="specialist:access_control",
        failed_path="0",
        failure=failure,
    )
    try:
        assert refusals == ()
        entries = journal.truncation_recovery_entries
        results = [
            entry for entry in entries if isinstance(entry, SchedulerTruncationRecoveryChildResult)
        ]
        failed = next(result for result in results if result.terminal_status is failure)
        child = next(
            child
            for child in journal.truncation_recovery_families[0].recovery_plan.children
            if child.child_task_id == failed.child_task_id
        )
        assert failed.accounted_cost_usd_exact == child.reserved_usd_exact
        assert failed.accounted_provider_attempts == child.reserved_provider_attempts
        assert failed.runtime_specialist_accepted_outcome is None
        assert not entries[-1].completion_authorized
        before = _journal_private_file_snapshot(journal.path)
        with pytest.raises(ValueError):
            truncation_recovery_tree_inventory(
                entries, root_family_id=journal.truncation_recovery_families[0].family_id
            )
        assert _journal_private_file_snapshot(journal.path) == before
    finally:
        journal.close()


def test_shared_parent_request_ceiling_still_bounds_specialist_tree(tmp_path: Path) -> None:
    journal, refusals = _build_tree(
        tmp_path / "synthetic-specialist-request-bound",
        source_count=9,
        request_limit=5,
        parent_role="specialist:access_control",
        truncated_paths=frozenset({"0", "1", "00"}),
    )
    try:
        assert refusals and set(refusals) == {"SHARED_REQUEST_EXHAUSTED"}
        assert len(journal.truncation_recovery_families) == 2
        entries = journal.truncation_recovery_entries
        results = [
            entry for entry in entries if isinstance(entry, SchedulerTruncationRecoveryChildResult)
        ]
        assert len(results) == 4
        assert sum(Decimal(result.accounted_cost_usd_exact) for result in results) == Decimal("0.2")
        assert isinstance(entries[-1], SchedulerTruncationRecoveryFamilyClosure)
        assert entries[-1].closure_status is SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
        assert not entries[-1].completion_authorized
        with pytest.raises(ValueError):
            truncation_recovery_tree_inventory(
                entries, root_family_id=journal.truncation_recovery_families[0].family_id
            )
    finally:
        journal.close()
