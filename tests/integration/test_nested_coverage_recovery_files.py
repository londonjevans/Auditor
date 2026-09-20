"""Versioned nested coverage preserves unresolved findings without granting audit credit."""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.models.truncation import CandidateReviewChannelState
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryChannel,
    TruncationRecoveryDisposition,
    TruncationRecoveryResourceBudget,
    plan_truncation_recovery,
)
from mmaudit.models.truncation_recovery_journal import SchedulerTruncationRecoveryClosureStatus
from mmaudit.models.truncation_tree import truncation_recovery_tree_inventory
from mmaudit.orchestration.scheduler import _recursive_recovery_tree_inventory
from tests.channel_retention_support import VALID_FINDING_IDS
from tests.integration.test_channel_retention_journal import (
    _assert_no_recovery_credit,
    _assert_original_resume_preserves_channels,
)
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.nested_coverage_support import complete_child, nested_coverage_case
from tests.unit.test_scheduler_journal import _journal_private_file_snapshot


@pytest.mark.parametrize(
    "state", (CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID)
)
def test_original_nested_coverage_closes_without_findings_completion_or_resume_dispatch(
    tmp_path: Path, state: CandidateReviewChannelState
) -> None:
    path = tmp_path / "original-nested-coverage"
    with nested_coverage_case(path, state) as case:
        journal = case.journal
        original_entries = tuple(e.model_dump_json() for e in journal.truncation_recovery_entries)
        original_files = _journal_private_file_snapshot(path)
        with pytest.raises(ValueError, match="nested scheduler recovery root differs"):
            journal.open_truncation_recovery_family(
                recovery_plan=case.plan,
                truncation_projection=case.projection,
                requested_surface_manifest=case.manifest,
            )
        assert _journal_private_file_snapshot(path) == original_files
        nested = journal.open_nested_coverage_recovery_family(
            recovery_plan=case.plan,
            truncation_projection=case.projection,
            requested_surface_manifest=case.manifest,
        )
        assert nested.schema_version == "1.1"
        assert nested.parent_family_id == case.root.family_id
        assert nested.truncation_projection.findings_state is state
        assert (
            tuple(f.candidate_id for f in nested.truncation_projection.findings)
            == VALID_FINDING_IDS
        )
        assert nested.recovery_plan.irreducible_channels == (TruncationRecoveryChannel.FINDINGS,)
        assert nested.recovery_plan.parent == case.plan.parent
        assert nested.request_limit_binding == case.root.request_limit_binding
        opened_files = _journal_private_file_snapshot(path)
        with pytest.raises(ValueError, match="already has a recovery family"):
            journal.open_nested_coverage_recovery_family(
                recovery_plan=case.plan,
                truncation_projection=case.projection,
                requested_surface_manifest=case.manifest,
            )
        assert _journal_private_file_snapshot(path) == opened_files
        results = tuple(
            complete_child(journal, child, case.manifest, case.surfaces)
            for child in nested.recovery_plan.children
        )
        nested_closure = journal.seal_truncation_recovery_family(nested.family_id)
        root_closure = journal.seal_truncation_recovery_family(case.root.family_id)
        assert (
            nested_closure.closure_status
            is SchedulerTruncationRecoveryClosureStatus.COVERAGE_CLOSED
        )
        assert root_closure.closure_status is (
            SchedulerTruncationRecoveryClosureStatus.RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING
        )
        assert (
            nested_closure.covered_unfinished_surface_ids == case.plan.parent.unfinished_surface_ids
        )
        assert (
            root_closure.covered_unfinished_surface_ids
            == case.root.recovery_plan.parent.unfinished_surface_ids
        )
        assert not set(nested_closure.covered_unfinished_surface_ids).intersection(
            case.plan.parent.retained_surface_ids
        )
        assert (
            tuple(
                e.model_dump_json()
                for e in journal.truncation_recovery_entries[: len(original_entries)]
            )
            == original_entries
        )
        assert sum(
            (
                Decimal(r.accounted_cost_usd_exact)
                for r in (case.bridge_result, case.leaf_result, *results)
            ),
            Decimal(0),
        ) == Decimal("0.20")
        assert case.root.recovery_plan.resources.parent_accounted_cost_usd_exact == "0.02"
        assert not nested_closure.completion_authorized
        assert not root_closure.completion_authorized
        current_files = _journal_private_file_snapshot(path)
        with pytest.raises(ValueError, match="full recovery tree lacks a complete exact family"):
            truncation_recovery_tree_inventory(
                journal.truncation_recovery_entries, root_family_id=case.root.family_id
            )
        with pytest.raises(ValueError, match="requires one bridge and one direct leaf"):
            _recursive_recovery_tree_inventory(
                family=case.root,
                closure=root_closure,
                indexes=journal._truncation_recovery_indexes,
            )
        assert _journal_private_file_snapshot(path) == current_files
        immutable_prefix = {
            name: value
            for name, value in original_files.items()
            if name.startswith("truncation-recovery/")
        }
        assert immutable_prefix
        assert all(current_files[name] == value for name, value in immutable_prefix.items())
        _assert_no_recovery_credit(journal, case.root.recovery_plan.parent.parent_task_id)
        _assert_original_resume_preserves_channels(journal, path)


@pytest.mark.parametrize(
    "state", (CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID)
)
@pytest.mark.parametrize(
    "mutation", ("closed_parent", "lower_parent_cost", "lower_prior_cost", "changed_cap")
)
def test_versioned_nested_admission_preserves_original_files_on_resource_or_ancestry_refusal(
    tmp_path: Path, state: CandidateReviewChannelState, mutation: str
) -> None:
    path = tmp_path / "original-nested-refusal"
    with nested_coverage_case(path, state) as case:
        plan = case.plan
        if mutation == "closed_parent":
            closure = case.journal.seal_truncation_recovery_family(case.root.family_id)
            assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
        else:
            resource = plan.resources
            resources = TruncationRecoveryResourceBudget.build(
                campaign_cap_usd_exact="249"
                if mutation == "changed_cap"
                else resource.campaign_cap_usd_exact,
                accounted_usd_before_parent_exact="0"
                if mutation == "lower_prior_cost"
                else resource.accounted_usd_before_parent_exact,
                parent_accounted_cost_usd_exact="0.04"
                if mutation == "lower_parent_cost"
                else resource.parent_accounted_cost_usd_exact,
                child_reserved_usd_exact=resource.child_reserved_usd_exact,
                recovery_requests_consumed=resource.recovery_requests_consumed,
                provider_attempts_before_parent=resource.provider_attempts_before_parent,
                parent_provider_attempts=resource.parent_provider_attempts,
                child_provider_attempts=resource.child_provider_attempts,
                completion_tokens_before_parent=resource.completion_tokens_before_parent,
                parent_completion_tokens=resource.parent_completion_tokens,
                child_completion_tokens=resource.child_completion_tokens,
            )
            plan = plan_truncation_recovery(parent=plan.parent, resources=resources)
            assert plan.disposition is TruncationRecoveryDisposition.PLANNED
        before = _journal_private_file_snapshot(path)
        entries = case.journal.truncation_recovery_entries
        with pytest.raises(ValueError):
            case.journal.open_nested_coverage_recovery_family(
                recovery_plan=plan,
                truncation_projection=case.projection,
                requested_surface_manifest=case.manifest,
            )
        assert _journal_private_file_snapshot(path) == before
        assert case.journal.truncation_recovery_entries == entries
        assert case.journal.truncation_recovery_families == (case.root,)
        _assert_no_recovery_credit(case.journal, case.root.recovery_plan.parent.parent_task_id)
