"""Exact mixed-version ancestry cannot erase an earlier unresolved findings liability."""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal

import pytest

from mmaudit.models.truncation import CandidateReviewChannelState
from mmaudit.models.truncation_recovery import TruncationRecoveryChannel
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyClosure,
    resolve_truncation_recovery_root_family,
)
from mmaudit.models.truncation_tree import truncation_recovery_tree_inventory
from tests.channel_retention_support import VALID_FINDING_IDS
from tests.unresolved_recovery_tree_support import (
    OriginalUnresolvedTree,
    TreeScenario,
    original_unresolved_tree,
    tree_scenarios,
)


def assert_exact_unresolved_tree(tree: OriginalUnresolvedTree) -> None:
    case, journal = tree.scenario, tree.journal
    families = journal.truncation_recovery_families
    entries = journal.truncation_recovery_entries
    activations = tuple(
        e for e in entries if isinstance(e, SchedulerTruncationRecoveryChildActivation)
    )
    results = tuple(e for e in entries if isinstance(e, SchedulerTruncationRecoveryChildResult))
    closures = tuple(e for e in entries if isinstance(e, SchedulerTruncationRecoveryFamilyClosure))
    assert len(results) == len(activations) == case.expected_children
    assert len(families) == len(closures) == case.expected_children // 2
    assert max(c.depth for f in families for c in f.recovery_plan.children) == case.expected_depth
    assert tuple(e.global_request_ordinal for e in activations) == tuple(range(1, len(results) + 1))
    assert max(e.request_limit_count_after_child for e in activations) == len(results) + 1
    assert max(e.request_limit_count_after_child for e in activations) <= case.request_limit
    assert families[0].schema_version == "1.0"
    assert len(families[0].recovery_plan.parent.requested_surface_ids) == case.sources
    assert families[0].recovery_plan.resources.parent_accounted_cost_usd_exact == "0.02"
    assert sum((Decimal(r.accounted_cost_usd_exact) for r in results), Decimal(0)) == Decimal(
        "0.05"
    ) * len(results)
    result_by_task = {r.child_task_id: r for r in results}
    for family in families:
        assert family.request_limit_binding == families[0].request_limit_binding
        parent = family.recovery_plan.parent
        surfaces = [s for c in family.recovery_plan.children for s in c.surface_ids]
        assert tuple(sorted(surfaces)) == parent.unfinished_surface_ids
        assert len(surfaces) == len(set(surfaces))
        assert set(surfaces).isdisjoint(parent.retained_surface_ids)
        assert not family.completion_authorized and not family.coverage_credit_authorized
        if family.parent_family_id is None:
            continue
        bridge = result_by_task[parent.parent_task_id]
        assert family.truncation_projection == bridge.truncation_projection
        assert family.parent_terminal_result_sha256 == bridge.entry_sha256
        if family.truncation_projection.findings_state is CandidateReviewChannelState.COMPLETE:
            assert family.schema_version == "1.0"
            assert family.recovery_plan.irreducible_channels == ()
        else:
            assert family.schema_version == "1.1"
            assert family.recovery_plan.irreducible_channels == (
                TruncationRecoveryChannel.FINDINGS,
            )
            assert (
                tuple(f.candidate_id for f in family.truncation_projection.findings)
                == VALID_FINDING_IDS
            )
    for result in results:
        assert result.runtime_usage_record is not None and result.runtime_activation is not None
        usage = result.runtime_usage_record
        assert usage.role == result.runtime_activation.request_role == case.journal_role
        assert Decimal(result.accounted_cost_usd_exact) <= Decimal(result.reserved_usd_exact)
        if result.terminal_status.value == "TRUNCATED":
            projection = result.truncation_projection
            assert projection is not None and result.schema_version == "1.1"
            assert projection.findings_state is case.child_state(len(result.child_surface_ids))
            assert result.runtime_output_artifact is None
            assert result.runtime_specialist_accepted_outcome is None
            assert result.completed_surface_ids == ()
            assert result.retained_surface_ids == tuple(
                r.surface_id for r in projection.surface_reviews
            )
        else:
            assert result.terminal_status.value == "SUCCEEDED"
            assert result.completed_surface_ids == result.child_surface_ids
            outcome = result.runtime_specialist_accepted_outcome
            if case.role.startswith("specialist:"):
                assert result.schema_version == "1.2" and outcome is not None
                assert outcome.request_role == usage.role
                assert outcome.request_id == usage.request_id == result.child_logical_request_id
                assert outcome.validated_response_sha256 == usage.validated_response_sha256
                assert outcome.requested_surface_count == len(result.child_surface_ids)
                assert (
                    outcome.surface_review_artifact_sha256 == result.runtime_output_artifact_sha256
                )
                assert outcome.evidence_sha256 == result.runtime_specialist_accepted_outcome_sha256
            else:
                assert result.schema_version == "1.1" and outcome is None
    assert closures[-1].family_id == families[0].family_id
    if case.fully_covered:
        assert not tree.refusals
        assert closures[-1].closure_status.value == "RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING"
        for family, closure in zip(
            families, sorted(closures, key=lambda c: c.family_index), strict=True
        ):
            assert (
                closure.covered_unfinished_surface_ids
                == family.recovery_plan.parent.unfinished_surface_ids
            )
    else:
        assert tree.refusals and set(tree.refusals) == {"SHARED_REQUEST_EXHAUSTED"}
        assert closures[-1].closure_status.value == "INCOMPLETE"
    assert all(not c.completion_authorized and not c.coverage_credit_authorized for c in closures)
    assert not any(e.entry_kind.value == "FAMILY_PROMOTED" for e in entries)
    with pytest.raises(ValueError):
        truncation_recovery_tree_inventory(entries, root_family_id=families[0].family_id)


@pytest.mark.parametrize("case", tree_scenarios(), ids=lambda case: case.name)
def test_predeclared_tree_bounds_do_not_expand_production_limits(case: TreeScenario) -> None:
    assert case.expected_children + 1 <= case.request_limit <= 33
    assert case.expected_depth <= 4
    assert case.child_state(1) is None
    assert case.pipeline is not None


@pytest.fixture(scope="module")
def mixed_tree(tmp_path_factory: pytest.TempPathFactory) -> Iterator[OriginalUnresolvedTree]:
    case = next(c for c in tree_scenarios() if c.name == "mixed-specialist")
    with original_unresolved_tree(
        tmp_path_factory.mktemp("mixed-unresolved-unit") / "journal", case
    ) as tree:
        yield tree


def test_complete_descendants_never_resolve_ancestor_findings(
    mixed_tree: OriginalUnresolvedTree,
) -> None:
    assert_exact_unresolved_tree(mixed_tree)
    assert {f.schema_version for f in mixed_tree.journal.truncation_recovery_families} == {
        "1.0",
        "1.1",
    }
    assert {
        f.truncation_projection.findings_state
        for f in mixed_tree.journal.truncation_recovery_families
    } == {
        CandidateReviewChannelState.COMPLETE,
        CandidateReviewChannelState.OPEN,
        CandidateReviewChannelState.INVALID,
    }


@pytest.mark.parametrize(
    "mutation", ("version", "findings", "liability", "missing_sibling", "role", "closed_ancestor")
)
def test_deep_family_revalidates_every_earlier_unresolved_edge(
    mixed_tree: OriginalUnresolvedTree, mutation: str
) -> None:
    journal = mixed_tree.journal
    families = {f.family_id: f for f in journal.truncation_recovery_families}
    deepest = journal.truncation_recovery_families[-1]
    ancestor = deepest
    while ancestor.recovery_plan.parent.current_depth > 1:
        assert ancestor.parent_family_id is not None
        ancestor = families[ancestor.parent_family_id]
    assert ancestor.schema_version == "1.1"
    entries = journal.truncation_recovery_entries
    activations = {
        e.child_task_id: e
        for e in entries
        if isinstance(e, SchedulerTruncationRecoveryChildActivation)
    }
    results = {
        e.child_task_id: e for e in entries if isinstance(e, SchedulerTruncationRecoveryChildResult)
    }
    closures = {
        e.family_id: e for e in entries if isinstance(e, SchedulerTruncationRecoveryFamilyClosure)
    }
    assert (
        resolve_truncation_recovery_root_family(
            family=deepest,
            families=families,
            activations=activations,
            results=results,
            closures=closures,
        )
        == journal.truncation_recovery_families[0]
    )
    if mutation == "version":
        families[ancestor.family_id] = ancestor.model_copy(update={"schema_version": "2.0"})
    elif mutation == "findings":
        families[ancestor.family_id] = ancestor.model_copy(
            update={
                "truncation_projection": ancestor.truncation_projection.model_copy(
                    update={"findings_state": CandidateReviewChannelState.COMPLETE}
                )
            }
        )
    elif mutation == "liability":
        families[ancestor.family_id] = ancestor.model_copy(
            update={
                "recovery_plan": ancestor.recovery_plan.model_copy(
                    update={"irreducible_channels": ()}
                )
            }
        )
    elif mutation == "missing_sibling":
        results.pop(ancestor.recovery_plan.children[1].child_task_id)
    elif mutation == "role":
        child_id = ancestor.recovery_plan.children[1].child_task_id
        activations[child_id] = activations[child_id].model_copy(
            update={"request_role": "specialist:access_control"}
        )
    else:
        closures[ancestor.family_id] = closures[ancestor.family_id].model_copy(
            update={"entry_index": ancestor.entry_index}
        )
    with pytest.raises(ValueError):
        resolve_truncation_recovery_root_family(
            family=deepest,
            families=families,
            activations=activations,
            results=results,
            closures=closures,
        )
    assert journal.truncation_recovery_entries == entries
