"""Synthetic bounded-tree ancestry, complete partition, accounting and replay invariants."""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.models.scheduler import build_scheduler_truncation_recovery_model_request_evidence
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryChildPlan,
    TruncationRecoveryDisposition,
    TruncationRecoveryParentBinding,
    TruncationRecoveryPlan,
    TruncationRecoveryResourceBudget,
    plan_truncation_recovery,
)
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryClosureStatus,
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryTerminalStatus,
    rebuild_truncation_recovery_parent_from_projection,
    resolve_truncation_recovery_root_family,
)
from mmaudit.orchestration.scheduler import SchedulerJournal, resume_scheduler_journal
from tests.unit.test_truncation_recovery_journal import (
    _activate_child,
    _bindings,
    _digest,
    _inventory,
    _journal_with_truncated_parent,
    _placeholder_channels,
    _reseal_recovery_chain,
    _specialist_success_outcome,
    _success_custody,
    _truncated_custody,
)


def _usd(value: Decimal) -> str:
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _nested_plan(
    journal: SchedulerJournal,
    family: SchedulerTruncationRecoveryFamilyRoot,
    child: TruncationRecoveryChildPlan,
    result: SchedulerTruncationRecoveryChildResult,
) -> TruncationRecoveryPlan:
    projection = result.truncation_projection
    activation = result.runtime_activation
    assert projection is not None and activation is not None
    assert result.provider_attempt_evidence_sha256 is not None
    claimed = TruncationRecoveryParentBinding.build(
        campaign_id=child.campaign_id,
        pass_plan_id=child.pass_plan_id,
        parent_task_id=child.child_task_id,
        parent_logical_request_id=child.child_logical_request_id,
        parent_task_plan_sha256=child.child_plan_sha256,
        parent_activation_sha256=activation.entry_sha256,
        provider_attempt_evidence_sha256=result.provider_attempt_evidence_sha256,
        truncation_projection_sha256=projection.evidence_sha256,
        requested_surface_manifest_sha256=child.requested_surface_manifest_sha256,
        requested_surface_ids=child.surface_ids,
        retained_surface_ids=result.retained_surface_ids,
        channel_bindings=_placeholder_channels(projection),
        current_depth=child.depth,
        parent_path=child.path,
    )
    root_resources = journal.truncation_recovery_families[0].recovery_plan.resources
    prior = tuple(
        entry
        for entry in journal.truncation_recovery_entries
        if isinstance(entry, SchedulerTruncationRecoveryChildResult)
        and entry.child_task_id != child.child_task_id
    )
    resources = TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact=root_resources.campaign_cap_usd_exact,
        accounted_usd_before_parent_exact=_usd(
            Decimal(root_resources.accounted_usd_before_parent_exact)
            + Decimal(root_resources.parent_accounted_cost_usd_exact)
            + sum((Decimal(entry.accounted_cost_usd_exact) for entry in prior), Decimal("0"))
        ),
        parent_accounted_cost_usd_exact=result.accounted_cost_usd_exact,
        child_reserved_usd_exact=family.recovery_plan.resources.child_reserved_usd_exact,
        recovery_requests_consumed=sum(
            len(item.recovery_plan.children) for item in journal.truncation_recovery_families
        ),
        provider_attempts_before_parent=(
            root_resources.provider_attempts_before_parent
            + root_resources.parent_provider_attempts
            + sum(entry.accounted_provider_attempts for entry in prior)
        ),
        parent_provider_attempts=result.accounted_provider_attempts,
        child_provider_attempts=family.recovery_plan.resources.child_provider_attempts,
        completion_tokens_before_parent=(
            root_resources.completion_tokens_before_parent
            + root_resources.parent_completion_tokens
            + sum(entry.accounted_completion_tokens for entry in prior)
        ),
        parent_completion_tokens=result.accounted_completion_tokens,
        child_completion_tokens=family.recovery_plan.resources.child_completion_tokens,
    )
    return plan_truncation_recovery(
        parent=rebuild_truncation_recovery_parent_from_projection(
            claimed_parent=claimed, projection=projection
        ),
        resources=resources,
    )


def _build_tree(
    path: Path,
    *,
    source_count: int = 17,
    retained_count: int = 0,
    request_limit: int = 33,
    failed_path: str | None = None,
    truncated_paths: frozenset[str] | None = None,
    parent_role: str | None = None,
    failure: SchedulerTruncationRecoveryTerminalStatus = SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN,
) -> tuple[SchedulerJournal, tuple[str, ...]]:
    journal, plan, projection, surfaces, manifest = _journal_with_truncated_parent(
        path,
        typed_parent_attempt=True,
        request_limit_maximum=request_limit,
        source_count=source_count,
        parent_role=parent_role,
    )
    root = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=projection,
        requested_surface_manifest=manifest,
    )
    refusals: list[str] = []

    def finish(family: SchedulerTruncationRecoveryFamilyRoot) -> None:
        terminals: dict[str, SchedulerTruncationRecoveryChildResult] = {}
        for child in family.recovery_plan.children:
            activation = _activate_child(journal, child.child_task_id)
            dispatch = journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
            if child.path == failed_path:
                terminal = SchedulerTruncationRecoveryChildResult.build_runtime(
                    child=child,
                    dispatch=dispatch,
                    terminal_status=failure,
                    terminal_evidence_sha256=_digest("synthetic incomplete descendant"),
                    provider_attempt_evidence_sha256=_digest("synthetic uncertain attempt"),
                    accounted_provider_attempts=child.reserved_provider_attempts,
                    accounted_completion_tokens=child.reserved_completion_tokens,
                    accounted_cost_usd_exact=child.reserved_usd_exact,
                    entry_index=len(journal.truncation_recovery_entries),
                    previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
                )
                journal.record_truncation_recovery_child_result(terminal)
            elif len(child.surface_ids) > 1 + retained_count and (
                truncated_paths is None or child.path in truncated_paths
            ):
                usage, envelope, child_projection = _truncated_custody(
                    child=child,
                    activation=activation,
                    surfaces=surfaces,
                    retained_count=retained_count,
                )
                terminal = journal.record_truncation_recovery_child_truncated(
                    child.child_task_id,
                    failed_usage_record=usage,
                    truncated_envelope_evidence=envelope,
                    truncation_projection=child_projection,
                )
            else:
                usage, normalization, batch, requests, artifact = _success_custody(
                    child=child, activation=activation, surface_manifest=manifest, surfaces=surfaces
                )
                terminal = journal.record_truncation_recovery_child_success(
                    child.child_task_id,
                    usage_record=usage,
                    normalization_evidence=normalization,
                    normalized_batch=batch,
                    requested_surface_requests=requests,
                    output_artifact=artifact,
                    specialist_accepted_outcome=(
                        _specialist_success_outcome(
                            usage=usage, requests=requests, artifact=artifact
                        )
                        if parent_role is not None and parent_role.startswith("specialist:")
                        else None
                    ),
                )
            terminals[child.child_task_id] = terminal
        for child in family.recovery_plan.children:
            terminal = terminals[child.child_task_id]
            if terminal.terminal_status is not SchedulerTruncationRecoveryTerminalStatus.TRUNCATED:
                continue
            nested_plan = _nested_plan(journal, family, child, terminal)
            if nested_plan.disposition is not TruncationRecoveryDisposition.PLANNED:
                refusals.append(nested_plan.disposition.value)
                continue
            assert terminal.truncation_projection is not None
            before = journal.truncation_recovery_entries
            try:
                nested = journal.open_truncation_recovery_family(
                    recovery_plan=nested_plan,
                    truncation_projection=terminal.truncation_projection,
                    requested_surface_manifest=manifest,
                )
            except ValueError as exc:
                assert journal.truncation_recovery_entries == before
                if "exceeds its parent request limit" not in str(exc):
                    raise
                refusals.append("SHARED_REQUEST_EXHAUSTED")
            else:
                finish(nested)
        journal.seal_truncation_recovery_family(family.family_id)

    try:
        finish(root)
    except BaseException:
        journal.close()
        raise
    return journal, tuple(refusals)


@pytest.fixture(scope="module")
def complete_tree(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SchedulerJournal]:
    journal, refusals = _build_tree(tmp_path_factory.mktemp("generic-tree") / "journal")
    assert refusals == ()
    try:
        yield journal
    finally:
        journal.close()


def test_all_depth_four_branches_close_with_exact_attempt_ordinals(
    complete_tree: SchedulerJournal,
) -> None:
    journal = complete_tree
    families = journal.truncation_recovery_families
    entries = journal.truncation_recovery_entries
    results = tuple(e for e in entries if isinstance(e, SchedulerTruncationRecoveryChildResult))
    activations = tuple(
        e for e in entries if isinstance(e, SchedulerTruncationRecoveryChildActivation)
    )
    closures = tuple(e for e in entries if isinstance(e, SchedulerTruncationRecoveryFamilyClosure))
    assert len(families) == len(closures) == 15
    assert len(results) == 30
    assert max(child.depth for family in families for child in family.recovery_plan.children) == 4
    assert tuple(e.global_request_ordinal for e in activations) == tuple(range(1, 31))
    assert tuple(e.request_limit_count_before_child for e in activations) == tuple(range(1, 31))
    assert families[-1].request_count_after_family == 30
    assert families[-1].request_limit_count_after_family == 31
    assert sum(Decimal(e.accounted_cost_usd_exact) for e in results) == Decimal("1.5")
    assert sum(e.accounted_provider_attempts for e in results) == 30
    assert sum(e.accounted_completion_tokens for e in results) == 300
    closure_by_id = {e.family_id: e for e in closures}
    for family in families:
        closure = closure_by_id[family.family_id]
        assert (
            closure.covered_unfinished_surface_ids
            == family.recovery_plan.parent.unfinished_surface_ids
        )
        children = tuple(f for f in families if f.parent_family_id == family.family_id)
        if children:
            assert closure.schema_version == "1.3"
            assert len(closure.nested_family_closure_sha256s) == 2
            assert all(
                closure_by_id[f.family_id].entry_index < closure.entry_index for f in children
            )
        else:
            assert closure.schema_version == "1.1"
        assert not closure.coverage_credit_authorized
        assert not closure.completion_authorized
    assert closures[-1].family_id == families[0].family_id
    assert not any(e.entry_kind.value == "FAMILY_PROMOTED" for e in entries)


def test_public_replay_retains_every_deeper_attempt_without_credit(
    complete_tree: SchedulerJournal,
) -> None:
    public = complete_tree.recovery_model_requests
    assert len(public) == 30
    assert len({item.logical_request_id for item in public}) == 30
    assert all(item.promotion_entry_sha256 is None for item in public)
    assert all(
        not item.review_credit_authorized and not item.coverage_credit_authorized for item in public
    )
    assert complete_tree.artifact().recovery_model_requests == public


def test_structural_tree_cannot_masquerade_as_live_promotion(
    complete_tree: SchedulerJournal,
) -> None:
    before = complete_tree.truncation_recovery_entries
    root = complete_tree.truncation_recovery_families[0]
    with pytest.raises(ValueError):
        complete_tree.promote_truncation_recovery_family(
            root.family_id,
            before[-1],  # type: ignore[arg-type]
        )
    assert complete_tree.truncation_recovery_entries == before


@pytest.mark.parametrize("mutation", ("omit_descendant", "duplicate_family", "close_root_early"))
def test_public_replay_refuses_broken_tree_custody(
    complete_tree: SchedulerJournal, mutation: str
) -> None:
    entries = complete_tree.truncation_recovery_entries
    families = complete_tree.truncation_recovery_families
    if mutation == "omit_descendant":
        changed = tuple(e for e in entries if e != families[-1])
    elif mutation == "duplicate_family":
        changed = (*entries, families[-1])
    else:
        changed = (entries[0], entries[-1], *entries[1:-1])
    forged = _reseal_recovery_chain(changed)
    with pytest.raises(ValueError):
        build_scheduler_truncation_recovery_model_request_evidence(
            manifest=complete_tree.manifest,
            model_requests=complete_tree.model_requests,
            provider_attempts=complete_tree.provider_attempts,
            truncation_recovery_entries=forged,
        )


def test_retained_records_do_not_reappear_in_descendant_work(tmp_path: Path) -> None:
    journal, refusals = _build_tree(tmp_path / "retained", retained_count=1)
    try:
        assert refusals == ()
        families = journal.truncation_recovery_families
        assert len(families) == 7
        for family in families:
            retained = set(family.recovery_plan.parent.retained_surface_ids)
            unfinished = [
                surface for child in family.recovery_plan.children for surface in child.surface_ids
            ]
            assert retained.isdisjoint(unfinished)
            assert len(unfinished) == len(set(unfinished))
            assert sorted(unfinished) == list(family.recovery_plan.parent.unfinished_surface_ids)
        assert journal.truncation_recovery_entries[-1].schema_version == "1.3"
        assert len(journal.recovery_model_requests) == 14
    finally:
        journal.close()


def test_depth_four_refusal_preserves_all_charges_and_no_coverage(tmp_path: Path) -> None:
    journal, refusals = _build_tree(tmp_path / "depth-bound", source_count=33)
    try:
        assert refusals == ("DEPTH_EXHAUSTED",) * 16
        assert len(journal.truncation_recovery_families) == 15
        results = [
            e
            for e in journal.truncation_recovery_entries
            if isinstance(e, SchedulerTruncationRecoveryChildResult)
        ]
        assert len(results) == 30
        assert sum(Decimal(e.accounted_cost_usd_exact) for e in results) == Decimal("1.5")
        assert all(
            e.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
            for e in results
        )
        closure = journal.truncation_recovery_entries[-1]
        assert isinstance(closure, SchedulerTruncationRecoveryFamilyClosure)
        assert closure.closure_status is SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
        assert closure.covered_unfinished_surface_ids == ()
        assert len(journal.recovery_model_requests) == 30
    finally:
        journal.close()


def test_original_shared_request_limit_refuses_next_whole_family(tmp_path: Path) -> None:
    journal, refusals = _build_tree(tmp_path / "request-bound", request_limit=5)
    try:
        assert refusals == ("SHARED_REQUEST_EXHAUSTED",) * 3
        assert len(journal.truncation_recovery_families) == 2
        results = [
            e
            for e in journal.truncation_recovery_entries
            if isinstance(e, SchedulerTruncationRecoveryChildResult)
        ]
        assert len(results) == 4
        assert sum(Decimal(e.accounted_cost_usd_exact) for e in results) == Decimal("0.2")
        assert (
            journal.truncation_recovery_entries[-1].closure_status
            is SchedulerTruncationRecoveryClosureStatus.INCOMPLETE
        )
        assert len(journal.recovery_model_requests) == 4
    finally:
        journal.close()


@pytest.mark.parametrize(
    ("failure", "expected"),
    (
        (
            SchedulerTruncationRecoveryTerminalStatus.UNCERTAIN,
            SchedulerTruncationRecoveryClosureStatus.UNCERTAIN,
        ),
        (
            SchedulerTruncationRecoveryTerminalStatus.FAILED,
            SchedulerTruncationRecoveryClosureStatus.INCOMPLETE,
        ),
    ),
)
def test_descendant_liability_propagates_without_ancestor_credit(
    tmp_path: Path,
    failure: SchedulerTruncationRecoveryTerminalStatus,
    expected: SchedulerTruncationRecoveryClosureStatus,
) -> None:
    journal, refusals = _build_tree(
        tmp_path / failure.value, source_count=9, failed_path="000", failure=failure
    )
    try:
        assert refusals == ()
        assert journal.truncation_recovery_entries[-1].closure_status is expected
        assert not any(
            e.entry_kind.value == "FAMILY_PROMOTED" for e in journal.truncation_recovery_entries
        )
        assert len(journal.recovery_model_requests) == 13
    finally:
        journal.close()


def test_deeper_tree_resume_has_no_dispatchable_or_rewritten_work(tmp_path: Path) -> None:
    path = tmp_path / "resumed"
    journal, refusals = _build_tree(path, source_count=9)
    assert refusals == ()
    entries = journal.truncation_recovery_entries
    evidence = journal.journal_evidence
    requests = journal.recovery_model_requests
    analysis_inputs = journal.analysis_input_inventory
    journal.close()
    resumed = resume_scheduler_journal(
        path,
        expected_bindings=_bindings(),
        expected_shard_inventory=_inventory(),
        expected_analysis_input_inventory=analysis_inputs,
        expected_journal_evidence=evidence,
    )
    try:
        assert resumed.truncation_recovery_entries == entries
        assert resumed.recovery_model_requests == requests
        assert resumed.dispatchable_truncation_recovery_child_ids == ()
        assert resumed.uncertain_truncation_recovery_child_ids == ()
    finally:
        resumed.close()


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_parent",
        "missing_sibling_result",
        "missing_sibling_activation",
        "reparent_to_root",
        "closed_ancestor",
    ),
)
def test_every_deep_ancestry_edge_requires_exact_prior_custody(
    complete_tree: SchedulerJournal, mutation: str
) -> None:
    entries = complete_tree.truncation_recovery_entries
    families = {item.family_id: item for item in complete_tree.truncation_recovery_families}
    activations = {
        item.child_task_id: item
        for item in entries
        if isinstance(item, SchedulerTruncationRecoveryChildActivation)
    }
    results = {
        item.child_task_id: item
        for item in entries
        if isinstance(item, SchedulerTruncationRecoveryChildResult)
    }
    closures = {
        item.family_id: item
        for item in entries
        if isinstance(item, SchedulerTruncationRecoveryFamilyClosure)
    }
    root = complete_tree.truncation_recovery_families[0]
    family = next(
        item for item in families.values() if item.recovery_plan.parent.current_depth == 3
    )
    assert family.parent_family_id is not None
    immediate = families[family.parent_family_id]
    sibling = next(
        child
        for child in immediate.recovery_plan.children
        if child.child_task_id != family.recovery_plan.parent.parent_task_id
    )
    if mutation == "missing_parent":
        families.pop(immediate.family_id)
    elif mutation == "missing_sibling_result":
        results.pop(sibling.child_task_id)
    elif mutation == "missing_sibling_activation":
        activations.pop(sibling.child_task_id)
    elif mutation == "reparent_to_root":
        family = SchedulerTruncationRecoveryFamilyRoot.build(
            request_limit_binding=family.request_limit_binding,
            family_index=family.family_index,
            parent_kind=family.parent_kind,
            parent_family_id=root.family_id,
            parent_terminal_result_sha256=family.parent_terminal_result_sha256,
            requested_surface_manifest=family.requested_surface_manifest,
            truncation_projection=family.truncation_projection,
            recovery_plan=family.recovery_plan,
            request_count_before_family=family.request_count_before_family,
            request_limit_count_before_family=family.request_limit_count_before_family,
            entry_index=family.entry_index,
            previous_entry_sha256=family.previous_entry_sha256,
        )
    else:
        closure = closures[root.family_id]
        closures[root.family_id] = SchedulerTruncationRecoveryFamilyClosure.build(
            family=root,
            closure_status=closure.closure_status,
            child_result_sha256s=closure.child_result_sha256s,
            nested_family_closure_sha256s=closure.nested_family_closure_sha256s,
            covered_unfinished_surface_ids=closure.covered_unfinished_surface_ids,
            entry_index=family.entry_index - 1,
            previous_entry_sha256=closure.previous_entry_sha256,
            recursive_schema_version="1.3",
        )
    with pytest.raises(ValueError):
        resolve_truncation_recovery_root_family(
            family=family,
            families=families,
            activations=activations,
            results=results,
            closures=closures,
        )


def test_single_deep_branch_cannot_downgrade_to_five_request_closure(tmp_path: Path) -> None:
    journal, refusals = _build_tree(
        tmp_path / "deep-single-branch", truncated_paths=frozenset({"0", "00", "000"})
    )
    try:
        assert refusals == ()
        assert len(journal.truncation_recovery_families) == 4
        entries = journal.truncation_recovery_entries
        root = journal.truncation_recovery_families[0]
        closure = entries[-1]
        assert isinstance(closure, SchedulerTruncationRecoveryFamilyClosure)
        assert closure.schema_version == "1.3"
        assert len(closure.nested_family_closure_sha256s) == 1
        assert len(journal.recovery_model_requests) == 8
        downgraded = SchedulerTruncationRecoveryFamilyClosure.build(
            family=root,
            closure_status=closure.closure_status,
            child_result_sha256s=closure.child_result_sha256s,
            nested_family_closure_sha256s=closure.nested_family_closure_sha256s,
            covered_unfinished_surface_ids=closure.covered_unfinished_surface_ids,
            entry_index=closure.entry_index,
            previous_entry_sha256=closure.previous_entry_sha256,
            recursive_schema_version="1.2",
        )
        # This is a valid old data model with a freshly calculated hash, not a damaged JSON file.
        assert downgraded.schema_version == "1.2"
        with pytest.raises(ValueError):
            build_scheduler_truncation_recovery_model_request_evidence(
                manifest=journal.manifest,
                model_requests=journal.model_requests,
                provider_attempts=journal.provider_attempts,
                truncation_recovery_entries=(*entries[:-1], downgraded),
            )
    finally:
        journal.close()
