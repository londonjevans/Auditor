"""Recovered findings must reach report reconstruction only through original promotion."""

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest

from mmaudit.models.scheduler import (
    SchedulerPassKind,
    SchedulerPassStatus,
    SchedulerTerminalStatus,
    scheduler_candidate_payload_sha256,
)
from mmaudit.models.schemas import CandidateFinding
from mmaudit.models.truncation_recovery_journal import (
    SchedulerRecoveredCandidateOrigin,
    SchedulerRecoveredCandidateReviewOutput,
    SchedulerTruncationRecoveryFamilyPromotion,
)
from mmaudit.orchestration import manifest
from mmaudit.orchestration.scheduler import _full_tree_promotion_capability_binding
from mmaudit.orchestration.truncation_tree_evidence import verify_truncation_recovery_full_tree
from mmaudit.orchestration.truncation_tree_promotion import (
    issue_promoted_full_tree_surface_coverage,
    promote_truncation_recovery_full_tree,
)
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.truncation_tree_candidate_support import build_nonempty_candidate_tree
from tests.unit.test_truncation_tree_evidence import LiveTreeFixture


@pytest.fixture(scope="module")
def candidate_tree(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Any, ...]]:
    with pytest.MonkeyPatch.context() as patch:
        fixture = build_nonempty_candidate_tree(
            tmp_path_factory.mktemp("candidate-report") / "journal", patch
        )
    try:
        source, _artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        private, promotion = promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=source
        )
        public = issue_promoted_full_tree_surface_coverage(private)
        result = fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
        assert result.status is SchedulerPassStatus.COMPLETE and public is not None
        yield fixture, promotion
    finally:
        fixture.journal.close()


def _candidates(fixture: LiveTreeFixture) -> dict[str, CandidateFinding]:
    _hashes, candidates = manifest._scheduler_accepted_candidate_authority(
        manifest._scheduler_report_authority_snapshot(fixture.journal),
        trusted_scanner_fingerprints=frozenset(),
    )
    return candidates[SchedulerPassKind.BLIND_SHARD_REVIEW]


def test_original_promoted_parent_bridge_and_leaf_candidates_survive_report_reconstruction(
    candidate_tree: tuple[Any, ...],
) -> None:
    fixture, promotion = candidate_tree
    expected = {
        candidate.candidate_id: candidate
        for candidate in promotion.recovered_output.recovered_batch.findings
    }
    assert len(expected) == 7
    hashes, candidates = manifest._scheduler_accepted_candidate_authority(
        manifest._scheduler_report_authority_snapshot(fixture.journal),
        trusted_scanner_fingerprints=frozenset(),
    )
    # Named invariant: no original promoted candidate disappears at report reconstruction.
    assert candidates[SchedulerPassKind.BLIND_SHARD_REVIEW] == expected
    assert hashes[SchedulerPassKind.BLIND_SHARD_REVIEW] == (
        manifest._scheduler_candidate_payload_sha256s(
            expected.values(), algorithm_version=fixture.journal.manifest.algorithm_version
        )
    )
    original = fixture.journal.task_results[-1]
    assert any(
        result.terminal_status is SchedulerTerminalStatus.TRUNCATED
        for result in fixture.journal.task_results
    )
    assert fixture.journal.task_results[-1] == original


@pytest.mark.parametrize(
    "field", ("pass_plan_id", "campaign_id", "result_sha256", "missing_binding", "binding_output")
)
def test_recovered_candidates_require_the_original_sealed_pass_and_terminal_result(
    candidate_tree: tuple[Any, ...], field: str
) -> None:
    fixture, _promotion = candidate_tree
    snapshot = manifest._scheduler_report_authority_snapshot(fixture.journal)
    blind = snapshot.pass_results_by_kind[SchedulerPassKind.BLIND_SHARD_REVIEW]
    if field in {"missing_binding", "binding_output"}:
        altered = blind.model_copy(
            update={
                "recovery_promotion_bindings": ()
                if field == "missing_binding"
                else tuple(
                    item.model_copy(update={"recovered_output_artifact_sha256": "0" * 64})
                    for item in blind.recovery_promotion_bindings
                )
            }
        )
    elif field == "result_sha256":
        altered = blind.model_copy(
            update={
                "task_results": tuple(
                    result.model_copy(update={field: "0" * 64}) for result in blind.task_results
                )
            }
        )
    else:
        plan = blind.plan.model_copy(
            update={field: "different-pass"}
            if field == "pass_plan_id"
            else {"manifest": blind.plan.manifest.model_copy(update={field: "different-campaign"})}
        )
        altered = blind.model_copy(update={"plan": plan})
    changed = replace(
        snapshot,
        pass_results_by_kind={
            **snapshot.pass_results_by_kind,
            SchedulerPassKind.BLIND_SHARD_REVIEW: altered,
        },
    )
    with pytest.raises(ValueError, match="original blind task result"):
        manifest._scheduler_accepted_candidate_authority(
            changed, trusted_scanner_fingerprints=frozenset()
        )
    assert len(_candidates(fixture)) == 7


def test_returned_recovered_candidates_cannot_mutate_original_journal_content(
    candidate_tree: tuple[Any, ...],
) -> None:
    fixture, promotion = candidate_tree
    observed = _candidates(fixture)
    first = next(iter(observed.values()))
    first.title = "Mutated comparison only"
    fresh = _candidates(fixture)
    assert fresh[first.candidate_id].title != first.title
    assert tuple(fresh.values()) == tuple(promotion.recovered_output.recovered_batch.findings)


def test_recovered_candidates_cannot_be_counted_twice_in_a_pass_snapshot(
    candidate_tree: tuple[Any, ...],
) -> None:
    fixture, _promotion = candidate_tree
    snapshot = manifest._scheduler_report_authority_snapshot(fixture.journal)
    blind = snapshot.pass_results_by_kind[SchedulerPassKind.BLIND_SHARD_REVIEW]
    changed = replace(
        snapshot,
        pass_results_by_kind={
            **snapshot.pass_results_by_kind,
            SchedulerPassKind.BLIND_SHARD_REVIEW: blind.model_copy(
                update={"task_results": (*blind.task_results, *blind.task_results)}
            ),
        },
    )
    with pytest.raises(ValueError, match="repeats an identity"):
        manifest._scheduler_accepted_candidate_authority(
            changed, trusted_scanner_fingerprints=frozenset()
        )
    assert len(_candidates(fixture)) == 7


def test_data_only_journal_cannot_supply_recovered_candidate_authority(
    candidate_tree: tuple[Any, ...],
) -> None:
    fixture, _promotion = candidate_tree
    snapshot = manifest._scheduler_report_authority_snapshot(fixture.journal)
    with pytest.raises(ValueError, match="original journal custody"):
        manifest._scheduler_accepted_candidate_authority(
            replace(snapshot, journal=object()), trusted_scanner_fingerprints=frozenset()
        )


@pytest.mark.parametrize("mutation", ("payload", "origin", "omit"))
def test_original_reader_refuses_coherently_rehashed_recovery_substitutions(
    candidate_tree: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    fixture, original = candidate_tree
    journal = fixture.journal
    output = original.recovered_output
    candidates = list(output.recovered_batch.findings)
    origins = list(output.candidate_origins)
    if mutation == "omit":
        candidates.pop(0)
        origins.pop(0)
    else:
        origin_values = origins[0].model_dump(mode="python", exclude={"origin_sha256"})
        if mutation == "payload":
            candidates[0] = candidates[0].model_copy(
                update={"title": "Substituted synthetic claim"}
            )
            origin_values["accepted_candidate_sha256"] = scheduler_candidate_payload_sha256(
                candidates[0], algorithm_version=journal.manifest.algorithm_version
            )
        else:
            origin_values["raw_candidate_sha256"] = "0" * 64
        origins[0] = SchedulerRecoveredCandidateOrigin.build(**origin_values)
    changed = SchedulerRecoveredCandidateReviewOutput.build(
        **{
            name: getattr(output, name)
            for name in (
                "campaign_id",
                "pass_plan_id",
                "parent_task_id",
                "parent_logical_request_id",
                "parent_activation_sha256",
                "original_truncated_result_sha256",
                "parent_provider_attempt_sha256",
                "recovery_family_id",
                "family_root_sha256",
                "family_closure_sha256",
                "structural_surface_artifact_sha256",
                "scanner_fingerprints_by_request",
                "delivered_source_descriptor_sha256s",
            )
        },
        recovered_batch=output.recovered_batch.model_copy(update={"findings": candidates}),
        candidate_origins=tuple(origins),
        recursive_tree=True,
        algorithm_version=journal.manifest.algorithm_version,
    )
    indexes = journal._truncation_recovery_indexes
    family = indexes.families[fixture.root_family_id]
    closure = indexes.closures[fixture.root_family_id]
    substituted = SchedulerTruncationRecoveryFamilyPromotion.build(
        family=family,
        closure=closure,
        direct_child_result_sha256s=original.direct_child_result_sha256s,
        recovered_output=changed,
        entry_index=original.entry_index,
        previous_entry_sha256=original.previous_entry_sha256,
        full_tree_binding=original.full_tree_binding,
        capability_binding_sha256=_full_tree_promotion_capability_binding(
            family=family,
            closure=closure,
            output=changed,
            binding=original.full_tree_binding,
        ),
    )
    with monkeypatch.context() as patch:
        patch.setitem(indexes.promotions, fixture.root_family_id, substituted)
        # Named invariant: fresh self-hashes cannot replace original frames or host stamping.
        with pytest.raises(ValueError):
            journal.recovered_candidate_review_output_for_task(original.parent_task_id)
    assert len(_candidates(fixture)) == 7


def test_unpromoted_truncation_does_not_gain_candidate_authority(
    candidate_tree: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture, promotion = candidate_tree
    snapshot = manifest._scheduler_report_authority_snapshot(fixture.journal)
    blind = snapshot.pass_results_by_kind[SchedulerPassKind.BLIND_SHARD_REVIEW]
    changed = replace(
        snapshot,
        pass_results_by_kind={
            **snapshot.pass_results_by_kind,
            SchedulerPassKind.BLIND_SHARD_REVIEW: blind.model_copy(
                update={"recovery_promotion_bindings": ()}
            ),
        },
    )
    with monkeypatch.context() as patch:
        patch.delitem(
            fixture.journal._truncation_recovery_indexes.promotion_by_parent_task,
            promotion.parent_task_id,
        )
        hashes, candidates = manifest._scheduler_accepted_candidate_authority(
            changed, trusted_scanner_fingerprints=frozenset()
        )
        assert not hashes[SchedulerPassKind.BLIND_SHARD_REVIEW]
        assert not candidates[SchedulerPassKind.BLIND_SHARD_REVIEW]
    assert len(_candidates(fixture)) == 7
