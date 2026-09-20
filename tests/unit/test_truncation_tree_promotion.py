"""Synthetic original-journal full-tree promotion; no provider or audit qualification."""

from __future__ import annotations

import copy
import pickle
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import tests.unit.test_truncation_recovery_journal as recovery_fixture_module
import tests.unit.test_truncation_tree_evidence as tree_fixture_module
from mmaudit.models.scheduler import SchedulerPassKind, SchedulerPassStatus
from mmaudit.models.schemas import CandidateReviewBatch
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryFamilyPromotion,
    SchedulerTruncationRecoveryFullTreeBinding,
    SchedulerTruncationRecoveryPromotionBinding,
    _entry_body_sha256,
)
from mmaudit.orchestration.scheduler import (
    _full_tree_promotion_capability_binding,
    _validate_durable_recovery_promotion,
)
from mmaudit.orchestration.truncation_tree_evidence import (
    VerifiedTruncationRecoveryFullTree,
    verify_truncation_recovery_full_tree,
)
from mmaudit.orchestration.truncation_tree_promotion import (
    VerifiedJournalPromotedTruncationRecoveryTree,
    promote_truncation_recovery_full_tree,
    require_journal_promoted_truncation_recovery_tree,
)
from tests.unit.test_truncation import _candidate
from tests.unit.test_truncation_tree_evidence import LiveTreeFixture, build_live_tree


@pytest.fixture(scope="module")
def promoted_tree(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Any, Any, Any]]:
    fixture = build_live_tree(
        tmp_path_factory.mktemp("full-tree-private-promotion") / "journal",
        source_count=7,
        truncated_paths=frozenset({"0", "1"}),
        retained_count=1,
    )
    try:
        source, artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        token, promotion = promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=source
        )
        yield fixture, token, (source, artifact, promotion)
    finally:
        fixture.journal.close()


def test_original_journal_promotes_every_branch_without_issuing_live_public_credit(
    promoted_tree: tuple[Any, Any, Any],
) -> None:
    fixture, token, (_source, artifact, promotion) = promoted_tree
    readback = require_journal_promoted_truncation_recovery_tree(token)
    assert readback.promotion == promotion
    assert promotion.schema_version == "1.2"
    assert promotion.full_tree_binding is not None
    assert len(promotion.full_tree_binding.family_root_sha256s) == 3
    assert len(promotion.full_tree_binding.child_result_sha256s) == 6
    assert len(promotion.full_tree_binding.bridge_result_sha256s) == 2
    assert len(promotion.full_tree_binding.leaf_result_sha256s) == 4
    assert tuple(promotion.recovered_output.recovered_batch.surface_reviews) == artifact.records
    assert len(artifact.records) == 7
    assert artifact.accounting.other_accounted_cost_usd_exact == "0.01"
    assert promotion.recovered_output.structural_surface_artifact_sha256 == artifact.artifact_sha256
    assert len(promotion.recovered_output.scanner_fingerprints_by_request) == 7
    assert fixture.journal._truncation_recovery_entries[-1] == promotion
    binding = SchedulerTruncationRecoveryPromotionBinding.from_promotion(promotion)
    assert binding.schema_version == "1.2"
    assert not binding.review_credit_authorized
    assert fixture.journal.promoted_recursive_truncation_recovery_surface_coverages == ()


def test_promotion_data_roundtrip_is_not_append_custody(
    promoted_tree: tuple[Any, Any, Any],
) -> None:
    _fixture, token, (_source, _artifact, promotion) = promoted_tree
    decoded = SchedulerTruncationRecoveryFamilyPromotion.model_validate_json(
        promotion.model_dump_json(), strict=True
    )
    assert decoded == promotion
    with pytest.raises(ValueError):
        require_journal_promoted_truncation_recovery_tree(decoded)  # type: ignore[arg-type]
    assert require_journal_promoted_truncation_recovery_tree(token).promotion == promotion


@pytest.mark.parametrize("operation", (copy.copy, copy.deepcopy, pickle.dumps))
def test_promoted_tree_token_cannot_be_transferred(
    promoted_tree: tuple[Any, Any, Any], operation: Any
) -> None:
    with pytest.raises(TypeError):
        operation(promoted_tree[1])


def test_returned_promotion_aliases_do_not_own_durable_state(
    promoted_tree: tuple[Any, Any, Any],
) -> None:
    _fixture, token, _details = promoted_tree
    before = require_journal_promoted_truncation_recovery_tree(token).promotion.model_dump_json()
    returned = require_journal_promoted_truncation_recovery_tree(token).promotion
    returned.recovered_output.accepted_candidate_payload_sha256s["not-an-original-candidate"] = (
        "0" * 64
    )
    assert (
        require_journal_promoted_truncation_recovery_tree(token).promotion.model_dump_json()
        == before
    )


def test_forged_promotion_and_source_tokens_are_refused(
    promoted_tree: tuple[Any, Any, Any],
) -> None:
    fixture, _token, _details = promoted_tree
    with pytest.raises(TypeError):
        VerifiedJournalPromotedTruncationRecoveryTree()
    with pytest.raises(ValueError, match="absent or forged"):
        require_journal_promoted_truncation_recovery_tree(
            object.__new__(VerifiedJournalPromotedTruncationRecoveryTree)
        )
    with pytest.raises(ValueError, match="absent or forged"):
        promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=object.__new__(VerifiedTruncationRecoveryFullTree)
        )


def test_duplicate_promotion_is_refused_without_another_append(
    promoted_tree: tuple[Any, Any, Any],
) -> None:
    fixture, _token, (source, _artifact, _promotion) = promoted_tree
    before = tuple(fixture.journal._truncation_recovery_entries)
    with pytest.raises(ValueError, match="original live head"):
        promote_truncation_recovery_full_tree(journal=fixture.journal, capability=source)
    assert tuple(fixture.journal._truncation_recovery_entries) == before


@pytest.mark.parametrize("mutation", ("omit", "duplicate", "overlap", "reorder", "cross_kind"))
def test_full_tree_binding_refuses_ambiguous_partitions(
    promoted_tree: tuple[Any, Any, Any], mutation: str
) -> None:
    tree = promoted_tree[2][2].full_tree_binding
    payload = tree.model_dump(mode="python")
    if mutation == "omit":
        payload["leaf_result_sha256s"] = payload["leaf_result_sha256s"][:-1]
    elif mutation == "duplicate":
        payload["child_result_sha256s"] = (payload["child_result_sha256s"][0],) * 6
    elif mutation == "overlap":
        payload["bridge_result_sha256s"] = payload["leaf_result_sha256s"][:2]
    elif mutation == "reorder":
        payload["leaf_result_sha256s"] = tuple(reversed(payload["leaf_result_sha256s"]))
    else:
        payload["family_root_sha256s"] = payload["family_closure_sha256s"]
    with pytest.raises(ValueError):
        SchedulerTruncationRecoveryFullTreeBinding.model_validate(payload, strict=True)


def test_full_tree_promotion_cannot_follow_a_sealed_original_pass(tmp_path: Path) -> None:
    fixture: LiveTreeFixture = build_live_tree(
        tmp_path / "late", source_count=5, truncated_paths=frozenset({"0", "1"})
    )
    try:
        source, _artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        assert (
            fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW).status
            is not SchedulerPassStatus.COMPLETE
        )
        before = tuple(fixture.journal._truncation_recovery_entries)
        with pytest.raises(ValueError, match="after its pass is sealed"):
            promote_truncation_recovery_full_tree(journal=fixture.journal, capability=source)
        assert tuple(fixture.journal._truncation_recovery_entries) == before
    finally:
        fixture.journal.close()


def test_rehashed_branch_permutation_cannot_replace_original_journal_topology(
    promoted_tree: tuple[Any, Any, Any],
) -> None:
    fixture, _token, (_source, _artifact, original) = promoted_tree
    topology = original.full_tree_binding.model_dump(mode="python")
    child_hashes = list(topology["child_result_sha256s"])
    child_hashes[2], child_hashes[3] = child_hashes[3], child_hashes[2]
    topology["child_result_sha256s"] = tuple(child_hashes)
    topology["leaf_result_sha256s"] = tuple(child_hashes[2:])
    binding = SchedulerTruncationRecoveryFullTreeBinding.model_validate(topology, strict=True)
    indexes = fixture.journal._truncation_recovery_indexes
    family = indexes.families[fixture.root_family_id]
    closure = indexes.closures[fixture.root_family_id]
    payload = original.model_dump(mode="python")
    payload["full_tree_binding"] = binding
    payload["capability_binding_sha256"] = _full_tree_promotion_capability_binding(
        family=family, closure=closure, output=original.recovered_output, binding=binding
    )
    payload.pop("entry_sha256")
    payload["entry_sha256"] = _entry_body_sha256(payload)
    forged = SchedulerTruncationRecoveryFamilyPromotion.model_validate(payload, strict=True)
    with pytest.raises(ValueError, match="every original branch"):
        _validate_durable_recovery_promotion(
            promotion=forged,
            family=family,
            closure=closure,
            indexes=indexes,
            scheduler=fixture.journal._indexes,
        )


@pytest.mark.parametrize(
    ("source_count", "truncated_paths", "bridges", "leaves"),
    (
        (7, frozenset({"0", "1"}), 2, 4),
        (25, frozenset({"0", "00", "000"}), 3, 5),
    ),
    ids=("two-branches", "depth-four-retained"),
)
def test_nonempty_original_root_bridge_and_leaf_findings_keep_distinct_origins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_count: int,
    truncated_paths: frozenset[str],
    bridges: int,
    leaves: int,
) -> None:
    # All responses are synthetic. The same raw ID deliberately appears in every request.
    raw = _candidate("same-synthetic-raw-id")
    project = tree_fixture_module._projection
    parent = tree_fixture_module._typed_parent_truncation
    truncate = tree_fixture_module._truncated_custody
    complete = tree_fixture_module._success_custody

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

        # Generate the response before original synthetic ownership is bound; never edit usage.
        with monkeypatch.context() as fixture_patch:
            fixture_patch.setattr(recovery_fixture_module, "CandidateReviewBatch", response)
            return complete(**kwargs)

    monkeypatch.setattr(tree_fixture_module, "_projection", project_nonempty)
    monkeypatch.setattr(tree_fixture_module, "_typed_parent_truncation", parent_nonempty)
    monkeypatch.setattr(tree_fixture_module, "_truncated_custody", truncate_nonempty)
    monkeypatch.setattr(tree_fixture_module, "_success_custody", complete_nonempty)
    fixture = build_live_tree(
        tmp_path / "nonempty",
        source_count=source_count,
        truncated_paths=truncated_paths,
        retained_count=1,
    )
    try:
        source, artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        token, promotion = promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=source
        )
        output = promotion.recovered_output
        assert len(output.recovered_batch.findings) == 1 + bridges + leaves
        assert (
            len({item.candidate_id for item in output.recovered_batch.findings})
            == 1 + bridges + leaves
        )
        assert {item.raw_candidate_id for item in output.candidate_origins} == {raw.candidate_id}
        assert Counter(item.origin_kind.value for item in output.candidate_origins) == {
            "PARENT_FRAME": 1,
            "TRUNCATED_CHILD_FRAME": bridges,
            "CHILD_BATCH": leaves,
        }
        assert {item.request_id for item in output.candidate_origins} == {
            fixture.parent_usage.request_id,
            *(usage.request_id for usage in fixture.usages),
        }
        assert tuple(output.recovered_batch.surface_reviews) == artifact.records
        assert require_journal_promoted_truncation_recovery_tree(token).promotion == promotion
    finally:
        fixture.journal.close()
