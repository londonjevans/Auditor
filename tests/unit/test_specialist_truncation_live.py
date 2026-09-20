"""Provider-free specialist verification/promotion with original synthetic ownership."""

from __future__ import annotations

import copy
import json
import pickle
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from mmaudit.models.scheduler import (
    SchedulerTerminalStatus,
    SchedulerTruncationRecoveryModelRequestEvidence,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
)
from mmaudit.models.truncation_tree import TruncationRecoveredTreeArtifact
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    require_verified_promoted_recursive_truncation_recovery_surface_coverage,
)
from mmaudit.orchestration.truncation_tree_evidence import (
    require_verified_truncation_recovery_full_tree,
    verify_truncation_recovery_full_tree,
)
from mmaudit.orchestration.truncation_tree_promotion import (
    issue_promoted_full_tree_surface_coverage,
    promote_truncation_recovery_full_tree,
    require_journal_promoted_truncation_recovery_tree,
)
from tests.unit.test_truncation_tree_evidence import LiveTreeFixture, build_live_tree


@pytest.fixture(scope="module", params=(0, 1))
def specialist_live_tree(
    tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> Iterator[LiveTreeFixture]:
    fixture = build_live_tree(
        tmp_path_factory.mktemp(f"specialist-live-{request.param}") / "journal",
        source_count=7,
        truncated_paths=frozenset({"0", "1"}),
        retained_count=request.param,
        request_role="specialist:access_control",
    )
    try:
        yield fixture
    finally:
        fixture.journal.close()


def test_specialist_tree_verification_promotion_and_public_outcomes_agree(
    specialist_promoted_tree: tuple[Any, ...],
) -> None:
    fixture, source, artifact, token, promotion, public, requests = specialist_promoted_tree
    verified = require_verified_truncation_recovery_full_tree(source)
    assert verified.journal is fixture.journal
    assert verified.parent_usage_record is fixture.parent_usage
    assert all(
        left is right
        for left, right in zip(verified.child_usage_records, fixture.usages, strict=True)
    )
    assert artifact.accounting.tree_accounted_cost_usd_exact == "0.34"
    assert artifact.accounting.other_accounted_cost_usd_exact == "0.01"
    assert not artifact.accounting.parent_cost_refunded
    assert not artifact.scheduler_custody_verified
    assert not artifact.surface_review_credit_eligible
    assert not artifact.candidate_credit_eligible
    assert len(artifact.bridges) == 2 and len(artifact.leaves) == 4

    assert require_journal_promoted_truncation_recovery_tree(token).promotion == promotion
    projection = require_verified_promoted_recursive_truncation_recovery_surface_coverage(public)
    assert projection.parent_usage_record is fixture.parent_usage

    expected_outcomes = {
        entry.child_logical_request_id: entry.runtime_specialist_accepted_outcome_sha256
        for entry in artifact.recovery_prefix
        if isinstance(entry, SchedulerTruncationRecoveryChildResult)
    }
    assert len(requests) == 6
    assert projection.matches_requests(requests)
    assert {item.schema_version for item in requests} == {"1.4"}
    assert {item.role for item in requests} == {"specialist:access_control"}
    for item in requests:
        # Invariant: each leaf keeps its own outcome; failed bridges acquire none.
        assert item.specialist_accepted_outcome_sha256 == expected_outcomes[item.logical_request_id]
        assert (item.specialist_accepted_outcome_sha256 is not None) == (
            item.terminal_status is SchedulerTerminalStatus.SUCCEEDED
        )
        assert not item.review_credit_authorized
        assert not item.coverage_credit_authorized
        assert not item.release_authorized


@pytest.fixture(scope="module")
def specialist_promoted_tree(specialist_live_tree: LiveTreeFixture) -> tuple[Any, ...]:
    fixture = specialist_live_tree
    source, artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
    token, promotion = promote_truncation_recovery_full_tree(
        journal=fixture.journal, capability=source
    )
    public = issue_promoted_full_tree_surface_coverage(token)
    return (
        fixture,
        source,
        artifact,
        token,
        promotion,
        public,
        fixture.journal.recovery_model_requests,
    )


def test_specialist_public_wire_schema_preserves_leaf_and_bridge_contracts(
    specialist_promoted_tree: tuple[Any, ...],
) -> None:
    schema_path = Path(__file__).resolve().parents[2] / "schemas/scheduler_state.schema.json"
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(
        {
            "$defs": schema["$defs"],
            "$ref": "#/$defs/SchedulerTruncationRecoveryModelRequestEvidence",
        }
    )
    requests = specialist_promoted_tree[-1]
    for item in requests:
        wire = item.model_dump(mode="json")
        validator.validate(wire)
        for field in (
            "promotion_entry_sha256",
            "promotion_disposition",
            "global_request_ordinal",
            "recovery_family_id",
            "family_root_sha256",
            "recovery_plan_sha256",
            "family_closure_id",
            "family_closure_sha256",
        ):
            missing = dict(wire)
            del missing[field]
            assert not validator.is_valid(missing), field
        for role in ("source_audit", "specialist:unknown_role"):
            assert not validator.is_valid({**wire, "role": role})
        if item.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            missing_outcome = dict(wire)
            del missing_outcome["specialist_accepted_outcome_sha256"]
            assert not validator.is_valid(missing_outcome)
            assert not validator.is_valid({**wire, "specialist_accepted_outcome_sha256": None})
        else:
            assert not validator.is_valid({**wire, "specialist_accepted_outcome_sha256": "a" * 64})


@pytest.mark.parametrize(
    "owner", ("parent", "bridge", "leaf", "contexts", "usage_order", "journal", "missing_leaf")
)
def test_specialist_live_verification_rejects_substituted_original_owners(
    specialist_live_tree: LiveTreeFixture, owner: str
) -> None:
    fixture = specialist_live_tree
    arguments = fixture.arguments()
    if owner == "parent":
        arguments["parent_usage_record"] = UsageRecord.model_validate_json(
            fixture.parent_usage.model_dump_json()
        )
    elif owner in {"bridge", "leaf"}:
        usages = list(fixture.usages)
        index = 0 if owner == "bridge" else len(usages) - 1
        usages[index] = UsageRecord.model_validate_json(usages[index].model_dump_json())
        arguments["child_usage_records"] = tuple(usages)
    elif owner == "contexts":
        arguments["child_contexts"] = tuple(reversed(fixture.contexts))
    elif owner == "usage_order":
        arguments["child_usage_records"] = tuple(reversed(fixture.usages))
    elif owner == "missing_leaf":
        arguments["child_usage_records"] = fixture.usages[:-1]
    else:
        forged = object.__new__(SchedulerJournal)
        forged.__dict__.update(fixture.journal.__dict__)
        arguments["journal"] = forged
    before = fixture.journal.truncation_recovery_entries
    with pytest.raises(ValueError):
        verify_truncation_recovery_full_tree(**arguments)
    assert fixture.journal.truncation_recovery_entries == before


@pytest.mark.parametrize(
    "succeeded,field,value",
    (
        (True, "schema_version", "1.2"),
        (False, "schema_version", "1.2"),
        (True, "schema_version", "1.1"),
        (False, "schema_version", "1.3"),
        (True, "specialist_accepted_outcome_sha256", None),
        (False, "specialist_accepted_outcome_sha256", "1" * 64),
        (True, "role", "source_audit"),
        (False, "role", "specialist:unknown_synthetic_role"),
        (True, "family_closure_sha256", None),
        (True, "global_request_ordinal", None),
        (False, "terminal_status", "SUCCEEDED"),
        (True, "terminal_status", "TRUNCATED"),
        (True, "provider_dispatch_authorized", True),
        (True, "review_credit_authorized", True),
        (False, "coverage_credit_authorized", True),
        (True, "completion_authorized", True),
        (False, "release_authorized", True),
    ),
)
def test_public_specialist_recursive_variant_refuses_rehashed_shape_substitutions(
    specialist_promoted_tree: tuple[Any, ...], succeeded: bool, field: str, value: Any
) -> None:
    request = next(
        item
        for item in specialist_promoted_tree[-1]
        if (item.terminal_status is SchedulerTerminalStatus.SUCCEEDED) == succeeded
    )
    original_body = request.model_dump(mode="json", exclude={"request_evidence_sha256"})
    assert scheduler_canonical_sha256(original_body) == request.request_evidence_sha256
    altered = request.model_copy(update={field: value})
    raw = altered.model_dump(mode="json", warnings=False)
    # Rehash the altered projection: a digest mismatch must not be the only refusal.
    body = altered.model_dump(mode="json", exclude={"request_evidence_sha256"}, warnings=False)
    raw["request_evidence_sha256"] = scheduler_canonical_sha256(body)
    with pytest.raises(ValueError):
        SchedulerTruncationRecoveryModelRequestEvidence.model_validate_json(
            json.dumps(raw), strict=True
        )


@pytest.mark.parametrize("operation", (copy.copy, copy.deepcopy, pickle.dumps))
def test_specialist_recursive_tokens_remain_nontransferable(
    specialist_promoted_tree: tuple[Any, ...], operation: Any
) -> None:
    for token in (
        specialist_promoted_tree[1],
        specialist_promoted_tree[3],
        specialist_promoted_tree[5],
    ):
        with pytest.raises(TypeError):
            operation(token)


@pytest.mark.parametrize(
    "field",
    (
        "specialist_accepted_outcome_sha256",
        "family_closure_sha256",
        "promotion_entry_sha256",
        "role",
    ),
)
def test_well_formed_public_specialist_substitutions_do_not_match_original_promotion(
    specialist_promoted_tree: tuple[Any, ...], field: str
) -> None:
    *_, public, requests = specialist_promoted_tree
    leaves = [
        item for item in requests if item.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    ]
    target = leaves[0]
    substituted = (
        leaves[1].specialist_accepted_outcome_sha256
        if field == "specialist_accepted_outcome_sha256"
        else "f" * 64
    )
    assert getattr(target, field) != substituted
    changes = (
        {
            "role": "source_audit",
            "schema_version": "1.2",
            "specialist_accepted_outcome_sha256": None,
        }
        if field == "role"
        else {field: substituted}
    )
    altered = target.model_copy(update=changes)
    raw = altered.model_dump(mode="json")
    raw["request_evidence_sha256"] = scheduler_canonical_sha256(
        altered.model_dump(mode="json", exclude={"request_evidence_sha256"})
    )
    decoded = SchedulerTruncationRecoveryModelRequestEvidence.model_validate_json(
        json.dumps(raw), strict=True
    )
    projection = require_verified_promoted_recursive_truncation_recovery_surface_coverage(public)
    assert projection.matches_requests(requests)
    assert not projection.matches_requests(
        tuple(decoded if item is target else item for item in requests)
    )


def test_complete_specialist_artifact_roundtrip_is_comparison_only(
    specialist_promoted_tree: tuple[Any, ...],
) -> None:
    artifact = specialist_promoted_tree[2]
    decoded = TruncationRecoveredTreeArtifact.model_validate_json(
        artifact.model_dump_json(), strict=True
    )
    assert decoded == artifact
    with pytest.raises(ValueError, match="absent or forged"):
        require_verified_truncation_recovery_full_tree(decoded)  # type: ignore[arg-type]


def test_deeper_known_specialist_tree_promotes_all_original_leaves(tmp_path: Path) -> None:
    fixture = build_live_tree(
        tmp_path / "deeper-specialist-journal",
        source_count=17,
        truncated_paths=frozenset({"0", "00"}),
        retained_count=1,
        request_role="specialist:false_negative_hunter",
    )
    try:
        source, artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        assert max(leaf.child_plan.depth for leaf in artifact.leaves) == 3
        token, promotion = promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=source
        )
        assert promotion.full_tree_binding is not None
        assert len(promotion.full_tree_binding.leaf_result_sha256s) == 4
        public = issue_promoted_full_tree_surface_coverage(token)
        projection = require_verified_promoted_recursive_truncation_recovery_surface_coverage(
            public
        )
        assert projection.matches_requests(fixture.journal.recovery_model_requests)
    finally:
        fixture.journal.close()
