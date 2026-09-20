"""Legacy one-level specialist recovery keeps exact outcomes and original live owners."""

from __future__ import annotations

import json
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
    SchedulerTruncationRecoveryFamilyClosure,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.orchestration.scheduler import (
    require_verified_promoted_recursive_truncation_recovery_surface_coverage,
)
from mmaudit.orchestration.truncation_recovery_evidence import (
    verify_recursive_truncation_recovery_tree,
)
from tests.unit.test_truncation_tree_evidence import LiveTreeFixture, build_live_tree


def legacy_arguments(fixture: LiveTreeFixture) -> dict[str, Any]:
    """Join original fixture objects to the unchanged one-level topology contract."""

    root, nested = fixture.journal.truncation_recovery_families
    entries = fixture.journal.truncation_recovery_entries
    closures = {
        entry.family_id: entry
        for entry in entries
        if isinstance(entry, SchedulerTruncationRecoveryFamilyClosure)
    }
    results = {
        entry.child_task_id: entry
        for entry in entries
        if isinstance(entry, SchedulerTruncationRecoveryChildResult)
    }
    root_results = tuple(results[child.child_task_id] for child in root.recovery_plan.children)
    nested_results = tuple(results[child.child_task_id] for child in nested.recovery_plan.children)
    bridge = next(
        result
        for result in root_results
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.TRUNCATED
    )
    direct = next(
        result
        for result in root_results
        if result.terminal_status is SchedulerTruncationRecoveryTerminalStatus.SUCCEEDED
    )
    originals = {
        usage.request_id: (usage, context)
        for usage, context in zip(fixture.usages, fixture.contexts, strict=True)
    }
    leaves = (direct, *nested_results)
    return {
        "root_family": root,
        "nested_family": nested,
        "root_closure": closures[root.family_id],
        "nested_closure": closures[nested.family_id],
        "root_child_results": root_results,
        "nested_child_results": nested_results,
        "parent_usage_record": fixture.parent_usage,
        "bridge_usage_record": originals[bridge.child_logical_request_id][0],
        "leaf_usage_records": tuple(originals[item.child_logical_request_id][0] for item in leaves),
        "parent_context": fixture.parent_context,
        "bridge_context": originals[bridge.child_logical_request_id][1],
        "leaf_contexts": tuple(originals[item.child_logical_request_id][1] for item in leaves),
        "requests": root.requested_surface_manifest.requests,
    }


@pytest.fixture(scope="module", params=((0, "access_control"), (1, "formal_methods_property")))
def legacy_specialist_tree(
    tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> Iterator[LiveTreeFixture]:
    retained, role = request.param
    fixture = build_live_tree(
        tmp_path_factory.mktemp(f"specialist-legacy-{retained}") / "journal",
        source_count=7,
        truncated_paths=frozenset({"0"}),
        retained_count=retained,
        request_role=f"specialist:{role}",
    )
    try:
        yield fixture
    finally:
        fixture.journal.close()


def test_legacy_specialist_verification_promotion_and_public_outcomes_agree(
    legacy_specialist_tree: LiveTreeFixture,
) -> None:
    fixture = legacy_specialist_tree
    arguments = legacy_arguments(fixture)
    assert arguments["root_closure"].schema_version == "1.2"
    assert arguments["nested_closure"].schema_version == "1.1"
    for field in ("parent_usage_record", "bridge_usage_record"):
        substituted = dict(arguments)
        substituted[field] = UsageRecord.model_validate_json(arguments[field].model_dump_json())
        with pytest.raises(ValueError, match=r"live.*custody"):
            verify_recursive_truncation_recovery_tree(**substituted)
    source, artifact = verify_recursive_truncation_recovery_tree(**arguments)
    assert artifact.accounting.family_accounted_cost_usd_exact == "0.24"
    assert not artifact.accounting.parent_cost_refunded
    before = fixture.journal.truncation_recovery_entries
    promotion = fixture.journal.promote_truncation_recovery_family(fixture.root_family_id, source)
    assert fixture.journal.truncation_recovery_entries[:-1] == before
    assert promotion.schema_version == "1.1"
    public = fixture.journal.issue_promoted_recursive_truncation_recovery_surface_coverage(
        fixture.root_family_id, source
    )
    projection = require_verified_promoted_recursive_truncation_recovery_surface_coverage(public)
    assert projection.bridge_usage_record is arguments["bridge_usage_record"]
    assert all(
        actual is original
        for actual, original in zip(
            projection.leaf_usage_records, arguments["leaf_usage_records"], strict=True
        )
    )
    requests = fixture.journal.recovery_model_requests
    assert len(requests) == 4
    assert projection.matches_requests(requests)
    assert {item.schema_version for item in requests} == {"1.4"}
    schema_path = Path(__file__).resolve().parents[2] / "schemas/scheduler_state.schema.json"
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(
        {
            "$defs": schema["$defs"],
            "$ref": "#/$defs/SchedulerTruncationRecoveryModelRequestEvidence",
        }
    )
    for item in requests:
        validator.validate(item.model_dump(mode="json"))
    leaves = [
        item for item in requests if item.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    ]
    for changes in (
        {"specialist_accepted_outcome_sha256": leaves[1].specialist_accepted_outcome_sha256},
        {
            "role": "source_audit",
            "schema_version": "1.2",
            "specialist_accepted_outcome_sha256": None,
        },
    ):
        changed = leaves[0].model_copy(update=changes)
        raw = changed.model_dump(mode="json")
        raw["request_evidence_sha256"] = scheduler_canonical_sha256(
            changed.model_dump(mode="json", exclude={"request_evidence_sha256"})
        )
        decoded = SchedulerTruncationRecoveryModelRequestEvidence.model_validate_json(
            json.dumps(raw), strict=True
        )
        assert not projection.matches_requests(
            tuple(decoded if item is leaves[0] else item for item in requests)
        )
    results = {
        entry.child_logical_request_id: entry
        for entry in before
        if isinstance(entry, SchedulerTruncationRecoveryChildResult)
    }
    for item in requests:
        assert item.specialist_accepted_outcome_sha256 == (
            results[item.logical_request_id].runtime_specialist_accepted_outcome_sha256
        )
        assert (item.specialist_accepted_outcome_sha256 is not None) == (
            item.terminal_status is SchedulerTerminalStatus.SUCCEEDED
        )
        assert not item.review_credit_authorized
        assert not item.coverage_credit_authorized
        assert not item.release_authorized
