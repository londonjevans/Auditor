"""Specialist recursion retains exact typed custody without gaining review authority."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.scheduler import scheduler_canonical_sha256
from mmaudit.models.schemas import ModelSurfaceReviewRecord
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
    resolve_truncation_recovery_root_family,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.unit.test_truncation_recovery_journal import (
    _activate_child,
    _journal_with_truncated_parent,
    _nested_plan_for_typed_truncated_child,
    _specialist_success_outcome,
    _success_custody,
    _truncated_custody,
)


@dataclass(frozen=True)
class SpecialistAncestryFixture:
    journal: SchedulerJournal
    root: SchedulerTruncationRecoveryFamilyRoot
    nested: SchedulerTruncationRecoveryFamilyRoot
    bridge: SchedulerTruncationRecoveryChildResult
    sibling: SchedulerTruncationRecoveryChildResult
    surfaces: tuple[ModelSurfaceReviewRecord, ...]
    surface_manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest

    def arguments(self) -> dict[str, Any]:
        entries = self.journal.truncation_recovery_entries
        return {
            "family": self.nested,
            "families": {item.family_id: item for item in (self.root, self.nested)},
            "activations": {
                item.child_task_id: item
                for item in entries
                if isinstance(item, SchedulerTruncationRecoveryChildActivation)
            },
            "results": {item.child_task_id: item for item in (self.bridge, self.sibling)},
            "closures": {},
        }


def build_specialist_ancestry(
    path: Path, *, role: str = "access_control", retained_count: int = 0
) -> SpecialistAncestryFixture:
    journal, plan, projection, surfaces, manifest = _journal_with_truncated_parent(
        path,
        request_limit_maximum=5,
        typed_parent_attempt=True,
        parent_role=f"specialist:{role}",
        source_count=6 if retained_count else 4,
    )
    try:
        root = journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        bridge_child, sibling_child = plan.children
        activation = _activate_child(journal, bridge_child.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(bridge_child.child_task_id)
        usage, envelope, bridge_projection = _truncated_custody(
            child=bridge_child,
            activation=activation,
            surfaces=surfaces,
            retained_count=retained_count,
        )
        bridge = journal.record_truncation_recovery_child_truncated(
            bridge_child.child_task_id,
            failed_usage_record=usage,
            truncated_envelope_evidence=envelope,
            truncation_projection=bridge_projection,
        )
        sibling_activation = _activate_child(journal, sibling_child.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(sibling_child.child_task_id)
        custody = _success_custody(
            child=sibling_child,
            activation=sibling_activation,
            surface_manifest=manifest,
            surfaces=surfaces,
        )
        sibling = journal.record_truncation_recovery_child_success(
            sibling_child.child_task_id,
            usage_record=custody[0],
            normalization_evidence=custody[1],
            normalized_batch=custody[2],
            requested_surface_requests=custody[3],
            output_artifact=custody[4],
            specialist_accepted_outcome=_specialist_success_outcome(
                usage=custody[0], requests=custody[3], artifact=custody[4]
            ),
        )
        nested_plan = _nested_plan_for_typed_truncated_child(
            root=root,
            root_plan=plan,
            child=bridge_child,
            activation=activation,
            result=bridge,
            projection=bridge_projection,
            other_direct_results=(sibling,),
        )
        nested = journal.open_truncation_recovery_family(
            recovery_plan=nested_plan,
            truncation_projection=bridge_projection,
            requested_surface_manifest=manifest,
        )
        return SpecialistAncestryFixture(journal, root, nested, bridge, sibling, surfaces, manifest)
    except BaseException:
        journal.close()
        raise


@pytest.fixture(scope="module")
def ancestry(tmp_path_factory: pytest.TempPathFactory) -> Iterator[SpecialistAncestryFixture]:
    fixture = build_specialist_ancestry(tmp_path_factory.mktemp("specialist-ancestry") / "journal")
    try:
        yield fixture
    finally:
        fixture.journal.close()


def test_exact_specialist_ancestry_is_structural_only(ancestry: SpecialistAncestryFixture) -> None:
    before = ancestry.journal.truncation_recovery_entries
    assert resolve_truncation_recovery_root_family(**ancestry.arguments()) == ancestry.root
    assert ancestry.bridge.completed_surface_ids == ()
    assert ancestry.bridge.runtime_specialist_accepted_outcome is None
    assert ancestry.sibling.schema_version == "1.2"
    assert all(
        not item.review_credit_authorized for item in ancestry.journal.recovery_model_requests
    )
    assert ancestry.journal.truncation_recovery_entries == before


@pytest.mark.parametrize("role", ["formal_methods_property", "false_negative_hunter"])
def test_other_declared_investigators_preserve_exact_role(tmp_path: Path, role: str) -> None:
    fixture = build_specialist_ancestry(tmp_path / role, role=role)
    try:
        assert resolve_truncation_recovery_root_family(**fixture.arguments()) == fixture.root
        assert fixture.sibling.runtime_specialist_accepted_outcome is not None
        assert fixture.sibling.runtime_specialist_accepted_outcome.specialist_role == role
    finally:
        fixture.journal.close()


@pytest.mark.parametrize(
    "change",
    [
        "missing_outcome",
        "missing_hash",
        "wrong_hash",
        "generic_schema",
        "truncated_success",
        "wrong_request",
        "wrong_role",
        "wrong_specialist",
        "wrong_response",
        "wrong_context",
        "wrong_surface_count",
        "wrong_artifact",
        "missing_usage",
        "missing_output",
        "unknown_role",
        "changed_usage_role",
        "changed_usage_context",
        "changed_activation",
        "early_terminal",
    ],
)
def test_specialist_ancestry_refuses_substituted_custody_without_mutation(
    ancestry: SpecialistAncestryFixture, change: str
) -> None:
    args = ancestry.arguments()
    result = ancestry.sibling
    outcome = result.runtime_specialist_accepted_outcome
    assert outcome is not None
    updates: dict[str, Any] = {}
    if change == "missing_outcome":
        updates["runtime_specialist_accepted_outcome"] = None
    elif change in {"missing_hash", "wrong_hash"}:
        updates["runtime_specialist_accepted_outcome_sha256"] = (
            None if change == "missing_hash" else "a" * 64
        )
    elif change == "generic_schema":
        updates["schema_version"] = "1.1"
    elif change == "truncated_success":
        result = ancestry.bridge
        updates["runtime_specialist_accepted_outcome"] = outcome
        updates["runtime_specialist_accepted_outcome_sha256"] = outcome.evidence_sha256
    elif change == "missing_usage":
        updates["runtime_usage_record"] = None
    elif change == "missing_output":
        updates["runtime_output_artifact_sha256"] = None
    elif change == "unknown_role":
        for child_id, activation in args["activations"].items():
            changed = activation.model_copy(update={"request_role": "specialist:unknown_role"})
            args["activations"][child_id] = changed
            args["results"][child_id] = args["results"][child_id].model_copy(
                update={"runtime_activation": changed}
            )
        result = args["results"][result.child_task_id]
    elif change in {"changed_usage_role", "changed_usage_context"}:
        usage = result.runtime_usage_record
        assert usage is not None
        usage_updates: dict[str, Any] = (
            {"role": "specialist:false_negative_hunter"}
            if change == "changed_usage_role"
            else {"routing": {**usage.routing, "context_request_evidence_sha256": "a" * 64}}
        )
        updates["runtime_usage_record"] = usage.model_copy(update=usage_updates)
    elif change == "changed_activation":
        args["activations"].pop(result.child_task_id)
    elif change == "early_terminal":
        updates["entry_index"] = ancestry.root.entry_index
    else:
        field, value = {
            "wrong_request": ("request_id", ancestry.bridge.child_logical_request_id),
            "wrong_role": ("request_role", "specialist:false_negative_hunter"),
            "wrong_specialist": ("specialist_role", "false_negative_hunter"),
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
        updates["runtime_specialist_accepted_outcome"] = substituted
        updates["runtime_specialist_accepted_outcome_sha256"] = substituted.evidence_sha256
    args["results"][result.child_task_id] = result.model_copy(update=updates)
    before = ancestry.journal.truncation_recovery_entries
    with pytest.raises(ValueError):
        resolve_truncation_recovery_root_family(**args)
    assert ancestry.journal.truncation_recovery_entries == before
