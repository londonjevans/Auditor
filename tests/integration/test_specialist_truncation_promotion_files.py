"""Disposable specialist promotion files replay data, never serialized live authority."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.scheduler import (
    SchedulerPassKind,
    SchedulerPassStatus,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
)
from mmaudit.orchestration.scheduler import (
    _truncation_recovery_entry_path,
    require_verified_promoted_recursive_truncation_recovery_surface_coverage,
)
from mmaudit.orchestration.truncation_recovery_evidence import (
    verify_recursive_truncation_recovery_tree,
)
from mmaudit.orchestration.truncation_tree_evidence import verify_truncation_recovery_full_tree
from mmaudit.orchestration.truncation_tree_promotion import (
    issue_promoted_full_tree_surface_coverage,
    promote_truncation_recovery_full_tree,
    require_journal_promoted_truncation_recovery_tree,
)
from tests.unit.test_scheduler_journal import (
    _journal_private_file_snapshot,
    open_scheduler_journal_for_verification,
)
from tests.unit.test_specialist_truncation_legacy_live import legacy_arguments
from tests.unit.test_truncation_tree_evidence import build_live_tree


@pytest.mark.parametrize("topology", ("legacy", "full_tree"))
def test_specialist_private_replay_preserves_public_bytes_without_live_authority(
    tmp_path: Path, topology: str
) -> None:
    path = tmp_path / "specialist-private-journal"
    fixture = build_live_tree(
        path,
        source_count=7,
        truncated_paths=frozenset({"0"} if topology == "legacy" else {"0", "1"}),
        retained_count=1,
        request_role="specialist:formal_methods_property",
    )
    try:
        if topology == "legacy":
            source, _artifact = verify_recursive_truncation_recovery_tree(
                **legacy_arguments(fixture)
            )
            fixture.journal.promote_truncation_recovery_family(fixture.root_family_id, source)
            public = fixture.journal.issue_promoted_recursive_truncation_recovery_surface_coverage(
                fixture.root_family_id, source
            )
        else:
            source, _artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
            token, _promotion = promote_truncation_recovery_full_tree(
                journal=fixture.journal, capability=source
            )
            public = issue_promoted_full_tree_surface_coverage(token)
        # The required base audit is deliberately unexecuted: this is not a complete audit.
        with pytest.raises(ValueError, match="unfinished task evidence"):
            fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
        plan = next(
            plan
            for plan in fixture.journal.plans
            if plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
        )
        base_task = next(task for task in plan.tasks if task.role == "source_audit")
        fixture.journal.record_preflight_failure(
            SchedulerTaskResult.build_preflight_failure(
                plan=plan,
                task=base_task,
                terminal_status=SchedulerTerminalStatus.FAILED,
                terminal_evidence_sha256=scheduler_canonical_sha256(
                    {"synthetic_local_preflight": "base audit deliberately not executed"}
                ),
            )
        )
        result = fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
        assert result.status is not SchedulerPassStatus.COMPLETE
        serialized = fixture.journal.artifact().model_dump_json()
        requests = fixture.journal.recovery_model_requests
        assert {request.schema_version for request in requests} == {"1.4"}
        assert require_verified_promoted_recursive_truncation_recovery_surface_coverage(
            public
        ).matches_requests(requests)
        evidence = fixture.journal.journal_evidence
        manifest = fixture.journal.manifest
    finally:
        fixture.journal.close()
    with pytest.raises(ValueError):
        require_verified_promoted_recursive_truncation_recovery_surface_coverage(public)
    before = _journal_private_file_snapshot(path)
    replay = open_scheduler_journal_for_verification(
        path,
        expected_bindings=manifest.bindings,
        expected_shard_inventory=manifest.shard_inventory,
        expected_cost_ledger_baseline=manifest.cost_ledger_baseline,
        expected_privacy_evidence_custody=manifest.privacy_evidence_custody,
        expected_journal_evidence=evidence,
    )
    try:
        assert replay.artifact().model_dump_json() == serialized
        assert replay.recovery_model_requests == requests
        assert replay.promoted_recursive_truncation_recovery_surface_coverages == ()
        assert all(
            not request.review_credit_authorized for request in replay.recovery_model_requests
        )
        assert _journal_private_file_snapshot(path) == before
    finally:
        replay.close()


@pytest.mark.parametrize("change", ("bytes", "inode", "symlink"))
def test_changed_specialist_promotion_file_revokes_original_live_custody(
    tmp_path: Path, change: str
) -> None:
    path = tmp_path / "specialist-owned-journal"
    fixture = build_live_tree(
        path,
        source_count=5,
        truncated_paths=frozenset({"0", "1"}),
        request_role="specialist:false_negative_hunter",
    )
    try:
        source, _artifact = verify_truncation_recovery_full_tree(**fixture.arguments())
        token, promotion = promote_truncation_recovery_full_tree(
            journal=fixture.journal, capability=source
        )
        public = issue_promoted_full_tree_surface_coverage(token)
        target = path / _truncation_recovery_entry_path(promotion)
        original = target.read_bytes()
        if change == "bytes":
            target.write_bytes(original + b"\n")
        elif change == "inode":
            replacement = target.with_name("synthetic-identical-promotion")
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            os.replace(replacement, target)
        else:
            retained = target.with_name("synthetic-promotion-symlink-source")
            target.rename(retained)
            target.symlink_to(retained.name)
        for require, capability in (
            (require_journal_promoted_truncation_recovery_tree, token),
            (require_verified_promoted_recursive_truncation_recovery_surface_coverage, public),
        ):
            check: Any = require
            with pytest.raises(ValueError):
                check(capability)
    finally:
        fixture.journal.close()
