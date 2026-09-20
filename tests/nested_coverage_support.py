"""Original synthetic parent ownership for noncrediting nested coverage recovery."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import pytest

from mmaudit.models.schemas import ModelSurfaceReviewRecord
from mmaudit.models.truncation import (
    CandidateReviewChannelState,
    CandidateReviewTruncationProjection,
)
from mmaudit.models.truncation_recovery import TruncationRecoveryChildPlan, TruncationRecoveryPlan
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryRequestedSurfaceManifest,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.channel_retention_support import channel_projection
from tests.unit import test_truncation_recovery_journal as support


@dataclass(frozen=True)
class NestedCoverageCase:
    journal: SchedulerJournal
    root: SchedulerTruncationRecoveryFamilyRoot
    plan: TruncationRecoveryPlan
    projection: CandidateReviewTruncationProjection
    bridge_result: SchedulerTruncationRecoveryChildResult
    leaf_result: SchedulerTruncationRecoveryChildResult
    surfaces: tuple[ModelSurfaceReviewRecord, ...]
    manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest


def complete_child(
    journal: SchedulerJournal,
    child: TruncationRecoveryChildPlan,
    manifest: SchedulerTruncationRecoveryRequestedSurfaceManifest,
    surfaces: tuple[ModelSurfaceReviewRecord, ...],
) -> SchedulerTruncationRecoveryChildResult:
    activation = support._activate_child(journal, child.child_task_id)
    journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
    usage, normalization, batch, requests, artifact = support._success_custody(
        child=child, activation=activation, surface_manifest=manifest, surfaces=surfaces
    )
    return journal.record_truncation_recovery_child_success(
        child.child_task_id,
        usage_record=usage,
        normalization_evidence=normalization,
        normalized_batch=batch,
        requested_surface_requests=requests,
        output_artifact=artifact,
    )


@contextmanager
def nested_coverage_case(
    path: Path,
    state: CandidateReviewChannelState,
    *,
    request_limit_maximum: int = 10,
) -> Iterator[NestedCoverageCase]:
    journal, root_plan, root_projection, surfaces, manifest = (
        support._journal_with_truncated_parent(
            path,
            typed_parent_attempt=True,
            source_count=7,
            parent_cost_usd_exact="0.02",
            request_limit_maximum=request_limit_maximum,
        )
    )
    try:
        root = journal.open_truncation_recovery_family(
            recovery_plan=root_plan,
            truncation_projection=root_projection,
            requested_surface_manifest=manifest,
        )
        bridge, leaf = root_plan.children
        activation = support._activate_child(journal, bridge.child_task_id)
        journal.mark_truncation_recovery_child_dispatched(bridge.child_task_id)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(support, "_projection", partial(channel_projection, state=state))
            usage, envelope, projection = support._truncated_custody(
                child=bridge, activation=activation, surfaces=surfaces, retained_count=1
            )
        result = journal.record_truncation_recovery_child_truncated(
            bridge.child_task_id,
            failed_usage_record=usage,
            truncated_envelope_evidence=envelope,
            truncation_projection=projection,
        )
        leaf_result = complete_child(journal, leaf, manifest, surfaces)
        plan = support._nested_plan_for_typed_truncated_child(
            root=root,
            root_plan=root_plan,
            child=bridge,
            activation=activation,
            result=result,
            projection=projection,
            other_direct_results=(leaf_result,),
        )
        yield NestedCoverageCase(
            journal, root, plan, projection, result, leaf_result, surfaces, manifest
        )
    finally:
        journal.close()
