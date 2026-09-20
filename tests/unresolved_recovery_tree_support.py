"""Predeclared synthetic mixed-version trees built through the original journal owner."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from mmaudit.models.truncation import CandidateReviewChannelState
from mmaudit.models.truncation_recovery import TruncationRecoveryDisposition
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryTerminalStatus,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from tests.channel_retention_support import channel_projection
from tests.unit import test_truncation_recovery_journal as support
from tests.unit.test_generic_truncation_tree import _nested_plan


class TreeScenario(BaseModel):
    """Fixture coordinates are data, never permission to contact a provider."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    name: str
    role: Literal[
        "whole_protocol_review:0", "specialist:access_control", "specialist:false_negative_hunter"
    ]
    sources: int = Field(ge=5, le=33)
    pattern: Literal["OPEN", "INVALID", "MIXED"]
    request_limit: int = Field(ge=3, le=33)
    expected_children: int = Field(ge=2, le=30)
    expected_depth: int = Field(ge=1, le=4)
    fully_covered: bool
    pipeline: bool

    @property
    def journal_role(self) -> str:
        """The original generic journal fixture is shard-scoped, not whole-protocol scoped."""

        return self.role if self.role.startswith("specialist:") else "source_audit"

    def child_state(self, surface_count: int) -> CandidateReviewChannelState | None:
        """Select deliberately truncated fixture responses, not production retry policy."""

        assert type(surface_count) is int and 1 <= surface_count < self.sources
        if surface_count == 1:
            return None
        if self.pattern == "OPEN":
            return CandidateReviewChannelState.OPEN
        if self.pattern == "INVALID":
            return CandidateReviewChannelState.INVALID if surface_count > 2 else None
        if surface_count == 2:
            return None
        states = {
            16: CandidateReviewChannelState.OPEN,
            8: CandidateReviewChannelState.COMPLETE,
            4: CandidateReviewChannelState.INVALID,
        }
        assert surface_count in states, "mixed fixture received an undeclared surface shape"
        return states[surface_count]


def tree_scenarios() -> tuple[TreeScenario, ...]:
    path = Path(__file__).parent / "fixtures/unresolved_recovery_tree/cases.json"
    raw = path.read_bytes()
    assert len(raw) < 16_384
    cases = TypeAdapter(tuple[TreeScenario, ...]).validate_json(raw, strict=True)
    assert len(cases) == 6 and len({case.name for case in cases}) == 6
    return cases


@dataclass(frozen=True)
class OriginalUnresolvedTree:
    scenario: TreeScenario
    journal: SchedulerJournal
    refusals: tuple[str, ...]


@contextmanager
def original_unresolved_tree(
    path: Path, scenario: TreeScenario
) -> Iterator[OriginalUnresolvedTree]:
    journal, plan, projection, surfaces, manifest = support._journal_with_truncated_parent(
        path,
        typed_parent_attempt=True,
        source_count=scenario.sources,
        parent_cost_usd_exact="0.02",
        request_limit_maximum=scenario.request_limit,
        parent_role=scenario.role if scenario.role.startswith("specialist:") else None,
    )
    refusals: list[str] = []

    def finish(family: SchedulerTruncationRecoveryFamilyRoot) -> None:
        terminals: dict[str, SchedulerTruncationRecoveryChildResult] = {}
        for child in family.recovery_plan.children:
            activation = support._activate_child(journal, child.child_task_id)
            journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
            state = scenario.child_state(len(child.surface_ids))
            if state is not None:
                with pytest.MonkeyPatch.context() as patch:
                    if state is not CandidateReviewChannelState.COMPLETE:
                        patch.setattr(
                            support, "_projection", partial(channel_projection, state=state)
                        )
                    usage, envelope, child_projection = support._truncated_custody(
                        child=child,
                        activation=activation,
                        surfaces=surfaces,
                        retained_count=int(state is CandidateReviewChannelState.INVALID),
                    )
                terminal = journal.record_truncation_recovery_child_truncated(
                    child.child_task_id,
                    failed_usage_record=usage,
                    truncated_envelope_evidence=envelope,
                    truncation_projection=child_projection,
                )
            else:
                usage, normalization, batch, requests, artifact = support._success_custody(
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
                        support._specialist_success_outcome(
                            usage=usage, requests=requests, artifact=artifact
                        )
                        if scenario.role.startswith("specialist:")
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
            open_family = (
                journal.open_truncation_recovery_family
                if terminal.truncation_projection.findings_state
                is CandidateReviewChannelState.COMPLETE
                else journal.open_nested_coverage_recovery_family
            )
            before = journal.truncation_recovery_entries
            try:
                nested = open_family(
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
        root = journal.open_truncation_recovery_family(
            recovery_plan=plan,
            truncation_projection=projection,
            requested_surface_manifest=manifest,
        )
        finish(root)
        yield OriginalUnresolvedTree(scenario, journal, tuple(refusals))
    finally:
        journal.close()
