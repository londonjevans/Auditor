"""Fail-closed severity accounting for execution-origin findings."""

from __future__ import annotations

from mmaudit.models.schemas import (
    CandidateOriginKind,
    FindingStatus,
    ReproductionResolutionKind,
    Severity,
)
from mmaudit.orchestration.consensus import group_candidates, merge_group
from mmaudit.orchestration.pipeline import _enforce_post_judge_execution_severity_accounting
from mmaudit.orchestration.reproduction_resolution import (
    build_candidate_reproduction_resolutions,
)
from tests.unit.test_execution_origin_consensus import (
    _execution_candidate,
    _judge,
    _model_candidate,
    _provenance,
    _validation,
)


def test_post_judge_high_execution_origin_fails_closed_and_enters_accounting() -> None:
    candidate = _execution_candidate(_provenance(), severity=Severity.INFORMATIONAL)
    group = group_candidates([candidate])[0]
    judge = _judge(
        group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.CRITICAL,
    )
    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: _validation(valid=True, marker="a")},
        scanner_findings=[],
        judge=judge,
    )

    # Reproduce the old bypass: judgment alone could turn the informational
    # execution observation into a confirmed critical finding after all
    # high/critical accounting phases had already run.
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.severity is Severity.CRITICAL

    gated, accounting_candidates, limitation = _enforce_post_judge_execution_severity_accounting(
        group=group,
        finding=finding,
        judge=judge,
        pre_judgment_high_critical_ids=set(),
        status_bearing_candidate_ids=frozenset({candidate.candidate_id}),
    )

    assert gated.severity is Severity.CRITICAL
    assert gated.status is FindingStatus.NEEDS_REVIEW
    assert limitation is not None
    assert limitation in gated.disagreement
    assert len(accounting_candidates) == 1
    accounting_candidate = accounting_candidates[0]
    assert accounting_candidate.candidate_id == candidate.candidate_id
    assert accounting_candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
    assert accounting_candidate.severity is Severity.INFORMATIONAL
    assert accounting_candidate.execution_provenance == candidate.execution_provenance
    assert accounting_candidate.locations == candidate.locations
    assert accounting_candidate.model_dump(mode="json") == candidate.model_dump(mode="json")

    resolutions = build_candidate_reproduction_resolutions(
        candidates=list(accounting_candidates),
        results=[],
        forced_candidate_ids={candidate.candidate_id},
    )
    assert len(resolutions) == 1
    assert resolutions[0].candidate_id == candidate.candidate_id
    assert resolutions[0].kind is ReproductionResolutionKind.INCONCLUSIVE


def test_post_judge_gate_preserves_preclassified_high_execution_finding() -> None:
    candidate = _execution_candidate(_provenance(), severity=Severity.HIGH)
    group = group_candidates([candidate])[0]
    judge = _judge(
        group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.CRITICAL,
    )
    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: _validation(valid=True, marker="a")},
        scanner_findings=[],
        judge=judge,
    )

    gated, accounting_candidates, limitation = _enforce_post_judge_execution_severity_accounting(
        group=group,
        finding=finding,
        judge=judge,
        pre_judgment_high_critical_ids={candidate.candidate_id},
        status_bearing_candidate_ids=frozenset({candidate.candidate_id}),
    )

    assert gated == finding
    assert accounting_candidates == ()
    assert limitation is None


def test_high_model_peer_does_not_satisfy_execution_candidate_obligation() -> None:
    execution = _execution_candidate(_provenance(), severity=Severity.INFORMATIONAL)
    model_peer = _model_candidate(
        candidate_id="model-high-impact-peer",
        locations=execution.locations,
        severity=Severity.HIGH,
        execution_candidate=execution,
    )
    groups = group_candidates([execution, model_peer])
    assert len(groups) == 1
    group = groups[0]
    judge = _judge(
        group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.CRITICAL,
    )
    finding = merge_group(
        group,
        decisions={},
        validations={
            execution.candidate_id: _validation(valid=True, marker="a"),
            model_peer.candidate_id: _validation(valid=True, marker="b"),
        },
        scanner_findings=[],
        judge=judge,
    )

    gated, accounting_candidates, limitation = _enforce_post_judge_execution_severity_accounting(
        group=group,
        finding=finding,
        judge=judge,
        pre_judgment_high_critical_ids={model_peer.candidate_id},
        status_bearing_candidate_ids=frozenset({execution.candidate_id}),
    )

    assert gated.status is FindingStatus.NEEDS_REVIEW
    assert accounting_candidates == (execution,)
    assert limitation is not None
    assert execution.candidate_id in limitation
    assert model_peer.candidate_id not in limitation


def test_post_judge_gate_does_not_fail_low_impact_analysis() -> None:
    candidate = _execution_candidate(_provenance(), severity=Severity.INFORMATIONAL)
    group = group_candidates([candidate])[0]
    judge = _judge(
        group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.LOW,
    )
    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: _validation(valid=True, marker="a")},
        scanner_findings=[],
        judge=judge,
    )

    gated, accounting_candidates, limitation = _enforce_post_judge_execution_severity_accounting(
        group=group,
        finding=finding,
        judge=judge,
        pre_judgment_high_critical_ids=set(),
        status_bearing_candidate_ids=frozenset({candidate.candidate_id}),
    )

    assert gated == finding
    assert accounting_candidates == ()
    assert limitation is None


def test_post_judge_high_model_origin_enters_fail_closed_accounting() -> None:
    candidate = _model_candidate(
        candidate_id="model-medium-before-judgment",
        locations=_execution_candidate(_provenance()).locations,
        severity=Severity.MEDIUM,
    )
    group = group_candidates([candidate])[0]
    judge = _judge(
        group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
    )
    finding = merge_group(
        group,
        decisions={},
        validations={candidate.candidate_id: _validation(valid=True, marker="model")},
        scanner_findings=[],
        judge=judge,
    )

    gated, accounting_candidates, limitation = _enforce_post_judge_execution_severity_accounting(
        group=group,
        finding=finding,
        judge=judge,
        pre_judgment_high_critical_ids=set(),
        status_bearing_candidate_ids=frozenset({candidate.candidate_id}),
    )

    assert gated.status is FindingStatus.NEEDS_REVIEW
    assert gated.severity is Severity.HIGH
    assert accounting_candidates == (candidate,)
    assert limitation is not None
    assert "model-review group" in limitation
    assert candidate.candidate_id in limitation


def test_nonwinning_medium_peer_cannot_trigger_late_severity_accounting() -> None:
    locations = _execution_candidate(_provenance()).locations
    high_winner = _model_candidate(
        candidate_id="model-high-winner",
        locations=locations,
        confidence=0.8,
        severity=Severity.HIGH,
    )
    medium_peer = _model_candidate(
        candidate_id="model-medium-peer",
        locations=locations,
        confidence=0.99,
        severity=Severity.MEDIUM,
    )
    group = group_candidates([high_winner, medium_peer])[0]
    judge = _judge(
        group.group_id,
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
    )
    finding = merge_group(
        group,
        decisions={},
        validations={
            high_winner.candidate_id: _validation(valid=True, marker="a"),
            medium_peer.candidate_id: _validation(valid=True, marker="b"),
        },
        scanner_findings=[],
        judge=judge,
    ).model_copy(update={"status": FindingStatus.CONFIRMED})

    gated, accounting_candidates, limitation = _enforce_post_judge_execution_severity_accounting(
        group=group,
        finding=finding,
        judge=judge,
        pre_judgment_high_critical_ids={high_winner.candidate_id},
        status_bearing_candidate_ids=frozenset({high_winner.candidate_id}),
    )

    assert gated == finding
    assert accounting_candidates == ()
    assert limitation is None
