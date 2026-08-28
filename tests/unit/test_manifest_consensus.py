"""Detached replay checks for the exact pass-six consensus-review artifact."""

from __future__ import annotations

from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any, cast

import pytest

import mmaudit.orchestration.manifest as manifest_module
from mmaudit.models.scheduler import (
    SchedulerEvidenceCapJudgmentOutput,
    SchedulerEvidencePayloadBinding,
    SchedulerFindingReductionCandidate,
    SchedulerFindingReductionValidation,
    SchedulerPassKind,
    SchedulerTaskActivation,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalReportAuthority,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    AuditReport,
    ConsensusReviewArtifact,
    LocationValidation,
    Severity,
    StrictModel,
    UsageRecord,
)
from mmaudit.orchestration.consensus import merge_group, publication_groups
from mmaudit.orchestration.manifest import (
    _reconstruct_scheduler_consensus_review,
    _scheduler_report_authority_snapshot,
    _validate_scheduler_consensus_review_authority,
    _validate_scheduler_reviewer_provider_generations,
    _validate_scheduler_terminal_finding_replay,
)
from tests.scheduler_support import CompleteSchedulerFixture, build_complete_scheduler_fixture


class _DetachedJournal:
    """Small read-only journal surface used by the manifest reconstruction."""

    def __init__(
        self,
        *,
        outputs: Sequence[SchedulerTaskOutput],
        pass_results: Sequence[object],
    ) -> None:
        self.outputs = tuple(outputs)
        self.pass_results = tuple(pass_results)

    def reconstruct_output[OutputT: StrictModel](
        self,
        task_id: str,
        output_type: type[OutputT],
    ) -> OutputT:
        output = next(item for item in self.outputs if item.task_id == task_id)
        return output_type.model_validate(output.payload)


@pytest.fixture(scope="module")
def complete_fixture() -> CompleteSchedulerFixture:
    return build_complete_scheduler_fixture(seed="manifest-consensus")


def _snapshot(
    fixture: CompleteSchedulerFixture,
    *,
    pass_results: Sequence[object] | None = None,
) -> Any:
    journal = _DetachedJournal(
        outputs=fixture.outputs,
        pass_results=fixture.pass_results if pass_results is None else pass_results,
    )
    return _scheduler_report_authority_snapshot(cast(Any, journal))


def _binding(artifact: ConsensusReviewArtifact) -> SchedulerEvidencePayloadBinding:
    return SchedulerEvidencePayloadBinding.build(
        kind="consensus_review",
        subject_id=artifact.campaign_id,
        payload=artifact,
    )


def _report(artifact: ConsensusReviewArtifact | None) -> AuditReport:
    return cast(AuditReport, SimpleNamespace(consensus_review=artifact))


def _authority(
    artifact: ConsensusReviewArtifact | None,
) -> SchedulerTerminalReportAuthority:
    return cast(
        SchedulerTerminalReportAuthority,
        SimpleNamespace(consensus_review=_binding(artifact) if artifact is not None else None),
    )


def _judgment(
    artifact: ConsensusReviewArtifact | None,
) -> SchedulerEvidenceCapJudgmentOutput:
    return cast(
        SchedulerEvidenceCapJudgmentOutput,
        SimpleNamespace(consensus_review=_binding(artifact) if artifact is not None else None),
    )


def test_manifest_reconstructs_exact_three_reviewer_consensus(
    complete_fixture: CompleteSchedulerFixture,
) -> None:
    reconstructed = _reconstruct_scheduler_consensus_review(snapshot=_snapshot(complete_fixture))

    assert reconstructed is not None
    validation_plan = next(
        plan
        for plan in complete_fixture.plans
        if plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )
    assert validation_plan.candidate_workset is not None
    assert reconstructed.candidate_ids == (validation_plan.candidate_workset.selected_candidate_ids)
    assert tuple(item.scheduler_task_id for item in reconstructed.reviewers) == tuple(
        task.task_id
        for task_key in (
            "independent-verifier",
            "candidate-falsifier-1",
            "candidate-falsifier-2",
        )
        for task in validation_plan.tasks
        if task.task_key == task_key
    )
    _validate_scheduler_consensus_review_authority(
        report=_report(reconstructed),
        reconstructed=reconstructed,
        authority=_authority(reconstructed),
        judgment=_judgment(reconstructed),
    )


def _fixture_with_reused_provider_generation(
    pass_kind: SchedulerPassKind,
) -> CompleteSchedulerFixture:
    def reuse_generation(
        task: SchedulerTaskPlan,
        _activation: SchedulerTaskActivation,
        usage: UsageRecord,
    ) -> UsageRecord:
        if task.pass_kind is pass_kind:
            return usage.model_copy(
                update={"openrouter_generation_id": "gen-reused-across-lineages"}
            )
        return usage

    return build_complete_scheduler_fixture(
        seed=f"manifest-reused-generation-{pass_kind.value}",
        usage_transform=reuse_generation,
    )


def test_manifest_rejects_reused_pass_six_provider_generation() -> None:
    fixture = _fixture_with_reused_provider_generation(
        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )

    with pytest.raises(ValueError, match="retained pass-six evidence"):
        _reconstruct_scheduler_consensus_review(snapshot=_snapshot(fixture))


def test_manifest_rejects_reused_pass_five_provider_generation() -> None:
    fixture = _fixture_with_reused_provider_generation(
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION
    )

    with pytest.raises(ValueError, match="reuse one provider generation identity"):
        _validate_scheduler_reviewer_provider_generations(_snapshot(fixture))


def test_manifest_rejects_provider_generation_reused_across_review_passes() -> None:
    def reuse_across_passes(
        task: SchedulerTaskPlan,
        _activation: SchedulerTaskActivation,
        usage: UsageRecord,
    ) -> UsageRecord:
        if (
            task.pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION
            and task.role.endswith("reviewer_1")
        ) or task.task_key == "independent-verifier":
            return usage.model_copy(
                update={"openrouter_generation_id": "gen-reused-across-review-passes"}
            )
        return usage

    fixture = build_complete_scheduler_fixture(
        seed="manifest-cross-pass-reused-generation",
        usage_transform=reuse_across_passes,
    )

    with pytest.raises(ValueError, match="reuse one provider generation identity"):
        _validate_scheduler_reviewer_provider_generations(_snapshot(fixture))


def test_manifest_rejects_reused_blind_candidate_origin_provider_generation() -> None:
    fixture = _fixture_with_reused_provider_generation(SchedulerPassKind.BLIND_SHARD_REVIEW)

    with pytest.raises(ValueError, match="reuse one provider generation identity"):
        _validate_scheduler_reviewer_provider_generations(_snapshot(fixture))


def test_manifest_rejects_provider_generation_reused_across_orientation_and_candidate_passes() -> (
    None
):
    blind_generation_reused = False

    def reuse_across_orientation_and_candidate_passes(
        task: SchedulerTaskPlan,
        _activation: SchedulerTaskActivation,
        usage: UsageRecord,
    ) -> UsageRecord:
        nonlocal blind_generation_reused
        reused = task.pass_kind is SchedulerPassKind.ORIENTATION
        if task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW and not blind_generation_reused:
            blind_generation_reused = True
            reused = True
        if reused:
            return usage.model_copy(
                update={"openrouter_generation_id": "gen-reused-across-model-passes"}
            )
        return usage

    fixture = build_complete_scheduler_fixture(
        seed="manifest-orientation-candidate-reused-generation",
        usage_transform=reuse_across_orientation_and_candidate_passes,
    )

    with pytest.raises(ValueError, match="reuse one provider generation identity"):
        _validate_scheduler_reviewer_provider_generations(_snapshot(fixture))


@pytest.mark.parametrize("projection", ("report", "authority", "judgment"))
def test_manifest_rejects_consensus_projection_drift(
    complete_fixture: CompleteSchedulerFixture,
    projection: str,
) -> None:
    reconstructed = _reconstruct_scheduler_consensus_review(snapshot=_snapshot(complete_fixture))
    assert reconstructed is not None
    report = _report(reconstructed)
    authority = _authority(reconstructed)
    judgment = _judgment(reconstructed)
    if projection == "report":
        report = _report(None)
    elif projection == "authority":
        authority = _authority(None)
    else:
        judgment = _judgment(None)

    with pytest.raises(ValueError, match="consensus review differs"):
        _validate_scheduler_consensus_review_authority(
            report=report,
            reconstructed=reconstructed,
            authority=authority,
            judgment=judgment,
        )


def test_manifest_treats_failed_reviewer_inventory_as_absent(
    complete_fixture: CompleteSchedulerFixture,
) -> None:
    validation_result = next(
        result
        for result in complete_fixture.pass_results
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )
    task = next(
        task for task in validation_result.plan.tasks if task.task_key == "candidate-falsifier-2"
    )
    failed = SchedulerTaskResult.build_preflight_failure(
        plan=validation_result.plan,
        task=task,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256="0" * 64,
    )
    changed_results = tuple(
        failed if result.task_id == task.task_id else result
        for result in validation_result.task_results
    )
    incomplete_pass = SimpleNamespace(
        plan=validation_result.plan,
        task_results=changed_results,
    )
    pass_results = tuple(
        incomplete_pass
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
        else result
        for result in complete_fixture.pass_results
    )

    assert (
        _reconstruct_scheduler_consensus_review(
            snapshot=_snapshot(complete_fixture, pass_results=pass_results)
        )
        is None
    )
    _validate_scheduler_consensus_review_authority(
        report=_report(None),
        reconstructed=None,
        authority=_authority(None),
        judgment=_judgment(None),
    )


def test_manifest_rejects_published_consensus_when_reviewer_inventory_is_incomplete(
    complete_fixture: CompleteSchedulerFixture,
) -> None:
    artifact = _reconstruct_scheduler_consensus_review(snapshot=_snapshot(complete_fixture))
    assert artifact is not None

    with pytest.raises(ValueError, match="public consensus review differs"):
        _validate_scheduler_consensus_review_authority(
            report=_report(artifact),
            reconstructed=None,
            authority=_authority(artifact),
            judgment=_judgment(artifact),
        )


def test_manifest_rejects_forged_reused_reviewer_lineage(
    complete_fixture: CompleteSchedulerFixture,
) -> None:
    validation_result = next(
        result
        for result in complete_fixture.pass_results
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )
    verifier = next(
        task for task in validation_result.plan.tasks if task.task_key == "independent-verifier"
    )
    falsifier_two = next(
        task for task in validation_result.plan.tasks if task.task_key == "candidate-falsifier-2"
    )
    assert verifier.root_lineage is not None
    forged_falsifier = falsifier_two.model_copy(update={"root_lineage": verifier.root_lineage})
    forged_tasks: tuple[SchedulerTaskPlan, ...] = tuple(
        forged_falsifier if task.task_id == falsifier_two.task_id else task
        for task in validation_result.plan.tasks
    )
    forged_plan = SimpleNamespace(
        pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        candidate_workset=validation_result.plan.candidate_workset,
        tasks=forged_tasks,
    )
    forged_pass = SimpleNamespace(
        plan=forged_plan,
        task_results=validation_result.task_results,
    )
    pass_results = tuple(
        forged_pass
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
        else result
        for result in complete_fixture.pass_results
    )

    with pytest.raises(ValueError, match="retained pass-six evidence"):
        _reconstruct_scheduler_consensus_review(
            snapshot=_snapshot(complete_fixture, pass_results=pass_results)
        )


def test_manifest_rejects_extra_reviewer_role_even_without_plan_revalidation(
    complete_fixture: CompleteSchedulerFixture,
) -> None:
    validation_result = next(
        result
        for result in complete_fixture.pass_results
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )
    verifier = next(
        task for task in validation_result.plan.tasks if task.task_key == "independent-verifier"
    )
    extra_reviewer = verifier.model_copy(update={"task_key": "unexpected-extra-reviewer"})
    forged_plan = SimpleNamespace(
        pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        candidate_workset=validation_result.plan.candidate_workset,
        tasks=(*validation_result.plan.tasks, extra_reviewer),
    )
    forged_pass = SimpleNamespace(
        plan=forged_plan,
        task_results=validation_result.task_results,
    )
    pass_results = tuple(
        forged_pass
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
        else result
        for result in complete_fixture.pass_results
    )

    with pytest.raises(ValueError, match="exact three reviewer tasks"):
        _reconstruct_scheduler_consensus_review(
            snapshot=_snapshot(complete_fixture, pass_results=pass_results)
        )


def test_manifest_empty_validation_workset_requires_consensus_absence() -> None:
    pass_result = SimpleNamespace(
        plan=SimpleNamespace(
            pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            candidate_workset=SimpleNamespace(selected_candidate_ids=()),
            tasks=(),
        ),
        task_results=(),
    )
    journal = _DetachedJournal(outputs=(), pass_results=(pass_result,))
    snapshot = _scheduler_report_authority_snapshot(cast(Any, journal))

    assert _reconstruct_scheduler_consensus_review(snapshot=snapshot) is None
    _validate_scheduler_consensus_review_authority(
        report=_report(None),
        reconstructed=None,
        authority=_authority(None),
        judgment=_judgment(None),
    )


def test_detached_replay_uses_terminal_not_pass_four_validation(
    candidate_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = candidate_factory()
    candidate_id = candidate.candidate_id
    candidate_sha256 = scheduler_canonical_sha256(candidate.model_dump(mode="json"))
    repository_sha256 = "a" * 64
    validation_error = "app.py:11: file changed since repository discovery"
    valid = LocationValidation(
        valid=True,
        content_hash=repository_sha256,
        errors=[],
        validated_at=None,
    )
    invalid = LocationValidation(
        valid=False,
        content_hash=repository_sha256,
        errors=[validation_error],
        validated_at=None,
    )
    group = publication_groups([candidate])[0]
    active = merge_group(
        group,
        decisions={},
        validations={candidate_id: valid},
        scanner_findings=[],
        judge=None,
    )
    rejected = merge_group(
        group,
        decisions={},
        validations={candidate_id: invalid},
        scanner_findings=[],
        judge=None,
    )
    assert active.status.value != "rejected"
    assert rejected.status.value == "rejected"

    def record(*, valid: bool) -> SchedulerFindingReductionCandidate:
        return SchedulerFindingReductionCandidate(
            candidate_id=candidate_id,
            candidate_sha256=candidate_sha256,
            location_validation=SchedulerFindingReductionValidation(
                valid=valid,
                content_hash=repository_sha256,
                errors=() if valid else (validation_error,),
            ),
        )

    integration = cast(
        Any,
        SimpleNamespace(
            candidate_payload_sha256s={candidate_id: candidate_sha256},
            candidate_records=(record(valid=True),),
        ),
    )
    judgment = cast(
        Any,
        SimpleNamespace(
            candidate_ids=(candidate_id,),
            terminal_candidate_records=(record(valid=False),),
            critical_confirmation_requires_execution=False,
            severity_threshold=Severity.MEDIUM,
        ),
    )
    common_report_fields = {
        "cross_examination_decisions": (),
        "reproductions": (),
        "falsification_decisions": (),
        "verification_decisions": (),
        "scanner_runs": (),
        "filtered_findings": (),
    }
    active_report = cast(
        Any,
        SimpleNamespace(
            **common_report_fields,
            findings=(active,),
            rejected_findings=(),
        ),
    )
    rejected_report = cast(
        Any,
        SimpleNamespace(
            **common_report_fields,
            findings=(),
            rejected_findings=(rejected,),
        ),
    )
    snapshot = cast(Any, SimpleNamespace())
    monkeypatch.setattr(
        manifest_module,
        "_reconstruct_scheduler_consensus_review",
        lambda *, snapshot: None,
    )
    monkeypatch.setattr(
        manifest_module,
        "_validate_scheduler_retained_judge_decisions",
        lambda **kwargs: (),
    )
    call = {
        "judgment": judgment,
        "integration": integration,
        "candidates": (candidate,),
        "trusted_scanner_fingerprints": frozenset(),
        "snapshot": snapshot,
        "config": None,
        "run_options": None,
        "require_complete_pass": False,
    }

    with pytest.raises(ValueError, match="deterministic consensus replay"):
        _validate_scheduler_terminal_finding_replay(report=active_report, **call)
    _validate_scheduler_terminal_finding_replay(report=rejected_report, **call)
