from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import BaseModel, ValidationError

from mmaudit.models.scheduler import (
    SchedulerAbsenceReason,
    SchedulerCampaignSummary,
    SchedulerCrossShardDecision,
    SchedulerCrossShardIntegrationOutput,
    SchedulerCrossShardRelationship,
    SchedulerEvidenceCapJudgmentOutput,
    SchedulerEvidencePayloadBinding,
    SchedulerFindingReductionCandidate,
    SchedulerFindingReductionGroup,
    SchedulerFindingReductionOutput,
    SchedulerFindingReductionValidation,
    SchedulerPassKind,
    SchedulerReproductionHostOutput,
    SchedulerScope,
    SchedulerTaskActivation,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    SchedulerTerminalReportAuthority,
    SchedulerTerminalStatus,
    _parse_scheduler_host_payload,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    AuditReport,
    CandidateFinding,
    CandidateOriginKind,
    CandidateReproductionResolution,
    GeneratedFoundryTestSpec,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    Severity,
)
from mmaudit.orchestration.manifest import (
    _ManifestReproductionArtifact,
    _validate_scheduler_prejudgment_evidence_authority,
)
from mmaudit.orchestration.pipeline import _scheduled_reproduction_candidate_ids
from mmaudit.orchestration.reproduction_resolution import (
    build_candidate_reproduction_resolutions,
)
from tests.scheduler_support import _synthetic_manifest


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _task(
    *,
    seed: str,
    pass_kind: SchedulerPassKind,
    role: str,
    task_kind: SchedulerTaskKind,
    scope: SchedulerScope | None = None,
    candidate_ids: tuple[str, ...] = (),
) -> SchedulerTaskPlan:
    manifest = _synthetic_manifest(seed)
    model_fields: dict[str, Any] = {}
    if task_kind is SchedulerTaskKind.MODEL_REQUEST:
        model_fields = {
            "requested_model": "synthetic/auditor-v1",
            "root_lineage": "sha256:" + _sha256(f"{seed}:lineage:{role}"),
            "system_prompt_sha256": _sha256(f"{seed}:system:{role}"),
            "normalizer_sha256": _sha256(f"{seed}:normalizer:{role}"),
        }
    return SchedulerTaskPlan.build(
        manifest=manifest,
        pass_kind=pass_kind,
        scope=scope or SchedulerScope.global_scope(),
        task_kind=task_kind,
        task_key=f"test-{role.replace(':', '-')}",
        role=role,
        candidate_ids=candidate_ids,
        input_sha256=_sha256(f"{seed}:input:{role}"),
        prompt_sha256=_sha256(f"{seed}:prompt:{role}"),
        response_schema_sha256=_sha256(f"{seed}:schema:{role}"),
        **model_fields,
    )


def _activation(actual_input: object) -> SchedulerTaskActivation:
    return cast(
        SchedulerTaskActivation,
        SimpleNamespace(actual_input_sha256=scheduler_canonical_sha256(actual_input)),
    )


def _reduction_payload() -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "algorithm": "mmaudit.deterministic-finding-reduction.v1",
        "blind_candidate_ids": ["candidate-a"],
        "execution_candidate_ids": [],
        "candidate_ids": ["candidate-a"],
        "candidate_payload_sha256s": {"candidate-a": _sha256("candidate-a:payload")},
        "candidate_records": [
            SchedulerFindingReductionCandidate(
                candidate_id="candidate-a",
                candidate_sha256=_sha256("candidate-a:payload"),
                location_validation=SchedulerFindingReductionValidation(
                    valid=True,
                    content_hash=_sha256("source"),
                    errors=(),
                ),
            ).model_dump(mode="json")
        ],
        "groups": [
            SchedulerFindingReductionGroup(
                group_id="group-a",
                candidate_ids=("candidate-a",),
                canonical_candidate_id="candidate-a",
                valid_candidate_ids=("candidate-a",),
                invalid_candidate_ids=(),
            ).model_dump(mode="json")
        ],
        "canonical_candidate_ids": ["candidate-a"],
    }
    return {**body, "reduction_sha256": scheduler_canonical_sha256(body)}


def _cross_shard_payload(seed: str) -> dict[str, Any]:
    manifest = _synthetic_manifest(seed)
    source_shard_id, target_shard_id = manifest.shard_ids
    relationship = SchedulerCrossShardRelationship(
        relationship_id="relationship-a",
        relationship_kind="graph_boundary",
        source_shard_id=source_shard_id,
        target_shard_id=target_shard_id,
        source_path="contracts/A.sol",
        target_path="contracts/B.sol",
        resource_id="edge-a",
        relationship_sha256=_sha256("trusted-relationship-a"),
    )
    decision = SchedulerCrossShardDecision(
        relationship_id=relationship.relationship_id,
        linked_candidate_ids=("candidate-a",),
        status="CANDIDATE",
        surface_id="model-surface:" + _sha256("surface-a"),
        review_artifact_sha256=_sha256("review-artifact-a"),
    )
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "algorithm": "mmaudit.cross-shard-integration.v1",
        "status": "EVALUATED",
        "semantic_inventory_sha256": manifest.shard_inventory.semantic_inventory_sha256,
        "candidate_ids": ["candidate-a"],
        "candidate_payload_sha256s": {"candidate-a": _sha256("candidate-a:payload")},
        "shard_ids": list(manifest.shard_ids),
        "semantic_relationship_ids": [relationship.relationship_id],
        "boundary_review_artifact_sha256s": [decision.review_artifact_sha256],
        "invariant_review_present": True,
        "high_critical_candidate_ids": ["candidate-a"],
        "validation_candidate_ids": ["candidate-a"],
        "relationships": [relationship.model_dump(mode="json")],
        "decisions": [decision.model_dump(mode="json")],
        "invariant_review_decision_ids": ["invariant-a"],
    }
    return {**body, "integration_sha256": scheduler_canonical_sha256(body)}


def _cross_shard_activation_input(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_ids": payload["candidate_ids"],
        "candidate_payload_sha256s": payload["candidate_payload_sha256s"],
        "high_critical_candidate_ids": payload["high_critical_candidate_ids"],
        "validation_candidate_ids": payload["validation_candidate_ids"],
        "shard_ids": payload["shard_ids"],
        "semantic_inventory_sha256": payload["semantic_inventory_sha256"],
        "semantic_relationship_ids": payload["semantic_relationship_ids"],
        "semantic_relationships": payload["relationships"],
        "boundary_review_artifact_sha256s": payload["boundary_review_artifact_sha256s"],
        "invariant_review_present": payload["invariant_review_present"],
    }


def _judgment_payload(
    *,
    group_id: str = "group-a",
    candidate_id: str = "candidate-a",
    finding_id: str = "finding-a",
) -> dict[str, Any]:
    finding_sha256 = _sha256(f"{finding_id}:complete-finding-payload")

    def evidence_binding(kind: str, subject_id: str, identity: object) -> dict[str, str]:
        payload_sha256 = scheduler_canonical_sha256(
            {
                "kind": kind,
                "subject_id": subject_id,
                "identity": identity,
                "complete_payload": True,
            }
        )
        return {
            "record_id": scheduler_canonical_sha256(
                {
                    "kind": kind,
                    "subject_id": subject_id,
                    "payload_sha256": payload_sha256,
                }
            ),
            "subject_id": subject_id,
            "payload_sha256": payload_sha256,
        }

    terminal_findings = [
        {
            "group_id": group_id,
            "candidate_ids": [candidate_id],
            "finding_id": finding_id,
            "finding_payload_sha256": finding_sha256,
            "state": "REPORTED_ACTIVE",
            "finding_status": "needs_review",
            "finding_severity": "high",
            "finding_origin_kind": "model_review",
        }
    ]
    body: dict[str, Any] = {
        "schema_version": "2.0",
        "algorithm": "mmaudit.evidence-cap-terminal-authority.v2",
        "severity_threshold": "medium",
        "group_ids": [group_id],
        "judge_decision_ids": [group_id],
        "candidate_ids": [candidate_id],
        "candidate_payload_sha256s": {
            candidate_id: _sha256(f"{candidate_id}:complete-candidate-payload")
        },
        "candidate_grouping_sha256": scheduler_canonical_sha256(
            [{"group_id": group_id, "candidate_ids": [candidate_id]}]
        ),
        "terminal_findings": terminal_findings,
        "final_finding_ids": [finding_id],
        "rejected_finding_ids": [],
        "filtered_finding_ids": [],
        "final_finding_payload_sha256s": {finding_id: finding_sha256},
        "rejected_finding_payload_sha256s": {},
        "filtered_finding_payload_sha256s": {},
        "judge_decisions": [evidence_binding("judge", group_id, {"group_id": group_id})],
        "verification_decisions": [
            evidence_binding("verification", candidate_id, {"candidate_id": candidate_id})
        ],
        "cross_examination_decisions": [
            evidence_binding(
                "cross_examination",
                candidate_id,
                {"candidate_id": candidate_id, "reviewer_index": 1},
            )
        ],
        "falsification_decisions": [
            evidence_binding(
                "falsification",
                candidate_id,
                {"candidate_id": candidate_id, "test_name": "negative-control"},
            )
        ],
        "reproduction_results": [
            evidence_binding(
                "reproduction",
                candidate_id,
                {"candidate_id": candidate_id, "test_name": "local-regression"},
            )
        ],
        "reproduction_resolutions": [
            evidence_binding(
                "reproduction_resolution",
                candidate_id,
                {"candidate_id": candidate_id},
            )
        ],
    }
    return {**body, "judgment_sha256": scheduler_canonical_sha256(body)}


@pytest.mark.parametrize(
    "model",
    (
        SchedulerFindingReductionOutput,
        SchedulerCrossShardIntegrationOutput,
        SchedulerReproductionHostOutput,
        SchedulerEvidenceCapJudgmentOutput,
    ),
)
def test_host_contracts_reject_generic_payload(model: type[BaseModel]) -> None:
    with pytest.raises(ValidationError):
        model.model_validate({"unvalidated_generic_summary": True})


def test_finding_reduction_rejects_omission_duplicate_and_hash_tamper() -> None:
    payload = _reduction_payload()
    SchedulerFindingReductionOutput.model_validate(payload)

    missing = {**payload, "candidate_records": []}
    missing["reduction_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in missing.items() if key != "reduction_sha256"}
    )
    with pytest.raises(ValidationError):
        SchedulerFindingReductionOutput.model_validate(missing)

    duplicated = {**payload, "groups": [*payload["groups"], *payload["groups"]]}
    duplicated["reduction_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in duplicated.items() if key != "reduction_sha256"}
    )
    with pytest.raises(ValidationError):
        SchedulerFindingReductionOutput.model_validate(duplicated)

    with pytest.raises(ValidationError):
        SchedulerFindingReductionOutput.model_validate(
            {**payload, "reduction_sha256": _sha256("tampered-reduction")}
        )

    mismatched_record = {
        **payload["candidate_records"][0],
        "candidate_sha256": _sha256("different-candidate-payload"),
    }
    mismatched = {**payload, "candidate_records": [mismatched_record]}
    mismatched["reduction_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in mismatched.items() if key != "reduction_sha256"}
    )
    with pytest.raises(ValidationError):
        SchedulerFindingReductionOutput.model_validate(mismatched)

    with pytest.raises(ValidationError):
        SchedulerFindingReductionGroup(
            group_id="group-unsorted",
            candidate_ids=("candidate-a", "candidate-b"),
            canonical_candidate_id="candidate-a",
            valid_candidate_ids=("candidate-b", "candidate-a"),
            invalid_candidate_ids=(),
        )


def test_finding_reduction_is_bound_to_activated_candidate_projection() -> None:
    seed = "finding-activation"
    task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.FINDING_REDUCTION,
        role="host:finding_reducer",
        task_kind=SchedulerTaskKind.HOST_COMPUTATION,
    )
    payload = _reduction_payload()
    activation_input = {
        "blind_candidate_ids": payload["blind_candidate_ids"],
        "execution_candidate_ids": payload["execution_candidate_ids"],
        "candidate_payload_sha256s": payload["candidate_payload_sha256s"],
    }
    plan = cast(Any, SimpleNamespace(tasks=(task,), manifest=_synthetic_manifest(seed)))
    _parse_scheduler_host_payload(
        plan=plan,
        task=task,
        activation=_activation(activation_input),
        payload=payload,
    )

    changed = {
        **payload,
        "blind_candidate_ids": [],
        "execution_candidate_ids": ["candidate-a"],
    }
    changed["reduction_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in changed.items() if key != "reduction_sha256"}
    )
    with pytest.raises(ValueError, match="activated inventory"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=task,
            activation=_activation(activation_input),
            payload=changed,
        )


def test_cross_shard_contract_rejects_omitted_duplicate_and_tampered_relationships() -> None:
    payload = _cross_shard_payload("cross-shard-contract")
    SchedulerCrossShardIntegrationOutput.model_validate(payload)

    omitted = {**payload, "decisions": [], "boundary_review_artifact_sha256s": []}
    omitted["integration_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in omitted.items() if key != "integration_sha256"}
    )
    with pytest.raises(ValidationError):
        SchedulerCrossShardIntegrationOutput.model_validate(omitted)

    duplicated = {
        **payload,
        "relationships": [*payload["relationships"], *payload["relationships"]],
    }
    duplicated["integration_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in duplicated.items() if key != "integration_sha256"}
    )
    with pytest.raises(ValidationError):
        SchedulerCrossShardIntegrationOutput.model_validate(duplicated)

    with pytest.raises(ValidationError):
        SchedulerCrossShardIntegrationOutput.model_validate(
            {**payload, "integration_sha256": _sha256("tampered-integration")}
        )


def test_cross_shard_relationship_descriptor_and_scope_are_activation_bound() -> None:
    seed = "cross-shard-activation"
    manifest = _synthetic_manifest(seed)
    payload = _cross_shard_payload(seed)
    surface_id = payload["decisions"][0]["surface_id"]
    business_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        role="business_logic",
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        scope=SchedulerScope.shard_set(manifest.shard_ids),
        candidate_ids=(surface_id,),
    )
    host_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        role="host:cross_shard_integrator",
        task_kind=SchedulerTaskKind.HOST_COMPUTATION,
    )
    plan = cast(
        Any,
        SimpleNamespace(tasks=(business_task, host_task), manifest=manifest),
    )
    activation_input = _cross_shard_activation_input(payload)
    _parse_scheduler_host_payload(
        plan=plan,
        task=host_task,
        activation=_activation(activation_input),
        payload=payload,
    )

    changed_relationship = {
        **payload["relationships"][0],
        "target_path": "contracts/Substituted.sol",
        "relationship_sha256": _sha256("substituted-relationship"),
    }
    changed = {**payload, "relationships": [changed_relationship]}
    changed["integration_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in changed.items() if key != "integration_sha256"}
    )
    with pytest.raises(ValueError, match="activated input"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(activation_input),
            payload=changed,
        )

    suppressed_high = {**payload, "high_critical_candidate_ids": []}
    suppressed_high["integration_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in suppressed_high.items() if key != "integration_sha256"}
    )
    with pytest.raises(ValueError, match="activated input"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(activation_input),
            payload=suppressed_high,
        )

    suppressed_validation = {**payload, "validation_candidate_ids": []}
    suppressed_validation["integration_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in suppressed_validation.items() if key != "integration_sha256"}
    )
    with pytest.raises(ValueError, match="activated input"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(activation_input),
            payload=suppressed_validation,
        )

    changed_semantic = {
        **payload,
        "semantic_inventory_sha256": _sha256("substituted-semantic-inventory"),
    }
    changed_semantic["integration_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in changed_semantic.items() if key != "integration_sha256"}
    )
    with pytest.raises(ValueError, match="wrong semantic inventory"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(_cross_shard_activation_input(changed_semantic)),
            payload=changed_semantic,
        )

    unknown_shard = "shard-000000000000000000000003"
    wrong_scope_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        role="business_logic",
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        scope=SchedulerScope.shard_set((manifest.shard_ids[0], unknown_shard)),
        candidate_ids=(surface_id,),
    )
    wrong_plan = cast(
        Any,
        SimpleNamespace(tasks=(wrong_scope_task, host_task), manifest=manifest),
    )
    with pytest.raises(ValueError, match="wrong shard scope"):
        _parse_scheduler_host_payload(
            plan=wrong_plan,
            task=host_task,
            activation=_activation(activation_input),
            payload=payload,
        )


def test_reproduction_contract_requires_exact_candidate_and_test_coverage() -> None:
    valid = SchedulerReproductionHostOutput(
        eligible_candidate_ids=("candidate-a",),
        generated_test_ids=("candidate-a:test-a",),
        reproduction_result_ids=("candidate-a:test-a",),
        falsification_decisions=1,
    )
    with pytest.raises(ValidationError):
        SchedulerReproductionHostOutput(
            eligible_candidate_ids=("candidate-a",),
            generated_test_ids=(),
            reproduction_result_ids=(),
            falsification_decisions=0,
        )

    seed = "reproduction-partition"
    planner_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        role="specialist:test_generation:exploit_test",
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        candidate_ids=("candidate-a",),
    )
    host_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        role="host:reproduction",
        task_kind=SchedulerTaskKind.HOST_COMPUTATION,
    )
    plan = cast(
        Any,
        SimpleNamespace(
            tasks=(planner_task, host_task),
            manifest=_synthetic_manifest(seed),
            candidate_workset=SimpleNamespace(selected_candidate_ids=("candidate-a",)),
        ),
    )
    payload = valid.model_dump(mode="json", exclude_none=True)
    _parse_scheduler_host_payload(
        plan=plan,
        task=host_task,
        activation=_activation(payload),
        payload=payload,
    )

    wrong = SchedulerReproductionHostOutput(
        eligible_candidate_ids=("candidate-b",),
        generated_test_ids=("candidate-b:test-b",),
        reproduction_result_ids=("candidate-b:test-b",),
        falsification_decisions=1,
    ).model_dump(mode="json", exclude_none=True)
    with pytest.raises(ValueError, match="exact candidate workset"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(wrong),
            payload=wrong,
        )


def test_reproduction_inventory_remains_bound_when_post_verifier_eligibility_changes() -> None:
    seed = "reproduction-planned-inventory"
    planner_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        role="specialist:test_generation:exploit_test",
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        candidate_ids=("candidate-a",),
    )
    host_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        role="host:reproduction",
        task_kind=SchedulerTaskKind.HOST_COMPUTATION,
    )
    plan = cast(
        Any,
        SimpleNamespace(
            tasks=(planner_task, host_task),
            manifest=_synthetic_manifest(seed),
            candidate_workset=SimpleNamespace(selected_candidate_ids=("candidate-a",)),
        ),
    )

    post_verifier_eligible_candidate_ids: tuple[str, ...] = ()
    assert _scheduled_reproduction_candidate_ids(plan.tasks) == ("candidate-a",)
    stale_payload = SchedulerReproductionHostOutput(
        eligible_candidate_ids=post_verifier_eligible_candidate_ids,
        generated_test_ids=(),
        reproduction_result_ids=(),
        falsification_decisions=0,
    ).model_dump(mode="json", exclude_none=True)

    with pytest.raises(ValueError, match="exact candidate workset"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(stale_payload),
            payload=stale_payload,
        )


def test_current_manifest_requires_empty_reproduction_evidence_without_successful_host() -> None:
    manifest = _synthetic_manifest("absent-reproduction-host")
    summary = SchedulerCampaignSummary.build(manifest=manifest, pass_results=())
    authority = SchedulerTerminalReportAuthority.build(
        manifest=manifest,
        summary=summary,
        severity_threshold=Severity.MEDIUM,
        candidates=(),
        final_findings=(),
        rejected_findings=(),
        filtered_findings=(),
        report_quality_review=None,
        verification_decisions=(),
        cross_examination_decisions=(),
        falsification_decisions=(),
        reproduction_results=(),
        reproduction_resolutions=(),
    )
    report = AuditReport.model_construct(findings=[], rejected_findings=[])
    empty_artifact = _ManifestReproductionArtifact(
        schema_version="1.0",
        test_specifications=[],
        results=[],
        candidate_resolutions=[],
        falsification_decisions=[],
    )
    absence_task = SimpleNamespace(
        task_id="scheduler-task-conditional-absence",
        task_kind=SchedulerTaskKind.EMPTY_COMPLETION,
        role="host:conditional_absence",
    )
    absence_result = SimpleNamespace(
        task_id=absence_task.task_id,
        terminal_status=SchedulerTerminalStatus.EXPLICIT_EMPTY,
    )
    absence_pass = SimpleNamespace(
        plan=SimpleNamespace(
            pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            tasks=(absence_task,),
            conditional_absence=SimpleNamespace(
                reason=SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES
            ),
        ),
        task_results=(absence_result,),
    )
    absent_host_journal = cast(Any, SimpleNamespace(pass_results=(absence_pass,)))

    _validate_scheduler_prejudgment_evidence_authority(
        authority=authority,
        report=report,
        candidates=(),
        reproduction_artifact=empty_artifact,
        journal=absent_host_journal,
    )

    result = ReproductionResult(
        candidate_id="candidate-a",
        test_name="SyntheticReplay",
        state=ReproductionState.NOT_ATTEMPTED,
        specification_sha256="1" * 64,
    )
    resolution = CandidateReproductionResolution(
        candidate_id="candidate-a",
        kind=ReproductionResolutionKind.INCONCLUSIVE,
        detail="No successful host retained this synthetic resolution.",
    )
    typed_presence_cases = (
        empty_artifact.model_copy(
            update={
                "test_specifications": [
                    GeneratedFoundryTestSpec.model_construct(
                        candidate_id="candidate-a",
                        name="SyntheticReplay",
                    )
                ]
            }
        ),
        empty_artifact.model_copy(update={"results": [result]}),
        empty_artifact.model_copy(update={"candidate_resolutions": [resolution]}),
    )
    for nonempty_artifact in typed_presence_cases:
        with pytest.raises(
            ValueError,
            match="terminal reproduction differs from typed pass-six absence",
        ):
            _validate_scheduler_prejudgment_evidence_authority(
                authority=authority,
                report=report,
                candidates=(),
                reproduction_artifact=nonempty_artifact,
                journal=absent_host_journal,
            )

    authority_presence_cases = (
        authority.model_copy(
            update={
                "reproduction_results": (
                    SchedulerEvidencePayloadBinding.build(
                        kind="reproduction",
                        subject_id=result.candidate_id,
                        payload=result,
                    ),
                )
            }
        ),
        authority.model_copy(
            update={
                "reproduction_resolutions": (
                    SchedulerEvidencePayloadBinding.build(
                        kind="reproduction_resolution",
                        subject_id=resolution.candidate_id,
                        payload=resolution,
                    ),
                )
            }
        ),
    )
    for nonempty_authority in authority_presence_cases:
        with pytest.raises(
            ValueError,
            match="terminal reproduction differs from typed pass-six absence",
        ):
            _validate_scheduler_prejudgment_evidence_authority(
                authority=nonempty_authority,
                report=report,
                candidates=(),
                reproduction_artifact=empty_artifact,
                journal=absent_host_journal,
            )

    candidate = CandidateFinding.model_construct(
        candidate_id="candidate-a",
        severity=Severity.HIGH,
        origin_kind=CandidateOriginKind.MODEL_REVIEW,
    )
    exact_resolutions = build_candidate_reproduction_resolutions(
        candidates=(candidate,),
        results=(),
    )
    exact_artifact = empty_artifact.model_copy(update={"candidate_resolutions": exact_resolutions})
    exact_authority = authority.model_copy(
        update={
            "reproduction_resolutions": tuple(
                SchedulerEvidencePayloadBinding.build(
                    kind="reproduction_resolution",
                    subject_id=item.candidate_id,
                    payload=item,
                )
                for item in exact_resolutions
            )
        }
    )
    _validate_scheduler_prejudgment_evidence_authority(
        authority=exact_authority,
        report=report,
        candidates=(candidate,),
        reproduction_artifact=exact_artifact,
        journal=absent_host_journal,
    )

    changed_resolution = exact_resolutions[0].model_copy(
        update={"detail": "Coherently changed terminal accounting detail."}
    )
    changed_artifact = exact_artifact.model_copy(
        update={"candidate_resolutions": [changed_resolution]}
    )
    with pytest.raises(
        ValueError,
        match="terminal reproduction differs from typed pass-six absence",
    ):
        _validate_scheduler_prejudgment_evidence_authority(
            authority=exact_authority,
            report=report,
            candidates=(candidate,),
            reproduction_artifact=changed_artifact,
            journal=absent_host_journal,
        )


def test_evidence_cap_contract_is_bound_to_judge_partition_and_activation() -> None:
    seed = "judgment-partition"
    judge_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
        role="judge",
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        candidate_ids=("group-a",),
    )
    host_task = _task(
        seed=seed,
        pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
        role="host:evidence_cap_judgment",
        task_kind=SchedulerTaskKind.HOST_COMPUTATION,
    )
    plan = cast(
        Any,
        SimpleNamespace(tasks=(judge_task, host_task), manifest=_synthetic_manifest(seed)),
    )
    output = SchedulerEvidenceCapJudgmentOutput.model_validate(_judgment_payload()).model_dump(
        mode="json"
    )
    _parse_scheduler_host_payload(
        plan=plan,
        task=host_task,
        activation=_activation(output),
        payload=output,
    )

    wrong = _judgment_payload(group_id="group-b")
    with pytest.raises(ValueError, match="judge partition"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(wrong),
            payload=wrong,
        )

    changed_payload_sha256 = _sha256("substituted-verification-payload")
    changed_verification = {
        **output["verification_decisions"][0],
        "record_id": scheduler_canonical_sha256(
            {
                "kind": "verification",
                "subject_id": "candidate-a",
                "payload_sha256": changed_payload_sha256,
            }
        ),
        "payload_sha256": changed_payload_sha256,
    }
    changed_evidence = {**output, "verification_decisions": [changed_verification]}
    changed_evidence["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in changed_evidence.items() if key != "judgment_sha256"}
    )
    with pytest.raises(ValueError, match="activated input"):
        _parse_scheduler_host_payload(
            plan=plan,
            task=host_task,
            activation=_activation(output),
            payload=changed_evidence,
        )

    incomplete = {**output, "judge_decision_ids": []}
    incomplete["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in incomplete.items() if key != "judgment_sha256"}
    )
    with pytest.raises(ValidationError):
        SchedulerEvidenceCapJudgmentOutput.model_validate(incomplete)


def test_evidence_cap_contract_rejects_terminal_partition_and_evidence_drift() -> None:
    payload = _judgment_payload()
    SchedulerEvidenceCapJudgmentOutput.model_validate(payload)

    second_payload_sha256 = _sha256("second-independent-verification")
    second_verification = {
        "record_id": scheduler_canonical_sha256(
            {
                "kind": "verification",
                "subject_id": "candidate-a",
                "payload_sha256": second_payload_sha256,
            }
        ),
        "subject_id": "candidate-a",
        "payload_sha256": second_payload_sha256,
    }
    multiple_verifications = {
        **payload,
        "verification_decisions": sorted(
            [*payload["verification_decisions"], second_verification],
            key=lambda item: (item["subject_id"], item["record_id"]),
        ),
    }
    multiple_verifications["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in multiple_verifications.items() if key != "judgment_sha256"}
    )
    SchedulerEvidenceCapJudgmentOutput.model_validate(multiple_verifications)

    unknown_payload_sha256 = payload["verification_decisions"][0]["payload_sha256"]
    unknown_subject = {
        **payload["verification_decisions"][0],
        "record_id": scheduler_canonical_sha256(
            {
                "kind": "verification",
                "subject_id": "candidate-unknown",
                "payload_sha256": unknown_payload_sha256,
            }
        ),
        "subject_id": "candidate-unknown",
    }
    drifted_evidence = {**payload, "verification_decisions": [unknown_subject]}
    drifted_evidence["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in drifted_evidence.items() if key != "judgment_sha256"}
    )
    with pytest.raises(ValidationError, match="partitions are inconsistent"):
        SchedulerEvidenceCapJudgmentOutput.model_validate(drifted_evidence)

    reproduction_payload_sha256 = payload["reproduction_results"][0]["payload_sha256"]
    unknown_reproduction = {
        **payload["reproduction_results"][0],
        "record_id": scheduler_canonical_sha256(
            {
                "kind": "reproduction",
                "subject_id": "candidate-post-judgment",
                "payload_sha256": reproduction_payload_sha256,
            }
        ),
        "subject_id": "candidate-post-judgment",
    }
    reproduction_drift = {**payload, "reproduction_results": [unknown_reproduction]}
    reproduction_drift["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in reproduction_drift.items() if key != "judgment_sha256"}
    )
    with pytest.raises(ValidationError, match="partitions are inconsistent"):
        SchedulerEvidenceCapJudgmentOutput.model_validate(reproduction_drift)

    filtered_binding = {
        **payload["terminal_findings"][0],
        "state": "FILTERED_BELOW_THRESHOLD",
    }
    filtered = {
        **payload,
        "terminal_findings": [filtered_binding],
        "final_finding_ids": [],
        "filtered_finding_ids": ["finding-a"],
        "final_finding_payload_sha256s": {},
        "filtered_finding_payload_sha256s": payload["final_finding_payload_sha256s"],
    }
    filtered["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in filtered.items() if key != "judgment_sha256"}
    )
    with pytest.raises(ValidationError, match="violates report threshold"):
        SchedulerEvidenceCapJudgmentOutput.model_validate(filtered)

    tampered_hash = {
        **payload,
        "final_finding_payload_sha256s": {"finding-a": _sha256("changed-finding")},
    }
    tampered_hash["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in tampered_hash.items() if key != "judgment_sha256"}
    )
    with pytest.raises(ValidationError, match="hash or disposition"):
        SchedulerEvidenceCapJudgmentOutput.model_validate(tampered_hash)


def test_evidence_cap_contract_retains_execution_origin_below_reporting_threshold() -> None:
    payload = _judgment_payload(
        candidate_id="exec-post-judgment",
        finding_id="finding-execution",
    )
    execution_binding = {
        **payload["terminal_findings"][0],
        "finding_origin_kind": "deterministic_execution",
        "finding_severity": "high",
    }
    execution_payload = {
        **payload,
        "severity_threshold": "critical",
        "terminal_findings": [execution_binding],
    }
    execution_payload["judgment_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in execution_payload.items() if key != "judgment_sha256"}
    )

    validated = SchedulerEvidenceCapJudgmentOutput.model_validate(execution_payload)

    assert validated.final_finding_ids == ("finding-execution",)
    assert tuple(item.subject_id for item in validated.reproduction_results) == (
        "exec-post-judgment",
    )
    assert tuple(item.subject_id for item in validated.reproduction_resolutions) == (
        "exec-post-judgment",
    )
