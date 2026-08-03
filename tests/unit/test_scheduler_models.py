from __future__ import annotations

import hashlib
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass

import pytest
from pydantic import ValidationError

from mmaudit.constants import SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.models.scheduler import (
    ABSENT_QUALIFICATION_SHA256,
    ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256,
    SCHEDULER_ANALYSIS_INPUT_LABELS,
    SCHEDULER_PASS_ORDER,
    SchedulerAbsenceReason,
    SchedulerAnalysisInputDescriptor,
    SchedulerAnalysisInputInventory,
    SchedulerArtifact,
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerCampaignStatus,
    SchedulerCampaignSummary,
    SchedulerCandidateWorkset,
    SchedulerConditionalAbsence,
    SchedulerJournalEvidence,
    SchedulerPassDependency,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerPrivacyEvidenceCustody,
    SchedulerReportBinding,
    SchedulerResultOrigin,
    SchedulerScope,
    SchedulerScopeKind,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerShardKind,
    SchedulerSourceDescriptor,
    SchedulerTaskActivation,
    SchedulerTaskEvent,
    SchedulerTaskEventKind,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    build_scheduler_model_request_evidence,
    repository_pseudo_shard_id,
    scheduler_canonical_sha256,
    scheduler_role_requires_specialist_accepted_outcome,
    scheduler_source_tree_sha256,
)
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
)
from tests.scheduler_support import (
    SchedulerFixtureModelTask,
    build_complete_scheduler_fixture,
    build_scheduler_test_host_payload,
    build_scheduler_test_model_payload,
    build_scheduler_test_model_surface_review_custody,
    build_scheduler_test_usage,
    scheduler_test_delivered_source_descriptor_sha256s,
    scheduler_test_host_activation_input_sha256,
    scheduler_test_model_fields,
    scheduler_test_response_schema_sha256,
)


def _sha256(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _analysis_inventory() -> SchedulerAnalysisInputInventory:
    return SchedulerAnalysisInputInventory.build(
        SchedulerAnalysisInputDescriptor.build(
            label=label,
            type_name="SyntheticProjection",
            value={"label": label},
        )
        for label in SCHEDULER_ANALYSIS_INPUT_LABELS
    )


def _shard(index: int) -> str:
    return f"shard-{index:024x}"


def _source(path: str, seed: str = "base") -> SchedulerSourceDescriptor:
    content = f"{seed}:{path}".encode()
    return SchedulerSourceDescriptor.build(
        path=path,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
    )


def _inventory(seed: str = "base") -> SchedulerShardInventory:
    first = SchedulerShardDescriptor.semantic(
        shard_id=_shard(1),
        semantic_shard_sha256=_sha256(f"{seed}:semantic:1"),
        sources=(_source("src/Alpha.sol", seed),),
    )
    second = SchedulerShardDescriptor.semantic(
        shard_id=_shard(2),
        semantic_shard_sha256=_sha256(f"{seed}:semantic:2"),
        sources=(_source("src/Beta.sol", seed),),
    )
    pseudo = SchedulerShardDescriptor.repository_pseudo(sources=(_source("README.md", seed),))
    return SchedulerShardInventory.build(
        semantic_inventory_sha256=_sha256(f"{seed}:semantic-inventory"),
        shards=(second, pseudo, first),
    )


def _privacy_custody(
    inventory: SchedulerShardInventory,
    seed: str = "base",
) -> SchedulerPrivacyEvidenceCustody:
    provenance_sha256 = _sha256(f"{seed}:privacy-provenance")
    return SchedulerPrivacyEvidenceCustody.build(
        source_sha256=inventory.source_tree_sha256,
        source_provenance_size=128,
        source_provenance_artifact_sha256=_sha256(f"{seed}:privacy-provenance-bytes"),
        source_provenance_evidence_sha256=provenance_sha256,
        effective_policy_size=256,
        effective_policy_artifact_sha256=_sha256(f"{seed}:privacy-policy-bytes"),
        effective_policy_evidence_sha256=_sha256(f"{seed}:privacy-policy"),
        policy_source_provenance_sha256=provenance_sha256,
    )


def _bindings(
    seed: str = "base",
    inventory: SchedulerShardInventory | None = None,
) -> SchedulerBindings:
    exact_inventory = inventory or _inventory(seed)
    privacy_custody = _privacy_custody(exact_inventory, seed)
    return SchedulerBindings.build(
        source_sha256=exact_inventory.source_tree_sha256,
        analysis_input_sha256=_analysis_inventory().analysis_input_sha256,
        effective_config_sha256=_sha256(f"{seed}:config"),
        shard_inventory_sha256=exact_inventory.inventory_sha256,
        model_selection_sha256=_sha256(f"{seed}:models"),
        qualification_sha256=_sha256(f"{seed}:qualification"),
        prompt_set_sha256=_sha256(f"{seed}:prompts"),
        schema_set_sha256=_sha256(f"{seed}:schemas"),
        tool_policy_sha256=_sha256(f"{seed}:tools"),
        privacy_evidence_custody_sha256=privacy_custody.custody_sha256,
    )


def _manifest(seed: str = "base") -> SchedulerCampaignManifest:
    inventory = _inventory(seed)
    privacy_custody = _privacy_custody(inventory, seed)
    return SchedulerCampaignManifest.build(
        bindings=_bindings(seed, inventory),
        shard_inventory=inventory,
        privacy_evidence_custody=privacy_custody,
    )


_HOST_ROLES = {
    SchedulerPassKind.FINDING_REDUCTION: "host:finding_reducer",
    SchedulerPassKind.CROSS_SHARD_INTEGRATION: "host:cross_shard_integrator",
    SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT: "host:evidence_cap_judgment",
}

_MODEL_ROLES = {
    SchedulerPassKind.ORIENTATION: "threat_model",
    SchedulerPassKind.BLIND_SHARD_REVIEW: "source_audit",
    SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION: "adversarial_reviewer",
    SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION: "falsifier",
}


def _task(
    manifest: SchedulerCampaignManifest,
    pass_kind: SchedulerPassKind,
    *,
    key: str,
    kind: SchedulerTaskKind,
    role: str | None = None,
    scope: SchedulerScope | None = None,
    recipe_seed: str | None = None,
    candidate_ids: Iterable[str] = (),
    root_lineage: str | None = None,
) -> SchedulerTaskPlan:
    requested_model = None
    resolved_lineage = root_lineage
    if kind is SchedulerTaskKind.MODEL_REQUEST:
        requested_model = "synthetic/auditor-v1"
        resolved_lineage = resolved_lineage or "sha256:" + _sha256(f"lineage:{key}")
    resolved_role = role
    if resolved_role is None:
        if kind is SchedulerTaskKind.EMPTY_COMPLETION:
            resolved_role = "host:conditional_absence"
        elif kind is SchedulerTaskKind.HOST_COMPUTATION:
            resolved_role = _HOST_ROLES.get(pass_kind, "host:computation")
        else:
            resolved_role = _MODEL_ROLES.get(pass_kind, "specialist")
    response_schema_sha256 = _sha256(f"schema:{key}")
    if kind is SchedulerTaskKind.MODEL_REQUEST:
        # Intentionally invalid role/pass combinations must reach pass-plan validation.
        with suppress(ValueError):
            response_schema_sha256 = scheduler_test_response_schema_sha256(
                pass_kind,
                resolved_role,
            )
    return SchedulerTaskPlan.build(
        manifest=manifest,
        pass_kind=pass_kind,
        scope=scope or SchedulerScope.global_scope(),
        task_kind=kind,
        task_key=key,
        role=resolved_role,
        requested_model=requested_model,
        root_lineage=resolved_lineage,
        candidate_ids=candidate_ids,
        input_sha256=_sha256(f"recipe-input:{recipe_seed or key}"),
        prompt_sha256=_sha256(f"recipe-prompt:{recipe_seed or key}"),
        response_schema_sha256=response_schema_sha256,
        **(
            scheduler_test_model_fields(f"model-task:{key}")
            if kind is SchedulerTaskKind.MODEL_REQUEST
            else {}
        ),
    )


def _tasks_for_pass(
    manifest: SchedulerCampaignManifest,
    pass_kind: SchedulerPassKind,
    workset: SchedulerCandidateWorkset | None = None,
) -> tuple[SchedulerTaskPlan, ...]:
    if pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW:
        return tuple(
            _task(
                manifest,
                pass_kind,
                key=f"blind:{shard_id}",
                kind=SchedulerTaskKind.MODEL_REQUEST,
                scope=SchedulerScope.single_shard(shard_id),
            )
            for shard_id in reversed(manifest.shard_ids)
        )
    if pass_kind is SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION:
        assert workset is not None
        return tuple(
            _task(
                manifest,
                pass_kind,
                key=f"cross:{candidate_id}:{index}",
                kind=SchedulerTaskKind.MODEL_REQUEST,
                role=(
                    "candidate_falsifier:"
                    + hashlib.sha256(candidate_id.encode()).hexdigest()
                    + f":reviewer_{index}"
                ),
                candidate_ids=(candidate_id,),
            )
            for candidate_id in workset.selected_candidate_ids
            for index in (1, 2)
        )
    if pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION:
        assert workset is not None
        return (
            _task(
                manifest,
                pass_kind,
                key="validation:verifier",
                kind=SchedulerTaskKind.MODEL_REQUEST,
                role="verifier",
                candidate_ids=workset.selected_candidate_ids,
            ),
            _task(
                manifest,
                pass_kind,
                key="validation:candidate-falsifier-1",
                kind=SchedulerTaskKind.MODEL_REQUEST,
                role="candidate_falsifier",
                candidate_ids=workset.selected_candidate_ids,
            ),
            _task(
                manifest,
                pass_kind,
                key="validation:candidate-falsifier-2",
                kind=SchedulerTaskKind.MODEL_REQUEST,
                role="candidate_falsifier",
                candidate_ids=workset.selected_candidate_ids,
            ),
        )
    if pass_kind in _MODEL_ROLES:
        return (
            _task(
                manifest,
                pass_kind,
                key=pass_kind.value,
                kind=SchedulerTaskKind.MODEL_REQUEST,
            ),
        )
    return (
        _task(
            manifest,
            pass_kind,
            key=pass_kind.value,
            kind=SchedulerTaskKind.HOST_COMPUTATION,
        ),
    )


def _activation(
    plan: SchedulerPassPlan,
    task: SchedulerTaskPlan,
    *,
    seed: str = "runtime",
    upstream: Iterable[str] = (),
    candidate_ids: tuple[str, ...] = ("candidate-critical",),
) -> SchedulerTaskActivation:
    if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
        return SchedulerTaskActivation.build(
            plan=plan,
            task=task,
            actual_input_sha256=_sha256(f"{seed}:input:{task.task_id}"),
            system_prompt_sha256=task.system_prompt_sha256,
            user_prompt_sha256=_sha256(f"{seed}:user:{task.task_id}"),
            provider_prompt_sha256=_sha256(f"{seed}:provider:{task.task_id}"),
            response_schema_sha256=task.response_schema_sha256,
            delivered_source_descriptor_sha256s=(
                scheduler_test_delivered_source_descriptor_sha256s(plan, task)
            ),
            upstream_task_result_sha256s=upstream,
        )
    return SchedulerTaskActivation.build(
        plan=plan,
        task=task,
        actual_input_sha256=(
            scheduler_test_host_activation_input_sha256(
                plan,
                task,
                candidate_ids=candidate_ids,
            )
            if task.task_kind is SchedulerTaskKind.HOST_COMPUTATION
            else _sha256(f"{seed}:input:{task.task_id}")
        ),
        upstream_task_result_sha256s=upstream,
    )


@dataclass(frozen=True)
class _PassBundle:
    plan: SchedulerPassPlan
    activations: tuple[SchedulerTaskActivation, ...]
    outputs: tuple[SchedulerTaskOutput, ...]
    task_results: tuple[SchedulerTaskResult, ...]
    result: SchedulerPassResult


def _pass_bundle(
    manifest: SchedulerCampaignManifest,
    pass_kind: SchedulerPassKind,
    prior: Iterable[_PassBundle],
    *,
    terminal_status: SchedulerTerminalStatus = SchedulerTerminalStatus.SUCCEEDED,
    empty: bool = False,
    candidate_ids: tuple[str, ...] = ("candidate-critical",),
) -> _PassBundle:
    prior_bundles = tuple(prior)
    dependencies = tuple(
        SchedulerPassDependency.from_result(bundle.result) for bundle in prior_bundles
    )
    conditional_absence = None
    candidate_workset = None
    if pass_kind in {
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
    }:
        source_bundle = next(
            bundle
            for bundle in prior_bundles
            if bundle.plan.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        )
        source_result = next(
            result
            for result in source_bundle.task_results
            if next(
                task for task in source_bundle.plan.tasks if task.task_id == result.task_id
            ).role
            == "host:cross_shard_integrator"
        )
        source_output = next(
            output for output in source_bundle.outputs if output.task_id == source_result.task_id
        )
        candidate_workset = SchedulerCandidateWorkset.build(
            pass_kind=pass_kind,
            source_pass_result=source_bundle.result,
            source_result=source_result,
            source_output=source_output,
        )
    tasks: tuple[SchedulerTaskPlan, ...]
    if empty:
        task = _task(
            manifest,
            pass_kind,
            key=f"{pass_kind.value}:empty",
            kind=SchedulerTaskKind.EMPTY_COMPLETION,
        )
        tasks = (task,)
        reason = {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION: (
                SchedulerAbsenceReason.NO_HIGH_CRITICAL_CANDIDATES
            ),
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION: (
                SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES
            ),
        }[pass_kind]
        conditional_absence = SchedulerConditionalAbsence.build(
            reason=reason,
            candidate_workset=candidate_workset,
        )
    else:
        tasks = _tasks_for_pass(manifest, pass_kind, candidate_workset)
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=pass_kind,
        dependencies=dependencies,
        tasks=reversed(tasks),
        candidate_workset=candidate_workset,
        conditional_absence=conditional_absence,
    )
    activations: list[SchedulerTaskActivation] = []
    outputs: list[SchedulerTaskOutput] = []
    results: list[SchedulerTaskResult] = []
    for task in plan.tasks:
        activation = _activation(
            plan,
            task,
            upstream=(
                (candidate_workset.source_result_sha256,)
                if task.task_kind is SchedulerTaskKind.EMPTY_COMPLETION
                and candidate_workset is not None
                else ()
            ),
            candidate_ids=candidate_ids,
        )
        activations.append(activation)
        status = (
            SchedulerTerminalStatus.EXPLICIT_EMPTY
            if task.task_kind is SchedulerTaskKind.EMPTY_COMPLETION
            else terminal_status
        )
        output = None
        usage = None
        surface_requests = ()
        surface_artifact = None
        if status is SchedulerTerminalStatus.SUCCEEDED:
            if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
                payload = build_scheduler_test_model_payload(plan, task)
                usage = build_scheduler_test_usage(
                    task,
                    activation,
                    validated_output=payload,
                )
                surface_requests, surface_artifact = (
                    build_scheduler_test_model_surface_review_custody(
                        plan,
                        task,
                        activation,
                        usage,
                        payload,
                    )
                )
            elif task.task_kind is SchedulerTaskKind.HOST_COMPUTATION:
                payload = build_scheduler_test_host_payload(
                    plan,
                    task,
                    candidate_ids=candidate_ids,
                )
            else:
                payload = {"reviewed": True, "task_id": task.task_id}
            output = SchedulerTaskOutput.build(
                plan=plan,
                task=task,
                activation=activation,
                payload=payload,
                usage_record=usage,
                model_surface_review_requests=surface_requests,
                model_surface_review_artifact=surface_artifact,
            )
            outputs.append(output)
        results.append(
            SchedulerTaskResult.build(
                plan=plan,
                task=task,
                activation=activation,
                terminal_status=status,
                terminal_evidence_sha256=(
                    usage.validated_response_sha256
                    if usage is not None and usage.validated_response_sha256 is not None
                    else _sha256(f"terminal:{task.task_id}:{status.value}")
                ),
                output=output,
            )
        )
    pass_result = SchedulerPassResult.build(plan=plan, task_results=results)
    return _PassBundle(
        plan=plan,
        activations=tuple(activations),
        outputs=tuple(outputs),
        task_results=tuple(results),
        result=pass_result,
    )


def _complete_campaign(manifest: SchedulerCampaignManifest) -> tuple[_PassBundle, ...]:
    bundles: list[_PassBundle] = []
    for pass_kind in SCHEDULER_PASS_ORDER:
        bundles.append(_pass_bundle(manifest, pass_kind, bundles))
    return tuple(bundles)


def _events(bundles: Iterable[_PassBundle]) -> tuple[SchedulerTaskEvent, ...]:
    events: list[SchedulerTaskEvent] = []
    for bundle in bundles:
        activation_by_task = {item.task_id: item for item in bundle.activations}
        result_by_task = {item.task_id: item for item in bundle.task_results}
        for task in bundle.plan.tasks:
            previous = events[-1] if events else None
            planned = SchedulerTaskEvent.build(
                plan=bundle.plan,
                task=task,
                kind=SchedulerTaskEventKind.PLANNED,
                event_index=len(events),
                previous_event=previous,
            )
            events.append(planned)
            activation = activation_by_task[task.task_id]
            activated = SchedulerTaskEvent.build(
                plan=bundle.plan,
                task=task,
                kind=SchedulerTaskEventKind.ACTIVATED,
                event_index=len(events),
                previous_event=events[-1],
                prior_task_event=planned,
                activation=activation,
            )
            events.append(activated)
            dispatched = SchedulerTaskEvent.build(
                plan=bundle.plan,
                task=task,
                kind=SchedulerTaskEventKind.DISPATCHED,
                event_index=len(events),
                previous_event=events[-1],
                prior_task_event=activated,
                activation=activation,
                request_id=task.logical_request_id,
            )
            events.append(dispatched)
            events.append(
                SchedulerTaskEvent.build(
                    plan=bundle.plan,
                    task=task,
                    kind=SchedulerTaskEventKind.TERMINAL,
                    event_index=len(events),
                    previous_event=events[-1],
                    prior_task_event=dispatched,
                    activation=activation,
                    request_id=task.logical_request_id,
                    result=result_by_task[task.task_id],
                )
            )
    return tuple(events)


def _journal_evidence(
    manifest: SchedulerCampaignManifest,
    bundles: Iterable[_PassBundle],
) -> tuple[SchedulerCampaignSummary, SchedulerJournalEvidence]:
    exact_bundles = tuple(bundles)
    summary = SchedulerCampaignSummary.build(
        manifest=manifest,
        pass_results=(bundle.result for bundle in exact_bundles),
    )
    activations = tuple(item for bundle in exact_bundles for item in bundle.activations)
    outputs = tuple(item for bundle in exact_bundles for item in bundle.outputs)
    results = tuple(item for bundle in exact_bundles for item in bundle.task_results)
    model_requests = build_scheduler_model_request_evidence(
        plans=(bundle.plan for bundle in exact_bundles),
        activations=activations,
        task_results=results,
    )
    evidence = SchedulerJournalEvidence.build(
        manifest=manifest,
        analysis_input_inventory=_analysis_inventory(),
        summary=summary,
        plans=(bundle.plan for bundle in exact_bundles),
        model_requests=model_requests,
        activations=activations,
        outputs=outputs,
        task_results=results,
        result_observations=results,
        events=_events(exact_bundles),
    )
    return summary, evidence


def test_closed_pass_order_and_absent_commitments_are_stable() -> None:
    assert tuple(SchedulerPassKind) == SCHEDULER_PASS_ORDER
    assert len(ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256) == 64
    assert len(ABSENT_QUALIFICATION_SHA256) == 64
    assert (
        scheduler_canonical_sha256(
            {"domain": "mmaudit.scheduler.absent-production-qualification.v1"}
        )
        == ABSENT_QUALIFICATION_SHA256
    )


def test_inventory_binds_every_mixed_source_and_campaign_uses_exact_descriptors() -> None:
    inventory = _inventory()
    privacy_custody = _privacy_custody(inventory)
    assert inventory.source_count == 3
    assert inventory.source_tree_sha256 == scheduler_source_tree_sha256(
        source for shard in inventory.shards for source in shard.sources
    )
    assert {item.kind for item in inventory.shards} == {
        SchedulerShardKind.SOLIDITY_SEMANTIC,
        SchedulerShardKind.REPOSITORY_PSEUDO,
    }
    manifest = SchedulerCampaignManifest.build(
        bindings=_bindings(inventory=inventory),
        shard_inventory=inventory,
        privacy_evidence_custody=privacy_custody,
    )
    assert manifest.shard_ids == inventory.shard_ids
    assert manifest.shard_inventory == inventory


def test_non_solidity_inventory_uses_one_deterministic_pseudo_shard() -> None:
    source = _source("src/service.py")
    pseudo = SchedulerShardDescriptor.repository_pseudo(sources=(source,))
    inventory = SchedulerShardInventory.build(
        semantic_inventory_sha256=ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256,
        shards=(pseudo,),
    )
    assert pseudo.shard_id == repository_pseudo_shard_id(scheduler_source_tree_sha256((source,)))
    assert inventory.shard_ids == (pseudo.shard_id,)


def test_inventory_rejects_duplicate_source_assignment_and_wrong_source_kind() -> None:
    source = _source("src/Alpha.sol")
    first = SchedulerShardDescriptor.semantic(
        shard_id=_shard(1),
        semantic_shard_sha256=_sha256("first"),
        sources=(source,),
    )
    second = SchedulerShardDescriptor.semantic(
        shard_id=_shard(2),
        semantic_shard_sha256=_sha256("second"),
        sources=(source,),
    )
    with pytest.raises(ValidationError, match="exactly one"):
        SchedulerShardInventory.build(
            semantic_inventory_sha256=_sha256("semantic"),
            shards=(first, second),
        )
    with pytest.raises(ValidationError, match="non-Solidity"):
        SchedulerShardDescriptor.repository_pseudo(sources=(source,))


def test_inventory_and_campaign_are_stable_under_descriptor_reordering() -> None:
    inventory = _inventory()
    reordered = SchedulerShardInventory.build(
        semantic_inventory_sha256=inventory.semantic_inventory_sha256,
        shards=reversed(inventory.shards),
    )
    assert reordered == inventory
    privacy_custody = _privacy_custody(inventory)
    left = SchedulerCampaignManifest.build(
        bindings=_bindings(inventory=inventory),
        shard_inventory=inventory,
        privacy_evidence_custody=privacy_custody,
    )
    right = SchedulerCampaignManifest.build(
        bindings=_bindings(inventory=reordered),
        shard_inventory=reordered,
        privacy_evidence_custody=privacy_custody,
    )
    assert left == right


def test_campaign_rejects_bindings_detached_from_inventory() -> None:
    inventory = _inventory()
    detached = SchedulerBindings.build(
        source_sha256=_sha256("wrong-source"),
        analysis_input_sha256=_sha256("analysis-input"),
        effective_config_sha256=_sha256("config"),
        shard_inventory_sha256=inventory.inventory_sha256,
        model_selection_sha256=_sha256("models"),
        qualification_sha256=_sha256("qualification"),
        prompt_set_sha256=_sha256("prompts"),
        schema_set_sha256=_sha256("schemas"),
        tool_policy_sha256=_sha256("tools"),
    )
    with pytest.raises(ValidationError, match="exact shard inventory"):
        SchedulerCampaignManifest.build(
            bindings=detached,
            shard_inventory=inventory,
        )


def test_scope_shapes_are_explicit_canonical_and_self_hashed() -> None:
    assert SchedulerScope.global_scope().kind is SchedulerScopeKind.GLOBAL
    assert SchedulerScope.single_shard(_shard(1)).shard_ids == (_shard(1),)
    assert SchedulerScope.shard_set((_shard(2), _shard(1))).shard_ids == (
        _shard(1),
        _shard(2),
    )
    with pytest.raises(ValidationError, match="global"):
        SchedulerScope.build(SchedulerScopeKind.GLOBAL, (_shard(1),))
    with pytest.raises(ValidationError, match="at least two"):
        SchedulerScope.build(SchedulerScopeKind.SHARD_SET, (_shard(1),))


def test_task_plan_identity_is_stable_while_activation_binds_dynamic_inputs() -> None:
    manifest = _manifest()
    task = _tasks_for_pass(manifest, SchedulerPassKind.ORIENTATION)[0]
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.ORIENTATION,
        dependencies=(),
        tasks=(task,),
    )
    first = _activation(plan, task, seed="first", upstream=(_sha256("b"), _sha256("a")))
    second = _activation(plan, task, seed="second", upstream=(_sha256("a"), _sha256("b")))
    assert first.task_id == second.task_id == task.task_id
    assert first.logical_request_id == second.logical_request_id == task.logical_request_id
    assert first.activation_id != second.activation_id
    assert first.upstream_task_result_sha256s == tuple(sorted((_sha256("a"), _sha256("b"))))


def test_activation_requires_exact_provider_material_and_schema_for_model_only() -> None:
    manifest = _manifest()
    task = _tasks_for_pass(manifest, SchedulerPassKind.ORIENTATION)[0]
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.ORIENTATION,
        dependencies=(),
        tasks=(task,),
    )
    with pytest.raises(ValueError, match="provider hashes differ"):
        SchedulerTaskActivation.build(
            plan=plan,
            task=task,
            actual_input_sha256=_sha256("input"),
        )
    with pytest.raises(ValueError, match="provider material"):
        SchedulerTaskActivation.build(
            plan=plan,
            task=task,
            actual_input_sha256=_sha256("input"),
            system_prompt_sha256=task.system_prompt_sha256,
            user_prompt_sha256=_sha256("user"),
            provider_prompt_sha256=_sha256("provider"),
            response_schema_sha256=_sha256("wrong-schema"),
        )


def test_result_and_normalized_output_bind_the_exact_activation() -> None:
    bundle = _pass_bundle(_manifest(), SchedulerPassKind.ORIENTATION, ())
    result = bundle.task_results[0]
    output = bundle.outputs[0]
    activation = bundle.activations[0]
    assert result.activation_sha256 == activation.activation_sha256
    assert result.output_artifact_sha256 == output.output_artifact_sha256
    assert output.output_sha256 == scheduler_canonical_sha256(output.payload)

    changed = _activation(bundle.plan, bundle.plan.tasks[0], seed="changed")
    with pytest.raises(ValueError, match="differs from its exact task activation"):
        output.require_exact_activation(changed)


def test_model_output_must_equal_exact_provider_validated_response() -> None:
    bundle = _pass_bundle(_manifest("provider-output-binding"), SchedulerPassKind.ORIENTATION, ())
    task = bundle.plan.tasks[0]
    activation = bundle.activations[0]
    provider_output = build_scheduler_test_model_payload(bundle.plan, task)
    substituted_output = provider_output.model_copy(
        update={"review_targets": ["host-substituted synthetic invariant"]}
    )
    usage = build_scheduler_test_usage(
        task,
        activation,
        validated_output=provider_output,
    )
    with pytest.raises(ValueError, match="exact provider-validated response"):
        SchedulerTaskOutput.build(
            plan=bundle.plan,
            task=task,
            activation=activation,
            payload=substituted_output,
            usage_record=usage,
        )


def test_workflow_context_hash_is_distinct_from_whole_user_prompt_hash() -> None:
    fixture = build_complete_scheduler_fixture(seed="workflow-context-hash")
    activations = {item.task_id: item for item in fixture.activations}
    workflow_outputs = tuple(
        output
        for output in fixture.outputs
        if next(
            plan for plan in fixture.plans if plan.pass_plan_id == output.pass_plan_id
        ).pass_kind
        in {
            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
            SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        }
    )
    assert workflow_outputs
    for output in workflow_outputs:
        completion = output.model_completion_evidence
        assert completion is not None
        assert (
            completion.context_request_evidence.rendered_sha256
            != activations[output.task_id].user_prompt_sha256
        )


def test_preflight_failure_is_typed_terminal_and_can_never_credit_success() -> None:
    manifest = _manifest()
    task = _tasks_for_pass(manifest, SchedulerPassKind.ORIENTATION)[0]
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.ORIENTATION,
        dependencies=(),
        tasks=(task,),
    )
    failed = SchedulerTaskResult.build_preflight_failure(
        plan=plan,
        task=task,
        terminal_status=SchedulerTerminalStatus.FAILED,
        terminal_evidence_sha256=_sha256("preflight"),
    )
    assert failed.result_origin is SchedulerResultOrigin.LOCAL_PREFLIGHT
    assert failed.activation_sha256 is None
    with pytest.raises(ValueError, match="must fail closed"):
        SchedulerTaskResult.build_preflight_failure(
            plan=plan,
            task=task,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=_sha256("false-success"),
        )


def test_pass_plan_requires_every_exact_prior_result_dependency() -> None:
    manifest = _manifest()
    orientation = _pass_bundle(manifest, SchedulerPassKind.ORIENTATION, ())
    with pytest.raises(ValidationError, match="every exact prior"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            dependencies=(),
            tasks=_tasks_for_pass(manifest, SchedulerPassKind.BLIND_SHARD_REVIEW),
        )
    assert SchedulerPassDependency.from_result(orientation.result).pass_result_sha256 == (
        orientation.result.pass_result_sha256
    )


def test_orientation_requires_substantive_threat_model_and_never_empty_or_host_only() -> None:
    manifest = _manifest()
    host = _task(
        manifest,
        SchedulerPassKind.ORIENTATION,
        key="host-only",
        kind=SchedulerTaskKind.HOST_COMPUTATION,
        role="host:orientation",
    )
    with pytest.raises(ValidationError, match="threat-model"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.ORIENTATION,
            dependencies=(),
            tasks=(host,),
        )
    empty = _task(
        manifest,
        SchedulerPassKind.ORIENTATION,
        key="empty",
        kind=SchedulerTaskKind.EMPTY_COMPLETION,
    )
    with pytest.raises(ValidationError, match="typed absence"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.ORIENTATION,
            dependencies=(),
            tasks=(empty,),
        )
    threat_model = _task(
        manifest,
        SchedulerPassKind.ORIENTATION,
        key="threat-model",
        kind=SchedulerTaskKind.MODEL_REQUEST,
        role="threat_model",
    )
    early_specialist = _task(
        manifest,
        SchedulerPassKind.ORIENTATION,
        key="early-specialist",
        kind=SchedulerTaskKind.MODEL_REQUEST,
        role="specialist:access_control",
    )
    with pytest.raises(ValidationError, match="exactly one global threat-model"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.ORIENTATION,
            dependencies=(),
            tasks=(threat_model, early_specialist),
        )


def test_blind_pass_requires_model_source_audit_for_every_exact_shard() -> None:
    manifest = _manifest()
    orientation = _pass_bundle(manifest, SchedulerPassKind.ORIENTATION, ())
    dependency = (SchedulerPassDependency.from_result(orientation.result),)
    tasks = _tasks_for_pass(manifest, SchedulerPassKind.BLIND_SHARD_REVIEW)
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        dependencies=dependency,
        tasks=tasks,
    )
    assert {task.scope.shard_ids[0] for task in plan.tasks} == set(manifest.shard_ids)
    whole_protocol = _task(
        manifest,
        SchedulerPassKind.BLIND_SHARD_REVIEW,
        key="whole-protocol-0",
        kind=SchedulerTaskKind.MODEL_REQUEST,
        role="whole_protocol_review:0",
        scope=SchedulerScope.global_scope(),
    )
    plan_with_whole_protocol = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        dependencies=dependency,
        tasks=(*tasks, whole_protocol),
    )
    assert whole_protocol.task_id in {task.task_id for task in plan_with_whole_protocol.tasks}
    with pytest.raises(ValidationError, match="exact shard inventory"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            dependencies=dependency,
            tasks=tasks[:-1],
        )
    host = _task(
        manifest,
        SchedulerPassKind.BLIND_SHARD_REVIEW,
        key="host",
        kind=SchedulerTaskKind.HOST_COMPUTATION,
        scope=SchedulerScope.single_shard(manifest.shard_ids[0]),
    )
    with pytest.raises(ValidationError, match="only single-shard model"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
            dependencies=dependency,
            tasks=(*tasks, host),
        )


def test_blind_source_review_inconclusive_dispositions_never_earn_source_custody() -> None:
    manifest = _manifest("inconclusive-blind-source")
    orientation = _pass_bundle(manifest, SchedulerPassKind.ORIENTATION, ())
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        dependencies=(SchedulerPassDependency.from_result(orientation.result),),
        tasks=_tasks_for_pass(manifest, SchedulerPassKind.BLIND_SHARD_REVIEW),
    )
    task = next(task for task in plan.tasks if task.role == "source_audit")
    activation = _activation(plan, task, seed="inconclusive-blind-source")
    payload = build_scheduler_test_model_payload(plan, task)
    assert isinstance(payload, CandidateReviewBatch)
    inconclusive = payload.model_copy(
        update={
            "surface_reviews": tuple(
                record.model_copy(update={"status": ModelSurfaceReviewStatus.INCONCLUSIVE})
                for record in payload.surface_reviews
            )
        }
    )
    usage = build_scheduler_test_usage(task, activation, validated_output=inconclusive)
    requests, artifact = build_scheduler_test_model_surface_review_custody(
        plan,
        task,
        activation,
        usage,
        inconclusive,
    )

    with pytest.raises(ValueError, match="did not substantively cover every scoped source"):
        SchedulerTaskOutput.build(
            plan=plan,
            task=task,
            activation=activation,
            payload=inconclusive,
            usage_record=usage,
            model_surface_review_requests=requests,
            model_surface_review_artifact=artifact,
        )


@pytest.mark.parametrize(
    ("pass_kind", "required_role"),
    [
        (SchedulerPassKind.FINDING_REDUCTION, "host:finding_reducer"),
        (SchedulerPassKind.CROSS_SHARD_INTEGRATION, "host:cross_shard_integrator"),
        (SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT, "host:evidence_cap_judgment"),
    ],
)
def test_structural_passes_require_their_exact_host_authority(
    pass_kind: SchedulerPassKind,
    required_role: str,
) -> None:
    manifest = _manifest()
    bundles: list[_PassBundle] = []
    for kind in SCHEDULER_PASS_ORDER[: SCHEDULER_PASS_ORDER.index(pass_kind)]:
        bundles.append(_pass_bundle(manifest, kind, bundles))
    wrong = _task(
        manifest,
        pass_kind,
        key="wrong-host",
        kind=SchedulerTaskKind.HOST_COMPUTATION,
        role="host:generic",
    )
    with pytest.raises(ValidationError, match=required_role):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=pass_kind,
            dependencies=tuple(
                SchedulerPassDependency.from_result(bundle.result) for bundle in bundles
            ),
            tasks=(wrong,),
        )


def test_cross_shard_boundary_requires_exact_surface_and_both_sources_delivered() -> None:
    manifest = _manifest("boundary-delivery")
    prior: list[_PassBundle] = []
    for kind in SCHEDULER_PASS_ORDER[:3]:
        prior.append(_pass_bundle(manifest, kind, prior))
    dependencies = tuple(SchedulerPassDependency.from_result(bundle.result) for bundle in prior)
    host = _task(
        manifest,
        SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        key="boundary-host",
        kind=SchedulerTaskKind.HOST_COMPUTATION,
        role="host:cross_shard_integrator",
    )
    surface_id = ModelSurfaceReviewRequest.calculate_surface_id(
        ModelReviewSurfaceKind.INVARIANT,
        "cross-shard:boundary-review",
    )
    boundary = _task(
        manifest,
        SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        key="boundary-review",
        kind=SchedulerTaskKind.MODEL_REQUEST,
        role="business_logic",
        scope=SchedulerScope.shard_set(manifest.shard_ids[:2]),
        candidate_ids=(surface_id,),
    )
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        dependencies=dependencies,
        tasks=(host, boundary),
    )
    activation = _activation(plan, boundary, seed="boundary-complete")
    payload = build_scheduler_test_model_payload(plan, boundary)
    usage = build_scheduler_test_usage(boundary, activation, validated_output=payload)
    requests, artifact = build_scheduler_test_model_surface_review_custody(
        plan,
        boundary,
        activation,
        usage,
        payload,
    )
    output = SchedulerTaskOutput.build(
        plan=plan,
        task=boundary,
        activation=activation,
        payload=payload,
        usage_record=usage,
        model_surface_review_requests=requests,
        model_surface_review_artifact=artifact,
    )
    assert output.reviewed_candidate_ids == (surface_id,)

    delivered = scheduler_test_delivered_source_descriptor_sha256s(plan, boundary)
    assert len(delivered) >= 2
    partial_activation = SchedulerTaskActivation.build(
        plan=plan,
        task=boundary,
        actual_input_sha256=_sha256("boundary-partial-input"),
        system_prompt_sha256=boundary.system_prompt_sha256,
        user_prompt_sha256=_sha256("boundary-partial-user"),
        provider_prompt_sha256=_sha256("boundary-partial-provider"),
        response_schema_sha256=boundary.response_schema_sha256,
        delivered_source_descriptor_sha256s=delivered[:-1],
    )
    partial_usage = build_scheduler_test_usage(
        boundary,
        partial_activation,
        validated_output=payload,
    )
    with pytest.raises(ValueError, match="exact full-source delivery"):
        partial_requests, partial_artifact = build_scheduler_test_model_surface_review_custody(
            plan,
            boundary,
            partial_activation,
            partial_usage,
            payload,
        )
        SchedulerTaskOutput.build(
            plan=plan,
            task=boundary,
            activation=partial_activation,
            payload=payload,
            usage_record=partial_usage,
            model_surface_review_requests=partial_requests,
            model_surface_review_artifact=partial_artifact,
        )

    omitted = payload.model_copy(update={"surface_reviews": ()})
    omitted_usage = build_scheduler_test_usage(
        boundary,
        activation,
        validated_output=omitted,
    )
    with pytest.raises(ValueError, match="surface"):
        SchedulerTaskOutput.build(
            plan=plan,
            task=boundary,
            activation=activation,
            payload=omitted,
            usage_record=omitted_usage,
            model_surface_review_requests=requests,
            model_surface_review_artifact=artifact,
        )

    unbound_boundary = _task(
        manifest,
        SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        key="unbound-boundary-review",
        kind=SchedulerTaskKind.MODEL_REQUEST,
        role="business_logic",
        scope=SchedulerScope.shard_set(manifest.shard_ids[:2]),
    )
    with pytest.raises(ValidationError, match="one exact boundary surface"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
            dependencies=dependencies,
            tasks=(host, unbound_boundary),
        )


def test_pass_six_requires_two_independent_falsifier_lineages_per_candidate() -> None:
    manifest = _manifest("two-falsifiers")
    prior: list[_PassBundle] = []
    for kind in SCHEDULER_PASS_ORDER[:5]:
        prior.append(_pass_bundle(manifest, kind, prior))
    valid = _pass_bundle(
        manifest,
        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
        prior,
    ).plan
    falsifiers = tuple(task for task in valid.tasks if task.role == "candidate_falsifier")
    assert len(falsifiers) == 2
    with pytest.raises(ValidationError, match="two independent falsifier lineages"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            dependencies=valid.dependencies,
            tasks=tuple(task for task in valid.tasks if task != falsifiers[-1]),
            candidate_workset=valid.candidate_workset,
        )


def test_conditional_empty_is_closed_to_passes_five_and_six_and_exact_dependency() -> None:
    manifest = _manifest()
    bundles: list[_PassBundle] = []
    for kind in SCHEDULER_PASS_ORDER[:4]:
        bundles.append(
            _pass_bundle(
                manifest,
                kind,
                bundles,
                candidate_ids=(
                    ()
                    if kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
                    else ("candidate-critical",)
                ),
            )
        )
    empty_five = _pass_bundle(
        manifest,
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
        bundles,
        empty=True,
    )
    assert empty_five.result.status is SchedulerPassStatus.COMPLETE
    assert empty_five.task_results[0].terminal_status is SchedulerTerminalStatus.EXPLICIT_EMPTY

    with pytest.raises(ValidationError, match="not permitted"):
        SchedulerConditionalAbsence.build(
            reason=SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES,
            candidate_workset=empty_five.plan.candidate_workset,
        )


def test_nonempty_downstream_pass_requires_substantive_model_request() -> None:
    manifest = _manifest()
    bundles: list[_PassBundle] = []
    for kind in SCHEDULER_PASS_ORDER[:4]:
        bundles.append(_pass_bundle(manifest, kind, bundles))
    host = _task(
        manifest,
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
        key="host-only",
        kind=SchedulerTaskKind.HOST_COMPUTATION,
    )
    valid_five = _pass_bundle(
        manifest,
        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
        bundles,
    )
    with pytest.raises(ValidationError, match="one exact model review"):
        SchedulerPassPlan.build(
            manifest=manifest,
            pass_kind=SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
            dependencies=tuple(
                SchedulerPassDependency.from_result(bundle.result) for bundle in bundles
            ),
            tasks=(host,),
            candidate_workset=valid_five.plan.candidate_workset,
        )


@pytest.mark.parametrize(
    ("terminal_status", "expected_pass_status"),
    [
        (SchedulerTerminalStatus.FAILED, SchedulerPassStatus.FAILED),
        (SchedulerTerminalStatus.INVALID, SchedulerPassStatus.FAILED),
        (SchedulerTerminalStatus.UNBOUND, SchedulerPassStatus.FAILED),
        (SchedulerTerminalStatus.TRUNCATED, SchedulerPassStatus.INCOMPLETE),
        (SchedulerTerminalStatus.UNCERTAIN, SchedulerPassStatus.INCOMPLETE),
        (SchedulerTerminalStatus.INCONCLUSIVE, SchedulerPassStatus.INCONCLUSIVE),
    ],
)
def test_nonqualifying_terminal_statuses_never_complete_a_pass(
    terminal_status: SchedulerTerminalStatus,
    expected_pass_status: SchedulerPassStatus,
) -> None:
    bundle = _pass_bundle(
        _manifest(),
        SchedulerPassKind.ORIENTATION,
        (),
        terminal_status=terminal_status,
    )
    assert bundle.result.status is expected_pass_status
    assert bundle.result.status is not SchedulerPassStatus.COMPLETE


def test_campaign_completion_requires_all_seven_closed_passes() -> None:
    manifest = _manifest()
    bundles = _complete_campaign(manifest)
    complete = SchedulerCampaignSummary.build(
        manifest=manifest,
        pass_results=(bundle.result for bundle in reversed(bundles)),
    )
    assert complete.status is SchedulerCampaignStatus.COMPLETE
    assert complete.completed_passes == SCHEDULER_PASS_ORDER


def test_event_lifecycle_requires_activation_before_dispatch_and_terminal() -> None:
    bundle = _pass_bundle(_manifest(), SchedulerPassKind.ORIENTATION, ())
    plan = bundle.plan
    task = plan.tasks[0]
    activation = bundle.activations[0]
    result = bundle.task_results[0]
    planned = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.PLANNED,
        event_index=0,
    )
    with pytest.raises(ValueError, match="prior task event"):
        SchedulerTaskEvent.build(
            plan=plan,
            task=task,
            kind=SchedulerTaskEventKind.DISPATCHED,
            event_index=1,
            previous_event=planned,
            prior_task_event=planned,
            activation=activation,
            request_id=task.logical_request_id,
        )
    activated = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.ACTIVATED,
        event_index=1,
        previous_event=planned,
        prior_task_event=planned,
        activation=activation,
    )
    dispatched = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.DISPATCHED,
        event_index=2,
        previous_event=activated,
        prior_task_event=activated,
        activation=activation,
        request_id=task.logical_request_id,
    )
    terminal = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.TERMINAL,
        event_index=3,
        previous_event=dispatched,
        prior_task_event=dispatched,
        activation=activation,
        request_id=task.logical_request_id,
        result=result,
    )
    assert terminal.task_result_sha256 == result.result_sha256


def test_plan_task_index_preserves_exact_same_id_membership_semantics() -> None:
    bundle = _pass_bundle(_manifest(), SchedulerPassKind.ORIENTATION, ())
    plan = bundle.plan
    task = plan.tasks[0]
    altered = task.model_copy(update={"role": "falsifier"})
    assert altered.task_id == task.task_id
    assert plan.has_exact_task(task)
    assert not plan.has_exact_task(altered)

    with pytest.raises(ValueError, match="not in the sealed pass plan"):
        SchedulerTaskEvent.build(
            plan=plan,
            task=altered,
            kind=SchedulerTaskEventKind.PLANNED,
            event_index=0,
        )

    copied = plan.model_copy(update={"tasks": (altered,)})
    assert copied.has_exact_task(altered)
    assert not copied.has_exact_task(task)


def test_preflight_terminal_event_closes_planned_task_without_activation() -> None:
    manifest = _manifest()
    task = _tasks_for_pass(manifest, SchedulerPassKind.ORIENTATION)[0]
    plan = SchedulerPassPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.ORIENTATION,
        dependencies=(),
        tasks=(task,),
    )
    result = SchedulerTaskResult.build_preflight_failure(
        plan=plan,
        task=task,
        terminal_status=SchedulerTerminalStatus.INVALID,
        terminal_evidence_sha256=_sha256("preflight-invalid"),
    )
    planned = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.PLANNED,
        event_index=0,
    )
    terminal = SchedulerTaskEvent.build(
        plan=plan,
        task=task,
        kind=SchedulerTaskEventKind.PREFLIGHT_TERMINAL,
        event_index=1,
        previous_event=planned,
        prior_task_event=planned,
        result=result,
    )
    assert terminal.activation_id is None
    assert terminal.task_result_sha256 == result.result_sha256


def test_complete_public_artifact_requires_full_journal_and_report_binding() -> None:
    manifest = _manifest()
    bundles = _complete_campaign(manifest)
    summary, evidence = _journal_evidence(manifest, bundles)
    artifact = SchedulerArtifact.build(
        summary=summary,
        journal_evidence=evidence,
        model_requests=build_scheduler_model_request_evidence(
            plans=(bundle.plan for bundle in bundles),
            activations=(item for bundle in bundles for item in bundle.activations),
            task_results=(item for bundle in bundles for item in bundle.task_results),
        ),
    )
    binding = SchedulerReportBinding.from_artifact(artifact)
    binding.require_exact(artifact)
    assert binding.status is SchedulerCampaignStatus.COMPLETE
    assert binding.pass_result_count == 7
    assert binding.planned_task_count == binding.terminal_task_count
    assert binding.activated_task_count == binding.planned_task_count
    assert binding.task_output_count == binding.succeeded_count
    assert binding.event_chain_head_sha256 == evidence.event_sha256s[-1]


def test_reusable_complete_fixture_exposes_actual_hash_only_model_requests() -> None:
    fixture = build_complete_scheduler_fixture(seed="public-model-projection")
    assert fixture.summary.status is SchedulerCampaignStatus.COMPLETE
    assert len(fixture.artifact.model_requests) == fixture.journal_evidence.model_request_count
    assert all(item.user_prompt_sha256 is not None for item in fixture.artifact.model_requests)
    assert all(item.result_sha256 is not None for item in fixture.artifact.model_requests)


def test_summary_only_or_incomplete_journal_cannot_publish_complete_artifact() -> None:
    manifest = _manifest()
    bundles = _complete_campaign(manifest)
    summary = SchedulerCampaignSummary.build(
        manifest=manifest,
        pass_results=(bundle.result for bundle in bundles),
    )
    with pytest.raises(TypeError):
        SchedulerArtifact.build(summary=summary)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="PLANNED event"):
        SchedulerJournalEvidence.build(
            manifest=manifest,
            analysis_input_inventory=_analysis_inventory(),
            summary=summary,
            plans=(bundle.plan for bundle in bundles),
            model_requests=build_scheduler_model_request_evidence(
                plans=(bundle.plan for bundle in bundles),
                activations=(item for bundle in bundles for item in bundle.activations),
                task_results=(item for bundle in bundles for item in bundle.task_results),
            ),
            activations=(item for bundle in bundles for item in bundle.activations),
            outputs=(item for bundle in bundles for item in bundle.outputs),
            task_results=(item for bundle in bundles for item in bundle.task_results),
            result_observations=(item for bundle in bundles for item in bundle.task_results),
            events=(),
        )


def test_journal_preserves_provisional_success_when_dispatch_recovers_uncertain() -> None:
    provisional = _pass_bundle(_manifest(), SchedulerPassKind.ORIENTATION, ())
    plan = provisional.plan
    task = plan.tasks[0]
    activation = provisional.activations[0]
    uncertain = SchedulerTaskResult.build(
        plan=plan,
        task=task,
        activation=activation,
        terminal_status=SchedulerTerminalStatus.UNCERTAIN,
        terminal_evidence_sha256=_sha256("recovery-uncertain"),
    )
    pass_result = SchedulerPassResult.build(plan=plan, task_results=(uncertain,))
    summary = SchedulerCampaignSummary.build(
        manifest=plan.manifest,
        pass_results=(pass_result,),
    )
    credited = _PassBundle(
        plan=plan,
        activations=(activation,),
        outputs=provisional.outputs,
        task_results=(uncertain,),
        result=pass_result,
    )
    evidence = SchedulerJournalEvidence.build(
        manifest=plan.manifest,
        analysis_input_inventory=_analysis_inventory(),
        summary=summary,
        plans=(plan,),
        model_requests=build_scheduler_model_request_evidence(
            plans=(plan,),
            activations=(activation,),
            task_results=(uncertain,),
        ),
        activations=(activation,),
        outputs=provisional.outputs,
        task_results=(uncertain,),
        result_observations=(provisional.task_results[0], uncertain),
        events=_events((credited,)),
    )
    assert evidence.result_observation_count == 2
    assert evidence.task_result_count == 1
    assert evidence.task_output_count == 1
    assert evidence.uncertain_count == 1


def test_report_binding_structural_tampering_is_rejected() -> None:
    manifest = _manifest()
    bundles = _complete_campaign(manifest)
    summary, evidence = _journal_evidence(manifest, bundles)
    artifact = SchedulerArtifact.build(
        summary=summary,
        journal_evidence=evidence,
        model_requests=build_scheduler_model_request_evidence(
            plans=(bundle.plan for bundle in bundles),
            activations=(item for bundle in bundles for item in bundle.activations),
            task_results=(item for bundle in bundles for item in bundle.task_results),
        ),
    )
    binding = SchedulerReportBinding.from_artifact(artifact)
    payload = binding.model_dump(mode="json")
    payload["succeeded_count"] += 1
    payload["binding_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in payload.items() if key != "binding_sha256"}
    )
    with pytest.raises(ValidationError, match="counts are inconsistent"):
        SchedulerReportBinding.model_validate(payload)


def test_scheduler_models_are_immutable() -> None:
    manifest = _manifest()
    with pytest.raises(ValidationError, match="frozen"):
        manifest.shard_ids = (_shard(3),)  # type: ignore[misc]


def test_analysis_input_inventory_requires_every_exact_typed_projection() -> None:
    descriptors = tuple(
        SchedulerAnalysisInputDescriptor.build(
            label=label,
            type_name="SyntheticProjection",
            value={"label": label, "value": _sha256(label)},
        )
        for label in reversed(SCHEDULER_ANALYSIS_INPUT_LABELS)
    )

    inventory = SchedulerAnalysisInputInventory.build(descriptors)

    assert tuple(item.label for item in inventory.descriptors) == tuple(
        sorted(SCHEDULER_ANALYSIS_INPUT_LABELS)
    )
    assert len(inventory.analysis_input_sha256) == 64
    with pytest.raises(ValidationError, match="at least 24 items"):
        SchedulerAnalysisInputInventory.build(descriptors[:-1])


def test_complete_fixture_supports_typed_model_tasks_across_later_passes() -> None:
    assignments = (
        SchedulerFixtureModelTask(
            task_key="invariant-review",
            role="specialist:invariant_review",
            requested_model="synthetic/invariant-v1",
            root_lineage="sha256:" + _sha256("invariant-lineage"),
            scope=SchedulerScope.global_scope(),
            pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
        ),
        SchedulerFixtureModelTask(
            task_key="test-generation",
            role="specialist:test_generation:exploit_test",
            requested_model="synthetic/test-generation-v1",
            root_lineage="sha256:" + _sha256("test-generation-lineage"),
            scope=SchedulerScope.global_scope(),
            pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            candidate_ids=("candidate-critical",),
        ),
        SchedulerFixtureModelTask(
            task_key="reproduction-planner",
            role="specialist:exploit_reproduction_planner:exploit_test",
            requested_model="synthetic/reproduction-v1",
            root_lineage="sha256:" + _sha256("reproduction-lineage"),
            scope=SchedulerScope.global_scope(),
            pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            candidate_ids=("candidate-critical",),
        ),
        SchedulerFixtureModelTask(
            task_key="judge",
            role="judge",
            requested_model="synthetic/judge-v1",
            root_lineage="sha256:" + _sha256("judge-lineage"),
            scope=SchedulerScope.global_scope(),
            pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
            candidate_ids=("candidate-group-critical",),
        ),
        SchedulerFixtureModelTask(
            task_key="report-quality",
            role="specialist:report_quality",
            requested_model="synthetic/report-quality-v1",
            root_lineage="sha256:" + _sha256("report-quality-lineage"),
            scope=SchedulerScope.global_scope(),
            pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
        ),
    )
    fixture = build_complete_scheduler_fixture(
        seed="typed-multi-pass-model-tasks",
        model_tasks=assignments,
    )

    usage_by_role = {item.role: item for item in fixture.usage_records}
    assert set(usage_by_role) >= {item.role for item in assignments}
    assert (
        fixture.context_request_evidence[
            tuple(item.role for item in fixture.usage_records).index(
                "specialist:test_generation:exploit_test"
            )
        ].context_role
        == "specialist:test_generation"
    )
    assert (
        fixture.context_request_evidence[
            tuple(item.role for item in fixture.usage_records).index(
                "specialist:exploit_reproduction_planner:exploit_test"
            )
        ].context_role
        == "specialist:exploit_reproduction_planner"
    )
    outputs_by_role = {
        task.role: next(output for output in fixture.outputs if output.task_id == task.task_id)
        for plan in fixture.plans
        for task in plan.tasks
    }
    assert outputs_by_role["specialist:invariant_review"].payload == {
        "decisions": [],
        "proposals": [],
    }
    assert outputs_by_role["specialist:test_generation:exploit_test"].payload == {"tests": []}
    assert (
        outputs_by_role["specialist:test_generation:exploit_test"].specialist_accepted_outcome
        is not None
    )
    assert (
        outputs_by_role[
            "specialist:exploit_reproduction_planner:exploit_test"
        ].specialist_accepted_outcome
        is not None
    )
    test_generation_task = next(
        task
        for plan in fixture.plans
        for task in plan.tasks
        if task.role == "specialist:test_generation:exploit_test"
    )
    test_generation_output = outputs_by_role[test_generation_task.role]
    test_generation_activation = next(
        activation
        for activation in fixture.activations
        if activation.task_id == test_generation_task.task_id
    )
    test_generation_usage = next(
        usage
        for usage in fixture.usage_records
        if usage.request_id == test_generation_task.logical_request_id
    )
    test_generation_pass = next(
        result
        for result in fixture.pass_results
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )
    with pytest.raises(ValueError, match="requires one exact host-accepted outcome"):
        SchedulerTaskOutput.build(
            plan=test_generation_pass.plan,
            task=test_generation_task,
            activation=test_generation_activation,
            payload=test_generation_output.payload,
            usage_record=test_generation_usage,
        )

    test_generation_result = next(
        result
        for result in test_generation_pass.task_results
        if result.task_id == test_generation_task.task_id
    )
    forged_result_body = test_generation_result.model_dump(
        mode="json",
        exclude={"result_sha256", "specialist_accepted_outcome_sha256"},
    )
    forged_result_body["specialist_accepted_outcome_sha256"] = None
    forged_result = SchedulerTaskResult.model_validate(
        {
            **forged_result_body,
            "result_sha256": scheduler_canonical_sha256(forged_result_body),
        }
    )
    with pytest.raises(ValueError, match="differs from its host-accepted outcome"):
        SchedulerPassResult.build(
            plan=test_generation_pass.plan,
            task_results=tuple(
                forged_result if result.task_id == forged_result.task_id else result
                for result in test_generation_pass.task_results
            ),
        )
    assert outputs_by_role["judge"].reviewed_candidate_ids == ("candidate-group-critical",)
    assert fixture.summary.status is SchedulerCampaignStatus.COMPLETE


def test_specialist_accepted_outcome_role_contract_is_closed() -> None:
    required_roles = {
        *(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES),
        "specialist:invariant_review",
        "specialist:falsifier",
        "specialist:report_quality",
        "specialist:test_generation:exploit_test",
        "specialist:exploit_reproduction_planner:exploit_test",
    }
    for role in required_roles:
        assert scheduler_role_requires_specialist_accepted_outcome(role)

    for role in {
        "source_audit",
        "specialist:source_audit",
        "specialist:source_audit:exploit_test",
        "specialist:business_logic:exploit_test",
        "specialist:test_generation",
        "specialist:exploit_reproduction_planner",
        "specialist:unknown",
    }:
        assert not scheduler_role_requires_specialist_accepted_outcome(role)


@pytest.mark.parametrize("base_role", ["source_audit", "business_logic"])
def test_base_role_exploit_planner_succeeds_without_specialist_credit(base_role: str) -> None:
    request_role = f"specialist:{base_role}:exploit_test"
    fixture = build_complete_scheduler_fixture(
        seed=f"fallback-exploit-planner:{base_role}",
        model_tasks=(
            SchedulerFixtureModelTask(
                task_key=f"fallback-planner:{base_role}",
                role=request_role,
                requested_model=f"synthetic/{base_role}-v1",
                root_lineage="sha256:" + _sha256(f"fallback-lineage:{base_role}"),
                scope=SchedulerScope.global_scope(),
                pass_kind=SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                candidate_ids=("candidate-critical",),
            ),
        ),
    )

    task = next(task for plan in fixture.plans for task in plan.tasks if task.role == request_role)
    output = next(output for output in fixture.outputs if output.task_id == task.task_id)
    result = next(result for result in fixture.task_results if result.task_id == task.task_id)
    pass_result = next(
        result
        for result in fixture.pass_results
        if result.plan.pass_kind is SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )

    assert output.payload == {"tests": []}
    assert output.specialist_accepted_outcome is None
    assert result.terminal_status is SchedulerTerminalStatus.SUCCEEDED
    assert result.specialist_accepted_outcome_sha256 is None
    assert pass_result.status is SchedulerPassStatus.COMPLETE
