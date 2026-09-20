"""Historical judge-vote comparison never recreates live provider authority."""

import hashlib
from dataclasses import replace
from types import MappingProxyType

import pytest

from mmaudit.models.scheduler import (
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerPassKind,
    SchedulerScope,
    SchedulerTaskOutput,
    SchedulerTerminalStatus,
)
from mmaudit.models.schemas import JudgeDecision, ModelVote, UsageRecord
from mmaudit.models.usage import (
    is_creditable_usage_record,
    is_structurally_creditable_usage_record,
)
from mmaudit.orchestration import manifest
from tests.scheduler_support import (
    SchedulerFixtureModelTask,
    build_complete_scheduler_fixture,
    build_scheduler_test_audit_model_refresh_binding,
    build_scheduler_test_audit_model_refresh_pricing_binding,
    build_scheduler_test_audit_model_selection_binding,
)
from tests.unit.test_manifest_consensus import _snapshot

_JUDGMENT = SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
type JudgeReplay = tuple[
    manifest._SchedulerReportAuthoritySnapshot, JudgeDecision, UsageRecord, str
]


def _assignment(_pass: SchedulerPassKind, task_key: str, _role: str) -> tuple[str, str]:
    model_id = "synthetic/" + hashlib.sha256(task_key.encode()).hexdigest()[:16]
    return model_id, "sha256:" + hashlib.sha256(model_id.encode()).hexdigest()


@pytest.fixture(scope="module")
def judge_replay() -> JudgeReplay:
    assignment = SchedulerFixtureModelTask(
        task_key="judge",
        role="judge",
        requested_model="synthetic/judge",
        root_lineage="sha256:" + "7" * 64,
        scope=SchedulerScope.global_scope(),
        pass_kind=_JUDGMENT,
        candidate_ids=("candidate-critical",),
    )
    options = {
        "seed": "manifest-judge-vote",
        "model_tasks": (assignment,),
        "model_assignment_resolver": _assignment,
    }
    template = build_complete_scheduler_fixture(**options)
    usage_by_task = {
        output.task_id: output.model_completion_evidence.usage_record
        for output in template.outputs
        if output.model_completion_evidence is not None
    }
    routes = {
        task.requested_model: (
            task.requested_model,
            task.root_lineage,
            usage_by_task[task.task_id].provider,
            usage_by_task[task.task_id].actual_provider_endpoint,
        )
        for plan in template.plans
        for task in plan.tasks
        if task.requested_model is not None
    }
    selection = build_scheduler_test_audit_model_selection_binding(
        source_sha256=template.manifest.bindings.source_sha256,
        selected_routes=tuple(sorted(routes.values())),
        seed="manifest-judge-vote",
    )
    refresh = build_scheduler_test_audit_model_refresh_binding(selection)
    pricing = build_scheduler_test_audit_model_refresh_pricing_binding(selection, refresh)
    values = template.manifest.bindings.model_dump(
        mode="python",
        exclude={"schema_version", "algorithm_version", "evidence_authority", "bindings_sha256"},
    )
    values.update(
        audit_model_selection=selection,
        audit_model_refresh=refresh,
        audit_model_refresh_pricing=pricing,
    )
    campaign = SchedulerCampaignManifest.build(
        bindings=SchedulerBindings.build(**values),
        shard_inventory=template.manifest.shard_inventory,
        privacy_evidence_custody=template.manifest.privacy_evidence_custody,
    )
    # Construct coherent synthetic evidence before comparison; no journal is retrofitted.
    fixture = build_complete_scheduler_fixture(**options, manifest=campaign, real_usage=True)
    snapshot = _snapshot(fixture)
    task = next(task for plan in fixture.plans for task in plan.tasks if task.role == "judge")
    output = snapshot.outputs_by_task_id[task.task_id]
    decision = JudgeDecision.model_validate(output.payload["decisions"][0])
    owned = next(
        usage for usage in fixture.usage_records if usage.request_id == task.logical_request_id
    )
    assert is_creditable_usage_record(owned, require_real=True)
    return snapshot, decision, owned, task.task_id


def _with_output(
    snapshot: manifest._SchedulerReportAuthoritySnapshot, output: SchedulerTaskOutput
) -> manifest._SchedulerReportAuthoritySnapshot:
    return replace(
        snapshot,
        outputs_by_task_id=MappingProxyType(
            dict(snapshot.outputs_by_task_id) | {output.task_id: output}
        ),
    )


def test_detached_judge_vote_preserves_history_without_live_credit(
    judge_replay: JudgeReplay,
) -> None:
    snapshot, decision, owned, task_id = judge_replay
    original = snapshot.outputs_by_task_id[task_id]
    decoded = SchedulerTaskOutput.model_validate_json(original.model_dump_json())
    completion = decoded.model_completion_evidence
    assert completion is not None
    usage = completion.usage_record
    assert usage == owned and not is_creditable_usage_record(usage, require_real=True)
    assert is_structurally_creditable_usage_record(usage, require_real=True)
    before = decoded.model_dump_json()
    expected = ModelVote(
        role="judge",
        requested_model=usage.requested_model,
        returned_model=usage.returned_model,
        family=usage.model_family,
        verdict=decision.status.value,
        rationale=decision.rationale,
    )
    # Named invariant: a comparison preserves the retained vote, never a live capability.
    assert (
        manifest._scheduler_judge_vote(decision=decision, snapshot=_with_output(snapshot, decoded))
        == expected
    )
    assert decoded.model_dump_json() == before
    assert not is_creditable_usage_record(usage, require_real=True)
    assert is_creditable_usage_record(owned, require_real=True)


@pytest.mark.parametrize(
    "change",
    ("status", "model", "endpoint", "schema", "response", "cost", "tokens", "privacy"),
)
def test_detached_judge_vote_still_refuses_invalid_usage(
    judge_replay: JudgeReplay, change: str
) -> None:
    snapshot, decision, _, task_id = judge_replay
    output = snapshot.outputs_by_task_id[task_id]
    completion = output.model_completion_evidence
    assert completion is not None
    usage = completion.usage_record
    updates = {
        "status": {"status": "failed"},
        "model": {"returned_model": "synthetic/different-model"},
        "endpoint": {"actual_provider_endpoint": "different-endpoint"},
        "schema": {"schema_sha256": "0" * 64},
        "response": {"validated_response_sha256": "0" * 64},
        "cost": {"accounted_cost_usd": -1.0},
        "tokens": {
            "routing": {
                key: value for key, value in usage.routing.items() if key != "request_token_plan"
            }
        },
        "privacy": {"routing": usage.routing | {"effective_privacy_policy_sha256": "invalid"}},
    }
    changed = usage.model_copy(update=updates[change])
    assert not is_structurally_creditable_usage_record(changed)
    altered = output.model_copy(
        update={
            "model_completion_evidence": completion.model_copy(update={"usage_record": changed})
        }
    )
    assert (
        manifest._scheduler_judge_vote(decision=decision, snapshot=_with_output(snapshot, altered))
        is None
    )
    assert not is_creditable_usage_record(changed, require_real=True)


@pytest.mark.parametrize("absence", ("decision", "pass", "completion"))
def test_judge_vote_requires_retained_inputs(judge_replay: JudgeReplay, absence: str) -> None:
    snapshot, decision, _, task_id = judge_replay
    if absence == "decision":
        decision = None
    elif absence == "pass":
        snapshot = replace(snapshot, pass_results_by_kind=MappingProxyType({}))
    else:
        output = snapshot.outputs_by_task_id[task_id]
        snapshot = _with_output(
            output=output.model_copy(update={"model_completion_evidence": None}), snapshot=snapshot
        )
    assert manifest._scheduler_judge_vote(decision=decision, snapshot=snapshot) is None


@pytest.mark.parametrize("change", ("missing_task", "duplicate_task", "failed", "hash"))
def test_judge_vote_requires_one_exact_successful_task(
    judge_replay: JudgeReplay, change: str
) -> None:
    snapshot, decision, _, task_id = judge_replay
    result = snapshot.pass_results_by_kind[_JUDGMENT]
    task = next(task for task in result.plan.tasks if task.task_id == task_id)
    if change in {"missing_task", "duplicate_task"}:
        tasks = (
            tuple(item for item in result.plan.tasks if item.task_id != task_id)
            if change == "missing_task"
            else (*result.plan.tasks, task)
        )
        result = result.model_copy(update={"plan": result.plan.model_copy(update={"tasks": tasks})})
        expected = "one exact judge task"
    else:
        update = (
            {"terminal_status": SchedulerTerminalStatus.FAILED}
            if change == "failed"
            else {"output_artifact_sha256": "0" * 64}
        )
        result = result.model_copy(
            update={
                "task_results": tuple(
                    item.model_copy(update=update) if item.task_id == task_id else item
                    for item in result.task_results
                )
            }
        )
        expected = (
            "one successful retained output"
            if change == "failed"
            else "differs from its retained output"
        )
    snapshot = replace(
        snapshot,
        pass_results_by_kind=MappingProxyType(
            dict(snapshot.pass_results_by_kind) | {_JUDGMENT: result}
        ),
    )
    with pytest.raises(ValueError, match=expected):
        manifest._scheduler_judge_vote(decision=decision, snapshot=snapshot)
