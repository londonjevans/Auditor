"""Public comparison-only projection for released recovery requests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.scheduler import (
    SchedulerArtifact,
    SchedulerCampaignManifest,
    SchedulerJournalEvidence,
    SchedulerModelRequestEvidence,
    SchedulerPassKind,
    SchedulerProviderAttemptEvidence,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    SchedulerTruncationRecoveryModelRequestEvidence,
    SchedulerTruncationRecoveryPromotionDisposition,
    build_scheduler_truncation_recovery_model_request_evidence,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import ModelRequestValidationStatus
from mmaudit.models.truncation import candidate_review_frame_wire_schema_sha256
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildDispatch,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryCostDisposition,
    SchedulerTruncationRecoveryEntry,
    SchedulerTruncationRecoveryFamilyRoot,
    SchedulerTruncationRecoveryResultOrigin,
)
from tests.unit.test_scheduler_journal import (
    _bindings,
    _failed_accountable_mock_usage,
    _inventory,
    _plan,
    create_scheduler_journal,
)
from tests.unit.test_truncation_recovery_cost_resume import _released_recovery_usage
from tests.unit.test_truncation_recovery_journal import (
    _activate_child,
    _digest,
    _journal_with_truncated_parent,
)


@dataclass(frozen=True)
class _ReleasedProjectionBase:
    manifest: SchedulerCampaignManifest
    parent_request: SchedulerModelRequestEvidence
    parent_attempt: SchedulerProviderAttemptEvidence
    family: SchedulerTruncationRecoveryFamilyRoot
    activation: SchedulerTruncationRecoveryChildActivation
    dispatch: SchedulerTruncationRecoveryChildDispatch | None
    result: SchedulerTruncationRecoveryChildResult
    entries: tuple[SchedulerTruncationRecoveryEntry, ...]
    request: SchedulerTruncationRecoveryModelRequestEvidence
    artifact: SchedulerArtifact


def _main_pre_send_release_journal_evidence(
    path: Path,
    *,
    terminal_status: SchedulerTerminalStatus | None,
    forgery: str | None = None,
    validation_status: ModelRequestValidationStatus | None = None,
    status: str | None = None,
) -> SchedulerJournalEvidence:
    journal = create_scheduler_journal(
        path,
        bindings=_bindings(),
        shard_inventory=_inventory(),
    )
    try:
        plan = journal.seal_pass_plan(_plan(journal, SchedulerPassKind.ORIENTATION))
        task = plan.tasks[0]
        activation = journal.activate_task(
            task.task_id,
            actual_input_sha256=task.input_sha256,
            system_prompt_sha256=task.system_prompt_sha256,
            user_prompt_sha256="1" * 64,
            provider_prompt_sha256="2" * 64,
            response_schema_sha256=task.response_schema_sha256,
        )
        usage = _failed_accountable_mock_usage(
            plan,
            task,
            activation,
            reported_cost_usd_exact=None,
            accounted_cost_usd_exact="0.01" if forgery == "cost" else "0",
            attempts=2 if forgery == "retry" else 1,
            released_before_send=True,
        )
        if validation_status is not None or status is not None:
            usage = type(usage).model_validate(
                usage.model_copy(
                    update={
                        **(
                            {"validation_status": validation_status}
                            if validation_status is not None
                            else {}
                        ),
                        **({"status": status} if status is not None else {}),
                    }
                ).model_dump(mode="python")
            )
        if forgery == "response":
            usage = type(usage).model_validate(
                usage.model_copy(update={"response_sha256": _digest("forged-response")}).model_dump(
                    mode="python"
                )
            )
        elif forgery == "model":
            usage = type(usage).model_validate(
                usage.model_copy(update={"actual_model": task.requested_model}).model_dump(
                    mode="python"
                )
            )
        elif forgery == "success":
            usage = type(usage).model_validate(
                usage.model_copy(update={"status": "success"}).model_dump(mode="python")
            )
        attempt = SchedulerProviderAttemptEvidence.build(
            task=task,
            activation=activation,
            usage_record=usage,
            audit_model_selection=journal.manifest.bindings.audit_model_selection,
            audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
            audit_model_refresh_pricing=journal.manifest.bindings.audit_model_refresh_pricing,
        )
        if terminal_status is not None:
            journal.record_activated_preflight_failure(
                SchedulerTaskResult.build(
                    plan=plan,
                    task=task,
                    activation=activation,
                    terminal_status=terminal_status,
                    terminal_evidence_sha256=_digest("main-pre-send-release"),
                )
            )
        return SchedulerJournalEvidence.build(
            manifest=journal.manifest,
            analysis_input_inventory=journal.analysis_input_inventory,
            summary=journal.summary,
            plans=journal.plans,
            model_requests=journal.model_requests,
            activations=journal.activations,
            outputs=journal.outputs,
            provider_attempts=(attempt,),
            task_results=journal.task_results,
            result_observations=journal.result_observations,
            events=journal.events,
            truncation_recovery_entries=journal.truncation_recovery_entries,
            terminal_report_authority=journal.terminal_report_authority,
        )
    finally:
        journal.close()


def _released_projection(
    path: Path,
    *,
    with_dispatch: bool,
) -> _ReleasedProjectionBase:
    journal, plan, truncation, _surfaces, surface_manifest = _journal_with_truncated_parent(
        path,
        parent_cost_usd_exact="0.01",
    )
    family = journal.open_truncation_recovery_family(
        recovery_plan=plan,
        truncation_projection=truncation,
        requested_surface_manifest=surface_manifest,
    )
    child = plan.children[0]
    activation = _activate_child(journal, child.child_task_id)
    dispatch = (
        journal.mark_truncation_recovery_child_dispatched(child.child_task_id)
        if with_dispatch
        else None
    )
    failed_usage = _released_recovery_usage(activation)
    result = SchedulerTruncationRecoveryChildResult.build_released_pre_send(
        child=child,
        activation=activation,
        dispatch=dispatch,
        terminal_evidence_sha256=_digest(f"released-cost:{with_dispatch}"),
        release_reason="failed_before_send",
        accounted_prefix_attempts=0,
        accounted_prefix_cost_usd_exact="0",
        failed_usage_record=failed_usage,
        result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
        entry_index=len(journal.truncation_recovery_entries),
        previous_entry_sha256=journal.truncation_recovery_entries[-1].entry_sha256,
    )
    entries = (*journal.truncation_recovery_entries, result)
    parent_request = next(
        item
        for item in journal.model_requests
        if item.task_id == family.recovery_plan.parent.parent_task_id
    )
    parent_attempt = next(
        item
        for item in journal.provider_attempts
        if item.task_id == family.recovery_plan.parent.parent_task_id
    )
    requests = build_scheduler_truncation_recovery_model_request_evidence(
        manifest=journal.manifest,
        model_requests=journal.model_requests,
        truncation_recovery_entries=entries,
        provider_attempts=journal.provider_attempts,
    )
    evidence = SchedulerJournalEvidence.build(
        manifest=journal.manifest,
        analysis_input_inventory=journal.analysis_input_inventory,
        summary=journal.summary,
        plans=journal.plans,
        model_requests=journal.model_requests,
        activations=journal.activations,
        outputs=journal.outputs,
        provider_attempts=journal.provider_attempts,
        task_results=journal.task_results,
        result_observations=journal.result_observations,
        events=journal.events,
        truncation_recovery_entries=entries,
        terminal_report_authority=journal.terminal_report_authority,
    )
    artifact = SchedulerArtifact.build(
        summary=journal.summary,
        journal_evidence=evidence,
        model_requests=journal.model_requests,
        recovery_model_requests=requests,
    )
    journal.close()
    assert len(requests) == 1
    return _ReleasedProjectionBase(
        manifest=journal.manifest,
        parent_request=parent_request,
        parent_attempt=parent_attempt,
        family=family,
        activation=activation,
        dispatch=dispatch,
        result=result,
        entries=entries,
        request=requests[0],
        artifact=artifact,
    )


@pytest.mark.parametrize("terminal_status", (None, SchedulerTerminalStatus.FAILED))
def test_main_pre_send_release_attempt_allows_only_exact_activation_lifecycle(
    tmp_path: Path,
    terminal_status: SchedulerTerminalStatus | None,
) -> None:
    evidence = _main_pre_send_release_journal_evidence(
        tmp_path / f"main-pre-send-{terminal_status}",
        terminal_status=terminal_status,
    )

    assert evidence.provider_attempt_count == 1
    assert evidence.task_result_count == (terminal_status is not None)
    assert evidence.failed_count == (terminal_status is SchedulerTerminalStatus.FAILED)


@pytest.mark.parametrize(
    ("validation_status", "status"),
    (
        (
            ModelRequestValidationStatus.PROVIDER_MISMATCH,
            "rejected_provider_substitution",
        ),
        (ModelRequestValidationStatus.MODEL_MISMATCH, "failed:OpenRouterModelError"),
        (
            ModelRequestValidationStatus.INVALID_RESPONSE,
            "failed:OpenRouterStructuredOutputError",
        ),
        (
            ModelRequestValidationStatus.PROVIDER_ERROR,
            "failed:OpenRouterAuthenticationError",
        ),
    ),
)
def test_main_pre_send_release_accepts_live_failure_status_variants(
    tmp_path: Path,
    validation_status: ModelRequestValidationStatus,
    status: str,
) -> None:
    evidence = _main_pre_send_release_journal_evidence(
        tmp_path / f"main-pre-send-{validation_status.value}",
        terminal_status=None,
        validation_status=validation_status,
        status=status,
    )

    assert evidence.provider_attempt_count == 1
    assert evidence.task_result_count == 0


@pytest.mark.parametrize(
    "forgery",
    ("response", "model", "cost", "retry", "success"),
)
def test_main_pre_send_release_attempt_rejects_forged_custody(
    tmp_path: Path,
    forgery: str,
) -> None:
    with pytest.raises(ValueError, match="exact pre-send release evidence"):
        _main_pre_send_release_journal_evidence(
            tmp_path / f"main-pre-send-forged-{forgery}",
            terminal_status=None,
            forgery=forgery,
        )


def test_main_pre_send_release_terminal_requires_failed_result(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exact pre-send release evidence"):
        _main_pre_send_release_journal_evidence(
            tmp_path / "main-pre-send-inconclusive",
            terminal_status=SchedulerTerminalStatus.INCONCLUSIVE,
        )


@pytest.mark.parametrize("with_dispatch", (False, True))
def test_released_runtime_usage_projects_only_failed_comparison_custody(
    tmp_path: Path,
    with_dispatch: bool,
) -> None:
    base = _released_projection(tmp_path / f"released-{with_dispatch}", with_dispatch=with_dispatch)
    request = base.request

    assert request.schema_version == "1.3"
    assert request.terminal_status is SchedulerTerminalStatus.FAILED
    assert request.result_origin is SchedulerTruncationRecoveryResultOrigin.RUNTIME
    assert request.recovery_family_id == base.family.family_id
    assert request.family_root_sha256 == base.family.entry_sha256
    assert request.recovery_plan_sha256 == base.family.recovery_plan.plan_sha256
    assert request.child_plan_sha256 == base.result.child_plan_sha256
    assert request.activation_id == base.activation.activation_id
    assert request.activation_entry_sha256 == base.activation.entry_sha256
    assert request.child_result_entry_sha256 == base.result.entry_sha256
    assert request.dispatch_id == (base.dispatch.dispatch_id if base.dispatch is not None else None)
    assert request.dispatch_sha256 == (
        base.dispatch.entry_sha256 if base.dispatch is not None else None
    )
    assert request.released_cost_entry_sha256 == base.result.terminal_evidence_sha256
    assert request.pre_send_release_reason == "failed_before_send"
    assert request.provider_attempt_evidence_sha256 == base.result.provider_attempt_evidence_sha256
    assert request.accounted_provider_attempts == base.result.accounted_provider_attempts == 1
    assert request.accounted_completion_tokens == 0
    assert request.accounted_cost_usd_exact == "0"
    assert (
        request.cost_disposition
        is SchedulerTruncationRecoveryCostDisposition.RELEASED_PRE_SEND_TAIL
    )
    assert request.request_limit_count_after == request.request_limit_count_before + 1
    assert request.usage_record_sha256 == base.result.runtime_usage_record_sha256
    assert request.context_request_evidence_sha256 == (
        base.result.runtime_usage_record.routing["context_request_evidence_sha256"]
        if base.result.runtime_usage_record is not None
        else None
    )
    assert request.provider_response_sha256 is None
    assert request.runtime_completion_evidence_sha256 is None
    assert request.validated_response_sha256 is None
    assert request.normalization_evidence_sha256 is None
    assert request.output_artifact_sha256 is None
    assert request.specialist_accepted_outcome_sha256 is None
    assert request.promotion_entry_sha256 is None
    assert request.provider_dispatch_authorized is False
    assert request.review_credit_authorized is False
    assert request.coverage_credit_authorized is False
    assert request.completion_authorized is False
    assert request.release_authorized is False
    assert base.artifact.recovery_model_requests == (request,)
    assert (
        SchedulerTruncationRecoveryModelRequestEvidence.model_validate_json(
            request.model_dump_json(),
            strict=True,
        )
        == request
    )


def test_released_public_builder_rejects_result_outside_exact_chain(tmp_path: Path) -> None:
    base = _released_projection(tmp_path / "mismatched-result", with_dispatch=False)
    child = base.family.recovery_plan.children[0]
    alternate = SchedulerTruncationRecoveryChildResult.build_released_pre_send(
        child=child,
        activation=base.activation,
        dispatch=None,
        terminal_evidence_sha256=_digest("alternate-release-cost"),
        release_reason="failed_before_send",
        accounted_prefix_attempts=0,
        accounted_prefix_cost_usd_exact="0",
        failed_usage_record=base.result.runtime_usage_record,
        result_origin=SchedulerTruncationRecoveryResultOrigin.RUNTIME,
        entry_index=base.result.entry_index,
        previous_entry_sha256=base.result.previous_entry_sha256,
    )

    with pytest.raises(ValueError, match="family parent"):
        SchedulerTruncationRecoveryModelRequestEvidence.build(
            manifest=base.manifest,
            parent_request=base.parent_request,
            parent_attempt=base.parent_attempt,
            family=base.family,
            promotion=None,
            activation=base.activation,
            result=alternate,
            recovery_entries=base.entries,
        )


def _resealed_payload(
    request: SchedulerTruncationRecoveryModelRequestEvidence,
    **updates: Any,
) -> dict[str, Any]:
    payload = request.model_dump(mode="json")
    payload.update(updates)
    payload.pop("request_evidence_sha256")
    payload["request_evidence_sha256"] = scheduler_canonical_sha256(payload)
    return payload


def _legacy_public_request(schema_version: str) -> SchedulerTruncationRecoveryModelRequestEvidence:
    succeeded = schema_version in {"1.1", "1.2"}
    values: dict[str, Any] = {
        "schema_version": schema_version,
        "evidence_authority": "comparison_required",
        "provider_dispatch_authorized": False,
        "review_credit_authorized": False,
        "coverage_credit_authorized": False,
        "completion_authorized": False,
        "release_authorized": False,
        "campaign_id": f"scheduler-campaign-{'1' * 64}",
        "parent_task_id": f"scheduler-task-{'2' * 64}",
        "child_task_id": f"scheduler-recovery-task-{'3' * 64}",
        "logical_request_id": f"scheduler-recovery-request-{'4' * 64}",
        "child_result_entry_sha256": "5" * 64,
        "activation_id": f"scheduler-recovery-activation-{'6' * 64}",
        "activation_entry_sha256": "7" * 64,
        "activation_status": "ACTIVATED",
        "role": "specialist:access_control" if schema_version == "1.1" else "source_audit",
        "requested_model": "synthetic/recovery-model-v1",
        "root_lineage": f"sha256:{'8' * 64}",
        "actual_input_sha256": "9" * 64,
        "system_prompt_sha256": "a" * 64,
        "user_prompt_sha256": "b" * 64,
        "provider_prompt_sha256": "c" * 64,
        "response_schema_sha256": candidate_review_frame_wire_schema_sha256(),
        "delivered_source_inventory_sha256": "d" * 64,
        "request_limit_scope": f"scheduler-request-{'e' * 64}",
        "request_limit_count_before": 1,
        "request_limit_count_after": 2,
        "request_limit_maximum": 10,
        "request_limit_reservation_evidence_sha256": "f" * 64,
        "terminal_status": "SUCCEEDED" if succeeded else "TRUNCATED",
        "terminal_evidence_sha256": "0" * 64,
        "usage_record_sha256": "1" * 64,
        "context_request_evidence_sha256": "2" * 64,
        "provider_response_sha256": "3" * 64,
    }
    if succeeded:
        values.update(
            {
                "runtime_completion_evidence_sha256": "4" * 64,
                "validated_response_sha256": "5" * 64,
                "normalization_evidence_sha256": "6" * 64,
                "output_artifact_sha256": "7" * 64,
            }
        )
    if schema_version == "1.1":
        values["specialist_accepted_outcome_sha256"] = "8" * 64
    if schema_version == "1.2":
        values.update(
            {
                "promotion_entry_sha256": "9" * 64,
                "promotion_disposition": (
                    SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
                ),
                "global_request_ordinal": 1,
                "recovery_family_id": f"scheduler-recovery-family-{'a' * 64}",
                "family_root_sha256": "b" * 64,
                "recovery_plan_sha256": "c" * 64,
                "family_closure_id": f"scheduler-recovery-closure-{'d' * 64}",
                "family_closure_sha256": "e" * 64,
            }
        )
    return SchedulerTruncationRecoveryModelRequestEvidence(
        **values,
        request_evidence_sha256=scheduler_canonical_sha256(values),
    )


def test_legacy_public_recovery_json_bytes_remain_compatible() -> None:
    expected_json_sha256s = {
        "1.0": "7e9f3ca32c6383d25ba4ede2a7334146538eb03cbfd144843b9c92089442b089",
        "1.1": "6ae14e2953e6937b0e55fd3aaa194c6b266352f9ec996b37827f5e50d0111810",
        "1.2": "0416192a5d1003280ff74a3da3f6e3599432d337ce5ea2f6129c38d10ab781f9",
    }

    for schema_version, expected_sha256 in expected_json_sha256s.items():
        request = _legacy_public_request(schema_version)
        payload = request.model_dump_json()
        assert hashlib.sha256(payload.encode()).hexdigest() == expected_sha256
        assert (
            SchedulerTruncationRecoveryModelRequestEvidence.model_validate_json(
                payload,
                strict=True,
            )
            == request
        )


@pytest.mark.parametrize(
    "updates",
    (
        {"released_cost_entry_sha256": "f" * 64},
        {"accounted_cost_usd_exact": "0.0"},
        {"review_credit_authorized": True},
        {"promotion_entry_sha256": "e" * 64},
        {"output_artifact_sha256": "d" * 64},
    ),
)
def test_released_public_projection_rejects_mismatch_credit_and_promotion(
    tmp_path: Path,
    updates: dict[str, Any],
) -> None:
    base = _released_projection(
        tmp_path / f"forged-{next(iter(updates))}",
        with_dispatch=False,
    )

    with pytest.raises(ValidationError):
        SchedulerTruncationRecoveryModelRequestEvidence.model_validate(
            _resealed_payload(base.request, **updates)
        )


def test_crash_release_is_skipped_by_aggregate_and_rejected_by_direct_builder(
    tmp_path: Path,
) -> None:
    base = _released_projection(tmp_path / "crash-private-only", with_dispatch=False)
    child = base.family.recovery_plan.children[0]
    crash_result = SchedulerTruncationRecoveryChildResult.build_released_pre_send(
        child=child,
        activation=base.activation,
        dispatch=None,
        terminal_evidence_sha256=_digest("crash-release-cost"),
        release_reason="failed_before_send",
        accounted_prefix_attempts=0,
        accounted_prefix_cost_usd_exact="0",
        result_origin=SchedulerTruncationRecoveryResultOrigin.CRASH_RECOVERY,
        entry_index=base.result.entry_index,
        previous_entry_sha256=base.result.previous_entry_sha256,
    )
    crash_entries = (*base.entries[:-1], crash_result)

    assert (
        build_scheduler_truncation_recovery_model_request_evidence(
            manifest=base.manifest,
            model_requests=(base.parent_request,),
            truncation_recovery_entries=crash_entries,
            provider_attempts=(base.parent_attempt,),
        )
        == ()
    )
    with pytest.raises(ValueError, match="failed usage"):
        SchedulerTruncationRecoveryModelRequestEvidence.build(
            manifest=base.manifest,
            parent_request=base.parent_request,
            parent_attempt=base.parent_attempt,
            family=base.family,
            promotion=None,
            activation=base.activation,
            result=crash_result,
            recovery_entries=crash_entries,
        )
