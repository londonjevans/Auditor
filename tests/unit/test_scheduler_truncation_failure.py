"""Scheduler custody tests for typed candidate-review truncation failures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.openrouter as openrouter_module
from mmaudit.models.openrouter import OpenRouterTruncatedResponseError
from mmaudit.models.scheduler import SchedulerTaskPlan, SchedulerTerminalStatus
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    project_truncated_candidate_review_prefix,
    seal_candidate_review_truncated_envelope_evidence,
)
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from tests.identity_fixtures import reattest_synthetic_real_usage
from tests.unit.test_scheduler_journal import _framed_candidate_review_fixture


def _typed_truncation_custody(
    fixture: dict[str, Any],
) -> tuple[
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationProjection,
    UsageRecord,
]:
    task = fixture["task"]
    payload = fixture["payload"]
    base_usage = fixture["usage"]
    assert isinstance(task, SchedulerTaskPlan)
    assert isinstance(payload, CandidateReviewBatch)
    assert isinstance(base_usage, UsageRecord)
    assert base_usage.openrouter_generation_id is not None
    assert base_usage.provider is not None
    assert base_usage.actual_provider_endpoint is not None

    framed = frame_candidate_review_batch(payload)
    begin = json.dumps(
        framed.frames[0].model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    projection = project_truncated_candidate_review_prefix(
        '{"frames":[' + begin + ",",
        finish_reason="length",
        native_finish_reason="max_tokens",
    )
    envelope = seal_candidate_review_truncated_envelope_evidence(
        logical_request_id=task.logical_request_id,
        generation_id=base_usage.openrouter_generation_id,
        generation_header_id=base_usage.openrouter_generation_id,
        requested_model=base_usage.requested_model,
        returned_model=base_usage.returned_model or base_usage.requested_model,
        selected_model=base_usage.actual_model or base_usage.requested_model,
        response_provider_identity=base_usage.actual_provider_endpoint,
        selected_provider_endpoint=base_usage.actual_provider_endpoint,
        selected_provider_identity=base_usage.actual_provider_endpoint,
        selected_provider_name=base_usage.provider,
        router_metadata_sha256="9" * 64,
        finish_reason=projection.finish_reason,
        native_finish_reason=projection.native_finish_reason,
        wire_schema_sha256=candidate_review_frame_wire_schema_sha256(),
        response_sha256=projection.original_response_sha256,
    )
    routing = {
        **base_usage.routing,
        "generation_id": envelope.generation_id,
        "generation_header_id": envelope.generation_header_id,
        "provider": envelope.selected_provider_name,
        "router_metadata_sha256": envelope.router_metadata_sha256,
        "finish_reason": envelope.finish_reason,
        "native_finish_reason": envelope.native_finish_reason,
        "schema_sha256": envelope.wire_schema_sha256,
        "validation_status": ModelRequestValidationStatus.TRUNCATED.value,
        **openrouter_module._candidate_review_truncated_envelope_routing(envelope),
        **openrouter_module._candidate_review_truncation_projection_routing(projection),
    }
    failed_usage = reattest_synthetic_real_usage(
        base_usage.model_copy(
            update={
                "response_sha256": projection.original_response_sha256,
                "validated_response_sha256": None,
                "finish_reason": envelope.finish_reason,
                "validation_status": ModelRequestValidationStatus.TRUNCATED,
                "identity_strength": ModelIdentityStrength.UNBOUND,
                "status": "rejected_truncated_response",
                "routing": routing,
            }
        )
    )
    return envelope, projection, failed_usage


def _truncation_error(
    envelope: CandidateReviewTruncatedEnvelopeEvidence,
    projection: CandidateReviewTruncationProjection,
    failed_usage: UsageRecord,
    *,
    custody: str,
) -> OpenRouterTruncatedResponseError:
    error = OpenRouterTruncatedResponseError(
        "synthetic candidate-review truncation",
        envelope_evidence=envelope if custody != "none" else None,
    )
    if custody in {"projection", "complete"}:
        error._attach_projection(projection)
    if custody == "complete":
        error._attach_failed_usage_record(failed_usage)
    return error


def test_record_failure_uses_projection_digest_only_for_exact_typed_custody(
    tmp_path: Path,
) -> None:
    fixture = _framed_candidate_review_fixture(tmp_path / "exact")
    envelope, projection, failed_usage = _typed_truncation_custody(fixture)
    error = _truncation_error(
        envelope,
        projection,
        failed_usage,
        custody="complete",
    )
    runtime = fixture["runtime"]
    task = fixture["task"]
    assert isinstance(runtime, PipelineScheduler)
    assert isinstance(task, SchedulerTaskPlan)

    result = runtime.record_failure(task, error, usage_records=(failed_usage,))

    assert result.terminal_status is SchedulerTerminalStatus.TRUNCATED
    assert result.terminal_evidence_sha256 == projection.evidence_sha256
    assert len(runtime.journal.provider_attempts) == 1
    attempt = runtime.journal.provider_attempts[0]
    assert attempt.usage_record == failed_usage
    assert attempt.provider_response_sha256 == projection.original_response_sha256
    assert attempt.validated_response_sha256 is None
    assert all(output.task_id != task.task_id for output in runtime.journal.outputs)
    assert all(
        usage.request_id != task.logical_request_id
        for usage in runtime.journal.structurally_successful_review_usage_records
    )
    runtime.close()


@pytest.mark.parametrize(
    ("case", "custody", "passed_usage", "expected_status", "expected_attempts"),
    (
        (
            "missing-envelope",
            "none",
            "exact",
            SchedulerTerminalStatus.TRUNCATED,
            1,
        ),
        (
            "missing-projection",
            "envelope",
            "exact",
            SchedulerTerminalStatus.TRUNCATED,
            1,
        ),
        (
            "missing-failed-usage",
            "projection",
            "exact",
            SchedulerTerminalStatus.TRUNCATED,
            1,
        ),
        (
            "omitted-passed-usage",
            "complete",
            "omitted",
            SchedulerTerminalStatus.UNBOUND,
            0,
        ),
        (
            "swapped-passed-usage",
            "complete",
            "swapped",
            SchedulerTerminalStatus.UNBOUND,
            1,
        ),
        (
            "duplicate-passed-usage",
            "complete",
            "duplicate",
            SchedulerTerminalStatus.UNBOUND,
            0,
        ),
    ),
)
def test_record_failure_rejects_incomplete_or_nonexact_truncation_custody(
    tmp_path: Path,
    case: str,
    custody: str,
    passed_usage: str,
    expected_status: SchedulerTerminalStatus,
    expected_attempts: int,
) -> None:
    fixture = _framed_candidate_review_fixture(tmp_path / case)
    envelope, projection, failed_usage = _typed_truncation_custody(fixture)
    error = _truncation_error(
        envelope,
        projection,
        failed_usage,
        custody=custody,
    )
    swapped_usage = reattest_synthetic_real_usage(
        failed_usage.model_copy(update={"provider_error_classification": "synthetic_swap"})
    )
    usage_records = {
        "exact": (failed_usage,),
        "omitted": (),
        "swapped": (swapped_usage,),
        "duplicate": (failed_usage, failed_usage),
    }[passed_usage]
    runtime = fixture["runtime"]
    task = fixture["task"]
    assert isinstance(runtime, PipelineScheduler)
    assert isinstance(task, SchedulerTaskPlan)

    result = runtime.record_failure(task, error, usage_records=usage_records)

    assert result.terminal_status is expected_status
    assert result.terminal_evidence_sha256 != projection.evidence_sha256
    assert len(runtime.journal.provider_attempts) == expected_attempts
    if expected_attempts:
        assert result.terminal_evidence_sha256 == (
            runtime.journal.provider_attempts[0].attempt_evidence_sha256
        )
    assert all(output.task_id != task.task_id for output in runtime.journal.outputs)
    assert all(
        usage.request_id != task.logical_request_id
        for usage in runtime.journal.structurally_successful_review_usage_records
    )
    assert runtime.journal.truncation_recovery_entries == ()
    runtime.close()
