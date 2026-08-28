"""Pure reconstruction of exact pass-six consensus-review evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from pydantic import BaseModel

from mmaudit.models.scheduler import (
    SchedulerCandidateWorkset,
    SchedulerPassKind,
    SchedulerResultOrigin,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
    scheduler_response_schema_sha256,
)
from mmaudit.models.schemas import (
    CONSENSUS_REVIEWER_SLOTS,
    ConsensusReviewArtifact,
    ConsensusReviewerBatch,
    ConsensusReviewerSlot,
    ContextRequestEvidence,
    ModelRequestValidationStatus,
    UsageRecord,
    VerificationBatch,
)


class ConsensusEvidenceError(ValueError):
    """Raised when pass-six reviewer evidence is incomplete or inconsistently joined."""


@dataclass(frozen=True, slots=True)
class ConsensusReviewerEvidenceRecord:
    """Inputs required to reconstruct one exact pass-six reviewer batch."""

    slot: ConsensusReviewerSlot
    task: SchedulerTaskPlan
    result: SchedulerTaskResult
    usage: UsageRecord
    raw_batch: VerificationBatch


_EXPECTED_TASK_IDENTITIES: Final[Mapping[ConsensusReviewerSlot, tuple[str, str]]] = (
    MappingProxyType(
        {
            ConsensusReviewerSlot.VERIFIER: ("independent-verifier", "verifier"),
            ConsensusReviewerSlot.FALSIFIER_1: (
                "candidate-falsifier-1",
                "candidate_falsifier",
            ),
            ConsensusReviewerSlot.FALSIFIER_2: (
                "candidate-falsifier-2",
                "candidate_falsifier",
            ),
        }
    )
)


def _freeze_exact_model[ModelT: BaseModel](
    value: ModelT,
    expected_type: type[ModelT],
    label: str,
) -> ModelT:
    """Detach and fully revalidate an exact Pydantic model input."""

    if type(value) is not expected_type:
        raise ConsensusEvidenceError(f"consensus {label} has an invalid exact type")
    try:
        frozen = expected_type.model_validate(value.model_dump(mode="python"), strict=True)
    except (TypeError, ValueError) as exc:
        raise ConsensusEvidenceError(
            f"consensus {label} failed exact structural validation"
        ) from exc
    if frozen != value:
        raise ConsensusEvidenceError(f"consensus {label} changed during validation")
    return frozen


def _canonical_records(
    reviewers: Sequence[ConsensusReviewerEvidenceRecord],
) -> tuple[ConsensusReviewerEvidenceRecord, ...]:
    if isinstance(reviewers, (str, bytes)) or not isinstance(reviewers, Sequence):
        raise ConsensusEvidenceError("consensus reviewer inputs must be a bounded sequence")
    if len(reviewers) != len(CONSENSUS_REVIEWER_SLOTS) or any(
        type(record) is not ConsensusReviewerEvidenceRecord for record in reviewers
    ):
        raise ConsensusEvidenceError("consensus requires exactly three reviewer records")
    if any(type(record.slot) is not ConsensusReviewerSlot for record in reviewers):
        raise ConsensusEvidenceError("consensus reviewer slot has an invalid exact type")
    by_slot = {record.slot: record for record in reviewers}
    if len(by_slot) != len(CONSENSUS_REVIEWER_SLOTS) or set(by_slot) != set(
        CONSENSUS_REVIEWER_SLOTS
    ):
        raise ConsensusEvidenceError("consensus requires each exact reviewer slot once")
    return tuple(by_slot[slot] for slot in CONSENSUS_REVIEWER_SLOTS)


def _validate_task_result_join(
    *,
    slot: ConsensusReviewerSlot,
    task: SchedulerTaskPlan,
    result: SchedulerTaskResult,
    candidate_ids: tuple[str, ...],
) -> None:
    expected_task_key, expected_role = _EXPECTED_TASK_IDENTITIES[slot]
    if (
        task.pass_kind is not SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
        or task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
        or task.task_key != expected_task_key
        or task.role != expected_role
        or task.candidate_ids != candidate_ids
        or task.requested_model is None
        or task.root_lineage is None
        or task.response_schema_sha256 != scheduler_response_schema_sha256(VerificationBatch)
    ):
        raise ConsensusEvidenceError(
            f"consensus {slot.value} task differs from its exact pass-six reviewer slot"
        )
    if (
        result.result_origin is not SchedulerResultOrigin.ACTIVATED
        or result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
        or result.campaign_id != task.campaign_id
        or result.manifest_sha256 != task.manifest_sha256
        or result.pass_kind is not task.pass_kind
        or result.pass_id != task.pass_id
        or result.task_id != task.task_id
        or result.task_plan_sha256 != task.task_plan_sha256
        or result.logical_request_id != task.logical_request_id
        or result.scope != task.scope
        or result.reviewed_candidate_ids != candidate_ids
        or result.output_sha256 is None
        or result.output_artifact_sha256 is None
        or result.model_completion_evidence_sha256 is None
        or result.usage_record_sha256 is None
        or result.context_request_evidence_sha256 is None
        or result.provider_response_sha256 is None
        or result.validated_response_sha256 is None
        or result.normalizer_sha256 is None
        or result.normalizer_sha256 != task.normalizer_sha256
    ):
        raise ConsensusEvidenceError(
            f"consensus {slot.value} result differs from its exact successful task"
        )


def _validate_usage_join(
    *,
    slot: ConsensusReviewerSlot,
    task: SchedulerTaskPlan,
    result: SchedulerTaskResult,
    usage: UsageRecord,
) -> None:
    usage_sha256 = scheduler_canonical_sha256(usage.model_dump(mode="json"))
    routed_lineage = usage.routing.get("qualified_root_lineage")
    try:
        context = ContextRequestEvidence.model_validate(
            usage.routing.get("context_request_evidence")
        )
    except (TypeError, ValueError) as exc:
        raise ConsensusEvidenceError(
            f"consensus {slot.value} usage lacks exact context request evidence"
        ) from exc
    if (
        usage.request_id != task.logical_request_id
        or usage.role != task.role
        or usage.requested_model != task.requested_model
        or usage.returned_model != task.requested_model
        or usage.actual_model != task.requested_model
        or usage.status != "success"
        or usage.validation_status is not ModelRequestValidationStatus.VALID
        or not usage.openrouter_generation_id
        or usage.fallback_used
        or usage.substitution_detected
        or usage.schema_sha256 != task.response_schema_sha256
        or usage.response_sha256 != result.provider_response_sha256
        or usage.validated_response_sha256 != result.validated_response_sha256
        or context.request_id != task.logical_request_id
        or context.request_role != task.role
        or usage.routing.get("context_request_evidence_sha256") != context.evidence_sha256
        or result.context_request_evidence_sha256 != context.evidence_sha256
        or result.usage_record_sha256 != usage_sha256
        or (routed_lineage is not None and routed_lineage != task.root_lineage)
    ):
        raise ConsensusEvidenceError(
            f"consensus {slot.value} usage differs from its exact task completion"
        )


def _validate_batch_join(
    *,
    slot: ConsensusReviewerSlot,
    result: SchedulerTaskResult,
    usage: UsageRecord,
    raw_batch: VerificationBatch,
    candidate_ids: tuple[str, ...],
) -> None:
    observed_ids = tuple(decision.candidate_id for decision in raw_batch.decisions)
    if len(observed_ids) != len(set(observed_ids)) or tuple(sorted(observed_ids)) != candidate_ids:
        raise ConsensusEvidenceError(
            f"consensus {slot.value} batch differs from the exact candidate inventory"
        )
    batch_sha256 = scheduler_canonical_sha256(raw_batch.model_dump(mode="json"))
    if (
        result.output_sha256 != batch_sha256
        or result.validated_response_sha256 != batch_sha256
        or result.terminal_evidence_sha256 != batch_sha256
        or usage.validated_response_sha256 != batch_sha256
    ):
        raise ConsensusEvidenceError(
            f"consensus {slot.value} raw batch differs from its validated completion hash"
        )


def build_consensus_review_artifact(
    *,
    candidate_workset: SchedulerCandidateWorkset,
    reviewers: Sequence[ConsensusReviewerEvidenceRecord],
) -> ConsensusReviewArtifact:
    """Reconstruct a closed three-review artifact from exact scheduler evidence.

    The function is side-effect free and performs the same comparisons for live pipeline
    assembly and detached manifest replay.  Serialized self-hashes are never treated as a
    substitute for the cross-object task, usage, completion, and raw-output joins.
    """

    workset = _freeze_exact_model(
        candidate_workset,
        SchedulerCandidateWorkset,
        "candidate workset",
    )
    if (
        workset.pass_kind is not SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
        or not workset.selected_candidate_ids
    ):
        raise ConsensusEvidenceError(
            "consensus requires a non-empty pass-six validation candidate workset"
        )
    candidate_ids = workset.selected_candidate_ids
    candidate_payload_sha256s = {
        binding.candidate_id: binding.candidate_payload_sha256
        for binding in workset.selected_candidate_payload_bindings
    }
    if tuple(candidate_payload_sha256s) != candidate_ids:
        raise ConsensusEvidenceError(
            "consensus candidate payload bindings differ from the selected workset"
        )

    reviewer_batches: list[ConsensusReviewerBatch] = []
    plan_identities: set[tuple[str, str, str, str, str]] = set()
    reviewer_identities: list[tuple[str, str, str, str, str, str]] = []
    for record in _canonical_records(reviewers):
        task = _freeze_exact_model(record.task, SchedulerTaskPlan, f"{record.slot.value} task")
        result = _freeze_exact_model(
            record.result,
            SchedulerTaskResult,
            f"{record.slot.value} result",
        )
        usage = _freeze_exact_model(record.usage, UsageRecord, f"{record.slot.value} usage")
        raw_batch = _freeze_exact_model(
            record.raw_batch,
            VerificationBatch,
            f"{record.slot.value} raw batch",
        )
        _validate_task_result_join(
            slot=record.slot,
            task=task,
            result=result,
            candidate_ids=candidate_ids,
        )
        _validate_usage_join(
            slot=record.slot,
            task=task,
            result=result,
            usage=usage,
        )
        _validate_batch_join(
            slot=record.slot,
            result=result,
            usage=usage,
            raw_batch=raw_batch,
            candidate_ids=candidate_ids,
        )
        assert task.requested_model is not None
        assert task.root_lineage is not None
        assert result.model_completion_evidence_sha256 is not None
        assert usage.openrouter_generation_id is not None
        reviewer_batches.append(
            ConsensusReviewerBatch.build(
                slot=record.slot,
                scheduler_task_id=task.task_id,
                logical_request_id=task.logical_request_id,
                requested_model=task.requested_model,
                returned_model=usage.returned_model,
                root_lineage=task.root_lineage,
                model_completion_evidence_sha256=(result.model_completion_evidence_sha256),
                decisions=raw_batch.decisions,
            )
        )
        reviewer_identities.append(
            (
                task.task_id,
                result.result_id,
                task.logical_request_id,
                task.root_lineage,
                result.model_completion_evidence_sha256,
                usage.openrouter_generation_id,
            )
        )
        plan_identities.add(
            (
                task.campaign_id,
                task.manifest_sha256,
                task.pass_id,
                result.pass_plan_id,
                result.pass_plan_sha256,
            )
        )

    if len(plan_identities) != 1:
        raise ConsensusEvidenceError("consensus reviewers do not belong to one exact pass-six plan")
    if any(
        len({identities[index] for identities in reviewer_identities})
        != len(CONSENSUS_REVIEWER_SLOTS)
        for index in range(6)
    ):
        raise ConsensusEvidenceError(
            "consensus task, result, request, root, completion, and provider generation "
            "identities must be distinct"
        )
    campaign_id, manifest_sha256, _pass_id, pass_plan_id, pass_plan_sha256 = next(
        iter(plan_identities)
    )
    try:
        return ConsensusReviewArtifact.build(
            campaign_id=campaign_id,
            manifest_sha256=manifest_sha256,
            pass_plan_id=pass_plan_id,
            pass_plan_sha256=pass_plan_sha256,
            candidate_workset_sha256=workset.workset_sha256,
            candidate_payload_sha256s=candidate_payload_sha256s,
            reviewers=reviewer_batches,
        )
    except (TypeError, ValueError) as exc:
        raise ConsensusEvidenceError(
            "consensus reviewer inventory failed exact artifact reconstruction"
        ) from exc


__all__ = [
    "ConsensusEvidenceError",
    "ConsensusReviewerEvidenceRecord",
    "build_consensus_review_artifact",
]
