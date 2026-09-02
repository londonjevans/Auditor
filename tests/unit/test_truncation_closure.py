"""Deterministic model tests for multi-attempt candidate-review surface closure."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from decimal import Inexact, localcontext
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.openrouter import StructuredCompletion
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.schemas import (
    CandidateReviewBatch,
    ContextExcerpt,
    ContextPackage,
    ContextRequestEvidence,
    ExecutionEvidenceKind,
    Location,
    ModelRequestValidationStatus,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    RepositoryFile,
    RepositoryMap,
    ScannerFinding,
    Severity,
    UsageRecord,
)
from mmaudit.models.truncation import (
    CandidateReviewFramedDocument,
    CandidateReviewNormalizationEvidence,
    CandidateReviewTruncatedEnvelopeEvidence,
    candidate_review_frame_wire_schema_sha256,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
    project_truncated_candidate_review_prefix,
    seal_candidate_review_truncated_envelope_evidence,
)
from mmaudit.models.truncation_closure import (
    TruncationClosureError,
    TruncationNoncompletionState,
    TruncationRecoveredSurfaceReviewArtifact,
    TruncationRecoveryChildCompletionEvidence,
    TruncationRecoveryNoncompletionEvidence,
    TruncationRecoveryParentAttemptEvidence,
    TruncationSurfaceOriginKind,
    build_truncation_recovered_surface_artifact,
)
from mmaudit.models.truncation_recovery import (
    TruncationRecoveryChannel,
    TruncationRecoveryChannelBinding,
    TruncationRecoveryChannelState,
    TruncationRecoveryParentBinding,
    TruncationRecoveryResourceBudget,
    plan_truncation_recovery,
)
from mmaudit.models.truncation_recovery_journal import (
    rebuild_truncation_recovery_parent_from_projection,
)
from mmaudit.models.usage import (
    is_structurally_accountable_usage_record,
    is_structurally_recovery_creditable_usage_record,
    request_token_plan_from_usage,
)
from mmaudit.orchestration.budgets import AtomicRequestLimitReservationEvidence
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.model_review_evidence import (
    build_source_file_review_request,
    model_surface_context_source_custody,
    seal_model_surface_review_artifact,
)
from mmaudit.orchestration.truncation_recovery_evidence import (
    model_surface_analysis_context_sha256,
)
from tests.identity_fixtures import (
    synthetic_strict_zdr_privacy_routing,
    synthetic_token_plan_routing,
)
from tests.output_evidence_fixtures import synthetic_structured_output_routing

_ROLE = "source_audit"
_MODEL = "author/exact-model"
_PROVIDER = "Approved Provider"
_ENDPOINT = "approved-provider"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _source(index: int) -> tuple[str, str]:
    path = f"src/Synthetic{index}.sol"
    content = (
        f"contract Synthetic{index} {{\n"
        "    uint256 public value;\n"
        "    function update(uint256 next) external { value = next; }\n"
        "}\n"
    )
    return path, content


def _requests() -> tuple[ModelSurfaceReviewRequest, ...]:
    values = []
    for index in range(4):
        path, content = _source(index)
        values.append(
            build_source_file_review_request(
                path=path,
                size=len(content.encode()),
                lines=len(content.splitlines()),
                sha256=hashlib.sha256(content.encode()).hexdigest(),
            )
        )
    return tuple(sorted(values, key=lambda item: item.surface_id))


def _record(
    request: ModelSurfaceReviewRequest,
    *,
    status: ModelSurfaceReviewStatus = ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
) -> ModelSurfaceReviewRecord:
    citation = ModelSurfaceReviewCitation(location=request.allowed_locations[0])
    return ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=_ROLE,
        status=status,
        rationale="The exact file was reviewed for security-relevant state behavior.",
        citation=citation,
        invariant_considered=request.invariant_considered,
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=citation,
                observed_behavior="The local update validates its input before recording state.",
                security_relevance=(
                    "The delivered source preserves input validation and state integrity."
                ),
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=citation,
            path=(citation,),
            actor_or_caller="local repository reviewer",
            preconditions=(),
        ),
        assumptions=(),
        confidence=0.9,
    )


def _context(requests: tuple[ModelSurfaceReviewRequest, ...]) -> ContextPackage:
    files: list[RepositoryFile] = []
    excerpts: list[ContextExcerpt] = []
    for index in range(4):
        path, content = _source(index)
        digest = hashlib.sha256(content.encode()).hexdigest()
        lines = len(content.splitlines())
        files.append(
            RepositoryFile(
                path=path,
                size=len(content.encode()),
                lines=lines,
                sha256=digest,
                language="Solidity",
            )
        )
        excerpts.append(
            ContextExcerpt(
                path=path,
                start_line=1,
                end_line=lines,
                content_hash=digest,
                content=content,
            )
        )
    package = ContextPackage(
        role=_ROLE,
        byte_budget=100_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=100_000,
        effective_source_byte_ceiling=100_000,
        repository_map=RepositoryMap(
            root_name="synthetic",
            languages={"Solidity": 4},
            frameworks=[],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=files,
        ),
        scanner_findings=(
            ScannerFinding(
                scanner="synthetic",
                rule_id="synthetic.local-state",
                title="Synthetic local state observation",
                severity=Severity.INFORMATIONAL,
                message="Synthetic committed scanner evidence for closure replay.",
                locations=[Location(path="src/Synthetic0.sol", start_line=1, end_line=1)],
                fingerprint=_digest("truncation-closure-scanner-fingerprint"),
            ),
        ),
        excerpts=tuple(excerpts),
        requested_model_surfaces=requests,
    )
    return package.model_copy(update={"bytes_used": len(render_context(package).encode("utf-8"))})


def _context_evidence(context: ContextPackage, request_id: str) -> ContextRequestEvidence:
    rendered = render_context(context)
    requested_surface_manifest_sha256, source_location_proof_sha256s = (
        model_surface_context_source_custody(context)
    )
    return ContextRequestEvidence.build(
        request_id=request_id,
        request_role=_ROLE,
        context_role=context.role,
        byte_budget=context.byte_budget,
        declared_bytes_used=context.bytes_used,
        rendered_bytes=len(rendered.encode()),
        source_bytes=sum(len(item.content.encode()) for item in context.excerpts),
        configured_maximum_source_tokens_per_request=(
            context.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=context.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(rendered.encode()).hexdigest(),
        requested_surface_manifest_sha256=requested_surface_manifest_sha256,
        source_location_proof_sha256s=source_location_proof_sha256s,
    )


def _usage(
    *,
    context: ContextPackage,
    request_id: str,
    generation_id: str,
    response_sha256: str,
    validated_response_sha256: str | None,
    status: str,
    finish_reason: str,
    validation_status: ModelRequestValidationStatus,
    cost: str,
    completion_tokens: int,
) -> UsageRecord:
    started = datetime(2026, 8, 18, 1, 0, tzinfo=UTC)
    ended = started + timedelta(milliseconds=50)
    schema_sha256 = candidate_review_frame_wire_schema_sha256()
    prompt_sha256 = _digest("provider-prompt")
    request_body_sha256 = _digest("body:" + request_id)
    context_evidence = _context_evidence(context, request_id)
    structured_validated = validated_response_sha256 or _digest("nonvalidated:" + request_id)
    routing = synthetic_strict_zdr_privacy_routing(
        {
            "generation_id": generation_id,
            "generation_header_id": generation_id,
            "provider": "approved-provider-identity",
            "selected_model": _MODEL,
            "canonical_model": _MODEL,
            "selected_provider_name": _PROVIDER,
            "selected_provider_identity": "approved-provider-identity",
            "response_provider_identity": "approved-provider-identity",
            "selected_provider_endpoint": _ENDPOINT,
            "router_strategy": "direct",
            "finish_reason": finish_reason,
            "native_finish_reason": None,
            "schema_sha256": schema_sha256,
            "router_metadata_sha256": _digest("router-metadata"),
            "provider_policy_sha256": _digest("provider-policy"),
            "endpoint_snapshot_sha256": _digest("endpoint-snapshot"),
            "output_capability_sha256": _digest("output-capability"),
            "validation_status": "valid" if status == "success" else "rejected",
            "zdr_requested": True,
            "data_collection": "deny",
            "repair_used": False,
            "repair_request": False,
            "structured_output": synthetic_structured_output_routing(
                configured_provider_endpoints=(_ENDPOINT,),
                selected_provider_endpoint=_ENDPOINT,
                endpoint_snapshot_sha256=_digest("endpoint-snapshot"),
                output_capability_sha256=_digest("output-capability"),
                prompt_sha256=prompt_sha256,
                request_body_sha256=request_body_sha256,
                provider_policy_sha256=_digest("provider-policy"),
                schema_sha256=schema_sha256,
                original_response_sha256=response_sha256,
                validated_response_sha256=structured_validated,
                mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
            ),
            "context_request_evidence": context_evidence.model_dump(mode="json"),
            "context_request_evidence_sha256": context_evidence.evidence_sha256,
            "request_started_at": started.isoformat(),
            "request_ended_at": ended.isoformat(),
            "latency_ms": 50,
            "certification_request": False,
        },
        source_label="truncation-closure-synthetic-source",
    )
    numeric_cost = float(cost)
    provisional = UsageRecord(
        request_id=request_id,
        role=_ROLE,
        execution_evidence=ExecutionEvidenceKind.MOCK,
        requested_model=_MODEL,
        returned_model=_MODEL,
        actual_model=_MODEL,
        provider=_PROVIDER,
        model_family="author",
        timestamp=started,
        prompt_tokens=100,
        completion_tokens=completion_tokens,
        total_tokens=100 + completion_tokens,
        reported_cost_usd=numeric_cost,
        accounted_cost_usd=numeric_cost,
        reported_cost_usd_exact=cost,
        accounted_cost_usd_exact=cost,
        routing=routing,
        prompt_sha256=prompt_sha256,
        user_prompt_sha256=context_evidence.rendered_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256=request_body_sha256,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[_ENDPOINT],
        actual_provider_endpoint=_ENDPOINT,
        started_at=started,
        ended_at=ended,
        latency_ms=50,
        finish_reason=finish_reason,
        retry_count=0,
        provider_error_classification=(None if status == "success" else "truncated_response"),
        validation_status=validation_status,
        status=status,
        attempts=1,
    )
    return provisional.model_copy(
        update={"routing": synthetic_token_plan_routing(provisional, provisional.routing)}
    )


def _with_request_limit(
    usage: UsageRecord,
    *,
    request_limit_scope: str | None = None,
    request_limit_count_before: int = 0,
) -> UsageRecord:
    plan = request_token_plan_from_usage(usage)
    assert plan is not None
    evidence = AtomicRequestLimitReservationEvidence.build(
        request_id=usage.request_id,
        exact_model_id=usage.requested_model,
        role=usage.role,
        request_token_plan_sha256=plan.plan_sha256,
        request_limit_scope=request_limit_scope or usage.request_id,
        request_limit_count_before=request_limit_count_before,
        request_limit_maximum=10,
    )
    return usage.model_copy(
        update={
            "routing": {
                **usage.routing,
                "atomic_request_limit_reservations": [evidence.model_dump(mode="json")],
                "atomic_request_limit_reservation_sha256s": [evidence.evidence_sha256],
                "atomic_request_limit_reservation": evidence.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": evidence.evidence_sha256,
            }
        }
    )


def _truncated_projection(
    requests: tuple[ModelSurfaceReviewRequest, ...],
    *,
    record_status: ModelSurfaceReviewStatus,
) -> tuple[Any, str]:
    records = tuple(_record(request, status=record_status) for request in requests)
    document = frame_candidate_review_batch(
        CandidateReviewBatch(findings=[], surface_reviews=records)
    )
    retained_frame_count = 4  # BEGIN, FINDINGS_END, and two complete surface records.
    frame_json = tuple(
        json.dumps(
            frame.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        for frame in document.frames
    )
    content = (
        '{"frames":['
        + ",".join(frame_json[:retained_frame_count])
        + ',{"schema_version":"1.0","sequence":4,"phase":"SURFACE_REVIEW","record":'
    )
    projection = project_truncated_candidate_review_prefix(
        content,
        finish_reason="length",
        native_finish_reason=None,
    )
    return projection, hashlib.sha256(content.encode()).hexdigest()


def _channel_binding(
    channel: TruncationRecoveryChannel,
    state: TruncationRecoveryChannelState,
    count: int,
) -> TruncationRecoveryChannelBinding:
    return TruncationRecoveryChannelBinding.build(
        channel=channel,
        state=state,
        retained_record_count=count,
        retained_inventory_sha256=_digest(f"{channel.value}:{state.value}:{count}"),
    )


def _artifact(
    context: ContextPackage,
    batch: CandidateReviewBatch,
    usage: UsageRecord,
    normalization: CandidateReviewNormalizationEvidence,
    *,
    request_limit_scope: str,
    request_limit_count_before: int,
) -> ModelSurfaceReviewArtifact:
    artifact = seal_model_surface_review_artifact(
        context,
        StructuredCompletion(value=batch, usage_record=usage),
        rendered_user_context=render_context(context),
        normalization_evidence=normalization,
        recovery_request_limit_scope=request_limit_scope,
        recovery_request_limit_count_before=request_limit_count_before,
    )
    assert artifact is not None
    return artifact


def _with_truncation_custody(
    usage: UsageRecord,
    *,
    envelope: CandidateReviewTruncatedEnvelopeEvidence,
    projection: Any,
) -> UsageRecord:
    routing = {
        **usage.routing,
        "candidate_review_truncated_envelope_evidence": envelope.model_dump(mode="json"),
        "candidate_review_truncated_envelope_sha256": envelope.evidence_sha256,
        "candidate_review_truncation_projection_sha256": projection.evidence_sha256,
        "candidate_review_truncation_termination": projection.termination.value,
        "candidate_review_truncation_findings_state": projection.findings_state.value,
        "candidate_review_truncation_surface_reviews_state": (
            projection.surface_reviews_state.value
        ),
        "candidate_review_truncation_summary_state": projection.summary_state.value,
        "candidate_review_truncation_stream_integrity_valid": (projection.stream_integrity_valid),
        "candidate_review_truncation_document_complete": projection.document_complete,
        "candidate_review_truncation_declared_finding_count": (projection.declared_finding_count),
        "candidate_review_truncation_declared_surface_review_count": (
            projection.declared_surface_review_count
        ),
        "candidate_review_truncation_observed_frame_count": projection.observed_frame_count,
        "candidate_review_truncation_observed_finding_frame_count": (
            projection.observed_finding_frame_count
        ),
        "candidate_review_truncation_observed_surface_review_frame_count": (
            projection.observed_surface_review_frame_count
        ),
        "candidate_review_truncation_accepted_frame_count": len(projection.accepted_frames),
        "candidate_review_truncation_accepted_finding_count": projection.accepted_finding_count,
        "candidate_review_truncation_accepted_surface_review_count": (
            projection.accepted_surface_review_count
        ),
        "candidate_review_truncation_invalid_frame_count": projection.invalid_frame_count,
        "candidate_review_truncation_credit_eligible": False,
        "candidate_review_truncation_authority_eligible": False,
    }
    return UsageRecord.model_validate(
        usage.model_copy(update={"routing": routing}).model_dump(mode="python")
    )


def build_closure_fixture(
    *,
    record_status: ModelSurfaceReviewStatus = ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
    parent_cost: str = "0.4",
    child_cost: str = "0.05",
) -> tuple[
    TruncationRecoveredSurfaceReviewArtifact,
    ContextPackage,
    tuple[ContextPackage, ...],
]:
    requests = _requests()
    parent_context = _context(requests)
    projection, response_sha256 = _truncated_projection(
        requests,
        record_status=record_status,
    )
    parent_request_id = "scheduler-request-" + _digest("parent-request")
    parent_usage = _with_request_limit(
        _usage(
            context=parent_context,
            request_id=parent_request_id,
            generation_id="generation-parent",
            response_sha256=response_sha256,
            validated_response_sha256=None,
            status="rejected_truncated_response",
            finish_reason="length",
            validation_status=ModelRequestValidationStatus.TRUNCATED,
            cost=parent_cost,
            completion_tokens=20,
        )
    )
    assert is_structurally_accountable_usage_record(parent_usage)
    envelope: CandidateReviewTruncatedEnvelopeEvidence = (
        seal_candidate_review_truncated_envelope_evidence(
            logical_request_id=parent_request_id,
            generation_id="generation-parent",
            generation_header_id="generation-parent",
            requested_model=_MODEL,
            returned_model=_MODEL,
            selected_model=_MODEL,
            response_provider_identity="approved-provider-identity",
            selected_provider_endpoint=_ENDPOINT,
            selected_provider_identity="approved-provider-identity",
            selected_provider_name=_PROVIDER,
            router_metadata_sha256=_digest("router-metadata"),
            finish_reason="length",
            native_finish_reason=None,
            wire_schema_sha256=candidate_review_frame_wire_schema_sha256(),
            response_sha256=response_sha256,
        )
    )
    parent_usage = _with_truncation_custody(
        parent_usage,
        envelope=envelope,
        projection=projection,
    )
    provider_attempt_sha256 = _digest("parent-provider-attempt")
    parent = TruncationRecoveryParentAttemptEvidence.build(
        parent_task_id="scheduler-task-" + _digest("parent-task"),
        parent_activation_sha256=_digest("parent-activation"),
        provider_attempt_evidence_sha256=provider_attempt_sha256,
        usage_record=parent_usage,
        envelope=envelope,
        projection=projection,
    )
    manifest_sha256 = ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(
        requests
    )
    claimed_parent_binding = TruncationRecoveryParentBinding.build(
        campaign_id="scheduler-campaign-" + _digest("campaign"),
        pass_plan_id="scheduler-plan-" + _digest("pass-plan"),
        parent_task_id=parent.parent_task_id,
        parent_logical_request_id=parent_request_id,
        parent_task_plan_sha256=_digest("parent-task-plan"),
        parent_activation_sha256=parent.parent_activation_sha256,
        provider_attempt_evidence_sha256=provider_attempt_sha256,
        truncation_projection_sha256=projection.evidence_sha256,
        requested_surface_manifest_sha256=manifest_sha256,
        requested_surface_ids=tuple(request.surface_id for request in requests),
        retained_surface_ids=parent.retained_surface_ids,
        channel_bindings=(
            _channel_binding(
                TruncationRecoveryChannel.COVERAGE,
                TruncationRecoveryChannelState.INCOMPLETE,
                2,
            ),
            _channel_binding(
                TruncationRecoveryChannel.FINDINGS,
                TruncationRecoveryChannelState.COMPLETE,
                0,
            ),
            _channel_binding(
                TruncationRecoveryChannel.SUMMARY,
                TruncationRecoveryChannelState.INCOMPLETE,
                0,
            ),
        ),
    )
    parent_binding = rebuild_truncation_recovery_parent_from_projection(
        claimed_parent=claimed_parent_binding,
        projection=projection,
    )
    resources = TruncationRecoveryResourceBudget.build(
        campaign_cap_usd_exact="250",
        accounted_usd_before_parent_exact="1",
        parent_accounted_cost_usd_exact="0.4",
        child_reserved_usd_exact="0.1",
        recovery_requests_consumed=0,
        provider_attempts_before_parent=0,
        parent_provider_attempts=1,
        child_provider_attempts=1,
        completion_tokens_before_parent=0,
        parent_completion_tokens=20,
        child_completion_tokens=100,
    )
    plan = plan_truncation_recovery(parent=parent_binding, resources=resources)
    child_evidence: list[TruncationRecoveryChildCompletionEvidence] = []
    child_contexts: list[ContextPackage] = []
    analysis_hash = model_surface_analysis_context_sha256(parent_context)
    request_by_id = {request.surface_id: request for request in requests}
    for index, child_plan in enumerate(plan.children):
        child_requests = tuple(request_by_id[item] for item in child_plan.surface_ids)
        child_context = _context(child_requests)
        records = tuple(_record(request, status=record_status) for request in child_requests)
        batch = CandidateReviewBatch(findings=[], surface_reviews=records)
        document: CandidateReviewFramedDocument = frame_candidate_review_batch(batch)
        normalized_batch, normalization = normalize_candidate_review_document(
            document,
            request_id=child_plan.child_logical_request_id,
        )
        raw_response_sha256 = _digest(f"child-raw-response:{index}")
        request_limit_count_before = index + 1
        usage = _with_request_limit(
            _usage(
                context=child_context,
                request_id=child_plan.child_logical_request_id,
                generation_id=f"generation-child-{index}",
                response_sha256=raw_response_sha256,
                validated_response_sha256=normalization.wire_validated_response_sha256,
                status="success",
                finish_reason="stop",
                validation_status=ModelRequestValidationStatus.VALID,
                cost=child_cost,
                completion_tokens=25,
            ),
            request_limit_scope=parent_request_id,
            request_limit_count_before=request_limit_count_before,
        )
        assert is_structurally_recovery_creditable_usage_record(
            usage,
            request_limit_scope=parent_request_id,
            request_limit_count_before=request_limit_count_before,
        )
        artifact = _artifact(
            child_context,
            normalized_batch,
            usage,
            normalization,
            request_limit_scope=parent_request_id,
            request_limit_count_before=request_limit_count_before,
        )
        child_evidence.append(
            TruncationRecoveryChildCompletionEvidence.build(
                child_plan=child_plan,
                analysis_context_sha256=analysis_hash,
                requests=child_requests,
                request_limit_scope=parent_request_id,
                request_limit_count_before=request_limit_count_before,
                usage_record=usage,
                normalization=normalization,
                normalized_batch=normalized_batch,
                surface_artifact=artifact,
            )
        )
        child_contexts.append(child_context)
    closure = build_truncation_recovered_surface_artifact(
        recovery_plan=plan,
        analysis_context_sha256=analysis_hash,
        requests=requests,
        parent=parent,
        children=child_evidence,
    )
    return closure, parent_context, tuple(child_contexts)


def _reseal_closure(payload: dict[str, Any]) -> None:
    payload["artifact_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "artifact_sha256"}
    )


def test_closed_family_has_exact_union_origins_and_accounting() -> None:
    closure, _parent_context, _child_contexts = build_closure_fixture()

    assert tuple(record.surface_id for record in closure.records) == tuple(
        request.surface_id for request in closure.requests
    )
    assert tuple(origin.surface_id for origin in closure.origins) == tuple(
        request.surface_id for request in closure.requests
    )
    assert (
        tuple(origin.origin_kind for origin in closure.origins).count(
            TruncationSurfaceOriginKind.PARENT_PROVISIONAL
        )
        == 2
    )
    assert closure.surface_set_structurally_closed
    assert not closure.scheduler_custody_verified
    assert not closure.scheduler_surface_closure_eligible
    assert not closure.surface_review_credit_eligible
    assert not closure.candidate_credit_eligible
    assert not closure.summary_credit_eligible
    assert not closure.completion_authorized
    assert closure.accepted_candidates == ()
    assert all(child.surface_artifact.schema_version == "1.1" for child in closure.children)
    assert all(
        child.surface_artifact.normalization_evidence == child.normalization
        and child.surface_artifact.normalized_response == child.normalized_batch
        for child in closure.children
    )
    assert closure.accounting.provider_request_count == 3
    assert closure.accounting.provider_attempt_count == 3
    assert closure.accounting.family_accounted_cost_usd_exact == "0.5"
    assert closure.accounting.campaign_accounted_cost_usd_exact == "1.5"
    assert not closure.accounting.parent_cost_refunded


@pytest.mark.parametrize(
    "mutation",
    ["missing_child", "overlap", "generation_collision", "wire_normalized_swap"],
)
def test_gap_overlap_identity_and_schema_splices_fail_closed(mutation: str) -> None:
    closure, _parent_context, _child_contexts = build_closure_fixture()
    if mutation == "missing_child":
        with pytest.raises(TruncationClosureError):
            build_truncation_recovered_surface_artifact(
                recovery_plan=closure.recovery_plan,
                analysis_context_sha256=closure.invariant_binding.analysis_context_sha256,
                requests=closure.requests,
                parent=closure.parent,
                children=closure.children[:1],
            )
        return
    payload = closure.model_dump(mode="json")
    if mutation == "overlap":
        payload["children"][1]["surface_artifact"]["records"] = payload["children"][0][
            "surface_artifact"
        ]["records"]
    elif mutation == "generation_collision":
        payload["children"][1]["usage_record"]["openrouter_generation_id"] = payload["children"][0][
            "usage_record"
        ]["openrouter_generation_id"]
    else:
        payload["children"][0]["normalization"]["wire_validated_response_sha256"] = payload[
            "children"
        ][0]["normalization"]["normalized_batch_sha256"]
    _reseal_closure(payload)
    with pytest.raises(ValidationError):
        TruncationRecoveredSurfaceReviewArtifact.model_validate(payload)


def test_parent_failed_usage_must_retain_exact_raw_free_truncation_custody() -> None:
    closure, _parent_context, _child_contexts = build_closure_fixture()
    payload = closure.parent.model_dump(mode="json")
    payload["usage_record"]["routing"]["candidate_review_truncation_observed_frame_count"] += 1
    payload["usage_record_sha256"] = _canonical_sha256(payload["usage_record"])
    payload["parent_attempt_evidence_sha256"] = _canonical_sha256(
        {key: value for key, value in payload.items() if key != "parent_attempt_evidence_sha256"}
    )

    with pytest.raises(ValidationError, match="envelope or projection"):
        TruncationRecoveryParentAttemptEvidence.model_validate_json(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )


def test_child_resource_overrun_and_parent_cost_mismatch_reject() -> None:
    closure, _parent_context, _child_contexts = build_closure_fixture()
    child = closure.children[0]
    overrun_usage = child.usage_record.model_copy(
        update={"completion_tokens": 101, "total_tokens": 201}
    )
    with pytest.raises(ValidationError):
        TruncationRecoveryChildCompletionEvidence.model_validate(
            {
                **child.model_dump(mode="python"),
                "usage_record": overrun_usage,
                "usage_record_sha256": _canonical_sha256(overrun_usage.model_dump(mode="json")),
            }
        )

    payload = closure.model_dump(mode="json")
    payload["recovery_plan"]["resources"]["parent_accounted_cost_usd_exact"] = "0.3"
    _reseal_closure(payload)
    with pytest.raises(ValidationError):
        TruncationRecoveredSurfaceReviewArtifact.model_validate(payload)


def test_accounting_ignores_hostile_ambient_decimal_context() -> None:
    baseline, _parent_context, _child_contexts = build_closure_fixture()
    with localcontext() as context:
        context.prec = 2
        context.traps[Inexact] = True
        closure = build_truncation_recovered_surface_artifact(
            recovery_plan=baseline.recovery_plan,
            analysis_context_sha256=baseline.invariant_binding.analysis_context_sha256,
            requests=baseline.requests,
            parent=baseline.parent,
            children=baseline.children,
        )

    assert closure.accounting.campaign_accounted_cost_usd_exact == "1.5"


def test_fixed_scale_provider_cost_text_is_preserved_and_compared_exactly() -> None:
    closure, _parent_context, _child_contexts = build_closure_fixture(
        parent_cost="0.400000000000000000",
        child_cost="0.050000000000000000",
    )

    assert closure.parent.usage_record.accounted_cost_usd_exact == "0.400000000000000000"
    assert all(
        child.usage_record.accounted_cost_usd_exact == "0.050000000000000000"
        for child in closure.children
    )
    assert closure.accounting.parent_accounted_cost_usd_exact == "0.4"
    assert closure.accounting.child_accounted_cost_usd_exact == "0.1"
    assert closure.accounting.family_accounted_cost_usd_exact == "0.5"


def test_noncompletion_states_are_literal_false_and_cannot_claim_recovered() -> None:
    evidence = TruncationRecoveryNoncompletionEvidence.build(
        state=TruncationNoncompletionState.UNCERTAIN,
        recovery_plan_sha256=_digest("plan"),
        observed_child_task_ids=(),
        observed_evidence_sha256s=(),
    )

    assert not evidence.surface_review_credit_eligible
    assert not evidence.review_credit_authorized
    assert not evidence.completion_authorized
    payload = evidence.model_dump(mode="python")
    payload["surface_review_credit_eligible"] = True
    with pytest.raises(ValidationError):
        TruncationRecoveryNoncompletionEvidence.model_validate(payload)


def test_inconclusive_surface_records_cannot_claim_a_recovered_surface_set() -> None:
    with pytest.raises(TruncationClosureError):
        build_closure_fixture(record_status=ModelSurfaceReviewStatus.INCONCLUSIVE)
