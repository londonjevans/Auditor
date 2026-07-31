from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.models import usage as usage_module
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningExecutionEvidence,
    ReasoningPolicyArtifact,
    ReasoningRequestPlanEvidence,
)
from mmaudit.models.schemas import (
    AuditReport,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    RepositoryMap,
    UsageRecord,
)
from mmaudit.models.token_planning import (
    CONTEXT_OMISSION_SAMPLE_CAP,
    PROMPT_ALLOCATION_CATEGORIES,
    ContextOmissionCategory,
    ContextOmissionItem,
    ContextOmissionReason,
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
    build_request_token_plan,
)
from mmaudit.orchestration import context_manifest as context_manifest_module
from mmaudit.orchestration.budgets import AtomicTokenReservationEvidence
from mmaudit.orchestration.context_manifest import (
    ActualTokenUsageEvidence,
    ActualTokenUsageSource,
    ContextManifest,
    ContextManifestError,
    ContextOmissionProvenance,
    ContextPlanningSnapshot,
    ContextPreflightLedger,
    ContextPreflightReason,
    ContextPreflightRequestEvidence,
    ContextPreflightSource,
    ContextRequestEvidence,
    ContextRequestState,
    OmissionTokenEstimationState,
    build_context_manifest,
    context_manifest_report_binding,
    load_context_manifest,
    validate_context_manifest_against_usage,
    write_context_manifest,
)
from mmaudit.orchestration.manifest import (
    _validate_context_manifest_configuration,
    _validated_context_manifest,
)
from mmaudit.reporting.json_report import stable_json

_PreflightRequestState = Literal[
    ContextRequestState.PRE_FLIGHT_REJECTED,
    ContextRequestState.NOT_SENT,
]


@pytest.fixture(autouse=True)
def _install_usage_token_plan_parser_for_older_usage_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if callable(getattr(usage_module, "request_token_plan_from_usage", None)):
        return

    def parse(record: UsageRecord) -> RequestTokenPlan:
        raw = record.routing.get("request_token_plan")
        plan = RequestTokenPlan.model_validate_json(json.dumps(raw))
        if record.routing.get("request_token_plan_sha256") != plan.plan_sha256:
            raise ValueError("usage token-plan hash is inconsistent")
        if raw != plan.model_dump(mode="json"):
            raise ValueError("usage token-plan projection is not canonical")
        return plan

    monkeypatch.setattr(
        usage_module,
        "request_token_plan_from_usage",
        parse,
        raising=False,
    )


def _plan(
    *,
    request_id: str = "request-1",
    raw_canary: str = "PRIVATE-SOURCE-CANARY",
    omitted_item_sha256s: Sequence[str] | None = None,
    reasoning_plan: ReasoningRequestPlanEvidence | None = None,
) -> RequestTokenPlan:
    route = EndpointRouteTokenCapacity.build(
        exact_model_id="alpha/frontier-secure",
        provider_endpoint="approved-provider",
        endpoint_snapshot_sha256="a" * 64,
        context_tokens=100_000,
        max_prompt_tokens=90_000,
        max_prompt_tokens_source="metadata",
        max_completion_tokens=20_000,
        max_completion_tokens_source="metadata",
    )
    allocations = tuple(
        PromptTokenAllocation.from_text(
            category,
            (
                ""
                if category is PromptAllocationCategory.PRIOR_AUDIT
                else (
                    raw_canary
                    if category is PromptAllocationCategory.SOURCE
                    else f"host-{category.value}"
                )
            ),
        )
        for category in PROMPT_ALLOCATION_CATEGORIES
    )
    return build_request_token_plan(
        request_id=request_id,
        role="source_audit",
        route_intersection=EndpointRouteIntersection.build((route,)),
        allocations=allocations,
        required_output_tokens=2_048,
        reserved_reasoning_tokens=1_024,
        reasoning_plan=reasoning_plan,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
        context_utilization=Decimal("0.70"),
        configured_reserved_system_tokens=8_192,
        configured_reserved_schema_tokens=8_192,
        configured_reserved_protocol_tokens=2_048,
        configured_reserved_workflow_tokens=32_768,
        context_omissions=(
            ContextOmissionItem.build_aggregate(
                category=ContextOmissionCategory.SOURCE,
                reason=ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                omitted_item_sha256s=(
                    tuple(omitted_item_sha256s)
                    if omitted_item_sha256s is not None
                    else (hashlib.sha256(b"source excerpt omitted by role budget").hexdigest(),)
                ),
            ),
        ),
        prompt_envelope_byte_upper_bound_tokens=sum(
            allocation.estimate.byte_upper_bound_tokens for allocation in allocations
        ),
    )


def _planning_snapshot(
    *,
    request_id: str,
    reason: ContextPreflightReason,
) -> ContextPlanningSnapshot:
    plan = _plan(request_id=request_id)
    return ContextPlanningSnapshot.build(
        request_id=request_id,
        role=plan.role,
        requested_model="alpha/frontier-secure",
        reason=reason,
        route_intersection=plan.route_intersection,
        allocations=plan.allocations,
        output_allocations=plan.output_allocations,
        requested_surface_count=plan.requested_surface_count,
        required_output_tokens=plan.required_output_tokens,
        reserved_reasoning_tokens=plan.reserved_reasoning_tokens,
        prompt_envelope_byte_upper_bound_tokens=(plan.prompt_byte_upper_bound_tokens),
        context_omissions=plan.context_omissions,
    )


def _usage(
    *,
    request_id: str = "request-1",
    plan: RequestTokenPlan | None = None,
    reasoning_evidence: ReasoningExecutionEvidence | None = None,
    reasoning_tokens: int = 0,
    status: str = "success",
    validation_status: ModelRequestValidationStatus = ModelRequestValidationStatus.VALID,
) -> UsageRecord:
    token_plan = plan or _plan(request_id=request_id)
    token_reservation = AtomicTokenReservationEvidence.build(
        request_id=request_id,
        exact_model_id="alpha/frontier-secure",
        role="source_audit",
        request_token_plan_sha256=token_plan.plan_sha256,
        planned_prompt_tokens=token_plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=token_plan.reserved_output_tokens,
        planned_reasoning_tokens=token_plan.reserved_reasoning_tokens,
        planned_completion_tokens=token_plan.requested_completion_tokens,
        global_input_token_limit=1_000_000,
        global_output_token_limit=100_000,
        spent_input_tokens_before=0,
        reserved_input_tokens_before=0,
        spent_output_tokens_before=0,
        reserved_output_tokens_before=0,
    )
    started = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
    return UsageRecord(
        request_id=request_id,
        role="source_audit",
        execution_evidence=ExecutionEvidenceKind.MOCK,
        requested_model="alpha/frontier-secure",
        returned_model="alpha/frontier-secure",
        actual_model="alpha/frontier-secure",
        provider="Synthetic",
        model_family="frontier-secure",
        timestamp=started,
        prompt_tokens=100,
        completion_tokens=100,
        total_tokens=200,
        reported_cost_usd=0.001,
        accounted_cost_usd=0.001,
        routing={
            "request_token_plan": token_plan.model_dump(mode="json"),
            "request_token_plan_sha256": token_plan.plan_sha256,
            "atomic_token_reservation": token_reservation.model_dump(mode="json"),
            "atomic_token_reservation_sha256": token_reservation.evidence_sha256,
        },
        prompt_sha256="1" * 64,
        user_prompt_sha256="2" * 64,
        response_sha256="3" * 64,
        validated_response_sha256="4" * 64,
        request_body_sha256="5" * 64,
        schema_sha256="6" * 64,
        openrouter_generation_id="generation-1",
        configured_provider_endpoints=["approved-provider"],
        actual_provider_endpoint="approved-provider",
        started_at=started,
        ended_at=started,
        latency_ms=0,
        finish_reason="stop",
        reasoning_tokens=reasoning_tokens,
        reasoning_evidence=reasoning_evidence,
        retry_count=0,
        validation_status=validation_status,
        identity_strength=ModelIdentityStrength.UNBOUND,
        status=status,
        attempts=1,
    )


def _usage_with_reasoning_observation(
    observed_reasoning_tokens: int | None,
) -> UsageRecord:
    disabled = ReasoningControlProfile.build(
        mode="disabled",
        reserved_reasoning_tokens=0,
    )
    controls = {role: disabled for role in CANONICAL_REASONING_POLICY_ROLES}
    controls["source_audit"] = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=1_024,
    )
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role="source_audit",
        policy=ReasoningPolicyArtifact.build(controls_by_role=controls),
    )
    plan = _plan(reasoning_plan=reasoning_plan)
    reasoning_evidence = ReasoningExecutionEvidence.build(
        request_plan=reasoning_plan,
        observed_reasoning_tokens=observed_reasoning_tokens,
        provider_completion_tokens=100,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256="5" * 64,
    )
    return _usage(
        plan=plan,
        reasoning_evidence=reasoning_evidence,
        reasoning_tokens=observed_reasoning_tokens or 0,
        status=("success" if observed_reasoning_tokens is not None else "provider_error"),
        validation_status=(
            ModelRequestValidationStatus.VALID
            if observed_reasoning_tokens is not None
            else ModelRequestValidationStatus.PROVIDER_ERROR
        ),
    )


def _retry_preflight(
    plan: RequestTokenPlan,
    *,
    attempt: int = 2,
) -> ContextPreflightRequestEvidence:
    return ContextPreflightRequestEvidence.build(
        request_id=f"{plan.request_id}:attempt:{attempt}:preflight",
        logical_request_id=plan.request_id,
        role=plan.role,
        requested_model="alpha/frontier-secure",
        request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
        decision_source=ContextPreflightSource.BUDGET_MANAGER,
        reason=ContextPreflightReason.COST_BUDGET,
        decision_evidence_sha256s=("a" * 64, plan.plan_sha256),
        estimated_prompt_tokens=plan.estimated_prompt_tokens,
        requested_completion_tokens=plan.requested_completion_tokens,
        request_plan=plan,
    )


def _report(
    *,
    usage: UsageRecord,
    manifest: ContextManifest,
) -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        run_id=manifest.run_id,
        generated_at=datetime(2026, 7, 29, 12, 1, tzinfo=UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic-context-target",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
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
            files=[],
        ),
        configuration_hash="7" * 64,
        model_configuration_hash="8" * 64,
        privacy={},
        scanner_runs=[],
        usage=[usage],
        budget_usd=1,
        accounted_cost_usd=usage.accounted_cost_usd,
        findings=[],
        rejected_findings=[],
        metadata={
            "context_manifest": context_manifest_report_binding(manifest).model_dump(mode="json")
        },
    )


def test_context_manifest_is_deterministic_hash_only_and_conserved() -> None:
    canary = "PRIVATE-SOURCE-CANARY"
    second_plan = _plan(request_id="request-2", raw_canary=canary)
    usages = [_usage(request_id="request-2", plan=second_plan), _usage()]

    first = build_context_manifest(run_id="run-1", usage_records=usages)
    second = build_context_manifest(run_id="run-1", usage_records=list(reversed(usages)))

    assert first == second
    assert tuple(item.request_id for item in first.requests) == ("request-1", "request-2")
    assert first.totals.request_count == 2
    assert first.totals.completed_request_count == 2
    assert first.totals.mock_reported_request_count == 2
    assert first.totals.mock_reported_prompt_tokens == 200
    assert first.totals.mock_reported_completion_tokens == 200
    assert first.totals.requested_completion_tokens == (
        first.totals.reserved_output_tokens + first.totals.reserved_reasoning_tokens
    )
    assert first.totals.planned_prompt_tokens == sum(
        category.estimated_tokens for category in first.totals.categories
    )
    provider_requests = [
        request for request in first.requests if isinstance(request, ContextRequestEvidence)
    ]
    assert len(provider_requests) == 2
    assert all(
        request.actual_usage.source is ActualTokenUsageSource.MOCK_RESPONSE
        for request in provider_requests
    )
    assert all(
        any(
            omission.reason is ContextOmissionReason.BLIND_DISCOVERY_WITHHELD
            for omission in request.omissions
        )
        for request in provider_requests
    )
    assert all(
        any(
            omission.category is ContextOmissionCategory.SOURCE
            and omission.reason is ContextOmissionReason.SOURCE_BUDGET_EXCLUDED
            and omission.omitted_item_count == 1
            for omission in request.omissions
        )
        for request in provider_requests
    )
    assert all(
        omission.token_estimation_state is OmissionTokenEstimationState.NOT_ESTIMATED
        and omission.estimated_tokens is None
        for request in provider_requests
        for omission in request.omissions
    )
    serialized = first.model_dump_json()
    assert canary not in serialized
    assert "source excerpt omitted by role budget" not in serialized
    assert '"content"' not in serialized


def test_context_manifest_retains_bounded_aggregate_omission_commitment() -> None:
    omitted_hashes = tuple(
        hashlib.sha256(f"synthetic-omitted-block-{index:04d}".encode()).hexdigest()
        for index in range(1_000)
    )
    plan = _plan(omitted_item_sha256s=omitted_hashes)
    manifest = build_context_manifest(
        run_id="bounded-omissions",
        usage_records=[_usage(plan=plan)],
    )
    request = manifest.requests[0]
    assert isinstance(request, ContextRequestEvidence)
    aggregate = next(
        omission
        for omission in request.omissions
        if omission.provenance is ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE
    )
    planned_aggregate = plan.context_omissions[0]

    assert aggregate.inventory_sha256 == planned_aggregate.omitted_item_sha256
    assert aggregate.context_omission_evidence_sha256 == planned_aggregate.evidence_sha256
    assert aggregate.omitted_item_count == len(omitted_hashes)
    assert len(aggregate.omitted_item_sha256s) == CONTEXT_OMISSION_SAMPLE_CAP
    assert aggregate.samples_truncated
    assert manifest.totals.omitted_item_count == len(omitted_hashes)
    assert manifest.totals.sampled_omitted_item_count == CONTEXT_OMISSION_SAMPLE_CAP
    assert manifest.totals.truncated_omission_record_count == 1

    serialized = manifest.model_dump_json()
    unsampled_hash = next(
        value for value in omitted_hashes if value not in aggregate.omitted_item_sha256s
    )
    assert unsampled_hash not in serialized
    assert ContextManifest.model_validate_json(serialized) == manifest


def test_context_manifest_rejects_valid_aggregate_from_a_different_request_plan() -> None:
    original_hashes = tuple(
        hashlib.sha256(f"original-{index:02d}".encode()).hexdigest()
        for index in range(CONTEXT_OMISSION_SAMPLE_CAP + 2)
    )
    replacement_hashes = tuple(
        hashlib.sha256(f"replacement-{index:02d}".encode()).hexdigest()
        for index in range(CONTEXT_OMISSION_SAMPLE_CAP + 2)
    )
    original = build_context_manifest(
        run_id="aggregate-join",
        usage_records=[_usage(plan=_plan(omitted_item_sha256s=original_hashes))],
    )
    replacement = build_context_manifest(
        run_id="aggregate-join",
        usage_records=[_usage(plan=_plan(omitted_item_sha256s=replacement_hashes))],
    )
    original_request = original.requests[0]
    replacement_request = replacement.requests[0]
    assert isinstance(original_request, ContextRequestEvidence)
    assert isinstance(replacement_request, ContextRequestEvidence)
    replacement_aggregate = next(
        omission
        for omission in replacement_request.omissions
        if omission.provenance is ContextOmissionProvenance.HASHED_CONTEXT_PACKAGE
    )
    blind = next(
        omission
        for omission in original_request.omissions
        if omission.provenance is ContextOmissionProvenance.BLIND_DISCOVERY_POLICY
    )
    payload = original_request.model_dump(mode="python")
    payload["omissions"] = tuple(
        sorted(
            (blind, replacement_aggregate),
            key=lambda item: (item.category.value, item.reason.value),
        )
    )

    with pytest.raises(ValidationError, match="differs from its request plan"):
        ContextRequestEvidence.model_validate(payload)


def test_context_manifest_report_binding_is_small_and_self_hashed() -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    assert manifest.schema_version == "1.1"

    binding = context_manifest_report_binding(manifest)
    assert binding.schema_version == "1.1"

    assert binding.manifest_sha256 == manifest.manifest_sha256
    assert binding.request_count == 1
    assert binding.planned_source_tokens > 0
    assert binding.provider_reported_request_count == 0
    assert binding.mock_reported_request_count == 1
    assert binding.omission_record_count == 2
    assert binding.omitted_item_count == 1
    assert binding.sampled_omitted_item_count == 1
    assert binding.truncated_omission_record_count == 0


def test_synthetic_real_evidence_is_counted_only_as_provider_reported_usage() -> None:
    usage = _usage().model_copy(update={"execution_evidence": ExecutionEvidenceKind.REAL})

    manifest = build_context_manifest(run_id="run-1", usage_records=[usage])

    assert manifest.totals.provider_reported_request_count == 1
    assert manifest.totals.provider_reported_prompt_tokens == usage.prompt_tokens
    assert manifest.totals.provider_reported_completion_tokens == usage.completion_tokens
    assert manifest.totals.mock_reported_request_count == 0
    request = manifest.requests[0]
    assert isinstance(request, ContextRequestEvidence)
    assert request.actual_usage.source is ActualTokenUsageSource.PROVIDER_RESPONSE


def test_actual_usage_distinguishes_observed_zero_from_unavailable_reasoning() -> None:
    observed_usage = _usage_with_reasoning_observation(0)
    unavailable_usage = _usage_with_reasoning_observation(None)
    observed_manifest = build_context_manifest(
        run_id="observed-zero",
        usage_records=[observed_usage],
    )
    unavailable_manifest = build_context_manifest(
        run_id="observation-unavailable",
        usage_records=[unavailable_usage],
    )
    observed_request = observed_manifest.requests[0]
    unavailable_request = unavailable_manifest.requests[0]
    assert isinstance(observed_request, ContextRequestEvidence)
    assert isinstance(unavailable_request, ContextRequestEvidence)

    observed = observed_request.actual_usage
    unavailable = unavailable_request.actual_usage
    assert observed.reasoning_observation_available is True
    assert observed.observed_reasoning_tokens == 0
    assert observed.reasoning_execution_state == "active_observed"
    assert unavailable.reasoning_observation_available is False
    assert unavailable.observed_reasoning_tokens is None
    assert unavailable.reasoning_execution_state == "active_unavailable"
    assert observed_usage.reasoning_evidence is not None
    assert unavailable_usage.reasoning_evidence is not None
    assert observed.reasoning_evidence_sha256 == observed_usage.reasoning_evidence.evidence_sha256
    assert (
        unavailable.reasoning_evidence_sha256
        == unavailable_usage.reasoning_evidence.evidence_sha256
    )
    assert observed.evidence_sha256 != unavailable.evidence_sha256
    assert "observed_reasoning_tokens" in observed.model_dump(mode="json")
    assert "observed_reasoning_tokens" not in unavailable.model_dump(mode="json")
    assert (
        ActualTokenUsageEvidence.model_validate_json(observed.model_dump_json(), strict=True)
        == observed
    )
    assert (
        ActualTokenUsageEvidence.model_validate_json(unavailable.model_dump_json(), strict=True)
        == unavailable
    )


def test_actual_usage_reasoning_projection_is_semantic_and_self_hashed() -> None:
    evidence = ActualTokenUsageEvidence.build(_usage_with_reasoning_observation(0))
    unavailable_with_tokens = evidence.model_dump(mode="json")
    unavailable_with_tokens["reasoning_observation_available"] = False
    unavailable_with_tokens["evidence_sha256"] = context_manifest_module._canonical_sha256(
        {key: value for key, value in unavailable_with_tokens.items() if key != "evidence_sha256"}
    )

    with pytest.raises(ValidationError, match="unavailable reasoning evidence"):
        ActualTokenUsageEvidence.model_validate_json(
            json.dumps(unavailable_with_tokens),
            strict=True,
        )

    wrong_hash = evidence.model_dump(mode="json")
    wrong_hash["evidence_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="canonical evidence"):
        ActualTokenUsageEvidence.model_validate_json(json.dumps(wrong_hash), strict=True)


def test_actual_usage_legacy_projection_omits_new_optional_reasoning_fields() -> None:
    evidence = ActualTokenUsageEvidence.build(_usage())
    payload = evidence.model_dump(mode="json")

    assert "reasoning_observation_available" not in payload
    assert "observed_reasoning_tokens" not in payload
    assert "reasoning_execution_state" not in payload
    assert "reasoning_evidence_sha256" not in payload
    assert evidence.evidence_sha256 == context_manifest_module._canonical_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )


def test_truncated_provider_prompt_usage_is_preserved_without_fabricated_completion() -> None:
    usage = _usage().model_copy(
        update={
            "execution_evidence": ExecutionEvidenceKind.REAL,
            "completion_tokens": 0,
            "total_tokens": 100,
            "status": "rejected",
            "validation_status": ModelRequestValidationStatus.TRUNCATED,
        }
    )

    manifest = build_context_manifest(run_id="run-1", usage_records=[usage])
    request = manifest.requests[0]

    assert isinstance(request, ContextRequestEvidence)
    assert request.request_state is ContextRequestState.TRUNCATED
    assert request.actual_usage.source is ActualTokenUsageSource.PROVIDER_RESPONSE
    assert request.actual_usage.prompt_tokens == 100
    assert request.actual_usage.completion_tokens == 0
    assert manifest.totals.provider_reported_prompt_tokens == 100
    assert manifest.totals.provider_reported_completion_tokens == 0


@pytest.mark.parametrize(
    ("prompt_tokens", "completion_tokens", "total_tokens"),
    [
        pytest.param(500, 100, 600, id="existing-prompt-plan-overrun"),
        pytest.param(100, 5_121, 5_221, id="completion-plan-overrun"),
        pytest.param(90_000, 10_001, 100_001, id="total-endpoint-overrun"),
    ],
)
def test_completed_context_manifest_rejects_actual_usage_over_plan_or_endpoint(
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
) -> None:
    usage = _usage().model_copy(
        update={
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }
    )

    with pytest.raises(ValueError, match="actual token usage exceeds"):
        build_context_manifest(run_id="run-1", usage_records=[usage])


def test_context_manifest_rejects_missing_or_tampered_plan() -> None:
    usage = _usage()
    missing_routing = dict(usage.routing)
    missing_routing.pop("request_token_plan")
    missing_routing.pop("request_token_plan_sha256")
    missing = usage.model_copy(update={"routing": missing_routing})

    with pytest.raises(ContextManifestError, match="token-plan"):
        build_context_manifest(run_id="run-1", usage_records=[missing])

    tampered_routing = dict(usage.routing)
    tampered_routing["request_token_plan_sha256"] = "0" * 64
    tampered = usage.model_copy(update={"routing": tampered_routing})
    with pytest.raises(ContextManifestError, match="token-plan"):
        build_context_manifest(run_id="run-1", usage_records=[tampered])


def test_context_manifest_rejects_missing_or_tampered_atomic_reservation() -> None:
    usage = _usage()
    without_reservation = dict(usage.routing)
    without_reservation.pop("atomic_token_reservation")
    without_reservation.pop("atomic_token_reservation_sha256")

    with pytest.raises(ContextManifestError, match="atomic token-reservation"):
        build_context_manifest(
            run_id="run-1",
            usage_records=[usage.model_copy(update={"routing": without_reservation})],
        )

    tampered_routing = dict(usage.routing)
    tampered_evidence = dict(tampered_routing["atomic_token_reservation"])
    tampered_evidence["planned_prompt_tokens"] += 1
    tampered_routing["atomic_token_reservation"] = tampered_evidence
    with pytest.raises(ContextManifestError, match="atomic token-reservation"):
        build_context_manifest(
            run_id="run-1",
            usage_records=[usage.model_copy(update={"routing": tampered_routing})],
        )


def test_context_manifest_rejects_duplicate_request_ids() -> None:
    with pytest.raises(ContextManifestError, match="unique provider request IDs"):
        build_context_manifest(run_id="run-1", usage_records=[_usage(), _usage()])


def test_context_manifest_rejects_retry_preflight_with_a_different_logical_plan() -> None:
    provider_plan = _plan(omitted_item_sha256s=(hashlib.sha256(b"provider omission").hexdigest(),))
    spliced_plan = _plan(omitted_item_sha256s=(hashlib.sha256(b"spliced omission").hexdigest(),))

    with pytest.raises(ContextManifestError, match="logical request plan"):
        build_context_manifest(
            run_id="retry-plan-splice",
            usage_records=[_usage(plan=provider_plan)],
            preflight_records=[_retry_preflight(spliced_plan)],
        )


def test_context_manifest_rejects_preflight_only_retries_with_different_plans() -> None:
    original_plan = _plan(
        omitted_item_sha256s=(hashlib.sha256(b"original preflight omission").hexdigest(),)
    )
    spliced_plan = _plan(
        omitted_item_sha256s=(hashlib.sha256(b"spliced preflight omission").hexdigest(),)
    )

    with pytest.raises(ContextManifestError, match="logical request plan"):
        build_context_manifest(
            run_id="preflight-only-plan-splice",
            usage_records=[],
            preflight_records=[
                _retry_preflight(original_plan),
                _retry_preflight(spliced_plan, attempt=3),
            ],
        )


def test_context_manifest_retains_matching_preflight_only_retries_once_in_totals() -> None:
    plan = _plan()

    manifest = build_context_manifest(
        run_id="matching-preflight-only-retries",
        usage_records=[],
        preflight_records=[
            _retry_preflight(plan),
            _retry_preflight(plan, attempt=3),
        ],
    )

    assert manifest.totals.omission_record_count == 1
    assert manifest.totals.omission_evidence_occurrence_count == 2
    assert manifest.totals.omitted_item_count == 1
    assert manifest.totals.sampled_omitted_item_count == 1
    assert manifest.totals.truncated_omission_record_count == 0


def test_context_manifest_deduplicates_logical_retry_omission_totals() -> None:
    plan = _plan()
    retry_preflight = _retry_preflight(plan)

    manifest = build_context_manifest(
        run_id="retry-omission-totals",
        usage_records=[_usage(plan=plan)],
        preflight_records=[retry_preflight],
    )
    provider = next(
        request for request in manifest.requests if isinstance(request, ContextRequestEvidence)
    )

    assert retry_preflight in manifest.requests
    assert len(provider.omissions) == 2
    assert manifest.totals.omission_record_count == 2
    assert manifest.totals.omission_evidence_occurrence_count == 3
    assert manifest.totals.omitted_item_count == 1
    assert manifest.totals.sampled_omitted_item_count == 1
    assert manifest.totals.truncated_omission_record_count == 0
    binding = context_manifest_report_binding(manifest)
    assert binding.omission_record_count == 2
    assert binding.omission_evidence_occurrence_count == 3


def test_context_manifest_retains_typed_preflight_rejection_without_fabricated_usage() -> None:
    snapshot = _planning_snapshot(
        request_id="request-preflight-1",
        reason=ContextPreflightReason.ENDPOINT_CAPACITY,
    )
    rejection = ContextPreflightRequestEvidence.build(
        request_id="request-preflight-1",
        role="source_audit",
        requested_model="alpha/frontier-secure",
        request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
        decision_source=ContextPreflightSource.TOKEN_PLANNER,
        reason=ContextPreflightReason.ENDPOINT_CAPACITY,
        decision_evidence_sha256s=("9" * 64, snapshot.snapshot_sha256),
        estimated_prompt_tokens=snapshot.estimated_prompt_tokens,
        requested_completion_tokens=snapshot.requested_completion_tokens,
        planning_snapshot=snapshot,
    )

    manifest = build_context_manifest(
        run_id="run-1",
        usage_records=[],
        preflight_records=[rejection],
    )

    assert manifest.requests == (rejection,)
    assert manifest.totals.request_count == 1
    assert manifest.totals.planned_request_count == 0
    assert manifest.totals.preflight_rejected_request_count == 1
    assert manifest.totals.not_sent_request_count == 0
    assert manifest.totals.unavailable_actual_usage_count == 1
    assert manifest.totals.provider_reported_prompt_tokens == 0
    assert manifest.totals.reserved_output_tokens == 0
    assert manifest.totals.provider_attempt_count == 0
    assert manifest.totals.atomic_reservation_count == 0
    assert manifest.totals.omission_record_count == 1
    assert manifest.totals.omitted_item_count == 1
    assert manifest.totals.sampled_omitted_item_count == 1
    assert manifest.totals.truncated_omission_record_count == 0
    assert all(category.request_count == 0 for category in manifest.totals.categories)
    validate_context_manifest_against_usage(
        manifest,
        run_id="run-1",
        usage_records=[],
        preflight_records=[rejection],
    )
    with pytest.raises(ContextManifestError, match="differs from final provider usage"):
        validate_context_manifest_against_usage(
            manifest,
            run_id="run-1",
            usage_records=[],
        )


def test_partial_planning_snapshot_is_complete_self_hashed_and_diagnostic_only() -> None:
    snapshot = _planning_snapshot(
        request_id="request-partial-plan",
        reason=ContextPreflightReason.ENDPOINT_CAPACITY,
    )

    assert snapshot.route_intersection is not None
    assert snapshot.allocations is not None
    assert tuple(item.category for item in snapshot.allocations) == (PROMPT_ALLOCATION_CATEGORIES)
    assert snapshot.output_allocations is not None
    assert sum(item.reserved_tokens for item in snapshot.output_allocations) == (
        snapshot.required_output_tokens
    )
    assert snapshot.estimated_prompt_tokens == sum(
        item.estimate.estimated_tokens for item in snapshot.allocations
    )
    assert snapshot.prompt_content_byte_upper_bound_tokens == sum(
        item.estimate.byte_upper_bound_tokens for item in snapshot.allocations
    )
    assert snapshot.context_omissions
    assert snapshot.context_omission_sha256s == tuple(
        sorted(item.omitted_item_sha256 for item in snapshot.context_omissions)
    )
    assert not snapshot.review_credit
    assert not snapshot.atomic_reservation_created
    assert not snapshot.provider_request_sent
    assert ContextPlanningSnapshot.model_validate_json(snapshot.model_dump_json()) == snapshot


def test_partial_planning_snapshot_rejects_hash_or_component_drift() -> None:
    snapshot = _planning_snapshot(
        request_id="request-partial-drift",
        reason=ContextPreflightReason.ENDPOINT_CAPACITY,
    )
    assert snapshot.estimated_prompt_tokens is not None
    tampered = snapshot.model_copy(
        update={"estimated_prompt_tokens": snapshot.estimated_prompt_tokens + 1}
    )

    with pytest.raises(ValidationError, match=r"totals|hash"):
        ContextPlanningSnapshot.model_validate_json(tampered.model_dump_json())


def test_context_preflight_rejects_planless_token_planner_without_snapshot() -> None:
    with pytest.raises(ValidationError, match="diagnostic planning evidence"):
        ContextPreflightRequestEvidence.build(
            request_id="request-planless-no-snapshot",
            role="source_audit",
            requested_model="alpha/frontier-secure",
            request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
            decision_source=ContextPreflightSource.TOKEN_PLANNER,
            reason=ContextPreflightReason.ENDPOINT_CAPACITY,
            decision_evidence_sha256s=("9" * 64,),
            estimated_prompt_tokens=None,
            requested_completion_tokens=2_048,
        )


def test_context_preflight_rejects_snapshot_identity_or_reason_drift() -> None:
    snapshot = _planning_snapshot(
        request_id="request-snapshot-drift",
        reason=ContextPreflightReason.ENDPOINT_CAPACITY,
    )

    with pytest.raises(ValidationError, match="planning snapshot"):
        ContextPreflightRequestEvidence.build(
            request_id=snapshot.request_id,
            role=snapshot.role,
            requested_model="other/frontier-secure",
            request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
            decision_source=ContextPreflightSource.TOKEN_PLANNER,
            reason=snapshot.reason,
            decision_evidence_sha256s=(snapshot.snapshot_sha256,),
            estimated_prompt_tokens=snapshot.estimated_prompt_tokens,
            requested_completion_tokens=snapshot.requested_completion_tokens,
            planning_snapshot=snapshot,
        )


def test_context_manifest_retains_not_sent_valid_plan() -> None:
    plan = _plan(request_id="request-not-sent")
    not_sent = ContextPreflightRequestEvidence.build(
        request_id=plan.request_id,
        role=plan.role,
        requested_model="alpha/frontier-secure",
        request_state=ContextRequestState.NOT_SENT,
        decision_source=ContextPreflightSource.ORCHESTRATOR,
        reason=ContextPreflightReason.ORCHESTRATOR_NOT_SCHEDULED,
        decision_evidence_sha256s=("a" * 64, "b" * 64),
        estimated_prompt_tokens=plan.estimated_prompt_tokens,
        requested_completion_tokens=plan.requested_completion_tokens,
        request_plan=plan,
    )

    manifest = build_context_manifest(
        run_id="run-1",
        usage_records=[],
        preflight_records=[not_sent],
    )

    assert manifest.totals.planned_request_count == 1
    assert manifest.totals.not_sent_request_count == 1
    assert manifest.totals.planned_prompt_tokens == plan.estimated_prompt_tokens
    assert manifest.totals.reserved_output_tokens == plan.reserved_output_tokens


@pytest.mark.parametrize(
    ("state", "source", "reason"),
    [
        (
            ContextRequestState.NOT_SENT,
            ContextPreflightSource.ORCHESTRATOR,
            ContextPreflightReason.ORCHESTRATOR_NOT_SCHEDULED,
        ),
        *[
            (
                ContextRequestState.PRE_FLIGHT_REJECTED,
                ContextPreflightSource.TOKEN_PLANNER,
                reason,
            )
            for reason in (
                ContextPreflightReason.ENDPOINT_CAPACITY,
                ContextPreflightReason.GLOBAL_TOKEN_BUDGET,
                ContextPreflightReason.ROUTE_UNAVAILABLE,
                ContextPreflightReason.CONTEXT_PLAN_INVALID,
                ContextPreflightReason.COST_BUDGET,
            )
        ],
        *[
            (
                ContextRequestState.PRE_FLIGHT_REJECTED,
                ContextPreflightSource.BUDGET_MANAGER,
                reason,
            )
            for reason in (
                ContextPreflightReason.GLOBAL_TOKEN_BUDGET,
                ContextPreflightReason.COST_BUDGET,
                ContextPreflightReason.CONTEXT_PLAN_INVALID,
            )
        ],
    ],
)
def test_context_preflight_state_source_reason_matrix_accepts_only_valid_pairs(
    state: _PreflightRequestState,
    source: ContextPreflightSource,
    reason: ContextPreflightReason,
) -> None:
    request_id = f"valid-{source.value.lower()}-{reason.value.lower()}"
    request_plan = (
        _plan(request_id=request_id) if source is ContextPreflightSource.BUDGET_MANAGER else None
    )
    planning_snapshot = (
        _planning_snapshot(request_id=request_id, reason=reason)
        if source is ContextPreflightSource.TOKEN_PLANNER
        else None
    )
    bound_evidence_sha256 = (
        request_plan.plan_sha256
        if request_plan is not None
        else (planning_snapshot.snapshot_sha256 if planning_snapshot is not None else "a" * 64)
    )
    estimated_prompt_tokens = (
        request_plan.estimated_prompt_tokens
        if request_plan is not None
        else (planning_snapshot.estimated_prompt_tokens if planning_snapshot is not None else None)
    )
    requested_completion_tokens = (
        request_plan.requested_completion_tokens
        if request_plan is not None
        else (
            planning_snapshot.requested_completion_tokens
            if planning_snapshot is not None
            else 1_024
        )
    )
    evidence = ContextPreflightRequestEvidence.build(
        request_id=request_id,
        role="source_audit",
        requested_model="alpha/frontier-secure",
        request_state=state,
        decision_source=source,
        reason=reason,
        decision_evidence_sha256s=(bound_evidence_sha256,),
        estimated_prompt_tokens=estimated_prompt_tokens,
        requested_completion_tokens=requested_completion_tokens,
        request_plan=request_plan,
        planning_snapshot=planning_snapshot,
    )

    assert evidence.request_state is state
    assert evidence.decision_source is source
    assert evidence.reason is reason


_VALID_PREFLIGHT_MATRIX = {
    (
        ContextRequestState.NOT_SENT,
        ContextPreflightSource.ORCHESTRATOR,
        ContextPreflightReason.ORCHESTRATOR_NOT_SCHEDULED,
    ),
    *{
        (
            ContextRequestState.PRE_FLIGHT_REJECTED,
            ContextPreflightSource.TOKEN_PLANNER,
            reason,
        )
        for reason in (
            ContextPreflightReason.ENDPOINT_CAPACITY,
            ContextPreflightReason.GLOBAL_TOKEN_BUDGET,
            ContextPreflightReason.ROUTE_UNAVAILABLE,
            ContextPreflightReason.CONTEXT_PLAN_INVALID,
            ContextPreflightReason.COST_BUDGET,
        )
    },
    *{
        (
            ContextRequestState.PRE_FLIGHT_REJECTED,
            ContextPreflightSource.BUDGET_MANAGER,
            reason,
        )
        for reason in (
            ContextPreflightReason.GLOBAL_TOKEN_BUDGET,
            ContextPreflightReason.COST_BUDGET,
            ContextPreflightReason.CONTEXT_PLAN_INVALID,
        )
    },
}


@pytest.mark.parametrize(
    ("state", "source", "reason"),
    [
        (state, source, reason)
        for state in (
            ContextRequestState.NOT_SENT,
            ContextRequestState.PRE_FLIGHT_REJECTED,
        )
        for source in ContextPreflightSource
        for reason in ContextPreflightReason
        if (state, source, reason) not in _VALID_PREFLIGHT_MATRIX
    ],
)
def test_context_preflight_state_source_reason_matrix_rejects_invalid_pairs(
    state: _PreflightRequestState,
    source: ContextPreflightSource,
    reason: ContextPreflightReason,
) -> None:
    with pytest.raises(ValidationError, match=r"orchestrator decision|source and reason"):
        ContextPreflightRequestEvidence.build(
            request_id="invalid-preflight-matrix",
            role="source_audit",
            requested_model="alpha/frontier-secure",
            request_state=state,
            decision_source=source,
            reason=reason,
            decision_evidence_sha256s=("b" * 64,),
            estimated_prompt_tokens=None,
            requested_completion_tokens=1_024,
        )


def test_context_preflight_ledger_is_thread_safe_sorted_and_duplicate_closed() -> None:
    ledger = ContextPreflightLedger()
    records = []
    for index in reversed(range(64)):
        request_id = f"request-{index:03d}"
        snapshot = _planning_snapshot(
            request_id=request_id,
            reason=ContextPreflightReason.ENDPOINT_CAPACITY,
        )
        records.append(
            ContextPreflightRequestEvidence.build(
                request_id=request_id,
                role="source_audit",
                requested_model="alpha/frontier-secure",
                request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
                decision_source=ContextPreflightSource.TOKEN_PLANNER,
                reason=ContextPreflightReason.ENDPOINT_CAPACITY,
                decision_evidence_sha256s=(
                    hashlib.sha256(str(index).encode()).hexdigest(),
                    snapshot.snapshot_sha256,
                ),
                estimated_prompt_tokens=snapshot.estimated_prompt_tokens,
                requested_completion_tokens=snapshot.requested_completion_tokens,
                planning_snapshot=snapshot,
            )
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(ledger.add, records))

    assert [record.request_id for record in ledger.records] == [
        f"request-{index:03d}" for index in range(64)
    ]
    with pytest.raises(ContextManifestError, match="identity is duplicated"):
        ledger.add(records[0])
    with pytest.raises(TypeError, match="typed evidence"):
        ledger.add("not evidence")  # type: ignore[arg-type]
    ledger.clear()
    assert ledger.records == ()


def test_context_manifest_semantic_verification_rejects_independently_resealed_drift() -> None:
    usage = _usage()
    original = build_context_manifest(run_id="run-1", usage_records=[usage])
    changed_usage = usage.model_copy(
        update={
            "prompt_tokens": usage.prompt_tokens + 1,
            "total_tokens": usage.total_tokens + 1,
        }
    )
    independently_resealed = build_context_manifest(
        run_id="run-1",
        usage_records=[changed_usage],
    )
    assert independently_resealed.manifest_sha256 != original.manifest_sha256

    with pytest.raises(ContextManifestError, match="differs from final provider usage"):
        validate_context_manifest_against_usage(
            independently_resealed,
            run_id="run-1",
            usage_records=[usage],
        )


def test_run_manifest_semantic_join_rejects_resealed_context_artifact(
    tmp_path: Path,
) -> None:
    usage = _usage()
    original = build_context_manifest(run_id="run-1", usage_records=[usage])
    report = _report(usage=usage, manifest=original)
    path = tmp_path / "context-manifest.json"
    with pytest.raises(ValueError, match="lacks context-manifest"):
        _validated_context_manifest(tmp_path, report)

    write_context_manifest(path, original)
    assert _validated_context_manifest(tmp_path, report) == original

    changed_usage = usage.model_copy(
        update={
            "completion_tokens": usage.completion_tokens + 1,
            "total_tokens": usage.total_tokens + 1,
        }
    )
    independently_resealed = build_context_manifest(
        run_id="run-1",
        usage_records=[changed_usage],
    )
    write_context_manifest(path, independently_resealed)

    with pytest.raises(ContextManifestError, match="differs from final provider usage"):
        _validated_context_manifest(tmp_path, report)


def test_context_manifest_atomic_limits_bind_effective_configuration(
    config_factory: Callable[..., AuditConfig],
) -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    matching = config_factory(
        token_budgets={
            "global_input_token_budget": 1_000_000,
            "global_output_token_budget": 100_000,
        }
    )
    _validate_context_manifest_configuration(manifest, matching)

    with pytest.raises(ValueError, match=r"differs from effective (?:token )?configuration"):
        _validate_context_manifest_configuration(manifest, config_factory())
    source_mismatch = config_factory(
        token_budgets={
            "global_input_token_budget": 1_000_000,
            "global_output_token_budget": 100_000,
            "maximum_source_tokens_per_request": 199_999,
        }
    )
    with pytest.raises(ValueError, match="differs from effective token configuration"):
        _validate_context_manifest_configuration(manifest, source_mismatch)


@pytest.mark.parametrize(
    ("token_budget_updates", "execution_updates"),
    [
        ({"usable_input_fraction": 0.71}, {}),
        ({"reserved_output_tokens": 2_049}, {"max_output_tokens_per_request": 2_049}),
        ({"reserved_system_tokens": 8_193}, {}),
        ({"reserved_schema_tokens": 8_193}, {}),
        ({"reserved_protocol_tokens": 2_049}, {}),
        ({"reserved_workflow_tokens": 32_769}, {}),
    ],
    ids=(
        "context-utilization",
        "output-reserve",
        "system-reserve",
        "schema-reserve",
        "protocol-reserve",
        "workflow-reserve",
    ),
)
def test_context_manifest_plan_binds_every_effective_token_control(
    config_factory: Callable[..., AuditConfig],
    token_budget_updates: dict[str, int | float],
    execution_updates: dict[str, int],
) -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    token_budgets: dict[str, int | float] = {
        "global_input_token_budget": 1_000_000,
        "global_output_token_budget": 100_000,
        **token_budget_updates,
    }
    config = config_factory(
        token_budgets=token_budgets,
        execution=execution_updates,
    )

    with pytest.raises(ValueError, match="differs from effective token configuration"):
        _validate_context_manifest_configuration(manifest, config)


def test_context_manifest_preflight_plan_binds_effective_source_configuration(
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = _plan(request_id="preflight-source-binding")
    manifest = build_context_manifest(
        run_id="preflight-source-binding",
        usage_records=[],
        preflight_records=[_retry_preflight(plan)],
    )
    matching = config_factory(
        token_budgets={
            "global_input_token_budget": 1_000_000,
            "global_output_token_budget": 100_000,
        }
    )
    _validate_context_manifest_configuration(manifest, matching)

    mismatch = config_factory(
        token_budgets={
            "global_input_token_budget": 1_000_000,
            "global_output_token_budget": 100_000,
            "maximum_source_tokens_per_request": 199_999,
        }
    )
    with pytest.raises(ValueError, match="differs from effective token configuration"):
        _validate_context_manifest_configuration(manifest, mismatch)


def test_context_manifest_schema_rejects_tampered_aggregate_and_self_hash() -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    payload = manifest.model_dump(mode="python")
    payload["totals"]["planned_prompt_tokens"] += 1

    with pytest.raises(ValidationError, match=r"planned prompt total|totals_sha256"):
        ContextManifest.model_validate(payload)


def test_context_manifest_load_rejects_duplicate_keys_and_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "context-manifest.json"
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    write_context_manifest(path, manifest)

    assert load_context_manifest(path) == manifest

    path.write_text('{"schema_version":"1.1","schema_version":"1.1"}\n', encoding="utf-8")
    with pytest.raises(ContextManifestError, match="duplicate JSON keys"):
        load_context_manifest(path)


def test_context_manifest_io_rejects_a_symlinked_parent_component(tmp_path: Path) -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)
    linked_path = linked_parent / "context-manifest.json"

    with pytest.raises(ContextManifestError, match=r"parent path.*link"):
        write_context_manifest(linked_path, manifest)
    assert not (actual_parent / "context-manifest.json").exists()

    actual_path = actual_parent / "context-manifest.json"
    write_context_manifest(actual_path, manifest)
    with pytest.raises(ContextManifestError, match=r"parent path.*link"):
        load_context_manifest(linked_path)


def test_context_manifest_loader_rejects_a_shared_hardlink(tmp_path: Path) -> None:
    path = tmp_path / "context-manifest.json"
    sibling = tmp_path / "context-manifest-copy.json"
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    write_context_manifest(path, manifest)
    os.link(path, sibling)

    with pytest.raises(ContextManifestError, match="bounded unique non-link regular file"):
        load_context_manifest(path)


def test_context_manifest_loader_opens_fifo_nonblocking_before_type_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    if not isinstance(nonblocking, int) or nonblocking <= 0:
        pytest.skip("platform has no nonblocking descriptor flag")
    path = tmp_path / "context-manifest.json"
    os.mkfifo(path)
    real_open = os.open
    leaf_open_observed = False

    def guarded_open(
        path_value: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal leaf_open_observed
        if path_value == path.name and dir_fd is not None:
            leaf_open_observed = True
            assert flags & nonblocking
        return real_open(path_value, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", guarded_open)

    with pytest.raises(ContextManifestError, match="bounded unique non-link regular file"):
        load_context_manifest(path)
    assert leaf_open_observed


def test_context_manifest_loader_rejects_descriptor_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "context-manifest.json"
    sibling = tmp_path / "concurrent-link.json"
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    write_context_manifest(path, manifest)
    real_read = os.read
    linked = False

    def link_after_first_read(descriptor: int, byte_count: int) -> bytes:
        nonlocal linked
        chunk = real_read(descriptor, byte_count)
        if chunk and not linked:
            linked = True
            os.link(path, sibling)
        return chunk

    monkeypatch.setattr(os, "read", link_after_first_read)

    with pytest.raises(ContextManifestError, match="changed while being read"):
        load_context_manifest(path)


def test_context_manifest_loader_enforces_the_descriptor_byte_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "context-manifest.json"
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    write_context_manifest(path, manifest)
    monkeypatch.setattr(
        context_manifest_module,
        "_MAX_CONTEXT_MANIFEST_BYTES",
        path.stat().st_size - 1,
    )

    with pytest.raises(ContextManifestError, match="bounded unique non-link regular file"):
        load_context_manifest(path)


def test_context_manifest_writer_enforces_the_loader_bound_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "context-manifest.json"
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])
    serialized_bytes = len(stable_json(manifest).encode("utf-8"))
    preserved = "preserved-existing-artifact\n"
    path.write_text(preserved, encoding="utf-8")
    monkeypatch.setattr(
        context_manifest_module,
        "_MAX_CONTEXT_MANIFEST_BYTES",
        serialized_bytes - 1,
    )

    with pytest.raises(ContextManifestError, match="serialized byte limit"):
        write_context_manifest(path, manifest)

    assert path.read_text(encoding="utf-8") == preserved
    assert list(tmp_path.iterdir()) == [path]

    monkeypatch.setattr(
        context_manifest_module,
        "_MAX_CONTEXT_MANIFEST_BYTES",
        serialized_bytes,
    )
    write_context_manifest(path, manifest)

    assert path.stat().st_size == serialized_bytes
    assert load_context_manifest(path) == manifest


def test_empty_context_manifest_is_explicitly_non_provider_evidence() -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[])

    assert manifest.requests == ()
    assert manifest.totals.request_count == 0
    assert manifest.totals.provider_reported_request_count == 0
    assert manifest.totals.unavailable_actual_usage_count == 0
