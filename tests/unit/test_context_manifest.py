from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.models import usage as usage_module
from mmaudit.models.schemas import (
    AuditReport,
    ExecutionEvidenceKind,
    ModelIdentityStrength,
    ModelRequestValidationStatus,
    RepositoryMap,
    UsageRecord,
)
from mmaudit.models.token_planning import (
    PROMPT_ALLOCATION_CATEGORIES,
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
    build_request_token_plan,
)
from mmaudit.orchestration.budgets import AtomicTokenReservationEvidence
from mmaudit.orchestration.context_manifest import (
    ActualTokenUsageSource,
    ContextManifest,
    ContextManifestError,
    ContextOmissionReason,
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
        required_output_tokens=4_096,
        reserved_reasoning_tokens=1_024,
        global_input_token_budget=1_000_000,
        global_output_token_budget=100_000,
        context_utilization=Decimal("0.70"),
        context_omission_sha256s=(
            hashlib.sha256(b"source excerpt omitted by role budget").hexdigest(),
        ),
        prompt_envelope_byte_upper_bound_tokens=sum(
            allocation.estimate.byte_upper_bound_tokens for allocation in allocations
        ),
    )


def _usage(
    *,
    request_id: str = "request-1",
    plan: RequestTokenPlan | None = None,
) -> UsageRecord:
    token_plan = plan or _plan(request_id=request_id)
    token_reservation = AtomicTokenReservationEvidence.build(
        request_id=request_id,
        exact_model_id="alpha/frontier-secure",
        role="source_audit",
        request_token_plan_sha256=token_plan.plan_sha256,
        planned_prompt_tokens=token_plan.prompt_byte_upper_bound_tokens,
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
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        identity_strength=ModelIdentityStrength.UNBOUND,
        status="success",
        attempts=1,
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
        omission.token_estimation_state is OmissionTokenEstimationState.NOT_ESTIMATED
        and omission.estimated_tokens is None
        for request in provider_requests
        for omission in request.omissions
    )
    serialized = first.model_dump_json()
    assert canary not in serialized
    assert "source excerpt omitted by role budget" not in serialized
    assert '"content"' not in serialized


def test_context_manifest_report_binding_is_small_and_self_hashed() -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[_usage()])

    binding = context_manifest_report_binding(manifest)

    assert binding.manifest_sha256 == manifest.manifest_sha256
    assert binding.request_count == 1
    assert binding.planned_source_tokens > 0
    assert binding.provider_reported_request_count == 0
    assert binding.mock_reported_request_count == 1


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


def test_context_manifest_retains_typed_preflight_rejection_without_fabricated_usage() -> None:
    rejection = ContextPreflightRequestEvidence.build(
        request_id="request-preflight-1",
        role="source_audit",
        requested_model="alpha/frontier-secure",
        request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
        decision_source=ContextPreflightSource.TOKEN_PLANNER,
        reason=ContextPreflightReason.ENDPOINT_CAPACITY,
        decision_evidence_sha256s=("9" * 64,),
        estimated_prompt_tokens=90_001,
        requested_completion_tokens=20_000,
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
    state: ContextRequestState,
    source: ContextPreflightSource,
    reason: ContextPreflightReason,
) -> None:
    evidence = ContextPreflightRequestEvidence.build(
        request_id=f"valid-{source.value.lower()}-{reason.value.lower()}",
        role="source_audit",
        requested_model="alpha/frontier-secure",
        request_state=state,
        decision_source=source,
        reason=reason,
        decision_evidence_sha256s=("a" * 64,),
        estimated_prompt_tokens=None,
        requested_completion_tokens=1_024,
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
    state: ContextRequestState,
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
    records = [
        ContextPreflightRequestEvidence.build(
            request_id=f"request-{index:03d}",
            role="source_audit",
            requested_model="alpha/frontier-secure",
            request_state=ContextRequestState.PRE_FLIGHT_REJECTED,
            decision_source=ContextPreflightSource.TOKEN_PLANNER,
            reason=ContextPreflightReason.ENDPOINT_CAPACITY,
            decision_evidence_sha256s=(hashlib.sha256(str(index).encode()).hexdigest(),),
            estimated_prompt_tokens=None,
            requested_completion_tokens=1_024,
        )
        for index in reversed(range(64))
    ]

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

    path.write_text('{"schema_version":"1.0","schema_version":"1.0"}\n', encoding="utf-8")
    with pytest.raises(ContextManifestError, match="duplicate JSON keys"):
        load_context_manifest(path)


def test_empty_context_manifest_is_explicitly_non_provider_evidence() -> None:
    manifest = build_context_manifest(run_id="run-1", usage_records=[])

    assert manifest.requests == ()
    assert manifest.totals.request_count == 0
    assert manifest.totals.provider_reported_request_count == 0
    assert manifest.totals.unavailable_actual_usage_count == 0
