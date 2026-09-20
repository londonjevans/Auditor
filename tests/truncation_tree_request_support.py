"""Original configured request evidence for synthetic full-manifest integration only."""

import hashlib
import json
from decimal import Decimal

from mmaudit.models.openrouter import _model_retry_routing_evidence
from mmaudit.models.reasoning import ReasoningExecutionEvidence
from mmaudit.models.schemas import ContextPackage, ContextRequestEvidence, UsageRecord
from mmaudit.models.token_planning import (
    EndpointRouteIntersection,
    EndpointRouteTokenCapacity,
    PromptAllocationCategory,
    PromptTokenAllocation,
    RequestTokenPlan,
    build_request_token_plan,
)
from mmaudit.orchestration.budgets import (
    AtomicRequestLimitReservationEvidence,
    AtomicTokenReservationEvidence,
)
from mmaudit.orchestration.context import render_context
from tests.refresh_runtime_support import SyntheticRefreshRuntime

# Explicit synthetic context, prompt and completion metadata; not a real endpoint claim.
CONFIGURED_RUN_TOKEN_CAPACITY = (262_144, 196_608, 65_536)


def bind_configured_original_request(
    record: UsageRecord,
    runtime: SyntheticRefreshRuntime,
    original_plan: RequestTokenPlan,
    context: ContextPackage,
    *,
    spent_input_tokens: int,
    spent_output_tokens: int,
) -> UsageRecord:
    """Bind original context and resource positions without lowering the selected profile."""

    config = runtime.config.effective()
    rendered = render_context(context)
    context_evidence = ContextRequestEvidence.model_validate_json(
        json.dumps(record.routing["context_request_evidence"])
    )
    if (
        context_evidence.request_id != record.request_id
        or context_evidence.request_role != record.role
        or context_evidence.context_role != context.role
        or context_evidence.rendered_sha256 != hashlib.sha256(rendered.encode()).hexdigest()
    ):
        raise ValueError("configured request differs from its original context")
    candidates = tuple(
        candidate
        for candidate in runtime.history.candidate_registry.candidates
        if candidate.exact_model_id == record.requested_model
        and candidate.approved_provider_endpoint == record.actual_provider_endpoint
    )
    if len(candidates) != 1:
        raise ValueError("configured request lacks exact original endpoint metadata")
    candidate = candidates[0]
    qualified_model = runtime.technical_qualification.model_for(
        record.requested_model, now=runtime.verified_at
    )
    qualification_routing = {
        "benchmark_report_sha256": qualified_model.benchmark_report_sha256,
        "qualified_reasoning_binding_sha256": [
            binding.binding_sha256 for binding in qualified_model.reasoning_bindings
        ],
    }
    if any(
        record.routing.get(key) is not None and record.routing[key] != value
        for key, value in qualification_routing.items()
    ):
        raise ValueError("configured original reasoning qualification differs")
    route = EndpointRouteTokenCapacity.build(
        exact_model_id=candidate.exact_model_id,
        provider_endpoint=candidate.approved_provider_endpoint,
        endpoint_snapshot_sha256=record.routing["endpoint_snapshot_sha256"],
        context_tokens=candidate.context_size,
        max_prompt_tokens=candidate.max_prompt_tokens,
        max_prompt_tokens_source=candidate.max_prompt_tokens_source,
        max_completion_tokens=candidate.output_limit,
        max_completion_tokens_source=candidate.output_limit_source,
    )
    # Retain the scripted non-context allocations and conservatively include all rendered bytes.
    replacements = {
        PromptAllocationCategory.SOURCE: "\n".join(item.content for item in context.excerpts),
        PromptAllocationCategory.WORKFLOW: rendered,
    }
    allocations = tuple(
        PromptTokenAllocation.from_text(item.category, replacements[item.category])
        if item.category in replacements
        else item
        for item in original_plan.allocations
    )
    plan = build_request_token_plan(
        request_id=record.request_id,
        role=record.role,
        route_intersection=EndpointRouteIntersection.build((route,)),
        allocations=allocations,
        requested_surface_count=len(context.requested_model_surfaces),
        required_output_tokens=config.effective_reserved_output_tokens,
        reserved_reasoning_tokens=original_plan.reserved_reasoning_tokens,
        reasoning_plan=original_plan.reasoning_plan,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        input_tokens_reserved_before=spent_input_tokens,
        output_tokens_reserved_before=spent_output_tokens,
        context_utilization=Decimal(str(config.token_budgets.usable_input_fraction)),
        configured_reserved_system_tokens=config.token_budgets.reserved_system_tokens,
        configured_reserved_schema_tokens=config.token_budgets.reserved_schema_tokens,
        configured_reserved_protocol_tokens=config.token_budgets.reserved_protocol_tokens,
        configured_reserved_workflow_tokens=config.token_budgets.reserved_workflow_tokens,
        maximum_source_tokens_per_request=config.token_budgets.maximum_source_tokens_per_request,
        context_package_source_byte_ceiling=context.effective_source_byte_ceiling,
        context_omissions=context.omissions,
        prompt_envelope_byte_upper_bound_tokens=sum(
            item.estimate.byte_upper_bound_tokens for item in allocations
        ),
    )
    atomic = AtomicTokenReservationEvidence.build(
        request_id=record.request_id,
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=plan.plan_sha256,
        planned_prompt_tokens=plan.prompt_byte_upper_bound_tokens,
        planned_visible_output_tokens=plan.reserved_output_tokens,
        planned_reasoning_tokens=plan.reserved_reasoning_tokens,
        planned_completion_tokens=plan.requested_completion_tokens,
        global_input_token_limit=plan.global_budget.global_input_token_budget,
        global_output_token_limit=plan.global_budget.global_output_token_budget,
        spent_input_tokens_before=spent_input_tokens,
        reserved_input_tokens_before=0,
        spent_output_tokens_before=spent_output_tokens,
        reserved_output_tokens_before=0,
    )
    original_limit = AtomicRequestLimitReservationEvidence.model_validate_json(
        json.dumps(record.routing["atomic_request_limit_reservation"])
    )
    request_limit = AtomicRequestLimitReservationEvidence.build(
        request_id=record.request_id,
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=plan.plan_sha256,
        request_limit_scope=original_limit.request_limit_scope,
        request_limit_count_before=original_limit.request_limit_count_before,
        request_limit_maximum=original_limit.request_limit_maximum,
    )
    assert plan.reasoning_plan is not None and record.request_body_sha256 is not None
    reasoning = ReasoningExecutionEvidence.build(
        request_plan=plan.reasoning_plan,
        observed_reasoning_tokens=record.reasoning_tokens,
        provider_completion_tokens=record.completion_tokens,
        request_token_plan_sha256=plan.plan_sha256,
        request_body_sha256=record.request_body_sha256,
    )
    retry = _model_retry_routing_evidence(
        config.execution.model_retry_policy,
        maximum_attempts_for_request=1,
        attempts=1,
        attempt_outcomes=("SUCCESS" if record.status == "success" else "TERMINAL_OTHER_ERROR",),
    )
    return record.model_copy(
        update={
            "reasoning_evidence": reasoning,
            "routing": record.routing
            | retry
            | qualification_routing
            | {
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [atomic.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [atomic.evidence_sha256],
                "atomic_token_reservation": atomic.model_dump(mode="json"),
                "atomic_token_reservation_sha256": atomic.evidence_sha256,
                "atomic_request_limit_reservations": [request_limit.model_dump(mode="json")],
                "atomic_request_limit_reservation_sha256s": [request_limit.evidence_sha256],
                "atomic_request_limit_reservation": request_limit.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": request_limit.evidence_sha256,
            },
        }
    )


def configured_child_resource_limits(runtime: SyntheticRefreshRuntime) -> tuple[str, int]:
    """Reserve the largest original selected endpoint envelope before opening any child."""

    candidates = {
        item.exact_model_id: item for item in runtime.history.candidate_registry.candidates
    }
    costs: list[Decimal] = []
    completions: list[int] = []
    for route in runtime.pricing_evidence.routes:
        if not route.audit_selected:
            continue
        candidate = candidates[route.exact_model_id]
        units = {
            "prompt": candidate.max_prompt_tokens,
            "completion": candidate.output_limit,
            "request": 1,
        }
        if not set(route.current_pricing) <= set(units):
            raise ValueError("configured child has an unsupported priced component")
        costs.append(
            sum(
                (Decimal(price) * units[field] for field, price in route.current_pricing.items()),
                Decimal(0),
            )
        )
        completions.append(candidate.output_limit)
    if not costs:
        raise ValueError("configured child lacks an original selected pricing route")
    return format(max(costs).normalize(), "f"), max(completions)
