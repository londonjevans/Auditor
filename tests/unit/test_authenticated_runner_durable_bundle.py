from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from decimal import Decimal
from functools import cache
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import mmaudit.models.authenticated_runner_durable_bundle as durable_bundle_module
import mmaudit.models.evidence_seal_authority as evidence_seal_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationCaseResult,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_report,
)
from mmaudit.benchmark.models import ModelBenchmarkReport
from mmaudit.config import ModelRetryPolicy
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageCaseExecutionEvidence,
    AuthenticatedCrossLineageLedgerEntryEvidence,
    AuthenticatedCrossLineageLedgerIntervalEvidence,
    AuthenticatedCrossLineageRunnerEvidence,
    AuthenticatedCrossLineageRunnerRunEvidence,
)
from mmaudit.models.authenticated_runner_cost_plan import (
    AuthenticatedRunnerCostPlanStage,
    AuthenticatedRunnerStagedCostPlan,
    build_authenticated_runner_staged_cost_plan,
)
from mmaudit.models.authenticated_runner_durable_bundle import (
    AuthenticatedRunnerAuthsealComplete,
    AuthenticatedRunnerAuthsealRejected,
    AuthenticatedRunnerDurableBundleError,
    AuthenticatedRunnerDurableEvidenceBundle,
    AuthenticatedRunnerDurableRunEvidence,
    authenticated_runner_durable_bundle_bytes,
    build_authenticated_runner_durable_bundle,
    load_authenticated_runner_durable_bundle,
    require_authenticated_runner_durable_config_binding,
    revalidate_authenticated_runner_durable_bundle,
)
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealDecisionProjection,
    EvidenceSealLineageRole,
    EvidenceSealRunKind,
    build_evidence_seal_collision_map,
    build_evidence_seal_lineage_binding,
)
from mmaudit.models.ground_truth_authority import (
    FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
    FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
    FROZEN_GROUND_TRUTH_SOURCE_REVISION,
    VerifiedFrozenGroundTruthProjection,
)
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.models.reasoning import ReasoningExecutionEvidence, ReasoningRequestPlanEvidence
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.token_planning import (
    RequestTokenPlan,
    request_token_plan_projection_sha256,
)
from mmaudit.orchestration.budgets import EndpointRequestCostBound
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import JsonEvidenceObservation
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
)
from tests.unit import test_authenticated_runner as runner_fixtures
from tests.unit.test_authenticated_runner import _LiveInputs
from tests.unit.test_authenticated_runner_cost_plan import _preview as _cost_preview_fixture
from tests.unit.test_openrouter_request_cost_preview import _disabled_reasoning_policy

_LIVE_INPUTS_FACTORY = cast(Callable[[], _LiveInputs], runner_fixtures.live_inputs.__wrapped__)
_EFFECTIVE_CONFIG_SHA256 = "e81516464de46b3b10d4533b1c0f792ae895e09c43cafc2d01f60cc2ad5bc438"
_EXECUTION_CONFIG_SHA256 = "2e19ab801f4f18ce66beb757a7009a7cb0a1d5959f8ed199db3a50b9cf1a4a5f"
_CONTINUITY_EFFECTIVE_CONFIG_SHA256 = (
    "c848ab89d2ecce2c182c635eb2f4825ece82ef39f30907fa3ce0cb63937c8b20"
)
_CONTINUITY_EXECUTION_CONFIG_SHA256 = (
    "5abc674bbd119ec4b1705265b9b7b7ccb178eb07712a995d860e9cfe358c18f1"
)
_RETRY_OFF_POLICY = ModelRetryPolicy.build(
    transient_retry_limit=1,
    schema_validation_retry_limit=0,
)
_CONTINUITY_POLICY = ModelRetryPolicy.build(
    transient_retry_limit=1,
    schema_validation_retry_limit=3,
)
_MODEL_RETRY_ROUTING_KEYS = {
    "maximum_attempts_for_request",
    "model_retry_attempts",
    "model_retry_evidence_sha256",
    "model_retry_policy",
    "model_retry_policy_sha256",
    "schema_validation_retries_used",
    "transient_retries_used",
}


@cache
def _live_inputs() -> _LiveInputs:
    return _LIVE_INPUTS_FACTORY()


def _routing_sha256(usage: UsageRecord, key: str, fallback: str) -> str:
    value = usage.routing.get(key)
    return value if isinstance(value, str) and len(value) == 64 else fallback


def _decimal_text(value: Decimal) -> str:
    rendered = format(value, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _model_retry_routing() -> dict[str, Any]:
    policy = ModelRetryPolicy.build(
        transient_retry_limit=1,
        schema_validation_retry_limit=1,
    )
    values = {
        "model_retry_policy": policy.model_dump(mode="json"),
        "model_retry_policy_sha256": policy.policy_sha256,
        "maximum_attempts_for_request": 3,
        "transient_retries_used": 1,
        "schema_validation_retries_used": 1,
        "model_retry_attempts": [
            {"attempt_ordinal": 1, "outcome": "TRANSIENT_STATUS"},
            {"attempt_ordinal": 2, "outcome": "SCHEMA_VALIDATION_FAILED"},
            {"attempt_ordinal": 3, "outcome": "SUCCESS"},
        ],
    }
    return {
        **values,
        "model_retry_evidence_sha256": canonical_sha256(
            {"domain": "mmaudit.model-retry-evidence.v1", **values}
        ),
    }


def _successful_model_retry_routing(policy: ModelRetryPolicy) -> dict[str, Any]:
    values = {
        "model_retry_policy": policy.model_dump(mode="json"),
        "model_retry_policy_sha256": policy.policy_sha256,
        "maximum_attempts_for_request": policy.maximum_attempts,
        "transient_retries_used": 0,
        "schema_validation_retries_used": 0,
        "model_retry_attempts": [
            {"attempt_ordinal": 1, "outcome": "SUCCESS"},
        ],
    }
    return {
        **values,
        "model_retry_evidence_sha256": canonical_sha256(
            {"domain": "mmaudit.model-retry-evidence.v1", **values}
        ),
    }


def test_retry_policy_routing_evidence_is_durable_and_raw_output_free() -> None:
    routing = _model_retry_routing()

    durable_bundle_module._require_safe_routing_value(routing, attempts=3)
    assert set(routing) == _MODEL_RETRY_ROUTING_KEYS


@pytest.mark.parametrize(
    "tamper",
    ("partial", "policy_hash", "counter", "ordinal", "evidence_hash"),
)
def test_durable_retry_policy_routing_rejects_semantic_tamper(tamper: str) -> None:
    routing = json.loads(json.dumps(_model_retry_routing()))
    if tamper == "partial":
        routing.pop("model_retry_attempts")
    elif tamper == "policy_hash":
        routing["model_retry_policy"]["policy_sha256"] = "f" * 64
    elif tamper == "counter":
        routing["schema_validation_retries_used"] = 0
    elif tamper == "ordinal":
        routing["model_retry_attempts"][1]["attempt_ordinal"] = 3
    else:
        routing["model_retry_evidence_sha256"] = "f" * 64

    with pytest.raises(
        AuthenticatedRunnerDurableBundleError,
        match="model retry evidence is inconsistent",
    ):
        durable_bundle_module._require_safe_routing_value(routing, attempts=3)


def _v2_token_plan_for_usage(
    usage: UsageRecord,
    *,
    endpoint_capability_sha256: str,
) -> RequestTokenPlan:
    original = durable_bundle_module._durable_request_token_plan(usage.routing)
    if original.reasoning_plan is not None:
        return original
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role=original.role,
        policy=_disabled_reasoning_policy(),
        endpoint_capability_sha256=endpoint_capability_sha256,
    )
    payload = original.model_dump(mode="json", exclude={"plan_sha256"})
    payload.update(
        {
            "schema_version": "2.0",
            "reasoning_plan": reasoning_plan.model_dump(mode="json"),
        }
    )
    return RequestTokenPlan.model_validate_json(
        json.dumps(
            {**payload, "plan_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _usage_with_singleton_identity_and_reasoning(
    usage: UsageRecord,
    *,
    started_at: datetime,
    ended_at: datetime,
    endpoint_capability_sha256: str,
) -> UsageRecord:
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role=usage.role,
        policy=_disabled_reasoning_policy(),
        endpoint_capability_sha256=endpoint_capability_sha256,
    )
    payload = usage.model_dump(mode="python")
    payload.update(
        {
            "timestamp": started_at,
            "started_at": started_at,
            "ended_at": ended_at,
            "latency_ms": int((ended_at - started_at).total_seconds() * 1_000),
            "reasoning_evidence": None,
            "reasoning_tokens": 0,
        }
    )
    routing = dict(payload["routing"])
    routing.update(
        {
            "request_started_at": started_at.isoformat(),
            "request_ended_at": ended_at.isoformat(),
            "latency_ms": payload["latency_ms"],
        }
    )
    for field in (
        "request_token_plan",
        "request_token_plan_sha256",
        "atomic_token_reservation",
        "atomic_token_reservation_sha256",
        "atomic_token_reservations",
        "atomic_token_reservation_sha256s",
    ):
        routing.pop(field, None)
    payload["routing"] = routing
    return bind_synthetic_usage_identity(
        UsageRecord.model_validate(payload),
        reasoning_plan=reasoning_plan,
        observed_reasoning_tokens=0,
    )


def _cost_preview_for_usage(
    usage: UsageRecord,
    *,
    index: int,
    drift: str | None = None,
    maximum_attempts: int = 2,
    execution_config_sha256: str = _EXECUTION_CONFIG_SHA256,
) -> OpenRouterStructuredRequestCostPreview:
    template = _cost_preview_fixture(
        index,
        maximum_attempts=maximum_attempts,
        execution_config_sha256=execution_config_sha256,
    )
    payload = template.model_dump(mode="json", exclude={"preview_sha256"})
    token_plan = _v2_token_plan_for_usage(
        usage,
        endpoint_capability_sha256=template.reasoning_capability_sha256,
    )
    reasoning_plan = token_plan.reasoning_plan
    assert reasoning_plan is not None
    endpoint = usage.actual_provider_endpoint
    user_prompt_sha256 = usage.user_prompt_sha256 or template.user_prompt_sha256
    schema_sha256 = usage.schema_sha256 or template.response_schema_sha256
    assert endpoint is not None
    exact_model_id = usage.requested_model
    prompt_sha256 = usage.prompt_sha256
    if drift == "exact_model_id":
        exact_model_id = "retargeted/model-v9"
    elif drift == "provider_endpoint":
        endpoint = "retargeted-provider/fp8"
    elif drift == "prompt_sha256":
        prompt_sha256 = canonical_sha256({"retargeted_prompt": usage.prompt_sha256})
    elif drift == "response_schema_sha256":
        schema_sha256 = "f" * 64
    components = payload["cost_components"]
    assert isinstance(components, list)
    pricing = {
        str(component["pricing_field"]): str(component["unit_price_usd_exact"])
        for component in components
    }
    prompt_units = token_plan.prompt_byte_upper_bound_tokens
    component_units = {
        "completion": token_plan.requested_completion_tokens,
        "image": 0,
        "input_cache_read": prompt_units,
        "input_cache_write": prompt_units,
        "internal_reasoning": token_plan.reserved_reasoning_tokens,
        "prompt": prompt_units,
        "request": 1,
        "web_search": 0,
    }
    for component in components:
        component["maximum_units"] = component_units[str(component["pricing_field"])]
    maximum_units = {
        str(component["pricing_field"]): int(component["maximum_units"]) for component in components
    }
    bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=exact_model_id,
        provider_endpoint=endpoint,
        request_material="mmaudit-provider-free-cost-preview",
        pricing=pricing,
        maximum_units=maximum_units,
    )
    maximum_cost_per_attempt = _decimal_text(bound.maximum_cost_usd)
    maximum_cost_all_attempts = _decimal_text(
        bound.maximum_cost_usd * int(payload["maximum_attempts"])
    )
    required_parameters = usage.routing.get("structured_output_required_provider_parameters")
    assert isinstance(required_parameters, list)
    payload.update(
        {
            "logical_request_id": usage.request_id,
            "role": usage.role,
            "exact_model_id": exact_model_id,
            "provider_endpoint": endpoint,
            "provider_policy_sha256": _routing_sha256(
                usage,
                "provider_policy_sha256",
                template.provider_policy_sha256,
            ),
            "discovery_evidence_sha256": _routing_sha256(
                usage,
                "discovery_evidence_sha256",
                template.discovery_evidence_sha256,
            ),
            "discovery_provenance_sha256": _routing_sha256(
                usage,
                "discovery_provenance_sha256",
                template.discovery_provenance_sha256,
            ),
            "catalog_snapshot_sha256": _routing_sha256(
                usage,
                "catalog_snapshot_sha256",
                template.catalog_snapshot_sha256,
            ),
            "catalog_identity_binding_sha256": _routing_sha256(
                usage,
                "catalog_identity_binding_sha256",
                template.catalog_identity_binding_sha256,
            ),
            "model_metadata_snapshot_sha256": _routing_sha256(
                usage,
                "model_metadata_snapshot_sha256",
                template.model_metadata_snapshot_sha256,
            ),
            "model_identity_snapshot_sha256": _routing_sha256(
                usage,
                "identity_snapshot_sha256",
                template.model_identity_snapshot_sha256,
            ),
            "endpoint_policy_snapshot_sha256": _routing_sha256(
                usage,
                "endpoint_snapshot_sha256",
                template.endpoint_policy_snapshot_sha256,
            ),
            "endpoint_record_snapshot_sha256": _routing_sha256(
                usage,
                "endpoint_snapshot_sha256",
                template.endpoint_record_snapshot_sha256,
            ),
            "endpoint_pricing_sha256": _routing_sha256(
                usage,
                "endpoint_pricing_sha256",
                template.endpoint_pricing_sha256,
            ),
            "output_capability_sha256": _routing_sha256(
                usage,
                "output_capability_sha256",
                template.output_capability_sha256,
            ),
            "structured_output_mode": usage.routing["structured_output_mode"],
            "prompt_sha256": prompt_sha256,
            "user_prompt_sha256": user_prompt_sha256,
            "response_schema_sha256": schema_sha256,
            "output_request_shape_sha256": usage.routing["structured_output_request_shape_sha256"],
            "required_provider_parameters_sha256": canonical_sha256(tuple(required_parameters)),
            "strict_output_protocol_sha256": usage.routing.get("structured_output_protocol_sha256"),
            "reasoning_request_sha256": usage.routing.get(
                "structured_output_reasoning_request_sha256"
            ),
            "reasoning_plan_sha256": reasoning_plan.evidence_sha256,
            "reasoning_policy_sha256": reasoning_plan.policy_artifact_sha256,
            "reasoning_policy_role_binding_sha256": (reasoning_plan.policy_role_binding_sha256),
            "reasoning_profile_sha256": reasoning_plan.control_profile.profile_sha256,
            "reasoning_capability_sha256": reasoning_plan.endpoint_capability_sha256,
            "reasoning_qualification_sha256": reasoning_plan.qualification_binding_sha256,
            "request_token_plan_projection_sha256": (
                request_token_plan_projection_sha256(token_plan)
            ),
            "request_material_projection_utf8_bytes": prompt_units,
            "endpoint_cost_bound_pricing_sha256": bound.pricing_snapshot_sha256,
            "prompt_byte_upper_bound_tokens": prompt_units,
            "requested_completion_tokens": token_plan.requested_completion_tokens,
            "reserved_output_tokens": token_plan.reserved_output_tokens,
            "reserved_reasoning_tokens": token_plan.reserved_reasoning_tokens,
            "maximum_priced_prompt_units": prompt_units,
            "maximum_cost_usd_per_attempt_exact": maximum_cost_per_attempt,
            "maximum_cost_usd_all_attempts_exact": maximum_cost_all_attempts,
        }
    )
    return OpenRouterStructuredRequestCostPreview.model_validate_json(
        json.dumps(
            {**payload, "preview_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        ),
        strict=True,
    )


def _cost_plan_for_usages(
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    stage: AuthenticatedRunnerCostPlanStage,
    case_ids: tuple[str, ...],
    usages: tuple[UsageRecord, ...],
    drift: str | None = None,
    maximum_attempts: int = 2,
    execution_config_sha256: str = _EXECUTION_CONFIG_SHA256,
) -> AuthenticatedRunnerStagedCostPlan:
    return build_authenticated_runner_staged_cost_plan(
        run_kind=run_kind,
        stage=stage,
        case_ids=case_ids,
        request_previews=tuple(
            _cost_preview_for_usage(
                usage,
                index=index,
                drift=drift,
                maximum_attempts=maximum_attempts,
                execution_config_sha256=execution_config_sha256,
            )
            for index, usage in enumerate(usages)
        ),
    )


def _usage_with_cost_preview(
    usage: UsageRecord,
    preview: OpenRouterStructuredRequestCostPreview,
) -> UsageRecord:
    payload = usage.model_dump(mode="python")
    token_plan = _v2_token_plan_for_usage(
        usage,
        endpoint_capability_sha256=preview.reasoning_capability_sha256,
    )
    reasoning_plan = token_plan.reasoning_plan
    request_body_sha256 = usage.request_body_sha256
    assert reasoning_plan is not None
    assert request_body_sha256 is not None
    reasoning_evidence = ReasoningExecutionEvidence.build(
        request_plan=reasoning_plan,
        observed_reasoning_tokens=0,
        provider_completion_tokens=usage.completion_tokens,
        request_token_plan_sha256=token_plan.plan_sha256,
        request_body_sha256=request_body_sha256,
    )
    payload["user_prompt_sha256"] = payload["user_prompt_sha256"] or preview.user_prompt_sha256
    payload["schema_sha256"] = payload["schema_sha256"] or preview.response_schema_sha256
    payload["reasoning_evidence"] = reasoning_evidence
    payload["routing"] = {
        **payload["routing"],
        "selected_provider_endpoint": preview.provider_endpoint,
        "discovery_evidence_sha256": preview.discovery_evidence_sha256,
        "discovery_provenance_sha256": preview.discovery_provenance_sha256,
        "catalog_snapshot_sha256": preview.catalog_snapshot_sha256,
        "catalog_identity_binding_sha256": preview.catalog_identity_binding_sha256,
        "model_metadata_snapshot_sha256": preview.model_metadata_snapshot_sha256,
        "identity_snapshot_sha256": preview.model_identity_snapshot_sha256,
        "endpoint_snapshot_sha256": preview.endpoint_policy_snapshot_sha256,
        "endpoint_pricing_sha256": preview.endpoint_pricing_sha256,
        "output_capability_sha256": preview.output_capability_sha256,
        "structured_output_mode": preview.structured_output_mode.value,
        "structured_output_request_shape_sha256": preview.output_request_shape_sha256,
        "structured_output_protocol_sha256": preview.strict_output_protocol_sha256,
        "structured_output_reasoning_request_sha256": preview.reasoning_request_sha256,
        "request_token_plan": token_plan.model_dump(mode="json"),
        "request_token_plan_sha256": token_plan.plan_sha256,
        "request_cost_preview_sha256": preview.preview_sha256,
        "request_cost_preview_maximum_cost_usd_per_attempt_exact": (
            preview.maximum_cost_usd_per_attempt_exact
        ),
        "request_cost_preview_maximum_cost_usd_all_attempts_exact": (
            preview.maximum_cost_usd_all_attempts_exact
        ),
    }
    return reattest_synthetic_real_usage(UsageRecord.model_validate(payload))


def _candidate_report_with_cost_plan(
    report: ModelBenchmarkReport,
    plan: AuthenticatedRunnerStagedCostPlan,
    *,
    revalidate: bool = True,
) -> ModelBenchmarkReport:
    result = report.results[0]
    cases = [
        case.model_copy(update={"usage_record": _usage_with_cost_preview(usage, preview)})
        for case, preview in zip(result.cases, plan.request_previews, strict=True)
        if (usage := case.usage_record) is not None
    ]
    assert len(cases) == len(result.cases)
    if not revalidate:
        return report.model_copy(update={"results": [result.model_copy(update={"cases": cases})]})
    payload = report.model_dump(mode="json")
    payload["results"][0]["cases"] = [item.model_dump(mode="json") for item in cases]
    return runner_fixtures._reseal_report(payload)


def _adjudication_report_with_cost_plan(
    prepared: CrossLineageAdjudicationPreparedRun,
    report: CrossLineageAdjudicationReport,
    plan: AuthenticatedRunnerStagedCostPlan,
) -> CrossLineageAdjudicationReport:
    cases = tuple(
        build_cross_lineage_adjudication_case_result(
            request=request,
            response=case.response,
            usage_record=_usage_with_cost_preview(case.usage_record, preview),
            generation_evidence=case.generation_evidence,
        )
        for request, case, preview in zip(
            prepared.requests,
            report.cases,
            plan.request_previews,
            strict=True,
        )
    )
    assert prepared.prepared_run_sha256 == report.prepared_run_sha256
    return build_cross_lineage_adjudication_report(prepared=prepared, results=cases)


def _case_evidence(
    *,
    case_id: str,
    usage: UsageRecord,
    generation_id: str,
    generation_sha256: str,
    validated_response_sha256: str,
) -> AuthenticatedCrossLineageCaseExecutionEvidence:
    assert usage.request_body_sha256 is not None
    assert usage.accounted_cost_usd_exact is not None
    attempt_ids = tuple(
        usage.request_id if index == 1 else f"{usage.request_id}:attempt:{index}"
        for index in range(1, usage.attempts + 1)
    )
    return AuthenticatedCrossLineageCaseExecutionEvidence(
        case_id=case_id,
        request_id=usage.request_id,
        attempt_count=usage.attempts,
        attempt_request_ids=attempt_ids,
        generation_id=generation_id,
        request_body_sha256=usage.request_body_sha256,
        validated_response_sha256=validated_response_sha256,
        generation_attestation_sha256=generation_sha256,
        accounted_cost_usd=usage.accounted_cost_usd_exact,
    )


def _ground_truth_projection(live: _LiveInputs) -> VerifiedFrozenGroundTruthProjection:
    return live.ground_truth.require_for(
        objective_sha256=FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
        provenance_sha256=FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
        source_revision=FROZEN_GROUND_TRUTH_SOURCE_REVISION,
        benchmark_corpus_sha256=live.suite.corpus_sha256,
        benchmark_ground_truth_sha256=live.suite.ground_truth_sha256,
    )


def _runner_evidence(
    live: _LiveInputs,
    *,
    reports: tuple[CrossLineageAdjudicationReport, ...] | None = None,
    candidate_cost_plans: tuple[AuthenticatedRunnerStagedCostPlan, ...] | None = None,
    judge_cost_plans: tuple[AuthenticatedRunnerStagedCostPlan, ...] | None = None,
    effective_config_sha256: str = _EFFECTIVE_CONFIG_SHA256,
) -> AuthenticatedCrossLineageRunnerEvidence:
    if (candidate_cost_plans is None) != (judge_cost_plans is None):
        raise AssertionError("test fixture requires both cost-plan inventories together")
    adjudications = (
        tuple(run.adjudication_report for run in live.runs) if reports is None else reports
    )
    run_evidence: list[AuthenticatedCrossLineageRunnerRunEvidence] = []
    ledger_costs: dict[str, str] = {}
    ledger_reservations: dict[str, str] = {}
    for run_index, (custody, adjudication) in enumerate(zip(live.runs, adjudications, strict=True)):
        candidate_plan = (
            candidate_cost_plans[run_index] if candidate_cost_plans is not None else None
        )
        judge_plan = judge_cost_plans[run_index] if judge_cost_plans is not None else None
        candidate_cases = []
        for case_index, case in enumerate(custody.candidate_report.results[0].cases):
            assert case.usage_record is not None
            assert case.generation_evidence is not None
            assert case.validated_response_sha256 is not None
            candidate = _case_evidence(
                case_id=case.case_id,
                usage=case.usage_record,
                generation_id=case.generation_evidence.generation_id,
                generation_sha256=case.generation_evidence.evidence_sha256,
                validated_response_sha256=case.validated_response_sha256,
            )
            candidate_cases.append(candidate)
            assert case.usage_record.accounted_cost_usd_exact is not None
            for request_id in candidate.attempt_request_ids:
                ledger_costs[request_id] = case.usage_record.accounted_cost_usd_exact
                if candidate_plan is not None:
                    ledger_reservations[request_id] = candidate_plan.request_previews[
                        case_index
                    ].maximum_cost_usd_per_attempt_exact
        judge_cases = []
        for case_index, case in enumerate(adjudication.cases):
            judge = _case_evidence(
                case_id=case.case_id,
                usage=case.usage_record,
                generation_id=case.generation_evidence.generation_id,
                generation_sha256=case.generation_evidence.evidence_sha256,
                validated_response_sha256=case.judge_validated_response_sha256,
            )
            judge_cases.append(judge)
            assert case.usage_record.accounted_cost_usd_exact is not None
            for request_id in judge.attempt_request_ids:
                ledger_costs[request_id] = case.usage_record.accounted_cost_usd_exact
                if judge_plan is not None:
                    ledger_reservations[request_id] = judge_plan.request_previews[
                        case_index
                    ].maximum_cost_usd_per_attempt_exact
        target = adjudication.target
        run_evidence.append(
            AuthenticatedCrossLineageRunnerRunEvidence(
                run_kind=custody.run_kind,
                candidate_model_id=target.candidate_model_id,
                candidate_root_lineage=target.candidate_root_lineage,
                judge_model_id=target.judge_model_id,
                judge_root_lineage=target.judge_root_lineage,
                candidate_report_sha256=custody.candidate_report.report_sha256,
                candidate_portfolio_sha256=custody.candidate_portfolio.portfolio_sha256,
                candidate_campaign_report_sha256s=(custody.candidate_report.report_sha256,),
                prepared_run_sha256=adjudication.prepared_run_sha256,
                adjudication_report_sha256=adjudication.report_sha256,
                candidate_cases=tuple(candidate_cases),
                judge_cases=tuple(judge_cases),
            )
        )
    ledger_entries = tuple(
        AuthenticatedCrossLineageLedgerEntryEvidence(
            request_id=request_id,
            entry_sha256=canonical_sha256(
                {"request_id": request_id, "actual_cost_usd": actual_cost}
            ),
            reserved_usd=ledger_reservations.get(request_id),
            actual_cost_usd=actual_cost,
        )
        for request_id, actual_cost in sorted(ledger_costs.items())
    )
    interval_cost = sum((float(item.actual_cost_usd) for item in ledger_entries), start=0.0)
    interval_cost_text = format(interval_cost, ".12f").rstrip("0").rstrip(".")
    ledger = AuthenticatedCrossLineageLedgerIntervalEvidence(
        ledger_identity_sha256="1" * 64,
        initial_snapshot_sha256="2" * 64,
        final_snapshot_sha256="3" * 64,
        cap_usd="250",
        initial_spent_usd="0",
        interval_spent_usd=interval_cost_text,
        final_spent_usd=interval_cost_text,
        entries=ledger_entries,
    )
    ground = _ground_truth_projection(live)
    first_target = adjudications[0].target
    payload: dict[str, Any] = {
        "schema_version": "1.1",
        "effective_config_sha256": effective_config_sha256,
        "objective_sha256": ground.objective_sha256,
        "frozen_ground_truth_provenance_sha256": ground.provenance_sha256,
        "frozen_source_revision": ground.source_revision,
        "benchmark_corpus_sha256": ground.benchmark_corpus_sha256,
        "benchmark_ground_truth_sha256": ground.benchmark_ground_truth_sha256,
        "ground_truth_case_binding_set_sha256": ground.case_binding_set_sha256,
        "public_lineage_bundle_sha256": first_target.public_lineage_bundle_sha256,
        "public_lineage_manifest_file_sha256": (first_target.public_lineage_manifest_file_sha256),
        "case_ids": tuple(item.case_id for item in live.suite.cases),
        "runs": tuple(run_evidence),
        "ledger_interval": ledger,
        "serialized_authority": False,
        "lineage_identity_authorized": False,
        "provider_call_authorized": False,
        "source_egress_authorized": False,
        "runner_custody_authorized": False,
        "generation_verification_authorized": False,
        "adjudication_credit_authorized": False,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
        "seal_publication_authorized": False,
        "release_authorized": False,
        "benchmark_authorized": False,
    }
    json_payload = {
        key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
        for key, value in payload.items()
    }
    json_payload["runs"] = [item.model_dump(mode="json") for item in run_evidence]
    return AuthenticatedCrossLineageRunnerEvidence(
        **payload,
        evidence_sha256=canonical_sha256(json_payload),
    )


def _complete_authseal_inputs(
    live: _LiveInputs,
    evidence: AuthenticatedCrossLineageRunnerEvidence,
) -> tuple[object, tuple[EvidenceSealDecisionProjection, ...]]:
    candidate_run = evidence.runs[0]
    candidate = build_evidence_seal_lineage_binding(
        exact_model_id=candidate_run.candidate_model_id,
        root_lineage=candidate_run.candidate_root_lineage,
        role=EvidenceSealLineageRole.CANDIDATE,
    )
    judges = tuple(
        build_evidence_seal_lineage_binding(
            exact_model_id=item.judge_model_id,
            root_lineage=item.judge_root_lineage,
            role=EvidenceSealLineageRole.JUDGE,
        )
        for item in sorted(
            evidence.runs,
            key=lambda item: (item.judge_model_id, item.judge_root_lineage),
        )
    )
    collision = build_evidence_seal_collision_map(candidate=candidate, judges=judges)
    judge_by_identity = {
        (item.exact_model_id, item.root_lineage): item for item in collision.judges
    }
    ground = _ground_truth_projection(live)
    decisions = tuple(
        evidence_seal_module._build_evidence_seal_decision_projection(
            suite=live.suite,
            report=custody.candidate_report,
            candidate=candidate,
            runner=judge_by_identity[(run.judge_model_id, run.judge_root_lineage)],
            run_kind=EvidenceSealRunKind(run.run_kind.value),
            ground_truth_projection=ground,
            authenticated_rootless_candidate=True,
        )
        for custody, run in zip(live.runs, evidence.runs, strict=True)
    )
    return collision, decisions


def _bound_stage_usages(
    usages: tuple[UsageRecord, ...],
    *,
    retry_policy: ModelRetryPolicy | None,
) -> tuple[UsageRecord, ...]:
    anchor = usages[0]
    assert anchor.started_at is not None
    assert anchor.ended_at is not None
    reasoning_capability_sha256 = _cost_preview_fixture(0).reasoning_capability_sha256
    retained: list[UsageRecord] = []
    for usage in usages:
        bound = _usage_with_singleton_identity_and_reasoning(
            usage,
            started_at=anchor.started_at,
            ended_at=anchor.ended_at,
            endpoint_capability_sha256=reasoning_capability_sha256,
        )
        assert bound.attempts == 1
        payload = bound.model_dump(mode="python")
        if retry_policy is not None:
            payload["routing"] = {
                **payload["routing"],
                **_successful_model_retry_routing(retry_policy),
            }
        retained.append(reattest_synthetic_real_usage(UsageRecord.model_validate(payload)))
    return tuple(retained)


@dataclass(frozen=True, slots=True)
class _V11Inputs:
    live: _LiveInputs
    candidate_cost_plans: tuple[AuthenticatedRunnerStagedCostPlan, ...]
    judge_cost_plans: tuple[AuthenticatedRunnerStagedCostPlan, ...]
    evidence: AuthenticatedCrossLineageRunnerEvidence


@cache
def _v11_inputs(
    maximum_attempts: int = 2,
    execution_config_sha256: str = _EXECUTION_CONFIG_SHA256,
    effective_config_sha256: str = _EFFECTIVE_CONFIG_SHA256,
    routing_transient_retries: int | None = 1,
) -> _V11Inputs:
    original = _live_inputs()
    retry_policy = (
        None
        if routing_transient_retries is None
        else ModelRetryPolicy.build(
            transient_retry_limit=routing_transient_retries,
            schema_validation_retry_limit=(maximum_attempts - 1 - routing_transient_retries),
        )
    )
    candidate_plans: list[AuthenticatedRunnerStagedCostPlan] = []
    judge_plans: list[AuthenticatedRunnerStagedCostPlan] = []
    retained_runs = []
    for index, custody in enumerate(original.runs):
        candidate_cases = tuple(custody.candidate_report.results[0].cases)
        maybe_candidate_usages = tuple(case.usage_record for case in candidate_cases)
        assert all(usage is not None for usage in maybe_candidate_usages)
        candidate_usages = _bound_stage_usages(
            cast(tuple[UsageRecord, ...], maybe_candidate_usages),
            retry_policy=retry_policy,
        )
        candidate_plan = _cost_plan_for_usages(
            run_kind=custody.run_kind,
            stage=AuthenticatedRunnerCostPlanStage.CANDIDATE,
            case_ids=tuple(case.case_id for case in candidate_cases),
            usages=candidate_usages,
            maximum_attempts=maximum_attempts,
            execution_config_sha256=execution_config_sha256,
        )
        candidate_seed = custody.candidate_report.model_copy(
            update={
                "results": [
                    custody.candidate_report.results[0].model_copy(
                        update={
                            "cases": [
                                case.model_copy(update={"usage_record": usage})
                                for case, usage in zip(
                                    candidate_cases,
                                    candidate_usages,
                                    strict=True,
                                )
                            ]
                        }
                    )
                ]
            }
        )
        candidate_report = _candidate_report_with_cost_plan(
            candidate_seed,
            candidate_plan,
        )
        prepared, provisional_adjudication = runner_fixtures._adjudication_report(
            public_lineage=original.public_lineage,
            suite=original.suite,
            candidate_report=candidate_report,
            judge=custody.judge,
            run_kind=custody.run_kind,
            request_offset=index * 1_000,
        )
        judge_usages = _bound_stage_usages(
            tuple(case.usage_record for case in provisional_adjudication.cases),
            retry_policy=retry_policy,
        )
        judge_plan = _cost_plan_for_usages(
            run_kind=custody.run_kind,
            stage=AuthenticatedRunnerCostPlanStage.JUDGE,
            case_ids=tuple(case.case_id for case in provisional_adjudication.cases),
            usages=judge_usages,
            maximum_attempts=maximum_attempts,
            execution_config_sha256=execution_config_sha256,
        )
        adjudication_seed = provisional_adjudication.model_copy(
            update={
                "cases": tuple(
                    case.model_copy(update={"usage_record": usage})
                    for case, usage in zip(
                        provisional_adjudication.cases,
                        judge_usages,
                        strict=True,
                    )
                )
            }
        )
        adjudication = _adjudication_report_with_cost_plan(
            prepared,
            adjudication_seed,
            judge_plan,
        )
        candidate_plans.append(candidate_plan)
        judge_plans.append(judge_plan)
        retained_runs.append(
            replace(
                custody,
                candidate_report=candidate_report,
                candidate_campaign_reports=(candidate_report,),
                prepared_adjudication=prepared,
                adjudication_report=adjudication,
            )
        )
    live = replace(original, runs=tuple(retained_runs))
    exact_candidate_plans = tuple(candidate_plans)
    exact_judge_plans = tuple(judge_plans)
    evidence = _runner_evidence(
        live,
        candidate_cost_plans=exact_candidate_plans,
        judge_cost_plans=exact_judge_plans,
        effective_config_sha256=effective_config_sha256,
    )
    return _V11Inputs(
        live=live,
        candidate_cost_plans=exact_candidate_plans,
        judge_cost_plans=exact_judge_plans,
        evidence=evidence,
    )


def _rejected_bundle_from_inputs(
    inputs: _V11Inputs,
    *,
    effective_config_sha256: str,
) -> AuthenticatedRunnerDurableEvidenceBundle:
    live = inputs.live
    return build_authenticated_runner_durable_bundle(
        effective_config_sha256=effective_config_sha256,
        runner_evidence=inputs.evidence,
        candidate_cost_plans=inputs.candidate_cost_plans,
        judge_cost_plans=inputs.judge_cost_plans,
        candidate_reports=tuple(item.candidate_report for item in live.runs),
        prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
        adjudication_reports=tuple(item.adjudication_report for item in live.runs),
        authseal_collision_map=None,
        authseal_decision_projections=(),
        authseal_rejection_kind="EvidenceSealAuthorityError",
    )


def _rejected_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    return _rejected_bundle_from_inputs(
        _v11_inputs(),
        effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
    )


@cache
def _continuity_rejected_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    inputs = _v11_inputs(
        5,
        _CONTINUITY_EXECUTION_CONFIG_SHA256,
        _CONTINUITY_EFFECTIVE_CONFIG_SHA256,
    )
    return _rejected_bundle_from_inputs(
        inputs,
        effective_config_sha256=_CONTINUITY_EFFECTIVE_CONFIG_SHA256,
    )


@cache
def _legacy_v11_rejected_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    payload = _rejected_bundle().model_dump(mode="json")
    payload["schema_version"] = "1.1"
    payload.pop("effective_config_sha256")
    runner_evidence = payload["runner_evidence"]
    assert isinstance(runner_evidence, dict)
    runner_evidence["schema_version"] = "1.0"
    runner_evidence.pop("effective_config_sha256")
    runner_evidence["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in runner_evidence.items() if key != "evidence_sha256"}
    )
    payload["runner_evidence_sha256"] = runner_evidence["evidence_sha256"]
    payload["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "bundle_sha256"}
    )
    return AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
        json.dumps(payload, sort_keys=True, separators=(",", ":"))
    )


@cache
def _legacy_rejected_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    payload = _legacy_v11_rejected_bundle().model_dump(mode="json")
    payload["schema_version"] = "1.0"
    for retained in payload["runs"]:
        retained["schema_version"] = "1.0"
        retained["candidate_cost_plan"] = None
        retained["judge_cost_plan"] = None
        retained["run_bundle_sha256"] = canonical_sha256(
            {key: value for key, value in retained.items() if key != "run_bundle_sha256"}
        )
    payload["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "bundle_sha256"}
    )
    return AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
        json.dumps(payload, sort_keys=True, separators=(",", ":"))
    )


def _candidate_report_with_sensitive_routing(
    report: ModelBenchmarkReport,
) -> ModelBenchmarkReport:
    result = report.results[0]
    case = result.cases[0]
    assert case.usage_record is not None
    usage_payload = case.usage_record.model_dump(mode="python")
    routing = dict(usage_payload["routing"])
    routing["access_token"] = "synthetic-redteam-marker"
    usage_payload["routing"] = routing
    usage = UsageRecord.model_validate(usage_payload)
    replacement_case = case.model_copy(update={"usage_record": usage})
    replacement_result = result.model_copy(update={"cases": [replacement_case, *result.cases[1:]]})
    provisional = report.model_copy(
        update={"results": [replacement_result], "report_sha256": "0" * 64}
    )
    payload = provisional.model_dump(mode="json", exclude={"report_sha256"})
    return ModelBenchmarkReport.model_validate_json(
        json.dumps(
            {**payload, "report_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _single_case_runner_evidence(
    evidence: AuthenticatedCrossLineageRunnerEvidence,
) -> AuthenticatedCrossLineageRunnerEvidence:
    case_id = evidence.case_ids[0]
    runs = tuple(
        run.model_copy(
            update={
                "candidate_cases": run.candidate_cases[:1],
                "judge_cases": run.judge_cases[:1],
            }
        )
        for run in evidence.runs
    )
    retained_request_ids = {
        request_id
        for run in runs
        for cases in (run.candidate_cases, run.judge_cases)
        for case in cases
        for request_id in case.attempt_request_ids
    }
    entries = tuple(
        item for item in evidence.ledger_interval.entries if item.request_id in retained_request_ids
    )
    interval_cost = sum((Decimal(item.actual_cost_usd) for item in entries), start=Decimal(0))
    interval_cost_text = format(interval_cost, "f").rstrip("0").rstrip(".") or "0"
    ledger = evidence.ledger_interval.model_copy(
        update={
            "interval_spent_usd": interval_cost_text,
            "final_spent_usd": interval_cost_text,
            "entries": entries,
        }
    )
    payload = evidence.model_dump(mode="json", exclude={"evidence_sha256"})
    payload.update(
        {
            "case_ids": [case_id],
            "runs": [item.model_dump(mode="json") for item in runs],
            "ledger_interval": ledger.model_dump(mode="json"),
        }
    )
    return AuthenticatedCrossLineageRunnerEvidence.model_validate_json(
        json.dumps(
            {**payload, "evidence_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def test_rejected_bundle_round_trips_canonically_without_authority() -> None:
    bundle = _rejected_bundle()
    raw = authenticated_runner_durable_bundle_bytes(bundle)
    replay = revalidate_authenticated_runner_durable_bundle(raw)

    assert replay == bundle
    assert replay.schema_version == "1.2"
    assert replay.effective_config_sha256 == _EFFECTIVE_CONFIG_SHA256
    assert replay.runner_evidence.schema_version == "1.1"
    assert replay.runner_evidence.effective_config_sha256 == _EFFECTIVE_CONFIG_SHA256
    assert all(item.schema_version == "1.1" for item in replay.runs)
    assert all(item.candidate_cost_plan is not None for item in replay.runs)
    assert all(item.judge_cost_plan is not None for item in replay.runs)
    assert isinstance(replay.authseal_comparison, AuthenticatedRunnerAuthsealRejected)
    assert tuple(item.run_kind for item in replay.runs) == (
        CrossLineageAdjudicationRunKind.PRIMARY,
        CrossLineageAdjudicationRunKind.REPLAY,
    )
    assert tuple(item.prepared_run for item in replay.runs) == tuple(
        item.prepared_adjudication for item in _v11_inputs().live.runs
    )
    assert tuple(item.adjudication_report for item in replay.runs) == tuple(
        item.adjudication_report for item in _v11_inputs().live.runs
    )
    assert replay.runner_evidence.ledger_interval == replay.closed_ledger_evidence
    assert replay.serialized_authority is False
    assert replay.runner_custody_authorized is False
    assert replay.authority_issuance_authorized is False
    assert replay.release_authorized is False


def test_legacy_v10_bundle_remains_loadable_but_has_no_cost_admission() -> None:
    bundle = _legacy_rejected_bundle()

    replay = revalidate_authenticated_runner_durable_bundle(
        authenticated_runner_durable_bundle_bytes(bundle)
    )

    assert replay == bundle
    assert replay.schema_version == "1.0"
    assert all(item.schema_version == "1.0" for item in replay.runs)
    assert all(item.candidate_cost_plan is None for item in replay.runs)
    assert all(item.judge_cost_plan is None for item in replay.runs)


def test_legacy_v11_bundle_remains_canonical_but_is_not_current_config_evidence() -> None:
    bundle = _legacy_v11_rejected_bundle()
    raw = authenticated_runner_durable_bundle_bytes(bundle)

    replay = revalidate_authenticated_runner_durable_bundle(raw)

    assert replay == bundle
    assert replay.schema_version == "1.1"
    assert replay.effective_config_sha256 is None
    assert replay.runner_evidence.schema_version == "1.0"
    assert replay.runner_evidence.effective_config_sha256 is None
    assert b'"effective_config_sha256"' not in raw
    with pytest.raises(
        AuthenticatedRunnerDurableBundleError,
        match="legacy and lacks effective config custody",
    ):
        require_authenticated_runner_durable_config_binding(
            replay,
            effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
            execution_config_sha256=_EXECUTION_CONFIG_SHA256,
            maximum_attempts_per_logical_request=2,
            model_retry_policy_sha256=_RETRY_OFF_POLICY.policy_sha256,
        )


@pytest.mark.parametrize(
    (
        "bundle_factory",
        "effective_hash",
        "execution_hash",
        "maximum_attempts",
        "retry_policy_sha256",
    ),
    (
        (
            _rejected_bundle,
            _EFFECTIVE_CONFIG_SHA256,
            _EXECUTION_CONFIG_SHA256,
            2,
            _RETRY_OFF_POLICY.policy_sha256,
        ),
        (
            _continuity_rejected_bundle,
            _CONTINUITY_EFFECTIVE_CONFIG_SHA256,
            _CONTINUITY_EXECUTION_CONFIG_SHA256,
            5,
            _CONTINUITY_POLICY.policy_sha256,
        ),
    ),
    ids=("retry-off", "retry-continuity"),
)
def test_current_bundle_requires_exact_full_execution_and_attempt_config_binding(
    bundle_factory: Callable[[], AuthenticatedRunnerDurableEvidenceBundle],
    effective_hash: str,
    execution_hash: str,
    maximum_attempts: int,
    retry_policy_sha256: str,
) -> None:
    bundle = bundle_factory()

    assert (
        require_authenticated_runner_durable_config_binding(
            bundle,
            effective_config_sha256=effective_hash,
            execution_config_sha256=execution_hash,
            maximum_attempts_per_logical_request=maximum_attempts,
            model_retry_policy_sha256=retry_policy_sha256,
        )
        == bundle
    )


@pytest.mark.parametrize(
    "routing_transient_retries",
    (None, 0),
    ids=("retry-evidence-omitted", "equal-total-split-swapped"),
)
def test_current_bundle_rejects_missing_or_wrong_split_retry_policy_custody(
    routing_transient_retries: int | None,
) -> None:
    inputs = _v11_inputs(routing_transient_retries=routing_transient_retries)
    bundle = _rejected_bundle_from_inputs(
        inputs,
        effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
    )

    with pytest.raises(
        AuthenticatedRunnerDurableBundleError,
        match="differs from the selected effective configuration",
    ):
        require_authenticated_runner_durable_config_binding(
            bundle,
            effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
            execution_config_sha256=_EXECUTION_CONFIG_SHA256,
            maximum_attempts_per_logical_request=2,
            model_retry_policy_sha256=_RETRY_OFF_POLICY.policy_sha256,
        )


@pytest.mark.parametrize(
    ("effective_hash", "execution_hash", "maximum_attempts"),
    (
        (
            _CONTINUITY_EFFECTIVE_CONFIG_SHA256,
            _EXECUTION_CONFIG_SHA256,
            2,
        ),
        (
            _EFFECTIVE_CONFIG_SHA256,
            _CONTINUITY_EXECUTION_CONFIG_SHA256,
            2,
        ),
        (
            _EFFECTIVE_CONFIG_SHA256,
            _EXECUTION_CONFIG_SHA256,
            5,
        ),
        (
            _CONTINUITY_EFFECTIVE_CONFIG_SHA256,
            _CONTINUITY_EXECUTION_CONFIG_SHA256,
            5,
        ),
    ),
    ids=(
        "old-full-hash-as-continuity",
        "wrong-execution-subtree",
        "wrong-attempt-capacity",
        "coherent-continuity-claim-over-retry-off-bundle",
    ),
)
def test_retry_off_bundle_cannot_substitute_for_continuity_evidence(
    effective_hash: str,
    execution_hash: str,
    maximum_attempts: int,
) -> None:
    with pytest.raises(
        AuthenticatedRunnerDurableBundleError,
        match="differs from the selected effective configuration",
    ):
        require_authenticated_runner_durable_config_binding(
            _rejected_bundle(),
            effective_config_sha256=effective_hash,
            execution_config_sha256=execution_hash,
            maximum_attempts_per_logical_request=maximum_attempts,
            model_retry_policy_sha256=(
                _CONTINUITY_POLICY.policy_sha256
                if maximum_attempts == 5
                else _RETRY_OFF_POLICY.policy_sha256
            ),
        )


def test_current_bundle_rejects_free_full_hash_assertion_against_runner_evidence() -> None:
    inputs = _v11_inputs()
    live = inputs.live

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="bundle is invalid"):
        build_authenticated_runner_durable_bundle(
            effective_config_sha256="f" * 64,
            runner_evidence=inputs.evidence,
            candidate_cost_plans=inputs.candidate_cost_plans,
            judge_cost_plans=inputs.judge_cost_plans,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=tuple(item.adjudication_report for item in live.runs),
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_v12_bundle_rejects_historical_runner_evidence_even_when_resealed() -> None:
    payload = _legacy_v11_rejected_bundle().model_dump(mode="json")
    payload["schema_version"] = "1.2"
    payload["effective_config_sha256"] = _EFFECTIVE_CONFIG_SHA256
    payload["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "bundle_sha256"}
    )

    with pytest.raises(ValidationError, match="lacks exact effective config custody"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )


def _run_cost_plan_join_fixture(
    *,
    candidate_drift: str | None = None,
) -> tuple[
    AuthenticatedRunnerStagedCostPlan,
    AuthenticatedRunnerStagedCostPlan,
    ModelBenchmarkReport,
    CrossLineageAdjudicationReport,
]:
    run = _live_inputs().runs[0]
    candidate_cases = tuple(run.candidate_report.results[0].cases)
    raw_candidate_usages = tuple(item.usage_record for item in candidate_cases)
    assert all(item is not None for item in raw_candidate_usages)
    exact_raw_candidate_usages = cast(tuple[UsageRecord, ...], raw_candidate_usages)
    candidate_anchor = exact_raw_candidate_usages[0]
    reasoning_capability_sha256 = _cost_preview_fixture(0).reasoning_capability_sha256
    candidate_usages = tuple(
        _usage_with_singleton_identity_and_reasoning(
            usage,
            started_at=candidate_anchor.started_at,
            ended_at=candidate_anchor.ended_at,
            endpoint_capability_sha256=reasoning_capability_sha256,
        )
        for usage in exact_raw_candidate_usages
    )
    raw_judge_usages = tuple(item.usage_record for item in run.adjudication_report.cases)
    judge_anchor = raw_judge_usages[0]
    judge_usages = tuple(
        _usage_with_singleton_identity_and_reasoning(
            usage,
            started_at=judge_anchor.started_at,
            ended_at=judge_anchor.ended_at,
            endpoint_capability_sha256=reasoning_capability_sha256,
        )
        for usage in raw_judge_usages
    )
    candidate_plan = _cost_plan_for_usages(
        run_kind=run.run_kind,
        stage=AuthenticatedRunnerCostPlanStage.CANDIDATE,
        case_ids=tuple(item.case_id for item in candidate_cases),
        usages=candidate_usages,
        drift=candidate_drift,
    )
    judge_plan = _cost_plan_for_usages(
        run_kind=run.run_kind,
        stage=AuthenticatedRunnerCostPlanStage.JUDGE,
        case_ids=tuple(item.case_id for item in run.adjudication_report.cases),
        usages=judge_usages,
    )
    candidate_seed = run.candidate_report.model_copy(
        update={
            "results": [
                run.candidate_report.results[0].model_copy(
                    update={
                        "cases": [
                            case.model_copy(update={"usage_record": usage})
                            for case, usage in zip(
                                candidate_cases,
                                candidate_usages,
                                strict=True,
                            )
                        ]
                    }
                )
            ]
        }
    )
    adjudication_seed = run.adjudication_report.model_copy(
        update={
            "cases": tuple(
                case.model_copy(update={"usage_record": usage})
                for case, usage in zip(
                    run.adjudication_report.cases,
                    judge_usages,
                    strict=True,
                )
            )
        }
    )
    return (
        candidate_plan,
        judge_plan,
        _candidate_report_with_cost_plan(
            candidate_seed,
            candidate_plan,
            revalidate=candidate_drift is None,
        ),
        _adjudication_report_with_cost_plan(
            run.prepared_adjudication,
            adjudication_seed,
            judge_plan,
        ),
    )


def test_v11_cost_plans_exactly_join_durable_usage() -> None:
    candidate_plan, judge_plan, candidate_report, adjudication_report = (
        _run_cost_plan_join_fixture()
    )

    durable_bundle_module._require_exact_cost_plan_report_join(
        candidate_cost_plan=candidate_plan,
        judge_cost_plan=judge_plan,
        candidate_report=candidate_report,
        adjudication_report=adjudication_report,
    )


@pytest.mark.parametrize(
    "drift",
    (
        "exact_model_id",
        "provider_endpoint",
        "prompt_sha256",
        "response_schema_sha256",
    ),
)
def test_v11_cost_plan_join_rejects_self_valid_routing_reseal_retarget(
    drift: str,
) -> None:
    candidate_plan, judge_plan, candidate_report, adjudication_report = _run_cost_plan_join_fixture(
        candidate_drift=drift
    )

    with pytest.raises(ValueError, match="request-cost preview"):
        durable_bundle_module._require_exact_cost_plan_report_join(
            candidate_cost_plan=candidate_plan,
            judge_cost_plan=judge_plan,
            candidate_report=candidate_report,
            adjudication_report=adjudication_report,
        )


def test_complete_bundle_exactly_joins_authseal_inputs() -> None:
    inputs = _v11_inputs()
    live = inputs.live
    evidence = inputs.evidence
    collision, decisions = _complete_authseal_inputs(live, evidence)
    bundle = build_authenticated_runner_durable_bundle(
        effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
        runner_evidence=evidence,
        candidate_cost_plans=inputs.candidate_cost_plans,
        judge_cost_plans=inputs.judge_cost_plans,
        candidate_reports=tuple(item.candidate_report for item in live.runs),
        prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
        adjudication_reports=tuple(item.adjudication_report for item in live.runs),
        authseal_collision_map=collision,
        authseal_decision_projections=decisions,
        authseal_rejection_kind=None,
    )

    comparison = bundle.authseal_comparison
    assert isinstance(comparison, AuthenticatedRunnerAuthsealComplete)
    assert tuple(item.run_kind for item in comparison.decision_projections) == (
        EvidenceSealRunKind.PRIMARY,
        EvidenceSealRunKind.REPLAY,
    )
    assert tuple(item.benchmark_report_sha256 for item in comparison.decision_projections) == (
        tuple(item.candidate_report_sha256 for item in evidence.runs)
    )
    assert (
        revalidate_authenticated_runner_durable_bundle(
            authenticated_runner_durable_bundle_bytes(bundle)
        )
        == bundle
    )


def test_bundle_rejects_order_hash_ledger_and_noncanonical_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _rejected_bundle()
    payload = bundle.model_dump(mode="json")

    reversed_runs = dict(payload)
    reversed_runs["runs"] = list(reversed(payload["runs"]))
    reversed_runs["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in reversed_runs.items() if key != "bundle_sha256"}
    )
    with pytest.raises(ValidationError, match="PRIMARY then REPLAY"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(reversed_runs, sort_keys=True, separators=(",", ":"))
        )

    wrong_report = json.loads(json.dumps(payload))
    wrong_report["runs"][0]["runner_run_evidence_sha256"] = "f" * 64
    wrong_report["runs"][0]["run_bundle_sha256"] = canonical_sha256(
        {key: value for key, value in wrong_report["runs"][0].items() if key != "run_bundle_sha256"}
    )
    wrong_report["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in wrong_report.items() if key != "bundle_sha256"}
    )
    with pytest.raises(ValidationError, match="runner run hashes"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(wrong_report, sort_keys=True, separators=(",", ":"))
        )

    wrong_ledger = json.loads(json.dumps(payload))
    wrong_ledger["closed_ledger_evidence"]["entries"][0]["request_id"] = "unused-request"
    wrong_ledger["closed_ledger_evidence"]["entries"] = sorted(
        wrong_ledger["closed_ledger_evidence"]["entries"],
        key=lambda item: item["request_id"],
    )
    wrong_ledger["closed_ledger_evidence_sha256"] = canonical_sha256(
        wrong_ledger["closed_ledger_evidence"]
    )
    wrong_ledger["runner_evidence"]["ledger_interval"] = wrong_ledger["closed_ledger_evidence"]
    wrong_ledger["runner_evidence"]["evidence_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in wrong_ledger["runner_evidence"].items()
            if key != "evidence_sha256"
        }
    )
    wrong_ledger["runner_evidence_sha256"] = wrong_ledger["runner_evidence"]["evidence_sha256"]
    wrong_ledger["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in wrong_ledger.items() if key != "bundle_sha256"}
    )
    with pytest.raises(ValidationError, match="closed ledger differs"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(wrong_ledger, sort_keys=True, separators=(",", ":"))
        )

    raw = authenticated_runner_durable_bundle_bytes(bundle)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="canonically serialized"):
        revalidate_authenticated_runner_durable_bundle(b" \n" + raw)
    with monkeypatch.context() as context:
        context.setattr(durable_bundle_module, "MAX_JSON_ARTIFACT_BYTES", 100)
        with pytest.raises(AuthenticatedRunnerDurableBundleError, match="over the byte ceiling"):
            revalidate_authenticated_runner_durable_bundle(b"x" * 101)


def test_full_bundle_rejects_resealed_judge_cost_plan_execution_config_drift() -> None:
    bundle = _rejected_bundle()
    retained = bundle.runs[0]
    judge_plan = retained.judge_cost_plan
    assert judge_plan is not None
    drifted_previews = []
    for preview in judge_plan.request_previews:
        preview_payload = preview.model_dump(mode="json", exclude={"preview_sha256"})
        preview_payload["execution_config_sha256"] = "9" * 64
        drifted_previews.append(
            OpenRouterStructuredRequestCostPreview.model_validate_json(
                json.dumps(
                    {
                        **preview_payload,
                        "preview_sha256": canonical_sha256(preview_payload),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                strict=True,
            )
        )
    drifted_judge_plan = build_authenticated_runner_staged_cost_plan(
        run_kind=judge_plan.run_kind,
        stage=judge_plan.stage,
        case_ids=judge_plan.case_ids,
        request_previews=tuple(drifted_previews),
    )
    drifted_cases = tuple(
        build_cross_lineage_adjudication_case_result(
            request=request,
            response=case.response,
            usage_record=reattest_synthetic_real_usage(
                case.usage_record.model_copy(
                    update={
                        "routing": {
                            **case.usage_record.routing,
                            "request_cost_preview_sha256": preview.preview_sha256,
                        }
                    }
                )
            ),
            generation_evidence=case.generation_evidence,
        )
        for request, case, preview in zip(
            retained.prepared_run.requests,
            retained.adjudication_report.cases,
            drifted_judge_plan.request_previews,
            strict=True,
        )
    )
    drifted_report = build_cross_lineage_adjudication_report(
        prepared=retained.prepared_run,
        results=drifted_cases,
    )
    run_payload: dict[str, object] = {
        "schema_version": "1.1",
        "run_kind": retained.run_kind,
        "candidate_cost_plan": retained.candidate_cost_plan,
        "judge_cost_plan": drifted_judge_plan,
        "candidate_report": retained.candidate_report,
        "prepared_run": retained.prepared_run,
        "adjudication_report": drifted_report,
        "runner_run_evidence_sha256": retained.runner_run_evidence_sha256,
    }
    drifted_retained = AuthenticatedRunnerDurableRunEvidence(
        **run_payload,
        run_bundle_sha256=canonical_sha256(durable_bundle_module._json_payload(run_payload)),
    )
    payload = bundle.model_dump(mode="json")
    payload["runs"][0] = drifted_retained.model_dump(mode="json")
    payload["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "bundle_sha256"}
    )

    with pytest.raises(ValidationError, match="runner run hashes"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )


def test_bundle_rejects_sensitive_routing_even_when_report_is_resealed() -> None:
    inputs = _v11_inputs()
    live = inputs.live
    original = live.runs[0].adjudication_report
    first = original.cases[0]
    usage_payload = first.usage_record.model_dump(mode="python")
    usage_payload["routing"] = {**usage_payload["routing"], "private_source": "forbidden"}
    usage = UsageRecord.model_validate(usage_payload)
    replacement = build_cross_lineage_adjudication_case_result(
        request=first.request,
        response=first.response,
        usage_record=usage,
        generation_evidence=first.generation_evidence,
    )
    cases: tuple[CrossLineageAdjudicationCaseResult, ...] = (
        replacement,
        *original.cases[1:],
    )
    resealed = build_cross_lineage_adjudication_report(
        prepared=live.runs[0].prepared_adjudication,
        results=cases,
    )
    reports = (resealed, live.runs[1].adjudication_report)
    evidence = _runner_evidence(
        live,
        reports=reports,
        candidate_cost_plans=inputs.candidate_cost_plans,
        judge_cost_plans=inputs.judge_cost_plans,
    )

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="sensitive field name"):
        build_authenticated_runner_durable_bundle(
            effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
            runner_evidence=evidence,
            candidate_cost_plans=inputs.candidate_cost_plans,
            judge_cost_plans=inputs.judge_cost_plans,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=reports,
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_bundle_rejects_access_token_in_candidate_routing() -> None:
    inputs = _v11_inputs()
    live = inputs.live
    evidence = inputs.evidence
    candidate_reports = (
        _candidate_report_with_sensitive_routing(live.runs[0].candidate_report),
        live.runs[1].candidate_report,
    )

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="sensitive field name"):
        build_authenticated_runner_durable_bundle(
            effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
            runner_evidence=evidence,
            candidate_cost_plans=inputs.candidate_cost_plans,
            judge_cost_plans=inputs.judge_cost_plans,
            candidate_reports=candidate_reports,
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=tuple(item.adjudication_report for item in live.runs),
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_bundle_rejects_nested_access_token_in_judge_routing() -> None:
    inputs = _v11_inputs()
    live = inputs.live
    original = live.runs[0].adjudication_report
    first = original.cases[0]
    usage_payload = first.usage_record.model_dump(mode="python")
    routing = dict(usage_payload["routing"])
    identity_binding = dict(routing["identity_binding"])
    identity_binding["access_token"] = "synthetic-redteam-marker"
    routing["identity_binding"] = identity_binding
    usage_payload["routing"] = routing
    usage = UsageRecord.model_validate(usage_payload)
    replacement = build_cross_lineage_adjudication_case_result(
        request=first.request,
        response=first.response,
        usage_record=usage,
        generation_evidence=first.generation_evidence,
    )
    resealed = build_cross_lineage_adjudication_report(
        prepared=live.runs[0].prepared_adjudication,
        results=(replacement, *original.cases[1:]),
    )
    reports = (resealed, live.runs[1].adjudication_report)
    evidence = _runner_evidence(
        live,
        reports=reports,
        candidate_cost_plans=inputs.candidate_cost_plans,
        judge_cost_plans=inputs.judge_cost_plans,
    )

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="sensitive field name"):
        build_authenticated_runner_durable_bundle(
            effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
            runner_evidence=evidence,
            candidate_cost_plans=inputs.candidate_cost_plans,
            judge_cost_plans=inputs.judge_cost_plans,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=reports,
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_bundle_rejects_runtime_shape_below_frozen_release_protocol() -> None:
    inputs = _v11_inputs()
    live = inputs.live
    evidence = _single_case_runner_evidence(inputs.evidence)
    assert len(evidence.case_ids) == 1
    assert len(evidence.ledger_interval.entries) == 4

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="two-run 24-case protocol"):
        build_authenticated_runner_durable_bundle(
            effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
            runner_evidence=evidence,
            candidate_cost_plans=inputs.candidate_cost_plans,
            judge_cost_plans=inputs.judge_cost_plans,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=tuple(item.adjudication_report for item in live.runs),
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_complete_bundle_rejects_resealed_authseal_scoring_tamper() -> None:
    inputs = _v11_inputs()
    live = inputs.live
    evidence = inputs.evidence
    collision, decisions = _complete_authseal_inputs(live, evidence)
    original = decisions[0]
    payload = original.model_dump(mode="json", exclude={"projection_sha256"})
    payload["overall_score_micros"] = 0
    payload["deterministic_output_sha256"] = evidence_seal_module._decision_output_sha256(
        candidate=original.candidate,
        corpus_sha256=original.benchmark_corpus_sha256,
        ground_truth_sha256=original.benchmark_ground_truth_sha256,
        case_outcome_sha256s=original.case_outcome_sha256s,
        case_dimension_outcome_set_sha256=original.case_dimension_outcome_set_sha256,
        dimension_score_sha256s=original.dimension_score_sha256s,
        overall_score_micros=0,
        execution_evidence=original.execution_evidence,
    )
    tampered = EvidenceSealDecisionProjection.model_validate_json(
        json.dumps(
            {**payload, "projection_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="bundle is invalid"):
        build_authenticated_runner_durable_bundle(
            effective_config_sha256=_EFFECTIVE_CONFIG_SHA256,
            runner_evidence=evidence,
            candidate_cost_plans=inputs.candidate_cost_plans,
            judge_cost_plans=inputs.judge_cost_plans,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=tuple(item.adjudication_report for item in live.runs),
            authseal_collision_map=collision,
            authseal_decision_projections=(tampered, decisions[1]),
            authseal_rejection_kind=None,
        )


def test_authseal_rejection_is_bounded_type_only() -> None:
    inputs = _v11_inputs()
    live = inputs.live
    evidence = inputs.evidence
    common = {
        "effective_config_sha256": _EFFECTIVE_CONFIG_SHA256,
        "runner_evidence": evidence,
        "candidate_cost_plans": inputs.candidate_cost_plans,
        "judge_cost_plans": inputs.judge_cost_plans,
        "candidate_reports": tuple(item.candidate_report for item in live.runs),
        "prepared_runs": tuple(item.prepared_adjudication for item in live.runs),
        "adjudication_reports": tuple(item.adjudication_report for item in live.runs),
        "authseal_collision_map": None,
        "authseal_decision_projections": (),
    }
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="exception type"):
        build_authenticated_runner_durable_bundle(
            **common,
            authseal_rejection_kind="ValueError: provider said secret text",
        )
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="collision map"):
        build_authenticated_runner_durable_bundle(
            **common,
            authseal_rejection_kind=None,
        )


def test_durable_bundle_release_schema_is_closed_bounded_and_non_authorizing() -> None:
    filename = "authenticated_runner_durable_evidence_bundle.schema.json"
    assert MODELS[filename] is AuthenticatedRunnerDurableEvidenceBundle
    schema = json.loads(rendered_schema(filename, MODELS[filename]))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["runs"]["minItems"] == 2
    assert schema["properties"]["runs"]["maxItems"] == 2
    assert (
        schema["properties"]["runs"]["prefixItems"][0]["allOf"][1]["properties"]["run_kind"][
            "const"
        ]
        == "PRIMARY"
    )
    assert (
        schema["properties"]["runs"]["prefixItems"][1]["allOf"][1]["properties"]["run_kind"][
            "const"
        ]
        == "REPLAY"
    )
    definitions = schema["$defs"]
    prepared = definitions["CrossLineageAdjudicationPreparedRun"]["properties"]
    report = definitions["CrossLineageAdjudicationReport"]["properties"]
    candidate_report = definitions["ModelBenchmarkReport"]["properties"]
    candidate_result = definitions["ModelBenchmarkModelResult"]["properties"]
    for inventory in (
        prepared["case_ids"],
        prepared["requests"],
        report["case_ids"],
        report["cases"],
        candidate_report["case_ids"],
        candidate_result["cases"],
    ):
        assert inventory["minItems"] == inventory["maxItems"] == 24
        assert inventory["uniqueItems"] is True
    assert candidate_report["results"]["minItems"] == 1
    assert candidate_report["results"]["maxItems"] == 1
    assert candidate_report["results"]["uniqueItems"] is True
    runner_run = definitions["AuthenticatedCrossLineageRunnerRunEvidence"]["properties"]
    for field_name in ("candidate_cases", "judge_cases"):
        assert runner_run[field_name]["minItems"] == 24
        assert runner_run[field_name]["maxItems"] == 24
        assert runner_run[field_name]["uniqueItems"] is True
    ledger_entries = definitions["AuthenticatedCrossLineageLedgerIntervalEvidence"]["properties"][
        "entries"
    ]
    assert ledger_entries["minItems"] == 96
    assert ledger_entries["maxItems"] == 3_072
    assert ledger_entries["uniqueItems"] is True
    decisions = definitions["AuthenticatedRunnerAuthsealComplete"]["properties"][
        "decision_projections"
    ]
    assert decisions["minItems"] == decisions["maxItems"] == 2
    assert decisions["uniqueItems"] is True
    assert [
        item["allOf"][1]["properties"]["run_kind"]["const"] for item in decisions["prefixItems"]
    ] == ["PRIMARY", "REPLAY"]
    routing = definitions["UsageRecord"]["properties"]["routing"]
    assert routing["maxProperties"] == 256
    assert routing["additionalProperties"] == {
        "$ref": "#/$defs/AuthenticatedRunnerSafeRoutingValue"
    }
    allowed_routing_keys = set(routing["propertyNames"]["allOf"][-1]["enum"])
    assert "access_token" not in allowed_routing_keys
    assert allowed_routing_keys >= _MODEL_RETRY_ROUTING_KEYS
    bundle_payload = json.loads(authenticated_runner_durable_bundle_bytes(_rejected_bundle()))
    assert len(bundle_payload["runs"]) == schema["properties"]["runs"]["minItems"]
    assert len(bundle_payload["runner_evidence"]["case_ids"]) == 24
    assert len(bundle_payload["closed_ledger_evidence"]["entries"]) >= ledger_entries["minItems"]
    for retained_run in bundle_payload["runs"]:
        assert len(retained_run["candidate_report"]["case_ids"]) == 24
        assert len(retained_run["candidate_report"]["results"]) == 1
        assert len(retained_run["candidate_report"]["results"][0]["cases"]) == 24
        assert len(retained_run["prepared_run"]["case_ids"]) == 24
        assert len(retained_run["prepared_run"]["requests"]) == 24
        assert len(retained_run["adjudication_report"]["case_ids"]) == 24
        assert len(retained_run["adjudication_report"]["cases"]) == 24
        routing_values = (
            case["usage_record"]["routing"]
            for case in retained_run["candidate_report"]["results"][0]["cases"]
        )
        assert all(set(value) <= allowed_routing_keys for value in routing_values)
    assert (
        schema["$defs"]["AuthenticatedRunnerAuthsealRejected"]["properties"]["rejection_kind"][
            "pattern"
        ]
        == r"^[A-Za-z][A-Za-z0-9_]{0,99}$"
    )
    names = set()

    def collect(value: object) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                names.update(properties)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(schema)
    assert {
        "api_key",
        "credential",
        "execution",
        "operator_secrets",
        "private_source",
        "runner_capability",
        "runner_custody",
        "secret",
    }.isdisjoint(names)
    assert {
        name for name, field in schema["properties"].items() if field.get("const") is False
    } == {
        "serialized_authority",
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_custody_authorized",
        "authority_issuance_authorized",
        "benchmark_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
    }


def _write_private_bundle(path: Path, raw: bytes) -> None:
    path.parent.mkdir(mode=0o700)
    path.parent.chmod(0o700)
    path.write_bytes(raw)
    path.chmod(0o600)


def test_private_file_loader_replays_canonical_bundle(tmp_path: Path) -> None:
    bundle = _rejected_bundle()
    path = tmp_path / "private" / "runner-evidence.json"
    _write_private_bundle(path, authenticated_runner_durable_bundle_bytes(bundle))

    loaded = load_authenticated_runner_durable_bundle(path)

    assert loaded == bundle
    assert loaded.serialized_authority is False
    assert loaded.runner_custody_authorized is False


@pytest.mark.parametrize(
    "raw",
    (
        b'{"schema_version":"1.0","schema_version":"1.0"}',
        b'{"nonfinite":NaN}',
        b" {}",
    ),
)
def test_private_file_loader_rejects_duplicate_nonfinite_and_noncanonical_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    path = tmp_path / "private" / "runner-evidence.json"
    _write_private_bundle(path, raw)

    with pytest.raises(AuthenticatedRunnerDurableBundleError):
        load_authenticated_runner_durable_bundle(path)


def test_private_file_loader_rejects_unsafe_mode_links_and_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = authenticated_runner_durable_bundle_bytes(_rejected_bundle())

    public_path = tmp_path / "public" / "runner-evidence.json"
    _write_private_bundle(public_path, raw)
    public_path.chmod(0o644)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(public_path)

    shared_path = tmp_path / "shared" / "runner-evidence.json"
    _write_private_bundle(shared_path, raw)
    shared_link = shared_path.parent / "second-name.json"
    shared_link.hardlink_to(shared_path)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(shared_path)

    source_path = tmp_path / "source" / "runner-evidence.json"
    _write_private_bundle(source_path, raw)
    linked_parent = tmp_path / "linked"
    linked_parent.mkdir(mode=0o700)
    linked_parent.chmod(0o700)
    symlink_path = linked_parent / "runner-evidence.json"
    symlink_path.symlink_to(source_path)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(symlink_path)

    bounded_path = tmp_path / "bounded" / "runner-evidence.json"
    _write_private_bundle(bounded_path, raw)
    monkeypatch.setattr(durable_bundle_module, "MAX_JSON_ARTIFACT_BYTES", 64)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(bounded_path)


def test_private_file_loader_rejects_path_replacement_during_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = authenticated_runner_durable_bundle_bytes(_rejected_bundle())
    path = tmp_path / "private" / "runner-evidence.json"
    _write_private_bundle(path, raw)
    real_read = durable_bundle_module.read_json_evidence

    def replace_after_read(
        *,
        evidence_root: Path,
        relative_path: str | Path,
        max_bytes: int,
    ) -> JsonEvidenceObservation:
        observed = real_read(
            evidence_root=evidence_root,
            relative_path=relative_path,
            max_bytes=max_bytes,
        )
        path.unlink()
        path.write_bytes(raw)
        path.chmod(0o600)
        return observed

    monkeypatch.setattr(durable_bundle_module, "read_json_evidence", replace_after_read)

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="changed during observation"):
        load_authenticated_runner_durable_bundle(path)


def test_private_file_loader_requires_absolute_path(tmp_path: Path) -> None:
    del tmp_path
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="absolute private file"):
        load_authenticated_runner_durable_bundle(Path("runner-evidence.json"))
