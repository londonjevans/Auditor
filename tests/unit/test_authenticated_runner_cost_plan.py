from __future__ import annotations

import hashlib
import json
from decimal import Decimal, localcontext
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.cross_lineage_adjudication import CrossLineageAdjudicationRunKind
from mmaudit.models.authenticated_runner_cost_plan import (
    AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT,
    AuthenticatedRunnerCostPlanError,
    AuthenticatedRunnerCostPlanStage,
    AuthenticatedRunnerStagedCostPlan,
    authenticated_runner_staged_cost_plan_bytes,
    build_authenticated_runner_staged_cost_plan,
    revalidate_authenticated_runner_staged_cost_plan,
)
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.orchestration.budgets import EndpointRequestCostBound


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _format_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _case_ids() -> tuple[str, ...]:
    return tuple(f"case-{index:016x}" for index in range(AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT))


def _preview(
    index: int,
    *,
    logical_request_id: str | None = None,
    provider_endpoint: str = "fixture-provider/fp8",
    maximum_attempts: int = 2,
    execution_config_sha256: str | None = None,
    discovery_evidence_sha256: str | None = None,
    prompt_price: str = "0.001",
    reserved_output_tokens: int = 5,
    reserved_reasoning_tokens: int = 3,
) -> OpenRouterStructuredRequestCostPreview:
    exact_model_id = "fixture/model-v1"
    prompt_units = 100 + index
    completion_units = reserved_output_tokens + reserved_reasoning_tokens
    pricing = {
        "completion": "0.002",
        "input_cache_read": "0.0001",
        "prompt": prompt_price,
    }
    maximum_units = {
        "completion": completion_units,
        "input_cache_read": prompt_units,
        "prompt": prompt_units,
    }
    bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=exact_model_id,
        provider_endpoint=provider_endpoint,
        request_material="mmaudit-provider-free-cost-preview",
        pricing=pricing,
        maximum_units=maximum_units,
    )
    per_attempt = _format_decimal(bound.maximum_cost_usd)
    with localcontext() as context:
        context.prec = 200
        all_attempts = _format_decimal(bound.maximum_cost_usd * maximum_attempts)
    values: dict[str, Any] = {
        "artifact_kind": "openrouter_structured_request_cost_preview",
        "schema_version": "1.0",
        "logical_request_id": logical_request_id or f"authrunner-request-{index:02d}",
        "role": "model_benchmark",
        "exact_model_id": exact_model_id,
        "provider_endpoint": provider_endpoint,
        "maximum_attempts": maximum_attempts,
        "execution_config_sha256": execution_config_sha256 or _sha("execution-config"),
        "privacy_config_sha256": _sha("privacy-config"),
        "token_budget_config_sha256": _sha("token-budget-config"),
        "provider_policy_sha256": _sha("provider-policy"),
        "discovery_manifest_sha256": _sha("discovery-manifest"),
        "discovery_evidence_sha256": discovery_evidence_sha256 or _sha("discovery-evidence"),
        "discovery_provenance_sha256": _sha("discovery-provenance"),
        "catalog_snapshot_sha256": _sha("catalog-snapshot"),
        "catalog_identity_binding_sha256": _sha("catalog-identity-binding"),
        "model_metadata_snapshot_sha256": _sha("model-metadata-snapshot"),
        "model_identity_snapshot_sha256": _sha("model-identity-snapshot"),
        "endpoint_policy_snapshot_sha256": _sha("endpoint-policy-snapshot"),
        "endpoint_record_snapshot_sha256": _sha("endpoint-record-snapshot"),
        "endpoint_policy_pricing_sha256": _sha("endpoint-policy-pricing"),
        "endpoint_pricing_sha256": _sha("endpoint-pricing"),
        "output_capability_sha256": _sha("output-capability"),
        "reasoning_capability_sha256": _sha("reasoning-capability"),
        "structured_output_mode": StructuredOutputMode.NATIVE_JSON_SCHEMA,
        "prompt_sha256": _sha(f"prompt-{index}"),
        "system_prompt_sha256": _sha("system-prompt"),
        "user_prompt_sha256": _sha(f"user-prompt-{index}"),
        "response_schema_sha256": _sha("response-schema"),
        "output_request_shape_sha256": _sha("output-request-shape"),
        "required_provider_parameters_sha256": _sha("provider-parameters"),
        "strict_output_protocol_sha256": _sha("strict-output-protocol"),
        "reasoning_request_sha256": _sha("reasoning-request"),
        "reasoning_plan_sha256": _sha("reasoning-plan"),
        "reasoning_policy_sha256": _sha("reasoning-policy"),
        "reasoning_policy_role_binding_sha256": _sha("reasoning-role-binding"),
        "reasoning_profile_sha256": _sha("reasoning-profile"),
        "reasoning_qualification_sha256": None,
        "context_request_evidence_sha256": None,
        "rendered_context_sha256": None,
        "request_token_plan_projection_sha256": _sha(f"token-plan-{index}"),
        "request_material_projection_sha256": _sha(f"request-material-{index}"),
        "request_material_projection_utf8_bytes": prompt_units,
        "endpoint_cost_bound_pricing_sha256": bound.pricing_snapshot_sha256,
        "endpoint_cost_bound_projection_sha256": _sha(f"cost-projection-{index}"),
        "cost_components": tuple(
            {
                "pricing_field": field,
                "unit_price_usd_exact": price,
                "maximum_units": maximum_units[field],
            }
            for field, price in sorted(pricing.items())
        ),
        "prompt_byte_upper_bound_tokens": prompt_units,
        "requested_completion_tokens": completion_units,
        "reserved_output_tokens": reserved_output_tokens,
        "reserved_reasoning_tokens": reserved_reasoning_tokens,
        "maximum_priced_prompt_units": prompt_units,
        "maximum_cost_usd_per_attempt_exact": per_attempt,
        "maximum_cost_usd_all_attempts_exact": all_attempts,
        "authorizes_dispatch": False,
        "authorizes_budget_reservation": False,
        "authorizes_provider_transport": False,
        "grants_review_credit": False,
        "grants_completion_credit": False,
    }
    return OpenRouterStructuredRequestCostPreview.model_validate(
        {**values, "preview_sha256": _canonical_sha256(values)},
        strict=True,
    )


def _previews() -> tuple[OpenRouterStructuredRequestCostPreview, ...]:
    return tuple(_preview(index) for index in range(AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT))


def _build(
    previews: tuple[OpenRouterStructuredRequestCostPreview, ...] | None = None,
    *,
    case_ids: tuple[str, ...] | None = None,
    run_kind: CrossLineageAdjudicationRunKind = CrossLineageAdjudicationRunKind.PRIMARY,
    stage: AuthenticatedRunnerCostPlanStage = AuthenticatedRunnerCostPlanStage.CANDIDATE,
) -> AuthenticatedRunnerStagedCostPlan:
    return build_authenticated_runner_staged_cost_plan(
        run_kind=run_kind,
        stage=stage,
        case_ids=case_ids or _case_ids(),
        request_previews=previews or _previews(),
    )


def _replace_preview(
    preview: OpenRouterStructuredRequestCostPreview,
    **changes: object,
) -> OpenRouterStructuredRequestCostPreview:
    values = preview.model_dump(mode="json", exclude={"preview_sha256"})
    values.update(changes)
    raw = json.dumps(
        {**values, "preview_sha256": _canonical_sha256(values)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return OpenRouterStructuredRequestCostPreview.model_validate_json(raw, strict=True)


def _rehash_plan_payload(plan: AuthenticatedRunnerStagedCostPlan, **changes: object) -> bytes:
    values = plan.model_dump(mode="json", exclude={"plan_sha256"})
    values.update(changes)
    return json.dumps(
        {**values, "plan_sha256": _canonical_sha256(values)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_builds_exact_retry_inclusive_deterministic_plan() -> None:
    previews = _previews()

    plan = _build(previews)
    rebuilt = _build(previews)

    assert plan == rebuilt
    assert len(plan.request_previews) == AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT
    assert plan.logical_request_count == AUTHENTICATED_RUNNER_COST_PLAN_CASE_COUNT
    assert plan.maximum_provider_attempt_count == 48
    assert plan.provider_attempt_request_ids[:4] == (
        "authrunner-request-00",
        "authrunner-request-00:attempt:2",
        "authrunner-request-01",
        "authrunner-request-01:attempt:2",
    )
    assert Decimal(plan.maximum_cost_usd_per_attempt_exact) == max(
        Decimal(preview.maximum_cost_usd_per_attempt_exact) for preview in previews
    )
    assert Decimal(plan.maximum_cost_usd_per_logical_request_exact) == max(
        Decimal(preview.maximum_cost_usd_all_attempts_exact) for preview in previews
    )
    assert Decimal(plan.maximum_cost_usd_exact) == sum(
        (Decimal(preview.maximum_cost_usd_all_attempts_exact) for preview in previews),
        start=Decimal(0),
    )
    assert plan.authorizes_dispatch is False
    assert plan.authorizes_budget_reservation is False
    assert plan.authorizes_provider_transport is False
    assert plan.grants_review_credit is False
    assert plan.grants_completion_credit is False
    assert plan.runner_custody_authorized is False
    assert plan.release_authorized is False
    raw = authenticated_runner_staged_cost_plan_bytes(plan)
    assert raw == authenticated_runner_staged_cost_plan_bytes(rebuilt)
    assert revalidate_authenticated_runner_staged_cost_plan(raw) == plan


def test_builds_independent_replay_judge_stage_identity() -> None:
    candidate = _build()
    replay_judge = _build(
        run_kind=CrossLineageAdjudicationRunKind.REPLAY,
        stage=AuthenticatedRunnerCostPlanStage.JUDGE,
    )

    assert replay_judge.run_kind is CrossLineageAdjudicationRunKind.REPLAY
    assert replay_judge.stage is AuthenticatedRunnerCostPlanStage.JUDGE
    assert replay_judge.plan_sha256 != candidate.plan_sha256


def test_order_is_bound_without_silently_sorting_previews() -> None:
    previews = _previews()
    swapped = (previews[1], previews[0], *previews[2:])

    original = _build(previews)
    reordered = _build(swapped)

    assert reordered.request_previews == swapped
    assert reordered.ordered_request_set_sha256 != original.ordered_request_set_sha256
    assert reordered.plan_sha256 != original.plan_sha256


@pytest.mark.parametrize("count", [23, 25])
def test_rejects_any_request_count_other_than_24(count: int) -> None:
    previews = tuple(_preview(index) for index in range(count))
    cases = tuple(f"case-{index:016x}" for index in range(count))

    with pytest.raises(AuthenticatedRunnerCostPlanError, match="exactly 24"):
        _build(previews, case_ids=cases)


@pytest.mark.parametrize(
    ("replacement", "match"),
    [
        (
            _preview(7, execution_config_sha256=_sha("other-execution-config")),
            "singleton route, discovery, or config",
        ),
        (
            _preview(7, discovery_evidence_sha256=_sha("other-discovery-evidence")),
            "singleton route, discovery, or config",
        ),
        (
            _preview(7, provider_endpoint="other-provider/fp8"),
            "singleton route, discovery, or config",
        ),
        (
            _preview(7, maximum_attempts=1),
            "singleton route, discovery, or config",
        ),
    ],
)
def test_rejects_singleton_binding_drift(
    replacement: OpenRouterStructuredRequestCostPreview,
    match: str,
) -> None:
    previews = list(_previews())
    previews[7] = replacement

    with pytest.raises(AuthenticatedRunnerCostPlanError, match="invalid"):
        _build(tuple(previews))


@pytest.mark.parametrize(
    "replacement",
    [
        _preview(7, prompt_price="0.003"),
        _preview(7, reserved_output_tokens=6),
    ],
)
def test_rejects_singleton_pricing_and_output_budget_drift(
    replacement: OpenRouterStructuredRequestCostPreview,
) -> None:
    previews = list(_previews())
    previews[7] = replacement

    with pytest.raises(AuthenticatedRunnerCostPlanError, match="invalid"):
        _build(tuple(previews))


def test_rejects_duplicate_and_retry_colliding_logical_request_ids() -> None:
    previews = list(_previews())
    previews[1] = _replace_preview(
        previews[1],
        logical_request_id=previews[0].logical_request_id,
    )
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="invalid"):
        _build(tuple(previews))

    previews = list(_previews())
    previews[0] = _replace_preview(previews[0], logical_request_id="r" * 128)
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="retry inventory"):
        _build(tuple(previews))

    previews = list(_previews())
    previews[0] = _replace_preview(previews[0], logical_request_id="retry-collision")
    previews[1] = _replace_preview(
        previews[1],
        logical_request_id="retry-collision:attempt:2",
    )
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="invalid"):
        _build(tuple(previews))


def test_rejects_noncanonical_case_inventory() -> None:
    cases = list(_case_ids())
    cases[1] = cases[0]
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="invalid"):
        _build(case_ids=tuple(cases))

    cases = list(_case_ids())
    cases[0], cases[1] = cases[1], cases[0]
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="invalid"):
        _build(case_ids=tuple(cases))


def test_revalidation_rejects_rehashed_aggregate_and_authority_tampering() -> None:
    plan = _build()

    with pytest.raises(AuthenticatedRunnerCostPlanError, match="do not validate"):
        revalidate_authenticated_runner_staged_cost_plan(
            _rehash_plan_payload(plan, maximum_cost_usd_exact="999")
        )
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="do not validate"):
        revalidate_authenticated_runner_staged_cost_plan(
            _rehash_plan_payload(plan, authorizes_dispatch=True)
        )


def test_revalidation_accepts_only_exact_canonical_bytes() -> None:
    plan = _build()
    canonical = authenticated_runner_staged_cost_plan_bytes(plan)
    noncanonical = json.dumps(plan.model_dump(mode="json"), indent=2).encode("utf-8")

    assert revalidate_authenticated_runner_staged_cost_plan(canonical) == plan
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="not canonically serialized"):
        revalidate_authenticated_runner_staged_cost_plan(noncanonical)
    with pytest.raises(AuthenticatedRunnerCostPlanError, match="absent, non-exact"):
        revalidate_authenticated_runner_staged_cost_plan(bytearray(canonical))  # type: ignore[arg-type]


def test_direct_model_validation_rejects_even_self_rehashed_cost_tampering() -> None:
    plan = _build()

    with pytest.raises(ValidationError, match="retry-inclusive aggregate is inconsistent"):
        AuthenticatedRunnerStagedCostPlan.model_validate_json(
            _rehash_plan_payload(
                plan,
                maximum_cost_usd_per_logical_request_exact="100",
            ),
            strict=True,
        )

    values = plan.model_dump(mode="json")
    values["plan_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="hash does not match"):
        AuthenticatedRunnerStagedCostPlan.model_validate_json(
            json.dumps(values).encode("utf-8"),
            strict=True,
        )
