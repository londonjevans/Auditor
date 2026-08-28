from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.config import ModelRetryPolicy
from mmaudit.models.coverage_planning import (
    ModelPortfolioResourcePreflight,
    ModelPortfolioTaskKind,
    ModelPortfolioTaskResourceEnvelope,
    build_model_portfolio_resource_preflight,
)
from mmaudit.models.prepurchase_quote import (
    AcceptedPrepurchaseQuote,
    PrepurchaseQuote,
    PrepurchaseQuoteInconclusiveReason,
    PrepurchaseQuoteLocalAnalysisCeiling,
    PrepurchaseQuoteReconciliationStatus,
    PrepurchaseQuoteRuntimeRoleKind,
    PrepurchaseQuoteTaskCeiling,
    PrepurchaseQuoteTaskClass,
    accept_prepurchase_quote,
    build_prepurchase_quote,
    reconcile_prepurchase_quote,
)
from mmaudit.models.scheduler import (
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.sharding import SolidityShardInventory
from mmaudit.orchestration.budgets import EndpointRequestCostBound
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostReservationOverrunError,
)
from mmaudit.orchestration.scheduler_runtime import build_scheduler_cost_ledger_baseline
from mmaudit.reporting.bundle import build_run_cost_ledger_evidence
from tests.unit.test_coverage_planning import _single_task_plan
from tests.unit.test_forensic_cost_ledger import _usage
from tests.unit.test_semantic_sharding import _inventory, _shard_inputs

_MODEL = "synthetic/model"
_ACCEPTED_AT = datetime(2026, 8, 28, 1, 0, tzinfo=UTC)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _QuoteFixture:
    ledger: AtomicCostLedger
    manifest: SchedulerCampaignManifest
    inventory: SolidityShardInventory
    preflight: ModelPortfolioResourcePreflight
    local_analysis: PrepurchaseQuoteLocalAnalysisCeiling
    retry_policy: ModelRetryPolicy
    ceilings: tuple[PrepurchaseQuoteTaskCeiling, ...]
    quote: PrepurchaseQuote
    acceptance: AcceptedPrepurchaseQuote


def _scheduler_manifest(
    inventory: SolidityShardInventory,
    ledger: AtomicCostLedger,
    *,
    seed: str,
) -> SchedulerCampaignManifest:
    source_by_shard = {item.primary_shard_id: item for item in inventory.source_units}
    semantic_by_id = {item.shard_id: item for item in inventory.shards}
    descriptors = tuple(
        SchedulerShardDescriptor.semantic(
            shard_id=shard_id,
            semantic_shard_sha256=semantic_by_id[shard_id].shard_sha256,
            sources=(
                SchedulerSourceDescriptor.build(
                    path=source_by_shard[shard_id].path,
                    sha256=source_by_shard[shard_id].content_sha256,
                    size=source_by_shard[shard_id].utf8_bytes,
                ),
            ),
        )
        for shard_id in sorted(semantic_by_id)
    )
    scheduler_inventory = SchedulerShardInventory.build(
        semantic_inventory_sha256=inventory.inventory_sha256,
        shards=descriptors,
    )
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    bindings = SchedulerBindings.build(
        source_sha256=scheduler_inventory.source_tree_sha256,
        analysis_input_sha256=_sha256(f"{seed}:analysis"),
        effective_config_sha256=_sha256(f"{seed}:config"),
        shard_inventory_sha256=scheduler_inventory.inventory_sha256,
        model_selection_sha256=_sha256(f"{seed}:models"),
        qualification_sha256=_sha256(f"{seed}:qualification"),
        prompt_set_sha256=_sha256(f"{seed}:prompts"),
        schema_set_sha256=_sha256(f"{seed}:schemas"),
        tool_policy_sha256=_sha256(f"{seed}:tools"),
        cost_ledger_baseline_sha256=baseline.baseline_sha256,
    )
    return SchedulerCampaignManifest.build(
        bindings=bindings,
        shard_inventory=scheduler_inventory,
        cost_ledger_baseline=baseline,
    )


def _portfolio_preflight(
    manifest: SchedulerCampaignManifest,
    *,
    maximum_attempts: int = 2,
) -> ModelPortfolioResourcePreflight:
    plan = _single_task_plan()
    task = plan.tasks[0]
    request_id = "scheduler-request-" + "1" * 64
    endpoint_bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=task.requested_model,
        provider_endpoint="synthetic-provider",
        request_material="synthetic quote fixture",
        pricing={"completion": "0", "prompt": "0", "request": "0.1"},
        maximum_units={"completion": 50, "prompt": 100, "request": 1},
    )
    envelope = ModelPortfolioTaskResourceEnvelope.build(
        task_kind=ModelPortfolioTaskKind.COMPACT_COVERAGE,
        scheduler_task_id="scheduler-task-" + "2" * 64,
        scheduler_task_plan_sha256="3" * 64,
        scheduler_logical_request_id=request_id,
        campaign_manifest_sha256=manifest.manifest_sha256,
        request_role=task.review_role,
        requested_model=task.requested_model,
        request_envelope_recipe_sha256="4" * 64,
        endpoint_policy_snapshot_sha256="5" * 64,
        endpoint_policy_pricing_sha256="6" * 64,
        provider_endpoint="synthetic-provider",
        endpoint_pricing_snapshot_sha256=endpoint_bound.pricing_snapshot_sha256,
        maximum_attempts=maximum_attempts,
        attempt_request_ids=tuple(
            request_id if ordinal == 1 else f"{request_id}:attempt:{ordinal}"
            for ordinal in range(1, maximum_attempts + 1)
        ),
        maximum_prompt_tokens_per_attempt=100,
        maximum_visible_output_tokens_per_attempt=30,
        maximum_reasoning_tokens_per_attempt=20,
        maximum_completion_tokens_per_attempt=50,
        maximum_cost_usd_per_attempt_exact="0.1",
        coverage_task=task,
    )
    return build_model_portfolio_resource_preflight(
        plan,
        (envelope,),
        campaign_manifest_sha256=manifest.manifest_sha256,
        maximum_requests_per_task=maximum_attempts,
        maximum_input_tokens=100 * maximum_attempts,
        maximum_output_tokens=50 * maximum_attempts,
        maximum_cost_usd_exact="1",
    )


def _task_ceilings(
    preflight: ModelPortfolioResourcePreflight,
    *,
    disabled: frozenset[PrepurchaseQuoteTaskClass] = frozenset(),
) -> tuple[PrepurchaseQuoteTaskCeiling, ...]:
    envelope = preflight.task_envelopes[0]
    ceilings: list[PrepurchaseQuoteTaskCeiling] = []
    for index, task_class in enumerate(PrepurchaseQuoteTaskClass, start=1):
        if task_class in disabled:
            ceilings.append(
                PrepurchaseQuoteTaskCeiling.build(
                    task_class=task_class,
                    request_role=None,
                    requested_model=None,
                    request_envelope_recipe_sha256=None,
                    endpoint_policy_snapshot_sha256=None,
                    endpoint_policy_pricing_sha256=None,
                    provider_endpoint=None,
                    endpoint_pricing_snapshot_sha256=None,
                    standard_task_count=0,
                    maximum_task_count=0,
                    standard_attempts_per_task=1,
                    maximum_attempts_per_task=1,
                    maximum_input_tokens_per_attempt=0,
                    maximum_output_tokens_per_attempt=0,
                    maximum_cost_usd_per_attempt_exact="0",
                    standard_wall_clock_seconds_per_task=0,
                    maximum_wall_clock_seconds_per_task=0,
                )
            )
            continue
        compact = task_class is PrepurchaseQuoteTaskClass.COMPACT_COVERAGE
        request_role = (
            envelope.request_role
            if compact
            else (
                "candidate_falsifier"
                if task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
                else task_class.value
            )
        )
        requested_model = envelope.requested_model if compact else _MODEL
        endpoint_pricing_sha256 = EndpointRequestCostBound.from_endpoint_pricing(
            exact_model_id=requested_model,
            provider_endpoint="synthetic-provider",
            request_material=f"synthetic quote fixture {task_class.value}",
            pricing={"completion": "0", "prompt": "0", "request": "0.1"},
            maximum_units={"completion": 50, "prompt": 100, "request": 1},
        ).pricing_snapshot_sha256
        ceilings.append(
            PrepurchaseQuoteTaskCeiling.build(
                task_class=task_class,
                request_role=request_role,
                requested_model=requested_model,
                request_envelope_recipe_sha256=(
                    envelope.request_envelope_recipe_sha256 if compact else f"{index + 20:064x}"
                ),
                endpoint_policy_snapshot_sha256=(
                    envelope.endpoint_policy_snapshot_sha256 if compact else f"{index + 40:064x}"
                ),
                endpoint_policy_pricing_sha256=(
                    envelope.endpoint_policy_pricing_sha256 if compact else f"{index + 60:064x}"
                ),
                provider_endpoint=(envelope.provider_endpoint if compact else "synthetic-provider"),
                endpoint_pricing_snapshot_sha256=(
                    envelope.endpoint_pricing_snapshot_sha256
                    if compact
                    else endpoint_pricing_sha256
                ),
                standard_task_count=1,
                maximum_task_count=2,
                standard_attempts_per_task=1,
                maximum_attempts_per_task=envelope.maximum_attempts,
                maximum_input_tokens_per_attempt=100,
                maximum_output_tokens_per_attempt=50,
                maximum_cost_usd_per_attempt_exact="0.1",
                standard_wall_clock_seconds_per_task=10,
                maximum_wall_clock_seconds_per_task=30,
            )
        )
    return tuple(ceilings)


def _quote_fixture(
    tmp_path: Path,
    config_factory: Callable[..., Any],
    *,
    seed: str = "prepurchase-quote",
    cap_usd: str = "100",
    baseline_spent_usd_exact: str = "0",
    disabled: frozenset[PrepurchaseQuoteTaskClass] = frozenset(),
    transient_retry_limit: int = 1,
    schema_validation_retry_limit: int = 0,
) -> _QuoteFixture:
    inventory = _inventory(_shard_inputs(tmp_path, config_factory))
    ledger = AtomicCostLedger.initialize(
        tmp_path / f"{seed}-ledger.json",
        cap_usd=Decimal(cap_usd),
    )
    if Decimal(baseline_spent_usd_exact) > 0:
        prior = ledger.reserve(
            f"{seed}:prior-cost",
            Decimal(baseline_spent_usd_exact),
        )
        ledger.reconcile(prior, Decimal(baseline_spent_usd_exact))
    manifest = _scheduler_manifest(inventory, ledger, seed=seed)
    retry_policy = ModelRetryPolicy.build(
        transient_retry_limit=transient_retry_limit,
        schema_validation_retry_limit=schema_validation_retry_limit,
    )
    preflight = _portfolio_preflight(
        manifest,
        maximum_attempts=retry_policy.maximum_attempts,
    )
    local_analysis = PrepurchaseQuoteLocalAnalysisCeiling.build(
        analysis_input_sha256=manifest.bindings.analysis_input_sha256,
        execution_limits_sha256=_sha256(f"{seed}:local-execution-limits"),
        standard_wall_clock_seconds=60,
        maximum_wall_clock_seconds=120,
    )
    ceilings = _task_ceilings(preflight, disabled=disabled)
    quote = build_prepurchase_quote(
        campaign_manifest=manifest,
        solidity_shard_inventory=inventory,
        portfolio_preflight=preflight,
        local_analysis_ceiling=local_analysis,
        retry_policy=retry_policy,
        task_ceilings=ceilings,
    )
    acceptance = accept_prepurchase_quote(quote, accepted_at=_ACCEPTED_AT)
    return _QuoteFixture(
        ledger=ledger,
        manifest=manifest,
        inventory=inventory,
        preflight=preflight,
        local_analysis=local_analysis,
        retry_policy=retry_policy,
        ceilings=ceilings,
        quote=quote,
        acceptance=acceptance,
    )


def _accepted_quote(
    tmp_path: Path,
    config_factory: Callable[..., Any],
    *,
    seed: str = "accepted-prepurchase-quote",
) -> AcceptedPrepurchaseQuote:
    """Compact shared budget-test fixture with a real, fully joined quote."""

    return _quote_fixture(tmp_path, config_factory, seed=seed).acceptance


def test_quote_is_deterministic_complete_bounded_and_nonauthorizing(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory)
    repeated = build_prepurchase_quote(
        campaign_manifest=fixture.manifest,
        solidity_shard_inventory=fixture.inventory,
        portfolio_preflight=fixture.preflight,
        local_analysis_ceiling=fixture.local_analysis,
        retry_policy=fixture.retry_policy,
        task_ceilings=reversed(fixture.ceilings),
    )

    assert repeated == fixture.quote
    assert PrepurchaseQuote.model_validate_json(fixture.quote.model_dump_json()) == fixture.quote
    assert (
        AcceptedPrepurchaseQuote.model_validate_json(fixture.acceptance.model_dump_json())
        == fixture.acceptance
    )
    assert fixture.quote.covered_task_classes == tuple(PrepurchaseQuoteTaskClass)
    assert fixture.quote.cost_range.lower_bound_usd_exact == "0"
    assert Decimal(fixture.quote.cost_range.standard_bound_usd_exact) <= Decimal(
        fixture.quote.cost_range.worst_case_usd_exact
    )
    assert fixture.quote.wall_clock_range.standard_local_seconds == 60
    assert fixture.quote.wall_clock_range.maximum_local_seconds == 120
    assert fixture.quote.wall_clock_range.worst_case_seconds > 120
    assert not fixture.quote.completion_within_hard_ceiling_guaranteed
    assert not fixture.quote.authorizes_dispatch
    assert not fixture.acceptance.authorizes_dispatch
    assert fixture.acceptance.run_hard_ceiling_usd_exact == (
        fixture.quote.cost_range.worst_case_usd_exact
    )


def test_quote_hash_binds_equal_total_split_retry_policy(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed="split-retry-policy")
    swapped_policy = ModelRetryPolicy.build(
        transient_retry_limit=0,
        schema_validation_retry_limit=1,
    )
    changed = build_prepurchase_quote(
        campaign_manifest=fixture.manifest,
        solidity_shard_inventory=fixture.inventory,
        portfolio_preflight=fixture.preflight,
        local_analysis_ceiling=fixture.local_analysis,
        retry_policy=swapped_policy,
        task_ceilings=fixture.ceilings,
    )

    assert fixture.retry_policy.maximum_attempts == swapped_policy.maximum_attempts == 2
    assert fixture.quote.retry_policy == fixture.retry_policy
    assert fixture.quote.retry_policy.transient_retry_scope == "NETWORK_OR_STATUS"
    assert fixture.quote.retry_policy.schema_retry_failure_code == "SCHEMA_VALIDATION_FAILED"
    assert fixture.quote.retry_policy.schema_retry_route == "SAME_ROUTE"
    assert fixture.quote.retry_policy.exhaustion_disposition == (
        "EXPLICIT_FALLBACK_OR_TERMINATE"
    )
    assert changed.retry_policy == swapped_policy
    assert changed.retry_policy.policy_sha256 != fixture.quote.retry_policy.policy_sha256
    assert changed.quote_sha256 != fixture.quote.quote_sha256


def test_quote_caps_spend_at_remaining_ledger_and_disclaims_completion(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(
        tmp_path,
        config_factory,
        seed="hard-cap",
        cap_usd="1",
    )

    assert Decimal(fixture.quote.unconstrained_workflow_worst_usd_exact) > Decimal("1")
    assert fixture.quote.cost_range.worst_case_usd_exact == "1"
    assert fixture.quote.cost_range.standard_bound_usd_exact == "1"
    assert fixture.quote.hard_budget_limited
    assert not fixture.quote.completion_within_hard_ceiling_guaranteed
    assert fixture.acceptance.run_hard_ceiling_usd_exact == "1"


def test_quote_hard_ceiling_is_incremental_from_exact_baseline(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(
        tmp_path,
        config_factory,
        seed="incremental-hard-cap",
        cap_usd="5",
        baseline_spent_usd_exact="2",
    )

    assert fixture.quote.ledger_baseline.cap_usd_exact == "5"
    assert fixture.quote.ledger_baseline.spent_usd_exact == "2"
    assert fixture.quote.ledger_baseline.remaining_usd_exact == "3"
    assert fixture.quote.cost_range.worst_case_usd_exact == "3"
    assert fixture.acceptance.run_hard_ceiling_usd_exact == "3"


def test_quote_requires_every_class_and_exact_early_route(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed="coverage-refusal")
    incomplete = tuple(
        item
        for item in fixture.ceilings
        if item.task_class is not PrepurchaseQuoteTaskClass.TRUNCATION_RECOVERY
    )
    with pytest.raises(ValueError, match="every paid task class"):
        build_prepurchase_quote(
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
            local_analysis_ceiling=fixture.local_analysis,
            retry_policy=fixture.retry_policy,
            task_ceilings=incomplete,
        )

    compact = next(
        item
        for item in fixture.ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.COMPACT_COVERAGE
    )
    changed = PrepurchaseQuoteTaskCeiling.build(
        **{
            **compact.model_dump(
                mode="python",
                exclude={
                    "artifact_kind",
                    "schema_version",
                    "runtime_role_kind",
                    "maximum_distinct_runtime_roles",
                    "standard_request_count",
                    "worst_case_request_count",
                    "standard_cost_usd_exact",
                    "worst_case_cost_usd_exact",
                    "standard_wall_clock_seconds",
                    "worst_case_wall_clock_seconds",
                    "ceiling_sha256",
                    "authorizes_dispatch",
                    "grants_review_credit",
                    "grants_completion_credit",
                    "grants_release_authority",
                },
            ),
            "endpoint_pricing_snapshot_sha256": "f" * 64,
        }
    )
    mismatched = tuple(changed if item is compact else item for item in fixture.ceilings)
    with pytest.raises(ValueError, match="omit an exact early portfolio route"):
        build_prepurchase_quote(
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
            local_analysis_ceiling=fixture.local_analysis,
            retry_policy=fixture.retry_policy,
            task_ceilings=mismatched,
        )


def test_disabled_optional_class_has_no_fake_route_or_role(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(
        tmp_path,
        config_factory,
        seed="disabled-optional",
        disabled=frozenset(
            {
                PrepurchaseQuoteTaskClass.INVARIANT_REVIEW,
                PrepurchaseQuoteTaskClass.REPORT_QUALITY,
            }
        ),
    )
    disabled = tuple(item for item in fixture.ceilings if item.maximum_task_count == 0)

    assert len(disabled) == 2
    assert all(item.request_role is None and item.requested_model is None for item in disabled)
    assert all(item.worst_case_cost_usd_exact == "0" for item in disabled)
    exact_roles = {
        item.request_role
        for item in fixture.ceilings
        if item.runtime_role_kind is PrepurchaseQuoteRuntimeRoleKind.EXACT
        and item.request_role is not None
    }
    dynamic_role_count = sum(
        item.maximum_distinct_runtime_roles
        for item in fixture.ceilings
        if item.task_class is not PrepurchaseQuoteTaskClass.TRUNCATION_RECOVERY
        and item.runtime_role_kind
        is PrepurchaseQuoteRuntimeRoleKind.CANDIDATE_FALSIFIER_SHA256_REVIEWER
    )
    assert fixture.quote.planned_role_count == len(exact_roles) + dynamic_role_count


def test_task_ceiling_rejects_inexact_counts_and_noncanonical_money() -> None:
    kwargs: dict[str, object] = {
        "task_class": PrepurchaseQuoteTaskClass.ORIENTATION,
        "request_role": "orientation",
        "requested_model": _MODEL,
        "request_envelope_recipe_sha256": "1" * 64,
        "endpoint_policy_snapshot_sha256": "2" * 64,
        "endpoint_policy_pricing_sha256": "3" * 64,
        "provider_endpoint": "synthetic-provider",
        "endpoint_pricing_snapshot_sha256": "4" * 64,
        "standard_task_count": 1,
        "maximum_task_count": 1,
        "standard_attempts_per_task": 1,
        "maximum_attempts_per_task": 1,
        "maximum_input_tokens_per_attempt": 1,
        "maximum_output_tokens_per_attempt": 1,
        "maximum_cost_usd_per_attempt_exact": "0.1",
        "standard_wall_clock_seconds_per_task": 1,
        "maximum_wall_clock_seconds_per_task": 1,
    }
    with pytest.raises(ValueError, match="exact integers"):
        PrepurchaseQuoteTaskCeiling.build(**{**kwargs, "maximum_task_count": True})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="redundant notation"):
        PrepurchaseQuoteTaskCeiling.build(
            **{**kwargs, "maximum_cost_usd_per_attempt_exact": "0.10"}  # type: ignore[arg-type]
        )


def test_reconciliation_records_exact_actual_and_deltas(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed="reconciled")
    baseline = fixture.manifest.cost_ledger_baseline
    assert baseline is not None
    request_id = fixture.preflight.task_envelopes[0].scheduler_logical_request_id
    reservation = fixture.ledger.reserve(request_id, Decimal("0.2"))
    fixture.ledger.reconcile(reservation, Decimal("0.1"))
    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=fixture.ledger.snapshot(),
        campaign_logical_request_ids=(request_id,),
        usage_records=(_usage(cost="0.1", request_id=request_id),),
        campaign_id=fixture.manifest.campaign_id,
        campaign_manifest_sha256=fixture.manifest.manifest_sha256,
    )

    reconciliation = reconcile_prepurchase_quote(
        fixture.acceptance,
        evidence,
        reconciled_at=_ACCEPTED_AT + timedelta(hours=1),
    )

    assert reconciliation.status is PrepurchaseQuoteReconciliationStatus.CONCLUSIVE
    assert reconciliation.actual_cost_usd_exact == "0.1"
    assert reconciliation.standard_delta_usd_exact is not None
    assert reconciliation.worst_case_delta_usd_exact is not None
    assert reconciliation.within_worst_case
    assert reconciliation.ledger_evidence() == evidence
    assert not reconciliation.authorizes_dispatch


@pytest.mark.parametrize("accounting", ["uncertain", "overrun"])
def test_uncertain_or_overrun_reconciliation_never_claims_actuals(
    accounting: str,
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed=f"inconclusive-{accounting}")
    baseline = fixture.manifest.cost_ledger_baseline
    assert baseline is not None
    request_id = fixture.preflight.task_envelopes[0].scheduler_logical_request_id
    reservation = fixture.ledger.reserve(request_id, Decimal("0.1"))
    usage: tuple[UsageRecord, ...] = ()
    if accounting == "uncertain":
        fixture.ledger.reconcile(reservation, None)
        expected_reason = PrepurchaseQuoteInconclusiveReason.UNCERTAIN_ACCOUNTING
    else:
        with pytest.raises(CostReservationOverrunError):
            fixture.ledger.reconcile(reservation, Decimal("0.2"))
        usage = (_usage(cost="0.2", request_id=request_id),)
        expected_reason = PrepurchaseQuoteInconclusiveReason.RESERVATION_OVERRUN
    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=fixture.ledger.snapshot(),
        campaign_logical_request_ids=(request_id,),
        usage_records=usage,
        campaign_id=fixture.manifest.campaign_id,
        campaign_manifest_sha256=fixture.manifest.manifest_sha256,
    )

    reconciliation = reconcile_prepurchase_quote(
        fixture.acceptance,
        evidence,
        reconciled_at=_ACCEPTED_AT + timedelta(hours=1),
    )

    assert reconciliation.status is PrepurchaseQuoteReconciliationStatus.INCONCLUSIVE
    assert reconciliation.inconclusive_reason is expected_reason
    assert reconciliation.actual_cost_usd_exact is None
    assert reconciliation.standard_delta_usd_exact is None
    assert reconciliation.worst_case_delta_usd_exact is None
    assert reconciliation.within_worst_case is None


def test_acceptance_rejects_rehashed_ceiling_tamper(
    tmp_path: Path,
    config_factory: Callable[..., Any],
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed="acceptance-tamper")
    payload = fixture.acceptance.model_dump(mode="python")
    payload["run_hard_ceiling_usd_exact"] = "0"

    with pytest.raises(ValidationError, match="exact hard spend ceiling"):
        AcceptedPrepurchaseQuote.model_validate(payload)
