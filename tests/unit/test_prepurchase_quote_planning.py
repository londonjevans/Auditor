from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.config import (
    AuditConfig,
    RepositoryCleanForkMatrixStateConfig,
    RepositoryForkSuiteConfig,
    RepositoryPinnedForkMatrixStateConfig,
    configured_model_ids,
)
from mmaudit.models.coverage_planning import ModelPortfolioResourcePreflight
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.prepurchase_quote import (
    AcceptedPrepurchaseQuote,
    PrepurchaseQuote,
    PrepurchaseQuoteRuntimeRoleKind,
    PrepurchaseQuoteTaskCeiling,
    PrepurchaseQuoteTaskClass,
    accept_prepurchase_quote,
    build_prepurchase_quote,
)
from mmaudit.models.scheduler import (
    SchedulerBindings,
    SchedulerCampaignManifest,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
)
from mmaudit.models.sharding import SolidityShardInventory
from mmaudit.models.truncation_recovery import TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.prepurchase_quote import (
    PrepurchaseQuotePlanningError,
    build_prepurchase_quote_from_frozen_inputs,
    build_quote_local_analysis_ceiling,
    validate_accepted_prepurchase_quote_for_run,
)
from mmaudit.orchestration.scheduler_runtime import build_scheduler_cost_ledger_baseline
from mmaudit.scanners.fork_matrix import repository_fork_matrix_timeout_budget_seconds
from tests.scheduler_support import build_scheduler_test_audit_model_selection_binding
from tests.unit.test_candidate_benchmark import _CandidateSpec, _discovery_and_registry
from tests.unit.test_prepurchase_quote import _portfolio_preflight
from tests.unit.test_semantic_sharding import _inventory, _shard_inputs


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _scheduler_manifest(
    inventory: SolidityShardInventory,
    ledger: AtomicCostLedger,
    config: AuditConfig,
    *,
    seed: str,
    bind_audit_selection: bool = False,
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
    audit_selection = (
        build_scheduler_test_audit_model_selection_binding(
            source_sha256=scheduler_inventory.source_tree_sha256,
            selected_routes=tuple(
                (
                    model_id,
                    f"sha256:{_sha256(f'{seed}:lineage:{model_id}')}",
                    "Synthetic Provider",
                    "synthetic-provider",
                )
                for model_id in configured_model_ids(config, include_fallbacks=True)
            ),
            seed=f"{seed}:audit-selection",
        )
        if bind_audit_selection
        else None
    )
    bindings = SchedulerBindings.build(
        source_sha256=scheduler_inventory.source_tree_sha256,
        analysis_input_sha256=_sha256(f"{seed}:analysis"),
        effective_config_sha256=config.stable_hash(),
        shard_inventory_sha256=scheduler_inventory.inventory_sha256,
        model_selection_sha256=_sha256(f"{seed}:models"),
        qualification_sha256=_sha256(f"{seed}:qualification"),
        prompt_set_sha256=_sha256(f"{seed}:prompts"),
        schema_set_sha256=_sha256(f"{seed}:schemas"),
        tool_policy_sha256=_sha256(f"{seed}:tools"),
        cost_ledger_baseline_sha256=baseline.baseline_sha256,
        audit_model_selection=audit_selection,
    )
    return SchedulerCampaignManifest.build(
        bindings=bindings,
        shard_inventory=scheduler_inventory,
        cost_ledger_baseline=baseline,
    )


@dataclass(frozen=True)
class _PlanningFixture:
    config: AuditConfig
    inventory: SolidityShardInventory
    ledger: AtomicCostLedger
    manifest: SchedulerCampaignManifest
    preflight: ModelPortfolioResourcePreflight
    discovery_manifest: OpenRouterModelDiscoveryRunManifest
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...]
    quote: PrepurchaseQuote
    acceptance: AcceptedPrepurchaseQuote


def _planning_fixture(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> _PlanningFixture:
    config = config_factory(
        execution={
            "max_model_retries": 1,
            "max_requests_per_agent": 64,
            "max_candidates_per_run": 50,
        },
        models={"reasoning": {"effort": "high", "reserved_tokens": 512}},
    )
    inventory = _inventory(_shard_inputs(tmp_path / "target", config_factory))
    ledger = AtomicCostLedger.initialize(
        tmp_path / "quote-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    manifest = _scheduler_manifest(inventory, ledger, config, seed="quote-planning")
    preflight = _portfolio_preflight(manifest)
    specifications = tuple(
        _CandidateSpec(
            model_id=model_id,
            provider_endpoint="synthetic-provider",
            provider_name="Synthetic Provider",
            native_structured_output_parameter="json_schema",
        )
        for model_id in configured_model_ids(config, include_fallbacks=True)
    )
    discovery_manifest, discovery_evidence, _registry = _discovery_and_registry(
        tmp_path=tmp_path / "discovery",
        config=config,
        specs=specifications,
    )
    quote = build_prepurchase_quote_from_frozen_inputs(
        config,
        campaign_manifest=manifest,
        solidity_shard_inventory=inventory,
        portfolio_preflight=preflight,
        discovery_manifest=discovery_manifest,
        discovery_evidence=discovery_evidence,
    )
    acceptance = accept_prepurchase_quote(
        quote,
        accepted_at=discovery_manifest.run_provenance.retrieved_at,
    )
    return _PlanningFixture(
        config=config,
        inventory=inventory,
        ledger=ledger,
        manifest=manifest,
        preflight=preflight,
        discovery_manifest=discovery_manifest,
        discovery_evidence=discovery_evidence,
        quote=quote,
        acceptance=acceptance,
    )


@pytest.fixture
def planning_fixture(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> _PlanningFixture:
    return _planning_fixture(tmp_path, config_factory)


def _rebuild_ceiling(
    ceiling: PrepurchaseQuoteTaskCeiling,
    **updates: object,
) -> PrepurchaseQuoteTaskCeiling:
    values = ceiling.model_dump(
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
    )
    return PrepurchaseQuoteTaskCeiling.build(**{**values, **updates})


def test_provider_free_quote_is_stable_and_bounds_all_paid_and_local_work(
    planning_fixture: _PlanningFixture,
) -> None:
    fixture = planning_fixture
    repeated = build_prepurchase_quote_from_frozen_inputs(
        fixture.config,
        campaign_manifest=fixture.manifest,
        solidity_shard_inventory=fixture.inventory,
        portfolio_preflight=fixture.preflight,
        discovery_manifest=fixture.discovery_manifest,
        discovery_evidence=tuple(reversed(fixture.discovery_evidence)),
    )

    assert repeated == fixture.quote
    assert fixture.quote.covered_task_classes == tuple(PrepurchaseQuoteTaskClass)
    assert {item.task_class for item in fixture.quote.task_ceilings} == set(
        PrepurchaseQuoteTaskClass
    )
    cross_examinations = tuple(
        item
        for item in fixture.quote.task_ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
    )
    assert len(cross_examinations) == 2
    assert all(
        item.maximum_task_count == fixture.config.execution.max_candidates_per_run
        for item in cross_examinations
    )
    assert all(item.request_role == "candidate_falsifier" for item in cross_examinations)
    assert all(
        item.runtime_role_kind
        is PrepurchaseQuoteRuntimeRoleKind.CANDIDATE_FALSIFIER_SHA256_REVIEWER
        and item.maximum_distinct_runtime_roles == item.maximum_task_count
        for item in cross_examinations
    )
    later = tuple(
        item
        for item in fixture.quote.task_ceilings
        if item.task_class
        in {
            PrepurchaseQuoteTaskClass.CROSS_SHARD_INTEGRATION,
            PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION,
            PrepurchaseQuoteTaskClass.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
            PrepurchaseQuoteTaskClass.EVIDENCE_CAPPED_JUDGMENT,
        }
        and item.maximum_task_count
    )
    assert later
    assert all(
        item.maximum_attempts_per_task == fixture.config.execution.maximum_model_attempts
        for item in later
    )
    assert all(
        item.maximum_input_tokens_per_attempt == fixture.config.execution.max_request_bytes
        for item in later
    )
    assert any(
        item.maximum_output_tokens_per_attempt
        == fixture.config.effective_reserved_output_tokens + 512
        for item in later
    )
    assert all(
        Decimal(item.maximum_cost_usd_per_attempt_exact) >= Decimal("4.00512") for item in later
    )
    recovery = tuple(
        item
        for item in fixture.quote.task_ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.TRUNCATION_RECOVERY
    )
    assert len(recovery) == 1
    assert recovery[0].maximum_task_count == TRUNCATION_RECOVERY_MAX_CHILD_REQUESTS
    assert recovery[0].maximum_attempts_per_task == 1
    assert fixture.quote.local_analysis_ceiling.maximum_wall_clock_seconds >= (
        fixture.quote.local_analysis_ceiling.standard_wall_clock_seconds
    )


def test_quote_refuses_missing_pricing_and_oversized_ledger_cap(
    planning_fixture: _PlanningFixture,
    tmp_path: Path,
) -> None:
    fixture = planning_fixture
    with pytest.raises(PrepurchaseQuotePlanningError, match="evidence differs"):
        build_prepurchase_quote_from_frozen_inputs(
            fixture.config,
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
            discovery_manifest=fixture.discovery_manifest,
            discovery_evidence=fixture.discovery_evidence[:-1],
        )

    oversized = AtomicCostLedger.initialize(
        tmp_path / "oversized-ledger.json",
        cap_usd=Decimal("21"),
    )
    oversized_manifest = _scheduler_manifest(
        fixture.inventory,
        oversized,
        fixture.config,
        seed="oversized-ledger",
    )
    with pytest.raises(PrepurchaseQuotePlanningError, match="configured execution budget"):
        build_prepurchase_quote_from_frozen_inputs(
            fixture.config,
            campaign_manifest=oversized_manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=_portfolio_preflight(oversized_manifest),
            discovery_manifest=fixture.discovery_manifest,
            discovery_evidence=fixture.discovery_evidence,
        )


def test_quote_refuses_config_manifest_drift_and_stale_target(
    planning_fixture: _PlanningFixture,
    config_factory: Callable[..., AuditConfig],
) -> None:
    fixture = planning_fixture
    changed_config = config_factory(
        execution={
            "max_model_retries": 1,
            "max_requests_per_agent": 64,
            "max_candidates_per_run": 49,
        },
        models={"reasoning": {"effort": "high", "reserved_tokens": 512}},
    )
    with pytest.raises(PrepurchaseQuotePlanningError, match="effective-config binding"):
        build_prepurchase_quote_from_frozen_inputs(
            changed_config,
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
            discovery_manifest=fixture.discovery_manifest,
            discovery_evidence=fixture.discovery_evidence,
        )

    with pytest.raises(PrepurchaseQuotePlanningError, match="lacks a scheduler selection"):
        validate_accepted_prepurchase_quote_for_run(
            fixture.config,
            acceptance=fixture.acceptance,
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
            selected_model_ids=frozenset({fixture.config.models.judge.primary}),
        )

    changed_manifest = _scheduler_manifest(
        fixture.inventory,
        fixture.ledger,
        fixture.config,
        seed="changed-target",
    )
    with pytest.raises(PrepurchaseQuotePlanningError, match="stale for the current target"):
        validate_accepted_prepurchase_quote_for_run(
            fixture.config,
            acceptance=fixture.acceptance,
            campaign_manifest=changed_manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=_portfolio_preflight(changed_manifest),
        )


def test_quote_persists_and_cross_checks_scheduler_selected_model_set(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    fixture = _planning_fixture(tmp_path, config_factory)
    selected_manifest = _scheduler_manifest(
        fixture.inventory,
        fixture.ledger,
        fixture.config,
        seed="selected-model-binding",
        bind_audit_selection=True,
    )
    selection = selected_manifest.bindings.audit_model_selection
    assert selection is not None
    preflight = _portfolio_preflight(selected_manifest)
    quote = build_prepurchase_quote_from_frozen_inputs(
        fixture.config,
        campaign_manifest=selected_manifest,
        solidity_shard_inventory=fixture.inventory,
        portfolio_preflight=preflight,
        discovery_manifest=fixture.discovery_manifest,
        discovery_evidence=fixture.discovery_evidence,
        selected_model_ids=frozenset(selection.selected_model_ids),
    )

    assert quote.target_binding.audit_selected_model_set_sha256 == (
        selection.selected_model_set_sha256
    )
    acceptance = accept_prepurchase_quote(
        quote,
        accepted_at=fixture.acceptance.accepted_at,
    )
    with pytest.raises(PrepurchaseQuotePlanningError, match="differs from the scheduler"):
        validate_accepted_prepurchase_quote_for_run(
            fixture.config,
            acceptance=acceptance,
            campaign_manifest=selected_manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=preflight,
            selected_model_ids=frozenset({fixture.config.models.judge.primary}),
        )


def test_accepted_quote_rederives_current_candidate_and_route_ceilings(
    planning_fixture: _PlanningFixture,
) -> None:
    fixture = planning_fixture
    assert (
        validate_accepted_prepurchase_quote_for_run(
            fixture.config,
            acceptance=fixture.acceptance,
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
        )
        == fixture.quote
    )
    selected = next(
        item
        for item in fixture.quote.task_ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
    )
    assert selected.standard_task_count < selected.maximum_task_count
    lowered = _rebuild_ceiling(
        selected,
        maximum_task_count=selected.maximum_task_count - 1,
    )
    changed_ceilings = tuple(
        lowered if item == selected else item for item in fixture.quote.task_ceilings
    )
    changed_quote = build_prepurchase_quote(
        campaign_manifest=fixture.manifest,
        solidity_shard_inventory=fixture.inventory,
        portfolio_preflight=fixture.preflight,
        local_analysis_ceiling=fixture.quote.local_analysis_ceiling,
        retry_policy=fixture.quote.retry_policy,
        task_ceilings=changed_ceilings,
    )
    changed_acceptance = accept_prepurchase_quote(
        changed_quote,
        accepted_at=fixture.acceptance.accepted_at,
    )

    with pytest.raises(PrepurchaseQuotePlanningError, match="understates or changes"):
        validate_accepted_prepurchase_quote_for_run(
            fixture.config,
            acceptance=changed_acceptance,
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
        )


def test_accepted_quote_rejects_equal_total_split_retry_policy_drift(
    planning_fixture: _PlanningFixture,
) -> None:
    fixture = planning_fixture
    execution = type(fixture.config.execution).model_validate(
        {
            **fixture.config.execution.model_dump(mode="python"),
            "max_model_retries": 0,
            "max_schema_validation_retries": 1,
        }
    )
    changed_config = fixture.config.model_copy(update={"execution": execution})

    assert fixture.config.execution.maximum_model_attempts == execution.maximum_model_attempts == 2
    assert (
        fixture.config.execution.model_retry_policy.policy_sha256
        != execution.model_retry_policy.policy_sha256
    )
    with pytest.raises(PrepurchaseQuotePlanningError, match="quote config differs"):
        validate_accepted_prepurchase_quote_for_run(
            changed_config,
            acceptance=fixture.acceptance,
            campaign_manifest=fixture.manifest,
            solidity_shard_inventory=fixture.inventory,
            portfolio_preflight=fixture.preflight,
        )


def test_local_ceiling_multiplies_project_harness_formal_and_matrix_limits(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    clean = RepositoryCleanForkMatrixStateConfig(
        state_id="clean-local",
        expected_chain_id=31_337,
        anvil_version="anvil Version: 1.3.2-stable",
        anvil_sha256="a" * 64,
        hardfork="cancun",
        genesis_timestamp=1,
        startup_timeout_seconds=1,
        shutdown_timeout_seconds=1,
    )
    pinned = RepositoryPinnedForkMatrixStateConfig(
        state_id="pinned-local",
        rpc_url_env="MMAUDIT_PINNED_LOCAL_RPC_URL",
        expected_chain_id=31_338,
        pinned_block_number=42,
        state_source_sha256="b" * 64,
    )
    suite = RepositoryForkSuiteConfig(
        profile="explicit",
        foundry_include_paths=("test/*.t.sol",),
        foundry_include_tests=("test*",),
        hardhat_include_paths=(),
        hardhat_include_tests=(),
        fork_matrix_states=(clean, pinned),
        fork_matrix_repetitions=2,
    )
    config = config_factory(
        smart_contracts={
            "compile": True,
            "allow_fork_probing": True,
            "repository_suite": suite,
        },
        invariants={
            "execute_generated": True,
            "generate_foundry_templates": True,
            "max_invariants": 3,
        },
        formal={"enabled": True},
    )
    inventory = _inventory(_shard_inputs(tmp_path / "local-target", config_factory))
    ledger = AtomicCostLedger.initialize(
        tmp_path / "local-ledger.json",
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    manifest = _scheduler_manifest(inventory, ledger, config, seed="local-limits")

    ceiling = build_quote_local_analysis_ceiling(
        config,
        campaign_manifest=manifest,
        solidity_shard_inventory=inventory,
    )
    compilation = math.ceil(config.smart_contracts.compilation_timeout_seconds) * len(
        inventory.source_units
    )
    matrix = math.ceil(repository_fork_matrix_timeout_budget_seconds(suite))
    generated_harnesses = 2 * config.invariants.max_invariants
    harness_execution = math.ceil(config.reproduction.timeout_seconds) * generated_harnesses
    formal_tools = 7
    formal_execution = math.ceil(config.formal.timeout_seconds) * formal_tools

    assert ceiling.maximum_wall_clock_seconds >= (
        compilation + matrix + harness_execution + formal_execution
    )
