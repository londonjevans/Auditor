from __future__ import annotations

import shutil
from pathlib import Path

from mmaudit.models.schemas import (
    EconomicSimulationKind,
    InvariantSuite,
    InvariantTemplate,
    LocalInvariantDeployment,
    LocalInvariantDeploymentArgument,
    PropertyCorpus,
    SolidityGraphKind,
    TransactionOrderingCapability,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.economics import (
    ECONOMIC_TEMPLATE_REGISTRY,
    plan_economic_simulations,
)
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.invariant_templates import generate_invariant_harnesses
from mmaudit.solidity.invariants import discover_invariants
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.properties import build_property_corpus

FIXTURES = Path(__file__).parents[1] / "fixtures" / "solidity"


def test_economic_registry_has_every_bounded_template() -> None:
    assert set(ECONOMIC_TEMPLATE_REGISTRY) == set(EconomicSimulationKind)
    for kind, template in ECONOMIC_TEMPLATE_REGISTRY.items():
        assert template.kind is kind
        assert template.required_fixtures
        assert template.attacker_capabilities
        assert template.preconditions
        assert template.expected_invariant_violation
        assert all(value > 0 for value in template.bounded_parameters.values())
        assert template.measured_outputs


def test_protocol_facts_select_source_linked_economic_plans(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "semantic"
    shutil.copytree(FIXTURES / "semantic", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    selected = {plan.kind for plan in plans}
    assert {
        EconomicSimulationKind.ERC4626_DONATION,
        EconomicSimulationKind.FLASH_ORACLE,
        EconomicSimulationKind.ROUNDING,
    } <= selected
    assert all(plan.applicable and plan.execution_required for plan in plans)
    assert any(plan.source_locations for plan in plans)
    typed = {plan.kind for plan in plans if plan.typed_harness_available}
    assert typed == {
        EconomicSimulationKind.AMM_RESERVES,
        EconomicSimulationKind.ERC4626_DONATION,
        EconomicSimulationKind.FLASH_ORACLE,
        EconomicSimulationKind.ROUNDING,
        EconomicSimulationKind.SIGNATURE_REPLAY,
    }
    assert typed == selected
    assert all(plan.limitations for plan in plans)


def test_rounding_plan_requires_source_linked_division_evidence() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["amm"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.ROUNDING for plan in plans)


def test_rounding_fixture_selects_source_linked_typed_plan(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-rounding"
    shutil.copytree(FIXTURES / "economic_rounding", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    rounding = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.ROUNDING_BOUNDS
    ]
    assert rounding
    assert all(invariant.locations and invariant.entity_ids for invariant in rounding)
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.ROUNDING)
    assert plan.applicable
    assert plan.typed_harness_available
    assert set(plan.invariant_ids) == {invariant.id for invariant in rounding}


def test_oracle_guard_fixture_selects_only_missing_configured_guards(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-oracle-guards"
    shutil.copytree(FIXTURES / "economic_oracle_guards", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    entities = {entity.id: entity for entity in build.index.entities}
    validation_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
        and edge.source_id in entities
        and entities[edge.source_id].name == "validatePreset"
        and entities[edge.source_id].contract_name in {"UnsafeOracleGuard", "SafeOracleGuard"}
    ]
    unsafe_edges = [
        edge
        for edge in validation_edges
        if entities[edge.source_id].contract_name == "UnsafeOracleGuard"
    ]
    safe_edges = [
        edge
        for edge in validation_edges
        if entities[edge.source_id].contract_name == "SafeOracleGuard"
    ]
    assert unsafe_edges and safe_edges
    validation_fields = {
        "freshness_validation",
        "scale_validation",
        "availability_validation",
        "sequencer_validation",
    }
    assert all(edge.metadata["oracle_guard_configuration"] == "configured" for edge in unsafe_edges)
    assert all(
        {edge.metadata[field] for field in validation_fields} == {"unknown"}
        for edge in unsafe_edges
    )
    assert all(edge.metadata["oracle_guard_configuration"] == "configured" for edge in safe_edges)
    assert all(
        {edge.metadata[field] for field in validation_fields} == {"present"} for edge in safe_edges
    )

    guard_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.ORACLE_GUARD_SANITY
    ]
    assert guard_invariants
    unsafe_ids = {edge.source_id for edge in unsafe_edges}
    safe_ids = {edge.source_id for edge in safe_edges}
    assert {entity_id for invariant in guard_invariants for entity_id in invariant.entity_ids} <= (
        unsafe_ids
    )
    assert all(safe_ids.isdisjoint(invariant.entity_ids) for invariant in guard_invariants)
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.ORACLE_GUARDS)
    assert plan.applicable
    assert plan.typed_harness_available
    assert set(plan.invariant_ids) == {invariant.id for invariant in guard_invariants}


def test_temporary_liquidity_fixture_generates_settled_local_harnesses(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-temporary-liquidity"
    shutil.copytree(FIXTURES / "economic_temporary_liquidity_oracle", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)
    source_path = "src/TemporaryLiquidityOracle.sol"
    contract_names = (
        "UnsafeTemporaryLiquidityOracle",
        "SafeTemporaryLiquidityOracle",
    )
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticLiquidityAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticLiquidityAsset",
                        )
                    ],
                ),
            )
        )

    generated = generate_invariant_harnesses(
        invariants,
        build.index,
        targets=targets,
        economic_plans=plans,
        runs=256,
        depth=64,
        local_deployments=deployments,
    )
    harnesses = [
        harness
        for harness in generated.harnesses
        if harness.economic_template is EconomicSimulationKind.FLASH_ORACLE
    ]

    assert {harness.actions[0].target for harness in harnesses} == set(contract_names)
    assert all(harness.runs == 8 and harness.depth == 1 for harness in harnesses)
    assert all(harness.financial_settlement is not None for harness in harnesses)
    assert all(
        harness.financial_settlement.repaid_assets.function_signature == "repaidAssets()"
        for harness in harnesses
        if harness.financial_settlement is not None
    )
    assert all(
        harness.capability_policy is not None
        and harness.capability_policy.flash_liquidity_wei == 1_000
        for harness in harnesses
    )
    assert all(len(harness.local_deployments) == 2 for harness in harnesses)


def test_amm_reserve_fixture_generates_distinct_settled_local_harnesses(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-amm-reserves"
    shutil.copytree(FIXTURES / "economic_amm_reserves", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)
    source_path = "src/ReservePricing.sol"
    contract_names = (
        "UnsafeSpotReservePricing",
        "SafeProtectedReservePricing",
    )
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticSettlementAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticSettlementAsset",
                        )
                    ],
                ),
            )
        )

    generated = generate_invariant_harnesses(
        invariants,
        build.index,
        targets=targets,
        economic_plans=plans,
        runs=256,
        depth=64,
        local_deployments=deployments,
    )
    harnesses = [
        harness
        for harness in generated.harnesses
        if harness.economic_template is EconomicSimulationKind.AMM_RESERVES
    ]

    assert {harness.actions[0].target for harness in harnesses} == set(contract_names)
    assert all(
        harness.actions[0].function_signature == "reserveMovementPreset()" for harness in harnesses
    )
    assert all(harness.runs == 8 and harness.depth == 1 for harness in harnesses)
    assert all(
        [property_spec.property_id for property_spec in harness.properties]
        == [
            "ReserveProductPreserved",
            "SpotMovementCannotCreateExcessExtraction",
        ]
        for harness in harnesses
    )
    assert all(harness.financial_settlement is not None for harness in harnesses)
    assert all(
        harness.capability_policy is not None and harness.capability_policy.flash_liquidity_wei == 0
        for harness in harnesses
    )
    assert all(len(harness.local_deployments) == 2 for harness in harnesses)
    assert not [
        harness
        for harness in generated.harnesses
        if harness.economic_template is EconomicSimulationKind.FLASH_ORACLE
    ]


def test_liquidation_fixture_generates_source_linked_settled_boundary_harnesses(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-liquidation"
    shutil.copytree(FIXTURES / "economic_liquidation", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)
    liquidation_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.DEBT_COLLATERAL_CONSISTENCY
    ]
    contract_names = (
        "UnsafeHealthyPositionLiquidation",
        "SafeHealthyPositionLiquidation",
    )

    assert len(liquidation_invariants) == 2
    assert {
        next(
            entity.contract_name
            for entity in build.index.entities
            if entity.id == invariant.entity_ids[0]
        )
        for invariant in liquidation_invariants
    } == set(contract_names)
    assert all(
        "liquidationBoundaryPreset" in invariant.functions for invariant in liquidation_invariants
    )
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.LIQUIDATION)
    assert plan.typed_harness_available
    assert set(plan.invariant_ids) == {invariant.id for invariant in liquidation_invariants}

    source_path = "src/LiquidationBoundary.sol"
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticLiquidationAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticLiquidationAsset",
                        )
                    ],
                ),
            )
        )
    executable_suite = invariants.model_copy(
        update={
            "invariants": [
                invariant.model_copy(update={"executable": True})
                if invariant in liquidation_invariants
                else invariant
                for invariant in invariants.invariants
            ],
            "executable_count": len(liquidation_invariants),
        }
    )
    generated = generate_invariant_harnesses(
        executable_suite,
        build.index,
        targets=targets,
        economic_plans=[plan],
        runs=256,
        depth=64,
        local_deployments=deployments,
    )
    harnesses = [
        harness
        for harness in generated.harnesses
        if harness.economic_template is EconomicSimulationKind.LIQUIDATION
    ]

    assert {harness.actions[0].target for harness in harnesses} == set(contract_names)
    assert all(
        harness.actions[0].function_signature == "liquidationBoundaryPreset()"
        for harness in harnesses
    )
    assert all(harness.runs == 8 and harness.depth == 1 for harness in harnesses)
    assert all(
        [property_spec.property_id for property_spec in harness.properties]
        == [
            "HealthyPositionPreservesCollateral",
            "HealthyPositionCannotCreateBadDebt",
        ]
        for harness in harnesses
    )
    assert all(
        harness.financial_settlement is not None
        and harness.lending_boundary is not None
        and len(harness.local_deployments) == 2
        for harness in harnesses
    )
    corpus = build_property_corpus(executable_suite, build.index, harnesses)
    assert len(corpus.properties) == 4
    assert PropertyCorpus.model_validate_json(corpus.model_dump_json()) == corpus


def test_lending_profile_without_source_linked_boundary_is_not_applicable() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["lending"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.LIQUIDATION for plan in plans)


def test_share_price_fixture_generates_yield_adjusted_settled_harnesses(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-share-price"
    shutil.copytree(FIXTURES / "economic_share_price", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)
    rate_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.ERC4626_CONVERSION_SANITY
        and "exchangeRateBoundaryPreset" in invariant.functions
    ]
    contract_names = (
        "UnsafeReportedAssetRateVault",
        "SafeObservedAssetRateVault",
    )

    assert len(rate_invariants) == 2
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.SHARE_PRICE)
    assert plan.typed_harness_available
    assert set(plan.invariant_ids) >= {invariant.id for invariant in rate_invariants}

    source_path = "src/SharePriceBoundary.sol"
    targets = {
        **{name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)},
        **{f"{name}Asset": f"0x{index + 12:040x}" for index, name in enumerate(contract_names)},
    }
    deployments: list[LocalInvariantDeployment] = []
    for name in contract_names:
        asset_alias = f"{name}Asset"
        deployments.extend(
            (
                LocalInvariantDeployment(
                    target_alias=asset_alias,
                    contract_name="SyntheticRateAsset",
                    source_path=source_path,
                    token_seed_function_signature="mint(address,uint256)",
                ),
                LocalInvariantDeployment(
                    target_alias=name,
                    contract_name=name,
                    source_path=source_path,
                    constructor_arguments=[
                        LocalInvariantDeploymentArgument(
                            target_alias=asset_alias,
                            cast_contract="SyntheticRateAsset",
                        )
                    ],
                ),
            )
        )
    executable_suite = invariants.model_copy(
        update={
            "invariants": [
                invariant.model_copy(update={"executable": True})
                if invariant in rate_invariants
                else invariant
                for invariant in invariants.invariants
            ],
            "executable_count": len(rate_invariants),
        }
    )
    generated = generate_invariant_harnesses(
        executable_suite,
        build.index,
        targets=targets,
        economic_plans=[plan],
        runs=256,
        depth=64,
        local_deployments=deployments,
    )
    harnesses = [
        harness
        for harness in generated.harnesses
        if harness.economic_template is EconomicSimulationKind.SHARE_PRICE
    ]

    assert {harness.actions[0].target for harness in harnesses} == set(contract_names)
    assert all(
        harness.actions[0].function_signature == "exchangeRateBoundaryPreset()"
        for harness in harnesses
    )
    assert all(harness.runs == 8 and harness.depth == 1 for harness in harnesses)
    assert all(
        [property_spec.property_id for property_spec in harness.properties]
        == [
            "ReachableRateCannotExceedYieldRate",
            "RedemptionCannotExceedYieldValue",
        ]
        for harness in harnesses
    )
    assert all(
        harness.financial_settlement is not None
        and harness.share_price_boundary is not None
        and len(harness.local_deployments) == 2
        for harness in harnesses
    )
    corpus = build_property_corpus(executable_suite, build.index, harnesses)
    assert len(corpus.properties) == 4
    assert PropertyCorpus.model_validate_json(corpus.model_dump_json()) == corpus


def test_erc4626_profile_without_source_linked_rate_boundary_has_no_share_plan() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["erc4626_vault"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.SHARE_PRICE for plan in plans)


def test_state_ordering_fixture_generates_two_action_minimizable_harnesses(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-state-ordering"
    shutil.copytree(FIXTURES / "economic_state_ordering", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)
    sequence_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.MULTI_STEP_STATE_CONSISTENCY
    ]
    contract_names = (
        "UnsafePreparedStateMachine",
        "SafePreparedStateMachine",
    )

    assert len(sequence_invariants) == 2
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.STATE_ORDERING)
    assert plan.typed_harness_available
    assert plan.required_transaction_ordering is TransactionOrderingCapability.MULTI_TRANSACTION
    assert set(plan.invariant_ids) == {invariant.id for invariant in sequence_invariants}

    source_path = "src/StateOrdering.sol"
    targets = {name: f"0x{index + 2:040x}" for index, name in enumerate(contract_names)}
    executable_suite = invariants.model_copy(
        update={
            "invariants": [
                invariant.model_copy(update={"executable": True})
                if invariant in sequence_invariants
                else invariant
                for invariant in invariants.invariants
            ],
            "executable_count": len(sequence_invariants),
        }
    )
    generated = generate_invariant_harnesses(
        executable_suite,
        build.index,
        targets=targets,
        economic_plans=[plan],
        runs=256,
        depth=64,
        local_deployments=[
            LocalInvariantDeployment(
                target_alias=name,
                contract_name=name,
                source_path=source_path,
            )
            for name in contract_names
        ],
    )
    harnesses = [
        harness
        for harness in generated.harnesses
        if harness.economic_template is EconomicSimulationKind.STATE_ORDERING
    ]

    assert harnesses, generated.limitations
    assert {harness.actions[0].target for harness in harnesses} == set(contract_names), (
        generated.limitations
    )
    assert all(
        [action.function_signature for action in harness.actions]
        == ["preparePreset()", "commitPreset()"]
        for harness in harnesses
    )
    assert all(
        harness.required_action_sequence == ["PrepareState", "CommitState"]
        and harness.properties[0].required_action_ids == ["PrepareState", "CommitState"]
        and harness.runs == 32
        and harness.depth == 2
        and harness.seed == 18
        and harness.capability_policy is not None
        and harness.capability_policy.transaction_ordering
        is TransactionOrderingCapability.MULTI_TRANSACTION
        and len(harness.local_deployments) == 1
        for harness in harnesses
    )
    corpus = build_property_corpus(executable_suite, build.index, harnesses)
    assert len(corpus.properties) == 2
    assert {item.campaign.seed for item in corpus.properties} == {18}
    assert {item.campaign.depth for item in corpus.properties} == {2}
    assert PropertyCorpus.model_validate_json(corpus.model_dump_json()) == corpus


def test_state_ordering_plan_requires_exact_source_linked_sequence() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["state_machine"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.STATE_ORDERING for plan in plans)


def test_governance_fixture_selects_only_rights_guarded_missing_delay(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-governance"
    shutil.copytree(FIXTURES / "economic_governance", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    entities = {entity.id: entity for entity in build.index.entities}
    lifecycle_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.GOVERNANCE
        and edge.source_id in entities
        and entities[edge.source_id].contract_name
        in {"UnsafeGovernanceLifecycle", "SafeGovernanceLifecycle"}
    ]
    unsafe_edges = [
        edge
        for edge in lifecycle_edges
        if entities[edge.source_id].contract_name == "UnsafeGovernanceLifecycle"
    ]
    safe_edges = [
        edge
        for edge in lifecycle_edges
        if entities[edge.source_id].contract_name == "SafeGovernanceLifecycle"
    ]
    expected_stages = {"proposal", "vote", "queue", "execute", "cancel"}
    assert {edge.metadata["stage"] for edge in unsafe_edges} == expected_stages
    assert {edge.metadata["stage"] for edge in safe_edges} == expected_stages
    assert {edge.metadata["authorization_control"] for edge in lifecycle_edges} == {"present"}
    unsafe_execute = next(edge for edge in unsafe_edges if edge.metadata["stage"] == "execute")
    safe_execute = next(edge for edge in safe_edges if edge.metadata["stage"] == "execute")
    assert unsafe_execute.metadata["delay_control"] == "unknown"
    assert safe_execute.metadata["delay_control"] == "present"

    delay_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.GOVERNANCE_DELAY_SANITY
    ]
    assert len(delay_invariants) == 1
    unsafe_ids = {edge.source_id for edge in unsafe_edges}
    safe_ids = {edge.source_id for edge in safe_edges}
    assert set(delay_invariants[0].entity_ids) == unsafe_ids
    assert safe_ids.isdisjoint(delay_invariants[0].entity_ids)
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.GOVERNANCE_RACE)
    assert plan.applicable
    assert plan.typed_harness_available
    assert plan.invariant_ids == [delay_invariants[0].id]


def test_governance_profile_without_source_linked_lifecycle_is_not_applicable() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["governance"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.GOVERNANCE_RACE for plan in plans)


def test_upgrade_fixture_selects_only_missing_authorization_and_initializer_guards(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-upgrade-initializer"
    shutil.copytree(FIXTURES / "economic_upgrade_initializer", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    entities = {entity.id: entity for entity in build.index.entities}
    upgrade_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.PROXY
        and edge.metadata.get("surface") == "upgrade_or_implementation"
        and edge.source_id in entities
        and entities[edge.source_id].contract_name in {"UnsafeUpgradeProxy", "SafeUpgradeProxy"}
    ]
    initializer_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.INITIALIZER
        and edge.source_id in entities
        and entities[edge.source_id].contract_name in {"UnsafeUpgradeProxy", "SafeUpgradeProxy"}
    ]
    unsafe_upgrade = next(
        edge
        for edge in upgrade_edges
        if entities[edge.source_id].contract_name == "UnsafeUpgradeProxy"
    )
    safe_upgrade = next(
        edge
        for edge in upgrade_edges
        if entities[edge.source_id].contract_name == "SafeUpgradeProxy"
    )
    unsafe_initializer = next(
        edge
        for edge in initializer_edges
        if entities[edge.source_id].contract_name == "UnsafeUpgradeProxy"
    )
    safe_initializer = next(
        edge
        for edge in initializer_edges
        if entities[edge.source_id].contract_name == "SafeUpgradeProxy"
    )
    assert unsafe_upgrade.metadata["authorization_resolution"] == "unknown"
    assert safe_upgrade.metadata["authorization_resolution"] == "present"
    assert unsafe_initializer.metadata["guard_resolution"] == "unknown"
    assert safe_initializer.metadata["guard_resolution"] == "inline_state_guard"

    upgrade_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.UPGRADE_INITIALIZER_SANITY
    ]
    assert len(upgrade_invariants) == 1
    assert set(upgrade_invariants[0].entity_ids) == {
        unsafe_upgrade.source_id,
        unsafe_initializer.source_id,
    }
    assert {
        safe_upgrade.source_id,
        safe_initializer.source_id,
    }.isdisjoint(upgrade_invariants[0].entity_ids)
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.UPGRADE_INITIALIZER)
    assert plan.applicable
    assert plan.typed_harness_available
    assert plan.invariant_ids == [upgrade_invariants[0].id]


def test_upgrade_profile_without_linked_unsafe_pair_is_not_applicable() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["upgradeable_system"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.UPGRADE_INITIALIZER for plan in plans)


def test_cross_chain_fixture_selects_only_missing_replay_and_order_guards(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-cross-chain"
    shutil.copytree(FIXTURES / "economic_cross_chain", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    entities = {entity.id: entity for entity in build.index.entities}
    inbound_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.CROSS_CHAIN
        and edge.metadata.get("direction") == "inbound"
        and edge.source_id in entities
        and entities[edge.source_id].signature == "processMessagePreset(uint256,bytes32)"
    ]
    unsafe_edge = next(
        edge
        for edge in inbound_edges
        if entities[edge.source_id].contract_name == "UnsafeMessageInbox"
    )
    safe_edge = next(
        edge
        for edge in inbound_edges
        if entities[edge.source_id].contract_name == "SafeMessageInbox"
    )
    assert unsafe_edge.metadata["replay_protection_evidence"] == "unknown"
    assert unsafe_edge.metadata["ordering_evidence"] == "unknown"
    assert safe_edge.metadata["replay_protection_evidence"] == "present"
    assert safe_edge.metadata["ordering_evidence"] == "present"
    assert unsafe_edge.metadata["deterministic_fact"] is False
    assert safe_edge.metadata["deterministic_fact"] is False

    message_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.MESSAGE_CONSUMPTION_ONCE
    ]
    assert len(message_invariants) == 1
    assert message_invariants[0].entity_ids == [unsafe_edge.source_id]
    assert safe_edge.source_id not in message_invariants[0].entity_ids
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.CROSS_CHAIN_REPLAY)
    assert plan.applicable
    assert plan.typed_harness_available
    assert plan.invariant_ids == [message_invariants[0].id]


def test_bridge_profile_without_linked_inbound_transition_is_not_applicable() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["bridge"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.CROSS_CHAIN_REPLAY for plan in plans)


def test_callback_fixture_links_reachable_hook_to_affected_state(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-callback"
    shutil.copytree(FIXTURES / "economic_callback", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    entities = {entity.id: entity for entity in build.index.entities}
    callback_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.REENTRANCY
        and edge.metadata.get("entrypoint_signature") == "withdrawCallbackPreset()"
        and edge.metadata.get("callback_member") == "onCreditReceived"
        and edge.metadata.get("affected_state_name") == "availableCredit"
    ]
    assert len(callback_edges) == 1
    unsafe_edge = callback_edges[0]
    unsafe_entry = entities[str(unsafe_edge.metadata["function_id"])]
    assert unsafe_entry.contract_name == "UnsafeCallbackAccounting"
    assert unsafe_edge.metadata["callback_reachability"] == "present"
    assert unsafe_edge.metadata["callback_kind"] == "explicit_receiver_hook"
    assert unsafe_edge.metadata["callback_target"] == "receiver"
    assert unsafe_edge.metadata["unsafe_transition_candidate"] is True
    assert entities[unsafe_edge.target_id].name == "availableCredit"
    assert not any(
        edge.metadata.get("function_id") == entity.id
        for entity in entities.values()
        if entity.contract_name == "SafeCallbackAccounting"
        and entity.signature == "withdrawCallbackPreset()"
        for edge in callback_edges
    )

    callback_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.CALLBACK_STATE_CONSISTENCY
    ]
    assert len(callback_invariants) == 1
    assert set(callback_invariants[0].entity_ids) == {
        unsafe_entry.id,
        unsafe_edge.target_id,
    }
    assert "receiver.onCreditReceived()" in " ".join(callback_invariants[0].assumptions)
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.CALLBACK_REENTRANCY)
    assert plan.applicable
    assert plan.typed_harness_available
    assert plan.invariant_ids == [callback_invariants[0].id]
    serialized = graphs.model_dump_json()
    assert '"callback_reachability":"present"' in serialized
    assert '"affected_state_name":"availableCredit"' in serialized


def test_callback_plan_requires_linked_reachable_state_transition() -> None:
    plans = plan_economic_simulations(InvariantSuite(), graphs=None)

    assert all(plan.kind is not EconomicSimulationKind.CALLBACK_REENTRANCY for plan in plans)


def test_state_growth_fixture_resolves_safe_threshold_and_selects_unsafe_append(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-state-growth"
    shutil.copytree(FIXTURES / "economic_state_growth", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    entities = {entity.id: entity for entity in build.index.entities}
    growth_edges = [
        edge
        for edge in graphs.edges
        if edge.graph is SolidityGraphKind.STATE_GROWTH
        and edge.metadata.get("entrypoint_signature") == "appendPreset()"
        and edge.metadata.get("state_variable_name") == "entries"
    ]
    assert len(growth_edges) == 2
    by_contract = {entities[edge.source_id].contract_name: edge for edge in growth_edges}
    unsafe = by_contract["UnsafeStateGrowth"]
    safe = by_contract["SafeStateGrowth"]
    assert unsafe.metadata["growth_limit_resolution"] == "unknown"
    assert unsafe.metadata["growth_threshold"] is None
    assert safe.metadata["growth_limit_resolution"] == "present"
    assert safe.metadata["growth_threshold"] == 4
    assert safe.metadata["deterministic_fact"] is False

    growth_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.STATE_GROWTH_BOUND
    ]
    assert len(growth_invariants) == 1
    assert unsafe.source_id in growth_invariants[0].entity_ids
    assert unsafe.target_id in growth_invariants[0].entity_ids
    assert safe.source_id not in growth_invariants[0].entity_ids
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.BOUNDED_STATE_GROWTH)
    assert plan.applicable
    assert plan.typed_harness_available
    assert plan.invariant_ids == [growth_invariants[0].id]
    assert (
        "growth_threshold"
        in ECONOMIC_TEMPLATE_REGISTRY[
            EconomicSimulationKind.BOUNDED_STATE_GROWTH
        ].bounded_parameters
    )


def test_state_growth_plan_requires_linked_unguarded_append() -> None:
    plans = plan_economic_simulations(InvariantSuite(), graphs=None)

    assert all(plan.kind is not EconomicSimulationKind.BOUNDED_STATE_GROWTH for plan in plans)


def test_ordering_plan_requires_source_linked_staged_value_bound() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["amm"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.SANDWICH for plan in plans)


def test_ordering_fixture_selects_same_block_capability_gated_plan(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-ordering"
    shutil.copytree(FIXTURES / "economic_ordering", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    ordering = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.ORDERING_VALUE_BOUND
    ]
    assert ordering
    assert all(
        len(invariant.locations) == 3 and len(invariant.entity_ids) == 3 for invariant in ordering
    )
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.SANDWICH)
    assert plan.applicable
    assert plan.typed_harness_available
    assert plan.required_transaction_ordering is TransactionOrderingCapability.SAME_BLOCK
    assert set(plan.invariant_ids) == {invariant.id for invariant in ordering}


def test_token_behavior_fixture_selects_source_linked_typed_plan(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-token-behavior"
    shutil.copytree(FIXTURES / "economic_token_behavior", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    observed = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.OBSERVED_ASSET_ACCOUNTING
    ]
    assert observed
    assert observed[0].locations
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.NON_STANDARD_TOKEN)
    assert plan.applicable
    assert plan.typed_harness_available
    assert observed[0].id in plan.invariant_ids


def test_malformed_return_fixture_detects_only_unchecked_outcomes(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-erc20-returns"
    shutil.copytree(FIXTURES / "economic_erc20_returns", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    return_handling = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.ERC20_RETURN_HANDLING
    ]
    assert len(return_handling) == 1
    linked_entities = {
        entity.id: entity
        for entity in build.index.entities
        if entity.id in return_handling[0].entity_ids
    }
    assert {entity.contract_name for entity in linked_entities.values()} == {
        "UnsafeUncheckedReturnVault"
    }
    assert return_handling[0].locations
    assert return_handling[0].template_available
    assert not return_handling[0].executable
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.NON_STANDARD_TOKEN)
    assert plan.applicable
    assert plan.typed_harness_available
    assert return_handling[0].id in plan.invariant_ids

    executable = return_handling[0].model_copy(update={"executable": True})
    executable_suite = InvariantSuite(
        invariants=[executable],
        protocol_profiles=invariants.protocol_profiles,
        templates_available_count=1,
        executable_count=1,
    )
    targets = {
        "UnsafeUncheckedReturnVault": "0x2000000000000000000000000000000000000002",
        "UnsafeUncheckedReturnVaultAsset": "0x3000000000000000000000000000000000000003",
    }
    generated = generate_invariant_harnesses(
        executable_suite,
        build.index,
        targets=targets,
        economic_plans=[plan],
        runs=16,
        depth=8,
    )
    assert len(generated.harnesses) == 1
    corpus = build_property_corpus(executable_suite, build.index, generated.harnesses)
    assert len(corpus.properties) == 1
    assert corpus.properties[0].property_id == "ERC20ReturnOutcomePreservesAccounting"
    assert PropertyCorpus.model_validate_json(corpus.model_dump_json()) == corpus
    assert not corpus.limitations


def test_reward_fixture_extracts_both_source_linked_typed_properties(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-reward-accounting"
    shutil.copytree(FIXTURES / "economic_reward_accounting", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    reward_invariants = [
        invariant
        for invariant in invariants.invariants
        if invariant.template
        in {
            InvariantTemplate.REWARD_INDEX_MONOTONIC,
            InvariantTemplate.CLAIM_ONCE,
        }
    ]
    assert {invariant.template for invariant in reward_invariants} == {
        InvariantTemplate.REWARD_INDEX_MONOTONIC,
        InvariantTemplate.CLAIM_ONCE,
    }
    linked_ids = {
        entity_id for invariant in reward_invariants for entity_id in invariant.entity_ids
    }
    linked_entities = [entity for entity in build.index.entities if entity.id in linked_ids]
    assert {entity.contract_name for entity in linked_entities} == {"UnsafeRewardAccounting"}
    assert all(
        invariant.locations and invariant.template_available for invariant in reward_invariants
    )

    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.REWARD_INDEX)
    assert plan.applicable
    assert plan.typed_harness_available
    assert set(plan.invariant_ids) == {invariant.id for invariant in reward_invariants}

    executable_invariants = [
        invariant.model_copy(update={"executable": True}) for invariant in reward_invariants
    ]
    executable_suite = InvariantSuite(
        invariants=executable_invariants,
        protocol_profiles=invariants.protocol_profiles,
        templates_available_count=2,
        executable_count=2,
    )
    generated = generate_invariant_harnesses(
        executable_suite,
        build.index,
        targets={
            "UnsafeRewardAccounting": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[plan],
        runs=16,
        depth=8,
    )
    assert not generated.limitations
    assert {harness.properties[0].property_id for harness in generated.harnesses} == {
        "RewardIndexDoesNotDecrease",
        "FiniteEntitlementIsPaidAtMostOnce",
    }
    corpus = build_property_corpus(executable_suite, build.index, generated.harnesses)
    assert len(corpus.properties) == 2
    assert PropertyCorpus.model_validate_json(corpus.model_dump_json()) == corpus
    assert not corpus.limitations


def test_reward_plan_requires_a_source_derived_property() -> None:
    plans = plan_economic_simulations(
        InvariantSuite(protocol_profiles=["staking"]),
        graphs=None,
    )

    assert all(plan.kind is not EconomicSimulationKind.REWARD_INDEX for plan in plans)


def test_signature_fixture_selects_primitive_backed_typed_plan(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "economic-signature-replay"
    shutil.copytree(FIXTURES / "economic_signature_replay", root)
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    replay = [
        invariant
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.PERMIT_REPLAY_PROTECTION
    ]
    assert replay
    assert all(invariant.locations and invariant.entity_ids for invariant in replay)
    plan = next(plan for plan in plans if plan.kind is EconomicSimulationKind.SIGNATURE_REPLAY)
    assert plan.applicable
    assert plan.typed_harness_available
    assert set(plan.invariant_ids) == {invariant.id for invariant in replay}


def test_permit_like_name_without_signature_primitive_is_not_applicable(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "named-only"
    source_dir = root / "src"
    source_dir.mkdir(parents=True)
    (source_dir / "NamedOnly.sol").write_text(
        """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
contract NamedOnly {
    mapping(address => uint256) public claimed;
    function permitPreset() external {
        claimed[msg.sender] += 1;
    }
}
""",
        encoding="utf-8",
    )
    config = config_factory()
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, build)
    invariants = discover_invariants(discovery, build.index, graphs, config.invariants)
    plans = plan_economic_simulations(invariants, graphs)

    assert all(plan.kind is not EconomicSimulationKind.SIGNATURE_REPLAY for plan in plans)
