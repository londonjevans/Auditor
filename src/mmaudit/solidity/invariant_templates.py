"""Deterministic generation of bounded Foundry invariant specifications."""

from __future__ import annotations

import re
from dataclasses import dataclass

from mmaudit.models.schemas import (
    AttackerCapability,
    AttackerCapabilityPolicy,
    CrossChainMessageCapability,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    FinancialAssetKind,
    FinancialSettlementProbeSpec,
    ForkActor,
    ForkArgument,
    ForkArgumentKind,
    ForkCallStep,
    FoundryInvariantHarnessSpec,
    HarnessArgument,
    HarnessArgumentSource,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    LendingBoundaryProbeSpec,
    LocalInvariantDeployment,
    OracleInfluenceCapability,
    SharePriceBoundaryProbeSpec,
    SolidityEntity,
    SolidityEntityKind,
    SoliditySymbolIndex,
    StatefulActionSpec,
    TokenBalanceSeed,
    TransactionOrderingCapability,
)

_ALICE = "0x1000000000000000000000000000000000000001"
_ATTACKER = "0x1000000000000000000000000000000000000002"
_VICTIM = "0x1000000000000000000000000000000000000003"
_MESSAGE_ONE = "0x" + "01".zfill(64)
_MESSAGE_THREE = "0x" + "03".zfill(64)


@dataclass(frozen=True)
class InvariantHarnessGeneration:
    """Generated typed harnesses plus explicit unsupported/binding limitations."""

    harnesses: list[FoundryInvariantHarnessSpec]
    limitations: list[str]


def generate_invariant_harnesses(
    suite: InvariantSuite | None,
    index: SoliditySymbolIndex | None,
    *,
    targets: dict[str, str],
    economic_plans: list[EconomicSimulationPlan],
    runs: int,
    depth: int,
    local_deployments: list[LocalInvariantDeployment] | None = None,
) -> InvariantHarnessGeneration:
    """Generate only invariant shapes expressible without free-form Solidity."""

    if suite is None or index is None:
        return InvariantHarnessGeneration(
            harnesses=[],
            limitations=["invariant harness generation requires a Solidity index and suite"],
        )
    entities_by_id = {entity.id: entity for entity in index.entities}
    harnesses: list[FoundryInvariantHarnessSpec] = []
    limitations: list[str] = []
    selected_economic = {plan.kind for plan in economic_plans if plan.applicable}
    for invariant in suite.invariants:
        related = [
            entities_by_id[entity_id]
            for entity_id in invariant.entity_ids
            if entity_id in entities_by_id
        ]
        contract_name = next(
            (entity.contract_name for entity in related if entity.contract_name),
            None,
        )
        if contract_name is None or contract_name not in targets:
            limitations.append(
                f"{invariant.id}: no operator-pinned target alias for "
                f"{contract_name or 'the inferred contract'}"
            )
            continue
        same_contract = [
            entity for entity in index.entities if entity.contract_name == contract_name
        ]
        candidates: list[
            tuple[
                EconomicSimulationKind | None,
                tuple[FoundryInvariantHarnessSpec | None, str],
            ]
        ]
        if invariant.template is InvariantTemplate.ORACLE_MANIPULATION_RESISTANCE:
            candidates = []
            if EconomicSimulationKind.FLASH_ORACLE in selected_economic:
                candidates.append(
                    (
                        EconomicSimulationKind.FLASH_ORACLE,
                        _temporary_liquidity_oracle_harness(
                            invariant,
                            contract_name,
                            same_contract,
                            targets,
                            runs,
                            depth,
                        ),
                    )
                )
            if EconomicSimulationKind.AMM_RESERVES in selected_economic:
                candidates.append(
                    (
                        EconomicSimulationKind.AMM_RESERVES,
                        _amm_reserve_harness(
                            invariant,
                            contract_name,
                            same_contract,
                            targets,
                            runs,
                            depth,
                        ),
                    )
                )
        else:
            candidates = [
                (
                    None,
                    _build_harness(
                        invariant,
                        contract_name,
                        same_contract,
                        targets=targets,
                        runs=runs,
                        depth=depth,
                    ),
                )
            ]
        for economic_kind, (harness, reason) in candidates:
            if harness is None:
                label = f" ({economic_kind.value})" if economic_kind is not None else ""
                limitations.append(f"{invariant.id}{label}: {reason}")
                continue
            deployment_by_target = {
                deployment.target_alias: deployment for deployment in (local_deployments or [])
            }
            referenced_targets = _harness_target_aliases(harness)
            if referenced_targets and referenced_targets <= set(deployment_by_target):
                harness = harness.model_copy(
                    update={
                        "local_deployments": [
                            deployment
                            for deployment in (local_deployments or [])
                            if deployment.target_alias in referenced_targets
                        ],
                        "assumptions": [
                            *harness.assumptions,
                            (
                                "All target aliases are deployed from operator-configured "
                                "synthetic project-local contracts inside the isolated test"
                            ),
                        ][:40],
                    }
                )
            harnesses.append(harness)
    return InvariantHarnessGeneration(
        harnesses=[
            harness
            for harness in harnesses
            if harness.economic_template is None or harness.economic_template in selected_economic
        ],
        limitations=limitations,
    )


def _harness_target_aliases(harness: FoundryInvariantHarnessSpec) -> set[str]:
    return {
        *(call.target for call in harness.setup_calls),
        *(seed.token for seed in harness.token_balance_seeds),
        *(action.target for action in harness.actions),
        *(property_spec.left.target for property_spec in harness.properties),
        *(
            property_spec.right.target
            for property_spec in harness.properties
            if property_spec.right is not None
        ),
        *(
            _financial_settlement_targets(harness.financial_settlement)
            if harness.financial_settlement is not None
            else set()
        ),
        *(
            _lending_boundary_targets(harness.lending_boundary)
            if harness.lending_boundary is not None
            else set()
        ),
        *(
            _share_price_boundary_targets(harness.share_price_boundary)
            if harness.share_price_boundary is not None
            else set()
        ),
    }


def _financial_settlement_targets(
    settlement: FinancialSettlementProbeSpec,
) -> set[str]:
    return {
        *((settlement.asset_target,) if settlement.asset_target is not None else ()),
        settlement.starting_assets.target,
        settlement.borrowed_assets.target,
        settlement.repaid_assets.target,
        settlement.gross_assets_received.target,
        settlement.fees_paid.target,
        settlement.slippage_loss.target,
        settlement.ending_assets.target,
        settlement.net_impact.target,
    }


def _lending_boundary_targets(
    boundary: LendingBoundaryProbeSpec,
) -> set[str]:
    return {
        boundary.debt_before.target,
        boundary.collateral_before.target,
        boundary.debt_after.target,
        boundary.collateral_after.target,
        boundary.collateral_seized.target,
        boundary.bad_debt_after.target,
    }


def _share_price_boundary_targets(
    boundary: SharePriceBoundaryProbeSpec,
) -> set[str]:
    return {
        boundary.rate_scale.target,
        boundary.total_assets_before.target,
        boundary.total_shares_before.target,
        boundary.legitimate_yield.target,
        boundary.expected_rate_after_yield.target,
        boundary.observed_rate_after.target,
        boundary.shares_redeemed.target,
        boundary.assets_redeemed.target,
        boundary.excess_assets.target,
    }


def _build_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    *,
    targets: dict[str, str],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    if invariant.template in {
        InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
        InvariantTemplate.ERC20_RETURN_HANDLING,
    }:
        return _observed_asset_accounting_harness(
            invariant,
            contract_name,
            entities,
            targets,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.ROUNDING_BOUNDS:
        return _rounding_bounds_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.ORACLE_GUARD_SANITY:
        return _oracle_guard_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.ORACLE_MANIPULATION_RESISTANCE:
        return _temporary_liquidity_oracle_harness(
            invariant,
            contract_name,
            entities,
            targets,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.DEBT_COLLATERAL_CONSISTENCY:
        return _liquidation_boundary_harness(
            invariant,
            contract_name,
            entities,
            targets,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.ERC4626_CONVERSION_SANITY:
        return _share_price_boundary_harness(
            invariant,
            contract_name,
            entities,
            targets,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.GOVERNANCE_DELAY_SANITY:
        return _governance_delay_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.UPGRADE_INITIALIZER_SANITY:
        return _upgrade_initializer_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.MESSAGE_CONSUMPTION_ONCE:
        return _cross_chain_message_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.CALLBACK_STATE_CONSISTENCY:
        return _callback_reentrancy_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.STATE_GROWTH_BOUND:
        return _state_growth_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.MULTI_STEP_STATE_CONSISTENCY:
        return _state_ordering_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template in {
        InvariantTemplate.REWARD_INDEX_MONOTONIC,
        InvariantTemplate.CLAIM_ONCE,
    }:
        return _reward_accounting_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.PERMIT_REPLAY_PROTECTION:
        return _signature_replay_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.ORDERING_VALUE_BOUND:
        return _ordering_value_bound_harness(
            invariant,
            contract_name,
            entities,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.DONATION_INFLATION_RESISTANCE:
        return _erc4626_donation_harness(
            invariant,
            contract_name,
            entities,
            targets,
            runs,
            depth,
        )
    if invariant.template is InvariantTemplate.ERC20_SUPPLY_BALANCE:
        return _erc20_supply_harness(invariant, contract_name, entities, runs, depth)
    action = _action_for_template(invariant, entities)
    if action is None or action.signature is None:
        return None, "no supported public/external action signature was indexed"
    arguments = _action_arguments(action.signature)
    if arguments is None:
        return None, f"{action.signature} uses an unsupported ABI shape"
    probe, relation = _baseline_probe(invariant, entities)
    if probe is None or relation is None:
        return None, "the current typed DSL cannot express this invariant without assumptions"
    actors = _actors()
    harness = FoundryInvariantHarnessSpec(
        invariant_id=invariant.id,
        name=_harness_name(invariant),
        actors=actors,
        actions=[
            StatefulActionSpec(
                action_id=_safe_identifier(action.name),
                target=contract_name,
                function_signature=action.signature,
                actor_names=["attacker"],
                actor_fuzz_slot=0,
                arguments=arguments,
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="BaselinePreserved",
                left=probe,
                relation=relation,
                compare_to_initial=True,
            )
        ],
        runs=max(1, runs),
        depth=max(1, depth),
        seed=1,
        assumptions=[
            *invariant.assumptions,
            "The target alias is operator-pinned to the intended deployed contract",
            "The synthetic attacker address has no intended privileged role",
            "The initial local-fork state represents a valid initialized protocol state",
        ][:40],
    )
    return harness, ""


def _rounding_bounds_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Build a bounded no-value-creation check for an explicit round-trip transition."""

    round_trip = next(
        (
            entity
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and entity.visibility in {"public", "external"}
            and entity.signature == "roundTrip(uint256)"
            and entity.id in invariant.entity_ids
        ),
        None,
    )
    account_balance = next(
        (
            entity
            for signature in (
                "credit(address)",
                "balanceOf(address)",
                "assetsOf(address)",
                "accountBalance(address)",
            )
            for entity in entities
            if entity.signature == signature
            and len(entity.return_types) == 1
            and entity.return_types[0] == "uint256"
        ),
        None,
    )
    if round_trip is None or account_balance is None or account_balance.signature is None:
        return None, (
            "bounded rounding execution requires source-linked roundTrip(uint256) and "
            "an address-indexed uint256 account-balance getter"
        )
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            actions=[
                StatefulActionSpec(
                    action_id="RoundTrip",
                    target=contract_name,
                    function_signature=round_trip.signature or "roundTrip(uint256)",
                    actor_names=["attacker"],
                    arguments=[
                        HarnessArgument(
                            kind=ForkArgumentKind.UINT256,
                            source=HarnessArgumentSource.FUZZ_UINT,
                            minimum=1,
                            maximum=10**18,
                            fuzz_slot=0,
                        )
                    ],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="NoRoundTripValueCreation",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature=account_balance.signature,
                        arguments=[
                            ForkArgument(
                                kind=ForkArgumentKind.ADDRESS,
                                value=_ATTACKER,
                            )
                        ],
                    ),
                    relation=InvariantRelation.LTE,
                    compare_to_initial=True,
                )
            ],
            runs=max(1, min(runs, 64)),
            depth=max(1, min(depth, 64)),
            seed=1,
            economic_template=EconomicSimulationKind.ROUNDING,
            assumptions=[
                *invariant.assumptions,
                "roundTrip(uint256) is the source-linked conversion cycle under review",
                "The address-indexed getter measures the actor's asset-denominated claim",
                "Loss from downward rounding is permitted; only value creation violates the property",
                "The target alias is operator-pinned to the intended accounting contract",
            ][:40],
        ),
        "",
    )


def _oracle_guard_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Reject a fixed invalid feed preset before it changes validation accounting."""

    configure = _signature_entity(entities, "configurePreset()")
    validate = _signature_entity(entities, "validatePreset()")
    guard_failures = _signature_entity(entities, "guardFailures()")
    if (
        configure is None
        or validate is None
        or validate.id not in invariant.entity_ids
        or guard_failures is None
        or guard_failures.return_types != ["uint256"]
    ):
        return None, (
            "oracle guard execution requires source-linked validatePreset(), "
            "configurePreset(), and a uint256 guardFailures() getter"
        )
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            setup_calls=[
                ForkCallStep(
                    step_id="ConfigureInvalidFeedPreset",
                    actor="attacker",
                    target=contract_name,
                    function_signature="configurePreset()",
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id="ValidateConfiguredFeed",
                    target=contract_name,
                    function_signature="validatePreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="InvalidFeedIsRejected",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="guardFailures()",
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=max(1, min(depth, 1)),
            seed=1,
            economic_template=EconomicSimulationKind.ORACLE_GUARDS,
            assumptions=[
                *invariant.assumptions,
                "configurePreset() selects only the synthetic invalid feed state",
                "validatePreset() is the source-linked configured oracle transition",
                "guardFailures() records acceptance of that invalid state",
                "A reverting validation action leaves the failure count unchanged",
            ][:40],
        ),
        "",
    )


def _temporary_liquidity_oracle_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    targets: dict[str, str],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Build one settled synthetic temporary-liquidity price transition."""

    action = _signature_entity(entities, "temporaryLiquidityPreset()")
    required_getters = {
        "starting_assets": "startingAssets()",
        "borrowed_assets": "borrowedAssets()",
        "repaid_assets": "repaidAssets()",
        "gross_assets_received": "grossAssetsReceived()",
        "fees_paid": "feesPaid()",
        "slippage_loss": "slippageLoss()",
        "ending_assets": "endingAssets()",
        "net_impact": "netImpact()",
        "excess_extraction": "excessExtraction()",
    }
    getters = {
        name: _signature_entity(entities, signature) for name, signature in required_getters.items()
    }
    asset_alias = f"{contract_name}Asset"
    if (
        action is None
        or action.id not in invariant.entity_ids
        or any(
            entity is None or (bool(entity.return_types) and entity.return_types != ["uint256"])
            for entity in getters.values()
        )
        or asset_alias not in targets
    ):
        return None, (
            "temporary-liquidity oracle execution requires source-linked "
            "temporaryLiquidityPreset(), exact uint256 settlement getters, "
            "excessExtraction(), and a configured synthetic asset alias"
        )

    def probe(name: str) -> InvariantProbe:
        entity = getters[name]
        assert entity is not None and entity.signature is not None
        return InvariantProbe(target=contract_name, function_signature=entity.signature)

    liquidity = 1_000
    action_id = "ExecuteTemporaryLiquiditySequence"
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=f"{_harness_name(invariant)}FlashOracle",
            actors=_actors(),
            token_balance_seeds=[
                TokenBalanceSeed(
                    token=asset_alias,
                    actor="attacker",
                    amount=100,
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id=action_id,
                    target=contract_name,
                    function_signature="temporaryLiquidityPreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="TemporaryLiquidityCannotCreateExcessExtraction",
                    left=probe("excess_extraction"),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                    required_action_ids=[action_id],
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=1,
            seed=1,
            economic_template=EconomicSimulationKind.FLASH_ORACLE,
            capability_policy=AttackerCapabilityPolicy(
                attacker_controlled_actors=["attacker"],
                flash_liquidity_wei=liquidity,
                oracle_influence=OracleInfluenceCapability.FIXTURE_CONFIGURED,
                capability_justifications={
                    AttackerCapability.FLASH_LIQUIDITY: (
                        "One fixed synthetic temporary-liquidity principal."
                    ),
                    AttackerCapability.ORACLE_INFLUENCE: (
                        "One fixture-configured local price preset."
                    ),
                },
            ),
            financial_settlement=FinancialSettlementProbeSpec(
                actor="attacker",
                asset_kind=FinancialAssetKind.ERC20,
                asset_target=asset_alias,
                action_id=action_id,
                starting_assets=probe("starting_assets"),
                borrowed_assets=probe("borrowed_assets"),
                repaid_assets=probe("repaid_assets"),
                gross_assets_received=probe("gross_assets_received"),
                fees_paid=probe("fees_paid"),
                slippage_loss=probe("slippage_loss"),
                ending_assets=probe("ending_assets"),
                net_impact=probe("net_impact"),
            ),
            assumptions=[
                *invariant.assumptions,
                "The temporary principal, price preset, fee, and slippage are fixed local values",
                "The synthetic principal is fully repaid inside one bounded action",
                "Settlement getters are asset-base-unit counters, not live market observations",
                "No RPC, external liquidity source, or deployed contract is contacted",
            ][:40],
        ),
        "",
    )


def _amm_reserve_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    targets: dict[str, str],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Build one bounded constant-product reserve movement and value check."""

    del depth
    action = _signature_entity(entities, "reserveMovementPreset()")
    required_getters = {
        "starting_assets": "startingAssets()",
        "borrowed_assets": "borrowedAssets()",
        "repaid_assets": "repaidAssets()",
        "gross_assets_received": "grossAssetsReceived()",
        "fees_paid": "feesPaid()",
        "slippage_loss": "slippageLoss()",
        "ending_assets": "endingAssets()",
        "net_impact": "netImpact()",
        "excess_extraction": "excessExtraction()",
        "reserve_product_before": "reserveProductBefore()",
        "reserve_product_after": "reserveProductAfter()",
        "spot_price_before": "spotPriceBefore()",
        "spot_price_after": "spotPriceAfter()",
        "protected_price": "protectedPrice()",
    }
    getters = {
        name: _signature_entity(entities, signature) for name, signature in required_getters.items()
    }
    asset_alias = f"{contract_name}Asset"
    if (
        action is None
        or action.id not in invariant.entity_ids
        or any(
            entity is None or (bool(entity.return_types) and entity.return_types != ["uint256"])
            for entity in getters.values()
        )
        or asset_alias not in targets
    ):
        return None, (
            "AMM reserve execution requires source-linked reserveMovementPreset(), "
            "exact uint256 reserve, price, settlement, and excessExtraction() getters, "
            "plus a configured synthetic asset alias"
        )

    def probe(name: str) -> InvariantProbe:
        entity = getters[name]
        assert entity is not None and entity.signature is not None
        return InvariantProbe(target=contract_name, function_signature=entity.signature)

    action_id = "ExecuteBoundedReserveMovement"
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=f"{_harness_name(invariant)}AmmReserve",
            actors=_actors(),
            token_balance_seeds=[
                TokenBalanceSeed(
                    token=asset_alias,
                    actor="attacker",
                    amount=100,
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id=action_id,
                    target=contract_name,
                    function_signature="reserveMovementPreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="ReserveProductPreserved",
                    left=probe("reserve_product_after"),
                    relation=InvariantRelation.EQ,
                    right=probe("reserve_product_before"),
                    required_action_ids=[action_id],
                ),
                InvariantPropertySpec(
                    property_id="SpotMovementCannotCreateExcessExtraction",
                    left=probe("excess_extraction"),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                    required_action_ids=[action_id],
                ),
            ],
            runs=max(1, min(runs, 8)),
            depth=1,
            seed=1,
            economic_template=EconomicSimulationKind.AMM_RESERVES,
            capability_policy=AttackerCapabilityPolicy(
                attacker_controlled_actors=["attacker"],
                oracle_influence=OracleInfluenceCapability.FIXTURE_CONFIGURED,
                capability_justifications={
                    AttackerCapability.ORACLE_INFLUENCE: (
                        "One fixed constant-product reserve movement inside a local fixture."
                    )
                },
            ),
            financial_settlement=FinancialSettlementProbeSpec(
                actor="attacker",
                asset_kind=FinancialAssetKind.ERC20,
                asset_target=asset_alias,
                action_id=action_id,
                starting_assets=probe("starting_assets"),
                borrowed_assets=probe("borrowed_assets"),
                repaid_assets=probe("repaid_assets"),
                gross_assets_received=probe("gross_assets_received"),
                fees_paid=probe("fees_paid"),
                slippage_loss=probe("slippage_loss"),
                ending_assets=probe("ending_assets"),
                net_impact=probe("net_impact"),
            ),
            assumptions=[
                *invariant.assumptions,
                "The reserve movement preserves one fixed synthetic constant-product value",
                "Spot and protected price getters expose deterministic fixture base units",
                "No temporary borrowing, RPC, external market, or deployed pool is used",
                "Settlement getters record one local actor's exact asset-base-unit impact",
            ][:40],
        ),
        "",
    )


def _liquidation_boundary_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    targets: dict[str, str],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Build one settled healthy-position liquidation boundary transition."""

    del depth
    action = _signature_entity(entities, "liquidationBoundaryPreset()")
    required_getters = {
        "starting_assets": "startingAssets()",
        "borrowed_assets": "borrowedAssets()",
        "repaid_assets": "repaidAssets()",
        "gross_assets_received": "grossAssetsReceived()",
        "fees_paid": "feesPaid()",
        "slippage_loss": "slippageLoss()",
        "ending_assets": "endingAssets()",
        "net_impact": "netImpact()",
        "debt_before": "debtBefore()",
        "collateral_before": "collateralBefore()",
        "debt_after": "debtAfter()",
        "collateral_after": "collateralAfter()",
        "collateral_seized": "collateralSeized()",
        "bad_debt_after": "badDebtAfter()",
    }
    getters = {
        name: _signature_entity(entities, signature) for name, signature in required_getters.items()
    }
    asset_alias = f"{contract_name}Asset"
    if (
        action is None
        or action.id not in invariant.entity_ids
        or any(
            entity is None or (bool(entity.return_types) and entity.return_types != ["uint256"])
            for entity in getters.values()
        )
        or asset_alias not in targets
    ):
        return None, (
            "liquidation execution requires source-linked liquidationBoundaryPreset(), "
            "exact uint256 debt, collateral, bad-debt, and settlement getters, plus "
            "a configured synthetic collateral asset alias"
        )

    def probe(name: str) -> InvariantProbe:
        entity = getters[name]
        assert entity is not None and entity.signature is not None
        return InvariantProbe(target=contract_name, function_signature=entity.signature)

    action_id = "ExecuteHealthyLiquidationBoundary"
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=f"{_harness_name(invariant)}Liquidation",
            actors=_actors(),
            token_balance_seeds=[
                TokenBalanceSeed(
                    token=asset_alias,
                    actor="attacker",
                    amount=10,
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id=action_id,
                    target=contract_name,
                    function_signature="liquidationBoundaryPreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="HealthyPositionPreservesCollateral",
                    left=probe("collateral_after"),
                    relation=InvariantRelation.GTE,
                    right=probe("collateral_before"),
                    required_action_ids=[action_id],
                ),
                InvariantPropertySpec(
                    property_id="HealthyPositionCannotCreateBadDebt",
                    left=probe("bad_debt_after"),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                    required_action_ids=[action_id],
                ),
            ],
            runs=max(1, min(runs, 8)),
            depth=1,
            seed=1,
            economic_template=EconomicSimulationKind.LIQUIDATION,
            capability_policy=AttackerCapabilityPolicy(
                attacker_controlled_actors=["attacker"],
            ),
            financial_settlement=FinancialSettlementProbeSpec(
                actor="attacker",
                asset_kind=FinancialAssetKind.ERC20,
                asset_target=asset_alias,
                action_id=action_id,
                starting_assets=probe("starting_assets"),
                borrowed_assets=probe("borrowed_assets"),
                repaid_assets=probe("repaid_assets"),
                gross_assets_received=probe("gross_assets_received"),
                fees_paid=probe("fees_paid"),
                slippage_loss=probe("slippage_loss"),
                ending_assets=probe("ending_assets"),
                net_impact=probe("net_impact"),
            ),
            lending_boundary=LendingBoundaryProbeSpec(
                action_id=action_id,
                debt_before=probe("debt_before"),
                collateral_before=probe("collateral_before"),
                debt_after=probe("debt_after"),
                collateral_after=probe("collateral_after"),
                collateral_seized=probe("collateral_seized"),
                bad_debt_after=probe("bad_debt_after"),
            ),
            assumptions=[
                *invariant.assumptions,
                "Debt and collateral use one fixed synthetic base-unit scale",
                "The starting position is healthy because collateral covers debt",
                "The action is one public local liquidation-boundary transition",
                "No price movement, loan, RPC, deployed market, or external asset is used",
            ][:40],
        ),
        "",
    )


def _share_price_boundary_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    targets: dict[str, str],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Build one settled yield-adjusted share-price boundary transition."""

    del depth
    action = _signature_entity(entities, "exchangeRateBoundaryPreset()")
    required_getters = {
        "starting_assets": "startingAssets()",
        "borrowed_assets": "borrowedAssets()",
        "repaid_assets": "repaidAssets()",
        "gross_assets_received": "grossAssetsReceived()",
        "fees_paid": "feesPaid()",
        "slippage_loss": "slippageLoss()",
        "ending_assets": "endingAssets()",
        "net_impact": "netImpact()",
        "rate_scale": "rateScale()",
        "total_assets_before": "totalAssetsBefore()",
        "total_shares_before": "totalSharesBefore()",
        "legitimate_yield": "legitimateYield()",
        "expected_rate_after_yield": "expectedRateAfterYield()",
        "observed_rate_after": "observedRateAfter()",
        "shares_redeemed": "sharesRedeemed()",
        "assets_redeemed": "assetsRedeemed()",
        "excess_assets": "excessAssets()",
    }
    getters = {
        name: _signature_entity(entities, signature) for name, signature in required_getters.items()
    }
    asset_alias = f"{contract_name}Asset"
    if (
        action is None
        or action.id not in invariant.entity_ids
        or any(
            entity is None or (bool(entity.return_types) and entity.return_types != ["uint256"])
            for entity in getters.values()
        )
        or asset_alias not in targets
    ):
        return None, (
            "share-price execution requires source-linked exchangeRateBoundaryPreset(), "
            "exact uint256 yield, rate, redemption, and settlement getters, plus a "
            "configured synthetic asset alias"
        )

    def probe(name: str) -> InvariantProbe:
        entity = getters[name]
        assert entity is not None and entity.signature is not None
        return InvariantProbe(target=contract_name, function_signature=entity.signature)

    action_id = "ExecuteYieldAdjustedRateBoundary"
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=f"{_harness_name(invariant)}ShareRate",
            actors=_actors(),
            token_balance_seeds=[
                TokenBalanceSeed(
                    token=asset_alias,
                    actor="attacker",
                    amount=100,
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id=action_id,
                    target=contract_name,
                    function_signature="exchangeRateBoundaryPreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="ReachableRateCannotExceedYieldRate",
                    left=probe("observed_rate_after"),
                    relation=InvariantRelation.LTE,
                    right=probe("expected_rate_after_yield"),
                    required_action_ids=[action_id],
                ),
                InvariantPropertySpec(
                    property_id="RedemptionCannotExceedYieldValue",
                    left=probe("excess_assets"),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                    required_action_ids=[action_id],
                ),
            ],
            runs=max(1, min(runs, 8)),
            depth=1,
            seed=1,
            economic_template=EconomicSimulationKind.SHARE_PRICE,
            capability_policy=AttackerCapabilityPolicy(
                attacker_controlled_actors=["attacker"],
            ),
            financial_settlement=FinancialSettlementProbeSpec(
                actor="attacker",
                asset_kind=FinancialAssetKind.ERC20,
                asset_target=asset_alias,
                action_id=action_id,
                starting_assets=probe("starting_assets"),
                borrowed_assets=probe("borrowed_assets"),
                repaid_assets=probe("repaid_assets"),
                gross_assets_received=probe("gross_assets_received"),
                fees_paid=probe("fees_paid"),
                slippage_loss=probe("slippage_loss"),
                ending_assets=probe("ending_assets"),
                net_impact=probe("net_impact"),
            ),
            share_price_boundary=SharePriceBoundaryProbeSpec(
                action_id=action_id,
                rate_scale=probe("rate_scale"),
                total_assets_before=probe("total_assets_before"),
                total_shares_before=probe("total_shares_before"),
                legitimate_yield=probe("legitimate_yield"),
                expected_rate_after_yield=probe("expected_rate_after_yield"),
                observed_rate_after=probe("observed_rate_after"),
                shares_redeemed=probe("shares_redeemed"),
                assets_redeemed=probe("assets_redeemed"),
                excess_assets=probe("excess_assets"),
            ),
            assumptions=[
                *invariant.assumptions,
                "The actor starts with one fixed synthetic preloaded share position",
                "Legitimate yield is an observed local asset increase",
                "Expected and observed rates share one fixed source-exposed scale",
                "No loan, RPC, deployed vault, market, or external asset is used",
            ][:40],
        ),
        "",
    )


def _governance_delay_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Exercise one declared governance lifecycle before its readiness boundary."""

    signatures = (
        "proposePreset()",
        "votePreset()",
        "queuePreset()",
        "executePreset()",
        "cancelPreset()",
    )
    lifecycle = {signature: _signature_entity(entities, signature) for signature in signatures}
    early_executions = _signature_entity(entities, "earlyExecutions()")
    if (
        any(
            entity is None or entity.id not in invariant.entity_ids for entity in lifecycle.values()
        )
        or early_executions is None
        or early_executions.return_types != ["uint256"]
    ):
        return None, (
            "governance delay execution requires source-linked proposePreset(), votePreset(), "
            "queuePreset(), executePreset(), cancelPreset(), and a uint256 earlyExecutions() getter"
        )
    time_shift_seconds = 3_600
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            setup_calls=[
                ForkCallStep(
                    step_id="ProposeConfiguredAction",
                    actor="attacker",
                    target=contract_name,
                    function_signature="proposePreset()",
                ),
                ForkCallStep(
                    step_id="ApproveConfiguredAction",
                    actor="attacker",
                    target=contract_name,
                    function_signature="votePreset()",
                ),
                ForkCallStep(
                    step_id="QueueConfiguredAction",
                    actor="attacker",
                    target=contract_name,
                    function_signature="queuePreset()",
                ),
            ],
            actions=[
                StatefulActionSpec(
                    action_id="ExecuteBeforeConfiguredDelay",
                    target=contract_name,
                    function_signature="executePreset()",
                    actor_names=["attacker"],
                    time_shift_seconds_before=time_shift_seconds,
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="NoExecutionBeforeConfiguredDelay",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="earlyExecutions()",
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=max(1, min(depth, 1)),
            seed=1,
            economic_template=EconomicSimulationKind.GOVERNANCE_RACE,
            capability_policy=AttackerCapabilityPolicy(
                attacker_controlled_actors=["attacker"],
                max_time_shift_seconds=time_shift_seconds,
                governance_rights=True,
                capability_justifications={
                    AttackerCapability.TIMING: (
                        "One bounded fixture-only move remains below the configured delay."
                    ),
                    AttackerCapability.GOVERNANCE_RIGHTS: (
                        "The synthetic actor has declared proposal and voting rights."
                    ),
                },
            ),
            assumptions=[
                *invariant.assumptions,
                "The preset lifecycle uses only the declared synthetic governance actor",
                "The bounded time move remains below the target's configured readiness delay",
                "earlyExecutions() records only execution before that readiness boundary",
            ][:40],
        ),
        "",
    )


def _upgrade_initializer_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Use only proxy entry-point calls to test authorization and one-time setup."""

    initialize = _signature_entity(entities, "initializePreset()")
    upgrade = _signature_entity(entities, "upgradePreset()")
    invalid_transitions = _signature_entity(entities, "invalidTransitions()")
    if (
        initialize is None
        or initialize.id not in invariant.entity_ids
        or upgrade is None
        or upgrade.id not in invariant.entity_ids
        or invalid_transitions is None
        or invalid_transitions.return_types != ["uint256"]
    ):
        return None, (
            "upgrade execution requires source-linked initializePreset(), upgradePreset(), "
            "and a uint256 invalidTransitions() getter on one proxy target"
        )
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            setup_calls=[
                ForkCallStep(
                    step_id="InitializeProxyOnce",
                    actor="alice",
                    target=contract_name,
                    function_signature="initializePreset()",
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id="RepeatInitializer",
                    target=contract_name,
                    function_signature="initializePreset()",
                    actor_names=["attacker"],
                ),
                StatefulActionSpec(
                    action_id="AttemptUnauthorizedUpgrade",
                    target=contract_name,
                    function_signature="upgradePreset()",
                    actor_names=["attacker"],
                ),
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="OnlyLegitimateProxyTransitions",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="invalidTransitions()",
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=max(1, min(depth, 1)),
            seed=1,
            economic_template=EconomicSimulationKind.UPGRADE_INITIALIZER,
            assumptions=[
                *invariant.assumptions,
                "The setup call initializes the proxy once through its public entry point",
                "Only initializePreset() and upgradePreset() are attacker-reachable",
                "No storage, bytecode, implementation slot, or code is mutated by a cheatcode",
                "invalidTransitions() records repeated initialization or unauthorized upgrade",
            ][:40],
        ),
        "",
    )


def _cross_chain_message_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Replay and reorder only fixed offline messages through one inbound entry point."""

    process = _signature_entity(entities, "processMessagePreset(uint256,bytes32)")
    invalid_transitions = _signature_entity(entities, "invalidMessageTransitions()")
    if (
        process is None
        or process.id not in invariant.entity_ids
        or invalid_transitions is None
        or invalid_transitions.return_types != ["uint256"]
    ):
        return None, (
            "message execution requires source-linked "
            "processMessagePreset(uint256,bytes32) and a uint256 "
            "invalidMessageTransitions() getter"
        )
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            setup_calls=[
                ForkCallStep(
                    step_id="ConsumeFirstOfflineMessage",
                    actor="attacker",
                    target=contract_name,
                    function_signature="processMessagePreset(uint256,bytes32)",
                    arguments=[
                        ForkArgument(kind=ForkArgumentKind.UINT256, value="1"),
                        ForkArgument(kind=ForkArgumentKind.BYTES32, value=_MESSAGE_ONE),
                    ],
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id="ReplayConsumedMessage",
                    target=contract_name,
                    function_signature="processMessagePreset(uint256,bytes32)",
                    actor_names=["attacker"],
                    arguments=[
                        HarnessArgument(
                            kind=ForkArgumentKind.UINT256,
                            source=HarnessArgumentSource.CONSTANT,
                            value="1",
                        ),
                        HarnessArgument(
                            kind=ForkArgumentKind.BYTES32,
                            source=HarnessArgumentSource.CONSTANT,
                            value=_MESSAGE_ONE,
                        ),
                    ],
                ),
                StatefulActionSpec(
                    action_id="ProcessOutOfOrderMessage",
                    target=contract_name,
                    function_signature="processMessagePreset(uint256,bytes32)",
                    actor_names=["attacker"],
                    arguments=[
                        HarnessArgument(
                            kind=ForkArgumentKind.UINT256,
                            source=HarnessArgumentSource.CONSTANT,
                            value="3",
                        ),
                        HarnessArgument(
                            kind=ForkArgumentKind.BYTES32,
                            source=HarnessArgumentSource.CONSTANT,
                            value=_MESSAGE_THREE,
                        ),
                    ],
                ),
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="OnlyNextUnconsumedMessageChangesState",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="invalidMessageTransitions()",
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=max(1, min(depth, 1)),
            seed=1,
            economic_template=EconomicSimulationKind.CROSS_CHAIN_REPLAY,
            capability_policy=AttackerCapabilityPolicy(
                attacker_controlled_actors=["attacker"],
                cross_chain_messages=CrossChainMessageCapability.REORDER_VALID_MESSAGES,
                capability_justifications={
                    AttackerCapability.CROSS_CHAIN_MESSAGE: (
                        "Only fixed fixture-confined offline messages may be replayed or reordered."
                    )
                },
            ),
            assumptions=[
                *invariant.assumptions,
                "The configured actor is a synthetic local messenger",
                "Message identifiers and nonces are fixed fixture values",
                "No relayer, RPC, remote chain, signature, or external transport is accessed",
                "invalidMessageTransitions() records accepted duplicate or out-of-order messages",
            ][:40],
        ),
        "",
    )


def _callback_reentrancy_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Trigger one fixed receiver hook and measure its affected accounting state."""

    withdraw = _signature_entity(entities, "withdrawCallbackPreset()")
    available_credit = _signature_entity(entities, "availableCredit()")
    invalid_transitions = _signature_entity(entities, "invalidCallbackTransitions()")
    if (
        withdraw is None
        or withdraw.id not in invariant.entity_ids
        or available_credit is None
        or available_credit.id not in invariant.entity_ids
        or available_credit.return_types != ["uint256"]
        or invalid_transitions is None
        or invalid_transitions.return_types != ["uint256"]
    ):
        return None, (
            "callback execution requires source-linked withdrawCallbackPreset() and "
            "availableCredit(), plus a uint256 invalidCallbackTransitions() getter"
        )
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            actions=[
                StatefulActionSpec(
                    action_id="TriggerReachableCallback",
                    target=contract_name,
                    function_signature="withdrawCallbackPreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="ReachableCallbackPreservesAvailableCredit",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="invalidCallbackTransitions()",
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=max(1, min(depth, 1)),
            seed=1,
            economic_template=EconomicSimulationKind.CALLBACK_REENTRANCY,
            capability_policy=AttackerCapabilityPolicy(
                attacker_controlled_actors=["attacker"],
                attacker_controlled_contracts=["CallbackReceiver"],
            ),
            assumptions=[
                *invariant.assumptions,
                "Reachable callback: receiver.onCreditReceived()",
                "Affected state: availableCredit",
                "The callback receiver and target are synthetic, preconfigured, and local-only",
                "One action is sufficient to distinguish the unsafe and remediated transitions",
            ][:40],
        ),
        "",
    )


def _state_growth_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Fill one fixed threshold, then permit exactly one bounded growth action."""

    append = _signature_entity(entities, "appendPreset()")
    entry_count = _signature_entity(entities, "entryCount()")
    threshold = _signature_entity(entities, "growthThreshold()")
    if (
        append is None
        or append.id not in invariant.entity_ids
        or entry_count is None
        or entry_count.id not in invariant.entity_ids
        or threshold is None
        or threshold.id not in invariant.entity_ids
    ):
        return None, (
            "state-growth execution requires source-linked appendPreset(), entryCount(), "
            "and growthThreshold() uint256 probes"
        )
    configured_threshold = 4
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            setup_calls=[
                ForkCallStep(
                    step_id=f"FillEntry{index}",
                    actor="attacker",
                    target=contract_name,
                    function_signature="appendPreset()",
                )
                for index in range(1, configured_threshold + 1)
            ],
            actions=[
                StatefulActionSpec(
                    action_id="AppendBeyondConfiguredThreshold",
                    target=contract_name,
                    function_signature="appendPreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="EntryCountWithinGrowthThreshold",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="entryCount()",
                    ),
                    relation=InvariantRelation.LTE,
                    right=InvariantProbe(
                        target=contract_name,
                        function_signature="growthThreshold()",
                    ),
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=max(1, min(depth, 1)),
            seed=1,
            economic_template=EconomicSimulationKind.BOUNDED_STATE_GROWTH,
            assumptions=[
                *invariant.assumptions,
                "The configured synthetic growth threshold is exactly four entries",
                "Four setup calls reach, but do not exceed, the configured threshold",
                "The campaign exposes exactly one additional bounded append action",
                "No unbounded loop, recursive growth, or denial-of-service workload is generated",
            ][:40],
        ),
        "",
    )


def _state_ordering_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Exercise one exact two-transaction transition with a zero-invalid-state bound."""

    del depth
    prepare = _signature_entity(entities, "preparePreset()")
    commit = _signature_entity(entities, "commitPreset()")
    invalid_state = _signature_entity(entities, "invalidState()")
    evidence_ids = set(invariant.entity_ids)
    if (
        prepare is None
        or prepare.id not in evidence_ids
        or commit is None
        or commit.id not in evidence_ids
        or invalid_state is None
        or invalid_state.id not in evidence_ids
    ):
        return None, (
            "multi-step state execution requires source-linked preparePreset(), "
            "commitPreset(), and invalidState() uint256 signatures"
        )
    action_ids = ["PrepareState", "CommitState"]
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["attacker"],
        transaction_ordering=TransactionOrderingCapability.MULTI_TRANSACTION,
        capability_justifications={
            AttackerCapability.TRANSACTION_ORDERING: (
                "Two ordered synthetic local calls are required to validate the state transition"
            )
        },
    )
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=f"{_harness_name(invariant)[:53]}Sequence",
            actors=_actors(),
            actions=[
                StatefulActionSpec(
                    action_id=action_ids[0],
                    target=contract_name,
                    function_signature="preparePreset()",
                    actor_names=["attacker"],
                ),
                StatefulActionSpec(
                    action_id=action_ids[1],
                    target=contract_name,
                    function_signature="commitPreset()",
                    actor_names=["attacker"],
                ),
            ],
            required_action_sequence=action_ids,
            properties=[
                InvariantPropertySpec(
                    property_id="PreparedStateConsumedBeforeFinalization",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="invalidState()",
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                    required_action_ids=action_ids,
                )
            ],
            runs=max(1, min(runs, 32)),
            depth=2,
            seed=18,
            economic_template=EconomicSimulationKind.STATE_ORDERING,
            required_transaction_ordering=TransactionOrderingCapability.MULTI_TRANSACTION,
            capability_policy=policy,
            assumptions=[
                *invariant.assumptions,
                "The retained sequence is exactly PrepareState then CommitState",
                "Each step is one unprivileged synthetic local transaction",
                "Removing either action must leave invalidState() equal to zero",
                "No block, time, RPC, external market, or deployed target is used",
            ][:40],
        ),
        "",
    )


def _signature_replay_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Repeat one preconfigured local authorization and bound its accounted effect."""

    replay_action = next(
        (
            entity
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and entity.visibility in {"public", "external"}
            and entity.signature in {"claimPreset()", "permitPreset()"}
            and entity.id in invariant.entity_ids
        ),
        None,
    )
    accounted_state = next(
        (
            entity
            for signature in (
                "claimed(address)",
                "claimCount(address)",
                "authorizedAmount(address)",
            )
            for entity in entities
            if entity.signature == signature
            and len(entity.return_types) == 1
            and entity.return_types[0] == "uint256"
        ),
        None,
    )
    if replay_action is None or accounted_state is None or accounted_state.signature is None:
        return None, (
            "signature replay execution requires a source-linked claimPreset()/permitPreset() "
            "transition and an address-indexed uint256 accounting getter"
        )
    action_signature = replay_action.signature or "claimPreset()"
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            setup_calls=[
                ForkCallStep(
                    step_id="ConsumeAuthorizationOnce",
                    actor="attacker",
                    target=contract_name,
                    function_signature=action_signature,
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id="ReplayAuthorization",
                    target=contract_name,
                    function_signature=action_signature,
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="AuthorizationConsumedOnce",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature=accounted_state.signature,
                        arguments=[
                            ForkArgument(
                                kind=ForkArgumentKind.ADDRESS,
                                value=_ATTACKER,
                            )
                        ],
                    ),
                    relation=InvariantRelation.LTE,
                    compare_to_initial=True,
                )
            ],
            runs=max(1, min(runs, 16)),
            depth=max(1, min(depth, 4)),
            seed=1,
            economic_template=EconomicSimulationKind.SIGNATURE_REPLAY,
            assumptions=[
                *invariant.assumptions,
                "The pinned local target is preconfigured with one fixture-only authorization",
                "The setup call consumes that authorization before the replay campaign",
                "The harness contains no private key, wallet access, or signing operation",
                "The accounting getter measures the authorized state effect for the actor",
            ][:40],
        ),
        "",
    )


def _ordering_value_bound_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Stage one bounded action, then exercise one declared same-block reorder."""

    stage = next(
        (
            entity
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and entity.visibility in {"public", "external"}
            and entity.signature == "stagePreset()"
            and entity.id in invariant.entity_ids
        ),
        None,
    )
    reorder = next(
        (
            entity
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and entity.visibility in {"public", "external"}
            and entity.signature == "reorderPreset()"
            and entity.id in invariant.entity_ids
        ),
        None,
    )
    shortfall = next(
        (
            entity
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and entity.signature == "shortfall(address)"
            and entity.return_types == ["uint256"]
            and entity.id in invariant.entity_ids
        ),
        None,
    )
    if stage is None or reorder is None or shortfall is None:
        return None, (
            "ordering execution requires source-linked stagePreset(), reorderPreset(), "
            "and shortfall(address) uint256 signatures"
        )
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(include_victim=True),
            setup_calls=[
                ForkCallStep(
                    step_id="StageBoundedAction",
                    actor="victim",
                    target=contract_name,
                    function_signature="stagePreset()",
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id="ReorderSettlement",
                    target=contract_name,
                    function_signature="reorderPreset()",
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="StagedValueBoundPreserved",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature="shortfall(address)",
                        arguments=[
                            ForkArgument(
                                kind=ForkArgumentKind.ADDRESS,
                                value=_VICTIM,
                            )
                        ],
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=0,
                )
            ],
            runs=max(1, min(runs, 8)),
            depth=max(1, min(depth, 1)),
            seed=1,
            economic_template=EconomicSimulationKind.SANDWICH,
            required_transaction_ordering=TransactionOrderingCapability.SAME_BLOCK,
            assumptions=[
                *invariant.assumptions,
                "The victim setup stages the source-linked bounded action before fuzzing",
                "The only attacker transition is the source-linked reorderPreset() call",
                "No time or block movement occurs between staging and reordering",
                "The operator explicitly authorizes same-block transaction ordering",
                "A zero shortfall represents preservation of the staged minimum value",
            ][:40],
        ),
        "",
    )


def _observed_asset_accounting_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    targets: dict[str, str],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Build a fixed observed-balance-versus-claim accounting check."""

    return_handling = invariant.template is InvariantTemplate.ERC20_RETURN_HANDLING
    asset_alias = _asset_target_alias(contract_name, targets)
    deposit = next(
        (
            _signature_entity(entities, signature)
            for signature in (
                "deposit(uint256)",
                "deposit(uint256,address)",
                "stake(uint256)",
                "supply(uint256)",
            )
            if _signature_entity(entities, signature) is not None
        ),
        None,
    )
    claim = next(
        (
            _signature_entity(entities, signature)
            for signature in (
                "claimable(address)",
                "credit(address)",
                "shares(address)",
                "depositBalance(address)",
                "balanceOf(address)",
            )
            if _signature_entity(entities, signature) is not None
        ),
        None,
    )
    if asset_alias is None:
        return None, (
            "observed asset accounting requires an operator-pinned asset alias such as "
            f"{contract_name}Asset or Asset"
        )
    if deposit is None or deposit.signature is None or claim is None or claim.signature is None:
        return None, (
            "observed asset accounting requires a supported deposit/stake signature and "
            "an address-indexed claim getter"
        )
    amount = 10**18
    target_address = targets[contract_name]
    deposit_arguments = [
        ForkArgument(kind=ForkArgumentKind.UINT256, value=str(amount)),
    ]
    if deposit.signature == "deposit(uint256,address)":
        deposit_arguments.append(ForkArgument(kind=ForkArgumentKind.ADDRESS, value=_ATTACKER))
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            token_balance_seeds=[
                TokenBalanceSeed(token=asset_alias, actor="attacker", amount=amount),
            ],
            setup_calls=[
                ForkCallStep(
                    step_id="ApproveObservedAsset",
                    actor="attacker",
                    target=asset_alias,
                    function_signature="approve(address,uint256)",
                    arguments=[
                        ForkArgument(
                            kind=ForkArgumentKind.ADDRESS,
                            value=target_address,
                        ),
                        ForkArgument(kind=ForkArgumentKind.UINT256, value=str(amount)),
                    ],
                ),
                ForkCallStep(
                    step_id="DepositObservedAsset",
                    actor="attacker",
                    target=contract_name,
                    function_signature=deposit.signature,
                    arguments=deposit_arguments,
                ),
            ],
            properties=[
                InvariantPropertySpec(
                    property_id=(
                        "ERC20ReturnOutcomePreservesAccounting"
                        if return_handling
                        else "ObservedAssetsCoverClaims"
                    ),
                    left=InvariantProbe(
                        target=asset_alias,
                        function_signature="balanceOf(address)",
                        arguments=[
                            ForkArgument(
                                kind=ForkArgumentKind.ADDRESS,
                                value=target_address,
                            )
                        ],
                    ),
                    relation=InvariantRelation.GTE,
                    right=InvariantProbe(
                        target=contract_name,
                        function_signature=claim.signature,
                        arguments=[
                            ForkArgument(
                                kind=ForkArgumentKind.ADDRESS,
                                value=_ATTACKER,
                            )
                        ],
                    ),
                )
            ],
            runs=max(1, min(runs, 16)),
            depth=max(1, min(depth, 8)),
            seed=1,
            economic_template=EconomicSimulationKind.NON_STANDARD_TOKEN,
            assumptions=[
                *invariant.assumptions,
                (
                    "The asset target is operator-pinned with bounded missing, false, or unusual "
                    "return behavior"
                    if return_handling
                    else "The asset target is operator-pinned and has configured fee or elastic "
                    "behavior"
                ),
                "Token balance seeding occurs only during isolated harness setup",
                "The claim getter is denominated in the configured asset",
            ][:40],
        ),
        "",
    )


def _reward_accounting_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    """Build bounded monotonic-index or one-time-claim reward properties."""

    if invariant.template is InvariantTemplate.REWARD_INDEX_MONOTONIC:
        index = next(
            (
                _signature_entity(entities, signature)
                for signature in (
                    "rewardIndex()",
                    "accPerShare()",
                    "rewardPerShare()",
                )
                if _signature_entity(entities, signature) is not None
            ),
            None,
        )
        action = next(
            (
                _signature_entity(entities, signature)
                for signature in (
                    "resetIndex()",
                    "updateRewards(uint256)",
                    "accrue(uint256)",
                    "stake(uint256)",
                )
                if _signature_entity(entities, signature) is not None
            ),
            None,
        )
        seed_index = next(
            (
                _signature_entity(entities, signature)
                for signature in (
                    "accrue(uint256)",
                    "updateRewards(uint256)",
                )
                if _signature_entity(entities, signature) is not None
            ),
            None,
        )
        if index is None or index.signature is None:
            return None, "reward-index monotonicity requires a zero-argument uint index getter"
        if action is None or action.signature is None:
            return None, "reward-index monotonicity requires a supported indexed transition"
        if seed_index is None or seed_index.signature is None:
            return None, "reward-index monotonicity requires a bounded index setup transition"
        arguments = _action_arguments(action.signature)
        if arguments is None:
            return None, f"{action.signature} uses an unsupported ABI shape"
        amount = 10**18
        return (
            FoundryInvariantHarnessSpec(
                invariant_id=invariant.id,
                name=_harness_name(invariant),
                actors=_actors(),
                setup_calls=[
                    ForkCallStep(
                        step_id="SeedCumulativeRewardIndex",
                        actor="alice",
                        target=contract_name,
                        function_signature=seed_index.signature,
                        arguments=[
                            ForkArgument(kind=ForkArgumentKind.UINT256, value=str(amount)),
                        ],
                    )
                ],
                actions=[
                    StatefulActionSpec(
                        action_id="UpdateRewardIndex",
                        target=contract_name,
                        function_signature=action.signature,
                        actor_names=["attacker"],
                        arguments=arguments,
                    )
                ],
                properties=[
                    InvariantPropertySpec(
                        property_id="RewardIndexDoesNotDecrease",
                        left=InvariantProbe(
                            target=contract_name,
                            function_signature=index.signature,
                        ),
                        relation=InvariantRelation.GTE,
                        compare_to_initial=True,
                    )
                ],
                runs=max(1, min(runs, 32)),
                depth=max(1, min(depth, 16)),
                seed=1,
                economic_template=EconomicSimulationKind.REWARD_INDEX,
                assumptions=[
                    *invariant.assumptions,
                    "The source-linked index getter is cumulative rather than epoch-local",
                    "The bounded action is reachable without undeclared privilege",
                    "The campaign starts from a clean initialized local fixture",
                ][:40],
            ),
            "",
        )

    claim = next(
        (
            _signature_entity(entities, signature)
            for signature in (
                "claim()",
                "claimRewards()",
                "harvest()",
            )
            if _signature_entity(entities, signature) is not None
        ),
        None,
    )
    seed = next(
        (
            _signature_entity(entities, signature)
            for signature in (
                "seedEntitlement(address,uint256)",
                "setEntitlement(address,uint256)",
            )
            if _signature_entity(entities, signature) is not None
        ),
        None,
    )
    paid = next(
        (
            _signature_entity(entities, signature)
            for signature in (
                "rewardsPaid(address)",
                "claimsPaid(address)",
                "claimedAmount(address)",
            )
            if _signature_entity(entities, signature) is not None
        ),
        None,
    )
    if claim is None or claim.signature is None:
        return None, "claim-once requires a supported zero-argument claim transition"
    if seed is None or seed.signature is None:
        return None, "claim-once requires a bounded entitlement setup transition"
    if paid is None or paid.signature is None:
        return None, "claim-once requires an address-indexed cumulative payout getter"
    amount = 10**18
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            setup_calls=[
                ForkCallStep(
                    step_id="SeedFiniteEntitlement",
                    actor="alice",
                    target=contract_name,
                    function_signature=seed.signature,
                    arguments=[
                        ForkArgument(kind=ForkArgumentKind.ADDRESS, value=_ATTACKER),
                        ForkArgument(kind=ForkArgumentKind.UINT256, value=str(amount)),
                    ],
                )
            ],
            actions=[
                StatefulActionSpec(
                    action_id="ClaimFiniteEntitlement",
                    target=contract_name,
                    function_signature=claim.signature,
                    actor_names=["attacker"],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="FiniteEntitlementIsPaidAtMostOnce",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature=paid.signature,
                        arguments=[
                            ForkArgument(kind=ForkArgumentKind.ADDRESS, value=_ATTACKER),
                        ],
                    ),
                    relation=InvariantRelation.LTE,
                    expected_uint=amount,
                )
            ],
            runs=max(1, min(runs, 32)),
            depth=max(2, min(depth, 16)),
            seed=1,
            economic_template=EconomicSimulationKind.REWARD_INDEX,
            assumptions=[
                *invariant.assumptions,
                "The setup transition creates one bounded synthetic entitlement",
                "The cumulative payout getter is denominated in the entitlement unit",
                "Repeated calls execute only in a clean isolated local fixture",
            ][:40],
        ),
        "",
    )


def _erc20_supply_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    supply = _probe_entity(entities, ("totalsupply",), signatures=("totalSupply()",))
    balance = _probe_entity(entities, ("balanceof",), signatures=("balanceOf(address)",))
    action = _action_entity(entities, ("transfer", "mint", "burn"))
    if supply is None or balance is None or action is None or action.signature is None:
        return None, "ERC20 supply, balance, and supported transition signatures were incomplete"
    arguments = _action_arguments(action.signature)
    if arguments is None:
        return None, f"{action.signature} uses an unsupported ABI shape"
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(),
            actions=[
                StatefulActionSpec(
                    action_id=_safe_identifier(action.name),
                    target=contract_name,
                    function_signature=action.signature,
                    actor_names=["alice", "attacker"],
                    actor_fuzz_slot=0,
                    arguments=arguments,
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="SupplyCoversAttackerBalance",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature=supply.signature or "totalSupply()",
                    ),
                    relation=InvariantRelation.GTE,
                    right=InvariantProbe(
                        target=contract_name,
                        function_signature=balance.signature or "balanceOf(address)",
                        arguments=[
                            ForkArgument(
                                kind=ForkArgumentKind.ADDRESS,
                                value=_ATTACKER,
                            )
                        ],
                    ),
                )
            ],
            runs=max(1, runs),
            depth=max(1, depth),
            seed=1,
            assumptions=[
                *invariant.assumptions,
                "The target follows non-rebasing ERC20 balance and totalSupply semantics",
                "The target alias is operator-pinned to the intended deployed token",
            ][:40],
        ),
        "",
    )


def _erc4626_donation_harness(
    invariant: InvariantSpec,
    contract_name: str,
    entities: list[SolidityEntity],
    targets: dict[str, str],
    runs: int,
    depth: int,
) -> tuple[FoundryInvariantHarnessSpec | None, str]:
    asset_alias = _asset_target_alias(contract_name, targets)
    deposit = _signature_entity(entities, "deposit(uint256,address)")
    share_balance = _signature_entity(entities, "balanceOf(address)")
    if asset_alias is None:
        return None, (
            "ERC4626 donation simulation requires an operator-pinned asset token alias "
            f"such as {contract_name}Asset or Asset"
        )
    if deposit is None or share_balance is None:
        return (
            None,
            "ERC4626 deposit(uint256,address) and balanceOf(address) signatures were incomplete",
        )

    attacker_seed = 2 * 10**18
    victim_seed = 10**18
    attacker_deposit = 1
    donation = 10**18
    victim_deposit = 10**18
    vault_address = targets[contract_name]
    return (
        FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=_harness_name(invariant),
            actors=_actors(include_victim=True),
            token_balance_seeds=[
                TokenBalanceSeed(token=asset_alias, actor="attacker", amount=attacker_seed),
                TokenBalanceSeed(token=asset_alias, actor="victim", amount=victim_seed),
            ],
            setup_calls=[
                ForkCallStep(
                    step_id="ApproveAttacker",
                    actor="attacker",
                    target=asset_alias,
                    function_signature="approve(address,uint256)",
                    arguments=[
                        ForkArgument(kind=ForkArgumentKind.ADDRESS, value=vault_address),
                        ForkArgument(kind=ForkArgumentKind.UINT256, value=str(attacker_seed)),
                    ],
                ),
                ForkCallStep(
                    step_id="ApproveVictim",
                    actor="victim",
                    target=asset_alias,
                    function_signature="approve(address,uint256)",
                    arguments=[
                        ForkArgument(kind=ForkArgumentKind.ADDRESS, value=vault_address),
                        ForkArgument(kind=ForkArgumentKind.UINT256, value=str(victim_seed)),
                    ],
                ),
                ForkCallStep(
                    step_id="AttackerSeedDeposit",
                    actor="attacker",
                    target=contract_name,
                    function_signature=deposit.signature or "deposit(uint256,address)",
                    arguments=[
                        ForkArgument(kind=ForkArgumentKind.UINT256, value=str(attacker_deposit)),
                        ForkArgument(kind=ForkArgumentKind.ADDRESS, value=_ATTACKER),
                    ],
                ),
                ForkCallStep(
                    step_id="AttackerDonation",
                    actor="attacker",
                    target=asset_alias,
                    function_signature="transfer(address,uint256)",
                    arguments=[
                        ForkArgument(kind=ForkArgumentKind.ADDRESS, value=vault_address),
                        ForkArgument(kind=ForkArgumentKind.UINT256, value=str(donation)),
                    ],
                ),
            ],
            actions=[
                StatefulActionSpec(
                    action_id="VictimDeposit",
                    target=contract_name,
                    function_signature=deposit.signature or "deposit(uint256,address)",
                    actor_names=["victim"],
                    arguments=[
                        HarnessArgument(
                            kind=ForkArgumentKind.UINT256,
                            source=HarnessArgumentSource.CONSTANT,
                            value=str(victim_deposit),
                        ),
                        HarnessArgument(
                            kind=ForkArgumentKind.ADDRESS,
                            source=HarnessArgumentSource.CONSTANT,
                            value=_VICTIM,
                        ),
                    ],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="VictimReceivesShares",
                    left=InvariantProbe(
                        target=contract_name,
                        function_signature=share_balance.signature or "balanceOf(address)",
                        arguments=[
                            ForkArgument(kind=ForkArgumentKind.ADDRESS, value=_VICTIM),
                        ],
                    ),
                    relation=InvariantRelation.GTE,
                    expected_uint=1,
                    required_action_ids=["VictimDeposit"],
                )
            ],
            runs=max(1, min(runs, 16)),
            depth=1,
            seed=1,
            economic_template=EconomicSimulationKind.ERC4626_DONATION,
            assumptions=[
                *invariant.assumptions,
                "The vault target alias is operator-pinned to the ERC4626 vault at the pinned fork block",
                "The asset token alias is operator-pinned to the ERC4626 underlying asset",
                "Forge stdstore token balance seeding is valid for the asset token on the local fork",
                "The generated sequence models a first-depositor donation/inflation attack only",
            ][:40],
        ),
        "",
    )


def _action_for_template(
    invariant: InvariantSpec,
    entities: list[SolidityEntity],
) -> SolidityEntity | None:
    if invariant.template is None:
        return None
    keywords = {
        InvariantTemplate.AUTHORIZED_UPGRADE: ("upgrade", "implementation"),
        InvariantTemplate.AUTHORIZED_ADMIN_CHANGE: (
            "set",
            "pause",
            "unpause",
            "rescue",
            "sweep",
            "ownership",
            "grantrole",
            "revokerole",
        ),
        InvariantTemplate.NO_FREE_MINT: ("mint",),
        InvariantTemplate.INITIALIZE_ONCE: ("initialize", "reinitialize"),
        InvariantTemplate.REWARD_INDEX_MONOTONIC: (
            "claim",
            "stake",
            "deposit",
            "update",
        ),
    }.get(invariant.template)
    if keywords is None:
        return None
    related = [
        entity
        for entity in entities
        if entity.id in invariant.entity_ids
        and entity.kind is SolidityEntityKind.FUNCTION
        and entity.visibility in {"public", "external"}
        and entity.signature
    ]
    return related[0] if related else _action_entity(entities, keywords)


def _baseline_probe(
    invariant: InvariantSpec,
    entities: list[SolidityEntity],
) -> tuple[InvariantProbe | None, InvariantRelation | None]:
    if invariant.template is InvariantTemplate.AUTHORIZED_UPGRADE:
        entity = _probe_entity(entities, ("implementation", "owner", "admin"))
        relation = InvariantRelation.EQ
    elif invariant.template is InvariantTemplate.AUTHORIZED_ADMIN_CHANGE:
        function_name = invariant.functions[0].lower() if invariant.functions else ""
        preferred = (
            function_name.removeprefix("set"),
            "paused" if "pause" in function_name else "",
            "owner" if "ownership" in function_name else "",
            "oracle",
            "fee",
            "treasury",
            "strategy",
        )
        entity = _probe_entity(entities, tuple(value for value in preferred if value))
        relation = InvariantRelation.EQ
    elif invariant.template is InvariantTemplate.NO_FREE_MINT:
        entity = _probe_entity(entities, ("totalsupply",))
        relation = InvariantRelation.EQ
    elif invariant.template is InvariantTemplate.INITIALIZE_ONCE:
        entity = _probe_entity(entities, ("owner", "admin", "initialized"))
        relation = InvariantRelation.EQ
    elif invariant.template is InvariantTemplate.REWARD_INDEX_MONOTONIC:
        entity = _probe_entity(
            entities,
            ("rewardindex", "accpershare", "rewardpershare"),
        )
        relation = InvariantRelation.GTE
    else:
        return None, None
    if entity is None or entity.signature is None:
        return None, None
    return (
        InvariantProbe(target=entity.contract_name or "", function_signature=entity.signature),
        relation,
    )


def _probe_entity(
    entities: list[SolidityEntity],
    preferred_names: tuple[str, ...],
    *,
    signatures: tuple[str, ...] = (),
) -> SolidityEntity | None:
    normalized = [value.lower() for value in preferred_names]
    candidates = [
        entity
        for entity in entities
        if entity.signature
        and _signature_arguments(entity.signature) == []
        and len(entity.return_types) == 1
        and entity.return_types[0]
        in {
            "uint256",
            "address",
            "bool",
            "bytes32",
        }
    ]
    if signatures:
        exact = next((entity for entity in entities if entity.signature in signatures), None)
        if exact is not None:
            return exact
    return next(
        (
            entity
            for preferred in normalized
            for entity in candidates
            if preferred and preferred in entity.name.lower()
        ),
        None,
    )


def _action_entity(
    entities: list[SolidityEntity],
    keywords: tuple[str, ...],
) -> SolidityEntity | None:
    return next(
        (
            entity
            for keyword in keywords
            for entity in entities
            if entity.kind is SolidityEntityKind.FUNCTION
            and entity.visibility in {"public", "external"}
            and entity.signature
            and keyword in entity.name.lower()
            and _action_arguments(entity.signature) is not None
        ),
        None,
    )


def _signature_entity(
    entities: list[SolidityEntity],
    signature: str,
) -> SolidityEntity | None:
    return next((entity for entity in entities if entity.signature == signature), None)


def _asset_target_alias(contract_name: str, targets: dict[str, str]) -> str | None:
    candidates = (
        f"{contract_name}Asset",
        f"{contract_name}Token",
        "Asset",
        "Underlying",
        "Token",
    )
    return next((candidate for candidate in candidates if candidate in targets), None)


def _action_arguments(signature: str) -> list[HarnessArgument] | None:
    kinds = _signature_arguments(signature)
    if kinds is None:
        return None
    arguments: list[HarnessArgument] = []
    fuzz_slot = 1
    for kind in kinds:
        if kind is ForkArgumentKind.UINT256:
            if fuzz_slot > 7:
                return None
            arguments.append(
                HarnessArgument(
                    kind=kind,
                    source=HarnessArgumentSource.FUZZ_UINT,
                    minimum=0,
                    maximum=10**24,
                    fuzz_slot=fuzz_slot,
                )
            )
            fuzz_slot += 1
        elif kind is ForkArgumentKind.ADDRESS:
            if fuzz_slot > 7:
                return None
            arguments.append(
                HarnessArgument(
                    kind=kind,
                    source=HarnessArgumentSource.ACTOR,
                    fuzz_slot=fuzz_slot,
                )
            )
            fuzz_slot += 1
        else:
            value = {
                ForkArgumentKind.INT256: "0",
                ForkArgumentKind.BOOL: "false",
                ForkArgumentKind.BYTES32: "0x" + ("00" * 32),
                ForkArgumentKind.BYTES: "0x",
                ForkArgumentKind.STRING: "mmaudit",
            }[kind]
            arguments.append(
                HarnessArgument(
                    kind=kind,
                    source=HarnessArgumentSource.CONSTANT,
                    value=value,
                )
            )
    return arguments


def _signature_arguments(signature: str) -> list[ForkArgumentKind] | None:
    match = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\((?P<arguments>[^()]*)\)", signature)
    if match is None:
        return None
    raw = match.group("arguments")
    if not raw:
        return []
    try:
        return [ForkArgumentKind(value) for value in raw.split(",")]
    except ValueError:
        return None


def _actors(*, include_victim: bool = False) -> list[ForkActor]:
    actors = [
        ForkActor(name="alice", address=_ALICE, initial_native_balance_wei=10**24),
        ForkActor(name="attacker", address=_ATTACKER, initial_native_balance_wei=10**24),
    ]
    if include_victim:
        actors.append(ForkActor(name="victim", address=_VICTIM, initial_native_balance_wei=10**24))
    return actors


def _harness_name(invariant: InvariantSpec) -> str:
    template = invariant.template.value if invariant.template is not None else "Invariant"
    words = re.split(r"[^A-Za-z0-9]+", template)
    stem = "".join(word[:1].upper() + word[1:] for word in words if word)
    return f"Auto{stem[:40]}{invariant.id[-8:]}"


def _safe_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "Action" + cleaned
    return cleaned[:48]
