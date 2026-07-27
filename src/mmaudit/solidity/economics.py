"""Protocol-aware, declarative economic simulation planning."""

from __future__ import annotations

from mmaudit.models.schemas import (
    EconomicSimulationKind,
    EconomicSimulationPlan,
    EconomicSimulationTemplate,
    InvariantSuite,
    InvariantTemplate,
    SolidityGraphKind,
    SolidityGraphSet,
    TransactionOrderingCapability,
)

ECONOMIC_TEMPLATE_REGISTRY: dict[
    EconomicSimulationKind,
    EconomicSimulationTemplate,
] = {
    EconomicSimulationKind.ERC4626_DONATION: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.ERC4626_DONATION,
        title="ERC4626 first-depositor donation/inflation sequence",
        protocol_profiles=["erc4626_vault"],
        required_fixtures=["vault target", "asset token", "victim and attacker actors"],
        attacker_capabilities=["deposit", "direct asset donation", "withdraw/redeem"],
        preconditions=["Share conversion depends on mutable total assets and supply"],
        expected_invariant_violation="Victim receives zero or unfairly diluted shares",
        bounded_parameters={"actors": 3, "sequence_depth": 8, "capital_samples": 32},
        measured_outputs=["shares minted", "assets redeemed", "attacker profit", "victim loss"],
    ),
    EconomicSimulationKind.REWARD_INDEX: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.REWARD_INDEX,
        title="Reward-index manipulation and repeated claim sequence",
        protocol_profiles=["staking", "token_distribution"],
        required_fixtures=["reward contract", "reward token", "multiple actors"],
        attacker_capabilities=["stake", "unstake", "claim", "repeat actions"],
        preconditions=["Rewards use an accumulator, checkpoint, or finite entitlement"],
        expected_invariant_violation="One entitlement is extracted twice or index accounting diverges",
        bounded_parameters={"actors": 4, "sequence_depth": 32, "time_steps": 16},
        measured_outputs=[
            "reward index before/after",
            "rewards paid",
            "entitlement consumed",
            "protocol loss",
        ],
    ),
    EconomicSimulationKind.FLASH_ORACLE: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.FLASH_ORACLE,
        title="Temporary-liquidity oracle manipulation",
        protocol_profiles=["oracle_consumer", "lending", "amm"],
        required_fixtures=["oracle consumer", "liquidity source", "priced asset"],
        attacker_capabilities=["temporary borrow", "price movement", "value-sensitive action"],
        preconditions=["A manipulable price is consumed in the same bounded sequence"],
        expected_invariant_violation="Temporary price movement enables excess extraction",
        bounded_parameters={"liquidity_samples": 32, "price_steps": 16, "sequence_depth": 12},
        measured_outputs=["borrowed capital", "price delta", "fees", "net extraction"],
    ),
    EconomicSimulationKind.ORACLE_GUARDS: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.ORACLE_GUARDS,
        title="Configured oracle guard validation",
        protocol_profiles=["oracle_consumer", "lending"],
        required_fixtures=["oracle consumer", "configurable synthetic feed"],
        attacker_capabilities=["invoke the configured price-sensitive transition"],
        preconditions=[
            "The source configures freshness, decimal-scale, and sequencer availability inputs"
        ],
        expected_invariant_violation=(
            "An invalid configured feed state is accepted without every required guard"
        ),
        bounded_parameters={"configured_scenarios": 2, "sequence_depth": 1},
        measured_outputs=[
            "freshness guard",
            "decimal-scale guard",
            "answer availability guard",
            "sequencer guard",
        ],
    ),
    EconomicSimulationKind.AMM_RESERVES: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.AMM_RESERVES,
        title="AMM reserve manipulation",
        protocol_profiles=["amm", "oracle_consumer"],
        required_fixtures=["pool", "paired assets", "dependent protocol"],
        attacker_capabilities=["swap", "add/remove liquidity", "dependent call"],
        preconditions=["Spot reserves or pool balances influence a security decision"],
        expected_invariant_violation="Manipulated reserve state produces unfair protocol accounting",
        bounded_parameters={"swap_samples": 32, "reserve_ratios": 16, "sequence_depth": 10},
        measured_outputs=["reserve delta", "gross extraction", "fees", "victim loss"],
    ),
    EconomicSimulationKind.LIQUIDATION: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.LIQUIDATION,
        title="Liquidation and solvency boundary sequence",
        protocol_profiles=["lending"],
        required_fixtures=["debt market", "collateral asset", "oracle", "liquidator"],
        attacker_capabilities=["borrow", "repay", "move price", "liquidate"],
        preconditions=["Health and liquidation state can reach the tested boundary"],
        expected_invariant_violation="Liquidation creates bad debt or exceeds permitted collateral",
        bounded_parameters={"health_boundaries": 32, "price_steps": 16, "sequence_depth": 20},
        measured_outputs=["debt", "collateral seized", "bad debt", "liquidator profit"],
    ),
    EconomicSimulationKind.SHARE_PRICE: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.SHARE_PRICE,
        title="Share-price and exchange-rate value boundary",
        protocol_profiles=["erc4626_vault", "amm"],
        required_fixtures=[
            "share accounting target",
            "synthetic asset",
            "preloaded share position",
        ],
        attacker_capabilities=["invoke one source-linked exchange-rate boundary transition"],
        preconditions=["Legitimate yield and attacker-reachable accounting are distinguishable"],
        expected_invariant_violation=(
            "Attacker-reachable accounting creates redemption value beyond legitimate yield"
        ),
        bounded_parameters={"actors": 1, "rate_transitions": 1, "sequence_depth": 1},
        measured_outputs=[
            "assets and shares before",
            "legitimate yield",
            "expected and observed rate",
            "assets redeemed",
            "excess assets",
        ],
    ),
    EconomicSimulationKind.NON_STANDARD_TOKEN: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.NON_STANDARD_TOKEN,
        title="Non-standard token return and balance accounting",
        protocol_profiles=["erc20_token", "erc4626_vault", "staking", "lending", "amm"],
        required_fixtures=["protocol target", "configurable adversarial token"],
        attacker_capabilities=[
            "transfer",
            "deposit",
            "withdraw",
            "select bounded return/fee/rebase behavior",
        ],
        preconditions=[
            "Protocol accounting assumes nominal transfer amounts or unchecked token outcomes"
        ],
        expected_invariant_violation="Internal credits exceed assets actually received",
        bounded_parameters={
            "fee_bps_samples": 16,
            "decimal_samples": 8,
            "return_modes": 4,
            "sequence_depth": 16,
        },
        measured_outputs=[
            "call success",
            "return-data shape",
            "nominal amount",
            "received amount",
            "claim amount",
            "shortfall",
        ],
    ),
    EconomicSimulationKind.ROUNDING: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.ROUNDING,
        title="Repeated rounding-boundary extraction",
        protocol_profiles=["erc4626_vault", "staking", "lending", "amm"],
        required_fixtures=["accounting target", "multiple actors"],
        attacker_capabilities=["repeat smallest-unit state transitions"],
        preconditions=["Conversions or fees use integer division"],
        expected_invariant_violation="Repeated transitions accumulate attacker-favorable value",
        bounded_parameters={"amount_samples": 64, "repetitions": 64, "sequence_depth": 64},
        measured_outputs=["round-trip delta", "cumulative extraction", "victim loss"],
    ),
    EconomicSimulationKind.SIGNATURE_REPLAY: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.SIGNATURE_REPLAY,
        title="Signature nonce and domain replay",
        protocol_profiles=[
            "erc20_token",
            "token_distribution",
            "governance",
            "bridge",
        ],
        required_fixtures=[
            "preconfigured local signature target",
            "fixture-confined synthetic signer",
        ],
        attacker_capabilities=["submit one authorization", "repeat identical authorization"],
        preconditions=["A signature primitive authorizes a source-linked state transition"],
        expected_invariant_violation=(
            "The same authorization changes accounted state more than once"
        ),
        bounded_parameters={"actors": 1, "replays": 2, "sequence_depth": 4},
        measured_outputs=["nonce before/after", "authorized state delta", "domain binding"],
    ),
    EconomicSimulationKind.CROSS_CHAIN_REPLAY: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.CROSS_CHAIN_REPLAY,
        title="Offline duplicate and out-of-order message consumption",
        protocol_profiles=["bridge"],
        required_fixtures=[
            "synthetic inbound message consumer",
            "configured local messenger",
        ],
        attacker_capabilities=[
            "replay one valid message",
            "reorder valid synthetic messages",
        ],
        preconditions=["The inbound transition is source-linked and locally reproducible"],
        expected_invariant_violation=(
            "A duplicate or out-of-order message changes accounted destination state"
        ),
        bounded_parameters={"messages": 3, "sequence_depth": 1},
        measured_outputs=["processed message state", "next nonce", "accounted transitions"],
    ),
    EconomicSimulationKind.CALLBACK_REENTRANCY: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.CALLBACK_REENTRANCY,
        title="Callback and receiver state consistency",
        protocol_profiles=["erc20_token", "erc4626_vault", "staking", "lending"],
        required_fixtures=[
            "source-linked callback target",
            "synthetic controlled receiver",
        ],
        attacker_capabilities=[
            "invoke one public preset transition",
            "execute one bounded receiver callback",
        ],
        preconditions=[
            "An explicit receiver hook is reachable before affected accounting state is consumed"
        ],
        expected_invariant_violation=(
            "One reachable callback reuses accounting state before the outer transition consumes it"
        ),
        bounded_parameters={"controlled_receivers": 1, "sequence_depth": 1},
        measured_outputs=[
            "reachable callback",
            "affected state",
            "settled credit",
            "invalid callback transitions",
        ],
    ),
    EconomicSimulationKind.BOUNDED_STATE_GROWTH: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.BOUNDED_STATE_GROWTH,
        title="Bounded collection growth and iteration safety",
        protocol_profiles=["erc20_token", "staking", "governance", "token_distribution"],
        required_fixtures=[
            "source-linked append transition",
            "configured entry-count threshold",
        ],
        attacker_capabilities=["invoke one bounded public append transition"],
        preconditions=["A public collection append lacks a resolved pre-append length guard"],
        expected_invariant_violation=(
            "The collection exceeds its configured threshold after one bounded append"
        ),
        bounded_parameters={
            "growth_threshold": 4,
            "total_actions": 5,
            "sequence_depth": 1,
        },
        measured_outputs=["entry count", "growth threshold", "bounded action count"],
    ),
    EconomicSimulationKind.STATE_ORDERING: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.STATE_ORDERING,
        title="Bounded multi-transaction state ordering",
        protocol_profiles=["state_machine"],
        required_fixtures=[
            "source-linked prepare transition",
            "source-linked commit transition",
            "invalid-state probe",
        ],
        attacker_capabilities=["submit two ordered unprivileged local transactions"],
        preconditions=["The invalid state requires the exact prepare-then-commit sequence"],
        expected_invariant_violation=(
            "Finalization leaves mutually exclusive prepared and finalized states active"
        ),
        bounded_parameters={"actors": 1, "transactions": 2, "sequence_depth": 2},
        measured_outputs=[
            "campaign seed",
            "shrunk action sequence",
            "single-action removal trials",
            "clean replay outcome",
        ],
    ),
    EconomicSimulationKind.GOVERNANCE_RACE: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.GOVERNANCE_RACE,
        title="Governance/timelock ordering and race sequence",
        protocol_profiles=["governance"],
        required_fixtures=["governor", "timelock", "privileged target"],
        attacker_capabilities=["propose", "vote", "queue", "execute", "cancel"],
        preconditions=["Governance lifecycle and timing are locally reproducible"],
        expected_invariant_violation="A privileged action executes without the intended delay or vote",
        bounded_parameters={"actors": 5, "time_steps": 16, "sequence_depth": 24},
        measured_outputs=["voting power", "delay observed", "privileged effect"],
    ),
    EconomicSimulationKind.UPGRADE_INITIALIZER: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.UPGRADE_INITIALIZER,
        title="Proxy upgrade and initializer misuse",
        protocol_profiles=["upgradeable_system"],
        required_fixtures=["proxy", "implementation", "admin and unprivileged actors"],
        attacker_capabilities=["initialize/reinitialize", "attempt upgrade", "delegatecall"],
        preconditions=["Proxy and implementation addresses are pinned in the local fork"],
        expected_invariant_violation="Unauthorized actor initializes or changes implementation state",
        bounded_parameters={"actors": 3, "upgrade_variants": 8, "sequence_depth": 12},
        measured_outputs=["implementation slot", "admin state", "ownership state"],
    ),
    EconomicSimulationKind.SANDWICH: EconomicSimulationTemplate(
        kind=EconomicSimulationKind.SANDWICH,
        title="Same-block ordering-sensitive value-bound sequence",
        protocol_profiles=["erc4626_vault", "amm", "lending"],
        required_fixtures=["staged value-bound action", "bounded reorder transition"],
        attacker_capabilities=["declared same-block transaction ordering"],
        preconditions=["A source-linked staged transition can be reordered before settlement"],
        expected_invariant_violation="Ordering settles below the staged minimum value",
        bounded_parameters={"actors": 2, "orderings": 1, "sequence_depth": 2},
        measured_outputs=["staged minimum", "settled value", "value shortfall"],
    ),
}
_TYPED_FOUNDRY_HARNESS_TEMPLATES = frozenset(
    {
        EconomicSimulationKind.CROSS_CHAIN_REPLAY,
        EconomicSimulationKind.CALLBACK_REENTRANCY,
        EconomicSimulationKind.BOUNDED_STATE_GROWTH,
        EconomicSimulationKind.STATE_ORDERING,
        EconomicSimulationKind.ERC4626_DONATION,
        EconomicSimulationKind.FLASH_ORACLE,
        EconomicSimulationKind.AMM_RESERVES,
        EconomicSimulationKind.LIQUIDATION,
        EconomicSimulationKind.SHARE_PRICE,
        EconomicSimulationKind.GOVERNANCE_RACE,
        EconomicSimulationKind.NON_STANDARD_TOKEN,
        EconomicSimulationKind.ORACLE_GUARDS,
        EconomicSimulationKind.REWARD_INDEX,
        EconomicSimulationKind.ROUNDING,
        EconomicSimulationKind.SANDWICH,
        EconomicSimulationKind.SIGNATURE_REPLAY,
        EconomicSimulationKind.UPGRADE_INITIALIZER,
    }
)


_INVARIANT_TO_ECONOMIC: dict[InvariantTemplate, set[EconomicSimulationKind]] = {
    InvariantTemplate.OBSERVED_ASSET_ACCOUNTING: {EconomicSimulationKind.NON_STANDARD_TOKEN},
    InvariantTemplate.ERC20_RETURN_HANDLING: {EconomicSimulationKind.NON_STANDARD_TOKEN},
    InvariantTemplate.ERC4626_CONVERSION_SANITY: {
        EconomicSimulationKind.ERC4626_DONATION,
        EconomicSimulationKind.ROUNDING,
        EconomicSimulationKind.SHARE_PRICE,
    },
    InvariantTemplate.DONATION_INFLATION_RESISTANCE: {EconomicSimulationKind.ERC4626_DONATION},
    InvariantTemplate.REWARD_INDEX_MONOTONIC: {EconomicSimulationKind.REWARD_INDEX},
    InvariantTemplate.CLAIM_ONCE: {EconomicSimulationKind.REWARD_INDEX},
    InvariantTemplate.DEBT_COLLATERAL_CONSISTENCY: {EconomicSimulationKind.LIQUIDATION},
    InvariantTemplate.ORACLE_MANIPULATION_RESISTANCE: {
        EconomicSimulationKind.FLASH_ORACLE,
        EconomicSimulationKind.AMM_RESERVES,
    },
    InvariantTemplate.ORACLE_GUARD_SANITY: {EconomicSimulationKind.ORACLE_GUARDS},
    InvariantTemplate.GOVERNANCE_DELAY_SANITY: {EconomicSimulationKind.GOVERNANCE_RACE},
    InvariantTemplate.ROUNDING_BOUNDS: {EconomicSimulationKind.ROUNDING},
    InvariantTemplate.PERMIT_REPLAY_PROTECTION: {EconomicSimulationKind.SIGNATURE_REPLAY},
    InvariantTemplate.ORDERING_VALUE_BOUND: {EconomicSimulationKind.SANDWICH},
    InvariantTemplate.UPGRADE_INITIALIZER_SANITY: {EconomicSimulationKind.UPGRADE_INITIALIZER},
    InvariantTemplate.MESSAGE_CONSUMPTION_ONCE: {EconomicSimulationKind.CROSS_CHAIN_REPLAY},
    InvariantTemplate.CALLBACK_STATE_CONSISTENCY: {EconomicSimulationKind.CALLBACK_REENTRANCY},
    InvariantTemplate.STATE_GROWTH_BOUND: {EconomicSimulationKind.BOUNDED_STATE_GROWTH},
    InvariantTemplate.MULTI_STEP_STATE_CONSISTENCY: {EconomicSimulationKind.STATE_ORDERING},
}


def plan_economic_simulations(
    invariants: InvariantSuite | None,
    graphs: SolidityGraphSet | None,
) -> list[EconomicSimulationPlan]:
    """Select applicable templates from source-linked facts without claiming execution."""

    if invariants is None:
        return []
    profiles = set(invariants.protocol_profiles)
    kinds: set[EconomicSimulationKind] = set()
    invariant_ids: dict[EconomicSimulationKind, list[str]] = {}
    for invariant in invariants.invariants:
        if invariant.template is None:
            continue
        for kind in _INVARIANT_TO_ECONOMIC.get(invariant.template, set()):
            kinds.add(kind)
            invariant_ids.setdefault(kind, []).append(invariant.id)
    if graphs is not None and any(
        edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY for edge in graphs.edges
    ):
        kinds.add(EconomicSimulationKind.FLASH_ORACLE)
    if _non_standard_token_applicable(invariants, graphs):
        kinds.add(EconomicSimulationKind.NON_STANDARD_TOKEN)
    if not _rounding_applicable(invariants):
        kinds.discard(EconomicSimulationKind.ROUNDING)
    if not _reward_index_applicable(invariants):
        kinds.discard(EconomicSimulationKind.REWARD_INDEX)
    if not _liquidation_applicable(invariants):
        kinds.discard(EconomicSimulationKind.LIQUIDATION)
    if not _share_price_applicable(invariants):
        kinds.discard(EconomicSimulationKind.SHARE_PRICE)
    if not _oracle_guards_applicable(invariants, graphs):
        kinds.discard(EconomicSimulationKind.ORACLE_GUARDS)
    if not _governance_race_applicable(invariants, graphs):
        kinds.discard(EconomicSimulationKind.GOVERNANCE_RACE)
    if not _upgrade_initializer_applicable(invariants, graphs):
        kinds.discard(EconomicSimulationKind.UPGRADE_INITIALIZER)
    if not _cross_chain_replay_applicable(invariants, graphs):
        kinds.discard(EconomicSimulationKind.CROSS_CHAIN_REPLAY)
    if not _callback_reentrancy_applicable(invariants, graphs):
        kinds.discard(EconomicSimulationKind.CALLBACK_REENTRANCY)
    if not _bounded_state_growth_applicable(invariants, graphs):
        kinds.discard(EconomicSimulationKind.BOUNDED_STATE_GROWTH)
    if not _state_ordering_applicable(invariants):
        kinds.discard(EconomicSimulationKind.STATE_ORDERING)
    if not _signature_replay_applicable(invariants, graphs):
        kinds.discard(EconomicSimulationKind.SIGNATURE_REPLAY)
    if not _ordering_applicable(invariants):
        kinds.discard(EconomicSimulationKind.SANDWICH)
    for kind, template in ECONOMIC_TEMPLATE_REGISTRY.items():
        if kind is EconomicSimulationKind.NON_STANDARD_TOKEN and not _non_standard_token_applicable(
            invariants, graphs
        ):
            continue
        if kind is EconomicSimulationKind.ROUNDING and not _rounding_applicable(invariants):
            continue
        if kind is EconomicSimulationKind.REWARD_INDEX and not _reward_index_applicable(invariants):
            continue
        if kind is EconomicSimulationKind.LIQUIDATION and not _liquidation_applicable(invariants):
            continue
        if kind is EconomicSimulationKind.SHARE_PRICE and not _share_price_applicable(invariants):
            continue
        if kind is EconomicSimulationKind.ORACLE_GUARDS and not _oracle_guards_applicable(
            invariants, graphs
        ):
            continue
        if kind is EconomicSimulationKind.GOVERNANCE_RACE and not _governance_race_applicable(
            invariants, graphs
        ):
            continue
        if (
            kind is EconomicSimulationKind.UPGRADE_INITIALIZER
            and not _upgrade_initializer_applicable(invariants, graphs)
        ):
            continue
        if kind is EconomicSimulationKind.CROSS_CHAIN_REPLAY and not _cross_chain_replay_applicable(
            invariants, graphs
        ):
            continue
        if (
            kind is EconomicSimulationKind.CALLBACK_REENTRANCY
            and not _callback_reentrancy_applicable(invariants, graphs)
        ):
            continue
        if (
            kind is EconomicSimulationKind.BOUNDED_STATE_GROWTH
            and not _bounded_state_growth_applicable(invariants, graphs)
        ):
            continue
        if kind is EconomicSimulationKind.STATE_ORDERING and not _state_ordering_applicable(
            invariants
        ):
            continue
        if kind is EconomicSimulationKind.SIGNATURE_REPLAY and not _signature_replay_applicable(
            invariants, graphs
        ):
            continue
        if kind is EconomicSimulationKind.SANDWICH and not _ordering_applicable(invariants):
            continue
        if profiles & set(template.protocol_profiles):
            kinds.add(kind)
    plans: list[EconomicSimulationPlan] = []
    invariants_by_id = {invariant.id: invariant for invariant in invariants.invariants}
    for kind in sorted(kinds, key=lambda value: value.value):
        linked_ids = sorted(set(invariant_ids.get(kind, [])))
        locations = [
            location
            for invariant_id in linked_ids
            for location in invariants_by_id[invariant_id].locations
        ]
        template = ECONOMIC_TEMPLATE_REGISTRY[kind]
        typed_harness_available = kind in _TYPED_FOUNDRY_HARNESS_TEMPLATES
        plans.append(
            EconomicSimulationPlan(
                kind=kind,
                applicable=True,
                rationale=(
                    f"Selected from profiles {sorted(profiles & set(template.protocol_profiles))} "
                    f"and {len(linked_ids)} linked source invariant(s)"
                ),
                invariant_ids=linked_ids,
                source_locations=locations[:20],
                typed_harness_available=typed_harness_available,
                execution_required=True,
                required_transaction_ordering=(
                    TransactionOrderingCapability.SAME_BLOCK
                    if kind is EconomicSimulationKind.SANDWICH
                    else TransactionOrderingCapability.MULTI_TRANSACTION
                    if kind is EconomicSimulationKind.STATE_ORDERING
                    else TransactionOrderingCapability.NONE
                ),
                limitations=[
                    _economic_execution_limitation(
                        kind,
                        typed_harness_available=typed_harness_available,
                    )
                ],
            )
        )
    return plans


def _economic_execution_limitation(
    kind: EconomicSimulationKind,
    *,
    typed_harness_available: bool,
) -> str:
    if not typed_harness_available:
        return (
            "No deterministic typed Foundry harness is implemented for this template yet; "
            "selected for model/formal review and coverage tracking only"
        )
    if kind is EconomicSimulationKind.FLASH_ORACLE:
        return (
            "Execution is restricted to synthetic source-local liquidity, "
            "a pinned external compiler, and isolated offline replay"
        )
    if kind is EconomicSimulationKind.AMM_RESERVES:
        return (
            "Execution is restricted to synthetic source-local reserves, "
            "a pinned external compiler, and isolated offline replay"
        )
    if kind is EconomicSimulationKind.LIQUIDATION:
        return (
            "Execution is restricted to synthetic source-local debt and collateral, "
            "a pinned external compiler, and isolated offline replay"
        )
    if kind is EconomicSimulationKind.SHARE_PRICE:
        return (
            "Execution is restricted to synthetic source-local share and asset accounting, "
            "a pinned external compiler, and isolated offline replay"
        )
    if kind is EconomicSimulationKind.STATE_ORDERING:
        return (
            "Execution is restricted to two source-linked synthetic local transactions, "
            "a pinned seed, and isolated clean replay"
        )
    return "Execution requires pinned local fork targets and operator-validated market assumptions"


def _non_standard_token_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require deterministic accounting or asset-flow evidence before selection."""

    if any(
        invariant.template
        in {
            InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
            InvariantTemplate.ERC20_RETURN_HANDLING,
        }
        for invariant in invariants.invariants
    ):
        return True
    return graphs is not None and any(
        edge.graph is SolidityGraphKind.ASSET_FLOW
        and edge.metadata.get("classification") == "member_call"
        and str(edge.metadata.get("member", "")).casefold().replace("_", "")
        in {
            "deposit",
            "safetransferfrom",
            "stake",
            "transferfrom",
        }
        for edge in graphs.edges
    )


def _rounding_applicable(invariants: InvariantSuite) -> bool:
    """Require a source-linked integer-division invariant, not a profile label alone."""

    return any(
        invariant.template is InvariantTemplate.ROUNDING_BOUNDS
        and bool(invariant.locations)
        and bool(invariant.entity_ids)
        for invariant in invariants.invariants
    )


def _reward_index_applicable(invariants: InvariantSuite) -> bool:
    """Require a source-derived reward transition property."""

    return any(
        invariant.template
        in {
            InvariantTemplate.REWARD_INDEX_MONOTONIC,
            InvariantTemplate.CLAIM_ONCE,
        }
        for invariant in invariants.invariants
    )


def _state_ordering_applicable(invariants: InvariantSuite) -> bool:
    """Require the exact source-linked two-step transition and invalid-state probe."""

    return any(
        invariant.template is InvariantTemplate.MULTI_STEP_STATE_CONSISTENCY
        and {
            "preparePreset",
            "commitPreset",
            "invalidState",
        }
        <= {function.removesuffix("()") for function in invariant.functions}
        and bool(invariant.locations)
        and bool(invariant.entity_ids)
        for invariant in invariants.invariants
    )


def _liquidation_applicable(invariants: InvariantSuite) -> bool:
    """Require the exact source-linked local boundary transition before execution."""

    return any(
        invariant.template is InvariantTemplate.DEBT_COLLATERAL_CONSISTENCY
        and any(
            function.casefold() == "liquidationboundarypreset" for function in invariant.functions
        )
        for invariant in invariants.invariants
    )


def _share_price_applicable(invariants: InvariantSuite) -> bool:
    """Require the exact source-linked local rate boundary before execution."""

    return any(
        invariant.template is InvariantTemplate.ERC4626_CONVERSION_SANITY
        and any(
            function.casefold() == "exchangerateboundarypreset" for function in invariant.functions
        )
        for invariant in invariants.invariants
    )


def _oracle_guards_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require a source-linked configured feed with at least one missing guard."""

    entity_ids = {
        entity_id
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.ORACLE_GUARD_SANITY and invariant.locations
        for entity_id in invariant.entity_ids
    }
    if not entity_ids or graphs is None:
        return False
    validation_fields = (
        "freshness_validation",
        "scale_validation",
        "availability_validation",
        "sequencer_validation",
    )
    return any(
        edge.graph is SolidityGraphKind.ORACLE_DEPENDENCY
        and edge.source_id in entity_ids
        and edge.metadata.get("oracle_guard_configuration") == "configured"
        and any(edge.metadata.get(field) != "present" for field in validation_fields)
        for edge in graphs.edges
    )


def _governance_race_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require a rights-guarded lifecycle whose execute stage omits its delay guard."""

    entity_ids = {
        entity_id
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.GOVERNANCE_DELAY_SANITY and invariant.locations
        for entity_id in invariant.entity_ids
    }
    if not entity_ids or graphs is None:
        return False
    return any(
        edge.graph is SolidityGraphKind.GOVERNANCE
        and edge.source_id in entity_ids
        and edge.metadata.get("stage") == "execute"
        and edge.metadata.get("authorization_control") == "present"
        and edge.metadata.get("delay_control") != "present"
        for edge in graphs.edges
    )


def _upgrade_initializer_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require linked unsafe upgrade authorization and initializer guard facts."""

    entity_ids = {
        entity_id
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.UPGRADE_INITIALIZER_SANITY
        and invariant.locations
        for entity_id in invariant.entity_ids
    }
    if len(entity_ids) < 2 or graphs is None:
        return False
    unsafe_upgrade = any(
        edge.graph is SolidityGraphKind.PROXY
        and edge.source_id in entity_ids
        and edge.metadata.get("surface") == "upgrade_or_implementation"
        and edge.metadata.get("authorization_resolution") != "present"
        for edge in graphs.edges
    )
    unsafe_initializer = any(
        edge.graph is SolidityGraphKind.INITIALIZER
        and edge.source_id in entity_ids
        and edge.metadata.get("guard_resolution") == "unknown"
        for edge in graphs.edges
    )
    return unsafe_upgrade and unsafe_initializer


def _cross_chain_replay_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require a linked inbound transition with unresolved replay or ordering guards."""

    entity_ids = {
        entity_id
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.MESSAGE_CONSUMPTION_ONCE and invariant.locations
        for entity_id in invariant.entity_ids
    }
    if not entity_ids or graphs is None:
        return False
    return any(
        edge.graph is SolidityGraphKind.CROSS_CHAIN
        and edge.source_id in entity_ids
        and edge.metadata.get("direction") == "inbound"
        and (
            edge.metadata.get("replay_protection_evidence") != "present"
            or edge.metadata.get("ordering_evidence") != "present"
        )
        for edge in graphs.edges
    )


def _callback_reentrancy_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require one linked public receiver hook and its post-callback affected state."""

    entity_ids = {
        entity_id
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.CALLBACK_STATE_CONSISTENCY
        and invariant.locations
        for entity_id in invariant.entity_ids
    }
    if len(entity_ids) < 2 or graphs is None:
        return False
    return any(
        edge.graph is SolidityGraphKind.REENTRANCY
        and edge.metadata.get("function_id") in entity_ids
        and edge.target_id in entity_ids
        and edge.metadata.get("unsafe_transition_candidate") is True
        and edge.metadata.get("callback_reachability") == "present"
        and edge.metadata.get("callback_kind") == "explicit_receiver_hook"
        and edge.metadata.get("callback_member") == "onCreditReceived"
        and edge.metadata.get("affected_state_name") == "availableCredit"
        for edge in graphs.edges
    )


def _bounded_state_growth_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require a linked public append with no resolved source length guard."""

    entity_ids = {
        entity_id
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.STATE_GROWTH_BOUND and invariant.locations
        for entity_id in invariant.entity_ids
    }
    if len(entity_ids) < 4 or graphs is None:
        return False
    return any(
        edge.graph is SolidityGraphKind.STATE_GROWTH
        and edge.source_id in entity_ids
        and edge.target_id in entity_ids
        and edge.metadata.get("operation") == "array_push"
        and edge.metadata.get("entrypoint_visibility") in {"public", "external"}
        and edge.metadata.get("growth_limit_resolution") != "present"
        for edge in graphs.edges
    )


def _signature_replay_applicable(
    invariants: InvariantSuite,
    graphs: SolidityGraphSet | None,
) -> bool:
    """Require a source-linked signature primitive, not a permit-like name alone."""

    entity_ids = {
        entity_id
        for invariant in invariants.invariants
        if invariant.template is InvariantTemplate.PERMIT_REPLAY_PROTECTION and invariant.locations
        for entity_id in invariant.entity_ids
    }
    if not entity_ids or graphs is None:
        return False
    return any(
        edge.graph is SolidityGraphKind.SIGNATURE_REPLAY
        and edge.source_id in entity_ids
        and edge.metadata.get("aspect") == "signature_primitive"
        for edge in graphs.edges
    )


def _ordering_applicable(invariants: InvariantSuite) -> bool:
    """Require the exact source-linked staged/reorder/value-bound property."""

    return any(
        invariant.template is InvariantTemplate.ORDERING_VALUE_BOUND
        and bool(invariant.locations)
        and len(invariant.entity_ids) >= 3
        for invariant in invariants.invariants
    )
