from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    AnalysisState,
    AttackerCapability,
    AttackerCapabilityPolicy,
    CrossChainMessageCapability,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    ExecutionEvidenceKind,
    FinancialAssetKind,
    FinancialSettlementProbeSpec,
    ForkActor,
    ForkArgument,
    ForkArgumentKind,
    ForkCallStep,
    FoundryInvariantHarnessSpec,
    HarnessArgument,
    InvariantCategory,
    InvariantExecutionMinimizationEvidence,
    InvariantExecutionRemovalTrial,
    InvariantExecutionStatus,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    LendingBoundaryEvidence,
    LendingBoundaryProbeSpec,
    Location,
    OracleInfluenceCapability,
    SharePriceBoundaryEvidence,
    SharePriceBoundaryProbeSpec,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
    StatefulActionSpec,
    TokenBalanceSeed,
    TransactionOrderingCapability,
)
from mmaudit.solidity.invariant_execution import (
    FoundryInvariantRunner,
    _foundry_counterexample_sequence,
    _structured_foundry_invariant_result,
    normalize_foundry_invariant_output,
    translate_foundry_invariant,
)
from mmaudit.solidity.invariant_templates import generate_invariant_harnesses

_ALICE = "0x1000000000000000000000000000000000000001"


class TestIsolationBackend:
    name = "synthetic-test-isolation"

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


class SelfAssertedRealIsolationBackend(TestIsolationBackend):
    """Adversarial injected backend that must not mint real provenance."""

    name = "sandbox-exec"
    execution_evidence = ExecutionEvidenceKind.REAL


def _specification() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-assets",
        name="AssetsRemainBacked",
        actors=[
            ForkActor(
                name="alice",
                address="0x1000000000000000000000000000000000000001",
                initial_native_balance_wei=10**18,
            ),
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
                initial_native_balance_wei=10**18,
            ),
        ],
        actions=[
            StatefulActionSpec(
                action_id="deposit",
                target="Vault",
                function_signature="deposit(uint256,address)",
                actor_names=["alice", "attacker"],
                arguments=[
                    HarnessArgument(
                        kind="uint256",
                        source="fuzz_uint",
                        minimum=1,
                        maximum=10**18,
                        fuzz_slot=0,
                    ),
                    HarnessArgument(
                        kind="address",
                        source="actor",
                        fuzz_slot=1,
                    ),
                ],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="AssetsNonzero",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="totalAssets()",
                ),
                relation="gte",
                expected_uint=0,
            )
        ],
        runs=32,
        depth=8,
        seed=7,
        assumptions=["Vault target is configured at the pinned local fork block"],
    )


def _ordering_specification() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-ordering",
        name="StagedValueBound",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            ),
            ForkActor(
                name="victim",
                address="0x1000000000000000000000000000000000000003",
            ),
        ],
        setup_calls=[
            ForkCallStep(
                step_id="StageBoundedAction",
                actor="victim",
                target="Vault",
                function_signature="stagePreset()",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="ReorderSettlement",
                target="Vault",
                function_signature="reorderPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="StagedValueBoundPreserved",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="shortfall(address)",
                    arguments=[
                        ForkArgument(
                            kind=ForkArgumentKind.ADDRESS,
                            value="0x1000000000000000000000000000000000000003",
                        )
                    ],
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.SANDWICH,
        required_transaction_ordering=TransactionOrderingCapability.SAME_BLOCK,
    )


def _state_ordering_specification() -> FoundryInvariantHarnessSpec:
    action_ids = ["PrepareState", "CommitState"]
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-state-ordering",
        name="PreparedStateConsumedSequence",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id=action_ids[0],
                target="Vault",
                function_signature="preparePreset()",
                actor_names=["attacker"],
            ),
            StatefulActionSpec(
                action_id=action_ids[1],
                target="Vault",
                function_signature="commitPreset()",
                actor_names=["attacker"],
            ),
        ],
        required_action_sequence=action_ids,
        properties=[
            InvariantPropertySpec(
                property_id="PreparedStateConsumedBeforeFinalization",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="invalidState()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
                required_action_ids=action_ids,
            )
        ],
        runs=32,
        depth=2,
        seed=18,
        economic_template=EconomicSimulationKind.STATE_ORDERING,
        required_transaction_ordering=TransactionOrderingCapability.MULTI_TRANSACTION,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            transaction_ordering=TransactionOrderingCapability.MULTI_TRANSACTION,
            capability_justifications={
                AttackerCapability.TRANSACTION_ORDERING: (
                    "Two ordered synthetic calls validate the state transition"
                )
            },
        ),
    )


def _governance_specification() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-governance",
        name="GovernanceDelay",
        actors=[
            ForkActor(
                name="governor",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        setup_calls=[
            ForkCallStep(
                step_id="ProposeConfiguredAction",
                actor="governor",
                target="Governance",
                function_signature="proposePreset()",
            ),
            ForkCallStep(
                step_id="ApproveConfiguredAction",
                actor="governor",
                target="Governance",
                function_signature="votePreset()",
            ),
            ForkCallStep(
                step_id="QueueConfiguredAction",
                actor="governor",
                target="Governance",
                function_signature="queuePreset()",
            ),
        ],
        actions=[
            StatefulActionSpec(
                action_id="ExecuteBeforeConfiguredDelay",
                target="Governance",
                function_signature="executePreset()",
                actor_names=["governor"],
                time_shift_seconds_before=3_600,
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="NoExecutionBeforeConfiguredDelay",
                left=InvariantProbe(
                    target="Governance",
                    function_signature="earlyExecutions()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.GOVERNANCE_RACE,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["governor"],
            max_time_shift_seconds=3_600,
            governance_rights=True,
            capability_justifications={
                AttackerCapability.TIMING: "One bounded pre-delay time move.",
                AttackerCapability.GOVERNANCE_RIGHTS: "Synthetic declared governance rights.",
            },
        ),
    )


def _upgrade_specification() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-upgrade",
        name="UpgradeInitializer",
        actors=[
            ForkActor(
                name="alice",
                address="0x1000000000000000000000000000000000000001",
            ),
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            ),
        ],
        setup_calls=[
            ForkCallStep(
                step_id="InitializeProxyOnce",
                actor="alice",
                target="Proxy",
                function_signature="initializePreset()",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="RepeatInitializer",
                target="Proxy",
                function_signature="initializePreset()",
                actor_names=["attacker"],
            ),
            StatefulActionSpec(
                action_id="AttemptUnauthorizedUpgrade",
                target="Proxy",
                function_signature="upgradePreset()",
                actor_names=["attacker"],
            ),
        ],
        properties=[
            InvariantPropertySpec(
                property_id="OnlyLegitimateProxyTransitions",
                left=InvariantProbe(
                    target="Proxy",
                    function_signature="invalidTransitions()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.UPGRADE_INITIALIZER,
    )


def _cross_chain_specification() -> FoundryInvariantHarnessSpec:
    message_one = "0x" + "01".zfill(64)
    message_three = "0x" + "03".zfill(64)
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-cross-chain",
        name="OfflineMessageConsumption",
        actors=[
            ForkActor(
                name="messenger",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        setup_calls=[
            ForkCallStep(
                step_id="ConsumeFirstOfflineMessage",
                actor="messenger",
                target="Inbox",
                function_signature="processMessagePreset(uint256,bytes32)",
                arguments=[
                    ForkArgument(kind=ForkArgumentKind.UINT256, value="1"),
                    ForkArgument(kind=ForkArgumentKind.BYTES32, value=message_one),
                ],
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="ReplayConsumedMessage",
                target="Inbox",
                function_signature="processMessagePreset(uint256,bytes32)",
                actor_names=["messenger"],
                arguments=[
                    HarnessArgument(
                        kind=ForkArgumentKind.UINT256,
                        source="constant",
                        value="1",
                    ),
                    HarnessArgument(
                        kind=ForkArgumentKind.BYTES32,
                        source="constant",
                        value=message_one,
                    ),
                ],
            ),
            StatefulActionSpec(
                action_id="ProcessOutOfOrderMessage",
                target="Inbox",
                function_signature="processMessagePreset(uint256,bytes32)",
                actor_names=["messenger"],
                arguments=[
                    HarnessArgument(
                        kind=ForkArgumentKind.UINT256,
                        source="constant",
                        value="3",
                    ),
                    HarnessArgument(
                        kind=ForkArgumentKind.BYTES32,
                        source="constant",
                        value=message_three,
                    ),
                ],
            ),
        ],
        properties=[
            InvariantPropertySpec(
                property_id="OnlyNextUnconsumedMessageChangesState",
                left=InvariantProbe(
                    target="Inbox",
                    function_signature="invalidMessageTransitions()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.CROSS_CHAIN_REPLAY,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["messenger"],
            cross_chain_messages=CrossChainMessageCapability.REORDER_VALID_MESSAGES,
            capability_justifications={
                AttackerCapability.CROSS_CHAIN_MESSAGE: (
                    "Only fixed fixture-confined offline messages are reordered."
                )
            },
        ),
    )


def _callback_specification() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-callback",
        name="CallbackStateConsistency",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="TriggerReachableCallback",
                target="CallbackAccounting",
                function_signature="withdrawCallbackPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="ReachableCallbackPreservesAvailableCredit",
                left=InvariantProbe(
                    target="CallbackAccounting",
                    function_signature="invalidCallbackTransitions()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.CALLBACK_REENTRANCY,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            attacker_controlled_contracts=["CallbackReceiver"],
        ),
        assumptions=[
            "Reachable callback: receiver.onCreditReceived()",
            "Affected state: availableCredit",
        ],
    )


def _state_growth_specification() -> FoundryInvariantHarnessSpec:
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-state-growth",
        name="BoundedStateGrowth",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        setup_calls=[
            ForkCallStep(
                step_id=f"FillEntry{index}",
                actor="attacker",
                target="StateGrowth",
                function_signature="appendPreset()",
            )
            for index in range(1, 5)
        ],
        actions=[
            StatefulActionSpec(
                action_id="AppendBeyondConfiguredThreshold",
                target="StateGrowth",
                function_signature="appendPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="EntryCountWithinGrowthThreshold",
                left=InvariantProbe(
                    target="StateGrowth",
                    function_signature="entryCount()",
                ),
                relation=InvariantRelation.LTE,
                right=InvariantProbe(
                    target="StateGrowth",
                    function_signature="growthThreshold()",
                ),
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.BOUNDED_STATE_GROWTH,
    )


def _flash_oracle_specification() -> FoundryInvariantHarnessSpec:
    target = "TemporaryLiquidityOracle"

    def probe(signature: str) -> InvariantProbe:
        return InvariantProbe(target=target, function_signature=signature)

    return FoundryInvariantHarnessSpec(
        invariant_id="inv-temporary-liquidity",
        name="TemporaryLiquiditySettlement",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="ExecuteTemporaryLiquiditySequence",
                target=target,
                function_signature="temporaryLiquidityPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="TemporaryLiquidityCannotCreateExcessExtraction",
                left=probe("excessExtraction()"),
                relation=InvariantRelation.LTE,
                expected_uint=0,
                required_action_ids=["ExecuteTemporaryLiquiditySequence"],
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.FLASH_ORACLE,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            flash_liquidity_wei=1_000,
            oracle_influence=OracleInfluenceCapability.FIXTURE_CONFIGURED,
            capability_justifications={
                AttackerCapability.FLASH_LIQUIDITY: "Fixed synthetic principal.",
                AttackerCapability.ORACLE_INFLUENCE: "Fixed synthetic price preset.",
            },
        ),
        financial_settlement=FinancialSettlementProbeSpec(
            actor="attacker",
            asset_kind=FinancialAssetKind.ERC20,
            asset_target="TemporaryLiquidityOracleAsset",
            action_id="ExecuteTemporaryLiquiditySequence",
            starting_assets=probe("startingAssets()"),
            borrowed_assets=probe("borrowedAssets()"),
            repaid_assets=probe("repaidAssets()"),
            gross_assets_received=probe("grossAssetsReceived()"),
            fees_paid=probe("feesPaid()"),
            slippage_loss=probe("slippageLoss()"),
            ending_assets=probe("endingAssets()"),
            net_impact=probe("netImpact()"),
        ),
    )


def _amm_reserve_specification() -> FoundryInvariantHarnessSpec:
    target = "ReservePricing"

    def probe(signature: str) -> InvariantProbe:
        return InvariantProbe(target=target, function_signature=signature)

    return FoundryInvariantHarnessSpec(
        invariant_id="inv-amm-reserves",
        name="BoundedReservePricing",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="ExecuteBoundedReserveMovement",
                target=target,
                function_signature="reserveMovementPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="ReserveProductPreserved",
                left=probe("reserveProductAfter()"),
                relation=InvariantRelation.EQ,
                right=probe("reserveProductBefore()"),
                required_action_ids=["ExecuteBoundedReserveMovement"],
            ),
            InvariantPropertySpec(
                property_id="SpotMovementCannotCreateExcessExtraction",
                left=probe("excessExtraction()"),
                relation=InvariantRelation.LTE,
                expected_uint=0,
                required_action_ids=["ExecuteBoundedReserveMovement"],
            ),
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.AMM_RESERVES,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            oracle_influence=OracleInfluenceCapability.FIXTURE_CONFIGURED,
            capability_justifications={
                AttackerCapability.ORACLE_INFLUENCE: (
                    "Fixed synthetic constant-product reserve movement."
                )
            },
        ),
        financial_settlement=FinancialSettlementProbeSpec(
            actor="attacker",
            asset_kind=FinancialAssetKind.ERC20,
            asset_target="ReservePricingAsset",
            action_id="ExecuteBoundedReserveMovement",
            starting_assets=probe("startingAssets()"),
            borrowed_assets=probe("borrowedAssets()"),
            repaid_assets=probe("repaidAssets()"),
            gross_assets_received=probe("grossAssetsReceived()"),
            fees_paid=probe("feesPaid()"),
            slippage_loss=probe("slippageLoss()"),
            ending_assets=probe("endingAssets()"),
            net_impact=probe("netImpact()"),
        ),
    )


def _liquidation_specification() -> FoundryInvariantHarnessSpec:
    target = "LiquidationBoundary"

    def probe(signature: str) -> InvariantProbe:
        return InvariantProbe(target=target, function_signature=signature)

    action_id = "ExecuteHealthyLiquidationBoundary"
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-liquidation-boundary",
        name="HealthyPositionLiquidation",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        token_balance_seeds=[
            TokenBalanceSeed(
                token="LiquidationBoundaryAsset",
                actor="attacker",
                amount=10,
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id=action_id,
                target=target,
                function_signature="liquidationBoundaryPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="HealthyPositionPreservesCollateral",
                left=probe("collateralAfter()"),
                relation=InvariantRelation.GTE,
                right=probe("collateralBefore()"),
                required_action_ids=[action_id],
            ),
            InvariantPropertySpec(
                property_id="HealthyPositionCannotCreateBadDebt",
                left=probe("badDebtAfter()"),
                relation=InvariantRelation.LTE,
                expected_uint=0,
                required_action_ids=[action_id],
            ),
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.LIQUIDATION,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
        ),
        financial_settlement=FinancialSettlementProbeSpec(
            actor="attacker",
            asset_kind=FinancialAssetKind.ERC20,
            asset_target="LiquidationBoundaryAsset",
            action_id=action_id,
            starting_assets=probe("startingAssets()"),
            borrowed_assets=probe("borrowedAssets()"),
            repaid_assets=probe("repaidAssets()"),
            gross_assets_received=probe("grossAssetsReceived()"),
            fees_paid=probe("feesPaid()"),
            slippage_loss=probe("slippageLoss()"),
            ending_assets=probe("endingAssets()"),
            net_impact=probe("netImpact()"),
        ),
        lending_boundary=LendingBoundaryProbeSpec(
            action_id=action_id,
            debt_before=probe("debtBefore()"),
            collateral_before=probe("collateralBefore()"),
            debt_after=probe("debtAfter()"),
            collateral_after=probe("collateralAfter()"),
            collateral_seized=probe("collateralSeized()"),
            bad_debt_after=probe("badDebtAfter()"),
        ),
    )


def _share_price_specification() -> FoundryInvariantHarnessSpec:
    target = "ShareRateVault"

    def probe(signature: str) -> InvariantProbe:
        return InvariantProbe(target=target, function_signature=signature)

    action_id = "ExecuteYieldAdjustedRateBoundary"
    return FoundryInvariantHarnessSpec(
        invariant_id="inv-share-rate-boundary",
        name="YieldAdjustedShareRate",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        token_balance_seeds=[
            TokenBalanceSeed(
                token="ShareRateVaultAsset",
                actor="attacker",
                amount=100,
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id=action_id,
                target=target,
                function_signature="exchangeRateBoundaryPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="ReachableRateCannotExceedYieldRate",
                left=probe("observedRateAfter()"),
                relation=InvariantRelation.LTE,
                right=probe("expectedRateAfterYield()"),
                required_action_ids=[action_id],
            ),
            InvariantPropertySpec(
                property_id="RedemptionCannotExceedYieldValue",
                left=probe("excessAssets()"),
                relation=InvariantRelation.LTE,
                expected_uint=0,
                required_action_ids=[action_id],
            ),
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.SHARE_PRICE,
        capability_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
        ),
        financial_settlement=FinancialSettlementProbeSpec(
            actor="attacker",
            asset_kind=FinancialAssetKind.ERC20,
            asset_target="ShareRateVaultAsset",
            action_id=action_id,
            starting_assets=probe("startingAssets()"),
            borrowed_assets=probe("borrowedAssets()"),
            repaid_assets=probe("repaidAssets()"),
            gross_assets_received=probe("grossAssetsReceived()"),
            fees_paid=probe("feesPaid()"),
            slippage_loss=probe("slippageLoss()"),
            ending_assets=probe("endingAssets()"),
            net_impact=probe("netImpact()"),
        ),
        share_price_boundary=SharePriceBoundaryProbeSpec(
            action_id=action_id,
            rate_scale=probe("rateScale()"),
            total_assets_before=probe("totalAssetsBefore()"),
            total_shares_before=probe("totalSharesBefore()"),
            legitimate_yield=probe("legitimateYield()"),
            expected_rate_after_yield=probe("expectedRateAfterYield()"),
            observed_rate_after=probe("observedRateAfter()"),
            shares_redeemed=probe("sharesRedeemed()"),
            assets_redeemed=probe("assetsRedeemed()"),
            excess_assets=probe("excessAssets()"),
        ),
    )


def _project() -> SolidityProjectMetadata:
    return SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault {}\n",
        encoding="utf-8",
    )
    return root


def _entity(
    identifier: str,
    kind: SolidityEntityKind,
    name: str,
    *,
    signature: str | None = None,
    return_types: list[str] | None = None,
    visibility: str | None = None,
    contract_name: str = "Token",
) -> SolidityEntity:
    return SolidityEntity(
        id=identifier,
        kind=kind,
        name=name,
        contract_name=contract_name,
        path=f"src/{contract_name}.sol",
        start_line=1,
        end_line=1,
        byte_start=0,
        byte_end=1,
        source_hash="a" * 64,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="synthetic_test_entity",
        signature=signature,
        return_types=return_types or [],
        visibility=visibility,
    )


def _invariant(
    template: InvariantTemplate,
    entity_ids: list[str],
) -> InvariantSpec:
    return InvariantSpec(
        id=f"inv-{template.value}",
        title=template.value,
        category=InvariantCategory.ACCOUNTING,
        description="Synthetic source-linked invariant.",
        template=template,
        locations=[
            Location(
                path="src/Token.sol",
                start_line=1,
                end_line=1,
                symbol="Token",
                content_hash="a" * 64,
            )
        ],
        entity_ids=entity_ids,
        protocol_profiles=["erc20_token"],
        assumptions=["Synthetic fixture uses standard semantics"],
        provenance=SolidityProvenance.HEURISTIC,
        confidence=0.9,
        template_available=True,
        executable=False,
        analysis_state=AnalysisState.DETERMINISTIC,
        evidence_hash="b" * 64,
    )


def _fake_forge(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _runner(forge: Path) -> FoundryInvariantRunner:
    return FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )


def test_typed_invariant_translates_to_fixed_stateful_foundry_harness() -> None:
    source = translate_foundry_invariant(
        _specification(),
        targets={"Vault": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    assert "targetContract(address(handler))" in source
    assert "function action_deposit(uint256 fuzz0, uint256 fuzz1)" in source
    assert "function invariant_AssetsNonzero()" in source
    assert "bound(fuzz0, 1, 1000000000000000000)" in source
    for forbidden in ("ffi", "broadcast", "privateKey", "vm.sign", "system("):
        assert forbidden not in source


def test_state_ordering_harness_translates_two_guarded_actions() -> None:
    source = translate_foundry_invariant(
        _state_ordering_specification(),
        targets={"Vault": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )

    assert "function action_PrepareState()" in source
    assert "function action_CommitState()" in source
    assert "handler.attempts_PrepareState() == 0" in source
    assert "handler.attempts_CommitState() == 0" in source
    assert "function invariant_PreparedStateConsumedBeforeFinalization()" in source


def test_state_ordering_schema_requires_exact_two_action_sequence() -> None:
    payload = _state_ordering_specification().model_dump(mode="json")
    payload["required_action_sequence"] = ["CommitState", "PrepareState"]

    with pytest.raises(ValidationError, match="two distinct ordered actions"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_foundry_sequence_parser_requires_one_declared_shrunk_sequence() -> None:
    output = "\n".join(
        (
            "[FAIL: prepared state remained active]",
            "[Sequence] (original: 4, shrunk: 2)",
            "sender=0x1 calldata=action_PrepareState() args=[]",
            "sender=0x2 calldata=action_CommitState() args=[]",
            " invariant_PreparedStateConsumedBeforeFinalization() counterexample",
        )
    )

    sequence = _foundry_counterexample_sequence(
        output,
        {"PrepareState", "CommitState"},
    )

    assert sequence is not None
    assert sequence.original_length == 4
    assert sequence.shrunk_length == 2
    assert sequence.action_ids == ["PrepareState", "CommitState"]
    assert _foundry_counterexample_sequence(output, {"PrepareState"}) is None


def test_bounded_action_removal_evidence_round_trips() -> None:
    evidence = InvariantExecutionMinimizationEvidence(
        original_action_ids=["PrepareState", "CommitState"],
        retained_action_ids=["PrepareState", "CommitState"],
        strategy="bounded_action_removal",
        proven_minimal=True,
        foundry_original_sequence_length=4,
        foundry_shrunk_sequence_length=2,
        removal_trials=[
            InvariantExecutionRemovalTrial(
                removed_action_id="PrepareState",
                retained_action_ids=["CommitState"],
                status=InvariantExecutionStatus.PASSED,
                replay_confirmed=True,
                seed=18,
            ),
            InvariantExecutionRemovalTrial(
                removed_action_id="CommitState",
                retained_action_ids=["PrepareState"],
                status=InvariantExecutionStatus.PASSED,
                replay_confirmed=True,
                seed=18,
            ),
        ],
    )

    assert (
        InvariantExecutionMinimizationEvidence.model_validate_json(evidence.model_dump_json())
        == evidence
    )


def test_temporary_liquidity_harness_emits_exact_settlement_validation() -> None:
    source = translate_foundry_invariant(
        _flash_oracle_specification(),
        targets={
            "TemporaryLiquidityOracle": ("0x2000000000000000000000000000000000000002"),
            "TemporaryLiquidityOracleAsset": ("0x3000000000000000000000000000000000000003"),
        },
        expected_chain_id=1,
    )

    assert "function test_MMAuditFinancialSettlement()" in source
    assert "handler.action_ExecuteTemporaryLiquiditySequence();" in source
    assert 'assertEq(repaidAssetsValue, borrowedAssetsValue, "principal not repaid")' in source
    assert "settlementInflows - settlementOutflows" in source
    assert "endingAssetsValue - startingAssetsValue" in source
    assert "MMAUDIT_SETTLEMENT_REPAID_ASSETS" in source
    assert "MMAUDIT_SETTLEMENT_FEES_PAID" in source
    assert "MMAUDIT_SETTLEMENT_SLIPPAGE_LOSS" in source
    assert "MMAUDIT_SETTLEMENT_NET_IMPACT" in source


def test_temporary_liquidity_schema_requires_settlement_and_bounded_policy() -> None:
    payload = _flash_oracle_specification().model_dump(mode="json")
    payload["financial_settlement"] = None
    with pytest.raises(ValidationError, match="require financial settlement"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _flash_oracle_specification().model_dump(mode="json")
    payload["capability_policy"]["flash_liquidity_wei"] = 0
    del payload["capability_policy"]["capability_justifications"]["flash_liquidity"]
    with pytest.raises(ValidationError, match="bounded liquidity"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_amm_reserve_harness_uses_zero_borrow_settlement_and_two_properties() -> None:
    source = translate_foundry_invariant(
        _amm_reserve_specification(),
        targets={
            "ReservePricing": "0x2000000000000000000000000000000000000002",
            "ReservePricingAsset": "0x3000000000000000000000000000000000000003",
        },
        expected_chain_id=1,
    )

    assert "function action_ExecuteBoundedReserveMovement()" in source
    assert "function invariant_ReserveProductPreserved()" in source
    assert "function invariant_SpotMovementCannotCreateExcessExtraction()" in source
    assert 'assertEq(borrowedAssetsValue, 0, "unexpected borrowed assets")' in source
    assert "MMAUDIT_SETTLEMENT_GROSS_ASSETS_RECEIVED" in source
    assert "MMAUDIT_SETTLEMENT_NET_IMPACT" in source


def test_amm_reserve_schema_requires_settlement_and_fixture_only_influence() -> None:
    payload = _amm_reserve_specification().model_dump(mode="json")
    payload["financial_settlement"] = None
    with pytest.raises(ValidationError, match="AMM reserve harnesses require"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _amm_reserve_specification().model_dump(mode="json")
    payload["capability_policy"]["oracle_influence"] = "bounded_market"
    with pytest.raises(ValidationError, match="fixture-configured"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_liquidation_harness_emits_settlement_and_boundary_validation() -> None:
    source = translate_foundry_invariant(
        _liquidation_specification(),
        targets={
            "LiquidationBoundary": "0x2000000000000000000000000000000000000002",
            "LiquidationBoundaryAsset": "0x3000000000000000000000000000000000000003",
        },
        expected_chain_id=1,
    )

    assert "function action_ExecuteHealthyLiquidationBoundary()" in source
    assert "function invariant_HealthyPositionPreservesCollateral()" in source
    assert "function invariant_HealthyPositionCannotCreateBadDebt()" in source
    assert 'assertGe(collateralBeforeValue, debtBeforeValue, "position not healthy")' in source
    assert "collateralBeforeValue - collateralAfterValue" in source
    assert "debtAfterValue - collateralAfterValue : 0" in source
    assert "MMAUDIT_LENDING_DEBT_BEFORE" in source
    assert "MMAUDIT_LENDING_COLLATERAL_BEFORE" in source
    assert "MMAUDIT_LENDING_COLLATERAL_SEIZED" in source
    assert "MMAUDIT_LENDING_BAD_DEBT_AFTER" in source


def test_liquidation_schema_requires_settlement_boundary_and_caller_policy() -> None:
    payload = _liquidation_specification().model_dump(mode="json")
    payload["financial_settlement"] = None
    with pytest.raises(ValidationError, match="financial settlement and lending boundary"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _liquidation_specification().model_dump(mode="json")
    payload["lending_boundary"] = None
    with pytest.raises(ValidationError, match="financial settlement and lending boundary"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _liquidation_specification().model_dump(mode="json")
    payload["capability_policy"] = None
    with pytest.raises(ValidationError, match="declared caller policy"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_lending_boundary_evidence_rejects_inconsistent_bad_debt() -> None:
    with pytest.raises(ValidationError, match="bad debt does not match"):
        LendingBoundaryEvidence(
            debt_before=100,
            collateral_before=150,
            debt_after=100,
            collateral_after=0,
            collateral_seized=150,
            bad_debt_after=0,
        )


def test_share_price_harness_emits_yield_rate_and_settlement_validation() -> None:
    source = translate_foundry_invariant(
        _share_price_specification(),
        targets={
            "ShareRateVault": "0x2000000000000000000000000000000000000002",
            "ShareRateVaultAsset": "0x3000000000000000000000000000000000000003",
        },
        expected_chain_id=1,
    )

    assert "function action_ExecuteYieldAdjustedRateBoundary()" in source
    assert "function invariant_ReachableRateCannotExceedYieldRate()" in source
    assert "function invariant_RedemptionCannotExceedYieldValue()" in source
    assert "mmauditValidateSharePriceBoundary(grossAssetsReceivedValue);" in source
    assert "assetsAfterYield * rateScaleValue / totalSharesBeforeValue," in source
    assert "sharesRedeemedValue * observedRateAfterValue / rateScaleValue," in source
    assert "MMAUDIT_SHARE_LEGITIMATE_YIELD" in source
    assert "MMAUDIT_SHARE_EXPECTED_RATE_AFTER_YIELD" in source
    assert "MMAUDIT_SHARE_OBSERVED_RATE_AFTER" in source
    assert "MMAUDIT_SHARE_EXCESS_ASSETS" in source


def test_share_price_schema_requires_settlement_boundary_and_caller_policy() -> None:
    payload = _share_price_specification().model_dump(mode="json")
    payload["financial_settlement"] = None
    with pytest.raises(ValidationError, match="financial settlement and rate boundary"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _share_price_specification().model_dump(mode="json")
    payload["share_price_boundary"] = None
    with pytest.raises(ValidationError, match="financial settlement and rate boundary"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _share_price_specification().model_dump(mode="json")
    payload["capability_policy"] = None
    with pytest.raises(ValidationError, match="declared caller policy"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_share_price_evidence_rejects_unreconciled_excess_assets() -> None:
    with pytest.raises(ValidationError, match="excess share redemption"):
        SharePriceBoundaryEvidence(
            rate_scale=1_000,
            total_assets_before=1_000,
            total_shares_before=1_000,
            legitimate_yield=100,
            expected_rate_after_yield=1_100,
            observed_rate_after=1_500,
            shares_redeemed=100,
            assets_redeemed=150,
            excess_assets=0,
        )


def test_mocked_temporary_liquidity_runner_normalizes_replayed_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(
        tmp_path / "forge",
        "\n".join(
            (
                "echo 'MMAUDIT_SETTLEMENT_STARTING_ASSETS: 100'",
                "echo 'MMAUDIT_SETTLEMENT_BORROWED_ASSETS: 1000'",
                "echo 'MMAUDIT_SETTLEMENT_REPAID_ASSETS: 1000'",
                "echo 'MMAUDIT_SETTLEMENT_GROSS_ASSETS_RECEIVED: 35'",
                "echo 'MMAUDIT_SETTLEMENT_FEES_PAID: 10'",
                "echo 'MMAUDIT_SETTLEMENT_SLIPPAGE_LOSS: 5'",
                "echo 'MMAUDIT_SETTLEMENT_ENDING_ASSETS: 120'",
                "echo 'MMAUDIT_SETTLEMENT_NET_IMPACT: 20'",
                "exit 0",
            )
        ),
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            repetitions=2,
            max_flash_liquidity_wei=1_000,
            allowed_oracle_influence=OracleInfluenceCapability.FIXTURE_CONFIGURED,
            targets={
                "TemporaryLiquidityOracle": ("0x2000000000000000000000000000000000000002"),
                "TemporaryLiquidityOracleAsset": ("0x3000000000000000000000000000000000000003"),
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_flash_oracle_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.replay_confirmed
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 100
    assert result.economic_metrics.borrowed_capital == 1_000
    assert result.economic_metrics.gross_extraction == 35
    assert result.economic_metrics.fees == 10
    assert result.economic_metrics.net_profit_or_loss == 20
    assert result.economic_metrics.financial_settlement is not None
    assert result.economic_metrics.financial_settlement.repaid_assets == 1_000
    assert result.economic_metrics.financial_settlement.slippage_loss == 5


def test_mocked_temporary_liquidity_runner_fails_closed_without_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(
        tmp_path / "forge",
        "echo 'MMAUDIT_SETTLEMENT_STARTING_ASSETS: 100'\nexit 0",
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            repetitions=2,
            max_flash_liquidity_wei=1_000,
            allowed_oracle_influence=OracleInfluenceCapability.FIXTURE_CONFIGURED,
            targets={
                "TemporaryLiquidityOracle": ("0x2000000000000000000000000000000000000002"),
                "TemporaryLiquidityOracleAsset": ("0x3000000000000000000000000000000000000003"),
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_flash_oracle_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.EXECUTION_FAILED
    assert not result.replay_confirmed
    assert result.economic_metrics is not None
    assert result.economic_metrics.financial_settlement is None
    assert "missing, invalid, or inconsistent" in " ".join(result.limitations)


def test_mocked_amm_reserve_runner_records_settled_spot_impact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(
        tmp_path / "forge",
        "\n".join(
            (
                "echo 'MMAUDIT_SETTLEMENT_STARTING_ASSETS: 100'",
                "echo 'MMAUDIT_SETTLEMENT_BORROWED_ASSETS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_REPAID_ASSETS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_GROSS_ASSETS_RECEIVED: 40'",
                "echo 'MMAUDIT_SETTLEMENT_FEES_PAID: 10'",
                "echo 'MMAUDIT_SETTLEMENT_SLIPPAGE_LOSS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_ENDING_ASSETS: 130'",
                "echo 'MMAUDIT_SETTLEMENT_NET_IMPACT: 30'",
                "echo 'invariant_SpotMovementCannotCreateExcessExtraction() counterexample'",
                "exit 1",
            )
        ),
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            repetitions=2,
            allowed_oracle_influence=OracleInfluenceCapability.FIXTURE_CONFIGURED,
            targets={
                "ReservePricing": "0x2000000000000000000000000000000000000002",
                "ReservePricingAsset": ("0x3000000000000000000000000000000000000003"),
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_amm_reserve_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert result.replay_confirmed
    assert result.economic_metrics is not None
    assert result.economic_metrics.borrowed_capital == 0
    assert result.economic_metrics.gross_extraction == 40
    assert result.economic_metrics.fees == 10
    assert result.economic_metrics.net_profit_or_loss == 30
    assert result.economic_metrics.financial_settlement is not None
    assert result.economic_metrics.financial_settlement.ending_assets == 130
    assert "constant-product reserve movement" in (result.counterexample_summary or "")


def test_mocked_liquidation_runner_normalizes_debt_collateral_and_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(
        tmp_path / "forge",
        "\n".join(
            (
                "echo 'MMAUDIT_SETTLEMENT_STARTING_ASSETS: 10'",
                "echo 'MMAUDIT_SETTLEMENT_BORROWED_ASSETS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_REPAID_ASSETS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_GROSS_ASSETS_RECEIVED: 150'",
                "echo 'MMAUDIT_SETTLEMENT_FEES_PAID: 0'",
                "echo 'MMAUDIT_SETTLEMENT_SLIPPAGE_LOSS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_ENDING_ASSETS: 160'",
                "echo 'MMAUDIT_SETTLEMENT_NET_IMPACT: 150'",
                "echo 'MMAUDIT_LENDING_DEBT_BEFORE: 100'",
                "echo 'MMAUDIT_LENDING_COLLATERAL_BEFORE: 150'",
                "echo 'MMAUDIT_LENDING_DEBT_AFTER: 100'",
                "echo 'MMAUDIT_LENDING_COLLATERAL_AFTER: 0'",
                "echo 'MMAUDIT_LENDING_COLLATERAL_SEIZED: 150'",
                "echo 'MMAUDIT_LENDING_BAD_DEBT_AFTER: 100'",
                "echo 'invariant_HealthyPositionPreservesCollateral() counterexample'",
                "exit 1",
            )
        ),
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            repetitions=2,
            targets={
                "LiquidationBoundary": "0x2000000000000000000000000000000000000002",
                "LiquidationBoundaryAsset": ("0x3000000000000000000000000000000000000003"),
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_liquidation_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert result.replay_confirmed
    assert result.economic_metrics is not None
    assert result.economic_metrics.financial_settlement is not None
    assert result.economic_metrics.financial_settlement.net_impact == 150
    boundary = result.economic_metrics.lending_boundary
    assert boundary is not None
    assert (
        boundary.debt_before,
        boundary.collateral_before,
        boundary.debt_after,
        boundary.collateral_after,
        boundary.collateral_seized,
        boundary.bad_debt_after,
    ) == (100, 150, 100, 0, 150, 100)
    assert result.economic_metrics.maximum_victim_loss == 150
    assert result.economic_metrics.protocol_insolvency == 100
    assert "debt 100 and collateral 150" in (result.counterexample_summary or "")


def test_mocked_share_price_runner_normalizes_yield_rate_and_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(
        tmp_path / "forge",
        "\n".join(
            (
                "echo 'MMAUDIT_SETTLEMENT_STARTING_ASSETS: 100'",
                "echo 'MMAUDIT_SETTLEMENT_BORROWED_ASSETS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_REPAID_ASSETS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_GROSS_ASSETS_RECEIVED: 150'",
                "echo 'MMAUDIT_SETTLEMENT_FEES_PAID: 0'",
                "echo 'MMAUDIT_SETTLEMENT_SLIPPAGE_LOSS: 0'",
                "echo 'MMAUDIT_SETTLEMENT_ENDING_ASSETS: 250'",
                "echo 'MMAUDIT_SETTLEMENT_NET_IMPACT: 150'",
                "echo 'MMAUDIT_SHARE_RATE_SCALE: 1000'",
                "echo 'MMAUDIT_SHARE_TOTAL_ASSETS_BEFORE: 1000'",
                "echo 'MMAUDIT_SHARE_TOTAL_SHARES_BEFORE: 1000'",
                "echo 'MMAUDIT_SHARE_LEGITIMATE_YIELD: 100'",
                "echo 'MMAUDIT_SHARE_EXPECTED_RATE_AFTER_YIELD: 1100'",
                "echo 'MMAUDIT_SHARE_OBSERVED_RATE_AFTER: 1500'",
                "echo 'MMAUDIT_SHARE_SHARES_REDEEMED: 100'",
                "echo 'MMAUDIT_SHARE_ASSETS_REDEEMED: 150'",
                "echo 'MMAUDIT_SHARE_EXCESS_ASSETS: 40'",
                "echo 'invariant_RedemptionCannotExceedYieldValue() counterexample'",
                "exit 1",
            )
        ),
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            repetitions=2,
            targets={
                "ShareRateVault": "0x2000000000000000000000000000000000000002",
                "ShareRateVaultAsset": "0x3000000000000000000000000000000000000003",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_share_price_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert result.replay_confirmed
    assert result.economic_metrics is not None
    assert result.economic_metrics.financial_settlement is not None
    assert result.economic_metrics.financial_settlement.net_impact == 150
    boundary = result.economic_metrics.share_price_boundary
    assert boundary is not None
    assert (
        boundary.total_assets_before,
        boundary.total_shares_before,
        boundary.legitimate_yield,
        boundary.expected_rate_after_yield,
        boundary.observed_rate_after,
        boundary.shares_redeemed,
        boundary.assets_redeemed,
        boundary.excess_assets,
    ) == (1_000, 1_000, 100, 1_100, 1_500, 100, 150, 40)
    assert result.economic_metrics.maximum_victim_loss == 40
    assert "legitimate yield 100" in (result.counterexample_summary or "")
    assert "excess assets 40" in (result.counterexample_summary or "")


def test_mocked_state_ordering_runner_proves_two_action_minimization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(
        tmp_path / "forge",
        "\n".join(
            (
                'case "$*" in',
                "  *PreparedStateConsumedSequenceR1*|*PreparedStateConsumedSequenceR2*) exit 0 ;;",
                "esac",
                "echo '[FAIL: prepared state remained active]'",
                "echo '[Sequence] (original: 2, shrunk: 2)'",
                "echo 'sender=0x1 calldata=action_PrepareState() args=[]'",
                "echo 'sender=0x2 calldata=action_CommitState() args=[]'",
                "echo ' invariant_PreparedStateConsumedBeforeFinalization() counterexample'",
                "exit 1",
            )
        ),
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            repetitions=2,
            allowed_transaction_ordering=(TransactionOrderingCapability.MULTI_TRANSACTION),
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_state_ordering_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert result.replay_confirmed
    assert result.seed == 18
    campaign_coverage = result.campaign_coverage
    assert campaign_coverage is not None
    assert campaign_coverage.declared_action_functions == [
        "commitPreset()",
        "preparePreset()",
    ]
    assert campaign_coverage.observed_action_functions == [
        "commitPreset()",
        "preparePreset()",
    ]
    assert campaign_coverage.declared_state_properties == [
        "PreparedStateConsumedBeforeFinalization"
    ]
    assert campaign_coverage.observed_state_properties == [
        "PreparedStateConsumedBeforeFinalization"
    ]
    assert campaign_coverage.sequence_depth_bound == 2
    assert campaign_coverage.observed_sequence_lengths == [2]
    assert campaign_coverage.minimized_sequence_action_ids == [
        "PrepareState",
        "CommitState",
    ]
    assert campaign_coverage.attempts_consistent
    assert result.minimization_evidence is not None
    assert result.minimization_evidence.proven_minimal
    assert result.minimization_evidence.strategy == "bounded_action_removal"
    assert result.minimization_evidence.retained_action_ids == [
        "PrepareState",
        "CommitState",
    ]
    assert len(result.minimization_evidence.removal_trials) == 2
    assert all(
        trial.status is InvariantExecutionStatus.PASSED
        and trial.replay_confirmed
        and trial.seed == 18
        for trial in result.minimization_evidence.removal_trials
    )
    assert result.economic_metrics is not None
    assert result.economic_metrics.bounded_actions == 2
    assert "seed 18" in (result.counterexample_summary or "")
    assert "PrepareState then CommitState" in (result.counterexample_summary or "")


def test_deterministic_erc20_harness_generation_uses_distinct_actor_fuzzing() -> None:
    entities = [
        _entity("contract-token", SolidityEntityKind.CONTRACT, "Token"),
        _entity(
            "supply",
            SolidityEntityKind.STATE_VARIABLE,
            "totalSupply",
            signature="totalSupply()",
            return_types=["uint256"],
            visibility="public",
        ),
        _entity(
            "balance",
            SolidityEntityKind.STATE_VARIABLE,
            "balanceOf",
            signature="balanceOf(address)",
            return_types=["uint256"],
            visibility="public",
        ),
        _entity(
            "transfer",
            SolidityEntityKind.FUNCTION,
            "transfer",
            signature="transfer(address,uint256)",
            return_types=["bool"],
            visibility="external",
        ),
    ]
    generated = generate_invariant_harnesses(
        InvariantSuite(
            invariants=[
                _invariant(
                    InvariantTemplate.ERC20_SUPPLY_BALANCE,
                    ["supply", "balance", "transfer"],
                )
            ]
        ),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={"Token": "0x2000000000000000000000000000000000000002"},
        economic_plans=[],
        runs=32,
        depth=8,
    )
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    action = harness.actions[0]
    assert action.actor_fuzz_slot == 0
    assert {argument.fuzz_slot for argument in action.arguments} == {1, 2}
    source = translate_foundry_invariant(
        harness,
        targets={"Token": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    assert "fuzz0" in source
    assert "SupplyCoversAttackerBalance" in source


def test_authorization_harness_snapshots_initial_state() -> None:
    entities = [
        _entity("contract-token", SolidityEntityKind.CONTRACT, "Token"),
        _entity(
            "owner",
            SolidityEntityKind.STATE_VARIABLE,
            "owner",
            signature="owner()",
            return_types=["address"],
            visibility="public",
        ),
        _entity(
            "upgrade",
            SolidityEntityKind.FUNCTION,
            "upgradeTo",
            signature="upgradeTo(address)",
            visibility="external",
        ),
    ]
    generated = generate_invariant_harnesses(
        InvariantSuite(
            invariants=[
                _invariant(
                    InvariantTemplate.AUTHORIZED_UPGRADE,
                    ["upgrade"],
                ).model_copy(update={"category": InvariantCategory.AUTHORIZATION})
            ]
        ),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={"Token": "0x2000000000000000000000000000000000000002"},
        economic_plans=[],
        runs=16,
        depth=4,
    )
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.properties[0].compare_to_initial
    source = translate_foundry_invariant(
        harness,
        targets={"Token": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    assert "initial_BaselinePreserved" in source
    assert "assertEq(leftValue, initial_BaselinePreserved" in source


def test_invariant_schema_rejects_model_command_and_signature_injection() -> None:
    payload = _specification().model_dump(mode="json")
    payload["actions"][0]["function_signature"] = "deposit(uint256); curl attacker"
    with pytest.raises(ValidationError):
        FoundryInvariantHarnessSpec.model_validate(payload)
    payload = _specification().model_dump(mode="json")
    payload["command"] = ["sh", "-c", "curl attacker"]
    with pytest.raises(ValidationError):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_invariant_schema_rejects_undeclared_setup_and_seed_actors() -> None:
    with pytest.raises(ValidationError):
        FoundryInvariantHarnessSpec(
            invariant_id="inv",
            name="BadSetup",
            actors=[ForkActor(name="alice", address=_ALICE)],
            setup_calls=[
                ForkCallStep(
                    step_id="Setup",
                    actor="mallory",
                    target="Vault",
                    function_signature="totalAssets()",
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="AssetsNonzero",
                    left=InvariantProbe(target="Vault", function_signature="totalAssets()"),
                    relation="gte",
                    expected_uint=0,
                )
            ],
        )
    payload = _specification().model_dump(mode="json")
    payload["properties"][0]["required_action_ids"] = ["MissingAction"]
    with pytest.raises(ValidationError, match="action guards"):
        FoundryInvariantHarnessSpec.model_validate(payload)
    with pytest.raises(ValidationError):
        FoundryInvariantHarnessSpec(
            invariant_id="inv",
            name="BadSeed",
            actors=[ForkActor(name="alice", address=_ALICE)],
            setup_calls=[
                ForkCallStep(
                    step_id="Setup",
                    actor="alice",
                    target="Vault",
                    function_signature="totalAssets()",
                )
            ],
            token_balance_seeds=[
                TokenBalanceSeed(token="Asset", actor="mallory", amount=1),
            ],
            properties=[
                InvariantPropertySpec(
                    property_id="AssetsNonzero",
                    left=InvariantProbe(target="Vault", function_signature="totalAssets()"),
                    relation="gte",
                    expected_uint=0,
                )
            ],
        )


def test_invariant_translation_rejects_nonliteral_target_addresses() -> None:
    with pytest.raises(ValueError, match="literal EVM addresses"):
        translate_foundry_invariant(
            _specification(),
            targets={"Vault": "address(vm.envAddress('VAULT'))"},
            expected_chain_id=1,
        )


def test_erc4626_donation_template_generates_typed_setup_sequence() -> None:
    entities = [
        _entity("contract-vault", SolidityEntityKind.CONTRACT, "Vault", contract_name="Vault"),
        _entity(
            "deposit",
            SolidityEntityKind.FUNCTION,
            "deposit",
            signature="deposit(uint256,address)",
            return_types=["uint256"],
            visibility="external",
            contract_name="Vault",
        ),
        _entity(
            "shares",
            SolidityEntityKind.FUNCTION,
            "balanceOf",
            signature="balanceOf(address)",
            return_types=["uint256"],
            visibility="public",
            contract_name="Vault",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.DONATION_INFLATION_RESISTANCE,
        ["deposit", "shares"],
    ).model_copy(
        update={
            "protocol_profiles": ["erc4626_vault"],
            "entity_ids": ["deposit", "shares"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "Vault": "0x2000000000000000000000000000000000000002",
            "VaultAsset": "0x3000000000000000000000000000000000000003",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.ERC4626_DONATION,
                applicable=True,
                rationale="test",
                invariant_ids=[invariant.id],
                execution_required=True,
            )
        ],
        runs=32,
        depth=8,
    )
    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.ERC4626_DONATION
    assert [call.step_id for call in harness.setup_calls] == [
        "ApproveAttacker",
        "ApproveVictim",
        "AttackerSeedDeposit",
        "AttackerDonation",
    ]
    assert [action.action_id for action in harness.actions] == ["VictimDeposit"]
    assert harness.properties[0].required_action_ids == ["VictimDeposit"]
    assert harness.depth == 1
    assert {seed.actor for seed in harness.token_balance_seeds} == {"attacker", "victim"}
    source = translate_foundry_invariant(
        harness,
        targets={
            "Vault": "0x2000000000000000000000000000000000000002",
            "VaultAsset": "0x3000000000000000000000000000000000000003",
        },
        expected_chain_id=1,
    )
    assert "deal(target_VaultAsset, 0x1000000000000000000000000000000000000002" in source
    assert 'abi.encodeWithSignature("approve(address,uint256)"' in source
    assert 'abi.encodeWithSignature("deposit(uint256,address)"' in source
    assert 'abi.encodeWithSignature("transfer(address,uint256)"' in source
    assert "function action_VictimDeposit()" in source
    assert "attempts_VictimDeposit += 1;" in source
    assert "if (!success) return;" in source
    assert "function invariant_VictimReceivesShares()" in source
    assert "if (handler.attempts_VictimDeposit() == 0) return;" in source
    assert "targetContract(address(handler))" in source


def test_non_standard_token_template_generates_minimal_observed_balance_check() -> None:
    entities = [
        _entity(
            "contract-vault",
            SolidityEntityKind.CONTRACT,
            "Vault",
            contract_name="Vault",
        ),
        _entity(
            "deposit",
            SolidityEntityKind.FUNCTION,
            "deposit",
            signature="deposit(uint256)",
            visibility="external",
            contract_name="Vault",
        ),
        _entity(
            "claimable",
            SolidityEntityKind.FUNCTION,
            "claimable",
            signature="claimable(address)",
            return_types=["uint256"],
            visibility="external",
            contract_name="Vault",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.OBSERVED_ASSET_ACCOUNTING,
        ["deposit", "claimable"],
    ).model_copy(
        update={
            "entity_ids": ["deposit", "claimable"],
            "protocol_profiles": ["erc20_token"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "Vault": "0x2000000000000000000000000000000000000002",
            "VaultAsset": "0x3000000000000000000000000000000000000003",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.NON_STANDARD_TOKEN,
                applicable=True,
                rationale="Source-linked observed accounting fixture.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=8,
    )
    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.NON_STANDARD_TOKEN
    assert [call.step_id for call in harness.setup_calls] == [
        "ApproveObservedAsset",
        "DepositObservedAsset",
    ]
    assert harness.actions == []
    assert harness.properties[0].property_id == "ObservedAssetsCoverClaims"
    assert harness.properties[0].right is not None
    source = translate_foundry_invariant(
        harness,
        targets={
            "Vault": "0x2000000000000000000000000000000000000002",
            "VaultAsset": "0x3000000000000000000000000000000000000003",
        },
        expected_chain_id=1,
    )
    assert 'abi.encodeWithSignature("deposit(uint256)"' in source
    assert 'abi.encodeWithSignature("balanceOf(address)"' in source
    assert 'abi.encodeWithSignature("claimable(address)"' in source
    assert "assertGe(leftValue, rightValue" in source


def test_malformed_return_template_reuses_observed_balance_typed_property() -> None:
    entities = [
        _entity(
            "contract-vault",
            SolidityEntityKind.CONTRACT,
            "Vault",
            contract_name="Vault",
        ),
        _entity(
            "deposit",
            SolidityEntityKind.FUNCTION,
            "deposit",
            signature="deposit(uint256)",
            visibility="external",
            contract_name="Vault",
        ),
        _entity(
            "credit",
            SolidityEntityKind.FUNCTION,
            "credit",
            signature="credit(address)",
            return_types=["uint256"],
            visibility="external",
            contract_name="Vault",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.ERC20_RETURN_HANDLING,
        ["deposit", "credit"],
    ).model_copy(
        update={
            "entity_ids": ["deposit", "credit"],
            "protocol_profiles": ["erc20_token"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "Vault": "0x2000000000000000000000000000000000000002",
            "VaultAsset": "0x3000000000000000000000000000000000000003",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.NON_STANDARD_TOKEN,
                applicable=True,
                rationale="Source-linked malformed-return fixture.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=8,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.NON_STANDARD_TOKEN
    assert harness.properties[0].property_id == "ERC20ReturnOutcomePreservesAccounting"
    assert any("missing, false, or unusual return" in item for item in harness.assumptions)
    source = translate_foundry_invariant(
        harness,
        targets={
            "Vault": "0x2000000000000000000000000000000000000002",
            "VaultAsset": "0x3000000000000000000000000000000000000003",
        },
        expected_chain_id=1,
    )
    assert "function invariant_ERC20ReturnOutcomePreservesAccounting()" in source
    assert "assertGe(leftValue, rightValue" in source


def test_reward_templates_generate_monotonic_and_claim_once_properties() -> None:
    entities = [
        _entity(
            "contract-rewards",
            SolidityEntityKind.CONTRACT,
            "Rewards",
            contract_name="Rewards",
        ),
        _entity(
            "reward-index",
            SolidityEntityKind.FUNCTION,
            "rewardIndex",
            signature="rewardIndex()",
            return_types=["uint256"],
            visibility="external",
            contract_name="Rewards",
        ),
        _entity(
            "reset-index",
            SolidityEntityKind.FUNCTION,
            "resetIndex",
            signature="resetIndex()",
            visibility="external",
            contract_name="Rewards",
        ),
        _entity(
            "accrue",
            SolidityEntityKind.FUNCTION,
            "accrue",
            signature="accrue(uint256)",
            visibility="external",
            contract_name="Rewards",
        ),
        _entity(
            "claim",
            SolidityEntityKind.FUNCTION,
            "claim",
            signature="claim()",
            visibility="external",
            contract_name="Rewards",
        ),
        _entity(
            "seed-entitlement",
            SolidityEntityKind.FUNCTION,
            "seedEntitlement",
            signature="seedEntitlement(address,uint256)",
            visibility="external",
            contract_name="Rewards",
        ),
        _entity(
            "rewards-paid",
            SolidityEntityKind.FUNCTION,
            "rewardsPaid",
            signature="rewardsPaid(address)",
            return_types=["uint256"],
            visibility="external",
            contract_name="Rewards",
        ),
    ]
    monotonic = _invariant(
        InvariantTemplate.REWARD_INDEX_MONOTONIC,
        ["reward-index", "reset-index", "accrue"],
    )
    claim_once = _invariant(
        InvariantTemplate.CLAIM_ONCE,
        ["claim", "seed-entitlement", "rewards-paid"],
    )
    plan = EconomicSimulationPlan(
        kind=EconomicSimulationKind.REWARD_INDEX,
        applicable=True,
        rationale="Source-linked reward accounting fixture.",
        invariant_ids=[monotonic.id, claim_once.id],
        typed_harness_available=True,
        execution_required=True,
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[monotonic, claim_once]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "Rewards": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[plan],
        runs=32,
        depth=8,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 2
    harnesses = {harness.properties[0].property_id: harness for harness in generated.harnesses}
    monotonic_harness = harnesses["RewardIndexDoesNotDecrease"]
    assert monotonic_harness.setup_calls[0].function_signature == "accrue(uint256)"
    assert monotonic_harness.actions[0].function_signature == "resetIndex()"
    assert monotonic_harness.properties[0].compare_to_initial
    assert monotonic_harness.economic_template is EconomicSimulationKind.REWARD_INDEX
    claim_harness = harnesses["FiniteEntitlementIsPaidAtMostOnce"]
    assert claim_harness.setup_calls[0].function_signature == ("seedEntitlement(address,uint256)")
    assert claim_harness.actions[0].function_signature == "claim()"
    assert claim_harness.depth >= 2
    assert claim_harness.economic_template is EconomicSimulationKind.REWARD_INDEX

    monotonic_source = translate_foundry_invariant(
        monotonic_harness,
        targets={"Rewards": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    claim_source = translate_foundry_invariant(
        claim_harness,
        targets={"Rewards": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    assert "function invariant_RewardIndexDoesNotDecrease()" in monotonic_source
    assert 'abi.encodeWithSignature("accrue(uint256)"' in monotonic_source
    assert "initial_RewardIndexDoesNotDecrease" in monotonic_source
    assert "function invariant_FiniteEntitlementIsPaidAtMostOnce()" in claim_source
    assert 'abi.encodeWithSignature("claim()"' in claim_source
    assert "assertLe(leftValue, 1000000000000000000" in claim_source


def test_rounding_template_generates_loss_tolerant_bounded_round_trip_property() -> None:
    entities = [
        _entity(
            "contract-account",
            SolidityEntityKind.CONTRACT,
            "RoundingAccount",
            contract_name="RoundingAccount",
        ),
        _entity(
            "round-trip",
            SolidityEntityKind.FUNCTION,
            "roundTrip",
            signature="roundTrip(uint256)",
            visibility="external",
            contract_name="RoundingAccount",
        ),
        _entity(
            "credit",
            SolidityEntityKind.STATE_VARIABLE,
            "credit",
            signature="credit(address)",
            return_types=["uint256"],
            visibility="public",
            contract_name="RoundingAccount",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.ROUNDING_BOUNDS,
        ["round-trip"],
    ).model_copy(
        update={
            "category": InvariantCategory.ECONOMIC,
            "entity_ids": ["round-trip"],
            "protocol_profiles": ["amm"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "RoundingAccount": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.ROUNDING,
                applicable=True,
                rationale="Source-linked integer division in an explicit conversion cycle.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=128,
        depth=128,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.ROUNDING
    assert harness.runs == 64
    assert harness.depth == 64
    assert harness.actions[0].function_signature == "roundTrip(uint256)"
    assert harness.actions[0].arguments[0].minimum == 1
    assert harness.properties[0].relation.value == "lte"
    assert harness.properties[0].compare_to_initial
    source = translate_foundry_invariant(
        harness,
        targets={
            "RoundingAccount": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert "initial_NoRoundTripValueCreation" in source
    assert "bound(fuzz0, 1, 1000000000000000000)" in source
    assert "assertLe(leftValue, initial_NoRoundTripValueCreation" in source


def test_oracle_guard_template_generates_fixed_invalid_preset_property() -> None:
    entities = [
        _entity(
            "contract-oracle-guard",
            SolidityEntityKind.CONTRACT,
            "UnsafeOracleGuard",
            contract_name="UnsafeOracleGuard",
        ),
        _entity(
            "configure-preset",
            SolidityEntityKind.FUNCTION,
            "configurePreset",
            signature="configurePreset()",
            visibility="external",
            contract_name="UnsafeOracleGuard",
        ),
        _entity(
            "validate-preset",
            SolidityEntityKind.FUNCTION,
            "validatePreset",
            signature="validatePreset()",
            visibility="external",
            contract_name="UnsafeOracleGuard",
        ),
        _entity(
            "guard-failures",
            SolidityEntityKind.STATE_VARIABLE,
            "guardFailures",
            signature="guardFailures()",
            return_types=["uint256"],
            visibility="public",
            contract_name="UnsafeOracleGuard",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.ORACLE_GUARD_SANITY,
        ["validate-preset"],
    ).model_copy(
        update={
            "category": InvariantCategory.ECONOMIC,
            "entity_ids": ["validate-preset"],
            "protocol_profiles": ["oracle_consumer"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "UnsafeOracleGuard": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.ORACLE_GUARDS,
                applicable=True,
                rationale="A configured source-linked oracle transition omits required guards.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.ORACLE_GUARDS
    assert harness.runs == 8
    assert harness.depth == 1
    assert [call.function_signature for call in harness.setup_calls] == ["configurePreset()"]
    assert [action.function_signature for action in harness.actions] == ["validatePreset()"]
    assert harness.properties[0].left.function_signature == "guardFailures()"
    assert harness.properties[0].expected_uint == 0
    source = translate_foundry_invariant(
        harness,
        targets={
            "UnsafeOracleGuard": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert source.index('abi.encodeWithSignature("configurePreset()"') < source.index(
        "targetContract(address(handler))"
    )
    assert "function action_ValidateConfiguredFeed()" in source
    assert 'abi.encodeWithSignature("guardFailures()"' in source
    assert "assertLe(leftValue, 0" in source


def test_governance_template_uses_declared_rights_and_bounded_time() -> None:
    entities = [
        _entity(
            "contract-governance",
            SolidityEntityKind.CONTRACT,
            "UnsafeGovernanceLifecycle",
            contract_name="UnsafeGovernanceLifecycle",
        ),
        *[
            _entity(
                f"governance-{name}",
                SolidityEntityKind.FUNCTION,
                f"{name}Preset",
                signature=f"{name}Preset()",
                visibility="external",
                contract_name="UnsafeGovernanceLifecycle",
            )
            for name in ("propose", "vote", "queue", "execute", "cancel")
        ],
        _entity(
            "early-executions",
            SolidityEntityKind.STATE_VARIABLE,
            "earlyExecutions",
            signature="earlyExecutions()",
            return_types=["uint256"],
            visibility="public",
            contract_name="UnsafeGovernanceLifecycle",
        ),
    ]
    lifecycle_ids = [
        "governance-propose",
        "governance-vote",
        "governance-queue",
        "governance-execute",
        "governance-cancel",
    ]
    invariant = _invariant(
        InvariantTemplate.GOVERNANCE_DELAY_SANITY,
        lifecycle_ids,
    ).model_copy(
        update={
            "category": InvariantCategory.ECONOMIC,
            "entity_ids": lifecycle_ids,
            "protocol_profiles": ["governance"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "UnsafeGovernanceLifecycle": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.GOVERNANCE_RACE,
                applicable=True,
                rationale="A rights-guarded lifecycle omits its execution-delay guard.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.GOVERNANCE_RACE
    assert harness.runs == 8
    assert harness.depth == 1
    assert [call.function_signature for call in harness.setup_calls] == [
        "proposePreset()",
        "votePreset()",
        "queuePreset()",
    ]
    assert harness.actions[0].function_signature == "executePreset()"
    assert harness.actions[0].time_shift_seconds_before == 3_600
    assert harness.properties[0].left.function_signature == "earlyExecutions()"
    assert harness.properties[0].expected_uint == 0
    assert harness.capability_policy is not None
    assert harness.capability_policy.governance_rights
    assert harness.capability_policy.max_time_shift_seconds == 3_600
    assert set(harness.capability_policy.enabled_capabilities()) == {
        AttackerCapability.TIMING,
        AttackerCapability.GOVERNANCE_RIGHTS,
    }
    source = translate_foundry_invariant(
        harness,
        targets={
            "UnsafeGovernanceLifecycle": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert 'abi.encodeWithSignature("proposePreset()"' in source
    assert "vm.warp(block.timestamp + 3600);" in source
    assert source.index("vm.warp(block.timestamp + 3600);") < source.index(
        'abi.encodeWithSignature("executePreset()"'
    )
    assert "function action_ExecuteBeforeConfiguredDelay()" in source
    assert 'abi.encodeWithSignature("earlyExecutions()"' in source


def test_upgrade_template_uses_only_legitimate_proxy_entry_points() -> None:
    entities = [
        _entity(
            "contract-upgrade",
            SolidityEntityKind.CONTRACT,
            "UnsafeUpgradeProxy",
            contract_name="UnsafeUpgradeProxy",
        ),
        _entity(
            "initialize-preset",
            SolidityEntityKind.FUNCTION,
            "initializePreset",
            signature="initializePreset()",
            visibility="external",
            contract_name="UnsafeUpgradeProxy",
        ),
        _entity(
            "upgrade-preset",
            SolidityEntityKind.FUNCTION,
            "upgradePreset",
            signature="upgradePreset()",
            visibility="external",
            contract_name="UnsafeUpgradeProxy",
        ),
        _entity(
            "invalid-transitions",
            SolidityEntityKind.STATE_VARIABLE,
            "invalidTransitions",
            signature="invalidTransitions()",
            return_types=["uint256"],
            visibility="public",
            contract_name="UnsafeUpgradeProxy",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.UPGRADE_INITIALIZER_SANITY,
        ["initialize-preset", "upgrade-preset"],
    ).model_copy(
        update={
            "category": InvariantCategory.ECONOMIC,
            "entity_ids": ["initialize-preset", "upgrade-preset"],
            "protocol_profiles": ["upgradeable_system"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "UnsafeUpgradeProxy": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.UPGRADE_INITIALIZER,
                applicable=True,
                rationale="A proxy has linked missing authorization and initializer guards.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.UPGRADE_INITIALIZER
    assert harness.runs == 8
    assert harness.depth == 1
    assert [(call.actor, call.function_signature) for call in harness.setup_calls] == [
        ("alice", "initializePreset()")
    ]
    assert {
        (tuple(action.actor_names), action.function_signature) for action in harness.actions
    } == {
        (("attacker",), "initializePreset()"),
        (("attacker",), "upgradePreset()"),
    }
    assert harness.properties[0].left.function_signature == "invalidTransitions()"
    assert harness.properties[0].expected_uint == 0
    source = translate_foundry_invariant(
        harness,
        targets={
            "UnsafeUpgradeProxy": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert 'abi.encodeWithSignature("initializePreset()"' in source
    assert 'abi.encodeWithSignature("upgradePreset()"' in source
    assert "function action_RepeatInitializer()" in source
    assert "function action_AttemptUnauthorizedUpgrade()" in source
    assert all(
        token not in source for token in ("vm.store", "vm.etch", "deployCode", "stdstore", "sstore")
    )


def test_cross_chain_template_uses_only_declared_offline_messages() -> None:
    entities = [
        _entity(
            "contract-inbox",
            SolidityEntityKind.CONTRACT,
            "UnsafeMessageInbox",
            contract_name="UnsafeMessageInbox",
        ),
        _entity(
            "process-message",
            SolidityEntityKind.FUNCTION,
            "processMessagePreset",
            signature="processMessagePreset(uint256,bytes32)",
            visibility="external",
            contract_name="UnsafeMessageInbox",
        ),
        _entity(
            "invalid-message-transitions",
            SolidityEntityKind.STATE_VARIABLE,
            "invalidMessageTransitions",
            signature="invalidMessageTransitions()",
            return_types=["uint256"],
            visibility="public",
            contract_name="UnsafeMessageInbox",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.MESSAGE_CONSUMPTION_ONCE,
        ["process-message"],
    ).model_copy(
        update={
            "category": InvariantCategory.ECONOMIC,
            "entity_ids": ["process-message"],
            "protocol_profiles": ["bridge"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "UnsafeMessageInbox": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.CROSS_CHAIN_REPLAY,
                applicable=True,
                rationale="An inbound message transition omits replay and order guards.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.CROSS_CHAIN_REPLAY
    assert harness.runs == 8
    assert harness.depth == 1
    assert harness.setup_calls[0].function_signature == "processMessagePreset(uint256,bytes32)"
    assert harness.setup_calls[0].arguments[0].value == "1"
    assert {action.action_id for action in harness.actions} == {
        "ReplayConsumedMessage",
        "ProcessOutOfOrderMessage",
    }
    assert {
        tuple(argument.value for argument in action.arguments) for action in harness.actions
    } == {
        ("1", "0x" + "01".zfill(64)),
        ("3", "0x" + "03".zfill(64)),
    }
    assert harness.capability_policy is not None
    assert (
        harness.capability_policy.cross_chain_messages
        is CrossChainMessageCapability.REORDER_VALID_MESSAGES
    )
    source = translate_foundry_invariant(
        harness,
        targets={
            "UnsafeMessageInbox": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert source.count('abi.encodeWithSignature("processMessagePreset(uint256,bytes32)"') == 3
    assert "function action_ReplayConsumedMessage()" in source
    assert "function action_ProcessOutOfOrderMessage()" in source
    assert all(token not in source.casefold() for token in ("http://", "https://", "rpc"))


def test_callback_template_cites_reachable_hook_and_affected_state() -> None:
    entities = [
        _entity(
            "contract-callback",
            SolidityEntityKind.CONTRACT,
            "UnsafeCallbackAccounting",
            contract_name="UnsafeCallbackAccounting",
        ),
        _entity(
            "withdraw-callback",
            SolidityEntityKind.FUNCTION,
            "withdrawCallbackPreset",
            signature="withdrawCallbackPreset()",
            visibility="external",
            contract_name="UnsafeCallbackAccounting",
        ),
        _entity(
            "available-credit",
            SolidityEntityKind.STATE_VARIABLE,
            "availableCredit",
            signature="availableCredit()",
            return_types=["uint256"],
            visibility="public",
            contract_name="UnsafeCallbackAccounting",
        ),
        _entity(
            "invalid-callback-transitions",
            SolidityEntityKind.STATE_VARIABLE,
            "invalidCallbackTransitions",
            signature="invalidCallbackTransitions()",
            return_types=["uint256"],
            visibility="public",
            contract_name="UnsafeCallbackAccounting",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.CALLBACK_STATE_CONSISTENCY,
        ["withdraw-callback", "available-credit"],
    ).model_copy(
        update={
            "category": InvariantCategory.ECONOMIC,
            "entity_ids": ["withdraw-callback", "available-credit"],
            "assumptions": [
                "Reachable callback receiver.onCreditReceived() precedes affected state "
                "availableCredit"
            ],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "UnsafeCallbackAccounting": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.CALLBACK_REENTRANCY,
                applicable=True,
                rationale="A public receiver hook precedes its source-linked accounting write.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.CALLBACK_REENTRANCY
    assert harness.runs == 8
    assert harness.depth == 1
    assert len(harness.actions) == 1
    assert harness.actions[0].function_signature == "withdrawCallbackPreset()"
    assert harness.properties[0].property_id == "ReachableCallbackPreservesAvailableCredit"
    assert harness.properties[0].left.function_signature == "invalidCallbackTransitions()"
    assert harness.capability_policy is not None
    assert harness.capability_policy.attacker_controlled_contracts == ["CallbackReceiver"]
    assert "receiver.onCreditReceived()" in " ".join(harness.assumptions)
    assert "availableCredit" in " ".join(harness.assumptions)
    source = translate_foundry_invariant(
        harness,
        targets={
            "UnsafeCallbackAccounting": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert source.count('abi.encodeWithSignature("withdrawCallbackPreset()")') == 1
    assert "function action_TriggerReachableCallback()" in source
    assert "invariant_ReachableCallbackPreservesAvailableCredit" in source


def test_state_growth_template_has_fixed_threshold_and_one_bounded_action() -> None:
    entities = [
        _entity(
            "contract-growth",
            SolidityEntityKind.CONTRACT,
            "UnsafeStateGrowth",
            contract_name="UnsafeStateGrowth",
        ),
        _entity(
            "append-preset",
            SolidityEntityKind.FUNCTION,
            "appendPreset",
            signature="appendPreset()",
            visibility="external",
            contract_name="UnsafeStateGrowth",
        ),
        _entity(
            "entries",
            SolidityEntityKind.STATE_VARIABLE,
            "entries",
            contract_name="UnsafeStateGrowth",
        ),
        _entity(
            "entry-count",
            SolidityEntityKind.FUNCTION,
            "entryCount",
            signature="entryCount()",
            return_types=["uint256"],
            visibility="external",
            contract_name="UnsafeStateGrowth",
        ),
        _entity(
            "growth-threshold",
            SolidityEntityKind.FUNCTION,
            "growthThreshold",
            signature="growthThreshold()",
            return_types=["uint256"],
            visibility="external",
            contract_name="UnsafeStateGrowth",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.STATE_GROWTH_BOUND,
        ["append-preset", "entries", "entry-count", "growth-threshold"],
    ).model_copy(
        update={
            "category": InvariantCategory.ECONOMIC,
            "entity_ids": [
                "append-preset",
                "entries",
                "entry-count",
                "growth-threshold",
            ],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "UnsafeStateGrowth": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.BOUNDED_STATE_GROWTH,
                applicable=True,
                rationale="A public array append omits its source-linked length guard.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.BOUNDED_STATE_GROWTH
    assert harness.runs == 8
    assert harness.depth == 1
    assert len(harness.setup_calls) == 4
    assert all(call.function_signature == "appendPreset()" for call in harness.setup_calls)
    assert len(harness.actions) == 1
    assert harness.actions[0].action_id == "AppendBeyondConfiguredThreshold"
    assert harness.properties[0].left.function_signature == "entryCount()"
    assert harness.properties[0].right is not None
    assert harness.properties[0].right.function_signature == "growthThreshold()"
    source = translate_foundry_invariant(
        harness,
        targets={
            "UnsafeStateGrowth": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert source.count('abi.encodeWithSignature("appendPreset()")') == 5
    assert "function action_AppendBeyondConfiguredThreshold()" in source
    assert "invariant_EntryCountWithinGrowthThreshold" in source
    assert all(token not in source for token in ("while (", "for (", "vm.ffi"))


def test_signature_template_replays_only_a_preconfigured_local_authorization() -> None:
    entities = [
        _entity(
            "contract-claim",
            SolidityEntityKind.CONTRACT,
            "SignedClaim",
            contract_name="SignedClaim",
        ),
        _entity(
            "claim-preset",
            SolidityEntityKind.FUNCTION,
            "claimPreset",
            signature="claimPreset()",
            visibility="external",
            contract_name="SignedClaim",
        ),
        _entity(
            "claimed",
            SolidityEntityKind.STATE_VARIABLE,
            "claimed",
            signature="claimed(address)",
            return_types=["uint256"],
            visibility="public",
            contract_name="SignedClaim",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.PERMIT_REPLAY_PROTECTION,
        ["claim-preset"],
    ).model_copy(
        update={
            "category": InvariantCategory.TOKEN_STANDARD,
            "entity_ids": ["claim-preset"],
        }
    )
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "SignedClaim": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.SIGNATURE_REPLAY,
                applicable=True,
                rationale="A signature primitive authorizes the indexed transition.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.SIGNATURE_REPLAY
    assert harness.runs == 16
    assert harness.depth == 4
    assert [call.step_id for call in harness.setup_calls] == ["ConsumeAuthorizationOnce"]
    assert harness.actions[0].function_signature == "claimPreset()"
    assert harness.properties[0].compare_to_initial
    source = translate_foundry_invariant(
        harness,
        targets={
            "SignedClaim": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert "initial_AuthorizationConsumedOnce" in source
    assert "function action_ReplayAuthorization()" in source
    assert "assertLe(leftValue, initial_AuthorizationConsumedOnce" in source
    assert "vm.sign" not in source
    assert "privateKey" not in source


def test_ordering_template_declares_and_translates_only_same_block_reordering() -> None:
    entities = [
        _entity(
            "contract-ordering",
            SolidityEntityKind.CONTRACT,
            "OrderedSettlement",
            contract_name="OrderedSettlement",
        ),
        _entity(
            "stage-preset",
            SolidityEntityKind.FUNCTION,
            "stagePreset",
            signature="stagePreset()",
            visibility="external",
            contract_name="OrderedSettlement",
        ),
        _entity(
            "reorder-preset",
            SolidityEntityKind.FUNCTION,
            "reorderPreset",
            signature="reorderPreset()",
            visibility="external",
            contract_name="OrderedSettlement",
        ),
        _entity(
            "shortfall",
            SolidityEntityKind.FUNCTION,
            "shortfall",
            signature="shortfall(address)",
            return_types=["uint256"],
            visibility="external",
            contract_name="OrderedSettlement",
        ),
    ]
    invariant = _invariant(
        InvariantTemplate.ORDERING_VALUE_BOUND,
        ["stage-preset", "reorder-preset", "shortfall"],
    ).model_copy(update={"category": InvariantCategory.ECONOMIC})
    generated = generate_invariant_harnesses(
        InvariantSuite(invariants=[invariant]),
        SoliditySymbolIndex(projects=[_project()], entities=entities),
        targets={
            "OrderedSettlement": "0x2000000000000000000000000000000000000002",
        },
        economic_plans=[
            EconomicSimulationPlan(
                kind=EconomicSimulationKind.SANDWICH,
                applicable=True,
                rationale="A source-linked staged value bound can be reordered.",
                invariant_ids=[invariant.id],
                typed_harness_available=True,
                execution_required=True,
                required_transaction_ordering=TransactionOrderingCapability.SAME_BLOCK,
            )
        ],
        runs=32,
        depth=16,
    )

    assert generated.limitations == []
    assert len(generated.harnesses) == 1
    harness = generated.harnesses[0]
    assert harness.economic_template is EconomicSimulationKind.SANDWICH
    assert harness.required_transaction_ordering is TransactionOrderingCapability.SAME_BLOCK
    assert harness.runs == 8
    assert harness.depth == 1
    assert harness.setup_calls[0].actor == "victim"
    assert harness.setup_calls[0].function_signature == "stagePreset()"
    assert harness.actions[0].actor_names == ["attacker"]
    assert harness.actions[0].function_signature == "reorderPreset()"
    assert harness.properties[0].left.function_signature == "shortfall(address)"
    assert harness.properties[0].expected_uint == 0
    source = translate_foundry_invariant(
        harness,
        targets={
            "OrderedSettlement": "0x2000000000000000000000000000000000000002",
        },
        expected_chain_id=1,
    )
    assert source.index('abi.encodeWithSignature("stagePreset()"') < source.index(
        "targetContract(address(handler))"
    )
    assert "function action_ReorderSettlement()" in source
    assert 'abi.encodeWithSignature("shortfall(address)"' in source
    assert "vm.warp" not in source
    assert "vm.roll" not in source


def test_foundry_output_normalization_keeps_counterexample_and_compile_failure_distinct() -> None:
    status, limitations, summary = normalize_foundry_invariant_output(
        1,
        "[FAIL: observed assets do not cover claims] invariant_ObservedAssetsCoverClaims()",
    )
    assert status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert limitations == []
    assert summary is not None

    status, limitations, summary = normalize_foundry_invariant_output(
        1,
        "Compiler run failed: TypeError:",
    )
    assert status is InvariantExecutionStatus.COMPILE_FAILED
    assert limitations
    assert summary is None


def _forge_invariant_json(
    *,
    property_id: str = "AssetsNonzero",
    status: str = "Success",
    kind: dict[str, object] | None = None,
    reason: str | None = None,
) -> str:
    if kind is None:
        invariant_kind: dict[str, object] = {
            "runs": 32,
            "calls": 256,
            "metrics": {
                "MMAuditHandler.action_Deposit": {"calls": 1 if status == "Failure" else 256}
            },
        }
        kind = {"Invariant": invariant_kind}
    result: dict[str, object] = {
        "status": status,
        "kind": kind,
    }
    if reason is not None:
        result["reason"] = reason
    if status == "Failure":
        result["counterexample"] = {
            "Sequence": [
                1,
                [
                    {
                        "func_name": "action_Deposit",
                        "signature": "action_Deposit()",
                    }
                ],
            ]
        }
    return json.dumps(
        {
            "test/MMAuditInvariant.t.sol:MMAuditInvariant": {
                "test_results": {f"invariant_{property_id}()": result}
            }
        }
    )


@pytest.mark.parametrize(
    ("forge_status", "return_code", "expected_status"),
    [
        ("Success", 0, InvariantExecutionStatus.PASSED),
        ("Failure", 1, InvariantExecutionStatus.COUNTEREXAMPLE),
    ],
)
def test_structured_foundry_invariant_accepts_exact_nonempty_campaign(
    forge_status: str,
    return_code: int,
    expected_status: InvariantExecutionStatus,
) -> None:
    output = _forge_invariant_json(
        status=forge_status,
        reason="declared invariant did not hold" if return_code else None,
    )

    status, counterexample, structured_text, property_ids, runs, calls = (
        _structured_foundry_invariant_result(
            output,
            return_code=return_code,
            property_ids={"AssetsNonzero"},
        )
    )

    assert status is expected_status
    assert property_ids == ["AssetsNonzero"]
    assert (runs, calls) == ((33, 256) if return_code else (32, 256))
    if return_code:
        assert counterexample is not None
        assert "action_Deposit()" in structured_text
    else:
        assert counterexample is None
        assert structured_text == "observed=action_Deposit()"


def test_structured_foundry_invariant_does_not_credit_zero_call_actions() -> None:
    kind = {
        "Invariant": {
            "runs": 32,
            "calls": 256,
            "metrics": {
                "MMAuditHandler.action_Deposit": {"calls": 256},
                "MMAuditHandler.action_Withdraw": {"calls": 0},
            },
        }
    }

    _status, _counterexample, structured_text, _properties, _runs, _calls = (
        _structured_foundry_invariant_result(
            _forge_invariant_json(kind=kind),
            return_code=0,
            property_ids={"AssetsNonzero"},
            action_ids={"Deposit", "Withdraw"},
        )
    )

    assert structured_text == "observed=action_Deposit()"


@pytest.mark.parametrize(
    "output",
    [
        "[PASS] invariant_AssetsNonzero()",
        '{"test/MMAuditInvariant.t.sol:MMAuditInvariant":',
        ("[PASS] invariant_AssetsNonzero()\n" + _forge_invariant_json()),
    ],
)
def test_structured_foundry_invariant_rejects_log_spoofing_and_malformed_json(
    output: str,
) -> None:
    with pytest.raises(ValueError):
        _structured_foundry_invariant_result(
            output,
            return_code=0,
            property_ids={"AssetsNonzero"},
        )


@pytest.mark.parametrize(
    ("output", "property_ids"),
    [
        (
            _forge_invariant_json(),
            {"AssetsNonzero", "ClaimsCovered"},
        ),
        (
            _forge_invariant_json(property_id="UnexpectedProperty"),
            {"AssetsNonzero"},
        ),
    ],
)
def test_structured_foundry_invariant_requires_exact_property_coverage(
    output: str,
    property_ids: set[str],
) -> None:
    with pytest.raises(ValueError):
        _structured_foundry_invariant_result(
            output,
            return_code=0,
            property_ids=property_ids,
        )


@pytest.mark.parametrize(
    "kind",
    [
        {"Unit": {"gas": 123}},
        {"Invariant": {"runs": 32, "calls": 0}},
    ],
)
def test_structured_foundry_invariant_rejects_wrong_kind_or_empty_campaign(
    kind: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        _structured_foundry_invariant_result(
            _forge_invariant_json(kind=kind),
            return_code=0,
            property_ids={"AssetsNonzero"},
        )


def test_invariant_runner_records_erc4626_economic_metrics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = FoundryInvariantHarnessSpec(
        invariant_id="inv-erc4626",
        name="DonationInflation",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
                initial_native_balance_wei=10**18,
            ),
            ForkActor(
                name="victim",
                address="0x1000000000000000000000000000000000000003",
                initial_native_balance_wei=10**18,
            ),
        ],
        token_balance_seeds=[
            TokenBalanceSeed(token="VaultAsset", actor="attacker", amount=2 * 10**18),
            TokenBalanceSeed(token="VaultAsset", actor="victim", amount=10**18),
        ],
        setup_calls=[
            ForkCallStep(
                step_id="VictimDeposit",
                actor="victim",
                target="Vault",
                function_signature="deposit(uint256,address)",
                arguments=[
                    ForkArgument(kind=ForkArgumentKind.UINT256, value=str(10**18)),
                    ForkArgument(
                        kind=ForkArgumentKind.ADDRESS,
                        value="0x1000000000000000000000000000000000000003",
                    ),
                ],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="VictimReceivesShares",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="balanceOf(address)",
                    arguments=[
                        ForkArgument(
                            kind=ForkArgumentKind.ADDRESS,
                            value="0x1000000000000000000000000000000000000003",
                        )
                    ],
                ),
                relation="gte",
                expected_uint=1,
            )
        ],
        economic_template=EconomicSimulationKind.ERC4626_DONATION,
    )
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "Vault": "0x2000000000000000000000000000000000000002",
                "VaultAsset": "0x3000000000000000000000000000000000000003",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )
    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )
    assert result.status is InvariantExecutionStatus.PASSED
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 2 * 10**18
    assert result.economic_metrics.borrowed_capital == 0
    assert result.economic_metrics.maximum_victim_loss == 10**18
    assert "unprivileged attacker" in result.economic_metrics.required_privileges


def test_invariant_runner_records_bounded_rounding_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = FoundryInvariantHarnessSpec(
        invariant_id="inv-rounding",
        name="RoundingBounds",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="RoundTrip",
                target="RoundingAccount",
                function_signature="roundTrip(uint256)",
                actor_names=["attacker"],
                arguments=[
                    HarnessArgument(
                        kind=ForkArgumentKind.UINT256,
                        source="fuzz_uint",
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
                    target="RoundingAccount",
                    function_signature="credit(address)",
                    arguments=[
                        ForkArgument(
                            kind=ForkArgumentKind.ADDRESS,
                            value="0x1000000000000000000000000000000000000002",
                        )
                    ],
                ),
                relation="lte",
                compare_to_initial=True,
            )
        ],
        economic_template=EconomicSimulationKind.ROUNDING,
    )
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "RoundingAccount": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 1
    assert result.economic_metrics.borrowed_capital == 0
    assert "unprivileged account holder" in result.economic_metrics.required_privileges
    assert "downward-rounding loss" in " ".join(result.economic_metrics.market_assumptions)


def test_invariant_runner_records_synthetic_oracle_guard_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = FoundryInvariantHarnessSpec(
        invariant_id="inv-oracle-guards",
        name="OracleGuardSanity",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        setup_calls=[
            ForkCallStep(
                step_id="ConfigureInvalidFeedPreset",
                actor="attacker",
                target="OracleConsumer",
                function_signature="configurePreset()",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="ValidateConfiguredFeed",
                target="OracleConsumer",
                function_signature="validatePreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="InvalidFeedIsRejected",
                left=InvariantProbe(
                    target="OracleConsumer",
                    function_signature="guardFailures()",
                ),
                relation="lte",
                expected_uint=0,
            )
        ],
        economic_template=EconomicSimulationKind.ORACLE_GUARDS,
    )
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "OracleConsumer": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 0
    assert result.economic_metrics.borrowed_capital == 0
    assert "oracle consumer caller" in " ".join(result.economic_metrics.required_privileges)
    assert "synthetic presets" in " ".join(result.economic_metrics.market_assumptions)


def test_invariant_runner_enforces_and_records_governance_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = _governance_specification()

    time_blocked = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "Governance": "0x2000000000000000000000000000000000000002",
            },
            allow_governance_rights=True,
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    ).run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "time-blocked",
    )
    assert time_blocked.status is InvariantExecutionStatus.GENERATION_FAILED
    assert "time shift" in " ".join(time_blocked.limitations)

    rights_blocked = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "Governance": "0x2000000000000000000000000000000000000002",
            },
            max_time_shift_seconds=3_600,
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    ).run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "rights-blocked",
    )
    assert rights_blocked.status is InvariantExecutionStatus.GENERATION_FAILED
    assert "governance rights" in " ".join(rights_blocked.limitations)

    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "Governance": "0x2000000000000000000000000000000000000002",
            },
            max_time_shift_seconds=3_600,
            allow_governance_rights=True,
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )
    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.capability_policy == specification.capability_policy
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 0
    assert "governance proposer" in " ".join(result.economic_metrics.required_privileges)
    assert "3600 seconds" in " ".join(result.economic_metrics.market_assumptions)


def test_invariant_runner_records_legitimate_proxy_call_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = _upgrade_specification()
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "Proxy": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 0
    assert "unprivileged proxy caller" in " ".join(result.economic_metrics.required_privileges)
    assumptions = " ".join(result.economic_metrics.market_assumptions)
    assert "synthetic and local-only" in assumptions
    assert "without direct storage or code mutation" in assumptions


def test_invariant_runner_enforces_and_records_offline_message_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    specification = _cross_chain_specification()
    blocked = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "Inbox": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    ).run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "blocked",
    )
    assert blocked.status is InvariantExecutionStatus.GENERATION_FAILED
    assert "cross-chain message" in " ".join(blocked.limitations)

    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "Inbox": "0x2000000000000000000000000000000000000002",
            },
            allowed_cross_chain_messages=(CrossChainMessageCapability.REORDER_VALID_MESSAGES),
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )
    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.capability_policy == specification.capability_policy
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 0
    assert "synthetic local messenger" in " ".join(result.economic_metrics.required_privileges)
    assumptions = " ".join(result.economic_metrics.market_assumptions)
    assert "offline fixture values" in assumptions
    assert "no relayer" in assumptions


def test_invariant_runner_bounds_receiver_and_contextualizes_callback_counterexample(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "callback-forge-ran"
    forge = _fake_forge(
        tmp_path / "forge",
        (
            f"printf ran > {marker}; "
            "echo '[FAIL: invariant violated] "
            "invariant_ReachableCallbackPreservesAvailableCredit() counterexample'; exit 1"
        ),
    )
    specification = _callback_specification()
    blocked = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "CallbackAccounting": "0x2000000000000000000000000000000000000002",
            },
            max_attacker_controlled_contracts=0,
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    ).run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "blocked",
    )
    assert blocked.status is InvariantExecutionStatus.GENERATION_FAILED
    assert "contract count" in " ".join(blocked.limitations)
    assert not marker.exists()

    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "CallbackAccounting": "0x2000000000000000000000000000000000000002",
            },
            max_attacker_controlled_contracts=1,
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    ).run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert marker.exists()
    assert result.capability_policy == specification.capability_policy
    assert result.counterexample_summary is not None
    assert "receiver.onCreditReceived()" in result.counterexample_summary
    assert "availableCredit" in result.counterexample_summary
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 0
    assert "synthetic callback receiver" in " ".join(result.economic_metrics.required_privileges)
    assumptions = " ".join(result.economic_metrics.market_assumptions)
    assert "source-linked reachable callback" in assumptions
    assert "affected accounting state" in assumptions


def test_invariant_runner_records_state_growth_threshold_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(
        tmp_path / "forge",
        (
            "echo '[FAIL: invariant violated] "
            "invariant_EntryCountWithinGrowthThreshold() counterexample'; exit 1"
        ),
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "StateGrowth": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    ).run(
        repository_root=root,
        project=_project(),
        specification=_state_growth_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert result.counterexample_summary is not None
    assert "entryCount" in result.counterexample_summary
    assert "growthThreshold" in result.counterexample_summary
    assert result.economic_metrics is not None
    assert result.economic_metrics.resource_threshold == 4
    assert result.economic_metrics.bounded_actions == 5
    assumptions = " ".join(result.economic_metrics.market_assumptions)
    assert "one extra action" in assumptions
    assert "no unbounded loop" in assumptions


def test_invariant_runner_stops_state_growth_campaign_at_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "sleep 2; exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=0.05,
            expected_chain_id=1,
            targets={
                "StateGrowth": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    ).run(
        repository_root=root,
        project=_project(),
        specification=_state_growth_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.TIMED_OUT
    assert result.duration_seconds < 1
    assert "timed out" in " ".join(result.limitations)


def test_invariant_runner_records_local_signature_replay_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = FoundryInvariantHarnessSpec(
        invariant_id="inv-signature",
        name="SignatureReplay",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        setup_calls=[
            ForkCallStep(
                step_id="ConsumeAuthorizationOnce",
                actor="attacker",
                target="SignedClaim",
                function_signature="claimPreset()",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="ReplayAuthorization",
                target="SignedClaim",
                function_signature="claimPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="AuthorizationConsumedOnce",
                left=InvariantProbe(
                    target="SignedClaim",
                    function_signature="claimed(address)",
                    arguments=[
                        ForkArgument(
                            kind=ForkArgumentKind.ADDRESS,
                            value="0x1000000000000000000000000000000000000002",
                        )
                    ],
                ),
                relation="lte",
                compare_to_initial=True,
            )
        ],
        economic_template=EconomicSimulationKind.SIGNATURE_REPLAY,
    )
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={
                "SignedClaim": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.economic_metrics is not None
    assert result.economic_metrics.required_initial_capital == 0
    assert result.economic_metrics.borrowed_capital == 0
    assert "fixture-authorized signature" in " ".join(result.economic_metrics.required_privileges)
    assert "synthetic and local-only" in " ".join(result.economic_metrics.market_assumptions)


def test_ordering_harness_requires_same_block_declaration() -> None:
    payload = _ordering_specification().model_dump(mode="json")
    payload["required_transaction_ordering"] = "none"
    with pytest.raises(ValidationError, match="same_block"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_governance_harness_requires_declared_rights_and_bounded_time() -> None:
    payload = _governance_specification().model_dump(mode="json")
    payload["capability_policy"] = None
    with pytest.raises(ValidationError, match="time-shifting actions"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _governance_specification().model_dump(mode="json")
    payload["depth"] = 2
    with pytest.raises(ValidationError, match="bounded capability"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _governance_specification().model_dump(mode="json")
    policy = payload["capability_policy"]
    assert isinstance(policy, dict)
    policy["governance_rights"] = False
    justifications = policy["capability_justifications"]
    assert isinstance(justifications, dict)
    justifications.pop("governance_rights")
    with pytest.raises(ValidationError, match="governance rights"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_cross_chain_harness_requires_declared_offline_message_capability() -> None:
    payload = _cross_chain_specification().model_dump(mode="json")
    payload["capability_policy"] = None
    with pytest.raises(ValidationError, match="message capability"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _cross_chain_specification().model_dump(mode="json")
    policy = payload["capability_policy"]
    assert isinstance(policy, dict)
    policy["cross_chain_messages"] = "none"
    justifications = policy["capability_justifications"]
    assert isinstance(justifications, dict)
    justifications.pop("cross_chain_message")
    with pytest.raises(ValidationError, match="message capability"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_callback_harness_requires_declared_controlled_receiver() -> None:
    payload = _callback_specification().model_dump(mode="json")
    payload["capability_policy"] = None
    with pytest.raises(ValidationError, match="controlled receiver"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _callback_specification().model_dump(mode="json")
    policy = payload["capability_policy"]
    assert isinstance(policy, dict)
    policy["attacker_controlled_contracts"] = []
    with pytest.raises(ValidationError, match="controlled receiver"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_state_growth_harness_enforces_runs_depth_and_threshold_probe() -> None:
    payload = _state_growth_specification().model_dump(mode="json")
    payload["depth"] = 2
    with pytest.raises(ValidationError, match="exactly one action depth"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _state_growth_specification().model_dump(mode="json")
    payload["runs"] = 9
    with pytest.raises(ValidationError, match="at most 8 runs"):
        FoundryInvariantHarnessSpec.model_validate(payload)

    payload = _state_growth_specification().model_dump(mode="json")
    properties = payload["properties"]
    assert isinstance(properties, list)
    properties[0]["right"]["function_signature"] = "otherThreshold()"
    with pytest.raises(ValidationError, match="growthThreshold"):
        FoundryInvariantHarnessSpec.model_validate(payload)


def test_ordering_execution_is_rejected_until_operator_authorizes_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "forge-ran"
    forge = _fake_forge(tmp_path / "forge", f"printf ran > {marker}; exit 0")
    specification = _ordering_specification()
    denied_runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )

    denied = denied_runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "denied",
    )

    assert denied.status is InvariantExecutionStatus.GENERATION_FAILED
    assert not marker.exists()
    assert "not operator-authorized" in " ".join(denied.limitations)
    assert denied.required_transaction_ordering is TransactionOrderingCapability.SAME_BLOCK

    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    approved_runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
            allowed_transaction_ordering=TransactionOrderingCapability.SAME_BLOCK,
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=forge,
    )
    approved = approved_runner.run(
        repository_root=root,
        project=_project(),
        specification=specification,
        private_dir=tmp_path / "approved",
    )

    assert approved.status is InvariantExecutionStatus.PASSED
    assert marker.exists()
    assert approved.economic_metrics is not None
    assert "same-block transaction ordering" in " ".join(
        approved.economic_metrics.required_privileges
    )
    assert approved.required_transaction_ordering is TransactionOrderingCapability.SAME_BLOCK


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("exit 0", InvariantExecutionStatus.PASSED),
        (
            "echo '[FAIL: invariant violated] invariant_AssetsNonzero()'; exit 1",
            InvariantExecutionStatus.COUNTEREXAMPLE,
        ),
        (
            "echo 'Compiler run failed: ParserError:'; exit 1",
            InvariantExecutionStatus.COMPILE_FAILED,
        ),
    ],
)
def test_invariant_runner_classifies_bounded_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    expected: InvariantExecutionStatus,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", body)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = _runner(forge).run(
        repository_root=root,
        project=_project(),
        specification=_specification(),
        private_dir=tmp_path / "private",
    )
    assert result.status is expected
    assert result.command[0] == "[FORGE]"
    assert "127.0.0.1" not in " ".join(result.command)
    assert result.source_sha256
    assert not (root / "test").exists()


def test_injected_invariant_backend_cannot_self_assert_real(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            repetitions=2,
            expected_chain_id=1,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
        ),
        SmartContractsConfig(),
        backend=SelfAssertedRealIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_specification(),
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.PASSED
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert not runner.isolation_available


def test_invariant_runner_requires_hardened_isolation(tmp_path: Path) -> None:
    runner = FoundryInvariantRunner(
        ReproductionConfig(targets={"Vault": "0x2000000000000000000000000000000000000002"}),
        SmartContractsConfig(),
        backend=None,
        forge_executable=tmp_path / "forge",
    )
    runner.backend = None
    result = runner.run(
        repository_root=_repository(tmp_path),
        project=_project(),
        specification=_specification(),
        private_dir=tmp_path / "private",
    )
    assert result.status is InvariantExecutionStatus.ENVIRONMENT_BLOCKED
    assert "isolation" in " ".join(result.limitations)


def test_invariant_runner_rejects_repository_local_forge_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    bin_dir = root / "bin"
    bin_dir.mkdir()
    _fake_forge(bin_dir / "forge", "exit 0")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    runner = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=2,
            expected_chain_id=1,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
    )
    result = runner.run(
        repository_root=root,
        project=_project(),
        specification=_specification(),
        private_dir=tmp_path / "private",
    )
    assert result.status is InvariantExecutionStatus.ENVIRONMENT_BLOCKED
    assert "outside the audited repository" in " ".join(result.limitations)


@pytest.mark.parametrize(
    "unsafe_rpc",
    [
        "https://127.0.0.1:8545",
        "http://user:password@127.0.0.1:8545",
        "http://127.0.0.1:8545?api_key=secret",
        "http://127.0.0.1",
        "http://203.0.113.10:8545",
    ],
)
def test_invariant_runner_rejects_unsafe_fork_rpc_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_rpc: str,
) -> None:
    root = _repository(tmp_path)
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", unsafe_rpc)
    result = _runner(forge).run(
        repository_root=root,
        project=_project(),
        specification=_specification(),
        private_dir=tmp_path / "private",
    )
    assert result.status is InvariantExecutionStatus.ENVIRONMENT_BLOCKED
    assert "local fork RPC validation failed" in " ".join(result.limitations)


def test_invariant_runner_does_not_copy_secret_files_to_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    (root / ".env").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (root / "wallet.pem").write_text("synthetic pem\n", encoding="utf-8")
    (root / "signing.key").write_text("synthetic key\n", encoding="utf-8")
    (root / "id_rsa").write_text("synthetic ssh key\n", encoding="utf-8")
    (root / "mnemonic.txt").write_text("synthetic seed phrase\n", encoding="utf-8")
    (root / "wallet.json").write_text("synthetic wallet\n", encoding="utf-8")
    (root / ".ENV.PROD").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (root / "WALLET.PEM").write_text("synthetic pem\n", encoding="utf-8")
    (root / "ID_ED25519").write_text("synthetic ssh key\n", encoding="utf-8")
    forge = _fake_forge(
        tmp_path / "forge",
        'test ! -e ".env"\n'
        'test ! -e "wallet.pem"\n'
        'test ! -e "signing.key"\n'
        'test ! -e "id_rsa"\n'
        'test ! -e "mnemonic.txt"\n'
        'test ! -e "wallet.json"\n'
        'test ! -e ".ENV.PROD"\n'
        'test ! -e "WALLET.PEM"\n'
        'test ! -e "ID_ED25519"',
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = _runner(forge).run(
        repository_root=root,
        project=_project(),
        specification=_specification(),
        private_dir=tmp_path / "private",
    )
    assert result.status is InvariantExecutionStatus.PASSED
