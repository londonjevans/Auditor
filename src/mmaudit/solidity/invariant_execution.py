"""Typed Foundry stateful-invariant generation and isolated execution."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    EconomicMetrics,
    EconomicSimulationKind,
    FinancialSettlementEvidence,
    FinancialSettlementProbeSpec,
    ForkArgument,
    ForkArgumentKind,
    ForkCallStep,
    FoundryInvariantHarnessSpec,
    HarnessArgument,
    HarnessArgumentSource,
    InvariantCampaignCoverage,
    InvariantExecutionAttemptEvidence,
    InvariantExecutionMinimizationEvidence,
    InvariantExecutionRemovalTrial,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    LendingBoundaryEvidence,
    LendingBoundaryProbeSpec,
    LocalInvariantDeployment,
    SharePriceBoundaryEvidence,
    SharePriceBoundaryProbeSpec,
    SolidityProjectMetadata,
    SolidityProjectType,
    StatefulActionSpec,
    TransactionOrderingCapability,
)
from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.solidity.reproduction import (
    IsolationBackend,
    _argument_literal,
    _copy_project,
    _external_executable,
    _local_rpc,
    _stop_process,
    attacker_capability_policy_error,
    default_isolation_backend,
)


def translate_foundry_invariant(
    specification: FoundryInvariantHarnessSpec,
    *,
    targets: dict[str, str],
    expected_chain_id: int | None,
) -> str:
    """Translate a declarative stateful harness without accepting source text."""

    referenced_targets = {
        *(setup.target for setup in specification.setup_calls),
        *(seed.token for seed in specification.token_balance_seeds),
        *(action.target for action in specification.actions),
        *(property_spec.left.target for property_spec in specification.properties),
        *(
            property_spec.right.target
            for property_spec in specification.properties
            if property_spec.right is not None
        ),
        *(
            _financial_probe_targets(specification.financial_settlement)
            if specification.financial_settlement is not None
            else set()
        ),
        *(
            _lending_probe_targets(specification.lending_boundary)
            if specification.lending_boundary is not None
            else set()
        ),
        *(
            _share_price_probe_targets(specification.share_price_boundary)
            if specification.share_price_boundary is not None
            else set()
        ),
    }
    unknown = referenced_targets - set(targets)
    if unknown:
        raise ValueError(f"unknown target aliases: {', '.join(sorted(unknown))}")
    invalid_targets = [
        name
        for name in sorted(referenced_targets)
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", targets[name])
    ]
    if invalid_targets:
        raise ValueError(
            f"target aliases are not literal EVM addresses: {', '.join(invalid_targets)}"
        )
    local_deployments = specification.local_deployments
    local_targets = {deployment.target_alias for deployment in local_deployments}
    base_contract = "MMAuditLocalInvariantTest" if local_deployments else "Test"
    lines = [
        *_invariant_source_header(local_deployments),
        f"contract MMAuditHandler_{specification.name} is {base_contract} {{",
    ]
    for name in sorted(referenced_targets):
        if name in local_targets:
            lines.append(f"    address internal target_{name};")
        else:
            lines.append(f"    address internal constant target_{name} = {targets[name]};")
    if local_deployments:
        parameters = ", ".join(f"address local_{name}" for name in sorted(local_targets))
        lines.extend(("", f"    constructor({parameters}) {{"))
        for name in sorted(local_targets):
            lines.append(f"        target_{name} = local_{name};")
        lines.extend(("    }", ""))
    lines.append("")
    for action in specification.actions:
        lines.append(f"    uint256 public attempts_{action.action_id};")
    if specification.actions:
        lines.append("")
    actors_by_name = {actor.name: actor.address for actor in specification.actors}
    for action in specification.actions:
        lines.extend(
            _action_lines(
                action,
                actors_by_name,
                targets=targets,
                local_targets=local_targets,
            )
        )
    lines.extend(
        (
            "}",
            "",
            f"contract MMAuditInvariant_{specification.name} is {base_contract} {{",
        )
    )
    lines.append(f"    MMAuditHandler_{specification.name} internal handler;")
    for name in sorted(referenced_targets):
        if name in local_targets:
            lines.append(f"    address internal target_{name};")
        else:
            lines.append(f"    address internal constant target_{name} = {targets[name]};")
    for property_spec in specification.properties:
        if property_spec.compare_to_initial:
            lines.append(f"    uint256 internal initial_{property_spec.property_id};")
    lines.extend(
        (
            "",
            "    function setUp() public {",
        )
    )
    if expected_chain_id is not None:
        lines.append(
            f'        assertEq(block.chainid, {expected_chain_id}, "unexpected fork chain");'
        )
    for deployment in local_deployments:
        lines.extend(f"        {line}" for line in _local_deployment_lines(deployment))
    for actor in specification.actors:
        if actor.initial_native_balance_wei:
            lines.append(f"        vm.deal({actor.address}, {actor.initial_native_balance_wei});")
    actors_by_name = {actor.name: actor.address for actor in specification.actors}
    deployments_by_target = {
        deployment.target_alias: deployment for deployment in local_deployments
    }
    for seed in specification.token_balance_seeds:
        seed_deployment = deployments_by_target.get(seed.token)
        if seed_deployment is None:
            lines.append(
                f"        deal(target_{seed.token}, {actors_by_name[seed.actor]}, "
                f"{seed.amount}, true);"
            )
        else:
            assert seed_deployment.token_seed_function_signature is not None
            seed_name = f"seed_{seed.token}_{seed.actor}"
            lines.extend(
                (
                    f"        (bool {seed_name}Ok,) = target_{seed.token}.call(",
                    "            abi.encodeWithSignature("
                    f'"{seed_deployment.token_seed_function_signature}", '
                    f"{actors_by_name[seed.actor]}, {seed.amount})",
                    "        );",
                    f'        require({seed_name}Ok, "local token seed failed");',
                )
            )
    for setup in specification.setup_calls:
        lines.extend(
            f"        {line}"
            for line in _setup_call_lines(
                setup,
                actors_by_name,
                targets=targets,
                local_targets=local_targets,
            )
        )
    for property_spec in specification.properties:
        if not property_spec.compare_to_initial:
            continue
        prefix = f"initial_{property_spec.property_id}"
        probe_lines, probe_value = _probe_lines(
            property_spec.left,
            prefix,
            targets=targets,
            local_targets=local_targets,
        )
        lines.extend(f"        {line}" for line in probe_lines)
        lines.append(f"        initial_{property_spec.property_id} = {probe_value};")
    handler_arguments = ", ".join(f"target_{name}" for name in sorted(local_targets))
    lines.append(
        f"        handler = new MMAuditHandler_{specification.name}({handler_arguments});"
        if local_deployments
        else f"        handler = new MMAuditHandler_{specification.name}();"
    )
    if specification.actions:
        lines.append("        targetContract(address(handler));")
    lines.extend(("    }", ""))
    for property_spec in specification.properties:
        lines.extend(
            _property_lines(
                property_spec,
                targets=targets,
                local_targets=local_targets,
            )
        )
    if specification.financial_settlement is not None:
        lines.extend(_financial_settlement_test_lines(specification))
    lines.extend(("}", ""))
    source = "\n".join(lines)
    forbidden = ("vm.ffi", "vm.broadcast", "vm.startBroadcast", "vm.sign", "privateKey")
    if any(token in source for token in forbidden):
        raise ValueError("generated invariant source violated the fixed safety template")
    return source


def _invariant_source_header(
    local_deployments: list[LocalInvariantDeployment],
) -> list[str]:
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.20;",
    ]
    if not local_deployments:
        return [*lines, 'import "forge-std/Test.sol";', ""]
    for source_path in sorted({deployment.source_path for deployment in local_deployments}):
        lines.append(f'import "../../{source_path}";')
    lines.extend(
        (
            "",
            "interface MMAuditVm {",
            "    function deal(address account, uint256 balance) external;",
            "    function prank(address caller) external;",
            "}",
            "",
            "abstract contract MMAuditLocalInvariantTest {",
            "    MMAuditVm internal constant vm = MMAuditVm(",
            '        address(uint160(uint256(keccak256("hevm cheat code"))))',
            "    );",
            "    address[] private mmauditTargetContracts;",
            "    event log_named_uint(string key, uint256 value);",
            "",
            "    function targetContract(address target) internal {",
            "        mmauditTargetContracts.push(target);",
            "    }",
            "",
            "    function targetContracts() public view returns (address[] memory) {",
            "        return mmauditTargetContracts;",
            "    }",
            "",
            "    function bound(uint256 value, uint256 minimum, uint256 maximum)",
            "        internal pure returns (uint256)",
            "    {",
            '        require(minimum <= maximum, "invalid bound");',
            "        if (value >= minimum && value <= maximum) return value;",
            "        uint256 span = maximum - minimum;",
            "        if (span == type(uint256).max) return value;",
            "        return minimum + (value % (span + 1));",
            "    }",
            "",
            "    function assertEq(uint256 left, uint256 right, string memory reason)",
            "        internal pure",
            "    {",
            "        require(left == right, reason);",
            "    }",
            "",
            "    function assertGe(uint256 left, uint256 right, string memory reason)",
            "        internal pure",
            "    {",
            "        require(left >= right, reason);",
            "    }",
            "",
            "    function assertLe(uint256 left, uint256 right, string memory reason)",
            "        internal pure",
            "    {",
            "        require(left <= right, reason);",
            "    }",
            "}",
            "",
        )
    )
    return lines


def _financial_probe_targets(
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


def _lending_probe_targets(
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


def _share_price_probe_targets(
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


def _local_deployment_lines(deployment: LocalInvariantDeployment) -> list[str]:
    arguments = []
    for argument in deployment.constructor_arguments:
        expression = f"target_{argument.target_alias}"
        if argument.cast_contract is not None:
            expression = f"{argument.cast_contract}({expression})"
        arguments.append(expression)
    encoded_arguments = ", ".join(arguments)
    return [
        f"target_{deployment.target_alias} = address("
        f"new {deployment.contract_name}({encoded_arguments})"
        ");",
        f'require(target_{deployment.target_alias}.code.length > 0, "local deployment failed");',
    ]


def _action_lines(
    action: StatefulActionSpec,
    actors_by_name: dict[str, str],
    *,
    targets: dict[str, str],
    local_targets: set[str],
) -> list[str]:
    fuzz_slot_values = {
        argument.fuzz_slot
        for argument in action.arguments
        if argument.source is not HarnessArgumentSource.CONSTANT and argument.fuzz_slot is not None
    }
    if action.actor_fuzz_slot is not None:
        fuzz_slot_values.add(action.actor_fuzz_slot)
    fuzz_slots = sorted(fuzz_slot_values)
    parameters = ", ".join(f"uint256 fuzz{slot}" for slot in fuzz_slots)
    actor_slot = (
        action.actor_fuzz_slot
        if action.actor_fuzz_slot is not None
        else (fuzz_slots[0] if fuzz_slots else None)
    )
    action_actors = [actors_by_name[name] for name in action.actor_names]
    actor_expression = _actor_expression(action_actors, actor_slot)
    call_arguments = ", ".join(
        _harness_argument(
            argument,
            action_actors,
            targets=targets,
            local_targets=local_targets,
        )
        for argument in action.arguments
    )
    comma = ", " if call_arguments else ""
    return [
        f"    function action_{action.action_id}({parameters}) external {{",
        f"        attempts_{action.action_id} += 1;",
        *(
            [f"        vm.warp(block.timestamp + {action.time_shift_seconds_before});"]
            if action.time_shift_seconds_before
            else []
        ),
        f"        address actor = {actor_expression};",
        "        vm.prank(actor);",
        f"        (bool success,) = target_{action.target}.call{{value: {action.value_wei}}}("
        f'abi.encodeWithSignature("{action.function_signature}"{comma}{call_arguments}));',
        "        if (!success) return;",
        "    }",
        "",
    ]


def _setup_call_lines(
    setup: ForkCallStep,
    actors_by_name: dict[str, str],
    *,
    targets: dict[str, str],
    local_targets: set[str],
) -> list[str]:
    arguments = ", ".join(
        _invariant_argument_literal(
            argument,
            targets=targets,
            local_targets=local_targets,
        )
        for argument in setup.arguments
    )
    comma = ", " if arguments else ""
    return [
        f"vm.prank({actors_by_name[setup.actor]});",
        f"(bool setup_{setup.step_id}Ok,) = target_{setup.target}.call{{value: {setup.value_wei}}}("
        f'abi.encodeWithSignature("{setup.function_signature}"{comma}{arguments}));',
        f'require(setup_{setup.step_id}Ok, "mmaudit setup call failed: {setup.step_id}");',
    ]


def _harness_argument(
    argument: HarnessArgument,
    actor_addresses: list[str],
    *,
    targets: dict[str, str],
    local_targets: set[str],
) -> str:
    if argument.source is HarnessArgumentSource.CONSTANT:
        assert argument.value is not None
        return _invariant_argument_literal(
            ForkArgument(kind=argument.kind, value=argument.value),
            targets=targets,
            local_targets=local_targets,
        )
    assert argument.fuzz_slot is not None
    if argument.source is HarnessArgumentSource.ACTOR:
        return _actor_expression(actor_addresses, argument.fuzz_slot)
    assert argument.minimum is not None and argument.maximum is not None
    return f"bound(fuzz{argument.fuzz_slot}, {argument.minimum}, {argument.maximum})"


def _invariant_argument_literal(
    argument: ForkArgument,
    *,
    targets: dict[str, str],
    local_targets: set[str],
) -> str:
    if argument.kind is ForkArgumentKind.ADDRESS:
        matching_alias = next(
            (
                name
                for name in sorted(local_targets)
                if targets[name].casefold() == argument.value.casefold()
            ),
            None,
        )
        if matching_alias is not None:
            return f"target_{matching_alias}"
    return _argument_literal(argument)


def _actor_expression(addresses: list[str], fuzz_slot: int | None) -> str:
    if fuzz_slot is None or len(addresses) == 1:
        return addresses[0]
    expression = addresses[-1]
    for index in range(len(addresses) - 2, -1, -1):
        expression = (
            f"(fuzz{fuzz_slot} % {len(addresses)} == {index} ? {addresses[index]} : {expression})"
        )
    return expression


def _property_lines(
    property_spec: InvariantPropertySpec,
    *,
    targets: dict[str, str],
    local_targets: set[str],
) -> list[str]:
    left_lines, left_value = _probe_lines(
        property_spec.left,
        "left",
        targets=targets,
        local_targets=local_targets,
    )
    lines = [
        f"    function invariant_{property_spec.property_id}() public view {{",
        *(
            f"        if (handler.attempts_{action_id}() == 0) return;"
            for action_id in property_spec.required_action_ids
        ),
        *(f"        {line}" for line in left_lines),
    ]
    if property_spec.right is not None:
        right_lines, right_value = _probe_lines(
            property_spec.right,
            "right",
            targets=targets,
            local_targets=local_targets,
        )
        lines.extend(f"        {line}" for line in right_lines)
    elif property_spec.expected_uint is not None:
        assert property_spec.expected_uint is not None
        right_value = str(property_spec.expected_uint)
    else:
        assert property_spec.compare_to_initial
        right_value = f"initial_{property_spec.property_id}"
    assertion = {
        InvariantRelation.EQ: "assertEq",
        InvariantRelation.GTE: "assertGe",
        InvariantRelation.LTE: "assertLe",
    }[property_spec.relation]
    lines.extend(
        (
            f'        {assertion}({left_value}, {right_value}, "invariant violated");',
            "    }",
            "",
        )
    )
    return lines


def _financial_settlement_test_lines(
    specification: FoundryInvariantHarnessSpec,
) -> list[str]:
    """Render one deterministic action plus exact single-asset settlement checks."""

    settlement = specification.financial_settlement
    assert settlement is not None
    action = next(item for item in specification.actions if item.action_id == settlement.action_id)
    fuzz_slots = {
        argument.fuzz_slot
        for argument in action.arguments
        if argument.source is not HarnessArgumentSource.CONSTANT and argument.fuzz_slot is not None
    }
    if action.actor_fuzz_slot is not None:
        fuzz_slots.add(action.actor_fuzz_slot)
    call_arguments = ", ".join("0" for _ in sorted(fuzz_slots))
    lines = [
        "    function mmauditFinancialProbe(address target, string memory signature)",
        "        internal view returns (uint256)",
        "    {",
        "        (bool success, bytes memory data) = target.staticcall(",
        "            abi.encodeWithSignature(signature)",
        "        );",
        '        require(success && data.length >= 32, "financial probe failed");',
        "        return abi.decode(data, (uint256));",
        "    }",
        "",
        "    function test_MMAuditFinancialSettlement() public {",
        f"        handler.action_{action.action_id}({call_arguments});"
        if call_arguments
        else f"        handler.action_{action.action_id}();",
    ]
    probes = (
        ("startingAssets", settlement.starting_assets),
        ("borrowedAssets", settlement.borrowed_assets),
        ("repaidAssets", settlement.repaid_assets),
        ("grossAssetsReceived", settlement.gross_assets_received),
        ("feesPaid", settlement.fees_paid),
        ("slippageLoss", settlement.slippage_loss),
        ("endingAssets", settlement.ending_assets),
        ("netImpact", settlement.net_impact),
    )
    for prefix, probe in probes:
        lines.extend(
            (
                f"        uint256 {prefix}Value = mmauditFinancialProbe(",
                f"            target_{probe.target},",
                f'            "{probe.function_signature}"',
                "        );",
            )
        )
    flash_limit = (
        specification.capability_policy.flash_liquidity_wei
        if specification.capability_policy is not None
        else 0
    )
    borrowing_assertions = (
        (
            '        assertGe(borrowedAssetsValue, 1, "temporary principal not observed");',
            f"        assertLe(borrowedAssetsValue, {flash_limit}, "
            '"temporary principal exceeds policy");',
        )
        if specification.economic_template is EconomicSimulationKind.FLASH_ORACLE
        else ('        assertEq(borrowedAssetsValue, 0, "unexpected borrowed assets");',)
    )
    lines.extend(
        (
            *borrowing_assertions,
            '        assertEq(repaidAssetsValue, borrowedAssetsValue, "principal not repaid");',
            "        uint256 settlementInflows = startingAssetsValue",
            "            + borrowedAssetsValue + grossAssetsReceivedValue;",
            "        uint256 settlementOutflows = repaidAssetsValue",
            "            + feesPaidValue + slippageLossValue;",
            '        assertGe(settlementInflows, settlementOutflows, "negative uint settlement");',
            "        assertEq(",
            "            endingAssetsValue,",
            "            settlementInflows - settlementOutflows,",
            '            "ending assets do not reconcile"',
            "        );",
            '        assertGe(endingAssetsValue, startingAssetsValue, "negative net impact");',
            "        assertEq(",
            "            netImpactValue,",
            "            endingAssetsValue - startingAssetsValue,",
            '            "net impact does not reconcile"',
            "        );",
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_STARTING_ASSETS", '
            "startingAssetsValue);",
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_BORROWED_ASSETS", '
            "borrowedAssetsValue);",
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_REPAID_ASSETS", repaidAssetsValue);',
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_GROSS_ASSETS_RECEIVED", '
            "grossAssetsReceivedValue);",
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_FEES_PAID", feesPaidValue);',
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_SLIPPAGE_LOSS", slippageLossValue);',
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_ENDING_ASSETS", endingAssetsValue);',
            '        emit log_named_uint("MMAUDIT_SETTLEMENT_NET_IMPACT", netImpactValue);',
        )
    )
    boundary = specification.lending_boundary
    if boundary is not None:
        boundary_probes = (
            ("debtBefore", boundary.debt_before),
            ("collateralBefore", boundary.collateral_before),
            ("debtAfter", boundary.debt_after),
            ("collateralAfter", boundary.collateral_after),
            ("collateralSeized", boundary.collateral_seized),
            ("badDebtAfter", boundary.bad_debt_after),
        )
        for prefix, probe in boundary_probes:
            lines.extend(
                (
                    f"        uint256 {prefix}Value = mmauditFinancialProbe(",
                    f"            target_{probe.target},",
                    f'            "{probe.function_signature}"',
                    "        );",
                )
            )
        lines.extend(
            (
                '        assertGe(collateralBeforeValue, debtBeforeValue, "position not healthy");',
                '        assertLe(debtAfterValue, debtBeforeValue, "position debt increased");',
                "        assertLe(",
                "            collateralAfterValue,",
                "            collateralBeforeValue,",
                '            "position collateral increased"',
                "        );",
                "        assertEq(",
                "            collateralSeizedValue,",
                "            collateralBeforeValue - collateralAfterValue,",
                '            "collateral transition does not reconcile"',
                "        );",
                "        uint256 expectedBadDebtAfter = debtAfterValue > collateralAfterValue",
                "            ? debtAfterValue - collateralAfterValue : 0;",
                "        assertEq(",
                "            badDebtAfterValue,",
                "            expectedBadDebtAfter,",
                '            "bad debt does not reconcile"',
                "        );",
                "        assertEq(",
                "            grossAssetsReceivedValue,",
                "            collateralSeizedValue,",
                '            "liquidator settlement does not match collateral seized"',
                "        );",
                '        emit log_named_uint("MMAUDIT_LENDING_DEBT_BEFORE", debtBeforeValue);',
                '        emit log_named_uint("MMAUDIT_LENDING_COLLATERAL_BEFORE", '
                "collateralBeforeValue);",
                '        emit log_named_uint("MMAUDIT_LENDING_DEBT_AFTER", debtAfterValue);',
                '        emit log_named_uint("MMAUDIT_LENDING_COLLATERAL_AFTER", '
                "collateralAfterValue);",
                '        emit log_named_uint("MMAUDIT_LENDING_COLLATERAL_SEIZED", '
                "collateralSeizedValue);",
                '        emit log_named_uint("MMAUDIT_LENDING_BAD_DEBT_AFTER", badDebtAfterValue);',
            )
        )
    rate_boundary = specification.share_price_boundary
    if rate_boundary is not None:
        lines.append("        mmauditValidateSharePriceBoundary(grossAssetsReceivedValue);")
    lines.extend(("    }", ""))
    if rate_boundary is not None:
        lines.extend(
            (
                "    function mmauditValidateSharePriceBoundary(uint256 grossAssetsReceivedValue)",
                "        internal",
                "    {",
                "        uint256 rateScaleValue = mmauditFinancialProbe(",
                f"            target_{rate_boundary.rate_scale.target},",
                f'            "{rate_boundary.rate_scale.function_signature}"',
                "        );",
                '        assertGe(rateScaleValue, 1, "rate scale is zero");',
                "        uint256 expectedRateAfterYieldValue;",
                "        {",
                "            uint256 totalAssetsBeforeValue = mmauditFinancialProbe(",
                f"                target_{rate_boundary.total_assets_before.target},",
                f'                "{rate_boundary.total_assets_before.function_signature}"',
                "            );",
                "            uint256 totalSharesBeforeValue = mmauditFinancialProbe(",
                f"                target_{rate_boundary.total_shares_before.target},",
                f'                "{rate_boundary.total_shares_before.function_signature}"',
                "            );",
                "            uint256 legitimateYieldValue = mmauditFinancialProbe(",
                f"                target_{rate_boundary.legitimate_yield.target},",
                f'                "{rate_boundary.legitimate_yield.function_signature}"',
                "            );",
                "            expectedRateAfterYieldValue = mmauditFinancialProbe(",
                f"                target_{rate_boundary.expected_rate_after_yield.target},",
                f'                "{rate_boundary.expected_rate_after_yield.function_signature}"',
                "            );",
                '            assertGe(totalSharesBeforeValue, 1, "share supply is zero");',
                "            uint256 assetsAfterYield = totalAssetsBeforeValue",
                "                + legitimateYieldValue;",
                "            assertEq(",
                "                expectedRateAfterYieldValue,",
                "                assetsAfterYield * rateScaleValue / totalSharesBeforeValue,",
                '                "yield-adjusted rate does not reconcile"',
                "            );",
                '            emit log_named_uint("MMAUDIT_SHARE_TOTAL_ASSETS_BEFORE", '
                "totalAssetsBeforeValue);",
                '            emit log_named_uint("MMAUDIT_SHARE_TOTAL_SHARES_BEFORE", '
                "totalSharesBeforeValue);",
                '            emit log_named_uint("MMAUDIT_SHARE_LEGITIMATE_YIELD", '
                "legitimateYieldValue);",
                "        }",
                "        uint256 observedRateAfterValue = mmauditFinancialProbe(",
                f"            target_{rate_boundary.observed_rate_after.target},",
                f'            "{rate_boundary.observed_rate_after.function_signature}"',
                "        );",
                "        uint256 sharesRedeemedValue = mmauditFinancialProbe(",
                f"            target_{rate_boundary.shares_redeemed.target},",
                f'            "{rate_boundary.shares_redeemed.function_signature}"',
                "        );",
                "        uint256 assetsRedeemedValue = mmauditFinancialProbe(",
                f"            target_{rate_boundary.assets_redeemed.target},",
                f'            "{rate_boundary.assets_redeemed.function_signature}"',
                "        );",
                "        uint256 excessAssetsValue = mmauditFinancialProbe(",
                f"            target_{rate_boundary.excess_assets.target},",
                f'            "{rate_boundary.excess_assets.function_signature}"',
                "        );",
                "        uint256 expectedAssetsRedeemed = sharesRedeemedValue",
                "            * expectedRateAfterYieldValue / rateScaleValue;",
                "        assertEq(",
                "            assetsRedeemedValue,",
                "            sharesRedeemedValue * observedRateAfterValue / rateScaleValue,",
                '            "observed redemption does not reconcile"',
                "        );",
                "        uint256 calculatedExcessAssets = assetsRedeemedValue",
                "            > expectedAssetsRedeemed",
                "            ? assetsRedeemedValue - expectedAssetsRedeemed : 0;",
                "        assertEq(",
                "            excessAssetsValue,",
                "            calculatedExcessAssets,",
                '            "excess redemption does not reconcile"',
                "        );",
                "        assertEq(",
                "            grossAssetsReceivedValue,",
                "            assetsRedeemedValue,",
                '            "settlement does not match assets redeemed"',
                "        );",
                '        emit log_named_uint("MMAUDIT_SHARE_RATE_SCALE", rateScaleValue);',
                '        emit log_named_uint("MMAUDIT_SHARE_EXPECTED_RATE_AFTER_YIELD", '
                "expectedRateAfterYieldValue);",
                '        emit log_named_uint("MMAUDIT_SHARE_OBSERVED_RATE_AFTER", '
                "observedRateAfterValue);",
                '        emit log_named_uint("MMAUDIT_SHARE_SHARES_REDEEMED", '
                "sharesRedeemedValue);",
                '        emit log_named_uint("MMAUDIT_SHARE_ASSETS_REDEEMED", '
                "assetsRedeemedValue);",
                '        emit log_named_uint("MMAUDIT_SHARE_EXCESS_ASSETS", excessAssetsValue);',
                "    }",
                "",
            )
        )
    return lines


def _probe_lines(
    probe: InvariantProbe,
    prefix: str,
    *,
    targets: dict[str, str],
    local_targets: set[str],
) -> tuple[list[str], str]:
    arguments = ", ".join(
        _invariant_argument_literal(
            argument,
            targets=targets,
            local_targets=local_targets,
        )
        for argument in probe.arguments
    )
    comma = ", " if arguments else ""
    return (
        [
            f"(bool {prefix}Ok, bytes memory {prefix}Data) = "
            f"target_{probe.target}.staticcall("
            f'abi.encodeWithSignature("{probe.function_signature}"{comma}{arguments}));',
            f'require({prefix}Ok && {prefix}Data.length >= 32, "probe failed");',
            f"uint256 {prefix}Value = abi.decode({prefix}Data, (uint256));",
        ],
        f"{prefix}Value",
    )


class FoundryInvariantRunner:
    """Run only typed invariant harnesses against a loopback local fork."""

    def __init__(
        self,
        reproduction: ReproductionConfig,
        smart_contracts: SmartContractsConfig,
        *,
        backend: IsolationBackend | None = None,
        forge_executable: Path | None = None,
        solc_executable: Path | None = None,
    ) -> None:
        self.reproduction = reproduction
        self.smart_contracts = smart_contracts
        self.backend = (
            backend
            if backend is not None
            else default_isolation_backend(
                reproduction.isolation_backend,
                rootless_container_image=reproduction.rootless_container_image,
                rootless_container_runtime=reproduction.rootless_container_runtime,
            )
        )
        self.forge_executable = forge_executable
        self.solc_executable = solc_executable

    @property
    def isolation_available(self) -> bool:
        return self.backend is not None and bool(
            getattr(self.backend, "supports_local_fork_rpc", True)
        )

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        specification: FoundryInvariantHarnessSpec,
        private_dir: Path,
    ) -> InvariantExecutionResult:
        started = time.monotonic()
        base = {
            "invariant_id": specification.invariant_id,
            "harness_name": specification.name,
            "runs": specification.runs,
            "depth": specification.depth,
            "seed": specification.seed,
            "economic_template": specification.economic_template,
            "required_transaction_ordering": specification.required_transaction_ordering,
            "capability_policy": specification.capability_policy,
        }
        if specification.capability_policy is not None:
            policy_error = attacker_capability_policy_error(
                specification.capability_policy,
                self.reproduction,
                attack_transactions=(
                    len(specification.required_action_sequence)
                    if specification.required_action_sequence
                    else len(specification.actions) * specification.depth
                ),
            )
            if policy_error is not None:
                return InvariantExecutionResult(
                    **base,
                    status=InvariantExecutionStatus.GENERATION_FAILED,
                    limitations=[policy_error],
                    duration_seconds=time.monotonic() - started,
                )
        ordering_rank = {
            TransactionOrderingCapability.NONE: 0,
            TransactionOrderingCapability.SAME_BLOCK: 1,
            TransactionOrderingCapability.MULTI_TRANSACTION: 2,
        }
        if (
            ordering_rank[specification.required_transaction_ordering]
            > ordering_rank[self.reproduction.allowed_transaction_ordering]
        ):
            return InvariantExecutionResult(
                **base,
                status=InvariantExecutionStatus.GENERATION_FAILED,
                limitations=["required transaction-ordering capability is not operator-authorized"],
                duration_seconds=time.monotonic() - started,
            )
        if project.project_type not in {
            SolidityProjectType.FOUNDRY,
            SolidityProjectType.MIXED,
        }:
            return InvariantExecutionResult(
                **base,
                status=InvariantExecutionStatus.GENERATION_FAILED,
                limitations=["generated stateful invariants currently require Foundry"],
                duration_seconds=time.monotonic() - started,
            )
        if self.backend is None:
            return InvariantExecutionResult(
                **base,
                status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                limitations=["no hardened isolation backend is available"],
                duration_seconds=time.monotonic() - started,
            )
        local_only = bool(specification.local_deployments)
        if not local_only and not getattr(self.backend, "supports_local_fork_rpc", True):
            return InvariantExecutionResult(
                **base,
                status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                limitations=[
                    f"{self.backend.name} denies network access and cannot reach a host "
                    "loopback fork RPC"
                ],
                isolation_backend=self.backend.name,
                duration_seconds=time.monotonic() - started,
            )
        forge = self.forge_executable or _external_executable(repository_root, "forge")
        if forge is None:
            return InvariantExecutionResult(
                **base,
                status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                limitations=["forge is not installed outside the audited repository"],
                isolation_backend=self.backend.name,
                duration_seconds=time.monotonic() - started,
            )
        compiler: Path | None = None
        compiler_sha256: str | None = None
        if local_only:
            if self.solc_executable is None:
                return InvariantExecutionResult(
                    **base,
                    status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                    limitations=[
                        "source-local invariant execution requires an explicitly selected "
                        "external Solidity compiler"
                    ],
                    isolation_backend=self.backend.name,
                    duration_seconds=time.monotonic() - started,
                )
            try:
                compiler = _validated_external_executable(
                    repository_root,
                    self.solc_executable,
                )
                compiler_sha256 = _file_sha256(compiler)
            except (OSError, ValueError) as exc:
                return InvariantExecutionResult(
                    **base,
                    status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                    limitations=[
                        f"external Solidity compiler validation failed: {type(exc).__name__}"
                    ],
                    isolation_backend=self.backend.name,
                    duration_seconds=time.monotonic() - started,
                )
        rpc_url: str | None = None
        rpc_port = 0
        if not local_only:
            try:
                rpc_url, rpc_port = _local_rpc(
                    os.environ.get(self.smart_contracts.fork_rpc_url_env, "")
                )
            except ValueError as exc:
                return InvariantExecutionResult(
                    **base,
                    status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                    limitations=[f"local fork RPC validation failed: {exc}"],
                    isolation_backend=self.backend.name,
                    duration_seconds=time.monotonic() - started,
                )
        try:
            source = translate_foundry_invariant(
                specification,
                targets=self.reproduction.targets,
                expected_chain_id=self.reproduction.expected_chain_id,
            )
            source_hash = hashlib.sha256(source.encode()).hexdigest()
        except (OSError, ValueError) as exc:
            return InvariantExecutionResult(
                **base,
                status=InvariantExecutionStatus.GENERATION_FAILED,
                limitations=[f"safe invariant generation failed: {type(exc).__name__}: {exc}"],
                isolation_backend=self.backend.name,
                duration_seconds=time.monotonic() - started,
            )
        attempt_limit = max(2, self.reproduction.repetitions)
        executions: list[_InvariantExecution] = []
        attempt_evidence: list[InvariantExecutionAttemptEvidence] = []
        display_command: list[str] = []
        test_paths: list[Path] = []
        completed_statuses = {
            InvariantExecutionStatus.PASSED,
            InvariantExecutionStatus.COUNTEREXAMPLE,
        }
        for attempt in range(1, attempt_limit + 1):
            attempt_root = private_dir / source_hash[:16] / f"attempt-{attempt}"
            workspace = attempt_root / "workspace"
            copied_compiler: Path | None = None
            try:
                _copy_project(repository_root, project, workspace)
                test_dir = workspace / "test" / "mmaudit_generated"
                test_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                test_path = test_dir / f"MMAuditInvariant_{specification.name}.t.sol"
                test_path.write_text(source, encoding="utf-8")
                if compiler is not None:
                    toolchain_dir = test_dir / "toolchain"
                    toolchain_dir.mkdir(mode=0o700)
                    copied_compiler = toolchain_dir / "solc"
                    shutil.copyfile(compiler, copied_compiler)
                    copied_compiler.chmod(0o500)
            except (OSError, ValueError) as exc:
                return InvariantExecutionResult(
                    **base,
                    status=InvariantExecutionStatus.GENERATION_FAILED,
                    source_sha256=source_hash,
                    limitations=[
                        f"safe invariant workspace creation failed: {type(exc).__name__}: {exc}"
                    ],
                    isolation_backend=self.backend.name,
                    duration_seconds=time.monotonic() - started,
                )
            test_paths.append(test_path)
            relative_test = test_path.relative_to(workspace).as_posix()
            command = [
                str(forge),
                "test",
                "--root",
                str(workspace),
                "--match-path",
                relative_test,
                "--match-contract",
                f"MMAuditInvariant_{specification.name}",
            ]
            if rpc_url is not None:
                command.extend(["--fork-url", rpc_url])
            if copied_compiler is not None:
                command.extend(["--use", str(copied_compiler)])
            command.extend(
                [
                    "--offline",
                    "--color",
                    "never",
                    "--fuzz-runs",
                    str(specification.runs),
                    "--fuzz-seed",
                    str(specification.seed),
                    "-vvv",
                ]
            )
            display_command = [
                "[FORGE]",
                *(
                    "[REDACTED_LOCAL_FORK_RPC]"
                    if item == rpc_url
                    else "[WORKSPACE]"
                    if item == str(workspace)
                    else "[PINNED_SOLC]"
                    if copied_compiler is not None and item == str(copied_compiler)
                    else item
                    for item in command[1:]
                ),
            ]
            execution = self._execute(
                command,
                workspace=workspace,
                private_dir=attempt_root,
                rpc_port=rpc_port,
                runs=specification.runs,
                depth=specification.depth,
                seed=specification.seed,
                action_functions={
                    action.action_id: action.function_signature for action in specification.actions
                },
                property_ids={
                    property_spec.property_id for property_spec in specification.properties
                },
            )
            executions.append(execution)
            attempt_evidence.append(
                InvariantExecutionAttemptEvidence(
                    attempt=attempt,
                    status=execution.status,
                    source_sha256=source_hash,
                    fresh_workspace=True,
                    stdout_sha256=hashlib.sha256(execution.stdout_path.read_bytes()).hexdigest(),
                    stderr_sha256=hashlib.sha256(execution.stderr_path.read_bytes()).hexdigest(),
                    stdout_path=execution.stdout_path.relative_to(private_dir).as_posix(),
                    stderr_path=execution.stderr_path.relative_to(private_dir).as_posix(),
                )
            )
            if execution.status not in completed_statuses:
                break
        first_status = executions[0].status
        replay_confirmed = (
            len(executions) >= 2
            and first_status in completed_statuses
            and all(execution.status is first_status for execution in executions)
        )
        status = (
            first_status
            if len(executions) == 1 or replay_confirmed
            else InvariantExecutionStatus.EXECUTION_FAILED
        )
        limitations = list(
            dict.fromkeys(
                limitation for execution in executions for limitation in execution.limitations
            )
        )
        if len(executions) > 1 and not replay_confirmed:
            limitations.append("clean invariant replay produced inconsistent outcomes")
        counterexample_sequence: _FoundryCounterexampleSequence | None = None
        if (
            status is InvariantExecutionStatus.COUNTEREXAMPLE
            and specification.required_action_sequence
        ):
            first_sequence = executions[0]
            sequence_consistent = (
                first_sequence.counterexample_action_ids == specification.required_action_sequence
                and first_sequence.original_sequence_length is not None
                and first_sequence.shrunk_sequence_length
                == len(specification.required_action_sequence)
                and all(
                    execution.counterexample_action_ids == first_sequence.counterexample_action_ids
                    and execution.original_sequence_length
                    == first_sequence.original_sequence_length
                    and execution.shrunk_sequence_length == first_sequence.shrunk_sequence_length
                    for execution in executions
                )
            )
            if sequence_consistent:
                assert first_sequence.original_sequence_length is not None
                assert first_sequence.shrunk_sequence_length is not None
                counterexample_sequence = _FoundryCounterexampleSequence(
                    original_length=first_sequence.original_sequence_length,
                    shrunk_length=first_sequence.shrunk_sequence_length,
                    action_ids=first_sequence.counterexample_action_ids,
                )
            else:
                status = InvariantExecutionStatus.EXECUTION_FAILED
                replay_confirmed = False
                limitations.append(
                    "counterexample action sequence was missing, unexpected, or "
                    "inconsistent across clean replay"
                )
        settlement_evidence: FinancialSettlementEvidence | None = None
        if specification.financial_settlement is not None:
            settlements = [
                _financial_settlement_from_execution(
                    execution,
                    specification.financial_settlement,
                )
                for execution in executions
            ]
            settlement_evidence = settlements[0] if settlements else None
            settlement_consistent = settlement_evidence is not None and all(
                item == settlement_evidence for item in settlements
            )
            if not settlement_consistent:
                status = InvariantExecutionStatus.EXECUTION_FAILED
                replay_confirmed = False
                settlement_evidence = None
                limitations.append(
                    "financial settlement evidence was missing, invalid, or inconsistent "
                    "across clean replay"
                )
        lending_evidence: LendingBoundaryEvidence | None = None
        if specification.lending_boundary is not None:
            boundaries = [_lending_boundary_from_execution(execution) for execution in executions]
            lending_evidence = boundaries[0] if boundaries else None
            boundary_consistent = lending_evidence is not None and all(
                item == lending_evidence for item in boundaries
            )
            if not boundary_consistent:
                status = InvariantExecutionStatus.EXECUTION_FAILED
                replay_confirmed = False
                lending_evidence = None
                limitations.append(
                    "lending boundary evidence was missing, invalid, or inconsistent "
                    "across clean replay"
                )
        share_price_evidence: SharePriceBoundaryEvidence | None = None
        if specification.share_price_boundary is not None:
            share_prices = [
                _share_price_boundary_from_execution(execution) for execution in executions
            ]
            share_price_evidence = share_prices[0] if share_prices else None
            share_price_consistent = share_price_evidence is not None and all(
                item == share_price_evidence for item in share_prices
            )
            if not share_price_consistent:
                status = InvariantExecutionStatus.EXECUTION_FAILED
                replay_confirmed = False
                share_price_evidence = None
                limitations.append(
                    "share-price boundary evidence was missing, invalid, or inconsistent "
                    "across clean replay"
                )
        minimization_evidence: InvariantExecutionMinimizationEvidence | None = None
        if status is InvariantExecutionStatus.COUNTEREXAMPLE and replay_confirmed:
            action_ids = [action.action_id for action in specification.actions]
            if len(action_ids) == 1:
                minimization_evidence = InvariantExecutionMinimizationEvidence(
                    original_action_ids=action_ids,
                    retained_action_ids=action_ids,
                    strategy="single_action_trivial",
                    proven_minimal=True,
                )
            elif (
                specification.economic_template is EconomicSimulationKind.STATE_ORDERING
                and counterexample_sequence is not None
            ):
                removal_trials: list[InvariantExecutionRemovalTrial] = []
                for index, removed_action_id in enumerate(specification.required_action_sequence):
                    retained_ids = [
                        action_id
                        for action_id in specification.required_action_sequence
                        if action_id != removed_action_id
                    ]
                    retained = set(retained_ids)
                    reduced_policy = (
                        specification.capability_policy.model_copy(
                            update={
                                "transaction_ordering": TransactionOrderingCapability.NONE,
                                "capability_justifications": {},
                            }
                        )
                        if specification.capability_policy is not None
                        else None
                    )
                    reduced_draft = specification.model_copy(
                        update={
                            "invariant_id": (
                                f"{specification.invariant_id[:120]}:"
                                f"remove:{removed_action_id[:24]}"
                            ),
                            "name": f"{specification.name[:54]}R{index + 1}",
                            "actions": [
                                action
                                for action in specification.actions
                                if action.action_id in retained
                            ],
                            "required_action_sequence": [],
                            "properties": [
                                property_spec.model_copy(
                                    update={
                                        "required_action_ids": [
                                            action_id
                                            for action_id in property_spec.required_action_ids
                                            if action_id in retained
                                        ]
                                    }
                                )
                                for property_spec in specification.properties
                            ],
                            "runs": min(specification.runs, 16),
                            "depth": 1,
                            "economic_template": None,
                            "required_transaction_ordering": (TransactionOrderingCapability.NONE),
                            "capability_policy": reduced_policy,
                        }
                    )
                    reduced_specification = FoundryInvariantHarnessSpec.model_validate(
                        reduced_draft.model_dump(mode="json")
                    )
                    trial_result = self.run(
                        repository_root=repository_root,
                        project=project,
                        specification=reduced_specification,
                        private_dir=(
                            private_dir / "minimization" / f"remove-{index + 1}-{removed_action_id}"
                        ),
                    )
                    if (
                        trial_result.status is not InvariantExecutionStatus.PASSED
                        or not trial_result.replay_confirmed
                    ):
                        limitations.append(
                            f"bounded minimization trial removing {removed_action_id} "
                            "did not pass on clean replay"
                        )
                        removal_trials = []
                        break
                    removal_trials.append(
                        InvariantExecutionRemovalTrial(
                            removed_action_id=removed_action_id,
                            retained_action_ids=retained_ids,
                            status=trial_result.status,
                            replay_confirmed=trial_result.replay_confirmed,
                            seed=trial_result.seed,
                        )
                    )
                if len(removal_trials) == len(specification.required_action_sequence):
                    minimization_evidence = InvariantExecutionMinimizationEvidence(
                        original_action_ids=specification.required_action_sequence,
                        retained_action_ids=counterexample_sequence.action_ids,
                        strategy="bounded_action_removal",
                        proven_minimal=True,
                        foundry_original_sequence_length=(counterexample_sequence.original_length),
                        foundry_shrunk_sequence_length=(counterexample_sequence.shrunk_length),
                        removal_trials=removal_trials,
                    )
            else:
                limitations.append("counterexample action sequence was replayed but not minimized")
        first_execution = executions[0]
        first_test_path = test_paths[0]
        return InvariantExecutionResult(
            **base,
            status=status,
            source_sha256=source_hash,
            compiler_sha256=compiler_sha256,
            command=display_command,
            economic_metrics=_economic_metrics_from_specification(
                specification,
                settlement_evidence,
                lending_evidence,
                share_price_evidence,
            ),
            attempts=len(executions),
            successful_attempts=sum(
                execution.status in completed_statuses for execution in executions
            ),
            replay_confirmed=replay_confirmed,
            attempt_evidence=attempt_evidence,
            minimization_evidence=minimization_evidence,
            campaign_coverage=_invariant_campaign_coverage(
                specification,
                executions,
                minimization_evidence,
            ),
            duration_seconds=time.monotonic() - started,
            limitations=limitations,
            counterexample_summary=_contextual_counterexample_summary(
                specification,
                first_execution.counterexample_summary,
                lending_evidence,
                share_price_evidence,
            )
            if status is InvariantExecutionStatus.COUNTEREXAMPLE
            else None,
            source_path=first_test_path.relative_to(private_dir).as_posix(),
            stdout_path=first_execution.stdout_path.relative_to(private_dir).as_posix(),
            stderr_path=first_execution.stderr_path.relative_to(private_dir).as_posix(),
            isolation_backend=self.backend.name,
        )

    def _execute(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
        runs: int,
        depth: int,
        seed: int,
        action_functions: dict[str, str],
        property_ids: set[str],
    ) -> _InvariantExecution:
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        assert self.backend is not None
        wrapped = self.backend.wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=rpc_port,
        )
        stdout_path = private_dir / "stdout.txt"
        stderr_path = private_dir / "stderr.txt"
        environment = sanitized_scanner_environment(private_dir)
        environment.update(
            {
                "FOUNDRY_FFI": "false",
                "FOUNDRY_NO_STORAGE_CACHING": "true",
                "FOUNDRY_INVARIANT_RUNS": str(runs),
                "FOUNDRY_INVARIANT_DEPTH": str(depth),
                "FOUNDRY_FUZZ_SEED": str(seed),
            }
        )
        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        output_exceeded = False
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    wrapped,
                    cwd=workspace,
                    stdout=stdout,
                    stderr=stderr,
                    env=environment,
                    shell=False,
                    start_new_session=os.name != "nt",
                    preexec_fn=_limit_invariant_process if os.name != "nt" else None,
                )
                deadline = time.monotonic() + self.reproduction.timeout_seconds
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _stop_process(process)
                        break
                    if (
                        stdout_path.stat().st_size > self.reproduction.max_output_bytes
                        or stderr_path.stat().st_size > self.reproduction.max_output_bytes
                    ):
                        output_exceeded = True
                        _stop_process(process)
                        break
                    time.sleep(0.05)
                return_code = process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if process is not None:
                _stop_process(process)
            return _InvariantExecution(
                status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                limitations=[f"isolated invariant execution failed: {type(exc).__name__}"],
            )
        if timed_out:
            return _InvariantExecution(
                status=InvariantExecutionStatus.TIMED_OUT,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                limitations=["generated invariant campaign timed out"],
            )
        if output_exceeded:
            return _InvariantExecution(
                status=InvariantExecutionStatus.EXECUTION_FAILED,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                limitations=["generated invariant campaign exceeded the output limit"],
            )
        output = "\n".join(
            (
                stdout_path.read_text(encoding="utf-8", errors="replace"),
                stderr_path.read_text(encoding="utf-8", errors="replace"),
            )
        )
        status, limitations, counterexample = normalize_foundry_invariant_output(
            return_code,
            output,
        )
        sequence = _foundry_counterexample_sequence(output, set(action_functions))
        observed_action_ids = sorted(
            set(
                re.findall(
                    r"\baction_([A-Za-z][A-Za-z0-9_]{0,47})(?:\(\))?",
                    output,
                )
            )
            & set(action_functions)
        )
        observed_property_ids = sorted(
            set(
                re.findall(
                    r"\binvariant_([A-Za-z][A-Za-z0-9_]{0,47})\(\)",
                    output,
                )
            )
            & property_ids
        )
        observed_sequence_lengths = sorted(
            {
                int(length)
                for length in re.findall(
                    r"\[Sequence\]\s+\(original:\s*[0-9]+,\s*shrunk:\s*([0-9]+)\)",
                    output,
                )
                if 1 <= int(length) <= depth
            }
        )
        return _InvariantExecution(
            status=status,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            limitations=limitations,
            counterexample_summary=counterexample,
            counterexample_action_ids=sequence.action_ids if sequence is not None else [],
            original_sequence_length=(sequence.original_length if sequence is not None else None),
            shrunk_sequence_length=(sequence.shrunk_length if sequence is not None else None),
            observed_action_functions=sorted(
                {action_functions[action_id] for action_id in observed_action_ids}
            ),
            observed_state_properties=observed_property_ids,
            observed_sequence_lengths=observed_sequence_lengths,
        )


def _validated_external_executable(repository_root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError("selected compiler is not an executable regular file")
    try:
        resolved.relative_to(repository_root.resolve(strict=True))
    except ValueError:
        return resolved
    raise ValueError("selected compiler resolves inside the audited repository")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _limit_invariant_process() -> None:
    """Apply bounded local limits without lowering macOS's user-wide process ceiling."""

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50_000_000, 50_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        if sys.platform != "darwin" and hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ImportError, OSError, ValueError):
        return


@dataclass(frozen=True)
class _InvariantExecution:
    status: InvariantExecutionStatus
    stdout_path: Path
    stderr_path: Path
    limitations: list[str]
    counterexample_summary: str | None = None
    counterexample_action_ids: list[str] = dataclass_field(default_factory=list)
    original_sequence_length: int | None = None
    shrunk_sequence_length: int | None = None
    observed_action_functions: list[str] = dataclass_field(default_factory=list)
    observed_state_properties: list[str] = dataclass_field(default_factory=list)
    observed_sequence_lengths: list[int] = dataclass_field(default_factory=list)


@dataclass(frozen=True)
class _FoundryCounterexampleSequence:
    original_length: int
    shrunk_length: int
    action_ids: list[str]


def _foundry_counterexample_sequence(
    output: str,
    declared_action_ids: set[str],
) -> _FoundryCounterexampleSequence | None:
    """Parse one unambiguous bounded Foundry shrink sequence from retained output."""

    header_pattern = re.compile(r"\[Sequence\]\s+\(original:\s*([0-9]+),\s*shrunk:\s*([0-9]+)\)")
    candidates: set[tuple[int, int, tuple[str, ...]]] = set()
    for header in header_pattern.finditer(output):
        original_length = int(header.group(1))
        shrunk_length = int(header.group(2))
        suffix = output[header.end() :]
        invariant_line = re.search(r"(?m)^\s*invariant_[A-Za-z0-9_]+\(\)", suffix)
        if invariant_line is None:
            continue
        block = suffix[: invariant_line.start()]
        action_ids = re.findall(
            r"\bcalldata=action_([A-Za-z][A-Za-z0-9_]{0,47})\(",
            block,
        )
        if (
            not action_ids
            or len(action_ids) != shrunk_length
            or not set(action_ids) <= declared_action_ids
            or shrunk_length > original_length
        ):
            continue
        candidates.add((original_length, shrunk_length, tuple(action_ids)))
    if len(candidates) != 1:
        return None
    original_length, shrunk_length, retained_action_ids = candidates.pop()
    return _FoundryCounterexampleSequence(
        original_length=original_length,
        shrunk_length=shrunk_length,
        action_ids=list(retained_action_ids),
    )


def _invariant_campaign_coverage(
    specification: FoundryInvariantHarnessSpec,
    executions: list[_InvariantExecution],
    minimization: InvariantExecutionMinimizationEvidence | None,
) -> InvariantCampaignCoverage:
    """Keep observed function, state-property, and sequence dimensions independent."""

    attempt_dimensions = [
        (
            tuple(execution.observed_action_functions),
            tuple(execution.observed_state_properties),
            tuple(execution.observed_sequence_lengths),
        )
        for execution in executions
    ]
    observed_sequence_lengths = sorted(
        {length for execution in executions for length in execution.observed_sequence_lengths}
    )
    minimized_action_ids = (
        list(minimization.retained_action_ids)
        if minimization is not None
        and minimization.proven_minimal
        and len(minimization.retained_action_ids) in observed_sequence_lengths
        else []
    )
    return InvariantCampaignCoverage(
        declared_action_functions=sorted(
            {action.function_signature for action in specification.actions}
        ),
        observed_action_functions=sorted(
            {
                signature
                for execution in executions
                for signature in execution.observed_action_functions
            }
        ),
        declared_state_properties=sorted(
            {property_spec.property_id for property_spec in specification.properties}
        ),
        observed_state_properties=sorted(
            {
                property_id
                for execution in executions
                for property_id in execution.observed_state_properties
            }
        ),
        sequence_depth_bound=specification.depth,
        observed_sequence_lengths=observed_sequence_lengths,
        minimized_sequence_action_ids=minimized_action_ids,
        attempts_consistent=len(set(attempt_dimensions)) <= 1,
    )


_SETTLEMENT_OUTPUT_LABELS = {
    "starting_assets": "MMAUDIT_SETTLEMENT_STARTING_ASSETS",
    "borrowed_assets": "MMAUDIT_SETTLEMENT_BORROWED_ASSETS",
    "repaid_assets": "MMAUDIT_SETTLEMENT_REPAID_ASSETS",
    "gross_assets_received": "MMAUDIT_SETTLEMENT_GROSS_ASSETS_RECEIVED",
    "fees_paid": "MMAUDIT_SETTLEMENT_FEES_PAID",
    "slippage_loss": "MMAUDIT_SETTLEMENT_SLIPPAGE_LOSS",
    "ending_assets": "MMAUDIT_SETTLEMENT_ENDING_ASSETS",
    "net_impact": "MMAUDIT_SETTLEMENT_NET_IMPACT",
}

_LENDING_BOUNDARY_OUTPUT_LABELS = {
    "debt_before": "MMAUDIT_LENDING_DEBT_BEFORE",
    "collateral_before": "MMAUDIT_LENDING_COLLATERAL_BEFORE",
    "debt_after": "MMAUDIT_LENDING_DEBT_AFTER",
    "collateral_after": "MMAUDIT_LENDING_COLLATERAL_AFTER",
    "collateral_seized": "MMAUDIT_LENDING_COLLATERAL_SEIZED",
    "bad_debt_after": "MMAUDIT_LENDING_BAD_DEBT_AFTER",
}

_SHARE_PRICE_OUTPUT_LABELS = {
    "rate_scale": "MMAUDIT_SHARE_RATE_SCALE",
    "total_assets_before": "MMAUDIT_SHARE_TOTAL_ASSETS_BEFORE",
    "total_shares_before": "MMAUDIT_SHARE_TOTAL_SHARES_BEFORE",
    "legitimate_yield": "MMAUDIT_SHARE_LEGITIMATE_YIELD",
    "expected_rate_after_yield": "MMAUDIT_SHARE_EXPECTED_RATE_AFTER_YIELD",
    "observed_rate_after": "MMAUDIT_SHARE_OBSERVED_RATE_AFTER",
    "shares_redeemed": "MMAUDIT_SHARE_SHARES_REDEEMED",
    "assets_redeemed": "MMAUDIT_SHARE_ASSETS_REDEEMED",
    "excess_assets": "MMAUDIT_SHARE_EXCESS_ASSETS",
}


def _financial_settlement_from_execution(
    execution: _InvariantExecution,
    specification: FinancialSettlementProbeSpec,
) -> FinancialSettlementEvidence | None:
    """Parse only fixed settlement labels and reject ambiguous replay output."""

    output = "\n".join(
        (
            execution.stdout_path.read_text(encoding="utf-8", errors="replace"),
            execution.stderr_path.read_text(encoding="utf-8", errors="replace"),
        )
    )
    values: dict[str, int] = {}
    for field, label in _SETTLEMENT_OUTPUT_LABELS.items():
        matches = {int(match) for match in re.findall(rf"(?m){label}\s*:\s*([0-9]+)\b", output)}
        if len(matches) != 1:
            return None
        values[field] = matches.pop()
    try:
        return FinancialSettlementEvidence(
            actor=specification.actor,
            asset_kind=specification.asset_kind,
            asset_target=specification.asset_target,
            **values,
        )
    except ValueError:
        return None


def _lending_boundary_from_execution(
    execution: _InvariantExecution,
) -> LendingBoundaryEvidence | None:
    """Parse fixed debt/collateral labels and validate transition arithmetic."""

    output = "\n".join(
        (
            execution.stdout_path.read_text(encoding="utf-8", errors="replace"),
            execution.stderr_path.read_text(encoding="utf-8", errors="replace"),
        )
    )
    values: dict[str, int] = {}
    for field, label in _LENDING_BOUNDARY_OUTPUT_LABELS.items():
        matches = {int(match) for match in re.findall(rf"(?m){label}\s*:\s*([0-9]+)\b", output)}
        if len(matches) != 1:
            return None
        values[field] = matches.pop()
    try:
        return LendingBoundaryEvidence(**values)
    except ValueError:
        return None


def _share_price_boundary_from_execution(
    execution: _InvariantExecution,
) -> SharePriceBoundaryEvidence | None:
    """Parse fixed share-rate labels and validate yield/redemption arithmetic."""

    output = "\n".join(
        (
            execution.stdout_path.read_text(encoding="utf-8", errors="replace"),
            execution.stderr_path.read_text(encoding="utf-8", errors="replace"),
        )
    )
    values: dict[str, int] = {}
    for field, label in _SHARE_PRICE_OUTPUT_LABELS.items():
        matches = {int(match) for match in re.findall(rf"(?m){label}\s*:\s*([0-9]+)\b", output)}
        if len(matches) != 1:
            return None
        values[field] = matches.pop()
    try:
        return SharePriceBoundaryEvidence(**values)
    except ValueError:
        return None


def normalize_foundry_invariant_output(
    return_code: int,
    output: str,
) -> tuple[InvariantExecutionStatus, list[str], str | None]:
    """Normalize bounded Foundry output without treating failures as safety."""

    if return_code == 0:
        return InvariantExecutionStatus.PASSED, [], None
    if any(
        marker in output
        for marker in (
            "Compiler run failed",
            "ParserError:",
            "TypeError:",
            "DeclarationError:",
        )
    ):
        return (
            InvariantExecutionStatus.COMPILE_FAILED,
            ["generated invariant harness did not compile"],
            None,
        )
    if re.search(
        r"(?is)(invariant_[A-Za-z0-9_]+.*(?:fail|counterexample)"
        r"|(?:fail|counterexample).*invariant_[A-Za-z0-9_]+)",
        output,
    ):
        return (
            InvariantExecutionStatus.COUNTEREXAMPLE,
            [],
            (
                "Foundry reported a failing invariant; bounded raw output is retained "
                "only in the private run artifact."
            ),
        )
    return (
        InvariantExecutionStatus.EXECUTION_FAILED,
        [f"forge invariant campaign exited with code {return_code}"],
        None,
    )


def _contextual_counterexample_summary(
    specification: FoundryInvariantHarnessSpec,
    summary: str | None,
    lending_boundary: LendingBoundaryEvidence | None = None,
    share_price_boundary: SharePriceBoundaryEvidence | None = None,
) -> str | None:
    """Attach deterministic source-linked context without retaining raw tool output."""

    if summary is None:
        return None
    if specification.economic_template is EconomicSimulationKind.CALLBACK_REENTRANCY:
        return (
            "Foundry reported a failing invariant for reachable callback "
            "receiver.onCreditReceived() and affected state availableCredit; "
            "bounded raw output is retained only in the private run artifact."
        )
    if specification.economic_template is EconomicSimulationKind.BOUNDED_STATE_GROWTH:
        return (
            "Foundry reported a failing invariant because entryCount exceeded the "
            "configured growthThreshold after one bounded append; bounded raw output "
            "is retained only in the private run artifact."
        )
    if specification.economic_template is EconomicSimulationKind.STATE_ORDERING:
        sequence = " then ".join(specification.required_action_sequence)
        return (
            "Foundry reported a failing bounded multi-transaction state invariant "
            f"for seed {specification.seed} and sequence {sequence}; bounded raw output "
            "is retained only in the private run artifact."
        )
    if specification.economic_template is EconomicSimulationKind.AMM_RESERVES:
        return (
            "Foundry reported a failing invariant after one bounded constant-product "
            "reserve movement because source-linked spot pricing produced excess "
            "extraction; bounded raw output is retained only in the private run artifact."
        )
    if (
        specification.economic_template is EconomicSimulationKind.LIQUIDATION
        and lending_boundary is not None
    ):
        return (
            "Foundry reported a violated healthy-position liquidation invariant with "
            f"debt {lending_boundary.debt_before} and collateral "
            f"{lending_boundary.collateral_before} before the transition; observed debt "
            f"{lending_boundary.debt_after}, collateral {lending_boundary.collateral_after}, "
            f"collateral seized {lending_boundary.collateral_seized}, and bad debt "
            f"{lending_boundary.bad_debt_after} afterward. Bounded raw output is retained "
            "only in the private run artifact."
        )
    if (
        specification.economic_template is EconomicSimulationKind.SHARE_PRICE
        and share_price_boundary is not None
    ):
        return (
            "Foundry reported a violated yield-adjusted share-price invariant with "
            f"legitimate yield {share_price_boundary.legitimate_yield}, expected rate "
            f"{share_price_boundary.expected_rate_after_yield}, observed rate "
            f"{share_price_boundary.observed_rate_after}, shares redeemed "
            f"{share_price_boundary.shares_redeemed}, assets redeemed "
            f"{share_price_boundary.assets_redeemed}, and excess assets "
            f"{share_price_boundary.excess_assets}. Bounded raw output is retained only "
            "in the private run artifact."
        )
    return summary


def _economic_metrics_from_specification(
    specification: FoundryInvariantHarnessSpec,
    financial_settlement: FinancialSettlementEvidence | None = None,
    lending_boundary: LendingBoundaryEvidence | None = None,
    share_price_boundary: SharePriceBoundaryEvidence | None = None,
) -> EconomicMetrics | None:
    """Derive bounded economic inputs from a typed harness, not from model prose."""

    if specification.economic_template not in {
        EconomicSimulationKind.ERC4626_DONATION,
        EconomicSimulationKind.FLASH_ORACLE,
        EconomicSimulationKind.AMM_RESERVES,
        EconomicSimulationKind.LIQUIDATION,
        EconomicSimulationKind.SHARE_PRICE,
        EconomicSimulationKind.CALLBACK_REENTRANCY,
        EconomicSimulationKind.BOUNDED_STATE_GROWTH,
        EconomicSimulationKind.STATE_ORDERING,
        EconomicSimulationKind.CROSS_CHAIN_REPLAY,
        EconomicSimulationKind.NON_STANDARD_TOKEN,
        EconomicSimulationKind.ORACLE_GUARDS,
        EconomicSimulationKind.ROUNDING,
        EconomicSimulationKind.SANDWICH,
        EconomicSimulationKind.SIGNATURE_REPLAY,
        EconomicSimulationKind.GOVERNANCE_RACE,
        EconomicSimulationKind.UPGRADE_INITIALIZER,
    }:
        return None
    if specification.economic_template is EconomicSimulationKind.FLASH_ORACLE:
        if financial_settlement is None:
            return EconomicMetrics(
                required_privileges=["unprivileged synthetic temporary-liquidity caller"],
                market_assumptions=[
                    "financial settlement output was not validated",
                    "no executed economic impact is claimed without reconciled replay evidence",
                ],
            )
        return EconomicMetrics(
            required_initial_capital=financial_settlement.starting_assets,
            borrowed_capital=financial_settlement.borrowed_assets,
            gross_extraction=financial_settlement.gross_assets_received,
            fees=financial_settlement.fees_paid,
            net_profit_or_loss=financial_settlement.net_impact,
            repeatable=None,
            required_privileges=["unprivileged synthetic temporary-liquidity caller"],
            market_assumptions=[
                "the principal, price preset, repayment, fee, and slippage are synthetic",
                "the result is one bounded local transition and does not establish repeatability",
                "no external liquidity source, market, deployed contract, or RPC was contacted",
            ],
            financial_settlement=financial_settlement,
        )
    if specification.economic_template is EconomicSimulationKind.AMM_RESERVES:
        if financial_settlement is None:
            return EconomicMetrics(
                required_privileges=["unprivileged synthetic reserve-movement caller"],
                market_assumptions=[
                    "financial settlement output was not validated",
                    "no executed reserve-dependent impact is claimed without reconciled replay",
                ],
            )
        return EconomicMetrics(
            required_initial_capital=financial_settlement.starting_assets,
            borrowed_capital=financial_settlement.borrowed_assets,
            gross_extraction=financial_settlement.gross_assets_received,
            fees=financial_settlement.fees_paid,
            net_profit_or_loss=financial_settlement.net_impact,
            repeatable=None,
            required_privileges=["unprivileged synthetic reserve-movement caller"],
            market_assumptions=[
                "the reserves, spot price, protected price, fee, and payout are synthetic",
                "the result is one bounded local constant-product movement",
                "no temporary loan, external pool, market, deployed contract, or RPC was used",
            ],
            financial_settlement=financial_settlement,
        )
    if specification.economic_template is EconomicSimulationKind.LIQUIDATION:
        if financial_settlement is None or lending_boundary is None:
            return EconomicMetrics(
                required_privileges=["unprivileged synthetic liquidation caller"],
                market_assumptions=[
                    "financial settlement or lending boundary output was not validated",
                    "no executed liquidation impact is claimed without reconciled replay",
                ],
            )
        return EconomicMetrics(
            required_initial_capital=financial_settlement.starting_assets,
            borrowed_capital=financial_settlement.borrowed_assets,
            gross_extraction=financial_settlement.gross_assets_received,
            fees=financial_settlement.fees_paid,
            net_profit_or_loss=financial_settlement.net_impact,
            maximum_victim_loss=lending_boundary.collateral_seized,
            protocol_insolvency=lending_boundary.bad_debt_after,
            repeatable=None,
            required_privileges=["unprivileged synthetic liquidation caller"],
            market_assumptions=[
                "debt and collateral use one synthetic base-unit scale",
                "the result is one healthy-position liquidation boundary transition",
                "no price movement, external market, deployed contract, or RPC was used",
            ],
            financial_settlement=financial_settlement,
            lending_boundary=lending_boundary,
        )
    if specification.economic_template is EconomicSimulationKind.SHARE_PRICE:
        if financial_settlement is None or share_price_boundary is None:
            return EconomicMetrics(
                required_privileges=["unprivileged synthetic share holder"],
                market_assumptions=[
                    "financial settlement or share-price boundary output was not validated",
                    "no executed exchange-rate impact is claimed without reconciled replay",
                ],
            )
        return EconomicMetrics(
            required_initial_capital=financial_settlement.starting_assets,
            borrowed_capital=financial_settlement.borrowed_assets,
            gross_extraction=financial_settlement.gross_assets_received,
            fees=financial_settlement.fees_paid,
            net_profit_or_loss=financial_settlement.net_impact,
            maximum_victim_loss=share_price_boundary.excess_assets,
            repeatable=None,
            required_privileges=["unprivileged synthetic share holder"],
            market_assumptions=[
                "the actor begins with one fixed synthetic share position",
                "legitimate yield is an observed local asset increase",
                "the result is one bounded share-rate and redemption transition",
                "no loan, external market, deployed contract, or RPC was used",
            ],
            financial_settlement=financial_settlement,
            share_price_boundary=share_price_boundary,
        )
    if specification.economic_template is EconomicSimulationKind.ORACLE_GUARDS:
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=["unprivileged oracle consumer caller"],
            market_assumptions=[
                "feed values are deterministic synthetic presets, not live market observations",
                "the result validates configured freshness, scale, answer, and sequencer guards",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.CALLBACK_REENTRANCY:
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=[
                "unprivileged trigger actor",
                "one declared synthetic callback receiver",
            ],
            market_assumptions=[
                "receiver.onCreditReceived() is the source-linked reachable callback",
                "availableCredit is the affected accounting state",
                "the receiver, target, and callback sequence are synthetic and local-only",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.BOUNDED_STATE_GROWTH:
        threshold = len(specification.setup_calls)
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            resource_threshold=threshold,
            bounded_actions=threshold + len(specification.actions) * specification.depth,
            required_privileges=["unprivileged bounded append caller"],
            market_assumptions=[
                "entryCount and growthThreshold are source-exposed deterministic probes",
                "the campaign reaches threshold four with setup and performs one extra action",
                "no unbounded loop, recursive growth, or denial-of-service workload is executed",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.STATE_ORDERING:
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            bounded_actions=len(specification.required_action_sequence),
            required_privileges=["two unprivileged ordered synthetic local transactions"],
            market_assumptions=[
                "the required sequence is source-linked and limited to two actions",
                "the campaign seed and minimized action sequence are retained",
                "single-action removal trials and the full sequence use clean workspaces",
                "no block, time, RPC, deployed target, or external market is used",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.CROSS_CHAIN_REPLAY:
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=["declared synthetic local messenger"],
            market_assumptions=[
                "message identifiers, nonces, and payload effects are offline fixture values",
                "no relayer, remote chain, RPC, or external transport is contacted",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.GOVERNANCE_RACE:
        policy = specification.capability_policy
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=["declared governance proposer and voter rights"],
            market_assumptions=[
                (
                    "time movement is bounded to "
                    f"{policy.max_time_shift_seconds if policy is not None else 0} seconds"
                ),
                "the preset proposal lifecycle and voting entitlement are synthetic and local-only",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.UPGRADE_INITIALIZER:
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=["unprivileged proxy caller for negative transitions"],
            market_assumptions=[
                "the proxy and both implementation addresses are synthetic and local-only",
                "all transitions use declared proxy ABI calls without direct storage or code mutation",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.ROUNDING:
        minimum_amount = next(
            (
                argument.minimum
                for action in specification.actions
                for argument in action.arguments
                if argument.source is HarnessArgumentSource.FUZZ_UINT
                and argument.minimum is not None
            ),
            None,
        )
        return EconomicMetrics(
            required_initial_capital=minimum_amount,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=["unprivileged account holder"],
            market_assumptions=[
                "the tested account getter is asset-denominated",
                (
                    "a passing no-gain property permits bounded downward-rounding loss; "
                    "it does not establish economic optimality"
                ),
            ],
        )
    if specification.economic_template is EconomicSimulationKind.SIGNATURE_REPLAY:
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=["holder of one fixture-authorized signature"],
            market_assumptions=[
                "signature material and signer identity are synthetic and local-only",
                "the result measures duplicate state consumption, not key security",
            ],
        )
    if specification.economic_template is EconomicSimulationKind.SANDWICH:
        return EconomicMetrics(
            required_initial_capital=0,
            borrowed_capital=0,
            repeatable=None,
            required_privileges=["declared same-block transaction ordering"],
            market_assumptions=[
                "the staged action and reorder execute without time or block movement",
                "the shortfall getter measures only the source-linked staged value bound",
            ],
        )
    attacker_capital = sum(
        seed.amount for seed in specification.token_balance_seeds if seed.actor == "attacker"
    )
    borrowed_capital = 0
    maximum_victim_loss = (
        _first_uint_argument(specification.setup_calls, "VictimDeposit")
        or _first_stateful_uint_argument(specification, "VictimDeposit")
        if specification.economic_template is EconomicSimulationKind.ERC4626_DONATION
        else None
    )
    scenario = (
        "ERC4626 donation sequence"
        if specification.economic_template is EconomicSimulationKind.ERC4626_DONATION
        else "observed-versus-assumed token accounting sequence"
    )
    required_privileges = (
        ["unprivileged attacker", "victim performs a deposit after donation"]
        if specification.economic_template is EconomicSimulationKind.ERC4626_DONATION
        else ["unprivileged depositor", "configured non-standard asset behavior"]
    )
    return EconomicMetrics(
        required_initial_capital=attacker_capital or None,
        borrowed_capital=borrowed_capital,
        maximum_victim_loss=maximum_victim_loss,
        repeatable=None,
        required_privileges=required_privileges,
        market_assumptions=[
            f"metrics are bounded inputs from the generated {scenario}",
            "profitability, liquidity, fees, and repeatability require additional protocol-specific measurement",
        ],
    )


def _first_uint_argument(
    calls: list[ForkCallStep],
    step_id: str,
) -> int | None:
    call = next((item for item in calls if item.step_id == step_id), None)
    if call is None:
        return None
    argument = next(
        (item for item in call.arguments if item.kind is ForkArgumentKind.UINT256),
        None,
    )
    if argument is None:
        return None
    try:
        return int(argument.value, 10)
    except ValueError:
        return None


def _first_stateful_uint_argument(
    specification: FoundryInvariantHarnessSpec,
    action_id: str,
) -> int | None:
    action = next(
        (item for item in specification.actions if item.action_id == action_id),
        None,
    )
    if action is None:
        return None
    argument = next(
        (
            item
            for item in action.arguments
            if item.kind is ForkArgumentKind.UINT256
            and item.source is HarnessArgumentSource.CONSTANT
            and item.value is not None
        ),
        None,
    )
    if argument is None or argument.value is None:
        return None
    try:
        return int(argument.value, 10)
    except ValueError:
        return None
