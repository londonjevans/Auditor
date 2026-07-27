// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/LiquidationBoundary.sol";

interface Vm {
    function prank(address caller) external;
}

abstract contract LiquidationBoundaryInvariantBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);

    SyntheticLiquidationAsset internal asset;
    address internal target;
    bool internal attempted;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }

    function action_ExecuteHealthyLiquidationBoundary() public {
        if (attempted) return;
        attempted = true;
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("liquidationBoundaryPreset()"));
        require(success, "fixture action");
    }

    function invariant_HealthyPositionPreservesCollateral() public view {
        if (!attempted) return;
        require(_read("collateralAfter()") >= _read("collateralBefore()"), "healthy collateral seized");
    }

    function invariant_HealthyPositionCannotCreateBadDebt() public view {
        if (!attempted) return;
        require(_read("badDebtAfter()") <= 0, "healthy liquidation created bad debt");
    }

    function _read(string memory signature) internal view returns (uint256 value) {
        (bool success, bytes memory data) = target.staticcall(abi.encodeWithSignature(signature));
        require(success && data.length >= 32, "fixture probe");
        value = abi.decode(data, (uint256));
    }
}

contract UnsafeHealthyPositionLiquidationInvariant is LiquidationBoundaryInvariantBase {
    function setUp() public {
        asset = new SyntheticLiquidationAsset();
        target = address(new UnsafeHealthyPositionLiquidation(asset));
        asset.mint(ACTOR, 10);
    }
}

contract SafeHealthyPositionLiquidationInvariant is LiquidationBoundaryInvariantBase {
    function setUp() public {
        asset = new SyntheticLiquidationAsset();
        target = address(new SafeHealthyPositionLiquidation(asset));
        asset.mint(ACTOR, 10);
    }
}

contract LiquidationBoundaryControls {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);

    function testUnsafeHealthyPositionIsLiquidated() public {
        (SyntheticLiquidationAsset asset, address target) = _prepare(false);
        _execute(target);
        _assertBoundary(target, 0, 150, 100);
        _assertSettlement(target, 150, 160, 150);
        require(asset.balanceOf(ACTOR) == 160, "unsafe ending balance");
    }

    function testSafeHealthyPositionIsPreserved() public {
        (SyntheticLiquidationAsset asset, address target) = _prepare(true);
        _execute(target);
        _assertBoundary(target, 150, 0, 0);
        _assertSettlement(target, 0, 10, 0);
        require(asset.balanceOf(ACTOR) == 10, "safe ending balance");
    }

    function testSetupAloneHasNoLiquidationTransition() public {
        (SyntheticLiquidationAsset asset, address target) = _prepare(false);
        require(asset.balanceOf(ACTOR) == 10, "unexpected initial balance");
        require(_read(target, "debtBefore()") == 0, "setup debt");
        require(_read(target, "collateralSeized()") == 0, "setup seizure");
    }

    function _prepare(bool safe) internal returns (SyntheticLiquidationAsset asset, address target) {
        asset = new SyntheticLiquidationAsset();
        target = safe
            ? address(new SafeHealthyPositionLiquidation(asset))
            : address(new UnsafeHealthyPositionLiquidation(asset));
        asset.mint(ACTOR, 10);
    }

    function _execute(address target) internal {
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("liquidationBoundaryPreset()"));
        require(success, "fixture action");
    }

    function _assertBoundary(
        address target,
        uint256 collateralAfterValue,
        uint256 collateralSeizedValue,
        uint256 badDebtAfterValue
    ) internal view {
        require(_read(target, "debtBefore()") == 100, "debt before");
        require(_read(target, "collateralBefore()") == 150, "collateral before");
        require(_read(target, "debtAfter()") == 100, "debt after");
        require(_read(target, "collateralAfter()") == collateralAfterValue, "collateral after");
        require(_read(target, "collateralSeized()") == collateralSeizedValue, "collateral seized");
        require(_read(target, "badDebtAfter()") == badDebtAfterValue, "bad debt");
    }

    function _assertSettlement(address target, uint256 gross, uint256 ending, uint256 net) internal view {
        require(_read(target, "startingAssets()") == 10, "starting assets");
        require(_read(target, "borrowedAssets()") == 0, "borrowed assets");
        require(_read(target, "repaidAssets()") == 0, "repaid assets");
        require(_read(target, "grossAssetsReceived()") == gross, "gross assets");
        require(_read(target, "feesPaid()") == 0, "fees");
        require(_read(target, "slippageLoss()") == 0, "slippage");
        require(_read(target, "endingAssets()") == ending, "ending assets");
        require(_read(target, "netImpact()") == net, "net impact");
    }

    function _read(address target, string memory signature) internal view returns (uint256 value) {
        (bool success, bytes memory data) = target.staticcall(abi.encodeWithSignature(signature));
        require(success && data.length >= 32, "fixture probe");
        value = abi.decode(data, (uint256));
    }
}
