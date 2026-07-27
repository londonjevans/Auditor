// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/SharePriceBoundary.sol";

interface Vm {
    function prank(address caller) external;
}

abstract contract SharePriceBoundaryInvariantBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = 0x1000000000000000000000000000000000000002;

    SyntheticRateAsset internal asset;
    address internal target;
    bool internal attempted;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }

    function action_ExecuteYieldAdjustedRateBoundary() public {
        if (attempted) return;
        attempted = true;
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("exchangeRateBoundaryPreset()"));
        require(success, "fixture action");
    }

    function invariant_ReachableRateCannotExceedYieldRate() public view {
        if (!attempted) return;
        require(
            _read("observedRateAfter()") <= _read("expectedRateAfterYield()"), "reachable rate exceeds legitimate yield"
        );
    }

    function invariant_RedemptionCannotExceedYieldValue() public view {
        if (!attempted) return;
        require(_read("excessAssets()") <= 0, "redemption exceeds yield-adjusted value");
    }

    function _read(string memory signature) internal view returns (uint256 value) {
        (bool success, bytes memory data) = target.staticcall(abi.encodeWithSignature(signature));
        require(success && data.length >= 32, "fixture probe");
        value = abi.decode(data, (uint256));
    }
}

contract UnsafeReportedAssetRateInvariant is SharePriceBoundaryInvariantBase {
    function setUp() public {
        asset = new SyntheticRateAsset();
        target = address(new UnsafeReportedAssetRateVault(asset));
        asset.mint(ACTOR, 100);
    }
}

contract SafeObservedAssetRateInvariant is SharePriceBoundaryInvariantBase {
    function setUp() public {
        asset = new SyntheticRateAsset();
        target = address(new SafeObservedAssetRateVault(asset));
        asset.mint(ACTOR, 100);
    }
}

contract SharePriceBoundaryControls {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = 0x1000000000000000000000000000000000000002;

    function testUnsafeReportedAssetsCreateExcessRedemption() public {
        (SyntheticRateAsset asset, address target) = _prepare(false);
        _execute(target);
        _assertBoundary(target, 1_500, 150, 40);
        _assertSettlement(target, 150, 250, 150);
        require(asset.balanceOf(ACTOR) == 250, "unsafe ending balance");
    }

    function testSafeObservedAssetsRetainLegitimateYield() public {
        (SyntheticRateAsset asset, address target) = _prepare(true);
        _execute(target);
        _assertBoundary(target, 1_100, 110, 0);
        _assertSettlement(target, 110, 210, 110);
        require(asset.balanceOf(ACTOR) == 210, "safe ending balance");
    }

    function testSetupAloneHasNoRateTransition() public {
        (SyntheticRateAsset asset, address target) = _prepare(false);
        require(asset.balanceOf(ACTOR) == 100, "unexpected initial balance");
        require(_read(target, "totalAssetsBefore()") == 0, "setup assets");
        require(_read(target, "excessAssets()") == 0, "setup excess");
    }

    function _prepare(bool safe) internal returns (SyntheticRateAsset asset, address target) {
        asset = new SyntheticRateAsset();
        target =
            safe ? address(new SafeObservedAssetRateVault(asset)) : address(new UnsafeReportedAssetRateVault(asset));
        asset.mint(ACTOR, 100);
    }

    function _execute(address target) internal {
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("exchangeRateBoundaryPreset()"));
        require(success, "fixture action");
    }

    function _assertBoundary(address target, uint256 observedRate, uint256 redeemed, uint256 excess) internal view {
        require(_read(target, "rateScale()") == 1_000, "rate scale");
        require(_read(target, "totalAssetsBefore()") == 1_000, "assets before");
        require(_read(target, "totalSharesBefore()") == 1_000, "shares before");
        require(_read(target, "legitimateYield()") == 100, "yield");
        require(_read(target, "expectedRateAfterYield()") == 1_100, "expected rate");
        require(_read(target, "observedRateAfter()") == observedRate, "observed rate");
        require(_read(target, "sharesRedeemed()") == 100, "shares redeemed");
        require(_read(target, "assetsRedeemed()") == redeemed, "assets redeemed");
        require(_read(target, "excessAssets()") == excess, "excess assets");
    }

    function _assertSettlement(address target, uint256 gross, uint256 ending, uint256 net) internal view {
        require(_read(target, "startingAssets()") == 100, "starting assets");
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
