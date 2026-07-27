// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/ReservePricing.sol";

interface Vm {
    function prank(address caller) external;
}

abstract contract ReservePricingInvariantBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);

    SyntheticSettlementAsset internal asset;
    address internal target;
    bool internal attempted;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }

    function action_ExecuteBoundedReserveMovement() public {
        if (attempted) return;
        attempted = true;
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("reserveMovementPreset()"));
        require(success, "fixture action");
    }

    function invariant_ReserveProductPreserved() public view {
        if (!attempted) return;
        require(_read("reserveProductAfter()") == _read("reserveProductBefore()"), "reserve product changed");
    }

    function invariant_SpotMovementCannotCreateExcessExtraction() public view {
        if (!attempted) return;
        require(_read("excessExtraction()") <= 0, "excess extraction observed");
    }

    function _read(string memory signature) internal view returns (uint256 value) {
        (bool success, bytes memory data) = target.staticcall(abi.encodeWithSignature(signature));
        require(success && data.length >= 32, "fixture probe");
        value = abi.decode(data, (uint256));
    }
}

contract UnsafeSpotReservePricingInvariant is ReservePricingInvariantBase {
    function setUp() public {
        asset = new SyntheticSettlementAsset();
        target = address(new UnsafeSpotReservePricing(asset));
        asset.mint(ACTOR, 100);
    }
}

contract SafeProtectedReservePricingInvariant is ReservePricingInvariantBase {
    function setUp() public {
        asset = new SyntheticSettlementAsset();
        target = address(new SafeProtectedReservePricing(asset));
        asset.mint(ACTOR, 100);
    }
}

contract ReservePricingControls {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);

    function testUnsafeSpotDependenceCreatesExcess() public {
        (SyntheticSettlementAsset asset, address target) = _prepare(false);
        _execute(target);
        _assertReserveMovement(target);
        _assertSettlement(target, 40, 130, 30);
        require(asset.balanceOf(ACTOR) == 130, "unsafe ending balance");
    }

    function testSafeProtectedPriceSettlesWithoutExcess() public {
        (SyntheticSettlementAsset asset, address target) = _prepare(true);
        _execute(target);
        _assertReserveMovement(target);
        _assertSettlement(target, 10, 100, 0);
        require(asset.balanceOf(ACTOR) == 100, "safe ending balance");
    }

    function testSetupAloneHasNoReserveMovement() public {
        (SyntheticSettlementAsset asset, address target) = _prepare(false);
        require(asset.balanceOf(ACTOR) == 100, "unexpected initial balance");
        require(_read(target, "reserveProductBefore()") == 0, "setup product");
        require(_read(target, "excessExtraction()") == 0, "setup extraction");
    }

    function _prepare(bool safe) internal returns (SyntheticSettlementAsset asset, address target) {
        asset = new SyntheticSettlementAsset();
        target = safe ? address(new SafeProtectedReservePricing(asset)) : address(new UnsafeSpotReservePricing(asset));
        asset.mint(ACTOR, 100);
    }

    function _execute(address target) internal {
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("reserveMovementPreset()"));
        require(success, "fixture action");
    }

    function _assertReserveMovement(address target) internal view {
        require(_read(target, "reserveProductBefore()") == 1_000_000, "before product");
        require(_read(target, "reserveProductAfter()") == 1_000_000, "after product");
        require(_read(target, "spotPriceBefore()") == 10, "before spot");
        require(_read(target, "spotPriceAfter()") == 40, "after spot");
        require(_read(target, "protectedPrice()") == 10, "protected price");
    }

    function _assertSettlement(address target, uint256 gross, uint256 ending, uint256 net) internal view {
        require(_read(target, "startingAssets()") == 100, "starting assets");
        require(_read(target, "borrowedAssets()") == 0, "borrowed assets");
        require(_read(target, "repaidAssets()") == 0, "repaid assets");
        require(_read(target, "grossAssetsReceived()") == gross, "gross assets");
        require(_read(target, "feesPaid()") == 10, "fees");
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
