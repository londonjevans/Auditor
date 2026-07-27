// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/TemporaryLiquidityOracle.sol";

interface Vm {
    function prank(address caller) external;
}

abstract contract TemporaryLiquidityInvariantBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);

    SyntheticLiquidityAsset internal asset;
    address internal target;
    bool internal attempted;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }

    function action_ExecuteTemporaryLiquiditySequence() public {
        if (attempted) return;
        attempted = true;
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("temporaryLiquidityPreset()"));
        require(success, "fixture action");
    }

    function invariant_TemporaryLiquidityCannotCreateExcessExtraction() public view {
        if (!attempted) return;
        (bool success, bytes memory data) = target.staticcall(abi.encodeWithSignature("excessExtraction()"));
        require(success && abi.decode(data, (uint256)) <= 0, "excess extraction observed");
    }
}

contract UnsafeTemporaryLiquidityInvariant is TemporaryLiquidityInvariantBase {
    function setUp() public {
        asset = new SyntheticLiquidityAsset();
        target = address(new UnsafeTemporaryLiquidityOracle(asset));
        asset.mint(ACTOR, 100);
    }
}

contract SafeTemporaryLiquidityInvariant is TemporaryLiquidityInvariantBase {
    function setUp() public {
        asset = new SyntheticLiquidityAsset();
        target = address(new SafeTemporaryLiquidityOracle(asset));
        asset.mint(ACTOR, 100);
    }
}

contract TemporaryLiquiditySettlementControls {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);

    function testUnsafeTransitionViolatesNoExcessInvariant() public {
        (SyntheticLiquidityAsset asset, address target) = _prepare(false);
        _execute(target);
        _assertSettled(target, 35, 120, 20);
        require(asset.balanceOf(ACTOR) == 120, "unsafe ending balance");
        require(_read(target, "excessExtraction()") > 0, "unsafe condition not observed");
    }

    function testSafeTransitionSettlesWithoutExcess() public {
        (SyntheticLiquidityAsset asset, address target) = _prepare(true);
        _execute(target);
        _assertSettled(target, 15, 100, 0);
        require(asset.balanceOf(ACTOR) == 100, "safe ending balance");
        require(_read(target, "excessExtraction()") == 0, "safe implementation extracted value");
    }

    function testSetupAloneHasNoTemporaryLiquidityTransition() public {
        (SyntheticLiquidityAsset asset, address target) = _prepare(false);
        require(asset.balanceOf(ACTOR) == 100, "unexpected initial balance");
        require(_read(target, "borrowedAssets()") == 0, "setup borrowed assets");
        require(_read(target, "excessExtraction()") == 0, "setup extracted assets");
    }

    function _prepare(bool safe) internal returns (SyntheticLiquidityAsset asset, address target) {
        asset = new SyntheticLiquidityAsset();
        target =
            safe ? address(new SafeTemporaryLiquidityOracle(asset)) : address(new UnsafeTemporaryLiquidityOracle(asset));
        asset.mint(ACTOR, 100);
    }

    function _execute(address target) internal {
        vm.prank(ACTOR);
        (bool success,) = target.call(abi.encodeWithSignature("temporaryLiquidityPreset()"));
        require(success, "fixture action");
    }

    function _assertSettled(address target, uint256 gross, uint256 ending, uint256 net) internal view {
        require(_read(target, "startingAssets()") == 100, "starting assets");
        require(_read(target, "borrowedAssets()") == 1_000, "borrowed assets");
        require(_read(target, "repaidAssets()") == 1_000, "repaid assets");
        require(_read(target, "grossAssetsReceived()") == gross, "gross assets");
        require(_read(target, "feesPaid()") == 10, "fees");
        require(_read(target, "slippageLoss()") == 5, "slippage");
        require(_read(target, "endingAssets()") == ending, "ending assets");
        require(_read(target, "netImpact()") == net, "net impact");
    }

    function _read(address target, string memory signature) internal view returns (uint256 value) {
        (bool success, bytes memory data) = target.staticcall(abi.encodeWithSignature(signature));
        require(success && data.length >= 32, "fixture probe");
        value = abi.decode(data, (uint256));
    }
}
