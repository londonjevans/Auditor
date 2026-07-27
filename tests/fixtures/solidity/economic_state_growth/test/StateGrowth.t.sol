// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/StateGrowth.sol";

abstract contract StateGrowthInvariantFixture {
    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeStateGrowthInvariant is StateGrowthInvariantFixture {
    UnsafeStateGrowth internal target;

    function setUp() public {
        target = new UnsafeStateGrowth();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
    }

    function action_AppendBeyondConfiguredThreshold() public {
        target.appendPreset();
    }

    function invariant_EntryCountWithinGrowthThreshold() public view {
        require(target.entryCount() <= target.growthThreshold(), "bounded append exceeded configured threshold");
    }
}

contract SafeStateGrowthInvariant is StateGrowthInvariantFixture {
    SafeStateGrowth internal target;

    function setUp() public {
        target = new SafeStateGrowth();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
    }

    function action_AppendBeyondConfiguredThreshold() public {
        (bool ok,) = address(target).call(abi.encodeWithSignature("appendPreset()"));
        ok;
    }

    function invariant_EntryCountWithinGrowthThreshold() public view {
        require(target.entryCount() <= target.growthThreshold(), "bounded append exceeded configured threshold");
    }
}

contract StateGrowthControls {
    function testUnsafeFourActionsReachButDoNotExceedThreshold() public {
        UnsafeStateGrowth target = new UnsafeStateGrowth();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        require(target.entryCount() == target.growthThreshold(), "threshold setup diverged");
    }

    function testUnsafeFifthActionIsMinimalThresholdViolation() public {
        UnsafeStateGrowth target = new UnsafeStateGrowth();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        require(target.entryCount() == target.growthThreshold(), "invalid precondition");
        target.appendPreset();
        require(target.entryCount() == 5, "fifth bounded action was not observed");
    }

    function testSafeFifthActionIsRejectedAndStateIsPreserved() public {
        SafeStateGrowth target = new SafeStateGrowth();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        target.appendPreset();
        (bool ok,) = address(target).call(abi.encodeWithSignature("appendPreset()"));
        require(!ok, "safe threshold accepted another entry");
        require(target.entryCount() == target.growthThreshold(), "safe state changed");
    }
}
