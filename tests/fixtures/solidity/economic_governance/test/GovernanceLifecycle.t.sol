// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/GovernanceLifecycle.sol";

interface Vm {
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
}

abstract contract GovernanceInvariantFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant GOVERNOR = 0x1000000000000000000000000000000000000002;
    address internal constant OUTSIDER = 0x1000000000000000000000000000000000000003;
    uint256 internal constant EARLY_SHIFT = 1 hours;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeGovernanceInvariant is GovernanceInvariantFixture {
    UnsafeGovernanceLifecycle internal target;

    function setUp() public {
        target = new UnsafeGovernanceLifecycle(GOVERNOR);
        vm.prank(GOVERNOR);
        target.proposePreset();
        vm.prank(GOVERNOR);
        target.votePreset();
        vm.prank(GOVERNOR);
        target.queuePreset();
    }

    function action_ExecuteBeforeConfiguredDelay() public {
        vm.warp(block.timestamp + EARLY_SHIFT);
        vm.prank(GOVERNOR);
        target.executePreset();
    }

    function invariant_NoExecutionBeforeConfiguredDelay() public view {
        require(target.earlyExecutions() == 0, "configured delay bypassed");
    }
}

contract SafeGovernanceInvariant is GovernanceInvariantFixture {
    SafeGovernanceLifecycle internal target;

    function setUp() public {
        target = new SafeGovernanceLifecycle(GOVERNOR);
        vm.prank(GOVERNOR);
        target.proposePreset();
        vm.prank(GOVERNOR);
        target.votePreset();
        vm.prank(GOVERNOR);
        target.queuePreset();
    }

    function action_ExecuteBeforeConfiguredDelay() public {
        vm.warp(block.timestamp + EARLY_SHIFT);
        vm.prank(GOVERNOR);
        (bool ok,) = address(target).call(abi.encodeWithSignature("executePreset()"));
        ok;
    }

    function invariant_NoExecutionBeforeConfiguredDelay() public view {
        require(target.earlyExecutions() == 0, "configured delay bypassed");
    }
}

contract GovernanceLifecycleControls is GovernanceInvariantFixture {
    function _advanceTo(uint256 timestamp) internal {
        vm.warp(timestamp);
    }

    function _governanceCall(address target, string memory signature) internal returns (bool) {
        vm.prank(GOVERNOR);
        (bool ok,) = target.call(abi.encodeWithSignature(signature));
        return ok;
    }

    function _queue(SafeGovernanceLifecycle target) internal {
        require(_governanceCall(address(target), "proposePreset()"), "proposal failed");
        require(_governanceCall(address(target), "votePreset()"), "vote failed");
        require(_governanceCall(address(target), "queuePreset()"), "queue failed");
    }

    function testOnlyDeclaredGovernanceRightsReachLifecycle() public {
        SafeGovernanceLifecycle target = new SafeGovernanceLifecycle(GOVERNOR);
        vm.prank(OUTSIDER);
        (bool ok,) = address(target).call(abi.encodeWithSignature("proposePreset()"));
        require(!ok, "undeclared governance caller accepted");
        require(_governanceCall(address(target), "proposePreset()"), "governor rejected");
    }

    function testInvalidOrderingAndEarlyExecutionAreRejected() public {
        SafeGovernanceLifecycle target = new SafeGovernanceLifecycle(GOVERNOR);
        require(!_governanceCall(address(target), "queuePreset()"), "queue preceded approval");
        _queue(target);
        _advanceTo(block.timestamp + EARLY_SHIFT);
        require(!_governanceCall(address(target), "executePreset()"), "execution preceded configured delay");
    }

    function testExactDelayAllowsSafeExecution() public {
        SafeGovernanceLifecycle target = new SafeGovernanceLifecycle(GOVERNOR);
        _queue(target);
        _advanceTo(target.readyAt());
        require(_governanceCall(address(target), "executePreset()"), "ready action rejected");
        require(target.executions() == 1, "ready action not executed");
    }

    function testCancellationRemainsTerminal() public {
        SafeGovernanceLifecycle target = new SafeGovernanceLifecycle(GOVERNOR);
        _queue(target);
        require(_governanceCall(address(target), "cancelPreset()"), "cancel failed");
        _advanceTo(target.readyAt());
        require(!_governanceCall(address(target), "executePreset()"), "cancelled action executed");
    }

    function testUnsafeImplementationAcceptsValidDelayedExecution() public {
        UnsafeGovernanceLifecycle target = new UnsafeGovernanceLifecycle(GOVERNOR);
        require(_governanceCall(address(target), "proposePreset()"), "proposal failed");
        require(_governanceCall(address(target), "votePreset()"), "vote failed");
        require(_governanceCall(address(target), "queuePreset()"), "queue failed");
        _advanceTo(target.readyAt());
        require(_governanceCall(address(target), "executePreset()"), "ready action rejected");
        require(target.executions() == 1, "valid action not executed");
        require(target.earlyExecutions() == 0, "valid action marked early");
    }
}
