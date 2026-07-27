// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/CallbackAccounting.sol";

abstract contract CallbackInvariantFixture {
    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeCallbackInvariant is CallbackInvariantFixture {
    UnsafeCallbackAccounting internal target;

    function setUp() public {
        SyntheticCallbackReceiver receiver = new SyntheticCallbackReceiver();
        target = new UnsafeCallbackAccounting(address(receiver));
        receiver.configureTarget(address(target));
    }

    function action_TriggerReachableCallback() public {
        (bool ok,) = address(target).call(abi.encodeWithSignature("withdrawCallbackPreset()"));
        ok;
    }

    function invariant_ReachableCallbackPreservesAvailableCredit() public view {
        require(target.invalidCallbackTransitions() == 0, "reachable callback reused availableCredit");
    }
}

contract SafeCallbackInvariant is CallbackInvariantFixture {
    SafeCallbackAccounting internal target;

    function setUp() public {
        SyntheticCallbackReceiver receiver = new SyntheticCallbackReceiver();
        target = new SafeCallbackAccounting(address(receiver));
        receiver.configureTarget(address(target));
    }

    function action_TriggerReachableCallback() public {
        (bool ok,) = address(target).call(abi.encodeWithSignature("withdrawCallbackPreset()"));
        ok;
    }

    function invariant_ReachableCallbackPreservesAvailableCredit() public view {
        require(target.invalidCallbackTransitions() == 0, "reachable callback reused availableCredit");
    }
}

contract CallbackSequenceControls {
    function testUnsafeOneActionIsMinimalCounterexample() public {
        SyntheticCallbackReceiver receiver = new SyntheticCallbackReceiver();
        UnsafeCallbackAccounting target = new UnsafeCallbackAccounting(address(receiver));
        receiver.configureTarget(address(target));

        require(target.invalidCallbackTransitions() == 0, "invalid initial transition");
        target.withdrawCallbackPreset();
        require(target.availableCredit() == 0, "credit was not consumed");
        require(target.settledCredit() == 2, "callback did not reuse the credit");
        require(target.invalidCallbackTransitions() == 1, "violation was not recorded");
        require(receiver.callbackCount() == 2, "callback reachability was not observed");
    }

    function testSafeEffectsFirstPreserveAccounting() public {
        SyntheticCallbackReceiver receiver = new SyntheticCallbackReceiver();
        SafeCallbackAccounting target = new SafeCallbackAccounting(address(receiver));
        receiver.configureTarget(address(target));

        target.withdrawCallbackPreset();
        require(target.availableCredit() == 0, "credit was not consumed");
        require(target.settledCredit() == 1, "safe settlement diverged");
        require(target.invalidCallbackTransitions() == 0, "safe transition was rejected");
        require(receiver.callbackCount() == 1, "configured callback was not reached");
    }
}
