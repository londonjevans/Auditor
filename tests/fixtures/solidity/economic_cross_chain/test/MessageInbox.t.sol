// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/MessageInbox.sol";

interface Vm {
    function prank(address sender) external;
}

abstract contract MessageInvariantFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant MESSENGER = 0x1000000000000000000000000000000000000002;
    address internal constant OUTSIDER = 0x1000000000000000000000000000000000000003;
    bytes32 internal constant MESSAGE_ONE = bytes32(uint256(1));
    bytes32 internal constant MESSAGE_TWO = bytes32(uint256(2));
    bytes32 internal constant MESSAGE_THREE = bytes32(uint256(3));

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeMessageInvariant is MessageInvariantFixture {
    UnsafeMessageInbox internal target;

    function setUp() public {
        target = new UnsafeMessageInbox(MESSENGER);
        vm.prank(MESSENGER);
        target.processMessagePreset(1, MESSAGE_ONE);
    }

    function action_ReplayConsumedMessage() public {
        vm.prank(MESSENGER);
        target.processMessagePreset(1, MESSAGE_ONE);
    }

    function action_ProcessOutOfOrderMessage() public {
        vm.prank(MESSENGER);
        target.processMessagePreset(3, MESSAGE_THREE);
    }

    function invariant_OnlyNextUnconsumedMessageChangesState() public view {
        require(target.invalidMessageTransitions() == 0, "invalid offline message transition accepted");
    }
}

contract SafeMessageInvariant is MessageInvariantFixture {
    SafeMessageInbox internal target;

    function setUp() public {
        target = new SafeMessageInbox(MESSENGER);
        vm.prank(MESSENGER);
        target.processMessagePreset(1, MESSAGE_ONE);
    }

    function action_ReplayConsumedMessage() public {
        vm.prank(MESSENGER);
        (bool ok,) =
            address(target).call(abi.encodeWithSignature("processMessagePreset(uint256,bytes32)", 1, MESSAGE_ONE));
        ok;
    }

    function action_ProcessOutOfOrderMessage() public {
        vm.prank(MESSENGER);
        (bool ok,) =
            address(target).call(abi.encodeWithSignature("processMessagePreset(uint256,bytes32)", 3, MESSAGE_THREE));
        ok;
    }

    function invariant_OnlyNextUnconsumedMessageChangesState() public view {
        require(target.invalidMessageTransitions() == 0, "invalid offline message transition accepted");
    }
}

contract MessageSequenceControls is MessageInvariantFixture {
    function _processAs(address actor, address target, uint256 nonce, bytes32 messageId) internal returns (bool) {
        vm.prank(actor);
        (bool ok,) = target.call(abi.encodeWithSignature("processMessagePreset(uint256,bytes32)", nonce, messageId));
        return ok;
    }

    function testOnlyConfiguredLocalMessengerCanProcess() public {
        SafeMessageInbox target = new SafeMessageInbox(MESSENGER);
        require(!_processAs(OUTSIDER, address(target), 1, MESSAGE_ONE), "undeclared messenger accepted");
        require(_processAs(MESSENGER, address(target), 1, MESSAGE_ONE), "configured messenger rejected");
    }

    function testSafeInboxRejectsReplayAndPreservesState() public {
        SafeMessageInbox target = new SafeMessageInbox(MESSENGER);
        require(_processAs(MESSENGER, address(target), 1, MESSAGE_ONE), "first failed");
        require(!_processAs(MESSENGER, address(target), 1, MESSAGE_ONE), "duplicate accepted");
        require(target.acceptedMessages() == 1, "duplicate changed accounted state");
        require(target.nextNonce() == 2, "duplicate changed sequence state");
    }

    function testSafeInboxRejectsOutOfOrderThenAcceptsNext() public {
        SafeMessageInbox target = new SafeMessageInbox(MESSENGER);
        require(_processAs(MESSENGER, address(target), 1, MESSAGE_ONE), "first failed");
        require(!_processAs(MESSENGER, address(target), 3, MESSAGE_THREE), "out-of-order message accepted");
        require(_processAs(MESSENGER, address(target), 2, MESSAGE_TWO), "next failed");
        require(target.acceptedMessages() == 2, "valid sequence not accounted");
        require(target.nextNonce() == 3, "valid sequence did not advance");
    }

    function testUnsafeInboxAcceptsValidOrderedMessageWithoutFailure() public {
        UnsafeMessageInbox target = new UnsafeMessageInbox(MESSENGER);
        require(_processAs(MESSENGER, address(target), 1, MESSAGE_ONE), "first failed");
        require(_processAs(MESSENGER, address(target), 2, MESSAGE_TWO), "next failed");
        require(target.invalidMessageTransitions() == 0, "valid message marked invalid");
        require(target.acceptedMessages() == 2, "valid message not accounted");
    }
}
