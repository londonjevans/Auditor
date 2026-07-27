// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {FullProtocol} from "../src/FullProtocol.sol";

contract SyntheticCaller {
    function consume(FullProtocol protocol, bytes32 messageId) external {
        protocol.consumeMessage(messageId);
    }

    function updateOracle(FullProtocol protocol, address nextOracle) external {
        protocol.updateOracle(nextOracle);
    }
}

contract FullProtocolControls {
    function testDeclaredConstantsAreBounded() external {
        FullProtocol protocol = new FullProtocol(address(1), address(2), address(3), address(4));
        require(protocol.ORACLE_HEARTBEAT_SECONDS() == 1 hours);
        require(protocol.MINIMUM_DELAY_SECONDS() == 2 days);
    }

    function testRelayerAuthorizationAndDuplicateConsumptionControl() external {
        FullProtocol protocol = new FullProtocol(address(1), address(2), address(3), address(this));
        bytes32 messageId = keccak256("synthetic-message");
        protocol.consumeMessage(messageId);
        require(protocol.consumedMessages(messageId));

        (bool duplicateAccepted,) = address(protocol).call(abi.encodeCall(FullProtocol.consumeMessage, (messageId)));
        require(!duplicateAccepted);

        SyntheticCaller caller = new SyntheticCaller();
        (bool unauthorizedAccepted,) =
            address(caller).call(abi.encodeCall(SyntheticCaller.consume, (protocol, keccak256("other-message"))));
        require(!unauthorizedAccepted);
    }

    function testTimelockOnlyOracleUpdateControl() external {
        FullProtocol protocol = new FullProtocol(address(1), address(this), address(3), address(4));
        protocol.updateOracle(address(5));
        require(protocol.oracle() == address(5));

        SyntheticCaller caller = new SyntheticCaller();
        (bool unauthorizedAccepted,) =
            address(caller).call(abi.encodeCall(SyntheticCaller.updateOracle, (protocol, address(6))));
        require(!unauthorizedAccepted);
        require(protocol.oracle() == address(5));
    }
}
