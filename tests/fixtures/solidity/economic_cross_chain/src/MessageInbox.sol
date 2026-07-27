// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeMessageInbox {
    address public immutable messenger;
    mapping(bytes32 => bool) public processed;
    uint256 public nextNonce = 1;
    uint256 public acceptedMessages;
    uint256 public invalidMessageTransitions;

    constructor(address configuredMessenger) {
        messenger = configuredMessenger;
    }

    modifier onlyMessenger() {
        require(msg.sender == messenger, "local messenger required");
        _;
    }

    function processMessagePreset(uint256 messageNonce, bytes32 messageId) external onlyMessenger {
        if (processed[messageId] || messageNonce != nextNonce) {
            invalidMessageTransitions += 1;
        }
        processed[messageId] = true;
        nextNonce = messageNonce + 1;
        acceptedMessages += 1;
    }
}

contract SafeMessageInbox {
    address public immutable messenger;
    mapping(bytes32 => bool) public processed;
    uint256 public nextNonce = 1;
    uint256 public acceptedMessages;
    uint256 public invalidMessageTransitions;

    constructor(address configuredMessenger) {
        messenger = configuredMessenger;
    }

    modifier onlyMessenger() {
        require(msg.sender == messenger, "local messenger required");
        _;
    }

    function processMessagePreset(uint256 messageNonce, bytes32 messageId) external onlyMessenger {
        require(!processed[messageId], "message already processed");
        require(messageNonce == nextNonce, "message out of order");
        processed[messageId] = true;
        nextNonce = messageNonce + 1;
        acceptedMessages += 1;
    }
}
