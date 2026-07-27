// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IMessageTransport {
    function sendMessage(uint256 destinationChain, bytes calldata payload) external;
}

contract UnsafeBridgeEndpoint {
    event MessageDispatched(bytes32 indexed messageId, uint256 destinationChain);
    event MessageProcessed(bytes32 indexed messageId);

    IMessageTransport public messenger;
    mapping(address => uint256) public credit;

    function dispatch(uint256 destinationChain, bytes calldata payload) external {
        bytes32 messageId = keccak256(payload);
        messenger.sendMessage(destinationChain, payload);
        emit MessageDispatched(messageId, destinationChain);
    }

    function receiveMessage(
        bytes32 messageId,
        address account,
        uint256 amount
    ) external {
        credit[account] += amount;
        emit MessageProcessed(messageId);
    }
}

contract SafeBridgeEndpoint {
    event MessageDispatched(bytes32 indexed messageId, uint256 destinationChain);
    event MessageProcessed(bytes32 indexed messageId);

    uint256 public constant TRUSTED_CHAIN = 7;
    uint256 public constant MIN_CONFIRMATIONS = 12;
    address public trustedMessenger;
    address public trustedRemote;
    mapping(bytes32 => bool) public processed;
    mapping(address => uint256) public credit;

    function dispatch(uint256 destinationChain, bytes calldata payload) external {
        bytes32 messageId = keccak256(payload);
        IMessageTransport(trustedMessenger).sendMessage(destinationChain, payload);
        emit MessageDispatched(messageId, destinationChain);
    }

    function receiveMessage(
        uint256 sourceChain,
        address sourceSender,
        bytes32 messageId,
        address account,
        uint256 amount,
        uint256 confirmations
    ) external {
        require(msg.sender == trustedMessenger, "messenger");
        require(sourceChain == TRUSTED_CHAIN, "chain");
        require(sourceSender == trustedRemote, "remote");
        require(confirmations >= MIN_CONFIRMATIONS, "finality");
        require(!processed[messageId], "processed");
        processed[messageId] = true;
        credit[account] += amount;
        emit MessageProcessed(messageId);
    }
}

contract RelayedOracleRequest {
    event PriceRequested(bytes32 indexed requestId);
    event PriceFulfilled(bytes32 indexed requestId, uint256 price);

    address public relayer;
    mapping(bytes32 => bool) public pending;
    uint256 public latestPrice;

    modifier onlyRelayer() {
        require(msg.sender == relayer, "relayer");
        _;
    }

    function requestPrice(bytes32 requestId) external {
        pending[requestId] = true;
        emit PriceRequested(requestId);
    }

    function fulfillPrice(
        bytes32 requestId,
        uint256 price
    ) external onlyRelayer {
        require(pending[requestId], "request");
        pending[requestId] = false;
        latestPrice = price;
        emit PriceFulfilled(requestId, price);
    }
}
