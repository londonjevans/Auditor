// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract FullProtocol {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    uint256 public constant ORACLE_HEARTBEAT_SECONDS = 1 hours;
    uint256 public constant MINIMUM_DELAY_SECONDS = 2 days;

    address public admin;
    address public timelock;
    address public oracle;
    address public authorizedRelayer;
    mapping(bytes32 => bool) public consumedMessages;

    event MessageConsumed(bytes32 indexed messageId);
    event OracleUpdated(address indexed previousOracle, address indexed nextOracle);

    constructor(
        address configuredAdmin,
        address configuredTimelock,
        address configuredOracle,
        address configuredRelayer
    ) {
        require(configuredAdmin != address(0), "admin");
        require(configuredTimelock != address(0), "timelock");
        require(configuredOracle != address(0), "oracle");
        require(configuredRelayer != address(0), "relayer");
        admin = configuredAdmin;
        timelock = configuredTimelock;
        oracle = configuredOracle;
        authorizedRelayer = configuredRelayer;
    }

    function consumeMessage(bytes32 messageId) external {
        require(msg.sender == authorizedRelayer, "not relayer");
        require(!consumedMessages[messageId], "message consumed");
        consumedMessages[messageId] = true;
        emit MessageConsumed(messageId);
    }

    function updateOracle(address nextOracle) external {
        require(msg.sender == timelock, "not timelock");
        require(nextOracle != address(0), "oracle");
        address previousOracle = oracle;
        oracle = nextOracle;
        emit OracleUpdated(previousOracle, nextOracle);
    }
}
