// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeOrderedSettlement {
    uint256 internal constant MINIMUM_OUTPUT = 9;
    uint256 internal constant REORDERED_OUTPUT = 1;

    address internal pendingActor;
    bool internal pending;
    mapping(address => uint256) public minimumOutput;
    mapping(address => uint256) public received;

    function stagePreset() external {
        require(!pending, "already staged");
        pendingActor = msg.sender;
        pending = true;
        minimumOutput[msg.sender] = MINIMUM_OUTPUT;
    }

    function reorderPreset() external {
        require(pending, "nothing staged");
        received[pendingActor] = REORDERED_OUTPUT;
        pending = false;
    }

    function shortfall(address actor) external view returns (uint256) {
        uint256 minimum = minimumOutput[actor];
        uint256 observed = received[actor];
        if (observed == 0 || observed >= minimum) {
            return 0;
        }
        return minimum - observed;
    }
}

contract SafeOrderedSettlement {
    uint256 internal constant MINIMUM_OUTPUT = 9;
    uint256 internal constant REORDERED_OUTPUT = 1;

    address internal pendingActor;
    bool internal pending;
    mapping(address => uint256) public minimumOutput;
    mapping(address => uint256) public received;

    function stagePreset() external {
        require(!pending, "already staged");
        pendingActor = msg.sender;
        pending = true;
        minimumOutput[msg.sender] = MINIMUM_OUTPUT;
    }

    function reorderPreset() external {
        require(pending, "nothing staged");
        require(REORDERED_OUTPUT >= minimumOutput[pendingActor], "staged minimum not preserved");
        received[pendingActor] = REORDERED_OUTPUT;
        pending = false;
    }

    function shortfall(address actor) external view returns (uint256) {
        uint256 minimum = minimumOutput[actor];
        uint256 observed = received[actor];
        if (observed == 0 || observed >= minimum) {
            return 0;
        }
        return minimum - observed;
    }
}
