// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IRewardReceiver {
    function onReward() external;
}

contract RewardReplay {
    mapping(address => uint256) public entitlement;

    // BENCHMARK: callback occurs before entitlement consumption.
    function claim() external {
        uint256 amount = entitlement[msg.sender];
        IRewardReceiver(msg.sender).onReward();
        entitlement[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

