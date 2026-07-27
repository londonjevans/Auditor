// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract BadLiquidation {
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateral;

    // BENCHMARK: the comparison is reversed and permits healthy-account liquidation.
    function liquidate(address user) external {
        require(collateral[user] >= debt[user]);
        collateral[msg.sender] += collateral[user];
        collateral[user] = 0;
    }
}

