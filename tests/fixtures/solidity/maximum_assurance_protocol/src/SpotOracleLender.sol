// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface ISpotPool {
    function spotPrice() external view returns (uint256);
}

contract SpotOracleLender {
    ISpotPool public pool;
    mapping(address => uint256) public debt;

    constructor(ISpotPool configuredPool) {
        pool = configuredPool;
    }

    // BENCHMARK: a same-transaction spot price controls borrowing power.
    function borrow(uint256 collateral) external {
        debt[msg.sender] += collateral * pool.spotPrice();
    }
}

