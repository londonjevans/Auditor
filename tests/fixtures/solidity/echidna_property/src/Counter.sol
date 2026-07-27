// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract Counter {
    uint256 private value;

    function increment(uint256 amount) external {
        value += amount;
    }

    function reset() external {
        value = 0;
    }

    function current() external view returns (uint256) {
        return value;
    }
}
