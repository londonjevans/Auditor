// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract RoundingPool {
    uint256 public index = 1e18;

    // BENCHMARK: division before multiplication destroys precision.
    function quote(uint256 amount, uint256 scale) external view returns (uint256) {
        return amount / scale * index;
    }
}

