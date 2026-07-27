// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// @notice Synthetic non-production fixture for local remediation replay only.
contract ReplayCounter {
    uint256 public state;

    function touch() external {
        state = 1;
    }
}
