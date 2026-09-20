// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic local-only guard control. No funds, dependencies or deployment use.
// Invariant: a permitted transition increments exactly once; a refusal changes nothing.
contract ModifierControl {
    uint256 public counter;

    constructor() {
        require(block.chainid == 31337 && block.timestamp > 0, "synthetic local only");
    }

    function advance(bool allowed) external {
        require(allowed, "blocked transition must preserve state");
        counter += 1;
    }
}
