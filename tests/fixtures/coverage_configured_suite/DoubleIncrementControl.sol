// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Intentionally defective synthetic local-only counterpart of InlineControl.sol.
// Violates the named exactly-one-increment invariant. No funds or deployment use.
contract ModifierControl {
    uint256 public counter;

    constructor() {
        require(block.chainid == 31337 && block.timestamp > 0, "synthetic local only");
    }

    function advance(bool allowed) external {
        require(allowed, "blocked transition must preserve state");
        counter += 2;
    }
}
