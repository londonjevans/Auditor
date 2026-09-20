// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic local-only coverage control. No funds or external dependencies.
contract ModifierControl {
    uint256 public counter;

    constructor() {
        require(block.chainid == 31337 && block.timestamp > 0, "synthetic local only");
    }

    modifier permitted(bool allowed) {
        require(allowed, "blocked transition must preserve state");
        _;
    }

    function advance(bool allowed) external permitted(allowed) {
        counter += 1;
    }
}
