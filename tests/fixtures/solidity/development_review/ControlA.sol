// SPDX-License-Identifier: UNLICENSED
// Synthetic local regression only. Abstract and intentionally non-deployable.
pragma solidity ^0.8.20;

abstract contract ControlA {
    // Invariant: only the configured administrator may change the limit.
    address public immutable administrator;
    uint256 public limit;

    constructor(address administrator_) {
        administrator = administrator_;
    }

    function setLimit(uint256 nextLimit) external {
        limit = nextLimit;
    }
}
