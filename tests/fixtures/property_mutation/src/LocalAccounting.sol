// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic, local-only, intentionally non-production regression control.
contract LocalAccounting {
    address private immutable owner;
    uint256 public accounted;

    constructor() {
        require(block.chainid == 31337, "synthetic local-only fixture");
        owner = msg.sender;
    }

    function setAccounted(uint256 amount) external {
        require(msg.sender == owner, "owner only");
        accounted = amount;
    }

    function scaled(uint256 amount) external pure returns (uint256) {
        return amount * 1e18;
    }
}
