// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract ReplayInitializer {
    address public owner;

    // BENCHMARK: initializer has no one-time guard.
    function initialize(address newOwner) external {
        owner = newOwner;
    }
}

