// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Intentionally non-compilable synthetic input for fallback provenance tests.
contract MalformedAccounting {
    uint256 public observedTotal;

    function record(uint256 amount) external {
        observedTotal += amount;
    // Deliberately missing closing braces.
