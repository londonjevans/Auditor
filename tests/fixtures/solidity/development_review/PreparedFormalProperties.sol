// SPDX-License-Identifier: UNLICENSED
// Synthetic local plumbing fixture. Abstract and intentionally non-deployable.
pragma solidity ^0.8.20;

abstract contract PreparedFormalProperties {
    function invariant_SyntheticConstantIsPreserved() external pure {
        assert(2 + 2 == 4);
    }
}
