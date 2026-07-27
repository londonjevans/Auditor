// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeUUPS {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // BENCHMARK: any caller can replace the implementation.
    function upgradeTo(address implementation) external {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, implementation)
        }
    }
}

