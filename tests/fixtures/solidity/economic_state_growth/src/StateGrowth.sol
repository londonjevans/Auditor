// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeStateGrowth {
    bytes32[] public entries;

    function appendPreset() external {
        entries.push(bytes32(entries.length + 1));
    }

    function entryCount() external view returns (uint256) {
        return entries.length;
    }

    function growthThreshold() external pure returns (uint256) {
        return 4;
    }
}

contract SafeStateGrowth {
    uint256 internal constant MAX_ENTRIES = 4;
    bytes32[] public entries;

    function appendPreset() external {
        require(entries.length < MAX_ENTRIES, "growth threshold reached");
        entries.push(bytes32(entries.length + 1));
    }

    function entryCount() external view returns (uint256) {
        return entries.length;
    }

    function growthThreshold() external pure returns (uint256) {
        return 4;
    }
}
