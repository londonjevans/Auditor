// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Synthetic, non-production source used only to validate provider transport.
contract ProviderSmoke {
    function boundedIncrement(uint256 value) external pure returns (uint256) {
        require(value < 100, "synthetic bound");
        return value + 1;
    }
}
