// Synthetic source-custody capacity fixture. Never compile or deploy.
// Abstract declaration: no executable test target, credentials, funds or addresses.
pragma solidity ^0.8.24;
// CAPACITY_IMPORTS
abstract contract CapacityFixture {
    function marker() external pure virtual returns (uint256);
}
