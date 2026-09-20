// Synthetic source-only fixture: every concrete descendant reverts during construction.
pragma solidity ^0.8.24;

abstract contract Guard {
    constructor() { revert("NON_DEPLOYABLE_FIXTURE"); }
}
