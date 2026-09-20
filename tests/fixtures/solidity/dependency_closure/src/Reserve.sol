// Synthetic non-production source-only dependency fixture. No deployment or funds.
pragma solidity ^0.8.20;
import {IReserve} from "./IReserve.sol";
import {Math} from "@local/Math.sol";

contract Reserve is IReserve {
    constructor() { revert("Synthetic source-only fixture: deployment prohibited"); }
    function value() external pure returns (uint256) {
        return Math.zero();
    }
}
