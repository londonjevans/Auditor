// Synthetic alternate implementation; never infer deployment wiring from inheritance.
pragma solidity ^0.8.20;
import {IReserve} from "./IReserve.sol";

contract SecondReserve is IReserve {
    constructor() { revert("Synthetic source-only fixture: deployment prohibited"); }
    function value() external pure returns (uint256) {
        return 1;
    }
}
