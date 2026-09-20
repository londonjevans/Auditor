// Synthetic source-only implementation; construction always refuses deployment.
pragma solidity ^0.8.20;
import * as Types from "./Intermediate.sol";
contract InheritedReserve is Types.Intermediate {
    constructor() { revert("synthetic fixture: deployment prohibited"); }
    function value() external pure returns (uint256) { return 2; }
}
