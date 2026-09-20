// Synthetic non-production source-only dependency fixture. No deployment or funds.
pragma solidity ^0.8.20;
import {IReserve} from "./IReserve.sol";

contract Controller {
    constructor() { revert("Synthetic source-only fixture: deployment prohibited"); }
    function observedValue(address reserve) external view returns (uint256) {
        return IReserve(reserve).value();
    }
}
