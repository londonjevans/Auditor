// Synthetic source-only fixture; construction is prohibited.
pragma solidity ^0.8.24;
import "./IReserve.sol";
contract ReserveB is IReserve {
    constructor() { revert("NON_DEPLOYABLE_FIXTURE"); }
    function value() external pure returns (uint256) { return 1; }
}
