// Synthetic source-only fixture; inherited construction always reverts.
pragma solidity ^0.8.24;
import "./IReserve.sol";
contract Guards {
    constructor() { revert("NON_DEPLOYABLE_FIXTURE"); }
    modifier open { _; }
    modifier checked(IReserve reserve, uint256 bound) virtual {
        require(reserve.value() <= bound);
        _;
    }
    function normalise(uint256 amount) internal pure returns (uint256) { return amount; }
}
