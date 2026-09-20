// Synthetic source-only fixture; Guards prohibits deployment.
pragma solidity ^0.8.24;
import "./Guards.sol";
import "./IReserve.sol";
contract Controller is Guards {
    function inspect(IReserve reserve, uint256 bound)
        external open checked(reserve, normalise(bound)) returns (uint256)
    {
        return reserve.value();
    }
}
