// Synthetic source-only fixture; Guards prohibits deployment.
pragma solidity ^0.8.24;
import "./Controller.sol";
import "./IReserve.sol";
contract Child is Controller {
    modifier checked(IReserve reserve, uint256 bound) override {
        require(reserve.value() == bound);
        _;
    }
}
