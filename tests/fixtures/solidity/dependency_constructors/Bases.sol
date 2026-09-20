// Synthetic source-only fixture; inherited Guard prevents deployment.
pragma solidity ^0.8.24;
import "./Guard.sol";

abstract contract Seeded is Guard {
    uint256 internal seed;
    constructor(uint256 initial) { seed = initial; }
    function value() public view virtual returns (uint256) { return seed; }
}
