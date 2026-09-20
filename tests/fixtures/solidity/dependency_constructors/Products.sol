// Synthetic source-only fixture; every product inherits the reverting Guard.
pragma solidity ^0.8.24;
import {Seeded as Base} from "./Bases.sol";
import "./Guard.sol";

contract Product is Base {
    constructor(uint256 initial) Base(uint256(initial)) { }
}
contract HeaderProduct is Base(uint256(7)) { }
contract Implicit is Guard { }
contract DerivedProduct is Product {
    constructor(uint256 initial) Product(initial) { }
}
