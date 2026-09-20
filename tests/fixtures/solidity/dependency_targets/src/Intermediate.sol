// Synthetic source-only namespace/inheritance control; no deployment or funds.
pragma solidity ^0.8.20;
import {IReserve as Parent} from "./IReserve.sol";
interface Intermediate is Parent {}
