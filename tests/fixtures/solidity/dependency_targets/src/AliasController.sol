// Synthetic source-only alias control; construction always refuses deployment.
pragma solidity ^0.8.20;
import {IReserve as ReserveApi} from "./IReserve.sol";
import * as Protocol from "./IReserve.sol";
contract AliasController {
    constructor() { revert("synthetic fixture: deployment prohibited"); }
    function observe(address reserve) external view returns (uint256) {
        return ReserveApi(reserve).value() + Protocol.IReserve(reserve).value();
    }
}
