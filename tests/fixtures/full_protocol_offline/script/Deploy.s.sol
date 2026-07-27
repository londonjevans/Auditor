// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {FullProtocol} from "../src/FullProtocol.sol";

contract SyntheticDeploymentDescription {
    function describe(address admin, address timelock, address oracle, address relayer)
        external
        returns (FullProtocol)
    {
        return new FullProtocol(admin, timelock, oracle, relayer);
    }
}
