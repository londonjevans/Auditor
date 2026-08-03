// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Ledger} from "./Ledger.sol";

abstract contract Router {
    Ledger internal ledger;
    uint256 public totalRecorded;

    constructor(Ledger configuredLedger) {
        ledger = configuredLedger;
    }

    function route(uint256 requested) external {
        uint256 observed = ledger.record(requested);
        totalRecorded += observed;
    }
}
