// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract Ledger {
    uint256 public reserve;

    function record(uint256 requested) external virtual returns (uint256 observed) {
        observed = requested == 0 ? 0 : requested - 1;
        reserve += observed;
    }
}
