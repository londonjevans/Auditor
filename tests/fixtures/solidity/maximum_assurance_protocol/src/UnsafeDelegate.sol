// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeDelegate {
    // BENCHMARK: arbitrary caller-controlled delegatecall target and calldata.
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory result) = target.delegatecall(data);
        require(ok);
        return result;
    }
}

