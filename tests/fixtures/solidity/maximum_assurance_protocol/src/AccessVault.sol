// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract AccessVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BENCHMARK: intentionally missing owner authorization.
    function drain(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }

    receive() external payable {}
}

