// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract FeeTokenVault {
    IERC20Like public asset;
    mapping(address => uint256) public credit;

    constructor(IERC20Like configuredAsset) {
        asset = configuredAsset;
    }

    // BENCHMARK: credits nominal amount without measuring fee-on-transfer receipt.
    function deposit(uint256 amount) external {
        require(asset.transferFrom(msg.sender, address(this), amount));
        credit[msg.sender] += amount;
    }
}

