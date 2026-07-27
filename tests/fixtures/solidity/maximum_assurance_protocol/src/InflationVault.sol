// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract InflationVault {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // BENCHMARK: first-depositor/donation state can round a victim to zero shares.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
        totalAssets += assets;
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function donate(uint256 assets) external {
        totalAssets += assets;
    }
}

