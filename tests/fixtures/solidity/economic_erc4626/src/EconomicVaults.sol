// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleToken {
    string public name = "Fixture Asset";
    string public symbol = "FAST";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 approved = allowance[from][msg.sender];
        require(approved >= amount, "allowance");
        allowance[from][msg.sender] = approved - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

contract VulnerableInflationVault {
    SimpleToken public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) internal shareBalances;

    constructor(SimpleToken asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function balanceOf(address account) external view returns (uint256) {
        return shareBalances[account];
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 assetsBefore = totalAssets();
        uint256 supply = totalSupply;
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer");
        uint256 mintedShares = supply == 0 ? assets : (assets * supply) / assetsBefore;
        require(mintedShares > 0, "zero shares");
        totalSupply = supply + mintedShares;
        shareBalances[receiver] += mintedShares;
        return mintedShares;
    }
}

contract PatchedInflationVault {
    SimpleToken public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) internal shareBalances;

    constructor(SimpleToken asset_) {
        asset = asset_;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function balanceOf(address account) external view returns (uint256) {
        return shareBalances[account];
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        uint256 assetsBefore = totalAssets();
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer");
        uint256 mintedShares = supply == 0 ? assets * 1 ether : (assets * supply) / assetsBefore;
        require(mintedShares > 0, "zero shares");
        totalSupply = supply + mintedShares;
        shareBalances[receiver] += mintedShares;
        return mintedShares;
    }
}
