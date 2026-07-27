// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract SyntheticBehaviorToken {
    uint256 public constant BPS = 10_000;
    uint256 public feeBps;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function setFeeBps(uint256 nextFeeBps) external {
        require(nextFeeBps <= 2_000, "fixture fee bound");
        feeBps = nextFeeBps;
    }

    function mint(address account, uint256 amount) external {
        totalSupply += amount;
        balanceOf[account] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 approved = allowance[from][msg.sender];
        require(approved >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        allowance[from][msg.sender] = approved - amount;
        balanceOf[from] -= amount;
        uint256 fee = (amount * feeBps) / BPS;
        balanceOf[to] += amount - fee;
        totalSupply -= fee;
        return true;
    }

    function rebaseAccountDown(address account, uint256 amount) external {
        require(balanceOf[account] >= amount, "rebase amount");
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }
}

contract UnsafeNominalCreditVault {
    SyntheticBehaviorToken public immutable asset;
    mapping(address => uint256) public credit;

    constructor(SyntheticBehaviorToken configuredAsset) {
        asset = configuredAsset;
    }

    function deposit(uint256 amount) external {
        require(asset.transferFrom(msg.sender, address(this), amount), "transfer");
        credit[msg.sender] += amount;
    }

    function claimable(address account) external view returns (uint256) {
        return credit[account];
    }
}

contract SafeObservedBalanceVault {
    SyntheticBehaviorToken public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(SyntheticBehaviorToken configuredAsset) {
        asset = configuredAsset;
    }

    function deposit(uint256 amount) external {
        uint256 beforeBalance = asset.balanceOf(address(this));
        require(asset.transferFrom(msg.sender, address(this), amount), "transfer");
        uint256 received = asset.balanceOf(address(this)) - beforeBalance;
        require(received > 0, "no assets received");
        totalShares += received;
        shares[msg.sender] += received;
    }

    function claimable(address account) external view returns (uint256) {
        if (totalShares == 0) return 0;
        return (asset.balanceOf(address(this)) * shares[account]) / totalShares;
    }
}
