// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IAccountingAsset {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract UnsafeNominalLedger {
    IAccountingAsset public asset;
    mapping(address => uint256) public credit;

    function deposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        asset.transfer(msg.sender, amount);
        credit[msg.sender] -= amount;
    }
}

contract SafeObservedLedger {
    IAccountingAsset public asset;
    mapping(address => uint256) public credit;

    function deposit(uint256 amount) external {
        uint256 beforeBalance = asset.balanceOf(address(this));
        asset.transferFrom(msg.sender, address(this), amount);
        uint256 received = asset.balanceOf(address(this)) - beforeBalance;
        credit[msg.sender] += received;
    }

    function withdraw(uint256 amount) external {
        credit[msg.sender] -= amount;
        asset.transfer(msg.sender, amount);
    }
}

contract LifecycleLedger {
    uint256 public supply;
    uint256 public rewards;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public collateral;

    function mint(uint256 amount) external {
        supply += amount;
        balances[msg.sender] += amount;
    }

    function burn(uint256 amount) external {
        balances[msg.sender] -= amount;
        supply -= amount;
    }

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
    }

    function reward(uint256 amount) external {
        rewards += amount;
    }

    function claim(uint256 amount) external {
        rewards -= amount;
        balances[msg.sender] += amount;
    }

    function liquidate(address account) external {
        collateral[account] = 0;
    }
}
