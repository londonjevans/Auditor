// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeRewardAccounting {
    uint256 private _rewardIndex;
    mapping(address => uint256) private _entitlement;
    mapping(address => uint256) private _rewardsPaid;

    function accrue(uint256 amount) external {
        _rewardIndex += amount;
    }

    function resetIndex() external {
        _rewardIndex = 0;
    }

    function seedEntitlement(address account, uint256 amount) external {
        _entitlement[account] = amount;
    }

    function claim() external {
        uint256 amount = _entitlement[msg.sender];
        require(amount > 0, "no entitlement");
        _rewardsPaid[msg.sender] += amount;
    }

    function rewardIndex() external view returns (uint256) {
        return _rewardIndex;
    }

    function rewardsPaid(address account) external view returns (uint256) {
        return _rewardsPaid[account];
    }
}

contract SafeRewardAccounting {
    uint256 private _rewardIndex;
    mapping(address => uint256) private _entitlement;
    mapping(address => uint256) private _rewardsPaid;

    function updateRewards(uint256 amount) external {
        _rewardIndex += amount;
    }

    function seedEntitlement(address account, uint256 amount) external {
        _entitlement[account] = amount;
    }

    function claim() external {
        uint256 amount = _entitlement[msg.sender];
        require(amount > 0, "no entitlement");
        _entitlement[msg.sender] = 0;
        _rewardsPaid[msg.sender] += amount;
    }

    function rewardIndex() external view returns (uint256) {
        return _rewardIndex;
    }

    function rewardsPaid(address account) external view returns (uint256) {
        return _rewardsPaid[account];
    }
}
