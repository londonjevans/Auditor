// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract SyntheticRoundingAccount {
    uint256 public constant SCALE = 100;
    mapping(address => uint256) public credit;

    constructor(address holder, uint256 initialCredit) {
        credit[holder] = initialCredit;
    }

    function roundTrip(uint256 amount) external virtual;
}

contract UnsafeRoundingAccount is SyntheticRoundingAccount {
    constructor(address holder, uint256 initialCredit) SyntheticRoundingAccount(holder, initialCredit) {}

    function roundTrip(uint256 amount) external override {
        require(amount > 0 && amount <= credit[msg.sender], "bounded amount");
        credit[msg.sender] -= amount;
        uint256 converted = (amount + SCALE - 1) / SCALE;
        credit[msg.sender] += converted * SCALE;
    }
}

contract SafeRoundingAccount is SyntheticRoundingAccount {
    constructor(address holder, uint256 initialCredit) SyntheticRoundingAccount(holder, initialCredit) {}

    function roundTrip(uint256 amount) external override {
        require(amount > 0 && amount <= credit[msg.sender], "bounded amount");
        credit[msg.sender] -= amount;
        uint256 converted = amount / SCALE;
        credit[msg.sender] += converted * SCALE;
    }
}
