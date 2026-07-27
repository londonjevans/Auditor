// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract SafeControls {
    address public immutable owner;
    mapping(address => uint256) public balanceOf;
    bool private entered;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier nonReentrant() {
        require(!entered);
        entered = true;
        _;
        entered = false;
    }

    // SAFE CONTROL: nearby authorization must prevent a false positive.
    function rescue(address payable recipient) external onlyOwner {
        recipient.transfer(address(this).balance);
    }

    // SAFE CONTROL: checks-effects-interactions plus guard.
    function withdraw() external nonReentrant {
        uint256 amount = balanceOf[msg.sender];
        balanceOf[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }

    receive() external payable {}
}

