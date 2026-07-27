// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract ReentrantBank {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // BENCHMARK: state is cleared after the external callback.
    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balanceOf[msg.sender] = 0;
    }
}

