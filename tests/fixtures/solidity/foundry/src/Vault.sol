// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Owned {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not-owner");
        _;
    }
}

contract Vault is Owned {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        _withdraw(msg.sender, amount);
    }

    function _withdraw(address to, uint256 amount) internal {
        balances[to] -= amount;
        payable(to).transfer(amount);
    }
}

