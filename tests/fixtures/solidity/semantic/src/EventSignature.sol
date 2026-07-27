// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract EventSignature {
    event Deposited(address indexed account, uint256 amount);

    mapping(address => uint256) public nonces;
    uint256 public totalAssets;

    function deposit(uint256 amount) external {
        totalAssets += amount;
        emit Deposited(msg.sender, amount);
    }

    function permitDeposit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        uint256 nonce = nonces[msg.sender]++;
        bytes32 digest =
            keccak256(abi.encode(block.chainid, address(this), msg.sender, amount, nonce, deadline));
        require(ecrecover(digest, v, r, s) != address(0), "signature");
        totalAssets += amount;
        emit Deposited(msg.sender, amount);
    }
}
