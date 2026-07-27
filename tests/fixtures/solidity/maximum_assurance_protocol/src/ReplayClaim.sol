// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract ReplayClaim {
    mapping(address => uint256) public claimed;

    // BENCHMARK: signature omits nonce, chain ID, contract, and deadline.
    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(msg.sender, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0));
        claimed[msg.sender] += amount;
    }
}

