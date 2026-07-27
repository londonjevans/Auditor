// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeSignedClaim {
    uint256 public constant CLAIM_AMOUNT = 7;
    address public immutable signer;
    uint8 internal immutable signatureV;
    bytes32 internal immutable signatureR;
    bytes32 internal immutable signatureS;
    mapping(address => uint256) public claimed;

    constructor(address configuredSigner, uint8 v, bytes32 r, bytes32 s) {
        signer = configuredSigner;
        signatureV = v;
        signatureR = r;
        signatureS = s;
    }

    function claimPreset() external {
        bytes32 digest = keccak256(abi.encode(msg.sender, CLAIM_AMOUNT));
        require(ecrecover(digest, signatureV, signatureR, signatureS) == signer, "invalid fixture signature");
        claimed[msg.sender] += CLAIM_AMOUNT;
    }
}

contract SafeSignedClaim {
    uint256 public constant CLAIM_AMOUNT = 7;
    address public immutable signer;
    bytes32 public immutable domain;
    uint8 internal immutable signatureV;
    bytes32 internal immutable signatureR;
    bytes32 internal immutable signatureS;
    mapping(address => uint256) public claimed;
    mapping(address => uint256) public nonces;

    constructor(address configuredSigner, bytes32 configuredDomain, uint8 v, bytes32 r, bytes32 s) {
        signer = configuredSigner;
        domain = configuredDomain;
        signatureV = v;
        signatureR = r;
        signatureS = s;
    }

    function claimPreset() external {
        uint256 nonce = nonces[msg.sender];
        bytes32 digest = keccak256(abi.encode(block.chainid, domain, msg.sender, CLAIM_AMOUNT, nonce));
        require(ecrecover(digest, signatureV, signatureR, signatureS) == signer, "invalid fixture signature");
        nonces[msg.sender] = nonce + 1;
        claimed[msg.sender] += CLAIM_AMOUNT;
    }
}
