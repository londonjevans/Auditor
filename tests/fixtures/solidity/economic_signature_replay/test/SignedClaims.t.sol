// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/SignedClaims.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

abstract contract SignedClaimFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SYNTHETIC_LOCAL_KEY = uint256(keccak256("mmaudit synthetic signature fixture only"));
    uint256 internal constant CLAIM_AMOUNT = 7;
    bytes32 internal constant DOMAIN = keccak256("mmaudit.synthetic.signature.domain");

    function _sign(bytes32 digest) internal returns (address signer, uint8 v, bytes32 r, bytes32 s) {
        signer = vm.addr(SYNTHETIC_LOCAL_KEY);
        (v, r, s) = vm.sign(SYNTHETIC_LOCAL_KEY, digest);
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeSignatureReplayInvariant is SignedClaimFixture {
    UnsafeSignedClaim internal target;

    function setUp() public {
        bytes32 digest = keccak256(abi.encode(address(this), CLAIM_AMOUNT));
        (address signer, uint8 v, bytes32 r, bytes32 s) = _sign(digest);
        target = new UnsafeSignedClaim(signer, v, r, s);
        target.claimPreset();
    }

    function action_ReplayAuthorization() public {
        target.claimPreset();
    }

    function invariant_AuthorizationConsumedOnce() public view {
        require(target.claimed(address(this)) <= CLAIM_AMOUNT, "authorization reused");
    }
}

contract SafeSignatureReplayInvariant is SignedClaimFixture {
    SafeSignedClaim internal target;

    function setUp() public {
        bytes32 digest = keccak256(abi.encode(block.chainid, DOMAIN, address(this), CLAIM_AMOUNT, uint256(0)));
        (address signer, uint8 v, bytes32 r, bytes32 s) = _sign(digest);
        target = new SafeSignedClaim(signer, DOMAIN, v, r, s);
        target.claimPreset();
    }

    function action_ReplayAuthorization() public {
        (bool ok,) = address(target).call(abi.encodeWithSignature("claimPreset()"));
        ok;
    }

    function invariant_AuthorizationConsumedOnce() public view {
        require(target.claimed(address(this)) <= CLAIM_AMOUNT, "authorization reused");
    }
}

contract SignatureReplayMinimalityControls is SignedClaimFixture {
    function testSafeNonceRejectsSecondConsumption() public {
        bytes32 digest = keccak256(abi.encode(block.chainid, DOMAIN, address(this), CLAIM_AMOUNT, uint256(0)));
        (address signer, uint8 v, bytes32 r, bytes32 s) = _sign(digest);
        SafeSignedClaim target = new SafeSignedClaim(signer, DOMAIN, v, r, s);
        target.claimPreset();
        (bool replayAccepted,) = address(target).call(abi.encodeWithSignature("claimPreset()"));
        require(!replayAccepted, "nonce did not reject replay");
        require(target.nonces(address(this)) == 1, "unexpected nonce");
        require(target.claimed(address(this)) == CLAIM_AMOUNT, "duplicate state effect");
    }

    function testSafeDomainRejectsMismatchedAuthorization() public {
        bytes32 digest = keccak256(abi.encode(block.chainid, DOMAIN, address(this), CLAIM_AMOUNT, uint256(0)));
        (address signer, uint8 v, bytes32 r, bytes32 s) = _sign(digest);
        bytes32 differentDomain = keccak256("mmaudit.synthetic.signature.other-domain");
        SafeSignedClaim target = new SafeSignedClaim(signer, differentDomain, v, r, s);
        (bool accepted,) = address(target).call(abi.encodeWithSignature("claimPreset()"));
        require(!accepted, "domain mismatch accepted");
        require(target.claimed(address(this)) == 0, "mismatched authorization changed state");
    }

    function testSecondIdenticalCallIsMinimalUnsafeSequence() public {
        bytes32 digest = keccak256(abi.encode(address(this), CLAIM_AMOUNT));
        (address signer, uint8 v, bytes32 r, bytes32 s) = _sign(digest);
        UnsafeSignedClaim target = new UnsafeSignedClaim(signer, v, r, s);
        target.claimPreset();
        target.claimPreset();
        require(target.claimed(address(this)) == CLAIM_AMOUNT * 2, "fixture condition absent");
    }
}
