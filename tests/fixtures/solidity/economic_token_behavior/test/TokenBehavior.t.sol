// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/TokenBehavior.sol";

interface Vm {
    function prank(address) external;
}

abstract contract TokenBehaviorFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);
    uint256 internal constant AMOUNT = 100 ether;

    SyntheticBehaviorToken internal token;

    function _approveAndDeposit(address vault) internal {
        vm.prank(ACTOR);
        token.approve(vault, AMOUNT);
        vm.prank(ACTOR);
        (bool ok,) = vault.call(abi.encodeWithSignature("deposit(uint256)", AMOUNT));
        require(ok, "fixture deposit failed");
    }
}

contract UnsafeFeeAccountingInvariant is TokenBehaviorFixture {
    UnsafeNominalCreditVault internal vault;

    function setUp() public {
        token = new SyntheticBehaviorToken();
        vault = new UnsafeNominalCreditVault(token);
        token.setFeeBps(1_000);
        token.mint(ACTOR, AMOUNT);
        _approveAndDeposit(address(vault));
    }

    function invariant_ObservedAssetsCoverClaims() public view {
        require(
            token.balanceOf(address(vault)) >= vault.claimable(ACTOR), "observed assets do not cover recorded claim"
        );
    }
}

contract SafeFeeAccountingInvariant is TokenBehaviorFixture {
    SafeObservedBalanceVault internal vault;

    function setUp() public {
        token = new SyntheticBehaviorToken();
        vault = new SafeObservedBalanceVault(token);
        token.setFeeBps(1_000);
        token.mint(ACTOR, AMOUNT);
        _approveAndDeposit(address(vault));
    }

    function invariant_ObservedAssetsCoverClaims() public view {
        require(
            token.balanceOf(address(vault)) >= vault.claimable(ACTOR), "observed assets do not cover recorded claim"
        );
    }
}

contract UnsafeRebaseAccountingInvariant is TokenBehaviorFixture {
    UnsafeNominalCreditVault internal vault;

    function setUp() public {
        token = new SyntheticBehaviorToken();
        vault = new UnsafeNominalCreditVault(token);
        token.mint(ACTOR, AMOUNT);
        _approveAndDeposit(address(vault));
        token.rebaseAccountDown(address(vault), AMOUNT / 2);
    }

    function invariant_ObservedAssetsCoverClaims() public view {
        require(
            token.balanceOf(address(vault)) >= vault.claimable(ACTOR), "observed assets do not cover recorded claim"
        );
    }
}

contract SafeRebaseAccountingInvariant is TokenBehaviorFixture {
    SafeObservedBalanceVault internal vault;

    function setUp() public {
        token = new SyntheticBehaviorToken();
        vault = new SafeObservedBalanceVault(token);
        token.mint(ACTOR, AMOUNT);
        _approveAndDeposit(address(vault));
        token.rebaseAccountDown(address(vault), AMOUNT / 2);
    }

    function invariant_ObservedAssetsCoverClaims() public view {
        require(
            token.balanceOf(address(vault)) >= vault.claimable(ACTOR), "observed assets do not cover recorded claim"
        );
    }
}

contract TokenBehaviorMinimalityControls is TokenBehaviorFixture {
    function testNoFeeHasNoImmediateDivergence() public {
        token = new SyntheticBehaviorToken();
        UnsafeNominalCreditVault vault = new UnsafeNominalCreditVault(token);
        token.mint(ACTOR, AMOUNT);
        _approveAndDeposit(address(vault));
        require(token.balanceOf(address(vault)) >= vault.claimable(ACTOR), "unexpected gap");
    }

    function testNoRebaseHasNoImmediateDivergence() public {
        token = new SyntheticBehaviorToken();
        UnsafeNominalCreditVault vault = new UnsafeNominalCreditVault(token);
        token.mint(ACTOR, AMOUNT);
        _approveAndDeposit(address(vault));
        require(token.balanceOf(address(vault)) >= vault.claimable(ACTOR), "unexpected gap");
    }
}
