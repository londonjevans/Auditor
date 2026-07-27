// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/RewardAccounting.sol";

interface Vm {
    function prank(address) external;
}

abstract contract RewardAccountingFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);
    uint256 internal constant AMOUNT = 100 ether;
}

contract UnsafeRewardIndexInvariant is RewardAccountingFixture {
    UnsafeRewardAccounting internal rewards;

    function setUp() public {
        rewards = new UnsafeRewardAccounting();
        rewards.accrue(AMOUNT);
        rewards.resetIndex();
    }

    function invariant_RewardIndexDoesNotDecrease() public view {
        require(rewards.rewardIndex() >= AMOUNT, "cumulative reward index decreased");
    }
}

contract SafeRewardIndexInvariant is RewardAccountingFixture {
    SafeRewardAccounting internal rewards;

    function setUp() public {
        rewards = new SafeRewardAccounting();
        rewards.updateRewards(AMOUNT);
        rewards.updateRewards(AMOUNT / 2);
    }

    function invariant_RewardIndexDoesNotDecrease() public view {
        require(rewards.rewardIndex() >= AMOUNT, "cumulative reward index decreased");
    }
}

contract UnsafeClaimOnceInvariant is RewardAccountingFixture {
    UnsafeRewardAccounting internal rewards;

    function setUp() public {
        rewards = new UnsafeRewardAccounting();
        rewards.seedEntitlement(ACTOR, AMOUNT);
        vm.prank(ACTOR);
        rewards.claim();
        vm.prank(ACTOR);
        rewards.claim();
    }

    function invariant_FiniteEntitlementIsPaidAtMostOnce() public view {
        require(rewards.rewardsPaid(ACTOR) <= AMOUNT, "entitlement paid repeatedly");
    }
}

contract SafeClaimOnceInvariant is RewardAccountingFixture {
    SafeRewardAccounting internal rewards;

    function setUp() public {
        rewards = new SafeRewardAccounting();
        rewards.seedEntitlement(ACTOR, AMOUNT);
        vm.prank(ACTOR);
        rewards.claim();
        vm.prank(ACTOR);
        (bool repeated,) = address(rewards).call(abi.encodeWithSignature("claim()"));
        require(!repeated, "consumed claim succeeded");
    }

    function invariant_FiniteEntitlementIsPaidAtMostOnce() public view {
        require(rewards.rewardsPaid(ACTOR) <= AMOUNT, "entitlement paid repeatedly");
    }
}

contract RewardAccountingMinimalityControls is RewardAccountingFixture {
    function testAccrualWithoutResetIsMonotonic() public {
        UnsafeRewardAccounting rewards = new UnsafeRewardAccounting();
        rewards.accrue(AMOUNT);
        require(rewards.rewardIndex() == AMOUNT, "unexpected index");
    }

    function testSingleUnsafeClaimDoesNotExceedEntitlement() public {
        UnsafeRewardAccounting rewards = new UnsafeRewardAccounting();
        rewards.seedEntitlement(ACTOR, AMOUNT);
        vm.prank(ACTOR);
        rewards.claim();
        require(rewards.rewardsPaid(ACTOR) == AMOUNT, "unexpected payout");
    }
}
