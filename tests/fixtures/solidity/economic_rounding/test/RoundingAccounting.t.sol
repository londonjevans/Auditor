// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/RoundingAccounting.sol";

abstract contract RoundingInvariantFixture {
    uint256 internal constant INITIAL_CREDIT = 1_000_000;
    uint256 internal constant ROUNDING_SCALE = 100;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }

    function _boundedAmount(uint256 candidate) internal pure returns (uint256) {
        return 1 + (candidate % (ROUNDING_SCALE - 1));
    }
}

contract UnsafeRoundingInvariant is RoundingInvariantFixture {
    UnsafeRoundingAccount internal account;

    function setUp() public {
        account = new UnsafeRoundingAccount(address(this), INITIAL_CREDIT);
    }

    function action_RoundTrip(uint256 candidate) public {
        account.roundTrip(_boundedAmount(candidate));
    }

    function invariant_NoRoundTripValueCreation() public view {
        require(account.credit(address(this)) <= INITIAL_CREDIT, "round trip created account value");
    }
}

contract SafeRoundingInvariant is RoundingInvariantFixture {
    SafeRoundingAccount internal account;

    function setUp() public {
        account = new SafeRoundingAccount(address(this), INITIAL_CREDIT);
    }

    function action_RoundTrip(uint256 candidate) public {
        account.roundTrip(_boundedAmount(candidate));
    }

    function invariant_NoRoundTripValueCreation() public view {
        require(account.credit(address(this)) <= INITIAL_CREDIT, "round trip created account value");
    }
}

contract RoundingMinimalityControls is RoundingInvariantFixture {
    function testExactBoundaryDoesNotCreateValue() public {
        UnsafeRoundingAccount account = new UnsafeRoundingAccount(address(this), INITIAL_CREDIT);
        account.roundTrip(ROUNDING_SCALE);
        require(account.credit(address(this)) == INITIAL_CREDIT, "unexpected boundary delta");
    }

    function testSafeLossIsBoundedBelowOneScaleUnit() public {
        SafeRoundingAccount account = new SafeRoundingAccount(address(this), INITIAL_CREDIT);
        uint256 beforeCredit = account.credit(address(this));
        account.roundTrip(ROUNDING_SCALE - 1);
        uint256 afterCredit = account.credit(address(this));
        require(afterCredit <= beforeCredit, "safe transition created value");
        require(beforeCredit - afterCredit < ROUNDING_SCALE, "loss unbounded");
    }

    function testOneUnitIsMinimalValueCreatingBoundary() public {
        UnsafeRoundingAccount account = new UnsafeRoundingAccount(address(this), INITIAL_CREDIT);
        account.roundTrip(1);
        require(account.credit(address(this)) > INITIAL_CREDIT, "fixture condition absent");
    }
}
