// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/OracleGuards.sol";

abstract contract OracleGuardInvariantFixture {
    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeOracleGuardInvariant is OracleGuardInvariantFixture {
    PresetOracle internal oracle;
    UnsafeOracleGuard internal consumer;

    function setUp() public {
        oracle = new PresetOracle();
        consumer = new UnsafeOracleGuard(oracle);
        consumer.configurePreset();
    }

    function action_ValidateConfiguredFeed() public {
        consumer.validatePreset();
    }

    function invariant_InvalidFeedIsRejected() public view {
        require(consumer.guardFailures() == 0, "invalid feed state was accepted");
    }
}

contract SafeOracleGuardInvariant is OracleGuardInvariantFixture {
    PresetOracle internal oracle;
    SafeOracleGuard internal consumer;

    function setUp() public {
        oracle = new PresetOracle();
        consumer = new SafeOracleGuard(oracle);
        consumer.configurePreset();
    }

    function action_ValidateConfiguredFeed() public {
        (bool ok,) = address(consumer).call(abi.encodeWithSignature("validatePreset()"));
        ok;
    }

    function invariant_InvalidFeedIsRejected() public view {
        require(consumer.guardFailures() == 0, "invalid feed state was accepted");
    }
}

contract OracleGuardBoundaryControls {
    PresetOracle internal oracle;
    SafeOracleGuard internal safeConsumer;

    function setUp() public {
        oracle = new PresetOracle();
        safeConsumer = new SafeOracleGuard(oracle);
    }

    function _validationReverts() internal returns (bool) {
        (bool ok,) = address(safeConsumer).call(abi.encodeWithSignature("validatePreset()"));
        return !ok;
    }

    function testGuardedImplementationRejectsEachInvalidBoundary() public {
        oracle.configureStalePreset();
        require(_validationReverts(), "freshness boundary accepted");
        oracle.configureScalePreset();
        require(_validationReverts(), "scale boundary accepted");
        oracle.configureUnavailablePreset();
        require(_validationReverts(), "availability boundary accepted");
        oracle.configureSequencerPreset();
        require(_validationReverts(), "sequencer boundary accepted");
        require(safeConsumer.guardFailures() == 0, "rejected state was recorded");
    }

    function testGuardedImplementationAcceptsValidPreset() public {
        safeConsumer.configureValidPreset();
        safeConsumer.validatePreset();
        require(safeConsumer.guardFailures() == 0, "valid state was rejected");
    }

    function testUnsafeValidPresetDoesNotRecordFailure() public {
        UnsafeOracleGuard unsafeConsumer = new UnsafeOracleGuard(oracle);
        unsafeConsumer.configureValidPreset();
        unsafeConsumer.validatePreset();
        require(unsafeConsumer.guardFailures() == 0, "minimal valid state marked invalid");
    }
}
