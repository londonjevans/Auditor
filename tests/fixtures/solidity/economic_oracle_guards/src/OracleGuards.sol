// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract PresetOracle {
    int256 public answer;
    uint256 public updatedAt;
    uint8 public feedDecimals;
    bool public sequencerAvailable;
    bool public invalidScenario;

    function configureInvalidPreset() external {
        answer = 1_000e8;
        updatedAt = block.timestamp + 1;
        feedDecimals = 8;
        sequencerAvailable = false;
        invalidScenario = true;
    }

    function configureValidPreset() external {
        answer = 1_000e18;
        updatedAt = block.timestamp;
        feedDecimals = 18;
        sequencerAvailable = true;
        invalidScenario = false;
    }

    function configureStalePreset() external {
        answer = 1_000e18;
        updatedAt = block.timestamp + 1;
        feedDecimals = 18;
        sequencerAvailable = true;
        invalidScenario = true;
    }

    function configureScalePreset() external {
        answer = 1_000e8;
        updatedAt = block.timestamp;
        feedDecimals = 8;
        sequencerAvailable = true;
        invalidScenario = true;
    }

    function configureUnavailablePreset() external {
        answer = 0;
        updatedAt = block.timestamp;
        feedDecimals = 18;
        sequencerAvailable = true;
        invalidScenario = true;
    }

    function configureSequencerPreset() external {
        answer = 1_000e18;
        updatedAt = block.timestamp;
        feedDecimals = 18;
        sequencerAvailable = false;
        invalidScenario = true;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, answer, updatedAt, updatedAt, 1);
    }

    function decimals() external view returns (uint8) {
        return feedDecimals;
    }

    function sequencerUp() external view returns (bool) {
        return sequencerAvailable;
    }
}

contract UnsafeOracleGuard {
    PresetOracle public immutable oracle;
    uint256 public guardFailures;
    bytes32 public lastObservation;

    constructor(PresetOracle configuredOracle) {
        oracle = configuredOracle;
    }

    function configurePreset() external {
        oracle.configureInvalidPreset();
    }

    function configureValidPreset() external {
        oracle.configureValidPreset();
    }

    function validatePreset() external {
        (, int256 answer,, uint256 updatedAt,) = oracle.latestRoundData();
        uint8 feedDecimals = oracle.decimals();
        bool sequencerAvailable = oracle.sequencerUp();
        lastObservation = keccak256(abi.encode(answer, updatedAt, feedDecimals, sequencerAvailable));
        if (oracle.invalidScenario()) {
            guardFailures += 1;
        }
    }
}

contract SafeOracleGuard {
    uint256 public constant MAX_AGE = 1 hours;
    uint8 public constant EXPECTED_DECIMALS = 18;

    PresetOracle public immutable oracle;
    uint256 public guardFailures;
    bytes32 public lastObservation;

    constructor(PresetOracle configuredOracle) {
        oracle = configuredOracle;
    }

    function configurePreset() external {
        oracle.configureInvalidPreset();
    }

    function configureValidPreset() external {
        oracle.configureValidPreset();
    }

    function validatePreset() external {
        (, int256 answer,, uint256 updatedAt,) = oracle.latestRoundData();
        uint8 feedDecimals = oracle.decimals();
        bool sequencerAvailable = oracle.sequencerUp();
        require(answer > 0, "unavailable answer");
        require(updatedAt <= block.timestamp, "future update");
        require(block.timestamp - updatedAt <= MAX_AGE, "stale update");
        require(feedDecimals == EXPECTED_DECIMALS, "unexpected decimals");
        require(sequencerAvailable, "sequencer unavailable");
        lastObservation = keccak256(abi.encode(answer, updatedAt, feedDecimals, sequencerAvailable));
        if (oracle.invalidScenario()) {
            guardFailures += 1;
        }
    }
}
