// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Synthetic non-production fixture for bounded state-transition validation.
contract UnsafePreparedStateMachine {
    uint256 internal _prepared;
    uint256 internal _finalized;

    function preparePreset() external {
        if (_prepared == 0 && _finalized == 0) {
            _prepared = 1;
        }
    }

    function commitPreset() external {
        if (_prepared == 1 && _finalized == 0) {
            _finalized = 1;
        }
    }

    function invalidState() external view returns (uint256) {
        return _prepared == 1 && _finalized == 1 ? 1 : 0;
    }
}

/// @notice Remediated fixture consumes prepared state before finalization.
contract SafePreparedStateMachine {
    uint256 internal _prepared;
    uint256 internal _finalized;

    function preparePreset() external {
        if (_prepared == 0 && _finalized == 0) {
            _prepared = 1;
        }
    }

    function commitPreset() external {
        if (_prepared == 1 && _finalized == 0) {
            _prepared = 0;
            _finalized = 1;
        }
    }

    function invalidState() external view returns (uint256) {
        return _prepared == 1 && _finalized == 1 ? 1 : 0;
    }
}
