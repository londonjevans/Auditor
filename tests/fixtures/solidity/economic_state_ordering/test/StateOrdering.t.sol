// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/StateOrdering.sol";

abstract contract StateOrderingFixture {
    uint256 internal attemptsPrepare;
    uint256 internal attemptsCommit;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeStateOrderingInvariant is StateOrderingFixture {
    UnsafePreparedStateMachine internal target;

    function setUp() public {
        target = new UnsafePreparedStateMachine();
    }

    function action_PrepareState() public {
        attemptsPrepare += 1;
        target.preparePreset();
    }

    function action_CommitState() public {
        attemptsCommit += 1;
        target.commitPreset();
    }

    function invariant_PreparedStateConsumedBeforeFinalization() public view {
        if (attemptsPrepare == 0 || attemptsCommit == 0) return;
        require(target.invalidState() == 0, "prepared state remained active");
    }
}

contract SafeStateOrderingInvariant is StateOrderingFixture {
    SafePreparedStateMachine internal target;

    function setUp() public {
        target = new SafePreparedStateMachine();
    }

    function action_PrepareState() public {
        attemptsPrepare += 1;
        target.preparePreset();
    }

    function action_CommitState() public {
        attemptsCommit += 1;
        target.commitPreset();
    }

    function invariant_PreparedStateConsumedBeforeFinalization() public view {
        if (attemptsPrepare == 0 || attemptsCommit == 0) return;
        require(target.invalidState() == 0, "prepared state remained active");
    }
}

contract StateOrderingMinimalityControls {
    function testPrepareAlonePreservesState() public {
        UnsafePreparedStateMachine target = new UnsafePreparedStateMachine();
        target.preparePreset();
        require(target.invalidState() == 0, "prepare alone violated the invariant");
    }

    function testCommitAlonePreservesState() public {
        UnsafePreparedStateMachine target = new UnsafePreparedStateMachine();
        target.commitPreset();
        require(target.invalidState() == 0, "commit alone violated the invariant");
    }

    function testUnsafeTwoStepSequenceReachesInvalidState() public {
        UnsafePreparedStateMachine target = new UnsafePreparedStateMachine();
        target.preparePreset();
        target.commitPreset();
        require(target.invalidState() == 1, "unsafe fixture condition absent");
    }

    function testSafeTwoStepSequenceConsumesPreparedState() public {
        SafePreparedStateMachine target = new SafePreparedStateMachine();
        target.preparePreset();
        target.commitPreset();
        require(target.invalidState() == 0, "safe implementation violated the invariant");
    }
}
