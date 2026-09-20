// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import "../src/PortfolioTargets.sol";

contract DifferentLocalCaller {
    function callOwnerMethod(PortfolioTargets target) external returns (bool ok) {
        (ok,) = address(target).call(abi.encodeCall(target.callerAllowed, ()));
    }

    function callPauseMethod(PortfolioTargets target) external returns (bool ok) {
        (ok,) = address(target).call(abi.encodeCall(target.pauseForControl, ()));
    }
}

contract AlwaysRefusedLocalResult is LocalResult {
    function accepted() external pure returns (bool) { return false; }
}

contract PortfolioProperties is LocalObserver {
    PortfolioTargets private target;

    function setUp() external { target = new PortfolioTargets(); }

    function testCallerMustBeAuthorized() external {
        DifferentLocalCaller caller = new DifferentLocalCaller();
        assert(!caller.callOwnerMethod(target));
        assert(!caller.callPauseMethod(target));
    }

    function testIdentifierCannotBeConsumedTwice() external {
        target.consume(7);
        (bool ok,) = address(target).call(abi.encodeCall(target.consume, (7)));
        assert(!ok);
    }

    function testRequiredRoundingIsUpward() external view { assert(target.rounded(4) == 2); }

    function testStalePriceMustBeRefused() external {
        (bool ok,) = address(target).call(abi.encodeCall(target.fresh, (0, 0)));
        assert(!ok);
    }

    function testStateIsFinalBeforeNotification() external { target.notify(this); }

    function observe(uint256 value) external view {
        assert(msg.sender == address(target));
        assert(value == 5 && target.pendingValue() == 0);
    }

    function testInitializationCannotRepeat() external {
        target.initializeOnce();
        (bool ok,) = address(target).call(abi.encodeCall(target.initializeOnce, ()));
        assert(!ok);
    }

    function testDelayCannotBeBypassedAtSchedulingTime() external {
        (bool ok,) = address(target).call(abi.encodeCall(target.ready, (block.timestamp)));
        assert(!ok);
    }

    function testStorageSlotRetainsItsBoundValue() external view { assert(target.stored() == 77); }

    function testPauseMustStopProtectedOperation() external {
        target.pauseForControl();
        (bool ok,) = address(target).call(abi.encodeCall(target.pauseProtected, ()));
        assert(!ok);
    }

    function testFalseReturnMustBeChecked() external {
        AlwaysRefusedLocalResult refused = new AlwaysRefusedLocalResult();
        (bool ok,) = address(target).call(abi.encodeCall(target.checkedResult, (refused)));
        assert(!ok);
    }

    function testScaleMustRetainEighteenDecimals() external view { assert(target.scaled(2) == 2e18); }
}
