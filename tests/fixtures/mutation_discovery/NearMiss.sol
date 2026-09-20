// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic non-deployable declaration controls; no live systems, assets or tooling.
library Rounding {
    uint256 internal constant Ceil = 2;
    uint256 internal constant Floor = 1;
}

library LocalObserverShim {
    function observe(uint256) internal pure {}
}

abstract contract NearMiss {
    function localControls(bool initialized, bool paused, uint256 nonce) internal pure {
        require(!initialized, "local parameter, not initializer state");
        require(!paused, "local parameter, not pause state");
        nonce += 1;
        uint256 localState = 7;
        localState = 0;
        LocalObserverShim.observe(localState);
        bool success = internalSuccess();
        require(success, "internal result, not an external call result");
        uint256 choice = Rounding.Ceil;
    }

    function internalSuccess() private pure returns (bool) { return true; }
}
