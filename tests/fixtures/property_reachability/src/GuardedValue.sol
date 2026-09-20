// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic defensive controls; no funds, network dependencies or production deployment.
interface InertValidator {
    function validate() external view;
}

contract GuardedValue {
    bool private paused = true;
    uint256 public pausedValue;
    uint256 public freshValue;

    constructor() {
        require(block.chainid == 31337 && block.timestamp > 0, "synthetic local-only fixture");
    }

    modifier requireLive() {
        _liveCheck();
        _;
    }

    function changePaused(uint256 amount) external requireLive {
        pausedValue += amount;
    }

    function changeFresh(uint256 amount) external {
        _freshCheck(0, 0);
        freshValue += amount;
    }

    function _liveCheck() internal view {
        _nestedLiveCheck();
    }

    function _nestedLiveCheck() private view {
        require(!paused, "paused state must prohibit changes");
    }

    function _freshCheck(uint256 updatedAt, uint256 maxAge) internal view {
        require(block.timestamp - updatedAt <= maxAge, "stale input must prohibit changes");
    }

    // Uncalled structural negative controls: no external endpoint is provided or contacted.
    function externalReference(InertValidator supplied) external view {
        supplied.validate();
    }

    function virtualReference() external pure {
        _virtualCheck();
    }

    function _virtualCheck() internal pure virtual {
        require(true);
    }

    function boundedRecursion(uint256 count) external pure {
        _bounded(count % 2);
    }

    function _bounded(uint256 count) private pure {
        if (count > 0) _bounded(count - 1);
    }
}
