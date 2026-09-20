// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic local-only defensive controls, never production protocol source.
library LocalMath {
    enum Rounding { Floor, Ceil }

    function mulDiv(uint256 amount, uint256 numerator, uint256 denominator, Rounding mode)
        internal pure returns (uint256)
    {
        uint256 product = amount * numerator;
        return product / denominator + (mode == Rounding.Ceil && product % denominator != 0 ? 1 : 0);
    }
}

interface LocalObserver {
    function observe(uint256 value) external;
}

interface LocalResult {
    function accepted() external pure returns (bool);
}

contract PortfolioTargets {
    address private immutable owner;
    mapping(uint256 => bool) private consumedIdentifiers;
    bool private initialized;
    bool private paused;
    uint256 public pendingValue = 5;
    bytes32 internal constant STORAGE_SLOT = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    constructor() {
        require(block.chainid == 31337, "synthetic local-only fixture");
        owner = msg.sender;
        assembly { sstore(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, 77) }
    }

    function callerAllowed() external view returns (bool) {
        require(msg.sender == owner, "caller denied");
        return true;
    }

    function consume(uint256 identifier) external {
        require(!consumedIdentifiers[identifier], "already consumed");
        consumedIdentifiers[identifier] = true;
    }

    function rounded(uint256 amount) external pure returns (uint256) {
        return LocalMath.mulDiv(amount, 1, 3, LocalMath.Rounding.Ceil);
    }

    function fresh(uint256 updatedAt, uint256 maxAge) external view returns (bool) {
        require(block.timestamp - updatedAt <= maxAge, "stale price");
        return true;
    }

    function notify(LocalObserver observer) external {
        uint256 amount = pendingValue;
        pendingValue = 0;
        observer.observe(amount);
    }

    function initializeOnce() external {
        require(!initialized, "already initialized");
        initialized = true;
    }

    function ready(uint256 scheduledAt) external view returns (bool) {
        require(block.timestamp >= scheduledAt + 2 seconds, "too early");
        return true;
    }

    function stored() external view returns (uint256 value) {
        bytes32 selectedSlot = STORAGE_SLOT;
        assembly { value := sload(selectedSlot) }
    }

    function pauseForControl() external {
        require(msg.sender == owner, "owner only");
        paused = true;
    }

    function pauseProtected() external view returns (bool) {
        require(!paused, "paused");
        return true;
    }

    function checkedResult(LocalResult result) external view returns (bool) {
        bool success = result.accepted();
        require(success, "result refused");
        return true;
    }

    function scaled(uint256 amount) external pure returns (uint256) {
        return amount * 1e18;
    }
}
