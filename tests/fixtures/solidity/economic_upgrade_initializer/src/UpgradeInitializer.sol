// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract ImplementationV1 {
    function version() external pure returns (uint256) {
        return 1;
    }
}

contract ImplementationV2 {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract UnsafeUpgradeProxy {
    address public immutable admin;
    address public immutable presetImplementation;
    address public implementation;
    address public owner;
    bool public initialized;
    uint256 public invalidTransitions;

    constructor(address configuredAdmin, address initialImplementation, address nextImplementation) {
        admin = configuredAdmin;
        implementation = initialImplementation;
        presetImplementation = nextImplementation;
    }

    function initializePreset() external {
        if (initialized) {
            invalidTransitions += 1;
        }
        initialized = true;
        owner = msg.sender;
    }

    function upgradePreset() external {
        if (msg.sender != admin) {
            invalidTransitions += 1;
        }
        implementation = presetImplementation;
    }

    fallback() external payable {
        address target = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

contract SafeUpgradeProxy {
    address public immutable admin;
    address public immutable presetImplementation;
    address public implementation;
    address public owner;
    bool public initialized;
    uint256 public invalidTransitions;

    constructor(address configuredAdmin, address initialImplementation, address nextImplementation) {
        admin = configuredAdmin;
        implementation = initialImplementation;
        presetImplementation = nextImplementation;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "upgrade admin required");
        _;
    }

    function initializePreset() external onlyAdmin {
        require(!initialized, "already initialized");
        initialized = true;
        owner = msg.sender;
    }

    function upgradePreset() external onlyAdmin {
        implementation = presetImplementation;
    }

    fallback() external payable {
        address target = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}
