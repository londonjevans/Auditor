// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {SyntheticAccess} from "./SyntheticFixtureOnly.sol";

// Synthetic fixture only. These reverting-base proxies cannot be deployed.
abstract contract SyntheticTransparentProxy is SyntheticAccess {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        keccak256("mmaudit.synthetic.scale.proxy.implementation");
    address internal _implementation;

    event SyntheticImplementationChanged(
        address indexed previousImplementation,
        address indexed nextImplementation
    );

    function implementation() external view returns (address) {
        return _implementation;
    }

    function initializeProxy(
        address governor_,
        address implementation_
    ) external {
        _initializeSyntheticAccess(governor_);
        _setSyntheticImplementation(implementation_);
    }

    function upgradeTo(address nextImplementation) external onlyGovernor {
        _setSyntheticImplementation(nextImplementation);
    }

    function _setSyntheticImplementation(address nextImplementation) internal {
        if (nextImplementation == address(0)) revert InvalidSyntheticAddress();
        address previous = _implementation;
        _implementation = nextImplementation;
        emit SyntheticImplementationChanged(previous, nextImplementation);
    }

    fallback() external payable {
        address target = _implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

abstract contract SyntheticBeaconProxy is SyntheticAccess {
    address internal _beacon;

    event SyntheticBeaconChanged(address indexed previousBeacon, address indexed nextBeacon);

    function initializeBeaconProxy(address governor_, address beacon_) external {
        _initializeSyntheticAccess(governor_);
        _setSyntheticBeacon(beacon_);
    }

    function setBeacon(address nextBeacon) external onlyGovernor {
        _setSyntheticBeacon(nextBeacon);
    }

    function beacon() external view returns (address) {
        return _beacon;
    }

    function _setSyntheticBeacon(address nextBeacon) internal {
        if (nextBeacon == address(0)) revert InvalidSyntheticAddress();
        address previous = _beacon;
        _beacon = nextBeacon;
        emit SyntheticBeaconChanged(previous, nextBeacon);
    }
}
