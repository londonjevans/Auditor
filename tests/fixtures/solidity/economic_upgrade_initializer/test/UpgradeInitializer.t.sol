// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/UpgradeInitializer.sol";

interface Vm {
    function prank(address sender) external;
}

interface IImplementationVersion {
    function version() external view returns (uint256);
}

abstract contract UpgradeInvariantFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ADMIN = 0x1000000000000000000000000000000000000001;
    address internal constant ATTACKER = 0x1000000000000000000000000000000000000002;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeUpgradeInvariant is UpgradeInvariantFixture {
    UnsafeUpgradeProxy internal target;

    function setUp() public {
        ImplementationV1 first = new ImplementationV1();
        ImplementationV2 second = new ImplementationV2();
        target = new UnsafeUpgradeProxy(ADMIN, address(first), address(second));
        vm.prank(ADMIN);
        target.initializePreset();
    }

    function action_RepeatInitializer() public {
        vm.prank(ATTACKER);
        target.initializePreset();
    }

    function action_AttemptUnauthorizedUpgrade() public {
        vm.prank(ATTACKER);
        target.upgradePreset();
    }

    function invariant_OnlyLegitimateProxyTransitions() public view {
        require(target.invalidTransitions() == 0, "invalid proxy transition accepted");
    }
}

contract SafeUpgradeInvariant is UpgradeInvariantFixture {
    SafeUpgradeProxy internal target;

    function setUp() public {
        ImplementationV1 first = new ImplementationV1();
        ImplementationV2 second = new ImplementationV2();
        target = new SafeUpgradeProxy(ADMIN, address(first), address(second));
        vm.prank(ADMIN);
        target.initializePreset();
    }

    function action_RepeatInitializer() public {
        vm.prank(ATTACKER);
        (bool ok,) = address(target).call(abi.encodeWithSignature("initializePreset()"));
        ok;
    }

    function action_AttemptUnauthorizedUpgrade() public {
        vm.prank(ATTACKER);
        (bool ok,) = address(target).call(abi.encodeWithSignature("upgradePreset()"));
        ok;
    }

    function invariant_OnlyLegitimateProxyTransitions() public view {
        require(target.invalidTransitions() == 0, "invalid proxy transition accepted");
    }
}

contract UpgradeInitializerControls is UpgradeInvariantFixture {
    function _callAs(address actor, address target, string memory signature) internal returns (bool) {
        vm.prank(actor);
        (bool ok,) = target.call(abi.encodeWithSignature(signature));
        return ok;
    }

    function testSafeProxyRejectsRepeatInitializationAndUnauthorizedUpgrade() public {
        ImplementationV1 first = new ImplementationV1();
        ImplementationV2 second = new ImplementationV2();
        SafeUpgradeProxy target = new SafeUpgradeProxy(ADMIN, address(first), address(second));
        require(_callAs(ADMIN, address(target), "initializePreset()"), "initialization failed");
        address initialImplementation = target.implementation();
        require(!_callAs(ATTACKER, address(target), "initializePreset()"), "repeat initialization accepted");
        require(target.owner() == ADMIN, "owner changed after rejected initializer");
        require(!_callAs(ATTACKER, address(target), "upgradePreset()"), "unauthorized upgrade accepted");
        require(target.implementation() == initialImplementation, "implementation changed after rejected upgrade");
    }

    function testAuthorizedUpgradeUsesTheProxyEntryPoint() public {
        ImplementationV1 first = new ImplementationV1();
        ImplementationV2 second = new ImplementationV2();
        SafeUpgradeProxy target = new SafeUpgradeProxy(ADMIN, address(first), address(second));
        require(_callAs(ADMIN, address(target), "initializePreset()"), "initialization failed");
        require(_callAs(ADMIN, address(target), "upgradePreset()"), "authorized upgrade failed");
        require(target.implementation() == address(second), "implementation not updated");
        require(
            IImplementationVersion(address(target)).version() == 2,
            "proxy did not delegate to the upgraded implementation"
        );
    }

    function testUnsafeValidTransitionsDoNotRecordFailure() public {
        ImplementationV1 first = new ImplementationV1();
        ImplementationV2 second = new ImplementationV2();
        UnsafeUpgradeProxy target = new UnsafeUpgradeProxy(ADMIN, address(first), address(second));
        require(_callAs(ADMIN, address(target), "initializePreset()"), "initialization failed");
        require(_callAs(ADMIN, address(target), "upgradePreset()"), "authorized upgrade failed");
        require(target.owner() == ADMIN, "valid owner not retained");
        require(target.invalidTransitions() == 0, "valid transition marked invalid");
        require(IImplementationVersion(address(target)).version() == 2, "valid upgrade path did not delegate");
    }
}
