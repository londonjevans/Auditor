// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/OrderedSettlement.sol";

interface Vm {
    function prank(address sender) external;
}

abstract contract OrderingFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant VICTIM = 0x1000000000000000000000000000000000000003;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }
}

contract UnsafeOrderingInvariant is OrderingFixture {
    UnsafeOrderedSettlement internal target;

    function setUp() public {
        target = new UnsafeOrderedSettlement();
        vm.prank(VICTIM);
        target.stagePreset();
    }

    function action_ReorderSettlement() public {
        target.reorderPreset();
    }

    function invariant_StagedValueBoundPreserved() public view {
        require(target.shortfall(VICTIM) == 0, "staged value bound violated");
    }
}

contract SafeOrderingInvariant is OrderingFixture {
    SafeOrderedSettlement internal target;

    function setUp() public {
        target = new SafeOrderedSettlement();
        vm.prank(VICTIM);
        target.stagePreset();
    }

    function action_ReorderSettlement() public {
        (bool ok,) = address(target).call(abi.encodeWithSignature("reorderPreset()"));
        ok;
    }

    function invariant_StagedValueBoundPreserved() public view {
        require(target.shortfall(VICTIM) == 0, "staged value bound violated");
    }
}

contract OrderingMinimalityControls is OrderingFixture {
    function testStagingAlonePreservesTheBound() public {
        UnsafeOrderedSettlement target = new UnsafeOrderedSettlement();
        vm.prank(VICTIM);
        target.stagePreset();
        require(target.shortfall(VICTIM) == 0, "staging created a shortfall");
    }

    function testOneReorderIsTheMinimalUnsafeTransition() public {
        UnsafeOrderedSettlement target = new UnsafeOrderedSettlement();
        vm.prank(VICTIM);
        target.stagePreset();
        target.reorderPreset();
        require(target.shortfall(VICTIM) > 0, "fixture condition absent");
    }

    function testSafeSettlementRejectsTheIncorrectTransition() public {
        SafeOrderedSettlement target = new SafeOrderedSettlement();
        vm.prank(VICTIM);
        target.stagePreset();
        (bool accepted,) = address(target).call(abi.encodeWithSignature("reorderPreset()"));
        require(!accepted, "unsafe settlement was accepted");
        require(target.shortfall(VICTIM) == 0, "safe control recorded a shortfall");
    }
}
