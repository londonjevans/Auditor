// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ModifierControl} from "../src/ModifierControl.sol";

// Synthetic non-production harness, copied beside the coverage_compilation fixture.
// Named invariant: the permitted transition increments once; a refused transition
// leaves the counter unchanged. No funds, private inputs, live network or FFI.
contract PopulationControlTest {
    function test_invariant_unit_transition_increments_once() public {
        ModifierControl control = new ModifierControl();
        control.advance(true);
        require(control.counter() == 1, "permitted transition did not increment once");
    }

    function testFuzz_invariant_transition_matches_permission(bool allowed) public {
        ModifierControl control = new ModifierControl();
        if (allowed) {
            control.advance(true);
            require(control.counter() == 1, "permitted transition did not increment once");
        } else {
            try control.advance(false) {
                revert("blocked transition was not refused");
            } catch {}
            require(control.counter() == 0, "blocked transition changed the counter");
        }
    }
}
