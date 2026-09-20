// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ModifierControl} from "../src/ModifierControl.sol";

// Synthetic named state invariants; execution stays in the disposable local VM.
contract ModifierControlTest {
    function test_invariant_blocked_transition_preserves_counter() public {
        ModifierControl control = new ModifierControl();
        try control.advance(false) {
            revert("blocked transition was not refused");
        } catch {}
        require(control.counter() == 0, "blocked transition changed the counter");
    }

    function test_invariant_permitted_transition_increments_once() public {
        ModifierControl control = new ModifierControl();
        control.advance(true);
        require(control.counter() == 1, "permitted transition did not increment exactly once");
    }
}
