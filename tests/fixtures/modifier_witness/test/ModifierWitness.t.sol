// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ModifierWitness} from "../src/ModifierWitness.sol";

// Non-production named-invariant controls, only for the disposable local EVM.
contract ModifierWitnessTest {
    function test_single_allowed() public {
        ModifierWitness target = new ModifierWitness();
        target.single(true);
        require(target.count() == 1 && target.marks() == 11, "single body/resume invariant");
    }

    function test_single_blocked() public {
        ModifierWitness target = new ModifierWitness();
        try target.single(false) {
            revert("blocked body unexpectedly completed");
        } catch {}
        require(target.count() == 0 && target.marks() == 0, "refusal preserves state invariant");
    }

    function test_nested() public {
        ModifierWitness target = new ModifierWitness();
        target.nested();
        require(target.count() == 1 && target.marks() == 1111, "nested resume invariant");
    }

    function test_repeated() public {
        ModifierWitness target = new ModifierWitness();
        target.repeated();
        require(target.count() == 2 && target.marks() == 0, "two body invocations invariant");
    }

    function test_conditional_left() public {
        ModifierWitness target = new ModifierWitness();
        target.conditional(true);
        require(target.count() == 1, "left body exactly once invariant");
    }

    function test_conditional_right() public {
        ModifierWitness target = new ModifierWitness();
        target.conditional(false);
        require(target.count() == 1, "right body exactly once invariant");
    }

    function test_early_return() public {
        ModifierWitness target = new ModifierWitness();
        target.earlyReturn(true);
        require(target.count() == 0 && target.marks() == 11, "early return resumes modifier invariant");
    }

    function test_empty() public {
        ModifierWitness target = new ModifierWitness();
        target.empty();
        require(target.count() == 0 && target.marks() == 11, "empty body resumes modifier invariant");
    }

    function test_internal() public {
        ModifierWitness target = new ModifierWitness();
        target.viaHelper();
        require(target.count() == 1 && target.marks() == 11, "internal guarded body invariant");
    }
}
