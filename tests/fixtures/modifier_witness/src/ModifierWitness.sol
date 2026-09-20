// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic, local-only compiler/trace control; no funds or deployment use.
// Invariants: refused bodies do not update count; repeated bodies update twice;
// nested guards resume in order, including when the body returns early.
contract ModifierWitness {
    uint256 public count;
    uint256 public marks;

    constructor() {
        require(block.chainid == 31337 && block.timestamp > 0, "synthetic local only");
    }

    modifier first(bool allowed) {
        require(allowed, "body must stay blocked");
        marks += 1;
        _;
        marks += 10;
    }

    modifier second() {
        marks += 100;
        _;
        marks += 1000;
    }

    modifier repeatBody() {
        _;
        _;
    }

    modifier chooseBody(bool left) {
        if (left) {
            _;
        } else {
            _;
        }
    }

    function single(bool allowed) external first(allowed) {
        count += 1;
    }

    function nested() external first(true) second {
        count += 1;
    }

    function repeated() external repeatBody {
        count += 1;
    }

    function conditional(bool left) external chooseBody(left) {
        count += 1;
    }

    function earlyReturn(bool stop) external first(true) {
        if (stop) {
            return;
        }
        count += 1;
    }

    function empty() external first(true) {}

    function viaHelper() external {
        localHelper();
    }

    function localHelper() internal first(true) {
        count += 1;
    }
}
