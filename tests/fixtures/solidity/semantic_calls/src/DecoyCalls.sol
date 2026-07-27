// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract DecoyCalls {
    function callOne(address target) external {
        target.call("");
    }

    function callTwo(address target) external {
        target.call("");
    }

    function callThree(address target) external {
        target.call("");
    }

    function callFour(address target) external {
        target.call("");
    }

    function callFive(address target) external {
        target.call("");
    }
}
