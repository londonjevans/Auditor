// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../src/Vault.sol";

contract VaultAuditTest {
    Vault internal vault;

    function setUp() public {
        vault = new Vault();
    }

    function testWithdrawRequiresOwner() public {
        vault.withdraw(1 ether);
    }
}

