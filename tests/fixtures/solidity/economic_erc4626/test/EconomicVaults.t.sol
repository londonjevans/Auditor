// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/EconomicVaults.sol";

interface Vm {
    function prank(address) external;
}

contract EconomicVaultsTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SimpleToken internal asset;
    VulnerableInflationVault internal vulnerable;
    PatchedInflationVault internal patched;
    address internal attacker = address(0xA11CE);
    address internal victim = address(0xB0B);

    function setUp() public {
        asset = new SimpleToken();
        vulnerable = new VulnerableInflationVault(asset);
        patched = new PatchedInflationVault(asset);
        asset.mint(attacker, 4 ether);
        asset.mint(victim, 2 ether);
    }

    function testVulnerableDonationInflationRevertsVictimDeposit() public {
        attackerApproveVulnerable();
        victimApproveVulnerable();
        attackerDepositVulnerable(1);
        attackerDonate(address(vulnerable));

        bool ok = victimDepositVulnerable(1 ether);
        require(!ok, "vulnerable vault accepted diluted victim deposit");
    }

    function testPatchedDonationInflationMintsVictimShares() public {
        attackerApprovePatched();
        victimApprovePatched();
        attackerDepositPatched(1);
        attackerDonate(address(patched));

        bool ok = victimDepositPatched(1 ether);
        require(ok, "patched victim deposit failed");
        require(patched.balanceOf(victim) > 0, "patched victim received no shares");
    }

    function attackerApproveVulnerable() internal {
        vm.prank(attacker);
        asset.approve(address(vulnerable), type(uint256).max);
    }

    function victimApproveVulnerable() internal {
        vm.prank(victim);
        asset.approve(address(vulnerable), type(uint256).max);
    }

    function attackerDepositVulnerable(uint256 amount) internal {
        vm.prank(attacker);
        vulnerable.deposit(amount, attacker);
    }

    function victimDepositVulnerable(uint256 amount) internal returns (bool) {
        vm.prank(victim);
        (bool ok,) = address(vulnerable).call(abi.encodeWithSelector(vulnerable.deposit.selector, amount, victim));
        return ok;
    }

    function attackerApprovePatched() internal {
        vm.prank(attacker);
        asset.approve(address(patched), type(uint256).max);
    }

    function victimApprovePatched() internal {
        vm.prank(victim);
        asset.approve(address(patched), type(uint256).max);
    }

    function attackerDepositPatched(uint256 amount) internal {
        vm.prank(attacker);
        patched.deposit(amount, attacker);
    }

    function victimDepositPatched(uint256 amount) internal returns (bool) {
        vm.prank(victim);
        (bool ok,) = address(patched).call(abi.encodeWithSelector(patched.deposit.selector, amount, victim));
        return ok;
    }

    function attackerDonate(address vault) internal {
        vm.prank(attacker);
        asset.transfer(vault, 1 ether);
    }
}

abstract contract ERC4626InvariantFixture {
    Vm internal constant invariantVm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ATTACKER = address(0xA11CE);
    address internal constant VICTIM = address(0xB0B);

    SimpleToken internal invariantAsset;

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(this);
    }

    function _prepare(address vault) internal {
        invariantAsset.mint(ATTACKER, 4 ether);
        invariantAsset.mint(VICTIM, 2 ether);
        invariantVm.prank(ATTACKER);
        invariantAsset.approve(vault, type(uint256).max);
        invariantVm.prank(VICTIM);
        invariantAsset.approve(vault, type(uint256).max);
        invariantVm.prank(ATTACKER);
        (bool seeded,) = vault.call(abi.encodeWithSignature("deposit(uint256,address)", 1, ATTACKER));
        require(seeded, "attacker seed deposit failed");
        invariantVm.prank(ATTACKER);
        invariantAsset.transfer(vault, 1 ether);
    }

    function _victimDeposit(address vault) internal returns (bool) {
        invariantVm.prank(VICTIM);
        (bool ok,) = vault.call(abi.encodeWithSignature("deposit(uint256,address)", 1 ether, VICTIM));
        return ok;
    }
}

contract UnsafeERC4626Invariant is ERC4626InvariantFixture {
    VulnerableInflationVault internal vault;
    bool internal victimDepositAttempted;
    bool internal victimDepositSucceeded;

    function setUp() public {
        invariantAsset = new SimpleToken();
        vault = new VulnerableInflationVault(invariantAsset);
        _prepare(address(vault));
    }

    function action_VictimDeposit() public {
        if (victimDepositAttempted) return;
        victimDepositAttempted = true;
        victimDepositSucceeded = _victimDeposit(address(vault));
    }

    function invariant_VictimDepositMintsShares() public view {
        if (!victimDepositAttempted) return;
        require(victimDepositSucceeded && vault.balanceOf(VICTIM) > 0, "victim deposit did not mint shares");
    }
}

contract SafeERC4626Invariant is ERC4626InvariantFixture {
    PatchedInflationVault internal vault;
    bool internal victimDepositAttempted;
    bool internal victimDepositSucceeded;

    function setUp() public {
        invariantAsset = new SimpleToken();
        vault = new PatchedInflationVault(invariantAsset);
        _prepare(address(vault));
    }

    function action_VictimDeposit() public {
        if (victimDepositAttempted) return;
        victimDepositAttempted = true;
        victimDepositSucceeded = _victimDeposit(address(vault));
    }

    function invariant_VictimDepositMintsShares() public view {
        if (!victimDepositAttempted) return;
        require(victimDepositSucceeded && vault.balanceOf(VICTIM) > 0, "victim deposit did not mint shares");
    }
}

contract ERC4626MinimalityControls is ERC4626InvariantFixture {
    function testSetupAloneDoesNotPerformVictimTransition() public {
        invariantAsset = new SimpleToken();
        VulnerableInflationVault vault = new VulnerableInflationVault(invariantAsset);
        _prepare(address(vault));
        require(vault.balanceOf(VICTIM) == 0, "setup unexpectedly minted victim shares");
    }

    function testOneVictimDepositIsMinimalUnsafeTransition() public {
        invariantAsset = new SimpleToken();
        VulnerableInflationVault vault = new VulnerableInflationVault(invariantAsset);
        _prepare(address(vault));
        bool ok = _victimDeposit(address(vault));
        require(!ok && vault.balanceOf(VICTIM) == 0, "unsafe condition was not reached");
    }

    function testSafeOneVictimDepositMintsShares() public {
        invariantAsset = new SimpleToken();
        PatchedInflationVault vault = new PatchedInflationVault(invariantAsset);
        _prepare(address(vault));
        bool ok = _victimDeposit(address(vault));
        require(ok && vault.balanceOf(VICTIM) > 0, "safe transition did not mint shares");
    }
}
