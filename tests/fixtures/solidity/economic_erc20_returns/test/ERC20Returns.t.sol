// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "../src/ERC20Returns.sol";

interface Vm {
    function prank(address) external;
}

abstract contract ERC20ReturnFixture {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ACTOR = address(0xA11CE);
    uint256 internal constant AMOUNT = 100 ether;

    SyntheticReturnToken internal token;

    function _configure(SyntheticReturnToken.ReturnMode mode) internal {
        token = new SyntheticReturnToken();
        token.setMode(mode);
        token.mint(ACTOR, AMOUNT);
    }

    function _approve(address vault) internal {
        vm.prank(ACTOR);
        token.approve(vault, AMOUNT);
    }

    function _deposit(address vault) internal returns (bool) {
        vm.prank(ACTOR);
        (bool ok,) = vault.call(abi.encodeWithSignature("deposit(uint256)", AMOUNT));
        return ok;
    }
}

contract UnsafeFalseReturnInvariant is ERC20ReturnFixture {
    UnsafeUncheckedReturnVault internal vault;

    function setUp() public {
        _configure(SyntheticReturnToken.ReturnMode.FalseReturn);
        vault = new UnsafeUncheckedReturnVault(token);
        _approve(address(vault));
        require(_deposit(address(vault)), "fixture deposit");
    }

    function invariant_ERC20ReturnOutcomePreservesAccounting() public view {
        require(
            token.balanceOf(address(vault)) >= vault.claimable(ACTOR),
            "unchecked false return created an unbacked claim"
        );
    }
}

contract UnsafeShortReturnInvariant is ERC20ReturnFixture {
    UnsafeUncheckedReturnVault internal vault;

    function setUp() public {
        _configure(SyntheticReturnToken.ReturnMode.ShortReturn);
        vault = new UnsafeUncheckedReturnVault(token);
        _approve(address(vault));
        require(_deposit(address(vault)), "fixture deposit");
    }

    function invariant_ERC20ReturnOutcomePreservesAccounting() public view {
        require(
            token.balanceOf(address(vault)) >= vault.claimable(ACTOR),
            "unchecked short return created an unbacked claim"
        );
    }
}

abstract contract SafeReturnInvariant is ERC20ReturnFixture {
    SafeReturnCheckedVault internal vault;

    function invariant_ERC20ReturnOutcomePreservesAccounting() public view {
        require(token.balanceOf(address(vault)) >= vault.claimable(ACTOR), "safe accounting diverged");
    }
}

contract SafeMissingReturnInvariant is SafeReturnInvariant {
    function setUp() public {
        _configure(SyntheticReturnToken.ReturnMode.MissingReturn);
        vault = new SafeReturnCheckedVault(token);
        _approve(address(vault));
        require(_deposit(address(vault)), "compatible empty return was rejected");
    }
}

contract SafeFalseReturnInvariant is SafeReturnInvariant {
    function setUp() public {
        _configure(SyntheticReturnToken.ReturnMode.FalseReturn);
        vault = new SafeReturnCheckedVault(token);
        _approve(address(vault));
        require(!_deposit(address(vault)), "false return was accepted");
    }
}

contract SafeShortReturnInvariant is SafeReturnInvariant {
    function setUp() public {
        _configure(SyntheticReturnToken.ReturnMode.ShortReturn);
        vault = new SafeReturnCheckedVault(token);
        _approve(address(vault));
        require(!_deposit(address(vault)), "short return was accepted");
    }
}

contract ERC20ReturnMinimalityControls is ERC20ReturnFixture {
    function testTrueReturnMovesAssetsBeforeCredit() public {
        _configure(SyntheticReturnToken.ReturnMode.TrueReturn);
        UnsafeUncheckedReturnVault vault = new UnsafeUncheckedReturnVault(token);
        _approve(address(vault));
        require(_deposit(address(vault)), "standard return rejected");
        require(token.balanceOf(address(vault)) == vault.claimable(ACTOR), "unexpected gap");
    }

    function testMissingReturnMovesAssetsBeforeCredit() public {
        _configure(SyntheticReturnToken.ReturnMode.MissingReturn);
        UnsafeUncheckedReturnVault vault = new UnsafeUncheckedReturnVault(token);
        _approve(address(vault));
        require(_deposit(address(vault)), "empty return rejected");
        require(token.balanceOf(address(vault)) == vault.claimable(ACTOR), "unexpected gap");
    }
}
