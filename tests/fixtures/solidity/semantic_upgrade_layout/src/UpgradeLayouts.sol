// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract BaseAccessStorage {
    address public owner;
}

contract LayoutV1 is BaseAccessStorage {
    uint128 public fee;
    uint128 public limit;
    uint256[48] private __gap;

    function initialize(address firstOwner) external {
        owner = firstOwner;
    }
}

contract LayoutV2Safe is BaseAccessStorage {
    uint128 public fee;
    uint128 public limit;
    uint256 public newValue;
    uint256[47] private __gap;

    modifier initializer() {
        _;
    }

    function initialize(address firstOwner) external initializer {
        owner = firstOwner;
    }
}

contract LayoutV2Unsafe is BaseAccessStorage {
    uint256 public newValue;
    uint128 public fee;
    uint128 public limit;
    uint256[47] private __gap;

    function initialize(address firstOwner) external {
        owner = firstOwner;
    }
}

contract LocalProxy {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant ADMIN_SLOT = keccak256("mmaudit.synthetic.proxy.admin");

    fallback() external payable {
        assembly {
            let implementation := sload(IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}
