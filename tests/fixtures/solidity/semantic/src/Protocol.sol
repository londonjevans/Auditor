// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IOracleLike {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract UpgradeProxy {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    address public owner;
    bool public initialized;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address firstOwner) external {
        require(!initialized, "initialized");
        initialized = true;
        owner = firstOwner;
    }

    function upgradeTo(address implementation) external onlyOwner {
        assembly {
            sstore(IMPLEMENTATION_SLOT, implementation)
        }
    }

    fallback() external payable {
        assembly {
            let implementation := sload(IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract SemanticVault {
    mapping(address => uint256) public balances;
    uint256 public totalAssets;
    uint256 public totalSupply;
    bool public paused;
    address public owner;
    IERC20Like public asset;
    IOracleLike public oracle;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
        totalAssets += amount;
        totalSupply += amount;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return totalAssets == 0 ? assets : assets * totalSupply / totalAssets;
    }

    function unsafeWithdraw(uint256 amount) external {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] -= amount;
        totalAssets -= amount;
    }

    function privilegedDrain(address to, uint256 amount) external onlyOwner {
        asset.transfer(to, amount);
    }

    function currentPrice() external view returns (int256 answer) {
        (, answer,,,) = oracle.latestRoundData();
    }

    function setOracle(IOracleLike nextOracle) external onlyOwner {
        oracle = nextOracle;
    }
}
