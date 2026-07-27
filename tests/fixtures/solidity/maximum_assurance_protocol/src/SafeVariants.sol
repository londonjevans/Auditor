// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface ISafeToken {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IFreshPrice {
    function latestPrice() external view returns (uint256 price, uint256 updatedAt);
}

contract SafeAccessVault {
    address public immutable owner = msg.sender;

    function rescue(address payable receiver, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        (bool sent,) = receiver.call{value: amount}("");
        require(sent, "transfer failed");
    }
}

contract SafeReentrantBank {
    mapping(address => uint256) public balances;
    bool private entered;

    function withdraw(uint256 amount) external {
        require(!entered, "reentrant");
        require(balances[msg.sender] >= amount, "balance");
        entered = true;
        balances[msg.sender] -= amount;
        (bool sent,) = payable(msg.sender).call{value: amount}("");
        require(sent, "transfer failed");
        entered = false;
    }
}

contract SafeOracleLender {
    IFreshPrice public immutable oracle;
    uint256 public constant MAX_AGE = 30 minutes;

    constructor(IFreshPrice configuredOracle) {
        require(address(configuredOracle) != address(0), "oracle");
        oracle = configuredOracle;
    }

    function collateralValue(uint256 collateral) external view returns (uint256) {
        (uint256 price, uint256 updatedAt) = oracle.latestPrice();
        require(price > 0 && updatedAt <= block.timestamp, "invalid price");
        require(block.timestamp - updatedAt <= MAX_AGE, "stale price");
        return collateral * price / 1e18;
    }
}

contract SafeUUPSAuthorization {
    address public immutable upgradeAdmin = msg.sender;
    address public implementation;

    function upgradeTo(address nextImplementation) external {
        require(msg.sender == upgradeAdmin, "not upgrade admin");
        require(nextImplementation.code.length > 0, "not contract");
        implementation = nextImplementation;
    }
}

contract SafeReplayClaim {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public claimed;

    function claim(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        uint256 nonce = nonces[msg.sender]++;
        bytes32 digest =
            keccak256(abi.encode(block.chainid, address(this), msg.sender, amount, nonce, deadline));
        require(ecrecover(digest, v, r, s) != address(0), "signature");
        claimed[msg.sender] += amount;
    }
}

contract SafeInflationVault {
    uint256 private constant VIRTUAL_ASSETS = 1;
    uint256 private constant VIRTUAL_SHARES = 1e6;
    uint256 public totalAssets;
    uint256 public totalSupply;

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + VIRTUAL_SHARES) / (totalAssets + VIRTUAL_ASSETS);
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        require(shares > 0, "zero shares");
        totalAssets += assets;
        totalSupply += shares;
    }
}

contract SafeRewardClaim {
    mapping(address => uint256) public entitlement;

    function claim() external {
        uint256 amount = entitlement[msg.sender];
        require(amount > 0, "nothing to claim");
        entitlement[msg.sender] = 0;
        (bool sent,) = payable(msg.sender).call{value: amount}("");
        require(sent, "transfer failed");
    }
}

contract SafeLiquidation {
    mapping(address => uint256) public debt;
    mapping(address => uint256) public collateral;

    function liquidate(address user) external {
        require(debt[user] > collateral[user], "healthy");
        uint256 seized = collateral[user];
        collateral[user] = 0;
        collateral[msg.sender] += seized;
    }
}

contract SafeFixedDelegate {
    address public immutable implementation;

    constructor(address trustedImplementation) {
        require(trustedImplementation.code.length > 0, "not contract");
        implementation = trustedImplementation;
    }

    fallback() external payable {
        (bool ok, bytes memory result) = implementation.delegatecall(msg.data);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}

contract SafeInitializer {
    address public owner;
    bool private initialized;

    function initialize(address newOwner) external {
        require(!initialized, "initialized");
        require(newOwner != address(0), "owner");
        initialized = true;
        owner = newOwner;
    }
}

contract SafeRoundingPool {
    uint256 public index = 1e18;

    function quote(uint256 amount, uint256 scale) external view returns (uint256) {
        require(scale != 0, "scale");
        return amount * index / scale;
    }
}

contract SafeFeeTokenVault {
    ISafeToken public immutable asset;
    mapping(address => uint256) public credit;

    constructor(ISafeToken configuredAsset) {
        asset = configuredAsset;
    }

    function deposit(uint256 amount) external {
        uint256 beforeBalance = asset.balanceOf(address(this));
        require(asset.transferFrom(msg.sender, address(this), amount), "transfer");
        uint256 received = asset.balanceOf(address(this)) - beforeBalance;
        require(received > 0, "no assets");
        credit[msg.sender] += received;
    }
}
