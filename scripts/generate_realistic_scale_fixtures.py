"""Generate deterministic, non-deployable Solidity scale fixtures.

The generated repositories are intentionally synthetic. They contain no deployment
scripts, chain endpoints, credentials, copied production source, or executable
artifacts. Use ``--write`` to refresh the committed golden trees; the default mode
only verifies that committed bytes match this generator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

GENERATOR_VERSION = "1.0.0"
GENERATOR_REPOSITORY_PATH = "scripts/generate_realistic_scale_fixtures.py"
DEFAULT_OUTPUT_ROOT = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "solidity" / "realistic_scale"
)
MANIFEST_NAME = "fixture-manifest.json"
CORPUS_MANIFEST_NAME = "manifest.json"
TARGET_TOLERANCE_BASIS_POINTS = 250
REQUIRED_GRAPH_KINDS = (
    "asset_flow",
    "delegatecall",
    "external_call",
    "initializer",
    "oracle_dependency",
    "privilege",
    "proxy",
    "state_write",
)


@dataclass(frozen=True, slots=True)
class ScaleProfile:
    """One reproducible scale target."""

    fixture_id: str
    target_solidity_lines: int
    module_count: int


PROFILES = (
    ScaleProfile("solidity_005k", 5_000, 15),
    ScaleProfile("solidity_015k", 15_000, 48),
    ScaleProfile("solidity_035k", 35_000, 114),
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _text(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode("utf-8")


def _foundry_configuration() -> bytes:
    return _text(
        "[profile.default]",
        'src = "src"',
        'test = "test"',
        'solc_version = "0.8.30"',
        "optimizer = false",
        "offline = true",
        "ffi = false",
    )


def _interfaces_source() -> bytes:
    return _text(
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity 0.8.30;",
        "",
        "// Synthetic fixture only. This original test protocol is not production source.",
        "interface ISyntheticScaleAsset {",
        "    function balanceOf(address account) external view returns (uint256);",
        "",
        "    function transfer(address receiver, uint256 amount) external returns (bool);",
        "",
        "    function transferFrom(",
        "        address sender,",
        "        address receiver,",
        "        uint256 amount",
        "    ) external returns (bool);",
        "}",
        "",
        "interface ISyntheticScaleOracle {",
        "    function latestPrice(",
        "        bytes32 marketId",
        "    ) external view returns (uint256 price, uint64 updatedAt, bool valid);",
        "}",
        "",
        "interface ISyntheticScaleStrategy {",
        "    function allocate(",
        "        address asset,",
        "        uint256 amount",
        "    ) external returns (uint256 accepted);",
        "",
        "    function withdraw(",
        "        address asset,",
        "        uint256 amount,",
        "        address receiver",
        "    ) external returns (uint256 returnedAssets);",
        "",
        "    function managedAssets(address asset) external view returns (uint256);",
        "}",
        "",
        "// Synthetic beacon-shaped dependency used only by proxy graph fixtures.",
        "interface ISyntheticScaleBeacon {",
        "    function implementation() external view returns (address);",
        "}",
        "",
        "interface ISyntheticScaleMarket {",
        "    function depositFor(address receiver, uint256 assets) external returns (uint256);",
        "",
        "    function redeemFor(address receiver, uint256 shares) external returns (uint256);",
        "",
        "    function totalAssets() external view returns (uint256);",
        "}",
    )


def _fixture_only_source() -> bytes:
    return _text(
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity 0.8.30;",
        "",
        "// Synthetic fixture only. Every inheriting contract is intentionally non-deployable.",
        "abstract contract SyntheticFixtureOnly {",
        "    error SyntheticFixtureCannotDeploy();",
        "",
        "    constructor() {",
        "        revert SyntheticFixtureCannotDeploy();",
        "    }",
        "}",
        "",
        "abstract contract SyntheticAccess is SyntheticFixtureOnly {",
        "    error AlreadyInitialized();",
        "    error InvalidSyntheticAddress();",
        "    error PausedSyntheticMarket();",
        "    error UnauthorizedSyntheticActor();",
        "",
        "    address internal _governor;",
        "    mapping(address guardian => bool approved) internal _guardians;",
        "    bool internal _paused;",
        "",
        "    event GovernorChanged(address indexed previousGovernor, address indexed newGovernor);",
        "    event GuardianSet(address indexed guardian, bool approved);",
        "    event PauseStateChanged(bool paused);",
        "",
        "    modifier onlyGovernor() {",
        "        if (msg.sender != _governor) revert UnauthorizedSyntheticActor();",
        "        _;",
        "    }",
        "",
        "    modifier onlyGuardian() {",
        "        if (!_guardians[msg.sender]) revert UnauthorizedSyntheticActor();",
        "        _;",
        "    }",
        "",
        "    modifier whenActive() {",
        "        if (_paused) revert PausedSyntheticMarket();",
        "        _;",
        "    }",
        "",
        "    function _initializeSyntheticAccess(address governor_) internal {",
        "        if (_governor != address(0)) revert AlreadyInitialized();",
        "        if (governor_ == address(0)) revert InvalidSyntheticAddress();",
        "        _governor = governor_;",
        "        emit GovernorChanged(address(0), governor_);",
        "    }",
        "",
        "    function governor() external view returns (address) {",
        "        return _governor;",
        "    }",
        "",
        "    function isGuardian(address account) external view returns (bool) {",
        "        return _guardians[account];",
        "    }",
        "",
        "    function setGuardian(address guardian, bool approved) external onlyGovernor {",
        "        if (guardian == address(0)) revert InvalidSyntheticAddress();",
        "        _guardians[guardian] = approved;",
        "        emit GuardianSet(guardian, approved);",
        "    }",
        "",
        "    function transferGovernor(address nextGovernor) external onlyGovernor {",
        "        if (nextGovernor == address(0)) revert InvalidSyntheticAddress();",
        "        address previous = _governor;",
        "        _governor = nextGovernor;",
        "        emit GovernorChanged(previous, nextGovernor);",
        "    }",
        "",
        "    function pause() external onlyGuardian {",
        "        _paused = true;",
        "        emit PauseStateChanged(true);",
        "    }",
        "",
        "    function unpause() external onlyGovernor {",
        "        _paused = false;",
        "        emit PauseStateChanged(false);",
        "    }",
        "}",
        "",
        "abstract contract SyntheticAccounting is SyntheticAccess {",
        "    error InsufficientSyntheticBalance();",
        "    error InvalidSyntheticAmount();",
        "",
        "    mapping(address account => uint256 shares) internal _shareBalance;",
        "    uint256 internal _totalShares;",
        "    uint256 internal _totalManagedAssets;",
        "",
        "    event SyntheticSharesMinted(address indexed receiver, uint256 assets, uint256 shares);",
        "    event SyntheticSharesBurned(address indexed owner, uint256 assets, uint256 shares);",
        "",
        "    function _convertToShares(uint256 assets) internal view returns (uint256) {",
        "        if (assets == 0) revert InvalidSyntheticAmount();",
        "        if (_totalShares == 0 || _totalManagedAssets == 0) return assets;",
        "        return assets * _totalShares / _totalManagedAssets;",
        "    }",
        "",
        "    function _convertToAssets(uint256 shares) internal view returns (uint256) {",
        "        if (shares == 0) revert InvalidSyntheticAmount();",
        "        if (_totalShares == 0 || _totalManagedAssets == 0) return shares;",
        "        return shares * _totalManagedAssets / _totalShares;",
        "    }",
        "",
        "    function _mintSyntheticShares(",
        "        address receiver,",
        "        uint256 assets",
        "    ) internal returns (uint256 shares) {",
        "        shares = _convertToShares(assets);",
        "        _shareBalance[receiver] += shares;",
        "        _totalShares += shares;",
        "        _totalManagedAssets += assets;",
        "        emit SyntheticSharesMinted(receiver, assets, shares);",
        "    }",
        "",
        "    function _burnSyntheticShares(",
        "        address owner,",
        "        uint256 shares",
        "    ) internal returns (uint256 assets) {",
        "        if (_shareBalance[owner] < shares) revert InsufficientSyntheticBalance();",
        "        assets = _convertToAssets(shares);",
        "        _shareBalance[owner] -= shares;",
        "        _totalShares -= shares;",
        "        _totalManagedAssets -= assets;",
        "        emit SyntheticSharesBurned(owner, assets, shares);",
        "    }",
        "",
        "    function shareBalance(address account) external view returns (uint256) {",
        "        return _shareBalance[account];",
        "    }",
        "",
        "    function totalShares() external view returns (uint256) {",
        "        return _totalShares;",
        "    }",
        "}",
    )


def _proxies_source() -> bytes:
    return _text(
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity 0.8.30;",
        "",
        'import {SyntheticAccess} from "./SyntheticFixtureOnly.sol";',
        "",
        "// Synthetic fixture only. These reverting-base proxies cannot be deployed.",
        "abstract contract SyntheticTransparentProxy is SyntheticAccess {",
        "    bytes32 internal constant IMPLEMENTATION_SLOT =",
        '        keccak256("mmaudit.synthetic.scale.proxy.implementation");',
        "    address internal _implementation;",
        "",
        "    event SyntheticImplementationChanged(",
        "        address indexed previousImplementation,",
        "        address indexed nextImplementation",
        "    );",
        "",
        "    function implementation() external view returns (address) {",
        "        return _implementation;",
        "    }",
        "",
        "    function initializeProxy(",
        "        address governor_,",
        "        address implementation_",
        "    ) external {",
        "        _initializeSyntheticAccess(governor_);",
        "        _setSyntheticImplementation(implementation_);",
        "    }",
        "",
        "    function upgradeTo(address nextImplementation) external onlyGovernor {",
        "        _setSyntheticImplementation(nextImplementation);",
        "    }",
        "",
        "    function _setSyntheticImplementation(address nextImplementation) internal {",
        "        if (nextImplementation == address(0)) revert InvalidSyntheticAddress();",
        "        address previous = _implementation;",
        "        _implementation = nextImplementation;",
        "        emit SyntheticImplementationChanged(previous, nextImplementation);",
        "    }",
        "",
        "    fallback() external payable {",
        "        address target = _implementation;",
        "        assembly {",
        "            calldatacopy(0, 0, calldatasize())",
        "            let result := delegatecall(gas(), target, 0, calldatasize(), 0, 0)",
        "            returndatacopy(0, 0, returndatasize())",
        "            switch result",
        "            case 0 { revert(0, returndatasize()) }",
        "            default { return(0, returndatasize()) }",
        "        }",
        "    }",
        "",
        "    receive() external payable {}",
        "}",
        "",
        "abstract contract SyntheticBeaconProxy is SyntheticAccess {",
        "    address internal _beacon;",
        "",
        "    event SyntheticBeaconChanged(address indexed previousBeacon, address indexed nextBeacon);",
        "",
        "    function initializeBeaconProxy(address governor_, address beacon_) external {",
        "        _initializeSyntheticAccess(governor_);",
        "        _setSyntheticBeacon(beacon_);",
        "    }",
        "",
        "    function setBeacon(address nextBeacon) external onlyGovernor {",
        "        _setSyntheticBeacon(nextBeacon);",
        "    }",
        "",
        "    function beacon() external view returns (address) {",
        "        return _beacon;",
        "    }",
        "",
        "    function _setSyntheticBeacon(address nextBeacon) internal {",
        "        if (nextBeacon == address(0)) revert InvalidSyntheticAddress();",
        "        address previous = _beacon;",
        "        _beacon = nextBeacon;",
        "        emit SyntheticBeaconChanged(previous, nextBeacon);",
        "    }",
        "}",
    )


def _registry_source() -> bytes:
    return _text(
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity 0.8.30;",
        "",
        'import {ISyntheticScaleMarket} from "./Interfaces.sol";',
        'import {SyntheticAccess} from "./SyntheticFixtureOnly.sol";',
        "",
        "// Synthetic fixture only. This registry has no deployable production target.",
        "abstract contract SyntheticProtocolRegistry is SyntheticAccess {",
        "    mapping(bytes32 marketId => address market) internal _markets;",
        "    mapping(bytes32 marketId => address oracle) internal _oracles;",
        "    mapping(bytes32 marketId => address strategy) internal _strategies;",
        "",
        "    event SyntheticMarketRegistered(bytes32 indexed marketId, address indexed market);",
        "    event SyntheticOracleRegistered(bytes32 indexed marketId, address indexed oracle);",
        "    event SyntheticStrategyRegistered(bytes32 indexed marketId, address indexed strategy);",
        "",
        "    function initializeRegistry(address governor_) external {",
        "        _initializeSyntheticAccess(governor_);",
        "    }",
        "",
        "    function setMarket(bytes32 marketId, address market_) external onlyGovernor {",
        "        if (market_ == address(0)) revert InvalidSyntheticAddress();",
        "        _markets[marketId] = market_;",
        "        emit SyntheticMarketRegistered(marketId, market_);",
        "    }",
        "",
        "    function setOracle(bytes32 marketId, address oracle_) external onlyGovernor {",
        "        if (oracle_ == address(0)) revert InvalidSyntheticAddress();",
        "        _oracles[marketId] = oracle_;",
        "        emit SyntheticOracleRegistered(marketId, oracle_);",
        "    }",
        "",
        "    function setStrategy(bytes32 marketId, address strategy_) external onlyGovernor {",
        "        if (strategy_ == address(0)) revert InvalidSyntheticAddress();",
        "        _strategies[marketId] = strategy_;",
        "        emit SyntheticStrategyRegistered(marketId, strategy_);",
        "    }",
        "",
        "    function routeDeposit(",
        "        bytes32 marketId,",
        "        address receiver,",
        "        uint256 assets",
        "    ) external whenActive returns (uint256 shares) {",
        "        address marketAddress_ = _markets[marketId];",
        "        if (marketAddress_ == address(0)) revert InvalidSyntheticAddress();",
        "        shares = ISyntheticScaleMarket(marketAddress_).depositFor(receiver, assets);",
        "    }",
        "",
        "    function routeRedemption(",
        "        bytes32 marketId,",
        "        address receiver,",
        "        uint256 shares",
        "    ) external whenActive returns (uint256 assets) {",
        "        address marketAddress_ = _markets[marketId];",
        "        if (marketAddress_ == address(0)) revert InvalidSyntheticAddress();",
        "        assets = ISyntheticScaleMarket(marketAddress_).redeemFor(receiver, shares);",
        "    }",
        "",
        "    function marketAddress(bytes32 marketId) external view returns (address) {",
        "        return _markets[marketId];",
        "    }",
        "",
        "    function oracleAddress(bytes32 marketId) external view returns (address) {",
        "        return _oracles[marketId];",
        "    }",
        "",
        "    function strategyAddress(bytes32 marketId) external view returns (address) {",
        "        return _strategies[marketId];",
        "    }",
        "}",
    )


def _market_source(index: int) -> bytes:
    suffix = f"{index:03d}"
    market_name = f"SyntheticMarket{suffix}"
    market_label = f"mmaudit-synthetic-market-{suffix}"
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity 0.8.30;",
        "",
        "import {",
        "    ISyntheticScaleAsset,",
        "    ISyntheticScaleMarket,",
        "    ISyntheticScaleOracle,",
        "    ISyntheticScaleStrategy",
        '} from "../core/Interfaces.sol";',
        'import {SyntheticAccounting} from "../core/SyntheticFixtureOnly.sol";',
        "",
        "// Synthetic fixture only. This original market is intentionally non-deployable.",
        f"abstract contract {market_name} is SyntheticAccounting, ISyntheticScaleMarket {{",
        f'    bytes32 public constant MARKET_ID = keccak256("{market_label}");',
        "    uint256 public constant SCALE = 1e18;",
        "",
        "    struct Position {",
        "        uint128 collateral;",
        "        uint128 debt;",
        "        uint64 lastAccrual;",
        "        bool liquidationPending;",
        "    }",
        "",
        "    ISyntheticScaleAsset internal _asset;",
        "    ISyntheticScaleOracle internal _oracle;",
        "    ISyntheticScaleStrategy internal _strategy;",
        "    mapping(address account => Position position) internal _positions;",
        "    uint256 internal _borrowIndex;",
        "    uint256 internal _feeRate;",
        "    uint256 internal _maximumStaleness;",
        "    uint256 internal _strategyDebt;",
        "",
        "    event SyntheticDeposit(address indexed caller, address indexed receiver, uint256 assets);",
        "    event SyntheticRedemption(address indexed owner, address indexed receiver, uint256 shares);",
        "    event SyntheticBorrow(address indexed account, uint256 amount);",
        "    event SyntheticRepayment(address indexed account, uint256 amount);",
        "    event SyntheticLiquidation(address indexed account, uint256 repaid, uint256 collateral);",
        "    event SyntheticStrategyAllocation(uint256 requested, uint256 accepted);",
        "    event SyntheticOracleUpdated(address indexed oracle);",
        "",
        "    function initializeMarket(",
        "        address governor_,",
        "        ISyntheticScaleAsset asset_,",
        "        ISyntheticScaleOracle oracle_,",
        "        ISyntheticScaleStrategy strategy_",
        "    ) external {",
        "        _initializeSyntheticAccess(governor_);",
        "        if (address(asset_) == address(0)) revert InvalidSyntheticAddress();",
        "        if (address(oracle_) == address(0)) revert InvalidSyntheticAddress();",
        "        if (address(strategy_) == address(0)) revert InvalidSyntheticAddress();",
        "        _asset = asset_;",
        "        _oracle = oracle_;",
        "        _strategy = strategy_;",
        "        _borrowIndex = SCALE;",
        "        _feeRate = 5e15;",
        "        _maximumStaleness = 1 hours;",
        "    }",
        "",
        "    function deposit(uint256 assets, address receiver)",
        "        external",
        "        whenActive",
        "        returns (uint256 shares)",
        "    {",
        "        shares = _depositFrom(msg.sender, receiver, assets);",
        "    }",
        "",
        "    function depositFor(",
        "        address receiver,",
        "        uint256 assets",
        "    ) external whenActive returns (uint256 shares) {",
        "        shares = _depositFrom(msg.sender, receiver, assets);",
        "    }",
        "",
        "    function _depositFrom(",
        "        address sender,",
        "        address receiver,",
        "        uint256 assets",
        "    ) internal returns (uint256 shares) {",
        "        if (!_asset.transferFrom(sender, address(this), assets)) {",
        "            revert InvalidSyntheticAmount();",
        "        }",
        "        shares = _mintSyntheticShares(receiver, assets);",
        "        _positions[receiver].collateral += uint128(assets);",
        "        emit SyntheticDeposit(sender, receiver, assets);",
        "    }",
        "",
        "    function redeem(uint256 shares, address receiver)",
        "        external",
        "        whenActive",
        "        returns (uint256 assets)",
        "    {",
        "        assets = _redeemFrom(msg.sender, receiver, shares);",
        "    }",
        "",
        "    function redeemFor(",
        "        address receiver,",
        "        uint256 shares",
        "    ) external whenActive returns (uint256 assets) {",
        "        assets = _redeemFrom(msg.sender, receiver, shares);",
        "    }",
        "",
        "    function _redeemFrom(",
        "        address owner,",
        "        address receiver,",
        "        uint256 shares",
        "    ) internal returns (uint256 assets) {",
        "        assets = _burnSyntheticShares(owner, shares);",
        "        if (!_asset.transfer(receiver, assets)) revert InvalidSyntheticAmount();",
        "        emit SyntheticRedemption(owner, receiver, shares);",
        "    }",
        "",
        "    function borrow(uint256 amount) external whenActive {",
        "        (uint256 price, uint64 updatedAt, bool valid) = _oracle.latestPrice(MARKET_ID);",
        "        if (!valid || price == 0) revert InvalidSyntheticAmount();",
        "        if (block.timestamp > uint256(updatedAt) + _maximumStaleness) {",
        "            revert InvalidSyntheticAmount();",
        "        }",
        "        Position storage position = _positions[msg.sender];",
        "        if (uint256(position.collateral) * price / SCALE < amount * 2) {",
        "            revert InsufficientSyntheticBalance();",
        "        }",
        "        position.debt += uint128(amount);",
        "        if (!_asset.transfer(msg.sender, amount)) revert InvalidSyntheticAmount();",
        "        emit SyntheticBorrow(msg.sender, amount);",
        "    }",
        "",
        "    function repay(uint256 amount) external whenActive {",
        "        Position storage position = _positions[msg.sender];",
        "        if (amount > position.debt) amount = position.debt;",
        "        if (!_asset.transferFrom(msg.sender, address(this), amount)) {",
        "            revert InvalidSyntheticAmount();",
        "        }",
        "        position.debt -= uint128(amount);",
        "        emit SyntheticRepayment(msg.sender, amount);",
        "    }",
        "",
        "    function markLiquidation(address account) external onlyGuardian {",
        "        _positions[account].liquidationPending = true;",
        "    }",
        "",
        "    function settleLiquidation(",
        "        address account,",
        "        uint256 repayment",
        "    ) external whenActive returns (uint256 collateralReleased) {",
        "        Position storage position = _positions[account];",
        "        if (!position.liquidationPending) revert UnauthorizedSyntheticActor();",
        "        if (!_asset.transferFrom(msg.sender, address(this), repayment)) {",
        "            revert InvalidSyntheticAmount();",
        "        }",
        "        uint256 boundedRepayment = repayment > position.debt ? position.debt : repayment;",
        "        position.debt -= uint128(boundedRepayment);",
        "        collateralReleased = boundedRepayment * 11 / 10;",
        "        if (collateralReleased > position.collateral) {",
        "            collateralReleased = position.collateral;",
        "        }",
        "        position.collateral -= uint128(collateralReleased);",
        "        position.liquidationPending = false;",
        "        if (!_asset.transfer(msg.sender, collateralReleased)) {",
        "            revert InvalidSyntheticAmount();",
        "        }",
        "        emit SyntheticLiquidation(account, boundedRepayment, collateralReleased);",
        "    }",
        "",
        "    function allocateToStrategy(uint256 amount) external onlyGovernor whenActive {",
        "        if (!_asset.transfer(address(_strategy), amount)) revert InvalidSyntheticAmount();",
        "        uint256 accepted = _strategy.allocate(address(_asset), amount);",
        "        _strategyDebt += accepted;",
        "        emit SyntheticStrategyAllocation(amount, accepted);",
        "    }",
        "",
        "    function recallFromStrategy(uint256 amount) external onlyGuardian {",
        "        uint256 returnedAssets = _strategy.withdraw(address(_asset), amount, address(this));",
        "        if (returnedAssets > _strategyDebt) returnedAssets = _strategyDebt;",
        "        _strategyDebt -= returnedAssets;",
        "    }",
        "",
        "    function accrueBorrowIndex(uint256 elapsed) external onlyGuardian {",
        "        _borrowIndex += _borrowIndex * _feeRate * elapsed / SCALE;",
        "    }",
        "",
        "    function setOracle(ISyntheticScaleOracle nextOracle) external onlyGovernor {",
        "        if (address(nextOracle) == address(0)) revert InvalidSyntheticAddress();",
        "        _oracle = nextOracle;",
        "        emit SyntheticOracleUpdated(address(nextOracle));",
        "    }",
        "",
        "    function setStrategy(ISyntheticScaleStrategy nextStrategy) external onlyGovernor {",
        "        if (address(nextStrategy) == address(0)) revert InvalidSyntheticAddress();",
        "        _strategy = nextStrategy;",
        "    }",
        "",
        "    function setRiskParameters(",
        "        uint256 nextFeeRate,",
        "        uint256 nextMaximumStaleness",
        "    ) external onlyGovernor {",
        "        if (nextFeeRate > 5e16 || nextMaximumStaleness == 0) {",
        "            revert InvalidSyntheticAmount();",
        "        }",
        "        _feeRate = nextFeeRate;",
        "        _maximumStaleness = nextMaximumStaleness;",
        "    }",
        "",
        "    function emergencyAssetReturn(",
        "        address receiver,",
        "        uint256 amount",
        "    ) external onlyGuardian {",
        "        if (!_paused) revert UnauthorizedSyntheticActor();",
        "        if (!_asset.transfer(receiver, amount)) revert InvalidSyntheticAmount();",
        "    }",
        "",
        "    function totalAssets() external view returns (uint256) {",
        "        return _totalManagedAssets + _strategy.managedAssets(address(_asset));",
        "    }",
        "",
        "    function positionOf(address account) external view returns (Position memory) {",
        "        return _positions[account];",
        "    }",
        "",
        "    function previewHealth(address account) external view returns (uint256) {",
        "        Position memory position = _positions[account];",
        "        if (position.debt == 0) return type(uint256).max;",
        "        (uint256 price,, bool valid) = _oracle.latestPrice(MARKET_ID);",
        "        if (!valid) return 0;",
        "        return uint256(position.collateral) * price / uint256(position.debt);",
        "    }",
        "",
    ]
    for risk_window in range(12):
        adjustment = index + risk_window + 1
        lines.extend(
            [
                f"    function riskWindow{risk_window:02d}(",
                "        uint256 assets",
                "    ) external pure returns (uint256 adjustedAssets) {",
                f"        adjustedAssets = assets + assets * {adjustment} / 10_000;",
                "    }",
                "",
            ]
        )
    lines.extend(
        [
            "    function syntheticInvariantSummary()",
            "        external",
            "        view",
            "        returns (uint256 assets, uint256 shares, uint256 strategyDebt)",
            "    {",
            "        assets = _totalManagedAssets;",
            "        shares = _totalShares;",
            "        strategyDebt = _strategyDebt;",
            "    }",
            "}",
        ]
    )
    return _text(*lines)


def render_profile(profile: ScaleProfile) -> dict[str, bytes]:
    """Render one standalone fixture without host, clock, randomness, or network input."""

    files: dict[str, bytes] = {
        "foundry.toml": _foundry_configuration(),
        "src/core/Interfaces.sol": _interfaces_source(),
        "src/core/ProtocolRegistry.sol": _registry_source(),
        "src/core/SyntheticFixtureOnly.sol": _fixture_only_source(),
        "src/core/SyntheticProxies.sol": _proxies_source(),
    }
    for index in range(profile.module_count):
        files[f"src/markets/SyntheticMarket{index:03d}.sol"] = _market_source(index)
    return dict(sorted(files.items()))


def _source_metrics(files: dict[str, bytes]) -> dict[str, int]:
    source = "\n".join(
        content.decode("utf-8")
        for path, content in files.items()
        if PurePosixPath(path).suffix == ".sol"
    )
    contracts = len(re.findall(r"(?m)^abstract contract ", source))
    interfaces = len(re.findall(r"(?m)^interface ", source))
    functions = len(re.findall(r"(?m)^\s+function ", source))
    public_or_external = len(
        re.findall(
            r"(?ms)^\s+function\s+\w+.*?\)\s+(?:[^\n{]*\s)?(?:public|external)\b",
            source,
        )
    )
    privileged = len(re.findall(r"\bonly(?:Governor|Guardian)\b", source))
    return {
        "abstract_contracts": contracts,
        "interfaces": interfaces,
        "functions": functions,
        "public_or_external_functions": public_or_external,
        "privileged_control_references": privileged,
    }


def _tree_hash(bindings: list[dict[str, Any]]) -> str:
    identity = [
        {
            "path": binding["path"],
            "sha256": binding["sha256"],
            "utf8_bytes": binding["utf8_bytes"],
            "lines": binding["lines"],
        }
        for binding in bindings
    ]
    return _sha256(_canonical_json(identity))


def _self_hash(payload: dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    return _sha256(_canonical_json(unsigned))


def _manifest_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _profile_manifest(
    profile: ScaleProfile,
    files: dict[str, bytes],
    *,
    generator_sha256: str,
) -> dict[str, Any]:
    bindings: list[dict[str, Any]] = [
        {
            "path": path,
            "mode": "0644",
            "utf8_bytes": len(content),
            "lines": len(content.decode("utf-8").splitlines()),
            "sha256": _sha256(content),
        }
        for path, content in files.items()
    ]
    solidity_bindings = [
        binding for binding in bindings if PurePosixPath(binding["path"]).suffix == ".sol"
    ]
    actual_lines = sum(int(binding["lines"]) for binding in solidity_bindings)
    lower = profile.target_solidity_lines * (10_000 - TARGET_TOLERANCE_BASIS_POINTS) // 10_000
    upper = profile.target_solidity_lines * (10_000 + TARGET_TOLERANCE_BASIS_POINTS) // 10_000
    if not lower <= actual_lines <= upper:
        raise ValueError(
            f"{profile.fixture_id} generated {actual_lines} Solidity lines; "
            f"expected {lower}..{upper}"
        )
    metrics = _source_metrics(files)
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "fixture_id": profile.fixture_id,
        "generator": {
            "path": GENERATOR_REPOSITORY_PATH,
            "version": GENERATOR_VERSION,
            "sha256": generator_sha256,
        },
        "provenance": {
            "synthetic": True,
            "original_for_mmaudit_tests": True,
            "copied_production_source": False,
            "non_deployable": True,
            "deployment_artifacts_present": False,
        },
        "target": {
            "solidity_lines": profile.target_solidity_lines,
            "tolerance_basis_points": TARGET_TOLERANCE_BASIS_POINTS,
        },
        "actual": {
            "solidity_lines": actual_lines,
            "source_utf8_bytes": sum(int(binding["utf8_bytes"]) for binding in solidity_bindings),
            "file_count": len(bindings),
            "solidity_file_count": len(solidity_bindings),
            "module_count": profile.module_count,
        },
        "structure": {
            **metrics,
            "required_graph_kinds": list(REQUIRED_GRAPH_KINDS),
            "features": [
                "asset_custody_and_transfer",
                "cross_contract_registry_routing",
                "external_oracle_and_strategy_calls",
                "guardian_and_governor_controls",
                "inheritance",
                "initialization",
                "proxy_and_delegatecall",
            ],
        },
        "files": bindings,
        "source_tree_sha256": _tree_hash(bindings),
    }
    payload["manifest_sha256"] = _self_hash(payload)
    return payload


def render_corpus() -> dict[str, bytes]:
    """Render all golden fixture bytes, including sealed manifests."""

    generator_sha256 = _sha256(Path(__file__).read_bytes())
    rendered: dict[str, bytes] = {}
    profile_summaries: list[dict[str, Any]] = []
    for profile in PROFILES:
        files = render_profile(profile)
        manifest = _profile_manifest(
            profile,
            files,
            generator_sha256=generator_sha256,
        )
        prefix = f"{profile.fixture_id}/"
        for relative_path, content in files.items():
            rendered[f"{prefix}{relative_path}"] = content
        manifest_content = _manifest_bytes(manifest)
        rendered[f"{prefix}{MANIFEST_NAME}"] = manifest_content
        profile_summaries.append(
            {
                "fixture_id": profile.fixture_id,
                "root": profile.fixture_id,
                "manifest_path": f"{profile.fixture_id}/{MANIFEST_NAME}",
                "manifest_file_sha256": _sha256(manifest_content),
                "manifest_sha256": manifest["manifest_sha256"],
                "source_tree_sha256": manifest["source_tree_sha256"],
                "target_solidity_lines": profile.target_solidity_lines,
                "actual_solidity_lines": manifest["actual"]["solidity_lines"],
                "module_count": profile.module_count,
            }
        )
    corpus_manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "corpus_id": "mmaudit-realistic-solidity-scale-v1",
        "generator": {
            "path": GENERATOR_REPOSITORY_PATH,
            "version": GENERATOR_VERSION,
            "sha256": generator_sha256,
        },
        "profiles": profile_summaries,
    }
    corpus_manifest["manifest_sha256"] = _self_hash(corpus_manifest)
    rendered[CORPUS_MANIFEST_NAME] = _manifest_bytes(corpus_manifest)
    return dict(sorted(rendered.items()))


def _validate_output_root(output_root: Path) -> Path:
    if output_root.is_symlink():
        raise ValueError("output root must not be a symlink")
    try:
        metadata = output_root.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("existing output root must be a regular directory")
    resolved = output_root.resolve(strict=False)
    if resolved == Path(resolved.anchor):
        raise ValueError("filesystem root is not a valid fixture output")
    return resolved


def _preflight_existing_tree(root: Path, expected: set[str]) -> None:
    """Refuse to replace links, special files, shared files, or unknown entries."""

    if not root.exists():
        return
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        relative_path = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        actual_files.add(relative_path)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"refusing to replace fixture symlink: {relative_path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"refusing to replace non-regular fixture file: {relative_path}")
        if metadata.st_nlink != 1:
            raise ValueError(f"refusing to replace shared fixture hardlink: {relative_path}")
        if stat.S_IMODE(metadata.st_mode) != 0o644:
            raise ValueError(
                f"refusing to replace fixture file with mode other than 0644: {relative_path}"
            )
    unexpected = sorted(actual_files - expected)
    if unexpected:
        raise ValueError(f"refusing to remove unexpected fixture files: {unexpected}")


def write_corpus(output_root: Path) -> None:
    """Write only the deterministic expected files; never remove unexpected data."""

    root = _validate_output_root(output_root)
    expected = render_corpus()
    _preflight_existing_tree(root, set(expected))
    root.mkdir(parents=True, exist_ok=True)
    for relative_path, content in expected.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.mmaudit-tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o644)
        try:
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        os.replace(temporary, target)


def verify_corpus(output_root: Path) -> list[str]:
    """Return deterministic drift diagnostics for the committed golden corpus."""

    root = _validate_output_root(output_root)
    expected = render_corpus()
    if not root.is_dir():
        return [f"missing fixture root: {root}"]
    diagnostics: list[str] = []
    actual_files: set[str] = set()
    for path in root.rglob("*"):
        relative_path = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        actual_files.add(relative_path)
        if stat.S_ISLNK(metadata.st_mode):
            diagnostics.append(f"{relative_path}: symlink is prohibited")
            continue
        if not stat.S_ISREG(metadata.st_mode):
            diagnostics.append(f"{relative_path}: non-regular file is prohibited")
            continue
        if metadata.st_nlink != 1:
            diagnostics.append(f"{relative_path}: shared hardlink is prohibited")
            continue
        if stat.S_IMODE(metadata.st_mode) != 0o644:
            diagnostics.append(f"{relative_path}: mode must be 0644")
            continue
        expected_content = expected.get(relative_path)
        if expected_content is not None and path.read_bytes() != expected_content:
            diagnostics.append(f"{relative_path}: content differs from deterministic output")
    for missing in sorted(set(expected) - actual_files):
        diagnostics.append(f"{missing}: expected file is missing")
    for unexpected in sorted(actual_files - set(expected)):
        diagnostics.append(f"{unexpected}: unexpected file is present")
    return diagnostics


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="fixture corpus root (defaults to the committed golden location)",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write deterministic expected files instead of checking for drift",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.write:
        write_corpus(args.output_root)
        diagnostics = verify_corpus(args.output_root)
        if diagnostics:
            for diagnostic in diagnostics:
                print(diagnostic)
            return 1
        print(f"wrote {len(render_corpus())} deterministic fixture files")
        return 0
    diagnostics = verify_corpus(args.output_root)
    if diagnostics:
        for diagnostic in diagnostics:
            print(diagnostic)
        return 1
    print(f"verified {len(render_corpus())} deterministic fixture files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
