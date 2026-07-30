// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {
    ISyntheticScaleAsset,
    ISyntheticScaleMarket,
    ISyntheticScaleOracle,
    ISyntheticScaleStrategy
} from "../core/Interfaces.sol";
import {SyntheticAccounting} from "../core/SyntheticFixtureOnly.sol";

// Synthetic fixture only. This original market is intentionally non-deployable.
abstract contract SyntheticMarket062 is SyntheticAccounting, ISyntheticScaleMarket {
    bytes32 public constant MARKET_ID = keccak256("mmaudit-synthetic-market-062");
    uint256 public constant SCALE = 1e18;

    struct Position {
        uint128 collateral;
        uint128 debt;
        uint64 lastAccrual;
        bool liquidationPending;
    }

    ISyntheticScaleAsset internal _asset;
    ISyntheticScaleOracle internal _oracle;
    ISyntheticScaleStrategy internal _strategy;
    mapping(address account => Position position) internal _positions;
    uint256 internal _borrowIndex;
    uint256 internal _feeRate;
    uint256 internal _maximumStaleness;
    uint256 internal _strategyDebt;

    event SyntheticDeposit(address indexed caller, address indexed receiver, uint256 assets);
    event SyntheticRedemption(address indexed owner, address indexed receiver, uint256 shares);
    event SyntheticBorrow(address indexed account, uint256 amount);
    event SyntheticRepayment(address indexed account, uint256 amount);
    event SyntheticLiquidation(address indexed account, uint256 repaid, uint256 collateral);
    event SyntheticStrategyAllocation(uint256 requested, uint256 accepted);
    event SyntheticOracleUpdated(address indexed oracle);

    function initializeMarket(
        address governor_,
        ISyntheticScaleAsset asset_,
        ISyntheticScaleOracle oracle_,
        ISyntheticScaleStrategy strategy_
    ) external {
        _initializeSyntheticAccess(governor_);
        if (address(asset_) == address(0)) revert InvalidSyntheticAddress();
        if (address(oracle_) == address(0)) revert InvalidSyntheticAddress();
        if (address(strategy_) == address(0)) revert InvalidSyntheticAddress();
        _asset = asset_;
        _oracle = oracle_;
        _strategy = strategy_;
        _borrowIndex = SCALE;
        _feeRate = 5e15;
        _maximumStaleness = 1 hours;
    }

    function deposit(uint256 assets, address receiver)
        external
        whenActive
        returns (uint256 shares)
    {
        shares = _depositFrom(msg.sender, receiver, assets);
    }

    function depositFor(
        address receiver,
        uint256 assets
    ) external whenActive returns (uint256 shares) {
        shares = _depositFrom(msg.sender, receiver, assets);
    }

    function _depositFrom(
        address sender,
        address receiver,
        uint256 assets
    ) internal returns (uint256 shares) {
        if (!_asset.transferFrom(sender, address(this), assets)) {
            revert InvalidSyntheticAmount();
        }
        shares = _mintSyntheticShares(receiver, assets);
        _positions[receiver].collateral += uint128(assets);
        emit SyntheticDeposit(sender, receiver, assets);
    }

    function redeem(uint256 shares, address receiver)
        external
        whenActive
        returns (uint256 assets)
    {
        assets = _redeemFrom(msg.sender, receiver, shares);
    }

    function redeemFor(
        address receiver,
        uint256 shares
    ) external whenActive returns (uint256 assets) {
        assets = _redeemFrom(msg.sender, receiver, shares);
    }

    function _redeemFrom(
        address owner,
        address receiver,
        uint256 shares
    ) internal returns (uint256 assets) {
        assets = _burnSyntheticShares(owner, shares);
        if (!_asset.transfer(receiver, assets)) revert InvalidSyntheticAmount();
        emit SyntheticRedemption(owner, receiver, shares);
    }

    function borrow(uint256 amount) external whenActive {
        (uint256 price, uint64 updatedAt, bool valid) = _oracle.latestPrice(MARKET_ID);
        if (!valid || price == 0) revert InvalidSyntheticAmount();
        if (block.timestamp > uint256(updatedAt) + _maximumStaleness) {
            revert InvalidSyntheticAmount();
        }
        Position storage position = _positions[msg.sender];
        if (uint256(position.collateral) * price / SCALE < amount * 2) {
            revert InsufficientSyntheticBalance();
        }
        position.debt += uint128(amount);
        if (!_asset.transfer(msg.sender, amount)) revert InvalidSyntheticAmount();
        emit SyntheticBorrow(msg.sender, amount);
    }

    function repay(uint256 amount) external whenActive {
        Position storage position = _positions[msg.sender];
        if (amount > position.debt) amount = position.debt;
        if (!_asset.transferFrom(msg.sender, address(this), amount)) {
            revert InvalidSyntheticAmount();
        }
        position.debt -= uint128(amount);
        emit SyntheticRepayment(msg.sender, amount);
    }

    function markLiquidation(address account) external onlyGuardian {
        _positions[account].liquidationPending = true;
    }

    function settleLiquidation(
        address account,
        uint256 repayment
    ) external whenActive returns (uint256 collateralReleased) {
        Position storage position = _positions[account];
        if (!position.liquidationPending) revert UnauthorizedSyntheticActor();
        if (!_asset.transferFrom(msg.sender, address(this), repayment)) {
            revert InvalidSyntheticAmount();
        }
        uint256 boundedRepayment = repayment > position.debt ? position.debt : repayment;
        position.debt -= uint128(boundedRepayment);
        collateralReleased = boundedRepayment * 11 / 10;
        if (collateralReleased > position.collateral) {
            collateralReleased = position.collateral;
        }
        position.collateral -= uint128(collateralReleased);
        position.liquidationPending = false;
        if (!_asset.transfer(msg.sender, collateralReleased)) {
            revert InvalidSyntheticAmount();
        }
        emit SyntheticLiquidation(account, boundedRepayment, collateralReleased);
    }

    function allocateToStrategy(uint256 amount) external onlyGovernor whenActive {
        if (!_asset.transfer(address(_strategy), amount)) revert InvalidSyntheticAmount();
        uint256 accepted = _strategy.allocate(address(_asset), amount);
        _strategyDebt += accepted;
        emit SyntheticStrategyAllocation(amount, accepted);
    }

    function recallFromStrategy(uint256 amount) external onlyGuardian {
        uint256 returnedAssets = _strategy.withdraw(address(_asset), amount, address(this));
        if (returnedAssets > _strategyDebt) returnedAssets = _strategyDebt;
        _strategyDebt -= returnedAssets;
    }

    function accrueBorrowIndex(uint256 elapsed) external onlyGuardian {
        _borrowIndex += _borrowIndex * _feeRate * elapsed / SCALE;
    }

    function setOracle(ISyntheticScaleOracle nextOracle) external onlyGovernor {
        if (address(nextOracle) == address(0)) revert InvalidSyntheticAddress();
        _oracle = nextOracle;
        emit SyntheticOracleUpdated(address(nextOracle));
    }

    function setStrategy(ISyntheticScaleStrategy nextStrategy) external onlyGovernor {
        if (address(nextStrategy) == address(0)) revert InvalidSyntheticAddress();
        _strategy = nextStrategy;
    }

    function setRiskParameters(
        uint256 nextFeeRate,
        uint256 nextMaximumStaleness
    ) external onlyGovernor {
        if (nextFeeRate > 5e16 || nextMaximumStaleness == 0) {
            revert InvalidSyntheticAmount();
        }
        _feeRate = nextFeeRate;
        _maximumStaleness = nextMaximumStaleness;
    }

    function emergencyAssetReturn(
        address receiver,
        uint256 amount
    ) external onlyGuardian {
        if (!_paused) revert UnauthorizedSyntheticActor();
        if (!_asset.transfer(receiver, amount)) revert InvalidSyntheticAmount();
    }

    function totalAssets() external view returns (uint256) {
        return _totalManagedAssets + _strategy.managedAssets(address(_asset));
    }

    function positionOf(address account) external view returns (Position memory) {
        return _positions[account];
    }

    function previewHealth(address account) external view returns (uint256) {
        Position memory position = _positions[account];
        if (position.debt == 0) return type(uint256).max;
        (uint256 price,, bool valid) = _oracle.latestPrice(MARKET_ID);
        if (!valid) return 0;
        return uint256(position.collateral) * price / uint256(position.debt);
    }

    function riskWindow00(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 63 / 10_000;
    }

    function riskWindow01(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 64 / 10_000;
    }

    function riskWindow02(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 65 / 10_000;
    }

    function riskWindow03(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 66 / 10_000;
    }

    function riskWindow04(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 67 / 10_000;
    }

    function riskWindow05(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 68 / 10_000;
    }

    function riskWindow06(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 69 / 10_000;
    }

    function riskWindow07(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 70 / 10_000;
    }

    function riskWindow08(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 71 / 10_000;
    }

    function riskWindow09(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 72 / 10_000;
    }

    function riskWindow10(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 73 / 10_000;
    }

    function riskWindow11(
        uint256 assets
    ) external pure returns (uint256 adjustedAssets) {
        adjustedAssets = assets + assets * 74 / 10_000;
    }

    function syntheticInvariantSummary()
        external
        view
        returns (uint256 assets, uint256 shares, uint256 strategyDebt)
    {
        assets = _totalManagedAssets;
        shares = _totalShares;
        strategyDebt = _strategyDebt;
    }
}
