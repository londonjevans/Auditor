// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ISyntheticScaleMarket} from "./Interfaces.sol";
import {SyntheticAccess} from "./SyntheticFixtureOnly.sol";

// Synthetic fixture only. This registry has no deployable production target.
abstract contract SyntheticProtocolRegistry is SyntheticAccess {
    mapping(bytes32 marketId => address market) internal _markets;
    mapping(bytes32 marketId => address oracle) internal _oracles;
    mapping(bytes32 marketId => address strategy) internal _strategies;

    event SyntheticMarketRegistered(bytes32 indexed marketId, address indexed market);
    event SyntheticOracleRegistered(bytes32 indexed marketId, address indexed oracle);
    event SyntheticStrategyRegistered(bytes32 indexed marketId, address indexed strategy);

    function initializeRegistry(address governor_) external {
        _initializeSyntheticAccess(governor_);
    }

    function setMarket(bytes32 marketId, address market_) external onlyGovernor {
        if (market_ == address(0)) revert InvalidSyntheticAddress();
        _markets[marketId] = market_;
        emit SyntheticMarketRegistered(marketId, market_);
    }

    function setOracle(bytes32 marketId, address oracle_) external onlyGovernor {
        if (oracle_ == address(0)) revert InvalidSyntheticAddress();
        _oracles[marketId] = oracle_;
        emit SyntheticOracleRegistered(marketId, oracle_);
    }

    function setStrategy(bytes32 marketId, address strategy_) external onlyGovernor {
        if (strategy_ == address(0)) revert InvalidSyntheticAddress();
        _strategies[marketId] = strategy_;
        emit SyntheticStrategyRegistered(marketId, strategy_);
    }

    function routeDeposit(
        bytes32 marketId,
        address receiver,
        uint256 assets
    ) external whenActive returns (uint256 shares) {
        address marketAddress_ = _markets[marketId];
        if (marketAddress_ == address(0)) revert InvalidSyntheticAddress();
        shares = ISyntheticScaleMarket(marketAddress_).depositFor(receiver, assets);
    }

    function routeRedemption(
        bytes32 marketId,
        address receiver,
        uint256 shares
    ) external whenActive returns (uint256 assets) {
        address marketAddress_ = _markets[marketId];
        if (marketAddress_ == address(0)) revert InvalidSyntheticAddress();
        assets = ISyntheticScaleMarket(marketAddress_).redeemFor(receiver, shares);
    }

    function marketAddress(bytes32 marketId) external view returns (address) {
        return _markets[marketId];
    }

    function oracleAddress(bytes32 marketId) external view returns (address) {
        return _oracles[marketId];
    }

    function strategyAddress(bytes32 marketId) external view returns (address) {
        return _strategies[marketId];
    }
}
