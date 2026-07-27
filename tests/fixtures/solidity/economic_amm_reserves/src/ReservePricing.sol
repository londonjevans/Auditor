// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Synthetic fixture asset. It is intentionally unsuitable for deployment.
contract SyntheticSettlementAsset {
    mapping(address => uint256) public balanceOf;

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function settle(address account, address recipient, uint256 amount) external {
        require(balanceOf[account] >= amount, "fixture balance");
        balanceOf[account] -= amount;
        balanceOf[recipient] += amount;
    }
}

contract UnsafeSpotReservePricing {
    SyntheticSettlementAsset public immutable asset;

    uint256 internal _reserve0 = 1_000;
    uint256 internal _reserve1 = 1_000;
    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _excessExtraction;
    uint256 internal _reserveProductBefore;
    uint256 internal _reserveProductAfter;
    uint256 internal _spotPriceBefore;
    uint256 internal _spotPriceAfter;
    bool internal _moved;

    constructor(SyntheticSettlementAsset asset_) {
        asset = asset_;
    }

    function spotPrice() external view returns (uint256) {
        return (_reserve1 * 10) / _reserve0;
    }

    function protectedPrice() external pure returns (uint256) {
        return 10;
    }

    function reserveMovementPreset() external {
        require(!_moved, "fixture transition already settled");
        _moved = true;
        _startingAssets = asset.balanceOf(msg.sender);
        _reserveProductBefore = _reserve0 * _reserve1;
        _spotPriceBefore = this.spotPrice();

        _reserve0 = 500;
        _reserve1 = 2_000;
        _reserveProductAfter = _reserve0 * _reserve1;
        _spotPriceAfter = this.spotPrice();

        _grossAssetsReceived = _spotPriceAfter;
        _feesPaid = 10;
        asset.mint(msg.sender, _grossAssetsReceived);
        asset.settle(msg.sender, address(this), _feesPaid);
        _endingAssets = asset.balanceOf(msg.sender);
        _netImpact = _endingAssets - _startingAssets;
        _excessExtraction = _netImpact;
    }

    function startingAssets() external view returns (uint256) {
        return _startingAssets;
    }

    function borrowedAssets() external view returns (uint256) {
        return _borrowedAssets;
    }

    function repaidAssets() external view returns (uint256) {
        return _repaidAssets;
    }

    function grossAssetsReceived() external view returns (uint256) {
        return _grossAssetsReceived;
    }

    function feesPaid() external view returns (uint256) {
        return _feesPaid;
    }

    function slippageLoss() external view returns (uint256) {
        return _slippageLoss;
    }

    function endingAssets() external view returns (uint256) {
        return _endingAssets;
    }

    function netImpact() external view returns (uint256) {
        return _netImpact;
    }

    function excessExtraction() external view returns (uint256) {
        return _excessExtraction;
    }

    function reserveProductBefore() external view returns (uint256) {
        return _reserveProductBefore;
    }

    function reserveProductAfter() external view returns (uint256) {
        return _reserveProductAfter;
    }

    function spotPriceBefore() external view returns (uint256) {
        return _spotPriceBefore;
    }

    function spotPriceAfter() external view returns (uint256) {
        return _spotPriceAfter;
    }
}

contract SafeProtectedReservePricing {
    SyntheticSettlementAsset public immutable asset;

    uint256 internal _reserve0 = 1_000;
    uint256 internal _reserve1 = 1_000;
    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _excessExtraction;
    uint256 internal _reserveProductBefore;
    uint256 internal _reserveProductAfter;
    uint256 internal _spotPriceBefore;
    uint256 internal _spotPriceAfter;
    bool internal _moved;

    constructor(SyntheticSettlementAsset asset_) {
        asset = asset_;
    }

    function spotPrice() external view returns (uint256) {
        return (_reserve1 * 10) / _reserve0;
    }

    function protectedPrice() external pure returns (uint256) {
        return 10;
    }

    function reserveMovementPreset() external {
        require(!_moved, "fixture transition already settled");
        _moved = true;
        _startingAssets = asset.balanceOf(msg.sender);
        _reserveProductBefore = _reserve0 * _reserve1;
        _spotPriceBefore = this.spotPrice();

        _reserve0 = 500;
        _reserve1 = 2_000;
        _reserveProductAfter = _reserve0 * _reserve1;
        _spotPriceAfter = this.spotPrice();

        _grossAssetsReceived = this.protectedPrice();
        _feesPaid = 10;
        asset.mint(msg.sender, _grossAssetsReceived);
        asset.settle(msg.sender, address(this), _feesPaid);
        _endingAssets = asset.balanceOf(msg.sender);
        _netImpact = _endingAssets - _startingAssets;
        _excessExtraction = _netImpact;
    }

    function startingAssets() external view returns (uint256) {
        return _startingAssets;
    }

    function borrowedAssets() external view returns (uint256) {
        return _borrowedAssets;
    }

    function repaidAssets() external view returns (uint256) {
        return _repaidAssets;
    }

    function grossAssetsReceived() external view returns (uint256) {
        return _grossAssetsReceived;
    }

    function feesPaid() external view returns (uint256) {
        return _feesPaid;
    }

    function slippageLoss() external view returns (uint256) {
        return _slippageLoss;
    }

    function endingAssets() external view returns (uint256) {
        return _endingAssets;
    }

    function netImpact() external view returns (uint256) {
        return _netImpact;
    }

    function excessExtraction() external view returns (uint256) {
        return _excessExtraction;
    }

    function reserveProductBefore() external view returns (uint256) {
        return _reserveProductBefore;
    }

    function reserveProductAfter() external view returns (uint256) {
        return _reserveProductAfter;
    }

    function spotPriceBefore() external view returns (uint256) {
        return _spotPriceBefore;
    }

    function spotPriceAfter() external view returns (uint256) {
        return _spotPriceAfter;
    }
}
