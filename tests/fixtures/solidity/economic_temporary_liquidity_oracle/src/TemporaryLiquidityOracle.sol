// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Synthetic fixture asset. It is intentionally unsuitable for deployment.
contract SyntheticLiquidityAsset {
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

contract UnsafeTemporaryLiquidityOracle {
    SyntheticLiquidityAsset public immutable asset;

    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _excessExtraction;

    constructor(SyntheticLiquidityAsset asset_) {
        asset = asset_;
    }

    function latestPrice() external pure returns (uint256) {
        return 35;
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

    function temporaryLiquidityPreset() external {
        require(_borrowedAssets == 0, "fixture transition already settled");
        _startingAssets = asset.balanceOf(msg.sender);
        _borrowedAssets = 1_000;
        _repaidAssets = _borrowedAssets;
        _feesPaid = 10;
        _slippageLoss = 5;

        asset.mint(msg.sender, _borrowedAssets);
        _grossAssetsReceived = this.latestPrice();
        asset.mint(msg.sender, _grossAssetsReceived);
        asset.settle(msg.sender, address(this), _repaidAssets + _feesPaid + _slippageLoss);

        _endingAssets = asset.balanceOf(msg.sender);
        _netImpact = _endingAssets - _startingAssets;
        _excessExtraction = _netImpact;
    }
}

contract SafeTemporaryLiquidityOracle {
    SyntheticLiquidityAsset public immutable asset;

    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _excessExtraction;

    constructor(SyntheticLiquidityAsset asset_) {
        asset = asset_;
    }

    function latestPrice() external pure returns (uint256) {
        return 35;
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

    function temporaryLiquidityPreset() external {
        require(_borrowedAssets == 0, "fixture transition already settled");
        _startingAssets = asset.balanceOf(msg.sender);
        _borrowedAssets = 1_000;
        _repaidAssets = _borrowedAssets;
        _feesPaid = 10;
        _slippageLoss = 5;

        asset.mint(msg.sender, _borrowedAssets);
        uint256 maximumSettledPayout = 15;
        uint256 observedPrice = this.latestPrice();
        _grossAssetsReceived = observedPrice > maximumSettledPayout ? maximumSettledPayout : observedPrice;
        asset.mint(msg.sender, _grossAssetsReceived);
        asset.settle(msg.sender, address(this), _repaidAssets + _feesPaid + _slippageLoss);

        _endingAssets = asset.balanceOf(msg.sender);
        _netImpact = _endingAssets - _startingAssets;
        _excessExtraction = _netImpact;
    }
}
