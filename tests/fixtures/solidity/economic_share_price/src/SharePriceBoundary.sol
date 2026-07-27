// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Synthetic fixture asset. It is intentionally unsuitable for deployment.
contract SyntheticRateAsset {
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

contract UnsafeReportedAssetRateVault {
    address internal constant PRELOADED_HOLDER = 0x1000000000000000000000000000000000000002;
    uint256 internal constant RATE_SCALE = 1_000;

    SyntheticRateAsset public immutable asset;
    uint256 public totalSupply = 1_000;
    mapping(address => uint256) public balanceOf;
    uint256 internal _reportedAssets = 1_000;
    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _totalAssetsBefore;
    uint256 internal _totalSharesBefore;
    uint256 internal _legitimateYield;
    uint256 internal _expectedRateAfterYield;
    uint256 internal _observedRateAfter;
    uint256 internal _sharesRedeemed;
    uint256 internal _assetsRedeemed;
    uint256 internal _excessAssets;
    bool internal _attempted;

    constructor(SyntheticRateAsset asset_) {
        asset = asset_;
        asset.mint(address(this), 1_000);
        balanceOf[PRELOADED_HOLDER] = 100;
    }

    function totalAssets() public view returns (uint256) {
        return _reportedAssets;
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return assets * totalSupply / totalAssets();
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets();
        asset.settle(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[receiver] += shares;
        _reportedAssets += assets;
    }

    function exchangeRateBoundaryPreset() external {
        require(!_attempted, "fixture transition already settled");
        require(balanceOf[msg.sender] >= 100, "fixture share position");
        _attempted = true;
        _startingAssets = asset.balanceOf(msg.sender);
        _totalAssetsBefore = asset.balanceOf(address(this));
        _totalSharesBefore = totalSupply;
        _legitimateYield = 100;
        asset.mint(address(this), _legitimateYield);
        _expectedRateAfterYield = (_totalAssetsBefore + _legitimateYield) * RATE_SCALE / _totalSharesBefore;

        _reportedAssets = asset.balanceOf(address(this)) + 400;
        _observedRateAfter = _reportedAssets * RATE_SCALE / _totalSharesBefore;
        _sharesRedeemed = 100;
        _assetsRedeemed = _sharesRedeemed * _observedRateAfter / RATE_SCALE;
        balanceOf[msg.sender] -= _sharesRedeemed;
        totalSupply -= _sharesRedeemed;
        asset.settle(address(this), msg.sender, _assetsRedeemed);

        uint256 expectedAssets = _sharesRedeemed * _expectedRateAfterYield / RATE_SCALE;
        _excessAssets = _assetsRedeemed > expectedAssets ? _assetsRedeemed - expectedAssets : 0;
        _grossAssetsReceived = _assetsRedeemed;
        _endingAssets = asset.balanceOf(msg.sender);
        _netImpact = _endingAssets - _startingAssets;
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

    function rateScale() external pure returns (uint256) {
        return RATE_SCALE;
    }

    function totalAssetsBefore() external view returns (uint256) {
        return _totalAssetsBefore;
    }

    function totalSharesBefore() external view returns (uint256) {
        return _totalSharesBefore;
    }

    function legitimateYield() external view returns (uint256) {
        return _legitimateYield;
    }

    function expectedRateAfterYield() external view returns (uint256) {
        return _expectedRateAfterYield;
    }

    function observedRateAfter() external view returns (uint256) {
        return _observedRateAfter;
    }

    function sharesRedeemed() external view returns (uint256) {
        return _sharesRedeemed;
    }

    function assetsRedeemed() external view returns (uint256) {
        return _assetsRedeemed;
    }

    function excessAssets() external view returns (uint256) {
        return _excessAssets;
    }
}

contract SafeObservedAssetRateVault {
    address internal constant PRELOADED_HOLDER = 0x1000000000000000000000000000000000000002;
    uint256 internal constant RATE_SCALE = 1_000;

    SyntheticRateAsset public immutable asset;
    uint256 public totalSupply = 1_000;
    mapping(address => uint256) public balanceOf;
    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _totalAssetsBefore;
    uint256 internal _totalSharesBefore;
    uint256 internal _legitimateYield;
    uint256 internal _expectedRateAfterYield;
    uint256 internal _observedRateAfter;
    uint256 internal _sharesRedeemed;
    uint256 internal _assetsRedeemed;
    uint256 internal _excessAssets;
    bool internal _attempted;

    constructor(SyntheticRateAsset asset_) {
        asset = asset_;
        asset.mint(address(this), 1_000);
        balanceOf[PRELOADED_HOLDER] = 100;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return assets * totalSupply / totalAssets();
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = assets * totalSupply / totalAssets();
        asset.settle(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function exchangeRateBoundaryPreset() external {
        require(!_attempted, "fixture transition already settled");
        require(balanceOf[msg.sender] >= 100, "fixture share position");
        _attempted = true;
        _startingAssets = asset.balanceOf(msg.sender);
        _totalAssetsBefore = asset.balanceOf(address(this));
        _totalSharesBefore = totalSupply;
        _legitimateYield = 100;
        asset.mint(address(this), _legitimateYield);
        _expectedRateAfterYield = (_totalAssetsBefore + _legitimateYield) * RATE_SCALE / _totalSharesBefore;

        _observedRateAfter = totalAssets() * RATE_SCALE / _totalSharesBefore;
        _sharesRedeemed = 100;
        _assetsRedeemed = _sharesRedeemed * _observedRateAfter / RATE_SCALE;
        balanceOf[msg.sender] -= _sharesRedeemed;
        totalSupply -= _sharesRedeemed;
        asset.settle(address(this), msg.sender, _assetsRedeemed);

        uint256 expectedAssets = _sharesRedeemed * _expectedRateAfterYield / RATE_SCALE;
        _excessAssets = _assetsRedeemed > expectedAssets ? _assetsRedeemed - expectedAssets : 0;
        _grossAssetsReceived = _assetsRedeemed;
        _endingAssets = asset.balanceOf(msg.sender);
        _netImpact = _endingAssets - _startingAssets;
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

    function rateScale() external pure returns (uint256) {
        return RATE_SCALE;
    }

    function totalAssetsBefore() external view returns (uint256) {
        return _totalAssetsBefore;
    }

    function totalSharesBefore() external view returns (uint256) {
        return _totalSharesBefore;
    }

    function legitimateYield() external view returns (uint256) {
        return _legitimateYield;
    }

    function expectedRateAfterYield() external view returns (uint256) {
        return _expectedRateAfterYield;
    }

    function observedRateAfter() external view returns (uint256) {
        return _observedRateAfter;
    }

    function sharesRedeemed() external view returns (uint256) {
        return _sharesRedeemed;
    }

    function assetsRedeemed() external view returns (uint256) {
        return _assetsRedeemed;
    }

    function excessAssets() external view returns (uint256) {
        return _excessAssets;
    }
}
