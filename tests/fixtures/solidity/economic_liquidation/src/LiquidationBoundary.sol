// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Synthetic fixture asset. It is intentionally unsuitable for deployment.
contract SyntheticLiquidationAsset {
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

contract UnsafeHealthyPositionLiquidation {
    SyntheticLiquidationAsset public immutable asset;

    uint256 internal _positionDebt = 100;
    uint256 internal _positionCollateral = 150;
    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _debtBefore;
    uint256 internal _collateralBefore;
    uint256 internal _debtAfter;
    uint256 internal _collateralAfter;
    uint256 internal _collateralSeized;
    uint256 internal _badDebtAfter;
    bool internal _attempted;

    constructor(SyntheticLiquidationAsset asset_) {
        asset = asset_;
        asset.mint(address(this), _positionCollateral);
    }

    function liquidationBoundaryPreset() external {
        require(!_attempted, "fixture transition already settled");
        _attempted = true;
        _startingAssets = asset.balanceOf(msg.sender);
        _debtBefore = _positionDebt;
        _collateralBefore = _positionCollateral;

        if (_positionCollateral >= _positionDebt) {
            _collateralSeized = _positionCollateral;
            _positionCollateral = 0;
            asset.settle(address(this), msg.sender, _collateralSeized);
        }

        _debtAfter = _positionDebt;
        _collateralAfter = _positionCollateral;
        _badDebtAfter = _debtAfter > _collateralAfter ? _debtAfter - _collateralAfter : 0;
        _grossAssetsReceived = _collateralSeized;
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

    function debtBefore() external view returns (uint256) {
        return _debtBefore;
    }

    function collateralBefore() external view returns (uint256) {
        return _collateralBefore;
    }

    function debtAfter() external view returns (uint256) {
        return _debtAfter;
    }

    function collateralAfter() external view returns (uint256) {
        return _collateralAfter;
    }

    function collateralSeized() external view returns (uint256) {
        return _collateralSeized;
    }

    function badDebtAfter() external view returns (uint256) {
        return _badDebtAfter;
    }
}

contract SafeHealthyPositionLiquidation {
    SyntheticLiquidationAsset public immutable asset;

    uint256 internal _positionDebt = 100;
    uint256 internal _positionCollateral = 150;
    uint256 internal _startingAssets;
    uint256 internal _borrowedAssets;
    uint256 internal _repaidAssets;
    uint256 internal _grossAssetsReceived;
    uint256 internal _feesPaid;
    uint256 internal _slippageLoss;
    uint256 internal _endingAssets;
    uint256 internal _netImpact;
    uint256 internal _debtBefore;
    uint256 internal _collateralBefore;
    uint256 internal _debtAfter;
    uint256 internal _collateralAfter;
    uint256 internal _collateralSeized;
    uint256 internal _badDebtAfter;
    bool internal _attempted;

    constructor(SyntheticLiquidationAsset asset_) {
        asset = asset_;
        asset.mint(address(this), _positionCollateral);
    }

    function liquidationBoundaryPreset() external {
        require(!_attempted, "fixture transition already settled");
        _attempted = true;
        _startingAssets = asset.balanceOf(msg.sender);
        _debtBefore = _positionDebt;
        _collateralBefore = _positionCollateral;

        if (_positionDebt > _positionCollateral) {
            _collateralSeized = _positionCollateral;
            _positionCollateral = 0;
            asset.settle(address(this), msg.sender, _collateralSeized);
        }

        _debtAfter = _positionDebt;
        _collateralAfter = _positionCollateral;
        _badDebtAfter = _debtAfter > _collateralAfter ? _debtAfter - _collateralAfter : 0;
        _grossAssetsReceived = _collateralSeized;
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

    function debtBefore() external view returns (uint256) {
        return _debtBefore;
    }

    function collateralBefore() external view returns (uint256) {
        return _collateralBefore;
    }

    function debtAfter() external view returns (uint256) {
        return _debtAfter;
    }

    function collateralAfter() external view returns (uint256) {
        return _collateralAfter;
    }

    function collateralSeized() external view returns (uint256) {
        return _collateralSeized;
    }

    function badDebtAfter() external view returns (uint256) {
        return _badDebtAfter;
    }
}
