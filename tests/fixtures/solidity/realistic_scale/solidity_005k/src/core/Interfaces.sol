// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// Synthetic fixture only. This original test protocol is not production source.
interface ISyntheticScaleAsset {
    function balanceOf(address account) external view returns (uint256);

    function transfer(address receiver, uint256 amount) external returns (bool);

    function transferFrom(
        address sender,
        address receiver,
        uint256 amount
    ) external returns (bool);
}

interface ISyntheticScaleOracle {
    function latestPrice(
        bytes32 marketId
    ) external view returns (uint256 price, uint64 updatedAt, bool valid);
}

interface ISyntheticScaleStrategy {
    function allocate(
        address asset,
        uint256 amount
    ) external returns (uint256 accepted);

    function withdraw(
        address asset,
        uint256 amount,
        address receiver
    ) external returns (uint256 returnedAssets);

    function managedAssets(address asset) external view returns (uint256);
}

// Synthetic beacon-shaped dependency used only by proxy graph fixtures.
interface ISyntheticScaleBeacon {
    function implementation() external view returns (address);
}

interface ISyntheticScaleMarket {
    function depositFor(address receiver, uint256 assets) external returns (uint256);

    function redeemFor(address receiver, uint256 shares) external returns (uint256);

    function totalAssets() external view returns (uint256);
}
