// Synthetic source-ingestion control; intentionally abstract and non-deployable.
pragma solidity ^0.8.20;

abstract contract SourceIngestionControl {
    function observedBalance() external view virtual returns (uint256);
}
