// Synthetic, intentionally non-deployable local package material.
pragma solidity ^0.8.20;
abstract contract DependencyBase {
    function dependencyInvariant() external pure virtual returns (bool);
}
