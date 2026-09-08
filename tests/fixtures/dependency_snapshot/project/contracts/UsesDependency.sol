// Synthetic, intentionally non-deployable dependency-preparation fixture.
pragma solidity ^0.8.20;
abstract contract UsesDependency {
    function declaredInvariant() external pure virtual returns (bool);
}
