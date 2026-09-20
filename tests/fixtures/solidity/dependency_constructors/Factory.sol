// Synthetic source-only fixture. Never compile, deploy or execute it.
pragma solidity ^0.8.24;
import "./Products.sol";
import "./Guard.sol";

contract Factory is Guard {
    Product private seeded = new Product(uint256(1));
    function inspect(uint256 n) external returns (uint256) {
        return new Product(uint256(n)).value();
    }
    function observe(Product supplied) internal view returns (uint256) {
        return supplied.value();
    }
    function nested(uint256 n) external returns (uint256) {
        return observe(new Product(n));
    }
    function header() external returns (HeaderProduct) { return new HeaderProduct(); }
    function implicitProduct() external returns (Implicit) { return new Implicit(); }
    function derived(uint256 n) external returns (DerivedProduct) { return new DerivedProduct(n); }
}
