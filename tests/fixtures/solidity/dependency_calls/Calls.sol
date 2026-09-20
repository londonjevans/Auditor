// Synthetic, non-deployable source-only dependency resolution fixture. No funds or live targets.
pragma solidity ^0.8.24;

interface IReserve {
    function value(uint256 amount) external view returns (uint256);
    function value(bool choice) external view returns (uint256);
}
interface IFactory {
    function reserve() external view returns (IReserve);
}
contract ReserveA is IReserve {
    constructor() { revert("synthetic non-deployable fixture"); }
    function value(uint256 amount) external pure returns (uint256) { return amount; }
    function value(bool choice) external pure returns (uint256) { return choice ? 1 : 0; }
}
contract ReserveB is IReserve {
    constructor() { revert("synthetic non-deployable fixture"); }
    function value(uint256 amount) external pure returns (uint256) { return amount + 1; }
    function value(bool choice) external pure returns (uint256) { return choice ? 2 : 0; }
}
contract Factory is IFactory {
    constructor() { revert("synthetic non-deployable fixture"); }
    function reserve() external pure returns (IReserve) { return IReserve(address(0)); }
}
contract Controller {
    constructor() { revert("synthetic non-deployable fixture"); }
    function inspect(IFactory factory, uint256 amount, bool choice) external view returns (uint256) {
        IReserve selected = factory.reserve();
        require(choice, "synthetic precondition");
        return selected.value(amount) + factory.reserve().value(choice);
    }
    function choose(IFactory factory) internal view returns (IReserve) { return factory.reserve(); }
    function inspectReturned(IFactory factory, uint256 amount) external view returns (uint256) {
        return choose(factory).value(amount);
    }
}
