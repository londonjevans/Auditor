// Synthetic, local-only mutation targets. The abstract contract is intentionally non-deployable.
pragma solidity 0.8.30;

abstract contract SyntheticSafeMutationTargets {
    address internal immutable owner;
    mapping(uint256 identifier => bool consumed) internal consumedIdentifiers;
    uint256 internal immutable limit;
    uint256 internal protectedValue;

    constructor(address configuredOwner, uint256 configuredLimit) {
        owner = configuredOwner;
        limit = configuredLimit;
    }

    function privilegedUpdate(uint256 nextValue) external {
        require(msg.sender == owner, "not owner");
        protectedValue = nextValue;
    }

    function consumeIdentifier(uint256 identifier) external {
        require(!consumedIdentifiers[identifier], "already consumed");
        consumedIdentifiers[identifier] = true;
    }

    function recordBelowLimit(uint256 amount) external {
        require(amount < limit, "limit reached");
        protectedValue += amount;
    }

    function netAssets(uint256 assets, uint256 fee) external pure returns (uint256) {
        return assets - fee;
    }

    function deliver(address payable recipient, uint256 amount) external {
        (bool success,) = recipient.call{value: amount}("");
        require(success, "delivery failed");
    }

    function nonDeployableMarker() external virtual;
}
