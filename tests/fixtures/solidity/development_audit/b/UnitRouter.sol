// SPDX-License-Identifier: UNLICENSED
// Synthetic local audit corpus. Abstract and intentionally non-deployable.
pragma solidity ^0.8.20;

import "./UnitStore.sol";

abstract contract UnitRouter is UnitStore {
    // Invariant: each public unit mutation requires the policy's authorized gateway.
    // Invariant: paused policy prohibits every mutation exposed by this router.
    constructor(address administrator_) UnitStore(administrator_) {}

    function creditUnits(address account, uint256 amount) external onlyGateway whenActive {
        _credit(account, amount);
        _recordMutation(account, "credit");
    }

    function retireUnits(address account, uint256 amount) external onlyGateway whenActive {
        _retire(account, amount);
        _recordMutation(account, "retire");
    }

    function moveUnits(address from, address to, uint256 amount) external onlyGateway whenActive {
        _move(from, to, amount);
        _recordMutation(from, "move");
    }

    function reserveUnits(address account, uint256 nextReserved)
        external onlyGateway whenActive
    {
        _reserve(account, nextReserved);
        _recordMutation(account, "reserve");
    }

    function accountState(address account)
        external view returns (uint256 recorded, uint256 reserved, uint256 available)
    {
        return (units[account], reservedUnits[account], availableUnits(account));
    }

    function policyState()
        external view returns (address selectedGateway, bool operationsPaused, uint256 revision)
    {
        return (gateway, paused, policyRevision);
    }

    // Deliberately unimplemented: this corpus cannot be deployed as a runtime target.
    function _recordMutation(address account, bytes32 kind) internal virtual;
}
