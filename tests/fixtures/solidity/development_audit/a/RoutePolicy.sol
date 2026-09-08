// SPDX-License-Identifier: UNLICENSED
// Synthetic local audit corpus. Abstract, non-production, no funds or network use.
pragma solidity ^0.8.20;

abstract contract RoutePolicy {
    // Invariant: only the administrator may select the gateway trusted by all unit mutations.
    address public immutable administrator;
    address public gateway;
    bool public paused;
    uint256 public policyRevision;
    uint256 public issuanceLimit;
    uint256 public accountCreditLimit;

    event GatewayChanged(address indexed previousGateway, address indexed nextGateway);
    event CreditLimitsChanged(uint256 issuance, uint256 accountCredit);
    event PauseChanged(bool paused);

    constructor(address administrator_) {
        require(administrator_ != address(0), "administrator required");
        administrator = administrator_;
        issuanceLimit = 1_000_000;
        accountCreditLimit = 10_000;
    }

    modifier onlyAdministrator() {
        require(msg.sender == administrator, "administrator required");
        _;
    }

    modifier onlyGateway() {
        require(gateway != address(0) && msg.sender == gateway, "gateway required");
        _;
    }

    modifier whenActive() {
        require(!paused, "unit operations paused");
        _;
    }

    function setGateway(address nextGateway) external {
        require(nextGateway != address(0), "gateway required");
        address previous = gateway;
        gateway = nextGateway;
        policyRevision += 1;
        emit GatewayChanged(previous, nextGateway);
    }

    // These limits restrict new credits; changing them does not rewrite existing units.
    function setCreditLimits(uint256 issuance, uint256 accountCredit)
        external onlyAdministrator
    {
        require(issuance > 0 && accountCredit > 0, "positive limits required");
        require(accountCredit <= issuance, "account limit exceeds issuance limit");
        issuanceLimit = issuance;
        accountCreditLimit = accountCredit;
        policyRevision += 1;
        emit CreditLimitsChanged(issuance, accountCredit);
    }

    function setPaused(bool nextPaused) external onlyAdministrator {
        paused = nextPaused;
        policyRevision += 1;
        emit PauseChanged(nextPaused);
    }
}
