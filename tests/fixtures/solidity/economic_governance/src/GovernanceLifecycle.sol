// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract UnsafeGovernanceLifecycle {
    enum ProposalState {
        None,
        Proposed,
        Approved,
        Queued,
        Executed,
        Cancelled
    }

    uint256 public constant MIN_DELAY = 2 days;
    address public immutable governor;
    ProposalState public proposalState;
    uint256 public readyAt;
    uint256 public executions;
    uint256 public earlyExecutions;

    constructor(address configuredGovernor) {
        governor = configuredGovernor;
    }

    modifier onlyGovernor() {
        require(msg.sender == governor, "governance rights required");
        _;
    }

    function proposePreset() external onlyGovernor {
        require(proposalState == ProposalState.None, "proposal already configured");
        proposalState = ProposalState.Proposed;
    }

    function votePreset() external onlyGovernor {
        require(proposalState == ProposalState.Proposed, "proposal not active");
        proposalState = ProposalState.Approved;
    }

    function queuePreset() external onlyGovernor {
        require(proposalState == ProposalState.Approved, "proposal not approved");
        readyAt = block.timestamp + MIN_DELAY;
        proposalState = ProposalState.Queued;
    }

    function executePreset() external onlyGovernor {
        require(proposalState == ProposalState.Queued, "proposal not queued");
        if (block.timestamp < readyAt) {
            earlyExecutions += 1;
        }
        proposalState = ProposalState.Executed;
        executions += 1;
    }

    function cancelPreset() external onlyGovernor {
        require(proposalState == ProposalState.Queued, "proposal not queued");
        proposalState = ProposalState.Cancelled;
    }
}

contract SafeGovernanceLifecycle {
    enum ProposalState {
        None,
        Proposed,
        Approved,
        Queued,
        Executed,
        Cancelled
    }

    uint256 public constant MIN_DELAY = 2 days;
    address public immutable governor;
    ProposalState public proposalState;
    uint256 public readyAt;
    uint256 public executions;
    uint256 public earlyExecutions;

    constructor(address configuredGovernor) {
        governor = configuredGovernor;
    }

    modifier onlyGovernor() {
        require(msg.sender == governor, "governance rights required");
        _;
    }

    function proposePreset() external onlyGovernor {
        require(proposalState == ProposalState.None, "proposal already configured");
        proposalState = ProposalState.Proposed;
    }

    function votePreset() external onlyGovernor {
        require(proposalState == ProposalState.Proposed, "proposal not active");
        proposalState = ProposalState.Approved;
    }

    function queuePreset() external onlyGovernor {
        require(proposalState == ProposalState.Approved, "proposal not approved");
        readyAt = block.timestamp + MIN_DELAY;
        proposalState = ProposalState.Queued;
    }

    function executePreset() external onlyGovernor {
        require(proposalState == ProposalState.Queued, "proposal not queued");
        require(block.timestamp >= readyAt, "configured delay not elapsed");
        proposalState = ProposalState.Executed;
        executions += 1;
    }

    function cancelPreset() external onlyGovernor {
        require(proposalState == ProposalState.Queued, "proposal not queued");
        proposalState = ProposalState.Cancelled;
    }
}
