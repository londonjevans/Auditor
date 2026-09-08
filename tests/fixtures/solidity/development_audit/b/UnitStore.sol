// SPDX-License-Identifier: UNLICENSED
// Synthetic local audit corpus. Unit counters only; no token or currency transfer.
pragma solidity ^0.8.20;

import "./RoutePolicy.sol";

abstract contract UnitStore is RoutePolicy {
    // Invariant: totalUnits equals the sum of account units after every mutation.
    // Invariant: reserved units never exceed an account's recorded units.
    mapping(address => uint256) public units;
    mapping(address => uint256) public reservedUnits;
    uint256 public totalUnits;
    uint256 public mutationCount;

    event UnitsCredited(address indexed account, uint256 amount);
    event UnitsRetired(address indexed account, uint256 amount);
    event UnitsMoved(address indexed from, address indexed to, uint256 amount);
    event ReservationChanged(address indexed account, uint256 reserved);

    constructor(address administrator_) RoutePolicy(administrator_) {}

    function availableUnits(address account) public view returns (uint256) {
        return units[account] - reservedUnits[account];
    }

    function _credit(address account, uint256 amount) internal {
        require(account != address(0), "account required");
        require(amount > 0, "positive units required");
        uint256 nextBalance = units[account] + amount;
        uint256 nextTotal = totalUnits + amount;
        require(nextBalance <= accountCreditLimit, "account credit limit");
        require(nextTotal <= issuanceLimit, "issuance limit");
        units[account] = nextBalance;
        totalUnits = nextTotal;
        mutationCount += 1;
        emit UnitsCredited(account, amount);
    }

    function _retire(address account, uint256 amount) internal {
        require(amount > 0, "positive units required");
        require(availableUnits(account) >= amount, "available units required");
        units[account] -= amount;
        totalUnits -= amount;
        mutationCount += 1;
        emit UnitsRetired(account, amount);
    }

    function _move(address from, address to, uint256 amount) internal {
        require(to != address(0) && from != to, "distinct accounts required");
        require(amount > 0, "positive units required");
        require(availableUnits(from) >= amount, "available units required");
        require(units[to] + amount <= accountCreditLimit, "account credit limit");
        units[from] -= amount;
        units[to] += amount;
        mutationCount += 1;
        emit UnitsMoved(from, to, amount);
    }

    function _reserve(address account, uint256 nextReserved) internal {
        require(nextReserved <= units[account], "recorded units required");
        reservedUnits[account] = nextReserved;
        mutationCount += 1;
        emit ReservationChanged(account, nextReserved);
    }
}
