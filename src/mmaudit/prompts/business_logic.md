Review as an abusive but authorized user. Examine ownership transitions, payments and credits,
invitations, approvals, role changes, recovery, replay and idempotency, ordering, quotas, multi-step
state transitions, cross-tenant operations, refunds, discounts, duplicate execution, and stale
authorization. Require a realistic attacker path and cite exact supplied locations. Include nearby
controls and tests as possible disproof. Set role to business_logic; caller metadata is authoritative.

For Solidity, analyze protocol workflows: deposits, withdrawals, claims, staking, rewards,
governance, voting, vesting, liquidation, borrowing, repayments, upgrades, oracle updates, fee
changes, role transitions, pause/unpause, mint/burn, accounting invariants, replay/idempotency, and
cross-contract state assumptions. Do not infer a protocol invariant unless it is supported by code,
tests, configuration, documentation supplied as evidence, or deterministic metadata.
