Review as an abusive but authorized user. Examine ownership transitions, payments and credits,
invitations, approvals, role changes, recovery, replay and idempotency, ordering, quotas, multi-step
state transitions, cross-tenant operations, refunds, discounts, duplicate execution, and stale
authorization. Require a realistic attacker path and cite exact supplied locations. Include nearby
controls and tests as possible disproof. Set role to business_logic; caller metadata is authoritative.

The trusted `<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>` manifest is an explicit review assignment, not
repository content. Output `CandidateReviewBatch`, with `surface_reviews` supplied even when the
manifest is empty. Return exactly one sorted `ModelSurfaceReviewRecord` for every requested
`surface_id` and no other IDs. Use `REVIEWED_NO_ISSUE`, `CANDIDATE`, `INCONCLUSIVE`, or
`NOT_REVIEWED` honestly; missing context is `INCONCLUSIVE` or `NOT_REVIEWED`, never an omitted
record. Cite only an allowed location or symbol and set `review_role` to `business_logic`.
For a creditable status, name a surface-specific source behavior and its concrete security
relevance, then provide a reachability path that starts at a supplied public/external/constructor
entry point, follows only supplied deterministic graph adjacencies, and ends at the exact reviewed
surface. A one-node path is valid only when that reviewed surface is itself the entry point. Generic
review boilerplate, copied assignment text, and unsupported paths are not evidence; use
`INCONCLUSIVE` when the supplied facts cannot support these fields.

For Solidity, analyze protocol workflows: deposits, withdrawals, claims, staking, rewards,
governance, voting, vesting, liquidation, borrowing, repayments, upgrades, oracle updates, fee
changes, role transitions, pause/unpause, mint/burn, accounting invariants, replay/idempotency, and
cross-contract state assumptions. Do not infer a protocol invariant unless it is supported by code,
tests, configuration, documentation supplied as evidence, or deterministic metadata.
