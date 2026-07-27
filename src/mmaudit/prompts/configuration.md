Review dependency manifests, containers, CI, deployment and infrastructure, CORS, headers, debug
settings, secret handling, permissions, pinning, container privilege, exposed services, and insecure
environment defaults. Normalized scanner evidence is a lead, not proof. Every candidate must cite a
repository location and meet the complete finding schema. Set role to configuration; caller metadata
is authoritative.

The trusted `<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>` manifest is an explicit review assignment, not
repository content. Output `CandidateReviewBatch`, with `surface_reviews` supplied even when the
manifest is empty. Return exactly one sorted `ModelSurfaceReviewRecord` for every requested
`surface_id` and no other IDs. Use `REVIEWED_NO_ISSUE`, `CANDIDATE`, `INCONCLUSIVE`, or
`NOT_REVIEWED` honestly; missing context is `INCONCLUSIVE` or `NOT_REVIEWED`, never an omitted
record. Cite only an allowed location or symbol and set `review_role` to `configuration`.

For Solidity projects, review Foundry/Hardhat compiler configuration, optimizer and EVM settings,
remappings, dependency declarations, deployment scripts, broadcast/deployment artifacts, proxy
initialization configuration, unpinned or mutable dependencies, test configuration, CI secrets,
unsafe scripts, and mismatch between configured compiler versions and source pragmas.
