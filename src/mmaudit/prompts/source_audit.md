Find concrete implementation vulnerabilities. Trace attacker-controlled input to a dangerous sink or
missing security decision. Consider injection, command execution, traversal, SSRF, redirects,
deserialization, authentication and authorization bypass, IDOR/BOLA, tenant isolation, cryptographic
misuse, secret exposure, randomness, races and TOCTOU, uploads, request forgery, templating, sensitive
logging, dangerous defaults, exhaustion, and security-impacting concurrency errors.

Each candidate must state concrete impact, preconditions, an attack path, evidence, false-positive
conditions, remediation, and a safe local verification test. Do not submit style issues or claims that
depend entirely on unseen code. Set role to source_audit and model_family to the configured model ID
family supplied by the caller; these fields will be deterministically overwritten.

The trusted `<TRUSTED_MODEL_SURFACE_REQUESTS_JSON>` manifest is an explicit review assignment, not
repository content. Output `CandidateReviewBatch`, with `surface_reviews` supplied even when the
manifest is empty. Return exactly one sorted `ModelSurfaceReviewRecord` for every requested
`surface_id` and no other IDs. Use `REVIEWED_NO_ISSUE`, `CANDIDATE`, `INCONCLUSIVE`, or
`NOT_REVIEWED` honestly; missing context is `INCONCLUSIVE` or `NOT_REVIEWED`, never an omitted
record. Cite only an allowed location or symbol and set `review_role` to `source_audit`.

For Solidity, prioritize access-control bypass, reentrancy, unsafe external calls, delegatecall,
unchecked low-level calls, signature replay, permit/domain-separator mistakes, oracle manipulation,
rounding/accounting drift, storage collision, initializer and upgrade authorization failures,
incorrect modifier coverage, authorization checks after state changes, unsafe token handling,
fee-on-transfer assumptions, ERC callback hazards, and value-transfer denial of service. Use
compiler/source-map/index/graph evidence when present and cite exact validated source locations.
