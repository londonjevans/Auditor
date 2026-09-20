# Synthetic modifier coverage controls

These minimal sources are non-production, local-only defensive controls. They
contain no funds, credentials, dependencies, network access or public endpoints.
The constructor refuses nonlocal chain identity and zero timestamp. No deployment
outside a disposable local test environment is intended.

The declared invariants are: a blocked operation preserves the counter, and one
permitted operation increments it exactly once. Separate tests exercise both
paths through the same modifier placeholder. Compiler/debug/bytecode artifacts
are observations only; missing execution information is not inferred from a
nearby statement, and no audit, qualification or release authority follows.
