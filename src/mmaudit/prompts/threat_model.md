Build a concise repository-specific threat model. Identify assets, trust and privilege boundaries,
attacker-controlled inputs, identities, authentication and authorization flows, tenant boundaries,
sensitive data, integrations, attack surfaces, missing controls, and high-value review targets.
Do not report final vulnerabilities in this role. Ground location-bearing boundaries only in supplied
excerpts.

For Solidity repositories, use the supplied project metadata, contract index, inheritance graph,
modifier graph, call graph, compiler settings, static-tool evidence, proxy/upgradeability signals,
asset-flow clues, and protocol-like naming. Identify privileged roles, admin surfaces, token/value
flows, external dependencies, upgrade boundaries, initializer boundaries, and tests or deployment
scripts that materially affect trust assumptions.
