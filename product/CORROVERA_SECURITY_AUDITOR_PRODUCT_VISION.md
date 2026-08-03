# Corrovera Security Auditor

## Product Vision and Target-State Specification

**Status:** North-star product and engineering specification<br>
**Primary product scope:** Solidity and EVM smart-contract systems<br>
**Delivery model:** Fully autonomous, website-purchased security audit<br>
**Model access layer:** OpenRouter, with a continuously refreshed and policy-filtered model registry<br>
**Core promise:** The deepest practical multi-model smart-contract audit, with evidence strong enough that every published finding is defensible, source-bound, independently challenged, and dynamically validated whenever validation is feasible

---

## 1. Purpose of this document

This document defines what Corrovera Security Auditor is intended to become.

It is a target-state specification, not a statement that the current implementation already satisfies every requirement. It should be used to guide product design, system architecture, implementation priorities, testing, release gates, marketing claims, and independent evaluation.

The system is intended to be the most capable autonomous smart-contract security auditor in the world. It should combine:

- the best eligible frontier AI models available through OpenRouter;
- deterministic Solidity and EVM analysis;
- specialist model reviewers with genuinely different responsibilities;
- static analysis, semantic graphs, fuzzing, invariant testing, symbolic execution, formal verification, and economic simulation;
- source-bound validation and false-positive rejection;
- realistic local or forked-chain reproduction;
- an evidence-capped consensus process;
- a concise client-facing audit report and a complete forensic evidence bundle;
- a fully autonomous web product through which a customer can purchase an audit, connect or upload a repository, and receive the finished result without an internal operator manually running the audit.

The ambition is not merely to generate a large number of possible issues. The system must maximize discovery while minimizing false claims. A finding is valuable only when it is real, reachable, relevant to the audited code, correctly located, correctly characterized, and presented with the evidence needed for a client to act on it.

---

## 2. Mission

Corrovera Security Auditor exists to make elite smart-contract security review:

- deeper;
- more repeatable;
- more evidence-driven;
- more scalable;
- more transparent;
- more accessible;
- less dependent on one auditor's memory, available time, or specialist background.

The system should review a protocol with the breadth of a large expert audit team, the reproducibility of a deterministic engineering pipeline, and the adversarial skepticism of an independent verification laboratory.

Its long-term standard is:

> No important surface is ignored, no model opinion is treated as proof, no finding is published without validation, no unavailable analysis is hidden, and no clean report is represented as a guarantee of safety.

---

## 3. Product promise

A customer should be able to:

1. Create an account on the Corrovera website.
2. Select an audit product and scope.
3. Connect a Git provider, upload an immutable repository snapshot, or identify a specific commit.
4. Declare the relevant chains, deployments, proxy addresses, prior audits, protocol documentation, and expected off-chain components.
5. Choose a privacy profile and approve the estimated model/tool budget.
6. Pay for the audit.
7. Allow the autonomous system to perform preflight, analysis, testing, validation, reporting, and quality assurance.
8. Monitor audit progress from a client portal.
9. Receive:
   - a concise executive audit report;
   - detailed, evidence-rich findings;
   - source-validated locations and code excerpts;
   - reproduction, counterexample, or proof status;
   - remediation guidance;
   - coverage and limitation disclosures;
   - a complete forensic evidence bundle;
   - a machine-readable JSON report and SARIF output;
   - an immutable run manifest proving exactly what was analyzed and what executed.
10. Optionally purchase remediation verification or a re-audit against a later commit.

After the customer completes the required scope, consent, and payment steps, the audit should run without an internal operator manually choosing models, copying prompts, executing scanners, interpreting raw tool output, or assembling the report.

“Fully autonomous” does not mean concealing problems. If a mandatory component cannot run, the system must fail or explicitly downgrade the audit, explain what is missing, and tell the client what is required to proceed.

---

## 4. What “best in class” means

“Best in class” is an empirical quality standard, not a marketing adjective.

The system should be designed to outperform excellent professional smart-contract audit teams in aggregate coverage, reproducibility, consistency, evidence quality, and time to completion. It may claim that superiority only after blind, independently adjudicated comparisons support the claim.

Best-in-class performance requires all of the following.

### 4.1 Discovery quality

The system must demonstrate:

- exceptionally high recall for critical and high-severity vulnerabilities;
- strong detection of cross-contract and business-logic failures;
- strong detection of economic and state-machine defects;
- strong detection of upgrade, storage-layout, initialization, authorization, oracle, token-integration, governance, bridge, replay, and denial-of-service defects;
- high safe-near-miss rejection;
- low invalid-location and invalid-reachability rates;
- the ability to find previously unknown issues, not merely replay known benchmark labels.

### 4.2 Evidence quality

Every published finding must have:

- a stable finding identifier;
- an exact repository path;
- a validated source range;
- a hash of the exact reviewed excerpt;
- the affected contract, function, state, and call path;
- the violated security property;
- realistic prerequisites;
- a defensible impact statement;
- evidence from independent methods where available;
- independent verification and falsification;
- a clear dynamic, symbolic, formal, or deterministic validation status;
- a remediation recommendation;
- a safe regression-test recommendation;
- explicit residual uncertainty.

### 4.3 Truthfulness

The system must never:

- call a run complete when required analysis did not run;
- describe binary availability as successful execution;
- describe generated tests as executed tests;
- describe model agreement as confirmation;
- describe a failed reproduction as proof that an issue is false;
- hide missing tools, model failures, timeouts, or omitted source;
- reduce coverage denominators by silently dropping difficult surfaces;
- describe internal fixtures as proof of real-world discovery quality;
- claim superiority without a blind and independently adjudicated comparison.

### 4.4 Client usefulness

The primary report must be understandable by:

- protocol founders;
- chief technology officers;
- smart-contract engineers;
- security teams;
- governance participants;
- investors and counterparties assessing technical risk.

It must be concise enough to read, detailed enough to act upon, and backed by a forensic bundle that allows a security expert to verify every conclusion.

---

## 5. Initial product scope

The first best-in-class product is a **Solidity and EVM smart-contract security auditor**.

It should support:

- Foundry projects;
- Hardhat projects;
- mixed Foundry/Hardhat projects;
- plain Solidity repositories;
- multi-package monorepos;
- proxy and upgradeable systems;
- DeFi protocols;
- token systems;
- vaults;
- lending and liquidation systems;
- staking and rewards;
- governance;
- bridges and cross-chain components;
- deployment and initialization tooling;
- relevant off-chain assumptions supplied with the audit.

The platform may later add first-class security engines for other languages and chains, but it must not imply equivalent coverage before those language-specific capabilities exist.

A generic source review for non-Solidity repositories may be offered as a separate, clearly reduced product. It must not inherit the Solidity/EVM maximum-assurance claim.

---

## 6. Core product principles

### 6.1 Evidence before confidence

Confidence must come from source, semantics, tests, counterexamples, proof, and independent challenge—not model eloquence.

### 6.2 Diversity before repetition

Calling the same base model many times does not create an independent audit team. The system must distinguish model IDs, providers, versions, aliases, and root lineages.

### 6.3 Complete scope before selective review

The system must inventory the full repository and explicitly account for every contract, entry point, privilege surface, asset-moving operation, external call, upgrade path, and declared protocol component.

### 6.4 Sharding without losing context

Large repositories must be reviewed in coherent architectural shards. A function must not be separated from its modifiers, inherited controls, relevant callers, relevant callees, state dependencies, or protocol invariants.

### 6.5 Blind discovery before consensus

Primary reviewers must independently discover issues before they see peer findings. This reduces herding and preserves genuine independence.

### 6.6 Falsification before publication

Every serious candidate must be challenged. The system should actively search for controls, assumptions, unreachable paths, incorrect attacker capabilities, and existing tests that invalidate the candidate.

### 6.7 Fail closed

Missing mandatory analysis cannot become “completed with zero findings.” It must result in a failed, incomplete, inconclusive, or explicitly downgraded run.

### 6.8 Reproducibility

Every audit must be bound to exact source, configuration, prompts, schemas, models, provider endpoints, tool versions, compiler versions, random seeds, isolation image, and evidence artifacts.

### 6.9 Customer privacy is explicit

Privacy policy, endpoint routing, and source-code retention must be transparent and selected before source is sent to a model.

### 6.10 The auditor itself is a high-risk system

An audited repository may be malicious. Compilation, tests, scanners, build scripts, plugins, and generated files must be treated as untrusted execution.

---

## 7. End-to-end client journey

### 7.1 Account and purchase

The website should provide:

- secure authentication;
- organization and team accounts;
- role-based access;
- audit package selection;
- transparent pricing or a preflight estimate;
- payment authorization;
- invoices and receipts;
- data-processing and privacy disclosures;
- optional enterprise terms;
- a record of the customer's authorization to audit the repository.

### 7.2 Repository onboarding

The customer should be able to:

- connect GitHub, GitLab, or another supported provider;
- select an organization, repository, branch, and commit;
- upload an immutable archive;
- provide submodule access;
- specify private dependencies;
- declare the contracts, chains, deployments, and scope;
- provide architecture documents and protocol specifications;
- optionally provide prior audits that remain hidden until blind discovery is complete;
- provide an offline deployment snapshot or authorize read-only snapshot import;
- identify excluded files and explain exclusions.

The system must freeze the source snapshot before analysis and show the customer exactly what will be audited.

### 7.3 Privacy and model consent

The customer must choose a privacy profile before the audit starts.

Recommended profiles:

#### Strict confidential mode

- only endpoints meeting the configured zero-retention and no-training requirements;
- only approved providers;
- no unapproved fallback;
- source never sent to an endpoint outside the policy;
- the report states which high-quality models were excluded by the privacy policy.

#### Frontier ensemble mode with explicit consent

- permits selected frontier endpoints that do not meet strict zero-retention requirements;
- requires explicit, source-bound, time-limited customer consent;
- displays the model, provider, endpoint, and applicable retention policy;
- prohibits silent activation;
- still excludes secrets and unrelated repository content;
- uses exact provider allowlists and no unapproved fallback.

#### Public or synthetic benchmark mode

- used for public repositories and internal quality testing;
- may evaluate a wider model pool;
- must not be automatically applied to private client source.

The long-term product goal should be to secure commercial arrangements or approved private endpoints that make leading frontier models available under strong confidentiality terms.

### 7.4 Preflight and quote

Before payment is finalized or irreversible model spending begins, the system should determine:

- repository size;
- language and framework;
- dependency availability;
- compilation feasibility;
- expected number of shards;
- expected number of model calls;
- selected model ensemble;
- estimated context and output tokens;
- scanner and formal-tool applicability;
- likely fork or snapshot requirements;
- estimated runtime;
- estimated cost;
- whether the requested assurance level is feasible.

An audit that cannot satisfy its advertised assurance gates must be rejected, re-scoped, or explicitly downgraded before execution.

### 7.5 Autonomous execution

The platform should:

- create a durable job;
- allocate isolated workers;
- run deterministic discovery;
- build the threat model and security properties;
- run scanners and semantic analysis;
- schedule model reviews;
- validate candidates;
- run dynamic and formal validation;
- reconcile findings;
- generate reports;
- run internal quality gates;
- deliver the finished artifacts.

### 7.6 Delivery and follow-up

The portal should provide:

- live phase status;
- prominent blockers;
- cost and budget status;
- completed analyses;
- secure report download;
- machine-readable artifacts;
- questions and clarification workflow;
- remediation tracking;
- re-audit purchase;
- verification against a remediation commit;
- data deletion controls.

---

## 8. High-level system architecture

The production system should contain the following major subsystems.

### 8.1 Web application and client portal

Responsible for:

- authentication;
- organizations;
- billing;
- repository connections;
- audit configuration;
- consent;
- status;
- report delivery;
- retention controls;
- support workflow.

### 8.2 Audit control plane

Responsible for:

- validating customer scope;
- freezing source;
- generating job manifests;
- selecting privacy and assurance profiles;
- estimating cost;
- resolving the daily model registry;
- creating the execution graph;
- scheduling workers;
- tracking retries;
- enforcing budgets;
- enforcing completion gates;
- resuming interrupted audits.

### 8.3 Secure repository ingestion service

Responsible for:

- immutable source snapshots;
- commit and tree identity;
- submodule and dependency recording;
- secret exclusion;
- path normalization;
- symlink and hardlink rejection;
- file-count and size limits;
- generated-output classification;
- prompt-injection delimiting;
- source excerpt hashing.

### 8.4 Isolated analysis workers

Separate worker pools should exist for:

- compilation;
- deterministic scanners;
- semantic indexing;
- fuzzing and invariant testing;
- symbolic execution;
- formal verification;
- forked-chain validation;
- report generation.

Untrusted repository code must execute only in hardened disposable environments.

### 8.5 Model orchestration service

Responsible for:

- daily model discovery;
- policy eligibility;
- quality qualification;
- role routing;
- shard construction;
- prompt assembly;
- request execution;
- output validation;
- retry and resharding;
- model lineage accounting;
- cost accounting;
- blind-review ordering;
- cross-examination;
- verifier and falsifier scheduling.

### 8.6 Evidence and artifact store

Stores:

- immutable run manifests;
- source hashes;
- model metadata snapshots;
- provider endpoint snapshots;
- prompts and schema hashes;
- tool output;
- semantic graphs;
- candidate history;
- reproduction artifacts;
- proofs and counterexamples;
- reports;
- cost ledgers;
- replay data.

### 8.7 Benchmark and certification service

Responsible for:

- model qualification;
- product benchmark execution;
- mutation testing;
- release certification;
- stale-certificate detection;
- regression detection;
- superiority claim gates.

---

## 9. Daily OpenRouter model intelligence

The model list must not be a static hand-edited file.

The system must maintain a **daily, versioned, policy-aware model registry**.

It should refresh at least every 24 hours and again before each new audit begins.

### 9.1 Discovery

The discovery job should:

1. Query the authenticated OpenRouter model list available to the Corrovera account.
2. Query canonical model details.
3. Query every relevant provider endpoint for each candidate model.
4. Record:
   - canonical model ID;
   - aliases;
   - model author;
   - creation or availability date;
   - deprecation date;
   - context limit;
   - output limit;
   - supported parameters;
   - reasoning support;
   - structured-output support;
   - tool support;
   - input and output modalities;
   - provider endpoints;
   - provider slugs;
   - pricing;
   - throughput and latency data where available;
   - data-retention policy;
   - training/data-collection policy;
   - regional restrictions;
   - current operational status.
5. Compare the result with the previous snapshot.
6. Trigger qualification when:
   - a new potentially high-quality model appears;
   - an existing model changes endpoint or capability;
   - pricing materially changes;
   - a model is deprecated;
   - a provider policy changes;
   - a previously approved model becomes unavailable.

Every audit must pin the exact registry snapshot used at job start.

### 9.2 Policy eligibility

OpenRouter availability alone does not mean a model is eligible.

A model and endpoint may participate only when the system has current evidence that:

- the model provider's terms permit the intended defensive smart-contract security analysis;
- commercial, customer-facing use is permitted;
- source-code analysis is permitted;
- the client's entity and location are permitted;
- the Corrovera entity and location are permitted;
- the provider endpoint is available to the account;
- the requested privacy mode is satisfied;
- the output may be incorporated into a commercial audit report;
- no relevant model or provider restriction prohibits the use case;
- the task templates remain inside the permitted defensive scope.

The platform must maintain a `ModelPolicyEligibility` record for every model-endpoint pair.

Suggested states:

- `ELIGIBLE`
- `ELIGIBLE_WITH_CUSTOMER_CONSENT`
- `ELIGIBLE_FOR_PUBLIC_OR_SYNTHETIC_ONLY`
- `PENDING_POLICY_REVIEW`
- `INELIGIBLE`
- `SUSPENDED`
- `RETIRED`

Unknown or ambiguous policy status must default to exclusion.

The policy registry must record:

- official source reviewed;
- policy version or retrieval timestamp;
- allowed and prohibited use notes;
- geographic and entity restrictions;
- privacy restrictions;
- commercial-use status;
- reviewer or automated decision provenance;
- expiry or next review date.

A daily automated policy check may flag changes, but ambiguous legal or provider-policy questions should be resolved by a platform-level compliance review. This does not prevent customer audits from being autonomous; it ensures the approved model pool is governed responsibly.

### 9.3 Capability eligibility

A model must also satisfy minimum technical requirements for its assigned roles, such as:

- enough context for the planned shard;
- enough output capacity;
- reliable structured output or a validated JSON protocol;
- strong source-code comprehension;
- support for reasoning where required;
- low truncation rate;
- acceptable latency;
- stable endpoint identity;
- cost compatible with the product tier.

### 9.4 Security-audit qualification

A model must not be called “top-tier” merely because it is marketed as frontier.

It must pass a versioned Corrovera benchmark covering:

- Solidity vulnerability analysis;
- multi-contract business logic;
- accounting and conservation;
- access control;
- oracle and pricing assumptions;
- proxies, upgrades, and storage;
- signatures, permits, nonces, and replay;
- economic invariants;
- false-positive rejection;
- safe-near-miss rejection;
- exact source-location accuracy;
- reachability analysis;
- structured-output reliability;
- prompt-injection resistance;
- verifier performance;
- falsifier performance;
- remediation quality.

The benchmark must include vulnerable and safe controls.

A model may be approved only for the roles it performs well.

### 9.5 Lineage independence

The registry must distinguish:

- exact model ID;
- model version;
- model author;
- root model lineage;
- provider endpoint;
- hosting provider;
- aliases;
- quantizations;
- fine-tunes;
- mirrors.

The same underlying model hosted by several providers counts as one root lineage.

Repeated calls to one model do not create independent agreement.

### 9.6 Production model set

The production audit should use:

- every qualified, policy-eligible Tier-A frontier model supported by the selected privacy profile and product budget;
- multiple independent root lineages;
- whole-protocol reviews from each major lineage;
- specialist routing based on measured benchmark strengths;
- redundant independent review of critical surfaces;
- multiple independent verifiers and falsifiers.

Exact model and provider endpoint selection must be pinned for the audit. Certification runs must not use an opaque automatic router or silently substitute another model.

If an approved model becomes unavailable during an audit:

- retry the same approved endpoint within bounds;
- use a fallback only when explicitly allowed;
- record the substitution;
- never inherit the original model's qualification automatically;
- downgrade or fail the audit when required lineage coverage is no longer met.

---

## 10. Multi-model audit architecture

The system should operate like a coordinated security organization, not a collection of duplicated prompts.

### 10.1 Whole-protocol orientation

Before specialist review, qualified lead models should receive a compact but complete representation of:

- repository structure;
- architecture;
- asset inventory;
- roles;
- trust boundaries;
- critical state;
- contract relationships;
- deployment model;
- upgrade model;
- external dependencies;
- protocol specifications;
- semantic graphs;
- coverage inventory.

Each independent frontier lineage should perform a blind whole-protocol orientation pass.

### 10.2 Coherent sharding

The repository should be partitioned into review units based on:

- package boundaries;
- inheritance clusters;
- strongly connected call-graph components;
- shared accounting state;
- asset-flow boundaries;
- privilege boundaries;
- proxy and implementation relationships;
- oracle dependencies;
- bridge relationships;
- deployment and initialization relationships.

A shard should include:

- primary source;
- relevant interfaces;
- inherited modifiers;
- relevant callers and callees;
- graph slices;
- state definitions;
- security properties;
- scanner evidence;
- stable surface IDs;
- exact source hashes;
- declared omitted dependencies.

### 10.3 Specialist roles

The system should maintain a broad specialist catalogue, including at least:

1. Protocol threat-model lead
2. Architecture and trust-boundary reviewer
3. General Solidity source auditor
4. Cross-contract business-logic auditor
5. Access-control specialist
6. Privilege-escalation specialist
7. Reentrancy and callback specialist
8. Accounting and conservation specialist
9. Invariant specialist
10. Oracle and price-manipulation specialist
11. AMM and liquidity specialist
12. Lending and liquidation specialist
13. Vault and ERC-4626 specialist
14. Token-standard specialist
15. Non-standard token behavior specialist
16. Precision and rounding specialist
17. MEV and transaction-ordering specialist
18. Governance and timelock specialist
19. Upgradeability and storage-layout specialist
20. Initialization and deployment specialist
21. Signature, permit, nonce, and replay specialist
22. Cross-chain and bridge specialist
23. Gas, state-growth, and denial-of-service specialist
24. Assembly, Yul, and low-level EVM specialist
25. Dependency and supply-chain specialist
26. Keeper, relayer, and off-chain dependency specialist
27. Formal-property specialist
28. Fuzz and invariant-harness specialist
29. Economic simulation specialist
30. Reproduction planner
31. Independent verifier
32. Independent falsifier
33. Severity and economic-impact reviewer
34. Evidence-quality reviewer
35. Client-report reviewer

Roles should be activated based on detected protocol features. A bridge specialist is mandatory when bridge logic exists; it should not be run merely to create volume on a repository with no bridge surface.

### 10.4 Blind discovery

During initial review:

- agents do not see peer findings;
- agents do not see prior audit findings;
- agents receive only the relevant source and deterministic evidence;
- each output is source-bound and schema-validated.

### 10.5 Per-surface review records

A model review must explicitly state which surfaces it reviewed.

Each review record should include:

- stable surface ID;
- contract and function;
- role;
- `REVIEWED_NO_ISSUE`, `CANDIDATE`, `INCONCLUSIVE`, or `NOT_REVIEWED`;
- security property considered;
- concise rationale;
- exact source reference;
- assumptions;
- confidence.

A surface is not considered reviewed merely because it appeared somewhere in the prompt.

### 10.6 Risk-tiered coverage

Security surfaces should be classified deterministically.

#### Tier 0: critical

Examples:

- asset custody and movement;
- mint, burn, deposit, withdraw, redeem, claim, and liquidation;
- privileged configuration;
- upgrades and initialization;
- signature validation;
- nonce and replay state;
- oracle use;
- bridge message validation;
- delegatecall;
- low-level calls;
- emergency controls;
- sensitive external calls before state updates.

Every Tier-0 surface should receive at least three substantive reviews from independent qualified root lineages.

#### Tier 1: high risk

Examples:

- public or external state changes;
- accounting mutations;
- role management;
- fee and reward calculations;
- protocol configuration.

Every Tier-1 surface should receive at least two independent qualified reviews.

#### Tier 2: supporting

Examples:

- important internal transitions;
- supporting libraries;
- secondary accounting helpers.

Every Tier-2 surface should receive at least one qualified model review plus deterministic analysis.

#### Tier 3: low risk

Examples:

- simple views;
- constants;
- events;
- basic getters.

These may use deterministic review plus risk-based sampling, while still remaining in the repository inventory.

### 10.7 Truncation and retries

The system must estimate output size before each call.

If a response truncates:

- preserve complete valid records;
- mark incomplete records invalid;
- split the shard;
- retry smaller child shards;
- never resend the same infeasible request unchanged;
- never discard valid findings because a coverage appendix was malformed.

Finding extraction, coverage accounting, and shard summaries must be separable.

### 10.8 Cross-shard integration

After shard review, the system must run dedicated reviews for:

- cross-contract call paths;
- cross-shard accounting;
- proxy and implementation interactions;
- asset flows crossing modules;
- governance and upgrade dependencies;
- oracle consumers;
- bridge message flows;
- deployment-state consistency.

### 10.9 Cross-examination

High-value candidates should be anonymized and sent to independent lineages that:

- attempt to support the candidate;
- attempt to disprove the candidate;
- identify missing prerequisites;
- search for compensating controls;
- assess reachability;
- assess impact.

### 10.10 Verification, falsification, and judgment

No single conservative verifier should silently remove a credible candidate.

For high and critical candidates, use multiple independent validators.

Each must return:

- `SUPPORT`
- `DISPUTE`
- `INCONCLUSIVE`

with exact evidence.

Deterministic aggregation should decide the maximum allowed finding state. A final judge may organize, rank, and explain findings, but may not increase evidence beyond the deterministic cap.

---

## 11. Repository ingestion and scope integrity

Before model review, the system must:

- freeze the exact source commit or archive;
- record dirty state where applicable;
- hash all relevant source;
- validate repository boundaries;
- reject path traversal;
- reject escaping symlinks and hardlinks;
- exclude `.git`;
- exclude `.env` and secret files;
- exclude private keys, wallets, credentials, and generated private output;
- classify dependencies;
- apply file and context limits;
- detect prompt-injection content;
- treat documentation and comments as untrusted evidence;
- record every exclusion.

Scope should include, where present:

- production contracts;
- interfaces;
- libraries;
- deployment scripts;
- initialization;
- upgrade scripts;
- compiler and optimizer settings;
- storage layout;
- dependency lockfiles;
- role and governance configuration;
- oracle configuration;
- bridge adapters;
- keepers and relayers;
- front-end transaction construction where included in the product tier;
- prior audit remediation status.

For a full-protocol audit, the client must provide or approve an expected-component manifest. Missing components must not silently become “not applicable.”

---

## 12. Deterministic Solidity and EVM analysis

### 12.1 Project detection

Detect:

- Foundry;
- Hardhat;
- mixed projects;
- plain Solidity;
- monorepos;
- compiler versions;
- optimizer settings;
- EVM version;
- remappings;
- dependency layout;
- expected test commands.

### 12.2 Compilation

Compilation should:

- run in hardened isolation;
- use trusted pinned toolchains;
- use a sanitized environment;
- exclude target `.env`;
- avoid package lifecycle execution;
- keep source read-only;
- write only to a disposable workspace;
- record compiler output and artifacts;
- preserve source mappings and AST.

Compilation failure must prevent maximum-assurance completion.

### 12.3 Semantic index

Build a source-bound index of:

- contracts;
- interfaces;
- libraries;
- functions;
- modifiers;
- events;
- errors;
- structs;
- enums;
- state variables;
- constants;
- immutables;
- inheritance;
- calls;
- source mappings;
- storage layout.

### 12.4 Graphs

Generate:

- inheritance graph;
- modifier graph;
- internal-call graph;
- external-call graph;
- low-level-call graph;
- delegatecall graph;
- state-read/write graph;
- state-ordering graph;
- asset-flow graph;
- privilege graph;
- governance/timelock graph;
- oracle dependency graph;
- proxy/implementation graph;
- storage-layout graph;
- cross-chain message graph;
- deployment/initialization graph;
- off-chain dependency graph.

Every graph edge must retain path, source range, hash, confidence, and provenance.

### 12.5 Scanners

Use a complementary portfolio, such as:

- Slither;
- Semgrep;
- dependency scanners;
- secret scanners;
- filesystem and supply-chain scanners;
- compiler diagnostics;
- configured CodeQL or equivalent tools where applicable.

Availability is not execution. Every scanner record must include version, binary hash, isolation status, target, result, and failure reason.

---

## 13. Security properties and invariant discovery

The system must derive and validate protocol-specific properties.

Categories include:

### Authorization

- only permitted roles can perform privileged operations;
- ownership, role, governor, multisig, and timelock boundaries are consistent;
- emergency powers match the threat model.

### Initialization and upgrade

- initialization occurs exactly once;
- reinitializers are correctly bounded;
- implementation upgrades are authorized;
- proxy state remains compatible;
- storage layout is safe;
- upgrade scripts and deployed state are consistent.

### Accounting and solvency

- assets and liabilities reconcile;
- shares and assets convert consistently;
- supply and balances conserve;
- fees remain bounded;
- users cannot claim twice;
- reward indices remain consistent;
- debt and collateral remain coherent;
- liquidation preserves intended invariants.

### Oracle and pricing

- freshness;
- decimal normalization;
- sequencer availability;
- manipulation resistance;
- fallback behavior;
- time-weight assumptions;
- dependency failure behavior.

### Token behavior

- standard token assumptions;
- fee-on-transfer behavior;
- rebasing behavior;
- callback behavior;
- non-returning or false-returning tokens;
- approval edge cases;
- ERC-4626 behavior.

### State machines

- no permanent latch;
- no impossible transition;
- pausing behaves consistently;
- cooldowns and epochs progress;
- finalized state is immutable;
- cancellation and recovery paths are viable.

### Signatures and replay

- domain separation;
- nonce updates;
- chain binding;
- expiry;
- replay protection;
- cross-chain uniqueness.

### Governance and ordering

- timelocks;
- proposal state;
- execution ordering;
- vote accounting;
- same-block and MEV assumptions.

Each property must record applicability, source evidence, confidence, testability, validation method, and result.

---

## 14. Dynamic testing, fuzzing, symbolic execution, and formal verification

The system should use multiple independent engines because different methods find different classes of failure.

### 14.1 Foundry

Use:

- unit tests;
- fuzz tests;
- stateful invariant tests;
- replayable seeds;
- minimized call sequences;
- protocol-specific harnesses.

### 14.2 Coverage-guided fuzzers

Use independently implemented fuzzers such as Echidna and Medusa where applicable.

Require:

- FFI disabled;
- no public RPC by default;
- bounded workers;
- bounded time;
- bounded memory;
- corpus retention;
- counterexample replay;
- unsafe and safe controls.

### 14.3 Symbolic execution

Use Halmos or other approved symbolic tools for suitable properties.

Record:

- solver version;
- bounds;
- assumptions;
- unsupported features;
- counterexamples;
- replay status.

### 14.4 Formal verification

Use appropriate formal engines such as Kontrol, Certora, SMTChecker, or other approved systems when the properties and project justify them.

Formal evidence must include:

- exact property;
- assumptions;
- scope;
- tool and version;
- proof result;
- counterexample;
- vacuity checks;
- mutation-based non-vacuity validation.

A proof is only as strong as its specification and assumptions.

### 14.5 Economic simulations

Use deterministic typed templates for:

- vault donation and inflation;
- rounding exploitation;
- oracle manipulation;
- flash-liquidity-sensitive accounting;
- reward manipulation;
- liquidation edge cases;
- fee-on-transfer and rebasing behavior;
- sandwich-sensitive flows;
- governance timing;
- upgrade and initializer misuse;
- cross-chain replay and ordering.

Planning a test does not count as executing it.

---

## 15. Forked-chain validation

Where a candidate depends on real deployed state, integrations, balances, liquidity, proxy configuration, or historical state, the system should validate it against a controlled local fork.

Fork validation must be:

- explicitly authorized;
- local and isolated;
- pinned to an exact chain ID and block;
- reproducible;
- source and bytecode bound;
- non-broadcasting;
- free of production signing keys;
- limited to approved read-only upstream access;
- recorded in the run manifest.

The system must verify:

- the deployed runtime bytecode corresponds to the audited source and compiler configuration;
- proxy and implementation addresses are correct;
- library links and immutable values are accounted for;
- relevant storage slots match the declared deployment;
- attacker capabilities are realistic;
- the decisive behavior is reachable through real interfaces;
- all borrowed value is repaid where required;
- fees, slippage, gas, and settlement are included when material;
- protocol or victim loss is measured;
- the witness replays from a clean fork.

The system must not confirm a finding when the decisive test depends on:

- direct target storage mutation;
- target bytecode replacement;
- impossible privileged impersonation;
- fabricated authority;
- impossible balances;
- arbitrary oracle replacement;
- bypassing timelocks with test-only controls;
- unapproved FFI;
- signing or broadcasting.

A local fork is evidence, not permission to interact with the live protocol.

---

## 16. Finding lifecycle and evidence states

### 16.1 Candidate

A scanner, model, property engine, or reviewer has proposed an issue.

Candidates are private working hypotheses.

### 16.2 Validated candidate

The path, source location, symbol, invariant, and reachability have been checked.

### 16.3 Strongly supported

Multiple independent methods or lineages support the issue, the path is reachable, and no decisive contradiction remains, but a qualifying deterministic confirmation is unavailable.

### 16.4 Confirmed

A finding may be confirmed only when:

- exact source and reachability are validated;
- impact and prerequisites are realistic;
- independent verification accepts it;
- independent falsification does not decisively reject it;
- and qualifying deterministic evidence exists, such as:
  - realistic local reproduction;
  - fork reproduction;
  - symbolic counterexample;
  - formal counterexample;
  - equivalent source-bound deterministic proof.

Model agreement alone can never produce confirmation.

### 16.5 Needs manual review

Credible evidence exists, but disagreement, incomplete scope, unavailable tooling, or unverified assumptions prevent a stronger conclusion.

### 16.6 Inconclusive

The analysis ran but could not support or reject the issue.

### 16.7 Rejected

A candidate is rejected only with a recorded reason, such as:

- unreachable path;
- controlling modifier;
- invalid assumption;
- duplicate;
- safe arithmetic;
- incorrect location;
- impossible attacker capability;
- deterministic contradictory evidence;
- multiple independent falsifiers.

Rejected candidates remain in the forensic bundle.

---

## 17. Severity, confidence, and evidence are separate

A finding must have three independent dimensions.

### Severity

The potential impact if the issue is real:

- Critical
- High
- Medium
- Low
- Informational

### Confidence

The system's confidence in the reasoning and applicability.

### Evidence tier

The strongest validation obtained:

- model hypothesis;
- static support;
- scanner support;
- fuzz counterexample;
- symbolic counterexample;
- realistic local reproduction;
- fork reproduction;
- formal counterexample;
- formal proof;
- rejected.

A severe hypothesis with weak evidence must not be presented as a confirmed critical finding.

---

## 18. Coverage and assurance status

Coverage should be reported separately for:

- files;
- contracts;
- entry points;
- privileged functions;
- asset-moving functions;
- external calls;
- low-level calls;
- state variables;
- branches;
- semantic graph edges;
- upgrade surfaces;
- deployment surfaces;
- security properties;
- scanners;
- model reviews;
- dynamic tests;
- formal properties;
- candidate validation;
- fork validation.

Every metric must include:

- numerator;
- denominator;
- exclusions;
- failures;
- blockers;
- provenance.

Zero denominator is not a pass.

### Run statuses

#### Complete

All mandatory gates for the selected product and privacy profile passed.

#### Degraded

The customer explicitly accepted a lower assurance level before execution.

#### Incomplete

Some meaningful work completed, but the run does not support the advertised conclusion.

#### Failed

A mandatory gate failed or an integrity condition was violated.

#### Inconclusive

The analysis completed but could not reach a supported conclusion on a material issue or scope.

If zero scanners and zero model roles complete, the system must exit non-zero and refuse to issue a “completed, no findings” report.

---

## 19. Client deliverables

### 19.1 Client report

The main report should be approximately a 10–20 page equivalent for a typical audit.

It should contain:

1. Title and audit status
2. Executive risk narrative
3. Scope and source identity
4. Architecture summary
5. Methodology
6. What actually executed
7. Prominent limitations
8. Severity-ordered finding summary
9. Priority remediation roadmap
10. Detailed findings
11. Residual risk
12. Conclusion

Each finding should include:

- title;
- severity;
- confidence;
- evidence tier;
- affected component;
- exact source range;
- a short inline code excerpt with line numbers;
- violated property;
- impact;
- prerequisites;
- reachable path;
- validation status;
- verifier and falsifier result;
- remediation;
- safe verification test;
- residual uncertainty.

### 19.2 Forensic bundle

The forensic bundle should contain:

- full scope inventory;
- source hash manifest;
- all coverage tables;
- model registry snapshot;
- exact model and provider execution records;
- model-role assignments;
- shard manifests;
- scanner results;
- semantic graphs;
- security property catalogue;
- candidate history;
- rejected candidates;
- cross-examination;
- verifier and falsifier decisions;
- dynamic test artifacts;
- fork manifests;
- proofs and counterexamples;
- cost ledger;
- run evidence manifest;
- replay data;
- JSON report;
- SARIF.

### 19.3 Remediation verification

A follow-up product should:

- bind to the original finding IDs;
- compare the remediation commit;
- verify the original mechanism;
- run the original regression;
- search for introduced regressions;
- update closure status;
- produce a concise remediation-verification report.

---

## 20. Autonomous execution and resumability

Every audit should be a durable state machine.

The platform must persist:

- current phase;
- completed phases;
- active shards;
- model requests;
- retries;
- cost;
- candidate states;
- tool execution;
- blockers;
- next action.

An interrupted worker must resume from the last valid checkpoint.

The system should not rerun expensive completed model calls unless integrity requires it.

Retry behavior must be bounded and cause-aware:

- truncation leads to smaller shards;
- schema failure leads to one bounded syntax repair or smaller response protocol;
- rate limit leads to delayed retry;
- model unavailability follows the approved fallback policy;
- policy failure stops the request;
- source mismatch invalidates the run;
- budget exhaustion stops paid calls and marks the unmet gate.

---

## 21. Security and privacy of the auditor

### 21.1 Multi-tenant isolation

Each client job must have:

- separate storage namespace;
- separate encryption context;
- separate job credentials;
- separate artifact access controls;
- no cross-tenant prompt or artifact reuse;
- verifiable deletion.

### 21.2 Execution containment

Untrusted code should run in:

- rootless containers or stronger isolated compute;
- digest-pinned images;
- read-only root filesystem;
- read-only source mount;
- disposable writable output;
- no network by default;
- no container-engine socket;
- no host home;
- no SSH agent;
- no cloud credentials;
- no wallet credentials;
- bounded CPU;
- bounded memory;
- bounded PIDs;
- bounded runtime;
- bounded output;
- explicit trusted `PATH`;
- no privileged mode.

### 21.3 Secret handling

Target repository secrets must never enter:

- model prompts;
- scanner contexts;
- reports;
- logs;
- manifests;
- client-visible artifacts.

Operator service credentials must be separated from target code and delivered only to the component that needs them.

The OpenRouter credential must never enter scanner, compiler, fuzzer, formal, or target-code containers.

### 21.4 Model egress

Before code is sent to a model, the system must record:

- client consent;
- privacy profile;
- exact source scope;
- exact model;
- exact endpoint policy;
- provider;
- reason for selection;
- expiry of consent.

---

## 22. Service platform requirements

A fully autonomous website product requires more than the audit CLI.

The production service should include:

- authenticated API;
- web portal;
- organization and user management;
- role-based access;
- repository connectors;
- secure upload;
- job queue;
- scheduler;
- isolated worker fleet;
- secret management;
- payment and billing;
- per-job budgets;
- cancellation;
- retry policy;
- artifact storage;
- notification service;
- report delivery;
- audit event log;
- support tooling;
- retention and deletion;
- admin controls;
- abuse and policy controls;
- status page and operational monitoring.

The service must support idempotent jobs, durable checkpoints, and immutable evidence.

---

## 23. Cost management

Audit quality should not be strangled by arbitrary token caps, but spending must remain controlled.

The system should:

- estimate the complete audit before execution;
- reserve worst-case cost before each model request;
- reconcile actual usage after each response;
- prevent parallel requests from exceeding the budget;
- show the client estimated and actual cost;
- allocate budget by phase;
- preserve a retry reserve;
- fail preflight when the requested quality cannot fit the approved budget;
- never silently reduce model coverage to fit cost.

Premium tiers may use more frontier models, more lineages, more specialist passes, deeper dynamic testing, and larger fork-validation budgets.

Every product tier must state exactly what it includes.

---

## 24. Benchmarking and proof of quality

The benchmark programme is part of the product, not an optional research project.

### 24.1 Must-catch suite

A small mandatory set of critical and high vulnerabilities that every release must detect.

### 24.2 Safe-control suite

Secure equivalents and near misses that must not produce false confirmed findings.

### 24.3 Security mutation testing

Mutations should include:

- removed authorization;
- removed nonce update;
- changed rounding;
- removed stale-price validation;
- external-call/state-update reordering;
- removed initializer protection;
- weakened timelock;
- changed storage slot;
- removed pause enforcement;
- unchecked return;
- incorrect decimal scale.

The product must run against mutated repositories and measure whether the audit kills the mutation.

### 24.4 Public time-split corpus

Use public pre-fix commits and findings, with report publication dates recorded. Freeze the system report before revealing ground truth.

### 24.5 Private blinded holdout

Use an operator-controlled or third-party-controlled holdout that the implementation team and auditing models have not seen.

### 24.6 Professional comparison

Run the same commit and scope through Corrovera and excellent professional auditors. Findings should be independently adjudicated.

Measure:

- critical recall;
- high recall;
- medium recall;
- confirmed precision;
- false-confirmed critical rate;
- false-confirmed high rate;
- safe-near-miss rejection;
- exact-location accuracy;
- reachability accuracy;
- reproduction success;
- mutation kill rate;
- coverage;
- cost;
- runtime.

### 24.7 Superiority claim

Use:

- `NOT_EVALUATED`
- `NOT_DEMONSTRATED`
- `DEMONSTRATED`

`DEMONSTRATED` requires:

- blind comparison;
- identical commit;
- identical scope;
- independent adjudication;
- superior recall and precision;
- disclosed time and resource differences;
- statistically defensible evidence;
- published methodology and limitations.

---

## 25. Release gates

A maximum-assurance production release must not ship until:

### Model layer

- real OpenRouter calls succeed;
- exact canonical model identity is bound;
- exact provider endpoints are recorded;
- the daily model registry runs;
- policy eligibility is current;
- at least the required number of independent qualified frontier lineages participate;
- substantive per-surface review is measured;
- no mandatory shard remains truncated;
- no silent substitution occurs.

### Deterministic layer

- compilation succeeds;
- AST and source mappings exist;
- required semantic graphs exist;
- required scanners execute;
- source locations validate;
- coverage denominators reconcile.

### Dynamic and formal layer

- required fuzzers execute;
- invariant campaigns execute;
- symbolic engine executes;
- required formal engine executes;
- unsafe and safe controls pass;
- counterexamples replay;
- isolation is proven.

### Finding integrity

- every published finding has validated source and reachability;
- no model-only finding is confirmed;
- high and critical candidates receive independent challenge;
- unresolved high or critical candidates prevent `COMPLETE`;
- fork validation runs where necessary;
- reproduction realism checks pass.

### Product benchmark

- completed product reports exist;
- benchmark denominators are non-zero;
- critical recall gate passes;
- high recall gate passes;
- false-confirmed critical and high gates pass;
- location accuracy passes;
- mutation kill rate passes;
- benchmark certificate is current and bound to the release.

### Service layer

- website purchase flow works;
- repository connection works;
- billing works;
- tenant isolation is tested;
- job resume works;
- report delivery works;
- data deletion works;
- client portal shows truthful status.

---

## 26. Honest product claims

Before superiority is demonstrated, Corrovera may say:

- “Designed to deliver exceptionally deep multi-model Solidity/EVM security audits.”
- “Uses independently qualified AI models, deterministic analysis, and evidence-capped validation.”
- “Every published finding is source-bound and independently challenged.”
- “Dynamic and fork-based validation is used where applicable.”
- “Reports disclose exactly what ran and what did not.”

It must not say:

- “Guaranteed secure.”
- “Finds every vulnerability.”
- “Better than every audit firm.”
- “Maximum assurance complete” when mandatory gates did not execute.
- “All frontier models participated” when privacy, policy, availability, or budget excluded them.
- “No findings” as a safety conclusion from an incomplete run.

The product objective is to become demonstrably best in class. The product claim must follow the evidence.

---

## 27. Definition of satisfactory completion

The project has reached its intended first major destination when a customer can purchase an audit through the website, connect a real Solidity repository, and receive—without an internal operator—a complete audit that:

- uses the daily-qualified set of policy-eligible frontier models;
- reviews the full repository through coherent shards;
- gives every critical surface independent multi-lineage review;
- runs deterministic scanners and semantic analysis;
- derives and tests protocol invariants;
- executes applicable fuzzing, symbolic, formal, and economic methods;
- validates serious candidates on a realistic local or forked environment where relevant;
- publishes only source-valid, evidence-supported findings;
- exposes uncertainty and limitations;
- produces a concise client report and complete forensic bundle;
- is reproducible from its run manifest;
- passes the product benchmark and release gates;
- protects client source, credentials, and tenant boundaries;
- completes autonomously from purchase to delivery.

The ultimate destination is reached when blind, independently adjudicated evidence shows that Corrovera consistently matches or exceeds elite professional smart-contract audits on recall, precision, evidence quality, and coverage.

---

## 28. Product mantra

> Use every eligible source of intelligence.<br>
> Trust no single model.<br>
> Validate every location.<br>
> Challenge every candidate.<br>
> Reproduce what can be reproduced.<br>
> Prove what can be proved.<br>
> Publish only what the evidence supports.<br>
> Disclose everything that did not run.<br>
> Make the audit autonomous, but never opaque.
