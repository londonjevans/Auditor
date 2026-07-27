# Codex Defensive Engineering Queue

This queue decomposes the maximum-assurance roadmap into independently testable
work units. It is a planning artifact, not evidence that a capability exists.

Statuses: `QUEUED`, `IN_PROGRESS`, `COMPLETE`, `PARTIAL`,
`BLOCKED_SAFETY`, `BLOCKED_TECHNICAL`.

## Queue governance

### QUEUE-BOOTSTRAP-001

- **Objective:** Establish the persistent queue and worklog.
- **Files/modules:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`.
- **Acceptance criteria:** Both documents exist, use bounded tickets, and record the
  next safe action.
- **Tests:** Manual Markdown and required-field review.
- **Dependencies:** None.
- **Status:** `COMPLETE`

### TRACE-001

- **Objective:** Enforce traceability evidence rules in CI.
- **Files/modules:** `src/mmaudit/traceability.py`, `schemas/`, CI workflow,
  `tests/unit/test_traceability.py`.
- **Acceptance criteria:** An `implemented` row fails validation when code, tests, or
  runtime artifacts are absent.
- **Tests:** Unit validation plus pipeline artifact integration test.
- **Dependencies:** `QUEUE-BOOTSTRAP-001`.
- **Status:** `COMPLETE`

### ASSURE-001

- **Objective:** Align the maximum-assurance contract with every blocking queue item.
- **Files/modules:** `orchestration/assurance.py`, `models/schemas.py`,
  `tests/unit/test_assurance.py`.
- **Acceptance criteria:** Missing required capability produces `FAILED`, or
  `DOWNGRADED` only after explicit acknowledgement.
- **Tests:** Table-driven requirement-state tests.
- **Dependencies:** `TRACE-001`.
- **Status:** `COMPLETE`

## Executable economic validation

Each economic ticket must add a typed applicability detector, declarative harness,
vulnerable fixture, safe near-miss, deterministic replay, minimization assertion,
and report serialization.

### ECO-001 — Fee-on-transfer and rebasing compatibility

- **Objective:** Detect accounting divergence caused by non-standard balance changes.
- **Files/modules:** `solidity/economics.py`, `invariant_templates.py`,
  `invariant_execution.py`, `tests/fixtures/solidity/economic_token_behavior/`.
- **Acceptance criteria:** Vulnerable fixture yields a replayable invariant violation;
  safe variant does not.
- **Tests:** Unit translation and real local Foundry integration.
- **Dependencies:** `REAL-001`.
- **Status:** `COMPLETE`

### ECO-002 — Rounding and precision boundaries

- **Objective:** Validate bounded conversion and rounding invariants.
- **Files/modules:** Economic/invariant modules; `economic_rounding` fixtures.
- **Acceptance criteria:** Detects value-creating rounding sequences without
  confirming bounded safe loss.
- **Tests:** Boundary unit tests and Foundry replay/minimization.
- **Dependencies:** `REAL-001`.
- **Status:** `COMPLETE`

### ECO-003 — Ordering-sensitive operations

- **Objective:** Validate declared same-block ordering protections.
- **Files/modules:** Economic/invariant modules; `economic_ordering` fixtures.
- **Acceptance criteria:** Reports only invariant violations reachable by declared
  transaction-ordering capabilities.
- **Tests:** Deterministic sequence tests with safe near-miss.
- **Dependencies:** `REAL-001`, `REAL-002`.
- **Status:** `COMPLETE`

### ECO-004 — ERC4626 donation and initial-depositor behavior

- **Objective:** Finish pipeline execution and coverage accounting for the existing
  ERC4626 typed harness.
- **Files/modules:** `invariant_execution.py`, pipeline, ERC4626 fixtures/reports.
- **Acceptance criteria:** Applicable harness is generated, compiled, executed,
  replayed, and separately counted.
- **Tests:** Existing real Foundry test plus pipeline integration.
- **Dependencies:** `REAL-003`.
- **Status:** `COMPLETE`

### ECO-005 — Temporary-liquidity oracle sensitivity

- **Objective:** Validate price-dependent invariants under bounded temporary liquidity.
- **Files/modules:** Economic templates; local oracle/liquidity fixtures.
- **Acceptance criteria:** Uses synthetic local liquidity only and records repayment,
  fees, and settled impact.
- **Tests:** Vulnerable/safe Foundry integrations.
- **Dependencies:** `REAL-004`, `SEM-004`.
- **Status:** `COMPLETE`

### ECO-006 — AMM reserve and spot-price dependence

- **Objective:** Test bounded reserve changes against declared pricing invariants.
- **Files/modules:** Economic templates; synthetic AMM fixtures.
- **Acceptance criteria:** Distinguishes unsafe spot dependence from protected pricing.
- **Tests:** Deterministic vulnerable/safe Foundry tests.
- **Dependencies:** `REAL-004`, `SEM-004`.
- **Status:** `COMPLETE`

### ECO-007 — Price freshness, decimals, and sequencer checks

- **Objective:** Validate feed freshness, scale, and configured availability guards.
- **Files/modules:** Economic templates; oracle fixtures.
- **Acceptance criteria:** Detects missing guards and rejects guarded near-misses.
- **Tests:** Boundary and local integration tests.
- **Dependencies:** `SEM-004`.
- **Status:** `COMPLETE`

### ECO-008 — Lending health and liquidation boundaries

- **Objective:** Validate health-factor and liquidation state transitions.
- **Files/modules:** Economic templates; lending fixtures.
- **Acceptance criteria:** Counterexample includes debt, collateral, settlement, and
  violated invariant.
- **Tests:** Stateful Foundry integration and replay.
- **Dependencies:** `REAL-004`, `DYN-001`.
- **Status:** `COMPLETE`

### ECO-009 — Reward index and claim-once behavior

- **Objective:** Validate reward monotonicity and duplicate-claim prevention.
- **Files/modules:** Economic templates; reward fixtures.
- **Acceptance criteria:** Reproduces unsafe accounting; safe claim tracking passes.
- **Tests:** Unit invariant extraction and Foundry sequence replay.
- **Dependencies:** `DYN-001`.
- **Status:** `COMPLETE`

### ECO-010 — Share-price and exchange-rate manipulation

- **Objective:** Validate bounded share/asset exchange-rate transitions.
- **Files/modules:** Economic templates; vault/pool fixtures.
- **Acceptance criteria:** Separates legitimate yield from attacker-reachable value
  creation.
- **Tests:** Stateful Foundry tests and minimized replay.
- **Dependencies:** `REAL-004`.
- **Status:** `COMPLETE`

### ECO-011 — Governance and timelock transitions

- **Objective:** Validate configured proposal, delay, and execution invariants.
- **Files/modules:** Economic templates; governance fixtures.
- **Acceptance criteria:** Uses only declared governance rights and bounded time moves.
- **Tests:** Vulnerable/safe state-machine integrations.
- **Dependencies:** `REAL-001`, `SEM-004`.
- **Status:** `COMPLETE`

### ECO-012 — Upgrade and initializer transitions

- **Objective:** Validate upgrade authorization and one-time initialization.
- **Files/modules:** Economic templates; proxy/initializer fixtures.
- **Acceptance criteria:** Reaches only legitimate upgrade paths; direct storage/code
  mutation is rejected.
- **Tests:** Proxy vulnerable/safe Foundry integrations.
- **Dependencies:** `REAL-002`, `SEM-005`.
- **Status:** `COMPLETE`

### ECO-013 — Signature, permit, and nonce replay

- **Objective:** Validate domain, nonce, and replay invariants using synthetic keys
  confined to fixtures.
- **Files/modules:** Economic templates; signature fixtures.
- **Acceptance criteria:** No wallet or operator key access; safe nonce/domain controls
  reject replay.
- **Tests:** Deterministic local signature regression tests.
- **Dependencies:** `REAL-001`.
- **Status:** `COMPLETE`

### ECO-014 — Cross-chain duplicate-message state

- **Objective:** Validate offline message-ordering and duplicate-consumption invariants.
- **Files/modules:** Economic templates; synthetic bridge fixtures.
- **Acceptance criteria:** Uses offline messages only and proves message-state
  transitions.
- **Tests:** Vulnerable/safe local sequence tests.
- **Dependencies:** `SEM-006`, `REAL-001`.
- **Status:** `COMPLETE`

### ECO-015 — Callback and receiver reentrancy

- **Objective:** Validate state consistency across attacker-reachable callbacks.
- **Files/modules:** Economic templates; callback-token/receiver fixtures.
- **Acceptance criteria:** Counterexample cites reachable callback and affected state.
- **Tests:** Vulnerable/safe Foundry integrations.
- **Dependencies:** `SEM-002`, `SEM-003`.
- **Status:** `COMPLETE`

### ECO-016 — Bounded resource and state-growth safety

- **Objective:** Detect unbounded state-growth or iteration risks without generating
  denial-of-service tooling.
- **Files/modules:** Economic templates; bounded synthetic fixtures.
- **Acceptance criteria:** Tests remain resource-capped and report threshold evidence.
- **Tests:** Unit bounds and isolated integration timeout tests.
- **Dependencies:** `ISO-001`.
- **Status:** `COMPLETE`

### ECO-017 — Malformed ERC20 return behavior

- **Objective:** Validate accounting with missing, false, or unusual token returns.
- **Files/modules:** Economic templates; non-standard token fixtures.
- **Acceptance criteria:** Detects unchecked outcomes; safe wrappers are not confirmed.
- **Tests:** Vulnerable/safe Foundry integration.
- **Dependencies:** `DYN-001`.
- **Status:** `COMPLETE`

### ECO-018 — Multi-transaction state ordering

- **Objective:** Validate bounded multi-step state-machine invariants.
- **Files/modules:** Economic templates; transaction-sequence fixtures.
- **Acceptance criteria:** Persists seed and minimized sequence; same clean state replays.
- **Tests:** Stateful Foundry replay test.
- **Dependencies:** `DYN-001`, `REAL-003`.
- **Status:** `COMPLETE`

## Exploit-realism and evidence integrity

### REAL-001

- **Objective:** Add a typed `AttackerCapabilityPolicy`.
- **Files/modules:** `models/schemas.py`, `solidity/reproduction.py`, exploit-test prompt.
- **Acceptance criteria:** Undeclared actors, capital, privilege, oracle, timing, or
  ordering capabilities are rejected before generation.
- **Tests:** Schema and policy-negative unit tests.
- **Dependencies:** None.
- **Status:** `COMPLETE`

### REAL-002

- **Objective:** Separate reproduction setup and attack phases.
- **Files/modules:** Reproduction schemas, translator, prompts.
- **Acceptance criteria:** Prohibited attack-phase cheatcodes/state mutation cannot be
  represented; setup actions are explicit.
- **Tests:** Translation snapshots and injection-negative tests.
- **Dependencies:** `REAL-001`.
- **Status:** `COMPLETE`

### REAL-003

- **Objective:** Add deterministic reproduction-integrity verification.
- **Files/modules:** New `solidity/reproduction_integrity.py`, pipeline, schemas.
- **Acceptance criteria:** Validates target identity, cited reachability, clean replay,
  repository hash, settlement, and minimization.
- **Tests:** Vulnerable, patched, tampered-source, and prohibited-capability tests.
- **Dependencies:** `REAL-002`, `MAN-001`.
- **Status:** `COMPLETE`

### REAL-004

- **Objective:** Record settled financial impact for financial reproductions.
- **Files/modules:** Reproduction schemas/translator/reporting.
- **Acceptance criteria:** Starting assets, borrowing, repayment, fees, slippage,
  ending assets, and net impact are explicit and arithmetically validated.
- **Tests:** Schema arithmetic and Foundry serialization tests.
- **Dependencies:** `REAL-003`.
- **Status:** `COMPLETE`

## Dynamic, symbolic, formal, and mutation engines

### DYN-001

- **Objective:** Define one typed property corpus shared by dynamic engines.
- **Files/modules:** New `solidity/properties.py`, invariant schemas, tests.
- **Acceptance criteria:** Properties retain source evidence, assumptions, covered
  functions/state, seeds, and bounds.
- **Tests:** Schema, provenance, and deterministic serialization tests.
- **Dependencies:** `SEM-003`, `COV-001`.
- **Status:** `COMPLETE`

### DYN-002

- **Objective:** Implement real Echidna property translation and execution.
- **Files/modules:** `solidity/formal.py` or `solidity/engines/echidna.py`.
- **Acceptance criteria:** Trusted external binary, pinned supported version, isolated
  fixture run, normalized/replayable counterexample, explicit timeout.
- **Tests:** Unit parser plus real integration when installed.
- **Dependencies:** `DYN-001`, `ISO-001`.
- **Status:** `COMPLETE`

### DYN-003

- **Objective:** Implement real Medusa property translation and execution.
- **Files/modules:** `solidity/engines/medusa.py`.
- **Acceptance criteria:** Same evidence and isolation contract as Echidna; outcomes
  compared without hiding disagreement.
- **Tests:** Unit parser plus real integration when installed.
- **Dependencies:** `DYN-001`, `ISO-001`.
- **Status:** `COMPLETE`

### DYN-004

- **Objective:** Expand Foundry fuzz and stateful invariant campaigns.
- **Files/modules:** `invariant_execution.py`, property translators.
- **Acceptance criteria:** Seeds/corpora persist, failing sequences minimize and replay,
  and function/state/sequence coverage is separate.
- **Tests:** Real Foundry vulnerable/safe integration.
- **Dependencies:** `DYN-001`, `REAL-003`.
- **Status:** `COMPLETE`

### SYM-001

- **Objective:** Add a real Halmos symbolic adapter.
- **Files/modules:** `solidity/engines/halmos.py`.
- **Acceptance criteria:** Fixed command, version/hash provenance, assumptions,
  bounds, unsupported features, and counterexample capture.
- **Tests:** Unit parser plus real fixture integration when installed.
- **Dependencies:** `DYN-001`, `ISO-001`.
- **Status:** `COMPLETE`

### FORM-001

- **Objective:** Add configured Certora property execution.
- **Files/modules:** `solidity/engines/certora.py`, config schemas.
- **Acceptance criteria:** Explicit operator configuration, no secret leakage,
  specification/assumption/vacuity artifacts, and honest unavailable status.
- **Tests:** Unit command/schema tests; real integration only in configured CI.
- **Dependencies:** `DYN-001`, `MUT-001`.
- **Status:** `COMPLETE`

### FORM-002

- **Objective:** Add configured Kontrol property execution.
- **Files/modules:** `solidity/engines/kontrol.py`.
- **Acceptance criteria:** Fixed commands, isolation, proof assumptions, coverage, and
  counterexample artifacts.
- **Tests:** Unit parser; real integration when installed.
- **Dependencies:** `DYN-001`, `MUT-001`, `ISO-001`.
- **Status:** `COMPLETE`

### MUT-001

- **Objective:** Implement typed, source-local security mutations.
- **Files/modules:** New `benchmark/mutations.py`, synthetic mutation fixtures.
- **Acceptance criteria:** Required mutation classes apply deterministically to
  disposable copies and never modify the source repository.
- **Tests:** One apply/revert test per mutation class.
- **Dependencies:** `MAN-001`.
- **Status:** `COMPLETE`

### MUT-002

- **Objective:** Enforce invariant/property mutation-score gates.
- **Files/modules:** Benchmark engine/schemas/reporting.
- **Acceptance criteria:** Per-property kill score is explicit; poor score blocks
  maximum assurance.
- **Tests:** Passing, failing, and hidden-aggregate regression tests.
- **Dependencies:** `MUT-001`, `DYN-001`.
- **Status:** `COMPLETE`

## Model ensemble

### MODEL-001

- **Objective:** Extend the model registry with immutable lineage and measured quality.
- **Files/modules:** `models/registry.py`, config/schema examples.
- **Acceptance criteria:** Mirrors/aliases do not count independently; retention and
  approval policies gate source egress.
- **Tests:** Lineage, duplicate, approval, and tier validation tests.
- **Dependencies:** None.
- **Status:** `COMPLETE`

### MODEL-002

- **Objective:** Implement `mmaudit models benchmark`.
- **Files/modules:** CLI, new `benchmark/models.py`, blinded fixture metadata.
- **Acceptance criteria:** Scores location accuracy, rejection, economic/invariant
  quality, injection resistance, and structured-output reliability.
- **Tests:** Deterministic fake-provider unit tests; configured real-provider job.
- **Dependencies:** `MODEL-001`, `BENCH-001`.
- **Status:** `COMPLETE`

### MODEL-003

- **Objective:** Complete the bounded specialist catalog and execution requirements.
- **Files/modules:** `constants.py`, `agents/specialists.py`, prompts, config.
- **Acceptance criteria:** Every required specialist has a distinct responsibility,
  schema, bounded context, and recorded execution.
- **Tests:** Role registry completeness and no-duplicate-responsibility tests.
- **Dependencies:** `MODEL-001`.
- **Status:** `COMPLETE`

### MODEL-004

- **Objective:** Enforce blind first-pass discovery.
- **Files/modules:** Pipeline scheduling and agent context assembly.
- **Acceptance criteria:** First-pass agents cannot receive another agent's findings.
- **Tests:** Context-isolation integration test.
- **Dependencies:** `MODEL-003`.
- **Status:** `COMPLETE`

### MODEL-005

- **Objective:** Add anonymized multi-lineage adversarial cross-examination.
- **Files/modules:** Verifier/falsifier agents, pipeline, evidence schemas.
- **Acceptance criteria:** Two independent falsifiers review high/critical candidates;
  dissent is retained and no new finding bypasses intake.
- **Tests:** Unknown-finding rejection and dissent serialization tests.
- **Dependencies:** `MODEL-001`, `MODEL-004`.
- **Status:** `COMPLETE`

### MODEL-006

- **Objective:** Emit per-surface model review coverage.
- **Files/modules:** New `orchestration/model_coverage.py`, reports.
- **Acceptance criteria:** Contracts, entry points, privilege/asset functions, calls,
  state, invariants, and templates list roles and root lineages.
- **Tests:** Numerator/denominator and critical-surface gate tests.
- **Dependencies:** `MODEL-003`, `COV-001`.
- **Status:** `COMPLETE`

## Semantic and coverage verification

### SEM-001

- **Objective:** Audit AST/fallback provenance for every semantic entity and edge.
- **Files/modules:** `solidity/index.py`, `graphs.py`, schemas.
- **Acceptance criteria:** Exact path/range/hash and transformation provenance survive
  serialization; fallback confidence is lower.
- **Tests:** Compiler AST and malformed-source fixtures.
- **Dependencies:** None.
- **Status:** `COMPLETE`

### SEM-002

- **Objective:** Verify internal, external, low-level, delegatecall, and reentrancy graphs.
- **Files/modules:** `solidity/graphs.py`, semantic fixtures.
- **Acceptance criteria:** Vulnerable and guarded near-miss edges have exact source
  provenance and model/verifier projections.
- **Tests:** AST graph unit/integration fixtures.
- **Dependencies:** `SEM-001`.
- **Status:** `COMPLETE`

### SEM-003

- **Objective:** Verify state-read/write, write-after-call, and asset-flow graphs.
- **Files/modules:** Graph builder/retrieval/reporting.
- **Acceptance criteria:** Reads, writes, mint/burn, deposit/withdraw, reward, claim,
  liquidation, sources, and sinks are separately represented.
- **Tests:** Vulnerable/safe accounting fixtures.
- **Dependencies:** `SEM-001`, `SEM-002`.
- **Status:** `COMPLETE`

### SEM-004

- **Objective:** Verify role, privilege, governance, oracle, and dependency graphs.
- **Files/modules:** Graph builder/retrieval/reporting.
- **Acceptance criteria:** Privileged and dependency surfaces retain deterministic
  evidence and explicit unknowns.
- **Tests:** Role drain, timelock, oracle, and safe-control fixtures.
- **Dependencies:** `SEM-001`.
- **Status:** `COMPLETE`

### SEM-005

- **Objective:** Verify proxy, initializer, storage, and upgrade-compatibility graphs.
- **Files/modules:** Graph/index/compiler artifact modules.
- **Acceptance criteria:** Implementation/admin slots, inheritance order, gaps, packing,
  and layout changes are compiler-backed where available.
- **Tests:** Proxy and storage-layout vulnerable/safe fixtures.
- **Dependencies:** `SEM-001`.
- **Status:** `COMPLETE`

### SEM-006

- **Objective:** Add cross-chain, event, and off-chain dependency graph evidence.
- **Files/modules:** Graph/index/retrieval modules.
- **Acceptance criteria:** Messaging and event-driven assumptions are explicit and
  heuristic edges never become deterministic facts.
- **Tests:** Synthetic bridge/relayer fixtures.
- **Dependencies:** `SEM-001`.
- **Status:** `COMPLETE`

### COV-001

- **Objective:** Standardize independent coverage denominators and exclusions.
- **Files/modules:** `solidity/coverage.py`, schemas, reports.
- **Acceptance criteria:** Every required dimension shows numerator, denominator,
  exclusions, not-applicable evidence, confidence, provenance, and failures.
- **Tests:** No denominator-shrinking or aggregate-masking tests.
- **Dependencies:** `SEM-001`.
- **Status:** `COMPLETE`

## Full-protocol scope and snapshots

### SCOPE-001

- **Objective:** Add `contracts-only`, `contracts-and-deployment`, and `full-protocol`
  scope schemas and gates.
- **Files/modules:** Config, discovery, pipeline, reporting.
- **Acceptance criteria:** Reports state requested/achieved scope and fail closed on
  required omitted components.
- **Tests:** Scope discovery and downgrade tests.
- **Dependencies:** `ASSURE-001`.
- **Status:** `COMPLETE`

### SNAP-001

- **Objective:** Define and validate an offline deployment snapshot format.
- **Files/modules:** New `snapshots/schema.py`, JSON schema, fixtures.
- **Acceptance criteria:** Chain/block, bytecode, proxies, roles, timelocks, oracles,
  balances, and configuration are hash-linked and source-free where required.
- **Tests:** Valid, malformed, traversal, and secret-withholding tests.
- **Dependencies:** `MAN-001`.
- **Status:** `COMPLETE`

### SNAP-002

- **Objective:** Compare compiled and snapshot bytecode/configuration.
- **Files/modules:** New `snapshots/compare.py`, compiler artifacts, reports.
- **Acceptance criteria:** Reports mismatches, links, immutables, and compiler-setting
  differences without live RPC access.
- **Tests:** Matching and mismatching offline fixtures.
- **Dependencies:** `SNAP-001`, `SEM-005`.
- **Status:** `COMPLETE`

### SNAP-003

- **Objective:** Add a read-only allowlisted snapshot importer.
- **Files/modules:** New `snapshots/importer.py`, CLI.
- **Acceptance criteria:** Only approved read methods, no signing/sending, explicit
  opt-in, sanitized deterministic output.
- **Tests:** Mock RPC allowlist tests and local-chain integration.
- **Dependencies:** `SNAP-001`, `ISO-001`.
- **Status:** `COMPLETE`

### SCOPE-002

- **Objective:** Implement blind-first prior-audit remediation comparison.
- **Files/modules:** Pipeline, prior-audit parser, reporting.
- **Acceptance criteria:** Prior findings remain hidden until discovery completes;
  misses and remediation status are reported separately.
- **Tests:** Context-ordering and regression tests.
- **Dependencies:** `MODEL-004`, `SCOPE-001`.
- **Status:** `COMPLETE`

## Benchmark certificates and claim gates

### BENCH-001

- **Objective:** Define a component-bound benchmark certificate schema.
- **Files/modules:** New `benchmark/certificate.py`, `schemas/`.
- **Acceptance criteria:** Commit, config, prompts, models, tools, compilers, corpus,
  and ground truth are hash-bound.
- **Tests:** Round-trip, tamper, stale, and path-safety tests.
- **Dependencies:** `MAN-001`.
- **Status:** `COMPLETE`

### BENCH-002

- **Objective:** Add `benchmark certify` and `verify-certificate`.
- **Files/modules:** CLI, benchmark certificate module.
- **Acceptance criteria:** Certification requires passed gates; changed binding
  invalidates verification.
- **Tests:** CLI success/tamper/stale tests.
- **Dependencies:** `BENCH-001`.
- **Status:** `COMPLETE`

### BENCH-003

- **Objective:** Integrate certificate and repository gates into `mmaudit run`.
- **Files/modules:** CLI, pipeline, assurance contract.
- **Acceptance criteria:** `run --benchmark-gate` verifies a current certificate and
  exits nonzero on any required failure.
- **Tests:** CLI/pipeline pass, absent, stale, and failed-corpus tests.
- **Dependencies:** `BENCH-002`, `ASSURE-001`.
- **Status:** `COMPLETE`

### BENCH-004

- **Objective:** Expand must-catch, safe, mutation, and blinded benchmark layers.
- **Files/modules:** `benchmarks/corpus/`, manifest schemas, benchmark engine.
- **Acceptance criteria:** Per-repository critical recall, false confirmations,
  location accuracy, reproduction, mutation score, cost, and runtime are explicit.
- **Tests:** Ground-truth integrity and aggregate-masking tests.
- **Dependencies:** `MUT-002`, `BENCH-001`.
- **Status:** `COMPLETE`

### BENCH-005

- **Objective:** Add the three-state superiority claim gate.
- **Files/modules:** Benchmark schemas/evaluator/reporting.
- **Acceptance criteria:** `DEMONSTRATED` requires blinded comparable human review,
  independent adjudication, and statistically supported precision/recall.
- **Tests:** All precondition combinations; default `NOT_EVALUATED`.
- **Dependencies:** `BENCH-004`.
- **Status:** `COMPLETE`

## OS isolation and hostile repositories

### ISO-001

- **Objective:** Implement a rootless pinned-container execution backend.
- **Files/modules:** New `isolation/` package, config, Docker assets.
- **Acceptance criteria:** Digest-pinned image, read-only source/toolchain, private
  home, no network/socket/credentials, resource/syscall limits, verified cleanup.
- **Tests:** Command construction plus real rootless backend integration when available.
- **Dependencies:** None.
- **Status:** `COMPLETE`

### ISO-002

- **Objective:** Force all Hardhat/config/plugin execution through isolation.
- **Files/modules:** Solidity compiler/test runners, isolation backend.
- **Acceptance criteria:** No repository JavaScript executes on the host; unavailable
  isolation fails before execution.
- **Tests:** Malicious synthetic Hardhat configuration containment test.
- **Dependencies:** `ISO-001`.
- **Status:** `COMPLETE`

### ISO-003

- **Objective:** Add a separate dependency-fetch preparation stage.
- **Files/modules:** New `isolation/dependencies.py`, SBOM artifacts.
- **Acceptance criteria:** Explicit opt-in, lock/checksum validation, lifecycle scripts
  disabled, dependency scan, only required files copied.
- **Tests:** Synthetic postinstall rejection and lock mismatch tests.
- **Dependencies:** `ISO-001`.
- **Status:** `COMPLETE`

### ISO-004

- **Objective:** Build the adversarial repository fixture suite.
- **Files/modules:** `tests/fixtures/adversarial_repository/`, isolation/security tests.
- **Acceptance criteria:** Fake binaries, symlinks, traversal, environment/home reads,
  network/socket access, process/output/resource abuse, crafted names, and prompt
  injection are rejected or contained.
- **Tests:** Real isolated integration where backend exists; fail-closed otherwise.
- **Dependencies:** `ISO-001`, `ISO-002`.
- **Status:** `COMPLETE`

## Reproducibility and replay

### MAN-001

- **Objective:** Emit a hash-linked evidence manifest for every run.
- **Files/modules:** New `orchestration/manifest.py`, pipeline, schema.
- **Acceptance criteria:** Source/config/prompt/model/tool/compiler/isolation/seed/
  corpus/harness/reproduction/coverage bindings are deterministic.
- **Tests:** Stable serialization and tamper tests.
- **Dependencies:** `TRACE-001`.
- **Status:** `COMPLETE`

### MAN-002

- **Objective:** Implement `mmaudit verify-run`.
- **Files/modules:** CLI, manifest verifier.
- **Acceptance criteria:** Detects changed source, prompt, model fingerprint, tool,
  compiler, artifact, or certificate without executing target code.
- **Tests:** CLI clean/tampered/missing-artifact tests.
- **Dependencies:** `MAN-001`, `BENCH-001`.
- **Status:** `COMPLETE`

### MAN-003

- **Objective:** Implement offline `mmaudit replay`.
- **Files/modules:** CLI, replay orchestrator.
- **Acceptance criteria:** Replays deterministic scanners, saved tests, and
  counterexamples without model-provider contact by default.
- **Tests:** Local fixture replay and network-denial tests.
- **Dependencies:** `MAN-002`, `REAL-003`, `DYN-004`.
- **Status:** `COMPLETE`

## End-to-end acceptance suites

### E2E-001

- **Objective:** Add the synthetic economic-protocol acceptance suite.
- **Files/modules:** `tests/fixtures/solidity/maximum_assurance_economic/`,
  integration tests.
- **Acceptance criteria:** Applicable harnesses execute; planted issues reproduce;
  safe near-misses remain unconfirmed.
- **Tests:** Real local Foundry and report/schema validation.
- **Dependencies:** `ECO-001` through `ECO-018`, `REAL-004`.
- **Status:** `COMPLETE`

### E2E-002

- **Objective:** Add the hostile-repository acceptance suite.
- **Files/modules:** Adversarial fixture and integration tests.
- **Acceptance criteria:** Every hostile behavior is contained or rejected before host
  execution.
- **Tests:** Real isolation backend integration.
- **Dependencies:** `ISO-004`.
- **Status:** `BLOCKED_TECHNICAL`

### E2E-003

- **Objective:** Add the full-protocol offline-snapshot acceptance suite.
- **Files/modules:** Full-protocol fixture, snapshot, previous-audit sample, tests.
- **Acceptance criteria:** Source/deployment consistency, roles, oracle/timelock,
  relayer assumptions, and prior remediation are validated blind-first.
- **Tests:** End-to-end offline integration.
- **Dependencies:** `SNAP-002`, `SCOPE-002`.
- **Status:** `COMPLETE`

### RELEASE-001

- **Objective:** Run the complete maximum-assurance release gate.
- **Files/modules:** CI workflow, Makefile, release report.
- **Acceptance criteria:** Ruff, mypy, pytest, doctor, model benchmark, benchmark
  certificate, maximum-assurance run, schemas, manifests, artifacts, and replay all
  pass; status remains non-`COMPLETE` otherwise.
- **Tests:** The required end-to-end command set.
- **Dependencies:** All required tickets above.
- **Status:** `BLOCKED_TECHNICAL`

## Next action

No safe actionable ticket remains. Resume `E2E-002` and the four blocked
`RELEASE-001` gates only when an operator supplies a pinned rootless containment
backend, immutable non-placeholder model selection and provider access, and the
other explicitly recorded local tool prerequisites.
