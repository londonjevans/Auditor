# Codex Defensive Engineering Worklog

This file is the persistent handoff record. Update it after every meaningful
implementation slice. Do not record secrets, source excerpts from external targets,
credentials, RPC URLs, or operational attack instructions.

AUTORUN_STATUS: FINISHED_BLOCKED_TECHNICAL
CURRENT_TICKET: None
LAST_COMPLETED_TICKET: E2E-003
NEXT_ACTION: No safe actionable ticket remains; await operator-provided pinned rootless containment, immutable non-placeholder model/provider configuration, and the other recorded local tool prerequisites before rerunning blocked real integrations.
LAST_VALIDATION_COMMAND: .venv/bin/ruff format .; .venv/bin/ruff check .; .venv/bin/mypy; .venv/bin/pytest -q; make release-evidence PYTHON=.venv/bin/python
LAST_VALIDATION_RESULT: PASS — Ruff left 206 files unchanged and reported no issues; strict mypy passed 101 source files; pytest passed 635 tests with 9 documented technical skips in 138.49s; all 18 schemas and persisted release evidence validated with release_status=blocked_technical.
LAST_CHECKPOINT_COMMIT: None; all repository files are untracked, so an isolated ticket commit would create a broken partial history.
REMAINING_ACTIONABLE_TICKETS: 0
BLOCKED_TICKETS: DYN-002 real Echidna and DYN-003 real Medusa binary integration subtasks are BLOCKED_TECHNICAL because no local binaries are installed; SYM-001 real Halmos target integration is BLOCKED_TECHNICAL because no hardened isolation backend is available; FORM-001 real configured Certora service integration is BLOCKED_TECHNICAL because certoraRun and configured CI credential/connectivity are unavailable; FORM-002 real Kontrol proof integration is BLOCKED_TECHNICAL because no local kontrol binary is installed; ISO-002, ISO-004, and E2E-002 real rootless containment integrations and other rootless/nested OS-isolation integration subtasks remain BLOCKED_TECHNICAL because no rootless runtime or pinned test image is configured; MODEL-002 real-provider execution is BLOCKED_TECHNICAL locally because no provider credential or committed operator model selection is available, while its conditional default-branch CI path and deterministic fake-provider coverage are complete; MAN-003 real isolated Foundry replay integration is BLOCKED_TECHNICAL in this sandbox because sandbox-exec cannot be nested and no other hardened backend is configured, while the conditional integration test is present; RELEASE-001 is BLOCKED_TECHNICAL because doctor, the real-provider model benchmark, the maximum-assurance run, and real isolated replay cannot pass without those prerequisites, while all eight safe local release gates are complete.

## Final ticket disposition

- **Ticket:** `RELEASE-001`
- **Status:** `BLOCKED_TECHNICAL`
- **Defensive objective:** Execute and serialize the complete
  maximum-assurance release gate without promoting mocked or unavailable real
  integrations.
- **Completed changes so far:**
  - Added a typed, self-hashed twelve-gate release report that distinguishes
    passed, failed, and technically blocked requirements.
  - Prevented mocked evidence from satisfying doctor, real-provider model
    benchmark, maximum-assurance run, or real replay gates.
  - Added a strict release-report schema, bounded loader/writer, and status,
    accounting, tamper, link, and mocked-evidence negative tests.
  - Added a safe local release-evidence validator covering every published
    schema, benchmark and acceptance manifests, compiler/snapshot artifacts,
    traceability paths, and the persisted release report.
  - Added `make release-evidence` and `make release-local`; CI quality now
    executes the safe local release target.
- **Commands and results so far:**
  - Affected Ruff passed, strict mypy passed the release module and validator,
    and `7` focused release-report tests passed in `0.04s`.
  - Credential-free `mmaudit doctor` exited `2` after completing local checks
    and identifying missing provider configuration plus unavailable hardened
    and local-fork isolation; it printed no credential value.
  - The real model-benchmark preflight exited `2` before provider construction
    because the illustrative target lacks an immutable lineage. Its
    deterministic model and egress-control coverage passed `7` tests in
    `0.22s`; this mocked evidence is not recorded as real execution.
  - A real maximum-assurance invocation on the synthetic full protocol exited
    `2` with an `INCONCLUSIVE` report and stopped before dynamic or model
    execution because hardened isolation is unavailable. Its report also
    preserved every non-complete traceability and runtime clause.
  - A credential-free scanner-only run completed on the synthetic full
    protocol. `mmaudit verify-run` reported `current` with zero mismatches;
    typed validation reconciled all `30` manifest artifacts, a complete report,
    and SARIF `2.1.0`.
  - Benchmark-certificate implementation and real CLI round-trip passed `8`
    tests in `0.24s`.
  - Deterministic replay coverage passed `4` tests; the conditional real
    Foundry replay integration skipped because no hardened backend exists and
    is recorded only as `BLOCKED_TECHNICAL`.
  - The combined benchmark, certificate, model, manifest, replay, release, and
    CLI set passed `81` tests with the one documented real-replay skip.
  - Added `docs/release_gate_report.json`, which self-hashes all twelve required
    gate observations and reports `8` passed plus `4` technically blocked
    gates without a completion claim.
  - `make release-evidence PYTHON=.venv/bin/python` validated all `18` strict
    schemas, `15` benchmark source bindings, `4` model cases, `18` economic
    cases, `10` adversarial cases, the `9`-file full-protocol fixture,
    compiler/snapshot artifacts, traceability evidence, and release report.
  - `make release-local PYTHON=.venv/bin/python` passed Ruff format checking,
    Ruff checking, strict mypy over `100` source files, the full suite with
    `635` passed and `9` documented technical skips in `137.04s`, and the
    complete persisted release-evidence validator.
  - The initial bare `make release-evidence` used the system interpreter and
    failed because that interpreter did not have the editable package. The
    Makefile now accepts `PYTHON`; the materially different repository-venv
    invocation passed and no dependency installation or network access was
    attempted.
  - `.venv/bin/ruff format .` left `206` files unchanged;
    `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed all `101` source
    files; and `.venv/bin/pytest -q` passed `635` tests with `9` documented
    technical skips in `138.49s`.
  - `make release-evidence PYTHON=.venv/bin/python` passed after the final
    report refresh, validating `18` strict schemas, `15` benchmark source
    bindings, `4` model cases, `18` economic cases, `10` adversarial cases,
    `9` full-protocol files, compiler/snapshot agreement, traceability
    evidence, and release status `blocked_technical`.
  - The bounded typed release-report loader reverified
    `status=blocked_technical`, `passed=8`, `blocked=4`,
    `safe_local=true`, and self-hash
    `4f2c0ea1da9cb83cad2ca80fbaa271250ca55618821a6d1d8c999aa01f210e22`.
  - `forge fmt --check tests/fixtures/full_protocol_offline
    tests/fixtures/solidity/economic_token_behavior` passed with no formatting
    drift.
  - Final artifact inspection found no disposable Foundry failure cache,
    logs, coverage output, or unignored Python bytecode. The only Foundry
    `out` file is the intentional normalized AST fixture; interpreter caches
    are ignored.
  - A bounded secret-pattern scan excluded every `.env*` file. Matches were
    limited to hash evidence, detector literals, and explicit `synthetic`
    negative-test sentinels; no credential material was found.
  - `git diff --check` passed. `git status --short` still reports the complete
    repository as untracked, so no isolated checkpoint commit can safely
    represent this ticket.
  - Final queue reconciliation found `66` complete tickets and exactly
    `2` specifically blocked-technical tickets, with no `OPEN`, `READY`,
    `IN_PROGRESS`, `PARTIAL`, or `QUEUED` status remaining.
- **Files changed:**
  - `.github/workflows/mmaudit.yml`
  - `Makefile`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `docs/release_gate_report.json`
  - `schemas/release_gate_report.schema.json`
  - `scripts/validate_release_evidence.py`
  - `src/mmaudit/release.py`
  - `tests/unit/test_release.py`
- **Final result:** All eight safe local release gates pass. The report remains
  self-hashed and non-`COMPLETE`, with `doctor`, `model_benchmark`,
  `maximum_assurance_run`, and `replay` specifically
  `BLOCKED_TECHNICAL`; mocked coverage does not satisfy them.
- **Unresolved issues:** The four real release integrations require
  operator-provided immutable model/provider configuration and a supported
  hardened execution backend. `E2E-002` likewise requires a pinned rootless
  runtime/image. No safe unimplemented portion remains.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** None until the recorded external prerequisites
  are supplied; then rerun only the blocked real integrations and rebuild the
  release report from their actual evidence.

## 2026-07-27 — E2E-003

- **Ticket:** `E2E-003`
- **Status:** `COMPLETE`
- **Defensive objective:** Validate a full synthetic protocol and offline
  deployment snapshot for source consistency, roles, oracle/timelock and
  relayer assumptions, plus blind-first prior-remediation comparison.
- **Exact next safe action:** Inventory existing protocol, snapshot,
  comparison, scope, and prior-audit fixtures and tests, then bind them into one
  aggregate offline acceptance path.
- **Completed changes so far:**
  - Added a synthetic full-protocol fixture spanning contract, deployment
    description, off-chain relayer assumption, tests, and documentation.
  - Compiled the fixture offline with the installed external Solidity `0.8.20`
    compiler and normalized the real compiler artifact into the fixture.
  - Added a self-hashed, source-bound offline deployment snapshot covering
    protocol, timelock, oracle, administrative role, relayer role, and declared
    configuration observations.
  - Added a one-finding historical audit sample whose expected current range
    hash binds the corrected duplicate-message state transition.
  - Sealed a strict nine-file manifest with typed expectations for protocol,
    source/compiler identity, administrative and relayer roles, timelock,
    oracle, and the expected prior finding.
  - Added a typed ten-check aggregate acceptance report with fail-closed
    source/deployment, full-scope, role, relayer, timelock, oracle, blind-first
    remediation, and offline-execution accounting.
  - Added strict manifest/report schemas, normalized bounded report writing,
    tamper/link/drift negative tests, and one real offline-Forge integration
    that independently compares generated compiler output to the committed
    normalized artifact.
  - Extended scope and prior-audit traceability evidence with the new
    aggregate acceptance implementation and integration.
- **Commands and results so far:**
  - `forge build --root tests/fixtures/full_protocol_offline --offline --use
    '/Users/josevans/Library/Application Support/svm/0.8.20/solc-0.8.20'
    --cache-path /private/tmp/mmaudit-e2e003-build-cache --out
    /private/tmp/mmaudit-e2e003-build-out` compiled three Solidity files
    successfully.
  - `load_deployment_snapshot` validated snapshot self-hash
    `407798d04c1c966bbf5a20f8aa019b3c694b2db129e0a6e2e1c333296ea7a446`;
    `compare_deployment_snapshot` returned `matched` for the one source-bound
    contract.
  - The first affected strict-mypy run found one optional achieved-scope
    rendering diagnostic; the evidence renderer was made explicit and mypy
    passed.
  - The initial focused unit run exposed the audit-scope enum spelling and a
    symbol/range mismatch in the historical sample. Both inputs were corrected
    and their source-bound hashes were resealed.
  - The first real integration attempt showed that raw Foundry artifacts do
    not use the normalized direct-artifact shape. The integration now compares
    the generated deployed bytecode and compiler settings directly before
    loading the committed normalized artifact.
  - Final affected Ruff and strict source mypy passed; `13` focused tests
    passed in `0.75s`, including all three real offline Foundry controls,
    blind-context exclusion, source/deployment matching, full-scope evidence,
    role/oracle/timelock/relayer checks, prior remediation, schema shape, and
    report round-trip.
  - The first broadened pipeline run exposed that adding the standalone
    acceptance filename to an existing pipeline traceability row incorrectly
    required every ordinary pipeline run to emit that ticket-specific
    artifact. The row retains the new code/test evidence while using its
    existing pipeline artifacts.
  - The corrected broadened command passed all `85` collected full-protocol,
    snapshot, prior-audit, scope, traceability, pipeline, and
    traceability-artifact tests.
  - Repository-wide `.venv/bin/ruff format .` left all `203` files formatted;
    full Ruff passed and configured strict mypy passed all `100` source files.
  - `.venv/bin/pytest -q` passed `628` tests with `9` documented
    environment/tool skips in `141.24s`.
  - Both acceptance schemas parsed; Forge formatting passed; the sealed
    nine-file manifest reloaded with hash
    `bb640b91d8285ec38bc624e77d393b66705017304e0a376e44f38e102411f67a`;
    snapshot `407798d04c1c966bbf5a20f8aa019b3c694b2db129e0a6e2e1c333296ea7a446`
    matched `1/1` source-bound contract.
  - Final link, credential-pattern, generated-artifact, status,
    trailing-whitespace, and diff checks passed. The only fixture `out`
    directory is the intentional source-controlled Foundry AST artifact
    already documented in this worklog; no disposable failure caches were
    present.
- **Files changed:** `schemas/full_protocol_acceptance_manifest.schema.json`,
  `schemas/full_protocol_acceptance_report.schema.json`,
  `src/mmaudit/full_protocol_acceptance.py`,
  `src/mmaudit/traceability.py`,
  `tests/fixtures/full_protocol_offline/README.md`,
  `tests/fixtures/full_protocol_offline/audit/prior.json`,
  `tests/fixtures/full_protocol_offline/compiler/FullProtocol.json`,
  `tests/fixtures/full_protocol_offline/foundry.toml`,
  `tests/fixtures/full_protocol_offline/manifest.json`,
  `tests/fixtures/full_protocol_offline/script/Deploy.s.sol`,
  `tests/fixtures/full_protocol_offline/service/relayer.py`,
  `tests/fixtures/full_protocol_offline/snapshot.json`,
  `tests/fixtures/full_protocol_offline/src/FullProtocol.sol`,
  `tests/fixtures/full_protocol_offline/test/FullProtocol.t.sol`,
  `tests/integration/test_full_protocol_offline_acceptance.py`, and
  `tests/unit/test_full_protocol_acceptance.py`.
- **Remaining limitation:** This acceptance suite validates a fixed synthetic
  protocol and an operator-supplied offline snapshot; it does not claim live
  deployment equivalence or universal protocol coverage.
- **Checkpoint commit:** None; every repository path remains untracked, so an
  isolated ticket commit would create a broken partial initial history.
- **Exact next safe action:** Begin `RELEASE-001` by inventorying and running
  every safe local release command while retaining explicit non-complete
  states for unavailable real integrations.

## 2026-07-27 — E2E-002

- **Ticket:** `E2E-002`
- **Status:** `BLOCKED_TECHNICAL`
- **Defensive objective:** Prove every source-bound hostile fixture behavior is
  rejected before hostile host execution or contained within real rootless
  isolation, while never presenting fail-closed evidence as real execution.
- **Completed changes so far:**
  - Upgraded the ten-case fixture inventory to a self-hashed manifest binding
    every non-manifest fixture file by normalized path, size, and content hash.
  - Added typed observations and a self-hashed acceptance report that
    distinguishes pre-execution rejection, deterministic containment, and real
    rootless containment. A safe fail-closed result explicitly records the
    unavailable real-rootless integration instead of claiming a pass.
  - Added strict manifest/report schemas, source drift, extra-file, link,
    tamper, unsafe-host-execution, boundary-mismatch, serialization, and schema
    tests.
  - Added one aggregate integration covering normalized crafted names,
    untrusted prompt delimiting, repository-local fake-tool rejection,
    symlink/traversal rejection, bounded output/process behavior, and Hardhat
    compilation refusal before repository code execution.
  - Extended the existing conditional real rootless probe to produce a passing
    report only after private environment/home, network denial, traversal
    denial, bounded output/child behavior, and cleanup all execute successfully.
- **Commands and results so far:**
  - Affected Ruff and strict source mypy passed.
  - `17` focused unit and integration tests passed in `0.72s`; the conditional
    real rootless probe was collected and skipped because
    `MMAUDIT_TEST_ROOTLESS_IMAGE` is not configured.
  - The broadened isolation/pipeline set passed `240` tests with `3` documented
    rootless-image skips in `42.44s`.
  - Both schemas and the sealed fixture manifest parsed; the runtime probe
    passed syntax-only validation. Fixture link, executable, and marker checks
    were empty. Neither `podman` nor `docker` is installed, confirming that a
    materially different local real-rootless attempt is unavailable.
  - `.venv/bin/pytest -q` passed `615` tests with `9` documented
    environment/tool skips in `137.18s`; repository-wide Ruff passed, all `198`
    files were formatted, and configured strict mypy passed `99` source files.
  - Final credential-pattern, fixture marker, generated-artifact, diff, and
    status checks passed after removing `17` disposable Foundry failure caches.
- **Files changed:** `schemas/adversarial_acceptance_manifest.schema.json`,
  `schemas/adversarial_acceptance_report.schema.json`,
  `src/mmaudit/adversarial_acceptance.py`, `src/mmaudit/traceability.py`,
  `tests/fixtures/adversarial_repository/cases.json`,
  `tests/integration/test_adversarial_acceptance_fail_closed.py`,
  `tests/integration/test_adversarial_repository_isolation.py`, and
  `tests/unit/test_adversarial_acceptance.py`.
- **Technical blocker:** Real rootless containment remains unexecuted on
  this host because no pinned test image or verified rootless runtime is
  configured. All independent rejection, deterministic containment,
  fail-closed, schema, report, and conditional-integration work is complete;
  current evidence is explicitly `fail_closed`, never real execution.
- **Checkpoint commit:** None; every repository path remains untracked, so an
  isolated ticket commit would create a broken partial initial history.
- **Exact next safe action:** Continue with `E2E-003`; inventory the synthetic
  full protocol, offline snapshot, scope, and blind-first prior-audit flows.

## 2026-07-27 — E2E-001

- **Ticket:** `E2E-001`
- **Status:** `COMPLETE`
- **Defensive objective:** Validate all source-bound synthetic economic
  harnesses end to end, reproduce each planted unsafe condition twice, keep
  safe near-misses unconfirmed, and serialize normalized acceptance evidence.
- **Completed changes so far:**
  - Added a strict, self-hashed 18-case manifest binding every Foundry config,
    Solidity source, test, typed economic template, and exact unsafe/safe
    harness inventory.
  - Added bounded non-link manifest loading with exact fixture-tree and content
    hash validation.
  - Added typed observations that distinguish harness execution from unsafe
    reproduction and safe-control outcomes, plus internally reconciled,
    self-hashed acceptance reports.
  - Added strict manifest/report schemas, tamper and link-negative unit tests,
    and a real aggregate Foundry integration using fixed contract selectors,
    offline mode, external tool validation, sanitized environments, disposable
    artifacts, bounded timeouts, and no model or network use.
  - Updated economic-portfolio traceability from its outdated partial status
    after the aggregate suite compiled and executed all 43 applicable harnesses.
- **Commands and results so far:**
  - Affected Ruff and strict mypy passed throughout implementation.
  - Initial unit coverage passed `8` tests; one subsequent link-message
    assertion mismatch was corrected without changing the safety behavior.
  - The first sanitized real-Forge attempt failed closed because the sanitized
    home could not resolve a compiler. The second materially different attempt
    pinned the installed external Foundry-managed Solidity `0.8.30` compiler
    while retaining the sanitized environment and offline execution.
  - Final focused validation passed `9` tests in `28.54s`; the real aggregate
    run compiled and executed all `43` applicable harnesses, reproduced all
    `21` unsafe controls in two fresh campaigns, and passed all `22` safe
    near-miss controls.
  - The first broader validation passed `184` tests with one documented
    isolation skip and exposed one stale pipeline assertion that still expected
    the economic traceability row to fail. The assertion now requires that row
    to pass while the independent protocol-economic runtime gate remains
    honestly failed; `24` focused traceability/assurance/pipeline tests passed.
  - The corrected broader command passed `185` tests with the one documented
    local-isolation skip in `119.91s`.
  - `.venv/bin/pytest -q` passed `606` tests with `9` documented
    environment/tool skips in `145.76s`.
  - Repository-wide Ruff formatting/check passed `195` files and configured
    strict mypy passed `98` source files.
  - An optional `forge fmt --check` exposed style-only drift in `12` synthetic
    economic fixture trees. Mechanical `forge fmt` normalized them; all `18`
    fixture trees then passed the format check, their source-bound hashes and
    aggregate manifest hash were resealed, and the real focused acceptance set
    again passed `9` tests in `28.63s`.
  - Direct normalized report/schema validation passed for `18` cases, `43`
    executed harnesses, `21` reproduced unsafe controls, and `22` unconfirmed
    safe near-misses.
  - The post-format `.venv/bin/pytest -q` run passed `606` tests with `9`
    documented environment/tool skips in `138.11s`; final Ruff, strict mypy,
    Forge formatting, JSON parsing, sealed-hash, credential-pattern,
    generated-artifact, status, and diff checks passed.
  - An explicit strict-mypy invocation against the entire legacy pipeline test
    module reported its existing `43` test-annotation diagnostics; affected
    source-module mypy remains clean, and the repository-configured full mypy
    command is still required before completion.
- **Files changed:** `schemas/economic_acceptance_manifest.schema.json`,
  `schemas/economic_acceptance_report.schema.json`,
  `src/mmaudit/economic_acceptance.py`, `src/mmaudit/traceability.py`,
  `tests/fixtures/solidity/maximum_assurance_economic/manifest.json`,
  `tests/integration/test_economic_acceptance_foundry.py`, and
  `tests/unit/test_economic_acceptance.py`; mechanically formatted `12`
  existing `economic_*` fixture trees and aligned one maximum-assurance
  pipeline expectation with the implemented economic traceability row.
- **Remaining limitation:** The aggregate acceptance suite validates the fixed
  local synthetic portfolio; it does not claim universal protocol coverage.
- **Checkpoint commit:** None; every repository path remains untracked, so an
  isolated ticket commit would create a broken partial initial history.
- **Exact next safe action:** Begin `E2E-002` by inventorying hostile behavior
  coverage, rejection evidence, isolation adapters, and conditional real
  containment tests without executing repository-local hostile commands.

## 2026-07-27 — MAN-003

- **Ticket:** `MAN-003`
- **Status:** `COMPLETE`
- **Defensive objective:** Replay sealed deterministic scanner, saved-test, and
  counterexample evidence locally without constructing or contacting a model
  provider.
- **Completed changes so far:**
  - Added a typed offline replay orchestrator that first requires a clean
    `verify-run` result, then loads only bounded, non-link, manifest-bound
    artifacts.
  - Reused the existing scanner, Foundry invariant, and reproduction runners;
    replay uses disposable workspaces, disables fork probing for scanners, and
    records remote-network denial plus local-loopback-only policy.
  - Added stable semantic projections that exclude timings, commands, and
    disposable paths while comparing tool fingerprints, normalized findings,
    execution states, source/compiler hashes, attempt evidence, minimization,
    and settlement evidence.
  - Added a self-hashed normalized replay report, strict bounded schema, and
    `mmaudit replay`; success requires matched execution evidence for scanner,
    saved-test, and counterexample kinds.
  - Added a synthetic non-production Foundry fixture and a conditional real
    hardened-isolation integration test.
- **Commands and results so far:**
  - Affected Ruff and strict mypy passed.
  - Deterministic mocked local-runner and CLI coverage passed `27` tests in
    `1.14s`, including clean replay, semantic drift, manifest-first refusal,
    link rejection, self-hash/schema validation, and a network/provider denial
    sentinel.
  - The real Foundry integration collected but skipped because
    `default_isolation_backend("auto")` found no usable hardened backend.
    A direct `/usr/bin/sandbox-exec` preflight confirmed the nested sandbox
    limitation with exit `71` (`sandbox_apply` operation not permitted).
  - Final focused validation passed affected Ruff, strict mypy, and `45`
    replay/CLI/manifest/traceability tests in `1.34s` after enforcing exact
    harness/result coverage and saved-test specification hashes.
  - The broader replay, scanner, invariant, reproduction-integrity, isolation,
    assurance, pipeline, CLI, and traceability set passed `263` tests with the
    one documented hardened-isolation skip in `51.15s`.
  - `.venv/bin/pytest -q` passed `597` tests with `9` documented environment
    skips in `109.02s`.
  - Final full Ruff formatting/check and strict mypy passed all `192` files and
    `97` source files respectively. Installed replay help, JSON schema parsing,
    Solidity fixture formatting, bounded credential-pattern scanning,
    trailing-whitespace validation, status/diff review, and generated-artifact
    inspection passed.
  - Removed `17` disposable Foundry invariant failure-cache files regenerated
    by the full suite.
- **Files changed so far:** `schemas/offline_replay.schema.json`,
  `src/mmaudit/cli.py`, `src/mmaudit/orchestration/replay.py`,
  `tests/fixtures/solidity/offline_replay/foundry.toml`,
  `tests/fixtures/solidity/offline_replay/src/ReplayCounter.sol`,
  `tests/integration/test_offline_replay.py`, `tests/unit/test_cli.py`, and
  `tests/unit/test_replay.py`.
- **Remaining limitation:** The real hardened Foundry replay test is present
  but skipped in this sandbox because nested `sandbox-exec` is prohibited and
  no other hardened backend is configured. The deterministic mocked adapter
  coverage is explicitly labeled mocked; no real execution was fabricated.
- **Checkpoint commit:** None; every repository path remains untracked, so a
  safe isolated ticket checkpoint cannot be created.
- **Exact next safe action:** Begin `E2E-001` by inventorying economic fixtures,
  execution coverage, and existing real local Foundry acceptance helpers.

## 2026-07-27 — MAN-002

- **Ticket:** `MAN-002`
- **Status:** `COMPLETE`
- **Defensive objective:** Detect changed or missing security-relevant run
  evidence without executing target code.
- **Completed changes so far:**
  - Added bounded loading and observation APIs around the self-hashed evidence
    manifest, including sensitive-name and link rejection.
  - Added a typed, self-hashed, deterministic run-verification record that
    reconciles source, configuration, prompt, model, tool, compiler, isolation,
    seed, corpus, harness, reproduction, coverage, artifact, and benchmark
    certificate bindings.
  - Added the read-only `mmaudit verify-run` command with distinct clean,
    stale, and invalid-input exit behavior.
  - Published the strict bounded run-verification schema and updated
    traceability to record independent verification as implemented while
    retaining an explicit offline-replay limitation.
  - Added clean, changed, missing, category coverage, tamper, serialization,
    schema, and sensitive-path tests.
- **Commands and results so far:**
  - Affected Ruff formatting/check, strict mypy, and the initial focused
    manifest/CLI suite passed `30` tests before the final bounded-writer,
    schema, traceability, and hardening additions.
  - Final focused validation passed affected Ruff, strict mypy, `40`
    manifest/CLI/traceability tests in `1.23s`, installed `verify-run --help`,
    and JSON schema parsing.
  - The first broader command used the nonexistent pluralized path
    `tests/integration/test_traceability_artifacts.py` and collected no tests.
    The corrected command used `test_traceability_artifact.py` and passed
    `111` assurance, manifest, pipeline, benchmark-certificate, CLI, and
    traceability tests in `37.91s`.
  - `.venv/bin/pytest -q` passed `593` tests with `8` documented environment
    skips in `105.48s`.
  - Final `.venv/bin/ruff format --check .` reported all `189` files formatted;
    full Ruff passed; strict mypy passed all `96` source files; schema parsing,
    bounded credential-pattern scanning, trailing-whitespace validation,
    `git diff --check`, status inspection, and affected-file review passed.
  - Removed `17` disposable Foundry invariant failure-cache files regenerated by
    the full suite; no committed or source artifact was removed.
- **Files changed so far:** `schemas/run_verification.schema.json`,
  `src/mmaudit/cli.py`, `src/mmaudit/orchestration/manifest.py`,
  `src/mmaudit/orchestration/verification.py`,
  `src/mmaudit/traceability.py`, `tests/unit/test_cli.py`, and
  `tests/unit/test_manifest.py`.
- **Remaining limitation:** Verification proves local evidence consistency but
  intentionally does not execute evidence or independently replay it; that
  capability is dependency-ordered `MAN-003`.
- **Checkpoint commit:** None; every repository path remains untracked, so a
  safe isolated ticket checkpoint cannot be created.
- **Exact next safe action:** Begin `MAN-003` by mapping persisted deterministic
  scanner, saved-test, and counterexample evidence to existing bounded local
  execution APIs.

## 2026-07-27 — BENCH-005

- **Ticket:** `BENCH-005`
- **Status:** `COMPLETE`
- **Defensive objective:** Prevent unsupported superiority claims with a strict
  `NOT_EVALUATED`, `NOT_DEMONSTRATED`, or `DEMONSTRATED` assessment.
- **Completed changes:**
  - Added strict self-hashed human-comparison evidence with bounded proportion
    samples and hash bindings for the corpus, benchmark result, blinding protocol,
    review protocol, and independent adjudication.
  - Added a deterministic three-state assessment that defaults to
    `NOT_EVALUATED`, resolves supplied but insufficient evidence to
    `NOT_DEMONSTRATED`, and permits `DEMONSTRATED` only when all five necessary
    blind/comparable/adjudicated/precision/recall preconditions pass.
  - Added reproducible 95% Wilson/Newcombe lower-bound calculations for both
    precision and recall; parsed statistical projections and the outer assessment
    are arithmetically and cryptographically tamper-evident.
  - Integrated the assessment into benchmark report serialization and
    `mmaudit benchmark --human-comparison`, with exact corpus-hash binding.
  - Published a strict bounded human-comparison schema and updated traceability
    to distinguish the implemented gate from the still-unavailable qualifying
    real human-comparison evidence.
- **Commands and results so far:**
  - The initial affected Ruff run identified one import-order defect; it was
    corrected, after which Ruff passed.
  - Initial strict mypy rejected a floating-point `Literal`; replacing it with
    an exact bounded float field preserved the `0.95` contract and passed mypy.
  - The focused claim, benchmark, CLI, and traceability set passed `78` tests in
    `0.97s` on the final focused run, including all `32` boolean precondition combinations, default-state,
    tamper, symlink, corpus-mismatch, schema, and serialization coverage.
  - The broader claim, benchmark, mutation, certificate, manifest, assurance,
    CLI, scanner-reporting, traceability, pipeline, and traceability-artifact set
    passed `196` tests in `46.80s`.
  - The installed no-evidence CLI path verified all `15` source bindings,
    reported `not_evaluated`, exited with expected `INCOMPLETE` code `6`, and
    reloaded with deterministic assessment hash
    `55fa7ad0831eed662d54e418541a4989dbc64c1e7af8a2ddf43aa1a67a76d2eb`.
  - `.venv/bin/pytest -q` passed `588` tests with `8` documented environment
    skips in `105.60s`.
  - Final strict mypy passed all `95` source files. Affected Ruff format/check,
    schema parsing, deterministic default-assessment reload, credential-pattern
    scanning, generated-artifact scanning, whitespace validation, status
    inspection, and diff review passed.
- **Files changed:** `docs/codex_work_queue.md`,
  `docs/codex_worklog.md`, `schemas/human_comparison_evidence.schema.json`,
  `src/mmaudit/benchmark/claims.py`, `src/mmaudit/benchmark/engine.py`,
  `src/mmaudit/cli.py`, `src/mmaudit/traceability.py`,
  `tests/unit/test_benchmark.py`, `tests/unit/test_benchmark_claims.py`, and
  `tests/unit/test_cli.py`.
- **Remaining limitation:** No qualifying real blinded human-comparison corpus
  has been executed. Traceability therefore remains partial and the emitted
  default is `NOT_EVALUATED`; no superiority claim is made.
- **Checkpoint commit:** None; every repository path remains untracked, so a
  safe isolated ticket checkpoint cannot be created.

## 2026-07-27 — BENCH-004

- **Ticket:** `BENCH-004`
- **Status:** `COMPLETE`
- **Defensive objective:** Expand must-catch, safe, mutation, and blinded
  benchmark layers while keeping every required repository-level metric explicit.
- **Completed changes:**
  - Upgraded the benchmark manifest to a strict self-hashed `2.0` corpus with
    declared post-run ground-truth disclosure, sorted repository/case identities,
    safe controls for every must-catch category, and SHA-256 bindings for every
    referenced synthetic source.
  - Added non-executing local ground-truth verification with traversal, link,
    hardlink, size, sensitive-name, source-hash, UTF-8, and line-range checks;
    `mmaudit benchmark` now validates those sources before evaluating reports.
  - Added explicit arithmetically validated per-repository critical recall, safe
    false confirmations, exact-location accuracy, reproduction rate, attributed
    mutation score/gate, cost, tokens, runtime, and first-finding time.
  - Added fail-closed exact-location and unmasked repository gates; aggregate
    counts, rates, cost, runtime, and mutation projections must reconcile with
    the repository records during report parsing.
  - Extended mutation scorecards with exact property-to-repository attribution
    and published `schemas/benchmark_manifest.schema.json`.
- **Commands and results so far:**
  - Source SHA-256 inspection bound `15` fixture files; the sealed `28`-case,
    `2`-repository corpus hash is
    `186534e1d0d263920d42041e39b05fd6fb4acc57f5e7e4c9c1321a403756845b`.
  - Affected Ruff format/check and strict mypy passed.
  - The focused benchmark, mutation, and CLI set passed `43` tests in `1.09s`.
  - `.venv/bin/mmaudit benchmark --help` passed and exposed the local
    ground-truth root and typed mutation-scorecard controls.
  - The first broader command named a nonexistent `tests/unit/test_reporting.py`
    and collected no tests. The corrected benchmark, mutation, certificate,
    manifest, assurance, CLI, scanner-reporting, traceability, pipeline, and
    traceability-artifact set passed `160` tests in `38.70s`.
  - The installed `mmaudit benchmark` no-report path verified all `15` source
    bindings, wrote a typed `2.0` report, and exited with the expected
    `INCOMPLETE` code `6`; the report reloaded with both repository records and
    the sealed corpus hash.
  - Optional `jsonschema` validation was unavailable because that package is not
    installed. No retry was made; independent JSON parsing, Pydantic corpus/report
    validation, published-schema structural tests, source validation, and
    whitespace validation passed.
  - `.venv/bin/pytest -q` passed `552` tests with `8` documented environment
    skips in `105.26s`.
  - Final strict mypy passed all `94` source files. Affected Ruff format/check,
    corpus/schema JSON parsing, source-binding validation, credential-pattern
    scanning, generated-artifact scanning, whitespace validation, status
    inspection, and diff review passed.
- **Files changed:** `benchmarks/corpus/manifest.json`,
  `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `schemas/benchmark_manifest.schema.json`,
  `src/mmaudit/benchmark/engine.py`,
  `src/mmaudit/benchmark/mutations.py`, `src/mmaudit/cli.py`,
  `tests/unit/test_benchmark.py`, and `tests/unit/test_cli.py`.
- **Remaining limitation:** The optional third-party `jsonschema` package is not
  installed; no external-validator result is claimed. The published schema was
  parsed and structurally tested, while the stricter Pydantic validators checked
  cross-field, canonical-hash, source-integrity, and aggregate consistency.
- **Checkpoint commit:** None; every repository path remains untracked, so a
  safe isolated ticket checkpoint cannot be created.

## 2026-07-27 — MODEL-002

- **Ticket:** `MODEL-002`
- **Status:** `COMPLETE`
- **Defensive objective:** Implement deterministic model-quality benchmarking
  across location accuracy, rejection behavior, economic/invariant quality,
  prompt-injection resistance, and structured-output reliability.
- **Completed changes:**
  - Added a strict self-hashed synthetic corpus whose provider-visible request
    excludes expectation and dimension metadata.
  - Added canonical root-lineage target selection, alias deduplication, explicit
    synthetic-source egress/retention/approval gates, and a narrow adapter over
    the existing bounded structured-output client.
  - Added independent per-case and per-lineage scores for exact location,
    rejection, observed-versus-assumed economic invariant quality, repository
    instruction resistance, and strict structured-output reliability.
  - Added deterministic self-hashed reporting without raw provider output and a
    `mmaudit models benchmark` CLI that requires explicit configured egress and
    provider credentials.
  - Added a default-branch-only, secret-conditional real-provider CI step whose
    immutable model ID must be supplied through repository configuration; no
    provider call is attempted for pull requests or unconfigured jobs.
  - Added fake-provider regressions for perfect, malformed-structured, and
    repository-instruction-influenced outputs plus blinded-request, alias, policy,
    tamper, stable serialization, bounded output, and path-safety coverage.
- **Commands and results so far:**
  - `.venv/bin/ruff format src/mmaudit/benchmark/models.py src/mmaudit/cli.py
    tests/unit/test_model_benchmark.py tests/unit/test_cli.py` left the four
    affected files formatted.
  - `.venv/bin/ruff check src/mmaudit/benchmark/models.py src/mmaudit/cli.py
    tests/unit/test_model_benchmark.py tests/unit/test_cli.py` passed.
  - `.venv/bin/mypy src/mmaudit/benchmark/models.py src/mmaudit/cli.py` passed
    with no issues in the two source files.
  - The first focused test run found one assertion expecting the report-hash
    validator before the stronger aggregate-consistency validator. The fixture
    tamper was changed to preserve internal aggregates and exercise the outer
    hash; the corrected focused run passed `28` tests in `0.82s`.
  - `.venv/bin/mmaudit models benchmark --help` passed and exposed the corpus,
    repeated model, output, and explicit synthetic-source egress options.
  - The broader model, registry, provider, configuration, benchmark, certificate,
    manifest, traceability, CLI, and traceability-artifact set passed `101` tests
    in `1.07s`.
  - The committed model corpus loaded as `4` cases with canonical SHA-256
    `0215c11598cddbf8fd17f978a9c2b272d6014b6d58d96650ddc5ed9bd957c3d7`;
    the combined whitespace check passed.
  - `.venv/bin/pytest -q` passed `547` tests with `8` documented environment
    skips in `106.25s`.
  - Final strict mypy passed all `94` source files. Affected Ruff format/check,
    workflow YAML parsing, credential-pattern scanning, generated-artifact
    scanning, whitespace validation, status inspection, and diff review passed.
- **Files changed:** `.github/workflows/mmaudit.yml`,
  `benchmarks/model_corpus/manifest.json`, `docs/codex_work_queue.md`,
  `docs/codex_worklog.md`, `src/mmaudit/benchmark/models.py`,
  `src/mmaudit/cli.py`, `tests/unit/test_cli.py`, and
  `tests/unit/test_model_benchmark.py`.
- **Remaining limitation:** The real-provider command is configured only for the
  protected default-branch CI job and remains unexecuted locally because no
  provider credential or committed operator model selection is available. No
  integration success is claimed.
- **Checkpoint commit:** None; every repository file remains untracked, so an
  isolated ticket checkpoint would create a broken partial history.

## 2026-07-27 — BENCH-003

- **Ticket:** `BENCH-003`
- **Status:** `COMPLETE`
- **Defensive objective:** Make `mmaudit run --benchmark-gate` verify a current
  passed-corpus certificate and exit nonzero before audit execution when the
  certificate is absent, tampered, or stale.
- **Completed changes:**
  - Added explicit certificate, component-root, and observed-commit inputs to
    the existing benchmark-gate preflight for both run modes.
  - Added a shared non-executing verifier that rejects absent, stale, tampered,
    projection-only, identity-mismatched, and failed-corpus certificates before
    pipeline construction.
  - Replaced the assurance boolean with typed self-hashed verification evidence;
    required pipeline calls now reject absent/non-current evidence before
    creating a run, and current evidence is persisted into the run manifest.
  - Marked the traceability row implemented with code, unit/integration, and
    final-report runtime evidence, while retaining the dedicated verification
    artifact for gated runs.
- **Files changed:** `docs/codex_work_queue.md`,
  `docs/codex_worklog.md`, `src/mmaudit/benchmark/certificate.py`,
  `src/mmaudit/cli.py`, `src/mmaudit/orchestration/assurance.py`,
  `src/mmaudit/orchestration/pipeline.py`, `src/mmaudit/traceability.py`,
  `tests/integration/test_pipeline.py`, `tests/unit/test_assurance.py`, and
  `tests/unit/test_cli.py`.
- **Commands and results:**
  - Initial strict mypy passed. The first focused unit run passed `48` tests and
    found one Rich line-wrap assertion; the corrected run passed `49` tests in
    `0.84s`.
  - The first focused pipeline run passed the absent preflight and found that a
    standard-profile report does not expose the maximum-assurance clause list.
    The test was corrected to validate the stronger persisted run-manifest
    binding; both focused pipeline tests then passed in `0.35s`.
  - The broader CLI, pipeline, assurance, certificate, traceability, manifest,
    and reporting set passed `136` tests in `38.30s`.
  - `.venv/bin/pytest -q` passed `539` tests with `8` documented environment
    skips in `105.33s`.
  - Final strict mypy passed all `93` source files; affected Ruff format/check,
    `mmaudit run --help`, traceability validation, generated-artifact review,
    credential-pattern review, trailing-whitespace review, and `git diff
    --check` passed.
- **Unresolved issues:** None specific to BENCH-003.
- **Checkpoint:** None; every repository path remains untracked, so an isolated
  ticket commit would create a broken partial history.

## 2026-07-27 — BENCH-002

- **Ticket:** `BENCH-002`
- **Status:** `COMPLETE`
- **Defensive objective:** Add CLI certification and verification commands that
  create certificates only from passed benchmark gates and fail closed when any
  repository or component binding is stale.
- **Completed changes:**
  - Converted `mmaudit benchmark` into a backward-compatible command group while
    preserving direct evaluation and adding `benchmark certify`.
  - Added a strict sorted local component-path manifest and file-backed
    certificate builder that parses the benchmark report and refuses issuance
    unless its status and every declared gate passed.
  - Added top-level `verify-certificate`, which re-hashes every recorded local
    file, compares the observed commit and bindings, emits self-hashed
    verification evidence, and exits `INCOMPLETE` for stale certificates.
  - Added CLI success/current, changed-binding, envelope-tamper, and failed-gate
    regressions without executing any component file.
- **Files changed:** `docs/codex_work_queue.md`,
  `docs/codex_worklog.md`, `src/mmaudit/benchmark/certificate.py`,
  `src/mmaudit/cli.py`, and `tests/unit/test_cli.py`.
- **Commands and results:**
  - Initial affected Ruff and strict mypy passed. The first focused CLI run had
    one Rich line-wrap assertion mismatch; adjusting the output assertion
    produced `23` passing certificate/CLI tests in `0.68s`.
  - `mmaudit benchmark --help`, `mmaudit benchmark certify --help`, and
    `mmaudit verify-certificate --help` rendered the preserved evaluation and
    new certificate surfaces.
  - The broader CLI, certificate, benchmark, manifest, repository, and
    traceability set passed `72` tests in `1.07s`.
  - `.venv/bin/pytest -q` passed `532` tests with `8` documented environment
    skips in `105.06s`.
  - Final strict mypy passed all `93` source files; affected Ruff format/check,
    generated-artifact review, credential-pattern review, trailing-whitespace
    review, and `git diff --check` passed.
- **Unresolved issues:** None specific to BENCH-002. `BENCH-003` supplies
  automatic `mmaudit run` enforcement.
- **Checkpoint:** None; every repository path remains untracked, so an isolated
  ticket commit would create a broken partial history.

## 2026-07-27 — BENCH-001

- **Ticket:** `BENCH-001`
- **Status:** `COMPLETE`
- **Defensive objective:** Define a path-safe benchmark certificate that
  cryptographically binds the exact commit, configuration, prompts, models,
  tools, compilers, corpus, ground truth, and evaluated report.
- **Completed changes:**
  - Added strict file/projection bindings for every required component category
    and the evaluated benchmark report.
  - Added commit-inclusive component hashing, deterministic certificate sealing,
    and typed current/stale verification evidence for changed, missing,
    unexpected, and commit-mismatched components.
  - Added bounded non-link file hashing/loading/writing with traversal,
    sensitive-name, special-file, hardlink, and symlink rejection.
  - Published a strict bounded JSON schema without embedding corpus or blinded
    ground-truth contents.
- **Files changed:** `docs/codex_work_queue.md`,
  `docs/codex_worklog.md`, `schemas/benchmark_certificate.schema.json`,
  `src/mmaudit/benchmark/certificate.py`, and
  `tests/unit/test_benchmark_certificate.py`.
- **Commands and results:**
  - Initial affected Ruff and strict mypy passed; JSON parsing passed.
  - The first focused run passed six tests and found one test assertion that
    dereferenced a shared schema definition as an inline array. Correcting the
    assertion produced `7` passing focused tests in `0.04s`.
  - The broader benchmark, manifest, repository, assurance, and traceability
    set passed `69` tests in `0.55s`.
  - `.venv/bin/pytest -q` passed `528` tests with `8` documented environment
    skips in `104.78s`.
  - Final strict mypy passed all `93` source files; affected Ruff format/check,
    schema parsing, generated-artifact review, credential-pattern review,
    trailing-whitespace review, and `git diff --check` passed.
- **Unresolved issues:** None specific to BENCH-001. Certificate issuance and
  CLI verification are intentionally implemented by dependency ticket
  `BENCH-002`.
- **Checkpoint:** None; every repository path remains untracked, so an isolated
  ticket commit would create a broken partial history.

## 2026-07-27 — SNAP-003

- **Ticket:** `SNAP-003`
- **Status:** `COMPLETE`
- **Defensive objective:** Add an explicit-opt-in read-only importer that permits
  only approved observation methods and emits sanitized deterministic snapshots
  without signing or sending.
- **Completed changes:**
  - Added a strict, self-hashed import plan whose enum vocabulary contains only
    six approved observation methods and cannot represent endpoints, signing,
    sending, wallet data, or arbitrary method names.
  - Added an explicit double opt-in importer restricted to plain HTTP loopback
    endpoints with bounded, non-redirecting, environment-independent requests
    and sanitized failures.
  - Added deterministic observation of pinned chain/block identity, runtime code,
    proxy storage, roles, timelocks, oracle values, balances, and typed raw
    configuration into the existing source-free deployment snapshot schema.
  - Added `mmaudit snapshot import`, mocked-RPC allowlist/determinism/negative
    tests, CLI pre-network opt-in coverage, and a zero-account disposable Anvil
    integration using only local synthetic chain state.
- **Files changed:** `docs/codex_work_queue.md`,
  `docs/codex_worklog.md`, `src/mmaudit/cli.py`,
  `src/mmaudit/snapshots/importer.py`,
  `tests/integration/test_snapshot_importer_local_chain.py`,
  `tests/unit/test_cli.py`, and `tests/unit/test_snapshot_importer.py`.
- **Commands and results:**
  - Initial mocked-RPC and CLI coverage passed `21` tests in `0.58s`; affected
    Ruff and strict mypy passed.
  - `.venv/bin/pytest -q tests/unit/test_snapshot_importer.py
    tests/unit/test_cli.py
    tests/integration/test_snapshot_importer_local_chain.py` passed `21` tests
    and skipped only loopback binding in the normal sandbox in `0.51s`.
  - The same local-chain integration, rerun with permission for a loopback socket,
    passed `1` real zero-account Anvil test in `0.21s`. It used no public
    endpoint, account, signing, or broadcast path.
  - The broader snapshot, CLI, reproduction, and reporting set passed `120`
    tests with the same normal-sandbox loopback skip in `2.95s`.
  - `.venv/bin/pytest -q` passed `521` tests with `8` documented environment
    skips in `104.87s`; the new skip is the separately passed loopback test.
  - An affected formatting check identified three files; Ruff formatted them,
    final Ruff passed, strict mypy passed all `92` source files, and the
    post-format focused suite passed `21` tests in `0.53s`.
  - `mmaudit snapshot import --help`, generated-artifact review, bounded
    credential-pattern review, trailing-whitespace review, and `git diff
    --check` passed. Matches were only negative validation fixtures and existing
    environment-variable names, never values.
- **Unresolved issues:** None specific to SNAP-003. The local-chain integration
  needs loopback socket permission in this sandbox and passed when provided.
- **Checkpoint:** None; every repository path remains untracked, so an isolated
  ticket commit would create a broken partial history.

## 2026-07-27 — SNAP-002

- **Ticket:** `SNAP-002`
- **Status:** `COMPLETE`
- **Defensive objective:** Compare validated offline deployed state with local
  compiler artifacts and report bytecode, library-link, immutable, and
  compiler-setting mismatches without live RPC access.
- **Completed changes:**
  - Extended snapshot source bindings with exact compiler projections, full
    settings hashes, and explicit library/immutable ranges and expected values.
  - Added a bounded, non-executing parser for direct and build-info compiler
    artifacts with root containment, link, size, UTF-8, placeholder, reference,
    ordering, and overlap validation.
  - Added deterministic core-bytecode comparison that masks only declared
    variable ranges while independently checking library addresses and immutable
    values.
  - Added field-level compiler version, optimizer, EVM, via-IR, metadata, full
    settings, and exact artifact-hash differences.
  - Added self-hashed matched/mismatched/inconclusive comparison reports and
    synthetic matching/mismatching offline compiler artifacts.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `schemas/deployment_snapshot.schema.json`,
  `src/mmaudit/snapshots/compare.py`,
  `src/mmaudit/snapshots/schema.py`,
  `tests/fixtures/snapshots/compiler_artifacts/matching-compiler-artifact.json`,
  `tests/fixtures/snapshots/compiler_artifacts/mismatching-compiler-artifact.json`,
  `tests/fixtures/snapshots/traversal.json`,
  `tests/fixtures/snapshots/valid.json`,
  `tests/unit/test_snapshot_compare.py`, and
  `tests/unit/test_snapshot_schema.py`.
- **Commands and results:**
  - `.venv/bin/pytest -q tests/unit/test_snapshot_schema.py
    tests/unit/test_snapshot_compare.py` passed `13` focused tests in `0.07s`.
  - `.venv/bin/pytest -q tests/unit/test_snapshot_schema.py
    tests/unit/test_snapshot_compare.py tests/unit/test_solidity.py
    tests/unit/test_manifest.py tests/unit/test_scanners_reporting.py` passed
    `94` tests in `2.24s`.
  - The first full suite passed `511` tests with `7` skips in `104.53s`.
    A final fixture-location review found the generic `artifacts/` directory was
    intentionally ignored, so fixtures were moved to `compiler_artifacts/` and
    the focused suite was rerun rather than weakening ignore rules.
  - Final `.venv/bin/pytest -q` passed `511` tests with `7` documented
    optional-integration skips in `102.02s`.
  - Final affected Ruff format/check, strict mypy, JSON parsing, exact
    snapshot/artifact/report hash replay, ignored/generated-artifact review,
    synthetic secret-pattern review, and `git diff --check` passed.

## 2026-07-27 — SNAP-001

- **Ticket:** `SNAP-001`
- **Status:** `COMPLETE`
- **Defensive objective:** Define a source-free, hash-linked offline deployment
  snapshot covering chain/block identity, bytecode, proxies, roles, timelocks,
  oracles, balances, and configuration.
- **Completed changes:**
  - Added a strict offline snapshot payload and canonical self-hashed envelope
    covering exact chain/block identity, runtime bytecode, proxy links, roles,
    timelocks, oracle observations, balances, and typed configuration.
  - Bound runtime code to SHA-256, optional source identities to normalized
    source/artifact hashes, and all deployment relationships to observed code.
  - Enforced deterministic ordering, lowercase addresses, canonical typed values,
    explicit empty sections, and oracle freshness bounded by the pinned block.
  - Added bounded non-link read/write helpers with sensitive filename/key,
    traversal, shared-hardlink, source-content, and secret-content protections.
  - Published a strict bounded JSON schema and safe synthetic valid,
    malformed-hash, traversal, and secret-bearing fixtures.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `schemas/deployment_snapshot.schema.json`,
  `src/mmaudit/snapshots/__init__.py`,
  `src/mmaudit/snapshots/schema.py`,
  `tests/fixtures/snapshots/malformed.json`,
  `tests/fixtures/snapshots/secret-bearing.json`,
  `tests/fixtures/snapshots/traversal.json`,
  `tests/fixtures/snapshots/valid.json`, and
  `tests/unit/test_snapshot_schema.py`.
- **Commands and results:**
  - `.venv/bin/pytest -q tests/unit/test_snapshot_schema.py` passed `6` focused
    tests in `0.04s`.
  - `.venv/bin/pytest -q tests/unit/test_snapshot_schema.py
    tests/unit/test_manifest.py tests/unit/test_repository.py` passed `41` tests
    in `0.39s`.
  - `.venv/bin/python -m json.tool` parsed the published schema and all four
    fixtures successfully.
  - Final `.venv/bin/pytest -q` passed `505` tests with `7` documented
    optional-integration skips in `104.69s`.
  - Final affected Ruff format/check, strict mypy, canonical fixture hash,
    bounded synthetic secret-pattern review, generated-artifact review, and
    `git diff --check` passed. Secret-pattern matches were validation rules,
    assertions, and the zero-valued negative fixture only.

## 2026-07-27 — MUT-002

- **Ticket:** `MUT-002`
- **Status:** `COMPLETE`
- **Defensive objective:** Enforce explicit invariant/property mutation kill-score
  gates so weak remediation validation cannot receive maximum assurance.
- **Completed changes:**
  - Added hash-linked typed property/mutation outcomes with explicit killed,
    survived, and inconclusive states.
  - Added arithmetically validated per-property scorecards. Every expected
    property must have applicable evidence, no inconclusive outcome, and a `1.0`
    kill score for the maximum-assurance benchmark gate.
  - Preserved an overall score for reporting while ensuring it cannot conceal an
    unexercised or weak property.
  - Embedded scorecards in typed benchmark reports, enforced gate/report
    consistency during deserialization, and added a bounded non-symlink CLI
    scorecard loader.
  - Updated traceability to recognize the fail-closed mutation gate without
    removing the separate real cross-engine execution limitation.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/benchmark/engine.py`,
  `src/mmaudit/benchmark/mutations.py`, `src/mmaudit/cli.py`,
  `src/mmaudit/traceability.py`, `tests/unit/test_benchmark.py`, and
  `tests/unit/test_cli.py`.
- **Commands and results:**
  - Initial `.venv/bin/pytest -q tests/unit/test_benchmark.py
    tests/unit/test_mutations.py` passed `16` tests in `0.15s`.
  - CLI, symlink, schema-tampering, and hidden-aggregate additions brought
    `.venv/bin/pytest -q tests/unit/test_benchmark.py
    tests/unit/test_mutations.py tests/unit/test_cli.py` to `27` passing tests in
    `0.58s`.
  - `.venv/bin/pytest -q tests/unit/test_benchmark.py
    tests/unit/test_mutations.py tests/unit/test_cli.py
    tests/unit/test_assurance.py tests/unit/test_manifest.py
    tests/unit/test_scanners_reporting.py tests/unit/test_traceability.py`
    passed `97` tests in `1.20s`.
  - `.venv/bin/pytest -q tests/unit/test_traceability.py
    tests/unit/test_benchmark.py` passed `15` tests in `0.06s` after the final
    traceability update.
  - Final `.venv/bin/pytest -q` passed `498` tests with `7` documented
    optional-integration skips in `104.94s`.
  - Final affected Ruff format/check, strict mypy, bounded generated-artifact and
    credential-pattern review, and `git diff --check` passed. Credential-pattern
    matches were existing environment-variable reads in the CLI, not values.

## 2026-07-27 — FORM-002

- **Ticket:** `FORM-002`
- **Status:** `COMPLETE`
- **Defensive objective:** Add a fixed-command, isolated Kontrol property adapter
  with explicit trust policy, bounded proof assumptions and coverage, and
  normalized counterexample artifacts.
- **Completed changes:**
  - Added exact Kontrol version/SHA-256 trust pins and bounded proof depth and
    iteration configuration with synchronized disabled examples.
  - Added deterministic shared-corpus translation to assertion properties,
    validated fixed-command plans, bounded proof assumptions, and property maps.
  - Replaced the placeholder with an isolated, single-worker adapter that records
    source, plan, property-map, stdout, coverage, and normalized counterexample
    evidence without treating process success alone as proof.
  - Added deterministic translation/real local fixture compilation, bounded
    parser, mocked pinned execution, pin-mismatch prevention, plan validation,
    serialization, and reporting compatibility regressions.
  - Kept real proof integration honest: no local `kontrol` binary is installed,
    so only that optional subtask is `BLOCKED_TECHNICAL`.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `mmaudit.example.toml`, `src/mmaudit/config.py`,
  `src/mmaudit/solidity/engines/kontrol.py`,
  `src/mmaudit/solidity/formal.py`,
  `src/mmaudit/templates/mmaudit.example.toml`, and
  `tests/unit/test_kontrol.py`.
- **Commands and results:**
  - `.venv/bin/ruff check src/mmaudit/config.py
    src/mmaudit/solidity/engines/kontrol.py src/mmaudit/solidity/formal.py
    tests/unit/test_kontrol.py` passed.
  - `.venv/bin/mypy src/mmaudit/config.py
    src/mmaudit/solidity/engines/kontrol.py
    src/mmaudit/solidity/formal.py` passed with no issues in 3 files.
  - `.venv/bin/pytest -q tests/unit/test_kontrol.py` passed `5` tests in
    `0.92s`; the installed local Forge binary compiled the generated synthetic
    property fixture in an explicitly disposable output directory.
  - `.venv/bin/pytest -q tests/unit/test_kontrol.py
    tests/unit/test_formal.py tests/unit/test_halmos.py
    tests/unit/test_config.py tests/unit/test_manifest.py
    tests/unit/test_scanners_reporting.py` passed `85` tests in `4.35s`.
  - `cmp mmaudit.example.toml
    src/mmaudit/templates/mmaudit.example.toml` and explicit
    `load_config(Path("mmaudit.example.toml"), environ={})` validation passed.
  - `command -v kontrol` exited `1` with no output; no real execution was
    claimed.
  - Final `.venv/bin/pytest -q` passed `493` tests with `7` documented
    optional-integration skips in `103.87s`.
  - Final affected Ruff formatting/check, strict mypy, bounded artifact/secret
    review, and `git diff --check` passed.
- **Unresolved issue:** Real Kontrol proof execution remains
  `BLOCKED_TECHNICAL` until a trust-pinned local binary is installed.

## 2026-07-27 — FORM-001

- **Ticket:** `FORM-001`
- **Status:** `COMPLETE`
- **Defensive objective:** Add explicitly configured Certora property execution
  that preserves specification, assumption, vacuity, tool, and isolation evidence
  without leaking secrets or overstating unavailable integration.
- **Completed changes:**
  - Added an opt-in nested Certora configuration requiring exact CLI
    version/SHA-256 pins, safe repository-relative source/spec paths, indexed
    contract identity, a non-secret credential environment-variable name, sorted
    operator assumptions, and explicit vacuity mode.
  - Added a fixed, trust-pinned adapter that generates hash-linked
    specification-plan, assumption, and vacuity artifacts in a validated isolated
    repository copy.
  - Added bounded JSON normalization that distinguishes counterexamples,
    non-vacuous proofs, and vacuous/unknown outcomes; tool exit success cannot
    become a proof without normalized non-vacuity evidence.
  - Added adapter-scoped environment extension and immediate bounded scrubbing of
    stdout, stderr, and machine results. Synthetic canaries never enter serialized
    commands, runs, or generated plans.
  - Extended formal-run schemas with separately validated specification,
    assumption, and vacuity artifact paths plus vacuity coverage.
  - Added mocked local command/schema/result/redaction/unavailable tests and
    synchronized, safely disabled example configuration.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `mmaudit.example.toml`, `src/mmaudit/config.py`,
  `src/mmaudit/models/schemas.py`,
  `src/mmaudit/solidity/engines/certora.py`,
  `src/mmaudit/solidity/formal.py`,
  `src/mmaudit/templates/mmaudit.example.toml`, and
  `tests/unit/test_certora.py`.
- **Commands and results:**
  - Initial Ruff found one nested-condition style issue and strict mypy found one
    union-narrowing gap; both were corrected.
  - Initial focused pytest passed 3 tests and exposed a macOS process-limit
    interaction in the fake shell plus an artifact-path assertion mismatch. A
    shell-builtin marker and corrected workspace prefix resolved both without
    weakening isolation or evidence.
  - `.venv/bin/pytest -q tests/unit/test_certora.py` then passed `5` tests in
    `1.68s`; an honest-unavailable regression was added before broader validation.
  - `.venv/bin/pytest -q tests/unit/test_certora.py tests/unit/test_formal.py
    tests/unit/test_config.py tests/unit/test_manifest.py
    tests/unit/test_scanners_reporting.py` passed `81` tests in `3.13s`.
  - `cmp mmaudit.example.toml
    src/mmaudit/templates/mmaudit.example.toml` and explicit
    `load_config(Path("mmaudit.example.toml"), environ={})` validation passed.
  - Final `.venv/bin/pytest -q` passed `488` tests with `7` documented
    optional-integration skips in `103.02s`.
  - Final affected Ruff format/check, strict mypy, example synchronization,
    bounded credential-pattern review, and `git diff --check` passed. Credential
    scan matches were limited to the synthetic environment-variable identifier in
    redaction tests, not a credential value.
- **Artifact cleanup:** Removed `17` disposable Foundry invariant failure-cache
  files regenerated by the full suite.
- **Blocked integration subtask:** `command -v certoraRun` returned no executable.
  Real configured CI service execution is `BLOCKED_TECHNICAL`; no network,
  credential, or remote service access was attempted. Mocked adapter testing is
  explicitly recorded as mocked.
- **Remaining limitation:** The real configured-CI integration remains blocked as
  above; all independent safe implementation and validation portions are complete.
- **Checkpoint:** None; every repository path remains untracked, so an isolated
  cohesive commit cannot be created without manufacturing a broken partial
  history.

## 2026-07-27 — MUT-001

- **Ticket:** `MUT-001`
- **Status:** `COMPLETE`
- **Defensive objective:** Implement typed source-local security mutations that
  apply deterministically only to disposable repository copies and restore
  exactly.
- **Completed changes:**
  - Added a typed required five-class portfolio covering authorization-guard
    removal, replay-state update removal, strict-boundary weakening,
    accounting-operator replacement, and external-call result-check removal.
  - Pinned every mutation to a normalized Solidity path, exact source line, and
    full-file SHA-256 with kind-specific structural validation.
  - Reused bounded link/special-file workspace validation, excluded generated and
    sensitive paths, rejected workspaces within the source tree, and hash-verified
    the pristine copy before mutation.
  - Added deterministic whole-tree and file/line evidence for applications;
    duplicate applications must produce identical content hashes.
  - Added guarded restoration that rejects intervening changes and proves the
    disposable tree is byte-identical to the source while rechecking that the
    source itself never changed.
  - Added an abstract, synthetic, local-only Solidity fixture, one named
    apply/revert test per class, negative schema/integrity/containment controls,
    and a real local solc compilation test for every materialized mutant.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/benchmark/mutations.py`,
  `tests/fixtures/mutations/solidity/SafeMutationTargets.sol`,
  `tests/integration/test_mutation_compilation.py`, and
  `tests/unit/test_mutations.py`.
- **Commands and results:**
  - Initial focused pytest passed 8 tests and exposed one overly strict
    consumed-state identifier boundary; it was corrected. Initial Ruff exposed one
    assertion-order style issue; it was corrected.
  - Final `.venv/bin/ruff format --check`, `.venv/bin/ruff check`, and strict mypy
    passed for all affected Python files.
  - `.venv/bin/pytest -q tests/unit/test_mutations.py` passed `9` tests in
    `0.10s`.
  - `forge fmt --check
    tests/fixtures/mutations/solidity/SafeMutationTargets.sol` passed.
  - `.venv/bin/pytest -q tests/unit/test_benchmark.py
    tests/unit/test_repository.py tests/unit/test_mutations.py` passed `43` tests
    in `0.39s`.
  - The initial compiler integration passed, but the first full-suite invocation
    stopped at collection because unit and integration tests shared the
    `test_mutations.py` basename. Renaming the integration file corrected the
    collection identity.
  - `.venv/bin/pytest -q tests/integration/test_mutation_compilation.py
    tests/unit/test_mutations.py` passed `10` tests in `0.20s`.
  - The real local compiler integration used installed solc `0.8.30`; all `5`
    independently materialized mutants compiled, and every workspace restored
    exactly.
  - Final `.venv/bin/pytest -q` passed `482` tests with `7` documented
    optional-integration skips in `101.46s`.
  - The bounded credential-pattern scan of affected files returned no matches;
    final fixture formatting, generated-artifact scan, and `git diff --check`
    passed.
- **Artifact cleanup:** Removed `17` disposable Foundry invariant failure-cache
  files regenerated by the full suite; pre-existing ignored Python/pytest caches
  and the intentional offline Foundry fixture artifact were preserved.
- **Remaining limitation:** None specific to MUT-001.
- **Checkpoint:** None; every repository path remains untracked, so an isolated
  cohesive commit cannot be created without manufacturing a broken partial
  history.

## 2026-07-27 — DYN-004

- **Ticket:** `DYN-004`
- **Status:** `COMPLETE`
- **Defensive objective:** Expand deterministic Foundry fuzz/stateful campaigns so
  seeds and corpora persist, failing sequences minimize and replay, and
  function/state/sequence coverage remains separately measurable.
- **Completed changes:**
  - Added typed per-campaign evidence for declared/observed action functions,
    declared/observed state properties, sequence depth and observed lengths,
    minimized action IDs, and cross-attempt consistency.
  - Normalized Foundry output into those independent dimensions and attached it to
    every completed generated campaign without treating generated-only labels as
    execution evidence.
  - Added aggregate Solidity coverage counters and independent quality metrics for
    function, state-property, and minimized counterexample-sequence coverage.
  - Extended Markdown reporting and JSON round-trip validation for the separate
    ratios.
  - Extended mocked and real paired unsafe/safe state-ordering regressions to prove
    stable seed/depth, property-corpus hashing, manifest seed/corpus bindings,
    clean replay, bounded minimization, normalized evidence, and report
    serialization.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/coverage.py`,
  `src/mmaudit/solidity/invariant_execution.py`,
  `tests/integration/test_pipeline.py`, and
  `tests/unit/test_invariant_execution.py`.
- **Commands and results:**
  - Affected `.venv/bin/ruff format` and `.venv/bin/ruff check` passed.
  - Initial strict mypy found one heterogeneous-list inference error in the
    campaign-coverage validator; separating string and integer uniqueness checks
    corrected it, and strict mypy passed for all 4 affected source modules.
  - `.venv/bin/pytest -q tests/unit/test_invariant_execution.py::test_mocked_state_ordering_runner_proves_two_action_minimization`
    passed `1` test in `1.01s`.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_state_ordering_harness_persists_seed_sequence_and_removal_trials`
    passed `1` real local Foundry test in `8.30s`.
  - `.venv/bin/pytest -q tests/unit/test_invariant_execution.py
    tests/unit/test_manifest.py tests/unit/test_solidity.py
    tests/unit/test_scanners_reporting.py tests/unit/test_model_coverage.py
    tests/integration/test_economic_state_ordering_fixture.py` passed `151` tests
    in `12.03s`.
  - The first `.venv/bin/pytest -q` run reached `471` passed and `7` skipped in
    `100.86s` but exposed one fixture-specific assertion inserted under an earlier
    non-unique context. The assertion block was relocated without changing runtime
    behavior.
  - `.venv/bin/pytest -q
    tests/integration/test_pipeline.py::test_temporary_liquidity_harness_replays_settled_unsafe_and_safe_variants
    tests/integration/test_pipeline.py::test_state_ordering_harness_persists_seed_sequence_and_removal_trials`
    then passed `2` tests in `12.89s`.
  - Final `.venv/bin/pytest -q` passed `472` tests with `7` documented
    optional-integration skips in `100.83s`.
  - Final affected Ruff format/check and strict mypy passed; bounded
    credential-pattern hits were limited to pre-existing synthetic `.env`
    rejection tests and historical worklog command text; `git diff --check`
    passed.
- **Artifact cleanup:** Removed `17` disposable Foundry invariant failure-cache
  files regenerated by the full suite. Pre-existing ignored Python/pytest caches
  and the intentional offline Foundry artifact fixture were preserved.
- **Remaining limitation:** None specific to DYN-004; unavailable optional engine
  and hardened/rootless-isolation integrations remain separately tracked
  technical blockers.
- **Checkpoint:** None; every repository path remains untracked, so an isolated
  cohesive commit cannot be created without manufacturing a broken partial
  history.

## 2026-07-27 — ECO-018

- **Ticket:** `ECO-018`
- **Status:** `COMPLETE`
- **Defensive objective:** Validate bounded multi-step state-machine invariants
  with persisted seeds, minimized sequences, and same-clean-state replay.
- **Completed changes:**
  - Added a source-linked `MULTI_STEP_STATE_CONSISTENCY` invariant and
    `multi_transaction_state_ordering` economic template selected only from exact
    prepare, commit, and invalid-state evidence.
  - Added a typed depth-two harness with seed `18`, explicit ordered actions,
    multi-transaction capability policy, and a zero-invalid-state property guarded
    by both actions.
  - Parsed one unambiguous Foundry shrunk sequence, required identical sequence
    evidence across fresh-workspace replay, and proved bounded minimality only after
    both single-action removal campaigns passed twice on clean workspaces.
  - Persisted seed, original/shrunk lengths, retained action sequence, and typed
    removal-trial evidence through JSON/report serialization and coverage
    accounting.
  - Added paired unsafe/safe synthetic fixtures and deterministic prepare-only,
    commit-only, unsafe-full-sequence, and remediated-full-sequence controls.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/economics.py`,
  `src/mmaudit/solidity/invariant_execution.py`,
  `src/mmaudit/solidity/invariant_templates.py`,
  `src/mmaudit/solidity/invariants.py`,
  `tests/fixtures/solidity/economic_state_ordering/`,
  `tests/integration/test_economic_state_ordering_fixture.py`,
  `tests/integration/test_pipeline.py`, `tests/unit/test_economics.py`,
  `tests/unit/test_invariant_execution.py`, and
  `tests/unit/test_scanners_reporting.py`.
- **Commands and results:**
  - `forge fmt tests/fixtures/solidity/economic_state_ordering` and final
    `forge fmt --check tests/fixtures/solidity/economic_state_ordering` passed.
  - `forge test --root /private/tmp/mmaudit-eco018-fixture.5bfN14 --offline --color never --cache-path /private/tmp/mmaudit-eco018-cache --out /private/tmp/mmaudit-eco018-out --fuzz-runs 32 --fuzz-seed 18 -vvv`
    compiled successfully; `4` controls and the safe invariant passed, while the
    unsafe invariant produced the expected two-action counterexample
    (`5` passed, `1` expected failed; original `2`, shrunk `2`).
  - Affected `.venv/bin/ruff format`, `.venv/bin/ruff check`, and strict mypy
    passed for all changed source modules after one import-order correction.
  - The first focused pytest run exposed two assertion/integration-contract
    mismatches: fallback index metadata had already been source-validated but the
    harness redundantly required compiler return metadata, and Markdown correctly
    escaped an underscore. Both were corrected without weakening source evidence.
  - The focused ECO-018 pytest node set then passed `9` tests in `2.14s`.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_state_ordering_harness_persists_seed_sequence_and_removal_trials`
    passed in `8.12s`, including real generated compilation, two clean full-sequence
    replays, four clean removal-trial replays, coverage, and report round-trip.
  - `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/unit/test_scanners_reporting.py tests/integration/test_economic_state_ordering_fixture.py`
    passed `145` tests in `10.91s`.
  - `.venv/bin/pytest -q` passed `472` tests with `7` documented integration
    skips in `101.25s`.
  - Final affected Ruff format/check, strict mypy, fixture formatting,
    secret-pattern scan, generated-artifact scan, and `git diff --check` passed.
- **Artifact cleanup:** Removed `17` disposable Foundry invariant failure-cache
  files created by local regression runs; they were generated replay artifacts and
  can be regenerated by the tests.
- **Remaining limitation:** None specific to ECO-018; unavailable optional engine
  and hardened-isolation integrations remain separately tracked blockers.
- **Checkpoint:** None; the repository has no baseline commit and every path is
  untracked, so an isolated ticket commit cannot safely be created.

## 2026-07-27 — ECO-010

- **Ticket:** `ECO-010`
- **Status:** `COMPLETE`
- **Defensive objective:** Validate bounded share/asset exchange-rate transitions
  while separating legitimate yield from attacker-reachable value creation.
- **Completed changes:**
  - Added an exact source-linked yield-adjusted share-rate invariant and typed
    one-action harness with financial settlement plus normalized rate/redemption
    evidence.
  - Added paired local reported-asset unsafe and observed-asset safe fixtures with
    the same legitimate yield, share position, deterministic controls, and
    remediation-oriented regression coverage.
  - Added clean replay consistency checks, contextual evidence, economic metrics,
    coverage accounting, JSON round-trip, and Markdown serialization.
  - Split settlement and share-rate reconciliation into bounded generated
    Solidity frames after a compiler stack-depth diagnostic; removed an invalid
    helper qualifier exposed by the next compile.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/economics.py`,
  `src/mmaudit/solidity/invariant_execution.py`,
  `src/mmaudit/solidity/invariant_templates.py`,
  `src/mmaudit/solidity/invariants.py`,
  `tests/fixtures/solidity/economic_share_price/`,
  `tests/integration/test_economic_share_price_fixture.py`,
  `tests/integration/test_pipeline.py`, `tests/unit/test_economics.py`,
  `tests/unit/test_invariant_execution.py`, and
  `tests/unit/test_scanners_reporting.py`.
- **Commands and results:**
  - `forge fmt --check tests/fixtures/solidity/economic_share_price` passed.
  - `forge test --root tests/fixtures/solidity/economic_share_price --offline --color never --cache-path /private/tmp/mmaudit-eco010-cache --out /private/tmp/mmaudit-eco010-out -vv`
    compiled successfully; `3` controls and `2` safe properties passed, and both
    unsafe properties produced expected minimized one-action counterexamples
    (`5` passed, `2` expected failed; exit `1` for the negative fixture).
  - Affected `.venv/bin/ruff format` and `.venv/bin/ruff check` passed after one
    import-order correction.
  - `.venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariants.py src/mmaudit/solidity/invariant_templates.py src/mmaudit/solidity/invariant_execution.py src/mmaudit/reporting/markdown.py`
    passed for `6` source files.
  - The focused ECO-010 pytest node set passed `8` tests in `5.36s`.
  - The first generated-pipeline pytest attempt failed in `2.57s` with
    stack-too-deep diagnostics for both generated harnesses. After separating
    frames, the second attempt failed in `2.25s` solely because the evidence
    helper was incorrectly declared `view`; both exact causes were corrected.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_share_price_harness_replays_reported_asset_excess_and_observed_asset_rate`
    then passed in `5.22s`.
  - `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/unit/test_scanners_reporting.py tests/integration/test_economic_share_price_fixture.py`
    passed `137` tests in `13.83s`.
  - `.venv/bin/pytest -q` passed `462` tests with `7` documented integration
    skips in `93.03s`.
  - Secret-pattern and generated-artifact scans of the new fixture returned no
    matches; `git diff --check` passed.
- **Remaining limitation:** None specific to ECO-010; unavailable optional engine
  and hardened-isolation integrations remain separately tracked blockers.
- **Checkpoint:** None; the repository has no baseline commit and every path is
  untracked, so an isolated ticket commit cannot safely be created.

## 2026-07-27 — ECO-008

- **Ticket:** `ECO-008`
- **Status:** `COMPLETE`
- **Defensive objective:** Validate source-linked lending health and liquidation
  state transitions with explicit debt, collateral, settlement, and
  violated-invariant evidence.
- **Completed changes:**
  - Made debt/collateral invariant extraction contract-local and excluded Foundry
    test-source entities; lending execution now requires the exact source-linked
    local boundary transition instead of a planning-only lending profile.
  - Added typed lending-boundary probes and validated normalized evidence for debt,
    collateral, collateral seized, and bad debt, tied to the same one-action
    financial settlement and replay lifecycle.
  - Added a bounded healthy-position liquidation harness, contextual violated-
    invariant summary, economic/report fields, paired unsafe/safe local fixtures,
    deterministic controls, property-corpus coverage, and generated-pipeline
    execution.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/economics.py`,
  `src/mmaudit/solidity/invariant_execution.py`,
  `src/mmaudit/solidity/invariant_templates.py`,
  `src/mmaudit/solidity/invariants.py`,
  `tests/fixtures/solidity/economic_liquidation/`,
  `tests/integration/test_economic_liquidation_fixture.py`,
  `tests/integration/test_pipeline.py`, `tests/unit/test_economics.py`,
  `tests/unit/test_invariant_execution.py`, and
  `tests/unit/test_scanners_reporting.py`.
- **Commands and results:**
  - Affected `.venv/bin/ruff format`, `.venv/bin/ruff check`, and
    `.venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/invariants.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_templates.py src/mmaudit/solidity/invariant_execution.py src/mmaudit/reporting/markdown.py`
    formatted `4` source files, passed Ruff, and passed strict mypy for all `6`
    affected source files.
  - `forge test --root tests/fixtures/solidity/economic_liquidation --offline --color never --cache-path /private/tmp/mmaudit-eco008-cache --out /private/tmp/mmaudit-eco008-out -vv`
    compiled successfully. All `3` controls and `2` safe properties passed; both
    intentionally unsafe healthy-position properties produced minimized one-action
    counterexamples, so the combined command exited `1` with `5` passing and `2`
    expected failing tests.
  - The first focused seven-test command passed `6` and failed only because the
    fixture's Foundry invariant test contract was also classified as lending
    protocol source. Excluding `test/` and `tests/` entities from lending property
    extraction corrected the scope; the exact retry passed `7` in `4.56s`.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_liquidation_harness_replays_unsafe_health_boundary_and_safe_guard`
    passed in `4.84s`; both generated harnesses compiled and executed, clean replay
    was stable, exact debt/collateral and financial settlement evidence matched,
    and coverage plus JSON/Markdown serialization passed.
  - The final affected `.venv/bin/ruff format` command left all `11` Python files
    unchanged, the matching Ruff command passed, strict mypy passed `6` source
    files, and `forge fmt --root tests/fixtures/solidity/economic_liquidation --check`
    passed.
  - `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/unit/test_scanners_reporting.py tests/unit/test_properties.py tests/unit/test_solidity.py tests/integration/test_economic_liquidation_fixture.py tests/integration/test_pipeline.py`
    passed `199` tests in `38.79s`.
  - `.venv/bin/ruff format --check .`, `.venv/bin/ruff check .`,
    `.venv/bin/mypy`, and `.venv/bin/pytest -q` reported `165` files formatted,
    passed Ruff, passed strict mypy for `85` source files, and passed `453` tests
    with `7` explicitly recorded external binary/isolation skips in `81.61s`.
- **Artifact and workspace review:** Removed only the `14` disposable invariant
  replay files created by the full suite, including both unsafe liquidation
  properties. Follow-up cache and fixture cache/output/broadcast searches returned
  no files. The bounded new-fixture credential/network scan returned no matches,
  and `git diff --check` passed.
- **Unresolved limitations:** The remediation validation uses one healthy position,
  one collateral asset, one unit scale, and a fixed full-seizure transition. It
  does not claim live oracle correctness, partial-liquidation safety, interest
  accrual correctness, multi-asset solvency, or market repeatability.
- **Checkpoint:** Not created. The repository still has no commits and all paths
  remain untracked, so an isolated ECO-008 commit would absorb unrelated operator
  state.
- **Exact next safe action:** Complete dependency-ready `ECO-010` with a
  source-linked share/exchange-rate property, paired synthetic local fixtures,
  and bounded settled-value replay evidence.

## 2026-07-27 — ECO-006

- **Ticket:** `ECO-006`
- **Status:** `COMPLETE`
- **Defensive objective:** Distinguish unsafe reserve/spot-price dependence from a
  protected pricing implementation under bounded synthetic local reserve changes.
- **Completed changes:**
  - Split source-linked oracle-manipulation invariants into distinct selected
    FLASH_ORACLE and AMM_RESERVES harness candidates instead of assigning one
    harness lifecycle to both plans.
  - Added one typed AMM harness action with constant-product reserve and
    no-excess-extraction properties, zero-borrow settlement evidence, stable
    normalized outputs, fixture-configured influence, replay, coverage, and report
    serialization.
  - Added paired non-deployable local unsafe spot-dependent and safe
    protected-pricing fixtures with deterministic reserve, price, fee,
    actor-balance, and minimality controls.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/solidity/economics.py`,
  `src/mmaudit/solidity/invariant_execution.py`,
  `src/mmaudit/solidity/invariant_templates.py`,
  `tests/fixtures/solidity/economic_amm_reserves/`,
  `tests/integration/test_economic_amm_reserves_fixture.py`,
  `tests/integration/test_pipeline.py`, `tests/unit/test_economics.py`, and
  `tests/unit/test_invariant_execution.py`.
- **Commands and results:**
  - `forge test --root tests/fixtures/solidity/economic_amm_reserves --offline --color never --cache-path /private/tmp/mmaudit-eco006-cache --out /private/tmp/mmaudit-eco006-out -vv`
    compiled the paired fixture offline. All `3` controls, both safe properties,
    and both reserve-product properties passed; the intentionally unsafe
    no-excess property produced the expected one-action counterexample, so the
    combined command exited `1` with `6` passing and `1` expected failing test.
  - The first `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/integration/test_economic_amm_reserves_fixture.py`
    run passed `79` and failed one stale inventory assertion that expected a
    selected untyped plan. Requiring the selected and typed sets to match corrected
    the expectation; the exact retry passed `80` in `14.66s`.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_amm_reserve_harness_replays_unsafe_spot_and_safe_protected_pricing`
    passed in `5.27s`; both generated harnesses compiled and executed, fresh replay
    distinguished the unsafe condition from the safe implementation, and exact
    settlement, minimization, coverage, JSON, and Markdown assertions passed.
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_execution.py src/mmaudit/solidity/invariant_templates.py tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/integration/test_economic_amm_reserves_fixture.py tests/integration/test_pipeline.py`
    left all `8` files unchanged; the matching `.venv/bin/ruff check` command
    passed.
  - `.venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_execution.py src/mmaudit/solidity/invariant_templates.py`
    passed all `4` source files, and
    `forge fmt --root tests/fixtures/solidity/economic_amm_reserves --check`
    passed.
  - `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/unit/test_scanners_reporting.py tests/unit/test_properties.py tests/unit/test_solidity.py tests/integration/test_economic_amm_reserves_fixture.py tests/integration/test_pipeline.py`
    passed `191` tests in `35.62s`.
  - `.venv/bin/ruff format --check .`, `.venv/bin/ruff check .`,
    `.venv/bin/mypy`, and `.venv/bin/pytest -q` reported `164` files formatted,
    passed Ruff, passed strict mypy for `85` source files, and passed `444` tests
    with `7` explicitly recorded external binary/isolation skips in `72.83s`.
- **Artifact and workspace review:** Removed only the `12` disposable invariant
  replay files created by the full suite, including the new unsafe AMM replay.
  Follow-up `find cache -type f -print` and fixture cache/output/broadcast searches
  returned no files. The bounded new-fixture credential/network scan returned no
  matches, and `git diff --check` passed.
- **Unresolved limitations:** The remediation regression proves one fixed,
  synthetic constant-product reserve transition and single-asset base-unit
  settlement. It does not claim live-market price correctness, liquidity depth,
  repeatability, or cross-asset valuation.
- **Checkpoint:** Not created. `git status --short --branch` reports no commits and
  an entirely untracked repository, so an isolated ECO-006 commit would absorb
  unrelated operator state.
- **Exact next safe action:** Complete dependency-ready `ECO-008` using only
  source-linked lending properties, paired synthetic local fixtures, and bounded
  deterministic settlement/replay evidence.

## 2026-07-26 — ECO-005

- **Ticket:** `ECO-005`
- **Status:** `COMPLETE`
- **Defensive objective:** Validate a source-linked price-dependent invariant
  under bounded synthetic temporary liquidity while recording principal
  repayment, fees, and arithmetically settled impact.
- **Exact next safe action:** Reuse the existing FLASH_ORACLE plan and typed
  invariant DSL, then define the minimum local-only unsafe/safe fixture and exact
  observed settlement evidence without any public RPC or deployed target.
- **Completed implementation slice:**
  - Added typed zero-argument settlement probes to the stateful invariant DSL and
    required bounded temporary principal plus fixture-configured oracle influence
    for the FLASH_ORACLE template.
  - Added a deterministic price-dependent harness with one bounded action, a
    no-excess-extraction property, full settlement assertions, stable normalized
    output labels, replay-consistency validation, and economic/report metrics.
  - Added paired synthetic unsafe and safe local contracts plus invariant and
    settlement controls using actual fixture-asset starting and ending balances.
- **Validation so far:** Affected source files passed Ruff and strict mypy. Offline
  Forge compiled the paired fixture; three settlement controls and the safe
  invariant passed, while the unsafe invariant produced the expected minimized
  one-action counterexample. Affected Python/test files were then formatted and
  passed Ruff.
- **Exact next safe action:** Run the real fixture through offline Forge, fix any
  compilation or execution failure, and then add Python regression coverage.
- **Failure correction:** The first focused Python run passed `115` tests and
  failed `3`. Target-specific oracle invariants replaced one cross-target grouped
  invariant; explicit fallback getter signatures remain runtime-compiled and
  fail closed; the schema test now reaches the intended harness validator; and
  mocked execution explicitly authorizes only the fixed `1000`-unit principal
  and fixture-configured oracle influence. The three focused retries pass.
- **Generated-pipeline correction:** The first real generated run failed
  compilation because eight low-level probe calls retained too many temporary
  values. A fixed internal typed probe helper now scopes call data per probe; the
  second real run passed both unsafe and safe variants with two fresh replays,
  normalized settlement evidence, and serialized report/coverage assertions.
- **Files changed:** `docs/codex_work_queue.md`,
  `docs/codex_worklog.md`, `src/mmaudit/models/schemas.py`,
  `src/mmaudit/reporting/markdown.py`, `src/mmaudit/solidity/economics.py`,
  `src/mmaudit/solidity/invariants.py`,
  `src/mmaudit/solidity/invariant_execution.py`,
  `src/mmaudit/solidity/invariant_templates.py`,
  `tests/fixtures/solidity/economic_temporary_liquidity_oracle/`,
  `tests/integration/test_economic_temporary_liquidity_oracle_fixture.py`,
  `tests/integration/test_pipeline.py`, `tests/unit/test_economics.py`,
  `tests/unit/test_invariant_execution.py`, and
  `tests/unit/test_scanners_reporting.py`.
- **Commands and results:**
  - Affected source Ruff and strict mypy passed before fixture execution.
  - `forge test --root tests/fixtures/solidity/economic_temporary_liquidity_oracle --offline --color never --cache-path /private/tmp/mmaudit-eco005-cache --out /private/tmp/mmaudit-eco005-out -vv`
    compiled successfully; all `3` settlement controls and the safe invariant
    passed, while the intentionally unsafe invariant produced the expected
    one-action counterexample and therefore the combined command exited `1`.
  - The first focused Python run passed `115` tests and exposed `3` deterministic
    implementation/test gaps. After the target grouping, validation expectation,
    and explicit capability corrections, all `3` retries passed.
  - `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/unit/test_scanners_reporting.py tests/integration/test_economic_temporary_liquidity_oracle_fixture.py`
    passed `118` tests in `9.68s`.
  - The first real generated pipeline run failed compilation with a recorded
    stack-depth error. After scoping each low-level financial probe, the
    translation and real pipeline retry passed `2` tests in `4.63s`.
  - Affected Ruff passed, strict mypy passed for all `6` affected source modules,
    and the broader semantic/economic/invariant/report/fixture/pipeline set passed
    `181` tests in `27.56s`.
  - `.venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q` passed
    repository-wide Ruff, strict mypy across `85` source files, and `438` tests
    with `7` explicitly recorded external binary/isolation skips in `59.26s`.
  - `forge fmt --root tests/fixtures/solidity/economic_temporary_liquidity_oracle --check && git diff --check`
    passed.
- **Artifact and workspace review:** No fixture cache, output, broadcast, or
  dependency directories were added. The first credential scan command had an
  invalid shell pattern; the corrected bounded scan found no credential or
  network-execution indicators in the affected fixture/files. All repository
  paths remain untracked, so ordinary Git diff output is empty.
- **Unresolved limitations:** The regression proves one fixed, single-asset,
  nonnegative base-unit settlement under synthetic local price and liquidity
  presets. It does not claim live-market profitability, repeatability, or
  cross-asset valuation.
- **Checkpoint:** Not created. With no baseline commit and every path untracked,
  an isolated ECO-005 initial commit would absorb unrelated operator state.
- **Exact next safe action:** Complete dependency-ready `ECO-006` with paired
  synthetic reserve/spot-price fixtures and no external market or RPC access.

## 2026-07-26 — REAL-004

- **Ticket:** `REAL-004`
- **Status:** `COMPLETE`
- **Defensive objective:** Record starting assets, bounded borrowing, repayment,
  fees, slippage, ending assets, and net impact as explicit typed evidence whose
  arithmetic is validated before a financial reproduction can be credited.
- **Exact next safe action:** Inspect and reuse the existing reproduction and
  economic-metric abstractions, then add the smallest typed settlement model and
  schema arithmetic regressions without executing any live or public target.
- **Completed implementation slice:**
  - Added a reusable single-asset base-unit settlement model with explicit
    starting assets, borrowed and fully repaid principal, gross receipts, fees,
    slippage loss, ending assets, and signed net impact.
  - Required financial reproductions to supply settlement evidence and validated
    full principal repayment, uint256 bounds, the complete cashflow equation, and
    ending-minus-starting net impact.
  - Added native/ERC20 endpoint probes, fixed settlement serialization labels,
    runner verification state, integrity hashes, and JSON/Markdown reporting.
  - Added schema arithmetic, typed translation, clearly mocked runner,
    integrity-linkage, report round-trip, and real offline synthetic Foundry
    compilation/execution coverage.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/orchestration/pipeline.py`,
  `src/mmaudit/prompts/exploit_test.md`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/reproduction.py`,
  `src/mmaudit/solidity/reproduction_integrity.py`,
  `src/mmaudit/traceability.py`, `tests/fake_openrouter.py`,
  `tests/integration/test_financial_settlement_foundry.py`,
  `tests/unit/test_reproduction.py`,
  `tests/unit/test_reproduction_integrity.py`, and
  `tests/unit/test_scanners_reporting.py`.
- **Commands and results:**
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/reproduction_integrity.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py tests/unit/test_scanners_reporting.py tests/integration/test_financial_settlement_foundry.py && .venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/reproduction_integrity.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py tests/unit/test_scanners_reporting.py tests/integration/test_financial_settlement_foundry.py && .venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/reproduction_integrity.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py && .venv/bin/pytest -q tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py tests/unit/test_scanners_reporting.py tests/integration/test_financial_settlement_foundry.py`
    — formatted `2` files, passed Ruff and strict mypy, and passed `88` focused
    tests in `4.57s`; the generated synthetic settlement harness actually
    compiled and executed offline under Forge.
  - The first broader regression passed Ruff and mypy, then passed `128` tests and
    failed `3` pipeline tests because the synthetic structured-model adapter
    omitted the new optional field. After explicitly emitting
    `financial_settlement: null`, the focused retry passed all `3` cases in
    `2.27s`.
  - `.venv/bin/pytest -q tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py tests/unit/test_scanners_reporting.py tests/unit/test_traceability.py tests/unit/test_manifest.py tests/integration/test_financial_settlement_foundry.py tests/integration/test_pipeline.py tests/integration/test_traceability_artifact.py`
    — passed all `131` broader regressions in `14.75s`.
  - `.venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q` — passed
    Ruff, passed strict mypy across `85` source files, and passed `430` tests with
    `7` explicitly recorded external binary/isolation skips in `51.62s`.
- **Artifact and workspace review:**
  - `git diff --check` passed; integration-fixture generated-output and invariant
    replay-debris searches returned no paths.
  - The first credential-indicator scan used a pattern beginning with hyphens and
    was rejected by `rg` as an option; the corrected `rg ... -- <pattern>` scan
    returned no matches in the affected file set.
  - `git status --short --branch` still reports no commits and an entirely
    untracked repository; `git diff --no-ext-diff` is empty for that reason.
- **Unresolved issues:** Financial settlement is intentionally single-asset and
  base-unit denominated; cross-asset valuation remains an explicit economic-model
  concern. The typed record verifies observed endpoints and exact cashflow
  arithmetic but does not infer unavailable fee or slippage values.
- **Checkpoint:** Not created. With no baseline commit and every path untracked, an
  isolated REAL-004 initial commit would absorb unrelated operator state.
- **Exact next safe action:** Complete dependency-ready `ECO-005` using synthetic
  local liquidity and the new repayment/fee/settled-impact evidence.

## 2026-07-26 — ECO-004

- **Ticket:** `ECO-004`
- **Status:** `COMPLETE`
- **Defensive objective:** Ensure the applicable ERC4626 invariant harness is
  generated, compiled, executed, replayed/minimized, serialized, and counted as its
  own coverage dimension.
- **Recovery evidence:**
  - Reconciled the authoritative queue and worklog: `REAL-001`, `ECO-001`,
    `ECO-002`, and `ECO-003` are complete; `ECO-004` is the sole in-progress
    ticket.
  - `git status --short --branch` reports no commits and a wholly untracked
    repository, so an isolated ticket checkpoint remains unsafe.
  - Existing generation and generic execution wiring is present. The missing
    acceptance slice is typed replay/minimization evidence, a replayable/minimal
    real ERC4626 invariant fixture, and pipeline execution/report/coverage
    integration.
  - Fresh focused validation passed the runner unit suite and paired real fixture,
    but the generated pipeline campaign failed before compilation. Its scrubbed
    environment correctly concealed the host compiler cache; all three normalized
    private stderr artifacts reported no available Solidity compiler. The next
    remediation binds one explicitly selected external compiler into each
    disposable workspace instead of weakening HOME isolation.
- **Completed implementation slices:**
  - Added explicitly selected external-compiler validation, SHA-256 provenance, and
    an executable-only compiler copy inside each fresh disposable harness
    workspace; commands redact both workspace and compiler paths.
  - Preserved scrubbed environment isolation and replaced the reproduction
    process limiter with a bounded invariant-specific limiter that avoids the
    macOS user-wide process-count failure while retaining CPU, file, descriptor,
    address-space, timeout, and process-group limits.
  - Added typed post-action property guards so an execution-required property is
    evaluated only after its declared action was attempted. The unsafe transition
    now yields a replayed counterexample while the corrected transition passes.
  - Added per-template generated, compiled, executed, replayed, counterexample,
    minimization, status, source-hash, compiler-hash, and limitation evidence;
    exposed independent quality metrics and JSON/Markdown summaries.
- **Validation evidence so far:**
  - Focused Ruff plus schema, template generation, and pipeline execution passed
    `3` tests in `7.11s` before lifecycle serialization was added.
  - A subsequent focused gate passed formatting, Ruff, and mypy but exposed two
    test-expectation mismatches; after correcting them, the real pipeline test
    passed in `6.79s`.
- **Files changed:** `docs/codex_work_queue.md`, `docs/codex_worklog.md`,
  `src/mmaudit/config.py`, `src/mmaudit/models/schemas.py`,
  `src/mmaudit/orchestration/pipeline.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/coverage.py`,
  `src/mmaudit/solidity/invariant_execution.py`,
  `src/mmaudit/solidity/invariant_templates.py`,
  `src/mmaudit/solidity/invariants.py`,
  `tests/fixtures/solidity/economic_erc4626/`,
  `tests/integration/test_economic_erc4626_fixture.py`,
  `tests/integration/test_pipeline.py`,
  `tests/unit/test_invariant_execution.py`,
  `tests/unit/test_scanners_reporting.py`, and `tests/unit/test_solidity.py`.
- **Commands and results:**
  - `.venv/bin/ruff check tests/integration/test_pipeline.py && .venv/bin/pytest -q tests/unit/test_invariant_execution.py::test_invariant_schema_rejects_undeclared_setup_and_seed_actors tests/unit/test_invariant_execution.py::test_erc4626_donation_template_generates_typed_setup_sequence tests/integration/test_pipeline.py::test_erc4626_generated_harness_executes_locally_and_is_counted_separately -vv`
    — Ruff passed and all `3` tests passed in `7.11s`; the real generated
    pipeline compiled and replayed both unsafe and corrected local harnesses.
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/solidity/coverage.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py tests/unit/test_solidity.py tests/integration/test_pipeline.py && .venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/solidity/coverage.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py tests/unit/test_solidity.py tests/integration/test_pipeline.py && .venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/coverage.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py`
    — formatting, Ruff, and strict mypy passed.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_erc4626_generated_harness_executes_locally_and_is_counted_separately -vv`
    — passed in `6.79s` with exact JSON, report round-trip, quality-metric, and
    Markdown lifecycle assertions.
  - `.venv/bin/pytest -q tests/unit/test_invariant_execution.py tests/integration/test_economic_erc4626_fixture.py tests/unit/test_solidity.py tests/unit/test_scanners_reporting.py tests/unit/test_config.py tests/unit/test_properties.py tests/integration/test_pipeline.py`
    — passed `173` tests in `20.98s`.
  - `.venv/bin/ruff check . && .venv/bin/mypy` — Ruff passed and strict mypy
    passed across `85` source files. The combined pytest output was
    inconclusive because the tool returned only a partial progress stream, so no
    pass was inferred.
  - `.venv/bin/pytest -q` — passed `424` tests with `7` explicitly recorded
    external binary/isolation skips in `49.60s`.
- **Artifact and workspace review:**
  - `git diff --check` passed.
  - `find tests/fixtures/solidity/economic_erc4626 -type d \( -name out -o -name cache -o -name broadcast \) -print`
    and `find cache/invariant/failures -type f -name '*.json' -print` returned no
    generated fixture output or replay debris.
  - The targeted credential-indicator filename scan returned only the existing
    defensive module `src/mmaudit/repository/secrets.py`; no credential artifact
    was added or read.
  - `git status --short --branch` still reports no commits and an entirely
    untracked repository; `git diff --no-ext-diff` remains empty for that reason.
- **Unresolved issues:** The local execution path intentionally requires an
  operator-selected external compiler and records its SHA-256. The broader
  financial settlement model remains assigned to `REAL-004`; no public RPC,
  deployed target, wallet, key, or live transaction was used.
- **Checkpoint:** Not created. With no baseline commit and every repository path
  untracked, a ticket-only initial commit would absorb unrelated operator state.
- **Exact next safe action:** Complete dependency-ready `REAL-004`, which unlocks
  the earlier queue-priority `ECO-005`, `ECO-006`, `ECO-008`, and `ECO-010`
  financial simulation tickets.

## 2026-07-26 — REAL-003

- **Ticket:** `REAL-003`
- **Status:** `COMPLETE`
- **Completed implementation slice:**
  - Added canonical typed evidence for target identity, cited public/external
    reachability, per-attempt repository/generated-test/output hashes, clean replay,
    assertion settlement, bounded minimization evidence, six ordered integrity
    checks, and a self-hashed assessment.
  - Added bounded repository-tree hashing with the same generated/secret exclusions
    used by disposable reproduction copies. Each real runner repetition now starts
    from a fresh copy, records its normalized evidence, and repeats both positive
    and negative outcomes.
  - Integrated deterministic verification before reproduction evidence can confirm
    or falsify a candidate. Added a required reproduction-integrity quality gate,
    report status/count rendering, and updated maximum-assurance traceability.
  - Added minimal unsafe and remediated local Solidity fixtures in unit-test
    workspaces plus tampered-source/minimization and prohibited-capability negative
    regressions.
  - Updated the deterministic pipeline test adapter to emit explicitly mocked
    attempt evidence and candidate-specific target/function bindings; mocked
    execution remains clearly separate from real Foundry execution.
- **Commands and results:**
  - `.venv/bin/ruff check src/mmaudit/solidity/reproduction_integrity.py tests/unit/test_reproduction_integrity.py && .venv/bin/mypy src/mmaudit/solidity/reproduction_integrity.py src/mmaudit/solidity/reproduction.py src/mmaudit/orchestration/pipeline.py src/mmaudit/models/schemas.py src/mmaudit/reporting/markdown.py && .venv/bin/pytest tests/unit/test_reproduction_integrity.py tests/unit/test_reproduction.py -q`
    — Ruff and strict mypy passed; pytest exposed one remaining tampered-citation
    expectation after the full-file/line-range hash mismatch was corrected.
  - `.venv/bin/pytest tests/unit/test_reproduction_integrity.py tests/unit/test_reproduction.py -q`
    — passed `41` in `2.53s` after making the tamper regression modify the cited
    source range.
  - The first focused generated-reproduction pipeline run failed both parameter
    cases because the mocked runner lacked REAL-003 hashes; after adding explicit
    mocked evidence it still failed because the fake planner emitted `withdraw()`
    for `Vault.withdraw(uint256)`. The candidate-specific ABI mapping corrected
    that evidence mismatch.
  - `.venv/bin/ruff check tests/fake_openrouter.py tests/integration/test_pipeline.py && .venv/bin/pytest tests/integration/test_pipeline.py::test_generated_foundry_reproduction_caps_solidity_classification -q`
    — Ruff passed and both unsafe/remediated pipeline cases passed.
  - The first maximum-assurance integration attempt rejected symbolic actor names
    as address arguments before translation. Replacing them with the fixture's
    literal synthetic actor address preserved the typed DSL boundary.
  - `.venv/bin/ruff check tests/fake_openrouter.py tests/integration/test_pipeline.py && .venv/bin/pytest tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete -q`
    — Ruff passed and the maximum-assurance integration test passed.
  - `.venv/bin/pytest tests/integration/test_pipeline.py -q` — passed `29` in
    `3.90s`.
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/reproduction_integrity.py src/mmaudit/traceability.py tests/fake_openrouter.py tests/integration/test_pipeline.py tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py && .venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/reproduction_integrity.py src/mmaudit/traceability.py tests/fake_openrouter.py tests/integration/test_pipeline.py tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py && .venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/reproduction_integrity.py src/mmaudit/traceability.py`
    — reformatted one file; affected Ruff and strict mypy passed.
  - `.venv/bin/pytest -q tests/unit/test_reproduction_integrity.py tests/unit/test_reproduction.py tests/unit/test_config.py tests/unit/test_scanners_reporting.py tests/unit/test_traceability.py tests/integration/test_pipeline.py tests/integration/test_traceability_artifact.py`
    — passed `138` in `7.52s`.
- **Files changed so far:** `README.md`, `src/mmaudit/models/schemas.py`,
  `src/mmaudit/orchestration/pipeline.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/reproduction.py`,
  `src/mmaudit/solidity/reproduction_integrity.py`,
  `src/mmaudit/traceability.py`, `tests/fake_openrouter.py`,
  `tests/integration/test_pipeline.py`, and
  `tests/unit/test_reproduction_integrity.py`.
- **Final validation and artifact review:**
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q`
    — left `161` files unchanged, passed Ruff, passed strict mypy for `85` source
    files, and passed `422` tests with `7` explicitly recorded external
    binary/isolation skips in `40.52s`.
  - The skips remained the known rootless-runtime, Echidna, Medusa, Halmos, and
    state-growth local-fork integrations; none was represented as executed.
  - `find cache/invariant/failures -type f -name '*.json' -print 2>/dev/null` —
    returned no replay debris.
  - `shasum -a 256 tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json` —
    preserved SHA-256
    `0b73df3bb6ecbcf3abde8a03ba9aa2276a91efc1db2baf96cb4c4ec60ebd524e`.
  - `git diff --check` passed. The targeted credential-keyword filename scan found
    only expected defensive documentation/code references and no added credential
    material. `git status --short` still showed the entire repository as untracked.
- **Unresolved issues:** Full financial-asset settlement is deliberately assigned
  to `REAL-004`; configured target bytecode/source equivalence is not claimed and
  remains an explicit traceability limitation.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated REAL-003 commit would absorb unrelated operator state.
- **Exact next safe action:** Begin dependency-ready `ECO-004`; inspect the existing
  ERC4626 typed harness, real fixture, pipeline execution path, replay evidence, and
  coverage metrics before completing the missing end-to-end wiring.

## 2026-07-26 — MAN-001

- **Ticket:** `MAN-001`
- **Status:** `COMPLETE`
- **Defensive objective:** Emit a stable hash-linked evidence manifest that binds
  every security-relevant run input and output without re-executing repository code.
- **Completed implementation slice:**
  - Added a typed, canonical, self-hashed run evidence manifest with normalized
    source and artifact inventories and required deterministic binding categories
    for configuration, prompts, models, tools, compilers, isolation, seeds,
    corpora, harnesses, reproductions, and coverage.
  - Added bounded, link/hardlink/special-file rejecting artifact collection and
    post-write tamper validation without target-code execution.
  - Added executable SHA-256 provenance to scanner and compiler results and selected
    isolation-backend provenance to formal-tool results.
  - Integrated manifest emission after final report and traceability serialization,
    included it in maximum-assurance artifact accounting and latest-report copying,
    and added a strict published JSON schema and traceability row.
  - Added stable serialization, self-hash tamper, artifact tamper, link rejection,
    schema-boundary, and pipeline artifact validation coverage.
- **Commands run in this slice:**
  - `test -f src/mmaudit/orchestration/manifest.py && wc -l src/mmaudit/orchestration/manifest.py && sed -n '1,260p' src/mmaudit/orchestration/manifest.py && sed -n '261,620p' src/mmaudit/orchestration/manifest.py && tail -40 src/mmaudit/orchestration/manifest.py` —
    confirmed the interrupted patch had produced a complete `755`-line module.
  - `.venv/bin/ruff format --check src/mmaudit/orchestration/manifest.py && .venv/bin/ruff check src/mmaudit/orchestration/manifest.py && .venv/bin/mypy src/mmaudit/orchestration/manifest.py` —
    stopped at the format check because the new module required formatting.
  - `.venv/bin/ruff format src/mmaudit/orchestration/manifest.py; .venv/bin/ruff check src/mmaudit/orchestration/manifest.py; .venv/bin/mypy src/mmaudit/orchestration/manifest.py` —
    formatted the module and exposed missing scanner executable and formal
    isolation provenance fields through strict mypy.
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/scanners/base.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/formal.py src/mmaudit/orchestration/manifest.py; .venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/scanners/base.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/formal.py src/mmaudit/orchestration/manifest.py; .venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/scanners/base.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/formal.py src/mmaudit/orchestration/manifest.py` —
    reformatted one file; Ruff and strict mypy then passed all five affected source
    modules.
  - The first combined affected format/Ruff/mypy command reformatted one test file;
    Ruff identified only a pipeline import-order defect while strict mypy passed
    all seven affected source modules. The import was reordered.
  - The first broad focused pytest run passed `88` tests and failed `31` manifest
    and downstream pipeline cases from one shared cause: the two deterministic
    corpus bindings were emitted in reverse canonical order. No distinct failures
    remained once that root cause was isolated.
  - `.venv/bin/pytest -q tests/unit/test_manifest.py` — passed `4` after sorting
    the corpus bindings.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py` — passed `29` in
    `3.93s`, including typed manifest loading, artifact revalidation, and latest
    artifact copying.
  - `.venv/bin/pytest -q tests/unit/test_manifest.py tests/unit/test_traceability.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/unit/test_formal.py tests/integration/test_pipeline.py tests/integration/test_traceability_artifact.py`
    — passed `120` in `6.45s`.
  - Added direct regression assertions for host scanner/compiler executable
    SHA-256 values and formal isolation-backend serialization, and normalized
    unexecuted-tool manifest details so they do not claim image binding.
  - `.venv/bin/ruff format src/mmaudit/orchestration/manifest.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/unit/test_formal.py; .venv/bin/ruff check src/mmaudit/orchestration/manifest.py src/mmaudit/orchestration/pipeline.py src/mmaudit/traceability.py src/mmaudit/models/schemas.py src/mmaudit/scanners/base.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/formal.py tests/unit/test_manifest.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/unit/test_formal.py tests/integration/test_pipeline.py; .venv/bin/mypy src/mmaudit/orchestration/manifest.py src/mmaudit/orchestration/pipeline.py src/mmaudit/traceability.py src/mmaudit/models/schemas.py src/mmaudit/scanners/base.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/formal.py; .venv/bin/pytest -q tests/unit/test_manifest.py tests/unit/test_traceability.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/unit/test_formal.py tests/integration/test_pipeline.py tests/integration/test_traceability_artifact.py`
    — formatted two files, passed affected Ruff, passed strict mypy for seven
    source modules, and passed `120` tests in `6.57s`.
  - Published schema parsing, link/executable searches, credential-pattern search
    over MAN-001 files, `git diff --check`, and replay-file search passed with no
    unexpected output. The intentional Foundry artifact remained at SHA-256
    `0b73df3bb6ecbcf3abde8a03ba9aa2276a91efc1db2baf96cb4c4ec60ebd524e`;
    `git status --short` still showed the entire pre-existing repository as
    untracked.
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy` —
    left `159` files unchanged, passed Ruff, and passed strict mypy for `84`
    source files.
  - `.venv/bin/pytest -q` — passed `418`, skipped `7` explicitly unavailable
    external binary/isolation integrations in `38.62s`. The skips remained the
    already recorded rootless-runtime, Echidna, Medusa, Halmos, and state-growth
    local-fork integrations; none was represented as execution.
  - The full suite created no invariant replay debris. Follow-up artifact hashing,
    `git diff --check`, and status inspection passed; the intentional Foundry
    artifact retained its required SHA-256 and all repository paths remained
    untracked.
- **Files changed:** `README.md`,
  `schemas/run_evidence_manifest.schema.json`,
  `src/mmaudit/models/schemas.py`,
  `src/mmaudit/orchestration/manifest.py`,
  `src/mmaudit/orchestration/pipeline.py`, `src/mmaudit/scanners/base.py`,
  `src/mmaudit/solidity/compile.py`, `src/mmaudit/solidity/formal.py`,
  `src/mmaudit/traceability.py`, `tests/unit/test_manifest.py`,
  `tests/unit/test_scanners_reporting.py`, `tests/unit/test_solidity.py`,
  `tests/unit/test_formal.py`, and `tests/integration/test_pipeline.py`.
- **Unresolved issues:** None within MAN-001. Independent manifest verification and
  replay remain deliberately assigned to MAN-002 and MAN-003 and are not claimed
  by this ticket.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated MAN-001 commit would absorb unrelated operator state.
- **Exact next safe action:** Begin dependency-ready `REAL-003`; define and enforce
  deterministic reproduction-integrity evidence for target/source identity,
  reachability, clean replay, settlement, and minimization.

## 2026-07-26 — ISO-004

- **Ticket:** `ISO-004`
- **Status:** `COMPLETE`
- **Defensive objective:** Build a bounded synthetic adversarial-repository suite
  proving that fake binaries, links/traversal, host environment/home access,
  network/socket attempts, process/output/resource abuse, crafted names, and prompt
  injection are rejected, contained off-host, or fail closed.
- **Completed implementation slice:**
  - Added a ten-case synthetic adversarial repository manifest and minimal local
    fixtures for repository-local fake tools, Hardhat execution canaries, crafted
    names, prompt-injection text, and a bounded rootless runtime probe.
  - Added shared bounded workspace-tree validation used before scanner, compiler,
    reproduction, and formal copies. It rejects unsupported/control-format paths,
    symlinks, junctions, hardlinks, special files, excessive entries/files, and
    excessive per-file/aggregate bytes while pruning excluded trees.
  - Hardened discovery to omit unsupported crafted names with normalized messages
    rather than echoing or aborting on untrusted path text. Path normalization now
    rejects control/format/surrogate characters and overlong paths/components.
  - Rejected direct container argument traversal before mount translation.
  - Added deterministic fake-binary non-execution, link/traversal/crafted-name,
    resource/special-file, prompt-boundary, rootless-command, output/timeout, and
    Hardhat fail-closed coverage, plus an opt-in real rootless probe for private
    environment/home, network/socket denial, bounded child behavior, traversal
    denial, writable-copy containment, and cleanup.
- **Commands run in this slice:**
  - `.venv/bin/ruff format src/mmaudit/repository/workspace.py src/mmaudit/repository/ignore.py src/mmaudit/repository/discovery.py src/mmaudit/scanners/base.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/formal.py tests/unit/test_adversarial_repository.py tests/integration/test_adversarial_repository.py` —
    reformatted five files before the integration test was renamed to avoid a
    pytest module-name collision.
  - A parallel affected Ruff/mypy check passed strict mypy for seven source files
    and passed Ruff.
  - The first combined focused pytest collection found the unit/integration basename
    collision; the integration file was renamed to
    `test_adversarial_repository_isolation.py`.
  - The next focused run passed `150`, skipped the one opt-in real rootless probe,
    and exposed two existing assertions expecting legacy symlink wording/catching.
    Shared errors were normalized to retain `symlink` evidence and compilation now
    catches validation `ValueError` before execution.
  - `.venv/bin/pytest -q tests/unit/test_solidity.py::test_compilation_rejects_symlink_before_execution tests/unit/test_reproduction.py::test_repository_symlink_escape_is_rejected tests/unit/test_adversarial_repository.py tests/integration/test_adversarial_repository_isolation.py` —
    passed `9`, skipped the same real rootless probe.
  - `.venv/bin/ruff format src/mmaudit/isolation/container.py src/mmaudit/repository/workspace.py src/mmaudit/repository/ignore.py src/mmaudit/repository/discovery.py src/mmaudit/scanners/base.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/reproduction.py src/mmaudit/solidity/formal.py tests/unit/test_adversarial_repository.py tests/integration/test_adversarial_repository_isolation.py` —
    left ten files unchanged.
  - A parallel affected Ruff/mypy check found one test import-order issue, which was
    corrected; strict mypy passed eight source files.
  - `.venv/bin/pytest -q tests/unit/test_adversarial_repository.py tests/integration/test_adversarial_repository_isolation.py tests/unit/test_repository.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/unit/test_reproduction.py tests/unit/test_formal.py tests/unit/test_isolation.py` —
    passed `162`, skipped `1` because `MMAUDIT_TEST_ROOTLESS_IMAGE` is not configured,
    in `4.21s`.
  - Final affected Ruff check passed after the import-order correction.
- **Additional validation and final evidence:**
  - `.venv/bin/python -m json.tool tests/fixtures/adversarial_repository/cases.json >/dev/null`
    and the equivalent package-manifest validation passed.
  - Fixture link, executable, marker, and credential-pattern searches returned no
    files or matches. `command -v podman` and `command -v docker` returned no
    executable, so the opt-in real probe remained explicitly skipped.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py tests/unit/test_traceability.py tests/integration/test_traceability_artifact.py` —
    passed `38` in `3.61s`.
  - `.venv/bin/ruff format --check .` — passed with `157` files already formatted.
  - `.venv/bin/ruff check .` — passed.
  - `.venv/bin/mypy` — passed strict checking for `83` source files.
  - `.venv/bin/pytest -q` — passed `414`, skipped `7` explicitly unavailable
    external binary/isolation integrations in `37.99s`. The new skip is only the
    opt-in real adversarial rootless probe.
  - The full suite recreated exactly the nine known disposable invariant replay
    files; each was removed individually with the patch tool. Follow-up replay and
    marker searches returned no files.
  - `shasum -a 256 tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json` —
    preserved
    `0b73df3bb6ecbcf3abde8a03ba9aa2276a91efc1db2baf96cb4c4ec60ebd524e`.
  - `git diff --check` passed; `git status --short` continued to show the
    pre-existing wholly untracked repository state.
- **Files changed:** `README.md`, `src/mmaudit/isolation/container.py`,
  `src/mmaudit/repository/discovery.py`, `src/mmaudit/repository/ignore.py`,
  `src/mmaudit/repository/workspace.py`, `src/mmaudit/scanners/base.py`,
  `src/mmaudit/solidity/compile.py`, `src/mmaudit/solidity/formal.py`,
  `src/mmaudit/solidity/reproduction.py`, `src/mmaudit/traceability.py`,
  `tests/fixtures/adversarial_repository/`,
  `tests/unit/test_adversarial_repository.py`, and
  `tests/integration/test_adversarial_repository_isolation.py`.
- **Unresolved issues:** The real rootless runtime probe is
  `BLOCKED_TECHNICAL` on this host because neither a rootless runtime nor
  `MMAUDIT_TEST_ROOTLESS_IMAGE` is configured. Its skip is not represented as
  execution; deterministic command construction and fail-closed behavior are green.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ISO-004 commit would absorb unrelated operator state.
- **Exact next safe action:** Begin dependency-ready `MAN-001`; inventory existing
  provenance and artifacts, define one canonical hash-link contract, and add stable
  serialization/tamper coverage before pipeline integration.

## 2026-07-26 — ISO-003

- **Ticket:** `ISO-003`
- **Status:** `COMPLETE`
- **Defensive objective:** Add an explicit, offline dependency-preparation stage
  that accepts only validated lock/checksum inputs, rejects lifecycle scripts,
  scans the prepared dependency set, copies only required files, and emits SBOM
  evidence.
- **Completed implementation slice:**
  - Added an explicit, disabled-by-default dependency preparation configuration
    that requires an operator-pinned local snapshot path and SHA-256 before use.
  - Added strict checksum-bound npm lockfile v2/v3 and package-tree validation,
    lifecycle-script rejection, exact-version offline advisory matching, bounded
    file inventory, unsafe-file/link rejection, and private atomic package copying.
  - Added typed normalized preparation, scan, package, advisory, and CycloneDX
    SBOM evidence plus published bounded snapshot/SBOM schemas.
  - Integrated preparation before Solidity compilation, excluded all snapshot
    material from discovery and copied compilation workspaces, overlaid only the
    validated package set, and failed closed before Hardhat execution when required
    preparation was unavailable.
  - Emitted preparation/SBOM run artifacts, latest copies, report metadata and
    Markdown, and an implemented machine-validated traceability row.
  - Added paired synthetic safe/postinstall fixtures and deterministic tests for
    opt-in/pinning, lock mismatch, lifecycle rejection without execution, advisory
    rejection, selective copy, non-executable modes, private compile overlay,
    missing-dependency refusal, schemas, serialization, report projection, and
    discovery exclusion.
- **Commands run in this slice:**
  - `.venv/bin/ruff format --check src/mmaudit/isolation/dependencies.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py src/mmaudit/solidity/compile.py src/mmaudit/models/schemas.py src/mmaudit/config.py tests/unit/test_dependencies.py` —
    passed with seven files already formatted.
  - `.venv/bin/ruff check src/mmaudit/isolation/dependencies.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py src/mmaudit/solidity/compile.py src/mmaudit/models/schemas.py src/mmaudit/config.py tests/unit/test_dependencies.py` —
    found only two import-order/source issues; both were corrected.
  - `.venv/bin/mypy src/mmaudit/isolation/dependencies.py src/mmaudit/orchestration/pipeline.py src/mmaudit/solidity/compile.py src/mmaudit/models/schemas.py src/mmaudit/config.py` —
    passed five source files.
  - `.venv/bin/pytest -q tests/unit/test_dependencies.py tests/unit/test_solidity.py tests/integration/test_pipeline.py` —
    passed `64` in `5.10s`.
  - `.venv/bin/ruff format src/mmaudit/solidity/compile.py src/mmaudit/orchestration/pipeline.py src/mmaudit/traceability.py tests/unit/test_dependencies.py tests/integration/test_pipeline.py` —
    reformatted two files.
  - `.venv/bin/ruff check src/mmaudit/isolation/dependencies.py src/mmaudit/solidity/compile.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py src/mmaudit/traceability.py src/mmaudit/models/schemas.py src/mmaudit/config.py tests/unit/test_dependencies.py tests/integration/test_pipeline.py` —
    passed.
  - `.venv/bin/mypy src/mmaudit/isolation/dependencies.py src/mmaudit/solidity/compile.py src/mmaudit/orchestration/pipeline.py src/mmaudit/traceability.py src/mmaudit/models/schemas.py src/mmaudit/config.py` —
    first found one reused local variable type; after correction it passed six
    source files.
  - `.venv/bin/pytest -q tests/unit/test_dependencies.py tests/unit/test_solidity.py tests/unit/test_traceability.py tests/integration/test_pipeline.py` —
    passed `76` in `5.55s`.
  - `.venv/bin/python -m json.tool schemas/dependency_snapshot.schema.json >/dev/null`,
    `.venv/bin/python -m json.tool schemas/dependency_sbom.schema.json >/dev/null`,
    and the equivalent loop over all seven synthetic package/lock manifests —
    passed.
  - `rg -n "(0x[0-9a-fA-F]{64}|BEGIN [A-Z ]*PRIVATE KEY|PRIVATE_KEY|MNEMONIC|API_KEY)" tests/fixtures/dependency_preparation || true`,
    fixture link/executable/canary searches, and
    `shasum -a 256 tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json` —
    found no credential-like material, links, executable files, or canary output
    and preserved digest
    `0b73df3bb6ecbcf3abde8a03ba9aa2276a91efc1db2baf96cb4c4ec60ebd524e`.
  - `.venv/bin/ruff format --check .` — passed with `154` files already formatted.
  - `.venv/bin/ruff check .` — passed.
  - `.venv/bin/mypy` — passed strict checking for `82` source files.
  - The first yielded `.venv/bin/pytest -q` invocation returned only partial
    progress to the orchestrator, so it was not treated as evidence. A direct
    repeat of `.venv/bin/pytest -q` passed `406`, skipped `6` explicitly unavailable
    external binary/isolation integrations, in `36.31s`.
  - `find cache/invariant/failures -type f -print 2>/dev/null | sort` identified
    exactly the nine known disposable replay files, which were removed individually
    with the patch tool. Follow-up replay/canary searches returned no files.
  - `git diff --check` passed; `git status --short` confirmed every repository
    top-level path remains untracked.
- **Files changed:** `README.md`, `mmaudit.example.toml`,
  `schemas/dependency_snapshot.schema.json`,
  `schemas/dependency_sbom.schema.json`, `src/mmaudit/config.py`,
  `src/mmaudit/isolation/__init__.py`,
  `src/mmaudit/isolation/dependencies.py`,
  `src/mmaudit/models/schemas.py`,
  `src/mmaudit/orchestration/pipeline.py`,
  `src/mmaudit/reporting/markdown.py`, `src/mmaudit/solidity/compile.py`,
  `src/mmaudit/traceability.py`,
  `tests/fixtures/dependency_preparation/`,
  `tests/unit/test_dependencies.py`, and
  `tests/integration/test_pipeline.py`.
- **Unresolved issues:** The embedded advisory set is intentionally offline and
  snapshot-bound; a clean result does not claim consultation of a current external
  vulnerability database. No package manager, package code, or network operation
  was executed.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ISO-003 commit would absorb unrelated operator state.
- **Exact next safe action:** Begin dependency-ready `ISO-004`; map each required
  hostile repository behavior to existing isolation/security boundaries, then add
  the smallest bounded synthetic fixtures and fail-closed tests without executing
  repository content on the host.

## 2026-07-26 — ISO-002

- **Status:** `COMPLETE`
- **Defensive objective:** Prevent repository JavaScript, Hardhat configuration, and
  plugins from executing on the host by routing supported operations through the
  existing bounded isolation contract and failing closed when it is unavailable.
- **Completed implementation slice:**
  - Added a typed repository-JavaScript execution state to scanner and compiler
    results, with consistency validation and JSON/Markdown serialization.
  - Added bounded static Hardhat configuration/package detection without importing
    repository code. JavaScript, TypeScript, CommonJS, and ESM Hardhat configuration
    names are recognized.
  - Required the off-host rootless-container adapter for Hardhat compilation and
    Slither runs that can load Hardhat configuration. Generic host isolation now
    returns `UNAVAILABLE` before resolving or starting those tools.
  - Gave only the disposable copied workspace a writable repository-JavaScript
    mount; the original repository is never mounted. Existing rootless network,
    root-filesystem, capability, syscall, resource, credential, and cleanup controls
    remain enforced.
  - Added the minimal `hardhat_isolation` synthetic fixture with a harmless
    repository-write canary, negative host-execution regressions, mocked off-host
    remediation-path tests, command-construction checks, normalized evidence
    round trips, report rendering coverage, and an opt-in real rootless containment
    integration.
- **Files changed in this slice:** `README.md`,
  `src/mmaudit/isolation/__init__.py`,
  `src/mmaudit/isolation/container.py`,
  `src/mmaudit/isolation/repository_code.py`,
  `src/mmaudit/models/schemas.py`,
  `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/repository/discovery.py`,
  `src/mmaudit/repository/mapping.py`,
  `src/mmaudit/scanners/base.py`, `src/mmaudit/scanners/runner.py`,
  `src/mmaudit/scanners/slither.py`, `src/mmaudit/solidity/compile.py`,
  `src/mmaudit/solidity/projects.py`, `src/mmaudit/traceability.py`,
  `tests/fixtures/solidity/hardhat_isolation/`,
  `tests/unit/test_isolation.py`, `tests/unit/test_scanners_reporting.py`,
  `tests/unit/test_solidity.py`, and
  `tests/integration/test_rootless_container.py`.
- **Commands run:**
  - `.venv/bin/ruff format --check src/mmaudit/isolation/container.py src/mmaudit/isolation/repository_code.py src/mmaudit/scanners/base.py src/mmaudit/scanners/slither.py src/mmaudit/solidity/compile.py src/mmaudit/models/schemas.py` — correctly
    identified three files needing formatting.
  - `.venv/bin/ruff check src/mmaudit/isolation/container.py src/mmaudit/isolation/repository_code.py src/mmaudit/scanners/base.py src/mmaudit/scanners/slither.py src/mmaudit/solidity/compile.py src/mmaudit/models/schemas.py` — passed.
  - `.venv/bin/mypy src/mmaudit/isolation/container.py src/mmaudit/isolation/repository_code.py src/mmaudit/scanners/base.py src/mmaudit/scanners/slither.py src/mmaudit/solidity/compile.py` — passed.
  - `.venv/bin/ruff format src/mmaudit/isolation/container.py src/mmaudit/isolation/repository_code.py src/mmaudit/scanners/base.py src/mmaudit/scanners/slither.py src/mmaudit/solidity/compile.py src/mmaudit/models/schemas.py` — reformatted three files.
  - `.venv/bin/pytest -q tests/unit/test_isolation.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/integration/test_rootless_container.py` — passed `79`, skipped `2` real rootless tests because
    `MMAUDIT_TEST_ROOTLESS_IMAGE` is not configured.
  - `.venv/bin/ruff check src/mmaudit/isolation src/mmaudit/scanners/base.py src/mmaudit/scanners/slither.py src/mmaudit/solidity/compile.py src/mmaudit/solidity/projects.py src/mmaudit/repository/discovery.py src/mmaudit/repository/mapping.py src/mmaudit/models/schemas.py tests/unit/test_isolation.py tests/unit/test_solidity.py tests/unit/test_scanners_reporting.py tests/integration/test_rootless_container.py` —
    identified only an `__all__` ordering defect, which was corrected.
  - `.venv/bin/mypy` — passed strict checking for `81` source files.
  - `.venv/bin/pytest -q tests/unit/test_isolation.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/unit/test_traceability.py tests/unit/test_assurance.py tests/integration/test_rootless_container.py tests/integration/test_traceability_artifact.py` — passed `102`, skipped the same `2` explicitly
    unavailable real rootless integrations in `2.00s`.
  - `.venv/bin/ruff format --check README.md src/mmaudit/isolation src/mmaudit/models/schemas.py src/mmaudit/reporting/markdown.py src/mmaudit/repository/discovery.py src/mmaudit/repository/mapping.py src/mmaudit/scanners src/mmaudit/solidity/compile.py src/mmaudit/solidity/projects.py src/mmaudit/traceability.py tests/unit/test_isolation.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/integration/test_rootless_container.py` —
    passed with `25` files already formatted.
  - `.venv/bin/ruff check README.md src/mmaudit/isolation src/mmaudit/models/schemas.py src/mmaudit/reporting/markdown.py src/mmaudit/repository/discovery.py src/mmaudit/repository/mapping.py src/mmaudit/scanners src/mmaudit/solidity/compile.py src/mmaudit/solidity/projects.py src/mmaudit/traceability.py tests/unit/test_isolation.py tests/unit/test_scanners_reporting.py tests/unit/test_solidity.py tests/integration/test_rootless_container.py` —
    passed.
  - `.venv/bin/mypy` — passed strict checking for `81` source files.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py tests/unit/test_config.py tests/unit/test_cli.py tests/unit/test_traceability.py` —
    passed `63` in `3.91s`.
  - `command -v podman`, `command -v docker`, and `command -v hardhat` —
    returned no executable; `command -v node` returned `/opt/homebrew/bin/node`.
    Node was not used to execute repository JavaScript.
  - `find tests/fixtures/solidity/hardhat_isolation -maxdepth 3 -type f -print | sort` —
    listed exactly the synthetic contract, Hardhat configuration, and package
    manifest. `find tests/fixtures/solidity/hardhat_isolation -name 'repository-config-executed.marker' -print` returned no marker.
  - `shasum -a 256 tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json` —
    preserved the required artifact digest
    `0b73df3bb6ecbcf3abde8a03ba9aa2276a91efc1db2baf96cb4c4ec60ebd524e`.
  - `git status --short` — confirmed the repository remains wholly untracked; no
    isolated ticket checkpoint can be created without absorbing unrelated state.
- **Unresolved issues:** The real rootless containment branch is
  `BLOCKED_TECHNICAL` on this host until a verified rootless runtime and
  `MMAUDIT_TEST_ROOTLESS_IMAGE` are available. The mocked off-host adapter tests are
  explicitly mocked and are not represented as real container execution.
- **Final validation commands and results:**
  - `.venv/bin/ruff format .` — `152 files left unchanged`.
  - `.venv/bin/ruff check .` — passed.
  - `.venv/bin/mypy` — passed strict checking for `81` source files.
  - `.venv/bin/pytest -q` — passed `396`, skipped `6` explicitly recorded external
    binary/isolation integrations in `37.97s`. The additional ISO-002 skip is the
    opt-in real rootless Hardhat-containment test.
  - `find cache/invariant/failures -type f -print 2>/dev/null | sort` — identified
    exactly the nine expected disposable invariant replay files; each exact file
    was then removed with the patch tool.
  - `find cache/invariant/failures -type f -print 2>/dev/null` and
    `find . -name 'repository-config-executed.marker' -print` — returned no files
    after cleanup.
  - `rg -n "(0x[0-9a-fA-F]{64}|BEGIN [A-Z ]*PRIVATE KEY|PRIVATE_KEY|MNEMONIC|API_KEY)" tests/fixtures/solidity/hardhat_isolation || true` —
    returned no credential-like content.
  - `.venv/bin/python -m json.tool tests/fixtures/solidity/hardhat_isolation/package.json` —
    validated the synthetic package manifest.
  - `git diff --check` — passed; `git status --short` continued to show only the
    pre-existing wholly untracked repository state.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ISO-002 commit would absorb unrelated operator state.
- **Exact next safe action:** Begin dependency-ready `ISO-003` and inspect current
  dependency/lockfile, scanner, isolation, configuration, artifact, and SBOM
  abstractions before defining the preparation boundary.

## 2026-07-26 — ECO-009

- **Status:** `COMPLETE`
- **Defensive objective:** Reproduce unsafe reward accounting and confirm safe
  monotonic-index and claim-consumption transitions with source-linked invariants.
- **Completed changes:**
  - Refined reward-index extraction to link cumulative index state/getters and
    their source-local mutable transitions, and claim-once extraction to link an
    actual state-changing claim with its finite entitlement and payout state.
  - Required a source-derived reward invariant before selecting the economic plan,
    preventing a staking profile name from creating an unsupported executable plan.
  - Promoted the existing reward economic kind to a typed Foundry capability and
    added normalized index-before/after evidence to its measured outputs.
  - Added a bounded monotonic-index harness that deterministically seeds the
    cumulative index, performs an indexed transition, and compares the result to
    its captured initial value.
  - Added a bounded claim-once harness that seeds one synthetic entitlement,
    repeats only the source-linked claim transition, and caps cumulative payout at
    that entitlement.
  - Added paired unsafe/safe local contracts and deterministic Foundry sequences
    for index reset and duplicate claim behavior, plus single-transition controls.
  - Validated both generated properties through the shared property corpus and a
    deterministic JSON round trip with exact source locations.
- **Files changed:**
  - `src/mmaudit/solidity/invariants.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `tests/fixtures/solidity/economic_reward_accounting/foundry.toml`
  - `tests/fixtures/solidity/economic_reward_accounting/src/RewardAccounting.sol`
  - `tests/fixtures/solidity/economic_reward_accounting/test/RewardAccounting.t.sol`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/integration/test_economic_reward_accounting_fixture.py`
- **Commands run:**
  - Reconciled queue dependencies. `ECO-018` remains gated by `REAL-003`;
    `ECO-009` depends only on complete `DYN-001` and was the earliest actionable
    economic ticket.
  - `.venv/bin/ruff format --check src/mmaudit/solidity/invariants.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_templates.py tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/integration/test_economic_reward_accounting_fixture.py` — identified formatting changes in three edited Python files.
  - `.venv/bin/ruff format src/mmaudit/solidity/invariants.py tests/unit/test_economics.py tests/unit/test_invariant_execution.py` — reformatted three files.
  - Initial three-test focused run produced two actionable failures: fallback
    entities lacked synthesized public-getter return types, and one translated
    assertion expectation included an absent cast. Explicit fixture getters,
    signature-based bounded probes, and the exact translated assertion fixed both.
  - `.venv/bin/pytest -q tests/unit/test_economics.py::test_reward_fixture_extracts_both_source_linked_typed_properties tests/unit/test_economics.py::test_reward_plan_requires_a_source_derived_property tests/unit/test_invariant_execution.py::test_reward_templates_generate_monotonic_and_claim_once_properties` — `3 passed in 0.08s`.
  - `.venv/bin/pytest -q tests/integration/test_economic_reward_accounting_fixture.py -vv` — real local Foundry compilation/execution passed all repeated unsafe, safe, and minimality sequences in `1.77s`.
  - `.venv/bin/mypy src/mmaudit/solidity/invariants.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_templates.py` — passed.
  - `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/unit/test_properties.py tests/integration/test_economic_reward_accounting_fixture.py` — `76 passed in 7.05s`.
  - Final focused Ruff and pytest rerun after adding deterministic index seeding —
    Ruff passed and `3 passed in 1.98s`.
  - First repository-wide gate: Ruff formatting left 135 files unchanged, Ruff
    passed, and strict mypy passed 73 source files; pytest then reported
    `2 failed, 356 passed, 2 skipped in 33.11s` because the preceding cleanup had
    incorrectly removed the repository's intentional offline
    `tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json` AST fixture.
  - `forge build --root tests/fixtures/solidity/foundry --offline --force --ast` —
    regenerated the required local AST without network access. Retained only the
    pre-existing fixture path and removed the new cache, unrelated contract/test
    artifacts, and build-info output.
  - `.venv/bin/pytest -q tests/unit/test_solidity.py::test_solidity_index_and_graphs_from_foundry_artifact tests/unit/test_solidity.py::test_compiler_semantic_provenance_survives_serialization` — `2 passed in 0.18s`.
- **Test results:** Source-linked extraction, source-required planning, typed DSL
  translation, exact property serialization, normalized counterexamples, clean
  replay, safe implementations, and minimality controls all pass. The corrected
  repository-wide gate left 135 files unchanged by formatting, passed Ruff,
  passed strict mypy across 73 source files, and passed `358` tests with the two
  recorded isolation skips in `32.08s`.
- **Unresolved issues:** None in the implemented local scope. The offline AST
  artifact is required test evidence and must not be treated as disposable output.
- **Additional commands run:**
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q` — `135 files left unchanged`; Ruff passed; strict mypy passed 73 source files; pytest reported `358 passed, 2 skipped in 32.08s`.
  - Removed the exact disposable `cache/test-failures` file and nine local invariant
    replay files. Preserved the required offline AST artifact at
    `tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json`.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin `DYN-002`, the next earliest dependency-ready
  ticket; inspect existing Echidna parser/execution and isolation boundaries.

## 2026-07-26 — DYN-002

- **Status:** `COMPLETE`
- **Defensive objective:** Translate shared typed properties into bounded Echidna
  inputs, execute only a pinned trusted binary inside the repository's isolation
  contract, and normalize replayable evidence.
- **Completed changes:**
  - Added exact operator-configured Echidna semantic-version and executable
    SHA-256 pins. Both are verified inside the isolated preflight before any target
    campaign can execute; repository-local tools and pin mismatches remain rejected.
  - Added a deterministic engine module that translates the shared property corpus
    into a standalone Echidna Solidity harness, bounded YAML configuration, and
    hash-linked property map.
  - Limited translation to exact source-linked, no-argument local deployments with
    one target per property; preserved actor call identity through generated local
    actor proxies, fixed setup calls, bounded action arguments, initial-value or
    right-hand probes, and typed equality/ordering predicates.
  - Explicitly excludes unsupported constructor bindings, multiple targets,
    token-storage seeding, value calls, time movement, ordering capabilities,
    unsafe paths/constants, inconsistent campaign bounds, and oversized seeds.
  - Moved version validation ahead of Echidna campaign execution while retaining
    post-run version inventory for engines without preflight trust requirements.
  - Passed `property_corpus` through the pipeline formal stage and added typed run
    fields for binary hash, corpus hash, seed, translated count, and limitations.
  - Normalized whole-document, line-delimited, stdout, and stderr JSON; retained
    bounded call sequences, seed, exact source locations, corpus/property hashes,
    clean-state replay bounds, assumptions, and generated artifact paths.
  - Extended Markdown formal reporting with binary/corpus provenance, translated
    property count, seed, and translation limitations.
  - Added a synthetic no-argument local counter fixture; the generated Echidna
    Solidity compiled successfully with offline Forge.
  - Added clearly labeled mocked execution coverage for successful pinned
    translation/replay and pre-execution hash rejection, plus a conditional real
    hardened-isolation integration test.
- **Files changed:**
  - `src/mmaudit/config.py`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/engines/__init__.py`
  - `src/mmaudit/solidity/engines/echidna.py`
  - `src/mmaudit/solidity/formal.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `src/mmaudit/reporting/markdown.py`
  - `mmaudit.example.toml`
  - `src/mmaudit/templates/mmaudit.example.toml`
  - `README.md`
  - `tests/fixtures/solidity/echidna_property/foundry.toml`
  - `tests/fixtures/solidity/echidna_property/src/Counter.sol`
  - `tests/unit/test_echidna.py`
  - `tests/unit/test_formal.py`
  - `tests/integration/test_echidna_engine.py`
- **Commands run:**
  - `command -v echidna-test; command -v echidna` — neither executable is
    installed; no network or installation attempt was made.
  - Initial affected Ruff formatting found two Python files requiring formatting;
    `.venv/bin/ruff format src/mmaudit/solidity/engines/echidna.py src/mmaudit/solidity/formal.py` corrected them.
  - `.venv/bin/ruff check ...` and `.venv/bin/mypy ...` over the five initial
    affected source files — passed after removing one extraneous f-string.
  - Initial formal/pipeline pytest found one pre-existing timeout test racing the
    process limit after a new version subprocess. Preflight version execution was
    correctly scoped to trust-requiring adapters; the focused timeout regression
    then passed in `0.40s`.
  - `.venv/bin/pytest -q tests/unit/test_echidna.py -vv` — `3 passed`; this includes
    deterministic source/config translation, actual offline Forge compilation,
    mocked pinned execution/replay normalization, schema round-trip, and hash
    mismatch rejection before campaign execution.
  - `.venv/bin/pytest -q tests/integration/test_echidna_engine.py -vv` — skipped
    with exact reason `echidna is not installed`.
  - `.venv/bin/ruff format --check ... && .venv/bin/ruff check ... && .venv/bin/mypy ... && .venv/bin/pytest -q tests/unit/test_echidna.py tests/unit/test_formal.py tests/unit/test_properties.py tests/unit/test_scanners_reporting.py tests/integration/test_echidna_engine.py tests/integration/test_pipeline.py` — affected format/Ruff/mypy passed; `77 passed, 1 skipped in 5.24s`.
- **Test results:** All independent implementation, parser, mocked adapter,
  translation compilation, schema/report serialization, and pipeline coverage is
  green. Repository-wide formatting changed one file and left 138 unchanged;
  Ruff passed, strict mypy passed 75 source files, and pytest reported
  `361 passed, 3 skipped in 34.45s`.
- **Unresolved issues:** `BLOCKED_TECHNICAL` only for the real Echidna binary
  execution: neither `echidna` nor `echidna-test` is installed. The conditional
  real test also requires an operator-provided exact version pin and a discovered
  hardened isolation backend; no result is fabricated.
- **Additional commands run:**
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q` — one file reformatted and 138 unchanged; Ruff passed; strict mypy passed 75 source files; pytest reported `361 passed, 3 skipped in 34.45s`.
  - Removed the nine disposable invariant replay files created by the full suite;
    preserved the required offline Foundry AST fixture.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin dependency-ready `DYN-003`, reusing the shared
  property corpus and DYN-002 trust/isolation/replay abstractions.

## 2026-07-26 — DYN-003

- **Status:** `COMPLETE`
- **Defensive objective:** Provide Medusa translation/execution with the same
  trusted-binary, isolation, bounded campaign, replay, and exact-evidence contract
  as Echidna while reporting outcomes independently.
- **Completed changes:**
  - Refactored the Echidna translator into an engine-neutral, typed-property
    Solidity source translation while preserving the Echidna compatibility API.
  - Added a deterministic Medusa translator with a fixed local compilation target,
    single worker, corpus directory, campaign seed, run/depth/time bounds, and
    explicit unsupported-property limitations.
  - Added exact Medusa semantic-version and executable SHA-256 trust pins. Trust is
    checked before the generated-target campaign executes.
  - Added private-workspace Medusa source, configuration, and property-map
    artifacts; normalized bounded JSON documents and line-delimited JSON from
    stdout/stderr; remapped counterexamples to corpus properties and source
    locations; and retained replay seed, bounds, normalized sequence, corpus hash,
    property hash, and binary provenance.
  - Added deterministic per-property Echidna/Medusa outcome comparison with
    explicit `counterexample`, `no_counterexample_within_bounds`, `inconclusive`,
    and `not_executed` states. JSON and Markdown reports preserve both outcomes
    and flag disagreement rather than aggregating it away.
  - Documented Medusa trust pins and independent result semantics in both example
    configurations and the README.
- **Files changed:** `README.md`, `mmaudit.example.toml`,
  `src/mmaudit/config.py`, `src/mmaudit/templates/mmaudit.example.toml`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/orchestration/pipeline.py`,
  `src/mmaudit/reporting/markdown.py`, `src/mmaudit/solidity/formal.py`,
  `src/mmaudit/solidity/engines/echidna.py`,
  `src/mmaudit/solidity/engines/medusa.py`,
  `tests/unit/test_medusa.py`, and
  `tests/integration/test_medusa_engine.py`.
- **Commands run:**
  - `command -v medusa` — no executable found.
  - `.venv/bin/pytest -q tests/unit/test_medusa.py tests/unit/test_echidna.py tests/unit/test_formal.py tests/integration/test_medusa_engine.py -vv`
    — `13 passed, 1 skipped in 2.88s`; the exact skip was `medusa is not
    installed`.
  - `.venv/bin/ruff format src/mmaudit/solidity/engines/echidna.py README.md tests/unit/test_medusa.py`
    — one file reformatted and two unchanged.
  - `.venv/bin/ruff check src/mmaudit/solidity/engines/echidna.py src/mmaudit/solidity/engines/medusa.py src/mmaudit/solidity/formal.py src/mmaudit/models/schemas.py src/mmaudit/config.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py tests/unit/test_medusa.py tests/integration/test_medusa_engine.py`
    — passed.
  - `.venv/bin/ruff format .` — `142 files left unchanged`.
  - `.venv/bin/ruff check .` — `All checks passed!`.
  - `.venv/bin/mypy` — `Success: no issues found in 76 source files`.
  - `.venv/bin/pytest -q` — `364 passed, 4 skipped in 34.81s`. Exact skips:
    Echidna not installed; Medusa not installed; no real local-fork-capable
    isolation backend; rootless test image not configured.
- **Test results:** The generated Medusa source compiled with local offline Forge
  when available in the focused unit test; mocked isolated execution distinguished
  a normalized counterexample from an independent no-counterexample outcome,
  round-tripped typed run/comparison serialization, and proved version mismatch
  prevents campaign execution.
- **Unresolved issues:** The real Medusa integration subtask is
  `BLOCKED_TECHNICAL` because no local Medusa binary is installed. The conditional
  hardened-isolation integration test remains ready to validate a locally
  installed, operator-pinned binary without any network access.
- **Artifact review:** Removed nine disposable Foundry invariant replay files
  created by the full suite. Preserved
  `tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json`, the intentional
  offline compiler-AST fixture. No disposable fixture cache or other generated
  output remained.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin dependency-ready `SYM-001`, reusing the
  property-corpus, trust-preflight, private workspace, isolation, and normalized
  evidence abstractions.

## 2026-07-26 — SYM-001

- **Status:** `COMPLETE`
- **Defensive objective:** Add a real Halmos symbolic adapter with fixed bounded
  execution, exact version/hash provenance, explicit assumptions and unsupported
  features, and normalized counterexample capture.
- **Completed changes:**
  - Added `solidity/engines/halmos.py` with deterministic assertion-based
    translation of the shared typed property subset. Generated source is placed
    beside an indexed target source so offline Foundry compilation includes it.
  - Added deterministic generated-name collision checks and preserved
    engine-specific import paths while reusing the Echidna/Medusa translation
    machinery.
  - Added operator-configured Halmos and fixed local Z3 semantic-version and
    executable SHA-256 pins. Both executables are checked inside the hardened
    isolation boundary before target code is compiled or symbolically explored.
  - Added fixed command-line bounds for invariant depth, loop unrolling, path
    width/depth, dynamic input lengths, solver time, solver memory, and one solver
    thread. Foundry dependency resolution is forced offline.
  - Added a trusted generated Halmos configuration that disables FFI and bypasses
    any repository configuration. Repository-provided `@custom:halmos` option
    annotations are an explicit unsupported feature because they could override
    trusted execution policy.
  - Added bounded monitoring and parsing of Halmos's separate JSON result artifact.
    Counterexample models retain only bounded symbolic values and path metrics;
    query-file and host-path fields are dropped.
  - Added typed dependency provenance, formal-run assumptions, result-artifact
    paths, and host-path-redacted fixed commands to JSON/Markdown report data.
  - Added mocked trust/preflight and normalization coverage, offline generated
    source compilation, parser coverage, unsupported-annotation coverage, and a
    conditional real synthetic-fixture integration.
- **Files changed:** `README.md`, `mmaudit.example.toml`,
  `src/mmaudit/config.py`, `src/mmaudit/templates/mmaudit.example.toml`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/solidity/formal.py`,
  `src/mmaudit/solidity/engines/echidna.py`,
  `src/mmaudit/solidity/engines/medusa.py`,
  `src/mmaudit/solidity/engines/halmos.py`,
  `tests/unit/test_halmos.py`, and
  `tests/integration/test_halmos_engine.py`.
- **Commands run:**
  - `command -v halmos` — resolved
    `/Users/josevans/anaconda3/bin/halmos`.
  - `/Users/josevans/anaconda3/bin/halmos --version` — `halmos 0.3.3`.
  - `/Users/josevans/anaconda3/bin/halmos --help` — confirmed the local fixed
    JSON-output, invariant/loop/path, solver-time, memory, thread, and FFI command
    surface used by the adapter.
  - `shasum -a 256 /Users/josevans/anaconda3/bin/halmos` —
    `99ef8b6844cfe6e5288fa2f3b57587a3356c9b563a31f52dfb335d9e87623065`.
  - `z3 --version` — `Z3 version 4.15.0 - 64 bit`.
  - `shasum -a 256 /opt/homebrew/bin/z3` —
    `5d83379fd1979ed2d308658ffb4564f2af46edc4b3e3556f098b9ea89c3d3878`.
  - `.venv/bin/pytest -q tests/unit/test_halmos.py tests/unit/test_echidna.py tests/unit/test_medusa.py tests/unit/test_formal.py tests/integration/test_halmos_engine.py -vv`
    — `17 passed, 1 skipped in 4.67s`; the exact skip was no hardened
    isolation backend.
  - `.venv/bin/pytest -q tests/unit/test_halmos.py tests/unit/test_echidna.py tests/unit/test_medusa.py tests/unit/test_formal.py tests/unit/test_assurance.py tests/unit/test_scanners_reporting.py tests/integration/test_halmos_engine.py tests/integration/test_pipeline.py`
    — `92 passed, 1 skipped in 8.32s`.
  - `.venv/bin/ruff format src/mmaudit tests/unit/test_halmos.py tests/integration/test_halmos_engine.py README.md mmaudit.example.toml`
    — one file reformatted and 91 unchanged.
  - `.venv/bin/ruff check src/mmaudit tests/unit/test_halmos.py tests/integration/test_halmos_engine.py`
    — passed.
  - `.venv/bin/mypy` — `Success: no issues found in 77 source files`.
  - `.venv/bin/ruff format .` — `145 files left unchanged`.
  - `.venv/bin/ruff check .` — `All checks passed!`.
  - `.venv/bin/mypy` — `Success: no issues found in 77 source files`.
  - `.venv/bin/pytest -q` — `369 passed, 5 skipped in 36.57s`. Exact skips:
    Echidna not installed; Medusa not installed; no hardened backend for the
    Halmos target integration; no real local-fork-capable isolation backend; and
    rootless test image not configured.
- **Test results:** The generated assertion harness compiled with local offline
  Forge. Mocked isolated execution validated both executable pins before the
  campaign, retained normalized symbolic models and exact source/corpus evidence,
  round-tripped the typed report schema, redacted host paths, and prevented target
  execution on a solver hash mismatch.
- **Unresolved issues:** The real Halmos target integration subtask is
  `BLOCKED_TECHNICAL`: Halmos and Z3 are installed locally, but
  `default_isolation_backend("auto")` returned no hardened isolation backend.
  The conditional test skipped before executing target code; no real symbolic
  result is claimed.
- **Artifact review:** Removed nine disposable Foundry invariant replay files
  created by the full suite. Preserved
  `tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json`, the intentional
  offline compiler-AST fixture. No disposable fixture cache or other generated
  output remained.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin dependency-ready `MODEL-006`, reusing
  deterministic surface inventories, specialist execution records, root model
  lineage, and existing coverage/assurance abstractions.

## 2026-07-26 — MODEL-006

- **Status:** `COMPLETE`
- **Defensive objective:** Emit per-surface model-review coverage, including
  reviewer roles and root lineages, and enforce an explicit critical-surface gate.
- **Completed changes:**
  - Added a typed, stable surface inventory for contracts, public/external entry
    points, privilege functions, asset functions, call edges, state, invariants,
    invariant templates, and applicable economic templates.
  - Credited a surface only when it appeared in a context associated with a
    successful request, retained the exact request roles, and resolved returned
    model IDs through the immutable registry before crediting root lineages.
  - Added explicit overall and per-kind numerators/denominators plus an independent
    critical-surface denominator requiring two distinct registered root lineages
    for every critical surface.
  - Integrated the gate into quality and maximum-assurance contracts and emitted
    `model-review-coverage.json`, typed final-report data, metadata summaries, and
    per-surface Markdown rows.
  - Updated maximum-assurance traceability so the now-implemented surface matrix
    is no longer listed as an ensemble gap; the separate hidden benchmark, Tier A
    model inventory, and lineage-count gaps remain explicit.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/orchestration/model_coverage.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `src/mmaudit/orchestration/assurance.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/traceability.py`
  - `tests/unit/test_model_coverage.py`
  - `tests/unit/test_assurance.py`
  - `tests/integration/test_pipeline.py`
- **Commands run:**
  - Inspected the model usage ledger, context package compaction, Solidity index
    and graph schemas, invariant/economic schemas, coverage metrics, quality
    gates, maximum-assurance runtime clauses, report construction, artifact
    copying, and traceability evidence.
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/orchestration/model_coverage.py && .venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/orchestration/model_coverage.py && .venv/bin/mypy src/mmaudit/orchestration/model_coverage.py` —
    formatted two files; Ruff and mypy passed.
  - `.venv/bin/ruff format tests/unit/test_model_coverage.py && .venv/bin/ruff check tests/unit/test_model_coverage.py src/mmaudit/orchestration/model_coverage.py && .venv/bin/mypy tests/unit/test_model_coverage.py src/mmaudit/orchestration/model_coverage.py && .venv/bin/pytest -q tests/unit/test_model_coverage.py` —
    the first mypy attempt found two untyped pytest fixture parameters. Adding
    explicit callable/config annotations resolved both without suppressions.
  - Repeated the preceding focused command — Ruff passed, mypy passed two files,
    and pytest passed `2` tests.
  - `.venv/bin/ruff format src/mmaudit tests/unit/test_model_coverage.py tests/unit/test_assurance.py tests/integration/test_pipeline.py && .venv/bin/ruff check src/mmaudit tests/unit/test_model_coverage.py tests/unit/test_assurance.py tests/integration/test_pipeline.py && .venv/bin/mypy && .venv/bin/pytest -q tests/unit/test_model_coverage.py tests/unit/test_assurance.py` —
    Ruff passed, strict mypy passed `78` source files, and pytest passed `14`
    tests.
  - Initial maximum-assurance integration run correctly produced `158/198`
    overall surface coverage and a failed critical-surface gate, exposing that
    role-specific bounded contexts intentionally omit some surfaces. The test's
    incorrect expectation of fabricated full coverage was replaced with assertions
    for exact partial coverage, normalized unreviewed surfaces, and matching failed
    quality/assurance gates.
  - Repeated maximum-assurance integration test — passed in `1.54s`.
  - An initial combined subset command named a nonexistent
    `tests/unit/test_reporting.py`; file discovery identified the existing
    `tests/unit/test_scanners_reporting.py`, and no test execution was claimed for
    the invalid command.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py tests/unit/test_model_coverage.py tests/unit/test_assurance.py tests/unit/test_scanners_reporting.py tests/unit/test_traceability.py` —
    `84 passed in 3.82s`.
- **Test results:** The numerator/denominator tests cover every required surface
  kind. A negative gate regression holds aggregate coverage at 100% while one
  critical asset function has only one lineage and confirms the critical gate
  fails. The end-to-end pipeline round-trips the typed JSON artifact/final report,
  renders roles and lineages, and preserves truthful partial coverage.
- **Unresolved issues:** None in the implemented local scope. Bounded model
  contexts can truthfully leave surfaces uncovered; maximum assurance now fails
  rather than masking those omissions.
- **Final validation:**
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q` —
    Ruff format left `147` files unchanged, Ruff check passed, strict mypy passed
    `78` source files, and pytest began successfully; the combined tool capture
    ended after progress output, so no fabricated pytest completion was recorded
    from that invocation.
  - `.venv/bin/pytest -q` — `371 passed, 5 skipped in 35.42s`. The skips are the
    previously recorded missing Echidna/Medusa binaries, unavailable hardened
    local-fork/Halmos isolation, and unconfigured rootless integration image.
  - Removed only the nine exact disposable invariant replay files recreated by
    pytest. Confirmed the replay tree contains no files and preserved
    `tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json`.
  - Repository-state review confirmed every repository path remains untracked;
    the only secret-pattern hits are documented safeguards or deliberately
    synthetic redaction/isolation fixtures.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin highest-priority dependency-ready `SCOPE-001`;
  inspect existing scope configuration, discovery inventories, report schemas, and
  maximum-assurance gates before defining the fail-closed scope matrix.

## 2026-07-26 — SCOPE-001

- **Status:** `COMPLETE`
- **Defensive objective:** Add explicit contracts-only,
  contracts-and-deployment, and full-protocol scope modes with truthful
  requested-versus-achieved evidence and incomplete-status handling.
- **Completed changes:**
  - Added typed `contracts-only`, `contracts-and-deployment`, and
    `full-protocol` scope modes plus evidence states for contracts, deployment
    material, off-chain components, documentation, and tests.
  - Added deterministic scope filtering before repository mapping, semantic
    analysis, scanner context, and model context. Contract modes retain only
    Solidity contract/test files and required framework metadata; deployment mode
    additionally retains local script/deployment material.
  - Added requested-versus-achieved assessment with exact analyzed paths, known
    bounded/config omissions, fixed hierarchical denominators, and explicit
    missing required component classes.
  - Added optional/required scope configuration, CLI overrides, documented
    environment overrides, maximum-assurance enforcement of required
    full-protocol scope, and a blocking quality/assurance gate.
  - Emitted `scope-assessment.json`, copied it to `latest`, embedded the typed
    assessment in the final report/metadata, and rendered a Markdown component
    matrix.
  - Added an implemented `MA-SCOPE-CONTROL` traceability row with code, unit,
    integration, and runtime-artifact evidence.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/config.py`
  - `src/mmaudit/cli.py`
  - `src/mmaudit/orchestration/scope.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `src/mmaudit/orchestration/assurance.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/traceability.py`
  - `mmaudit.example.toml`
  - `src/mmaudit/templates/mmaudit.example.toml`
  - `README.md`
  - `tests/unit/test_scope.py`
  - `tests/unit/test_assurance.py`
  - `tests/unit/test_config.py`
  - `tests/unit/test_cli.py`
  - `tests/integration/test_pipeline.py`
- **Commands run:**
  - Inspected config/profile enforcement, CLI overrides, bounded repository
    discovery and omission semantics, repository mapping categories, Solidity
    project deployment metadata, report construction, quality gates,
    maximum-assurance clauses, and traceability requirements.
  - Initial affected Ruff/mypy run found one invalid unparenthesized boolean
    comparison in the new schema; the direct syntax fix passed Ruff. Strict mypy
    then identified loop-variable type reuse in omission normalization; distinct
    typed variables fixed all five diagnostics.
  - `.venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/config.py src/mmaudit/orchestration/scope.py && .venv/bin/mypy src/mmaudit/orchestration/scope.py src/mmaudit/config.py` —
    passed.
  - `.venv/bin/ruff format tests/unit/test_scope.py src/mmaudit/orchestration/scope.py && .venv/bin/ruff check tests/unit/test_scope.py src/mmaudit/orchestration/scope.py && .venv/bin/mypy tests/unit/test_scope.py src/mmaudit/orchestration/scope.py && .venv/bin/pytest -q tests/unit/test_scope.py` —
    Ruff and mypy passed; `5 passed in 0.14s`.
  - First combined focused run passed Ruff and strict mypy but produced one
    assurance-test expectation mismatch: absent runtime scope evidence is
    machine-classified as `FAILED` when not attempted and omitted required evidence
    is `INCONCLUSIVE` when attempted. The implementation and test were aligned to
    those existing assurance semantics; a second failure exposed a contradictory
    synthetic runtime that retained an artifact name after removing its typed
    assessment, and the fixture was corrected.
  - A subsequent 146-test run found only a Rich help-table truncation in an
    over-specific CLI string assertion; the option itself was present and accepted,
    so the test now asserts the untruncated `--scope` mode selector.
  - `.venv/bin/ruff format src/mmaudit/orchestration/scope.py src/mmaudit/orchestration/assurance.py tests/unit/test_assurance.py tests/integration/test_pipeline.py tests/unit/test_config.py && .venv/bin/ruff check src/mmaudit tests/unit/test_scope.py tests/unit/test_assurance.py tests/unit/test_cli.py tests/unit/test_config.py tests/integration/test_pipeline.py && .venv/bin/mypy && .venv/bin/pytest -q tests/unit/test_scope.py tests/unit/test_assurance.py tests/unit/test_config.py tests/unit/test_cli.py tests/unit/test_scanners_reporting.py tests/unit/test_traceability.py tests/unit/test_repository.py tests/integration/test_pipeline.py` —
    formatting left affected files stable, Ruff passed, strict mypy passed `79`
    source files, and pytest passed `146` tests in `4.57s`.
- **Test results:** The mode matrix proves exact discovery filtering and achieved
  scope for all three modes. Negative tests distinguish missing from explicitly
  omitted documentation/tests, fail a required deployment scope in a real
  scanner-only pipeline run, round-trip the artifact/report schema, and preserve a
  visible maximum-assurance downgrade rather than claiming full-protocol scope.
- **Unresolved issues:** Scope assessment cannot enumerate paths completely hidden
  by ignore rules; that limitation is explicit. Known discovery bounds, configured
  documentation/test exclusions, missing component classes, and retained-without-
  content paths all fail a required scope.
- **Final validation and review:**
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q` —
    Ruff format left `149` files unchanged, Ruff check passed, strict mypy passed
    `79` source files, and pytest passed `378` tests with `5` recorded technical
    skips in `37.72s`.
  - Removed only the nine exact disposable invariant replay files recreated by
    pytest, confirmed the replay tree has no files, and preserved the intentional
    offline AST fixture.
  - `cmp mmaudit.example.toml src/mmaudit/templates/mmaudit.example.toml` and
    `.venv/bin/mmaudit run --help` passed.
  - Repository-state review confirmed all paths remain untracked and secret-pattern
    hits are limited to documented safeguards and deliberately synthetic
    redaction/isolation fixtures.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin earliest dependency-ready `SCOPE-002`; inspect
  blind context ordering, prior-finding schemas, source validation, and reporting
  before implementing the parser and comparison.

## 2026-07-26 — SCOPE-002

- **Status:** `COMPLETE`
- **Defensive objective:** Compare prior audit findings only after blind independent
  discovery and report misses/remediation states separately.
- **Completed changes:** Selected the earliest queue-ordered dependency-ready
  ticket after SCOPE-001 passed all gates. Added bounded repository-relative
  prior-audit configuration, strict historical corpus and normalized comparison
  schemas, exact pre-context withholding, post-discovery parsing with local secret
  safeguards, source-range/hash validation, independent candidate/finding matching,
  separate discovery and remediation states, and a configurable quality gate.
  Wired exact corpus exclusion before discovery reads/context construction and
  delayed parsing until after all model requests. Emitted typed JSON, final-report,
  metadata, Markdown, latest-copy, quality-gate, and traceability evidence. Added
  model and scanner-only ordering/match regressions plus normalized error handling.
- **Files changed:** `README.md`, `mmaudit.example.toml`,
  `schemas/prior_audit.schema.json`,
  `src/mmaudit/templates/mmaudit.example.toml`, `src/mmaudit/config.py`,
  `src/mmaudit/models/schemas.py`, `src/mmaudit/orchestration/prior_audit.py`,
  `src/mmaudit/orchestration/pipeline.py`, `src/mmaudit/reporting/markdown.py`,
  `src/mmaudit/traceability.py`, `tests/unit/test_config.py`,
  `tests/unit/test_prior_audit.py`, `tests/integration/test_pipeline.py`.
- **Commands run:**
  - Reconciled dependencies and confirmed `MODEL-004` and `SCOPE-001` are
    complete.
  - Initial focused formatting identified one new file and one schema expression;
    corrected the parenthesized boolean comparison and applied Ruff formatting.
  - `.venv/bin/ruff format src/mmaudit/orchestration/prior_audit.py src/mmaudit/models/schemas.py && .venv/bin/ruff check src/mmaudit/config.py src/mmaudit/models/schemas.py src/mmaudit/orchestration/prior_audit.py && .venv/bin/mypy src/mmaudit/config.py src/mmaudit/models/schemas.py src/mmaudit/orchestration/prior_audit.py`
    — passed.
  - `.venv/bin/pytest -q tests/unit/test_prior_audit.py -vv` — initial bounded
    parser, source-state, and normalization suite passed `6` tests; the suite now
    contains an additional non-echoing schema-error regression.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_prior_audit_is_loaded_only_after_blind_model_discovery -vv`
    — passed; the spy observed all six independent model requests before the
    corpus load and confirmed the corpus path and canary were absent from requests.
  - Affected Ruff, strict mypy, configuration, traceability, prior-audit, and full
    pipeline regressions passed `59` tests in `3.56s`.
  - Final focused model/scanner ordering run passed `9` tests in `0.45s` after
    affected Ruff and strict mypy passed.
  - First affected-suite command referenced the nonexistent
    `tests/unit/test_reporting.py`; pytest collected no tests. Located the actual
    reporting suite with `rg --files tests/unit | rg 'report|markdown|sarif'` and
    did not repeat the invalid command.
  - Corrected affected gate with `tests/unit/test_scanners_reporting.py` passed
    `100` tests in `4.16s`; Ruff passed and strict mypy passed all `80` source
    files immediately beforehand.
  - `cmp -s mmaudit.example.toml src/mmaudit/templates/mmaudit.example.toml`,
    `.venv/bin/python -m json.tool schemas/prior_audit.schema.json`,
    `.venv/bin/mmaudit run --help`, and `.venv/bin/mmaudit scan --help` all
    passed.
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q`
    — `151 files left unchanged`; Ruff passed; strict mypy passed `80` source
    files; pytest reported `389 passed, 5 skipped in 37.42s`.
  - The first post-suite artifact listing used zsh's reserved lowercase `path`
    variable and consequently lost the command search path after confirming all
    nine expected replay files and the offline AST. It performed no deletion.
    Removed only those nine exact disposable replay files with the repository edit
    mechanism, then rechecked with a non-reserved variable and absolute read-only
    utilities; no cache files remain.
  - Confirmed the intentional offline AST remains at
    `tests/fixtures/solidity/foundry/out/Vault.sol/Vault.json` with SHA-256
    `0b73df3bb6ecbcf3abde8a03ba9aa2276a91efc1db2baf96cb4c4ec60ebd524e`.
  - A bounded secret-pattern scan of only affected files found documented
    safeguards and synthetic regression values, with no credential material.
    `git diff --check` passed; `git status --short` confirmed every repository path
    remains untracked.
- **Test results:** Blind model roles never receive the configured corpus path or
  content; parsing occurs after the last model request; local source hashes,
  rediscovery, misses, and remediation/regression states serialize separately;
  required missed findings fail the run; scanner-only discovery remains eligible.
  The final repository-wide gate passed `389` tests with the five recorded
  external-tool/isolation skips.
- **Unresolved issues:** None in SCOPE-002's local defensive scope.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin queue-ordered dependency-ready `ISO-002`;
  inspect all repository-JavaScript execution paths and existing isolation
  contracts before implementing fail-closed Hardhat routing.

## 2026-07-26 — ISO-002

- **Status:** `IN_PROGRESS`
- **Defensive objective:** Route Hardhat configuration, plugin, compilation, and test
  execution through hardened isolation so repository JavaScript never executes on
  the host.
- **Completed changes:** Selected the earliest queue-ordered dependency-ready ticket
  after SCOPE-002 passed all gates; its sole dependency `ISO-001` is complete.
- **Files changed:** Pending implementation inspection.
- **Commands run:** Reconciled all remaining queue statuses and dependencies;
  earlier partial/queued economic, realism, dynamic, formal, mutation, model,
  snapshot, and benchmark tickets remain dependency-blocked.
- **Test results:** Starting baseline is `389 passed, 5 skipped`.
- **Unresolved issues:** The Hardhat execution call graph, current isolation adapter
  interface, and platform-available integration boundary require inspection.
- **Exact next safe action:** Inspect compiler, project discovery, scanner/test
  runners, configuration, isolation adapters, and existing containment tests for
  every possible repository-JavaScript execution path.

## 2026-07-26 — SEM-003

- **Status:** `COMPLETE`
- **Defensive objective:** Keep accounting reads, writes, dependencies, and asset
  movements distinct with exact evidence for vulnerable and safe fixtures.
- **Completed changes:** Added explicit read-versus-write semantics for overwrite and
  read-modify-write state access; classified mint, burn, deposit, withdraw, reward,
  claim, liquidation, transfer, and observed-balance operations with separate
  source/sink/observation directions; retained repeated heuristic call sites with
  bounded occurrence provenance; projected operation counts through coverage and
  Markdown reporting; added paired unsafe-nominal and safe-observed accounting
  fixtures plus deterministic graph/retrieval/report regressions.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/solidity/coverage.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/invariants.py`
  - `tests/fixtures/solidity/semantic_accounting/foundry.toml`
  - `tests/fixtures/solidity/semantic_accounting/src/AccountingFlows.sol`
  - `tests/unit/test_scanners_reporting.py`
  - `tests/unit/test_solidity.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue order and dependencies; inspected graph
  schemas/builders, compact retrieval, coverage, reporting, and fixture behavior;
  ran affected Ruff formatting/checks; ran the Solidity/reporting unit subset and
  focused compiler/fallback access tests; compiled the fixture offline; ran full
  Ruff and mypy; ran full pytest once; traced its single downstream selection
  regression and reran focused economic/graph tests after remediation.
- **Test results:** Affected Ruff checks passed; Solidity/reporting subset `55
  passed`; compiler/fallback focus `3 passed, 20 deselected`; local Solc 0.8.20
  compilation succeeded with expected unchecked-return fixture warnings; full Ruff
  and mypy passed; first full pytest exposed one function-name-only asset-boundary
  over-selection (`291 passed, 1 failed`); invariant/economic selection now
  requires member-call evidence and the focused remediation passed `3 passed`;
  final full pytest passed `292 passed`.
- **Unresolved issues:** None for the acceptance criteria. Artifact review found
  only the two intended fixture source/configuration files and no generated
  compiler output in the repository. No checkpoint commit was safe because the
  entire repository remains untracked.
- **Exact next safe action:** Begin dependency-ready `SEM-004`; inspect role,
  privilege, governance, oracle, and dependency graph evidence and explicit
  unknown handling.

## 2026-07-26 — SEM-004

- **Status:** `COMPLETE`
- **Defensive objective:** Preserve deterministic role, privilege, governance,
  oracle, and dependency evidence while distinguishing unresolved controls.
- **Completed changes:** Added distinct governance and external-dependency graph
  kinds; classified governance lifecycle stages and delay evidence; added explicit
  resolved/unknown control, dependency-reference, and oracle-freshness metadata;
  stopped safe named controls from also receiving an unclassified-control edge;
  retained unresolved compiler modifier invocations as unknown nodes/edges; added
  control/dependency coverage summaries, report projection, specialist ranking,
  documentation, and a paired role/timelock/oracle fixture.
- **Files changed:**
  - `README.md`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/solidity/coverage.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/retrieval.py`
  - `tests/fixtures/solidity/semantic_controls/foundry.toml`
  - `tests/fixtures/solidity/semantic_controls/src/ControlDependencies.sol`
  - `tests/unit/test_scanners_reporting.py`
  - `tests/unit/test_solidity.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue/dependencies; inspected graph schemas/builders,
  retrieval, coverage, reporting, and existing control/oracle fixtures; ran focused
  Ruff and fixture-backed graph/report tests; adjusted bounded specialist ranking
  after the first oracle projection omitted the guarded near-miss.
- **Test results:** Affected Ruff checks passed. First focused run had one retrieval
  assertion failure and one pass; after ranking remediation, `2 passed, 54
  deselected`; broader subset passed `65 passed`; strict mypy passed; the fixture
  compiled locally with Solc 0.8.20 and non-blocking fixture lint/mutability
  warnings; compiler/fallback dependency focus passed `2 passed, 22 deselected`.
- **Unresolved issues:** None for the acceptance criteria. Final full pytest passed
  `293 passed`; only the two intended fixture files exist under
  `semantic_controls`, with compiler output confined to disposable paths. No
  checkpoint commit was safe because the entire repository remains untracked.
- **Exact next safe action:** Begin dependency-ready `SEM-005`; inspect compiler
  storage-layout, proxy, initializer, and compatibility evidence.

## 2026-07-26 — SEM-005

- **Status:** `COMPLETE`
- **Defensive objective:** Prefer compiler-backed proxy/storage facts while
  preserving exact provenance and explicit heuristic limitations.
- **Completed changes:** Loaded inherited compiler-layout entries by declaration,
  retained declaring-contract and AST identity, sorted numeric slots, represented
  packed fields and overlap precisely, separated implementation/admin proxy slots,
  classified initializer guard resolution for implementation contracts, compared
  versioned layouts with safe gap consumption versus incompatible inserted fields,
  and labeled fallback compatibility as unknown. Added a synthetic upgrade/layout
  fixture, deterministic compiler-artifact unit coverage, and a real local Foundry
  storage-layout integration.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/index.py`
  - `tests/fixtures/solidity/semantic_upgrade_layout/foundry.toml`
  - `tests/fixtures/solidity/semantic_upgrade_layout/src/UpgradeLayouts.sol`
  - `tests/integration/test_semantic_upgrade_layout_fixture.py`
  - `tests/unit/test_solidity.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue/dependencies; inspected graph/index artifact
  handling; ran affected Ruff checks; ran the synthetic-layout unit regression
  twice around one bounded retrieval-limit adjustment; ran the real local Foundry
  storage-layout integration twice around correcting the expected base-layout
  count.
- **Test results:** Affected Ruff checks passed. Final deterministic unit result `1
  passed, 24 deselected`; real local Foundry integration `1 passed`. Initial
  failures were limited to an overly tight compact projection and the valid base
  contract layout emitted by Solc; both expectations were corrected.
- **Unresolved issues:** None for the acceptance criteria. Broader regressions
  passed `26 passed`; full pytest passed `295 passed`; only the intended source and
  Foundry configuration exist in the fixture, with real artifacts confined to
  pytest disposable paths. No checkpoint commit was safe because the entire
  repository remains untracked.
- **Exact next safe action:** Begin dependency-ready `SEM-006`; inspect event,
  bridge-message, relayer, and off-chain dependency graph evidence.

## 2026-07-26 — SEM-006

- **Status:** `COMPLETE`
- **Defensive objective:** Make bridge/event/off-chain assumptions source-linked,
  serializable, and explicitly heuristic when compiler resolution is unavailable.
- **Completed changes:** Added event-flow, cross-chain-message, and off-chain
  dependency graph kinds; retained compiler-resolved event emission facts while
  classifying message direction, authentication, replay, finality, delivery,
  ordering, and consumer assumptions only as lower-confidence heuristics; added
  message-aware dependency metadata and bridge-specialist retrieval ranking; added
  a paired unsafe/safe bridge plus relayed-oracle fixture and real compiler
  integration proving heuristic assumptions are not promoted.
- **Files changed:**
  - `README.md`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/retrieval.py`
  - `tests/fixtures/solidity/semantic_bridge/foundry.toml`
  - `tests/fixtures/solidity/semantic_bridge/src/BridgeRelayer.sol`
  - `tests/integration/test_semantic_bridge_fixture.py`
  - `tests/unit/test_solidity.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue/dependencies; inspected event/state/signature
  and dependency builders and retrieval; ran affected Ruff checks; ran focused
  fallback/compiler event and bridge tests; compiled/indexed the fixture with real
  local Foundry artifacts in a disposable workspace.
- **Test results:** Affected Ruff checks passed; focused unit result `2 passed, 24
  deselected`; real compiler integration `1 passed`; broader regression `28
  passed`; the first strict mypy run found one local optional-string narrowing
  conflict, which was renamed and then passed across 70 source files.
- **Unresolved issues:** None for the acceptance criteria. Full pytest passed `297
  passed`; only the intended source and Foundry configuration exist in the bridge
  fixture, with real artifacts confined to pytest disposable paths. No checkpoint
  commit was safe because the entire repository remains untracked.
- **Exact next safe action:** Begin highest-priority dependency-ready `ECO-007`;
  inspect oracle guard applicability, typed harness support, fixtures, and reports.

## 2026-07-26 — ECO-007

- **Status:** `COMPLETE`
- **Defensive objective:** Validate freshness, decimal scaling, and configured
  availability/sequencer guards without confirming guarded near-misses.
- **Completed changes:** Added a distinct source-linked oracle-guard invariant and
  economic simulation kind; classified configured freshness, decimal-scale,
  answer-availability, and sequencer validation; added a bounded typed preset
  harness, normalized economic metrics, paired unsafe/safe synthetic consumers,
  boundary controls, deterministic replay, and report serialization coverage.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `src/mmaudit/solidity/reproduction.py`
  - `tests/fixtures/solidity/economic_oracle_guards/foundry.toml`
  - `tests/fixtures/solidity/economic_oracle_guards/src/OracleGuards.sol`
  - `tests/fixtures/solidity/economic_oracle_guards/test/OracleGuards.t.sol`
  - `tests/integration/test_economic_oracle_guard_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_reproduction.py`
  - `tests/unit/test_scanners_reporting.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue order and dependencies; inspected economic and
  invariant registries, typed translation/execution, graph metadata, reporting,
  and prior fixtures; formatted affected Python files; ran focused Ruff checks;
  corrected graph-edge test scoping and deterministic Foundry target selection
  after the first focused run; reran the failures and the complete focused subset;
  ran the Solidity graph suite, strict mypy, full formatting/checks, full pytest,
  diff whitespace validation, status review, fixture-artifact inspection, and a
  bounded sensitive-name scan.
- **Test results:** Focused Ruff passed. Focused pytest passed `74` tests. The real
  local Foundry regression compiled and ran twice for the unsafe implementation,
  normalized both runs as counterexamples, passed the guarded implementation, and
  passed freshness/scale/availability/sequencer boundary and valid-state controls.
  The initial focused run reported `2 failed, 72 passed`; the two local fixture/test
  determinism issues were fixed, and the focused rerun passed `74`. Solidity graph
  regressions passed `26`; strict mypy passed `70` source files; full Ruff format
  left `122` files unchanged; full Ruff check passed; full pytest passed `302`.
- **Unresolved issues:** The typed DSL output was deterministically translated and
  structurally asserted but was not separately deployed; the equivalent paired
  fixture compiled and executed locally. No live integration was attempted or
  required. The generated invariant replay file from diagnostic execution was
  removed. No fixture `cache` or `out` directory remains.
- **Checkpoint:** Not created. Every repository path is still untracked, so a
  ticket-only commit would create an unusable partial repository history.
- **Exact next safe action:** Begin highest-priority dependency-ready `ECO-011`;
  inspect governance/timelock lifecycle applicability, templates, fixtures, and
  reports.

## 2026-07-26 — ECO-011

- **Status:** `COMPLETE`
- **Defensive objective:** Validate proposal, voting, queue, delay, execution, and
  cancellation transitions without accepting invalid lifecycle shortcuts.
- **Completed changes:** Selected after `ECO-007`; dependencies `REAL-001` and
  `SEM-004` are complete. Added a distinct rights-guarded governance-delay
  invariant; made lifecycle applicability require proposal/vote/queue/execute/cancel
  source facts and a missing guarded delay; added typed capability-policy reuse,
  operator gates for governance rights and bounded time, deterministic time
  translation, paired lifecycle fixtures, boundary/minimality controls, metrics,
  and report serialization.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `src/mmaudit/solidity/reproduction.py`
  - `tests/fixtures/solidity/economic_governance/foundry.toml`
  - `tests/fixtures/solidity/economic_governance/src/GovernanceLifecycle.sol`
  - `tests/fixtures/solidity/economic_governance/test/GovernanceLifecycle.t.sol`
  - `tests/integration/test_economic_governance_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue order and dependency readiness; inspected
  governance graph stages, delay metadata, capability policy/operator limits,
  typed translation and execution, reports, and existing fixtures; formatted and
  linted affected Python files; ran the focused suite, corrected one Markdown
  escaping expectation, reran that regression plus integration, then reran the
  complete focused subset.
- **Test results:** Focused Ruff passed. Initial focused pytest reported `1 failed,
  142 passed`; the assertion-only escaping mismatch was corrected. The focused
  rerun passed `143`, including real local compilation and two unsafe replays,
  guarded lifecycle execution, declared-right rejection, invalid ordering,
  early/exact delay boundaries, cancellation, and valid unsafe minimality. The
  first mypy run found one optional-name narrowing error; after remediation strict
  mypy passed `70` source files. Full Ruff format left `123` files unchanged, full
  Ruff check passed, and full pytest passed `309`.
- **Unresolved issues:** Typed governance source was translated and structurally
  asserted but not separately deployed; the equivalent paired fixture compiled
  and executed locally. No live integration was attempted or required. The
  diagnostic Foundry replay file was removed; fixture `cache`/`out` directories
  and sensitive material are absent.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin highest-priority dependency-ready `ECO-012`;
  inspect legitimate proxy upgrade and initializer execution abstractions,
  fixtures, and reporting.

## 2026-07-26 — ECO-012

- **Status:** `COMPLETE`
- **Defensive objective:** Validate only authorized proxy upgrade paths and
  one-time initialization, rejecting direct storage/code mutation.
- **Completed changes:** Selected after `ECO-011`; dependencies `REAL-002` and
  `SEM-005` are complete. Added a combined source-linked unsafe upgrade and
  initializer invariant; restricted applicability to a proxy with both unresolved
  upgrade authorization and one-time initialization guards; added a typed harness
  containing only proxy ABI calls, paired delegatecall-capable proxy fixtures,
  authorization/one-time/valid-upgrade controls, normalized metrics, and report
  serialization.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `tests/fixtures/solidity/economic_upgrade_initializer/foundry.toml`
  - `tests/fixtures/solidity/economic_upgrade_initializer/src/UpgradeInitializer.sol`
  - `tests/fixtures/solidity/economic_upgrade_initializer/test/UpgradeInitializer.t.sol`
  - `tests/integration/test_economic_upgrade_initializer_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue order and dependency readiness; inspected
  proxy/initializer graph metadata, storage-layout evidence, economic planning,
  typed translation/execution, and prior fixtures; formatted and linted affected
  Python files; ran focused tests; corrected proxy authorization resolution to
  distinguish unresolved sensitive surfaces and constrained combined invariants
  to the exact typed preset signatures; reran the failures and focused subset.
- **Test results:** Focused Ruff passed. Initial focused pytest reported `1 failed,
  110 passed`; the graph resolution issue was corrected. A targeted rerun exposed
  test-harness name noise, which exact signature binding removed. The focused
  rerun passed `111`, including real local compilation, two unsafe counterexamples,
  safe rejections, authorized delegatecall upgrade, and valid-path minimality.
  Strict mypy passed `70` source files; full Ruff format left `124` files
  unchanged; full Ruff check passed; full pytest passed `315`.
- **Unresolved issues:** Typed proxy source was translated and structurally
  asserted but not separately deployed; the equivalent paired proxy fixture
  compiled and executed locally. No live integration or direct storage/code
  mutation was attempted. The diagnostic Foundry replay file was removed; fixture
  `cache`/`out` directories and sensitive material are absent.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin highest-priority dependency-ready `ECO-014`;
  inspect cross-chain message/replay applicability, declared capabilities,
  fixtures, and reporting.

## 2026-07-26 — ECO-014

- **Status:** `COMPLETE`
- **Defensive objective:** Validate message uniqueness and ordering with only
  declared synthetic local messages and no external relayer or chain interaction.
- **Completed changes:** Selected after `ECO-012`; dependencies `SEM-006` and
  `REAL-001` are complete. Added explicit guarded message-ordering evidence while
  retaining heuristic provenance; added a source-linked duplicate/order invariant,
  a typed offline-message plan and harness, declared cross-chain message capability
  validation/operator gating, paired inbox fixtures, sequence/minimality controls,
  metrics, and report serialization.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `tests/fixtures/solidity/economic_cross_chain/foundry.toml`
  - `tests/fixtures/solidity/economic_cross_chain/src/MessageInbox.sol`
  - `tests/fixtures/solidity/economic_cross_chain/test/MessageInbox.t.sol`
  - `tests/integration/test_economic_cross_chain_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue order and dependency readiness; inspected
  cross-chain direction/authentication/replay/finality facts, capability policy
  limits, typed translation/execution, semantic bridge coverage, and reporting;
  formatted and linted affected Python files; ran the focused unit/reporting/local
  Foundry subset; inspected the fallback source index when typed invariant
  selection initially failed; bound the fixture declaration to the exact indexed
  signature; reran the failed unit plus integration test and then the complete
  focused subset.
- **Test results:** Focused Ruff checks passed. The first focused pytest run
  reported `1 failed, 153 passed`; the real local unsafe/safe regressions already
  passed, while the fallback index did not retain the multiline preset signature.
  After making that synthetic declaration exactly indexable, the targeted rerun
  passed `2`, and the complete focused rerun passed `154`. The unsafe fixture
  produced stable normalized counterexamples twice, the safe fixture passed,
  message-order controls passed, and source hashes remained unchanged. Strict
  mypy passed all `70` source files. Full Ruff format left `125` files unchanged,
  full Ruff check passed, and full pytest passed `322`. Diff checks passed; the
  fixture contains only its configuration, source, and test files. The generated
  unsafe-message replay file was removed after inspection.
- **Unresolved issues:** Typed harness source was structurally asserted rather
  than separately deployed; the equivalent paired fixture compiled and executed
  locally. No external relayer, RPC, remote chain, signature, or transport was
  used.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin dependency-ready `ECO-015`; inspect callback
  reachability, affected-state evidence, typed harnesses, fixtures, and reporting.

## 2026-07-26 — ECO-015

- **Status:** `COMPLETE`
- **Defensive objective:** Validate state consistency across source-linked,
  attacker-reachable synthetic callbacks with a paired local remediation fixture.
- **Completed changes:** Selected after `ECO-014`; dependencies `SEM-002` and
  `SEM-003` are complete. Extended compiler and bounded-source reentrancy edges
  with public callback reachability, explicit receiver hook, entry point, and
  affected-state evidence. Added a source-linked callback state-consistency
  invariant, applicability-gated economic plan, fixed-shape one-action harness,
  controlled-receiver policy validation, contextual normalized counterexample,
  economic metrics, report projection, paired effects-after/effects-first
  fixtures, and one-action minimality coverage.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `tests/fixtures/solidity/economic_callback/foundry.toml`
  - `tests/fixtures/solidity/economic_callback/src/CallbackAccounting.sol`
  - `tests/fixtures/solidity/economic_callback/test/CallbackAccounting.t.sol`
  - `tests/integration/test_economic_callback_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue priority and dependency readiness after the
  `ECO-014` full validation gates; inspected compiler/fallback reentrancy ordering,
  invariant selection, typed translation/execution, capability bounds, existing
  fixture patterns, normalized evidence, and report serialization; implemented
  the minimal source-linked receiver callback slice; formatted and linted affected
  Python files; ran the focused graph/harness/policy/reporting/local Foundry
  subset.
- **Test results:** Affected Ruff checks passed. Focused pytest passed `160`,
  including compiler/fallback graph regressions, typed harness and controlled
  receiver validation, contextual normalized evidence, report serialization, two
  stable unsafe counterexamples, the safe effects-first invariant, and explicit
  one-action minimality controls. The paired fixture compiled and executed
  locally with Forge offline. The first strict mypy run identified one optional
  fallback entity dereference; explicit narrowing fixed it, affected Ruff passed,
  and strict mypy then passed all `70` source files. Full Ruff format left `126`
  files unchanged, full Ruff check passed, and full pytest passed `329`. Diff and
  fixture artifact checks passed; all diagnostic Foundry replay files produced by
  the full suite were removed.
- **Unresolved issues:** Typed generated source was structurally asserted rather
  than separately deployed; the equivalent paired callback fixture compiled and
  executed locally. No live target, network, funds, or external callback was used.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Resume dependency-priority `ISO-001`, which is the
  unmet dependency for next economic ticket `ECO-016`; inspect existing partial
  isolation behavior against every acceptance criterion.

## 2026-07-26 — ISO-001

- **Status:** `COMPLETE`
- **Defensive objective:** Complete a rootless digest-pinned container backend
  with read-only source/toolchain inputs, private writable state, denied
  network/socket/credentials, bounded resources/syscalls, and verified cleanup.
- **Completed changes:** Resumed the pre-existing partial ticket because it is the
  unmet dependency of the next sequential economic ticket, `ECO-016`. Added a
  dedicated rootless container backend that accepts only lowercase digest-pinned
  images and locally verified rootless Docker/Podman runtimes. Its fixed invocation
  uses no pull, no network/IPC sharing, a read-only root filesystem and source
  mount, a single private output mount, private tmp/home filesystems, non-root UID,
  dropped capabilities, no-new-privileges, a deny-by-default syscall profile that
  omits socket/mount/ptrace operations, CPU/memory/swap/PID/file limits, sanitized
  runtime routing, a CID file, automatic removal, and force-remove/absence
  verification. Added validated configuration/env routing, doctor resolution,
  digest-required Docker base input, documentation, traceability, unit coverage,
  and an opt-in real local integration.
- **Files changed:**
  - `Dockerfile`
  - `README.md`
  - `mmaudit.example.toml`
  - `src/mmaudit/templates/mmaudit.example.toml`
  - `src/mmaudit/isolation/__init__.py`
  - `src/mmaudit/isolation/container.py`
  - `src/mmaudit/config.py`
  - `src/mmaudit/cli.py`
  - `src/mmaudit/solidity/reproduction.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/traceability.py`
  - `tests/unit/test_isolation.py`
  - `tests/integration/test_rootless_container.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled all queue statuses and dependencies after
  completing `ECO-015`; inspected sandbox-exec/Bubblewrap wrapping, every backend
  call site, isolation configuration/doctor behavior, Docker assets, traceability,
  and current tests; formatted and linted affected Python; ran an initial focused
  isolation/config/runner/CLI subset; checked local `podman` and `docker`
  resolution without network or image pulls; added static digest/runtime
  discovery tests and reran the broadened focused subset.
- **Test results:** Affected Ruff checks passed. Initial focused validation passed
  `110` with one opt-in real-backend test skipped. The broadened focused suite
  passed `133` with the same one skip, covering digest rejection, rootless
  verification, read-only/private mounts, sanitized environment, syscall and
  resource bounds, cleanup verification, configuration, runners, CLI,
  traceability, and assurance behavior.
- **Unresolved issues:** `BLOCKED_TECHNICAL` applies only to the real rootless
  runtime integration: `command -v podman` and `command -v docker` both failed,
  and no `MMAUDIT_TEST_ROOTLESS_IMAGE` digest was configured. No runtime was
  installed and no image was pulled. Strict mypy passed all `72` source files.
  Full Ruff format left `130` files unchanged and full Ruff check passed. The first
  full pytest run reported `1 failed, 335 passed, 1 skipped`: an existing unsafe
  rounding invariant intermittently targeted its deployed account rather than its
  fixed handler. Constraining that fixture to `address(this)` restored the intended
  deterministic one-action replay; the targeted rounding/isolation rerun passed
  `8` with the same one technical skip. Final full pytest passed `336` with that
  one opt-in real-container skip. Diff/Docker asset checks passed, no tag-pinned
  base remains in the Dockerfile, fixture cache/output directories are absent,
  and all diagnostic Foundry replay files were removed.
- **Unresolved issues:** The real local rootless backend integration is
  `BLOCKED_TECHNICAL`: neither `podman` nor `docker` resolves locally and no
  digest-pinned `MMAUDIT_TEST_ROOTLESS_IMAGE` is configured. The backend was not
  executed and no image was built or pulled; mocked command and cleanup tests are
  explicitly recorded as mocked. All independent implementation portions are
  complete.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin now-unblocked `ECO-016`; inspect bounded
  state-growth applicability, resource ceilings, isolated timeout behavior, and
  threshold report evidence.

## 2026-07-26 — ECO-016

- **Status:** `COMPLETE`
- **Defensive objective:** Detect unsafe state growth or iteration while keeping
  every synthetic action, sequence, timeout, and reported threshold resource
  capped.
- **Completed changes:** Selected after completing dependency `ISO-001`. Added a
  bounded source state-growth graph for public collection appends with explicit
  resolved/unknown length guards and numeric threshold evidence; added an exact
  source-linked state-growth invariant, applicability-gated economic template,
  fixed four-call setup plus one-action typed harness, schema-enforced run/depth/
  setup ceilings, contextual counterexample, generic resource-threshold metrics,
  report serialization, and paired no-loop unsafe/safe fixtures with explicit
  fifth-action minimality. Added both a real local Forge regression and bounded
  timeout coverage, including an opt-in real OS-isolation timeout path.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `tests/fixtures/solidity/economic_state_growth/foundry.toml`
  - `tests/fixtures/solidity/economic_state_growth/src/StateGrowth.sol`
  - `tests/fixtures/solidity/economic_state_growth/test/StateGrowth.t.sol`
  - `tests/integration/test_economic_state_growth_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:** Reconciled queue order and dependencies after the `ISO-001`
  full validation gates; inspected graph/index construction, economic
  applicability, typed invariant translation/execution, subprocess timeouts,
  resource metrics, report rendering, and paired fixture conventions; implemented
  the bounded threshold property without any unbounded loop or recursive workload;
  formatted/linted affected code; ran the focused graph/harness/timeout/reporting/
  Forge subset; diagnosed two initial failures; accepted compiler or exact fallback
  uint getter evidence; corrected the macOS sandbox loopback host syntax; then
  added a benign sandbox policy probe so an installed but unusable backend fails
  closed rather than claiming availability.
- **Test results:** Affected Ruff checks passed. The first focused run reported `2
  failed, 166 passed`: fallback getters omitted return-type metadata, and the real
  sandbox timeout path failed before execution. Exact source return declarations
  restored invariant selection. The first sandbox remediation corrected an invalid
  numeric-host policy; a second materially different run reached
  `sandbox_apply: Operation not permitted`, establishing the platform restriction.
  The targeted rerun passed `2` with one explicit skip, and the complete focused
  rerun passed `167` with that same skip. Real local Forge compiled and executed
  two stable unsafe counterexamples, the safe threshold guard, and three
  minimality controls. The mocked isolation adapter's real subprocess timeout
  test returns `TIMED_OUT` within its bound.
- **Unresolved issues:** `BLOCKED_TECHNICAL` applies only to the real OS-isolated
  timeout subtest: the available `sandbox-exec` binary cannot apply a nested
  policy in this platform sandbox, and no rootless container runtime/image is
  available. The backend probe now reports it unavailable. Strict mypy passed all
  `72` source files. Full Ruff format left `131` files unchanged, full Ruff check
  passed, and final full pytest passed `344` with the two explicitly documented
  real-isolation skips. Diff and fixture checks passed, the fixture contains no
  loop, network, cache, or output artifacts, and all diagnostic Foundry replay
  files were removed.
- **Unresolved issues:** The real OS-isolated timeout subtest remains
  `BLOCKED_TECHNICAL` because nested sandbox policy application is prohibited and
  no rootless container runtime/image is available. Unit timeout behavior uses a
  mocked isolation adapter and is labeled accordingly; every independent
  detector, harness, fixture, threshold, serialization, and bounded subprocess
  portion is complete.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Resume `COV-001`, the unmet dependency of `DYN-001`
  and therefore of next economic ticket `ECO-017`; inspect all independent
  denominator and exclusion semantics.

## 2026-07-26 — COV-001

- **Status:** `COMPLETE`
- **Defensive objective:** Standardize every required coverage dimension with
  explicit numerator, denominator, exclusions, not-applicable evidence,
  confidence, provenance, and failures.
- **Completed changes:**
  - Added a typed coverage provenance vocabulary and per-member exclusion evidence.
  - Made each coverage metric declare its complete population and validate
    `population == denominator + exclusions`, without silently clamping an
    oversized numerator.
  - Required explicit not-applicable or failure evidence for every empty
    denominator and failure evidence for every incomplete non-empty denominator.
  - Carried confidence, provenance, exclusions, applicability evidence, and
    failures through deterministic, model-context, runtime, economic, scanner,
    compiler, and formal-engine dimensions.
  - Kept skipped scanners, dependency-free projects, non-required economic
    templates, and skipped formal engines visible as typed exclusions.
  - Changed compiler/index coverage to use the union of compiler and symbol-index
    contract names so an unavailable compiler cannot collapse a populated
    denominator to zero.
  - Reused standardized metrics for Solidity-index and candidate-reproduction
    quality gates; an empty denominator passes only with explicit applicability
    evidence, and a nominally complete ratio with upstream population failures
    fails its integrity gate.
  - Expanded Markdown and normalized report serialization with all required
    independent evidence fields.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/coverage.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `src/mmaudit/reporting/markdown.py`
  - `tests/unit/test_solidity.py`
  - `tests/integration/test_pipeline.py`
- **Commands run:**
  - `git status --short`
  - `rg -n "Coverage|coverage|denominator|exclusion|not_applicable|confidence|provenance|failures" src/mmaudit tests/unit tests/integration schemas -g '*.py' -g '*.json' -g '*.md'`
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/solidity/coverage.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py tests/unit/test_solidity.py tests/integration/test_pipeline.py`
  - `.venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/solidity/coverage.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py tests/unit/test_solidity.py tests/integration/test_pipeline.py`
  - `.venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/coverage.py src/mmaudit/orchestration/pipeline.py src/mmaudit/reporting/markdown.py`
  - `.venv/bin/pytest -q tests/unit/test_solidity.py`
  - `.venv/bin/pytest -q tests/unit/test_scanners_reporting.py tests/unit/test_assurance.py tests/unit/test_benchmark.py`
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py`
  - `.venv/bin/pytest -q tests/unit/test_solidity.py::test_coverage_reports_denominators tests/unit/test_solidity.py::test_coverage_metric_rejects_denominator_shrinking tests/unit/test_solidity.py::test_independent_coverage_gate_prevents_aggregate_masking`
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete`
- **Test results:**
  - Coverage schema, denominator-shrinking, aggregate-masking, and empty-denominator
    focused regressions passed (`3 passed`).
  - Solidity unit suite passed (`28 passed`).
  - Reporting, assurance, and benchmark consumers passed (`54 passed`).
  - Pipeline integration suite passed before the final denominator-integrity
    tightening (`24 passed`); the affected maximum-assurance integration passed
    afterward (`1 passed`).
  - Combined affected regression set passed (`106 passed in 4.82s`) after all
    denominator-integrity changes.
  - Affected Ruff passed and mypy reported no issues in 4 source files.
- **Final validation:**
  - `.venv/bin/ruff format .` — passed; 131 files unchanged.
  - `.venv/bin/ruff check .` — passed.
  - `.venv/bin/mypy` — passed; no issues in 72 source files.
  - `.venv/bin/pytest -q` — passed; `346 passed, 2 skipped in 29.13s`.
  - The skips remain limited to the previously recorded real nested-isolation and
    rootless-container integrations unavailable on this host.
  - Removed the Foundry failure cache and nine generated invariant replay artifacts
    created by the full suite; `find cache -type f -print` returned no files.
  - The affected-file credential-marker scan found only pre-existing explicit
    synthetic test values and configuration variable references; no credential
    material was added or read.
- **Unresolved issues:** None within `COV-001`.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin dependency-ready `DYN-001` by inspecting the
  existing invariant schemas, typed harness translation, formal adapters, and
  serialization consumers.

## 2026-07-26 — DYN-001

- **Status:** `COMPLETE`
- **Defensive objective:** Define one typed property corpus shared by dynamic
  engines while retaining exact source evidence, assumptions, covered functions
  and state, seeds, and bounded campaign parameters.
- **Completed changes:**
  - Added engine-neutral typed property, exact source-evidence, fuzz-input bound,
    campaign-bound, and corpus schemas.
  - Reused the existing actor, setup-call, token-seed, stateful-action, predicate,
    capability-policy, invariant-category, and invariant-template DSL types.
  - Added deterministic corpus construction from validated executable invariants,
    the Solidity symbol index, and typed harnesses.
  - Retained exact entity path/range/hash, transformation provenance, bounded
    confidence, invariant assumptions, harness assumptions, covered entity IDs,
    function names/signatures, state variables, seed, runs, depth, input bounds,
    value bounds, setup balances, time shifts, and transaction-ordering policy.
  - Rejected model-only or non-executable hypotheses, unresolved/mismatched source
    evidence, and conflicting reuse of a fuzz slot without creating an executable
    property.
  - Hash-linked every property to all typed contents and the ordered corpus to its
    property hashes and explicit limitations.
  - Added stable `property-corpus.json` pipeline output, latest-report copying, and
    normalized report metadata summary.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/properties.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `tests/unit/test_properties.py`
  - `tests/integration/test_pipeline.py`
- **Commands run:**
  - `sed -n '1178,1545p' src/mmaudit/models/schemas.py`
  - `sed -n '210,370p' src/mmaudit/solidity/formal.py`
  - `rg -n -i "echidna|medusa|property corpus|property_id|property translation|seed|bounds" src tests docs -g '*.py' -g '*.md'`
  - `.venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/solidity/properties.py src/mmaudit/orchestration/pipeline.py tests/unit/test_properties.py tests/integration/test_pipeline.py`
  - `.venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/properties.py src/mmaudit/orchestration/pipeline.py`
  - `.venv/bin/pytest -q tests/unit/test_properties.py`
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete`
- **Test results:**
  - Property schema, provenance, bounds, missing-evidence, conflicting-slot, stable
    serialization, and tamper regressions passed (`4 passed`).
  - Affected Ruff passed and mypy reported no issues in 3 source files.
  - The first pipeline assertion incorrectly required a populated corpus from a
    fixture with no generated harness; the artifact itself was valid and empty.
    The assertion was corrected to validate honest emptiness and exact summary
    counts, and the integration then passed (`1 passed`).
  - Combined property, invariant-execution, formal-adapter, and pipeline suite
    passed (`80 passed in 10.76s`).
  - Latest-report copying regression passed after adding the corpus artifact
    (`1 passed in 0.24s`).
- **Final validation:**
  - `.venv/bin/ruff format .` — passed; 3 files reformatted and 130 unchanged.
  - `.venv/bin/ruff check .` — passed.
  - `.venv/bin/mypy` — passed; no issues in 73 source files.
  - `.venv/bin/pytest -q` — passed; `351 passed, 2 skipped in 28.06s`.
  - The skips remain limited to the previously documented unavailable nested
    OS-isolation and rootless-container integrations.
  - Removed the Foundry failure cache and nine generated invariant replay
    artifacts; the new property module and tests contained no credential or
    network markers.
- **Unresolved issues:** None within `DYN-001`; real engine translation and
  execution remain separately scoped to `DYN-002` through `DYN-004`.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Begin newly dependency-ready `ECO-017` using the
  shared property corpus and existing typed local Foundry infrastructure.

## 2026-07-26 — ECO-017

- **Status:** `COMPLETE`
- **Defensive objective:** Detect accounting state transitions that accept missing,
  false, or unusual ERC20 return behavior while rejecting safe wrapper handling.
- **Completed changes:**
  - Added a source-local `ERC20_RETURN_HANDLING` invariant for deposit-like
    transitions that ignore token return bytes or unchecked direct boolean results.
  - Kept safe wrapper calls as negative matches by requiring explicit byte capture,
    return-data length validation, and boolean decoding for low-level calls.
  - Reused the existing non-standard-token economic kind and observed-balance
    invariant DSL rather than adding another planning-only classification.
  - Extended the bounded economic template with explicit return modes and normalized
    call-success, return-shape, observed-balance, claim, and shortfall outputs.
  - Added a minimal synthetic token with true, missing, false, and short return
    modes plus paired unsafe and safe accounting implementations.
  - Added deterministic Foundry regressions: false and short unchecked outcomes
    replay as counterexamples; safe false/short rejection and safe compatible-empty
    handling pass; true/empty controls show the unsafe fixture does not diverge
    when assets actually move.
  - Validated the generated typed property through deterministic property-corpus
    JSON serialization with exact source evidence.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/invariants.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `tests/fixtures/solidity/economic_erc20_returns/foundry.toml`
  - `tests/fixtures/solidity/economic_erc20_returns/src/ERC20Returns.sol`
  - `tests/fixtures/solidity/economic_erc20_returns/test/ERC20Returns.t.sol`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/integration/test_economic_erc20_returns_fixture.py`
- **Commands run:**
  - `.venv/bin/ruff format --check src/mmaudit/models/schemas.py src/mmaudit/solidity/invariants.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_templates.py tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/integration/test_economic_erc20_returns_fixture.py` — found one formatting change in the new detector.
  - `.venv/bin/ruff format src/mmaudit/solidity/invariants.py` — reformatted one file.
  - `.venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/solidity/invariants.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_templates.py tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/integration/test_economic_erc20_returns_fixture.py` — passed.
  - `.venv/bin/pytest -q tests/unit/test_economics.py::test_malformed_return_fixture_detects_only_unchecked_outcomes tests/unit/test_invariant_execution.py::test_malformed_return_template_reuses_observed_balance_typed_property` — `2 passed in 0.21s`.
  - `.venv/bin/pytest -q tests/integration/test_economic_erc20_returns_fixture.py -vv` — the real local Foundry regression passed, compiling and executing all unsafe, safe, replay, and minimality cases.
  - `.venv/bin/mypy src/mmaudit/models/schemas.py src/mmaudit/solidity/invariants.py src/mmaudit/solidity/economics.py src/mmaudit/solidity/invariant_templates.py` — passed for four affected source files.
  - `.venv/bin/pytest -q tests/unit/test_economics.py tests/unit/test_invariant_execution.py tests/integration/test_economic_erc20_returns_fixture.py tests/unit/test_properties.py` — `73 passed in 8.04s`.
  - `.venv/bin/ruff check tests/unit/test_economics.py && .venv/bin/pytest -q tests/unit/test_economics.py::test_malformed_return_fixture_detects_only_unchecked_outcomes` — passed after adding property-corpus serialization coverage.
- **Test results:** Focused detection, typed-harness, deterministic serialization,
  normalized execution, and real Foundry replay evidence are green. Repository-wide
  validation left 134 files unchanged by Ruff formatting, passed Ruff, passed
  strict mypy across 73 source files, and passed `354` tests with the two
  pre-existing explicitly recorded isolation skips in `31.16s`.
- **Unresolved issues:** None in the implemented local scope.
- **Additional commands run:**
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q` — `134 files left unchanged`; Ruff passed; mypy passed 73 source files; pytest reported `354 passed, 2 skipped in 31.16s`.
  - Removed only the exact generated `cache/test-failures`, nine Foundry invariant
    failure replays, and fixture-local `cache/`/`out/` directories created by the
    full suite; a follow-up file search found no remaining cache artifacts.
- **Checkpoint:** Not created. Every repository path remains untracked, so an
  isolated ticket commit would create an unusable partial repository history.
- **Exact next safe action:** Complete newly dependency-ready `ECO-009`; `ECO-018`
  remains gated by queued `REAL-003`.

## 2026-07-26 — SEM-002

- **Status:** `COMPLETE`
- **Defensive objective:** Distinguish unsafe and guarded call/control-flow
  transitions with exact compiler-backed provenance and bounded downstream context.
- **Completed changes:**
  - Resolved compiler internal calls by referenced declaration before name fallback
    and labeled internal, external, low-level, and delegatecall edge kinds.
  - Changed reentrancy ordering evidence to span the external interaction through
    the later state write, preserving an exact combined source hash.
  - Added explicit named-guard versus unguarded metadata while retaining guarded
    interaction-before-write edges as near-miss facts; effects-before-interaction
    does not produce the prohibited-order candidate.
  - Normalized fallback reentrancy edges to interaction-target-to-state-write
    direction with bounded sequence ranges and the same control metadata.
  - Made compact Solidity index/graph retrieval prefer verifier candidate paths and
    prioritize reentrancy facts for the dedicated specialist.
  - Added a synthetic compiler-AST call/control fixture plus decoy source and
    regression coverage for all call kinds, guarded/unguarded distinction, exact
    hashes, serialization, specialist context, and verifier context.
- **Files changed:**
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/solidity/retrieval.py`
  - `src/mmaudit/orchestration/context.py`
  - `tests/unit/test_solidity.py`
  - `tests/fixtures/solidity/semantic_calls/foundry.toml`
  - `tests/fixtures/solidity/semantic_calls/src/CallControl.sol`
  - `tests/fixtures/solidity/semantic_calls/src/DecoyCalls.sol`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:**
  - Reconciled queue order and dependencies; `SEM-002` depends only on the
    now-complete `SEM-001`.
  - Audited AST and source graph construction, graph retrieval rankings, context
    construction, model/verifier prompt projection, and current semantic fixtures.
  - `.venv/bin/ruff format src/mmaudit/solidity/graphs.py src/mmaudit/solidity/retrieval.py src/mmaudit/orchestration/context.py tests/unit/test_solidity.py`
  - `.venv/bin/ruff check src/mmaudit/solidity/graphs.py src/mmaudit/solidity/retrieval.py src/mmaudit/orchestration/context.py tests/unit/test_solidity.py`
  - `.venv/bin/mypy`
  - `.venv/bin/pytest -q tests/unit/test_solidity.py::test_ast_call_and_reentrancy_graphs_distinguish_guarded_near_miss tests/unit/test_solidity.py::test_full_semantic_graphs_are_built_with_explicit_fallback_provenance tests/unit/test_repository.py`
  - `.venv/bin/pytest -q tests/unit/test_solidity.py::test_ast_call_and_reentrancy_graphs_distinguish_guarded_near_miss`
- **Test results:** Affected Ruff passed; strict mypy passed across 70 source files;
  focused graph/repository pytest passed 32 tests, and the expanded specialist/verifier
  projection regression passed independently. The complete Solidity, repository
  context, and pipeline integration subset then passed 76 tests; affected Ruff and
  strict mypy passed again. Full pytest passed 290 tests. Local offline Forge/Solc
  0.8.20 compiled both fixture sources successfully; warnings were the expected
  unchecked low-level calls represented by the negative regression fixture.
- **Unresolved issues:** None within SEM-002 acceptance criteria.
- **Exact next safe action:** Complete `SEM-003`.
- **Artifact review:** The compiler wrote only to explicit `/private/tmp` paths;
  no fixture `out/`, cache, credentials, private material, or generated binaries
  were added to the repository.
- **Checkpoint commit:** Not created; the repository still has no tracked baseline
  and every file is untracked, so a ticket-only commit would create an unusable
  partial project history.

## 2026-07-26 — SEM-001

- **Status:** `COMPLETE`
- **Defensive objective:** Audit compiler and fallback provenance for every semantic
  entity and graph edge.
- **Completed changes:**
  - Required exact nonempty paths, ordered source ranges, SHA-256 line hashes, and
    named transformations for semantic entities, storage entries, graph nodes, and
    graph edges.
  - Added exact byte ranges and extraction transformations to compiler and fallback
    entities; invalid compiler entity spans no longer become compiler evidence.
  - Propagated extraction/transformation provenance into every graph-node constructor
    and corrected multi-line storage-order edge hashes to cover the serialized range.
  - Added a deliberately malformed, non-compilable synthetic Solidity fixture and
    compiler/fallback JSON round-trip regression coverage, including lower-confidence
    fallback and negative schema checks.
- **Files changed:**
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/index.py`
  - `src/mmaudit/solidity/graphs.py`
  - `src/mmaudit/orchestration/context.py`
  - `tests/unit/test_solidity.py`
  - `tests/unit/test_assurance.py`
  - `tests/unit/test_formal.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/fixtures/solidity/semantic_malformed/foundry.toml`
  - `tests/fixtures/solidity/semantic_malformed/src/MalformedAccounting.sol`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:**
  - Reconciled dependency status; audited every entity, storage, node, and edge
    constructor plus current semantic tests and source-hash helper.
  - `.venv/bin/ruff format src/mmaudit/models/schemas.py src/mmaudit/solidity/index.py src/mmaudit/solidity/graphs.py tests/unit/test_solidity.py tests/unit/test_assurance.py tests/unit/test_formal.py tests/unit/test_invariant_execution.py`
  - `.venv/bin/ruff check src/mmaudit/models/schemas.py src/mmaudit/solidity/index.py src/mmaudit/solidity/graphs.py tests/unit/test_solidity.py tests/unit/test_assurance.py tests/unit/test_formal.py tests/unit/test_invariant_execution.py`
  - `.venv/bin/mypy`
  - `.venv/bin/pytest -q tests/unit/test_solidity.py tests/unit/test_formal.py tests/unit/test_invariant_execution.py tests/unit/test_assurance.py`
- **Test results:**
  - Ruff format: 7 files already formatted.
  - Initial Ruff check found one import-order issue; fixed without suppression.
  - Initial focused pytest: 65 passed, 3 failed because existing synthetic AST
    fixtures contain compiler ranges extending a few bytes beyond discovered source.
    Entity-span normalization now bounds those ends to the discovered source and
    records `.bounded_to_source_length` in transformation provenance.
  - Final affected Ruff check passed.
  - Strict mypy passed across 70 source files.
  - Focused pytest passed: 68 tests.
  - Initial full pytest: 288 passed, 1 failed. Required provenance fields made the
    minimum 64-edge/64-entity deterministic context exceed the source-audit role
    allocation, so no specialist work was scheduled.
  - Reduced the bounded compact-context floor to 32 edges/entities, retaining
    deterministic provenance while allowing the existing byte-budget loop to fit.
  - The formerly failing maximum-assurance integration passed alone, then the
    combined repository-context, Solidity, and integration subset passed 52 tests.
  - Affected Ruff and strict mypy passed again.
  - Final full pytest passed: 289 tests.
  - Final constructor review confirmed all semantic entity, storage, graph-node,
    and graph-edge paths use required ranges, SHA-256 hashes, and named
    transformations. Targeted artifact review found no new secrets, caches,
    private output, or generated binaries.
- **Unresolved issues:** None within SEM-001 acceptance criteria.
- **Exact next safe action:** Complete `SEM-002`.
- **Checkpoint commit:** Not created; the repository still has no tracked baseline
  and every file is untracked, so a ticket-only commit would create an unusable
  partial project history.

## 2026-07-26 — MODEL-005

- **Status:** `COMPLETE`
- **Defensive objective:** Add two independent anonymized falsifier reviews for
  every high/critical candidate with strict candidate intake and retained dissent.
- **Completed changes:** Added opaque candidate references and origin-metadata
  removal; a strict no-new-finding response schema; exact intake completeness,
  duplicate, and unknown-reference rejection; deterministic selection of two exact
  models from distinct immutable root lineages; concurrent candidate falsifiers;
  retained supporting/disputing/inconclusive votes; report, artifact, and Markdown
  serialization; a two-lineage maximum-assurance gate; synthetic dissent; and
  focused anonymization/intake/lineage tests.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/agents/verifier.py`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/orchestration/assurance.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `src/mmaudit/prompts/cross_examination.md`
  - `src/mmaudit/reporting/markdown.py`
  - `tests/fake_openrouter.py`
  - `tests/integration/test_pipeline.py`
  - `tests/unit/test_assurance.py`
  - `tests/unit/test_cross_examination.py`
- **Commands run:** Re-read MODEL-005/worklog; inspected candidate/vote/report
  schemas, verifier and reproduction falsifiers, registry-lineage lookup, pipeline
  candidate flow, consensus dissent retention, report/artifact serialization,
  maximum-assurance gates, prompts, fake-provider behavior, and adjacent tests.
- **Test results:** Focused anonymization, unknown-intake, two-lineage selection and
  gate, dissent serialization, assurance, and maximum-pipeline suite passed:
  `16 passed`. Ruff formatted six files; its first check found one mergeable import,
  which was corrected. Strict mypy passed all `70` source files, final affected
  Ruff passed, and the complete cross-examination/assurance/reporting/pipeline
  subset passed `70` tests. Full pytest passed all `287` tests. Final review found
  no repository-local cross-examination artifact, candidate canary, credential
  material, public target, or generated build output; request anonymization is
  asserted before downstream validation.
- **Unresolved issues:** No isolated checkpoint commit was safe because the
  repository has no baseline commit and all files remain untracked.
- **Exact next safe action:** Continue with dependency-ready `SEM-001`.

## 2026-07-26 — MODEL-004

- **Status:** `COMPLETE`
- **Defensive objective:** Enforce and test first-pass context isolation across all
  investigator roles.
- **Completed changes:** Preconstructed and froze every base/specialist investigator
  context before yielding to any investigator task, while retaining the threat
  model as the only model-produced first-pass planning input. Added a deterministic
  fake-provider canary and an integration regression proving peer discovery
  requests exclude it while the downstream verifier receives it.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/orchestration/pipeline.py`
  - `tests/fake_openrouter.py`
  - `tests/integration/test_pipeline.py`
- **Commands run:** Re-read MODEL-004/worklog; inspected pipeline ordering,
  ContextBuilder's strict input surface and rendered payload, first-pass versus
  downstream candidate flow, fake-provider request capture, and integration tests.
- **Test results:** Focused context-isolation integration passed `1` test. Ruff
  reformatted one file, affected Ruff passed, strict mypy passed all `70` source
  files, and the complete pipeline integration suite passed `24` tests. Full pytest
  passed all `283` tests. Final review found no repository-local canary artifact,
  credential material, public target, or generated build output.
- **Unresolved issues:** No isolated checkpoint commit was safe because the
  repository has no baseline commit and all files remain untracked.
- **Exact next safe action:** Continue with dependency-ready `MODEL-005`.

## 2026-07-26 — MODEL-003

- **Status:** `COMPLETE`
- **Defensive objective:** Reconcile every required specialist role against a
  distinct responsibility, typed schema, bounded context, and execution record.
- **Completed changes:** Extended the specialist catalog across every investigator
  and auxiliary role with distinct missions, checks, priorities, structured schema
  identifiers, and fixed context ceilings. Added catalog consistency enforcement,
  dedicated bounded contexts for both planners and the falsifier, role contracts in
  every auxiliary prompt, canonical usage-role accounting, normalized typed
  execution records, a persistent execution artifact, assurance artifact binding,
  auxiliary retrieval weights, and completeness/duplicate-schema/execution tests.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/agents/invariant_review.py`
  - `src/mmaudit/agents/reproduction.py`
  - `src/mmaudit/agents/specialists.py`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/orchestration/assurance.py`
  - `src/mmaudit/orchestration/context.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `tests/fake_openrouter.py`
  - `tests/integration/test_pipeline.py`
  - `tests/unit/test_assurance.py`
- **Commands run:** Re-read MODEL-003/worklog; inspected constants, all specialist
  and auxiliary agents/prompts, response schemas, context ranking/budgeting,
  pipeline scheduling, usage accounting, assurance clauses, fake-provider behavior,
  and existing unit/integration coverage.
- **Test results:** Initial focused suite: `33 passed, 1 failed`. The failure was a
  fail-closed `ContextBudgetError`: the initial 128 KB test-generation cap could
  not contain the fixture's minimum deterministic metadata, so reproduction and
  dependent roles were correctly not scheduled. Raised all auxiliary caps that
  consume the same deterministic envelope to 192 KB; the dedicated maximum-
  assurance integration and assurance suite then passed `12` tests. Ruff formatted
  six files, affected Ruff passed, strict mypy passed all `70` source files, and
  the complete focused assurance/pipeline subset passed `34` tests. Full pytest
  passed all `282` tests. Final review found no repository-local execution
  artifact, credential material, public target, or new build output; the only URL
  in affected tests is the existing synthetic provider endpoint.
- **Unresolved issues:** No isolated checkpoint commit was safe because the
  repository has no baseline commit and all files remain untracked.
- **Exact next safe action:** Continue with dependency-ready `MODEL-004`.

## 2026-07-26 — MODEL-001

- **Status:** `COMPLETE`
- **Defensive objective:** Add deterministic model-lineage, duplicate, approval, and
  quality-tier validation.
- **Completed changes:** Added frozen, hash-identified root-lineage records with
  benchmark-bound measured quality and retention metadata; global alias/lineage
  duplicate rejection; lineage-aware independence and high-quality slot counting;
  explicit privacy retention ceilings and approved lineage lists; model-role tier,
  approval, and retention validation before source egress; validation-artifact
  serialization; deterministic tests; and configuration examples.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `mmaudit.example.toml`
  - `src/mmaudit/cli.py`
  - `src/mmaudit/config.py`
  - `src/mmaudit/models/registry.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `src/mmaudit/templates/mmaudit.example.toml`
  - `tests/conftest.py`
  - `tests/integration/test_pipeline.py`
  - `tests/unit/test_model_registry.py`
- **Commands run:** Re-read the ticket and worklog; inspected registry/cache
  behavior, model and privacy configuration, provider metadata validation, CLI and
  pipeline call sites, examples, and existing model/config/pipeline tests. Ran
  focused pytest; affected Ruff format/check; strict mypy; focused pytest again;
  full pytest; synchronized-example comparison; repository status and
  secret/network/generated-artifact review.
- **Test results:** Initial focused suite passed `59` tests. Ruff formatted five
  affected files. The first Ruff check found one unescaped regex metacharacter in a
  test expectation; it was corrected. Final affected Ruff passed, strict mypy
  passed all `70` source files, and the focused suite again passed `59` tests. Full
  pytest passed all `282` tests. Configuration examples are byte-identical. Review
  found no introduced credential, public-network, or generated build-artifact
  material; ignored build directories found by the review predated this ticket.
- **Unresolved issues:** No isolated checkpoint commit was safe because the
  repository has no baseline commit and all files remain untracked.
- **Exact next safe action:** Continue with dependency-ready `MODEL-003`.

## 2026-07-26 — ECO-003

- **Status:** `COMPLETE`
- **Defensive objective:** Add a typed ordering-sensitive property and deterministic
  unsafe/remediated local sequence regression.
- **Completed changes:** Selected newly dependency-ready `ECO-003` after completing
  its `REAL-001` and `REAL-002` prerequisites. Added an exact source-linked staged
  value-bound invariant, capability-gated ordering plan, typed victim-setup and
  attacker-reorder harness, operator authorization enforcement before Forge,
  normalized same-block evidence/metrics, report fields, setup binding validation,
  and synthetic unsafe/remediated local fixtures with minimality controls.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `src/mmaudit/reporting/markdown.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `tests/fixtures/solidity/economic_ordering/`
  - `tests/integration/test_economic_ordering_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
- **Commands run:** Reconciled queue dependencies after the `REAL-002` full gate;
  re-read queue/worklog; inspected economic planning, invariant discovery, typed
  harness schemas/translation/execution, reproduction ordering policy, pipeline
  binding validation, reporting, and adjacent fixture/test patterns; implemented
  the bounded ordering validation slice.
- **Test results:** Ruff reformatted 6 files. Initial focused suite: `89 passed,
  3 failed`. The real offline Forge unsafe/remediated ordering regression and
  reporting/pipeline coverage passed. Failures were limited to absent deterministic
  ordering invariant selection and a missing `InvariantRelation` test import.
  Inspection showed fallback indexing retained the exact function signature but not
  its return type; the detector now accepts a source-linked exact `returns
  (uint256)` declaration as lower-confidence evidence. One mocked Forge marker used
  an external process under a process-capped runner; replacing it with a shell
  builtin preserved the execution assertion. Final focused suite: `92 passed`.
  Affected Ruff and strict mypy passed; the full suite passed all `275` tests.
- **Unresolved issues:** The exact typed staged/reorder/shortfall shape is required;
  unsupported protocol shapes remain explicit limitation evidence. Final review
  found no fixture artifacts or secret/network material. No isolated checkpoint
  commit was safe because the repository still has no baseline commit and every
  file is untracked.
- **Exact next safe action:** Begin dependency-ready `MODEL-001`.

## 2026-07-26 — REAL-002

- **Status:** `COMPLETE`
- **Defensive objective:** Add explicit typed setup/attack phase separation with
  fixed translation and injection-negative validation.
- **Completed changes:** Selected the first dependency-ready queue ticket after
  completing `ECO-013`. Split generated reproductions into typed `setup_calls` and
  `attack_calls`; limited assertions, capability accounting, transaction counts, and
  minimization to attacker-reachable calls; translated explicit setup before attack
  evidence snapshots; required setup calls to succeed; rejected the Foundry
  cheatcode address as a phase target; and updated planner/fake-provider contracts.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/agents/reproduction.py`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/prompts/exploit_test.md`
  - `src/mmaudit/solidity/reproduction.py`
  - `tests/fake_openrouter.py`
  - `tests/integration/test_pipeline.py`
  - `tests/unit/test_reproduction.py`
- **Commands run:** Reconciled post-`ECO-013` dependency ordering and selected
  `REAL-002`, whose `REAL-001` dependency is complete; re-read queue/worklog;
  inspected schemas, runner/translator, planner prompt/payload, fake provider, and
  reproduction/pipeline tests; implemented explicit phase separation and negative
  validation coverage.
- **Test results:** Ruff reformatted 3 affected files. Focused reproduction and
  pipeline suite passed all `60` tests, including deterministic phase ordering,
  attack-only assertion evidence, legacy undifferentiated-call rejection, untyped
  state-mutation field rejection, and cheatcode-target rejection. Affected Ruff
  checks passed. The first strict mypy run found one setup/attack loop-variable type
  collision; after using phase-specific names, strict mypy passed all 70 source
  files. The full pytest suite passed all `268` tests.
- **Unresolved issues:** Final review found no current-ticket artifacts or stale
  undifferentiated source fields. Existing ignored Solidity caches predate this
  ticket. No isolated checkpoint commit was safe because the repository still has
  no baseline commit and every file is untracked.
- **Exact next safe action:** Begin newly dependency-ready `ECO-003`.

## 2026-07-26 — ECO-013

- **Status:** `COMPLETE`
- **Defensive objective:** Add a typed, source-linked signature replay property with
  unsafe and remediated deterministic local fixtures.
- **Completed changes:** Selected the highest-priority dependency-ready economic
  ticket after completing and recording `ECO-002`. Recovered and inspected an
  interrupted implementation slice containing primitive-backed applicability,
  a typed consume-once harness, fixture-confined unsafe/remediated contracts,
  deterministic replay/minimality controls, bounded economic evidence, and report
  serialization coverage. Corrected the real fixture's explicit invariant target so
  Foundry exercises the typed replay action instead of only direct calls that revert
  before the intended transition.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `tests/fixtures/solidity/economic_signature_replay/`
  - `tests/integration/test_economic_signature_replay_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
- **Commands run:** Reconciled queue statuses and dependencies after the `ECO-002`
  full validation gate; re-read authoritative repository state in the required
  order; inspected signature graph/invariant applicability, typed execution,
  fixture, integration, and serialization coverage; initial focused pytest; verbose
  local Forge diagnosis; focused pytest after the target correction.
- **Test results:** Initial focused suite: `62 passed, 1 failed`. Verbose Forge
  evidence showed all 16 direct target calls reverted before the intended action.
  After explicit action targeting, Forge compiled the fixture and minimized the
  unsafe violation to one replay call. Final focused suite: `63 passed`; it replayed
  the unsafe counterexample twice and passed the safe nonce/domain and minimality
  controls.
- **Unresolved issues:** The translated generic harness is syntax-checked in unit
  tests; only the synthetic local regression fixture is claimed as compiled and
  executed. No isolated checkpoint commit was safe because the repository still
  has no baseline commit and every file is untracked.
- **Exact next safe action:** Begin dependency-ready `REAL-002` and add explicit
  reproduction setup/attack phase separation.

## 2026-07-26 — ECO-002

- **Status:** `COMPLETE`
- **Defensive objective:** Add a typed bounded-rounding applicability detector and
  executable local invariant harness with unsafe and remediated controls.
- **Completed changes:** Verified that the recovered ticket scaffold selected
  rounding only from a source-linked integer-division invariant; completed a typed,
  bounded round-trip action/property that rejects account-value creation while
  permitting downward-rounding loss; recorded bounded rounding inputs in normalized
  execution evidence; added unsafe and corrected local fixtures, deterministic
  replay, exact-boundary/minimality controls, and JSON/Markdown serialization
  coverage.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `tests/fixtures/solidity/economic_rounding/`
  - `tests/integration/test_economic_rounding_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
- **Commands run:** Authoritative-state and Git inspection; baseline focused pytest
  exposed the recovered planning/execution mismatch
  (`1 failed, 23 passed`); affected Ruff formatting; focused pytest over economic,
  invariant, reporting, and real rounding integration tests; affected Ruff checks;
  strict mypy; repository-wide Ruff formatting/check, strict mypy, and full pytest;
  final Git/artifact review.
- **Test results:** Focused final suite `58 passed`; the real local Forge test
  compiled and replayed the unsafe counterexample twice, passed the corrected
  invariant, and passed all three boundary/minimality controls. Affected Ruff checks
  passed; mypy passed across 70 source files. Final repository gates passed: Ruff
  left 114 files unchanged and reported no issues, mypy passed 70 source files, and
  pytest passed all 255 tests.
- **Unresolved issues:** The generic harness intentionally requires an explicit
  source-linked `roundTrip(uint256)` transition and an address-indexed accounting
  getter; protocols without that typed shape remain limitation evidence rather than
  fabricated execution. No isolated checkpoint commit was safe because the
  repository still has no baseline commit and every file is untracked.
- **Exact next safe action:** Begin dependency-ready `ECO-013` and implement bounded
  signature-domain/nonce replay validation with synthetic local-only keys.

## 2026-07-26 — ECO-001

- **Status:** `COMPLETE`
- **Defensive objective:** Add a typed applicability detector and deterministic local
  invariant harness for non-standard token balance behavior.
- **Completed changes:** Added a source-linked observed-assets-versus-claims
  invariant, deterministic applicability selection, a typed Foundry harness with
  bounded setup and fixed probes, normalized Foundry outcome parsing, economic
  evidence serialization coverage, and synthetic fee/rebase unsafe and remediated
  fixtures with replay and minimality controls.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/solidity/economics.py`
  - `src/mmaudit/solidity/invariant_execution.py`
  - `src/mmaudit/solidity/invariant_templates.py`
  - `src/mmaudit/solidity/invariants.py`
  - `tests/fixtures/solidity/economic_token_behavior/`
  - `tests/integration/test_economic_token_behavior_fixture.py`
  - `tests/unit/test_economics.py`
  - `tests/unit/test_invariant_execution.py`
  - `tests/unit/test_scanners_reporting.py`
- **Commands run:** Repeated authoritative-state/Git inspection after user recovery
  messages; relevant invariant/economic/report code inspection; trusted Forge
  executable/version check.
- **Test results:** Focused suite `53 passed`; real Forge fixture executed both
  unsafe counterexamples twice, both remediated controls, and minimality controls;
  Ruff formatting/check passed; mypy passed across 70 source files; full suite
  `249 passed`.
- **Unresolved issues:** Rebase activation is represented through the same typed
  observed-assets property and fixture-specific bounded setup; general protocol
  behavior binding still requires operator-pinned targets. No checkpoint commit was
  safe because the entire repository remains untracked.
- **Exact next safe action:** Re-read AGENTS, queue, worklog, Git status, and diff;
  begin dependency-ready `ECO-002`.

## 2026-07-26 — REAL-001

- **Status:** `COMPLETE`
- **Defensive objective:** Add a typed, bounded attacker capability policy to the
  declarative reproduction flow.
- **Completed changes:** Added a typed attacker capability policy to generated
  reproduction specifications; required exact justifications for every active
  capability; rejected undeclared actors, call capabilities, and capital; added
  operator ceilings for controlled actors/contracts, capital/liquidity, token
  approvals, time/block movement, ordering, oracle influence, governance,
  privileged roles, cross-chain messages, and transaction count; enforced the
  policy both after model parsing and before workspace/tool execution.
- **Files changed:**
  - `README.md`
  - `docs/codex_worklog.md`
  - `mmaudit.example.toml`
  - `src/mmaudit/agents/reproduction.py`
  - `src/mmaudit/config.py`
  - `src/mmaudit/models/schemas.py`
  - `src/mmaudit/prompts/exploit_test.md`
  - `src/mmaudit/solidity/reproduction.py`
  - `src/mmaudit/templates/mmaudit.example.toml`
  - `src/mmaudit/traceability.py`
  - `tests/fake_openrouter.py`
  - `tests/unit/test_config.py`
  - `tests/unit/test_reproduction.py`
- **Commands run:** Authoritative-state/Git inspection; focused policy,
  configuration, and pipeline pytest; Ruff formatting/check; strict mypy; full
  pytest.
- **Test results:** Focused final suite `50 passed`; Ruff passed; mypy passed across
  70 source files; full suite `244 passed`.
- **Unresolved issues:** `REAL-002` still needs explicit setup/attack phase
  separation; this ticket does not claim reproduction integrity.
- **Exact next safe action:** Re-read AGENTS, queue, worklog, and Git state, then
  select the highest-priority dependency-ready ticket.

## 2026-07-25 — ASSURE-001

- **Status:** `COMPLETE`
- **Defensive objective:** Missing required capabilities must fail the assurance
  contract, or produce `DOWNGRADED` only after explicit acknowledgement.
- **Completed changes:** Added typed traceability input to the assurance runtime,
  required the matrix to be present, converted every required traceability row into
  a blocking assurance clause, proved current incomplete rows cannot yield
  `COMPLETE`, and added `MA-ASSURANCE-CONTRACT` to the emitted matrix.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `src/mmaudit/orchestration/assurance.py`
  - `src/mmaudit/orchestration/pipeline.py`
  - `tests/integration/test_pipeline.py`
  - `tests/unit/test_assurance.py`
- **Commands run:** Authoritative-state/Git inspection; focused assurance, traceability,
  and pipeline pytest; Ruff formatting/check; strict mypy; full pytest twice around
  the final traceability update.
- **Test results:** Focused final suite `21 passed`; Ruff passed; mypy passed across 70
  source files; full suite `225 passed`.
- **Unresolved issues:** Current matrix intentionally blocks `COMPLETE` because other
  required roadmap groups remain incomplete. No checkpoint commit was safe because
  the entire repository remains untracked.
- **Exact next safe action:** Re-read AGENTS, queue, worklog, and Git state; begin
  dependency-ready `REAL-001`.

## 2026-07-25 — TRACE-001

- **Status:** `COMPLETE`
- **Defensive objective:** Ensure an implemented traceability row cannot survive
  missing code, test, or runtime-artifact evidence.
- **Completed changes:** Tightened evidence-path validation, rejected documentation,
  tests, traversal, and symlinks as implementation evidence, added independent
  missing-code/test/artifact cases, removed an unsupported discovery integration
  claim, added pipeline artifact validation, and wired the gate into CI.
- **Files changed:**
  - `.github/workflows/mmaudit.yml`
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
  - `schemas/maximum_assurance_traceability.schema.json`
  - `src/mmaudit/traceability.py`
  - `tests/integration/test_pipeline.py`
  - `tests/unit/test_traceability.py`
- **Commands run:** Focused inspection and pytest; Ruff formatting and checks; strict
  mypy; full pytest; real scanner-only CLI run on a synthetic fixture; emitted-matrix
  repository/artifact validation.
- **Test results:** Focused `10 passed`; Ruff passed; mypy passed across 70 source
  files; full suite `221 passed`; real artifact validated all 11 requirements.
- **Unresolved issues:** Other traceability rows remain honestly partial or
  unimplemented. No checkpoint commit was created because every repository file is
  currently untracked and a ticket-only initial commit would be structurally broken.
- **Exact next safe action:** Re-read AGENTS, queue, worklog, and Git state; begin
  dependency-ready `ASSURE-001`.

## Latest completed work unit

- **Ticket:** `QUEUE-BOOTSTRAP-001`
- **Status:** `COMPLETE`
- **Completed changes:** Converted the maximum-assurance roadmap into bounded,
  dependency-ordered defensive engineering tickets and initialized this worklog.
- **Files changed:**
  - `docs/codex_work_queue.md`
  - `docs/codex_worklog.md`
- **Commands run:**
  - Read `AGENTS.md`.
  - Checked whether queue/worklog files already existed.
  - Read the current maximum-assurance traceability documentation and implementation.
- **Test results:** No code was changed; manual required-field review only.
- **Unresolved issues:** The queue records many partial and missing capabilities.
  Queue status is not evidence of implementation or maximum-assurance completeness.
- **Exact next safe action:** Begin `TRACE-001`; mark it `IN_PROGRESS`, inspect the
  traceability pipeline/tests, run focused validation, correct unsupported claims,
  and update this log before selecting another ticket.

## Work-unit template

Copy this section for each ticket:

```markdown
## YYYY-MM-DD — TICKET-ID

- **Status:** IN_PROGRESS | COMPLETE | PARTIAL | BLOCKED_SAFETY | BLOCKED_TECHNICAL
- **Defensive objective:**
- **Completed changes:**
- **Files changed:**
- **Commands run:**
- **Test results:**
- **Unresolved issues:**
- **Exact next safe action:**
```

## Status rules

- `COMPLETE`: Acceptance criteria passed with the required automated evidence.
- `PARTIAL`: Useful implementation exists, but one or more criteria remain unmet.
- `BLOCKED_SAFETY`: The specific subtask cannot be performed within repository safety
  boundaries; record only a short non-operational reason.
- `BLOCKED_TECHNICAL`: A required tool or environment is unavailable.
- `IN_PROGRESS`: Exactly one bounded implementation ticket is active.
