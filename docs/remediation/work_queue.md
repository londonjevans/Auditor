# mmaudit Remediation Work Queue

This queue repairs the immutable fit-for-purpose baseline evaluated at commit
`e304807cf942542706b88544fa216516f8f95cad`. The baseline artifacts under
`docs/evaluation/` are evidence inputs and must not be edited.

Statuses: `QUEUED`, `IN_PROGRESS`, `COMPLETE`, `PARTIAL`,
`BLOCKED_TECHNICAL`, `BLOCKED_SAFETY`.

## REM-SECRET-001 — Explicit operator-secret boundary

- **Objective:** Load only approved control-plane credentials from an explicitly
  selected, validated dotenv file and prevent their propagation or serialization.
- **Files/modules:** `src/mmaudit/operator_secrets.py`, CLI/provider construction,
  repository exclusions, subprocess/container environments, tests.
- **Acceptance criteria:** `--secrets-env-file` and
  `MMAUDIT_SECRETS_ENV_FILE` are explicit; links, non-files, and group/world-writable
  files are rejected; only allowlisted names are loaded; a canary never appears in
  output, logs, reports, manifests, SARIF, model messages, exceptions, subprocesses,
  scanners, formal tools, or containers; doctor reports only accepted/rejected,
  present/missing, and valid/invalid states.
- **Real-integration boundary:** Credential authentication is separately recorded
  as real only after explicit opt-in and a successful authenticated request.
- **Dependencies:** None.
- **Status:** `COMPLETE`
- **Next action:** None. The isolated checkpoint is recorded in the remediation
  worklog; continue with `EVAL-DEFECT-001`.

## EVAL-DEFECT-001 — Compilation failure can satisfy maximum assurance

- **Objective:** Require successful AST-backed compilation for maximum assurance.
- **Acceptance criteria:** `FAILED`, `TIMED_OUT`, `SKIPPED`, `UNAVAILABLE`, and
  fallback-parser-only compilation all fail the required clause; the baseline
  `compilation_failed` assay is a permanent regression.
- **Dependencies:** `REM-SECRET-001`.
- **Status:** `COMPLETE`
- **Next action:** None; continue with `EVAL-DEFECT-002`.

## EVAL-DEFECT-002 — Failed reproduction can satisfy maximum assurance

- **Objective:** Prevent attempted but unsuccessful high/critical reproduction from
  satisfying maximum assurance.
- **Acceptance criteria:** Every feasible high/critical candidate has qualifying
  successful reproduction/counterexample, qualifying falsification and rejection,
  validated severity reduction, or explicit `INCONCLUSIVE`; unresolved candidates
  block `COMPLETE`; the baseline `failed_reproduction_attempt` assay fails closed.
- **Dependencies:** `EVAL-DEFECT-001`.
- **Status:** `COMPLETE`
- **Next action:** None; continue with `EVAL-DEFECT-003`.

## EVAL-DEFECT-003 — Complementary engines are optional by default

- **Objective:** Require the exact certified engine portfolio to execute
  successfully under maximum assurance.
- **Acceptance criteria:** Foundry unit/property/invariant, Echidna, Medusa, Halmos,
  at least one formal proof engine, hardened isolation, isolated replay, real model
  review, and the current benchmark gate are mandatory; unavailable, skipped,
  mocked, timed-out, unisolated, or empty evidence fails closed.
- **Dependencies:** `EVAL-DEFECT-002`.
- **Status:** `COMPLETE`
- **Next action:** None; certified execution remains fail-closed and the unavailable
  real portfolio is tracked under `REM-INTEGRATIONS-001`. Continue with
  `EVAL-DEFECT-004`.

## EVAL-DEFECT-004 — Missing Slither can be hidden

- **Objective:** Require one real successful Slither execution record independently
  of other scanners.
- **Acceptance criteria:** The `required_slither_missing` assay fails and no other
  scanner can satisfy the Slither clause.
- **Dependencies:** `EVAL-DEFECT-003`.
- **Status:** `COMPLETE`
- **Next action:** None; continue with `REM-OPENROUTER-001`.

## REM-OPENROUTER-001 — Exact OpenRouter client and cost ledger

- **Objective:** Implement current exact-model/provider routing, bounded typed
  errors, complete response validation, non-secret request evidence, and an atomic
  hard cost ledger.
- **Acceptance criteria:** Official metadata and key endpoints are validated; exact
  model and endpoint policy is enforced; certification fallback is disabled;
  privacy routing is mandatory; substitutions downgrade; concurrent reservations
  cannot exceed `250.00 USD`; malformed, truncated, mismatched, timed-out,
  rate-limited, and unavailable responses never count as reviews.
- **Dependencies:** `EVAL-DEFECT-004`.
- **Status:** `COMPLETE`
- **Runtime artifact:** `docs/remediation/runtime/rem_openrouter_001.json`.
- **Real integration boundary:** Protocol, routing, validation, cost-ledger, and
  fail-closed behavior are covered by deterministic local tests. No paid
  completion was executed or credited; exact-model provider execution remains
  tracked by `REM-MODELS-001`.
- **Next action:** None; continue with `REM-MODELS-001`.

## REM-MODELS-001 — Production model registry and qualification

- **Objective:** Discover, benchmark, qualify, freeze, and verify exact production
  model identities without marketing-based or self-qualification shortcuts.
- **Files/artifacts:** `config/models.candidates.toml`,
  `config/models.maximum-assurance.toml`,
  `schemas/model_qualification.schema.json`,
  `docs/models/model_selection.md`, model CLI and benchmark modules.
- **Acceptance criteria:** All qualification dimensions are non-empty and
  version-bound; Tier A hashes resolve to passing artifacts; operator-reviewed
  lineage mapping is mandatory; production selection is `all_eligible_tier_a`;
  minimum certified ensemble counts are enforced from completed real requests.
- **Dependencies:** `REM-OPENROUTER-001`.
- **Status:** `IN_PROGRESS`
- **Next action:** Freeze the exact candidate-registry and qualification schemas,
  then implement non-empty, artifact-bound discovery, benchmark, qualification,
  and verification commands before any paid model call.

## EVAL-DEFECT-005 — Context delivery is credited as model review

- **Objective:** Credit only explicit, valid, substantive per-surface review records.
- **Acceptance criteria:** Strict reviewer output records every requested stable
  surface with status, role, rationale, location/symbol, invariant, assumptions,
  and confidence; generic, malformed, truncated, failed, invalid-location,
  duplicate-alias, unqualified, or missing records receive no credit.
- **Dependencies:** `REM-MODELS-001`.
- **Status:** `QUEUED`

## EVAL-DEFECT-006 — Quality hashes are not benchmark-resolved

- **Objective:** Bind every production-quality designation to a current passing
  qualification artifact.
- **Acceptance criteria:** Shape-only hashes fail; source/config/prompt/schema/model/
  tool/isolation bindings, expiry, non-empty cases, and thresholds verify.
- **Dependencies:** `EVAL-DEFECT-005`.
- **Status:** `QUEUED`

## EVAL-DEFECT-007 — verify-run loses effective CLI overrides

- **Objective:** Persist and verify the complete effective run configuration.
- **Acceptance criteria:** A profile-overridden run verifies without operator
  recollection; effective configuration and CLI override hashes reconcile.
- **Dependencies:** `EVAL-DEFECT-006`.
- **Status:** `QUEUED`

## EVAL-DEFECT-008 — Empty benchmark gates pass vacuously

- **Objective:** Represent unavailable denominators explicitly and fail required
  metrics closed.
- **Acceptance criteria:** Zero reports/cases/calls/locations/attempts produce
  `NOT_EVALUABLE`, never `PASS`; malformed/stale/failed analyses remain in
  denominators; required metrics and costs are distinct.
- **Dependencies:** `EVAL-DEFECT-007`.
- **Status:** `QUEUED`

## EVAL-DEFECT-009 — Release validation trusts declared names

- **Objective:** Validate actual emitted release artifacts and hashes.
- **Acceptance criteria:** Missing, linked, undeclared, name-only, stale, or
  hash-mismatched runtime artifacts fail validation.
- **Dependencies:** `EVAL-DEFECT-008`.
- **Status:** `QUEUED`

## EVAL-DEFECT-010 — Release report is stale and unbound

- **Objective:** Generate a fresh release report bound to the exact candidate commit.
- **Acceptance criteria:** Report inputs, emitted artifacts, gate results, commit,
  effective config, and evidence hashes reconcile; blocked integrations stay
  blocked.
- **Dependencies:** `EVAL-DEFECT-009`.
- **Status:** `QUEUED`

## EVAL-DEFECT-011 — Mutation portfolio and real kill score are incomplete

- **Objective:** Implement all eleven required source-local mutation classes and
  execute property-class kill scoring.
- **Acceptance criteria:** Each mutation applies/restores in disposable copies,
  compiles, and executes against applicable properties; critical mandatory classes
  meet the configured 95% gate with no hidden aggregate.
- **Dependencies:** `EVAL-DEFECT-010`.
- **Status:** `QUEUED`

## EVAL-DEFECT-012 — Reproduction identity lacks bytecode equivalence

- **Objective:** Independently compare deployed runtime bytecode with compiled
  audited source before crediting reproduction.
- **Acceptance criteria:** Compiler settings, libraries, immutables, metadata, and
  runtime bytecode bind to the reproduced target; mismatch is explicit and blocks
  confirmation.
- **Dependencies:** `EVAL-DEFECT-011`.
- **Status:** `QUEUED`

## EVAL-DEFECT-013 — Rejected Markdown omits evidence

- **Objective:** Render complete rejected-finding evidence and dissent.
- **Acceptance criteria:** Location, symbol, preconditions, reachability, severity,
  evidence tier, verifier, falsifier, reproduction/formal status, remediation, and
  residual uncertainty are retained and escaped.
- **Dependencies:** `EVAL-DEFECT-012`.
- **Status:** `QUEUED`

## REM-INTEGRATIONS-001 — Real engine, isolation, replay, and benchmark evidence

- **Objective:** Execute every locally available certified integration against paired
  unsafe/safe controls while preserving explicit blockers.
- **Acceptance criteria:** Runtime artifacts distinguish real from mock, record
  executable/version/hash/isolation/target/time/coverage/result, and never count
  discoverability as execution; unavailable prerequisites have exact operator
  commands and do not weaken assurance.
- **Dependencies:** `EVAL-DEFECT-013`.
- **Status:** `QUEUED`

## REM-RELEASE-001 — Candidate release and independent handoff

- **Objective:** Produce a commit-bound candidate, complete validation evidence,
  final remediation status, and an independent re-evaluation handoff.
- **Acceptance criteria:** All safe code defects are complete; every remaining
  integration is specifically blocked or real; full Ruff/mypy/pytest, schemas,
  reports, SARIF, benchmarks, manifests, verify-run, replay, and release validation
  execute; baseline artifacts retain their frozen hashes.
- **Dependencies:** `REM-INTEGRATIONS-001`.
- **Status:** `QUEUED`
