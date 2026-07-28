# mmaudit v3 Product Remediation Queue

This queue implements the externally reviewed v3 product objective captured by
SHA-256 `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
Historical evaluation artifacts remain immutable. A unit test, mock, declaration,
or configured adapter is not real runtime evidence.

Statuses: `QUEUED`, `IN_PROGRESS`, `COMPLETE`, `PARTIAL`,
`BLOCKED_TECHNICAL`, `BLOCKED_SAFETY`.

## V3-BASELINE-001 — Restore the engineering baseline

- **Objective:** Freeze the clean candidate, run the full existing suite, reproduce
  the two externally reported release-schema failures, fix any failures still
  present, and run Ruff format/check, strict mypy, and full pytest before paid calls.
- **Acceptance criteria:** Exact commands and results are recorded; no release-schema
  failure remains; unrelated operator changes are preserved.
- **Dependencies:** None.
- **Status:** `COMPLETE`
- **Evidence:** Generated release schemas verified; focused release-schema/report
  tests passed; Ruff format/check, strict mypy, and two full-suite executions passed,
  ending with `1799 passed, 10 skipped in 217.18s`.
- **Next action:** None; continue with `V3-IDENTITY-001`.

## V3-IDENTITY-001 — Canonical provider identity binding

- **Objective:** Bind every completion to immutable model identity, canonical aliases,
  approved endpoint metadata, and generation evidence without discarding valid
  unbound evidence.
- **Acceptance criteria:** Identity strengths are typed; mutable labels never satisfy
  immutable identity; exact aliases normalize; endpoint/provider/model mismatches
  fail closed; frozen snapshots and focused regressions pass.
- **Dependencies:** `V3-BASELINE-001`.
- **Status:** `COMPLETE`
- **Evidence:** All four metadata surfaces are runtime-bound; canonical aliases,
  endpoint/provider/model/generation mismatches, valid-unbound retention, no
  automatic fallback, process-local authority, and persisted-evidence regressions
  pass. The complete suite passed `1859` tests with `10` explicit prerequisite
  skips; independent final review found no material blocker.
- **Next action:** None; on operator resume continue with `V3-SMOKE-001`.

## V3-SMOKE-001 — Successful real synthetic OpenRouter call

- **Objective:** Complete one exact-model, exact-endpoint, identity-bound,
  non-truncated structured response against a committed synthetic Solidity fixture.
- **Acceptance criteria:** Explicit operator-secret loading, strict routing, approved
  privacy, reconciled cost, bounded output, schema validation, and canary
  non-disclosure are evidenced in a non-secret runtime artifact.
- **Dependencies:** `V3-IDENTITY-001`.
- **Status:** `IN_PROGRESS`
- **Pause evidence:** The first v3 launch stopped before a completion POST when
  single-model metadata lookup returned HTTP `404`; no artifact, spend, or
  reservation was added.
- **Runtime evidence:** Exact-ID metadata succeeds. One response was rejected
  fail-closed as truncated after spending `0.00054756 USD`; a materially changed
  reasoning-disabled response was schema-valid but rejected as identity
  `UNBOUND` after spending `0.00006484 USD`. A fifth materially changed response
  also concluded `UNBOUND`; its private rejection sink then exposed an
  attempt-qualified ledger-ID join defect. The terminal attempt conservatively
  accounted `0.00072452 USD`. No response received review credit and no success
  artifact exists.
- **Local diagnostic correction:** Endpoint-tag versus provider-display identity
  normalization and exact/canonical model reconciliation now have negative
  regressions. Typed unbound generation observations are retained without review
  credit; affected validation passed `198` tests, Ruff, strict mypy, and diff
  checks. No provider call ran.
- **Durable rejection evidence:** The real smoke path now retains a schema-valid
  concluded `UNBOUND` response in a separate private, self-hashed,
  non-creditable artifact; the success artifact remains absent and the test fails
  closed. An executed local branch regression requires process-attested REAL
  provenance, rejects reconstructed evidence, reconciles cost, and proves prompt,
  source, path, and credential canaries do not persist.
- **Local validation:** Independent re-review found no remaining blocker. Ruff,
  strict mypy, and the full suite passed, ending with `1892 passed, 10 skipped in
  240.48s`; the paid provider test remained explicitly disabled.
- **Metadata readiness correction:** Authenticated metadata-only discovery
  identified exact route `mistralai/mistral-small-2603` at `venice/fp8`; no
  completion was requested and cost state did not change. Generation evidence now
  polls the same generation at fixed bounded delays for a transient `404` or
  same-ID incomplete response, while authentication failures, identity
  contradictions, and exhaustion remain fail-closed. Focused validation passed
  `235` tests, affected Ruff, and strict mypy.
- **Sixth runtime attempt:** From clean synchronized checkpoint `dd871cc`, the
  exact Mistral/Venice response was structured, non-truncated, and canonically
  bound. The mandatory independent generation re-fetch then failed usage
  reconciliation, so no success credit or artifact was issued. The exact attempt
  reconciled `0.0000635625 USD`; cumulative spend is `0.0019275425 USD` with no
  active reservation.
- **Local reconciliation correction:** Post-bind mismatches now retain a typed,
  value-free diagnostic. Only usage and cost fields receive the existing bounded
  same-generation polling window; identity, provider, finish, timestamp, and
  internally inconsistent metadata fail immediately. A separate private,
  self-hashed rejection artifact preserves the bound-but-unverified result
  without granting success credit.
- **Independent correction:** Review found that a retryable cost mismatch could
  mask a simultaneous decisive timestamp contradiction. A compound negative
  regression reproduced the defect; decisive identity, provider, finish, and
  timestamp checks now precede all retryable usage/cost comparisons.
- **Complete local gate:** Independent re-review found no material blocker.
  Ruff format/check, strict mypy, release-schema generation, `320` focused tests
  plus one paid skip, and the complete suite passed, ending with `1912 passed,
  10 skipped`. No seventh provider request ran.
- **Seventh runtime attempt:** From clean synchronized checkpoint `1ceab96`, the
  exact Mistral/Venice route passed local preflight but the completion endpoint
  returned provider rate limiting before any model output. The bounded zero-retry
  policy failed closed; no response, success artifact, rejection artifact, or
  review credit exists. The terminal entry conservatively accounted its
  `0.00072452 USD` reservation, bringing cumulative spend to `0.0031470425 USD`
  with zero active reservation.
- **Materially different route:** DeepSeek/Novita metadata failed closed because
  the live single-model response differed from the frozen catalog projection.
  Exact Qwen `qwen/qwen3.6-35b-a3b` through `akashml/fp8` then passed authenticated
  metadata-only discovery with typed `STRICT_ZDR`, data-denial, native structured
  output, optional reasoning, and exact endpoint evidence. No completion ran and
  ledger cost did not change.
- **Eighth runtime attempt:** From clean synchronized checkpoint `129c4ac`, the
  exact Qwen/AkashML response was structured and non-truncated but remained
  `UNBOUND` because generation metadata was not ready within the fixed
  `0/1/3/7` window. The durable private rejection artifact is self-hashed,
  non-creditable, canary-free, and joined to a reconciled `0.00006484 USD`
  attempt; cumulative spend is `0.0032118825 USD`.
- **Late-evidence diagnostic:** An authenticated metadata-only re-fetch of the
  already-paid generation later produced exact canonical Qwen/AkashML,
  `finish=stop` evidence without another completion or ledger change. This
  isolates the remaining cause as a too-short readiness window rather than a
  model/provider identity contradiction.
- **Local readiness correction:** The request-aware schedule now permits seven
  observations through a cumulative `116`-second readiness horizon and enforces
  one total wall deadline. Typed reconciliation validates every explicit field in
  partial or complete metadata, including observations whose generation ID has not
  materialized yet. Initial identity binding uses the same expectation, and
  multi-generation verification shares an auth-inclusive deadline with bounded,
  non-starving GET concurrency and cancellation cleanup.
- **Current next action:** `PAUSED_BY_OPERATOR` at validated implementation
  checkpoint `9f63ab4`. On resume, verify a clean synchronized tree and run a
  fresh no-network Qwen/AkashML preflight before considering at most one
  materially changed paid retry.

## V3-PRIVACY-001 — Explicit privacy and retention profiles

- **Objective:** Implement `STRICT_ZDR`, explicit operator-authored frontier-retention
  consent, and synthetic-benchmark privacy profiles.
- **Acceptance criteria:** Strict ZDR is the default; consent cannot activate
  implicitly; private source never routes under weaker policy without validated
  consent; effective privacy evidence is recorded.
- **Dependencies:** `V3-SMOKE-001`.
- **Status:** `QUEUED`

## V3-OUTPUT-001 — Capability-adaptive structured output

- **Objective:** Negotiate native schema, JSON object, or validated text JSON per
  approved endpoint, with at most one syntax-only repair bound to the original.
- **Acceptance criteria:** Response-format support is not used as a global model
  filter; malformed, semantically altered, truncated, or unbound output receives no
  review credit.
- **Dependencies:** `V3-PRIVACY-001`.
- **Status:** `QUEUED`

## V3-TOKENS-001 — Endpoint-aware token budgets and context manifests

- **Objective:** Replace the fixed global byte pool with endpoint-aware input,
  reasoning, and output token planning.
- **Acceptance criteria:** Frozen endpoint limits drive a conservative usable input
  fraction and sufficient finding/coverage/summary output budgets; preflight records
  source, framework, prior-audit, graph, prompt, and requested-output allocations.
- **Dependencies:** `V3-OUTPUT-001`.
- **Status:** `QUEUED`

## V3-SHARD-001 — Deterministic coherent semantic shards

- **Objective:** Build stable shard inventories from contracts, call/state graphs,
  inheritance/proxy relationships, assets, privileges, oracles, initialization,
  cross-chain flows, and accounting dependencies.
- **Acceptance criteria:** Shards retain coherent graph boundaries, stable IDs and
  hashes, explicit overlap, risk surfaces, and complete source coverage.
- **Dependencies:** `V3-TOKENS-001`.
- **Status:** `QUEUED`

## V3-SCHEDULER-001 — Resumable seven-pass map-reduce scheduler

- **Objective:** Execute orientation, blind shard review, finding reduction,
  cross-shard integration, adversarial cross-examination, multi-lineage
  validation/falsification, and evidence-capped judgment as resumable passes.
- **Acceptance criteria:** Every request/result has stable pass/shard identity and
  durable resume state; incomplete mandatory passes cannot be represented complete.
- **Dependencies:** `V3-SHARD-001`.
- **Status:** `QUEUED`

## V3-TRUNCATION-001 — Preserve and reshard truncated responses

- **Objective:** Retain complete provisional records and metadata from truncated
  output, create deterministic smaller child shards, and retry within bounded cost.
- **Acceptance criteria:** Truncation never receives review credit by itself and
  never discards otherwise schema-valid complete finding records; findings,
  coverage, and summary channels fail independently.
- **Dependencies:** `V3-SCHEDULER-001`.
- **Status:** `QUEUED`

## V3-COVERAGE-001 — Risk-tiered feasible surface coverage

- **Objective:** Assign T0–T3 surface risk, calculate independent lineage
  requirements, issue compact gap-fill tasks, and preflight mathematical/cost
  feasibility before paid work.
- **Acceptance criteria:** Critical surfaces receive the configured independent
  substantive reviews; missing mandatory coverage blocks completion; no exact
  all-surface response requirement makes the gate impossible.
- **Dependencies:** `V3-TRUNCATION-001`.
- **Status:** `QUEUED`

## V3-CONSENSUS-001 — Independent cross-examination and adjudication

- **Objective:** Apply blind discovery, adversarial cross-examination, multiple
  independent validators/falsifiers, and evidence-capped deterministic judgment.
- **Acceptance criteria:** A single verifier cannot suppress a candidate group;
  model agreement alone cannot confirm; high/critical decisions satisfy lineage and
  evidence constraints.
- **Dependencies:** `V3-COVERAGE-001`.
- **Status:** `QUEUED`

## V3-FLOOR-001 — Honest minimum analysis floor and run status

- **Objective:** Derive `COMPLETE`, `DEGRADED`, `INCOMPLETE`, or `FAILED` only from
  real completed analysis and feasible risk-tier coverage.
- **Acceptance criteria:** Zero scanners plus zero completed model roles is non-zero
  exit and never a completed no-findings report; infeasible surface gates fail or
  downgrade before spend.
- **Dependencies:** `V3-CONSENSUS-001`.
- **Status:** `QUEUED`

## V3-REPORT-001 — Client report and forensic evidence bundle

- **Objective:** Produce a concise branded client report with inline excerpts and a
  separately hash-bound forensic bundle.
- **Acceptance criteria:** Confirmed, supported, disputed, inconclusive, rejected,
  complete-no-findings, and incomplete-no-findings report-quality cases pass;
  dissent and limitations are prominent; large coverage tables stay forensic.
- **Dependencies:** `V3-FLOOR-001`.
- **Status:** `QUEUED`

## V3-SCOPE-001 — Honest Solidity/EVM product profile

- **Objective:** Define the immediate product as a maximum-assurance Solidity/EVM
  security auditor and provide a reduced generic-source-review plugin boundary.
- **Acceptance criteria:** Language mismatch is detected; non-Solidity runs cannot
  claim EVM assurance; README and CLI claims match actual capability.
- **Dependencies:** `V3-REPORT-001`.
- **Status:** `QUEUED`

## V3-QUALIFY-001 — Real staged model qualification

- **Objective:** Discover, preflight, benchmark, qualify, and freeze all eligible
  high-quality exact models and independently reviewed root lineages within the
  aggregate USD 250 cap.
- **Acceptance criteria:** Staged funnel, atomic reservations, exact identities,
  endpoint/privacy eligibility, non-empty benchmark dimensions, frozen selection,
  actual cost, and rejection reasons are recorded; no model self-qualifies.
- **Dependencies:** `V3-SCOPE-001`.
- **Status:** `QUEUED`

## V3-SINGLE-AUDIT-001 — Real sharded single-model audit

- **Objective:** Complete a resumable multi-shard audit against a medium synthetic
  or licensed public Solidity fixture using one exact identity-bound model.
- **Acceptance criteria:** Multiple coherent shards complete; findings and coverage
  remain independently valid; no batch is discarded solely by coverage formatting;
  cost and runtime reconcile.
- **Dependencies:** `V3-QUALIFY-001`.
- **Status:** `QUEUED`

## V3-MULTI-AUDIT-001 — Real sharded multi-model audit

- **Objective:** Complete a real multi-model Solidity audit with whole-protocol,
  specialist, cross-examination, validation, consensus, client report, and forensic
  evidence.
- **Acceptance criteria:** At least four independently qualified root lineages are
  used for the multi-model run; critical-surface and validator coverage is real,
  substantive, and non-zero; all costs and resumable artifacts reconcile.
- **Dependencies:** `V3-SINGLE-AUDIT-001`.
- **Status:** `QUEUED`

## V3-MUTATION-001 — Complete the security mutation portfolio

- **Objective:** Finish all eleven required source-local mutation classes and run a
  real property-class kill score in disposable copies.
- **Acceptance criteria:** Mutations apply, compile, execute, restore, and score
  without fixture recognition or hidden aggregation; mandatory critical classes
  meet the configured gate.
- **Dependencies:** `V3-MULTI-AUDIT-001`.
- **Status:** `QUEUED`

## V3-BYTECODE-001 — Independently bind reproduction runtime bytecode

- **Objective:** Compare deployed runtime bytecode with compiled audited source,
  including compiler settings, libraries, immutables, and metadata.
- **Acceptance criteria:** A mismatch blocks reproduction credit and is explicit;
  matching evidence is independently hash-bound.
- **Dependencies:** `V3-MUTATION-001`.
- **Status:** `QUEUED`

## V3-ENGINES-001 — Real engines, isolation, replay, and containment

- **Objective:** Execute every mandatory available engine plus digest-pinned rootless
  isolation, isolated replay, and the adversarial containment suite; preserve exact
  blockers for unavailable prerequisites.
- **Acceptance criteria:** Foundry, Slither, Echidna, Medusa, Halmos, a formal
  engine, isolation, and replay are distinguishable from mocks and include
  executable/version/hash/target/runtime/result evidence.
- **Dependencies:** `V3-BYTECODE-001`.
- **Status:** `QUEUED`

## V3-BENCHMARK-001 — Blind product benchmark reports

- **Objective:** Run mmaudit end-to-end before revealing ground truth for
  `economic_erc4626` and `maximum_assurance_protocol`, then score product reports.
- **Acceptance criteria:** Required recall, precision, safe-control, location,
  reachability, review, reproduction, cost, and runtime denominators are non-zero;
  release gates and a current certificate pass without fixture recognition.
- **Dependencies:** `V3-ENGINES-001`.
- **Status:** `QUEUED`

## V3-CERTIFICATE-001 — Current product benchmark certificate

- **Objective:** Bind non-zero blind product benchmark metrics, exact model
  selection, prompts, schemas, tools, isolation, configuration, source, and
  candidate commit into a current fail-closed certificate.
- **Acceptance criteria:** Stale, malformed, zero-report, wrong-commit, wrong-model,
  wrong-config, wrong-toolchain, or wrong-isolation evidence fails.
- **Dependencies:** `V3-BENCHMARK-001`.
- **Status:** `QUEUED`

## V3-ADR-001 — Choose the supported CLI product release

- **Objective:** After the engine passes its real gates, document the supported CLI
  workflow and explicitly defer a self-service service until separately built.
- **Acceptance criteria:** ADR covers install, doctor/preflight, model discovery,
  single-command configuration, artifacts, reproducibility, and operator support;
  no SaaS claim is made.
- **Dependencies:** `V3-CERTIFICATE-001`.
- **Status:** `QUEUED`

## V3-RELEASE-001 — Candidate release and independent handoff

- **Objective:** Finish candidate-bound EVAL-010 generation/validation, validate the
  exact candidate, artifacts, claims, budget, real runtime evidence, and
  independent-evaluation handoff, then commit and push via SSH.
- **Acceptance criteria:** Full validation passes; release status is evidence-derived;
  all remaining external prerequisites are explicit; superiority remains
  `NOT_DEMONSTRATED` absent independent blind human comparison.
- **Dependencies:** `V3-ADR-001`.
- **Status:** `QUEUED`
