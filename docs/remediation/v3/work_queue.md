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
- **Status:** `COMPLETE`
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
- **Ninth runtime attempt:** From clean synchronized checkpoint `c86bae5`, one
  Qwen/AkashML response completed structured and non-truncated but failed closed
  after seven observations. Generation metadata's normalized token pair was
  `211/19`; its native pair was `256/29`, exactly matching completion usage.
  The private rejection is self-hashed and non-creditable, cost reconciled at
  `0.00006484 USD`, and no success artifact exists.
- **Local token-basis correction:** A pre-fix regression reproduced the observed
  rejection. Reconciliation now accepts completion usage only when one whole
  normalized or complete native prompt/completion pair matches; mixed, partial,
  and unmatched pairs remain typed, retry-bounded failures. Native reasoning and
  cache bounds use their native parent counts when present. The focused
  generation, rejection-artifact, and gated-provider slice passes `159` tests
  with the paid test explicitly skipped; affected Ruff and strict mypy pass.
- **Independent review:** No production blocker was found. Added terminal
  unmatched-pair exhaustion, reverse mixed/partial, and native-bound negative
  coverage identified by the reviewer.
- **Complete local gate:** Ruff format/check, configured strict mypy over `129`
  source files, release-schema drift verification, and the full suite passed,
  ending with `1950 passed, 10 skipped in 227.81s`. Final diff, untracked-file,
  and secret-pattern checks passed with no generated artifact drift.
- **Validated implementation checkpoint:** Commit `0ff4918` contains the atomic
  token-basis correction and complete regression matrix.
- **Attempt-ten no-network preflight:** From clean synchronized checkpoint
  `a36302c`, exact Qwen/AkashML allowlists, `STRICT_ZDR`, the pinned fixture, a
  fresh private output, and the nine-entry terminal ledger validated. Spend is
  `0.0032767225 USD`, reserved is zero, and remaining budget is
  `249.9967232775 USD`. Only secret-file metadata was checked; no secret content
  or network endpoint was accessed.
- **Tenth runtime attempt:** From clean synchronized launch checkpoint `d473305`,
  the exact Qwen/AkashML response completed, schema-validated, stopped normally,
  and reconciled against independently re-fetched generation evidence through
  one complete native token pair. The explicitly gated integration passed
  `1` test in `13.73s`.
- **Successful durable evidence:** Private artifact
  `v3-smoke-qwen-akash-success-20260728-attempt10.json` is mode `0600`,
  single-link, self-hashed, descriptor-safe, and success-only in its attempt
  namespace. File SHA-256 is
  `a49573826590c928902507a0ccc1d54be9c776a6dd9d5afd914384f4e7ef8674`;
  evidence SHA-256 is
  `cb32ca347acafc219a7bf66b28c26d7dc87898463769a9368ac248db066d4dcf`.
  It records exact/canonical Qwen identity, `akashml/fp8`, provider `AkashML`,
  `CANONICAL_MODEL_AND_ENDPOINT_BOUND`, `finish=stop`, strict ZDR, no fallback,
  and no raw prompt or response.
- **Runtime accounting:** Completion usage is `256` prompt, `29` completion,
  zero reasoning, zero cached tokens; latency is `829 ms`. Actual and accounted
  cost are both `0.00006484 USD`. The ten-entry ledger is fully terminal with
  `0.0033415625 USD` spent, zero reserved, and `249.9966584375 USD` remaining.
- **Acceptance:** Typed readback, self-hash, fixture binding, ledger totals,
  success-only namespace, and source/path/credential/authorization canary checks
  passed. No unbound response was credited. All ticket criteria are satisfied.
- **Next action:** None; continue with `V3-PRIVACY-001`.

## V3-PRIVACY-001 — Explicit privacy and retention profiles

- **Objective:** Implement `STRICT_ZDR`, explicit operator-authored frontier-retention
  consent, and synthetic-benchmark privacy profiles.
- **Acceptance criteria:** Strict ZDR is the default; consent cannot activate
  implicitly; private source never routes under weaker policy without validated
  consent; effective privacy evidence is recorded.
- **Dependencies:** `V3-SMOKE-001`.
- **Status:** `COMPLETE`
- **Implementation:** Strict ZDR is the fail-closed default. Non-ZDR private-source
  routing requires a descriptor-safe, self-hashed, source/model/provider/budget/
  expiry-bound consent observation and its live process-local capability.
  Synthetic egress requires exact committed or package-pinned source provenance.
  Paid routes revalidate immutable effective-policy evidence before reservation
  and again immediately before transport; no implicit, stale, mismatched, or
  profile-less route receives execution credit.
- **Evidence:** Effective policy and source provenance are bound through usage,
  final report, metadata, and current-schema manifest validation. The combined
  focused privacy suite passed `679` tests; all initially exposed legacy-fixture
  groups passed `405`; Ruff, strict mypy over `135` source files, schema
  synchronization, and diff checks passed; the complete suite passed `2092`
  tests with `10` explicit prerequisite skips in `236.21s`. Clean-commit
  source-mode proof returned `DISTRIBUTION_COMMITTED_SYNTHETIC` bound to
  implementation checkpoint `4da4fa08b66d0ebd04a2a8ae7d3bd181e140db33`.
  No network, paid provider call, or operator secret access occurred.
- **Validated implementation checkpoint:**
  `4da4fa08b66d0ebd04a2a8ae7d3bd181e140db33`.
- **Remaining limitation:** Ordinary API-key metadata cannot independently prove
  account-level ZDR guardrail state. Public benchmark classification remains
  unavailable until independent publication provenance is implemented.
- **Next action:** None; on operator resume continue with `V3-OUTPUT-001`.

## V3-OUTPUT-001 — Capability-adaptive structured output

- **Objective:** Negotiate native schema, JSON object, or validated text JSON per
  approved endpoint, with at most one syntax-only repair bound to the original.
- **Acceptance criteria:** Response-format support is not used as a global model
  filter; malformed, semantically altered, truncated, or unbound output receives no
  review credit.
- **Dependencies:** `V3-PRIVACY-001`.
- **Files expected to change:** `src/mmaudit/models/openrouter.py`,
  `src/mmaudit/models/endpoint_snapshots.py`,
  `src/mmaudit/models/candidate_benchmark.py`, typed model/evidence schemas,
  and focused unit/integration regressions.
- **Status:** `COMPLETE`
- **Evidence:** Exact endpoint/model capability negotiation selects native JSON
  Schema, JSON object, or validated text JSON; strict local decoding rejects
  malformed, duplicated, non-finite, coercible, omitted, unexpected, truncated,
  unbound, or capability-drifted responses without review credit. One
  syntax-envelope-only repair is hash-bound and non-creditable. Exact output
  mode/capability evidence survives discovery, request, usage, qualification,
  public runtime projection, and run-manifest serialization. The broad matrix
  passed `1096` tests; Ruff, strict mypy over `137` source files, schema
  synchronization, and the complete suite passed, ending with `2206 passed,
  10 skipped in 272.93s`.
- **Remaining limitation:** JSON-object and validated-text modes are proven by
  deterministic local fake-provider execution, not a new paid provider call.
- **Next action:** Continue with `V3-TOKENS-001`.

## V3-TOKENS-001 — Endpoint-aware token budgets and context manifests

- **Objective:** Replace the fixed global byte pool with endpoint-aware input,
  reasoning, and output token planning.
- **Acceptance criteria:** Frozen endpoint limits drive a conservative usable input
  fraction and sufficient finding/coverage/summary output budgets; preflight records
  source, framework, prior-audit, graph, prompt, and requested-output allocations.
- **Dependencies:** `V3-OUTPUT-001`.
- **Files expected to change:** Context construction and orchestration budget
  models, endpoint-derived request planning, typed run/context evidence, and
  focused unit/local integration regressions.
- **Status:** `COMPLETE`
- **Evidence:** Frozen exact-route endpoint metadata now drives conservative
  65–75% usable-input planning, explicit 32,768-token maximum-assurance output
  and workflow floors, source/framework/graph/scanner/invariant/workflow/output
  allocations, typed omissions, hash-only diagnostic preflight evidence, and
  planned-versus-provider token reconciliation. Dynamic verifier, judge,
  cross-examination, reproduction, falsification, and report-quality workflows
  are prepared and exact-bound before context allocation; JSON escaping and
  context capacity are iteratively validated before transport. Independent
  closure review found no material blocker. Ruff, strict mypy over 139 source
  files, schema synchronization, and the complete local suite passed, ending
  with `2367 passed, 10 skipped in 329.08s` on the final post-closure tree.
- **Remaining limitation:** This ticket proves local deterministic and
  fake-provider execution only. Indivisible oversized logical blocks remain
  typed omissions and make a requested-surface context fail before transport
  pending semantic sharding. No new paid provider call or real audit is claimed.
- **Next action:** None; continue with promoted `V3-FLOOR-001`.

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
- **Dependencies:** `V3-TOKENS-001` under the operator-authored revised
  sequencing; the original `V3-CONSENSUS-001` ordering is superseded for this
  minimum-floor defect.
- **Status:** `COMPLETE`
- **Evidence:** Typed report schema `1.2` cross-binds the evidence-derived run
  state to source ingestion, AST-backed compilation, qualifying REAL static
  analysis, structurally creditable REAL model roles, non-empty coverage
  denominators, surface feasibility, required quality gates, and the
  maximum-assurance assessment. Zero qualifying scanners plus zero completed
  model roles now returns a non-zero exit and prominent incomplete no-findings
  wording. Infeasible required scope or model-surface assignments stop before
  provider transport unless a lower profile is explicitly authorized and
  feasible. The final local gate passed Ruff, strict mypy over `140` source
  files, release-schema synchronization, diff integrity, and `2397` tests with
  `10` explicit external-prerequisite skips.
- **Remaining limitation:** The deterministic decision logic and negative
  regressions use synthetic typed evidence and fake transports; they do not
  claim a new provider call, real scanner execution, hardened isolation, or a
  completed real audit.
- **Next action:** On operator resume, begin `V3-FORKSUITE-001` under the revised
  engine-and-execution-evidence track.

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

# Operator-added scope — appended out of band

These tickets were appended by the operator while `V3-TOKENS-001` was mid-implementation.
Do not interrupt or re-plan the ticket in progress. Finish `V3-TOKENS-001` to its normal
standard — green Ruff, strict mypy, full suite, worklog entry, validated checkpoint — and
only then read this section and continue with the revised sequencing at the end.

Every ticket below inherits the existing safety model without exception: no live-chain
writes, no wallet or private-key material, no signing or broadcasting, no execution of
model-generated commands, and all dynamic execution isolated, bounded, and local. If a
capability appears to require weakening any of those, mark it `BLOCKED_SAFETY` and record
why rather than relaxing the boundary.

**Motivating gap.** `[scanners.foundry_fork]` defaults to `enabled = false` with
`foundry_match_path = "test/audit/*.t.sol"`. Essentially no client repository has a
`test/audit/` directory, so on a real target that glob matches nothing and the adapter
contributes no evidence. `[reproduction]` runs only on candidates a model has already
proposed. Therefore deterministic execution can currently confirm or falsify a finding but
can never originate one. Operator evidence: a CI fork-test run on a separate repository
surfaced defects that nine prior review passes had missed. Real deployed-dependency
behaviour, real token semantics, real oracle values, real liquidity, and real chain state
are invisible to source review by construction.

## V3-FORKSUITE-001 — Execute the audited repository's own suite against pinned fork state

- **Objective:** Execute the audited repository's existing Foundry suite, and its
  container-isolated Hardhat suite, against operator-pinned fork state, treating failing,
  reverting, or assertion-violating tests as deterministic finding evidence rather than only
  as candidate reproduction.
- **Acceptance criteria:** Suite selection is explicit, bounded, and configurable via
  include/exclude globs with per-test and total ceilings, and the default does not silently
  execute every repository test. The legacy `test/audit/*.t.sol` behaviour survives as one
  selectable profile and is no longer the only reachable path. Execution requires hardened
  isolation; `ffi` is force-disabled, `fs_permissions` denied, repository-supplied Foundry or
  Hardhat options that would re-enable either are rejected, wallet and private-key
  environment variables are absent, and network is denied except the configured loopback fork
  RPC. Hardhat suites execute only inside the digest-pinned rootless container against a
  disposable copy. Each executed test records project, path, test name, fork chain and block,
  seed, status, revert or assertion detail, duration, output hash, and command hash. A
  failing test produces a typed finding whose evidence strength reflects real execution; a
  passing suite is never represented as evidence of safety. Missing toolchain, isolation, or
  RPC is `unavailable`, never a pass.
- **Files expected to change:** `src/mmaudit/scanners/foundry.py`,
  `src/mmaudit/solidity/projects.py`, `src/mmaudit/isolation/container.py`,
  `src/mmaudit/config.py`, `src/mmaudit/orchestration/pipeline.py`, scanner and finding
  schemas, `mmaudit.example.toml`, unit and local integration regressions.
- **Dependencies:** `V3-TOKENS-001`.
- **Status:** `PARTIAL`
- **Validated result:** The Foundry path is complete for the bounded pinned-fork
  scope: compiler-backed inherited-test inventory, exact selection, hardened
  loopback-only execution, per-test evidence, typed findings, cumulative output
  ceilings, source/replay identity, and fail-closed prerequisite handling have
  real local integration evidence. The final local gate passed `2645` tests with
  `11` explicit unavailable external-prerequisite skips.
- **Blocked subtask:** Real Hardhat execution is `BLOCKED_TECHNICAL`. The current
  adapter safely validates configuration, selection, and reporter evidence but
  cannot execute repository JavaScript or receive REAL credit until the
  process-attested digest-pinned rootless single-loopback runtime and trusted
  image-baked reporter described in `operator_prerequisites.md` are supplied.
- **Next action:** Continue the independent Foundry-capable
  `V3-FORKDIFF-001` work. Resume only the Hardhat integration subtask when its
  external isolation and toolchain prerequisites exist; do not substitute a
  mock or broad-network container.

## V3-FORKDIFF-001 — Differential and multi-state fork matrix

- **Objective:** Run the selected suite against a clean local chain and against each
  operator-pinned fork state, and classify per-test divergence. A test that passes locally
  and fails against pinned real state is the highest-signal class this engine can produce.
- **Acceptance criteria:** At least two execution states are supported — clean local chain,
  and one or more pinned fork blocks or chains. Divergence is a distinct typed
  classification, separate from outright failure. A divergence claim requires agreeing
  repeated executions in fresh disposable workspaces; a single observation is
  `inconclusive`. Seeds, block numbers, and chain IDs are pinned and recorded, and a run is
  reproducible from the emitted manifest. Fork RPC reads are declared explicitly as a
  read-only egress boundary in the report and in privacy evidence; the audited code never
  transacts.
- **Files expected to change:** fork execution and result schemas, comparison logic,
  reporting, regressions.
- **Dependencies:** `V3-FORKSUITE-001`.
- **Status:** `COMPLETE`
- **Evidence:** The matrix supports one clean state and bounded operator-pinned
  states with repeated fresh-workspace execution, typed divergence, exact
  seed/chain/block/policy identity, read-only scoped RPC evidence, aggregate
  cleanup, manifest serialization, and trust-first default replay. Process-local
  inventory self-hashes, RPC multiplicity/order, clean-process identities, and
  cleanup measurements project to stable semantics only after their complete raw
  evidence validates. The real local clean-Anvil-versus-pinned-Anvil/Foundry
  integration passed direct execution and default manifest-bound replay (`1
  passed in 20.00s`); the focused gate passed `574` tests; Ruff, strict mypy,
  release schemas, diff checks, and the full suite passed, ending with `2992
  passed, 10` explicit prerequisite skips.
- **Next action:** None; continue with dependency-free `V3-FIXTURE-001`, then use
  its realistic-scale corpus to complete `V3-OMISSION-001`.

## V3-EXECORIGIN-001 — Execution-originated candidates

- **Objective:** Allow deterministic execution evidence to originate a candidate group and
  enter consensus, instead of only confirming or falsifying a model-proposed candidate. This
  is the architectural change behind the operator observation that a fork test caught what
  nine review passes did not.
- **Acceptance criteria:** An execution-originated group carries execution provenance, is
  location-validated against real source, and is never attributed to a model. Such a group
  may be sent to model roles for impact, exploitability, and remediation analysis without
  those roles being able to create, delete, or re-locate it. Model agreement alone still
  cannot confirm it; deterministic execution evidence is what supports it. It is never
  silently merged into an unrelated model-proposed group, and grouping still requires the
  existing similarity and location constraints. Reports distinguish execution-originated from
  review-originated findings.
- **Files expected to change:** `src/mmaudit/orchestration/consensus.py`,
  `src/mmaudit/orchestration/pipeline.py`, candidate and finding schemas, reporting,
  regressions.
- **Dependencies:** `V3-FORKDIFF-001`.
- **Status:** `QUEUED`

## V3-TESTQUALITY-001 — Audited-suite coverage and assertion strength

- **Objective:** Measure the audited repository's own test suite — coverage over indexed
  entities and mutation kill score using the existing portfolio — and emit weakly tested or
  weakly asserted critical surfaces as prioritized model review targets and as reportable
  coverage gaps.
- **Acceptance criteria:** Coverage is reported with concrete denominators over indexed
  contracts and functions. A critical surface with no assertion coverage is reported as a gap
  with its exact source location, not as a vulnerability. Mutation execution happens only in
  disposable copies and restores cleanly. Uncovered critical surfaces raise review priority
  for the model roles.
- **Files expected to change:** `src/mmaudit/benchmark/mutations.py`,
  `src/mmaudit/solidity/coverage.py`, `src/mmaudit/orchestration/model_coverage.py`,
  reporting, regressions.
- **Dependencies:** `V3-EXECORIGIN-001`; reuse `V3-MUTATION-001` work where already built.
- **Status:** `QUEUED`

## V3-CI-001 — Continuous integration execution mode

- **Objective:** Provide a first-class CI path with incremental changed-since
  prioritization, deterministic and fork-suite execution on pull requests without exposing
  provider secrets to pull-request-controlled code, SARIF upload, and resumable state.
- **Acceptance criteria:** Pull-request events never receive the provider secret and never
  execute model roles. Fork-suite execution on pull-request code runs only inside hardened
  isolation and fails closed when isolation is unavailable. Incremental runs reuse prior
  deterministic evidence only when bound source hashes still match. Job status distinguishes
  new findings, unchanged findings, and coverage regressions.
- **Files expected to change:** `src/mmaudit/cli.py`, `.github/workflows/mmaudit.yml`,
  orchestration resume state, documentation, regressions.
- **Dependencies:** `V3-FORKSUITE-001`.
- **Status:** `QUEUED`

## V3-CALIBRATE-001 — Evidence-derived qualification thresholds

- **Objective:** Replace the aspirational all-dimension `1.0` policy with thresholds derived
  from measurement, so qualification is a meaningful filter rather than an unreachable gate.
  `config/models.maximum-assurance.toml` currently requires `minimum_score = 1.0` across 17
  dimensions and 50 cases with `tier_a_minimum_overall_score = 1.0`, and the disposition enum
  offers only `TIER_A`, `NOT_QUALIFIED`, and `INCONCLUSIVE`. As frozen, `V3-QUALIFY-001` will
  spend budget and qualify nothing.
- **Acceptance criteria:** A calibration mode runs the frozen corpus against candidate models
  and records observed per-dimension pass distributions without asserting a disposition. The
  resulting policy keeps `1.0` only where determinism is genuinely required — for example
  structured-output compliance, exact source location, and prompt-injection resistance — and
  sets measured, statistically meaningful thresholds elsewhere. No judgment dimension retains
  a two-case `1.0` gate where a single miss forces `0.5`. A role-scoped secondary disposition
  exists, so a model may qualify for investigator roles without qualifying as verifier,
  falsifier, or judge. The revised policy is frozen and hash-pinned before any paid
  qualification, and the rationale for every threshold is recorded. No model self-qualifies,
  and the existing independent verification requirement is unchanged.
- **Files expected to change:** `config/models.maximum-assurance.toml`,
  `src/mmaudit/models/qualification.py`, `src/mmaudit/models/qualification_workflow.py`,
  benchmark corpus, regressions.
- **Dependencies:** `V3-TOKENS-001`. Must precede `V3-QUALIFY-001`.
- **Status:** `QUEUED`

## V3-LINEAGE-001 — Operator root-lineage review record

- **Objective:** Perform and record the independent root-lineage review that
  `privacy.approved_model_lineages` requires, so source egress is not blocked for every
  candidate. The list is currently empty and is a hard fail-closed gate in six call sites;
  all twelve candidates carry `lineage_review.status = "pending"`.
- **Acceptance criteria:** Each candidate carries a dated operator review, rationale, and
  evidence hash. Approved root lineages are committed. Distinct vendor aliases of one root
  model do not count as independent lineages. An unreviewed or rejected lineage remains
  fail-closed at every existing call site.
- **Files expected to change:** `config/models.candidates.toml`, operator configuration,
  lineage evidence artifacts, regressions.
- **Dependencies:** None beyond current `HEAD`; this is an operator judgment task and can be
  recorded at any clean boundary.
- **Status:** `QUEUED`

## V3-INTAKE-001 — Untrusted client repository intake

- **Objective:** Support third-party client repositories as untrusted input with an explicit
  per-audit authorization record, rather than assuming operator-owned source. This amends the
  `AGENTS.md` scope boundary, which currently assumes operator ownership.
- **Acceptance criteria:** A signed client authorization and scope attestation exists per
  audit. Intake validates size, structure, and shape, and rejects unsupported input. Secrets
  detected in client source fail closed with a client-safe message. Per-tenant isolation
  prevents any cross-tenant artifact access. An unauthorized or out-of-scope target is
  refused and recorded.
- **Dependencies:** `V3-RELEASE-001`.
- **Status:** `QUEUED`

## V3-CONSENT-001 — Per-client privacy and retention consent

- **Objective:** Make the client the consenting party for non-ZDR frontier routing. The
  consent implemented by `V3-PRIVACY-001` is operator-authored and bound to one source, model
  set, budget, and expiry; a self-serve product must capture equivalent consent per client at
  purchase.
- **Acceptance criteria:** Consent is bound to that client's exact source, model and provider
  set, budget, and expiry. Declining consent selects the strict-ZDR model set, and the report
  states the reduced ensemble and its effect on assurance. Consent never activates
  implicitly. Effective policy is recorded in that client's evidence.
- **Dependencies:** `V3-INTAKE-001`.
- **Status:** `QUEUED`

## V3-SERVICE-001 — Service boundary and multi-tenant accounting

- **Objective:** Provide the service layer the CLI does not have: job submission and status,
  durable artifact storage, authentication, billing hooks, and per-tenant cost accounting.
- **Acceptance criteria:** Concurrent audits for distinct tenants cannot interfere. The cost
  ledger is per-tenant and atomic under concurrency; the current design is a single
  operator-owned JSON file with one lock file and will not hold under concurrent client runs.
  A failed or partial run is never billable as a completed audit. Artifact retention and
  deletion are explicit.
- **Dependencies:** `V3-CONSENT-001`.
- **Status:** `QUEUED`

## V3-EFFORT-001 — Per-role reasoning effort and test-time compute

- **Objective:** Make reasoning effort a per-role, qualified, recorded parameter instead of
  one global setting. `[models.reasoning]` is currently a single `ModelReasoningConfig` for
  the entire run, so the judge, falsifier, and blind false-negative hunter receive exactly
  the same test-time compute as a cheap classification pass. On this task, reasoning effort
  is likely the highest quality-per-dollar control available and it is currently flat.
- **Acceptance criteria:** Effort and reasoning-token budgets are configurable per base role
  and per specialist role, bounded by the endpoint's frozen capability evidence. Effort is
  never silently raised above what the approved endpoint supports or what the budget
  preflight reserved. Effective per-role effort is recorded in usage, run manifest, and
  report evidence. Qualification measures each candidate at the effort level it will actually
  run at; an effort level not covered by qualification evidence is not selectable in
  production. Cost reservation accounts for reasoning tokens explicitly.
- **Files expected to change:** `src/mmaudit/config.py`, `src/mmaudit/models/openrouter.py`,
  `src/mmaudit/orchestration/budgets.py`, `src/mmaudit/models/qualification.py`, usage and
  run-evidence schemas, `mmaudit.example.toml`, regressions.
- **Dependencies:** `V3-TOKENS-001`.
- **Status:** `QUEUED`

## V3-RETRIEVAL-001 — Bounded read-only retrieval loop

- **Objective:** Allow a review role to request specific already-indexed, already-redacted
  entities on demand, instead of receiving one pushed context slice and being unable to ask
  anything further. Context is currently push-only and single-shot; `openrouter.py` hard
  rejects any response containing `tool_calls` or `function_call`. A reviewer that cannot ask
  a follow-up question is guessing at every boundary of its slice, and sharding does not
  change this because shards are still pushed.
- **Acceptance criteria:** The retrieval vocabulary is a fixed, typed, read-only allowlist
  over the existing symbol index and graphs — for example resolve an entity by ID, list
  callers of an entity, list writers of a state variable, fetch a validated source range.
  There is no free-form path, glob, shell, filesystem, or network capability. A request for
  an unindexed, redacted, secret-bearing, or out-of-scope subject is refused and recorded.
  Requests are bounded per role by count and by token budget, and exhaustion degrades to the
  current single-shot behaviour rather than failing the run. Every request and response is
  hashed into the run manifest so the exchange is replayable. Retrieved content is subject to
  the same redaction and egress rules as pushed context. `src/mmaudit/prompts/
  shared_security_rules.md` is amended deliberately to distinguish prohibited execution from
  permitted validated index lookup; the prohibition on claiming to have executed anything is
  unchanged.
- **Files expected to change:** `src/mmaudit/models/openrouter.py`,
  `src/mmaudit/orchestration/context.py`, `src/mmaudit/solidity/retrieval.py`,
  `src/mmaudit/agents/base.py`, prompts, run-evidence schemas, regressions.
- **Dependencies:** `V3-SCHEDULER-001`.
- **Status:** `QUEUED`

## V3-TAXONOMY-001 — Known-issue taxonomy with mandatory disposition

- **Objective:** Add a versioned taxonomy of known vulnerability classes, bound to the
  detected protocol profile, where every applicable item must receive an explicit
  `REVIEWED`, `NOT_APPLICABLE`, or `GAP` disposition with cited evidence. Surface coverage
  answers "was this code looked at"; this answers "was this failure mode considered", which
  location coverage structurally cannot.
- **Acceptance criteria:** The taxonomy is a committed, versioned, hash-pinned artifact with
  a published schema, and is defensive classification only — no exploit procedures. Profile
  detection selects applicable items deterministically; applicability is evidence-backed, not
  model-asserted. Every applicable item carries a disposition and a citation; an omitted item
  is a `GAP`, never an implicit pass. Dispositions are reported as a coverage denominator
  alongside surface coverage. A `GAP` on a critical class blocks `COMPLETE` under maximum
  assurance. Taxonomy items cannot themselves create findings.
- **Files expected to change:** new taxonomy corpus and schema,
  `src/mmaudit/orchestration/model_coverage.py`, `src/mmaudit/solidity/economics.py`,
  reporting, regressions.
- **Dependencies:** `V3-COVERAGE-001`.
- **Status:** `QUEUED`

## V3-ENSEMBLE-001 — Measure whether the specialist ensemble beats concentrated compute

- **Objective:** Determine empirically whether 25 narrow specialists across several mid-tier
  lineages actually outperforms a small number of passes by one strong model at high
  reasoning effort. This is currently assumed, not measured, and it determines unit
  economics, latency, and the specialist architecture itself.
- **Acceptance criteria:** At least three configurations are scored on identical corpora with
  identical scoring — full specialist ensemble, a reduced ensemble, and concentrated
  repeated passes by the single strongest qualified model. Recall, precision, safe-control
  false confirmation, location accuracy, cost, and wall-clock are reported per configuration.
  Findings unique to each configuration are enumerated, so complementarity is visible rather
  than only aggregate score. The result is recorded as evidence and the specialist
  architecture is explicitly retained, reduced, or restructured on that basis.
- **Files expected to change:** `src/mmaudit/benchmark/engine.py`,
  `src/mmaudit/benchmark/model_portfolio.py`, evaluation artifacts, regressions.
- **Dependencies:** `V3-CALIBRATE-001`, `V3-EFFORT-001`.
- **Status:** `QUEUED`

## V3-TIMESPLIT-001 — Public time-split benchmark and private holdout

- **Objective:** Build a credible external evidence base. The current corpus is 28
  self-authored synthetic cases with `public_real_world_time_split: false`,
  `private_holdout: false`, and `identical_commit_human_comparison: false`. Self-authored
  synthetic fixtures are the weakest available evidence and are vulnerable to fixture
  recognition.
- **Acceptance criteria:** A time-split corpus is assembled from public protocols with public
  source and published post-incident or published-audit findings, each evaluated at a commit
  that predates the fix, with provenance, licence, and commit recorded per case. A private
  holdout is withheld from all prompt, template, taxonomy, and configuration development and
  is used only for final measurement. Corpus construction records who selected each case and
  on what basis, so selection bias is auditable. Scores are reported separately for
  synthetic, public time-split, and holdout; a synthetic score is never presented as product
  performance. Cases whose source is unavailable under an acceptable licence are excluded and
  recorded, not approximated.
- **Files expected to change:** `benchmarks/`, corpus schemas,
  `src/mmaudit/benchmark/claims.py`, evaluation documentation, regressions.
- **Dependencies:** `V3-SINGLE-AUDIT-001`.
- **Status:** `QUEUED`

## V3-HUMANCMP-001 — Independent blind human comparison

- **Objective:** Perform the independent blind human-auditor comparison that every existing
  superiority statement is conditioned on. `V3-RELEASE-001` states that superiority remains
  `NOT_DEMONSTRATED` absent this comparison, and no ticket currently performs it, so the
  claim can never be substantiated by the queue as written.
- **Acceptance criteria:** Two or more independent qualified human auditors review the same
  target at the same commit, blind to the tool's output and to each other. Finding sets are
  compared by an adjudicator who is independent of both. Results report agreement, tool-only
  findings, human-only findings, and false positives on both sides. Any published comparative
  claim is bound to the exact commit, corpus, model selection, configuration, and date, and
  expires. A result that does not support superiority is recorded and published internally
  with the same weight as one that does.
- **Files expected to change:** evaluation artifacts, `src/mmaudit/benchmark/claims.py`,
  claim-discipline documentation.
- **Dependencies:** `V3-TIMESPLIT-001`.
- **Status:** `QUEUED`

## V3-STABILITY-001 — Run-to-run stability measurement

- **Objective:** Measure and publish the variance of the audit itself. Model sampling is
  non-deterministic, so a client running the same audit twice may receive different findings;
  for a paid deliverable that is a credibility problem, and instability is also a useful
  signal for where the ensemble is weak.
- **Acceptance criteria:** A fixed target is audited N times under identical configuration
  and the finding-set jitter is reported — stable findings, intermittent findings, and
  single-run findings. Stability is reported per severity and per role. Intermittent
  high-severity findings are surfaced as an explicit quality signal rather than averaged
  away. The measured stability figure is published alongside recall and precision, and the
  client report states the expected variance honestly.
- **Files expected to change:** `src/mmaudit/benchmark/engine.py`, evaluation artifacts,
  reporting, regressions.
- **Dependencies:** `V3-MULTI-AUDIT-001`.
- **Status:** `QUEUED`

## V3-QUOTE-001 — Pre-purchase cost and runtime estimate

- **Objective:** Produce a bounded cost and wall-clock estimate for a target before any paid
  work begins, so a self-serve purchase can be priced. Budget preflight exists, but there is
  no quote a buyer can be shown before committing.
- **Acceptance criteria:** The estimate derives from deterministic local analysis only —
  repository size, indexed entities, shard count, planned roles, and frozen endpoint pricing
  — and requires no provider spend. It is a bounded range with an explicit worst case, never
  a point estimate presented as certain. The accepted quote binds the run's hard budget
  ceiling. Actual cost is reconciled against the quote after the run and the delta is
  recorded so estimation accuracy can be measured over time. A target the engine cannot
  bound is refused rather than quoted optimistically.
- **Files expected to change:** `src/mmaudit/cli.py`, `src/mmaudit/orchestration/budgets.py`,
  quote schema, regressions.
- **Dependencies:** `V3-SHARD-001`.
- **Status:** `QUEUED`

## V3-LIFECYCLE-001 — Finding lifecycle and triage state across runs

- **Objective:** Give findings durable identity and triage state across repeated runs, which
  a continuous or subscription product requires. The `[prior_audit]` corpus is a one-shot
  comparison input, not a lifecycle.
- **Acceptance criteria:** A finding retains a stable identity across runs where its bound
  source range still matches, and identity changes are explicit when the source moves.
  Client triage state — accepted, won't-fix, false positive, remediated — persists across
  runs with the recording party and timestamp. Suppression is bound to source content, so a
  refactor that materially changes the code re-raises the finding rather than silently
  inheriting a stale suppression. Suppressed findings remain in the forensic bundle even when
  omitted from the client report. Triage state can never upgrade a status or manufacture a
  finding.
- **Files expected to change:** `src/mmaudit/orchestration/prior_audit.py`,
  `src/mmaudit/orchestration/consensus.py`, finding schemas, reporting, regressions.
- **Dependencies:** `V3-CI-001`, `V3-REPORT-001`.
- **Status:** `QUEUED`

## V3-REVERIFY-001 — Remediation verification runs

- **Objective:** Productize verification of client fixes as a distinct run mode. Most of the
  mechanism exists in remediated-hash comparison; it is not exposed as a deliverable.
- **Acceptance criteria:** A verification run takes a prior audit's findings and the client's
  updated source and reports, per finding, whether the remediation is verified, unverified,
  regressed, or source-inconclusive. Where a generated harness or fork test originally
  demonstrated the issue, the same bounded execution is re-run against the fix, and a
  now-passing test is reported as evidence of remediation for that specific property only,
  never as evidence of general safety. New findings introduced by the fix are reported as new
  findings. A verification run is never represented as a full audit.
- **Files expected to change:** `src/mmaudit/cli.py`,
  `src/mmaudit/orchestration/prior_audit.py`, reproduction re-execution, reporting,
  regressions.
- **Dependencies:** `V3-LIFECYCLE-001`.
- **Status:** `QUEUED`

## V3-OMISSION-001 — Bound the omission ledger and restore graceful degradation

- **Priority:** Blocking. Take this at the next clean ticket boundary. In committed `HEAD`,
  no Solidity repository above roughly 5,000 lines can complete context construction for any
  specialist role, so no real-size protocol can be audited even once a model is qualified.
- **Objective:** Stop the forensic omission ledger from consuming the byte budget it exists
  to document, and restore bounded degradation in place of a hard failure.
- **Observed defect:** `ContextBuilder.build` raises
  `ContextBudgetError: serialized metadata for role specialist:access_control exceeds its
  256000-byte allocation` on any Solidity tree above about 200 KB. Specialist role caps in
  `SPECIALIST_ROLE_REGISTRY` are 192–256 KB, so every specialist role fails.
  `build_context` converts that into `terminal_code = INCOMPLETE` with `budget_halted =
  True`, and with `V3-FLOOR-001` now correctly enforcing the analysis floor the run produces
  no audit at all. Previous behaviour on the same inputs was partial coverage, not failure.
- **Measured evidence:** One synthetic 40-contract, 14,800-line, 548,790-byte Solidity tree,
  role `specialist:access_control`, varying only `requested_budget`:

  | budget | source delivered | omission records | omission bytes |
  |---:|---:|---:|---:|
  | 600,000 | 548,790 | 0 | 2 |
  | 500,000 | 411,596 | 223 | 59,664 |
  | 400,000 | 233,237 | 536 | 143,479 |
  | 256,000 | — | — | `ContextBudgetError` |

  At a 400,000-byte budget, 36 per cent of the whole allocation is spent recording what was
  omitted rather than carrying source.
- **Root cause:** The failure is self-reinforcing. `chunk_limit = min(48_000,
  remaining_source_bytes, max(1, budget - used))` shrinks as `used` approaches `budget`.
  Every remaining logical block then emits a `LOGICAL_BLOCK_EXCEEDS_LIMIT` omission carrying
  three SHA-256 digests, roughly 250 bytes per record. Those records are counted in
  `render_context`, so the ledger tightens the budget, which shrinks `chunk_limit`, which
  emits more records. The recovery loop at `context.py:1123` removes only `package.excerpts`
  and never omissions, so it strips all source and still exceeds the cap, then raises.
- **Acceptance criteria:**
  - The omission ledger is bounded. Aggregate by category and reason with counts and
    representative samples rather than one hashed record per excluded block; per-record
    digests are retained only up to an explicit cap, and truncation of the ledger itself is
    stated in the ledger.
  - Forensic omission accounting is not charged against the analysis budget it documents.
    Either exclude it from the package byte budget and carry it in the run manifest, or
    reserve a separate bounded allocation for it that cannot grow into source capacity.
  - The recovery loop degrades rather than raises: it reduces omission detail before source,
    and a package that cannot fit its metadata returns the largest valid bounded package with
    an explicit limitation, not `ContextBudgetError`. Raising remains correct only when no
    valid bounded package exists at all.
  - Byte caps in `SPECIALIST_ROLE_REGISTRY` are reconciled with
    `maximum_source_tokens_per_request`; a token ceiling implying about 600 KB of source
    while the package cap is 192–256 KB is an inconsistency, and whichever bound is intended
    to govern must be the one enforced.
  - Regressions cover realistic scale, not only the existing small fixtures: context
    construction succeeds and reports honest partial coverage at approximately 5,000, 15,000
    and 35,000 lines, and the omission ledger stays within its declared bound at every size.
  - No coverage denominator, gate, or report ever counts omitted source as reviewed.
- **Principle to record:** Forensic completeness must never be charged against analysis
  capacity. Evidence about what was not reviewed cannot be allowed to displace the source
  that would have been reviewed.
- **Files expected to change:** `src/mmaudit/orchestration/context.py`,
  `src/mmaudit/agents/specialists.py`, `src/mmaudit/orchestration/context_manifest.py`,
  context omission and manifest schemas, `tests/unit/test_context.py`,
  `tests/unit/test_context_manifest.py`, new realistic-scale regressions.
- **Dependencies:** `V3-FORKSUITE-001` may finish first; do not interrupt it.
- **Status:** `QUEUED`

## V3-FIXTURE-001 — Realistic-scale Solidity fixtures

- **Objective:** Provide synthetic Solidity fixtures at realistic protocol scale so that
  budget, sharding, coverage, token-planning, and execution work is exercised at the sizes
  real targets actually have.
- **Rationale:** The largest committed Solidity fixture is 300 lines and the entire fixture
  corpus is about 5,000 lines, so the whole suite passes while `V3-OMISSION-001` blocks every
  real-size repository. Scale-dependent defects are currently invisible to the test suite by
  construction.
- **Acceptance criteria:** Fixtures exist at approximately 5,000, 15,000 and 35,000 lines
  with plausible protocol structure — multiple contracts, inheritance, proxies, external
  calls, asset flows and privileged entry points — so index, graph and coverage paths are
  genuinely exercised. Fixtures remain synthetic, non-deployable, credential-free and
  deterministic, and carry no copied production source. Generation is scripted and
  reproducible so sizes can be regenerated rather than hand-maintained. Slow, large-scale
  tests are marked so they can be selected separately from the fast suite. At least one
  fixture is wired into context-budget, sharding and coverage regressions.
- **Files expected to change:** `tests/fixtures/solidity/`, fixture generation script,
  `tests/` selection markers, affected regressions.
- **Dependencies:** None; can be built alongside `V3-OMISSION-001` and is required by its
  acceptance criteria.
- **Status:** `PARTIAL`
- **Evidence:** A deterministic scripted corpus now provides independent 4,952,
  15,116, and 35,444-line synthetic Foundry roots with plausible inheritance,
  proxy, external-call, asset-flow, oracle, initializer, state-write, and
  privilege structures. All contracts are deliberately non-deployable. Golden
  manifests bind all `196` generated files and three source-tree hashes. Marked
  scale regressions exercise repository discovery, fallback indexing, semantic
  graph construction, coverage, and context planning; a conditional real
  `solc 0.8.30` integration proved AST-backed inheritance for the 5k root. The
  complete suite passed `3005` tests with `11` explicit prerequisite skips and
  the two exact `V3-OMISSION-001` expected reds.
- **Remaining acceptance gap:** No semantic-sharding implementation exists yet,
  so the acceptance item requiring a scale fixture to be consumed by a real
  sharding regression remains uncredited. `V3-SHARD-001` must consume this
  corpus before this ticket can become `COMPLETE`.
- **Next action:** Operator-requested pause boundary. On resume, begin
  `V3-OMISSION-001`; revisit this ticket when `V3-SHARD-001` implements the
  missing semantic-sharding regression.

## Revised sequencing

Three tracks are largely independent and should not be run as one strict chain. The
execution-evidence track needs no model qualification and no provider spend. The benchmark
track needs no sharding. Only the model track is gated on qualification. Running them
sequentially adds months for no engineering reason; the one-ticket-at-a-time discipline
still applies within a track.

**Track 1 — engine and execution evidence**

1. `V3-TOKENS-001` — `COMPLETE`.
2. `V3-FLOOR-001` — `COMPLETE`. Verified independently: the previously false-clean
   scanner-only run now exits `6`, reports `RUN STATUS: INCOMPLETE`, and names the failed
   `minimum_analysis_floor` gate.
3. `V3-FORKSUITE-001` — in progress; finish it, do not interrupt.
4. `V3-OMISSION-001` with `V3-FIXTURE-001` — **take these next.** Until they land, no
   Solidity repository above roughly 5,000 lines can complete context construction for any
   specialist role, so every downstream ticket in this track is being validated only against
   toy-sized inputs. `V3-FIXTURE-001` is what makes the defect visible to the suite at all.
5. `V3-FORKDIFF-001`, `V3-EXECORIGIN-001`, `V3-TESTQUALITY-001`.
6. `V3-CI-001`.
7. `V3-SHARD-001`, `V3-SCHEDULER-001`, `V3-TRUNCATION-001`, `V3-COVERAGE-001`,
   `V3-TAXONOMY-001`, `V3-CONSENSUS-001`, `V3-REPORT-001`, `V3-SCOPE-001`.
8. `V3-RETRIEVAL-001`.

**Track 2 — model selection and quality**

1. `V3-LINEAGE-001` — operator judgment, cheap, unblocks egress; can be recorded immediately.
2. `V3-EFFORT-001` — small, and likely the largest quality gain per line of code available.
3. `V3-CALIBRATE-001`, then `V3-QUALIFY-001`.
4. `V3-SINGLE-AUDIT-001`, `V3-MULTI-AUDIT-001`.
5. `V3-ENSEMBLE-001` — settle the specialist architecture on measured evidence before
   committing to its cost and latency.

**Track 3 — evidence, claims, and product**

1. `V3-TIMESPLIT-001`, then `V3-HUMANCMP-001`. These gate every quality claim and are the
   binding constraint on the commercial objective, not on the engineering.
2. `V3-STABILITY-001`.
3. Remaining existing tickets through `V3-RELEASE-001`.
4. `V3-QUOTE-001`, `V3-LIFECYCLE-001`, `V3-REVERIFY-001`.
5. `V3-INTAKE-001`, `V3-CONSENT-001`, `V3-SERVICE-001`.

**Deferrals.** `V3-BYTECODE-001` and the parts of `V3-CERTIFICATE-001` that bind toolchain
and isolation evidence lose nothing by moving after `V3-MULTI-AUDIT-001`. The evidence
apparatus is a genuine differentiator, but its marginal value is close to zero until the
engine demonstrably finds real defects. Effort spent proving in detail that the engine found
nothing is effort not spent making it find something.

## Operator decisions required

Record these in the worklog as explicit operator inputs rather than inferring them.

- Which fork states are canonical — chain IDs and pinned block numbers — and which archive
  RPC provider is approved for read-only forking.
- Whether product scope stays Solidity/EVM per `V3-SCOPE-001`, or whether non-Solidity
  targets need coverage and gate parity rather than a reduced review mode. Quality gates
  currently return early for any repository with no Solidity project.
- Whether `V3-ADR-001` is amended to a self-serve product, and if so whether frontier
  retention consent is offered to clients as a tier or refused in favour of strict ZDR.
  `V3-ADR-001` currently defers a self-service offering and makes no SaaS claim, which
  conflicts with the operator's stated intent.
- Which public protocols and incidents are acceptable sources for the `V3-TIMESPLIT-001`
  corpus, under which licences, and who selects them. Selection must be recorded because the
  chooser can bias the result.
- Which independent auditors are commissioned for `V3-HUMANCMP-001`, who adjudicates, and
  the prior commitment to publish an unfavourable result on the same terms as a favourable
  one.
- The product liability posture: what the audit promises, what it disclaims, whether
  professional indemnity cover is carried, and how a missed critical finding is handled
  commercially. This is an operator and legal decision, not an engineering ticket, but it
  determines permitted report and marketing language and should be settled before the first
  external sale.
