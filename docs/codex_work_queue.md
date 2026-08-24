# Codex Defensive Engineering Queue

This queue decomposes the maximum-assurance roadmap into independently testable
work units. It is a planning artifact, not evidence that a capability exists.

Statuses: `QUEUED`, `IN_PROGRESS`, `COMPLETE`, `PARTIAL`,
`BLOCKED_SAFETY`, `BLOCKED_TECHNICAL`.

## Queue governance

### V3-OBJECTIVE-002 — Freeze explicit autonomous completion objective

- **Objective:** Replace the prior frozen product objective only from the operator's
  explicit target-change decision, bind the exact new bytes and SHA-256 everywhere,
  and preserve the supersession chain without silently rewriting history.
- **Files/modules:** Frozen objective, product-vision precedence, queue/worklog/runtime
  authorities, review traceability, and objective/documentation regressions.
- **Acceptance criteria:** The exact supplied text is the sole current objective;
  path, byte count, line count, and digest are deterministic; every current authority
  binds the same digest; the prior digest remains historical; drift fails closed.
- **Tests:** Objective custody, documentation/traceability status, JSON parsing, Ruff,
  and diff integrity.
- **Dependencies:** Explicit operator target-change authorization supplied on
  `2026-08-17`.
- **Status:** `COMPLETE`
- **Result:** The exact `2892`-byte, `24`-line replacement is frozen at SHA-256
  `e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15`.
  Current authorities and drift tests agree; the prior objective remains recoverable
  through its recorded Git blob and commit.
- **Next action:** Begin `V3-AUTHSEAL-001`.

### V3-AUTHSEAL-001 — Evidence-sealed reproducible autonomous authority

- **Objective:** Replace signer-dependent model authority with a non-self-authored,
  reproducible evidence capability that requires frozen ground truth, cross-lineage
  judging, and externally anchored append-only inclusion proof.
- **Files/modules:** New typed authority/seal models, corpus provenance and lineage
  collision joins, transparency-log/replay verification, consumers, schemas, and tests.
- **Acceptance criteria:** Hashes alone never authorize; same-root judging is void;
  ground truth is construction- or public-provenance bound; an exact independent
  rerun and inclusion proof are mandatory; serialized evidence cannot mint authority.
- **Tests:** Synthetic local nominal and tamper/reseal/collision/replay/log-proof
  negatives, schema drift, static checks, and focused consumer revocation.
- **Dependencies:** `V3-OBJECTIVE-002`.
- **Status:** `PARTIAL`
- **Result:** Added verifier-compiled provenance for all 24 planted synthetic cases,
  an opaque comparison-only ground-truth projection, exact candidate/judge collision
  maps, deterministic report projections, independent-replay equality, and bounded
  append-only prefix evidence. Every durable artifact is schema-fixed as
  non-authorizing. Independent review demonstrated that mock reports, caller-labeled
  judge roots, and a locally compiled checkpoint do not prove REAL cross-lineage
  execution or external publication, so the unsafe runtime issuer was removed.
- **Remaining limitation:** No authenticated REAL judge execution binds runner lineage
  to report evidence and no independently verified external transparency receipt exists.
  The frozen comparison policy now fails closed on the absent baseline, trusted clock,
  REAL execution custody, and closed campaign ledger. Existing signer-based consumers
  remain unchanged and fail closed.
- **Next action:** Begin `V3-AUTHLINEAGE-001`; keep runtime authority issuance blocked
  until separate REAL execution and external-log prerequisites exist.

### V3-BENCHSCORE-001 — Exact frozen-ground-truth scoring identity

- **Objective:** Prevent benchmark credit when a finding matches only a source range
  but not the frozen truth identity, classification, category, and one-to-one case
  assignment.
- **Files/modules:** Benchmark scorer, frozen corpus tests, generated evidence where
  required, and focused regressions.
- **Acceptance criteria:** Wrong CWE/category/classification cannot receive recall or
  precision credit; one finding cannot satisfy overlapping truth cases; safe and
  insufficient-context cases remain exact; existing corpus scores replay
  deterministically.
- **Tests:** Synthetic exact-match/near-miss/overlap regressions plus the benchmark and
  release-schema matrices.
- **Dependencies:** Provider-free portion of `V3-AUTHSEAL-001`.
- **Status:** `COMPLETE`
- **Result:** Vulnerable credit now requires an active positive classification, exact
  category, exact canonical CWE inventory, severity floor, and hash-valid location.
  A bounded deterministic maximum matching assigns each finding and vulnerable case
  at most once; safe controls remain conservative negatives. Detached evidence
  enforces the same assignment cardinality. The broad benchmark matrix passed `297`
  tests, and independent exhaustive review matched brute-force maxima for `1,440`
  small graphs.
- **Next action:** Begin `V3-AUTHVERDICT-001`.

### V3-AUTHVERDICT-001 — Frozen autonomous benchmark verdict policy

- **Objective:** Convert exact frozen-corpus scores into a deterministic pass/fail and
  cross-lineage superiority verdict without letting the evaluated process author or
  relax its own thresholds.
- **Files/modules:** Typed benchmark policy and verdict models, evidence-seal subject
  joins, generated schemas, and focused policy/replay regressions.
- **Acceptance criteria:** The objective-pinned policy fixes aggregate and per-dimension
  floors, safety/consistency requirements, baseline comparison, and budget ceiling;
  failing or unevaluable reports cannot receive a positive verdict; deterministic
  replay produces byte-identical verdict evidence; durable verdicts remain
  non-authorizing until REAL runner-lineage and external-log capabilities exist.
- **Tests:** Boundary/equality/one-below/unevaluable/baseline/replay/reseal negatives,
  schema drift, static checks, and the benchmark matrix.
- **Dependencies:** `V3-BENCHSCORE-001` and the provider-free evidence portion of
  `V3-AUTHSEAL-001`.
- **Status:** `COMPLETE`
- **Result:** Added a raw-byte- and semantic-pinned comparison policy over all `17`
  frozen benchmark dimensions, exact per-case outcomes, deterministic primary/replay
  joins, a strict `< 250 USD` closed-ledger gate, and schema-v2 evidence-subject joins.
  Detached report, score, execution, replay-identity, budget, sequence, Decimal-context,
  and ledger-width reseals fail closed. The affected benchmark matrix passed `354`
  tests and independent review found no remaining blocker/HIGH.
- **Remaining limitation:** The compiled policy deliberately records no frozen baseline
  and accepts no caller clock or runtime capability. Superiority and freshness therefore
  remain `UNEVALUABLE`; MOCK/structural REAL labels cannot authorize qualification.
- **Next action:** Begin `V3-AUTHLINEAGE-001`; authenticated runner execution cannot
  safely consume the current operator-authored root labels.

### V3-AUTHLINEAGE-001 — Externally grounded autonomous model lineage

- **Objective:** Replace caller/operator-authored root labels for the new autonomous
  authority path with exact, non-model-authored, provenance-tagged model ancestry.
- **Files/modules:** Frozen lineage provenance and opaque resolver models, conservative
  alias/root collision projection, schemas, and focused synthetic/public-origin tests.
- **Acceptance criteria:** Root lineage is derived only from a verifier-pinned
  constructed or independently verified public source; unknown, ambiguous, alias,
  or conflicting ancestry fails closed; a hash or serialized record cannot issue the
  opaque capability; existing signed lineage consumers remain unchanged.
- **Tests:** Synthetic construction/collision nominal path; public-placeholder,
  missing/extra/alias/conflict/reseal/forgery/copy/pickle negatives; schema and static
  checks.
- **Dependencies:** `V3-OBJECTIVE-002` and the provider-free provenance portion of
  `V3-AUTHSEAL-001`.
- **Status:** `PARTIAL`
- **Result:** Added a provider-free, non-authorizing synthetic construction and opaque
  PID-bound resolver. Conservative roots are derived from the exact complete group
  membership under a reserved non-deployable model namespace; unknown/provider IDs,
  conflicting ancestry, forged or serialized capabilities, same-root pairs, forked
  use, fixture drift, and public-origin placeholders fail closed. The frozen
  provenance raw SHA-256 is
  `44a916b74457b51b486ca98954fc0a1280e45187e4e20c2c048b7f597fa9bf98`,
  its semantic SHA-256 is
  `7b36005d5ee33f31db8edf056b5d2dbe035c901de70eaa7c940153e69d9acbb5`,
  and every durable authority, qualification, provider, runner, egress, completion,
  and release flag is false. The final combined matrix passed `118` tests; schema,
  Ruff, strict mypy over `185` source files, and diff gates passed, and independent
  adversarial review found no blocker/HIGH within the documented mechanism boundary.
- **Remaining limitation:** The synthetic fixture was authored during this Codex run,
  so it cannot prove non-model authorship or external provenance. No independently
  anchored public/provider ancestry, authenticated runner integration, or external
  transparency receipt exists. The opaque capability also trusts the current Python
  interpreter and imported verifier code; hostile same-interpreter reflection is
  outside this mechanism's boundary.
- **Next action:** Begin `V3-AUTHLINEAGE-PUBLIC-001`; `V3-AUTHRUNNER-001` remains
  queued behind independently anchored public lineage.

### V3-AUTHLINEAGE-PUBLIC-001 — Independently anchored public model lineage

- **Objective:** Establish conservative real-model ancestry from independently
  revalidated authoritative documentary evidence without allowing the evaluated
  process or the operator review to author roots.
- **Files/modules:** Exact-byte public-source provenance, corroboration and conflict
  evidence, frozen source pins, independent replay verifier, resolver extension,
  generated schemas, and bounded offline/public-origin regressions.
- **Acceptance criteria:** Each production model identity binds the evidence hash,
  source URL, publisher identity, retrieval timestamp, exact fetched bytes, and
  SHA-256; authority requires either two independent authoritative sources or one
  decisive primary-publisher source. The operator review is seed material only.
  Conflicts or insufficient corroboration produce `UNCONFIRMED`; those candidates are
  excluded without blocking confirmed candidates. All six negative-only non-independence
  constraints, including the four original constraints, remain explicit. Provider route identity
  and a model-lineage Sigstore/Rekor/TUF receipt are not requirements. Missing, stale, ambiguous,
  conflicting, rewritten, or self-authored evidence fails closed; no private source,
  credential, or caller root override is accepted.
- **Tests:** Exact public-evidence replay plus missing/source-swap/publisher/timestamp/
  corroboration/alias/conflict/reseal/forgery negatives, six-constraint preservation,
  partial-candidate exclusion, schema drift, and static checks.
- **Dependencies:** The mechanism-only result of `V3-AUTHLINEAGE-001` and independently
  available public publication evidence.
- **Status:** `COMPLETE`
- **Historical feasibility evidence:** Official publisher bytes provide useful genealogy seeds.
  DeepSeek's pinned commit
  `87e509a2e5a100d221c97df52c6e8be7835f0057` has raw README SHA-256
  `dffcdf358a42599945d49293a4f210dbe589141085207b76c081c9ace1f8fd74`; Google's
  Gemma revision `4d7ae4984b7db7de8f8457170b3f1a419ee76d52` identifies blob
  `742346e1fe57997c831b9065f4c54a9416021526`. The earlier route-receipt feasibility
  attempt issued no authority and is retained as historical evidence only.
- **Result:** Captured 15 bounded first-party documents (`411,429` bytes) for all 14 exact
  configured identities and compiled 16 exact nonoverlapping claims in canonical manifest SHA-256
  `6f46b3c779262cf11b0ec58b1a2fe88947cd71d7ab788734abb36cd9f96374e4` (semantic bundle
  `de2192a2eaede4a54e1b24216d5c3c51cebd63086131c20367e166dfa672a388`). Exact replay derives
  ten confirmed identities across nine roots and continues to exclude Hunyuan, Mistral, GPT-OSS,
  and Z.AI as `UNCONFIRMED`; all six conservative constraints remain negative-only. The DeepSeek V4,
  then-selected MiniMax M3, and Kimi K3 triple replays as three pairwise-independent roots, while
  DeepSeek-family and Kimi-generation variants cannot receive false independence credit. The opaque capability and
  config-ready projection resist stale, synthetic, serialized, caller-root, module-retarget,
  clock, and output-constructor substitution.
- **Validation:** The current affected provider-free matrix passed `194` tests; the release/objective
  subset passed `24`. Schema generation/verification, Ruff/format over `536` files, strict mypy
  over `202` source files, both governance JSON documents, and diff integrity passed.
- **Remaining limitation:** This is documentary identity/root authority only. Four ambiguous
  candidates are intentionally excluded; the config-ready projection is not an `AuditConfig`, and
  no provider, runner, egress, qualification, selection, seal, release, or benchmark authority was
  granted. Hostile closure/registry reflection remains outside the trusted-interpreter boundary.
- **Next action:** Begin `V3-AUTHRUNNER-001` as unblock fix #2. Keep external authority-log
  publication (#3), benchmark harness implementation, and every benchmark run queued.

### V3-AUTHLINEAGE-RECEIPT-001 — Offline public-lineage receipt verification

- **Objective:** Implement a provider-free, mechanism-only verifier for externally supplied
  Sigstore/Rekor evidence and its TUF-pinned trust state without treating local replay or a
  digest as public-lineage authority.
- **Files/modules:** Strict receipt/checkpoint/trust-root models, bounded offline verification,
  generated schema, frozen public test vectors, and focused negative regressions.
- **Acceptance criteria:** Exact source bytes, signature identity, canonical Rekor entry,
  inclusion proof, signed checkpoint, trusted TUF metadata, verification time, and any required
  witness/consistency evidence are replayed fail-closed; malformed, stale, rolled-back, swapped,
  unrelated, or locally self-authored inputs reject; every durable authority, provider, runner,
  qualification, selection, egress, completion, and release flag remains literal false.
- **Tests:** Official public mechanism vector replay plus source/signature/checkpoint/proof/TUF/
  time/witness swap and reseal negatives, schema drift, Ruff, and strict mypy.
- **Dependencies:** The mechanism-only result of `V3-AUTHLINEAGE-001` and suitable official
  public transparency-log test vectors. This optional mechanism is not a prerequisite for the
  corrected documentary `V3-AUTHLINEAGE-PUBLIC-001` authority.
- **Status:** `QUEUED`
- **Next action:** Implement only the bounded offline verification mechanism; do not bind a
  production candidate or issue an opaque lineage capability from unrelated test evidence.

### V3-TRUNCATION-001 — Preserve and reshard truncated responses

- **Objective:** Retain only complete, schema-valid provisional records from a truncated
  response, deterministically split the unfinished requested surface into smaller child shards,
  and retry under exact request and cost ceilings.
- **Files/modules:** Structured-output truncation evidence, scheduler task/shard planning and
  journal custody, usage/report projections, generated schemas, and focused fake-provider tests.
- **Acceptance criteria:** Truncation itself earns no review or coverage credit; retained finding,
  coverage, and summary channels validate independently; incomplete or ambiguous records are
  discarded; child shards exactly cover only unfinished work, remain bounded and deterministic,
  and cannot exceed retry, token, or USD limits.
- **Tests:** Complete-record retention, malformed/incomplete/duplicate record rejection, channel
  independence, child partition determinism, retry/cost exhaustion, resume/tamper, and no-credit
  regressions using local synthetic responses only.
- **Dependencies:** `V3-SCHEDULER-001` (`COMPLETE`).
- **Status:** `PARTIAL`
- **Result:** Added strict framed truncation projection, deterministic bounded child planning,
  append-only typed recovery-family custody, exact shared request/cost accounting, opaque
  promotion, and hash-only public usage/report/manifest/assurance joins. Truncation and
  unpromoted or MOCK recovery remain non-creditable. Final red-team review was `CLEAN` for
  blocker/HIGH findings after fixing the reproduced unbounded recovery-root and recovery-usage
  iterable seams. Validation passed `170` recovery tests, `678` cross-artifact/accounting/
  assurance/schema tests, `117` scheduler/status tests after the final bounds, `58`
  scheduler-model tests, `6` local pipeline integrations, the schema generator and `16` schema
  tests, plus Ruff format/check, strict mypy, and diff integrity. Terminal governance replay also
  passed strict duplicate-key parsing for both JSON ledgers and `11` product
  documentation/objective tests.
- **Remaining limitation:** The pipeline deliberately does not recover specialist roles or a
  parent projection with retained surface records, does not recursively consume a truncated
  recovery child, and has no positive full-pipeline REAL promotion test. Those paths remain
  incomplete and receive no review, coverage, floor, qualification, assurance, or completion
  credit.
- **Next action:** Begin `V3-COVERAGE-001`. Before any future `AUTHLINEAGE` work, reconcile the
  newly supplied `2026-08-18` lineage-evidence-standard correction with the existing lineage
  queue history; do not silently treat the superseded receipt assumptions as current authority.

### V3-COVERAGE-001 — Risk-tiered feasible surface coverage

- **Objective:** Assign T0–T3 surface risk, calculate independent-lineage requirements, issue
  compact gap-fill tasks, and preflight mathematical/request/token/USD feasibility before paid
  work.
- **Files/modules:** Model-review coverage and surface schemas, deterministic assignment/gap-fill
  planning, specialist responsibility evidence, scheduler/pipeline preflight, generated schemas,
  and focused local tests.
- **Acceptance criteria:** Mandatory high-risk surfaces receive their configured independent
  substantive reviews; missing mandatory coverage blocks completion; compact tasks avoid an
  impossible exact all-surface response contract; and at least 24 distinct candidate-independent
  responsibilities are actually executable on a clean target without counting aliases, retries,
  repeated calls, or conditional absences.
- **Tests:** Tier derivation, lineage requirements, compact partition conservation, request/token/
  USD boundary and one-over failures, clean-target 24-responsibility execution, no-credit aliases
  and absences, resume/tamper, generated schemas, Ruff, and strict mypy.
- **Dependencies:** `V3-TRUNCATION-001` (`PARTIAL`, with fail-closed direct recovery available).
- **Status:** `PARTIAL`
- **Result:** Implemented a versioned T0-T3 policy and independently replayed completion gate;
  deterministic distinct-root gap assignments and 32-surface compact tasks; exact provider
  context/pricing previews and nonauthorizing request/token/USD preflight evidence; private
  preflight retention with byte-stable zero-transport resume; an exact 24-role
  candidate-independent portfolio (22 investigators plus `invariant_review` and
  `report_quality`); graph-omission fail-closed classification; and trusted captured-descriptor
  preview/completion dispatch that rejects mutable client or class dispatch seams.
- **Validation:** Final root matrices passed `129` coverage tests, `42` trusted-dispatch tests,
  `29` documentation/schema tests, and `5` coverage integrations. Exact post-hardening
  integrations passed for generic fallback (`1` in `147.48s`), enabled-specialist fallback (`1`
  in `234.14s`), and compact no-duplication plus byte-identical zero-transport resume (`1` in
  `123.19s`); its focused unit/shadow slice passed `5` in `4.06s`. Ruff, strict mypy over `11`
  coverage/pipeline source files, release-schema generation/verification, and diff integrity
  passed.
- **Remaining limitation:** Aggregate preflight occurs after paid orientation and covers compact
  gap tasks only; supplemental `source_audit`/`whole_protocol` spend is excluded. There is no
  atomic all-task reservation, no clean/no-candidate full-runtime proof that all exact 24 roles
  execute, and no REAL coverage run. None of those missing paths receives completion credit.
- **Next action:** Begin corrected documentary `V3-AUTHLINEAGE-PUBLIC-001` as unblock fix #1;
  then real egress (#2), then external authority-log publication (#3). Keep benchmark harness
  implementation and every benchmark run queued until those prerequisites complete.

### V3-BENCHMARK-001 — Blind contamination-controlled benchmark harness

- **Objective:** Implement requirement R's frozen-before-truth benchmark harness and use it to
  measure real product finding power only after independently grounded lineage, authenticated real
  egress, and external append-only seal inclusion are operational.
- **Target definition:** `BEST-IN-CLASS-PROOF-protocol-2026-08-18.md`, exactly `7900` bytes and
  SHA-256 `d4097606321210f6ff432490fe517a1e2c1a727b792852528c59d262061ac4e7`.
- **Files/modules:** `benchmarks/` corpus and selection manifests; pre-registration,
  contamination, sealed-run, scoring, adjudication, and claim models; authority-log receipt joins;
  generated schemas; and bounded local regressions.
- **Acceptance criteria:**
  - Target commits, category strata, model knowledge cutoffs, prompts/configuration, scoring policy,
    and publish-regardless terms are frozen before results exist.
  - The complete report, including honestly negative output, is sealed into the independent
    external authority log before findings or ground truth become visible to the scoring process.
  - Per-target/model contamination custody covers cutoff status, holdout/private status where
    available, semantics-preserving mutation identity, a separate memorisation probe, and explicit
    adjustment/stratification; missing evidence cannot support a finding-power claim.
  - Reproducible one-to-one scoring reports severity-weighted High/Medium recall, precision and the
    complete false-positive inventory, severity calibration, distinct-class coverage, deduplication,
    independently adjudicated unique/tool-only findings, cost, and wall-clock without hiding zero
    denominators or omitted targets/categories.
  - Tier 0 establishes methodology only. Tier 1 requires at least 25 blind category-spanning
    contests on identical commits, recall at least the median human field, and precision at least
    `0.70`. Tier 2 additionally meets or exceeds the best single human firm and includes at least
    one independently adjudicated valid finding absent from the human set. Unmet tiers remain
    `NOT_DEMONSTRATED`.
- **Tests:** Provider-free manifest/order, contamination, blinded-truth, inclusion-receipt,
  one-to-one scoring, denominator, threshold, tamper/reseal, privacy, schema, Ruff, and strict-mypy
  regressions. Real benchmark execution is explicitly excluded until the dependencies complete.
- **Dependencies (strict order):** Corrected documentary public-lineage authority
  (`V3-AUTHLINEAGE-PUBLIC-001`) → authenticated real runner/egress (`V3-AUTHRUNNER-001`) →
  independently included authority log (`V3-AUTHSEAL-001`), plus `V3-TIMESPLIT-001` and
  `V3-ENGINES-001`.
- **Status:** `QUEUED`
- **Frozen-objective boundary:** The human-relative Tier 1/2 thresholds above are retained as an
  optional commercial comparison protocol, not as completion authority. The current
  synthetic/public objective requires a precommitted frozen public benchmark, cross-lineage
  automated adjudication, independent external-log inclusion, and the objective-pinned verdict
  policy; it must not wait for commissioned auditors.
- **Next action:** Documentary lineage (#1) is complete. Do not implement or execute the harness
  while authenticated REAL runner/egress (#2) and external seal inclusion (#3) remain incomplete;
  preserve this frozen acceptance contract for the downstream ticket.

### V3-HUMANCMP-001 — Independent blind human comparison

- **Objective:** Provide the external human-comparison evidence required for any Tier 2 or Tier 3
  best-in-class statement; architecture, synthetic fixtures, or cross-lineage self-evaluation may
  not substitute.
- **Files/modules:** Human-comparison population/adjudication records, claim bindings and expiry,
  evaluation artifacts, `src/mmaudit/benchmark/claims.py`, and claim-discipline documentation.
- **Acceptance criteria:**
  - Retrospective evidence uses the exact sealed population of at least 25 targets and identical
    commits, reporting both the median human field and best single firm under independent ground
    truth; tool-only findings receive no unique/0-day credit without independent validity and
    severity adjudication.
  - Prospective Tier 3 evaluates one or two novel protocols against a top independent firm in
    parallel under mutual blinding, a neutral protocol-team-plus-independent-judge panel, frozen
    target/commit/scoring/conflict terms, and a publish-regardless pre-registration.
  - Results publish agreement, human-only/tool-only findings, false positives, severity
    calibration, distinct classes, High recall, precision, cost, time, and contamination on
    favourable and unfavourable outcomes. Tier 3 requires a win or tie on High-severity recall at
    better precision and/or cost under the frozen policy; otherwise superiority remains
    `NOT_DEMONSTRATED`.
  - Claims bind exact target commits, benchmark selection, model/lineage inventory, configuration,
    pre-reveal report seals and inclusion receipts, adjudicators, dates, and expiry/revalidation.
- **Tests:** Provider-free comparison/claim binding, population identity, blind-order,
  adjudication, threshold, expiry, tamper/reseal, schema, Ruff, and strict-mypy regressions. Human
  commissioning and adjudication are external prerequisites and are never fabricated.
- **Dependencies:** Completed Tier-1-capable `V3-BENCHMARK-001` harness and its strict lineage →
  real-egress → external-log chain.
- **Status:** `QUEUED`
- **Frozen-objective disposition:** `OBJECTIVE_OUT_OF_SCOPE`. This optional commercial claim path
  remains fail-closed and may be implemented later, but commissioned auditors and human
  adjudicators are not prerequisites for the current synthetic/public completion objective.
- **Next action:** Keep queued as an optional later tier. Do not map it into current completion or
  use its absence to block the automated benchmark verdict.

### V3-AUTHRUNNER-001 — Authenticated cross-lineage runner custody

- **Objective:** Bind REAL generation, report, cost, and replay evidence to an exact
  independently grounded runner lineage before any cross-lineage verdict can issue
  runtime authority.
- **Files/modules:** Runner execution envelope, generation/report/usage joins,
  lineage-capability consumer, schemas, and focused custody/revocation tests.
- **Acceptance criteria:** Runner lineage comes only from the exact opaque public-lineage
  capability; same-root candidate/judge execution is void; MOCK or structural labels,
  serialized records, and caller roots cannot authorize; every credited execution is
  joined to authenticated generation, report, replay, and cost evidence.
- **Tests:** Provider-free custody/revocation tests followed by authorized REAL
  synthetic/public execution when all external prerequisites exist.
- **Dependencies:** Completed `V3-AUTHLINEAGE-PUBLIC-001`, existing authenticated generation
  refetch, and closed usage/report evidence.
- **Status:** `PARTIAL`
- **Historical required-provider-parameter join continuation:** Checkpoint
  `03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc`, direct child of historical clause-diagnostic
  checkpoint `3a1246daf19ffa4a772be7806bd903199634ab0b`, closes the provider-free
  required-provider-parameter construction asymmetry while retaining closed, value-free
  `STRUCTURED_OUTPUT_ROUTING` diagnostics. It is the source checkpoint that produced the operator's
  index-19 bundle; it is now the direct parent of the replay repair.
- **Bounded canonical-replay continuation:** `COMPLETE_NONAUTHORIZING` at checkpoint
  `c627f2debfa18df7d9567cd7c3300d19a9e9f5ce`, direct child of `03d6e8a`. The exact three-path
  repair removes only the call-level strict override that was propagated into nested mapping-copy
  validators, retains every model-level strict contract, requires the exact bundle type, and keeps
  exact canonical-byte equality as the coercion/noncanonical encoding boundary. A genuine synthetic
  265,244-byte sealed v1.2 bundle with two runs and four usages round-trips provider-free; coercive
  string and whitespace variants reject canonically. This is a completed local replay mechanism, not
  provider, qualification, runner, audit, benchmark, AUTHSEAL, release, or campaign authority.
- **Current checkpoint result:** Exact canonical candidate/judge v3 `NONCREDITING_SMOKE` uses an
  all-or-none immutable completion-plus-metadata receipt composite across completion retry and
  metadata polling vectors under same client/transport/task/thread/PID/ledger custody. Generic and
  RELEASE behavior retain the historical path. The four-path hotfix validates and neutralizes
  response-derived HTTPX cookie state, rejects outgoing Cookie headers, strips Set-Cookie from safe
  responses, and fails before grant/reservation/transport on unsupported CPython/private-cookie
  shapes. Historical `3a1246d` exposes the first of 35 ordered, unique, closed, value-free clause
  codes without changing boolean creditability, optional/unbound behavior, generic/RELEASE parity,
  or production call-root scope. Historical five-path `03d6e8a` captures the exact CANDIDATE/JUDGE
  `NONCREDITING_SMOKE` reasoning-identity join: disabled reasoning requires neither the evidence nor
  identity required-parameter set to contain `reasoning`; active reasoning requires evidence `reasoning` plus identity
  reasoning capability/support, while only exact CANDIDATE/JUDGE v3 smoke may omit `reasoning` from
  the identity required-parameter set. Generic/RELEASE exact equality is unchanged. Current `c627f2d`
  validation passed 95 smoke-runtime tests, 111 adjacent CLI/durable/inventory/release-schema tests,
  and the retained 789-test AUTHRUNNER matrix as separate, overlapping results. Ruff format/check,
  strict mypy over the changed source, the canonical umbrella release-schema/inventory generator,
  `pip check`, and diff integrity passed. Independent exact-byte audit found no blocker, HIGH, or
  MEDIUM. Historical `03d6e8a` retains its separate 19 request-cost-preview, 26 model-benchmark,
  overlapping 185 usage-plus-preview, and 47-root/1,073-state guard evidence.
  Historical `3a1246d` retains its independent 564-test / 47-root / 1,072-state evidence. Historical
  `68126e0` retains 785 focused
  tests, one actual pinned-HTTPX local numeric-loopback integration, and `pip check`. The last repository-wide
  suite remains
  `INCOMPLETE`, not a pass: 1,492 passed / 25 skipped / 1 failed after 3,878.41 seconds at
  `test_authenticated_runner_candidate_consumes_exact_cost_preview_inventory`; the same exact test
  fails on untouched parent `4e035a9d58b98284e7cceecf1fb844bc84e0dbe6`.
- **Current operator-reported offline result / limitation:** Operator record
  `4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251` is 115,171 bytes / 2,111
  lines. It reports that the `c627f2d` offline verifier returned the same 282,802-byte index-19
  bundle at SHA-256 `e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703`
  as `VALID / NONCREDITING / NONAUTHORIZING`, without another provider run or new spend. The closed
  four-entry run ledger remains `$0.39622262` and the global 25-entry ledger remains `$0.396223`.
  This is operator-supplied evidence for one case and an offline replay. No post-`c627f2d` provider
  call or independent authentication of the private artifact by Codex occurred. Completed real
  audits remain zero; no 24-case aggregation,
  scoring, audit-quality, calibration, qualification, benchmark, AUTHSEAL, or release result exists.
  Exact per-index costs for r10-r13/r17-r19, current reserved/remaining/aggregate counters, and the
  next unused index remain unstated and are not inferred. Broad provider compatibility and both full
  production publication rollback joins remain unexecuted. The pure-Python threat exclusions remain
  unchanged, and no runtime authority, readiness, or campaign authority exists.
- **Next action:** Preserve `c627f2d`, the operator-owned bundle, and ledger state; no operator action
  is authorized and no new index may be inferred. Take only the provider-free
  `V3-PLANCONSTRAINTS-001` slice before considering any 24-case campaign. No command is
  current.
- **Historical structured-output eligibility slice:** The first REAL smoke candidate completion proved transport-origin custody
  and exact reserve/spend reconciliation (`$0.0547272` reserved; `$0.01680888` actual), then failed
  closed because the selected DeepSeek/`novita/fp8` route lacks native `structured_outputs`. No
  bundle was published. That paid-attempt record was 54,081 bytes / 979 lines / SHA-256
  `f0c87e608633dc8ae940a977c8207d9e371b2bf683d0a91f415316273d5ac0dc`. The exact
  structured-output eligibility constraint now covers selection-plan derivation and smoke/full
  provider-free admission before any route is eligible. Local code-only checkpoint
  `68d774b2cee5fa69476b1cfea2f8172731a365c8` implements that first gate. Subsequent r7 metadata
  accepted DeepSeek/`fireworks`, rejected Tencent/`novita` at native-output admission, and then
  rejected the historical Gemma/`deepinfra/fp8` proposal because it cannot prove configured
  `effort=high`; no later completion or new spend occurred.
  Historical checkpoint `f6cc07aa5228c13a6c5c740ef0d57b550f25ec37` added the self-hashed
  `required_reasoning_effort=high` selection constraint and proposed Z.AI GLM-5.2 on
  `sail-research/fp8` as a nonauthorizing seed. Capture-source checkpoint
  `dce1c2591d62b0cfe8eef28385e3d9a8f759e3e3` enabled a fresh 17-source `$0` capture. Local
  checkpoint `331bde27c7085d4da34c7b8ec1f688f2ce1e52b3` adopts that capture in manifest raw SHA-256
  `b097a65613a07930f5c256c63065202a8998d5212a0021312a0e315ff6557b53` and semantic bundle
  `815fc0e376682f83f994ac5c21962c5f43556a78f5e736045f93a6ee81e5de0d`: 17 sources,
  16 aliases, 18 claims, 16 decisions, 12 confirmed identities across 11 roots, four unconfirmed
  identities, eight constraints, and all six directed DeepSeek/Z.AI/Moonshot independence checks.
  The plan's advisory `UNCONFIRMED` and `distinct_root_lineages_verified=false` literals remain
  unchanged and nonauthorizing; compiled lineage separately confirms the triple.

  The operator then froze PRIMARY Z.AI/`sail-research/fp8` as r8 at `$0` with registry SHA-256
  `8f3fc274390d983bde683e3039a91f7cb6ead0f4dfa9aa89caa02ecca7e9ed26`. The r7/r8/r7
  live-route gate failed safely before completion because the candidate `fireworks` and replay
  `together` routes lacked explicit completion-capacity metadata; no new spend or bundle resulted.
  Historical checkpoint `3975d2e12fd81a214b9faa1c3031c94506ab696d` requires metadata-backed
  completion limits and bound plan
  `4e6c744559b1cc49c8ede590c868df103a10402d429d5e5d02cf4f429e0f3a66`. Candidate r8 then
  froze DeepSeek/`parasail/fp8` at
  `4e08e6496952e817e39d6872684a4e69cfb05cf74374870f51c234a6513b7306`, while replay
  Kimi/`wafer` failed closed at status `-5`; no replay registry, live-route gate, completion, new
  spend, or bundle followed. Current selection-plan checkpoint
  `dcabe3128ba1aca84c3df90d8a64b1a6bc77db1d`
  binds nonauthorizing plan v1.3
  `ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f`, retaining candidate
  `parasail/fp8` and PRIMARY `sail-research/fp8` while replacing the failed replay singleton with
  sorted allowlist `modal/mxfp4`, `phala`. Exact operator choice remains mandatory; there is no
  automatic fallback. The operator explicitly selected `modal/mxfp4`, froze replay r8 at
  `75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8`, and validated r8/r8/r8
  through 15 logical GETs with at most 30 attempts, `$0`, no completion, and no output. Historical
  checkpoint `7ca15589453fbc5219da4bbda87e37da824470a7` emitted the r8 pair. Its step A then found
  overnight candidate drift. The operator re-froze candidate r9 at `$0` as
  `candidate-registry-r9.json` / `authrunner-candidate-20260822-r9`, frozen SHA-256
  `cc65071ef3723fc075b958aec4ad0180cdc99dc853d19b3a7983015f7e1c34ad`; PRIMARY and REPLAY
  r8 remained valid, and the r9/r8/r8 gate passed through 15 GETs. Paid smoke #3 stopped before
  provider completion or new spend because cumulative ledger request ID
  `authrunner.smoke.r1.candidate.primary:721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497`
  already exists. The ledger remains one reconciled `$0.01680888` entry and no bundle exists.
  At that historical boundary, operator custody was 74,562 bytes / 1,330 lines / SHA-256
  `302679f3e8e9281cdf9e0ec3d6d1d566d172cb54b389fbac607180d1f0911940`. Local checkpoint
  `9c61871502abbd19ff13278893f9c7785c5b28ba` makes a canonical positive smoke run index explicit,
  seals it through every durable layer, and rejects reused ledger namespaces provider-free. Its 385
  focused tests and independent 363-test review passed. At that historical boundary the checkpoint
  emitted corrected r9/r8/r8 A/B commands with `--smoke-run-index 2`; both commands have since run
  or been superseded and are no longer current.
  The operator next re-froze drifted candidate evidence at `$0` as
  `candidate-registry-r10.json` / `authrunner-candidate-20260823-r10`, frozen SHA-256
  `66b620665f4c8911c38b280b36b70eeab9fe4a0ae44259a608ede271f207dd5c`; PRIMARY and REPLAY r8
  remained unchanged. The immediate r10/r8/r8 gate was VALID through 15 logical GETs, but it is now
  historical route evidence, not a current freshness claim. At the prior `efab7ac` snapshot, paid
  smoke runs r1 through r9 were permanently occupied. The first four actual/accounted/status tuples
  were respectively
  `$0.01680888`/`$0.01680888`/`reconciled`, `null`/`$0.05225616`/`uncertain_accounted`,
  `$0.00554796`/`$0.00554796`/`reconciled`, and
  `$0.00537768`/`$0.00537768`/`reconciled`. Runs 5–9 are also reconciled, but the current operator
  record did not enumerate an authoritative per-index cost mapping for them. That nine-entry snapshot
  accounted `$0.10457436`, reserved `$0`, and left `$249.89542564`; none may be released, reused, or
  edited. At the pre-hotfix `48ea635` live-negative boundary, operator record SHA-256
  `7ae7a108144a3d6800b0a708dfa4d16c0f7fcba1c1bb2ceb2667f5ec1faac59b` is 102,651 bytes / 1,863
  lines. It reported thirteen ledger entries and total `$0.133173`; all were reconciled except retained
  r2, while exact per-index costs for r10–r13, reserved/remaining values, and aggregate model-call
  counts were not stated. At that boundary, indices 1–13 were occupied and 14 was the next unused
  namespace.
  Run 10 followed checkpoint `d2364f6`: an immediately preceding gate with PRIMARY re-frozen as
  `primary-judge-registry-r14.json` was operator-reported VALID, then the paid run stopped at the
  intended immutable completion-receipt cutoff with `usage_diagnostics=NONE`. That means zero codes
  from the exceptional noncrediting-smoke diagnostic, not generic creditability or authority. The
  live run confirms the candidate cutoff; complete candidate-and-judge pre-metadata-GET,
  pre-ledger-replacement, pre-origin, and pre-capability coverage remains provider-free source/test
  evidence. After checkpoint `48ea635`, both judges were re-frozen at r15 and the index-14 gate
  reported VALID, but paid launch failed safely pre-transport with `provider transport receipt cannot
  seal owned request state`. The ledger stayed unchanged, there was no provider charge or bundle,
  and index 14 was not consumed. The operator's wrapped-transport diagnosis is unverified analysis.
  No current command or authority follows. Run 3 passed token
  validation and failed later at the successful-REAL benchmark boundary, but the historical caller
  discarded its typed cause. Run 4 recorded raw provider counters
  `prompt=234`, `completion=1280`, `reasoning=1307`, `cached=0`; those values disprove a universal
  response-level reasoning-within-completion assumption for that sample, but do not prove a
  route-wide additive or same-domain convention.
  Source checkpoint `531a9d822e9989bf2eda94530e88cf55f2dd2e0d` preserves raw provider counters,
  adds a typed self-hashed full-request-plan accounting envelope for unknown inclusive/additive
  semantics, and admits that envelope only to exact owned REAL `NONCREDITING_SMOKE` custody plus
  authenticated generation reconciliation. General creditability and the full 24-case campaign
  remain fail closed. It also emits bounded closed-code smoke usage diagnostics. Runs 5–7 confirm the
  token envelope and typed `UsageValidationError` reporting work nonauthorizingly. The historical
  r5–r9 failure was `generation_metadata_unbound`: provisional exact canonical model and endpoint identity was
  downgraded to `UNBOUND` only during generation-metadata binding despite accepted exact/canonical
  aliases, Parasail, no fallback, and ZDR. An operator-side direct query found complete generation
  records but is nonauthorizing and does not distinguish timeout, validation, or reconciliation. The
  successor checkpoint `77fb4b9a0c03969a9776edf2091dc09d3b67daec` surfaces the already-sealed
  bounded closed `OpenRouterIdentityDiagnosticCode` values at that branch without retaining provider
  text, keeps case mismatch separate, and regresses the closed alternatives. Its 340-test focused
  matrix, Ruff, format, strict mypy, generator write/verify, and independent no-HIGH review passed.
  Index 9 confirms the bounded surface as
  `GENERATION_METADATA_INVALID|GENERATION_METADATA_MISSING`. Operator-side alias, timing/IO-budget,
  and live-payload-validator probes are nonauthorizing. Source inspection identified generic initial
  generation reconciliation rejecting the unknown-token convention before later special
  `NONCREDITING_SMOKE` reconciliation could run. Historical source checkpoint
  `8058e7bff88594b44aa42b8695ce5c25442ae73c` selects the special structural policy only for the
  exact owned REAL v3 unknown-token smoke case while preserving generic credit fail-closed. It also
  adds a closure-owned isolated raw GET/POST/error receipt state machine, tested for exact request,
  reservation, transport, lifecycle, one-shot, replay, cross-registry, mutation, and ledger custody.
  Production receipt dispatch was deliberately dormant and unreachable at that historical boundary:
  normal completion and metadata used their prior path. Historical operator evidence from that
  checkpoint reports v3 candidate identity
  reaches
  `CANONICAL_MODEL_AND_ENDPOINT_BOUND` / `generation_metadata_bound`, is persisted BOUND, traverses the
  high-level origin-marking path, and then fails the intrinsic strict-usage predicate; the operator
  evidence cannot independently prove the opaque origin capability and does not surface the exact
  rejecting clause. The intended candidate receipt cutoff was therefore bypassed; judge verification
  then remained before capability issuance awaiting an immutable metadata receipt. The scaffold grants no
  provider, credit, certification, runner, or release authority. Its focused provider-free matrix
  passed 458 tests. Direct-child hotfix
  `d2364f6b528f2e839fbef8b878552f95c4b92c9c` owns exactly seven paths and replaces validity-based
  classification with a closed exact candidate/judge smoke-scope classifier. Exact smoke coordinates,
  including intrinsic-invalid records, now stop before generation-metadata GET, `UsageLedger`
  replacement, owned-REAL origin marking, or generation-verification capability issuance. Strict
  rejection exposes at most one code from a closed vocabulary, while generic and RELEASE behavior
  remains in parity. Parent matrices passed 642 plus 57 tests; independent matrices passed 648 plus
  125 tests, a 3,488-case differential found zero mismatches, and review found no BLOCKER/HIGH. This
  is historical provider-free local evidence, not a live success or launch authority.
  Index 8's separate `SCHEMA_VALIDATION_FAILED` remains candidate reliability evidence rather than
  route-disqualification authority.
  At the historical `03d6e8a` generation boundary, the inventory snapshot was raw SHA-256
  `fb101900c8ef83ef49d32f25b49b7d7b841b1107c1fdb417e1e86f72935a4d26`, self-hash
  `bab10efc4a5472ce6dacddbb5133505a59a0813df9200679d34badcf6fa7072d`, discovery semantics
  `bed305fc0f024b01742d29f1229665bde283361e41e7d64f278860b1601faaf8`, and source universe
  `421e6ac9925388fc5c81baf43f4e50dda83d6c567a473a35bc2c47906c8dbb78`, with counts
  `3649/3652/3606/43/13/35/29/15` (sources/occurrences/gate sources/non-gating
  controls/source kinds/logical/unsatisfied/current-manual). The smoke schema raw SHA-256 is
  `2163642df1d0b7adf463eb04887e2027e462acdd716ec83451d76c49d80db78d`.
  The immediate pre-run-10 gate with PRIMARY r14 is historical, nonauthorizing evidence and cannot
  serve as durable launch freshness. At that historical pre-`c627f2d` boundary, command count was
  zero. Paid indices 14–16 were consumed; checkpoint `3a1246d` made index 16's exact live negative
  `STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS`, and child `03d6e8a` closed that
  construction asymmetry before producing the index-19 bundle. Its first canonical replay failed;
  current child `c627f2d` repairs that reader, and the current operator record reports the unchanged
  bundle valid/noncrediting/nonauthorizing offline without rerun or new spend. The next unused index
  remains NOT_STATED.
- **Local revocation-cascade slice:** Pushed checkpoint
  `692eb173f002818b4434b746c8801b4cbeb852e2` adds explicit PID-bound campaign and generation
  revokers, parent-to-child cascade, traceback-safe execution handoff guards, and immediate smoke
  candidate/judge generation revocation. Root passed 229 focused plus 266 adjacent tests;
  repository Ruff, format over 510 tracked Python files, strict mypy over 206 sources, schema and
  diff gates passed; independent review reported `CLEAN` with no blocker/HIGH. Source checkpoint
  `692eb173f002818b4434b746c8801b4cbeb852e2` and pushed zero-command governance checkpoint
  `02ed5bef89d094e0d0c4852e1bf73914d9960c6b` remain the implementation and historical eligibility
  bases; pushed, remote-resolved guide checkpoint
  `4bebab16bb2e36d54665918dec64429602b4f4e6` freezes the exact re-emitted adjacent A/B sequence.
  Command emission grants no execution or authority; every REAL path remains `BLOCKED_SAFETY`.
- **Result:** The provider-free same-process candidate/judge/generation/ledger and AUTHSEAL
  path, strict self-hashed nonauthorizing prepared-run/report/ledger bundle, explicit egress gate,
  pre-reservation per-attempt ceiling, callback-ledger fail-stop, and fresh-only publication are
  implemented and locally green. The durable bundle also has a bounded descriptor-safe offline
  loader and `models verify-authenticated-runner` command. A one-way PID-local runner lease,
  concurrent replay recheck, cascading child revocation, top-level negative post-revoke checks, and
  detached durable-only return snapshot are implemented. Replay remains explicitly nonauthorizing
  and uses no config, secret, provider, or ledger state.
- **Durability checkpoint 2026-08-20:** The 207-path WIP recovery checkpoint and its bounded
  scheduler follow-ups are preserved through
  `c90a1531cad6f09866bc1309a3130b5e4673214b` on
  `origin/agent/v3-wip-checkpoint`. This is durability evidence only: it changes no model-call,
  cost, audit, runner-authority, AUTHSEAL, benchmark, or release state.
- **Provider-free registry bootstrap 2026-08-20:** Added canonical nonauthorizing selection plan
  `b365a0ce5056ec1328f3f54722a97104dd25308a1cfab663d4185476165b06a7`, binding the exact staged
  ranking and lineage-review source bytes while keeping every availability, lineage, qualification,
  runner, benchmark, seal, and release claim false. `models discover` can now use that plan to
  publish a rootless, role-empty, pending registry whose runtime fields come only from one fresh
  exact discovery bundle. The stale registry remains historical and was not rewritten.
- **Provider-contract correction 2026-08-20:** OpenRouter metadata reproduced a seventh
  reasoning-effort tier, `max`, and exact endpoint tags that invalidated the first discovery
  commands. The canonical effort order now ends in `max`; the nonauthorizing selection plan is
  resealed as `e1fcfa451f7d4b352663c4c870d65fe03fbaff1745efc0350277b84194288a05` with DeepSeek
  restricted to `novita/fp8` or `together`, Qwen to `alibaba`, and Kimi to `deepinfra/bf16` or
  `together`. Fresh `-r2` metadata-only discovery commands and a secret-free
  `models authenticated-runner --preflight-only` command are frozen in
  `docs/models/model_selection.md`. Green checkpoint
  `ca4e2ddd4c85e38b808f7794f2a93ebef791109f` is verified on
  `origin/agent/v3-wip-checkpoint`; no corrected registry or REAL runner evidence is claimed.
- **Singleton discovery disposition 2026-08-20:** Operator-run metadata discovery produced exact
  rootless pending DeepSeek/`novita/fp8` and Kimi/`together` registry+discovery pairs without a
  completion or ledger spend. Qwen/`alibaba` lacked an exact-model ZDR entry, Meta Muse likewise
  had no ZDR route, and Kimi/`deepinfra/bf16` was non-operational; none is substitutable. The
  nonauthorizing plan is resealed as
  `47cd417c3aa73369da16981bbef3a3c450040e95ecf55f9af837f6a0b3edf459` with singleton selected
  routes DeepSeek/`novita/fp8`, Anthropic Claude Opus 5/`amazon-bedrock`, and Kimi/`together`.
  Existing successful r2 pairs remain bound to their original discovery evidence; only the fresh
  PRIMARY r3 pair is outstanding. Green checkpoint
  `09a6288fe39d76b6bd7d58c1e92a9989e3ea575e` is verified on
  `origin/agent/v3-wip-checkpoint`. Exact-ID public lineage for all three remains absent.
- **PRIMARY r3 disposition and r4 completion 2026-08-21:** The exact operator-supplied result log is
  retained verbatim at `docs/remediation/v3/operator_results.md`, raw SHA-256
  `3c8fc79c24615fae4f80dbbed6c86a9ddbb4b61cd0b1441ac83d2b020a1b60fd`, as nonauthorizing
  metadata. Claude Opus 5/`amazon-bedrock` failed closed before registry publication because its
  provider display name is duplicated across the exact-model endpoint inventory; the injective
  provider-identity invariant remains unchanged. Of the operator-reported viable replacements,
  MiniMax M3/`coreweave/fp4` is the only exact ID already `CONFIRMED` by the compiled documentary
  lineage manifest. The nonauthorizing selection plan is therefore resealed as
  `8899739a0a4a36bacacb17592df8263f57f94c65b96a63b69ab61ab67e455761` over singleton
  DeepSeek/`novita/fp8`, MiniMax/`coreweave/fp4`, and Kimi/`together` routes. PRIMARY r4 then
  succeeded with operator-reported frozen registry SHA-256
  `eaed67e745d448299e3aa5d58b406de065fae09813b3c6ff1c646403ca8023a1`. All three rootless,
  pending registry+discovery pairs now exist. Metadata discovery is 6 attempted / 3 succeeded / 3
  rejected; completion calls and campaign spend remain zero.
- **Lineage-only preflight and capture preparation 2026-08-21:** The exact r2/r4/r2 secret-free
  preflight accepted every non-lineage input and rejected only because DeepSeek V4 and Kimi K3
  lack compiled exact-ID roots. Two operator-staged publisher cards are exact-bound at 7,522 and
  45,261 bytes, but remain nonauthorizing because their full HTTP capture observations are absent
  and their Aug-21 bytes cannot be merged into the coherent Aug-18 journal. The compiled capture
  inventory now includes both immutable source specifications and tests bind the decisive claim
  spans. No manifest pin or lineage decision changed.
- **Capture adoption and lineage reseal 2026-08-21:** One fresh three-second capture reproduced all
  13 historical files and both staged hashes in a coherent 15-source journal. Its raw journal,
  observation set, and capture-bundle SHA-256 values are respectively
  `db08339e6d2790faef033f5695e9217a16ddf340e3787eb51863565869034712`,
  `848b1dfda5b60c6793089ed3916073d86e3a734da9dbc5a824302bec7f4b37da`, and
  `d9e46cb7c29792ab3d9b2d696bdb889a20f79338d72d628d267bb3705576f8f5`. The resealed manifest
  `6f46b3c779262cf11b0ec58b1a2fe88947cd71d7ab788734abb36cd9f96374e4` and semantic bundle
  `de2192a2eaede4a54e1b24216d5c3c51cebd63086131c20367e166dfa672a388` prove the active
  DeepSeek/MiniMax/Moonshot triple pairwise independent while preserving all six negative-only
  non-independence constraints. Only the DeepSeek-family and Kimi-generation groups are new. The
  reseal itself claimed no provider-free preflight result.
- **Provider-free r2/r4/r2 preflight 2026-08-21:** The operator subsequently reported
  `VALID / NONAUTHORIZING / NO PROVIDER EGRESS` for two runs, 24 cases, 96 logical requests, at
  most 192 provider attempts, and 96 generation refetches under effective-config SHA-256
  `f0ff2d76017dfcd075c6758f0da7256c98dd45ca749a42b81ca1ce8c95a93f9e`. The `$192.00`
  declared interval/final cap is the arithmetic result of placeholder `$1.00` attempt tripwires,
  not a derived live request cap. The operator reports no provider egress and an unchanged `$0`
  ledger. The locally verified preflight contract stops before secret selection, completion, or
  durable output publication; transient private write probes are created and removed during path
  preflight. No authority transition occurred.
- **Historical exact-cost admission slice 2026-08-21:** The then-current provider-free path derived
  two exact,
  self-hashed 24-request candidate cost plans from the retained singleton route, request, token,
  reasoning, pricing, retry, and discovery evidence. Preflight reports their plan hashes and exact
  retry-inclusive candidate interval/final caps. Judge admission is deliberately
  `PENDING_REAL_CANDIDATE_OUTPUTS`: both REAL candidate campaigns must complete before either
  candidate response can be sealed into its judge requests. The live path then refreshes and
  retains both judge routes, derives both exact 24-request judge plans, and admits their aggregate
  remaining cost below the USD 250 ledger ceiling before any judge POST. Operator-supplied manual
  per-attempt caps are additional tripwires that every exact plan must fit; they are not pricing
  evidence or substitutes for derived caps. Then-current durable output was schema v1.1 and exact-joined
  both stage plans through reports, usage, token/reasoning plans, route/pricing hashes, attempt IDs,
  and per-attempt ledger reservations. Legacy v1.0 remains readable only as historical evidence;
  the verifier refuses to label it current `VALID`. The base exact-cost implementation passed its
  486-test affected matrix, 47-test durable/CLI subset, 5,989-test terminal full-unit gate, schema,
  lint, strict-mypy, documentation, JSON, diff, and independent review gates before checkpoint
  `f6acf206f2c55eeb57b1a11fcf58cc4694a41208` (`Bind exact AUTHRUNNER request costs`). The
  17,087-byte operator-supplied log at raw SHA-256
  `3c8fc79c24615fae4f80dbbed6c86a9ddbb4b61cd0b1441ac83d2b020a1b60fd` then records that
  checkpoint's provider-free preflight failing safely at `_routing_max_price`: all three retained
  routes have nonzero `input_cache_read`, which the provider cap cannot express. The failure occurred
  before secret selection, provider egress, or reservation, and the operator reported an unchanged
  `$0` campaign ledger. The same-ticket cache-dominance fix admits `input_cache_read` only when each
  endpoint's raw cache-read price is no greater than its raw prompt price, transmits only the hard
  prompt `max_price`, and reserves both full prompt and full cache-read units at the upward-rounded
  prompt cap. Nonzero cache-write and internal-reasoning pricing remain rejected, and durable evidence
  mirrors those invariants. Root-independent and owner affected matrices each passed all 406 tests
  (the independent run in 110.81s); durable/CLI passed 47/47, execution/candidate/release passed
  71/71, schema verification, Ruff, strict mypy over 203 source files, 12 product-documentation/
  objective tests, strict governance JSON, and diff integrity passed, and independent red-team review
  passed 16 focused tests with no blocker/HIGH. The terminal frozen post-fix suite
  (`.venv/bin/pytest -q`) exited 0 with 6,230 passed, 21 skipped, and 2 warnings in 4,599.65s
  (1:16:39) under required local loopback/Unix-socket permission. The skips are explicit unavailable
  rootless, Foundry, scanner, and paid-provider prerequisites; the warnings are `os.fork`
  deprecations in two existing tests. The cache implementation is checkpointed at
  `fd1459b519ea0ce28a2d123ddeb57653dd2f7918` (`Bound OpenRouter prompt-cache pricing`) and its
  pushed governance successor is `5f35436e1ffdb2a5c8d229e79e7f4637abbb3279`; at that recorded
  validation boundary the committed-byte preflight was still pending. No model-call, governed spend,
  audit, runner-authority, AUTHSEAL, benchmark, or release counter/state changed.
- **Reasoning-profile and PRIMARY r5 preparation 2026-08-21:** The then-current 24,059-byte
  operator-supplied log at raw SHA-256
  `3af4473feac473c3ef5b7ecd553ed67dc141d6f174647e29bd2c1dc485bc609e` records that the
  `fd1459b519ea0ce28a2d123ddeb57653dd2f7918` preflight cleared the cache-price gate and then
  failed safely during candidate cost-plan derivation because configured max-token reasoning lacked
  exact frozen support. The operator reports the dedicated campaign ledger remained `$0`. The local
  correction selects `effort = "high"` with a 4,096-token reserve, prefers an exact endpoint effort
  inventory when present, and uses the frozen model-catalog inventory only when the endpoint inventory
  is absent; explicit empty inventories, missing model and endpoint evidence, parameter absence, and
  endpoint/model contradictions still fail closed. The operator-reported frozen catalog inventories
  contain `high` for DeepSeek V4 and Kimi K3; MiniMax M3 has no usable reasoning mode and is no longer
  selected. The nonauthorizing selection plan is resealed
  as `f7d8df3c4bdc584c33a9ed80e6aab49c66180f198185b8f8ccff5150467af115` with Tencent Hy3 on
  singleton `tencent/fp8` as PRIMARY r5; fresh r5 metadata is not yet present. The 16-source capture
  specification adds exact immutable Tencent card revision
  `a960ebc3da325ba167f069f76c41eb62c9280d22`, but the existing 15-source lineage bundle remains
  unchanged and Tencent is not yet confirmed. Owner matrices passed 419 and 134 tests, independent
  red-team passed 15, candidate-selection passed 10, capture preparation passed 25, root combined
  matrices passed 166 and 57, and the final combined affected matrix passed 433/433 in 45.40s;
  12 product-documentation/objective tests, schema verification, Ruff,
  strict mypy, strict governance JSON, and diff integrity passed. No terminal full-suite result is
  claimed for these new bytes. The implementation is durably checkpointed, pushed, and
  remote-verified at `9075ca7635c861194cc732e67d9ebb92e6ffa0af` (`Bind catalog reasoning and
  select Tencent`); no authority or counter changed.
- **PRIMARY r5 discovery and Tencent lineage reseal 2026-08-21:** The then-current 26,945-byte
  operator-supplied log at raw SHA-256
  `1ed1da7c47f7c595c099e5c70cfe947430db41bd7811b7b0b7ecddeb97e14ecc` records two exact
  exit-zero prerequisites after `9075ca7635c861194cc732e67d9ebb92e6ffa0af`. PRIMARY r5 discovery
  retained `tencent/hy3=tencent/fp8` in discovery manifest
  `fe3e3daa21eeb370f35558c5eca5746c140f2b92e88a37233952ab77034dc07b` and frozen registry
  `2d825234bfc1cf05fb9ec883c555bc007bd3a6033145507d629d5da7aa5619ad` without a completion
  or spend; metadata discovery now totals 7 attempted / 4 succeeded / 3 rejected. The coherent
  16-source capture produced observation-set SHA-256
  `6ae6e75a1732c05b85ffe189febbc3ecfa8ae2eeeb83000a8a24d30035b966eb` and capture-bundle
  SHA-256 `7b6ff67506bceaaf05c944edb2c28bf6d8386df3690444b827035ed5c83bc134`.
  Local exact-byte compilation and replay reseal raw manifest
  `90389d27f553d6f167a21aab364cebdb40ca5afbdbcc977d9127338ace4a3008` and semantic bundle
  `7c6dd26743733ae46aa94b7171ff2ca42f967ac8323b7f2d0aa95cf66f2dbc68`, binding 16 sources,
  421,754 bytes, 15 aliases, 17 claims, 11 confirmed identities across 10 roots, four unchanged
  unconfirmed identities, and seven negative-only constraints. Tencent Hy3 is confirmed, the
  Tencent/Hunyuan organizational constraint remains negative-only, and all six directed then-selected-triple
  independence pairs replay successfully. Implementer validation passed 176 tests; root lineage passed
  108; independent red-team passed 117, plus 22 schema and 16 runner tests. Then-current root affected
  validation passed 120/120 in 43.91s and 22 release-schema checks in 0.59s; schema verification,
  Ruff, strict mypy, strict governance JSON, and diff integrity passed. No terminal full-suite result
  is claimed. The reseal is durably checkpointed, pushed, and remote-verified at
  `a1ace778afcf308b57fe436271cdc16a2bb8e156` (`Confirm Tencent documentary lineage`). No authority
  or governed counter changed.
- **Provider-free r2/r5/r2 preflight 2026-08-21:** The then-current 29,375-byte operator-supplied log at
  raw SHA-256 `911081e8d6121896ae4edb4514855431b7024b164307e5bb808b7f4099cc85c4`
  records the exact post-`a1ace778afcf308b57fe436271cdc16a2bb8e156` preflight as
  `VALID / NONAUTHORIZING / NO PROVIDER EGRESS`. It binds two runs, 24 cases, 48 candidate and 48
  judge logical requests, 96 total logical requests, at most two attempts per request, 192 maximum
  attempts, and 96 generation refetches under effective-config SHA-256
  `42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`. Candidate plans
  `f0f367605dd75674b08c8974bf69570190e4137be46a47619c1b5b9d85c83b57` and
  `3fc6e535d22baf9bbbdafe4ccb50f9127fdb6d5c2fba7ce0463388765d2f8436` derive exact candidate
  interval and final-spend caps of USD `5.27438208`. Judge exact admission remains
  `PENDING_REAL_CANDIDATE_OUTPUTS`, and a full-campaign bound is unavailable before genuine candidate
  outputs exist. The USD `192.00` operator interval/final tripwires and USD `250.00` ledger cap remain
  backstops, not exact judge-price evidence. All three roles validated `effort = "high"`; the ledger
  remained `$0`, no completion or provider egress occurred, and no REAL or downstream authority was
  granted.
- **One-case noncrediting smoke boundary 2026-08-21:** The active ticket freezes exact parent
  case `case-df79ea132113b863` (`synthetic/C0015.sol`) in the four-file
  `benchmarks/model_corpus_smoke/` bundle. Semantic bundle SHA-256
  `721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497` binds one case, two
  candidate plus two judge logical requests, at most eight attempts, and four generation refetches.
  Every credit/authority field is literal false; the bundle is explicitly
  `NONCREDITING_SMOKE`, nonrepresentative for calibration, and unable to authorize the later full
  launch. The dedicated one-shot smoke CLI and strict offline verifier passed the 231-test affected
  matrix in 72.13s, 18 focused and 109 neighboring independent red-team tests with no blocker/HIGH,
  the combined 108-test CLI/schema matrix, repository-wide Ruff, format over 525 files, strict mypy
  over 206 sources, schema verification, and diff integrity. The implementation is pushed and
  remote-resolved at `af70559ddaf84178efffee1ec1bf7b99bf0b12df` (`Add noncrediting provider
  smoke path`). Codex did not read a secret, contact the provider, mutate the retained ledger, or
  execute a REAL command. The full 24-case REAL command remains absent and withheld.
- **Smoke preflight defect 2026-08-21:** The then-current 31,643-byte operator-supplied log at raw SHA-256
  `4f71b2ebf33037317095a1f16c64d21b102bb6229be75ae58a55158c95454e0a` records the
  provider-free smoke `--preflight-only` run after `af70559` failing safely with `smoke public lineage
  returned a non-independent projection`. Real discovery registries have `root_lineage = None`, but
  the smoke adapter compared those null values unconditionally with the genuine sealed roots. The
  full runner already checks a registry root only when non-null. No secret was selected, no provider
  egress or REAL completion occurred, the ledger remained `$0`, and the smoke REAL command is removed
  and withheld pending a narrow fix, real-registry-shape regression, new checkpoint, and successful
  provider-free preflight.
- **Null-root correction 2026-08-21:** The smoke adapter now tolerates a null registry root only for a
  `PENDING` review, while exact model IDs, sealed projected roots and bundle pins, projection type,
  `independent = true`, three-root distinctness, non-null mismatches, and `REJECTED` reviews remain
  fail-closed. Validation passed 33 focused and 81 bounded smoke/neighbor tests, Ruff/format, strict
  mypy, and diff integrity. Checkpoint `7e9db03145b4afc1834dd47e9f4f97800e1edffb` (`Fix smoke null
  lineage projection`) is pushed and remote-resolved. Guide checkpoint
  `f0a0f39ee275bc774709bd0fbff411cfa7ecac04` then froze its exact provider-free preflight.
- **Corrected smoke preflight VALID 2026-08-21:** The then-current 33,621-byte operator-supplied log at raw
  SHA-256 `33d06db3bde140204843282dda56c91704d58a054f02532ea68cfa830f618e62`
  records that exact preflight as `VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS`, with
  `$0` spend, two runs, one case, four logical requests, at most eight attempts, four generation
  refetches, and USD `8.00` arithmetic interval/final tripwires. Candidate plans
  `944343e272b05b9925a0d4c618946ffbd4742f861e792c83be423531af07ea19` and
  `b281a184b96ee208284f57de5c17adf59a9a61a72788bfb1fb5b9ac80e25dd3d` derive exact candidate
  interval/final caps of USD `0.21890352`. Judge admission remains
  `PENDING_REAL_CANDIDATE_OUTPUTS`; this remains provider-free evidence only.
- **Paid-path origin-custody blocker 2026-08-21:** Historical checkpoint
  `f5afb2bff074254ee5c4a484386ee4c416b17a88` emitted a smoke launch that a deeper local audit proved
  unsafe to run. The owned-REAL origin issuer accepts only the two `RELEASE_PINNED_*` proof kinds,
  while smoke deliberately uses the two `PINNED_NONCREDITING_SMOKE_*` kinds. After a provider response
  is charged and bound, the first completion would fail origin attestation before durable smoke
  evidence completes. No operator paid command ran; the dedicated ledger remains `$0`. Safety
  withdrawal checkpoint `ca63b924f244cc9bcee2d2405d20b000ce0bb9d6` removes both smoke commands.
  The then-current 35,771-byte operator record at SHA-256
  `612943ec6e7f138d7a85ce7f4439a5054127b385f008fb1d1af25134890ebfb9` operator-reports
  withdrawal-before-execution, zero provider completions, and a `$0` ledger; the source mismatch was
  independently source-reviewed. Smoke and
  full REAL commands are absent; the ticket remains `PARTIAL / BLOCKED_SAFETY`.
- **Origin-custody correction checkpoint 2026-08-21:** Checkpoint
  `c9a8923064ef1bb606a67b14641c4c8df55bc9ea` (`Bind smoke REAL origin custody`) is pushed and
  remote-resolved. Each of the four closed release/smoke proof kinds is now bound to its exact,
  disjoint candidate or judge request namespace before owned-REAL origin can be minted; missing,
  malformed, cross-kind, release-to-smoke, smoke-to-release, and forged mappings reject, and smoke
  custody grants no release or downstream authority. Implementer validation passed 584 provider-free
  tests. Independent validation passed 371 usage/OpenRouter, 83 runner/smoke/cross-lineage, and 123
  generation/candidate tests (577 broad tests total), followed by 22 focused usage-scope and three
  OpenRouter transport-path passes; final red-team review was clean with no blocker/HIGH. Scoped and
  repository-wide Ruff, scoped format, strict mypy over both
  changed source files and the full 206-source tree, and diff integrity passed. The whole-repository
  format check is not credited because it would rewrite a code fence in the exact operator-owned
  result bytes; no terminal full-suite result is claimed. At that correction checkpoint, the operator
  record remained 35,771 bytes at
  SHA-256 `612943ec6e7f138d7a85ce7f4439a5054127b385f008fb1d1af25134890ebfb9`, with no paid run,
  provider completion, or spend and a `$0` dedicated ledger. Only the exact provider-free one-case
  preflight is emitted; paid smoke, offline verifier, and full REAL commands remain absent.
- **Post-fix smoke preflight VALID 2026-08-21:** Implementation checkpoint
  `c9a8923064ef1bb606a67b14641c4c8df55bc9ea` remains the source correction; distinct pushed guide
  checkpoint `c137f8bae9d27f5120e7e08eba2d9b5b384e1ca5` froze the operator-visible command. The then-current
  38,352-byte, 690-line operator record at SHA-256
  `ed416745d3d0d957e05919e7cf10e14e75b4e9f3da800000e5789371520abbe2` records that exact command
  as `VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS`, with `$0` spend, two runs, one
  case, four logical requests, at most eight attempts, four generation refetches, USD `8.00`
  interval/final tripwires, exact candidate final cap USD `0.21890352`, judge admission
  `PENDING_REAL_CANDIDATE_OUTPUTS`, and unchanged effective-config SHA-256
  `42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`. The operator's code review
  agrees with the four-way namespace correction but explicitly cannot exercise the post-response
  issuer. No provider completion, spend, authority, or governed counter changed. A terminal suite
  launched before the live operator evidence and reconciliation bytes changed; it was interrupted
  after 82 passed, 13 prerequisite skips, and 1381.01 seconds and receives no pass credit.
  Paid-smoke guide/evidence checkpoint `7b2db061ceb7449674399d6133428b97b74b4b96` is pushed and
  remote-resolved and freezes the one-case command plus conditional verifier over the unchanged
  `c9a8923` implementation.
- **Paid smoke failed closed before provider request 2026-08-21:** The operator attempted the exact
  one-case command from historical checkpoint `7b2db061ceb7449674399d6133428b97b74b4b96`.
  `OpenRouterClient` construction rejected `request and atomic global input token budgets differ`
  before any provider request. The dedicated ledger remained empty at `$0`, and no bundle was
  published, so its conditional verifier has no input and was not run. The then-current 44,808-byte,
  807-line operator record has raw SHA-256
  `5b9d455d1a82c8ae70dedfb2b38ad17bcd2a881c5d3ca7a9e56bac1379cd7c19`. Both commands were
  withdrawn at that boundary;
  the full 24-case command remains absent. `V3-AUTHRUNNER-001` is `IN_PROGRESS` only for the local
  token-budget parity fix, while its REAL subtask remained `BLOCKED_SAFETY`. `V3-AUTONOMY-001`
  Phase 0 was paused before artifact adoption.
- **Token-budget parity correction 2026-08-21:** Source checkpoint
  `59f9f40a97dce41a16fb3ab9243b4d8588bcf3cb` (`Bind AUTHRUNNER token budgets`) is pushed and
  remote-resolved. Smoke and full-runner shared budgets now receive the exact configured global input
  and output token budgets and scoped cost caps. Both preflights compare every relevant shared-budget
  field before secret selection, client construction, or transport, so any construction drift fails
  provider-free. Owner and root each passed the same 136-test five-file matrix; independent review
  passed 122 tests and was `CLEAN` with no blocker/HIGH; seven focused ordering tests passed. Ruff,
  tracked-Python format over 510 files, strict mypy over 206 source files, schema verification, 12
  product-documentation/objective tests, strict governance JSON, and diff integrity passed. The
  operator ran the exact fresh provider-free preflight after this checkpoint; the then-current
  44,808-byte, 807-line record at raw SHA-256
  `5b9d455d1a82c8ae70dedfb2b38ad17bcd2a881c5d3ca7a9e56bac1379cd7c19` reports
  `VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS`, four logical requests, at most eight
  attempts, exact candidate final cap USD `0.21890352`, and `$0` spend. Its output is byte-identical
  to the pre-fix preflight and still does not construct the live `OpenRouterClient`, so it does not
  exercise that construction seam. Paid smoke, offline verifier, and full 24-case REAL commands
  were absent at that evidence boundary. Independent paid-readiness review was `SAFE` with no
  blocker/HIGH: the prior attempt reached the exact constructor at `$0`, while `59f9f40` binds both
  token budgets and every adjacent shared-budget field used by real CLI-built clients. One exact paid
  smoke command is now emitted for separate operator authorization, with one verifier strictly
  conditional on exit zero and a fresh bundle; no construct-only command or full-run command is
  emitted. No provider, secret, private ledger, completion, spend, authority, or governed counter
  changed at that boundary. `V3-AUTHRUNNER-001` returned to `PARTIAL / BLOCKED_SAFETY`;
  `V3-AUTONOMY-001` Phase 0 remained queued and paused.
- **Paid smoke #2 failed during live discovery refresh 2026-08-21:** The operator ran the exact
  post-`59f9f40` paid smoke. The token-budget mismatch was gone, but authenticated live metadata
  refresh rejected `smoke current discovery differs from its frozen exact route` before any model
  completion. The ledger remained empty at `$0` and no bundle was published, so the conditional
  verifier did not run. The then-current 44,808-byte, 807-line operator record has raw SHA-256
  `5b9d455d1a82c8ae70dedfb2b38ad17bcd2a881c5d3ca7a9e56bac1379cd7c19`.
  The operator's normalization-versus-drift analysis is advisory and used a naive recursive scan;
  root cause remains `INCONCLUSIVE` until the actual typed frozen and live objects are compared.
  Paid smoke and verifier are withdrawn again; no preflight, construct-only, metadata-refresh, or
  full command is emitted. `V3-AUTHRUNNER-001` is `IN_PROGRESS` only for this bounded local diagnosis,
  its REAL subtask remains `BLOCKED_SAFETY`, and `V3-AUTONOMY-001` Phase 0 remains queued and paused.
- **Live-route preflight proved genuine candidate drift 2026-08-21:** At pushed and remote-resolved
  source checkpoint `5e94b779f2592a2a0a46e7535de3e346310285e2`, the operator ran the bounded
  metadata-only live-route preflight against the unchanged r2/r5/r2 evidence. It failed safely at
  `$0` on candidate category `endpoint exact-model identity inventory`: the frozen DeepSeek V4-Pro
  inventory had 12 endpoints and the live inventory had 13, adding `sail-research/fp4`, while the
  selected `novita/fp8` route remained unchanged. This refutes the earlier normalization hypothesis
  and establishes genuine candidate provider drift. No model completion ran and no bundle was
  published. The gate stopped on candidate, so both judge roles remained untested. The then-current
  47,422-byte, 855-line operator record has raw SHA-256
  `074c9f16a580473ac930f48715e737b6951ddc34cde7cd951e0b24373a3fcc16`. At that evidence
  boundary, AUTHRUNNER paid, verifier, normal-preflight, fresh-discovery, and full
  commands remained absent.
  Aggregate successor `9f5c94d97b3d79d51c10e250b99244591461e959` is pushed and remote-resolved;
  owner/root each passed 164 tests, independent validation passed 237 plus seven focused tests with
  `CLEAN`/no blocker-HIGH, and Ruff/format/mypy/schema/diff gates passed. The formerly emitted
  r2/r5/r2 probe has now run and is historical. `V3-AUTONOMY-001` Phase 0 remains queued and paused.
- **Fresh r6/r6/r2 live-route preflight VALID 2026-08-21:** The aggregate probe reported candidate
  and PRIMARY whole-inventory drift and no REPLAY mismatch. The operator independently re-froze
  candidate as `candidate-registry-r6.json` / `authrunner-candidate-20260821-r6` with frozen SHA-256
  `6cd3463347e794e92831d69629a820fbdc4a6cb226ee4f2ef7daff03603117e1`, and PRIMARY as
  `primary-judge-registry-r6.json` / `authrunner-primary-judge-20260821-r6` with frozen SHA-256
  `7b2f11aed42a7d1c5c79b68339682eb21c7f57c765db0ea0d83004a717d8fa8c`; REPLAY kept r2.
  The r6/r6/r2 live-route preflight then validated all three exact routes through 15 authenticated
  logical GETs with at most 30 attempts: zero completion, zero usage, unchanged budget and atomic
  ledger, no output, unchanged effective config, and operator-reported `$0`. The then-current
  50,211-byte,
  906-line operator record has raw SHA-256
  `e7e631be16b5502f6e16b1d2aeae9ac226d8d79050263f27555f5ff8f812b0fd`. PRIMARY drifted in
  under seven hours, so discovery freshness is measured in hours.
- **Historical adjacent operator sequence after cascade 2026-08-21:** The exact source base was
  `692eb173f002818b4434b746c8801b4cbeb852e2`; pushed zero-command checkpoint
  `02ed5bef89d094e0d0c4852e1bf73914d9960c6b` is the historical eligibility state. Pushed,
  remote-resolved command-emission guide checkpoint
  `4bebab16bb2e36d54665918dec64429602b4f4e6` emits exactly two separate commands from the historical
  r6/r6/r2 sequence at
  `092a09ee94d528f67b43edb180860d45328f741f`: metadata-only step A followed by paid one-case step B.
  They must not be chained and require separate authorization. Before A, inspect an exactly empty
  ledger, absent output, and mode-`0700` operator-owned output parent. B is eligible only immediately
  after A exits `0` and its complete result exactly matches all three models, 15 logical GETs, at
  most 30 attempts, zero usage, unchanged budget/ledger, absent output, and pinned config, with no
  delay or intervening source/config/artifact/ledger/output/secret/environment change; otherwise A
  must be separately reauthorized and rerun. At that boundary both commands were emitted and had not
  yet run. The later paid attempt is the schema-validation failure recorded above; no fresh immediately
  adjacent step-A record exists. At that historical boundary no normal preflight, verifier,
  discovery, construct-only, smoke, or full command was emitted.
- **Remaining limitation:** One prior REAL `SYNTHETIC_BENCHMARK` completion was identity-`UNBOUND`
  and non-crediting. Both the historical and post-fix provider-free smoke preflights were valid and
  nonauthorizing, but neither constructed the live client. The first paid attempt exposed a mismatch
  between request and atomic global input-token budgets before provider dispatch. The local parity
  repair is checkpointed and its committed-byte provider-free smoke preflight is valid. Paid smoke #2
  proved constructor parity, and the later metadata-only live-route gate established genuine
  candidate endpoint-inventory drift. Current evidence reports outcomes through index 19 and a
  25-entry global ledger totaling `$0.396223`; the next unused index is not stated. Historical
  r14/r15/r16 cost `$0.004044`/`$0.008478`/`$0.006281`, while exact r16 terminal status, current reserved/remaining
  values, aggregate model-call/provider-completion counts, authenticated metadata GET count, route
  artifact identities/composition, and bundle publication are unstated. Run 10
  stopped at the intended immutable completion-receipt cutoff with
  `usage_diagnostics=NONE`; this live-confirms only the candidate cutoff and grants no generic
  creditability or authority. Run 3's typed
  post-validation cause is unavailable because the historical caller discarded it. Run 4 proves
  only that one raw response reported `reasoning_tokens=1307 > completion_tokens=1280`; it does not
  establish a provider-wide accounting convention. Runs 5–7 confirm the plan-bounded token envelope
  and typed usage error worked, while exposing `generation_metadata_unbound` as the next closed
  blocker at that historical r5–r9 boundary.
  The current typed envelope is deliberately smoke-only and noncrediting. The isolated transport
  receipt scaffold is not production authority. Its production issuer was dormant only at the
  historical `8058e7b` boundary; checkpoint `48ea635` later activated the exact-smoke receipt
  composite, historical child `68126e0` repaired receipt-state sealing provider-free, historical
  checkpoint `3a1246d` supplies the closed clause diagnostic without changing
  creditability truth, and historical `03d6e8a` closes the required-provider-parameter join
  provider-free without widening generic/RELEASE behavior.
  At historical checkpoint `8058e7b`, an intrinsic-invalid v3 smoke record bypassed the candidate
  cutoff, was persisted BOUND, and traversed the high-level origin-marking path before strict
  validation failed; operator evidence cannot prove the opaque origin capability. Historical
  checkpoint `d2364f6` closed that classifier bypass before metadata GET, usage replacement, origin,
  or capability. Current replay checkpoint `c627f2d` repairs the datetime asymmetry provider-free,
  and the latest operator record reports that the unchanged index-19 bundle now verifies offline as
  `VALID / NONCREDITING / NONAUTHORIZING` without another provider call or new spend. That one-case
  evidence does not establish 24-case aggregation/scoring, audit quality, calibration, qualification,
  benchmark, AUTHSEAL, release, broad provider compatibility, or either complete production
  publication rollback join. An explicit evidence-backed token-detail convention policy remains
  required rather than an inferred additive/subset rule.
  Exact judge admission and the
  full-campaign cost bound cannot exist before both genuine candidate outputs. Current repository
  rules prohibit Codex from reading real credentials or accessing the provider. Judge request bytes
  and exact caps cannot exist before both genuine
  candidate outputs, so the provider-free result intentionally supplies candidate-only admission,
  not a fabricated full-campaign bound. The authenticated runner is a one-shot, non-resumable
  same-process launch; interrupted work cannot be resumed as valid campaign evidence. The retained
  whole-inventory provider-display-name uniqueness invariant conservatively excludes otherwise viable
  routes whose regional endpoints reuse a display name; this is an explicit selection-quality
  limitation and is not relaxed for the current triple. Genuine v1.1 durable REAL evidence and a
  positive owned-REAL parent issue-consume-revoke-reject assay against the external runtime remain
  absent; the completed provider-free cascade does not substitute for that evidence. External-log
  publication and every benchmark run remain queued.
- **Next action:** Keep `V3-AUTHRUNNER-001` `PARTIAL / BLOCKED_SAFETY`. Checkpoint `48ea635` activated
  the receipt composite; historical child `68126e0` repaired the index-14 receipt-state-seal
  incompatibility provider-free; historical checkpoint `3a1246d` maps index 16's live failure to
  exact closed code `IDENTITY_REQUIRED_PROVIDER_PARAMETERS`; historical `03d6e8a` closes that
  construction asymmetry provider-free; and current `c627f2d` completes the provider-free replay
  repair. The latest operator record reports the unchanged index-19 bundle offline-valid,
  noncrediting, and nonauthorizing. No operator action is authorized, no next index is stated, and no
  command is current. Take only provider-free `V3-PLANCONSTRAINTS-001` before any campaign.
  `V3-AUTONOMY-001` Phase 2 remains paused;
  AUTHSEAL publication, audits, benchmarks, the 24-case campaign, and release remain unauthorized.

### V3-PLANCONSTRAINTS-001 — Enforce selection/runtime route-constraint parity

- **Objective:** Define one typed, self-hashed route-predicate profile and make plan construction,
  publication, provider-free qualification, and runtime admission consume the same finite predicates.
- **Files/modules:** Candidate selection and endpoint snapshots, selection-plan schemas/builders,
  provider-free route checks, runtime admission adapters, documentation, and focused parity tests.
- **Acceptance criteria:**
  - The profile covers exact model identity and endpoint tag, whole-inventory provider display-name
    injectivity, the exact operational accepted state, ZDR eligibility, and the emitted request
    parameters `max_tokens`, `temperature`, `response_format`, and `reasoning`. It separately binds
    the `structured_outputs` native-capability marker in both the exact-model inventory and the
    selected-endpoint inventory rather than treating that marker as an emitted parameter.
  - It binds singleton exact-route/no-automatic-fallback selection; the complete effective reasoning
    control and profile hashes, mode/effort and reserve; prompt/output/context capacity envelopes and
    metadata-sourced completion capacity; exact-pricing eligibility that proves the configured
    provider cap is expressible by, and no weaker than, the exact route's price bound rather than
    merely checking that a price is present; frozen-discovery/live-route equivalence; and registry
    selection/constraint hash custody. Reasoning-effort support is endpoint-first, with exact-model
    catalog fallback only under the validated endpoint-inventory-absence rule; an explicit empty or
    contradictory endpoint inventory fails closed.
  - Discovery applies the complete profile before it can publish an endpoint snapshot; validating
    only a base model or applying constraints after snapshot construction is rejected.
  - Selection-plan construction and publication use the same typed predicate implementations as
    runtime admission; no parallel hand-maintained list may silently diverge.
  - A provider-free internal diagnostic/test API returns one closed typed disposition/reason for
    every route predicate,
    and regressions fail whenever a runtime admission predicate lacks a selection representation.
  - Exact-model and selected-endpoint `structured_outputs` metadata parity is necessary but never
    proves behavioral schema reliability. Runtime schema conformance remains a separate empirical,
    fail-closed gate; intermittent run-8 nonconformance cannot be promoted into metadata authority.
  - Runtime-only token-detail reporting convention has an explicit completeness disposition. Because
    discovery exposes no authoritative same-domain inclusive/additive field and r3/r4 cannot establish
    one, it must remain typed `UNAVAILABLE` and fail closed for the 24-case campaign until a separate
    policy/evidence gate resolves it. Completing metadata parity alone cannot grant launch readiness.
- **Tests:** Provider-free profile construction, route-reason sweep, plan/runtime parity, missing-
  predicate mutation, ambiguous display identity, output-parameter, reasoning-effort precedence,
  capacity, and runtime-only convention-`UNAVAILABLE` regressions.
- **Dependencies:** The operator-reported, nonauthorizing `c627f2d` offline-valid sealed one-case
  `V3-AUTHRUNNER-001` smoke satisfies only this provider-free prerequisite; it is not independent
  bundle authentication or campaign authority. This ticket is mandatory before the 24-case campaign.
- **Status:** `QUEUED`
- **Operator proposal disposition:** Proposal item 1 is converted into this bounded ticket without
  adopting the operator-supplied direct-reference count as proof that these predicates are wholly
  runtime-only: high effort is already checked indirectly, endpoint snapshot construction already
  rejects ambiguous display names, and native-output helpers already check part of the parameter
  set. The defect is absence of one complete shared predicate profile. Proposal item 2's `models
  check` route-sweep UX remains adjacent. Item 3's REPLAY allowlist is historical; its proposed
  candidate/PRIMARY extension remains advisory and is not absorbed by the internal diagnostic/parity
  acceptance above. Item 5 is
  `ADOPTED_NONAUTHORIZING / IMPLEMENTED` by checkpoint `531a9d822e9989bf2eda94530e88cf55f2dd2e0d`:
  bounded typed successful-usage errors preserve the cause, keep case mismatch separate, and do not
  fetch generation evidence prematurely. Items 2, 3, 4, and 6 remain
  `OPERATOR_SUPPLIED_NONAUTHORIZING_ANALYSIS`; none grants command or launch authority.
- **Next action:** This queued ticket is the current actionable provider-free slice: implement it
  before authoring or launching the 24-case campaign. It authorizes no operator action, provider
  access, command, or campaign.

### V3-MODELREFRESH-001 — Provider-free model-refresh runtime and pricing custody

- **Objective:** Make persisted model-refresh evidence a narrowing, non-authorizing
  runtime veto and bind independently verified current route pricing to paid REAL
  request limits, reservations, usage evidence, recovery, and assurance.
- **Files/modules:** `src/mmaudit/models/refresh*.py`, endpoint/OpenRouter, scheduler,
  usage/report schemas, pipeline, assurance, manifest, generated schemas, focused
  refresh/pricing tests, and the V3 remediation ledgers.
- **Acceptance criteria:** Paid REAL dispatch requires the exact live technical,
  audit-selection, refresh, and pricing opaque authorities; immutable qualification
  baselines remain distinct from current price custody; every request attempt uses
  bounded exact-decimal caps and cost evidence; stale, partial, forged, swapped, or
  coherently resealed inputs fail before unauthorized reserve, recovery, credit, or
  POST; durable artifacts cannot recreate authority.
- **Tests:** Provider-free core, transport TOCTOU/mutation, scheduler create/resume,
  usage/report/manifest/assurance, schema drift, static checks, and full pytest.
- **Dependencies:** Existing opaque production qualification and audit selection;
  validated durable refresh history; independently supplied workflow pins. Stock
  CLI production issuance and real-provider evidence remain external prerequisites.
- **Status:** `PARTIAL`
- **Result:** The provider-free refresh/runtime/pricing custody slice is green. The
  final full suite passed `5392` tests with `21` explicit unavailable/opt-in skips;
  independent review found no remaining provider-free blocker or HIGH.
- **Next action:** No provider or operator action is current. Preserve the provider-free mechanism;
  the repository's current actionable slice is provider-free `V3-PLANCONSTRAINTS-001`. Resume this
  ticket only under separate future authorization with fresh exact provider evidence and the stock
  live authority quartet; do not emit or rerun an authenticated refresh command from this ticket.

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

## Product identity and reporting

### BRAND-001 — Corrovera Security identity system

- **Objective:** Provide a coherent production identity and apply it to generated
  security-assurance reports.
- **Files/modules:** `assets/brand/corrovera/`, `README.md`, package metadata,
  Markdown reporting, reporting tests.
- **Acceptance criteria:** The kit includes editable logo variants, generated master
  imagery, color and typography tokens, web/app icons, social formats, audit-report
  and business templates, usage guidance, and reproducible image prompts; generated
  Markdown reports carry the Corrovera name, tagline, and engine identity.
- **Tests:** Visual inspection; SVG/XML, HTML, JSON, PNG/ICO, exact-dimension, Ruff,
  mypy, focused reporting, full pytest, and release-evidence validation.
- **Dependencies:** None.
- **Status:** `COMPLETE`

## Independent release evaluation

### EVAL-001 — Fit-for-purpose acceptance evaluation

- **Objective:** Independently determine whether the frozen release candidate
  satisfies the operator's evidence-driven maximum-assurance product requirement,
  without changing or repairing production implementation.
- **Files/modules:** `docs/evaluation/`, queue and worklog only.
- **Acceptance criteria:** Freeze a clean source snapshot; classify every material
  requirement; distinguish real, mocked, partial, unexecuted, unavailable, and
  absent evidence; exercise safe fail-closed and local real acceptance paths; report
  required metrics and explicit fit-for-purpose, implementation, and superiority
  verdicts in all seven requested artifacts.
- **Tests:** Snapshot/hash verification, focused assurance/tool/benchmark/isolation
  execution, artifact/schema consistency, JSON parsing, and evaluation-only diff
  review.
- **Dependencies:** `RELEASE-001`.
- **Status:** `COMPLETE`

## Next action

### V3-AUTHRUNNER-001 — provider-free canonical-replay datetime continuation complete

- **Objective:** Preserve historical checkpoint `03d6e8a` and the operator-owned bundle while fixing
  the provider-free canonical-replay datetime contract without weakening strict validation or exact
  canonical byte equality; retain zero operator commands.
- **Dependencies:** Exact current operator evidence
  `4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251`, historical negative
  checkpoint `48ea635ab5a2fa778d6b5ce5c9a1592f0f27b375`, historical receipt-seal hotfix
  `68126e0fe438f853fb9b75582023f807a208bdae`, historical diagnostic checkpoint
  `3a1246daf19ffa4a772be7806bd903199634ab0b`, historical join-fix checkpoint
  `03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc`, current replay checkpoint
  `c627f2debfa18df7d9567cd7c3300d19a9e9f5ce`, and nonauthorizing plan
  `ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f`. The operator reports a
  25-entry global ledger / `$0.396223`, a complete index-19 four-entry closed run ledger /
  `$0.39622262`, and the unchanged sealed bundle offline-valid at `c627f2d` with no new spend.
- **Status:** `COMPLETE_NONAUTHORIZING` provider-free continuation within overall
  `PARTIAL / BLOCKED_SAFETY`.
- **Boundary:** Historical post-`3a1246d` operator evidence traverses receipt sealing and four earlier
  structured-output identity clauses, then paid index 16 fails at the exact closed
  `IDENTITY_REQUIRED_PROVIDER_PARAMETERS` clause. Historical `03d6e8a` produced the index-19 bundle;
  current `c627f2d` repairs replay without changing those bytes. Do not release, reuse, or edit any recorded
  ledger entry or infer unstated statuses, costs, counters, artifacts, or bundle state. The operator
  explicitly retracts its `requested_mode` hypothesis. The next unused index is NOT_STATED. No current command or provider access is
  authorized. No verifier, full runner, qualification, seal,
  audit, benchmark, or release command is emitted.
- **Current evidence:** Exact three-path replay checkpoint `c627f2d` passed 95 runtime tests, 111
  adjacent CLI/durable/inventory/release-schema tests, and the retained 789-test AUTHRUNNER matrix as
  separate overlapping results, plus Ruff, format, strict mypy, canonical generator, `pip check`,
  diff integrity, and exact-byte review with no blocker/HIGH/MEDIUM. Historical `03d6e8a` retains
  19 request-cost-preview, 26 model-benchmark, overlapping 185 usage-plus-preview, and 47-root/1,073-state
  evidence; historical `3a1246d` retains 564 tests / 47 roots / 1,072 states. The current operator
  file reports the same index-19 bundle offline-valid, noncrediting, and nonauthorizing with no rerun
  or new spend. This is not runner or release authority. `V3-AUTONOMY-001` remains
  `IN_PROGRESS`, but its Phase 2 working bytes are paused. The exact 28-role bundle pins three
  reviewed package resources and explicitly leaves 25 external roles unresolved.
- **Next action:** Preserve `c627f2d`, the operator-owned bundle, and ledger state. No operator action
  is authorized; do not infer another run index or grant runner/release authority. Begin only
  provider-free `V3-PLANCONSTRAINTS-001` before any 24-case campaign.
