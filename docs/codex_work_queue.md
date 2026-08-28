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
- **Next action:** Begin `V3-AUTHLINEAGE-001`; authenticated runner execution could not safely
  consume the then-current operator-authored root labels at that historical boundary.

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
  promotion, and hash-only public usage/report/manifest/assurance joins. Checkpoint
  `390e9b29e748e38d511da9f0a54cfc4fa1a2c0a8` additionally consumes retained-parent surface
  records only through a journal-owned PID-local opaque promotion capability: live parent/child
  usage and context custody must join the current run, the parent remains truncated and
  noncreditable as an ordinary artifact, only `PARENT_PROVISIONAL` records may receive composite
  coverage credit, children remain ordinary successful artifacts, and public promotion bindings
  must equal the live token set with ordered child-result hashes. Truncation and unpromoted,
  serialized-only, forged, ambiguous, swapped, or MOCK recovery remain non-creditable. The
  retained-parent validation passed `510` affected tests, full Ruff/format, strict mypy, canonical
  generator, dependency, import, and diff gates; independent red-team review found no remaining
  blocker/HIGH. Checkpoint `721d17a4ff08cc52ccdf0aa92ed04258e4137807` additionally admits an
  exact specialist investigator root into the same bounded direct family, binds each successful
  child to a v1.2 `SpecialistAcceptedOutcome`, and exposes only its hash in v1.1 public recovery
  evidence. Serialized outcomes remain nonauthorizing: specialist completion requires the exact
  promoted live parent/child usage identities, recovery coordinates, contexts, artifacts, and
  public hashes. The still-truncated parent is superseded in role failure accounting only by that
  live promotion; unrelated failures remain failures. MOCK recovery remains unpromoted,
  noncreditable, and byte-stable across zero-transport resume. Checkpoint
  `dcd9ab2be15f4a0416372c110734b5079af1efe2` adds exactly one provider-free recursive level for
  one generic zero-retained truncated child. Its nested family closes as v1.1 `COVERAGE_CLOSED`,
  while the ancestor closes as v1.2 `RECURSIVE_STRUCTURALLY_CLOSED_NONAUTHORIZING`; neither closure
  creates promotion, coverage, specialist, or assurance credit. Exact shared request, token, USD,
  global-ordinal, and append-order custody; max-cap refusal; zero-transport resume; and unchanged
  direct and specialist paths pass locally. Checkpoint
  `e61b7d7d168488bea8f27f40b31c4db4a0bf8386`, direct child of
  `ea85af3849db30c9832624c675594541a698ab06`, owns the exact 20-path source manifest recorded in
  the worklog and adds a distinct PID-local opaque verifier plus journal-owned promotion
  capability for the complete five-request tree. One v1.1 promotion and
  v1.1 recovered output bind the root and nested families, both closures, the superseded bridge,
  and three ordered successful leaves. Its four public v1.2 recovery requests expose exactly one
  `SUPERSEDED_TRUNCATED_BRIDGE` and three `SUCCESSFUL_LEAF` dispositions. The bridge remains
  accountable but receives no artifact, review, coverage, floor, specialist, or completion credit;
  only the three leaves retain ordinary successful-artifact credit. Coverage and assurance require
  every direct or recursive promoted composite to consume its exact parent-provisional and
  child/leaf ordinary-artifact surface partitions; a zero-retained parent needs no invented
  composite reference, and unrelated artifacts cannot substitute for either partition. Local
  synthetic usage was re-attested only to exercise the REAL-only identity predicates; it is not
  genuine provider execution. MOCK recursive recovery remains unpromoted and noncrediting and
  resumes with byte-stable zero transport. Separate overlapping validation gates passed `108`
  evidence/journal/promotion, `63` model-coverage, `244` assurance, `58` scheduler-model, `9`
  scheduler/recovery runtime, `105` scheduler-journal, `2` exact direct/recursive live synthetic,
  `1` MOCK recursive, `1` specialist direct compatibility, `4` PLAN selected-display regression,
  and `57` final inventory/schema tests. Focused consumer and independent adversarial matrices also
  passed without additive counting; Ruff/format, separate strict-mypy runs, canonical generation,
  import smoke, diff integrity, and independent no-blocker/HIGH review passed.
- **Remaining limitation:** Positive nonempty full-pipeline promotion backed by genuine provider
  execution remains unavailable. Deeper recursion, retained surfaces on the recursive bridge, and
  specialist-role recursion remain unimplemented; synthetic re-attestation and MOCK evidence are
  not provider evidence. The ticket therefore remains `PARTIAL` and grants no provider, campaign,
  completion, or release authority.
- **Current action:** Require separately authorized genuine provider-backed positive promotion and
  a terminal maximum-assurance result before completion. Do not infer a provider command or run
  index; keep deeper, retained-bridge, and specialist recursion fail closed.

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
- **Status:** `COMPLETE`
- **Result:** Implemented a versioned T0-T3 policy and independently replayed completion gate;
  deterministic distinct-root gap assignments and 32-surface compact tasks; exact provider
  context/pricing previews and nonauthorizing request/token/USD preflight evidence; private
  preflight retention with byte-stable zero-transport resume; an exact 24-role
  candidate-independent portfolio (22 investigators plus `invariant_review` and
  `report_quality`); graph-omission fail-closed classification; and trusted captured-descriptor
  preview/completion dispatch that rejects mutable client or class dispatch seams. Checkpoint
  `33001d12d62ffe54788a41ed7321a77cd9fcb05f`, direct child of
  `d6c7c5b05d8466a3793b3174809e1cd48b6a02e8`, adds a durable pre-orientation portfolio hold for
  the exact orientation, compact, `source_audit`, and `whole_protocol` attempt envelopes. The
  private preflight and one atomic request/token/USD reservation must persist before orientation
  transport; infeasibility, persistence failure, or preview drift fails before paid work. The
  scheduler journal now publishes immutable artifacts crash-safely and recovers only exact legal
  checkpoint transitions. Released pre-send truncation tails remain v1.3 `FAILED`, comparison-only,
  noncrediting, and zero-transport on resume.
- **Validation:** Separate overlapping gates passed `187` scheduler-journal, `78`
  truncation-journal, `178` wider scheduler-unit, `46` scheduler-integration, `280`
  cost-ledger/budget/usage, `82` coverage planning/resource/wiring, `33` autonomy-inventory, and
  `48` release-schema/public-projection tests. The clean no-candidate Solidity/EVM runtime executed
  exactly the 22 investigator roles plus `invariant_review` and `report_quality` (`1` pass in
  `710.96s`) while its 244-file manifest digest remained
  `634323f697cb0c8d4ed38dd04452a857c9374f5e026bc1c441122763a142198f`. A live local v1.3
  release/resume regression passed in `105.34s`. Ruff/format, strict mypy over all `210` source
  modules, canonical generation, bytecode compilation, scoped diff integrity, and independent
  no-blocker/HIGH review passed.
- **Remaining limitation:** The clean runtime and retained recovery evidence are synthetic/MOCK,
  not REAL/provider execution, and grant no qualification, campaign, benchmark, AUTHSEAL, audit,
  completion, or release authority. `V3-TRUNCATION-001` remains `PARTIAL` with its separately
  recorded provider and recursive limitations. The operator-supplied result current at this
  coverage-closure boundary recorded a provider-free `$0` authenticated-runner preflight refusing
  because the supplied
  `--qualification-policy` path was absent; that stat failure does not establish the artifact stage,
  reopen this ticket, or prove a REAL audit.
- **Historical next critical path at closure:** `V3-CALIBRATE-001` remains `BLOCKED_TECHNICAL` and
  is not reopened by this closure. The immediate missing-file remedy was `UNDETERMINED`: current C1
  pins schema-v1 P1, a
  standalone P1 bootstrap has no repository CLI materializer, and derived P2 would require a
  reviewed successor C2. The implemented legacy/optional J1-to-A/P2-to-C2-to-J2 bridge remains
  insufficient for frozen current-objective completion; precommitted constructed/public frozen
  truth, cross-lineage automated adjudication, and exact REAL calibration custody remain absent.
  Stop after recording this ticket `COMPLETE`: do not select AUTHSEAL, launch a campaign, emit a
  command, or infer a run index.
- **Current reconciliation:** The latest `2026-08-27T10:28Z` operator record reports that a private
  provider-free index-21/r21 replay satisfied `EMPIRICAL_SCHEMA_CONFORMANCE` and exposed a pre-fix
  token-detail digest mismatch. `V3-RUNTIMEADMIT-001` is now complete at its corrected provider-free
  boundary; no post-fix private replay or current FULL admission exists. This nonauthorizing record
  does not reopen the completed coverage ticket.

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
- **Latest completed AUTHRUNNER replay result:** Exact canonical candidate/judge v3
  `NONCREDITING_SMOKE` uses an
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
  the identity required-parameter set. Generic/RELEASE exact equality is unchanged. Historical
  AUTHRUNNER replay checkpoint `c627f2d`
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
- **Last reconciled operator-reported offline result / limitation:** Operator record
  `4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251` is 115,171 bytes / 2,111
  lines. It reports that the `c627f2d` offline verifier returned the same 282,802-byte index-19
  bundle at SHA-256 `e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703`
  as `VALID / NONCREDITING / NONAUTHORIZING`, without another provider run or new spend. The closed
  four-entry run ledger remains `$0.39622262` and the global 25-entry ledger remains `$0.396223`.
  This is operator-supplied evidence for one case and an offline replay. No post-`c627f2d` provider
  call or independent authentication of the private artifact by Codex occurred. Completed real
  audits remain zero; no 24-case aggregation,
  scoring, audit-quality, calibration, qualification, benchmark, AUTHSEAL, or release result exists.
  Exact per-index costs for r10-r13/r17-r19, reserved/remaining/aggregate counters in that
  last-reconciled record, and the
  next unused index remain unstated and are not inferred. The user-owned working-tree record later
  drifted during this source-only ticket and was not opened or reconciled; no conclusion or command
  in `V3-PLANCONSTRAINTS-001` depends on its new contents. Broad provider compatibility and both full
  production publication rollback joins remain unexecuted. The pure-Python threat exclusions remain
  unchanged, and no runtime authority, readiness, or campaign authority exists.
- **Next action:** Preserve `c627f2d`, the operator-owned bundle, and ledger state; no operator action
  is authorized and no new index may be inferred. `V3-PLANCONSTRAINTS-001` is complete provider-free,
  but its two runtime-only dispositions remain `UNAVAILABLE`; keep this ticket blocked and emit no
  campaign command.
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
  spend, or bundle followed. Historical selection-plan checkpoint
  `dcabe3128ba1aca84c3df90d8a64b1a6bc77db1d`
  bound nonauthorizing plan v1.3
  `ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f`, retaining candidate
  `parasail/fp8` and PRIMARY `sail-research/fp8` while replacing the failed replay singleton with
  sorted allowlist `modal/mxfp4`, `phala`. Exact operator choice remains mandatory; there is no
  automatic fallback. Current provider-free checkpoint
  `7ef471744adfce557edf612a74b2847aafb3e8bc` upgrades that selection artifact to schema v1.4 /
  plan SHA-256 `bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f`
  and binds its shared route-predicate profile and exact constraints without refreshing route
  evidence or granting authority. The operator explicitly selected `modal/mxfp4`, froze replay r8 at
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
  `$0.00537768`/`$0.00537768`/`reconciled`. Runs 5–9 are also reconciled, but that operator record
  did not enumerate an authoritative per-index cost mapping for them. That nine-entry snapshot
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
  replay checkpoint `c627f2d` repairs that reader, and the last reconciled operator record reported
  the unchanged
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
  candidate endpoint-inventory drift. Historical c627f2d-boundary operator evidence reports outcomes through
  index 19 and a
  25-entry global ledger totaling `$0.396223`; the next unused index is not stated. Historical
  r14/r15/r16 cost `$0.004044`/`$0.008478`/`$0.006281`, while exact r16 terminal status and
  reserved/remaining at that historical boundary
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
  or capability. Historical AUTHRUNNER replay checkpoint `c627f2d` repairs the datetime asymmetry
  provider-free,
  and the historical c627f2d-boundary operator record reports that the unchanged index-19 bundle verifies offline as
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
  same-process launch; interrupted work cannot be resumed as valid campaign evidence. Selected-route
  provider display-name ambiguity remains fail-closed, while checkpoint `425502c` restores parity so
  duplicate display names among unrelated endpoints do not disqualify an otherwise unambiguous
  selected route. Genuine v1.1 durable REAL evidence and a
  positive owned-REAL parent issue-consume-revoke-reject assay against the external runtime remain
  absent; the completed provider-free cascade does not substitute for that evidence. External-log
  publication and every benchmark run remain queued.
- **Next action:** Keep `V3-AUTHRUNNER-001` `PARTIAL / BLOCKED_SAFETY`. Checkpoint `48ea635` activated
  the receipt composite; historical child `68126e0` repaired the index-14 receipt-state-seal
  incompatibility provider-free; historical checkpoint `3a1246d` maps index 16's live failure to
  exact closed code `IDENTITY_REQUIRED_PROVIDER_PARAMETERS`; historical `03d6e8a` closes that
  construction asymmetry provider-free; and historical AUTHRUNNER replay checkpoint `c627f2d`
  completes the provider-free replay
  repair. Historical c627f2d-boundary operator evidence reports the unchanged index-19 bundle offline-valid,
  noncrediting, and nonauthorizing. No operator action is authorized, no next index is stated, and no
  command is current. `V3-PLANCONSTRAINTS-001` is complete provider-free at repair checkpoint
  `425502c`; the unresolved empirical
  schema and token-detail gates still prohibit any campaign.
  Current operator record `50d72b5e00040ccbdf2b5558809d39f35e51892a3e549209b100599e9891a820`
  reports that exact P1 and fresh r22 evidence reached those two gates at its recorded source
  boundary. `V3-RUNTIMEADMIT-001` now completes the provider-free promotion mechanism, but no
  private evidence was replayed and current FULL admission remains rejected. The record is
  nonauthorizing and supplies no current command or index.
  `V3-AUTONOMY-001` Phase 2 remains paused;
  AUTHSEAL publication, audits, benchmarks, the 24-case campaign, and release remain unauthorized.

### V3-RETRY-001 — Bounded same-route retry for schema-invalid structured output

- **Objective:** Honour the operator's `2026-08-25` decision to retry schema-invalid candidate
  responses by adding a bounded, explicitly configured same-route retry that is distinct from
  transient network/status retry, without granting any new authority or invalidating frozen
  evidence.
- **Files/modules:** Attempt/retry classification and the per-request attempt loop in
  `src/mmaudit/models/openrouter.py`, `authenticated_runner_execution.py` attempt limits,
  `ExecutionConfig` in `src/mmaudit/config.py`, retry-inclusive cost planning in
  `authenticated_runner_cost_plan.py`, and focused retry/fallback/ledger regressions.
- **Acceptance criteria:**
  - A `SCHEMA_VALIDATION_FAILED` response is retried on the **same** route up to an exact bounded
    configured limit, separate from `max_model_retries`, which continues to govern transient
    network/status retry only; the existing explicit-fallback and terminal paths remain reachable
    once same-route retries are exhausted, and no silent success is introduced.
  - Every retry attempt is separately reserved, spent, and reconciled; the run ledger stays closed
    and exact, the per-attempt cost tripwire applies unchanged to each attempt, and no attempt can
    leave an `uncertain_accounted` entry on a clean terminal path.
  - Attempt inventory, `maximum_attempts`, attempt ordinals, and logical request identity remain
    exact and bounded within the existing `32`-attempt ceiling; retry-inclusive cost aggregates stay
    consistent with the staged plan.
  - Terminal schema exhaustion raises a **typed, named** reason distinguishing it from transport
    failure and from fallback exhaustion; no `raise ... from None` is introduced on this path.
  - Attempt provenance is preserved in durable evidence so scoring can distinguish a first-attempt
    success from a retried success. Per the operator decision of `2026-08-25`,
    `structured_output_compliance` is scored on the **first attempt only**; a retried success earns
    no compliance credit, and retry exists solely to keep a multi-case campaign from terminating on
    a recoverable schema miss so the remaining dimensions still measure. Any retry-tolerant metric
    must be a separately named dimension with its own derived threshold and must not overload this
    deterministic gate.
  - The behaviour is **off by default**: with no new configuration present, default and
    explicit-zero serialization, canonical config bytes/hash, attempt counts, request identities,
    and repository-owned synthetic sealed-bundle compatibility are unchanged. Operator-owned smoke
    bundles at indices 19 and 21 are private external evidence, not repository fixtures; their bytes
    and replay are outside this provider-free acceptance and are not claimed.
  - Every durable authority, provider, runner, qualification, selection, egress, completion, and
    release flag remains literal false; `completed_real_audits` is unchanged.
- **Tests:** Provider-free same-route schema-retry and exhaustion regressions, transient-vs-schema
  classification negatives, closed-ledger reserve/spend/reconcile under retry, per-attempt tripwire
  enforcement, attempt-bound and logical-request-identity invariants, default-off byte-identity
  against the existing sealed bundles, schema drift, Ruff, and strict mypy.
- **Dependencies:** The confirmed classification recorded at `docs/codex_worklog.md:64` — schema
  failures bypass same-route retries, become `SCHEMA_VALIDATION_FAILED`, then use an explicit
  fallback or terminate. Operator decision supplied `2026-08-25`. Empirical motivation: smoke run
  index `18` failed `SCHEMA_VALIDATION_FAILED`, and `deepseek/deepseek-v4-pro-0813` via
  `parasail/fp8` returned schema-invalid structured output on `2` of roughly `10` attempts despite
  the route advertising `structured_outputs`, which is expected to recur across a 24-case campaign.
- **Status:** `COMPLETE`
- **Evidence:** `ExecutionConfig.max_schema_validation_retries` is explicit, defaults to zero, and
  is omitted from default serialization so the canonical qualification config bytes and SHA-256
  remain unchanged. Schema failures alone consume this quota on the same route; transient failures
  continue to consume `max_model_retries`; both share the existing 32-attempt ceiling. Every paid
  attempt retains its own reservation, finalization, usage, logical-request identity, ordinal, and
  receipt classification. Exhaustion is typed, explicit fallback remains post-exhaustion, and
  benchmark replay grants structured-output compliance only to one-attempt successes. Provider-free
  regressions cover both mixed retry orders, fallback, exact ledger totals, tripwires, schema drift,
  policy-sealed local synthetic trusted-REAL structural receipt assays, benchmark score-laundering
  rejection, and staged preflight capacity. These assays are not provider execution evidence.
- **Remaining limitation:** The operator-owned sealed bundles for smoke indices 19 and 21 are not
  repository fixtures and were not available for independent byte replay. Default/explicit-zero
  serialization, the canonical qualification-config hash, and repository-owned synthetic bundle
  compatibility are unchanged; this local evidence is not a claim about private bundle contents.
  The later operator-reported attempt to enable `3` retries in the hash-pinned qualification config
  failed the canonical-hash regressions and was reverted. Using retries in that campaign requires a
  deliberate release re-pin or a separate continuity path; neither was part of this ticket. The
  later `V3-RETRYCONT-001` successor completed a separate package-pinned path without changing this
  ticket's frozen default profile.
- **Next action:** None for this ticket. Stop after recording `COMPLETE`; do not launch a campaign,
  emit an operator command, infer a run index, or claim qualification, calibration, or release
  authority from this provider-free change.

### V3-RETRYCONT-001 — Explicit campaign-continuity retry activation

- **Objective:** Expose the completed schema-only same-route retry through an explicit provider-free
  continuity configuration path while preserving the frozen default qualification profile and every
  evidence and scoring boundary.
- **Files/modules:** Separate explicit configuration profile or isolated typed activation path,
  configuration/effective-hash custody, authenticated-runner preflight, documentation, and focused
  regressions.
- **Acceptance criteria:** The existing qualification profile bytes/hash and generic retry-off
  defaults remain unchanged. Explicit continuity selection enables exactly `3` schema retries while
  transient retry remains exactly `1`; preflight proves attempt/request/cost capacity; downstream
  evidence binds the distinct effective config hash; old default-off evidence is non-substitutive;
  fallback order, first-attempt-only scoring, per-attempt ledger custody, and the 32-attempt cap are
  unchanged; no authority or external action is granted.
- **Dependencies:** `V3-RETRY-001` (`COMPLETE`) and the recorded operator choice of exactly `3`
  schema retries.
- **Status:** `COMPLETE`
- **Evidence:** The exact frozen retry-off base bytes and semantic hash remain unchanged. A separate
  package-pinned profile enables exactly three schema retries plus one transient retry, proves five
  maximum attempts and `480 <= 576` request capacity, and binds distinct full/execution hashes
  through runner evidence v1.1, all four staged plans, durable bundle v1.2, and offline verification.
  Historical v1.0/v1.1 evidence cannot substitute; fallback, first-attempt-only scoring, and exact
  per-attempt cost/ledger provenance remain unchanged. Focused tests and static/generated gates pass.
- **Remaining limitation:** No provider execution, replacement candidate, qualification, campaign,
  runtime authority, or release is proven or authorized. Route-only smoke is noncrediting for this
  configuration binding.
- **Next action:** Stop after provider-free closure. `V3-QUOTE-001` remains queued and unstarted;
  candidate reselection and all REAL/provider/operator work remain separately gated.

### V3-QUOTE-001 — Pre-purchase cost and runtime estimate

- **Objective:** Produce a deterministic, bounded pre-purchase cost and wall-clock quote from
  local target analysis, complete planned paid work, and frozen route pricing before any paid work.
- **Files/modules:** `src/mmaudit/cli.py`, `src/mmaudit/orchestration/budgets.py`, typed quote and
  reconciliation models, generated schemas, and focused provider-free regressions.
- **Acceptance criteria:** Bind exact source/index/graph/shard inputs, the complete bounded paid-task
  envelope, planned roles/models, retry and recovery bounds, local execution limits, and frozen
  pricing. Expose a range and explicit worst case; refuse any unbounded task or target; enforce the
  accepted worst case as a separate exact per-run spend ceiling; and record terminal deltas only
  from fully reconciled ledger evidence. Serialized quote/acceptance remains nonauthorizing.
- **Dependencies:** `V3-SHARD-001` (`COMPLETE`).
- **Status:** `COMPLETE`
- **Evidence:** Provider-free quote creation binds the exact scheduler campaign, target/index/graph/
  shard inventory, scheduler-selected model set, early and later paid routes, dynamic reviewer-role
  multiplicity, transient-attempt and campaign-global recovery ceilings, local timeout bounds, and
  frozen request-specific endpoint pricing. Acceptance installs a separate exact incremental ledger
  ceiling and rejects route, role, model, endpoint, pricing, token, cost, task-count, or campaign
  drift before durable mutation. Terminal reconciliation requires campaign-bound v1.1 ledger
  evidence. Canonical schemas, governance inventory, strict production typing, and focused quote,
  budget, CLI, forensic, integration, config, and candidate-bound regressions pass.
- **Remaining limitation:** The accepted spend ceiling may be lower than the complete-work worst
  case; the quote exposes both values, sets `hard_budget_limited`, and promises no completion. No
  provider execution or completed real audit is claimed.
- **Next action:** Stop after provider-free closure. `V3-SCHEMARETRY-001` is queued for the
  operator-selected same-route schema retry; this quote ticket changed neither retry code nor retry
  configuration.

### V3-SCHEMARETRY-001 — Operator-selected same-route schema retry

- **Objective:** Implement the operator-selected retry of schema-invalid structured output on the
  applicable audit route without treating transient network/status retry as schema retry.
- **Files/modules:** Structured-output route control, explicit retry configuration custody,
  per-attempt budget/evidence handling, and focused regressions.
- **Acceptance criteria:** `max_model_retries` remains transient-only. A schema-invalid response is
  `SCHEMA_VALIDATION_FAILED` and uses explicit fallback or terminates unless a separate exact
  same-route schema-retry policy is configured. The selected policy is bounded, budgeted, recorded
  per attempt, and covered by success, exhaustion, fallback, configuration-drift, and no-implicit-
  retry regressions.
- **Dependencies:** `V3-RETRY-001` (`COMPLETE`) and `V3-QUOTE-001` (`COMPLETE`).
- **Status:** `COMPLETE`
- **Evidence:** Ordinary paid `run` and provider-free `quote create` accept an explicit bounded
  `--schema-validation-retries` selection while omission remains retry-off and
  `max_model_retries` remains transient-only. The exact split policy and hash are bound through
  quote, acceptance, budget, usage, durable runner, current smoke v1.3, and manifest v1.3 evidence;
  explicit v1.2 legacy verification is retry-off only. Provider-free regressions cover success,
  exhaustion, fallback, exact accounting, failure classification, equal-total policy substitution,
  partial/mixed evidence, helper retargeting, and mid-attempt drift.
- **Remaining limitation:** No provider-backed retry, replacement candidate, successful real audit,
  qualification, runtime authority, or release is proven. The historical failed campaign used zero
  schema retries and is unchanged; the frozen qualification profile remains retry-off.
- **Next action:** Stop after closure. `V3-REVOKERECON-001` is the next dependency-ready queued
  provider-free ticket, but it is not selected in this work unit.

### V3-RUNTIMEADMIT-001 — Promote runtime evidence into campaign admission predicates

- **Objective:** Provide the missing mechanism that lets real runtime evidence satisfy
  `EMPIRICAL_SCHEMA_CONFORMANCE` and `TOKEN_DETAIL_REPORTING_CONVENTION`, which
  `FULL_CAMPAIGN_ADMISSION` requires but which no current code path can ever set to `SATISFIED`.
  Discovery unconditionally emits both as `_unavailable_result`
  (`EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE`, `TOKEN_DETAIL_CONVENTION_UNAVAILABLE`), so the 24-case
  campaign is currently unreachable by construction rather than by policy.
- **Files/modules:** `_SEPARATE_RUNTIME_PREDICATES` handling and the purpose matrix in
  `src/mmaudit/models/route_constraints.py`, a durable runtime-evidence carrier bound to exact route
  identity, the authenticated-runner admission path, generated schema, and focused negatives.
- **Acceptance criteria:**
  - A defined, auditable path takes runtime observations from a completed authenticated run and
    produces `SATISFIED` for both predicates, replacing the unconditional unavailable results only
    when exact evidence is present.
  - Evidence binds to the **exact** model id, provider endpoint, route identity, constraint profile,
    and discovery run the campaign will use. Evidence from any other route, model, endpoint, or
    profile is rejected; nothing is inferred across routes.
  - Evidence carries a bounded age consistent with the existing evidence-age policy and fails closed
    when stale, exactly as other route evidence does.
  - No self-attestation: evidence derives from durable sealed run artifacts with their own custody,
    never from caller-supplied assertions or locally recomputed claims.
  - Smoke-derived evidence is admissible **only** where it exercised the same route under the same
    constraint profile, and confers no benchmark, qualification, authority, or release credit.
  - Fail-closed default is preserved: with no evidence present both predicates remain
    `UNAVAILABLE` and `FULL_CAMPAIGN_ADMISSION` continues to reject, with unchanged bytes for every
    existing sealed artifact.
  - Every durable authority, provider, runner, qualification, selection, egress, completion, and
    release flag remains literal false; `completed_real_audits` is unchanged by this ticket.
- **Tests:** Provider-free promotion and rejection regressions, route/model/endpoint/profile binding
  negatives, evidence-age expiry, tamper and reseal negatives, the full purpose matrix across all
  four `RouteConstraintPurpose` values, default-unavailable byte identity, schema drift, Ruff, and
  strict mypy.
- **Dependencies:** The latest operator-supplied record
  `955b5d3e75c7cb0fe3f4ef571829dfde55a337bd704d140268b3dffa66485808` reports that
  index-21 plus matching r21 evidence satisfied `EMPIRICAL_SCHEMA_CONFORMANCE` and exposed the
  pre-fix token-detail digest mismatch. It reports no new smoke, provider completion, spend, or
  launch and is nonauthorizing and not independently authenticated by Codex. The corrected code has
  not been replayed against those private bytes.
- **Status:** `COMPLETE`
- **Evidence:** The provider-free runtime-evidence carrier, canonical schema, exact three-route
  projection, sealed same-process consumer, bounded-age policy, authenticated-runner/CLI plumbing,
  and predicate/reason diagnostics are implemented. Exact candidate, PRIMARY, and REPLAY positives;
  every route/model/endpoint/profile/discovery/facts/report/policy mismatch; staleness; tamper,
  coherent reseal, origin, and caller-substitution negatives; all four purposes; default-byte
  identity; schema generation; Ruff; and strict mypy pass. The final correction separately joins
  usage/token evidence to the full `RequestTokenPlan.plan_sha256` and the preview to the stable
  domain-separated projection, rejects the former impossible equality, enforces that projection in
  base smoke replay, and seals the shared projector in the provider callable graph.
- **Selection state:** completed provider-free and nonauthorizing at `2026-08-27T11:08:16Z`; no
  external action or successor ticket is selected.
- **Remaining limitation:** The operator-supplied index-21/r21 replay predates the final digest fix:
  it proved `EMPIRICAL_SCHEMA_CONFORMANCE` and exposed the invalid token-detail equality, but the
  corrected code has not been replayed against those private bytes. Current evidence-backed
  `FULL_CAMPAIGN_ADMISSION` therefore remains unproven/rejected. Serialized smoke provenance retains
  the repository's existing structural/self-hash custody rather than independent provider-origin
  authentication. No campaign, provider, qualification, audit, runtime, or release authority follows.
- **Next action:** None for this ticket. Stop without launching a smoke/campaign, emitting an operator
  command, inferring a run index, selecting a successor, or granting authority.

### V3-CONSENSUS-001 — Independent cross-examination and adjudication

- **Objective:** Apply blind discovery, adversarial cross-examination, multiple independent
  validators/falsifiers, and evidence-capped deterministic judgment.
- **Files/modules:** `src/mmaudit/orchestration/consensus.py`, pass-six pipeline evidence plumbing,
  deterministic judge payloads, focused unit/integration regressions, generated autonomy inventory,
  and governance records.
- **Acceptance criteria:** A single verifier cannot suppress a candidate group; model agreement alone
  cannot confirm; high/critical decisions satisfy exact lineage and evidence constraints; incomplete,
  duplicated, reused, or forged reviewer inventories fail closed; every dissenting vote is retained.
- **Tests:** Closed three-review vote matrix, exact-inventory and distinct-lineage negatives,
  judge-cap preservation, high/critical evidence caps, pipeline artifact/replay coverage, schema and
  static gates.
- **Dependencies:** `V3-COVERAGE-001` (`COMPLETE`).
- **Status:** `COMPLETE`
- **Selection state:** Completed provider-free and nonauthorizing at `2026-08-27T17:10:18Z`; no
  external action or successor ticket is selected.
- **Evidence:** Pass six retains exactly one verifier and two lineage-distinct falsifiers, with exact
  task/request/completion/root custody, globally unique provider generations, all dissent, and a
  closed deterministic quorum. Runtime and detached replay share vote/reproduction enrichment,
  consume exact final candidate validation, reconstruct every active/rejected/filtered finding, and
  bind evidence-cap and severity policy to trusted inputs. A single reviewer cannot suppress a
  two-review majority, and model agreement alone never confirms. Latest-tree validation passed
  `614` affected unit tests and `7` selected synthetic local integrations; independent final review
  found no HIGH/blocking defect.
- **Remaining limitation:** The bundle is self-sealed rather than externally authenticated; scanner
  evidence is deliberately nonconfirming until trusted host code provides exact full-claim binding;
  and the provider-free regressions do not claim a real provider run, a completed real audit, or
  release/runtime authority.
- **Next action:** None for this ticket. `V3-MULTI-AUDIT-001` remains queued and unselected because
  `V3-SINGLE-AUDIT-001` is unresolved. Stop without launching a campaign, issuing an operator
  command, inferring a run index, changing retry/configuration behavior, or granting authority.

### V3-LEARNING-001 — Cross-audit learning corpus

- **Objective:** Capture what each completed audit established before the first real audit makes
  that terminal evidence unrecoverable.
- **Files/modules:** New versioned learning-corpus model/schema, terminal orchestration capture,
  generated schemas, focused unit/integration regressions, and governance records.
- **Acceptance criteria for this Phase 1 slice:** Tenant-scoped bounded records retain confirmed
  findings, rejected candidates and reasons, reviewer attribution and misses, reviewed surfaces and
  outcomes, and per-role cost/runtime. Benchmark and time-split inputs are rejected by construction.
  Corpus-derived material remains a nonauthorizing lead and cannot supply finding evidence,
  confidence, coverage, or consensus credit.
- **Dependencies:** None for Phase 1; completion/Phase 2 remains behind `V3-TIMESPLIT-001` and a
  measured unprimed baseline.
- **Status:** `PARTIAL`
- **Result:** Phase 1 is complete provider-free. A versioned, self-hashed, size-bounded record binds
  one opaque tenant scope to exact terminal-report authority, confirmed/rejected outcomes, exact
  reviewer and specialist attribution, reviewed surfaces, later-established misses, and per-role
  cost/runtime. Eligible private REAL runs persist it mode `0600` before manifest sealing; strict
  deterministic manifest replay detects resealed drift, and `latest` excludes/purges the payload.
  Every durable authority/credit flag is false. Registered synthetic/public benchmark routes cannot
  enable capture, and Phase 2 application remains disabled.
- **Remaining limitation:** Phase 1 trusts the registered operator source classification and cannot
  detect deliberate relabeling of undisclosed holdout/time-split bytes. `V3-TIMESPLIT-001` must add
  non-overridable purpose/provenance binding before introducing such a route. A COMPLETE report with
  no reviewed surfaces fails capture closed. Corpus application/priming and its measured A/B gate
  remain unimplemented behind `V3-TIMESPLIT-001`.
- **Selection state:** Phase 1 closed `PARTIAL` provider-free and nonauthorizing; no successor ticket,
  current operator command, run index, authority, or Phase 2 priming is selected. The later
  operator-supplied record `f3569e3eac39391a9b09566ccc5a2b83a5eed6e963fb8ce417c03c850166e617`
  reports a separate FULL-admitted campaign that failed closed after nine schema failures and 15
  unbound identities, with 57 reconciled ledger entries / `0.68118684` USD and zero completed real
  audits. That evidence is nonauthorizing and not independently authenticated by Codex.
- **Next action:** Keep Phase 2 disabled until `V3-TIMESPLIT-001`. The next canonical ticket is
  `V3-SINGLE-AUDIT-001`, still queued. Do not reuse the frozen DeepSeek/`parasail/fp8` candidate;
  separate reselection, empirical structured-output validation, and resolution of unbound generation
  identity are required. Same-route schema retry was future work at this learning-ticket boundary;
  later `V3-RETRYCONT-001` completed the separate package-pinned path. This learning ticket itself
  changed neither retry code nor configuration.

### V3-REVOKERECON-001 — Reconcile candidate revocation with pinned plan selection

- **Objective:** Restore candidate selectability after a revocation. Revoking one route must disqualify
  that route from being **assigned**; it must not invalidate an entire pinned selection plan that
  merely lists it. At present the single correct revocation of
  `deepseek/deepseek-v4-pro-0813=parasail/fp8` makes **every** candidate discovery fail, so the
  reselection that the campaign failure made mandatory is impossible and the build cannot progress.
- **Files/modules:** Route-set revocation evaluation in `src/mmaudit/models/candidate_revocation.py`,
  its call sites in `candidate_selection.py` and `cli.py`, any supported successor-plan emission path,
  and focused regressions.
- **Acceptance criteria:**
  - **Primary acceptance test:** with `deepseek/deepseek-v4-pro-0813=parasail/fp8` revoked for
    `role=candidate`, a provider-free discovery requesting a **different, unrevoked** candidate
    succeeds; a discovery requesting the revoked route still fails closed with a named reason.
  - Revocation is evaluated against the route actually being **assigned**, rather than against every
    entry in the validated route set, **or** a supported path emits a successor plan whose candidate
    constraint names a live route. Either design is acceptable; hand-editing a hash-pinned plan is not.
  - Judge-role selection is unaffected by a candidate-role revocation, and vice versa; role scoping is
    exact.
  - The existing tombstone remains effective and non-bypassable: no plan regeneration, refresh, or
    successor artifact may resurrect a revoked route, and revocation matching must not depend on
    `selection_plan_sha256` such that changing the plan silently un-revokes.
  - Fail-closed default is preserved and the refusal names the offending role, model, endpoint, and
    reason, so a rejected selection is diagnosable without reading source.
  - Every durable authority, provider, runner, qualification, selection, egress, completion, and
    release flag remains literal false; `completed_real_audits` is unchanged by this ticket.
- **Tests:** Provider-free regressions covering revoked-route refusal, unrevoked-alternative
  admission, cross-role isolation, resurrection attempts via plan change, tombstone persistence,
  named-reason rendering, schema drift, Ruff, and strict mypy.
- **Dependencies:** Operator record of `2026-08-28`. Revocation resource holds exactly one entry
  (`EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE`). Plan
  `bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f` pins the revoked route as
  `authenticated_runner_selection.route_constraints[0]`. Observed: `minimax/minimax-m3=coreweave/fp4`,
  `google/gemma-4-26b-a4b-it=deepinfra/fp8`, and `tencent/hy3=novita` are all refused
  `candidate selection route is revoked`.
- **Status:** `COMPLETE`
- **Result:** Requested-assignment discovery now admits unrevoked routes even when a separately
  listed route in the validated pinned plan is tombstoned. Exact candidate, PRIMARY, and REPLAY role
  custody reaches selection, discovery, admission, benchmark, smoke, and concrete OpenRouter
  transport boundaries. The revoked DeepSeek/Parasail exact and canonical identities still fail
  closed with role, model, endpoint, and
  `EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE`; plan/constraint hash changes, mutable role shadows,
  and transport-registry mutation cannot resurrect or rescope the tombstone.
- **Remaining limitation:** The unchanged pinned plan still selects the revoked candidate and is not
  runnable. This ticket selected no replacement, performed no provider call, and granted no
  qualification, campaign, runtime, audit, or release authority. The operator-reported pre-fix
  whole-plan deadlock remains historical evidence rather than a post-fix provider result.
- **Next action:** Stop after closure. No successor ticket is selected. Candidate replacement,
  empirical validation, and any later paid run require separate work and fresh authorization.

### V3-PLANSUCCESSOR-001 — Emit a successor selection plan naming a live candidate route

- **Objective:** Make candidate replacement actually usable. `V3-REVOKERECON-001` correctly scoped
  revocation to the assigned route, so an unrevoked candidate now passes discovery. But
  `config/models.selection-plan.json` still carries `authenticated_runner_selection.route_constraints`
  naming only the revoked `deepseek/deepseek-v4-pro-0813=parasail/fp8` for `role=candidate`, and
  discovery emits **constrained** route evidence only for routes the plan pins. A replacement
  candidate therefore discovers successfully but produces evidence the runner rejects with
  `authenticated runner route lacks constrained discovery evidence`
  (`route_admission.py:655`), so no replacement can reach a live-route gate, smoke, or campaign.
- **Files/modules:** Selection-plan emission/succession, `models.selection-plan.json` custody and
  `plan_sha256` derivation, discovery constrained-evidence emission, `cli.py` wiring, and focused
  regressions.
- **Acceptance criteria:**
  - **Primary acceptance test:** starting from the current plan with
    `deepseek/deepseek-v4-pro-0813=parasail/fp8` revoked, an operator can obtain a successor plan whose
    `role=candidate` route constraint names a different, live, unrevoked route, and with it a
    provider-free `--live-route-preflight-only` gate for that candidate **succeeds**. Discovery
    succeeding is not sufficient; the replacement must be usable end to end.
  - Successor emission is deterministic and hash-custodied: `plan_sha256`, per-entry `entry_sha256`,
    `constraint_sha256`, and `profile_sha256` are all derived, never caller-supplied, and the
    predecessor plan digest is recorded so the succession chain is auditable.
  - Revocation remains non-bypassable: a successor plan cannot name a tombstoned route, and emitting a
    successor cannot un-revoke anything.
  - Judge-role constraints are carried forward unchanged unless explicitly replaced; a candidate
    replacement does not disturb judge selection or lineage independence.
  - Frozen evidence bound to the predecessor plan remains valid as historical evidence and is never
    silently reinterpreted under the successor.
  - Every durable authority, provider, runner, qualification, selection, egress, completion, and
    release flag remains literal false; `completed_real_audits` is unchanged by this ticket.
- **Tests:** Provider-free succession/derivation regressions, revoked-route rejection in a successor,
  predecessor-digest custody, judge carry-forward, constrained-evidence emission for the new candidate,
  gate admission for the replacement, tamper and reseal negatives, schema drift, Ruff, strict mypy.
- **Dependencies:** Operator record of `2026-08-28`. `V3-REVOKERECON-001` `COMPLETE`. Observed: with
  the reconciliation in place, `google/gemma-4-26b-a4b-it=deepinfra/fp8` and `tencent/hy3=novita` both
  pass discovery, but the gemma discovery artifact contains none of
  `route_predicate_profile`/`exact_route_constraint`/`normalized_route_facts`/`route_predicate_report`
  while the plan-pinned deepseek artifact contains all four. Plan
  `bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f`.
- **Status:** `QUEUED`
- **Next action:** Implement only successor emission and its negatives. Do not choose the replacement
  candidate, launch a campaign, emit an operator command, or grant any qualification, calibration, or
  release authority. Candidate choice remains an operator decision informed by a provider-free sweep.

### V3-PLANCONSTRAINTS-001 — Enforce selection/runtime route-constraint parity

- **Objective:** Define one typed, self-hashed route-predicate profile and make plan construction,
  publication, provider-free qualification, and runtime admission consume the same finite predicates.
- **Files/modules:** Candidate selection and endpoint snapshots, selection-plan schemas/builders,
  provider-free route checks, runtime admission adapters, documentation, and focused parity tests.
- **Acceptance criteria:**
  - The profile covers exact model identity and endpoint tag, requires the selected endpoint's
    normalized provider display name to occur exactly once in the complete exact-model inventory,
    the exact operational accepted state, ZDR eligibility, and the emitted request
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
- **Dependencies:** The last-reconciled operator-reported, nonauthorizing `c627f2d` offline-valid sealed one-case
  `V3-AUTHRUNNER-001` smoke satisfies only this provider-free prerequisite; it is not independent
  bundle authentication or campaign authority. This ticket is mandatory before the 24-case campaign.
- **Status:** `COMPLETE`
- **Regression repair:** Checkpoint `425502c5cbc173578053423d946ef24843f26285`, direct child of
  `390e9b29e748e38d511da9f0a54cfc4fa1a2c0a8`, removes only the stricter whole-inventory
  display-name uniqueness conjunct introduced at `7ef4717`. Complete inventory custody and the
  case-insensitive `display_count == 1` selected-name rule remain fail-closed. Exact Sail Research
  and Modal route regressions admit unrelated Fireworks/Alibaba/Morph collisions across generic,
  constrained, and full discovery paths and reject casefold collisions of either selected name.
  The five-path checkpoint passed the `921`-test adjacent runner matrix, the overlapping `250`-test
  route/snapshot/discovery/admission matrix, `32` inventory tests, Ruff/format, strict mypy, canonical
  generation, and diff integrity. Independent review found no blocker/HIGH. No provider, network,
  secret, ledger, campaign, operator-record, or run-index action occurred.
- **Prior result:** Candidate-selection schema v1.4 binds one strict self-hashed 29-predicate profile
  and exact per-role route constraints. The same evaluator and closed report are required before
  constrained endpoint/model publication, through registry plan/profile/constraint/report custody,
  and at FULL or NONCREDITING runtime admission. Selected-endpoint display-name ambiguity, model or
  endpoint emitted-parameter gaps, reasoning precedence/empty/contradictory inventories, capacity,
  exact-price cap weakness, live/frozen drift, custody swaps, and lower or higher runtime output-token
  drift fail closed. FULL rejects the deliberately `UNAVAILABLE` empirical-schema and token-detail
  predicates before ledger, secret, output, registration, reservation, or provider state. The final
  changed-surface matrix passed `951` tests with two known code-retarget warnings; the disjoint
  adjacent qualification/lineage matrix passed `201`; generated inventory/schema tests passed `57`
  overlapping tests. Ruff, format, strict mypy over `210` source files, dependency, generator, import,
  and diff gates passed. Independent review found no blocker/HIGH; `1,012` defensive mutation probes
  and six import permutations failed closed and restored cleanly. Source checkpoint
  `7ef471744adfce557edf612a74b2847aafb3e8bc`, direct child of
  `85c06b07ccc3905af4e0231497276934f7ae142a`, owns the exact 33-path provider-free implementation,
  config, schema, generated-inventory, and focused-test slice; it excludes governance, operator
  results, `.gitignore`, and provider execution.
- **Remaining limitation:** This provider-free result does not establish empirical structured-output
  reliability or the provider-domain token-detail convention. Those two typed dispositions remain
  `UNAVAILABLE`, so FULL campaign admission remains blocked and no provider, runner, qualification,
  benchmark, audit, AUTHSEAL, release, or readiness authority follows.
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
- **Next action:** Keep `V3-AUTHRUNNER-001` `PARTIAL / BLOCKED_SAFETY`. The provider-free route-bound
  evidence mechanism is complete under `V3-RUNTIMEADMIT-001`; separately supplied fresh canonical
  private evidence must still pass it before FULL admission can succeed. No operator action,
  provider access, inferred index, command, or campaign is current; `V3-AUTONOMY-001` Phase 2 remains
  paused.

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
- **Resumed provider-free slice 2026-08-27:** Add a strict, negative-only tombstone for the exact
  rejected DeepSeek/`parasail/fp8` selection assignment. Preserve historical plan, registry, and run
  bytes as parseable evidence, but reject new discovery and every live execution path before secret,
  reservation, ledger, or provider transport. The tombstone cannot select or qualify a successor.
- **Candidate-revocation result 2026-08-27:** A versioned, self-hashed, package-bound negative
  registry now tombstones the exact and canonical DeepSeek identities on `parasail/fp8`. Discovery,
  plan derivation, benchmark, qualification, CLI, direct pipeline validation, selected metadata,
  completion, and generation-refetch boundaries reject before secrets, reservation, usage/ledger
  mutation, or provider transport. Immutable closure seals reject coherent anchor replacement and
  selected instance-delegator retargeting. Adjacent explicitly pinned endpoints remain eligible.
- **Next action:** No provider or operator action is current. Fresh candidate reselection,
  qualification, and promotion remain separate prerequisites before `V3-SINGLE-AUDIT-001`; do not
  infer a run index or reuse the rejected assignment. Schema-invalid structured output was not
  retried on the same route at this ticket boundary; later `V3-RETRYCONT-001` completed the explicit
  package-pinned path. This ticket itself changed neither retry code nor retry configuration.

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

## Current next action

`V3-SCHEMARETRY-001` and `V3-REVOKERECON-001` are `COMPLETE` provider-free and nonauthorizing. The
requested-assignment path admits unrevoked alternatives while the existing tombstone continues to
refuse the revoked route with exact diagnostics and exact role isolation. No successor ticket or
replacement candidate is selected, and no provider, operator, campaign, qualification, runtime,
audit, or release authority is current.
`V3-SINGLE-AUDIT-001` and `V3-MULTI-AUDIT-001` remain queued behind their prerequisites. No provider
action, campaign, operator command, run index, candidate selection, qualification, runtime authority,
or release action is current.

## Historical next action — c627 replay boundary (superseded)

### V3-AUTHRUNNER-001 — provider-free canonical-replay datetime continuation complete

- **Objective:** Preserve historical checkpoint `03d6e8a` and the operator-owned bundle while fixing
  the provider-free canonical-replay datetime contract without weakening strict validation or exact
  canonical byte equality; retain zero operator commands.
- **Dependencies:** Last reconciled operator evidence
  `4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251`, historical negative
  checkpoint `48ea635ab5a2fa778d6b5ce5c9a1592f0f27b375`, historical receipt-seal hotfix
  `68126e0fe438f853fb9b75582023f807a208bdae`, historical diagnostic checkpoint
  `3a1246daf19ffa4a772be7806bd903199634ab0b`, historical join-fix checkpoint
  `03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc`, replay checkpoint
  `c627f2debfa18df7d9567cd7c3300d19a9e9f5ce`, and nonauthorizing plan
  `ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f`. The operator reports a
  25-entry global ledger / `$0.396223`, a complete index-19 four-entry closed run ledger /
  `$0.39622262`, and the unchanged sealed bundle offline-valid at `c627f2d` with no new spend.
- **Status:** `COMPLETE_NONAUTHORIZING` provider-free continuation within overall
  `PARTIAL / BLOCKED_SAFETY`.
- **Boundary:** Historical post-`3a1246d` operator evidence traverses receipt sealing and four earlier
  structured-output identity clauses, then paid index 16 fails at the exact closed
  `IDENTITY_REQUIRED_PROVIDER_PARAMETERS` clause. Historical `03d6e8a` produced the index-19 bundle;
  historical AUTHRUNNER replay checkpoint `c627f2d` repairs replay without changing those bytes. Do
  not release, reuse, or edit any recorded
  ledger entry or infer unstated statuses, costs, counters, artifacts, or bundle state. The operator
  explicitly retracts its `requested_mode` hypothesis. The next unused index is NOT_STATED. No current command or provider access is
  authorized. No verifier, full runner, qualification, seal,
  audit, benchmark, or release command is emitted.
- **Completed AUTHRUNNER replay evidence:** Exact three-path replay checkpoint `c627f2d` passed 95
  runtime tests, 111
  adjacent CLI/durable/inventory/release-schema tests, and the retained 789-test AUTHRUNNER matrix as
  separate overlapping results, plus Ruff, format, strict mypy, canonical generator, `pip check`,
  diff integrity, and exact-byte review with no blocker/HIGH/MEDIUM. Historical `03d6e8a` retains
  19 request-cost-preview, 26 model-benchmark, overlapping 185 usage-plus-preview, and 47-root/1,073-state
  evidence; historical `3a1246d` retains 564 tests / 47 roots / 1,072 states. The last-reconciled
  operator record reports the same index-19 bundle offline-valid, noncrediting, and nonauthorizing
  with no rerun
  or new spend. This is not runner or release authority. `V3-AUTONOMY-001` remains
  `IN_PROGRESS`, but its Phase 2 working bytes are paused. The exact 28-role bundle pins three
  reviewed package resources and explicitly leaves 25 external roles unresolved.
- **Historical next action at that boundary:** Preserve `c627f2d`, the operator-owned bundle, and
  ledger state. No operator action
  is authorized; do not infer another run index or grant runner/release authority.
  `V3-PLANCONSTRAINTS-001` is complete provider-free, while FULL admission remains blocked by its
  two typed `UNAVAILABLE` runtime-only gates.
