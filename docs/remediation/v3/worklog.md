# mmaudit v3 Product Remediation Worklog

The objective source has SHA-256
`f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
Do not record credentials, raw private prompts, or raw provider completions here.

AUTORUN_STATUS: PAUSED
CURRENT_MILESTONE: Client report and forensic evidence bundle
CURRENT_TICKET: V3-REPORT-001 (IN_PROGRESS)
LAST_COMPLETED_TICKET: V3-FIXTURE-001 (COMPLETE)
NEXT_ACTION: Resume V3-REPORT-001 with strict mypy and the broader reporting/release test matrix; fix any failures, review the diff, update traceability, and only then consider the ticket complete.
LAST_COMMAND: `.venv/bin/ruff check` over the 18 affected Python implementation and test files.
LAST_RESULT: PASS: Ruff reported `All checks passed!`; the ticket remains intentionally IN_PROGRESS pending strict mypy and broader validation.
REAL_MODEL_CALLS_ATTEMPTED: 10
REAL_MODEL_CALLS_SUCCEEDED: 1
REAL_MODEL_CALLS_REJECTED: 9
OPENROUTER_COST_USED_USD: 0.0033415625
OPENROUTER_COST_RESERVED_USD: 0.00
OPENROUTER_BUDGET_REMAINING_USD: 249.9966584375
COMPLETED_REAL_AUDITS: 0
BLOCKED_EXTERNAL_ITEMS: The exact Mistral/Venice smoke route returned provider rate limiting and will not be retried unchanged; no qualified production ensemble; required rootless isolation and several certified external engines remain unavailable; private holdout and independently adjudicated professional comparison are not supplied. The previously absent exact objective source is now committed at `517559e5c9526f78e516374ebc194933d01eac7f` with the required SHA-256; its remaining queue references and regression are actionable after the current bounded ticket.
LAST_CHECKPOINT_COMMIT: 92f1be4c080f6853b852626c0cf3ea8dd65301cc

## 2026-08-03 — V3-REPORT-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Produce a concise Corrovera-branded client report with prominent
  status, limitations, evidence-capped finding detail, and inline source excerpts, while moving
  exhaustive coverage and execution custody into a separately hash-bound forensic bundle.
- **Starting evidence:** The current pipeline emits one branded Markdown report plus JSON, SARIF,
  coverage, model-use, and manifest artifacts. Traceability still records no concise client split,
  no complete seven-artifact forensic contract, and incomplete rejected-finding evidence.
- **Next action:** Map existing writers and artifact bindings, then add failing report-quality
  regressions for all required finding states and complete/incomplete no-findings outcomes.
- **Pause:** At `2026-08-03T17:23:41Z`, the operator requested a graceful laptop-safe pause.
  The remaining delegated read-only audit was interrupted. No provider request, test command, or
  implementation edit was started for this ticket. Resume by inspecting the exact verification,
  falsification, and reproduction evidence fields, then add the first failing report-quality
  regression for the typed client/forensic split.
- **Resume:** At `2026-08-03T17:25:33Z`, persistent-goal continuation resumed this ticket from
  clean checkpoint `4a2ea45fec836f467c23b52e3b3522dc23678c47`. The next action is unchanged;
  no provider call is authorized or needed for this reporting slice.
- **Implementation slice:** Added a typed seven-deliverable report bundle, concise deterministic
  Corrovera client rendering, complete forensic finding custody, source-bound inert excerpts,
  manifest schema `1.2` leaf requirements and semantic projections, release-observer checks,
  generated JSON schemas, CI staging, traceability plumbing, and negative report/manifest
  regressions. The legacy exhaustive report remains an explicit compatibility artifact.
- **Focused evidence:** The new client/forensic suite passed `10` tests; the selected end-to-end
  pipeline report-bundle case passed; manifest tests passed `29`; release artifact, release run,
  and release verification suites passed `26`, `12`, and `12`; traceability passed `11`; release
  schemas passed `3`; and the six coherent bundle-omission cases passed. These focused results
  are retained as partial-ticket evidence and do not replace strict mypy or the broader suite.
- **Pause:** At `2026-08-03T17:51:23Z`, the operator requested a laptop-safe pause. Ruff format
  left all `18` affected Python files unchanged and focused Ruff check passed after import-order,
  comparison-style, and literal-regex cleanup. No paid provider call, network operation, or
  long-running validation was started. Resume with strict mypy and broader reporting/release
  tests; do not mark this ticket complete from the focused evidence alone.
- **Checkpoint:** Partial implementation and its honest paused state were committed as
  `92f1be4c080f6853b852626c0cf3ea8dd65301cc`. This is not a ticket-complete or release claim.

## 2026-08-03 — V3-FIXTURE-001

- **Status:** `COMPLETE`; this was a close-out of existing implementation, with no new fixture
  architecture required.
- **Defensive objective:** Verify that the already committed deterministic 5k/15k/35k
  synthetic Solidity corpus satisfies every original fixture acceptance criterion and that the
  completed shard implementation actually consumes all three roots.
- **Starting evidence:** The queue records 4,952/15,116/35,444-line roots, 196 manifest-bound
  generated files, marked discovery/index/graph/coverage/context tests, a conditional real solc
  assay, and complete V3-SHARD-001 consumption. These statements must be rechecked against the
  current tree before changing `PARTIAL` to `COMPLETE`.
- **Next action:** Inspect generation/manifests and exact test selectors, run the marked scale and
  sharding regressions, and retain the optional compiler prerequisite as an honest independent
  skip if unavailable.
- **Pause:** At `2026-08-03T17:04:13Z`, the operator requested a graceful laptop-safe pause.
  Delegated read-only work was stopped before validation began. No provider call, test process,
  or repository mutation is intentionally left running. Resume from the preceding next action.
- **Resume:** At `2026-08-03T17:06:04Z`, the operator resumed the persistent goal. Validation
  restarts from the clean `13d46b7` pause checkpoint; provider calls remain zero for this ticket.
- **Closure result:** Every original acceptance criterion is satisfied on the current tree. The
  deterministic generator verified `196` exact committed files; the corpus manifest binds
  4,952/15,116/35,444-line roots with source-tree hashes
  `7634650a...44e`, `b2a56a28...131`, and `e5b21b27...fb8`. The generator and corpus-file hashes
  are `52579570...1b0` and `5acc4a50...099`; the embedded corpus self-hash is
  `32a8812c...266`.
- **Commands and results:**
  - `.venv/bin/python scripts/generate_realistic_scale_fixtures.py`: PASS, `verified 196
    deterministic fixture files`.
  - `.venv/bin/pytest -q tests/unit/test_realistic_scale_fixture_generator.py --cache-clear`:
    PASS, `8 passed in 1.48s`.
  - `.venv/bin/pytest -q -m large_scale tests/large_scale/test_realistic_solidity_scale.py
    --cache-clear`: the first invocation was externally interrupted and received no credit; a
    clean materially separate rerun passed `8` tests in `69.38s` with no skip.
  - `.venv/bin/pytest -q tests/unit/test_semantic_sharding.py
    tests/unit/test_scheduler_blind_shards.py --cache-clear`: PASS, `57 passed in 3.01s`.
  - `env MMAUDIT_TEST_SOLC_EXECUTABLE=/opt/homebrew/Cellar/solidity/0.8.30/bin/solc
    .venv/bin/pytest -q tests/integration/test_realistic_scale_fixture.py -rs`: PASS, `1 passed
    in 2.08s`; compiler SHA-256 `a037e036...ddc4`. Execution was offline and disposable.
  - `.venv/bin/ruff format --check .`; `.venv/bin/ruff check .`; `.venv/bin/mypy`: PASS,
    `423` files formatted, Ruff clean, strict mypy clean across `166` source files.
- **Independent review:** A requirement-by-requirement review found no closure blocker. All three
  roots are consumed by coverage, bounded-context, and complete deterministic semantic-shard
  regressions; both large-scale modules carry registered `large_scale` and `slow` markers.
- **Honest limitation:** Authorship/originality is provenance evidence supported by the committed
  deterministic generator, not an independently machine-provable property. No production source,
  provider execution, or customer target is claimed.
- **Status:** `COMPLETE`.

## 2026-08-03 — V3-TOOLDIAG-002

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Make remaining deterministic scanner outcomes accurate and
  actionable under bounded macOS isolation: real success only for validated machine output,
  typed non-applicability and external prerequisites, and a distinct silent-failure diagnosis
  with retained private evidence paths.
- **Starting evidence:** The queue records real host reproduction against the committed
  realistic-scale Solidity fixture: Gitleaks could not read its bundled rules under isolation,
  OSV correctly found no package sources but was marked failed, Trivy lacked its offline database,
  and Slither exited non-zero without output. No one of these states is accepted as scanner
  success.
- **Next action:** Add focused negative/positive regressions around the shared scanner runner,
  adapter-specific classification, public report serialization, and exact isolation read grants
  before rerunning real local tools.
- **Pause checkpoint (2026-08-03T15:42:09Z):** Paused immediately at the operator's request.
  Both completed parallel slices remain in the worktree: trusted Semgrep/Gitleaks rule staging
  and typed scanner outcomes/report serialization. The Slither slice was stopped after its local
  implementation and tests were written; its diff still requires primary-agent review and final
  focused validation. No paid provider call, network operation, commit, push, or long-running
  validation was started during the pause. `git diff --check` passed. Resume without discarding
  or rewriting the preserved in-progress files.
- **Resume slice (2026-08-03T15:45:23Z):** Added the missing real-backend Semgrep case against
  committed `solidity_005k` without replacing its existing normalization canary. The combined
  focused scanner outcome, Slither, reporting, analysis-floor, and Solidity coverage matrix
  passed `250` tests in `12.07s`; no provider or network operation occurred.
- **Independent-review hardening (2026-08-03T15:59:46Z):** Strict Semgrep/Gitleaks parsing now
  rejects malformed, defaulted, reversed, out-of-root, and non-normalizable finding records;
  staged package rules are inode/link/mode/owner/byte revalidated before launch and made
  read-only to the macOS/bubblewrap child boundary; an actual wheel build/import regression
  proves both bundled rule files ship outside the editable source tree. Typed exit schemas now
  require safe relative stdout paths and bound empty-output digests. Default new evidence fields
  remain absent from legacy serialization so enclosing historical attempt hashes round-trip.
  Scanner completion now requires REAL, strictly validated, nonempty, observation-bound runtime
  evidence rather than a status string alone. Ruff and focused strict mypy passed; `451` focused
  tests passed in `18.81s`; the final real macOS matrix passed `4` in `15.58s`. Direct host
  `semgrep --version` was not retried after a local empty-trust-store diagnostic; Homebrew
  metadata reports `semgrep 1.172.0`, while the isolated scanner version probe and real analysis
  succeeded. Gitleaks is `8.30.1`, Slither `0.11.6`, and native solc is
  `0.8.30+commit.73712a01.Darwin.appleclang`. No paid provider call or public network was used.
- **Pre-full-suite checkpoint (2026-08-03T16:06:13Z):** The affected pipeline and reporting
  matrix passed `116` tests in `344.84s`; release-schema verification and the built-wheel
  resource regression passed `4` in `1.05s`; diff checks passed. The only warnings were inherited
  best-effort cleanup warnings for stale clean-Anvil temporary directories. The next command is
  the repository-wide static/full-suite gate; no ticket-complete claim has been made yet.
- **Exact-host diagnostic closure (2026-08-03T16:34:54Z):** A first expanded real-host matrix
  produced one useful negative result: OSV `128` emitted the current bounded no-source wording
  rather than the previously reproduced shorter wording, so it remained generic `FAILED`.
  The adapter now accepts only those two exact normalized no-source messages. An additional
  diagnostic suffix still fails classification. Ruff, focused mypy, `16` typed-outcome tests,
  and the exact real OSV assay passed; the complete real macOS matrix then passed `6` cases in
  `17.49s`, including REAL OSV `NOT_APPLICABLE` and REAL Trivy `UNMET_PREREQUISITE` evidence.
  The earlier exact-tree full suite before this narrow closure passed `4497` with `11` explicit
  skips in `1423.11s`; a second full run is starting because production code changed afterward.
- **Final result (2026-08-03T16:59:37Z):** `COMPLETE`. The exact final tree passed `4501`
  tests with `11` explicit external-prerequisite or paid-provider skips in `1430.04s`
  (`23m50s`). Ruff reported all `423` files formatted and no lint findings; strict mypy passed
  all `166` source files; release schemas and diff integrity passed. The skipped engines,
  rootless image, compiler-bound integrations, replay, and paid provider test remain explicit
  prerequisites and received no credit. No provider request, public network, target secret,
  wallet material, or additional spend was used. Trivy's prepared-cache consumption remains a
  later integration boundary and is documented as `UNMET_PREREQUISITE`; it did not prevent the
  ticket's typed-diagnostic acceptance criteria from completing.

## 2026-08-03 — V3-BOOTSTRAP-001

- **Status:** `COMPLETE`; final independent review found no remaining acceptance gap.
- **Defensive objective:** Remove the quality-before-quality-measurement cycle while keeping
  every audit-role and production-selection path fail closed for unmeasured identities.
- **Typed separation:** `ModelLineageConfig` now contains immutable declared identity and
  retention fields plus an optional nested `measured_quality` record. The nested record is
  atomic (`score`, `tier`, and hash-bound `measurement`), omitted while unmeasured, and rejects
  explicit null, partial records, flat legacy fields, invalid hashes, and tier/score mismatch.
  A legitimate measured zero remains distinguishable from missing evidence; no zero or sentinel
  is synthesized.
- **Measurement boundary:** Approved identity-only canonical and alias records can be resolved
  by the existing model benchmark target and egress controls without a prior quality value.
  Unapproved root lineages and retention above policy still fail before provider access.
- **Selection boundary:** Both the audit preflight and model registry reject an identity-only
  configured role. Maximum-assurance production validation additionally rejects an absent nested
  quality record even when otherwise valid opaque Tier-A evidence is supplied, and continues to
  require exact current independently verified qualification evidence.
- **Promotion transition:** `promote_qualified_model_lineages` is the single deterministic
  candidate-to-config quality attachment. It accepts no caller-supplied score, tier, or hash;
  derives them from exact current Tier-A results; validates candidate, artifact, verification,
  canonical ID, root, endpoint, output mode, benchmark report, expiry, and eligible-set joins;
  and rejects aliases, already-measured identities, pending/inconclusive/mock-only evidence,
  stale evidence, and mismatches. The transition itself does not grant runtime selection
  authority.
- **Schema and documentation:** Added generated `schemas/models_config.schema.json`; both
  example TOML files describe the same identity/quality boundary; model-selection and lineage
  review documentation now record the candidate registry, declared identity, explicit promotion,
  and separately verified production selection relationship.
- **Focused validation:** Registry/benchmark/promotion matrix passed `79` tests in `11.07s`;
  configuration/CLI passed `119` tests in `5.51s`; candidate, calibration, qualification,
  role, and CLI workflows passed `169` tests in `126.26s`; release-schema tests passed `2`.
  Full Ruff format check reported `419` files formatted, Ruff check passed, strict mypy passed
  all `165` source files, release schemas verified, both TOML templates parsed, and diff checks
  passed. The only warnings were inherited best-effort cleanup permission warnings for stale
  local clean-Anvil temporary directories.
- **External boundary:** No provider call, paid spend, network access, target repository, or
  operator secret was used. Real model qualification remains a later queue ticket and receives
  no credit here.
- **Repository-wide validation:** `.venv/bin/pytest -q --cache-clear` passed `4416` tests with
  `11` explicit external-prerequisite or paid-provider opt-in skips in `1293.89s` (`21m33s`).
  The skips were the unavailable rootless image/adversarial container cases, Echidna, Halmos,
  Medusa, offline replay compiler, realistic AST compiler, fork-differential compiler, Foundry
  fork compiler, and the deliberately disabled paid-provider integration. Two inherited
  best-effort cleanup warnings referenced stale permission-restricted clean-Anvil temporary
  directories and did not affect the result.
- **Independent review:** The first pass did not bind ordinary REAL production model execution
  to the opaque current qualification artifact. A manually populated nested quality record could
  therefore still authorize ordinary production roles, including aliases, even though the static
  record is intended to be descriptive rather than runtime authority. The full-suite result above
  predates this finding and will not be used as final acceptance evidence after the correction.
- **Next action:** Gate all REAL and UNVERIFIED production execution on current verified
  qualification while retaining explicit MOCK-only test execution without REAL evidence credit.
- **Boundary correction:** Added an execution-evidence-aware production qualification gate.
  Owned provider construction is treated as planned REAL execution and requires opaque current
  qualification before client construction or spend. Unknown evidence fails closed as
  UNVERIFIED. Closed-transport standard tests may omit production qualification only because
  their evidence is irreducibly MOCK; maximum-assurance remains qualification-bound even there.
- **Correction validation:** The focused runtime, registry, standard REAL preflight, and
  maximum-assurance MOCK preflight set passed `65` tests in `9.75s`. The standard REAL negative
  regression retained a zero-spend ledger and never constructed a provider client.
- **Next action:** Run the expanded affected suite and final ticket validation; the earlier
  repository-wide result will remain historical until it is superseded on the corrected tree.
- **Expanded pipeline validation:** `.venv/bin/pytest -q tests/integration/test_pipeline.py
  --cache-clear` passed all `106` tests in `311.41s`. The corrected boundary preserved all
  standard MOCK-only orchestration behavior. Affected-file Ruff passed, strict mypy reported no
  issues in the two changed source modules, and `git diff --check` passed.
- **Next action:** Run all changed model/config/schema tests, resolve independent read-only
  review findings, then supersede the historical repository-wide result on the corrected tree.
- **Independent review follow-up:** Three additional gaps were reproduced and corrected before
  checkpointing. First, MOCK qualification exemption is now bound to the exact closed in-memory
  transport, so mutating an injected network client's public evidence label cannot bypass
  qualification. Second, the generated schema now represents `measured_quality` as optional but
  non-null and carries the exact lowercase SHA-256 measurement pattern; both committed templates'
  commented identity-only and measured examples parse through the runtime model. Third,
  promotion now preserves declared aliases, while the existing exact-canonical opaque selection
  gates continue to prevent aliases from inheriting qualification. An end-to-end regression
  proves promoted alias-bearing output can pass current exact production validation only with
  the independently issued opaque capability.
- **API footgun removed:** `ModelRegistry.validate` no longer infers whether qualification is
  required from the profile. Every caller must explicitly declare measurement-only versus
  production-authoritative validation; the audit pipeline always supplies its immutable
  transport-derived requirement.
- **Follow-up focused validation:** The schema/template, promotion-to-production, transport
  relabel, runtime, and registry set passed `73` tests in `10.32s`.
- **Next action:** Run the full affected OpenRouter, generation-evidence, pipeline, model,
  configuration, and schema suites before repository-wide validation.
- **Final affected-suite validation:** OpenRouter and generation-evidence suites passed `307`
  tests in `2.22s`; the complete pipeline integration file passed `107` tests in `309.77s`;
  and all changed CLI, runtime, registry, benchmark, promotion, schema, and qualification-config
  tests passed `183` tests in `16.41s`. Only the two inherited best-effort cleanup permission
  warnings appeared. No real provider or network path executed.
- **Next action:** Run repository-wide formatting, lint, strict typing, schema/template checks,
  and full pytest on this corrected tree, then checkpoint only if final review remains clean.
- **Repository-wide static validation:** Ruff found all `419` files already formatted and all
  checks passed; strict mypy found no issues in `165` source files; release-schema verification,
  both complete TOML template parses, and `git diff --check` passed.
- **Next action:** Run the full pytest suite on the corrected tree, incorporate final independent
  review, and checkpoint only if both remain clean.
- **Final provenance hardening:** An adversarial review found that execution evidence still
  trusted a mutable public label and generic injected HTTPX mock transports. Evidence is now
  derived only from the exact base client and sealed transport identities. A dedicated internal
  test-only mock construction path is classified `MOCK`; generic injected clients remain
  `UNVERIFIED`. Both MOCK and owned REAL paths reject client, transport, handler, callable, URL
  mount, auth, hook, or environment-trust mutation before any request. Subclasses and concurrent
  label changes have no authority. Runtime/schema parity now also covers strict numeric scores,
  tier thresholds, immutable hash/model identifiers, and unique aliases.
- **Latest validation:** The focused schema, registry, runtime, and transport regression matrix
  passed `76` tests in `10.33s`; affected Ruff passed; strict mypy passed all `165` source files;
  and the complete OpenRouter/generation-evidence matrix passed `308` tests in `2.28s`. One
  superseded repository-wide run was deliberately interrupted after `57` passes and `5` skips
  when the mount/callable gap was found, so no acceptance result is claimed from it. No provider,
  network, target, operator secret, or additional spend was used.
- **Next action:** Run the complete pipeline integration file and changed model/config/schema
  matrix on this final tree, incorporate the final independent review, then run repository-wide
  validation.
- **Review-driven base URL/schema correction:** Owned provider evidence now snapshots the exact
  canonical base URL and rejects later redirection before a request; the MOCK seam also seals its
  configured base URL and refuses non-synthetic credentials. The generated conditional score
  subschemas compile under local Ajv 2020 strict mode. Cross-record case-insensitive ID uniqueness
  is explicitly documented as a runtime semantic constraint because draft 2020-12 cannot express
  that cross-item relation; the typed runtime loader remains authoritative and rejects it.
- **Superseded run and revalidation:** The pipeline run started before these corrections was
  deliberately interrupted after `32` passing cases in `145.89s`; no acceptance result is claimed.
  On the corrected tree, strict mypy passed `165` source files, Ajv strict schema compilation
  returned `AJV_STRICT_OK`, focused correction tests passed `8`, the OpenRouter/generation suite
  passed `310` in `2.28s`, and the affected CLI/model/config/schema suite passed `188` in `16.34s`.
  No provider, network, target, secret, or spend was used.
- **Next action:** Run the complete pipeline integration file on the corrected tree, incorporate
  final independent review, and then run repository-wide validation.
- **Issuer-held transport authority:** A final review proved that an injected generic mock could
  rewrite all prior instance snapshot fields and manufacture the descriptive MOCK label. Trusted
  evidence now requires an exact immutable binding issued into a module-held weak identity
  registry only by exact base-client construction; instance fields, labels, subclasses, and
  injected transports cannot create that binding. A regression rewrites every former instance
  flag and still fails closed before the injected handler runs.
- **Trusted test-code boundary:** The explicit mock handler remains repository-controlled test
  code rather than a production isolation primitive. It can receive only an explicitly synthetic
  credential, always records MOCK evidence, and cannot satisfy real maximum-assurance model-review
  credit. Mutable handler behavior is therefore not claimed as network isolation; real execution
  continues to require the owned canonical transport and opaque production qualification.
- **Superseded pipeline result:** The next pre-registry pipeline run exposed one expected test
  adaptation: a realistic local leak canary lacked the required synthetic marker. It was stopped
  after `1` failure and `31` passes in `140.45s`; no acceptance result is claimed. The canary now
  retains its realistic prefix while explicitly identifying itself as synthetic. Seven focused
  provenance/canary cases passed in `4.22s`, Ruff passed, strict mypy passed `165` source files,
  and the full OpenRouter/generation suite passed `310` in `2.57s`. No external call or spend ran.
- **Next action:** Run the complete pipeline integration file on the issuer-held-authority tree,
  incorporate final read-only review, and then run repository-wide validation.
- **Owned object-graph correction:** Read-only review then proved two deeper mutations remained:
  an instance-level HTTPX authentication dispatcher and replacement connection pool retained a
  REAL classification. The issuer-held binding now covers the exact client/transport attribute
  sets, canonical base URL, redirect settings, owned pool identity and attribute set, pool request
  callable, and HTTPX build/auth/redirect/send dispatch callables. Both reproduced mutations now
  return `UNVERIFIED` and fail before their fabricated path can run.
- **Operational evidence correction:** Every OpenRouter request-planning, routing, generation,
  usage, and debug-evidence decision now derives the trusted classification directly; the mutable
  public label is descriptive and cannot change behavior or serialized evidence. A regression
  sets the label to REAL on a MOCK transport and still records MOCK usage. Twenty-five legacy unit
  cases had been using that label mutation to simulate REAL branches. Those cases now use clearly
  named, test-local mocked-control-flow helpers; generation retrieval remains MOCK except within
  the explicitly mocked REAL-reconciliation branch. None is credited as a real provider test.
- **Superseded run and validation:** The pipeline run predating these corrections was deliberately
  interrupted after `39` passes in `255.57s`; no acceptance result is claimed. Six focused
  object-graph/label cases passed, Ruff passed, strict mypy passed `165` source files, and the full
  OpenRouter/generation suite passed `312` in `2.43s`. No provider, network, target, secret, or
  spend was used.
- **Next action:** Run the complete pipeline integration file on the final object-graph-bound
  tree, incorporate final review, and then run repository-wide validation.
- **Nested transport closure:** A subsequent read-only review reproduced mutations below the
  transport identity itself. The issuer-held binding now snapshots the complete connection-pool
  field identities, pool connection/assignment/close dispatch, lazy network-backend identity and
  initialization dispatch, exact inner AnyIO backend dispatch, and relevant `__getattribute__`
  authority. Legitimate lazy AnyIO backend initialization remains accepted; replacement fields,
  instance dispatch, and class dispatch all revoke REAL evidence before request execution.
- **Class-dispatch validation:** Five focused pool/backend/HTTPX mutation and legitimate-init
  cases passed. Affected Ruff passed, strict mypy passed all `165` source files, and the complete
  OpenRouter/generation-evidence matrix passed `321` tests in `2.47s`. Unit helpers that select
  REAL control-flow branches remain explicitly mocked branch tests and are not real provider
  execution evidence. No provider, network, target, secret, or spend was used.
- **Superseded pipeline result:** A pipeline run started before nested pool configuration was
  sealed was deliberately interrupted after `32` passing cases in `53.16s`; no acceptance result
  is claimed from it.
- **Newly available objective bytes:** `docs/remediation/v3/product_completion_goal.txt` is now
  committed at `517559e5c9526f78e516374ebc194933d01eac7f` and hashes exactly to the previously required
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43` value. It is preserved and
  excluded from this ticket's checkpoint; `V3-OBJECTIVE-001` can be reopened after this bounded
  ticket completes.
- **Next action:** Run the complete pipeline integration file on the class-dispatch-sealed tree,
  incorporate final read-only review, and then run repository-wide validation.
- **Request-boundary and pool-content closure:** The final read-only probe found that replacing
  the client `_bounded_request` method or appending a response-producing object to the existing
  pool connection list could still preserve descriptive REAL evidence. Central trusted
  classification now seals the client-owned request/evidence callables, internal callers use the
  snapshotted request boundary, and the original request implementation calls the snapshotted
  provenance validator. REAL owned clients disable keepalive, reject nonempty connection or
  request queues before dispatch, and serialize their pool use with an issuer-held lock. MOCK
  clients retain concurrent test execution and cannot earn REAL credit.
- **No-progress isolation:** The first combined unit rerun exposed a MOCK concurrency deadlock
  caused by applying the REAL serialization lock too broadly. It was interrupted after `123`
  passes and isolated to `test_concurrent_usage_records_account_only_their_own_request_cost`.
  Restricting serialization to REAL owned transport restored the intended MOCK concurrency; the
  isolated concurrency plus both new negative regressions passed `3` tests in `0.53s`.
- **Corrected focused evidence:** Affected formatting and Ruff passed; strict mypy passed all
  `165` source files; and the complete OpenRouter/generation-evidence matrix passed `323` tests in
  `2.49s`. The two false-REAL regressions reject before the fabricated response path runs. No
  provider, network, target, secret, or spend was used.
- **Next action:** Run the complete pipeline integration file on this corrected tree, confirm the
  bounded re-review, and then run repository-wide validation.
- **Independent closure recheck:** The same two no-network probes now report `UNVERIFIED`, raise
  `OpenRouterPrivacyError`, leave authentication false, and execute neither fabricated response
  path. The reviewer found no failure in the bounded recheck and edited no files.
- **Operator pause:** The restarted pipeline integration gate was interrupted cleanly at the
  operator's request after `79` passing tests in `302.30s`; no failure had surfaced. This partial
  result is not acceptance evidence and must be rerun from the beginning. No provider request,
  network access, target execution, operator-secret read, reservation, or paid spend occurred.
  No test or child process remains active. The ticket remains `IN_PROGRESS`, and no checkpoint
  commit was created from the not-yet-final tree.
- **Resume action:** Rerun `.venv/bin/pytest -q tests/integration/test_pipeline.py --cache-clear`,
  then the changed model/config/schema matrix, repository-wide static gates, and complete pytest.
- **Autorun resumed:** The authoritative 1,417-line objective was reread from the operator
  attachment and reverified at SHA-256
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`. Repository guidance,
  both durable queues/worklogs, and Git state were rechecked. Source checkpoint
  `116657c0a3d4ecc23af457a1a7a93977be947f45` was clean and one commit ahead of the SSH remote;
  that unrelated queue-only operator change is preserved. The complete pipeline gate is being
  rerun from the beginning; no paid-provider opt-in is enabled.
- **Final pipeline gate:** `.venv/bin/pytest -q tests/integration/test_pipeline.py --cache-clear`
  passed all `113` tests in `666.31s` (`11m06s`) on the request-boundary and pool-content-sealed
  tree. Two inherited best-effort cleanup warnings referenced stale permission-restricted
  clean-Anvil temporary directories and did not affect the result. No provider, network,
  target, secret, reservation, or spend was used.
- **Independent acceptance review:** Read-only review found no material ticket acceptance gap;
  its focused matrix passed `9` tests in `7.69s`. The reviewer explicitly classified all of this
  as unit or synthetic/mock integration evidence, not a real benchmark, qualification, provider,
  or production-audit execution.
- **Next action:** Run the complete model/config/schema acceptance matrix, then repository-wide
  formatting, lint, strict typing, schema/template checks, and full pytest.
- **Broad-matrix stale expectation:** The first model/config/schema matrix completed with
  `1 failed, 739 passed in 469.10s`. The sole case still expected a caller-injected
  `httpx.MockTransport` to receive descriptive MOCK evidence. The hardened issuer boundary
  correctly returns `UNVERIFIED` and refuses the injected client before discovery sealing. The
  regression now asserts that stronger negative behavior and its exact focused test passed in
  `1.20s`; affected Ruff passed. No production behavior or acceptance threshold was weakened.
- **Next action:** Rerun the complete `740`-test model/config/schema matrix, then continue to
  repository-wide gates.
- **Corrected broad acceptance gate:** `.venv/bin/pytest -q tests/unit/test_cli.py
  tests/unit/test_config.py tests/unit/test_model_*.py
  tests/unit/test_openrouter_qualification_config.py tests/unit/test_release_schemas.py` passed
  all `740` tests in `507.83s` (`8m27s`). The two inherited best-effort stale temporary-tree
  cleanup warnings remained non-failing. No provider, network, target, secret, reservation, or
  spend was used.
- **Pre-full-suite static gates:** `.venv/bin/ruff format .` left all `419` files unchanged;
  `.venv/bin/ruff check .` passed; strict mypy passed all `165` source files; committed release
  schemas verified without drift; both TOML templates parsed; the models schema compiled under
  Ajv 2020 strict mode; and `git diff --check` passed.
- **Next action:** Run `.venv/bin/pytest -q --cache-clear`, then perform the final diff/artifact
  review and checkpoint the ticket only if the complete suite is green.
- **Repository-wide gate result:** `.venv/bin/pytest -q --cache-clear` completed in `5501.57s`
  (`1h31m41s`) with `4335 passed`, `16 skipped`, `24 failed`, and `88 errors`. The errors are
  concentrated in listener-backed Hardhat/RPC fixtures and report managed-environment
  `PermissionError: [Errno 1] Operation not permitted` during local socket creation. The failures
  are concentrated in candidate benchmarking, mocked OpenRouter routing, context/token planning,
  and Hardhat relay tests. This result is failure evidence, not acceptance evidence; the ticket
  remains `IN_PROGRESS`. Focused diagnosis is running, and no threshold or isolation control will
  be weakened to make the gate pass. No paid-provider opt-in, provider request, target execution,
  operator-secret read, reservation, or additional spend occurred.
- **Next action:** Resolve genuine bootstrap regressions with focused tests, keep environmental
  listener denials explicitly classified, then rerun the affected matrix and the complete gate.
- **Failure isolation:** The `24` failures split into `19` stale test-harness expectations and
  `5` AF_UNIX listener denials. Candidate benchmark tests still supplied a caller-owned
  `httpx.MockTransport`; context/token tests did the same; and five discovery tests used
  synthetic identity evidence whose fixed date had crossed the real seven-day TTL. Production
  behavior was correct: injected clients remained `UNVERIFIED`, and expired identity evidence
  remained non-creditable. The tests now use the sealed internal test-only MOCK seam and generate
  fresh synthetic discovery evidence without changing the production TTL. No production code or
  acceptance threshold changed.
- **Focused model validation:** `.venv/bin/ruff check
  tests/unit/test_candidate_benchmark.py tests/unit/test_context_serialization_boundary.py
  tests/unit/test_model_discovery.py tests/unit/test_openrouter.py
  tests/unit/test_token_planning_acceptance.py` passed. The combined command
  `.venv/bin/pytest -q tests/unit/test_candidate_benchmark.py
  tests/unit/test_candidate_benchmark_campaign.py tests/unit/test_candidate_benchmark_cli.py
  tests/unit/test_candidate_reasoning_profile_campaign.py
  tests/unit/test_context_serialization_boundary.py tests/unit/test_openrouter.py
  tests/unit/test_token_planning_acceptance.py --cache-clear` passed all `271` tests in `7.31s`.
  Two inherited stale temporary-tree cleanup warnings were non-failing.
- **Listener classification:** Under the managed sandbox, the three listener-backed files
  produced `36 passed, 88 errors`; every error was an AF_INET bind denied with `EPERM`. The relay
  file produced `9 passed, 5 failed`; each failed before product logic at AF_UNIX bind with the
  same `EPERM`. An exact host-policy rerun using `.venv/bin/pytest -q
  tests/unit/test_read_only_rpc_bridge.py tests/unit/test_read_only_rpc_unix_bridge.py
  tests/unit/test_hardhat_isolation_backend.py tests/unit/test_hardhat_loopback_relay.py` passed
  all `138` tests in `51.57s`. This is local test execution, not live RPC or external-network
  evidence.
- **Next action:** Rerun the complete repository suite with the same host policy so local
  listeners are available; retain the managed-sandbox failure as environmental evidence and
  claim acceptance only from the completed host-policy result.
- **Final repository-wide gate:** `.venv/bin/pytest -q --cache-clear` under the local host policy
  passed `4452` tests with `11` explicit external-prerequisite or paid-provider opt-in skips and
  zero failures/errors in `1385.11s` (`23m05s`). The skips were the unavailable rootless image
  cases, Echidna, Halmos, Medusa, offline replay compiler, realistic AST compiler,
  fork-differential compiler, Foundry fork compiler, and deliberately disabled paid-provider
  integration. The two inherited cleanup warnings concern stale permission-restricted temporary
  clean-Anvil directories and did not affect the result.
- **Exact schema/template checks:** `.venv/bin/python -c 'import tomllib; from pathlib import
  Path; [tomllib.loads(Path(path).read_text(encoding="utf-8")) for path in
  ("mmaudit.example.toml", "src/mmaudit/templates/mmaudit.example.toml")];
  print("TOML_TEMPLATES_OK")'` returned `TOML_TEMPLATES_OK`. `node -e 'const
  fs=require("fs"); const Ajv2020=require("ajv/dist/2020").default; const
  schema=JSON.parse(fs.readFileSync("schemas/models_config.schema.json","utf8")); new
  Ajv2020({strict:true,allErrors:true}).compile(schema); console.log("AJV_STRICT_OK")'` returned
  `AJV_STRICT_OK`.
- **Final static gate:** After Ruff normalized one blank line in the token-planning regression,
  that file's `5` focused cases passed in `2.10s`; all `419` files passed Ruff format check and
  Ruff lint, strict mypy passed all `165` source files, release schemas verified without drift,
  and `git diff --check` passed. The formatting change was mechanical and followed by its focused
  semantic test.
- **Completion boundary:** No paid-provider opt-in, provider request, external target, operator
  secret, reservation, or spend was used. The final evidence is deterministic/unit, synthetic
  MOCK integration, and local listener execution only; it grants no real benchmark,
  qualification, ensemble, or production-audit credit.
- **Next action:** Create and push the isolated checkpoint, then begin `V3-TOOLDIAG-002`.

## 2026-08-03 — V3-OBJECTIVE-001 and V3-TARGETSPEC-001 dependency disposition

- **V3-OBJECTIVE-001 status:** `BLOCKED_TECHNICAL`.
- **Exact source audit:** The required SHA-256 is
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
  The exact nonignored-file command shown in `LAST_COMMAND` hashed `918` files and returned
  `MATCHES=0`. Only the queue, this worklog, and `review_traceability.json` mention the digest,
  and none supplies a canonical source path.
- **Integrity boundary:** The separate 1,812-line Corrovera product vision hashes to
  `77e5ab93225377e86e4ad08f09775deaac86b927a6817b8dca9eaa6f81b8a2a6` and cannot substitute
  for the absent objective. The objective was not reconstructed, summarized, or paraphrased.
- **V3-TARGETSPEC-001 status:** `BLOCKED_TECHNICAL` on its explicit objective dependency. Its
  precedence and reconciliation acceptance criteria cannot be completed without knowing the
  missing objective's content.
- **Operator prerequisite:** Supply the exact byte stream or canonical readable source path
  matching the required objective digest. No other safe portion remains in these two tickets.
- **Continuation:** `V3-BOOTSTRAP-001` is dependency-free and is now `IN_PROGRESS`.

## 2026-08-02 — V3-SCHEDULER-001

- **Status:** `COMPLETE`; isolated checkpoint pending.
- **Defensive objective:** Represent orientation, blind shard review, finding reduction,
  cross-shard integration, adversarial cross-examination, multi-lineage validation/falsification,
  and evidence-capped judgment as durable, resumable, fail-closed passes.
- **Starting boundary:** Reuse existing request, context, candidate, specialist, verification,
  falsification, judgment, and run-manifest evidence. This ticket will not call a provider, grant
  review credit from scheduled work, or make an incomplete mandatory pass representable as
  complete.
- **Pass-two invariant-terminal diagnostic:** The first post-context-custody maximum-assurance
  rerun failed closed after `145.87s` with two invalid accounting-specialist tasks. Exact local
  artifacts traced both to one canonical invariant surface: generators emit `inv-<20 hex>` IDs,
  while terminal validation recognized only `inv:`. Independent reconstruction also proved a
  latent HIGH-severity ambiguity: the synthetic reviewer and validator could resolve a generic
  `credit` symbol to an unrelated same-name state in another contract if the delimiter alone were
  corrected.
- **Invariant-terminal remediation:** Canonical invariant IDs and enum-bound template IDs now
  derive composite terminal authority only from request-bound exact entity IDs and locations.
  Reachability rechecks the adjacency-disambiguated final frontier, and the synthetic provider
  prefers an exact location-and-ID target instead of a cross-contract same-name symbol. The new
  negative regression accepts the exact Fee-like entry-to-state path and rejects the unrelated
  Safe-like path. Affected Ruff and mypy passed; model-review/model-coverage tests passed `91`
  cases, the focused scheduler accounting integration passed in `9.49s`, and `git diff --check`
  passed. No assurance gate was weakened and no real provider call ran.
- **Reproduction join diagnostic:** The materially changed maximum-assurance run advanced through
  the corrected invariant review and independent verifier, then failed closed after `130.63s`
  while building the final run manifest. Its retained `reproduction-results.json` contains three
  generated specifications but only the result for `Exploit1`; `Exploit2` and `Exploit3` have no
  terminal result row. Production currently plans tests from the exact pass-four validation
  workset but executes them through a later decision-filtered eligibility map, silently skipping
  a specification when those inventories diverge. The manifest rejection is correct and remains
  unchanged. The next bounded slice will make every accepted specification terminate explicitly
  and prove the exact key join before another end-to-end run.
- **Reproduction join remediation:** The sealed pre-verifier planned-candidate inventory now owns
  every generated test identity. Post-verifier eligibility controls only whether the local runner
  executes: a pruned candidate receives an explicit `NOT_ATTEMPTED` result with zero attempts and
  no command or integrity evidence, while an unknown specification candidate fails immediately.
  This preserves exact specification/result custody without allowing nonexecution to satisfy the
  existing real-attempt gate. The focused regression and generated-reproduction/host-contract
  matrix passed `14` tests in `12.40s`; affected Ruff, source mypy, and `git diff --check` passed.
  Independent artifact review confirmed the retained failure and the remediation invariant. No
  provider or network call ran.
- **Post-join report diagnostic:** The materially changed maximum-assurance run passed the prior
  pass-six join and final manifest boundary, then failed a later report-content assertion after
  `152.42s`. The accepted report retained only the reproduced ReentrantBank finding; AccessVault,
  SpotOracleLender, and UnsafeUUPS were absent from the expected unsafe-contract set. The exact run
  is retained under pytest run `3534` for artifact-by-artifact tracing. This is not yet classified
  as a stale fixture or production evidence-loss defect, and the unchanged end-to-end command will
  not be retried until that distinction is proven.
- **Missing-candidate root cause and remediation:** Pass-02 evidence proved that no later pass
  dropped a candidate: AccessVault, SpotOracleLender, and UnsafeUUPS were never created. A blind
  specialist task could declare a primary shard while disposing only a semantic-neighbour surface;
  the scheduler now retains neighbour assignments but adds an exact whole-file disposition for
  every otherwise-unreviewed primary source. Separately, the synthetic provider incorrectly used
  fine-grained surface identity as its candidate gate even when an exact `SOURCE_FILE` request and
  source excerpt had been delivered. Synthetic candidate identity now binds the logical request to
  the exact provider-visible excerpt path, line range, content hash, and verified bytes. The full
  model-coverage unit file passed `56` tests; the primary-shard regressions passed `2`; the combined
  exact synthetic subset passed `5` with `51` deselected. Affected Ruff, source mypy, and diff checks
  passed. No provider or network call ran.
- **Specialist execution accounting remediation:** The scheduler journal now exposes a distinct
  structurally successful review inventory without promoting MOCK evidence to REAL. Specialist
  artifacts bind host-accepted outcomes only to scheduler-succeeded requests, record one explicit
  execution-evidence class, reject mixed REAL/MOCK role evidence, and retain null scalar summaries
  for multi-context roles. Mock workflows may therefore be described as completed test execution,
  while `completed_specialist_roles`, substantive model coverage, the minimum analysis floor, and
  maximum-assurance role credit remain REAL-only. Failed or unbound scheduler tasks cannot become
  descriptive successes. The combined specialist, scheduler-journal, and primary-shard matrix
  passed `106` tests in `8.87s`; four targeted assurance regressions passed in `18.05s`; the exact
  synthetic fixture subset passed `5` in `0.23s`; affected strict mypy, Ruff, and diff checks passed.
  An earlier full assurance run was deliberately interrupted after `68` tests and `279.90s` because
  it predated the final custody refinement, so no result is claimed from that run. No provider or
  network call ran.
- **Authoritative coverage-boundary migration:** The next materially changed end-to-end run
  completed the audit and artifact pipeline in `158.08s`, retained all four expected unsafe-fixture
  findings, and passed the reproduction and specialist-execution checks. It then reached a stale
  assertion requiring every enum member—including supplemental whole-file `SOURCE_FILE` custody—to
  appear in the authoritative product model-surface denominator. The typed coverage builder and its
  permanent unit regression intentionally reconstruct the denominator from audited Solidity
  entities, graphs, invariants, and templates; whole-file scheduler requests are supplemental and
  cannot inflate it. The E2E assertion now excludes only `SOURCE_FILE`, requires zero reviewed
  surfaces and zero reviewer/lineage credit for MOCK usage, and retains every sealed but uncredited
  evidence reference. Four focused authoritative/supplemental coverage cases passed in `0.63s`;
  Ruff and diff checks passed. Retained report artifacts also prove exact cross-examination usage
  joins and the required `0/31` `not_analyzed` model-role gate. No provider or network call ran.
- **Mock coverage provenance remediation:** The next run passed the corrected coverage-kind
  boundary and again reached final artifacts in `158.13s`, then proved that prefiltering coverage
  input to REAL usage erased the explicit reason its sealed MOCK review artifacts received no
  credit. Coverage construction now receives only structurally creditable, scheduler-succeeded
  review usage and performs its existing REAL/certification checks internally. This preserves the
  explicit MOCK-exclusion limitation and uncredited forensic references without changing the
  zero numerator. The minimum analysis floor, successful role inventory, and maximum-assurance
  inputs continue receiving only REAL creditable usage. A focused production scheduler wiring
  regression passed in `4.07s`; two mock/supplemental coverage cases passed in `0.25s`; affected
  Ruff, strict pipeline mypy, and diff checks passed. No provider or network call ran.
- **Changed-boundary end-to-end validation:** `.venv/bin/pytest -q
  tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete
  --durations=5` passed `1` test in `156.99s`. The run retained all expected unsafe-fixture
  findings and safe-control rejection, exact reproduction joins, seven-pass scheduler custody,
  descriptive MOCK specialist completion with zero REAL credit, supplemental source custody outside
  the authoritative denominator, explicit MOCK-exclusion provenance, sealed report artifacts, and
  an honest fail-closed downgraded result. Pytest emitted only the previously observed macOS
  temporary cleanup permission warnings. No provider or network call ran.
- **Consolidated scheduler validation:** The stable pre-format tree passed `28` scheduler pipeline
  integration tests in `51.94s`, `224` scheduler/identity unit tests in `16.69s`, `208` assurance
  tests in `424.28s`, and `34` release-schema/scheduler-manifest tests in `6.71s`. Full mypy passed
  over `165` source files, Ruff lint passed, and release-schema generation/verification passed. The
  full pipeline integration file passed `103` tests and exposed two stale expectations: an
  intentionally all-INCONCLUSIVE fake source audit now correctly fails mandatory pass 2, and a
  timed-out mandatory task preserves successful peer candidates without promoting them through
  unexecuted verifier/judge passes. The post-judge fixture now emits a substantive source
  disposition and proves all seven passes completed; the timeout regression proves exact candidate
  IDs survive in rejected evidence while the scheduler stops after pass 2. Both focused cases
  passed in `5.37s`. A permanent unit negative proves INCONCLUSIVE blind source dispositions never
  earn custody. No production gate was weakened and no provider or network call ran.
- **Preview schema TOCTOU closure:** Scheduler request preview now returns the schema hash from the
  single sealed structured-output request plan instead of regenerating the schema after planning.
  A race regression replaces the public schema generator after the plan is built and proves no
  second generation occurs. The new race, exact preview/usage join, and INCONCLUSIVE source-custody
  negative passed `3` tests in `0.54s`; affected Ruff, strict mypy, and diff checks passed.
- **Repository-wide gate diagnosis:** The exact `.venv/bin/pytest -q` gate did not pass and its
  detached terminal session expired before the summary could be retained. Pytest's historical
  cache initially listed `145` nodes, but focused collection proved that inventory mixed obsolete
  renamed tests with current failures and therefore was not a valid current-failure count. Current
  model/provider files passed `430` tests, the complete OpenRouter file passed `208`, and the
  isolation/RPC cluster passed all `208` cases when local socket creation was permitted. The broad
  error burst was the managed sandbox's socket restriction. One genuine stale test fixture changed
  floating-point cost fields without their exact-decimal compatibility fields; the fixture and its
  test-only rejection normalizer now update both representations, and all `61` real-provider
  harness unit tests pass. A clean-cache full run with local loopback/Unix-socket permission is next.
- **Clean repository-wide gate:** `.venv/bin/pytest -q --cache-clear` passed `4399` tests with
  `11` explicit external-prerequisite skips in `1293.27s` (`21m33s`) under the local-only socket
  mode required by the isolation tests. The skipped cases remain unavailable rootless images,
  Echidna, Halmos, Medusa, pinned compiler/replay/fork integrations, the explicitly opted-out paid
  provider test, and realistic-scale AST validation; none was promoted to passing evidence. Two
  inherited pytest cleanup warnings reference old permission-restricted clean-Anvil garbage trees
  and did not affect the run. No provider, public network, live target, external engine, or secret
  was used.
- **Final static, schema, and CLI gates:** `.venv/bin/ruff format .` left all `418` files
  unchanged; `.venv/bin/ruff check .` passed; strict `.venv/bin/mypy` passed all `165` source
  files; and `.venv/bin/python scripts/generate_release_schemas.py` verified the committed schemas
  synchronized. Root CLI help and `verify-run --help` exited `0`. One legacy operator invocation,
  `mmaudit audit --help`, exited `2` because the command is named `run`; the corrected
  `mmaudit run --help` exited `0`. `git diff --check` passed. Added-diff and untracked-file scans
  found no private-key marker, OpenRouter-key assignment, mnemonic/seed assignment, debug break,
  or generated runtime artifact. The `.env` file was not read.
- **Independent final-review finding and remediation:** Production review found one fail-closed
  ordering defect: pass-three activation hashed blind and pending candidates before overlapping
  formal counterexamples were attached, while its reduction output hashed the later evidence-rich
  payloads. Useful formal evidence therefore made the reducer invalidate itself. Pending execution
  candidates and formal evidence are now finalized before one shared activation projection is
  sealed and reused by the deterministic output. The strengthened regression executes the real
  seven-pass pipeline, opens durable pass-three activation/output evidence, proves the fixed hashes
  match, proves at least one formal-bound candidate is retained, and proves the old-order projection
  differs. It and the nominal seven-pass persistence test passed `2` cases in `7.56s`; affected
  Ruff/format/diff checks passed. The complete scheduler integration file then passed `30` tests
  in `54.17s`; final Ruff format/check, strict mypy over `165` source files, and release-schema
  verification passed. Independent re-review found no remaining material production or regression
  gap. Repository-wide validation must be repeated after this change.
- **Final post-review gate:** `.venv/bin/pytest -q --cache-clear` passed `4401` tests with `11`
  explicit external-prerequisite skips in `1299.39s` (`21m39s`) under the required local-only
  loopback/Unix-socket mode. No failure occurred. The skips preserve unavailable rootless images,
  Echidna, Halmos, Medusa, pinned compiler/replay/fork integrations, realistic-scale AST, and the
  explicitly disabled paid-provider test as unavailable; none received passing credit. The two
  inherited permission-restricted clean-Anvil garbage cleanup warnings remained non-failing.
- **Independent closure reviews:** Production review found no remaining fail-open, privacy, cost,
  resume, identity, or formal-order defect after the remediation. Acceptance review found stable
  identity, crash/resume, mandatory-pass rejection, normalized evidence, report/manifest joins,
  CLI tamper rejection, and paired unsafe/safe fixture coverage substantive. Hygiene review found
  no secret, host path, symlink/executable untracked file, runtime artifact, cache, or log. The
  operator-authored Corrovera product vision is preserved for a separate commit. Real multi-lineage
  model execution remains explicitly provisional until qualification; MOCK evidence grants no REAL
  credit.
- **Staged-diff normalization:** The first staged diff check rejected six synthetic fixture files
  with one extra blank line at EOF. Removing those lines changed derived source hashes and exposed a
  brittle test-only request order; production correctly requires stable surface-ID ordering. The
  fixture test now sorts its two requests by `surface_id`, both fixture-dependent regressions passed
  in `8.93s`, and `git diff --cached --check` is clean. This exact tree postdates the `4401`-pass
  run, so no final-tree claim is made until the full gate repeats.
- **Post-normalization full-gate diagnostic:** The exact full run emitted one early failure marker;
  it was deliberately interrupted during the next long pipeline case rather than allowed to spend
  another full cycle on a known-bad run. Fresh pytest cache identified only
  `test_real_counterexample_originates_pipeline_finding_but_safe_control_does_not`. That real local
  execution-origin case passed alone under the same isolation permission in `16.32s`; inside the
  restricted sandbox it correctly skipped because hardened isolation is unavailable. The failure
  is therefore not yet reproducible in isolation. Its preceding local Foundry/economic sequence
  must be tested before changing production or retrying the unchanged full command.
- **Execution-origin non-reproduction:** The entire economic predecessor sequence followed by the
  execution-origin test passed `21` cases in `91.74s`. The remaining adversarial and clean-chain
  lifecycle predecessors followed by execution-origin passed `4` with `1` explicit rootless-image
  skip in `17.45s`. Along with its isolated `16.32s` pass, two materially different order tests did
  not reproduce the failure. It is therefore a transient local integration observation, not a
  basis for changing production. One unchanged full retry is permitted; a repeated failure will be
  retained and scoped to that integration under the no-progress rule.
- **Exact normalized-tree completion gate:** The single permitted unchanged full retry passed
  `4401` tests with `11` explicit external-prerequisite skips in `1299.53s` (`21m39s`). The
  execution-origin integration passed in normal collection order and the transient failure did not
  recur. The external-prerequisite skips remain unchanged and receive no passing credit. No
  provider, public network, live target, external engine, or secret was used. This supersedes the
  earlier pre-normalization full-suite evidence as the ticket's final complete-tree gate.
- **Checkpoint:** V3-SCHEDULER-001 was committed as
  `136f8322aee78f53812461f20c4987fc6b6b1918` (`Add resumable seven-pass audit scheduler`) and
  pushed to `origin/main` over SSH. The operator-authored Corrovera product vision was kept out of
  that isolated checkpoint, committed separately as
  `3d97425d5db42bbbda776dfc3abe27270670b127`, and pushed over the same SSH remote.
- **Typed response and surface-custody closure:** Every model pass now uses its exact canonical
  response-schema digest and a strict typed payload. Candidate-review tasks retain a nonempty,
  deterministic requested-surface manifest and response artifact joined to the scheduled request,
  provider prompt/context/response/schema hashes, and any host-accepted specialist outcome. Typed
  host outputs bind pass-3 candidate inventory, pass-4 semantic inventory and downstream candidate
  partitions, and pass-6/pass-7 output identity to their activation inputs. Maximum assurance now
  requires the public scheduler request fields to join one-for-one to runtime surface artifacts;
  missing, duplicate, wrong-manifest, or wrong-context artifacts fail closed. The scheduler
  model/manifest/journal matrix passed `103` tests in `18.52s`; nominal assurance plus the six
  permanent false-COMPLETE assays and three new artifact-tamper cases passed `10` tests in
  `36.95s`. Affected Ruff checks and production assurance mypy passed; no provider call ran.
- **Production integration diagnostic:** `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py --maxfail=20` passed `7` cases and failed `6` in
  `26.25s`. The live pipeline has not yet migrated its candidate-review request/artifact into the
  host-accepted specialist outcome, so maximum campaigns fail closed rather than claiming blind
  review completion. The failed first run also leaves no resumable completed journal, and the
  verifier/judge omission assays correctly cannot reach their intended later passes. These are
  active production integration defects assigned to the pipeline slice; no assurance gate was
  weakened and no provider or network call ran.
- **Full assurance regression diagnostic:** `.venv/bin/pytest -q
  tests/unit/test_assurance.py` passed `190` cases and failed `17` in `382.22s`. The failures are
  retained evidence of three stale fixture assumptions: copied or tampered REAL usage was still
  asserted creditable despite non-transferable runtime authority; nominal runtime construction
  omitted the exact configuration later evaluated, leaving scheduler bindings intentionally
  incomplete; and one falsifier test appended calls outside the exact scheduler inventory. These
  are test-fixture migrations, not production-gate failures. No assertion or threshold has been
  weakened and no provider or network call ran.
- **First exact failure rerun:** `.venv/bin/pytest -q --lf
  tests/unit/test_assurance.py` passed `15` of the previously failing cases and retained `2`
  fixture failures in `117.07s`. The remaining cases referenced a removed unscheduled `falsifier`
  role and looked up scheduler-added candidate-falsifier models in static configuration rather
  than the exact qualification artifact. Production evidence remained fail closed; the next
  focused migration uses only the two scheduler-owned candidate-falsifier requests.
- **Exact fixture closure:** The two remaining cases now select the candidate-falsifier requests
  already scheduled in the campaign and resolve their two independent root lineages from the
  exact qualification artifact. `.venv/bin/pytest -q
  'tests/unit/test_assurance.py::test_reasoning_authority_mismatch_revokes_runtime_credit[wrong_role_pair_binding]'
  tests/unit/test_assurance.py::test_high_critical_cross_examination_requires_two_lineages`
  passed `2` tests in `14.14s`. No unscheduled usage was appended and no provider call ran.
- **Full assurance closure:** `.venv/bin/pytest -q tests/unit/test_assurance.py` passed all `207`
  cases in `480.38s`. Copied or tampered serialized REAL records remain non-creditable without
  fresh runtime authority, scheduler bindings use the exact evaluated configuration, and the
  independent-falsifier assay uses only scheduler-owned qualified requests. No production gate,
  threshold, or runtime-authority rule was weakened and no provider or network call ran.
- **Cycle-free retained-journal contract:** Resumed runs can bind one exact prior direct-child
  owner without copying its private journal. The typed, self-hashed reference commits the owner
  and consumer run IDs, exact relative physical-journal location, campaign, scheduler manifest,
  summary, journal-evidence, public-artifact, and event-chain identities; same-run, path/basename,
  hash, and recursive-field substitution fail closed. The contract is registered in release
  schema generation as `schemas/scheduler_retained_journal_reference.schema.json`, and the
  scheduler-state schema was regenerated from the current typed model. `.venv/bin/python
  scripts/generate_release_schemas.py && .venv/bin/pytest -q
  tests/unit/test_release_schemas.py tests/unit/test_scheduler_journal_reference.py` passed `9`
  tests in `2.50s`; affected Ruff and strict mypy checks passed. No provider call ran. Physical
  owner resolution, no-chain enforcement, and detached reconstruction remain in the production
  pipeline integration slice and are not claimed by this component result.
- **Production aggregate recovery check:** After the pipeline added deterministic source-file
  review surfaces for scheduled blind roles that lacked a fine-grained assignment, the previously
  red `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_persists_exact_seven_pass_scheduler_evidence
  -x` passed `1` test in `16.19s`. The case completed and persisted all seven typed passes, compared
  the persisted artifact against its owner-held physical journal, and validated the fresh run
  evidence. Only inherited protected disposable-toolchain cleanup warnings were emitted; they did
  not change the result. This focused result does not exercise completed-run resume or the
  retained-reference resolver, does not replace the remaining integration/assurance matrix, and
  made no real provider or network call.
- **Completed-resume accounting-order diagnostic:** The separate `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resumes_exact_completed_campaign_without_provider_replay
  -x` reached a provider-free resumed report but failed `1` test in `18.66s` because its restored
  `UsageRecord` inventory was reordered. The owner report retained provider completion/timestamp
  order, while `SchedulerJournal.retained_provider_usage_records` returned the same exact records
  sorted by request ID. This is an active recovery-integrity defect; it is not a replay, reference,
  or passing result. The pipeline slice will restore report ordering from durable usage evidence
  and rerun the case. No provider or network call ran.
- **Completed-resume recovery closure:** Report serialization now canonically orders usage by
  stable logical request ID, matching the durable scheduler/context identity order and removing
  concurrency completion-order drift without changing or re-attesting any `UsageRecord`. The
  materially changed rerun of `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resumes_exact_completed_campaign_without_provider_replay
  -x` passed `1` test in `19.73s`. It proves zero provider replay, unchanged cost ledger, exact
  report/finding/usage/coverage/context/public-scheduler equality, one typed no-copy prior-journal
  reference, and detached run-manifest validation after the live owner closed. No real provider or
  network call ran; adversarial missing/tampered/swap/symlink/reference-chain cases remain part of
  final retained-custody validation.
- **Retained-journal adversarial custody matrix:** A separate manifest test module now validates
  detached reconstruction after the physical owner closes and asserts the public run manifest's
  exact SHA-256 and size binding for the private reference bytes. It fails closed for missing
  owner/journal, a tampered self-hash, a semantically valid reference swapped to a different valid
  physical journal, linked reference/consumer/owner/private/journal components, an owner reference
  chain, same-run ownership, mutable `latest`, parent traversal, and normalized-path tricks.
  `.venv/bin/pytest -q tests/unit/test_scheduler_journal_reference.py
  tests/unit/test_scheduler_retained_journal_manifest.py` passed `24` tests in `5.82s`; `.venv/bin/ruff
  check tests/unit/test_scheduler_journal_reference.py
  tests/unit/test_scheduler_retained_journal_manifest.py` passed. An exploratory test-module-only
  mypy command followed imported legacy test helpers and reported the repository's pre-existing
  test typing backlog (`153` errors across `10` imported test modules); a `--follow-imports=skip`
  variant reported `5` untyped pytest-decorator/import-skip artifacts. Neither is recorded as a
  production typing pass; strict mypy for the affected production scheduler model had already
  passed. No provider or network call ran.
- **Retained-reference TOCTOU closure:** Independent review found that detached manifest
  validation first hashed the reference, then reopened it later without carrying the sealed
  `ManifestFileBinding`; an owner-A reference could therefore be replaced after inventory with a
  self-valid owner-B reference backed by an exact duplicate journal. Owner-chain absence was also
  checked only before reconstruction. Detached validation now passes the sealed reference binding
  into scheduler validation; one `O_NOFOLLOW` descriptor retains the exact unique reference bytes
  across parsing and reconstruction, enforces the sealed path/size/SHA-256, and rechecks descriptor
  and path identity afterward. Consumer, owner, private, and journal directory identities are
  revalidated across the authority decision, and owner-chain absence is checked again immediately
  before return. Deterministic monkeypatch barriers permanently exercise both replacement windows.
  The first adjacent manifest run stopped at `1 failed, 3 passed` because an existing assertion
  expected the older missing-journal diagnostic; restoring the compatible fail-closed wording and
  rerunning `.venv/bin/pytest -q tests/unit/test_scheduler_manifest.py
  tests/unit/test_scheduler_journal_reference.py
  tests/unit/test_scheduler_retained_journal_manifest.py -x` passed `39` tests in `8.64s`.
  `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resumes_exact_completed_campaign_without_provider_replay
  -x` passed `1` test in `19.06s`, including issuance under the live owner and detached post-close
  verification. Ruff, strict mypy for `manifest.py` and `models/scheduler.py`, and `git diff
  --check` passed. A final atomic replacement barrier swaps the consumer reference only after its
  descriptor is held and while journal reconstruction is in progress; `.venv/bin/pytest -q
  tests/unit/test_scheduler_retained_journal_manifest.py::test_manifest_rejects_reference_replacement_during_journal_reconstruction`
  passed `1` test in `0.74s`, and affected Ruff checks passed. No real provider or network call
  ran.
- **Production crash-window and drift closure:** The pipeline now adopts an exact activated,
  pre-dispatch model reservation and dispatches that logical request once after restart. A request
  durably marked dispatched without a terminal result becomes `UNCERTAIN`, accounts its full
  reservation once, never re-enters provider transport, and can be inspected through repeated
  resumes without charging or replaying again. The first dispatched-resume assay correctly found
  that a second resume treated the already `UNCERTAIN_ACCOUNTED` entry as unbound (`1 failed in
  2.16s`); recovery now idempotently rejoins that terminal ledger entry to the exact dispatched
  scheduler task. An exact non-secret ledger identity commitment binds the canonical
  operator-selected ledger and persistent private lock identity into the scheduler baseline, so a
  byte-identical empty same-cap ledger or replaced lock cannot masquerade as the campaign ledger.
  Two identity tests plus scheduler schema/baseline assurance passed `4` tests in `6.02s`.
- **Production resume drift matrix:** Source, effective configuration, resolved tool policy, model
  selection, pre-scheduler analysis inputs, journal contents, and persistent ledger identity are
  each changed after an activated pre-dispatch crash. Source/model changes fail at retained privacy
  binding; all other changes fail at scheduler preflight; every case records zero resumed provider
  transports. The first source case exposed a report/artifact mismatch because a valid current
  privacy policy was retained in memory but not emitted after prior-run privacy mismatch (`1 failed
  in 1.61s`); the failure path now emits that already-resolved current policy. The final focused
  command `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resume_rejects_drift_before_provider_transport`
  passed `7` tests in `7.16s`.
- **Combined restart acceptance command:** `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resumes_activated_request_after_pre_dispatch_crash_once
  tests/integration/test_scheduler_pipeline.py::test_pipeline_marks_dispatched_crash_uncertain_and_never_retries
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resume_rejects_drift_before_provider_transport`
  passed `9` tests in `22.75s` after the retry-edge recovery patch landed. It proves exact
  request/reservation ID and amount adoption, one provider transport for the resumed logical
  request, `RECONCILED` completion, conservative post-dispatch uncertainty, repeated no-retry
  recovery, and all seven pre-transport drift refusals. Release-schema generation and verification
  passed. These are deterministic local fake-provider transports; no real provider or network call
  ran.
- **Reproduction host sole-authority closure:** Pass six now emits its deterministic reproduction
  host result at one post-falsification write point. Its candidate denominator is derived only from
  the exact sealed exploit-test planner and falsifier task plans, so a verifier's later disposition
  cannot shrink planned reproduction work; missing generated-test or result identities make the
  typed host result fail rather than pass vacuously. The focused host-contract suite, including a
  post-verifier eligibility-divergence regression, passed `11` tests in `0.52s`; the unsafe/safe
  cross-shard accounting and verifier/judge omission integrations passed `3` tests in `87.82s`.
  Affected Ruff, strict production mypy, and `git diff --check` passed. These were deterministic
  local fake-provider runs with no network access or real provider call.
- **Architecture inventory:** The production pipeline currently performs the relevant work in one
  in-memory orchestration method. It freezes blind specialist contexts before awaiting peer work
  and enforces two-lineage candidate cross-examination and host-side evidence caps, but it has no
  pass journal, exact resume API, persisted blind barrier, explicit cross-shard integration pass,
  or stable scheduler identity on provider requests. Provider logical request IDs are random by
  default and every audit creates a fresh UUID-suffixed run directory.
- **Acceptance decision:** A standalone planning schema would not satisfy this ticket. The live
  `AuditPipeline` request path must use the scheduler, every scheduled request/result must carry a
  stable pass and shard scope, and emitted state must make every missing, failed, truncated,
  invalid, unbound, inconclusive, or crash-uncertain mandatory item block scheduler completion.
  CLI-level resume is not stated as mandatory, but an exact public resume API and production
  pipeline integration are required. No provider call or external engine execution is part of
  this implementation slice.
- **Stable request-identity slice:** Provider completion APIs now accept an optional bounded
  scheduler logical request ID. Exact fallback routes and retry attempts receive deterministic,
  distinct suffixes; one client atomically rejects reuse. The identity reaches provider metadata,
  token/context planning, usage evidence, and the atomic cost ledger. Every current agent entry
  point threads the optional identity while preserving random UUID behavior for ordinary
  unscheduled calls. The focused OpenRouter, usage, context-manifest, and new identity regressions
  passed `396` tests in `2.04s`; no provider request ran.
- **Exact pre-transport lifecycle slice:** `OpenRouterClient` can now preview the exact primary
  route prompt, user-prompt, and response-schema hashes, and accepts one run-local lifecycle
  observer. The observer is notified with those exact commitments and durable dispatch identity
  before token planning or transport, while normalized success remains subject to later agent-side
  validation. The OpenRouter and identity matrix passed `228` tests; no provider request ran.
- **Shard-scoped context slice:** Context construction now accepts an exact normalized source-path
  allowlist, excludes all other source excerpts with a typed hash-only
  `SHARD_SCOPE_WITHHELD` omission commitment, and rejects unknown, unsafe, or inconsistent
  requested paths. The focused context/token-planning matrix passed `129` tests; Ruff and strict
  mypy passed.
- **Adversarial design review:** The first typed/journal draft passed its focused tests but was not
  accepted. Review demonstrated a descriptor-custody root-swap window, orientation/blind false
  completion through empty tasks, summary-only public completion without journal evidence,
  missing private normalized outputs needed for resume, no late-bound activation for dependent
  tasks, and incomplete mixed-language shard coverage. These are active implementation defects,
  not limitations or passing evidence. Remediation is in progress before pipeline integration.
- **Hardened contract slice:** Exact all-source shard descriptors, late-bound task activations,
  private normalized outputs, typed local-preflight failures, and a public journal hash/count
  projection are now implemented. The production binding layer creates one deterministic
  non-Solidity pseudo-shard while refusing to let Solidity source bypass semantic sharding. Its
  focused runtime suite passed `5` tests with Ruff and strict mypy clean, and the pure scheduler
  model suite passed `33` tests. A single journal-suite run during API convergence exposed `14`
  outdated-helper failures versus `8` passes; these remain active remediation evidence rather
  than a passing claim and were handed to the journal owner without an unchanged retry.
- **Durable journal slice:** Descriptor-held `O_NOFOLLOW` custody now spans journal creation and
  resume; exact activation, dispatch, private normalized output, terminal, and preflight records
  survive crashes. A dispatched request without terminal evidence becomes non-retriable
  `UNCERTAIN`, while activated-but-undispatched work remains exactly resumable. Swap, tamper,
  deletion, duplicate, lifecycle, reconstruction, and journal-binding regressions brought the
  scheduler model/journal/runtime matrix to `78` passing tests with Ruff and strict mypy clean.
- **Assurance integration slice:** Maximum assurance now requires a complete seven-pass artifact
  and the emitted `scheduler-state.json`; the fully satisfied assurance fixture carries a
  journal-derived scheduler artifact, and the missing-artifact negative assay fails closed. Ruff
  passed, strict mypy passed on the production assurance module, and
  `tests/unit/test_assurance.py` passed `182` tests in `119.06s`.
- **Focused lifecycle validation:** The scheduler model, durable journal, production binding, and
  logical-request identity suites passed `107` tests in `2.10s`. The affected OpenRouter,
  budget, context, usage, and token-planning suites passed `487` tests in `4.78s`; request-count
  ceilings are task-scoped for scheduler retries while existing role cost/token caps remain in
  force. Two pytest cleanup warnings concerned pre-existing protected disposable toolchain paths
  and did not change either test result. Ruff and `git diff --check` passed, and strict mypy found
  no issues in all eight affected production modules.
- **Production and manifest slice:** The live fake-provider audit completed all seven passes with
  `12` exact scheduled model requests; a forced orientation timeout produced one failed pass and
  no later calls. Report binding, exact mixed-source inventory reconstruction, emitted artifact
  hashing, and request↔activation↔result↔provider joins now validate, including fail-closed
  rejection of stale, fallback, malformed, truncated, unqualified, and substituted evidence.
  The production scheduler integration passed `2` tests in `3.47s`, the focused manifest suite
  passed `9` tests in `1.29s`, and the adjacent manifest/sharding/scheduler matrix passed `131`
  tests. No provider or network call occurred.
- **Second adversarial review:** The integrated build is not yet accepted. Independent review
  demonstrated remaining false-completion or unverifiable-resume paths involving downstream
  lineage/subject semantics, self-declared absence, blind source delivery, provider-output
  normalization, trusted prompt derivation, assurance/runtime binding, durable-journal release
  verification, pass-3 reduction, pass-4 cross-boundary integration, omitted verifier/judge
  decisions, and restoration of provider usage/context evidence after a crash. These are active
  defects being remediated, not limitations or passing evidence.
- **Request-count capability fix:** Lifecycle observation alone no longer authorizes fresh
  per-task request ceilings. Only an exact scheduler validation may return the private local
  capability; generic observers retain the configured per-role ceiling. The new two-ID no-op
  observer assay and adjacent OpenRouter/logical-identity matrix passed `232` tests in `1.56s`.
- **Exact source-delivery boundary:** Provider lifecycle activation now receives only sorted paths
  proven to be present as exact whole-file provider-visible excerpts matching repository-map
  path, UTF-8 size, line span, and SHA-256. Repository metadata, partial excerpts, omitted source,
  and reconstructed multi-excerpt files receive no delivery credit. Strict mypy passed and the
  logical-identity suite passed `31` tests in `0.38s`; scheduler-side descriptor custody and the
  cited-but-undelivered completion assay remain active before this slice can receive review credit.
- **Typed non-Solidity file review:** Repository pseudo-shards no longer need to choose between
  false AST evidence and delivery-only credit. A `SOURCE_FILE` surface binds normalized path,
  UTF-8 size, line count, whole-file SHA-256, an explicit model disposition, concrete
  source/security observations, and an exact file-level path record to one whole provider-visible
  excerpt. Other surface kinds still require the deterministic Solidity index/graph. Empty files
  use an explicit empty excerpt rather than metadata-only credit. Ruff and strict mypy passed; the
  model-review-evidence suite passed `33` tests in `0.88s` and the logical lifecycle suite passed
  `31` tests in `0.40s`.
- **Compacted map identity fix:** Repository-map metadata compaction now retains every requested or
  preferred shard path ahead of role-weighted optional entries, including when the original map
  exceeds its 300-file default projection. This prevents an exact whole-file excerpt from losing
  the provider-visible path/size/line/hash identity needed for review credit. Five focused
  shard-context tests passed in `0.92s`, and all `17` context tests passed in `1.56s`; no provider
  request ran.
- **Assurance fixture assay:** The missing-scheduler negative test remains fail-closed, but the
  nominal maximum-assurance fixture now correctly falls to `INCONCLUSIVE` because its scheduler
  artifact is detached from the runtime configuration, shard inventory, and REAL request set. The
  focused command produced `1 failed, 1 passed in 2.94s`; this is active fixture/integration work,
  not passing evidence or a weakened join.
- **Qualification and pass-order review:** A generic REAL usage check is insufficient for a
  mandatory scheduled request: each request must independently join the current production
  qualification, approved provider session, exact model, and verified root lineage. The first
  full-ensemble fixture API also placed optional model tasks in orientation, which would weaken
  blind-discovery ordering. Both remain active remediation: orientation is restricted to its
  threat-model contract, specialist work belongs to blind shard review, and global whole-protocol
  review must remain blind and precede adversarial cross-examination.
- **Exact cost-recovery slice:** Usage evidence now retains exact decimal reported and accounted
  costs independently of presentation floats, and one-shot journal-authorized budget recovery
  cross-checks the exact persistent ledger values without charging USD twice. Ruff, strict mypy,
  and `171` budget/usage/journal tests passed in `3.15s` (`7.4s` command wall), including an
  18-decimal regression. Active reservations and provider failures without normalized output are
  still unresolved and receive no completion claim.
- **Scheduler pass-role contract:** Orientation now permits only its exact threat-model request;
  specialist/source work is shard-scoped in blind review, candidate reviewers and validators stay
  in their ordered passes, and judgment stays last. The scheduler model/journal matrix passed `81`
  tests in `3.41s` after formatting, Ruff, and strict mypy. Whole-protocol reviews are global
  blind-pass work and must deliver the entire trusted source inventory; their follow-up negative
  assay remains in progress.
- **Whole-protocol production gap:** Assurance alignment showed that the live pipeline had no
  `whole_protocol_review:N` calls even though the certified ensemble requires four independent
  whole-protocol lineages. This is a safely failing functional blocker, not fixture-only work.
  Production blind-pass scheduling, qualified-lineage selection, full trusted-source delivery,
  and exact usage/context joins are now part of the active scheduler remediation.
- **Specialist responsibility honesty:** A successful REAL request label alone does not prove a
  specialist responsibility completed. Scheduler task evidence and maximum assurance must join the
  exact host-validated `SpecialistAcceptedOutcome` and its response, context, requested-surface,
  and artifact hashes; the contract must derive completed investigator/auxiliary roles from the
  resulting specialist execution records. Arbitrary specialist JSON remains active negative-test
  work and cannot be used to make the nominal fixture complete.
- **Active-reservation recovery:** Resume now distinguishes the journal-proven send boundary.
  ACTIVATED without DISPATCH retains its exact reservation for one-shot adoption by the same stable
  logical request, model, role, and maximum; every other dispatch remains blocked until adoption.
  The resumed task dispatches and reconciles once. DISPATCHED without durable output becomes
  non-retriable `UNCERTAIN`, accounts the full reservation exactly once, restores scoped model/role
  cost, and conservatively exhausts unknown token ceilings. The initial matrix passed `211` tests;
  the corrected adoption assay passed `85` budget/journal tests in `2.97s` (`6.9s` wall).
  Failed-paid-attempt custody remains unresolved; campaign-ledger delta binding is recorded below.
- **Campaign-ledger delta binding:** The scheduler freezes exact terminal cost-entry and ledger-head
  hashes before its first provider request. Resume reads that baseline under journal custody,
  verifies the current ledger as the exact immutable prefix plus campaign-only entries, restores
  baseline spend without attributing it to campaign model/role counters, and restores only the
  campaign delta into scoped counters. Formatting, Ruff, strict mypy, and `87` budget/journal tests
  passed in `3.11s` (`4.6s` wall). Durable failed-paid-attempt evidence remains the last P0 recovery
  slice.
- **Unseeded pass-4 discovery regression:** Two synthetic local campaigns now reach all seven passes
  through the fake provider without pre-seeding a host finding; the unsafe condition produces a
  persisted boundary candidate/workset while the safe implementation produces the safe disposition.
  `.venv/bin/pytest -q tests/integration/test_scheduler_pipeline.py -k
  pass_four_model_discovery` passed `1` test with `8` deselected in `20.34s`.
- **Pipeline assurance wiring:** The live pipeline now supplies the exact scheduler bindings, shard
  inventory, and specialist execution records to maximum assurance. Formatting, Ruff, strict mypy,
  and the exact seven-pass persistence integration passed, ending with `1 passed in 6.55s`.
  Whole-protocol maximum-assurance end-to-end coverage and production resume remain active.
- **Whole-protocol first end-to-end assay:** The initial exact maximum-assurance integration ran
  for `189.07s` and failed safely with run status `FAILED` rather than the expected `INCOMPLETE`:
  duplicating the complete fine-grained surface catalogue made the first whole-protocol request's
  minimum metadata exceed its `119478`-byte allocation before blind calls. The changed design still
  delivers every trusted source but requests one exact validated `SOURCE_FILE` disposition per
  source; critical/function coverage remains a separate mandatory denominator. An identical-command
  rerun was attempted once and the first failure is not passing evidence.
- **Whole-protocol focused production closure:** Surface-evidence sealing now accepts only the
  closed relationship between a frozen `whole_protocol_review` context and its exact indexed
  `whole_protocol_review:N` request role; a different investigator role remains rejected. The
  literal role-boundary command `.venv/bin/pytest -q tests/unit/test_model_review_evidence.py -k
  'whole_protocol_context'` passed `2` tests with `33` deselected in `0.47s`. The literal combined
  production command recorded in `LAST_COMMAND` passed Ruff, strict mypy, and `1` integration test
  in `25.86s`. That assay proves exactly four scheduler-managed global blind tasks, four exact
  models, four distinct root lineages, successful terminal results, exact source-descriptor
  delivery, and four validated `SOURCE_FILE` review artifacts with the exact path and content hash.
  Fine-grained critical/function coverage remains independently enforced by the existing shard
  review and model-coverage gates; whole-source delivery alone does not satisfy those denominators.
- **Failed-paid-attempt custody closure:** Every dispatched model exception path now supplies the
  exact accountable usage record to scheduler failure handling. The focused command
  `.venv/bin/ruff format src/mmaudit/orchestration/pipeline.py
  tests/integration/test_scheduler_pipeline.py && .venv/bin/ruff check
  src/mmaudit/orchestration/pipeline.py tests/integration/test_scheduler_pipeline.py &&
  .venv/bin/mypy src/mmaudit/orchestration/pipeline.py && .venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_failed_mandatory_scheduler_pass_stops_later_provider_calls`
  passed Ruff, strict mypy, and `1` regression in `1.28s`. The failed dispatched request retained
  one private provider-attempt object plus exact public hash/count evidence, the pass remained
  failed, and no later provider request ran. Preflight failures remain correctly usage-free.
- **Default in-repository output authority:** The scheduler aggregate now receives the exact
  prevalidated audited-output exclusion root used by discovery and scanner source hashing, while
  every run-private path remains separately classified as disposable. The production-default
  command `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_scheduler_accepts_default_in_repository_private_output_exclusion`
  passed `1` test in `6.35s`. It ran a complete synthetic local seven-pass campaign beneath the
  target's excluded `.mmaudit/runs/<run-id>` root and emitted the private typed analysis-input
  inventory. No network, live target, or real provider was used.
- **Mandatory aggregate fresh-run validation:** After making the typed pre-scheduler aggregate
  mandatory, the exact command `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_persists_exact_seven_pass_scheduler_evidence
  tests/integration/test_scheduler_pipeline.py::test_maximum_scheduler_executes_four_blind_whole_protocol_reviews
  tests/integration/test_scheduler_pipeline.py::test_pass_four_model_discovery_distinguishes_unsafe_and_safe_cross_shard_accounting
  tests/integration/test_scheduler_pipeline.py::test_failed_mandatory_scheduler_pass_stops_later_provider_calls`
  passed `4` tests in `53.21s`. Fresh unsafe/safe, whole-protocol, and mandatory-failure campaign
  behavior remains intact; the two cleanup warnings concerned pre-existing protected disposable
  toolchain paths. No network, live target, or real provider was used.
- **Whole-protocol bounded rerun:** The materially changed 15-shard integration remained CPU-bound
  and was interrupted once after `669.57s`; pytest had not reached assertion completion. The
  interruption exposed completed task failures because exact indexed `whole_protocol_review:N`
  roles were still rejected by the surface-evidence contract as non-investigators. The large run
  will not be retried unchanged. A focused schema assay and small production campaign must prove
  exactly four distinct qualified global calls, full source delivery, and exact `SOURCE_FILE`
  dispositions before this slice can pass.
- **Exact maximum-assurance scheduler closure:** The nominal runtime now derives and supplies the
  exact pre-scheduler analysis-input digest, cost-ledger baseline, effective bindings, shard/source
  inventory, current production qualification, REAL provider usage/context records, typed
  host-accepted specialist outcomes, and journal-bound outcome hashes. It reached `COMPLETE` with
  `14/14` selected qualified models executed, `25/24` accepted specialist responsibilities,
  `4/4` independent whole-protocol lineages with exact global source delivery, one critical
  surface with `3/3` independent lineages, and `2/2` candidate-falsifier lineages. Exact evidence:
  - `.venv/bin/pytest -q
    tests/unit/test_assurance.py::test_maximum_assurance_complete_requires_all_runtime_clauses`
    passed `1` test in `5.28s`; every required assurance clause passed.
  - `.venv/bin/pytest -q tests/unit/test_assurance.py -k
    'missing_scheduler_artifact or missing_trusted_scheduler_inputs or wrong_scheduler_binding or
    wrong_scheduler_analysis_input_binding or wrong_scheduler_cost_ledger_baseline or
    wrong_scheduler_shard_inventory or extra_unscheduled_provider_usage or mock_scheduler_usage or
    unqualified_real_scheduler_usage or scheduler_context_hash_mismatch or
    scheduler_usage_record_hash_mismatch or declared_specialist_roles_without_execution_records or
    real_specialist_usage_without_host_accepted_outcome or
    scheduler_rejects_specialist_outcome_for_another_validated_response'` passed `17` tests with
    `181` deselected in `79.11s`. Missing, wrong, extra, MOCK, unqualified, detached, and
    hash-mismatched evidence all remained non-`COMPLETE`.
  - `.venv/bin/pytest -q tests/unit/test_scheduler_models.py` passed `39` tests in `0.60s` after
    exact specialist-outcome journaling and global-scope source delivery were incorporated.
  - The exact `LAST_COMMAND` passed formatting, Ruff, and strict mypy. No provider or network call
    occurred; all fixture evidence is synthetic, local, and explicitly test-only.
- **Adversarial specialist closure assays:** Six permanent negative assay cases now demonstrate
  that scheduler completion remains incorrectly reachable with (1) a generic blind investigator
  payload plus a declared accepted outcome, (2) a generic invariant-review payload, or (3) an
  investigator outcome whose declared surface-artifact hash resolves to no runtime artifact, plus
  generic (4) orientation, (5) deterministic finding-reduction, and (6) evidence-cap judgment
  payloads. The first three exact focused commands failed as intended in `5.19s`, `5.55s`, and
  `5.63s`; the final three-case command failed in `15.02s`, always with
  `seven_pass_scheduler` still passing. Generic pass-five, verifier, judge, and cross-shard
  integration payloads were already rejected by typed validation or exact downstream candidate
  inventory and did not receive duplicate regressions. These are active remediation evidence, not
  passing release evidence. The helper has no pass-six reproduction-host task to mutate safely, so
  reproduction-resolution payload validation remains an explicit part of architecture's typed
  host-output contract rather than an additional assurance fixture assay. No provider or network
  call occurred.
- **Safe-target responsibility availability:** A no-candidate campaign executes the 20
  investigator roles plus candidate-independent invariant and report-quality review, yielding only
  22 distinct responsibilities against the preserved hard floor of 24. This is fail-closed
  availability, not false completion. `V3-COVERAGE-001` now requires at least 24 distinct
  candidate-independent substantive responsibilities (or an equally non-vacuous policy that still
  executes 24); conditional absence, retries, aliases, and repeated calls receive no credit.
- **Mandatory analysis-input custody migration:** All `306` selected scheduler/assurance tests
  collected after the complete typed analysis-input inventory became mandatory scheduler evidence.
  The focused scheduler model, release-manifest, and durable-journal matrix passed `102` tests in
  `6.51s`; Ruff format/check passed across the shared scheduler helper and affected test modules.
  The test custody layout now expects `analysis-input-inventory.json`. No production architecture
  file was modified in this mechanical migration, and no provider or network call occurred.
- **Reproducible semantic projection:** The production scheduler commits a closed 24-label,
  hash-only inventory of all deterministic pre-scheduler inputs. Engine projections exclude only
  schema-known timing, process identity, and disposable-output fields; exact status, normalized
  findings/results, tool/compiler hashes, coverage, failures, limitations, and external
  rule/spec/source paths remain bound. Normalizing a path requires an explicitly validated
  disposable root and, for the default in-repository output, exact exclusion authority proven
  disjoint from discovered source. Resume retains and exact-compares every private descriptor and
  reports only drift labels; public evidence contains the aggregate hash, all descriptor hashes,
  and exact count.
  - `.venv/bin/ruff check src/mmaudit/models/scheduler.py
    src/mmaudit/orchestration/scheduler.py src/mmaudit/orchestration/scheduler_runtime.py
    tests/unit/test_scheduler_analysis_inputs.py` — PASS; Ruff clean.
  - `.venv/bin/mypy src/mmaudit/models/scheduler.py
    src/mmaudit/orchestration/scheduler.py src/mmaudit/orchestration/scheduler_runtime.py
    tests/unit/test_scheduler_analysis_inputs.py` — PASS; strict mypy clean across four files.
  - `.venv/bin/pytest -q tests/unit/test_scheduler_analysis_inputs.py -x` — PASS,
    `4 passed in 0.25s`, covering stable timing/staging relocation, changed tool/status/result and
    external-path inequality, and exact in-repository exclusion authority. No provider, scanner,
    compiler, formal engine, or network call occurred.
- **Typed-contract migration diagnostic:** After central schema-hash response parsing and
  model-surface artifact custody landed, `.venv/bin/pytest -q
  tests/unit/test_scheduler_models.py` produced `24 passed, 16 failed in 2.08s`. The failures
  are active fixture-migration evidence: legacy arbitrary payloads and candidate-review helpers
  lacked their now-mandatory typed surface requests and artifacts. No gate was weakened and no
  provider or network call occurred. The independent analysis-input/request-identity command
  recorded in `LAST_COMMAND` subsequently passed `35` tests in `0.45s`.
- **Typed fixture recovery:** Canonical per-role schemas, nonempty candidate-review surface
  requests/artifacts, specialist outcome binding, typed host outputs, and recovery fixtures now
  replace every legacy arbitrary success payload. The exact command recorded in `LAST_COMMAND`
  passed `103` tests in `18.77s`; no provider or network call occurred. Exact assurance
  artifact joins and activation-input/relationship descriptor tamper negatives remain active.
- **Typed response and host activation closure:** Every scheduled model success now parses through
  one closed response-schema-hash-to-Pydantic registry and its exact role contract. Blind model
  reviews retain nonempty exact surface requests and the sealed private review artifact; task and
  public request evidence expose the artifact hash, request-manifest hash, and exact count.
  Candidate-review specialist acceptance must match that artifact and cannot claim a zero-surface
  responsibility. Orientation additionally requires nonempty core threat evidence.
  Pass-three candidate hashes, location dispositions, canonical groups, and blind/execution
  partitions are bound to activation. Pass four binds its semantic inventory, complete campaign
  shard set, high/critical and valid downstream candidate sets, every semantic relationship
  descriptor/hash, review artifact, invariant-presence bit, and exact review surface/shard scope.
  Pass six binds planned reproduction candidate and generated-test/result coverage; pass seven
  requires one judge decision for every planned group and binds its complete output to activation.
  Permanent negatives cover generic payloads, omissions, duplicates, detached hashes, relationship
  descriptor and semantic-inventory substitution, downstream candidate suppression, wrong scope,
  and incomplete reproduction coverage.
  - `.venv/bin/ruff check src/mmaudit/models/scheduler.py
    tests/unit/test_scheduler_host_contracts.py tests/unit/test_scheduler_response_contracts.py`
    passed; `.venv/bin/mypy src/mmaudit/models/scheduler.py` passed strict checking.
  - `.venv/bin/pytest -q tests/unit/test_scheduler_host_contracts.py
    tests/unit/test_scheduler_response_contracts.py` passed `13` tests in `0.30s`.
  - `.venv/bin/pytest -q tests/unit/test_scheduler_models.py
    tests/unit/test_scheduler_manifest.py tests/unit/test_scheduler_journal.py
    tests/unit/test_scheduler_host_contracts.py tests/unit/test_scheduler_response_contracts.py`
    passed `116` tests in `19.63s`. Two inherited protected-temporary-tree cleanup warnings were
    non-failing. No provider, network, live target, external scanner, compiler, or formal engine
    ran in these tests.
- **Next safe action:** Complete the read-only adversarial review of the final assurance,
  architecture, and pipeline joins; remediate only concrete fail-open gaps, then run the combined
  scheduler validation matrix while retaining `V3-SCHEDULER-001` as `IN_PROGRESS`.
- **Blind surface-custody remediation:** Every scheduled blind role that has no fine-grained
  assignment now receives deterministic shard `SOURCE_FILE` review requests bound to the exact
  discovery path, byte count, line count, and SHA-256. A scheduled `CandidateReviewBatch` can no
  longer reach specialist acceptance with zero requested surfaces or a missing review artifact.
  `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_maximum_scheduler_executes_four_blind_whole_protocol_reviews
  --maxfail=1` passed, `1 passed in 79.46s`; only local synthetic fixtures and the mock provider
  transport ran.
- **Resume stability and containment slice:** Provider-visible scanner evidence now omits only the
  incidental `location_validation[].validated_at` observation time while retaining validation
  status, content hash, and errors; a focused test proves timestamp-only replay stability and
  security-relevant evidence drift inequality. Exact private-run resolution rejects both a
  symlinked run and a symlinked `<run>/private` descendant. Completed resume now reaches release
  emission with retained terminal failures adopted and no provider replay; detached no-copy prior
  journal authority remains the active implementation gate.
- **Exact completed-resume acceptance:** A completed campaign is adopted from one explicit prior
  direct-child run with zero repeated provider calls and no copied private journal. The consumer
  run retains a typed, self-hashed, same-output-root reference to the physical owner journal;
  detached manifest validation reopens that journal after live custody closes and reconstructs
  the exact public artifact. The assay proves byte/hash equality for candidate findings,
  model-review coverage, and scheduler evidence; exact finding, usage, scheduler metadata,
  context-request evidence, and cost-ledger snapshot equality; and a distinct consumer run ID.
  `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resumes_exact_completed_campaign_without_provider_replay`
  passed, `1 passed in 19.73s`. No network, live target, external engine, or real provider ran.
- **Cost-ledger identity custody review:** The scheduler baseline serializes only hash and exact
  accounting fields, remains stable when the exact operator ledger is reopened, and rejects a
  different same-cap ledger. The ledger identity now derives from the descriptor actually held
  under `flock`; every locked operation compares that descriptor with the configured lock path
  both before and after its critical section. A deterministic atomic replacement after descriptor
  open now fails closed instead of computing identity for an unheld replacement lock.
  `.venv/bin/pytest -q tests/unit/test_cost_ledger.py -x` passed `22` tests in `0.46s`; the
  baseline/same-cap subset passed `3` tests in `6.19s`; and the stable path-free baseline subset
  passed `2` tests in `0.35s`.
- **Retained privacy-evidence custody review:** Exact resume no longer performs independent
  path-based reads of provenance and policy. The prior run manifest and both exact manifest-bound
  JSON artifacts remain held through unique `O_NOFOLLOW` descriptors across strict typed and
  current-source/policy semantic validation. A deterministic identical-byte atomic replacement
  after descriptor read is rejected by the post-validation custody check. The privacy race assay
  passed `1` test in `15.91s`; combined with completed zero-replay resume it passed `2` tests in
  `33.99s`. Affected Ruff checks and strict mypy over `manifest.py`, `pipeline.py`, and
  `cost_ledger.py` passed; `git diff --check` was clean. These local synthetic tests made no paid
  call and persisted no credential, secret path, prompt, or completion.
- **Pre-final privacy-custody closure:** The scheduler campaign now freezes a self-hashed
  `SchedulerPrivacyEvidenceCustody` before any model task can be sealed. It binds the exact source,
  fixed provenance/policy artifact names, emitted byte size and SHA-256, typed evidence hashes,
  and policy-to-provenance link. Model-task construction, plan sealing, activation, dispatch, and
  persisted-state reload all fail closed when exact custody is absent. Partial crash resumes hold
  the scheduler manifest and both prior privacy files through no-follow descriptors even though no
  final run manifest exists; completed runs additionally require the final manifest's exact file
  bindings. Final artifact validation holds the private scheduler manifest while descriptor-reading
  both files and exact-joining their typed evidence to the report. Source mismatch, valid rehashed
  tamper, and identical-byte atomic path replacement are permanent negative regressions.
- **Provider lifecycle privacy join:** The validated in-memory OpenRouter policy now supplies a
  frozen, non-secret source/policy/provenance triple to the scheduler before request activation.
  The client retains that accepted binding and revalidates the canonical live policy after cost
  reservation and immediately before every dispatch/network attempt; policy replacement releases
  the reservation with zero transport, zero usage, and no `DISPATCHED` event. Successful provider
  usage must repeat the exact campaign custody triple. A post-transport mismatch remains retained
  as accountable provider-attempt evidence but terminalizes `UNBOUND`, never `SUCCEEDED`.
- **Privacy-custody validation evidence:**
  - `.venv/bin/python scripts/generate_release_schemas.py --write && .venv/bin/python
    scripts/generate_release_schemas.py && .venv/bin/pytest -q
    tests/unit/test_scheduler_models.py tests/unit/test_scheduler_runtime.py
    tests/unit/test_scheduler_journal.py tests/unit/test_scheduler_manifest.py
    tests/unit/test_logical_request_identity.py -x` — PASS; `148 passed in 20.05s` and the generated
    scheduler schema verified current.
  - `.venv/bin/ruff check --fix src/mmaudit/models/openrouter.py
    src/mmaudit/models/scheduler.py src/mmaudit/orchestration/assurance.py
    src/mmaudit/orchestration/manifest.py src/mmaudit/orchestration/pipeline.py
    src/mmaudit/orchestration/scheduler.py src/mmaudit/orchestration/scheduler_runtime.py
    tests/scheduler_support.py tests/unit/test_scheduler_journal.py
    tests/unit/test_logical_request_identity.py tests/integration/test_scheduler_pipeline.py &&
    .venv/bin/ruff format src/mmaudit/models/openrouter.py src/mmaudit/models/scheduler.py
    src/mmaudit/orchestration/assurance.py src/mmaudit/orchestration/manifest.py
    src/mmaudit/orchestration/pipeline.py src/mmaudit/orchestration/scheduler.py
    src/mmaudit/orchestration/scheduler_runtime.py tests/scheduler_support.py
    tests/unit/test_scheduler_journal.py tests/unit/test_logical_request_identity.py
    tests/integration/test_scheduler_pipeline.py && .venv/bin/mypy
    src/mmaudit/models/openrouter.py src/mmaudit/models/scheduler.py
    src/mmaudit/orchestration/assurance.py src/mmaudit/orchestration/manifest.py
    src/mmaudit/orchestration/pipeline.py src/mmaudit/orchestration/scheduler.py
    src/mmaudit/orchestration/scheduler_runtime.py && .venv/bin/pytest -q
    tests/unit/test_logical_request_identity.py::test_scheduler_privacy_binding_is_rechecked_after_reservation
    tests/integration/test_scheduler_pipeline.py::test_partial_scheduler_resume_privacy_rejects_atomic_path_replacement
    tests/integration/test_scheduler_pipeline.py::test_partial_scheduler_resume_privacy_rejects_valid_rehashed_tamper`
    — PASS; Ruff fixed one import-order issue, strict mypy passed seven production files, and all
    three focused lifecycle/partial-resume negatives passed in `1.60s`.
- **Recovered crash/drift acceptance:** `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py::test_pipeline_resumes_activated_request_after_pre_dispatch_crash_once
  tests/integration/test_scheduler_pipeline.py::test_pipeline_marks_dispatched_crash_uncertain_and_never_retries
  'tests/integration/test_scheduler_pipeline.py::test_pipeline_resume_rejects_drift_before_provider_transport[config]'
  'tests/integration/test_scheduler_pipeline.py::test_pipeline_resume_rejects_drift_before_provider_transport[tool]'
  'tests/integration/test_scheduler_pipeline.py::test_pipeline_resume_rejects_drift_before_provider_transport[analysis]'
  'tests/integration/test_scheduler_pipeline.py::test_pipeline_resume_rejects_drift_before_provider_transport[journal]'
  'tests/integration/test_scheduler_pipeline.py::test_pipeline_resume_rejects_drift_before_provider_transport[ledger]'`
  passed all `7` cases in `21.18s`. Activated pre-dispatch work resumed once; dispatched work stayed
  uncertain and non-retriable; configuration, tool, deterministic-analysis, journal, and exact
  ledger-identity drift each refused before a resumed provider transport.
- **Full production scheduler integration acceptance:** `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py` passed all `23` cases in `251.37s`. This includes
  fresh and exact completed resume, pre-final partial resume, descriptor-held privacy replacement
  rejection, all seven drift dimensions, primary-route failure, typed unsafe/safe semantic
  accounting, omitted verifier/judge failures, exact reduction, cross-shard evidence, and semantic
  blind-context delivery. Only inherited protected disposable-toolchain cleanup warnings were
  emitted. `.venv/bin/ruff check src/mmaudit/models/scheduler.py
  src/mmaudit/models/openrouter.py src/mmaudit/orchestration/pipeline.py
  src/mmaudit/orchestration/scheduler.py src/mmaudit/orchestration/scheduler_runtime.py
  src/mmaudit/orchestration/cost_ledger.py src/mmaudit/orchestration/manifest.py
  tests/scheduler_support.py tests/unit/test_scheduler_host_contracts.py
  tests/unit/test_scheduler_journal.py tests/unit/test_scheduler_manifest.py
  tests/unit/test_scheduler_models.py tests/integration/test_scheduler_pipeline.py` passed.
  `.venv/bin/mypy src/mmaudit/models/scheduler.py src/mmaudit/models/openrouter.py
  src/mmaudit/orchestration/pipeline.py src/mmaudit/orchestration/scheduler.py
  src/mmaudit/orchestration/scheduler_runtime.py src/mmaudit/orchestration/cost_ledger.py
  src/mmaudit/orchestration/manifest.py` reported no issues in seven production files, and `git
  diff --check` was clean. All executions were deterministic local fake-provider tests with no real
  provider or network call.
- **Recorded operator-level limitation:** Cost-ledger snapshot and descriptor-derived identity are
  each locked observations but are still acquired by two sequential calls when building the
  scheduler baseline. A same-operator process able to replace the private `0700` control-plane lock
  path in the exact interval could mix observation heads. Audited target content cannot access that
  path. This does not weaken the target isolation boundary, but a future cohesive baseline API
  should take both values under one lock.
- **Consolidated scheduler validation:** `.venv/bin/pytest -q tests/unit/test_budgets.py
  tests/unit/test_cost_ledger.py tests/unit/test_logical_request_identity.py
  tests/unit/test_scheduler_analysis_inputs.py tests/unit/test_scheduler_host_contracts.py
  tests/unit/test_scheduler_journal.py tests/unit/test_scheduler_journal_reference.py
  tests/unit/test_scheduler_manifest.py tests/unit/test_scheduler_models.py
  tests/unit/test_scheduler_response_contracts.py
  tests/unit/test_scheduler_retained_journal_manifest.py tests/unit/test_scheduler_runtime.py`
  passed `256` tests in `27.92s`. `.venv/bin/pytest -q
  tests/integration/test_scheduler_pipeline.py` passed all `23` production scheduler integration
  cases in `251.37s`. The complete integration covers fresh completion, exact completed and partial
  resume, pre-dispatch adoption, post-dispatch conservative uncertainty without retry, seven drift
  classes, privacy atomic replacement and valid-rehashed tamper refusal, unsafe/safe cross-shard
  accounting, mandatory omissions, and deterministic host sole-authority behavior. Only inherited
  protected disposable-toolchain cleanup warnings were non-failing. No network, live target,
  external engine, or real provider ran.
- **Specialist candidate-review fixture closure:** The stale accepted-outcome helper now carries
  the mandatory positive requested-surface count and accepted surface-artifact digest. The obsolete
  zero-surface success expectation is a construction-rejection regression, and the self-hashed
  context-digest splice retains the original candidate-review custody fields so it reaches the
  intended context-binding check. `.venv/bin/ruff format tests/unit/test_specialists.py &&
  .venv/bin/ruff check tests/unit/test_specialists.py && .venv/bin/pytest -q
  tests/unit/test_specialists.py --tb=short` passed Ruff and all `30` tests in `0.45s`. Two
  inherited protected disposable-toolchain cleanup warnings were non-failing. No production schema,
  provider, network, live target, or external engine was changed or used.
- **Complete-suite recovery assay:** The first `.venv/bin/pytest -q` attempt was interrupted after
  more than 45 minutes because it had emitted six failures and then remained CPU-bound in the
  maximum-assurance pipeline case. A changed diagnostic command, `.venv/bin/pytest -x -vv`,
  identified the first stale assertion after `37` passes and `5` explicit external-prerequisite
  skips: the seven-pass campaign executed `14` typed fake-provider requests rather than the legacy
  six-call path. The focused pipeline module exposed exactly six regressions before the slow case:
  two stale call-count assertions, one scheduler-phase error-label assertion, one descriptor-held
  missing-artifact exception-boundary defect, and two compile-disabled Solidity reproduction
  controls lacking a typed semantic source surface. A bounded profile of the following
  maximum-assurance case found `350` deterministic model tasks, `7,417` repeated strict-schema
  generations, and `929,708` repeated context-inventory hashes; no blocking I/O or external
  provider call was involved. The complete assurance unit module independently passed all `207`
  tests in `497.65s`.
- **Recovered pipeline regressions:** The seven-pass fake-provider and blind-prior-audit checks now
  assert the exact `14` completed requests. A judge-config preview refusal is attributed to the
  earlier `candidate_falsifier` scheduler role while still proving that no final judgment request
  occurred. Descriptor-held JSON validation no longer catches an exception raised by a different
  artifact observation and relabels it as a read failure on the already-open file. The focused
  command recorded in `LAST_COMMAND` passed all `5` selected integration cases in `64.24s`;
  `tests/unit/test_manifest.py tests/unit/test_scheduler_manifest.py` separately passed `40`
  tests in `8.80s`. No network, provider, live target, or paid call ran.
- **Immutable schema-cache correction:** The bounded maximum-assurance profile showed that the
  closed nine-model scheduler response registry was regenerating all strict Pydantic schemas for
  every planned task. Strict schemas are now cached only as canonical immutable JSON and every
  caller receives a newly decoded object; the scheduler retains its closed registry behind a
  read-only mapping and returns mutation-isolated public copies. Immutable runtime registry pairs,
  the schema-set digest, permitted hash set, and normalizer digests are cached without changing
  task planning, task counts, request schemas, or canonical hashes. The pipeline resolves each
  scheduler response hash from that exact closed registry instead of regenerating it. Mutation
  regressions cover nested strict schemas, parser maps, and runtime record dictionaries. `.venv/bin/ruff
  check src/mmaudit/models/openrouter.py src/mmaudit/models/scheduler.py
  src/mmaudit/orchestration/scheduler_runtime.py src/mmaudit/orchestration/pipeline.py
  tests/unit/test_openrouter.py tests/unit/test_scheduler_runtime.py
  tests/unit/test_scheduler_response_contracts.py` passed; strict `.venv/bin/mypy` over the four
  affected production modules passed; and `.venv/bin/pytest -q tests/unit/test_openrouter.py
  tests/unit/test_scheduler_runtime.py tests/unit/test_scheduler_response_contracts.py` passed all
  `214` tests in `1.48s`. A fresh-process equivalence assay performed `10,000` complete public
  registry reads in `0.014571s` after a `0.014031s` cold build while proving every returned
  contract equal. No provider, network, live target, or external engine ran.
- **Generation-bound schema-cache hardening:** A same-class `model_rebuild(force=True)` can replace
  Pydantic's live validator and core schema while a class-keyed cache retains the old structured
  contract. Strict-schema JSON and digest caches are now independently bounded to `128` entries
  and keyed by identity-only live validator/core-schema generations. Cache misses and callers
  check those identities before and after schema generation, normalization, and hashing, so a
  concurrent rebuild fails closed instead of storing new semantics under an old key. The fixed
  scheduler registry revalidates every live class against its frozen hash before exposing cached
  records, and parsing captures/rechecks both generation identities and the exact hash around
  `model_validate`. Regressions cover forced same-class semantic drift, rebuild during schema
  generation, rebuild during parsing, caller mutation isolation, and `160` transient dynamic
  response classes without exceeding either cache bound. Affected Ruff and strict mypy passed;
  `.venv/bin/pytest -q tests/unit/test_openrouter.py
  tests/unit/test_scheduler_response_contracts.py tests/unit/test_scheduler_runtime.py` passed all
  `219` tests in `2.12s`. No provider or network call ran.
- **Context-inventory cache assessment:** The same profile's repeated inventory hashes cannot be
  safely memoized by object identity alone because the current Pydantic/dict inputs are mutable;
  doing so could preserve a stale omission identity after caller or concurrent mutation. The safe
  follow-up is an owned immutable inventory snapshot at `ContextBuilder` construction, with
  ordinal/field-bound canonical item identities consumed by compaction, plus before/after
  regression equivalence for every omission aggregate. This requires a separate context-custody
  slice and was not mixed into the response-schema cache.
- **Owned context-inventory snapshot:** `ContextBuilder` now deep-copies every provider-visible
  repository, scanner, Solidity, invariant, economic, formal, and coverage model into builder
  custody before capturing an immutable field/ordinal-bound digest inventory. Compaction resolves
  identities only against those owned objects. The field and ordinal are cache lookup custody,
  not new digest inputs, so every cached raw, tagged-index, tagged-graph, and repository-list item
  retains its exact legacy SHA-256. A cache-disabled reference build is byte-for-byte identical,
  including omission aggregates and provider commitment; mutating the caller's repository map,
  project, index, and graph after construction cannot alter either rendered context or omission
  evidence. Affected Ruff and strict production mypy passed; `.venv/bin/pytest -q
  tests/unit/test_context.py tests/unit/test_context_omissions.py
  tests/unit/test_context_optional_metadata.py tests/unit/test_context_serialization_boundary.py
  tests/unit/test_scheduler_analysis_inputs.py tests/unit/test_scheduler_runtime.py` passed all
  `45` tests in `2.09s`. No provider, network, live target, or external engine ran.
- **Context cache-hit correction:** Review caught that `dict.get(key, expensive_fallback())`
  evaluates the fallback eagerly. The lookup now uses an explicit branch. A monkeypatched
  call-count regression proves an owned item performs zero fallback serializations while one
  unknown item performs exactly one. Affected Ruff and strict mypy passed; the omission and
  optional-metadata modules passed all `13` tests in `0.69s`.
- **Combined cache/parser regression gate:** `.venv/bin/pytest -q tests/unit/test_context.py
  tests/unit/test_context_omissions.py tests/unit/test_context_optional_metadata.py
  tests/unit/test_context_serialization_boundary.py tests/unit/test_scheduler_analysis_inputs.py
  tests/unit/test_openrouter.py tests/unit/test_scheduler_response_contracts.py
  tests/unit/test_scheduler_runtime.py tests/unit/test_scheduler_models.py` passed all `302` tests
  in `3.96s`; `git diff --check` passed. The two inherited protected temporary-toolchain cleanup
  warnings were non-failing.
- **Residual maximum-assurance runtime evidence:** A fresh execution of
  `tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete`
  remained CPU-bound beyond the bounded observation window and was interrupted with exit `130`
  rather than misreported as a pass. The interrupt stacks had progressed into concurrent task
  dispatch, but repeatedly rebuilt and compared the complete scheduler journal in
  `_validate_state`, including linear Pydantic task membership. This is a distinct scheduler-state
  validation hotspot; it does not invalidate the context equivalence tests and should not be
  addressed by reducing the required `350`-task denominator.
- **Post-linearization maximum-assurance rerun:** After the journal owner replaced repeated full
  validation with exact incremental joins, `.venv/bin/pytest -q
  tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete
  --durations=5` no longer stalled: it reached post-scheduler model-review coverage and failed in
  `49.48s` (`48.85s` call duration). `ModelReviewCoverage` rejected `132` distinct limitations
  against its explicit `100`-item bound at `model_coverage.py:285`. This is retained next-failure
  evidence, not a pass and not a direct context/schema-cache regression; no implementation was
  changed by this diagnostic run.
- **Manifest consumer-exception custody regression:** A public two-artifact
  `open_manifest_bound_json_artifacts` regression now raises one exact sentinel `BaseException`
  from the stable consumer. It proves the same exception object propagates, all three held
  descriptors (manifest plus two sealed artifacts) receive their post-validation `fstat`, close
  once in reverse acquisition order, and subsequently fail `fstat` with `EBADF`. The existing
  deterministic atomic-replacement case separately retains custody-error precedence. `.venv/bin/ruff
  format tests/unit/test_manifest.py && .venv/bin/ruff check tests/unit/test_manifest.py &&
  .venv/bin/pytest -q
  tests/unit/test_manifest.py::test_manifest_bound_artifacts_propagate_consumer_abort_and_close_descriptors
  --tb=short` passed Ruff and `1` test in `0.61s`; two inherited protected disposable-toolchain
  cleanup warnings were non-failing. Production code was unchanged and no provider or network call
  ran.
- **Supplemental-surface coverage hardening:** Test-only regressions now prove that a semantic
  scheduler surface outside the authoritative product inventory cannot enter the product coverage
  denominator or receive credit, and that mixing one such supplemental surface with a known
  product surface invalidates credit for the complete response artifact rather than laundering the
  known record. The semantic-shard custody assay now parameterizes missing, ambiguous, and
  entity/index-mismatched provenance. The local fake-provider finding gate requires an exact typed
  entity ID, surface kind, path, line range, and current indexed content hash instead of path-only
  delivery; direct wrong-kind and wrong-hash negatives prove that boundary. `.venv/bin/ruff format
  tests/unit/test_model_coverage.py tests/fake_openrouter.py` and
  `.venv/bin/ruff check tests/unit/test_model_coverage.py tests/fake_openrouter.py
  tests/integration/test_pipeline.py` passed. `.venv/bin/pytest -q
  tests/unit/test_model_coverage.py` passed all `53` tests in `0.53s`; `.venv/bin/pytest -q
  tests/integration/test_pipeline.py::test_generated_foundry_reproduction_caps_solidity_classification`
  passed both unsafe/safe local cases in `17.89s`. Two inherited protected temporary-toolchain
  cleanup warnings were non-failing. Production code was unchanged; no provider, network, live
  target, or external engine ran.
- **Scheduler-bound verify-run CLI regression:** A scheduler-bound synthetic run is now emitted
  through the existing manifest/journal helpers, its public `scheduler-state.json` self-hash is
  changed after manifest issuance, and the actual Typer `mmaudit verify-run` command is invoked
  through `CliRunner`. The command returns the nonzero `INCOMPLETE` exit, writes typed `STALE`
  verification evidence with nonempty mismatches, and never represents the run `CURRENT` or
  complete. `.venv/bin/ruff format tests/unit/test_scheduler_manifest.py && .venv/bin/ruff check
  tests/unit/test_scheduler_manifest.py && .venv/bin/pytest -q
  tests/unit/test_scheduler_manifest.py::test_verify_run_cli_fails_closed_after_scheduler_artifact_tampering
  --tb=short` passed Ruff and `1` test in `0.81s`. Only inherited protected disposable-toolchain
  cleanup warnings were non-failing. Production code was unchanged; no provider, network, live
  target, external engine, or secret was used.
- **Scheduler durable-state final-boundary closure:** The journal append path retains its exact
  indexed, append-local validation, while `require_complete()` and public evidence generation now
  descriptor-read the canonical manifest, analysis-input inventory, and every retained plan,
  activation, event, output, provider attempt, task result, and pass result. Full validation
  compares the durable reconstruction with retained state, rebuilds the indexes from durable
  evidence, and brackets reconstruction with exact `(path, file identity, raw SHA-256)` snapshots.
  This rejects in-place byte drift, same-name atomic replacement, and replacement of an already-read
  artifact during a later cross-file read. `PipelineScheduler.require_complete()`, `artifact()`, and
  `report_binding()` now delegate through that journal authority rather than deriving a potentially
  stale `COMPLETE` projection from memory. The negative matrix covers in-place and same-name
  replacement of a middle event, task result, and pass result; deleted wrapper evidence; wrapper
  tampering; a deterministic post-read identical-byte inode replacement; and replacement between
  `artifact()` summary derivation and journal-evidence validation.
- **Durable-state focused validation:** `.venv/bin/pytest -q
  tests/unit/test_scheduler_journal.py::test_live_full_validation_rejects_retained_artifact_byte_drift
  tests/unit/test_scheduler_journal.py::test_live_full_validation_rejects_replacement_after_an_earlier_artifact_read
  tests/unit/test_scheduler_journal.py::test_artifact_rejects_replacement_between_summary_and_journal_evidence
  tests/unit/test_scheduler_journal.py::test_pipeline_scheduler_final_boundaries_delegate_to_durable_validation`
  passed all `10` cases in `2.86s`. `.venv/bin/pytest -q
  tests/unit/test_scheduler_journal.py` passed all `71` cases in `8.36s`.
- **Durable-state scheduler matrix:** `.venv/bin/pytest -q
  tests/unit/test_scheduler_analysis_inputs.py tests/unit/test_scheduler_host_contracts.py
  tests/unit/test_scheduler_journal.py tests/unit/test_scheduler_journal_reference.py
  tests/unit/test_scheduler_manifest.py tests/unit/test_scheduler_models.py
  tests/unit/test_scheduler_response_contracts.py
  tests/unit/test_scheduler_retained_journal_manifest.py tests/unit/test_scheduler_runtime.py
  tests/integration/test_scheduler_pipeline.py` passed all `210` cases in `67.77s` with exit `0`.
  Two inherited protected disposable-toolchain cleanup warnings were non-failing. `.venv/bin/ruff
  format src/mmaudit/orchestration/scheduler.py tests/unit/test_scheduler_journal.py
  src/mmaudit/orchestration/scheduler_runtime.py` left the files unchanged;
  `.venv/bin/ruff check` over those three files passed; and `.venv/bin/mypy
  src/mmaudit/orchestration/scheduler.py src/mmaudit/orchestration/scheduler_runtime.py` reported no
  issues. No provider, network, live target, external engine, or secret was used.
- **Bounded model-coverage failure accounting:** Supplemental semantic-shard surfaces remain
  outside the authoritative product denominator and receive no credit. Identity-specific duplicate,
  invalid-context, unknown-surface, unregistered-model, and unapproved-lineage limitations are now
  represented by one deterministic category summary containing the exact affected identity count
  and a SHA-256 commitment over the sorted unique identities. Full per-record rejection reasons and
  private artifacts remain unchanged. A `101`-artifact overflow regression proves the public
  limitation list remains within its `100`-item schema bound while numerator, denominator, critical
  metric, by-kind metrics, and evidence references remain identical to the no-credit baseline.
- **Exact response-schema generation custody:** The closed scheduler registry now freezes each
  response class with its exact original `SchemaValidator`, core-schema identity, and strict-schema
  digest. Parsing invokes that captured pydantic-core validator directly, requires the exact output
  class, and detached-revalidates before credit; mutating `model_validate` cannot bypass validation.
  Strict-schema decoding checks generation identity after cached JSON decode. OpenRouter captures
  one generation through structured planning, token planning, request activation, request body/hash,
  pre-transport, and bound response decoding/hashing. Rebuild after token planning fails with zero
  transport and zero usage records. Provider response decoding likewise invokes the captured
  validator directly and rejects classmethod mutation or generation drift.
- **Context inventory custody and scanner projection closure:** Builder-owned repository, scanner,
  Solidity, invariant, economic, formal, and coverage models are now private; public properties
  return detached deep copies, so mutating `builder.repository_map` or another exposed view cannot
  stale the cached omission identities. Internal cache hits retain zero fallback serialization.
  Scanner inventory identities now use the same provider projection as rendering, consistently
  excluding only incidental location-validation `validated_at` values while retaining security
  evidence changes. Timestamp-only replay has identical rendered and omission identities; changed
  validation evidence does not.
- **Affected integrity matrix:** Ruff passed over all affected production and test modules; strict
  mypy passed the five affected production modules. `.venv/bin/pytest -q tests/unit/test_openrouter.py
  tests/unit/test_structured_output.py tests/unit/test_scheduler_response_contracts.py
  tests/unit/test_scheduler_runtime.py tests/unit/test_context.py
  tests/unit/test_context_omissions.py tests/unit/test_context_optional_metadata.py
  tests/unit/test_context_serialization_boundary.py tests/unit/test_model_coverage.py
  --durations=15` passed all `355` tests in `4.21s`. Two inherited protected temporary-toolchain
  cleanup warnings were non-failing. No provider, network, live target, external engine, or secret
  was used.
- **Synthetic specialist candidate identity recovery:** The first maximum-assurance rerun reached
  pass `02_blind_shard_review` and failed closed because the synthetic provider emitted five static
  candidate IDs across independent shard tasks. Exact typed path/surface gating removed unrelated
  emissions, but the second rerun still failed after `101.04s`: semantic overlap correctly exposed
  the SafeControls surface in more than one independent request, so surface identity alone did not
  distinguish origins. The fixture now commits each candidate ID to both the required
  `mmaudit_request_id` and the sorted exact typed matching-surface set. An exact retry remains
  stable, a distinct request or surface differs, and an out-of-scope path emits no candidate.
  Production duplicate/conflict rejection is unchanged. The direct regression passed `4` tests
  in `0.27s`; affected Ruff passed.
- **Host origin-identity correction:** The next exact rerun failed in `100.99s` at the same first
  typed boundary because both generic and specialist agent normalization discarded the provider
  candidate ID and stamped only role, title, path, and line. Independently scheduled overlapping
  reviews therefore collided even after the synthetic provider supplied request-bound identities.
  One shared host helper now derives the origin candidate ID from the exact validated usage request
  ID, request role, raw candidate identity, and canonical security payload while excluding only
  fields that the host itself overwrites. Both agent paths reject duplicate raw IDs before
  stamping. Same-request retained replay is stable; distinct requests, raw identities, or raw
  security content differ; pass-three semantic grouping remains deterministic across identical
  scheduler reruns. Production origin-package duplicate rejection remains unchanged.
- **Origin-identity validation:** The direct request/replay, distinct-request/raw/content,
  duplicate-raw, generic/specialist binder, and deterministic-grouping matrix passed `8` tests in
  `0.49s`. The broader model-review evidence, specialist, and consensus matrix passed all `83`
  tests in `0.64s`; affected Ruff and strict mypy over both production modules passed. Inherited
  protected temporary-toolchain cleanup warnings were non-failing.
- **Post-origin maximum-assurance evidence:** Exactly one rerun of `.venv/bin/pytest -q
  tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete
  --durations=5` ran for `101.52s` (`100.97s` call). Passes `01_orientation`,
  `02_blind_shard_review`, and `03_finding_reduction` completed, proving the duplicate origin-ID
  failure is closed. The run then failed closed at the first pass-four business-logic task over
  two exact shards with `cross-shard boundary review was not substantively completed`. The exit
  code was `INCOMPLETE`, but report status remained `FAILED`, so the integration assertion did not
  pass. No second rerun was launched and no production gate was reduced.
- **Historical next safe action (superseded by the later green gates above):** Run one exact
  maximum-assurance end-to-end regression, retain only its first
  typed failure if any, then run repository-wide static, schema, complete-suite, diff, artifact,
  and secret gates before checkpointing `V3-SCHEDULER-001`.

## 2026-08-02 — V3-SHARD-001

- **Status:** `COMPLETE`; isolated checkpoint pending.
- **Defensive objective:** Turn the complete deterministic Solidity symbol and graph inventories
  into stable, coherent review shards with machine-checked source coverage and explicit overlap.
- **Starting evidence:** No shard schema or production builder exists. The 5k/15k/35k synthetic
  scale corpus currently characterizes only deterministic bounded inputs and deliberately grants
  no semantic-sharding credit. Existing graph kinds already represent call/state, inheritance,
  proxy/storage, asset/accounting, privilege/governance, oracle, initializer, cross-chain,
  signature, reentrancy, and external dependency relationships.
- **Implementation boundary:** This ticket will partition those trusted deterministic facts; it
  will not manufacture findings, count context delivery as review, call a provider, or claim an
  external engine execution.
- **Implemented slice:** A bounded file-primary shard algorithm now consumes every discovered
  Solidity source and every exact entity, graph-node, graph-edge, and storage fact. It derives
  stable source/shard IDs, canonical semantic hashes, cross-source boundaries, explicit remote
  and shared-node overlap, and the closed risk-surface set. Primary, overlap, boundary, aggregate,
  and source-byte caps fail closed and are re-enforced during deserialization. Source provenance,
  graph coverage counters, source-owned node kinds/locations, edge endpoints, ownership, and all
  denominators are exact-checked.
- **Authority boundary:** Public hashes prove only structural consistency. Every serialized
  inventory declares `comparison_required`; trusted-input verification detached-validates and
  deterministically rebuilds the complete inventory, while persisted readback exact-compares the
  typed index, graphs, shard envelope, and report binding. The run evidence manifest separately
  binds exact artifact bytes. Canonical index/graph fields are semantic typed-content hashes, not
  raw file-byte hashes.
- **Focused evidence:** `tests/unit/test_semantic_sharding.py` passed `44` tests in `3.13s`,
  including a fully re-sealed relocation that remains structurally parseable but is rejected by
  both trusted-source rebuild and persisted upstream comparison. The maximum-assurance pipeline
  integration passed `1` test in `19.41s`; the 5k/15k/35k shard scale regression previously passed
  `3` cases in `28.51s`. Affected Ruff and strict mypy passed. Release schema generation and
  verification passed after changing the schema to match the emitted typed envelope.
- **Honest limitation:** Version 1 uses one primary shard per source file and fails closed when a
  source exceeds its configured byte cap; it does not subdivide an oversized logical block.
  The scheduler/truncation track must not claim that remaining token-context problem is solved.
- **Consolidated validation:** The final affected matrix passed `93` tests in `82.96s` across
  shard integrity, manifest/release verification, maximum-assurance serialization, and all
  realistic-scale profiles. Repository-wide Ruff format/check, strict mypy over `162` source
  files, release-schema synchronization, and diff checks passed.
- **Full-suite remediation:** The first complete run exposed one compiler-AST half-open range
  ending on a trailing newline and was stopped after `1 failed, 79 passed, 9 skipped in 258.37s`.
  The graph source-location converter now maps the last included byte instead of treating the
  exclusive end as a new line; its direct regression, the previously failing pipeline case, and
  all shard tests passed `46` tests in `3.66s`. This corrects normalized evidence rather than
  weakening shard location checks.
- **Managed-sandbox rerun:** The unchanged full suite advanced to `1668 passed, 16 skipped` before
  an intentional early stop. Its `5` failures and `7` setup errors were exclusively operating-
  system `PermissionError` results from pre-existing Hardhat tests attempting local TCP or AF_UNIX
  socket binds inside the restricted command sandbox. The earlier source-range failure did not
  recur. This is environmental and grants no passing credit; the next command reruns the exact
  suite with local socket permission.
- **Independent persisted-evidence review:** Review identified that a fully re-sealed public
  artifact could previously preserve an impossible graph coverage counter, omit the repository
  source join, or set a null shard inventory despite non-empty upstream evidence. It also found
  that the initial trailing-newline correction could convert a past-EOF AST start into a valid
  final-line citation. No affected result was granted completion credit.
- **Integrity remediation:** Compiler spans now require exactly three numeric components,
  non-negative in-bounds byte coordinates, and half-open end handling; compiler ASTs are
  source-ID and byte-inventory checked before use, so malformed, cross-source-ID, or
  out-of-inventory spans fall back rather than producing normalized compiler evidence. This does
  not prove content identity for a same-length stale artifact. Persisted comparison validates index provenance,
  graph kinds/counters/source-owned nodes, fact ranges, all six semantic/context/projection
  commitments, exact report repository source membership and hashes, commit binding, and typed
  report summaries. Completed reports cannot omit or null their Solidity shard evidence. JSON
  artifacts are read with duplicate-key/non-finite rejection through a bounded stable descriptor.
- **Compatibility boundary:** Runs emitted before this ticket that contain index/graph artifacts
  without the new shard artifact are intentionally unverifiable and become `STALE`; report schema
  `1.2` predates sharding, so preserving replay acceptance for those incomplete artifact sets would
  retain an all-shard-evidence erasure ambiguity. This does not rewrite their historical evidence.
- **Focused remediation evidence:** The range, stale-artifact pipeline, full shard suite, and all
  three independent persisted negative assays passed `59` tests in `3.14s`.
- **Final focused evidence:** Independent context/projection drift, report-summary drift,
  duplicate-key/non-finite JSON, null/erased inventory, repository projection, graph coverage,
  and manifest-bound verify-run mismatch regressions all fail closed. The consolidated shard,
  manifest, verification, Solidity, realistic-scale, reproduction, and maximum-assurance matrix
  passed `155` tests in `93.68s`. Ruff format/check, strict mypy over `162` source files, release
  schema synchronization, and diff checks passed.
- **Complete suite gate:** The exact `.venv/bin/pytest -q` command passed `4062` tests with `11`
  explicit external-prerequisite skips in `931.46s` after granting only the local TCP and AF_UNIX
  listener permission used by existing isolation tests. No unavailable engine, rootless image,
  compiler, replay, or paid-provider integration was promoted to passing evidence. Two inherited
  stale temporary-tree cleanup warnings remained non-failing.
- **Independent final review:** After remediation of persisted graph counters, all semantic hash
  projections, report/repository joins, null/erased evidence, strict JSON reads, AST byte spans,
  and current-report erasure, the read-only reviewer found no remaining material ticket blocker.
  Same-length stale AST content identity and historical pre-sharding replay compatibility remain
  explicitly limited.
- **Next action:** Review the final diff and artifact inventory, create and push the isolated
  checkpoint, then begin `V3-SCHEDULER-001`.

## 2026-07-31 — V3-EFFORT-001

- **Status:** `PARTIAL`; paused by the operator after a coherent provider-free sub-slice.
- **Defensive objective:** Resolve reasoning effort and reasoning-token reserves by exact base or
  specialist role, and make the effective choice fail-closed, endpoint-bound, qualification-bound,
  cost-reserved, and visible in durable evidence.
- **Starting state:** `ModelsConfig.reasoning` is one global `ModelReasoningConfig`; runtime
  controls construct one `OpenRouterReasoning`; every production client receives that same value.
  Existing request token plans reserve a global reasoning allowance and endpoint cost bounds
  separately price `internal_reasoning`, but neither proves which role-specific policy was
  selected or that qualification covered it.
- **Implemented slice:**
  - Atomic reservation evidence schema `2.0` separately records visible-output and
    reasoning-token ceilings and verifies their conservation against the combined completion
    ceiling.
  - `BudgetManager` requires the split for plan-bound reservations, preserves it in immutable
    reservation evidence, and rejects unobserved active reasoning or either observed slice above
    its reserve during reconciliation.
  - OpenRouter request reservations now pass the exact token-plan split and reconciliation
    preserves provider-observed reasoning usage.
  - Provider token validation and usage-credit validation reject reasoning or visible-output
    usage above the matching reserved slice.
  - Synthetic fixtures were updated to prove reasoning usage when a reasoning-enabled request is
    expected to succeed.
  - A frozen, self-hashed per-role policy now covers every exact base and specialist role. Dynamic
    request-role forms resolve through one closed grammar into distinct semantic, configured-policy,
    and qualification roles; unknown and noncanonical forms fail before transport.
  - Model and endpoint discovery preserve explicit reasoning parameter support, mandatory/default
    state, max-token support, and published ceilings without inferring unknown capabilities.
    Paid requests require an exact frozen capability compatible with the selected role profile.
  - Request token-plan schema `2.0` binds the exact reasoning plan while retaining validation of
    legacy `1.0` hashes. Usage records require the routed plan and execution evidence to agree on
    role, request, profile, token-plan hash, request-body hash, and observed provider accounting.
  - Context evidence preserves observed zero versus unavailable reasoning. The run manifest binds
    configured policy, effective execution, endpoint capability, and qualification evidence and
    rejects effective-config drift. Markdown reports expose effective control, reserve, observed
    tokens, profile, capability, and qualification hashes.
  - Qualification now requires real benchmark usage with typed capability-bound reasoning evidence,
    seals cycle-free role/policy-pair bindings only after verification, preserves them through the
    production registry and OpenRouter routing projection, and rejects exact profile, capability,
    model, provider, report, result, or verification drift.
  - Candidate benchmarking uses the same frozen policy and endpoint capability evidence. Unsupported
    or incompatible reasoning is an explicit failed denominator, never silent suppression.
- **Safe pause continuation:**
  - Endpoint discovery now allowlists, canonicalizes, cross-checks, and hashes the exact
    `reasoning.supported_efforts` inventory. A named effort, including `none` or `xhigh`, requires
    exact inventory membership; generic reasoning support is insufficient.
    An independent review caught an intermediate model-catalog-derived implementation before
    checkpointing. The corrected evidence is sourced from the exact configured endpoint record,
    while the model-catalog inventory is retained separately and may only upper-bound that exact
    endpoint inventory. Missing exact endpoint inventory remains `None` and fails closed.
  - Qualification bindings now include the whole policy artifact hash and exact role-binding hash.
    The opaque capability and serialized registry projection both require the complete sorted
    approved-role/configured-policy route inventory and reject missing, extra, duplicate, unknown,
    or nested-to-parent mismatched routes.
  - Real post-qualification OpenRouter certification now requires the current opaque
    `VerifiedProductionQualification` capability and exact-compares every public routing and
    reasoning field before transport. Public self-hashes alone remain non-authoritative.
  - Context/usage credit exact-joins visible-output and reasoning reservations, requires token-plan
    schema `2.0`, and requires positive observed active reasoning. Strict legacy `1.0` omission
    normalizes only for preservation and remains non-creditable.
  - A transient import cycle introduced while joining the opaque authority was reproduced during
    collection and removed by keeping the OpenRouter-to-qualification dependency runtime-local.
    The OpenRouter synthetic routing fixture was upgraded to complete policy-bound role routes;
    no production gate was weakened.
- **Validation:**
  - `.venv/bin/ruff format src/mmaudit/models/openrouter.py src/mmaudit/models/usage.py
    src/mmaudit/orchestration/budgets.py tests/identity_fixtures.py
    tests/unit/test_budgets.py tests/unit/test_context_manifest.py
    tests/unit/test_token_planning_acceptance.py tests/unit/test_usage.py` — PASS; three files
    reformatted.
  - `.venv/bin/ruff check` over the same affected paths — PASS.
  - `.venv/bin/pytest -q tests/unit/test_budgets.py tests/unit/test_usage.py
    tests/unit/test_context_manifest.py tests/unit/test_token_planning_acceptance.py` — PASS;
    201 tests passed.
  - `.venv/bin/mypy src/mmaudit/models/openrouter.py src/mmaudit/models/usage.py
    src/mmaudit/orchestration/budgets.py` — PASS; no issues in three source files.
  - The first broader pytest command referenced nonexistent
    `tests/unit/test_openrouter_provider.py` and exited 4 before collection; it was not retried
    unchanged.
  - The next broader run exposed three synthetic responses that requested/reported reasoning
    without complete split evidence. The fixtures were corrected to report bounded reasoning
    usage; production gates were not weakened.
  - `.venv/bin/pytest -q tests/unit/test_openrouter.py tests/unit/test_model_runtime.py
    tests/unit/test_usage.py tests/unit/test_budgets.py
    tests/unit/test_openrouter_qualification_config.py` — PASS; 319 tests passed.
- **External effects:** None. No secret was read, no provider or network was contacted, and the
  cumulative OpenRouter ledger remains unchanged.
- **Continuation validation before full-suite gate:**
  - Focused reasoning and candidate policy matrix: `97 passed`.
  - Qualification, registry, OpenRouter, usage, manifest, context, discovery, runtime, and candidate
    matrix: `699 passed in 25.72s`.
  - Maximum-assurance synthetic pipeline regression: `1 passed in 13.39s`.
  - `.venv/bin/ruff format --check . && .venv/bin/ruff check .` — PASS; `384` files formatted and
    all checks clean.
  - `.venv/bin/mypy` — PASS; no issues in `156` source files.
  - `.venv/bin/python scripts/generate_release_schemas.py --write` followed by verification — PASS;
    the context-manifest schema is synchronized.
  - `git diff --check` — PASS.
  - First final `.venv/bin/pytest -q` attempt — INCOMPLETE: one clean-Anvil lifecycle
    integration exceeded its 12-second deadline under load; the run was then stopped after
    `113 passed, 5 skipped, 1 failed in 220.22s` to avoid waiting through the corpus with a known
    failure. The exact failed test subsequently passed alone in `1.55s`; the isolated pass does
    not replace the required complete-suite gate.
  - First remainder-suite run excluding that already-passed lifecycle test — FAIL:
    `47 failed, 3681 passed, 11 skipped in 572.07s`. All failures were in the generation-evidence
    fixture, whose synthetic usage declared two reasoning tokens without a typed reasoning plan or
    execution record. The fixture now uses the recognized `specialist:accounting_invariant` role,
    an exact two-token capability-bound plan, and matching execution evidence.
  - `.venv/bin/pytest -q tests/unit/test_generation_evidence.py` — PASS; `99 passed in 0.91s`.
  - `.venv/bin/pytest -q --ignore=tests/integration/test_clean_chain_integration.py` —
    PASS; `3728 passed, 11 skipped in 562.72s`. Together with the isolated
    `test_real_trusted_clean_anvil_lifecycle_is_pid_and_state_bound` pass, this covers the complete
    suite as `3729 passed, 11 skipped`.
  - `.venv/bin/ruff format .` — PASS; `384 files left unchanged`.
  - `.venv/bin/ruff check .` — PASS.
  - `.venv/bin/mypy` — PASS; no issues in `156` source files.
  - `.venv/bin/python scripts/generate_release_schemas.py` — PASS; generated schemas synchronized.
  - `git diff --check` — PASS.
  - Continuation component validations reported by the isolated implementation slices:
    endpoint/discovery capability `134 passed`; serialized registry routing `41 passed`;
    usage/context/token integrity `200 passed` and `170 passed`; affected Ruff and strict mypy
    passed in each slice.
  - Initial combined continuation run failed `49` OpenRouter tests because the stricter serialized
    route model correctly rejected legacy synthetic fixtures with an empty reasoning-route
    inventory. The shared fixture was repaired to emit complete policy-bound routes.
  - `.venv/bin/pytest -q tests/unit/test_openrouter.py` — PASS; `192 passed`.
  - `.venv/bin/pytest -q tests/unit/test_openrouter.py tests/unit/test_model_qualification.py
    tests/unit/test_model_registry.py tests/unit/test_usage.py tests/unit/test_context_manifest.py
    tests/unit/test_reasoning_qualification_binding.py
    tests/unit/test_reasoning_capability_evidence.py tests/unit/test_model_discovery.py
    tests/unit/test_candidate_benchmark.py` — PASS; `579 passed in 24.25s`.
  - Opaque-authority projection and no-authority-before-transport negative assays — PASS;
    `2 passed in 0.64s`.
  - Affected Ruff formatting changed three files; affected Ruff check passed, strict mypy passed
    over eight source files, release-schema verification passed, and `git diff --check` passed.
  - Final pause gate ran the full affected matrix after formatting and documentation updates:
    `581 passed in 24.50s`. In parallel, `.venv/bin/ruff format --check .` reported all `384`
    files formatted, `.venv/bin/ruff check .` passed, `.venv/bin/mypy` found no issues in `156`
    source files, release schemas verified, and `git diff --check` passed.
  - Independent review then identified that the first effort inventory came from model-level
    metadata rather than the exact endpoint. The first provenance-corrected component run exposed
    seven synthetic-fixture/projection inconsistencies; exact endpoint fixtures and the separately
    serialized model inventory were corrected without weakening the gate. The component matrix
    passed `94` tests, followed by the expanded affected matrix passing `639 tests in 24.27s`.
  - Final post-review pause gate — PASS: expanded matrix `639 passed in 24.80s`; all `384` files
    formatted; Ruff clean; strict mypy clean over `156` source files; release schemas synchronized;
    `git diff --check` clean.
  - **Validated partial-ticket checkpoint:**
    `82884f37b45b84c9ba43a002fe2128b871e26f04`.
- **Travel-pause continuation:**
  - REAL post-qualification transport now rejects absent and legacy reasoning controls and
    exact-compares the sealed role-policy request shape before transport.
  - Ensemble, maximum-assurance, pipeline-manifest, and verification-only replay paths now join or
    structurally validate the opaque qualification authority without promoting a serialized
    projection into fresh runtime credit.
  - Active qualification requires positive observed reasoning for every non-disabled profile.
    Distinct production profiles require fresh, non-reused, full-corpus supplemental benchmark
    evidence bound to exact report, verification, and generation-evidence hashes.
  - The combined reasoning, benchmark, qualification, OpenRouter, and manifest matrix passed
    `398 tests in 66.25s`; the maximum-assurance pipeline regression passed in `15.71s`.
    Affected Ruff, strict mypy, and `git diff --check` passed.
  - Release-schema verification initially identified the expected stale context-manifest schema
    after the new authority fields. `.venv/bin/python scripts/generate_release_schemas.py --write`
    synchronized it, and immediate verification passed.
- **Remaining limitation:** The qualification workflow generation-refetch helper and candidate
  benchmark campaign still execute and authenticate only the primary report. They must be extended
  to cover every required supplemental profile report in one live campaign. Until that integration
  and the complete suite run, `V3-EFFORT-001` remains `PARTIAL` and the release remains
  `INCOMPLETE`.
- **Pause boundary:** At `2026-07-31T03:37:51Z`, all workers were stopped at an atomic
  provider-free boundary. No provider, network, or secret access occurred and the cumulative
  OpenRouter ledger remains unchanged. Resume with the supplemental-profile campaign integration,
  not with already-validated authority joins. The isolated implementation checkpoint is
  `36eff43d3b79637ce193d6a3dff7c8d65fafddac`.

## 2026-07-30 — V3-LINEAGE-001

- **Status:** `PARTIAL` (provider-free lineage identity binding complete; real decision binding
  unavailable).
- **Defensive objective:** Bind an operator decision to the exact refreshed candidate inventory
  without granting production selection, source-egress, or quality authority before calibration
  and qualification.
- **Consumer audit correction:** Model-independence validation previously invented
  `heuristic:<vendor/family>` roots for models absent from the immutable operator-reviewed
  registry. Candidate falsifier selection deduplicated registered roots but did not require those
  roots to be in `privacy.approved_model_lineages`. Both paths now fail closed: unknown models
  receive no independence credit, strict profiles report the missing lineage records, and
  falsifier candidates outside the approved set are excluded.
- **Validation:** Affected Ruff formatting/checking and strict mypy passed. The focused
  configuration/cross-examination suite passed `44` tests; the wider registry, coverage,
  assurance, benchmark, candidate-benchmark, cross-examination, and configuration matrix passed
  `331` tests in `28.73s`. Only inherited pytest temporary-directory cleanup warnings were
  emitted.
- **Independent artifact audit:** The lineage decision must be a separate overlay because
  resealing a candidate registry would invalidate the exact registry hash already bound by
  refresh evidence. It must replay source-to-snapshot evidence, revalidate the discovery join,
  recompute current freshness at a trusted time, cover the exact candidate set once, verify
  bounded evidence bytes, collapse canonical/routing variants, and expose no conversion to
  production quality or privacy authority. A workflow-status self-hash alone is inventory
  metadata, not provider authority.
- **Real-evidence limitation:** No successful post-correction real refresh snapshot exists, the
  frozen registry is obsolete, and the documentary decision lacks a whole-second UTC decision
  time and omits one listed candidate. Therefore this ticket can close only the safe synthetic
  implementation slice and must remain `PARTIAL`; it cannot truthfully activate public or private
  source egress.
- **Typed overlay implementation:** Added a frozen, self-hashed lineage-identity-only artifact
  with literal public-open-source scope, `NOT_EVALUATED` quality, and hard-coded false
  source-egress/production-selection authority. Its builder revalidates the pending/rootless
  discovery registry, replays allowlisted refresh source into the exact supplied snapshot,
  reproduces `CURRENT` freshness at a trusted whole-second UTC time, verifies bounded raw review
  evidence bytes, binds exact candidate/model/route state, and rejects incomplete, overlapping,
  mistimed, stale, identity-drifted, variant-split, or root-split decisions. Descriptor-safe
  private JSON persistence and a generated strict schema are included.
- **Overlay focused validation:** Ruff and strict mypy passed; schema generation and verification
  passed; `tests/unit/test_model_lineage_review.py` plus the general release-schema registry
  ultimately passed `16` tests in `0.46s`.
- **Adversarial overlay corrections:** Read-only review found that nested operator-review models
  were mutable after the outer hash was sealed, freshness limits were supplied by the record they
  judged, and permissive JSON coercion diverged from the published schema. Nested decisions are
  now frozen, the builder and validator require explicit trusted age-policy inputs, strict JSON
  loading rejects stringified integers and integer booleans, and authority flags accept only
  literal `false`. The artifact now machine-labels itself `PROVIDER_FREE_STRUCTURAL` and records
  that provider-observation and operator-decision authenticity are
  `NOT_INDEPENDENTLY_PROVEN`. Exact re-assays passed; no remaining code-level fail-open was found.
- **Existing-consumer regression expansion:** Five additional negative assays prove that approval
  revocation fails closed during assignment feasibility, substantive usage credit, assurance
  revalidation, benchmark egress, and production qualification. Their focused selector passed
  `5` tests with `268` unrelated tests deselected.
- **Joined focused gate:** The lineage overlay, discovery, refresh, refresh staging/schema,
  qualification, registry, coverage, assurance, benchmark, candidate benchmark,
  cross-examination, configuration, and release-schema matrix passed `565` tests in `40.92s`.
- **Repository-wide gate:** Ruff left `380` files unchanged and passed all checks; strict mypy
  passed `155` source files; generated schemas and `git diff --check` passed. The complete
  sandboxed pytest run reached `3549 passed, 15 skipped, 71 errors in 422.30s`; every error was
  a setup-time `PermissionError [Errno 1]` from the managed sandbox denying the local read-only
  RPC bridge permission to bind `127.0.0.1`. The exact affected file was rerun with only
  local-loopback permission and passed all `76` tests in `41.04s`. Thus every collected test
  passed or carried an explicit external-prerequisite skip (`3620` unique passes, `15` skips).
  Paid-provider execution remained disabled.
- **External effects:** No provider call, network request, credential access, `.env` read, or
  OpenRouter spend occurred. Production `approved_model_lineages` remains empty.
- **Next safe action:** Create and push the isolated checkpoint, then begin `V3-EFFORT-001`.
  Return to real lineage binding only when a successful current refresh and complete
  independently authenticated operator decision exist.

## 2026-07-30 — V3-MODELREFRESH-001

- **Status:** `PARTIAL` (provider-free discovery/diff/workflow slice complete).
- **Defensive objective:** Refresh and compare time-bound provider catalogue evidence without
  allowing discovery to qualify, promote, or silently substitute a model.
- **Starting boundary:** No paid benchmark, provider completion, lineage inference, or production
  promotion is authorized by this slice. Synthetic local snapshots and fake transports will
  establish deterministic classification, stale/failure distinction, idempotence, and fail-closed
  selection gates before any explicitly opted-in metadata refresh.
- **Architecture audit:** Existing exact-route discovery and runtime request preflight already
  reject endpoint, pricing, capability, ZDR, and model-metadata drift, but discovery only records
  successful operator-named routes. It cannot represent catalogue withdrawal or endpoint loss,
  and production selection has no independent current-catalogue freshness input. The scheduled
  workflow is weekly, references an absent default config, and emits no refresh artifact.
  Persisted self-hashes alone will not be treated as live provider authority.
- **Static policy slice:** Added exact canonical Decimal pricing tolerance, soft/hard snapshot age,
  and disabled-by-default daily/per-model automatic benchmark ceilings beneath
  `models.catalog_refresh`. Dynamic observations remain outside configuration and candidate
  registry hashes. Two focused configuration regressions and affected Ruff passed.
- **Qualification freshness correction:** A fresh benchmark campaign can no longer qualify a
  candidate whose bound discovery predates the policy's maximum evidence age. The synthetic
  negative regression and affected Ruff check pass.
- **Normalized discovery evidence:** Added strict self-hashed source projection, snapshot, diff,
  terminal-attempt, freshness, and workflow-status models plus six published JSON Schemas.
  Snapshot normalization
  covers the full exact-ID catalogue, ZDR routes, and authoritative exact candidate endpoint
  responses. Every required drift class retains exact before/after state; aliases and
  `-fast`/`:batch` variants can trigger lineage review but never acquire lineage authority.
- **Fail-closed route and price handling:** Empty exact endpoint results override stale ZDR
  entries. Withdrawn, non-operational, provider-changed, required-parameter-deficient,
  canonical-identity-changed, non-ZDR, and unobserved selected routes block with exact top-level
  reasons. Selected routes must match the frozen registry before secret access. A hash-only price
  baseline never fabricates values; exact tolerance comparison is credited only when prior exact
  pricing hashes to the frozen candidate value. A repeated observation can be semantically
  unchanged while remaining production-blocked when its live price no longer matches the frozen
  qualified binding.
- **Typed provider boundary:** Added `mmaudit models refresh`, using only authenticated metadata
  GETs and no completion or usage record. Duplicate-key, non-finite, exponent-overflow, malformed
  nested metadata, authentication, timeout, rate-limit, provider-unavailable, and secret
  prerequisite failures remain typed. Operator-credential reflection anywhere in metadata is
  rejected before allowlisted projection or persistence. A canary regression confirms no reflected
  value reaches output or diagnostics.
- **Strict scheduled staging:** The daily protected-default-branch workflow now runs provider-free
  regressions before the protected job, removes its explicit mode-`0600` secret before staging,
  and uploads only a reconstructed exact inventory. The staging validator checks private
  unshared files, canonical JSON, self/cross-hashes, registry/baseline/selected-route joins,
  source/workflow identity, exact `0.05` pricing and `30`/`72` freshness controls, and a current
  observation. Exit `0`, `4`, `6`, and `78` have disjoint exact contracts. A failed final
  inventory is atomically quarantined away from the upload path.
- **Adversarial corrections:** Independent read-only reviews identified and regressions now cover
  stale-ZDR endpoint resurrection, skipped selected-route checks, omitted withdrawn-model
  blockers, canonical identity drift, nested Pydantic failures without a receipt, exponent
  overflow, credential reflection, policy-mismatched staging, hard-expired staging, and
  injected-file upload residue. A final independent review also found four provider-shape and
  identity gaps before checkpointing: valid trailing-zero prices and numeric non-billable
  discount metadata were rejected; legitimate routed aliases in the full ZDR inventory failed
  the entire refresh; secondary endpoint identity drift was neither classified nor blocking; and
  a mismatched ZDR row could confer eligibility by sharing only one endpoint label. Refresh now
  reuses the production pricing and tag/slug/provider-name normalizers, ignores only syntactically
  valid routed ZDR aliases while retaining their bounded occurrence projection, validates optional
  item model
  bindings, compares exact prior tag/slug identities, and grants ZDR only after the authoritative
  exact endpoint and ZDR counterpart agree across normalized identity, provider, status,
  capabilities, limits, and billable pricing.
- **Validation so far:** The joined refresh/config/qualification/schema slice passed `95` tests in
  `2.53s`; the later adversarially hardened refresh/schema slice passed `62` tests in `1.26s`.
  A workflow validation attempt passed `16` tests but then found PyYAML absent and used a flawed
  regex shell extractor; both validation commands failed without changing code. The corrected
  Ruby YAML traversal parsed the workflow and validated all `10` `run` scripts with `bash -n`.
  Ruff and strict mypy pass on the affected implementation. The sandboxed complete pytest run
  reached `3454 passed, 15 skipped, 71 errors in 660.72s`; every error was a setup-time
  `PermissionError [Errno 1]` from the sandbox denying the local read-only RPC bridge permission
  to bind `127.0.0.1`. The bridge file was therefore rerun with only local-loopback permission:
  `.venv/bin/pytest -x -vv tests/unit/test_read_only_rpc_bridge.py` passed all `76` tests in
  `40.68s`. One failure seen in an earlier interrupted attempt did not reproduce. The complete
  run under the same local-only permission then passed `3529` tests with `11` explicit
  external-integration skips in `516.92s`. Pytest emitted two non-fatal cleanup warnings for
  already-restricted temporary `clean-anvil/toolchain` paths; no test or gate failed.
  After the final independent review corrections, the complete affected refresh, endpoint,
  OpenRouter, configuration, qualification, workflow, and schema slice passed `422` tests in
  `39.60s`; generated release schemas matched. Repository-wide Ruff formatting/checking, strict
  mypy over `154` source files, generated-schema verification, and `git diff --check` then passed.
  The corrected complete suite passed `3534` tests with `11` explicit external-integration skips
  in `493.12s`.
- **External effects so far:** No completion, model spend, target access, public RPC, wallet,
  signing, or broadcast occurred. The first explicitly opted-in authenticated metadata-only
  refresh read `.env` only through the operator
  secret interface, issued no completion, created zero usage records, and failed closed as
  `MALFORMED_METADATA`. Its exact private failure receipt passed strict staging as `FAILED`.
  A non-raw diagnostic isolated rejection of the full model catalogue before any ZDR or
  exact-endpoint normalization; an aggregate public-catalog shape check observed `364` records,
  of which `10` used the documented `~author/family-latest` router syntax. No provider-controlled
  value or credential was printed or persisted. The cumulative OpenRouter ledger remains
  `0.0033415625` USD spent with zero reservation.
- **Real-catalog correction:** Added one shared bounded catalog-ID grammar that accepts current
  tilde-prefixed router rows as non-exact discovery metadata. Refresh hash-binds and excludes
  those rows from its exact-model semantic projection, while request, qualification, selection,
  and endpoint paths continue to reject them as non-exact. Malformed catalogue identifiers still
  fail closed. The correction passed `250` focused tests plus affected Ruff, mypy, and
  generated-schema verification. The complete suite then passed `3544` tests with `11` explicit
  external-integration skips in `500.97s`.
- **Second authenticated metadata assay:** The exact command recorded in `LAST_COMMAND` ran
  against source checkpoint `ddf2d2d2df947b77da53fc55968cc67eba9917e1` and failed closed with
  exit `4`. It issued metadata GETs only, created zero usage records, and made no completion
  request. One non-raw diagnostic isolated the distinct normalization incompatibility:
  `ModelRefreshValidationError: ZDR catalogue contains duplicate exact routes`. Current provider
  metadata can contain multiple routes sharing a tag while retaining distinct endpoint slugs;
  collapsing the full `(tag, slug)` identity to one label is therefore ambiguous. No raw payload,
  credential, Authorization data, or provider-controlled value was persisted in this worklog.
- **No-progress and pause boundary:** Two materially different authenticated refresh attempts
  have now failed closed on distinct provider-shape incompatibilities. A third provider attempt
  is prohibited for this ticket. At `2026-07-30T20:22:44Z`, the operator requested a pause; the
  read-only endpoint-identity review was stopped and no implementation edit had begun. Resume
  with local deterministic normalization that preserves the complete route identity, rejects
  genuinely ambiguous candidate bindings, and grants ZDR only to an exact reconciled
  counterpart. Add synthetic regressions and run local gates before checkpointing.
- **Resume boundary:** Autorun resumed from the clean synchronized pause checkpoint. The next
  slice is local and provider-free: represent exact endpoint rows by their complete tag/slug
  identity, derive only injective public route identifiers across each model's endpoint
  inventory, and retain the production endpoint validator's fail-closed ambiguity semantics.
  No third authenticated refresh attempt is authorized for this ticket.
- **Exact capability parity:** Live routes now reuse the production endpoint parameter and
  token-limit normalizers, preserve prompt/completion values and fallback sources, and bind the
  model/endpoint intersection of all supported output modes. Padded operational statuses and
  duplicate parameter inventories fail closed. Prompt-limit loss, source-only drift, and
  native-schema-to-JSON-object downgrade are explicit changes; an unchanged exact selected route
  is no longer false-blocked merely because catalog-level capacity metadata drifted.
- **Candidate baseline honesty:** Candidate records can retain discovery-bound prompt capacity and
  prompt/completion sources alongside the existing output-capability hash and exact mode. Those
  facts are all-or-none and revalidated against the exact endpoint snapshot. Hash-only legacy
  candidates retain null unknown facts rather than derived provider claims; they remain usable
  for unselected discovery but cannot satisfy a selected production route.
- **Semantic staging correction:** Strict staging now deterministically reconstructs the complete
  diff from the current snapshot, exact previous or registry baseline, frozen candidate registry,
  selected routes, tolerance, and comparison time. A fully resealed, self-consistent diff that
  omits real capability drift is rejected, closing reliance on declared nested before/after
  values.
- **Producer chronology correction:** The producer now requires the semantic diff comparison time
  to equal the current snapshot retrieval time and rejects a paired exact prior snapshot whose
  retrieval time is later than the current observation. Direct diff and fake-provider CLI
  regressions prove that the previously accepted inverted baseline now fails closed and that the
  CLI persists only a typed failure attempt rather than a success bundle. An independent
  provider-free replay confirmed both cases.
- **Selected bootstrap identity correction:** A final adversarial review proved that the
  registry-only baseline lacks the complete endpoint tag/slug pair and therefore could not detect
  secondary endpoint-identity drift for a production-selected route. Selected routes now carry an
  explicit `ENDPOINT_IDENTITY_UNVERIFIED` classification and block until an exact replayable prior
  snapshot exists; unselected discovery remains available. The former dual-identity `UNCHANGED`
  result is a deterministic negative regression. The focused refresh/schema/staging/CLI matrix
  passed `110` tests after schema regeneration.
- **Allowlisted source replay correction:** Success evidence now includes a fifth runtime artifact,
  `model-refresh-source-evidence.json`, containing only bounded canonical catalogue, routed-alias,
  ZDR, and exact-candidate endpoint fields used by the semantic projection. Unknown provider fields
  are dropped. The snapshot binds the source self-hash and canonical catalogue/ZDR projection
  hashes; staging rebuilds the snapshot from the retained source and frozen registry before
  replaying the diff. A negative regression fully reseals a false snapshot, diff, attempt, and
  freshness record while leaving the source unchanged; staging rejects it. Cross-run source swaps,
  nullable token provenance, order invariance, private five-file inventory, and schema bounds are
  also covered. This proves deterministic projection from the staged authenticated-observation
  artifact, not cryptographic provider authorship; OpenRouter does not sign these metadata bodies.
  Live snapshot schema types now require exact route pricing, prompt/output provenance, and an exact
  output mode, while diff baselines may still represent honest hash-only candidate evidence.
- **Independent time and baseline validation:** Strict staging now evaluates future skew and
  freshness against a trusted local validation clock recorded in workflow-status schema v2, rather
  than trusting an artifact-relative timestamp. An exact previous baseline is accepted only as a
  paired source/snapshot input whose projection is replayed against the frozen registry. Exact
  filename-to-self-hash mapping prevents one artifact's hash-shaped field from satisfying another
  artifact's inventory entry, and diff `after` values require live exact state rather than the
  hash-only baseline type. Fully resealed future, stale, source-mismatched, prior-mismatched,
  wrong-artifact-hash, hash-only-after, and workflow-v1 regressions all fail closed.
- **Provider-free regression evidence:** The initial schema verifier reproduced the expected
  stale v2 snapshot/diff schemas and exited `1`; regeneration followed by verification passed.
  The refresh suite passed `52` tests; qualification/refresh/staging coverage passed `201`;
  schema/staging/workflow coverage passed `30`; and the expanded endpoint/discovery/refresh/
  qualification/workflow matrix passed `310` tests in `51.98s`. The later source-replay and exact
  capability matrix passed `343` tests in `53.36s`; its narrower red/green matrix passed `107`
  tests. Affected Ruff and strict mypy passed, and generated schemas were synchronized. Two
  inherited temporary-tree cleanup warnings were non-failing.
  Three independent post-implementation reviews replayed the source/snapshot, staging-time,
  prior-baseline, self-hash, capability, and chronology negative assays. Their only concrete
  remaining producer-boundary chronology finding was corrected and independently re-tested.
  Repository-wide Ruff format/check left all `378` files unchanged and passed, strict mypy passed
  all `154` source files, generated-schema verification and `git diff --check` passed, and the
  complete suite passed `3601` tests with `11` explicit external-prerequisite skips in `496.79s`.
  The workflow YAML parsed and all `11` embedded shell scripts passed `bash -n`; the first Ruby
  command used an unsupported Ruby 2.6 keyword and exited `1`, then the compatible safe-load
  command passed. Two inherited temporary-tree cleanup warnings were non-failing.
- **Remaining partial work:** The scheduled workflow does not yet retrieve a durable prior
  snapshot or bind a real production selection; the audit pipeline does not consume the refresh
  freshness artifact. Automatic benchmark reservation/execution, refreshed-price runtime
  authority, lineage re-evaluation, and production promotion remain gated by calibration,
  qualification, lineage review, and the cumulative ledger. Snapshot/diff v1 is intentionally
  rejected by v2; until durable prior retrieval includes a reviewed migration, the first v2 daily
  run must use the explicit registry baseline rather than silently treating v1 as exact history.
  Exact source/snapshot history also binds the complete candidate-registry hash, so a later
  qualification or registry-status update invalidates prior replay and forces another fail-closed
  bootstrap; durable retrieval needs an explicit cross-registry continuity design rather than
  merely downloading the old pair.
- **Ticket boundary:** No further provider action is permitted within this ticket. Preserve the
  validated provider-free slice as `PARTIAL`, checkpoint it, and continue with the next independent
  queue ticket.
- **Final corrected gate:** After the selected-route bootstrap correction, the expanded touched
  matrix passed `354` tests in `54.98s`; repository-wide Ruff format/check left all `378` files
  unchanged and passed; strict mypy passed all `154` source files; release-schema verification and
  `git diff --check` passed; and the complete suite passed `3602` tests with `11` explicit
  external-prerequisite skips in `505.06s`. The paid-provider test remained disabled. Workflow
  YAML and all `11` embedded shell scripts passed their provider-free syntax checks. Final status
  and filename-only artifact inspection found only the intended source, generated schema,
  workflow, documentation, and regression changes; no tracked operator secret file, private
  runtime artifact, or credential-value pattern was added.
- **Disposition:** `PARTIAL`. The deterministic provider-free slice is complete and independently
  reviewed. There is no successful post-correction real metadata snapshot, durable prior retrieval,
  cross-registry continuity, pipeline freshness consumption, refreshed-price budget authority,
  automatic benchmark execution, lineage re-evaluation, or promotion path. No completion,
  provider call, secret access, public RPC, target access, wallet, signing, broadcast, or spend
  occurred in the final provider-free implementation slice.
- **Validated checkpoint:** `9d70253f58f759ac2b6b930cc4a9c2efef21cf79`. Push it through
  the SSH remote with the following transition record, then continue the provider-free
  reviewed-lineage binding in `V3-LINEAGE-001`.

## 2026-07-30 — V3-LINEAGE-001 starting state

- **Status:** `PARTIAL` (provider-free reviewed-lineage binding implemented and validated).
- **Defensive objective:** Bind an explicit operator lineage decision to exact refreshed candidate
  evidence without inferring lineage from vendor labels or inventing qualification-derived quality.
- **Starting checkpoint:** `9d70253f58f759ac2b6b930cc4a9c2efef21cf79`.
- **Starting evidence:** An operator decision record exists, but it is documentary and deliberately
  not copied into the obsolete frozen candidate registry. Production quality fields and
  `privacy.approved_model_lineages` remain empty, so private-source egress remains fail-closed.
- **Completed safe slice:** Reused the existing lineage review, candidate registry, discovery,
  refresh, privacy, and qualification abstractions to implement a strict, hash-bound,
  provider-free review artifact and exact candidate-evidence join with synthetic local
  regressions. No provider refresh, operator secret, qualification-derived quality, or production
  source-egress activation occurred.
- **Exact next safe action:** Create and push the ticket checkpoint, then begin
  `V3-EFFORT-001`.

## 2026-07-30 — V3-CALIBRATE-001

- **Status:** `PARTIAL`.
- **Defensive objective:** Derive a frozen, hash-bound qualification policy from observed
  non-empty benchmark distributions without allowing calibration to qualify a model, and retain
  strict deterministic gates where perfect behavior is required.
- **Starting evidence:** `config/models.maximum-assurance.toml` requires a perfect score on all
  seventeen dimensions and a perfect overall score. `QualificationDisposition` exposes only
  `TIER_A`, `NOT_QUALIFIED`, and `INCONCLUSIVE`; the workflow applies only the global policy and
  cannot express a role-scoped investigator-only qualification. No calibration artifact or
  calibration execution mode exists.
- **Initial next safe action:** Add failing schema/policy regressions for a non-dispositive
  calibration result, non-vacuous distribution-bound thresholds, and role-scoped secondary
  disposition. Preserve the independent verifier and frozen-policy requirements. No provider,
  secret, public RPC, wallet, signing, broadcast, or external-target operation is required.
- **Initial regressions:** The first calibration collection failed as expected with
  `ModuleNotFoundError` because no calibration module existed. The independent role-policy
  regression also failed collection because no role-scoped derivation API existed. Intermediate
  runs retained six role-policy failures and then seven timestamp/policy/schema failures until the
  corresponding implementation and generated-schema bindings were corrected.
- **Implemented safe slice:** Added a strict non-dispositive calibration schema and implementation,
  canonical mode-0600 artifact persistence, exact candidate/discovery/corpus/truth/portfolio/
  policy/config/journal joins, explicit exclusions, campaign-time lineage decisions, and exact
  per-dimension distributions. Candidate benchmark CLI mode can emit the artifact only from a
  fresh complete live campaign and preflights its output before provider work. Calibration cannot
  issue a qualification disposition.
- **Measured-policy structure:** Qualification policy schema v2 carries a rationale and exact
  calibration-distribution hash for every threshold. The three designated hard-gate dimensions
  retain exact `1.0`; judgment dimensions require at least four cases and a measured non-absolute
  score.
  At least three complete REAL candidates from three campaign-timely approved lineages are
  required. Investigator, verifier, falsifier, and judge policies have mandatory semantic
  dimensions and can only narrow a globally Tier-A model's authority.
- **Runtime authority hardening:** Calibration authority is issued only by rebuilding exact live
  campaign provenance; calibrated-policy sealing additionally requires at least three complete
  REAL models from three approved root lineages. Campaign issuance replays the private journal and
  exact report bindings. Raw campaign capability registration was removed, and fresh-journal
  binding is attached only to the exact newly created journal; a resumed campaign cannot reattach
  live provenance. Regression tests assert that the former raw registrar/state names are not
  module-reachable.
- **Validation so far:** Schema generation write and verify completed successfully. A joined
  pre-hardening slice passed `123` tests in `43.72s`; the timestamp/lineage follow-up passed `13`
  tests in `7.60s`. A later joined campaign/calibration/qualification/schema run passed `130`
  tests in `51.54s`, and the final authority-hardened repeat passed `130` tests in `317.29s`.
  A mistyped joined command naming absent `tests/unit/test_schema_generation.py` exited `4` with
  no tests collected; it was corrected to the actual schema test files. Affected Ruff and strict
  mypy checks pass.
- **Exact focused acceptance command:** `.venv/bin/pytest -q tests/unit/test_candidate_benchmark_campaign.py tests/unit/test_model_calibration.py tests/unit/test_model_calibration_cli.py tests/unit/test_qualification_policy_calibration.py tests/unit/test_role_qualification.py tests/unit/test_qualification_workflow.py tests/unit/test_model_qualification.py tests/unit/test_model_qualification_schema.py tests/unit/test_release_schemas.py` — PASS, `130 passed in 317.29s`.
- **Final repository validation:** `.venv/bin/ruff format .` left `370` files unchanged;
  `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed all `152` source files;
  `.venv/bin/python scripts/generate_release_schemas.py` verified synchronization;
  `python -m json.tool docs/remediation/v3/review_traceability.json` and
  `git diff --check` passed. The full `.venv/bin/pytest -q` run, with only numeric local loopback
  enabled, passed `3464` tests with `11` explicit external-prerequisite skips in `781.73s`. Two
  inherited stale temporary-tree cleanup warnings were non-failing.
- **Disposition rationale:** No real calibration run or measured v2 policy is claimed. The
  committed v1 policy remains unchanged because most judgment dimensions have only two cases,
  the stale candidate registry has no approved lineages, literal verifier/judge roles are absent,
  and per-role reasoning effort is not yet bound. The predecessor-policy/config binding of a
  calibration campaign versus the later derived-policy qualification campaign also needs an
  explicit two-campaign lifecycle before paid qualification.
- **Narrow blocked review:** One auxiliary read-only authority review was rejected by the platform
  and is recorded `BLOCKED_SAFETY` without retrying the same content. The root agent completed the
  local source review and added the campaign authority regressions; this does not block the safe
  implementation slice.
- **External effects:** No provider call, model spend, secret access, public RPC, wallet, signing,
  broadcast, or external-target operation occurred. `.env` was not read and the cumulative
  OpenRouter ledger remains `0.0033415625` USD spent with zero reservation.
- **Remaining acceptance work:** Refresh and diff the current model catalogue, complete independent
  operator lineage review and role-specific effort controls, expand the frozen judgment corpus,
  resolve the two-campaign policy lifecycle, then execute a real non-dispositive calibration and
  freeze the measured v2 policy before any qualification campaign.
- **Implementation checkpoint:** `937d97e1d337305ac56cd792fe0d6c2b8bd50674`
  (`Add evidence-bound model calibration`).

## 2026-07-30 — V3-CI-001

- **Status:** `PARTIAL`.
- **Defensive objective:** Make pull-request analysis structurally model-free and secret-free,
  retain evidence after fail-closed exits, execute applicable repository-owned tests only through
  hardened isolation, and compare current deterministic evidence with a source- and
  producer-bound prior run.
- **Starting evidence:** The existing workflow's scanner job does not receive the provider key and
  calls the scanner-only command, but it neither executes the configured fork suite nor passes a
  changed-since base. Its artifact observation and upload steps run only after audit success, and
  the isolated SARIF job explicitly excludes pull requests. The repository has replay and
  qualification journals, but no general CI resume artifact. Existing run-manifest verification is
  not a safe cache oracle because it validates the prior scoped source list rather than
  rediscovering the complete current scanner workspace or re-resolving intended producer
  identities.
- **Exact next safe action:** Add typed CI state/comparison models and regressions proving that
  source additions, source drift, producer/config drift, unavailable isolation, secret/model
  workflow references, and reduced coverage cannot receive reuse or unchanged credit.
- **Implementation slice preserved at operator pause:** Typed CI evidence, comparison, repository
  suite, baseline loading, pipeline artifact emission, CLI execution mode, provider-free pull-request
  workflow, trusted provider workflow, README guidance, and focused unit coverage are present but
  uncommitted and remain under review. The last focused CI-state run passed `19` tests; the workflow
  slice passed `7` tests plus YAML and shell-syntax checks. These are intermediate results, not
  ticket acceptance.
- **Outstanding adversarial review findings:** Normalize volatile location-validation timestamps;
  require valid host location annotations; bind unchanged findings to the complete scanner
  workspace; reject incomplete or failed states from whole-run reuse and cache admission; validate
  all report-to-state summary projections; enforce scanner/finding attribution; and annotate the
  typed test helper return. A failed default-branch result must not poison the next baseline cache.
- **Pause state:** `PAUSED_BY_OPERATOR`. All subagents were stopped or already complete. No
  checkpoint commit was created because this ticket is not yet coherent or validated.
- **Resumed implementation evidence:** Host location-validation records are normalized without
  volatile timestamps, invalid or misattributed scanner findings become explicit analysis
  failures, unchanged credit requires the complete workspace/source tree, and whole-run
  equivalence binds semantic tool output, finding, coverage, and suite evidence. CI minimum-floor
  coverage now excludes model/formal/invariant obligations that cannot apply to the structurally
  provider-free scanner-only mode while preserving the complete forensic coverage artifact.
  Scanner-only CI remains explicitly `DEGRADED`, never a full-audit `COMPLETE` claim.
- **Focused results after resume:** CI-state Ruff and strict mypy passed; `30` CI-state tests
  passed. The four pipeline acceptance tests passed in `8.25s`; the seven CLI-focused tests and
  eight workflow tests passed independently. Workflow YAML, every shell block, and cache-admission
  ordering were also validated. No provider, secret, paid call, public RPC, wallet, signing,
  broadcast, or external-target operation occurred.
- **Second operator pause:** `PAUSED_BY_OPERATOR`. The joined validation produced exactly one
  failure and `270` passes in `158.66s`; the failure was a stale published run-evidence manifest
  schema after four CI override paths were added. The schema synchronization edit is preserved,
  but no acceptance rerun or checkpoint commit has occurred. Both active independent review agents
  were stopped at this safe boundary.
- **Second resumed validation:** The published-schema focus passed `2` tests, the full joined
  CI/config/manifest/run-status/schema/pipeline matrix passed `271` tests in `126.62s`, Ruff
  formatting left `365` files unchanged, Ruff checking passed, strict mypy passed `151` source
  files, and generated release schemas verified synchronized. The ordinary full suite reached
  `3318 passed, 15 skipped`; all `71` setup errors were the same managed-sandbox denial while
  binding a numeric-loopback test listener. That environmental result is not recorded as a green
  full suite and requires the established loopback-enabled validation mode after code closure.
- **Independent adversarial defects reproduced:** A non-qualifying scanner declaration could
  receive reusable CI credit; scanner invocation drift was not bound; reduced repository-suite
  selection could remain `CLEAN`; extra report CI-projection keys and a contradictory report source
  inventory were admitted; wildcard failure artifacts could include checkout decoys; and the cache
  staged the complete run including `private/`. Three new integration assays produced the expected
  pre-fix result `3 failed, 9 passed in 7.72s`. The workflow also lacks a provisioned, pinned,
  loopback-capable external execution stack, so positive real suite execution remains an explicit
  technical integration limitation rather than release evidence.
- **Final core correction:** CI tool reuse now delegates to the canonical qualifying real-scanner
  gate and retains adapter-normalized successful finding exits. Repository-suite state binds
  selected and executed test descriptor identities, so an equal-count replacement is a coverage
  regression. Invocation hashing no longer treats unproven `.mmaudit`, `src/mmaudit`,
  `runs/private`, `tmp`, `_temp`, or `runs/workspace` lexical names as volatile, and distinguishes
  default from explicit loopback ports. The focused core suite passed `48` tests; an independent
  read-only review found no remaining blocker in these three invariants.
- **Projection and snapshot correction:** Public baseline admission now joins effective and model
  configuration, repository root, changed-since, audit profile, and exact configured/observed tool
  bindings across state, report, and reconstructable manifest. The exact three-file bundle is
  captured beneath held no-follow directory descriptors, then re-observed through both the held
  and current root before parsing captured bytes. Coherently resealed configuration/root/tool/report
  projections and same-byte root/member replacements now fail closed. The expanded focused matrix
  passed `84` tests. FIFO substitution cannot block because both bundle and full-admission reads
  require `O_NOFOLLOW|O_NONBLOCK`; exact inventory rejects after at most four entries. Independent
  post-fix projection, snapshot, manifest-compatibility, workflow, and core reviews found no
  remaining material blocker.
- **Final validation:** The joined CI/CLI/config/manifest/schema/run-status/pipeline matrix passed
  `312` tests in `116.20s`. `.venv/bin/ruff format .` left `365` files unchanged,
  `.venv/bin/ruff check .` passed, strict `.venv/bin/mypy` passed all `151` source files,
  release-schema generation exited successfully, and `git diff --check` passed. The final
  `.venv/bin/pytest -q` run passed `3434` tests with `11` explicit prerequisite skips in
  `511.50s`. The prior isolated timeout remains recorded rather than overwritten; its exact
  three-case rerun and complete `78`-test file passed before the green full rerun.
- **Disposition:** `PARTIAL`. All safe implementation, adversarial regression, evidence-binding,
  serialization, workflow, and validation work in this ticket is complete. The hosted workflow
  still does not provision or execute the complete digest-pinned compiler, Slither,
  Foundry/Hardhat, rootless-isolation, and local-loopback stack. Applicable unavailable execution
  fails closed, but positive real fork-suite execution is `BLOCKED_TECHNICAL` and is not claimed.
- **Secret/artifact review:** The final changed-file scan found only five deliberately synthetic
  `sk-or-v1-...` canaries in defensive tests; no real credential pattern or generated runtime
  artifact was added. `.env` was not read. The worktree contains only the recorded source,
  workflow, schema, documentation, and test changes.
- **Pause state:** `PAUSED_BY_OPERATOR`. V3-CALIBRATE-001 had not started at this checkpoint. The cohesive
  V3-CI-001 implementation is checkpointed at
  `5e61fcad6bf93aab5d4aec4dd3765302d40d25ed`; the state-record commit was
  `360e3c0fbb5d2e892e220633462cb40e54cb1518`, and both were pushed through the SSH remote.

## 2026-07-30 — V3-TESTQUALITY-001

- **Status:** `IN_PROGRESS`.
- **Goal continuation:** Autorun resumed from the preserved operator pause after
  re-reading the complete 1,417-line product-completion objective, repository
  instructions, current queue/worklog, Git status, and affected diff. Work
  remains bounded to the four recorded focused regressions and the current
  ticket's fail-closed validation; no paid provider, network, secret, public
  RPC, wallet, signing, broadcast, or external-target operation is in scope.
- **Focused repair slice:** Standard profile assignment and feasibility now
  share a scheduled-role inventory and reject injected unscheduled specialists;
  deep/max profiles retain configured coverage-gap hunter routing. The
  mutation capture-failure regression installs its `os.open` race only after
  descriptor-root preflight. The forged mutation-origin benchmark regression
  explicitly expects only the two Pydantic serializer warnings caused by its
  deliberately invalid low-level model copy. Independently focused results
  were `36`, `54`, and `23` passing tests respectively; affected Ruff and
  strict model-coverage mypy checks passed.
- **Joined focused closure:** The five-file joined suite passed `221` tests in
  `3.76s`. Ruff passed after formatting one affected file, strict mypy passed
  eight affected source files, release schemas regenerated and verified
  synchronized, and the maximum-assurance synthetic pipeline plus infeasible
  pre-spend assignment regressions passed `2` tests in `13.63s`. Two inherited
  stale temporary-tree cleanup warnings remain unrelated to this ticket.
- **Expanded regression discovery:** The broader benchmark, context,
  model-review, specialist, reporting, and pipeline matrix produced `28 failed,
  705 passed in 106.93s`. The failures cluster into two stale test builders
  that no longer satisfy non-vacuous audited-suite/mutation and critical-review
  gates, plus one execution-origin integration severity mismatch. The
  fail-closed production validators remain unchanged while each shared cause
  is being diagnosed.
- **Acceptance audit:** Production currently cannot emit credited statement
  coverage or decisive runtime mutation evidence. The Foundry suite adapter
  emits selected/executed/failed test evidence but no trusted executable-
  statement artifact; pipeline calls supply neither statement nor mutation
  inputs. Current mutation execution is an adapter protocol exercised only by
  mock tests, and all persisted/planned scorecards remain non-crediting.
  Therefore this ticket cannot honestly be marked `COMPLETE`: structural
  denominators, exact nonfinding gaps, elevated priority, and disposable
  custody are implemented, while real statement production is unimplemented
  and decisive mutation execution remains assigned to `V3-MUTATION-001`.
- **Expanded-cluster correction:** The certificate mechanism's positive
  file-backed fixture now uses a valid standard-profile report with mutation
  evidence explicitly not evaluable; a separate maximum-assurance negative
  proves caller-authored declarative kill evidence cannot be certified. The
  synthetic benchmark model-review helper no longer treats an empty critical
  denominator as a pass. In production, incomplete critical classification
  now suppresses coverage-gap priority and the independent critical gate
  without suppressing all ordinary source review; incomplete source
  classification still fails preflight. The exact correction matrix passed
  `88` tests in `2.37s`, with affected Ruff green.
- **Expanded regression closure:** The exact 18-file benchmark, context,
  model-review, reporting, Solidity, and pipeline matrix passed `735` tests in
  `110.45s`. Affected Ruff, strict mypy over eight source files, release-schema
  generation/checking, and the synthetic maximum-assurance integration were
  green before the final adversarial review.
- **Final adversarial evidence findings:** Independent review found that
  caller-authored `ScannerRun` values could claim REAL isolated repository-suite
  execution, timed-out/invalid executions were omitted from the failure count,
  wholly unexecuted metrics still advertised runtime provenance, scanner and
  mutation repository digests used different exclusion/Unicode domains, a
  final cleanup name swap could leave an owned mutation inode linked, and
  contract-level criticality/source denominators could diverge from the
  function-level inventory. These are implementation defects, not successful
  runtime evidence, and the ticket remains `IN_PROGRESS`.
- **Evidence-integrity repair in progress:** Repository-suite credit now uses a
  process-local weak-reference authority bound to the exact fully validated
  scanner object and its canonical digest; serialization, ordinary copying,
  mutation, and injected non-exact adapters cannot inherit it. Location
  annotation explicitly preserves authority only from its trusted source
  object. A shared audited-tree policy now aligns scanner and mutation hashes,
  including Unicode paths and every excluded output directory. Descriptor-held
  mutation disposal rescans the bounded parent after final removal and fails
  closed if the owned inode remains linked under any name.
- **Focused evidence so far:** The mutation cleanup suite passed `55` tests;
  the combined scanner-workspace/mutation digest suite passed `60`; affected
  Ruff and mypy passed; and the first scanner authority-adjacent regression
  slice passed `2` tests. These are local defensive regressions. No statement
  coverage producer, decisive real mutation executor, provider call, secret,
  public RPC, wallet, signing, broadcast, or external target was used or
  credited.
- **Expanded matrix after evidence repair:** The 20-file affected benchmark,
  assurance, context, model-review, scanner, Solidity, reporting, and pipeline
  matrix passed `752` tests in `106.68s`. This demonstrates regression
  compatibility only; it does not override the independent adversarial
  findings below.
- **Mutation follow-up:** Disposal now performs a bounded recursive
  private-root scan after final removal, so moving the retained owned inode
  beneath another private-root child cannot be mislabeled disposed. Shared
  admission now rejects source directories deeper than the scanner/cleanup
  limit of 128. The exact mutation/workspace suite passed `62` tests in
  `0.76s`, affected Ruff passed, strict mypy passed, and diff integrity is
  clean. Portable name-based final-directory removal still cannot atomically
  compare inode identity and remove the name; the simulated substitution path
  fails closed but can remove an empty replacement before detection. Do not
  claim the stronger “only the descriptor-held child can ever be removed”
  property until a suitable platform primitive or isolated-parent guarantee
  is implemented.
- **Adversarial runtime-authority findings:** The current process registry is
  not acceptable for completion: its attester is directly callable with any
  schema-valid self-authored run, and its derivation helper can transplant
  authority to an unrelated valid run. Production Foundry finalization also
  labels only an all-success scanner run REAL, making the new timeout and
  invalid-output accounting unreachable from the actual producer; repeated
  qualifying runs use inconsistent descriptor/execution deduplication.
  Authority must be bound to an exact built-in producer invocation and a live
  sealed isolation backend, and annotation propagation must permit only the
  findings/digest delta.
- **Adversarial coverage findings:** Critical contracts currently receive no
  assertion gap or elevated routing; omitted audited coverage can bypass
  critical-classification completeness; symbolic or stale/unverifiable
  invariant, graph, and applicable economic-plan bindings can disappear from
  denominators; graph-kind absence can become a clean 0/0 metric; and Markdown
  hides applicability/classification limitations. These are material
  fail-closed defects and remain unimplemented at this pause boundary.
- **Operator pause boundary:** All workers are stopped and no command is
  running. The worktree is intentionally uncommitted because the current
  ticket has known material review findings despite green regression tests.
  No provider call, secret access, network operation, public RPC, wallet,
  signing, broadcast, external target, commit, or push occurred in this slice.
- **Operator pause boundary (current):** Autorun is `PAUSED_BY_OPERATOR`.
  All review workers are stopped and no command is running. The current
  implementation and regression changes remain intentionally uncommitted
  because the latest focused suite is red (`4 failed, 216 passed, 1 warning`).
  `git diff --check` passed at the pause boundary. No provider call, network
  operation, secret access, commit, or push occurred during this final slice.
- **Operator pause (latest):** Execution paused at the operator's request after
  joined focused validation. All subagents are stopped, no command is running,
  and the intentionally uncommitted worktree remains preserved for resumption.
  No provider call, secret access, network operation, commit, or push occurred
  during this resumed slice.
- **Operator pause:** Parallel coverage/schema and mutation-evidence work was
  interrupted at a clean tool boundary on 2026-07-30. The worktree is
  intentionally uncommitted and must be reconciled and revalidated before any
  completion or checkpoint claim.
- **Defensive objective:** Measure the audited repository's own test coverage
  over exact indexed source contracts/functions, preserve honest mutation
  denominators and disposable-workspace custody, and elevate exact uncovered
  critical surfaces for model review without creating vulnerability findings.
- **Starting checkpoint:** Synchronized SSH-published state commit
  `0ce4e43f` follows validated implementation checkpoint
  `7db592e572d2065703ec78808bf35bfefbe62151`. No provider, secret, public RPC,
  wallet, signing, broadcast, external target, reservation, or paid operation
  is in scope for this ticket.
- **Inventory reproduction:** `build_solidity_coverage` never consumes
  repository-suite selections or executions, and the later
  `tests_executed/tests_failed` projection counts candidate reproductions
  instead of repository-owned tests. Against the existing synthetic Foundry
  fixture, the symbol index contains `3` contracts and `5` functions, while
  only `2` contracts and `3` functions are audited source; the remaining test
  contract and two test functions currently pollute both coverage and critical
  model-surface inventories. No audited-suite assertion metric or exact gap
  exists.
- **Mutation reproduction:** The current five source-local transformations have
  deterministic apply/revert and one real compile-only synthetic integration,
  but no repository test/property executes against a mutant. Unit/CLI
  scorecards hand-construct `KILLED` outcomes, and one claimed kill can yield a
  passing denominator of one without an independently declared applicability
  plan. `exact_restoration` hashes exclude generated output directories and
  leaves the owned workspace present, so it cannot be used as disposal
  evidence.
- **Bounded implementation slices:** Add typed source-only audited-suite
  surfaces and non-finding gaps; require independently declared mutation
  applicability and typed execution identity before kill credit; remove owned
  mutation workspaces on success and failure; then bind exact critical gaps to
  elevated model-review assignments and bounded Markdown/JSON reporting.
  `V3-MUTATION-001` remains separately queued for the full eleven-class real
  portfolio and receives no completion credit here.
- **Operator pause:** Autorun is `PAUSED_BY_OPERATOR` during the first two
  implementation slices. The coverage and mutation workers were interrupted;
  the model-priority worker had completed only a read-only inventory. The
  preserved worktree contains changes to `schemas.py`, `coverage.py`,
  `mutations.py`, their two focused unit-test files, and this worklog. No
  focused green validation, ticket completion, checkpoint commit, or SSH push
  is claimed for this partial state.
- **Exact resume point:** Review the interrupted production diffs for complete
  definitions and fail-closed validators, repair any partially written code,
  run `tests/unit/test_audited_suite_coverage.py` and
  `tests/unit/test_mutations.py`, and record the actual results before
  proceeding to the model-review priority join.
- **Goal continuation:** Autorun resumed from the preserved pause state after
  re-reading the operator objective, repository queue/worklog, Git status, and
  complete affected diff. Review confirmed that the coverage implementation is
  substantially present while the mutation campaign still references missing
  descriptor-relative disposal helpers. Two disjoint workers resumed only
  those interrupted slices; the model-priority join remains deliberately
  unopened until both focused suites pass.
- **Audited-suite coverage slice:** Source/test partitioning now reports exact
  indexed populations, denominators, and exclusions; test harness contracts and
  functions cannot enter audited-source coverage. Exact critical
  assertion-strength gaps are source-hash-bound non-findings. Statement credit
  requires a self-hashed, entity-bound record joined to successful REAL,
  isolated, hash-valid repository-test execution; tampered, unknown, vacuous,
  or mismatched evidence fails closed. Mutation outcomes remain `NOT_ANALYZED`
  until the separately typed campaign evidence is mapped to exact source
  entities, so arbitrary kill-shaped hashes receive no credit.
- **Coverage validation:** The exact combined Ruff, strict-mypy, focused
  coverage/Solidity/mutation test, and scoped-diff command recorded in
  the prior worklog state passed: `75 passed in 3.96s`. Full schema
  reconstruction now rejects forged `model_construct` scanner evidence before
  it can affect statement credit or suite counts; the positive test uses sealed
  descriptor, selection, execution-policy, execution, and scanner evidence.
  This proves the local typed
  coverage boundary, not a production statement-coverage adapter or a real
  mutation campaign.
- **Mutation custody and denominator slice:** A self-hashed applicability plan
  independently declares every property/mutation/test denominator member and
  binds the approved executor, isolation policy, source, and exact suite
  inventory. Kill credit is derived only from matching REAL, compiled,
  isolated, same-suite baseline-pass/mutant-fail observations after source
  preservation, exact restoration, and disposal succeed; missing, mocked,
  unavailable, timed-out, invalid, mismatched, corrupt, or incomplete evidence
  remains inconclusive. Campaigns run only under an operator-owned private
  child with descriptor-relative no-follow custody, bounded enumeration and
  deletion, failure cleanup, pre-existing-name refusal, and symlink-target
  preservation.
- **Mutation validation:** Ruff passed after formatting one assigned file;
  `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider
  tests/unit/test_mutations.py` passed `35` tests in `0.53s`; strict mypy passed
  `mutations.py`; and the exact benchmark/report/mutation command in
  `LAST_COMMAND` passed `60` tests in `0.73s`. These are typed and mocked-adapter
  tests, not a real audited-suite mutation execution or kill artifact.
- **Independent pause review:** Read-only adversarial review found that the
  campaign scorer does not reconstruct typed plans/campaigns at its public
  boundary, so validator-bypassed copies can alter denominator or kill credit.
  It also found that the provisional surface mutation record is not yet bound
  to a validated campaign/property/source/entity join. Additional gaps are:
  fake-adapter unit observations must never be described as real execution;
  incomplete graph/invariant or project classification can collapse or pollute
  denominators; statement counts are not yet parsed from a trusted production
  artifact; renamed campaign custody can leave the descriptor-held copy
  undisposed; and gap evidence hashes are not cross-bound to the credited
  surface evidence. The ticket remains `IN_PROGRESS`; none of these findings
  has been repaired or credited during the pause transition.
- **Pause boundary:** All workers are stopped, `git diff --check` passes, and
  the cohesive ticket remains uncommitted. Resume at the scorer reconstruction
  boundary and typed mutation-to-surface join before model-priority/reporting
  work. No provider call, secret access, public RPC, wallet, signing,
  broadcast, external target, reservation, or paid operation occurred.
- **Mutation evidence closure after resume:** Public campaign and score
  boundaries now reconstruct every typed plan, campaign, and nested
  observation. Planned campaigns are always labeled
  `PLANNED_UNATTESTED` and remain `INCONCLUSIVE`; there is no public receipt,
  token, factory, or caller-supplied path to decisive runtime mutation credit.
  Persisted/self-hashed declarations and all fake adapters remain
  non-crediting, and no production REAL executor or mutation kill is claimed.
  Descriptor-held trees are erased by inode after a safe rename while an
  unrelated replacement name remains untouched.
- **Mutation closure validation:** Affected Ruff passed; strict mypy passed
  `mutations.py`; the focused mutation suite passed `44` tests in `0.55s`; and
  the benchmark/report/mutation matrix in `LAST_COMMAND` passed `69` tests in
  `0.77s`. These are local typed and mock-only regressions, not real mutation
  execution evidence.
- **Reproduction-accounting correction:** Candidate replay activity now updates
  only `reproduction_attempts`; it cannot overwrite the audited repository
  suite's `tests_executed` or `tests_failed`. The focused regression preserves
  `7` executed and `2` failed repository tests while recording one candidate
  replay activity; `tests/unit/test_solidity.py` passed `34` tests in `1.98s`,
  with affected Ruff, strict mypy, and diff checks green.
- **Runtime-authority repair:** The public repository-suite attester was
  removed. Process authority now requires the exact built-in Foundry
  invocation and the same live, process-sealed isolation backend before and
  after execution and during later validation. Hardhat, serialized values,
  named impostors, reconstructed backends, mutated runs, and unrelated
  derivations cannot inherit authority. Only an exact copy or constrained
  source-location annotation projection may retain it. Complete invoked
  timeout and invalid-output observations can retain honest REAL evidence;
  preflight, launch, fallback, cleanup, source/inventory integrity, and
  unisolated failures remain UNVERIFIED. This is synthetic regression
  evidence only; no real isolation integration was executed or claimed.
- **Runtime-authority validation:** `.venv/bin/pytest -q
  tests/unit/test_runtime_evidence.py
  tests/unit/test_foundry_execution_hardening.py
  tests/unit/test_scanners_reporting.py` passed `160` tests in `4.42s`;
  `.venv/bin/ruff check src/mmaudit/scanners/runtime_evidence.py
  src/mmaudit/scanners/runner.py src/mmaudit/scanners/foundry.py
  tests/unit/test_runtime_evidence.py` passed; and `.venv/bin/mypy --strict
  src/mmaudit/scanners/runtime_evidence.py src/mmaudit/scanners/runner.py
  src/mmaudit/scanners/foundry.py` passed three source files. Two inherited
  pytest temporary-directory cleanup warnings remain.
- **Mutation custody and digest hardening:** Scanner and mutation repository
  hashes now bind one versioned audited-tree exclusion domain. Arbitrary
  in-repository scanner output exclusions fail closed instead of hiding
  audited source. The mutation private root must retain the exact operator
  owner and mode `0700`; widening access fails disposal and preserves source.
  Declarative and mocked campaigns remain non-decisive. POSIX exposes no
  portable atomic inode-conditional directory removal: a same-UID actor that
  can mutate the retained parent namespace can still race the final
  name-based `rmdir`. Decisive real execution therefore still requires an
  isolation boundary that makes that namespace inaccessible; this limitation
  is explicit and is not represented as atomic cleanup.
- **Mutation custody validation:** `.venv/bin/pytest -q
  tests/unit/test_mutations.py tests/unit/test_scanner_workspace.py
  tests/unit/test_scanners_reporting.py` passed `163` tests in `3.37s`;
  the declarative/mock/planned subset passed `23` with `34` deselected in
  `0.99s`; and the adjacent Foundry/repository-suite/replay matrix passed
  `116` tests in `10.80s`. Ruff format/check passed eight affected files,
  strict mypy passed the three production files, and `git diff --check`
  passed. Two inherited pytest temporary-directory cleanup warnings remain.
- **Final runtime-authority correction:** The production authority now captures
  the exact unbound built-in Foundry repository-suite producer body and the
  isolation provenance and source-location validators when its private
  registry is constructed. Later rebinding of the public dispatcher, producer
  body, or provenance globals is ignored. The captured body retains the
  producer's descriptor-held workspace-custody finalization contract. An
  independent synthetic authority exists only inside tests and cannot mint
  receipts recognized by production consumers. The negative rebinding
  regression and the broader runtime/coverage matrix passed `38` and `253`
  tests respectively; Ruff and scoped strict mypy passed.
- **Ordinary-scanner source custody:** Pipeline now passes the exact
  post-discovery audited inventory digest to every ordinary scanner. The runner
  retains a no-follow source descriptor across all concurrent tasks, each
  built-in ordinary adapter copies and verifies that exact inventory, all task
  outcomes are awaited, and source drift or root replacement raises a typed
  integrity error that pipeline records as `INCOMPLETE`. Offline replay freezes
  and revalidates the same inventory. The exact custody slice passed `9`
  tests, the scanner/workspace/replay matrix passed `197`, and the
  pipeline/execution-origin matrix passed `72` with one explicit hardened-
  isolation prerequisite skip. Ruff, scoped strict mypy, and diff integrity
  passed.
- **Current-source and fallback-index closure:** Model surface requests,
  assignment, feasibility, and accepted review coverage now share ephemeral
  exact source bytes; stale or missing source conservatively blocks critical
  credit, and raw source is not serialized. Runtime and mutation evidence from
  another repository receives no audited-suite credit. A synthetic fallback-
  indexed vault with exact `deposit`, `totalAssets`, and `balanceOf` surfaces
  now receives the existing bound accounting invariant instead of leaving an
  applicable economic plan unbound. The focused source-bound model slice
  passed `67` tests, the fallback-index invariant slice passed `2`, and both
  formerly failing pipeline regressions passed.
- **Full-suite diagnosis and closure:** The first sandboxed full run produced
  `3247 passed, 15 skipped, 7 failed, 71 errors in 408.81s`. Every error was a
  denied numeric-loopback listener in the read-only RPC bridge tests. The seven
  failures were stale test builders: two benchmark CLI fixtures and five
  execution-origin report fixtures. They were updated to construct internally
  consistent current-schema evidence without weakening any product validator;
  their complete files passed `81` tests. Rerunning `.venv/bin/pytest -q` with
  explicit local-loopback permission passed `3334` tests with `11` explicit
  unavailable external-prerequisite skips in `478.51s`. Paid provider tests
  remained disabled.
- **Final local release gate:** `.venv/bin/ruff format .` reported `362 files
  left unchanged`; `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed
  `150` source files; `.venv/bin/python scripts/generate_release_schemas.py`
  completed without schema drift; and `git diff --check` passed. Two inherited
  pytest temporary-tree cleanup warnings remain and do not alter results.
- **Honest disposition:** `V3-TESTQUALITY-001` is `PARTIAL`. Exact source
  denominators, conservative critical gaps, elevated review routing,
  producer-bound runtime receipts, source custody, and fail-closed mutation
  declarations/custody are implemented. Production still emits no trusted
  statement-coverage record and ran no decisive real mutation campaign. The
  same-UID final-directory cleanup race requires an isolation boundary that
  makes the retained parent namespace inaccessible. A real Foundry run using
  an arbitrary custom in-repository output exclusion fails safely rather than
  silently weakening identity. No real rootless isolation, new model call,
  secret access, public RPC, wallet, signing, broadcast, or external target was
  used or credited.
- **Operator pause boundary:** Autorun is `PAUSED_BY_OPERATOR`. The validated
  cohesive checkpoint will be committed and pushed over SSH. On resume,
  continue with `V3-CI-001`; retain this ticket as `PARTIAL` until its remaining
  real-evidence prerequisites exist.

## 2026-07-30 — V3-OMISSION-001

- **Status:** `COMPLETE`.
- **Defensive objective:** Bound omission evidence independently from source
  analysis capacity and return the largest honest bounded context package at
  realistic repository sizes instead of entering a self-reinforcing
  omission-growth failure.
- **Starting evidence:** Clean synchronized checkpoint
  `0994a6c6e274fa96d4f57fbb248c07e1c8f4f1ba`. The marked realistic-scale suite
  currently retains two strict expected reds: 15k raises the exact recorded
  `ContextBudgetError`, while 35k returns `73` omission records against the
  declared `64`-record target. The 5k case already succeeds.
- **Exact next safe action:** Inspect typed omission models, renderer accounting,
  recovery ordering, manifest joins, specialist byte/token caps, and review
  coverage consumers; then replace the expected reds with positive
  realistic-scale regressions. No provider, secret, public RPC, wallet, signing,
  broadcast, or paid operation is in scope.
- **Expected-red reproduction:** `.venv/bin/pytest -q -m large_scale
  tests/large_scale/test_realistic_solidity_scale.py` completed with `5 passed,
  2 xfailed in 9.05s`; the 15k case raised the recorded context-budget failure
  and the 35k case exceeded the bounded-ledger target.
- **Implementation slice before operator pause:** Began typed aggregate omission
  groups with bounded representative samples, package-level effective source
  ceilings, and omission-detail degradation ahead of source removal in
  `token_planning.py`, `schemas.py`, and `context.py`. The provider-visible
  renderer still needs its bounded limitation payload, request-plan propagation
  is not complete, and no post-edit tests have been credited.
- **Pause checkpoint:** At `2026-07-30T01:12:02Z`, the operator requested a pause.
  `git diff --check` passed. No commit was created because the cohesive ticket is
  incomplete. All edits are preserved in the working tree; no provider call,
  secret access, public RPC, wallet, signing, broadcast, or paid operation
  occurred.
- **Resume evidence:** Autorun resumed at `2026-07-30T01:21:09Z` from the
  preserved checkpoint. Provider-visible limitation rendering now carries only
  bounded counts while full commitments and representative digests remain
  host-side; request-token planning binds the actual package source ceiling;
  and static specialist role caps have been replaced by a configuration-derived
  source-plus-metadata bound. Focused evidence so far: core context,
  token-planning, and OpenRouter tests `204 passed`; expanded token-planning
  tests `27 passed`; omission-renderer regressions `3 passed`; token-planning
  acceptance `5 passed`; source-ceiling OpenRouter join `1 passed`; specialist
  cap unit/integration slice `17 passed`. The strict 15k and 35k expected reds
  now XPASS and are being converted into positive regressions. No paid or
  external operation occurred.
- **Integrity correction:** The first broad focused run returned `2 failed,
  428 passed in 3.52s`. Both failures proved that removing all omission bytes
  from provider rendering also removed post-hoc context-substitution detection.
  The renderer now includes one constant-size SHA-256 commitment over the
  host-only aggregate ledger while withholding every per-record inventory and
  sample digest. The two original failures plus four omission-rendering
  regressions then passed (`6 passed in 0.30s`).
- **Expanded focused evidence:** The combined context, token-plan, manifest,
  OpenRouter, specialist, model-coverage, assurance, and pipeline slice passed
  `589` tests in `96.20s`. The realistic 5k/15k/35k run first exposed three
  test-harness defects in newly added assertions; after passing the real
  index/graph evidence into context construction and fixing the missing typed
  import, it passed `5` tests in `18.57s`. Release-schema regeneration and
  drift verification passed.
- **Independent adversarial findings:** Three read-only reviews reproduced
  additional fail-closed gaps: optional framework metadata could still force a
  hard context failure; logical-block diagnostics and collection transitions
  could misstate exact omission counts; source-budget evidence did not
  recompute derived maxima; source inventory processing retained quadratic
  suffix copies; context-manifest I/O followed linked path components and had
  descriptor-identity races; logical retry/preflight evidence could splice a
  different context plan and double-count the same omission inventory; and
  specialist execution collapsed multiple contexts, trusted stale byte counts,
  lacked request-role/context-role binding, and could grant role completion to
  a source-less response.
- **Correction state:** The source-budget validator now recomputes its exact
  byte and estimated-token maxima from every governing ceiling; a separately
  resealed impossible maximum is rejected. The exact focused negative and two
  neighboring source-budget tests passed, followed by `38` token-planning and
  omission tests. The other reproduced findings are being corrected in
  disjoint bounded slices before ticket completion; no provider, secret,
  public RPC, wallet, signing, broadcast, or paid operation is involved.
- **Bounded slice checkpoint:** Descriptor-safe manifest I/O, logical retry-plan
  identity, unique omission totals with explicit occurrence accounting, and
  schema synchronization passed `71` focused tests, Ruff, strict mypy, and the
  release-schema drift check. Specialist request/context binding, byte-evidence
  validation, complete context inventories, partial-outcome honesty, immutable
  omission tuples, and source-backed assurance credit passed `188` specialist
  and OpenRouter tests, `220` assurance/model-evidence tests, `12` context
  tests, one maximum-assurance pipeline integration, Ruff, and strict mypy.
- **Remaining acceptance blocker:** Independent read-only re-review found that
  repository-map compaction reserves a slot for a synthesized file summary but
  does not commit one displaced original `omitted_files` item. A reproduced
  case reports `198` omissions for `199` removed original file/list items, and
  inputs differing only in the displaced item can produce identical omission
  evidence. Exact forensic accounting is therefore not yet proven and
  `V3-OMISSION-001` remains `IN_PROGRESS`.
- **Operator pause:** At `2026-07-30T02:20:25Z`, all three in-flight bounded
  reviews reached checkpoints and stopped. Autorun is paused with the working
  tree preserved. No commit or push was attempted because the cohesive ticket
  is incomplete; no provider call, secret access, public RPC, wallet, signing,
  broadcast, or paid operation occurred during this resumed slice.
- **Second resume:** Autorun resumed at `2026-07-30T02:22:56Z` from synchronized
  commit `0994a6c6e274fa96d4f57fbb248c07e1c8f4f1ba`. The only implementation
  action in progress is the reproduced repository-map omission-accounting
  correction and its negative regression; no next ticket has begun.
- **Map-accounting correction:** The old negative reproduced `198` recorded
  omissions for `199` removed original repository-map items. Compaction now
  retains original-list inventory separately from its synthesized summary.
  Two inputs differing only in the formerly displaced item produce equal
  provider maps but different omission commitments. The focused context slice
  passed `68` tests; Ruff, strict mypy, and scoped diff checks passed.
- **Pre-gate evidence review:** The complete focused gate was deliberately not
  started after independent review reproduced three further integrity gaps:
  context execution evidence accepted a source ceiling above its configured
  token-derived/package bound; different retry preflights could share one
  logical request without agreeing on a plan when no provider record existed;
  and deserialized specialist records could claim source-review credit without
  joining request evidence to an actual retained source-bearing context.
  Disjoint fail-closed regressions and corrections are in progress.
- **Evidence-join corrections:** Repeated logical provider/preflight records now
  require one exact role, model, and request plan even when no provider record
  exists; valid retry occurrences remain separately counted while their logical
  omission inventory remains unique. Context execution evidence rejects source
  ceilings above either its package budget or configured token-derived limit.
  Specialist records retain canonical successful/failed request IDs, join each
  request context to exact retained rendered/source/config evidence, and
  recompute source-review credit instead of trusting a serialized counter.
  Focused evidence: manifest `71` passed; specialist compatibility `498`
  passed; Ruff and strict mypy passed both slices.
- **Complete focused gate:** The context, omission, token-plan, manifest,
  OpenRouter, specialist, coverage, assurance, reproduction, repository, and
  pipeline matrix passed `672` tests in `97.06s`. Only non-failing cleanup
  warnings for immutable test toolchain directories were emitted.
- **Scale and schema gate:** The positive realistic-scale suite passed all `5`
  tests in `18.70s`. Release schemas were regenerated and immediately verified
  synchronized. Full Ruff formatting changed `3` affected files and the
  complete Ruff check passed.
- **Static type gate:** Configured strict mypy passed all `148` source files.
- **Complete local gate:** With only test-owned numeric-loopback listeners
  permitted and paid-provider execution disabled, `.venv/bin/pytest -q` passed
  `3051` tests with `11` explicit external-engine, rootless-isolation,
  compiler, fork, replay, and paid-provider prerequisite skips in `394.66s`.
  Two inherited immutable-toolchain cleanup warnings were non-failing.
- **Trusted compiler scale integration:** The external immutable Solidity
  `0.8.30` compiler remained a unique regular non-writable executable with
  recorded SHA-256
  `738dcdc6afddeb505ee4e4ef24f1c1fdba2b8c924e614cbbf5801a5b062dd683`.
  The explicit offline realistic-scale AST/inheritance integration passed `1`
  test in `1.88s` using only disposable output.
- **Final manifest review:** Pre-commit review withheld completion after
  reproducing three further evidence-integrity gaps: a FIFO/device manifest
  leaf could block before regular-file rejection; effective configuration
  validation did not derive and compare utilization and all configured token
  reserves; and incompatible manifest/binding evidence still claimed
  top-level schema `1.0`. Bounded regressions and corrections are in progress;
  the earlier green suite remains historical evidence, not post-fix credit.
- **Final context/specialist review:** Two further read-only reviews withheld
  completion. They reproduced remaining-budget exclusions mislabeled as
  oversized logical constructs; uncommitted nested index/graph metadata
  removals; mutable or unvalidated package copies exceeding declared bounds;
  workflow-rejected provider responses receiving raw-usage specialist credit;
  derivative `:exploit_test` calls satisfying investigator review; and the
  required indexed whole-protocol request role being rejected before
  transport. Disjoint context and specialist corrections are in progress.
- **Operator pause after bounded review slices:** At
  `2026-07-30T03:09:16Z`, the context slice completed with `7` focused
  regressions and `5` realistic-scale tests passing, plus Ruff, strict mypy,
  and `git diff --check`. The manifest slice had already passed `96` focused
  tests, schema regeneration, Ruff, and strict mypy. The specialist slice was
  stopped mid-implementation at the requested pause boundary: four production
  files contain incomplete, unvalidated edits and their compatibility tests
  have not yet been updated. No commit or push was attempted, no next ticket
  began, and no provider call, secret access, public RPC, wallet, signing,
  broadcast, or paid operation occurred.
- **Third resume:** Autorun resumed at `2026-07-30T03:11:25Z` from the exact
  preserved working tree. The bounded specialist-evidence correction and its
  compatibility regressions are the only implementation work in progress; the
  validated context and manifest slices remain preserved, and no next ticket
  has begun.
- **Resumed adversarial evidence review:** Pre-gate review reproduced further
  source-credit bypasses, so completion remains withheld. Accepted role
  outcomes were inferred from a shared usage-ledger suffix instead of the exact
  host-validated result; surface evidence was not fully joined to response and
  context hashes; mutable accepted-outcome evidence retained a stale self-hash;
  a constructed auxiliary `COMPLETED` record could receive role credit without
  accepted evidence; and candidate locations were validated against the union
  of every role's source packages, allowing one role to lend another omitted
  source. Context packages also require detached resealing at all artifact and
  coverage boundaries. These are being corrected with exact-request,
  exact-context, and recomputed-credit regressions before any green gate is
  credited.
- **Evidence-integrity correction:** Host-accepted role outcomes now bind the
  exact completion request, validated response, schema, context request
  evidence, requested-surface manifest, and retained source package.
  Candidate locations are checked only against their originating package in
  both validation passes, and duplicate/conflicting candidate origins fail
  closed. Investigator completion requires a nonempty accepted surface review;
  derivative test-planning calls cannot satisfy investigator responsibility.
  Serialized specialist records are registry-bound and revalidated, including
  exact outcome-to-context evidence hashes. Whole-protocol lineage credit
  requires a canonical indexed request with typed, source-bearing context
  evidence. Detached context boundaries revalidate nested state and exact
  rendered/source limits; unsupported scanner metadata is deterministically
  normalized and serialization failures become typed boundary failures.
  Agent-focused evidence passed `288` specialist/evidence tests, `68` pipeline
  integration tests, `169` assurance tests, `31` specialist/qualification
  tests, `4` whole-protocol binding tests, and `263` context-boundary tests.
  Root-level combined validation is now running.
- **Root focused gates:** The complete combined V3-OMISSION matrix passed `779`
  tests in `114.10s`. Release schemas regenerated and verified current. Ruff
  formatted `10` affected files, the complete Ruff check passed, and strict
  mypy passed all `148` source files. The positive 5k/15k/35k scale suite
  passed `5` tests in `21.21s`. The explicit trusted offline Solidity `0.8.30`
  compiler remained a regular non-writable executable with SHA-256
  `738dcdc6afddeb505ee4e4ef24f1c1fdba2b8c924e614cbbf5801a5b062dd683`;
  its realistic-scale AST/inheritance integration passed `1` test in `1.94s`.
- **Final review correction:** A last independent test review proved that
  source-backed whole-protocol credit did not yet join typed context evidence
  to the provider-visible prompt hash. Credit now requires a non-null exact
  `user_prompt_sha256 == rendered_sha256` binding; missing, mismatched, and
  independently resealed evidence all revoke lineage credit. The same-role
  request-selection regression now selects an earlier exact completion while a
  later same-role record exists. The post-fix focused matrix passed `455`
  tests, the new negative subset passed `8`, Ruff passed, strict mypy passed all
  `148` source files, release schemas regenerated and verified current, and
  `git diff --check` passed.
- **Final closure:** At `2026-07-30T04:15:44Z`, the exact final source state
  passed `3095` tests with `11` explicit external-engine,
  rootless-isolation, compiler, replay, fork, and paid-provider prerequisite
  skips in `426.94s`. Two inherited immutable-toolchain cleanup warnings were
  non-failing. Ruff formatting verification and the complete Ruff check passed;
  strict mypy passed all `148` source files; release-schema drift verification,
  JSON validation, and `git diff --check` passed. Three final independent
  reviews found no remaining V3-OMISSION acceptance blocker. No provider call,
  secret access, public RPC, wallet, signing, broadcast, or paid operation
  occurred. `V3-OMISSION-001` is `COMPLETE`; the unavailable real integrations
  remain accurately represented by their explicit suite skips and existing
  external blockers.

## 2026-07-30 — V3-EXECORIGIN-001

- **Status:** `COMPLETE`.
- **Defensive objective:** Permit a location-validated deterministic execution
  witness to originate a candidate group without model attribution, while
  preserving deterministic evidence caps and preventing model roles from
  deleting, relocating, or independently confirming that candidate.
- **Starting evidence:** The dependency `V3-FORKDIFF-001` is complete, and
  `V3-OMISSION-001` is checkpointed at
  `14391ba7234aba3adfb1e3eb4159e5950754d833`. The queue records that execution
  currently confirms or falsifies only model-proposed candidates; no
  execution-originated group enters consensus.
- **Exact next safe action:** Inspect existing candidate, reproduction,
  consensus, grouping, and report provenance types; reproduce the missing
  path with a synthetic local execution record; then implement one cohesive
  typed origin flow with exact source-location and no-model-attribution
  regressions. No provider, secret, public RPC, wallet, signing, broadcast, or
  paid operation is in scope.
- **Operator pause:** At `2026-07-30T04:26:20Z`, both active read-only review
  agents were interrupted before implementation began. Their completed
  architecture observations remain available in the conversation state; no
  production source or test file changed, and no provider, secret, network,
  wallet, signing, broadcast, or paid operation occurred. Resume from the
  typed provenance and authority-boundary regression design.
- **Resume:** Autorun resumed at `2026-07-30T04:28:42Z` from clean synchronized
  checkpoint `bb2d1f0dcd3ea764e2a099487bd225b3dd7c093c`. The current ticket and
  defensive scope are unchanged; no paid provider or external execution is in
  scope for this work unit.
- **Operator pause:** At `2026-07-30T04:46:28Z`, all three implementation
  workers stopped at safe atomic boundaries. The typed origin/provenance schema
  and its 10 focused tests are preserved; the execution-candidate builder and
  its 8 focused tests are preserved; and the reporting slice is preserved
  pending post-schema regressions. The schema worker reports Ruff, focused
  schema tests, and 152 neighboring regression tests passing; the builder
  worker reports Ruff, strict mypy, and all 8 focused tests passing. A final
  pause check caught one missing type import and five import-order findings;
  the missing import was restored, Ruff fixed the ordering mechanically, and
  all affected Python files now pass Ruff. Root-owned
  consensus, pipeline, replay, manifest, and model-boundary edits remain
  uncommitted and require integrated review and validation. `git diff --check`
  passed. No provider call, secret access, public RPC, wallet, signing,
  broadcast, external execution, or paid operation occurred. A clearly labeled
  pause checkpoint `0a9660a84f454da1d1f589a8c0523c34692c1aa8`
  preserves this incomplete ticket at the operator's request; it does not
  constitute acceptance or completion.
- **Resume:** Autorun resumed at `2026-07-30T04:52:29Z` from synchronized
  checkpoint `0d28c54a7cf957ab604bf2e9fd8ed8b0b022bf61`. The complete objective and
  active acceptance criteria were re-read. Three disjoint independent reviews
  are covering consensus authority, artifact cross-binding, and reporting while
  root performs integrated pipeline review. An unrelated concurrent queue edit
  is preserved and will not be silently folded into this ticket. No provider,
  secret, public RPC, wallet, signing, broadcast, or paid operation is in scope.
- **Operator pause:** At `2026-07-30T05:08:02Z`, the remaining
  pipeline-integration worker was interrupted before it created a test file.
  The artifact-boundary review added 26 regressions and reported its focused
  suite passing, plus adjacent execution and manifest/replay slices passing
  `44` and `58` tests respectively. Consensus and reporting reviews reproduced
  authority/provenance defects; corresponding production corrections are
  preserved but still require an exact post-correction integrated run because
  the last combined command output was truncated and is not credited. Three
  new unit-test files and the root implementation edits remain uncommitted;
  `git diff --check` passes. The unrelated concurrent work-queue additions
  remain preserved. No provider call, secret access, public RPC, wallet,
  signing, broadcast, external execution, or paid operation occurred.
- **Resume:** Autorun resumed at `2026-07-30T05:11:40Z` from clean synchronized
  checkpoint `d69c7a740bd86942f9c0b25554aaea677e68456b`. The exact objective,
  repository policy, active acceptance criteria, and persistent state were
  re-read. Work resumes with the missing safe real-local pipeline regression
  and post-correction validation; no provider, secret, public RPC, wallet,
  signing, broadcast, or paid operation is in scope.
- **Operator pause:** At `2026-07-30T05:32:47Z`, the remaining read-only
  acceptance worker was interrupted at a safe boundary. The new sealed local
  Forge pipeline regression passed (`1 passed in 8.38s`), the focused
  execution-origin slices passed `32` and `240` tests, and `git diff --check`
  passed. Independent review still reports three stale `model_construct`
  helper failures (`121 passed, 3 failed`) and one strict-mypy SARIF error.
  Typed offline replay rejects the pipeline's emitted `candidate_resolutions`;
  manifest validation does not yet require every qualifying runtime
  counterexample to have an execution-origin candidate; and post-judge
  high/critical severity accounting still needs a fail-closed regression.
  The ticket remains `IN_PROGRESS`; no full pipeline or complete release gate
  is credited. No provider call, secret access, public RPC, wallet, signing,
  broadcast, paid operation, or active reservation occurred.
- **Pause checkpoint:** Incomplete execution-origin work is preserved in
  `bd45918924bd530044d88369644f8d0eb569f302`. This commit is a recovery
  checkpoint, not acceptance evidence and not a completed ticket.
- **Resume:** Autorun resumed at `2026-07-30T05:36:46Z` from clean synchronized
  state checkpoint `27cd4e4f1c4313da08d37c457faaa4987b804949`.
  The exact objective, repository policy, queue, and recorded blockers were
  re-read. Work remains limited to the existing execution-origin ticket; no
  provider, secret, public RPC, wallet, signing, broadcast, or paid operation
  is in scope.
- **Resumed expected-red evidence:** The exact artifact suite reproduced the
  recorded stale-helper failure with `3 failed, 23 passed in 0.56s`; all three
  failures are `AuditReport.model_construct` fixtures that omit the now-required
  `schema_version`, not accepted runtime reports. Affected strict mypy also
  reproduced the SARIF dictionary-unpack error.
- **First corrective slice:** SARIF now constructs an explicitly typed
  `dict[str, Any]` result-property map before serialization. Ruff and strict
  mypy pass for the affected module; the corrected scanner/reporting suite
  passed `104` tests in `2.30s`. One initial pytest command named a nonexistent
  `tests/unit/test_sarif.py` and ran no tests, so it receives no credit.
- **Replay and severity slices:** Typed replay now validates emitted candidate
  resolutions against exact candidates and qualifying integrity-bound results;
  actual hardened local replay of the real Forge/solc execution-origin run
  reached `REPLAYED`. Replay/artifact tests passed `78`, and the real local
  integration passed `1` in `15.55s`. Post-judge HIGH/CRITICAL impact remains
  visible but an execution candidate omitted from pre-judgment high/critical
  phases becomes `NEEDS_REVIEW`, forces `INCOMPLETE`, and enters the exact
  assurance denominators. Its focused and adjacent suites passed `4` and `190`
  tests respectively; affected Ruff and strict mypy passed.
- **Runtime-completeness correction and deeper negative assay:** Initial
  schema/manifest changes closed the empty-candidate omission and passed `71`
  focused tests plus all `68` pipeline integration tests. A follow-up assay
  then proved those changes were over-broad: a runtime-valid counterexample
  correctly rejected for a mismatched harness caused final report construction
  to raise instead of emitting the intended incomplete forensic evidence. A
  typed per-runtime origin disposition is now required so each counterexample
  is either exactly originated or explicitly rejected with its bound reason;
  metadata counts and free-form limitation strings alone are not accepted.
- **Operator pause:** At `2026-07-30T06:03:29Z`, all three remaining parallel
  workers were interrupted at safe tool-call boundaries. The working tree
  preserves the in-progress typed disposition, replay, post-judge accounting,
  manifest, reporting, and regression changes. `git diff --check` and affected
  Ruff passed. Integrated tests are not credited for the interrupted
  disposition slice, and `V3-EXECORIGIN-001` remains `IN_PROGRESS`. Resume must
  also close the independently identified host-link grouping, no-result
  high/critical replay-resolution, pipeline post-judge, and rejected-disposition
  Markdown gaps before acceptance. No provider call, secret access, public RPC,
  wallet, signing, broadcast, external execution, reservation, or paid
  operation occurred during this pause slice.
- **Pause checkpoint:** Commit
  `ab3998d5d14cf30f3cd64d29af7cfff88267c3b8` preserves the incomplete
  execution-origin disposition slice and its exact paused runtime state. It is
  a recovery checkpoint, not ticket-completion or release-acceptance evidence.
- **Resume:** Autorun resumed at `2026-07-30T06:07:25Z` from clean synchronized
  state commit `92f7654d82fa877c030717c4e2413d91611ab851`. The complete
  product objective, repository policy, queue, worklog, and recorded acceptance
  gaps were re-read. Work remains limited to `V3-EXECORIGIN-001`; no provider,
  secret, public RPC, wallet, signing, broadcast, external target, or paid
  operation is in scope for this ticket.
- **Operator pause:** At `2026-07-30T06:31:59Z`, all delegated slices were
  complete and no process remained active. The host-owned execution-analysis
  link, typed originated/rejected dispositions, no-result high/critical replay
  resolution, bounded Markdown disposition evidence, and post-judge
  fail-closed pipeline regression are preserved in the working tree. The exact
  mocked pipeline regression passed `1` test in `1.16s`; because its synthetic
  wiring intentionally omits real compilation and scanning, its evidence-derived
  run status remains allowed to be stricter than `INCOMPLETE` but can never be
  `COMPLETE`. This does not weaken a product gate and is not real engine
  evidence. The full integrated, schema, static, and complete gates have not
  run for this resumed slice, so `V3-EXECORIGIN-001` remains `IN_PROGRESS`.
  No provider call, secret access, public RPC, wallet, signing, broadcast,
  external target, reservation, or paid operation occurred.
- **Pause checkpoint:** Commit
  `c1199ea305a839227961bf59739fc2365d140058` preserves the incomplete,
  fail-closed execution-origin slice and its mocked pipeline regression. It is
  a recovery checkpoint, not ticket-completion, real-engine, or release
  acceptance evidence.
- **Resume:** Autorun resumed at `2026-07-30T06:36:53Z` from clean synchronized
  state commit `be7b57b80f375ac7cf4c5040e3b3a1c929d6631f`. The objective hash,
  repository policy, queue priority, acceptance criteria, worklog, and Git
  state were re-verified. Independent read-only acceptance review, the focused
  unit matrix, and credential-free pipeline integrations are running in
  parallel. No provider call, secret access, public RPC, wallet, signing,
  broadcast, external target, reservation, or paid operation is in scope.
- **Integrated validation:** The complete focused execution-candidate,
  artifact, consensus, reporting, model-boundary, post-judge, replay, manifest,
  assurance, and scanner/reporting matrix passed `421` tests in `29.05s`.
  Full pipeline integration passed `69` tests in `75.95s`. The conditional real
  execution-origin integration remained an explicit skip (`1 skipped in
  0.38s`) because hardened local isolation is unavailable in this runtime; it
  is not counted as current real-engine evidence. The passing commands emitted
  only inherited pytest cleanup warnings for stale temporary
  `clean-anvil/toolchain` paths. No provider, network, secret, public RPC,
  wallet, signing, broadcast, external target, reservation, or paid operation
  occurred.
- **Pre-complete static gate:** Release-schema synchronization passed without
  drift; `.venv/bin/ruff format --check .` reported `358 files already
  formatted`; `.venv/bin/ruff check .` passed; and configured strict
  `.venv/bin/mypy` passed all `149` source files. The independent acceptance
  review and complete pytest gate remain before ticket acceptance.
- **Independent fail-closed finding:** A local negative assay proved that the
  pipeline's post-judge correction was not independently enforced by serialized
  artifact validation. An informational execution candidate with zero terminal
  resolutions could be paired with a `HIGH/CONFIRMED` final execution finding,
  and both replay-artifact parsing and manifest consistency accepted the
  resealed semantics. Candidate/current-source provenance, no-model-attribution,
  model authority, host-linked grouping, evidence cap, and report-origin checks
  otherwise had no material blocker; the reviewer ran `84` focused tests.
- **Obsolete full gate stopped:** The pre-fix `.venv/bin/pytest -q` run was
  interrupted after `127 passed, 15 skipped in 171.30s` so it would not waste
  time or be misrepresented as ticket evidence. The narrow corrective slice
  will join final HIGH/CRITICAL execution impact back to exact candidate
  resolutions, reject accepted post-judge status, require a non-complete run,
  and prove resealed manifest/offline replay tampering fails closed.
- **Cross-artifact correction:** Current report schema `1.2` now type-loads
  reproduction evidence, binds results and falsifier decisions exactly to the
  final report, requires every serialized HIGH/CRITICAL candidate and every
  active HIGH/CRITICAL execution-origin finding to have a terminal resolution,
  and validates every `REPRODUCED` resolution against exact qualifying
  integrity evidence. A post-judge execution severity elevation cannot retain
  `CONFIRMED`, `STRONGLY_SUPPORTED`, `HIGH_CONFIDENCE`, or `PLAUSIBLE`, and
  cannot coexist with a `COMPLETE` report. Legacy schema `1.0` compatibility is
  preserved without granting current execution-origin semantics.
- **Producer correction:** Resolution serialization now considers every saved
  candidate while the existing helper filters to HIGH/CRITICAL or explicitly
  forced post-judge IDs. This gives an invalid-location HIGH candidate a typed
  `INCONCLUSIVE` terminal record without admitting it into the separate
  location-valid assurance denominator.
- **Corrective validation:** Four expected-red cases initially failed because
  no exception was raised: accepted post-judge status, missing terminal
  resolution, false COMPLETE state, and forged reproduced evidence. After the
  correction, focused artifact/integration tests passed `43`; the
  manifest/replay/certification/release set passed `134`; full pipeline
  integration passed `69`; affected Ruff and mypy passed; and
  `git diff --check` passed. The integration regression deletes the forced
  resolution, reseals artifact and manifest hashes, observes `STALE`, and proves
  offline replay refuses the tampered evidence before execution.
- **Fresh post-fix gate:** The complete eleven-file execution-origin unit matrix
  passed `426` tests in `28.43s`, and the exact post-judge plus invalid-location
  pipeline regressions passed `2` tests in `1.48s`. Release-schema
  synchronization passed without drift; Ruff reported all `358` files already
  formatted and passed checks; strict mypy passed all `149` source files; and
  `git diff --check` passed. Four inherited pytest cleanup warnings concerned
  stale temporary `clean-anvil/toolchain` paths and did not affect tests.
- **Second adversarial finding and correction:** A fully validated schema `1.2`
  report could splice a `HIGH/REJECTED` execution finding into the active
  `findings` inventory, omit its resolution, and claim `COMPLETE`; the
  manifest correctly treated the status as rejected and skipped the active
  obligation. Current reports now require the active inventory to contain no
  rejected statuses and the rejected inventory to contain only rejected
  statuses. A rejected deterministic-execution finding additionally requires
  invalid source-location evidence and a non-complete report, preventing a
  model-driven deletion from being serialized as a valid rejection. Exact
  positive, reverse-splice, bypass, location, completion, and legacy `1.0/1.1`
  compatibility regressions pass.
- **Final pre-pytest gate:** The second-fix focused unit/pipeline set passed
  `71` tests in `1.87s`. `.venv/bin/ruff format .` left all `358` files
  unchanged; Ruff check passed; strict mypy passed all `149` source files;
  release-schema synchronization and `git diff --check` passed.
- **First complete-suite result:** The sandboxed `.venv/bin/pytest -q` completed
  with `22 failed, 3106 passed, 15 skipped, 71 errors in 344.66s`. All `71`
  setup errors were the same sandbox-only `PermissionError` when the
  read-only RPC bridge tests attempted to bind a numeric loopback listener.
  The `22` assertion failures were isolated to synthetic release-artifact and
  release-run writers that did not yet emit the now-mandatory typed candidate
  inventory before production manifest validation. Production validation was
  not weakened.
- **Release-fixture correction:** Both synthetic release writers now emit and
  inventory a typed empty candidate artifact and complete empty reproduction
  artifact before sealing. Their two exact files passed `38` tests, and the
  combined release-fixture, execution-origin artifact, and full pipeline
  integration matrix passed `154` tests in `81.53s`. Only inherited cleanup
  warnings for stale temporary `clean-anvil/toolchain` paths were emitted.
- **Pre-retry gate:** `.venv/bin/python scripts/generate_release_schemas.py`
  verified schema synchronization; `.venv/bin/ruff format .` left all `358`
  files unchanged; Ruff check passed; strict mypy passed all `149` source
  files; and `git diff --check` passed. The materially different complete-suite
  retry grants only local loopback binding to test-owned listeners; it does not
  authorize a provider call, public RPC, target network, secret access, wallet,
  signing, broadcast, reservation, or paid operation.
- **Complete local gate:** With only test-owned numeric-loopback binding
  permitted, `.venv/bin/pytest -q` passed `3203` tests with `11` explicit
  external-engine, compiler, isolation, replay, fork, and paid-provider
  prerequisite skips in `411.75s`. The paid-provider integration remained
  disabled. Two inherited immutable-toolchain cleanup warnings were non-failing.
- **Acceptance result:** `V3-EXECORIGIN-001` is `COMPLETE`. Exact execution
  provenance and current-source location validation originate the candidate;
  host-owned linking and grouping preserve identity and location; model roles
  have analysis-only authority; deterministic evidence remains the confirmation
  cap; report formats identify execution origin; and current manifest/replay
  validation requires coherent runtime inventories and terminal resolution.
  The current conditional hardened Foundry/solc integration remains an explicit
  skip because hardened isolation is unavailable, so this checkpoint is
  classified as validated local implementation rather than current real-engine
  evidence. No provider, secret, public RPC, wallet, signing, broadcast,
  external target, reservation, or paid operation occurred.
- **Implementation checkpoint:** Commit
  `7db592e572d2065703ec78808bf35bfefbe62151` contains the validated
  execution-origin artifact obligations, current report-inventory partition,
  producer correction, tamper regressions, and corrected synthetic release
  fixtures. The state transition begins `V3-TESTQUALITY-001`; release status
  remains incomplete.

## 2026-07-30 — V3-FIXTURE-001

- **Status:** `PARTIAL`.
- **Defensive objective:** Add deterministic, credential-free, non-deployable
  Solidity repositories at approximately 5,000, 15,000, and 35,000 lines so
  scale-dependent context, index, graph, coverage, and future semantic-sharding
  behavior is measured rather than inferred from the existing 5,051-line
  aggregate fixture corpus.
- **Starting evidence:** The complete committed Solidity fixture corpus contains
  only `5,051` lines and its largest individual source file is `300` lines.
  `V3-OMISSION-001` records the current expected-red context failure above
  realistic size; `V3-SHARD-001` remains separately queued and receives no
  implementation credit from fixture generation.
- **Generated corpus:** Added `196` deterministic golden files under
  `tests/fixtures/solidity/realistic_scale/`. The three independent Foundry roots
  contain `4,952`, `15,116`, and `35,444` Solidity lines across `15`, `48`, and
  `114` generated market modules. Shared prefixes are byte-identical. Every
  contract is abstract and inherits a reverting synthetic-only base; no
  deployment script, endpoint, credential, copied production source, compiler
  artifact, cache, or chain state is present.
- **Reproducibility evidence:** The typed generator has SHA-256
  `525795709599aafe69427ef06a720b2611b3e5fc7caab8f4d6fbbce1ae1921b0`.
  The corpus manifest file has SHA-256
  `5acc4a50442251aa9944ae57881bd58d82351d806d04588193590c9b5e572099`.
  Per-profile manifests bind every relative path, UTF-8 byte count, line count,
  mode, SHA-256, structural minimum, generator hash, and self-hash.
  `.venv/bin/python scripts/generate_realistic_scale_fixtures.py --write`
  wrote the golden corpus, and the default check verified all `196` files.
  Independent unit regeneration into two disposable roots also matched every
  committed byte.
- **Expected-red evidence before deferral:** The first scale run produced four
  failures: the fallback graph lacked an oracle edge because the synthetic
  interface used an unrecognized member name; the 5k desired context assertion
  incorrectly required an omission even though all source fit; the 15k package
  raised the queue-recorded `ContextBudgetError`; and the 35k package exceeded
  the intended `64`-record ledger bound. The fixture renamed its original oracle
  member to the analyzer-recognized `latestPrice`; the 5k assertion now permits
  honest full coverage; and only the two unchanged production defects are
  retained as strict, ticket-linked expected reds.
- **Scale path validation:** The marked command `.venv/bin/pytest -q -m
  large_scale tests/large_scale/test_realistic_solidity_scale.py` passed `5`
  discovery/index/graph/coverage/context-input tests with `2` strict expected
  reds in `9.23s`. All sizes have monotonic nonzero file, contract, function, and
  graph populations; asset, external-call, oracle, privilege, initializer,
  proxy, delegatecall, and state-write graph kinds are present; model-review
  numerators remain exactly zero against nonzero public and privileged
  denominators. The 15k compact index/graph projection is deterministic and
  explicitly reports bounded truncation; it is not called a semantic shard.
- **Compiler evidence:** Using the already trusted immutable compiler copy
  `/private/tmp/mmaudit-trusted-solc-0.8.30/solc` and only disposable output,
  `forge build --root
  tests/fixtures/solidity/realistic_scale/solidity_035k --offline --use
  /private/tmp/mmaudit-trusted-solc-0.8.30/solc --cache-path
  /private/tmp/mmaudit-scale-build-large.C1Bqoo/cache --out
  /private/tmp/mmaudit-scale-build-large.C1Bqoo/out` compiled all `118` Solidity
  files successfully in `590.97ms`. No generated build artifact entered the
  repository.
- **Focused and static validation:** The final generator/manifest unit gate passed `8`
  tests; the combined context, context-manifest, Solidity, generator, and scale
  gate passed `106` with the same two strict expected reds in `11.77s`. Affected
  Ruff formatting/checks passed. Explicit strict mypy over the generator passed.
  `git diff --check` passed; artifact checks found no generated cache/output; the
  changed-source credential scan found only its two negative canary literals.
- **AST inheritance regression:** A separately marked conditional integration
  invokes only external canonical Forge and the explicit trusted `0.8.30`
  compiler with offline mode, sanitized environment, and disposable
  cache/output/build-info. The exact command
  `MMAUDIT_TEST_SOLC_EXECUTABLE=/private/tmp/mmaudit-trusted-solc-0.8.30/solc
  .venv/bin/pytest -q tests/integration/test_realistic_scale_fixture.py`
  passed `1` test in `1.68s`. Every 5k source file was AST-backed with no
  fallback source, compiler-provenance inheritance edges were nonempty, current
  source hashes were unchanged, and no build artifact entered the fixture.
- **Pre-full gate state:** Repository-wide Ruff passed; configured strict mypy
  passed all `148` source files; the deterministic generator verified all `196`
  committed corpus files. The complete pytest gate is the remaining checkpoint
  validation.
- **First complete pytest attempt:** The sandboxed `.venv/bin/pytest -q`
  completed with `2,926` passing tests, `14` explicit prerequisite skips, `2`
  expected-red V3-OMISSION xfails, and `71` setup errors in `335.79s`. Every
  error was the same `PermissionError` while
  `tests/unit/test_read_only_rpc_bridge.py` attempted to bind a numeric
  loopback-only listener; no assertion or fixture-ticket test failed. The
  materially different retry grants only the required local-loopback execution
  capability and does not authorize public network access.
- **Loopback-enabled complete-suite result:** The materially different
  `.venv/bin/pytest -q` retry completed with `3,005` passing tests, `11`
  explicit external-prerequisite skips, and the two exact
  `V3-OMISSION-001` expected reds in `383.22s`. The scale integration skip is
  expected in the default suite because its explicit compiler variable is not
  configured; the same integration passed separately with the trusted compiler.
  No assertion failed, no provider call ran, and no public network was used.
- **Final static and artifact gate:** `.venv/bin/ruff format .` reported `344`
  files unchanged; `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed all
  `148` source files; the generator verified all `196` committed files; both
  v3 JSON state documents parsed; and `git diff --check` passed. The final
  fixture-tree review found no cache, output, broadcast, environment, credential,
  wallet, mnemonic, PEM, or key artifact. The only sensitive-word matches were
  the two deliberate negative canaries in the generator unit test.
- **Remaining acceptance gap:** There is no semantic shard implementation or
  schema in current production code. The fixture proves deterministic graph and
  index inputs but cannot honestly satisfy the acceptance item requiring a real
  sharding regression. This ticket will be checkpointed `PARTIAL` and revisited
  when `V3-SHARD-001` consumes the scale corpus.
- **Independent review:** Three bounded reviews found no remaining material
  generator, fixture, or regression blocker after descriptor-safe file
  replacement, symlink/special-file/hardlink refusal, explicit `0644` modes, and
  restrictive-umask coverage. All reviewers agreed that semantic sharding
  remains an honest, separately queued acceptance gap.
- **Pause boundary:** At `2026-07-30T00:49:44Z`, the operator requested a pause.
  No next ticket was started. The safe resume action is `V3-OMISSION-001` using
  these three committed scale roots; `V3-FIXTURE-001` remains `PARTIAL` until
  `V3-SHARD-001` supplies a genuine sharding regression. No model, provider,
  secret, public RPC, wallet, signing, broadcast, or paid operation is in scope.
- **Implementation checkpoint:** The validated fixture generator, golden corpus,
  marked regressions, and pause state were committed as
  `7c65c26003e294072534513f7d78d61eee3c42d0`
  (`Add realistic Solidity scale fixtures`). This state-only update binds the
  durable candidate fields to that implementation commit before SSH publication.

## 2026-07-29 — V3-FORKDIFF-001

- **Status:** `IN_PROGRESS`.
- **Workspace lifecycle resume:** The expected-red retained-directory regression
  was followed by implementation of exclusive descriptor-custodied audited
  source copies, stable pre/post source and workspace inventories, path-free
  copy evidence, bounded no-follow attempt-tree disposal, exact absence checks,
  and typed copy-to-execution-to-removal joins. The matrix owner removes its
  attempt trees on success, failure, timeout, and interruption without removing
  its caller-owned private root or following symlinks.
- **Focused lifecycle validation:** `.venv/bin/pytest -q
  tests/unit/test_repository_fork_differential_schema.py
  tests/unit/test_fork_matrix.py
  tests/unit/test_foundry_execution_hardening.py
  tests/unit/test_scanner_workspace.py` passed `222` tests in `2.32s`.
  `.venv/bin/pytest -q tests/unit/test_replay.py` passed `29` tests in `1.50s`
  after its synthetic matrix rebinding helper was updated to preserve every new
  selection, copy, scope, egress, observation, and lifecycle hash join. These
  are unit and synthetic evidence only; default replay and conditional real
  local Anvil/Foundry integration remain unimplemented and uncredited.
- **Requested pause boundary:** At `2026-07-29T21:32:15Z`, no new ticket or
  replay/integration slice was started. Repository-wide validation is running
  solely to make this in-progress lifecycle checkpoint safe to pause and push.
- **First full-suite result:** `.venv/bin/pytest -q` completed in `315.93s`
  with `2857 passed`, `12 skipped`, `22 failed`, and `65 errors`. All `65`
  errors were the same managed-sandbox denial of numeric-loopback listener
  creation in `test_read_only_rpc_bridge.py`, before the bridge tests could run.
  The `22` failures exposed stale release-test fixture writers that emitted a
  placeholder `scanner-results.json` even though release validation correctly
  requires it to match the final report. Both fixture writers now emit the
  exact typed empty run list; their focused combined gate passed `38` tests in
  `6.63s`. At `2026-07-29T21:39:38Z`, the full suite is being retried with
  local-loopback permission; no public network or external service is in scope.
- **Loopback-enabled full-suite result:** The materially different retry of
  `.venv/bin/pytest -q` completed in `368.88s` with `2947 passed`, `7 skipped`,
  and `2 failed`. Local bridge coverage ran instead of being denied. The two
  failures are exact external-tool mismatches unrelated to this slice:
  the discoverable Halmos `0.3.3` binary was rejected by the configured
  supported-version policy, and the default `/opt/homebrew/bin/solc` selector
  failed external compiler validation. A focused diagnostic retry reproduced
  those same typed fail-closed results, so they were not retried again or
  credited as execution. The conditional matrix integration will use an
  explicit pinned compiler on resume; neither blocker weakens a gate.
- **Final focused and static gates:** After tightening the copy operation to use
  the already-retained source and destination descriptors directly,
  `.venv/bin/pytest -q tests/unit/test_foundry_execution_hardening.py
  tests/unit/test_scanner_workspace.py tests/unit/test_fork_matrix.py
  tests/unit/test_repository_fork_differential_schema.py
  tests/unit/test_replay.py tests/unit/test_release_artifacts.py
  tests/unit/test_release_run.py` passed `289` tests in `10.14s`.
  Ruff reported all `11` affected Python files formatted and clean; strict mypy
  reported no issues in the four affected source files;
  `.venv/bin/python scripts/generate_release_schemas.py` passed; and
  `git diff --check` passed.
- **Pause state:** At `2026-07-29T21:50:25Z`, the workspace-copy and bounded
  disposal slice is validated and ready for an isolated checkpoint.
  `V3-FORKDIFF-001` remains `IN_PROGRESS`: default replay and the conditional
  real local matrix integration are unimplemented and uncredited. No child
  agent, subprocess, local listener, provider call, budget reservation, secret
  access, or external network operation remains active.
- **Implementation checkpoint:** The cohesive source, schema, and regression
  slice was committed as `82fe859dc9cd66c9d7e10f608d7d17c2f11b181b`
  (`Bind fork workspace lifecycle evidence`). This is an in-progress
  `V3-FORKDIFF-001` checkpoint, not ticket completion.
- **Autorun resume:** At `2026-07-29T21:55:06Z`, the complete product objective
  was reread and hash-verified as
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
  The queue, worklog, and synchronized clean Git state were reloaded. Work
  resumed only on the remaining replay and local-integration acceptance
  portions of `V3-FORKDIFF-001`; no provider request, secret access, public RPC,
  wallet, signing, broadcast, or paid operation is involved.
- **Replay implementation slice:** The default offline replay path now binds a
  repository fork-matrix runner to the effective configuration, the selected
  scanner backend, and a trusted clean-Anvil launcher. Explicit runner injection
  retains precedence; a missing backend fails closed. The stable projection
  retains copy/lifecycle policy, inventory, bounds, and non-retention evidence
  while excluding attempt-local identities. Qualification requires joined,
  validated copy and lifecycle evidence. The expected-red assays reproduced the
  missing default adapter, volatile projection, and qualification gaps; the
  completed focused run passed `204` fork-matrix/schema/replay tests.
- **Explicit compiler prerequisite:** The operator-installed Solidity compiler
  at version `0.8.30+commit.73712a01.Darwin.appleclang` has SHA-256
  `738dcdc6afddeb505ee4e4ef24f1c1fdba2b8c924e614cbbf5801a5b062dd683`
  but is group-writable, so the integration harness rejected it as an
  untrusted prerequisite (`1 skipped`). A disposable canonical `0555`, single-
  link copy under `/private/tmp` retained the identical hash and version; no
  repository or target-controlled executable was used.
- **Offline replay negative assay and remediation:** With that trusted copy,
  `MMAUDIT_TEST_SOLC_EXECUTABLE=/private/tmp/mmaudit-trusted-solc-0.8.30/solc
  .venv/bin/pytest -q --tb=short
  tests/integration/test_offline_replay.py` first reached real isolated Forge
  execution and failed because macOS sandbox policy emitted the invalid
  endpoint `localhost:0` for a replay requiring no RPC. The sandbox wrapper now
  grants no network entitlement when the RPC port is non-positive. Three
  focused policy regressions passed, and the same real local replay command
  then passed `1` test in `2.38s`.
- **Child Forge trust-pin negative assay:** The first real fork-matrix attempt
  reached both local execution states but rejected the child Forge identity
  because the baseline stored a whitespace-normalized multiline version while
  the child comparison used raw multiline output. Trust comparison now
  normalizes both bounded identity strings while retaining the exact executable
  SHA-256 requirement. The focused normalization and mismatch regressions
  passed `2` tests in `0.40s`; the real matrix rerun remains pending.
- **Independent review state:** Read-only review found further acceptance gaps
  in effective-backend sharing, per-descriptor RPC-scope projection, lifecycle
  parent identity, platform no-follow capability checks, exact validated
  removal minima, aggregate cleanup bounds, and default-orchestrator real
  replay. These remain `IN_PROGRESS`; none is credited as complete until its
  negative assay, implementation, focused validation, and real local replay
  succeed.
- **Adversarial evidence hardening:** Copy evidence now retains the actual
  workspace-parent device/inode and descriptor custody and joins it to the
  lifecycle attempt root. Matrix execution fails before any lease or scanner
  when descriptor-relative directory/no-follow capabilities are unavailable.
  A validated disposal requires the runtime-realistic copied-workspace/root
  minimum, and all state custodies share one aggregate removal budget. Six
  expected-red assays reproduced the prior gaps; the completed lifecycle suite
  passed `258` tests. Effective replay now resolves one configured hardened
  backend and shares that exact object across all default runners, retains
  descriptor-scoped RPC semantics in its stable projection, and normalizes
  equivalent clean-process termination outcomes. Four expected-red replay
  assays reproduced the prior gaps; `tests/unit/test_replay.py` passed `32`
  tests and strict mypy passed all `143` source files.
- **Real RPC compatibility assays:** Real Forge initialization first exposed
  `eth_gasPrice` and then `eth_getAccountInfo` as the only denied requests. The
  former is now returned as a fixed `1 gwei` synthetic value and is never sent
  to the origin. The latter is accepted only with exactly two parameters,
  rewritten to the canonical EIP-1898 pinned block hash, and its origin result
  must contain exactly bounded hexadecimal `balance`, `code`, and `nonce`
  fields. The bridge policy version and hash bind both semantics; Forge also
  receives the same fixed gas price in its recorded command. Focused bridge
  regressions passed `11` tests, including malformed account-result rejection.
  No transaction-capable method, credential, endpoint, raw payload, or target
  path was retained.
- **Real matrix execution:** With the trusted compiler copy, the final command
  `MMAUDIT_TEST_SOLC_EXECUTABLE=/private/tmp/mmaudit-trusted-solc-0.8.30/solc
  .venv/bin/pytest -q --tb=short
  tests/integration/test_repository_fork_differential_matrix.py` passed `1`
  real local integration in `10.14s`. It executed the one selected synthetic
  repository test twice in a fresh workspace against a clean local chain and
  twice against a separately launched pinned local chain, produced a typed
  `DIVERGED` comparison, validated all read-only per-test RPC scopes and copy/
  lifecycle joins, serialized and revalidated the result/privacy evidence, and
  proved all matrix attempt directories absent. The pinned setup had no
  accounts and no mining; no wallet, key, signing, broadcast, public RPC, or
  deployed third-party contract was used. Production default offline replay of
  this frozen artifact remains the final integration acceptance item.
- **Aggregate lifecycle and replay hardening:** Each state now emits a sealed
  shared-budget cleanup record joined to its reverse attempt-removal sequence,
  cumulative entry/time accounting, exact owned-directory count, descriptor
  closure, path absence, and non-retention. Matrix construction and replay
  qualification reject missing, resealed, over-limit, or cross-state evidence.
  The combined lifecycle/schema/matrix/Foundry/scanner/replay gate passed `262`
  tests in `4.90s`; the two focused serialization-warning regressions then
  passed `2` tests. Ruff, strict mypy, release-schema verification, and scoped
  diff checks passed. Replay verification and bounded artifact loading now
  precede backend resolution or default runner construction; stale evidence
  cannot trigger backend/container probing. The complete replay unit suite
  passed `33` tests.
- **Real default-replay negative acceptance:** The manifest-bound conditional
  local integration was rerun twice after the aggregate schema stabilized.
  Both runs executed the direct four-attempt matrix and matched the baseline
  scanner, then correctly refused to claim replay completion. The diagnostic
  run reported the differential component as `blocked`, expected `complete`,
  observed `inconclusive`, while the scanner component was `matched`; the
  command ended with `1 failed in 19.84s`. Inspection isolated the remaining
  defect: pipeline and replay allocate one configured suite timeout to the
  entire multi-state matrix, while each child receives the diminishing
  remainder and consequently emits a different execution-policy identity from
  the baseline. No gate or identity comparison was weakened.
- **Operator pause:** At `2026-07-29T22:52:49Z`, all already-started lifecycle,
  replay-trust-order, and integration-diagnostic work stopped at a coherent
  checkpoint. `V3-FORKDIFF-001` remains `IN_PROGRESS`; the conditional real
  replay test is intentionally expected-red until the matrix-wide timeout
  budget is implemented. No child agent, test process, local listener, provider
  call, secret access, public RPC, wallet, signing, broadcast, paid operation,
  or budget reservation remains active.
- **Final pause gate:** Ruff formatting completed with one integration-test
  reformat; scoped Ruff checks passed; strict mypy passed `148` source files;
  release schemas and `git diff --check` passed; and the final focused suite
  passed `480` tests in `50.26s`. Pytest reported only cleanup warnings for
  inherited immutable garbage directories outside the repository. The
  conditional real replay acceptance remains the separately recorded
  expected-red result and received no completion credit.
- **Implementation checkpoint:** Commit
  `dd5e6b159ba4f0c7c5d9c31bb2a34ff2bba2d8f4`
  (`Harden fork differential replay evidence`) preserves the validated
  in-progress slice. It does not mark `V3-FORKDIFF-001` complete.
- **SSH publication:** Implementation checkpoint `dd5e6b1` and paused-state
  checkpoint `5b2e4c1` were pushed successfully on `main` to the configured SSH
  remote `git@github.com:londonjevans/Auditor.git`.
- **Matrix-timeout expected-red and remediation:** Before implementation, the
  focused timeout regressions produced two collection-time import errors because
  no shared matrix-wide budget existed. The implemented helper now derives one
  finite bounded budget from every state, repetition, exact child-suite timeout,
  observation window, cleanup allowance, clean-node attestation/startup/shutdown,
  and orchestration reserve. Pipeline and default replay use that same identity;
  every child receives the exact configured suite timeout, and an
  unschedulable fork-probe policy fails before execution.
- **Timeout validation:** The core focused gate passed `94` tests, the replay
  unit gate passed `34`, and affected Ruff and strict mypy checks passed. The
  final combined command `.venv/bin/pytest -q tests/unit/test_fork_matrix.py
  tests/integration/test_pipeline.py tests/unit/test_replay.py` passed `180`
  tests in `71.19s`. Two warnings concerned inherited immutable pytest garbage
  directories outside the repository and did not change the result.
- **Real replay diagnostic:** The local-only command
  `MMAUDIT_TEST_SOLC_EXECUTABLE=/private/tmp/mmaudit-trusted-solc-0.8.30/solc
  .venv/bin/pytest -q --tb=short
  tests/integration/test_repository_fork_differential_matrix.py` executed both
  direct and replay matrices to `COMPLETE` with a matched scanner, but correctly
  withheld `REPLAYED` because the stable projection still compared
  process-local RPC call multiplicities/order hashes, the raw clean-process
  source identity, and inventory self-hashes. The bounded diagnostic ended
  `1 failed in 19.68s` and retained only field paths, not endpoints or payloads.
  This is the next implementation defect; no qualifying-evidence gate was
  weakened and the ticket remains `IN_PROGRESS`.
- **Operator pause:** At `2026-07-29T23:24:57Z`, all launched tests and delegated
  reviews had completed. The validated timeout slice and the expected-red replay
  diagnostic are preserved for an in-progress checkpoint. No provider call,
  credential access, public RPC, wallet, signing, broadcast, paid operation, or
  budget reservation occurred; no process or listener launched by this slice
  remains active.
- **Implementation checkpoint:** Commit
  `af2ea7a690a573c887726291fdbebe32f59e4c8d` (`Bound fork matrix timeout
  identity`) preserves this validated in-progress slice. It does not mark
  `V3-FORKDIFF-001` complete.
- **SSH publication:** Implementation checkpoint `af2ea7a` and paused-state
  checkpoint `dcb31c9` were pushed successfully at `2026-07-29T23:27:01Z` on
  `main` to `git@github.com:londonjevans/Auditor.git`.
- **Autorun resume:** At `2026-07-29T23:29:07Z`, the complete 1,417-line product
  objective was reread and hash-verified, repository instructions and both
  persistent queues were reloaded, and synchronized commit `e270591` was clean.
  Work resumed only on the recorded stable replay-projection defect. No provider,
  secret, public RPC, wallet, signing, broadcast, or paid operation is involved.
- **Stable projection remediation:** Read-only inventory and bridge review
  confirmed that raw pre/post inventory self-hashes, concurrent Forge RPC call
  multiplicities/order, clean-process source identities, and generated-tree
  cleanup measurements are process-local observations. Replay now compares
  normalized compiler inventory semantics, exact RPC method vocabulary and
  validation facts, stable clean-state semantics, and bounded cleanup outcomes.
  It retains exact policy, pinned state, error counters, binding-validity facts,
  source/test identity, machine results, isolation, ownership, limits, closure,
  and non-retention. The expected-red projection assay failed before the fix;
  `.venv/bin/pytest -q tests/unit/test_replay.py` then passed `41` tests, and
  affected Ruff, strict mypy, and `git diff --check` passed.
- **Real default replay acceptance:** With the immutable `0.8.30` compiler copy
  (SHA-256 `738dcdc6afddeb505ee4e4ef24f1c1fdba2b8c924e614cbbf5801a5b062dd683`),
  the local-only command
  `MMAUDIT_TEST_SOLC_EXECUTABLE=/private/tmp/mmaudit-trusted-solc-0.8.30/solc
  .venv/bin/pytest -q --tb=short
  tests/integration/test_repository_fork_differential_matrix.py` passed `1`
  test in `20.00s`. Direct and replay matrices both completed, the scanner and
  semantic projection matched, default replay returned `REPLAYED`, emitted
  artifacts revalidated, deadlines held, and disposable workspaces were absent.
  Two non-fatal warnings concerned inherited immutable pytest garbage directories
  outside the repository. No external network or provider path was used.
- **Focused and static gates:** The complete differential, matrix, Foundry,
  workspace, read-only RPC, replay, reproduction, reporting, and pipeline command
  passed `574` tests in `134.31s`; two inherited immutable-garbage cleanup
  warnings were non-fatal. `.venv/bin/ruff format .` left all `340` files
  unchanged, `.venv/bin/ruff check .` passed, strict `.venv/bin/mypy` passed
  `148` source files, release-schema generation verified synchronization, and
  `git diff --check` passed.
- **Complete local gate:** `.venv/bin/pytest -q` passed `2992` tests with `10`
  explicit Echidna, Medusa, Halmos, rootless-isolation, paid-provider, and
  opt-in real-local integration prerequisite skips in `372.66s`. The separately
  required real differential integration had already passed with its explicit
  trusted compiler. Two inherited immutable-garbage cleanup warnings remained
  non-fatal.
- **Independent closure review:** Read-only adversarial review found no material
  blocker. It confirmed that raw RPC arithmetic/self-hashes, state and cleanup
  joins, inventory bindings, isolation, and non-retention remain independently
  validated before semantic projection. Exact RPC multiplicity/order within one
  unchanged approved method vocabulary is intentionally not replay drift; all
  raw observations remain in the forensic artifact.
- **Final scope review:** Only the intended replay implementation, fail-closed
  regressions, queue, runtime status, traceability, and worklog are changed.
  `git diff --check` passed, no generated runtime artifact is tracked, and the
  changed-file credential/key scan returned no match.
- **Ticket result:** `V3-FORKDIFF-001` is `COMPLETE`. This proves the bounded
  local differential execution and manifest-bound replay path; it does not
  resolve the separately blocked real Hardhat/rootless subtask or claim any
  public-chain execution.
- **Implementation checkpoint:** Commit
  `41a3cf5977c33a66d8286f100c32d6c31dd7f23d` (`Stabilize fork differential
  replay`) contains the completed ticket implementation, regressions, and
  evidence.
- **SSH publication:** Implementation checkpoint `41a3cf5` and state checkpoint
  `915911c` were pushed successfully at `2026-07-29T23:57:28Z` on `main` to
  `git@github.com:londonjevans/Auditor.git`.
- **Defensive objective:** Execute the same bounded audited-repository suite
  against a clean local state and one or more operator-pinned fork states, then
  classify only repeated fresh-workspace agreement as typed divergence while a
  single observation remains inconclusive.
- **Starting state:** The cohesive predecessor checkpoint is
  `aa7ea0f1eb5053c95d7d44c2d97ec1c776c3d7e1`. Its Foundry scope is validated
  with real local loopback execution; its real Hardhat subtask remains
  `BLOCKED_TECHNICAL` and will not be credited or emulated.
- **Next safe action:** Inspect the existing execution, fork identity, manifest,
  privacy, report, and replay abstractions; define the typed state/comparison
  evidence and add expected-red tests before implementation. No live target,
  public RPC, provider call, secret, wallet, signing, or paid path is involved.
- **Expected-red configuration proof:** The focused configuration suite initially
  rejected `fork_matrix_states` and `fork_matrix_repetitions` as unrecognized
  fields. The implementation now accepts only a canonically ordered matrix with
  exactly one clean-local state, at least one pinned-fork state, at least two
  repetitions, nonzero operator-authored state identities, non-secret RPC
  environment names, and a genesis-pinned clean state.
- **Focused validation:** `.venv/bin/pytest -q
  tests/unit/test_repository_suite_config.py` passed `27` tests in `0.02s`;
  `.venv/bin/ruff check src/mmaudit/config.py
  tests/unit/test_repository_suite_config.py` passed; and
  `.venv/bin/ruff format --check src/mmaudit/config.py
  tests/unit/test_repository_suite_config.py` reported both files formatted.
- **Independent design review:** Three read-only reviews completed without file
  changes. They agree that the existing qualifying single-state
  `foundry_fork` run must remain intact, repeated matrix evidence must be a
  separate typed artifact, and a trusted bounded method-allowlisting loopback
  bridge is required before any read-only RPC or no-transaction claim can be
  credited.
- **Operator pause:** Work stopped at this cohesive configuration boundary.
  `V3-FORKDIFF-001` remains `IN_PROGRESS`; no divergence execution, read-only
  bridge, report integration, or real differential integration is being
  credited yet. No child task, target process, provider request, secret access,
  public RPC, budget reservation, or paid operation remains active.
- **Pause checkpoint:** The validated bounded configuration slice was committed
  as `d643b14218977ec79f5050e4f02d30b0765a40ca` (`Define repository fork matrix
  configuration`). It is an in-progress checkpoint, not ticket completion.
- **Resume checkpoint:** Autorun resumed from synchronized commit `625c718`.
  The complete objective was reread and hash-verified, repository instructions
  and current queue state were reloaded, and the worktree was clean. The next
  implementation slice remains local-only and introduces no provider, secret,
  public-RPC, signing, wallet, or paid operation.
- **Manifest expected-red proof:** Two focused regressions first failed: the
  seed extractor omitted `fuzz_seed`, and a tampered `scanner-results.json`
  differing from the final report was accepted. The exact focused command
  reported both failures before implementation.
- **Manifest remediation slice:** Run-manifest construction now requires
  `scanner-results.json` to match the report exactly, includes its nested
  repository-suite fuzz seeds in the seed bindings, and therefore binds
  differential execution seeds rather than relying only on unrelated campaign
  artifacts. The two expected-red regressions passed, followed by all `16`
  manifest tests in `0.87s`.
- **Independent clean-chain review:** The first launcher draft is not accepted.
  Read-only adversarial review reproduced four high-severity trust gaps: an
  unrelated loopback listener can be mistaken for the spawned child; current
  head/state changes are not detected by the genesis-only shutdown check;
  descendants of the version probe can survive; and replacement of the copied
  executable at the spawn boundary is not bound to the sealed hash. It also
  identified exception-unsafe lifecycle cleanup, pathname races, stuck
  collectors, ambiguous workspace retention, missing real-node integration,
  and untested ancestor-configuration isolation. These are unresolved defects,
  not credited evidence.
- **Operator pause:** At `2026-07-29T18:32:37Z`, both active implementation
  sub-agents were interrupted at the operator's request. `V3-FORKDIFF-001`
  remains `IN_PROGRESS`; uncommitted launcher and matrix-runner files are
  explicitly unvalidated work in progress. The last accepted focused result
  remains the 36-test schema/privacy/report/manifest gate above. No provider
  request or cost reservation was started, and cumulative OpenRouter spend
  remains `0.0033415625 USD`.
- **Goal continuation after pause:** At `2026-07-29T18:34:42Z`, the persisted
  product-completion goal resumed autorun. The complete 1,417-line objective was
  reread and hash-verified, repository instructions and current diff were
  reloaded, and the same bounded ticket remains active. The launcher worker is
  addressing the reproduced trust/lifecycle defects while the matrix worker
  finishes the bridge-v2-bound runner. No provider, public RPC, secret, wallet,
  signing, or paid operation is involved.
- **Read-only bridge expected-red proof:** The new bridge suite first failed
  collection because no bridge module existed. The completed implementation
  exposes only an ephemeral numeric-loopback endpoint, canonicalizes a
  credential-free loopback origin, permits a fixed read vocabulary, pins state
  reads, rejects an entire mixed batch before forwarding, and retains only
  endpoint-free counters and self-hashed policy/method evidence.
- **Read-only bridge validation:** The exact focused bridge/fork command passed
  `28` tests in `6.76s` when granted only the local socket-bind capability that
  the managed sandbox denies. Ruff and strict mypy passed the new module and
  tests. No public RPC, source egress, secret, wallet, signing, transaction,
  provider call, or paid operation occurred.
- **Bounded integration seam:** Foundry now accepts a validated in-memory RPC
  override without mutating global environment state; its redacted display
  command never includes the bridge port. Matrix configuration rejects more
  than `100000` possible state/repetition/test execution slots. These changes
  are scaffolding only and do not yet claim a completed matrix.
- **Operator pause at partial-ticket boundary:** Autorun stopped before the
  matrix runner or report integration began. The manifest, bridge, Foundry
  override, and aggregate-bound slices are preserved; the differential schema
  slice is explicitly incomplete with `4` focused tests passing and `5`
  failing, and has not received Ruff or mypy validation. Before integration,
  its egress counters must be aligned exactly with the bridge snapshot. The
  bridge review also identified two fail-closed regressions to add first:
  bounded shutdown under a slow handler and validation that upstream block
  results match the pinned number/hash. No child task, target process, listener,
  provider call, secret access, public RPC, budget reservation, or paid
  operation remains active. The intentional uncommitted worktree is preserved;
  this is not a ticket-completion or release checkpoint.
- **Resume after operator pause:** The complete objective was reread and its
  SHA-256 reverified; repository instructions, queue priority, worklog, status,
  and intentional diff were reloaded. Autorun resumed the same bounded ticket.
  The bridge shutdown/pinning and endpoint-free schema corrections are being
  completed before any matrix runner, report, or replay integration. No
  provider, public RPC, secret, wallet, signing, or paid path is involved.
- **Checkpoint identity correction:** The synchronized pause checkpoint is
  `625c718761212ddd127bc1e43fa6fb6957eeab94`; its configuration parent is
  `d643b147a8e71d899dc155d8195244eaf3c7acb7`. A previously recorded
  `d643b142...` expansion was not a Git object and is superseded by these
  repository-resolved identities.
- **Bridge hardening expected-red proof:** Six local-loopback regressions first
  failed: exact pinned block number/hash mismatches and a well-formed upstream
  JSON-RPC error were relayed, while a slow request exceeded the intended
  shutdown bound. No external endpoint was used.
- **Bridge hardening result:** The bridge now uses tracked daemon handlers and
  nonjoining close semantics, interrupts accepted sockets, enforces one
  absolute shutdown deadline, withholds snapshots after incomplete cleanup,
  validates exact block lookup results, and classifies every upstream RPC error
  as a failed read. Truthful request/call partitions are retained. The bridge
  and fork-identity suite passed `37` tests in `11.26s` with only ephemeral
  local-bind capability; affected Ruff and strict mypy also passed.
- **Typed matrix boundary:** Fifteen schema regressions first failed. The
  self-hashed matrix now distinguishes divergence from outright failure,
  requires two agreeing REAL isolated fresh-workspace observations, requires
  enforced endpoint-free bridge evidence for observed clean and pinned states,
  and permits unavailable states only as `INCONCLUSIVE`. Its bridge counters
  and snapshot digest mirror the runtime bridge exactly. The focused schema
  suite passed `15` tests, followed by affected Ruff and strict mypy.
- **Runtime/schema join:** A dedicated conversion rejects unobserved or
  mismatched state identities and converts a stopped bridge snapshot into
  endpoint-free typed egress evidence without inventing successful-forward or
  denied-method semantics. Its expected-red import failure was followed by `3`
  passing focused tests, Ruff, and strict mypy.
- **Operator pause at expected-red boundary:** Autorun is
  `PAUSED_BY_OPERATOR`. The independent second-cycle bridge review has been
  converted into `21` failing local-loopback regressions covering origin
  attestation, exact hash-bound reads, result provenance, admission saturation,
  exact integer validation, and bounded cleanup; the source remediation has not
  begun. The clean-chain worker stopped after its expected-red import proof, and
  the matrix worker was interrupted without any process left under agent
  control. No provider call, public RPC, secret access, wallet, signing, budget
  reservation, paid operation, commit, or push occurred. The intentional dirty
  worktree is preserved and `V3-FORKDIFF-001` remains `IN_PROGRESS`.
- **Goal continuation:** Autorun resumed from the preserved expected-red
  boundary. The complete 1,417-line objective was reread and hash-verified,
  repository instructions and queues were reloaded, and the intentional diff
  was reviewed before source remediation. The active slice remains local-only:
  bridge origin/state binding, bounded cleanup, clean-chain leasing, and typed
  repeated-state comparison. No provider, public RPC, secret, wallet, signing,
  or paid path is involved.
- **Second-cycle bridge closure:** The preserved `21` expected-red regressions
  are now green. Runtime snapshot schema `2.0` directly attests matching
  preflight/postflight origin identity, hash-binds every forwarded state read,
  distinguishes attempted from provenance-validated origin calls, rejects
  methods whose state cannot be proven, saturates admission at the configured
  request ceiling, validates exact integers, and drains tracked request
  resources within one shutdown deadline. The bridge and fork-observation
  suites passed `66` tests in `29.08s`; focused identity/deadline coverage
  passed `6`; affected Ruff and strict mypy passed.
- **Privacy/report/manifest expected-red proof:** A missing typed fork-RPC
  privacy projection first failed import; absent client-report disclosure then
  failed one focused assertion; and a tampered
  `privacy-fork-rpc-egress.json` was initially accepted by manifest
  construction. These failures were recorded before each remediation.
- **Privacy/report/manifest remediation slice:** Endpoint-free aggregate privacy
  evidence is now self-hashed and result-bound; the report explicitly names the
  trusted read-only loopback boundary, validated/attempted reads, repeated
  states, classifications, and divergence directions without retaining an
  endpoint. Differential and privacy artifacts must match the final report,
  metadata, and effective matrix state/repetition configuration before manifest
  sealing or verification. The combined schema/manifest suite passed `36`
  tests, followed by affected Ruff and strict mypy.
- **Pipeline expected-red proof:** A configured matrix regression first failed
  because `AuditPipeline` had no differential-runner seam. This established
  that typed matrix/report artifacts could not be produced by a real product
  run even though their schemas existed.
- **Pipeline integration slice:** A configured matrix now runs after the
  qualifying top-level scanner portfolio under one absolute deadline and before
  post-execution source revalidation. Its child executions remain outside
  `scanner_runs`; missing identity/backend/baseline/result and typed adapter
  failures become a sealed failed differential, prominently make the product
  run incomplete, and emit endpoint-free privacy and manifest-bound artifacts.
  The focused integration passed in `0.90s`. Default launcher/runner execution,
  real local replay, and affected static gates remain pending.
- **Matrix runner first pass:** The dependency-injected runner now produces
  repeated clean/pinned observations, fresh attempt evidence, typed consensus
  and divergence, and endpoint-free bridge-v2 evidence. Its expected-red
  boundary was `5 failed, 7 passed`; the initial implementation plus schema and
  pipeline join passed `35` focused tests, Ruff, and strict mypy.
- **Independent matrix review remains open:** Adversarial probes have already
  reproduced non-finite/backward-clock false `COMPLETE`, exception paths that
  can orphan a clean lease, unsafe/overlapping/linkable private roots,
  silent deletion of material limitations, and incomplete private-path leak
  rejection. The first-pass runner is therefore not accepted yet; these are
  active defects, not limitations to waive.
- **Offline replay first pass:** The differential is now a separate replay
  component with endpoint/workspace/timing-free semantic projection and
  fail-closed missing-prerequisite behavior. Its replay/schema/manifest suite
  passed `66` tests with one explicit hardened-isolation skip; Ruff and strict
  mypy passed. Default real-runner/backend wiring and schema regeneration remain
  to close after runner hardening.
- **Clean-chain implementation under review:** The first launcher pass produced
  `13` green unit regressions plus affected Ruff and strict mypy, but independent
  review found residual ownership, process-group, exception-cleanup, TOCTOU,
  retained-copy, and collector-lifecycle gaps. Those gaps are being remediated;
  the launcher is not yet credited or integrated.
- **Clean-chain v2 pause slice:** The launcher now emits the mandatory v2
  process attestation with a PID-bound kernel listener proof, runtime executable
  identity and execution-path binding, pristine genesis-head/state-root checks,
  process-group and collector cleanup, ancestor-configuration rejection, and
  private-workspace removal. Its focused suite passed `20` tests; affected Ruff
  and strict mypy passed. A conditional real local Anvil integration and
  independent second review remain required before this is credited as
  complete runtime evidence.
- **Schema hardening pause slice:** Fifty-five expected-red schema regressions
  preceded the v2 clean-chain attestation, canonical pinned-origin observation
  digest, nonzero validated-origin-read requirement, and top-level
  differential-configuration cross-binding. The final schema suite passed `57`
  tests; affected Ruff, strict mypy, and diff checks passed.
- **Independent matrix review:** A read-only adversarial review passed the
  existing `34` focused tests but reproduced unresolved false-completion and
  evidence-custody gaps: synthetic-only or non-per-test origin reads, asserted
  rather than observed fresh workspaces, non-finite/regressing deadlines and
  exception-unsafe lease cleanup, unsafe or linkable private roots, erased
  material limitations, omitted child Forge trust pins, incomplete private-path
  rejection, incomplete pinned-state source identity, and incomplete baseline
  policy equivalence. It also confirmed that no real default-path matrix
  integration exists yet. These are active defects; the first-pass runner is
  not accepted and `V3-FORKDIFF-001` remains `IN_PROGRESS`.
- **Operator pause requested:** At `2026-07-29T19:04:47Z`, all delegated tasks
  reached safe checkpoints and stopped with no child process or provider
  request active. One combined focused gate is running before the dirty,
  explicitly incomplete worktree is recorded for pause. No new ticket will be
  started.
- **Pause-boundary regression correction:** The first combined command reported
  `7` stale synthetic-fixture failures plus `51` setup errors caused solely by
  the managed sandbox denying numeric-loopback socket binds. The stale replay,
  bridge-observation, and clean-attestation fixtures were migrated to the
  stricter schema without weakening it; their exact focused rerun passed `7`
  tests.
- **Pause-boundary validation:** Excluding only the socket-binding suite, the
  repository-suite configuration, manifest, replay, report, differential
  schema, clean launcher, matrix runner, and pipeline tests passed `329` tests
  in `81.24s` using `.venv/bin/pytest -q
  tests/unit/test_repository_suite_config.py tests/unit/test_manifest.py
  tests/unit/test_replay.py tests/unit/test_scanners_reporting.py
  tests/unit/test_repository_fork_differential_schema.py
  tests/unit/test_clean_chain.py tests/unit/test_fork_matrix.py
  tests/integration/test_pipeline.py`. Ruff formatted `3` affected files, affected Ruff passed, strict
  mypy passed `10` source files, release-schema synchronization passed, and
  `git diff --check` passed. Pytest emitted warnings about immutable stale
  temporary directories from an earlier clean-launcher regression; no runtime
  process remains, and those external temporary paths are not credited as
  successful cleanup evidence.
- **Paused incomplete checkpoint:** Autorun is `PAUSED_BY_OPERATOR`.
  `V3-FORKDIFF-001` remains `IN_PROGRESS`; the independent matrix defects and
  real local default-path integration are unresolved. No provider call, public
  RPC, credential access, wallet, signing, transaction, budget reservation, or
  paid action occurred, and cumulative OpenRouter spend remains
  `0.0033415625 USD`.
- **In-progress implementation checkpoint:** Commit
  `6d23d16d872d69902d176a3de8ea89c30633e4c4` preserves the validated typed
  bridge, clean-launcher, matrix, pipeline, report, manifest, and replay
  scaffolding plus regressions. This is deliberately an `IN_PROGRESS`
  checkpoint, not accepted real differential evidence and not a release
  candidate.
- **Goal continuation after pause:** At `2026-07-29T19:16:09Z`, persisted
  autorun resumed from clean synchronized `main` at state checkpoint
  `a0957dddf6191cf379c92f94916e391fd4cf4acf`. The 1,417-line objective was
  reread completely and its SHA-256 reverified; repository instructions,
  current queues, worklog, runtime state, Git status, and diff were reloaded.
  The same bounded ticket remains active. Work is limited to local synthetic
  regressions and trusted local Anvil/Foundry integration; no provider, public
  RPC, credential, wallet, signing, transaction, or paid path is involved.
- **Trusted clean-chain closure:** The exact pinned local Anvil integration ran
  against `/Users/josevans/.foundry/bin/anvil` version
  `anvil Version: 1.3.2-stable`, SHA-256
  `80ff77a2dfe71fac6bd9810d942c4f1b0447e42f4c086956417d9e63f5f7f0d3`.
  It validated PID-bound loopback ownership, runtime executable identity,
  pristine block-zero hash/state root before and after use, sanitized child
  inputs, and process-group/private-workspace removal. Two regressions also
  prove that an ancestor control file introduced after admission prevents
  attestation and still triggers cleanup. The exact capability-granted command
  `.venv/bin/pytest -q tests/unit/test_clean_chain.py
  tests/integration/test_clean_chain_integration.py -rs` passed `23` tests in
  `7.05s`; affected Ruff, format, and strict mypy passed. A post-run read-only
  process query found no copied clean-Anvil process. This is local clean-chain
  lifecycle evidence, not a completed differential matrix.
- **Validated clean-chain checkpoint:** Commit
  `8bda5f8f0b11032d9d3b85b428e9091b448d9a4a` contains only the clean-launcher
  hardening and its unit/real-local integration coverage.
- **Matrix hardening expected-red checkpoint:** The interrupted hardening slice
  introduces initial finite/regression-detecting clock handling, descriptor-held
  private-directory custody, overlap/link/permission checks, recursive private
  path and loopback-URI detection, baseline Forge trust-pin validation, and
  limitation-preserving intent. It is deliberately not accepted: the exact
  `.venv/bin/pytest -q tests/unit/test_fork_matrix.py` result is `19 failed, 13
  passed`, because `_execute_state` has not yet been joined to the new
  custody/clock/tool-pin inputs. After trivial formatting/import cleanup,
  affected Ruff and `git diff --check` pass, while exact strict mypy reports `7`
  corresponding unfinished-call-interface errors. Commit
  `74768911f6e98ac6587786ba718a658470cb85e4` preserves this expected-red state
  without crediting it as product evidence.
- **Operator pause:** At `2026-07-29T19:30:36Z`, autorun is
  `PAUSED_BY_OPERATOR` at the requested safe handoff. `V3-FORKDIFF-001` remains
  `IN_PROGRESS`; no next ticket was started. No listener, child process,
  provider request, public RPC, secret access, wallet, signing, transaction,
  budget reservation, or paid operation remains active. OpenRouter spend
  remains `0.0033415625 USD`.
- **Goal continuation after pause:** At `2026-07-29T19:33:26Z`, the persisted
  product-completion goal resumed from clean, SSH-synchronized commit
  `dd987f0b25c85907de23680e43ff6728aae69eb6`. The complete 1,417-line
  objective was reread in bounded chunks and hash-verified at
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  repository instructions, queues, worklog, runtime state, Git state, and the
  expected-red handoff were reloaded. Work resumes only on the existing
  `V3-FORKDIFF-001` join; no provider, public RPC, secret, wallet, signing,
  transaction, or paid path is involved.
- **Matrix hardening join completed:** The interrupted custody, monotonic-clock,
  child-tool-pin, baseline-backend, recursive private-reference, and
  unconditional lifecycle-cleanup join is now coherent. Four new negative
  regressions first produced the intended `4 failed, 3 passed` result for
  cleanup exception precedence, supplied-backend drift, multiply encoded
  private paths, and case-folded private paths. After remediation, the narrow
  command passed `7` tests. A material limitation without an inconclusive
  comparison now fails the configured run without retaining a completed matrix;
  the existing schema gate remains fail-closed.
- **Static validation:** Ruff formatting and checks passed for the four affected
  files, strict mypy passed for both affected source modules, and
  `git diff --check` passed. Pytest emitted only sandbox cleanup warnings for
  protected synthetic toolchain directories; no product test failed.
- **Remaining ticket scope:** Per-test state-read provenance, typed evidence of
  actual disposable-workspace creation and removal, default replay, and a real
  local differential integration remain unimplemented. Aggregate bridge reads
  and claimed workspace freshness are not being credited for those requirements.
  No provider request, public RPC, secret access, wallet, signing, transaction,
  budget reservation, or paid operation occurred.
- **Operator pause checkpoint:** At `2026-07-29T19:50:29Z`, autorun stopped at
  validated in-progress checkpoint
  `ca9b65245d1e34388965797d2ce059cad5f7f6d9` (`Harden repository fork matrix
  custody`). `V3-FORKDIFF-001` remains `IN_PROGRESS`; no remaining scope is
  credited. All child reviews are complete, and no target process, provider
  request, public RPC, secret access, wallet, signing, transaction, budget
  reservation, or paid operation remains active. OpenRouter spend remains
  `0.0033415625 USD`.
- **Goal continuation:** At `2026-07-29T19:52:41Z`, autorun resumed from clean,
  SSH-synchronized commit `5a7f30e41b7c2b0b8acaccf382796f5a1fc790ce`.
  The complete 1,417-line product objective was reread and hash-verified at
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  repository instructions, current queues, worklog, runtime state, and Git state
  were reloaded. Work continues only on the open `V3-FORKDIFF-001` evidence
  gaps. No provider, public RPC, secret, wallet, signing, transaction, or paid
  path is involved.
- **Per-test state-read expected-red join:** The first combined gate exposed the
  intended semantic join defects: bridge-policy evidence was initially compared
  with the unrelated repository execution-policy hash, matrix fixtures lacked
  descriptor-scoped reads, and aggregate-only evidence remained sufficient for
  consensus. Those defects were corrected without weakening the aggregate
  bridge or the legacy non-matrix Foundry path.
- **Descriptor-scoped bridge evidence:** The read-only bridge now opens exactly
  one 1-based selected-descriptor scope at a quiescent boundary, attributes
  admitted requests and validated origin reads to that scope, seals an
  endpoint-free self-hashed snapshot, rejects overlap/wrong identity/reuse, and
  always closes listener, handler, and upstream resources even when shutdown
  discovers an abandoned scope.
- **Foundry and matrix binding:** Foundry begins and unconditionally ends each
  scope around the exact selected test, preserves a validated prefix on
  interruption, and requires complete validated scope coverage for a successful
  scoped run. Matrix evidence binds each scope to its workspace-attempt identity,
  selection, descriptor, bridge policy, and observed state. Missing,
  not-observed, violating, cross-attempt, or wrong-policy evidence produces typed
  `state_read_unproven` consensus and cannot support a comparison.
- **Double-credit prevention:** A state attempt rejects rehashed evidence when
  per-test counter or method totals exceed the aggregate stopped-bridge ledger.
  A negative regression proves that one aggregate origin read cannot be credited
  to two selected tests. Unscoped pre/post identity reads remain permitted only
  as an aggregate residual and cannot satisfy a descriptor scope.
- **Independent race and join review:** Read-only review reproduced two
  boundary races in the first draft: listener-queued requests were not captured
  at scope transitions, and a completed client response could precede handler
  drain. The hardened bridge now pauses its accept loop behind a trusted
  loopback checkpoint, binds accepted/admitted work to an exact generation,
  drains within one absolute bound, serializes shutdown, and appends each
  successfully sealed scope hash to an ordered aggregate ledger. Failed or
  timed-out checkpoints always release the accept loop.
- **Ordered-ledger and compatibility assays:** Matrix consensus requires the
  aggregate stopped-bridge ledger to equal the exact ordered per-test scope
  ledger. Positive two-descriptor round trips, reversed and missing ledgers,
  rehashed persisted-artifact tampering, aggregate residual masking,
  interrupted prefix retention for `FAILED`, `TIMED_OUT`, and `UNAVAILABLE`,
  and the exact pre-ledger/pre-scope historical projections are covered.
- **Final focused validation:** `.venv/bin/pytest -q
  tests/unit/test_repository_fork_differential_schema.py
  tests/unit/test_fork_matrix.py tests/unit/test_foundry_execution_hardening.py
  tests/unit/test_assurance.py` passed `358` tests in `23.91s`. The exact
  capability-granted local-loopback command `.venv/bin/pytest -q
  tests/unit/test_read_only_rpc_bridge.py` passed `70` tests in `37.23s`.
  Ruff formatting/checks passed all ten affected source/test files, strict mypy
  passed all five affected source modules, and `git diff --check` passed.
  Independent production review found no remaining fail-open blocker in this
  slice. Pytest emitted only pre-existing managed-sandbox cleanup warnings for
  protected synthetic toolchain directories.
- **Remaining ticket scope:** Actual typed source-copy/workspace creation and
  bounded removal evidence, default replay, and one real local
  clean-versus-pinned Anvil/Foundry matrix remain. No workspace policy hash or
  aggregate RPC counter is credited as proof of those missing requirements. No
  provider, public RPC, secret, wallet, signing, transaction, budget
  reservation, or paid operation occurred.
- **Operator pause checkpoint:** At `2026-07-29T20:50:49Z`, autorun stopped at
  validated in-progress checkpoint
  `f940dd1ca3051a38b7ff4dfa539bf5ac47653f6b` (`Bind fork reads to selected
  tests`). `V3-FORKDIFF-001` remains `IN_PROGRESS`; the lifecycle, replay, and
  real local integration requirements above are not credited. All child tasks
  are complete, and no listener, child process, provider request, public RPC,
  secret access, wallet, signing, transaction, budget reservation, or paid
  operation remains active. OpenRouter spend remains `0.0033415625 USD`.
- **Goal continuation:** At `2026-07-29T20:54:20Z`, persistent-goal autorun
  resumed from clean SSH-synchronized state commit
  `0dde1434b1274fed155f07322949efe8a75ba37c`. The complete 1,417-line product
  objective was reread and hash-verified at
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  repository instructions, queue, worklog, runtime state, Git status, and
  upstream identity were reloaded. Work continues only on the remaining
  `V3-FORKDIFF-001` lifecycle, replay, and real local integration evidence. No
  provider, public RPC, secret, wallet, signing, transaction, or paid path is
  involved.
- **Operator pause:** At `2026-07-29T21:01:20Z`, work paused before production
  edits. Three read-only lifecycle/replay reviews were stopped or completed,
  and their findings were retained in the current task context: the existing
  disposal hash does not prove removal, lifecycle evidence must be joined
  across Foundry and matrix ownership, and default replay requires a
  backend-bound differential adapter plus stable semantic projection. The
  worktree contains only this persistent-state update; no implementation file,
  test, provider request, listener, child process, public RPC, secret, wallet,
  signing, transaction, budget reservation, or paid operation is active.
- **Goal continuation:** At `2026-07-29T21:04:25Z`, persistent autorun resumed
  from clean SSH-synchronized state commit
  `3c41c22796bd389220b3d32397a8f0dcd85bff9a`. The complete 1,417-line
  objective was reread in bounded chunks and hash-verified; repository
  instructions, the active queue/worklog state, and Git status/diff were
  reloaded. Work resumes only on typed source-copy and disposal evidence for
  `V3-FORKDIFF-001`; no provider, public RPC, secret, wallet, signing,
  transaction, or paid path is involved.
- **Workspace-lifecycle expected-red proof:** The exact command
  `.venv/bin/pytest -q
  tests/unit/test_fork_matrix.py::test_runner_emits_repeated_real_divergence_without_top_level_child_runs`
  failed `1` test in `0.16s` after the assertion was corrected from retained
  directories to required absence. All four nominally disposable attempt trees
  survived a result that otherwise reported `COMPLETE`, directly reproducing
  the unproven-disposal defect before implementation.

## 2026-07-29 — V3-FORKSUITE-001

- **Status:** `PARTIAL`; safe Foundry scope complete, real Hardhat integration
  `BLOCKED_TECHNICAL`.
- **2026-08-03 terminal reconciliation:** The authoritative execution order returned to this
  already validated ticket after scheduler completion. The complete current suite again includes
  all Foundry/Hardhat refusal regressions and passed `4401` tests with `11` explicit prerequisite
  skips. No safe Foundry or adapter portion remains open. Real Hardhat execution still lacks the
  documented process-attested digest-pinned rootless single-loopback runtime and trusted
  image-baked reporter; no mock can substitute. The correct mixed disposition remains `PARTIAL`,
  with only that real integration subtask `BLOCKED_TECHNICAL`.
- **Defensive objective:** Execute an explicitly selected, bounded subset of an
  audited repository's existing Foundry suite against operator-pinned local fork
  state, with typed deterministic finding evidence and fail-closed hardened
  isolation. Preserve the legacy audit-test profile and prepare the digest-pinned
  rootless Hardhat boundary without treating unavailable prerequisites as passes.
- **Starting state:** Clean synchronized `main` at
  `14908b3dcd38cdb1c91428306d160d80d67eb325`; the complete objective was reread
  and reverified at SHA-256
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
  No provider call, network access, operator-secret access, live RPC, signing, or
  paid spend is part of this implementation slice.
- **Next safe action:** Inspect existing trusted tool resolution, Foundry fork
  execution, container isolation, project discovery, normalized scanner evidence,
  and pipeline finding origination; then add an expected-red bounded-selection
  regression before implementation.
- **Expected-red defect proof:** Three focused regressions failed against the
  checkpoint tree. Recursive nonempty Foundry `fs_permissions` was accepted; a
  backend declaring no local-fork RPC capability reached Forge resolution; and
  a missing configured loopback RPC was reported as engine failure rather than
  `UNAVAILABLE`. These failures occurred before any target process, RPC,
  provider request, secret access, or spend.
- **Independent design review:** Read-only Foundry, isolation/Hardhat, and
  evidence reviews confirmed the missing bounded selection manifest,
  project-aware per-test execution, chain/block/seed binding, per-test evidence,
  cleanup, and configuration controls. They also found that location annotation
  mutates a sealed scanner run without resealing it. The current rootless
  container deliberately denies all networking and is not REAL-attested, so a
  Hardhat fork suite must remain explicitly unavailable until a separately
  proven single-loopback-endpoint boundary exists; broad container networking
  will not be introduced.
- **Implemented before operator pause:** Foundry preflight now rejects a backend
  without explicit local-fork RPC capability, classifies a missing configured
  RPC as `UNAVAILABLE`, recursively rejects nonempty `fs_permissions`, fixes the
  profile and filesystem-permission environment, and avoids target execution in
  each refusal case. Scanner location annotation now reseals and revalidates the
  modified execution observation.
- **Focused validation:** The three Foundry fail-closed regressions passed
  together (`3 passed in 0.23s`), and the scanner-observation resealing
  regression passed (`1 passed in 0.40s`).
- **Pause checkpoint:** At the operator's request, delegated workers stopped at
  clean boundaries without filesystem edits. The bounded selector, typed
  per-test schemas, full project-aware execution path, Hardhat refusal adapter,
  and ticket-wide validation remain incomplete. Temporary Forge output created
  while inspecting trusted list output was removed; only intentional source,
  test, queue, and worklog changes remain.
- **Resume checkpoint:** Persistent-goal continuation resumed the same bounded
  ticket from the preserved worktree. The authoritative objective was reread
  and its SHA-256 reverified before further implementation.
- **Second operator pause:** Autorun stopped at the next safe boundary after the
  typed repository-suite configuration, evidence schemas, deterministic selector,
  loopback fork binding, per-test Foundry execution path, maximum-assurance
  portfolio gate, and explicit Hardhat prerequisite adapter were implemented.
  Focused schema, selector, RPC, Hardhat, scanner, and root assurance regressions
  have passed; ticket-wide and full-suite validation have not yet run. The
  uncommitted implementation and tests are intentionally preserved for review
  and completion on resume. No target process, provider request, secret access,
  budget reservation, or external network operation remains active.
- **Second resume checkpoint:** Persistent-goal continuation reactivated the
  same bounded ticket from the preserved worktree. The complete 1417-line
  objective and repository instructions were reread, the objective hash matched,
  the current diff passed its whitespace check, and no paid or external operation
  was initiated.
- **Third operator pause:** Work stopped at a clean diagnostic boundary. All
  delegated reviews are complete and no child process or delegated task remains
  active. The hardened local Foundry integration now reaches the selected
  synthetic test and emits output, but strict per-test JSON normalization rejects
  the observed Forge payload. The next action is bounded inspection and parser
  correction, followed by the affected validation matrix. The intentional
  uncommitted implementation is preserved; no provider request, public RPC,
  secret access, budget reservation, or external network operation remains active.
- **Third resume checkpoint:** Persistent-goal continuation resumed the same
  bounded ticket. The complete objective was reread and hash-verified, the
  intentional worktree passed `git diff --check`, and work resumed from the
  strict Forge JSON normalization failure without paid or external operations.
- **Implemented execution evidence:** Added a typed, self-hashed repository-suite
  execution policy; exact Foundry/solc/isolation/fork/config binding; stable
  normalized machine-result hashes; raw-output forensic hashes; honest
  pre-filter candidate denominators; fail-closed inherited-test detection; and
  replay comparison that ignores volatile timing/private paths while detecting
  toolchain, block, policy, and normalized-evidence drift.
- **Real local execution evidence:** The synthetic integration executed pinned
  unit, fuzz, invariant, and failing-control tests twice in fresh private
  workspaces against loopback Anvil chain `31337` at block `0`. It required an
  explicit external native solc path, produced typed failure evidence, validated
  JSON round-trips and private manifests, and matched the semantic replay
  projection. The exact command recorded above passed once in `6.32s`.
- **Focused regression evidence:** The latest combined schema, replay,
  assurance, and scanner matrix passed `273` tests in `28.72s`; repository-suite
  selection and inherited-test refusal passed `17` tests in `0.32s`. An earlier
  broad affected matrix passed `452` tests in `132.93s`, but it predates the
  final policy and denominator changes and is not represented as final
  ticket-wide validation.
- **Remaining ticket limitations:** Real Hardhat execution is
  `BLOCKED_TECHNICAL`: neither Podman nor Docker is installed/configured, no
  approved digest-pinned image is present, and the existing rootless backend
  intentionally denies networking and lacks a REAL identity attestation.
  Inherited Foundry tests fail closed rather than run because a trusted isolated
  runtime inventory reconciled to declarations is not yet implemented. These
  limitations cannot satisfy the complete ticket acceptance criteria.
- **Pause-time static validation:** `.venv/bin/ruff format --check <25 affected
  Python files>` reported all 25 already formatted; `.venv/bin/ruff check <same
  files>` passed; canonical `.venv/bin/mypy` passed all 143 configured source
  files; and `git diff --check` passed. The noncanonical
  `.venv/bin/mypy <14 affected production paths>` invocation still included
  configured test modules and returned 70 existing test-only diagnostics, so it
  is not used as the authoritative type gate.
- **Fourth operator pause:** Work stopped at a clean resumable boundary. All
  delegated tasks and child processes are complete. The queue ticket remains
  `IN_PROGRESS`; the final affected pytest matrix and full repository suite have
  not run after the latest changes. This is a partial-ticket checkpoint, not
  ticket completion. No provider request, public RPC, operator secret access,
  budget reservation, container, or external network operation is active.
- **Checkpoint:** The bounded partial-ticket implementation was committed as
  `6c67db4e95567200d51038665c65bb18bf5b5f16` (`Add pinned repository suite
  execution`) and pushed to `origin/main` over SSH. This does not mark
  `V3-FORKSUITE-001` complete.
- **Fourth resume checkpoint:** Persistent-goal continuation resumed the clean
  synchronized metadata checkpoint `cae223ab6cc10c623dfc06f1207c0bee29eddebe`.
  The full objective was reread and hash-verified, repository instructions and
  current ticket state were reloaded, and the worktree was clean before
  validation resumed. No provider, public RPC, secret, or paid operation is
  involved.
- **Final affected matrix:** The exact affected unit and pipeline command
  recorded immediately before this entry passed `534` tests in `305.87s`.
  Provider-gated tests were not enabled and no external network or secret path
  ran.
- **Final real Foundry integration:** With the explicit trusted native solc
  path, `tests/integration/test_repository_foundry_fork_suite.py` passed `1`
  test in `6.47s`, exercising two fresh hardened local executions and semantic
  replay comparison against loopback-only Anvil.
- **Acceptance-gap correction:** A typed scanner finding now carries
  `DETERMINISTIC_ANALYZER` strength only when its hash-linked repository test
  execution is REAL; mock/unverified execution cannot claim that strength.
  Scanner-only report conversion preserves the typed strength without upgrading
  status. Focused regressions now classify assertion, revert, and generic
  failure outcomes; missing Forge or pinned solc emits typed `UNAVAILABLE`
  executions without target execution. The focused schema/scanner matrix passed
  `110` tests in `3.08s`.
- **Expanded real outcome portfolio:** The real integration now executes six
  selected tests and distinguishes unit, fuzz, invariant, assertion-failed,
  reverted, and generic-failed outcomes. Three failing executions each produce
  exactly one hash-bound typed finding with REAL deterministic evidence. The
  two-fresh-workspace replay integration passed `1` test in `7.34s`.
- **Pre-full-suite gates:** `.venv/bin/ruff format .` left all `325` files
  unchanged; `.venv/bin/ruff check .` passed; `.venv/bin/mypy` reported no
  issues in `143` source files; and
  `.venv/bin/python scripts/generate_release_schemas.py` verified the committed
  release schemas without drift.
- **First full-suite result and fixes:** `.venv/bin/pytest -q` completed with
  `2496 passed, 11 skipped, 2 failed in 345.13s`. One stale synthetic assurance
  fixture omitted the newly required REAL deterministic strength. The second
  failure exposed a real token-planning edge: serializing the default
  `evidence_strength=none` on every scanner record could crowd all source
  excerpts out at a tight boundary. The fixture now binds its REAL strength;
  provider-visible scanner serialization omits only that semantically empty
  default while retaining all non-default strength and forensic serialization.
  The two exact failures passed, followed by `272` affected context, token,
  assurance, schema, and scanner tests in `26.60s`. Ruff format/check, strict
  mypy over `143` source files, and release-schema verification pass after the
  correction.
- **Final full-suite gate:** The corrected `.venv/bin/pytest -q` run passed
  `2498` tests with `11` explicit external-prerequisite skips in `645.50s`.
  The real provider test remained opt-in and skipped; no API key, provider
  request, public RPC, or paid spend was involved.
- **Closure review decision:** The ticket remains `IN_PROGRESS`, not complete or
  partial-closed. Independent review confirmed the direct-test Foundry slice is
  real and bounded, but inherited tests are a safe implementable gap. Safe
  support requires an isolated, pinned `forge test --list --json --ast
  --build-info` inventory reconciled to compiler AST
  `linearizedBaseContracts`, with separate execution and declaration identity.
  The current refusal remains until that binding exists. Hardhat remains
  independently `BLOCKED_TECHNICAL` pending a REAL-attested rootless runtime,
  digest-pinned image, narrow Unix-socket RPC bridge, and trusted reporter; its
  safe mock/conditional adapter work will be audited after the inherited slice.
- **Validated evidence checkpoint:** The direct-test and evidence-strength slice
  was committed as `a8c732f11e02ba65fc358f311ed5df3cc7b57037`
  (`Bind repository test execution strength`) and pushed to `origin/main` over
  SSH.
- **Inherited expected-red proof:** The real synthetic fixture now includes an
  inherited abstract-base negative regression. The exact local integration
  command recorded above failed as expected in `0.91s` because the existing
  parser refuses inheritance before execution. This proves the next slice is
  not already implemented; no target test, provider call, public RPC, secret, or
  paid path ran.
- **Compiler inventory implementation:** Added bounded isolated pre/post Forge
  inventory execution, strict compiler build-info AST reconciliation, separate
  execution and effective-declaration identity, self-hashed artifact and record
  evidence, compiler-backed selection denominators, inherited/override/diamond
  parser regressions, no-network execution support, and maximum-assurance/replay
  bindings. The focused parser, runner, schema, selector, and fail-closed
  provenance subsets are green; the real local integration command recorded
  above is running next.
- **First real inventory correction:** The unprivileged invocation skipped
  because process-attested `sandbox-exec` is unavailable inside the outer
  filesystem sandbox. The authorized local rerun reached compiler inventory and
  failed closed in `0.96s` with `Forge version is invalid`; the attested
  multiline Forge version is now normalized to bounded printable text only
  after its trust-pin check. No public network, provider, or secret path ran.
- **Second real inventory correction:** The next local rerun failed closed in
  `1.19s` before compilation. Its isolated stderr recorded OS error 35 while
  Forge attempted to start the regular, one-link, hash-matched private solc
  copy. The inventory runner had applied `RLIMIT_NPROC=64` on Darwin, where that
  limit counts all processes owned by the login user; the established per-test
  runner already excludes Darwin for this reason. Inventory execution now
  skips only `RLIMIT_NPROC` on Darwin while retaining CPU, file-size,
  descriptor, address-space, sandbox, output, and deadline bounds. A synthetic
  resource-module regression proves the platform-specific limit set, and the
  runner unit suite passes `8` tests in `2.80s`. The real inherited-test
  integration is the next validation; no external network, provider, secret,
  or paid path is involved.
- **Fresh-workspace replay correction:** The next real integration completed
  both hardened scanner runs but failed its semantic replay assertion
  (`1 failed in 6.76s`). Exact artifact comparison isolated all compiler
  inventory drift to Forge's derived build ID and the private absolute
  `basePath`, `allowPaths`, and `includePaths`; source, AST declaration,
  selection semantics, toolchain, and fork identity agreed. Raw artifact
  name/hash/bytes remain sealed forensic evidence. A duplicate-key-rejecting
  normalizer now replaces only the validated volatile build ID and paths with
  canonical stable values, rejects escapes and malformed/link paths, and emits
  separate normalized artifact and bundle hashes. Selection, executions,
  replay, and maximum-assurance qualification bind those normalized identities,
  while each run still requires exact raw pre/post equality. The combined
  parser, runner, and schema suite passed `45` tests; Ruff and strict mypy
  passed. The real inherited-test integration is being rerun with no provider,
  public network, secret, or paid operation.
- **Normalized-evidence focused gate:** The affected compiler-inventory,
  selection, schema, assurance, replay, scanner, benchmark-binding, and
  configuration matrix passed `359` tests in `28.13s`. The macOS isolation
  subset passed `3` tests, including an explicit inventory policy assertion
  that grants no network entitlement. Affected Ruff passed and configured
  strict mypy passed all `145` source files. The real two-workspace integration
  is running next.
- **Source and artifact containment closure:** Scanner workspace hashing and
  copying now use one bounded descriptor-relative no-follow inventory. Foundry
  inventory, process streams, generated artifacts, and Forge result parsing are
  bound to retained descriptor snapshots. Exact custom output exclusion is a
  normalized, self-hashed selection field; offline replay reconstructs that
  exclusion, verifies the frozen repository hash before and after execution,
  rejects conflicting identities, and passes the exact identity into the
  scanner runner.
- **Independent hardening findings:** Read-only review found a whole-path
  compiler-inventory denominator omission, resource-limit callbacks that could
  abandon later limits after one failure, missing direct credential-environment
  evidence, duplicate normalized compiler-artifact multiplicity, and pathname
  races in Hardhat configuration reads. Expected-red regressions reproduced
  each unsafe condition. The implementation now requires global Forge/compiler
  suite equality, attempts all applicable resource limits before failing
  closed, uses an explicit Foundry subprocess environment allowlist, rejects
  duplicate normalized artifacts, and reads Hardhat configuration/package
  inputs through retained repository-root no-follow descriptors.
- **Hardhat boundary result:** Strict self-hashed reporter inventory and result
  schemas, explicit bounded selection, exact reporter/repository/fork/seed/test
  bindings, deadline validation, and extensive malformed-evidence and
  no-execution regressions are implemented. The current adapter always returns
  `UNAVAILABLE`, `UNVERIFIED`, and repository execution `BLOCKED`; it cannot
  invoke target JavaScript or receive REAL credit. Production execution remains
  `BLOCKED_TECHNICAL` because no process-attested digest-pinned rootless
  single-loopback backend or trusted image-baked reporter exists.
- **Repeatability defect and correction:** The first real post-hardening
  integration failed safely with `Foundry inventory generated root could not be
  inspected`; a fresh rerun passed. A three-run assay then produced two passes
  and one fail-closed `Foundry private artifact directory changed while it was
  traversed`, proving a real flake. Live limit polling had incorrectly required
  stable directory size/timestamps while trusted Forge/solc was actively
  writing. Explicit `LIVE_LIMIT_MONITOR` and `STRICT_SNAPSHOT` purposes now
  tolerate only stale live samples from benign metadata churn or vanished
  same-type entries while preserving descriptor ancestry, no-follow/type/link
  checks, identities, and ceilings. Every post-process content hash and captured
  result still requires a strict stable snapshot.
- **Real local repeatability evidence:** After that correction, five consecutive
  invocations of
  `MMAUDIT_TEST_SOLC_EXECUTABLE=/Users/josevans/.solc-select/artifacts/solc-0.8.30/solc-0.8.30
  .venv/bin/pytest -q
  tests/integration/test_repository_foundry_fork_suite.py -rs` passed in
  `6.59s`, `6.49s`, `6.34s`, `6.51s`, and `6.24s`. Each invocation ran two
  fresh hardened scanner workspaces against loopback-only Anvil. No provider,
  public RPC, operator secret, wallet, signing, or paid path ran.
- **Current focused gate:** The exact command recorded in `LAST_COMMAND` passed
  `517` tests in `30.26s` before `LAST_COMMAND` advanced to the full suite. The
  delegated Hardhat matrix passed `100` tests; the
  live-monitor unit slice passed `49`; and the compiler denominator/resource/
  environment slice passed `53`. Affected Ruff, formatting, strict mypy, and
  `git diff --check` passed. The ticket remains `IN_PROGRESS` pending the
  independent closure review and complete repository gates.
- **Pre-full-suite gates:** `.venv/bin/ruff format .` reformatted `3` files and
  left `328` unchanged; `.venv/bin/ruff check .` passed; `.venv/bin/mypy`
  reported no issues in `145` source files; and
  `.venv/bin/python scripts/generate_release_schemas.py` verified the committed
  release schemas without drift. The complete pytest command recorded in
  `LAST_COMMAND` ran with paid-provider tests disabled.
- **Operator pause after complete gate:** `.venv/bin/pytest -q` passed `2642`
  tests with `11` explicit unavailable external-engine, isolation, loopback,
  compiler, and opt-in paid-provider prerequisite skips in `318.13s`. The
  independent closure reviewer was stopped without edits, all delegated work
  and child processes are inactive, and no provider request, public RPC,
  operator-secret access, budget reservation, or paid spend occurred. The
  ticket intentionally remains `IN_PROGRESS`; on resume, finish the read-only
  closure review and final diff inspection before recording its terminal
  disposition and checkpoint.
- **Resume after complete gate:** Persistent-goal continuation reactivated the
  same ticket from the preserved worktree. The complete 1417-line objective was
  reread and hash-verified, repository instructions and both persistent queues
  were inspected, `git diff --check` passed, and two independent read-only
  closure reviews are running. No provider, public RPC, operator-secret, wallet,
  signing, or paid path is involved.
- **Final independent acceptance review:** Both read-only reviewers accept the
  Foundry selection, compiler inventory, execution, replay, source identity,
  typed evidence, and fail-closed semantics. They reject whole-ticket
  completion because Hardhat remains deliberately non-executable without a
  process-attested digest-pinned rootless single-loopback runtime and trusted
  reporter. The correct disposition after final gates is `PARTIAL`, with only
  the real Hardhat integration subtask `BLOCKED_TECHNICAL`.
- **Closure-review corrections:** An isolation backend must now explicitly
  attest `supports_local_fork_rpc is True`; an absent or merely truthy capability
  stops before tool lookup. Compiler inventory stream, build-info, cache, and
  output limits are now all capped by the suite's remaining byte budget, with a
  combined stream-plus-generated ceiling checked during execution and after
  strict capture. Pre- and post-inventory phases consume the same cumulative
  suite budget rather than each receiving oversized defaults.
- **Corrected focused evidence:** The explicit/undeclared loopback-capability
  regressions passed `2` tests; the remaining-budget and combined-output
  regressions passed with the existing stream-overflow control (`3 passed`);
  Ruff passed. The exact real local integration in `LAST_COMMAND` passed in
  `6.30s`, exercising two fresh process-attested workspaces against loopback
  Anvil after the correction. No provider, public RPC, secret, wallet, signing,
  or paid path ran.
- **Corrected pre-final gates:** The complete affected matrix passed `520`
  tests in `32.40s`; `.venv/bin/ruff format .` left `331` files unchanged;
  Ruff check passed; strict mypy passed all `145` configured source files;
  release-schema synchronization and `git diff --check` passed. The complete
  pytest command recorded in `LAST_COMMAND` ran with paid-provider execution
  disabled.
- **Final complete gate:** `.venv/bin/pytest -q` passed `2645` tests with `11`
  explicit unavailable external-engine, isolation, loopback, compiler, and
  opt-in paid-provider prerequisite skips in `297.43s`.
- **Ticket disposition:** `V3-FORKSUITE-001` is `PARTIAL`. The Foundry scope has
  real local execution evidence and satisfies its bounded selection, pinned
  state, isolation, source identity, typed evidence, replay, and failure
  semantics. Real Hardhat execution remains the sole ticket subtask
  `BLOCKED_TECHNICAL`: its current adapter cannot execute JavaScript or receive
  REAL credit, and no approved process-attested digest-pinned rootless
  single-loopback runtime or trusted image-baked reporter is available. The
  independently actionable Foundry differential ticket may proceed without
  weakening this blocker.

## 2026-07-29 — V3-FLOOR-001 implementation and focused validation

- **Status:** `IN_PROGRESS`.
- **Expected-red defect proof:** The original scanner-only regression used an
  unavailable scanner, zero provider calls, and zero completed model roles yet
  returned `SUCCESS`. The inverted regression failed before the implementation,
  proving the false-complete condition.
- **Implementation:** Added typed `COMPLETE`, `DEGRADED`, `INCOMPLETE`, and
  `FAILED` run states; a serialized minimum-analysis-floor assessment; strict
  REAL scanner/model evidence credit; pre-spend model-surface assignment
  feasibility; and run-state-consistent report completion and quality status.
  Required infeasible scope and surface assignments now block provider work
  before spend.
- **Reporting:** Incomplete zero-finding Markdown leads with the required
  limitation and does not present a normal no-findings headline. SARIF and
  metadata carry consistent run-state evidence and report unsuccessful
  execution unless the explicit state is `COMPLETE`.
- **Focused evidence:** Affected Ruff formatting/check and strict mypy passed.
  The combined integration, CLI, typed status, model coverage, and reporting
  matrix passed `108` tests in `3.80s`.
- **Broad-matrix correction:** The first compatibility run passed `502`, skipped
  one explicit hardened-replay prerequisite, and failed `15` in `148.98s`.
  Thirteen failures were stale assertions that MOCK, UNVERIFIED, unavailable,
  or synthetic execution completed an audit; those tests now assert
  `INCOMPLETE` while retaining their privacy, ordering, evidence, finding, and
  artifact checks. Two failures exposed real control-flow defects: local model
  qualification evidence could be skipped while its filename was declared,
  and a pre-authorized maximum-assurance scope downgrade blocked all bounded
  analysis. Qualification validation is now emitted before transport decisions,
  only an emitted qualification artifact is credited, and explicit maximum
  scope downgrade preserves reduced analysis without permitting `COMPLETE`.
- **Corrected regression evidence:** The `16` exact affected production and
  compatibility nodes passed in `18.43s`; affected Ruff and strict mypy also
  passed. Mock scanner findings remain in SARIF, but `INCOMPLETE` correctly
  takes precedence over a findings-only exit.
- **Independent evidence-binding review:** A direct assay proved that the first
  typed report draft could accept a self-consistent `COMPLETE` floor while the
  serialized report contained zero scanner runs and zero model usage. Report
  schema `1.2` now requires the floor and its gate and cross-binds claimed
  source, compilation, qualifying REAL scanner, qualifying REAL model-role, and
  coverage evidence to the report. Legacy schemas `1.0` and `1.1` cannot carry
  the new typed floor. A schema-1.2 report cannot become legacy-valid merely by
  deleting the floor fields.
- **Additional fail-closed corrections:** An enabled formal-adapter exception
  now makes the terminal run non-successful. Surface feasibility uses one
  approved root lineage for a lower profile and three for maximum assurance;
  applicable infeasibility blocks provider transport, while a maximum downgrade
  proceeds only when the lower-profile gate is feasible. SARIF rejects
  contradictory run-status, quality-status, completion, or missing limitation
  tuples instead of serializing them.
- **Post-review focused evidence:** The exact status, coverage, reporting,
  schema-binding, surface preflight, formal failure, scope, qualification, and
  maximum-downgrade matrix passed `46` tests in `12.63s`. The reporting,
  manifest, replay, release, and benchmark-model evidence subset passed `201`
  tests in `13.16s`; the complete pipeline and CLI files passed `134` in
  `83.52s`. Affected Ruff and strict mypy checks passed.
- **Consolidated compatibility evidence:** The corrected broad local matrix
  passed `523` tests with one explicit hardened-isolation replay prerequisite
  skipped in `125.44s`.
- **Final serialized-evidence review:** A typed REAL usage record now retains
  credit after JSON round-trip only when its complete structural execution
  identity validates; `COMPLETE` rejects retained incomplete reasons and any
  failed required quality gate. A maximum-assurance report can be `COMPLETE`
  only when its requested assurance assessment is also `COMPLETE`; legitimate
  pre-authorized downgraded assessments remain serializable as non-complete.
  The typed report suite passed `12` tests, and both affected maximum-assurance
  pipeline regressions passed in `23.46s`.
- **Honesty boundary:** Unit evidence may construct typed REAL records to test
  the deterministic decision function, but it is not recorded as a real
  scanner or provider integration. No provider call, network access, operator
  secret access, reservation, or spend occurred.
- **Ticket result:** `V3-FLOOR-001` is `COMPLETE`. This proves the local
  fail-closed run-status and serialized-evidence boundary; it does not claim a
  real provider review, real external-engine execution, or completed real
  audit.
- **Final static/schema gate:** `.venv/bin/ruff format .` reformatted one
  affected file and left `315` unchanged; `.venv/bin/ruff check .` passed;
  strict `.venv/bin/mypy` passed all `140` source files; release-schema
  synchronization and `git diff --check` passed without output.
- **Complete local gate:** `.venv/bin/pytest -q` passed `2397` tests with `10`
  explicit external-engine, isolation, loopback, and paid-provider prerequisite
  skips in `364.66s`. No provider call, network access, operator-secret access,
  reservation, or spend occurred.
- **Validated implementation checkpoint:** Commit
  `c9ff0a8f49ad65728c031505ceab372d4e779ec7` contains the cohesive
  V3-FLOOR-001 implementation and regression evidence.
- **Operator pause:** Autorun is paused at the requested clean ticket boundary.
  No process or cost reservation remains active. On resume, begin
  `V3-FORKSUITE-001`; it was not started in this pause turn.

## 2026-07-29 — Operator pause during V3-TOKENS-001

- **Status:** `PAUSED_BY_OPERATOR`; the ticket remains `IN_PROGRESS`.
- **Preserved state:** All V3-TOKENS-001 implementation, generated schema, tests,
  operator documentation, and prior validation evidence remain uncommitted in
  the worktree at source commit
  `5f52bb0eb19a19c43e2ea480fb8563e4109df5b7`.
- **Last proven validation:** The combined formerly failing fixture matrix
  passed `427` tests in `104.90s`. The final repository-wide static/schema gate
  result was lost to output truncation and is intentionally not claimed.
- **Resume action:** Re-run formatting, Ruff, mypy, schema freshness, and diff
  checks; run the complete pytest suite; then review, record, checkpoint, and
  SSH-push V3-TOKENS-001 before starting `V3-FLOOR-001`.
- **Safety/accounting:** No provider call, network access, operator-secret
  access, paid spend, commit, or push was performed while pausing.

## 2026-07-29 — V3-TOKENS-001 resumed after operator pause

- **Status:** `IN_PROGRESS`.
- **Recovery:** Re-read the authoritative objective in four complete chunks;
  its `1417` lines and SHA-256
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`
  are unchanged. Rechecked the queue, worklog, current status, diff stat, and
  diff integrity.
- **Preserved scope:** The worktree still contains only the uncommitted
  endpoint-aware token planning, typed omission evidence, context-manifest,
  report-quality budgeting, generated schema, operator documentation, and
  regression work for this ticket.
- **Next validation:** Run formatting, Ruff, strict mypy, schema synchronization,
  diff checks, and the complete local suite before recording or checkpointing
  completion. No paid provider call is part of this ticket.
- **Static/schema validation:** `.venv/bin/ruff format .` reported `312 files
  left unchanged`; the first Ruff check identified one mechanical import-order
  issue in a modified synthetic qualification test, which was corrected, and
  the second `.venv/bin/ruff check .` passed. `.venv/bin/mypy` passed with
  `Success: no issues found in 139 source files`;
  `.venv/bin/python scripts/generate_release_schemas.py` and
  `git diff --check` both passed without output.
- **Long-running gate prepared:** The complete local pytest suite is the next
  command. Provider tests remain explicitly gated and no secret file will be
  read.
- **First complete-suite result:** `.venv/bin/pytest -q` passed with `2340
  passed, 10 skipped in 326.79s`. The skips remain explicit external
  prerequisites: rootless isolation image, Echidna, Medusa, hardened isolation
  for Halmos/replay, local-fork-capable isolation, paid-provider opt-in, and
  loopback availability.
- **Independent closure review:** Corrected the operator document's
  `atomic-reservation` label to the emitted `cost-budget` preflight class. Added
  a negative report-quality regression that provides a separately valid but
  evidence-drifted prepared workflow and proves typed rejection before a spy
  transport receives any call. The affected token/context/report-quality
  matrix passed `88` tests in `0.81s`; the report-quality file independently
  passed `4` tests, Ruff, and diff integrity.
- **Final validation prepared:** Because the new regression was added after the
  first complete run, all repository-wide static/schema gates and the complete
  suite will run again before completion is claimed.
- **Second complete-suite baseline:** After the drift regression,
  `.venv/bin/pytest -q` passed with `2341 passed, 10 skipped in 328.36s`. This
  remains a baseline rather than completion evidence because the independent
  production-diff review identified additional ticket-scope gaps.
- **Closure defects accepted:** The review demonstrated that a
  maximum-assurance effective config could retain a `256`-token visible output
  cap and `1024`-token source cap; context omission hashes could collapse
  repeated reductions behind a generic descriptor; multiple individually
  bounded logical blocks could cumulatively exceed the source ceiling; dynamic
  candidate falsifier routes could differ from the context-preview routes;
  verifier/judge preview rejection could append `None` and later crash evidence
  normalization; and a self-rehashed persisted request plan could omit
  metadata-backed completion capacity.
- **Maximum-assurance and persisted-plan remediation:** The effective maximum
  assurance profile now floors visible output and workflow reserve at `32768`
  tokens and source capacity at `200000` tokens while final endpoint planning
  still fails closed if an approved route cannot supply them. A
  `RequestTokenPlan` now independently rejects routes without an explicit
  metadata completion limit, including a self-rehashed persisted-plan
  regression. The affected config/token/OpenRouter/context-manifest matrix
  passed `298` tests in `1.26s`; Ruff and strict mypy passed.
- **Remaining ticket work:** Complete the bounded ContextBuilder omission/source
  fixes and pipeline route/graceful-preflight fixes, then rerun all affected,
  static/schema, integration, and complete-suite gates. No provider call,
  secret access, or spend is involved.
- **First closure remediation:** Context omissions now bind each actual
  before/after inventory transition without persisting omitted content, repeated
  reductions remain distinct, and source excerpts share one cumulative
  source-token ceiling. Verifier/judge preview failures preserve fail-closed
  artifacts without appending invalid context values. Exact dynamically selected
  candidate cross-examination routes are previewed instead of the configured
  falsifier alias.
- **Exact workflow and envelope remediation:** Verification, judgment,
  candidate cross-examination, exploit planning, reproduction falsification,
  and report-quality inputs are prepared as immutable canonical workflows before
  context allocation. Each carries an exact UTF-8 bound and SHA-256 and is
  recomputed before transport; drift receives a typed rejection with zero
  transport calls. Preview uses provider-visible JSON-string workflow size and
  iterates against the exact rendered-context JSON escape overhead.
- **Context identity and source-priority remediation:** Candidate
  cross-examination packages use a distinct context role and cannot masquerade
  as the completed reproduction-falsifier context in specialist execution
  evidence. ContextBuilder now measures its base serialization exactly and
  reserves bounded per-file serialization overhead so graph/metadata material
  cannot consume all source capacity on a review request.
- **Focused closure evidence:** Prepared-input unit tests passed `16`; the
  exact-route, graceful-refusal, generated-reproduction, and
  maximum-assurance integration slice passed `7`; the combined
  token/config/OpenRouter/context/report-quality/pipeline matrix passed `380`
  tests in `111.66s`. Affected Ruff and strict mypy checks passed. All paid
  provider paths remained disabled; no network, secret access, reservation, or
  spend occurred.
- **Pre-full-gate state:** `V3-TOKENS-001` remains `IN_PROGRESS` pending the
  final independent re-review and repository-wide formatter, Ruff, mypy, schema,
  diff, artifact, secret-pattern, and complete pytest gates.
- **Second closure correction:** Independent review found that a temporary
  per-file source-framing estimate could reserve `65,000` bytes for `27` source
  bytes and discard fitting deterministic metadata, and that the first
  escape-adjusted preview could retain a larger pre-adjustment `byte_budget`.
  The reserve is now a fixed bounded serialization allowance only when source
  exists; a 100-file/100,000-byte regression retains source, all `40` indexed
  entities, `20` invariants, and `10` scanner findings while using more than
  `75,000` bytes. Preview returns only when the built package's recorded budget
  is no greater than the escape-adjusted endpoint cap; otherwise it rebuilds or
  fails closed after eight deterministic passes.
- **Post-correction evidence:** The tiny-file capacity regression and complete
  maximum-assurance synthetic integration both passed (`2 passed in 21.07s`);
  affected Ruff and strict mypy passed. Indivisible logical blocks larger than
  the configured chunk bound remain explicitly omitted with typed evidence;
  a requested-surface context with no source excerpt now fails before provider
  transport. Semantic resharding remains a later queued ticket.
- **Independent final re-review:** The reviewer reran the tiny-file and exact
  selected-model assays (`3 passed`) and found no material blocker in source
  allocation, prepared workflow identity, route selection, context identity,
  escape convergence, or persisted context-budget evidence.
- **Final static/schema gate:** `.venv/bin/ruff format .` left `314` files
  unchanged; `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed `139`
  source files; `.venv/bin/python scripts/generate_release_schemas.py` and
  `git diff --check` passed without output. The complete local pytest suite is
  the remaining ticket gate.
- **Complete local gate:** `.venv/bin/pytest -q` passed `2366` tests with `10`
  explicit skips in `421.74s`. The skips are the documented unavailable
  rootless isolation image, Echidna, Medusa, hardened Halmos/replay isolation,
  local-fork isolation, loopback binding, and explicitly disabled paid-provider
  integration. No skipped requirement is represented as real execution.
- **Ticket result:** `V3-TOKENS-001` is `COMPLETE` as a local implementation
  ticket. It proves endpoint-aware fail-closed token/context accounting,
  prepared dynamic workflow preflight, normalized evidence, and report/schema
  serialization through deterministic local and fake-provider execution. It
  does not claim a new provider call, real audit, external engine, or semantic
  resharding result.
- **Zero-source preflight closure:** A final adversarial assay showed that one
  oversized indivisible logical block could produce a requested-surface package
  with zero source excerpts. Although downstream evidence validation rejected
  review credit, the provider request itself was inherently uncreditable.
  Context construction now rejects that state before transport. The new
  zero-source regression, tiny-file capacity regression, and complete
  maximum-assurance synthetic integration passed together (`3 passed`); affected
  Ruff and strict mypy passed.
- **Final post-closure validation:** `.venv/bin/ruff format .` left `314` files
  unchanged; `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed all `139`
  source files; schema synchronization and `git diff --check` passed. The exact
  final tree then passed `.venv/bin/pytest -q` with `2367 passed, 10 skipped in
  329.08s`. Every skip is an explicit external-engine, isolation, loopback, or
  paid-provider prerequisite; none is counted as real execution.
- **Validated checkpoint:** Commit
  `94b9f0791dee832273f016d81c06af3a56158d3e` contains the complete
  V3-TOKENS-001 implementation, schemas, operator documentation, and regression
  evidence.

## 2026-07-29 — V3-FLOOR-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Ensure zero real scanner execution plus zero completed
  model roles can never produce a successful exit or completed no-findings
  report, and derive the run status only from real completed analysis evidence.
- **Initial action:** Reproduce the standard-profile false-complete path and map
  the existing terminal exit, report-completion, scanner, and model-role
  evidence before implementing the minimum floor. This local diagnostic work
  requires no network, provider call, secret access, or paid spend.
- **Defect reproduced:** The renamed negative regression
  `tests/integration/test_pipeline.py::test_zero_completed_analysis_fails_closed`
  failed at the first assertion because the standard-profile scanner-only run
  returned `ExitCode.SUCCESS` despite an unavailable scanner, zero provider
  calls, zero completed model roles, and no findings. The local assay completed
  in `1.04s` and made no external call.
- **Independent review:** Three read-only reviews agreed that `completed` is
  currently derived from terminal control flow rather than qualifying runtime
  evidence; mock or unverified scanner/model records can receive completion
  credit; scanner-only bypasses substantive gates; incomplete zero-finding
  Markdown leads with a misleading finding-count sentence; and current
  critical-surface assignment feasibility is not checked before provider
  spend.

## 2026-07-29 — V3-OUTPUT-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Negotiate exact endpoint output capability as native
  JSON Schema, JSON object, or locally validated text JSON while preserving
  strict schema semantics, identity binding, truncation rejection, and review
  credit gates.
- **Starting state:** Clean synchronized `main` at
  `d6a7a58fd6689b219772827389304133665d73ab`; `V3-PRIVACY-001` is complete.
  No paid provider call, network access, or operator secret access is part of
  this implementation slice.
- **Next safe action:** Inspect request construction, endpoint discovery,
  response parsing, usage evidence, candidate benchmarking, qualification
  scoring, and existing malformed/truncated response tests; then add a failing
  regression before implementation.
- **Pause checkpoint:** Operator requested a pause before production
  implementation began. Read-only mapping confirmed that request construction
  currently always emits native JSON Schema, endpoint registration drops
  structured-output capabilities, and review credit does not bind an achieved
  output mode to exact endpoint capability evidence. It also identified strict
  JSON regressions for duplicate keys and non-finite constants. No source or
  test files were changed, no provider call was made, and all audit agents were
  stopped.
- **Resume checkpoint:** Automatic goal continuation resumed from clean
  synchronized commit `48d9f9d1b3606d6bd1c8167793ce9675dfbcb4f1`.
  The authoritative objective, repository instructions, queue, and worklog were
  reread; implementation begins with negative strict-JSON and endpoint-mode
  binding regressions. No paid provider call is authorized by this ticket.
- **Reproduced strict-JSON defects:** Added negative regressions for duplicate
  object keys and non-finite numeric constants. Before remediation,
  `.venv/bin/pytest -q
  tests/unit/test_openrouter.py::test_duplicate_json_keys_are_rejected_without_review_credit
  tests/unit/test_openrouter.py::test_nonfinite_json_number_is_rejected_without_review_credit`
  failed `2` tests: duplicate keys were accepted last-wins and `NaN` reached a
  later canonical-hash exception instead of a typed fail-closed schema
  rejection. These responses must receive no review credit.
- **Implemented checkpoint:** Added strict JSON decoding, bounded syntax-repair
  evidence, capability-adaptive output modes, exact endpoint capability
  snapshots, typed structured-output evidence, review-credit joins, and
  qualification/runtime selection bindings. The combined qualification and
  evidence matrix passed `564` tests in `31.88s`; focused endpoint-mode tests
  passed `170`; affected Ruff and strict mypy checks passed. Changes are
  intentionally uncommitted because the ticket is not complete.
- **Independent review blockers:** Before the ticket can complete, strict
  response validation must disable Pydantic coercion; non-native benchmark
  verification must compute the same protocol-augmented prompt hash as the
  provider request; and `provider.require_parameters` must bind all emitted
  endpoint-dependent parameters, including reasoning in validated-text mode.
  Each requires a negative regression and focused validation.
- **Pause checkpoint:** The operator requested a pause. All parallel workers
  were stopped after reaching a filesystem-stable checkpoint. The worktree
  contains only the in-progress V3-OUTPUT-001 implementation and tests listed
  by `git status`; no commit or push was made, no generated runtime artifact was
  claimed, and no paid provider call, network access, or secret access occurred.
- **Second resume checkpoint:** Goal continuation resumed from the preserved
  uncommitted checkpoint. The authoritative `1417`-line objective, repository
  instructions, queue, worklog, status, diff stat, and diff check were reread.
  Work remains limited to the three independent-review integrity blockers; no
  paid provider call or secret access is part of this slice.
- **Independent blocker regressions:** Strict scalar-coercion tests failed `5`
  cases before remediation and now pass after enabling strict Pydantic
  validation. The combined non-native prompt/request-parameter assay
  `.venv/bin/pytest -q
  tests/unit/test_openrouter.py::test_require_parameters_binds_all_emitted_endpoint_dependent_parameters
  tests/unit/test_openrouter.py::test_reasoning_request_profile_drift_fails_before_transport
  tests/unit/test_model_benchmark.py::test_report_verifies_protocol_augmented_non_native_prompt_binding`
  failed `4` and passed `5`: validated-text plus reasoning omitted
  `require_parameters`, reasoning-profile drift reached transport, and both
  protocol-augmented benchmark modes were rejected against the legacy raw
  prompt hash.
- **Remediation validation before pause:** Strict JSON validation now preserves
  schema-valid string enums without scalar coercion and rejects exponent
  overflow; parser tests passed `39` and consuming-path tests passed `201`.
  Protocol-augmented benchmark prompt binding, complete request-shape evidence,
  endpoint-profile drift rejection, and a discovered validated-text downgrade
  regression also pass in focused runs. Qualification fixture evidence was
  resealed against the canonical per-mode request plan and its focused tests
  passed `21`.
- **Current unresolved design item:** Discovery evidence is capability-oriented,
  but runtime reasoning must be authorized only by exact support for the
  emitted `reasoning` request parameter. On resume, derive the runtime identity
  and required-parameter profile from that exact capability without making
  discovery snapshots depend on the caller's current reasoning configuration.
  Add alias-only negative coverage before rerunning the broad matrix.
- **Operator pause:** Work is paused at a filesystem-stable, uncommitted
  `V3-OUTPUT-001` checkpoint. All delegated workers completed; no process,
  provider request, cost reservation, network access, or secret access remains
  active. The ticket is deliberately not marked complete and no checkpoint
  commit or SSH push is claimed.
- **Third resume checkpoint:** Automatic goal continuation resumed from
  synchronized commit `48d9f9d1b3606d6bd1c8167793ce9675dfbcb4f1`.
  The complete `1417`-line objective was reread and its SHA-256 reverified as
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
  The preserved worktree passes `git diff --check`. Work resumes only on the
  exact reasoning-capability/runtime-profile issue; no provider, network, or
  secret access is authorized for this slice.
- **Fourth pause checkpoint:** The exact reasoning-capability/runtime profile,
  semantic native-marker negotiation, marker-only text fallback, redundant
  routing-evidence joins, native truncation rejection, historical candidate
  registry honesty, schema synchronization, and adaptive fake-provider support
  are implemented in the preserved worktree. Focused validation passed `129`
  tests; `git diff --check` and release-schema synchronization also passed.
  Independent review identified one remaining fail-closed regression for
  unexpected fields accepted by otherwise loose Pydantic response models.
  Autorun is paused before that change. All delegated workers were stopped; no
  provider request, cost reservation, network access, secret access, commit, or
  push occurred at this checkpoint.
- **Fourth resume checkpoint:** Automatic goal continuation resumed from
  synchronized commit `48d9f9d1b3606d6bd1c8167793ce9675dfbcb4f1`.
  The complete `1417`-line objective was reread and reverified at SHA-256
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  repository instructions, queue, worklog, status, diff, and synchronized
  remote state were also rechecked. Work resumes with the outstanding
  unexpected-field rejection assay. No provider, network, or secret access is
  authorized for this ticket.
- **Unexpected-field rejection:** Five negative regressions reproduced that a
  permissive caller-supplied Pydantic response model silently discarded
  unexpected top-level or nested fields in all three output modes. Local
  validation now overrides permissive model configuration with recursive
  `extra="forbid"` validation. The same five regressions pass, followed by a
  `510`-test focused structured-output, capability, identity, provider, usage,
  benchmark, and qualification matrix in `27.12s`; no rejected response is
  creditable.
- **Evidence and truncation hardening:** Negative regressions reproduced that
  the sanitized production qualification projection and run manifest omitted
  the exact structured-output mode/capability hash, and that an identity
  mismatch could divert a response before its native truncation marker was
  checked. Public qualification evidence and per-model manifest bindings now
  carry both output fields; preservation rechecks native finish reason, labels
  truncation ahead of substitution, and emits no validated-response hash for a
  truncated response. Capability discovery now defaults to validated text
  rather than silently requiring provider-native formatting, while an explicit
  required mode remains fail-closed.
- **Operator-facing honesty:** `models list` now reports the catalog-advertised
  output mode instead of a misleading marker boolean, with exact endpoint
  discovery documented as authoritative. README and model-selection guidance
  now describe all three modes and conditional `provider.require_parameters`.
  A strict mypy defect exposed by historical candidates with unavailable
  output evidence was also narrowed fail-closed.
- **Broad local matrix:** The exact `35`-file V3-OUTPUT unit and local pipeline
  integration command passed `1096` tests in `136.34s`. This includes all output
  modes, endpoint/discovery identity, usage credit, benchmark qualification,
  assurance, report schemas, and the fake-provider pipeline. Paid-provider
  execution remained disabled.
- **Static and serialization gate:** `.venv/bin/ruff format .` reformatted `14`
  affected files; the first check exposed two import-order-only findings, which
  were safely fixed, and `.venv/bin/ruff check .` then passed. Strict mypy
  passed over `137` source files, release-schema synchronization produced no
  drift, and focused CLI, manifest, registry, and qualification-schema
  validation passed `126` tests in `5.47s`.
- **Complete local gate:** `.venv/bin/pytest -q` passed `2206` tests with `10`
  explicit external-engine, hardened-isolation, loopback, and paid-provider
  prerequisite skips in `272.93s`. The skipped paid-provider test remains
  opt-in and was not converted into a pass. No provider, network, operator
  secret, wallet, or live-chain access occurred.
- **Independent final review:** Three read-only reviews found no remaining
  fail-open review-credit bypass, output-capability/identity drift, vacuous
  qualification, truncation preservation, or serialization omission after the
  final fixes. Public production qualification and manifest evidence now expose
  the exact output mode and capability hash; operator-facing mode and
  `require_parameters` descriptions match the runtime plan.
- **Ticket result:** `V3-OUTPUT-001` is `COMPLETE` as a local implementation
  ticket. Native, JSON-object, and validated-text behavior are executed through
  deterministic local fake-provider tests; no new paid provider execution is
  claimed. The next queue-priority ticket is `V3-TOKENS-001`.
- **Validated implementation checkpoint:** Commit
  `4f04a6fd79ff96466b48bc14ddc7557bb3a809b5` contains the cohesive
  capability-adaptive output implementation, evidence projections,
  documentation, generated qualification schema, and regression matrix.

## 2026-07-29 — V3-TOKENS-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Replace equal division of one global byte pool with
  endpoint-bound token planning that reserves protocol/output space and records
  exact source, framework, prior-audit, graph, prompt, omission, and requested
  output allocations.
- **Starting state:** `V3-OUTPUT-001` is complete at implementation checkpoint
  `4f04a6fd79ff96466b48bc14ddc7557bb3a809b5`. No provider, network, paid call,
  or operator-secret access is authorized for the initial mapping and local
  regression slice.
- **Next safe action:** Inspect existing context builders, per-role byte
  division, endpoint capacity evidence, run manifests, and prompt usage
  reconciliation; then add a failing deterministic regression before changing
  production planning.
- **Pause checkpoint:** The operator requested a pause before production
  implementation began. Read-only mapping reproduced the allocation defect:
  the same specialist receives `256000` bytes with `7` planned packages but
  only `64516` bytes with `31`, solely because unrelated roles were added.
  The existing focused context, budget, and endpoint-snapshot suite passed
  `56` tests. Both remaining read-only mapping workers were stopped; no source
  or test files changed, and no provider call, network access, secret access,
  or spend occurred. The pre-pause branch was clean and synchronized with
  `origin/main` at `740a3fa696beab7d442bdb3762bc6dd67d7ec282`.
- **Resume checkpoint:** Automatic goal continuation resumed from clean,
  synchronized pause checkpoint
  `8e813c24ffb5a935e2f4a8d60e78bfede4a9983b`. The authoritative `1417`-line
  objective, repository instructions, active v3 queue/worklog state, Git status,
  and diff were reread. Implementation remains local and deterministic; this
  ticket does not authorize provider calls, network access, or secret access.
- **Permanent negative regression:** Before production changes,
  `.venv/bin/pytest -q
  tests/unit/test_context.py::test_specialist_context_budget_is_independent_of_unrelated_peer_roles`
  failed `1` test: the same `access_control` role received `256000` bytes with
  `7` planned packages and `64516` with `31`. This proves the current global
  equal-share architecture couples one review's context to unrelated roles.
- **Partial local remediation:** Removed peer-role-count coupling from context
  allocation, added exact rendered-category byte accounting, introduced typed
  endpoint-route token planning and scoped global/model/role budget evidence,
  preserved endpoint capacity-source metadata, and added request-context
  propagation call sites. The request planner and budget components are not yet
  integrated into OpenRouter request construction or emitted as a fail-closed
  context manifest, so this ticket remains `IN_PROGRESS`.
- **Focused validation:** `.venv/bin/pytest -q
  tests/unit/test_token_planning.py tests/unit/test_budgets.py
  tests/unit/test_context.py
  tests/unit/test_openrouter_qualification_config.py` passed `48` tests in
  `0.54s`. Affected Ruff checks passed after correcting two test regexes. No
  provider call, network access, secret access, generated runtime artifact, or
  spend occurred.
- **Pause checkpoint:** The operator requested a pause at the first safe
  filesystem boundary. All delegated workers are complete, the partial
  implementation is preserved, and the next action is the explicit integration
  step above. No ticket-completion or production-readiness claim is made.
- **Second resume checkpoint:** Automatic goal continuation resumed from clean,
  synchronized commit `caaaf634a03790fad8ab4d53420c88dae339c077`.
  The complete `1417`-line objective was reread and its SHA-256 reverified as
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
  Repository instructions, legacy and active queues, worklogs, Git status, and
  upstream state were rechecked. Work remains local and deterministic; no paid
  provider call, network access, or operator-secret access is authorized for
  this integration slice.
- **Integrated local checkpoint:** The endpoint-aware plan now binds exact
  endpoint-route capacity and snapshot provenance, conservative prompt-byte and
  output reservations, configured system/schema/protocol/source limits,
  OpenRouter request construction, planned-versus-actual token reconciliation,
  and lock-atomic reservation evidence. The new hash-only context manifest
  semantically joins plans, reservations, usage, omissions, report bindings,
  and generated-schema validation without persisting raw prompts or source.
- **Focused validation:** The OpenRouter and usage suite passed `228` tests; the
  planner, budget, context, and qualification-config suite passed `58`; and the
  context-manifest, run-manifest, schema, and scanner-only pipeline slice passed
  `31`. Affected Ruff checks passed, focused mypy passed before final
  compatibility adjustments, schema write/check passed, and `git diff --check`
  passed.
- **Known incomplete integration:** The successful fake-provider pipeline probe
  remains fail-closed because its test helper constructs the budget manager and
  client without the new configured global token limits. Runtime preflight
  rejection recording and complete retry-attempt reservation inventory also
  remain to be integrated; no evidence is fabricated and no maximum-assurance
  credit is claimed.
- **Pause checkpoint:** The operator requested a pause. Both delegated workers
  stopped at a filesystem-stable boundary with no command or edit in flight.
  `V3-TOKENS-001` remains `IN_PROGRESS`; no provider call, network access,
  operator-secret access, new spend, or ticket-completion claim occurred.
  Implementation checkpoint `b987a547dad8249fab1ee15b1a8baa1f5200831b`
  preserves the exact resumable state and the operator-appended queue scope.
- **Third resume checkpoint:** Automatic goal continuation resumed from clean,
  synchronized pause-state commit
  `c7f631bfa69f525658e49537cfd542d0c93b2cc4`. The authoritative `1417`-line
  objective was reread and reverified at SHA-256
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  repository instructions, legacy and active queue state, worklogs, Git status,
  and upstream state were rechecked. Work resumes only on local deterministic
  V3-TOKENS integration; no provider, network, paid call, or operator-secret
  access is authorized for this slice.
- **Retry and preflight evidence checkpoint:** Provider retries now retain an
  exact ordered inventory of lock-atomic token reservations, distinguish
  provider attempts from preflight reservation rejection, and require strict
  request/model/role/plan/limit joins before usage or review credit. A
  thread-safe runtime preflight ledger records hash-only typed planner and
  budget rejection evidence without raw prompt, source, or exception content.
  Context manifests, reports, and run-manifest reconstruction bind the complete
  reservation and preflight inventories, including conservative
  attempt-reserved token totals. The fake-provider integration now uses the
  configured global/model/role token budgets and validates the emitted context
  artifact semantically.
- **Checkpoint validation:** `.venv/bin/pytest -q
  tests/unit/test_usage.py tests/unit/test_openrouter.py
  tests/unit/test_context_manifest.py` passed `300` tests in `1.15s`.
  `.venv/bin/pytest -q
  tests/integration/test_pipeline.py::test_successful_multi_agent_audit
  tests/unit/test_release_schemas.py tests/unit/test_manifest.py` passed `16`
  tests in `1.61s`. `.venv/bin/ruff check
  src/mmaudit/models/openrouter.py src/mmaudit/models/usage.py
  src/mmaudit/orchestration/context_manifest.py
  src/mmaudit/orchestration/manifest.py
  src/mmaudit/orchestration/pipeline.py tests/identity_fixtures.py
  tests/integration/test_pipeline.py tests/unit/test_context_manifest.py
  tests/unit/test_openrouter.py tests/unit/test_usage.py` passed.
  `.venv/bin/mypy src/mmaudit/models/openrouter.py
  src/mmaudit/models/usage.py
  src/mmaudit/orchestration/context_manifest.py
  src/mmaudit/orchestration/manifest.py
  src/mmaudit/orchestration/pipeline.py` passed with no issues.
  `.venv/bin/python scripts/generate_release_schemas.py --write` and
  `.venv/bin/python scripts/generate_release_schemas.py` passed, as did
  `git diff --check`. The generated context manifest schema is synchronized.
- **Operator pause:** The operator requested a pause at this safe boundary.
  All delegated workers and validation processes are complete. No provider
  request, network access, paid call, cost reservation, or operator-secret
  access occurred. `V3-TOKENS-001` remains deliberately `IN_PROGRESS`: the
  complete fake-provider pipeline suite, broader validation matrix, independent
  final cross-artifact review, full required suite, and final ticket evidence
  updates have not yet run. Implementation checkpoint
  `5a675a1a75925febfc2031c17fd61ae6bbcb64ae` preserves the resumable source,
  schema, and test state without claiming ticket completion.
- **Fourth resume checkpoint:** Automatic goal continuation resumed from clean,
  synchronized pause commit
  `ffb0c2ca46fd19630f58032cd5d96a60bb3e6861`. The complete authoritative
  objective, repository rules, legacy queue/worklog state, active v3 queue
  including the operator-appended revised sequence, current v3 worklog, Git
  status, and upstream state were rechecked. The objective SHA-256 remains
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
  Work resumes with the remaining local V3-TOKENS validation and independent
  review only; no provider, network, paid call, cost reservation, or
  operator-secret access is authorized for this slice.
- **Independent review findings:** Three completed read-only reviews identified
  fail-open accounting gaps in endpoint prompt-capacity estimation, actual
  usage reconciliation, preflight failure classification, conservative source
  allocation without an exact tokenizer, and the model-visible chat envelope.
  Existing retry/reservation inventory and cross-artifact pipeline joins
  otherwise remained coherent under focused deterministic probes.
- **Local remediation checkpoint:** Endpoint capacity and atomic reservations
  now use a frozen conservative upper bound over the complete model-visible
  UTF-8 request envelope plus an explicit framing reserve. Context source
  allocation uses a one-byte-per-token conservative bound without an exact
  tokenizer. Typed planning failures retain global-budget, context-plan, route,
  and endpoint-capacity distinctions. Completed usage evidence is rejected when
  actual prompt, completion, or total usage exceeds its frozen plan or endpoint
  limits. Negative regressions cover each unsafe condition.
- **Pause validation:** `.venv/bin/python
  scripts/generate_release_schemas.py --write` regenerated the context-manifest
  schema. The focused token/context/manifest/usage/OpenRouter suite passed `327`
  tests in `1.47s`; affected Ruff checks, schema synchronization, and
  `git diff --check` passed. No provider call, network access, operator-secret
  access, cost reservation, or spend occurred.
- **Operator pause:** Autorun is paused at a filesystem-stable
  `V3-TOKENS-001` checkpoint. All delegated workers and validation processes are
  complete. The ticket remains `IN_PROGRESS`; complete fake-provider pipeline
  validation, the broader matrix, independent closure review, full repository
  gates, and final queue/traceability/runtime evidence remain intentionally
  pending.
- **Validated implementation checkpoint:** Commit
  `39fb4392f3dfcf06f2f92dd79bc5bc3563432b49` preserves the conservative
  prompt-envelope planning, typed preflight classification, actual-usage
  fail-closed checks, generated schema, regressions, and exact resumable pause
  state without claiming ticket completion.
- **Fifth resume checkpoint:** Automatic goal continuation resumed from clean,
  synchronized state commit
  `5f52bb0eb19a19c43e2ea480fb8563e4109df5b7`. The authoritative `1417`-line
  objective was reread and reverified at SHA-256
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  repository instructions, active queue sequencing, worklog, Git status, and
  upstream state were rechecked. Work resumes with local deterministic
  V3-TOKENS closure only; no provider request, secret access, paid call, or
  additional spend is authorized for this validation slice.
- **Sixth operator pause checkpoint:** The operator requested a pause after the
  endpoint-aware source/total-package separation and explicit output-allocation
  regressions reached a filesystem-stable checkpoint. The focused token/context
  suite passes `25` tests. The maximum-assurance fake-provider regression now
  retains its expected findings and confirmations, but remains failing because
  `specialist:report_quality` bypasses endpoint-aware context construction and
  is correctly rejected before transport for endpoint capacity. Three
  independent read-only reviews are complete and no worker or validation
  process remains active. The nine modified files shown by `git status` preserve
  uncommitted in-progress work; no commit, push, generated runtime artifact,
  provider request, network access, secret access, cost reservation, or spend
  occurred. `V3-TOKENS-001` remains `IN_PROGRESS`.
- **Sixth resume checkpoint:** Automatic goal continuation resumed from the
  preserved nine-file V3-TOKENS worktree at source commit
  `5f52bb0eb19a19c43e2ea480fb8563e4109df5b7`. The complete authoritative
  objective was reread and its SHA-256 remains
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  queue sequencing, worklog, current diff, and whitespace integrity were
  rechecked. Work resumes only on local deterministic ticket closure. No
  provider, network, paid call, cost reservation, or operator-secret access is
  authorized for this slice.
- **Endpoint-aware report-quality closure:** Report-quality review now prepares
  and hashes its exact workflow before context construction, reserves the
  greater of the configured and measured workflow bounds, and reuses the exact
  prepared workflow at execution. Drift is rejected before transport. The
  maximum-assurance fake-provider regression passed `1` test in `5.41s` after
  role-specific metadata compaction preserved the invariant symbol index.
- **Output-capacity closure:** Token planning now records typed finding,
  coverage, and summary minimums, conserves the requested output allocation,
  and rejects endpoint routes without an explicit metadata-backed completion
  limit. Focused token-planning and context-manifest validation passed `80`
  tests; usage validation passed `81`.
- **Partial-preflight evidence:** Added a self-hashed diagnostic planning
  snapshot that retains only measured route, prompt-allocation,
  output-allocation, envelope, demand, and omission evidence when a complete
  request plan cannot be formed. It is mutually exclusive with a full plan,
  receives zero review, reservation, provider-request, or planned-request
  credit, and is required for planless token-planner rejection. Focused
  snapshot coverage passed `83` tests; the broader OpenRouter,
  context-manifest, and usage matrix passed `311`.
- **Static validation so far:** Affected Ruff and strict mypy checks passed
  after the report-quality closure. The example configuration and its tests now
  expose and bound `reserved_workflow_tokens = 32768`.
- **Seventh operator pause checkpoint:** The operator requested a pause at this
  filesystem-stable boundary. Three delegated read-only reviewers are complete.
  The worktree preserves `16` modified files and one new focused test file; no
  commit or push is claimed because `V3-TOKENS-001` is still `IN_PROGRESS`.
  Category-specific omission evidence, large-metadata pressure coverage,
  persisted nonzero category allocation evidence, a high-capacity
  ContextBuilder-to-manifest regression, operator documentation, schema
  regeneration, full static and pytest gates, and final queue/traceability/
  runtime-state updates remain pending. No provider request, network access,
  secret access, cost reservation, generated runtime claim, or additional
  spend occurred.
- **Seventh resume checkpoint:** Goal continuation resumed from source commit
  `5f52bb0eb19a19c43e2ea480fb8563e4109df5b7`. The authoritative objective was
  reread completely and its SHA-256 remains
  `f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`;
  repository instructions, active queue sequencing, status, diff, and
  whitespace integrity were rechecked.
- **Typed omission closure:** Context packages now retain only self-hashed,
  category- and reason-bound omission records. Host construction assigns each
  category at the omission origin; OpenRouter no longer guesses from strings or
  accepts an unknown fallback. Full plans, diagnostic partial snapshots, usage,
  and manifests bind the same exact inventory, while blind prior-audit
  withholding remains separate. Raw omitted paths and detail do not persist.
- **End-to-end acceptance coverage:** Added deterministic pressure coverage
  proving oversized framework, graph, scanner, and invariant metadata compacts
  before coherent source is exhausted; a serialized manifest preserves nonzero
  semantic category allocations and zero prior-audit allocation; and a
  high-capacity ContextBuilder-to-fake-OpenRouter-to-manifest flow proves an
  approximately 200,000-token estimate with a 32,768-token visible-output
  reserve. The three acceptance tests passed in `0.59s`.
- **Schema and focused validation:** The stale context-manifest schema was
  reproduced, regenerated, and verified current. Typed omission/context tests
  passed `260`; the broader token, context, OpenRouter, usage, specialist,
  manifest, schema, and selected pipeline matrix passed `368` in `9.24s`.
  Affected Ruff and strict mypy passed. No provider, network, secret, paid call,
  cost reservation, or new runtime claim occurred.

## 2026-07-28 — V3-SMOKE-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Complete one strictly routed, identity-bound,
  non-truncated structured response against only the committed bounded synthetic
  Solidity fixture, with reconciled cost and a non-secret evidence artifact.
- **Starting evidence:** The operator-gated integration harness and fixture
  preparation are preserved locally; the paid test remains disabled by default.
  Historical spend is `0.00118674 USD`, with no reservation and no successful
  response credited.
- **Next safe action:** Review and test every local gate before explicitly loading
  the operator-controlled secret file or enabling network access.
- **Reproduced regression:** Before implementation,
  `.venv/bin/pytest -q tests/unit/test_real_provider_harness.py` failed during
  collection because the typed smoke-evidence contract and sink did not exist.
- **Local remediation:** Added a pinned descriptor-safe read of the committed
  synthetic Solidity fixture, a fresh-path preflight, a self-hashed typed success
  artifact, mode-`0600` descriptor-safe JSON write/readback, credential/path/source
  canary scans, explicit `STRICT_ZDR` and real-execution evidence, canonical
  identity/provider assertions, independent generation evidence, and exact atomic
  ledger reconciliation under a `5 USD` smoke-stage ceiling.
- **Verification subject:** Replaced the placeholder generation-binding hash with
  a canonical hash of the actual fixture, request/generation IDs, exact/canonical
  model IDs, validated-response hash, prompt/schema hashes, endpoint snapshot, and
  discovery evidence.
- **Focused evidence:** The secret, ledger, discovery, generation, usage,
  OpenRouter, release-I/O, harness, and gated-integration subset passed `334` tests
  with one explicit paid-provider skip in `1.25s`; the expanded pinned-fixture and
  output-preflight subset passed `81` with the same skip. Affected Ruff and strict
  mypy passed.
- **Provider state:** No provider request or metadata fetch has run in this ticket.
  Spend remains `0.00118674 USD`, reservations remain zero, and no successful
  response is credited.
- **Next safe action:** Complete independent pre-spend review, commit the clean
  harness/fixture checkpoint, then run the one explicitly gated synthetic call
  only from that exact checkpoint.
- **Independent pre-spend acceptance:** Final read-only review found no material
  local blocker after enforcing the exact pinned fixture hash, recomputing the
  verification-subject hash from artifact fields, and treating optional generation
  reasoning/cached metadata as optional. The reviewer independently passed `334`
  tests with one paid skip and confirmed affected Ruff and diff checks.
- **Exact pre-call complete suite:** `.venv/bin/pytest -q` passed `1868` tests and
  skipped `10` explicit external/provider/isolation prerequisites in `243.36s`.
  The real provider smoke remained disabled.
- **Explicit privacy correction:** The paid harness now requires the independent
  non-secret prerequisite
  `MMAUDIT_REAL_PROVIDER_PRIVACY_PROFILE=STRICT_ZDR`; an implicit hardcoded route
  alone cannot enable provider access. The corrected focused provider/security
  subset passed `295` tests with one paid skip; Ruff, strict mypy, and diff checks
  passed.
- **Paid-call launch preflight:** Clean synchronized `main` at
  `b45a6e19ebf648e6bb5919ed4349e86cf32ca97a`; implementation checkpoint
  `d2a54d9d3d57b89f6abeb567caaad7719eb74f96`; fixture and evidence directory are
  committed; the destination is absent; the operator secret is a regular
  non-writable-by-group/world file; and the existing atomic ledger reports
  `cap=250.00`, `spent=0.00118674`, `reserved=0`, `remaining=249.99881326`,
  two entries, no over-cap state, and no reservation overrun.
- **Real-provider preflight outcome:** The explicitly gated integration command
  failed in `2.41s` before a completion request. Authenticated credential
  validation and the exact-model catalog lookup succeeded. The subsequent
  single-model metadata GET for the catalog-resolved canonical slug returned
  HTTP `404`, so no completion POST occurred and no provider response was
  credited.
- **Post-failure evidence:** The expected runtime artifact remains absent. The
  atomic ledger still contains exactly two historical
  `UNCERTAIN_ACCOUNTED` entries with `spent=0.00118674 USD`, `reserved=0`, and
  `remaining=249.99881326`; Git remains clean and synchronized at
  `6a24f119334f6e7552141361944f6d3aed3c76ce`. This metadata-route failure is not
  counted as a paid model-call attempt.
- **Operator pause:** Autorun is paused at a clean boundary. No process or
  reservation is active. On resume, confirm the current official OpenRouter
  single-model metadata route, reproduce the `404` with a local regression,
  correct the confirmed route defect, and re-run local gates before considering
  one materially changed provider attempt.
- **Resume diagnosis:** Official OpenRouter API references confirm that the
  single-model route remains singular,
  `/api/v1/model/:author/:slug`; the endpoints route remains plural. The
  preflight defect is therefore not the route shape. The client queried the
  route using a catalog-resolved dated `canonical_slug` that returned `404`,
  while the catalog `id` is the documented API model ID. The remediation is to
  query by the exact requested/catalog ID and independently validate and bind
  the returned canonical slug.
- **Independent route assay:** Credential-free status-only GETs returned HTTP
  `200` for `/api/v1/model/qwen/qwen3.6-35b-a3b` and HTTP `404` for
  `/api/v1/model/qwen/qwen3.6-35b-a3b-20260415`. No response body, secret, or
  completion request was used.
- **Negative regression:** A benchmark-client fixture now returns `404` unless
  single-model metadata is queried with the exact catalog ID while returning a
  distinct dated canonical slug in the validated response. Before the source
  correction,
  `test_candidate_benchmark_uses_exact_mock_certification_route` failed with
  `UNVERIFIED` evidence; after the correction it passes.
- **Local correction:** CLI discovery/benchmark, pipeline discovery, candidate
  qualification, smoke integration, and trusted provenance sealing now query
  `/model/:author/:slug` with the exact requested/catalog ID. The response's
  independently validated canonical slug remains frozen in discovery evidence;
  the binding rejects a provenance query made with that canonical slug.
- **Focused validation:** The exact three-test route regression passed; affected
  Ruff passed; strict mypy reports no issues in `129` source files; release
  schema generation produced no drift; and the expanded discovery, provider,
  candidate, qualification, CLI, pipeline, and gated integration subset passed
  `335` tests with one explicit paid-provider skip in `74.05s`.
- **Complete local validation:** `.venv/bin/pytest -q` passed `1872` tests and
  skipped `10` explicitly gated paid-provider, external-engine, isolation, and
  loopback prerequisites in `252.25s`. `.venv/bin/ruff format .` left `297`
  files unchanged, `.venv/bin/ruff check .` passed, strict mypy passed all
  `129` source files, and `git diff --check` passed. The provider artifact
  remains absent and the atomic ledger remains exactly
  `spent=0.00118674`, `reserved=0`, `remaining=249.99881326`, two entries.
- **Independent acceptance review:** A read-only reviewer found no missed
  production caller: CLI discovery, CLI benchmark, candidate benchmark, audit
  pipeline, and the gated smoke all query with the requested/catalog ID.
  Provenance independently binds the returned canonical slug. The reviewer
  passed the three focused route regressions in `0.35s` and made no edit,
  network request, secret access, or paid call.
- **Corrected source checkpoint:**
  `8004dd7662ca521565db1d87cd3e76d8678cf44b`.
- **Second launch preflight:** Clean synchronized `main` at
  `38ed5e07bf746e91fbe9958527d82d2f19a7d8f3`, source checkpoint
  `8004dd7662ca521565db1d87cd3e76d8678cf44b`; the explicit operator secret is a
  regular, non-writable-by-group/world file; the evidence destination is absent;
  exact model and endpoint-metadata URLs return HTTP `200`; and the ledger
  remains `cap=250.00`, `spent=0.00118674`, `reserved=0`,
  `remaining=249.99881326`, two entries, with no over-cap or reservation-overrun
  state.
- **Second launch outcome:** Exactly one completion POST ran. OpenRouter returned
  generation `gen-1785255808-bjFsZT1Hmk04U4Edm3tB` for the exact requested
  model, but its only choice had `finish_reason=length` and no content. The
  client raised `OpenRouterTruncatedResponseError`; the response earned no
  schema, review, identity, or success credit and no runtime artifact was
  emitted.
- **Cost reconciliation:** The third ledger entry is `RECONCILED` with
  `reserved=0.00084758 USD`, `actual=0.00054756 USD`, and
  `accounted=0.00054756 USD`. Aggregate spend is now `0.00173430 USD`,
  active reservation is zero, remaining budget is `249.99826570 USD`, and no
  over-cap or reservation-overrun state exists.
- **No-progress guard:** The truncated request will not be retried unchanged.
  Before another POST, add a local regression that distinguishes total
  reasoning/output exhaustion from sufficient bounded answer space and make a
  materially different, evidence-backed token/reasoning configuration.
- **Content-free generation diagnosis:** The first diagnostic command failed
  locally before secret loading because it referenced the wrong loader module;
  the corrected explicit-loader command made only authenticated metadata GETs.
  Frozen generation evidence reports `prompt_tokens=211`,
  `completion_tokens=506`, `reasoning_tokens=506`, `cached_tokens=0`,
  `finish_reason=length`, provider `AkashML`, canonical model
  `qwen/qwen3.6-35b-a3b-20260415`, and cost `0.00054756 USD`. This proves the
  entire completion budget was consumed by reasoning.
- **Capability evidence:** Current public exact-model metadata reports
  `reasoning.mandatory=false`, `reasoning.default_enabled=true`, and omits
  `reasoning.supports_max_tokens`. OpenRouter's official reasoning reference
  defines `effort=none` as reasoning disabled. The prior
  `reasoning.max_tokens=64` control was therefore not supported by this model
  and was not an adequate answer-space guarantee.
- **Bounded remediation:** The smoke now requires exact catalog proof that
  reasoning is optional, sends `reasoning={effort:none, exclude:true}`, reserves
  `1024` output tokens, and will reject success evidence unless observed
  reasoning tokens are zero. Its artifact records the requested reasoning/output
  controls and the catalog capability fields.
- **Local remediation validation:** The optional-reasoning capability matrix,
  explicit-off request payload, config parsing, evidence reconciliation, and
  gated integration subset passed `168` tests with one paid-provider skip in
  `0.70s`; affected Ruff and strict mypy passed.
- **Expanded local validation:** The provider, discovery, candidate,
  qualification, CLI, pipeline, harness, and gated integration subset passed
  `388` tests with one explicit paid-provider skip in `69.10s`.
- **Complete local validation:** `.venv/bin/pytest -q` passed `1879` tests and
  skipped `10` explicitly gated paid-provider, external-engine, isolation, and
  loopback prerequisites in `230.28s`. Full Ruff left `297` files unchanged
  and passed; strict mypy passed `129` source files; release schema generation
  produced no drift; `git diff --check` passed. The success artifact remains
  absent and the reconciled ledger remains `spent=0.00173430`,
  `reserved=0`, `remaining=249.99826570`, three entries.
- **Independent pre-spend correction:** A read-only reviewer demonstrated that a
  synthetic success artifact could claim `completion_tokens=1025` while
  declaring a `1024` requested ceiling. Evidence coherence now requires
  `completion_tokens <= requested_max_output_tokens`, and the negative
  regression passes in a `47`-test focused harness suite. No production privacy,
  identity, cost, or fail-closed control was weakened.
- **Post-review complete validation:** `.venv/bin/pytest -q` passed `1879`
  tests with the same `10` explicit prerequisite skips in `228.56s`; full Ruff
  and strict mypy passed. The expected success artifact remains absent and the
  ledger remains `spent=0.00173430`, `reserved=0`,
  `remaining=249.99826570`, three entries.
- **Reasoning/output checkpoint:**
  `432cfd0c0b976939c05abe2df1fe8eb8673fb107`.
- **Third launch preflight:** Clean synchronized `main` at
  `abef98c2bd4c5761bdca3b7f3727efe08d82d304`, source checkpoint
  `432cfd0c0b976939c05abe2df1fe8eb8673fb107`; artifact absent; operator secret
  regular and non-writable-by-group/world; exact model and endpoint metadata
  return HTTP `200`; current reasoning metadata remains
  `mandatory=false`, `default_enabled=true`; ledger remains
  `spent=0.00173430`, `reserved=0`, `remaining=249.99826570`, three entries,
  no over-cap or reservation-overrun state.
- **Third launch outcome:** Exactly one materially changed completion POST ran
  from synchronized checkpoint
  `fa0dcf6e38a963962f780230359f3ac28ce9050a`, with reasoning explicitly disabled
  and a `1024`-token output ceiling. The provider returned schema-valid structured
  output, but post-generation identity binding concluded `UNBOUND`. The
  compatibility wrapper raised `OpenRouterUnboundIdentityError`; no review,
  identity, certification, or success credit was granted and no success artifact
  was emitted.
- **Cost reconciliation:** The fourth ledger entry,
  `c93f28a5-49b4-40ab-8c9b-531a4b70af6b:attempt:1`, is `RECONCILED` with
  `reserved=0.00135972 USD`, `actual=0.00006484 USD`, and
  `accounted=0.00006484 USD`. Aggregate spend is `0.00179914 USD`, active
  reservation is zero, remaining budget is `249.99820086 USD`, and no over-cap
  or reservation-overrun state exists.
- **Pause boundary:** Autorun is paused at the operator's request. Git was clean
  and synchronized before this state-only update; the expected success artifact
  remains absent and no process or reservation is active. The rejected completion
  must not be retried unchanged. On resume, first make unbound completion
  diagnostics durably available without granting credit, then isolate and
  reproduce the identity mismatch locally before another provider request.

## 2026-07-28 — V3-BASELINE-001

- **Status:** `COMPLETE`
- **Starting state:** Clean `main` at
  `6465bb5824903180f2fc631663ab327993c36a20`, matching `origin/main`.
- **Preserved evidence:** Historical paid spend is `0.00118674 USD`; both prior
  completion attempts were rejected and remain uncredited.
- **Commands and results:**
  - Read the complete authoritative objective and verified its SHA-256.
  - Read `AGENTS.md`, current remediation queue/worklog, Git status, and full diff.
  - `git status --short --branch` — PASS; clean and synchronized.
  - `git diff --stat && git diff --check && git diff` — PASS; no diff.
  - `.venv/bin/pytest -q` — PASS; `1799 passed, 10 skipped in 226.05s`. Every
    skip names an explicit paid-provider, external-engine, isolation, or sandbox
    prerequisite.
  - `.venv/bin/python scripts/generate_release_schemas.py` — PASS; all committed
    generated release schemas exactly match current typed models.
  - A first focused pytest selector used one stale/nonexistent node name and exited
    `4` before collection; no product test ran. The corrected focused command
    `.venv/bin/pytest -q tests/unit/test_release_schemas.py
    tests/unit/test_release_report.py
    tests/unit/test_release_artifacts.py::test_published_release_artifact_schema_matches_typed_contract`
    passed `8` tests in `0.31s`.
  - **Reported-failure disposition:** The two externally reported release-schema
    failures are `NOT_REPRODUCIBLE_AT_6465BB5`; current generated-schema
    verification, focused schema/report tests, and the entire suite pass. No
    failure was manufactured and no threshold was weakened.
  - `.venv/bin/ruff format .` — PASS; `294 files left unchanged`.
  - `.venv/bin/ruff check .` — PASS; all checks passed.
  - `.venv/bin/mypy` — PASS; strict checking succeeded for `128` source files.
  - Final `.venv/bin/pytest -q` — PASS; `1799 passed, 10 skipped in 217.18s`.
- **Result:** `COMPLETE`; the exact current candidate is green. The review's two
  schema defect classes were already resolved by checkpoint `559e187`: the stale
  legacy release-report schema was regenerated and seven missing typed release
  evidence schemas were committed. The pre-fix dirty snapshot was not retained, so
  only one historical failing pytest node can be reproduced exactly; no second node
  is invented.
- **Checkpoint commit:** `5ea145302520cc295eb551eb74a623e1471e98d3`.
- **Next safe action:** Checkpoint the v3 ledgers, then implement
  `V3-IDENTITY-001`.

## 2026-07-28 — V3-IDENTITY-001

- **Status:** `IN_PROGRESS`
- **Defensive objective:** Classify and seal canonical model/provider endpoint
  identity while retaining valid structured output that remains unbound and
  ineligible for review credit.
- **Starting evidence:** Frozen model and endpoint snapshots plus fresh generation
  refetch exist. Raw requested/returned string equality still rejects legitimate
  canonical aliases; identity strength and durable `UNBOUND` evidence are absent.
- **Next safe action:** Add the failing canonical-alias, endpoint-variant,
  generation-binding, and unbound-retention regression matrix before changing the
  provider implementation.

### Operator pause checkpoint

- **Autorun state:** `PAUSED_BY_OPERATOR`.
- **Preserved work:** Typed identity snapshots and bindings, canonical-alias
  handling, generation-evidence joins, certification-credit checks, focused
  regressions, and the partially edited opt-in real-provider smoke harness remain
  in the working tree.
- **Latest validated slice:** The broader identity/provider unit subset passed
  `353` tests; affected Ruff and strict mypy checks passed before the latest
  smoke-harness edits.
- **Unvalidated slice:** The latest smoke-harness edits and the complete current
  diff still require formatting, focused tests, strict typing, and final review.
- **Provider state:** No paid request was launched during this slice; aggregate
  spend remains `0.00118674 USD`, reserved spend is `0.00 USD`, and no response is
  credited.
- **Resume action:** Finish the explicit non-secret runtime evidence artifact and
  post-generation identity binding in
  `tests/integration/test_real_openrouter_provider.py`, validate
  `V3-IDENTITY-001`, and create its isolated checkpoint commit before
  `V3-SMOKE-001`.

### Implemented identity slice

- Added typed, frozen, self-hashed identity snapshots and binding results with
  explicit `IMMUTABLE_VERSION_BOUND`,
  `CANONICAL_MODEL_AND_ENDPOINT_BOUND`, and `UNBOUND` states.
- Exact and canonical aliases are frozen together; unrelated same-author and
  cross-author metadata, model, provider, endpoint-variant, generation-ID,
  generation-model, generation-provider, fallback, expiry, and execution-origin
  mismatches fail closed.
- All completion records remain `UNBOUND` until generation metadata is fetched.
  Exact returned slugs no longer bypass the post-generation gate.
- A schema-valid response whose identity fails is retained with bounded
  diagnostics and hashes but receives no model-review or certification credit.
- Publicly fabricated generation objects cannot upgrade `REAL` usage. The owned,
  authenticated, transport-pristine client path performs the trusted upgrade and
  atomically replaces only the matching provisional ledger record.
- OpenRouter endpoint identity is explicitly represented as policy-constrained
  rather than a cryptographic endpoint-ID or provider-build attestation.
- Unit fixtures that previously relabelled mock records as `REAL` were repaired
  with explicit test-only synthetic bindings; production evidence gates were not
  weakened.
- **Focused validation:** `524 passed`; affected strict mypy passed. Full-suite
  validation is the next command.
- **First complete-suite attempt:** `1824 passed, 7 failed, 10 skipped in
  224.72s`. The failures were all legacy unit fixtures outside the focused set
  that represented unbound synthetic data as `REAL`; there was no production
  regression. Those fixtures now use explicit test-only bindings, while the
  relabelled-mock negative assay fails earlier during report validation. The
  corrected 59-test benchmark/model-coverage subset passes.
- **Post-review correction:** A production-call-site review found that the first
  implementation required bound REAL usage but left normal audit and benchmark
  callers on the provisional completion path. The central REAL completion path
  now requires an authenticated owned client plus frozen identity metadata before
  transport and performs trusted generation binding before returning. A second
  review finding showed that failed generation binding left the ledger in a
  misleading pending state; the concluded self-hashed `UNBOUND` evidence and its
  bounded diagnostics are now retained without earning credit.
- **Post-review focused validation:** The exact identity, OpenRouter, usage,
  generation, qualification, assurance, candidate-benchmark, review-evidence,
  and pipeline subset passed `612 passed in 84.51s`.
- **Final focused validation before operator pause:** The expanded command recorded
  in `LAST_COMMAND` passed `620` tests in `83.78s`. Independent re-review found no
  remaining blocker in the exact-endpoint routing or concluded-unbound
  generation-evidence paths. The current tree has not yet received its final full
  suite, formatting, strict typing, identity-only diff review, or checkpoint
  commit.
- **Pause state:** `PAUSED_BY_OPERATOR` at a safe validation boundary. No command
  is running, no paid provider request was launched, no response was credited,
  and aggregate spend remains `0.00118674 USD`.
- **Resume action:** Run the complete current-tree suite, affected formatting and
  static checks, review and checkpoint only the identity slice, then begin
  `V3-SMOKE-001`.
- **Resumed complete-suite evidence:** `.venv/bin/pytest -q` passed `1835` tests
  with `10` explicit external/prerequisite skips in `250.99s`. This is retained as
  intermediate evidence only because independent review subsequently identified
  and the implementation corrected an unbound-alias credit gap.
- **Final review correction:** A self-hashed snapshot could previously add an
  arbitrary same-author or cross-author slug to `frozen_aliases`, after which
  bound validation trusted membership alone. Snapshot validation now requires the
  requested and canonical authors to match the frozen author and permits exactly
  the catalog-bound requested/canonical pair. Negative snapshot and REAL-credit
  regressions distinguish the former unsafe condition. The focused identity and
  usage tests pass `59 passed in 0.07s`; affected Ruff passes and strict mypy
  reports no issues in `129` source files. The finding author independently
  reproduced the corrected fail-closed result.
- **Second complete-suite attempt:** `.venv/bin/pytest -q` passed `1837` tests,
  skipped the same `10` explicit external prerequisites, and failed `2` tests in
  `268.82s`. One failure was a state-ordering minimization assertion that passed
  immediately in isolation (`1 passed in 9.53s`) without a source change. The
  other exposed a legacy negative fixture that attempted to seal a cross-author
  canonical mismatch; the fixture now uses a coherent same-author mismatch so
  the downstream qualification gate, rather than identity construction, performs
  the intended rejection.
- **Runtime-provenance correction:** A second independent review showed that
  self-hashed JSON proves consistency but cannot establish that a completion came
  from the owned authenticated transport. REAL usage now carries a private,
  non-serialized, content-bound runtime capability issued by the owned provider
  path. Mutation or JSON reconstruction revokes live credit. Bound/unbound ledger
  replacement verifies the provisional capability and atomically reissues it for
  the exact concluded record.
- **Persisted-evidence correction:** The first capability implementation made
  persisted benchmark evidence operationally impossible and caused an expanded
  focused run to fail `100` tests while `526` passed. Structural persisted-record
  validation is now separate from live REAL credit. Serialized reports may be
  schema- and hash-validated, but production qualification still requires the
  existing opaque, freshly authenticated `TrustedGenerationVerification` and
  `VerifiedProductionQualification` capabilities. The generation suite passes
  `45` tests; qualification/workflow/portfolio/coverage passes `118`; the final
  expanded identity/benchmark/pipeline command passes `626` tests in `83.97s`.
  Arbitrary in-process Python execution is not presented as contained by this
  capability; repository-controlled code remains prohibited from execution.
- **Final static evidence before complete suite:** Identity-scope Ruff formatting
  and checks pass, strict mypy reports no issues in `129` source files,
  `.venv/bin/python scripts/generate_release_schemas.py` produces no drift, and
  `git diff --check` passes.

### 2026-07-28 operator pause checkpoint

- **Autorun state:** `PAUSED_BY_OPERATOR` at a safe boundary; no command or
  sub-agent is running.
- **Latest execution evidence:** The complete current-tree suite passed
  `1841 passed, 10 skipped in 288.49s`. This is intermediate evidence only:
  independent review subsequently identified three architectural gaps not
  covered by that suite.
- **Unresolved identity blockers:** Candidate benchmark joins incorrectly compare
  serialized and live Pydantic records including private runtime attributes;
  persisted benchmark-certificate evaluation has no trusted bridge for
  runtime-only model evidence; and authenticated generation metadata does not
  bind original response content, allowing structurally rewritten benchmark
  content to seek qualification.
- **Required resume work:** Add an opaque original-live-content campaign binding,
  compare canonical public record projections while independently requiring the
  live runtime attestation, keep persisted-only qualification fail-closed, and
  add the corresponding negative regressions. Re-run focused checks,
  independent review, static validation, and the full suite before checkpointing
  `V3-IDENTITY-001`.
- **Provider state:** No paid request was launched during this slice; aggregate
  spend remains `0.00118674 USD`, reserved spend is `0.00 USD`, and no response
  is credited.
- **Preservation:** All incomplete identity work and the separate unfinished
  `V3-SMOKE-001` harness edits remain uncommitted in the working tree. No commit
  or push was made from this unvalidated state.

### Live-content trust-boundary correction

- Canonical public JSON projections now join live and serialized usage records
  without treating Pydantic private attributes as report data. Any changed public
  field still rejects, and serialized REAL records do not regain runtime credit.
- Persisted structurally coherent REAL benchmark evidence retains nonzero
  denominators but is `NOT_EVALUABLE` when the process-local execution authority
  is absent. Invalid, mock, failed, ambiguous, or mismatched evidence remains an
  evaluated failure.
- Candidate campaign files now validate structure only. A separate opaque,
  noncopyable, nonserializable capability is issued only by the original complete
  in-memory campaign and binds the exact portfolio, policy, effective
  configuration, and complete canonical report content.
- Qualification without that capability produces `INCONCLUSIVE`; a caller-forged
  capability is rejected. Production qualification cannot mint authority without
  it. Disk-only audit loading fails before generation refetch, preventing paid
  work that could not produce production authority.
- A negative regression reproduces the independently reported condition: an
  original report scoring below the self-consistent rewritten report has identical
  generation attestations, but the original live-content capability rejects the
  rewritten report.
- **Focused evidence:**
  - Candidate usage join: `15 passed in 0.79s`; Ruff, formatting, strict mypy,
    and diff checks passed.
  - Benchmark model evidence and related certificate suite: `59 passed in
    0.65s`; Ruff and strict mypy passed.
  - Qualification workflow and production resolution: `84 passed in 12.59s`.
  - Live campaign, resumed-journal, and disk-only audit regressions: `86 passed
    in 13.93s`.
- **Provider state:** No paid request ran; total recorded spend remains
  `0.00118674 USD`, with `0.00 USD` reserved and no successful response credited.

### Valid-but-unbound response retention correction

- REAL schema-valid completions whose post-call generation metadata is missing or
  mismatched are now returned to evidence-aware callers as concluded `UNBOUND`
  evidence instead of being discarded or advancing automatically to another host
  model.
- Value-only and bound-identity callers fail closed with a typed exception that
  retains the completion in memory while keeping its content out of exception text
  and formatted tracebacks.
- **Focused evidence:** `.venv/bin/pytest -q tests/unit/test_openrouter.py` passed
  `113` tests in `0.51s`; affected Ruff, strict mypy, and `git diff --check`
  passed.
- **Independent review in progress:** Directly importable issuer tokens and a
  caller-mutable live campaign-binding list were reproduced as an in-process
  authority-bypass under ordinary package introspection. The current bounded fix
  is moving these runtime-only decisions into authority-owned identity registries.
  Arbitrary reflective Python execution remains outside the trusted-process,
  untrusted-data threat model and will not be claimed as contained.

### Final identity re-review corrections

- REAL usage, fresh generation verification, original campaign content authority,
  and final production qualification now retain authority in process-local weak
  identity/hash registries rather than caller-mutable model fields or importable
  issuer tokens. Direct constructor, `object.__new__` reconstruction, mutation,
  copy, pickle, and JSON-roundtrip regressions fail closed.
- The official single-model lookup is now executed using the catalog-resolved
  canonical slug. Its raw response hash and normalized metadata hash are frozen
  into discovery provenance and reconciled with the list-model and endpoint
  snapshots. Requested/canonical aliases are accepted only as the exact frozen
  pair; missing, malformed, unrelated, or transport-substituted lookup evidence
  fails closed.
- Schema-valid response identity contradictions now return concluded `UNBOUND`
  evidence, reconcile actual cost, stop host fallback, and retain the normalized
  value in a bounded client-owned in-memory registry. Model-only and bound callers
  still raise a content-safe typed exception. Generation-metadata failures retain
  a bounded specific reason in addition to the missing-metadata conclusion.
- **Focused slice evidence:** authority tests passed `80`; canonical discovery,
  candidate, CLI, and pipeline slices passed `159` plus `10`; the completed
  OpenRouter regression file passed `115`. Ruff and affected source mypy passed.
  The combined post-merge focused validation passed `659` tests in `41.73s`.
- `.venv/bin/ruff format .` reformatted two identity-scope files; the unfinished
  opt-in smoke module then exposed four static-only issues. Import ordering and
  unused future assertions were corrected, and its missing bounded local fixture
  loader was completed without enabling or running the paid test.
- `.venv/bin/ruff check .` now passes the complete repository.
- `.venv/bin/mypy` passes with no issues in `129` source files.
- `.venv/bin/python scripts/generate_release_schemas.py` completed with no
  generated-schema drift, and `git diff --check` passed.
- The explicit provider harness gate passed `31` unit tests and skipped its one
  paid integration test because `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1` was absent.
- **Provider state:** No paid request ran; total recorded spend remains
  `0.00118674 USD`, with `0.00 USD` reserved and no successful response credited.

### V3-IDENTITY-001 completion and pause checkpoint

- **Status:** `COMPLETE`.
- **Complete-suite evidence:** `.venv/bin/pytest -q` passed `1859` tests and
  skipped `10` explicitly gated external/provider/isolation prerequisites in
  `237.78s`. The paid OpenRouter smoke remained disabled and skipped.
- **Final exact-diff evidence:** A final non-functional diagnostic wording
  correction was followed by `115` passing OpenRouter tests, affected Ruff checks,
  and `git diff --check`.
- **Independent acceptance:** One review passed `253` focused tests and a nested
  independent review passed `143`; both reported no material identity blocker.
  They confirmed all four metadata surfaces execute in the local fake-provider
  path, aliases remain the exact requested/canonical pair, mismatches conclude
  unbound, valid values are retained without fallback or credit, and live evidence
  cannot overclaim immutable provider-version identity.
- **Remaining limitation:** OpenRouter exposes no provider-version observation in
  this path, so production identity honestly tops out at
  `CANONICAL_MODEL_AND_ENDPOINT_BOUND`; `IMMUTABLE_VERSION_BOUND` remains available
  only when explicit matching version evidence exists. A successful real
  identity-bound synthetic completion remains `V3-SMOKE-001`.
- **Pause:** Operator-requested pause begins at this clean ticket boundary. No
  provider request is running and no paid call was launched.

### V3-SMOKE-001 provider-alias diagnostic checkpoint

- **Status:** `IN_PROGRESS`; paused by operator after a validated local slice.
- **Confirmed local defect:** OpenRouter may identify the approved route by its
  endpoint tag while generation metadata uses the frozen provider display name.
  The completion envelope now preserves both raw observations and normalizes the
  provider used for identity comparison to the frozen endpoint display name.
- **Alias reconciliation:** Trusted generation metadata now accepts only the
  exact requested/canonical model pair frozen by discovery; a third model remains
  rejected. This removes a false mismatch without broadening accepted aliases.
- **Fail-closed diagnostics:** A schema-valid unbound generation observation can
  now be retained as a strictly validated, self-hashed projection in the
  concluded usage record. It remains non-creditable, cannot appear on a bound
  record, and cannot alter immutable request evidence.
- **Focused evidence:** The first four-case run reproduced a ledger replacement
  failure (`1 failed, 3 passed`). The usage ledger was tightened to validate and
  permit only the typed unbound observation. The final affected validation passed
  Ruff, strict mypy, `198` unit tests in `1.25s`, and `git diff --check`.
- **Provider and secret state:** No network request, paid model call, secret-file
  read, or artifact write occurred. Recorded spend and runtime counters remain
  unchanged.
- **Resume action:** Implement the separate private typed rejection artifact,
  validate non-disclosure and no-credit behavior, then inspect its bounded
  diagnostics before any materially different paid completion.

### V3-SMOKE-001 durable unbound-rejection evidence

- **Status:** `IN_PROGRESS`; local implementation complete, full validation in
  progress, and no paid request has run.
- **Reproduced gap:** The first new harness test failed at collection because no
  typed rejection artifact existed. After the initial schema/writer slice,
  focused execution exposed missing generation-fixture controls before reaching
  the intended assertions; these were corrected without weakening validation.
- **Durable fail-closed path:** The real-provider test now calls
  `complete_with_evidence`, branches before independent success verification when
  identity is concluded `UNBOUND`, reconciles the exact atomic-ledger entry, and
  writes a distinct self-hashed `REJECTED_IDENTITY_UNBOUND` artifact. The success
  artifact remains absent and the test still fails.
- **Evidence integrity:** The sink requires a process-attested, generation-bindable
  REAL usage record and cross-checks its self-hashed identity request and frozen
  snapshot against runtime, route, discovery, model, endpoint, response, and
  source-hash evidence. A JSON-roundtripped fabricated REAL record is rejected.
- **Privacy and retention:** The fresh hashed sibling uses descriptor-safe private
  release I/O. The writer scans the API key, secret path, complete system prompt,
  complete user prompt, and fixture source. Raw provider prompt/completion fields
  are discarded by the typed generation projection.
- **No false credit:** Rejection status, evidence kind, `creditable=false`, and
  `UNBOUND` identity are literals; the artifact cannot parse as successful smoke
  evidence. Secondary model, endpoint, reasoning, output, and stage-cost control
  failures remain visible as non-creditable booleans rather than suppressing the
  rejection record.
- **Focused evidence:** The end-to-end local branch test and harness passed `56`
  tests with the paid provider test explicitly skipped. The broader OpenRouter,
  generation, usage, release-I/O, harness, and gated integration subset passed
  `296` tests with one paid skip. Affected Ruff, mypy, and diff checks passed.
- **Independent review:** A first review identified the missing executed branch
  regression and missing positive REAL-provenance check. Both were implemented.
  Re-review found no remaining blocker and independently passed Ruff, mypy, `56`
  focused tests with one paid skip, and diff validation.
- **Complete local gates:** `.venv/bin/ruff format .` left `297` files unchanged;
  Ruff check passed; strict mypy found no issues in `129` source files; and
  `.venv/bin/pytest -q` passed `1892` tests with `10` explicit external,
  provider, and isolation skips in `240.48s`.
- **Provider state:** No secret file was opened and no metadata or completion
  network request ran. Spend, reservations, and runtime call counters are
  unchanged.
- **Checkpoint and paid-call preflight:** Commit
  `e4a9444bfe65fd63c9184f64c69d1211b71250a0` is clean and synchronized to the
  SSH origin. The pinned fixture hash is
  `bbb0127919f734caedffb6f9143a634b6925ff4451985d1410a47e1637f1517b`;
  no success or derived rejection destination exists. The operator ledger
  validates at `250.00` cap, `0.00179914` spent, zero reserved,
  `249.99820086` remaining, four terminal entries, and no over-cap or overrun
  state. This makes one materially changed request eligible; unchanged retry is
  prohibited.
- **Fifth real attempt:** The clean, materially changed smoke ran once. Provider
  authentication and metadata preflight passed, one structured response
  completed, and identity again concluded `UNBOUND`; no success credit was
  granted. Before the rejection artifact could be written, its ledger join
  required the parent usage request ID while the atomic ledger correctly stored
  the network-attempt ID with `:attempt:1`. The terminal ledger entry is
  `uncertain_accounted` with no fabricated actual cost and `0.00072452` USD
  conservatively accounted. Cumulative spent is `0.00186398` USD, reserved is
  zero, remaining is `249.99813602` USD, and no success or rejection artifact
  exists. Because the process-local completion was lost after this local sink
  failure, the exact identity diagnostic is not claimed or reconstructed.
- **No-progress control:** The request will not be repeated unchanged. The next
  local slice must support attempt-qualified IDs and terminal conservative cost
  evidence, execute a regression for both, and remain fail-closed.
- **Local bookkeeping correction:** The smoke harness now joins the exact
  `:attempt:1` ledger entry, accepts only terminal cost states, and preserves
  unknown provider cost as `uncertain_accounted` without fabricating an actual
  value. Rejection evidence records prior-entry hashes, spend-delta consistency,
  reservation closure, over-cap and overrun state. The successful smoke path
  additionally requires unchanged prior entries and an exact cost delta.
- **Integrity assay:** A disposable atomic-ledger regression proves that adding
  and conservatively closing a new attempt leaves all terminal prior entries
  unchanged and increases spent cost by exactly the new accounted amount. A
  separate synthetic rejection regression preserves the observed discrepancy as
  non-creditable evidence with both integrity booleans false.
- **No-network validation:** Affected Ruff passed; strict project mypy passed for
  all `129` configured source files; the focused ledger, budget, provider,
  usage, harness, and gated-integration subset passed `241` tests with the one
  paid test explicitly skipped. No provider call ran.
- **Complete-suite pause gate:** `.venv/bin/ruff format .`,
  `.venv/bin/ruff check .`, `.venv/bin/mypy`, and `.venv/bin/pytest -q` all
  passed: `297` files were already formatted, Ruff passed, mypy found no issues
  in `129` source files, and pytest passed `1894` tests with `10` explicit
  external/provider/isolation skips in `234.39s`.
- **Independent-review correction:** Read-only review identified that owned
  process attestation alone was broader than the prior strict transport
  predicate. The rejection sink now retains every strict certification check
  and narrowly permits only a missing reported cost backed by the exact
  `uncertain_accounted` terminal entry. An attested record carrying a provider
  error is rejected by regression. The review also caught and corrected a
  transcribed predecessor commit hash. Affected Ruff, `109` focused tests plus
  one paid skip, and strict project mypy pass after both corrections.
- **Independent re-review:** The reviewer found no remaining blocker: the narrow
  unknown-cost exception retains the full strict REAL certification predicate,
  the provider-error negative regression fails closed, and checkpoint identity
  now matches Git. No provider or network call ran.
- **Pause checkpoint:** Implementation commit
  `ae5911933d47fd49671730280611cef21185b001` contains the validated terminal
  accounting and rejection-evidence correction. `V3-SMOKE-001` remains
  `IN_PROGRESS`; no successful model response or release credit is claimed.
- **Autorun resume:** Reloaded the complete objective and repository state from
  clean synchronized commit `bbd928f9b74dd61a9c90c56886e2308afa07442a`.
  The next bounded action is metadata-only discovery of materially different
  exact `STRICT_ZDR` routes. The rejected Qwen/AkashML completion will not be
  repeated unchanged.
- **Metadata-only route discovery:** An initial command using the absent
  `mmaudit.toml` path failed locally before secret loading or network access. A
  corrected multi-candidate discovery failed closed because a candidate differed
  from the frozen catalog projection. Isolated authenticated discovery succeeded
  for exact model `mistralai/mistral-small-2603` and endpoint `venice/fp8`, with
  discovery-evidence SHA-256
  `b01018a5aa5b7ed857aa868992a643d3db009e548f0dc5b209b2abb99883cdc2`
  and manifest SHA-256
  `d3359317d4069ba704ff09246c242c72e7dcf9bcc59b7c5715aebc755ad750c2`.
  This was metadata only: no completion was requested, provider cost did not
  change, and no review credit was granted.
- **Generation metadata readiness regression:** A pre-fix regression reproduced
  the immediate post-completion `404` failure with model retries disabled.
  Generation evidence now performs at most four same-generation observations at
  fixed `0/1/3/7` second offsets. Only transient retrieval failures and absent or
  same-ID incomplete metadata are retried; authentication failure, contradictory
  generation identity, cancellation, invalid metadata, and exhaustion remain
  typed fail-closed outcomes. The self-hashed evidence records the bounded
  retrieval-attempt count.
- **Pause validation:** `.venv/bin/pytest -q
  tests/unit/test_generation_evidence.py` passed `51` tests; affected Ruff passed;
  strict mypy passed for the three changed source files; and the broader
  generation, OpenRouter, identity, usage, and qualification-config subset passed
  `235` tests. No provider completion or cost-bearing request ran.
- **Pause checkpoint:** Implementation commit
  `982abd71862c543759c944c3f6cdcf67817d0ecc` preserves the bounded
  generation-metadata correction. `V3-SMOKE-001` remains `IN_PROGRESS`; zero real
  model calls have succeeded, no successful smoke artifact exists, and the
  release remains incomplete.
- **Goal continuation:** Reloaded the complete objective and authoritative
  repository state from clean synchronized checkpoint
  `ff538c2500b2bcd9dff8ffcf7bd3bb3aeb049091`. The current bounded action is
  typed validation of the Mistral/Venice discovery evidence and clean smoke
  preflight; no unchanged rejected route will be retried.
- **Typed route validation:** Descriptor-safe typed loading validated one complete
  discovery set for exact model `mistralai/mistral-small-2603`, canonical slug
  `mistralai/mistral-small-2603`, approved endpoint `venice/fp8`, provider
  `Venice`, strict-ZDR and data-collection-denial eligibility, `256000` context,
  `65536` output capacity, native structured-output parameters, and optional
  reasoning controls. The manifest hash is
  `d3359317d4069ba704ff09246c242c72e7dcf9bcc59b7c5715aebc755ad750c2`;
  endpoint and model snapshot hashes match the committed candidate facts.
- **No-network smoke preflight:** Validated the exact allowlists, explicit
  `STRICT_ZDR` profile, pinned fixture hash
  `bbb0127919f734caedffb6f9143a634b6925ff4451985d1410a47e1637f1517b`,
  fresh private success destination, and existing atomic ledger. The ledger has
  cap `250.00`, spent `0.00186398`, zero reserved, remaining `249.99813602`,
  five terminal entries, no over-cap state, and no reservation overrun. This
  check did not open the secret file and made no provider or network request.
- **Independent pre-spend review:** Read-only review found no material code
  blocker for one Mistral/Venice smoke and independently passed `137` local tests
  with only the explicitly disabled paid integration skipped. Runtime preconditions
  must still revalidate immediately before the POST: fresh output, healthy
  reservation-free ledger, live optional-reasoning metadata, and current matching
  route evidence. The older candidate-registry discovery hash is not reused as
  qualification credit; the smoke binds a fresh runtime discovery record.
- **Sixth real attempt:** From clean synchronized commit
  `dd871cc1179fb4af67bd6af84e03aff43af1a2b4`, the exact
  Mistral/Venice request passed authentication, live metadata, optional-reasoning,
  privacy, routing, schema, and initial identity gates. The response completed
  with `stop`, was non-truncated, schema-valid, and initially reached
  `CANONICAL_MODEL_AND_ENDPOINT_BOUND`. The mandatory separately authenticated
  generation re-fetch then failed deterministic usage reconciliation. The test
  therefore failed closed; no success artifact or release credit exists.
- **Attempt accounting:** The attempt-qualified ledger entry
  `351a6f77-d541-4b87-9e0f-9e6825bca857:attempt:1` is `reconciled` with
  actual/accounted cost `0.0000635625` against reservation `0.0012195`.
  Cumulative state is cap `250.00`, spent `0.0019275425`, zero reserved,
  remaining `249.9980724575`, six terminal entries, no over-cap state, and no
  reservation overrun.
- **No-progress control:** The provider request will not be repeated unchanged.
  The generic outer error discarded the exact locally generated mismatch label
  and the bound-but-unverified branch has no durable rejection sink. The next
  local regression must reproduce eventual same-generation usage metadata,
  preserve a typed non-secret diagnostic, and retry only potentially eventual
  fields within a fixed bound while contradictions still fail immediately.
- **Typed reconciliation correction:** Every deterministic generation
  reconciliation mismatch now has a value-free typed code. Prompt, completion,
  reasoning, cached-token, and reported-cost mismatches alone may use the fixed
  four-observation same-generation window. Model, endpoint/provider, generation,
  finish, timestamp, cancellation, and internally inconsistent metadata remain
  immediate fail-closed outcomes.
- **Durable post-bind rejection:** A separately typed, private, self-hashed
  rejection artifact now records the process-attested bound response, exact
  mismatch code, bounded observation count, identity/evidence hashes, and
  attempt-qualified terminal ledger facts without persisting the compared values,
  raw prompt, source, completion, secret, or secret path. It cannot parse as
  success or as the earlier unbound-rejection artifact and grants no review or
  release credit.
- **Focused validation:** The generation, OpenRouter, identity, usage, cost-ledger,
  real-provider harness, and disabled paid-integration subset passed `319` tests
  with one explicit paid-test skip. Affected Ruff and strict targeted mypy passed;
  `git diff --check` passed. No provider or network request ran during this local
  correction.
- **Pause state:** `PAUSED_BY_OPERATOR` at a safe local-validation boundary. No
  seventh paid call was made. `V3-SMOKE-001` remains `IN_PROGRESS`; the next
  action on resume is independent review and final local validation before any
  materially changed provider retry.
- **Pause checkpoint:** Implementation commit
  `f7ec46d72a192fe4457f87a17abec95d60d422c5` preserves the typed bounded
  reconciliation and durable post-bind rejection evidence. No successful model
  response or release credit is claimed.
- **Goal continuation:** Reloaded the complete product objective and authoritative
  repository state from clean synchronized checkpoint
  `7e394abe153aacf2389adaa6426b3a402e0e8d61`. `V3-SMOKE-001` is active again.
  The bounded reconciliation change must pass independent review and the complete
  local validation gates before any materially changed paid retry.
- **Independent-review defect:** A compound metadata payload containing both an
  eventual cost mismatch and an impossible request timestamp selected the
  retryable cost code first and exhausted four observations. A new negative
  regression reproduced the behavior. Decisive identity, provider, finish, and
  timestamp contradictions are now evaluated before every retryable token/cost
  comparison; the compound case fails immediately as `REQUEST_TIMESTAMP`.
- **Independent re-review:** No material blocker remains. Every decisive
  structural, identity, provider, finish, and timestamp contradiction now has
  priority over eventual usage/cost fields; the compound regression performs one
  metadata GET and no wait. Final capability issuance still independently
  revalidates the complete attestation set.
- **Complete local gate:** Ruff format left `297` files unchanged after the
  initial formatting normalization; Ruff check passed; strict mypy found no
  issues in `129` source files; release-schema generation completed without
  drift; the focused slice passed `320` tests with one paid-provider skip; and
  the complete suite passed `1912` tests with `10` explicit external,
  provider, and isolation skips in `229.55s`. No provider or network request ran.
- **Clean implementation checkpoint:** Commit
  `a6ef7bb04cdc58a1b01b06f94a8aa69461e5e44d` contains the independently
  reviewed reconciliation ordering fix and is synchronized to the SSH origin.
  No successful model response or release credit is claimed.
- **Attempt-seven no-network preflight:** The exact Mistral/Venice allowlists,
  explicit `STRICT_ZDR` policy, pinned fixture, fresh private success/rejection
  namespace, and existing atomic ledger validated. The ledger contains six
  terminal entries, `0.0019275425 USD` spent, zero reserved,
  `249.9980724575 USD` remaining, no over-cap state, and no reservation overrun.
  The secret file was not opened and no network request ran.
- **Seventh real attempt:** From clean synchronized checkpoint
  `1ceab96`, exact Mistral/Venice authentication and metadata preflight reached
  the completion request, which returned HTTP `429` before any model output.
  The configured zero-retry policy failed closed. No completion, success
  artifact, rejection artifact, or review credit exists.
- **Attempt-seven accounting:** The attempt-qualified terminal entry is
  `uncertain_accounted`; the provider supplied no usable actual cost, so the
  complete `0.00072452 USD` reservation was conservatively accounted without
  fabrication. Cumulative spend is `0.0031470425 USD`, active reservation is
  zero, remaining budget is `249.9968529575 USD`, and the ledger has neither
  over-cap state nor reservation overrun.
- **No-progress control:** Mistral/Venice will not be retried unchanged.
  The next safe action is metadata-only discovery of a materially different
  exact `STRICT_ZDR` route, followed by fresh endpoint binding and local
  preflight before another completion is considered.
- **Alternate discovery attempt one:** Exact DeepSeek/Novita metadata discovery
  failed closed because the single-model response differed from the frozen
  catalog projection. No completion was requested, no source was sent, and
  ledger cost did not change.
- **Alternate discovery attempt two:** Typed authenticated metadata-only
  discovery succeeded for exact `qwen/qwen3.6-35b-a3b`, canonical
  `qwen/qwen3.6-35b-a3b-20260415`, endpoint `akashml/fp8`, and provider
  `AkashML`. The route is strict-ZDR and data-denial eligible, supports native
  structured output and optional reasoning, and exposes `262144` context and
  output capacity. Discovery evidence is
  `afd7e1b6d657cd5ef8d5a543b68c6d90e01dcb9883757b742cc4fec0e0c3e784`;
  manifest SHA-256 is
  `8ec7e176e308c5806c52534467db27202eb026423cc9d47c8417e39b2dd07347`.
  No model completion was requested.
- **Attempt-eight no-network preflight:** Exact Qwen/AkashML allowlists, explicit
  `STRICT_ZDR`, the pinned fixture, fresh private success/rejection namespace,
  and the seven-entry atomic ledger validated. Spend remains
  `0.0031470425 USD`, active reservation is zero, remaining budget is
  `249.9968529575 USD`, and there is no over-cap state or reservation overrun.
- **Eighth real attempt:** From clean synchronized checkpoint `129c4ac`, the
  exact Qwen/AkashML response was structured, schema-valid, non-truncated, and
  provider-consistent, but generation metadata remained unavailable throughout
  the fixed `0/1/3/7` observation window. Identity therefore concluded
  `UNBOUND` with `GENERATION_METADATA_MISSING` and
  `GENERATION_METADATA_NOT_READY`; no success or review credit was granted.
- **Durable attempt-eight evidence:** Private rejection SHA-256
  `b5c3e21c094edd372806b00c8041e487293720c48084f5766e8645fe600a3e5a`
  is self-hashed, non-creditable, typed, source/prompt/credential-canary-free,
  and round-trips while the success artifact remains absent. Its exact ledger
  entry reconciled `0.00006484 USD` against a `0.00135972 USD` reservation.
  Cumulative spend is `0.0032118825 USD`, reserved is zero, and remaining is
  `249.9967881175 USD`.
- **Late generation diagnostic:** A later authenticated metadata-only re-fetch
  of the same already-paid generation returned canonical
  `qwen/qwen3.6-35b-a3b-20260415`, provider `AkashML`, and `finish=stop`.
  Content-free generation evidence SHA-256 is
  `afc99ea2271411c36590dcede73b61cf71f48c54f74a2df2a5aa2639878d92de`;
  its private artifact file SHA-256 is
  `ee04bbd5e703a19240c8261dce135a688d428f4f485487d774fc5948d6f8b44a`.
  No completion was requested, no source was sent, and ledger state did not
  change.
- **No-progress control:** Qwen/AkashML will not be retried unchanged. The late
  exact metadata isolates the remaining failure to the current readiness window.
  The next local slice must add a late-readiness regression and a fixed,
  request-aware longer window while preserving immediate contradiction failure.
- **Late-readiness regression:** The same-generation observation schedule now
  extends deterministically to at most seven observations at cumulative
  `0/1/4/11/26/56/116` second offsets when the configured request horizon permits.
  The configured horizon selects fewer observations rather than silently applying
  a longer minimum. Every single-generation operation has one hard wall-clock
  deadline, including all HTTP work and waits.
- **Explicit partial-field reconciliation:** A typed core expectation binds the
  provisional usage record, exact/canonical model pair, discovery and catalog
  hashes, frozen provider, and certification route class. Every explicit field in
  an incomplete response is validated using an ephemeral fill-only projection.
  Decisive model, provider, finish, timestamp, generation-ID, cancellation, and
  internal cost contradictions fail on the first observation; only usage/cost
  fields already classified as eventual may settle. The ephemeral projection is
  never returned, serialized, or credited.
- **Initial identity correction:** Owned REAL completion identity binding now passes
  the same typed reconciliation expectation. Complete metadata with a mismatched
  finish reason, timestamp, token count, or cost can no longer receive bound
  identity. Ordinary non-certification routes remain structurally reconcilable,
  while benchmark verification continues requiring certification evidence.
- **Set-level bound:** Trusted multi-generation verification includes
  authentication and all generation reads under one shared deadline, caps the set
  at `512`, preserves input ordering, deterministically selects the first
  input-ordered failure, limits only active metadata GETs with the configured
  semaphore, and cancels plus awaits every child on internal timeout or caller
  cancellation.
- **Regression evidence:** The pre-fix test file first failed collection because
  the core expectation did not exist. After implementation, the generation suite
  passed `87` tests. Its matrix includes late readiness, seven-attempt exhaustion,
  total wall time, matching-ID and absent-ID partial contradictions, eventual-only
  settlement, non-certification compatibility, bounded concurrency, non-starving
  waits, ordered set results, deterministic error selection, auth-inclusive
  timeout, shared cancellation cleanup, and fixed cardinality. The expanded
  provider, identity, usage, cost, harness, qualification, candidate, and release
  subset passed `521` tests with the one paid test explicitly skipped. Affected
  Ruff and strict mypy passed; release schema generation produced no drift.
- **Provider state:** No secret file was opened and no network or provider request
  ran during this correction. Recorded runtime counters and ledger values remain
  `8` attempted, `0` succeeded, `8` rejected, `0.0032118825 USD` spent, zero
  reserved, and `249.9967881175 USD` remaining.
- **Current gate:** Independent review is rechecking the final cancellation and
  absent-ID corrections. Full repository validation and a clean checkpoint remain
  mandatory before a fresh no-network preflight.
- **Final review correction:** Constructing the reconciliation expectation could
  itself reject an ordinary provider-fallback route after a valid paid completion,
  before the existing unbound-preservation path. That constructor rejection now
  concludes the response as typed, non-creditable `UNBOUND` evidence with bounded
  route diagnostics and without querying generation metadata. The negative
  regression preserves the completed value, records provider/endpoint/fallback
  disagreement, and prevents automatic host-model fallback. The focused
  generation and fallback slice passed `88` tests; affected Ruff and production
  mypy passed.
- **Independent final review:** A read-only reviewer found no material blocker.
  It verified ordinary fallback preservation and non-creditability, no subsequent
  generation query or host fallback, deterministic request-order timeout
  selection, and child-task cleanup. Its independent slice passed `266` tests;
  Ruff, configured mypy over `129` source files, release-schema verification, and
  diff checks passed without network, provider, secret-file, or credential access.
- **Expanded local gate:** The generation, OpenRouter, model-identity, usage,
  cost-ledger, real-provider harness, qualification, candidate benchmark, release,
  and explicitly gated provider-integration slice passed `709` tests with one
  paid-provider skip in `37.87s`. No provider access occurred.
- **Complete local gate:** `.venv/bin/ruff format .` left `297` files unchanged,
  Ruff check passed, configured mypy passed `129` source files, release-schema
  verification produced no drift, and `.venv/bin/pytest -q` passed `1938` tests
  with `10` explicit external-engine, provider, isolation, and loopback skips in
  `229.76s`. The paid provider test remained disabled. No secret file, network,
  metadata endpoint, or completion endpoint was accessed.
- **Final checkpoint review:** A separate read-only reviewer found no material
  blocker in the complete diff. Its focused regression slice passed `299` tests;
  affected Ruff, strict mypy, and diff checks passed. It confirmed fail-closed
  deadlines, partial-field contradiction handling, reconciliation, cancellation
  cleanup, and ordinary-fallback preservation, with no untracked secret, runtime,
  or generated artifact in scope.
- **Validated implementation checkpoint:** Commit
  `9f63ab48905ee297992feb6f383a573a4e33cef2` contains the complete local
  correction and its regression evidence. The operator-requested pause is now at
  a no-provider-access boundary: no process or reservation is active, the paid
  test remains disabled, and `V3-SMOKE-001` remains `IN_PROGRESS`.
- **Goal continuation and attempt-nine preflight:** Reloaded the complete
  authoritative objective and repository state from clean synchronized commit
  `175542c1f21eb5f3329c6fed2d8c7d83b71cacdf`. A fresh typed no-network
  preflight validated exact model `qwen/qwen3.6-35b-a3b`, canonical model
  `qwen/qwen3.6-35b-a3b-20260415`, endpoint `akashml/fp8`, provider `AkashML`,
  `STRICT_ZDR`, the pinned fixture hash, and a fresh attempt-nine success
  destination. The ledger remains eight terminal entries with
  `0.0032118825 USD` spent, zero reserved, and `249.9967881175 USD`
  remaining. Only secret-file metadata was validated; its contents were not
  opened, and no network or provider request ran.
- **Ninth real attempt:** From clean synchronized checkpoint
  `c86bae5c8867038ded9e6b8b9a05d40a3155a064`, exactly one explicitly
  gated Qwen/AkashML completion ran against only the pinned synthetic fixture.
  The response was structured, schema-valid, non-truncated, `finish=stop`, and
  used zero reasoning tokens. Identity still concluded `UNBOUND` after all seven
  bounded generation observations, with
  `GENERATION_METADATA_INVALID` and `GENERATION_METADATA_MISSING`; no success or
  review credit was granted.
- **Attempt-nine durable evidence:** The private self-hashed rejection artifact
  has file SHA-256
  `6fd020441eac23069a5e1028cdcb6a7d96b12985cff1ca3c14bac88fdb9e0238`
  and evidence SHA-256
  `c859e8d5469bad26b9f5dcb595cab94428c73dfb1ba8b519bd8bf59374121568`.
  It is mode `0600`, non-creditable, and retains no raw prompt, source, response,
  secret, or secret path. The success artifact remains absent.
- **Attempt-nine accounting:** The ninth exact attempt reconciled
  `0.00006484 USD` against a `0.00135972 USD` reservation. Aggregate spend is
  `0.0032767225 USD`, active reservation is zero, remaining budget is
  `249.9967232775 USD`, and all nine entries are terminal with no over-cap or
  reservation-overrun state.
- **Token-basis diagnosis:** The final generation observation is exact for model,
  provider, generation, finish reason, timestamp, cost, reasoning, and cache
  facts. Its normalized token counts are `211/19`; its native token counts are
  `256/29`, exactly matching the completion response usage. The current
  reconciler compares only normalized prompt/completion counts and therefore
  rejects a coherent native-basis observation. No unchanged provider retry is
  permitted; the next slice is a local regression and narrow evidence-preserving
  correction.
- **Red regression:** Before implementation,
  `.venv/bin/pytest -q
  tests/unit/test_generation_evidence.py::test_generation_reconciliation_accepts_one_complete_native_token_basis`
  failed with typed `PROMPT_TOKENS` reconciliation because the completion usage
  matched the complete native pair rather than the normalized pair.
- **Local token-basis correction:** Reconciliation now treats normalized
  prompt/completion counts as one atomic candidate pair and adds the native pair
  only when both native values exist. Completion usage must equal one complete
  pair; it cannot combine fields across bases, and partial or unmatched native
  evidence remains a typed eventual failure under the existing bounded polling
  policy. Native reasoning and cache validation now uses native completion and
  prompt parents when present, with an explicitly tested conservative normalized
  fallback when a native parent is absent.
- **Defensive regression matrix:** Added the observed native-basis success,
  normalized compatibility, both cross-basis orientations, both one-sided native
  cases, native-parent positive and negative bounds, settlement when a complete
  matching native pair appears later, and terminal unmatched-pair exhaustion with
  typed final evidence. The real-provider assertion now accepts only membership
  in one complete observed pair.
- **Independent correction review:** A read-only reviewer found no production
  blocker. It confirmed atomic tuple membership, complete-native-only eligibility,
  mixed/partial rejection, typed polling, and correct native-parent validation.
  Its requested terminal-exhaustion and reverse-orientation gaps were added.
- **Focused correction evidence:** The generation, private rejection-artifact,
  and explicitly gated provider slice passed `159` tests with one paid-provider
  skip. Affected Ruff passed and strict mypy found no issues. No secret file,
  network, metadata endpoint, completion endpoint, or ledger state was accessed.
- **Pre-full-gate state:** The next command is the complete local Ruff format/check,
  configured mypy, release-schema generation, and pytest suite. The paid test
  remains disabled; spend remains `0.0032767225 USD`, reservations remain zero,
  and no success artifact exists.
- **Complete correction gate:** `.venv/bin/ruff format .` left `297` files
  unchanged; Ruff check passed; configured strict mypy passed `129` source files;
  `.venv/bin/python scripts/generate_release_schemas.py` completed without drift;
  and `.venv/bin/pytest -q` passed `1950` tests with `10` explicit
  external-engine, isolation, loopback, and paid-provider prerequisite skips in
  `227.81s`. Provider access remained disabled.
- **Final local scope review:** `git diff --check` passed; the worktree contains
  only the reconciler, its unit and gated integration regressions, and this v3
  queue/worklog. There are no untracked files, generated schema changes, or
  secret-pattern additions. Runtime/private artifacts remain ignored and outside
  the commit.
- **Validated implementation checkpoint:** Commit
  `0ff4918568a304bcefc3ad108903ee74b197389b` records the reconciler, regression
  coverage, and exact attempt-nine/full-gate evidence. It contains only the five
  intended files and no runtime/private artifact.
- **SSH publication:** Implementation checkpoint `0ff4918` and state checkpoint
  `a36302c` were pushed to `git@github.com:londonjevans/Auditor.git`. Local
  `HEAD` and `origin/main` both resolved to
  `a36302cab3c32277f47b5154ee469d1699e50b49` with a clean worktree.
- **Attempt-ten no-network preflight:** From that clean synchronized checkpoint,
  the exact model `qwen/qwen3.6-35b-a3b`, exact endpoint `akashml/fp8`,
  `STRICT_ZDR`, pinned fixture SHA-256
  `bbb0127919f734caedffb6f9143a634b6925ff4451985d1410a47e1637f1517b`,
  and fresh destination
  `v3-smoke-qwen-akash-success-20260728-attempt10.json` validated. The operator
  secret path was checked by metadata only: regular, single-link,
  non-group/world-writable, bounded, and non-symlink; its contents were not
  opened.
- **Attempt-ten budget preflight:** The durable ledger has cap `250.00 USD`, nine
  terminal entries, `0.0032767225 USD` spent, zero reserved,
  `249.9967232775 USD` remaining, no over-cap state, and no reservation overrun.
  No network, metadata endpoint, completion endpoint, or ledger mutation occurred.
- **Attempt-ten launch checkpoint:** The preflight record was committed and pushed
  over SSH as `94b242e`; the in-progress launch record was committed and pushed as
  `d473305`. Local `HEAD` and `origin/main` were equal before provider access.
- **Tenth real attempt:** Exactly one explicitly gated Qwen/AkashML completion ran
  against only the pinned synthetic fixture using the audited explicit secret
  loader. The exact response completed with strict structured validation,
  `finish=stop`, zero reasoning, no fallback or substitution, and independently
  re-fetched generation evidence. The corrected atomic token-pair reconciliation
  accepted the complete native pair. The integration passed `1` test in `13.73s`.
- **Successful smoke evidence:** The private success artifact
  `v3-smoke-qwen-akash-success-20260728-attempt10.json` is a mode-`0600`,
  single-link, descriptor-safe, self-hashed `REAL` evidence record. Its file
  SHA-256 is
  `a49573826590c928902507a0ccc1d54be9c776a6dd9d5afd914384f4e7ef8674`
  and evidence SHA-256 is
  `cb32ca347acafc219a7bf66b28c26d7dc87898463769a9368ac248db066d4dcf`.
  It is the only attempt-ten artifact; no rejection sibling exists.
- **Bound runtime facts:** Requested model is `qwen/qwen3.6-35b-a3b`; canonical
  and generation model are `qwen/qwen3.6-35b-a3b-20260415`; endpoint is
  `akashml/fp8`; provider is `AkashML`; identity strength is
  `CANONICAL_MODEL_AND_ENDPOINT_BOUND`. Usage is `256` prompt and `29`
  completion tokens, with zero reasoning and zero cached tokens. Latency is
  `829 ms`.
- **Attempt-ten accounting:** Actual and accounted cost are both
  `0.00006484 USD`. The durable ledger now contains ten terminal entries,
  `0.0033415625 USD` spent, zero active reservation, and
  `249.9966584375 USD` remaining with no over-cap or overrun state.
- **Independent artifact readback:** Typed descriptor-safe readback revalidated
  the self-hash, fixture binding, identity, strict privacy claims, cost totals,
  output namespace, file mode/link count, and atomic ledger. Fixture source,
  secret path, authorization labels, bearer material, and the credential name
  are absent. The gated test itself also scanned the in-memory credential value
  before persisting evidence.
- **Ticket completion:** `V3-SMOKE-001` is `COMPLETE`. It now proves one real,
  exact-route, strict-ZDR, schema-valid, non-truncated, identity-bound,
  cost-reconciled synthetic OpenRouter completion. It does not qualify a
  production ensemble or constitute a completed real audit.

## 2026-07-28 — V3-PRIVACY-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Make strict zero-retention the default and require
  explicit operator-authored, evidence-bound consent before any weaker retention
  route can receive private source.
- **Starting action:** Inspect typed configuration, request routing, manifests,
  reports, CLI surfaces, and negative tests before selecting the smallest
  cohesive correction. No additional provider spend is authorized for this
  inspection slice.
- **Implemented slice:** Added typed `STRICT_ZDR`,
  `FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT`, and `SYNTHETIC_BENCHMARK`
  profiles; a self-hashed descriptor-safe consent schema and loader; exact
  source/model/provider/policy/expiry/cost binding; and a noncopyable,
  nonserializable, process-local authorization capability. Default configuration
  remains strict ZDR. Configuration alone cannot mint or activate consent.
- **Provider enforcement:** Real or cost-ledger-backed non-ZDR execution now
  revalidates the live capability before endpoint registration and immediately
  before a completion. Valid non-ZDR routing omits request-level `zdr`, retains
  `data_collection=deny`, exact provider routing, and disabled fallbacks.
  Invalid, expired, route-mismatched, or tampered authority fails before
  transport and before a cost reservation.
- **Discovery correction:** Candidate discovery now begins from the unfiltered
  `/models` catalog and records endpoint-specific ZDR and structured-output
  capabilities rather than globally excluding non-ZDR or non-native candidates.
- **Evidence and reporting:** Each provider audit resolves a self-hashed
  effective privacy policy from the exact repository inventory, persists
  `privacy-policy.json`, binds it into the run manifest and latest evidence
  directory, includes it in JSON/Markdown reports, and states the strict-profile
  ensemble limitation. Consent paths and operator references are not persisted.
- **Fail-closed regressions:** Added synthetic negatives for implicit consent,
  internal/symlink/writable/shared consent files, stale and mismatched authority,
  private source under synthetic policy, cross-profile source labels, malformed
  or expired usage evidence, scanner-only no-egress behavior, and transport
  non-execution. Canary checks cover requests, usage evidence, artifacts, and
  exceptions.
- **Diagnostic honesty:** `mmaudit doctor` now names the active profile and
  reports that account/guardrail ZDR compatibility is not observable from
  ordinary API-key metadata for non-ZDR routing; a successful exact-route
  consented runtime preflight is required before a frontier claim.
- **Validation so far:** Release-schema verification passed; the initial focused
  privacy/config/discovery/runtime slice passed `209` tests; focused transport,
  usage, CLI, and pipeline privacy slices passed; affected Ruff passed; strict
  mypy passed over `130` source files. No network or paid provider call ran and
  cumulative spend remains unchanged.
- **Expanded-suite correction:** The first expanded run passed `636` tests and
  exposed two integration defects: the manually published run-manifest schema
  lacked the new privacy run-option and override fields, and the pipeline's
  asynchronous finalizer retained the consent observation even though its public
  credential clearer discarded it. The manifest schema is updated without
  weakening bounds, and every run finalizer now drops the live authorization and
  consent observation. Both exact failing regressions pass after correction.
- **Post-review authorization hardening:** An independent adversarial review
  found that consent could expire between retries and that nominally frozen
  Pydantic evidence could be mutated with low-level attribute replacement. The
  transport now revalidates the exact model, exact pending provider route,
  complete capability content, current expiry, and budget immediately after
  every reservation and immediately before every POST. Pre-send refusal releases
  the reservation. Live weak identity registries and canonical content digests
  reject reconstructed or mutated consent observations and capabilities.
- **Consent-boundary hardening:** Loader failures now discard path/content-bearing
  exception state before raising fixed messages. Regression canaries cover
  formatted tracebacks, causes, contexts, and serialized exception projections.
  Persisted privacy-policy references reject user information, queries, and
  fragments. The ZDR acknowledgement is an explicit boolean required only when
  non-ZDR routing is authorized.
- **Source-provenance correction:** `SYNTHETIC_COMMITTED` no longer trusts an
  operator enum. Live pipeline execution requires a non-empty, clean,
  HEAD-matching provider-visible scope under this installed distribution's
  committed `tests/fixtures` or `benchmarks` tree, using a fixed trusted Git
  binary and sanitized environment. Arbitrary, modified, untracked, or
  out-of-distribution source is refused. `PUBLIC_BENCHMARK` fails closed until
  independent publication provenance exists. Private source remains the
  fail-closed default.
- **Endpoint privacy matrix:** Discovery no longer injects an unconditional
  data-collection-denial claim. Each exact endpoint now records either exact ZDR
  snapshot evidence, exact consent-bound effective-policy evidence, or
  `UNVERIFIED`; the last receives no qualification credit. ZDR synthetic runs
  require an explicit matching profile and committed-source provenance but no
  inapplicable retention-consent artifact.
- **Diagnostic and latest-artifact honesty:** Doctor reports account/guardrail
  ZDR state as unobservable for both strict and frontier profiles and requires
  an exact-route runtime preflight for a claim. Each run now removes optional
  artifacts absent from the new run's `latest/` view, preventing an older
  privacy policy or provenance record from surviving a scanner-only refresh.
- **Focused validation:** Privacy/OpenRouter acceptance passed `66` selected
  tests; privacy provenance/discovery/pipeline validation passed `312` broader
  tests in `81.98s`; the stale-latest regression passed `2` focused tests.
  Affected Ruff and strict mypy passed. Schema generation initially and
  correctly reported the changed consent schema as stale; regeneration with
  `.venv/bin/python scripts/generate_release_schemas.py --write` followed by
  verification passed. No provider completion, credential access, or spend
  occurred.
- **Next safe action:** Complete independent adversarial re-review, then run the
  final formatter, Ruff, strict mypy, and complete pytest gates before
  checkpointing and pausing at the operator-requested clean boundary.
- **Independent adversarial re-review:** Three read-only reviewers found
  fail-closed gaps in mutable route-policy handling, exact non-ZDR disclosure
  selection, consent-free synthetic-ZDR usage credit, declared synthetic-source
  custody, Git replacement-object handling, current-byte/Git-blob binding,
  Unicode source hashing, run-local state reset, and semantic agreement among
  policy, provenance, usage, report, and manifest evidence. The earlier focused
  suites remained green, so these are adversarial acceptance defects rather
  than reproduced ordinary-suite failures.
- **Remediation in progress:** The ticket remains `IN_PROGRESS`. Work is bounded
  to immutable exact-route snapshots, a distribution-controlled synthetic-source
  declaration with descriptor-safe current-byte and clean-commit proof, live
  provenance capabilities, evidence-source/expiry preservation, and deterministic
  cross-artifact consistency checks. No provider call, network request, secret
  file read, or additional spend is part of this slice.
- **Adversarial remediation closure:** Git proof now disables replacement objects
  and binds descriptor-safe current bytes to the exact clean Git blob. Installed
  distributions instead require a code-pinned declaration and exact packaged
  synthetic fixture. Unicode inventory hashing, noncopyable live observations,
  immutable canonical route policies, exact non-ZDR disclosures, evidence
  source/expiry preservation, and run-local privacy-state reset close the
  identified provenance and route gaps.
- **Paid-route and benchmark closure:** Every paid completion now requires a
  canonical effective privacy policy before reservation and revalidates its exact
  model, endpoint, active budget, and profile after reservation immediately
  before transport. Candidate benchmarking binds strict-ZDR evidence to its
  versioned synthetic corpus and exact candidate route. Profile-less legacy
  usage receives no execution credit. Discovery and candidate benchmark endpoint
  snapshots now use the same configured ZDR requirement.
- **Cross-artifact closure:** A provider audit refuses a reused client with any
  pre-existing usage record. Current manifests require the emitted report and
  metadata artifacts, validate their privacy payloads against each other, and
  require every serialized provider usage record to contain the complete policy,
  source, provenance, and routing bindings.
- **Independent closure evidence:** The provenance suite passed `75` tests; the
  route/privacy suite passed `378`; the pipeline stale-ledger regressions passed
  `55`; and focused manifest regressions passed `13`. A locally cached,
  offline-built wheel contained the pinned declaration and fixture and passed
  packaged-source proof; independent source and declaration tampering were both
  rejected. Temporary wheel-review directories were removed and no distribution
  artifact was written into the repository.
- **Pre-complete gate state:** The combined focused privacy suite and complete
  formatter, Ruff, strict mypy, pytest, schema-synchronization, diff, artifact,
  and secret-pattern checks remain to run. No network, provider, or operator
  secret access is authorized for these gates.
- **Combined focused gate:** The privacy, provenance, configuration, endpoint,
  discovery, identity, qualification, candidate benchmark, runtime, transport,
  usage, CLI, manifest, and pipeline suite passed `679` tests in `91.03s`.
  `.venv/bin/python scripts/generate_release_schemas.py` then verified that the
  committed release schemas are synchronized. Paid provider tests remained
  disabled; no network, credential, or provider access occurred.
- **Pre-full-gate state:** The ticket remains `IN_PROGRESS` while the complete
  local release gate runs. The cumulative OpenRouter spend remains
  `0.0033415625 USD` with zero reservation.
- **Static complete gates:** `.venv/bin/ruff format .` reformatted `5` affected
  files and left `296` unchanged; `.venv/bin/ruff check .` passed; configured
  strict `.venv/bin/mypy` passed `135` source files. The complete pytest gate is
  the remaining long-running validation.
- **First complete pytest result:** `.venv/bin/pytest -q` failed with `127`
  failures, `1964` passes, and `10` explicit external/provider/isolation
  prerequisite skips in `233.06s`. The failures exposed that older synthetic
  REAL-usage helpers do not construct the newly mandatory policy/source/
  provenance routing, and older current-schema release-run helpers do not emit
  the now-required metadata artifact. Production checks remain fail-closed; the
  corrective scope is limited to coherent synthetic test fixtures.
- **Legacy-fixture correction:** The shared synthetic identity helper now adds a
  complete strict-ZDR policy/source/provenance route only when all privacy fields
  are absent and the fixture already declares ZDR plus denied data collection.
  Partial, malformed, or tampered privacy evidence remains untouched for
  negative tests. Direct generation, portfolio, and model-review builders use
  the same helper.
- **Release-fixture correction:** Current-schema release fixture writers now emit
  typed `final-findings.json` and privacy-identical `metadata.json` before
  sealing their manifests. The fail-closed production requirement was not
  changed.
- **Harness-canary correction:** The test-only paid-provider evidence writer
  distinguishes the non-secret `privacy_authorization` evidence label from an
  exact `Authorization` JSON key or a Bearer value. Credential-bearing surfaces
  and supplied canary values remain prohibited, with a two-sided regression.
- **Affected regression result:** The exact groups that accounted for the first
  complete-suite failures passed `405` tests in `13.68s`. A subsequent full
  static gate left `301` files unchanged, passed Ruff, passed strict mypy over
  `135` source files, verified schema synchronization, and passed
  `git diff --check`.
- **Complete local gate:** The second `.venv/bin/pytest -q` run passed `2092`
  tests with `10` explicit external-engine, isolation, loopback, and paid-provider
  prerequisite skips in `236.21s`. Paid provider execution remained disabled.
- **Final scope review before checkpoint:** `git diff --check` passed. The
  repository has only the intended privacy implementation, schema, packaged
  synthetic declaration/fixture, documentation, and regression changes.
  Secret-pattern review found only named synthetic test canaries and explicit
  header-redaction assertions; no credential or runtime/private artifact is
  staged. Ignored interpreter caches and pre-existing `.DS_Store` files remain
  outside version control.
- **Validated implementation checkpoint:** Commit
  `4da4fa08b66d0ebd04a2a8ae7d3bd181e140db33` contains the cohesive privacy
  profile, consent, source-provenance, route enforcement, cross-artifact
  validation, documentation, schema, and regression implementation.
- **Clean-commit source proof:** From that immutable checkpoint, the declared
  repository-owned provider-smoke fixture proved
  `DISTRIBUTION_COMMITTED_SYNTHETIC`, exactly one declared file, commit
  `4da4fa08b66d0ebd04a2a8ae7d3bd181e140db33`, and evidence SHA-256
  `e03048b1471bd08af8fd41b0cb585767cf407aeee9bf7697baf51c0b29db4899`.
- **Ticket result:** `V3-PRIVACY-001` is `COMPLETE`. This proves the local
  fail-closed privacy control and evidence path, not account-level OpenRouter
  guardrail state. Public benchmark provenance remains unavailable until
  independently established.
- **Operator pause:** Autorun is paused at the requested clean ticket boundary.
  No process, reservation, provider call, or uncommitted implementation change
  is active. On resume, begin `V3-OUTPUT-001`.
- **SSH publication:** Implementation checkpoint `4da4fa0` and state checkpoint
  `0195279` were pushed to `git@github.com:londonjevans/Auditor.git` on `main`.

## 2026-08-02 — V3-EFFORT-001 supplemental campaign closure

- **State:** `IN_PROGRESS` pending the complete local release gate.
- **Implementation:** A frozen exact-route plan now drives one full-corpus supplemental
  candidate benchmark for every distinct production reasoning profile not covered by the
  primary benchmark. A fresh private append-only campaign journal binds the registry,
  discovery snapshot, corpus, policy, effective configuration, cost ledger, reports,
  diagnostics, request/generation evidence, and ledger transitions. Only the original live
  campaign can issue the non-serializable content authority consumed by production
  qualification; a structurally valid resumed journal cannot regain that authority or begin
  provider work.
- **Qualification integration:** The workflow authenticates primary and supplemental
  generations as one bounded exact set, rejects report/request/generation/request-body reuse,
  and binds the plan plus opaque authority into the final resolver. Missing, malformed,
  low-scoring, or unauthenticated supplemental evidence keeps production selection false.
- **Independent review:** A read-only adversarial review accepted the live-authority,
  persistence, route, non-reuse, and readiness boundaries without a material defect.
- **Focused validation:** `.venv/bin/pytest -q
  tests/unit/test_candidate_reasoning_profile_campaign.py
  tests/unit/test_qualification_workflow.py tests/unit/test_model_qualification.py
  tests/unit/test_openrouter.py` passed `313` tests in `104.83s`. The reviewer independently
  reproduced the same `313`-test pass; affected Ruff and strict mypy passed. Pytest emitted
  inherited non-failing temporary-directory cleanup warnings only.
- **External effects:** None. No credential was read, no network or provider was contacted,
  and OpenRouter spend remains `0.0033415625 USD` with zero active reservation.
- **First complete-suite attempt:** `.venv/bin/pytest -q` produced `3722` passes and `15`
  explicit prerequisite skips, but exited nonzero with `71` local-loopback listener setup
  errors denied by the managed sandbox and one model-refresh staging regression. The staging
  regression had coupled an immutable `2026-07-30` fixture to the real wall clock, so it crossed
  the unchanged 30-hour freshness threshold on 2026-08-02 before reaching the intended invalid
  workflow-identity assertion. The test now supplies its existing fixed validation clock; its
  focused rerun passed. Production freshness thresholds and validation are unchanged.
- **Next safe action:** Run Ruff format/check, strict mypy, schema synchronization, and the
  complete pytest gate with local-loopback capability; then review, checkpoint, and continue
  with `V3-TOOLDIAG-001`.
- **Complete local gate:** `.venv/bin/ruff format --check .` reported all `385` files formatted;
  `.venv/bin/ruff check .` passed; strict `.venv/bin/mypy` passed `156` source files; release
  schema synchronization passed; and the correctly authorized local-loopback
  `.venv/bin/pytest -q` run passed `3798` tests with `11` explicit prerequisite skips in
  `776.53s`. `git diff --check`, untracked-file inventory, and changed-diff credential-pattern
  checks passed. No generated runtime artifact, credential, provider call, network egress, or
  OpenRouter spend was added.
- **Ticket result:** `V3-EFFORT-001` is `COMPLETE`. This proves the fail-closed local campaign,
  authority, reasoning-profile qualification, and evidence path. It does not claim that a real
  production ensemble has been qualified; that runtime requirement remains `V3-QUALIFY-001`.
- **Next ticket:** `V3-TOOLDIAG-001` per the queue's operator-approved macOS priority.

## 2026-08-02 — V3-TOOLDIAG-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Make supported scanner installations executable under the real macOS
  isolation backend, distinguish missing tools from isolated-execution/interpreter failures, and
  prevent raw untrusted version stderr or host paths from entering public reports.
- **Starting invariant:** Environment scrubbing, network denial, bounded subprocess execution, and
  fail-closed unavailable results remain mandatory. Read access may be added only for validated
  prefixes derived from the exact resolved toolchain in use; no unisolated fallback is permitted.
- **Local reproduction:** On the operator's Darwin host, resolution selected the supported
  Homebrew installations ahead of a shadowing Anaconda Slither. Sanitized, bounded `--version`
  probes for exact resolved Semgrep and Slither executables through the unmodified macOS backend
  both exited `71` with the sandbox-denial signature. The diagnostic emitted only typed booleans
  and exit codes; raw host-path-bearing stderr was neither copied here nor persisted as public
  evidence. This reproduces defect 1 before implementation.
- **Next safe action:** Map the resolver-to-backend-to-result-to-report flow and reproduce the
  recorded failure classes with synthetic local executables before implementing the bounded fix.
- **Implementation slice:** Added exact resolved-executable and shebang-chain validation, derived
  read-only Homebrew/MacPorts/pipx grants, private staged Semgrep rules, typed bounded version
  probes, path-safe public version validation, the interpreter/loader scanner status, and doctor
  preflight states. No unisolated fallback or network entitlement was introduced.
- **Focused validation command:** `.venv/bin/pytest -q tests/unit/test_reproduction.py
  tests/unit/test_scanners_reporting.py tests/unit/test_doctor_tool_preflight.py
  tests/unit/test_scanner_runner_source_binding.py tests/unit/test_runtime_evidence.py
  tests/unit/test_solidity.py`
- **Focused validation result:** `231 passed, 18 failed in 5.73s`. All 18 failures had the same
  fail-closed cause before target execution: the initial Darwin process inventory classified too
  few real-UID processes, so the derived `RLIMIT_NPROC` ceiling was already below the live login
  population. No failed test executed its scanner target. Independent comparison showed that a
  per-PID effective-UID inventory is unsuitable under the enclosing sandbox. The implementation is
  being corrected to use the fixed Darwin `PROC_RUID_ONLY` kernel filter and retain a fixed child
  allowance; this is a code defect under repair, not an external blocker or a waived gate.
- **Independent review findings under repair:** Public version validation must reject absolute
  paths after all punctuation delimiters and any value copied from the scrubbed process
  environment. Generic self-contained tool prefixes and indirect shebangs must either derive a
  narrow validated read root or fail closed. Darwin's unsupported `RLIMIT_AS` must not silently
  remove the memory bound; an explicit parent-side bounded memory observation is required.
- **Post-implementation focused validation:** `.venv/bin/pytest -q
  tests/unit/test_reproduction.py tests/unit/test_scanners_reporting.py
  tests/unit/test_doctor_tool_preflight.py tests/unit/test_scanner_runner_source_binding.py
  tests/unit/test_runtime_evidence.py tests/unit/test_solidity.py
  tests/unit/test_execution_origin_consensus.py tests/unit/test_execution_origin_reporting.py`
  passed `311` tests in `13.11s`. The extended formal, audited-suite, inventory, Hardhat, and fork
  matrix subset passed `197` tests in `5.13s`.
- **Real-integration race and correction:** The first post-monitor real Homebrew Semgrep run failed
  closed after `2.86s` because Darwin retained exited process IDs in a process-group inventory after
  `PROC_PIDTASKINFO` returned `ESRCH`. The run was killed, remained `UNVERIFIED`, and credited no
  finding. A bounded local churn assay reproduced `1,309` stale-membership observations among
  `1,312` short task-info reads. The monitor now clears errno and tolerates only the exact
  short-read-plus-`ESRCH` exited-process race; zero errno, `EPERM`, `EINVAL`, missing group evidence,
  and every other failure remain fail closed. Regressions cover each branch.
- **Real macOS acceptance command:** `.venv/bin/pytest -q
  tests/integration/test_macos_homebrew_scanner_isolation.py -vv` executed outside the enclosing
  managed sandbox so the real process-attested `sandbox-exec` boundary could run. Result: `1 passed
  in 3.83s`; exact Homebrew Semgrep executed against a synthetic local fixture, its target policy
  contained no network entitlement, and normalized evidence was nonempty.
- **Static validation:** `.venv/bin/ruff format .` left `388` files unchanged;
  `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed for `157` source files; and
  `.venv/bin/python scripts/generate_release_schemas.py` exited `0` with schemas synchronized.
- **First complete-suite command:** `.venv/bin/pytest -q` with local numeric-loopback listener
  capability enabled for the repository's local-only integration tests. Result: `14 failed, 3876
  passed, 11 skipped in 725.47s`. Every failure came from one helper in
  `tests/unit/test_execution_candidate_schema.py` using the synthetic combined string `forge 1.5.0
  / solc 0.8.30` as a `compiler_version`. Production constructs that field directly from
  `InvariantExecutionResult.compiler_version`, which is the isolated solc probe's single public
  version. The fixture was corrected to that production shape (`Version: 0.8.30`); the strict path
  validator was not weakened. Both affected files then passed `57` tests in `1.72s`.
- **Final complete-suite result:** The corrected `.venv/bin/pytest -q` run passed `3890` tests
  with `11` explicit external-prerequisite or opt-in skips in `720.28s`. The skips cover only the
  documented unavailable rootless image/external engines or explicit local compiler, replay,
  provider, scale, fork-matrix, and Foundry-fork opt-ins. Non-failing pytest cleanup warnings are
  inherited and do not affect execution evidence.
- **Final static and artifact gate:** `.venv/bin/ruff format --check .` reported all `388` files
  formatted; `.venv/bin/ruff check .` passed; `.venv/bin/mypy` passed for `157` source files;
  `.venv/bin/python scripts/generate_release_schemas.py` synchronized the release schemas; and
  `git diff --check` passed. Changed-file review found no generated runtime artifact or real
  credential. The only secret-shaped values in new tests are explicit synthetic canaries.
- **Ticket result:** `V3-TOOLDIAG-001` is `COMPLETE`. This proves the supported Homebrew scanner
  path on the real macOS isolation backend and the fail-closed diagnostic/version boundary. It
  does not credit a container executable from host identity; that separate contract is now an
  explicit `V3-HARDHAT-001` acceptance item.
- **Next ticket:** Create and publish this cohesive checkpoint, then begin `V3-HARDHAT-001`.

## 2026-08-02 — V3-HARDHAT-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Specify the trusted Hardhat reporter and implement a dedicated,
  capability-derived single-loopback execution boundary without treating host tool identity or a
  process stub as real container execution.
- **Starting invariant:** Reporter output is untrusted until strict schema, version, semantic, and
  source binding validation succeeds. The backend must expose exactly one read-only loopback RPC
  capability, no general network, no host credential or socket access, and no caller-supplied
  attestation authority. Missing real runtime or image-side executable identity remains
  `UNAVAILABLE`.
- **Next safe action:** Inspect the existing Hardhat adapter, parser, rootless isolation backend,
  configuration schema, and tests; record the minimal cohesive implementation boundary before
  editing production code.
- **Boundary map:** The existing parsers accepted self-hashed same-process Mocha output, but no
  independent authority proved that repository JavaScript had not forged its descriptors or
  replaced the shared output. The generic doctor path could also resolve a host `hardhat`, strip
  that absolute path to a basename at the image boundary, and then pair the image response with
  the host path. `ScannerRun` suite policy, workspace, RPC egress, and maximum-assurance authority
  remain Foundry-specific. These are fail-closed integration gaps, not real Hardhat evidence.
- **Completed identity guard:** `preflight_configured_scanner_tools` now handles Hardhat before any
  host `PATH` lookup and returns an image-side-attestation-required diagnostic with no resolved
  path or version. `.venv/bin/pytest -q tests/unit/test_doctor_tool_preflight.py` passed `17` tests
  in `0.79s`; affected Ruff checks passed. A required Hardhat scanner therefore fails doctor
  without falsely attributing a host executable to the image.
- **Reporter and protocol slice:** Added separate published inventory/test schemas and separate
  self-hashed phase-request schemas. The exact reporter version and committed source SHA-256 are
  constants; source is read with no-follow identity checks. Parser tests reject malformed,
  duplicate-key, non-UTF-8, oversized, truncated, version/hash/request/repository mismatches, and
  semantic inconsistencies. Reporter values remain untrusted observations with
  `authorship_claim=false` and `execution_credit=false`.
- **Source and exact-join slice:** A process-local, non-serializable authority independently
  inventories source through no-follow descriptors, validates the repository before/after, and
  binds only complete direct-literal root-project Mocha snapshots. Every selection count, profile,
  descriptor, configuration, request, inventory, and nested self-hash is revalidated between
  phases. Independent review reproduced and closed direct/destructured aliases, stale nested
  hashes, selection-accounting drift, division-token ambiguity, template interpolation, escaped
  identifiers, Node hashbang/legacy HTML comments, ECMAScript line terminators, and JSX/TSX inert
  text. JSX/TSX is now deliberately unsupported. The snapshot is not a complete JavaScript/Mocha
  proof and grants no runtime, output, coverage, or execution credit.
- **Single-loopback slice:** Added a network-none rootless wrapper with a fixed read-only source
  mount, disposable output/home/tmp, bounded resources, seccomp, fixed in-image `hardhat`/`node`
  tokens, and no host credentials or container socket. A bounded in-container raw relay exposes
  only one IPv4 loopback listener backed by the fixed AF_UNIX mount; JSON-RPC authorization remains
  exclusively in the host read-only bridge. The bridge now supports an exclusive owner-only
  `0600` AF_UNIX endpoint beneath an exact `0700` control-plane directory with retained directory
  and socket identity and race-aware cleanup.
- **Process-local authority:** Positive wrapper tests no longer monkeypatch fabricated authority.
  An opaque non-copyable/non-serializable lifetime handle joins the exact backend, bridge object,
  PID, private directory, socket, upstream endpoint and forwarding host/port, policy, pinned state,
  preflight identity, listener capability, dispatch object, live serve thread, and open admission.
  Stop, close, copy, serialization, replacement, mode drift, policy/state/backend/forwarder drift,
  dead listener, or admission shutdown invalidates command construction. This authority remains
  `UNVERIFIED` and cannot claim that a container or Hardhat ran.
- **Focused validation evidence:**
  - `.venv/bin/pytest -q tests/unit/test_hardhat_scanner.py tests/unit/test_hardhat_source.py
    tests/unit/test_hardhat_protocol.py tests/integration/test_hardhat_reporter_reference.py
    tests/unit/test_doctor_tool_preflight.py` — PASS; `107 passed in 1.42s`.
  - `.venv/bin/pytest -q tests/unit/test_hardhat_isolation_backend.py
    tests/unit/test_read_only_rpc_unix_bridge.py tests/unit/test_hardhat_loopback_relay.py` — PASS
    outside the managed socket restriction; `62 passed in 10.74s`.
  - `.venv/bin/pytest -q tests/unit/test_read_only_rpc_bridge.py` — PASS outside the managed
    socket restriction; all `76` existing TCP compatibility tests passed in `40.39s`.
  - `.venv/bin/python scripts/generate_release_schemas.py` and
    `node --check src/mmaudit/scanners/hardhat_reporter.cjs` — PASS.
  - Affected Ruff and strict mypy checks passed; `git diff --check` was clean before the final
    documentation and complete validation pass.
- **Honest integration boundary:** `command -v` resolves Node.js but not `hardhat`, `podman`, or
  `docker`; no approved digest-pinned image or image-side executable attestation is configured.
  The reference integration therefore runs the reporter in a real local Node process behind a
  handcrafted EventEmitter process double explicitly marked `MOCK`, not Hardhat/Mocha. It does
  not prove `.only`, pending/filter semantics, phase-one body non-execution, monorepo projects,
  container exit/output custody, or per-test relay attribution. The adapter remains
  `UNAVAILABLE`, and these real portions are `BLOCKED_TECHNICAL` rather than fabricated.
- **Independent authority review:** After closing mutable execution-credit, forwarding host/port,
  copied-bridge, dispatch-object, serve-thread, and admission-liveness gaps, the final bounded
  review found no remaining construction-time bypass. Constructed argv remains replayable and can
  outlive its seal, so a future real executor must retain and revalidate the exact binding at
  spawn and postflight; no current command receives execution credit.
- **Affected matrix:** The complete affected command listed above passed `266` tests in `52.44s`.
  Three tests skipped only because the rootless image and pinned integration-test compiler are not
  configured. These skips are the same explicit real-integration blockers, not passing evidence.
- **Pre-full-suite static gate:** `.venv/bin/ruff format .` left all `397` files unchanged;
  `.venv/bin/ruff check .` passed; strict `.venv/bin/mypy` passed all `160` source files; release
  schema verification and reporter `node --check` passed; `git diff --check` was clean.
- **Complete suite gate:** The exact `.venv/bin/pytest -q` command recorded in `LAST_COMMAND`
  passed `3992` tests with `11` explicit external-prerequisite skips in `724.16s`. Skips retain
  unavailable rootless image, Echidna, Halmos, Medusa, pinned compiler/replay, fork differential,
  realistic-scale AST, and paid-provider integration as unavailable; none was promoted to a pass.
  Two inherited stale temporary-tree cleanup warnings were non-failing.
- **Final diff and artifact review:** `git diff --check` passed. The changed and untracked inventory
  contains only the documented source, schemas, reporter, tests, and remediation records; no cache,
  log, run, or generated runtime artifact is present. Credential-pattern review found no private
  key, OpenRouter token, or credential assignment; its sole match was the intentional
  `synthetic-user:synthetic-password` URL rejection fixture. The `.env` file was not read. The
  committed reporter SHA-256 recomputed as
  `2269138b1383a5cc37da5914b89cbd3d7c22c9f80503a5f69ebe5e1f7e404226`, matching its source pin.
