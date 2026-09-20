# September 19 checkpoint preparation

Checkpoint ticket: `V3-BASELINE-001`, **BLOCKED_TECHNICAL**. The owner resumed the goal;
the September 15 pause no longer selects the work. This is a progress receipt,
not a green checkpoint, qualified audit, or authorization to commit or spend.

## Current blockers and work selection

V3-BASELINE-001 is now BLOCKED_TECHNICAL, not COMPLETE or PARTIAL.
The original catalog acceptance still fails at 234/768 stages under its unchanged
1800-second bound after three measured repair hypotheses. The unchanged native
replay assertions also fail with the production compiler/startup fixes: Echidna
2.3.3 emits no usable property identity, and Medusa 1.5.1 provides no validated
property-to-sequence join. The final-source full repository suite is still
unverified. Scoped passes do not waive any of these requirements.

The owner directly authorized the non-green checkpoint, now committed as
e85e115e45f05e298e4d00f1f27675a16ca8396e on agent/v3-wip-checkpoint.
Local Git confirms 648 changed files and parent68ebf039; no baseline acceptance
criterion was waived. The September20 direct request authorizes publication of
this checkpoint and its coordination receipt before new implementation.
This is checkpoint publication only, not a release or a provider command.
V3-INGEST-001 remains QUEUED/next (tier1), with45 unfinished tickets.

Latest relay b7d76f8ab98e81bb72b0e5af74a637dfcf4f5533c9dbdc3949523245e8b62804 /
501385 bytes /8068 lines, labelled2026-09-20T05:12Z, records the operator commit
and no push. Its label is retained as reported, not independently verified time.
Ledger-6 remains operator-reported376 entries/USD80.60224894; zero real audits.
The active selection plan, cost/privacy/lineage gates and nine false authorities
are unchanged. Native replay and final-source full-suite acceptance remain
INCONCLUSIVE; no provider/private-ledger action or deployment is selected.

The following chronology records prior baseline steps, not the current selection.

The native output diagnostic is terminal: two unchanged replay assertions fail,
plus one help-helper setup error. The corrected help-only check passes;
it does not rerun or supersede either native failure. Exact commands/results:
`native-replay-contract-initial312.xml` and `native-replay-help312.xml` under
the scratch directory below. No product parser or native assertion was changed.

## Scope and changes

The baseline precedes tier 1 ingestion. Preserve the large pre-existing dirty
worktree and the operator's AGENTS.md changes. HEAD is
`68ebf03918d375e1132db11ab60194285cf6706a` on `agent/v3-wip-checkpoint`.
Nothing has been staged, committed or pushed by Codex.

The initial six reproduced baseline defects have local repairs:

1. Default pytest collection used conflicting module basenames. The default is
   now `--import-mode=importlib`; no test was excluded or renamed.
2. The governance report parser could not represent named development Ledger-6.
   Its explicit label is now bound along with the exact report bytes and amount.
   A bounded single-line accounting annotation is accepted. Historical evidence,
   ambiguity refusals and all nine false authority fields remain intact.
3. Inventory fingerprints depended on Python's version-specific AST debug
   formatter. An explicit parsed-AST formatter preserves the old Python 3.13
   representation on 3.12. Its single new introspection locus is recorded under
   the existing runtime-package-integrity gate. No source or gate is dropped.
4. The synthetic refresh harness froze the client clock but not the routing
   clock. It now freezes both to the fixture time. A regression advances the
   clock to 2099 and still requires the production expiry check to reject it.
   No production expiry, route, cost, qualification or authority rule changed.
5. Two ancestry/discovery refusal tests assumed the mutable active plan was
   unavailable. They now load the existing unavailable-plan fixture explicitly;
   their exact refusal and no-I/O checks remain intact.
6. The benchmark schema test compared the published strengthened contract with
   Pydantic's unstrengthened schema. It now uses the canonical renderer and
   explicitly checks its extra mutation-portfolio constraint. No schema changed.

Subsequent full-suite-driven repairs include cross-version test compatibility,
observation-time identity in the assurance test cache, and a measured inventory
performance repair: observe model-owner source once per traversal, not per field.
The latter keeps fresh observation on subsequent traversals/builds and retains
every existing field fingerprint. The unchanged guarded cold-build test now
passes in 16.681 seconds under its original 30-second limit.
The differential fixture now uses the current report and retained-output contract.
The source-derived Foundry normalization gap has a bounded auxiliary-artifact
replay implementation; real native verification, re-execution and cleanup pass
on 3.12/3.13 (latest 18.13s/17.56s). Full affected-file checks pass 374 on each,
including 65 new regressions. Full inventory checks pass 262 on each;
Ruff, strict mypy, schemas and governance also pass. These are scoped results,
not a new full-suite pass.
Failed system-temp attempts remain recorded: exact ancestor ctime churn, not
source-content drift. The unchanged check passes in the approved disposable root
/Users/generalcuster/Documents/dev/mmaudit-local-verification.rJCVg5.

Current inventory: 6160 sources, 6163 occurrences, 6108 gated sources;
35 logical gates, 29 unsatisfied, 15 manual. Subsequent formal-supervision and
source-binding batch observations remain under existing gates. The source batch
adds five observations; removing exactly those recovers the prior input digests.
The property compiler adds exactly21 observed inputs under the existing managed
toolchain gate. Removing just those inputs recovers each predecessor family hash;
all prior IDs and dispositions are retained. Current mirrors are reconciled;
immutable historical JSON bytes and all authority fields are unchanged.

The next bounded catalog repair is now under test: necessary-literal screening
before the same secret regexes, with full Unicode/unknown-rule fallback and no
cross-call cache. The original ordered rules retain digest `4c54b9d1`.
On the identical 533534-byte synthetic claims envelope, paired medians were
0.027570s before and 0.004206s after (6.56x); these are microbenchmark results,
not a full-catalog capacity pass. Final broad checks pass 967 on each interpreter
and complete inventory checks pass 262 on each; static/schema checks pass. The
unchanged 256-primary / 768-stage / 385-midpoint acceptance is now terminal:
1 failed / 1855.38s on Python 3.12. It recorded198 mock responses and197
checkpointed stages before the original1800-second first-phase bound; neither
385 midpoint nor768 completion was reached. Preserve this and the earlier161
response failure. No identical retry without a measured new hypothesis. Current
inventory changes only the redaction module fingerprint, with every source and
gate disposition unchanged. See the latest worklog for live handles/results.

The formal runner now uses platform-correct UID/group supervision, preserves
CPU600/file100000000/FD256/memory4GiB bounds and fails closed when observation or
limit installation fails. Successful leader exit requires group cleanup; unknown
outcomes cannot fall through to SUCCESS. All385 affected-file checks pass on each
interpreter, including three benign real isolated-process controls. Original
native checks remain2failed/1passed each: compiler-child launch now progresses,
but Forge discovery/compilation and a separate version-probe gap remain unresolved.
Final13-file matrices pass648 checks on each interpreter, including all263
inventory checks. All original selected IDs remain; earlier11 historical-input
comparison failures are retained. No native engine pass or green checkpoint.

The unchanged three-stage/resume catalog profile now passes in201.66s after
the privacy screening (previous367.68s); full768-stage acceptance remains failed.
The measured source-binding hotspot has a descriptor-reuse implementation:
one held root per bounded tuple, every file reopened/read twice, fresh lexical
ancestry/root checks around every read, exact file identities and detached
expected bindings. All source namespace and original-tree guards remain live.
Complete13-file matrices pass439 checks on each interpreter (251.53s/250.08s),
including64 new unit and17 integration controls. Paired256-file binding replay
medians0.108533s→0.046581s show2.33x reader-only improvement. No capacity claim
follows from that microbenchmark. The unchanged controller diagnostic now passes
in183.85s versus201.66s, with the same147 corpus revalidations and92314 leaf
reads; source-root opens fall182397→52416. Whole inventory264 checks also pass
each,703 distinct affected/inventory tests per interpreter. Full acceptance remains.
First draft's boolean-size coercion failure is retained alongside its tested fix.

Original full catalog session97733 is now terminal:1 failed/1854.32s. Planning
53.226s; first phase1800.008s under its unchanged1800s deadline.234 mock stages
across78 primaries are checkpointed, with234 reconciled synthetic rows/USD2.34;
235 progress files and no active/uncertain liability in the last checkpoint.
Neither385 midpoint nor768 completion exists; resume was not reached. All
authority fields stay false and provider calls0. XML ee86ef0c/observation d8f5780e,
receipt catalog-sourcebatch-terminal-1533.json. Preserve both prior catalog
failures. No runtime/test/schema/fixture edits or heavy competing verification
occurred during this run. The separately named48-stage profile is now terminal:
1 passed/571.17s, with52.597s planning and517.285s profiled invocation. All48
synthetic rows reconcile;240 primaries remain pending and all authorities false.
Its overlapping cumulative measurements identify captured-tree single-binding
replay at59.246s; repeated whole-plan projection is21.277s, not107s per stage.

Captured-tree revalidation now uses the existing batch reader, without changing
the material/binding join, either namespace check, remapping replay or two fresh
reads per source. New controls16 pass; .venv full17-file matrix511 passes, and
both full inventory264 selections pass. Python3.12 first matrix510 passes/1
setup-custody failure is retained; unchanged owned-root full-matrix rerun26538
passes511/251.96s.775 distinct affected/inventory identities pass each, digest
fd866a92. Ruff1244, fresh mypy353 and schema verification pass. Identical48-stage
AFTER profile passes1/534.81s: invocation517.285s to481.664s,6.89% lower.
All1102918 fresh leaf reads remain; root opens296504 to59168. Captured-tree,
corpus, namespace and retained-file guard populations remain exact. No source,
test, schema, fixture or policy changed during profiling. All48 fixture rows
reconcile at synthetic USD0.48,240 primaries pending and authorities false.
Full commands/failures: captured-binding-batch-final-verification.json and
catalog-captured-batch-profile-terminal.json in the scratch root. The former
captures230 pre-final-note coordination passes; final coordination is checked
separately. No new full retry is selected solely on this small improvement.
No small diagnostic result substitutes for the original385/768 acceptance.

The pinned Foundry compiler handoff preserves exact declared Forge/Solc pins,
bounded private staging, source/settings, offline/FFI-disabled execution and
pre-dispatch revalidation. Its previous source boundary passed 1059 supporting
identities per interpreter but only three of four native compilation cases.
Those failures remain recorded; they are not current-source full-suite evidence.

The Echidna version preflight failure is now reproduced as a typed private-memory
limit violation, not an unsupported version. Fixed version-only GHC startup
(`-N1 -M512m`) restricts workers/heap while retaining the independent 1 GiB monitor.
Compiler probes and campaigns do not inherit that setting. The unchanged native
compilation selection now passes all four cases on Python 3.12 and 3.13
(17.26s / 17.04s). Complete affected checks pass 449 each, including 16 new
version-scope controls; whole inventory checks pass 265 each. These 718 distinct
identities match fresh collection on both interpreters, digest 1bba6bf9.
Ruff checks/format (1248 files), fresh strict mypy (353 sources) and both schema
checks pass. Only two existing inventory fingerprints changed; no input,
classification, gate requirement or authority was removed or relaxed.

This is compilation evidence, not native campaign/replay qualification or
transitive tool attestation. The configured compiler handoff remains Foundry-only;
unconfigured direct adapters carry no compiler provenance. Native structured
output/replay, original catalog capacity and final-source full-suite acceptance
remain open. Baseline IN_PROGRESS; no green checkpoint or tier 1 completion.

Native diagnostic11794 retained2 failures/14.01s; after explicit property selection,
Medusa-only68610 retained1 failure/1 deselected/9.87s. The original Medusa fixture
test now reaches matching COUNTEREXAMPLE property IDs, then fails on missing
sequence. Config-relative corpus nesting and unnamed raw sequence arrays are
observed, not accepted as machine-validated campaign evidence. Production adapter
currently parses stdout/stderr rather than those corpus files. The test-only
compiler workaround was not shipped at that boundary; the subsequent production
handoff above has separate48-unit and3pass/1fail native receipts. Exact prior
source delta, failures and supporting
XML joins are in medusa-property-prefix-final-verification.json in the scratch
root. Final-source full-suite acceptance is still required; no green checkpoint.

## Actual verification receipts

All paths below are under `/private/tmp/mmaudit-resume-baseline.xug3Ys`.
Matrices overlap; do not add their counts as unique tests.

| Check | Actual result |
|---|---|
| Echidna version-only startup, current12-file matrix | 449 passed each:3.12/33.36s,3.13/32.14s;16 new controls |
| Current whole inventory | 265 passed each:3.12/338.28s,3.13/272.20s |
| Unchanged native compiler selection after startup repair | 4 passed each:3.12/17.26s,3.13/17.04s; compilation only |
| Current combined selection | 718 distinct passing IDs each, exact fresh collection, digest1bba6bf9 |
| Current static/record checks | Ruff1248,mypy353,both schema checks pass;230 records pass/31.98s;governance exit0 |
| Typed Echidna diagnostic before repair | 3failed/1passed; each refusal exceeded unchanged1GiB private memory limit |
| Version-environment controls before implementation | 9failed/7passed; final16 all included in passing449 |
| Pinned property compiler, complete19-file matrix | 794 passed each:3.12/2396.29s,3.13/2252.46s |
| Compiler-input inventory | 265 passed each; combined1059 identical supporting IDs,digest348976f8 |
| Native pinned compiler, four cases | 3passed/1failed EACH; alternating Echidna preflight failure, not replay qualification |
| Compiler slice static/current records | Ruff1247,mypy353,schema checks pass;230 coordination passes; governance exit0 |
| Initial default collection | Exit 2; seven duplicate-basename errors |
| Collection/workflow focus | 36 passed, 3.54 s |
| Named-ledger regression | Before: 3 failed/5 passed; after: 8 passed |
| Governance/docs/objective/CI focus | 260 passed, 36.33 s |
| Fresh current records | 47 passed, 36.31 s |
| AST compatibility | 7 passed, 7.14 s; real 3.12 subprocess, all source modules |
| Inventory/runtime-input matrix | 328 passed/1 stale-artifact failure, 332.10 s |
| Corrected canonical-artifact case | 1 passed, 46.78 s |
| Synthetic clock/cost focus | 7 passed, 11.31 s |
| All five refresh-harness consumer files | 166 passed, 127.54 s |
| Ruff check / format | Pass; latest check: 1237 files already formatted |
| Fresh-cache mypy, `src scripts` | Pass; 353 source files on both interpreters |
| Schema verification | Exit 0 on both interpreters; no schema rewrite |
| Governance CLI | Exit 0; 44 unfinished, NONAUTHORIZING |
| Fresh complete collection | 21044 tests, 734 files, zero collection errors |
| Final Foundry affected-file matrix | 374 passed on each interpreter; 36.89s/38.20s |
| Final complete inventory file | 262 passed on each; 308.53s/245.93s |
| Final real local Foundry replay/cleanup | 1 passed on each; 18.13s/17.56s |

The complete collection's sorted node-ID digest is
`1725b1f6741152bec64f52fc7630d39018a4ed6f2df5f7abdd68b1007e3f81ab`.
**There is not yet a full-suite pass on this checkpoint.**

Initial full fail-fast execution ended with 246 passed, 1 failed, 1 skipped in
583.16 s on stale coordination. The five cost-adoption CLI cases subsequently
passed. A subsequent four-group diagnostic exposed six expired-harness failures
and was deliberately interrupted: group 0 had 81 passes; group 1 had 211 passes
and one unavailable-rootless-image skip; group 2 had 214 passes. Group 3 caught
two interrupts inside a test and required SIGTERM of the verified owned PID
84665; exit 143, no complete result. None is a full pass. Preserve their XML and
tool outputs. Do not recycle their basetemp or receipt paths for the fresh run.

## Forge and unavailable checks

Both `forge build --offline` and `forge test --offline` were actually run on all
40 fixture trees. Exact argv, exits, timings and bounded stdout/stderr are in
`forge-results.json`; `output_truncated` explicitly marks 2500-character tails.

- Builds: 30 exit 0; ten cannot obtain uncached solc 0.8.20 offline.
- Tests: three exit 0; 18 nonzero negative-fixture suites report failures in
  deliberately unsafe invariant controls; nine have no Forge test harness;
  ten cannot compile without solc 0.8.20.

Keep the nonzero outputs, including negative controls, as nonzero outputs.
Missing compiler/harness checks are **INCONCLUSIVE**, never passes. No fixture or
compiler pin was relaxed. Already cached 0.8.30 was selected explicitly only for
matching 0.8.30 projects; unpinned projects selected cached 0.8.36.

Python 3.12.14 initially lacked project dependencies. They are now provisioned
as recorded below. The pure AST comparison alone did not establish a supported-
version runtime-suite or schema-generation pass.

## Operator-only dependency step — executed; do not repeat

Codex runs offline local verification. Downloading a missing compiler is an
operator action. This exact command provisions the fixture's pinned compiler
through the installed Forge and builds only the local synthetic fixture:

```sh
cd /Users/generalcuster/Documents/dev/Auditor
/Users/generalcuster/.foundry/bin/forge build \
  --root tests/fixtures/solidity/foundry \
  --out /private/tmp/mmaudit-resume-baseline.xug3Ys/operator-solc020/out \
  --cache-path /private/tmp/mmaudit-resume-baseline.xug3Ys/operator-solc020/cache
```

The operator has executed this command, as recorded in the relay entry labelled
2026-09-19T06:41Z. It intentionally lacked `--offline` to provision the compiler. No model,
RPC, secrets file, private ledger, qualification, seal or deployment is involved.
Codex read the relay and reran all20 affected offline commands: nine builds
succeed; semantic_malformed correctly remains uncompilable; full_protocol_offline
passes three tests; seven projects have no Forge harness; semantic_malformed's
test command fails compilation; foundry/VaultAuditTest fails not-owner. The latter
is an explicit nonzero result, not a pass. Receipts are in
`forge-solc020-recheck-results.json`; the original80 receipts remain.
The separate Python 3.12 environment is now available; `.venv` is unchanged.

### Isolated Python 3.12 dependency request — executed; do not repeat

To run the supported-version checks, provision a separate disposable environment
with the exact package versions already installed in `.venv`. The requirements
file was generated from local distribution metadata, not a new dependency choice.
This command downloads packages; the operator alone runs it. It refuses to
overwrite an existing environment and leaves `.venv` unchanged:

```sh
(
  set -eu
  cd /Users/generalcuster/Documents/dev/Auditor
  test ! -e /private/tmp/mmaudit-resume-baseline.xug3Ys/python312
  /opt/homebrew/bin/python3.12 -m venv /private/tmp/mmaudit-resume-baseline.xug3Ys/python312
  /private/tmp/mmaudit-resume-baseline.xug3Ys/python312/bin/python -m pip --isolated install \
    --index-url https://pypi.org/simple \
    --requirement /private/tmp/mmaudit-resume-baseline.xug3Ys/python312-verification-requirements.txt
  /private/tmp/mmaudit-resume-baseline.xug3Ys/python312/bin/python -m pip --isolated install \
    --no-index --no-deps --no-build-isolation --editable .
)
```

The relay labelled 2026-09-19T06:58Z records the actual result and one deviation:
the editable install failed because `editables` was absent; the operator chose
and installed `editables==0.5`, then repeated the final step successfully.
Codex verified the interpreter, local import and dependency versions offline.
The focused three-file baseline matrix now passes 51 tests on each of Python
3.12 and 3.13 (3.87 s and 3.68 s). Receipts are `stale-tests-after-py312.xml`
and `stale-tests-after-py313.xml`; the two earlier failing receipts remain.
This is not a full-suite pass. No further dependency command is current.

### Full-v2 terminal failures and generated-cache recovery

All four groups stopped nonzero: group 0's stable-root retry had 1951 passes and
one stale relay-binding failure; group 1 had 730 passes and one stale plan-test
failure; group 2 had 3099 passes and one fixture-inventory failure; group 3 had
483 passes, one schema-test failure and one unavailable-filesystem skip.
The original group-0 run had 1685 passes and a custody race; its unchanged
single-test and whole-file retries passed. These overlapping counts are not a
full-suite result. All XMLs and command manifests remain in the scratch root.

The inventory failure was caused by this turn's Forge run: its failure caches
are independent of `--cache-path`. Fifteen generated, untracked economic cache
directories created at 06:06:30–34 UTC were validated and moved, not deleted,
to `forge-cache-quarantine` under the scratch root. All five release-static
tests subsequently passed on both interpreters. Future Forge commands must
redirect test failures and both fuzz/invariant persistence, or run a disposable
fixture copy; do not weaken the fixture-inventory guard.

The next complete run uses the supported Python 3.12 environment without
fail-fast, preserving every failure and skip rather than repeatedly stopping
before the unexecuted portion. The changed test files define a new source epoch.

## Resume / checkpoint boundary

Original full supported-version run: `full-run-v3.json` in the scratch root;
all four sessions are terminal exit 1, **21044** tests, no fail-fast.
Group 2 is terminal exit 1: 4449 passed, 24 failed, 32 errors, 4 skipped.
Group 3 is also terminal exit 1: 5010 passed, 31 failed, 71 errors, 22 skipped.
Group 1 is terminal exit 1: 5340 passed, 33 failed, 10 errors, 12 skipped.
Group 0: 5948 passed, 21 failed, 28 errors, 9 skipped.
Combined: **20747 passed, 109 failed, 141 errors, 47 skipped; NOT GREEN**.
All 21044 unique identities match a fresh unchanged collection exactly.
The original compact-JSON selection digest is
`9d561b572cd5265d0fe3bfe4c2c515310275c59e5cc35618edfdb454255e6a32`.
Receipts: `full-v3-identity-reconciliation.json`, `full-v3-final-reconciled.json`.
The first summary used newline serialization; retain that intermediate mismatch
as well as the exact subsequent reconciliation. No test disappeared.
The full 256-primary / 768-stage catalog case hit its unchanged 1800-second
first-invocation bound after 161 mock requests. The 385-stage midpoint and
768-stage completion remain unproved. This is a current capacity failure;
retain the original population/deadline, not just smaller passing diagnostics.

Scoped, unchanged local-socket reruns pass 138 unit and 52 integration tests on
each interpreter; a further 20 integration tests pass on Python 3.12. Eight
offline native Forge coverage cases pass after permission for the nested
no-network sandbox. Original denied runs remain recorded, not erased.

The cleanup-test discrepancy is now reproducible: repository-contained basetemp
causes the repository-path rejection to precede the intended alias rejection.
The planned test isolates its own synthetic repository cwd. Separately, this
agent's custom PYTHONPYCACHEPREFIX causes two compiler-capture refusals; the
unchanged cases pass without that override. Omit it in subsequent verification;
do not relax compiler runtime-file custody.

The reviewed draft `baseline-test-compatibility.pending.patch` in the scratch
root covers seven existing test files. A second draft,
`baseline-real-integration.pending.patch`, removes one unsupported test-helper
keyword in the now-exercised local differential integration. Both were applied
at 10:44:02Z, after full-v3 terminated. Those eight-file runs are terminal:
3.12:474 passed/2 failed/915.10 s; .venv:475 passed/1 failed/597.83 s.
All 474 original identities and two new regressions ran.
A quiet cold-inventory retry failed at its unchanged 30-second bound
(1 failed/30.41 s). Profiling then isolated repeated owner-source inspection;
the subsequent repair passes the original guarded test in 16.681 s. The complete
owner/semantic-drift focus passes 3/49.37 s. Concurrency was not the sole cause.
The late manifest integration exposed missing observation time in the assurance
test-fixture cache key. The regression reproduced red before repair; callers
now use their runtime's recorded time. Corrected cache/manifest focus passes
9/449.55 s on 3.12, with production refresh expiry unchanged. Initial whole-file
attempts were deliberately interrupted after six caller failures on each
version; they are incomplete, not passing evidence.
Unchanged pipeline/Slither integrations now pass on both interpreters in a
stable owned temporary tree; the earlier custody refusals are retained.
Exact commands/results are in `additional-native-1008.json` and the worklog.

Explicit installed Medusa 1.5.1 and Echidna 2.3.3 checks fail on both Python
versions: each matrix records two failures and one passing timeout control.
Benign child-process probes isolate the formal runner's NPROC64 compiler-spawn
failure. They also show its requested address-space limit is not installed on
this host. Existing scanner supervision has separate Darwin process/memory
handling; no such repair or resource-policy change has been applied to formal
execution. Preserve these failures and the original catalog capacity failure.

Fresh 3.12 schema verification, governance, .venv Ruff and strict mypy on both
interpreters have passed. This is **not a full-suite pass or a green checkpoint**.
Candidate-v3 fingerprint:
`b1c933a682d87b87db2eb94e83a4ab76d775069e3b219426ce95a1eb6dad4316`.
Only documentation changed during that original run. Subsequent corrections
start a new source epoch. The original eight were test-only; the later inventory
optimization changes one production module and its generated/current bindings.
No cost, route, qualification or authority policy changed. Compared with the
original candidate at that earlier boundary, exactly eighteen public paths
differed; unrelated dirty work was preserved, nothing staged. That provisional
candidate fingerprint, not a green
checkpoint: `60c4c81a729104a3cb92689c10299e8ba3028613a12f5f947e3b99bdcada8ad6`.
The subsequent Foundry repair changes production, tests and current inventory
bindings; do not reuse that snapshot as final-source acceptance.

The missing Foundry normalization is now implemented, not allowlist-bypassed.
It reobserves original per-test artifacts through bounded descriptor custody,
reconstructs executions and findings from native Forge JSON, and compares the
whole finding stream. Empty streams retain no finding authority. Failure-gap
and debugger records cannot supply successful finding or coverage authority.
The exact original native failure remains in both ten-file receipts.

Sessions **38508 / 45761 are terminal**, each 723 passed / 1 failed out of
724 exact identities. Fresh collection and both XMLs share compact-JSON digest
`6abaa47f37dcd81199adeb8e9cfd477f4ecf889f7b5b0521b1e5abd673916b89`;
no missing, extra or duplicate identity. They are not retroactively green.
Final affected-file checks pass 374 on each interpreter, inventory checks pass
262 on each, and the real local differential matrix now passes on each with
CURRENT verification, native replay and workspace cleanup. Shared-temp ctime
failures stay recorded; final native checks use the approved disposable root.

Exact commands and terminal output are in `foundry-replay-progress-1226.json`;
all scoped XML hashes/outcomes and the 724-ID joins are in
`foundry-replay-reconciled.json`. Initial schema `--check` invocations failed
with exit 2; corrected no-argument verification exits 0 on both interpreters.
No test session remains live at the 12:26:54Z boundary. Broader full-suite
final-source acceptance is outstanding; catalog capacity and formal process/
memory failures remain. Next bounded repair is the original catalog capacity
failure, without narrowing its population or increasing its deadline.

The original
four invocations covered a disjoint partition of every collected file; no test
was excluded. Retain the selection manifest, terminal statuses, XML results and
source fingerprint. Focused retries do not erase original failures or establish
a new full-suite pass.

The earlier `checkpoint-candidate.json` is a **draft**, not a stage list: it
predates the clock-harness repair and this note. Refresh it after validation,
check for concurrent operator edits, and issue an exact reviewed operator-only
commit command only when the checkpoint is ready. Never use `git add .` to
absorb unrelated or ignored material. No commit or push command is current.

Next product work is tier 1 ingestion: start with the recorded `lib/` starvation,
dotfile/omission handling and retained remappings on a realistic local fixture.
Then address the forge-fmt fallback-parser crash and large-file/per-shard
degradation. Do not resume AUTOPARTITION merely because the historical queue
put it first. No second engineering ticket has started at this boundary.

The owner-authorized local-seal objective addendum remains pending an explicit
hash-bound implementation; it was not silently adopted by baseline repair.
Latest operator evidence is the capacity-deferral proposal labelled
2026-09-19T15:40Z, report digest
`fa01dc4796dd88482474335be690d42e79d75a497ad01f6403dfb08318f076e0`:
development Ledger-6, 376 entries / USD 80.60224894, zero completed real audits.
Its proposed checkpoint exception and deferral to tier2 are explicitly raised
for a direct owner decision, which is pending. Neither that proposal nor reported
host attribution establishes a final-source full-suite pass or authorizes a commit.
Its quality observations remain unresolved product evidence, not authority.

The operator report and its current-record rebind changed documentation during
full-v2. Tests were then repaired after those groups stopped. Do not claim the
original whole-tree digest is unchanged; retain every manifest and refresh the
final-source validation evidence before any checkpoint command.
