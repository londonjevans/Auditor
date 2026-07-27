# Corrovera Security

## Independent fit-for-purpose evaluation of mmaudit

**Evaluated release candidate:** `e304807cf942542706b88544fa216516f8f95cad`

**Evaluation window:** 2026-07-27 11:41:33Z–12:21:37Z

**Evaluation mode:** clean archived source, local/offline execution, no implementation repair

**Evaluator limitation:** this was an implementation-independent local acceptance exercise, not
an accredited external laboratory assessment or an independently adjudicated professional audit.

## Verdicts

| Product verdict | Result |
|---|---|
| `FIT_FOR_PURPOSE` | **FAIL** |
| `MAXIMUM_ASSURANCE_IMPLEMENTATION` | **FAILED** |
| `SUPERIORITY_STATUS` | **NOT_EVALUATED** |

The frozen candidate does not satisfy the operator's stated maximum-assurance purpose. It has
useful, strongly typed defensive components and real bounded Foundry regression execution, but
it cannot run the claimed model/tool portfolio in this release configuration. More importantly,
the maximum-assurance contract can report `COMPLETE` when compilation failed, when a critical or
high reproduction attempt did not reproduce, and when complementary fuzz/formal engines are
absent unless the operator separately opts into narrower gates.

The ordinary test suite passing does not change this verdict. The suite passed `636` tests, while
the nine skipped cases are precisely the unavailable real engines, hardened isolation, real
isolated replay, and local-chain capabilities needed to support the broader claim.

## Frozen build

| Item | Recorded value |
|---|---|
| Git commit | `e304807cf942542706b88544fa216516f8f95cad` |
| Git tree | `5709cc28f76856e98b18dfb1daeb955ee969d53a` |
| Dirty at freeze | No |
| Snapshot method | `git archive` into separate frozen and disposable trees |
| Archive SHA-256 | `299b1b3ef5707d60be73bcfbd7af47bbf8b71a03a5a26c496758538ca7d13e3a` |
| Source files | `447` |
| Source-hash-manifest SHA-256 | `be3e307f29780e15108e2cef06010f47cfb3130cbe11d9f206911c9a44ad5464` |
| Main config SHA-256 | `9772a68e007fc11c60c146273378549106c0e19d996e6d5bfc04dde50eef8304` |
| Prompt-manifest SHA-256 | `455221ae6589c13dc0e978bcd1d2219b1aceeb3ee2290262414425e0755114b1` |
| Schema-manifest SHA-256 | `39c246e30dfb6087d8e9b77ae536f829a51ccbb9ba1670da6b9c9a4572e4e8bd` |
| Model-selection SHA-256 | `05de45c23943626a02abbb2d9b6563eae548ea90f345a201a187354f28935570` |
| Benchmark corpus | schema `2.0`, 28 synthetic cases, 2 synthetic repositories |
| Benchmark corpus SHA-256 | `186534e1d0d263920d42041e39b05fd6fb4acc57f5e7e4c9c1321a403756845b` |
| Ground-truth version | No independently versioned artifact; ground truth is committed in the corpus manifest |
| Isolation backend | None |
| Container digest | None |
| Host | macOS 26.5.2, Darwin 25.5.0, arm64 |
| Evaluation Python | 3.13.4 |

All individual config, prompt, schema, binary, corpus, and artifact fingerprints are recorded in
[the machine report](fit_for_purpose_report.json) and
[the tool matrix](tool_execution_matrix.json).

## What was actually executed

The following are real local observations, not queue labels:

- The full frozen-source suite completed with `636 passed, 9 skipped in 134.66s`.
- The focused benchmark/model/reproduction/isolation slice completed with
  `199 passed, 3 skipped in 5.06s`; the three skips all required an unconfigured
  rootless image.
- Real offline Foundry/solc execution covered 43 known property harnesses:
  21 intentionally unsafe controls produced the expected counterexample twice and
  22 safe controls passed. The persisted temporary report has file SHA-256
  `d23019721216acf45096bbd7838191584f65fff07cfd64f72b28a377c4f51ed0`
  and internal report SHA-256
  `c760364b540f9bbc00b8d354d211cd9c35905f0370516faa0013c2acb929f71b`.
- A credential-free maximum-assurance invocation exited `2`. Run
  `20260727T114638Z-5641e2ed` was incomplete, quality status `failed`, and maximum
  assurance `INCONCLUSIVE`. It made zero model calls and executed no scanner or
  formal engine because hardened isolation was unavailable.
- Re-verifying that run exited `6` as `STALE` with four configuration mismatches.
  A CLI profile override changes effective hashes, but `verify-run` has no equivalent
  profile override, so the emitted run cannot be reproduced as current through that CLI path.
- The maximum-assurance benchmark was run against an intentionally empty immutable report
  directory. It exited `6` as `incomplete`, loaded zero of two required reports, and kept
  superiority `not_evaluated`.

The Foundry figures prove bounded property-regression execution against known fixtures. They do
not measure mmaudit's ability to discover those unsafe conditions from source and must not be
reported as audit recall or precision.

## Requirements traceability

The full matrix is in [requirements_traceability.json](requirements_traceability.json). The
conservative high-level result is:

| Requirement family | Classification |
|---|---|
| Bounded synthetic Foundry economic/property portfolio | `PROVEN_REAL` for fixture execution only |
| Offline scope, snapshot, prior-audit, source-binding primitives | `PROVEN_REAL` or `PARTIALLY_PROVEN`, as individually recorded |
| Compilation, reproduction, and maximum-assurance status integrity | `PARTIALLY_PROVEN`; material contract defects observed |
| Echidna, Medusa, Halmos, Kontrol, Certora adapters | `PROVEN_MOCK_ONLY`; real integration blocked |
| Slither, SMTChecker, Mythril negative controls | `IMPLEMENTED_NOT_EXECUTED` |
| Real independently qualified model ensemble | `BLOCKED` |
| Model orchestration, cross-examination, falsification, judgment | `PROVEN_MOCK_ONLY` |
| Semantic and coverage completeness | `PARTIALLY_PROVEN` |
| Security mutation effectiveness | `PARTIALLY_PROVEN`; five of eleven transforms, no real kill score |
| Audit benchmark, public time-split, private holdout, human comparison | `IMPLEMENTED_NOT_EXECUTED` or `UNIMPLEMENTED` |
| Real rootless containment and isolated replay | `BLOCKED` |
| Release acceptance | `BLOCKED`; committed release report records 8/12 gates passed and is not bound to this commit |

Documentation and `COMPLETE` queue labels were not accepted as runtime proof.

## Assurance-contract negative evaluation

| Deliberately missing or failed prerequisite | Observed result | Acceptance |
|---|---|---|
| Model key | `doctor` exit `2` before provider access | Fail-closed |
| Too few model families | Deterministic validation rejected the config | Fail-closed |
| Unavailable model | Placeholder config rejected; real unavailable response only mocked | Partial |
| Missing fuzzer | Baseline without Echidna/Medusa returned `COMPLETE` | **Violation** |
| Missing formal engine | One `UNAVAILABLE` formal record returned `COMPLETE` | **Violation** |
| Missing benchmark evidence | Returned `COMPLETE` while benchmark gate remained default-off | **Violation** |
| Stale benchmark with gate explicitly enabled | Rejected in focused tests | Fail-closed only when opted in |
| Missing isolation backend | Returned `FAILED`; real run stopped | Fail-closed |
| Unpinned image | Rejected by configuration test | Mock/unit proof only |
| Network-enabled untrusted execution | Command construction rejects it | No real container proof |
| Missing economic harness | Applicable untyped/missing harness test failed the clause | Fail-closed in unit evidence |
| Failed reproduction | `NOT_REPRODUCED`, attempts `1`, returned `COMPLETE` | **Violation** |
| Invalid source location | Local validation rejected it | Fail-closed in deterministic evidence |
| Compilation failure | `FAILED` compilation returned `COMPLETE` | **Violation** |
| Incomplete scope manifest | Returned `FAILED` | Fail-closed |

The decisive direct assay output was:

```text
baseline_no_echidna_medusa COMPLETE failed= none
compilation_failed COMPLETE failed= none
formal_only_unavailable_record COMPLETE failed= none
formal_inventory_missing FAILED failed= formal_adapter_inventory
failed_reproduction_attempt COMPLETE failed= none
missing_isolation FAILED failed= hardened_dynamic_isolation
missing_model_reviews FAILED failed= multi_agent_review,critical_model_surface_review
missing_benchmark_default COMPLETE failed= none
missing_benchmark_when_opted_in FAILED failed= benchmark_regression_gate
required_echidna_missing COMPLETE failed= none
required_echidna_explicit FAILED failed= required_formal_tool:echidna
```

The exact inline assay source and interpreter invocation are retained as
`CMD-ASSURANCE-ASSAY` in the machine report.

## Real engine execution

| Engine | Installed | Target really analyzed | Unsafe and safe controls | Result |
|---|---:|---:|---:|---|
| Foundry unit/property/invariant | Yes | Yes, bounded synthetic fixtures | Yes | Real component evidence |
| Slither | Yes | No | No | Blocked by hardened isolation |
| Echidna | No | No | Conditional test skipped | Mock adapter only |
| Medusa | No | No | Conditional test skipped | Mock adapter only |
| Halmos | Yes | No | Conditional vulnerable control skipped; no safe control | Blocked by hardened isolation |
| Kontrol | No | No | No | Mock adapter only |
| Certora | No/disabled | No | No | Mock adapter only |
| solc SMTChecker | Compiler present | No formal target run | No | Inconclusive without isolation |
| Mythril | No | No | No | Unavailable |

Forge was version `1.3.2-stable` at SHA-256
`c0ed9870bf0637ce351ef70e347bcf8ab5e23c4cc12d32ef6fdf4eb1d97116ee`.
Slither `0.11.5` and Halmos `0.3.3` were discoverable, but discoverability was not counted
as execution. Complete paths, versions, checksums, targets, limitations, and artifacts are in
[tool_execution_matrix.json](tool_execution_matrix.json).

## Model-ensemble reality

No production `mmaudit.toml` exists in the candidate. The example config contains 31 placeholder
slots, an empty registry, no immutable real lineages, and no benchmark-bound quality records.

| Observation | Result |
|---|---|
| Exact real model IDs called | None |
| Providers contacted | None |
| Provider fingerprints | None |
| Successful/invalid responses | `0` / `0` |
| Retries/substitutions | `0` / `0` |
| Source surfaces supplied to real models | None |
| Real model-review coverage | Not evaluable |
| Cost and latency | Not evaluable; observed cost `0` only because no calls occurred |

Alias deduplication, blind ordering, candidate ownership, evidence caps, verifier/falsifier
restrictions, and judge monotonicity have deterministic fake-provider coverage. They are not real
ensemble evidence. In addition:

- family diversity is partly inferred from provider/model strings rather than independently
  verified immutable root lineage;
- a registry `quality_measurement` is shape-validated but not resolved to a passed benchmark;
- any successful generic response is credited for every deterministic surface included in its
  context, without proving that the response reviewed each surface.

See [model_execution_matrix.json](model_execution_matrix.json).

## Five benchmark layers

### A. Must-catch security regressions

`NOT_EVALUATED` as an audit-discovery benchmark. No product reports were generated for either
benchmark repository. The empty-report evaluator recorded 0/13 detections and 0/13 exact locations,
but those zeros represent absent reports, not a measured completed audit.

The separate Foundry property portfolio passed 21/21 unsafe and 22/22 safe controls. That is
component remediation validation, not critical/high recall or confirmed precision.

### B. Security mutation testing

`NOT_EVALUATED` for mutation kill rate. Five implemented transforms apply, revert, and compile:
authorization guard removal, replay update removal, comparator change, accounting-operator change,
and external-call result-check removal.

Six requested classes are absent: stale-price validation, external-call/state-update reorder,
initializer protection, timelock weakening, storage-slot change, pause enforcement, and
decimal-scale alteration. Existing scorecard tests construct killed evidence; they do not run
mmaudit end to end against mutants. The mandatory 95% gate is therefore not measured.

### C. Public real-world time-split corpus

`UNIMPLEMENTED`. No post-cutoff public corpus, frozen pre-disclosure reports, or independent
adjudication exists.

### D. Private or blinded holdout

`NOT_EVALUATED`. No operator-provided private holdout exists. Public or internal fixtures were not
substituted.

### E. Human comparison

`NOT_EVALUATED`. There is no blind identical-commit/scope run against independently adjudicated
expert findings. Superiority is therefore not evaluated.

Machine-readable detail is in [benchmark_results.json](benchmark_results.json).

## Required quality metrics

| Metric | Product result |
|---|---|
| Critical, high, medium recall | `NOT_EVALUATED` |
| Confirmed precision | `NOT_EVALUATED` |
| False-confirmed critical/high rates | `NOT_EVALUATED` |
| Safe-near-miss rejection | `NOT_EVALUATED` for audit discovery; bounded property controls 22/22 |
| Exact-location accuracy | `NOT_EVALUATED`; deterministic validator tests pass |
| Attack-path/reachability accuracy | `NOT_EVALUATED` |
| Reproduction success | `NOT_EVALUATED` for findings; bounded property replay 21/21 |
| Symbolic counterexample success | `NOT_EVALUATED` |
| Formal property mutation score | `NOT_EVALUATED` |
| Invariant mutation score | `NOT_EVALUATED` |
| Contract/entry-point/privileged/asset-moving/external-call coverage | `NOT_EVALUATED` for a completed run |
| Model-review coverage | `NOT_EVALUATED`; zero real calls |
| Economic applicability/execution coverage | Known-fixture component: 43/43; real audit run: not reached |
| Average/worst cost | `NOT_EVALUATED`; observed zero is a no-call result |
| Audit runtime | `NOT_EVALUATED`; test suite 134.66s and economic slice 27.12s |
| Confidence intervals | Not statistically meaningful without completed blind samples |

None of the internal minimum product gates is accepted as passed from this evidence. In particular,
critical recall, safe false-confirmation rates, mutation kill rate, and source-location accuracy
were not measured on completed product reports. The no-missing-engine and no-isolation-escape gates
failed or were not evaluable.

The empty-report evaluator also has two misleading subgates: semantic coverage and safe-control
false confirmation pass vacuously when zero reports are loaded. Overall status remains incomplete,
but those subgate denominators are not acceptable assurance evidence.

## Reproduction realism

No confirmed dynamic witness exists in the evaluated run, so witness-by-witness realism is
`NOT_EVALUATED`.

The typed DSL and capability policy reject direct attack-phase storage mutation, bytecode
replacement, signing/broadcasting, FFI, shell injection, and test-only time controls. Integrity
models bind declared source, replay, reachability, minimization, and single-asset settlement.
Most of those flows are fake-runner tested.

Remaining gaps are material:

- target identity hashes declared aliases/addresses/chain/block but does not query and compare
  deployed runtime bytecode with compiled audited source;
- bounded `vm.deal` setup is justified and capped, but does not prove the actor held the assets at
  a pinned real state;
- financial settlement is single-asset and omits an explicit victim/protocol loss field;
- cross-asset value, gas, liquidity realism, and an actual isolated witness remain unproven.

## Adversarial isolation

The selected backend was `none`: Docker, Podman, and bwrap were absent; nested
`sandbox-exec` was unavailable; no pinned image digest was configured.

Deterministic tests prove rejection or bounding for repository-local fake binaries, symlink/path
escape, hardlinks/special files, control filenames, prompt text delimiting, subprocess timeout,
and output flooding. Rootless command construction specifies read-only source, private output/home,
no network, dropped capabilities, seccomp, and resource limits.

Those controls were not executed in a real rootless container. Three real-rootless acceptance
tests skipped, and the adversarial manifest has only ten cases. SSH-agent access, cloud
credentials, real memory exhaustion, comprehensive Unicode/case collisions, and generated-file
poisoning are missing or not exercised. `no isolation escape` is therefore `NOT_EVALUABLE`.

See [isolation_results.json](isolation_results.json).

## Report quality

The finding schema and surviving-finding Markdown support location/symbol, preconditions, attack
path, severity/confidence, evidence, verifier, cross-examination/falsifier, remediation, residual
uncertainty, and disagreement. Formal status is not a dedicated per-finding report field.

No frozen real report contains a sample across confirmed, strongly supported, inconclusive, and
rejected findings, so semantic report quality is not manually evaluable. Fake-provider tests are
the only multi-status report evidence. The human-readable rejected-findings section also collapses
each proposal to identifier, title, and disagreement, omitting the complete evidence fields
required by this evaluation.

## Material defects and acceptance gaps

1. Compilation failure can satisfy the maximum-assurance contract.
2. An unsuccessful high/critical reproduction attempt can satisfy the contract.
3. Complementary fuzz/formal engine success is optional unless separately configured.
4. Missing Slither can evade the standalone scanner clause if another scanner succeeds.
5. Model surface coverage measures context delivery, not substantive per-surface review.
6. Model quality hashes are not bound to passed model benchmarks.
7. A CLI profile-overridden run cannot be verified current through `verify-run`.
8. Empty-report semantic and safe-control subgates can pass vacuously.
9. Release validation treats declared traceability artifact names as if emitted.
10. The committed release report is stale, not current-commit bound, and records 8/12 gates.
11. Mutation support covers five of eleven requested classes, with no real kill score.
12. Reproduction identity lacks an independent deployed-bytecode/source comparison.
13. Human-readable rejected findings omit required per-finding detail.

No defect was repaired during this evaluation.

## Exact commands and artifacts

The exact commands, results, hashes, and direct assay source are recorded under `commands` in
[fit_for_purpose_report.json](fit_for_purpose_report.json). The decisive invocations were:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/mmaudit-fit-e304807.QF2xx6/run/src \
  /Users/josevans/dev/Auditor/.venv/bin/python -m pytest -q -p no:cacheprovider
# 636 passed, 9 skipped in 134.66s

env -u OPENROUTER_API_KEY PYTHONDONTWRITEBYTECODE=1 .venv/bin/mmaudit run \
  --config mmaudit.example.toml \
  --repo tests/fixtures/full_protocol_offline \
  --output /private/tmp/mmaudit-eval-engine-maximum \
  --profile maximum-assurance --require-maximum-assurance \
  --allow-code-egress --no-color
# exit 2; run 20260727T114638Z-5641e2ed; INCONCLUSIVE

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/mmaudit-eval-subagent.4jCjCg/src \
  /Users/josevans/dev/Auditor/.venv/bin/python -m mmaudit benchmark \
  --corpus benchmarks/corpus/manifest.json \
  --reports /private/tmp/mmaudit-eval-empty-reports \
  --ground-truth-root . --profile maximum-assurance \
  --output-json /private/tmp/mmaudit-eval-benchmark-empty.json --no-color
# exit 6; incomplete; zero reports; superiority not_evaluated
```

## Plain final assessment

1. **What mmaudit genuinely proves:** bounded typed validation, source/evidence binding, several
   fail-closed local controls, and real paired Foundry property regressions over synthetic fixtures.
2. **What it merely attempts:** a broad multi-engine, multi-model, evidence-capped audit and
   reproduction workflow.
3. **What was tested only with mocks:** every model interaction and ensemble phase; most formal,
   symbolic, replay, containment, and maximum-assurance end-to-end orchestration.
4. **What remains blocked:** real provider models, most engines, hardened/rootless isolation,
   isolated replay, public/private benchmarks, and professional comparison.
5. **Classes it performs well on:** only the bounded known-fixture property classes listed in the
   economic acceptance manifest; this is remediation validation, not discovery performance.
6. **Classes it misses:** no class-level discovery claim is supported; semantic completeness,
   real formal/symbolic findings, six mutation classes, deployment identity, and hostile isolation
   remain unmeasured or incomplete.
7. **Fit for production use:** no, not for the stated maximum-assurance purpose. It may serve as a
   development framework only with explicit limitations and independent professional review.
8. **Maximum assurance:** configured and partially implemented, but not real as a completed
   release capability; verdict `FAILED`.
9. **Superiority over elite audit firms:** not evaluated and not demonstrated.
10. **Exact supporting evidence:** frozen hashes, commands, results, runtime artifact hashes,
    requirement classifications, tool/model matrices, benchmark observations, and isolation
    results are contained in the seven linked evaluation artifacts.
