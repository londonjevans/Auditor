# mmaudit Remediation Worklog

The seven files under `docs/evaluation/` are immutable baseline evidence from
commit `e304807cf942542706b88544fa216516f8f95cad`.

AUTORUN_STATUS: IN_PROGRESS
CURRENT_TICKET: EVAL-DEFECT-010
LAST_COMPLETED_TICKET: EVAL-DEFECT-009
NEXT_ACTION: Review and checkpoint the clean EVAL-010 implementation, then generate fresh external candidate-bound runtime evidence without provider access.
LAST_COMMAND: .venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q
LAST_RESULT: PASS — 291 files unchanged, Ruff clean, strict mypy clean across 128 source files, and 1799 passed with 10 explicit external-prerequisite skips in 215.89s.
REMAINING_CODE_DEFECTS: 4
REMAINING_REAL_INTEGRATIONS: OpenRouter exact-model smoke/qualification/specialist review; certified-isolation Foundry and Slither; Echidna; Medusa; Halmos; formal proof engine; rootless isolation; isolated replay; product benchmark reports
BLOCKED_EXTERNAL_PREREQUISITES: Operator-reviewed production model lineage mapping; Echidna; Medusa; Kontrol; Certora; rootless runtime/image; private holdout; and independently adjudicated expert comparison are not yet evidenced as available
OPENROUTER_COST_USED_USD: 0.00118674
LAST_CHECKPOINT_COMMIT: cd46d215bd77e4c6e1d505d4a7f7773bdb78e525

## Immutable baseline

- **Evaluated commit:** `e304807cf942542706b88544fa216516f8f95cad`
- **Remediation start commit:** `9e0237b352606d3fcddca998a9777c4011ef41fb`
- **Start tree state:** clean; no current diff.
- **Frozen artifact hashes:**
  - `fit_for_purpose_report.md`:
    `fc09d9330ec2cfa8e56278a3692f494dac10b5b1f294c6d852cc6f0a1ddc5cde`
  - `fit_for_purpose_report.json`:
    `bf67e8fc18e031bae04159bceca7fe00d985bcef632c4c69ec78ada76389dd0c`
  - `requirements_traceability.json`:
    `6b71a2d8f39ac5e4e3529fb333a1856ee687353b734423f1e16d83b1d091040d`
  - `tool_execution_matrix.json`:
    `e3f7f085b036cde19fd02956686b0173763cc309ffdc2340613e835be9038456`
  - `model_execution_matrix.json`:
    `8bcd744893cef34f6e62d41b926d7e032de5695edf67a8c5834cedd87947b943`
  - `benchmark_results.json`:
    `5507ac83940727faff54c5f8bb5e26104985f8512da98f911cd3e5ac0d0a2b00`
  - `isolation_results.json`:
    `7064945c7fbc242cddcb032539c899a5aa53efcddef3a24ac5c78d7d4b43a696`

## 2026-07-27 — REM-SECRET-001

- **Status:** `COMPLETE`
- **Defensive objective:** Create an explicit, allowlisted, in-memory
  operator-secret interface and prove the provider credential cannot enter target
  input, child tools, containers, model messages, public artifacts, or errors.
- **Completed changes:** Created the remediation ledgers; added a bounded,
  allowlisted dotenv parser; routed CLI/provider construction through the explicit
  secret file; removed ambient OpenRouter-key loading; reserved control-plane
  variable names from fork/formal engines; scrubbed backend environments; excluded
  sensitive target inputs and link aliases; sanitized provider requests,
  responses, headers, and error contexts; and added synthetic canary regressions.
- **Files changed:** `docs/remediation/`, `pyproject.toml`,
  `src/mmaudit/operator_secrets.py`, CLI/config/provider/pipeline/isolation,
  repository ingestion/location validation, snapshot/prior-audit readers, and
  focused unit tests.
- **Commands run:**
  - Read `AGENTS.md`, all seven evaluation artifacts, the original queue/worklog,
    Git status, and the current diff in the required order.
  - Verified the exact SHA-256 of every frozen evaluation artifact.
  - Installed `python-dotenv==1.2.2` into the repository virtual environment after
    the sandboxed package-index attempt failed and approved network access
    succeeded.
  - `.venv/bin/ruff format <affected files>` — PASS; one file reformatted.
  - `.venv/bin/ruff check <affected files>` — PASS.
  - `.venv/bin/pytest -q tests/unit/test_operator_secrets.py
    tests/unit/test_openrouter.py tests/unit/test_cli.py tests/unit/test_config.py
    tests/unit/test_repository.py tests/unit/test_isolation.py
    tests/unit/test_scanners_reporting.py` — PASS, `195 passed in 2.32s`.
  - `.venv/bin/ruff check .` — PASS.
  - `.venv/bin/mypy` — initial FAIL on pickle-blocking override annotations;
    fixed with `Never`/`SupportsIndex`, then PASS, `102 source files`.
  - `.venv/bin/pytest -q tests/unit/test_operator_secrets.py
    tests/unit/test_openrouter.py` — PASS, `40 passed in 0.12s`.
  - `.venv/bin/pytest -q` — FAIL, `684 passed, 9 skipped, 1 failed in
    147.07s`; `credentials.py` was incorrectly excluded before the existing
    secret detector could fail closed.
  - Narrowed artifact exclusions so auditable source suffixes remain in scope;
    actual `.env`, credential-data, key, wallet-data, mnemonic, and seed artifacts
    remain permanently excluded.
  - `.venv/bin/pytest -q tests/unit/test_repository.py
    tests/integration/test_pipeline.py::test_secret_detection_blocks_all_model_calls`
    — PASS, `48 passed in 0.68s`.
  - `.venv/bin/pytest -q` — PASS, `686 passed, 9 skipped in 142.94s`;
    skips remain explicit real-engine/isolation prerequisites.
  - Corrected provider URL joining so relative endpoints remain under
    `https://openrouter.ai/api/v1/`.
  - `.venv/bin/pytest -q tests/unit/test_openrouter.py` — PASS, `26 passed in
    0.11s`, including exact `/api/v1/key`.
  - `stat -f '%Sp %HT %z bytes' .env; test -f .env; test ! -L .env` — PASS;
    regular non-link file, mode `0644`, 156 bytes. Contents were not displayed.
  - First real `mmaudit doctor ... --secrets-env-file .env` — FAIL before
    authentication adjudication with `httpx.DecodingError`: the bounded client
    reconstructed already-decoded bytes while retaining `Content-Encoding`. No
    credential value appeared in diagnostics.
  - Removed compression/length transport headers from reconstructed decoded
    responses and added a gzip metadata regression.
  - `.venv/bin/ruff check <provider files>; .venv/bin/mypy; .venv/bin/pytest -q
    tests/unit/test_openrouter.py
    tests/unit/test_cli.py::test_doctor_reports_only_secret_and_authentication_state`
    — PASS; mypy checked 102 source files and pytest passed 29 tests.
  - Corrected real `mmaudit doctor ... --secrets-env-file .env` — credential
    boundary PASS: secret file `accepted`, key `present`, OpenRouter authentication
    `valid`. Overall exit was `2` solely because placeholder model IDs remain.
    This authenticated metadata request was not a model completion and incurred
    `0.00 USD`.
  - Independent review found that credential-like generic directory names could
    hide auditable source namespaces. Added path-aware withholding: true
    control-plane paths and sensitive leaf artifacts stay excluded, while source
    under `wallet/`, `keys/`, `credentials/`, and `seed/` remains discoverable,
    location-valid, and copyable into bounded local analysis workspaces.
  - Independent review also found provider-controlled JSON mapping keys were not
    included in credential canary traversal. Mapping keys are now scanned before
    any private debug storage, with a negative regression.
  - Added a fake-provider integration that loads a canary through the explicit
    operator-secret parser, executes completed model reviews, asserts the report,
    SARIF, manifest, and traceability artifacts exist, and scans every emitted
    artifact plus captured logs/stdout/stderr for the canary and secret-file path.
  - Path-aware focused validation — PASS: `186 passed in 7.11s`, then `160 passed
    in 15.30s`; Ruff passed and focused mypy found no issues.
  - Provider mapping-key and loaded-secret artifact focused validation — PASS:
    `2 passed in 0.47s`; Ruff passed.
  - `.venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy &&
    .venv/bin/pytest -q` — PASS; Ruff formatted 7 files and passed, strict mypy
    checked 102 source files, and pytest passed `695` tests with `9` explicit
    external-integration skips in `142.76s`.
  - Reverified all seven immutable evaluation SHA-256 values exactly; `git diff
    --exit-code -- docs/evaluation` was clean. `.env` remains ignored and is not a
    tracked file.
- **Result:** `COMPLETE`. Explicit credential loading, real authentication
  metadata validation, fail-closed propagation controls, and non-vacuous canary
  evidence passed. No paid model completion occurred; OpenRouter spend is
  `0.00 USD`.
- **Checkpoint commit:** `a333ff9df5c1b680c110c0e011682dfbf4e7aa42`.
- **Exact next safe action:** Continue `EVAL-DEFECT-001` from the isolated
  checkpoint.

## 2026-07-27 — EVAL-DEFECT-001

- **Status:** `COMPLETE`
- **Defensive objective:** Require successful AST-backed compilation before a
  certified maximum-assurance run can be complete.
- **Completed changes:** The compilation clause now requires an exact one-to-one
  project/result inventory, `SUCCESS` for every project, non-empty compiled
  contracts, per-result AST availability, and a matching AST-backed index with no
  fallback-parsed sources. Current Foundry compilation-target metadata and
  top-level source maps are normalized so genuine current artifacts can satisfy
  the evidence fields.
- **Permanent negative assays:** `FAILED`, `TIMED_OUT`, `SKIPPED`, `UNAVAILABLE`,
  successful-without-AST, successful-without-contract-output, partial
  multi-project results, and fallback-parser-only indexing all produce a blocking
  clause and never `COMPLETE`.
- **Commands run:**
  - `.venv/bin/ruff format src/mmaudit/orchestration/assurance.py
    src/mmaudit/solidity/compile.py tests/unit/test_assurance.py
    tests/unit/test_solidity.py` — PASS; unchanged.
  - `.venv/bin/ruff check <affected files>` — PASS.
  - `.venv/bin/mypy src/mmaudit/orchestration/assurance.py
    src/mmaudit/solidity/compile.py` — PASS; two source files.
  - Initial focused pytest — one test assertion exposed that current Foundry
    artifacts store source maps under `bytecode`; normalized that supported
    format and reran.
  - `.venv/bin/pytest -q tests/unit/test_assurance.py
    tests/unit/test_solidity.py
    tests/integration/test_pipeline.py::test_maximum_assurance_e2e_is_evidence_rich_but_never_false_complete`
    — PASS, `56 passed in 3.78s`.
  - `forge --version` and executable SHA-256 — real local Forge
    `1.3.2-stable`, commit `b0381e15d1465396aabcb398b60d2c10cc0112f2`,
    SHA-256 `c0ed9870bf0637ce351ef70e347bcf8ab5e23c4cc12d32ef6fdf4eb1d97116ee`.
  - First offline synthetic control compilation without `--ast` — PASS but did
    not emit AST in the per-contract artifacts; it was not credited as the
    AST-backed control.
  - A follow-up attempt using unsupported `--extra-output ast` — correctly
    rejected by Forge with exit `2`; it was not credited.
  - `env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE forge build --root
    tests/fixtures/solidity/foundry --offline --force --ast --build-info --out
    /private/tmp/mmaudit-eval001.p9fvUf/out-ast --cache-path
    /private/tmp/mmaudit-eval001.p9fvUf/cache-ast` — PASS; two files compiled
    using Solc `0.8.20`, AST/ABI/bytecode validated, and output hashes recorded.
- **Runtime artifact:**
  `docs/remediation/runtime/eval_defect_001.json`.
- **Limitation:** The real compiler control used trusted synthetic local input but
  was not executed under the unavailable certified rootless backend. It is
  explicitly component evidence and does not satisfy maximum-assurance isolation.
- **Result:** `COMPLETE`; the false-COMPLETE code defect and its current-artifact
  normalization gap are fixed without claiming certified isolated compilation.
- **Checkpoint commit:** `f2a782b7319ccad848df392f5d40da45fcc63283`.
- **Exact next safe action:** Continue `EVAL-DEFECT-002`.

## 2026-07-27 — EVAL-DEFECT-002

- **Status:** `COMPLETE`
- **Defensive objective:** Prevent an attempted but unsuccessful high/critical
  reproduction from satisfying maximum assurance.
- **Completed changes:** Added a strict per-candidate resolution schema and a
  deterministic pipeline adjudicator. The assurance denominator now includes
  every source-valid high/critical candidate, including verifier-rejected
  candidates and candidates omitted by the bounded reproduction planner. A
  candidate qualifies only when its reproduced resolution resolves back to a
  complete, integrity-verified successful raw `ReproductionResult` for that same
  candidate.
- **Fail-closed behavior:** Missing, inconclusive, duplicate, stale, forged, or
  unbound resolutions block the candidate clause. An attempt count has no credit
  by itself. Unbound falsification, unvalidated severity reduction, and formal
  evidence without candidate-semantic real-execution provenance remain
  `INCONCLUSIVE`. Typed resolutions are serialized in
  `reproduction-results.json` and independently cross-checked by the assurance
  contract.
- **Commands run:**
  - Affected Ruff formatting/checks — PASS.
  - Strict mypy on the schema, assurance contract, and pipeline — PASS.
  - Focused failed-attempt and synthetic maximum-assurance pipeline command —
    PASS, `28 passed in 2.22s`.
  - `.venv/bin/pytest -q tests/unit/test_assurance.py
    tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py
    tests/integration/test_pipeline.py` — PASS, `110 passed in 42.49s`.
  - `.venv/bin/pytest -q
    tests/integration/test_financial_settlement_foundry.py` — PASS, `1 passed in
    0.27s`; real local generated witness compilation/execution with a sanitized
    child environment.
  - `.venv/bin/pytest -q
    tests/integration/test_economic_acceptance_foundry.py` — PASS, `1 passed in
    29.85s`; real local paired unsafe/safe Foundry controls were distinguished.
- **Runtime artifact:**
  `docs/remediation/runtime/eval_defect_002.json`.
- **Limitation:** Pipeline denominator and resolution serialization are covered
  with typed synthetic integration doubles. Real local Foundry controls executed,
  but not through the unavailable certified rootless replay backend; they are not
  credited as real maximum-assurance replay. Formal candidate resolution remains
  fail-closed until its property semantics and execution artifacts can be
  independently bound.
- **Result:** `COMPLETE` for the false-COMPLETE code defect. Certified isolated
  replay remains an explicit external integration blocker.
- **Checkpoint commit:** `30e04caec21d9d01e1ed39fd98f288cf25a025a3`.
- **Exact next safe action:** Checkpoint this ticket, record its commit, and
  continue `EVAL-DEFECT-003`.

## 2026-07-27 — EVAL-DEFECT-003

- **Status:** `COMPLETE`
- **Defensive objective:** Require the exact real engine portfolio, non-empty
  execution evidence, hardened isolation, replay, real model review, and a current
  benchmark for certified maximum assurance.
- **Implementation slice:** Exact Foundry, Slither, Echidna, Medusa, Halmos, and
  formal-proof gates now require configured version/checksum pins, sealed
  observation hashes, strict machine output, non-empty campaign/property evidence,
  and provenance minted only by preflighted built-in hardened-isolation backends.
  Foundry unit/fuzz/invariant summaries and generated invariant campaigns are
  derived from exact Forge JSON rather than human-readable logs. Manifest-bound
  replay records only applicable component kinds and can promote replay-only
  clauses only through a separately hash-sealed post-run certification.
- **Commands and results:**
  - `.venv/bin/pytest -q tests/unit/test_assurance.py tests/unit/test_scanners_reporting.py tests/unit/test_formal.py tests/unit/test_halmos.py tests/unit/test_kontrol.py tests/unit/test_echidna.py tests/unit/test_medusa.py tests/unit/test_replay.py tests/unit/test_config.py tests/unit/test_benchmark_certificate.py tests/unit/test_cli.py tests/unit/test_reproduction.py tests/unit/test_isolation.py tests/unit/test_openrouter.py tests/unit/test_invariant_execution.py tests/unit/test_certification.py tests/integration/test_pipeline.py`
    → `451 passed in 69.28s`.
  - `.venv/bin/pytest -q tests/unit/test_invariant_execution.py tests/integration/test_pipeline.py::test_erc4626_generated_harness_executes_locally_and_is_counted_separately`
    → `78 passed in 15.44s`.
  - Six real local Forge economic/invariant integration controls → `5 passed,
    1 failed`; inspection showed the remaining state-ordering control required
    structured handler-metric normalization. After the fix, its focused rerun
    passed. This execution used a synthetic local-only test backend and therefore
    is not credited as certified hardened-isolation evidence.
  - Ruff checks and strict mypy over the invariant runner passed.
  - Independent adversarial review reproduced ten additional false-COMPLETE
    paths: unbound proof/property identities, unconfigured model usage, detached
    benchmark commit, omitted economic applicability, incomplete replay member
    inventory, declarative isolation evidence, unvalidated Foundry output,
    partial campaigns, and zero-call action credit. Each path received a
    fail-closed implementation fix and permanent negative regression.
  - The first combined post-review command reported `9 failed, 467 passed`;
    all nine failures were certification fixture setup that mocked a run
    directory without mocking its newly required sealed replay inventory.
    After correcting the fixture, certification/replay passed `13 passed`.
  - `.venv/bin/pytest -q tests/unit/test_assurance.py
    tests/unit/test_certification.py tests/unit/test_replay.py
    tests/unit/test_invariant_execution.py tests/unit/test_isolation.py
    tests/unit/test_isolation_provenance.py tests/unit/test_scanners_reporting.py
    tests/unit/test_formal.py tests/unit/test_echidna.py tests/unit/test_medusa.py
    tests/unit/test_halmos.py tests/unit/test_kontrol.py
    tests/integration/test_pipeline.py` → `354 passed in 69.50s`.
  - `.venv/bin/ruff check src/mmaudit ...` → PASS.
  - `.venv/bin/mypy` → PASS, `104 source files`.
  - `.venv/bin/pytest -q` → PASS, `867 passed, 9 skipped in 152.18s`.
    Every skip named its unavailable real prerequisite; none was counted as
    certified engine, isolation, or replay evidence.
  - `.venv/bin/ruff format .`, `.venv/bin/ruff check .`, and
    `.venv/bin/mypy` → PASS after final formatting.
  - Immutable baseline artifact SHA-256 verification → PASS; all seven hashes
    exactly match the recorded baseline.
- **Runtime artifact:** `docs/remediation/runtime/eval_defect_003.json`.
- **External evidence boundary:** Echidna, Medusa, Kontrol, Certora, and an
  approved rootless runtime remain unavailable. Installed tools have not yet
  executed as the complete digest-pinned certified-isolation portfolio. These
  remain explicit blockers and cannot satisfy maximum assurance. The exact
  integration work remains queued under `REM-INTEGRATIONS-001`.
- **Result:** `COMPLETE` for the false-COMPLETE implementation defect. The
  contract now rejects unavailable, mocked, unobserved, partial, unattested,
  identity-drifted, or incomplete portfolio evidence.
- **Checkpoint commit:** `f9dc2e3c96e0eb64a9e13a3f22b9d18192bddfd1`.
- **Exact next safe action:** Checkpoint this ticket and continue
  `EVAL-DEFECT-004`.

## 2026-07-27 — EVAL-DEFECT-004

- **Status:** `COMPLETE`
- **Defensive objective:** Prevent any scanner other than one exact, successful,
  strict-machine-output Slither execution from satisfying the maximum-assurance
  Slither clause.
- **Completed changes:** The independent `slither_execution` clause accepts
  exactly one Slither record only when it has real execution evidence, an
  adversarially preflighted isolation attestation, exact version/checksum pins,
  exit code zero, strict validated output, and a matching observation digest.
  Generic scanner success and Foundry execution remain separate clauses.
- **Acceptance command:** `.venv/bin/pytest -q
  'tests/unit/test_assurance.py::test_exact_maximum_assurance_portfolio_fails_closed[required_slither_missing]'
  tests/unit/test_scanners_reporting.py -k 'slither or
  required_slither_missing'` → PASS, `9 passed, 56 deselected in 0.90s`.
- **Runtime artifact:** `docs/remediation/runtime/eval_defect_004.json`.
- **Real integration boundary:** Slither `0.11.5` is installed and hashed, but
  no certified isolation backend is available. Availability was not counted as
  execution; the real Slither run remains `BLOCKED_TECHNICAL` under
  `REM-INTEGRATIONS-001`.
- **Result:** `COMPLETE` for the false-COMPLETE code defect.
- **Implementation commit:** `f9dc2e3c96e0eb64a9e13a3f22b9d18192bddfd1`.
- **Exact next safe action:** Record this ledger checkpoint and continue
  `REM-OPENROUTER-001`.

## 2026-07-27 — REM-OPENROUTER-001

- **Status:** `COMPLETE` for the safe implementation and deterministic local
  protocol validation; the paid exact-model integration remains unexecuted and is
  tracked by `REM-MODELS-001`.
- **Defensive objective:** Require exact OpenRouter model and endpoint identities,
  certification-grade privacy and fallback policy, complete response validation,
  conservative typed failures, and a hard atomic campaign cost ledger.
- **Completed changes:** Added canonical OpenRouter metadata, endpoint, key, and
  completion handling; exact endpoint snapshots; exact requested-versus-returned
  identity checks; emitted-parameter capability validation; strict structured
  responses; timeout/retry/error classification; immutable transport provenance;
  redacted diagnostics; cumulative atomic reservation/reconciliation; and
  certification-grade model-usage evidence. Default reasoning is omitted unless
  configured, ambiguous provider display identities fail closed, and unsupported
  variable pricing dimensions are rejected because they cannot be provider-capped.
- **Cost integrity:** Every paid-control request reserves its maximum exact
  `Decimal` cost before transport. Successful usage reconciles against the exact
  provider amount; malformed/error responses retain the full reservation.
  Concurrent reservations share a locked persistent ledger. Injected or replaced
  transports cannot mint `REAL` execution evidence, and an injected real client
  cannot bypass the pipeline's effective controls or selected campaign ledger.
- **Focused commands and results:**
  - `.venv/bin/ruff check <OpenRouter affected files>` — PASS.
  - `.venv/bin/mypy src/mmaudit/models/openrouter.py
    src/mmaudit/models/endpoint_snapshots.py src/mmaudit/models/runtime.py
    src/mmaudit/orchestration/budgets.py
    src/mmaudit/orchestration/pipeline.py` — PASS, five source files.
  - `.venv/bin/pytest -q tests/unit/test_openrouter.py
    tests/unit/test_endpoint_snapshots.py tests/unit/test_model_runtime.py
    tests/unit/test_budgets.py tests/unit/test_cli.py
    tests/integration/test_pipeline.py
    tests/integration/test_real_openrouter_provider.py` — PASS,
    `212 passed, 1 skipped in 50.78s`. The sole skip requires explicit
    `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1`.
- **Full validation:**
  - `.venv/bin/ruff format .` — PASS, 230 files unchanged.
  - `.venv/bin/ruff check .` — PASS.
  - `.venv/bin/mypy` — PASS, 107 source files.
  - `.venv/bin/pytest -q` — PASS,
    `1060 passed, 10 skipped in 156.13s`. Every skip names an unavailable
    real-provider, real-engine, rootless-isolation, replay, or sandbox
    prerequisite and receives no maximum-assurance credit.
- **Runtime artifact:**
  `docs/remediation/runtime/rem_openrouter_001.json`.
- **Provider boundary:** No paid completion call was made, no provider completion
  was credited, and the cumulative OpenRouter campaign spend remains `0.00 USD`.
  The earlier credential validation remains separate zero-cost authentication
  evidence. Exact model qualification and specialist requests require the
  explicit real-provider controls under `REM-MODELS-001`.
- **Result:** The OpenRouter control path is locally validated and fail-closed.
  It is not real-provider execution evidence and cannot satisfy the
  maximum-assurance model-review clause by itself.
- **Implementation commit:** `40cb4e7cdf155401618553304cc69623d69fe69f4`.
- **Exact next safe action:** Push the bound checkpoint, then freeze the exact
  production candidate registry and qualification artifact contract under
  `REM-MODELS-001` before authorizing any paid call.

## 2026-07-27 — REM-MODELS-001

- **Status:** `IN_PROGRESS`.
- **Defensive objective:** Replace declared or SHA-shaped model quality with a
  non-empty, version-bound, independently verified qualification artifact and
  select every eligible Tier A exact model under the hard campaign budget.
- **Public metadata slice:** Fetched current official OpenRouter `/models`,
  per-model endpoint, and ZDR endpoint metadata without an API key and without a
  completion call. The snapshot identified exact base request IDs, canonical
  release slugs, endpoint tags, capabilities, context/output limits, pricing,
  operational status, and ZDR membership. Catalog presence remains discovery
  evidence only and assigns neither quality nor lineage independence.
- **Fail-closed compatibility correction:** Current endpoint metadata represents
  a missing prompt/output limit as JSON `null` and includes numeric `discount`
  metadata beside exact string prices. The endpoint normalizer now uses the
  explicit context ceiling when a limit is null, records whether each limit came
  from metadata or the context ceiling, ignores only a validated nonnegative
  discount because it cannot increase cost, and continues rejecting tier
  overrides, negative discounts, cache/internal-reasoning prices, and every
  unsupported billable component.
- **Commands and results:**
  - Public `GET https://openrouter.ai/api/v1/models?...` — PASS; `188` current
    ZDR/structured-output model records captured in a disposable local file.
  - Public exact Qwen endpoint and global ZDR snapshots — PASS; no authorization
    header or secret used.
  - `.venv/bin/pytest -q tests/unit/test_endpoint_snapshots.py` — PASS,
    `32 passed in 0.06s`.
  - `.venv/bin/pytest -q tests/unit/test_model_benchmark.py tests/unit/test_cli.py
    -k 'models_benchmark or model_benchmark'` — PASS, `18 passed, 41
    deselected in 0.94s`.
  - `.venv/bin/pytest -q tests/unit/test_config.py
    tests/unit/test_openrouter.py` — PASS, `103 passed in 0.29s`.
  - Affected Ruff and strict mypy — PASS.
  - Local normalization of current
    `qwen/qwen3.6-35b-a3b` / `akashml/fp8` metadata — PASS; the self-hashed
    snapshot records a context-derived prompt ceiling and only exact prompt and
    completion prices. This is metadata validation, not provider execution.
- **OpenRouter spend:** `0.00 USD`; no model completion has been requested.
- **Benchmark-v2 slice:** The blinded corpus now has `16` bounded synthetic
  cases and non-zero denominators for all `17` qualification dimensions. Each
  result retains exact per-case request evidence and recomputes summary
  aggregates. The independent assay below proved that the first draft did not
  yet bind those summaries or provenance strongly enough for qualification.
  This remains local component validation until the hardening completes and
  exact candidates execute real certification-bound requests.
- **Independent negative assay:** A deeper adversarial review showed that the
  first benchmark-v2 draft was still structurally forgeable: a coherent edit
  could inflate case scores, relabel internally consistent MOCK evidence as
  REAL, or disconnect the scored normalized response from the raw provider
  response while recomputing self-hashes. It also found descriptive
  provider-visible task text that disclosed expected conclusions. Those are
  recorded as active REM-MODELS-001 defects rather than accepted evidence.
- **Response-binding remediation slice:** Successful `UsageRecord` objects now
  require `validated_response_sha256`, computed from the canonical strict
  Pydantic output independently of the raw completion hash. The existing client,
  usage, coverage, and assurance regressions pass (`221 passed in 0.77s`).
  Benchmark hardening is in progress to retain the normalized response, re-score
  from separately frozen ground truth, bind both hashes, use opaque provider case
  identities, and require authenticated generation evidence before REAL credit.
- **Real discovery attempt 1:** The authenticated metadata-only command failed
  closed before writing evidence because the unfiltered provider catalog
  contained an unrelated identifier outside the strict exact-model grammar.
  No completion request or spend occurred. A fixed official catalog query now
  requests only ZDR models advertising structured response support, then still
  validates every returned identifier and each exact candidate endpoint
  locally. Its focused CLI/OpenRouter tests pass (`11 passed`).
- **Real discovery attempt 2:** The corrected command completed for all `12`
  exact candidates and wrote self-hashed mode-`0600` evidence under the ignored
  operator-private `.mmaudit/private/model-discovery/current` directory. Every
  record binds the requested ID, official canonical slug, one exact provider
  endpoint, current operational and ZDR state, structured-output capability,
  context/output limits, model metadata hash, endpoint snapshot hash, and exact
  pricing hash. Eleven endpoints advertise reasoning controls; the selected
  Llama endpoint does not and is recorded honestly. This was authenticated
  metadata execution only: no completion, generation, token use, or cost entry
  occurred.
- **Current limitation:** Root-lineage assignments remain provisional and must
  not count as independent until the operator reviews the frozen mapping.
- **Qualification trust-boundary slice:** Removed both arbitrary truthy callback
  promotion paths. Legacy benchmark verification now rejects serialized REAL
  labels and directs all REAL credit to the authenticated qualification
  workflow. The qualification CLI consumes one exact-set atomic portfolio,
  binds its hash into the workflow and artifact, requires non-empty all-REAL
  reports with complete diagnostics, and obtains a fresh authenticated
  generation-metadata attestation through an owned concrete OpenRouter client.
  A loose `--report`, missing capability, relabeled mock, or offline resolver
  cannot qualify a model. Fresh verification compares stable generation facts
  while excluding only retrieval timestamps and their transitive self-hashes.
- **Qualification validation evidence:** The trusted-generation boundary passed
  `82` focused tests with one explicit real-provider skip; the portfolio-bound
  qualification CLI/workflow/schema slice passed `136` focused tests; the
  removed legacy callback promotion assay passed `17` focused tests. Affected
  Ruff and strict mypy checks passed. These are local/mock protocol tests and
  are not provider-execution evidence.
- **Frozen pre-spend inventory:** The authenticated discovery run contains `12`
  exact model/provider routes. The initial `16`-case campaign preflight had a
  retry-inclusive maximum of `2.266474830 USD`, leaving
  `247.733525170 USD` under the operator's `250.00 USD` cap. This estimate is
  superseded if the corpus case count changes and must be recomputed before
  provider use.
- **Pre-spend independent audit blocker:** A read-only adversarial review found
  that the first semantic scorer could award Tier A credit for keyword stuffing
  while ignoring expected locations on most unsafe cases, and that several
  synthetic excerpts did not contain enough evidence to support their
  ground-truth label. It also found single-case semantic denominators and a
  campaign durability gap that could retain cost in the ledger while losing
  completed in-memory reports after a later failure. No paid campaign is
  authorized until the scorer, fixtures, denominators, durable per-candidate
  journal, and retry-attempt accounting are remediated and revalidated.
- **OpenRouter spend:** `0.00 USD`; no model completion has been requested.
- **Pre-spend hardening result:** The scorer now requires exact
  classification/location agreement for every semantic dimension, takes required
  reasoning concepts only from the rationale field, rejects contradictory
  rationales, and requires structured source-bound verifier evidence and
  falsifier tests. The frozen `16`-case corpus now supplies at least two disjoint
  evaluations for every semantic dimension, three prompt-injection styles, and
  sixteen structured-output evaluations. All training-exposure declarations are
  `unknown`; this is request-level blinded qualification, not a private holdout.
- **Frozen hardening hashes:** corpus
  `524f4c37c41d8178c6e159a5d7d67bf0b3fe33c83015c8a8401006f6fbd1ce3b`;
  ground truth
  `09c86d16caa05c9602fa8082a46b2dc438f92cc0b668fe7ce7d001e4a9358c92`;
  qualification policy
  `d286d1c5f9ed4a5a4c7c62eda7a55e9a1e23e972f21ffe64530ca34ed780224e`.
  The policy binds the realized denominators before secret access.
- **Campaign durability:** Candidate mode now requires an explicit fresh private
  campaign journal and qualification policy. Every candidate report, diagnostic,
  observed non-secret usage record, and before/after cost-ledger snapshot is
  atomically persisted before advancing. Resume is explicit and exact-bound;
  incomplete journals cannot seal a portfolio. Logical requests, provider
  attempts, retries, successful/failed requests, unresolved costs, token usage,
  latency, and cost are independently recomputed. A usage-then-failure regression
  retained a real synthetic `0.01 USD` ledger charge without an active
  reservation; an interrupted second candidate retained the first candidate's
  exact evidence.
- **Revised exact cost preflight:** `12 × 16 = 192` first-pass requests and
  `384` retry-inclusive provider attempts fit the configured `512` ceiling.
  The endpoint-bound maximum is `1.2599820925 USD` first pass and
  `2.519964185 USD` with one retry per request, leaving more than `247 USD`
  under the immutable `250.00 USD` campaign cap.
- **Integrated validation:**
  - `226` focused discovery, benchmark, scorer, corpus, journal, portfolio,
    qualification, schema, configuration, and CLI tests passed in `10.71s`.
  - `.venv/bin/ruff format .` reformatted three files; `.venv/bin/ruff check .`
    passed.
  - `.venv/bin/mypy` passed for `114` source files.
  - The first full-suite execution lost its final harness output and was not
    credited. The identical captured retry passed with `1293 passed, 10 skipped
    in 166.50s`; every skip explicitly names a real-provider, engine, isolation,
    replay, or loopback prerequisite.
- **OpenRouter spend:** `0.00 USD`; no model completion has been requested.
- **Final campaign-provenance review:** Qualification now requires an opaque
  in-memory capability issued only after reopening the actual complete private
  campaign journal and its exact existing cost ledger. The verifier checks the
  journal's registry, corpus, policy, effective configuration, ledger path,
  report set, diagnostics, retained usage, journal hash, and initial/final
  ledger snapshots against the portfolio. Caller-supplied booleans, lookalike
  objects, arbitrary claimed journal hashes, unresolved reservations, active
  reserved amounts, uncertain cost, failed requests, or budget overruns cannot
  satisfy the boundary. Both `models qualify` and `models
  verify-qualification` require the campaign journal and its dedicated ledger.
  Focused workflow, CLI, and portfolio validation passed with `42 passed in
  12.83s`; the targeted campaign/qualification set passed with `55 passed in
  13.82s`, including the caller-forged-capability regression. The final exact
  source state passed with `1296 passed, 10 skipped in 171.24s`. This is local
  provenance validation, not real provider evidence.
- **Pre-checkpoint integrity:** Full Ruff formatting left `253` files
  unchanged, Ruff checks passed, and strict mypy passed for `114` source files.
  `git diff --check` passed; `docs/evaluation/` has no diff and all seven frozen
  SHA-256 values still match. `.env` and `.mmaudit/` remain ignored and
  untracked. A repository-wide key-pattern scan found only explicit redaction
  regexes and clearly labelled synthetic canary fixtures; no operator secret or
  private generated evidence is staged.
- **Retry-level unresolved-cost assay:** Independent review found that two
  uncertain provider attempts for one logical request could exceed a
  logical-request-based unresolved-cost bound after the atomic ledger had
  already changed. Both diagnostic and portfolio invariants now bound unresolved
  ledger entries by provider attempts. A two-attempt synthetic timeout
  regression preserves both conservatively accounted entries in the campaign,
  resumes and seals deterministically, and remains ineligible for qualification.
  The affected Ruff and strict mypy checks passed; the focused campaign,
  portfolio, workflow, and CLI set passed with `47 passed in 14.42s`. The exact
  full source state then passed with `1297 passed, 10 skipped in 170.80s`.
- **Selection-chain splice assay:** Independent review found that a genuine
  ready qualification verification could be paired with a different
  self-hashed artifact containing the same eligible IDs, and downstream
  ensemble evaluation did not independently bind all supplied verification
  objects. Selection sealing, selection verification, and ensemble evaluation
  now require exact artifact, registry, policy, qualification-verification, and
  selection-verification hash continuity. Regressions cover cross-artifact
  selection and unrelated-but-valid downstream evidence objects. Ruff and
  strict mypy passed; `33` focused qualification tests passed in `0.51s`. The
  exact full source state then passed with `1300 passed, 10 skipped in 170.15s`.
- **Independent checkpoint audit:** A read-only adversarial recheck ran `218`
  integrity tests and `51` post-fix qualification/campaign/workflow tests. It
  found no remaining checkpoint blocker in mock/REAL promotion, campaign/ledger
  provenance, budget accounting, exact model/route enforcement, selection
  binding, or secret/private-artifact exposure. No provider request occurred.
- **Real provider smoke attempt 1:** After checkpoint `a946ae6`, the dedicated
  ignored mode-`0600` ledger was initialized with the immutable `250 USD` cap.
  Authentication, exact-model catalog lookup, exact AkashML endpoint validation,
  ZDR metadata validation, and request construction succeeded. The one paid
  Qwen request returned the exact model but `finish_reason=length` after using
  the original `256`-token ceiling for reasoning, so strict validation rejected
  it and no review or smoke success was credited. The ledger has one
  `uncertain_accounted` entry for `0.00046222 USD`, zero active reservations,
  and no secret-bearing fields. A materially different retry caps reasoning at
  `64` tokens, excludes reasoning content, and raises the bounded total output
  ceiling to `512`; local harness/OpenRouter validation passed with `110 passed,
  1 opt-in skip`.
- **Real provider smoke attempt 2:** The bounded reasoning configuration passed
  the prior truncation boundary and the provider returned the exact requested
  model at the response envelope, but OpenRouter router metadata identified the
  selected model as the dated canonical variant
  `qwen/qwen3.6-35b-a3b-20260415`. Because that did not equal the frozen exact
  request ID, the client rejected it as an unapproved identity substitution and
  credited no successful request. The dedicated ledger now contains two
  `uncertain_accounted` entries totaling `0.00118674 USD`, zero active
  reservations, and zero overruns. Per the two-attempt rule, the paid smoke is
  `INCONCLUSIVE`; no third paid retry is authorized until the
  requested-versus-canonical identity is resolved from official frozen metadata
  and reflected in a new exact candidate set.
- **Requested/canonical identity remediation:** Certification now permits a router
  selected model to use only the exact requested ID or the canonical slug bound by
  a complete REAL discovery artifact. The top-level response still must equal the
  exact requested ID. Unmanifested discovery must match the same authenticated,
  owned client session; frozen campaign discovery must match its exact manifest
  artifact and run provenance. Usage, generation refetch, benchmark verification,
  qualification, and selection all retain the requested/canonical/catalog/
  discovery hash chain.
- **Negative regressions:** Unbound canonical identities, wrong canonical
  identities, mixed provider-attempt identities, a canonical top-level response,
  and spliced discovery manifests all fail closed. No new paid request was made.
- **Focused validation:** `.venv/bin/pytest -q
  tests/unit/test_openrouter.py tests/unit/test_candidate_benchmark.py
  tests/unit/test_candidate_benchmark_cli.py
  tests/unit/test_candidate_benchmark_campaign.py
  tests/unit/test_generation_evidence.py tests/unit/test_model_benchmark.py
  tests/unit/test_model_benchmark_portfolio.py
  tests/unit/test_model_qualification.py
  tests/unit/test_qualification_workflow.py tests/unit/test_usage.py
  tests/unit/test_model_surface_review_schema.py
  tests/integration/test_real_openrouter_provider.py` — PASS, `282 passed, 1
  explicitly skipped in 10.79s`.
- **Full-suite correction:** The first full run failed with `1218 passed, 110
  failed, 10 skipped in 175.06s` because two shared synthetic REAL usage helpers
  omitted the newly mandatory actual/canonical routing identity. Production
  checks were not weakened. The corrected focused command `.venv/bin/pytest -q
  tests/unit/test_assurance.py tests/unit/test_model_coverage.py` passed `115`
  tests in `0.51s`.
- **Final validation:** `.venv/bin/pytest -q` — PASS, `1328 passed, 10 skipped in
  174.84s`; `.venv/bin/ruff format --check .` — PASS, `254` files; `.venv/bin/ruff
  check .` — PASS; `.venv/bin/mypy` — PASS, `114` source files.
- **Runtime evidence:**
  `docs/remediation/runtime/rem_models_001_identity_binding.json` and
  `docs/remediation/runtime/rem_models_001_provider_attempts.json`.
- **Result:** `PARTIAL`. The safe exact-identity code slice is complete at
  checkpoint `e219c0fe208dc48fbc2969590b11099d7d15fe34`; real provider execution
  remains `INCONCLUSIVE`, no model is qualified, and operator lineage review is
  outstanding. Maximum-assurance credit remains false.
- **Exact next safe action:** Continue `EVAL-DEFECT-005` with response-authored,
  source-validated per-surface review records.

## 2026-07-27 — EVAL-DEFECT-005

- **Status:** `IN_PROGRESS`
- **Defensive objective:** Prevent mere context delivery from counting as
  substantive model review. Credit only exact requested surfaces explicitly
  returned in a completed, validated response and bound to approved model,
  lineage, request, role, source location or symbol, and evidence hashes.
- **Initial safe slice:** Added strict response-record and locally sealed artifact
  schemas with exact stable-surface set, role, and hash consistency checks. The
  orchestration and coverage migration remains in progress; schema tests alone do
  not resolve the baseline defect.
- **Exact next safe action:** Add deterministic requested-surface descriptors,
  an evidence-returning completion API, response batches, local artifact sealing,
  and response-only coverage accounting.
- **Implemented slice:** Reviewer responses now contain one strict record per
  requested stable surface. The provider client returns the exact normalized
  usage record with each structured completion; the local sealer validates the
  exact surface set, role, source/symbol citation, prompt/response/schema hashes,
  and writes normalized evidence under the private run directory.
- **Coverage correction:** The denominator is the complete deterministic Solidity
  surface inventory. Review requests are deterministically distributed across
  independently registered and operator-approved root lineages; aliases do not
  inflate independence. Only completed, strict, non-truncated, validated
  `CANDIDATE` or `REVIEWED_NO_ISSUE` records from real approved usage can earn
  credit. `NOT_REVIEWED`, `INCONCLUSIVE`, mocks, missing records, invalid
  locations, role/hash/model mismatches, duplicate evidence, and unapproved
  lineages remain visible but earn no credit.
- **Fail-closed join:** Maximum assurance independently reconciles every credited
  surface reference with exactly one certification-grade usage record and one
  sealed artifact/record. Aggregate role or context claims without that exact
  join cannot satisfy the clause.
- **Focused validation:** Ruff and strict mypy passed. The combined schema,
  provider, context, evidence-sealer, coverage, Solidity-projection, assurance,
  reporting, and pipeline checks passed in focused groups, including `276 passed
  in 49.59s` and the end-to-end maximum-assurance negative-control audit.
- **Exact next safe action:** Run the full repository validation gate and inspect
  the final diff and emitted private/public artifact boundary.
- **Final validation:** `.venv/bin/ruff format --check .` — PASS, `258` files;
  `.venv/bin/ruff check .` — PASS; `.venv/bin/mypy` — PASS, `115` source files;
  `.venv/bin/pytest -q` — PASS, `1370 passed, 10 skipped in 173.11s`.
- **Immutable baseline check:** All seven recorded `docs/evaluation/` SHA-256
  digests still match the frozen baseline, and no evaluation file changed.
- **Runtime evidence:** `docs/remediation/runtime/eval_defect_005.json`.
- **Result:** `COMPLETE` at implementation checkpoint
  `6da9cec718a43e2ead4790f3e2b7f40f43f63bca`. Real paid model qualification
  remains independently `INCONCLUSIVE`; no mock or context-only record received
  real-review credit.

## 2026-07-27 — EVAL-DEFECT-006

- **Status:** `COMPLETE`
- **Defensive objective:** Prevent SHA-256-shaped quality labels or stale,
  unrelated benchmark documents from authorizing production model execution.
- **Completed changes:** Replaced self-asserted quality hashes with opaque,
  process-local verified qualification capabilities. Production selection now
  resolves exact non-empty passing benchmark reports and binds source, effective
  configuration, prompts, schemas, exact models, provider metadata, toolchain,
  isolation, expiry, and the frozen all-eligible selection. Runtime requests,
  usage, assurance, traceability, and manifests retain the verified evidence
  hashes without persisting raw prompts or source context.
- **Release observation:** Added a trusted release observation that measures the
  executing package root, exact committed `HEAD` inventory and bytes, fixed
  Python/dependency/toolchain state, and sealed real-isolation evidence. Alternate
  repositories, staged-only content, skip-worktree drift, copied/serialized
  capabilities, post-issuance mutation, and caller-controlled time fail closed.
- **Substantive review hardening:** Bound each credited model surface artifact to
  the exact rendered context bytes dispatched to the provider. Base and specialist
  agents deep-snapshot before the awaited request; success, failure, and fallback
  usage records carry the same digest; coverage independently re-renders and joins
  context, usage, artifact, exact source excerpts, symbols, and graph paths.
- **Negative assays:** Shape-only, stale, empty, failed-threshold, wrong-source,
  wrong-config, wrong-prompt/schema/model/tool/isolation, alias-inherited,
  cross-artifact-spliced, serialized-capability, and post-hoc-context evidence all
  remain uncredited. An independent read-only recheck reproduced the original
  post-hoc substitution assay and observed the corrected implementation reject it.
- **Focused commands:**
  - `.venv/bin/pytest -q tests/unit/test_model_review_evidence.py tests/unit/test_model_coverage.py tests/unit/test_openrouter.py`
    — PASS, `147 passed in 0.76s`.
  - `.venv/bin/pytest -q tests/unit/test_model_qualification_schema.py tests/unit/test_model_surface_review_schema.py`
    — PASS, `27 passed in 0.23s`.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py`
    — PASS, `44 passed in 52.98s`.
- **Complete validation:**
  - `.venv/bin/ruff format --check .` — PASS, `261 files already formatted`
    after Ruff formatted the three final context-binding files.
  - `.venv/bin/ruff check .` — PASS.
  - `.venv/bin/mypy` — PASS, `116 source files`.
  - `.venv/bin/pytest -q` — PASS,
    `1515 passed, 10 skipped in 190.34s`.
- **Integrity review:** `git diff --check` passed; all seven immutable baseline
  artifact hashes still match; no evaluation file changed; no credential,
  private-key, mnemonic, or seed pattern appeared in the implementation diff.
- **Runtime evidence:** `docs/remediation/runtime/eval_defect_006.json`.
- **Result:** `COMPLETE` at implementation checkpoint
  `6ad4e4ac786d2f8fa06af2d8aa0fd117110e9298`. Real paid model qualification
  remains independently `INCONCLUSIVE`: no exact production model has a current
  passing real benchmark, and the two prior bounded invalid provider responses
  remain uncredited at total cost `$0.00118674`.
- **Next action:** Begin `EVAL-DEFECT-007` by proving that effective CLI profile
  overrides can be reconstructed and verified from the emitted run alone.

## 2026-07-28 — EVAL-DEFECT-007

- **Status:** `COMPLETE`
- **Defensive objective:** Make every run self-describe its complete effective
  configuration and normalized safe override layers so `verify-run`, replay, and
  certification reproduce the audited configuration without operator memory.
- **Baseline negative assay:** A disposable synthetic manifest built from a
  standard base config plus `--profile maximum-assurance` recorded only derived
  hashes. The real `verify-run` CLI reloaded the unchanged standard config,
  returned exit `6`/`STALE`, and reported changed configuration, model, scanner,
  and compiler bindings. Passing the exact effective config directly produced
  `CURRENT` with zero mismatches, isolating the defect to discarded override
  provenance.
- **Adjacent reconciliation assay:** The current builder can combine a report
  claiming one profile/configuration with bindings built from another and the
  verifier can return `CURRENT`; report configuration hash, model hash, and audit
  profile therefore require explicit cross-checks at sealing and verification.
- **Implementation slice:** Added canonical, allowlisted file/environment/CLI
  configuration layers; typed non-secret run options; complete file and effective
  configuration serialization; layer, model, invocation, requested-profile, and
  achieved-profile hashes; manifest schema `1.1` with strict `1.0` compatibility;
  report-backed run-option and layer-origin reconciliation; and embedded config
  recovery for verification, replay, and certification. `--cost-ledger` is
  normalized into the effective CLI layer, while secret-file paths and key material
  remain excluded.
- **Adversarial assays closed so far:** Report identity hashes resealed into a
  manifest now produce explicit configuration mismatches; a raw base-config change
  masked by profile enforcement is still stale; self-consistent run-option
  tampering and CLI/environment layer reclassification are rejected through the
  independently emitted report provenance. Legacy `1.0` evidence remains readable
  but cannot self-authorize without an explicit configuration. Final independent
  review also found and closed missing `metadata.json`, type-confused Boolean,
  non-finite JSON, duplicate-key, unbound certification reread, mutable-path
  report-read, and quick/deep published-schema seams. Every verification and
  certification report read now uses the exact manifest-bound byte snapshot.
- **Focused validation so far:**
  - `.venv/bin/pytest -q tests/unit/test_config.py tests/unit/test_manifest.py
    tests/unit/test_traceability.py` — `52 passed`.
  - `.venv/bin/pytest -q tests/unit/test_replay.py
    tests/unit/test_certification.py` — `22 passed`.
  - `.venv/bin/pytest -q tests/unit/test_cli.py` — `59 passed`.
  - Two focused pipeline integration tests — `2 passed`.
  - `.venv/bin/pytest -q tests/unit/test_config.py tests/unit/test_manifest.py
    tests/unit/test_replay.py tests/unit/test_certification.py` — `75 passed in
    1.85s` after final adversarial fixes.
  - Focused Ruff and strict mypy checks on the final security-sensitive source
    changes — PASS.
  - `.venv/bin/pytest -q tests/integration/test_pipeline.py
    tests/integration/test_offline_replay.py` — `44 passed, 1 skipped in 58.82s`;
    the skip is the explicit unavailable hardened-isolation replay integration.
  - `.venv/bin/ruff check .` — PASS.
  - `.venv/bin/mypy` — PASS, `116 source files`.
  - `.venv/bin/pytest -q` — `1542 passed, 10 skipped in 202.71s`; every
    skip names an unavailable real provider, engine, hardened-isolation, replay,
    or sandbox loopback prerequisite and receives no maximum-assurance credit.
  - Final review found JSON exponent overflow and a certification manifest-swap
    seam; both are now fail-closed, with `78 passed in 2.28s` across the complete
    config/manifest/replay/certification focused set and strict mypy clean.
- Final post-review `.venv/bin/pytest -q` — `1545 passed, 10 skipped in
    203.25s`; targeted independent rechecks also passed `4` tests covering
    exponent overflow and cross-manifest certification identity.
- **Integrity review:** `git diff --check` passed; all seven immutable evaluation
  hashes match; `docs/evaluation/` is unchanged; `.env` remains ignored and
  untracked; no credential-like additions or generated debris were found.
- **Runtime evidence:** `docs/remediation/runtime/eval_defect_007.json`.
- **Result:** `COMPLETE` at implementation checkpoint
  `2b56995544f6393fd1b1d299beb1d24106aa5071`. The deterministic
  configuration/replay verification defect is closed. Real isolated Foundry
  replay remains independently `BLOCKED_TECHNICAL` because no hardened backend
  is available and receives no maximum-assurance credit.
- **Next action:** Begin `EVAL-DEFECT-008` by reproducing all vacuous benchmark
  metric passes and preserving failed/malformed/stale analyses in denominators.

## 2026-07-28 — EVAL-DEFECT-008

- **Status:** `COMPLETE`
- **Defensive objective:** Represent every unavailable benchmark denominator
  explicitly and make required zero-report, zero-case, zero-call, zero-location,
  and zero-attempt metrics fail closed without weakening acceptance thresholds.
- **Baseline empty-report assay (before remediation):** The real local CLI
  evaluated the frozen 28-case corpus against an empty disposable report
  directory. Overall status was
  `INCOMPLETE`, but emitted numeric recall, precision, safe-confirmation,
  location, and reproduction rates were all misleading `0.0`; the
  `safe_control_false_confirmations`, `evidence_caps`, and
  `maximum_assurance_semantic_coverage` gates reported `PASS`.
- **Baseline additional negative assays (before remediation):** Two parse-valid
  reports with `completed=false` and `quality_status=failed` still produced overall
  `PASSED` with every gate passing. Standard-profile reports with unrelated
  repository identities also passed when evaluated as maximum assurance.
  Setting all seven required semantic coverage metrics to `0/0` still passed
  semantic coverage. Aggregate coverage silently drops malformed entries.
- **Baseline certificate boundary assay (before remediation):** A manually
  constructed maximum-assurance report with no case results, no coverage
  metrics, and only arbitrary/mutation gate names was accepted by file-backed
  certification and could satisfy the assurance certificate clause.
- **Implementation slice:** Added typed `PASS`, `FAIL`, `NOT_EVALUABLE`,
  `NOT_APPLICABLE`, and `INCONCLUSIVE` metric states; fixed expected/evaluated
  denominators; typed missing/malformed/stale/failed report inputs; distinct
  quality and cost/runtime resources; strict source-hash location credit;
  unmatched-finding precision accounting; real-only provider/reproduction
  credit; typed Solidity coverage in product reports; and a fixed benchmark
  gate/metric portfolio.
- **Certification slice:** Benchmark report schema `3.0` is intentionally
  incompatible with vacuous legacy summaries. File-backed certification now
  calls the central certifiability predicate and rejects missing gates/metrics,
  non-PASS required metrics, `0/0`, incomplete case inventories, and legacy
  summaries even when invalid report bytes and the certificate envelope are
  re-hashed and resealed.
- **Published contract:** Added a generated strict Draft 2020-12 benchmark
  report schema and exact schema-parity tests.
- **Evidence classification:** Model joins, assurance inventories, certificate
  consistency, and certifier CLI controls use explicit synthetic/mock fixtures.
  The deliberately complete synthetic certifier fixture is certifiable only as a
  unit-level contract test; no real engine, provider, isolation, or product
  benchmark execution is inferred from it.
- **Commands and results:**
  - `.venv/bin/python -m mmaudit benchmark --corpus
    benchmarks/corpus/manifest.json --ground-truth-root . --profile
    maximum-assurance --output-json
    docs/remediation/runtime/eval_defect_008.json --no-color` — expected
    fail-closed exit `6`; emitted `INCOMPLETE`, 2 expected/0 loaded reports, and
    all 12 maximum-assurance gates `NOT_EVALUABLE`.
  - `.venv/bin/python -c 'from pathlib import Path; from
    mmaudit.benchmark.engine import BenchmarkReport;
    p=Path("docs/remediation/runtime/eval_defect_008.json");
    r=BenchmarkReport.model_validate_json(p.read_text());
    print({"schema_version": r.schema_version, "status": r.status.value,
    "reports_expected": r.reports_expected, "reports_loaded":
    r.reports_loaded, "gate_states": sorted({g.state.value for g in r.gates}),
    "gate_count": len(r.gates), "limitations": len(r.limitations)})'` — PASS;
    schema `3.0`, status `incomplete`, 2 expected/0 loaded, 12 gates, only
    `NOT_EVALUABLE` gate states.
  - `.venv/bin/pytest -q
    tests/unit/test_cli.py::test_benchmark_certificate_cli_success_and_current_verification
    tests/unit/test_cli.py::test_benchmark_certificate_cli_rejects_resealed_semantic_counter_bypass`
    — PASS, `2 passed in 0.45s`; this is synthetic CLI contract evidence.
  - `.venv/bin/pytest -q tests/unit/test_benchmark.py
    tests/unit/test_benchmark_certificate.py
    tests/unit/test_benchmark_model_evidence.py
    tests/unit/test_benchmark_assurance_binding.py
    tests/unit/test_benchmark_report_schema.py
    tests/unit/test_cli.py::test_benchmark_certificate_cli_success_and_current_verification
    tests/unit/test_cli.py::test_benchmark_certificate_cli_rejects_resealed_semantic_counter_bypass
    tests/unit/test_scanners_reporting.py tests/integration/test_pipeline.py` —
    PASS, `176 passed in 58.86s`.
  - `.venv/bin/ruff format .` — PASS, `264 files left unchanged`.
  - `.venv/bin/ruff check .` — PASS.
  - `.venv/bin/mypy` — PASS, `116 source files`.
  - `.venv/bin/pytest -q` — PASS, `1590 passed, 10 skipped in 196.79s`;
    every skip names an unavailable real provider, engine, hardened-isolation,
    replay, rootless image, or loopback prerequisite and earns no certification
    credit.
- **Integrity review:** `git diff --check` passed; all seven immutable evaluation
  hashes match; `docs/evaluation/` is unchanged; `.env` remains ignored and
  untracked; no credential material or unrelated generated debris was added.
- **Runtime evidence:** `docs/remediation/runtime/eval_defect_008.json`, SHA-256
  `b47e674c9ee86efdf505ce48d138327d1ae0beb3dd785134bd3f6a4bf8286cd7`.
- **Result:** `COMPLETE` at implementation checkpoint
  `a80087321a1a4f6ef1f79aee19ff4eebd8d7a0cd`. Required empty/partial
  denominators can no longer pass or certify, and report/case/coverage/model/
  resource/mutation/corpus evidence is internally reconciled before
  certification. Product artifact and candidate-commit binding remain correctly
  deferred to `EVAL-DEFECT-009` and `EVAL-DEFECT-010`.
- **Next action:** Begin `EVAL-DEFECT-009` by reproducing declared-name,
  missing/link, undeclared, stale, and hash-mismatch acceptance in release
  validation.

## 2026-07-28 — EVAL-DEFECT-009

- **Status:** `COMPLETE`
- **Defensive objective:** Require release validation to observe an actual,
  bounded emitted run directory, load its exact sealed evidence manifest, and
  verify the complete artifact inventory and hashes before runtime artifact names
  can satisfy traceability or release gates.
- **Baseline assay:** `.venv/bin/python scripts/validate_release_evidence.py`
  exited `0` and printed `release evidence valid` without accepting or loading a
  run directory. The script constructed `runtime_artifacts` by unioning the
  filenames declared in traceability itself, so missing, linked, undeclared,
  stale, or hash-mismatched emitted artifacts could not affect the result.
- **Implementation slice:** Added a typed, self-hashed release-artifact
  observation over one explicit emitted run; the observer parses the exact
  safely-read 1.1 manifest bytes, validates the complete emitted set and hashes,
  verifies current traceability content and required runtime artifacts, and
  observes the inventory again before accepting it. Artifact hashing now uses a
  non-following file descriptor with before/opened/finished/after identity
  reconciliation. Evidence writes use a fresh private read/write descriptor,
  byte-for-byte readback, and descriptor-to-final-path identity comparison.
  The validator refuses output within the observed run using directory identity
  rather than lexical casing. CI validates one emitted run and uploads only an
  explicit public-artifact allowlist, its run manifest, and the sealed
  observation; `private/**` remains local.
- **Negative regressions:** Missing manifest; linked run root or ancestor;
  linked/hardlinked artifact; missing, undeclared, changed-hash, stale
  traceability, legacy/non-reconstructable manifest, resealed name-only reduced
  inventory, pathname swap before open, evidence-link/tamper/replacement,
  validator-without-run, output-inside-run, and distinct case/Unicode filesystem
  aliases.
- **Runtime validation:** A fresh local scanner-only run was emitted at
  `/private/tmp/mmaudit-eval009-runtime/runs/20260728T082858Z-66f3e567`.
  `scripts/validate_release_evidence.py` observed 31 actual artifacts and wrote
  `docs/remediation/runtime/eval_defect_009.json`; its file SHA-256 is
  `bf2420a76c4009bb9ddb622b252c1658ddef974d80a923edc8a3be821bb869c1`.
  This is real local STANDARD scanner evidence, not maximum-assurance
  certification.
- **Validation so far:**
  - `.venv/bin/ruff format src/mmaudit/orchestration/manifest.py
    src/mmaudit/release_artifacts.py tests/unit/test_release_artifacts.py
    scripts/validate_release_evidence.py` — PASS; one file reformatted.
  - `.venv/bin/ruff check <same files>` — PASS.
  - `.venv/bin/mypy src/mmaudit/orchestration/manifest.py
    src/mmaudit/release_artifacts.py` — PASS, two source files.
  - `.venv/bin/pytest -q tests/unit/test_release_artifacts.py` — PASS,
    `20 passed in 3.34s`, including both distinct filesystem-alias regressions.
  - The first adjacent command named nonexistent
    `tests/integration/test_traceability.py`; pytest exited `4` before
    collection. The corrected path is `test_traceability_artifact.py`; this
    command will not be repeated unchanged.
  - The next command used the corrected traceability path but guessed a
    nonexistent pipeline test node; `rg` isolated the actual
    `test_successful_multi_agent_audit` node before retrying.
  - `.venv/bin/pytest -q tests/unit/test_manifest.py tests/unit/test_release.py
    tests/unit/test_release_artifacts.py tests/unit/test_traceability.py
    tests/integration/test_traceability_artifact.py
    tests/integration/test_pipeline.py::test_successful_multi_agent_audit` —
    PASS, `52 passed in 4.48s`.
  - Ruby/Psych 2.6 rejected the newer `aliases:` keyword after the tests passed;
    the compatible read-only parser command then validated the workflow as a
    four-job mapping. `git diff --check` passed.
  - Independent reviewers found no remaining EVAL-009 code blocker after
    verifying the public/private CI boundary, exact-run selection, SARIF handoff,
    manifest parsing, file-descriptor-bound hashing, evidence readback/final-path
    identity, missing/resealed/stale/hash/link regressions, and case/Unicode
    containment aliases. The uploaded CI bundle is explicitly documented as a
    public report subset, not a complete independently revalidatable run.
  - Re-running `.venv/bin/python scripts/validate_release_evidence.py --run-dir
    /private/tmp/mmaudit-eval009-runtime/runs/20260728T082858Z-66f3e567
    --artifact-evidence-output
    docs/remediation/runtime/eval_defect_009.json` under the hardened writer —
    PASS; 31 artifacts, mode `0600`, 5,568 bytes, unchanged deterministic file
    SHA-256
    `bf2420a76c4009bb9ddb622b252c1658ddef974d80a923edc8a3be821bb869c1`.
  - `.venv/bin/ruff format .` — PASS, 266 files unchanged.
  - `.venv/bin/ruff check .` — PASS.
  - `.venv/bin/mypy` — PASS, 117 source files.
  - `.venv/bin/pytest -q` — PASS, `1610 passed, 10 skipped in 205.76s`;
    every skip names an unavailable paid-provider, real engine, rootless image,
    local-fork isolation, replay, or loopback prerequisite and none counted as
    release execution.
  - `make release-evidence PYTHON=.venv/bin/python
    RELEASE_RUN_DIR=/private/tmp/mmaudit-eval009-runtime/runs/20260728T082858Z-66f3e567`
    — PASS; the release validator loaded the exact emitted manifest and reported
    `schemas=21`, `benchmark_sources=15`, `model_cases=16`,
    `economic_cases=18`, `adversarial_cases=10`,
    `full_protocol_files=9`, and the honest existing
    `release_status=blocked_technical`.
  - `.venv/bin/pytest -q tests/unit/test_release_artifacts.py
    tests/unit/test_manifest.py` — PASS, `33 passed in 4.13s`.
  - Final integrity review: Ruby/Psych parsed the workflow as four jobs;
    `git diff --check` passed; all seven immutable evaluation hashes match;
    `docs/evaluation/` has no diff; `.env` remains ignored and unstaged; the
    changed source, tests, schema, and runtime artifact contain no high-risk
    credential/key pattern.
- **Remaining limitation:** Commit-bound release-report freshness and
  reconciliation with the exact candidate remain intentionally deferred to
  `EVAL-DEFECT-010`; concurrent replacement of an already validated ancestor
  directory requires local filesystem control while no target process executes
  and remains outside this ticket's file-level acceptance contract.
- **Runtime evidence:** `docs/remediation/runtime/eval_defect_009.json`, SHA-256
  `bf2420a76c4009bb9ddb622b252c1658ddef974d80a923edc8a3be821bb869c1`.
- **Result:** `COMPLETE` at implementation checkpoint
  `cd46d215bd77e4c6e1d505d4a7f7773bdb78e525`. Release validation now
  observes a real explicit run, requires a reconstructable sealed manifest,
  reconciles the complete emitted set/size/hash and current traceability, and
  persists a self-hashed observation. Missing, linked, hardlinked, undeclared,
  name-only, stale, hash-mismatched, and concurrently replaced file evidence
  fails closed.
- **Next action:** Begin `EVAL-DEFECT-010` without weakening the honest
  `BLOCKED_TECHNICAL` real-integration status.

## 2026-07-28 — EVAL-DEFECT-010

- **Status:** `IN_PROGRESS`
- **Defensive objective:** Derive a fresh release report from actual gate
  observations and bind it to the exact candidate commit, effective
  configuration, emitted artifacts, and evidence hashes while preserving every
  external blocker.
- **Baseline assay:** The committed `docs/release_gate_report.json` still names
  `release-001-2026-07-27` and
  `repository_state=uncommitted-worktree-no-initial-commit`; it contains no
  candidate-commit, effective-config, emitted-artifact-observation, or generation
  timestamp binding. Its reported test/source/schema counts and manifest command
  predate the current candidate, yet its self-hash remains structurally valid.
- **Implementation slice:** Added strict, self-hashed observations for a clean
  Git candidate, one exact emitted audit run, and deterministic local release
  inputs. The run identity remains explicitly separate from the product
  candidate identity. Renamed the tracked operator-secret template out of the
  permanently forbidden `.env.*` namespace while retaining permanent target
  ingestion exclusions for the replacement template and all secret-shaped
  inputs.
- **Evidence derivation slice:** Added descriptor-safe canonical evidence I/O,
  typed runtime gate receipts, a five-input v2 release report, and a CURRENT
  run-verification binding. Passed gates require real exit-zero execution,
  measured tool identity, nonempty checks, and exact artifacts; failures cannot
  be laundered as blockers. The verifier independently re-observes the emitted
  run and hash-bound target sources, with distinct explicit target and mmaudit
  repository roots. The report derives every count and status from the receipt
  set and binds the candidate commit/tree, effective configuration, emitted
  inventory, verification, static corpus, and exact evidence files.
- **Validation so far:**
  - An initial Ruff command incorrectly included the non-Python
    `src/mmaudit/templates/mmauditignore` template and exited `2`; it was not
    repeated unchanged.
  - `.venv/bin/ruff format src/mmaudit/release_run.py
    src/mmaudit/release_static.py src/mmaudit/constants.py
    tests/unit/test_release_run.py tests/unit/test_release_static.py
    tests/unit/test_repository.py` — PASS; six files unchanged.
  - `.venv/bin/ruff check <same Python files>` — PASS.
  - `.venv/bin/mypy src/mmaudit/release_run.py
    src/mmaudit/release_static.py` — PASS, two source files.
  - `.venv/bin/pytest -q tests/unit/test_release_run.py
    tests/unit/test_release_static.py tests/unit/test_repository.py` — PASS,
    `68 passed in 1.17s`.
  - `.venv/bin/ruff format <candidate/gate/io/report/run/static/verification
    source and tests>` — PASS; 14 files unchanged.
  - `.venv/bin/ruff check <same files>` — PASS.
  - `.venv/bin/mypy src/mmaudit/release_candidate.py
    src/mmaudit/release_gates.py src/mmaudit/release_io.py
    src/mmaudit/release_report.py src/mmaudit/release_run.py
    src/mmaudit/release_static.py src/mmaudit/release_verification.py` — PASS,
    seven source files.
  - `.venv/bin/pytest -q tests/unit/test_release_candidate.py
    tests/unit/test_release_gates.py tests/unit/test_release_io.py
    tests/unit/test_release_report.py tests/unit/test_release_run.py
    tests/unit/test_release_static.py tests/unit/test_release_verification.py`
    — PASS, `115 passed in 4.01s`.
  - Hardened the four fixed local commands with Python safe-path execution,
    a hash-bound socket-denial guard, a fixed sanitized environment, separate
    Python/distribution hashes, bounded output/runtime/resources, nonempty
    pytest JUnit accounting, and confirmed descendant process-group cleanup.
    Regressions prove repository-local tool shadows are ignored, the network
    guard actually loads, direct/raw socket operations fail, and incomplete
    process cleanup fails closed.
  - Added typed bound-observation artifacts. Only exact emitted artifacts,
    reconstructable CURRENT manifests, and static schemas/nonempty corpus
    denominators can pass locally. Benchmark certificate, doctor, real
    maximum-assurance execution, exact-model benchmark, and isolated replay
    remain `BLOCKED_TECHNICAL`; attempts to relabel a blocker as a pass fail
    semantic validation.
  - Added the fixed report collector/generator, fresh private external output
    roots, exact flat output inventories, generated standalone result schemas,
    explicit artifact-only versus full validator modes, and an authoritative
    `--require-complete` policy. The old declarative report builder/loader is no
    longer a production certification path.
  - Independent review identified and resolved final source-state TOCTOU,
    one-way containment, auxiliary evidence identity, non-strict parsing,
    end-of-validation freshness, exact-role, ignored tool-shadow, tool-hash,
    network-guard, and descendant-cleanup gaps. No remaining completion-policy
    bypass was found in the reviewed path.
  - `.venv/bin/python scripts/generate_release_schemas.py --write` followed by
    verification — PASS; candidate, bound/local result, gate bundle, v2 report,
    run, verification, and static-evidence schemas match their strict models.
  - `.venv/bin/pytest -q tests/unit/test_release.py
    tests/unit/test_release_candidate.py tests/unit/test_release_collection.py
    tests/unit/test_release_gates.py tests/unit/test_release_io.py
    tests/unit/test_release_observations.py tests/unit/test_release_report.py
    tests/unit/test_release_run.py tests/unit/test_release_runtime.py
    tests/unit/test_release_schemas.py tests/unit/test_release_static.py
    tests/unit/test_release_validation.py
    tests/unit/test_release_verification.py` — PASS, `188 passed in 8.66s`.
  - All seven immutable baseline evaluation SHA-256 values reverified exactly;
    `docs/evaluation/` remains unchanged and `git diff --check` passed.
  - The first tracked-diff credential scan intentionally used an over-broad
    `OPENROUTER_API_KEY=` pattern and exited `9` on the documented placeholder;
    it exposed no value. A materially narrower scan rejected real
    `sk-or-v1-*` shapes and non-placeholder assignments and passed.
  - `.venv/bin/ruff format . && .venv/bin/ruff check . &&
    .venv/bin/mypy && .venv/bin/pytest -q` — PASS; 291 files unchanged,
    Ruff clean, strict mypy clean across 128 source files, and `1799 passed,
    10 skipped in 215.89s`. Every skip names an unavailable paid-provider,
    real-engine, rootless-image, local-fork, replay, or loopback prerequisite;
    none received release credit.
- **Exact next safe action:** Create the implementation checkpoint, then use
  that clean exact commit to generate and authoritatively validate fresh
  external `BLOCKED_TECHNICAL` release evidence without provider access.
