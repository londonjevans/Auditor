# mmaudit Remediation Worklog

The seven files under `docs/evaluation/` are immutable baseline evidence from
commit `e304807cf942542706b88544fa216516f8f95cad`.

AUTORUN_STATUS: IN_PROGRESS
CURRENT_TICKET: REM-MODELS-001
LAST_COMPLETED_TICKET: REM-OPENROUTER-001
NEXT_ACTION: Checkpoint and push the completed exact OpenRouter client and cost-ledger controls, then freeze the production model registry and qualification artifact contract before any paid model call.
LAST_COMMAND: .venv/bin/pytest -q
LAST_RESULT: PASS — post-review full suite passed with 1060 tests and 10 explicit real-integration skips in 156.13s; full Ruff formatting/check and strict mypy also passed.
REMAINING_CODE_DEFECTS: 9
REMAINING_REAL_INTEGRATIONS: OpenRouter exact-model smoke/qualification/specialist review; certified-isolation Foundry and Slither; Echidna; Medusa; Halmos; formal proof engine; rootless isolation; isolated replay; product benchmark reports
BLOCKED_EXTERNAL_PREREQUISITES: Echidna, Medusa, Kontrol, Certora, rootless runtime/image, private holdout, and independently adjudicated expert comparison are not yet evidenced as available
OPENROUTER_COST_USED_USD: 0.00
LAST_CHECKPOINT_COMMIT: ac71dc0400556f3a8b0b32ed33a1524f448718c7

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

- **Status:** `IN_PROGRESS`
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
- **Exact next safe action:** Checkpoint and push this ticket, then freeze the
  exact production candidate registry and qualification artifact contract under
  `REM-MODELS-001` before authorizing any paid call.
