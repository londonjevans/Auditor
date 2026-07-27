# mmaudit Remediation Worklog

The seven files under `docs/evaluation/` are immutable baseline evidence from
commit `e304807cf942542706b88544fa216516f8f95cad`.

AUTORUN_STATUS: IN_PROGRESS
CURRENT_TICKET: EVAL-DEFECT-003
LAST_COMPLETED_TICKET: EVAL-DEFECT-002
NEXT_ACTION: Require qualifying real, non-empty execution provenance for the exact certified engine portfolio.
LAST_COMMAND: .venv/bin/pytest -q tests/unit/test_assurance.py tests/unit/test_reproduction.py tests/unit/test_reproduction_integrity.py tests/integration/test_pipeline.py
LAST_RESULT: PASS — 110 tests passed in 42.49s; affected Ruff and strict mypy gates passed; independent code review found no remaining EVAL-DEFECT-002 blocker.
REMAINING_CODE_DEFECTS: 11
REMAINING_REAL_INTEGRATIONS: OpenRouter exact-model smoke/qualification/specialist review; Slither; Echidna; Medusa; Halmos; formal proof engine; rootless isolation; isolated replay; product benchmark reports
BLOCKED_EXTERNAL_PREREQUISITES: Echidna, Medusa, Kontrol, Certora, rootless runtime/image, private holdout, and independently adjudicated expert comparison are not yet evidenced as available
OPENROUTER_COST_USED_USD: 0.00
LAST_CHECKPOINT_COMMIT: f2a782b7319ccad848df392f5d40da45fcc63283

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
- **Exact next safe action:** Checkpoint this ticket, record its commit, and
  continue `EVAL-DEFECT-003`.

## 2026-07-27 — EVAL-DEFECT-003

- **Status:** `IN_PROGRESS`
- **Defensive objective:** Require the exact real engine portfolio, non-empty
  execution evidence, hardened isolation, replay, real model review, and a current
  benchmark for certified maximum assurance.
- **Exact next safe action:** Add explicit execution provenance and permanent
  missing-engine negative assays before changing portfolio defaults.
