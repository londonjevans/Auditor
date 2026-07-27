# mmaudit Remediation Worklog

The seven files under `docs/evaluation/` are immutable baseline evidence from
commit `e304807cf942542706b88544fa216516f8f95cad`.

AUTORUN_STATUS: IN_PROGRESS
CURRENT_TICKET: EVAL-DEFECT-001
LAST_COMPLETED_TICKET: REM-SECRET-001
NEXT_ACTION: Add the compilation_failed negative assay and require successful AST-backed compilation for certified maximum assurance.
LAST_COMMAND: .venv/bin/ruff format . && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q
LAST_RESULT: PASS — Ruff formatted 7 files and passed; mypy checked 102 source files; pytest passed 695 tests with 9 explicit external-integration skips in 142.76s.
REMAINING_CODE_DEFECTS: 13
REMAINING_REAL_INTEGRATIONS: OpenRouter exact-model smoke/qualification/specialist review; Slither; Echidna; Medusa; Halmos; formal proof engine; rootless isolation; isolated replay; product benchmark reports
BLOCKED_EXTERNAL_PREREQUISITES: Echidna, Medusa, Kontrol, Certora, rootless runtime/image, private holdout, and independently adjudicated expert comparison are not yet evidenced as available
OPENROUTER_COST_USED_USD: 0.00
LAST_CHECKPOINT_COMMIT: a333ff9df5c1b680c110c0e011682dfbf4e7aa42

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

- **Status:** `IN_PROGRESS`
- **Defensive objective:** Require successful AST-backed compilation before a
  certified maximum-assurance run can be complete.
- **Exact next safe action:** Reproduce the baseline `compilation_failed` assay in
  a permanent regression, then repair the assurance clause without weakening any
  profile or evidence gate.
