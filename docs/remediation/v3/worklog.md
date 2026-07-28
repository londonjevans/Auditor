# mmaudit v3 Product Remediation Worklog

The objective source has SHA-256
`f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43`.
Do not record credentials, raw private prompts, or raw provider completions here.

AUTORUN_STATUS: RUNNING
CURRENT_MILESTONE: Bind canonical OpenRouter model and endpoint identity
CURRENT_TICKET: V3-IDENTITY-001
LAST_COMPLETED_TICKET: V3-BASELINE-001
NEXT_ACTION: Add typed identity strengths, frozen alias resolution, exact endpoint binding, and valid-but-unbound response retention with focused regressions.
LAST_COMMAND: .venv/bin/pytest -q
LAST_RESULT: PASS — 1799 passed, 10 skipped in 217.18s; baseline format, lint, typing, generated schemas, and tests are green.
REAL_MODEL_CALLS_ATTEMPTED: 2
REAL_MODEL_CALLS_SUCCEEDED: 0
REAL_MODEL_CALLS_REJECTED: 2
OPENROUTER_COST_USED_USD: 0.00118674
OPENROUTER_COST_RESERVED_USD: 0.00
OPENROUTER_BUDGET_REMAINING_USD: 249.99881326
COMPLETED_REAL_AUDITS: 0
BLOCKED_EXTERNAL_ITEMS: No successful identity-bound model completion; no qualified production ensemble; required rootless isolation and several certified external engines remain unavailable; private holdout and independently adjudicated professional comparison are not supplied.
LAST_CHECKPOINT_COMMIT: 6465bb5824903180f2fc631663ab327993c36a20

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
