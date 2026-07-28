# Real OpenRouter Smoke Test

The real-provider integration is excluded from normal pytest execution. It makes
one synthetic structured-output request only when every fail-closed prerequisite is
present:

- `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1` (the exact sentinel);
- `MMAUDIT_SECRETS_ENV_FILE` set to an absolute operator-controlled dotenv path;
- `MMAUDIT_REAL_PROVIDER_COST_CAP_USD` set to a plain positive decimal no greater
  than the remediation-wide USD 250 cap;
- `MMAUDIT_OPENROUTER_COST_LEDGER` set to the absolute path of the existing
  cumulative remediation ledger created once with
  `mmaudit models init-cost-ledger --cost-ledger PATH`;
- `MMAUDIT_REAL_PROVIDER_MODEL_ID` set to one exact non-placeholder
  `author/model` ID;
- `MMAUDIT_REAL_PROVIDER_MODEL_ALLOWLIST` containing that exact model ID; and
- `MMAUDIT_REAL_PROVIDER_ENDPOINT_ALLOWLIST` containing exactly one approved
  provider endpoint tag or slug;
- `MMAUDIT_REAL_PROVIDER_PRIVACY_PROFILE=STRICT_ZDR`;
- `MMAUDIT_REAL_PROVIDER_EVIDENCE_OUTPUT` set to a fresh absolute `.json` path
  beneath an existing unlinked operator-controlled directory.

Run only the explicitly selected test:

```console
.venv/bin/pytest -q tests/integration/test_real_openrouter_provider.py
```

The harness validates all non-secret settings, the pinned committed
`tests/fixtures/solidity/provider_smoke/src/ProviderSmoke.sol` hash, and the fresh
evidence destination before opening the secret file. It
uses the repository's dotenv parser (never shell evaluation), canonical OpenRouter
transport, certification routing with fallbacks disabled, parameter enforcement,
data collection denied, ZDR required, a durable atomic cost ledger, one-request
limit, and no raw prompt/response storage. It sends no repository source or target
data beyond that bounded synthetic fixture. A successful response writes a fresh
mode-`0600`, self-hashed evidence artifact containing only validated structured
output and non-secret model, provider, identity, token, timing, hash, and reconciled
cost metadata. The raw prompt, raw completion, credential, secret-file path, and
fixture source are not persisted. The paid test opens the existing cumulative ledger and cannot create or reset
budget state. Missing, deleted, moved, malformed, or cap-mismatched ledger state
fails before secret loading or network access; absent opt-in skips the test.
Production `mmaudit run` uses the same rule: it must open an existing ledger
selected by `--cost-ledger`, `execution.cost_ledger_path`, or
`MMAUDIT_COST_LEDGER_PATH`; it never creates budget state in a per-run output
directory.
