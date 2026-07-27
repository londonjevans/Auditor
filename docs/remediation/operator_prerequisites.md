# Operator Prerequisites

This ledger records external prerequisites without treating their absence as
successful integration evidence. Commands use placeholders and must be adapted to
the operator-controlled environment.

## OpenRouter

- An operator-controlled regular dotenv file with owner-only or otherwise
  non-group/world-writable permissions.
- The allowlisted `OPENROUTER_API_KEY` entry.
- Explicit invocation with `--secrets-env-file <operator-secret-file>` or
  `MMAUDIT_SECRETS_ENV_FILE=<operator-secret-file>`.
- An absolute path in an operator-owned mode-`0700` directory for the cumulative
  paid-provider ledger. Initialize it exactly once with
  `mmaudit models init-cost-ledger --cost-ledger <absolute-path>`, then select that
  same existing file with `mmaudit run --cost-ledger <absolute-path>`,
  `execution.cost_ledger_path`, or `MMAUDIT_COST_LEDGER_PATH`.
- The configured `execution.budget_usd` must remain equal to the ledger's immutable
  campaign cap. A missing, deleted, moved, malformed, active-reservation, or
  cap-mismatched ledger fails before secret loading and provider access.
- Real tests additionally require `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1`, an exact
  model allowlist, and a numeric cost cap. The normal suite never spends money.

## Local engines

- Trusted, off-repository executables for Echidna, Medusa, Kontrol, and any selected
  formal proof engine, with exact supported version and SHA-256 pins.
- Slither, Foundry, Halmos, Z3, and Solidity compilers must be re-inventoried at the
  candidate commit and still require real paired-control execution.
- Certora requires a separately authorized service-network phase, its own explicit
  control-plane credential interface, and no OpenRouter credential propagation.

## Rootless isolation and replay

- A verified rootless Podman or Docker-compatible backend.
- A locally available digest-pinned audit image containing the exact trusted
  toolchain; no mutable tag and no implicit pull.
- The image must pass read-only source, private output/home, no network/socket/
  credentials, CPU/memory/PID/time/output limits, cleanup, and hostile-repository
  containment before it can qualify engine or replay evidence.

## Independent evaluation evidence

- A private or blinded holdout is required to evaluate holdout performance.
- Identical-commit, identical-scope professional reports with independent
  adjudication are required before superiority can be evaluated.
- Their absence keeps `SUPERIORITY_STATUS` at `NOT_EVALUATED`; internal fixtures,
  model count, and tool count cannot substitute.
