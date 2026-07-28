# mmaudit v3 Operator Prerequisites

This document records external prerequisites without credentials or private source.

## Baseline

No external prerequisite is required for `V3-BASELINE-001`.

## Real OpenRouter execution

Real provider tests require all of the following:

- explicit `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1`;
- explicit operator-controlled `--secrets-env-file PATH`;
- an exact model allowlist and exact approved endpoint;
- an explicit privacy profile;
- a numeric per-command cost cap within the aggregate remaining budget;
- a committed synthetic local Solidity source scope for smoke and qualification;
- fallback routing disabled for certification.

The secret file is never target input and its contents must not be displayed,
logged, hashed, copied, or persisted.

## External engines and isolation

Certified maximum assurance remains fail-closed until every mandatory engine and a
digest-pinned approved rootless isolation backend execute with real evidence.
Unavailable integrations must retain exact non-secret operator installation or
configuration instructions when their tickets begin.

## External evaluation

A private holdout and independently adjudicated professional comparison are not
present. Superiority therefore remains `NOT_DEMONSTRATED`.
