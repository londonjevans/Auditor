# mmaudit v3 Operator Prerequisites

This document records external prerequisites without credentials or private source.

## Baseline

No external prerequisite is required for `V3-BASELINE-001`.

## Real OpenRouter execution

Real provider tests require all of the following:

- explicit `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1`;
- explicit operator-controlled `--secrets-env-file PATH`;
- an exact model allowlist and exact approved endpoint;
- an explicit `MMAUDIT_REAL_PROVIDER_PRIVACY_PROFILE=STRICT_ZDR` profile;
- a numeric per-command cost cap within the aggregate remaining budget;
- a fresh absolute private JSON evidence destination beneath an existing
  operator-controlled directory;
- a committed synthetic local Solidity source scope for smoke and qualification;
- fallback routing disabled for certification.

The secret file is never target input and its contents must not be displayed,
logged, hashed, copied, or persisted.

## Endpoint-aware token planning

Every model request requires frozen endpoint metadata for its exact model and
approved provider routes. The conservative intersection of those routes supplies
the context, prompt, and completion limits; missing or incompatible limits fail
preflight.

Operators configure a usable-input fraction between 65% and 75%. mmaudit applies
that fraction only after reserving completion and reasoning capacity, then
reserves system, schema, protocol, and request-specific workflow overhead before
allocating source context. Configured reserves are floors, not permission to
ignore larger measured material.

Without an exact endpoint tokenizer, source selection uses a deterministic token
estimate while final request planning treats the complete UTF-8 prompt envelope
as a conservative upper bound. The source-token ceiling is therefore distinct
from the serialized context-package byte limit. Large metadata is reduced or
omitted with typed evidence before it can crowd required source out.

Visible output is allocated explicitly among findings, per-surface coverage, and
summary. Every category has a positive floor, coverage grows with the requested
surface count, and an infeasible allocation is rejected before transport rather
than silently reducing coverage.

Endpoint-capacity, context-plan, global-token-budget, and cost-budget
failures remain distinct. A rejected request may retain a self-hashed diagnostic
snapshot of whichever route, prompt-category, output-allocation, and omission
facts were measured; unavailable components remain explicitly unavailable.
Diagnostic snapshots contain no raw prompt or source and always record that no
provider request, reservation, or review credit was created. A preflight
rejection never counts as provider execution or substantive model review.

## External engines and isolation

Certified maximum assurance remains fail-closed until every mandatory engine and a
digest-pinned approved rootless isolation backend execute with real evidence.
Unavailable integrations must retain exact non-secret operator installation or
configuration instructions when their tickets begin.

## External evaluation

A private holdout and independently adjudicated professional comparison are not
present. Superiority therefore remains `NOT_DEMONSTRATED`.
