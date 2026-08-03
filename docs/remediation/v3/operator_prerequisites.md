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

### Trivy offline vulnerability database

The typed operator preparation step is
`prepare_trivy_offline_vulnerability_database`. Trivy 0.72.0 exposes this bounded
one-time network-enabled preparation command:

```text
trivy image --download-db-only --cache-dir <absolute-operator-controlled-cache-dir> --no-progress
```

Run that command only in an explicit operator-controlled preparation phase, never
inside target analysis. The audit phase remains offline.

The current adapter deliberately uses a fresh private per-run cache and does not
yet expose or stage an approved prepared-cache path. Consequently, running the
command against an unrelated cache does **not** unblock mmaudit today. Until a
future typed configuration binds, validates, and stages that exact prepared cache
read-only into the isolated scanner workspace, Trivy reports
`UNMET_PREREQUISITE` and does not earn scanner-completion or maximum-assurance
credit. No operator credential or target-controlled cache is accepted.

### Hardhat pinned-fork execution

`V3-FORKSUITE-001` cannot credit real Hardhat execution on the current host. A
future operator-authorized integration requires:

- an installed approved rootless Podman or Docker backend;
- an approved digest-pinned image containing the pinned Node.js, Hardhat, test
  runner, and machine-result reporter toolchain;
- REAL process and image-identity attestation bound to the emitted run;
- network-none container execution with a narrowly scoped Unix-socket,
  read-only JSON-RPC bridge to the exact operator-configured loopback fork
  endpoint;
- read-only audited source, disposable output and home directories, no host
  credentials or container socket, and bounded CPU, memory, process, output, and
  runtime limits.

Neither `podman` nor `docker` resolves on the current trusted host PATH and no
approved image digest is configured. The adapter therefore remains fail-closed
as `UNAVAILABLE`; broad container networking or host-loopback access is not an
acceptable substitute.

`V3-HARDHAT-001` now supplies the safe local contracts needed before that external
integration: pinned reporter source plus separate schemas, a non-crediting
two-phase request protocol, an owner-only AF_UNIX read-only RPC listener, a bounded
in-container raw relay, a `--network none` wrapper, fixed in-image executable
tokens, and a process-local lifetime seal that revalidates the exact backend,
bridge, PID, private directory, socket, endpoint, policy, and pinned state. Closing
the seal, stopping or replacing the socket, copying the backend, or changing any
bound identity invalidates command construction. This still grants only
`UNVERIFIED` command-construction authority.

The current trusted host resolves Node.js but not `hardhat`, `podman`, or `docker`.
The local protocol test therefore uses a handcrafted Node/EventEmitter reporter
process explicitly marked `MOCK`; it is not Hardhat/Mocha execution. It does not
prove `.only`, callback-less pending tests, runtime filtering, phase-one body
non-execution, relay-to-test attribution, monorepo project roots, container exit/
output custody, or image-side executable identity. JSX/TSX source snapshots are
deliberately rejected until a real syntax-aware parser exists. A real integration
must supply and attest all of those missing facts; no filename, host path, process
double, or serializable observation may substitute for them. Constructed container
argv is replayable and receives no authority of its own: the eventual executor must
retain the opaque live binding and revalidate it immediately before spawn and after
process completion.

## External evaluation

A private holdout and independently adjudicated professional comparison are not
present. Superiority therefore remains `NOT_DEMONSTRATED`.
