# mmaudit v3 Operator Prerequisites

This document records external prerequisites without credentials or private source.

## Baseline

No external prerequisite is required for `V3-BASELINE-001`.

## Real OpenRouter execution

Real provider tests require all of the following:

- explicit `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1`;
- explicit operator-controlled `--secrets-env-file PATH`;
- an exact model allowlist and exact approved endpoint;
- an explicit `MMAUDIT_REAL_PROVIDER_PRIVACY_PROFILE=SYNTHETIC_BENCHMARK` profile;
- a numeric per-command cost cap within the aggregate remaining budget;
- a fresh absolute private JSON evidence destination beneath an existing
  operator-controlled directory;
- a committed synthetic local Solidity source scope for smoke and qualification;
- the exact frozen release-pinned policy supplied as `--qualification-policy PATH` for candidate
  campaigns;
- fallback routing disabled for certification.

Private production audits additionally require a pre-execution
`--learning-tenant-scope-id tenant-scope-<64-lowercase-hex>`. The operator provisions one opaque
value per tenant boundary; repository/output paths, run IDs, and source hashes are not tenant
identities. Terminal learning stays private, manifest-bound, and explicitly nonauthorizing.

The secret file is never target input and its contents must not be displayed,
logged, hashed, copied, or persisted.

The dedicated `models authenticated-runner` command does not use the test-harness
`MMAUDIT_RUN_REAL_PROVIDER_TESTS` switch. It requires the same
`SYNTHETIC_BENCHMARK`/ZDR/no-fallback policy, the explicit `--allow-code-egress` CLI opt-in,
three fresh singleton discovery registries, the exact frozen `--qualification-policy PATH`, and
same-process runner custody. Its `--preflight-only` mode deliberately stops before secret selection
or provider access. The completed provider-free runtime-admission mechanism additionally accepts an
explicit absolute private canonical legacy-v1.2 or current-v1.3 smoke bundle through
`--runtime-evidence-smoke-bundle PATH`; that input can affect only the exact three
route/profile/discovery bindings it proves and cannot grant qualification, campaign, runtime,
audit, selection, or release authority. Token evidence and usage routing must join the full
request-token-plan hash, while the preview must separately join the recomputed stable projection
hash.

Schema retry continuity is provider-free and explicit. The frozen retry-off base remains
`config/openrouter-qualification.toml`; a future authenticated-runner launch selects exactly three
same-route schema retries only by also passing
`--retry-continuity-config config/openrouter-authenticated-runner-retry-continuity.toml`.
`max_model_retries = 1` remains transient-only, the combined maximum is five attempts per logical
request, and first-attempt-only qualification scoring is unchanged. Current durable v1.2 evidence
and offline verification bind the full effective configuration, execution subtree, and attempt
capacity. These local controls grant no candidate, provider, campaign, qualification, audit, or
release authority.

Ordinary paid audits and their provider-free quotes use the separate
`--schema-validation-retries N` selection on `mmaudit run` and `mmaudit quote create`, with `N`
bounded from `1` through `31`. Omission keeps same-route schema retry off. A configuration with a
nonzero quota requires the exact same explicit CLI selection, and a conflict fails before paid
controls or quote inputs. `max_model_retries` remains transient-only. Current quote, acceptance,
budget, usage, and manifest-v1.3 evidence bind the exact split-policy hash; manifest/smoke v1.2 is
legacy retry-off replay and cannot substitute for current split-retry custody.

### Current campaign-admission boundary

The `2026-08-28T07:56Z` operator-supplied record is 148,339 bytes / 2,648 lines at SHA-256
`d06ae996c74996110822dcd4cbbc1b754c72666551e630edb2627cc50c243089`. It is nonauthorizing,
uncommitted, and not independently authenticated by Codex. Its newest provider-free entry reports
that the one correct candidate tombstone rejects the revoked DeepSeek/`parasail/fp8` assignment but
also blocks every unrevoked alternative because plan eligibility evaluates the whole pinned route
set. The ledger remains 57 entries / `0.68118684` USD and completed real audits remain zero.
`V3-REVOKERECON-001` is queued and unselected.
The tombstone reason is `EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE`; pinned plan
`bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f` still lists that route.
MiniMax/Coreweave, Gemma/DeepInfra, and Tencent/Novita alternatives were all refused by plan-route
eligibility, while the incumbent was correctly refused at assignment. No repository command emits
a successor selection plan, so hand-editing the hash-pinned input is not an approved workaround.

The immediately preceding entry reports fresh r23 discovery, paid smoke index 22 (`0.04395915` USD;
bundle
`29702a02f52626deca38ff36401eb3cb7bb4602f07677881760ad26ba40df5d4`, verified
`VALID / NONCREDITING / NONAUTHORIZING`), and `FULL_CAMPAIGN_ADMISSION` satisfied for one launch.
The 24-case campaign then failed closed after roughly 24 logical requests and `0.20264508` USD: nine
schema-invalid responses became `SCHEMA_VALIDATION_FAILED`, 15 completed response identities were
unbound, and terminal candidate provenance was rejected. The operator reports all 24 new ledger
entries reconciled, 57 entries / `0.68118684` USD total, and zero completed real audits.

The corrected provider-free mechanism remains `COMPLETE` under `V3-RUNTIMEADMIT-001`, but that one
failed launch creates no reusable admission or future authority. Codex did not read the private
registries, bundle, campaign, or ledger. The frozen DeepSeek/`parasail/fp8` candidate is non-runnable
pending revocation/plan reconciliation, separate reselection, and empirical structured-output
validation; no replacement is selected.
The historical launch did not retry schema-invalid output on the same route;
`max_model_retries = 1` was and remains limited to transient network/status retry. The
operator-selected schema retry is now implemented and explicitly selectable provider-free as
described above, but it was not engaged in that launch and does not rehabilitate its rejected
candidate or evidence. There is no current operator command, run index, future FULL admission,
provider launch, qualification, or release authority.

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
present. That optional human-comparison tier remains `NOT_DEMONSTRATED` and is
objective-out-of-scope for frozen synthetic/public completion. The current objective's
superiority verdict must instead come from precommitted public ground truth,
cross-lineage automated adjudication, and the objective-pinned benchmark authority;
absence of a commissioned human auditor is not a completion blocker.
