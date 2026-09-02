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
- Private provider audits require a pre-execution
  `--learning-tenant-scope-id tenant-scope-<64-lowercase-hex>`. Provision an opaque value per
  tenant boundary; do not derive it from a repository/output path, run ID, or source hash. The
  terminal record is private, manifest-bound, tenant-scoped, and explicitly nonauthorizing.
- Candidate qualification requires the exact private `--campaign-journal` and
  `--portfolio` emitted by `models benchmark`, the same dedicated existing
  `--cost-ledger`, and the exact frozen release-pinned policy supplied as
  `--qualification-policy <absolute-path>`. Keep that ledger frozen after campaign
  sealing: `models qualify` and `models verify-qualification` reopen the policy,
  journal, and ledger and reject any binding, report, diagnostic, usage, snapshot,
  reservation, or cost drift.
- Real tests additionally require `MMAUDIT_RUN_REAL_PROVIDER_TESTS=1`, an exact
  model allowlist, and a numeric cost cap. The normal suite never spends money.
- The completed provider-free authenticated-runner runtime-admission path accepts an explicit
  absolute private
  canonical legacy-v1.2 or current-v1.3 smoke bundle through
  `--runtime-evidence-smoke-bundle <absolute-path>`. It can
  affect only the exact three route/profile/discovery bindings proved by that bundle and cannot
  confer qualification, campaign, runtime, audit, selection, or release authority. Token evidence
  and usage routing must join the full request-token-plan hash, while the preview must separately
  join the recomputed stable projection hash.
- Schema retry continuity is selected only by pairing the frozen retry-off
  `--config config/openrouter-qualification.toml` with
  `--retry-continuity-config config/openrouter-authenticated-runner-retry-continuity.toml`.
  The explicit profile enables exactly three same-route schema retries; `max_model_retries = 1`
  remains transient-only, for five maximum attempts per logical request. Durable v1.2 evidence and
  offline verification bind the full effective configuration, execution subtree, and attempt
  capacity. These provider-free controls grant no candidate, campaign, qualification, audit, or
  release authority.
- Ordinary paid `mmaudit run` and provider-free `mmaudit quote create` planning select a bounded
  same-route quota with `--schema-validation-retries N` (`1` through `31`). Omission means no
  same-route schema retry. If configuration already contains a nonzero quota, the exact same CLI
  value is mandatory; a conflicting or implicit activation fails before paid controls or quote
  inputs. `max_model_retries` remains transient-only. Current quote, acceptance, budget, usage, and
  manifest-v1.3 custody bind the exact split-policy hash; legacy manifest/smoke v1.2 replay is
  retry-off and cannot prove the selected schema-retry policy.

### Provider-free actor-model input

An actor model requires no provider access. An operator authors repository-relative JSON from
reviewed governance and economic evidence against `schemas/actor_model.schema.json`; model output
must not invent holders, admitted roles, constraints, or incentives. Start from the non-production
shape in `tests/fixtures/actor_model/synthetic_orchard_actor_model.json`, replacing every synthetic
assertion and evidence reference for the audited subject.

The file's `artifact_sha256` is the SHA-256 of compact, key-sorted UTF-8 JSON for the validated typed
payload excluding that hash field. Configure `[actor_model]` with its path plus matching
`expected_subject_id` and `expected_model_sha256`; add `expected_source_sha256` to pin the exact
source bytes. At run start,
only `valid_from <= run_started_at < valid_until` is current. Future, stale, invalid, or mismatched
evidence never calibrates findings. Set `required = true` when a non-current input must keep the
audit incomplete. Current input makes unresolved actor assessments a required quality gate even
when `required = false`.

### Current campaign-admission boundary

The current operator-supplied record is 162,656 bytes / 2,902 lines at SHA-256
`af7a24e382b4f164c7bec0948816e6e6eb3f40e898b2f0688641c4475b697f1b`, latest
`2026-09-01T04:49Z`. It is committed at remote-resolved
`4c553590fedd4d297442f0a73da703d993f5eec9`, is nonauthorizing, and was not independently
authenticated by Codex. Its newest entry accepts both refusals. Candidate requests genuinely emit
`effort=high` and reserve reasoning tokens, so reasoning-effort support remains required across every
role and all four route purposes. Ordinary JSON numeric price custody remains inadmissible: once a
price has transited a binary float, reserializing it cannot prove identity to the provider's original
decimal lexeme. No constraint was relaxed.

At the AF7 evidence boundary, the operator chose future lossless price-lexeme custody and queued
`V3-PRICELEXEME-001`. The operator reports that `json.loads(..., parse_float=Decimal)` can retain the
source decimal rather than reconstructing it from a float; Codex has not independently verified that
operator-side experiment. A later direct operator directive now selects `V3-PRICELEXEME-001` as the
sole `IN_PROGRESS` ticket after `V3-RETRIEVAL-001` reached `COMPLETE`. This is a selection-only
boundary: `implementation_started=false`, and no decoder, pricing, retry, or configuration change
has been made. Existing sealed evidence must remain byte-identical under any future work. The
conditional
`x-ai/grok-4.6=amazon-bedrock/us-west-2` route is not currently admissible or selected. Under the
current custody model there is no admissible candidate route, the active plan remains unchanged,
and `V3-CANDROUTE-001` remains `PARTIAL`. AF7's queued, unselected, and unimplemented price-lexeme
state remains historical evidence at that exact record boundary; the newer directive changes only
the local ticket selection state. The operator reports zero new spend, the unchanged 57-entry /
`0.68118684` USD ledger, and zero completed real audits. No provider action, operator command,
campaign, run index, qualification, runtime, audit, or release authority follows.

The historical `2026-08-30T19:00Z` credentialed metadata-only schema-v1.0 survey covered 12 models
and 112 endpoints, found zero endpoint-level reasoning-effort inventories, and exposed that the
diagnostic omitted model-level and admission-effective reasoning inventory. Local schema v1.1
corrects that gap and has not been exercised live; no repeat external command is required. The prior
15:18 plan-successor result is retained as historical evidence. The local emitter now has an
explicit schema-v1.6
`--refresh-endpoint-inventory` path that stages one previously unlisted endpoint as
`OPERATOR_STAGED_UNVERIFIED`, binds its predecessor inventory, requires later constrained discovery,
and grants no authority. Omission remains fail-closed. This local mechanism does not select or prove
a current real route, and no external action or command is current. Fresh operator evidence for a
current real route is required before `V3-CANDROUTE-001` can resume. Hand-editing the hash-pinned
input is not an approved workaround.

`V3-ENDPOINTLIST-001` schema v1.0 was exercised by the operator at `2026-08-30T19:00Z`: credentialed
metadata GETs enumerated `112` endpoints across `12` models, found zero endpoint-level
reasoning-effort inventories, issued no completion, and left the `57`-entry / `0.68118684` USD
ledger unchanged. The survey exposed that v1.0 omitted the model-catalog fallback and exact
effective reasoning value used by admission. The corrected v1.1 reference surface
`mmaudit models list-endpoints --model EXACT_ID [--json]` now reports separate model, endpoint, and
admission-effective reasoning inventories plus model/endpoint structured-output facts. Its shared
endpoint-first resolver preserves explicit-empty veto and exposes unavailable or contradictory
metadata. It remains metadata-only, self-hashed, ledger-free, and nonauthorizing. Codex validated
the correction only with local synthetic metadata and did not perform or authenticate the live
survey; the earlier v1.0 output does not validate v1.1. No repeat external command is required.
The survey produced zero admissible candidates, `V3-CANDROUTE-001` stays `PARTIAL`, and the active
plan remains unchanged.

The immediately preceding entry reports r23 discovery, paid smoke index 22 (`0.04395915` USD; bundle
`29702a02f52626deca38ff36401eb3cb7bb4602f07677881760ad26ba40df5d4`,
`VALID / NONCREDITING / NONAUTHORIZING`), and FULL admission for one launch. The 24-case campaign
then failed closed after roughly 24 logical requests and `0.20264508` USD: nine schema-invalid
responses became `SCHEMA_VALIDATION_FAILED`, 15 completed response identities were unbound, and
terminal candidate provenance was rejected. The operator reports all 24 new campaign entries
reconciled; the ledger now contains 57 total entries / `0.68118684` USD, with zero completed real
audits.

`V3-RUNTIMEADMIT-001` remains `COMPLETE` at its local provider-free mechanism boundary, but the
failed launch provides no reusable admission or future authority. Codex did not read the private
registries, bundle, campaign, or ledger. The frozen DeepSeek/`parasail/fp8` candidate is non-runnable;
the operator-reported successor sweep found zero admissible replacements, and its artifact is neither
active nor independently inspected by Codex. `V3-CANDROUTE-001` remains `PARTIAL` after its local
provider-free mechanism slice; no real replacement is selected. The historical
launch did not retry schema-invalid output on the same route; `max_model_retries = 1` was and
remains transient-only. The operator-selected schema retry is now implemented and explicitly
selectable provider-free as described above, but it was not engaged in that launch and does not
rehabilitate its rejected candidate or evidence. There is no current operator command, run index,
future FULL admission, provider launch, qualification, or release authority.

## Model lineage approval

- The discovery registry may record exact candidates and benchmark their individual
  quality while lineage review is pending.
- Before any candidate is production-eligible, the operator must review the frozen
  proposed mapping in `docs/models/model_selection.md` against independent ancestry
  evidence and approve or reject every selected model explicitly.
- The review artifact must identify the reviewer and review time, explain shared
  ancestry and alias/mirror/quantization relationships, bind the exact reviewed model
  IDs and supporting evidence by hash, and be self-hashed.
- Provider, endpoint, author-name, or quantization diversity alone is not lineage
  independence. Pending or rejected rows contribute zero independent lineages and
  keep a certified maximum-assurance ensemble incomplete.

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
