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

### Current campaign-admission boundary

The current operator-supplied record is 148,339 bytes / 2,648 lines at SHA-256
`d06ae996c74996110822dcd4cbbc1b754c72666551e630edb2627cc50c243089`, latest
`2026-08-28T07:56Z`. It is nonauthorizing, uncommitted, and not independently authenticated by
Codex. Its newest provider-free entry reports that the one correct candidate tombstone rejects the
revoked DeepSeek/`parasail/fp8` assignment but also blocks every unrevoked alternative because plan
eligibility evaluates the whole pinned route set. The ledger remains 57 entries / `0.68118684` USD
and completed real audits remain zero. `V3-REVOKERECON-001` is queued and unselected.
The tombstone reason is `EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE`; pinned plan
`bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f` still lists that route.
MiniMax/Coreweave, Gemma/DeepInfra, and Tencent/Novita alternatives were all refused by plan-route
eligibility, while the incumbent was correctly refused at assignment. No repository command emits
a successor selection plan, so hand-editing the hash-pinned input is not an approved workaround.

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
registries, bundle, campaign, or ledger. The frozen DeepSeek/`parasail/fp8` candidate is non-runnable
pending revocation/plan reconciliation, separate reselection, and empirical validation; no
replacement is selected. The historical
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
