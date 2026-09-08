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

### Historical AUTONOMY Phase-2 local provisioning boundary

The current work unit closes only a bounded local-provisioning slice;
`V3-AUTONOMY-001` remains `PARTIAL`. The supported `mmaudit managed provision` interface takes
explicit `--repo` and `--output-dir` paths plus optional `--config` and `--verify-only` controls. It
is provider-free and loads configuration from the selected file with ambient configuration
overrides disabled. It hashes the bounded audited-workspace content inventory, subject to the
compiled exclusion domain, under retained local custody, but it does not select
or read an operator secret source and does not make a provider or network request. The repository
and owned mode-`0700` output directory must be absolute and disjoint.

The one implemented provisioning action is exact cost-ledger create-or-verify. The configured
ledger path must be absolute, have an existing private parent, and remain outside both the repository
and receipt directory. A durable private provisioning marker serializes creation and prevents a
deleted ledger and ordinary lock from being treated as a fresh budget. Without `--verify-only`, a
ledger is initialized only when no prior marker, state, or ordinary lock was observed; an existing
ledger is opened only when its immutable cap and identity are exact. `--verify-only` requires the
existing exact marker and ledger pair. The marker is retained on initialization failure, and its
identity is bound into verified receipt evidence. Both paths record a typed point-in-time snapshot,
including entries, active reservations, portfolio holds, and held value. They do not reserve,
charge, reconcile, clear, or otherwise alter an existing ledger.

The command emits a self-contained typed receipt containing the complete plan and reduced state.
The canonical JSON envelope is self-hashed and content-addressed. Repository custody is finalized
and the original digest is reobserved before any final receipt name is linked. The fully written and
synced private temporary file then uses atomic no-replace publication; an existing destination is
accepted only when its canonical bytes and typed envelope are exact. Rollback is identity-checked
under the cooperative publication lease; it is not an unconditional guarantee against a
lock-ignoring same-UID pathname replacement. The repository digest is point-in-time evidence, not a
promise that source remains unchanged after custody finalization. The receipt records
`spend_admission_evaluated=false`, `runtime_authority=false`, `managed_run_ready=false`,
`provider_or_network_accessed=false`, and `operator_secret_sources_accessed=false`. Repository
content hashing is evidence collection, not trust or execution authority.

The following Phase-2 surfaces remain unsupported by this slice:

- CodeQL database and query-suite creation or verification;
- dependency-snapshot materialization, target binding, and transitive-closure verification;
- pinned loopback fork-RPC provisioning, identity, and health verification;
- installed-tool discovery, exact executable pinning, transitive toolchain verification, and image
  side attestation;
- process, isolation, execution-evidence, runtime-admission, and spend-admission authority; and
- any managed audit run, candidate or route selection, benchmark, qualification, seal, promotion,
  or release.

Required unsupported inputs and unresolved managed-toolchain roles reduce to closed typed refusals;
unused optional inputs remain `NOT_REQUIRED`. The mandatory installed-toolchain refusal keeps every
current receipt `REFUSED_INCOMPLETE`, even when the cost ledger is created or verified exactly.

This provider-free capability grants no selection state. The active repository artifact is now the
canonical schema-v1.7 unavailable-candidate plan
`14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3` (raw SHA-256
`4e7fff76ffb126a1cdf044cdfc889d79def96a29076aa11e3b42c7ef0ff9a695`), derived from exact
predecessor `bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f`. It selects no
candidate or candidate route, preserves the exact V1 profile and judge constraints, and explicitly
does not adopt the operator-reported private V2 successor. Codex did not invoke `mmaudit managed
provision` against operator-owned paths. Earlier current-state descriptions are historical at their
stated boundaries.

### Current PLANADOPT provider-free closure

`V3-PLANADOPT-001` is `COMPLETE`, provider-free, and nonauthorizing. The active plan records
`NO_ACTIVE_CANDIDATE_AFTER_REVOCATION` under state
`98941c3253ffe0f1aa88890b1c8b7fafb7d6575ee28ca31cb7724f14e784ceae` and exact matched
revocation-set digest `7c0118f5c170d46e6d2478bf92cbd83d1be6b426bda36dd57a6fc93e2ffd18c5`.
It contains no active revoked constraint. All durable authority flags remain false, the operator
ledger and `completed_real_audits == 0` are unchanged, and no replacement candidate was selected.
The retained exact V1 profile is
`00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82`.
Structural private-plan loading is not lineage authentication; any future repository adoption must
validate the exact predecessor and use a separately authenticated transition from this unavailable
state. Current and next tickets are `UNSELECTED`, PLANADOPT is last complete, PRICECAPCACHE is last
partial, and the combined unfinished count is `41`.

The latest operator-supplied record is 190,177 bytes / 3,377 lines at SHA-256
`215ea0f2f312b9674fb51285f6fdf758b166a0a998e2d2d621ac2da42f9a5f19`, latest
`2026-09-04T03:39Z`, at remote-resolved commit
`810ed7f32a9f39df104a6959e84b71c59966fb44`. It verifies the active schema-v1.7 null-selection
state and observes the deliberate authenticated-ancestry gate. No supported transition exists
today; it is deferred to a future separately selected bounded ticket. The operator should stop
probing this path, and this guide issues no command. The ledger remains 57 entries / `0.68118684`
USD and completed real audits remain zero. This evidence is operator-supplied, nonauthorizing, and
not independently authenticated by Codex.

### Retained PRICECAPCACHE provider-free partial closure

`V3-PRICECAPCACHE-001` is `PARTIAL`, provider-free, and nonauthorizing. V3 remains a
reserved policy identifier, but the trusted `project_provider_price_cap` boundary rejects it
unconditionally before discovery proof, registration, cost preview, reservation, or provider
egress. V1 and V2 behavior remains preserved, including V1/V2 refusal of
`input_cache_write` even when the observed value is zero.

No supported successor derivation or CLI path emits a V3 plan. The default-off V1→V2 successor
remains available and unchanged only from an exact historical V1 predecessor; it is unavailable
from the current schema-v1.7 active plan without a separately authenticated ancestry transition.
V2→V3 derivation fails closed. Preview schema `1.3` and
durable pricing-attempt schema `1.2` have been removed; supported preview versions stop at `1.2`
and supported pricing-attempt versions stop at `1.1`. No V3 preview or attempt can be published,
adopted, or used for transport.

The requested dominance rule cannot provide the ticket's provider-enforced safety property.
OpenRouter's
[prompt-caching documentation](https://openrouter.ai/docs/guides/best-practices/prompt-caching)
describes provider-specific cache-write prices, while its
[provider-routing documentation](https://openrouter.ai/docs/guides/routing/provider-selection)
documents `max_price` ceilings for prompt, completion, request, and image only. It exposes no
request-bound cache-write or total-cost cap. A metadata-time cache-write-to-prompt comparison is
therefore non-atomic: pricing can change between metadata refresh and POST without violating the
transmitted prompt ceiling, and reconciliation observes an overage only after spend.

Independent review also reproduced a second historical schema-`1.2` understatement in which both
prompt and cache-write units were lowered and the artifact resealed. That format is not repaired or
accepted as authority; it is neutralized because V3 preview/attempt publication and transport are
now unreachable.

The active schema-v1.7 plan retains the exact V1 price-cap profile. The operator-reported private V2
plan remains unselected and unadopted, and its prior metadata-only refusal did not exercise V3. No candidate, route, command,
run index, provider/network action, configuration, retry, ledger, completed-audit count,
qualification, runtime, release, or other authority changed. Resume only if a provider supplies a
request-bound cache-write or total-cost cap, or an equivalent enforceable atomic contract.
At the historical pre-PLANADOPT committed boundary, remote-resolved HEAD
`ad013aeeb4ea754ec7f0c751175e4badd5fc95b2` added only queued, unselected, and unstarted
`V3-PLANADOPT-001` over operator-result commit
`c8a46b9b53a77fcdd4241d8fadeecbebc876346d`. That boundary is not current: remote-resolved HEAD
`810ed7f32a9f39df104a6959e84b71c59966fb44` now records the operator's PLANADOPT verification,
while the current worktree completes PLANADOPT locally with no current or next ticket and `41`
unfinished.

### Historical PRICECAPCOMP campaign-admission boundary

At that historical boundary, the then-current operator-supplied record was 187,993 bytes / 3,335 lines at SHA-256
`63bfe90b281a6382b921c63669e817e65220c81b629fc75a7cb35b3f3e429d5b`, latest
`2026-09-03T22:31Z`, at remote-resolved commit
`c8a46b9b53a77fcdd4241d8fadeecbebc876346d`. It reports that the operator emitted private V2 plan
`96cc5301111c7b60cf9b8235870d8051e2ece737c80dc5321662a1f6adfa3aea` and used it for one
metadata-only constrained discovery. The same
`PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE` pair remained, and the ledger stayed at 57
entries / `0.68118684` USD. This evidence is operator-supplied, nonauthorizing, and not independently
authenticated by Codex. It does not adopt the private successor, select its route or candidate, or
replace the active repository V1 plan; no further command follows.

The immediately preceding record is 185,462 bytes / 3,287 lines at SHA-256
`d502c61a2525a2bdcc2e7efd79b115821af60f604e715d7be7ccd51b02983ab1`, latest
`2026-09-03T21:03Z`. Commit `dd141cd580c2a012a6efdef26213d3a727b68041` is remote-resolved;
the record remains nonauthorizing and was not independently authenticated by Codex. Its newest
entry accepted that every then-completed operator retest used the active V1-derived profile and did
not exercise V2, then asked whether a real run could select V2. At the historical 21:11
reconciliation boundary no supported selection surface existed; at 21:18 the same ticket reopened
because typed direct construction did not meet explicit-selection acceptance. That gap was later
resolved.
`V3-PRICECAPCOMP-001` is `COMPLETE`: the supported provider-free command surface is
`models emit-selection-plan-successor --upgrade-price-cap-profile-v2`. The flag is default-off;
omission preserves exact V1/default bytes. It accepts only an exact V1→V2 transition, supports a
same-route successor, and rebuilds the shared profile plus every resulting candidate, PRIMARY, and
REPLAY constraint. This capability does not select or activate a plan: no successor artifact was
selected or inspected, no live command or route retest is requested, and
`input_cache_write='0'` remains independently uncapped and blocks xAI admission.

The prior exact `2da419f85a9f6b2d087c1f75dca4247ef91d8fcf23005c719644de5830238b21`
record (182,652 bytes / 3,240 lines, latest `2026-09-03T20:43Z`, remote-resolved commit
`b9ea875e70d865b50c1eb847e39ed767162c9c6b`) remains historical evidence of the credentialed
metadata-only V1 constrained-discovery retest: the xAI route returned
`PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE`, produced no snapshot, and left the
57-entry / `0.68118684` USD ledger unchanged. Its possible flat-only explanation was an operator
question, not a root-cause claim; local inspection showed discovery is schedule-aware and the
quoted refusal is refresh-only. The earlier `2026-09-03T14:30Z` entry remains the exact correction
that retracts the key-order cause: direct construction bypassed provider-facing ingest, which
already sorts raw tier keys, and a provider-free 120-permutation full-ingest assay yields one
pricing hash and one snapshot hash. `V3-PRICEKEYORDER-001` remains
`WITHDRAWN_OPERATOR_ERROR` and must not be implemented.

That historical local provider-free closure marked `V3-PRICECAPCOMP-001` `COMPLETE` without reissuing
that live discovery. An opt-in V2 route profile may retain nonzero `web_search` pricing only when a
self-hashed immutable envelope proves the exact emitted request has zero reachable search units and
zero search cost. Search/tool/plugin fields are prohibited, the component is omitted from provider
`max_price`, and the same profile/envelope is joined through discovery, tier-wide projection,
registration, preview, refresh/durable evidence, smoke/runtime evidence, and the frozen provider
egress callable graph. The active plan remains byte-identical V1. The recorded xAI route remains
unselected and inadmissible because `input_cache_write='0'` still lacks an enforceable cap,
dominance invariant, or immutable disable control. The default-off successor option validates only
an exact V1 predecessor, rebuilds all role constraints, and rejects repeat V2, downgrade,
drift/tamper, non-boolean input, revocation, and stateful predecessor substitution before publishing
a fresh mode-`0600` output. This local capability authorizes no command, route, qualification,
campaign, audit, or release. The latest operator retest exercised the private V2 successor only for
metadata discovery and reproduced the same two refusal codes. It neither adopts nor selects that
private artifact as the repository's active plan, which remains V1, and it does not convert the
operator's earlier flat-only question into a finding. Provider-free call-graph inspection answers
that question: constrained discovery canonicalizes and retains the tier schedule, while the quoted
flat-only refusal belongs to a separate refresh helper. The shared public failure pair cannot
distinguish V1's two component refusals from V2's remaining cache-write refusal. No further live
route retest is currently requested and no active successor is selected.

At its `2026-09-03T11:27:12Z` boundary, `V3-PRICECAPTIER-001` closed `PARTIAL`, provider-free,
and nonauthorizing. Exact Decimal maxima
across the base and every ordered inherited partial tier are bound to the complete schedule and cap
proof. Later applicable tiers win; cache-read dominance is enforced per effective state; and provider
cap, request-cost, reserve, spend, and reconciliation use the same deliberately conservative maximum.
Flat-route bytes remain unchanged. Unsupported or unavailable schedules fail
`PRICE_CAP_NOT_EXPRESSIBLE` and `PRICE_CAP_PROOF_UNAVAILABLE`, while nested numeric override lexemes
fail closed. The recorded xAI maxima are prompt `0.0000044` and completion `0.0000132`, but
`input_cache_write='0'` and `web_search='0.01'` remain independently uncappable. Refresh and live
preflight were flat-only at that historical boundary, so the primary route/preflight criterion was
unmet and no route was selected.

`V3-MODELREFRESH-001` now closes a provider-free tier-schedule continuation as `PARTIAL`.
Refresh source/snapshot evidence, deterministic drift, durable pricing route and attempt evidence,
endpoint registration, and live preflight retain the exact ordered schedule and join its complete
digest. Provider caps and cost custody use the same conservative maximum; threshold-only changes are
detected even when maxima match; unavailable, mismatched, and tampered schedules fail closed; and
flat-route bytes remain unchanged. This grants no route admission: the independent
`input_cache_write='0'` and `web_search='0.01'` constraints remain, and successful current provider
evidence, the stock live authority quartet, automatic real benchmarking, lineage re-evaluation,
qualification, and promotion are absent. No terminal full-suite credit is claimed.

`V3-PRICEOVERRIDES-001` is `COMPLETE`, provider-free, and nonauthorizing. Bounded ordered tier
entries are recursively validated and retained; exact thresholds and nested canonical decimal
prices, strict `>` threshold inheritance, complete-schedule hashing, endpoint binding, and exact ZDR
schedule equality are enforced. Flat endpoint evidence remains byte-identical. Tiered cost
projection is explicitly `unavailable`; request preview, endpoint registration, identity sealing,
and flat refresh refuse conditional pricing rather than flattening or silently dropping a tier.
The full synthetic five-endpoint `models discover` regression accepts the recorded shape and then
reports `PRICE_CAP_NOT_EXPRESSIBLE` and `PRICE_CAP_PROOF_UNAVAILABLE`. Thus
`input_cache_write='0'` and `web_search='0.01'` remain independent unresolved provider-cap
constraints; the sole-blocker claim and route admission remain unproven. This does not prove a sole
blocker or route admission.

`V3-PRICEFORM-001` is `COMPLETE` as the decision-only ordinary-JSON custody refusal; its closure
changes no code, configuration, retry behavior, route, or authority. `V3-PRICELEXEME-001` is
terminal `PARTIAL` provider-free defense-in-depth: its route-specific numeric-price premise is
superseded and it
is nonblocking for the xAI route. Pure Python cannot
retrospectively detect hostile same-interpreter reflection fully restored before a trusted lookup;
every observed mismatch is permanently revoked, and arbitrary closure reflection is outside the
trusted-interpreter boundary. The focused live-shaped full-`models discover` raw-numeric-price case
passes `1` in `0.76s`; the adjacent price-decoder/endpoint/discovery/OpenRouter/CLI matrix passes
`793` in `17.73s` with two known warnings. Scoped Ruff passes and strict mypy is clean across `233`
source files. Trusted execution evidence remains `MOCK`; exact constrained-route identity,
normalized pricing, multi-ZDR custody, and MOCK-to-REAL refusal are asserted. The interrupted broader
CLI/pipeline attempt remains at `111` passes in `193.54s` and has no pass or full-suite credit. This
guide authorizes or issues no live command.

`V3-TESTQUALITY-001` is `PARTIAL`, provider-free, and nonauthorizing after its shared process-local
revocation-lease race slice. One PID-bound domain serializes run, observation, campaign, and score
authority reads and registrations plus handoff replay. Composite layers revalidate exact local
seals after dependency release; decisive scoring uses seal-SHA-matched immutable schema snapshots,
binds authenticated and canonical plan hashes, and revalidates exact live sources at registration.
Callbacks defer beyond the outer lease, partial and `BaseException` paths exact-remove without
masking the primary exception, and fork paths refuse before inherited locks. The result remains
comparison-only and noncrediting; same-interpreter reflection, asynchronous-exception micro-gaps,
and the post-linearization return boundary remain explicit. It does not authorize an independent or
portable cleanup receipt, a current REAL statement or campaign receipt, portable same-UID disposal,
a sealed backend, a production plan generator, a REAL mutation run/kill artifact, or production
campaign authority. `V3-TESTQUALITY-001` remains independently `PARTIAL`. Candidate requests still require
`effort=high`; ordinary binary-float or
missing-capture price custody remains inadmissible; the conditional
`x-ai/grok-4.6=amazon-bedrock/us-west-2` route remains unselected and not currently proven
admissible. The active plan, retry configuration, 57-entry / `0.68118684` USD ledger,
`completed_real_audits == 0`, and every provider, runner, candidate, route, command, campaign, run
index, selection, qualification, audit, and release authority remain unchanged or false. AF7 remains
historical evidence at its exact `2026-09-01T04:49Z` boundary. The final PRICECAPCOMP selector
validation passes `120` focused tests and `1,328` affected tests with two known warnings;
release-schema, autonomy-inventory, and refresh-schema validation passes `79`; canonical
generation, scoped Ruff, strict mypy over `233` source files, and diff integrity pass. The
regenerated autonomy inventory hashes are raw
`fcecc2351ab9d5fd7a0e6c0289e9daeb7f6ec83cebfd00552948e9b090617c73`, self
`0f575febde00869a20192214a40af87e7196660a8e82b5810e8beefb45caad28`, discovery
`bc80c98c469dc9cce61af880c8849e8387143ad1e3fb7d853d4eca8e9205e340`, universe
`3f41a8b19a0e7547bc619f1405692e19a05e62d9662471f10736d79a2d619389`, and schema raw
`88790b6d1d02fff4f2a39ff0bc0c023d062459e6d19d594a1c93cee03871c6c7`; counts are 3,941 sources,
3,944 occurrences, 3,892 gate sources, 49 non-gating controls, and 337 completion entrypoint
parameters. No terminal full-suite credit is claimed.
At that boundary, `CURRENT_TICKET` was `UNSELECTED`, and no next local ticket was selected;
`V3-PRICECAPCOMP-001` is the last completed ticket, `V3-MODELREFRESH-001` is the last partial
ticket, `V3-PRICELEXEME-001` and `V3-CANDROUTE-001` remain partial, and the combined queues retain
`40` unfinished tickets.
`V3-PRICEKEYORDER-001` is `WITHDRAWN_OPERATOR_ERROR` and must not be implemented. Current and next
tickets were unselected at that boundary. The later operator-reported private V2 successor remains
unadopted and unselected; the active repository plan remains V1.

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
