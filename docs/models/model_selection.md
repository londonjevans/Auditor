# Model Selection and Qualification

This document defines how `mmaudit` may move a model from discovery into a
maximum-assurance ensemble. It is a selection policy, not evidence that any model is
qualified.

> **Historical evidence notice:** the twelve-model roster below is a superseded
> 2026-07-27 discovery snapshot. It is retained for provenance only, is not a current
> candidate roster or production selection, and grants no qualification, lineage,
> commercial-use, or source-egress authority. Fresh exact discovery evidence is required
> before any new calibration, lineage decision, qualification, or selection.

The provider and model metadata referenced here is time-bound to **2026-07-27**.
Availability, pricing, capabilities, privacy policy, endpoint identity, and routing
behavior can change. A later qualification or release-certification run must use its
own frozen metadata snapshots.

## Provider-free current-selection bootstrap

`config/models.selection-plan.json` is a canonical, self-hashed, explicitly
`NONAUTHORIZING` schema-v1.7 unavailable-candidate successor. Its plan SHA-256 is
`14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3`; its raw-file SHA-256 is
`4e7fff76ffb126a1cdf044cdfc889d79def96a29076aa11e3b42c7ef0ff9a695`. It derives from predecessor
`bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f`. The exact predecessor
bytes remain at `tests/fixtures/model_selection/revoked-active-plan-v1.4.json` (14,918 bytes; raw
SHA-256 `0da03b75dd608efade4c41e87de38139fb735576049f824365889be9c9a3ff24`) for historical replay.
The successor preserves every source binding and roster entry, but its
`authenticated_runner_selection` is null: no candidate or candidate route is active.

The self-hashed unavailable state
`98941c3253ffe0f1aa88890b1c8b7fafb7d6575ee28ca31cb7724f14e784ceae` records
`NO_ACTIVE_CANDIDATE_AFTER_REVOCATION` and explicitly preserves the predecessor's V1 price-cap
profile rather than adopting the private V2 profile. It binds the domain-separated exact matched
revocation-set digest `7c0118f5c170d46e6d2478bf92cbd83d1be6b426bda36dd57a6fc93e2ffd18c5`, exact revocation entry
`67eb2be8bb4d51d8223c2893736c0adeea60bd73d7671ee22f39cc6f4dee6ec4`, and withdrawn candidate
constraint `126a1553cb4fbc96c642d803edacadd4879f41dbfbd69e53b0e4d19d4674763a`.
Route validation, constrained discovery, registry derivation, and the CLI bridge reject this state
with the named reason before staged-source reads, secrets, provider construction, or output
publication. Ordinary successor emission also refuses an unavailable predecessor: a future
candidate must use the separately scoped repository-pinned ancestry mechanism described below
before carrying judge or profile custody into an explicit currently eligible non-revoked route.
Structural plan loading and `models discover` do not authenticate a private plan's
`predecessor_plan_sha256`; they accept operator-staged, rootless, pending, nonauthorizing discovery
inputs. Any succession or repository-adoption claim requires
`validate_candidate_selection_plan_successor` with the exact predecessor artifact. A self-resealed
private plan therefore cannot claim the unavailable active plan as authenticated ancestry or alter
the active repository configuration.

### Repository-pinned unavailable-plan ancestry

`models emit-selection-plan-reactivation` is the only supported local construction path from the
active unavailable schema-v1.7 plan. It has no caller-supplied predecessor or ancestry path. The
command first reads the compiled exact 14,918-byte archived v1.4 file and 15,163-byte active v1.7
file under no-follow, regular-file custody, requires their raw SHA-256 values `0da03b75…` and
`4e7fff76…`, requires their internal plan SHA-256 values `bb3d60c3…` and `14566de1…`, and replays
the ordinary deterministic v1.4-to-v1.7 unavailable successor validation. A coherently resealed,
reformatted, substituted, linked, reversed, or read-time-drifting pair is rejected.

Successful replay issues only a PID-local opaque capability. It cannot be directly constructed,
subclassed, copied, serialized, or reused after `fork`, and every use re-reads the exact repository
pair before returning a fresh nonauthorizing projection. A capability-consuming derivation accepts
one operator-chosen route already listed in the v1.7 roster and rejects judge collisions, unlisted
endpoints, and current revocations. The resulting schema-v1.8 plan names v1.7—not the historical
v1.4 plan—as its immediate predecessor, retains the exact V1 profile and judge constraints, removes
only the no-active-candidate requirement, and embeds both ancestors, the unavailable state,
revocation set, retained custody, and replacement constraint in a self-hashed transition binding.
Endpoint inventory refresh and V2/V3 profile upgrade are unavailable on this path.

The selected catalogue entry is resealed to exactly the chosen endpoint, preserving its rank and
lineage; all other entries remain unchanged. Both the source model and exported v1.8 JSON schema
require an active assignment and the retained V1 profile. No schema-only V2 replacement is accepted.

Publication is a fresh private mode-`0600` file after immediate ancestry and revocation replay.
The original parent and output descriptors remain held through exact readback, final ancestry
validation, and final root/path/content/permission checks. Handled validation failures remove only
the created inode's own leaf, including after a parent rename; foreign replacements are preserved.
An unknown surviving alias or failed cleanup is an explicit error, not successful publication.
These are bounded in-process drift checks, not a Python/host sandbox or crash-atomic publication.
The serialized plan and projection remain explicitly `NONAUTHORIZING`: they confer no provider,
qualification, production-selection, runner, benchmark, seal, release, or source-egress authority.
No v1.8 artifact is checked in or adopted by this ticket, and the active v1.7 bytes remain unchanged.
A later repository adoption still requires a separately selected work unit and fresh admissible-route
evidence; structural loading alone does not prove ancestry. Ordinary
`models emit-selection-plan-successor` continues to reject v1.7.

`V3-PLANADOPT-001` remains `COMPLETE`, provider-free, and nonauthorizing. The bounded
`V3-PLANANCESTRY-001` implementation adds only the provider-free mechanism above; it does not select
a replacement candidate or mutate active configuration. No provider or operator command,
credential, private ledger, candidate, route, campaign, run index, qualification, runtime, audit,
release, or other authority was used or granted.

The retained judge custody is the complete 29-predicate V1 route profile
`00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82`, including exact
effort-high reasoning, request-parameter, capacity, and price requirements. Z.AI GLM-5.2 remains
the retained PRIMARY judge on `sail-research/fp8`; Kimi K3 remains the retained replay judge on
the two policy endpoints `modal/mxfp4` and `phala`, with no automatic fallback. The DeepSeek route
is retained only as a nonauthorizing roster allowlist entry, not as an active role constraint. The
DeepSeek entry SHA-256 is
`da576e8d1835b41be94ea4dab6cd6329ae8c1483b830214d9e05acef44e8617b`, the GLM entry SHA-256 is
`45f0a3f416a806932e2596ca4f6381e12bbc4901d15c301b22fd5d607a7f55ef`, the Kimi entry SHA-256 is
`77217b6dca94bc292a13cc5a5ce84c48c68a6bb2e055462db51048013abd3f11`, and the
historical predecessor role-assignment SHA-256 is
`7d67d43f98484890bf9f184a5bb89fbba25d0408dee65a7174eef5fdf1a75b14`.
Tencent/`novita` remains an unselected historical adaptive seed at rank 10. Gemma remains an
unselected rank-12 record of the superseded r7 proposal rather than being presented as viable for
the configured high-effort profile. The plan's own advisory entries remain literally
`documentary_lineage = UNCONFIRMED`; those sealed plan-local values are not rewritten by later
documentary evidence. The separately compiled public-lineage manifest confirms the historical
DeepSeek/Z.AI/Moonshot documentary triple and all six directed independence pairs. The DeepSeek
candidate route is tombstoned and cannot be a current assignment. Every discovery, lineage,
qualification, runner, benchmark, seal, release, provider, egress, and selection authority field
remains literally false.

Historically, the operator ran the three singleton metadata-only commands. DeepSeek succeeded on `novita/fp8`
with operator-reported frozen-registry SHA-256
`59dfdaf498cc2a8201351a7c6aacdfc2a3fd7f6daec09aa927202071ee7a0619`. Qwen 3.8 Max failed
closed because its exact model was absent from the ZDR endpoint snapshot, so it cannot serve as
the primary judge under `require_zdr = true`; the operator reports the same ZDR absence for Meta
Muse Spark 1.2. Kimi's `deepinfra/bf16` route was non-operational;
the explicit `together` retry succeeded with operator-reported frozen-registry SHA-256
`14937842d2a544540efa39199b2b0ed4c0f25e1f145f1385f32d43b728edbdea`. No completion was
requested, and at that boundary the operator reported an untouched `$0` ledger. Those statements
record operator-reported historical results only; the private artifacts and ledger were not read or
promoted by Codex. The then-current operator-supplied log for that later r7 boundary was retained at
[`operator_results.md`](../remediation/v3/operator_results.md): 57,374 bytes, 1,029 lines, and raw
SHA-256 `14ece147138fb5bf6f32d2737ca6b174817a923c5ca50269bc14337c60a3453c`. It is
`OPERATOR_SUPPLIED_UNVERIFIED` and grants no repository authority.

The subsequent Claude Opus 5 `amazon-bedrock` PRIMARY r3 attempt also failed closed before registry
publication. Although the tag matched, the endpoint's `provider_name` was duplicated elsewhere in
the exact-model inventory. Selected-name uniqueness is retained: generation metadata
does not always expose an endpoint tag, so accepting a duplicated display identity could import ZDR,
pricing, or capability evidence from an unapproved sibling route. Under the current validator no
reported Claude ZDR route can satisfy this invariant; route substitution alone cannot repair r3.
No completion was requested and the operator reports no ledger spend.

The historical PRIMARY r4 `minimax/minimax-m3=coreweave/fp4` metadata discovery succeeded. The
operator reports frozen registry SHA-256
`eaed67e745d448299e3aa5d58b406de065fae09813b3c6ff1c646403ca8023a1`, discovery manifest
SHA-256 `3921c5682bedf1f938236a5268fcf6d5a9138d1646726df00147705cba0b8969`, no completion, and no
ledger spend. That r4 registry remains historical and must not be overwritten. Later frozen
reasoning evidence showed that MiniMax publishes neither a supported-effort inventory nor a
default-enabled state, so no exact reasoning mode can admit it. It is no longer selected.

The operator ran the exact provider-free r2/r4/r2 preflight twice. Both runs accepted every
registry, discovery bundle, policy, corpus, provenance, ledger, and output-path input, then failed
closed only at `runner public lineage does not prove three distinct roots`; neither selected a
secret, contacted a model provider, mutated the ledger, or published an output. The two staged
publisher cards were therefore not promoted from raw bytes alone.

The operator subsequently ran the following public-document capture with exit `0`. It read no
secret, made no model completion, and reported `$0` spend. The adopted canonical journal has raw
SHA-256 `db08339e6d2790faef033f5695e9217a16ddf340e3787eb51863565869034712`, observation-set
SHA-256 `848b1dfda5b60c6793089ed3916073d86e3a734da9dbc5a824302bec7f4b37da`, and capture-bundle
SHA-256 `d9e46cb7c29792ab3d9b2d696bdb889a20f79338d72d628d267bb3705576f8f5`.
All 13 historical files reproduced byte-for-byte, both additions matched their separately staged
hashes, and all 15 retrievals completed within one three-second window.

```shell
.venv/bin/python scripts/capture_public_model_lineage.py --output-dir /private/tmp/mmaudit-public-lineage-20260821-r1
```

The resealed `53,960`-byte canonical manifest has raw SHA-256
`6f46b3c779262cf11b0ec58b1a2fe88947cd71d7ab788734abb36cd9f96374e4` and semantic bundle
SHA-256 `de2192a2eaede4a54e1b24216d5c3c51cebd63086131c20367e166dfa672a388`. It binds 15 source
files totaling `411,429` bytes, 14 exact aliases, 16 exact nonoverlapping claims, 10 confirmed
identities across nine roots, four unchanged `UNCONFIRMED` identities, and six conservative
non-independence constraints. The two new constraints prevent DeepSeek V3/V4/Cogito and Kimi
K2/K3 variants from being credited as independent roots. The then-selected historical DeepSeek V4,
MiniMax M3, and Kimi K3 triple replays pairwise independent. Verification is anchored at
`2026-08-21T05:26:00Z` and expires at `2027-02-17T05:26:00Z`.

If the cumulative ledger does not already exist, initialize it exactly once. Never replace an
existing ledger; its historical prefix is part of later AUTHRUNNER custody.

```shell
MMAUDIT_BUDGET_USD=250 .venv/bin/mmaudit models init-cost-ledger --config config/openrouter-qualification.toml --cost-ledger "$HOME/.mmaudit/private/openrouter-cost-ledger.json" --no-color
```

The prior provider-free r2/r4/r2 preflight against the resealed manifest is historical. The
operator reported `VALID / NONAUTHORIZING / NO PROVIDER EGRESS`, two runs, 24 cases, 96 logical
requests, at most 192 provider attempts, 96 generation refetches, effective-config SHA-256
`f0ff2d76017dfcd075c6758f0da7256c98dd45ca749a42b81ca1ce8c95a93f9e`, and an unchanged `$0`
campaign ledger. That run used three placeholder `$1.00` per-attempt tripwires and therefore
reported a nonauthoritative `$192.00` interval/final ceiling; it did not exercise the current
exact-cost admission implementation.

The first exact-cost implementation is checkpointed at
`f6acf206f2c55eeb57b1a11fcf58cc4694a41208`, but its committed-byte preflight failed safely on
the three routes' advertised `input_cache_read` pricing before secret selection, provider egress,
or ledger mutation. That checkpoint is historical and must not be rerun. The follow-up keeps
`input_cache_write` and `internal_reasoning` fail-closed, admits cache-read pricing only when each
exact endpoint's retained cache-read rate is no greater than its prompt rate, and prices both the
full prompt and full cache-read unit ceilings at the upward-rounded transmitted
`provider.max_price.prompt` cap. This deliberately conservative double reservation covers additive
accounting as well as OpenRouter's documented
[discounted prompt-cache accounting](https://openrouter.ai/docs/guides/best-practices/prompt-caching);
the provider's documented
[maximum-price filter](https://openrouter.ai/docs/guides/routing/provider-selection) remains the
external request-price contract. New or changed pricing components still fail before runtime
authority, reservation, or POST.

The follow-up is checkpointed at
`fd1459b519ea0ce28a2d123ddeb57653dd2f7918` (`Bound OpenRouter prompt-cache pricing`) and is
verified on `origin/agent/v3-wip-checkpoint`. The operator then ran its committed-byte provider-free
preflight: the cache-pricing gate cleared, but candidate cost-plan derivation failed later because
the configured `max_tokens = 4096` reasoning control lacked exact frozen support. The rejection
occurred before secret selection, provider egress, reservation, ledger mutation, or durable output;
the operator again reported `$0` campaign spend.

The same-ticket reasoning correction selects `effort = "high"` while retaining a 4,096-token atomic
reasoning reserve. Compatibility uses an endpoint's exact supported-effort inventory whenever it is
present and falls back to the exact frozen model-catalog inventory only when the endpoint inventory
is absent; discovery continues to reject endpoint/model contradictions. This repairs the field-source
asymmetry without inferring support from a model name or default behavior. DeepSeek V4 and Kimi K3
advertise `high` in their frozen catalog inventories. MiniMax M3 advertises no usable reasoning
metadata, so changing the validation rule cannot admit it.

Tencent Hy3 was chosen as the replacement planning seed because the operator-reported shortlist
records `high` support and identifies `tencent/fp8` as the distinct-provider route satisfying the
existing ZDR, operational-status, and display-name constraints. The reasoning and capture-preparation
checkpoint `9075ca7635c861194cc732e67d9ebb92e6ffa0af` was pushed and remote-verified before the
operator ran both prerequisites below verbatim. They are now historical command records and must not
be rerun or used as authority.

The public-document capture exited `0`, requested no model completion, and produced one coherent
16-source bundle containing Tencent Hy3:

```shell
.venv/bin/python scripts/capture_public_model_lineage.py --output-dir /private/tmp/mmaudit-public-lineage-20260821-r2
```

The operator reports observation-set SHA-256
`6ae6e75a1732c05b85ffe189febbc3ecfa8ae2eeeb83000a8a24d30035b966eb` and capture-bundle
SHA-256 `7b6ff67506bceaaf05c944edb2c28bf6d8386df3690444b827035ed5c83bc134`.
The exact Tencent card is 10,325 bytes at immutable revision
`a960ebc3da325ba167f069f76c41eb62c9280d22` with SHA-256
`dbdfc5920bf548fb484b5ec1837032f6c85e1886f2930aa5bee629c1f9620e8b`, byte-identical to the
earlier independent pre-fetch.

The exact Tencent r5 metadata-only discovery also exited `0`; it made no model completion and did not
mutate the `$0` campaign ledger:

```shell
MMAUDIT_SECRETS_ENV_FILE="$HOME/.mmaudit/secrets.env" MMAUDIT_BUDGET_USD=250 MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" .venv/bin/mmaudit models discover --candidate tencent/hy3=tencent/fp8 --config config/openrouter-qualification.toml --secrets-env-file "$HOME/.mmaudit/secrets.env" --output-dir "$HOME/.mmaudit/private/model-discovery/authrunner-primary-judge-20260821-r5" --candidate-selection-plan config/models.selection-plan.json --candidate-selection-ranking-source /Users/generalcuster/Documents/dev/CODEX_HANDOFF_v3-unblock-2026-08-17/model-ranking.py --candidate-selection-lineage-review-source /Users/generalcuster/Documents/dev/CODEX_HANDOFF_v3-unblock-2026-08-17/V3-LINEAGE-001-operator-review.md --candidate-registry-output "$HOME/.mmaudit/private/authrunner/primary-judge-registry-r5.json" --no-color
```

The r5 discovery run ID is `85ff0c1b872241e7aa48b2f2f77ccc84`; its manifest SHA-256 is
`fe3e3daa21eeb370f35558c5eca5746c140f2b92e88a37233952ab77034dc07b`, and its frozen
registry SHA-256 is `2d825234bfc1cf05fb9ec883c555bc007bd3a6033145507d629d5da7aa5619ad`.
Its exact catalog inventory supports `none`, `low`, and `high`; `effort = "high"` therefore validates
through the frozen catalog fallback while the endpoint-level effort inventory remains absent. The
candidate and replay r2 pairs were not rerun or overwritten.

The capture was adopted only after exact-byte reconciliation, claim extraction, and independent
replay. The then-current 57,621-byte canonical manifest had raw SHA-256
`90389d27f553d6f167a21aab364cebdb40ca5afbdbcc977d9127338ace4a3008` and semantic bundle
SHA-256 `7c6dd26743733ae46aa94b7171ff2ca42f967ac8323b7f2d0aa95cf66f2dbc68`. It binds 16 sources
totaling 421,754 bytes, 15 aliases, 17 exact nonoverlapping claims, 11 confirmed identities across
10 roots, four unchanged `UNCONFIRMED` identities, and seven conservative negative-only constraints.
Tencent Hy3 is `CONFIRMED` at root
`sha256:932e8cdba524bbf5280d368b0cb711bf0bf36b6fb57ea744bda2a86caea534fb`; the added
Tencent/Hy3-Hunyuan organizational constraint grants no positive root assignment. All six ordered
pair directions among the active DeepSeek V4, Tencent Hy3, and Kimi K3 triple replay as independent.
Verification is anchored at `2026-08-21T11:47:00Z` and expires at `2027-02-17T11:47:00Z`.
This is documentary identity/root authority only; it does not qualify a model or authorize a provider
call, runner, seal, benchmark, audit, or release.

The historical r6/r6/r2 input composition and its then-planned smoke boundary are retained below
for custody only. They are not a current plan, command, or reusable output target:

| Role/artifact | Exact path |
| --- | --- |
| Candidate registry | `$HOME/.mmaudit/private/authrunner/candidate-registry-r6.json` |
| Candidate discovery | `$HOME/.mmaudit/private/model-discovery/authrunner-candidate-20260821-r6` |
| PRIMARY registry | `$HOME/.mmaudit/private/authrunner/primary-judge-registry-r6.json` |
| PRIMARY discovery | `$HOME/.mmaudit/private/model-discovery/authrunner-primary-judge-20260821-r6` |
| REPLAY registry | `$HOME/.mmaudit/private/authrunner/replay-judge-registry-r2.json` |
| REPLAY discovery | `$HOME/.mmaudit/private/model-discovery/authrunner-replay-judge-20260820-r2` |
| Parent 24-case corpus | `benchmarks/model_corpus/manifest.json` |
| One-case smoke bundle | `benchmarks/model_corpus_smoke/` |
| Retained cost ledger | `$HOME/.mmaudit/private/openrouter-cost-ledger.json` |
| Historical smoke output (do not reuse) | `$HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260821-s1.json` |

The exact provider-free r2/r5/r2 preflight emitted from checkpoint
`a1ace778afcf308b57fe436271cdc16a2bb8e156` has now completed and is historical; do not rerun it.
The operator reports `VALID / NONAUTHORIZING / NO PROVIDER EGRESS`, an unchanged `$0` ledger, and the
expected inventory of 96 logical requests, at most 192 provider attempts, and 96 generation
refetches. The two exact candidate-plan SHA-256s are
`f0f367605dd75674b08c8974bf69570190e4137be46a47619c1b5b9d85c83b57` and
`3fc6e535d22baf9bbbdafe4ccb50f9127fdb6d5c2fba7ce0463388765d2f8436`; both the derived
candidate interval cap and derived final-spend cap are exactly USD `5.27438208`. The effective
configuration SHA-256 is `42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`.

Judge admission correctly remains `PENDING_REAL_CANDIDATE_OUTPUTS`, and the full campaign cost bound
remains unavailable until genuine candidate outputs exist. The `$192.00` figure is pre-callback
attempt-count arithmetic plus per-attempt tripwires; it is not a standalone live cumulative meter or
an end-only spend check.

Before the full launch, the repository freezes one exact case from the parent corpus as a separate
four-file smoke bundle. The chosen case is `case-df79ea132113b863`
(`synthetic/C0015.sol`): it exercises request construction, strict structured output, prompt-injection
resistance, exact source-location evidence, candidate generation metadata, and cross-lineage judge
adjudication while minimizing paid exposure. A second case would double this transport smoke without
making it representative or exercising another runtime stage, so the sealed subset contains one.
`manifest.json`, `ground_truth.json`,
`provenance.json`, and `verdict_policy.json` have file SHA-256 values
`aa453f655a4d09adf19498387c9cd2b48939119f1494e9517182dbb2b3ee685c`,
`e5e2baef1b986c77ae448fad1eb96052f061a8db1daae1b6f4122f61cbce8765`,
`d3f9e13733949f660ae4f3eeac8c3576a8b8b620e37adb4f1fc268e45163d46c`, and
`79b1aee6b28fc90f64887fff189b9f404114bd7671a7363bdb437e19d258d68f` respectively. The policy's
semantic bundle SHA-256 is
`721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497`.

Every artifact says `purpose = "NONCREDITING_SMOKE"`, every authority/credit flag is literal false,
and the policy says `representative_for_calibration = false`, `semantic_scores_creditable = false`,
and `smoke_success_authorizes_full_launch = false`. The bundle is an exact one-case projection, not a
replacement or mutation of the frozen 24-case corpus. It therefore leaves `V3-CALIBRATE-001`'s
representativeness requirement untouched and can never count as qualification, calibration,
benchmark, audit, AUTHSEAL, production-selection, or release evidence. Its fixed inventory is two
candidate requests plus two judge requests, four logical requests, at most eight provider attempts,
and four generation refetches. The operator's rough USD `0.22` candidate estimate is useful for
scale comparison only; the runtime derives exact candidate plans from frozen pricing and derives
judge plans only after genuine candidate outputs exist.

The exact runtime answers for both the smoke and full paths are:

- **A stopped run is not resumable.** Neither CLI has a resume flag. The full AUTHRUNNER requires all
  five mutable output leaves to be fresh and always creates new candidate campaigns; the smoke path
  likewise requires a fresh final output and does not expose an adoptable candidate journal or
  portfolio. Deterministic logical request IDs collide with retained ledger entries, and process-local
  live custody cannot be recreated from serialized evidence. Full-run candidate journals and
  portfolios, any partial smoke ledger entries, and all recorded spend remain durable accounting,
  but neither one-shot runner can adopt that work and spend cannot be refunded. After any cap,
  tripwire, interruption, or other partial failure, do not rerun the same command or reuse/overwrite
  its mutable paths. Changing only the smoke output path does not repair its deterministic ledger-ID
  collision. A later attempt requires either an explicitly implemented and validated resume mechanism
  or separately authorized fresh campaign identities and paths; the latter repeats paid candidate
  work.
- **Judge admission happens after both candidates and before either judge POST.** Both candidate runs
  must finish, then both judge routes are refreshed and two exact retry-inclusive plans are derived
  from the REAL candidate outputs: one request per judge in smoke and 24 per judge in the full run.
  Actual candidate spend plus the aggregate maximum of both judge plans must remain strictly below
  the USD `250.00` ledger cap before the first judge POST.
  Every judge request preview and attempt must also fit its USD `1.00` role tripwire. Immediately
  before transport, dispatch recomputes the exact body, route, pricing, and active per-request ceiling;
  the atomic ledger checks remaining cumulative capacity and reserves before every attempt, with at
  most two attempts per logical request. An unknown actual charge is finalized at the reserved amount,
  and any actual-cost overrun is durably recorded and blocks further calls. There is no separate live
  USD `8.00` smoke or USD `192.00` full cumulative meter: each figure is attempt-count arithmetic over
  the USD `1.00` role ceilings. Judge enforcement is not deferred to an end-only interval check
  because aggregate stage admission happens before the first judge POST and every attempt must reserve
  against the retained ledger. Exact interval and final spend are checked again when the interval
  closes.
  Kimi's total judge plan is unavailable before candidate outputs, but it becomes exactly bounded
  before dispatch; it is never uncapped at the POST boundary.
- **The selected endpoint's `provider_name` must be unique in the exact-model inventory.** Current
  generation/response evidence may expose only `provider_name`, and runtime identity handling accepts
  tag, slug, or name forms. If the selected name is duplicated, an unconfigured sibling route could
  otherwise be mistaken for the approved route. Duplicate names among unrelated, unselected
  endpoints do not make the selected identity ambiguous and therefore do not reject it. Checkpoint
  `425502c5cbc173578053423d946ef24843f26285` restores this exact snapshot/runtime parity while
  preserving complete-inventory custody and case-insensitive selected-name rejection.

### Post-origin fixes, failed one-case REAL attempt, and token-budget parity repair

The initial smoke implementation is durably checkpointed at
`af70559ddaf84178efffee1ec1bf7b99bf0b12df` (`Add noncrediting provider smoke path`). Its first
operator-run preflight failed safely with `smoke public lineage returned a non-independent
projection`, selected no secret, made no provider request, and spent `$0`. Real discovery registries
intentionally leave documentary lineage unset; the smoke adapter had compared those
`root_lineage = None` values unconditionally with the genuine sealed roots.

The narrow correction mirrors the full runner only for a `PENDING` review with a null registry root.
It still requires exact model IDs, resolver-projected sealed roots, the exact projection type and
bundle pins, `independent = true`, three distinct roots, and rejection of a non-null mismatch or any
`REJECTED` review. The fix passed 33 focused and 81 bounded smoke/neighbor tests, Ruff and format,
strict mypy, and diff integrity. It is committed, pushed, and remote-resolved at
`7e9db03145b4afc1834dd47e9f4f97800e1edffb` (`Fix smoke null lineage projection`).

The provider-free preflight command was frozen in guide checkpoint
`f0a0f39ee275bc774709bd0fbff411cfa7ecac04` (`Document provider-free smoke preflight`) over
implementation checkpoint `7e9db03145b4afc1834dd47e9f4f97800e1edffb`. The operator ran it
verbatim. It is now historical and must not be rerun. The then-current 33,621-byte operator record at raw
SHA-256 `33d06db3bde140204843282dda56c91704d58a054f02532ea68cfa830f618e62`
reports `VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS`, an unchanged `$0` ledger, two
runs, one case, four logical requests, at most eight attempts, and four generation refetches. Its
operator interval/final tripwires are USD `8.00`; its exact candidate plans are
`944343e272b05b9925a0d4c618946ffbd4742f861e792c83be423531af07ea19` and
`b281a184b96ee208284f57de5c17adf59a9a61a72788bfb1fb5b9ac80e25dd3d`, with exact derived
candidate interval and final-spend caps of USD `0.21890352`. Judge admission remains
`PENDING_REAL_CANDIDATE_OUTPUTS`, and the full smoke bound remains
`UNAVAILABLE_BEFORE_REAL_CANDIDATE_OUTPUTS`. The effective configuration SHA-256 is unchanged at
`42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`.
That identical configuration does not make the top-level runners identical: smoke uses a dedicated
orchestrator while exercising the shared request, transport, generation-refetch, adjudication, cost,
and evidence internals on the one-case projection.

Checkpoint `f5afb2bff074254ee5c4a484386ee4c416b17a88` (`Emit noncrediting smoke launch`) remains
historical and unsafe to execute. A deeper local paid-path audit found that the then-current
AUTHRUNNER owned-REAL usage-origin issuer accepted only `RELEASE_PINNED_MODEL_BENCHMARK` or
`RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION`, while the smoke path deliberately routes
`PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK` and
`PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION`. The mismatch was reached after a provider
response had been charged and bound, when origin attestation raised `REAL bound usage lacks
AUTHRUNNER transport-origin custody`. The first paid candidate completion could therefore have spent
money and then failed before smoke evidence completed. Provider-free preflight cannot exercise that
post-response issuer boundary.

At safety checkpoint `ca63b924f244cc9bcee2d2405d20b000ce0bb9d6`, the unsafe launch was withdrawn before
execution. The then-current 35,771-byte operator record at raw SHA-256
`612943ec6e7f138d7a85ce7f4439a5054127b385f008fb1d1af25134890ebfb9` operator-reports that no
paid smoke attempt, provider completion, or spend occurred and that the dedicated ledger remained
`$0`; the source mismatch was independently source-reviewed.

The narrow origin-custody correction is committed, pushed, and remote-resolved at
`c9a8923064ef1bb606a67b14641c4c8df55bc9ea` (`Bind smoke REAL origin custody`). It binds each of
the four closed proof kinds to its disjoint request namespace before owned-REAL origin is minted:
release candidate and cross-lineage requests retain only their two `RELEASE_PINNED_*` kinds, while
the smoke candidate and judge namespaces admit only their corresponding
`PINNED_NONCREDITING_SMOKE_*` kinds. Missing, malformed, cross-kind, release-to-smoke,
smoke-to-release, and forged namespace mappings reject. The sealed origin registry retains and
rechecks that scope; admitting a smoke proof kind grants no release, qualification, calibration,
benchmark, audit, AUTHSEAL, or production authority.

Implementer validation passed 584 provider-free tests across usage, OpenRouter, generation evidence,
authenticated runner/smoke, cross-lineage adjudication, privacy provenance, and candidate benchmark
surfaces. Independent validation passed 371 usage/OpenRouter tests, 83 runner/smoke/cross-lineage
tests, and 123 generation/candidate tests (577 broad tests total); final focused checks passed 22
usage-scope and three OpenRouter transport-path tests, and the red-team verdict was clean with no
blocker/HIGH. Scoped and repository-wide Ruff passed; Ruff format
reported the four changed source/test files already formatted; strict mypy passed both changed source
files and the full 206-source tree; and diff integrity passed. The whole-repository format check is
intentionally not credited because it would rewrite a Python code fence inside the exact
operator-owned result bytes; those bytes remain untouched. No terminal full-suite result is claimed,
and no provider call, secret selection, ledger mutation, authority, or governed counter changed.

The implementation checkpoint and the operator-visible guide checkpoint are intentionally distinct.
Checkpoint `c9a8923064ef1bb606a67b14641c4c8df55bc9ea` is the pushed source correction. Guide checkpoint
`c137f8bae9d27f5120e7e08eba2d9b5b384e1ca5` (`Emit fixed smoke preflight`) froze the exact
provider-free command over that implementation. The operator ran the guide command verbatim at
`2026-08-21T15:36:00Z`. The then-current 38,352-byte, 690-line operator record at raw SHA-256
`ed416745d3d0d957e05919e7cf10e14e75b4e9f3da800000e5789371520abbe2` records
`VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS`, `$0` spend, two runs, one case, four
logical requests, at most eight attempts, four generation refetches, USD `8.00` operator interval and
final tripwires, exact candidate final cap USD `0.21890352`, judge admission
`PENDING_REAL_CANDIDATE_OUTPUTS`, and effective-config SHA-256
`42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`. The operator also reports
that this result is identical to the pre-fix provider-free result. This closes the committed-byte
provider-free gate but cannot exercise the post-response origin issuer; only a paid call can settle
that runtime seam. A terminal suite started before the live operator evidence and reconciliation
bytes changed; it was interrupted after 82 passed, 13 prerequisite skips, and 1381.01 seconds and
receives no pass credit.

Paid-smoke guide/evidence checkpoint `7b2db061ceb7449674399d6133428b97b74b4b96`
(`Emit fixed noncrediting smoke launch`) is now historical and unsafe to rerun unchanged. At
`2026-08-21T16:30:00Z` the operator executed its exact one-case command; construction failed closed
with `request and atomic global input token budgets differ` before a provider request. The dedicated
ledger remained empty at `$0`, and no bundle was published. This is useful fail-closed evidence, not
a REAL completion.

At that historical boundary both the paid smoke and its conditional offline verifier were withdrawn.
The verifier precondition could not hold because no bundle existed. The bounded correction is
committed, pushed, and
remote-resolved at `59f9f40a97dce41a16fb3ab9243b4d8588bcf3cb` (`Bind AUTHRUNNER token
budgets`). Smoke and full-runner construction now initialize the shared budget manager from the
exact configured global input and output token budgets plus the configured model and role cost
budgets. Both preflights compare those values, the total USD budget, maximum output tokens,
conservative rate, request cap, and endpoint-cost requirement before secret selection, client
construction, or transport. Any mismatch fails provider-free at that boundary.

Owner and root validation each passed the same 136-test five-file AUTHRUNNER matrix. Independent
validation passed 122 tests and reported `CLEAN` with no blocker/HIGH; seven focused CLI-ordering
tests also passed. Ruff, tracked-Python format over 510 files, strict mypy over 206 source files,
schema verification, 12 product-documentation/objective tests, strict governance JSON parsing, and
diff integrity passed. No provider, secret, private ledger, completion, spend, authority, or governed
counter was accessed or changed.

At `2026-08-21T16:56:00Z`, the operator ran the exact fresh provider-free one-case smoke preflight
against source checkpoint `59f9f40a97dce41a16fb3ab9243b4d8588bcf3cb`. It reported
`VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS`, two runs, one case, four logical
requests, at most eight attempts, exact candidate final cap USD `0.21890352`, unchanged effective
config SHA-256 `42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`, and `$0`
spend. No bundle was published.

The output is byte-identical to the earlier provider-free preflight and still does not construct the
live `OpenRouterClient`. Independent paid-readiness review then concluded `SAFE`, with no
blocker/HIGH, and one paid command plus its conditional verifier were emitted.

At `2026-08-21T17:15:00Z`, the operator executed that exact paid command. The token-budget mismatch
was gone, and the run progressed to authenticated live metadata refresh before failing closed with
`smoke current discovery differs from its frozen exact route`. No model completion occurred, the
dedicated ledger remained empty at `$0`, and no bundle was published, so the verifier did not run.
That attempt's normalization-versus-drift cause was initially `INCONCLUSIVE`: the operator's similar
absent-versus-default field scan was naive, advisory, and nonauthorizing analysis.

Source checkpoint `5e94b779f2592a2a0a46e7535de3e346310285e2` (`Add AUTHRUNNER live-route
preflight`) is pushed and remote-resolved. At `2026-08-21T17:55:00Z`, the operator ran its bounded
metadata-only live-route preflight against the unchanged r2/r5/r2 evidence. It reproduced the
candidate rejection at `$0` with the precise category `endpoint exact-model identity inventory`.
The frozen `deepseek/deepseek-v4-pro-0813` inventory had 12 endpoints; the live inventory had 13,
adding `sail-research/fp4`, while selected route `novita/fp8` remained present and unchanged. This
refutes the normalization hypothesis and establishes genuine candidate provider drift. The exact
whole-inventory gate behaved correctly: the frozen candidate evidence had aged.

The live-route preflight made authenticated metadata GETs but issued no model completion, spent `$0`,
and published no bundle. It stopped at the candidate mismatch, so the PRIMARY and REPLAY judge routes
remain untested. The then-current 47,422-byte, 855-line operator record had raw SHA-256
`074c9f16a580473ac930f48715e737b6951ddc34cde7cd951e0b24373a3fcc16`.
Checkpoint `5e94b77` classifies only the first failing role. Its bounded successor is committed,
pushed, and remote-resolved at `9f5c94d97b3d79d51c10e250b99244591461e959` (`Aggregate
AUTHRUNNER route drift diagnostics`). Owner and root validation each passed 164 tests; independent
validation passed 237 plus seven focused tests and reported `CLEAN` with no blocker/HIGH. Repository
Ruff, format, strict mypy, schema verification, and diff integrity passed.

The operator ran the aggregate r2/r5/r2 probe. It reported typed whole-inventory drift for candidate
and PRIMARY judge, while REPLAY was unaffected. The operator then independently re-froze only the two
drifted roles: candidate discovery `authrunner-candidate-20260821-r6` with
`candidate-registry-r6.json` and frozen SHA-256
`6cd3463347e794e92831d69629a820fbdc4a6cb226ee4f2ef7daff03603117e1`; PRIMARY discovery
`authrunner-primary-judge-20260821-r6` with `primary-judge-registry-r6.json` and frozen SHA-256
`7b2f11aed42a7d1c5c79b68339682eb21c7f57c765db0ea0d83004a717d8fa8c`. REPLAY retains its
validated r2 pair.

The subsequent r6/r6/r2 live-route preflight was `VALID / NONCREDITING / NONAUTHORIZING / METADATA
EGRESS ONLY / NO MODEL COMPLETION`. All three exact routes completed 15 authenticated logical GETs
within a maximum of 30 attempts. It produced zero usage records; budget and the atomic ledger were
unchanged; output was not published; effective-config SHA-256 remained
`42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`; operator-reported spend was
`$0`. This validates the then-current r6/r6/r2 pre-transport metadata path at that historical
boundary, not any completion request or response. The PRIMARY evidence drifted in under seven
hours, so the observed discovery-freshness window is operationally measured in hours.

The then-current 50,211-byte, 906-line operator record had raw SHA-256
`e7e631be16b5502f6e16b1d2aeae9ac226d8d79050263f27555f5ff8f812b0fd`. The stale r2/r5/r2
command is withdrawn. At that historical boundary, source implementation was bound to pushed,
remote-resolved checkpoint `9f5c94d97b3d79d51c10e250b99244591461e959` and its zero-command evidence reconciliation was
checkpointed at `3bcac02da30bdad2c7e584d35c091ea5cb75ea7d`; the cascade and current governance base below
supersede those identities.

Provider-free review found a blocking lifecycle gap: the exact top-level runner revoker removed only
the runner lease while retained candidate-campaign and candidate/judge generation-verification
capabilities remained independently registered. Pushed checkpoint
`692eb173f002818b4434b746c8801b4cbeb852e2` closes that local gap with exact PID-bound campaign and
generation revokers, parent-to-child cascade, traceback-safe execution handoff guards, and immediate
candidate and judge generation-capability revocation in the smoke adapter. Negative downstream
consumer tests cover ordinary, retargeted, failed-handoff, and concurrent cleanup boundaries.
Root validation passed 229 focused and 266 adjacent tests. Repository Ruff, format over 510 tracked
Python files, strict mypy over 206 source files, schema verification, and diff integrity passed;
independent review reported `CLEAN` with no blocker/HIGH.
The provider-free `REVOCATION_CASCADE_FIX` is complete and clean at this local slice. It creates no
genuine owned-REAL parent capability and does not validate the positive external lifecycle.

The operator subsequently authorized the paid one-case smoke at repository checkpoint
`b4134c70641e33cbbff2b430b135910df903733b`.
Its first candidate completion reached the real transport and proved the production smoke namespace
and reserve/reconcile path: `$0.0547272` was reserved and `$0.01680888` was charged and reconciled.
The response then failed closed as `SCHEMA_VALIDATION_FAILED`; no bundle was published. The retained
candidate DeepSeek/`novita/fp8` and PRIMARY Tencent/`tencent/fp8` routes advertise
`response_format` without `structured_outputs`, so they could produce JSON-object output but not the
native strict JSON-Schema protocol required by AUTHRUNNER. Replay Kimi/`together` advertises the
required marker. That paid-attempt record was 54,081 bytes / 979 lines / SHA-256
`f0c87e608633dc8ae940a977c8207d9e371b2bf683d0a91f415316273d5ac0dc`.

After local gate checkpoint `68d774b2cee5fa69476b1cfea2f8172731a365c8`, the operator ran two
metadata-only r7 discoveries. DeepSeek/`fireworks` succeeded without a completion or new charge;
Tencent/`novita` was rejected by the new native-output gate before registry publication. The
operator reports that Tencent has no ZDR route carrying both `response_format` and
`structured_outputs`, so the initial route-only repair is not viable. The then-current operator record was
57,374 bytes / 1,029 lines / SHA-256
`14ece147138fb5bf6f32d2737ca6b174817a923c5ca50269bc14337c60a3453c`.
It reports `$0` additional spend and the same one-entry live ledger at `$0.01680888`.

The operator then froze Gemma/`deepinfra/fp8` and refreshed Kimi/`together` as r7, still at `$0`.
The r7/r7/r7 live-route gate rejected Gemma before paid transport because the configured profile
requires `effort = high` and Gemma publishes no supported effort inventory. Nemotron's reported
inventory also lacks `high`; neither already-confirmed alternative is eligible. The then-current
operator record at that boundary was 61,243 bytes / 1,092 lines / SHA-256
`00de61717cb6d61c003682abca12ae2c7e59613db03ef99558133b972c123516`.

At that historical boundary every previously emitted AUTHRUNNER command was withdrawn and there was
no runnable metadata, discovery, smoke, verifier, normal-preflight, construct-only, or full command.
Local code-only checkpoint `68d774b2cee5fa69476b1cfea2f8172731a365c8` now enforces native
`NATIVE_JSON_SCHEMA` plus literal `structured_outputs` in the self-hashed selection plan, fresh
registry derivation, and smoke/full provider-free admission. It also requires native mode during
AUTHRUNNER live refresh and preserves adaptive non-AUTHRUNNER selection. Historical local successor
`3989e7592de6e1c355365443c10e00c2083829d8` captured the Gemma proposal but is now retained only as
a failed-safe diagnostic; it is not a viable route plan.

Historical provider-free checkpoint `f6cc07aa5228c13a6c5c740ef0d57b550f25ec37` bumped the plan
schema to v1.2, self-hashed exact
`required_reasoning_effort = high`, and applies the endpoint-first/model-fallback effort check to all
three selected roles during discovery and pending-registry derivation. Its nonauthorizing plan
proposed Z.AI GLM-5.2/`sail-research/fp8` while that exact ID was not yet confirmed. Generic and
unselected candidates remain capability-adaptive. That exact local checkpoint binds plan SHA-256
`120ef35de53a6c13b0d173a30b0e5e3f6310c3bf7032ce2a7ed92134a5099fbf`, and these
provider-free admission tests; it remains an unpushed historical predecessor.

The operator then ran a 16-source documentary capture at `$0`. That capture necessarily omitted
GLM-5.2 because the compiled inventory contained only `zai-org/GLM-4.7`; its output is superseded and
grants no lineage or runtime authority. Local checkpoint
`dce1c2591d62b0cfe8eef28385e3d9a8f759e3e3` adds `zai-org/GLM-5.2` at immutable revision
`b4734de4facf877f85769a911abafc5283eab3d9` as the exact seventeenth capture source, while retaining
the repository's canonical `z-ai` publisher and independence identity. A fresh 17-source capture then
reproduced exact GLM-5.2 bytes at SHA-256
`ed5aca8ce3dc5f8de626c87e488444343e43b1dcbdeb0e643dc72fea63ab06e8`, observation-set
SHA-256 `db27957fd9bae451acfb78409936b12d795e89c0ac31f7c53874dcb52adb7c73`, and capture semantic
bundle SHA-256 `a7ef51f5c75b851c53991414d51f33af80cbfc419934dc9f5be6365829f7b114`.

Local checkpoint `331bde27c7085d4da34c7b8ec1f688f2ce1e52b3` adopts that exact capture provider-free. The raw
25,209-byte capture journal has SHA-256
`e2c999f7860f4b5a4753bf872baa71b12edc500fa220c35cdc780292a67d7ef7`; the raw 61,852-byte
manifest has SHA-256 `b097a65613a07930f5c256c63065202a8998d5212a0021312a0e315ff6557b53`, and its semantic
bundle is `815fc0e376682f83f994ac5c21962c5f43556a78f5e736045f93a6ee81e5de0d`. It binds 17
sources totaling 432,659 bytes, 16 aliases, 18 claims, 16 decisions, 12 confirmed identities across
11 roots, four unconfirmed identities, and eight conservative constraints. Z.AI GLM-5.2 is confirmed
at root `sha256:c75238db92f2deb5938759be4c163b22a95f1297a2eb560ab5d90ba69d0764e7`;
the GLM-4.7/GLM-5.2 same-publisher constraint remains negative-only, and all six directed checks for
the selected DeepSeek/Z.AI/Moonshot triple pass. This is documentary identity authority only; every
provider, selection, qualification, runner, seal, benchmark, audit, and release flag remains false.

After that reseal, the operator's metadata-only r8 discovery for Z.AI/`sail-research/fp8` succeeded at
`$0` with frozen-registry SHA-256
`8f3fc274390d983bde683e3039a91f7cb6ead0f4dfa9aa89caa02ecca7e9ed26`. The r7/r8/r7
live-route gate then failed safely before a completion because DeepSeek/`fireworks` and Kimi/`together`
lacked explicit `max_completion_tokens`; the Z.AI route supplied `131072`. No completion, new charge,
or AUTHRUNNER bundle resulted. That 66,812-byte / 1,198-line historical operator record has SHA-256
`5faa33fe1bd5b332e8dffa0b29ed5718886d0c8b22c65cb1dc67b306eba8d00f`.

Local checkpoint `3975d2e12fd81a214b9faa1c3031c94506ab696d` fails closed on missing explicit completion
capacity during plan, registry, smoke, and full-runner admission. Its historical schema-v1.3 plan
`4e6c744559b1cc49c8ede590c868df103a10402d429d5e5d02cf4f429e0f3a66` proposed
DeepSeek/`parasail/fp8`, Z.AI/`sail-research/fp8`, and Kimi/`wafer`. Subsequent `$0` r8 metadata
discovery froze candidate DeepSeek/`parasail/fp8` at
`4e08e6496952e817e39d6872684a4e69cfb05cf74374870f51c234a6513b7306`, while replay
Kimi/`wafer` failed closed because the endpoint had drifted to status `-5`. No replay registry,
live-route gate, completion, new charge, or bundle resulted. That 69,112-byte / 1,236-line operator
record has SHA-256 `5fb3d3091e339b840e84468093c0f1f64c738673a40761fcf7d7b9d7ae4c41c6`.

Historical local checkpoint `dcabe3128ba1aca84c3df90d8a64b1a6bc77db1d` retained the candidate and
PRIMARY routes and replaced the failed replay singleton with the nonauthorizing sorted allowlist
`modal/mxfp4`, `phala`. Plan SHA-256
`ecb8f621846fec735de5f541f6fc7a28f40b0bdac8c49dbbd57e37384e18b71f` was nonauthorizing,
local only, and not pushed or remote-resolved. Current provider-free checkpoint
`7ef471744adfce557edf612a74b2847aafb3e8bc` upgrades the same route choices to schema v1.4 / plan
SHA-256 `bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f`,
binding the shared route-predicate profile and exact constraints without refreshing route evidence
or granting authority. The operator explicitly selected `modal/mxfp4` and completed its exact r8
discovery; no automatic route fallback is permitted.

The operator froze replay r8 at
`75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8`, and validated the
complete r8/r8/r8 live-route gate through 15 logical metadata GETs with at most 30 attempts. The
effective config SHA-256 remained
`42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`; usage, budget, ledger,
and output were unchanged, with no completion, new spend, or bundle. Historical command checkpoint
`7ca15589453fbc5219da4bbda87e37da824470a7` then emitted the r8/r8/r8 pair. Its step A failed on
overnight candidate endpoint-inventory drift. The operator re-froze only the candidate at `$0` as
`candidate-registry-r9.json`, run `authrunner-candidate-20260822-r9`, frozen SHA-256
`cc65071ef3723fc075b958aec4ad0180cdc99dc853d19b3a7983015f7e1c34ad`; PRIMARY and REPLAY r8
remained unchanged for that historical sequence. The resulting r9/r8/r8 metadata-only gate was
exactly `VALID` through 15 logical
GETs. The paid launch then stopped before provider completion or new spend because the permanent
ledger already contained deterministic request ID
`authrunner.smoke.r1.candidate.primary:721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497`.
The ledger then contained exactly one reconciled `$0.01680888` entry and no bundle was published.

The cause was lifecycle identity, not route admission: every smoke request hardcoded namespace
`r1`, so the fixed one-case corpus could never be rerun against its cumulative ledger. Source
checkpoint `9c61871502abbd19ff13278893f9c7785c5b28ba` makes `--smoke-run-index` an explicit required canonical positive integer, seals that
index through candidate and judge cost plans, reports, run evidence, the final bundle, and offline
replay, and retains disjoint full-release namespaces. Provider-free preflight rejects an index
already present anywhere in the cumulative smoke ledger before secret selection or metadata/model
transport. Its 385-test implementer matrix and independent 363-test review passed alongside Ruff,
format, strict mypy, schema write/verify, and diff gates. That r9/index-2 command pair is historical
and has been removed from the current guide after execution.

### Historical r1–r19 accounting and canonical-replay boundary

At the `c627f2d` boundary, the then-reconciled operator record was 115,171 bytes / 2,111 lines /
SHA-256
`4616c5a143db158f3af12d0a4d58306e0da6ca9dd4bbb54e6c7484dfc2de0251`. It reports outcomes for
indices 17–19 after the previously occupied 1–16 and a later offline verification of the unchanged
index-19 bundle at checkpoint `c627f2d`; the next unused index is not stated and is not inferred.
That source-only route-constraint boundary intentionally did not open a later user-owned working-tree
record. The dated current reconciliation below supersedes this historical accounting snapshot; no
current result or command depends on these old bytes.
The first four entries were individually enumerated at the prior snapshot:

| index | actual USD | accounted USD | terminal status |
| --- | ---: | ---: | --- |
| 1 | `0.01680888` | `0.01680888` | `reconciled` |
| 2 | `null` | `0.05225616` | `uncertain_accounted` |
| 3 | `0.00554796` | `0.00554796` | `reconciled` |
| 4 | `0.00537768` | `0.00537768` | `reconciled` |

Runs 5–9 were all `reconciled`, but the prior operator snapshot did not provide an authoritative per-index
cost mapping for them; directly queried generation totals are not a complete ledger table and are not
assigned to indices here. That nine-entry snapshot accounted `$0.10457436`, reserved `$0`, and left
`$249.89542564`. The pre-hotfix operator record reported thirteen ledger entries and total
`$0.133173`, all reconciled except retained r2. The post-hotfix record then reported fifteen entries
and total `$0.145695`, with index 14
charged `$0.004044` and index 15 charged `$0.008478`; its per-entry status and budget fields were
unstated. The prior record reported sixteen entries and total `$0.151976`, with index 16 charged
`$0.006281`. That historical record reports a 25-entry global ledger totaling `$0.396223`; its completed
index-19 run has a separate closed four-entry ledger at `$0.39622262`. Exact per-index costs for
r10–r13 and r17–r19, reserved/remaining at that boundary, terminal-entry count, and aggregate
counters were unstated. No entry may
be released, superseded, reused, or hand-edited. Run 10 followed checkpoint `d2364f6`: an immediately preceding gate with PRIMARY
re-frozen as `primary-judge-registry-r14.json` was operator-reported VALID, then the paid run stopped
at the intended immutable completion-receipt cutoff with `usage_diagnostics=NONE`. `NONE` means zero
codes from the exceptional noncrediting-smoke diagnostic; it is not generic creditability or
authority. The live result confirms the candidate cutoff. Full candidate-and-judge pre-metadata-GET,
pre-ledger-replacement, pre-origin, and pre-capability coverage remains provider-free source/test
evidence, and no bundle existed at that historical boundary. Run 2 remains
conservatively accounted because no exact authenticated actual cost is available through a sanctioned
reconciliation path. Run 3 passed token validation and then failed at the successful-REAL benchmark
boundary; the historical caller discarded its typed cause. Run 4 retained raw provider counters
`prompt_tokens=234`, `completion_tokens=1280`, `reasoning_tokens=1307`, `cached_tokens=0`. This
disproves a universal response-level reasoning-within-completion assumption for that sample. It does
not prove that the route always reports additively or that completion and reasoning are same-domain
components, so neither `completion+reasoning` nor `max(completion, reasoning)` is treated as observed
usage.

After checkpoint `48ea635`, both judge routes drifted and the operator re-froze them at r15. The
metadata gate for index 14 then reported `VALID` nonauthorizingly, but the paid launch failed safely
before provider transport with `provider transport receipt cannot seal owned request state`. The
ledger remained thirteen entries / `$0.133173`, no provider charge or bundle occurred, and index 14
was not consumed. This is live negative compatibility evidence for the production-constructed
transport, not a strong-origin positive or provider-response-graph proof. The operator's suggestion
that a wrapped/custom transport may explain the mismatch is analysis, not independently proven fact.

Receipt-state-seal hotfix checkpoint `68126e0fe438f853fb9b75582023f807a208bdae` repairs that
receipt-state-seal incompatibility provider-free. It validates and neutralizes structurally exact
response-derived HTTPX cookie state, rejects Cookie-bearing request plans and outgoing requests,
removes Set-Cookie from safe response projections, and seals the cookie store, lock, and policy by
identity and exact state. Receipt use fails before grant, reservation, or transport unless the runtime
is CPython 3.12/3.13 with the pinned private cookie shape. Non-REAL and REAL generic/RELEASE scopes
return before this exact-smoke compatibility gate.

The prior operator record supplies post-diagnostic live evidence. The receipt-seal error remained
gone, the route gate was reported green, and paid index 16 failed later with
`NONCREDITING_SMOKE identity binding lacks immutable receipt custody` and exact closed code
`usage_diagnostics=STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS`. This positively
traverses the repaired receipt-seal boundary and four earlier structured-output identity clauses, then
negatively evidences the exact required-provider-parameters equality. It is not a genuine
candidate/judge strong-origin positive, sealed bundle, runner result, or release evidence. The
operator explicitly retracts its prior requested-mode hypothesis: `IDENTITY_MODE` passes. The
operator's construction-asymmetry explanation
and request to log both sets are nonauthorizing analysis, not independent source proof; the bounded
provider-free continuation must preserve exact equality and closed value-free diagnostics without
logging unbounded values.

That historical operator record reports that generation checkpoint `03d6e8a` cleared that join
and index 19 completed candidate primary/replay and judge primary/replay as
`COMPLETE / NONCREDITING / NONAUTHORIZING`. It reports a sealed 282,802-byte bundle at SHA-256
`e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703`. Its 02:17 entry records the
strict-datetime replay failure and diagnosis; the new 03:23 entry reports that the then-current
replay checkpoint `c627f2d` verifies the same bundle bytes offline as
`VALID / NONCREDITING / NONAUTHORIZING`, without another provider run or new spend. This is
operator-supplied verification, not independent private-artifact authentication by Codex. Index 17
ended after an operator-side timeout with one `uncertain_accounted` judge entry, index 18 failed
`SCHEMA_VALIDATION_FAILED`, and index 19 completed. The next unused index is not stated. Completed
real audits remain zero. One case does not establish 24-case aggregation/scoring, audit quality,
calibration, qualification, benchmark, AUTHSEAL, release, readiness, or runtime authority, and no
current command or campaign authority exists.

Source checkpoint `531a9d822e9989bf2eda94530e88cf55f2dd2e0d` keeps raw provider prompt,
completion, total, reasoning, and cached counters raw. Request-plan v3 separates the wire-visible
output maximum from the conservative visible-plus-reasoning reservation. A typed self-hashed
`MMAUDIT_INDEPENDENT_REASONING_COMPONENT_ENVELOPE_V1` accounts the complete planned prompt, visible
output, and reasoning reserves without claiming inclusive or additive provider semantics; exact USD
comes only from `usage.cost`. This exceptional envelope is admitted only for exact owned REAL
`NONCREDITING_SMOKE` records reconciled to authenticated generation identity, provider, time, cost,
and raw counters. General usage creditability, durable release evidence, qualification, and the
24-case campaign still reject unknown convention. Closed smoke diagnostics now retain the typed
usage-cause code and separate case-ID mismatch without exposing unbounded response data. Runs 5–9
confirm both the independent plan-envelope check and typed `UsageValidationError` surface work
nonauthorizingly.

The historical fail-closed boundary was later: provisional identity was
`CANONICAL_MODEL_AND_ENDPOINT_BOUND`, but final identity is downgraded to `UNBOUND` with
`identity_binding_status=generation_metadata_unbound`. Exact and canonical DeepSeek aliases are
accepted, provider is Parasail, both fallback flags are false, certification is requested, and the
endpoint policy is ZDR. Operator-side direct generation and timing/validation probes are
nonauthorizing observations and cannot independently establish the internal client cause.
Provider-free successor `77fb4b9a0c03969a9776edf2091dc09d3b67daec` surfaces the already-sealed closed
`OpenRouterIdentityDiagnosticCode` set at this branch, rejects raw or unbounded provider text, keeps
case mismatch separate, and regresses each disposition. Index 9 confirms that surface with
`GENERATION_METADATA_INVALID|GENERATION_METADATA_MISSING`. Operator-side probes report that aliases,
the configured IO budget/poll window, and the live payload validator are individually viable, but
those probes are nonauthorizing and do not prove the in-client fetch sequence. Source inspection
identified that initial REAL completion binding built the generic generation-reconciliation
expectation and applied generic bindability, which intentionally rejected the v3 unknown-token
convention before the later special `NONCREDITING_SMOKE` seam. Historical source checkpoint
`8058e7bff88594b44aa42b8695ce5c25442ae73c` selected the special structural policy only for the
exact owned REAL v3 unknown-token smoke case while generic credit remained fail-closed. It also added
a closure-owned isolated raw GET/POST/error receipt state machine. Production receipt preparation
and dispatch were deliberately dormant at that historical boundary. The then-current operator record
reports that candidate
identity now reaches `CANONICAL_MODEL_AND_ENDPOINT_BOUND` / `generation_metadata_bound`, is persisted
BOUND, traverses the high-level origin-marking path, and then the benchmark rejects the record at its
intrinsic strict-usage predicate. The operator record cannot independently prove the opaque origin
capability and does not identify the exact rejecting clause. The intended completion-receipt cutoff
was therefore bypassed; at that historical boundary judge verification remained before capability
issuance awaiting an immutable metadata receipt. The scaffold is not provider, credit,
certification, runner, or release authority. Direct-child hotfix
`d2364f6b528f2e839fbef8b878552f95c4b92c9c` owns exactly seven paths and uses a closed exact
candidate/judge smoke-scope classifier independent of strict validity. Exact smoke coordinates,
including intrinsic-invalid records, now stop before generation-metadata GET, `UsageLedger`
replacement, owned-REAL origin marking, or generation-verification capability issuance. Strict
rejection exposes at most one code from a closed vocabulary; generic and RELEASE behavior stays in
parity. Parent matrices passed 642 plus 57 tests; independent matrices passed 648 plus 125 tests, a
3,488-case differential found zero mismatches, and review found no BLOCKER/HIGH. This is provider-free
local evidence, not a live success or launch authority.

Historical AUTHRUNNER replay checkpoint `c627f2debfa18df7d9567cd7c3300d19a9e9f5ce` is the exact
three-path replay repair and direct child of historical five-path join checkpoint
`03d6e8a644dd4a807860bfcc4dfc9d004cff3cbc`, which is the exact child of historical
clause-diagnostic checkpoint `3a1246daf19ffa4a772be7806bd903199634ab0b`.
That diagnostic is the exact five-path child of receipt-state-seal hotfix
`68126e0fe438f853fb9b75582023f807a208bdae`; that hotfix is the exact
four-path child of historical receipt-composite checkpoint
`48ea635ab5a2fa778d6b5ce5c9a1592f0f27b375`. The receipt-composite checkpoint activates receipt
preparation, dispatch, all-or-none
completion-plus-metadata composition, and consumption only for exact canonical candidate or judge v3
`NONCREDITING_SMOKE` coordinates. Generic and RELEASE requests retain the historical path. The
source path is designed to bind completion POST retry vectors and generation-metadata GET polling vectors to the
same client, transport, task, thread, PID, and ledger, consumes the composite inside the corresponding
usage-origin or generation-capability boundary, and scrubs raw prompt, header, and response objects
after successful sealing. Public `StructuredCompletion` remains the two-field `value` / `usage_record`
carrier. The hotfix fixes cookie/state sealing and response-cookie cleanup without widening that
scope. Historical `3a1246d` refines the prior composite `STRUCTURED_OUTPUT_ROUTING` failure into
the first matching member of a closed set of 35 ordered, unique, value-free clause codes. It preserves
the previous boolean creditability truth and ordering, optional/missing/None/equality and unbound
behavior, generic and RELEASE scope parity, and the production call-root set. Both the legacy bool
helper and new diagnostic helper are captured and pristine/retarget checked. Historical `03d6e8a`
captures the exact CANDIDATE/JUDGE v3 `NONCREDITING_SMOKE` reasoning-identity join. Disabled
reasoning requires neither the evidence nor identity required-parameter set to contain `reasoning`; active reasoning requires
evidence `reasoning` plus identity reasoning capability/support, while only exact candidate/judge v3
smoke may omit `reasoning` from the identity required-parameter set. Generic/RELEASE exact equality
and the production call-root set remain unchanged. That historical replay checkpoint removes only
the call-level strict override whose propagation into nested mapping-copy validators rejected
canonical JSON datetimes. Model-level strict contracts, exact bundle type, the bounded bytes input, and exact
canonical-byte equality remain mandatory. The HTTP stack remains
exact-pinned to `h11==0.16.0`, `httpcore==1.0.9`, and `httpx==0.28.1`.

Historical `c627f2d` provider-free validation passed 95 smoke-runtime tests, 111 adjacent
CLI/durable/inventory/release-schema tests, and the retained exact 789-test AUTHRUNNER matrix as three
separate overlapping results. A genuine synthetic 265,244-byte sealed v1.2 bundle with two runs and
four usages round-trips through the real seal/serializer/parser, while coercive string and whitespace
variants reject canonically. Ruff format/check, strict mypy over the changed source, canonical umbrella
release-schema/inventory generator verification, `pip check`, and diff integrity passed; independent
exact-byte review found no blocker, HIGH, or MEDIUM. Historical `03d6e8a` retains 19
request-cost-preview tests, 26 model-benchmark tests, and an overlapping 185-test usage-plus-preview
run; 166 usage tests overlap its 789 matrix, so no combined unique total is inferred. Its independent
guard review covered 47 roots and 1,073 reachable function states. A clean
subprocess mutation loop replaced every unique function's code with an identity-distinct
same-semantics `code.replace(co_name=...)`, observed the pristine guard fail, restored the code, and
observed recovery for all 1,073 states. Ruff format/check, strict mypy over `usage.py`, canonical
release-schema generator verification (including autonomy inventory), and diff integrity passed.
Historical `68126e0` additionally retains 785 focused tests, one actual pinned-HTTPX HTTP/1.1 local
numeric-loopback integration with two chunked responses, and `pip check`; the loopback used no
provider, public network, or private artifact. The repository-wide
`.venv/bin/pytest -q` result is `INCOMPLETE`, not a pass: it stopped after 1,492 passed and 25 skipped
at the deterministic pre-existing
`tests/unit/test_candidate_benchmark.py::test_authenticated_runner_candidate_consumes_exact_cost_preview_inventory`
failure after 3,878.41 seconds. The failure message was `candidate benchmark request accounting is
inconsistent`; benchmark cases reported `ReasoningPolicyError` with zero observed usage. The same
exact test fails on untouched parent `4e035a9d58b98284e7cceecf1fb844bc84e0dbe6`, so it was not
introduced by the receipt-composite lineage. No repository-wide pass is claimed for `c627f2d`.

That historical reconciliation supplies one operator-reported production candidate/judge smoke and
offline replay, but it remains one-case, noncrediting, and nonauthorizing. The historical index-14
live negative shows that checkpoint `48ea635` could not seal the
owned request state. Historical child `68126e0` fixes that boundary provider-free; paid indices 14–16
traverse receipt sealing plus part of the actual-provider response path, with historical index 16
rejecting at exact `IDENTITY_REQUIRED_PROVIDER_PARAMETERS`; later index 19 traverses those exact
routes end to end according to the operator record. That does not establish broad provider/private-
graph compatibility beyond the exact reported routes. Two complete production publication
rollback joins remain unexecuted; the rollback ordering and per-stage cleanup are source-reviewed and
independently regressed. The bounded pure-Python guard covers persistent ordinary
subordinate module/class/instance/function identity, code, defaults, keyword defaults, globals,
closure-reference, and attribute drift plus reachable mutation or replacement of the guard's frozen
state holder. It excludes deliberate introspective writes into closure-owned live authority-registry
dicts or cells; coordinated mutation of the outermost checker together with its expected references;
and tracing, profiling, native-memory, or equivalent runtime compromise.
Index 8 independently failed `SCHEMA_VALIDATION_FAILED`; this is candidate reliability evidence, not
route-disqualification authority.

The `531a9d8` 906-test matrix and independent review were CLEAN. The identity successor's 340 focused
tests, Ruff, format, strict mypy, generator write/verify, and independent no-HIGH review also passed.
The dormant receipt scaffold's focused provider-free matrix passed 458 tests. Historical `3a1246d`
retains its independent 564-test / 47-root / 1,072-state evidence. The current committed
`425502c5cbc173578053423d946ef24843f26285` PLANCONSTRAINTS repair inventory
raw/self/discovery/universe hashes are
`7a0655597bf161bd3f90c67beba1845f9783626661b11ba8162acd1623b46965`,
`a1556b6f2b816af1562401a646fcea61e34dadc069140cbe7b40d0447bae3fb1`,
`4f1adb9e0bc8db7899fa4eb2928ee03f87d4d61d4113a0555fcdae750e260042`, and
`acf4bb31570e028336e572560d5348a30013070d2335c157a467dfae05c98b83`; counts are 3,657 sources /
3,660 occurrences / 3,614 gate sources / 43 non-gating controls / 13 source kinds / 35 logical gates /
29 unsatisfied / 15 current-manual. The current smoke schema raw SHA-256 is
`34f264a5fa9ae55ba6d0c02d2e1f78c81aa4abf2c19ab50b6366c2c4d6e75404`; the historical
pre-PLANCONSTRAINTS value was
`2163642df1d0b7adf463eb04887e2027e462acdd716ec83451d76c49d80db78d`.

The operator's r15 judge re-freezes and every later result remain nonauthorizing. No AUTHRUNNER
command is current; the next unused index is not stated. Preserve `c627f2d`, the operator-owned
bundle, and ledger state. No AUTHRUNNER action is authorized and no new index may be inferred.
Provider-free `V3-PLANCONSTRAINTS-001` is complete: its shared 29-predicate profile now binds the
selection plan, pre-snapshot discovery publication, registry custody, provider price-cap projection,
and FULL/NONCREDITING runtime admission. Runtime output tokens must exactly match the profile before
state mutation. Without explicit verified runtime evidence, empirical schema conformance and the
token-detail convention remain typed `UNAVAILABLE`.
Historical operator-supplied evidence records a private provider-free replay in which matching
index-21/r21 evidence promoted `EMPIRICAL_SCHEMA_CONFORMANCE` to `SATISFIED` but rejected
`TOKEN_DETAIL_REPORTING_CONVENTION` under the pre-fix digest join. `V3-RUNTIMEADMIT-001` is
`COMPLETE` at its corrected provider-free boundary and implements a path from one exact canonical
authenticated-runner smoke-v1.2 bundle to an opaque, policy-age-bound capability for the same
candidate, PRIMARY, and REPLAY model/endpoint/profile/discovery bindings. Missing, stale,
mismatched, tampered, caller-asserted, or non-FULL evidence remains rejected, and the default
discovery bytes still leave both predicates `UNAVAILABLE`. Codex did not read or replay the private
bundle. Later operator evidence reports corrected-code FULL admission for one launch, followed by a
candidate failure; that launch grants no reusable admission, and no current operator command or run
index follows. Proposal item 5 is
`ADOPTED_NONAUTHORIZING / IMPLEMENTED` at `531a9d8`: bounded typed successful-usage diagnostics keep
case mismatch separate and avoid premature generation fetch. Item 3's REPLAY allowlist is historical;
its proposed candidate/PRIMARY extension, and items 2, 4, and 6, remain
`OPERATOR_SUPPLIED_NONAUTHORIZING_ANALYSIS`. `V3-AUTHRUNNER-001` remains `PARTIAL / BLOCKED_SAFETY`.
At that historical AUTHRUNNER boundary, `V3-AUTONOMY-001` Phase 2 remained paused; that statement
does not describe the current local-provisioning slice. No qualification, runner, seal, audit,
benchmark, or release authority exists.

### Historical AUTONOMY Phase-2 local provisioning boundary

The current work unit closes only a bounded local-provisioning slice;
`V3-AUTONOMY-001` remains `PARTIAL`. The supported `mmaudit managed provision` interface takes
explicit `--repo` and `--output-dir` paths plus optional `--config` and `--verify-only` controls. It
is provider-free and loads configuration from the selected file with ambient configuration
overrides disabled. It hashes the bounded audited-workspace content inventory, subject to the
compiled exclusion domain, under retained local custody, but it selects no operator secret source
and performs no provider or network request. The repository and owned mode-`0700` output directory
must be absolute and disjoint.

Its sole implemented provisioning action is exact cost-ledger create-or-verify. The ledger path
must be absolute, have an existing private parent, and remain outside the repository and receipt
directory. A durable private provisioning marker serializes creation and prevents deleted state and
its ordinary lock from being treated as a fresh budget. The default path initializes only when no
prior marker, state, or ordinary lock was observed, or verifies an exact existing ledger;
`--verify-only` requires an existing exact marker and ledger pair. The receipt binds the marker
identity and a typed point-in-time snapshot of the immutable cap, ledger identity, entries, active
reservations, portfolio holds, and held value without reserving, charging, reconciling, clearing, or
otherwise altering an existing ledger.

The output is a self-contained typed plan-and-state receipt. Repository custody finalizes and
reobserves the original audited-workspace digest before a final receipt name is linked. Canonical
self-hashed JSON is fully written and synced to a private temporary file before atomic no-replace
publication under its content-addressed name; an existing destination is accepted only when its
canonical bytes and typed envelope match exactly. Identity-checked rollback operates under the
cooperative publication lease and is not an unconditional guarantee against lock-ignoring same-UID
pathname replacement. The repository digest is point-in-time evidence, not a promise that source
remains unchanged after finalization. The receipt keeps `spend_admission_evaluated`, `runtime_authority`,
`managed_run_ready`, `provider_or_network_accessed`, and `operator_secret_sources_accessed` literal
false. Repository hashing records local evidence and confers no trust, selection, or execution
authority.

This slice does not create or verify a CodeQL database/query suite, materialize or target-bind a
dependency snapshot, establish a pinned loopback fork RPC, inspect or install managed-toolchain
binaries, verify their transitive closure or image-side attestation, establish process/isolation or
execution evidence, evaluate spend admission, or run a managed audit. It does not benchmark,
qualify, seal, promote, or release anything. Required unsupported inputs and unresolved toolchain
roles become closed typed refusals; unused optional inputs remain `NOT_REQUIRED`. The mandatory
installed-toolchain refusal therefore keeps every current receipt `REFUSED_INCOMPLETE`, even when
the cost ledger is created or verified exactly.

Selection remains separate and fail-closed. The active repository schema-v1.7 plan retains the
exact V1 judge profile, with no selected candidate or candidate route. The operator reports an
externally emitted V2 successor and a completed metadata-only discovery against it; that artifact
is not adopted or selected, and there is no active selected successor or current live operator
command. Codex did not invoke the new local command against operator-owned paths.

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

The repository's active unavailable-candidate plan preserves the exact V1 price-cap profile. The
operator-reported private V2 plan remains unselected and unadopted, and its prior metadata-only
refusal did not exercise V3. No candidate, route, command,
run index, provider/network action, configuration, retry, ledger, completed-audit count,
qualification, runtime, release, or other authority changed. Resume only if a provider supplies a
request-bound cache-write or total-cost cap, or an equivalent enforceable atomic contract.
At the historical pre-verification boundary, remote-resolved HEAD
`ad013aeeb4ea754ec7f0c751175e4badd5fc95b2` introduced `V3-PLANADOPT-001` over operator-result
commit `c8a46b9b53a77fcdd4241d8fadeecbebc876346d`. Current remote-resolved HEAD
`810ed7f32a9f39df104a6959e84b71c59966fb44` records the operator's PLANADOPT verification; the
provider-free local implementation described above has not issued any external command.

### Historical PRICECAPCOMP selector closure

`V3-PRICECAPCOMP-001` is `COMPLETE`, provider-free, and nonauthorizing. An explicitly selected V2
route profile may retain nonzero `web_search` pricing only with a self-hashed immutable envelope
proving the exact emitted request has zero reachable search units and zero search cost. The request
shape prohibits search, tool, and plugin controls, omits the unsupported component from provider
`max_price`, and is revalidated before reservation and again at transport. The profile and envelope
remain joined through discovery, registration, tier-wide cap/cost projection, preview, refresh
controls and durable attempts, smoke plans, route-runtime evidence, and the frozen provider-egress
callable graph. Missing, duplicate, substituted, positive-unit, unknown-component, or tampered
custody fails closed.

A supported operator-facing provider-free selection path now exists:
`models emit-selection-plan-successor --upgrade-price-cap-profile-v2`. The flag is default-off, and
omitting it preserves exact V1/default bytes. The opt-in path accepts only an exact V1→V2
transition, supports a same-route successor, and rebuilds the shared profile plus every resulting
candidate, PRIMARY, and REPLAY constraint. Validation rejects repeat V2, downgrade, profile or
constraint drift/tamper, a non-boolean API flag, revocation, and stateful predecessor substitution.
Successful publication creates a fresh mode-`0600` output. This is a plan-construction capability,
not a live selection or execution: no successor artifact was selected or inspected and no live
command or route retest is requested.

At that historical closure boundary, the active selection plan remained schema `1.4` with its
original V1 price-cap profile and byte/hash identity; configuration, retry behavior, the 57-entry /
`0.68118684` USD ledger, candidate, and route remained unchanged. The recorded xAI route remains unselected and inadmissible
because `input_cache_write='0'` still lacks an enforceable provider cap, dominance invariant, or
immutable disable control. Conditional V2 handling resolves only `web_search='0.01'` for the exact
zero-unit request and grants no live admission.

The final validation passed `120` focused selector tests and `1,328` affected tests with two known
warnings; release-schema, autonomy-inventory, and refresh-schema validation passed `79` tests;
Ruff, strict mypy over `233` sources, canonical generation/verification, and diff integrity passed.
The regenerated autonomy inventory hashes are raw
`fcecc2351ab9d5fd7a0e6c0289e9daeb7f6ec83cebfd00552948e9b090617c73`, self
`0f575febde00869a20192214a40af87e7196660a8e82b5810e8beefb45caad28`, discovery
`bc80c98c469dc9cce61af880c8849e8387143ad1e3fb7d853d4eca8e9205e340`, universe
`3f41a8b19a0e7547bc619f1405692e19a05e62d9662471f10736d79a2d619389`, and schema raw
`88790b6d1d02fff4f2a39ff0bc0c023d062459e6d19d594a1c93cee03871c6c7`; it records 3,941 sources,
3,944 occurrences, 3,892 gate sources, 49 non-gating controls, and 337 completion entrypoint
parameters. No full-suite credit, provider action, or authority is claimed. At that boundary,
current and next tickets were `UNSELECTED`; `V3-PRICECAPCOMP-001` was last complete,
`V3-MODELREFRESH-001` was last partial, `V3-CANDROUTE-001` remained partial, and the combined
unfinished count was `40`.

The latest operator-supplied record is SHA-256
`215ea0f2f312b9674fb51285f6fdf758b166a0a998e2d2d621ac2da42f9a5f19`, 190,177 bytes / 3,377
lines, latest `2026-09-04T03:39Z`, at remote-resolved commit
`810ed7f32a9f39df104a6959e84b71c59966fb44`. It verifies the active schema-v1.7 null-selection
state and treats the unavailable-predecessor ancestry refusal as deliberately fail-closed. It asks
whether a supported authenticated transition exists. At that operator-evidence boundary none
existed, so its stop disposition remains accurate historical evidence and no operator command
follows from the record. The later local `V3-PLANANCESTRY-001` work unit implements only the
provider-free repository-pinned mechanism described above; it does not retroactively alter the
operator record or authorize adoption. The 57-entry / `0.68118684` USD ledger and zero completed
real audits are unchanged. The record is operator-supplied, nonauthorizing, and not independently
authenticated by Codex.

The prior operator-supplied record is SHA-256
`63bfe90b281a6382b921c63669e817e65220c81b629fc75a7cb35b3f3e429d5b`, 187,993 bytes / 3,335
lines, latest `2026-09-03T22:31Z`, at remote-resolved commit
`c8a46b9b53a77fcdd4241d8fadeecbebc876346d`. It reports a private emitted V2 plan
`96cc5301111c7b60cf9b8235870d8051e2ece737c80dc5321662a1f6adfa3aea` and one metadata-only
constrained discovery that genuinely exercised it. Discovery retained the same
`PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE` refusal pair, and the ledger remained at 57
entries / `0.68118684` USD. This is operator-supplied, nonauthorizing evidence and was not
independently authenticated by Codex. The private artifact is not adopted or selected; it changes
neither the active repository plan's retained V1 profile nor route/candidate state, and no further
command follows.

The immediately preceding operator record is SHA-256
`d502c61a2525a2bdcc2e7efd79b115821af60f604e715d7be7ccd51b02983ab1`, 185,462 bytes / 3,287
lines, latest `2026-09-03T21:03Z`, at remote-resolved commit
`dd141cd580c2a012a6efdef26213d3a727b68041`. Its newest entry accepts that every operator retest
completed by then used the active V1-derived profile and therefore did not exercise V2, then asks
whether a real run can select V2. The historical 21:11 answer was that no supported path yet
existed, and the 21:18 reopening recorded that direct construction did not meet the
explicit-selection criterion. Those statements remain boundary-local history; the same-ticket
option above later resolved that gap while leaving the then-active plan unchanged. The record remains
operator-supplied, nonauthorizing, and not independently authenticated by Codex.

The prior exact operator record,
`2da419f85a9f6b2d087c1f75dca4247ef91d8fcf23005c719644de5830238b21`, 182,652 bytes / 3,240
lines, latest `2026-09-03T20:43Z`, at remote-resolved commit
`b9ea875e70d865b50c1eb847e39ed767162c9c6b`, remains historical evidence. It reports that a
credentialed metadata-only V1 constrained-discovery retest returned
`PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE`, created no snapshot, and left the ledger
unchanged. Its possible flat-only discovery explanation was an operator question, not a root-cause
claim. Provider-free call-graph inspection showed constrained discovery is schedule-aware and the
quoted refusal belongs to a separate refresh-only helper. The shared failure pair cannot
distinguish V1's two component refusals from V2's remaining cache-write refusal. No live command or
retest follows from either operator record; `completed_real_audits` remains `0` and every authority
remains false.

### Previous MODELREFRESH tier-schedule closure — 2026-09-03T13:58:58Z

`V3-MODELREFRESH-001` closes a bounded provider-free continuation as `PARTIAL`. Exact ordered
base-plus-override schedules and their conservative maxima now traverse refresh source parsing,
snapshots, deterministic drift, durable route and attempt pricing evidence, endpoint registration,
live preflight, provider caps, reservation, usage, recovery, reporting, manifest, and assurance
custody. Schedule digests distinguish equal-maximum threshold changes; unavailable, mismatched, and
tampered schedules fail closed; and flat-route evidence remains byte-identical. Published nested
schemas expose the same tier-field allowlist and canonical-decimal bounds enforced at runtime.

At that boundary this work did not admit or select the recorded xAI route. Its independent
`input_cache_write='0'` and `web_search='0.01'` component-cap constraints remained unresolved, and no
successful current provider snapshot, live artifact round trip, automatic real benchmark, lineage
re-evaluation, qualification, promotion, or stock live authority quartet exists. Validation covers
the focused refresh/runtime/OpenRouter/schema path, downstream usage/recovery/assurance custody,
canonical schemas, Ruff, and strict mypy; no terminal full-suite credit is claimed. At that boundary,
current and next tickets were `UNSELECTED`; `V3-PRICEOVERRIDES-001` was last complete and
`V3-MODELREFRESH-001` was last partial. The exact operator correction at `2026-09-03T14:30Z`,
SHA-256 `e446f2c23f3de0b6dd1352b8f4874f8f95bbb26a128638b2356af29a0850f596`
(180,312 bytes / 3,194 lines; remote-resolved commit
`5245c02beb18d1376d14069e3df2b3fcc098aa55`), retracts the prior key-order root-cause claim.
Full provider ingest already canonicalizes raw tier keys, and the 120-permutation assay yields one
pricing hash and one snapshot hash. `V3-PRICEKEYORDER-001` is therefore
`WITHDRAWN_OPERATOR_ERROR` and must not be implemented. The operator-reported post-MODELREFRESH
live discovery failure remains the same named cap pair, so neither the correction nor the correct
schedule projection establishes route admission or authority.

### Previous PRICECAPTIER closure — 2026-09-03T11:27:12Z

`V3-PRICECAPTIER-001` is `PARTIAL`, provider-free, and nonauthorizing. For each otherwise
expressible retained schedule, the implementation computes exact Decimal component maxima across
the base and every ordered partial tier. Partial tiers inherit prior values, later applicable tiers
win, and prompt/cache-read dominance is checked in every effective state. The schedule artifact and
provider-cap proof bind the complete ordered schedule and its exact maximum so equal-max schedules
cannot substitute for one another. Provider cap, request-cost projection, reserve, spend, and
reconciliation all consume that same conservative maximum, while flat-route serialization and
historical digests remain byte-identical.

Indeterminate or provider-unsupported schedules remain unavailable and produce the named
`PRICE_CAP_NOT_EXPRESSIBLE` and `PRICE_CAP_PROOF_UNAVAILABLE` route results; nested numeric override
lexemes remain rejected rather than acquiring exact-string custody. The recorded xAI schedule has
an exact maximum prompt rate of `0.0000044` and completion rate of `0.0000132`, but the route still
fails the independent `input_cache_write='0'` and `web_search='0.01'` provider-cap constraints.
Refresh and provider-free live preflight were flat-only at that boundary. Therefore the primary
route/preflight acceptance criterion was unmet, the route was neither selected nor proven
admissible, and the ticket could not be marked complete.

Validation passed `280` focused tests, `1251` affected tests with two warnings, and `241`
adversarial focused tests. Canonical release-schema and autonomy-inventory generation are current;
Ruff, strict mypy over `233` source files, strict JSON, and diff integrity passed. No terminal full
suite was run or credited. At that boundary, the exact operator record was
`37330cfdbc960dbf24691ffbafad10791abf2363767d9adaa4409458c0519cb3` / 176,768 bytes / 3,140
lines, latest `2026-09-03T11:38Z`, at remote-resolved commit
`a9bc614f6243b593ad06ca9bf9b87f7cd32aa3bd`; it is operator-supplied and nonauthorizing. It reports
that direct tier construction rejects provider-order keys and sorted construction succeeds, and
queues `V3-PRICEKEYORDER-001`. The provider-facing path already sorts raw tier keys before internal
construction, so the reported full-ingest root cause and sole-blocker conclusion are not confirmed
or adopted by Codex. The active
plan, configuration, retry behavior, 57-entry / `0.68118684` USD ledger, zero completed real audits,
and every external or production authority remain unchanged. Current and next tickets were
`UNSELECTED`; `V3-PRICEOVERRIDES-001` was last complete and `V3-PRICECAPTIER-001` was last partial at
that boundary.

### Previous PRICEOVERRIDES closure — 2026-09-03T09:54:24Z

At that closure boundary, the operator-supplied record was 173,635 bytes / 3,084 lines at SHA-256
`f37f46d56a544af4bef6e2ef662dc9a8e5b23a20f3789391c56aae1bb6968e5f`. Its reported commit
`af16299f1612df656dbc5f25592230c812a62dc4` is remote-resolved; the record remains
nonauthorizing and was not independently authenticated by Codex. Its then-latest response-shape
diagnostic reports that every direct billable value and every nested override price on
`x-ai/grok-4.6=amazon-bedrock/us-west-2` is an exact string. The non-exempt `overrides` value is a
list and was the first parser blocker behind the generic exact-decimal-string refusal. No completion
or new spend is recorded; the active plan and 57-entry / `0.68118684` USD ledger remain unchanged.

`V3-PRICEOVERRIDES-001` is now `COMPLETE`, provider-free, and nonauthorizing. The implementation
recursively validates and retains a bounded, provider-ordered tuple of exact tier entries; every
`min_prompt_tokens` is an exact bounded nonnegative integer and every nested billable price is a
canonical decimal string. Duplicate, descending, malformed, unsupported, nonscalar, negative,
out-of-range, and nondecimal tier data fail closed with named reasons. Documented strict `>`
threshold inheritance and later-applicable-entry semantics are covered without granting cost
authority. `pricing_sha256` domain-binds the base prices and full ordered schedule, the endpoint
snapshot binds that digest, and ZDR evidence must carry the identical schedule. Existing flat
endpoint evidence remains byte-identical.

Tiered cost projection is explicitly `unavailable`. Request-cost preview, endpoint registration,
identity sealing, and flat model-refresh evidence refuse conditional pricing rather than flattening
or silently dropping a tier. The full synthetic five-endpoint `models discover` regression accepts
and retains the recorded shape, then reports both independent route constraints:
`PRICE_CAP_NOT_EXPRESSIBLE` and `PRICE_CAP_PROOF_UNAVAILABLE`. Accordingly,
`input_cache_write='0'` and `web_search='0.01'` remain unresolved provider-cap constraints;
`overrides` is not proven to have been the sole blocker, and the conditional xAI route remains
unselected and not proven admissible. Focused PRICEOVERRIDES tests pass `56`; the affected
provider-free matrix passes `481`; scoped Ruff and canonical generation pass; strict mypy is clean
across `233` source files. No terminal full-suite credit is claimed.

`V3-PRICEFORM-001` is `COMPLETE` as a decision-only, nonauthorizing ticket: ordinary parsed numeric
prices still cannot prove the provider's original decimal lexeme and remain refused. Its later
price-lexeme successor changes pre-float custody rather than relaxing that decision. The affected
price matrix passes `795` tests with two warnings, including canonical string storage and cost-bound
parity; no code or configuration changed for the decision closure.

`V3-PRICELEXEME-001` remains terminal `PARTIAL` provider-free defense-in-depth: its route-specific
premise is superseded and it no longer blocks the xAI route. Pure Python cannot retrospectively
detect hostile same-interpreter reflection fully
restored before any trusted lookup; every observed mismatch is permanently revoked, and arbitrary
closure reflection is outside the trusted-interpreter boundary. The ordinary binary-float/missing-
capture refusal stands, candidate requests still emit and reserve `effort=high`, and retry behavior
and runtime configuration are unchanged. The conditional
`x-ai/grok-4.6=amazon-bedrock/us-west-2` route remains unselected. The focused live-shaped
full-`models discover` raw-numeric-price case passes `1` test in `0.76s`; the adjacent
price-decoder/endpoint/discovery/OpenRouter/CLI matrix passes `793` tests in `17.73s` with two known
warnings. Its trusted execution evidence remains `MOCK`; exact constrained-route identity,
normalized pricing, multi-ZDR custody, and MOCK-to-REAL sealing refusal are asserted. A broader
CLI/pipeline attempt was intentionally interrupted after `111` passes at `193.54s` and has no pass
or full-suite credit.

`V3-TESTQUALITY-001` is `PARTIAL`, provider-free, and nonauthorizing after the shared process-local
revocation-lease race slice. One PID-bound domain serializes run, observation, campaign, and score
authority reads and registrations plus handoff replay. Campaign and score revalidate exact local
seals after dependency release; decisive scoring uses seal-SHA-matched immutable schema snapshots,
requires authenticated snapshot `plan_sha256` to equal the canonical score plan, and revalidates
exact live sources at registration. Callbacks defer beyond the outer lease, partial and
`BaseException` paths exact-remove without masking the primary exception, and fork paths refuse
before inherited locks. The capability remains comparison-only: same-interpreter reflection,
asynchronous-exception micro-gaps, and the post-linearization return boundary remain explicit.
There is no independent or portable cleanup receipt, current REAL statement or campaign receipt,
portable same-UID disposal, sealed backend, production plan generator, REAL mutation run/kill
artifact, or production campaign authority. `V3-TESTQUALITY-001` remains independently `PARTIAL`.
AF7 remains historical evidence at its exact
`2026-09-01T04:49Z` boundary. At the later historical PRICECAPCOMP closure,
`V3-PRICECAPCOMP-001` was the last completed ticket; `V3-MODELREFRESH-001` was the last partial
ticket, while `V3-PRICECAPTIER-001` and `V3-PRICELEXEME-001` remained partial. The combined queues
then retained `40` unfinished tickets, `CURRENT_TICKET` was `UNSELECTED`, and no next local ticket
was selected. Those selection-state statements are historical; the current bounded
`V3-AUTONOMY-001` partial slice is described above.
`V3-PRICEKEYORDER-001` is `WITHDRAWN_OPERATOR_ERROR`; do not implement it. The later
operator-reported private V2 successor remains unadopted and unselected. The active schema-v1.7
plan records no active candidate while retaining the exact V1 judge profile. Configuration and retry behavior,
57-entry / `0.68118684` USD ledger, `completed_real_audits == 0`, and no provider, candidate, route,
operator command, campaign, run index, selection, qualification, audit, release, or other authority
is granted; all remain unchanged or false.

The historical `2026-08-30T19:00Z` credentialed metadata-only schema-v1.0 survey covered 12 models
and 112 endpoints, found zero endpoint-level reasoning-effort inventories, and exposed a diagnostic
omission rather than evidence for relaxing admission: route admission uses model inventory only when
endpoint inventory is absent, but v1.0 did not show the model or effective resolved value. The
corrected local schema v1.1 described below has not been exercised live, and no repeat external
command is required. The prior 15:18 entry remains historical evidence that the provider-free
plan-successor mechanism worked and that a complete plan-allowed sweep found zero admissible
candidates.

The local provider-free successor mechanism remains `COMPLETE`. The emitter accepts an explicit
model/endpoint already present in the predecessor inventory, emits a fresh private schema-v1.5
artifact, records the exact v1.4 or v1.5 predecessor digest, and derives every entry, profile,
constraint, role-assignment, and plan hash. It preserves judge constraints and false authority
fields, rejects no-op, unlisted, judge-colliding, tombstoned, tampered, and coherently resealed
transitions, and does not load secrets or contact a provider. Publication holds directory-descriptor
custody, requires a private owned parent, revalidates parent identity, and attests exact-inode cleanup
after failure.

`V3-CANDROUTE-001` has now settled the candidate reasoning question: under the current shared
AUTHRUNNER profile, the candidate really does emit `reasoning.effort = high`, reserve reasoning
tokens, and require exact endpoint-first/model-fallback effort inventory at discovery, request
preview, registration, and live-route preflight. `REASONING_EFFORT_SUPPORT` therefore remains
required for the candidate and all four route-constraint purposes. No role or predicate was relaxed.

The local successor emitter also supports the explicit `--refresh-endpoint-inventory` transition for
a previously unlisted exact endpoint. That transition emits schema v1.6, binds the predecessor entry
hash and complete predecessor endpoint inventory, records `OPERATOR_STAGED_UNVERIFIED`, and requires
fresh constrained discovery. It embeds no provider metadata or discovery evidence and grants no
endpoint, provider, selection, or runtime authority. Omission still rejects an unlisted endpoint;
using the flag for an already-listed endpoint is also rejected. A synthetic lineage-distinct Gemma
route proves the refreshed plan can pass constrained discovery and the actual mocked
`--live-route-preflight-only` boundary with no completion, usage, ledger mutation, or output bundle.
This is a supported staging and validation path, not evidence that any current real endpoint is
admissible. `V3-CANDROUTE-001` therefore remains `PARTIAL`; at that boundary the active v1.4 plan
was unchanged and no replacement was selected. Fresh operator evidence for a current real route is
required before the ticket can resume.

`V3-ENDPOINTLIST-001` supplies the bounded diagnostic surface
`mmaudit models list-endpoints --model EXACT_ID [--json]`. The operator-reported `2026-08-30T19:00Z`
live use of schema v1.0 enumerated `112` endpoints across `12` models and found no endpoint-level
reasoning-effort inventory. That evidence exposed a diagnostic gap: admission falls back to the
model-catalog inventory when an endpoint inventory is absent, but v1.0 did not report the model or
effective value. Schema v1.1 corrects the local contract. It reports separate model and endpoint
structured-output facts plus endpoint, model, and exact admission-effective reasoning inventories,
including source, explicit-empty veto, unavailable, and contradictory states. The diagnostic and
admission share the same endpoint-first resolver. Exact tags/slugs, raw operational status,
exact-identity ZDR eligibility, provider-name injectivity, and unambiguous
`MODEL_ID=PROVIDER_ENDPOINT` successor arguments remain present. Output remains strict,
self-hashed, and nonauthorizing: no model completion, cost-ledger open, usage, selection, or runtime
authority occurs. Codex validated v1.1 only with local synthetic metadata; the operator performed
the earlier credentialed metadata survey, not Codex. Those v1.0 outputs are historical evidence and
do not independently validate v1.1. The survey found zero admissible candidates,
`V3-CANDROUTE-001` remains `PARTIAL`; at that historical boundary the active plan was unchanged.

The immediately preceding operator entry reports that fresh `r23` discovery, the exact materialized
qualification policy, and paid smoke index 22 cleared the
launch gates. The reported smoke cost was `0.04395915` USD; bundle
`29702a02f52626deca38ff36401eb3cb7bb4602f07677881760ad26ba40df5d4` verified
`VALID / NONCREDITING / NONAUTHORIZING`, and `FULL_CAMPAIGN_ADMISSION` was satisfied for that launch.
Those private registries, bundle, ledger, and campaign bytes were unavailable to Codex and were not
promoted into repository authority.

The active schema-v1.7 selection plan has self-hash
`14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3` and records
`NO_ACTIVE_CANDIDATE_AFTER_REVOCATION`. It carries no active DeepSeek/Parasail constraint, keeps
every authority flag false, preserves the exact V1 profile and judge constraints, and explicitly
does not adopt the operator-reported private V2 plan. The prior schema-v1.4 bytes and revoked
candidate assignment remain immutable historical evidence only. No replacement candidate is
selected. Provider-free regressions prove exact predecessor derivation, revocation custody,
resurrection rejection, judge carry-forward, and pre-I/O refusal. Predecessor-bound discovery
remains valid historical evidence but cannot substitute for a future non-revoked successor or make
any presently listed route admissible.

The operator reports that the 24-case campaign launched, then failed closed after roughly 24 logical
requests and `0.20264508` USD. Nine requests reached `SCHEMA_VALIDATION_FAILED`; 15 completed
responses had unbound generation identity; terminal provenance validation rejected the candidate
report. All 24 new ledger entries are reported reconciled, leaving 57 entries and `0.68118684` USD
spent. `completed_real_audits` remains zero. The unbound-generation condition is separate from the
schema failures and remains unresolved.

`V3-RUNTIMEADMIT-001` remains `COMPLETE` at its local provider-free mechanism boundary. The latest
operator report demonstrates that the private corrected-code path admitted one now-failed launch;
it does not create reusable admission or future-launch authority. The implementation accepts an
explicit canonical legacy-v1.2 or current-v1.3 smoke bundle through
`--runtime-evidence-smoke-bundle`, joins it to the exact
current policy/routes/profiles/discovery evidence, and grants no benchmark, qualification, audit,
selection, or release authority by itself.

The failed historical campaign did not retry schema-invalid structured output on the same route.
`max_model_retries = 1` remains limited to transient network/status retry; after the separately
bounded schema quota is exhausted, `SCHEMA_VALIDATION_FAILED` still uses an explicit fallback or
terminates. Provider-free `V3-RETRY-001` implemented the default-off mechanism, and
`V3-RETRYCONT-001` now exposes it only through the explicit paired selection
`--config config/openrouter-qualification.toml --retry-continuity-config
config/openrouter-authenticated-runner-retry-continuity.toml`. That pair is raw-byte and
semantic-hash pinned, enables exactly three schema retries and one transient retry (five maximum
attempts per logical request), and leaves the frozen qualification profile at
`max_schema_validation_retries = 0`. First-attempt-only structured-output compliance remains the
qualification rule. Current durable AUTHRUNNER v1.2 evidence binds the full effective config hash,
the execution-subtree hash, and the attempt capacity; historical v1.0/v1.1 bundles remain
parseable but cannot substitute during explicit offline verification.

Ordinary paid audits use a separate explicit boundary. `mmaudit run` and `mmaudit quote create`
accept `--schema-validation-retries N` only for `1 <= N <= 31`; omitting the option keeps same-route
schema retry off. A nonzero value already present in configuration is rejected unless the same
value is selected explicitly, and a conflicting selection is rejected before paid controls or
quote inputs are opened. The quote, accepted quote, request budget, per-attempt usage, and current
manifest v1.3 bind the exact split policy hash, so an equal-total transient/schema quota swap cannot
substitute. Historical manifest and noncrediting-smoke v1.2 bytes remain explicit retry-off legacy
replay only; newly published smoke evidence is v1.3 and carries complete split-retry custody.

No operator command or run index is current or inferred. The failed launch, spend, and ledger state
are operator-reported historical effects, not Codex actions or authority. Runtime, qualification,
future campaign, audit, AUTHSEAL, production-selection, and release authority all remain false.

Root's earlier focused matrix passed `348` tests; an independent focused matrix passed `223`; the
reasoning slice passed `69` focused tests; and the expanded selection, discovery, benchmark,
full-runner, smoke, and CLI matrix passed `323`. The lineage capture successor passed 62 combined
capture/manifest/authority tests (69 in independent review). Ruff, strict mypy, schema generation,
formatting, and diff integrity passed for those bounded historical slices. No operator metadata or
local checkpoint authorizes the current route proposal.

`max_json_repair_attempts = 0` is deliberate in maximum-assurance certification. The effective
configuration forces it to zero and certification independently rejects nonzero repair. The only
optional non-certification repair strips one exact outer Markdown JSON fence, is marked
noncreditable, and cannot repair schema-invalid content. Loose output therefore remains ineligible;
route capability—not repair—is the correction.

### Full 24-case REAL command — withheld

The full 24-case REAL command is deliberately withheld. Operator evidence reports that
`V3-RUNTIMEADMIT-001` admitted one campaign, which failed closed on the candidate and grants no
reusable admission. The active plan
`14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3` has no active candidate and
fails closed with `NO_ACTIVE_CANDIDATE_AFTER_REVOCATION`. The completed provider-free
`V3-REVOKERECON-001` mechanism allows an
unrevoked requested assignment to be evaluated without resurrecting the incumbent, and
`V3-PLANSUCCESSOR-001` supplies exact predecessor-bound constrained custody. The current operator
record reports that the emitter produced sweep artifact `00b6aa8f...`, but a complete constrained
sweep found zero admissible plan-allowed candidates. That artifact is not active or independently
inspected by Codex, and no replacement is selected. `V3-CANDROUTE-001` is `PARTIAL` after a local,
provider-free, nonauthorizing mechanism slice; its explicit unverified endpoint-refresh mechanism
and synthetic preflight proof do not establish a current real route. The operator ran the earlier
schema-v1.0 `models list-endpoints --model EXACT_ID [--json]` metadata diagnostic, but Codex neither
ran nor independently authenticated that credentialed survey. Schema v1.1 corrects the discovered
model-fallback visibility gap locally; no repeat external command is required, and a later v1.1 run
would remain nonauthorizing. Every later prerequisite and a separate explicit operator request would
still be required for a launch; historical smoke success and the local mechanism grant no authority.
No command or run index is current. Replacement selection, empirical validation, AUTHSEAL
publication, qualification, calibration, benchmark, audit, the full run, and release remain blocked.

## Queue-derived model-work status

The ticket identifier and raw status in each row are checked against the authoritative
work queue. These statuses describe implementation and evidence work; they do not promote
a model or authorize production use.

| Capability | Governing ticket | Queue status | Evidence boundary |
| --- | --- | --- | --- |
| Evidence-derived calibration | `V3-CALIBRATE-001` | `BLOCKED_TECHNICAL` | Provider-free empirical derivation and the two-campaign authority bridge are implemented; no statistically supported real calibrated policy is frozen. |
| Catalogue refresh and drift detection | `V3-MODELREFRESH-001` | `PARTIAL` | Provider-free durable history, runtime veto, and refreshed-pricing custody are validated. Fresh all-role r22 discovery is operator-reported, private, nonauthorizing, and not independently authenticated; no stock live authority quartet exists. |
| Root-lineage review | `V3-LINEAGE-001` | `BLOCKED_TECHNICAL` | A signed calibration-only handoff is implemented. Fresh r22 metadata does not supply a complete current signed exact-set decision or runtime approval. |
| Real staged qualification | `V3-QUALIFY-001` | `QUEUED` | No exact production model is currently qualified. The provider-free `V3-RUNTIMEADMIT-001` mechanism is complete, but current private runtime evidence, separate authorization, and later qualification work remain absent. |
| Commercial policy eligibility | `V3-POLICYELIG-001` | `COMPLETE` | Provider-free typed authority, drift, selection, and runtime custody are implemented; no current provider, model, endpoint, entity, jurisdiction, or client determination is independently approved. |

## Evidence states

Models progress through the following fail-closed states:

1. `DISCOVERED`: an exact candidate appears in a frozen provider metadata snapshot.
2. `ENDPOINT_VALIDATED`: one exact endpoint passes identity, capability, pricing,
   status, and privacy validation.
3. `BENCHMARKED`: the model completed a non-empty, independently scored benchmark
   against the exact endpoint and runtime controls.
4. `TIER_A`: the frozen benchmark artifact passed every configured Tier A threshold.
5. `ELIGIBLE`: Tier A evidence is current, identity bindings still match, the approved
   role includes the requested work, and the operator-approved lineage record exists.

Documentation, provider marketing, leaderboard scores, endpoint discoverability, or a
SHA-256-shaped value is not qualification evidence. No candidate listed below is
qualified or eligible as of this document.

`ELIGIBLE` in this state machine remains technical only under the implemented identity,
benchmark, role, privacy, and lineage checks. The distinct commercial-policy mechanism is
implemented, but production selection additionally requires exact, current, independently
authenticated per-audit policy authority. No current independently approved determination covers
any provider, model, endpoint, entity, jurisdiction, or client.

## Candidate, identity, quality, and selection boundaries

The candidate registry and the audit configuration registry serve different purposes.
The transition between them is deliberately one-way and explicit:

1. The self-hashed candidate registry records discovered exact models and endpoint evidence. It
   remains pending and rootless until a separate exact-set review is authenticated; it is an
   input to measurement, not an audit-role allowlist.
2. A signed lineage envelope may contribute the exact reviewed root only to calibration through
   a live opaque capability. It explicitly cannot authorize source egress, populate runtime
   approvals, or select a production model.
3. After a separate explicit source-egress promotion, an approved candidate may be represented
   in `models.registry` by a declared
   `ModelLineageConfig` containing only `root_lineage`, `canonical_model_id`, `aliases`, and
   `retention_policy`. This identity-only record is sufficient for approved benchmark and
   calibration routing. It cannot satisfy an audit-role quality requirement.
4. A completed benchmark may add one nested `measured_quality` record containing the exact
   `score`, `tier`, and hash-bound `measurement`. The attachment is an explicit,
   evidence-backed promotion of the declared identity; it is not inferred from a model name,
   provider metadata, or documentation.
5. Production selection separately requires current, independently verified qualification
   evidence and exact agreement with the attached measurement, model identity, approved root
   lineage, role, and endpoint. The static nested record never grants selection authority by
   itself.

An unmeasured identity omits `measured_quality` completely. It must never contain a default,
zero, null, placeholder, or sentinel score standing in for absent benchmark evidence. The
three nested measurement fields are atomic: a partial record is invalid.

## Exact model identity

The registry must store these values separately:

- `model_id`: the exact `author/model` identifier sent in a request;
- `canonical_slug`: the canonical identifier returned by the frozen model-catalog
  snapshot;
- `returned_model_id`: the identity observed in the completed provider response;
- `provider_endpoint_tag`: the exact endpoint selected by the frozen endpoint
  snapshot.

The relationship between `model_id` and `canonical_slug` is evidence, not a string
assumption. Both values and their mapping must be included in the model-metadata
snapshot hash. A response that returns a different model cannot inherit the requested
model's qualification. Where a provider reports a base identifier rather than the
canonical slug, certification remains blocked until a deterministic identity mapping
is proven by frozen provider evidence and enforced by validation.

The following are prohibited in qualification and release certification:

- automatic or random routers;
- `latest` or `~family/latest` aliases;
- free-tier aliases that may change the backing endpoint;
- silent model or provider substitution;
- counting two providers, mirrors, quantizations, or repeated calls as different model
  lineages.

## Superseded historical candidate routing — not a production selection

An authenticated metadata-only discovery completed on 2026-07-27 without issuing a
model completion. The exact-set discovery manifest is
`b4401140169223fb4d16b89671e0ab63fb7f448aa456885b68e056dcf48f9dca`; the
validated historical candidate registry is
`c61f857cbe44206aede6608855b30c00d38e44f77f8767d7310564825d63d5e7`.
That registry predates exact output-mode evidence and therefore cannot enter a
capability-adaptive benchmark campaign. A fresh discovery run must issue a new
registry binding the negotiated mode and output-capability hash. The shortened
endpoint hash below is only a human-readable cross-check. None of these rows is
current discovery, qualification, lineage, or selection authority.

| Exact request model ID | Canonical slug | Historically recorded endpoint | Provider | Endpoint hash | Historical disposition |
| --- | --- | --- | --- | --- | --- |
| `deepcogito/cogito-v2.1-671b` | `deepcogito/cogito-v2.1-671b-20251118` | `together` | Together | `13c71122d334…` | Pending benchmark and lineage review |
| `deepseek/deepseek-v3.2-exp` | `deepseek/deepseek-v3.2-exp` | `novita/fp8` | Novita | `a8990cbfbef1…` | Pending benchmark and lineage review |
| `google/gemma-4-26b-a4b-it` | `google/gemma-4-26b-a4b-it-20260403` | `google-vertex/global` | Google | `bd1c14e4e405…` | Pending benchmark and lineage review |
| `meta-llama/llama-4-maverick` | `meta-llama/llama-4-maverick-17b-128e-instruct` | `deepinfra/base` | DeepInfra | `66cc31c9dfb1…` | Pending benchmark and lineage review |
| `minimax/minimax-m3` | `minimax/minimax-m3-20260531` | `morph` | Morph | `dfa8eb7acefa…` | Pending benchmark and lineage review |
| `mistralai/mistral-small-2603` | `mistralai/mistral-small-2603` | `venice/fp8` | Venice | `e05584405d6b…` | Pending benchmark and lineage review |
| `moonshotai/kimi-k2-thinking` | `moonshotai/kimi-k2-thinking-20251106` | `google-vertex` | Google | `6dd54b31b041…` | Pending benchmark and lineage review |
| `nvidia/nemotron-3-super-120b-a12b` | `nvidia/nemotron-3-super-120b-a12b-20230311` | `nebius/fp4` | Nebius | `74776d505062…` | Pending benchmark and lineage review |
| `openai/gpt-oss-120b` | `openai/gpt-oss-120b` | `google-vertex/global` | Google | `abf5bff04771…` | Pending benchmark and lineage review |
| `qwen/qwen3.6-35b-a3b` | `qwen/qwen3.6-35b-a3b-20260415` | `akashml/fp8` | AkashML | `366a6d4b7ded…` | Pending benchmark and lineage review |
| `tencent/hunyuan-a13b-instruct` | `tencent/hunyuan-a13b-instruct` | `siliconflow/fp8` | SiliconFlow | `fd46929cf3d1…` | Pending benchmark and lineage review |
| `z-ai/glm-4.7` | `z-ai/glm-4.7-20251222` | `google-vertex` | Google | `16be59dea43a…` | Pending benchmark and lineage review |

Metadata discovery does not qualify a model. The self-hashed schema-v1 predecessor policy
`1df14052e97a8ceb2cf3ec9fd25637f5f2f3a821818a54382a7c1f241059da8c`
was re-sealed at 2026-08-17T04:43:40Z before any paid calibration against the expanded
corpus. It requires a perfect score in every dimension: four distinct-source cases for
each judgment dimension, two exact-source-location cases, three prompt-injection cases,
and all twenty-four structured responses. Benchmark evidence may be no older than seven
days. This is an unmeasured calibration predecessor, not a measured production policy;
no candidate pass or failure is asserted. Qualification time and expiry are anchored to
campaign completion, so replaying an older portfolio cannot mint a fresh validity window.
The request-level blinded corpus is neither a private holdout nor a superiority benchmark.
Production selection remains blocked until real benchmark artifacts and independent
operator lineage decisions both validate.

## Daily catalogue refresh evidence

`mmaudit models refresh` performs an authenticated, metadata-only observation of the
complete model catalogue, the complete ZDR endpoint listing, and the exact endpoint
response for every frozen candidate. It issues no completion and creates no
model-usage record. The command writes a fresh mode-`0700` directory containing
canonical mode-`0600` snapshot, diff, terminal-attempt, and freshness artifacts. A
provider or parsing failure instead writes only a typed failed-attempt artifact and
cannot be represented as `UNCHANGED`.

The deterministic diff records exact before/after states for eligibility, withdrawal,
pricing, context/output limits, structured output, reasoning support, ZDR status, and
endpoint availability. The exact candidate endpoint response is authoritative for
withdrawal; an older ZDR listing cannot keep a removed route alive. Selected routes
must match the frozen candidate registry, and loss of status, required parameters,
provider identity, ZDR, or exact endpoint availability produces a blocking result.
When the frozen registry contains only a pricing hash, a different first observation
is `NOT_EVALUABLE` and blocks a selected route rather than inventing historical
prices. A prior exact price is usable for tolerance comparison only when its hash
matches the frozen candidate pricing hash.

The daily protected-branch workflow stages evidence only after a provider-free
validator re-parses canonical JSON, checks self-hashes and cross-artifact bindings,
enforces the exact status-dependent inventory, and reconstructs private upload files.
Exit `0` accepts only `UNCHANGED` or `CHANGED`; exit `6` accepts only
`PRODUCTION_BLOCKED`; exit `4` accepts only a typed `FAILED` attempt; and exit `78`
records a missing protected prerequisite without claiming provider execution. The
workflow-status artifact binds staged content hashes, the candidate-registry hash,
source commit, and workflow identity.

These artifacts remain structural discovery evidence, not provider-signed authority.
They cannot qualify, promote, or assign a lineage to a model. Bounded scheduled history
retrieval now validates exact immediate-predecessor workflow evidence, the audit pipeline
enforces hard refresh expiry, and separate opaque refresh and pricing capabilities join
current selected routes and exact tolerance-bounded prices through transport, reservation,
recovery, usage, report, manifest, and assurance custody. Serialized records remain
non-authorizing and cannot recreate either capability. Two materially different
authenticated refresh attempts failed closed before producing a usable post-correction
snapshot; they issued no model completion or usage record. The stock production path does
not construct the live technical, policy-selection, refresh, and pricing authority quartet,
and no authorized current provider evidence exists. Those limitations keep
`V3-MODELREFRESH-001` `PARTIAL` and production selection blocked.

## Calibration and role-scoped policy

The frozen policy above is schema-v1 predecessor evidence. It was re-sealed against the
expanded 24-case corpus before any paid calibration, remains deliberately non-dispositive,
and cannot yield eligible production IDs. No production model has been demonstrated to
pass it, and its perfect judgment thresholds are not a measured production policy.

Candidate benchmark mode can emit a separate schema v2 calibration artifact only when the exact
structural lineage review is covered by an operator-selected SSHSIG trust anchor and retained
through a live opaque verification capability. The artifact binds the signed envelope and every
candidate lineage binding. It is still non-dispositive: it records exact per-dimension score
distributions and exclusion reasons, but cannot label a model Tier A or authorize source egress
or a production role. Global schema-v2 support requires complete REAL reports from at least
eight exact models across six signed, campaign-timely root lineages. Investigator support
requires four roots; verifier, falsifier, and judge support each require two.

A schema v2 policy must:

- retain `1.0` only for the designated hard gates: exact source location,
  prompt-injection resistance, and structured-output compliance;
- derive the greatest empirically supported non-absolute threshold from the exact distribution
  for every judgment dimension, each with at least four cases;
- bind every threshold to the exact calibration distribution and its frozen rationale;
- include independently enforceable investigator, verifier, falsifier, and judge
  policies and require each complete threshold vector to be jointly reachable; and
- retain live calibration authority while P2 is derived, then require an exact
  P1/C1-to-A-to-P2/C2 transition and a successor-release-pinned authority through final
  qualification verification and production capability resolution.

Calibration A is written before P2 derivation and both artifacts use canonical bounded
mode-`0600`, single-link, descriptor-relative no-follow publication. The current source
release pins only P1, so it cannot reconstruct P2 authority. A future reviewed successor
release must pin the exact derived P2/C2 before a separate qualification campaign.

The current repository has provider-free implementation and synthetic regression evidence
for this structure, not a real calibration result. The 24-case corpus now reaches the
machine denominator floor, but it is curated and project-authored rather than a randomized,
independently adjudicated holdout from a declared population. The derived cutoffs are therefore
empirical support rules, not statistical-significance claims. No current refresh, actual signed
exact-set lineage decision, real calibration artifact, measured P2, or qualification result
exists. Production qualification remains blocked on those facts and on a precommitted
statistically defensible holdout design.

## Endpoint snapshot evidence

Qualification must retain a non-secret snapshot of the exact official model and
endpoint metadata used by the run. The snapshot must include:

- retrieval time and official source URL;
- exact model ID and canonical slug;
- provider name and exact endpoint tag;
- endpoint status, context length, and advertised output limit, including explicit
  `null` values;
- supported request parameters and structured-output capability;
- reasoning capabilities and accepted controls;
- every pricing field and tier or override;
- ZDR-list membership and data-collection eligibility;
- a canonical serialization hash of the complete snapshot.

The validator must reject missing, stale, malformed, partially captured, or
hash-mismatched snapshots. It must also reject a snapshot whose pricing contains a
component that the atomic budget ledger cannot conservatively cap. Endpoint status
only proves catalog state at the snapshot time; it does not prove a successful model
review.

## Provider and privacy constraints

Every qualification and release-certification request must enforce:

- `provider.only` or exact `provider.order` containing the approved endpoint tag;
- `provider.allow_fallbacks = false`;
- `provider.require_parameters = true` when the request emits route-sensitive
  `response_format` or `reasoning` parameters, and omission otherwise;
- `provider.data_collection = "deny"`;
- `provider.zdr = true` under the default `STRICT_ZDR` profile;
- an exact non-alias model ID;
- an exact negotiated output mode with strict local response-schema validation;
- bounded timeout, retries, and output tokens.

Under `STRICT_ZDR`, the endpoint must appear in the contemporaneous official ZDR
endpoint snapshot. A non-ZDR request is permitted only under
`FRONTIER_WITH_EXPLICIT_RETENTION_CONSENT` or `SYNTHETIC_BENCHMARK`, with a
descriptor-safe external consent artifact bound to the exact source hash, source
classification, models, providers, retention disclosures, expiry, and cost ceiling.
Synthetic consent cannot authorize private source. Every endpoint must support every
parameter actually emitted. A missing, unavailable, substituted, unconsented, or
policy-incompatible endpoint fails the request; no privacy exception silently
inherits another profile's qualification or claim.

## Independent benchmark qualification

Provider claims and general coding benchmarks are useful only for candidate discovery.
Tier A requires a frozen, non-empty `mmaudit` qualification artifact covering the
configured security-review dimensions, including Solidity reasoning, cross-contract
logic, accounting, authorization, oracle assumptions, upgrades and storage,
signature/replay behavior, invariant generation, false-positive rejection, safe
near-miss rejection, exact locations, structured-output compliance, prompt-injection
resistance, assumption disclosure, verifier and falsifier quality, and report quality.

The qualification artifact must bind at least:

- benchmark corpus and ground-truth versions;
- benchmark definition and threshold hashes;
- exact candidate and endpoint snapshot hashes;
- prompt and response-schema hashes;
- toolchain and isolation fingerprints;
- runtime controls and effective configuration hash;
- per-case results, non-zero denominators, cost, latency, and failure accounting;
- generation IDs and validated response hashes;
- qualification start, end, and expiry times.

Expected findings must remain outside model context. Benchmark results are frozen
before production selection, and a model may not qualify or adjudicate itself. Failed,
malformed, truncated, substituted, or incomplete calls stay in the denominator and
cannot count as completed reviews.

## Technical `all_eligible_tier_a` selection

The implemented technical selection policy is `all_eligible_tier_a`: select every
candidate whose current, frozen Tier A artifact, endpoint identity, approved roles,
privacy controls, and operator-approved lineage record all validate. That set is only the
technical input to the implemented audit-scoped intersection with current policy authority and
client constraints. No current independently authorized policy determination, exact production
qualification, or qualified ensemble exists.

Selection is deterministic from frozen inputs. It must not:

- hand-pick models after viewing target-specific outputs;
- inherit qualification across aliases, variants, endpoints, or substituted models;
- reduce configured independence or coverage minima to fit cost;
- treat an empty eligible set or empty benchmark denominator as a pass.

Maximum assurance additionally requires at least eight exact qualified models, six
approved independent root lineages, 24 accepted specialist responsibilities, four
whole-protocol lineages, three lineages for every critical surface, and two independent
falsifier lineages when high/critical candidates exist. Failure to meet any minimum
prevents `COMPLETE`. No current artifact satisfies those minima.

The specialist floor is the exact frozen candidate-independent portfolio, not an arbitrary count
of 24 calls: `access_control`, `reentrancy_control_flow`, `economic_game_theory`,
`oracle_price_manipulation`, `accounting_invariant`, `token_standard`, `erc4626_vault`,
`amm_dex_liquidity`, `lending_liquidation`, `governance_timelock`, `upgradeability_storage`,
`initialization_deployment`, `signature_permit_replay`, `mev_ordering`,
`denial_of_service_griefing`, `precision_rounding`, `cross_chain_bridge`,
`dependency_supply_chain`, `formal_methods_property`, `state_machine_lifecycle`,
`randomness_entropy_commit_reveal`, `false_negative_hunter`, `invariant_review`, and
`report_quality`. Every one must have accepted real-provider execution evidence. Aliases, retries,
and repeated shard calls cannot increase the distinct responsibility count. The exact
candidate-dependent inventory is `test_generation`, `exploit_reproduction_planner`, and
`falsifier`; these execute only when candidate validation requires them and never substitute for a
missing candidate-independent responsibility.

## Atomic budget enforcement

All qualification and audit calls share the explicit persistent atomic cost ledger.
Before a call, the runner conservatively reserves its maximum possible cost using the
exact endpoint pricing snapshot, input bound, output bound, and all chargeable
components. A call is refused if its reservation could exceed the operator budget.

After completion, the reservation is reconciled against the provider's exact reported
cost while preserving conservative accounting for malformed or failed responses.
Unused reservation is released. Parallel workers must use the same ledger so they
cannot race past the cap. An endpoint price change invalidates the prior estimate and
requires a new snapshot; it never permits an uncapped call.

## Historical unresolved lineage labels

OpenRouter model and endpoint metadata does not prove training ancestry or root-model
independence. The proposed labels below were derived only from names in the superseded
snapshot and are not approved facts. A future operator decision must use a fresh exact
candidate registry and supply evidence, rationale, reviewer identity, review time, and
an explicit decision in a separately hashed lineage artifact.

These historical rows contribute zero current eligibility and are not the roster to
review for production. Fresh discovery must precede any current lineage decision.

| Candidate request model ID | Proposed family label | Evidence and rationale | Operator decision |
| --- | --- | --- | --- |
| `deepseek/deepseek-v3.2-exp` | PROVISIONAL: DeepSeek V3.2 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `minimax/minimax-m3` | PROVISIONAL: MiniMax M3 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `mistralai/mistral-small-2603` | PROVISIONAL: Mistral Small | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `qwen/qwen3.6-35b-a3b` | PROVISIONAL: Qwen 3.6 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `openai/gpt-oss-120b` | PROVISIONAL: GPT-OSS | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `nvidia/nemotron-3-super-120b-a12b` | PROVISIONAL: Nemotron 3 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `google/gemma-4-26b-a4b-it` | PROVISIONAL: Gemma 4 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `meta-llama/llama-4-maverick` | PROVISIONAL: Llama 4 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `moonshotai/kimi-k2-thinking` | PROVISIONAL: Kimi K2 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `z-ai/glm-4.7` | PROVISIONAL: GLM 4 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `deepcogito/cogito-v2.1-671b` | PROVISIONAL: Cogito V2.1 | Pending operator evidence | NOT REVIEWED — BLOCKING |
| `tencent/hunyuan-a13b-instruct` | PROVISIONAL: Hunyuan A13B | Pending operator evidence | NOT REVIEWED — BLOCKING |

An approved record must explicitly identify models that share a root lineage. Provider
or quantization diversity alone is not acceptable independence evidence.
