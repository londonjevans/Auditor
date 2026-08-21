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
`NONAUTHORIZING` replacement seed for the obsolete roster. Its plan SHA-256 is
`8899739a0a4a36bacacb17592df8263f57f94c65b96a63b69ab61ab67e455761`. It binds the exact bytes of the
operator-staged `model-ranking.py` and `V3-LINEAGE-001-operator-review.md`, but it does not
claim that the ranker ran, that any proposed ID or route currently exists, that an advisory
lineage label is correct, or that any model is qualified. Its endpoint lists are policy
constraints only. Every discovery, lineage, qualification, runner, benchmark, seal, and
release authority field is literally false.

The proposed AUTHRUNNER roles are also only planning data: DeepSeek V4 candidate, MiniMax M3
primary judge, and Kimi K3 replay judge. The current documentary public-lineage manifest now has
`CONFIRMED` exact-ID decisions for all three and independently replays their pairwise-distinct
DeepSeek, MiniMax, and Moonshot roots. This proves only documentary identity/root separation; it
does not qualify a model or authorize a runner, provider call, benchmark, seal, audit, or release.

The operator ran the three singleton metadata-only commands. DeepSeek succeeded on `novita/fp8`
with operator-reported frozen-registry SHA-256
`59dfdaf498cc2a8201351a7c6aacdfc2a3fd7f6daec09aa927202071ee7a0619`. Qwen 3.8 Max failed
closed because its exact model was absent from the ZDR endpoint snapshot, so it cannot serve as
the primary judge under `require_zdr = true`; the operator reports the same ZDR absence for Meta
Muse Spark 1.2. Kimi's `deepinfra/bf16` route was non-operational;
the explicit `together` retry succeeded with operator-reported frozen-registry SHA-256
`14937842d2a544540efa39199b2b0ed4c0f25e1f145f1385f32d43b728edbdea`. No completion was
requested, and the operator reports that the ledger remains untouched at `$0`. These statements
record operator-reported results only; the private artifacts and ledger were not read or promoted
by Codex. The exact operator-supplied log is retained at
[`operator_results.md`](../remediation/v3/operator_results.md), raw SHA-256
`3c8fc79c24615fae4f80dbbed6c86a9ddbb4b61cd0b1441ac83d2b020a1b60fd`, and is
`OPERATOR_SUPPLIED_UNVERIFIED`: it grants no repository authority.

The subsequent Claude Opus 5 `amazon-bedrock` PRIMARY r3 attempt also failed closed before registry
publication. Although the tag matched, the endpoint's `provider_name` was duplicated elsewhere in
the exact-model inventory. The whole-inventory uniqueness rule is retained: generation metadata
does not always expose an endpoint tag, so accepting a duplicated display identity could import ZDR,
pricing, or capability evidence from an unapproved sibling route. Under the current validator no
reported Claude ZDR route can satisfy this invariant; route substitution alone cannot repair r3.
No completion was requested and the operator reports no ledger spend.

The replacement PRIMARY r4 `minimax/minimax-m3=coreweave/fp4` metadata discovery succeeded. The
operator reports frozen registry SHA-256
`eaed67e745d448299e3aa5d58b406de065fae09813b3c6ff1c646403ca8023a1`, discovery manifest
SHA-256 `3921c5682bedf1f938236a5268fcf6d5a9138d1646726df00147705cba0b8969`, no completion, and no
ledger spend. Of the technically discoverable replacements, MiniMax M3 is the only exact ID already
`CONFIRMED` by the compiled public-lineage manifest. The plan restricts each selected role to one
route: DeepSeek to successful `novita/fp8`, MiniMax to successful `coreweave/fp4`, and Kimi to
successful `together`. All three registries now exist, remain rootless/role-empty/`PENDING`, and are
nonauthorizing. Do not rerun or overwrite any discovery path.

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
K2/K3 variants from being credited as independent roots. The active DeepSeek V4, MiniMax M3, and
Kimi K3 triple replays pairwise independent. Verification is anchored at
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
`fd1459b519ea0ce28a2d123ddeb57653dd2f7918` (`Bound OpenRouter prompt-cache pricing`). Run the
following unchanged provider-free command only after that checkpoint and this documentation-only
reconciliation are pushed and verified on `origin/agent/v3-wip-checkpoint`. On those committed
runtime bytes, the implementation must emit two distinct, exact 24-request candidate-plan hashes
and their retry-inclusive derived caps. Judge admission must remain
`PENDING_REAL_CANDIDATE_OUTPUTS`, and the full campaign cost must remain unavailable, because exact
judge prompts require genuine candidate outputs. The locally verified preflight contract returns
before secret selection, provider access, ledger mutation, or durable output publication; transient
private write probes are created and removed during fail-closed path preflight. The three `$1.00`
values remain only additional operator tripwires and are not pricing evidence or substitutes for the
derived request bounds.

```shell
env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE MMAUDIT_BUDGET_USD=250 MMAUDIT_COST_LEDGER_PATH="$HOME/.mmaudit/private/openrouter-cost-ledger.json" .venv/bin/mmaudit models authenticated-runner --candidate-registry "$HOME/.mmaudit/private/authrunner/candidate-registry-r2.json" --candidate-discovery-run "$HOME/.mmaudit/private/model-discovery/authrunner-candidate-20260820-r2" --primary-judge-registry "$HOME/.mmaudit/private/authrunner/primary-judge-registry-r4.json" --primary-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/authrunner-primary-judge-20260821-r4" --replay-judge-registry "$HOME/.mmaudit/private/authrunner/replay-judge-registry-r2.json" --replay-judge-discovery-run "$HOME/.mmaudit/private/model-discovery/authrunner-replay-judge-20260820-r2" --qualification-policy config/models.maximum-assurance.toml --primary-campaign-journal "$HOME/.mmaudit/private/authrunner/primary-campaign-20260821-r4" --primary-portfolio "$HOME/.mmaudit/private/authrunner/primary-portfolio-20260821-r4" --replay-campaign-journal "$HOME/.mmaudit/private/authrunner/replay-campaign-20260821-r4" --replay-portfolio "$HOME/.mmaudit/private/authrunner/replay-portfolio-20260821-r4" --output "$HOME/.mmaudit/private/authrunner/authenticated-runner-evidence-20260821-r4.json" --candidate-cost-cap-usd-per-attempt 1.00 --primary-judge-cost-cap-usd-per-attempt 1.00 --replay-judge-cost-cap-usd-per-attempt 1.00 --config config/openrouter-qualification.toml --corpus benchmarks/model_corpus/manifest.json --ground-truth-provenance benchmarks/model_corpus/provenance.json --cost-ledger "$HOME/.mmaudit/private/openrouter-cost-ledger.json" --allow-code-egress --preflight-only --no-color
```

This post-fix committed-byte rerun is pending and will validate only the current campaign contract; it grants
no runner, qualification, provider-call, AUTHSEAL, benchmark, audit, or release authority. Exact
candidate caps are derived provider-free. In any separately authorized live process, both candidate
runs must complete first; then both judge routes must be refreshed, both exact judge plans derived,
and their aggregate remaining cost admitted before the first judge POST. The operator's cost
estimates and statement that no known gate remains are advisory evidence, not authority. Any later
live command requires a separate operator action, exact fresh path custody, and a new provider-free
preflight if its inputs or destinations change.

## Queue-derived model-work status

The ticket identifier and raw status in each row are checked against the authoritative
work queue. These statuses describe implementation and evidence work; they do not promote
a model or authorize production use.

| Capability | Governing ticket | Queue status | Evidence boundary |
| --- | --- | --- | --- |
| Evidence-derived calibration | `V3-CALIBRATE-001` | `BLOCKED_TECHNICAL` | Provider-free empirical derivation and the two-campaign authority bridge are implemented; no statistically supported real calibrated policy is frozen. |
| Catalogue refresh and drift detection | `V3-MODELREFRESH-001` | `PARTIAL` | Provider-free durable history, runtime veto, and refreshed-pricing custody are validated; no successful current provider snapshot or stock live authority quartet exists. |
| Root-lineage review | `V3-LINEAGE-001` | `BLOCKED_TECHNICAL` | A signed calibration-only handoff is implemented; no current refresh, signed operator decision, or runtime approval exists. |
| Real staged qualification | `V3-QUALIFY-001` | `QUEUED` | No exact production model is currently qualified. |
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
