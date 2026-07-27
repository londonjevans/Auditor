# Model Selection and Qualification

This document defines how `mmaudit` may move a model from discovery into a
maximum-assurance ensemble. It is a selection policy, not evidence that any model is
qualified.

The provider and model metadata referenced here is time-bound to **2026-07-27**.
Availability, pricing, capabilities, privacy policy, endpoint identity, and routing
behavior can change. A later qualification or release-certification run must use its
own frozen metadata snapshots.

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

## Frozen candidate routing

An authenticated metadata-only discovery completed on 2026-07-27 without issuing a
model completion. The exact-set discovery manifest is
`b4401140169223fb4d16b89671e0ab63fb7f448aa456885b68e056dcf48f9dca`; the
validated candidate registry is
`c61f857cbe44206aede6608855b30c00d38e44f77f8767d7310564825d63d5e7`.
Those hashes bind the complete metadata snapshots; the shortened endpoint hash below
is only a human-readable cross-check.

| Exact request model ID | Canonical slug | Approved endpoint | Provider | Endpoint hash | Qualification |
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

Metadata discovery does not qualify a model. The self-hashed Tier A policy
`d286d1c5f9ed4a5a4c7c62eda7a55e9a1e23e972f21ffe64530ca34ed780224e`
was frozen before paid benchmark execution. It requires a perfect score in every
dimension, at least two disjoint cases for every semantic dimension, three
prompt-injection cases, and all sixteen structured responses. This is
request-level blinded qualification evidence, not a private holdout or a
superiority benchmark. Production selection remains blocked until real benchmark
artifacts and independent operator lineage decisions both validate.

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
- `provider.require_parameters = true`;
- `provider.data_collection = "deny"`;
- `provider.zdr = true`;
- an exact non-alias model ID;
- a complete structured-output schema;
- bounded timeout, retries, and output tokens.

The endpoint must appear in the contemporaneous official ZDR endpoint snapshot and
must support every parameter actually emitted. A missing, unavailable, substituted,
or policy-incompatible endpoint fails the request. An operator-approved privacy
exception, if one is ever permitted, must be a separate, explicit, time-bounded
artifact; it does not silently preserve maximum-assurance eligibility.

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

## `all_eligible_tier_a` selection

The production policy is `all_eligible_tier_a`: select every candidate whose current,
frozen Tier A artifact, endpoint identity, approved roles, privacy controls, and
operator-approved lineage record all validate.

Selection is deterministic from frozen inputs. It must not:

- hand-pick models after viewing target-specific outputs;
- inherit qualification across aliases, variants, endpoints, or substituted models;
- reduce configured independence or coverage minima to fit cost;
- treat an empty eligible set or empty benchmark denominator as a pass.

Maximum assurance additionally requires the configured minimum exact models, approved
independent root lineages, specialist responsibilities, whole-protocol reviews,
per-critical-surface reviews, and independent falsifier lineages. Failure to meet any
minimum prevents `COMPLETE`.

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

## Blocking operator lineage review

OpenRouter model and endpoint metadata does not prove training ancestry or root-model
independence. The proposed labels below are derived only from candidate naming and are
not approved facts. The operator must supply evidence, rationale, reviewer identity,
review time, and an explicit decision in a separately hashed lineage artifact.

Until that review is complete, every row is a blocking prerequisite and contributes
zero approved independent lineages.

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
