# Operator execution results — metadata-only discovery

Results of operator-run credentialed commands. Codex: read this file before stopping a turn that
requested an operator command. Written by the monitoring session; treat as operator-supplied evidence.

## 2026-08-21T11:42Z — BOTH r5 prerequisites RUN AND PASSED

Both commands listed in the operator guide after `9075ca7` were executed verbatim. Both exit 0.
Cost ledger unchanged — **$0 spent**, no model completion requested.

### 1. Lineage capture — 16 sources (was 15), Tencent Hy3 included

```
.venv/bin/python scripts/capture_public_model_lineage.py \
  --output-dir /private/tmp/mmaudit-public-lineage-20260821-r2
```

```
observation_set_sha256: 6ae6e75a1732c05b85ffe189febbc3ecfa8ae2eeeb83000a8a24d30035b966eb
bundle_sha256:          7b6ff67506bceaaf05c944edb2c28bf6d8386df3690444b827035ed5c83bc134
```

| source | size | sha256 | immutable_revision | publisher_id | redirects |
|---|---|---|---|---|---|
| `sources/tencent-hy3-card.md` | 10325 | `dbdfc5920bf548fb484b5ec1837032f6c85e1886f2930aa5bee629c1f9620e8b` | `a960ebc3da325ba167f069f76c41eb62c9280d22` | `tencent` | 2 |

These bytes are identical to the earlier independent pre-fetch recorded below — third consecutive
capture where a separate retrieval reproduced the same sha256 against a pinned revision.

### 2. PRIMARY r5 discovery — `tencent/hy3=tencent/fp8` — SUCCESS

```
output-dir: $HOME/.mmaudit/private/model-discovery/authrunner-primary-judge-20260821-r5
run:        85ff0c1b872241e7aa48b2f2f77ccc84
manifest:   fe3e3daa21eeb370f35558c5eca5746c140f2b92e88a37233952ab77034dc07b
registry:   $HOME/.mmaudit/private/authrunner/primary-judge-registry-r5.json
frozen:     2d825234bfc1cf05fb9ec883c555bc007bd3a6033145507d629d5da7aa5619ad
```

Stale discovery fields were not copied. The r2 candidate and r2 replay pairs were not rerun or
overwritten, per the guide's instruction.

### Reasoning capability confirmed present — the gap that disqualified MiniMax

Sealed r5 evidence for `tencent/hy3`:

```
reasoning_parameter_support     = supported
reasoning_mandatory             = False
reasoning_default_enabled       = True
reasoning_supports_max_tokens   = None
supported_reasoning_efforts     = None          (endpoint-level; empty for all OpenRouter routes)
model_supported_reasoning_efforts = ['none', 'low', 'high']
max_output_tokens               = 128000
```

The new config `effort = "high"` is present in the catalog inventory, and `reserved_tokens = 4096`
fits well inside `max_output_tokens = 128000`. All three roles carry `high`: candidate
`['low','high','max']`, primary `['none','low','high']`, replay `['low','high','max']`. Validation
depends on the catalog-fallback path added in `9075ca7`, since the endpoint-level inventory is `None`
for every OpenRouter route.

**Remaining before preflight:** claim-span binding, root decision, and manifest reseal over the 16-source
capture. The preflight command is not currently emitted as a runnable line in the operator guide (the
section is now a planned-artifact table) — re-emit it for the r2/r5/r2 composition and it will be run.

## 2026-08-21T10:55Z — Lineage prerequisites for BOTH replacement candidates (pre-fetched)

Whichever primary judge is chosen, it needs a new lineage capture: **neither is in the sealed bundle.**
Confirmed IDs currently are `deepseek/deepseek-v4-pro-0813`, `minimax/minimax-m3`, `moonshotai/kimi-k3`
plus the seven older entries — `tencent/hy3` and `z-ai/glm-5.2` are both **absent**.

Both have public first-party HuggingFace cards, verified reachable and ungated. Add whichever is
selected to `scripts/capture_public_model_lineage.py` and I will re-run the capture.

| OpenRouter ID | HF repo | immutable revision | bytes | sha256 |
|---|---|---|---|---|
| `tencent/hy3` | `tencent/Hy3` | `a960ebc3da325ba167f069f76c41eb62c9280d22` | 10325 | `dbdfc5920bf548fb484b5ec1837032f6c85e1886f2930aa5bee629c1f9620e8b` |
| `z-ai/glm-5.2` | `zai-org/GLM-5.2` | `b4734de4facf877f85769a911abafc5283eab3d9` | 10905 | `ed5aca8ce3dc5f8de626c87e488444343e43b1dcbdeb0e643dc72fea63ab06e8` |

Suggested `independence_key` / `publisher_id`: `tencent` and `zai-org`, matching existing convention.
Note `tencent/Hy3` is case-sensitive on HuggingFace (`HY3` and `Hunyuan-3` do not resolve).

Decisive claim spans located in each:

- **`tencent/Hy3`**, line 63: *"**Hy3** is a 295B-parameter Mixture-of-Experts (MoE) model with 21B
  active parameters and 3.8B MTP layer parameters, developed by the Tencent Hy Team. Following the Hy3
  Preview launch..."*
- **`zai-org/GLM-5.2`**, line 32: *"We're introducing GLM-5.2, our latest flagship model for
  long-horizon tasks. It marks a substantial leap in long-horizon task capability over its predecessor
  GLM-5.1..."*

Both cite a predecessor within their own publisher — the same shape as DeepSeek V4-Pro citing V4-Pro
Preview, which sealed successfully.

Recommendation unchanged: **`tencent/hy3` on `tencent/fp8`**, keeping three distinct serving providers
(Novita / Tencent / Together). `z-ai/glm-5.2` is an equally valid fallback but its operational ZDR set
overlaps `together`, so avoid `together` for that role if it is chosen.

## 2026-08-21T10:50Z — PREFLIGHT after `fd1459b` — cache gate CLEARED; fails later on reasoning capability

Cache-pricing fix works: the run now reaches cost-plan derivation. New failure:

```
mmaudit failed safely: runner candidate request costs cannot be derived from frozen launch evidence
```

`authenticated_runner_execution.py:1018-1022` catches `(TypeError, ValueError)` and re-raises
`from None`, discarding the cause. Surfaced by wrapping `_candidate_staged_cost_plan` externally (no
repo source modified). **Real underlying error:**

```
mmaudit.models.endpoint_snapshots.EndpointSnapshotValidationError: max-token reasoning lacks exact frozen support
  endpoint_snapshots.py:400  <- require_compatible_profile
  openrouter.py:3581         <- preview_openrouter_structured_request_cost
  authenticated_runner_execution.py:316
```

Suggest dropping the `from None` here — it hid a completely unrelated root cause behind a cost message.

Ledger unchanged — **$0 spent**.

### Finding 1 (bug): `effort` reasoning mode cannot validate for ANY OpenRouter model

`config/openrouter-qualification.toml:51-53` requests max-token mode:

```toml
[models.reasoning]
max_tokens = 4096
```

`supports_max_tokens` is advertised by only **10 of 419** catalogue models. None of the triple has it.
So max-token mode is near-unusable by design — but `effort` mode cannot substitute, because of a
field-sourcing asymmetry:

- `discovery.py:768` `reasoning_default_enabled` <- **catalog** `reasoning.default_enabled`
- `discovery.py:769` `reasoning_supports_max_tokens` <- **catalog** `reasoning.supports_max_tokens`
- `discovery.py:785` `model_supported_reasoning_efforts` <- **catalog** `reasoning.supported_efforts`
- but `require_compatible_profile` (`endpoint_snapshots.py:389`) checks
  `self.supported_reasoning_efforts` — the **endpoint-level** field.

Sampled 204 endpoints across 60 models: **0 populated, 204 empty**. OpenRouter never fills the
endpoint-level `reasoning` block, so `supported_reasoning_efforts` is always `None` and effort mode can
never validate. The catalog inventory is captured but never consulted at profile-check time.

Suggested fix: have `require_compatible_profile` fall back to the model-level effort inventory when the
endpoint-level one is absent — consistent with how `default_enabled` and `supports_max_tokens` are
already sourced from the catalog.

### Finding 2 (selection): `minimax/minimax-m3` is unusable and must be replaced

Sealed reasoning evidence per role:

| role | model | param_support | default_enabled | supports_max_tokens | endpoint efforts | model efforts |
|---|---|---|---|---|---|---|
| candidate | `deepseek-v4-pro-0813` | supported | None | None | None | `[low,high,max]` |
| primary | `minimax-m3` | supported | **None** | None | None | **None** |
| replay | `kimi-k3` | supported | True | None | None | `[low,high,max]` |

Mode viability today: `max_tokens` fails on all three; `effort` fails on all three (Finding 1);
`default` requires non-None `default_enabled`, so only `kimi-k3` passes; `disabled` requires
`default_enabled is False`, so none pass.

`minimax/minimax-m3` carries **no reasoning metadata at all** — no effort inventory and no
default-enabled state. It has **no viable mode under any of the four**, and no code fix changes that.
It must be replaced as primary judge.

Note `deepseek-v4-pro-0813` also has `default_enabled = None`, so the candidate depends on the
Finding 1 fix; it is fine under effort mode once that lands, and needs no replacement.

### Corrected primary-judge shortlist — now filtered on reasoning too

My earlier shortlist filtered on ZDR, operational status, display-name uniqueness, and lineage, but
**not** on reasoning capability. That omission is why `minimax-m3` was selected and then failed here.
Re-filtered:

| model | lineage | efforts | default_enabled | viable modes |
|---|---|---|---|---|
| `tencent/hy3` | Tencent | `[high,low,none]` | True | effort (after fix), default |
| `z-ai/glm-5.2` | Zhipu | `[xhigh,high]` | True | effort (after fix), default |
| `minimax/minimax-m3` | MiniMax | none | None | **NONE** |

Both survivors also passed the earlier four constraints. **Recommend `tencent/hy3` on `tencent/fp8`** —
own infrastructure, so the three roles keep three distinct serving providers (Novita / Tencent /
Together) and three distinct lineages.

Also worth noting: `anthropic/claude-opus-5`, `openai/gpt-5.6-sol`, `google/gemini-3.7-flash`, and
`x-ai/grok-4.6` all have full reasoning metadata (`default_enabled=True` plus effort inventories). They
remain excluded only by the display-name uniqueness rule flagged earlier — reinforcing that this rule
deserves an explicit decision, since it is now excluding the models with the best capability metadata.

**Advisory analysis, not evidence.** All rule changes, selection decisions, and resealing are codex's.

## 2026-08-21T08:33Z — PREFLIGHT after `f6acf20` — FAILED on unenforceable variable pricing

```
mmaudit failed safely: variable endpoint pricing component cannot be provider-capped
```

Raised by `_routing_max_price` at `src/mmaudit/models/openrouter.py:13671`. Ledger unchanged — **$0**.

This is a real catch by the new cost binding, not a regression. But it blocks **all three** roles.

`_UNENFORCEABLE_VARIABLE_PRICING_FIELDS` (`openrouter.py:353`) = `input_cache_read`,
`input_cache_write`, `internal_reasoning`. `_ROUTER_MAX_PRICE_FIELDS` (`openrouter.py:343`) =
`completion`, `image`, `prompt`, `request`. OpenRouter's provider-side max-price routing cannot
express a ceiling for cache pricing, so any nonzero unenforceable component defeats the guarantee.

Retained (sealed) pricing in the three discovery runs — every route has nonzero `input_cache_read`:

| role | prompt | completion | input_cache_read | cache_read vs prompt |
|---|---|---|---|---|
| candidate `deepseek-v4-pro-0813` | 0.00000132 | 0.00000396 | 0.000000132 | **10x cheaper** |
| primary judge `minimax-m3` | 0.00000023 | 0.00000096 | 0.00000005 | **4.6x cheaper** |
| replay judge `kimi-k3` | 0.000003 | 0.000015 | 0.0000003 | **10x cheaper** |

None of the three declares `input_cache_write` or `internal_reasoning`.

### Suggested narrow fix — a bound, not a bypass

Rejecting every nonzero `input_cache_read` is stricter than the guarantee requires. Cache-read applies
to *input* tokens, and on all three routes it is strictly **cheaper** than the `prompt` rate. So
charging every input token at the enforceable `prompt` ceiling is already a valid upper bound on actual
input cost — the provider-side prompt cap bounds the cache-read case a fortiori.

Proposed rule: permit an unenforceable field when its price is **less than or equal to** the
corresponding enforceable ceiling (`input_cache_read <= prompt`), and continue to reject outright when
absent-or-zero cannot be shown for fields that may *exceed* the enforceable ceiling — notably
`input_cache_write`, which on some providers costs more than fresh prompt, and `internal_reasoning`,
which is not bounded by any input ceiling at all.

That keeps the safety property (no unbounded provider-side spend) while not excluding routes whose
variable component is provably dominated. If codex prefers to stay maximally conservative and reject
all cache pricing, that is defensible — but it currently excludes all three selected models and, given
that cache pricing is near-universal on OpenRouter, would likely exclude most viable routes. Either
way the choice should be explicit.

**This is advisory analysis, not evidence.** The rule change, its proof obligation, and any resealing
are codex's to decide and implement.

## 2026-08-21T05:47Z — AUTHRUNNER PREFLIGHT — **VALID**

First end-to-end validation of the campaign contract. Run after reseal `83bad61`; all three triple
members now CONFIRMED in the lineage bundle (15 sources, 9 roots, `verified_at 2026-08-21T05:26:00Z`).

```
AUTHRUNNER preflight: VALID / NONAUTHORIZING / NO PROVIDER EGRESS
Inventory: runs=2; cases=24; candidate_logical_requests=48; judge_logical_requests=48;
           logical_requests=96
Attempts:  maximum_per_logical_request=2; maximum_provider_attempts=192; generation_refetches=96
Cost tripwire: initial_spent_usd=0; declared_interval_cap_usd=192.00;
               declared_final_spent_cap_usd=192.00
Effective config SHA-256: f0ff2d76017dfcd075c6758f0da7256c98dd45ca749a42b81ca1ce8c95a93f9e
```

Cost ledger unchanged — **$0 spent**. No known gate remains before a REAL launch.

### Cost analysis for the REAL run — the $1.00/attempt caps are placeholders and inflate the ceiling ~25x

Live per-token pricing on the exact pinned routes (USD per 1M tokens):

| role | model | route | prompt | completion |
|---|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813` | `novita/fp8` | $1.32 | $3.96 |
| primary judge | `minimax/minimax-m3` | `coreweave/fp4` | $0.23 | $0.96 |
| replay judge | `moonshotai/kimi-k3` | `together` | **$3.00** | **$15.00** |

Estimated actual campaign cost over 96 logical requests:

| per-request size | single attempt | if every request retries |
|---|---|---|
| 4k prompt + 1k completion | ~$1.14 | ~$2.27 |
| 10k prompt + 2k completion | ~$2.56 | ~$5.11 |
| 30k prompt + 6k completion | ~$7.67 | ~$15.33 |

The declared $192.00 tripwire is 192 attempts x the placeholder $1.00/attempt cap. Realistic spend is
**single-digit to low-double-digit dollars**. Deriving per-attempt caps from the retained pricing
evidence (as already queued) would tighten the tripwire from $192 to something proportionate and make
it an effective runaway guard rather than a nominal one.

Note `moonshotai/kimi-k3` on `together` is by far the most expensive leg — $15.00/1M completion tokens,
roughly 4x the candidate and 15x the primary judge. It is the replay judge, so its volume is half the
candidate's, but a per-attempt cap derived uniformly across roles would be badly calibrated for it.

## 2026-08-21T05:25Z — LINEAGE CAPTURE — SUCCESS, one coherent 15-source bundle

```
.venv/bin/python scripts/capture_public_model_lineage.py \
  --output-dir /private/tmp/mmaudit-public-lineage-20260821-r1
```

Exit 0. 15 sources captured in a single coherent run, including both previously missing cards.
No credentials involved; first-party publisher endpoints only; **$0 spent**.

```
output-dir:             /private/tmp/mmaudit-public-lineage-20260821-r1
observation_set_sha256: 848b1dfda5b60c6793089ed3916073d86e3a734da9dbc5a824302bec7f4b37da
bundle_sha256:          d9e46cb7c29792ab3d9b2d696bdb889a20f79338d72d628d267bb3705576f8f5
```

Complete HTTP capture observations for the two additions — the metadata the hand-staged bytes lacked:

| source | size | sha256 | immutable_revision | publisher_id / independence_key | media_type | redirects |
|---|---|---|---|---|---|---|
| `sources/deepseek-deepseek-v4-pro-0813-card.md` | 7522 | `61755d88e95789fcd7a36f50892f97bba977a30fc99d0f2907ab787ed10b0e66` | `72e1d3230f6c080a530b0a1d46f8eb4602340597` | `deepseek-ai` | `text/plain` | 2 |
| `sources/moonshot-kimi-k3-card.md` | 45261 | `57de265b5842dfa465c6e73b368b0e15a89b8793b5450528dad577da202cc6fe` | `a590ce090cb049c93a33dfe8c208ec652aa20503` | `moonshot-ai` | `text/plain` | 2 |

**Independent reproducibility check:** these sha256 values are byte-identical to the separate manual
fetch recorded further down this file, performed hours earlier against the same pinned revisions. Two
independent retrievals produced identical bytes, corroborating that the pinned revisions are immutable
as claimed. The hand-staged copies in `docs/remediation/v3/operator_captures/` are now redundant and
can be deleted once the reseal lands.

The lineage decision, claim-span binding, root assignment, and manifest reseal remain codex's to
perform. This entry records a capture, not an authority.

## 2026-08-21T05:00Z — PREFLIGHT (codex's exact emitted command, line 85 of the operator guide) — FAILED at the lineage gate, as predicted

```
mmaudit failed safely: runner public lineage does not prove three distinct roots
```

Ran verbatim with `env -u OPENROUTER_API_KEY -u MMAUDIT_SECRETS_ENV_FILE`, `--preflight-only`,
per-attempt caps 1.00/1.00/1.00, `--allow-code-egress`. Cost ledger unchanged — **$0 spent**.

All other inputs validated: the three registries, all three discovery runs, the maximum-assurance
qualification policy, the corpus manifest, and the ground-truth provenance were accepted. **Documentary
lineage is the sole remaining failure.**

NOTE FOR CODEX: you recorded this file at sha256 `961a0e9d…9104a` before responding, which was prior
to the lineage-capture section below being written. Current sha256 is
`9db31a83d28fb901fa31b5376ed834521621e837de79bcb9c5939987e7159572`. **Re-read from here down** — the
two missing publisher model cards are already fetched and staged in
`docs/remediation/v3/operator_captures/`.

## 2026-08-21T04:45Z — PREFLIGHT r2/r4/r2 — FAILED at the lineage gate

```
mmaudit failed safely: runner public lineage does not prove three distinct roots
```

Registry validation passed; all three registries were accepted. The blocker is
`authenticated_runner_execution.py:722`. Cost ledger still empty — **$0 spent**.

### Cause: the lineage bundle is stale in the same way the registry was

`config/public_model_lineage/manifest.json` (`evidence_standard DOCUMENTARY_EXACT_BYTES_V1`,
`verified_at 2026-08-18`, `valid_until 2027-02-14`) covers the previous model generation:

| triple role | model | in bundle? |
|---|---|---|
| primary judge | `minimax/minimax-m3` | **CONFIRMED**, root `sha256:e251821340d79fe40fba647e729f9dd8feea7b988efad1a61936bf62b3b38161` |
| candidate | `deepseek/deepseek-v4-pro-0813` | **ABSENT** — bundle holds `deepseek/deepseek-v3.2-exp` |
| replay judge | `moonshotai/kimi-k3` | **ABSENT** — bundle holds `moonshotai/kimi-k2-thinking` |

Two of three need fresh documentary capture. `minimax/minimax-m3` needs nothing.

### Operator-staged captures — publisher model cards, immutable-revision pinned

Fetched from the primary publisher over HTTPS, matching the existing capture method
(HuggingFace README at a pinned commit, keyed by publisher org). Raw bytes staged in
`docs/remediation/v3/operator_captures/`. **Unverified operator-supplied evidence — not a bundle
entry, not an authority claim.** Codex must do the claim extraction, byte-range binding, root
decision, and resealing.

| file | source repo | immutable revision | bytes | sha256 |
|---|---|---|---|---|
| `operator_captures/deepseek-v4-pro-0813-card.md` | `deepseek-ai/DeepSeek-V4-Pro-0813` | `72e1d3230f6c080a530b0a1d46f8eb4602340597` | 7522 | `61755d88e95789fcd7a36f50892f97bba977a30fc99d0f2907ab787ed10b0e66` |
| `operator_captures/moonshot-kimi-k3-card.md` | `moonshotai/Kimi-K3` | `a590ce090cb049c93a33dfe8c208ec652aa20503` | 45261 | `57de265b5842dfa465c6e73b368b0e15a89b8793b5450528dad577da202cc6fe` |

Resolve URL form used by existing sources:
`https://huggingface.co/<repo>/resolve/<revision>/README.md`. Both repos are ungated (`gated: false`).
Suggested `independence_key` values matching existing convention: `deepseek-ai`, `moonshot-ai`.

Lineage-bearing text located in each capture:

- **DeepSeek-V4-Pro-0813**, line 43: *"is the official release of DeepSeek-V4-Pro, superseding the
  preview version... It is built on the DeepSeek-V4-Pro (Preview) model structure, with a DSpark
  speculative decoding module attached."* Note this cites a predecessor within the same publisher; a
  base/post-train pair capture may be wanted, as done for Nemotron. The preview repo
  `deepseek-ai/DeepSeek-V4-Pro` exists at sha `b5968e9190ef611bbf34a7229255be88a0e937c1`
  (lastModified 2026-06-22) if a second capture is required.
- **Kimi-K3**, lines 40 and 43: *"a 2.8T-parameter model built on Kimi Delta Attention (KDA) and
  Attention Residuals (AttnRes)"*, *"New Architecture... yielding an approximate 2.5x improvement in
  overall scaling efficiency over Kimi K2."* K2 appears as a scaling comparison, not a derivation.

On this documentary basis the three roots (DeepSeek / MiniMax / Moonshot) appear mutually
independent, but that determination is codex's to make and seal, not this file's.

## 2026-08-21T04:36Z — PRIMARY r4 (`minimax/minimax-m3=coreweave/fp4`) — SUCCESS

All three role registries now exist. No model completion was requested; cost ledger still empty.

```
output-dir: $HOME/.mmaudit/private/model-discovery/authrunner-primary-judge-20260821-r4
run:        03d64875bbd447a8936edd5faed84177
manifest:   3921c5682bedf1f938236a5268fcf6d5a9138d1646726df00147705cba0b8969
registry:   $HOME/.mmaudit/private/authrunner/primary-judge-registry-r4.json
frozen:     eaed67e745d448299e3aa5d58b406de065fae09813b3c6ff1c646403ca8023a1
```

Stale discovery fields were not copied. Selection plan `8899739a0a4a36bacacb17592df8263f57f94c65b96a63b69ab61ab67e455761`.

### Complete triple — three distinct lineages, three distinct serving providers

| role | model | lineage | route | provider | registry |
|---|---|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813` | DeepSeek | `novita/fp8` | Novita | `candidate-registry-r2.json` |
| primary judge | `minimax/minimax-m3` | MiniMax | `coreweave/fp4` | CoreWeave | `primary-judge-registry-r4.json` |
| replay judge | `moonshotai/kimi-k3` | Moonshot | `together` | Together | `replay-judge-registry-r2.json` |

No two roles share a lineage or a serving provider. Note `distinct_root_lineages_verified` remains
`false` in the plan — that requires documentary public-lineage evidence, which metadata discovery
cannot supply.

**Next expected operator command:** the provider-free r2/r4/r2 `--preflight-only` run. Emit it and it
will be executed.

## 2026-08-20T19:59Z — PRIMARY r3 (`anthropic/claude-opus-5=amazon-bedrock`) — FAILED, unfixable

```
mmaudit failed safely: configured endpoint provider display name is ambiguous in exact-model metadata
```

Not a tag problem. The tag matched exactly one endpoint. `src/mmaudit/models/endpoint_snapshots.py:558-563`
imposes a second rule: the matched endpoint's `provider_name` must be unique across the model's
**entire** endpoint inventory. `amazon-bedrock` and `amazon-bedrock/us-east-1` both display as
"Amazon Bedrock", so both fail. A more specific tag cannot help.

`anthropic/claude-opus-5` endpoint inventory (tag → provider_name, status):

| tag | provider_name | status | ZDR |
|---|---|---|---|
| `claude-on-aws` | Claude Platform on AWS | 0 | no |
| `anthropic` | Anthropic | 0 | no |
| `azure/global` | Azure | 0 | no |
| `azure/us` | Azure | 0 | no |
| `amazon-bedrock` | Amazon Bedrock | 0 | yes |
| `amazon-bedrock/us-east-1` | Amazon Bedrock | 0 | yes |
| `google-vertex/global` | Google | 0 | yes |
| `google-vertex/us` | Google | 0 | yes |
| `google-vertex/europe` | Google | 0 | yes |

Every ZDR route has a duplicated display name; both unique-name routes are non-ZDR. Claude Opus 5
cannot satisfy ZDR AND unique-display-name. **Replace it.**

## Viable primary judges — all four constraints satisfied

Constraints: ZDR-eligible + operational (`status == 0`) + `provider_name` unique within the model +
root lineage distinct from DeepSeek (candidate) and Moonshot (replay judge).

| model | lineage | usable routes |
|---|---|---|
| `tencent/hy3` | Tencent | `tencent/fp8` [Tencent], `deepinfra/fp8` [DeepInfra], `novita` [Novita] |
| `z-ai/glm-5.2` | Zhipu | 16, incl. `z-ai/fp8` [Z.AI], `digitalocean`, `crusoe/fp8`, `sail-research/fp8` |
| `minimax/minimax-m3` | MiniMax | `coreweave/fp4`, `deepinfra/fp8`, `parasail/fp8`, `venice/fp8`, `modelrun/fp4` |

**Unusable — NO route satisfies all four:** `anthropic/claude-opus-5`, `google/gemini-3.7-flash`,
`openai/gpt-5.6-sol`, `x-ai/grok-4.6`, `meta/muse-spark-1.2`, `qwen/qwen3.8-max` (no ZDR route at all).

**Recommendation:** `tencent/hy3` on `tencent/fp8`, or `z-ai/glm-5.2` on `z-ai/fp8`. Both run on the
lab's own infrastructure, giving three distinct serving providers (Novita / Together / Tencent-or-Z.AI)
as well as three distinct lineages. Avoid `novita/fp8` and `together` for this role to preserve that.

## Design question requiring an explicit decision

The display-name uniqueness rule excludes **every** Western frontier model from judging on a ZDR route,
because those models are multi-homed across regional variants of one provider (Amazon Bedrock x2,
Google x3, Azure x2) and their ZDR routes are exactly the multi-homed ones. Only Chinese-lab models
remain eligible as judges.

If unintended: compare on `(provider_name, tag)`, or scope uniqueness to matched endpoints rather than
the model's whole inventory. If intended: record it as a known constraint on judge selection, since it
bears on cross-lineage adjudication quality claims.

## Standing results — still valid

| role | model | route | artifact | frozen registry sha256 |
|---|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813` | `novita/fp8` | `candidate-registry-r2.json` | `59dfdaf498cc2a8201351a7c6aacdfc2a3fd7f6daec09aa927202071ee7a0619` |
| replay judge | `moonshotai/kimi-k3` | `together` | `replay-judge-registry-r2.json` | `14937842d2a544540efa39199b2b0ed4c0f25e1f145f1385f32d43b728edbdea` |

`moonshotai/kimi-k3=deepinfra/bf16` failed (`endpoint is not operational`; that tag is `status=-2`).
`together` is `status=0` and succeeded. Note `status == 0` means operational; negative means not.

Cost ledger untouched: `{"cap_usd":"250","entries":{},"schema_version":1}` — **$0 spent**.

The PRIMARY role was resolved on 2026-08-21 with `minimax/minimax-m3=coreweave/fp4` (see top of file).
`tencent/hy3` and `z-ai/glm-5.2` remain unused viable alternates if MiniMax later fails a gate.
