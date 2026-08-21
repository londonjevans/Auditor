# Operator execution results — metadata-only discovery

Results of operator-run credentialed commands. Codex: read this file before stopping a turn that
requested an operator command. Written by the monitoring session; treat as operator-supplied evidence.

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
