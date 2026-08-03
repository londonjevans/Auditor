# Operator root-lineage review and authorisation

**Decision date:** 2026-07-30. **Decided by:** repository operator.
**Companion evidence:** `docs/remediation/v3/model_selection_candidates.md`.

This is the operator decision record required by `V3-LINEAGE-001`. It authorises root
lineages for source egress. It is **not** hash-bound discovery evidence and must not be
copied into `config/models.candidates.toml`.

## Machine-verifiable status

The provider-free implementation in `mmaudit.models.lineage_review` can bind a dated
decision to exact discovery, refreshed route state, trusted freshness limits, and bounded
decision-evidence bytes. Its artifact is deliberately labelled
`PROVIDER_FREE_STRUCTURAL`, `NOT_EVALUATED`, and `NOT_INDEPENDENTLY_PROVEN` for both
provider observation and operator-decision authenticity. It hard-codes source-egress and
production-selection authority to `false`.

This Markdown record is not currently eligible to produce that artifact: there is no
successful post-correction real refresh bundle, the recorded decision has no whole-second
UTC time, and the assignment table does not exactly cover the current documentary
candidate list. No root from this page is therefore populated into runtime
`approved_model_lineages`. A future binding must use the exact current candidate set and
retain the raw bounded review evidence; it must not infer provider or operator authorship
from a self-hash.

## Scope of the authorisation

The operator authorises all eight root lineages below, including the four non-US
jurisdictions, on the stated basis that audited target source is public open-source code.

**Boundary condition, recorded deliberately.** That basis holds only while targets are
public. Pre-deployment audits — typically the highest-value segment, where a protocol is
reviewed before its source is published or verified on-chain — involve private client source,
and for those the jurisdiction question returns and this authorisation does not extend to
them. `V3-CONSENT-001` remains the mechanism for private-source clients, and the
source-provenance modes already implemented by `V3-PRIVACY-001` are what distinguish the two
cases. This authorisation must be re-taken before the first private-source audit.

## Root-lineage identifier derivation

`root_lineage` must match `^sha256:[0-9a-f]{64}$`. It is an opaque stable grouping identifier,
not a hash of model weights. Deriving it from a documented canonical string makes assignment
reproducible and auditable rather than arbitrary:

```
root_lineage = "sha256:" + sha256("mmaudit/root-lineage/v1/" + <lab>)
```

Reference implementation and regeneration: the derivation is one line and must be reproduced
in-repo when the registry is populated, so any reviewer can recompute every identifier.

## Authorised lineages

| lab | root_lineage | authorised |
|---|---|---|
| anthropic | `sha256:56a692064d29b78241b9ab2aff623135de7453a7f5c8cedbf7a755813d1b9f20` | yes |
| openai | `sha256:5a56f394a5579be3bbda7f0343d7883d22a31e671b9317e3c82d6deb820e0f9f` | yes |
| google | `sha256:3971e4444db2d035fb2f9d041ad53115cd275678c1077fc2bd41ebf570d255fb` | yes |
| x-ai | `sha256:cd3cd825ae9177072fa3e48bd1c8bc38fb84abed8d0ebb436d966b5bdf05e9b2` | yes |
| moonshotai | `sha256:f393b50b9687e43b718a6534747fd5d0acc3ad9cfcdd8f39ad6b2ec72026c234` | yes |
| deepseek | `sha256:c7e8cdc80f762ddd61dfd47784dce66077d7ae03ff5d202903f7c8eec5d373eb` | yes |
| z-ai | `sha256:b1bddcb54df85bf9cad9a92adee7cc0915e335e922c7ac0ab2782b250db52a39` | yes |
| minimax | `sha256:2a12d9579a80cd448ac3dabca2a9f277f265ab47e71a334c0f64d65ccfbb26c5` | yes |

## Lineage assignment with derivation evidence

Observed 2026-07-30 from the public OpenRouter catalogue `hugging_face_id` field and, where a
repository exists, the HuggingFace model API `cardData.base_model` field. A declared
`base_model` would indicate a derivative; its absence on a first-party publication indicates
an original pretrain.

| exact model | derivation evidence | lineage |
|---|---|---|
| `anthropic/claude-opus-5` | closed weights, no HF repository | anthropic |
| `anthropic/claude-sonnet-5` | closed weights, no HF repository | anthropic |
| `openai/gpt-5.5` | closed weights, no HF repository | openai |
| `google/gemini-3.1-pro-preview` | closed weights, no HF repository | google |
| `x-ai/grok-4.20` | closed weights, no HF repository | x-ai |
| `x-ai/grok-4.5` | closed weights, no HF repository | x-ai |
| `moonshotai/kimi-k3` | `moonshotai/Kimi-K3`, no `base_model` declared | moonshotai |
| `deepseek/deepseek-v4-pro` | `deepseek-ai/DeepSeek-V4-Pro`, no `base_model` declared | deepseek |
| `z-ai/glm-5.2` | `zai-org/GLM-5.2`, no `base_model` declared | z-ai |
| `minimax/minimax-m3` | `MiniMaxAI/Minimax-M3`, first-party org | minimax |

Closed-weight models cannot be derivatives of any public base. The four open-weight models
publish under their own organisation and declare no base model.

## Collisions — models that do NOT add independence

- `anthropic/claude-opus-5` and `anthropic/claude-sonnet-5` are one lineage.
- `x-ai/grok-4.20` and `x-ai/grok-4.5` are one lineage.
- Any `-fast`, `:batch`, or equivalent variant is the same model and the same lineage as its
  base. `anthropic/claude-opus-5-fast` adds nothing over `anthropic/claude-opus-5`.
- Selecting both members of a colliding pair yields one independent vote, not two, and must
  not satisfy a distinct-family requirement.

## Explicitly NOT authorised

The previously frozen candidate set is superseded and is not authorised. Two of its entries
were unresolved and must not be revived without derivation evidence:

- `nvidia/nemotron-3-super-120b-a12b` — publishes under the NVIDIA organisation, but the
  Nemotron Super line has historically been Llama-derived. If revived, it may collide with
  `meta-llama/*` and must be evidenced, not inferred from the vendor prefix.
- `deepcogito/cogito-v2.1-671b` — no HuggingFace identifier is exposed in the catalogue, and
  its 671B parameter count matches DeepSeek V3. If revived it may collide with `deepseek/*`.

## Binding requirements — identity is not quality or selection authority

`ModelLineageConfig` now separates the operator-reviewed declaration from measured quality.
The declared identity contains `root_lineage`, `canonical_model_id`, `aliases`, and
`retention_policy`. Its optional nested `measured_quality` record contains only a benchmark's
hash-bound `score`, `tier`, and `measurement` output. This review can therefore authorize an
identity for approved benchmark and calibration routing before any quality result exists,
without making that identity selectable for an audit role.

The evidence transition is fixed:

1. `V3-MODELREFRESH-001` re-runs discovery so exact models, endpoints, pricing, and privacy
   eligibility carry current hash-bound evidence.
2. The operator review is joined to that candidate registry. The approved root lineage may
   populate an identity-only `models.registry` entry and `privacy.approved_model_lineages` for
   benchmark and calibration purposes.
3. `V3-CALIBRATE-001` sets reachable thresholds before paid qualification; the historical
   all-dimension `1.0` policy is not treated as measured production policy.
4. Qualification produces the quality score, tier, and measurement hash. One explicit,
   evidence-backed promotion attaches that complete nested record to the declared identity.
5. Production selection independently revalidates the current qualification, exact identity,
   root lineage, role, endpoint, and attached quality values. Neither the identity declaration
   nor the nested static record grants production authority by itself.

While a model is unmeasured, `measured_quality` is absent. A default, zero, null, placeholder,
or sentinel score must never stand in for missing evidence, and a partial nested measurement is
invalid. Source egress remains fail-closed unless the separate privacy, lineage, and retention
conditions are satisfied; production audit roles additionally remain fail-closed until the
quality and verified-selection conditions are satisfied.

## Note on ZDR scope

Because targets are public open-source code, ZDR eligibility is no longer a binding
constraint on model choice. The ZDR-eligible subset was 246 of 367 observed models; the full
catalogue becomes selectable for public-source audits, which additionally admits
`openai/gpt-5.5-pro`, `qwen/qwen3.7-max`, and `mistralai/mistral-medium-3-5`. Relaxing
`require_zdr` is a separate explicit configuration decision and must remain bound to a
validated public-source provenance mode, so a private-source target can never silently route
under the relaxed policy.
