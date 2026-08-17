# Provisional operator root-lineage review record — non-authorizing

**Documentary review date:** 2026-07-30. **Recorded reviewer:** repository operator.
**Companion evidence:** `docs/remediation/v3/model_selection_candidates.md`.

This is a provisional documentary input to the operator decision required by
`V3-LINEAGE-001`. It records proposed grouping labels, conservative collision assumptions,
and a public-source scope rationale; it does **not** authorize source egress or populate runtime
approvals. It is not hash-bound discovery evidence, is not independently authenticated, and must
not be copied into `config/models.candidates.toml`.

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
candidate list: it omits `openai/gpt-5.6-sol-pro` and
`deepseek/deepseek-v4-flash-0731`. No root from this page is therefore populated into runtime
`approved_model_lineages`. A future binding must use the exact current candidate set and
retain the raw bounded review evidence; it must not infer provider or operator authorship
from a self-hash.

## Authenticated calibration-only handoff

`mmaudit.models.lineage_authority` now defines a separate, fail-closed handoff for a future
operator decision. An SSHSIG Ed25519 envelope covers the exact structural review artifact,
candidate registry, discovery manifest and candidate set, refreshed source/snapshot/semantic
hashes, candidate bindings, approved roots, validity window, purpose, and literal authority
flags. Verification requires an explicit out-of-band operator trust anchor and a pinned,
root-owned system `ssh-keygen` executable. The trust anchor's self-hash protects integrity; it
does not by itself establish who controls the key, so selecting that anchor remains an operator
trust decision.

A successful verification issues only an opaque, process-local capability. Calibration schema
v2 requires that capability plus the exact review artifact and records the review, signed
envelope, and per-candidate binding hashes. Root-lineage credit is derived from the signed
projection, never from a caller-self-sealed candidate record. The envelope hard-codes
source-egress and production-selection authority to `false`; it cannot populate
`privacy.approved_model_lineages`, select an audit model, or authorize private-source handling.

Candidate-registry benchmark mode requires `--calibration-output`,
`--lineage-review-bundle`, and `--lineage-trust-anchor` together. The signature and exact joins
are checked before cost-ledger use, secret loading, campaign creation, or provider dispatch.
No current signed envelope, operator trust decision, successful current refresh, real
calibration, or runtime approval is claimed by this repository.

## Provisional scope rationale

The documentary record proposes eight lab-group identifiers, including four groups associated
with non-US jurisdictions, on the stated basis that the contemplated target source is public
open-source code. Those identifiers remain non-authorizing until a complete, current,
independently authenticated exact-set decision is bound through the fail-closed workflow.

**Boundary condition, recorded deliberately.** The provisional public-source rationale does not
extend to private client source. Pre-deployment audits — typically the highest-value segment,
where a protocol is reviewed before its source is published or verified on-chain — require a new
jurisdiction and policy decision. `V3-CONSENT-001` remains the mechanism for private-source
clients, and the source-provenance modes already implemented by `V3-PRIVACY-001` distinguish the
two cases. The lineage and policy decisions must be taken anew before the first private-source
audit.

## Root-lineage identifier derivation

`root_lineage` must match `^sha256:[0-9a-f]{64}$`. It is an opaque stable grouping identifier,
not a hash of model weights. Deriving a proposed identifier from a documented canonical string
makes the label reproducible, but the label itself is not evidence of shared or independent
model ancestry:

```
root_lineage = "sha256:" + sha256("mmaudit/root-lineage/v1/" + <lab>)
```

Reference implementation and regeneration: the derivation is one line and may be reproduced
when reviewing the proposed labels. A future authoritative decision must separately evidence
base-model, fine-tune, alias, mirror, and variant relationships before any registry is populated.

## Proposed lineage labels — not runtime approvals

| lab | proposed root_lineage | documentary status |
|---|---|---|
| anthropic | `sha256:56a692064d29b78241b9ab2aff623135de7453a7f5c8cedbf7a755813d1b9f20` | proposed only |
| openai | `sha256:5a56f394a5579be3bbda7f0343d7883d22a31e671b9317e3c82d6deb820e0f9f` | proposed only |
| google | `sha256:3971e4444db2d035fb2f9d041ad53115cd275678c1077fc2bd41ebf570d255fb` | proposed only |
| x-ai | `sha256:cd3cd825ae9177072fa3e48bd1c8bc38fb84abed8d0ebb436d966b5bdf05e9b2` | proposed only |
| moonshotai | `sha256:f393b50b9687e43b718a6534747fd5d0acc3ad9cfcdd8f39ad6b2ec72026c234` | proposed only |
| deepseek | `sha256:c7e8cdc80f762ddd61dfd47784dce66077d7ae03ff5d202903f7c8eec5d373eb` | proposed only |
| z-ai | `sha256:b1bddcb54df85bf9cad9a92adee7cc0915e335e922c7ac0ab2782b250db52a39` | proposed only |
| minimax | `sha256:2a12d9579a80cd448ac3dabca2a9f277f265ab47e71a334c0f64d65ccfbb26c5` | proposed only |

## Provisional assignment observations — not ancestry proof

Observed 2026-07-30 from the public OpenRouter catalogue `hugging_face_id` field and, where a
repository exists, the HuggingFace model API `cardData.base_model` field. A declared
`base_model` is useful derivative evidence; an absent field, a first-party publication, or closed
weights do not prove that a model is an original pretrain or independent of a public base.

| exact model | documentary observation | proposed lineage label |
|---|---|---|
| `anthropic/claude-opus-5` | closed weights; no HF repository; ancestry unresolved | anthropic |
| `anthropic/claude-sonnet-5` | closed weights; no HF repository; ancestry unresolved | anthropic |
| `openai/gpt-5.5` | closed weights; no HF repository; ancestry unresolved | openai |
| `google/gemini-3.1-pro-preview` | closed weights; no HF repository; ancestry unresolved | google |
| `x-ai/grok-4.20` | closed weights; no HF repository; ancestry unresolved | x-ai |
| `x-ai/grok-4.5` | closed weights; no HF repository; ancestry unresolved | x-ai |
| `moonshotai/kimi-k3` | `moonshotai/Kimi-K3`; no `base_model` declared | moonshotai |
| `deepseek/deepseek-v4-pro` | `deepseek-ai/DeepSeek-V4-Pro`; no `base_model` declared | deepseek |
| `z-ai/glm-5.2` | `zai-org/GLM-5.2`; no `base_model` declared | z-ai |
| `minimax/minimax-m3` | `MiniMaxAI/Minimax-M3`; first-party organisation | minimax |

These observations do not establish ancestry for any row. Grouping same-lab models together is a
conservative non-independence assumption; separation between different lab labels remains
unproven. Neither may be promoted merely because catalogue metadata omits a base model or because
a vendor controls the publication.

## Provisional conservative collisions — no added independence credit

- `anthropic/claude-opus-5` and `anthropic/claude-sonnet-5` are provisionally treated as one
  lineage and receive no extra independence credit.
- `x-ai/grok-4.20` and `x-ai/grok-4.5` are provisionally treated as one lineage and receive no
  extra independence credit.
- Any `-fast`, `:batch`, or equivalent variant is the same model and the same lineage as its
  base. `anthropic/claude-opus-5-fast` adds nothing over `anthropic/claude-opus-5`.
- Selecting both members of a colliding pair yields one independent vote, not two, and must
  not satisfy a distinct-family requirement.

## Explicitly NOT authorised

The previously frozen candidate set is superseded and is not authorised. Two of its entries
were unresolved and must not be revived without derivation evidence:

- `nvidia/nemotron-3-super-120b-a12b` — publishes under the NVIDIA organisation, but the
  available documentary record does not establish its base-model ancestry. If revived, any
  collision with another lineage must be evidenced, not inferred from the vendor prefix.
- `deepcogito/cogito-v2.1-671b` — no HuggingFace identifier or complete ancestry evidence is
  present in the documentary record. Its name and parameter count cannot establish or exclude a
  collision with another lineage.

## Binding requirements — identity is not quality or selection authority

`ModelLineageConfig` now separates an operator-reviewed declaration from measured quality.
The declared identity contains `root_lineage`, `canonical_model_id`, `aliases`, and
`retention_policy`. Its optional nested `measured_quality` record contains only a benchmark's
hash-bound `score`, `tier`, and `measurement` output. A future complete, authenticated,
exact-set review can therefore authorize an identity for approved benchmark and calibration
routing before any quality result exists, without making that identity selectable for an audit
role. This provisional page cannot perform that transition.

The evidence transition is fixed:

1. `V3-MODELREFRESH-001` re-runs discovery so exact models, endpoints, pricing, and privacy
   eligibility carry current hash-bound evidence.
2. The operator review is joined to that candidate registry. The implemented signed handoff may
   contribute identity-only root evidence to calibration, but cannot populate `models.registry`
   or `privacy.approved_model_lineages`. Any later source-egress promotion remains a distinct,
   explicit operator action and must preserve the signed evidence.
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

The documentary rationale considered public open-source targets, but this record does not relax
the current ZDR policy or make any catalogue row selectable. The 2026-07-30 observation recorded
246 ZDR-eligible models out of 367; the non-ZDR catalogue also included
`openai/gpt-5.5-pro`, `qwen/qwen3.7-max`, and `mistralai/mistral-medium-3-5`. Any future decision to
relax `require_zdr` is a separate explicit configuration and provenance decision and must remain
bound to validated public-source scope, so a private-source target can never silently use it.
