# Three-route admission review and operator cost decision — 2026-09-09

## Result before implementation

All three operator-shared retained routes pass the existing V1 and V2 price-cap
projection. Their pricing vectors contain prompt, completion and input-cache-read
charges, with cache reads prompt-dominated. No vector contains input-cache-write.
The projector does not invent absent components. Its rejection of an explicitly
present cache-write quote, even zero, is a different case.

No route is currently admitted by the active selection plan. The immediate
blockers are the unavailable candidate assignment and stale endpoint allowlists,
followed by missing constrained discovery and runtime evidence. Relaxing cost
enforcement alone would not remove these blockers.

This is provider-free source analysis, not a fresh provider survey, constrained
discovery publication, successful smoke, qualification or release. Runtime
admission and active-plan bytes have not been changed by this analysis slice.

## Explicit operator relaxation: OP-COST-2026-09-09

Authority: Jos Evans's direct conversation instruction dated September 9, 2026.
The later `operator_results.md` observation is nonauthorizing evidence, not the
source of this decision.

The operator explicitly relaxes the stricter internal price-cap rule for price
components that providers do not cap. The permitted replacement is conservative
reservation before dispatch followed by actual billed-cost reconciliation for
each call, a hard abort at the ledger ceiling inside USD 250, and durable recording
of any overage that blocks further work. No automatic budget increase or request
for more money is permitted. A reservation is not a provider-enforced ceiling:
post-call accounting cannot guarantee that a provider never bills above it.

This is an **explicit operator relaxation**, not a discovery that the previous
rule was wrong. The frozen objective's wording remains unchanged; the stricter
internal enforcement interpretation and its historical refusals remain recorded.
No assertion about what every current provider offers is independently verified
here. The decision supplies the authority for the bounded cost-policy change.

Qualification, lineage independence, privacy, native schema/reasoning requirements,
negative revocations, evidence seals and release gates are not relaxed. Cost is
an accounting/control requirement, not evidence of security or audit quality.
No paid run is authorized. Shared discovery bytes must remain gitignored and may
not be copied into tracked fixtures. Other private inputs and ledgers are outside
this inspection.

Implementation is queued as `V3-COSTRECON-001`. This document does not implement
the new cost contract, alter V1/V2 proofs, admit a route or grant runtime authority.

## Inputs and method

Source baseline: operator-only commit `6e73894`, on tested source/record tip
`a1836be62fa08df2a3f2fcec592b8cb0616130fd`. The operator-only change adds 56 report
lines and does not modify implementation. Latest report digest at inspection:
`08599d848f3a8ceff90a13c450c8f935cc866e3740dc9b5b93c3792b4fdc95ec`, label
`2026-09-09T18:05Z`.

Only the six explicitly authorized JSON files under
`.mmaudit/operator-shared/discovery/` were read. Each candidate and manifest passes
its exact typed validator. Each manifest's logical candidate filename, raw file
digest, discovery self-digest, exact route and run provenance match its prefixed
shared copy. No file was rewritten or published. Those joins establish internal
consistency, not independently authenticated live origin or freshness.

The existing functions `project_provider_price_cap`, `evaluate_route_predicates`
and `require_route_predicates` were exercised locally with socket connection
traps. Diagnostic facts used retained model/endpoint metadata and the current
frozen request profile. Proposed request parameters, role/profile bindings and
projected caps were constructed in memory and are not an active assignment or a
recorded dispatch. Missing full display inventory, registry custody and live
evidence stayed missing. No successful constrained artifact was manufactured.

The real pinned ancestry resolver was also exercised, followed by derivation
attempts for each requested route and negative-only revocation checks for all
three roles. Public lineage records were inspected as source data, not promoted
to live campaign custody.

## Plan and ancestry refusals outside the 29-predicate report

Active `config/models.selection-plan.json` has schema 1.7, raw digest
`4e7fff76ffb126a1cdf044cdfc889d79def96a29076aa11e3b42c7ef0ff9a695`, and semantic
digest `14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3`.
Its selection is null and its state is `NO_ACTIVE_CANDIDATE_AFTER_REVOCATION`.

| Requested route | Existing model allowlist | Additional candidate-role issue |
| --- | --- | --- |
| `moonshotai/kimi-k3=together` | `modal/mxfp4`, `phala` | Same exact model as retained replay judge |
| `deepseek/deepseek-v4-pro-0813=together` | `parasail/fp8` | None of the retained judge identities collide |
| `z-ai/glm-5.2=deepinfra/fp4` | `sail-research/fp8` | Same exact model as retained primary judge |

For all three, the actual authenticated reactivation deriver raises
`candidate-selection reactivation route uses an unlisted endpoint`. This is the
first refusal, not the complete set. The ordinary successor deriver separately
refuses the unavailable predecessor because it requires authenticated ancestry.

`V3-PLANANCESTRY-001` is now locally COMPLETE, unlike its older September-4 WIP
description. Its tested v1.8 transition preserves existing judge constraints and
the exact V1 profile, narrows an already-listed candidate endpoint, and emits a
private nonauthorizing plan. It deliberately does not refresh endpoint inventories,
reassign judge routes, upgrade cost policy or adopt the result. Thus it does not
yet support the requested three-route transition.

DeepSeek/Together is not revoked. The empirical schema-conformance tombstone
applies to the exact DeepSeek/Parasail FP8 route, including its bound canonical
identity; it must remain effective. Absence of a tombstone is not conformance proof.

The least disruptive role assignment is DeepSeek/Together candidate,
GLM/DeepInfra FP4 primary judge and Kimi/Together replay judge. It retains three
different model/root identities but requires refreshing both judge routes as well
as the candidate. Existing public-lineage records describe three CONFIRMED,
different roots; actual runner lineage verification is still required. Sharing
Together across two routes is not itself a distinct-root failure in the inspected
runner code; serving-provider diversity is not substituted for root independence.

## Full predicate inventory

The retained frozen V1 profile digest is
`00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82`.
All three produce the same diagnostic dispositions: 23 satisfied, one rejected
for missing retained inventory, and five unavailable. A satisfied *projected*
configuration check is not evidence that the unavailable active plan binds it.

| Predicate | All three: diagnostic result | Evidence or limitation |
| --- | --- | --- |
| `EXACT_MODEL_IDENTITY` | Satisfied | Retained exact ID matches the requested tuple, not active-plan admission |
| `EXACT_PROVIDER_ENDPOINT` | Satisfied | Retained tag matches the requested endpoint; allowlist refusal is separate |
| `PROVIDER_DISPLAY_NAME_INJECTIVITY` | Rejected: `DISPLAY_INVENTORY_INCOMPLETE` | Shared legacy evidence omits the full display-name inventory |
| `OPERATIONAL_STATUS` | Satisfied | Retained status is the accepted `0` |
| `ZDR_ELIGIBILITY` | Satisfied | Retained endpoint eligibility is true |
| `EMITS_MAX_TOKENS` | Satisfied, projected | Frozen request emits it; model and endpoint both list support |
| `EMITS_TEMPERATURE` | Satisfied, projected | Frozen request emits it; both inventories list support |
| `EMITS_RESPONSE_FORMAT` | Satisfied, projected | Frozen request emits it; both inventories list support |
| `EMITS_REASONING` | Satisfied, projected | Frozen request emits it; both inventories list support |
| `MODEL_STRUCTURED_OUTPUT_MARKER` | Satisfied | Model inventory contains `structured_outputs` |
| `ENDPOINT_STRUCTURED_OUTPUT_MARKER` | Satisfied | Endpoint inventory contains `structured_outputs` |
| `NATIVE_STRUCTURED_OUTPUT_MODE` | Satisfied | Retained negotiated mode is `NATIVE_JSON_SCHEMA` |
| `SINGLETON_EXACT_ROUTE` | Satisfied, projected | One requested endpoint, `only` policy |
| `AUTOMATIC_FALLBACK_DISABLED` | Satisfied, projected | Frozen no-fallback request policy |
| `REASONING_POLICY_BINDING` | Satisfied, projected | Exact frozen policy/role hashes used in memory |
| `REASONING_CONTROL_BINDING` | Satisfied, projected | Exact frozen control hash used in memory |
| `REASONING_CONTROL_VALUES` | Satisfied, projected | `effort=high`, no exclusion, 4096 reasoning tokens reserved |
| `REASONING_EFFORT_SUPPORT` | Satisfied | Endpoint inventory absent; model-level inventory explicitly supports high |
| `PROMPT_CAPACITY_ENVELOPE` | Satisfied | Retained 1,048,576 prompt tokens exceeds required 65,536 |
| `OUTPUT_CAPACITY_ENVELOPE` | Satisfied | All retained limits exceed required 4096 visible output tokens |
| `CONTEXT_CAPACITY_ENVELOPE` | Satisfied | Retained 1,048,576 context tokens exceeds required 73,728 |
| `METADATA_COMPLETION_CAPACITY` | Satisfied | Explicit metadata limit exceeds combined 8192 output/reasoning tokens |
| `PRICE_CAP_EXPRESSIBILITY` | Satisfied | Real V1 and V2 projection both succeed on every retained vector |
| `PRICE_CAP_NO_WEAKER` | Satisfied, projected | Exactly the projected caps were supplied to the real proof checker |
| `FROZEN_LIVE_EQUIVALENCE` | Unavailable | No provider refresh or live observation authorized/performed |
| `REGISTRY_SELECTION_HASH_CUSTODY` | Unavailable | No selected-plan-bound registry supplied for these routes |
| `REGISTRY_CONSTRAINT_HASH_CUSTODY` | Unavailable | No corresponding registry/profile/constraint binding supplied |
| `EMPIRICAL_SCHEMA_CONFORMANCE` | Unavailable | Metadata support is not authenticated response conformance |
| `TOKEN_DETAIL_REPORTING_CONVENTION` | Unavailable | No authenticated smoke token-detail evidence supplied |

The model-level effort inventories include high for every route. Endpoint-level
null is resolved by the existing absence-only fallback, not a new exemption.
Kimi and DeepSeek have explicit completion limits of 943,718; GLM has 163,840.
The actual runtime output envelope must still match the frozen 4096-token profile.

The legacy snapshot publisher checks full-inventory display uniqueness when
creating snapshots, but these retained artifacts do not carry that inventory for
independent replay. The diagnostic rejection means insufficient retained evidence,
not that Together or DeepInfra actually has a duplicate display name. The ordinary
admission entry point refuses the missing constrained artifact before it could
consume this diagnostic report.

The projected per-million-token request caps are:

| Route | Prompt USD | Completion USD |
| --- | ---: | ---: |
| DeepSeek/Together | 1.32 | 3.96 |
| GLM/DeepInfra FP4 | 0.4875 | 1.56 |
| Kimi/Together | 3.00 | 15.00 |

These are calculations from retained quotes, not current price promises, actual
bills or permission to dispatch. V3 remains the old reserved, unconditionally
refused cache-write algorithm; the operator relaxation must not be hidden inside
its existing provider-ceiling proof semantics.

## What each admission stage still refuses

The supplied legacy snapshot has none of `route_predicate_profile`,
`exact_route_constraint`, `normalized_route_facts` or `route_predicate_report`.
These are all required by AUTHRUNNER admission. Internally consistent development
evidence is therefore not directly promotable to a constrained registry.

For the diagnostic report above, the real closed purpose matrix yields:

| Purpose | Remaining failing predicates |
| --- | --- |
| `DISCOVERY_PUBLICATION` | Display-name inventory/injectivity |
| `REGISTRY_PUBLICATION` | Display inventory, selection custody, constraint/profile custody |
| `NONCREDITING_SMOKE_ADMISSION` | The registry-stage failures plus live equivalence |
| `FULL_CAMPAIGN_ADMISSION` | The registry-stage failures plus empirical schema conformance and token convention |

Full campaign's zero-state preflight intentionally allows *unavailable* live
equivalence until refresh; an explicit mismatch always rejects. Unavailable
schema/token evidence is never accepted for the full campaign. Only the existing
typed, live smoke-evidence transition can satisfy those two runtime predicates.
All three role registries and exact role/manifest joins are required, not just a
passing candidate report.

Beyond route admission, executing a campaign still needs a valid launch/config,
frozen ground-truth and public-lineage capabilities, exact PRIMARY/REPLAY plans,
bounded token/request budgets, safe outputs and an eligible shared cost ledger.
Those execution inputs were not supplied or inspected here. They are not invented
as additional route-specific metadata failures, nor assumed satisfied. A
three-root route setup also does not meet calibration's separate six-independent-
root/full-population requirement or supply external truth/seal/release evidence.

## Cost enforcement already present, and work still needed

`AtomicCostLedger.reserve` atomically checks remaining capacity and refuses any
prior reservation overrun. `reconcile` persists the exact actual bill before
raising on an overrun, including a bill above the overall ceiling. Reopening does
not erase that state. Portfolio claims also reject a retained overrun. Positive
new reservations cannot proceed when remaining capacity is zero.

Unknown bills remain `UNCERTAIN_ACCOUNTED`, not actual settlement. The optional
settled-history reservation check refuses pending or unallowed unknown liabilities.
The relaxed production path must bind and enforce the appropriate dispatch rules;
the existence of these ledger primitives alone does not establish that integration.
The decision does not authorize a historical balance reset or forgiving uncertainty.

## Bounded implementation sequence

1. `V3-CANDROUTE-001`: this source diagnosis, explicit relaxation record and
   synthetic regressions. Parent remains PARTIAL until an actual route meets its
   unchanged discovery/preflight acceptance.
2. `V3-PLANROUTES-001`: authenticated, predecessor-bound endpoint refresh and
   nonauthorizing active-plan transition for the three existing role identities.
   Keep V1 for these already-expressible vectors. Preserve exact unavailable
   ancestry for replay. Test the real local entry points with synthetic metadata;
   do not fabricate fresh provider or runtime evidence.
3. `V3-COSTRECON-001`: separately versioned reserve/reconcile admission contract
   for uncappable components, bound to this explicit operator relaxation. Reuse
   ledger primitives and test dispatch/accounting/overrun/unknown-cost boundaries;
   preserve legacy cap proofs and unrelated gates.
4. Resume `V3-CANDROUTE-001` evidence acceptance and then the existing authenticated
   campaign/calibration work. No paid execution is authorized by this sequence.

No second major ticket starts until the current slice is tested and recorded.
The complete queue criteria, exact commands, test results and latest operator
reconciliation are maintained in the worklog. No real audit or release is claimed.
