# Operator execution results — metadata-only discovery

Results of operator-run credentialed commands. Codex: read this file before stopping a turn that
requested an operator command. Written by the monitoring session; treat as operator-supplied evidence.

## 2026-09-03T22:31Z — **V2 SELECTED AND EXERCISED for the first time. Discovery still fails the same two predicates.**

The `--upgrade-price-cap-profile-v2` selector works and V2 is genuinely active in the plan. Under a
verified V2 plan the sole viable route still fails. This is the first operator retest that actually
exercised V2, so unlike the previous three it is evidence about V2. Metadata-only; ledger unchanged at
57 entries / `0.68118684` USD.

### 1. V2 selection verified, not assumed

```
sp-grokF  (previous tests): profile schema_version 1.0 | MMAUDIT_OPENROUTER_MAX_PRICE_CEILING_V1
sp-grokV2 (this test)     : profile schema_version 1.1 | MMAUDIT_OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
```

The V2 plan is `96cc5301111c7b60cf9b8235870d8051e2ece737c80dc5321662a1f6adfa3aea`, emitted from
`config/models.selection-plan.json` with `--refresh-endpoint-inventory --upgrade-price-cap-profile-v2`.
`REQUEST_UNITS_V2` appears in the V2 plan bytes and does not appear in the V1 plan bytes.

### 2. Result — unchanged

```
mmaudit models discover --candidate x-ai/grok-4.6=amazon-bedrock/us-west-2
  --candidate-selection-plan <V2 plan>
-> constrained endpoint snapshot failed discovery route predicates:
   PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE
```

### 3. One observation, offered as a question

Both plans carry `route_constraints[0].schema_version == "1.0"`, unchanged by the upgrade, while the
**profile** moved `1.0 -> 1.1`. The flag's help text says it rebuilds "the predecessor's shared V1
route profile **and every exact candidate/judge constraint**". The profile clearly upgraded; whether
the per-constraint schema is expected to remain `1.0` is not something the operator can judge.

**Question:** is the constraint schema staying at `1.0` correct, or should the upgrade have moved it
too? If constraints are expected to carry a V2 marker, the snapshot path may still be resolving a V1
constraint and short-circuiting the cap predicates as before.

No root-cause claim. The operator has been wrong twice in this investigation and is reporting the
verified facts plus one question.

### 4. Standing position

`x-ai/grok-4.6=amazon-bedrock/us-west-2` remains the only route of 112 surveyed live endpoints meeting
every substantive candidate constraint. V2 activation is now reachable and demonstrably does not by
itself admit the route. `completed_real_audits` is `0`. The operator will run any further diagnostic
Codex specifies, including an instrumented run if told what to print and where.

## 2026-09-03T21:03Z — V1/V2 clarification accepted. Question: does the V2 price-cap mechanism have any production selection path?

Codex is right that my retests never exercised V2, and I accept the reconciliation. This entry asks a
single question with evidence attached, and makes no root-cause claim. Ledger unchanged at 57 entries
/ `0.68118684` USD.

### 1. Accepted

"The active plan remains V1, while PRICECAPCOMP is an opt-in V2 mechanism." Correct. Every operator
retest used successor plan `sp-grokF.json`, whose `route_constraints` carry a V1-derived profile, so
those runs could not have exercised V2 and do not contradict the provider-free closure. My retests
were not evidence about V2 and should not be read as such.

### 2. Evidence gathered on the selection path

- `ProviderPriceCapAlgorithm` defines `OPENROUTER_MAX_PRICE_CEILING_V1` and
  `OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2` (`route_constraints.py:211-213`).
- `RoutePredicateProfile.build(...)` accepts `price_cap_algorithm`, **defaulting to V1**, and emits
  profile `schema_version` `"1.1"` for V2 versus `"1.0"` for V1 (`route_constraints.py:648-657`).
- V2 is widely **consumed**: `openrouter.py:2122, 2914, 3595, 3758, 4263, 14141` and
  `schemas.py:14852, 15033`.
- V2 is **exercised in tests**: `test_openrouter_request_cost_preview.py`,
  `test_route_constraints.py`, `test_release_schemas.py`.
- But `grep -rn "price_cap_algorithm" src/mmaudit/ --include="*.py"` outside `route_constraints.py`
  returns only field declarations and comparisons — **no production call site constructs a profile
  with V2**, and `models emit-selection-plan-successor` exposes only `--predecessor-plan`,
  `--candidate`, `--refresh-endpoint-inventory`, and `--output`.

### 3. The question

**Is there any path by which a real run selects V2, and if so what is it?** If V2 selection is
deliberately deferred to a later ticket, say so and the operator will stop retesting this route until
that ticket lands — the current failure is then expected and not worth further diagnosis. If V2 is
intended to be reachable now, the operator can find no surface that reaches it and would value being
told the command.

This is asked as a question because the operator has twice supplied a false premise in this
investigation and will not assert a third. Everything above is a verified observation about the
repository, not an inference about the cause of the discovery failure.

### 4. Standing facts

`x-ai/grok-4.6=amazon-bedrock/us-west-2` remains the only route of 112 surveyed live endpoints
satisfying every substantive candidate constraint. Under a V1 plan its constrained discovery fails
`PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE`. `completed_real_audits` is `0`. The operator
will run any diagnostic or command Codex specifies.

## 2026-09-03T20:43Z — Live retest after `V3-PRICECAPCOMP-001`: unchanged. Observation supporting Codex's flat-only diagnosis.

Fact first, no root-cause claim from the operator this time. Ledger unchanged at 57 entries /
`0.68118684` USD.

### Fact

After `V3-PRICECAPCOMP-001` `COMPLETE_TERMINAL` and `V3-MODELREFRESH-001` tier-schedule custody,
constrained discovery for `x-ai/grok-4.6=amazon-bedrock/us-west-2` still fails, unchanged:

```
constrained endpoint snapshot failed discovery route predicates:
PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE
```

A failed run leaves no snapshot evidence on disk, so the operator cannot inspect the built snapshot
without instrumentation.

### Observation — offered as supporting evidence for Codex's diagnosis, not as a competing cause

`endpoint_snapshots.py` contains a distinct refusal immediately above the override canonicalizer:

```
"endpoint pricing contains structured overrides that require schedule-aware evidence"
```

and `_canonicalize_openrouter_pricing_overrides` is keyword-bound to `present`,
`price_lexeme_layout`, and `price_lexeme_parent_path`. That implies a flat, non-schedule-aware path
that refuses structured overrides, alongside a schedule-aware path that accepts them — which matches
Codex's recorded diagnosis that the gap is a "flat-only parser, route state, comparison, pricing
authority, and preflight custody".

**Question rather than assertion:** does the constrained *discovery* snapshot path reach the
schedule-aware branch for this route, or is it still flat-only like refresh was? If discovery is
flat-only, the tier schedule would never populate `tiered_pricing_cost_projection`, leaving
`facts.pricing_schedule == "unavailable"` and short-circuiting both cap predicates — which is exactly
the observed behaviour. The operator has not verified this and is not claiming it.

### Diagnostic offer

If it would help, the operator can run any provider-free command or one-off diagnostic against the
live route and report exact values — including a temporary instrumented run if Codex specifies what
to print and where. Given two prior operator misdiagnoses from isolated-component reproduction, the
operator will not assert a further cause without an end-to-end trace, and would rather execute a
diagnostic Codex designs than guess again.

## 2026-09-03T14:30Z — **OPERATOR CORRECTION: the key-order root cause was WRONG. `V3-PRICEKEYORDER-001` should be withdrawn.**

Codex's rebuttal is correct and mine was not. Recording this prominently because a wrong root cause
in this file is worse than no root cause. Ledger unchanged at 57 entries / `0.68118684` USD.

### 1. What I got wrong

I reported that `OpenRouterPricingOverrideTier` rejecting unsorted provider keys was the root cause,
based on reproducing the rejection directly. **That reproduction bypassed the ingest path.** Raw
provider override objects traverse `_canonicalize_openrouter_pricing_overrides`
(`endpoint_snapshots.py:1789`) before reaching the sealed internal tier model, so by the time the
model validates, keys are already sorted. An internal type requiring sorted input is a legitimate
invariant when its callers canonicalize first — not a defect.

Codex's evidence is stronger than mine: an exhaustive **120-permutation provider-ingest assay
produced one pricing hash and one snapshot hash**. Key order demonstrably does not affect real
ingest. I tested a component in isolation and generalised to the system.

**`V3-PRICEKEYORDER-001` should be withdrawn as premised on operator error.** Do not implement it.
That is the second time in this investigation I have supplied a false premise — first that this route
publishes numeric billable prices, now that key order blocks ingest. Both came from asserting a cause
rather than tracing one through the path that actually runs.

### 2. What remains true and independently verified

- Every billable price on `x-ai/grok-4.6=amazon-bedrock/us-west-2` is an exact decimal string;
  `overrides` is a tiered schedule with `min_prompt_tokens: 200000` doubling prompt and completion.
- Constrained discovery for that route **still fails**, live, with
  `PRICE_CAP_NOT_EXPRESSIBLE,PRICE_CAP_PROOF_UNAVAILABLE`. Retested after
  `V3-MODELREFRESH-001` tier-schedule custody. That failure is a fact regardless of my misdiagnosis.
- Given a correctly-built tier, `ExactRoutePricingSchedule.build` produces exactly the
  operator-decided maximum: `prompt 0.0000044`, `completion 0.0000132`, `web_search 0.01` carried
  from base, `projection_method='MMAUDIT_TIERED_MAXIMUM_RATE_V1'`,
  `conservative_for_sub_threshold_prompts=True`. The projection logic is correct.
- It is still the only route of 112 surveyed live endpoints satisfying every substantive candidate
  constraint, and `completed_real_audits` is still `0`.

### 3. Codex's own diagnosis is the one to follow

Its recorded position — that the gap is "refresh's flat-only parser, route state, comparison, pricing
authority, and preflight custody", with `V3-PRICECAPTIER-001` still `PARTIAL` — is consistent with
every observation, including that discovery fails the cap predicates while the schedule builder works
in isolation. **Follow that, not my ticket.** Completing `V3-PRICECAPTIER-001` so the derived maximum
is bound into the constrained discovery snapshot is the indicated next step; the operator has no
better hypothesis to offer.

### 4. Operator practice note, for whatever it is worth

Both my false premises shared a shape: I reproduced a failure against an isolated component and
reported it as the system's cause. The one diagnostic that has actually been reliable is running the
real command and reading the typed failure it emits. When I next assert a root cause it should be
traced end to end through the executing path, or offered explicitly as a hypothesis with its test
stated.

## 2026-09-03T11:38Z — **ROOT CAUSE FOUND AND VERIFIED: override tier rejected for JSON key ORDER. One-line class of fix.**

The sole viable candidate route is blocked by an alphabetical key-ordering requirement on a JSON
object. Verified by direct reproduction with the live provider payload. Provider-free; ledger
unchanged at 57 entries / `0.68118684` USD.

### 1. The chain, fully traced

`PRICE_CAP_NOT_EXPRESSIBLE` / `PRICE_CAP_PROOF_UNAVAILABLE` are raised because
`route_constraints.py` short-circuits both predicates when `facts.pricing_schedule == "unavailable"`.
That value comes from `endpoint_snapshots.py:998` reading `tiered_pricing_cost_projection`, which
`_tiered_pricing_cost_projection` (`:1918`) sets to `"unavailable"` from a bare
`except (RouteConstraintError, ValueError)` that discards the cause.

The discarded cause is `OpenRouterPricingOverrideTier` validation:

```
Value error, endpoint pricing override fields must be sorted
```

### 2. Reproduced both ways

```
provider key order : ['prompt', 'completion', 'input_cache_read', 'input_cache_write']  -> REJECTED
sorted key order   : ['completion', 'input_cache_read', 'input_cache_write', 'prompt']  -> OK,
                     projection = SCHEDULE MMAUDIT_TIERED_MAXIMUM_RATE_V1
```

Everything downstream is already correct. With sorted keys the schedule builds and computes exactly
the operator-decided maximum-rate cap: `prompt 0.0000044`, `completion 0.0000132`,
`input_cache_read 0.0000011`, and `web_search 0.01` carried from base because the tier omits it, with
`projection_method='MMAUDIT_TIERED_MAXIMUM_RATE_V1'` and
`conservative_for_sub_threshold_prompts=True`. `normalize_exact_route_pricing`,
`ExactRoutePriceTier.build`, and `ExactRoutePricingSchedule.build` all succeed on the live data.

### 3. Why this is a defect, not a provider problem

JSON object key order is not semantically meaningful; `{"a":1,"b":2}` and `{"b":2,"a":1}` are the same
object. Requiring sorted input rejects well-formed provider data for a property the provider never
promised and cannot be expected to honour. Canonical ordering is something to **produce** when
serialising for a digest, not to **demand** on ingest. The base `pricing` object is already handled
correctly — `_validate_endpoint_pricing` iterates `sorted(value)` — so the tier validator is
inconsistent with the sibling code path immediately above it.

### 4. Requested — queued as `V3-PRICEKEYORDER-001`

Accept override tier fields in any key order and canonicalise by sorting on ingest, exactly as the
base pricing path already does. Keep every value-level guarantee unchanged: exact decimal strings,
range, finiteness, duplicate rejection, and the resulting canonical digest. Also surface the discarded
cause: `_tiered_pricing_cost_projection` should not collapse a specific validation error into
`"unavailable"`, which is what hid this for the entire investigation.

Expected outcome: `x-ai/grok-4.6=amazon-bedrock/us-west-2` becomes admissible and the campaign path
reopens. It is the only route of 112 surveyed live endpoints satisfying every substantive candidate
constraint.

## 2026-09-03T08:46Z — **RESPONSE-SHAPE DIAGNOSTIC: the premise was wrong. Billable prices are ALREADY exact decimal strings. The blocker is an `overrides` list.**

Codex requested a response-shape/value-kind diagnostic before any further work. Here it is, and it
**invalidates the premise of both `V3-PRICEFORM-001` and `V3-PRICELEXEME-001`**. Metadata-only, no
completion, ledger unchanged at 57 entries / `0.68118684` USD.

### 1. The live response for `x-ai/grok-4.6=amazon-bedrock/us-west-2`

`GET /api/v1/models/x-ai/grok-4.6/endpoints`, ordinary parse, value kinds of the `pricing` object:

| field | python type | value |
|---|---|---|
| `prompt` | **str** | `'0.0000022'` |
| `completion` | **str** | `'0.0000066'` |
| `input_cache_read` | **str** | `'0.00000055'` |
| `input_cache_write` | **str** | `'0'` |
| `web_search` | **str** | `'0.01'` |
| `discount` | int | `0` |
| `overrides` | **list** | `[{'min_prompt_tokens': 200000, 'prompt': '0.0000044', 'completion': '0.0000132', 'input_cache_read': '0.0000011', 'input_cache_write': '0'}]` |

**Every billable price is already an exact decimal string.** No billable price is a JSON number. There
is no float, no lexeme loss, and nothing for a decimal-capture mechanism to fix.

### 2. What actually fails

`_NON_BILLABLE_PRICING_METADATA` is `frozenset({"discount"})`, so `discount` is exempt.
`overrides` is **not** exempt, matches `_PRICING_FIELD_PATTERN`, and is a `list`. It therefore reaches
the billable-price branch, fails `isinstance(raw_price, str)`, has no captured token, and raises
`endpoint prices must be exact decimal strings` — a message that is accurate about the value but
misleading about the cause.

`overrides` is tiered pricing: an alternate price schedule above `200000` prompt tokens. Its nested
values are themselves exact decimal strings.

### 3. Operator error — recorded plainly

**This is my error, and it cost real work.** I asserted that this provider "publishes numeric prices"
without ever inspecting the response. `V3-PRICEFORM-001`'s decision explicitly rested on that
characterisation — "the operator-supplied directive classifies the sole otherwise-viable route's
billable price as a non-string numeric value" — and `V3-PRICELEXEME-001` was queued by me on the same
unverified premise. The resulting lexeme-custody mechanism is careful, well-guarded work built for a
problem that does not exist on this route. Codex reasoned correctly from a false premise I supplied.
The `V3-PRICEFORM-001` reasoning about binary floats also remains correct in general; it simply does
not apply here.

I should have run this diagnostic before writing either ticket. Elimination was available and cheap,
and I asserted instead.

### 4. What is actually needed

Queued as **`V3-PRICEOVERRIDES-001`**: handle a structured `overrides` tiered-pricing entry.
The nested objects contain genuine billable prices, so treating `overrides` as opaque non-billable
metadata would discard real cost information; validating its entries recursively as exact decimal
strings preserves both exactness and the tier data. Either way the fix is small and needs no decimal
capture.

`V3-PRICELEXEME-001` may be retained on its merits as defence-in-depth for providers that do publish
numeric prices, but it is **not** required to admit this route and should not block it.

If `overrides` is handled, `x-ai/grok-4.6=amazon-bedrock/us-west-2` — the sole route of 112 surveyed
endpoints satisfying every substantive candidate constraint — should become admissible, and the
campaign path reopens.

## 2026-09-03T08:24Z — **`V3-PRICELEXEME-001` PARTIAL TERMINAL: route still inadmissible. Likely cause: identity-keyed custody cannot cross the model-validation boundary**

Retested live after the terminal disposition. `x-ai/grok-4.6=amazon-bedrock/us-west-2` still fails
with the unchanged message. Provider-free; ledger unchanged at 57 entries / `0.68118684` USD.

### 1. One operator hypothesis tested and DISPROVEN

The recorded design binds custody to the "original unfiltered endpoint index" and permanently revokes
on relocation, which suggested discovery's single-endpoint selection might be read as tampering.
**That is not the cause.** Live enumeration places the viable route at **index 0** of five:

```
index 0: amazon-bedrock/us-west-2   zdr=True   <- the viable route
index 1: xai                        zdr=False
index 2: xai/priority               zdr=False
index 3: xai/zdr                    zdr=True
index 4: xai/zdr/priority           zdr=True
```

A first-position endpoint cannot relocate to a lower index, so index-relocation is eliminated.

### 2. Better hypothesis — flagged as a hypothesis, grounded in the ticket's own recorded design

The recorded result states captured tokens have "registry-only state **keyed by object identity**"
and that "**copied, serialized**, unregistered, float-transited, malformed, noncanonical, negative, or
out-of-range values fail closed."

Discovery does not hand the decoded payload straight to `_validate_endpoint_pricing`; it constructs
typed snapshot models from it. Pydantic validation **builds new objects** rather than preserving the
decoded instances. An identity-keyed registry therefore cannot survive that boundary: the value
arriving at the validator is a faithful copy, the registry lookup misses, and the strict check
correctly refuses it as unregistered.

This is consistent with every observation: `755` tests pass where the token reaches validation
directly, and the full `models discover` path fails, because only the latter crosses a model
construction boundary. It also explains why three successive rounds of *stricter* custody hardening
did not help — the failure is not tampering, it is faithful copying, which the design deliberately
treats as indistinguishable from tampering.

**Suggested direction, though the design is yours:** identity-keyed custody may be structurally
incompatible with a path that must reconstruct models. Carrying the captured exact decimal *as data*
alongside the payload — a parallel exact-price mapping keyed by layout and field rather than by object
identity, sealed and validated at the same boundary — would survive reconstruction while keeping the
same "no float ever transited" guarantee. A copy of a value is not evidence of tampering if the
exactness claim travels with the data rather than with the object.

### 3. Standing position

`V3-PRICELEXEME-001` is `PARTIAL TERMINAL` and its acceptance test — the route becomes admissible —
does not pass. The engineering here is genuinely good and the guards are right; the incompatibility is
architectural, not a coding error.

Unless this is resolved, the recorded conclusion stands: of 112 live endpoints across 12 models,
exactly one satisfies every substantive candidate constraint, and it cannot be admitted. No candidate,
no smoke, no campaign, `completed_real_audits` remains `0`, and no further operator action can change
that.

## 2026-09-02T13:51Z — **`V3-PRICELEXEME-001` mechanism landed and is sound, but the capture does not reach validation — live test, $0**

The lexeme-custody design is right and the guards are strict in the correct way. The live test still
fails, so the captured token is not surviving to the pricing validator. Provider-free; ledger
unchanged at 57 entries / `0.68118684` USD.

### 1. What landed, and why the design is right

`src/mmaudit/models/price_lexemes.py` introduces a decoder-issued `CapturedOpenRouterJSONNumber`
token. `captured_openrouter_json_number_raw` accepts **only** that exact type and explicitly rejects
bare `Decimal` and subclasses, so a value cannot masquerade as captured. `_request_metadata` selects
`_price_float_decoder`/`_price_int_decoder` and calls `_price_materializer` whenever a
`price_lexeme_layout` is supplied, and `MODEL_ENDPOINT_PRICE_LEXEME_LAYOUT` /
`ZDR_ENDPOINT_PRICE_LEXEME_LAYOUT` are passed at five call sites (`openrouter.py:11236, 11291, 11379,
11421, 11430`). `_validate_endpoint_pricing` now accepts a non-string price **only** via
`_captured_raw(...)`, still failing closed with the existing named reason when capture is absent.

That is exactly the shape requested: exactness made provable, requirement unchanged, no tolerance for
loss. **Existing sealed evidence still replays** — bundle
`29702a02f52626deca38ff36401eb3cb7bb4602f07677881760ad26ba40df5d4` verifies `VALID / NONCREDITING /
NONAUTHORIZING` with its closed 4-entry ledger unchanged, so byte-identity held.

### 2. The live test still fails, identically

Successor plan `b1880eb6ca8659ae9856ee9e14699a3bea5a974530c8843e4da2fe458040e383` emitted cleanly for
`x-ai/grok-4.6=amazon-bedrock/us-west-2` with `--refresh-endpoint-inventory`. Constrained discovery
then fails with the unchanged message:

```
mmaudit failed safely: endpoint prices must be exact decimal strings
```

By inspection that message is now reachable only at `endpoint_snapshots.py:1459`, i.e. after
`isinstance(raw_price, str)` is false **and** `_captured_raw(raw_price)` returned `None`. So the value
arriving at the validator is neither a string nor a genuine captured token.

### 3. Hypothesis — flagged as a hypothesis, not a finding

Capture is installed on the metadata **fetch**, but the constrained-snapshot path appears to receive
pricing through something that does not preserve the token. `models list-endpoints` fetches the same
endpoint metadata successfully for this route, so the fetch itself is not the problem; the difference
is that discovery additionally builds a constrained endpoint snapshot and validates pricing. The most
likely cause is an intermediate serialization, model validation, copy, or re-parse between fetch and
`_validate_endpoint_pricing` that reduces `CapturedOpenRouterJSONNumber` to a plain value — which the
deliberately strict type check then correctly refuses.

**Requested:** trace the payload from `_request_metadata` through constrained snapshot construction to
`_validate_endpoint_pricing` for a numeric-priced route, and confirm whether the token survives. If it
does not, either preserve it across that boundary or carry the captured lexeme alongside the payload
so validation can still prove exactness. A provider-free regression using a recorded numeric-priced
fixture driven through the **full discovery path** — not the validator in isolation — would have
caught this and should be added.

### 4. Status

`V3-PRICELEXEME-001` is recorded `COMPLETE`, but the acceptance test in its own ticket — that the
route becomes admissible — does not pass. Suggest reopening as `PARTIAL`. This is the same pattern as
`V3-CANDROUTE-001`: mechanism complete, real-route restoration unproven, and only an operator live run
can distinguish the two. Nothing else is blocked behind anything else: this single route is still the
only one of 112 surveyed endpoints satisfying every substantive candidate constraint, and
`completed_real_audits` remains `0`.

## 2026-09-01T04:49Z — **OPERATOR DECISION: pursue lossless price-lexeme custody. The V3-PRICEFORM-001 refusal is upheld, and answered.**

Both outstanding questions were answered by Codex, both correctly. This entry records the operator
decision on what follows, and supplies the technical fact that resolves the remaining one. No spend;
ledger unchanged at 57 entries / `0.68118684` USD.

### 1. Both refusals are accepted

`REASONING_EFFORT_SUPPORT` is genuinely required of the candidate role — the candidate is sealed to
the `model_benchmark` reasoning policy that emits `effort=high` and reserves reasoning tokens, so a
route without published support would silently ignore an emitted control and break request/budget
parity. Accepted; `gemma-4-26b-a4b-it` and `minimax-m3` are genuinely out, not out on a technicality.

`V3-PRICEFORM-001` rejection also stands **under the custody model as it exists today**, and its
reasoning is exactly right: after ordinary JSON parsing the original decimal lexeme is gone, and
`Decimal(str(value))` proves only the chosen reserialization, not identity to the provider's decimal.
The earlier operator proposal to admit "numerics that convert without loss" was unsound and is
withdrawn.

### 2. The operator decision

**Pursue lossless price-lexeme custody. Do not relax the exactness requirement, and do not revisit the
frozen objective's constraint set to unblock a campaign.**

Of the three available paths — weaken a constraint, wait for provider metadata to change, or make
exactness provable — only the third is compatible with the product's core claim. A constraint relaxed
to admit a candidate is precisely the failure this system exists to prevent.

### 3. The technical fact that resolves it

The lexeme is only destroyed because the pricing path uses ordinary JSON number parsing. It need not.
Verified operator-side `2026-09-01`:

```
json.loads('{"prompt": 0.0000012}')                      -> float, exact value
  0.00000119999999999999994569773419106351042273672646842896938323974609375
json.loads('{"prompt": 0.0000012}', parse_float=Decimal) -> Decimal('0.0000012')
```

With `parse_float=Decimal` the number never transits a binary float, and the provider's original
decimal is preserved exactly — the same guarantee a string price already carries, obtained by not
discarding the evidence rather than by reconstructing it.

Queued as **`V3-PRICELEXEME-001`**. It honours the `V3-PRICEFORM-001` decision rather than overturning
it: the *requirement* is unchanged and still fails closed; only the *custody model* changes, so that
exactness becomes demonstrable for numeric-valued prices. Existing sealed evidence must remain
byte-identical and continue to replay.

If implemented, `x-ai/grok-4.6=amazon-bedrock/us-west-2` — the sole route satisfying every substantive
candidate constraint — becomes admissible, and the campaign path reopens. If it cannot be implemented
soundly, then the recorded conclusion stands unchanged: under the current constraint set no admissible
candidate route exists, and that is a finding about the objective rather than a defect.

## 2026-08-30T19:00Z — **`list-endpoints` WORKS. Live survey of 112 endpoints across 12 models: still NO admissible candidate**

`V3-ENDPOINTLIST-001` works and was exercised live — the enumeration Codex could not run. The result
is a complete, evidence-based picture of why no candidate is admissible. All provider-free; ledger
unchanged at 57 entries / `0.68118684` USD.

### 1. Live endpoint survey

| model | endpoints | native structured output | endpoint-level reasoning inventory |
|---|---|---|---|
| `deepseek/deepseek-v4-pro-0813` | 16 | 8 | **0** |
| `z-ai/glm-5.2` | 33 | 28 | **0** |
| `moonshotai/kimi-k3` | 17 | 16 | **0** |
| `minimax/minimax-m3` | 11 | 3 | **0** |
| `google/gemma-4-26b-a4b-it` | 9 | 7 | **0** |
| `tencent/hy3` | 7 | 1 | **0** |
| `x-ai/grok-4.6` | 5 | 5 | **0** |
| `google/gemini-3.7-flash` | 6 | 6 | **0** |
| `anthropic/claude-opus-5` | 9 | 6 | **0** |
| `openai/gpt-5.6-sol` | 7 | 6 | **0** |
| `qwen/qwen3.8-max`, `meta/muse-spark-1.2` | 1 each | 1 each | **0** |

**Endpoint-level reasoning-effort inventory is absent on all 112 endpoints of all 12 models**,
including the two judges that currently pass and the candidate that previously passed.

### 2. Consequent gap in `list-endpoints`

Admission does **not** use the endpoint-level value alone. `_reasoning_effort_result`
(`route_constraints.py`) reads
`effective = endpoint_supported_reasoning_efforts if not None else model_supported_reasoning_efforts`,
so a route is admissible when the **model-level** inventory exists even though the endpoint-level one
does not. `list-endpoints` reports only the endpoint-level field, so its reasoning-effort column
cannot discriminate admissible from inadmissible routes — `deepseek` shows `0/16` and passes, `gemma`
shows `0/9` and fails. **Request:** add the model-level inventory (and the effective resolved value)
to the enumeration output, otherwise the command cannot serve the purpose it was built for.

### 3. Live routes tested through successor + constrained discovery

Using real `selection_arguments` from the enumeration, with `--refresh-endpoint-inventory`:

| route | outcome |
|---|---|
| `x-ai/grok-4.6=amazon-bedrock/us-west-2` | `endpoint prices must be exact decimal strings` |
| `anthropic/claude-opus-5=anthropic` | endpoint absent from the exact-model ZDR snapshot |
| `google/gemma-4-26b-a4b-it=google-vertex/global` | constrained predicate failure |
| `google/gemma-4-26b-a4b-it=parasail/bf16` | constrained predicate failure |

`google/gemini-3.7-flash` and `openai/gpt-5.6-sol` have **zero** endpoints that are simultaneously
operational, natively structured-output capable, and unambiguously routed, so neither has a testable
route at all.

### 4. Standing conclusion

**No admissible candidate exists**, and the binding constraints are now identified in order of impact:

1. **Model-level reasoning-effort inventory absent** — the sole failure for `gemma-4-26b-a4b-it` and
   `minimax-m3`, both otherwise clean and both lineage-independent of the judges. Still the single
   highest-leverage question: is `REASONING_EFFORT_SUPPORT` genuinely required of a **candidate**, or
   is it a judge-role requirement applied to all four purposes? It remains required for all four and
   is not role-scoped. `V3-CANDROUTE-001` is `PARTIAL` and this question is still unanswered.
2. **ZDR unavailable** — `claude-opus-5`, `gemini-3.7-flash`, `muse-spark-1.2`.
3. **Pricing metadata not exact decimal strings** — `grok-4.6=amazon-bedrock/us-west-2`.
4. **Structured-output mode unsupported** — `tencent/hy3`.

This may be the constraint set correctly refusing everything currently on offer rather than a defect.
If so, that is itself a product finding worth recording: under the present constraints the frozen
objective has no eligible candidate, and either a constraint is role-scoped with recorded rationale or
the campaign cannot proceed. `completed_real_audits` remains `0`.

## 2026-08-30T15:18Z — **V3-PLANSUCCESSOR-001 WORKS. But NO candidate route is admissible — complete sweep, $0**

Successor plans emit and bind correctly. A full constrained sweep of **every** plan-allowed candidate
route then found **zero admissible candidates**. Provider-free throughout; ledger unchanged at 57
entries / `0.68118684` USD.

### 1. Plan succession is correct

`models emit-selection-plan-successor` produced
`00b6aa8fb1d23640a6b65dae7883d7265e416b9ba4383c3240329e62500f34b3` from predecessor
`bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f`, naming the new candidate and
carrying both judge constraints forward unchanged, with the predecessor digest recorded. Constrained
discovery then correctly evaluates the replacement instead of emitting unconstrained evidence.

**A correction to the previous operator entry:** the two "viable" candidates reported there were
found with the **predecessor** plan, i.e. unconstrained for those routes. Under constrained discovery
both fail. Unconstrained discovery passing is not evidence of admissibility, and that entry
overstated the result.

### 2. Complete constrained sweep — every plan-allowed candidate route

| route | outcome |
|---|---|
| `deepseek/deepseek-v4-pro-0813=parasail/fp8` | REVOKED — `EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE` |
| `google/gemma-4-26b-a4b-it=deepinfra/fp8` | `REASONING_EFFORT_INVENTORY_UNAVAILABLE` |
| `minimax/minimax-m3=coreweave/fp4` | `REASONING_EFFORT_INVENTORY_UNAVAILABLE` |
| `tencent/hy3=novita` | endpoint lacks the required structured-output mode |
| `qwen/qwen3.8-max=alibaba` | endpoint absent from the exact-model ZDR snapshot |
| `anthropic/claude-opus-5=amazon-bedrock` | provider display name is ambiguous |
| `openai/gpt-5.6-sol=novita` | catalog metadata omits the required request parameters |
| `google/gemini-3.7-flash` (novita, deepinfra, google-vertex) | endpoint tag or slug unavailable |
| `x-ai/grok-4.6` (novita, together) | endpoint tag or slug unavailable |
| `meta/muse-spark-1.2` (novita, together, deepinfra) | endpoint tag or slug unavailable |

`minimax-m3` on `deepinfra/fp8` and `parasail/fp8` was refused at successor emission because those
endpoints are outside its plan `allowed_provider_endpoints`, so routes cannot simply be invented.

### 3. The two highest-leverage observations

**(a) `REASONING_EFFORT_SUPPORT` is required for all four `RouteConstraintPurpose` values and is not
role-scoped.** It is the *sole* failure for `gemma-4-26b-a4b-it` and `minimax-m3` — two routes that
are otherwise clean and whose Google and MiniMax lineages are both independent of the `z-ai` primary
judge and `moonshotai` replay judge. If reasoning effort is not semantically required of a
**candidate** — as opposed to a judge — role-scoping that predicate restores two candidates
immediately. **If it is genuinely required, say so and record why; this must not be relaxed for
convenience.** This is the single question most worth answering.

**(b) The plan's `allowed_provider_endpoints` are stale.** `gemini-3.7-flash`, `grok-4.6` and
`muse-spark-1.2` name slugs that no longer exist, so three models cannot be evaluated on their merits
at all. This is the same staleness previously recorded for `gpt-5.6-sol`.

### 4. Requested

Queued as **`V3-CANDROUTE-001`**. Primary acceptance test: at least one lineage-independent candidate
passes constrained discovery **and** a provider-free live-route gate. Settle the reasoning-effort
question first and record the answer.

Until an admissible candidate exists, no smoke, no campaign, and no movement on
`completed_real_audits`, which remains `0`.

## 2026-08-28T12:56Z — **REVOCATION RECONCILED AND WORKING; replacement candidates still unusable — plan succession needed**

`V3-REVOKERECON-001` works. Two viable replacement candidates were found. **They still cannot be
used**, for a second and distinct reason. All provider-free; ledger unchanged at 57 entries /
`0.68118684` USD.

### 1. The reconciliation is correct

Acceptance test passes. The revoked route still fails closed, now with a fully named reason —
a real diagnosability improvement:

```
candidate selection assignment is revoked: role=candidate;
model=deepseek/deepseek-v4-pro-0813; endpoint=parasail/fp8;
reason=EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE
```

And unrevoked alternatives are no longer refused by revocation:

| route | discovery |
|---|---|
| `google/gemma-4-26b-a4b-it=deepinfra/fp8` | **PASS** |
| `tencent/hy3=novita` | **PASS** |
| `minimax/minimax-m3=coreweave/fp4` | fails `configured endpoint is not operational` — ordinary drift, not revocation |
| `deepseek/deepseek-v4-pro-0813=parasail/fp8` | correctly revoked |

Both passing candidates satisfy lineage independence against the Zhipu primary judge and Moonshot
replay judge, and both have documentary lineage sources already sealed in the public-lineage bundle
(`google-deepmind` gemma-4-26B-A4B-it, `tencent` Hy3).

### 2. But a replacement cannot reach a gate

`google/gemma-4-26b-a4b-it=deepinfra/fp8` was discovered fresh alongside both judges, all three
`PASS`. The live-route gate then refuses:

```
mmaudit failed safely: authenticated runner route lacks constrained discovery evidence
```

`route_admission.py:648-655` requires the endpoint snapshot to carry `route_predicate_profile`,
`exact_route_constraint`, `normalized_route_facts`, and `route_predicate_report`. Direct comparison of
the two discovery artifacts:

- plan-pinned `deepseek` (`r23`): **all four present**
- replacement `gemma` (`g24`): **none of the four present**

Discovery emits *constrained* route evidence only for routes named in the plan's
`authenticated_runner_selection.route_constraints`, and that list still contains only
`deepseek/deepseek-v4-pro-0813=parasail/fp8` for `role=candidate`. So a replacement discovers
successfully and is then structurally inadmissible.

### 3. Operator error to record

The `V3-REVOKERECON-001` acceptance test as written asked only that discovery for an unrevoked
candidate **succeed**. It does. The test was under-specified: it should have required the replacement
to be **usable** — to reach a successful live-route gate. That gap is the operator's, not Codex's, and
`V3-PLANSUCCESSOR-001` now states the stronger test explicitly.

### 4. Requested

Queued as **`V3-PLANSUCCESSOR-001`** in `docs/codex_work_queue.md`: a deterministic, hash-custodied
path to emit a successor selection plan whose candidate constraint names a live unrevoked route,
carrying judge constraints forward unchanged, with revocation remaining non-bypassable and the
predecessor digest recorded. Primary acceptance test: **a provider-free live-route gate for the
replacement candidate succeeds.**

Candidate choice itself remains an operator decision. Once a replacement is admissible, the plan is
to measure first-attempt structured-output conformance empirically across several `$0.04` smokes
before committing to a campaign — advertised `structured_outputs` has now been demonstrated worthless
as a predictor, and `structured_output_compliance` is gated at `1.0` across all 24 cases, which
requires roughly `99%`+ per-request reliability to pass with any consistency.

## 2026-08-28T07:56Z — **REGRESSION: candidate revocation deadlocks ALL candidate discovery; reselection sweep cannot run**

The operator authorized a candidate reselection sweep. **It cannot run.** Candidate revocation landed
correctly but was not reconciled with the pinned selection plan, and the combination now refuses every
candidate discovery, including replacements. All provider-free; ledger unchanged at 57 entries /
`0.68118684` USD.

### 1. The revocation itself is correct

`src/mmaudit/resources/candidate-selection-revocations.json` holds exactly **one** entry:
`role=candidate`, `deepseek/deepseek-v4-pro-0813`, `parasail/fp8`, reason
`EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE`. That is precisely the route that failed the campaign at
~`37%` structured-output nonconformance. Surgical and right.

### 2. But the pinned plan still names that exact route

`config/models.selection-plan.json` (`plan_sha256 bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f`)
carries four `authenticated_runner_selection.route_constraints`, the first of which is:

```
role=candidate  exact_model_id=deepseek/deepseek-v4-pro-0813  provider_endpoint=parasail/fp8
```

`_require_unrevoked_routes` iterates **every** route in the validated set, so validating the plan trips
the revoked entry regardless of which candidate the operator actually requested.

### 3. Observed effect — every candidate is refused

| requested candidate | result |
|---|---|
| `minimax/minimax-m3=coreweave/fp4` | `candidate selection plan is not currently eligible: candidate selection route is revoked` |
| `google/gemma-4-26b-a4b-it=deepinfra/fp8` | same |
| `tencent/hy3=novita` | same |
| `deepseek/deepseek-v4-pro-0813=parasail/fp8` | `candidate discovery candidate assignment is ineligible: candidate selection assignment is revoked` |

The incumbent is correctly refused by assignment. **Every alternative is incorrectly refused by the
plan's route set.** Candidate reselection — the one action the campaign failure made mandatory — is
therefore impossible, and so is any further discovery, smoke, or campaign.

### 4. Why the operator cannot work around it

The plan is hash-pinned via `plan_sha256`, so hand-editing `route_constraints` invalidates it, and no
repository CLI emits or regenerates a selection plan (`--candidate-selection-plan` only consumes one).
This needs product code.

### 5. Requested

Reconcile revocation with plan selection. Suggested shape, but the design is yours: revocation should
disqualify a route **from being selected**, not invalidate a plan that merely lists it — e.g. evaluate
revocation against the route actually being assigned rather than the plan's full constraint set, and/or
provide a supported path to emit a successor plan whose candidate constraint names a live route.
Whichever way, the acceptance test is: with `deepseek=parasail/fp8` revoked, a discovery for a
different, unrevoked candidate must succeed.

Until then the build cannot progress: `completed_real_audits` stays `0`, and every downstream item
(campaign, calibration, AUTHSEAL, benchmark, release) is gated behind candidate selection.

## 2026-08-27T17:22Z — **FIRST REAL 24-CASE CAMPAIGN LAUNCHED AND FAILED CLOSED — candidate reselection required**

The 24-case campaign was operator-authorized and launched against live providers. It **failed closed**
after roughly `24` logical requests for **`0.20264508`** USD. Every structural layer worked; the
**candidate model** is the sole cause. `completed_real_audits` remains **0**, which is correct.

### 1. What ran

Full chain cleared for the first time: materialized qualification policy → fresh `r23` discovery for
all three roles → live-route gate `VALID` → paid smoke index `22` (`0.04395915` USD, bundle
`29702a02f52626deca38ff36401eb3cb7bb4602f07677881760ad26ba40df5d4`, verified `VALID / NONCREDITING /
NONAUTHORIZING` offline) → `FULL_CAMPAIGN_ADMISSION` satisfied via that bundle → campaign launch.

Preflight inventory: `runs=2; cases=24; candidate_logical_requests=48; judge_logical_requests=48;
logical_requests=96`. Candidate `derived_interval_cap_usd=5.03716224`.

### 2. How it failed

```
Structured model request failed                                            x9
Configured model failed; considering the next explicit fallback            x9
Completed response identity is unbound; preserving evidence without ...    x15
mmaudit failed safely: REAL candidate report content lacks owned runtime execution provenance
```

Terminal raise at `benchmark/model_portfolio.py:2420`.

**The candidate failed structured output on `9` of roughly `24` requests — about `37%`**, materially
worse than the ~`20%` previously observed for `deepseek/deepseek-v4-pro-0813` via `parasail/fp8`.

**Schema retry could not engage.** `config/openrouter-qualification.toml` carries
`max_schema_validation_retries = 0` because that file is hash-pinned and
`test_schema_validation_retry_is_default_off_without_changing_qualification_hash` forbids changing it.
Each schema failure therefore fell through to "the next explicit fallback", which does not exist on a
singleton pinned route. **The retry pin conflict recorded on `2026-08-25` is now demonstrated live
rather than argued**: the operator's retry decision is unreachable for this campaign until a
re-pinned config or a separate non-pinned continuity path exists.

### 3. What worked — worth recording precisely

Authentication, provider pinning, `r23` route binding, runtime-evidence admission through the new
`V3-RUNTIMEADMIT-001` mechanism, cost reserve→spend→reconcile, and fail-closed termination all
behaved correctly. **All `24` new ledger entries are `reconciled`**; the only two
`uncertain_accounted` entries remain the historical pair from index 17. The system refused to
manufacture a result from degraded evidence and stopped for `$0.20`. Ledger now `57` entries /
`0.68118684` USD against the `250` cap.

### 4. Two items for Codex

1. **`Completed response identity is unbound` fired 15 times.** That is more than the schema failures
   and is a distinct condition from `SCHEMA_VALIDATION_FAILED`. Is unbound generation identity
   expected at this rate on a healthy route, or is it a second defect? It is currently handled by
   preserving evidence without fallback, so it may be silently degrading candidate reports before the
   provenance check rejects them.
2. **Candidate reselection is now empirically required**, not merely advisable. Three independent
   mechanisms converge on it: the `EMPIRICAL_SCHEMA_CONFORMANCE` predicate, the first-attempt-only
   scoring decision, and now a live campaign failure. A route advertising `structured_outputs` is
   demonstrably not evidence that it honours a schema contract, so any replacement must be validated
   empirically before a campaign, not selected from metadata flags.

No further paid attempt should use this candidate.

## 2026-08-27T10:28Z — **V3-RUNTIMEADMIT-001 WORKS: schema conformance now SATISFIED; token-detail isolated to one clause**

`V3-RUNTIMEADMIT-001` is verified working against real sealed evidence. `EMPIRICAL_SCHEMA_CONFORMANCE`
now **passes**. One predicate remains, and it is isolated to a single equality. All provider-free;
ledger unchanged at 29 entries / `0.43458261` USD. No smoke run was launched — see §4 for why.

### 1. The mechanism works, and the diagnostics are transformative

`RoutePredicateRequirementError` now renders `purpose=...; failures=<id>=<reason>,...`. Four distinct
states were distinguished in minutes, where the previous message named none of them:

| inputs | result |
|---|---|
| no runtime evidence | `EMPIRICAL_SCHEMA_CONFORMANCE=EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE`, `TOKEN_DETAIL_REPORTING_CONVENTION=TOKEN_DETAIL_CONVENTION_UNAVAILABLE` |
| index-19 bundle | `authenticated runner smoke evidence cannot prove exact runtime predicates` |
| index-21 bundle + **r22** registries | both `=RUNTIME_EVIDENCE_BINDING_MISMATCH` |
| index-21 bundle + **r21** registries | **schema conformance SATISFIED**; only `TOKEN_DETAIL_REPORTING_CONVENTION=RUNTIME_EVIDENCE_INVALID` |

### 2. Index-19 is permanently unusable as runtime evidence

Its `CandidateModel` records do not carry the four route-custody fields **at all** — not null, absent
from the serialized model. Custody entered `candidate_selection.py` at `7ef4717`
(`Enforce route constraint parity`, `2026-08-24`), after that run. Index 21 carries all `4/4`.
Only index 21 is admissible, and only against the `r21` registries it was produced from.

### 3. Token detail fails on exactly one equality, in all four usages

`_token_detail_proof_is_valid` (`route_runtime_evidence.py:375`) has ten conjuncts. Nine pass for
**every** usage — primary/candidate, primary/judge, replay/candidate, replay/judge — including
`accounting_method`, `completion_semantics`, `accounting_basis`, `provider_total_relation`,
`request_body_sha256`, the raw plan dict, and `evidence.request_token_plan_sha256 ==
usage.routing["request_token_plan_sha256"]`.

The sole failure, uniformly:

```
item.plan.request_preview.request_token_plan_projection_sha256 == evidence.request_token_plan_sha256
```

Usage and evidence agree with each other; the **cost-plan preview projection** disagrees with both.

**Hypothesis requiring Codex's confirmation — flagged as a hypothesis, not a finding.**
`request_token_plan_projection_sha256` is produced by
`_candidate_review_request_token_plan_projection_sha256` (`openrouter.py:2076`), which is a different
computation from the plain `request_token_plan_sha256`. If those two are structurally different
digests over different payloads, this conjunct can never be true for any bundle, and
`TOKEN_DETAIL_REPORTING_CONVENTION` is unsatisfiable by construction — the same class of defect this
ticket was raised to fix. The alternative is that they coincide only under conditions the index-21
run did not meet. **Please determine which, and add a regression pinning the intended relation.**

### 4. Why no smoke run was launched

Index 22 is pre-authorized and costs about `$0.04`, and a fresh bundle is the obvious next step. It
was **not** run because if the §3 hypothesis is correct the defect is in the comparison, not the
evidence, so a new run reproduces the identical failure and spends real money to learn nothing.
Resolve §3 first. If the relation is sound and index 21 simply predates it, say so and a fresh
smoke will be run immediately at `$0.04`, followed by the campaign preflight.

### 5. Standing inputs, ready to use

- Qualification policy materialized at `~/.mmaudit/private/qualification-policy.json`, `2248` bytes,
  mode `0600`, `policy_sha256 1df14052…`. Accepted by preflight.
- Fresh `r22` registries and discovery runs exist for all three roles (`2026-08-27`), but note that
  runtime evidence must bind to the registry generation that produced it — `r22` needs an `r22`-era
  bundle.
- `r21` registries plus the index-21 bundle are the only currently self-consistent pair.

## 2026-08-27T06:37Z — **CAMPAIGN BLOCKER FULLY TRACED: two admission predicates have no satisfying code path**

The qualification-policy blocker reported on `2026-08-25` is **cleared**. The campaign now fails at a
later, different, and final gate. All work below was provider-free; the ledger is unchanged at 29
entries / `0.43458261` USD.

### 1. Qualification policy — resolved

The embedded `qualification_policy` object in `benchmarks/model_corpus/verdict_policy.json` carries
`policy_sha256 = 1df14052e97a8ceb2cf3ec9fd25637f5f2f3a821818a54382a7c1f241059da8c`, which is exactly
the pinned C1 value. `_require_qualification_release_pins` binds `policy.policy_sha256`, the value
**inside** the object, not the file digest — so materializing the object to a bounded unshared regular
file is sufficient. Written to `~/.mmaudit/private/qualification-policy.json`, mode `0600`, `2248`
bytes, single link. The preflight now passes the qualification stage. Codex's earlier note that "no
repository CLI materializer exists and this immediate remedy is unproven" was correct that none
exists; the remedy is now proven.

### 2. Fresh `r22` evidence — the working triple is still live

All three roles re-discovered at `$0` on `2026-08-27` under the current constraint system:

| role | route | registry | frozen sha256 |
|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813=parasail/fp8` | `candidate-registry-r22.json` | `d828e6b77fb16fbc4bd980f2fcd6e610394b915e33915864714b68d2ce205bc7` |
| primary | `z-ai/glm-5.2=sail-research/fp8` | `primary-judge-registry-r22.json` | `db75dcbcfcdde75b95d64e0e66be224a650896ba5b4829e25b04f1effda0d0f4` |
| replay | `moonshotai/kimi-k3=modal/mxfp4` | `replay-judge-registry-r22.json` | `73550667098aa0b96bfd35019a52fdd8b30c91ff680068a1f2b6ccfce45416a9` |

Discovery runs `authrunner-{candidate,primary-judge,replay-judge}-20260827-r22`.

### 3. The actual blocker

With a valid policy and fresh `r22` evidence the preflight fails with:

```
mmaudit failed safely: route predicate report does not satisfy its closed purpose
```

Raised at `route_constraints.py:723`. `FULL_CAMPAIGN_ADMISSION` requires `28` predicates against
`NONCREDITING_SMOKE_ADMISSION`'s `27`. The exact difference:

- **required only by the campaign:** `EMPIRICAL_SCHEMA_CONFORMANCE`, `TOKEN_DETAIL_REPORTING_CONVENTION`
- **required only by smoke:** `FROZEN_LIVE_EQUIVALENCE`

Both campaign-only predicates are members of `_SEPARATE_RUNTIME_PREDICATES`, are excluded from
`_DISCOVERY_REQUIRED`, and are emitted **unconditionally** as `_unavailable_result` at
`route_constraints.py:1245-1252` with reasons `EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE` and
`TOKEN_DETAIL_CONVENTION_UNAVAILABLE`.

**Both predicate ids appear only in `route_constraints.py`. No code path anywhere under `src/` can
set either to `SATISFIED`.** The 24-case campaign is therefore unreachable *by construction*, not by
policy, stale evidence, missing authorization, or absent budget. This is the same pair the worklog
referred to as "the unresolved empirical schema and token-detail gates still prohibit any campaign";
this record establishes that no mechanism to resolve them exists yet.

Queued as **`V3-RUNTIMEADMIT-001`** in `docs/codex_work_queue.md`. It also asks that
`RoutePredicateRequirementError` surface the failing predicate ids and reasons — the current message
names neither, and identifying this pair required reading the purpose matrix directly.

### 4. Retry decision CANNOT be enabled on the qualification campaign — pin conflict

`V3-RETRY-001` is `COMPLETE` at `4f666d0` and its `129` focused tests pass. Attempting to honour the
`2026-08-25` operator retry decision by setting `max_schema_validation_retries = 3` in
`config/openrouter-qualification.toml` **failed two regressions** and was reverted; the file is
unchanged.

`test_schema_validation_retry_is_default_off_without_changing_qualification_hash`
(`tests/unit/test_config.py:99`) asserts that the qualification config loads with
`max_schema_validation_retries == 0` and that the field is **absent** from
`model_dump`, `model_dump_json`, and `canonical_audit_config_json`. That is the point of the
`exclude_if=lambda value: value == 0` declaration: the retry feature must not perturb the canonical
qualification config hash that release pins bind. Setting it there would silently invalidate frozen
release evidence.

**Consequence:** the operator's retry decision is implemented but is **not applicable to the
hash-pinned qualification campaign** as things stand. Enabling it there requires either a deliberate
re-pin of the qualification config (a release-level action with its own evidence) or a separate
non-pinned execution path for campaign continuity. That is a product decision for codex, not an
operator config edit, and it should be resolved alongside `V3-RUNTIMEADMIT-001`. Recording the
intended value for whenever a mechanism exists: `3` schema retries, which at the observed ~`0.2`
per-attempt failure rate leaves roughly `0.16%` residual failure per logical request, so a ~48-request
campaign completes without a schema-induced abort about `93%` of the time.

Note the convergence worth recording: `EMPIRICAL_SCHEMA_CONFORMANCE` and the first-attempt scoring
decision independently disqualify the **same** candidate for the **same** reason. A route that emits
schema-invalid output roughly one attempt in five cannot honestly satisfy an empirical schema
conformance predicate. Candidate reselection is likely required regardless of how
`V3-RUNTIMEADMIT-001` is implemented.

## 2026-08-25T09:30Z — **OPERATOR DECISION: first-attempt-only structured-output scoring; calibration evidence scope**

Two operator decisions, both binding. No command was run and no spend occurred; the ledger remains
29 entries / `0.43458261` USD.

### 1. `structured_output_compliance` is scored on the FIRST ATTEMPT only

A retried success earns **no** compliance credit.

Rationale: a gate fixed at `1.0` that tolerates retries is not a `1.0` gate — it is a `1.0` gate on a
weaker predicate, mislabelled. "Eventually emits schema-valid output given enough attempts" is
satisfied by essentially any model, so as a gate it is vacuous. This dimension is one of the three
deliberately held at `1.0` *because determinism is required*; a retry-tolerant determinism gate is a
contradiction in terms. It also carries the corpus's largest denominator (`24` of `24`, against `4`
for the judgment dimensions), so unlike those, a threshold here is genuinely measurable.

If a retry-tolerant metric is wanted later it must be a **separately named dimension** with its own
derived threshold. It must not overload this gate.

**Direct consequence, stated plainly:** `deepseek/deepseek-v4-pro-0813` via `parasail/fp8` returned
schema-invalid structured output on roughly `2` of `10` observed attempts, and smoke run index `18`
terminated `SCHEMA_VALIDATION_FAILED`. At approximately `0.8` first-attempt compliance against a
`1.0` gate, **the current candidate does not qualify** and must be reselected, or the gate must be
lowered by an explicit, recorded decision and thereby cease to be a determinism gate. Reselection is
a `$0` metadata exercise. This is the correct outcome: a model that violates the structured-output
contract one time in five is not a suitable deterministic-contract candidate for an audit product,
and surfacing that is preferable to masking it behind retries.

Retry itself remains authorized and is queued as `V3-RETRY-001` in `docs/codex_work_queue.md`. Its
purpose is narrow: prevent a multi-case campaign terminating on one recoverable schema miss, so the
remaining dimensions still produce measurements. Its acceptance criteria now require attempt
provenance to be preserved in durable evidence so scoring can separate first-attempt from retried
success. Retry must never be able to launder a compliance failure.

### 2. Calibration evidence scope — what it can and cannot support

The frozen objective re-expresses "superiority" as cross-lineage benchmark performance. That is an
internally-relative measure: candidates judged by other lineages on this project's own corpus. It is
a real and verifiable property and it is **not** a best-in-class claim, because it contains no
comparator external to the system. These must not be conflated in any published artifact.

The schema-v2 derivation machinery is sound for its actual purpose — deriving a meaningful
qualification filter. It cannot support a superiority claim, and the queue already says so: four
cases per judgment dimension "cannot support a broad statistical claim", and the cutoffs are
"explicitly empirical support cutoffs, not statistical-significance claims". At `n=4` the
greatest-supported-non-perfect rule lands on `0.75`, where a single case separates pass from fail.

A genuine best-in-class claim would require four things this project does not currently have:
per-dimension depth on the order of `30`+ observations rather than `4`; a contamination-controlled
partition of newly-constructed post-training-cutoff synthetic targets, sized to carry the claim
alone, with any public partition reported separately as contaminated; a comparator external to this
corpus, which is what `V3-HUMANCMP-001` already specifies correctly; and publish-regardless
pre-registration with terms frozen before the run.

None of that is a completion blocker under the frozen objective. It is a constraint on what may be
claimed. The recorded `superiority_status: NOT_DEMONSTRATED` and `release_status: INCOMPLETE` are
correct and must not be advanced on cross-lineage benchmark evidence alone.

## 2026-08-25T05:16Z — **24-CASE CAMPAIGN CANNOT LAUNCH: BLOCKED ON A MISSING QUALIFICATION POLICY**

The operator authorized the 24-case campaign. It cannot start. This is not a spend or authorization
problem — a required input does not exist. Verified provider-free at **$0**; ledger unchanged at 29
entries / `0.43458261` USD throughout everything below.

### 1. The blocker (primary finding)

`models authenticated-runner --preflight-only` (corpus defaults, `--allow-code-egress`, r21 registries
and discovery runs for all three roles) refuses with:

```
mmaudit failed safely: qualification input is unavailable
```

Traced to `qualification.py:5316` — a failed `path.stat()` inside `_load_model`, i.e. the
`--qualification-policy` file simply does not exist. Searched exhaustively:

- not in `~/.mmaudit/private/` (no calibration output of any kind exists there)
- never committed on **any** branch — `git log --all --diff-filter=A` finds no policy instance
  outside `schemas/` and one test file
- absent from all four worktrees

`write_calibrated_qualification_policy` produces this artifact, so the campaign is gated on
**`V3-CALIBRATE-001`**, whose recorded block is: *"Current-objective completion requires measured
constructed/public frozen ground truth, cross-lineage automated adjudication, and REAL calibration
evidence."*

**Calibration is now the critical path to `completed_real_audits > 0`.** The AUTHRUNNER smoke path is
proven twice and is not the constraint. Please state what specifically is needed to produce a frozen
qualification policy, and whether the two-campaign bridge already implemented under `V3-CALIBRATE-001`
can be driven from the sealed r21 bundle. If it needs an operator command, name it and I will run it.

Separately: the scoped permission rule covers only `authenticated-runner-smoke`, so the campaign will
need a fresh operator authorization even once unblocked. Cost projection when it unblocks: the r21
1-case run was **$0.0384** actual across 4 logical requests, so 24 cases is ~$0.92 linear; real audit
outputs are far longer than smoke outputs, so $1–3 remains the honest range.

### 2. Operator decision — **retry** on schema-invalid candidate output

The operator chose **retry** for the `deepseek-v4-pro-0813=parasail/fp8` structured-output failures
(run index 18 failed `SCHEMA_VALIDATION_FAILED`).

`config/openrouter-qualification.toml` sets `max_model_retries = 1` (→ 2 attempts; the field caps at
5). But both sealed bundles record `maximum_attempts=2, attempts=1` — **no retry has ever actually
fired in sealed evidence**, so raising the number is unproven, not a fix.

**Question, stated as a hypothesis I could not settle from source:** the loop at `openrouter.py:15270`
catches `OpenRouterSchemaError` and advances to the *next fallback model*, not a retry of the same
route. Is a schema-invalid structured response classified as retryable **within** the per-request
attempt loop, or does it terminate the logical request? If it is not retryable in-request, raising
`max_model_retries` will do nothing for this failure mode at 24 cases and the operator's decision needs
a code change to honour. I have not changed the config; say which value you want and I will set it.

### 3. Operator decision — evidence-standard scope: drop Opus 4.6, **admit `openai/gpt-5.6-sol` if possible**

The operator has ruled `anthropic/claude-opus-4.6` out (superseded, not worth using) and asked
specifically about **`openai/gpt-5.6-sol`**. Three findings, in order of how binding they are.

**(a) The earlier "no HuggingFace model card" framing in this file is wrong and should not be relied
on.** `DOCUMENTARY_EXACT_BYTES_V1` is not HuggingFace-specific: of the 17 sources in
`config/public_model_lineage/manifest.json`, the `openai` entry is a **`raw.githubusercontent.com`
README pinned to git commit `599476783c6f88508dab8577808b5ead5cbee8d2`**. The real requirement is an
*immutably-revisioned primary-publisher document*, and a pinned git SHA satisfies it. So the standard
is more admissive than previously recorded here.

**(b) The documentary bar that actually fails for OpenAI is the claim, not the source.**
`openai/gpt-oss-120b` has a valid immutable source and is still `UNCONFIRMED` with
`unconfirmed_reasons: ["VAGUE_ONLY"]` — the bytes carry no decisive lineage claim, unlike the GLM-5.2
card's explicit "GLM-5.2 … over its predecessor GLM-5.1". For the closed GPT-5.x family there is no
immutably-revisioned primary document at all, and a mutable vendor page cannot satisfy an exact-bytes
standard by construction. Note the manifest already carries `sigstore_lineage_receipt_required`; if a
second source kind is ever added for closed models, an anchored transparency-log receipt looks like the
only shape that preserves reproducibility. **That is an operator/product decision, not mine.**

**(c) But the binding constraint today is route availability, and it is fresh, not stale.** The earlier
"no ZDR route at all" verdict for `gpt-5.6-sol` predated the `425502c` display-name repair, so I
re-tested it live rather than trusting it. `config/models.selection-plan.json` lists exactly four
allowed endpoints; all four were probed just now under the repaired constraint system, **$0**:

| route | result |
|---|---|
| `together` | `configured endpoint tag or slug is unavailable: together` |
| `deepinfra` | `configured endpoint tag or slug is unavailable: deepinfra` |
| `novita` | `configured endpoint tag or slug is unavailable: novita` |
| `google-vertex` | `configured endpoint tag or slug is unavailable: google-vertex` |
| `azure` | `candidate selection route uses an unlisted endpoint` (not in the plan) |

`openai/gpt-5.6-sol` therefore has **no live route whatsoever** right now, independent of any
documentary question. Its plan entry is also `availability: UNVERIFIED`, `documentary_lineage:
UNCONFIRMED`, `entry_authority: false`, `approved_roles: []`, and
`constraint-gpt-oss-gpt-5-6` binds it to `gpt-oss-120b` as one `CONSERVATIVE_ORGANIZATIONAL` group with
`positive_root_assignment_authorized: false` — so the two can never count as independent lineages.

**Question:** are those four endpoint slugs stale plan data, or is `gpt-5.6-sol` genuinely unserved on
OpenRouter? If the plan is stale, refreshing it is the cheapest possible step toward the operator's
goal and I will re-probe at $0 as soon as it changes. Admitting this model needs (c) fixed first, then
(b); (a) is already satisfied.

### 4. Diagnosability — a concrete case, freshly generated

Per the standing request to surface typed/named reasons: `qualification.py:5316` raises
`ValueError("qualification input is unavailable")` from a `_load_model` shared by **four** loaders
(`load_candidate_registry`, `load_qualification_policy`, `load_model_qualification_artifact`,
`load_production_selection`). The message names no path, no field, and no code — so a plain
"this file does not exist" cost a source read to identify, and would be materially harder to diagnose
mid-campaign. A named reason plus the offending path would have made §1 a one-line answer.

### 5. Durability

The 40 unpushed commits are now pushed: `origin/agent/v3-wip-checkpoint` is at `d6c7c5b`, 0 unpushed,
scanned for credentials before pushing (clean). Pushing had stopped for two days. `main` is at
`f794db0` and is a clean ancestor of `HEAD`, so a merge fast-forwards 82 commits with no conflicts
whenever that decision is taken.

## 2026-08-24T12:57Z — **REGRESSION REPAIRED; SECOND SEALED BUNDLE VERIFIED UNDER THE NEW CONSTRAINT SYSTEM**

`425502c` (`Restore selected endpoint name parity`) removed the whole-inventory clause. The predicate
is now `display_count == 1` alone, matching `endpoint_snapshots.py:558-563`. Confirmed at
`route_constraints.py`.

All three roles re-discovered cleanly under the constraint system ($0):

| role | route | registry | discovery run |
|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813=parasail/fp8` | `candidate-registry-r21.json` | `authrunner-candidate-20260824-r21` |
| primary | `z-ai/glm-5.2=sail-research/fp8` | `primary-judge-registry-r21.json` | `authrunner-primary-judge-20260824-r21` |
| replay | `moonshotai/kimi-k3=modal/mxfp4` | `replay-judge-registry-r21.json` | `authrunner-replay-judge-20260824-r21` |

Live-route gate **VALID**. Paid run at index 21 **COMPLETE**, and the bundle **verifies**:

```
AUTHRUNNER smoke evidence: VALID / NONCREDITING / NONAUTHORIZING
Smoke run index: 21
Bundle SHA-256: 3291d6a827fce5bcf169a301d1aa318532d0a6acab60b9ea2bb85514df6cb174
Inventory: case=case-df79ea132113b863; runs=2; logical_requests=4
Closed ledger: entries=4; final_spent_usd=0.43458261
```

**This is the second independent end-to-end success, and the first under `V3-PLANCONSTRAINTS-001`.**
The constraint system now admits the working triple, the campaign executes, and the bundle replays.
Global ledger 29 entries, **total $0.434583**.

### Two operator-side notes

1. **Output path cosmetic issue (operator error, harmless):** the run was launched from a command
   derived from the gate invocation, so `--output` still carried the gate's path. The index-21 bundle
   is therefore written to `authenticated-runner-smoke-evidence-20260822-s3.json`. Content and
   verification are correct — `smoke_run_index: 21`, SHA `3291d6a8…` — only the filename is
   misleading. Any emitted command should carry an output name matching its run index.

2. **An earlier rejection was legitimate, not a defect:** an attempt using the stale r10/r15
   registries correctly failed `authenticated runner route lacks constrained discovery evidence`.
   Pre-constraint evidence is properly inadmissible; re-discovery is required after
   `V3-PLANCONSTRAINTS-001`, and costs $0.

## 2026-08-24T09:52Z — **REGRESSION: `V3-PLANCONSTRAINTS-001` rejects the verified triple** (`DISPLAY_NAME_NOT_INJECTIVE`)

`7ef4717` (`Enforce route constraint parity`) is well-built — `route_constraints.py` /
`route_admission.py` with per-predicate named reasons and an explicit
registry / late-live / separate-runtime taxonomy. That is exactly the requested parity property, and
better structured than proposed.

**But it rejects the exact configuration that produced the verified index-19 bundle six hours ago.**

First, existing evidence was invalidated (expected for this change):
`authenticated runner route lacks constrained discovery evidence`. Re-discovery under the new system
gave:

| role | route | result |
|---|---|---|
| candidate `deepseek/deepseek-v4-pro-0813` | `parasail/fp8` | **OK** — `candidate-registry-r20.json` |
| primary `z-ai/glm-5.2` | `sail-research/fp8` | **REJECTED** — `predicates: DISPLAY_NAME_NOT_INJECTIVE` |
| replay `moonshotai/kimi-k3` | `modal/mxfp4` | **REJECTED** — `predicates: DISPLAY_NAME_NOT_INJECTIVE` |

Gate then fails `qualification input is unavailable` (two of three registries missing).

### The predicate is stricter than the runtime rule it mirrors

Live inventory, verified now:

```
z-ai/glm-5.2      selected=sail-research/fp8  provider_name="Sail Research"  count in inventory = 1
                  duplicated names elsewhere: Alibaba x2, Fireworks x3, Cloudflare x2, BaseTen x2
moonshotai/kimi-k3 selected=modal/mxfp4       provider_name="Modal"          count in inventory = 1
                  duplicated names elsewhere: Morph x2, Fireworks x2
```

**Both selected endpoints ARE injective.** The runtime check at `endpoint_snapshots.py:558-563`
iterates `for raw_endpoint in matched:` and requires
`provider_name_counts[provider_name] == 1` — i.e. uniqueness of the **selected** endpoint's display
name. The new plan-time predicate appears to require the **entire endpoint inventory** to be free of
duplicate display names, which is a different and stricter property.

Consequence if unchanged: duplicated display names are near-universal on OpenRouter (`Fireworks`
appears multiple times in most inventories), so whole-inventory injectivity would reject almost every
model — including one proven working end to end.

**Requested:** align the plan-time predicate to the runtime semantics — injectivity of the *selected*
endpoint's display name within the inventory, not injectivity of the whole inventory. Parity means the
same predicate, and the runtime is the reference.

Candidate `parasail/fp8` passing while both judges fail is consistent with this reading: its inventory
happens to have no duplicate display names.

## 2026-08-24T03:23Z — **END-TO-END COMPLETE: SEALED BUNDLE INDEPENDENTLY VERIFIED**

`c627f2d` (`Repair canonical smoke replay`) fixed the strict-mode datetime asymmetry. The **same
bundle** produced before the fix now verifies — no re-run, no new spend:

```
AUTHRUNNER smoke evidence: VALID / NONCREDITING / NONAUTHORIZING
Smoke run index: 19
Bundle SHA-256: e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703
Inventory: case=case-df79ea132113b863; runs=2; logical_requests=4
Closed ledger: entries=4; final_spent_usd=0.39622262
```

Bundle SHA-256 is byte-identical to the seal recorded at 02:17, confirming the evidence was always
valid and only the replay reader was at fault. **The full AUTHRUNNER smoke path is now proven:
live authenticated campaign → sealed evidence → independent offline verification.**

### What is now demonstrated against a real provider

| layer | status |
|---|---|
| authentication, routing, provider pinning | proven |
| ZDR / operational / display-name / structured-output / reasoning constraints | proven |
| custody namespacing, run-index lifecycle | proven |
| cost reserve → spend → reconcile, closed ledger | proven |
| token accounting (additive reasoning semantics) | proven |
| generation-metadata identity binding | proven |
| strict usage validation | proven |
| immutable transport receipt custody | proven |
| **cross-lineage adjudication (candidate + 2 judges, 3 lineages, 3 providers)** | **proven** |
| **evidence sealing and independent offline replay** | **proven** |

**Total spend to reach this: $0.396223 across 25 ledger entries.**

### What this does NOT establish

- `completed_real_audits` remains **0**. The bundle is `NONCREDITING` by construction and grants no
  qualification, calibration, benchmark, audit, AUTHSEAL, or release authority.
- One case, not 24. Cross-case aggregation, scoring, and adjudication at scale are unexercised.
- **Nothing about audit quality.** Whether findings are correct, complete, or better than alternatives
  is untouched — that is benchmarks and calibration, which have not started.

### Carried forward to the 24-case campaign

1. **Candidate reliability** — `deepseek/deepseek-v4-pro-0813` via `parasail/fp8` returned
   schema-invalid structured output on 2 of ~10 attempts despite advertising `structured_outputs`.
   At 24 cases this will fail intermittently; decide whether to retry, tolerate, or reselect.
2. **Evidence drift** — six sub-hour drifts observed on the primary judge route in one day; the replay
   judge drifted after ~24 h. Discovery, gate, and launch must be adjacent.
3. **Run duration** — a 1-case campaign takes ~3-5 minutes; budget command timeouts accordingly (an
   operator-side 2-minute timeout killed index 17 mid-run).
4. **`V3-PLANCONSTRAINTS-001`** — plan-time constraint parity, queued but not implemented.

## 2026-08-24T02:17Z — **FIRST COMPLETE SMOKE RUN — SEALED BUNDLE PRODUCED**

`03d6e8a` (`Bind smoke reasoning identity parameters`) cleared the required-provider-parameters
asymmetry. Index 19:

```
AUTHRUNNER smoke: COMPLETE / NONCREDITING / NONAUTHORIZING
Smoke run index: 19
Bundle SHA-256: e7537a2fc5aed79d274101364442faf0e515dd5879cfd8f6670784fcc2595703
Closed ledger: entries=4; final_spent_usd=0.39622262
Result: $HOME/.mmaudit/private/authrunner/authenticated-runner-smoke-evidence-20260824-s19.json
        (282,802 bytes)
```

**The full campaign executed end to end for the first time in this build's history:** candidate
primary + candidate replay + judge primary + judge replay, cross-lineage adjudication across three
distinct lineages and three distinct providers, with a closed 4-entry ledger and a sealed evidence
bundle.

Bundle header: `artifact_kind=authenticated_runner_noncrediting_smoke_evidence`,
`purpose=NONCREDITING_SMOKE`, `schema_version=1.2`, `smoke_run_index=19`.

### BLOCKER — the bundle cannot pass its own canonical replay

```
mmaudit models verify-authenticated-runner-smoke --bundle … --smoke-corpus benchmarks/model_corpus_smoke
-> mmaudit failed safely: authenticated runner smoke bundle failed canonical replay
```

Invocation verified correct against `--help` (both required arguments supplied). Underlying error,
obtained by calling the validator directly (`cli.py:5738` suppresses it with `from None`):

```
AuthenticatedRunnerSmokeError: authenticated runner smoke bytes do not validate
```

**Root cause — strict-mode datetime asymmetry.** `revalidate_authenticated_runner_smoke_evidence_bytes`
(`authenticated_runner_smoke.py:761`) calls:

```python
AuthenticatedRunnerSmokeEvidenceBundle.model_validate_json(raw, strict=True)
```

Pydantic **strict mode refuses str→datetime coercion**, but the bundle serializes datetimes as ISO
strings. Verified directly:

```
strict=True  -> 15 validation errors, ALL datetime fields
   runs.0.candidate_report.result.usage_record.timestamp
     Input should be a valid datetime [type=datetime_type,
      input_value='2026-08-24T02:14:55.181934Z', input_type=str]
   … started_at, ended_at, and the same three fields under runs.0.adjudication_report.cases.0
strict=False -> VALIDATES OK
```

**The bundle is not corrupt.** Its content is valid; the writer and the replay reader disagree on
strict-mode datetime handling, so *no* smoke bundle can ever replay. This is a write/read asymmetry in
the verification path.

Suggested fix: either serialize datetimes in a strict-parseable form, or relax `strict=True` for
datetime fields specifically (keeping strictness elsewhere), or validate via
`model_validate(json.loads(raw), strict=True)` after an explicit datetime coercion pass. Whichever
preserves the intended tamper-detection.

Also worth addressing: `cli.py:5738` discards the underlying error with `from None` — the fifth
occurrence of this pattern on this ticket. Each previous instance cost a diagnostic round trip.

### Spend

Ledger 25 entries, **total $0.396223**. Note index 17 was terminated mid-run by an operator-side
2-minute command timeout (my error, not a defect) leaving one `uncertain_accounted` judge entry; a full
campaign needs ~3-5 minutes. Index 18 hit the known intermittent `SCHEMA_VALIDATION_FAILED` on the
candidate. Index 19 completed.

**Candidate reliability remains a real concern for the 24-case campaign:** `deepseek/deepseek-v4-pro-0813`
via `parasail/fp8` produced schema-invalid structured output on indices 8 and 18 — roughly 2 failures
in ~10 candidate attempts despite the route advertising `structured_outputs`.

## 2026-08-24T01:10Z — clause isolated: `STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS`

`3a1246d` (`Refine structured output routing diagnostics`) works exactly as intended. Gate green, run
at index 16:

```
mmaudit failed safely: NONCREDITING_SMOKE identity binding lacks immutable receipt custody
  (usage_diagnostics=STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS)
```

Ledger 16 entries, **total $0.151976** (this run $0.006281). Next free index **17**.

**Note:** my stated guess in the previous entry (`requested_mode` mismatch) was **wrong** — the mode
check `IDENTITY_MODE` passes and the failure is two clauses later. That is the fourth incorrect
operator-side hypothesis on this ticket; the clause-level codes are doing the work that guessing could
not.

### The failing comparison

`usage.py:1900-1901`:

```python
required_special_parameters = set(capabilities.required_parameters) - {"max_tokens", "temperature"}
...
if set(evidence.required_provider_parameters) != required_special_parameters:
    return "STRUCTURED_OUTPUT_ROUTING:IDENTITY_REQUIRED_PROVIDER_PARAMETERS"
```

An **exact set equality** between two independently constructed sets. The clauses before it all pass:
`IDENTITY_ENDPOINT_SNAPSHOT_SHA256`, `IDENTITY_OUTPUT_CAPABILITY_SHA256`, `IDENTITY_MODE`, and
`IDENTITY_PARAMETER_SUBSET`.

### The two construction sites to compare

**Capabilities side** — `openrouter.py:18568`:

```python
required_parameters = tuple(sorted(
    (set(endpoint.required_request_parameters) - _ROUTE_SENSITIVE_REQUEST_PARAMETERS)
    | set(output_mode_request_parameters(evidence.structured_output_mode))
    | ({REASONING_REQUEST_PARAMETER} if reasoning_requested else set())
))
```

**Evidence side** — the structured-output request shape, built near `openrouter.py:~545`:

```python
sorted({*_BASE_REQUEST_PARAMETERS,
        *(("reasoning",) if reasoning_requested else ()),
        *special_output_parameters})
```

The two differ in construction: the capabilities side subtracts `_ROUTE_SENSITIVE_REQUEST_PARAMETERS`
from the endpoint's declared required parameters and unions `output_mode_request_parameters(...)`,
while the evidence side unions `_BASE_REQUEST_PARAMETERS` with `special_output_parameters`. The
comparison then subtracts only `{max_tokens, temperature}` from the capabilities side and nothing from
the evidence side. **A single element present in one construction and not the other fails the equality.**

### Supporting data (frozen discovery, candidate r10, `parasail/fp8`)

```
structured_output_parameters = ['response_format', 'structured_outputs']
supported_parameters         = [frequency_penalty, include_reasoning, logit_bias, logprobs,
                                max_tokens, presence_penalty, reasoning, reasoning_effort,
                                repetition_penalty, response_format, seed, stop,
                                structured_outputs, temperature, tool_choice, tools,
                                top_k, top_logprobs, top_p]
```

Frozen `supported_parameters` matches the live endpoint exactly, so the endpoint snapshot is accurate —
this is an internal construction asymmetry, not stale or wrong provider data.

**Request:** log both sets on mismatch (`expected=…, observed=…`). Given the equality is exact and both
sets are built internally, the two values will identify the discrepancy immediately.

## 2026-08-24T00:15Z — receipt seal FIXED; new named failure `STRUCTURED_OUTPUT_ROUTING`

`68126e0` (`Harden receipt cookie lifecycle`) cleared the receipt-seal blocker — the
`provider transport receipt cannot seal owned request state` error is gone. Gate was still green after
90 minutes (no drift this cycle). Run at index 14:

```
mmaudit failed safely: NONCREDITING_SMOKE identity binding lacks immutable receipt custody
  (usage_diagnostics=STRUCTURED_OUTPUT_ROUTING)
```

Ledger now 15 entries, **total $0.145695** (index 14 charged $0.004044; a follow-up instrumented run
at index 15 charged $0.008478). Indices 1–15 consumed; **next free index is 16.**

### The named code is working — this is your diagnostics investment paying off

`STRUCTURED_OUTPUT_ROUTING` is returned by `_strict_usage_record_failure_code`
(`usage.py:843-844`) when `_has_valid_structured_output_routing` (`usage.py:1648`) returns `False`.
Earlier at index 10 this reported `NONE`; it now reports a specific clause family. That is a strictly
better position than the generic errors of two days ago.

### Why the operator side cannot narrow it further

`_has_valid_structured_output_routing` is a single composite boolean over ~15 conditions:
`repair_used`, `truncated`, `requested_mode is not achieved_mode`, plus twelve hash/endpoint equality
checks (`configured_provider_endpoints`, `selected_provider_endpoint`, `prompt_sha256`,
`request_body_sha256`, `schema_sha256`, `original_response_sha256`, `validated_response_sha256`,
`provider_policy_sha256`, `endpoint_snapshot_sha256`, `output_capability_sha256`, `repair_used`
routing parity) and a further `request_shape_routing` block.

**External instrumentation cannot reach it.** The predicate is bound to a module-level name at import
(`usage.py:931`: `structured_output_routing_predicate = _has_valid_structured_output_routing`), so
patching the module attribute after import does not affect the captured reference — the same pattern
as `_authrunner_usage_origin_scope`. A wrapper attempt produced no output while still charging.

**Request:** extend the failure code with the specific clause, e.g.
`STRUCTURED_OUTPUT_ROUTING:requested_mode_mismatch` or
`STRUCTURED_OUTPUT_ROUTING:validated_response_sha256`. Given the route advertises `structured_outputs`
but the candidate has already been observed returning schema-invalid output intermittently (index 8),
`requested_mode is not achieved_mode` is the most probable clause — but that is a guess, and three
previous guesses of mine on this ticket were wrong.

## 2026-08-23T22:40Z — `48ea635` receipt custody blocks pre-transport — **$0, no charge**

Gate run at index 14 after `48ea635` (`Add receipt-bound smoke transport custody`). **Both judges had
drifted** and were re-frozen at $0:

| role | new registry | new discovery run | note |
|---|---|---|---|
| primary `z-ai/glm-5.2` | `primary-judge-registry-r15.json` | `authrunner-primary-judge-20260823-r15` | 6th sub-hour drift today |
| replay `moonshotai/kimi-k3` | `replay-judge-registry-r15.json` | `authrunner-replay-judge-20260823-r15` | first drift — r8 evidence was >24 h old, failed on `model metadata` |

Gate then **VALID** on all three routes. Paid launch at index 14:

```
mmaudit failed safely: provider transport receipt cannot seal owned request state
```

**Ledger unchanged — 13 entries, $0.133173. Index 14 was not consumed. No provider charge.**
The receipt check runs pre-transport, which is the correct ordering.

### Diagnosis

Raised at `openrouter.py:6198` (a second identical site at `:6226`), from an
`except (AttributeError, TypeError): ... raise ... from None` wrapping introspection of httpx
internals:

```
client._cookies, client._params, client._timeout, headers._list, cookies.jar,
jar._cookies, jar._policy, params._dict, binding.transport._pool, pool._ssl_context
```

**Every one of those attributes exists on a fresh `httpx.AsyncClient` under the installed httpx
0.28.1** — verified directly, all eleven return `True`. So this is not a missing-attribute or
httpx-version problem on a newly constructed client.

That leaves the object actually being introspected at runtime differing from a fresh client — most
likely `binding.transport` not exposing `_pool` when it is a wrapped/custom transport rather than
`httpx.AsyncHTTPTransport`, or the client having been replaced by then.

**`from None` suppresses the cause again.** This is the third occurrence of the same diagnostic
pattern (token details, usage strictness, now receipt sealing), and each previous instance was
resolved in one run once the underlying value or reason was surfaced. **Please include the failing
attribute name and owning type in this error.** External wrapping cannot reach it — the
`object.__getattribute__` alias is function-local, not module-level.

This is a regression in code committed ~90 minutes prior, caught before any spend.

## 2026-08-23T16:26Z — **STRICT USAGE PREDICATE NOW PASSES** — `usage_diagnostics=NONE`

Run at index 10 after `d2364f6` (`Harden smoke scope and usage diagnostics`). Gate re-run
immediately before launch; primary judge re-frozen again to `primary-judge-registry-r14.json` /
`authrunner-primary-judge-20260823-r14` (fifth sub-hour drift on that route today).

```
mmaudit failed safely: NONCREDITING_SMOKE identity binding awaits immutable completion receipts
  (usage_diagnostics=NONE)
```

**`usage_diagnostics=NONE` means the strict usage record has no failure code — the predicate that
blocked runs 11–13 is now satisfied.** Your `StrictUsageFailureCode` / `_strict_usage_record_failure_code`
work did exactly what was asked, and the answer is that there is no longer a strict failure to report.

The remaining message is **not a new defect** — it is the immutable-receipt composite you have already
scheduled (`PAUSED_FOR_AUTHRUNNER_SCOPE_CUTOFF_HOTFIX_THEN_IMMUTABLE_RECEIPT_COMPOSITE_BEFORE_INDEX_10_GATE`).
No operator action is available until that lands.

### Ledger

13 entries, **total $0.133173**. All `reconciled` except `r2` (the pre-fix `uncertain_accounted`
entry from before `8e1581d`, retained deliberately — that charge was real).

Indices consumed: 1–13. Next free index is **14**.

### Cumulative position

Every layer is now proven against live provider calls: authentication, routing, provider custody
namespacing, run-index lifecycle, cost reserve/reconcile, token accounting, structured-output
validation, **generation-metadata identity binding**, and now **strict usage validation**. The single
remaining gate before a sealed smoke bundle is the immutable completion-receipt composite, which is in
progress.

## 2026-08-23T15:30Z — **IDENTITY BINDING IS FIXED** — the pre-restart blocker is resolved

`8058e7b` (dormant provider receipt scaffold) resolved it. Runs 11, 12, 13. Ledger now 12 entries,
**total $0.124584**; indices 1–9 and 11–13 consumed (10 was gated but never launched).

Captured usage-record state at validation:

```
identity_strength  : CANONICAL_MODEL_AND_ENDPOINT_BOUND
identity_binding_status : generation_metadata_bound     <-- BOUND (was generation_metadata_unbound)
execution_evidence : real
status             : success
generation_id      : gen-1787498019-9wq863hcQEsYs4sNm0Cy
certification_request : True
```

**`generation_metadata_bound`.** The `UNBOUND provider identity` condition recorded in the
pre-restart handover — and reproduced continuously since — no longer occurs. The
"Completed response identity is unbound" warning is gone from the run output, and
`identity_diagnostics` no longer appears in the failure. Whatever the dormant-attempt receipt work
changed, it fixed the generation-metadata fetch.

### Remaining failure — same symptom, different cause

```
mmaudit failed safely: model benchmark smoke completion is not exact successful REAL evidence
  (usage_error=UsageValidationError)
```

Still `UsageValidationError`, but now with a **bound** identity, so it is no longer the identity path.
The failure is inside `_is_strict_usage_record` (`usage.py`), reached via
`is_creditable_usage_record(require_real=True, require_certification=True)`.

Observed call kwargs at failure:

```
require_real=True, require_certification=True, allow_unbound_real=False, require_runtime_attestation=False
```

**Bisection result:** flipping `require_certification`, `require_real`, or `allow_unbound_real`
individually does **not** make it pass. The record therefore fails an intrinsic strictness condition,
not a mode gate. External instrumentation cannot see which — the predicate is a single composite
boolean.

**Request:** surface which clause of `_is_strict_usage_record` rejects the record, in the same style as
the identity diagnostics you added in `77fb4b9`. That change turned a two-day-old unknown into a
one-run answer; the same treatment here should close this immediately.

### Status

Every layer from transport through identity binding is now proven working against live provider calls:
auth, routing, custody namespacing, run-index lifecycle, cost reserve/reconcile, token accounting,
structured output, and **generation-metadata identity binding**. The only remaining gate before a
sealed smoke bundle is this single strictness predicate.

## 2026-08-23T09:07Z — GATE READY at **index 10** (not 8 — 8 and 9 are consumed)

`PAUSED_FOR_AUTHRUNNER_FRESH_INDEX_8_GATE_AFTER_IDENTITY_DIAGNOSTIC` cannot be satisfied:
**indices 1–9 are all consumed.** Index 8 was spent producing the `SCHEMA_VALIDATION_FAILED`
observation and index 9 produced the identity diagnostic you requested. **Next free index is 10.**

Live-route gate at index 10 — **VALID**, provider-free, $0:

```
Validated exact routes: candidate=deepseek/deepseek-v4-pro-0813; primary_judge=z-ai/glm-5.2;
                        replay_judge=moonshotai/kimi-k3
Metadata request inventory: logical_gets=15; maximum_provider_attempts=30
Runtime state: usage_records=0; budget=UNCHANGED; atomic_cost_ledger=UNCHANGED; output=NOT_PUBLISHED
Effective config SHA-256: 42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54
```

Composition (primary judge re-frozen twice today due to drift):

| role | model | route | registry | discovery run |
|---|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813` | `parasail/fp8` | `candidate-registry-r10.json` | `authrunner-candidate-20260823-r10` |
| primary | `z-ai/glm-5.2` | `sail-research/fp8` | `primary-judge-registry-r12.json` | `authrunner-primary-judge-20260823-r12` |
| replay | `moonshotai/kimi-k3` | `modal/mxfp4` | `replay-judge-registry-r8.json` | `authrunner-replay-judge-20260822-r8` |

**Primary-judge evidence drifted again within ~25 minutes** (r11 frozen 09:40, stale by 10:05). Third
observation of sub-hour drift on this route. Any emitted sequence should assume the gate must be
re-run immediately before launch.

**No paid run was made at index 10.** The fetch-loop instrumentation is not yet in
(`77fb4b9` surfaced the codes only), so a paid attempt now would reproduce the identical failure at a
further ~$0.005. Emit the fix and the operator side will gate and launch in one pass.

## 2026-08-23T09:05Z — IDENTITY DIAGNOSTIC (answers `PAUSED_FOR_AUTHRUNNER_GENERATION_IDENTITY_DIAGNOSTIC_BEFORE_INDEX_8_GATE`)

`77fb4b9` surfaced the codes. Run at index 9:

```
mmaudit failed safely: model benchmark smoke completion is not exact successful REAL evidence
  (usage_error=UsageValidationError,
   identity_diagnostics=GENERATION_METADATA_INVALID|GENERATION_METADATA_MISSING)
```

Ledger: 9 entries, **total accounted $0.10457436**, indices 1–9 consumed. All reconciled except r2.

### Three hypotheses tested and ELIMINATED — do not re-investigate these

**1. Model-ID naming mismatch — NOT the cause.** The generation endpoint returns the canonical dated
form `deepseek/deepseek-v4-pro-20260813` while the request uses `deepseek/deepseek-v4-pro-0813`, but
the frozen registry already carries both (`exact_model_id` / `canonical_slug`) and the runtime routing
shows `accepted_model_aliases` containing both. Not it.

**2. Fetch timeout / IO budget — NOT the cause.** Measured generation-metadata availability directly:
issued a minimal completion, then polled `/api/v1/generation?id=…` once per second.
**Metadata became available after 9.6 s.** mmaudit's poll schedule
(`_GENERATION_METADATA_POLL_DELAYS_SECONDS = (0, 1, 3, 7, 15, 30, 60)`) attempts at cumulative
0 / 1 / 4 / 11 / 26 / 56 / 116 s, so the 4th attempt (11 s) should succeed. Per-attempt IO budget is
`request_timeout_seconds * 0.25` clamped to `[0.05, 15.0]`; `request_timeout_seconds = 180`
(`config/openrouter-qualification.toml:24`), giving the **maximum 15.00 s** budget per attempt. Ample.

**3. Payload validation rejection — NOT the cause.** Ran mmaudit's own validator against a live
response:

```
validate_openrouter_generation_payload(raw_response,
    requested_generation_id=…, retrieved_at=now, execution_evidence=REAL)
-> VALIDATES OK, exact_model_id=deepseek/deepseek-v4-pro-20260813
```

Note it must be passed the **full response object**, not `response["data"]` — the latter raises
"generation response data must be an object". Live payload fields all present and well-formed:
`cancelled=False`, `tokens_prompt`, `tokens_completion`, `total_cost`, `usage` (matching),
`native_tokens_*`, `finish_reason`, `provider_name`, `created_at`, `latency`, `generation_time`.

### What remains — the fetch loop itself

Metadata exists, arrives in ~9.6 s, validates cleanly, and the poll schedule and IO budget both cover
it. Yet the run reports `GENERATION_METADATA_MISSING`. **The most likely remaining explanation is that
the poll loop exits before its schedule completes** — e.g. an early empty/404/"not ready" response
being treated as terminal rather than retryable, or the loop being cut short by an outer deadline.

Suggested internal instrumentation (external wrapping cannot see inside the fetch):
- log each poll attempt: index, elapsed seconds, HTTP status, whether a body was returned
- log why the loop terminated (schedule exhausted vs early return vs exception)
- log which branch sets `GENERATION_METADATA_INVALID` vs `GENERATION_METADATA_MISSING`, since both are
  currently reported together and may not be independently meaningful

### Secondary finding — the candidate is intermittently non-conformant

Across runs 5–9 the same configuration produced **two different failures**: index 8 failed with
`SCHEMA_VALIDATION_FAILED` (model returned invalid structured data) while indices 5, 7 and 9 reached
identity binding. `deepseek/deepseek-v4-pro-0813` via `parasail/fp8` therefore does not reliably
produce schema-valid structured output even though the route advertises `structured_outputs`. This
will surface as flaky failures across a 24-case campaign and is worth a decision: tolerate with
retries, or prefer a candidate with more reliable structured output.

## 2026-08-23T08:45Z — **THE ORIGINAL BLOCKER ISOLATED**: identity downgrade happens only at generation-metadata binding

Runs 5, 6, 7 executed after `531a9d8`. Indices 1–7 now consumed. **Total accounted: $0.09414372.**
All entries `reconciled` except the pre-fix r2.

### Two of your fixes are confirmed working

1. **Token accounting (`531a9d8`)** — replacing the OpenAI subset assumption with independent
   plan-based bounds (`completion_tokens > reserved_output_tokens`,
   `reasoning_tokens > reserved_reasoning_tokens`) cleared the check entirely. No recurrence across
   three runs.
2. **Typed usage errors** — the failure now reports
   `usage_error=UsageValidationError` instead of the generic message. That was proposal item 5 and it
   immediately narrowed the search.

### The remaining failure is the pre-restart blocker, now precisely located

```
Completed response identity is unbound; preserving evidence without automatic fallback
mmaudit failed safely: model benchmark smoke completion is not exact successful REAL evidence
  (usage_error=UsageValidationError)
```

Captured routing state from the unbound usage record (external instrumentation, read-only):

```
provisional_identity_strength = CANONICAL_MODEL_AND_ENDPOINT_BOUND   <-- provisionally BOUND
identity_binding.strength     = UNBOUND                              <-- downgraded
identity_binding_status       = generation_metadata_unbound
accepted_model_aliases        = ["deepseek/deepseek-v4-pro-0813", "deepseek/deepseek-v4-pro-20260813"]
canonical_model               = deepseek/deepseek-v4-pro-20260813
provider                      = Parasail
provider_fallback_used        = false
host_model_fallback_used      = false
certification_request         = true
privacy_endpoint_policy_class = ZDR
generation_id                 = gen-1787474588-l7LSLr4WudUYE3orNGO8
```

**Everything except generation metadata binds correctly.** Model aliases cover both naming forms,
provider matches the frozen snapshot, no fallback occurred, endpoint policy is ZDR, and the
provisional strength is already `CANONICAL_MODEL_AND_ENDPOINT_BOUND`. The downgrade to `UNBOUND`
happens **only** in the generation-metadata step.

### The metadata is not missing — it exists and is complete

Queried `/api/v1/generation?id=…` directly for two unbound generations. Both returned full records:

| field | gen-1787474457-OH7yH0ph… | gen-1787474588-l7LSLr4W… |
|---|---|---|
| `model` | `deepseek/deepseek-v4-pro-20260813` | `deepseek/deepseek-v4-pro-20260813` |
| `provider_name` | Parasail | Parasail |
| `total_cost` | 0.00533808 | 0.00404316 |
| `tokens_prompt` / `tokens_completion` | 225 / 1474 | — |
| `native_tokens_reasoning` | 1237 | — |
| `finish_reason` | stop | — |
| `generation_time` | — | 10878 ms (latency 523 ms) |

The returned `model` is the canonical dated form, which **is** in `accepted_model_aliases`, so naming
is not the cause.

Timing looks unlikely but is not excluded: generation took ~10.9 s, and
`_GENERATION_METADATA_POLL_DELAYS_SECONDS = (0, 1, 3, 7, 15, 30, 60)` gives cumulative polls at
0/1/4/11/26/56/116 s. However the per-attempt IO budget is
`request_timeout_seconds * 0.25` clamped to `[0.05, 15.0]`
(`openrouter.py:350-354`, applied at `:15128`) — if `request_timeout_seconds` is small, each poll gets
a very short timeout regardless of the generous delay schedule. **Worth checking what
`request_timeout_seconds` actually is for this path.**

### What codex needs to determine (internal instrumentation required)

External wrapping cannot see inside the fetch. The three candidates are:

1. **Fetch timeout** — per-attempt IO budget too small (see above)
2. **Validation rejection** — `OpenRouterGenerationEvidence.model_validate` rejecting a field present
   in the live payload (note `native_tokens_completion_images`, `cache_discount`, `is_byok`,
   `data_region`, `moderation_latency` are present; if the model is strict, an unexpected key or an
   unmodelled type could reject an otherwise-valid record)
3. **Reconciliation mismatch** — `GenerationReconciliationExpectation` failing on a field other than
   model/provider (e.g. `catalog_identity_binding_sha256`, `discovery_evidence_sha256`, or
   `require_certification`)

**Please log the specific `OpenRouterIdentityDiagnosticCode` set on the unbound path** — the codes are
computed (`GENERATION_METADATA_INTEGRITY_REJECTED`, `GENERATION_METADATA_MISSING`,
`ENDPOINT_VARIANT_MISMATCH`, `PROVIDER_MISMATCH`, `UNAPPROVED_FALLBACK`) and then not surfaced. Same
diagnostic gap as the token message and the usage error, both of which resolved their questions in one
run once surfaced.

This is the last known gate before a sealed smoke bundle.

## PROPOSAL — six quality-preserving accelerations for V3-AUTHRUNNER-001 and the release campaign

Operator-side analysis, not evidence. Every item below reduces **cycle count and diagnosis time**, not
verification depth. None relaxes a fail-closed check, weakens the evidence model, or changes what is
proved. Ordered by expected value.

### Context: why the ticket has been slow

59 commits since the 2026-08-20 restart, 22 on the AUTHRUNNER path, **10 re-pins of
`config/models.selection-plan.json`**, **14 discovery re-freezes across 14 model/route combinations** —
still `PARTIAL`. Roughly sixteen defects, nearly all of one shape: *a constraint the runtime enforces
that the selection plan did not filter on*. Each was correct fail-closed behaviour; collectively they
mean the plan is validated by trial rather than by construction, and each trial costs a full
multi-actor round trip.

### 1. Make plan-time constraint enforcement exhaustive — highest value

`src/mmaudit/models/candidate_selection.py` reference counts today:

| constraint | refs | enforced at plan time? |
|---|---|---|
| lineage | 25 | yes |
| `status` | 5 | yes |
| `structured_outputs` | 5 | yes |
| `max_completion_tokens` | 3 | yes |
| zdr | 2 | yes |
| **`response_format`** | **0** | **no — runtime only** |
| **`supported_efforts`** | **0** | **no — runtime only** |
| **`display_name`** uniqueness | **0** | **no — runtime only** |

Those three zeros are exactly what caused the last three round trips (`tencent/hy3=novita`,
`gemma-4-26b`, and the display-name exclusions). All three are present in discovery metadata and are
checkable when the plan is built. **This cannot reduce quality** — it applies identical checks earlier;
a plan failing them was always going to fail at runtime, just later and after a charge.

### 2. Extend `models check` into a route-qualification sweep

`models check` already exists and already covers "exact models, endpoint capabilities, ZDR, duplicates,
and independence". Extending it to take the candidate set and report, per model, which routes satisfy
**all** constraints simultaneously would replace ad-hoc analysis. The monitoring session has been doing
this by hand and **produced three wrong recommendations** (`novita`, `gemma-4-26b`, `wafer`) by
filtering incrementally rather than against the full set. Metadata-only, $0, and it removes an entire
class of operator error.

### 3. Multi-endpoint allowlists for every role

Already done for the replay judge (`['modal/mxfp4', 'phala']`). Extending it to candidate and primary
means a dead or drifted route no longer forces a plan edit, commit, and round trip. Quality-neutral —
the runtime still pins exactly one route into frozen evidence; only the *candidate set* widens.

### 4. Fuse discovery → live-route gate → launch into one adjacent operator command

Observed drift: `wafer` went `status=0` → `status=-5` in **~15 minutes**; candidate evidence has gone
stale in as little as 7 hours and reliably overnight. Cycles have repeatedly outlived their own inputs.
Same checks, far less wall-clock exposure between them. This matters more for the 24-case campaign than
for the smoke.

### 5. Surface typed errors instead of generic ones

`benchmark/models.py:1619` discards the typed result of `_successful_usage_error` and conflates it with
the separate `case_id` mismatch condition. Precedent: adding observed values to the token-detail message
in `8e1581d` settled a two-day-old open question in a single run
(`reasoning_tokens=1307 > completion_tokens=1280`). Pure diagnostic speed, zero quality cost.

### 6. Widen the smoke corpus to 2–3 cases

One case proves transport but structurally cannot exercise cross-judge adjudication, aggregation, or
multi-case sealing. At ~$0.005 per run, finding those defects now is far cheaper than finding them
inside the 24-case campaign, where each failure costs the whole run.

### Explicitly NOT recommended

- Relaxing any fail-closed check
- Granting codex credential or provider access — this would collapse the author/executor separation the
  evidence model depends on, and is precisely what `V3-AUTONOMY-001` exists to solve properly
- Skipping the live-route gate
- Reusing stale or aged evidence
- Treating any smoke output as crediting

## 2026-08-23T07:10Z — SMOKE #5 and #6 after `8e1581d` — cost fix WORKS; **subset assumption CONFIRMED violated**

Both runs executed by the monitoring session directly (a scoped permission rule now allows the paid
smoke command). Gate was VALID immediately before each.

### Ledger — the cost-preservation fix works

| run | actual | accounted | status |
|---|---|---|---|
| r1 (08-21) | 0.01680888 | 0.01680888 | reconciled |
| r2 (08-23) | **null** | 0.05225616 | **uncertain_accounted** ← pre-fix |
| r3 (08-23) | 0.00554796 | 0.00554796 | **reconciled** ← post-fix |
| r4 (08-23) | 0.00537768 | 0.00537768 | **reconciled** |

**Total accounted: $0.07999068.** `8e1581d` resolved the `uncertain_accounted` state — token-detail
failures now reconcile the real cost instead of conservatively charging the full reservation.

The provider-free ledger guard also works: attempting index 2 again was rejected at the **live-route
gate**, before any charge — `smoke run index 2 is already present in the cumulative ledger`.

### Run 3 (`--smoke-run-index 3`) — passed token validation, failed later

```
mmaudit failed safely: model benchmark smoke completion is not exact successful REAL evidence
```

Raised at `benchmark/models.py:1619`. **Diagnostic gap:** `_successful_usage_error`
(`models.py:2160`) computes a *typed* error — `UsageProvenanceError`, `UsageTargetBindingError`,
`UsageResponseBindingError`, `UsageValidationError`, `UsageOutputModeBindingError`,
`UsagePromptBindingError`, schema-binding — and the caller discards it, raising a generic message that
also conflates the separate `case_id` mismatch condition. **Please include `usage_error` and which of
the two conditions fired.** Same class of fix as the token-detail message, which paid for itself
immediately (below).

### Run 4 (`--smoke-run-index 4`) — the new error message settled the question

```
mmaudit failed safely: model response token details are inconsistent
  (prompt_tokens=234, completion_tokens=1280, reasoning_tokens=1307, cached_tokens=0)
```

**`reasoning_tokens (1307) > completion_tokens (1280)`.** The OpenAI subset assumption is violated on
`deepseek/deepseek-v4-pro-0813` via `parasail/fp8`. Reasoning tokens are not contained in the
completion count on this route.

**The check is intermittent, which matters more than the failure itself.** Run 3 passed token
validation and failed later; run 4 failed at this check. With `effort = "high"` the two counts are
nearly equal (1307 vs 1280, ~2% apart), so whether the invariant holds depends on sampling. A gate
that passes or fails at random on identical configuration will be far harder to diagnose in the
24-case campaign than in a 1-case smoke.

### Recommendation

Treat `reasoning_tokens > completion_tokens` as **additive reporting**, not corruption: bill
`prompt_tokens + completion_tokens + reasoning_tokens` when the sum semantics are ambiguous, or
require a per-route declared convention captured at discovery. Failing after a charge on a routine,
sampling-dependent condition is the wrong trade — especially now that cost is correctly preserved, so
each failed attempt still spends real money (~$0.005 per run).

If the subset invariant is genuinely required, it must become a **plan-time constraint** — but no
discovery metadata field currently exposes reasoning-token accounting semantics, so it would not be
checkable in advance.

## 2026-08-23T06:33Z — PAID SMOKE #4 (`--smoke-run-index 2`) — run-index fix WORKS; new failure on token accounting

Executed from the main checkout at `3d4a43a`, with `candidate-registry-r10` substituted for the
drifted r9 evidence (re-frozen at $0:
`66b620665f4c8911c38b280b36b70eeab9fe4a0ae44259a608ede271f207dd5c`, run dir
`authrunner-candidate-20260823-r10`). Live-route gate was VALID immediately before, reporting
`Smoke run index: 2`.

```
Structured model request failed
Configured model failed; considering the next explicit fallback
mmaudit failed safely: model response token details are inconsistent
```

### The `--smoke-run-index` fix works

A second ledger entry was created under the `r2` namespace with no collision:

```
request_id:         authrunner.smoke.r2.candidate.primary:721f058726cf9509c07cb2aae662fb6a…
reservation_id:     bec758dc72d74ebebdd32bcd4c1efbd1
reserved_usd:       0.05225616
accounted_cost_usd: 0.05225616
actual_cost_usd:    null
status:             uncertain_accounted
```

### Spend

| entry | actual | accounted | status |
|---|---|---|---|
| `smoke.r1…` (2026-08-21) | 0.01680888 | 0.01680888 | reconciled |
| `smoke.r2…` (2026-08-23) | **null** | 0.05225616 | **uncertain_accounted** |

**Total accounted exposure: $0.06906504.** The r2 call charged but its actual cost could not be
determined, so the full reservation was conservatively accounted — correct fail-safe behaviour, but it
leaves an unresolved ledger entry.

### Root cause — reasoning-token subset assumption

`openrouter.py:14304`:

```python
if reasoning_tokens > fields["completion_tokens"] or cached_tokens > fields["prompt_tokens"]:
    raise OpenRouterSchemaError("model response token details are inconsistent")
```

This requires `completion_tokens_details.reasoning_tokens <= completion_tokens` and
`prompt_tokens_details.cached_tokens <= prompt_tokens` — i.e. it assumes OpenAI's schema semantics
where reasoning tokens are a **subset** of the completion count. Not all providers report that way;
some report reasoning tokens **additively**, excluded from `completion_tokens`. With
`effort = "high"` on a reasoning-heavy candidate, reasoning tokens are large, so the subset check is
very likely what tripped.

**Cannot confirm which of the two conditions fired** — the exception carries no values. Suggest
including the observed `reasoning_tokens/completion_tokens` and `cached_tokens/prompt_tokens` in the
error message; that single change would have made this self-diagnosing.

### Questions for codex

1. Is the subset assumption intended to be universal? If some providers report additively, this
   rejects otherwise-valid responses from any such route — a silent constraint on model selection
   that is not currently enforced at plan time.
2. If the semantics genuinely vary by provider, the accounting needs either a provider-declared
   convention or a tolerant path that treats `reasoning_tokens > completion_tokens` as additive and
   bills accordingly, rather than failing after a charge.
3. What resolves the `uncertain_accounted` r2 entry? It is neither reconciled nor released, and the
   actual cost is unknown.

**A retry requires `--smoke-run-index 3`** — index 2 is now permanently recorded.

## 2026-08-22T05:30Z — PAID SMOKE #3 blocked by request-ID collision — **the smoke run is single-use by construction**

Sequence this morning, after `7ca1558` emitted the r8 pair:

1. Live-route gate on r8 **FAILED** — `candidate=endpoint exact-model identity inventory`. Candidate
   evidence drifted overnight (~7h). Primary and replay were unaffected.
2. Candidate re-frozen at $0 — `candidate-registry-r9.json`, frozen
   `cc65071ef3723fc075b958aec4ad0180cdc99dc853d19b3a7983015f7e1c34ad`, run dir
   `authrunner-candidate-20260822-r9`.
3. Live-route gate on r9/r8/r8 — **VALID**, all three routes validated, 15 logical GETs.
4. Paid launch executed with the r9 candidate substituted — **FAILED**:

```
Structured model request failed
mmaudit failed safely: request ID already recorded:
  authrunner.smoke.r1.candidate.primary:721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497
```

**No new spend.** Ledger still holds exactly one entry — last night's `$0.01680888`, `reconciled`. No
bundle published. Guard at `cost_ledger.py:252`.

### Cause — deterministic request IDs plus a permanent ledger make the smoke run one-shot

The request ID is derived from the case content hash, and the smoke corpus is a fixed single case, so
**every** smoke attempt produces the identical ID. Last night's attempt recorded it permanently; the
ledger's uniqueness guard now rejects all future attempts against that ledger.

The run index `r1` is hardcoded in both the ID construction and the namespace validator, so nothing
increments it:

- `authenticated_runner_smoke.py:125,127,266` — `f"authrunner.smoke.r1.candidate.{...}"` / `...judge...`
- `usage.py:60,64` — `re.compile(r"^authrunner\.smoke\.r1\.candidate\.(?:primary|replay):[0-9a-f]{64}$")`

The `r1` naming anticipated repeat runs; the mechanism to advance it was never wired.

### Suggested fix — make the run index explicit

Add an operator-supplied smoke run index (e.g. `--smoke-run-index 2`), thread it through the ID
construction, and widen the namespace regexes to `r(?:[1-9][0-9]*)` while keeping the smoke and release
namespaces disjoint. That preserves every custody property, keeps IDs deterministic **within** a run,
and makes the smoke test repeatable — which is its whole purpose during debugging.

Do **not** release or supersede the existing reconciled entry: that $0.0168 was genuinely charged and
the record should stand.

A separate ledger per attempt would also unblock it, but discards the cumulative spend cap that the
ledger exists to enforce — not recommended.

### Note

This is the first defect found *after* a green live-route gate on a fully constraint-filtered
composition. The pre-transport path is now clean; this failure is in run lifecycle management, not
selection.

## 2026-08-21T23:14Z — **LIVE-ROUTE GATE VALID on r8/r8/r8** — paid command must be re-emitted

`dcabe31` adopted `modal/mxfp4` with `phala` as a second allowlist entry (the multi-endpoint
suggestion). Replay discovery then succeeded and the full gate passed. All **$0** — ledger unchanged at
the single $0.01680888 entry.

```
AUTHRUNNER smoke live-route preflight: VALID / NONCREDITING / NONAUTHORIZING /
                                        METADATA EGRESS ONLY / NO MODEL COMPLETION
Validated exact routes: candidate=deepseek/deepseek-v4-pro-0813; primary_judge=z-ai/glm-5.2;
                        replay_judge=moonshotai/kimi-k3
Metadata request inventory: logical_gets=15; maximum_provider_attempts=30
Runtime state: usage_records=0; budget=UNCHANGED; atomic_cost_ledger=UNCHANGED; output=NOT_PUBLISHED
Effective config SHA-256: 42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54
```

### The complete validated composition

| role | model | route | registry | frozen sha256 | discovery run |
|---|---|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813` | `parasail/fp8` | `candidate-registry-r8.json` | `4e08e6496952e817e39d6872684a4e69cfb05cf74374870f51c234a6513b7306` | `authrunner-candidate-20260821-r8` |
| primary judge | `z-ai/glm-5.2` | `sail-research/fp8` | `primary-judge-registry-r8.json` | `8f3fc274390d983bde683e3039a91f7cb6ead0f4dfa9aa89caa02ecca7e9ed26` | `authrunner-primary-judge-20260821-r8` |
| replay judge | `moonshotai/kimi-k3` | `modal/mxfp4` | `replay-judge-registry-r8.json` | `75451839c72020a5e34c2f21a433e420f79c6db3e7238adb808e1c382af348f8` | `authrunner-replay-judge-20260822-r8` |

Three distinct providers (Parasail / Sail Research / Modal), three distinct lineages (DeepSeek / Zhipu /
Moonshot), all lineage-CONFIRMED in the 17-source / 11-root sealed bundle.

### ACTION NEEDED — emitted commands are two route generations stale

The two smoke commands at HEAD still reference `registry-r2.json` and `registry-r6.json`. **Re-emit
both the live-route preflight and the paid smoke launch against the r8/r8/r8 paths above.**

**Time-sensitivity:** `wafer` went from operational to `status=-5` inside fifteen minutes earlier
tonight. The gate is green as of 2026-08-21T23:14Z but that is not durable. Suggested sequence to
minimise the window: emit both commands in one checkpoint, operator side re-runs the live-route gate
immediately, and the paid launch follows without an intervening round-trip.

Suggested output path for the fresh run: `authenticated-runner-smoke-evidence-20260822-s3.json`
(currently absent; `s1` was never published as the two earlier attempts failed closed).

## 2026-08-21T23:00Z — r8: candidate OK; replay route `wafer` went non-operational within ~15 minutes

Routes from `3975d2e` adopted as recommended. Discovery run metadata-only, **$0** (ledger unchanged at
$0.01680888).

| role | route | result |
|---|---|---|
| candidate `deepseek/deepseek-v4-pro-0813` | `parasail/fp8` | **SUCCESS** — `candidate-registry-r8.json`, frozen `4e08e6496952e817e39d6872684a4e69cfb05cf74374870f51c234a6513b7306`, run dir `authrunner-candidate-20260821-r8` |
| primary `z-ai/glm-5.2` | `sail-research/fp8` | already done — `primary-judge-registry-r8.json`, frozen `8f3fc274390d983bde683e3039a91f7cb6ead0f4dfa9aa89caa02ecca7e9ed26` |
| replay `moonshotai/kimi-k3` | `wafer` | **FAILED** — `configured endpoint is not operational` |

### `wafer` drifted from status 0 to status -5 in about fifteen minutes

It satisfied every constraint when the recommendation was made at ~22:40 and was non-operational by
~23:00. This is the fastest drift observed today, and it is faster than a single
recommend → adopt → discover cycle. **Route selection cannot assume operational status survives even
one cycle.**

### ACTION NEEDED — plan pins `['wafer']`, which blocks the operator side from substituting

Current `moonshotai/kimi-k3` options, verified at 2026-08-21T23:00Z:

| route | provider | status | max_completion | qualifies |
|---|---|---|---|---|
| **`modal/mxfp4`** | Modal | 0 | 1048576 | **yes — recommended** |
| `phala` | Phala | 0 | 65535 | yes |
| `sail-research/fp4` | Sail Research | 0 | 974842 | yes, but **collides** with the judge's provider |
| `wafer` | Wafer | **-5** | 1048576 | no |

**Recommend changing the plan entry for `moonshotai/kimi-k3` to `modal/mxfp4`** — highest completion
capacity among non-colliding options, provider distinct from Parasail and Sail Research. Once the plan
allows it, the operator side will discover r8 for it and run the live-route gate, both $0.

**Suggestion given the drift rate:** consider allowing more than one endpoint per role in the plan
allowlist, ordered by preference, so a single non-operational route does not require a plan edit,
commit, and full round-trip. The runtime would still pin exactly one route in the frozen evidence; the
allowlist would simply not be a single point of failure.

## 2026-08-21T22:40Z — Reseal confirmed; r8 judge discovered; live-route gate now fails on COMPLETION CAPACITY

Reseal `331bde2` verified: all three roles CONFIRMED, `verified_at 2026-08-21T22:19:00Z`, **17 sources,
11 roots**. r8 discovery for `z-ai/glm-5.2=sail-research/fp8` succeeded —
`primary-judge-registry-r8.json`, frozen
`8f3fc274390d983bde683e3039a91f7cb6ead0f4dfa9aa89caa02ecca7e9ed26`. All **$0**.

Live-route gate on r7/r8/r7:

```
mmaudit failed safely: endpoint completion capacity requires an explicit metadata limit
```

Raised at `token_planning.py:1283`. Two of three routes report `max_completion_tokens = None`:

| role | route | max_completion_tokens |
|---|---|---|
| candidate `deepseek-v4-pro-0813` | `fireworks` | **None** |
| primary `z-ai/glm-5.2` | `sail-research/fp8` | 131072 — OK |
| replay `kimi-k3` | `together` | **None** |

### Route changes needed — models unchanged, judge route unchanged

Complete constraint set applied (ZDR + `status==0` + unique provider display name + model & endpoint
`structured_outputs` + endpoint `response_format` + `supported_efforts` contains `high` + **explicit
`max_completion_tokens`**):

| role | model | qualifying routes (completion capacity) |
|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813` | `parasail/fp8` (1048576), `sail-research/fp4` (384000) |
| primary | `z-ai/glm-5.2` | `sail-research/fp8` (131072) — **current, keep** — plus 8 alternates |
| replay | `moonshotai/kimi-k3` | `wafer` (1048576), `modal/mxfp4` (1048576), `sail-research/fp4` (974842), `phala` (65535) |

**Recommended, preserving three distinct serving providers:**

```
candidate  deepseek/deepseek-v4-pro-0813 = parasail/fp8        [Parasail]
primary    z-ai/glm-5.2                  = sail-research/fp8   [Sail Research]  (unchanged, r8 done)
replay     moonshotai/kimi-k3            = wafer               [Wafer]
```

Note `sail-research/fp4` qualifies for both candidate and replay but would collide with the primary
judge's provider (Sail Research), so avoid it for those roles.

Lineage independence unchanged: DeepSeek / Zhipu / Moonshot. Only candidate and replay need fresh
discovery (r8); both are metadata-only and $0.

**Systemic suggestion:** explicit `max_completion_tokens` is the sixth selection constraint discovered
by trial today, after ZDR, operational status, display-name uniqueness, reasoning effort, and
structured outputs. All six are present in discovery metadata. Enforcing the full set inside
`candidate_selection.py` at plan-build time — rather than discovering them one gate at a time — would
have collapsed roughly six round-trips into one.

## 2026-08-21T22:18Z — LINEAGE CAPTURE with GLM-5.2 — SUCCESS, 17 sources, ready for reseal

Ran after `dce1c25`. Provider-free, **$0** (ledger unchanged at the single $0.01680888 entry).

```
output-dir:             /private/tmp/mmaudit-public-lineage-20260821-r4
observation_set_sha256: db27957fd9bae451acfb78409936b12d795e89c0ac31f7c53874dcb52adb7c73
bundle_sha256:          a7ef51f5c75b851c53991414d51f33af80cbfc419934dc9f5be6365829f7b114
sources:                17 (was 16)
```

| new source | size | sha256 | immutable_revision | publisher_id | redirects |
|---|---|---|---|---|---|
| `sources/z-ai-glm-5-2-card.md` | 10905 | `ed5aca8ce3dc5f8de626c87e488444343e43b1dcbdeb0e643dc72fea63ab06e8` | `b4734de4facf877f85769a911abafc5283eab3d9` | `z-ai` | 2 |

Byte-identical to the independent manual fetch recorded earlier in this session — **fourth consecutive
capture where a separate retrieval reproduced the same sha256 against a pinned revision.**

**Next:** codex to bind the claim span, assign the root, and reseal the manifest to 17 sources. Then
the operator side will run r8 discovery for `z-ai/glm-5.2=sail-research/fp8`, the live-route gate, and
report before any paid launch — all $0 except the launch.

## 2026-08-21T22:11Z — ACTION NEEDED: `z-ai/glm-5.2` selected but its lineage source is NOT in the capture script

`f6cc07a` set the primary judge to `z-ai/glm-5.2` on `sail-research/fp8` and bound reasoning
eligibility. Lineage capture was run at **$0** and produced **16 sources — GLM-5.2 is not among them.**

`scripts/capture_public_model_lineage.py` contains only `zai-org/GLM-4.7`; there is no `GLM-5.2`
entry, and the revision `b4734de4…` does not appear in the file. `z-ai/glm-5.2` is also absent from
`config/public_model_lineage/manifest.json` confirmed IDs. The live-route gate and any paid launch will
therefore fail on lineage for this judge.

Capture run (superseded, recorded for completeness):
`observation_set_sha256 3b44aead5e5f68b6c0c65413ad55eccce2f6db3c4715bc3a5ef9db6f0ce9aa67`,
`bundle_sha256 7aee28fb514a10e6bfc798c3d4e8c0ca20585ef7d2a70e3dfa3558f0d1c703d2`.

**To add — all values independently verified in this session:**

```
repo:               zai-org/GLM-5.2
immutable_revision: b4734de4facf877f85769a911abafc5283eab3d9
bytes:              10905
sha256:             ed5aca8ce3dc5f8de626c87e488444343e43b1dcbdeb0e643dc72fea63ab06e8
publisher_id / independence_key: zai-org
resolve URL form:   https://huggingface.co/zai-org/GLM-5.2/resolve/<revision>/README.md
```

Decisive claim at line 32: *"We're introducing GLM-5.2, our latest flagship model for long-horizon
tasks. It marks a substantial leap in long-horizon task capability over its predecessor GLM-5.1…"* —
same publisher-internal predecessor shape as DeepSeek V4-Pro, which sealed successfully.

Add the source, then the operator side will re-run the capture (17 sources) at $0 for reseal.

## 2026-08-21T21:55Z — r7 triple discovered; live-route gate rejects the new judge on REASONING

All three r7 registries were frozen (metadata-only, **$0**; ledger still holds only the single
$0.01680888 entry):

| role | route | registry | frozen sha256 |
|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813=fireworks` | `candidate-registry-r7.json` | `57b0e8fa7dfd4919fc720c25ba9dfa414a8e466605f8c0f8cbc286df5ea2b9db` |
| primary | `google/gemma-4-26b-a4b-it=deepinfra/fp8` | `primary-judge-registry-r7.json` | `a7a7bb3f0e4be1f3727926149602b58784848c350c5eb38e8629fb0c6365eb13` |
| replay | `moonshotai/kimi-k3=together` | `replay-judge-registry-r7.json` | `5f1fd10d0f10d5848723c42fda45d0fdbea1d58ff86700279524f2c37466d89a` |

Live-route gate on r7/r7/r7:

```
mmaudit failed safely: smoke judge reasoning profile is incompatible with frozen discovery
```

### Correction — `google/gemma-4-26b-a4b-it` cannot work, and neither can the other lineage-confirmed option

`config/openrouter-qualification.toml` sets `effort = "high"`. Neither lineage-confirmed candidate
supports it:

| model | supported_efforts | verdict |
|---|---|---|
| `google/gemma-4-26b-a4b-it` | **none** (`default_enabled=False`) | incompatible |
| `nvidia/nemotron-3-super-120b-a12b` | `['medium','low']` | no `high` — incompatible |

My earlier recommendation filtered on "has reasoning metadata" rather than "supports effort=high".
**There is no lineage-confirmed model that satisfies the full constraint set — a lineage capture cycle
is unavoidable for the primary judge.**

### Complete constraint set applied — 19 qualifying models, 0 lineage-confirmed

Constraints: ZDR + `status==0` + unique provider display name + model-level `structured_outputs` +
endpoint `structured_outputs` + endpoint `response_format` + `supported_efforts` containing `high` +
root lineage distinct from DeepSeek and Moonshot.

| model | routes | lineage source available? |
|---|---|---|
| **`z-ai/glm-5.2`** | `sail-research/fp8`, `decart/fp4`, `deepinfra/fp4` | **yes — already fetched** |
| `openai/gpt-oss-120b` | `coreweave/fp4`, `akashml/bf16`, `novita/fp4` | yes — bundle already uses a GitHub README for this publisher |
| `meta/muse-glimmer-30b` | `phala`, `deepinfra/bf16`, `together` | likely (HuggingFace) |
| `mistralai/mistral-small-2603` | `venice/fp8` | in bundle but currently EXCLUDED/unconfirmed |
| `anthropic/claude-opus-4.6` | `amazon-bedrock` | **no HuggingFace card** — documentary method may not reach it |
| `openai/gpt-5.2` … `gpt-5.4-pro` | `azure` | **no HuggingFace card** — same problem |

**Recommended: `z-ai/glm-5.2` on `sail-research/fp8`.**
- Lineage source already fetched and hashed in this session: `zai-org/GLM-5.2` @ immutable revision
  `b4734de4facf877f85769a911abafc5283eab3d9`, 10905 bytes, sha256
  `ed5aca8ce3dc5f8de626c87e488444343e43b1dcbdeb0e643dc72fea63ab06e8`. Decisive claim at line 32:
  *"We're introducing GLM-5.2, our latest flagship model … over its predecessor GLM-5.1"*.
  Add it to `scripts/capture_public_model_lineage.py` and the operator side will run the capture at $0.
- Three qualifying routes — resilience against the hours-scale drift observed today.
- Provider independence holds: `fireworks` / `sail-research` / `together`.
- Lineage independence holds: DeepSeek / Zhipu / Moonshot.

**Structural note:** the frontier models that satisfy every technical constraint
(`anthropic/claude-opus-4.6`, the `openai/gpt-5.x` family) publish no HuggingFace model card, so the
`DOCUMENTARY_EXACT_BYTES_V1` standard as currently implemented may not be able to admit them at all.
If frontier judges matter for the release campaign, the evidence standard needs a second accepted
source type (vendor documentation page, model card URL, or published system card) — worth deciding
before the 24-case run, not during it.

## 2026-08-21T21:45Z — r7 discovery after `68d774b`: candidate OK, PRIMARY route rejected at discovery

New `structured_outputs` constraint working as intended — it now rejects bad routes **at discovery
time** instead of at paid runtime. Both runs metadata-only, **$0** (ledger still holds only the single
$0.01680888 entry).

| role | route attempted | result |
|---|---|---|
| candidate `deepseek/deepseek-v4-pro-0813` | `fireworks` | **SUCCESS** — `candidate-registry-r7.json`, frozen `57b0e8fa7dfd4919fc720c25ba9dfa414a8e466605f8c0f8cbc286df5ea2b9db`, run dir `authrunner-candidate-20260821-r7` |
| primary judge `tencent/hy3` | `novita` | **FAILED** — `authenticated runner route lacks required native structured_outputs support` |

### Correction: my `novita` recommendation was wrong, and `tencent/hy3` has no viable route at all

`require_authenticated_runner_native_structured_output` (`candidate_selection.py:432-454`) requires
`structured_output_mode is NATIVE_JSON_SCHEMA` plus `structured_outputs` present at **both** model and
endpoint level. In practice a route needs **both** `structured_outputs` **and** `response_format`.
I filtered on `structured_outputs` alone, which is why `novita` looked valid.

`tencent/hy3` endpoints carrying both flags: **only `baidu/fp8`, which is not ZDR-eligible.**
Therefore `tencent/hy3` cannot satisfy the constraint set on any route and **must be replaced as
primary judge**. The candidate is unaffected — `fireworks`, `together`, `parasail/fp8` and
`sail-research/fp4` all carry both flags plus ZDR.

### Replacement primary judges that need NO new lineage work

Full constraint set applied — ZDR + `status==0` + unique provider display name + model-level and
endpoint-level `structured_outputs` + `response_format` + reasoning capability + root lineage distinct
from DeepSeek and Moonshot. 30 models qualify; **two are already CONFIRMED in the sealed lineage
bundle**, so no capture, claim-binding, root decision, or reseal is required:

| model | lineage root | qualifying routes |
|---|---|---|
| `google/gemma-4-26b-a4b-it` | Google | `deepinfra/fp8`, `nextbit/bf16`, `siliconflow/fp8`, `venice/bf16` |
| `nvidia/nemotron-3-super-120b-a12b` | NVIDIA | `digitalocean` |

**Recommended for the smoke run: `google/gemma-4-26b-a4b-it=deepinfra/fp8`.** Four qualifying routes
gives resilience against the hours-scale drift observed today; Nemotron's single route is a single
point of failure. Provider independence holds: candidate `fireworks`, primary `deepinfra/fp8`, replay
`together` — three distinct providers, three distinct lineages.

**Caveat for the full campaign, not the smoke run:** `gemma-4-26b-a4b-it` is a small MoE (26B total /
4B active) and is a weak adjudicator. It is fine for a transport smoke test, where judge quality is
irrelevant. For the real 24-case campaign a stronger judge is worth a fresh lineage capture —
`anthropic/claude-opus-4.6=amazon-bedrock` and `openai/gpt-5.1-codex=azure` both satisfy every
constraint but need capture + reseal.

**Note on the display-name rule:** `anthropic/claude-opus-4.6` qualifies where `claude-opus-5` did not,
so the rule does not categorically exclude Western frontier models — it excludes specific
multi-homed ones. That weakens my earlier framing of it.

## 2026-08-21T20:54Z — **FIRST REAL MODEL COMPLETION** — transport succeeded, $0.0168 spent, failed at structured-output validation

The operator executed the paid smoke launch at HEAD `b4134c7`. A real provider completion was issued
and charged. **This is the first real paid model completion in this build's history.**

```
Structured model request failed
Configured model failed; considering the next explicit fallback
mmaudit failed safely: model returned invalid structured data (SCHEMA_VALIDATION_FAILED)
```

### What worked — three subsystems exercised against reality for the first time

Cost ledger, first entry ever:

```
request_id:         authrunner.smoke.r1.candidate.primary:721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497
reservation_id:     58f2653f416d428d9a75fa8ae2bc8012
reserved_usd:       0.0547272
actual_cost_usd:    0.01680888
accounted_cost_usd: 0.01680888
status:             reconciled
created_at:         2026-08-21T20:53:46Z    updated_at: 2026-08-21T20:54:33Z
```

1. **Cost accounting closed correctly against a real charge** — reserve $0.0547 → actual $0.0168 →
   `reconciled`. The reserve/spend/reconcile cycle had never run against real money before.
2. **The origin-custody namespace binding from `c9a8923` works in production** — the request_id is
   exactly `authrunner.smoke.r1.candidate.primary:<64-hex>`, matching the disjoint smoke namespace.
3. **Fail-closed after a real charge** — it spent, received a non-conforming response, and refused to
   seal evidence rather than accepting it.

Total spend: **$0.0168**, against a derived cap of $0.2189 and a tripwire of $8.00. No bundle
published. Note `runtime_status.json` counters are stale (still `succeeded: 1`, `used 0.0034764325`);
the ledger is the live truth.

### Root cause — an unfiltered selection criterion: `structured_outputs`

The pinned routes for candidate and primary judge do not support strict JSON-schema mode:

| role | route | `response_format` | `structured_outputs` |
|---|---|---|---|
| candidate `deepseek-v4-pro-0813` | `novita/fp8` | yes | **no** |
| primary judge `tencent/hy3` | `tencent/fp8` | yes | **no** |
| replay judge `kimi-k3` | `together` | yes | yes |

The engine requests structured output; these routes return loosely-formatted JSON that fails strict
validation at `structured_output.py:282`. Note `max_repair_attempts` defaults to `0`, so no repair
round-trip is attempted — likely deliberate for evidence integrity, but worth confirming.

### Fix is a ROUTE change only — no model replacement needed

Routes satisfying **all five** constraints (ZDR + operational + unique provider display name +
reasoning capability + `structured_outputs`):

| role | model | current (broken) | valid alternatives |
|---|---|---|---|
| candidate | `deepseek/deepseek-v4-pro-0813` | `novita/fp8` | `together`, `sail-research/fp4`, `parasail/fp8`, `fireworks` |
| primary judge | `tencent/hy3` | `tencent/fp8` | `deepinfra/fp8`, `novita`, `phala` |
| replay judge | `moonshotai/kimi-k3` | `together` | already valid — no change |

**Recommended, preserving three distinct serving providers and three distinct lineages:**
candidate `deepseek/deepseek-v4-pro-0813=fireworks` [Fireworks], primary `tencent/hy3=novita`
[Novita], replay `moonshotai/kimi-k3=together` [Together] unchanged.

Both roles need fresh metadata-only discovery on the new routes (r7), then the live-route gate, then
relaunch. All of that is $0 except the relaunch.

**Systemic note:** discovery already captures `supported_parameters`, so `structured_outputs` could be
enforced as a selection-plan constraint rather than discovered by a paid failure. Recommend adding it
alongside the ZDR/operational/display-name checks. Western frontier models remain excluded at NONE
under the display-name rule, which continues to constrain selection.

## 2026-08-21T18:07Z — LIVE-ROUTE PREFLIGHT **VALID** on fresh r6/r6/r2 evidence — ACTION NEEDED

### 1. Aggregated diagnostics (`9f5c94d`) identified both drifted roles in one run

```
smoke live-route retained discovery mismatches:
  candidate=endpoint exact-model identity inventory; PRIMARY judge=endpoint exact-model identity inventory
```

Replay judge was unaffected. Aggregation is a real improvement over failing on the first mismatch.

**`tencent/hy3` was frozen at 2026-08-21 12:42 and had already drifted by 19:05 — under 7 hours.**
Combined with the candidate's ~25h drift, the practical freshness window for discovery evidence on
actively-served models is **hours, not days**.

### 2. Both drifted roles re-frozen — metadata-only, $0

| role | new discovery run | new registry | frozen sha256 |
|---|---|---|---|
| candidate | `authrunner-candidate-20260821-r6` | `candidate-registry-r6.json` | `6cd3463347e794e92831d69629a820fbdc4a6cb226ee4f2ef7daff03603117e1` |
| primary judge | `authrunner-primary-judge-20260821-r6` | `primary-judge-registry-r6.json` | `7b2f11aed42a7d1c5c79b68339682eb21c7f57c765db0ea0d83004a717d8fa8c` |

Replay judge keeps its r2 pair (`replay-judge-registry-r2.json` /
`authrunner-replay-judge-20260820-r2`), which validated live and was not rerun.

### 3. Live-route preflight on r6/r6/r2 — **VALID**

```
AUTHRUNNER smoke live-route preflight: VALID / NONCREDITING / NONAUTHORIZING /
                                        METADATA EGRESS ONLY / NO MODEL COMPLETION
Validated exact routes: candidate=deepseek/deepseek-v4-pro-0813; primary_judge=tencent/hy3;
                        replay_judge=moonshotai/kimi-k3
Metadata request inventory: logical_gets=15; maximum_provider_attempts=30
Runtime state: usage_records=0; budget=UNCHANGED; atomic_cost_ledger=UNCHANGED; output=NOT_PUBLISHED
Effective config SHA-256: 42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54
```

**15 real authenticated provider requests succeeded across all three routes.** Ledger unchanged, no
usage records, no output published. The entire pre-transport path is now validated against the live
provider; the only remaining untested surface is the completion request/response itself.

### ACTION NEEDED FROM CODEX

The emitted paid smoke command still references the stale **r2/r5** composition, which will now fail
the drift gate. **Re-emit the paid smoke command against r6/r6/r2** using the exact paths above.

Because drift is measured in hours, please also state whether the paid launch should be preceded by a
mandatory live-route preflight in the documented sequence — on this evidence the answer looks like yes,
and the same reasoning applies to the full 24-case campaign, which should carry the live-route gate
before its release run.

## 2026-08-21T17:55Z — LIVE-ROUTE PREFLIGHT `5e94b77` — works; root cause is REAL endpoint drift

The new `--live-route-preflight-only` mode reproduced paid launch #2's failure at **$0**, with a far
more precise message:

```
mmaudit failed safely: smoke candidate current OpenRouter endpoint exact-model endpoint
identity inventory differs from frozen discovery
```

Flag ergonomics observed while running it (both correct, both fail-closed):
- rejects `--allow-code-egress` — "rejects broader --allow-code-egress authority"
- requires `--allow-metadata-egress` — narrow authority must be stated explicitly

### Root cause: OpenRouter added an endpoint to the candidate model

**My earlier normalization hypothesis was wrong; codex's refutation was correct.** This is genuine
provider drift.

`deepseek/deepseek-v4-pro-0813` endpoint inventory:

- **2026-08-20** (when candidate discovery was frozen, independently fetched and recorded in this
  session): **12** endpoints — `deepseek, alibaba, gmicloud/fp8, streamlake, together, novita/fp8,
  parasail/fp8, siliconflow/fp8, baseten/fp4, digitalocean, cloudflare, fireworks`
- **2026-08-21 17:55Z**: **13** endpoints — the same twelve plus **`sail-research/fp4`**

The selected route `novita/fp8` still exists and is unchanged. What changed is the *exact-model
endpoint identity inventory*, which the frozen discovery binds in full. The gate is behaving
correctly: the sealed evidence has aged and no longer describes the current provider state.

### Remedy

Re-run metadata-only discovery for the affected role(s) to freeze current evidence, then re-run the
live-route preflight, then the paid smoke. Discovery is metadata-only, costs **$0**, and creates new
run directories without overwriting existing r2/r5 evidence. The operator side can run this on request.

Worth noting for the ticket: candidate and replay evidence was frozen 2026-08-20 and is now >24h old.
If exact whole-inventory equality is retained (it should be — it is the honest check), then discovery
evidence has an effective freshness window measured in hours-to-days for actively-served models, and
the campaign sequence needs discovery and launch close together. That is a real operational
constraint on the full 24-case run, not just the smoke.

### The live-route gate paid for itself immediately

Three prior defects in this region each cost a paid operator round-trip. This one was found at $0, in
a single command, with a message that named the exact failing comparison. Recommend the same gate be
made available for the full 24-case runner before the release campaign.

## 2026-08-21T17:15Z — PAID SMOKE LAUNCH #2 — failed closed, **$0 spent**, no provider completion

Operator executed line 425 of the operator guide (working-tree state at `59f9f40`).

```
mmaudit failed safely: smoke current discovery differs from its frozen exact route
```

Ledger unchanged `{"cap_usd":"250","entries":{},"schema_version":1}`; no bundle produced.

**Progress:** the token-budget mismatch from launch #1 is gone. This is a new, later failure —
`authenticated_runner_smoke_openrouter.py:1133-1140`, which performs a live metadata re-fetch and
requires exact equality with the frozen discovery:

```python
if (canonical_slug != evidence.canonical_slug
        or current_endpoint != evidence.endpoint_snapshot
        or current_model != frozen_model):
    raise ... "smoke current discovery differs from its frozen exact route"
```

### Signal: likely normalization mismatch, not provider drift

A field comparison of frozen discovery vs live endpoint metadata shows **all three routes differing in
the same way**, which genuine per-route drift would not produce:

| route | frozen vs live |
|---|---|
| `deepseek-v4-pro-0813` [novita/fp8] | `pricing.discount` absent vs `0`; `quantization` absent vs `fp8`; `status` absent vs `0` |
| `tencent/hy3` [tencent/fp8] | `pricing.discount` absent vs `0`; `quantization` absent vs `fp8`; `status` absent vs `0` |
| `moonshotai/kimi-k3` [together] | `pricing.discount` absent vs `0`; `quantization` absent vs `unknown`; `status` absent vs `0` |

`context_length` matches exactly on all three. Note the frozen pricing snapshots contain only
`prompt`, `completion`, `input_cache_read` — no `discount` key — while the live payload includes
`discount: 0`. Caveat: this comparison used a naive recursive field scan of the discovery-run JSON, so
the "absent" values may be an artifact of extraction rather than of the sealed record. Codex should
confirm against the real `endpoint_snapshot` and `OpenRouterModelDiscoveryPayload` objects.

**Decisive experiment available at $0:** re-run metadata-only discovery for the three routes and retry.
If fresh discovery still mismatches its own immediate re-fetch, the defect is normalization in the
smoke re-fetch path. If it matches, the cause was genuine drift and the frozen evidence simply aged
(candidate/replay were frozen 2026-08-20, ~25h before this attempt). **Say the word and the operator
side will re-run discovery** — it is metadata-only, costs nothing, and creates new run directories
without overwriting the existing r2/r5 evidence.

**Third defect in the post-preflight region.** After the post-response issuer mismatch and the
token-budget mismatch, this is the third failure living between "preflight VALID" and "first provider
byte". Reiterating the construct-only dry-run proposal that was declined at `59f9f40`: a mode that
builds the client and performs the pre-transport re-fetch, then stops, would have caught all three at
zero cost and without an operator round-trip.

## 2026-08-21T16:56Z — SMOKE PREFLIGHT after token-budget fix `59f9f40` — VALID, but unchanged

Ran line 407 of the operator guide (the only smoke command now present; the paid line was withdrawn
again pending re-validation). Provider-free, **$0 spent**.

```
AUTHRUNNER smoke preflight: VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS
Inventory: runs=2; cases=1; logical_requests=4; maximum_provider_attempts=8
Candidate exact admission: derived_final_spent_cap_usd=0.21890352
Effective config SHA-256: 42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54
```

**The output is byte-identical to the pre-fix preflight.** That confirms the preflight still does not
construct the live `OpenRouterClient`, so the token-budget consistency that `59f9f40` addresses remains
unexercised by any provider-free run. Whether the fix works can only be established by another paid
attempt.

Restating the standing suggestion, now with a second supporting data point: **a construct-only dry-run
mode** — build the `OpenRouterClient` and stop before issuing any request — would have caught both the
post-response issuer mismatch (partially) and this token-budget mismatch (fully), at zero cost. Two of
the last three defects lived in that unreachable region.

## 2026-08-21T16:30Z — PAID SMOKE LAUNCH ATTEMPTED — failed closed, **$0 spent**, no provider call

The operator executed line 389 of the operator guide verbatim (checkpoint `7b2db06`).

```
mmaudit failed safely: request and atomic global input token budgets differ
```

**Ledger unchanged: `{"cap_usd":"250","entries":{},"schema_version":1}`. No bundle produced. The
failure occurs during client construction, before any provider request.** Fail-closed behaviour was
correct.

### Diagnosis

`openrouter.py:4288-4293` requires the two token-budget sources to agree:

```python
if self.budget.global_input_token_budget != self.token_budgets.global_input_token_budget:
    raise OpenRouterCostControlError("request and atomic global input token budgets differ")
```

- `config/openrouter-qualification.toml` sets **neither** value; `config.py:197` defaults
  `global_input_token_budget` to `8_000_000`.
- The smoke orchestrator passes both from the same launch object
  (`authenticated_runner_smoke_openrouter.py:401-402`):
  `token_budgets=self._launch.config.token_budgets` and `budget=self._launch.budget`.
- They disagree at runtime, so the two are populated from different sources — `token_budgets` from
  config defaults, `budget` evidently from a derived or sealed value.

**Likely latent in the release runner too.** `authenticated_runner_openrouter.py:633` passes the same
`budget=launch.budget` / `token_budgets=launch.config.token_budgets` pairing. The release runner has
never executed either, so it would plausibly hit the identical check. Worth verifying before the
24-case launch rather than discovering it there.

### Why the preflight did not catch this

`--preflight-only` validated the campaign contract but does not construct the live `OpenRouterClient`,
so the constructor's budget-consistency check is unreachable provider-free. This is the second defect
in this class, after the post-response issuer mismatch — both live between "preflight passes" and
"first provider byte", a region no provider-free run can reach.

The one-case smoke corpus did its job exactly as intended: the defect surfaced for **$0** instead of
inside a $5.27 24-case run.

## 2026-08-21T15:36Z — SMOKE PREFLIGHT at checkpoint `c137f8b` (post origin-custody fix) — **VALID**

Ran the exact command at line 365 of the operator guide, verbatim. Provider-free, **$0 spent**.

```
AUTHRUNNER smoke preflight: VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS
Inventory: runs=2; cases=1; logical_requests=4; maximum_provider_attempts=8; generation_refetches=4
Operator cost tripwires: operator_interval_cap_usd=8.00; operator_final_spent_cap_usd=8.00
Candidate exact admission: derived_final_spent_cap_usd=0.21890352
Judge exact admission: status=PENDING_REAL_CANDIDATE_OUTPUTS
Effective config SHA-256: 42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54
```

Identical to the pre-fix preflight — `c9a8923` did not disturb the provider-free path.

### Independent review of the `c9a8923` origin-custody fix — by code reading

Verified across five layers:

1. **Disjoint namespaces** (`usage.py:46-104`) — each proof kind is regex-bound to its own `request_id`
   namespace; smoke and release namespaces cannot overlap. Enforced bidirectionally: a closed-namespace
   request lacking its proof kind also raises.
2. **Issuer** (`usage.py:1402+`) — the hardcoded release-only allowlist is replaced by
   `origin_scope is None`, admitting both scopes without widening what either may claim.
3. **Custody pinning** (`usage.py:1499`) — scope is registered at issuance and re-verified on every
   `contains()` check (`registered[3] == current_scope`), so it cannot drift post-issuance.
4. **Artifact isolation** — smoke evidence carries schema-`const` `artifact_kind:
   authenticated_runner_noncrediting_smoke_evidence` and `purpose: NONCREDITING_SMOKE`.
5. **Path isolation** — `orchestration/assurance.py` (AUTHSEAL) and `models/candidate_benchmark.py`
   contain no smoke references, so a smoke bundle cannot feed authority-granting paths.

Regression coverage added: 603 lines in `test_openrouter.py`, 119 in `test_usage.py`, including
`test_authrunner_origin_scope_is_a_closed_four_way_namespace_map` and
`test_nonclosed_uuid_only_preserves_legacy_release_proof_kinds`.

**Limit of this review, stated plainly:** it is code reading plus unit-test inspection. The
post-response issuer boundary — the exact defect that made `f5afb2b` unsafe — remains unreachable by
any provider-free preflight, because no provider response is ever produced. Operator sign-off on a
future paid command should be read as *"the path reads correctly and has regression coverage"*, not
*"this will succeed"*. Only a real call settles it.

## 2026-08-21T15:00Z — Paid smoke launch WITHDRAWN by codex before execution — independently verified

Checkpoint `f5afb2b` emitted a paid smoke launch; `ca63b92` withdrew it 14 minutes later after a local
paid-path audit. **The command was never run. No paid attempt, no provider completion, no spend.**
Ledger remains `{"cap_usd":"250","entries":{},"schema_version":1}` — **$0**.

Codex's reasoning was checked independently against the source and is correct:

- `usage.py:1352-1355` — the owned-REAL usage-origin issuer requires `privacy_source_proof_kind` to be
  one of `RELEASE_PINNED_MODEL_BENCHMARK` or `RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION`, else raises
  `AUTHRUNNER usage origin requires owned REAL bound-success evidence`.
- The smoke path deliberately routes `PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK` and
  `PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION` — confirmed present in source, and **not** in
  that allowlist.
- `openrouter.py:5892` calls `_attest_authrunner_owned_real_usage_origin(concluded_usage)` on
  *concluded* usage — after the provider response is charged and bound. Failure at
  `openrouter.py:5895` (`REAL bound usage lacks AUTHRUNNER transport-origin custody`) therefore occurs
  **post-charge**.

Consequence had it run: the first paid candidate completion would have spent money and then failed
before any smoke evidence could be sealed — money out, no artifact, no diagnostic bundle.

**Provider-free preflight cannot catch this.** It never receives a provider response, so the
post-response issuer boundary is structurally unreachable. This is the first defect found today that
the preflight layer could not have surfaced at any cost.

`V3-AUTHRUNNER-001` remains `BLOCKED_SAFETY`. Per codex, the fix must admit only the exact noncrediting
smoke proof kinds without granting release, qualification, calibration, benchmark, audit, AUTHSEAL, or
production authority, plus focused post-response regressions and a new provider-free checkpoint. No
paid command may be restored from `f5afb2b`.

Operator position: nothing to authorize. Awaiting a re-emitted provider-free preflight first.

## 2026-08-21T14:33Z — SMOKE PREFLIGHT at checkpoint `f0a0f39` — **VALID**

Ran the exact command emitted at line 306 of the operator guide, verbatim. Provider-free.
Cost ledger unchanged — **$0 spent**.

```
AUTHRUNNER smoke preflight: VALID / NONCREDITING / NONAUTHORIZING / NO PROVIDER EGRESS
Inventory: runs=2; cases=1; logical_requests=4; maximum_provider_attempts=8; generation_refetches=4
Operator cost tripwires: initial_spent_usd=0; operator_interval_cap_usd=8.00;
                         operator_final_spent_cap_usd=8.00
Candidate exact admission:
  plan_sha256s=944343e272b05b9925a0d4c618946ffbd4742f861e792c83be423531af07ea19,
               b281a184b96ee208284f57de5c17adf59a9a61a72788bfb1fb5b9ac80e25dd3d
  derived_interval_cap_usd=0.21890352; derived_final_spent_cap_usd=0.21890352
Judge exact admission: status=PENDING_REAL_CANDIDATE_OUTPUTS
                       full_smoke_cost_bound=UNAVAILABLE_BEFORE_REAL_CANDIDATE_OUTPUTS
Effective config SHA-256: 42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54
```

The `7e9db03` null-root fix works: `root_lineage = None` with `lineage_review.status = PENDING` is now
accepted, and the sha256 root-format validation passes on all three pairs.

### Smoke vs full campaign

| | full 24-case | smoke 1-case |
|---|---|---|
| logical requests | 96 | 4 |
| max provider attempts | 192 | 8 |
| derived candidate cap | $5.27438208 | **$0.21890352** |
| operator tripwire (hard ceiling) | $192.00 | **$8.00** |

**The effective config SHA-256 is byte-identical to the full 24-case preflight**
(`42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54`). Same runtime configuration, same
code paths, same three routes — only the corpus differs. The smoke run is therefore representative of
what the full run will exercise, not an easier alternate path.

**Awaiting the paid smoke command.** Emit it and the operator will authorize; it will then be run
verbatim and the result recorded here.

## 2026-08-21T14:10Z — SMOKE PREFLIGHT after `af70559` — BUG: smoke path drops the null-root tolerance

Ran `models authenticated-runner-smoke --preflight-only` with the r2/r5/r2 inputs and
`--smoke-corpus benchmarks/model_corpus_smoke`. Provider-free, **$0 spent**.

```
mmaudit failed safely: smoke public lineage returned a non-independent projection
```

`authenticated_runner_smoke_openrouter.py:996-1001` requires each returned projection to equal
`expected[index]`, where `expected` is built from the **registry** objects:

```python
expected = tuple((left.exact_model_id, left.root_lineage,
                  right.exact_model_id, right.root_lineage) for left, right in pairs)
```

But discovery does not bind lineage, so `root_lineage` is `None` in every registry:

| registry | exact_model_id | root_lineage |
|---|---|---|
| `candidate-registry-r2.json` | `deepseek/deepseek-v4-pro-0813` | **None** |
| `primary-judge-registry-r5.json` | `tencent/hy3` | **None** |
| `replay-judge-registry-r2.json` | `moonshotai/kimi-k3` | **None** |

The projection returns real sha256 roots from the sealed bundle, so `None != sha256:...` and the
comparison can never succeed. **The smoke path fails for any real registry set.**

The full runner already handles this. `authenticated_runner_execution.py:997` and `:1004` both guard
with `is not None`:

```python
if judge.root_lineage is not None and judge.root_lineage != projection.right_root_lineage:
```

`grep -c "root_lineage is not None"` returns **2** in `authenticated_runner_execution.py` and **0** in
`authenticated_runner_smoke_openrouter.py`. The tolerance was not carried over.

Suggested fix: apply the same null-tolerant comparison in the smoke path — compare
`exact_model_id` unconditionally, and `root_lineage` only when the registry value is not `None`,
while still requiring `item.independent is True` and the correct projection type. Note this also means
the smoke path's unit tests are passing against fixtures whose registries carry non-null
`root_lineage`, which real discovery output never does — worth a regression test using a null-root
registry.

**Not yet run:** the smoke REAL launch. Blocked on this fix. Derived smoke cost bound is still unknown
because preflight cannot complete.

## 2026-08-21T12:20Z — PREFLIGHT r2/r5/r2 — **VALID**, with derived exact caps

Run after `a1ace77`. All three roles CONFIRMED in the resealed 16-source / 10-root bundle
(`verified_at 2026-08-21T11:47:00Z`). Ledger unchanged — **$0 spent**.

```
AUTHRUNNER preflight: VALID / NONAUTHORIZING / NO PROVIDER EGRESS
Inventory: runs=2; cases=24; candidate_logical_requests=48; judge_logical_requests=48;
           logical_requests=96
Attempts:  maximum_per_logical_request=2; maximum_provider_attempts=192; generation_refetches=96
Operator cost tripwires: initial_spent_usd=0; operator_interval_cap_usd=192.00;
                         operator_final_spent_cap_usd=192.00
Candidate exact admission:
  plan_sha256s=f0f367605dd75674b08c8974bf69570190e4137be46a47619c1b5b9d85c83b57,
               3fc6e535d22baf9bbbdafe4ccb50f9127fdb6d5c2fba7ce0463388765d2f8436
  derived_interval_cap_usd=5.27438208; derived_final_spent_cap_usd=5.27438208
Judge exact admission: status=PENDING_REAL_CANDIDATE_OUTPUTS
                       full_campaign_cost_bound=UNAVAILABLE_BEFORE_REAL_CANDIDATE_OUTPUTS
Effective config SHA-256: 42dfc90d29f68562120e35714dfe7c09b60a8b234316d2ceb520a02611e75a54
```

The effort-mode catalog fallback works: all three roles validated on `effort = "high"`.

### Cost exposure for the REAL launch — partially bounded

- **Candidate phase: exactly bounded at $5.27.** Derived from sealed pricing, not estimated.
- **Judge phase: not boundable in advance.** Judges consume real candidate outputs, whose token counts
  do not exist until the candidate phase runs. Correctly reported as `UNAVAILABLE`, not guessed.
- Backstops if the judge phase runs long: operator tripwire $192.00, ledger cap $250.00.

So the REAL launch has a known floor of ~$5.27 and a judge component capped only by the $192 tripwire.
The replay judge `moonshotai/kimi-k3` on `together` is the cost risk at $15.00/1M completion tokens —
roughly 4x the candidate and far above the primary judge. If judge output volume resembles candidate
volume, total spend should land in the low tens of dollars; the $192 tripwire is the guard against
that assumption being wrong, and it is well inside the $250 ledger cap.

**This is the point requiring explicit operator authorization.** Everything to here has been
provider-free and cost-free. The REAL launch is the first step that spends money and the first that can
produce a completed real audit.

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
